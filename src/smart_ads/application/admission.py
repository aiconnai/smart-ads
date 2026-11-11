"""Fail-closed trusted admission before any credential lookup, reservation, or RPC (ADR-0001 §4.2)."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from types import MappingProxyType
from typing import Final

from smart_ads.contracts.jcs import (
    ADR_P1_DOMAIN_PREFIXES,
    MAX_JCS_SAFE_INT,
    ArtifactLocator,
    canonicalize_jcs,
    jcs_sha256,
    sort_utf8_strings,
)
from smart_ads.contracts.scalars import (
    ClosedValidationError,
    parse_timestamp_utc_micros,
    validate_non_empty_str,
    validate_opaque_ref,
    validate_timestamp_utc_seconds,
)
from smart_ads.contracts.schemas import (
    PURPOSE_REQUIRED_EFFECT_ROLES,
    AdmittedCollection,
    CanonicalQueryContract,
    CollectionRequest,
    DateRange,
    compute_schema_bundle_digest,
)
from smart_ads.domain.capabilities import is_io_denied_state
from smart_ads.domain.pipeboard_contract import PipeboardPhase1Contract
from smart_ads.domain.registry import (
    DriverCapabilityEntry,
    PrivateRegistrySnapshot,
)
from smart_ads.ports.cell_runtime import (
    AmbiguousLocalDayError,
    CellRuntimePorts,
    ClockAttestation,
    ResolvedClockState,
    ResolvedPrerequisiteBundle,
    ResolvedRegistryState,
    TimezoneRuleSnapshot,
)
from smart_ads.ports.provider import ExternalIOCounters

_PURPOSE_ALLOWED_CAPABILITY_STATES: Final[Mapping[str, frozenset[str]]] = (
    MappingProxyType(
        {
            "fixture_7a": frozenset({"declared", "fixture_certified"}),
            "live_verification_7b": frozenset(
                {"fixture_certified", "live_certified"}
            ),
            "operational_read": frozenset({"live_certified"}),
        }
    )
)


class AdmissionError(ClosedValidationError):
    """Fail-closed pre-dispatch admission error with all external I/O counters equal to zero."""

    reason_code: str
    detail: str
    counters: ExternalIOCounters

    def __init__(
        self,
        reason_code: str,
        detail: str,
        *,
        counters: ExternalIOCounters | None = None,
    ) -> None:
        checked_code = validate_non_empty_str(
            reason_code, field_name="admission_error.reason_code"
        )
        checked_detail = validate_non_empty_str(
            detail, field_name="admission_error.detail"
        )
        resolved_counters = (
            ExternalIOCounters.zero() if counters is None else counters
        )
        if (
            not isinstance(resolved_counters, ExternalIOCounters)
            or not resolved_counters.is_zero
        ):
            raise ClosedValidationError(
                "admission_error.counters: pre-dispatch admission errors must "
                "have all ExternalIOCounters equal to zero"
            )
        self.reason_code = checked_code
        self.detail = checked_detail
        self.counters = resolved_counters
        super().__init__(f"{checked_code}: {checked_detail}")


@dataclass(frozen=True, slots=True)
class AdmittedCollectionBundle:
    """Immutable `AdmittedCollection` paired with its locator, registry snapshot, and driver contract."""

    admitted: AdmittedCollection
    locator: ArtifactLocator
    registry_snapshot: PrivateRegistrySnapshot
    driver_contract: PipeboardPhase1Contract

    def __post_init__(self) -> None:
        if not isinstance(self.admitted, AdmittedCollection):
            raise ClosedValidationError(
                "admitted_collection_bundle.admitted: expected AdmittedCollection"
            )
        if (
            not isinstance(self.locator, ArtifactLocator)
            or self.locator.artifact_type != AdmittedCollection.SCHEMA
        ):
            raise ClosedValidationError(
                "admitted_collection_bundle.locator: expected ArtifactLocator "
                f"for {AdmittedCollection.SCHEMA!r}"
            )
        if not isinstance(self.registry_snapshot, PrivateRegistrySnapshot):
            raise ClosedValidationError(
                "admitted_collection_bundle.registry_snapshot: expected PrivateRegistrySnapshot"
            )
        if not isinstance(self.driver_contract, PipeboardPhase1Contract):
            raise ClosedValidationError(
                "admitted_collection_bundle.driver_contract: expected PipeboardPhase1Contract"
            )
        expected_admitted_loc = ArtifactLocator.for_canonical_bytes(
            AdmittedCollection.SCHEMA,
            canonicalize_jcs(self.admitted.to_dict()),
        )
        if self.locator != expected_admitted_loc:
            raise ClosedValidationError(
                "admitted_collection_bundle.locator: locator does not match canonical "
                "JCS digest of AdmittedCollection"
            )
        expected_snap_loc = ArtifactLocator.for_canonical_bytes(
            PrivateRegistrySnapshot.SCHEMA,
            canonicalize_jcs(self.registry_snapshot.to_dict()),
        )
        if self.admitted.registry_snapshot_locator != expected_snap_loc:
            raise ClosedValidationError(
                "admitted_collection_bundle.registry_snapshot: snapshot does not "
                "match admitted.registry_snapshot_locator canonical JCS digest"
            )
        expected_drv_loc = ArtifactLocator.for_canonical_bytes(
            PipeboardPhase1Contract.SCHEMA,
            canonicalize_jcs(self.driver_contract.to_dict()),
        )
        if self.admitted.driver_contract_locator != expected_drv_loc:
            raise ClosedValidationError(
                "admitted_collection_bundle.driver_contract: driver_contract does "
                "not match admitted.driver_contract_locator canonical JCS digest"
            )


def _admit_collection_unchecked(
    request: CollectionRequest,
    ports: CellRuntimePorts,
    *,
    admission_id: str,
) -> AdmittedCollectionBundle:
    if not isinstance(request, CollectionRequest):
        raise AdmissionError(
            "invalid_request",
            f"expected CollectionRequest, got {type(request).__name__}",
        )
    if not isinstance(ports, CellRuntimePorts):
        raise AdmissionError(
            "invalid_runtime_ports",
            f"expected CellRuntimePorts, got {type(ports).__name__}",
        )
    try:
        checked_admission_id = validate_opaque_ref(
            admission_id,
            field_name="admission_id",
            expected_prefix="admission",
        )
    except ClosedValidationError as exc:
        raise AdmissionError("invalid_admission_id", str(exc)) from exc

    # 1. Authenticated clock attestation & freshness
    clock_state = ports.clock_port.get_authenticated_clock()
    if not isinstance(clock_state, ResolvedClockState):
        raise AdmissionError(
            "invalid_clock_state",
            f"expected ResolvedClockState, got {type(clock_state).__name__}",
        )
    if clock_state.locator.artifact_type != ClockAttestation.SCHEMA:
        raise AdmissionError(
            "invalid_clock_locator",
            f"expected locator artifact_type {ClockAttestation.SCHEMA!r}, "
            f"got {clock_state.locator.artifact_type!r}",
        )
    expected_clock_loc = ArtifactLocator.for_canonical_bytes(
        ClockAttestation.SCHEMA,
        canonicalize_jcs(clock_state.attestation.to_dict()),
    )
    if clock_state.locator != expected_clock_loc:
        raise AdmissionError(
            "invalid_clock_locator",
            "clock_state.locator does not match canonical JCS digest of ClockAttestation",
        )
    if not (0 < clock_state.configured_max_uncertainty_ms <= MAX_JCS_SAFE_INT):
        raise AdmissionError(
            "invalid_clock_config",
            "configured_max_uncertainty_ms must be a positive safe int",
        )
    try:
        lower_us, upper_us = clock_state.attestation.verify_freshness(
            configured_max_uncertainty_ms=clock_state.configured_max_uncertainty_ms
        )
    except ClosedValidationError as exc:
        raise AdmissionError("clock_freshness_failed", str(exc)) from exc

    admitted_at_utc = validate_timestamp_utc_seconds(
        clock_state.attestation.now_utc[:19] + "Z",
        field_name="admitted_at_utc",
    )

    # 2. Reporting timezone policy & unambiguous previous local day (P-07)
    try:
        tz_rules = ports.timezone_port.get_reporting_timezone_rules()
    except AmbiguousLocalDayError as exc:
        raise AdmissionError("ambiguous_local_day", str(exc)) from exc
    except ClosedValidationError as exc:
        raise AdmissionError("invalid_timezone_policy", str(exc)) from exc

    if not isinstance(tz_rules, TimezoneRuleSnapshot):
        raise AdmissionError(
            "invalid_timezone_policy",
            f"expected TimezoneRuleSnapshot, got {type(tz_rules).__name__}",
        )
    if tz_rules.timezone_name != "America/Sao_Paulo":
        raise AdmissionError(
            "unsupported_reporting_timezone",
            f"Phase 1 requires 'America/Sao_Paulo', got {tz_rules.timezone_name!r}",
        )
    try:
        validate_non_empty_str(tz_rules.tzdb_version, field_name="tzdb_version")
    except ClosedValidationError as exc:
        raise AdmissionError("invalid_timezone_policy", str(exc)) from exc

    try:
        prev_day = tz_rules.compute_previous_local_day(
            lower_utc_micros=lower_us,
            upper_utc_micros=upper_us,
        )
    except AmbiguousLocalDayError as exc:
        raise AdmissionError("ambiguous_local_day", str(exc)) from exc

    computed_date_range = DateRange(
        start_date=prev_day,
        end_date=prev_day,
        inclusive=True,
    )

    # 3. Protected private registry snapshot, authorized scope, and capability state
    registry_state = ports.registry_port.get_active_registry(
        tenant_ref=request.tenant_ref
    )
    if not isinstance(registry_state, ResolvedRegistryState):
        raise AdmissionError(
            "invalid_registry_state",
            f"expected ResolvedRegistryState, got {type(registry_state).__name__}",
        )
    if registry_state.locator.artifact_type != PrivateRegistrySnapshot.SCHEMA:
        raise AdmissionError(
            "invalid_registry_locator",
            f"expected locator artifact_type {PrivateRegistrySnapshot.SCHEMA!r}",
        )
    expected_registry_loc = ArtifactLocator.for_canonical_bytes(
        PrivateRegistrySnapshot.SCHEMA,
        canonicalize_jcs(registry_state.snapshot.to_dict()),
    )
    if registry_state.locator != expected_registry_loc:
        raise AdmissionError(
            "invalid_registry_locator",
            "registry_state.locator does not match canonical JCS digest of PrivateRegistrySnapshot",
        )
    if (
        registry_state.driver_contract_locator.artifact_type
        != PipeboardPhase1Contract.SCHEMA
    ):
        raise AdmissionError(
            "invalid_driver_contract_locator",
            f"expected locator artifact_type {PipeboardPhase1Contract.SCHEMA!r}",
        )
    expected_driver_contract_loc = ArtifactLocator.for_canonical_bytes(
        PipeboardPhase1Contract.SCHEMA,
        canonicalize_jcs(registry_state.driver_contract.to_dict()),
    )
    if registry_state.driver_contract_locator != expected_driver_contract_loc:
        raise AdmissionError(
            "invalid_driver_contract_locator",
            "registry_state.driver_contract_locator does not match canonical JCS "
            "digest of PipeboardPhase1Contract",
        )

    snapshot = registry_state.snapshot
    if snapshot.tenant_ref != request.tenant_ref:
        raise AdmissionError(
            "tenant_mismatch",
            f"registry snapshot tenant {snapshot.tenant_ref!r} != request tenant {request.tenant_ref!r}",
        )

    snap_issued_us = parse_timestamp_utc_micros(
        snapshot.issued_at_utc,
        field_name="private_registry_snapshot.issued_at_utc",
        allow_whole_seconds=True,
    )
    snap_valid_until_us = parse_timestamp_utc_micros(
        snapshot.valid_until_utc,
        field_name="private_registry_snapshot.valid_until_utc",
        allow_whole_seconds=True,
    )
    if not (snap_issued_us <= lower_us and upper_us <= snap_valid_until_us):
        raise AdmissionError(
            "registry_snapshot_outside_validity_window",
            "authenticated clock uncertainty interval is not contained within "
            "registry snapshot [issued_at_utc, valid_until_utc]",
        )

    try:
        binding = snapshot.get_binding(request.binding_ref)
    except ClosedValidationError as exc:
        raise AdmissionError("unknown_binding", str(exc)) from exc

    if binding.currency != "BRL" or binding.ad_platform_ref != "meta":
        raise AdmissionError(
            "unsupported_binding_configuration",
            "Phase 1 requires binding currency='BRL' and ad_platform_ref='meta'",
        )
    if binding.driver_id != registry_state.driver_contract.driver_id:
        raise AdmissionError(
            "driver_contract_mismatch",
            f"binding driver_id {binding.driver_id!r} != contract driver_id "
            f"{registry_state.driver_contract.driver_id!r}",
        )

    scope_authorized = any(
        rel.binding_ref == request.binding_ref
        and rel.resource_scope_ref == request.resource_scope_ref
        for rel in snapshot.authorized_scopes
    )
    if not scope_authorized:
        raise AdmissionError(
            "unauthorized_binding_scope",
            f"no authorized_scopes relation permits ({request.binding_ref!r}, "
            f"{request.resource_scope_ref!r})",
        )

    allowed_states = _PURPOSE_ALLOWED_CAPABILITY_STATES[
        request.collection_purpose
    ]
    resolved_caps: list[DriverCapabilityEntry] = []
    metric_union: set[str] = set()
    for cap_ref in request.requested_capabilities:
        try:
            cap = snapshot.get_capability(cap_ref, request.resource_scope_ref)
        except ClosedValidationError as exc:
            raise AdmissionError("unknown_capability", str(exc)) from exc

        if cap.driver_id != binding.driver_id:
            raise AdmissionError(
                "capability_driver_mismatch",
                f"capability {cap_ref!r} driver_id {cap.driver_id!r} != "
                f"binding driver_id {binding.driver_id!r}",
            )
        if cap.driver_contract_locator != registry_state.driver_contract_locator:
            raise AdmissionError(
                "capability_driver_contract_mismatch",
                f"capability {cap_ref!r} driver_contract_locator does not match "
                "resolved active driver_contract_locator",
            )
        if is_io_denied_state(cap.state):
            raise AdmissionError(
                "capability_io_denied",
                f"capability {cap_ref!r} is in I/O-denied state {cap.state!r}",
            )
        if cap.state not in allowed_states:
            raise AdmissionError(
                "insufficient_capability_state",
                f"purpose {request.collection_purpose!r} requires capability state "
                f"in {sorted(allowed_states)}, got {cap.state!r}",
            )
        resolved_caps.append(cap)
        metric_union.update(cap.required_metrics)

    required_metrics = sort_utf8_strings(
        metric_union,
        field_name="required_metrics",
        allow_empty=False,
    )
    for metric_ref in required_metrics:
        if metric_ref not in registry_state.driver_contract.metric_source_mappings:
            raise AdmissionError(
                "unmapped_required_metric",
                f"required metric {metric_ref!r} is absent from pinned driver contract mappings",
            )

    driver_capability_snapshot_digest = jcs_sha256(
        [cap.to_dict() for cap in resolved_caps]
    )

    # 4. Canonical query contract
    canonical_query = CanonicalQueryContract(
        tenant_ref=request.tenant_ref,
        binding_ref=request.binding_ref,
        account_ref=binding.account_ref,
        resource_scope_ref=request.resource_scope_ref,
        ad_platform_ref=binding.ad_platform_ref,
        date_rule=request.date_rule,
        date_range=computed_date_range,
        reporting_timezone=tz_rules.timezone_name,
        tzdb_version=tz_rules.tzdb_version,
        resource_level=request.resource_level,
        metric_semantic_refs=required_metrics,
        requested_capabilities=request.requested_capabilities,
        breakdowns=request.breakdowns,
        currency=binding.currency,
    )

    # 5. Purpose-specific prerequisites & live certification / renewal / Hermes verification
    prereq = ports.prerequisite_port.resolve_prerequisites(
        request=request,
        canonical_query=canonical_query,
        clock_state=clock_state,
    )
    if not isinstance(prereq, ResolvedPrerequisiteBundle):
        raise AdmissionError(
            "invalid_prerequisites",
            f"expected ResolvedPrerequisiteBundle, got {type(prereq).__name__}",
        )
    if prereq.locators.purpose != request.collection_purpose:
        raise AdmissionError(
            "prerequisite_purpose_mismatch",
            f"prerequisite purpose {prereq.locators.purpose!r} != "
            f"request purpose {request.collection_purpose!r}",
        )

    expected_schema_bundle_digest = compute_schema_bundle_digest()
    expected_resource_mapping_digest = snapshot.resource_mapping_contract_digest

    if request.collection_purpose == "fixture_7a":
        if (
            prereq.gate3_selection is not None
            or prereq.live_certification is not None
            or prereq.hermes_delegation is not None
        ):
            raise AdmissionError(
                "unexpected_live_prerequisite_metadata",
                "fixture_7a forbids Gate-3 selection, live certification, or Hermes delegation state",
            )
    else:
        gate3 = prereq.gate3_selection
        if gate3 is None:
            raise AdmissionError(
                "missing_gate3_selection",
                f"{request.collection_purpose} requires resolved Gate-3 selection receipt state",
            )
        expected_gate3_locator = (
            prereq.locators.gate3_selection_receipt_locator
            if request.collection_purpose == "live_verification_7b"
            else prereq.locators.gate3_operational_renewal_locator
        )
        if gate3.locator != expected_gate3_locator:
            raise AdmissionError(
                "gate3_locator_mismatch",
                "resolved gate3_selection.locator must match purpose_prerequisite_locators",
            )
        expected_gate3_role = (
            "certification"
            if request.collection_purpose == "live_verification_7b"
            else "operational_renewal"
        )
        if gate3.selection_role != expected_gate3_role:
            raise AdmissionError(
                "invalid_gate3_selection_role",
                f"{request.collection_purpose} requires Gate-3 selection_role == "
                f"{expected_gate3_role!r}, got {gate3.selection_role!r}",
            )
        if (
            clock_state.configured_max_uncertainty_ms
            > gate3.maximum_clock_uncertainty_ms
            or clock_state.attestation.uncertainty_ms
            > gate3.maximum_clock_uncertainty_ms
        ):
            raise AdmissionError(
                "gate3_clock_uncertainty_exceeded",
                "clock uncertainty exceeds Gate-3 maximum_clock_uncertainty_ms (1000ms)",
            )

        revalidated_us = parse_timestamp_utc_micros(
            gate3.revalidated_at_utc,
            field_name="gate3.revalidated_at_utc",
            allow_whole_seconds=True,
        )
        gate3_valid_until_us = parse_timestamp_utc_micros(
            gate3.valid_until_utc,
            field_name="gate3.valid_until_utc",
            allow_whole_seconds=True,
        )
        if lower_us < revalidated_us:
            raise AdmissionError(
                "gate3_selection_not_yet_valid",
                "authenticated clock lower bound precedes Gate-3 revalidated_at_utc",
            )
        if upper_us > gate3_valid_until_us:
            raise AdmissionError(
                "expired_gate3_selection",
                "authenticated clock upper bound exceeds Gate-3 valid_until_utc",
            )
        if (
            upper_us
            + gate3.maximum_provider_dispatch_deadline_seconds * 1_000_000
            > gate3_valid_until_us
        ):
            raise AdmissionError(
                "gate3_dispatch_deadline_exceeds_validity",
                "authenticated clock upper bound + 60s provider dispatch deadline "
                "exceeds Gate-3 valid_until_utc",
            )

        if (
            gate3.candidate_driver_contract_digest
            != registry_state.driver_contract_locator.content_digest
        ):
            raise AdmissionError(
                "gate3_driver_contract_mismatch",
                "Gate-3 candidate_driver_contract_digest does not match active driver contract",
            )
        if gate3.canonical_query_digest != canonical_query.canonical_query_digest:
            raise AdmissionError(
                "gate3_canonical_query_mismatch",
                "Gate-3 canonical_query_digest does not match admitted CanonicalQueryContract",
            )
        if gate3.schema_bundle_digest != expected_schema_bundle_digest:
            raise AdmissionError(
                "gate3_schema_bundle_mismatch",
                "Gate-3 schema_bundle_digest does not match active core schema bundle",
            )
        if gate3.resource_mapping_contract_digest != expected_resource_mapping_digest:
            raise AdmissionError(
                "gate3_resource_mapping_mismatch",
                "Gate-3 resource_mapping_contract_digest does not match active registry snapshot",
            )
        if gate3.authorized_certification_scope != request.resource_scope_ref:
            raise AdmissionError(
                "gate3_scope_mismatch",
                "Gate-3 authorized_certification_scope does not match request.resource_scope_ref",
            )

        if request.collection_purpose == "live_verification_7b":
            if prereq.live_certification is not None:
                raise AdmissionError(
                    "unexpected_live_certification_state",
                    "live_verification_7b forbids operational live_certification state",
                )
            if prereq.hermes_delegation is not None:
                raise AdmissionError(
                    "unexpected_hermes_delegation_state",
                    "live_verification_7b forbids operational Hermes delegation state",
                )
        else:
            live_cert = prereq.live_certification
            if live_cert is None:
                raise AdmissionError(
                    "missing_live_certification",
                    "operational_read requires resolved live_certification head/transition/certificate",
                )
            if (
                live_cert.head_locator
                != prereq.locators.live_certification_head_locator
                or live_cert.transition_locator
                != prereq.locators.live_certification_transition_locator
                or live_cert.certificate_locator
                != prereq.locators.live_certification_certificate_locator
            ):
                raise AdmissionError(
                    "live_certification_locator_mismatch",
                    "resolved live_certification locators must match purpose_prerequisite_locators",
                )
            if live_cert.renewal_selection_role != "operational_renewal":
                raise AdmissionError(
                    "invalid_renewal_selection_role",
                    "operational_read requires Gate-3 selection_role == 'operational_renewal'",
                )
            if not (
                gate3.certification_fingerprint_digest
                == live_cert.renewal_fingerprint_digest
                == live_cert.certified_fingerprint_digest
            ):
                raise AdmissionError(
                    "renewal_fingerprint_mismatch",
                    "Gate-3 operational_renewal fingerprint must equal certified_fingerprint_digest",
                )
            if live_cert.tenant_ref != request.tenant_ref:
                raise AdmissionError(
                    "live_certificate_tenant_mismatch",
                    "live_certification_certificate tenant_ref does not match request.tenant_ref",
                )
            if live_cert.binding_ref != request.binding_ref:
                raise AdmissionError(
                    "live_certificate_binding_mismatch",
                    "live_certification_certificate binding_ref does not match request.binding_ref",
                )
            if live_cert.resource_scope_ref != request.resource_scope_ref:
                raise AdmissionError(
                    "live_certificate_scope_mismatch",
                    "live_certification_certificate resource_scope_ref does not match request.resource_scope_ref",
                )
            if live_cert.driver_id != binding.driver_id:
                raise AdmissionError(
                    "live_certificate_driver_mismatch",
                    "live_certification_certificate driver_id does not match binding.driver_id",
                )
            if (
                live_cert.driver_contract_digest
                != registry_state.driver_contract_locator.content_digest
            ):
                raise AdmissionError(
                    "live_certificate_driver_contract_mismatch",
                    "live_certification_certificate driver_contract_digest does not match active driver contract",
                )
            if (
                live_cert.canonical_query_digest
                != canonical_query.canonical_query_digest
            ):
                raise AdmissionError(
                    "live_certificate_canonical_query_mismatch",
                    "live_certification_certificate canonical_query_digest does not match CanonicalQueryContract",
                )
            if live_cert.schema_bundle_digest != expected_schema_bundle_digest:
                raise AdmissionError(
                    "live_certificate_schema_bundle_mismatch",
                    "live_certification_certificate schema_bundle_digest does not match core schema bundle",
                )
            if (
                live_cert.resource_mapping_contract_digest
                != expected_resource_mapping_digest
            ):
                raise AdmissionError(
                    "live_certificate_resource_mapping_mismatch",
                    "live_certification_certificate resource_mapping_contract_digest does not match registry snapshot",
                )

            cert_issued_us = parse_timestamp_utc_micros(
                live_cert.certificate_issued_at_utc,
                field_name="certificate_issued_at_utc",
                allow_whole_seconds=True,
            )
            cert_valid_until_us = parse_timestamp_utc_micros(
                live_cert.certificate_valid_until_utc,
                field_name="certificate_valid_until_utc",
                allow_whole_seconds=True,
            )
            if lower_us < cert_issued_us:
                raise AdmissionError(
                    "future_live_certificate",
                    "authenticated clock lower bound precedes live_certification_certificate issued_at_utc",
                )
            if upper_us > cert_valid_until_us:
                raise AdmissionError(
                    "expired_live_certificate",
                    "authenticated clock upper bound exceeds live_certification_certificate valid_until_utc",
                )

            if (
                ports.require_hermes_delegation
                or prereq.locators.delegation_context_locator is not None
                or prereq.hermes_delegation is not None
            ):
                deleg = prereq.hermes_delegation
                if (
                    prereq.locators.delegation_context_locator is None
                    or deleg is None
                ):
                    raise AdmissionError(
                        "missing_hermes_delegation_context",
                        "Hermes operational traffic requires both delegation_context_locator and ResolvedHermesDelegationState",
                    )
                if deleg.locator != prereq.locators.delegation_context_locator:
                    raise AdmissionError(
                        "hermes_delegation_locator_mismatch",
                        "resolved hermes_delegation.locator must match delegation_context_locator",
                    )
                if deleg.route != "/ibvi-ads":
                    raise AdmissionError(
                        "invalid_hermes_delegation_route",
                        "Hermes delegation context route must equal '/ibvi-ads'",
                    )
                if deleg.tenant_ref != request.tenant_ref:
                    raise AdmissionError(
                        "hermes_delegation_tenant_mismatch",
                        "Hermes delegation tenant_ref does not match request.tenant_ref",
                    )
                if deleg.binding_ref != request.binding_ref:
                    raise AdmissionError(
                        "hermes_delegation_binding_mismatch",
                        "Hermes delegation binding_ref does not match request.binding_ref",
                    )
                if deleg.resource_scope_ref != request.resource_scope_ref:
                    raise AdmissionError(
                        "hermes_delegation_scope_mismatch",
                        "Hermes delegation resource_scope_ref does not match request.resource_scope_ref",
                    )
                deleg_issued_us = parse_timestamp_utc_micros(
                    deleg.issued_at_utc,
                    field_name="hermes_delegation.issued_at_utc",
                    allow_whole_seconds=True,
                )
                deleg_valid_until_us = parse_timestamp_utc_micros(
                    deleg.valid_until_utc,
                    field_name="hermes_delegation.valid_until_utc",
                    allow_whole_seconds=True,
                )
                if lower_us < deleg_issued_us:
                    raise AdmissionError(
                        "future_hermes_delegation",
                        "authenticated clock lower bound precedes Hermes delegation issued_at_utc",
                    )
                if upper_us > deleg_valid_until_us:
                    raise AdmissionError(
                        "expired_hermes_delegation",
                        "authenticated clock upper bound exceeds Hermes delegation valid_until_utc",
                    )
                deleg_authorized = any(
                    rel.front_ref == deleg.front_ref
                    and rel.profile_ref == deleg.profile_ref
                    and rel.binding_ref == deleg.binding_ref
                    and rel.resource_scope_ref == deleg.resource_scope_ref
                    for rel in snapshot.authorized_scopes
                )
                if not deleg_authorized:
                    raise AdmissionError(
                        "unauthorized_hermes_delegation_scope",
                        "no authorized_scopes relation permits Hermes delegation "
                        f"({deleg.front_ref!r}, {deleg.profile_ref!r}, "
                        f"{deleg.binding_ref!r}, {deleg.resource_scope_ref!r})",
                    )

    # 6. Construct immutable AdmittedCollection & sign/store if signer_port is configured
    admitted = AdmittedCollection(
        admission_id=checked_admission_id,
        collection_purpose=request.collection_purpose,
        external_request_digest=request.external_request_digest,
        tenant_ref=request.tenant_ref,
        binding_ref=request.binding_ref,
        account_ref=binding.account_ref,
        resource_scope_ref=request.resource_scope_ref,
        resource_level=request.resource_level,
        requested_capabilities=request.requested_capabilities,
        admitted_at_utc=admitted_at_utc,
        clock_attestation_locator=clock_state.locator,
        maximum_clock_uncertainty_ms=clock_state.configured_max_uncertainty_ms,
        tzdb_version=tz_rules.tzdb_version,
        reporting_timezone=tz_rules.timezone_name,
        computed_date_range=computed_date_range,
        registry_snapshot_locator=registry_state.locator,
        registry_snapshot_digest=registry_state.locator.content_digest,
        currency=binding.currency,
        driver_id=binding.driver_id,
        driver_contract_locator=registry_state.driver_contract_locator,
        driver_contract_digest=registry_state.driver_contract_locator.content_digest,
        driver_capability_snapshot_digest=driver_capability_snapshot_digest,
        canonical_query_contract=canonical_query,
        canonical_query_digest=canonical_query.canonical_query_digest,
        purpose_prerequisite_locators=prereq.locators,
        required_effect_roles=PURPOSE_REQUIRED_EFFECT_ROLES[
            request.collection_purpose
        ],
    )

    if ports.signer_port is not None:
        unsigned_admitted = admitted
        domain_prefix = ADR_P1_DOMAIN_PREFIXES[AdmittedCollection.SCHEMA]
        sign_out = ports.signer_port.sign_and_store(
            unsigned_admitted.to_dict(), domain_prefix=domain_prefix
        )
        if not isinstance(sign_out, tuple) or len(sign_out) != 2:
            raise AdmissionError(
                "invalid_signer_response",
                "signer_port.sign_and_store must return a 2-tuple of (signed_dict, ArtifactLocator)",
            )
        signed_dict, admitted_locator = sign_out
        admitted = AdmittedCollection.from_dict(
            signed_dict, require_signed=True
        )
        if replace(admitted, integrity=None) != unsigned_admitted:
            raise AdmissionError(
                "signed_admission_payload_mismatch",
                "signer_port mutated AdmittedCollection payload fields outside integrity",
            )
        expected_loc = ArtifactLocator.for_canonical_bytes(
            AdmittedCollection.SCHEMA,
            canonicalize_jcs(admitted.to_dict()),
        )
        if admitted_locator != expected_loc:
            raise AdmissionError(
                "signed_admission_locator_mismatch",
                "signer_port returned an ArtifactLocator inconsistent with signed AdmittedCollection",
            )
    else:
        admitted_locator = ArtifactLocator.for_canonical_bytes(
            AdmittedCollection.SCHEMA,
            canonicalize_jcs(admitted.to_dict()),
        )

    return AdmittedCollectionBundle(
        admitted=admitted,
        locator=admitted_locator,
        registry_snapshot=snapshot,
        driver_contract=registry_state.driver_contract,
    )


def admit_collection(
    request: CollectionRequest,
    ports: CellRuntimePorts,
    *,
    admission_id: str,
) -> AdmittedCollectionBundle:
    """Resolve cell state and admit `CollectionRequest` with zero external I/O on failure."""
    try:
        return _admit_collection_unchecked(
            request, ports, admission_id=admission_id
        )
    except AdmissionError:
        raise
    except AmbiguousLocalDayError as exc:
        raise AdmissionError("ambiguous_local_day", str(exc)) from exc
    except ClosedValidationError as exc:
        raise AdmissionError("admission_validation_failed", str(exc)) from exc


__all__ = [
    "AdmissionError",
    "AdmittedCollectionBundle",
    "admit_collection",
]
