"""Fail-closed trusted admission before any credential lookup, reservation, or RPC (ADR-0001 §4.2)."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
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
    if (
        registry_state.driver_contract_locator.artifact_type
        != PipeboardPhase1Contract.SCHEMA
    ):
        raise AdmissionError(
            "invalid_driver_contract_locator",
            f"expected locator artifact_type {PipeboardPhase1Contract.SCHEMA!r}",
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

    # 5. Purpose-specific prerequisites & live certification / renewal verification
    prereq = ports.prerequisite_port.resolve_prerequisites(
        request=request,
        canonical_query=canonical_query,
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

    if request.collection_purpose == "fixture_7a":
        if (
            prereq.gate3_7b_selection_role is not None
            or prereq.live_certification is not None
        ):
            raise AdmissionError(
                "unexpected_live_prerequisite_metadata",
                "fixture_7a forbids 7B selection role or live certification state",
            )
    elif request.collection_purpose == "live_verification_7b":
        if prereq.gate3_7b_selection_role != "certification":
            raise AdmissionError(
                "invalid_gate3_selection_role",
                "live_verification_7b requires gate3_7b_selection_role == 'certification'",
            )
        if prereq.live_certification is not None:
            raise AdmissionError(
                "unexpected_live_certification_state",
                "live_verification_7b forbids operational live_certification state",
            )
    elif request.collection_purpose == "operational_read":
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
        if (
            live_cert.renewal_fingerprint_digest
            != live_cert.certified_fingerprint_digest
        ):
            raise AdmissionError(
                "renewal_fingerprint_mismatch",
                "operational_renewal fingerprint must equal certified_fingerprint_digest",
            )
        cert_valid_until_us = parse_timestamp_utc_micros(
            live_cert.certificate_valid_until_utc,
            field_name="certificate_valid_until_utc",
            allow_whole_seconds=True,
        )
        if upper_us > cert_valid_until_us:
            raise AdmissionError(
                "expired_live_certificate",
                "authenticated clock upper bound exceeds live_certification_certificate valid_until_utc",
            )
        if (
            ports.require_hermes_delegation
            and prereq.locators.delegation_context_locator is None
        ):
            raise AdmissionError(
                "missing_hermes_delegation_context",
                "Hermes operational traffic requires runtime-owned ibvi_ads_delegation_context/v1",
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
        domain_prefix = ADR_P1_DOMAIN_PREFIXES[AdmittedCollection.SCHEMA]
        signed_dict, admitted_locator = ports.signer_port.sign_and_store(
            admitted.to_dict(), domain_prefix=domain_prefix
        )
        admitted = AdmittedCollection.from_dict(
            signed_dict, require_signed=True
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
