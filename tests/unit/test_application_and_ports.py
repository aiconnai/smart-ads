"""Unit tests for smart_ads.ports and smart_ads.application (ADR-0001 §§4.1, 4.2, 12.1)."""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from pathlib import Path
import subprocess
from typing import Any

import pytest

import smart_ads.application as application_pkg
from smart_ads.application import (
    AdmissionError,
    AdmittedCollectionBundle,
    CompletenessEvaluation,
    CompletenessStatus,
    FixtureCollectionEvaluation,
    LiveCallExecutionOutcome,
    PurposeEntrypointMismatchError,
    admit_collection,
    build_expected_fact_universe,
    collect,
    evaluate_fixture_collection,
    execute_admitted_call,
    recompute_collection_completeness,
)
from smart_ads.contracts import (
    ADR_P1_DOMAIN_PREFIXES,
    ArtifactLocator,
    CallSide,
    CanonicalQueryContract,
    ClosedValidationError,
    CollectionPurpose,
    CollectionRequest,
    CollectionResult,
    DateRange,
    FactKey,
    NormalizedCollectionFact,
    NormalizedProviderError,
    P1Integrity,
    PurposePrerequisiteLocators,
    RetrievalContext,
    TransportOutcome,
    canonicalize_jcs,
    compute_normalized_fact_set_digest,
    jcs_sha256,
    parse_timestamp_utc_micros,
)
from smart_ads.domain import (
    FORBIDDEN_PIPEBOARD_ARGUMENTS,
    PINNED_LEGACY_COMMIT,
    PINNED_LEGACY_REPO,
    PINNED_PIPEBOARD_D26_SPECS,
    PIPEBOARD_PHASE1_METRIC_SOURCE_MAPPINGS,
    AuthorizedScopeRelation,
    CapabilityState,
    DriverCapabilityEntry,
    ExpectedResourceInventory,
    ExpectedResourceKey,
    LegacySourcePacket,
    PinnedGitArtifactMember,
    PinnedUpstreamReference,
    PipeboardPhase1Contract,
    PipeboardTransportLimits,
    PrivateRegistrySnapshot,
    RegistryBinding,
    TenantResourceKeyHandle,
    derive_resource_ref,
)
import smart_ads.ports as ports_pkg
from smart_ads.ports import (
    AdmittedFixtureCall,
    AdmittedProviderCall,
    AmbiguousLocalDayError,
    CellRuntimePorts,
    ClockAttestation,
    ClockAttestationPort,
    EnvelopeSignerPort,
    ExpectedInventoryPort,
    ExternalIOCounters,
    FixtureObservationPort,
    ProtectedRegistryPort,
    ProviderObservationBatch,
    ProviderPort,
    PurposePrerequisitePort,
    ReservationPort,
    ResolvedClockState,
    ResolvedLiveCertificationState,
    ResolvedPrerequisiteBundle,
    ResolvedRegistryState,
    SanitizedMetricObservation,
    SanitizedResourceObservation,
    TimezonePolicyPort,
    TimezoneRuleSnapshot,
    UtcOffsetTransition,
)
from tools.governance import p1 as gov_p1


# ---------------------------------------------------------------------------
# Deterministic fixtures & Spy ports
# ---------------------------------------------------------------------------


def _loc(artifact_type: str, fill: str = "a") -> ArtifactLocator:
    return ArtifactLocator.from_digest(artifact_type, "sha256:" + (fill * 64))


def _make_key_handle() -> TenantResourceKeyHandle:
    return TenantResourceKeyHandle(
        tenant_ref="tenant:ibvi",
        key_identity="key:tenant-ibvi-hmac-v1",
        secret_bytes=b"0123456789abcdef0123456789abcdef_secret",
    )


def _campaign_ref(raw_id: str) -> str:
    return derive_resource_ref(
        key_handle=_make_key_handle(),
        mapping_version="hmac-sha256-b32-v1",
        domain_separator="0x00",
        ad_platform_ref="meta",
        resource_level="campaign",
        raw_provider_id=raw_id,
    )


CAMPAIGN_REF_A = _campaign_ref("12021000000001")
CAMPAIGN_REF_B = _campaign_ref("12021000000002")
CAMPAIGN_REF_EXTRA = _campaign_ref("12021000000999")


def _make_pipeboard_contract() -> PipeboardPhase1Contract:
    fills = ("1", "2", "3", "4", "5")
    members = tuple(
        PinnedGitArtifactMember(
            role=role,
            repository=PINNED_LEGACY_REPO,
            commit_sha=PINNED_LEGACY_COMMIT,
            path=path,
            git_blob_oid=blob_oid,
            file_content_sha256=file_sha,
            git_artifact_provenance_locator=_loc(
                "smart_ads/git_artifact_provenance/v1", fill
            ),
        )
        for (role, path, blob_oid, file_sha), fill in zip(
            PINNED_PIPEBOARD_D26_SPECS, fills, strict=True
        )
    )
    return PipeboardPhase1Contract(
        contract_id="driver-contract:pipeboard-phase1-v1",
        driver_id="pipeboard_hosted",
        legacy_source_packet=LegacySourcePacket(
            repository=PINNED_LEGACY_REPO,
            commit_sha=PINNED_LEGACY_COMMIT,
            members=members,
        ),
        upstream_reference=PinnedUpstreamReference(),
        transport_limits=PipeboardTransportLimits(
            forbidden_arguments=FORBIDDEN_PIPEBOARD_ARGUMENTS,
        ),
        metric_source_mappings=dict(PIPEBOARD_PHASE1_METRIC_SOURCE_MAPPINGS),
    )


def _make_registry_state(
    *,
    cap_state: CapabilityState = "live_certified",
    tenant_ref: str = "tenant:ibvi",
    issued_at_utc: str = "2026-11-11T00:00:00Z",
    valid_until_utc: str = "2026-11-12T00:00:00Z",
    include_scope_auth: bool = True,
    cap_driver_id: str = "pipeboard_hosted",
    cap_contract_loc: ArtifactLocator | None = None,
) -> ResolvedRegistryState:
    contract = _make_pipeboard_contract()
    contract_loc = ArtifactLocator.for_canonical_bytes(
        PipeboardPhase1Contract.SCHEMA,
        canonicalize_jcs(contract.to_dict()),
    )
    effective_cap_contract_loc = (
        contract_loc if cap_contract_loc is None else cap_contract_loc
    )
    b_primary = RegistryBinding(
        binding_ref="binding:meta-primary",
        account_ref="account:ibvi-01",
        transport_provider_ref="provider:pipeboard",
        ad_platform_ref="meta",
        currency="BRL",
        driver_id="pipeboard_hosted",
    )
    b_other = RegistryBinding(
        binding_ref="binding:meta-other",
        account_ref="account:ibvi-02",
        transport_provider_ref="provider:pipeboard",
        ad_platform_ref="meta",
        currency="BRL",
        driver_id="pipeboard_hosted",
    )
    scopes: list[AuthorizedScopeRelation] = [
        AuthorizedScopeRelation(
            front_ref="front:ibvi",
            profile_ref="profile:reader",
            binding_ref="binding:meta-other",
            resource_scope_ref="scope:campaigns-other",
        )
    ]
    if include_scope_auth:
        scopes.append(
            AuthorizedScopeRelation(
                front_ref="front:ibvi",
                profile_ref="profile:reader",
                binding_ref="binding:meta-primary",
                resource_scope_ref="scope:campaigns-active",
            )
        )
    cap_entry = DriverCapabilityEntry(
        capability_ref="cap:campaign-basic-v1",
        capability_semantic_version="1.0.0",
        driver_id=cap_driver_id,
        driver_contract_locator=effective_cap_contract_loc,
        driver_contract_digest=effective_cap_contract_loc.content_digest,
        resource_scope_ref="scope:campaigns-active",
        state=cap_state,
        required_metrics=(
            "metric:clicks_v1",
            "metric:impressions_v1",
            "metric:spend_v1",
        ),
    )
    snapshot = PrivateRegistrySnapshot(
        snapshot_id="registry-snapshot:2026-11-11-001",
        tenant_ref=tenant_ref,
        issued_at_utc=issued_at_utc,
        valid_until_utc=valid_until_utc,
        resource_ref_mapping_version="hmac-sha256-b32-v1",
        key_identity="key:tenant-ibvi-hmac-v1",
        bindings=(b_primary, b_other),
        authorized_scopes=tuple(scopes),
        capabilities=(cap_entry,),
    )
    snap_loc = ArtifactLocator.for_canonical_bytes(
        PrivateRegistrySnapshot.SCHEMA,
        canonicalize_jcs(snapshot.to_dict()),
    )
    return ResolvedRegistryState(
        locator=snap_loc,
        snapshot=snapshot,
        driver_contract_locator=contract_loc,
        driver_contract=contract,
    )


def _make_clock_state(
    *,
    now_utc: str = "2026-11-11T15:00:00.250000Z",
    uncertainty_ms: int = 500,
    issued_at_utc: str = "2026-11-11T14:59:50Z",
    valid_until_utc: str = "2026-11-11T15:00:30Z",
    maximum_age_seconds: int = 30,
    configured_max_uncertainty_ms: int = 1000,
    locator_override: ArtifactLocator | None = None,
) -> ResolvedClockState:
    attestation = ClockAttestation(
        attestation_id="clock:att-2026-11-11-001",
        now_utc=now_utc,
        uncertainty_ms=uncertainty_ms,
        issued_at_utc=issued_at_utc,
        valid_until_utc=valid_until_utc,
        maximum_age_seconds=maximum_age_seconds,
    )
    loc = (
        ArtifactLocator.for_canonical_bytes(
            ClockAttestation.SCHEMA,
            canonicalize_jcs(attestation.to_dict()),
        )
        if locator_override is None
        else locator_override
    )
    return ResolvedClockState(
        locator=loc,
        attestation=attestation,
        configured_max_uncertainty_ms=configured_max_uncertainty_ms,
    )


def _make_sao_paulo_tz_rules(
    *,
    tzdb_version: str = "2026a",
    transitions: tuple[UtcOffsetTransition, ...] | None = None,
) -> TimezoneRuleSnapshot:
    effective_transitions = (
        (
            UtcOffsetTransition(
                effective_from_utc_micros=parse_timestamp_utc_micros(
                    "2020-01-01T00:00:00Z", allow_whole_seconds=True
                ),
                utc_offset_seconds=-10_800,
            ),
        )
        if transitions is None
        else transitions
    )
    return TimezoneRuleSnapshot(
        timezone_name="America/Sao_Paulo",
        tzdb_version=tzdb_version,
        transitions=effective_transitions,
    )


def _make_prereq_bundle(
    purpose: CollectionPurpose,
    *,
    gate3_7b_selection_role: str | None = "certification",
    renewal_selection_role: str = "operational_renewal",
    certified_fp: str = "sha256:" + ("c" * 64),
    renewal_fp: str = "sha256:" + ("c" * 64),
    certificate_valid_until_utc: str = "2026-11-12T00:00:00Z",
    include_delegation_context: bool = False,
    omit_live_cert: bool = False,
    mismatch_head_locator: bool = False,
) -> ResolvedPrerequisiteBundle:
    if purpose == "fixture_7a":
        return ResolvedPrerequisiteBundle(
            locators=PurposePrerequisiteLocators(
                purpose="fixture_7a",
                sealed_sandbox_profile_locator=_loc(
                    "smart_ads/sealed_sandbox_profile/v1", "1"
                ),
                regression_fixture_locator=_loc(
                    "smart_ads/regression_fixture/v1", "2"
                ),
            ),
        )
    if purpose == "live_verification_7b":
        return ResolvedPrerequisiteBundle(
            locators=PurposePrerequisiteLocators(
                purpose="live_verification_7b",
                legacy_step2_evidence_locator=_loc(
                    "smart_ads/legacy_step2_implementation_evidence/v1", "3"
                ),
                live_read_activation_receipt_locator=_loc(
                    "smart_ads/smart_ads_live_read_activation_receipt/v1", "4"
                ),
                gate3_selection_receipt_locator=_loc(
                    "smart_ads/gate3_selection_receipt/v1", "5"
                ),
                workload_identity_effect_proof_locator=_loc(
                    "smart_ads/effect_proof/v1", "6"
                ),
                deployment_effect_proof_locator=_loc(
                    "smart_ads/effect_proof/v1", "7"
                ),
            ),
            gate3_7b_selection_role=gate3_7b_selection_role,
        )

    head_loc = _loc("smart_ads/live_certification_head/v1", "8")
    tr_loc = _loc("smart_ads/live_certification_transition/v1", "9")
    cert_loc = _loc("smart_ads/live_certification_certificate/v1", "a")
    delegation_loc = (
        _loc("smart_ads/ibvi_ads_delegation_context/v1", "b")
        if include_delegation_context
        else None
    )
    live_cert = (
        None
        if omit_live_cert
        else ResolvedLiveCertificationState(
            head_locator=(
                _loc("smart_ads/live_certification_head/v1", "f")
                if mismatch_head_locator
                else head_loc
            ),
            transition_locator=tr_loc,
            certificate_locator=cert_loc,
            certified_fingerprint_digest=certified_fp,
            certificate_valid_until_utc=certificate_valid_until_utc,
            renewal_selection_role=renewal_selection_role,
            renewal_fingerprint_digest=renewal_fp,
        )
    )
    return ResolvedPrerequisiteBundle(
        locators=PurposePrerequisiteLocators(
            purpose="operational_read",
            legacy_step2_evidence_locator=_loc(
                "smart_ads/legacy_step2_implementation_evidence/v1", "3"
            ),
            live_read_activation_receipt_locator=_loc(
                "smart_ads/smart_ads_live_read_activation_receipt/v1", "4"
            ),
            live_certification_head_locator=head_loc,
            live_certification_transition_locator=tr_loc,
            live_certification_certificate_locator=cert_loc,
            gate3_operational_renewal_locator=_loc(
                "smart_ads/gate3_selection_receipt/v1", "5"
            ),
            workload_identity_effect_proof_locator=_loc(
                "smart_ads/effect_proof/v1", "6"
            ),
            deployment_effect_proof_locator=_loc(
                "smart_ads/effect_proof/v1", "7"
            ),
            delegation_context_locator=delegation_loc,
        ),
        live_certification=live_cert,
    )


def _make_request(
    purpose: CollectionPurpose = "operational_read",
    *,
    binding_ref: str = "binding:meta-primary",
    resource_scope_ref: str = "scope:campaigns-active",
    requested_capabilities: tuple[str, ...] = ("cap:campaign-basic-v1",),
) -> CollectionRequest:
    return CollectionRequest(
        request_id="req-2026-11-11-001",
        collection_purpose=purpose,
        tenant_ref="tenant:ibvi",
        binding_ref=binding_ref,
        resource_scope_ref=resource_scope_ref,
        date_rule="previous_local_day",
        resource_level="campaign",
        requested_capabilities=requested_capabilities,
        breakdowns=(),
    )


def _make_expected_inventory(
    *,
    registry_snapshot_locator: ArtifactLocator,
    metric_date: str = "2026-11-10",
    campaign_refs: tuple[str, ...] = (CAMPAIGN_REF_A, CAMPAIGN_REF_B),
) -> ExpectedResourceInventory:
    return ExpectedResourceInventory(
        inventory_id="inventory:ibvi-2026-11-10",
        registry_snapshot_locator=registry_snapshot_locator,
        registry_snapshot_digest=registry_snapshot_locator.content_digest,
        tenant_ref="tenant:ibvi",
        binding_ref="binding:meta-primary",
        account_ref="account:ibvi-01",
        resource_scope_ref="scope:campaigns-active",
        date_range=DateRange(
            start_date=metric_date, end_date=metric_date, inclusive=True
        ),
        expected_resources=tuple(
            ExpectedResourceKey(
                binding_ref="binding:meta-primary",
                account_ref="account:ibvi-01",
                resource_ref=ref,
                resource_level="campaign",
                metric_date=metric_date,
            )
            for ref in campaign_refs
        ),
    )


def _ok_transport_outcome(**overrides: Any) -> TransportOutcome:
    base: dict[str, Any] = {
        "network_ok": True,
        "http_status": 200,
        "media_and_encoding_valid": True,
        "auth_ok": True,
        "jsonrpc_error": False,
        "payload_schema_valid": True,
        "response_date_mismatch": False,
        "truncated_2mib": False,
        "non_empty_continuation": False,
        "reducer_order_or_count_mismatch": False,
        "duplicate_provider_observation": False,
    }
    base.update(overrides)
    return TransportOutcome(**base)


def _retrieval_context(
    retrieved_at_utc: str = "2026-11-11T15:00:05.123456Z",
) -> RetrievalContext:
    return RetrievalContext(
        retrieved_at_utc=retrieved_at_utc,
        source_observation_ref="observation:pipeboard-batch-001",
        adapter_version="pipeboard-adapter-0.1.0",
        semantic_version="phase1-v1",
    )


def _full_campaign_observations(
    resource_ref: str,
    *,
    metric_date: str = "2026-11-10",
    clicks: str = "15",
    impressions: str = "1000",
    spend_minor: str = "4590",
) -> SanitizedResourceObservation:
    return SanitizedResourceObservation(
        resource_ref=resource_ref,
        metric_date=metric_date,
        metric_observations=(
            SanitizedMetricObservation(
                metric_semantic_ref="metric:clicks_v1",
                presence_status="observed",
                value_type="int64_count",
                raw_numeric_value=clicks,
                unit="count",
                currency=None,
            ),
            SanitizedMetricObservation(
                metric_semantic_ref="metric:impressions_v1",
                presence_status="observed",
                value_type="int64_count",
                raw_numeric_value=impressions,
                unit="count",
                currency=None,
            ),
            SanitizedMetricObservation(
                metric_semantic_ref="metric:spend_v1",
                presence_status="observed",
                value_type="int64_minor_currency",
                raw_numeric_value=spend_minor,
                unit="minor_currency",
                currency="BRL",
            ),
        ),
    )


@dataclass
class StaticClockPort:
    state: ResolvedClockState
    calls: int = 0

    def get_authenticated_clock(self) -> ResolvedClockState:
        self.calls += 1
        return self.state


@dataclass
class StaticTimezonePort:
    rules: Any
    calls: int = 0

    def get_reporting_timezone_rules(self) -> TimezoneRuleSnapshot:
        self.calls += 1
        if callable(self.rules):
            return self.rules()
        return self.rules


@dataclass
class StaticRegistryPort:
    state: ResolvedRegistryState
    calls: int = 0

    def get_active_registry(self, *, tenant_ref: str) -> ResolvedRegistryState:
        self.calls += 1
        return self.state


@dataclass
class StaticPrerequisitePort:
    bundle: ResolvedPrerequisiteBundle
    calls: int = 0

    def resolve_prerequisites(
        self,
        *,
        request: CollectionRequest,
        canonical_query: CanonicalQueryContract,
    ) -> ResolvedPrerequisiteBundle:
        self.calls += 1
        return self.bundle


@dataclass
class SpyReservationPort:
    calls: list[tuple[ArtifactLocator, CallSide]] = field(default_factory=list)

    def reserve_admitted_call(
        self,
        *,
        admitted_collection_locator: ArtifactLocator,
        call_side: CallSide,
    ) -> ArtifactLocator:
        self.calls.append((admitted_collection_locator, call_side))
        fill = {"operational": "1", "candidate": "2", "reference": "3"}[call_side]
        return _loc("smart_ads/authorization_reservation_record/v1", fill)


@dataclass
class SpyProviderPort:
    batch: ProviderObservationBatch
    calls: list[AdmittedProviderCall] = field(default_factory=list)

    def fetch_observations(
        self, call: AdmittedProviderCall
    ) -> ProviderObservationBatch:
        self.calls.append(call)
        return self.batch


@dataclass
class SpyFixturePort:
    batch: ProviderObservationBatch
    calls: list[AdmittedFixtureCall] = field(default_factory=list)

    def load_fixture_observations(
        self, call: AdmittedFixtureCall
    ) -> ProviderObservationBatch:
        self.calls.append(call)
        return self.batch


@dataclass
class SpyInventoryPort:
    inventory: ExpectedResourceInventory | None
    calls: int = 0

    def resolve_expected_inventory(
        self,
        *,
        registry_snapshot_locator: ArtifactLocator,
        tenant_ref: str,
        binding_ref: str,
        account_ref: str,
        resource_scope_ref: str,
        date_range: DateRange,
    ) -> ExpectedResourceInventory | None:
        self.calls += 1
        return self.inventory


@dataclass
class Ed25519TestSignerPort:
    private_key_pem: Path
    key_id: str
    key_registry_locator: ArtifactLocator
    calls: list[tuple[str, str]] = field(default_factory=list)

    def sign_and_store(
        self, envelope_dict: dict[str, Any], *, domain_prefix: str
    ) -> tuple[dict[str, Any], ArtifactLocator]:
        schema = envelope_dict["$schema"]
        self.calls.append((schema, domain_prefix))
        unsigned_with_integrity = dict(
            envelope_dict,
            integrity={
                "key_id": self.key_id,
                "key_registry_snapshot_locator": self.key_registry_locator.to_dict(),
            },
        )
        signed = gov_p1.sign_envelope(
            unsigned_with_integrity, domain_prefix, self.private_key_pem
        )
        loc = ArtifactLocator.for_canonical_bytes(
            schema, canonicalize_jcs(signed)
        )
        return signed, loc


def _make_default_live_batch() -> ProviderObservationBatch:
    return ProviderObservationBatch(
        observed_capabilities=("cap:campaign-basic-v1",),
        retrieval_context=_retrieval_context(),
        transport_outcome=_ok_transport_outcome(),
        resource_observations=(
            _full_campaign_observations(CAMPAIGN_REF_B, clicks="0", impressions="500", spend_minor="0"),
            _full_campaign_observations(CAMPAIGN_REF_A, clicks="12", impressions="1200", spend_minor="3450"),
        ),
        normalized_errors=(),
        io_counters=ExternalIOCounters(
            credential_lookups=1,
            token_decryptions=1,
            socket_creations=1,
            provider_rpc_calls=1,
        ),
    )


# ---------------------------------------------------------------------------
# 1. Public package surface & Protocol conformance
# ---------------------------------------------------------------------------


def test_ports_and_application_packages_reexport_all_public_symbols() -> None:
    expected_ports = {
        "ExternalIOCounters",
        "SanitizedMetricObservation",
        "SanitizedResourceObservation",
        "AdmittedProviderCall",
        "ProviderObservationBatch",
        "ProviderPort",
        "AdmittedFixtureCall",
        "FixtureObservationPort",
        "AmbiguousLocalDayError",
        "ClockAttestation",
        "UtcOffsetTransition",
        "TimezoneRuleSnapshot",
        "ResolvedClockState",
        "ResolvedRegistryState",
        "ResolvedLiveCertificationState",
        "ResolvedPrerequisiteBundle",
        "ClockAttestationPort",
        "TimezonePolicyPort",
        "ProtectedRegistryPort",
        "PurposePrerequisitePort",
        "ExpectedInventoryPort",
        "ReservationPort",
        "EnvelopeSignerPort",
        "CellRuntimePorts",
    }
    assert expected_ports.issubset(set(ports_pkg.__all__))
    for name in expected_ports:
        assert hasattr(ports_pkg, name)

    expected_app = {
        "CompletenessStatus",
        "CompletenessEvaluation",
        "build_expected_fact_universe",
        "recompute_collection_completeness",
        "AdmissionError",
        "AdmittedCollectionBundle",
        "admit_collection",
        "PurposeEntrypointMismatchError",
        "LiveCallExecutionOutcome",
        "FixtureCollectionEvaluation",
        "execute_admitted_call",
        "evaluate_fixture_collection",
        "collect",
    }
    assert expected_app.issubset(set(application_pkg.__all__))
    for name in expected_app:
        assert hasattr(application_pkg, name)


# ---------------------------------------------------------------------------
# 2. Zero-I/O ProviderPort & narrow sanitized observation types
# ---------------------------------------------------------------------------


def test_external_io_counters_zero_roundtrip_and_strict_int_validation() -> None:
    zero = ExternalIOCounters.zero()
    assert zero.is_zero is True
    assert zero == ExternalIOCounters(0, 0, 0, 0)
    assert ExternalIOCounters.from_dict(zero.to_dict()) == zero

    non_zero = ExternalIOCounters(provider_rpc_calls=1)
    assert non_zero.is_zero is False
    assert ExternalIOCounters.from_dict(non_zero.to_dict()) == non_zero

    for bad_kwargs in (
        {"credential_lookups": True},
        {"token_decryptions": False},
        {"socket_creations": -1},
        {"provider_rpc_calls": -5},
        {"credential_lookups": "0"},  # type: ignore[dict-item]
    ):
        with pytest.raises(ClosedValidationError):
            ExternalIOCounters(**bad_kwargs)  # type: ignore[arg-type]

    with pytest.raises(ClosedValidationError):
        ExternalIOCounters.from_dict({**zero.to_dict(), "extra": 0})


def test_sanitized_observations_enforce_narrow_tuple_and_numeric_matrix() -> None:
    obs = _full_campaign_observations(CAMPAIGN_REF_A)
    assert SanitizedResourceObservation.from_dict(obs.to_dict()) == obs

    tombstone_metric = SanitizedMetricObservation(
        metric_semantic_ref="metric:spend_v1",
        presence_status="retracted_tombstone",
        value_type=None,
        raw_numeric_value=None,
        unit=None,
        currency=None,
    )
    assert SanitizedMetricObservation.from_dict(tombstone_metric.to_dict()) == tombstone_metric

    # Reject non-BRL currency, native ints/floats, mismatched metric vs value_type
    with pytest.raises(ClosedValidationError):
        SanitizedMetricObservation(
            metric_semantic_ref="metric:spend_v1",
            presence_status="observed",
            value_type="int64_minor_currency",
            raw_numeric_value="100",
            unit="minor_currency",
            currency="USD",
        )
    with pytest.raises(ClosedValidationError):
        SanitizedMetricObservation(
            metric_semantic_ref="metric:clicks_v1",
            presence_status="observed",
            value_type="int64_count",
            raw_numeric_value=10,  # type: ignore[arg-type]
            unit="count",
            currency=None,
        )
    with pytest.raises(ClosedValidationError):
        SanitizedMetricObservation(
            metric_semantic_ref="metric:clicks_v1",
            presence_status="observed",
            value_type="int64_minor_currency",
            raw_numeric_value="100",
            unit="minor_currency",
            currency="BRL",
        )

    # Reject non-canonical resource_ref and raw provider identifiers/fields
    for bad_ref in ("12021000000001", "resource:campaign-123", "campaign:123"):
        with pytest.raises(ClosedValidationError):
            SanitizedResourceObservation(
                resource_ref=bad_ref,
                metric_date="2026-11-10",
                metric_observations=obs.metric_observations,
            )

    for forbidden_field in (
        "campaign_id",
        "object_id",
        "account_id",
        "url",
        "headers",
        "after",
        "access_token",
    ):
        with pytest.raises(TypeError):
            SanitizedResourceObservation(  # type: ignore[call-arg]
                resource_ref=CAMPAIGN_REF_A,
                metric_date="2026-11-10",
                metric_observations=obs.metric_observations,
                **{forbidden_field: "leaked"},
            )
        with pytest.raises(ClosedValidationError):
            SanitizedResourceObservation.from_dict(
                {**obs.to_dict(), forbidden_field: "leaked"}
            )


def test_admitted_provider_call_and_fixture_call_contracts() -> None:
    cqc = CanonicalQueryContract(
        tenant_ref="tenant:ibvi",
        binding_ref="binding:meta-primary",
        account_ref="account:ibvi-01",
        resource_scope_ref="scope:campaigns-active",
        ad_platform_ref="meta",
        date_rule="previous_local_day",
        date_range=DateRange("2026-11-10", "2026-11-10", True),
        reporting_timezone="America/Sao_Paulo",
        tzdb_version="2026a",
        resource_level="campaign",
        metric_semantic_refs=("metric:clicks_v1", "metric:impressions_v1", "metric:spend_v1"),
        requested_capabilities=("cap:campaign-basic-v1",),
    )
    adm_loc = _loc("smart_ads/admitted_collection/v1", "a")
    res_loc = _loc("smart_ads/authorization_reservation_record/v1", "b")
    fix_loc = _loc("smart_ads/regression_fixture/v1", "c")

    live_call = AdmittedProviderCall(
        admitted_collection_locator=adm_loc,
        admitted_collection_digest=adm_loc.content_digest,
        call_side="operational",
        driver_id="pipeboard_hosted",
        driver_contract_digest="sha256:" + ("d" * 64),
        canonical_query=cqc,
        reservation_locator=res_loc,
    )
    assert AdmittedProviderCall.from_dict(live_call.to_dict()) == live_call

    # Wrong reservation locator artifact_type rejected
    with pytest.raises(ClosedValidationError):
        replace(live_call, reservation_locator=_loc("smart_ads/effect_proof/v1", "b"))

    fixture_call = AdmittedFixtureCall(
        admitted_collection_locator=adm_loc,
        admitted_collection_digest=adm_loc.content_digest,
        driver_id="pipeboard_hosted",
        driver_contract_digest="sha256:" + ("d" * 64),
        canonical_query=cqc,
        regression_fixture_locator=fix_loc,
    )
    assert AdmittedFixtureCall.from_dict(fixture_call.to_dict()) == fixture_call
    assert not hasattr(fixture_call, "call_side")
    assert not hasattr(fixture_call, "reservation_locator")
    assert "call_side" not in fixture_call.to_dict()
    assert "reservation_locator" not in fixture_call.to_dict()

    with pytest.raises(ClosedValidationError):
        replace(
            fixture_call,
            regression_fixture_locator=_loc("smart_ads/authorization_reservation_record/v1", "c"),
        )


# ---------------------------------------------------------------------------
# 3. ClockAttestation & pure UTC-micros TimezoneRuleSnapshot (P-07)
# ---------------------------------------------------------------------------


def test_clock_attestation_freshness_and_p1_roundtrip(tmp_path: Path) -> None:
    att = ClockAttestation(
        attestation_id="clock:att-001",
        now_utc="2026-11-11T15:00:10.000000Z",
        uncertainty_ms=500,
        issued_at_utc="2026-11-11T15:00:00Z",
        valid_until_utc="2026-11-11T15:00:30Z",
        maximum_age_seconds=15,
    )
    lower, upper = att.verify_freshness(configured_max_uncertainty_ms=1000)
    assert upper - lower == 1_000_000
    assert ClockAttestation.from_dict(att.to_dict()) == att

    # Signed P1 round-trip
    priv = tmp_path / "clock_ed25519.pem"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(priv)],
        check=True,
        capture_output=True,
    )
    pub_raw = gov_p1.raw_public_key_from_pem(priv)
    key_id = gov_p1.key_id_for(pub_raw)
    key_reg_loc = _loc("smart_ads/key_authorization_registry/v1", "9")
    signed_dict = gov_p1.sign_envelope(
        {
            **att.to_dict(),
            "integrity": {
                "key_id": key_id,
                "key_registry_snapshot_locator": key_reg_loc.to_dict(),
            },
        },
        ADR_P1_DOMAIN_PREFIXES[ClockAttestation.SCHEMA],
        priv,
    )
    signed_att = ClockAttestation.from_dict(signed_dict, require_signed=True)
    assert signed_att.integrity is not None and signed_att.integrity.is_signed

    # Uncertainty > configured bound
    with pytest.raises(ClosedValidationError):
        att.verify_freshness(configured_max_uncertainty_ms=499)

    # upper - issued == 10.5s > maximum_age_seconds=10
    stale_att = replace(att, maximum_age_seconds=10)
    with pytest.raises(ClosedValidationError):
        stale_att.verify_freshness(configured_max_uncertainty_ms=1000)

    # Future-issued: lower (14:59:59.5) < issued (15:00:00)
    future_att = replace(att, now_utc="2026-11-11T15:00:00.000000Z")
    with pytest.raises(ClosedValidationError):
        future_att.verify_freshness(configured_max_uncertainty_ms=1000)

    # Expired: upper (15:00:30.5) > valid_until (15:00:30)
    expired_att = replace(att, now_utc="2026-11-11T15:00:30.000000Z", maximum_age_seconds=60)
    with pytest.raises(ClosedValidationError):
        expired_att.verify_freshness(configured_max_uncertainty_ms=1000)


def test_timezone_rule_snapshot_pure_civil_date_midnight_and_dst_straddle() -> None:
    tz = _make_sao_paulo_tz_rules()
    assert issubclass(AmbiguousLocalDayError, ClosedValidationError)

    # Normal daytime interval -> previous local day 2026-11-10
    lower_ok = parse_timestamp_utc_micros("2026-11-11T14:59:59.000000Z")
    upper_ok = parse_timestamp_utc_micros("2026-11-11T15:00:01.000000Z")
    assert (
        tz.compute_previous_local_day(
            lower_utc_micros=lower_ok, upper_utc_micros=upper_ok
        )
        == "2026-11-10"
    )

    # Midnight straddle in America/Sao_Paulo (-10800s):
    # 2026-11-11T03:00:00.500000Z +/- 1000ms ->
    # lower = 2026-11-10T23:59:59.500000 local (2026-11-10)
    # upper = 2026-11-11T00:00:01.500000 local (2026-11-11)
    now_straddle = parse_timestamp_utc_micros("2026-11-11T03:00:00.500000Z")
    with pytest.raises(AmbiguousLocalDayError):
        tz.compute_previous_local_day(
            lower_utc_micros=now_straddle - 1_000_000,
            upper_utc_micros=now_straddle + 1_000_000,
        )

    # Uncovered timestamp before first transition
    before_rules = parse_timestamp_utc_micros("2019-12-31T23:59:59.000000Z")
    with pytest.raises(AmbiguousLocalDayError):
        tz.offset_seconds_at(before_rules)

    # Fall-back DST transition straddle inside (lower, upper] where lower & upper
    # have the SAME local date (2026-02-14), yet t - 1 crossed into 2026-02-15!
    t_init = parse_timestamp_utc_micros("2020-01-01T00:00:00Z", allow_whole_seconds=True)
    t_fallback = parse_timestamp_utc_micros("2026-02-15T02:00:00.500000Z")
    tz_fallback = TimezoneRuleSnapshot(
        timezone_name="America/Sao_Paulo",
        tzdb_version="2026a-dst-test",
        transitions=(
            UtcOffsetTransition(t_init, -7_200),  # UTC-2
            UtcOffsetTransition(t_fallback, -10_800),  # UTC-3 (falls back across midnight!)
        ),
    )
    lower_fb = parse_timestamp_utc_micros("2026-02-15T01:59:59.500000Z")
    upper_fb = parse_timestamp_utc_micros("2026-02-15T02:00:01.500000Z")
    assert tz_fallback.local_civil_date_at(lower_fb).isoformat() == "2026-02-14"
    assert tz_fallback.local_civil_date_at(upper_fb).isoformat() == "2026-02-14"
    with pytest.raises(AmbiguousLocalDayError):
        tz_fallback.compute_previous_local_day(
            lower_utc_micros=lower_fb, upper_utc_micros=upper_fb
        )

    # Validation errors on TimezoneRuleSnapshot
    with pytest.raises(ClosedValidationError):
        TimezoneRuleSnapshot(
            timezone_name="UTC",
            tzdb_version="2026a",
            transitions=tz.transitions,
        )
    with pytest.raises(ClosedValidationError):
        TimezoneRuleSnapshot(
            timezone_name="America/Sao_Paulo",
            tzdb_version="",
            transitions=tz.transitions,
        )
    with pytest.raises(ClosedValidationError):
        TimezoneRuleSnapshot(
            timezone_name="America/Sao_Paulo",
            tzdb_version="2026a",
            transitions=(),
        )


# ---------------------------------------------------------------------------
# 4. Fail-closed Admission with Spy ports (0 external I/O on ALL failures)
# ---------------------------------------------------------------------------


def _assert_zero_io_admission_failure(
    request: CollectionRequest,
    cell_ports: CellRuntimePorts,
    *,
    expected_reason_code: str | None = None,
) -> AdmissionError:
    spy_reservation = SpyReservationPort()
    spy_provider = SpyProviderPort(_make_default_live_batch())
    spy_fixture = SpyFixturePort(
        replace(_make_default_live_batch(), io_counters=ExternalIOCounters.zero())
    )
    spy_inventory = SpyInventoryPort(None)

    if request.collection_purpose == "operational_read":
        with pytest.raises(AdmissionError) as exc_info:
            collect(
                request,
                admission_id="admission:adm-fail-001",
                cell_ports=cell_ports,
                reservation_port=spy_reservation,
                provider_port=spy_provider,
                inventory_port=spy_inventory,
            )
    elif request.collection_purpose == "fixture_7a":
        with pytest.raises(AdmissionError) as exc_info:
            evaluate_fixture_collection(
                request,
                admission_id="admission:adm-fail-001",
                cell_ports=cell_ports,
                fixture_port=spy_fixture,
                inventory_port=spy_inventory,
            )
    else:
        with pytest.raises(AdmissionError) as exc_info:
            admit_collection(
                request,
                cell_ports,
                admission_id="admission:adm-fail-001",
            )

    err = exc_info.value
    assert err.counters == ExternalIOCounters.zero()
    assert err.counters.is_zero is True
    assert len(spy_reservation.calls) == 0
    assert len(spy_provider.calls) == 0
    assert len(spy_fixture.calls) == 0
    assert spy_inventory.calls == 0
    if expected_reason_code is not None:
        assert err.reason_code == expected_reason_code
    return err


def test_admission_clock_failures_emit_zero_io_counters() -> None:
    req = _make_request("operational_read")
    reg = _make_registry_state(cap_state="live_certified")
    tz = _make_sao_paulo_tz_rules()
    prereq = _make_prereq_bundle("operational_read")

    bad_clocks = (
        # Uncertainty > configured_max_uncertainty_ms
        (
            _make_clock_state(uncertainty_ms=1500, configured_max_uncertainty_ms=1000),
            "clock_freshness_failed",
        ),
        # Expired clock (upper > valid_until_utc)
        (
            _make_clock_state(
                now_utc="2026-11-11T15:00:30.000000Z",
                uncertainty_ms=500,
                valid_until_utc="2026-11-11T15:00:30Z",
                maximum_age_seconds=60,
            ),
            "clock_freshness_failed",
        ),
        # Future-issued clock (lower < issued_at_utc)
        (
            _make_clock_state(
                now_utc="2026-11-11T15:00:00.200000Z",
                uncertainty_ms=500,
                issued_at_utc="2026-11-11T15:00:00Z",
            ),
            "clock_freshness_failed",
        ),
        # upper - issued > maximum_age_seconds
        (
            _make_clock_state(
                now_utc="2026-11-11T15:00:10.000000Z",
                uncertainty_ms=500,
                issued_at_utc="2026-11-11T15:00:00Z",
                valid_until_utc="2026-11-11T15:00:30Z",
                maximum_age_seconds=10,
            ),
            "clock_freshness_failed",
        ),
        # Wrong clock locator type
        (
            _make_clock_state(
                locator_override=_loc("smart_ads/effect_proof/v1", "1"),
            ),
            "invalid_clock_locator",
        ),
    )

    for bad_clock, expected_code in bad_clocks:
        ports = CellRuntimePorts(
            clock_port=StaticClockPort(bad_clock),
            timezone_port=StaticTimezonePort(tz),
            registry_port=StaticRegistryPort(reg),
            prerequisite_port=StaticPrerequisitePort(prereq),
        )
        _assert_zero_io_admission_failure(
            req, ports, expected_reason_code=expected_code
        )


def test_admission_midnight_straddle_dst_straddle_and_bad_timezone_emit_zero_io() -> None:
    req = _make_request("operational_read")
    reg = _make_registry_state(cap_state="live_certified")
    prereq = _make_prereq_bundle("operational_read")

    # 1. Exact midnight straddle in America/Sao_Paulo (-10800s):
    # 2026-11-11T03:00:00.500000Z +/- 1000ms -> 2026-11-10T23:59:59.5 vs 2026-11-11T00:00:01.5
    midnight_clock = _make_clock_state(
        now_utc="2026-11-11T03:00:00.500000Z",
        uncertainty_ms=1000,
        issued_at_utc="2026-11-11T02:59:50Z",
        valid_until_utc="2026-11-11T03:00:20Z",
        maximum_age_seconds=30,
        configured_max_uncertainty_ms=1000,
    )
    midnight_ports = CellRuntimePorts(
        clock_port=StaticClockPort(midnight_clock),
        timezone_port=StaticTimezonePort(_make_sao_paulo_tz_rules()),
        registry_port=StaticRegistryPort(reg),
        prerequisite_port=StaticPrerequisitePort(prereq),
    )
    _assert_zero_io_admission_failure(
        req, midnight_ports, expected_reason_code="ambiguous_local_day"
    )

    # 2. DST / UTC-offset transition straddle inside [lower, upper]
    t_init = parse_timestamp_utc_micros("2020-01-01T00:00:00Z", allow_whole_seconds=True)
    t_spring = parse_timestamp_utc_micros("2026-11-11T03:00:00.000000Z")
    dst_tz = _make_sao_paulo_tz_rules(
        transitions=(
            UtcOffsetTransition(t_init, -10_800),
            UtcOffsetTransition(t_spring, -7_200),
        )
    )
    dst_clock = _make_clock_state(
        now_utc="2026-11-11T02:59:59.500000Z",
        uncertainty_ms=1000,
        issued_at_utc="2026-11-11T02:59:50Z",
        valid_until_utc="2026-11-11T03:00:20Z",
        maximum_age_seconds=30,
        configured_max_uncertainty_ms=1000,
    )
    dst_ports = CellRuntimePorts(
        clock_port=StaticClockPort(dst_clock),
        timezone_port=StaticTimezonePort(dst_tz),
        registry_port=StaticRegistryPort(reg),
        prerequisite_port=StaticPrerequisitePort(prereq),
    )
    _assert_zero_io_admission_failure(
        req, dst_ports, expected_reason_code="ambiguous_local_day"
    )

    # 3. Wrong timezone ("UTC") and empty tzdb_version ("")
    ok_clock = _make_clock_state()
    mutated_utc = _make_sao_paulo_tz_rules()
    object.__setattr__(mutated_utc, "timezone_name", "UTC")
    mutated_empty_ver = _make_sao_paulo_tz_rules()
    object.__setattr__(mutated_empty_ver, "tzdb_version", "")

    for bad_tz_factory, expected_code in (
        (
            lambda: TimezoneRuleSnapshot(
                timezone_name="UTC",
                tzdb_version="2026a",
                transitions=_make_sao_paulo_tz_rules().transitions,
            ),
            "invalid_timezone_policy",
        ),
        (
            lambda: TimezoneRuleSnapshot(
                timezone_name="America/Sao_Paulo",
                tzdb_version="",
                transitions=_make_sao_paulo_tz_rules().transitions,
            ),
            "invalid_timezone_policy",
        ),
        (mutated_utc, "unsupported_reporting_timezone"),
        (mutated_empty_ver, "invalid_timezone_policy"),
    ):
        bad_tz_ports = CellRuntimePorts(
            clock_port=StaticClockPort(ok_clock),
            timezone_port=StaticTimezonePort(bad_tz_factory),
            registry_port=StaticRegistryPort(reg),
            prerequisite_port=StaticPrerequisitePort(prereq),
        )
        _assert_zero_io_admission_failure(
            req, bad_tz_ports, expected_reason_code=expected_code
        )


@pytest.mark.parametrize(
    "denied_state",
    ("unavailable", "deferred", "invalidated", "revalidation_pending"),
)
@pytest.mark.parametrize(
    "purpose",
    ("fixture_7a", "live_verification_7b", "operational_read"),
)
def test_admission_rejects_all_four_io_denied_capability_states(
    denied_state: CapabilityState,
    purpose: CollectionPurpose,
) -> None:
    req = _make_request(purpose)
    ports = CellRuntimePorts(
        clock_port=StaticClockPort(_make_clock_state()),
        timezone_port=StaticTimezonePort(_make_sao_paulo_tz_rules()),
        registry_port=StaticRegistryPort(_make_registry_state(cap_state=denied_state)),
        prerequisite_port=StaticPrerequisitePort(_make_prereq_bundle(purpose)),
    )
    _assert_zero_io_admission_failure(
        req, ports, expected_reason_code="capability_io_denied"
    )


def test_admission_rejects_unauthorized_scope_and_insufficient_capability_states() -> None:
    clock = _make_clock_state()
    tz = _make_sao_paulo_tz_rules()

    # Unauthorized (binding_ref, resource_scope_ref)
    unauth_ports = CellRuntimePorts(
        clock_port=StaticClockPort(clock),
        timezone_port=StaticTimezonePort(tz),
        registry_port=StaticRegistryPort(_make_registry_state(include_scope_auth=False)),
        prerequisite_port=StaticPrerequisitePort(_make_prereq_bundle("operational_read")),
    )
    _assert_zero_io_admission_failure(
        _make_request("operational_read"),
        unauth_ports,
        expected_reason_code="unauthorized_binding_scope",
    )

    # Tenant mismatch
    wrong_tenant_ports = CellRuntimePorts(
        clock_port=StaticClockPort(clock),
        timezone_port=StaticTimezonePort(tz),
        registry_port=StaticRegistryPort(_make_registry_state(tenant_ref="tenant:other")),
        prerequisite_port=StaticPrerequisitePort(_make_prereq_bundle("operational_read")),
    )
    _assert_zero_io_admission_failure(
        _make_request("operational_read"),
        wrong_tenant_ports,
        expected_reason_code="tenant_mismatch",
    )

    # Expired registry snapshot
    expired_reg_ports = CellRuntimePorts(
        clock_port=StaticClockPort(clock),
        timezone_port=StaticTimezonePort(tz),
        registry_port=StaticRegistryPort(
            _make_registry_state(
                issued_at_utc="2026-11-11T00:00:00Z",
                valid_until_utc="2026-11-11T14:00:00Z",
            )
        ),
        prerequisite_port=StaticPrerequisitePort(_make_prereq_bundle("operational_read")),
    )
    _assert_zero_io_admission_failure(
        _make_request("operational_read"),
        expired_reg_ports,
        expected_reason_code="registry_snapshot_outside_validity_window",
    )

    # Insufficient state: declared for live_verification_7b
    declared_7b_ports = CellRuntimePorts(
        clock_port=StaticClockPort(clock),
        timezone_port=StaticTimezonePort(tz),
        registry_port=StaticRegistryPort(_make_registry_state(cap_state="declared")),
        prerequisite_port=StaticPrerequisitePort(_make_prereq_bundle("live_verification_7b")),
    )
    _assert_zero_io_admission_failure(
        _make_request("live_verification_7b"),
        declared_7b_ports,
        expected_reason_code="insufficient_capability_state",
    )

    # Insufficient state: fixture_certified for operational_read
    fixture_ops_ports = CellRuntimePorts(
        clock_port=StaticClockPort(clock),
        timezone_port=StaticTimezonePort(tz),
        registry_port=StaticRegistryPort(_make_registry_state(cap_state="fixture_certified")),
        prerequisite_port=StaticPrerequisitePort(_make_prereq_bundle("operational_read")),
    )
    _assert_zero_io_admission_failure(
        _make_request("operational_read"),
        fixture_ops_ports,
        expected_reason_code="insufficient_capability_state",
    )

    # Mismatched driver contract locator on capability
    bad_drv_loc_ports = CellRuntimePorts(
        clock_port=StaticClockPort(clock),
        timezone_port=StaticTimezonePort(tz),
        registry_port=StaticRegistryPort(
            _make_registry_state(
                cap_contract_loc=_loc("smart_ads/pipeboard_phase1_contract/v1", "f")
            )
        ),
        prerequisite_port=StaticPrerequisitePort(_make_prereq_bundle("operational_read")),
    )
    _assert_zero_io_admission_failure(
        _make_request("operational_read"),
        bad_drv_loc_ports,
        expected_reason_code="capability_driver_contract_mismatch",
    )


def test_admission_rejects_invalid_7b_and_operational_prerequisites() -> None:
    clock = _make_clock_state()
    tz = _make_sao_paulo_tz_rules()
    reg = _make_registry_state(cap_state="live_certified")

    # 7B with wrong selection role
    bad_7b_ports = CellRuntimePorts(
        clock_port=StaticClockPort(clock),
        timezone_port=StaticTimezonePort(tz),
        registry_port=StaticRegistryPort(reg),
        prerequisite_port=StaticPrerequisitePort(
            _make_prereq_bundle(
                "live_verification_7b",
                gate3_7b_selection_role="operational_renewal",
            )
        ),
    )
    _assert_zero_io_admission_failure(
        _make_request("live_verification_7b"),
        bad_7b_ports,
        expected_reason_code="invalid_gate3_selection_role",
    )

    # Operational read failures:
    ops_req = _make_request("operational_read")
    for bad_prereq, require_hermes, expected_code in (
        # Missing live_certification state
        (
            _make_prereq_bundle("operational_read", omit_live_cert=True),
            False,
            "missing_live_certification",
        ),
        # Mismatched renewal fingerprint
        (
            _make_prereq_bundle(
                "operational_read",
                certified_fp="sha256:" + ("c" * 64),
                renewal_fp="sha256:" + ("d" * 64),
            ),
            False,
            "renewal_fingerprint_mismatch",
        ),
        # Wrong renewal_selection_role
        (
            _make_prereq_bundle(
                "operational_read",
                renewal_selection_role="certification",
            ),
            False,
            "invalid_renewal_selection_role",
        ),
        # Expired certificate_valid_until_utc
        (
            _make_prereq_bundle(
                "operational_read",
                certificate_valid_until_utc="2026-11-11T14:59:59Z",
            ),
            False,
            "expired_live_certificate",
        ),
        # Head locator mismatch between live_certification and prerequisite locators
        (
            _make_prereq_bundle(
                "operational_read",
                mismatch_head_locator=True,
            ),
            False,
            "live_certification_locator_mismatch",
        ),
        # Missing delegation_context_locator when require_hermes_delegation=True
        (
            _make_prereq_bundle(
                "operational_read",
                include_delegation_context=False,
            ),
            True,
            "missing_hermes_delegation_context",
        ),
    ):
        ports = CellRuntimePorts(
            clock_port=StaticClockPort(clock),
            timezone_port=StaticTimezonePort(tz),
            registry_port=StaticRegistryPort(reg),
            prerequisite_port=StaticPrerequisitePort(bad_prereq),
            require_hermes_delegation=require_hermes,
        )
        _assert_zero_io_admission_failure(
            ops_req, ports, expected_reason_code=expected_code
        )


def test_admission_succeeds_with_hermes_delegation_and_ed25519_signer(
    tmp_path: Path,
) -> None:
    priv = tmp_path / "signer_ed25519.pem"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(priv)],
        check=True,
        capture_output=True,
    )
    pub_raw = gov_p1.raw_public_key_from_pem(priv)
    signer = Ed25519TestSignerPort(
        private_key_pem=priv,
        key_id=gov_p1.key_id_for(pub_raw),
        key_registry_locator=_loc("smart_ads/key_authorization_registry/v1", "9"),
    )
    reg = _make_registry_state(cap_state="live_certified")
    ports = CellRuntimePorts(
        clock_port=StaticClockPort(_make_clock_state()),
        timezone_port=StaticTimezonePort(_make_sao_paulo_tz_rules()),
        registry_port=StaticRegistryPort(reg),
        prerequisite_port=StaticPrerequisitePort(
            _make_prereq_bundle("operational_read", include_delegation_context=True)
        ),
        signer_port=signer,
        require_hermes_delegation=True,
    )
    bundle = admit_collection(
        _make_request("operational_read"),
        ports,
        admission_id="admission:adm-signed-001",
    )
    assert bundle.admitted.admitted_at_utc == "2026-11-11T15:00:00Z"
    assert bundle.admitted.computed_date_range == DateRange("2026-11-10", "2026-11-10", True)
    assert bundle.admitted.integrity is not None and bundle.admitted.integrity.is_signed
    gov_p1.verify_envelope(
        bundle.admitted.to_dict(),
        ADR_P1_DOMAIN_PREFIXES["smart_ads/admitted_collection/v1"],
        pub_raw,
    )


# ---------------------------------------------------------------------------
# 5. Exhaustive U x M completeness verifier (failed -> partial -> complete)
# ---------------------------------------------------------------------------


def _build_complete_facts_from_universe(
    universe: tuple[FactKey, ...],
) -> list[NormalizedCollectionFact]:
    facts: list[NormalizedCollectionFact] = []
    for idx, fk in enumerate(universe):
        if fk.metric_semantic_ref == "metric:spend_v1":
            facts.append(
                NormalizedCollectionFact(
                    fact_key=fk,
                    presence_status="observed",
                    value_type="int64_minor_currency",
                    raw_numeric_value="0" if idx % 2 == 0 else "2500",
                    unit="minor_currency",
                    currency="BRL",
                )
            )
        else:
            facts.append(
                NormalizedCollectionFact(
                    fact_key=fk,
                    presence_status="observed",
                    value_type="int64_count",
                    raw_numeric_value="0" if idx % 2 == 0 else "120",
                    unit="count",
                    currency=None,
                )
            )
    return facts


def test_recompute_collection_completeness_failed_partial_complete_matrix() -> None:
    reg = _make_registry_state()
    inventory = _make_expected_inventory(registry_snapshot_locator=reg.locator)
    required_metrics = ("metric:clicks_v1", "metric:impressions_v1", "metric:spend_v1")
    mappings = PIPEBOARD_PHASE1_METRIC_SOURCE_MAPPINGS

    universe = build_expected_fact_universe(
        inventory=inventory,
        required_metrics=required_metrics,
        metric_source_mappings=mappings,
    )
    assert len(universe) == 6  # 2 campaigns x 3 metrics
    complete_facts = _build_complete_facts_from_universe(universe)

    # 1. FAILED cases (including precedence over partial flags)
    failed_cases: tuple[tuple[bool, ExpectedResourceInventory | None, TransportOutcome], ...] = (
        (False, inventory, _ok_transport_outcome()),
        (True, None, _ok_transport_outcome()),
        (True, inventory, _ok_transport_outcome(network_ok=False, truncated_2mib=True)),
        (True, inventory, _ok_transport_outcome(auth_ok=False)),
        (True, inventory, _ok_transport_outcome(http_status=500)),
        (True, inventory, _ok_transport_outcome(media_and_encoding_valid=False)),
        (True, inventory, _ok_transport_outcome(jsonrpc_error=True)),
    )
    for adm_ok, inv, outcome in failed_cases:
        ev = recompute_collection_completeness(
            admission_succeeded=adm_ok,
            inventory=inv,
            required_metrics=required_metrics,
            metric_source_mappings=mappings,
            transport_outcome=outcome,
            candidate_facts=complete_facts,
        )
        assert ev.status == "failed"
        assert len(ev.reasons) >= 1
        assert ev.normalized_fact_set is None
        assert ev.normalized_fact_set_digest is None

    # 2. Empty candidate_facts when U has 2 campaigns -> PARTIAL (NOT failed!)
    empty_ev = recompute_collection_completeness(
        admission_succeeded=True,
        inventory=inventory,
        required_metrics=required_metrics,
        metric_source_mappings=mappings,
        transport_outcome=_ok_transport_outcome(),
        candidate_facts=(),
    )
    assert empty_ev.status == "partial"
    assert empty_ev.expected_fact_keys == frozenset(universe)
    assert empty_ev.normalized_fact_set is None
    assert empty_ev.normalized_fact_set_digest is None

    # 3. Transport/schema/pagination/reducer/duplicate partial flags -> PARTIAL
    for flag in (
        "response_date_mismatch",
        "truncated_2mib",
        "non_empty_continuation",
        "reducer_order_or_count_mismatch",
        "duplicate_provider_observation",
    ):
        ev = recompute_collection_completeness(
            admission_succeeded=True,
            inventory=inventory,
            required_metrics=required_metrics,
            metric_source_mappings=mappings,
            transport_outcome=_ok_transport_outcome(**{flag: True}),
            candidate_facts=complete_facts,
        )
        assert ev.status == "partial"
        assert ev.normalized_fact_set is None
        assert ev.normalized_fact_set_digest is None

    bad_schema_ev = recompute_collection_completeness(
        admission_succeeded=True,
        inventory=inventory,
        required_metrics=required_metrics,
        metric_source_mappings=mappings,
        transport_outcome=_ok_transport_outcome(payload_schema_valid=False),
        candidate_facts=complete_facts,
    )
    assert bad_schema_ev.status == "partial"

    # 4. Missing key, extra key outside U, duplicate candidate fact -> PARTIAL
    missing_one_ev = recompute_collection_completeness(
        admission_succeeded=True,
        inventory=inventory,
        required_metrics=required_metrics,
        metric_source_mappings=mappings,
        transport_outcome=_ok_transport_outcome(),
        candidate_facts=complete_facts[:-1],
    )
    assert missing_one_ev.status == "partial"

    extra_fk = replace(universe[0], resource_ref=CAMPAIGN_REF_EXTRA)
    extra_fact = NormalizedCollectionFact(
        fact_key=extra_fk,
        presence_status="observed",
        value_type="int64_count",
        raw_numeric_value="99",
        unit="count",
        currency=None,
    )
    extra_ev = recompute_collection_completeness(
        admission_succeeded=True,
        inventory=inventory,
        required_metrics=required_metrics,
        metric_source_mappings=mappings,
        transport_outcome=_ok_transport_outcome(),
        candidate_facts=[*complete_facts, extra_fact],
    )
    assert extra_ev.status == "partial"

    dup_ev = recompute_collection_completeness(
        admission_succeeded=True,
        inventory=inventory,
        required_metrics=required_metrics,
        metric_source_mappings=mappings,
        transport_outcome=_ok_transport_outcome(),
        candidate_facts=[*complete_facts, complete_facts[0]],
    )
    assert dup_ev.status == "partial"

    # 5. Unknown/inapplicable states -> PARTIAL (P-03)
    for partial_presence in (
        "missing",
        "timeout",
        "unproven_zero",
        "not_applicable_at_level",
    ):
        mutated = list(complete_facts)
        mutated[0] = NormalizedCollectionFact(
            fact_key=universe[0],
            presence_status=partial_presence,  # type: ignore[arg-type]
            value_type=None,
            raw_numeric_value=None,
            unit=None,
            currency=None,
        )
        ev = recompute_collection_completeness(
            admission_succeeded=True,
            inventory=inventory,
            required_metrics=required_metrics,
            metric_source_mappings=mappings,
            transport_outcome=_ok_transport_outcome(),
            candidate_facts=mutated,
        )
        assert ev.status == "partial"
        assert ev.normalized_fact_set is None
        assert ev.normalized_fact_set_digest is None

    # 6. COMPLETE: exact U x M (6 facts) with observed (including "0") + retracted_tombstone (P-03)
    complete_with_tombstone = list(complete_facts)
    complete_with_tombstone[-1] = NormalizedCollectionFact(
        fact_key=universe[-1],
        presence_status="retracted_tombstone",
        value_type=None,
        raw_numeric_value=None,
        unit=None,
        currency=None,
    )
    complete_ev = recompute_collection_completeness(
        admission_succeeded=True,
        inventory=inventory,
        required_metrics=required_metrics,
        metric_source_mappings=mappings,
        transport_outcome=_ok_transport_outcome(),
        candidate_facts=list(reversed(complete_with_tombstone)),
    )
    assert complete_ev.status == "complete"
    assert complete_ev.reasons == ()
    assert complete_ev.normalized_fact_set is not None
    assert len(complete_ev.normalized_fact_set) == 6
    expected_sorted, expected_digest = compute_normalized_fact_set_digest(
        complete_with_tombstone
    )
    assert complete_ev.normalized_fact_set == expected_sorted
    assert complete_ev.normalized_fact_set_digest == expected_digest


# ---------------------------------------------------------------------------
# 6. Purpose entrypoints (collect, evaluate_fixture_collection, execute_admitted_call)
# ---------------------------------------------------------------------------


def test_collect_operational_read_complete_and_partial_date_mismatch_or_duplicates() -> None:
    reg = _make_registry_state(cap_state="live_certified")
    cell_ports = CellRuntimePorts(
        clock_port=StaticClockPort(_make_clock_state()),
        timezone_port=StaticTimezonePort(_make_sao_paulo_tz_rules()),
        registry_port=StaticRegistryPort(reg),
        prerequisite_port=StaticPrerequisitePort(_make_prereq_bundle("operational_read")),
    )
    inventory = _make_expected_inventory(registry_snapshot_locator=reg.locator)

    # Complete operational_read
    res_port = SpyReservationPort()
    prov_port = SpyProviderPort(_make_default_live_batch())
    inv_port = SpyInventoryPort(inventory)

    result = collect(
        _make_request("operational_read"),
        admission_id="admission:ops-001",
        cell_ports=cell_ports,
        reservation_port=res_port,
        provider_port=prov_port,
        inventory_port=inv_port,
    )
    assert result.call_side == "operational"
    assert len(res_port.calls) == 1 and res_port.calls[0][1] == "operational"
    assert len(prov_port.calls) == 1 and prov_port.calls[0].call_side == "operational"
    assert len(result.candidates) == 6
    assert result.normalized_fact_set is not None
    assert len(result.normalized_fact_set) == 6
    assert result.normalized_fact_set_digest is not None
    assert CollectionResult.from_dict(result.to_dict()) == result

    # Partial via obs.metric_date != previous_local_day (2026-11-09 vs 2026-11-10)
    wrong_date_batch = replace(
        _make_default_live_batch(),
        resource_observations=(
            _full_campaign_observations(CAMPAIGN_REF_A, metric_date="2026-11-09"),
            _full_campaign_observations(CAMPAIGN_REF_B, metric_date="2026-11-10"),
        ),
    )
    wrong_date_res = collect(
        _make_request("operational_read"),
        admission_id="admission:ops-002",
        cell_ports=cell_ports,
        reservation_port=SpyReservationPort(),
        provider_port=SpyProviderPort(wrong_date_batch),
        inventory_port=SpyInventoryPort(inventory),
    )
    assert wrong_date_res.transport_outcome.response_date_mismatch is True
    assert wrong_date_res.normalized_fact_set is None
    assert wrong_date_res.normalized_fact_set_digest is None
    assert [r.candidate_sort_key_jcs() for r in wrong_date_res.candidates] == sorted(
        r.candidate_sort_key_jcs() for r in wrong_date_res.candidates
    )

    # Partial via duplicate resource observation: candidates sorted by K, preserved length 9, normalized_fact_set is None
    dup_batch = replace(
        _make_default_live_batch(),
        resource_observations=(
            _full_campaign_observations(CAMPAIGN_REF_B),
            _full_campaign_observations(CAMPAIGN_REF_A),
            _full_campaign_observations(CAMPAIGN_REF_A, clicks="99"),
        ),
    )
    dup_res = collect(
        _make_request("operational_read"),
        admission_id="admission:ops-003",
        cell_ports=cell_ports,
        reservation_port=SpyReservationPort(),
        provider_port=SpyProviderPort(dup_batch),
        inventory_port=SpyInventoryPort(inventory),
    )
    assert len(dup_res.candidates) == 9
    assert dup_res.normalized_fact_set is None
    assert dup_res.normalized_fact_set_digest is None

    # collect() rejects non-operational purposes BEFORE touching any port
    for wrong_purpose in ("fixture_7a", "live_verification_7b"):
        clock_spy = StaticClockPort(_make_clock_state())
        res_spy = SpyReservationPort()
        prov_spy = SpyProviderPort(_make_default_live_batch())
        with pytest.raises(PurposeEntrypointMismatchError):
            collect(
                _make_request(wrong_purpose),  # type: ignore[arg-type]
                admission_id="admission:wrong-purpose",
                cell_ports=replace(cell_ports, clock_port=clock_spy),
                reservation_port=res_spy,
                provider_port=prov_spy,
                inventory_port=SpyInventoryPort(inventory),
            )
        assert clock_spy.calls == 0
        assert len(res_spy.calls) == 0
        assert len(prov_spy.calls) == 0


def test_evaluate_fixture_collection_offline_7a_and_zero_io_enforcement() -> None:
    reg = _make_registry_state(cap_state="declared")
    cell_ports = CellRuntimePorts(
        clock_port=StaticClockPort(_make_clock_state()),
        timezone_port=StaticTimezonePort(_make_sao_paulo_tz_rules()),
        registry_port=StaticRegistryPort(reg),
        prerequisite_port=StaticPrerequisitePort(_make_prereq_bundle("fixture_7a")),
    )
    inventory = _make_expected_inventory(registry_snapshot_locator=reg.locator)
    zero_batch = replace(
        _make_default_live_batch(),
        io_counters=ExternalIOCounters.zero(),
    )
    fix_spy = SpyFixturePort(zero_batch)

    ev = evaluate_fixture_collection(
        _make_request("fixture_7a"),
        admission_id="admission:7a-001",
        cell_ports=cell_ports,
        fixture_port=fix_spy,
        inventory_port=SpyInventoryPort(inventory),
    )
    assert ev.admitted.collection_purpose == "fixture_7a"
    assert ev.admitted.required_effect_roles == ()
    assert ev.io_counters.is_zero is True
    assert ev.completeness.status == "complete"
    assert len(ev.candidates) == 6
    assert len(fix_spy.calls) == 1

    # Non-zero io_counters in fixture batch MUST fail closed
    leaky_batch = replace(
        zero_batch,
        io_counters=ExternalIOCounters(socket_creations=1),
    )
    with pytest.raises(ClosedValidationError):
        evaluate_fixture_collection(
            _make_request("fixture_7a"),
            admission_id="admission:7a-leaky",
            cell_ports=cell_ports,
            fixture_port=SpyFixturePort(leaky_batch),
            inventory_port=SpyInventoryPort(inventory),
        )

    # Rejects live purposes BEFORE touching any port
    for live_purpose in ("live_verification_7b", "operational_read"):
        clock_spy = StaticClockPort(_make_clock_state())
        fix_unused = SpyFixturePort(zero_batch)
        with pytest.raises(PurposeEntrypointMismatchError):
            evaluate_fixture_collection(
                _make_request(live_purpose),  # type: ignore[arg-type]
                admission_id="admission:7a-wrong",
                cell_ports=replace(cell_ports, clock_port=clock_spy),
                fixture_port=fix_unused,
                inventory_port=SpyInventoryPort(inventory),
            )
        assert clock_spy.calls == 0
        assert len(fix_unused.calls) == 0


def test_execute_admitted_call_runs_7b_candidate_and_reference_independently() -> None:
    reg = _make_registry_state(cap_state="fixture_certified")
    cell_ports = CellRuntimePorts(
        clock_port=StaticClockPort(_make_clock_state()),
        timezone_port=StaticTimezonePort(_make_sao_paulo_tz_rules()),
        registry_port=StaticRegistryPort(reg),
        prerequisite_port=StaticPrerequisitePort(_make_prereq_bundle("live_verification_7b")),
    )
    inventory = _make_expected_inventory(registry_snapshot_locator=reg.locator)

    bundle_7b = admit_collection(
        _make_request("live_verification_7b"),
        cell_ports,
        admission_id="admission:7b-dual-001",
    )
    assert bundle_7b.admitted.required_effect_roles == (
        "candidate_7b_call",
        "reference_7b_call",
    )

    res_port = SpyReservationPort()
    cand_res_loc = res_port.reserve_admitted_call(
        admitted_collection_locator=bundle_7b.locator, call_side="candidate"
    )
    ref_res_loc = res_port.reserve_admitted_call(
        admitted_collection_locator=bundle_7b.locator, call_side="reference"
    )

    cand_prov = SpyProviderPort(_make_default_live_batch())
    ref_prov = SpyProviderPort(_make_default_live_batch())

    cand_outcome = execute_admitted_call(
        bundle=bundle_7b,
        call_side="candidate",
        reservation_locator=cand_res_loc,
        provider_port=cand_prov,
        inventory_port=SpyInventoryPort(inventory),
    )
    ref_outcome = execute_admitted_call(
        bundle=bundle_7b,
        call_side="reference",
        reservation_locator=ref_res_loc,
        provider_port=ref_prov,
        inventory_port=SpyInventoryPort(inventory),
    )

    assert cand_outcome.result.call_side == "candidate"
    assert ref_outcome.result.call_side == "reference"
    assert cand_outcome.completeness.status == "complete"
    assert ref_outcome.completeness.status == "complete"
    assert (
        cand_outcome.result.normalized_fact_set_digest
        == ref_outcome.result.normalized_fact_set_digest
    )
    assert cand_outcome.result_locator != ref_outcome.result_locator

    # Rejects "operational" call_side on a 7B admission
    with pytest.raises(PurposeEntrypointMismatchError):
        execute_admitted_call(
            bundle=bundle_7b,
            call_side="operational",
            reservation_locator=_loc("smart_ads/authorization_reservation_record/v1", "1"),
            provider_port=SpyProviderPort(_make_default_live_batch()),
            inventory_port=SpyInventoryPort(inventory),
        )

    # Rejects any call_side on a 7A admission
    reg_7a = _make_registry_state(cap_state="declared")
    bundle_7a = admit_collection(
        _make_request("fixture_7a"),
        CellRuntimePorts(
            clock_port=StaticClockPort(_make_clock_state()),
            timezone_port=StaticTimezonePort(_make_sao_paulo_tz_rules()),
            registry_port=StaticRegistryPort(reg_7a),
            prerequisite_port=StaticPrerequisitePort(_make_prereq_bundle("fixture_7a")),
        ),
        admission_id="admission:7a-bundle",
    )
    for side in ("candidate", "reference", "operational"):
        with pytest.raises(PurposeEntrypointMismatchError):
            execute_admitted_call(
                bundle=bundle_7a,
                call_side=side,  # type: ignore[arg-type]
                reservation_locator=_loc("smart_ads/authorization_reservation_record/v1", "1"),
                provider_port=SpyProviderPort(_make_default_live_batch()),
                inventory_port=SpyInventoryPort(inventory),
            )
