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
    compute_schema_bundle_digest,
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
    ResolvedGate3SelectionState,
    ResolvedHermesDelegationState,
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


def _default_canonical_query() -> CanonicalQueryContract:
    return CanonicalQueryContract(
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
        metric_semantic_refs=(
            "metric:clicks_v1",
            "metric:impressions_v1",
            "metric:spend_v1",
        ),
        requested_capabilities=("cap:campaign-basic-v1",),
        breakdowns=(),
        currency="BRL",
    )


def _make_prereq_bundle(
    purpose: CollectionPurpose,
    *,
    gate3_7b_selection_role: str = "certification",
    gate3_ops_selection_role: str = "operational_renewal",
    gate3_revalidated_at_utc: str = "2026-11-11T14:55:00Z",
    gate3_valid_until_utc: str = "2026-11-11T15:10:00Z",
    gate3_driver_contract_digest: str | None = None,
    gate3_canonical_query_digest: str | None = None,
    gate3_schema_bundle_digest: str | None = None,
    gate3_resource_mapping_digest: str | None = None,
    gate3_scope: str = "scope:campaigns-active",
    gate3_fp: str = "sha256:" + ("c" * 64),
    omit_gate3_selection: bool = False,
    mismatch_gate3_locator: bool = False,
    renewal_selection_role: str = "operational_renewal",
    certified_fp: str = "sha256:" + ("c" * 64),
    renewal_fp: str = "sha256:" + ("c" * 64),
    certificate_issued_at_utc: str = "2026-11-11T00:00:00Z",
    certificate_valid_until_utc: str = "2026-11-12T00:00:00Z",
    cert_tenant_ref: str = "tenant:ibvi",
    cert_binding_ref: str = "binding:meta-primary",
    cert_scope_ref: str = "scope:campaigns-active",
    cert_driver_id: str = "pipeboard_hosted",
    cert_driver_contract_digest: str | None = None,
    cert_canonical_query_digest: str | None = None,
    cert_schema_bundle_digest: str | None = None,
    cert_resource_mapping_digest: str | None = None,
    include_delegation_context: bool = False,
    omit_hermes_state_only: bool = False,
    omit_delegation_locator_only: bool = False,
    mismatch_delegation_locator: bool = False,
    delegation_tenant_ref: str = "tenant:ibvi",
    delegation_front_ref: str = "front:ibvi",
    delegation_profile_ref: str = "profile:reader",
    delegation_binding_ref: str = "binding:meta-primary",
    delegation_scope_ref: str = "scope:campaigns-active",
    delegation_issued_at_utc: str = "2026-11-11T14:55:00Z",
    delegation_valid_until_utc: str = "2026-11-11T15:10:00Z",
    omit_live_cert: bool = False,
    mismatch_head_locator: bool = False,
    extra_gate3_on_7a: ResolvedGate3SelectionState | None = None,
    extra_hermes_on_non_ops: ResolvedHermesDelegationState | None = None,
) -> ResolvedPrerequisiteBundle:
    default_reg = _make_registry_state()
    default_drv_digest = default_reg.driver_contract_locator.content_digest
    default_query_digest = _default_canonical_query().canonical_query_digest
    default_schema_digest = compute_schema_bundle_digest()
    default_rmc_digest = default_reg.snapshot.resource_mapping_contract_digest

    eff_g3_drv = (
        default_drv_digest
        if gate3_driver_contract_digest is None
        else gate3_driver_contract_digest
    )
    eff_g3_q = (
        default_query_digest
        if gate3_canonical_query_digest is None
        else gate3_canonical_query_digest
    )
    eff_g3_schema = (
        default_schema_digest
        if gate3_schema_bundle_digest is None
        else gate3_schema_bundle_digest
    )
    eff_g3_rmc = (
        default_rmc_digest
        if gate3_resource_mapping_digest is None
        else gate3_resource_mapping_digest
    )

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
            gate3_selection=extra_gate3_on_7a,
            hermes_delegation=extra_hermes_on_non_ops,
        )

    g3_loc = _loc("smart_ads/gate3_selection_receipt/v1", "5")
    g3_state_loc = (
        _loc("smart_ads/gate3_selection_receipt/v1", "e")
        if mismatch_gate3_locator
        else g3_loc
    )
    if purpose == "live_verification_7b":
        g3_7b = (
            None
            if omit_gate3_selection
            else ResolvedGate3SelectionState(
                locator=g3_state_loc,
                selection_role=gate3_7b_selection_role,  # type: ignore[arg-type]
                revalidated_at_utc=gate3_revalidated_at_utc,
                valid_until_utc=gate3_valid_until_utc,
                candidate_driver_contract_digest=eff_g3_drv,
                canonical_query_digest=eff_g3_q,
                schema_bundle_digest=eff_g3_schema,
                resource_mapping_contract_digest=eff_g3_rmc,
                authorized_certification_scope=gate3_scope,
                certification_fingerprint_digest=gate3_fp,
            )
        )
        return ResolvedPrerequisiteBundle(
            locators=PurposePrerequisiteLocators(
                purpose="live_verification_7b",
                legacy_step2_evidence_locator=_loc(
                    "smart_ads/legacy_step2_implementation_evidence/v1", "3"
                ),
                live_read_activation_receipt_locator=_loc(
                    "smart_ads/smart_ads_live_read_activation_receipt/v1", "4"
                ),
                gate3_selection_receipt_locator=g3_loc,
                workload_identity_effect_proof_locator=_loc(
                    "smart_ads/effect_proof/v1", "6"
                ),
                deployment_effect_proof_locator=_loc(
                    "smart_ads/effect_proof/v1", "7"
                ),
            ),
            gate3_selection=g3_7b,
            hermes_delegation=extra_hermes_on_non_ops,
        )

    head_loc = _loc("smart_ads/live_certification_head/v1", "8")
    tr_loc = _loc("smart_ads/live_certification_transition/v1", "9")
    cert_loc = _loc("smart_ads/live_certification_certificate/v1", "a")
    delegation_loc = (
        _loc("smart_ads/ibvi_ads_delegation_context/v1", "b")
        if include_delegation_context and not omit_delegation_locator_only
        else None
    )
    hermes_state = (
        ResolvedHermesDelegationState(
            locator=(
                _loc("smart_ads/ibvi_ads_delegation_context/v1", "d")
                if mismatch_delegation_locator
                else _loc("smart_ads/ibvi_ads_delegation_context/v1", "b")
            ),
            tenant_ref=delegation_tenant_ref,
            front_ref=delegation_front_ref,
            profile_ref=delegation_profile_ref,
            binding_ref=delegation_binding_ref,
            resource_scope_ref=delegation_scope_ref,
            issued_at_utc=delegation_issued_at_utc,
            valid_until_utc=delegation_valid_until_utc,
        )
        if include_delegation_context and not omit_hermes_state_only
        else None
    )
    g3_ops = (
        None
        if omit_gate3_selection
        else ResolvedGate3SelectionState(
            locator=g3_state_loc,
            selection_role=gate3_ops_selection_role,  # type: ignore[arg-type]
            revalidated_at_utc=gate3_revalidated_at_utc,
            valid_until_utc=gate3_valid_until_utc,
            candidate_driver_contract_digest=eff_g3_drv,
            canonical_query_digest=eff_g3_q,
            schema_bundle_digest=eff_g3_schema,
            resource_mapping_contract_digest=eff_g3_rmc,
            authorized_certification_scope=gate3_scope,
            certification_fingerprint_digest=gate3_fp,
        )
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
            tenant_ref=cert_tenant_ref,
            binding_ref=cert_binding_ref,
            resource_scope_ref=cert_scope_ref,
            driver_id=cert_driver_id,
            driver_contract_digest=(
                default_drv_digest
                if cert_driver_contract_digest is None
                else cert_driver_contract_digest
            ),
            canonical_query_digest=(
                default_query_digest
                if cert_canonical_query_digest is None
                else cert_canonical_query_digest
            ),
            schema_bundle_digest=(
                default_schema_digest
                if cert_schema_bundle_digest is None
                else cert_schema_bundle_digest
            ),
            resource_mapping_contract_digest=(
                default_rmc_digest
                if cert_resource_mapping_digest is None
                else cert_resource_mapping_digest
            ),
            certificate_issued_at_utc=certificate_issued_at_utc,
            certificate_valid_until_utc=certificate_valid_until_utc,
            certified_fingerprint_digest=certified_fp,
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
            gate3_operational_renewal_locator=g3_loc,
            workload_identity_effect_proof_locator=_loc(
                "smart_ads/effect_proof/v1", "6"
            ),
            deployment_effect_proof_locator=_loc(
                "smart_ads/effect_proof/v1", "7"
            ),
            delegation_context_locator=delegation_loc,
        ),
        gate3_selection=g3_ops,
        live_certification=live_cert,
        hermes_delegation=hermes_state,
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
    state: Any
    calls: int = 0

    def get_authenticated_clock(self) -> ResolvedClockState:
        self.calls += 1
        if callable(self.state):
            return self.state()
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
    seen_clock_states: list[ResolvedClockState] = field(default_factory=list)

    def resolve_prerequisites(
        self,
        *,
        request: CollectionRequest,
        canonical_query: CanonicalQueryContract,
        clock_state: ResolvedClockState,
    ) -> ResolvedPrerequisiteBundle:
        self.calls += 1
        self.seen_clock_states.append(clock_state)
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
        "ResolvedGate3SelectionState",
        "ResolvedHermesDelegationState",
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
        # Wrong clock locator type (constructed lazily or mutated)
        (
            lambda: _make_clock_state(
                locator_override=_loc("smart_ads/effect_proof/v1", "1"),
            ),
            "admission_validation_failed",
        ),
    )

    mutated_clock = _make_clock_state()
    object.__setattr__(
        mutated_clock, "locator", _loc("smart_ads/effect_proof/v1", "1")
    )
    bad_clocks = (*bad_clocks, (mutated_clock, "invalid_clock_locator"))

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


# ---------------------------------------------------------------------------
# 7. Final Fix-Wave Regression Coverage (Security, Completeness, Reliability)
# ---------------------------------------------------------------------------


def test_canonical_locator_content_digest_enforced_on_resolved_states_and_bundle() -> None:
    # 1. ResolvedClockState rejects tampered content_digest even with matching artifact_type
    valid_clock = _make_clock_state()
    with pytest.raises(ClosedValidationError):
        ResolvedClockState(
            locator=_loc(ClockAttestation.SCHEMA, "f"),
            attestation=valid_clock.attestation,
            configured_max_uncertainty_ms=1000,
        )

    # 2. ResolvedRegistryState rejects tampered snapshot locator or driver_contract_locator
    valid_reg = _make_registry_state()
    with pytest.raises(ClosedValidationError):
        ResolvedRegistryState(
            locator=_loc(PrivateRegistrySnapshot.SCHEMA, "f"),
            snapshot=valid_reg.snapshot,
            driver_contract_locator=valid_reg.driver_contract_locator,
            driver_contract=valid_reg.driver_contract,
        )
    with pytest.raises(ClosedValidationError):
        ResolvedRegistryState(
            locator=valid_reg.locator,
            snapshot=valid_reg.snapshot,
            driver_contract_locator=_loc(PipeboardPhase1Contract.SCHEMA, "f"),
            driver_contract=valid_reg.driver_contract,
        )

    # 3. AdmittedCollectionBundle rejects tampered bundle/registry/driver_contract locators
    cell_ports = CellRuntimePorts(
        clock_port=StaticClockPort(valid_clock),
        timezone_port=StaticTimezonePort(_make_sao_paulo_tz_rules()),
        registry_port=StaticRegistryPort(valid_reg),
        prerequisite_port=StaticPrerequisitePort(_make_prereq_bundle("operational_read")),
    )
    bundle = admit_collection(
        _make_request("operational_read"),
        cell_ports,
        admission_id="admission:bundle-digest-001",
    )
    with pytest.raises(ClosedValidationError):
        AdmittedCollectionBundle(
            admitted=bundle.admitted,
            locator=_loc("smart_ads/admitted_collection/v1", "f"),
            registry_snapshot=bundle.registry_snapshot,
            driver_contract=bundle.driver_contract,
        )
    other_reg = _make_registry_state(cap_state="declared")
    with pytest.raises(ClosedValidationError):
        AdmittedCollectionBundle(
            admitted=bundle.admitted,
            locator=bundle.locator,
            registry_snapshot=other_reg.snapshot,
            driver_contract=bundle.driver_contract,
        )
    other_contract = replace(
        bundle.driver_contract, contract_id="driver-contract:pipeboard-phase1-alt"
    )
    with pytest.raises(ClosedValidationError):
        AdmittedCollectionBundle(
            admitted=bundle.admitted,
            locator=bundle.locator,
            registry_snapshot=bundle.registry_snapshot,
            driver_contract=other_contract,
        )

    # 4. admit_collection rejects tampered content_digest on mutated ResolvedClockState / ResolvedRegistryState with zero I/O
    tampered_clock = _make_clock_state()
    object.__setattr__(
        tampered_clock, "locator", _loc(ClockAttestation.SCHEMA, "f")
    )
    _assert_zero_io_admission_failure(
        _make_request("operational_read"),
        replace(cell_ports, clock_port=StaticClockPort(tampered_clock)),
        expected_reason_code="invalid_clock_locator",
    )

    tampered_reg = _make_registry_state()
    object.__setattr__(
        tampered_reg, "locator", _loc(PrivateRegistrySnapshot.SCHEMA, "f")
    )
    _assert_zero_io_admission_failure(
        _make_request("operational_read"),
        replace(cell_ports, registry_port=StaticRegistryPort(tampered_reg)),
        expected_reason_code="invalid_registry_locator",
    )

    tampered_drv_reg = _make_registry_state()
    object.__setattr__(
        tampered_drv_reg,
        "driver_contract_locator",
        _loc(PipeboardPhase1Contract.SCHEMA, "f"),
    )
    _assert_zero_io_admission_failure(
        _make_request("operational_read"),
        replace(cell_ports, registry_port=StaticRegistryPort(tampered_drv_reg)),
        expected_reason_code="invalid_driver_contract_locator",
    )


def test_gate3_freshness_bindings_and_hermes_delegation_fail_closed_with_zero_io() -> None:
    clock = _make_clock_state()  # 2026-11-11T15:00:00.250000Z +/- 500ms -> upper 15:00:00.750000Z
    tz = _make_sao_paulo_tz_rules()
    reg = _make_registry_state(cap_state="live_certified")
    bad_sha = "sha256:" + ("0" * 64)

    # ResolvedGate3SelectionState enforces exact 900s window, max_age=900, max_uncertainty=1000, deadline=60
    valid_g3 = _make_prereq_bundle("operational_read").gate3_selection
    assert valid_g3 is not None
    with pytest.raises(ClosedValidationError):
        replace(valid_g3, valid_until_utc="2026-11-11T15:10:01Z")
    with pytest.raises(ClosedValidationError):
        replace(valid_g3, maximum_age_seconds=901)
    with pytest.raises(ClosedValidationError):
        replace(valid_g3, maximum_clock_uncertainty_ms=1500)
    with pytest.raises(ClosedValidationError):
        replace(valid_g3, maximum_provider_dispatch_deadline_seconds=30)

    # ResolvedHermesDelegationState enforces route == '/ibvi-ads' and issued <= valid_until
    valid_hermes = _make_prereq_bundle(
        "operational_read", include_delegation_context=True
    ).hermes_delegation
    assert valid_hermes is not None
    with pytest.raises(ClosedValidationError):
        replace(valid_hermes, route="/other-route")
    with pytest.raises(ClosedValidationError):
        replace(
            valid_hermes,
            issued_at_utc="2026-11-11T15:10:00Z",
            valid_until_utc="2026-11-11T15:09:59Z",
        )

    # fixture_7a rejects non-None gate3_selection or hermes_delegation
    for bad_7a_prereq in (
        _make_prereq_bundle("fixture_7a", extra_gate3_on_7a=valid_g3),
        _make_prereq_bundle("fixture_7a", extra_hermes_on_non_ops=valid_hermes),
    ):
        _assert_zero_io_admission_failure(
            _make_request("fixture_7a"),
            CellRuntimePorts(
                clock_port=StaticClockPort(clock),
                timezone_port=StaticTimezonePort(tz),
                registry_port=StaticRegistryPort(_make_registry_state(cap_state="declared")),
                prerequisite_port=StaticPrerequisitePort(bad_7a_prereq),
            ),
            expected_reason_code="unexpected_live_prerequisite_metadata",
        )

    # live_verification_7b rejects non-None hermes_delegation
    _assert_zero_io_admission_failure(
        _make_request("live_verification_7b"),
        CellRuntimePorts(
            clock_port=StaticClockPort(clock),
            timezone_port=StaticTimezonePort(tz),
            registry_port=StaticRegistryPort(reg),
            prerequisite_port=StaticPrerequisitePort(
                _make_prereq_bundle(
                    "live_verification_7b", extra_hermes_on_non_ops=valid_hermes
                )
            ),
        ),
        expected_reason_code="unexpected_hermes_delegation_state",
    )

    # configured_max_uncertainty_ms > 1000 rejected against Gate-3 profile
    wide_cfg_clock = _make_clock_state(
        uncertainty_ms=500, configured_max_uncertainty_ms=1500
    )
    _assert_zero_io_admission_failure(
        _make_request("operational_read"),
        CellRuntimePorts(
            clock_port=StaticClockPort(wide_cfg_clock),
            timezone_port=StaticTimezonePort(tz),
            registry_port=StaticRegistryPort(reg),
            prerequisite_port=StaticPrerequisitePort(_make_prereq_bundle("operational_read")),
        ),
        expected_reason_code="gate3_clock_uncertainty_exceeded",
    )

    # Gate-3 freshness & exact bindings across BOTH live_verification_7b and operational_read
    for purpose in ("live_verification_7b", "operational_read"):
        req = _make_request(purpose)
        for prereq_kwargs, expected_code in (
            ({"omit_gate3_selection": True}, "missing_gate3_selection"),
            ({"mismatch_gate3_locator": True}, "gate3_locator_mismatch"),
            # Future Gate-3 receipt: revalidated_at 15:00:01Z > lower 14:59:59.750Z
            (
                {
                    "gate3_revalidated_at_utc": "2026-11-11T15:00:01Z",
                    "gate3_valid_until_utc": "2026-11-11T15:15:01Z",
                },
                "gate3_selection_not_yet_valid",
            ),
            # Expired Gate-3 receipt: valid_until 15:00:00Z < upper 15:00:00.750Z
            (
                {
                    "gate3_revalidated_at_utc": "2026-11-11T14:45:00Z",
                    "gate3_valid_until_utc": "2026-11-11T15:00:00Z",
                },
                "expired_gate3_selection",
            ),
            # < 60s remaining before valid_until_utc: valid_until 15:01:00Z < upper (15:00:00.750Z) + 60s
            (
                {
                    "gate3_revalidated_at_utc": "2026-11-11T14:46:00Z",
                    "gate3_valid_until_utc": "2026-11-11T15:01:00Z",
                },
                "gate3_dispatch_deadline_exceeds_validity",
            ),
            ({"gate3_driver_contract_digest": bad_sha}, "gate3_driver_contract_mismatch"),
            ({"gate3_canonical_query_digest": bad_sha}, "gate3_canonical_query_mismatch"),
            ({"gate3_schema_bundle_digest": bad_sha}, "gate3_schema_bundle_mismatch"),
            ({"gate3_resource_mapping_digest": bad_sha}, "gate3_resource_mapping_mismatch"),
            ({"gate3_scope": "scope:campaigns-other"}, "gate3_scope_mismatch"),
        ):
            _assert_zero_io_admission_failure(
                req,
                CellRuntimePorts(
                    clock_port=StaticClockPort(clock),
                    timezone_port=StaticTimezonePort(tz),
                    registry_port=StaticRegistryPort(reg),
                    prerequisite_port=StaticPrerequisitePort(
                        _make_prereq_bundle(purpose, **prereq_kwargs)
                    ),
                ),
                expected_reason_code=expected_code,
            )

    # Live certification bindings & Hermes delegation authorization on operational_read
    ops_req = _make_request("operational_read")
    for ops_kwargs, req_hermes, expected_code in (
        ({"gate3_ops_selection_role": "certification"}, False, "invalid_gate3_selection_role"),
        ({"gate3_fp": bad_sha}, False, "renewal_fingerprint_mismatch"),
        ({"cert_tenant_ref": "tenant:other"}, False, "live_certificate_tenant_mismatch"),
        ({"cert_binding_ref": "binding:meta-other"}, False, "live_certificate_binding_mismatch"),
        ({"cert_scope_ref": "scope:campaigns-other"}, False, "live_certificate_scope_mismatch"),
        ({"cert_driver_id": "meta_direct"}, False, "live_certificate_driver_mismatch"),
        (
            {"cert_driver_contract_digest": bad_sha},
            False,
            "live_certificate_driver_contract_mismatch",
        ),
        (
            {"cert_canonical_query_digest": bad_sha},
            False,
            "live_certificate_canonical_query_mismatch",
        ),
        (
            {"cert_schema_bundle_digest": bad_sha},
            False,
            "live_certificate_schema_bundle_mismatch",
        ),
        (
            {"cert_resource_mapping_digest": bad_sha},
            False,
            "live_certificate_resource_mapping_mismatch",
        ),
        (
            {"certificate_issued_at_utc": "2026-11-11T15:00:01Z"},
            False,
            "future_live_certificate",
        ),
        # Partial Hermes delegation (locator without state or state without locator)
        (
            {"include_delegation_context": True, "omit_hermes_state_only": True},
            False,
            "missing_hermes_delegation_context",
        ),
        (
            {"include_delegation_context": True, "omit_delegation_locator_only": True},
            False,
            "missing_hermes_delegation_context",
        ),
        (
            {"include_delegation_context": True, "mismatch_delegation_locator": True},
            True,
            "hermes_delegation_locator_mismatch",
        ),
        (
            {"include_delegation_context": True, "delegation_tenant_ref": "tenant:other"},
            True,
            "hermes_delegation_tenant_mismatch",
        ),
        (
            {
                "include_delegation_context": True,
                "delegation_binding_ref": "binding:meta-other",
            },
            True,
            "hermes_delegation_binding_mismatch",
        ),
        (
            {
                "include_delegation_context": True,
                "delegation_scope_ref": "scope:campaigns-other",
            },
            True,
            "hermes_delegation_scope_mismatch",
        ),
        (
            {
                "include_delegation_context": True,
                "delegation_issued_at_utc": "2026-11-11T15:00:01Z",
            },
            True,
            "future_hermes_delegation",
        ),
        (
            {
                "include_delegation_context": True,
                "delegation_valid_until_utc": "2026-11-11T15:00:00Z",
            },
            True,
            "expired_hermes_delegation",
        ),
        # Unauthorized Hermes (front_ref, profile_ref) not in snapshot.authorized_scopes
        (
            {
                "include_delegation_context": True,
                "delegation_front_ref": "front:rogue-front",
            },
            True,
            "unauthorized_hermes_delegation_scope",
        ),
        (
            {
                "include_delegation_context": True,
                "delegation_profile_ref": "profile:rogue-profile",
            },
            True,
            "unauthorized_hermes_delegation_scope",
        ),
    ):
        _assert_zero_io_admission_failure(
            ops_req,
            CellRuntimePorts(
                clock_port=StaticClockPort(clock),
                timezone_port=StaticTimezonePort(tz),
                registry_port=StaticRegistryPort(reg),
                prerequisite_port=StaticPrerequisitePort(
                    _make_prereq_bundle("operational_read", **ops_kwargs)
                ),
                require_hermes_delegation=req_hermes,
            ),
            expected_reason_code=expected_code,
        )


def test_cell_runtime_ports_protocol_validation_and_non_ports_rejection() -> None:
    clock_p = StaticClockPort(_make_clock_state())
    tz_p = StaticTimezonePort(_make_sao_paulo_tz_rules())
    reg_p = StaticRegistryPort(_make_registry_state())
    pre_p = StaticPrerequisitePort(_make_prereq_bundle("operational_read"))

    for bad_kwargs in (
        {"clock_port": None, "timezone_port": tz_p, "registry_port": reg_p, "prerequisite_port": pre_p},
        {"clock_port": object(), "timezone_port": tz_p, "registry_port": reg_p, "prerequisite_port": pre_p},
        {"clock_port": clock_p, "timezone_port": object(), "registry_port": reg_p, "prerequisite_port": pre_p},
        {"clock_port": clock_p, "timezone_port": tz_p, "registry_port": object(), "prerequisite_port": pre_p},
        {"clock_port": clock_p, "timezone_port": tz_p, "registry_port": reg_p, "prerequisite_port": object()},
        {
            "clock_port": clock_p,
            "timezone_port": tz_p,
            "registry_port": reg_p,
            "prerequisite_port": pre_p,
            "signer_port": object(),
        },
    ):
        with pytest.raises(ClosedValidationError):
            CellRuntimePorts(**bad_kwargs)  # type: ignore[arg-type]

    with pytest.raises(AdmissionError) as exc_info:
        admit_collection(
            _make_request("operational_read"),
            object(),  # type: ignore[arg-type]
            admission_id="admission:bad-ports-001",
        )
    assert exc_info.value.reason_code == "invalid_runtime_ports"
    assert exc_info.value.counters == ExternalIOCounters.zero()


def test_timezone_rule_snapshot_year_0001_and_9999_boundaries_fail_closed() -> None:
    earliest = parse_timestamp_utc_micros(
        "0001-01-01T00:00:00Z", allow_whole_seconds=True
    )
    tz_minus3 = TimezoneRuleSnapshot(
        timezone_name="America/Sao_Paulo",
        tzdb_version="2026a",
        transitions=(UtcOffsetTransition(earliest, -10_800),),
    )
    tz_plus2 = TimezoneRuleSnapshot(
        timezone_name="America/Sao_Paulo",
        tzdb_version="2026a",
        transitions=(UtcOffsetTransition(earliest, 7_200),),
    )

    # 1. 0001-01-01T01:00:00.000000Z in UTC-3 underflows date.min in local_civil_date_at
    ts_underflow_local = parse_timestamp_utc_micros("0001-01-01T01:00:00.000000Z")
    with pytest.raises(ClosedValidationError):
        tz_minus3.local_civil_date_at(ts_underflow_local)

    # 2. 0001-01-01T12:00:00.000000Z in UTC-3 has local date 0001-01-01 -> previous_local_day underflows date.min
    ts_prev_day_underflow = parse_timestamp_utc_micros("0001-01-01T12:00:00.000000Z")
    with pytest.raises(ClosedValidationError):
        tz_minus3.compute_previous_local_day(
            lower_utc_micros=ts_prev_day_underflow,
            upper_utc_micros=ts_prev_day_underflow,
        )

    # 3. 9999-12-31T23:59:59.000000Z in UTC+2 overflows date.max in local_civil_date_at
    ts_overflow_max = parse_timestamp_utc_micros("9999-12-31T23:59:59.000000Z")
    with pytest.raises(ClosedValidationError):
        tz_plus2.local_civil_date_at(ts_overflow_max)

    # Verify admit_collection wraps all extreme boundary clocks into AdmissionError(counters=0)
    reg = _make_registry_state(
        cap_state="live_certified",
        issued_at_utc="0001-01-01T00:00:00Z",
        valid_until_utc="9999-12-31T23:59:59Z",
    )
    for now_str, issued_str, valid_str, tz_obj in (
        (
            "0001-01-01T01:00:00.000000Z",
            "0001-01-01T00:59:50Z",
            "0001-01-01T01:00:10Z",
            tz_minus3,
        ),
        (
            "0001-01-01T12:00:00.000000Z",
            "0001-01-01T11:59:50Z",
            "0001-01-01T12:00:10Z",
            tz_minus3,
        ),
        (
            "9999-12-31T23:59:59.000000Z",
            "9999-12-31T23:59:50Z",
            "9999-12-31T23:59:59Z",
            tz_plus2,
        ),
    ):
        extreme_clock = _make_clock_state(
            now_utc=now_str,
            uncertainty_ms=100,
            issued_at_utc=issued_str,
            valid_until_utc=valid_str,
            maximum_age_seconds=30,
        )
        _assert_zero_io_admission_failure(
            _make_request("operational_read"),
            CellRuntimePorts(
                clock_port=StaticClockPort(extreme_clock),
                timezone_port=StaticTimezonePort(tz_obj),
                registry_port=StaticRegistryPort(reg),
                prerequisite_port=StaticPrerequisitePort(_make_prereq_bundle("operational_read")),
            ),
        )


def test_completeness_http_status_none_and_complete_evaluation_invariants() -> None:
    reg = _make_registry_state(cap_state="live_certified")
    inventory = _make_expected_inventory(registry_snapshot_locator=reg.locator)
    required_metrics = ("metric:clicks_v1", "metric:impressions_v1", "metric:spend_v1")
    mappings = dict(PIPEBOARD_PHASE1_METRIC_SOURCE_MAPPINGS)
    universe = build_expected_fact_universe(
        inventory=inventory,
        required_metrics=required_metrics,
        metric_source_mappings=mappings,
    )
    complete_facts = [
        NormalizedCollectionFact(
            fact_key=fk,
            presence_status="observed",
            value_type="int64_minor_currency" if fk.metric_semantic_ref == "metric:spend_v1" else "int64_count",
            raw_numeric_value="100",
            unit="minor_currency" if fk.metric_semantic_ref == "metric:spend_v1" else "count",
            currency="BRL" if fk.metric_semantic_ref == "metric:spend_v1" else None,
        )
        for fk in universe
    ]

    # TransportOutcome(network_ok=True, http_status=None, ...) MUST evaluate to FAILED
    missing_http_ev = recompute_collection_completeness(
        admission_succeeded=True,
        inventory=inventory,
        required_metrics=required_metrics,
        metric_source_mappings=mappings,
        transport_outcome=_ok_transport_outcome(http_status=None),
        candidate_facts=complete_facts,
    )
    assert missing_http_ev.status == "failed"
    assert "http_status_missing" in missing_http_ev.reasons
    assert missing_http_ev.normalized_fact_set is None
    assert missing_http_ev.normalized_fact_set_digest is None

    # CompletenessEvaluation.__post_init__ rejects empty expected_fact_keys or mismatched keys on complete
    sorted_facts, digest = compute_normalized_fact_set_digest(complete_facts)
    with pytest.raises(ClosedValidationError):
        CompletenessEvaluation(
            status="complete",
            reasons=(),
            expected_fact_keys=frozenset(),
            normalized_fact_set=sorted_facts,
            normalized_fact_set_digest=digest,
        )
    with pytest.raises(ClosedValidationError):
        CompletenessEvaluation(
            status="complete",
            reasons=(),
            expected_fact_keys=frozenset(universe[:-1]),
            normalized_fact_set=sorted_facts,
            normalized_fact_set_digest=digest,
        )


def test_signer_port_payload_mutation_and_non_tuple_fail_closed(tmp_path: Path) -> None:
    priv = tmp_path / "malicious_signer_ed25519.pem"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(priv)],
        check=True,
        capture_output=True,
    )
    pub_raw = gov_p1.raw_public_key_from_pem(priv)
    key_id = gov_p1.key_id_for(pub_raw)
    key_reg_loc = _loc("smart_ads/key_authorization_registry/v1", "9")

    @dataclass
    class _MutatingAdmissionSigner:
        def sign_and_store(
            self, envelope_dict: dict[str, Any], *, domain_prefix: str
        ) -> tuple[dict[str, Any], ArtifactLocator]:
            mutated = dict(envelope_dict, tenant_ref="tenant:attacker")
            mutated["canonical_query_contract"] = dict(
                envelope_dict["canonical_query_contract"],
                tenant_ref="tenant:attacker",
            )
            rebuilt_cqc = CanonicalQueryContract.from_dict(
                dict(mutated["canonical_query_contract"], canonical_query_digest="")
            ) if False else CanonicalQueryContract(
                tenant_ref="tenant:attacker",
                binding_ref=envelope_dict["binding_ref"],
                account_ref=envelope_dict["account_ref"],
                resource_scope_ref=envelope_dict["resource_scope_ref"],
                ad_platform_ref="meta",
                date_rule="previous_local_day",
                date_range=DateRange.from_dict(envelope_dict["computed_date_range"]),
                reporting_timezone=envelope_dict["reporting_timezone"],
                tzdb_version=envelope_dict["tzdb_version"],
                resource_level=envelope_dict["resource_level"],
                metric_semantic_refs=tuple(
                    envelope_dict["canonical_query_contract"]["metric_semantic_refs"]
                ),
                requested_capabilities=tuple(envelope_dict["requested_capabilities"]),
                breakdowns=(),
                currency=envelope_dict["currency"],
            )
            mutated["canonical_query_contract"] = rebuilt_cqc.to_dict()
            mutated["canonical_query_digest"] = rebuilt_cqc.canonical_query_digest
            mutated["integrity"] = {
                "key_id": key_id,
                "key_registry_snapshot_locator": key_reg_loc.to_dict(),
            }
            signed = gov_p1.sign_envelope(mutated, domain_prefix, priv)
            loc = ArtifactLocator.for_canonical_bytes(
                signed["$schema"], canonicalize_jcs(signed)
            )
            return signed, loc

    @dataclass
    class _NonTupleSigner:
        def sign_and_store(
            self, envelope_dict: dict[str, Any], *, domain_prefix: str
        ) -> Any:
            return [envelope_dict]

    reg = _make_registry_state(cap_state="live_certified")
    base_ports = CellRuntimePorts(
        clock_port=StaticClockPort(_make_clock_state()),
        timezone_port=StaticTimezonePort(_make_sao_paulo_tz_rules()),
        registry_port=StaticRegistryPort(reg),
        prerequisite_port=StaticPrerequisitePort(_make_prereq_bundle("operational_read")),
    )

    _assert_zero_io_admission_failure(
        _make_request("operational_read"),
        replace(base_ports, signer_port=_MutatingAdmissionSigner()),
        expected_reason_code="signed_admission_payload_mismatch",
    )
    _assert_zero_io_admission_failure(
        _make_request("operational_read"),
        replace(base_ports, signer_port=_NonTupleSigner()),
        expected_reason_code="invalid_signer_response",
    )

    # Also test execute_admitted_call signer payload mutation & non-2-tuple rejection
    bundle = admit_collection(
        _make_request("operational_read"),
        base_ports,
        admission_id="admission:result-signer-001",
    )
    res_loc = _loc("smart_ads/authorization_reservation_record/v1", "1")
    inventory = _make_expected_inventory(registry_snapshot_locator=reg.locator)

    @dataclass
    class _MutatingResultSigner:
        def sign_and_store(
            self, envelope_dict: dict[str, Any], *, domain_prefix: str
        ) -> tuple[dict[str, Any], ArtifactLocator]:
            mutated = dict(
                envelope_dict,
                call_side="candidate",
                integrity={
                    "key_id": key_id,
                    "key_registry_snapshot_locator": key_reg_loc.to_dict(),
                },
            )
            signed = gov_p1.sign_envelope(mutated, domain_prefix, priv)
            loc = ArtifactLocator.for_canonical_bytes(
                signed["$schema"], canonicalize_jcs(signed)
            )
            return signed, loc

    for bad_result_signer in (_MutatingResultSigner(), _NonTupleSigner()):
        with pytest.raises(ClosedValidationError):
            execute_admitted_call(
                bundle=bundle,
                call_side="operational",
                reservation_locator=res_loc,
                provider_port=SpyProviderPort(_make_default_live_batch()),
                inventory_port=SpyInventoryPort(inventory),
                signer_port=bad_result_signer,
            )


def test_collect_predispatch_admission_error_and_post_rpc_fail_closed_reduction() -> None:
    reg = _make_registry_state(cap_state="live_certified")
    cell_ports = CellRuntimePorts(
        clock_port=StaticClockPort(_make_clock_state()),
        timezone_port=StaticTimezonePort(_make_sao_paulo_tz_rules()),
        registry_port=StaticRegistryPort(reg),
        prerequisite_port=StaticPrerequisitePort(_make_prereq_bundle("operational_read")),
    )
    inventory = _make_expected_inventory(registry_snapshot_locator=reg.locator)

    # 1. Pre-dispatch reservation failures in collect() MUST raise AdmissionError with zero counters and 0 RPC calls
    @dataclass
    class _RaisingReservationPort:
        def reserve_admitted_call(
            self, *, admitted_collection_locator: ArtifactLocator, call_side: CallSide
        ) -> ArtifactLocator:
            raise ClosedValidationError("reservation store unavailable")

    @dataclass
    class _WrongTypeReservationPort:
        def reserve_admitted_call(
            self, *, admitted_collection_locator: ArtifactLocator, call_side: CallSide
        ) -> ArtifactLocator:
            return _loc("smart_ads/effect_proof/v1", "1")

    for bad_res_port in (_RaisingReservationPort(), _WrongTypeReservationPort(), object()):
        prov_spy = SpyProviderPort(_make_default_live_batch())
        inv_spy = SpyInventoryPort(inventory)
        with pytest.raises(AdmissionError) as exc_info:
            collect(
                _make_request("operational_read"),
                admission_id="admission:predispatch-res-fail",
                cell_ports=cell_ports,
                reservation_port=bad_res_port,  # type: ignore[arg-type]
                provider_port=prov_spy,
                inventory_port=inv_spy,
            )
        assert exc_info.value.counters == ExternalIOCounters.zero()
        assert len(prov_spy.calls) == 0
        assert inv_spy.calls == 0

    # Invalid request in collect() also raises AdmissionError with zero counters
    with pytest.raises(AdmissionError) as req_exc:
        collect(
            object(),  # type: ignore[arg-type]
            admission_id="admission:bad-req",
            cell_ports=cell_ports,
            reservation_port=SpyReservationPort(),
            provider_port=SpyProviderPort(_make_default_live_batch()),
            inventory_port=SpyInventoryPort(inventory),
        )
    assert req_exc.value.counters == ExternalIOCounters.zero()

    # 2. Post-RPC corrupt inventory_port (raising ClosedValidationError or returning garbage) -> FAILED outcome + CollectionResult + io_counters
    bundle = admit_collection(
        _make_request("operational_read"),
        cell_ports,
        admission_id="admission:post-rpc-001",
    )
    res_loc = _loc("smart_ads/authorization_reservation_record/v1", "1")

    @dataclass
    class _RaisingInventoryPort:
        def resolve_expected_inventory(self, **kwargs: Any) -> ExpectedResourceInventory | None:
            raise ClosedValidationError("corrupt inventory envelope")

    @dataclass
    class _BogusInventoryPort:
        def resolve_expected_inventory(self, **kwargs: Any) -> Any:
            return {"not": "ExpectedResourceInventory"}

    for corrupt_inv_port in (_RaisingInventoryPort(), _BogusInventoryPort()):
        outcome = execute_admitted_call(
            bundle=bundle,
            call_side="operational",
            reservation_locator=res_loc,
            provider_port=SpyProviderPort(_make_default_live_batch()),
            inventory_port=corrupt_inv_port,
        )
        assert outcome.completeness.status == "failed"
        assert "missing_expected_inventory" in outcome.completeness.reasons
        assert outcome.result.normalized_fact_set is None
        assert len(outcome.result.candidates) == 6
        assert outcome.io_counters == _make_default_live_batch().io_counters

    # 3. Post-RPC unmapped metric_semantic_ref in provider batch -> PARTIAL outcome + CollectionResult + io_counters
    base_obs_a = _full_campaign_observations(CAMPAIGN_REF_A)
    extra_unmapped_obs = SanitizedMetricObservation(
        metric_semantic_ref="metric:unknown_extra_v1",
        presence_status="observed",
        value_type="int64_count",
        raw_numeric_value="7",
        unit="count",
        currency=None,
    )
    obs_a_with_unmapped = SanitizedResourceObservation(
        resource_ref=CAMPAIGN_REF_A,
        metric_date="2026-11-10",
        metric_observations=(*base_obs_a.metric_observations, extra_unmapped_obs),
    )
    unmapped_batch = replace(
        _make_default_live_batch(),
        resource_observations=(
            obs_a_with_unmapped,
            _full_campaign_observations(CAMPAIGN_REF_B),
        ),
    )
    unmapped_outcome = execute_admitted_call(
        bundle=bundle,
        call_side="operational",
        reservation_locator=res_loc,
        provider_port=SpyProviderPort(unmapped_batch),
        inventory_port=SpyInventoryPort(inventory),
    )
    assert unmapped_outcome.completeness.status == "partial"
    assert "reducer_order_or_count_mismatch" in unmapped_outcome.completeness.reasons
    assert unmapped_outcome.result.transport_outcome.reducer_order_or_count_mismatch is True
    assert unmapped_outcome.result.normalized_fact_set is None
    assert len(unmapped_outcome.result.candidates) == 6
    assert unmapped_outcome.io_counters == unmapped_batch.io_counters
