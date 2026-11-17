"""A consistent, fully resolved 7B world for record and verifier tests (not collected)."""
from __future__ import annotations

import copy
import dataclasses
import hashlib
from typing import Any

import pytest

from smart_ads.contracts.jcs import ArtifactLocator, canonicalize_jcs
from smart_ads.contracts.scalars import ClosedValidationError
from smart_ads.contracts.schemas import (
    AdmittedCollection,
    CanonicalQueryContract,
    CollectionResult,
    NormalizedCollectionFact,
    PurposePrerequisiteLocators,
)
from smart_ads.domain.pipeboard_contract import (
    FORBIDDEN_PIPEBOARD_ARGUMENTS,
    PINNED_LEGACY_COMMIT,
    PINNED_LEGACY_REPO,
    PINNED_PIPEBOARD_D26_SPECS,
    PIPEBOARD_PHASE1_METRIC_SOURCE_MAPPINGS,
    LegacySourcePacket,
    PinnedGitArtifactMember,
    PinnedUpstreamReference,
    PipeboardPhase1Contract,
    PipeboardTransportLimits,
)
from smart_ads.ports.cell_runtime import ResolvedGate3SelectionState
from smart_ads.reconciliation import bundle_7b as b7
from smart_ads.reconciliation.bundle_7b import Bundle7BDefectError
from tests.unit._bundle_7b_builders import (
    BASE_VALUES,
    CANDIDATE_AT,
    CANDIDATE_VALUES,
    CLICKS,
    GATE3_LOC,
    IMPRESSIONS,
    QUERY_DIGEST,
    REFERENCE_AT,
    RUN_LOC,
    SCOPE,
    SPEND,
    canonical_query,
    code_of,
    collection_result,
    default_profiles,
    facts_for,
    fingerprint_dict,
    loc,
    native_dict,
    oracle_domain_digest,
    oracle_jcs,
    oracle_result_locator,
    reconcile,
    sha,
)

CANDIDATE_PROVIDER = "provider-target:pipeboard-hosted"
REFERENCE_PROVIDER = "provider-target:independent-meta-reference"
CAND_EFFECT = loc("smart_ads/effect_proof/v1", "5")
REF_EFFECT = loc("smart_ads/effect_proof/v1", "6")
CAND_ALGO = sha("a")
REF_ALGO = sha("b")
RECORD_KEYS = (
    "$schema",
    "migration_run_context_locator",
    "gate3_selection_locator",
    "canonical_query_contract",
    "canonical_query_digest",
    "required_metrics",
    "candidate_execution",
    "reference_execution",
    "row_pairing",
    "fact_reconciliations",
    "logical_fact_reconciliation_digest",
    "bundle_outcome",
)
CANDIDATE_KEYS = (
    "driver_id",
    "provider_target_ref",
    "admitted_collection_locator",
    "effect_proof_locator",
    "registry_snapshot_locator",
    "driver_contract_locator",
    "driver_contract_digest",
    "source_contract_ref",
    "wheel_digest",
    "adapter_code_digest",
    "parser_code_digest",
    "mapping_rules_digest",
    "native_request_projection",
    "native_request_digest",
    "native_to_canonical_projection_algorithm_digest",
    "canonical_query_projection",
    "canonical_query_projection_digest",
    "retrieved_at_utc",
    "result_status",
    "row_count",
    "row_universe_digest",
    "normalized_fact_set_digest",
    "gate3_certification_fingerprint",
)
REFERENCE_KEYS = (
    "reference_workload_ref",
    "provider_target_ref",
    "admitted_collection_locator",
    "effect_proof_locator",
    "reference_workload_binary_digest",
    "reference_code_digest",
    "source_contract_ref",
    "implementation_kind",
    "native_request_projection",
    "native_request_digest",
    "native_to_canonical_projection_algorithm_digest",
    "canonical_query_projection",
    "canonical_query_projection_digest",
    "retrieved_at_utc",
    "result_status",
    "row_count",
    "row_universe_digest",
    "normalized_fact_set_digest",
    "reference_run_digest",
    "gate3_certification_fingerprint",
)
ROW_PAIRING = {
    "canonical_key": "resource_ref,metric_date,resource_level,breakdown_signature,canonical_metric_ref",
    "aggregation_rule": "sum_by_canonical_fact_key_and_metric",
    "deduplication_rule": "canonical_fact_key_and_metric_unique",
    "maximum_retrieval_skew_seconds": 300,
}
DELETE = object()


def make_pipeboard_contract() -> PipeboardPhase1Contract:
    members = tuple(
        PinnedGitArtifactMember(
            role=role,
            repository=PINNED_LEGACY_REPO,
            commit_sha=PINNED_LEGACY_COMMIT,
            path=path,
            git_blob_oid=blob_oid,
            file_content_sha256=file_sha,
            git_artifact_provenance_locator=loc("smart_ads/git_artifact_provenance/v1", fill),
        )
        for (role, path, blob_oid, file_sha), fill in zip(
            PINNED_PIPEBOARD_D26_SPECS, ("1", "2", "3", "4", "5"), strict=True
        )
    )
    return PipeboardPhase1Contract(
        contract_id="driver-contract:pipeboard-phase1-v1",
        driver_id="pipeboard_hosted",
        legacy_source_packet=LegacySourcePacket(
            repository=PINNED_LEGACY_REPO, commit_sha=PINNED_LEGACY_COMMIT, members=members
        ),
        upstream_reference=PinnedUpstreamReference(
            repository="pipeboard-co/meta-ads-mcp",
            commit_sha="2ef198e266ca6a37b6dc2c42335f0a0885002771",
            path="meta_ads_mcp/core/insights.py",
            symbol="get_insights",
            hosted_parity_proven=False,
        ),
        transport_limits=PipeboardTransportLimits(
            endpoint_url="https://meta-ads.mcp.pipeboard.co/",
            http_method="POST",
            connect_timeout_seconds=5,
            wall_deadline_seconds=60,
            request_content_type="application/json",
            request_accept="application/json, text/event-stream",
            request_accept_encoding="identity",
            read_chunk_bytes=65536,
            max_streamed_bytes=2_097_152,
            max_decoded_text_bytes=2_097_152,
            jsonrpc_method="tools/call",
            tool_name="get_insights",
            level="campaign",
            limit=100,
            compact=True,
            max_campaign_rows=100,
            forbidden_arguments=FORBIDDEN_PIPEBOARD_ARGUMENTS,
        ),
        metric_source_mappings=dict(PIPEBOARD_PHASE1_METRIC_SOURCE_MAPPINGS),
    )


def locate(artifact_type: str, artifact: Any) -> ArtifactLocator:
    digest = "sha256:" + hashlib.sha256(canonicalize_jcs(artifact.to_dict())).hexdigest()
    return ArtifactLocator.from_digest(artifact_type, digest)


def _prerequisites(purpose: str) -> PurposePrerequisiteLocators:
    if purpose != "live_verification_7b":
        return PurposePrerequisiteLocators(
            purpose="fixture_7a",
            sealed_sandbox_profile_locator=loc("smart_ads/sealed_sandbox_profile/v1", "1"),
            regression_fixture_locator=loc("smart_ads/regression_fixture/v1", "2"),
        )
    return PurposePrerequisiteLocators(
        purpose="live_verification_7b",
        legacy_step2_evidence_locator=loc("smart_ads/legacy_step2_implementation_evidence/v1", "1"),
        live_read_activation_receipt_locator=loc(
            "smart_ads/smart_ads_live_read_activation_receipt/v1", "2"
        ),
        gate3_selection_receipt_locator=GATE3_LOC,
        workload_identity_effect_proof_locator=loc("smart_ads/effect_proof/v1", "3"),
        deployment_effect_proof_locator=loc("smart_ads/effect_proof/v1", "4"),
    )


def make_admission(
    query: CanonicalQueryContract,
    driver_locator: ArtifactLocator,
    registry_locator: ArtifactLocator,
    *,
    admission_id: str = "admission:adm-7b-001",
    purpose: str = "live_verification_7b",
) -> AdmittedCollection:
    return AdmittedCollection(
        admission_id=admission_id,
        collection_purpose=purpose,  # type: ignore[arg-type]
        external_request_digest=sha("2"),
        tenant_ref=query.tenant_ref,
        binding_ref=query.binding_ref,
        account_ref=query.account_ref,
        resource_scope_ref=query.resource_scope_ref,
        resource_level="campaign",
        requested_capabilities=query.requested_capabilities,
        admitted_at_utc="2026-11-11T04:05:00Z",
        clock_attestation_locator=loc("smart_ads/clock_attestation/v1", "0"),
        maximum_clock_uncertainty_ms=1000,
        tzdb_version=query.tzdb_version,
        reporting_timezone=query.reporting_timezone,
        computed_date_range=query.date_range,
        registry_snapshot_locator=registry_locator,
        registry_snapshot_digest=registry_locator.content_digest,
        currency="BRL",
        driver_id="pipeboard_hosted",
        driver_contract_locator=driver_locator,
        driver_contract_digest=driver_locator.content_digest,
        driver_capability_snapshot_digest=sha("3"),
        canonical_query_contract=query,
        canonical_query_digest=query.canonical_query_digest,
        purpose_prerequisite_locators=_prerequisites(purpose),
        required_effect_roles=(
            ("candidate_7b_call", "reference_7b_call") if purpose == "live_verification_7b" else ()
        ),
    )


def pinned_algorithm(projection: b7.NativeRequestProjection, digest: str) -> CanonicalQueryContract:
    expected = CAND_ALGO if projection.endpoint_version_ref.startswith("opaque-") else REF_ALGO
    if digest != expected:
        raise ClosedValidationError("unpinned native-to-canonical algorithm")
    return canonical_query()


def reseal(record: dict[str, Any]) -> dict[str, Any]:
    """Recompute the aggregate digest after tampering a reconciliation (oracle, not helper)."""
    return dict(
        record,
        logical_fact_reconciliation_digest=oracle_domain_digest(
            "SMART-ADS:7B-FACT-RECONCILIATIONS:V1\n", record["fact_reconciliations"]
        ),
    )


def tampered(record: dict[str, Any], path: tuple[Any, ...], value: Any) -> dict[str, Any]:
    out = copy.deepcopy(record)
    target = out
    for step in path[:-1]:
        target = target[step]
    if value is DELETE:
        del target[path[-1]]
    else:
        target[path[-1]] = value
    return out


def record_defect(record: dict[str, Any]) -> str:
    with pytest.raises(Bundle7BDefectError) as excinfo:
        b7.Certification7BRecord.from_dict(record)
    return code_of(excinfo)


@dataclasses.dataclass(frozen=True)
class World:
    record: dict[str, Any]
    kwargs: dict[str, Any]

    def parsed(self) -> b7.Certification7BRecord:
        return b7.Certification7BRecord.from_dict(self.record)

    def verify(self, record: dict[str, Any] | None = None, **overrides: Any) -> None:
        parsed = b7.Certification7BRecord.from_dict(self.record if record is None else record)
        b7.verify_certification_7b_record(parsed, **dict(self.kwargs, **overrides))


def verify_defect(world: World, record: dict[str, Any] | None = None, **overrides: Any) -> str:
    with pytest.raises(Bundle7BDefectError) as excinfo:
        world.verify(record, **overrides)
    return code_of(excinfo)


def _execution_dicts(
    *,
    locators: dict[str, ArtifactLocator],
    cand: CollectionResult,
    ref: CollectionResult,
    row_count: int,
    row_digest: str,
    fp: dict[str, str],
) -> tuple[dict[str, Any], dict[str, Any]]:
    drv_loc = locators["driver"]
    cand_native = native_dict(
        endpoint="/mcp/tools/get_insights",
        http_method="POST",
        endpoint_version_ref="opaque-driver-contract:" + drv_loc.content_digest,
    )
    ref_native = native_dict()
    shared = {
        "canonical_query_projection": canonical_query().to_dict(),
        "canonical_query_projection_digest": QUERY_DIGEST,
        "result_status": "complete",
        "gate3_certification_fingerprint": fp,
        "row_count": row_count,
        "row_universe_digest": row_digest,
    }
    candidate = {
        **shared,
        "admitted_collection_locator": locators["candidate_admission"].to_dict(),
        "driver_id": "pipeboard_hosted",
        "provider_target_ref": CANDIDATE_PROVIDER,
        "effect_proof_locator": CAND_EFFECT.to_dict(),
        "registry_snapshot_locator": locators["registry"].to_dict(),
        "driver_contract_locator": drv_loc.to_dict(),
        "driver_contract_digest": drv_loc.content_digest,
        "source_contract_ref": "opaque-driver-contract:" + drv_loc.content_digest,
        "wheel_digest": sha("b"),
        "adapter_code_digest": fp["adapter_code_digest"],
        "parser_code_digest": fp["parser_code_digest"],
        "mapping_rules_digest": fp["mapping_rules_digest"],
        "native_request_projection": cand_native,
        "native_request_digest": "sha256:" + hashlib.sha256(oracle_jcs(cand_native)).hexdigest(),
        "native_to_canonical_projection_algorithm_digest": CAND_ALGO,
        "retrieved_at_utc": cand.retrieval_context.retrieved_at_utc,
        "normalized_fact_set_digest": cand.normalized_fact_set_digest,
    }
    reference = {
        **shared,
        "admitted_collection_locator": locators["reference_admission"].to_dict(),
        "reference_workload_ref": "workload:independent_meta_reference_harness",
        "provider_target_ref": REFERENCE_PROVIDER,
        "effect_proof_locator": REF_EFFECT.to_dict(),
        "reference_workload_binary_digest": sha("c"),
        "reference_code_digest": sha("d"),
        "source_contract_ref": "api-version:" + fp["selected_meta_api_version"],
        "implementation_kind": "official_sdk",
        "native_request_projection": ref_native,
        "native_request_digest": "sha256:" + hashlib.sha256(oracle_jcs(ref_native)).hexdigest(),
        "native_to_canonical_projection_algorithm_digest": REF_ALGO,
        "retrieved_at_utc": ref.retrieval_context.retrieved_at_utc,
        "normalized_fact_set_digest": ref.normalized_fact_set_digest,
        "reference_run_digest": sha("0"),
    }
    return (
        copy.deepcopy({key: candidate[key] for key in CANDIDATE_KEYS}),
        copy.deepcopy({key: reference[key] for key in REFERENCE_KEYS}),
    )


def _row_digest(reconciliations: tuple[b7.FactReconciliation, ...]) -> str:
    rows: list[dict[str, str]] = []
    for item in reconciliations:
        if item.canonical_fact_key.to_dict() not in rows:
            rows.append(item.canonical_fact_key.to_dict())
    return oracle_domain_digest("SMART-ADS:7B-ROW-UNIVERSE:V1\n", rows)


def _record(
    candidate: dict[str, Any], reference: dict[str, Any], rec: b7.Reconciliation7BResult
) -> dict[str, Any]:
    return {
        "$schema": "smart_ads/certification_7b_record/v1",
        "migration_run_context_locator": RUN_LOC.to_dict(),
        "gate3_selection_locator": GATE3_LOC.to_dict(),
        "canonical_query_contract": canonical_query().to_dict(),
        "canonical_query_digest": QUERY_DIGEST,
        "required_metrics": [IMPRESSIONS, CLICKS, SPEND],
        "candidate_execution": candidate,
        "reference_execution": reference,
        "row_pairing": dict(ROW_PAIRING),
        "fact_reconciliations": [r.to_dict() for r in rec.fact_reconciliations],
        "logical_fact_reconciliation_digest": rec.logical_fact_reconciliation_digest,
        "bundle_outcome": "verified",
    }


def _gate3_state(drv_loc: ArtifactLocator, fp: dict[str, str]) -> ResolvedGate3SelectionState:
    return ResolvedGate3SelectionState(
        locator=GATE3_LOC,
        selection_role="certification",
        revalidated_at_utc="2026-11-11T04:00:00Z",
        valid_until_utc="2026-11-11T04:15:00Z",
        candidate_driver_contract_digest=drv_loc.content_digest,
        canonical_query_digest=QUERY_DIGEST,
        schema_bundle_digest=fp["schema_bundle_digest"],
        resource_mapping_contract_digest=fp["resource_mapping_contract_digest"],
        authorized_certification_scope=fp["authorized_certification_scope"],
        certification_fingerprint_digest=sha("c"),
    )


def _admissions(
    drv_loc: ArtifactLocator, reg_loc: ArtifactLocator, separate: bool
) -> tuple[AdmittedCollection, AdmittedCollection]:
    admission = make_admission(canonical_query(), drv_loc, reg_loc)
    if not separate:
        return admission, admission
    other = make_admission(canonical_query(), drv_loc, reg_loc, admission_id="admission:adm-7b-002")
    return admission, other


def build_world(
    cand_values: dict[tuple[str, str], str] = CANDIDATE_VALUES,
    ref_values: dict[tuple[str, str], str] = BASE_VALUES,
    *,
    ref_at: str = REFERENCE_AT,
    cand_facts: list[NormalizedCollectionFact] | None = None,
    require_verified: bool = True,
    separate_reference_admission: bool = False,
    scope: str = SCOPE,
) -> World:
    contract = make_pipeboard_contract()
    drv_loc = locate(PipeboardPhase1Contract.SCHEMA, contract)
    reg_loc = loc("smart_ads/private_registry_snapshot/v1", "e")
    admission, ref_admission = _admissions(drv_loc, reg_loc, separate_reference_admission)
    locators = {
        "driver": drv_loc,
        "registry": reg_loc,
        "candidate_admission": locate(AdmittedCollection.SCHEMA, admission),
        "reference_admission": locate(AdmittedCollection.SCHEMA, ref_admission),
    }
    cand = collection_result(
        cand_facts if cand_facts is not None else facts_for(cand_values),
        side="candidate", retrieved_at=CANDIDATE_AT,
        admitted_locator=locators["candidate_admission"], registry_locator=reg_loc,
    )
    ref = collection_result(
        facts_for(ref_values, side="reference"), side="reference", retrieved_at=ref_at,
        admitted_locator=locators["reference_admission"], registry_locator=reg_loc,
    )
    fp = fingerprint_dict(candidate_driver_contract_digest=drv_loc.content_digest,
                          canonical_query_digest=QUERY_DIGEST,
                          authorized_certification_scope=scope)
    profiles = default_profiles(scope)
    rec = reconcile(cand, ref, profiles, authorized_certification_scope=scope)
    if require_verified and rec.bundle_outcome != "verified":
        raise AssertionError(f"world is not verified: {rec.defect_codes}")
    candidate, reference = _execution_dicts(
        locators=locators, cand=cand, ref=ref, row_count=len(rec.fact_reconciliations),
        row_digest=_row_digest(rec.fact_reconciliations), fp=fp,
    )
    kwargs = {
        "migration_run_context_locator": RUN_LOC,
        "gate3_selection": _gate3_state(drv_loc, fp),
        "gate3_certification_fingerprint": b7.Gate3CertificationFingerprint.from_dict(fp),
        "driver_contract": contract,
        "candidate_admission": admission,
        "reference_admission": ref_admission,
        "candidate_result": cand,
        "reference_result": ref,
        "candidate_effect_proof_locator": CAND_EFFECT,
        "candidate_effect_result_locator": oracle_result_locator(cand),
        "reference_effect_proof_locator": REF_EFFECT,
        "reference_effect_result_locator": oracle_result_locator(ref),
        "tolerance_profiles": profiles,
        "project_native_request": pinned_algorithm,
    }
    return World(record=_record(candidate, reference, rec), kwargs=kwargs)


@pytest.fixture(scope="module")
def world() -> World:
    return build_world()
