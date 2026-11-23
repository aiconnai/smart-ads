"""Legacy seam contract/release verifiers and deterministic dual-projection parity (ADR-0001 §§9.2, 10, 12.6)."""
from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
import hashlib
from itertools import pairwise
from typing import Any, Final

from smart_ads.application.mcp_read_handler import VerifiedStoreMcpReadHandler
from smart_ads.application.predecessor_validators import (
    _check_store_and_verifier,
    _invoke_sig_verifier,
    _load_verified_p1_model,
    _verify_algorithm_with_sig,
    _verify_stored_wheel_build_provenance,
    verify_git_commit_parent_chain,
    verify_stored_decomposition_tip,
    verify_stored_legacy_merge_evidence,
    verify_stored_migration_run_context,
)
from smart_ads.contracts.effects import _strict_str, _typed_locator
from smart_ads.contracts.git_provenance import GitArtifactProvenance, verify_git_provenance_against_bytes
from smart_ads.contracts.jcs import (
    ArtifactLocator,
    P1Integrity,
    canonicalize_jcs,
    jcs_sha256,
    loads_strict_json,
)
from smart_ads.contracts.operational_evidence import AlgorithmProvenanceIdentity
from smart_ads.contracts.scalars import ClosedValidationError, validate_envelope_timestamp_utc, validate_sha256_prefixed
from smart_ads.contracts.seam import (
    CompatibilitySurfaceSpec,
    LegacySeamContract,
    LegacySeamRelease,
    SeamParityRecord,
    SurfaceParityComparison,
)
from smart_ads.ports.consumer import (
    P1SignatureVerifierPort,
    SeamDualProjectionCase,
    SeamLegacyProjectorPort,
)
from smart_ads.ports.storage import CellObjectStorePort
from smart_ads.transports.mcp.delegation import McpRuntimeContext
from smart_ads.transports.mcp.gateway import handle_mcp_request_bytes
from smart_ads.transports.mcp.schemas import ALLOWED_MCP_METHODS

_LEGACY_REPO: Final[str] = "mbras-tech/mbras-campaigns"
_ALLOWED_SURFACES_SET: Final[frozenset[str]] = frozenset(ALLOWED_MCP_METHODS)
_ACTIVE_PHASE1_SURFACES: Final[frozenset[str]] = frozenset({
    "smart_ads.queries.get_campaign_performance_v1",
    "smart_ads.queries.get_intelligence_findings_v1",
    "smart_ads.reports.generate_recurrent_summary_v1",
})
_DEFERRED_PHASE1_SURFACES: Final[frozenset[str]] = frozenset({
    "smart_ads.queries.get_adset_performance_v1",
    "smart_ads.queries.get_ad_performance_v1",
})


def verify_legacy_seam_contract(
    contract_or_locator: LegacySeamContract | ArtifactLocator,
    *,
    seam_raw_bytes: bytes,
    active_decomposition_head_locator: ArtifactLocator,
    store: CellObjectStorePort,
    signature_verifier: P1SignatureVerifierPort | None = None,
    require_signed: bool = True,
) -> LegacySeamContract:
    """Verify `LegacySeamContract`, run, decomposition tip, Git provenance, and MCP surface bijection."""
    if type(seam_raw_bytes) is not bytes:
        raise ClosedValidationError("seam_raw_bytes: expected bytes")
    contract = _load_verified_p1_model(
        store, contract_or_locator, LegacySeamContract,
        signature_verifier=signature_verifier, require_signed=require_signed, label="legacy_seam_contract",
    )
    verify_stored_migration_run_context(
        store, contract.migration_run_context_locator,
        signature_verifier=signature_verifier, require_signed=require_signed,
    )
    verify_stored_decomposition_tip(
        store, head_locator=active_decomposition_head_locator,
        expected_active_head_locator=active_decomposition_head_locator,
        manifest_locator=contract.decomposition_manifest_locator,
        expected_manifest_digest=contract.decomposition_manifest_digest,
        signature_verifier=signature_verifier, require_signed=require_signed,
    )
    seam_prov = _load_verified_p1_model(
        store, contract.seam_git_provenance_locator, GitArtifactProvenance,
        signature_verifier=signature_verifier, require_signed=require_signed, label="seam_git_provenance",
    )
    verify_git_provenance_against_bytes(seam_prov, seam_raw_bytes)
    if (
        seam_prov.repository != _LEGACY_REPO
        or seam_prov.commit_sha != contract.protected_release_identity.commit_sha
        or seam_prov.file_content_sha256 != contract.seam_file_content_sha256
    ):
        raise ClosedValidationError("legacy_seam_contract: seam Git provenance mismatch against release/sha256")
    if {s.surface_id for s in contract.compatibility_surfaces} != _ALLOWED_SURFACES_SET:
        raise ClosedValidationError("legacy_seam_contract.compatibility_surfaces: must equal ALLOWED_MCP_METHODS")
    return contract


def verify_legacy_seam_release(
    release_or_locator: LegacySeamRelease | ArtifactLocator, *,
    expected_active_decomposition_head_locator: ArtifactLocator, seam_raw_bytes: bytes,
    store: CellObjectStorePort, signature_verifier: P1SignatureVerifierPort | None = None, require_signed: bool = True,
) -> LegacySeamRelease:
    """Verify `LegacySeamRelease`, ancestry chain, protected merge evidence, and `LegacySeamContract`."""
    if type(seam_raw_bytes) is not bytes:
        raise ClosedValidationError("seam_raw_bytes: expected bytes")
    release = _load_verified_p1_model(store, release_or_locator, LegacySeamRelease, signature_verifier=signature_verifier, require_signed=require_signed, label="legacy_seam_release")
    run_ctx = verify_stored_migration_run_context(store, release.migration_run_context_locator, signature_verifier=signature_verifier, require_signed=require_signed)
    verify_stored_decomposition_tip(
        store, head_locator=release.decomposition_manifest_head_locator,
        expected_active_head_locator=expected_active_decomposition_head_locator,
        manifest_locator=release.decomposition_manifest_locator,
        expected_manifest_digest=release.decomposition_manifest_digest,
        signature_verifier=signature_verifier, require_signed=require_signed,
    )
    verify_git_commit_parent_chain(
        store, release.parent_edge_chain, release_identity=release.protected_release_identity,
        baseline_identity=release.baseline_identity, baseline_commit_object_ref=release.baseline_commit_object_ref,
    )
    verify_stored_legacy_merge_evidence(
        store, release.protected_merge_evidence_locator, expected_repository=_LEGACY_REPO,
        expected_protected_ref=release.protected_ref, expected_pr_number=release.pr_number,
        expected_reviewed_head_sha=release.reviewed_head_sha,
        expected_protected_merge_sha=release.protected_release_identity.commit_sha,
        expected_adr_git_identity=run_ctx["approved_adr_git_identity"],
        expected_branch_policy_digest=release.branch_policy_digest,
        signature_verifier=signature_verifier, require_signed=require_signed,
    )
    seam_prov = _load_verified_p1_model(store, release.seam_git_artifact.git_provenance_locator, GitArtifactProvenance, signature_verifier=signature_verifier, require_signed=require_signed, label="release.seam_git_provenance")
    verify_git_provenance_against_bytes(seam_prov, seam_raw_bytes)
    contract = verify_legacy_seam_contract(release.seam_contract_locator, seam_raw_bytes=seam_raw_bytes, active_decomposition_head_locator=expected_active_decomposition_head_locator, store=store, signature_verifier=signature_verifier, require_signed=require_signed)
    if (
        (seam_prov.repository, seam_prov.commit_sha, seam_prov.path, seam_prov.git_blob_oid, seam_prov.file_content_sha256)
        != (_LEGACY_REPO, release.protected_release_identity.commit_sha, release.seam_git_artifact.source_path, release.seam_git_artifact.git_blob_oid, release.seam_git_artifact.file_content_sha256)
        or (contract.locator(), contract.migration_run_context_locator, contract.baseline_identity, contract.protected_release_identity, contract.decomposition_manifest_locator, contract.decomposition_manifest_digest, contract.seam_git_provenance_locator, contract.seam_file_content_sha256)
        != (release.seam_contract_locator, release.migration_run_context_locator, release.baseline_identity, release.protected_release_identity, release.decomposition_manifest_locator, release.decomposition_manifest_digest, release.seam_git_artifact.git_provenance_locator, release.seam_git_artifact.file_content_sha256)
    ):
        raise ClosedValidationError("legacy_seam_release: seam Git artifact or seam contract binding mismatch")
    return release


def _serialize_case_descriptor(case: SeamDualProjectionCase) -> dict[str, Any]:
    rt = case.mcp_runtime_context
    if rt is None:
        rt_repr = None
    elif type(rt) is McpRuntimeContext:
        rt_repr = {
            "clock_lower_utc": rt.clock_lower_utc,
            "clock_upper_utc": rt.clock_upper_utc,
            "delegation_locator": None if rt.delegation_context is None else rt.delegation_context.locator.to_dict(),
        }
    else:
        raise ClosedValidationError("case.mcp_runtime_context: expected McpRuntimeContext or None")
    return {
        "case_id": case.case_id,
        "surface_id": case.surface_id,
        "mcp_wire_request_sha256": "sha256:" + hashlib.sha256(case.mcp_wire_request_bytes).hexdigest(),
        "mcp_runtime_context": rt_repr,
        "legacy_input_payload": dict(case.legacy_input_payload),
    }


def _validate_admitted_surface_wire_outcome(
    surface_id: str,
    case_id: str,
    admitted_request: object,
    canonical_wire: object,
    legacy_wire: object,
) -> None:
    admitted_method = getattr(admitted_request, "method", None) if admitted_request is not None else None
    if admitted_request is None or admitted_method != surface_id:
        raise ClosedValidationError(
            f"case[{case_id!r}]: pre-admission rejection or method mismatch ({admitted_method!r} != {surface_id!r})"
        )
    if not isinstance(canonical_wire, Mapping) or not isinstance(legacy_wire, Mapping):
        raise ClosedValidationError(f"case[{case_id!r}]: canonical and legacy wire payloads must be JSON objects")
    if surface_id in _ACTIVE_PHASE1_SURFACES:
        if "result" not in canonical_wire or "error" in canonical_wire or "result" not in legacy_wire or "error" in legacy_wire:
            raise ClosedValidationError(f"case[{case_id!r}]: active surface {surface_id!r} requires non-error result wire")
        return
    if surface_id in _DEFERRED_PHASE1_SURFACES:
        for side_lbl, wire in (("canonical", canonical_wire), ("legacy", legacy_wire)):
            err = wire.get("error")
            if "error" not in wire or "result" in wire or not isinstance(err, Mapping) or type(err.get("code")) is not int or err.get("code") != -32603:
                raise ClosedValidationError(f"case[{case_id!r}]: deferred surface {surface_id!r} requires {side_lbl} -32603 error")
        return
    raise ClosedValidationError(f"case[{case_id!r}]: unprofiled MCP surface {surface_id!r}")


def _evaluate_single_surface_parity(
    surface: CompatibilitySurfaceSpec,
    cases: Sequence[SeamDualProjectionCase],
    *,
    canonical_handler: VerifiedStoreMcpReadHandler,
    legacy_projector: SeamLegacyProjectorPort,
) -> SurfaceParityComparison:
    if isinstance(cases, (str, bytes)) or not isinstance(cases, Sequence) or len(cases) == 0:
        raise ClosedValidationError(f"cases_by_surface[{surface.surface_id!r}]: expected non-empty Sequence")
    checked_cases: list[SeamDualProjectionCase] = []
    id_bytes: list[bytes] = []
    for idx, case in enumerate(cases):
        if type(case) is not SeamDualProjectionCase or case.surface_id != surface.surface_id:
            raise ClosedValidationError(f"cases_by_surface[{surface.surface_id!r}][{idx}]: invalid case or surface_id")
        checked_cases.append(case)
        id_bytes.append(case.case_id.encode("utf-8"))
    if any(left >= right for left, right in pairwise(id_bytes)):
        raise ClosedValidationError(f"cases_by_surface[{surface.surface_id!r}]: case_id must be sorted and unique")
    case_descriptors: list[dict[str, Any]] = []
    legacy_projections: list[dict[str, Any]] = []
    canonical_projections: list[dict[str, Any]] = []
    for case in checked_cases:
        case_descriptors.append(_serialize_case_descriptor(case))
        outcome = handle_mcp_request_bytes(case.mcp_wire_request_bytes, case.mcp_runtime_context, handler=canonical_handler)
        canonical_wire = loads_strict_json(outcome.wire_bytes)
        raw_legacy = legacy_projector.project_legacy_surface(surface_id=surface.surface_id, mapping_contract_ref=surface.mapping_contract_ref, case=case)
        legacy_wire = loads_strict_json(canonicalize_jcs(raw_legacy))
        _validate_admitted_surface_wire_outcome(surface.surface_id, case.case_id, outcome.admitted_request, canonical_wire, legacy_wire)
        canonical_projections.append({"case_id": case.case_id, "projection": canonical_wire})
        legacy_projections.append({"case_id": case.case_id, "projection": legacy_wire})
    leg_digest = jcs_sha256(legacy_projections)
    can_digest = jcs_sha256(canonical_projections)
    if leg_digest != can_digest:
        raise ClosedValidationError(f"seam_parity[{surface.surface_id!r}]: legacy != canonical projection digest")
    return SurfaceParityComparison(surface.surface_id, surface.mapping_contract_ref, jcs_sha256(case_descriptors), len(checked_cases), leg_digest, can_digest, True)


def _evaluate_seam_dual_projections(
    *, legacy_seam_release_locator: ArtifactLocator, expected_active_decomposition_head_locator: ArtifactLocator,
    wheel_build_provenance_locator: ArtifactLocator, wheel_digest: str,
    seam_adapter_algorithm_identity: AlgorithmProvenanceIdentity, seam_raw_bytes: bytes,
    cases_by_surface: Mapping[str, Sequence[SeamDualProjectionCase]],
    canonical_handler: VerifiedStoreMcpReadHandler, legacy_projector: SeamLegacyProjectorPort,
    store: CellObjectStorePort, signature_verifier: P1SignatureVerifierPort | None, require_signed: bool,
) -> tuple[LegacySeamRelease, LegacySeamContract, AlgorithmProvenanceIdentity, tuple[SurfaceParityComparison, ...]]:
    if type(canonical_handler) is not VerifiedStoreMcpReadHandler:
        raise ClosedValidationError("canonical_handler: expected VerifiedStoreMcpReadHandler")
    if not isinstance(legacy_projector, SeamLegacyProjectorPort) or not callable(getattr(legacy_projector, "project_legacy_surface", None)):
        raise ClosedValidationError("legacy_projector: expected SeamLegacyProjectorPort")
    if not isinstance(cases_by_surface, Mapping):
        raise ClosedValidationError("cases_by_surface: expected Mapping")
    checked_rel_loc = _typed_locator(legacy_seam_release_locator, field_name="legacy_seam_release_locator", expected_type=LegacySeamRelease.SCHEMA)
    checked_wdig = validate_sha256_prefixed(_strict_str(wheel_digest, field_name="wheel_digest"), field_name="wheel_digest")
    release = verify_legacy_seam_release(checked_rel_loc, expected_active_decomposition_head_locator=expected_active_decomposition_head_locator, seam_raw_bytes=seam_raw_bytes, store=store, signature_verifier=signature_verifier, require_signed=require_signed)
    contract = verify_legacy_seam_contract(release.seam_contract_locator, seam_raw_bytes=seam_raw_bytes, active_decomposition_head_locator=expected_active_decomposition_head_locator, store=store, signature_verifier=signature_verifier, require_signed=require_signed)
    checked_alg = _verify_algorithm_with_sig(seam_adapter_algorithm_identity, expected_schema_id=SeamParityRecord.SCHEMA, store=store, signature_verifier=signature_verifier, require_signed=require_signed, label="seam_adapter_algorithm_identity")
    _verify_stored_wheel_build_provenance(
        store, _typed_locator(wheel_build_provenance_locator, field_name="wheel_build_provenance_locator", expected_type="smart_ads/wheel_build_provenance/v1"),
        expected_run_locator=release.migration_run_context_locator, expected_wheel_digest=checked_wdig,
        signature_verifier=signature_verifier, require_signed=require_signed,
    )
    expected_surfaces = {s.surface_id for s in contract.compatibility_surfaces}
    if any(type(k) is not str for k in cases_by_surface) or set(cases_by_surface.keys()) != expected_surfaces:
        raise ClosedValidationError("cases_by_surface: keys must match contract.compatibility_surfaces")
    comparisons = tuple(
        _evaluate_single_surface_parity(surf, cases_by_surface[surf.surface_id], canonical_handler=canonical_handler, legacy_projector=legacy_projector)
        for surf in contract.compatibility_surfaces
    )
    return release, contract, checked_alg, comparisons


def build_seam_parity_record(
    *,
    legacy_seam_release_locator: ArtifactLocator,
    expected_active_decomposition_head_locator: ArtifactLocator,
    wheel_build_provenance_locator: ArtifactLocator,
    wheel_digest: str,
    seam_adapter_algorithm_identity: AlgorithmProvenanceIdentity,
    evaluated_at_utc: str,
    seam_raw_bytes: bytes,
    cases_by_surface: Mapping[str, Sequence[SeamDualProjectionCase]],
    canonical_handler: VerifiedStoreMcpReadHandler,
    legacy_projector: SeamLegacyProjectorPort,
    store: CellObjectStorePort,
    integrity: P1Integrity | None = None,
    envelope_signer: Callable[[Mapping[str, Any], str], Mapping[str, Any]] | None = None,
    signature_verifier: P1SignatureVerifierPort | None = None,
    require_signed: bool = True,
) -> tuple[SeamParityRecord, ArtifactLocator]:
    """Execute dual-projection seam parity, build `SeamParityRecord`, and persist to `store`."""
    checked_store, checked_ver, checked_req = _check_store_and_verifier(store, signature_verifier, require_signed)
    validate_envelope_timestamp_utc(evaluated_at_utc, field_name="evaluated_at_utc")
    release, _, checked_alg, comparisons = _evaluate_seam_dual_projections(
        legacy_seam_release_locator=legacy_seam_release_locator,
        expected_active_decomposition_head_locator=expected_active_decomposition_head_locator,
        wheel_build_provenance_locator=wheel_build_provenance_locator, wheel_digest=wheel_digest,
        seam_adapter_algorithm_identity=seam_adapter_algorithm_identity, seam_raw_bytes=seam_raw_bytes,
        cases_by_surface=cases_by_surface, canonical_handler=canonical_handler, legacy_projector=legacy_projector,
        store=checked_store, signature_verifier=checked_ver, require_signed=checked_req,
    )
    record = SeamParityRecord(
        release.migration_run_context_locator, legacy_seam_release_locator,
        legacy_seam_release_locator.content_digest, release.seam_contract_locator, release.seam_contract_digest,
        release.decomposition_manifest_head_locator, release.decomposition_manifest_locator,
        wheel_build_provenance_locator, wheel_digest, checked_alg, evaluated_at_utc, comparisons, "PASS", integrity,
    )
    if envelope_signer is not None:
        if not callable(envelope_signer):
            raise ClosedValidationError("envelope_signer: expected callable")
        signed_raw = envelope_signer(record.to_dict(), SeamParityRecord.P1_DOMAIN_PREFIX)
        record = SeamParityRecord.from_dict(signed_raw, require_signed=True)
    if record.integrity is not None and record.integrity.is_signed and checked_ver is not None:
        _invoke_sig_verifier(
            checked_ver, envelope=record.to_dict(), domain_prefix=SeamParityRecord.P1_DOMAIN_PREFIX, store=checked_store
        )
    locator = checked_store.put_json_artifact(SeamParityRecord.SCHEMA, record.to_dict())
    return record, locator


def verify_seam_parity_record(
    record_or_locator: SeamParityRecord | ArtifactLocator,
    *,
    expected_active_decomposition_head_locator: ArtifactLocator,
    seam_raw_bytes: bytes,
    cases_by_surface: Mapping[str, Sequence[SeamDualProjectionCase]],
    canonical_handler: VerifiedStoreMcpReadHandler,
    legacy_projector: SeamLegacyProjectorPort,
    store: CellObjectStorePort,
    signature_verifier: P1SignatureVerifierPort | None = None,
    require_signed: bool = True,
) -> SeamParityRecord:
    """Verify `SeamParityRecord` and replay deterministic dual-projection parity byte-for-byte."""
    record = _load_verified_p1_model(
        store, record_or_locator, SeamParityRecord,
        signature_verifier=signature_verifier, require_signed=require_signed, label="seam_parity_record",
    )
    release, _, _, recomputed_comparisons = _evaluate_seam_dual_projections(
        legacy_seam_release_locator=record.legacy_seam_release_locator,
        expected_active_decomposition_head_locator=expected_active_decomposition_head_locator,
        wheel_build_provenance_locator=record.wheel_build_provenance_locator, wheel_digest=record.wheel_digest,
        seam_adapter_algorithm_identity=record.seam_adapter_algorithm_identity, seam_raw_bytes=seam_raw_bytes,
        cases_by_surface=cases_by_surface, canonical_handler=canonical_handler, legacy_projector=legacy_projector,
        store=store, signature_verifier=signature_verifier, require_signed=require_signed,
    )
    if (
        (record.migration_run_context_locator, record.seam_contract_locator, record.seam_contract_digest, record.decomposition_manifest_head_locator, record.decomposition_manifest_locator, record.parity_status)
        != (release.migration_run_context_locator, release.seam_contract_locator, release.seam_contract_digest, release.decomposition_manifest_head_locator, release.decomposition_manifest_locator, "PASS")
        or record.surface_comparisons != recomputed_comparisons
        or canonicalize_jcs([c.to_dict() for c in record.surface_comparisons]) != canonicalize_jcs([c.to_dict() for c in recomputed_comparisons])
    ):
        raise ClosedValidationError("seam_parity_record: stored bindings or surface_comparisons mismatch")
    return record


__all__ = [
    "build_seam_parity_record",
    "verify_legacy_seam_contract",
    "verify_legacy_seam_release",
    "verify_seam_parity_record",
]
