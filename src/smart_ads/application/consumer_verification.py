"""Pure `/ibvi-ads` delegation, consumer feature-flag/readback, and tripartite verifiers (ADR-0001 §§3.3, 12.6)."""
from __future__ import annotations

import hashlib
from typing import Final

from smart_ads.application.predecessor_validators import (
    _load_verified_p1_model,
    _verify_algorithm_with_sig,
    verify_stored_canonical_build_chain,
    verify_stored_deployment_config_result,
    verify_stored_migration_run_context,
)
from smart_ads.application.seam_parity import verify_legacy_seam_release
from smart_ads.contracts.consumer import (
    ConsumerDeploymentReadback,
    ConsumerFeatureFlagContract,
    IbviAdsDelegationContract,
    TripartiteGitArtifactRef,
    TripartiteTarget,
    compute_capture_replay_digest,
    compute_consumer_contract_digest,
    compute_tripartite_digest,
)
from smart_ads.contracts.effects import _safe_int, _typed_locator
from smart_ads.contracts.git_provenance import GitArtifactProvenance, verify_git_provenance_against_bytes
from smart_ads.contracts.jcs import ArtifactLocator
from smart_ads.contracts.scalars import ClosedValidationError, parse_timestamp_utc_micros
from smart_ads.ports.cell_runtime import ClockAttestation
from smart_ads.ports.consumer import (
    ConsumerRoutingAnalysis,
    ConsumerRoutingAnalyzerPort,
    P1SignatureVerifierPort,
)
from smart_ads.ports.storage import CellObjectStorePort

_CONSUMER_REPO: Final[str] = "limaronaldo/hermes-ronaldo"
_LEGACY_REPO: Final[str] = "mbras-tech/mbras-campaigns"
_IBVI_ADS_ROUTE: Final[str] = "/ibvi-ads"
_MICROS_PER_SECOND: Final[int] = 1_000_000


def _require_routing_analyzer(analyzer: object) -> ConsumerRoutingAnalyzerPort:
    if not isinstance(analyzer, ConsumerRoutingAnalyzerPort) or not callable(getattr(analyzer, "analyze_consumer_routing", None)):
        raise ClosedValidationError("routing_analyzer: expected ConsumerRoutingAnalyzerPort")
    return analyzer


def _verify_consumer_git_artifact(
    art_ref: TripartiteGitArtifactRef,
    raw_bytes: bytes,
    *,
    expected_commit_sha: str,
    store: CellObjectStorePort,
    signature_verifier: P1SignatureVerifierPort | None,
    require_signed: bool,
    label: str,
) -> None:
    if type(raw_bytes) is not bytes:
        raise ClosedValidationError(f"{label}: expected raw bytes")
    prov = _load_verified_p1_model(
        store, art_ref.git_provenance_locator, GitArtifactProvenance,
        signature_verifier=signature_verifier, require_signed=require_signed, label=f"{label}.git_provenance",
    )
    verify_git_provenance_against_bytes(prov, raw_bytes)
    if (prov.repository, prov.commit_sha, prov.path, prov.git_blob_oid, prov.file_content_sha256) != (
        _CONSUMER_REPO, expected_commit_sha, art_ref.source_path, art_ref.git_blob_oid, art_ref.file_content_sha256
    ):
        raise ClosedValidationError(f"{label}: Git provenance repository/commit/path/blob/sha256 mismatch")


def verify_ibvi_ads_delegation_contract(
    contract_or_locator: IbviAdsDelegationContract | ArtifactLocator,
    *,
    conductor_raw_bytes: bytes,
    store: CellObjectStorePort,
    signature_verifier: P1SignatureVerifierPort | None = None,
    require_signed: bool = True,
) -> IbviAdsDelegationContract:
    """Verify `IbviAdsDelegationContract`, run context, and host conductor Git provenance."""
    if type(conductor_raw_bytes) is not bytes:
        raise ClosedValidationError("conductor_raw_bytes: expected bytes")
    contract = _load_verified_p1_model(
        store, contract_or_locator, IbviAdsDelegationContract,
        signature_verifier=signature_verifier, require_signed=require_signed, label="ibvi_ads_delegation_contract",
    )
    verify_stored_migration_run_context(
        store, contract.migration_run_context_locator,
        signature_verifier=signature_verifier, require_signed=require_signed,
    )
    cond_prov = _load_verified_p1_model(
        store, contract.host_conductor_git_provenance_locator, GitArtifactProvenance,
        signature_verifier=signature_verifier, require_signed=require_signed, label="host_conductor_git_provenance",
    )
    verify_git_provenance_against_bytes(cond_prov, conductor_raw_bytes)
    if cond_prov.repository != _CONSUMER_REPO or cond_prov.commit_sha != contract.consumer_commit_sha:
        raise ClosedValidationError("ibvi_ads_delegation_contract: host conductor repository or commit_sha mismatch")
    return contract


def _cross_check_routing_analysis(
    analysis: object, contract: ConsumerFeatureFlagContract, deleg: IbviAdsDelegationContract
) -> None:
    if type(analysis) is not ConsumerRoutingAnalysis:
        raise ClosedValidationError("routing_analyzer: expected ConsumerRoutingAnalysis")
    fresh = ConsumerRoutingAnalysis(
        analysis.flag_key, analysis.default_enabled, analysis.disabled_legacy_route,
        analysis.enabled_smart_ads_route, analysis.discovered_public_entrypoints, analysis.verified_entrypoints,
    )
    exp_syms = tuple(ep.symbol_name for ep in contract.read_entrypoints)
    if (
        (fresh.flag_key, fresh.default_enabled, fresh.disabled_legacy_route, fresh.enabled_smart_ads_route, fresh.discovered_public_entrypoints)
        != (contract.flag_key, False, contract.disabled_legacy_route, _IBVI_ADS_ROUTE, exp_syms)
        or len(fresh.verified_entrypoints) != len(contract.read_entrypoints)
    ):
        raise ClosedValidationError("consumer_feature_flag_contract: routing analysis summary mismatch")
    allowed = set(deleg.allowed_mcp_methods)
    for fact, sel in zip(fresh.verified_entrypoints, contract.read_entrypoints, strict=True):
        if (
            (fact.symbol_name, fact.flag_key, fact.true_route, fact.true_mcp_method, fact.false_route)
            != (sel.symbol_name, contract.flag_key, _IBVI_ADS_ROUTE, sel.mcp_method, contract.disabled_legacy_route)
            or sel.mcp_method not in allowed
        ):
            raise ClosedValidationError(f"consumer_feature_flag_contract: route fact mismatch on {sel.symbol_name!r}")


def verify_consumer_feature_flag_contract(
    contract_or_locator: ConsumerFeatureFlagContract | ArtifactLocator,
    *,
    adapter_raw_bytes: bytes,
    feature_flag_raw_bytes: bytes,
    conductor_raw_bytes: bytes,
    routing_analyzer: ConsumerRoutingAnalyzerPort,
    store: CellObjectStorePort,
    signature_verifier: P1SignatureVerifierPort | None = None,
    require_signed: bool = True,
) -> ConsumerFeatureFlagContract:
    """Verify `ConsumerFeatureFlagContract`, Git bytes, `/ibvi-ads` delegation, and AST routing."""
    checked_analyzer = _require_routing_analyzer(routing_analyzer)
    contract = _load_verified_p1_model(
        store, contract_or_locator, ConsumerFeatureFlagContract,
        signature_verifier=signature_verifier, require_signed=require_signed, label="consumer_feature_flag_contract",
    )
    verify_stored_migration_run_context(
        store, contract.migration_run_context_locator,
        signature_verifier=signature_verifier, require_signed=require_signed,
    )
    _verify_algorithm_with_sig(
        contract.routing_verifier_identity, expected_schema_id=ConsumerFeatureFlagContract.SCHEMA,
        store=store, signature_verifier=signature_verifier, require_signed=require_signed,
        label="routing_verifier_identity",
    )
    deleg = verify_ibvi_ads_delegation_contract(
        contract.ibvi_ads_delegation_contract_locator, conductor_raw_bytes=conductor_raw_bytes,
        store=store, signature_verifier=signature_verifier, require_signed=require_signed,
    )
    if (deleg.migration_run_context_locator, deleg.consumer_repository, deleg.consumer_commit_sha, deleg.delegated_route) != (
        contract.migration_run_context_locator, contract.consumer_repository, contract.consumer_commit_sha, contract.enabled_smart_ads_route
    ):
        raise ClosedValidationError("consumer_feature_flag_contract: delegation contract run/commit/route mismatch")
    _verify_consumer_git_artifact(
        contract.adapter_git_artifact, adapter_raw_bytes, expected_commit_sha=contract.consumer_commit_sha,
        store=store, signature_verifier=signature_verifier, require_signed=require_signed, label="adapter_git_artifact",
    )
    _verify_consumer_git_artifact(
        contract.feature_flag_git_artifact, feature_flag_raw_bytes, expected_commit_sha=contract.consumer_commit_sha,
        store=store, signature_verifier=signature_verifier, require_signed=require_signed, label="feature_flag_git_artifact",
    )
    analysis = checked_analyzer.analyze_consumer_routing(
        adapter_bytes=adapter_raw_bytes, feature_flag_bytes=feature_flag_raw_bytes, contract=contract
    )
    _cross_check_routing_analysis(analysis, contract, deleg)
    return contract


def _verify_readback_clock_and_age(
    clock_att: ClockAttestation, captured_at_utc: str, *, max_clock_uncertainty_ms: int, max_capture_age_seconds: int
) -> None:
    max_unc = _safe_int(max_clock_uncertainty_ms, field_name="max_clock_uncertainty_ms", minimum=0)
    max_age_s = _safe_int(max_capture_age_seconds, field_name="max_capture_age_seconds", minimum=1)
    lower_us, upper_us = clock_att.verify_freshness(configured_max_uncertainty_ms=max_unc)
    captured_us = parse_timestamp_utc_micros(captured_at_utc, field_name="readback.captured_at_utc")
    issued_us = parse_timestamp_utc_micros(
        clock_att.issued_at_utc, field_name="clock_attestation.issued_at_utc", allow_whole_seconds=True
    )
    if not (lower_us <= captured_us <= upper_us):
        raise ClosedValidationError("consumer_deployment_readback: captured_at_utc outside [clock_lower, clock_upper]")
    if (upper_us - issued_us) > max_age_s * _MICROS_PER_SECOND or (upper_us - captured_us) > max_age_s * _MICROS_PER_SECOND:
        raise ClosedValidationError("consumer_deployment_readback: capture age exceeds max_capture_age_seconds")


def _recompute_readback_replay_digest(rb: ConsumerDeploymentReadback) -> str:
    return compute_capture_replay_digest(
        consumer_repository=rb.consumer_repository, consumer_commit_sha=rb.consumer_commit_sha,
        deployed_release_id=rb.deployed_release_id, runtime_binary_sha256=rb.runtime_binary_sha256,
        captured_at_utc=rb.captured_at_utc, capture_tool_identity=rb.capture_tool_identity,
        capture_tool_build_digest=rb.capture_tool_build_digest, live_adapter_artifact=rb.live_adapter_artifact,
        live_adapter_object_ref=rb.live_adapter_object_ref, live_feature_flag_artifact=rb.live_feature_flag_artifact,
        live_feature_flag_object_ref=rb.live_feature_flag_object_ref, live_flag_key=rb.live_flag_key,
        live_default_enabled=rb.live_default_enabled, live_disabled_legacy_route=rb.live_disabled_legacy_route,
        live_enabled_smart_ads_route=rb.live_enabled_smart_ads_route,
        feature_flag_contract_digest=rb.feature_flag_contract_digest,
        ibvi_ads_delegation_contract_digest=rb.ibvi_ads_delegation_contract_digest,
    )


def verify_consumer_deployment_readback(
    readback_or_locator: ConsumerDeploymentReadback | ArtifactLocator, *,
    max_clock_uncertainty_ms: int, max_capture_age_seconds: int, conductor_raw_bytes: bytes,
    routing_analyzer: ConsumerRoutingAnalyzerPort, store: CellObjectStorePort,
    signature_verifier: P1SignatureVerifierPort | None = None, require_signed: bool = True,
) -> ConsumerDeploymentReadback:
    """Verify `ConsumerDeploymentReadback`, authenticated clock, live objects, and replay digest."""
    checked_analyzer = _require_routing_analyzer(routing_analyzer)
    rb = _load_verified_p1_model(store, readback_or_locator, ConsumerDeploymentReadback, signature_verifier=signature_verifier, require_signed=require_signed, label="consumer_deployment_readback")
    verify_stored_migration_run_context(store, rb.migration_run_context_locator, signature_verifier=signature_verifier, require_signed=require_signed)
    verify_stored_deployment_config_result(
        store, rb.deployment_config_result_locator, expected_run_locator=rb.migration_run_context_locator,
        expected_consumer_repo=rb.consumer_repository, expected_consumer_commit_sha=rb.consumer_commit_sha,
        expected_deployed_release_id=rb.deployed_release_id, expected_runtime_binary_sha256=rb.runtime_binary_sha256,
        signature_verifier=signature_verifier, require_signed=require_signed,
    )
    clock_att = _load_verified_p1_model(store, rb.clock_attestation_locator, ClockAttestation, signature_verifier=signature_verifier, require_signed=require_signed, label="readback.clock_attestation")
    _verify_readback_clock_and_age(clock_att, rb.captured_at_utc, max_clock_uncertainty_ms=max_clock_uncertainty_ms, max_capture_age_seconds=max_capture_age_seconds)
    _verify_algorithm_with_sig(rb.capture_tool_identity, expected_schema_id=ConsumerDeploymentReadback.SCHEMA, store=store, signature_verifier=signature_verifier, require_signed=require_signed, label="capture_tool_identity")
    live_adp_bytes, live_flg_bytes = store.get_bytes(rb.live_adapter_object_ref), store.get_bytes(rb.live_feature_flag_object_ref)
    if "sha256:" + hashlib.sha256(live_adp_bytes).hexdigest() != rb.live_adapter_artifact.file_content_sha256 or "sha256:" + hashlib.sha256(live_flg_bytes).hexdigest() != rb.live_feature_flag_artifact.file_content_sha256:
        raise ClosedValidationError("consumer_deployment_readback: live object SHA-256 mismatch")
    ff = verify_consumer_feature_flag_contract(rb.feature_flag_contract_locator, adapter_raw_bytes=live_adp_bytes, feature_flag_raw_bytes=live_flg_bytes, conductor_raw_bytes=conductor_raw_bytes, routing_analyzer=checked_analyzer, store=store, signature_verifier=signature_verifier, require_signed=require_signed)
    dc = verify_ibvi_ads_delegation_contract(rb.ibvi_ads_delegation_contract_locator, conductor_raw_bytes=conductor_raw_bytes, store=store, signature_verifier=signature_verifier, require_signed=require_signed)
    if (
        (ff.migration_run_context_locator, dc.migration_run_context_locator, ff.ibvi_ads_delegation_contract_locator, ff.consumer_repository, ff.consumer_commit_sha, ff.adapter_git_artifact, ff.feature_flag_git_artifact, ff.flag_key, ff.default_enabled, ff.disabled_legacy_route, ff.enabled_smart_ads_route, rb.capture_replay_digest)
        != (rb.migration_run_context_locator, rb.migration_run_context_locator, rb.ibvi_ads_delegation_contract_locator, rb.consumer_repository, rb.consumer_commit_sha, rb.live_adapter_artifact, rb.live_feature_flag_artifact, rb.live_flag_key, False, rb.live_disabled_legacy_route, rb.live_enabled_smart_ads_route, _recompute_readback_replay_digest(rb))
    ):
        raise ClosedValidationError("consumer_deployment_readback: live consumer state diverges from approved contracts")
    return rb


def _resolve_consumer_side_bytes(
    art_ref: TripartiteGitArtifactRef, explicit_bytes: bytes | None, *, store: CellObjectStorePort, label: str
) -> bytes:
    obj_ref = f"cell-object:{art_ref.file_content_sha256}"
    if explicit_bytes is not None:
        if type(explicit_bytes) is not bytes:
            raise ClosedValidationError(f"{label}: expected bytes or None")
        if "sha256:" + hashlib.sha256(explicit_bytes).hexdigest() != art_ref.file_content_sha256:
            raise ClosedValidationError(f"{label}: SHA-256 mismatch against {art_ref.source_path!r}")
        if store.has_object(obj_ref) and store.get_bytes(obj_ref) != explicit_bytes:
            raise ClosedValidationError(f"{label}: explicit bytes diverge from stored cell object")
        return explicit_bytes
    return store.get_bytes(obj_ref)


def _verify_tripartite_consumer_side(
    checked: TripartiteTarget, *, expected_run_locator: ArtifactLocator, conductor_raw_bytes: bytes,
    adapter_raw_bytes: bytes | None, feature_flag_raw_bytes: bytes | None,
    deployment_readback_locator: ArtifactLocator | None, max_clock_uncertainty_ms: int, max_capture_age_seconds: int,
    routing_analyzer: ConsumerRoutingAnalyzerPort, store: CellObjectStorePort,
    signature_verifier: P1SignatureVerifierPort | None, require_signed: bool,
) -> None:
    cs = checked.consumer_side
    adp_b = _resolve_consumer_side_bytes(cs.adapter_git_artifact, adapter_raw_bytes, store=store, label="adapter_raw_bytes")
    flg_b = _resolve_consumer_side_bytes(cs.feature_flag_git_artifact, feature_flag_raw_bytes, store=store, label="feature_flag_raw_bytes")
    ff = verify_consumer_feature_flag_contract(cs.feature_flag_contract_locator, adapter_raw_bytes=adp_b, feature_flag_raw_bytes=flg_b, conductor_raw_bytes=conductor_raw_bytes, routing_analyzer=routing_analyzer, store=store, signature_verifier=signature_verifier, require_signed=require_signed)
    dc = verify_ibvi_ads_delegation_contract(cs.ibvi_ads_delegation_contract_locator, conductor_raw_bytes=conductor_raw_bytes, store=store, signature_verifier=signature_verifier, require_signed=require_signed)
    exp_cons_dig = compute_consumer_contract_digest(
        adapter_git_artifact=cs.adapter_git_artifact, feature_flag_git_artifact=cs.feature_flag_git_artifact,
        resolved_feature_flag_contract_envelope=store.get_json_artifact(cs.feature_flag_contract_locator),
        resolved_delegation_contract_envelope=store.get_json_artifact(cs.ibvi_ads_delegation_contract_locator),
    )
    if (
        (ff.migration_run_context_locator, dc.migration_run_context_locator, ff.ibvi_ads_delegation_contract_locator, ff.consumer_repository, ff.consumer_commit_sha, ff.adapter_git_artifact, ff.feature_flag_git_artifact, cs.consumer_contract_digest)
        != (expected_run_locator, expected_run_locator, cs.ibvi_ads_delegation_contract_locator, cs.repository, cs.commit_sha, cs.adapter_git_artifact, cs.feature_flag_git_artifact, exp_cons_dig)
    ):
        raise ClosedValidationError("tripartite_target.consumer_side: contract or digest mismatch")
    if deployment_readback_locator is not None:
        rb = verify_consumer_deployment_readback(_typed_locator(deployment_readback_locator, field_name="deployment_readback_locator", expected_type=ConsumerDeploymentReadback.SCHEMA), max_clock_uncertainty_ms=max_clock_uncertainty_ms, max_capture_age_seconds=max_capture_age_seconds, conductor_raw_bytes=conductor_raw_bytes, routing_analyzer=routing_analyzer, store=store, signature_verifier=signature_verifier, require_signed=require_signed)
        if (rb.migration_run_context_locator, rb.consumer_repository, rb.consumer_commit_sha, rb.live_adapter_artifact, rb.live_feature_flag_artifact, rb.feature_flag_contract_locator, rb.ibvi_ads_delegation_contract_locator) != (expected_run_locator, cs.repository, cs.commit_sha, cs.adapter_git_artifact, cs.feature_flag_git_artifact, cs.feature_flag_contract_locator, cs.ibvi_ads_delegation_contract_locator) or store.get_bytes(rb.live_adapter_object_ref) != adp_b or store.get_bytes(rb.live_feature_flag_object_ref) != flg_b:
            raise ClosedValidationError("tripartite_target.consumer_side: deployment readback mismatch")


def verify_tripartite_target(
    target: TripartiteTarget, *, expected_run_locator: ArtifactLocator,
    expected_active_decomposition_head_locator: ArtifactLocator,
    wheel_boundary_report_locator: ArtifactLocator, certification_7a_locator: ArtifactLocator,
    gov1_convergence_locator: ArtifactLocator, seam_raw_bytes: bytes, conductor_raw_bytes: bytes,
    routing_analyzer: ConsumerRoutingAnalyzerPort, store: CellObjectStorePort,
    adapter_raw_bytes: bytes | None = None, feature_flag_raw_bytes: bytes | None = None,
    deployment_readback_locator: ArtifactLocator | None = None,
    max_clock_uncertainty_ms: int = 1000, max_capture_age_seconds: int = 300,
    signature_verifier: P1SignatureVerifierPort | None = None, require_signed: bool = True,
) -> TripartiteTarget:
    """Verify legacy, canonical, and consumer sides plus role-tagged `tripartite_digest`."""
    if type(target) is not TripartiteTarget:
        raise ClosedValidationError("target: expected TripartiteTarget")
    checked = TripartiteTarget.from_dict(target.to_dict())
    if checked != target:
        raise ClosedValidationError("target: corrupted TripartiteTarget")
    verify_stored_migration_run_context(store, expected_run_locator, signature_verifier=signature_verifier, require_signed=require_signed)
    ls = checked.legacy_side
    release = verify_legacy_seam_release(ls.legacy_seam_release_locator, expected_active_decomposition_head_locator=expected_active_decomposition_head_locator, seam_raw_bytes=seam_raw_bytes, store=store, signature_verifier=signature_verifier, require_signed=require_signed)
    if (release.migration_run_context_locator, release.protected_release_identity.repository, release.protected_release_identity.commit_sha, release.seam_git_artifact, release.seam_contract_locator, release.seam_contract_digest) != (expected_run_locator, _LEGACY_REPO, ls.commit_sha, ls.seam_git_artifact, ls.seam_contract_locator, ls.seam_contract_digest):
        raise ClosedValidationError("tripartite_target.legacy_side: release binding mismatch")
    verify_stored_canonical_build_chain(
        store, wheel_locator=checked.canonical_side.wheel, wheel_digest=checked.canonical_side.wheel_digest,
        build_provenance_locator=checked.canonical_side.build_provenance_locator,
        wheel_boundary_report_locator=wheel_boundary_report_locator, certification_7a_locator=certification_7a_locator,
        gov1_convergence_locator=gov1_convergence_locator, expected_run_locator=expected_run_locator,
        expected_commit_sha=checked.canonical_side.commit_sha, signature_verifier=signature_verifier, require_signed=require_signed,
    )
    _verify_tripartite_consumer_side(
        checked, expected_run_locator=expected_run_locator, conductor_raw_bytes=conductor_raw_bytes,
        adapter_raw_bytes=adapter_raw_bytes, feature_flag_raw_bytes=feature_flag_raw_bytes,
        deployment_readback_locator=deployment_readback_locator, max_clock_uncertainty_ms=max_clock_uncertainty_ms,
        max_capture_age_seconds=max_capture_age_seconds, routing_analyzer=routing_analyzer, store=store,
        signature_verifier=signature_verifier, require_signed=require_signed,
    )
    if compute_tripartite_digest(legacy_side=checked.legacy_side, canonical_side=checked.canonical_side, consumer_side=checked.consumer_side) != checked.tripartite_digest:
        raise ClosedValidationError("tripartite_target.tripartite_digest: mismatch")
    return checked


__all__ = [
    "verify_consumer_deployment_readback",
    "verify_consumer_feature_flag_contract",
    "verify_ibvi_ads_delegation_contract",
    "verify_tripartite_target",
]
