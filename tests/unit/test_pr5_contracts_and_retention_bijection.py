"""Unit tests for PR 5 pure seam, delegation, consumer, tripartite contracts, MCP projector, and retention bijection."""
from __future__ import annotations

import ast
import base64
from dataclasses import replace
import hashlib
from pathlib import Path
from typing import Any

import pytest

from smart_ads.adapters.storage import InMemoryCellObjectStore
from smart_ads.application import (
    WheelObjectLocator as AppWheelObjectLocator,
    build_retention_root,
    compute_retention_reachability_graph,
    verify_retention_root,
)
import smart_ads.application.retention_service as retention_service
import smart_ads.contracts as contracts_pkg
import smart_ads.contracts.consumer as consumer_mod
import smart_ads.contracts.seam as seam_mod
from smart_ads.contracts import (
    ADR_DATA_DOMAIN_PREFIXES, ADR_P1_DOMAIN_PREFIXES, SUPPLEMENTAL_DOMAIN_PREFIXES,
    AlgorithmProvenanceIdentity, ArtifactLocator, ClosedValidationError, CompatibilitySurfaceSpec,
    ConsumerDeploymentReadback, ConsumerFeatureFlagContract, GitArtifactProvenance, GitParentEdge,
    GitReleaseIdentity, IbviAdsDelegationContext, IbviAdsDelegationContract, LegacyBaselineIdentity,
    LegacySeamContract, LegacySeamRelease, P1Integrity, ReadEntrypointSelector, SeamGitArtifactRef,
    SeamParityRecord, SurfaceParityComparison, TripartiteCanonicalSide, TripartiteConsumerSide,
    TripartiteGitArtifactRef, TripartiteLegacySide, TripartiteTarget, WheelObjectLocator,
    canonicalize_jcs, compute_capture_replay_digest, compute_consumer_contract_digest,
    compute_git_blob_oid, compute_tripartite_digest, jcs_sha256, p1_content_digest,
)
from smart_ads.transports.mcp import (
    ALLOWED_MCP_METHODS, McpRuntimeContext, PerformanceQueryParams,
    handle_mcp_request_bytes, project_delegation_envelope_to_mcp_context, verify_mcp_delegation_context,
)
from tests.contract.test_packaging_boundary import PURE_LAYER_ALLOWED_TOP_IMPORTS, scan_pure_layer_ast_violations

_KEY_ID = "key:ed25519:" + ("a" * 64)
_SIG_B64 = base64.b64encode(b"\x33" * 64).decode("ascii")
_KEY_REG_LOC = ArtifactLocator.from_digest("smart_ads/key_authorization_registry/v1", "sha256:" + ("9" * 64))
_RUN_LOC = ArtifactLocator.from_digest("smart_ads/migration_run_context/v1", "sha256:" + ("1" * 64))
_UNSIGNED = P1Integrity(key_id=_KEY_ID, key_registry_snapshot_locator=_KEY_REG_LOC)


def _loc(schema_id: str, fill: str) -> ArtifactLocator:
    return ArtifactLocator.from_digest(schema_id, "sha256:" + (fill * 64))


def _sign_model(obj: Any, key_reg_loc: ArtifactLocator = _KEY_REG_LOC) -> Any:
    raw_unsigned = {**obj.to_dict(), "integrity": P1Integrity(_KEY_ID, key_reg_loc).to_dict()}
    digest = p1_content_digest(raw_unsigned)
    signed_dict = {**raw_unsigned, "integrity": P1Integrity(_KEY_ID, key_reg_loc, digest, _SIG_B64).to_dict()}
    return type(obj).from_dict(signed_dict, require_signed=True)


def _make_alg_id(schema_id: str, prov_loc: ArtifactLocator | None = None) -> AlgorithmProvenanceIdentity:
    ploc = _loc("smart_ads/git_artifact_provenance/v1", "6") if prov_loc is None else prov_loc
    return AlgorithmProvenanceIdentity(
        "algorithm:pr5-verifier-v1", "1.0.0", ploc, "aiconnai/smart-ads", "b" * 40,
        "src/smart_ads/contracts/seam.py", "c" * 40, "sha256:" + ("d" * 64), "cpython-3.12", schema_id,
    )


def _build_seam_stack() -> tuple[LegacySeamContract, LegacySeamRelease, SeamParityRecord]:
    base_id = LegacyBaselineIdentity()
    rel_id = GitReleaseIdentity("mbras-tech/mbras-campaigns", "e" * 40, "f" * 40)
    manifest_loc = _loc("smart_ads/decomposition_manifest/v1", "2")
    head_loc = _loc("smart_ads/decomposition_manifest_head/v1", "3")
    prov_loc = _loc("smart_ads/git_artifact_provenance/v1", "4")
    seam_sha = "sha256:" + ("5" * 64)
    surfs = (
        CompatibilitySurfaceSpec("surface:a_campaign", "smart_ads/collection_result/v1", "smart_ads/analytics_landing_row/v1", "mapping:campaign-v1"),
        CompatibilitySurfaceSpec("surface:b_report", "smart_ads/report_execution/v1", "smart_ads/finding/v1", "mapping:report-v1"),
    )
    contract = LegacySeamContract(
        _RUN_LOC, base_id, rel_id, manifest_loc, manifest_loc.content_digest,
        prov_loc, seam_sha, "seam-v1", surfs, _UNSIGNED,
    )
    mid_sha = "a" * 40
    edges = (
        GitParentEdge(rel_id.commit_sha, mid_sha, "cell-object:sha256:" + ("7" * 64)),
        GitParentEdge(mid_sha, base_id.commit_sha, "cell-object:sha256:" + ("8" * 64)),
    )
    seam_ref = SeamGitArtifactRef("scripts/operator/seam_adapter.py", "1" * 40, seam_sha, prov_loc)
    release = LegacySeamRelease(
        _RUN_LOC, base_id, "cell-object:sha256:" + ("a" * 64), head_loc, manifest_loc,
        manifest_loc.content_digest, rel_id, edges, "refs/heads/main", 42, "2" * 40,
        rel_id.commit_sha, _loc("smart_ads/protected_merge_evidence/v1", "b"), "sha256:" + ("c" * 64),
        seam_ref, contract.locator(), contract.locator().content_digest, integrity=_UNSIGNED,
    )
    proj_dig = "sha256:" + ("e" * 64)
    comps = (
        SurfaceParityComparison("surface:a_campaign", "mapping:campaign-v1", "sha256:" + ("1" * 64), 3, proj_dig, proj_dig, True),
        SurfaceParityComparison("surface:b_report", "mapping:report-v1", "sha256:" + ("2" * 64), 2, proj_dig, proj_dig, True),
    )
    parity = SeamParityRecord(
        _RUN_LOC, release.locator(), release.locator().content_digest, contract.locator(),
        contract.locator().content_digest, head_loc, manifest_loc,
        _loc("smart_ads/wheel_build_provenance/v1", "d"), "sha256:" + ("f" * 64),
        _make_alg_id(SeamParityRecord.SCHEMA, prov_loc), "2026-11-12T12:00:00Z", comps, "PASS", _UNSIGNED,
    )
    return contract, release, parity


def _build_consumer_stack() -> tuple[
    IbviAdsDelegationContext, IbviAdsDelegationContract, ConsumerFeatureFlagContract, ConsumerDeploymentReadback
]:
    prov_a = _loc("smart_ads/git_artifact_provenance/v1", "4")
    prov_f = _loc("smart_ads/git_artifact_provenance/v1", "5")
    prov_h = _loc("smart_ads/git_artifact_provenance/v1", "6")
    deleg_ctx = IbviAdsDelegationContext(
        "/ibvi-ads", "conductor:hermes-main", "front:pinna", "profile:pinna", "tenant:ibvi",
        "binding:meta-primary", "scope:campaigns-active", "smart_ads.queries.get_campaign_performance_v1",
        "sha256:" + ("7" * 64), "2026-11-12T12:00:00Z", "2026-11-12T12:15:00Z", "nonce-deleg-001", _UNSIGNED,
    )
    deleg_contract = IbviAdsDelegationContract(
        _RUN_LOC, "limaronaldo/hermes-ronaldo", "3" * 40, prov_h, "conductor:hermes-main",
        "front:pinna", "/ibvi-ads", "sha256:" + ("7" * 64), ALLOWED_MCP_METHODS, True, _UNSIGNED,
    )
    adp_sha, ff_sha = "sha256:" + ("8" * 64), "sha256:" + ("9" * 64)
    adp_art = TripartiteGitArtifactRef("src/ibvi_ads/adapter.py", "4" * 40, adp_sha, prov_a)
    ff_art = TripartiteGitArtifactRef("src/ibvi_ads/flags.py", "5" * 40, ff_sha, prov_f)
    selectors = (
        ReadEntrypointSelector("CampaignGateway.fetch", "smart_ads.queries.get_campaign_performance_v1"),
        ReadEntrypointSelector("get_daily_summary", "smart_ads.reports.generate_recurrent_summary_v1"),
    )
    ff_contract = ConsumerFeatureFlagContract(
        _RUN_LOC, "limaronaldo/hermes-ronaldo", "3" * 40, adp_art, ff_art, "ibvi_ads.smart_ads_read_v1",
        False, "legacy:mbras_campaigns_direct", "/ibvi-ads", selectors,
        _make_alg_id(ConsumerFeatureFlagContract.SCHEMA, prov_h), deleg_contract.locator(), _UNSIGNED,
    )
    readback = ConsumerDeploymentReadback(
        _RUN_LOC, "limaronaldo/hermes-ronaldo", "3" * 40,
        _loc("smart_ads/deployment_config_execution_result/v1", "a"), "release:hermes-2026-11-12",
        "sha256:" + ("b" * 64), _loc("smart_ads/clock_attestation/v1", "c"), "2026-11-12T12:05:00.123456Z",
        _make_alg_id(ConsumerDeploymentReadback.SCHEMA, prov_h), "sha256:" + ("d" * 64),
        adp_art, f"cell-object:{adp_sha}", ff_art, f"cell-object:{ff_sha}", "ibvi_ads.smart_ads_read_v1",
        False, "legacy:mbras_campaigns_direct", "/ibvi-ads", ff_contract.locator(),
        ff_contract.locator().content_digest, deleg_contract.locator(),
        deleg_contract.locator().content_digest, integrity=_UNSIGNED,
    )
    return deleg_ctx, deleg_contract, ff_contract, readback


def test_pr5_domain_prefixes_and_contracts_pure_isolation() -> None:
    expected_new = {
        "smart_ads/legacy_seam_release/v1": "SMART-ADS:LEGACY-SEAM-RELEASE:V1\n",
        "smart_ads/legacy_seam_contract/v1": "SMART-ADS:LEGACY-SEAM-CONTRACT:V1\n",
        "smart_ads/seam_parity_record/v1": "SMART-ADS:SEAM-PARITY:V1\n",
        "smart_ads/ibvi_ads_delegation_context/v1": "SMART-ADS:IBVI-ADS-DELEGATION-CONTEXT:V1\n",
        "smart_ads/ibvi_ads_delegation_contract/v1": "SMART-ADS:IBVI-ADS-DELEGATION-CONTRACT:V1\n",
        "smart_ads/consumer_feature_flag_contract/v1": "SMART-ADS:CONSUMER-FEATURE-FLAG:V1\n",
        "smart_ads/consumer_deployment_readback/v1": "SMART-ADS:CONSUMER-DEPLOYMENT-READBACK:V1\n",
    }
    for sid, pfx in expected_new.items():
        assert ADR_P1_DOMAIN_PREFIXES[sid] == pfx
    all_prefixes = [*ADR_P1_DOMAIN_PREFIXES.values(), *ADR_DATA_DOMAIN_PREFIXES.values(), *SUPPLEMENTAL_DOMAIN_PREFIXES.values()]
    assert len(ADR_P1_DOMAIN_PREFIXES) == 63 and len(all_prefixes) == len(set(all_prefixes)) == 74
    assert WheelObjectLocator is AppWheelObjectLocator is contracts_pkg.WheelObjectLocator

    for mod in (seam_mod, consumer_mod):
        src = Path(mod.__file__).read_text(encoding="utf-8")
        assert scan_pure_layer_ast_violations(src, filename=str(mod.__file__)) == []
        for node in ast.walk(ast.parse(src)):
            if isinstance(node, ast.ImportFrom) and node.module is not None:
                top = node.module.split(".")[0]
                assert top in PURE_LAYER_ALLOWED_TOP_IMPORTS and (top != "smart_ads" or node.module.startswith("smart_ads.contracts"))
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    top = alias.name.split(".")[0]
                    assert top in PURE_LAYER_ALLOWED_TOP_IMPORTS and (top != "smart_ads" or alias.name.startswith("smart_ads.contracts"))


def test_wheel_locator_and_seam_value_objects_strict_validation() -> None:
    whl = WheelObjectLocator.for_wheel_bytes(b"PK\x03\x04-wheel")
    assert WheelObjectLocator.from_dict(whl.to_dict()) == whl == WheelObjectLocator(whl.wheel_digest, whl.size_bytes)
    with pytest.raises(ClosedValidationError):
        WheelObjectLocator.from_dict({**whl.to_dict(), "object_ref": ""})
    with pytest.raises(ClosedValidationError):
        WheelObjectLocator(whl.wheel_digest, True)  # type: ignore[arg-type]

    base = LegacyBaselineIdentity()
    assert LegacyBaselineIdentity.from_dict(base.to_dict()) == base
    for field_k, bad_v in (("repository", "aiconnai/smart-ads"), ("commit_sha", "0" * 40), ("source_tree_oid", "0" * 40)):
        with pytest.raises(ClosedValidationError):
            LegacyBaselineIdentity.from_dict({**base.to_dict(), field_k: bad_v})

    with pytest.raises(ClosedValidationError):
        GitParentEdge("a" * 40, "a" * 40, "cell-object:sha256:" + ("1" * 64))
    with pytest.raises(ClosedValidationError):
        SeamGitArtifactRef("../escape.py", "1" * 40, "sha256:" + ("2" * 64), _loc("smart_ads/git_artifact_provenance/v1", "3"))

    d1, d2 = "sha256:" + ("1" * 64), "sha256:" + ("2" * 64)
    ok_match = SurfaceParityComparison("s1", "mapping:m1", d1, 1, d1, d1, True)
    ok_diff = SurfaceParityComparison("s1", "mapping:m1", d1, 1, d1, d2, False)
    assert SurfaceParityComparison.from_dict(ok_match.to_dict()) == ok_match
    assert SurfaceParityComparison.from_dict(ok_diff.to_dict()) == ok_diff
    for bad_cmp in ({"parity_matched": False}, {"canonical_projection_digest": d2}, {"case_count": 0}, {"case_count": True}, {"parity_matched": 1}):
        with pytest.raises(ClosedValidationError):
            SurfaceParityComparison.from_dict({**ok_match.to_dict(), **bad_cmp})


def test_seam_p1_envelopes_roundtrip_and_invariants() -> None:
    contract, release, parity = _build_seam_stack()
    for env in (contract, release, parity):
        signed = _sign_model(env)
        assert type(env).from_dict(signed.to_dict(), require_signed=True) == signed
        assert env.locator().artifact_type == env.SCHEMA

    s_a, s_b = contract.compatibility_surfaces
    for bad_surfs in ((s_b, s_a), (s_a, s_a), ()):
        with pytest.raises(ClosedValidationError):
            replace(contract, compatibility_surfaces=bad_surfs)

    assert release.parent_edge_chain_digest == jcs_sha256([e.to_dict() for e in release.parent_edge_chain])
    for bad_rel in (
        {"parent_edge_chain_digest": ""},
        {"protected_merge_sha": "9" * 40},
        {"pr_number": 0},
        {"pr_number": True},
        {"parent_edge_chain_digest": "sha256:" + ("0" * 64)},
        {"parent_edge_chain": [release.parent_edge_chain[0].to_dict()]},
    ):
        with pytest.raises(ClosedValidationError):
            LegacySeamRelease.from_dict({**release.to_dict(), **bad_rel})

    rel_sha, mid_sha = release.protected_release_identity.commit_sha, "a" * 40
    cyc_edges = (
        GitParentEdge(rel_sha, mid_sha, "cell-object:sha256:" + ("7" * 64)),
        GitParentEdge(mid_sha, rel_sha, "cell-object:sha256:" + ("8" * 64)),
        GitParentEdge(rel_sha, release.baseline_identity.commit_sha, "cell-object:sha256:" + ("9" * 64)),
    )
    with pytest.raises(ClosedValidationError):
        replace(release, parent_edge_chain=cyc_edges, parent_edge_chain_digest="")

    unmatched = SurfaceParityComparison("surface:a_campaign", "mapping:campaign-v1", "sha256:" + ("1" * 64), 3, "sha256:" + ("1" * 64), "sha256:" + ("2" * 64), False)
    for bad_par in (
        {"surface_comparisons": (unmatched, parity.surface_comparisons[1])},
        {"parity_status": "FAIL"},
        {"seam_adapter_algorithm_identity": _make_alg_id("smart_ads/report_execution/v1")},
    ):
        with pytest.raises(ClosedValidationError):
            replace(parity, **bad_par)


def test_consumer_delegation_and_feature_flag_envelopes() -> None:
    deleg_ctx, deleg_contract, ff_contract, readback = _build_consumer_stack()
    for env in (deleg_ctx, deleg_contract, ff_contract, readback):
        signed = _sign_model(env)
        assert type(env).from_dict(signed.to_dict(), require_signed=True) == signed

    for bad_ctx in (
        {"route": "/direct"}, {"allowed_method": "smart_ads.mutations.pause_campaign"},
        {"issued_at_utc": "2026-11-12T12:00:00.000000Z"}, {"issued_at_utc": "2026-11-12T12:15:00Z"},
        {"nonce": "bad nonce with space"},
    ):
        with pytest.raises(ClosedValidationError):
            IbviAdsDelegationContext.from_dict({**deleg_ctx.to_dict(), **bad_ctx})

    for bad_dc in (
        {"consumer_repository": "aiconnai/smart-ads"}, {"delegated_route": "/other"},
        {"allowed_mcp_methods": list(ALLOWED_MCP_METHODS[:-1])},
        {"allowed_mcp_methods": list(reversed(ALLOWED_MCP_METHODS))},
        {"direct_route_bypass_denied": False}, {"direct_route_bypass_denied": 1},
    ):
        with pytest.raises(ClosedValidationError):
            IbviAdsDelegationContract.from_dict({**deleg_contract.to_dict(), **bad_dc})

    for bad_ff in (
        {"default_enabled": True}, {"default_enabled": 0}, {"disabled_legacy_route": "/ibvi-ads"},
        {"disabled_legacy_route": "smart_ads.queries.get_campaign_performance_v1"},
        {"enabled_smart_ads_route": "/legacy"},
        {"feature_flag_git_artifact": ff_contract.adapter_git_artifact.to_dict()},
        {"read_entrypoints": [s.to_dict() for s in reversed(ff_contract.read_entrypoints)]},
    ):
        with pytest.raises(ClosedValidationError):
            ConsumerFeatureFlagContract.from_dict({**ff_contract.to_dict(), **bad_ff})


def test_consumer_deployment_readback_and_capture_replay_digest() -> None:
    _, _, _, readback = _build_consumer_stack()
    expected_replay = compute_capture_replay_digest(
        consumer_repository=readback.consumer_repository, consumer_commit_sha=readback.consumer_commit_sha,
        deployed_release_id=readback.deployed_release_id, runtime_binary_sha256=readback.runtime_binary_sha256,
        captured_at_utc=readback.captured_at_utc, capture_tool_identity=readback.capture_tool_identity,
        capture_tool_build_digest=readback.capture_tool_build_digest, live_adapter_artifact=readback.live_adapter_artifact,
        live_adapter_object_ref=readback.live_adapter_object_ref, live_feature_flag_artifact=readback.live_feature_flag_artifact,
        live_feature_flag_object_ref=readback.live_feature_flag_object_ref, live_flag_key=readback.live_flag_key,
        live_default_enabled=readback.live_default_enabled, live_disabled_legacy_route=readback.live_disabled_legacy_route,
        live_enabled_smart_ads_route=readback.live_enabled_smart_ads_route,
        feature_flag_contract_digest=readback.feature_flag_contract_digest,
        ibvi_ads_delegation_contract_digest=readback.ibvi_ads_delegation_contract_digest,
    )
    assert readback.capture_replay_digest == expected_replay
    for bad_rb in (
        {"captured_at_utc": "2026-11-12T12:05:00Z"},
        {"live_adapter_object_ref": "cell-object:sha256:" + ("0" * 64)},
        {"live_default_enabled": True},
        {"capture_replay_digest": "sha256:" + ("0" * 64)},
        {"capture_replay_digest": ""},
    ):
        with pytest.raises(ClosedValidationError):
            ConsumerDeploymentReadback.from_dict({**readback.to_dict(), **bad_rb})


def test_tripartite_target_and_role_tagged_preimages() -> None:
    contract, release, _ = _build_seam_stack()
    _, deleg_contract, ff_contract, _ = _build_consumer_stack()
    signed_ff, signed_dc = _sign_model(ff_contract), _sign_model(deleg_contract)

    cons_digest = compute_consumer_contract_digest(
        adapter_git_artifact=signed_ff.adapter_git_artifact, feature_flag_git_artifact=signed_ff.feature_flag_git_artifact,
        resolved_feature_flag_contract_envelope=signed_ff.to_dict(), resolved_delegation_contract_envelope=signed_dc.to_dict(),
    )
    swapped_digest = compute_consumer_contract_digest(
        adapter_git_artifact=signed_ff.feature_flag_git_artifact, feature_flag_git_artifact=signed_ff.adapter_git_artifact,
        resolved_feature_flag_contract_envelope=signed_ff.to_dict(), resolved_delegation_contract_envelope=signed_dc.to_dict(),
    )
    assert cons_digest != swapped_digest

    legacy_side = TripartiteLegacySide(
        "mbras-tech/mbras-campaigns", release.protected_release_identity.commit_sha,
        release.locator(), release.seam_git_artifact, contract.locator(), contract.locator().content_digest,
    )
    legacy_via_tri = TripartiteLegacySide(
        "mbras-tech/mbras-campaigns", release.protected_release_identity.commit_sha,
        release.locator(), TripartiteGitArtifactRef.from_dict(release.seam_git_artifact.to_dict()),
        contract.locator(), contract.locator().content_digest,
    )
    assert legacy_via_tri == legacy_side == TripartiteLegacySide.from_dict(legacy_side.to_dict())

    whl = WheelObjectLocator.for_wheel_bytes(b"PK\x03\x04-smart-ads-wheel")
    canonical_side = TripartiteCanonicalSide("aiconnai/smart-ads", "b" * 40, whl, whl.wheel_digest, _loc("smart_ads/wheel_build_provenance/v1", "d"))
    consumer_side = TripartiteConsumerSide(
        "limaronaldo/hermes-ronaldo", signed_ff.consumer_commit_sha, signed_ff.adapter_git_artifact,
        signed_ff.feature_flag_git_artifact, signed_ff.locator(), signed_dc.locator(), cons_digest,
    )
    target = TripartiteTarget(legacy_side, canonical_side, consumer_side)
    assert target.tripartite_digest == compute_tripartite_digest(legacy_side=legacy_side, canonical_side=canonical_side, consumer_side=consumer_side)
    assert TripartiteTarget.from_dict(target.to_dict()) == target
    with pytest.raises(ClosedValidationError):
        TripartiteTarget(legacy_side, canonical_side, consumer_side, "sha256:" + ("0" * 64))
    with pytest.raises(ClosedValidationError):
        TripartiteTarget.from_dict({**target.to_dict(), "tripartite_digest": ""})


def test_project_delegation_envelope_to_mcp_context_and_gateway_flow() -> None:
    deleg_ctx, _, _, _ = _build_consumer_stack()
    signed_ctx = _sign_model(deleg_ctx)
    mcp_ctx = project_delegation_envelope_to_mcp_context(signed_ctx, locator=signed_ctx.locator())
    assert mcp_ctx.locator == signed_ctx.locator() and mcp_ctx.allowed_method == signed_ctx.allowed_method

    params = PerformanceQueryParams(
        method=signed_ctx.allowed_method, tenant_ref=signed_ctx.tenant_ref,
        binding_ref=signed_ctx.binding_ref, resource_scope_ref=signed_ctx.resource_scope_ref,
        date_range=contracts_pkg.DateRange("2026-11-10", "2026-11-10", True),
    )
    rt = McpRuntimeContext("2026-11-12T12:01:00Z", "2026-11-12T12:01:02Z", mcp_ctx)
    assert verify_mcp_delegation_context(rt, method=signed_ctx.allowed_method, params=params, request_id="r-1") == mcp_ctx

    wire = canonicalize_jcs({
        "jsonrpc": "2.0", "id": "r-1", "method": signed_ctx.allowed_method,
        "params": {
            "tenant_ref": signed_ctx.tenant_ref, "binding_ref": signed_ctx.binding_ref,
            "resource_scope_ref": signed_ctx.resource_scope_ref,
            "date_range": {"start_date": "2026-11-10", "end_date": "2026-11-10"},
        },
    })
    outcome = handle_mcp_request_bytes(wire, rt)
    assert outcome.rejection is None and outcome.admitted_request is not None

    with pytest.raises(ClosedValidationError):
        project_delegation_envelope_to_mcp_context(signed_ctx, locator=_loc(IbviAdsDelegationContext.SCHEMA, "0"))
    with pytest.raises(ClosedValidationError):
        project_delegation_envelope_to_mcp_context("not-an-envelope")  # type: ignore[arg-type]
    with pytest.raises(ClosedValidationError):
        project_delegation_envelope_to_mcp_context(deleg_ctx)
    with pytest.raises(ClosedValidationError):
        project_delegation_envelope_to_mcp_context(replace(deleg_ctx, integrity=None))
    assert project_delegation_envelope_to_mcp_context(deleg_ctx, require_signed=False).locator == deleg_ctx.locator()


def _populate_pr5_seam_store() -> tuple[InMemoryCellObjectStore, ArtifactLocator, ArtifactLocator, dict[str, Any]]:
    store = InMemoryCellObjectStore()
    run_loc = store.put_json_artifact("smart_ads/migration_run_context/v1", {"$schema": "smart_ads/migration_run_context/v1", "run_id": "run:pr5"})
    key_reg_loc = store.put_json_artifact("smart_ads/key_authorization_registry/v1", {"$schema": "smart_ads/key_authorization_registry/v1", "keys": [_KEY_ID]})
    raw_blob = b"def seam_or_consumer():\n    return True\n"
    prov = _sign_model(
        GitArtifactProvenance("aiconnai/smart-ads", "b" * 40, "src/smart_ads/contracts/seam.py", compute_git_blob_oid(raw_blob), "sha256:" + hashlib.sha256(raw_blob).hexdigest(), "2026-11-12T12:00:00Z"),
        key_reg_loc,
    )
    prov_loc = store.put_json_artifact(prov.SCHEMA, prov.to_dict())
    whl_bytes = b"PK\x03\x04-pr5-wheel"
    whl_ref = store.put_bytes(whl_bytes)
    whl_obj = WheelObjectLocator.for_wheel_bytes(whl_bytes)
    whl_prov_raw = {"$schema": "smart_ads/wheel_build_provenance/v1", "migration_run_context_locator": run_loc.to_dict(), "wheel": whl_obj.to_dict(), "integrity": P1Integrity(_KEY_ID, key_reg_loc).to_dict()}
    whl_prov_loc = store.put_json_artifact("smart_ads/wheel_build_provenance/v1", {**whl_prov_raw, "integrity": P1Integrity(_KEY_ID, key_reg_loc, p1_content_digest(whl_prov_raw), _SIG_B64).to_dict()})
    dm_loc = store.put_json_artifact("smart_ads/decomposition_manifest/v1", {"$schema": "smart_ads/decomposition_manifest/v1", "v": 1})
    dmh_loc = store.put_json_artifact("smart_ads/decomposition_manifest_head/v1", {"$schema": "smart_ads/decomposition_manifest_head/v1", "v": 1})
    pme_loc = store.put_json_artifact("smart_ads/protected_merge_evidence/v1", {"$schema": "smart_ads/protected_merge_evidence/v1", "v": 1})
    base_ref = store.put_bytes(b"commit 12\x00baseline-raw")
    e1_ref = store.put_bytes(b"commit 10\x00edge-one-1")
    e2_ref = store.put_bytes(b"commit 10\x00edge-two-2")
    contract, release, parity = _build_seam_stack()
    s_con = _sign_model(replace(contract, migration_run_context_locator=run_loc, decomposition_manifest_locator=dm_loc, decomposition_manifest_digest=dm_loc.content_digest, seam_git_provenance_locator=prov_loc), key_reg_loc)
    c_loc = store.put_json_artifact(s_con.SCHEMA, s_con.to_dict())
    real_edges = (
        GitParentEdge(release.parent_edge_chain[0].child_sha, release.parent_edge_chain[0].parent_sha, e1_ref),
        GitParentEdge(release.parent_edge_chain[1].child_sha, release.parent_edge_chain[1].parent_sha, e2_ref),
    )
    s_rel = _sign_model(replace(release, migration_run_context_locator=run_loc, baseline_commit_object_ref=base_ref, parent_edge_chain=real_edges, parent_edge_chain_digest="", decomposition_manifest_head_locator=dmh_loc, decomposition_manifest_locator=dm_loc, decomposition_manifest_digest=dm_loc.content_digest, protected_merge_evidence_locator=pme_loc, seam_git_artifact=replace(release.seam_git_artifact, git_provenance_locator=prov_loc), seam_contract_locator=c_loc, seam_contract_digest=c_loc.content_digest), key_reg_loc)
    r_loc = store.put_json_artifact(s_rel.SCHEMA, s_rel.to_dict())
    s_par = _sign_model(replace(parity, migration_run_context_locator=run_loc, legacy_seam_release_locator=r_loc, legacy_seam_release_digest=r_loc.content_digest, seam_contract_locator=c_loc, seam_contract_digest=c_loc.content_digest, decomposition_manifest_head_locator=dmh_loc, decomposition_manifest_locator=dm_loc, wheel_build_provenance_locator=whl_prov_loc, wheel_digest=whl_obj.wheel_digest, seam_adapter_algorithm_identity=_make_alg_id(SeamParityRecord.SCHEMA, prov_loc)), key_reg_loc)
    p_loc = store.put_json_artifact(s_par.SCHEMA, s_par.to_dict())
    return store, run_loc, key_reg_loc, {"c_loc": c_loc, "r_loc": r_loc, "p_loc": p_loc, "whl_ref": whl_ref, "s_con": s_con, "base_ref": base_ref, "e1_ref": e1_ref, "e2_ref": e2_ref}


def test_retention_schema_bijection_and_pr5_reachability_closure() -> None:
    parsers = retention_service._schema_parsers()
    assert len(retention_service._OTHER_ADR_STANDALONE_SCHEMAS) == 64
    assert len(parsers) == 117
    for pr5_cls in (
        LegacySeamContract, LegacySeamRelease, SeamParityRecord, IbviAdsDelegationContext,
        IbviAdsDelegationContract, ConsumerFeatureFlagContract, ConsumerDeploymentReadback,
    ):
        assert pr5_cls.SCHEMA in parsers and pr5_cls.SCHEMA not in retention_service._OTHER_ADR_STANDALONE_SCHEMAS

    store, run_loc, key_reg_loc, info = _populate_pr5_seam_store()
    root_unsigned, _ = build_retention_root(
        root_id="root:pr5-seam-parity", cell_ref="cell:ibvi-primary",
        migration_run_context_locator=run_loc, target_artifact_locator=info["p_loc"],
        created_at_utc="2026-11-12T12:10:00Z", store=store, integrity=P1Integrity(_KEY_ID, key_reg_loc),
    )
    root_signed = _sign_model(root_unsigned, key_reg_loc)
    closure = verify_retention_root(root_signed, store=store, require_signed=True)
    assert {
        info["c_loc"].object_ref, info["r_loc"].object_ref, info["p_loc"].object_ref,
        info["whl_ref"], info["base_ref"], info["e1_ref"], info["e2_ref"],
    }.issubset(set(closure.reachable_object_refs))

    store._blobs[info["c_loc"].object_ref] = canonicalize_jcs({**info["s_con"].to_dict(), "extra_field": 1})
    with pytest.raises(ClosedValidationError):
        compute_retention_reachability_graph((info["p_loc"],), store=store)
