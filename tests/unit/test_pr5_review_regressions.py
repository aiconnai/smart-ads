"""Regression tests covering all 18 validated PR 5 code-review findings and deferred minor."""
from __future__ import annotations

import base64
from collections.abc import Mapping
from dataclasses import replace
import datetime
import hashlib
from types import MappingProxyType
from typing import Any

import pytest

from smart_ads.adapters.consumer.routing_analyzer import Cpython312AstConsumerRoutingAnalyzer
from smart_ads.adapters.storage import InMemoryCellObjectStore
from smart_ads.analytics import (
    METRIC_WINDOW_COLUMNS,
    AnalyticalCertificationRecord,
    AnalysisExecution,
    AnalysisReplayInputBundle,
    AttestedCertificationInput,
    CanonicalResultEntry,
    CanonicalResultSet,
    CertificationInput,
    DerivedCertificationStatus,
    DerivedMetricDefinition,
    DuckDbBinaryObjectLocator,
    DuckDbExtensionBinaryLocator,
    DuckDbExtensionSpec,
    DuckDbQueryDefinition,
    DuckDbSessionSetting,
    EvaluationContext,
    EvaluationScope,
    FormulaAst,
    FormulaBundle,
    ResultColumn,
    TaggedScalarCell,
    derive_snapshot_restatement_history,
)
from smart_ads.application import (
    McpVerifiedReadIndex,
    RetentionRootSetService,
    VerifiedStoreMcpReadHandler,
    build_retention_root,
    build_seam_parity_record,
    compute_retention_reachability_graph,
    conduct_offline_run,
    execute_analysis_replay_bundle,
    execute_certified_report,
    head_pinned_object_refs,
    load_verified_snapshot_rows,
    verify_legacy_seam_release,
    verify_retention_root,
    verify_seam_parity_record,
    verify_stored_canonical_build_chain,
    verify_stored_decomposition_tip,
    verify_stored_legacy_merge_evidence,
    verify_tripartite_target,
)
import smart_ads.application.conductor as conductor_mod
from smart_ads.contracts import (
    PHASE1_BASE_METRICS,
    AlgorithmProvenanceIdentity,
    ArtifactLocator,
    BaseMetricDefinition,
    ClosedValidationError,
    ConsumerFeatureFlagContract,
    DateRange,
    GitArtifactProvenance,
    IbviAdsDelegationContext,
    IbviAdsDelegationContract,
    P1Integrity,
    ReadEntrypointSelector,
    SeamParityRecord,
    TripartiteCanonicalSide,
    TripartiteConsumerSide,
    TripartiteGitArtifactRef,
    TripartiteLegacySide,
    TripartiteTarget,
    canonicalize_jcs,
    compute_capture_replay_digest,
    compute_consumer_contract_digest,
    compute_git_blob_oid,
    loads_strict_json,
)
from smart_ads.contracts.effects import (
    AuthorizationReceipt,
    RetentionRootAdmissionTarget,
    sort_artifact_locators,
)
from smart_ads.contracts.retention import RetentionRootSetHead, compute_root_locator_set_digest
from smart_ads.domain import ExpectedResourceInventory, ExpectedResourceKey
from smart_ads.ports import CellObjectStorePort, SeamDualProjectionCase, SeamLegacyProjectorPort
from smart_ads.transports.mcp import (
    ALLOWED_MCP_METHODS,
    McpDelegationContext,
    McpRuntimeContext,
    project_delegation_envelope_to_mcp_context,
)
from tests.unit.test_conductor import (
    ConductorTestWorld,
    PolicyRuleOfflineIntelligence,
    ReadOnlyGuardStore,
    _CAMP_A,
    _CAMP_B,
    _put_signed_env as _cond_put_env,
    _put_signed_obj as _cond_put_obj,
    _scalar_row_count,
)
from tests.unit.test_duckdb_replay_and_reporting import (
    DeterministicInMemoryDuckDbEngine,
    _METRIC_ORDER,
    _METRIC_UKEY,
)
from tests.unit.test_mcp_read_handler import (
    DeterministicDomainP1Verifier,
    McpHandlerWorld,
    _put_signed_env as _mcp_put_env,
    _put_signed_obj as _mcp_put_obj,
    _two_camp_window_rows,
)
from tests.unit.test_seam_and_tripartite_verification import (
    FullDomainP1Verifier,
    MirrorLegacyProjector,
    _ADR_IDENTITY,
    _KEY_ID,
    _MAC_SECRET,
    _build_canonical_chain_in_store,
    _build_consumer_artifacts,
    _build_legacy_seam_artifacts,
    _build_mcp_cases_and_handler,
    _build_real_decomposition_artifacts,
    _build_run_and_merge_artifacts,
    _put_git_prov,
    _put_signed_dict,
    _put_signed_model,
    _sign_dict,
)
from tools.governance import artifacts as gov_artifacts, decomposition as gov_decomp


class _CorruptBytesStore(CellObjectStorePort):
    """Wraps a `CellObjectStorePort` to override or hide a specific bare object_ref."""

    def __init__(self, inner: CellObjectStorePort, *, missing_ref: str = "", override_bytes: dict[str, bytes] | None = None) -> None:
        self._inner = inner
        self._missing = missing_ref
        self._overrides = override_bytes or {}

    def put_bytes(self, raw: bytes) -> str:
        return self._inner.put_bytes(raw)

    def get_bytes(self, object_ref: str, *, expected_size_bytes: int | None = None) -> bytes:
        if object_ref == self._missing:
            raise ClosedValidationError(f"missing object_ref {object_ref}")
        if object_ref in self._overrides:
            return self._overrides[object_ref]
        return self._inner.get_bytes(object_ref, expected_size_bytes=expected_size_bytes)

    def has_object(self, object_ref: str) -> bool:
        return False if object_ref == self._missing else self._inner.has_object(object_ref)

    def put_json_artifact(self, schema_id: str, payload: Mapping[str, Any]) -> ArtifactLocator:
        return self._inner.put_json_artifact(schema_id, payload)

    def get_json_artifact(self, locator: ArtifactLocator) -> dict[str, Any]:
        if locator.object_ref == self._missing:
            raise ClosedValidationError(f"missing json object_ref {locator.object_ref}")
        return self._inner.get_json_artifact(locator)


def _build_stored_run_and_seam_world() -> tuple[InMemoryCellObjectStore, ArtifactLocator, Any, ArtifactLocator, Any, ArtifactLocator]:
    store = InMemoryCellObjectStore()
    key_reg_loc = store.put_json_artifact("smart_ads/key_authorization_registry/v1", {"$schema": "smart_ads/key_authorization_registry/v1", "keys": [_KEY_ID]})
    head_loc, manifest_loc, _, _ = _build_real_decomposition_artifacts(store, key_reg_loc)
    _, g2_rec_loc = _put_signed_dict(store, {"$schema": "smart_ads/gate2_approval_receipt/v1", "receipt_id": "g2:1"}, key_reg_loc)
    run_u = gov_artifacts.build_migration_run_context(gate2_receipt_locator=g2_rec_loc.to_dict(), approved_adr_git_identity=_ADR_IDENTITY, legacy_source_identity={"repository": "mbras-tech/mbras-campaigns", "commit_sha": "d26c73d8508c7c3d43161fe36a80c44a46bf0f2d"}, tenant_ref="tenant:ibvi", cell_ref="cell:ibvi-primary", run_id="run:ret-bare", created_at_utc="2026-11-10T00:00:00Z", key_registry_snapshot_locator=key_reg_loc.to_dict(), signer_key_id=_KEY_ID)
    _, run_loc = _put_signed_dict(store, run_u, key_reg_loc)
    _, _, rel_s, rel_loc, seam_bytes = _build_legacy_seam_artifacts(store, key_reg_loc, run_loc, head_loc, manifest_loc)
    store.put_bytes(seam_bytes)
    cons = _build_consumer_artifacts(store, key_reg_loc, run_loc)
    return store, run_loc, rel_s, rel_loc, cons["rb_s"], cons["rb_loc"]


def test_history_001_retention_reachability_pins_bare_seam_and_readback_blobs() -> None:
    store, run_loc, rel_s, rel_loc, rb_s, rb_loc = _build_stored_run_and_seam_world()
    bare_refs = {rel_s.baseline_commit_object_ref, *(e.child_commit_object_ref for e in rel_s.parent_edge_chain), rb_s.live_adapter_object_ref, rb_s.live_feature_flag_object_ref}
    closure = compute_retention_reachability_graph((rel_loc, rb_loc), store=store)
    assert bare_refs.issubset(set(closure.reachable_object_refs))
    root_rel, _ = build_retention_root(root_id="root:pr5-rel", cell_ref="cell:ibvi-primary", migration_run_context_locator=run_loc, target_artifact_locator=rel_loc, created_at_utc="2026-11-11T04:00:00Z", store=store)
    root_rb, _ = build_retention_root(root_id="root:pr5-rb", cell_ref="cell:ibvi-primary", migration_run_context_locator=run_loc, target_artifact_locator=rb_loc, created_at_utc="2026-11-11T04:00:00Z", store=store)
    pinned_union = set(verify_retention_root(root_rel, store=store).reachable_object_refs) | set(verify_retention_root(root_rb, store=store).reachable_object_refs)
    assert bare_refs.issubset(pinned_union)

    for ref in bare_refs:
        with pytest.raises(ClosedValidationError):
            compute_retention_reachability_graph((rel_loc, rb_loc), store=_CorruptBytesStore(store, missing_ref=ref))
        with pytest.raises(ClosedValidationError):
            compute_retention_reachability_graph((rel_loc, rb_loc), store=_CorruptBytesStore(store, override_bytes={ref: b""}))
        with pytest.raises(ClosedValidationError):
            compute_retention_reachability_graph((rel_loc, rb_loc), store=_CorruptBytesStore(store, override_bytes={ref: b"tampered"}))

    replay_kw = {"consumer_repository": "limaronaldo/hermes-ronaldo", "consumer_commit_sha": rb_s.consumer_commit_sha, "deployed_release_id": "release:1", "runtime_binary_sha256": "sha256:" + ("c" * 64), "captured_at_utc": "2026-11-11T03:00:00.500000Z", "capture_tool_identity": rb_s.capture_tool_identity, "capture_tool_build_digest": rb_s.capture_tool_build_digest, "live_adapter_artifact": rb_s.live_adapter_artifact, "live_adapter_object_ref": rb_s.live_adapter_object_ref, "live_feature_flag_artifact": rb_s.live_feature_flag_artifact, "live_feature_flag_object_ref": rb_s.live_feature_flag_object_ref, "live_disabled_legacy_route": "legacy:a", "live_enabled_smart_ads_route": "/ibvi-ads", "feature_flag_contract_digest": rb_s.feature_flag_contract_digest, "ibvi_ads_delegation_contract_digest": rb_s.ibvi_ads_delegation_contract_digest}
    with pytest.raises(ClosedValidationError, match="live_flag_key"):
        compute_capture_replay_digest(**replay_kw, live_flag_key="", live_default_enabled=False)
    with pytest.raises(ClosedValidationError, match="live_default_enabled"):
        compute_capture_replay_digest(**replay_kw, live_flag_key="ibvi_ads.smart_ads_read_v1", live_default_enabled="no")  # type: ignore[arg-type]


def test_history_001_retention_root_set_service_admits_bare_refs() -> None:
    store, run_loc, rel_s, rel_loc, rb_s, rb_loc = _build_stored_run_and_seam_world()
    _, r1_loc = build_retention_root(root_id="root:svc-rel", cell_ref="cell:ibvi-primary", migration_run_context_locator=run_loc, target_artifact_locator=rel_loc, created_at_utc="2026-11-11T04:00:00Z", store=store)
    _, r2_loc = build_retention_root(root_id="root:svc-rb", cell_ref="cell:ibvi-primary", migration_run_context_locator=run_loc, target_artifact_locator=rb_loc, created_at_utc="2026-11-11T04:00:00Z", store=store)
    admitted = sort_artifact_locators((r1_loc, r2_loc))
    h0 = RetentionRootSetHead("head:0", "cell:ibvi-primary", 0, (), None, "2026-11-11T04:00:00Z")
    h0_loc = store.put_json_artifact(h0.SCHEMA, h0.to_dict())
    b_dig = compute_retention_reachability_graph((), store=store).reachability_graph_digest
    adm_cl = compute_retention_reachability_graph(admitted, store=store)
    prop_dig = compute_root_locator_set_digest(admitted)
    target = RetentionRootAdmissionTarget(run_loc, "cell:ibvi-primary", h0_loc, 0, h0_loc.content_digest, admitted, adm_cl.reachable_object_refs, b_dig, adm_cl.reachability_graph_digest, prop_dig)
    auth = AuthorizationReceipt("auth:ret-bare", run_loc, "retention_root_admission", "retention_root_admission_effect_proof", target, "sha256:" + ("1" * 64), (), "principal:ops", "2026-11-11T04:01:00Z", "2026-11-11T05:00:00Z", "nonce-ret-bare")
    auth_loc = store.put_json_artifact(auth.SCHEMA, auth.to_dict())
    svc = RetentionRootSetService(store, h0_loc, require_signed=False)
    svc.admit_roots(authorization_locator=auth_loc, reservation_id="resv:1", reserved_at_utc="2026-11-11T04:02:00Z", new_head_id="head:1", cas_receipt_id="cas:1", cas_linearization_id="lin:1", committed_at_utc="2026-11-11T04:03:00Z", execution_id="ex:1", consumption_id="cn:1", effect_proof_id="ef:1", verified_at_utc="2026-11-11T04:04:00Z")
    pinned, _ = head_pinned_object_refs(svc.current_head()[1], store=store)
    assert {rel_s.baseline_commit_object_ref, rb_s.live_adapter_object_ref, rb_s.live_feature_flag_object_ref}.issubset(pinned)


def test_history_003_mcp_delegation_projector_enforces_require_signed_by_default() -> None:
    store = InMemoryCellObjectStore()
    key_reg_loc = store.put_json_artifact("smart_ads/key_authorization_registry/v1", {"$schema": "smart_ads/key_authorization_registry/v1", "keys": [_KEY_ID]})
    method = "smart_ads.queries.get_campaign_performance_v1"
    unsigned_none = IbviAdsDelegationContext("/ibvi-ads", "conductor:hermes", "front:pinna", "profile:pinna-ops", "tenant:ibvi", "binding:meta-primary", "scope:campaigns-active", method, "sha256:" + ("8" * 64), "2026-11-11T02:55:00Z", "2026-11-11T04:00:00Z", "nonce-h003")
    unsigned_2key = replace(unsigned_none, integrity=P1Integrity(_KEY_ID, key_reg_loc))
    signed_env, signed_loc = _put_signed_model(store, unsigned_none, key_reg_loc)

    for cand in (unsigned_none, unsigned_2key):
        with pytest.raises(ClosedValidationError):
            project_delegation_envelope_to_mcp_context(cand)
        with pytest.raises(ClosedValidationError):
            project_delegation_envelope_to_mcp_context(cand, require_signed=True)
        proj_u = project_delegation_envelope_to_mcp_context(cand, require_signed=False)
        assert proj_u.nonce == "nonce-h003" and proj_u.allowed_method == method

    with pytest.raises(ClosedValidationError):
        project_delegation_envelope_to_mcp_context(signed_env, require_signed=1)  # type: ignore[arg-type]
    proj_s = project_delegation_envelope_to_mcp_context(signed_env, locator=signed_loc)
    assert proj_s.locator == signed_loc and proj_s.tenant_ref == "tenant:ibvi"


def test_shallow_004_seam_case_deep_freezes_legacy_input_payload() -> None:
    method = "smart_ads.queries.get_campaign_performance_v1"
    wire = canonicalize_jcs({"jsonrpc": "2.0", "id": "1", "method": method, "params": {"tenant_ref": "tenant:ibvi", "binding_ref": "binding:meta-primary", "resource_scope_ref": "scope:campaigns-active", "date_range": {"start_date": "2026-11-10", "end_date": "2026-11-10"}}})
    caller_payload: dict[str, Any] = {"expected_wire": {"nested": {"items": [{"x": 1}]}}}
    case = SeamDualProjectionCase("case-freeze", method, wire, None, caller_payload)

    caller_payload["expected_wire"]["nested"]["items"][0]["x"] = 999
    assert isinstance(case.legacy_input_payload["expected_wire"]["nested"], MappingProxyType)
    assert case.legacy_input_payload["expected_wire"]["nested"]["items"] == (MappingProxyType({"x": 1}),)
    with pytest.raises(TypeError):
        case.legacy_input_payload["expected_wire"]["nested"]["x"] = 2  # type: ignore[index]
    with pytest.raises(TypeError):
        case.legacy_input_payload["expected_wire"]["nested"]["items"][0]["x"] = 2  # type: ignore[index]


def _make_contract_for_ast(adp_path: str, adp_bytes: bytes, flg_path: str, flg_bytes: bytes, entrypoints: tuple[tuple[str, str], ...]) -> ConsumerFeatureFlagContract:
    run_loc = ArtifactLocator.from_digest("smart_ads/migration_run_context/v1", "sha256:" + ("1" * 64))
    del_loc = ArtifactLocator.from_digest(IbviAdsDelegationContract.SCHEMA, "sha256:" + ("2" * 64))
    alg_loc = ArtifactLocator.from_digest(GitArtifactProvenance.SCHEMA, "sha256:" + ("3" * 64))
    adp_loc = ArtifactLocator.from_digest(GitArtifactProvenance.SCHEMA, "sha256:" + ("4" * 64))
    flg_loc = ArtifactLocator.from_digest(GitArtifactProvenance.SCHEMA, "sha256:" + ("5" * 64))
    adp_art = TripartiteGitArtifactRef(adp_path, compute_git_blob_oid(adp_bytes), "sha256:" + hashlib.sha256(adp_bytes).hexdigest(), adp_loc)
    flg_art = TripartiteGitArtifactRef(flg_path, compute_git_blob_oid(flg_bytes), "sha256:" + hashlib.sha256(flg_bytes).hexdigest(), flg_loc)
    alg = AlgorithmProvenanceIdentity("algorithm:ast-v1", "1.0.0", alg_loc, "aiconnai/smart-ads", "a" * 40, "src/smart_ads/adapters/consumer/routing_analyzer.py", "b" * 40, "sha256:" + ("c" * 64), "cpython-3.12", ConsumerFeatureFlagContract.SCHEMA)
    sels = tuple(ReadEntrypointSelector(ep, sf) for ep, sf in entrypoints)
    return ConsumerFeatureFlagContract(run_loc, "limaronaldo/hermes-ronaldo", "7" * 40, adp_art, flg_art, "ibvi_ads.smart_ads_read_v1", False, "legacy:mbras_direct", "/ibvi-ads", sels, alg, del_loc)


def test_shallow_001_ast_analyzer_rejects_non_closed_self_annotation() -> None:
    analyzer = Cpython312AstConsumerRoutingAnalyzer()
    flag_bytes = canonicalize_jcs({"flag_key": "ibvi_ads.smart_ads_read_v1", "default_enabled": False, "disabled_legacy_route": "legacy:mbras_direct", "enabled_smart_ads_route": "/ibvi-ads"})
    m = "smart_ads.queries.get_campaign_performance_v1"
    for bad_self in ("def __init__(self: bad(), flags, s, l):\n", "def _helper(self: mod.Attr, p):\n        return p\n    def __init__(self, flags, s, l):\n", ""):
        method_hdr = "def fetch(self: bad(), payload):" if not bad_self else "def fetch(self, payload):"
        init_hdr = bad_self if bad_self else "def __init__(self, flags, s, l):\n"
        src = (
            "FLAG_KEY = 'ibvi_ads.smart_ads_read_v1'\nclass Gw:\n    "
            + init_hdr
            + "        self.flags = flags\n        self.s = s\n        self.l = l\n    "
            + method_hdr
            + "\n        if self.flags.is_enabled(FLAG_KEY) is True:\n            return self.s.call('/ibvi-ads', '"
            + m
            + "', payload)\n        return self.l.call('legacy:mbras_direct', payload)\n"
        ).encode("utf-8")
        contract = _make_contract_for_ast("ibvi_ads/gw.py", src, "ibvi_ads/flags.json", flag_bytes, (("Gw.fetch", m),))
        with pytest.raises(ClosedValidationError):
            analyzer.analyze_consumer_routing(adapter_bytes=src, feature_flag_bytes=flag_bytes, contract=contract)


def test_deep_002_ast_analyzer_enforces_three_distinct_collaborators_and_class_roles() -> None:
    analyzer = Cpython312AstConsumerRoutingAnalyzer()
    flag_bytes = canonicalize_jcs({"flag_key": "ibvi_ads.smart_ads_read_v1", "default_enabled": False, "disabled_legacy_route": "legacy:mbras_direct", "enabled_smart_ads_route": "/ibvi-ads"})
    m1 = "smart_ads.queries.get_campaign_performance_v1"
    m2 = "smart_ads.queries.get_intelligence_findings_v1"

    same_collab = f"FLAG_KEY = 'ibvi_ads.smart_ads_read_v1'\ndef fetch(flags, client, payload):\n    if flags.is_enabled(FLAG_KEY) is True:\n        return client.call('/ibvi-ads', '{m1}', payload)\n    return client.call('legacy:mbras_direct', payload)\n".encode()
    with pytest.raises(ClosedValidationError):
        analyzer.analyze_consumer_routing(adapter_bytes=same_collab, feature_flag_bytes=flag_bytes, contract=_make_contract_for_ast("ibvi_ads/a.py", same_collab, "ibvi_ads/flags.json", flag_bytes, (("fetch", m1),)))

    swapped_roles = f"FLAG_KEY = 'ibvi_ads.smart_ads_read_v1'\nclass Gw:\n    def __init__(self, f, a, b):\n        self.f = f\n        self.a = a\n        self.b = b\n    def ep1(self, p):\n        if self.f.is_enabled(FLAG_KEY) is True:\n            return self.a.call('/ibvi-ads', '{m1}', p)\n        return self.b.call('legacy:mbras_direct', p)\n    def ep2(self, p):\n        if self.f.is_enabled(FLAG_KEY) is True:\n            return self.b.call('/ibvi-ads', '{m2}', p)\n        return self.a.call('legacy:mbras_direct', p)\n".encode()
    with pytest.raises(ClosedValidationError):
        analyzer.analyze_consumer_routing(adapter_bytes=swapped_roles, feature_flag_bytes=flag_bytes, contract=_make_contract_for_ast("ibvi_ads/a.py", swapped_roles, "ibvi_ads/flags.json", flag_bytes, (("Gw.ep1", m1), ("Gw.ep2", m2))))

    shadow_method = f"FLAG_KEY = 'ibvi_ads.smart_ads_read_v1'\nclass Gw:\n    def __init__(self, f, a, b):\n        self.f = f\n        self.a = a\n        self.b = b\n    def a(self):\n        return 1\n    def ep1(self, p):\n        if self.f.is_enabled(FLAG_KEY) is True:\n            return self.a.call('/ibvi-ads', '{m1}', p)\n        return self.b.call('legacy:mbras_direct', p)\n".encode()
    with pytest.raises(ClosedValidationError):
        analyzer.analyze_consumer_routing(adapter_bytes=shadow_method, feature_flag_bytes=flag_bytes, contract=_make_contract_for_ast("ibvi_ads/a.py", shadow_method, "ibvi_ads/flags.json", flag_bytes, (("Gw.ep1", m1),)))


def test_deep_003_ast_analyzer_enforces_python_adapter_path_and_flag_extension_dispatch() -> None:
    analyzer = Cpython312AstConsumerRoutingAnalyzer()
    m = "smart_ads.queries.get_campaign_performance_v1"
    adp = f"FLAG_KEY = 'ibvi_ads.smart_ads_read_v1'\ndef fetch(f, s, l, p):\n    if f.is_enabled(FLAG_KEY) is True:\n        return s.call('/ibvi-ads', '{m}', p)\n    return l.call('legacy:mbras_direct', p)\n".encode()
    flg_json = canonicalize_jcs({"flag_key": "ibvi_ads.smart_ads_read_v1", "default_enabled": False, "disabled_legacy_route": "legacy:mbras_direct", "enabled_smart_ads_route": "/ibvi-ads"})
    flg_py = b"FLAG_KEY = 'ibvi_ads.smart_ads_read_v1'\nDEFAULT_ENABLED = False\nDISABLED_LEGACY_ROUTE = 'legacy:mbras_direct'\nENABLED_SMART_ADS_ROUTE = '/ibvi-ads'\n"

    for adp_p, flg_p, flg_b in (
        ("ibvi_ads/adapter.txt", "ibvi_ads/flags.json", flg_json),
        ("ibvi_ads/adapter.py", "ibvi_ads/flags.py", flg_json),
        ("ibvi_ads/adapter.py", "ibvi_ads/flags.json", flg_py),
        ("ibvi_ads/adapter.py", "ibvi_ads/flags.yaml", flg_json),
    ):
        with pytest.raises(ClosedValidationError):
            analyzer.analyze_consumer_routing(adapter_bytes=adp, feature_flag_bytes=flg_b, contract=_make_contract_for_ast(adp_p, adp, flg_p, flg_b, (("fetch", m),)))


def test_shallow_003_unsigned_mode_with_non_none_verifier_across_mcp_and_conductor() -> None:
    mcp_w = McpHandlerWorld()
    u_inv = replace(mcp_w.eval_inv, integrity=None)
    u_inv_loc = mcp_w.store.put_json_artifact(ExpectedResourceInventory.SCHEMA, u_inv.to_dict())
    ver = DeterministicDomainP1Verifier()
    snap_u, rows_u = load_verified_snapshot_rows(mcp_w.snap2_loc, store=mcp_w.store, parquet_codec=mcp_w.codec, signature_verifier=ver, require_signed=False)
    assert snap_u == mcp_w.snap2 and len(rows_u) == 12 and ver.verified_schemas
    scope_key = ("tenant:ibvi", "binding:meta-primary", "scope:campaigns-active")
    idx_u = mcp_w.build_index(scope_inventory_locators={scope_key: (u_inv_loc,)}, signature_verifier=ver, require_signed=False)
    assert idx_u.require_signed is False

    bad_inv_dict = {**mcp_w.store.get_json_artifact(mcp_w.eval_inv_loc)}
    bad_inv_dict["integrity"] = {**bad_inv_dict["integrity"], "signature_base64": base64.b64encode(b"\x00" * 64).decode("ascii")}
    bad_inv_loc = mcp_w.store.put_json_artifact(ExpectedResourceInventory.SCHEMA, bad_inv_dict)
    with pytest.raises(ClosedValidationError):
        mcp_w.build_index(scope_inventory_locators={scope_key: (bad_inv_loc,)}, signature_verifier=ver, require_signed=False)

    cond_w = ConductorTestWorld()
    u_cond_inv = replace(cond_w.inventory, integrity=None)
    u_cond_inv_loc = cond_w.store.put_json_artifact(ExpectedResourceInventory.SCHEMA, u_cond_inv.to_dict())
    out = conduct_offline_run(run_input=cond_w.make_run_input(expected_resource_inventory_locator=u_cond_inv_loc, require_signed=False), intelligence=PolicyRuleOfflineIntelligence(cond_w.intel_alg_1))
    assert out.reduced_row_count == 12


def test_policy_003_snapshot_and_mcp_index_verify_migration_run_context() -> None:
    mcp_w = McpHandlerWorld()
    hidden_run = ReadOnlyGuardStore(mcp_w.store, hidden_refs=frozenset({mcp_w.run_loc.object_ref}))
    with pytest.raises(ClosedValidationError):
        load_verified_snapshot_rows(mcp_w.snap2_loc, store=hidden_run, parquet_codec=mcp_w.codec, signature_verifier=mcp_w.verifier, require_signed=True)
    with pytest.raises(ClosedValidationError):
        mcp_w.build_index(store=hidden_run)

    other_reg = replace(mcp_w.registry, tenant_ref="tenant:other", resource_mapping_contract_digest="", integrity=None)
    _, other_reg_loc = _mcp_put_obj(mcp_w.store, other_reg, mcp_w.key_reg_loc)
    with pytest.raises(ClosedValidationError):
        mcp_w.build_index(registry_snapshot_locator=other_reg_loc, scope_inventory_locators={}, findings_entries=(), summary_report_entries=())


def test_deep_004_mcp_findings_index_replays_evaluation_context_and_certification() -> None:
    mcp_w = McpHandlerWorld()
    scope_key = ("tenant:ibvi", "binding:meta-primary", "scope:campaigns-active")
    narrow_keys = tuple(ExpectedResourceKey("binding:meta-primary", "account:ibvi-01", _CAMP_A, "campaign", d) for d in ("2026-10-31", "2026-11-10"))
    _, narrow_inv_loc = _mcp_put_obj(mcp_w.store, ExpectedResourceInventory("inventory:narrow-001", mcp_w.reg_loc, mcp_w.reg_loc.content_digest, "tenant:ibvi", "binding:meta-primary", "account:ibvi-01", "scope:campaigns-active", DateRange("2026-10-31", "2026-11-10", True), narrow_keys), mcp_w.key_reg_loc)
    swapped_in = replace(mcp_w.rep2.canonical_report_input, expected_resource_inventory_locator=narrow_inv_loc)
    with pytest.raises(ClosedValidationError):
        mcp_w.build_index(findings_entries=((mcp_w.snap2_loc, *scope_key, mcp_w.exec2_loc, mcp_w.cert2_loc, mcp_w.f2_locs, swapped_in),))

    missing_hist_in = replace(mcp_w.rep2.canonical_report_input, restatement_history_generation_locators=())
    with pytest.raises(ClosedValidationError):
        mcp_w.build_index(findings_entries=((mcp_w.snap2_loc, *scope_key, mcp_w.exec2_loc, mcp_w.cert2_loc, mcp_w.f2_locs, missing_hist_in),))

    forged_cert = replace(mcp_w.cert2, derived_certification_status=DerivedCertificationStatus.UNAVAILABLE, integrity=None)
    _, forged_cert_loc = _mcp_put_obj(mcp_w.store, forged_cert, mcp_w.key_reg_loc)
    with pytest.raises(ClosedValidationError):
        mcp_w.build_index(findings_entries=((mcp_w.snap2_loc, *scope_key, mcp_w.exec2_loc, forged_cert_loc, mcp_w.f2_locs, mcp_w.rep2.canonical_report_input),))


def test_deep_005_mcp_summary_index_requires_inventory_date_coverage() -> None:
    mcp_w = McpHandlerWorld()
    scope_key = ("tenant:ibvi", "binding:meta-primary", "scope:campaigns-active")
    one_day_keys = tuple(ExpectedResourceKey("binding:meta-primary", "account:ibvi-01", c, "campaign", "2026-11-10") for c in (_CAMP_A, _CAMP_B))
    one_day_inv, one_day_inv_loc = _mcp_put_obj(mcp_w.store, ExpectedResourceInventory("inventory:1d-sum", mcp_w.reg_loc, mcp_w.reg_loc.content_digest, "tenant:ibvi", "binding:meta-primary", "account:ibvi-01", "scope:campaigns-active", DateRange("2026-11-10", "2026-11-10", True), one_day_keys), mcp_w.key_reg_loc)
    pol_1d = mcp_w.policy.from_dict({k: v for k, v in {**mcp_w.policy.to_dict(), "policy_id": "policy:restatement-1d-only", "rules": [{"rule_id": "rule:restatement-1d", "rule_type": "restatement", "lookback_days": 1, "restatement_kinds": ["value_change"]}]}.items() if k != "integrity"})
    pol_1d_s, pol_1d_loc = _mcp_put_obj(mcp_w.store, pol_1d, mcp_w.key_reg_loc)
    l_rows = tuple(r for gm in (mcp_w.gm_oct, mcp_w.gm_nov1, mcp_w.gm_nov2) for pq in gm.parquet_object_locators for r in mcp_w.codec.decode_and_verify_landing_rows(mcp_w.store.get_bytes(pq.object_ref, expected_size_bytes=pq.size_bytes), expected_partition_key=pq.partition_key))
    eval_ctx = EvaluationContext(pol_1d_s, EvaluationScope("tenant:ibvi", "scope:campaigns-active", "campaign", "meta", "BRL"), "2026-11-11T03:15:00.000000Z", "2026-11-10", 1, "2026-11-10", one_day_inv, "result:metrics", derive_snapshot_restatement_history(one_day_inv, l_rows))
    cols = tuple(ResultColumn(n, t, nl) for n, t, nl in METRIC_WINDOW_COLUMNS)
    q_m = DuckDbQueryDefinition("result:metrics", "query:metrics", "SELECT 1", mcp_w.metrics_schema_loc, "relation", cols, _METRIC_UKEY, _METRIC_ORDER)
    exts = (DuckDbExtensionSpec("parquet", "1.5.5", "explicit_local_binary", DuckDbExtensionBinaryLocator.for_binary_bytes(mcp_w.ext_bytes)),)
    _, b_loc = _mcp_put_obj(mcp_w.store, AnalysisReplayInputBundle("bundle:1d", mcp_w.run_loc, mcp_w.snap2_loc, "1.5.5", DuckDbBinaryObjectLocator.for_binary_bytes(mcp_w.duck_bytes), exts, (DuckDbSessionSetting("threads", TaggedScalarCell("int64", "1")),), (), (q_m,), pol_1d_loc, (mcp_w.tmpl_loc,)), mcp_w.key_reg_loc)
    eng = DeterministicInMemoryDuckDbEngine({"result:metrics": _two_camp_window_rows})
    _, _, u_res = execute_analysis_replay_bundle(bundle_locator=b_loc, store=mcp_w.store, parquet_codec=mcp_w.codec, duckdb_engine=eng, require_signed_inputs=True)
    s_res, _ = _mcp_put_obj(mcp_w.store, u_res[0][0], mcp_w.key_reg_loc)
    s_ex, _ = _mcp_put_obj(mcp_w.store, AnalysisExecution(b_loc, CanonicalResultSet.build(b_loc, (CanonicalResultEntry.from_result(s_res),))), mcp_w.key_reg_loc)
    _, ex_loc, _ = execute_analysis_replay_bundle(bundle_locator=b_loc, store=mcp_w.store, parquet_codec=mcp_w.codec, duckdb_engine=eng, result_integrities={"result:metrics": s_res.integrity}, execution_integrity=s_ex.integrity, require_signed_inputs=True)  # type: ignore[dict-item]
    att = (AttestedCertificationInput(CertificationInput(DerivedCertificationStatus.VERIFIED, "phase1_7b_base"), True),)
    _, _, _, _, u_f = execute_certified_report(report_id="rep:1d", executed_at_utc="2026-11-11T03:20:00Z", bundle_locator=b_loc, execution_locator=ex_loc, evaluation_context=eval_ctx, expected_resource_inventory_locator=one_day_inv_loc, curation_execution_locator=mcp_w.cur_nov2_loc, restatement_history_generation_locators=(mcp_w.gm_nov1_loc,), attested_certification_inputs=att, report_template_provenance_locator=mcp_w.tmpl_loc, render_algorithm_identity=mcp_w.render_alg, store=mcp_w.store, parquet_codec=mcp_w.codec)
    f_ints = tuple(_mcp_put_obj(mcp_w.store, f, mcp_w.key_reg_loc)[0].integrity for f, _ in u_f)
    _, _, u_c, _, _ = execute_certified_report(report_id="rep:1d", executed_at_utc="2026-11-11T03:20:00Z", bundle_locator=b_loc, execution_locator=ex_loc, evaluation_context=eval_ctx, expected_resource_inventory_locator=one_day_inv_loc, curation_execution_locator=mcp_w.cur_nov2_loc, restatement_history_generation_locators=(mcp_w.gm_nov1_loc,), attested_certification_inputs=att, report_template_provenance_locator=mcp_w.tmpl_loc, render_algorithm_identity=mcp_w.render_alg, store=mcp_w.store, parquet_codec=mcp_w.codec, finding_integrities=f_ints)  # type: ignore[arg-type]
    c_int = _mcp_put_obj(mcp_w.store, u_c, mcp_w.key_reg_loc)[0].integrity
    u_r, _, _, _, _ = execute_certified_report(report_id="rep:1d", executed_at_utc="2026-11-11T03:20:00Z", bundle_locator=b_loc, execution_locator=ex_loc, evaluation_context=eval_ctx, expected_resource_inventory_locator=one_day_inv_loc, curation_execution_locator=mcp_w.cur_nov2_loc, restatement_history_generation_locators=(mcp_w.gm_nov1_loc,), attested_certification_inputs=att, report_template_provenance_locator=mcp_w.tmpl_loc, render_algorithm_identity=mcp_w.render_alg, store=mcp_w.store, parquet_codec=mcp_w.codec, finding_integrities=f_ints, certification_integrity=c_int)  # type: ignore[arg-type]
    r_int = _mcp_put_obj(mcp_w.store, u_r, mcp_w.key_reg_loc)[0].integrity
    _, rep_1d_loc, _, _, _ = execute_certified_report(report_id="rep:1d", executed_at_utc="2026-11-11T03:20:00Z", bundle_locator=b_loc, execution_locator=ex_loc, evaluation_context=eval_ctx, expected_resource_inventory_locator=one_day_inv_loc, curation_execution_locator=mcp_w.cur_nov2_loc, restatement_history_generation_locators=(mcp_w.gm_nov1_loc,), attested_certification_inputs=att, report_template_provenance_locator=mcp_w.tmpl_loc, render_algorithm_identity=mcp_w.render_alg, store=mcp_w.store, parquet_codec=mcp_w.codec, finding_integrities=f_ints, certification_integrity=c_int, report_integrity=r_int, require_signed_inputs=True)  # type: ignore[arg-type]

    assert mcp_w.build_index(summary_report_entries=((mcp_w.snap2_loc, *scope_key, "daily", "2026-11-10", "2026-11-10", rep_1d_loc),))
    with pytest.raises(ClosedValidationError):
        mcp_w.build_index(summary_report_entries=((mcp_w.snap2_loc, *scope_key, "weekly", "2026-11-04", "2026-11-10", rep_1d_loc),))


def test_deep_009_conductor_filters_reduced_rows_to_inventory_and_guards_date_underflow() -> None:
    cond_w = ConductorTestWorld()
    camp_a_keys = tuple(ExpectedResourceKey("binding:meta-primary", "account:ibvi-01", _CAMP_A, "campaign", d) for d in ("2026-10-31", "2026-11-10"))
    _, camp_a_inv_loc = _cond_put_obj(cond_w.store, ExpectedResourceInventory("inventory:camp-a-only", cond_w.reg_loc, cond_w.reg_loc.content_digest, "tenant:ibvi", "binding:meta-primary", "account:ibvi-01", "scope:campaigns-active", DateRange("2026-10-31", "2026-11-10", True), camp_a_keys), cond_w.key_reg_loc)
    m_cols = tuple(ResultColumn(n, t, nl) for n, t, nl in METRIC_WINDOW_COLUMNS)
    q_m = DuckDbQueryDefinition("result:metrics", "query:metrics", "SELECT 1", cond_w.metrics_schema_loc, "relation", m_cols, _METRIC_UKEY, _METRIC_ORDER)
    exts = (DuckDbExtensionSpec("parquet", "1.5.5", "explicit_local_binary", DuckDbExtensionBinaryLocator.for_binary_bytes(cond_w.ext_bytes)),)
    _, b_loc = _cond_put_obj(cond_w.store, AnalysisReplayInputBundle("bundle:camp-a", cond_w.run_loc, cond_w.snap3_loc, "1.5.5", DuckDbBinaryObjectLocator.for_binary_bytes(cond_w.duck_bytes), exts, (DuckDbSessionSetting("threads", TaggedScalarCell("int64", "1")),), (), (q_m,), cond_w.policy_loc, (cond_w.tmpl_loc,)), cond_w.key_reg_loc)
    only_a_fn = lambda rows, q: tuple(r for r in _two_camp_window_rows(rows, q) if r[0].value == _CAMP_A)
    eng = DeterministicInMemoryDuckDbEngine({"result:metrics": only_a_fn})
    _, _, u_pairs = execute_analysis_replay_bundle(bundle_locator=b_loc, store=cond_w.store, parquet_codec=cond_w.codec, duckdb_engine=eng, require_signed_inputs=True)
    s_res, _ = _cond_put_obj(cond_w.store, u_pairs[0][0], cond_w.key_reg_loc)
    s_ex, _ = _cond_put_obj(cond_w.store, AnalysisExecution(b_loc, CanonicalResultSet.build(b_loc, (CanonicalResultEntry.from_result(s_res),))), cond_w.key_reg_loc)
    _, ex_loc, _ = execute_analysis_replay_bundle(bundle_locator=b_loc, store=cond_w.store, parquet_codec=cond_w.codec, duckdb_engine=eng, result_integrities={"result:metrics": s_res.integrity}, execution_integrity=s_ex.integrity, require_signed_inputs=True)  # type: ignore[dict-item]

    out = conduct_offline_run(run_input=cond_w.make_run_input(expected_resource_inventory_locator=camp_a_inv_loc, analysis_execution_locator=ex_loc, resolved_analysis_results=(s_res,)), intelligence=PolicyRuleOfflineIntelligence(cond_w.intel_alg_1))
    assert out.reduced_row_count == 6
    with pytest.raises(ClosedValidationError):
        conductor_mod._safe_shift_date(datetime.date(1, 1, 2), 10, label="test_underflow")


def test_deep_010_replay_bundle_verifies_formulas_base_metrics_git_inputs_and_binaries() -> None:
    cond_w = ConductorTestWorld()
    ctr_def = DerivedMetricDefinition("metric:ctr_v1", FormulaAst("DIVIDE_COUNT_BY_COUNT", "metric:clicks_v1", "metric:impressions_v1", "decimal_ratio", "ROUND_HALF_UP"))
    _, fb_loc = _cond_put_obj(cond_w.store, FormulaBundle(tuple(PHASE1_BASE_METRICS.values()), (ctr_def,)), cond_w.key_reg_loc)
    _, bm_loc = _cond_put_obj(cond_w.store, PHASE1_BASE_METRICS["metric:clicks_v1"], cond_w.key_reg_loc)
    s_cols = (ResultColumn("row_count", "int64", False),)
    m_cols = tuple(ResultColumn(n, t, nl) for n, t, nl in METRIC_WINDOW_COLUMNS)
    q_m = DuckDbQueryDefinition("result:metrics", "query:metrics", "SELECT 1", cond_w.metrics_schema_loc, "relation", m_cols, _METRIC_UKEY, _METRIC_ORDER)
    q_s = DuckDbQueryDefinition("result:row_count", "query:row_count", "SELECT 1", cond_w.scalar_schema_loc, "scalar", s_cols, None, ())
    duck_loc = DuckDbBinaryObjectLocator.for_binary_bytes(cond_w.duck_bytes)
    ext_loc = DuckDbExtensionBinaryLocator.for_binary_bytes(cond_w.ext_bytes)
    exts = (DuckDbExtensionSpec("parquet", "1.5.5", "explicit_local_binary", ext_loc),)
    raw_b = AnalysisReplayInputBundle("bundle:d010", cond_w.run_loc, cond_w.snap3_loc, "1.5.5", duck_loc, exts, (DuckDbSessionSetting("threads", TaggedScalarCell("int64", "1")),), (), (q_m, q_s), cond_w.policy_loc, sort_artifact_locators((cond_w.tmpl_loc, fb_loc, bm_loc)))
    _, b_loc = _cond_put_obj(cond_w.store, raw_b, cond_w.key_reg_loc)
    eng = DeterministicInMemoryDuckDbEngine({"result:metrics": _two_camp_window_rows, "result:row_count": _scalar_row_count})
    _, _, u_pairs = execute_analysis_replay_bundle(bundle_locator=b_loc, store=cond_w.store, parquet_codec=cond_w.codec, duckdb_engine=eng, require_signed_inputs=True)
    signed_res = {r.result_key: _cond_put_obj(cond_w.store, r, cond_w.key_reg_loc)[0] for r, _ in u_pairs}
    entries = tuple(CanonicalResultEntry.from_result(signed_res[k]) for k in sorted(signed_res))
    s_ex, _ = _cond_put_obj(cond_w.store, AnalysisExecution(b_loc, CanonicalResultSet.build(b_loc, entries)), cond_w.key_reg_loc)
    _, ex_loc, _ = execute_analysis_replay_bundle(bundle_locator=b_loc, store=cond_w.store, parquet_codec=cond_w.codec, duckdb_engine=eng, result_integrities={k: v.integrity for k, v in signed_res.items()}, execution_integrity=s_ex.integrity, require_signed_inputs=True)  # type: ignore[arg-type]
    res_tuple = tuple(signed_res[k] for k in sorted(signed_res))

    intel = PolicyRuleOfflineIntelligence(cond_w.intel_alg_1)
    assert conduct_offline_run(run_input=cond_w.make_run_input(analysis_execution_locator=ex_loc, resolved_analysis_results=res_tuple), intelligence=intel).reduced_row_count == 12
    for hide_ref in (fb_loc.object_ref, bm_loc.object_ref, cond_w.tmpl_loc.object_ref, duck_loc.object_ref, ext_loc.object_ref):
        guarded = ReadOnlyGuardStore(cond_w.store, hidden_refs=frozenset({hide_ref}))
        with pytest.raises(ClosedValidationError):
            conduct_offline_run(run_input=cond_w.make_run_input(analysis_execution_locator=ex_loc, resolved_analysis_results=res_tuple, store=guarded), intelligence=intel)


def test_policy_001_canonical_build_chain_verifies_77_modules_constituents_and_chronology() -> None:
    store, verifier = InMemoryCellObjectStore(), FullDomainP1Verifier()
    key_reg_loc = store.put_json_artifact("smart_ads/key_authorization_registry/v1", {"$schema": "smart_ads/key_authorization_registry/v1", "keys": [_KEY_ID]})
    run_loc, _, _ = _build_run_and_merge_artifacts(store, key_reg_loc, release_sha="e" * 40, reviewed_sha="d" * 40)
    can = _build_canonical_chain_in_store(store, key_reg_loc, run_loc)

    _, bad_prov = _put_signed_dict(store, {**can["prov_u"], "build_backend_version": "1.32.0"}, key_reg_loc)
    with pytest.raises(ClosedValidationError):
        verify_stored_canonical_build_chain(store, wheel_locator=can["whl_obj"], wheel_digest=can["whl_obj"].wheel_digest, build_provenance_locator=bad_prov, wheel_boundary_report_locator=can["bound_loc"], certification_7a_locator=can["cert7a_loc"], gov1_convergence_locator=can["conv_loc"], expected_run_locator=run_loc, expected_commit_sha=can["commit_sha"], signature_verifier=verifier)

    _, bad_bound = _put_signed_dict(store, {**can["bound_u"], "packaged_modules": ["smart_ads"]}, key_reg_loc)
    _, bad_c7a = _put_signed_model(store, replace(can["rec7a_s"], wheel_boundary_report_locator=bad_bound, integrity=None), key_reg_loc)
    _, bad_conv_b = _put_signed_dict(store, {**can["conv_u"], "wheel_boundary_report_locator": bad_bound.to_dict(), "certification_7a_record_locator": bad_c7a.to_dict()}, key_reg_loc)
    with pytest.raises(ClosedValidationError):
        verify_stored_canonical_build_chain(store, wheel_locator=can["whl_obj"], wheel_digest=can["whl_obj"].wheel_digest, build_provenance_locator=can["prov_loc"], wheel_boundary_report_locator=bad_bound, certification_7a_locator=bad_c7a, gov1_convergence_locator=bad_conv_b, expected_run_locator=run_loc, expected_commit_sha=can["commit_sha"], signature_verifier=verifier)

    bad_cases = [{**can["mcp_u"]["cases"][0], "io_counters": {**can["mcp_u"]["cases"][0]["io_counters"], "network_calls": 1}}, *can["mcp_u"]["cases"][1:]]
    _, bad_mcp = _put_signed_dict(store, {**can["mcp_u"], "cases": bad_cases}, key_reg_loc)
    for conv_patch in (
        {"convergence_status": "PASSED"},
        {"converged_at_utc": "2026-09-07T10:00:20Z"},
        {"mcp_rejection_matrix_report_locator": bad_mcp.to_dict()},
    ):
        _, bad_conv = _put_signed_dict(store, {**can["conv_u"], **conv_patch}, key_reg_loc)
        with pytest.raises(ClosedValidationError):
            verify_stored_canonical_build_chain(store, wheel_locator=can["whl_obj"], wheel_digest=can["whl_obj"].wheel_digest, build_provenance_locator=can["prov_loc"], wheel_boundary_report_locator=can["bound_loc"], certification_7a_locator=can["cert7a_loc"], gov1_convergence_locator=bad_conv, expected_run_locator=run_loc, expected_commit_sha=can["commit_sha"], signature_verifier=verifier)

    for hide_loc in (can["sbx_loc"], can["neg_loc"], can["mcp_rep_loc"]):
        with pytest.raises(ClosedValidationError):
            verify_stored_canonical_build_chain(_CorruptBytesStore(store, missing_ref=hide_loc.object_ref), wheel_locator=can["whl_obj"], wheel_digest=can["whl_obj"].wheel_digest, build_provenance_locator=can["prov_loc"], wheel_boundary_report_locator=can["bound_loc"], certification_7a_locator=can["cert7a_loc"], gov1_convergence_locator=can["conv_loc"], expected_run_locator=run_loc, expected_commit_sha=can["commit_sha"], signature_verifier=verifier)


def test_policy_002_decomposition_tip_enforces_closed_44_path_scope_and_lineage_walk() -> None:
    store, verifier = InMemoryCellObjectStore(), FullDomainP1Verifier()
    key_reg_loc = store.put_json_artifact("smart_ads/key_authorization_registry/v1", {"$schema": "smart_ads/key_authorization_registry/v1", "keys": [_KEY_ID]})
    head_loc, manifest_loc, head_s, manifest_s = _build_real_decomposition_artifacts(store, key_reg_loc)

    base_u = {k: v for k, v in manifest_s.items() if k not in {"manifest_digest", "integrity"}}
    for bad_m in (
        {**base_u, "entries": [{**base_u["entries"][0], "blocking_defects": ["defect:1"]}, *base_u["entries"][1:]]},
        {**base_u, "source_inventory": {**base_u["source_inventory"], "declared_paths": ["scripts/operator/conductor.py"]}},
        {**base_u, "source_inventory": {**base_u["source_inventory"], "inventory_scope": {**base_u["source_inventory"]["inventory_scope"], "extra": 1}}},
        {**base_u, "entries": [{**base_u["entries"][0], "extra": 1}, *base_u["entries"][1:]]},
    ):
        bad_m["manifest_digest"] = gov_decomp.manifest_digest(bad_m)
        _, bm_loc = _put_signed_dict(store, bad_m, key_reg_loc)
        _, bh_loc = _put_signed_dict(store, {**head_s, "active_manifest_locator": bm_loc.to_dict(), "active_manifest_digest": bm_loc.content_digest}, key_reg_loc)
        with pytest.raises(ClosedValidationError):
            verify_stored_decomposition_tip(store, head_locator=bh_loc, expected_active_head_locator=bh_loc, manifest_locator=bm_loc, expected_manifest_digest=bm_loc.content_digest, signature_verifier=verifier)

    corr_u = {**base_u, "generated_at": "2026-09-08T00:00:00Z", "supersedes_manifest_locator": manifest_loc.to_dict(), "supersedes_digest": manifest_loc.content_digest, "correction_reason": "reason:fix"}
    corr_u["manifest_digest"] = gov_decomp.manifest_digest(corr_u)
    _, corr_loc = _put_signed_dict(store, corr_u, key_reg_loc)
    for bad_h_patch in (
        {"head_epoch": 3},
        {"updated_at_utc": "2026-09-07T00:01:00Z"},
    ):
        _, bad_h2 = _put_signed_dict(store, {**head_s, "head_epoch": 2, "active_manifest_locator": corr_loc.to_dict(), "active_manifest_digest": corr_loc.content_digest, "previous_head_locator": head_loc.to_dict(), "previous_head_digest": head_loc.content_digest, "update_kind": "correction", "updated_at_utc": "2026-09-08T00:05:00Z", **bad_h_patch}, key_reg_loc)
        with pytest.raises(ClosedValidationError):
            verify_stored_decomposition_tip(store, head_locator=bad_h2, expected_active_head_locator=bad_h2, manifest_locator=corr_loc, expected_manifest_digest=corr_loc.content_digest, signature_verifier=verifier)

    eq_gen = {**base_u, "generated_at": "2026-09-07T00:00:00Z", "supersedes_manifest_locator": manifest_loc.to_dict(), "supersedes_digest": manifest_loc.content_digest, "correction_reason": "reason:same-ts"}
    eq_gen["manifest_digest"] = gov_decomp.manifest_digest(eq_gen)
    _, eq_loc = _put_signed_dict(store, eq_gen, key_reg_loc)
    _, eq_h2 = _put_signed_dict(store, {**head_s, "head_epoch": 2, "active_manifest_locator": eq_loc.to_dict(), "active_manifest_digest": eq_loc.content_digest, "previous_head_locator": head_loc.to_dict(), "previous_head_digest": head_loc.content_digest, "update_kind": "correction", "updated_at_utc": "2026-09-08T00:05:00Z"}, key_reg_loc)
    with pytest.raises(ClosedValidationError):
        verify_stored_decomposition_tip(store, head_locator=eq_h2, expected_active_head_locator=eq_h2, manifest_locator=eq_loc, expected_manifest_digest=eq_loc.content_digest, signature_verifier=verifier)

    _, ok_h2 = _put_signed_dict(store, {**head_s, "head_epoch": 2, "active_manifest_locator": corr_loc.to_dict(), "active_manifest_digest": corr_loc.content_digest, "previous_head_locator": head_loc.to_dict(), "previous_head_digest": head_loc.content_digest, "update_kind": "correction", "updated_at_utc": "2026-09-08T00:05:00Z"}, key_reg_loc)
    with pytest.raises(ClosedValidationError):
        verify_stored_decomposition_tip(_CorruptBytesStore(store, missing_ref=head_loc.object_ref), head_locator=ok_h2, expected_active_head_locator=ok_h2, manifest_locator=corr_loc, expected_manifest_digest=corr_loc.content_digest, signature_verifier=verifier)


def test_deep_008_legacy_merge_evidence_verifies_stored_gate2_authority_policy() -> None:
    store, verifier = InMemoryCellObjectStore(), FullDomainP1Verifier()
    key_reg_loc = store.put_json_artifact("smart_ads/key_authorization_registry/v1", {"$schema": "smart_ads/key_authorization_registry/v1", "keys": [_KEY_ID]})
    _, merge_loc, pol_dig = _build_run_and_merge_artifacts(store, key_reg_loc, release_sha="e" * 40, reviewed_sha="d" * 40)
    merge_raw = store.get_json_artifact(merge_loc)
    pol_loc = ArtifactLocator.from_dict(merge_raw["branch_protection_policy"]["locator"])

    with pytest.raises(ClosedValidationError):
        verify_stored_legacy_merge_evidence(_CorruptBytesStore(store, missing_ref=pol_loc.object_ref), merge_loc, expected_repository="mbras-tech/mbras-campaigns", expected_protected_ref="refs/heads/main", expected_pr_number=77, expected_reviewed_head_sha="d" * 40, expected_protected_merge_sha="e" * 40, expected_adr_git_identity=_ADR_IDENTITY, expected_branch_policy_digest=pol_dig, signature_verifier=verifier)

    pol_u = gov_artifacts.build_gate2_authority_policy("mbras-tech/mbras-campaigns", "refs/heads/main", "docs/adr/ADR-0001-smart-ads-read-gateway.md", "sha256:" + ("4" * 64), ["principal:ronaldo"], key_reg_loc.to_dict(), _KEY_ID)
    for bad_pol in (
        {**pol_u, "repository": "aiconnai/smart-ads"},
        {**pol_u, "protected_ref": "refs/heads/develop"},
        {**pol_u, "adr_path": "docs/adr/WRONG.md"},
        {**pol_u, "designated_principals": ["principal:z", "principal:a"]},
    ):
        _, bad_pol_loc = _put_signed_dict(store, bad_pol, key_reg_loc)
        _, bad_m_loc = _put_signed_dict(store, {**merge_raw, "branch_protection_policy": {"locator": bad_pol_loc.to_dict(), "digest": bad_pol_loc.content_digest}}, key_reg_loc)
        with pytest.raises(ClosedValidationError):
            verify_stored_legacy_merge_evidence(store, bad_m_loc, expected_repository="mbras-tech/mbras-campaigns", expected_protected_ref="refs/heads/main", expected_pr_number=77, expected_reviewed_head_sha="d" * 40, expected_protected_merge_sha="e" * 40, expected_adr_git_identity=_ADR_IDENTITY, expected_branch_policy_digest=bad_pol_loc.content_digest, signature_verifier=verifier)


def test_deep_006_seam_parity_verifies_handler_store_provenance_and_stored_delegation() -> None:
    store, verifier = InMemoryCellObjectStore(), FullDomainP1Verifier()
    key_reg_loc = store.put_json_artifact("smart_ads/key_authorization_registry/v1", {"$schema": "smart_ads/key_authorization_registry/v1", "keys": [_KEY_ID]})
    head_loc, manifest_loc, _, _ = _build_real_decomposition_artifacts(store, key_reg_loc)
    run_loc, _, _ = _build_run_and_merge_artifacts(store, key_reg_loc, release_sha="e" * 40, reviewed_sha="d" * 40)
    _, _, _, rel_loc, seam_bytes = _build_legacy_seam_artifacts(store, key_reg_loc, run_loc, head_loc, manifest_loc)
    can = _build_canonical_chain_in_store(store, key_reg_loc, run_loc)
    alg_p, alg_loc = _put_git_prov(store, key_reg_loc, "aiconnai/smart-ads", can["commit_sha"], "src/smart_ads/application/seam_parity.py", b"# seam")
    seam_alg = AlgorithmProvenanceIdentity("algorithm:seam-parity-v1", "1.0.0", alg_loc, alg_p.repository, alg_p.commit_sha, alg_p.path, alg_p.git_blob_oid, alg_p.file_content_sha256, "cpython-3.12", SeamParityRecord.SCHEMA)
    handler, cases = _build_mcp_cases_and_handler(store, key_reg_loc, run_loc, verifier)
    signer = lambda d, _p: _sign_dict(d, key_reg_loc)

    rec_1, _ = build_seam_parity_record(legacy_seam_release_locator=rel_loc, expected_active_decomposition_head_locator=head_loc, wheel_build_provenance_locator=can["prov_loc"], wheel_digest=can["whl_obj"].wheel_digest, seam_adapter_algorithm_identity=seam_alg, evaluated_at_utc="2026-11-11T03:10:00Z", seam_raw_bytes=seam_bytes, cases_by_surface=cases, canonical_handler=handler, legacy_projector=MirrorLegacyProjector(), store=store, integrity=P1Integrity(_KEY_ID, key_reg_loc), envelope_signer=signer, signature_verifier=verifier)
    m0 = ALLOWED_MCP_METHODS[0]
    c0 = cases[m0][0]
    alt_del, alt_del_loc = _put_signed_model(store, IbviAdsDelegationContext("/ibvi-ads", "conductor:hermes", "front:pinna", "profile:pinna-ops", "tenant:ibvi", "binding:meta-primary", "scope:campaigns-active", m0, "sha256:" + ("9" * 64), "2026-11-11T02:55:00Z", "2026-11-11T04:00:00Z", "nonce-alt-006"), key_reg_loc)
    alt_rt = McpRuntimeContext("2026-11-11T03:00:00Z", "2026-11-11T03:00:02Z", project_delegation_envelope_to_mcp_context(alt_del, locator=alt_del_loc))
    alt_cases = {**cases, m0: (SeamDualProjectionCase(c0.case_id, m0, c0.mcp_wire_request_bytes, alt_rt, dict(c0.legacy_input_payload)),)}
    rec_2, _ = build_seam_parity_record(legacy_seam_release_locator=rel_loc, expected_active_decomposition_head_locator=head_loc, wheel_build_provenance_locator=can["prov_loc"], wheel_digest=can["whl_obj"].wheel_digest, seam_adapter_algorithm_identity=seam_alg, evaluated_at_utc="2026-11-11T03:10:00Z", seam_raw_bytes=seam_bytes, cases_by_surface=alt_cases, canonical_handler=handler, legacy_projector=MirrorLegacyProjector(), store=store, integrity=P1Integrity(_KEY_ID, key_reg_loc), envelope_signer=signer, signature_verifier=verifier)
    assert rec_1.surface_comparisons != rec_2.surface_comparisons

    unstored_handler = McpHandlerWorld().default_handler
    unsigned_handler = VerifiedStoreMcpReadHandler(McpHandlerWorld(store=store, run_loc=run_loc, key_reg_loc=key_reg_loc, verifier=verifier, secret=_MAC_SECRET).build_index(require_signed=False))
    for bad_h in (unstored_handler, unsigned_handler):
        with pytest.raises(ClosedValidationError):
            build_seam_parity_record(legacy_seam_release_locator=rel_loc, expected_active_decomposition_head_locator=head_loc, wheel_build_provenance_locator=can["prov_loc"], wheel_digest=can["whl_obj"].wheel_digest, seam_adapter_algorithm_identity=seam_alg, evaluated_at_utc="2026-11-11T03:10:00Z", seam_raw_bytes=seam_bytes, cases_by_surface=cases, canonical_handler=bad_h, legacy_projector=MirrorLegacyProjector(), store=store, integrity=P1Integrity(_KEY_ID, key_reg_loc), envelope_signer=signer, signature_verifier=verifier)
    with pytest.raises(ClosedValidationError):
        build_seam_parity_record(legacy_seam_release_locator=rel_loc, expected_active_decomposition_head_locator=head_loc, wheel_build_provenance_locator=can["prov_loc"], wheel_digest=can["whl_obj"].wheel_digest, seam_adapter_algorithm_identity=seam_alg, evaluated_at_utc="2026-11-11T03:10:00Z", seam_raw_bytes=seam_bytes, cases_by_surface=cases, canonical_handler=handler, legacy_projector=MirrorLegacyProjector(), store=_CorruptBytesStore(store, missing_ref=c0.mcp_runtime_context.delegation_context.locator.object_ref), integrity=P1Integrity(_KEY_ID, key_reg_loc), envelope_signer=signer, signature_verifier=verifier)


def test_policy_004_and_shallow_002_seam_parity_requires_signed_before_put_and_guards_signer() -> None:
    store, verifier = InMemoryCellObjectStore(), FullDomainP1Verifier()
    key_reg_loc = store.put_json_artifact("smart_ads/key_authorization_registry/v1", {"$schema": "smart_ads/key_authorization_registry/v1", "keys": [_KEY_ID]})
    head_loc, manifest_loc, _, _ = _build_real_decomposition_artifacts(store, key_reg_loc)
    run_loc, _, _ = _build_run_and_merge_artifacts(store, key_reg_loc, release_sha="e" * 40, reviewed_sha="d" * 40)
    _, _, _, rel_loc, seam_bytes = _build_legacy_seam_artifacts(store, key_reg_loc, run_loc, head_loc, manifest_loc)
    can = _build_canonical_chain_in_store(store, key_reg_loc, run_loc)
    alg_p, alg_loc = _put_git_prov(store, key_reg_loc, "aiconnai/smart-ads", can["commit_sha"], "src/smart_ads/application/seam_parity.py", b"# seam")
    seam_alg = AlgorithmProvenanceIdentity("algorithm:seam-parity-v1", "1.0.0", alg_loc, alg_p.repository, alg_p.commit_sha, alg_p.path, alg_p.git_blob_oid, alg_p.file_content_sha256, "cpython-3.12", SeamParityRecord.SCHEMA)
    handler, cases = _build_mcp_cases_and_handler(store, key_reg_loc, run_loc, verifier)

    kw: dict[str, Any] = {"legacy_seam_release_locator": rel_loc, "expected_active_decomposition_head_locator": head_loc, "wheel_build_provenance_locator": can["prov_loc"], "wheel_digest": can["whl_obj"].wheel_digest, "seam_adapter_algorithm_identity": seam_alg, "evaluated_at_utc": "2026-11-11T03:10:00Z", "seam_raw_bytes": seam_bytes, "cases_by_surface": cases, "canonical_handler": handler, "legacy_projector": MirrorLegacyProjector(), "store": ReadOnlyGuardStore(store), "signature_verifier": verifier}
    for bad_int in (None, P1Integrity(_KEY_ID, key_reg_loc)):
        with pytest.raises(ClosedValidationError, match="envelope_signer|signed"):
            build_seam_parity_record(**kw, integrity=bad_int, envelope_signer=None, require_signed=True)

    for bad_signer in (
        lambda _d, _p: (_ for _ in ()).throw(RuntimeError("hsm failure")),
        lambda d, _p: _sign_dict({**d, "evaluated_at_utc": "2026-11-11T03:59:59Z"}, key_reg_loc),
    ):
        with pytest.raises(ClosedValidationError):
            build_seam_parity_record(**kw, integrity=P1Integrity(_KEY_ID, key_reg_loc), envelope_signer=bad_signer, require_signed=True)


def test_deep_006_seam_parity_rebuilds_full_mcp_index_against_store_and_verifier() -> None:
    store, verifier = InMemoryCellObjectStore(), FullDomainP1Verifier()
    key_reg_loc = store.put_json_artifact("smart_ads/key_authorization_registry/v1", {"$schema": "smart_ads/key_authorization_registry/v1", "keys": [_KEY_ID]})
    head_loc, manifest_loc, _, _ = _build_real_decomposition_artifacts(store, key_reg_loc)
    run_loc, _, _ = _build_run_and_merge_artifacts(store, key_reg_loc, release_sha="e" * 40, reviewed_sha="d" * 40)
    _, _, _, rel_loc, seam_bytes = _build_legacy_seam_artifacts(store, key_reg_loc, run_loc, head_loc, manifest_loc)
    can = _build_canonical_chain_in_store(store, key_reg_loc, run_loc)
    alg_p, alg_loc = _put_git_prov(store, key_reg_loc, "aiconnai/smart-ads", can["commit_sha"], "src/smart_ads/application/seam_parity.py", b"# seam")
    seam_alg = AlgorithmProvenanceIdentity("algorithm:seam-parity-v1", "1.0.0", alg_loc, alg_p.repository, alg_p.commit_sha, alg_p.path, alg_p.git_blob_oid, alg_p.file_content_sha256, "cpython-3.12", SeamParityRecord.SCHEMA)
    handler, cases = _build_mcp_cases_and_handler(store, key_reg_loc, run_loc, verifier)
    signer = lambda d, _p: _sign_dict(d, key_reg_loc)
    _, signed_loc = build_seam_parity_record(legacy_seam_release_locator=rel_loc, expected_active_decomposition_head_locator=head_loc, wheel_build_provenance_locator=can["prov_loc"], wheel_digest=can["whl_obj"].wheel_digest, seam_adapter_algorithm_identity=seam_alg, evaluated_at_utc="2026-11-11T03:10:00Z", seam_raw_bytes=seam_bytes, cases_by_surface=cases, canonical_handler=handler, legacy_projector=MirrorLegacyProjector(), store=store, integrity=P1Integrity(_KEY_ID, key_reg_loc), envelope_signer=signer, signature_verifier=verifier)

    idx = handler.index
    inv_loc = next(iter(idx._scope_inventory_locators.values()))[0]
    cert_loc, f_loc = idx._findings_entries[1][5], idx._findings_entries[1][6][0]
    rep_loc = idx._summary_report_entries[0][7]
    for missing in (inv_loc.object_ref, cert_loc.object_ref, f_loc.object_ref, rep_loc.object_ref):
        bad_store = _CorruptBytesStore(store, missing_ref=missing)
        with pytest.raises(ClosedValidationError):
            build_seam_parity_record(legacy_seam_release_locator=rel_loc, expected_active_decomposition_head_locator=head_loc, wheel_build_provenance_locator=can["prov_loc"], wheel_digest=can["whl_obj"].wheel_digest, seam_adapter_algorithm_identity=seam_alg, evaluated_at_utc="2026-11-11T03:10:00Z", seam_raw_bytes=seam_bytes, cases_by_surface=cases, canonical_handler=handler, legacy_projector=MirrorLegacyProjector(), store=bad_store, integrity=P1Integrity(_KEY_ID, key_reg_loc), envelope_signer=signer, signature_verifier=verifier)
        with pytest.raises(ClosedValidationError):
            verify_seam_parity_record(signed_loc, expected_active_decomposition_head_locator=head_loc, seam_raw_bytes=seam_bytes, cases_by_surface=cases, canonical_handler=handler, legacy_projector=MirrorLegacyProjector(), store=bad_store, signature_verifier=verifier)

    class _SchemaRejectingVerifier(FullDomainP1Verifier):
        def __init__(self, blocked: str) -> None:
            super().__init__()
            self._blocked = blocked

        def verify_p1_envelope_signature(self, *, envelope: Mapping[str, Any], domain_prefix: str, store: CellObjectStorePort) -> None:
            if envelope.get("$schema") == self._blocked:
                raise ClosedValidationError(f"rejected {self._blocked}")
            super().verify_p1_envelope_signature(envelope=envelope, domain_prefix=domain_prefix, store=store)

    for blocked in ("smart_ads/expected_resource_inventory/v1", "smart_ads/finding/v1", "smart_ads/report_execution/v1"):
        with pytest.raises(ClosedValidationError):
            verify_seam_parity_record(signed_loc, expected_active_decomposition_head_locator=head_loc, seam_raw_bytes=seam_bytes, cases_by_surface=cases, canonical_handler=handler, legacy_projector=MirrorLegacyProjector(), store=store, signature_verifier=_SchemaRejectingVerifier(blocked))


def test_delta_002_store_proxy_translates_runtime_error_and_rejects_non_mapping_json() -> None:
    mcp_w = McpHandlerWorld()

    class _FaultyStore(CellObjectStorePort):
        def __init__(self, *, mode: str) -> None:
            self._mode = mode

        def put_bytes(self, raw: bytes) -> str:
            raise RuntimeError("unused")

        def get_bytes(self, object_ref: str, *, expected_size_bytes: int | None = None) -> bytes:
            if self._mode == "bytes_err":
                raise RuntimeError("io error")
            return mcp_w.store.get_bytes(object_ref, expected_size_bytes=expected_size_bytes)

        def has_object(self, object_ref: str) -> bool:
            return mcp_w.store.has_object(object_ref)

        def put_json_artifact(self, schema_id: str, payload: Mapping[str, Any]) -> ArtifactLocator:
            raise RuntimeError("unused")

        def get_json_artifact(self, locator: ArtifactLocator) -> Any:
            if self._mode == "json_err":
                raise RuntimeError("json store failure")
            if self._mode == "list_json":
                return ["integrity"]
            return mcp_w.store.get_json_artifact(locator)

    list_loc = ArtifactLocator.for_canonical_bytes("smart_ads/private_registry_snapshot/v1", canonicalize_jcs(["integrity"]))
    with pytest.raises(ClosedValidationError):
        mcp_w.build_index(registry_snapshot_locator=list_loc, store=_FaultyStore(mode="list_json"), require_signed=False)
    with pytest.raises(ClosedValidationError):
        load_verified_snapshot_rows(mcp_w.snap2_loc, store=_FaultyStore(mode="json_err"), parquet_codec=mcp_w.codec, signature_verifier=mcp_w.verifier)
    with pytest.raises(ClosedValidationError):
        load_verified_snapshot_rows(mcp_w.snap2_loc, store=_FaultyStore(mode="bytes_err"), parquet_codec=mcp_w.codec, signature_verifier=mcp_w.verifier)
