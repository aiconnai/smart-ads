"""Regression tests for Fix Wave 3 external review notes across PR 5 surfaces."""
from __future__ import annotations

import ast
import base64
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from smart_ads.adapters.consumer.routing_analyzer import Cpython312AstConsumerRoutingAnalyzer
from smart_ads.adapters.storage import InMemoryCellObjectStore
from smart_ads.analytics import (
    METRIC_WINDOW_COLUMNS, AnalysisExecution, AnalysisReplayInputBundle, AttestedCertificationInput,
    CanonicalResultEntry, CanonicalResultSet, CertificationInput, DerivedCertificationStatus,
    DerivedMetricDefinition, DuckDbBinaryObjectLocator, DuckDbExtensionBinaryLocator,
    DuckDbExtensionSpec, DuckDbQueryDefinition, DuckDbSessionSetting, EvaluationContext,
    EvaluationScope, Finding, FormulaAst, FormulaBundle, ResultColumn, TaggedScalarCell,
    derive_snapshot_restatement_history, evaluate_findings,
)
from smart_ads.application import (
    ConductorRunInput, conduct_offline_run, execute_analysis_replay_bundle, execute_certified_report,
    verify_consumer_deployment_readback, verify_stored_canonical_build_chain,
    verify_stored_decomposition_tip, verify_stored_legacy_merge_evidence, verify_tripartite_target,
)
import smart_ads.application.conductor as conductor_mod
from smart_ads.contracts import (
    ArtifactLocator, ClosedValidationError, DateRange, P1Integrity, TripartiteCanonicalSide,
    TripartiteConsumerSide, TripartiteLegacySide, TripartiteTarget, canonicalize_jcs,
    compute_consumer_contract_digest, p1_content_digest, sort_artifact_locators,
)
from smart_ads.contracts.numerics import PHASE1_BASE_METRICS, BaseMetricDefinition
from smart_ads.domain.catalog import DatasetCatalogCutReceipt
from smart_ads.domain.curation import CurationExecution
from smart_ads.domain.registry import ExpectedResourceInventory, ExpectedResourceKey
from smart_ads.ports import CellObjectStorePort
from smart_ads.ports.cell_runtime import ClockAttestation
from tests.contract.test_packaging_boundary import REPO_ROOT, scan_pure_layer_ast_violations
from tests.unit.test_conductor import (
    _CAMP_A, _CAMP_B, _KEY_ID as _COND_KEY_ID, ConductorTestWorld, CustomCallbackIntelligence,
    PolicyRuleOfflineIntelligence, ReadOnlyGuardStore, _put_signed_obj as _cond_put_obj,
    _scalar_row_count, _sign_dict as _cond_sign_dict,
)
from tests.unit.test_duckdb_replay_and_reporting import (
    DeterministicInMemoryDuckDbEngine, _METRIC_ORDER, _METRIC_UKEY,
)
from tests.unit.test_mcp_read_handler import McpHandlerWorld, _two_camp_window_rows
from tests.unit.test_pr5_review_regressions import _make_contract_for_ast
from tests.unit.test_seam_and_tripartite_verification import (
    _ADR_IDENTITY, _KEY_ID, FullDomainP1Verifier, _build_canonical_chain_in_store,
    _build_consumer_artifacts, _build_legacy_seam_artifacts, _build_real_decomposition_artifacts,
    _build_run_and_merge_artifacts, _put_signed_dict, _put_signed_model,
)
from tools.governance import artifacts as gov_artifacts, decomposition as gov_decomp


class _CountingStore(CellObjectStorePort):
    """Delegating store tracking `get_json_artifact` calls by object_ref."""

    def __init__(self, inner: CellObjectStorePort) -> None:
        self._inner = inner
        self.json_reads: dict[str, int] = {}

    def put_bytes(self, raw: bytes) -> str:
        return self._inner.put_bytes(raw)

    def get_bytes(self, object_ref: str, *, expected_size_bytes: int | None = None) -> bytes:
        return self._inner.get_bytes(object_ref, expected_size_bytes=expected_size_bytes)

    def has_object(self, object_ref: str) -> bool:
        return self._inner.has_object(object_ref)

    def put_json_artifact(self, schema_id: str, payload: Mapping[str, Any]) -> ArtifactLocator:
        return self._inner.put_json_artifact(schema_id, payload)

    def get_json_artifact(self, locator: ArtifactLocator) -> Any:
        self.json_reads[locator.object_ref] = self.json_reads.get(locator.object_ref, 0) + 1
        return self._inner.get_json_artifact(locator)


def _build_tripartite_world() -> dict[str, Any]:
    store, verifier = InMemoryCellObjectStore(), FullDomainP1Verifier()
    key_reg_loc = store.put_json_artifact(
        "smart_ads/key_authorization_registry/v1", {"$schema": "smart_ads/key_authorization_registry/v1", "keys": [_KEY_ID]}
    )
    head_loc, manifest_loc, _, _ = _build_real_decomposition_artifacts(store, key_reg_loc)
    run_loc, _, _ = _build_run_and_merge_artifacts(store, key_reg_loc, release_sha="e" * 40, reviewed_sha="d" * 40)
    _, con_loc, rel_s, rel_loc, seam_bytes = _build_legacy_seam_artifacts(store, key_reg_loc, run_loc, head_loc, manifest_loc)
    can = _build_canonical_chain_in_store(store, key_reg_loc, run_loc)
    cons = _build_consumer_artifacts(store, key_reg_loc, run_loc)
    cons_dig = compute_consumer_contract_digest(
        adapter_git_artifact=cons["ff_s"].adapter_git_artifact,
        feature_flag_git_artifact=cons["ff_s"].feature_flag_git_artifact,
        resolved_feature_flag_contract_envelope=store.get_json_artifact(cons["ff_loc"]),
        resolved_delegation_contract_envelope=store.get_json_artifact(cons["del_loc"]),
    )
    target = TripartiteTarget(
        TripartiteLegacySide(
            "mbras-tech/mbras-campaigns", rel_s.protected_release_identity.commit_sha,
            rel_loc, rel_s.seam_git_artifact, con_loc, con_loc.content_digest,
        ),
        TripartiteCanonicalSide("aiconnai/smart-ads", can["commit_sha"], can["whl_obj"], can["whl_obj"].wheel_digest, can["prov_loc"]),
        TripartiteConsumerSide(
            "limaronaldo/hermes-ronaldo", cons["c_sha"], cons["ff_s"].adapter_git_artifact,
            cons["ff_s"].feature_flag_git_artifact, cons["ff_loc"], cons["del_loc"], cons_dig,
        ),
    )
    return {
        "store": store, "verifier": verifier, "key_reg_loc": key_reg_loc, "head_loc": head_loc,
        "run_loc": run_loc, "seam_bytes": seam_bytes, "can": can, "cons": cons, "target": target,
    }


def test_fable_1_evaluation_clock_attestation_freshness_on_readback_and_tripartite() -> None:
    w = _build_tripartite_world()
    store, verifier, key_reg_loc, cons = w["store"], w["verifier"], w["key_reg_loc"], w["cons"]
    analyzer = Cpython312AstConsumerRoutingAnalyzer()
    rb_kw: dict[str, Any] = {
        "max_clock_uncertainty_ms": 500, "max_capture_age_seconds": 60,
        "conductor_raw_bytes": cons["cond_bytes"], "routing_analyzer": analyzer,
        "store": store, "signature_verifier": verifier,
    }
    assert verify_consumer_deployment_readback(cons["rb_loc"], **rb_kw) == cons["rb_s"]

    fresh_clk, fresh_clk_loc = _put_signed_model(
        store, ClockAttestation("clock:eval-ok", "2026-11-11T03:00:30.000000Z", 200, "2026-11-11T03:00:25Z", "2026-11-11T03:01:00Z", 60), key_reg_loc
    )
    assert verify_consumer_deployment_readback(cons["rb_loc"], **rb_kw, evaluation_clock_attestation=fresh_clk) == cons["rb_s"]
    assert verify_consumer_deployment_readback(cons["rb_loc"], **rb_kw, evaluation_clock_attestation=fresh_clk_loc) == cons["rb_s"]

    stale_clk, stale_clk_loc = _put_signed_model(
        store, ClockAttestation("clock:eval-stale", "2026-11-11T04:05:00.000000Z", 200, "2026-11-11T04:04:55Z", "2026-11-11T04:05:30Z", 60), key_reg_loc
    )
    future_rb_clk, _ = _put_signed_model(
        store, ClockAttestation("clock:eval-early", "2026-11-11T02:59:59.000000Z", 100, "2026-11-11T02:59:55Z", "2026-11-11T03:00:30Z", 60), key_reg_loc
    )
    unsigned_clk = ClockAttestation("clock:eval-unsigned", "2026-11-11T03:00:30.000000Z", 200, "2026-11-11T03:00:25Z", "2026-11-11T03:01:00Z", 60)
    for bad_eval in (stale_clk, stale_clk_loc, future_rb_clk, unsigned_clk, "bad-clock"):
        with pytest.raises(ClosedValidationError):
            verify_consumer_deployment_readback(cons["rb_loc"], **rb_kw, evaluation_clock_attestation=bad_eval)  # type: ignore[arg-type]

    tri_kw: dict[str, Any] = {
        "expected_run_locator": w["run_loc"], "expected_active_decomposition_head_locator": w["head_loc"],
        "wheel_boundary_report_locator": w["can"]["bound_loc"], "certification_7a_locator": w["can"]["cert7a_loc"],
        "gov1_convergence_locator": w["can"]["conv_loc"], "seam_raw_bytes": w["seam_bytes"],
        "conductor_raw_bytes": cons["cond_bytes"], "routing_analyzer": analyzer, "store": store,
        "deployment_readback_locator": cons["rb_loc"], "max_clock_uncertainty_ms": 500,
        "max_capture_age_seconds": 60, "signature_verifier": verifier,
    }
    assert verify_tripartite_target(w["target"], **tri_kw, evaluation_clock_attestation=fresh_clk_loc) == w["target"]
    with pytest.raises(ClosedValidationError):
        verify_tripartite_target(w["target"], **tri_kw, evaluation_clock_attestation=stale_clk_loc)


def test_fable_2_merge_evidence_enforces_closed_exact_ci_and_review_keys() -> None:
    store, verifier = InMemoryCellObjectStore(), FullDomainP1Verifier()
    key_reg_loc = store.put_json_artifact(
        "smart_ads/key_authorization_registry/v1", {"$schema": "smart_ads/key_authorization_registry/v1", "keys": [_KEY_ID]}
    )
    _, merge_loc, pol_dig = _build_run_and_merge_artifacts(store, key_reg_loc, release_sha="e" * 40, reviewed_sha="d" * 40)
    base = {k: v for k, v in store.get_json_artifact(merge_loc).items() if k != "integrity"}
    rev_ok = [{"reviewer": "principal:ronaldo", "reviewed_head_sha": "d" * 40, "state": "APPROVED"}]
    ci_ok = [{"check": "pytest", "status": "success"}]

    for bad_ci, bad_rev in (
        ([{"name": "pytest", "status": "success"}], rev_ok),
        ([{"check_name": "pytest", "conclusion": "success"}], rev_ok),
        ([{"check": "pytest", "status": "passed"}], rev_ok),
        ([{"check": "pytest", "status": "success", "extra": 1}], rev_ok),
        (ci_ok, [{"reviewer": "principal:ronaldo", "reviewed_head_sha": "d" * 40, "status": "APPROVED"}]),
        (ci_ok, [{"reviewer": "principal:ronaldo", "reviewed_head_sha": "d" * 40, "state": "approved"}]),
        (ci_ok, [{"reviewed_head_sha": "d" * 40, "state": "APPROVED"}]),
        (ci_ok, [{"reviewer": "principal:ronaldo", "reviewed_head_sha": "d" * 40, "state": "APPROVED", "extra": 1}]),
    ):
        _, bad_loc = _put_signed_dict(
            store, {**base, "required_ci_results": bad_ci, "exact_head_review_evidence": bad_rev}, key_reg_loc
        )
        with pytest.raises(ClosedValidationError):
            verify_stored_legacy_merge_evidence(
                store, bad_loc, expected_repository="mbras-tech/mbras-campaigns",
                expected_protected_ref="refs/heads/main", expected_pr_number=77,
                expected_reviewed_head_sha="d" * 40, expected_protected_merge_sha="e" * 40,
                expected_adr_git_identity=_ADR_IDENTITY, expected_branch_policy_digest=pol_dig,
                signature_verifier=verifier,
            )


def test_fable_3_conductor_enforces_signed_findings_and_certification_in_signed_mode() -> None:
    cond_w = ConductorTestWorld()
    intel = PolicyRuleOfflineIntelligence(cond_w.intel_alg_1)
    with pytest.raises(ClosedValidationError, match="certification_signer"):
        cond_w.make_run_input(certification_signer="not-callable")  # type: ignore[arg-type]

    unsigned_f_intel = CustomCallbackIntelligence(cond_w.intel_alg_1, lambda ctx, ev: evaluate_findings(ctx, ev[0]))
    two_key_f_intel = CustomCallbackIntelligence(
        cond_w.intel_alg_1,
        lambda ctx, ev: tuple(
            Finding.from_dict({**f.to_dict(), "integrity": P1Integrity(_COND_KEY_ID, cond_w.key_reg_loc).to_dict()})
            for f in evaluate_findings(ctx, ev[0])
        ),
    )
    for bad_intel in (unsigned_f_intel, two_key_f_intel):
        with pytest.raises(ClosedValidationError):
            conduct_offline_run(run_input=cond_w.make_run_input(), intelligence=bad_intel)

    for bad_kw in (
        {"certification_integrity": None},
        {"certification_integrity": P1Integrity(_COND_KEY_ID, cond_w.key_reg_loc), "certification_signer": None},
        {"certification_signer": lambda _d, _p: (_ for _ in ()).throw(RuntimeError("hsm down"))},
        {"certification_signer": lambda d, _p: _cond_sign_dict({**d, "mutation_recommendations_blocked": False}, cond_w.key_reg_loc)},
    ):
        with pytest.raises(ClosedValidationError):
            conduct_offline_run(run_input=cond_w.make_run_input(**bad_kw), intelligence=intel)

    out_ok = conduct_offline_run(run_input=cond_w.make_run_input(), intelligence=intel)
    assert out_ok.certification_record.integrity is not None and out_ok.certification_record.integrity.is_signed
    assert all(f.integrity is not None and f.integrity.is_signed for f in out_ok.findings)


def test_fable_4_conductor_snapshot_curation_resolution_and_anchor_coverage() -> None:
    cond_w = ConductorTestWorld()
    intel = PolicyRuleOfflineIntelligence(cond_w.intel_alg_1)
    proxy = conductor_mod._SignatureVerifyingStoreProxy(
        cond_w.store, signature_verifier=cond_w.verifier, require_signed=True
    )
    cut_rec = conductor_mod._load_p1(
        proxy, cond_w.snap3.catalog_cut_receipt_locator, DatasetCatalogCutReceipt,
        field_name="cut", require_signed=True,
    )
    with pytest.raises(ClosedValidationError, match="generation_manifest missing"):
        conductor_mod._resolve_snapshot_curation_execution(
            cond_w.make_run_input(), cond_w.snap3, cut_rec, {}, proxy_store=proxy, require_signed=True
        )

    inv_keys = tuple(
        ExpectedResourceKey("binding:meta-primary", "account:ibvi-01", c, "campaign", d)
        for d in ("2026-10-31", "2026-11-15") for c in (_CAMP_A, _CAMP_B)
    )
    _, inv_nov15_loc = _cond_put_obj(
        cond_w.store,
        ExpectedResourceInventory(
            "inventory:nov15", cond_w.reg_loc, cond_w.reg_loc.content_digest, "tenant:ibvi",
            "binding:meta-primary", "account:ibvi-01", "scope:campaigns-active",
            DateRange("2026-10-31", "2026-11-15", True), inv_keys,
        ),
        cond_w.key_reg_loc,
    )
    with pytest.raises(ClosedValidationError, match="curation_anchor_date|window"):
        conduct_offline_run(
            run_input=cond_w.make_run_input(
                expected_resource_inventory_locator=inv_nov15_loc,
                evaluation_instant_utc="2026-11-16T00:00:00.000000Z",
                window_end_date="2026-11-15",
            ),
            intelligence=intel,
        )

    gen_by_key, _, _ = conductor_mod._load_snapshot_lineage_generations(
        cond_w.snap3, proxy_store=proxy, parquet_codec=cond_w.codec, require_signed=True
    )
    with pytest.raises(ClosedValidationError, match="not covered"):
        conductor_mod._resolve_snapshot_curation_execution(
            cond_w.make_run_input(window_end_date="2026-09-15"),
            cond_w.snap3, cut_rec, gen_by_key, proxy_store=proxy, require_signed=True,
        )


def test_fable_5_and_6_routing_analyzer_requires_is_true_and_catches_memory_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    analyzer = Cpython312AstConsumerRoutingAnalyzer()
    flg = canonicalize_jcs({
        "flag_key": "ibvi_ads.smart_ads_read_v1", "default_enabled": False,
        "disabled_legacy_route": "legacy:mbras_direct", "enabled_smart_ads_route": "/ibvi-ads",
    })
    m = "smart_ads.queries.get_campaign_performance_v1"
    for ok_cond in (
        "    if f.is_enabled(FLAG_KEY) is True:\n",
        "    enabled = f.is_enabled(FLAG_KEY)\n    if enabled is True:\n",
    ):
        src = f"FLAG_KEY = 'ibvi_ads.smart_ads_read_v1'\ndef fetch(f, s, l, p):\n{ok_cond}        return s.call('/ibvi-ads', '{m}', p)\n    else:\n        return l.call('legacy:mbras_direct', p)\n".encode()
        res = analyzer.analyze_consumer_routing(
            adapter_bytes=src, feature_flag_bytes=flg,
            contract=_make_contract_for_ast("ibvi_ads/a.py", src, "ibvi_ads/flags.json", flg, (("fetch", m),)),
        )
        assert res.verified_entrypoints[0].symbol_name == "fetch"

    for bad_cond in (
        "    if f.is_enabled(FLAG_KEY):\n",
        "    enabled = f.is_enabled(FLAG_KEY)\n    if enabled:\n",
        "    if f.is_enabled(FLAG_KEY) == True:\n",
        "    if f.is_enabled(FLAG_KEY) is False:\n",
    ):
        bad_src = f"FLAG_KEY = 'ibvi_ads.smart_ads_read_v1'\ndef fetch(f, s, l, p):\n{bad_cond}        return s.call('/ibvi-ads', '{m}', p)\n    else:\n        return l.call('legacy:mbras_direct', p)\n".encode()
        with pytest.raises(ClosedValidationError):
            analyzer.analyze_consumer_routing(
                adapter_bytes=bad_src, feature_flag_bytes=flg,
                contract=_make_contract_for_ast("ibvi_ads/a.py", bad_src, "ibvi_ads/flags.json", flg, (("fetch", m),)),
            )

    real_parse = ast.parse
    with monkeypatch.context() as mp:
        mp.setattr(ast, "parse", lambda src, *a, **k: (_ for _ in ()).throw(MemoryError("oom")) if type(src) is bytes else real_parse(src, *a, **k))
        ok_src = f"FLAG_KEY = 'ibvi_ads.smart_ads_read_v1'\ndef fetch(f, s, l, p):\n    if f.is_enabled(FLAG_KEY) is True:\n        return s.call('/ibvi-ads', '{m}', p)\n    else:\n        return l.call('legacy:mbras_direct', p)\n".encode()
        with pytest.raises(ClosedValidationError, match="failed to parse Python AST"):
            analyzer.analyze_consumer_routing(
                adapter_bytes=ok_src, feature_flag_bytes=flg,
                contract=_make_contract_for_ast("ibvi_ads/a.py", ok_src, "ibvi_ads/flags.json", flg, (("fetch", m),)),
            )


def test_fable_7_conductor_readability_and_pure_ast_invariants() -> None:
    cond_path: Path = REPO_ROOT / "src" / "smart_ads" / "application" / "conductor.py"
    source = cond_path.read_text(encoding="utf-8")
    lines = source.splitlines()
    assert len(lines) <= 800
    assert max(len(line) for line in lines) <= 125
    assert scan_pure_layer_ast_violations(source, filename=str(cond_path)) == []


def test_opus_1_canonical_build_chain_enforces_complete_constituent_chronology() -> None:
    store, verifier = InMemoryCellObjectStore(), FullDomainP1Verifier()
    key_reg_loc = store.put_json_artifact(
        "smart_ads/key_authorization_registry/v1", {"$schema": "smart_ads/key_authorization_registry/v1", "keys": [_KEY_ID]}
    )
    run_loc, _, _ = _build_run_and_merge_artifacts(store, key_reg_loc, release_sha="e" * 40, reviewed_sha="d" * 40)
    can = _build_canonical_chain_in_store(store, key_reg_loc, run_loc)

    _, prov_20_loc = _put_signed_dict(store, {**can["prov_u"], "built_at_utc": "2026-09-07T10:00:20Z"}, key_reg_loc)
    _, bound_22_loc = _put_signed_dict(
        store, {**can["bound_u"], "verified_at_utc": "2026-09-07T10:00:22Z", "wheel_build_provenance_locator": prov_20_loc.to_dict()}, key_reg_loc
    )
    neg_15 = {
        **{k: v for k, v in store.get_json_artifact(can["neg_loc"]).items() if k != "integrity"},
        "executed_at_utc": "2026-09-07T10:00:15Z", "wheel_build_provenance_locator": prov_20_loc.to_dict(),
    }
    _, neg_15_loc = _put_signed_dict(store, neg_15, key_reg_loc)
    _, c7a_neg_early = _put_signed_model(
        store, replace(can["rec7a_s"], wheel_build_provenance_locator=prov_20_loc, wheel_boundary_report_locator=bound_22_loc, negative_security_test_report_locator=neg_15_loc, integrity=None), key_reg_loc
    )
    _, conv_neg_early = _put_signed_dict(
        store, {**can["conv_u"], "wheel_boundary_report_locator": bound_22_loc.to_dict(), "negative_security_test_report_locator": neg_15_loc.to_dict(), "certification_7a_record_locator": c7a_neg_early.to_dict()}, key_reg_loc
    )
    _, mcp_early_loc = _put_signed_dict(store, {**can["mcp_u"], "executed_at_utc": "2026-09-07T10:00:01Z"}, key_reg_loc)
    _, conv_mcp_early = _put_signed_dict(store, {**can["conv_u"], "mcp_rejection_matrix_report_locator": mcp_early_loc.to_dict()}, key_reg_loc)
    _, bound_late_loc = _put_signed_dict(store, {**can["bound_u"], "verified_at_utc": "2026-09-07T10:00:30Z"}, key_reg_loc)
    _, c7a_bound_late = _put_signed_model(store, replace(can["rec7a_s"], wheel_boundary_report_locator=bound_late_loc, integrity=None), key_reg_loc)
    _, conv_bound_late = _put_signed_dict(
        store, {**can["conv_u"], "wheel_boundary_report_locator": bound_late_loc.to_dict(), "certification_7a_record_locator": c7a_bound_late.to_dict()}, key_reg_loc
    )

    for p_loc, b_loc, c7a_loc, conv_loc in (
        (prov_20_loc, bound_22_loc, c7a_neg_early, conv_neg_early),
        (can["prov_loc"], can["bound_loc"], can["cert7a_loc"], conv_mcp_early),
        (can["prov_loc"], bound_late_loc, c7a_bound_late, conv_bound_late),
    ):
        with pytest.raises(ClosedValidationError, match="chronology"):
            verify_stored_canonical_build_chain(
                store, wheel_locator=can["whl_obj"], wheel_digest=can["whl_obj"].wheel_digest,
                build_provenance_locator=p_loc, wheel_boundary_report_locator=b_loc,
                certification_7a_locator=c7a_loc, gov1_convergence_locator=conv_loc,
                expected_run_locator=run_loc, expected_commit_sha=can["commit_sha"], signature_verifier=verifier,
            )


def test_opus_2_decomposition_tip_guards_unhashable_decision_status() -> None:
    store, verifier = InMemoryCellObjectStore(), FullDomainP1Verifier()
    key_reg_loc = store.put_json_artifact(
        "smart_ads/key_authorization_registry/v1", {"$schema": "smart_ads/key_authorization_registry/v1", "keys": [_KEY_ID]}
    )
    _, _, head_s, manifest_s = _build_real_decomposition_artifacts(store, key_reg_loc)
    base_u = {k: v for k, v in manifest_s.items() if k not in {"manifest_digest", "integrity"}}
    for unhashable_status in ([], {"status": "approved"}):
        bad_m = {**base_u, "entries": [{**base_u["entries"][0], "decision_status": unhashable_status}, *base_u["entries"][1:]]}
        bad_m["manifest_digest"] = gov_decomp.manifest_digest(bad_m)
        _, bm_loc = _put_signed_dict(store, bad_m, key_reg_loc)
        _, bh_loc = _put_signed_dict(
            store, {**head_s, "active_manifest_locator": bm_loc.to_dict(), "active_manifest_digest": bm_loc.content_digest}, key_reg_loc
        )
        with pytest.raises(ClosedValidationError):
            verify_stored_decomposition_tip(
                store, head_locator=bh_loc, expected_active_head_locator=bh_loc,
                manifest_locator=bm_loc, expected_manifest_digest=bm_loc.content_digest, signature_verifier=verifier,
            )


def test_opus_3_duckdb_execution_dedups_build_inputs_and_verifies_integrity_and_signatures() -> None:
    cond_w = ConductorTestWorld()
    ctr_def = DerivedMetricDefinition(
        "metric:ctr_v1", FormulaAst("DIVIDE_COUNT_BY_COUNT", "metric:clicks_v1", "metric:impressions_v1", "decimal_ratio", "ROUND_HALF_UP")
    )
    fb_s, fb_loc = _cond_put_obj(cond_w.store, FormulaBundle(tuple(PHASE1_BASE_METRICS.values()), (ctr_def,)), cond_w.key_reg_loc)
    bm_s, bm_loc = _cond_put_obj(cond_w.store, PHASE1_BASE_METRICS["metric:clicks_v1"], cond_w.key_reg_loc)
    m_cols = tuple(ResultColumn(n, t, nl) for n, t, nl in METRIC_WINDOW_COLUMNS)
    s_cols = (ResultColumn("row_count", "int64", False),)
    q_m = DuckDbQueryDefinition("result:metrics", "query:metrics", "SELECT 1", cond_w.metrics_schema_loc, "relation", m_cols, _METRIC_UKEY, _METRIC_ORDER)
    q_s = DuckDbQueryDefinition("result:row_count", "query:row_count", "SELECT 1", cond_w.scalar_schema_loc, "scalar", s_cols, None, ())
    exts = (DuckDbExtensionSpec("parquet", "1.5.5", "explicit_local_binary", DuckDbExtensionBinaryLocator.for_binary_bytes(cond_w.ext_bytes)),)
    raw_b = AnalysisReplayInputBundle(
        "bundle:opus3", cond_w.run_loc, cond_w.snap3_loc, "1.5.5",
        DuckDbBinaryObjectLocator.for_binary_bytes(cond_w.duck_bytes), exts,
        (DuckDbSessionSetting("threads", TaggedScalarCell("int64", "1")),), (), (q_m, q_s),
        cond_w.policy_loc, sort_artifact_locators((cond_w.tmpl_loc, fb_loc, bm_loc)),
    )
    _, b_loc = _cond_put_obj(cond_w.store, raw_b, cond_w.key_reg_loc)
    eng = DeterministicInMemoryDuckDbEngine({"result:metrics": _two_camp_window_rows, "result:row_count": _scalar_row_count})

    counting = _CountingStore(cond_w.store)
    _, ex_loc, _ = execute_analysis_replay_bundle(
        bundle_locator=b_loc, store=counting, parquet_codec=cond_w.codec,
        duckdb_engine=eng, signature_verifier=cond_w.verifier, require_signed_inputs=True,
    )
    assert counting.json_reads[fb_loc.object_ref] == 1
    assert counting.json_reads[bm_loc.object_ref] == 1
    assert counting.json_reads[cond_w.tmpl_loc.object_ref] == 1

    with pytest.raises(ClosedValidationError, match="signature_verifier"):
        execute_analysis_replay_bundle(
            bundle_locator=b_loc, store=cond_w.store, parquet_codec=cond_w.codec,
            duckdb_engine=eng, signature_verifier=object(), require_signed_inputs=True,  # type: ignore[arg-type]
        )

    tampered_fb = {**fb_s.to_dict(), "integrity": {**fb_s.integrity.to_dict(), "content_digest": "sha256:" + ("0" * 64)}}  # type: ignore[union-attr]
    tampered_fb_loc = cond_w.store.put_json_artifact(FormulaBundle.SCHEMA, tampered_fb)
    bad_sig_bm = {**bm_s.to_dict(), "integrity": {**bm_s.integrity.to_dict(), "signature_base64": base64.b64encode(b"\x02" * 64).decode("ascii")}}  # type: ignore[union-attr]
    bad_sig_bm_loc = cond_w.store.put_json_artifact(BaseMetricDefinition.SCHEMA, bad_sig_bm)
    for bad_bi in (tampered_fb_loc, bad_sig_bm_loc):
        _, bad_b_loc = _cond_put_obj(
            cond_w.store, replace(raw_b, build_input_locators=sort_artifact_locators((cond_w.tmpl_loc, bad_bi)), integrity=None), cond_w.key_reg_loc
        )
        with pytest.raises(ClosedValidationError):
            execute_analysis_replay_bundle(
                bundle_locator=bad_b_loc, store=cond_w.store, parquet_codec=cond_w.codec,
                duckdb_engine=eng, signature_verifier=cond_w.verifier, require_signed_inputs=True,
            )


def test_opus_3_execute_certified_report_accepts_and_enforces_signature_verifier() -> None:
    mcp_w = McpHandlerWorld()
    l_rows = tuple(
        r for gm in (mcp_w.gm_oct, mcp_w.gm_nov1, mcp_w.gm_nov2)
        for pq in gm.parquet_object_locators
        for r in mcp_w.codec.decode_and_verify_landing_rows(mcp_w.store.get_bytes(pq.object_ref, expected_size_bytes=pq.size_bytes), expected_partition_key=pq.partition_key)
    )
    eval_ctx = EvaluationContext(
        mcp_w.policy, EvaluationScope("tenant:ibvi", "scope:campaigns-active", "campaign", "meta", "BRL"),
        "2026-11-11T03:15:00.000000Z", "2026-11-10", 1, "2026-11-10", mcp_w.eval_inv,
        "result:metrics", derive_snapshot_restatement_history(mcp_w.eval_inv, l_rows),
    )
    att = (AttestedCertificationInput(CertificationInput(DerivedCertificationStatus.VERIFIED, "phase1_7b_base"), True),)
    rep_kw: dict[str, Any] = {
        "report_id": "rep:opus3-sig", "executed_at_utc": "2026-11-11T03:20:00Z",
        "bundle_locator": mcp_w.rep2.analysis_replay_input_bundle_locator, "execution_locator": mcp_w.exec2_loc,
        "evaluation_context": eval_ctx, "expected_resource_inventory_locator": mcp_w.eval_inv_loc,
        "curation_execution_locator": mcp_w.cur_nov2_loc,
        "restatement_history_generation_locators": (mcp_w.gm_nov1_loc,),
        "attested_certification_inputs": att, "report_template_provenance_locator": mcp_w.tmpl_loc,
        "render_algorithm_identity": mcp_w.render_alg, "store": mcp_w.store, "parquet_codec": mcp_w.codec,
        "require_signed_inputs": True,
    }
    mcp_w.verifier.verified_schemas.clear()
    rep, _, _, _, _ = execute_certified_report(**rep_kw, signature_verifier=mcp_w.verifier)
    assert rep.report_id == "rep:opus3-sig" and mcp_w.verifier.verified_schemas
    with pytest.raises(ClosedValidationError, match="signature_verifier"):
        execute_certified_report(**rep_kw, signature_verifier=object())  # type: ignore[arg-type]
