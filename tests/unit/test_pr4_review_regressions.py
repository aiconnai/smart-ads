"""Targeted PR 4 final-review fix-wave regressions covering all 12 validated findings."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
import os
from pathlib import Path
from typing import Any

import pytest

from smart_ads.adapters.storage import (
    FilesystemCellObjectStore,
    InMemoryCellObjectStore,
    StdlibParquetLandingCodec,
)
from smart_ads.analytics import (
    METRIC_WINDOW_COLUMNS,
    REPORT_EXECUTION_SCHEMA,
    AnalysisExecution,
    AnalysisPolicy,
    AnalysisReplayInputBundle,
    AnalysisResultSchema,
    AttestedCertificationInput,
    CanonicalResultEntry,
    CanonicalResultSet,
    CertificationInput,
    DerivedCertificationStatus,
    DuckDbBinaryObjectLocator,
    DuckDbExtensionBinaryLocator,
    DuckDbExtensionSpec,
    DuckDbQueryDefinition,
    DuckDbSessionSetting,
    EvaluationContext,
    EvaluationScope,
    ReportExecution,
    ResultColumn,
    TaggedScalarCell,
    derive_snapshot_restatement_history,
    verify_report_execution,
)
from smart_ads.application import (
    GlobalDatasetCatalogService,
    RetentionRootSetService,
    WheelObjectLocator,
    build_retention_root,
    build_sanitized_candidate_fact_set,
    compute_retention_reachability_graph,
    execute_analysis_replay_bundle,
    execute_certified_report,
    materialize_parquet_generation,
    publish_dataset_snapshot,
    verify_curation_execution,
    verify_dataset_catalog_cut_receipt,
    verify_dataset_snapshot,
    verify_operational_read_evidence,
    verify_retention_release_proof,
    verify_retention_root_admission_proof,
)
from smart_ads.contracts import (
    ArtifactLocator,
    ClosedValidationError,
    DateRange,
    GitArtifactProvenance,
    P1Integrity,
    canonicalize_jcs,
)
from smart_ads.contracts.effects import (
    AuthorizationConsumptionRecord,
    AuthorizationReceipt,
    AuthorizationReservationRecord,
    EffectProof,
    ExecutionReceipt,
    ProviderCallTarget,
    sort_artifact_locators,
    verify_four_record_effect_proof,
)
from smart_ads.contracts.operational_evidence import (
    OperationalReadEvidence,
    SanitizedCandidateFactSet,
)
from smart_ads.contracts.retention import RetentionRootSetHead
from smart_ads.domain import (
    ActivePartitionHead,
    CatalogCasRequestProjection,
    CurationExecution,
    DatasetCatalog,
    DatasetCatalogCutReceipt,
    DatasetCatalogGenesisRecord,
    DatasetSnapshot,
    ExpectedResourceInventory,
    ExpectedResourceKey,
    GenerationManifest,
    ParquetObjectLocator,
    compute_curation_window,
)
from smart_ads.ports.storage import CellObjectStorePort
from tests.unit.test_curation_and_catalog import CurationWorld, _CAMP_A, _loc
from tests.unit.test_duckdb_replay_and_reporting import (
    DeterministicInMemoryDuckDbEngine,
    SignedPipelineWorld,
    _LIVE_METRICS_WINDOW_SQL,
    _METRIC_ORDER,
    _METRIC_UKEY,
    _store_signed,
)
from tests.unit.test_curation_and_catalog import _unsigned_p1
from tests.unit.test_replay_bundle_and_reporting_schemas import UNSIGNED, _build_report_world, _resign, _sign
from tests.unit.test_retention_graph_and_cas import (
    RetentionWorld,
    _KEY_ID,
    _OverlayStore,
    _compute_signed_admission_integrities,
    _put_prereq_effect_chain,
    _put_signed_envelope,
    _put_signed_model,
    _sign_payload,
)


def _build_effect_chain(
    *,
    issued: str = "2026-11-11T03:00:00Z",
    valid_until: str = "2026-11-11T04:00:00Z",
    reserved: str = "2026-11-11T03:01:00Z",
    executed: str = "2026-11-11T03:02:00Z",
    consumed: str = "2026-11-11T03:03:00Z",
    verified: str = "2026-11-11T03:04:00Z",
) -> tuple[AuthorizationReceipt, AuthorizationReservationRecord, ExecutionReceipt, AuthorizationConsumptionRecord, EffectProof]:
    run_loc, adm_loc = _loc("smart_ads/migration_run_context/v1", "1"), _loc("smart_ads/admitted_collection/v1", "2")
    reg_loc, res_loc = _loc("smart_ads/private_registry_snapshot/v1", "3"), _loc("smart_ads/collection_result/v1", "5")
    subj = ProviderCallTarget(run_loc, adm_loc, "operational", "provider-target:pipeboard", "sha256:" + ("7" * 64), reg_loc, "tenant:ibvi", "binding:meta-primary", "account:ibvi-01", "scope:campaigns-active", _loc("smart_ads/ibvi_ads_delegation_context/v1", "8"))
    auth = AuthorizationReceipt("auth:c001", run_loc, "provider_operational_read", "operational_provider_read_effect_proof", subj, "sha256:" + ("a" * 64), (adm_loc,), "principal:op-01", issued, valid_until, "nonce-c001")
    a_loc = auth.locator()
    resv = AuthorizationReservationRecord("resv:c001", run_loc, a_loc, a_loc.content_digest, "nonce-c001", "provider_operational_read", "operational_provider_read_effect_proof", subj, "consumed", None, reserved)
    ex = ExecutionReceipt("exec:c001", run_loc, a_loc, resv.locator(), "nonce-c001", "provider_operational_read", "operational_provider_read_effect_proof", subj, "succeeded", res_loc, executed)
    cn = AuthorizationConsumptionRecord("cons:c001", run_loc, a_loc, a_loc.content_digest, resv.locator(), ex.locator(), "nonce-c001", "provider_operational_read", "operational_provider_read_effect_proof", "consumed", consumed)
    pf = EffectProof("pf:c001", run_loc, "provider_operational_read", "operational_provider_read_effect_proof", a_loc, resv.locator(), ex.locator(), cn.locator(), res_loc, verified)
    return auth, resv, ex, cn, pf


def test_contracts_001_effect_proof_chronology_and_expiry() -> None:
    auth, resv, ex, cn, pf = _build_effect_chain()
    assert verify_four_record_effect_proof(
        effect_proof=pf, authorization=auth, reservation=resv, execution=ex, consumption=cn,
        expected_action="provider_operational_read", expected_dag_slot="operational_provider_read_effect_proof",
        expected_result_type="smart_ads/collection_result/v1",
    ) == pf
    for bad_kw in (
        {"reserved": "2026-11-11T02:59:59Z"},
        {"executed": "2026-11-11T03:00:30Z"},
        {"consumed": "2026-11-11T03:01:30Z"},
        {"verified": "2026-11-11T03:02:30Z"},
        {"executed": "2026-11-11T04:00:00Z", "consumed": "2026-11-11T04:01:00Z", "verified": "2026-11-11T04:02:00Z"},
        {"executed": "2026-11-11T04:05:00Z", "consumed": "2026-11-11T04:06:00Z", "verified": "2026-11-11T04:07:00Z"},
    ):
        b_a, b_r, b_e, b_c, b_p = _build_effect_chain(**bad_kw)
        with pytest.raises(ClosedValidationError, match="chronology|expiry"):
            verify_four_record_effect_proof(
                effect_proof=b_p, authorization=b_a, reservation=b_r, execution=b_e, consumption=b_c,
                expected_action="provider_operational_read", expected_dag_slot="operational_provider_read_effect_proof",
                expected_result_type="smart_ads/collection_result/v1",
            )


def test_contracts_001_operational_read_evidence_rejects_expired_execution() -> None:
    cw = CurationWorld()
    ev, _, _, _ = cw.store_operational_read("2026-11-10", tag="exp", obs_ref="observation:exp")
    ex = ExecutionReceipt.from_dict(cw.store.get_json_artifact(ev.execution_locator))
    cn = AuthorizationConsumptionRecord.from_dict(cw.store.get_json_artifact(ev.consumption_locator))
    pf = EffectProof.from_dict(cw.store.get_json_artifact(ev.effect_proof_locator))
    late_ex = replace(ex, executed_at_utc="2026-11-11T04:00:00Z", integrity=None)
    late_ex_loc = cw.store.put_json_artifact(ExecutionReceipt.SCHEMA, late_ex.to_dict())
    late_cn = replace(cn, execution_locator=late_ex_loc, consumed_at_utc="2026-11-11T04:01:00Z", integrity=None)
    late_cn_loc = cw.store.put_json_artifact(AuthorizationConsumptionRecord.SCHEMA, late_cn.to_dict())
    late_pf = replace(pf, execution_locator=late_ex_loc, consumption_locator=late_cn_loc, verified_at_utc="2026-11-11T04:02:00Z", integrity=None)
    late_pf_loc = cw.store.put_json_artifact(EffectProof.SCHEMA, late_pf.to_dict())
    bad_ev = replace(ev, execution_locator=late_ex_loc, consumption_locator=late_cn_loc, effect_proof_locator=late_pf_loc, integrity=None)
    with pytest.raises(ClosedValidationError, match="chronology|expiry"):
        verify_operational_read_evidence(bad_ev, store=cw.store)


def test_contracts_003_stage_specific_algorithm_schema_id_binding() -> None:
    cw = CurationWorld()
    ev, ev_loc, _, _ = cw.store_operational_read("2026-11-10", tag="alg", obs_ref="observation:alg")
    cs = build_sanitized_candidate_fact_set(
        migration_run_context_locator=cw.run_loc, sanitization_algorithm_identity=cw.san_alg,
        store=cw.store, evidence_locators=(ev_loc,),
    )
    cs_loc = cw.store.put_json_artifact(SanitizedCandidateFactSet.SCHEMA, cs.to_dict())
    with pytest.raises(ClosedValidationError, match="schema_id"):
        replace(cs, sanitization_algorithm_identity=replace(cw.san_alg, schema_id=CurationExecution.SCHEMA))
    with pytest.raises(ClosedValidationError, match="schema_id"):
        build_sanitized_candidate_fact_set(
            migration_run_context_locator=cw.run_loc,
            sanitization_algorithm_identity=replace(cw.san_alg, schema_id=CurationExecution.SCHEMA),
            store=cw.store, evidence_locators=(ev_loc,),
        )
    win = compute_curation_window("2026-11-10", "America/Sao_Paulo", "2026a", 1)
    with pytest.raises(ClosedValidationError, match="schema_id"):
        CurationExecution(
            cw.run_loc, "cur:bad-alg", "genesis", "2026-11-10", "America/Sao_Paulo", "2026a", 1, win,
            cs_loc, replace(cw.cur_alg, schema_id=SanitizedCandidateFactSet.SCHEMA), cw.genesis_loc,
            cw.epoch0_loc, None, None, (), "2026-11-11T03:05:00Z",
        )
    rw = _build_report_world()
    with pytest.raises(ClosedValidationError, match="schema_id"):
        replace(rw.report, render_algorithm_identity=replace(rw.report.render_algorithm_identity, schema_id=CurationExecution.SCHEMA))


def test_deep_1_002_transitive_generation_lineage_and_operational_evidence_union() -> None:
    from smart_ads.analytics import AnalysisEvidence, build_certification_record, evaluate_findings, render_canonical_report_result

    hist_world = _build_report_world(with_replaced_nov_history=True)
    gm1, hist_gm, gm2 = hist_world.generation_manifests
    hist_ev_loc = hist_gm.operational_read_evidence_locators[0]
    ev2 = next(e for e in hist_world.operational_evidences if e.locator() != hist_ev_loc)
    gm1_ev2 = _resign(gm1, operational_read_evidence_locators=(ev2.locator(),))
    gm2_ev2 = _resign(gm2, operational_read_evidence_locators=(ev2.locator(),))
    heads = (ActivePartitionHead("year=2026/month=10", 1, gm1_ev2.locator()), ActivePartitionHead("year=2026/month=11", 2, gm2_ev2.locator()))
    snap = _resign(hist_world.snapshot, partition_heads=heads, snapshot_digest="")
    bundle = _resign(hist_world.replay_bundle, dataset_snapshot_locator=snap.locator())
    a_res = _resign(hist_world.results[0], dataset_snapshot_locator=snap.locator(), replay_input_bundle_locator=bundle.locator())
    c_set = CanonicalResultSet.build(bundle.locator(), (CanonicalResultEntry.from_result(a_res),))
    a_exec = _resign(hist_world.execution, analysis_replay_input_bundle_locator=bundle.locator(), canonical_result_set=c_set)
    ev_b = AnalysisEvidence(a_exec, (a_res,), hist_world.result_schemas, snap.locator(), hist_world.policy_obj.locator(), True, hist_world.report.migration_run_context_locator)
    findings = tuple(_sign(f) for f in evaluate_findings(hist_world.evaluation_context, ev_b))
    cert = _sign(build_certification_record(hist_world.evaluation_context, ev_b, findings, hist_world.attested_inputs, integrity=UNSIGNED))
    f_locs = sort_artifact_locators([f.locator() for f in findings], expected_type="smart_ads/finding/v1", allow_empty=True)
    rep_in = replace(hist_world.report.canonical_report_input, dataset_snapshot_digest=snap.snapshot_digest, canonical_result_digest=c_set.canonical_result_digest, finding_digests=tuple(sorted((f.finding_digest for f in findings), key=lambda s: s.encode("utf-8"))))
    rep_res = render_canonical_report_result(rep_in, findings)
    dec = {gm1_ev2.locator().object_ref: hist_world.decoded_generation_rows[gm1.locator().object_ref], hist_gm.locator().object_ref: hist_world.decoded_generation_rows[hist_gm.locator().object_ref], gm2_ev2.locator().object_ref: hist_world.decoded_generation_rows[gm2.locator().object_ref]}
    only_ev2_rep = _resign(hist_world.report, dataset_snapshot_locator=snap.locator(), analysis_replay_input_bundle_locator=bundle.locator(), analysis_execution_locator=a_exec.locator(), finding_locators=f_locs, certification_record_locators=(cert.locator(),), operational_read_evidence_locators=(ev2.locator(),), operational_read_effect_proof_locators=(ev2.effect_proof_locator,), operational_read_effect_proof_set_digest="", canonical_report_input=rep_in, canonical_report_input_digest="", canonical_report_result=rep_res, canonical_report_result_digest="")
    kw = hist_world.verify_kwargs(snapshot=snap, generation_manifests=(gm1_ev2, hist_gm, gm2_ev2), replay_bundle=bundle, execution=a_exec, results=(a_res,), findings=findings, certifications=(cert,), decoded_generation_rows=dec)
    with pytest.raises(ClosedValidationError, match="operational_read_evidence_locators|transitive union"):
        verify_report_execution(only_ev2_rep, **{**kw, "operational_evidences": (ev2,)}, require_signed=True)
    full_rep = _resign(only_ev2_rep, operational_read_evidence_locators=hist_world.report.operational_read_evidence_locators, operational_read_effect_proof_locators=hist_world.report.operational_read_effect_proof_locators, operational_read_effect_proof_set_digest="")
    assert verify_report_execution(full_rep, **kw, require_signed=True) == full_rep
    with pytest.raises(ClosedValidationError):
        verify_report_execution(full_rep, **{**kw, "generation_manifests": (gm1_ev2, gm2_ev2), "decoded_generation_rows": {k: v for k, v in dec.items() if k != hist_gm.locator().object_ref}}, require_signed=True)


def _build_restatement_pipeline(base_rw: RetentionWorld) -> tuple[RetentionWorld, ArtifactLocator, ArtifactLocator, EvaluationContext, tuple[AttestedCertificationInput, ...]]:
    rw = base_rw.clone()
    _, rw.epoch0_loc = _put_signed_model(rw.store, DatasetCatalog("catalog:r0", rw.cell_ref, 0, "2026-11-10T00:00:00Z", ()), rw.key_reg_loc)
    _, rw.genesis_loc = _put_signed_model(rw.store, DatasetCatalogGenesisRecord("genesis:r001", rw.cell_ref, rw.run_loc, rw.epoch0_loc, rw.epoch0_loc.content_digest, "authority:root", "2026-11-10T00:01:00Z"), rw.key_reg_loc)
    cat_svc = GlobalDatasetCatalogService(rw.store, rw.epoch0_loc, parquet_codec=rw.codec, require_signed=True)
    _, ev_oct_r, _ = rw._store_op_read("2026-10-31", "octr", clicks_val="10", collected_at="2026-11-01T03:02:00.000000Z")
    gm_oct_r, gm_oct_r_loc = rw._materialize_signed_gen("octr", "genesis", "2026-10-31", ev_oct_r, rw.epoch0_loc, None, None, (), None)
    _, snap_oct_loc, cut1_loc = rw._commit_signed_cut(cat_svc, idx=1, op="add_partition", seq=1, gm=gm_oct_r, gm_loc=gm_oct_r_loc, genesis_loc=rw.genesis_loc)
    _, ev_n1_r, _ = rw._store_op_read("2026-11-10", "nov1r", clicks_val="10", collected_at="2026-11-11T03:02:00.000000Z")
    gm_n1, gm_n1_loc = rw._materialize_signed_gen("nov1r", "incremental", "2026-11-10", ev_n1_r, cat_svc.current_head()[0], snap_oct_loc, cut1_loc, (), None)
    _, snap_n1_loc, cut2_loc = rw._commit_signed_cut(cat_svc, idx=2, op="add_partition", seq=1, gm=gm_n1, gm_loc=gm_n1_loc)
    _, ev_n2_r, _ = rw._store_op_read("2026-11-10", "nov2r", clicks_val="25", collected_at="2026-11-11T03:04:00.000000Z")
    gm_n2, gm_n2_loc = rw._materialize_signed_gen("nov2r", "incremental", "2026-11-10", ev_n2_r, cat_svc.current_head()[0], snap_n1_loc, cut2_loc, (gm_n1_loc,), gm_n1_loc)
    _, snap_n2_loc, _ = rw._commit_signed_cut(cat_svc, idx=3, op="replace_partition", seq=2, gm=gm_n2, gm_loc=gm_n2_loc)
    pol_raw = AnalysisPolicy.from_dict({
        "$schema": "smart_ads/analysis_policy/v1", "policy_id": "policy:restatement-v1", "policy_version": "1", "tenant_ref": "tenant:ibvi",
        "applicability_scope": {"resource_scope_ref": "scope:campaigns-active", "resource_level": "campaign", "ad_platform_ref": "meta", "currency": "BRL"},
        "validity": {"valid_from_utc": "2026-01-01T00:00:00.000000Z", "valid_until_utc": "2027-01-01T00:00:00.000000Z"},
        "rules": [{"rule_id": "rule:restatement-1d", "rule_type": "restatement", "lookback_days": 1, "restatement_kinds": ["value_change"]}],
    })
    pol, pol_loc = _put_signed_model(rw.store, pol_raw, rw.key_reg_loc)
    cols = tuple(ResultColumn(n, t, nl) for n, t, nl in METRIC_WINDOW_COLUMNS)
    q_m = DuckDbQueryDefinition("result:metrics", "query:metrics", _LIVE_METRICS_WINDOW_SQL, rw.metrics_schema_loc, "relation", cols, _METRIC_UKEY, _METRIC_ORDER)
    exts = (DuckDbExtensionSpec("parquet", "1.5.5", "explicit_local_binary", DuckDbExtensionBinaryLocator.for_binary_bytes(rw.ext_bytes)),)
    _, b_loc = _put_signed_model(rw.store, AnalysisReplayInputBundle("bundle:rest", rw.run_loc, snap_n2_loc, "1.5.5", DuckDbBinaryObjectLocator.for_binary_bytes(rw.duck_bytes), exts, (DuckDbSessionSetting("threads", TaggedScalarCell("int64", "1")),), (), (q_m,), pol_loc, (rw.tmpl_loc,)), rw.key_reg_loc)
    _, exec_loc, _ = execute_analysis_replay_bundle(bundle_locator=b_loc, store=rw.store, parquet_codec=rw.codec, duckdb_engine=DeterministicInMemoryDuckDbEngine())
    rows = tuple(r for gm in (gm_oct_r, gm_n1, gm_n2) for pq in gm.parquet_object_locators for r in rw.codec.decode_and_verify_landing_rows(rw.store.get_bytes(pq.object_ref, expected_size_bytes=pq.size_bytes), expected_partition_key=pq.partition_key))
    ctx = EvaluationContext(pol, EvaluationScope("tenant:ibvi", "scope:campaigns-active", "campaign", "meta", "BRL"), "2026-11-11T03:15:00.000000Z", "2026-11-10", 1, "2026-11-10", rw.eval_inv, "result:metrics", derive_snapshot_restatement_history(rw.eval_inv, rows))
    attested = (AttestedCertificationInput(CertificationInput(DerivedCertificationStatus.VERIFIED, "phase1_7b_base"), True),)
    rw._rest_gm_n1_loc, rw._rest_gm_n2 = gm_n1_loc, gm_n2  # type: ignore[attr-defined]
    return rw, b_loc, exec_loc, ctx, attested


@pytest.fixture(scope="module")
def _shared_rw() -> RetentionWorld:
    return RetentionWorld()


@pytest.fixture
def retention_world(_shared_rw: RetentionWorld) -> RetentionWorld:
    return _shared_rw.clone()


@pytest.fixture
def pipeline_world() -> SignedPipelineWorld:
    return SignedPipelineWorld()


def test_deep_1_001_multi_generation_restatement_blocks_mutations_and_binds_context(_shared_rw: RetentionWorld) -> None:
    rw, b_loc, exec_loc, ctx, attested = _build_restatement_pipeline(_shared_rw)
    gm_n1_loc: ArtifactLocator = rw._rest_gm_n1_loc  # type: ignore[attr-defined]
    gm_n2: GenerationManifest = rw._rest_gm_n2  # type: ignore[attr-defined]
    rep, _, cert, _, f_pairs = execute_certified_report(
        report_id="report:rest-ok", executed_at_utc="2026-11-11T03:20:00Z", bundle_locator=b_loc,
        execution_locator=exec_loc, evaluation_context=ctx, expected_resource_inventory_locator=rw.eval_inv_loc,
        curation_execution_locator=gm_n2.curation_execution_locator, restatement_history_generation_locators=(gm_n1_loc,),
        attested_certification_inputs=attested, report_template_provenance_locator=rw.tmpl_loc,
        render_algorithm_identity=rw.render_alg, store=rw.store, parquet_codec=rw.codec,
    )
    assert len(f_pairs) == 1 and f_pairs[0][0].finding_type == "restatement"
    assert cert.mutation_recommendations_blocked is True
    assert rep.canonical_report_result.mutation_recommendations_blocked is True
    # Suppressing restatement_history, mismatching lookback_days, or omitting overlapping ancestor gm_n1_loc MUST fail closed
    for bad_ctx, bad_hist in (
        (replace(ctx, restatement_history=()), (gm_n1_loc,)),
        (replace(ctx, curation_restatement_lookback_days=7), (gm_n1_loc,)),
        (ctx, ()),
    ):
        with pytest.raises(ClosedValidationError):
            execute_certified_report(
                report_id="report:rest-bad", executed_at_utc="2026-11-11T03:20:00Z", bundle_locator=b_loc,
                execution_locator=exec_loc, evaluation_context=bad_ctx, expected_resource_inventory_locator=rw.eval_inv_loc,
                curation_execution_locator=gm_n2.curation_execution_locator, restatement_history_generation_locators=bad_hist,
                attested_certification_inputs=attested, report_template_provenance_locator=rw.tmpl_loc,
                render_algorithm_identity=rw.render_alg, store=rw.store, parquet_codec=rw.codec,
            )


def test_policy_004_build_input_locators_reject_unprofiled_and_schema_mismatch_pre_duckdb(
    pipeline_world: SignedPipelineWorld,
) -> None:
    pw = pipeline_world
    engine = DeterministicInMemoryDuckDbEngine()
    unprofiled_loc = pw.store.put_json_artifact("smart_ads/migration_run_context/v1", {"$schema": "smart_ads/migration_run_context/v1", "run_id": "run:bi"})
    _, b_non_p1 = _store_signed(pw.store, replace(pw.bundle, build_input_locators=(unprofiled_loc,), integrity=_unsigned_p1()))
    raw_prov = pw.tmpl_prov.to_dict()
    wrong_schema_loc = ArtifactLocator.for_canonical_bytes(AnalysisPolicy.SCHEMA, canonicalize_jcs(raw_prov))
    pw.store.put_bytes(canonicalize_jcs(raw_prov))
    _, b_schema_mismatch = _store_signed(pw.store, replace(pw.bundle, build_input_locators=(wrong_schema_loc,), integrity=_unsigned_p1()))
    unsig_prov_loc = pw.store.put_json_artifact(GitArtifactProvenance.SCHEMA, {**raw_prov, "integrity": _unsigned_p1().to_dict()})
    _, b_unsig_bi = _store_signed(pw.store, replace(pw.bundle, build_input_locators=(unsig_prov_loc,), integrity=_unsigned_p1()))
    for bad_loc in (b_non_p1, b_schema_mismatch, b_unsig_bi):
        with pytest.raises(ClosedValidationError):
            execute_analysis_replay_bundle(bundle_locator=bad_loc, store=pw.store, parquet_codec=pw.codec, duckdb_engine=engine, require_signed_inputs=True)
    assert engine.call_count == 0


def test_deep_1_004_recursive_cut_lineage_to_epoch0_and_sibling_partition_verification(
    pipeline_world: SignedPipelineWorld,
) -> None:
    pw = pipeline_world
    cut2 = DatasetCatalogCutReceipt.from_dict(pw.store.get_json_artifact(pw.cut2_loc), require_signed=True)
    # 1. Dropping epoch-0 genesis record from store breaks epoch-2 cut receipt, publish, and snapshot verification
    no_gen_store = _OverlayStore(pw.store, drop_refs={pw.genesis_loc.object_ref})
    with pytest.raises(ClosedValidationError):
        verify_dataset_catalog_cut_receipt(cut2, store=no_gen_store, parquet_codec=pw.codec, require_signed=True)
    with pytest.raises(ClosedValidationError):
        publish_dataset_snapshot(snapshot_id="snapshot:fail-gen", created_at="2026-11-11T03:11:00Z", cut_receipt_locator=pw.cut2_loc, store=no_gen_store, parquet_codec=pw.codec)
    with pytest.raises(ClosedValidationError):
        verify_dataset_snapshot(pw.snap2, store=no_gen_store, parquet_codec=pw.codec, require_signed=True)
    # 2. Corrupting sibling partition oct (gm1) Parquet bytes breaks epoch-2 cut receipt & incremental curation verification
    gm1_pq_ref = pw.gm1.parquet_object_locators[0].object_ref
    corrupt_sib_store = _OverlayStore(pw.store, raw_overrides={gm1_pq_ref: b"X" * pw.gm1.parquet_object_locators[0].size_bytes})
    with pytest.raises(ClosedValidationError):
        verify_dataset_catalog_cut_receipt(cut2, store=corrupt_sib_store, parquet_codec=pw.codec, require_signed=True)
    with pytest.raises(ClosedValidationError):
        verify_curation_execution(pw.cur2, store=corrupt_sib_store, parquet_codec=pw.codec, require_signed=True)


def test_deep_1_005_and_history_004_filesystem_object_store_hardlink_oserror_and_json_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fs_store = FilesystemCellObjectStore(tmp_path / "cell-store")
    payload = b'{"$schema":"smart_ads/migration_run_context/v1","run_id":"run:fs-1"}'
    obj_ref = fs_store.put_bytes(payload)
    hex_digest = obj_ref.removeprefix("cell-object:sha256:")
    primary_path = tmp_path / "cell-store" / "sha256" / hex_digest
    ino_before = os.lstat(primary_path).st_ino
    assert fs_store.put_bytes(payload) == obj_ref
    assert os.lstat(primary_path).st_ino == ino_before

    # Closed <64_hex>.json fallback readback + idempotent put_bytes
    json_payload = canonicalize_jcs({"$schema": "smart_ads/migration_run_context/v1", "run_id": "run:gov-json"})
    loc = ArtifactLocator.for_canonical_bytes("smart_ads/migration_run_context/v1", json_payload)
    json_hex = loc.object_ref.removeprefix("cell-object:sha256:")
    json_path = tmp_path / "cell-store" / "sha256" / f"{json_hex}.json"
    json_path.write_bytes(json_payload)
    os.chmod(json_path, 0o444)
    assert fs_store.has_object(loc.object_ref) is True
    assert fs_store.get_json_artifact(loc)["run_id"] == "run:gov-json"
    assert fs_store.put_bytes(json_payload) == loc.object_ref

    # Symlink at <64_hex>.json or raw OSError must fail closed with ClosedValidationError
    sym_loc = ArtifactLocator.from_digest("smart_ads/migration_run_context/v1", "sha256:" + ("b" * 64))
    sym_path = tmp_path / "cell-store" / "sha256" / ("b" * 64 + ".json")
    os.symlink(json_path, sym_path)
    with pytest.raises(ClosedValidationError):
        fs_store.has_object(sym_loc.object_ref)
    with pytest.raises(ClosedValidationError):
        fs_store.get_bytes(sym_loc.object_ref)
    monkeypatch.setattr(os, "open", lambda *_a, **_kw: (_ for _ in ()).throw(PermissionError("denied")))
    with pytest.raises(ClosedValidationError):
        fs_store.get_bytes(obj_ref)


def test_policy_001_non_pr4_effect_chain_validation_and_in_doubt_rejection() -> None:
    store = InMemoryCellObjectStore()
    run_loc = store.put_json_artifact("smart_ads/migration_run_context/v1", {"$schema": "smart_ads/migration_run_context/v1", "run_id": "run:np4"})
    key_reg_loc = store.put_json_artifact("smart_ads/key_authorization_registry/v1", {"$schema": "smart_ads/key_authorization_registry/v1", "keys": [_KEY_ID]})
    pf_loc = _put_prereq_effect_chain(store, run_loc, key_reg_loc, action="cutover_execution", slot="cutover_effect_proof", subject_kind="cutover_target", result_schema="smart_ads/cutover_execution_result/v1", tag="cut1")
    assert pf_loc.object_ref in compute_retention_reachability_graph((pf_loc,), store=store).reachable_object_refs

    pf_doc = store.get_json_artifact(pf_loc)
    resv_loc = ArtifactLocator.from_dict(pf_doc["reservation_locator"])
    resv_doc = store.get_json_artifact(resv_loc)
    # Standalone or linked non-PR4 in_doubt reservation must fail closed
    bad_resv = _sign_payload({**resv_doc, "reservation_status": "in_doubt", "in_doubt_reason": "ambiguous_external_effect"}, key_reg_loc)
    bad_resv_loc = store.put_json_artifact(AuthorizationReservationRecord.SCHEMA, bad_resv)
    with pytest.raises(ClosedValidationError, match="in_doubt"):
        compute_retention_reachability_graph((bad_resv_loc,), store=store)
    # Chronology violation (executed_at_utc >= valid_until_utc) on non-PR4 chain must fail closed
    ex_loc = ArtifactLocator.from_dict(pf_doc["execution_locator"])
    late_ex = _sign_payload({**store.get_json_artifact(ex_loc), "executed_at_utc": "2026-11-12T00:00:00Z"}, key_reg_loc)
    with pytest.raises(ClosedValidationError):
        compute_retention_reachability_graph((pf_loc,), store=_OverlayStore(store, json_overrides={ex_loc.object_ref: late_ex}))


def test_shallow_002_rejects_standalone_embedded_locators_and_unprofiled_schemas() -> None:
    store = InMemoryCellObjectStore()
    run_loc = store.put_json_artifact("smart_ads/migration_run_context/v1", {"$schema": "smart_ads/migration_run_context/v1", "run_id": "run:sh2"})
    embedded_and_unknown = (
        (ArtifactLocator.SCHEMA, run_loc.to_dict()),
        (ParquetObjectLocator.SCHEMA, ParquetObjectLocator("year=2026/month=11", "sha256:" + ("a" * 64), 128).to_dict()),
        (DuckDbBinaryObjectLocator.SCHEMA, DuckDbBinaryObjectLocator.for_binary_bytes(b"duck").to_dict()),
        (WheelObjectLocator.SCHEMA, WheelObjectLocator.for_wheel_bytes(b"whl").to_dict()),
        ("smart_ads/active_partition_head/v1", {"$schema": "smart_ads/active_partition_head/v1", "x": 1}),
        ("smart_ads/unprofiled_custom/v1", {"$schema": "smart_ads/unprofiled_custom/v1", "x": 1}),
    )
    for schema_id, payload in embedded_and_unknown:
        loc = store.put_json_artifact(schema_id, payload)
        with pytest.raises(ClosedValidationError):
            compute_retention_reachability_graph((loc,), store=store)
        with pytest.raises(ClosedValidationError):
            build_retention_root(
                root_id="root:bad-target", cell_ref="cell:ibvi-primary",
                migration_run_context_locator=run_loc, target_artifact_locator=loc,
                created_at_utc="2026-11-11T03:25:00Z", store=store,
            )


def test_contracts_006_build_retention_root_zero_write_and_proof_backbone_reachability(
    retention_world: RetentionWorld,
) -> None:
    rw = retention_world
    unsig_pol_loc = rw.store.put_json_artifact(AnalysisPolicy.SCHEMA, {k: v for k, v in rw.policy.to_dict().items() if k != "integrity"} | {"integrity": P1Integrity(_KEY_ID, rw.key_reg_loc).to_dict()})
    before_count = len(rw.store._blobs)
    signed_stub = P1Integrity(_KEY_ID, rw.key_reg_loc, "sha256:" + ("1" * 64), ("A" * 86) + "==")
    with pytest.raises(ClosedValidationError):
        build_retention_root(
            root_id="root:unsig-child", cell_ref=rw.cell_ref, migration_run_context_locator=rw.run_loc,
            target_artifact_locator=unsig_pol_loc, created_at_utc="2026-11-11T03:25:00Z",
            store=rw.store, integrity=signed_stub,
        )
    assert len(rw.store._blobs) == before_count

    # Proof verification and service reject dangling predecessor_head_locator / run_loc / predecessor_locators
    svc = RetentionRootSetService(rw.store, rw.head0_loc, parquet_codec=rw.codec)
    adm1_pf, _ = rw.admit_root(svc, (rw.root1_loc,), tag="c006a")
    adm2_pf, _ = rw.admit_root(svc, (rw.root2_loc,), tag="c006b")
    for drop_ref in (rw.head0_loc.object_ref, rw.run_loc.object_ref):
        with pytest.raises(ClosedValidationError):
            verify_retention_root_admission_proof(adm2_pf, store=_OverlayStore(rw.store, drop_refs={drop_ref}), parquet_codec=rw.codec)
    rel_auth = rw.authorize_release(svc, (rw.root2_loc,), nonce="nonce-c006-rel")
    rel_pf, _ = rw.call_release(svc, rel_auth, reservation_id="resv:c006-rel", tag="c006r")
    with pytest.raises(ClosedValidationError):
        verify_retention_release_proof(rel_pf, store=_OverlayStore(rw.store, drop_refs={adm1_pf.after_head_locator.object_ref}), parquet_codec=rw.codec)


class _FailOnCasPutStore(CellObjectStorePort):
    """Proxy store raising `ClosedValidationError` mid-commit when persisting CAS receipt."""

    def __init__(self, base: InMemoryCellObjectStore, fail_schema: str) -> None:
        self._base = base
        self._fail_schema = fail_schema

    def put_bytes(self, raw: bytes) -> str:
        return self._base.put_bytes(raw)

    def get_bytes(self, object_ref: str, *, expected_size_bytes: int | None = None) -> bytes:
        return self._base.get_bytes(object_ref, expected_size_bytes=expected_size_bytes)

    def has_object(self, object_ref: str) -> bool:
        return self._base.has_object(object_ref)

    def put_json_artifact(self, schema_id: str, payload: Mapping[str, Any]) -> ArtifactLocator:
        if schema_id == self._fail_schema:
            raise ClosedValidationError(f"injected write failure on {schema_id}")
        return self._base.put_json_artifact(schema_id, payload)

    def get_json_artifact(self, locator: ArtifactLocator) -> dict[str, Any]:
        return self._base.get_json_artifact(locator)


def test_deep_1_003_signed_upfront_integrities_and_commit_failure_quarantine(
    retention_world: RetentionWorld,
) -> None:
    rw = retention_world
    signed_svc = RetentionRootSetService(rw.store, rw.head0_loc, parquet_codec=rw.codec, require_signed=True)
    auth_loc = rw.authorize_admission(signed_svc, (rw.root1_loc,), nonce="nonce-d1003-1")
    full_ints = _compute_signed_admission_integrities(rw, auth_loc, tag="d1003")
    # Missing in_doubt_reservation or admission_proof fails BEFORE burning single_use_nonce
    for drop_key in ("in_doubt_reservation", "admission_proof"):
        with pytest.raises(ClosedValidationError, match="integrities"):
            signed_svc.admit_roots(
                authorization_locator=auth_loc, reservation_id="resv:d1003", reserved_at_utc="2026-11-11T03:31:00Z",
                cas_receipt_id="cas:d1003", cas_linearization_id="lin:d1003", committed_at_utc="2026-11-11T03:32:00Z",
                new_head_id="head:d1003", execution_id="exec:d1003", consumption_id="cons:d1003",
                effect_proof_id="efp:d1003", verified_at_utc="2026-11-11T03:33:00Z",
                integrities={k: v for k, v in full_ints.items() if k != drop_key},
            )
        assert signed_svc.reservation_status_for(auth_loc) is None

    # Mid-commit failure inside _commit_envelopes quarantines nonce to terminal in_doubt ("ambiguous_external_effect")
    fail_store = _FailOnCasPutStore(rw.store, "smart_ads/retention_root_set_cas_receipt/v1")
    fail_svc = RetentionRootSetService(fail_store, rw.head0_loc, parquet_codec=rw.codec)
    auth_amb = rw.authorize_admission(fail_svc, (rw.root1_loc,), nonce="nonce-d1003-amb")
    with pytest.raises(ClosedValidationError, match="injected write failure"):
        fail_svc.admit_roots(
            authorization_locator=auth_amb, reservation_id="resv:amb", reserved_at_utc="2026-11-11T03:31:00Z",
            cas_receipt_id="cas:amb", cas_linearization_id="lin:amb", committed_at_utc="2026-11-11T03:32:00Z",
            new_head_id="head:amb", execution_id="exec:amb", consumption_id="cons:amb",
            effect_proof_id="efp:amb", verified_at_utc="2026-11-11T03:33:00Z",
        )
    assert fail_svc.reservation_status_for(auth_amb) == "in_doubt"
    assert fail_svc.current_head() == (rw.head0_loc, rw.head0)
    amb_reasons = [
        doc.get("in_doubt_reason")
        for doc in (
            rw.store.get_json_artifact(ArtifactLocator.for_canonical_bytes(AuthorizationReservationRecord.SCHEMA, raw))
            for raw in rw.store._blobs.values()
            if b'"smart_ads/authorization_reservation_record/v1"' in raw and b'"resv:amb"' in raw
        )
    ]
    assert "ambiguous_external_effect" in amb_reasons


def test_contracts_006_and_deep_1_003_dangling_predecessor_and_signed_in_doubt(
    retention_world: RetentionWorld,
) -> None:
    rw = retention_world
    svc = RetentionRootSetService(rw.store, rw.head0_loc, parquet_codec=rw.codec)
    base_auth_loc = rw.authorize_admission(svc, (rw.root1_loc,), nonce="nonce-dangle-pred")
    base_auth = AuthorizationReceipt.from_dict(rw.store.get_json_artifact(base_auth_loc), require_signed=True)
    _, dangle_auth_loc = _put_signed_model(
        rw.store,
        replace(base_auth, predecessor_locators=(_loc(AuthorizationReceipt.SCHEMA, "d"),), integrity=None),
        rw.key_reg_loc,
    )
    with pytest.raises(ClosedValidationError):
        svc.admit_roots(
            authorization_locator=dangle_auth_loc, reservation_id="resv:dangle", reserved_at_utc="2026-11-11T03:31:00Z",
            cas_receipt_id="cas:dangle", cas_linearization_id="lin:dangle", committed_at_utc="2026-11-11T03:32:00Z",
            new_head_id="head:dangle", execution_id="exec:dangle", consumption_id="cons:dangle",
            effect_proof_id="efp:dangle", verified_at_utc="2026-11-11T03:33:00Z",
        )
    assert svc.reservation_status_for(dangle_auth_loc) is None

    # Signed service persists signed in_doubt record (never unsigned fallback) on stale-head quarantine
    signed_svc = RetentionRootSetService(rw.store, rw.head0_loc, parquet_codec=rw.codec, require_signed=True)
    ok_auth = rw.authorize_admission(signed_svc, (rw.root1_loc,), nonce="nonce-sg-ok")
    signed_svc.admit_roots(
        authorization_locator=ok_auth, reservation_id="resv:sgok", reserved_at_utc="2026-11-11T03:31:00Z",
        cas_receipt_id="cas:sgok", cas_linearization_id="lin:sgok", committed_at_utc="2026-11-11T03:32:00Z",
        new_head_id="head:sgok", execution_id="exec:sgok", consumption_id="cons:sgok",
        effect_proof_id="efp:sgok", verified_at_utc="2026-11-11T03:33:00Z",
        integrities=_compute_signed_admission_integrities(rw, ok_auth, tag="sgok"),
    )
    stale_auth = rw.authorize_admission(signed_svc, (rw.root2_loc,), nonce="nonce-sg-stale", override_head_loc=rw.head0_loc, override_epoch=0)
    with pytest.raises(ClosedValidationError):
        signed_svc.admit_roots(
            authorization_locator=stale_auth, reservation_id="resv:sgst", reserved_at_utc="2026-11-11T03:31:00Z",
            cas_receipt_id="cas:sgst", cas_linearization_id="lin:sgst", committed_at_utc="2026-11-11T03:32:00Z",
            new_head_id="head:sgst", execution_id="exec:sgst", consumption_id="cons:sgst",
            effect_proof_id="efp:sgst", verified_at_utc="2026-11-11T03:33:00Z",
            integrities=_compute_signed_admission_integrities(rw, stale_auth, tag="sgst"),
        )
    assert signed_svc.reservation_status_for(stale_auth) == "in_doubt"
    sgst_recs = [
        AuthorizationReservationRecord.from_dict(rw.store.get_json_artifact(ArtifactLocator.for_canonical_bytes(AuthorizationReservationRecord.SCHEMA, raw)), require_signed=True)
        for raw in rw.store._blobs.values()
        if b'"resv:sgst"' in raw and b'"in_doubt"' in raw
    ]
    assert len(sgst_recs) == 1 and sgst_recs[0].integrity is not None and sgst_recs[0].integrity.is_signed

