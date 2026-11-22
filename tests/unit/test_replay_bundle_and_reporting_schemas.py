"""Unit tests for DuckDB replay bundles, report execution verification, and storage ports."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Any, Literal

import pytest

from smart_ads.analytics.cells import (
    ANALYSIS_EXECUTION_TYPE,
    ANALYSIS_RESULT_SCHEMA_TYPE,
    DATASET_SNAPSHOT_TYPE,
    REPLAY_BUNDLE_TYPE,
    RUN_CONTEXT_TYPE,
    AnalysisResultSchema,
    ResultColumn,
    ResultProjection,
    TaggedScalarCell,
)
from smart_ads.analytics.certification import (
    AnalyticalCertificationRecord,
    AttestedCertificationInput,
    build_certification_record,
)
from smart_ads.analytics.formulas import CertificationInput, DerivedCertificationStatus
from smart_ads.analytics.intelligence import (
    METRIC_WINDOW_COLUMNS,
    AnalysisEvidence,
    EvaluationContext,
    Finding,
    evaluate_findings,
)
from smart_ads.analytics.policy import AnalysisPolicy, EvaluationScope
from smart_ads.analytics.replay_bundle import (
    DUCKDB_BINARY_LOCATOR_SCHEMA,
    DUCKDB_EXT_BINARY_LOCATOR_SCHEMA,
    FORBIDDEN_DUCKDB_SESSION_SETTINGS,
    AnalysisReplayInputBundle,
    DuckDbBinaryObjectLocator,
    DuckDbExtensionBinaryLocator,
    DuckDbExtensionSpec,
    DuckDbQueryDefinition,
    DuckDbSessionSetting,
    DuckDbViewDefinition,
)
from smart_ads.analytics.reporting import (
    REPORT_EXECUTION_SCHEMA,
    CanonicalReportInput,
    CanonicalReportResult,
    ReportExecution,
    derive_snapshot_restatement_history,
    render_canonical_report_result,
    verify_report_execution,
)
from smart_ads.analytics.results import (
    AnalysisExecution,
    AnalysisResult,
    CanonicalResultEntry,
    CanonicalResultSet,
)
from smart_ads.contracts.effects import sort_artifact_locators
from smart_ads.contracts.git_provenance import GitArtifactProvenance, compute_git_blob_oid
from smart_ads.contracts.jcs import (
    ArtifactLocator,
    P1Integrity,
    canonicalize_jcs,
    jcs_sha256,
    p1_content_digest,
)
from smart_ads.contracts.operational_evidence import (
    AlgorithmProvenanceIdentity,
    OperationalReadEvidence,
)
from smart_ads.contracts.scalars import ClosedValidationError
from smart_ads.contracts.schemas import AnalyticsLandingRow, DateRange, FactKey
from smart_ads.domain.catalog import (
    ActivePartitionHead,
    CatalogCasRequestProjection,
    DatasetCatalog,
    DatasetCatalogCutReceipt,
    DatasetSnapshot,
    GenerationManifest,
    ParquetObjectLocator,
    compute_logical_rows_digest,
)
from smart_ads.domain.curation import CurationExecution, compute_curation_window
from smart_ads.domain.registry import ExpectedResourceInventory, ExpectedResourceKey
import smart_ads.ports as ports_pkg
from smart_ads.ports.storage import (
    CellObjectStorePort,
    DuckDbEnginePort,
    ParquetLandingCodecPort,
)

RES_1 = "resource:" + ("a" * 52)
KEY_ID = "key:ed25519:" + ("a" * 64)


def _loc(artifact_type: str, fill: str) -> ArtifactLocator:
    return ArtifactLocator.from_digest(artifact_type, "sha256:" + (fill * 64))


KEY_REG_LOC = _loc("smart_ads/key_authorization_registry/v1", "9")
UNSIGNED = P1Integrity(key_id=KEY_ID, key_registry_snapshot_locator=KEY_REG_LOC)


def _sign(obj: Any) -> Any:
    d = {**obj.to_dict(), "integrity": UNSIGNED.to_dict()}
    signed_int = {
        **UNSIGNED.to_dict(),
        "content_digest": p1_content_digest(d),
        "signature_base64": ("A" * 86) + "==",
    }
    return type(obj).from_dict({**d, "integrity": signed_int}, require_signed=True)


def _resign(obj: Any, **changes: Any) -> Any:
    return _sign(replace(obj, **changes, integrity=UNSIGNED))


def _git_prov(path: str, raw: bytes) -> GitArtifactProvenance:
    import hashlib

    return GitArtifactProvenance(
        repository="aiconnai/smart-ads",
        commit_sha="1" * 40,
        path=path,
        git_blob_oid=compute_git_blob_oid(raw),
        file_content_sha256="sha256:" + hashlib.sha256(raw).hexdigest(),
        resolved_at_utc="2026-11-11T03:00:00Z",
        integrity=UNSIGNED,
    )


def _op_evidence(run_loc: ArtifactLocator, fill: str) -> OperationalReadEvidence:
    adm_loc = _loc("smart_ads/admitted_collection/v1", fill)
    reg_loc = _loc("smart_ads/private_registry_snapshot/v1", "3")
    res_loc = _loc("smart_ads/collection_result/v1", fill)
    return OperationalReadEvidence(
        migration_run_context_locator=run_loc,
        tenant_ref="tenant:ibvi",
        binding_ref="binding:meta-primary",
        account_ref="account:ibvi-01",
        resource_scope_ref="scope:campaigns-active",
        canonical_query_digest="sha256:" + (fill * 64),
        registry_snapshot_locator=reg_loc,
        registry_snapshot_digest=reg_loc.content_digest,
        expected_resource_inventory_locator=_loc("smart_ads/expected_resource_inventory/v1", "4"),
        admitted_collection_locator=adm_loc,
        admitted_collection_digest=adm_loc.content_digest,
        collection_result_locator=res_loc,
        collection_result_digest=res_loc.content_digest,
        normalized_fact_set_digest="sha256:" + (fill * 64),
        authorization_locator=_loc("smart_ads/authorization_receipt/v1", fill),
        reservation_locator=_loc("smart_ads/authorization_reservation_record/v1", fill),
        execution_locator=_loc("smart_ads/execution_receipt/v1", fill),
        consumption_locator=_loc("smart_ads/authorization_consumption_record/v1", fill),
        effect_proof_locator=_loc("smart_ads/effect_proof/v1", fill),
        integrity=UNSIGNED,
    )


def _landing_row(metric_date: str, fill: str = "a") -> AnalyticsLandingRow:
    fk = FactKey(
        binding_ref="binding:meta-primary",
        account_ref="account:ibvi-01",
        resource_ref=RES_1,
        resource_level="campaign",
        metric_date=metric_date,
        metric_semantic_ref="metric:clicks_v1",
        source_metric_ref="source-metric:provider:pipeboard.clicks:v1",
        attribution_ref="attribution:not_applicable",
        breakdown_signature="breakdown:none",
    )
    return AnalyticsLandingRow(
        fact_key=fk,
        value_type="int64_count",
        raw_numeric_value="10",
        unit="count",
        currency=None,
        metric_origin="provider_observation",
        presence_status="observed",
        unknown_reason=None,
        calculation_status="not_applicable",
        collected_at_utc=f"2026-11-11T03:00:0{fill if fill.isdigit() else '1'}.000000Z",
        source_observation_ref=f"observation:obs-{fill}",
        adapter_version="0.1.0",
        semantic_version="1.0.0",
    )


@pytest.fixture
def valid_bundle_dict() -> dict[str, Any]:
    db_bin = DuckDbBinaryObjectLocator.for_binary_bytes(b"\x7fELF-duckdb-1.5.5")
    ext_bin = DuckDbExtensionBinaryLocator.for_binary_bytes(b"parquet-ext-bytes")
    col = ResultColumn("total_spend", "int64", False)
    schema = AnalysisResultSchema("scalar", (col,), None, UNSIGNED)
    query = DuckDbQueryDefinition(
        result_key="result:total_spend",
        query_id="query:total_spend",
        sql_utf8="SELECT 1500 AS total_spend",
        analysis_result_schema_locator=schema.locator(),
        inline_result_kind="scalar",
        inline_columns=(col,),
        inline_unique_key=None,
        deterministic_order_by=(),
    )
    bundle = AnalysisReplayInputBundle(
        bundle_id="bundle:b-001",
        migration_run_context_locator=_loc(RUN_CONTEXT_TYPE, "1"),
        dataset_snapshot_locator=_loc(DATASET_SNAPSHOT_TYPE, "2"),
        duckdb_engine_version="1.5.5",
        duckdb_binary_locator=db_bin,
        extensions=(
            DuckDbExtensionSpec("icu", "1.5.5", "statically_linked", None),
            DuckDbExtensionSpec("parquet", "1.5.5", "explicit_local_binary", ext_bin),
        ),
        session_settings=(
            DuckDbSessionSetting("preserve_insertion_order", TaggedScalarCell("boolean", True)),
            DuckDbSessionSetting("threads", TaggedScalarCell("int64", "1")),
        ),
        views=(
            DuckDbViewDefinition("v_landing", "SELECT * FROM __smart_ads_landing", ()),
        ),
        queries=(query,),
        analysis_policy_locator=_loc("smart_ads/analysis_policy/v1", "5"),
        build_input_locators=(_loc("smart_ads/git_artifact_provenance/v1", "6"),),
        integrity=UNSIGNED,
    )
    return bundle.to_dict()


def test_duckdb_binary_and_extension_locators_closed_validation() -> None:
    eng = DuckDbBinaryObjectLocator.for_binary_bytes(b"duckdb-bin")
    ext = DuckDbExtensionBinaryLocator.for_binary_bytes(b"ext-bin")
    assert eng.to_dict()["$schema"] == DUCKDB_BINARY_LOCATOR_SCHEMA
    assert ext.to_dict()["$schema"] == DUCKDB_EXT_BINARY_LOCATOR_SCHEMA
    assert eng.media_type == "application/x-executable"
    assert ext.media_type == "application/x-duckdb-extension"
    assert DuckDbBinaryObjectLocator.from_dict(eng.to_dict()) == eng
    assert DuckDbExtensionBinaryLocator.from_dict(ext.to_dict()) == ext

    for bad_patch in (
        {"media_type": "application/octet-stream"},
        {"store_kind": "local_fs"},
        {"object_ref": "cell-object:sha256:" + ("0" * 64)},
        {"object_ref": ""},
        {"size_bytes": 0},
        {"size_bytes": True},
        {"extra": 1},
    ):
        with pytest.raises(ClosedValidationError):
            DuckDbBinaryObjectLocator.from_dict({**eng.to_dict(), **bad_patch})
        with pytest.raises(ClosedValidationError):
            DuckDbExtensionBinaryLocator.from_dict({**ext.to_dict(), **bad_patch})


def test_extension_spec_and_session_settings_validation() -> None:
    ext_bin = DuckDbExtensionBinaryLocator.for_binary_bytes(b"ext")
    with pytest.raises(ClosedValidationError):
        DuckDbExtensionSpec("parquet", "1.5.5", "statically_linked", ext_bin)
    with pytest.raises(ClosedValidationError):
        DuckDbExtensionSpec("parquet", "1.5.5", "explicit_local_binary", None)
    for bad_name in ("", "Parquet", "path/to/ext", "parquet.duckdb_extension"):
        with pytest.raises(ClosedValidationError):
            DuckDbExtensionSpec(bad_name, "1.5.5", "statically_linked", None)
    for bad_ver in ("", "latest", "*", ">=1.5.0", "1.5.5 beta"):
        with pytest.raises(ClosedValidationError):
            DuckDbExtensionSpec("parquet", bad_ver, "statically_linked", None)

    assert DuckDbSessionSetting("memory_limit", TaggedScalarCell("utf8", "256MB")).setting_name == "memory_limit"
    for bad_tag, bad_val in (
        ("null", None),
        ("decimal6", "1.000000"),
        ("date", "2026-11-10"),
        ("timestamp", "2026-11-10T00:00:00.000000Z"),
        ("opaque_ref", "tenant:t1"),
    ):
        with pytest.raises(ClosedValidationError):
            DuckDbSessionSetting("threads", TaggedScalarCell(bad_tag, bad_val))  # type: ignore[arg-type]


def test_replay_bundle_rejects_view_cycle_and_security_override(
    valid_bundle_dict: dict[str, object],
) -> None:
    cyclic = {
        **valid_bundle_dict,
        "views": [
            {"view_name": "v_a", "sql_utf8": "SELECT * FROM v_b", "depends_on_views": ["v_b"]},
            {"view_name": "v_b", "sql_utf8": "SELECT * FROM v_a", "depends_on_views": ["v_a"]},
        ],
    }
    with pytest.raises(ClosedValidationError):
        AnalysisReplayInputBundle.from_dict(cyclic)

    for forbidden in (*FORBIDDEN_DUCKDB_SESSION_SETTINGS, "ENABLE_EXTERNAL_ACCESS"):
        bad_setting_bundle = {
            **valid_bundle_dict,
            "session_settings": [
                {"setting_name": forbidden, "setting_value": {"_type": "boolean", "value": True}}
            ],
        }
        with pytest.raises(ClosedValidationError):
            AnalysisReplayInputBundle.from_dict(bad_setting_bundle)


def test_replay_bundle_topological_views_and_sql_restrictions(
    valid_bundle_dict: dict[str, Any],
) -> None:
    dag_dict = {
        **valid_bundle_dict,
        "views": [
            {"view_name": "v_a", "sql_utf8": "SELECT * FROM v_b", "depends_on_views": ["v_b"]},
            {"view_name": "v_b", "sql_utf8": "WITH c AS (SELECT * FROM v_c) SELECT * FROM c", "depends_on_views": ["v_c"]},
            {"view_name": "v_c", "sql_utf8": "SELECT * FROM __smart_ads_landing", "depends_on_views": []},
            {"view_name": "v_d", "sql_utf8": "SELECT 1 AS x", "depends_on_views": []},
        ],
    }
    bundle = AnalysisReplayInputBundle.from_dict(dag_dict)
    assert [v.view_name for v in bundle.views] == ["v_a", "v_b", "v_c", "v_d"]
    assert [v.view_name for v in bundle.topological_views()] == ["v_c", "v_b", "v_a", "v_d"]

    for bad_view in (
        {"view_name": "__smart_ads_landing", "sql_utf8": "SELECT 1", "depends_on_views": []},
        {"view_name": "v_semi", "sql_utf8": "SELECT 1; SELECT 2", "depends_on_views": []},
        {"view_name": "v_ddl", "sql_utf8": "DROP TABLE x", "depends_on_views": []},
        {"view_name": "v_self", "sql_utf8": "SELECT * FROM v_self", "depends_on_views": ["v_self"]},
        {"view_name": "v_miss", "sql_utf8": "SELECT * FROM v_ghost", "depends_on_views": ["v_ghost"]},
    ):
        with pytest.raises(ClosedValidationError):
            AnalysisReplayInputBundle.from_dict({**valid_bundle_dict, "views": [bad_view]})


def test_query_definition_order_by_and_schema_parity(valid_bundle_dict: dict[str, Any]) -> None:
    cols = (ResultColumn("b_col", "utf8", False), ResultColumn("a_col", "int64", False))
    rel_schema = AnalysisResultSchema("relation", cols, ("a_col",), UNSIGNED)
    # Non-alphabetical ORDER BY priority is preserved on relation queries
    q_rel = DuckDbQueryDefinition(
        result_key="result:rel",
        query_id="query:rel",
        sql_utf8="SELECT 'x' AS b_col, 1 AS a_col ORDER BY b_col, a_col",
        analysis_result_schema_locator=rel_schema.locator(),
        inline_result_kind="relation",
        inline_columns=cols,
        inline_unique_key=("a_col",),
        deterministic_order_by=("b_col", "a_col"),
    )
    q_rel.verify_against_schema(rel_schema)
    assert q_rel.deterministic_order_by == ("b_col", "a_col")

    wrong_schema = AnalysisResultSchema("relation", cols, None, UNSIGNED)
    with pytest.raises(ClosedValidationError):
        q_rel.verify_against_schema(wrong_schema)

    for bad_q_kwargs in (
        {"deterministic_order_by": ()},
        {"deterministic_order_by": ("missing_col",)},
        {"deterministic_order_by": ("a_col", "a_col")},
        {"sql_utf8": "SELECT 'x' AS b_col, 1 AS a_col;"},
        {"sql_utf8": "SET enable_external_access = true"},
    ):
        with pytest.raises(ClosedValidationError):
            replace(q_rel, **bad_q_kwargs)

    for bad_bundle_patch in (
        {"duckdb_engine_version": "v1.5.5"},
        {"queries": []},
        {"build_input_locators": []},
        {"extensions": list(reversed(valid_bundle_dict["extensions"]))},
        {"session_settings": list(reversed(valid_bundle_dict["session_settings"]))},
    ):
        with pytest.raises(ClosedValidationError):
            AnalysisReplayInputBundle.from_dict({**valid_bundle_dict, **bad_bundle_patch})


@dataclass(frozen=True)
class _ReportWorld:
    report: ReportExecution
    snapshot: DatasetSnapshot
    generation_manifests: tuple[GenerationManifest, ...]
    operational_evidences: tuple[OperationalReadEvidence, ...]
    replay_bundle: AnalysisReplayInputBundle
    execution: AnalysisExecution
    results: tuple[AnalysisResult, ...]
    result_schemas: tuple[AnalysisResultSchema, ...]
    policy_obj: AnalysisPolicy
    findings: tuple[Finding, ...]
    certifications: tuple[AnalyticalCertificationRecord, ...]
    evaluation_context: EvaluationContext
    attested_inputs: tuple[AttestedCertificationInput, ...]
    template_provenance: GitArtifactProvenance
    render_provenance: GitArtifactProvenance
    curation_execution: CurationExecution
    decoded_generation_rows: Mapping[str, Sequence[AnalyticsLandingRow]]

    def verify_kwargs(self, **overrides: Any) -> dict[str, Any]:
        base: dict[str, Any] = {
            "snapshot": self.snapshot,
            "generation_manifests": self.generation_manifests,
            "operational_evidences": self.operational_evidences,
            "replay_bundle": self.replay_bundle,
            "execution": self.execution,
            "results": self.results,
            "result_schemas": self.result_schemas,
            "policy_obj": self.policy_obj,
            "findings": self.findings,
            "certifications": self.certifications,
            "evaluation_context": self.evaluation_context,
            "attested_inputs": self.attested_inputs,
            "template_provenance": self.template_provenance,
            "render_provenance": self.render_provenance,
            "curation_execution": self.curation_execution,
            "decoded_generation_rows": self.decoded_generation_rows,
        }
        base.update(overrides)
        return base


def _build_snapshot_and_generations(
    run_loc: ArtifactLocator, *, with_replaced_nov_history: bool = False, hist_run_loc: ArtifactLocator | None = None
) -> tuple[DatasetSnapshot, tuple[GenerationManifest, ...], tuple[OperationalReadEvidence, ...], CurationExecution, dict[str, tuple[AnalyticsLandingRow, ...]], tuple[ArtifactLocator, ...]]:
    ev1, ev2 = _sign(_op_evidence(run_loc, "a")), _sign(_op_evidence(run_loc, "b"))
    reg_loc, cat0_loc = _loc("smart_ads/private_registry_snapshot/v1", "3"), _loc("smart_ads/dataset_catalog/v1", "0")
    cur_prov = _sign(_git_prov("src/smart_ads/domain/curation.py", b"# curation"))
    cur_prov_loc = ArtifactLocator.for_canonical_bytes(GitArtifactProvenance.SCHEMA, canonicalize_jcs(cur_prov.to_dict()))
    cur_alg = AlgorithmProvenanceIdentity("algorithm:curate-v1", "1.0.0", cur_prov_loc, cur_prov.repository, cur_prov.commit_sha, cur_prov.path, cur_prov.git_blob_oid, cur_prov.file_content_sha256, "cpython-3.12", CurationExecution.SCHEMA)
    win = compute_curation_window("2026-11-10", "America/Sao_Paulo", "2026a", 7)
    r1, r2, r_hist = _landing_row("2026-10-31", "1"), _landing_row("2026-11-10", "2"), _landing_row("2026-11-05", "3")
    _, d1 = compute_logical_rows_digest((r1,))
    _, d2 = compute_logical_rows_digest((r2,))
    _, d_hist = compute_logical_rows_digest((r_hist,))
    hist_locs: tuple[ArtifactLocator, ...] = ()
    parent_loc: ArtifactLocator | None = None
    extra_gms: tuple[GenerationManifest, ...] = ()
    if with_replaced_nov_history:
        h_cur = _sign(CurationExecution(run_loc, "curation:hist", "incremental", "2026-11-05", "America/Sao_Paulo", "2026a", 7, compute_curation_window("2026-11-05", "America/Sao_Paulo", "2026a", 7), _loc("smart_ads/sanitized_candidate_fact_set/v1", "6"), cur_alg, None, cat0_loc, _loc("smart_ads/dataset_snapshot/v1", "2"), _loc("smart_ads/dataset_catalog_cut_receipt/v1", "5"), (), "2026-11-06T03:00:00Z", UNSIGNED))
        hist_gm = _sign(GenerationManifest(hist_run_loc or run_loc, "gen:hist", "year=2026/month=11", None, "2026-11-06T03:00:00Z", 1, d_hist, reg_loc, h_cur.locator(), cat0_loc, (ev1.locator(),), (ParquetObjectLocator("year=2026/month=11", "sha256:" + ("7" * 64), 256),), integrity=UNSIGNED))
        hist_locs, parent_loc, extra_gms = (hist_gm.locator(),), hist_gm.locator(), (hist_gm,)
    cur_exec = _sign(CurationExecution(run_loc, "curation:cur-11", "incremental", "2026-11-10", "America/Sao_Paulo", "2026a", 7, win, _loc("smart_ads/sanitized_candidate_fact_set/v1", "7"), cur_alg, None, cat0_loc, _loc("smart_ads/dataset_snapshot/v1", "2"), _loc("smart_ads/dataset_catalog_cut_receipt/v1", "5"), hist_locs, "2026-11-11T03:00:00Z", UNSIGNED))
    gm1 = _sign(GenerationManifest(run_loc, "gen:10", "year=2026/month=10", None, "2026-11-01T03:00:00Z", 1, d1, reg_loc, cur_exec.locator(), cat0_loc, (ev1.locator(),), (ParquetObjectLocator("year=2026/month=10", "sha256:" + ("d" * 64), 256),), integrity=UNSIGNED))
    gm2_evs = sort_artifact_locators([ev1.locator(), ev2.locator()], expected_type=OperationalReadEvidence.SCHEMA)
    gm2 = _sign(GenerationManifest(run_loc, "gen:11", "year=2026/month=11", parent_loc, "2026-11-11T03:00:00Z", 1, d2, reg_loc, cur_exec.locator(), cat0_loc, gm2_evs, (ParquetObjectLocator("year=2026/month=11", "sha256:" + ("e" * 64), 256),), integrity=UNSIGNED))
    nov_seq = 2 if with_replaced_nov_history else 1
    heads = (ActivePartitionHead("year=2026/month=10", 1, gm1.locator()), ActivePartitionHead("year=2026/month=11", nov_seq, gm2.locator()))
    cat2 = _sign(DatasetCatalog("cat:2", "cell:ibvi", 2, "2026-11-11T03:01:00Z", heads, UNSIGNED))
    proj = CatalogCasRequestProjection("replace_partition" if with_replaced_nov_history else "add_partition", 1, cat0_loc.content_digest, "year=2026/month=11", nov_seq, gm2.locator())
    cut = _sign(DatasetCatalogCutReceipt("cut:2", "cell:ibvi", run_loc, cat0_loc, cat0_loc.content_digest, 1, cat2.locator(), cat2.locator().content_digest, 2, proj, "lin:2", "2026-11-11T03:01:00Z", integrity=UNSIGNED))
    snap = _sign(DatasetSnapshot("snapshot:s-2", 2, cat2.locator(), cut.locator(), "2026-11-11T03:02:00Z", heads, integrity=UNSIGNED))
    ordered_evs = tuple(sorted((ev1, ev2), key=lambda e: canonicalize_jcs(e.locator().to_dict())))
    dec = {gm1.locator().object_ref: (r1,), gm2.locator().object_ref: (r2,), **{g.locator().object_ref: (r_hist,) for g in extra_gms}}
    return snap, (gm1, *extra_gms, gm2), ordered_evs, cur_exec, dec, hist_locs


def _metric_rows(inconclusive_clicks: bool) -> tuple[tuple[TaggedScalarCell, ...], ...]:
    spend_row = (
        TaggedScalarCell("opaque_ref", RES_1), TaggedScalarCell("date", "2026-11-08"),
        TaggedScalarCell("date", "2026-11-10"), TaggedScalarCell("opaque_ref", "metric:spend_v1"),
        TaggedScalarCell("utf8", "provider_observation"), TaggedScalarCell("utf8", "observed"),
        TaggedScalarCell("utf8", "not_applicable"), TaggedScalarCell("null", None),
        TaggedScalarCell("utf8", "int64_minor_currency"), TaggedScalarCell("int64", "5000"),
        TaggedScalarCell("utf8", "minor_currency"), TaggedScalarCell("utf8", "BRL"),
    )
    if inconclusive_clicks:
        clicks_row = (
            TaggedScalarCell("opaque_ref", RES_1), TaggedScalarCell("date", "2026-11-08"),
            TaggedScalarCell("date", "2026-11-10"), TaggedScalarCell("opaque_ref", "metric:clicks_v1"),
            TaggedScalarCell("utf8", "provider_observation"), TaggedScalarCell("utf8", "missing"),
            TaggedScalarCell("utf8", "not_applicable"), TaggedScalarCell("utf8", "provider_omitted"),
            TaggedScalarCell("null", None), TaggedScalarCell("null", None),
            TaggedScalarCell("null", None), TaggedScalarCell("null", None),
        )
    else:
        clicks_row = (
            TaggedScalarCell("opaque_ref", RES_1), TaggedScalarCell("date", "2026-11-08"),
            TaggedScalarCell("date", "2026-11-10"), TaggedScalarCell("opaque_ref", "metric:clicks_v1"),
            TaggedScalarCell("utf8", "provider_observation"), TaggedScalarCell("utf8", "observed"),
            TaggedScalarCell("utf8", "not_applicable"), TaggedScalarCell("null", None),
            TaggedScalarCell("utf8", "int64_count"), TaggedScalarCell("int64", "0"),
            TaggedScalarCell("utf8", "count"), TaggedScalarCell("null", None),
        )
    return (clicks_row, spend_row)


def _build_analysis_and_context(
    run_loc: ArtifactLocator, snap: DatasetSnapshot, *, inconclusive_clicks: bool, lineage_rows: Sequence[AnalyticsLandingRow]
) -> tuple[AnalysisPolicy, AnalysisResultSchema, AnalysisReplayInputBundle, AnalysisResult, AnalysisExecution, EvaluationContext]:
    pol = _sign(AnalysisPolicy.from_dict({
        "$schema": "smart_ads/analysis_policy/v1", "policy_id": "policy:p1", "policy_version": "1",
        "tenant_ref": "tenant:ibvi",
        "applicability_scope": {"resource_scope_ref": "scope:campaigns-active", "resource_level": "campaign", "ad_platform_ref": "meta", "currency": "BRL"},
        "validity": {"valid_from_utc": "2026-01-01T00:00:00.000000Z", "valid_until_utc": "2027-01-01T00:00:00.000000Z"},
        "rules": [{"rule_id": "rule:waste", "rule_type": "waste", "window_days": 3, "spend_metric_ref": "metric:spend_v1", "outcome_metric_ref": "metric:clicks_v1", "min_spend_minor": "1000", "max_outcome_count": "0"}],
        "integrity": UNSIGNED.to_dict(),
    }))
    cols = tuple(ResultColumn(n, t, nl) for n, t, nl in METRIC_WINDOW_COLUMNS)
    ukey = ("metric_semantic_ref", "resource_ref", "window_end_date", "window_start_date")
    r_schema = _sign(AnalysisResultSchema("relation", cols, ukey, UNSIGNED))
    q_def = DuckDbQueryDefinition("result:metrics", "query:metrics", "SELECT * FROM __smart_ads_landing", r_schema.locator(), "relation", cols, ukey, ("resource_ref", "window_start_date", "window_end_date", "metric_semantic_ref"))
    bundle = _sign(AnalysisReplayInputBundle("bundle:b-1", run_loc, snap.locator(), "1.5.5", DuckDbBinaryObjectLocator.for_binary_bytes(b"duckdb"), (), (), (), (q_def,), pol.locator(), (_loc("smart_ads/git_artifact_provenance/v1", "6"),), UNSIGNED))
    rows = _metric_rows(inconclusive_clicks)
    proj = ResultProjection("relation", r_schema.locator(), cols, rows, len(rows))
    a_res = _sign(AnalysisResult(run_loc, snap.locator(), bundle.locator(), "result:metrics", proj, UNSIGNED))
    c_set = CanonicalResultSet.build(bundle.locator(), (CanonicalResultEntry.from_result(a_res),))
    a_exec = _sign(AnalysisExecution(bundle.locator(), c_set, UNSIGNED))
    reg_loc = _loc("smart_ads/private_registry_snapshot/v1", "3")
    inv = _sign(ExpectedResourceInventory("inventory:inv-1", reg_loc, reg_loc.content_digest, "tenant:ibvi", "binding:meta-primary", "account:ibvi-01", "scope:campaigns-active", DateRange("2026-11-01", "2026-11-10", True), (ExpectedResourceKey("binding:meta-primary", "account:ibvi-01", RES_1, "campaign", "2026-11-10"),), UNSIGNED))
    rest_hist = derive_snapshot_restatement_history(inv, lineage_rows)
    ctx = EvaluationContext(pol, EvaluationScope("tenant:ibvi", "scope:campaigns-active", "campaign", "meta", "BRL"), "2026-11-11T03:05:00.000000Z", "2026-11-10", 7, "2026-11-10", inv, "result:metrics", rest_hist)
    return pol, r_schema, bundle, a_res, a_exec, ctx


def _build_report_world(
    *, inconclusive_clicks: bool = False, with_replaced_nov_history: bool = False, hist_run_loc: ArtifactLocator | None = None
) -> _ReportWorld:
    run_loc = _loc(RUN_CONTEXT_TYPE, "1")
    snap, gms, op_evs, cur_exec, dec_rows, hist_locs = _build_snapshot_and_generations(run_loc, with_replaced_nov_history=with_replaced_nov_history, hist_run_loc=hist_run_loc)
    lineage_rows = tuple(r for rows in dec_rows.values() for r in rows)
    pol, r_schema, bundle, a_res, a_exec, ctx = _build_analysis_and_context(run_loc, snap, inconclusive_clicks=inconclusive_clicks, lineage_rows=lineage_rows)
    ev_bundle = AnalysisEvidence(a_exec, (a_res,), (r_schema,), snap.locator(), pol.locator(), True, run_loc)
    signed_findings = tuple(_sign(f) for f in evaluate_findings(ctx, ev_bundle))
    attested = (AttestedCertificationInput(CertificationInput(DerivedCertificationStatus.VERIFIED, "phase1_7b_base"), True),)
    cert = _sign(build_certification_record(ctx, ev_bundle, signed_findings, attested, integrity=UNSIGNED))
    tmpl_prov = _sign(_git_prov("src/smart_ads/analytics/reporting_template.json", b'{"v":1}'))
    rnd_prov = _sign(_git_prov("src/smart_ads/analytics/reporting.py", b"# reporting"))
    rnd_loc = ArtifactLocator.for_canonical_bytes(GitArtifactProvenance.SCHEMA, canonicalize_jcs(rnd_prov.to_dict()))
    tmpl_loc = ArtifactLocator.for_canonical_bytes(GitArtifactProvenance.SCHEMA, canonicalize_jcs(tmpl_prov.to_dict()))
    inv_loc = ArtifactLocator.for_canonical_bytes(ExpectedResourceInventory.SCHEMA, canonicalize_jcs(ctx.inventory.to_dict()))
    alg_id = AlgorithmProvenanceIdentity("algorithm:report-renderer-v1", "1.0.0", rnd_loc, rnd_prov.repository, rnd_prov.commit_sha, rnd_prov.path, rnd_prov.git_blob_oid, rnd_prov.file_content_sha256, "cpython-3.12", REPORT_EXECUTION_SCHEMA)
    rep_in = CanonicalReportInput(snap.snapshot_digest, a_exec.canonical_result_set.canonical_result_digest, ctx.evaluation_instant_utc, ctx.window_end_date, ctx.metrics_result_key, inv_loc, gms[-1].curation_execution_locator, hist_locs, attested, tuple(sorted((f.finding_digest for f in signed_findings), key=lambda s: s.encode("utf-8"))), cert.derived_certification_status, cert.mutation_recommendations_blocked)
    rep_res = render_canonical_report_result(rep_in, signed_findings)
    ev_locs = sort_artifact_locators([e.locator() for e in op_evs], expected_type=OperationalReadEvidence.SCHEMA)
    pf_locs = sort_artifact_locators([e.effect_proof_locator for e in op_evs], expected_type="smart_ads/effect_proof/v1")
    f_locs = sort_artifact_locators([f.locator() for f in signed_findings], expected_type=Finding.SCHEMA, allow_empty=True)
    rep = _sign(ReportExecution("report:r-001", run_loc, snap.locator(), bundle.locator(), a_exec.locator(), pol.locator(), f_locs, (cert.locator(),), ev_locs, pf_locs, tmpl_loc, alg_id, rep_in, rep_res, "2026-11-11T03:06:00Z", integrity=UNSIGNED))
    return _ReportWorld(rep, snap, gms, op_evs, bundle, a_exec, (a_res,), (r_schema,), pol, signed_findings, (cert,), ctx, attested, tmpl_prov, rnd_prov, cur_exec, dec_rows)


def test_report_execution_verifies_signed_detected_and_inconclusive_chains() -> None:
    detected_world = _build_report_world(inconclusive_clicks=False)
    verified = verify_report_execution(detected_world.report, **detected_world.verify_kwargs(), require_signed=True)
    assert verified == detected_world.report
    assert len(verified.to_dict()) == 20
    assert verified.canonical_report_result.detected_finding_count == 1
    assert verified.canonical_report_result.mutation_recommendations_blocked is False
    assert verified.operational_read_effect_proof_set_digest == jcs_sha256(
        [loc.to_dict() for loc in verified.operational_read_effect_proof_locators]
    )

    inc_world = _build_report_world(inconclusive_clicks=True)
    verified_inc = verify_report_execution(inc_world.report, **inc_world.verify_kwargs(), require_signed=True)
    assert verified_inc.canonical_report_result.inconclusive_finding_count == 1
    assert verified_inc.canonical_report_result.derived_certification_status is DerivedCertificationStatus.UNAVAILABLE
    assert verified_inc.canonical_report_result.mutation_recommendations_blocked is True
    assert CanonicalReportResult.from_dict(verified_inc.canonical_report_result.to_dict()) == verified_inc.canonical_report_result


def test_verify_report_execution_rejects_snapshot_evidence_and_cert_drift() -> None:
    world = _build_report_world(inconclusive_clicks=False)

    # 1. Missing active GenerationManifest or missing OperationalReadEvidence rejects
    with pytest.raises(ClosedValidationError):
        verify_report_execution(world.report, **world.verify_kwargs(generation_manifests=(world.generation_manifests[0],)))
    with pytest.raises(ClosedValidationError):
        verify_report_execution(world.report, **world.verify_kwargs(operational_evidences=(world.operational_evidences[0],)))

    # 2. Cross-run or mismatched OperationalReadEvidence rejects
    other_run_ev = _resign(world.operational_evidences[0], migration_run_context_locator=_loc(RUN_CONTEXT_TYPE, "f"))
    with pytest.raises(ClosedValidationError):
        verify_report_execution(world.report, **world.verify_kwargs(operational_evidences=(other_run_ev, world.operational_evidences[1])))

    # 3. Divergent DatasetSnapshot rejects
    other_snap = _resign(world.snapshot, snapshot_id="snapshot:s-other", snapshot_digest="")
    with pytest.raises(ClosedValidationError):
        verify_report_execution(world.report, **world.verify_kwargs(snapshot=other_snap))

    # 4. Divergent ReplayBundle or CertificationRecord rejects
    other_bundle = _resign(world.replay_bundle, bundle_id="bundle:other")
    with pytest.raises(ClosedValidationError):
        verify_report_execution(world.report, **world.verify_kwargs(replay_bundle=other_bundle))

    bad_cert = _resign(world.certifications[0], derived_certification_status=DerivedCertificationStatus.BLOCKED)
    with pytest.raises(ClosedValidationError):
        verify_report_execution(world.report, **world.verify_kwargs(certifications=(bad_cert,)))
    # Even if ReportExecution itself binds bad_cert.locator() and BLOCKED status, re-evaluation rejects!
    bad_in = replace(world.report.canonical_report_input, derived_certification_status=DerivedCertificationStatus.BLOCKED)
    bad_res = render_canonical_report_result(bad_in, world.findings)
    rep_with_bad_cert = _resign(
        world.report,
        certification_record_locators=(bad_cert.locator(),),
        canonical_report_input=bad_in,
        canonical_report_input_digest="",
        canonical_report_result=bad_res,
        canonical_report_result_digest="",
    )
    with pytest.raises(ClosedValidationError):
        verify_report_execution(rep_with_bad_cert, **world.verify_kwargs(certifications=(bad_cert,)))


def test_verify_report_execution_rejects_tampered_proofs_provenance_and_unsigned() -> None:
    world = _build_report_world(inconclusive_clicks=False)

    # Tamper effect_proof_locators inside ReportExecution while keeping valid internal digest
    fake_pf = (_loc("smart_ads/effect_proof/v1", "9"),)
    tampered_rep = _resign(
        world.report,
        operational_read_effect_proof_locators=fake_pf,
        operational_read_effect_proof_set_digest="",
    )
    with pytest.raises(ClosedValidationError):
        verify_report_execution(tampered_rep, **world.verify_kwargs())

    # Tamper template provenance or render provenance
    other_prov = _sign(_git_prov("src/smart_ads/analytics/other.py", b"# different"))
    with pytest.raises(ClosedValidationError):
        verify_report_execution(world.report, **world.verify_kwargs(template_provenance=other_prov))
    with pytest.raises(ClosedValidationError):
        verify_report_execution(world.report, **world.verify_kwargs(render_provenance=other_prov))

    # Unsigned report rejects when require_signed=True
    unsigned_rep = replace(world.report, integrity=UNSIGNED)
    with pytest.raises(ClosedValidationError):
        verify_report_execution(unsigned_rep, **world.verify_kwargs(), require_signed=True)


def test_verify_report_execution_rejects_unresolved_history_and_cross_run_generation() -> None:
    world = _build_report_world(inconclusive_clicks=False)
    run_loc = world.report.migration_run_context_locator
    reg_loc = _loc("smart_ads/private_registry_snapshot/v1", "3")
    cur_loc = world.generation_manifests[1].curation_execution_locator
    cat0_loc = _loc("smart_ads/dataset_catalog/v1", "0")
    r_hist = _landing_row("2026-11-05", "3")
    _, d_hist = compute_logical_rows_digest((r_hist,))

    # 1. Fabricated/unresolved restatement_history_generation_locators must reject
    unres_in = replace(world.report.canonical_report_input, restatement_history_generation_locators=(_loc(GenerationManifest.SCHEMA, "8"),))
    unres_rep = _resign(world.report, canonical_report_input=unres_in, canonical_report_input_digest="")
    with pytest.raises(ClosedValidationError, match="missing restatement history"):
        verify_report_execution(unres_rep, **world.verify_kwargs(), require_signed=True)

    # 2. Unlinked history generation outside snapshot partition_heads parent lineage must reject
    unlinked_gm = _sign(GenerationManifest(run_loc, "gen:unlinked", "year=2026/month=11", None, "2026-11-06T03:00:00Z", 1, d_hist, reg_loc, cur_loc, cat0_loc, (world.operational_evidences[0].locator(),), (ParquetObjectLocator("year=2026/month=11", "sha256:" + ("7" * 64), 256),), integrity=UNSIGNED))
    unlinked_in = replace(world.report.canonical_report_input, restatement_history_generation_locators=(unlinked_gm.locator(),))
    unlinked_rep = _resign(world.report, canonical_report_input=unlinked_in, canonical_report_input_digest="")
    with pytest.raises(ClosedValidationError, match="missing restatement history|unreferenced"):
        verify_report_execution(unlinked_rep, **world.verify_kwargs(generation_manifests=(*world.generation_manifests, unlinked_gm), decoded_generation_rows={**world.decoded_generation_rows, unlinked_gm.locator().object_ref: (r_hist,)}), require_signed=True)

    # 3. Snapshot-linked history generation (head_sequence_number=2, parent=hist_gm) passes
    hist_world = _build_report_world(with_replaced_nov_history=True)
    assert verify_report_execution(hist_world.report, **hist_world.verify_kwargs(), require_signed=True) == hist_world.report

    # 4. Unsigned history generation rejects when require_signed=True
    gm1, hist_gm, gm2 = hist_world.generation_manifests
    unsigned_hist = replace(hist_gm, integrity=UNSIGNED)
    with pytest.raises(ClosedValidationError):
        verify_report_execution(hist_world.report, **hist_world.verify_kwargs(generation_manifests=(gm1, unsigned_hist, gm2)), require_signed=True)

    # 5. Cross-run history generation linked into snapshot lineage rejects
    cross_world = _build_report_world(with_replaced_nov_history=True, hist_run_loc=_loc(RUN_CONTEXT_TYPE, "f"))
    with pytest.raises(ClosedValidationError, match="cross-run"):
        verify_report_execution(cross_world.report, **cross_world.verify_kwargs(), require_signed=True)


def test_verify_report_execution_rejects_swapped_per_query_result_schemas() -> None:
    world = _build_report_world(inconclusive_clicks=False)
    run_loc, snap_loc = world.report.migration_run_context_locator, world.snapshot.locator()
    c1, c2 = ResultColumn("v1", "int64", False), ResultColumn("v2", "utf8", False)
    s1 = _sign(AnalysisResultSchema("scalar", (c1,), None, UNSIGNED))
    s2 = _sign(AnalysisResultSchema("scalar", (c2,), None, UNSIGNED))
    q1 = DuckDbQueryDefinition("result:aux_1", "query:aux_1", "SELECT 1 AS v1", s1.locator(), "scalar", (c1,), None, ())
    q2 = DuckDbQueryDefinition("result:aux_2", "query:aux_2", "SELECT 'ok' AS v2", s2.locator(), "scalar", (c2,), None, ())
    queries = (q1, q2, world.replay_bundle.queries[0])
    bundle = _resign(world.replay_bundle, queries=queries)
    # Swap s1 and s2 across aux_1 and aux_2 in AnalysisResult / AnalysisExecution
    p1_swapped = ResultProjection("scalar", s2.locator(), (c2,), ((TaggedScalarCell("utf8", "ok"),),), 1)
    p2_swapped = ResultProjection("scalar", s1.locator(), (c1,), ((TaggedScalarCell("int64", "1"),),), 1)
    r1 = _sign(AnalysisResult(run_loc, snap_loc, bundle.locator(), "result:aux_1", p1_swapped, UNSIGNED))
    r2 = _sign(AnalysisResult(run_loc, snap_loc, bundle.locator(), "result:aux_2", p2_swapped, UNSIGNED))
    r_m = _resign(world.results[0], replay_input_bundle_locator=bundle.locator())
    c_set = CanonicalResultSet.build(bundle.locator(), (CanonicalResultEntry.from_result(r1), CanonicalResultEntry.from_result(r2), CanonicalResultEntry.from_result(r_m)))
    a_exec = _sign(AnalysisExecution(bundle.locator(), c_set, UNSIGNED))
    all_res, all_schemas = (r1, r2, r_m), (s1, s2, world.result_schemas[0])
    ev_b = AnalysisEvidence(a_exec, all_res, all_schemas, snap_loc, world.policy_obj.locator(), True, run_loc)
    findings = tuple(_sign(f) for f in evaluate_findings(world.evaluation_context, ev_b))
    cert = _sign(build_certification_record(world.evaluation_context, ev_b, findings, world.attested_inputs, integrity=UNSIGNED))
    rep_in = replace(world.report.canonical_report_input, canonical_result_digest=c_set.canonical_result_digest, finding_digests=tuple(sorted((f.finding_digest for f in findings), key=lambda s: s.encode("utf-8"))))
    rep_res = render_canonical_report_result(rep_in, findings)
    f_locs = sort_artifact_locators([f.locator() for f in findings], expected_type=Finding.SCHEMA, allow_empty=True)
    swapped_rep = _resign(world.report, analysis_replay_input_bundle_locator=bundle.locator(), analysis_execution_locator=a_exec.locator(), finding_locators=f_locs, certification_record_locators=(cert.locator(),), canonical_report_input=rep_in, canonical_report_input_digest="", canonical_report_result=rep_res, canonical_report_result_digest="")
    with pytest.raises(ClosedValidationError, match="analysis_result_schema_locator"):
        verify_report_execution(swapped_rep, **world.verify_kwargs(replay_bundle=bundle, execution=a_exec, results=all_res, result_schemas=all_schemas, findings=findings, certifications=(cert,)), require_signed=True)


def test_storage_ports_are_runtime_checkable_and_reexported() -> None:
    for sym in ("CellObjectStorePort", "DuckDbEnginePort", "ParquetLandingCodecPort"):
        assert sym in ports_pkg.__all__

    class _DummyStore:
        def put_bytes(self, raw: bytes) -> str: return "cell-object:sha256:" + ("0" * 64)
        def get_bytes(self, object_ref: str, *, expected_size_bytes: int | None = None) -> bytes: return b""
        def has_object(self, object_ref: str) -> bool: return True
        def put_json_artifact(self, schema_id: str, payload: Mapping[str, Any]) -> ArtifactLocator: return _loc(schema_id, "0")
        def get_json_artifact(self, locator: ArtifactLocator) -> dict[str, Any]: return {}

    class _DummyParquet:
        def encode_landing_rows(self, rows: Sequence[AnalyticsLandingRow], *, partition_key: str, compression: Literal["uncompressed", "gzip"] = "uncompressed") -> bytes:
            return b"PAR1PAR1"
        def decode_and_verify_landing_rows(self, raw_bytes: bytes, *, expected_partition_key: str) -> tuple[AnalyticsLandingRow, ...]:
            return ()

    class _DummyDuckDb:
        def execute_replay_queries(self, *, bundle: AnalysisReplayInputBundle, duckdb_binary_bytes: bytes, extension_binaries: Mapping[str, bytes], parquet_objects: Sequence[tuple[ParquetObjectLocator, bytes]], resolved_schemas: Mapping[bytes, AnalysisResultSchema]) -> Mapping[str, ResultProjection]:
            return {}

    assert isinstance(_DummyStore(), CellObjectStorePort)
    assert isinstance(_DummyParquet(), ParquetLandingCodecPort)
    assert isinstance(_DummyDuckDb(), DuckDbEnginePort)
