"""Unit and live-DuckDB tests for `CliDuckDbBinaryAdapter` and `application/duckdb_execution.py`."""
from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import replace
import hashlib
from pathlib import Path
import re
import shutil
import subprocess
from types import MappingProxyType
from typing import Any

import pytest

import smart_ads.adapters as adapters_pkg
import smart_ads.adapters.duckdb as duckdb_adapter_pkg
from smart_ads.adapters.duckdb import CliDuckDbBinaryAdapter
from smart_ads.adapters.storage import InMemoryCellObjectStore, StdlibParquetLandingCodec
from smart_ads.analytics.cells import AnalysisResultSchema, ResultColumn, ResultProjection, TaggedScalarCell, verify_result_projection
from smart_ads.analytics.certification import AttestedCertificationInput, build_certification_record
from smart_ads.analytics.formulas import CertificationInput, DerivedCertificationStatus
from smart_ads.analytics.intelligence import METRIC_WINDOW_COLUMNS, AnalysisEvidence, EvaluationContext, Finding, evaluate_findings
from smart_ads.analytics.policy import AnalysisPolicy, EvaluationScope
from smart_ads.analytics.replay_bundle import (
    AnalysisReplayInputBundle, DuckDbBinaryObjectLocator, DuckDbExtensionBinaryLocator,
    DuckDbExtensionSpec, DuckDbQueryDefinition, DuckDbSessionSetting, DuckDbViewDefinition,
)
from smart_ads.analytics.reporting import REPORT_EXECUTION_SCHEMA, CanonicalReportInput, ReportExecution, render_canonical_report_result, verify_report_execution
from smart_ads.analytics.results import AnalysisExecution, CanonicalResultEntry, CanonicalResultSet
import smart_ads.application as application_pkg
from smart_ads.application.curation_pipeline import GlobalDatasetCatalogService, build_sanitized_candidate_fact_set, materialize_parquet_generation, publish_dataset_snapshot
from smart_ads.application.duckdb_execution import execute_analysis_replay_bundle, execute_certified_report
from smart_ads.contracts.effects import sort_artifact_locators
from smart_ads.contracts.git_provenance import GitArtifactProvenance, compute_git_blob_oid
from smart_ads.contracts.jcs import ArtifactLocator, canonicalize_jcs, jcs_sha256
from smart_ads.contracts.operational_evidence import AlgorithmProvenanceIdentity, OperationalReadEvidence
from smart_ads.contracts.scalars import ClosedValidationError
from smart_ads.contracts.schemas import AnalyticsLandingRow, DateRange
from smart_ads.domain.catalog import (
    ActivePartitionHead, CatalogCasRequestProjection, DatasetCatalog, DatasetCatalogCutReceipt,
    DatasetCatalogGenesisConsumptionRecord, DatasetCatalogGenesisRecord, DatasetSnapshot,
    GenerationManifest, ParquetObjectLocator,
)
from smart_ads.domain.curation import CurationExecution, compute_curation_window
from smart_ads.domain.registry import ExpectedResourceInventory, ExpectedResourceKey
from smart_ads.ports.storage import DuckDbEnginePort
from tests.unit.test_curation_and_catalog import CurationWorld, _CAMP_A, _loc, _signed_p1_for, _unsigned_p1

_METRIC_UKEY = ("metric_semantic_ref", "resource_ref", "window_end_date", "window_start_date")
_METRIC_ORDER = ("resource_ref", "window_start_date", "window_end_date", "metric_semantic_ref")
_DUCKDB_VER_RE = re.compile(r"\Av([0-9]+\.[0-9]+\.[0-9]+)(?:\s|\Z)")
_LIVE_METRICS_WINDOW_SQL = (
    "SELECT resource_ref, DATE '2026-11-08' AS window_start_date, DATE '2026-11-10' AS window_end_date, "
    "metric_semantic_ref, 'provider_observation' AS metric_origin, 'observed' AS presence_status, "
    "'not_applicable' AS calculation_status, NULL::VARCHAR AS unknown_reason, MAX(value_type) AS value_type, "
    "CAST(SUM(CAST(raw_numeric_value AS BIGINT)) AS BIGINT) AS raw_numeric_value, MAX(unit) AS unit, MAX(currency) AS currency "
    "FROM __smart_ads_landing WHERE metric_date BETWEEN '2026-11-08' AND '2026-11-10' "
    "AND metric_semantic_ref IN ('metric:clicks_v1', 'metric:spend_v1') GROUP BY resource_ref, metric_semantic_ref"
)


def _p1_sign_obj(obj: Any) -> Any:
    raw = {k: v for k, v in obj.to_dict().items() if k != "integrity"}
    return type(obj).from_dict({**raw, "integrity": _signed_p1_for(raw).to_dict()}, require_signed=True)


def _store_signed(store: InMemoryCellObjectStore, obj: Any) -> tuple[Any, ArtifactLocator]:
    signed_obj = _p1_sign_obj(obj)
    return signed_obj, store.put_json_artifact(signed_obj.SCHEMA, signed_obj.to_dict())


def _default_window_rows(rows: tuple[AnalyticsLandingRow, ...]) -> tuple[tuple[TaggedScalarCell, ...], ...]:
    nov_rows = [r for r in rows if "2026-11-08" <= r.fact_key.metric_date <= "2026-11-10"]
    out: list[tuple[TaggedScalarCell, ...]] = []
    for metric_ref in ("metric:clicks_v1", "metric:spend_v1"):
        m_rows = [r for r in nov_rows if r.fact_key.metric_semantic_ref == metric_ref]
        if not m_rows:
            continue
        total = sum(int(r.raw_numeric_value) for r in m_rows if r.raw_numeric_value is not None)
        sample = m_rows[0]
        ccy = TaggedScalarCell("null", None) if sample.currency is None else TaggedScalarCell("utf8", sample.currency)
        out.append((
            TaggedScalarCell("opaque_ref", _CAMP_A), TaggedScalarCell("date", "2026-11-08"),
            TaggedScalarCell("date", "2026-11-10"), TaggedScalarCell("opaque_ref", metric_ref),
            TaggedScalarCell("utf8", "provider_observation"), TaggedScalarCell("utf8", "observed"),
            TaggedScalarCell("utf8", "not_applicable"), TaggedScalarCell("null", None),
            TaggedScalarCell("utf8", sample.value_type or "int64_count"), TaggedScalarCell("int64", str(total)),
            TaggedScalarCell("utf8", sample.unit or "count"), ccy,
        ))
    return tuple(out)


class DeterministicInMemoryDuckDbEngine(DuckDbEnginePort):
    """Offline deterministic `DuckDbEnginePort` for hermetic 4-way matrix testing."""

    def __init__(
        self,
        handlers: Mapping[str, Callable[[tuple[AnalyticsLandingRow, ...], DuckDbQueryDefinition], tuple[tuple[TaggedScalarCell, ...], ...]]] | None = None,
    ) -> None:
        self._codec = StdlibParquetLandingCodec()
        self._handlers = dict(handlers or {})
        self.call_count = 0

    def execute_replay_queries(
        self, *, bundle: AnalysisReplayInputBundle, duckdb_binary_bytes: bytes,
        extension_binaries: Mapping[str, bytes], parquet_objects: Sequence[tuple[ParquetObjectLocator, bytes]],
        resolved_schemas: Mapping[bytes, AnalysisResultSchema],
    ) -> Mapping[str, ResultProjection]:
        self.call_count += 1
        if len(duckdb_binary_bytes) != bundle.duckdb_binary_locator.size_bytes or "sha256:" + hashlib.sha256(duckdb_binary_bytes).hexdigest() != bundle.duckdb_binary_locator.binary_sha256:
            raise ClosedValidationError("in-memory engine: duckdb binary mismatch")
        exp_exts = {e.extension_name: e.binary_locator for e in bundle.extensions if e.load_mode == "explicit_local_binary"}
        if set(extension_binaries) != set(exp_exts):
            raise ClosedValidationError("in-memory engine: extension set mismatch")
        for name, loc in exp_exts.items():
            raw_ext = extension_binaries[name]
            if loc is None or len(raw_ext) != loc.size_bytes or "sha256:" + hashlib.sha256(raw_ext).hexdigest() != loc.binary_sha256:
                raise ClosedValidationError("in-memory engine: extension digest/size mismatch")
        if not parquet_objects:
            raise ClosedValidationError("in-memory engine: empty parquet_objects")
        decoded = tuple(r for pq_loc, pq_bytes in parquet_objects for r in self._codec.decode_and_verify_landing_rows(pq_bytes, expected_partition_key=pq_loc.partition_key))
        out: dict[str, ResultProjection] = {}
        for q in bundle.queries:
            schema = resolved_schemas.get(canonicalize_jcs(q.analysis_result_schema_locator.to_dict()))
            if schema is None:
                raise ClosedValidationError(f"missing schema for {q.result_key!r}")
            q.verify_against_schema(schema)
            rows = self._handlers[q.result_key](decoded, q) if q.result_key in self._handlers else _default_window_rows(decoded)
            proj = ResultProjection(q.inline_result_kind, q.analysis_result_schema_locator, q.inline_columns, rows, len(rows))
            verify_result_projection(proj, schema)
            out[q.result_key] = proj
        return MappingProxyType(out)


def _store_git_prov(store: InMemoryCellObjectStore, path: str, raw: bytes) -> tuple[GitArtifactProvenance, ArtifactLocator]:
    prov = GitArtifactProvenance("aiconnai/smart-ads", "b" * 40, path, compute_git_blob_oid(raw), "sha256:" + hashlib.sha256(raw).hexdigest(), "2026-11-11T03:00:00Z", _unsigned_p1())
    return _store_signed(store, prov)


class SignedPipelineWorld:
    """Two-partition signed curation + snapshot + replay bundle + reporting test world."""

    def __init__(self) -> None:
        self.cw = CurationWorld()
        self.store, self.codec, self.run_loc = self.cw.store, self.cw.codec, self.cw.run_loc
        self.epoch0_cat, self.epoch0_loc = _store_signed(self.store, self.cw.epoch0_cat)
        gen_rec = DatasetCatalogGenesisRecord("genesis:signed-001", "cell:ibvi-primary", self.run_loc, self.epoch0_loc, self.epoch0_loc.content_digest, "authority:bootstrap-root", "2026-11-10T00:01:00Z", _unsigned_p1())
        self.genesis_rec, self.genesis_loc = _store_signed(self.store, gen_rec)
        self.svc = GlobalDatasetCatalogService(self.store, self.epoch0_loc, parquet_codec=self.codec, require_signed=True)
        self.ev1, self.ev1_loc, self.gm1, self.gm1_loc, self.snap1, self.snap1_loc, self.cut1_loc = self._cut_genesis("2026-10-31", "p10")
        self.ev2, self.ev2_loc, self.gm2, self.gm2_loc, self.snap2, self.snap2_loc, self.cut2_loc = self._cut_incremental("2026-11-10", "p11", clicks_val="0")
        self.policy, self.policy_loc, self.metrics_schema, self.metrics_schema_loc = self._store_policy_and_schema()
        self.tmpl_prov, self.tmpl_loc = _store_git_prov(self.store, "src/smart_ads/analytics/template.json", b'{"v":1}')
        self.rnd_prov, self.rnd_loc = _store_git_prov(self.store, "src/smart_ads/analytics/reporting.py", b"# render")
        self.render_alg = AlgorithmProvenanceIdentity("algorithm:render-report-v1", "1.0.0", self.rnd_loc, self.rnd_prov.repository, self.rnd_prov.commit_sha, self.rnd_prov.path, self.rnd_prov.git_blob_oid, self.rnd_prov.file_content_sha256, "cpython-3.12", REPORT_EXECUTION_SCHEMA)
        self.inv, self.inv_loc, self.eval_ctx = self._store_inventory_and_context()
        self.duck_bytes, self.ext_bytes = b"\x7fELF-mock-duckdb-1.5.5", b"mock-parquet-extension-1.5.5"
        self.store.put_bytes(self.duck_bytes)
        self.store.put_bytes(self.ext_bytes)
        self.bundle, self.bundle_loc = self.build_signed_bundle()

    def _signed_gen(
        self, *, tag: str, mode: str, date_str: str, ev_loc: ArtifactLocator,
        base_cat_loc: ArtifactLocator, snap_loc: ArtifactLocator | None, cut_loc: ArtifactLocator | None,
    ) -> tuple[GenerationManifest, ArtifactLocator]:
        raw_cs = build_sanitized_candidate_fact_set(migration_run_context_locator=self.run_loc, sanitization_algorithm_identity=self.cw.san_alg, store=self.store, evidence_locators=(ev_loc,), require_signed_inputs=True)
        _, cs_loc = _store_signed(self.store, raw_cs)
        win = compute_curation_window(date_str, "America/Sao_Paulo", "2026a", 1)
        cur = CurationExecution(self.run_loc, f"curation:{tag}", mode, date_str, "America/Sao_Paulo", "2026a", 1, win, cs_loc, self.cw.cur_alg, self.genesis_loc if mode == "genesis" else None, base_cat_loc, snap_loc, cut_loc, (), "2026-11-11T03:05:00Z", _unsigned_p1())  # type: ignore[arg-type]
        _, cur_loc = _store_signed(self.store, cur)
        raw_gm, _ = materialize_parquet_generation(generation_id=f"gen:{tag}", created_at_utc="2026-11-11T03:06:00Z", registry_snapshot_locator=self.cw.reg_loc, curation_locator=cur_loc, store=self.store, parquet_codec=self.codec)
        return _store_signed(self.store, raw_gm)

    def _cut_genesis(self, date_str: str, tag: str) -> tuple[Any, ...]:
        ev, ev_loc, _, _ = self.cw.store_operational_read(date_str, tag=tag, obs_ref=f"observation:{tag}", signed=True)
        gm, gm_loc = self._signed_gen(tag=tag, mode="genesis", date_str=date_str, ev_loc=ev_loc, base_cat_loc=self.epoch0_loc, snap_loc=None, cut_loc=None)
        heads = (ActivePartitionHead(gm.partition_key, 1, gm_loc),)
        cat1 = _p1_sign_obj(DatasetCatalog("catalog:1", "cell:ibvi-primary", 1, "2026-11-11T03:07:00Z", heads, _unsigned_p1()))
        cons = _p1_sign_obj(DatasetCatalogGenesisConsumptionRecord(self.genesis_loc, self.genesis_loc.content_digest, self.epoch0_loc, self.epoch0_loc.content_digest, cat1.locator(), cat1.locator().content_digest, "cut:1", "lin:1", "2026-11-11T03:07:00Z", _unsigned_p1()))
        proj = CatalogCasRequestProjection("add_partition", 0, self.epoch0_loc.content_digest, gm.partition_key, 1, gm_loc)
        rec = _p1_sign_obj(DatasetCatalogCutReceipt("cut:1", "cell:ibvi-primary", self.run_loc, self.epoch0_loc, self.epoch0_loc.content_digest, 0, cat1.locator(), cat1.locator().content_digest, 1, proj, "lin:1", "2026-11-11T03:07:00Z", self.genesis_loc, self.genesis_loc.content_digest, cons.locator(), cons.locator().content_digest, _unsigned_p1()))
        _, _, _, rec_loc = self.svc.commit_partition_cut(cut_id="cut:1", cas_linearization_id="lin:1", committed_at_utc="2026-11-11T03:07:00Z", expected_old_catalog_locator=self.epoch0_loc, expected_old_catalog_epoch=0, generation_manifest_locator=gm_loc, new_catalog_id="catalog:1", genesis_record_locator=self.genesis_loc, consumption_integrity=cons.integrity, catalog_integrity=cat1.integrity, receipt_integrity=rec.integrity)
        raw_snap, _ = publish_dataset_snapshot(snapshot_id="snapshot:1", created_at="2026-11-11T03:08:00Z", cut_receipt_locator=rec_loc, store=self.store)
        snap1, snap1_loc = _store_signed(self.store, raw_snap)
        return ev, ev_loc, gm, gm_loc, snap1, snap1_loc, rec_loc

    def _cut_incremental(self, date_str: str, tag: str, *, clicks_val: str) -> tuple[Any, ...]:
        ev, ev_loc, _, _ = self.cw.store_operational_read(date_str, tag=tag, obs_ref=f"observation:{tag}", clicks_val=clicks_val, signed=True)
        old_loc, old_cat = self.svc.current_head()
        gm, gm_loc = self._signed_gen(tag=tag, mode="incremental", date_str=date_str, ev_loc=ev_loc, base_cat_loc=old_loc, snap_loc=self.snap1_loc, cut_loc=self.cut1_loc)
        heads = tuple(sorted((*old_cat.partition_heads, ActivePartitionHead(gm.partition_key, 1, gm_loc)), key=lambda h: h.partition_key.encode("utf-8")))
        cat2 = _p1_sign_obj(DatasetCatalog("catalog:2", "cell:ibvi-primary", 2, "2026-11-11T03:09:00Z", heads, _unsigned_p1()))
        proj = CatalogCasRequestProjection("add_partition", 1, old_loc.content_digest, gm.partition_key, 1, gm_loc)
        rec = _p1_sign_obj(DatasetCatalogCutReceipt("cut:2", "cell:ibvi-primary", self.run_loc, old_loc, old_loc.content_digest, 1, cat2.locator(), cat2.locator().content_digest, 2, proj, "lin:2", "2026-11-11T03:09:00Z", integrity=_unsigned_p1()))
        _, _, _, rec_loc = self.svc.commit_partition_cut(cut_id="cut:2", cas_linearization_id="lin:2", committed_at_utc="2026-11-11T03:09:00Z", expected_old_catalog_locator=old_loc, expected_old_catalog_epoch=1, generation_manifest_locator=gm_loc, new_catalog_id="catalog:2", catalog_integrity=cat2.integrity, receipt_integrity=rec.integrity)
        raw_snap, _ = publish_dataset_snapshot(snapshot_id="snapshot:2", created_at="2026-11-11T03:10:00Z", cut_receipt_locator=rec_loc, store=self.store)
        snap2, snap2_loc = _store_signed(self.store, raw_snap)
        return ev, ev_loc, gm, gm_loc, snap2, snap2_loc, rec_loc

    def _store_policy_and_schema(self) -> tuple[AnalysisPolicy, ArtifactLocator, AnalysisResultSchema, ArtifactLocator]:
        pol = AnalysisPolicy.from_dict({
            "$schema": "smart_ads/analysis_policy/v1", "policy_id": "policy:waste-v1", "policy_version": "1", "tenant_ref": "tenant:ibvi",
            "applicability_scope": {"resource_scope_ref": "scope:campaigns-active", "resource_level": "campaign", "ad_platform_ref": "meta", "currency": "BRL"},
            "validity": {"valid_from_utc": "2026-01-01T00:00:00.000000Z", "valid_until_utc": "2027-01-01T00:00:00.000000Z"},
            "rules": [{"rule_id": "rule:waste-3d", "rule_type": "waste", "window_days": 3, "spend_metric_ref": "metric:spend_v1", "outcome_metric_ref": "metric:clicks_v1", "min_spend_minor": "1000", "max_outcome_count": "0"}],
            "integrity": _unsigned_p1().to_dict(),
        })
        signed_pol, pol_loc = _store_signed(self.store, pol)
        cols = tuple(ResultColumn(n, t, nl) for n, t, nl in METRIC_WINDOW_COLUMNS)
        signed_schema, schema_loc = _store_signed(self.store, AnalysisResultSchema("relation", cols, _METRIC_UKEY, _unsigned_p1()))
        return signed_pol, pol_loc, signed_schema, schema_loc

    def _store_inventory_and_context(self) -> tuple[ExpectedResourceInventory, ArtifactLocator, EvaluationContext]:
        inv = ExpectedResourceInventory("inventory:eval-001", self.cw.reg_loc, self.cw.reg_loc.content_digest, "tenant:ibvi", "binding:meta-primary", "account:ibvi-01", "scope:campaigns-active", DateRange("2026-11-01", "2026-11-10", True), (ExpectedResourceKey("binding:meta-primary", "account:ibvi-01", _CAMP_A, "campaign", "2026-11-10"),), _unsigned_p1())
        signed_inv, inv_loc = _store_signed(self.store, inv)
        scope = EvaluationScope("tenant:ibvi", "scope:campaigns-active", "campaign", "meta", "BRL")
        return signed_inv, inv_loc, EvaluationContext(self.policy, scope, "2026-11-11T03:15:00.000000Z", "2026-11-10", 7, "2026-11-10", signed_inv, "result:metrics", ())

    def build_signed_bundle(
        self, *, duckdb_bytes: bytes | None = None, engine_version: str = "1.5.5",
        with_local_ext: bool = True, metrics_sql: str | None = None,
        extra_queries: Sequence[DuckDbQueryDefinition] = (), views: Sequence[DuckDbViewDefinition] = (),
    ) -> tuple[AnalysisReplayInputBundle, ArtifactLocator]:
        db_loc = DuckDbBinaryObjectLocator.for_binary_bytes(self.duck_bytes if duckdb_bytes is None else duckdb_bytes)
        exts = (DuckDbExtensionSpec("parquet", "1.5.5", "explicit_local_binary", DuckDbExtensionBinaryLocator.for_binary_bytes(self.ext_bytes)),) if with_local_ext else ()
        cols = tuple(ResultColumn(n, t, nl) for n, t, nl in METRIC_WINDOW_COLUMNS)
        q_m = DuckDbQueryDefinition("result:metrics", "query:metrics", metrics_sql or _LIVE_METRICS_WINDOW_SQL, self.metrics_schema_loc, "relation", cols, _METRIC_UKEY, _METRIC_ORDER)
        all_q = tuple(sorted((q_m, *extra_queries), key=lambda q: q.result_key.encode("utf-8")))
        settings = (DuckDbSessionSetting("preserve_insertion_order", TaggedScalarCell("boolean", True)), DuckDbSessionSetting("threads", TaggedScalarCell("int64", "1")))
        raw = AnalysisReplayInputBundle("bundle:main-001", self.run_loc, self.snap2_loc, engine_version, db_loc, exts, settings, tuple(sorted(views, key=lambda v: v.view_name.encode("utf-8"))), all_q, self.policy_loc, (self.tmpl_loc,), _unsigned_p1())
        return _store_signed(self.store, raw)


@pytest.fixture
def pipeline_world() -> SignedPipelineWorld:
    return SignedPipelineWorld()


def _discover_duckdb_binary() -> tuple[bytes, str] | None:
    cand = Path("/opt/homebrew/bin/duckdb")
    if not cand.is_file():
        which_path = shutil.which("duckdb")
        if which_path is None:
            return None
        cand = Path(which_path)
    proc = subprocess.run([str(cand), "--version"], stdin=subprocess.DEVNULL, capture_output=True, text=True, check=False)
    m = _DUCKDB_VER_RE.match(proc.stdout.strip())
    return None if (proc.returncode != 0 or m is None) else (cand.read_bytes(), m.group(1))


class _LiveDuckDbWorld:
    """Helper wrapping real DuckDB CLI binary bytes and `CliDuckDbBinaryAdapter`."""

    def __init__(self, binary_bytes: bytes, version: str) -> None:
        self.pw = SignedPipelineWorld()
        self.binary_bytes, self.version = binary_bytes, version
        self.pw.store.put_bytes(binary_bytes)
        self.adapter = CliDuckDbBinaryAdapter()
        self.pq_objects = tuple((pq, self.pw.store.get_bytes(pq.object_ref, expected_size_bytes=pq.size_bytes)) for gm in (self.pw.gm1, self.pw.gm2) for pq in gm.parquet_object_locators)

    def run_single_query(
        self, result_key: str, kind: str, cols: tuple[ResultColumn, ...], sql: str,
        *, unique_key: tuple[str, ...] | None = None, order_by: tuple[str, ...] = (),
        views: Sequence[DuckDbViewDefinition] = (), engine_version: str | None = None,
    ) -> Mapping[str, ResultProjection]:
        schema, s_loc = _store_signed(self.pw.store, AnalysisResultSchema(kind, cols, unique_key, _unsigned_p1()))
        q = DuckDbQueryDefinition(result_key, f"query:{result_key}", sql, s_loc, kind, cols, unique_key, order_by)  # type: ignore[arg-type]
        db_loc = DuckDbBinaryObjectLocator.for_binary_bytes(self.binary_bytes)
        bundle = AnalysisReplayInputBundle("bundle:live", self.pw.run_loc, self.pw.snap2_loc, engine_version or self.version, db_loc, (), (DuckDbSessionSetting("threads", TaggedScalarCell("int64", "1")),), tuple(sorted(views, key=lambda v: v.view_name.encode("utf-8"))), (q,), self.pw.policy_loc, (self.pw.tmpl_loc,), _unsigned_p1())
        return self.adapter.execute_replay_queries(bundle=bundle, duckdb_binary_bytes=self.binary_bytes, extension_binaries={}, parquet_objects=self.pq_objects, resolved_schemas={canonicalize_jcs(s_loc.to_dict()): schema})

    def run_extreme_types_bundle(self) -> Mapping[str, ResultProjection]:
        cols = (
            ResultColumn("max_i64", "int64", False), ResultColumn("min_i64", "int64", False),
            ResultColumn("huge_sum", "int64", False), ResultColumn("dec18", "decimal6", False),
            ResultColumn("dec6_sub1", "decimal6", False), ResultColumn("ts_utc", "timestamp", False),
            ResultColumn("tstz_utc", "timestamp", False), ResultColumn("day_val", "date", False),
            ResultColumn("flag", "boolean", False), ResultColumn("opt_null", "utf8", True),
        )
        sql = (
            "SELECT 9223372036854775807::BIGINT AS max_i64, (-9223372036854775808)::BIGINT AS min_i64, "
            "SUM(5000::BIGINT) AS huge_sum, (-12.345678)::DECIMAL(18,6) AS dec18, 0.123456::DECIMAL(6,6) AS dec6_sub1, "
            "TIMESTAMP '2026-11-10 12:30:45.123456' AS ts_utc, TIMESTAMPTZ '2026-11-10 09:30:45.123456-03' AS tstz_utc, "
            "DATE '2026-11-10' AS day_val, TRUE AS flag, NULL::VARCHAR AS opt_null"
        )
        return self.run_single_query("result:extremes", "relation", cols, sql, unique_key=("max_i64",), order_by=("max_i64",))

    def run_zero_row_double_query_bundle(self) -> Mapping[str, ResultProjection]:
        return self.run_single_query("result:zero_double", "relation", (ResultColumn("bad_float", "decimal6", False),), "SELECT 1.5::DOUBLE AS bad_float WHERE 1 = 0", order_by=("bad_float",))


@pytest.fixture(scope="module")
def live_duckdb_world() -> _LiveDuckDbWorld | None:
    found = _discover_duckdb_binary()
    return None if found is None else _LiveDuckDbWorld(found[0], found[1])


def test_public_exports_and_adapter_boundary_isolation() -> None:
    assert duckdb_adapter_pkg.__all__ == ["CliDuckDbBinaryAdapter"]
    assert "duckdb" not in adapters_pkg.__all__ and not hasattr(adapters_pkg, "CliDuckDbBinaryAdapter")
    assert "execute_analysis_replay_bundle" in application_pkg.__all__
    assert "execute_certified_report" in application_pkg.__all__
    assert isinstance(CliDuckDbBinaryAdapter(), DuckDbEnginePort)


def test_pre_duckdb_rejections_never_invoke_engine(pipeline_world: SignedPipelineWorld) -> None:
    pw = pipeline_world
    engine = DeterministicInMemoryDuckDbEngine()
    missing_bin = DuckDbBinaryObjectLocator.for_binary_bytes(b"unregistered-duckdb-binary")
    _, b_miss_bin = _store_signed(pw.store, replace(pw.bundle, duckdb_binary_locator=missing_bin, integrity=_unsigned_p1()))
    ghost_ext = DuckDbExtensionSpec("json", "1.5.5", "explicit_local_binary", DuckDbExtensionBinaryLocator.for_binary_bytes(b"ghost-ext"))
    _, b_miss_ext = _store_signed(pw.store, replace(pw.bundle, extensions=(ghost_ext,), integrity=_unsigned_p1()))
    unsig_pol_loc = pw.store.put_json_artifact(AnalysisPolicy.SCHEMA, replace(pw.policy, integrity=_unsigned_p1()).to_dict())
    _, b_unsig_pol = _store_signed(pw.store, replace(pw.bundle, analysis_policy_locator=unsig_pol_loc, integrity=_unsigned_p1()))
    _, b_miss_pol = _store_signed(pw.store, replace(pw.bundle, analysis_policy_locator=_loc(AnalysisPolicy.SCHEMA, "e"), integrity=_unsigned_p1()))
    _, b_miss_bi = _store_signed(pw.store, replace(pw.bundle, build_input_locators=(_loc(GitArtifactProvenance.SCHEMA, "d"),), integrity=_unsigned_p1()))
    _, b_miss_snap = _store_signed(pw.store, replace(pw.bundle, dataset_snapshot_locator=_loc(DatasetSnapshot.SCHEMA, "c"), integrity=_unsigned_p1()))
    tampered_snap = _p1_sign_obj(replace(pw.snap2, partition_heads=(pw.snap2.partition_heads[0],), snapshot_digest="", integrity=_unsigned_p1()))
    tampered_snap_loc = pw.store.put_json_artifact(DatasetSnapshot.SCHEMA, tampered_snap.to_dict())
    _, b_bad_snap = _store_signed(pw.store, replace(pw.bundle, dataset_snapshot_locator=tampered_snap_loc, integrity=_unsigned_p1()))
    for bad_loc in (b_miss_bin, b_miss_ext, b_unsig_pol, b_miss_pol, b_miss_bi, b_miss_snap, b_bad_snap):
        with pytest.raises(ClosedValidationError):
            execute_analysis_replay_bundle(bundle_locator=bad_loc, store=pw.store, parquet_codec=pw.codec, duckdb_engine=engine, require_signed_inputs=True)
    assert engine.call_count == 0


def test_offline_bundle_locator_byte_equality(pipeline_world: SignedPipelineWorld) -> None:
    pw = pipeline_world
    engine = DeterministicInMemoryDuckDbEngine()
    u_exec, _, u_res_pairs = execute_analysis_replay_bundle(bundle_locator=pw.bundle_loc, store=pw.store, parquet_codec=pw.codec, duckdb_engine=engine, require_signed_inputs=True)
    assert len(u_res_pairs) == 1
    expected_bytes = canonicalize_jcs(pw.bundle_loc.to_dict())
    assert canonicalize_jcs(u_exec.analysis_replay_input_bundle_locator.to_dict()) == expected_bytes
    assert canonicalize_jcs(u_exec.canonical_result_set.analysis_replay_input_bundle_locator.to_dict()) == expected_bytes
    assert canonicalize_jcs(u_res_pairs[0][0].replay_input_bundle_locator.to_dict()) == expected_bytes


def test_offline_signed_certified_report_and_operational_proof_propagation(pipeline_world: SignedPipelineWorld) -> None:
    pw = pipeline_world
    engine = DeterministicInMemoryDuckDbEngine()
    _, _, u_res_pairs = execute_analysis_replay_bundle(bundle_locator=pw.bundle_loc, store=pw.store, parquet_codec=pw.codec, duckdb_engine=engine, require_signed_inputs=True)
    signed_res = _p1_sign_obj(u_res_pairs[0][0])
    signed_cset = CanonicalResultSet.build(pw.bundle_loc, (CanonicalResultEntry.from_result(signed_res),))
    exec_sig = _p1_sign_obj(AnalysisExecution(pw.bundle_loc, signed_cset, _unsigned_p1())).integrity
    s_exec, s_exec_loc, s_res_pairs = execute_analysis_replay_bundle(
        bundle_locator=pw.bundle_loc, store=pw.store, parquet_codec=pw.codec, duckdb_engine=engine,
        result_integrities={"result:metrics": signed_res.integrity}, execution_integrity=exec_sig, require_signed_inputs=True,  # type: ignore[dict-item]
    )
    attested = (AttestedCertificationInput(CertificationInput(DerivedCertificationStatus.VERIFIED, "phase1_7b_base"), True),)
    ev_b = AnalysisEvidence(s_exec, (s_res_pairs[0][0],), (pw.metrics_schema,), pw.snap2_loc, pw.policy_loc, True, pw.run_loc)
    signed_findings = tuple(_p1_sign_obj(f) for f in evaluate_findings(pw.eval_ctx, ev_b))
    signed_cert = _p1_sign_obj(build_certification_record(pw.eval_ctx, ev_b, signed_findings, attested, integrity=_unsigned_p1()))
    exp_ev_locs = sort_artifact_locators([pw.ev1_loc, pw.ev2_loc], expected_type=OperationalReadEvidence.SCHEMA)
    exp_pf_locs = sort_artifact_locators([pw.ev1.effect_proof_locator, pw.ev2.effect_proof_locator], expected_type="smart_ads/effect_proof/v1")
    rep_in = CanonicalReportInput(pw.snap2.snapshot_digest, s_exec.canonical_result_set.canonical_result_digest, pw.eval_ctx.evaluation_instant_utc, pw.eval_ctx.window_end_date, "result:metrics", pw.inv_loc, pw.gm2.curation_execution_locator, (), attested, tuple(sorted((f.finding_digest for f in signed_findings), key=lambda s: s.encode("utf-8"))), signed_cert.derived_certification_status, signed_cert.mutation_recommendations_blocked)
    rep_res = render_canonical_report_result(rep_in, signed_findings)
    f_locs = sort_artifact_locators([f.locator() for f in signed_findings], expected_type=Finding.SCHEMA, allow_empty=True)
    rep_sig = _p1_sign_obj(ReportExecution("report:r-signed", pw.run_loc, pw.snap2_loc, pw.bundle_loc, s_exec_loc, pw.policy_loc, f_locs, (signed_cert.locator(),), exp_ev_locs, exp_pf_locs, pw.tmpl_loc, pw.render_alg, rep_in, rep_res, "2026-11-11T03:20:00Z", integrity=_unsigned_p1())).integrity
    rep, rep_loc, cert_out, cert_loc, f_pairs = execute_certified_report(
        report_id="report:r-signed", executed_at_utc="2026-11-11T03:20:00Z", bundle_locator=pw.bundle_loc,
        execution_locator=s_exec_loc, evaluation_context=pw.eval_ctx, expected_resource_inventory_locator=pw.inv_loc,
        curation_execution_locator=pw.gm2.curation_execution_locator, restatement_history_generation_locators=(),
        attested_certification_inputs=attested, report_template_provenance_locator=pw.tmpl_loc,
        render_algorithm_identity=pw.render_alg, store=pw.store, parquet_codec=pw.codec,
        finding_integrities=tuple(f.integrity for f in signed_findings), certification_integrity=signed_cert.integrity,  # type: ignore[arg-type]
        report_integrity=rep_sig, require_signed_inputs=True,
    )
    assert rep.locator() == rep_loc and cert_out.locator() == cert_loc and len(f_pairs) == 1
    assert rep.operational_read_evidence_locators == exp_ev_locs and rep.operational_read_effect_proof_locators == exp_pf_locs
    assert rep.operational_read_effect_proof_set_digest == jcs_sha256([loc.to_dict() for loc in exp_pf_locs])
    assert verify_report_execution(
        rep, snapshot=pw.snap2, generation_manifests=(pw.gm1, pw.gm2), operational_evidences=(pw.ev1, pw.ev2),
        replay_bundle=pw.bundle, execution=s_exec, results=(s_res_pairs[0][0],), result_schemas=(pw.metrics_schema,),
        policy_obj=pw.policy, findings=tuple(f for f, _ in f_pairs), certifications=(cert_out,),
        evaluation_context=pw.eval_ctx, attested_inputs=attested, template_provenance=pw.tmpl_prov,
        render_provenance=pw.rnd_prov, require_signed=True,
    ) == rep


def test_execute_certified_report_rejects_bad_render_schema_and_unlinked_curation(pipeline_world: SignedPipelineWorld) -> None:
    pw = pipeline_world
    _, u_exec_loc, _ = execute_analysis_replay_bundle(bundle_locator=pw.bundle_loc, store=pw.store, parquet_codec=pw.codec, duckdb_engine=DeterministicInMemoryDuckDbEngine())
    attested = (AttestedCertificationInput(CertificationInput(DerivedCertificationStatus.VERIFIED, "phase1_7b_base"), True),)
    base_kw: dict[str, Any] = {
        "report_id": "report:r-neg", "executed_at_utc": "2026-11-11T03:20:00Z", "bundle_locator": pw.bundle_loc,
        "execution_locator": u_exec_loc, "evaluation_context": pw.eval_ctx, "expected_resource_inventory_locator": pw.inv_loc,
        "curation_execution_locator": pw.gm2.curation_execution_locator, "restatement_history_generation_locators": (),
        "attested_certification_inputs": attested, "report_template_provenance_locator": pw.tmpl_loc,
        "render_algorithm_identity": pw.render_alg, "store": pw.store, "parquet_codec": pw.codec,
    }
    for overrides in (
        {"render_algorithm_identity": replace(pw.render_alg, schema_id=CurationExecution.SCHEMA)},
        {"render_algorithm_identity": replace(pw.render_alg, file_content_sha256="sha256:" + ("f" * 64))},
        {"curation_execution_locator": _loc(CurationExecution.SCHEMA, "9")},
        {"expected_resource_inventory_locator": _loc(ExpectedResourceInventory.SCHEMA, "9")},
        {"require_signed_inputs": True},
    ):
        with pytest.raises(ClosedValidationError):
            execute_certified_report(**{**base_kw, **overrides})


def test_live_cli_duckdb_adapter_handles_int64_extremes_and_rejects_zero_row_float(
    live_duckdb_world: Any,
) -> None:
    if live_duckdb_world is None:
        return
    projections = live_duckdb_world.run_extreme_types_bundle()
    row = projections["result:extremes"].rows[0]
    assert row[0] == TaggedScalarCell("int64", "9223372036854775807")
    assert row[1] == TaggedScalarCell("int64", "-9223372036854775808")
    assert row[2] == TaggedScalarCell("int64", "5000")
    assert row[3] == TaggedScalarCell("decimal6", "-12.345678")
    assert row[4] == TaggedScalarCell("decimal6", "0.123456")
    assert row[5] == TaggedScalarCell("timestamp", "2026-11-10T12:30:45.123456Z")
    assert row[6] == TaggedScalarCell("timestamp", "2026-11-10T12:30:45.123456Z")
    assert row[7] == TaggedScalarCell("date", "2026-11-10")
    assert row[8] == TaggedScalarCell("boolean", True)
    assert row[9] == TaggedScalarCell("null", None)
    with pytest.raises(ClosedValidationError):
        live_duckdb_world.run_zero_row_double_query_bundle()


def test_live_cli_duckdb_security_lockdown_views_and_full_pipeline(live_duckdb_world: _LiveDuckDbWorld | None) -> None:
    if live_duckdb_world is None:
        return
    lw = live_duckdb_world
    for cols, sql, ver in (
        ((ResultColumn("d2", "decimal6", False),), "SELECT 1.25::DECIMAL(18,2) AS d2 WHERE 1 = 0", None),
        ((ResultColumn("ovf", "int64", False),), "SELECT SUM(x) AS ovf FROM (SELECT 9223372036854775807::BIGINT AS x UNION ALL SELECT 1::BIGINT AS x)", None),
        ((ResultColumn("leak", "utf8", True),), "SELECT CAST(COUNT(*) AS VARCHAR) AS leak FROM read_parquet('/etc/hosts')", None),
        ((ResultColumn("leak", "utf8", True),), "SELECT CAST(COUNT(*) AS VARCHAR) AS leak FROM read_csv_auto('/etc/hosts')", None),
        ((ResultColumn("ok", "int64", False),), "SELECT 1::BIGINT AS ok", "0.0.1"),
    ):
        with pytest.raises(ClosedValidationError):
            lw.run_single_query("result:bad", "relation", cols, sql, order_by=(cols[0].name,), engine_version=ver)

    views = (
        DuckDbViewDefinition("v_nov", "SELECT * FROM __smart_ads_landing WHERE metric_date BETWEEN '2026-11-08' AND '2026-11-10'", ()),
        DuckDbViewDefinition("v_base", "SELECT * FROM v_nov WHERE metric_semantic_ref IN ('metric:clicks_v1', 'metric:spend_v1')", ("v_nov",)),
    )
    view_sql = _LIVE_METRICS_WINDOW_SQL.replace("FROM __smart_ads_landing WHERE metric_date BETWEEN '2026-11-08' AND '2026-11-10' AND metric_semantic_ref IN ('metric:clicks_v1', 'metric:spend_v1')", "FROM v_base")
    bundle, bundle_loc = lw.pw.build_signed_bundle(duckdb_bytes=lw.binary_bytes, engine_version=lw.version, with_local_ext=False, metrics_sql=view_sql, views=views)
    exec_obj, exec_loc, res_pairs = execute_analysis_replay_bundle(bundle_locator=bundle_loc, store=lw.pw.store, parquet_codec=lw.pw.codec, duckdb_engine=lw.adapter, require_signed_inputs=True)
    attested = (AttestedCertificationInput(CertificationInput(DerivedCertificationStatus.VERIFIED, "phase1_7b_base"), True),)
    rep, _, cert_rec, _, f_pairs = execute_certified_report(
        report_id="report:live-001", executed_at_utc="2026-11-11T03:25:00Z", bundle_locator=bundle_loc,
        execution_locator=exec_loc, evaluation_context=lw.pw.eval_ctx, expected_resource_inventory_locator=lw.pw.inv_loc,
        curation_execution_locator=lw.pw.gm2.curation_execution_locator, restatement_history_generation_locators=(),
        attested_certification_inputs=attested, report_template_provenance_locator=lw.pw.tmpl_loc,
        render_algorithm_identity=lw.pw.render_alg, store=lw.pw.store, parquet_codec=lw.pw.codec, require_signed_inputs=False,
    )
    assert rep.canonical_report_result.detected_finding_count == 1
    assert verify_report_execution(
        rep, snapshot=lw.pw.snap2, generation_manifests=(lw.pw.gm1, lw.pw.gm2), operational_evidences=(lw.pw.ev1, lw.pw.ev2),
        replay_bundle=bundle, execution=exec_obj, results=(res_pairs[0][0],), result_schemas=(lw.pw.metrics_schema,),
        policy_obj=lw.pw.policy, findings=tuple(f for f, _ in f_pairs), certifications=(cert_rec,),
        evaluation_context=lw.pw.eval_ctx, attested_inputs=attested, template_provenance=lw.pw.tmpl_prov,
        render_provenance=lw.pw.rnd_prov, require_signed=False,
    ) == rep


def test_cli_adapter_direct_prechecks_and_malformed_engine_output(pipeline_world: SignedPipelineWorld) -> None:
    pw = pipeline_world
    adapter = CliDuckDbBinaryAdapter()
    pq_loc = pw.gm2.parquet_object_locators[0]
    pq_bytes = pw.store.get_bytes(pq_loc.object_ref, expected_size_bytes=pq_loc.size_bytes)
    schemas = {canonicalize_jcs(pw.metrics_schema_loc.to_dict()): pw.metrics_schema}
    for bad_kw in (
        {"duckdb_binary_bytes": b"tampered", "extension_binaries": {"parquet": pw.ext_bytes}, "parquet_objects": ((pq_loc, pq_bytes),), "resolved_schemas": schemas},
        {"duckdb_binary_bytes": pw.duck_bytes, "extension_binaries": {}, "parquet_objects": ((pq_loc, pq_bytes),), "resolved_schemas": schemas},
        {"duckdb_binary_bytes": pw.duck_bytes, "extension_binaries": {"parquet": pw.ext_bytes, "extra": b"x"}, "parquet_objects": ((pq_loc, pq_bytes),), "resolved_schemas": schemas},
        {"duckdb_binary_bytes": pw.duck_bytes, "extension_binaries": {"parquet": b"bad-ext"}, "parquet_objects": ((pq_loc, pq_bytes),), "resolved_schemas": schemas},
        {"duckdb_binary_bytes": pw.duck_bytes, "extension_binaries": {"parquet": pw.ext_bytes}, "parquet_objects": (), "resolved_schemas": schemas},
        {"duckdb_binary_bytes": pw.duck_bytes, "extension_binaries": {"parquet": pw.ext_bytes}, "parquet_objects": ((pq_loc, b"bad-pq"),), "resolved_schemas": schemas},
        {"duckdb_binary_bytes": pw.duck_bytes, "extension_binaries": {"parquet": pw.ext_bytes}, "parquet_objects": ((pq_loc, pq_bytes),), "resolved_schemas": {}},
    ):
        with pytest.raises(ClosedValidationError):
            adapter.execute_replay_queries(bundle=pw.bundle, **bad_kw)  # type: ignore[arg-type]

    class _EmptyEngine:
        def execute_replay_queries(self, **_: Any) -> Mapping[str, ResultProjection]:
            return {}

    with pytest.raises(ClosedValidationError):
        execute_analysis_replay_bundle(bundle_locator=pw.bundle_loc, store=pw.store, parquet_codec=pw.codec, duckdb_engine=_EmptyEngine())  # type: ignore[arg-type]


def test_restatement_history_generation_and_locked_directory_settings(
    pipeline_world: SignedPipelineWorld, live_duckdb_world: _LiveDuckDbWorld | None
) -> None:
    pw = pipeline_world
    _, exec_loc, _ = execute_analysis_replay_bundle(
        bundle_locator=pw.bundle_loc, store=pw.store, parquet_codec=pw.codec, duckdb_engine=DeterministicInMemoryDuckDbEngine()
    )
    attested = (AttestedCertificationInput(CertificationInput(DerivedCertificationStatus.VERIFIED, "phase1_7b_base"), True),)
    # gm1 passed in restatement_history_generation_locators + non-existent history generation rejected
    rep, _, _, _, _ = execute_certified_report(
        report_id="report:r-hist", executed_at_utc="2026-11-11T03:30:00Z", bundle_locator=pw.bundle_loc,
        execution_locator=exec_loc, evaluation_context=pw.eval_ctx, expected_resource_inventory_locator=pw.inv_loc,
        curation_execution_locator=pw.gm2.curation_execution_locator, restatement_history_generation_locators=(pw.gm1_loc,),
        attested_certification_inputs=attested, report_template_provenance_locator=pw.tmpl_loc,
        render_algorithm_identity=pw.render_alg, store=pw.store, parquet_codec=pw.codec,
    )
    assert rep.canonical_report_input.restatement_history_generation_locators == (pw.gm1_loc,)
    with pytest.raises(ClosedValidationError):
        execute_certified_report(
            report_id="report:r-bad-hist", executed_at_utc="2026-11-11T03:31:00Z", bundle_locator=pw.bundle_loc,
            execution_locator=exec_loc, evaluation_context=pw.eval_ctx, expected_resource_inventory_locator=pw.inv_loc,
            curation_execution_locator=pw.gm2.curation_execution_locator, restatement_history_generation_locators=(_loc(GenerationManifest.SCHEMA, "7"),),
            attested_certification_inputs=attested, report_template_provenance_locator=pw.tmpl_loc,
            render_algorithm_identity=pw.render_alg, store=pw.store, parquet_codec=pw.codec,
        )
    if live_duckdb_world is None:
        return
    # Trailing '--' SQL comments inside view and query must not break subquery wrapping
    v_comment = DuckDbViewDefinition("v_cmt", "SELECT 42::BIGINT AS k -- trailing view comment", ())
    proj = live_duckdb_world.run_single_query(
        "result:cmt", "scalar", (ResultColumn("k", "int64", False),), "SELECT k FROM v_cmt -- trailing query comment", views=(v_comment,)
    )
    assert proj["result:cmt"].rows == ((TaggedScalarCell("int64", "42"),),)
    # Path-bearing DuckDB session settings (e.g. temp_directory) must fail closed
    bad_bundle = replace(
        pw.bundle, duckdb_engine_version=live_duckdb_world.version,
        duckdb_binary_locator=DuckDbBinaryObjectLocator.for_binary_bytes(live_duckdb_world.binary_bytes),
        extensions=(), session_settings=(DuckDbSessionSetting("temp_directory", TaggedScalarCell("utf8", "/tmp")),), integrity=_unsigned_p1(),
    )
    with pytest.raises(ClosedValidationError):
        live_duckdb_world.adapter.execute_replay_queries(
            bundle=bad_bundle, duckdb_binary_bytes=live_duckdb_world.binary_bytes, extension_binaries={},
            parquet_objects=live_duckdb_world.pq_objects, resolved_schemas={canonicalize_jcs(pw.metrics_schema_loc.to_dict()): pw.metrics_schema},
        )

