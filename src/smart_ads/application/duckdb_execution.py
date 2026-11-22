"""Pure rebuildable DuckDB replay execution and certified report orchestration (ADR-0001 §§6.4, 11.1)."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
import hashlib
from types import MappingProxyType

from smart_ads.analytics.cells import AnalysisResultSchema, ResultProjection, verify_result_projection
from smart_ads.analytics.certification import AnalyticalCertificationRecord, AttestedCertificationInput, build_certification_record
from smart_ads.analytics.intelligence import AnalysisEvidence, EvaluationContext, Finding, evaluate_findings
from smart_ads.analytics.policy import AnalysisPolicy
from smart_ads.analytics.replay_bundle import AnalysisReplayInputBundle
from smart_ads.analytics.reporting import CanonicalReportInput, ReportExecution, render_canonical_report_result, verify_report_execution
from smart_ads.analytics.results import AnalysisExecution, AnalysisResult, CanonicalResultEntry, CanonicalResultSet, verify_analysis_execution
from smart_ads.application.curation_pipeline import (
    _load_p1, _require_parquet_codec, _require_store_and_bool, verify_algorithm_provenance_identity,
    verify_curation_execution, verify_dataset_snapshot, verify_generation_manifest, verify_operational_read_evidence,
)
from smart_ads.contracts.effects import EffectProof, _strict_id, _typed_locator, sort_artifact_locators
from smart_ads.contracts.git_provenance import GitArtifactProvenance
from smart_ads.contracts.jcs import ADR_P1_DOMAIN_PREFIXES, ArtifactLocator, P1Integrity, canonicalize_jcs, p1_content_digest
from smart_ads.contracts.operational_evidence import AlgorithmProvenanceIdentity, OperationalReadEvidence
from smart_ads.contracts.scalars import ClosedValidationError, validate_envelope_timestamp_utc
from smart_ads.domain.catalog import DatasetSnapshot, GenerationManifest, ParquetObjectLocator
from smart_ads.domain.curation import CurationExecution
from smart_ads.domain.registry import ExpectedResourceInventory
from smart_ads.ports.storage import CellObjectStorePort, DuckDbEnginePort, ParquetLandingCodecPort


def _validate_optional_p1_integrity(value: object, *, label: str) -> P1Integrity | None:
    if value is None:
        return None
    if type(value) is not P1Integrity:
        raise ClosedValidationError(f"{label}: expected P1Integrity or None, got {type(value).__name__}")
    fresh = P1Integrity.from_dict(value.to_dict(), require_signed=value.is_signed)
    if (value.content_digest is None) != (value.signature_base64 is None) or value != fresh:
        raise ClosedValidationError(f"{label}: malformed or partial P1Integrity")
    return fresh


def _validate_result_integrities(
    result_integrities: Mapping[str, P1Integrity] | None, expected_keys: set[str]
) -> dict[str, P1Integrity] | None:
    if result_integrities is None:
        return None
    if not isinstance(result_integrities, Mapping):
        raise ClosedValidationError("result_integrities: expected Mapping[str, P1Integrity] or None")
    if any(type(k) is not str for k in result_integrities) or set(result_integrities) != expected_keys:
        raise ClosedValidationError("result_integrities: keys must match bundle query result_keys")
    out: dict[str, P1Integrity] = {}
    for key in sorted(expected_keys):
        checked = _validate_optional_p1_integrity(result_integrities[key], label=f"result_integrities[{key!r}]")
        if checked is None:
            raise ClosedValidationError(f"result_integrities[{key!r}]: expected P1Integrity")
        out[key] = checked
    return out


def _validate_finding_integrities(
    finding_integrities: Sequence[P1Integrity] | None,
) -> tuple[P1Integrity, ...] | None:
    if finding_integrities is None:
        return None
    if isinstance(finding_integrities, (str, bytes)) or not isinstance(finding_integrities, Sequence):
        raise ClosedValidationError("finding_integrities: expected Sequence[P1Integrity] or None")
    checked: list[P1Integrity] = []
    for idx, item in enumerate(finding_integrities):
        val = _validate_optional_p1_integrity(item, label=f"finding_integrities[{idx}]")
        if val is None:
            raise ClosedValidationError(f"finding_integrities[{idx}]: expected P1Integrity")
        checked.append(val)
    return tuple(checked)


def _verify_build_input_locators(
    bundle: AnalysisReplayInputBundle, *, store: CellObjectStorePort, require_signed: bool
) -> None:
    for idx, bi_loc in enumerate(bundle.build_input_locators):
        raw_doc = store.get_json_artifact(bi_loc)
        if ArtifactLocator.for_canonical_bytes(bi_loc.artifact_type, canonicalize_jcs(raw_doc)) != bi_loc:
            raise ClosedValidationError(f"build_input_locators[{idx}]: canonical digest mismatch")
        if bi_loc.artifact_type == GitArtifactProvenance.SCHEMA:
            GitArtifactProvenance.from_dict(raw_doc, require_signed=require_signed)
        elif bi_loc.artifact_type in ADR_P1_DOMAIN_PREFIXES and (require_signed or "integrity" in raw_doc):
            if "integrity" not in raw_doc:
                raise ClosedValidationError(f"build_input_locators[{idx}]: unsigned P1 build input")
            bi_int = P1Integrity.from_dict(raw_doc["integrity"], require_signed=require_signed)
            if bi_int.is_signed and bi_int.content_digest != p1_content_digest(raw_doc):
                raise ClosedValidationError(f"build_input_locators[{idx}]: P1 content_digest mismatch")


def _load_bundle_policy_and_snapshot(
    bundle_locator: ArtifactLocator, *, store: CellObjectStorePort, parquet_codec: ParquetLandingCodecPort, require_signed: bool
) -> tuple[ArtifactLocator, AnalysisReplayInputBundle, AnalysisPolicy, DatasetSnapshot]:
    checked_loc = _typed_locator(bundle_locator, field_name="bundle_locator", expected_type=AnalysisReplayInputBundle.SCHEMA)
    bundle = _load_p1(store, checked_loc, AnalysisReplayInputBundle, field_name="bundle_locator", require_signed=require_signed)
    policy_obj = _load_p1(store, bundle.analysis_policy_locator, AnalysisPolicy, field_name="bundle.analysis_policy_locator", require_signed=require_signed)
    _verify_build_input_locators(bundle, store=store, require_signed=require_signed)
    raw_snap = _load_p1(store, bundle.dataset_snapshot_locator, DatasetSnapshot, field_name="bundle.dataset_snapshot_locator", require_signed=require_signed)
    snapshot = verify_dataset_snapshot(raw_snap, store=store, parquet_codec=parquet_codec, require_signed=require_signed)
    return checked_loc, bundle, policy_obj, snapshot


def _resolve_query_schemas(
    bundle: AnalysisReplayInputBundle, *, store: CellObjectStorePort, require_signed: bool
) -> tuple[dict[bytes, AnalysisResultSchema], tuple[AnalysisResultSchema, ...]]:
    by_key: dict[bytes, AnalysisResultSchema] = {}
    ordered: list[AnalysisResultSchema] = []
    for q in bundle.queries:
        s_key = canonicalize_jcs(q.analysis_result_schema_locator.to_dict())
        schema = by_key.get(s_key)
        if schema is None:
            schema = _load_p1(store, q.analysis_result_schema_locator, AnalysisResultSchema, field_name=f"query[{q.result_key!r}].analysis_result_schema_locator", require_signed=require_signed)
            by_key[s_key] = schema
            ordered.append(schema)
        q.verify_against_schema(schema)
    return by_key, tuple(ordered)


def _load_verified_raw_binary(
    store: CellObjectStorePort, *, object_ref: str, expected_size: int, expected_sha256: str, label: str
) -> bytes:
    raw = store.get_bytes(object_ref, expected_size_bytes=expected_size)
    if len(raw) != expected_size or "sha256:" + hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ClosedValidationError(f"{label}: raw binary SHA-256 or size mismatch")
    return raw


def _resolve_duckdb_and_parquet_blobs(
    bundle: AnalysisReplayInputBundle, snapshot: DatasetSnapshot, *, store: CellObjectStorePort, require_signed: bool
) -> tuple[bytes, dict[str, bytes], tuple[tuple[ParquetObjectLocator, bytes], ...]]:
    db_loc = bundle.duckdb_binary_locator
    duckdb_bytes = _load_verified_raw_binary(store, object_ref=db_loc.object_ref, expected_size=db_loc.size_bytes, expected_sha256=db_loc.binary_sha256, label="duckdb_binary_locator")
    ext_blobs: dict[str, bytes] = {}
    for ext in bundle.extensions:
        if ext.load_mode == "explicit_local_binary":
            if ext.binary_locator is None:
                raise ClosedValidationError(f"extension {ext.extension_name!r}: missing binary_locator")
            ext_blobs[ext.extension_name] = _load_verified_raw_binary(store, object_ref=ext.binary_locator.object_ref, expected_size=ext.binary_locator.size_bytes, expected_sha256=ext.binary_locator.binary_sha256, label=f"extension[{ext.extension_name!r}]")
    pq_pairs: list[tuple[ParquetObjectLocator, bytes]] = []
    for head in snapshot.partition_heads:
        gm = _load_p1(store, head.generation_manifest_locator, GenerationManifest, field_name="snapshot.partition_heads[].generation_manifest_locator", require_signed=require_signed)
        if gm.migration_run_context_locator != bundle.migration_run_context_locator:
            raise ClosedValidationError("analysis_replay_input_bundle: cross-run GenerationManifest is forbidden")
        for pq_loc in gm.parquet_object_locators:
            pq_bytes = _load_verified_raw_binary(store, object_ref=pq_loc.object_ref, expected_size=pq_loc.size_bytes, expected_sha256=pq_loc.physical_parquet_digest, label=f"parquet[{pq_loc.partition_key!r}]")
            pq_pairs.append((pq_loc, pq_bytes))
    return duckdb_bytes, ext_blobs, tuple(pq_pairs)


def _materialize_analysis_results(
    bundle: AnalysisReplayInputBundle, bundle_locator: ArtifactLocator, projections: Mapping[str, ResultProjection],
    schemas_by_key: Mapping[bytes, AnalysisResultSchema], result_integrities: Mapping[str, P1Integrity] | None, *, store: CellObjectStorePort,
) -> tuple[tuple[AnalysisResult, ArtifactLocator], ...]:
    if not isinstance(projections, Mapping) or set(projections) != {q.result_key for q in bundle.queries}:
        raise ClosedValidationError("duckdb_engine: returned projections do not match bundle query result_keys")
    pairs: list[tuple[AnalysisResult, ArtifactLocator]] = []
    for q in bundle.queries:
        proj = projections[q.result_key]
        verify_result_projection(proj, schemas_by_key[canonicalize_jcs(q.analysis_result_schema_locator.to_dict())])
        res_int = None if result_integrities is None else result_integrities[q.result_key]
        res = AnalysisResult(bundle.migration_run_context_locator, bundle.dataset_snapshot_locator, bundle_locator, q.result_key, proj, res_int)
        res_loc = store.put_json_artifact(AnalysisResult.SCHEMA, res.to_dict())
        if res_loc != res.locator():
            raise ClosedValidationError(f"analysis_result[{q.result_key!r}]: stored locator mismatch")
        pairs.append((res, res_loc))
    return tuple(pairs)


def _build_and_store_analysis_execution(
    bundle: AnalysisReplayInputBundle, bundle_locator: ArtifactLocator,
    result_pairs: tuple[tuple[AnalysisResult, ArtifactLocator], ...], unique_schemas: tuple[AnalysisResultSchema, ...],
    execution_integrity: P1Integrity | None, *, store: CellObjectStorePort,
) -> tuple[AnalysisExecution, ArtifactLocator]:
    c_set = CanonicalResultSet.build(bundle_locator, [CanonicalResultEntry.from_result(r) for r, _ in result_pairs])
    execution = AnalysisExecution(bundle_locator, c_set, execution_integrity)
    outputs_signed = bool(
        execution.integrity is not None and execution.integrity.is_signed
        and all(r.integrity is not None and r.integrity.is_signed for r, _ in result_pairs)
        and all(s.integrity is not None and s.integrity.is_signed for s in unique_schemas)
    )
    verify_analysis_execution(
        execution, [r for r, _ in result_pairs], list(unique_schemas), bundle.dataset_snapshot_locator,
        require_signed=outputs_signed, bundle_migration_run_context_locator=bundle.migration_run_context_locator,
    )
    exec_loc = store.put_json_artifact(AnalysisExecution.SCHEMA, execution.to_dict())
    if exec_loc != execution.locator():
        raise ClosedValidationError("analysis_execution: stored locator mismatch")
    return execution, exec_loc


def execute_analysis_replay_bundle(
    *,
    bundle_locator: ArtifactLocator,
    store: CellObjectStorePort,
    parquet_codec: ParquetLandingCodecPort,
    duckdb_engine: DuckDbEnginePort,
    result_integrities: Mapping[str, P1Integrity] | None = None,
    execution_integrity: P1Integrity | None = None,
    require_signed_inputs: bool = False,
) -> tuple[AnalysisExecution, ArtifactLocator, tuple[tuple[AnalysisResult, ArtifactLocator], ...]]:
    """Verify all pre-DuckDB inputs, execute replay queries, and store `AnalysisExecution`."""
    checked_store = _require_store_and_bool(store, require_signed_inputs, bool_name="require_signed_inputs")
    checked_codec = _require_parquet_codec(parquet_codec)
    if not isinstance(duckdb_engine, DuckDbEnginePort):
        raise ClosedValidationError(f"duckdb_engine: expected DuckDbEnginePort, got {type(duckdb_engine).__name__}")
    checked_exec_int = _validate_optional_p1_integrity(execution_integrity, label="execution_integrity")
    checked_bundle_loc, bundle, _, snapshot = _load_bundle_policy_and_snapshot(
        bundle_locator, store=checked_store, parquet_codec=checked_codec, require_signed=require_signed_inputs
    )
    checked_res_ints = _validate_result_integrities(result_integrities, {q.result_key for q in bundle.queries})
    schemas_by_key, unique_schemas = _resolve_query_schemas(bundle, store=checked_store, require_signed=require_signed_inputs)
    duckdb_bytes, ext_blobs, pq_pairs = _resolve_duckdb_and_parquet_blobs(bundle, snapshot, store=checked_store, require_signed=require_signed_inputs)
    projections = duckdb_engine.execute_replay_queries(
        bundle=bundle, duckdb_binary_bytes=duckdb_bytes, extension_binaries=MappingProxyType(ext_blobs),
        parquet_objects=pq_pairs, resolved_schemas=MappingProxyType(schemas_by_key),
    )
    result_pairs = _materialize_analysis_results(bundle, checked_bundle_loc, projections, schemas_by_key, checked_res_ints, store=checked_store)
    execution, exec_loc = _build_and_store_analysis_execution(bundle, checked_bundle_loc, result_pairs, unique_schemas, checked_exec_int, store=checked_store)
    return execution, exec_loc, result_pairs


def _collect_snapshot_generations(
    snapshot: DatasetSnapshot, run_loc: ArtifactLocator, curation_loc: ArtifactLocator,
    restatement_hist_locs: tuple[ArtifactLocator, ...], *,
    store: CellObjectStorePort, parquet_codec: ParquetLandingCodecPort, require_signed: bool,
) -> tuple[tuple[GenerationManifest, ...], tuple[GenerationManifest, ...]]:
    gen_by_key: dict[bytes, GenerationManifest] = {}
    active_gens: list[GenerationManifest] = []
    for head in snapshot.partition_heads:
        gm = _load_p1(store, head.generation_manifest_locator, GenerationManifest, field_name="snapshot.partition_heads[].generation_manifest_locator", require_signed=require_signed)
        if gm.migration_run_context_locator != run_loc:
            raise ClosedValidationError("report_execution: cross-run active GenerationManifest is forbidden")
        gen_by_key[canonicalize_jcs(head.generation_manifest_locator.to_dict())] = gm
        active_gens.append(gm)
    if canonicalize_jcs(curation_loc.to_dict()) not in {canonicalize_jcs(g.curation_execution_locator.to_dict()) for g in active_gens}:
        raise ClosedValidationError("report_execution: curation_execution_locator not in active snapshot generations")
    for h_loc in restatement_hist_locs:
        h_key = canonicalize_jcs(h_loc.to_dict())
        if h_key not in gen_by_key:
            h_gm = _load_p1(store, h_loc, GenerationManifest, field_name="restatement_history_generation_locators[]", require_signed=require_signed)
            if h_gm.migration_run_context_locator != run_loc:
                raise ClosedValidationError("report_execution: cross-run historical GenerationManifest is forbidden")
            verify_generation_manifest(h_gm, store=store, parquet_codec=parquet_codec, require_signed=require_signed)
            gen_by_key[h_key] = h_gm
    return tuple(active_gens), tuple(gen_by_key[k] for k in sorted(gen_by_key))


def _resolve_operational_evidences_and_proofs(
    active_gens: tuple[GenerationManifest, ...], run_loc: ArtifactLocator, *, store: CellObjectStorePort, require_signed: bool
) -> tuple[tuple[OperationalReadEvidence, ...], tuple[ArtifactLocator, ...], tuple[ArtifactLocator, ...]]:
    unique_ev_map = {canonicalize_jcs(loc.to_dict()): loc for gm in active_gens for loc in gm.operational_read_evidence_locators}
    ev_locs = sort_artifact_locators(unique_ev_map.values(), expected_type=OperationalReadEvidence.SCHEMA, allow_empty=False, field_name="operational_read_evidence_locators")
    evidences: list[OperationalReadEvidence] = []
    for ev_loc in ev_locs:
        ev = _load_p1(store, ev_loc, OperationalReadEvidence, field_name="operational_read_evidence_locators[]", require_signed=require_signed)
        if ev.migration_run_context_locator != run_loc:
            raise ClosedValidationError("report_execution: cross-run OperationalReadEvidence is forbidden")
        verify_operational_read_evidence(ev, store=store, require_signed=require_signed)
        evidences.append(ev)
    pf_locs = sort_artifact_locators([ev.effect_proof_locator for ev in evidences], expected_type=EffectProof.SCHEMA, allow_empty=False, field_name="operational_read_effect_proof_locators")
    return tuple(evidences), ev_locs, pf_locs


def _resolve_verified_execution_and_results(
    bundle: AnalysisReplayInputBundle, bundle_loc: ArtifactLocator, execution_locator: ArtifactLocator, *, store: CellObjectStorePort, require_signed: bool
) -> tuple[AnalysisExecution, tuple[AnalysisResult, ...], tuple[AnalysisResultSchema, ...]]:
    checked_exec_loc = _typed_locator(execution_locator, field_name="execution_locator", expected_type=AnalysisExecution.SCHEMA)
    execution = _load_p1(store, checked_exec_loc, AnalysisExecution, field_name="execution_locator", require_signed=require_signed)
    if execution.analysis_replay_input_bundle_locator != bundle_loc:
        raise ClosedValidationError("execution_locator: analysis_replay_input_bundle_locator mismatch")
    results = tuple(_load_p1(store, e.result_locator, AnalysisResult, field_name=f"execution.results[{e.result_key!r}]", require_signed=require_signed) for e in execution.canonical_result_set.results)
    _, unique_schemas = _resolve_query_schemas(bundle, store=store, require_signed=require_signed)
    verify_analysis_execution(execution, list(results), list(unique_schemas), bundle.dataset_snapshot_locator, require_signed=require_signed, bundle_migration_run_context_locator=bundle.migration_run_context_locator)
    return execution, results, unique_schemas


def _resolve_report_provenance_inputs(
    evaluation_context: EvaluationContext, policy_obj: AnalysisPolicy, inventory_locator: ArtifactLocator,
    curation_locator: ArtifactLocator, template_locator: ArtifactLocator, render_identity: AlgorithmProvenanceIdentity,
    *, store: CellObjectStorePort, require_signed: bool,
) -> tuple[ArtifactLocator, ArtifactLocator, ArtifactLocator, GitArtifactProvenance, GitArtifactProvenance]:
    if type(evaluation_context) is not EvaluationContext:
        raise ClosedValidationError("evaluation_context: expected EvaluationContext")
    if canonicalize_jcs(evaluation_context.policy.to_dict()) != canonicalize_jcs(policy_obj.to_dict()):
        raise ClosedValidationError("evaluation_context.policy: differs from resolved bundle policy")
    checked_inv_loc = _typed_locator(inventory_locator, field_name="expected_resource_inventory_locator", expected_type=ExpectedResourceInventory.SCHEMA)
    resolved_inv = _load_p1(store, checked_inv_loc, ExpectedResourceInventory, field_name="expected_resource_inventory_locator", require_signed=require_signed)
    if canonicalize_jcs(evaluation_context.inventory.to_dict()) != canonicalize_jcs(resolved_inv.to_dict()):
        raise ClosedValidationError("evaluation_context.inventory: differs from resolved inventory")
    checked_cur_loc = _typed_locator(curation_locator, field_name="curation_execution_locator", expected_type=CurationExecution.SCHEMA)
    resolved_cur = _load_p1(store, checked_cur_loc, CurationExecution, field_name="curation_execution_locator", require_signed=require_signed)
    verify_curation_execution(resolved_cur, store=store, require_signed=require_signed)
    checked_tmpl_loc = _typed_locator(template_locator, field_name="report_template_provenance_locator", expected_type=GitArtifactProvenance.SCHEMA)
    tmpl_prov = _load_p1(store, checked_tmpl_loc, GitArtifactProvenance, field_name="report_template_provenance_locator", require_signed=require_signed)
    if type(render_identity) is not AlgorithmProvenanceIdentity or render_identity.schema_id != ReportExecution.SCHEMA:
        raise ClosedValidationError(f"render_algorithm_identity: expected AlgorithmProvenanceIdentity for {ReportExecution.SCHEMA!r}")
    rnd_prov = _load_p1(store, render_identity.git_artifact_provenance_locator, GitArtifactProvenance, field_name="render_algorithm_identity.git_artifact_provenance_locator", require_signed=require_signed)
    verify_algorithm_provenance_identity(render_identity, rnd_prov)
    return checked_inv_loc, checked_cur_loc, checked_tmpl_loc, tmpl_prov, rnd_prov


def _persist_findings_and_certification(
    evaluation_context: EvaluationContext, evidence: AnalysisEvidence, attested_inputs: Sequence[AttestedCertificationInput],
    finding_integrities: tuple[P1Integrity, ...] | None, certification_integrity: P1Integrity | None, *, store: CellObjectStorePort,
) -> tuple[tuple[tuple[Finding, ArtifactLocator], ...], AnalyticalCertificationRecord, ArtifactLocator]:
    raw_findings = evaluate_findings(evaluation_context, evidence)
    if finding_integrities is not None and len(finding_integrities) != len(raw_findings):
        raise ClosedValidationError(f"finding_integrities: expected {len(raw_findings)} items, got {len(finding_integrities)}")
    finding_pairs: list[tuple[Finding, ArtifactLocator]] = []
    for idx, f_obj in enumerate(raw_findings):
        if finding_integrities is not None:
            f_int = finding_integrities[idx]
            f_obj = Finding.from_dict({**f_obj.to_dict(), "integrity": f_int.to_dict()}, require_signed=f_int.is_signed)
        f_loc = store.put_json_artifact(Finding.SCHEMA, f_obj.to_dict())
        if f_loc != f_obj.locator():
            raise ClosedValidationError(f"finding[{f_obj.finding_key!r}]: stored locator mismatch")
        finding_pairs.append((f_obj, f_loc))
    stored_findings = tuple(f for f, _ in finding_pairs)
    cert_req_signed = bool(evidence.require_signed and all(f.integrity is not None and f.integrity.is_signed for f in stored_findings))
    cert_ev = AnalysisEvidence(evidence.execution, evidence.resolved_results, evidence.resolved_schemas, evidence.bundle_dataset_snapshot_locator, evidence.bundle_analysis_policy_locator, cert_req_signed, evidence.bundle_migration_run_context_locator)
    cert_rec = build_certification_record(evaluation_context, cert_ev, stored_findings, list(attested_inputs), integrity=certification_integrity)
    cert_loc = store.put_json_artifact(AnalyticalCertificationRecord.SCHEMA, cert_rec.to_dict())
    if cert_loc != cert_rec.locator():
        raise ClosedValidationError("certification_record: stored locator mismatch")
    return tuple(finding_pairs), cert_rec, cert_loc


def _build_verify_and_store_report_envelope(
    *, report_id: str, executed_at_utc: str, bundle: AnalysisReplayInputBundle, bundle_loc: ArtifactLocator,
    snapshot: DatasetSnapshot, policy_obj: AnalysisPolicy, execution: AnalysisExecution,
    results: tuple[AnalysisResult, ...], schemas: tuple[AnalysisResultSchema, ...],
    all_gens: tuple[GenerationManifest, ...], op_evs: tuple[OperationalReadEvidence, ...],
    ev_locs: tuple[ArtifactLocator, ...], pf_locs: tuple[ArtifactLocator, ...],
    inv_loc: ArtifactLocator, cur_loc: ArtifactLocator, hist_locs: tuple[ArtifactLocator, ...],
    tmpl_loc: ArtifactLocator, tmpl_prov: GitArtifactProvenance, rnd_prov: GitArtifactProvenance,
    render_identity: AlgorithmProvenanceIdentity, evaluation_context: EvaluationContext,
    attested_inputs: Sequence[AttestedCertificationInput],
    finding_pairs: tuple[tuple[Finding, ArtifactLocator], ...],
    cert_rec: AnalyticalCertificationRecord, cert_loc: ArtifactLocator,
    report_integrity: P1Integrity | None, require_signed_inputs: bool, store: CellObjectStorePort,
) -> tuple[ReportExecution, ArtifactLocator]:
    stored_findings = tuple(f for f, _ in finding_pairs)
    f_locs = sort_artifact_locators([loc for _, loc in finding_pairs], expected_type=Finding.SCHEMA, allow_empty=True, field_name="finding_locators")
    rep_in = CanonicalReportInput(
        snapshot.snapshot_digest, execution.canonical_result_set.canonical_result_digest,
        evaluation_context.evaluation_instant_utc, evaluation_context.window_end_date,
        evaluation_context.metrics_result_key, inv_loc, cur_loc, hist_locs, tuple(attested_inputs),
        tuple(sorted((f.finding_digest for f in stored_findings), key=lambda s: s.encode("utf-8"))),
        cert_rec.derived_certification_status, cert_rec.mutation_recommendations_blocked,
    )
    report = ReportExecution(
        report_id, bundle.migration_run_context_locator, snapshot.locator(), bundle_loc, execution.locator(),
        policy_obj.locator(), f_locs, (cert_loc,), ev_locs, pf_locs, tmpl_loc, render_identity,
        rep_in, render_canonical_report_result(rep_in, stored_findings), executed_at_utc, integrity=report_integrity,
    )
    full_signed = bool(
        require_signed_inputs and report.integrity is not None and report.integrity.is_signed
        and cert_rec.integrity is not None and cert_rec.integrity.is_signed
        and all(f.integrity is not None and f.integrity.is_signed for f in stored_findings)
    )
    verify_report_execution(
        report, snapshot=snapshot, generation_manifests=all_gens, operational_evidences=op_evs,
        replay_bundle=bundle, execution=execution, results=results, result_schemas=schemas,
        policy_obj=policy_obj, findings=stored_findings, certifications=(cert_rec,),
        evaluation_context=evaluation_context, attested_inputs=attested_inputs,
        template_provenance=tmpl_prov, render_provenance=rnd_prov, require_signed=full_signed,
    )
    rep_loc = store.put_json_artifact(ReportExecution.SCHEMA, report.to_dict())
    if rep_loc != report.locator():
        raise ClosedValidationError("report_execution: stored locator mismatch")
    return report, rep_loc


def execute_certified_report(
    *,
    report_id: str,
    executed_at_utc: str,
    bundle_locator: ArtifactLocator,
    execution_locator: ArtifactLocator,
    evaluation_context: EvaluationContext,
    expected_resource_inventory_locator: ArtifactLocator,
    curation_execution_locator: ArtifactLocator,
    restatement_history_generation_locators: Sequence[ArtifactLocator],
    attested_certification_inputs: Sequence[AttestedCertificationInput],
    report_template_provenance_locator: ArtifactLocator,
    render_algorithm_identity: AlgorithmProvenanceIdentity,
    store: CellObjectStorePort,
    parquet_codec: ParquetLandingCodecPort,
    finding_integrities: Sequence[P1Integrity] | None = None,
    certification_integrity: P1Integrity | None = None,
    report_integrity: P1Integrity | None = None,
    require_signed_inputs: bool = False,
) -> tuple[ReportExecution, ArtifactLocator, AnalyticalCertificationRecord, ArtifactLocator, tuple[tuple[Finding, ArtifactLocator], ...]]:
    """Evaluate findings, certify them, render `ReportExecution`, and verify the full chain."""
    _strict_id(report_id, field_name="report_id")
    validate_envelope_timestamp_utc(executed_at_utc, field_name="executed_at_utc")
    checked_store = _require_store_and_bool(store, require_signed_inputs, bool_name="require_signed_inputs")
    checked_codec = _require_parquet_codec(parquet_codec)
    checked_f_ints = _validate_finding_integrities(finding_integrities)
    checked_c_int = _validate_optional_p1_integrity(certification_integrity, label="certification_integrity")
    checked_r_int = _validate_optional_p1_integrity(report_integrity, label="report_integrity")
    if isinstance(attested_certification_inputs, (str, bytes)) or not isinstance(attested_certification_inputs, Sequence) or not attested_certification_inputs:
        raise ClosedValidationError("attested_certification_inputs: expected non-empty Sequence of AttestedCertificationInput")
    hist_locs = sort_artifact_locators(restatement_history_generation_locators, expected_type=GenerationManifest.SCHEMA, allow_empty=True, field_name="restatement_history_generation_locators")
    checked_bundle_loc, bundle, policy_obj, snapshot = _load_bundle_policy_and_snapshot(bundle_locator, store=checked_store, parquet_codec=checked_codec, require_signed=require_signed_inputs)
    inv_loc, cur_loc, tmpl_loc, tmpl_prov, rnd_prov = _resolve_report_provenance_inputs(evaluation_context, policy_obj, expected_resource_inventory_locator, curation_execution_locator, report_template_provenance_locator, render_algorithm_identity, store=checked_store, require_signed=require_signed_inputs)
    active_gens, all_gens = _collect_snapshot_generations(snapshot, bundle.migration_run_context_locator, cur_loc, hist_locs, store=checked_store, parquet_codec=checked_codec, require_signed=require_signed_inputs)
    op_evs, ev_locs, pf_locs = _resolve_operational_evidences_and_proofs(active_gens, bundle.migration_run_context_locator, store=checked_store, require_signed=require_signed_inputs)
    execution, results, schemas = _resolve_verified_execution_and_results(bundle, checked_bundle_loc, execution_locator, store=checked_store, require_signed=require_signed_inputs)
    evidence = AnalysisEvidence(execution, results, schemas, snapshot.locator(), policy_obj.locator(), require_signed_inputs, bundle.migration_run_context_locator)
    finding_pairs, cert_rec, cert_loc = _persist_findings_and_certification(evaluation_context, evidence, attested_certification_inputs, checked_f_ints, checked_c_int, store=checked_store)
    report, rep_loc = _build_verify_and_store_report_envelope(
        report_id=report_id, executed_at_utc=executed_at_utc, bundle=bundle, bundle_loc=checked_bundle_loc,
        snapshot=snapshot, policy_obj=policy_obj, execution=execution, results=results, schemas=schemas,
        all_gens=all_gens, op_evs=op_evs, ev_locs=ev_locs, pf_locs=pf_locs, inv_loc=inv_loc, cur_loc=cur_loc,
        hist_locs=hist_locs, tmpl_loc=tmpl_loc, tmpl_prov=tmpl_prov, rnd_prov=rnd_prov,
        render_identity=render_algorithm_identity, evaluation_context=evaluation_context,
        attested_inputs=attested_certification_inputs, finding_pairs=finding_pairs,
        cert_rec=cert_rec, cert_loc=cert_loc, report_integrity=checked_r_int,
        require_signed_inputs=require_signed_inputs, store=checked_store,
    )
    return report, rep_loc, cert_rec, cert_loc, finding_pairs


__all__ = [
    "execute_analysis_replay_bundle",
    "execute_certified_report",
]
