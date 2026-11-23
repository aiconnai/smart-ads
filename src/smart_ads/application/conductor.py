"""Pure offline conductor over verified snapshots and injected intelligence (ADR-0001 §§3.3, 6.4, 7)."""
from __future__ import annotations

from dataclasses import dataclass, field
import datetime
from itertools import pairwise
from typing import Any, ClassVar, Final

from smart_ads.analytics import FINDING_INCONCLUSIVE, METRIC_WINDOW_COLUMNS, AnalyticalCertificationRecord, AnalysisEvidence, AnalysisExecution, AnalysisPolicy, AnalysisReplayInputBundle, AnalysisResult, AnalysisResultSchema, AttestedCertificationInput, CanonicalResultEntry, DerivedCertificationStatus, EvaluationContext, EvaluationScope, Finding, RestatementRule, SaturationRule, StalledDeliveryRule, WasteRule, combine_derived_certification, derive_snapshot_restatement_history, require_policy_applicable, verify_analysis_execution
from smart_ads.analytics.reporting import _validate_attested_inputs
from smart_ads.application.curation_pipeline import _load_p1
from smart_ads.application.duckdb_execution import (
    _resolve_query_schemas, _validate_optional_p1_integrity, _verify_replay_bundle_inputs_and_binaries,
)
from smart_ads.application.mcp_read_handler import _SignatureVerifyingStoreProxy, _load_snapshot_lineage_generations, _prepare_read_ports, load_verified_snapshot_rows
from smart_ads.application.predecessor_validators import _invoke_sig_verifier, _verify_algorithm_with_sig, verify_stored_migration_run_context
from smart_ads.contracts import AlgorithmProvenanceIdentity, AnalyticsLandingRow, ArtifactLocator, ClosedValidationError, P1Integrity, canonicalize_jcs, jcs_sha256, parse_iso_date, require_exact_keys, self_digest_jcs_sha256, sort_artifact_locators, sort_utf8_strings, validate_iso_date, validate_sha256_prefixed, validate_timestamp_utc6
from smart_ads.contracts.effects import _safe_int, _strict_str, _typed_locator
from smart_ads.domain.catalog import DatasetCatalogCutReceipt, DatasetSnapshot, compute_logical_rows_digest
from smart_ads.domain.curation import CurationExecution, partition_key_for_metric_date
from smart_ads.domain.registry import ExpectedResourceInventory, PrivateRegistrySnapshot
from smart_ads.ports.consumer import OfflineIntelligencePort, P1SignatureVerifierPort
from smart_ads.ports.storage import CellObjectStorePort, ParquetLandingCodecPort

CONDUCTOR_RUN_OUTCOME_SCHEMA: Final[str] = "smart_ads/conductor_run_outcome/v1"
_RUN_CONTEXT_SCHEMA: Final[str] = "smart_ads/migration_run_context/v1"
_LOCATOR_SPECS: Final[tuple[tuple[str, str], ...]] = (("migration_run_context_locator", _RUN_CONTEXT_SCHEMA), ("dataset_snapshot_locator", DatasetSnapshot.SCHEMA), ("expected_resource_inventory_locator", ExpectedResourceInventory.SCHEMA), ("analysis_policy_locator", AnalysisPolicy.SCHEMA), ("analysis_execution_locator", AnalysisExecution.SCHEMA))

def _validate_five_locators(obj: object, *, label: str) -> None:
    for attr_name, schema_id in _LOCATOR_SPECS:
        object.__setattr__(obj, attr_name, _typed_locator(getattr(obj, attr_name), field_name=f"{label}.{attr_name}", expected_type=schema_id))

def _validate_results_tuple(values: object, *, label: str) -> tuple[AnalysisResult, ...]:
    if not isinstance(values, (list, tuple)) or not values:
        raise ClosedValidationError(f"{label}: expected non-empty list or tuple of AnalysisResult")
    out, seen_keys = [], set()
    for idx, item in enumerate(values):
        if type(item) is not AnalysisResult:
            raise ClosedValidationError(f"{label}[{idx}]: expected AnalysisResult")
        fresh = AnalysisResult.from_dict(item.to_dict(), require_signed=item.integrity is not None and item.integrity.is_signed)
        if fresh != item or fresh.result_key in seen_keys:
            raise ClosedValidationError(f"{label}[{idx}]: corrupted or duplicate result_key {fresh.result_key!r}")
        seen_keys.add(fresh.result_key)
        out.append(fresh)
    return tuple(out)

def _validate_evidence_tuple(values: object, *, label: str) -> tuple[AnalysisEvidence, ...]:
    if not isinstance(values, (list, tuple)) or any(type(item) is not AnalysisEvidence for item in values):
        raise ClosedValidationError(f"{label}: expected list or tuple of AnalysisEvidence")
    return tuple(AnalysisEvidence(i.execution, i.resolved_results, i.resolved_schemas, i.bundle_dataset_snapshot_locator, i.bundle_analysis_policy_locator, i.require_signed, i.bundle_migration_run_context_locator) for i in values)

def _evidence_to_jcs_dict(ev: AnalysisEvidence) -> dict[str, Any]:
    run_loc = None if ev.bundle_migration_run_context_locator is None else ev.bundle_migration_run_context_locator.to_dict()
    return {"execution": ev.execution.to_dict(), "resolved_results": [r.to_dict() for r in ev.resolved_results], "resolved_schemas": [s.to_dict() for s in ev.resolved_schemas], "bundle_dataset_snapshot_locator": ev.bundle_dataset_snapshot_locator.to_dict(), "bundle_analysis_policy_locator": ev.bundle_analysis_policy_locator.to_dict(), "require_signed": ev.require_signed, "bundle_migration_run_context_locator": run_loc}


@dataclass(frozen=True, slots=True)
class ConductorRunInput:
    """Closed offline input bundle for `conduct_offline_run` with zero provider ports."""

    migration_run_context_locator: ArtifactLocator
    dataset_snapshot_locator: ArtifactLocator
    expected_resource_inventory_locator: ArtifactLocator
    analysis_policy_locator: ArtifactLocator
    analysis_execution_locator: ArtifactLocator
    evaluation_instant_utc: str
    window_end_date: str
    attested_certification_inputs: tuple[AttestedCertificationInput, ...]
    resolved_analysis_results: tuple[AnalysisResult, ...]
    analysis_evidence: tuple[AnalysisEvidence, ...] = ()
    certification_integrity: P1Integrity | None = None
    store: CellObjectStorePort = field(kw_only=True)
    parquet_codec: ParquetLandingCodecPort = field(kw_only=True)
    signature_verifier: P1SignatureVerifierPort | None = field(default=None, kw_only=True)
    require_signed: bool = field(default=True, kw_only=True)

    def __post_init__(self) -> None:
        label = "conductor_run_input"
        _validate_five_locators(self, label=label)
        inst = validate_timestamp_utc6(_strict_str(self.evaluation_instant_utc, field_name=f"{label}.evaluation_instant_utc"), field_name=f"{label}.evaluation_instant_utc")
        w_end = validate_iso_date(_strict_str(self.window_end_date, field_name=f"{label}.window_end_date"), field_name=f"{label}.window_end_date")
        if parse_iso_date(w_end, field_name=f"{label}.window_end_date") > parse_iso_date(inst[:10], field_name=f"{label}.evaluation_instant_utc"):
            raise ClosedValidationError(f"{label}.window_end_date: must not follow evaluation_instant_utc date")
        object.__setattr__(self, "attested_certification_inputs", _validate_attested_inputs(self.attested_certification_inputs, field_name=f"{label}.attested_certification_inputs"))
        object.__setattr__(self, "resolved_analysis_results", _validate_results_tuple(self.resolved_analysis_results, label=f"{label}.resolved_analysis_results"))
        object.__setattr__(self, "analysis_evidence", _validate_evidence_tuple(self.analysis_evidence, label=f"{label}.analysis_evidence"))
        object.__setattr__(self, "certification_integrity", _validate_optional_p1_integrity(self.certification_integrity, label=f"{label}.certification_integrity"))
        _prepare_read_ports(store=self.store, parquet_codec=self.parquet_codec, signature_verifier=self.signature_verifier, require_signed=self.require_signed)


@dataclass(frozen=True, slots=True)
class ConductorRunOutcome:
    """Canonical JCS-deterministic outcome of an offline conductor run."""

    SCHEMA: ClassVar[str] = CONDUCTOR_RUN_OUTCOME_SCHEMA
    KEYS: ClassVar[frozenset[str]] = frozenset("$schema migration_run_context_locator dataset_snapshot_locator dataset_snapshot_digest expected_resource_inventory_locator analysis_policy_locator analysis_execution_locator intelligence_algorithm_identity reduced_row_count reduced_evidence_digest findings finding_digests certification_record outcome_digest".split())

    migration_run_context_locator: ArtifactLocator
    dataset_snapshot_locator: ArtifactLocator
    dataset_snapshot_digest: str
    expected_resource_inventory_locator: ArtifactLocator
    analysis_policy_locator: ArtifactLocator
    analysis_execution_locator: ArtifactLocator
    intelligence_algorithm_identity: AlgorithmProvenanceIdentity
    reduced_row_count: int
    reduced_evidence_digest: str
    findings: tuple[Finding, ...]
    finding_digests: tuple[str, ...]
    certification_record: AnalyticalCertificationRecord
    outcome_digest: str = ""

    def __post_init__(self) -> None:
        label = "conductor_run_outcome"
        _validate_five_locators(self, label=label)
        validate_sha256_prefixed(_strict_str(self.dataset_snapshot_digest, field_name=f"{label}.dataset_snapshot_digest"), field_name=f"{label}.dataset_snapshot_digest")
        if type(self.intelligence_algorithm_identity) is not AlgorithmProvenanceIdentity:
            raise ClosedValidationError(f"{label}.intelligence_algorithm_identity: expected AlgorithmProvenanceIdentity")
        alg = AlgorithmProvenanceIdentity.from_dict(self.intelligence_algorithm_identity.to_dict())
        if alg != self.intelligence_algorithm_identity or alg.schema_id != Finding.SCHEMA:
            raise ClosedValidationError(f"{label}.intelligence_algorithm_identity: invalid or non-finding schema_id")
        object.__setattr__(self, "intelligence_algorithm_identity", alg)
        _safe_int(self.reduced_row_count, field_name=f"{label}.reduced_row_count", minimum=0)
        validate_sha256_prefixed(_strict_str(self.reduced_evidence_digest, field_name=f"{label}.reduced_evidence_digest"), field_name=f"{label}.reduced_evidence_digest")
        self._validate_findings_and_certification(label)
        exp_dig = self_digest_jcs_sha256(self.to_dict(), digest_member="outcome_digest", domain_prefix=None, strip_integrity=False)
        raw_od = _strict_str(self.outcome_digest, field_name=f"{label}.outcome_digest")
        if raw_od == "":
            object.__setattr__(self, "outcome_digest", exp_dig)
        elif validate_sha256_prefixed(raw_od, field_name=f"{label}.outcome_digest") != exp_dig:
            raise ClosedValidationError(f"{label}.outcome_digest: recomputed {exp_dig!r} != {raw_od!r}")
        canonicalize_jcs(self.to_dict())

    def _validate_findings_and_certification(self, label: str) -> None:
        if not isinstance(self.findings, (list, tuple)) or not isinstance(self.finding_digests, (list, tuple)):
            raise ClosedValidationError(f"{label}: findings and finding_digests must be list or tuple")
        checked_f, f_keys = [], []
        for idx, item in enumerate(self.findings):
            if type(item) is not Finding:
                raise ClosedValidationError(f"{label}.findings[{idx}]: expected Finding")
            fresh = Finding.from_dict(item.to_dict(), require_signed=item.integrity is not None and item.integrity.is_signed)
            if fresh != item:
                raise ClosedValidationError(f"{label}.findings[{idx}]: corrupted Finding")
            checked_f.append(fresh)
            f_keys.append(fresh.finding_key.encode("utf-8"))
        if any(left >= right for left, right in pairwise(f_keys)):
            raise ClosedValidationError(f"{label}.findings: must be strictly sorted and unique by finding_key")
        exp_digs = sort_utf8_strings([f.finding_digest for f in checked_f], allow_empty=True, field_name=f"{label}.finding_digests", validator=lambda d: validate_sha256_prefixed(d, field_name=f"{label}.finding_digests"))
        if tuple(self.finding_digests) != exp_digs or type(self.certification_record) is not AnalyticalCertificationRecord:
            raise ClosedValidationError(f"{label}: finding_digests or certification_record type mismatch")
        fresh_c = AnalyticalCertificationRecord.from_dict(self.certification_record.to_dict(), require_signed=self.certification_record.integrity is not None and self.certification_record.integrity.is_signed)
        exp_locs = sort_artifact_locators([f.locator() for f in checked_f], expected_type=Finding.SCHEMA, allow_empty=True, field_name=f"{label}.finding_locators")
        if fresh_c != self.certification_record or fresh_c.finding_locators != exp_locs or fresh_c.mutation_recommendations_blocked != any(f.mutation_recommendation_blocked for f in checked_f):
            raise ClosedValidationError(f"{label}.certification_record: inconsistent with findings")
        object.__setattr__(self, "findings", tuple(checked_f))
        object.__setattr__(self, "finding_digests", exp_digs)
        object.__setattr__(self, "certification_record", fresh_c)

    def to_dict(self) -> dict[str, Any]:
        locs = {k: getattr(self, k).to_dict() for k, _ in _LOCATOR_SPECS}
        return {"$schema": self.SCHEMA, **locs, "dataset_snapshot_digest": self.dataset_snapshot_digest, "intelligence_algorithm_identity": self.intelligence_algorithm_identity.to_dict(), "reduced_row_count": self.reduced_row_count, "reduced_evidence_digest": self.reduced_evidence_digest, "findings": [f.to_dict() for f in self.findings], "finding_digests": list(self.finding_digests), "certification_record": self.certification_record.to_dict(), "outcome_digest": self.outcome_digest}

    @classmethod
    def from_dict(cls, data: object) -> ConductorRunOutcome:
        m = require_exact_keys(data, cls.KEYS, label="conductor_run_outcome")
        if type(m["$schema"]) is not str or m["$schema"] != cls.SCHEMA or not isinstance(m["findings"], list) or not isinstance(m["finding_digests"], list):
            raise ClosedValidationError("conductor_run_outcome: invalid $schema or JSON list members")
        od = validate_sha256_prefixed(_strict_str(m["outcome_digest"], field_name="conductor_run_outcome.outcome_digest"), field_name="conductor_run_outcome.outcome_digest")
        locs = {k: ArtifactLocator.from_dict(m[k], expected_type=s) for k, s in _LOCATOR_SPECS}
        return cls(**locs, dataset_snapshot_digest=m["dataset_snapshot_digest"], intelligence_algorithm_identity=AlgorithmProvenanceIdentity.from_dict(m["intelligence_algorithm_identity"]), reduced_row_count=m["reduced_row_count"], reduced_evidence_digest=m["reduced_evidence_digest"], findings=tuple(Finding.from_dict(f) for f in m["findings"]), finding_digests=tuple(m["finding_digests"]), certification_record=AnalyticalCertificationRecord.from_dict(m["certification_record"]), outcome_digest=od)

def _load_verified_scope_and_policy(fresh_in: ConductorRunInput, run_ctx: dict[str, Any], *, proxy_store: _SignatureVerifyingStoreProxy, require_signed: bool) -> tuple[ExpectedResourceInventory, AnalysisPolicy, EvaluationScope]:
    inv = _load_p1(proxy_store, fresh_in.expected_resource_inventory_locator, ExpectedResourceInventory, field_name="expected_resource_inventory_locator", require_signed=require_signed)
    levels = {u.resource_level for u in inv.expected_resources}
    if inv.tenant_ref != run_ctx["tenant_ref"] or len(levels) != 1:
        raise ClosedValidationError("expected_resource_inventory: tenant_ref or resource_level mismatch")
    pol = _load_p1(proxy_store, fresh_in.analysis_policy_locator, AnalysisPolicy, field_name="analysis_policy_locator", require_signed=require_signed)
    reg = _load_p1(proxy_store, inv.registry_snapshot_locator, PrivateRegistrySnapshot, field_name="inventory.registry_snapshot_locator", require_signed=require_signed)
    if reg.tenant_ref != inv.tenant_ref or not any(r.binding_ref == inv.binding_ref and r.resource_scope_ref == inv.resource_scope_ref for r in reg.authorized_scopes):
        raise ClosedValidationError("expected_resource_inventory: unauthorized scope in PrivateRegistrySnapshot")
    binding = reg.get_binding(inv.binding_ref)
    if binding.account_ref != inv.account_ref:
        raise ClosedValidationError("expected_resource_inventory: account_ref mismatch against RegistryBinding")
    scope = EvaluationScope(inv.tenant_ref, inv.resource_scope_ref, next(iter(levels)), binding.ad_platform_ref, binding.currency)
    require_policy_applicable(pol, scope, fresh_in.evaluation_instant_utc)
    return inv, pol, scope

def _verify_execution_and_results(exec_loc: ArtifactLocator, results_in: tuple[AnalysisResult, ...], schemas_in: tuple[AnalysisResultSchema, ...] | None, fresh_in: ConductorRunInput, inv: ExpectedResourceInventory, *, proxy_store: _SignatureVerifyingStoreProxy, require_signed: bool, label: str) -> tuple[AnalysisExecution, tuple[AnalysisResult, ...], tuple[AnalysisResultSchema, ...]]:
    raw_exec = _load_p1(proxy_store, exec_loc, AnalysisExecution, field_name=f"{label}.execution", require_signed=require_signed)
    bundle = _load_p1(proxy_store, raw_exec.analysis_replay_input_bundle_locator, AnalysisReplayInputBundle, field_name=f"{label}.bundle", require_signed=require_signed)
    if (bundle.migration_run_context_locator, bundle.dataset_snapshot_locator, bundle.analysis_policy_locator) != (fresh_in.migration_run_context_locator, fresh_in.dataset_snapshot_locator, fresh_in.analysis_policy_locator):
        raise ClosedValidationError(f"{label}: bundle run, snapshot, or policy locator mismatch")
    _verify_replay_bundle_inputs_and_binaries(bundle, store=proxy_store, require_signed=require_signed)
    _, schemas = _resolve_query_schemas(bundle, store=proxy_store, require_signed=require_signed)
    sorted_schemas = tuple(sorted(schemas, key=lambda s: canonicalize_jcs(s.locator().to_dict())))
    if schemas_in is not None:
        parsed_s = [AnalysisResultSchema.from_dict(s.to_dict(), require_signed=require_signed) for s in schemas_in]
        sup_s = tuple(sorted(parsed_s, key=lambda s: canonicalize_jcs(s.locator().to_dict())))
        if any(a != b for a, b in zip(parsed_s, schemas_in, strict=True)) or [canonicalize_jcs(s.to_dict()) for s in sup_s] != [canonicalize_jcs(s.to_dict()) for s in sorted_schemas]:
            raise ClosedValidationError(f"{label}: resolved_schemas mismatch against verified bundle schemas")
    sorted_results = tuple(sorted(_validate_results_tuple(results_in, label=f"{label}.results"), key=lambda r: r.result_key.encode("utf-8")))
    if {r.result_key: r.result_projection.analysis_result_schema_locator for r in sorted_results} != {q.result_key: q.analysis_result_schema_locator for q in bundle.queries}:
        raise ClosedValidationError(f"{label}: result_key or schema locator mismatch against bundle.queries")
    inv_res = {u.resource_ref for u in inv.expected_resources}
    for res in sorted_results:
        fresh_r = _load_p1(proxy_store, res.locator(), AnalysisResult, field_name=f"{label}.results[{res.result_key!r}]", require_signed=require_signed)
        if fresh_in.signature_verifier is not None and (require_signed or (fresh_r.integrity is not None and fresh_r.integrity.is_signed)):
            _invoke_sig_verifier(fresh_in.signature_verifier, envelope=fresh_r.to_dict(), domain_prefix="SMART-ADS:ANALYSIS-RESULT:V1\n", store=fresh_in.store)
        if (fresh_r.migration_run_context_locator, fresh_r.dataset_snapshot_locator) != (fresh_in.migration_run_context_locator, fresh_in.dataset_snapshot_locator) or CanonicalResultEntry.from_result(fresh_r) != raw_exec.canonical_result_set.entry(fresh_r.result_key):
            raise ClosedValidationError(f"{label}.results[{fresh_r.result_key!r}]: run, snapshot, or canonical_result_set mismatch")
        names = [c.name for c in fresh_r.result_projection.columns]
        if "resource_ref" in names and any(row[names.index("resource_ref")].value not in inv_res for row in fresh_r.result_projection.rows if row[names.index("resource_ref")].value is not None):
            raise ClosedValidationError(f"{label}.results[{fresh_r.result_key!r}]: resource_ref outside ExpectedResourceInventory")
    verified_exec = verify_analysis_execution(raw_exec, list(sorted_results), list(sorted_schemas), fresh_in.dataset_snapshot_locator, require_signed=require_signed, bundle_migration_run_context_locator=fresh_in.migration_run_context_locator)
    return verified_exec, sorted_results, sorted_schemas

def _canonicalize_evidence_set(fresh_in: ConductorRunInput, inv: ExpectedResourceInventory, primary_exec: AnalysisExecution, sorted_results: tuple[AnalysisResult, ...], sorted_schemas: tuple[AnalysisResultSchema, ...], *, proxy_store: _SignatureVerifyingStoreProxy, require_signed: bool) -> tuple[AnalysisEvidence, ...]:
    if not fresh_in.analysis_evidence:
        return (AnalysisEvidence(primary_exec, sorted_results, sorted_schemas, fresh_in.dataset_snapshot_locator, fresh_in.analysis_policy_locator, require_signed, fresh_in.migration_run_context_locator),)
    keyed, seen_keys = [], set()
    for idx, ev in enumerate(fresh_in.analysis_evidence):
        if (ev.bundle_dataset_snapshot_locator, ev.bundle_analysis_policy_locator, ev.require_signed) != (fresh_in.dataset_snapshot_locator, fresh_in.analysis_policy_locator, require_signed) or ev.bundle_migration_run_context_locator not in (None, fresh_in.migration_run_context_locator):
            raise ClosedValidationError(f"analysis_evidence[{idx}]: snapshot, policy, run, or require_signed mismatch")
        fresh_ev_exec = AnalysisExecution.from_dict(ev.execution.to_dict(), require_signed=require_signed)
        if fresh_ev_exec != ev.execution:
            raise ClosedValidationError(f"analysis_evidence[{idx}]: corrupted AnalysisExecution")
        v_exec, ev_res, ev_sch = _verify_execution_and_results(fresh_ev_exec.locator(), ev.resolved_results, ev.resolved_schemas, fresh_in, inv, proxy_store=proxy_store, require_signed=require_signed, label=f"analysis_evidence[{idx}]")
        norm_ev = AnalysisEvidence(v_exec, ev_res, ev_sch, fresh_in.dataset_snapshot_locator, fresh_in.analysis_policy_locator, require_signed, fresh_in.migration_run_context_locator)
        jcs_k = canonicalize_jcs(_evidence_to_jcs_dict(norm_ev))
        if jcs_k in seen_keys:
            raise ClosedValidationError(f"analysis_evidence[{idx}]: duplicate AnalysisEvidence")
        seen_keys.add(jcs_k)
        keyed.append((jcs_k, norm_ev))
    if fresh_in.analysis_execution_locator not in {ev.execution.locator() for _, ev in keyed}:
        raise ClosedValidationError("analysis_evidence: primary analysis_execution_locator absent")
    return tuple(ev for _, ev in sorted(keyed, key=lambda pair: pair[0]))

def _safe_shift_date(day: datetime.date, back_days: int, *, label: str) -> str:
    try:
        return (day - datetime.timedelta(days=back_days)).isoformat()
    except (OverflowError, ValueError) as exc:
        raise ClosedValidationError(f"{label}: date window underflow ({back_days} days before {day.isoformat()})") from exc

def _check_policy_rule_windows(ctx: EvaluationContext) -> None:
    end_d, anchor_d = parse_iso_date(ctx.window_end_date, field_name="window_end_date"), parse_iso_date(ctx.curation_anchor_date, field_name="curation_anchor_date")
    cur_start, cur_end = _safe_shift_date(anchor_d, ctx.curation_restatement_lookback_days - 1, label="curation_window"), anchor_d.isoformat()
    for rule in ctx.policy.rules:
        span = (rule.window_days * 2) if isinstance(rule, SaturationRule) else (rule.window_days if isinstance(rule, WasteRule) else (rule.min_consecutive_days if isinstance(rule, StalledDeliveryRule) else rule.lookback_days))
        w_start, w_stop = _safe_shift_date(end_d, span - 1, label=f"policy.rule[{rule.rule_id!r}]"), end_d.isoformat()
        if w_start < ctx.inventory.date_range.start_date or w_stop > ctx.inventory.date_range.end_date:
            raise ClosedValidationError(f"policy rule {rule.rule_id!r}: window outside ExpectedResourceInventory")
        if isinstance(rule, RestatementRule) and (w_start < cur_start or w_stop > cur_end):
            raise ClosedValidationError(f"policy rule {rule.rule_id!r}: restatement window outside curation window")

def _reduce_snapshot_and_build_context(fresh_in: ConductorRunInput, snapshot: DatasetSnapshot, snapshot_rows: tuple[AnalyticsLandingRow, ...], inv: ExpectedResourceInventory, pol: AnalysisPolicy, scope: EvaluationScope, analysis_exec: AnalysisExecution, ordered_evidence: tuple[AnalysisEvidence, ...], *, proxy_store: _SignatureVerifyingStoreProxy, require_signed: bool) -> tuple[int, str, EvaluationContext]:
    cut_rec = _load_p1(proxy_store, snapshot.catalog_cut_receipt_locator, DatasetCatalogCutReceipt, field_name="snapshot.catalog_cut_receipt_locator", require_signed=require_signed)
    if cut_rec.migration_run_context_locator != fresh_in.migration_run_context_locator:
        raise ClosedValidationError("dataset_snapshot: cross-run DatasetCatalogCutReceipt forbidden")
    gen_by_key, _, decoded_by_ref = _load_snapshot_lineage_generations(snapshot, proxy_store=proxy_store, parquet_codec=fresh_in.parquet_codec, require_signed=require_signed)
    head_by_pk = {h.partition_key: h.generation_manifest_locator for h in snapshot.partition_heads}
    gm_loc = head_by_pk.get(partition_key_for_metric_date(fresh_in.window_end_date), cut_rec.cas_request_projection.generation_manifest_locator)
    cur_exec = _load_p1(proxy_store, gen_by_key[canonicalize_jcs(gm_loc.to_dict())].curation_execution_locator, CurationExecution, field_name="curation_execution_locator", require_signed=require_signed)
    allowed_units = {(u.binding_ref, u.account_ref, u.resource_ref, u.resource_level, u.metric_date) for u in inv.expected_resources}
    reduced_rows, _ = compute_logical_rows_digest([
        r for r in snapshot_rows
        if (r.fact_key.binding_ref, r.fact_key.account_ref, r.fact_key.resource_ref, r.fact_key.resource_level, r.fact_key.metric_date) in allowed_units
        and inv.date_range.start_date <= r.fact_key.metric_date <= fresh_in.window_end_date
    ])
    lineage_rows = (r for k in sorted(gen_by_key) for r in decoded_by_ref[gen_by_key[k].locator().object_ref] if r.fact_key.metric_date <= fresh_in.window_end_date)
    m_keys = [e.result_key for e in analysis_exec.canonical_result_set.results if e.result_projection.result_kind == "relation" and tuple((c.name, c.cell_type, c.nullable) for c in e.result_projection.columns) == METRIC_WINDOW_COLUMNS]
    metrics_key = "result:metrics" if "result:metrics" in m_keys else (m_keys[0] if m_keys else analysis_exec.canonical_result_set.results[0].result_key)
    eval_ctx = EvaluationContext(pol, scope, fresh_in.evaluation_instant_utc, fresh_in.window_end_date, cur_exec.restatement_lookback_days, cur_exec.curation_anchor_date, inv, metrics_key, derive_snapshot_restatement_history(inv, lineage_rows))
    _check_policy_rule_windows(eval_ctx)
    ev_digest = jcs_sha256({"dataset_snapshot_digest": snapshot.snapshot_digest, "window_end_date": fresh_in.window_end_date, "reduced_rows": [r.to_dict() for r in reduced_rows], "analysis_evidence": [_evidence_to_jcs_dict(ev) for ev in ordered_evidence]})
    return len(reduced_rows), ev_digest, eval_ctx

def _build_conductor_certification(sorted_findings: tuple[Finding, ...], fresh_in: ConductorRunInput, analysis_exec: AnalysisExecution, *, require_signed: bool) -> AnalyticalCertificationRecord:
    if require_signed and fresh_in.certification_integrity is not None and not fresh_in.certification_integrity.is_signed:
        raise ClosedValidationError("certification_integrity: unsigned P1Integrity stub forbidden when require_signed=True")
    attested = combine_derived_certification(tuple(i.certification_input for i in fresh_in.attested_certification_inputs))
    degraded = DerivedCertificationStatus.DEGRADED
    if attested is degraded and not any(i.independently_validated and i.certification_input.status is degraded and i.certification_input.origin == "derived_input" for i in fresh_in.attested_certification_inputs):
        raise ClosedValidationError("attested_certification_inputs: DEGRADED requires independently validated derived_input")
    derived = min(attested, DerivedCertificationStatus.UNAVAILABLE) if any(f.finding_status == FINDING_INCONCLUSIVE for f in sorted_findings) else attested
    f_locs = sort_artifact_locators([f.locator() for f in sorted_findings], expected_type=Finding.SCHEMA, allow_empty=True, field_name="finding_locators")
    cert_rec = AnalyticalCertificationRecord(f_locs, derived, any(f.mutation_recommendation_blocked for f in sorted_findings), analysis_exec.canonical_result_set.canonical_result_digest, fresh_in.certification_integrity)
    if cert_rec.integrity is not None and cert_rec.integrity.is_signed and fresh_in.signature_verifier is not None:
        _invoke_sig_verifier(fresh_in.signature_verifier, envelope=cert_rec.to_dict(), domain_prefix=AnalyticalCertificationRecord.P1_DOMAIN_PREFIX, store=fresh_in.store)
    return cert_rec

def _validate_findings_and_certify(raw_findings: object, fresh_in: ConductorRunInput, pol: AnalysisPolicy, analysis_exec: AnalysisExecution, *, require_signed: bool) -> tuple[tuple[Finding, ...], tuple[str, ...], AnalyticalCertificationRecord]:
    if not isinstance(raw_findings, (list, tuple)):
        raise ClosedValidationError("evaluate_offline: expected list or tuple of Finding")
    allowed_types = frozenset(rule.RULE_TYPE for rule in pol.rules)
    validated, seen_fkeys = [], set()
    for idx, item in enumerate(raw_findings):
        if type(item) is not Finding or (require_signed and item.integrity is not None and not item.integrity.is_signed):
            raise ClosedValidationError(f"findings[{idx}]: expected Finding without unsigned P1 stub")
        fresh = Finding.from_dict(item.to_dict(), require_signed=require_signed and item.integrity is not None and item.integrity.is_signed)
        if fresh != item or canonicalize_jcs(fresh.to_dict()) != canonicalize_jcs(item.to_dict()):
            raise ClosedValidationError(f"findings[{idx}]: corrupted in-memory Finding")
        if fresh.integrity is not None and fresh.integrity.is_signed and fresh_in.signature_verifier is not None:
            _invoke_sig_verifier(fresh_in.signature_verifier, envelope=fresh.to_dict(), domain_prefix=Finding.P1_DOMAIN_PREFIX, store=fresh_in.store)
        if (fresh.analysis_execution_locator, fresh.analysis_policy_locator) != (fresh_in.analysis_execution_locator, fresh_in.analysis_policy_locator) or fresh.finding_type not in allowed_types:
            raise ClosedValidationError(f"findings[{idx}]: execution/policy locator or policy finding_type mismatch")
        if analysis_exec.canonical_result_set.entry(fresh.result_key).result_locator != fresh.result_locator or not set(fresh.evidence_locators).issubset({fresh.result_locator, fresh_in.dataset_snapshot_locator}) or fresh.finding_key in seen_fkeys:
            raise ClosedValidationError(f"findings[{idx}]: result_locator, evidence_locators, or duplicate finding_key violation")
        seen_fkeys.add(fresh.finding_key)
        validated.append(fresh)
    sorted_f = tuple(sorted(validated, key=lambda f: f.finding_key.encode("utf-8")))
    f_digs = sort_utf8_strings([f.finding_digest for f in sorted_f], allow_empty=True, field_name="finding_digests", validator=lambda d: validate_sha256_prefixed(d, field_name="finding_digests"))
    return sorted_f, f_digs, _build_conductor_certification(sorted_f, fresh_in, analysis_exec, require_signed=require_signed)


def conduct_offline_run(*, run_input: ConductorRunInput, intelligence: OfflineIntelligencePort) -> ConductorRunOutcome:
    """Execute offline verification, snapshot reduction, injected intelligence, and certification."""
    if type(run_input) is not ConductorRunInput or not isinstance(intelligence, OfflineIntelligencePort) or not callable(getattr(intelligence, "evaluate_offline", None)):
        raise ClosedValidationError("conduct_offline_run: expected ConductorRunInput and OfflineIntelligencePort")
    fresh_in = ConductorRunInput(run_input.migration_run_context_locator, run_input.dataset_snapshot_locator, run_input.expected_resource_inventory_locator, run_input.analysis_policy_locator, run_input.analysis_execution_locator, run_input.evaluation_instant_utc, run_input.window_end_date, run_input.attested_certification_inputs, run_input.resolved_analysis_results, run_input.analysis_evidence, run_input.certification_integrity, store=run_input.store, parquet_codec=run_input.parquet_codec, signature_verifier=run_input.signature_verifier, require_signed=run_input.require_signed)
    proxy_store, checked_codec, checked_req = _prepare_read_ports(store=fresh_in.store, parquet_codec=fresh_in.parquet_codec, signature_verifier=fresh_in.signature_verifier, require_signed=fresh_in.require_signed)
    checked_alg = _verify_algorithm_with_sig(intelligence.algorithm_identity, expected_schema_id=Finding.SCHEMA, store=fresh_in.store, signature_verifier=fresh_in.signature_verifier, require_signed=checked_req, label="intelligence.algorithm_identity")
    run_ctx = verify_stored_migration_run_context(fresh_in.store, fresh_in.migration_run_context_locator, signature_verifier=fresh_in.signature_verifier, require_signed=checked_req)
    snapshot, snapshot_rows = load_verified_snapshot_rows(fresh_in.dataset_snapshot_locator, store=fresh_in.store, parquet_codec=checked_codec, signature_verifier=fresh_in.signature_verifier, require_signed=checked_req)
    inv, pol, scope = _load_verified_scope_and_policy(fresh_in, run_ctx, proxy_store=proxy_store, require_signed=checked_req)
    analysis_exec, sorted_results, sorted_schemas = _verify_execution_and_results(fresh_in.analysis_execution_locator, fresh_in.resolved_analysis_results, None, fresh_in, inv, proxy_store=proxy_store, require_signed=checked_req, label="analysis_execution")
    ordered_ev = _canonicalize_evidence_set(fresh_in, inv, analysis_exec, sorted_results, sorted_schemas, proxy_store=proxy_store, require_signed=checked_req)
    row_count, ev_digest, eval_ctx = _reduce_snapshot_and_build_context(fresh_in, snapshot, snapshot_rows, inv, pol, scope, analysis_exec, ordered_ev, proxy_store=proxy_store, require_signed=checked_req)
    raw_findings = intelligence.evaluate_offline(context=eval_ctx, evidence=ordered_ev)
    sorted_findings, finding_digests, cert_rec = _validate_findings_and_certify(raw_findings, fresh_in, pol, analysis_exec, require_signed=checked_req)
    return ConductorRunOutcome(fresh_in.migration_run_context_locator, fresh_in.dataset_snapshot_locator, snapshot.snapshot_digest, fresh_in.expected_resource_inventory_locator, fresh_in.analysis_policy_locator, fresh_in.analysis_execution_locator, checked_alg, row_count, ev_digest, sorted_findings, finding_digests, cert_rec)


__all__ = ["CONDUCTOR_RUN_OUTCOME_SCHEMA", "ConductorRunInput", "ConductorRunOutcome", "conduct_offline_run"]
