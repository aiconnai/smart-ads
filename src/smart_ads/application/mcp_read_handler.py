"""Verified snapshot row loader, pre-verified read index, and read-only MCP handler (ADR-0001 §3.3)."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import hashlib
from types import MappingProxyType
from typing import Any, Final, TypeAlias

from smart_ads.analytics.cells import AnalysisResultSchema
from smart_ads.analytics.certification import AnalyticalCertificationRecord, verify_certification_record
from smart_ads.analytics.intelligence import AnalysisEvidence, EvaluationContext, Finding
from smart_ads.analytics.policy import AnalysisPolicy, EvaluationScope
from smart_ads.analytics.replay_bundle import AnalysisReplayInputBundle
from smart_ads.analytics.reporting import CanonicalReportInput, CanonicalReportResult, ReportExecution, derive_snapshot_restatement_history, verify_report_execution
from smart_ads.analytics.results import AnalysisExecution, AnalysisResult
from smart_ads.application.curation_pipeline import _load_p1, _require_parquet_codec, _require_store_and_bool, verify_curation_execution, verify_dataset_snapshot, verify_operational_read_evidence
from smart_ads.application.duckdb_execution import _resolve_verified_execution_and_results, _verify_replay_bundle_inputs_and_binaries
from smart_ads.application.predecessor_validators import PREDECESSOR_P1_DOMAIN_PREFIXES, verify_stored_migration_run_context
from smart_ads.contracts.effects import _typed_locator, sort_artifact_locators
from smart_ads.contracts.git_provenance import GitArtifactProvenance
from smart_ads.contracts.jcs import ADR_P1_DOMAIN_PREFIXES, ArtifactLocator, P1Integrity, canonicalize_jcs
from smart_ads.contracts.operational_evidence import OperationalReadEvidence
from smart_ads.contracts.scalars import ClosedValidationError, parse_iso_date, parse_timestamp_utc_micros, require_mapping, validate_iso_date, validate_opaque_ref
from smart_ads.contracts.schemas import AnalyticsLandingRow
from smart_ads.domain.catalog import DatasetCatalogCutReceipt, DatasetSnapshot, GenerationManifest, compute_logical_rows_digest
from smart_ads.domain.curation import CurationExecution, partition_key_for_metric_date
from smart_ads.domain.registry import AuthorizedScopeRelation, ExpectedResourceInventory, PrivateRegistrySnapshot, RegistryBinding
from smart_ads.ports.consumer import P1SignatureVerifierPort
from smart_ads.ports.storage import CellObjectStorePort, ParquetLandingCodecPort
from smart_ads.transports.mcp.gateway import AdmittedMcpRequest, McpReadHandlerPort
from smart_ads.transports.mcp.schemas import (
    IntelligenceFindingsQueryParams, PerformanceQueryParams, RecurrentSummaryReportParams,
)

_ScopeKey: TypeAlias = tuple[str, str, str]
_FindingsInputTuple: TypeAlias = tuple[
    ArtifactLocator, str, str, str, ArtifactLocator, ArtifactLocator,
    Sequence[ArtifactLocator], CanonicalReportInput | ArtifactLocator,
]
_SummaryInputTuple: TypeAlias = tuple[ArtifactLocator, str, str, str, str, str, str, ArtifactLocator]
_SnapMemoEntry: TypeAlias = tuple[DatasetSnapshot, ArtifactLocator, dict[str, Any]]

_INDEX_BUILD_GUARD: Final[object] = object()
_DEFERRED_PERF_METHODS: Final[frozenset[str]] = frozenset(
    {"smart_ads.queries.get_ad_performance_v1", "smart_ads.queries.get_adset_performance_v1"}
)
_CAMPAIGN_PERF_METHOD: Final[str] = "smart_ads.queries.get_campaign_performance_v1"
_FINDINGS_METHOD: Final[str] = "smart_ads.queries.get_intelligence_findings_v1"
_SUMMARY_METHOD: Final[str] = "smart_ads.reports.generate_recurrent_summary_v1"
_ALLOWED_CADENCES: Final[frozenset[str]] = frozenset({"daily", "weekly"})


class _SignatureVerifyingStoreProxy(CellObjectStorePort):
    """Read-only `CellObjectStorePort` proxy enforcing Layer-3 JCS and P1 signature checks."""

    def __init__(
        self, store: CellObjectStorePort, *, signature_verifier: P1SignatureVerifierPort | None, require_signed: bool = True
    ) -> None:
        self._store = store
        self._signature_verifier = signature_verifier
        self._require_signed = require_signed
        self._verified_p1: set[tuple[str, str]] = set()

    def put_bytes(self, raw: bytes) -> str:
        raise ClosedValidationError("read-only MCP verification store forbids put_bytes")

    def get_bytes(self, object_ref: str, *, expected_size_bytes: int | None = None) -> bytes:
        try:
            return self._store.get_bytes(object_ref, expected_size_bytes=expected_size_bytes)
        except ClosedValidationError:
            raise
        except Exception as exc:
            raise ClosedValidationError(f"store.get_bytes failed: {exc}") from exc

    def has_object(self, object_ref: str) -> bool:
        return self._store.has_object(object_ref)

    def put_json_artifact(self, schema_id: str, payload: Mapping[str, Any]) -> ArtifactLocator:
        raise ClosedValidationError("read-only MCP verification store forbids put_json_artifact")

    def get_json_artifact(self, locator: ArtifactLocator) -> dict[str, Any]:
        if type(locator) is not ArtifactLocator:
            raise ClosedValidationError("locator: expected ArtifactLocator")
        checked_loc = ArtifactLocator.from_dict(locator.to_dict())
        try:
            raw_obj = self._store.get_json_artifact(checked_loc)
        except ClosedValidationError:
            raise
        except Exception as exc:
            raise ClosedValidationError(f"store.get_json_artifact failed: {exc}") from exc
        raw_dict = dict(require_mapping(raw_obj, label="store.get_json_artifact"))
        if ArtifactLocator.for_canonical_bytes(checked_loc.artifact_type, canonicalize_jcs(raw_dict)) != checked_loc:
            raise ClosedValidationError("store.get_json_artifact: Layer-3 canonical digest mismatch")
        domain_prefix = ADR_P1_DOMAIN_PREFIXES.get(checked_loc.artifact_type) or PREDECESSOR_P1_DOMAIN_PREFIXES.get(checked_loc.artifact_type)
        if self._signature_verifier is not None and domain_prefix is not None:
            should_verify = self._require_signed or ("integrity" in raw_dict and P1Integrity.from_dict(raw_dict["integrity"]).is_signed)
            memo_key = (checked_loc.artifact_type, checked_loc.content_digest)
            if should_verify and memo_key not in self._verified_p1:
                try:
                    self._signature_verifier.verify_p1_envelope_signature(
                        envelope=raw_dict, domain_prefix=domain_prefix, store=self._store
                    )
                except ClosedValidationError:
                    raise
                except Exception as exc:
                    raise ClosedValidationError(f"P1 signature verification failed: {exc}") from exc
                self._verified_p1.add(memo_key)
        return raw_dict


def _prepare_read_ports(
    *, store: object, parquet_codec: object, signature_verifier: object, require_signed: object
) -> tuple[_SignatureVerifyingStoreProxy, ParquetLandingCodecPort, bool]:
    checked_store = _require_store_and_bool(store, require_signed)
    checked_codec = _require_parquet_codec(parquet_codec)
    checked_req = bool(require_signed)
    if checked_req and signature_verifier is None:
        raise ClosedValidationError("signature_verifier: P1SignatureVerifierPort required when require_signed=True")
    if signature_verifier is not None and (
        not isinstance(signature_verifier, P1SignatureVerifierPort)
        or not callable(getattr(signature_verifier, "verify_p1_envelope_signature", None))
    ):
        raise ClosedValidationError("signature_verifier: expected P1SignatureVerifierPort")
    return _SignatureVerifyingStoreProxy(checked_store, signature_verifier=signature_verifier, require_signed=checked_req), checked_codec, checked_req


def _decode_manifest_rows(
    gm: GenerationManifest, *, store: CellObjectStorePort, parquet_codec: ParquetLandingCodecPort
) -> tuple[AnalyticsLandingRow, ...]:
    decoded_rows: list[AnalyticsLandingRow] = []
    for pq in gm.parquet_object_locators:
        if pq.partition_key != gm.partition_key:
            raise ClosedValidationError("generation_manifest: Parquet locator partition_key mismatch")
        raw_pq = store.get_bytes(pq.object_ref, expected_size_bytes=pq.size_bytes)
        if len(raw_pq) != pq.size_bytes or "sha256:" + hashlib.sha256(raw_pq).hexdigest() != pq.physical_parquet_digest:
            raise ClosedValidationError("generation_manifest: Parquet SHA-256 or size mismatch")
        part_rows = parquet_codec.decode_and_verify_landing_rows(raw_pq, expected_partition_key=pq.partition_key)
        if any(partition_key_for_metric_date(r.fact_key.metric_date) != pq.partition_key for r in part_rows):
            raise ClosedValidationError("generation_manifest: decoded row partition_key mismatch")
        decoded_rows.extend(part_rows)
    ordered_rows, part_digest = compute_logical_rows_digest(decoded_rows)
    if part_digest != gm.logical_rows_digest or len(ordered_rows) != gm.row_count:
        raise ClosedValidationError("generation_manifest: logical_rows_digest or row_count mismatch")
    return ordered_rows


def _verify_snapshot_run_context(
    snapshot: DatasetSnapshot, *, proxy_store: _SignatureVerifyingStoreProxy, require_signed: bool
) -> tuple[ArtifactLocator, dict[str, Any]]:
    cut = _load_p1(proxy_store, snapshot.catalog_cut_receipt_locator, DatasetCatalogCutReceipt, field_name="snapshot.catalog_cut_receipt_locator", require_signed=require_signed)
    proxy_store.get_json_artifact(cut.migration_run_context_locator)
    run_ctx = verify_stored_migration_run_context(proxy_store._store, cut.migration_run_context_locator, signature_verifier=proxy_store._signature_verifier, require_signed=require_signed)
    return cut.migration_run_context_locator, run_ctx


def _load_snapshot_rows_from_proxy(
    snapshot_locator: ArtifactLocator, *, proxy_store: _SignatureVerifyingStoreProxy,
    parquet_codec: ParquetLandingCodecPort, require_signed: bool,
) -> tuple[ArtifactLocator, DatasetSnapshot, tuple[AnalyticsLandingRow, ...], ArtifactLocator, dict[str, Any]]:
    checked_loc = _typed_locator(snapshot_locator, field_name="snapshot_locator", expected_type=DatasetSnapshot.SCHEMA)
    snap = _load_p1(proxy_store, checked_loc, DatasetSnapshot, field_name="snapshot_locator", require_signed=require_signed)
    verified_snap = verify_dataset_snapshot(snap, store=proxy_store, parquet_codec=parquet_codec, require_signed=require_signed)
    run_loc, run_ctx = _verify_snapshot_run_context(verified_snap, proxy_store=proxy_store, require_signed=require_signed)
    all_rows: list[AnalyticsLandingRow] = []
    for head in verified_snap.partition_heads:
        gm = _load_p1(
            proxy_store, head.generation_manifest_locator, GenerationManifest,
            field_name="snapshot.partition_heads[].generation_manifest_locator", require_signed=require_signed,
        )
        if gm.partition_key != head.partition_key:
            raise ClosedValidationError("dataset_snapshot: head partition_key mismatch")
        all_rows.extend(_decode_manifest_rows(gm, store=proxy_store, parquet_codec=parquet_codec))
    sorted_rows, _ = compute_logical_rows_digest(all_rows)
    return checked_loc, verified_snap, sorted_rows, run_loc, run_ctx


def load_verified_snapshot_rows(
    snapshot_locator: ArtifactLocator,
    *,
    store: CellObjectStorePort,
    parquet_codec: ParquetLandingCodecPort,
    signature_verifier: P1SignatureVerifierPort | None = None,
    require_signed: bool = True,
) -> tuple[DatasetSnapshot, tuple[AnalyticsLandingRow, ...]]:
    """Verify `DatasetSnapshot`, `migration_run_context/v1`, active `GenerationManifest`s, and Parquet v1 rows."""
    proxy_store, checked_codec, checked_req = _prepare_read_ports(
        store=store, parquet_codec=parquet_codec, signature_verifier=signature_verifier, require_signed=require_signed
    )
    _, verified_snap, sorted_rows, _, _ = _load_snapshot_rows_from_proxy(
        snapshot_locator, proxy_store=proxy_store, parquet_codec=checked_codec, require_signed=checked_req
    )
    return verified_snap, sorted_rows


@dataclass(frozen=True, slots=True)
class _VerifiedFindingsEntry:
    dataset_snapshot_locator: ArtifactLocator
    certification_record: AnalyticalCertificationRecord
    findings: tuple[Finding, ...]


@dataclass(frozen=True, slots=True)
class _VerifiedSummaryReportEntry:
    dataset_snapshot_locator: ArtifactLocator
    report_execution_locator: ArtifactLocator
    canonical_report_result: CanonicalReportResult


def _validate_scope_against_registry(
    tenant_ref: object, binding_ref: object, resource_scope_ref: object, *, registry: PrivateRegistrySnapshot, label: str
) -> tuple[_ScopeKey, RegistryBinding]:
    if type(tenant_ref) is not str or type(binding_ref) is not str or type(resource_scope_ref) is not str:
        raise ClosedValidationError(f"{label}: scope refs must be exact str")
    checked_t = validate_opaque_ref(tenant_ref, field_name=f"{label}.tenant_ref", expected_prefix="tenant")
    checked_b = validate_opaque_ref(binding_ref, field_name=f"{label}.binding_ref", expected_prefix="binding")
    checked_s = validate_opaque_ref(resource_scope_ref, field_name=f"{label}.resource_scope_ref", expected_prefix="scope")
    if checked_t != registry.tenant_ref:
        raise ClosedValidationError(f"{label}: tenant_ref {checked_t!r} != registry.tenant_ref")
    if not any(r.binding_ref == checked_b and r.resource_scope_ref == checked_s for r in registry.authorized_scopes):
        raise ClosedValidationError(f"{label}: ({checked_b!r}, {checked_s!r}) absent from registry.authorized_scopes")
    return (checked_t, checked_b, checked_s), registry.get_binding(checked_b)


def _load_verified_inventory(
    proxy_store: _SignatureVerifyingStoreProxy, inv_locator: ArtifactLocator, *, registry_locator: ArtifactLocator,
    scope_key: _ScopeKey, expected_account_ref: str, require_signed: bool, label: str,
) -> ExpectedResourceInventory:
    inv = _load_p1(proxy_store, inv_locator, ExpectedResourceInventory, field_name=label, require_signed=require_signed)
    if (inv.registry_snapshot_locator, (inv.tenant_ref, inv.binding_ref, inv.resource_scope_ref), inv.account_ref) != (
        registry_locator, scope_key, expected_account_ref
    ):
        raise ClosedValidationError(f"{label}: inventory registry/tenant/binding/account/scope mismatch")
    return inv


def _get_or_verify_snapshot(
    snap_locator: ArtifactLocator, *, expected_tenant_ref: str, proxy_store: _SignatureVerifyingStoreProxy,
    parquet_codec: ParquetLandingCodecPort, require_signed: bool, snap_memo: dict[bytes, _SnapMemoEntry], label: str,
) -> tuple[ArtifactLocator, DatasetSnapshot, ArtifactLocator]:
    checked_loc = _typed_locator(snap_locator, field_name=label, expected_type=DatasetSnapshot.SCHEMA)
    memo_key = canonicalize_jcs(checked_loc.to_dict())
    cached = snap_memo.get(memo_key)
    if cached is not None:
        if cached[2]["tenant_ref"] != expected_tenant_ref:
            raise ClosedValidationError(f"{label}: migration_run_context.tenant_ref mismatch")
        return checked_loc, cached[0], cached[1]
    raw_snap = _load_p1(proxy_store, checked_loc, DatasetSnapshot, field_name=label, require_signed=require_signed)
    verified = verify_dataset_snapshot(raw_snap, store=proxy_store, parquet_codec=parquet_codec, require_signed=require_signed)
    run_loc, run_ctx = _verify_snapshot_run_context(verified, proxy_store=proxy_store, require_signed=require_signed)
    if run_ctx["tenant_ref"] != expected_tenant_ref:
        raise ClosedValidationError(f"{label}: migration_run_context.tenant_ref != registry.tenant_ref")
    snap_memo[memo_key] = (verified, run_loc, run_ctx)
    return checked_loc, verified, run_loc


def _load_execution_bundle_and_policy(
    exec_locator: ArtifactLocator, expected_snap_loc: ArtifactLocator, expected_run_loc: ArtifactLocator, *,
    proxy_store: _SignatureVerifyingStoreProxy, require_signed: bool,
) -> tuple[ArtifactLocator, AnalysisExecution, AnalysisReplayInputBundle, tuple[AnalysisResult, ...], tuple[AnalysisResultSchema, ...], AnalysisPolicy]:
    checked_exec_loc = _typed_locator(exec_locator, field_name="analysis_execution_locator", expected_type=AnalysisExecution.SCHEMA)
    raw_exec = _load_p1(proxy_store, checked_exec_loc, AnalysisExecution, field_name="analysis_execution_locator", require_signed=require_signed)
    bundle_loc = raw_exec.analysis_replay_input_bundle_locator
    bundle = _load_p1(proxy_store, bundle_loc, AnalysisReplayInputBundle, field_name="analysis_replay_input_bundle_locator", require_signed=require_signed)
    if (bundle.dataset_snapshot_locator, bundle.migration_run_context_locator) != (expected_snap_loc, expected_run_loc):
        raise ClosedValidationError("analysis_replay_input_bundle: snapshot or migration_run_context_locator mismatch")
    _verify_replay_bundle_inputs_and_binaries(bundle, store=proxy_store, require_signed=require_signed)
    v_exec, results, schemas = _resolve_verified_execution_and_results(
        bundle, bundle_loc, checked_exec_loc, store=proxy_store, require_signed=require_signed
    )
    policy = _load_p1(proxy_store, bundle.analysis_policy_locator, AnalysisPolicy, field_name="analysis_policy_locator", require_signed=require_signed)
    return checked_exec_loc, v_exec, bundle, results, schemas, policy


def _resolve_findings_eval_input(
    eval_spec: object, *, checked_snap_loc: ArtifactLocator, snap_run_loc: ArtifactLocator,
    checked_exec_loc: ArtifactLocator, cert_loc: ArtifactLocator,
    proxy_store: _SignatureVerifyingStoreProxy, require_signed: bool, label: str,
) -> CanonicalReportInput:
    if type(eval_spec) is CanonicalReportInput:
        fresh = CanonicalReportInput.from_dict(eval_spec.to_dict())
        if fresh != eval_spec:
            raise ClosedValidationError(f"{label}: corrupted CanonicalReportInput")
        return fresh
    if type(eval_spec) is ArtifactLocator:
        rep_loc = _typed_locator(eval_spec, field_name=label, expected_type=ReportExecution.SCHEMA)
        rep = _load_p1(proxy_store, rep_loc, ReportExecution, field_name=label, require_signed=require_signed)
        if (rep.dataset_snapshot_locator, rep.migration_run_context_locator, rep.analysis_execution_locator) != (
            checked_snap_loc, snap_run_loc, checked_exec_loc
        ) or cert_loc not in rep.certification_record_locators:
            raise ClosedValidationError(f"{label}: ReportExecution snapshot/run/execution/cert binding mismatch")
        return rep.canonical_report_input
    raise ClosedValidationError(f"{label}: expected CanonicalReportInput or ReportExecution ArtifactLocator")


def _build_verified_eval_context(
    rep_in: CanonicalReportInput, snapshot: DatasetSnapshot, snap_run_loc: ArtifactLocator, *,
    registry_locator: ArtifactLocator, scope_key: _ScopeKey, binding: RegistryBinding, policy: AnalysisPolicy,
    proxy_store: _SignatureVerifyingStoreProxy, parquet_codec: ParquetLandingCodecPort, require_signed: bool,
) -> tuple[ExpectedResourceInventory, CurationExecution, dict[bytes, GenerationManifest], dict[str, tuple[AnalyticsLandingRow, ...]], EvaluationContext]:
    if rep_in.dataset_snapshot_digest != snapshot.snapshot_digest:
        raise ClosedValidationError("canonical_report_input: dataset_snapshot_digest mismatch")
    inv = _load_verified_inventory(
        proxy_store, rep_in.expected_resource_inventory_locator, registry_locator=registry_locator,
        scope_key=scope_key, expected_account_ref=binding.account_ref, require_signed=require_signed, label="eval.inventory",
    )
    cur_exec = _load_p1(proxy_store, rep_in.curation_execution_locator, CurationExecution, field_name="eval.curation", require_signed=require_signed)
    verify_curation_execution(cur_exec, store=proxy_store, require_signed=require_signed)
    gen_by_key, active_keys, decoded_by_ref = _load_snapshot_lineage_generations(
        snapshot, proxy_store=proxy_store, parquet_codec=parquet_codec, require_signed=require_signed
    )
    if cur_exec.migration_run_context_locator != snap_run_loc or any(gm.migration_run_context_locator != snap_run_loc for gm in gen_by_key.values()):
        raise ClosedValidationError("eval_context: cross-run CurationExecution or GenerationManifest forbidden")
    if canonicalize_jcs(rep_in.curation_execution_locator.to_dict()) not in {canonicalize_jcs(gen_by_key[k].curation_execution_locator.to_dict()) for k in active_keys}:
        raise ClosedValidationError("eval_context: curation_execution_locator absent from active snapshot generations")
    hist_keys = {canonicalize_jcs(loc.to_dict()) for loc in rep_in.restatement_history_generation_locators}
    if not hist_keys.issubset(gen_by_key):
        raise ClosedValidationError("eval_context: restatement_history_generation_locators outside lineage")
    start_ym, end_ym = cur_exec.curation_window.start_date[:7], cur_exec.curation_window.end_date[:7]
    if any(start_ym <= f"{gen_by_key[ak].partition_key[5:9]}-{gen_by_key[ak].partition_key[16:18]}" <= end_ym and ak not in hist_keys for ak in set(gen_by_key) - active_keys):
        raise ClosedValidationError("eval_context: overlapping ancestor generation omitted from restatement_history_generation_locators")
    pool_rows = (r for k in sorted(active_keys | hist_keys) for r in decoded_by_ref[gen_by_key[k].locator().object_ref])
    eval_ctx = EvaluationContext(
        policy, EvaluationScope(scope_key[0], scope_key[2], "campaign", binding.ad_platform_ref, binding.currency),
        rep_in.evaluation_instant_utc, rep_in.window_end_date, cur_exec.restatement_lookback_days,
        cur_exec.curation_anchor_date, inv, rep_in.metrics_result_key, derive_snapshot_restatement_history(inv, pool_rows),
    )
    return inv, cur_exec, gen_by_key, decoded_by_ref, eval_ctx


def _load_and_replay_certified_findings(
    *, finding_locators: Sequence[ArtifactLocator], cert_locator: ArtifactLocator,
    rep_in: CanonicalReportInput, eval_ctx: EvaluationContext, evidence: AnalysisEvidence,
    proxy_store: _SignatureVerifyingStoreProxy, require_signed: bool,
) -> tuple[AnalyticalCertificationRecord, tuple[Finding, ...]]:
    if isinstance(finding_locators, (str, bytes)) or not isinstance(finding_locators, Sequence):
        raise ClosedValidationError("finding_locators: expected Sequence of ArtifactLocator")
    raw_locs = tuple(_typed_locator(loc, field_name="finding_locators[]", expected_type=Finding.SCHEMA) for loc in finding_locators)
    sorted_locs = sort_artifact_locators(raw_locs, expected_type=Finding.SCHEMA, allow_empty=True, field_name="finding_locators")
    findings = [_load_p1(proxy_store, loc, Finding, field_name="finding_locators[]", require_signed=require_signed) for loc in raw_locs]
    if len({f.finding_key for f in findings}) != len(findings):
        raise ClosedValidationError("finding_locators: duplicate finding_key")
    ordered = tuple(sorted(findings, key=lambda f: f.finding_key.encode("utf-8")))
    cert_rec = _load_p1(proxy_store, cert_locator, AnalyticalCertificationRecord, field_name="certification_record_locator", require_signed=require_signed)
    verify_certification_record(cert_rec, eval_ctx, evidence, ordered, rep_in.attested_certification_inputs)
    exp_fdigs = tuple(sorted((f.finding_digest for f in ordered), key=lambda s: s.encode("utf-8")))
    if (
        cert_rec.finding_locators != sorted_locs
        or rep_in.canonical_result_digest != evidence.execution.canonical_result_set.canonical_result_digest
        or (rep_in.derived_certification_status, rep_in.mutation_recommendations_blocked, rep_in.finding_digests)
        != (cert_rec.derived_certification_status, cert_rec.mutation_recommendations_blocked, exp_fdigs)
    ):
        raise ClosedValidationError("findings_entries: CanonicalReportInput or finding_locators mismatch against certified replay")
    return cert_rec, ordered


def _index_scope_inventories(
    scope_inventory_locators: Mapping[_ScopeKey, Sequence[ArtifactLocator]], *,
    registry: PrivateRegistrySnapshot, registry_locator: ArtifactLocator,
    proxy_store: _SignatureVerifyingStoreProxy, require_signed: bool,
) -> Mapping[_ScopeKey, tuple[ExpectedResourceInventory, ...]]:
    if not isinstance(scope_inventory_locators, Mapping):
        raise ClosedValidationError("scope_inventory_locators: expected Mapping")
    out: dict[_ScopeKey, tuple[ExpectedResourceInventory, ...]] = {}
    for raw_key, inv_locs in scope_inventory_locators.items():
        if type(raw_key) is not tuple or len(raw_key) != 3:
            raise ClosedValidationError("scope_inventory_locators: keys must be 3-tuples")
        scope_key, binding = _validate_scope_against_registry(*raw_key, registry=registry, label="scope_inventory_locators.key")
        if isinstance(inv_locs, (str, bytes)) or not isinstance(inv_locs, Sequence):
            raise ClosedValidationError("scope_inventory_locators.value: expected Sequence of ArtifactLocator")
        checked = tuple(_typed_locator(loc, field_name="scope_inventory_locators[]", expected_type=ExpectedResourceInventory.SCHEMA) for loc in inv_locs)
        if len({canonicalize_jcs(loc.to_dict()) for loc in checked}) != len(checked):
            raise ClosedValidationError("scope_inventory_locators: duplicate ExpectedResourceInventory locator")
        out[scope_key] = tuple(
            _load_verified_inventory(
                proxy_store, loc, registry_locator=registry_locator, scope_key=scope_key,
                expected_account_ref=binding.account_ref, require_signed=require_signed, label="scope_inventory_locators[]",
            )
            for loc in checked
        )
    return MappingProxyType(out)


def _index_findings_entries(
    findings_entries: Sequence[Any], *, registry: PrivateRegistrySnapshot, registry_locator: ArtifactLocator,
    proxy_store: _SignatureVerifyingStoreProxy, parquet_codec: ParquetLandingCodecPort,
    require_signed: bool, snap_memo: dict[bytes, _SnapMemoEntry],
) -> Mapping[tuple[str, str, str, str], _VerifiedFindingsEntry]:
    if isinstance(findings_entries, (str, bytes)) or not isinstance(findings_entries, Sequence):
        raise ClosedValidationError("findings_entries: expected Sequence")
    out: dict[tuple[str, str, str, str], _VerifiedFindingsEntry] = {}
    for idx, entry in enumerate(findings_entries):
        if type(entry) is not tuple or len(entry) != 8:
            raise ClosedValidationError(f"findings_entries[{idx}]: expected 8-tuple")
        snap_loc, t_ref, b_ref, s_ref, exec_loc, cert_loc, f_locs, eval_spec = entry
        scope_key, binding = _validate_scope_against_registry(t_ref, b_ref, s_ref, registry=registry, label=f"findings_entries[{idx}]")
        checked_snap_loc, snapshot, snap_run_loc = _get_or_verify_snapshot(
            snap_loc, expected_tenant_ref=registry.tenant_ref, proxy_store=proxy_store, parquet_codec=parquet_codec,
            require_signed=require_signed, snap_memo=snap_memo, label=f"findings_entries[{idx}].snapshot",
        )
        idx_key = (checked_snap_loc.content_digest, *scope_key)
        if idx_key in out:
            raise ClosedValidationError(f"findings_entries[{idx}]: duplicate index key")
        checked_exec_loc, v_exec, bundle, results, schemas, policy = _load_execution_bundle_and_policy(
            exec_loc, checked_snap_loc, snap_run_loc, proxy_store=proxy_store, require_signed=require_signed
        )
        checked_cert_loc = _typed_locator(cert_loc, field_name="certification_record_locator", expected_type=AnalyticalCertificationRecord.SCHEMA)
        rep_in = _resolve_findings_eval_input(
            eval_spec, checked_snap_loc=checked_snap_loc, snap_run_loc=snap_run_loc, checked_exec_loc=checked_exec_loc,
            cert_loc=checked_cert_loc, proxy_store=proxy_store, require_signed=require_signed, label=f"findings_entries[{idx}].eval_spec",
        )
        _, _, _, _, eval_ctx = _build_verified_eval_context(
            rep_in, snapshot, snap_run_loc, registry_locator=registry_locator, scope_key=scope_key,
            binding=binding, policy=policy, proxy_store=proxy_store, parquet_codec=parquet_codec, require_signed=require_signed,
        )
        evidence = AnalysisEvidence(v_exec, results, schemas, checked_snap_loc, bundle.analysis_policy_locator, require_signed, bundle.migration_run_context_locator)
        cert_rec, ordered = _load_and_replay_certified_findings(
            finding_locators=f_locs, cert_locator=checked_cert_loc, rep_in=rep_in, eval_ctx=eval_ctx,
            evidence=evidence, proxy_store=proxy_store, require_signed=require_signed,
        )
        out[idx_key] = _VerifiedFindingsEntry(checked_snap_loc, cert_rec, ordered)
    return MappingProxyType(out)


def _validate_summary_cadence_window(
    cadence: object, period_start_date: object, period_end_date: object, *, label: str
) -> tuple[str, str, str]:
    if type(cadence) is not str or cadence not in _ALLOWED_CADENCES:
        raise ClosedValidationError(f"{label}.cadence: expected 'daily' or 'weekly'")
    if type(period_start_date) is not str or type(period_end_date) is not str:
        raise ClosedValidationError(f"{label}: period dates must be exact str")
    validate_iso_date(period_start_date, field_name=f"{label}.period_start_date")
    validate_iso_date(period_end_date, field_name=f"{label}.period_end_date")
    start_d = parse_iso_date(period_start_date, field_name=f"{label}.period_start_date")
    end_d = parse_iso_date(period_end_date, field_name=f"{label}.period_end_date")
    if start_d > end_d:
        raise ClosedValidationError(f"{label}: period_start_date > period_end_date")
    if cadence == "daily" and period_start_date != period_end_date:
        raise ClosedValidationError(f"{label}: daily cadence requires period_start_date == period_end_date")
    if cadence == "weekly" and (end_d - start_d).days != 6:
        raise ClosedValidationError(f"{label}: weekly cadence requires 7-day inclusive window")
    return cadence, period_start_date, period_end_date


def _load_snapshot_lineage_generations(
    snapshot: DatasetSnapshot, *, proxy_store: _SignatureVerifyingStoreProxy,
    parquet_codec: ParquetLandingCodecPort, require_signed: bool,
) -> tuple[dict[bytes, GenerationManifest], set[bytes], dict[str, tuple[AnalyticsLandingRow, ...]]]:
    gen_by_key: dict[bytes, GenerationManifest] = {}
    active_keys: set[bytes] = set()
    decoded_by_ref: dict[str, tuple[AnalyticsLandingRow, ...]] = {}
    for head in snapshot.partition_heads:
        cur_loc: ArtifactLocator | None = head.generation_manifest_locator
        seq, seen = head.head_sequence_number, set()
        active_keys.add(canonicalize_jcs(head.generation_manifest_locator.to_dict()))
        while cur_loc is not None:
            g_key = canonicalize_jcs(cur_loc.to_dict())
            if g_key in seen:
                raise ClosedValidationError("report_execution: cycle in GenerationManifest lineage")
            seen.add(g_key)
            gm = gen_by_key.get(g_key)
            if gm is None:
                gm = _load_p1(proxy_store, cur_loc, GenerationManifest, field_name="lineage.generation_manifest_locator", require_signed=require_signed)
                gen_by_key[g_key] = gm
                decoded_by_ref[cur_loc.object_ref] = _decode_manifest_rows(gm, store=proxy_store, parquet_codec=parquet_codec)
            if gm.partition_key != head.partition_key or (seq == 1) != (gm.parent_generation_manifest_locator is None):
                raise ClosedValidationError("report_execution: lineage GenerationManifest sequence/parent mismatch")
            cur_loc, seq = gm.parent_generation_manifest_locator, seq - 1
    return gen_by_key, active_keys, decoded_by_ref


def _verify_report_transitive_graph(
    report: ReportExecution, snapshot: DatasetSnapshot, snap_loc: ArtifactLocator, snap_run_loc: ArtifactLocator, *,
    registry_locator: ArtifactLocator, scope_key: _ScopeKey, binding: RegistryBinding,
    proxy_store: _SignatureVerifyingStoreProxy, parquet_codec: ParquetLandingCodecPort, require_signed: bool,
) -> ExpectedResourceInventory:
    if report.migration_run_context_locator != snap_run_loc:
        raise ClosedValidationError("report_execution: migration_run_context_locator mismatch against snapshot")
    _, execution, bundle, results, schemas, policy = _load_execution_bundle_and_policy(
        report.analysis_execution_locator, snap_loc, snap_run_loc, proxy_store=proxy_store, require_signed=require_signed
    )
    inv, cur_exec, gen_by_key, decoded_by_ref, eval_ctx = _build_verified_eval_context(
        report.canonical_report_input, snapshot, snap_run_loc, registry_locator=registry_locator,
        scope_key=scope_key, binding=binding, policy=policy, proxy_store=proxy_store,
        parquet_codec=parquet_codec, require_signed=require_signed,
    )
    op_evs = tuple(_load_p1(proxy_store, loc, OperationalReadEvidence, field_name="report.evidences[]", require_signed=require_signed) for loc in report.operational_read_evidence_locators)
    for ev in op_evs:
        verify_operational_read_evidence(ev, store=proxy_store, require_signed=require_signed)
    findings = tuple(sorted((_load_p1(proxy_store, loc, Finding, field_name="report.findings[]", require_signed=require_signed) for loc in report.finding_locators), key=lambda f: f.finding_key.encode("utf-8")))
    certs = tuple(_load_p1(proxy_store, loc, AnalyticalCertificationRecord, field_name="report.certs[]", require_signed=require_signed) for loc in report.certification_record_locators)
    tmpl_prov = _load_p1(proxy_store, report.report_template_provenance_locator, GitArtifactProvenance, field_name="report.template", require_signed=require_signed)
    rnd_prov = _load_p1(proxy_store, report.render_algorithm_identity.git_artifact_provenance_locator, GitArtifactProvenance, field_name="report.render", require_signed=require_signed)
    verify_report_execution(
        report, snapshot=snapshot, curation_execution=cur_exec,
        generation_manifests=tuple(gen_by_key[k] for k in sorted(gen_by_key)),
        decoded_generation_rows=decoded_by_ref, operational_evidences=op_evs, replay_bundle=bundle,
        execution=execution, results=results, result_schemas=schemas, policy_obj=policy,
        findings=findings, certifications=certs, evaluation_context=eval_ctx,
        attested_inputs=report.canonical_report_input.attested_certification_inputs, template_provenance=tmpl_prov,
        render_provenance=rnd_prov, require_signed=require_signed,
    )
    return inv


def _index_summary_report_entries(
    summary_report_entries: Sequence[Any], *, registry: PrivateRegistrySnapshot, registry_locator: ArtifactLocator,
    proxy_store: _SignatureVerifyingStoreProxy, parquet_codec: ParquetLandingCodecPort,
    require_signed: bool, snap_memo: dict[bytes, _SnapMemoEntry],
) -> Mapping[tuple[str, str, str, str, str, str, str], _VerifiedSummaryReportEntry]:
    if isinstance(summary_report_entries, (str, bytes)) or not isinstance(summary_report_entries, Sequence):
        raise ClosedValidationError("summary_report_entries: expected Sequence")
    out: dict[tuple[str, str, str, str, str, str, str], _VerifiedSummaryReportEntry] = {}
    for idx, entry in enumerate(summary_report_entries):
        if type(entry) is not tuple or len(entry) != 8:
            raise ClosedValidationError(f"summary_report_entries[{idx}]: expected 8-tuple")
        snap_loc, t_ref, b_ref, s_ref, cadence, p_start, p_end, rep_loc = entry
        scope_key, binding = _validate_scope_against_registry(t_ref, b_ref, s_ref, registry=registry, label=f"summary_report_entries[{idx}]")
        c_cadence, c_start, c_end = _validate_summary_cadence_window(cadence, p_start, p_end, label=f"summary_report_entries[{idx}]")
        checked_snap_loc, snapshot, snap_run_loc = _get_or_verify_snapshot(
            snap_loc, expected_tenant_ref=registry.tenant_ref, proxy_store=proxy_store, parquet_codec=parquet_codec,
            require_signed=require_signed, snap_memo=snap_memo, label=f"summary_report_entries[{idx}].snapshot",
        )
        idx_key = (checked_snap_loc.content_digest, *scope_key, c_cadence, c_start, c_end)
        if idx_key in out:
            raise ClosedValidationError(f"summary_report_entries[{idx}]: duplicate index key")
        checked_rep_loc = _typed_locator(rep_loc, field_name="report_execution_locator", expected_type=ReportExecution.SCHEMA)
        report = _load_p1(proxy_store, checked_rep_loc, ReportExecution, field_name="report_execution_locator", require_signed=require_signed)
        if report.dataset_snapshot_locator != checked_snap_loc or report.canonical_report_input.window_end_date != c_end:
            raise ClosedValidationError(f"summary_report_entries[{idx}]: report snapshot or window_end_date mismatch")
        inv = _verify_report_transitive_graph(
            report, snapshot, checked_snap_loc, snap_run_loc, registry_locator=registry_locator, scope_key=scope_key,
            binding=binding, proxy_store=proxy_store, parquet_codec=parquet_codec, require_signed=require_signed,
        )
        if not (inv.date_range.start_date <= c_start and c_end <= inv.date_range.end_date):
            raise ClosedValidationError(f"summary_report_entries[{idx}]: inventory date_range does not cover [{c_start!r}, {c_end!r}]")
        out[idx_key] = _VerifiedSummaryReportEntry(checked_snap_loc, checked_rep_loc, report.canonical_report_result)
    return MappingProxyType(out)


@dataclass(frozen=True, slots=True)
class McpVerifiedReadIndex:
    """Immutable, eagerly verified runtime index serving `VerifiedStoreMcpReadHandler`."""

    registry_snapshot_locator: ArtifactLocator
    registry_snapshot: PrivateRegistrySnapshot
    active_dataset_snapshot_locator: ArtifactLocator
    active_snapshot: DatasetSnapshot
    active_rows: tuple[AnalyticsLandingRow, ...]
    scope_inventories: Mapping[_ScopeKey, tuple[ExpectedResourceInventory, ...]]
    findings_index: Mapping[tuple[str, str, str, str], _VerifiedFindingsEntry]
    summary_reports_index: Mapping[tuple[str, str, str, str, str, str, str], _VerifiedSummaryReportEntry]
    require_signed: bool
    run_context_locators: frozenset[ArtifactLocator]
    _parquet_codec: ParquetLandingCodecPort
    _scope_inventory_locators: Mapping[_ScopeKey, tuple[ArtifactLocator, ...]]
    _findings_entries: tuple[_FindingsInputTuple, ...]
    _summary_report_entries: tuple[_SummaryInputTuple, ...]
    _build_guard: object

    def __post_init__(self) -> None:
        if self._build_guard is not _INDEX_BUILD_GUARD:
            raise ClosedValidationError("McpVerifiedReadIndex must be constructed via McpVerifiedReadIndex.build()")

    @classmethod
    def build(
        cls,
        active_dataset_snapshot_locator: ArtifactLocator,
        registry_snapshot_locator: ArtifactLocator,
        scope_inventory_locators: Mapping[_ScopeKey, Sequence[ArtifactLocator]],
        findings_entries: Sequence[_FindingsInputTuple] = (),
        summary_report_entries: Sequence[_SummaryInputTuple] = (),
        *,
        store: CellObjectStorePort,
        parquet_codec: ParquetLandingCodecPort,
        signature_verifier: P1SignatureVerifierPort | None = None,
        require_signed: bool = True,
    ) -> McpVerifiedReadIndex:
        """Eagerly verify and cache registry, snapshot rows, inventories, findings, and reports."""
        proxy_store, checked_codec, checked_req = _prepare_read_ports(store=store, parquet_codec=parquet_codec, signature_verifier=signature_verifier, require_signed=require_signed)
        checked_reg_loc = _typed_locator(registry_snapshot_locator, field_name="registry_snapshot_locator", expected_type=PrivateRegistrySnapshot.SCHEMA)
        registry = _load_p1(proxy_store, checked_reg_loc, PrivateRegistrySnapshot, field_name="registry_snapshot_locator", require_signed=checked_req)
        checked_act_loc, active_snap, active_rows, act_run_loc, act_run_ctx = _load_snapshot_rows_from_proxy(active_dataset_snapshot_locator, proxy_store=proxy_store, parquet_codec=checked_codec, require_signed=checked_req)
        if act_run_ctx["tenant_ref"] != registry.tenant_ref:
            raise ClosedValidationError("active_dataset_snapshot: migration_run_context.tenant_ref != registry.tenant_ref")
        snap_memo: dict[bytes, _SnapMemoEntry] = {canonicalize_jcs(checked_act_loc.to_dict()): (active_snap, act_run_loc, act_run_ctx)}
        scope_invs = _index_scope_inventories(scope_inventory_locators, registry=registry, registry_locator=checked_reg_loc, proxy_store=proxy_store, require_signed=checked_req)
        findings_idx = _index_findings_entries(findings_entries, registry=registry, registry_locator=checked_reg_loc, proxy_store=proxy_store, parquet_codec=checked_codec, require_signed=checked_req, snap_memo=snap_memo)
        reports_idx = _index_summary_report_entries(summary_report_entries, registry=registry, registry_locator=checked_reg_loc, proxy_store=proxy_store, parquet_codec=checked_codec, require_signed=checked_req, snap_memo=snap_memo)
        frozen_invs = MappingProxyType({k: tuple(v) for k, v in scope_inventory_locators.items()})
        frozen_f = tuple((*e[:6], tuple(e[6]), e[7]) for e in findings_entries)
        frozen_s = tuple(tuple(e) for e in summary_report_entries)  # type: ignore[misc]
        run_locs = frozenset(entry[1] for entry in snap_memo.values())
        return cls(
            checked_reg_loc, registry, checked_act_loc, active_snap, active_rows, scope_invs, findings_idx,
            reports_idx, checked_req, run_locs, checked_codec, frozen_invs, frozen_f, frozen_s, _INDEX_BUILD_GUARD,  # type: ignore[arg-type]
        )


def _project_campaign_landing_row(row: AnalyticsLandingRow, *, expected_currency: str) -> dict[str, Any]:
    if row.currency is not None and row.currency != expected_currency:
        raise ClosedValidationError("landing_row: currency mismatch against RegistryBinding")
    return {
        "fact_key": row.fact_key.to_dict(), "value_type": row.value_type,
        "raw_numeric_value": row.raw_numeric_value, "unit": row.unit, "currency": row.currency,
        "presence_status": row.presence_status, "unknown_reason": row.unknown_reason,
        "calculation_status": row.calculation_status,
    }


def _resolve_covering_scope_pairs(
    inventories: tuple[ExpectedResourceInventory, ...], params: PerformanceQueryParams
) -> frozenset[tuple[str, str]]:
    start_s, end_s = params.date_range.start_date, params.date_range.end_date
    covering = [inv for inv in inventories if inv.date_range.start_date <= start_s and end_s <= inv.date_range.end_date]
    if not covering:
        raise ClosedValidationError("no verified ExpectedResourceInventory covers requested date_range")
    pair_sets = {
        frozenset((rk.resource_ref, rk.metric_date) for rk in inv.expected_resources if start_s <= rk.metric_date <= end_s)
        for inv in covering
    }
    if len(pair_sets) != 1:
        raise ClosedValidationError("covering ExpectedResourceInventory artifacts disagree on date_range")
    if params.resource_refs:
        req_refs = set(params.resource_refs)
        if any(not req_refs.issubset({rk.resource_ref for rk in inv.expected_resources}) for inv in covering):
            raise ClosedValidationError("requested resource_ref outside ExpectedResourceInventory scope")
    return next(iter(pair_sets))


class VerifiedStoreMcpReadHandler(McpReadHandlerPort):
    """Post-admission read-only MCP handler backed exclusively by `McpVerifiedReadIndex`."""

    def __init__(self, index: McpVerifiedReadIndex) -> None:
        if type(index) is not McpVerifiedReadIndex:
            raise ClosedValidationError("index: expected McpVerifiedReadIndex")
        self._index = index

    @property
    def index(self) -> McpVerifiedReadIndex:
        return self._index

    def _verify_registry_gate(self, request: AdmittedMcpRequest) -> tuple[AdmittedMcpRequest, RegistryBinding]:
        if type(request) is not AdmittedMcpRequest:
            raise ClosedValidationError("request: expected AdmittedMcpRequest")
        fresh_req = AdmittedMcpRequest(
            request.request_id, request.method, request.params,
            request.delegation_context, request.clock_lower_utc, request.clock_upper_utc,
        )
        reg = self._index.registry_snapshot
        if reg.tenant_ref != fresh_req.params.tenant_ref:
            raise ClosedValidationError("registry snapshot tenant_ref mismatch")
        reg_issued = parse_timestamp_utc_micros(reg.issued_at_utc, field_name="reg.issued_at_utc", allow_whole_seconds=True)
        reg_until = parse_timestamp_utc_micros(reg.valid_until_utc, field_name="reg.valid_until_utc", allow_whole_seconds=True)
        clk_lo = parse_timestamp_utc_micros(fresh_req.clock_lower_utc, field_name="clock_lower_utc", allow_whole_seconds=True)
        clk_hi = parse_timestamp_utc_micros(fresh_req.clock_upper_utc, field_name="clock_upper_utc", allow_whole_seconds=True)
        if not (reg_issued <= clk_lo <= clk_hi < reg_until):
            raise ClosedValidationError("registry snapshot freshness window violated")
        rel = AuthorizedScopeRelation(
            fresh_req.delegation_context.front_ref, fresh_req.delegation_context.profile_ref,
            fresh_req.params.binding_ref, fresh_req.params.resource_scope_ref,
        )
        if rel not in reg.authorized_scopes:
            raise ClosedValidationError("unauthorized relational scope in registry snapshot")
        return fresh_req, reg.get_binding(fresh_req.params.binding_ref)

    def _handle_campaign_performance(self, params: PerformanceQueryParams, binding: RegistryBinding) -> dict[str, Any]:
        invs = self._index.scope_inventories.get((params.tenant_ref, params.binding_ref, params.resource_scope_ref), ())
        allowed_pairs = _resolve_covering_scope_pairs(invs, params)
        start_s, end_s = params.date_range.start_date, params.date_range.end_date
        req_res, req_metrics = frozenset(params.resource_refs), frozenset(params.metric_refs)
        projected = [
            _project_campaign_landing_row(r, expected_currency=binding.currency)
            for r in self._index.active_rows
            if (
                (r.fact_key.binding_ref, r.fact_key.account_ref, r.fact_key.resource_level) == (params.binding_ref, binding.account_ref, "campaign")
                and (r.fact_key.resource_ref, r.fact_key.metric_date) in allowed_pairs
                and start_s <= r.fact_key.metric_date <= end_s
                and (not req_res or r.fact_key.resource_ref in req_res)
                and (not req_metrics or r.fact_key.metric_semantic_ref in req_metrics)
            )
        ]
        res = {
            "$schema": "smart_ads/mcp_campaign_performance_result/v1",
            "dataset_snapshot_locator": self._index.active_dataset_snapshot_locator.to_dict(),
            "dataset_snapshot_digest": self._index.active_snapshot.snapshot_digest,
            "tenant_ref": params.tenant_ref, "binding_ref": params.binding_ref,
            "resource_scope_ref": params.resource_scope_ref,
            "date_range": {"start_date": start_s, "end_date": end_s}, "rows": projected,
        }
        canonicalize_jcs(res)
        return res

    def _handle_intelligence_findings(self, params: IntelligenceFindingsQueryParams) -> dict[str, Any]:
        key = (params.dataset_snapshot_locator.content_digest, params.tenant_ref, params.binding_ref, params.resource_scope_ref)
        entry = self._index.findings_index.get(key)
        if entry is None or entry.dataset_snapshot_locator != params.dataset_snapshot_locator:
            raise ClosedValidationError("no verified findings entry for requested snapshot and scope")
        allowed_types = frozenset(params.finding_types)
        filtered = [f for f in entry.findings if not allowed_types or f.finding_type in allowed_types]
        res = {
            "$schema": "smart_ads/mcp_intelligence_findings_result/v1",
            "dataset_snapshot_locator": params.dataset_snapshot_locator.to_dict(),
            "tenant_ref": params.tenant_ref, "binding_ref": params.binding_ref,
            "resource_scope_ref": params.resource_scope_ref,
            "derived_certification_status": entry.certification_record.derived_certification_status.value,
            "mutation_recommendations_blocked": entry.certification_record.mutation_recommendations_blocked,
            "findings": [
                {
                    "finding_key": f.finding_key, "finding_type": f.finding_type, "finding_status": f.finding_status,
                    "mutation_recommendation_blocked": f.mutation_recommendation_blocked, "finding_digest": f.finding_digest,
                }
                for f in filtered
            ],
        }
        canonicalize_jcs(res)
        return res

    def _handle_recurrent_summary(self, params: RecurrentSummaryReportParams) -> dict[str, Any]:
        _validate_summary_cadence_window(params.cadence, params.period_start_date, params.period_end_date, label="params")
        key = (
            params.dataset_snapshot_locator.content_digest, params.tenant_ref, params.binding_ref,
            params.resource_scope_ref, params.cadence, params.period_start_date, params.period_end_date,
        )
        entry = self._index.summary_reports_index.get(key)
        if entry is None or entry.dataset_snapshot_locator != params.dataset_snapshot_locator:
            raise ClosedValidationError("no verified recurrent summary report entry for requested parameters")
        res = {
            "$schema": "smart_ads/mcp_recurrent_summary_result/v1",
            "dataset_snapshot_locator": params.dataset_snapshot_locator.to_dict(),
            "tenant_ref": params.tenant_ref, "binding_ref": params.binding_ref,
            "resource_scope_ref": params.resource_scope_ref, "cadence": params.cadence,
            "period_start_date": params.period_start_date, "period_end_date": params.period_end_date,
            "report_result": entry.canonical_report_result.to_dict(),
        }
        canonicalize_jcs(res)
        return res

    def handle(self, request: AdmittedMcpRequest) -> Mapping[str, Any]:
        """Execute registry scope/freshness gate and serve pre-verified canonical projections."""
        checked_req, binding = self._verify_registry_gate(request)
        if checked_req.method in _DEFERRED_PERF_METHODS:
            raise ClosedValidationError("Phase-1 dataset supports only campaign resource_level; adset and ad are deferred")
        if checked_req.method == _CAMPAIGN_PERF_METHOD and type(checked_req.params) is PerformanceQueryParams:
            return self._handle_campaign_performance(checked_req.params, binding)
        if checked_req.method == _FINDINGS_METHOD and type(checked_req.params) is IntelligenceFindingsQueryParams:
            return self._handle_intelligence_findings(checked_req.params)
        if checked_req.method == _SUMMARY_METHOD and type(checked_req.params) is RecurrentSummaryReportParams:
            return self._handle_recurrent_summary(checked_req.params)
        raise ClosedValidationError(f"unsupported admitted MCP method {checked_req.method!r}")


__all__ = [
    "McpVerifiedReadIndex",
    "VerifiedStoreMcpReadHandler",
    "load_verified_snapshot_rows",
]
