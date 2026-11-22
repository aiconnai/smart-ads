"""Deterministic curation pipeline, Parquet generations, global catalog CAS, and snapshots (ADR-0001 §§6.1–6.3)."""
from __future__ import annotations

from collections.abc import MutableSet, Sequence
import hashlib
from itertools import pairwise
from typing import Final, Literal, TypeVar

from smart_ads.analytics.lattice import order_candidates, select_winner
from smart_ads.application.completeness import recompute_collection_completeness
from smart_ads.contracts.effects import AuthorizationConsumptionRecord, AuthorizationReceipt, AuthorizationReservationRecord, EffectProof, ExecutionReceipt, ProviderCallTarget, _reparse_p1, _safe_int, _strict_id, _strict_str, _typed_locator, sort_artifact_locators, verify_four_record_effect_proof
from smart_ads.contracts.git_provenance import GitArtifactProvenance
from smart_ads.contracts.jcs import ArtifactLocator, P1Integrity, canonicalize_jcs
from smart_ads.contracts.operational_evidence import AlgorithmProvenanceIdentity, OperationalReadEvidence, SanitizedCandidateFactSet
from smart_ads.contracts.scalars import ClosedValidationError, parse_iso_date
from smart_ads.contracts.schemas import AdmittedCollection, AnalyticsLandingRow, CollectionResult, DateRange, project_collection_fact_to_landing_row
from smart_ads.domain.catalog import ActivePartitionHead, CatalogCasOperation, CatalogCasRequestProjection, DatasetCatalog, DatasetCatalogCutReceipt, DatasetCatalogGenesisConsumptionRecord, DatasetCatalogGenesisRecord, DatasetSnapshot, GenerationManifest, ParquetObjectLocator, compute_logical_rows_digest, compute_physical_parquet_set_digest
from smart_ads.domain.curation import CurationExecution, partition_key_for_metric_date, validate_partition_key
from smart_ads.domain.pipeboard_contract import PipeboardPhase1Contract
from smart_ads.domain.registry import ExpectedResourceInventory
from smart_ads.ports.storage import CellObjectStorePort, ParquetLandingCodecPort

_T = TypeVar("_T")
_RUN_CONTEXT_SCHEMA: Final[str] = "smart_ads/migration_run_context/v1"
_REGISTRY_SNAPSHOT_SCHEMA: Final[str] = "smart_ads/private_registry_snapshot/v1"
_PARQUET_COMPRESSIONS: Final[frozenset[str]] = frozenset({"uncompressed", "gzip"})


def _require_store_and_bool(
    store: object, require_signed: object = False, *, bool_name: str = "require_signed"
) -> CellObjectStorePort:
    if not isinstance(store, CellObjectStorePort):
        raise ClosedValidationError(f"store: expected CellObjectStorePort, got {type(store).__name__}")
    if type(require_signed) is not bool:
        raise ClosedValidationError(f"{bool_name}: expected bool")
    return store


def _require_parquet_codec(codec: object) -> ParquetLandingCodecPort:
    if not isinstance(codec, ParquetLandingCodecPort):
        raise ClosedValidationError(f"parquet_codec: expected ParquetLandingCodecPort, got {type(codec).__name__}")
    return codec


def _reparse_exact(obj: object, cls: type[_T], *, label: str, require_signed: bool = False) -> _T:
    fresh = _reparse_p1(obj, cls, label=label, require_signed=require_signed)
    if obj != fresh:
        raise ClosedValidationError(f"{label}: in-memory fields diverge from canonical form")
    return fresh


def _load_p1(
    store: CellObjectStorePort, locator: ArtifactLocator, cls: type[_T], *, field_name: str, require_signed: bool = False
) -> _T:
    checked_loc = _typed_locator(locator, field_name=field_name, expected_type=cls.SCHEMA)  # type: ignore[attr-defined]
    raw_dict = store.get_json_artifact(checked_loc)
    raw_bytes = canonicalize_jcs(raw_dict)
    if ArtifactLocator.for_canonical_bytes(cls.SCHEMA, raw_bytes) != checked_loc:  # type: ignore[attr-defined]
        raise ClosedValidationError(f"{field_name}: resolved JSON digest mismatch")
    parsed: _T = cls.from_dict(raw_dict, require_signed=require_signed)  # type: ignore[attr-defined]
    if canonicalize_jcs(parsed.to_dict()) != raw_bytes:  # type: ignore[attr-defined]
        raise ClosedValidationError(f"{field_name}: parsed canonical bytes diverged")
    return parsed


def _partition_year_month(partition_key: str) -> str:
    year_seg, month_seg = validate_partition_key(partition_key).split("/")
    return f"{year_seg.removeprefix('year=')}-{month_seg.removeprefix('month=')}"


def verify_algorithm_provenance_identity(
    identity: AlgorithmProvenanceIdentity, resolved_git: GitArtifactProvenance
) -> None:
    """Verify `AlgorithmProvenanceIdentity` locator and 5-field Git equality."""
    if type(identity) is not AlgorithmProvenanceIdentity:
        raise ClosedValidationError("identity: expected AlgorithmProvenanceIdentity")
    fresh_id = AlgorithmProvenanceIdentity.from_dict(identity.to_dict())
    if identity != fresh_id:
        raise ClosedValidationError("identity: corrupted AlgorithmProvenanceIdentity")
    fresh_git = _reparse_exact(resolved_git, GitArtifactProvenance, label="resolved_git")
    git_loc = ArtifactLocator.for_canonical_bytes(GitArtifactProvenance.SCHEMA, canonicalize_jcs(fresh_git.to_dict()))
    if fresh_id.git_artifact_provenance_locator != git_loc:
        raise ClosedValidationError("algorithm_provenance_identity.git_artifact_provenance_locator: locator mismatch")
    if (fresh_id.repository, fresh_id.commit_sha, fresh_id.path, fresh_id.git_blob_oid, fresh_id.file_content_sha256) != (
        fresh_git.repository, fresh_git.commit_sha, fresh_git.path, fresh_git.git_blob_oid, fresh_git.file_content_sha256
    ):
        raise ClosedValidationError("algorithm_provenance_identity: Git repository/commit/path/blob/sha256 mismatch")


def _verify_algorithm_in_store(
    identity: AlgorithmProvenanceIdentity, *, store: CellObjectStorePort, require_signed: bool, label: str
) -> AlgorithmProvenanceIdentity:
    if type(identity) is not AlgorithmProvenanceIdentity:
        raise ClosedValidationError(f"{label}: expected AlgorithmProvenanceIdentity")
    git_prov = _load_p1(store, identity.git_artifact_provenance_locator, GitArtifactProvenance, field_name=f"{label}.git_artifact_provenance_locator", require_signed=require_signed)
    verify_algorithm_provenance_identity(identity, git_prov)
    return identity


def _verify_operational_evidence_alignment(
    ev: OperationalReadEvidence, admitted: AdmittedCollection,
    driver_contract: PipeboardPhase1Contract, inventory: ExpectedResourceInventory, result: CollectionResult,
) -> None:
    if admitted.collection_purpose != "operational_read":
        raise ClosedValidationError(f"operational_read_evidence: collection_purpose {admitted.collection_purpose!r} != 'operational_read'")
    if result.call_side != "operational":
        raise ClosedValidationError(f"operational_read_evidence: result.call_side {result.call_side!r} != 'operational'")
    if driver_contract.driver_id != admitted.driver_id:
        raise ClosedValidationError("operational_read_evidence: driver_id mismatch")
    adm_scope = (admitted.tenant_ref, admitted.binding_ref, admitted.account_ref, admitted.resource_scope_ref, admitted.canonical_query_digest, admitted.registry_snapshot_locator)
    inv_scope = (inventory.tenant_ref, inventory.binding_ref, inventory.account_ref, inventory.resource_scope_ref, inventory.registry_snapshot_locator, inventory.date_range)
    ev_scope = (ev.tenant_ref, ev.binding_ref, ev.account_ref, ev.resource_scope_ref, ev.canonical_query_digest, ev.registry_snapshot_locator)
    if (
        ev_scope != adm_scope or inv_scope != (*adm_scope[:4], admitted.registry_snapshot_locator, admitted.computed_date_range)
        or (result.admitted_collection_locator, result.registry_snapshot_locator, result.requested_capabilities) != (ev.admitted_collection_locator, ev.registry_snapshot_locator, admitted.requested_capabilities)
    ):
        raise ClosedValidationError("operational_read_evidence: admitted/inventory/result identity mismatch")


def _verify_operational_effect_chain(
    ev: OperationalReadEvidence, admitted: AdmittedCollection, *, store: CellObjectStorePort, require_signed: bool
) -> None:
    auth = _load_p1(store, ev.authorization_locator, AuthorizationReceipt, field_name="evidence.authorization_locator", require_signed=require_signed)
    resv = _load_p1(store, ev.reservation_locator, AuthorizationReservationRecord, field_name="evidence.reservation_locator", require_signed=require_signed)
    exec_rec = _load_p1(store, ev.execution_locator, ExecutionReceipt, field_name="evidence.execution_locator", require_signed=require_signed)
    cons = _load_p1(store, ev.consumption_locator, AuthorizationConsumptionRecord, field_name="evidence.consumption_locator", require_signed=require_signed)
    proof = _load_p1(store, ev.effect_proof_locator, EffectProof, field_name="evidence.effect_proof_locator", require_signed=require_signed)
    verified_proof = verify_four_record_effect_proof(
        effect_proof=proof, authorization=auth, reservation=resv, execution=exec_rec, consumption=cons,
        expected_action="provider_operational_read", expected_dag_slot="operational_provider_read_effect_proof",
        expected_result_type=CollectionResult.SCHEMA, require_signed=require_signed,
    )
    subj = auth.subject
    exp_subj = (ev.migration_run_context_locator, ev.admitted_collection_locator, "operational", admitted.canonical_query_digest, admitted.registry_snapshot_locator, admitted.tenant_ref, admitted.binding_ref, admitted.account_ref, admitted.resource_scope_ref, admitted.purpose_prerequisite_locators.delegation_context_locator)
    if (
        type(subj) is not ProviderCallTarget or (verified_proof.migration_run_context_locator, verified_proof.action_result_locator) != (ev.migration_run_context_locator, ev.collection_result_locator)
        or (subj.migration_run_context_locator, subj.admitted_collection_locator, subj.call_side, subj.canonical_query_digest, subj.registry_snapshot_locator, subj.tenant_ref, subj.binding_ref, subj.account_ref, subj.resource_scope_ref, subj.delegation_context_locator) != exp_subj
    ):
        raise ClosedValidationError("operational_read_evidence: ProviderCallTarget mismatch")


def verify_operational_read_evidence(
    evidence: OperationalReadEvidence, *, store: CellObjectStorePort, require_signed: bool = False
) -> tuple[AdmittedCollection, CollectionResult]:
    """Verify `OperationalReadEvidence`, `complete` U x M evaluation, and 5-record effect chain."""
    checked_store = _require_store_and_bool(store, require_signed)
    fresh_ev = _reparse_exact(evidence, OperationalReadEvidence, label="evidence", require_signed=require_signed)
    admitted = _load_p1(checked_store, fresh_ev.admitted_collection_locator, AdmittedCollection, field_name="evidence.admitted_collection_locator", require_signed=require_signed)
    driver_contract = _load_p1(checked_store, admitted.driver_contract_locator, PipeboardPhase1Contract, field_name="admitted.driver_contract_locator", require_signed=require_signed)
    inventory = _load_p1(checked_store, fresh_ev.expected_resource_inventory_locator, ExpectedResourceInventory, field_name="evidence.expected_resource_inventory_locator", require_signed=require_signed)
    result = _load_p1(checked_store, fresh_ev.collection_result_locator, CollectionResult, field_name="evidence.collection_result_locator", require_signed=require_signed)
    _verify_operational_evidence_alignment(fresh_ev, admitted, driver_contract, inventory, result)
    completeness = recompute_collection_completeness(
        admission_succeeded=True, inventory=inventory, required_metrics=admitted.canonical_query_contract.metric_semantic_refs,
        metric_source_mappings=driver_contract.metric_source_mappings, transport_outcome=result.transport_outcome, candidate_facts=result.normalized_fact_set or (),
    )
    if (
        completeness.status != "complete" or result.normalized_fact_set is None
        or (result.normalized_fact_set, result.normalized_fact_set_digest, fresh_ev.normalized_fact_set_digest) != (completeness.normalized_fact_set, completeness.normalized_fact_set_digest, completeness.normalized_fact_set_digest)
    ):
        raise ClosedValidationError(f"operational_read_evidence: completeness status {completeness.status!r} != 'complete'")
    projected = tuple(sorted((project_collection_fact_to_landing_row(f, result.retrieval_context, query_currency=admitted.currency) for f in result.normalized_fact_set), key=lambda r: r.candidate_sort_key_jcs()))
    if projected != result.candidates:
        raise ClosedValidationError("operational_read_evidence: candidate projection mismatch")
    _verify_operational_effect_chain(fresh_ev, admitted, store=checked_store, require_signed=require_signed)
    return admitted, result


def _merge_unique_row_by_k(
    rows_by_k: dict[bytes, tuple[AnalyticsLandingRow, bytes]], row: AnalyticsLandingRow, *, label: str
) -> None:
    sort_k, row_bytes = row.candidate_sort_key_jcs(), canonicalize_jcs(row.to_dict())
    existing = rows_by_k.get(sort_k)
    if existing is not None:
        if existing[1] != row_bytes:
            raise ClosedValidationError(f"{label}: conflicting row bytes on equal sort key K")
        return
    rows_by_k[sort_k] = (row, row_bytes)


def _derive_bijective_candidates(
    *, run_loc: ArtifactLocator, sorted_ev_locs: tuple[ArtifactLocator, ...], store: CellObjectStorePort, require_signed: bool
) -> tuple[tuple[ArtifactLocator, ...], tuple[AnalyticsLandingRow, ...]]:
    seen_res_keys: set[bytes] = set()
    res_locs: list[ArtifactLocator] = []
    rows_by_k: dict[bytes, tuple[AnalyticsLandingRow, bytes]] = {}
    for ev_loc in sorted_ev_locs:
        ev = _load_p1(store, ev_loc, OperationalReadEvidence, field_name="operational_read_evidence_locators[]", require_signed=require_signed)
        if ev.migration_run_context_locator != run_loc:
            raise ClosedValidationError("sanitized_candidate_fact_set: cross-run OperationalReadEvidence is forbidden")
        _, result = verify_operational_read_evidence(ev, store=store, require_signed=require_signed)
        res_key = canonicalize_jcs(ev.collection_result_locator.to_dict())
        if res_key in seen_res_keys:
            raise ClosedValidationError("sanitized_candidate_fact_set: duplicate collection_result_locator breaks 1-to-1 bijection")
        seen_res_keys.add(res_key)
        res_locs.append(ev.collection_result_locator)
        for row in result.candidates:
            _merge_unique_row_by_k(rows_by_k, row, label="sanitized_candidate_fact_set")
    sorted_src_locs = sort_artifact_locators(res_locs, expected_type=CollectionResult.SCHEMA, allow_empty=False, field_name="source_collection_result_locators")
    return sorted_src_locs, order_candidates(pair[0] for pair in rows_by_k.values())


def build_sanitized_candidate_fact_set(
    *, migration_run_context_locator: ArtifactLocator, sanitization_algorithm_identity: AlgorithmProvenanceIdentity,
    store: CellObjectStorePort, evidence_locators: Sequence[ArtifactLocator],
    integrity: P1Integrity | None = None, require_signed_inputs: bool = False,
) -> SanitizedCandidateFactSet:
    """Build and store a verified `SanitizedCandidateFactSet` from operational read evidences."""
    checked_store = _require_store_and_bool(store, require_signed_inputs, bool_name="require_signed_inputs")
    run_loc = _typed_locator(migration_run_context_locator, field_name="migration_run_context_locator", expected_type=_RUN_CONTEXT_SCHEMA)
    checked_alg = _verify_algorithm_in_store(sanitization_algorithm_identity, store=checked_store, require_signed=require_signed_inputs, label="sanitization_algorithm_identity")
    if isinstance(evidence_locators, (str, bytes)) or not isinstance(evidence_locators, Sequence):
        raise ClosedValidationError("evidence_locators: expected Sequence of ArtifactLocator")
    sorted_ev_locs = sort_artifact_locators(evidence_locators, expected_type=OperationalReadEvidence.SCHEMA, allow_empty=False, field_name="evidence_locators")
    sorted_src_locs, ordered_rows = _derive_bijective_candidates(run_loc=run_loc, sorted_ev_locs=sorted_ev_locs, store=checked_store, require_signed=require_signed_inputs)
    candidate_set = SanitizedCandidateFactSet(run_loc, checked_alg, sorted_src_locs, sorted_ev_locs, ordered_rows, integrity=integrity)
    checked_store.put_json_artifact(SanitizedCandidateFactSet.SCHEMA, candidate_set.to_dict())
    return candidate_set


def verify_sanitized_candidate_fact_set(
    candidate_set: SanitizedCandidateFactSet, *, store: CellObjectStorePort, require_signed: bool = False
) -> SanitizedCandidateFactSet:
    """Verify 1-to-1 evidence/result bijection, provenance, and candidate rows."""
    checked_store = _require_store_and_bool(store, require_signed)
    fresh_cs = _reparse_exact(candidate_set, SanitizedCandidateFactSet, label="candidate_set", require_signed=require_signed)
    _verify_algorithm_in_store(fresh_cs.sanitization_algorithm_identity, store=checked_store, require_signed=require_signed, label="candidate_set.sanitization_algorithm_identity")
    sorted_src_locs, ordered_rows = _derive_bijective_candidates(
        run_loc=fresh_cs.migration_run_context_locator, sorted_ev_locs=fresh_cs.operational_read_evidence_locators, store=checked_store, require_signed=require_signed
    )
    if fresh_cs.source_collection_result_locators != sorted_src_locs:
        raise ClosedValidationError("sanitized_candidate_fact_set: 1-to-1 bijection mismatch against source_collection_result_locators")
    if fresh_cs.candidates != ordered_rows or [canonicalize_jcs(r.to_dict()) for r in fresh_cs.candidates] != [canonicalize_jcs(r.to_dict()) for r in ordered_rows]:
        raise ClosedValidationError("sanitized_candidate_fact_set: candidates differ from recomputed projection")
    return fresh_cs


def _validate_candidates_in_single_partition_window(
    candidates: tuple[AnalyticsLandingRow, ...], curation_window: DateRange
) -> str:
    start_d = parse_iso_date(curation_window.start_date, field_name="curation_window.start_date")
    end_d = parse_iso_date(curation_window.end_date, field_name="curation_window.end_date")
    partition_keys: set[str] = set()
    for row in candidates:
        if not (start_d <= parse_iso_date(row.fact_key.metric_date, field_name="candidate.metric_date") <= end_d):
            raise ClosedValidationError(f"curation_execution: candidate metric_date {row.fact_key.metric_date!r} outside curation_window")
        partition_keys.add(partition_key_for_metric_date(row.fact_key.metric_date))
    if len(partition_keys) != 1:
        raise ClosedValidationError(f"curation_execution: single-partition cut required, got {sorted(partition_keys)!r}")
    return next(iter(partition_keys))


def _expected_catalog_transition(
    old_catalog: DatasetCatalog, old_catalog_locator: ArtifactLocator,
    new_gen: GenerationManifest, new_gen_locator: ArtifactLocator,
) -> tuple[CatalogCasOperation, int, tuple[ActivePartitionHead, ...]]:
    if new_gen.base_dataset_catalog_locator != old_catalog_locator:
        raise ClosedValidationError("generation_manifest.base_dataset_catalog_locator: must equal old catalog locator")
    pk, old_by_pk = new_gen.partition_key, {h.partition_key: h for h in old_catalog.partition_heads}
    if pk not in old_by_pk:
        if new_gen.parent_generation_manifest_locator is not None:
            raise ClosedValidationError("generation_manifest.parent_generation_manifest_locator: must be None on add_partition")
        added = ActivePartitionHead(pk, 1, new_gen_locator)
        return "add_partition", 1, tuple(sorted((*old_catalog.partition_heads, added), key=lambda h: h.partition_key.encode("utf-8")))
    old_entry = old_by_pk[pk]
    if new_gen.parent_generation_manifest_locator != old_entry.generation_manifest_locator:
        raise ClosedValidationError("generation_manifest.parent_generation_manifest_locator: must equal old_entry.generation_manifest_locator")
    if new_gen_locator == old_entry.generation_manifest_locator:
        raise ClosedValidationError("dataset_catalog_cas: replacement manifest must be distinct")
    seq = old_entry.head_sequence_number + 1
    replaced = ActivePartitionHead(pk, seq, new_gen_locator)
    return "replace_partition", seq, tuple(replaced if h.partition_key == pk else h for h in old_catalog.partition_heads)


def _verify_epoch0_cut_genesis_bindings(
    receipt: DatasetCatalogCutReceipt, old_catalog: DatasetCatalog, new_catalog: DatasetCatalog,
    curation: CurationExecution, *, store: CellObjectStorePort, require_signed: bool,
) -> None:
    if (
        old_catalog.partition_heads != () or receipt.cas_request_projection.operation != "add_partition"
        or receipt.cas_request_projection.target_head_sequence_number != 1 or len(new_catalog.partition_heads) != 1
        or receipt.genesis_record_locator is None or receipt.genesis_consumption_locator is None
    ):
        raise ClosedValidationError("dataset_catalog_cut_receipt: invalid epoch-0 genesis cut shape")
    gen_rec = _load_p1(store, receipt.genesis_record_locator, DatasetCatalogGenesisRecord, field_name="cut_receipt.genesis_record_locator", require_signed=require_signed)
    cons_rec = _load_p1(store, receipt.genesis_consumption_locator, DatasetCatalogGenesisConsumptionRecord, field_name="cut_receipt.genesis_consumption_locator", require_signed=require_signed)
    if (
        (curation.curation_mode, curation.dataset_catalog_genesis_record_locator) != ("genesis", receipt.genesis_record_locator)
        or (gen_rec.cell_ref, gen_rec.empty_epoch0_catalog_locator) != (receipt.cell_ref, receipt.old_catalog_locator)
        or (cons_rec.genesis_record_locator, cons_rec.empty_epoch0_catalog_locator, cons_rec.first_successor_catalog_locator, cons_rec.preallocated_cut_id, cons_rec.cas_linearization_id)
        != (receipt.genesis_record_locator, receipt.old_catalog_locator, receipt.new_catalog_locator, receipt.cut_id, receipt.cas_linearization_id)
    ):
        raise ClosedValidationError("dataset_catalog_cut_receipt: epoch-0 genesis record or consumption binding mismatch")


def _verify_cut_receipt_metadata(
    receipt: DatasetCatalogCutReceipt, *, store: CellObjectStorePort, require_signed: bool
) -> tuple[DatasetCatalog, DatasetCatalog, GenerationManifest]:
    old_catalog = _load_p1(store, receipt.old_catalog_locator, DatasetCatalog, field_name="cut_receipt.old_catalog_locator", require_signed=require_signed)
    new_catalog = _load_p1(store, receipt.new_catalog_locator, DatasetCatalog, field_name="cut_receipt.new_catalog_locator", require_signed=require_signed)
    gen_loc = receipt.cas_request_projection.generation_manifest_locator
    new_gen = _load_p1(store, gen_loc, GenerationManifest, field_name="cut_receipt.cas_request_projection.generation_manifest_locator", require_signed=require_signed)
    curation = _load_p1(store, new_gen.curation_execution_locator, CurationExecution, field_name="new_generation.curation_execution_locator", require_signed=require_signed)
    op, seq, exp_heads = _expected_catalog_transition(old_catalog, receipt.old_catalog_locator, new_gen, gen_loc)
    exp_proj = CatalogCasRequestProjection(op, old_catalog.catalog_epoch, receipt.old_catalog_locator.content_digest, new_gen.partition_key, seq, gen_loc)
    if (
        (old_catalog.catalog_epoch, new_catalog.catalog_epoch, old_catalog.catalog_epoch + 1) != (receipt.old_catalog_epoch, receipt.new_catalog_epoch, new_catalog.catalog_epoch)
        or (old_catalog.cell_ref, new_catalog.cell_ref, receipt.migration_run_context_locator) != (receipt.cell_ref, receipt.cell_ref, new_gen.migration_run_context_locator)
        or (curation.base_dataset_catalog_locator, receipt.cas_request_projection, new_catalog.partition_heads) != (receipt.old_catalog_locator, exp_proj, exp_heads)
    ):
        raise ClosedValidationError("dataset_catalog_cut_receipt: catalog transition mismatch")
    if receipt.old_catalog_epoch == 0:
        _verify_epoch0_cut_genesis_bindings(receipt, old_catalog, new_catalog, curation, store=store, require_signed=require_signed)
    elif curation.curation_mode != "incremental":
        raise ClosedValidationError("dataset_catalog_cut_receipt: epoch >= 1 requires incremental curation")
    return old_catalog, new_catalog, new_gen


def _verify_incremental_curation_history(
    curation: CurationExecution, base_catalog: DatasetCatalog, *, store: CellObjectStorePort, require_signed: bool
) -> tuple[GenerationManifest, ...]:
    if base_catalog.catalog_epoch < 1 or curation.base_dataset_snapshot_locator is None or curation.base_catalog_cut_receipt_locator is None:
        raise ClosedValidationError("curation_execution: incremental mode requires epoch >= 1 base")
    base_snap = _load_p1(store, curation.base_dataset_snapshot_locator, DatasetSnapshot, field_name="curation.base_dataset_snapshot_locator", require_signed=require_signed)
    base_cut = _load_p1(store, curation.base_catalog_cut_receipt_locator, DatasetCatalogCutReceipt, field_name="curation.base_catalog_cut_receipt_locator", require_signed=require_signed)
    _, verified_new_cat, _ = _verify_cut_receipt_metadata(base_cut, store=store, require_signed=require_signed)
    if (
        (base_snap.dataset_catalog_locator, base_snap.catalog_cut_receipt_locator, base_cut.new_catalog_locator)
        != (curation.base_dataset_catalog_locator, curation.base_catalog_cut_receipt_locator, curation.base_dataset_catalog_locator)
        or (base_snap.catalog_epoch, base_snap.partition_heads, verified_new_cat) != (base_catalog.catalog_epoch, base_catalog.partition_heads, base_catalog)
    ):
        raise ClosedValidationError("curation_execution: base snapshot/catalog/cut-receipt mismatch")
    start_ym, end_ym = curation.curation_window.start_date[:7], curation.curation_window.end_date[:7]
    intersecting = [h for h in base_catalog.partition_heads if start_ym <= _partition_year_month(h.partition_key) <= end_ym]
    if curation.historical_generation_manifest_locators != tuple(h.generation_manifest_locator for h in intersecting):
        raise ClosedValidationError("curation_execution.historical_generation_manifest_locators: intersecting head mismatch")
    manifests: list[GenerationManifest] = []
    for head in intersecting:
        gm = _load_p1(store, head.generation_manifest_locator, GenerationManifest, field_name="curation.historical_generation_manifest_locators[]", require_signed=require_signed)
        if gm.partition_key != head.partition_key:
            raise ClosedValidationError("curation_execution: historical manifest partition_key mismatch")
        manifests.append(gm)
    return tuple(manifests)


def verify_curation_execution(
    curation: CurationExecution, *, store: CellObjectStorePort, require_signed: bool = False
) -> tuple[SanitizedCandidateFactSet, DatasetCatalog, tuple[GenerationManifest, ...]]:
    """Verify `CurationExecution`, candidate window/single-partition cut, and base catalog."""
    checked_store = _require_store_and_bool(store, require_signed)
    fresh_cur = _reparse_exact(curation, CurationExecution, label="curation", require_signed=require_signed)
    _verify_algorithm_in_store(fresh_cur.curation_algorithm_identity, store=checked_store, require_signed=require_signed, label="curation.curation_algorithm_identity")
    raw_cs = _load_p1(checked_store, fresh_cur.sanitized_candidate_fact_set_locator, SanitizedCandidateFactSet, field_name="curation.sanitized_candidate_fact_set_locator", require_signed=require_signed)
    if raw_cs.migration_run_context_locator != fresh_cur.migration_run_context_locator:
        raise ClosedValidationError("curation_execution: cross-run SanitizedCandidateFactSet forbidden")
    candidate_set = verify_sanitized_candidate_fact_set(raw_cs, store=checked_store, require_signed=require_signed)
    _validate_candidates_in_single_partition_window(candidate_set.candidates, fresh_cur.curation_window)
    base_catalog = _load_p1(checked_store, fresh_cur.base_dataset_catalog_locator, DatasetCatalog, field_name="curation.base_dataset_catalog_locator", require_signed=require_signed)
    if fresh_cur.curation_mode == "genesis":
        if fresh_cur.dataset_catalog_genesis_record_locator is None:
            raise ClosedValidationError("curation_execution: missing genesis record locator")
        gen_rec = _load_p1(checked_store, fresh_cur.dataset_catalog_genesis_record_locator, DatasetCatalogGenesisRecord, field_name="curation.dataset_catalog_genesis_record_locator", require_signed=require_signed)
        if (base_catalog.catalog_epoch, base_catalog.partition_heads, gen_rec.empty_epoch0_catalog_locator, gen_rec.cell_ref) != (0, (), fresh_cur.base_dataset_catalog_locator, base_catalog.cell_ref):
            raise ClosedValidationError("curation_execution: invalid genesis record or epoch-0 catalog")
        return candidate_set, base_catalog, ()
    return candidate_set, base_catalog, _verify_incremental_curation_history(fresh_cur, base_catalog, store=checked_store, require_signed=require_signed)


def _validate_historical_generation_pairs(
    curation: CurationExecution, historical_generations: Sequence[tuple[GenerationManifest, tuple[AnalyticsLandingRow, ...]]], target_pk: str
) -> tuple[AnalyticsLandingRow, ...]:
    if isinstance(historical_generations, (str, bytes)) or not isinstance(historical_generations, Sequence):
        raise ClosedValidationError("historical_generations: expected Sequence of (manifest, rows)")
    if len(historical_generations) != len(curation.historical_generation_manifest_locators):
        raise ClosedValidationError("historical_generations: length differs from curation execution")
    start_ym, end_ym = curation.curation_window.start_date[:7], curation.curation_window.end_date[:7]
    pks: list[bytes] = []
    target_hist_rows: tuple[AnalyticsLandingRow, ...] = ()
    for idx, pair in enumerate(historical_generations):
        if not isinstance(pair, tuple) or len(pair) != 2:
            raise ClosedValidationError(f"historical_generations[{idx}]: expected (manifest, rows) tuple")
        gm, rows = pair
        fresh_gm = _reparse_exact(gm, GenerationManifest, label=f"historical_generations[{idx}]")
        ordered_rows, logical_digest = compute_logical_rows_digest(rows)
        if (
            fresh_gm.locator() != curation.historical_generation_manifest_locators[idx] or not (start_ym <= _partition_year_month(fresh_gm.partition_key) <= end_ym)
            or (tuple(rows), len(ordered_rows), logical_digest) != (ordered_rows, fresh_gm.row_count, fresh_gm.logical_rows_digest)
            or any(partition_key_for_metric_date(r.fact_key.metric_date) != fresh_gm.partition_key for r in ordered_rows)
        ):
            raise ClosedValidationError(f"historical_generations[{idx}]: manifest or row digest mismatch")
        pks.append(fresh_gm.partition_key.encode("utf-8"))
        if fresh_gm.partition_key == target_pk:
            target_hist_rows = ordered_rows
    if any(a >= b for a, b in pairwise(pks)):
        raise ClosedValidationError("historical_generations: must be strictly sorted by partition_key")
    return target_hist_rows


def replay_curated_partition_rows(
    *, curation: CurationExecution, candidate_set: SanitizedCandidateFactSet,
    historical_generations: Sequence[tuple[GenerationManifest, tuple[AnalyticsLandingRow, ...]]],
) -> tuple[str, tuple[AnalyticsLandingRow, ...]]:
    """Replay deterministic winner selection and pre-window preservation for one partition."""
    fresh_cur = _reparse_exact(curation, CurationExecution, label="curation")
    fresh_cs = _reparse_exact(candidate_set, SanitizedCandidateFactSet, label="candidate_set")
    if (fresh_cur.sanitized_candidate_fact_set_locator, fresh_cur.migration_run_context_locator) != (fresh_cs.locator(), fresh_cs.migration_run_context_locator):
        raise ClosedValidationError("replay_curated_partition_rows: curation/candidate_set mismatch")
    target_pk = _validate_candidates_in_single_partition_window(fresh_cs.candidates, fresh_cur.curation_window)
    target_hist_rows = _validate_historical_generation_pairs(fresh_cur, historical_generations, target_pk)
    start_d = parse_iso_date(fresh_cur.curation_window.start_date, field_name="start_date")
    end_d = parse_iso_date(fresh_cur.curation_window.end_date, field_name="end_date")
    preserved_rows: list[AnalyticsLandingRow] = []
    pools_by_fk: dict[bytes, dict[bytes, tuple[AnalyticsLandingRow, bytes]]] = {}
    for h_row in target_hist_rows:
        if start_d <= parse_iso_date(h_row.fact_key.metric_date, field_name="historical.metric_date") <= end_d:
            _merge_unique_row_by_k(pools_by_fk.setdefault(canonicalize_jcs(h_row.fact_key.to_dict()), {}), h_row, label="curation_replay")
        else:
            preserved_rows.append(h_row)
    for c_row in fresh_cs.candidates:
        _merge_unique_row_by_k(pools_by_fk.setdefault(canonicalize_jcs(c_row.fact_key.to_dict()), {}), c_row, label="curation_replay")
    winners = [select_winner(pair[0] for pair in pool.values()) for pool in pools_by_fk.values()]
    ordered_partition_rows, _ = compute_logical_rows_digest([*preserved_rows, *winners])
    return target_pk, ordered_partition_rows


def _check_parent_against_base_catalog(
    base_catalog: DatasetCatalog, target_pk: str, parent_locator: ArtifactLocator | None
) -> None:
    existing = next((h for h in base_catalog.partition_heads if h.partition_key == target_pk), None)
    if existing is None and parent_locator is not None:
        raise ClosedValidationError("generation_manifest.parent_generation_manifest_locator: must be None for new partition")
    if existing is not None and parent_locator != existing.generation_manifest_locator:
        raise ClosedValidationError("generation_manifest.parent_generation_manifest_locator: must equal active base catalog head")


def _verify_manifest_curation_and_parent(
    manifest: GenerationManifest, *, store: CellObjectStorePort, require_signed: bool
) -> tuple[CurationExecution, SanitizedCandidateFactSet, tuple[GenerationManifest, ...]]:
    curation = _load_p1(store, manifest.curation_execution_locator, CurationExecution, field_name="manifest.curation_execution_locator", require_signed=require_signed)
    candidate_set, base_catalog, hist_manifests = verify_curation_execution(curation, store=store, require_signed=require_signed)
    target_pk = _validate_candidates_in_single_partition_window(candidate_set.candidates, curation.curation_window)
    if (manifest.partition_key, manifest.migration_run_context_locator, manifest.base_dataset_catalog_locator, manifest.operational_read_evidence_locators) != (target_pk, curation.migration_run_context_locator, curation.base_dataset_catalog_locator, candidate_set.operational_read_evidence_locators):
        raise ClosedValidationError("generation_manifest: partition_key, run, base catalog, or evidence mismatch")
    _check_parent_against_base_catalog(base_catalog, manifest.partition_key, manifest.parent_generation_manifest_locator)
    return curation, candidate_set, hist_manifests


def _decode_manifest_parquet_objects(
    manifest: GenerationManifest, *, store: CellObjectStorePort, parquet_codec: ParquetLandingCodecPort
) -> tuple[tuple[AnalyticsLandingRow, ...], str]:
    decoded_all: list[AnalyticsLandingRow] = []
    for pq_loc in manifest.parquet_object_locators:
        if pq_loc.partition_key != manifest.partition_key:
            raise ClosedValidationError("generation_manifest: Parquet locator partition_key mismatch")
        raw_pq = store.get_bytes(pq_loc.object_ref, expected_size_bytes=pq_loc.size_bytes)
        if len(raw_pq) != pq_loc.size_bytes or "sha256:" + hashlib.sha256(raw_pq).hexdigest() != pq_loc.physical_parquet_digest:
            raise ClosedValidationError("generation_manifest: Parquet SHA-256 or size mismatch")
        part_rows = parquet_codec.decode_and_verify_landing_rows(raw_pq, expected_partition_key=manifest.partition_key)
        if any(partition_key_for_metric_date(r.fact_key.metric_date) != manifest.partition_key for r in part_rows):
            raise ClosedValidationError("generation_manifest: decoded row partition_key mismatch")
        decoded_all.extend(part_rows)
    return compute_logical_rows_digest(decoded_all)


def _verify_generation_manifest_memo(
    manifest: GenerationManifest, *, store: CellObjectStorePort, parquet_codec: ParquetLandingCodecPort,
    require_signed: bool, memo: dict[bytes, tuple[AnalyticsLandingRow, ...]], visiting: frozenset[bytes],
) -> tuple[AnalyticsLandingRow, ...]:
    fresh_man = _reparse_exact(manifest, GenerationManifest, label="manifest", require_signed=require_signed)
    man_key = canonicalize_jcs(fresh_man.locator().to_dict())
    if man_key in memo:
        return memo[man_key]
    if man_key in visiting:
        raise ClosedValidationError("generation_manifest: ancestor cycle detected")
    curation, candidate_set, hist_manifests = _verify_manifest_curation_and_parent(fresh_man, store=store, require_signed=require_signed)
    next_visiting = visiting | {man_key}
    hist_pairs = tuple((hm, _verify_generation_manifest_memo(hm, store=store, parquet_codec=parquet_codec, require_signed=require_signed, memo=memo, visiting=next_visiting)) for hm in hist_manifests)
    exp_pk, exp_rows = replay_curated_partition_rows(curation=curation, candidate_set=candidate_set, historical_generations=hist_pairs)
    decoded_rows, decoded_digest = _decode_manifest_parquet_objects(fresh_man, store=store, parquet_codec=parquet_codec)
    if (fresh_man.partition_key, fresh_man.row_count, fresh_man.logical_rows_digest, decoded_rows) != (exp_pk, len(exp_rows), decoded_digest, exp_rows) or [canonicalize_jcs(r.to_dict()) for r in decoded_rows] != [canonicalize_jcs(r.to_dict()) for r in exp_rows]:
        raise ClosedValidationError("generation_manifest: decoded Parquet rows mismatch curation replay")
    memo[man_key] = decoded_rows
    return decoded_rows


def _encode_and_store_parquet_object(
    rows: tuple[AnalyticsLandingRow, ...], *, partition_key: str,
    compression: Literal["uncompressed", "gzip"], store: CellObjectStorePort, codec: ParquetLandingCodecPort,
) -> tuple[tuple[ParquetObjectLocator, ...], str]:
    raw_parquet = codec.encode_landing_rows(rows, partition_key=partition_key, compression=compression)
    if codec.decode_and_verify_landing_rows(raw_parquet, expected_partition_key=partition_key) != rows:
        raise ClosedValidationError("materialize_parquet_generation: Parquet codec readback mismatch")
    stored_ref = store.put_bytes(raw_parquet)
    pq_loc = ParquetObjectLocator.for_parquet_bytes(partition_key, raw_parquet)
    if pq_loc.object_ref != stored_ref:
        raise ClosedValidationError("materialize_parquet_generation: Parquet object_ref mismatch")
    return compute_physical_parquet_set_digest((pq_loc,))


def materialize_parquet_generation(
    *, generation_id: str, created_at_utc: str, registry_snapshot_locator: ArtifactLocator,
    curation_locator: ArtifactLocator, store: CellObjectStorePort, parquet_codec: ParquetLandingCodecPort,
    compression: Literal["uncompressed", "gzip"] = "uncompressed",
    parent_generation_manifest_locator: ArtifactLocator | None = None, integrity: P1Integrity | None = None,
) -> tuple[GenerationManifest, ArtifactLocator]:
    """Replay curation, materialize immutable Parquet v1 bytes, and store `GenerationManifest`."""
    checked_store, checked_codec = _require_store_and_bool(store, False), _require_parquet_codec(parquet_codec)
    if _strict_str(compression, field_name="compression") not in _PARQUET_COMPRESSIONS:
        raise ClosedValidationError(f"compression: unsupported {compression!r}")
    reg_loc = _typed_locator(registry_snapshot_locator, field_name="registry_snapshot_locator", expected_type=_REGISTRY_SNAPSHOT_SCHEMA)
    cur_loc = _typed_locator(curation_locator, field_name="curation_locator", expected_type=CurationExecution.SCHEMA)
    curation = _load_p1(checked_store, cur_loc, CurationExecution, field_name="curation_locator")
    candidate_set, base_catalog, hist_manifests = verify_curation_execution(curation, store=checked_store)
    memo: dict[bytes, tuple[AnalyticsLandingRow, ...]] = {}
    hist_pairs = tuple((hm, _verify_generation_manifest_memo(hm, store=checked_store, parquet_codec=checked_codec, require_signed=False, memo=memo, visiting=frozenset())) for hm in hist_manifests)
    target_pk, curated_rows = replay_curated_partition_rows(curation=curation, candidate_set=candidate_set, historical_generations=hist_pairs)
    _check_parent_against_base_catalog(base_catalog, target_pk, parent_generation_manifest_locator)
    ordered_rows, logical_digest = compute_logical_rows_digest(curated_rows)
    pq_locs, pq_set_digest = _encode_and_store_parquet_object(ordered_rows, partition_key=target_pk, compression=compression, store=checked_store, codec=checked_codec)
    manifest = GenerationManifest(
        curation.migration_run_context_locator, generation_id, target_pk, parent_generation_manifest_locator,
        created_at_utc, len(ordered_rows), logical_digest, reg_loc, cur_loc, curation.base_dataset_catalog_locator,
        candidate_set.operational_read_evidence_locators, pq_locs, physical_parquet_set_digest=pq_set_digest, integrity=integrity,
    )
    return manifest, checked_store.put_json_artifact(GenerationManifest.SCHEMA, manifest.to_dict())


def verify_generation_manifest(
    manifest: GenerationManifest, *, store: CellObjectStorePort, parquet_codec: ParquetLandingCodecPort, require_signed: bool = False
) -> tuple[AnalyticsLandingRow, ...]:
    """Verify `GenerationManifest` lineage, curation replay, and decoded Parquet v1 rows."""
    checked_store, checked_codec = _require_store_and_bool(store, require_signed), _require_parquet_codec(parquet_codec)
    return _verify_generation_manifest_memo(manifest, store=checked_store, parquet_codec=checked_codec, require_signed=require_signed, memo={}, visiting=frozenset())


def _verify_generation_for_cas(
    manifest: GenerationManifest, *, store: CellObjectStorePort, parquet_codec: ParquetLandingCodecPort | None, require_signed: bool
) -> None:
    if parquet_codec is not None:
        verify_generation_manifest(manifest, store=store, parquet_codec=parquet_codec, require_signed=require_signed)
        return
    _verify_manifest_curation_and_parent(manifest, store=store, require_signed=require_signed)
    for pq_loc in manifest.parquet_object_locators:
        if pq_loc.partition_key != manifest.partition_key:
            raise ClosedValidationError("generation_manifest: Parquet locator partition_key mismatch")
        raw_pq = store.get_bytes(pq_loc.object_ref, expected_size_bytes=pq_loc.size_bytes)
        if len(raw_pq) != pq_loc.size_bytes or "sha256:" + hashlib.sha256(raw_pq).hexdigest() != pq_loc.physical_parquet_digest:
            raise ClosedValidationError("generation_manifest: Parquet SHA-256 or size mismatch")


def _build_cut_envelopes(
    *, old_loc: ArtifactLocator, old_cat: DatasetCatalog, new_gen: GenerationManifest, gen_man_loc: ArtifactLocator,
    cut_id: str, cas_linearization_id: str, committed_at_utc: str, new_catalog_id: str,
    genesis_record_locator: ArtifactLocator | None, consumption_integrity: P1Integrity | None,
    catalog_integrity: P1Integrity | None, receipt_integrity: P1Integrity | None, require_signed: bool = False,
) -> tuple[DatasetCatalog, ArtifactLocator, DatasetCatalogGenesisConsumptionRecord | None, DatasetCatalogCutReceipt]:
    op, seq, new_heads = _expected_catalog_transition(old_cat, old_loc, new_gen, gen_man_loc)
    new_catalog = _reparse_p1(DatasetCatalog(new_catalog_id, old_cat.cell_ref, old_cat.catalog_epoch + 1, committed_at_utc, new_heads, catalog_integrity), DatasetCatalog, label="new_catalog", require_signed=require_signed)
    new_cat_loc = new_catalog.locator()
    cons_rec = None if genesis_record_locator is None else _reparse_p1(
        DatasetCatalogGenesisConsumptionRecord(genesis_record_locator, genesis_record_locator.content_digest, old_loc, old_loc.content_digest, new_cat_loc, new_cat_loc.content_digest, cut_id, cas_linearization_id, committed_at_utc, consumption_integrity),
        DatasetCatalogGenesisConsumptionRecord, label="genesis_consumption", require_signed=require_signed,
    )
    cons_loc = None if cons_rec is None else cons_rec.locator()
    raw_receipt = DatasetCatalogCutReceipt(
        cut_id=cut_id, cell_ref=old_cat.cell_ref, migration_run_context_locator=new_gen.migration_run_context_locator,
        old_catalog_locator=old_loc, old_catalog_digest=old_loc.content_digest, old_catalog_epoch=old_cat.catalog_epoch,
        new_catalog_locator=new_cat_loc, new_catalog_digest=new_cat_loc.content_digest, new_catalog_epoch=new_catalog.catalog_epoch,
        cas_request_projection=CatalogCasRequestProjection(op, old_cat.catalog_epoch, old_loc.content_digest, new_gen.partition_key, seq, gen_man_loc),
        cas_linearization_id=cas_linearization_id, committed_at_utc=committed_at_utc,
        genesis_record_locator=genesis_record_locator, genesis_record_digest=None if genesis_record_locator is None else genesis_record_locator.content_digest,
        genesis_consumption_locator=cons_loc, genesis_consumption_digest=None if cons_loc is None else cons_loc.content_digest, integrity=receipt_integrity,
    )
    return new_catalog, new_cat_loc, cons_rec, _reparse_p1(raw_receipt, DatasetCatalogCutReceipt, label="cut_receipt", require_signed=require_signed)


class GlobalDatasetCatalogService:
    """Linearizable single-writer global CAS service for `dataset_catalog/v1`."""

    def __init__(
        self, store: CellObjectStorePort, initial_catalog_locator: ArtifactLocator, *,
        parquet_codec: ParquetLandingCodecPort | None = None,
        consumed_genesis_digests: MutableSet[str] | None = None, require_signed: bool = False,
    ) -> None:
        checked_store = _require_store_and_bool(store, require_signed)
        if parquet_codec is not None:
            _require_parquet_codec(parquet_codec)
        if consumed_genesis_digests is not None and not isinstance(consumed_genesis_digests, MutableSet):
            raise ClosedValidationError("consumed_genesis_digests: expected MutableSet or None")
        init_loc = _typed_locator(initial_catalog_locator, field_name="initial_catalog_locator", expected_type=DatasetCatalog.SCHEMA)
        init_cat = _load_p1(checked_store, init_loc, DatasetCatalog, field_name="initial_catalog_locator", require_signed=require_signed)
        self._store, self._parquet_codec = checked_store, parquet_codec
        self._head_locator, self._head_catalog = init_loc, init_cat
        self._consumed_genesis: MutableSet[str] = consumed_genesis_digests if consumed_genesis_digests is not None else set()
        self._used_cut_ids: set[str] = set()
        self._used_linearization_ids: set[str] = set()
        self._require_signed = require_signed

    def current_head(self) -> tuple[ArtifactLocator, DatasetCatalog]:
        """Return the current `(catalog_locator, DatasetCatalog)` head."""
        return self._head_locator, self._head_catalog

    def _validate_cas_preconditions(
        self, *, cut_id: str, cas_linearization_id: str, expected_old_catalog_locator: ArtifactLocator,
        expected_old_catalog_epoch: int, genesis_record_locator: ArtifactLocator | None, consumption_integrity: P1Integrity | None,
    ) -> None:
        _strict_id(cut_id, field_name="cut_id")
        _strict_id(cas_linearization_id, field_name="cas_linearization_id")
        if cut_id in self._used_cut_ids or cas_linearization_id in self._used_linearization_ids:
            raise ClosedValidationError("dataset_catalog_cas: duplicate cut_id or cas_linearization_id")
        exp_loc = _typed_locator(expected_old_catalog_locator, field_name="expected_old_catalog_locator", expected_type=DatasetCatalog.SCHEMA)
        exp_ep = _safe_int(expected_old_catalog_epoch, field_name="expected_old_catalog_epoch", minimum=0)
        if exp_ep == 0 and genesis_record_locator is not None:
            gen_loc = _typed_locator(genesis_record_locator, field_name="genesis_record_locator", expected_type=DatasetCatalogGenesisRecord.SCHEMA)
            if gen_loc.content_digest in self._consumed_genesis:
                raise ClosedValidationError("dataset_catalog_cas: genesis record is single-use and already consumed")
        if (exp_loc, exp_ep) != (self._head_locator, self._head_catalog.catalog_epoch):
            raise ClosedValidationError("dataset_catalog_cas: stale expected_old_catalog_locator or expected_old_catalog_epoch")
        if exp_ep == 0:
            if genesis_record_locator is None:
                raise ClosedValidationError("dataset_catalog_cas: epoch-0 cut requires genesis_record_locator")
            gen_rec = _load_p1(self._store, genesis_record_locator, DatasetCatalogGenesisRecord, field_name="genesis_record_locator", require_signed=self._require_signed)
            if (gen_rec.cell_ref, gen_rec.empty_epoch0_catalog_locator) != (self._head_catalog.cell_ref, self._head_locator):
                raise ClosedValidationError("dataset_catalog_cas: genesis record does not match epoch-0 head")
        elif genesis_record_locator is not None or consumption_integrity is not None:
            raise ClosedValidationError("dataset_catalog_cas: genesis fields are forbidden when old_catalog_epoch >= 1")

    def commit_partition_cut(
        self, *, cut_id: str, cas_linearization_id: str, committed_at_utc: str,
        expected_old_catalog_locator: ArtifactLocator, expected_old_catalog_epoch: int,
        generation_manifest_locator: ArtifactLocator, new_catalog_id: str,
        genesis_record_locator: ArtifactLocator | None = None, consumption_integrity: P1Integrity | None = None,
        catalog_integrity: P1Integrity | None = None, receipt_integrity: P1Integrity | None = None,
    ) -> tuple[DatasetCatalog, ArtifactLocator, DatasetCatalogCutReceipt, ArtifactLocator]:
        """Atomically verify and commit a single-partition global catalog CAS cut."""
        self._validate_cas_preconditions(
            cut_id=cut_id, cas_linearization_id=cas_linearization_id, expected_old_catalog_locator=expected_old_catalog_locator,
            expected_old_catalog_epoch=expected_old_catalog_epoch, genesis_record_locator=genesis_record_locator, consumption_integrity=consumption_integrity,
        )
        gen_man_loc = _typed_locator(generation_manifest_locator, field_name="generation_manifest_locator", expected_type=GenerationManifest.SCHEMA)
        new_gen = _load_p1(self._store, gen_man_loc, GenerationManifest, field_name="generation_manifest_locator", require_signed=self._require_signed)
        _verify_generation_for_cas(new_gen, store=self._store, parquet_codec=self._parquet_codec, require_signed=self._require_signed)
        new_catalog, new_cat_loc, cons_rec, receipt = _build_cut_envelopes(
            old_loc=self._head_locator, old_cat=self._head_catalog, new_gen=new_gen, gen_man_loc=gen_man_loc,
            cut_id=cut_id, cas_linearization_id=cas_linearization_id, committed_at_utc=committed_at_utc,
            new_catalog_id=new_catalog_id, genesis_record_locator=genesis_record_locator,
            consumption_integrity=consumption_integrity, catalog_integrity=catalog_integrity,
            receipt_integrity=receipt_integrity, require_signed=self._require_signed,
        )
        self._store.put_json_artifact(DatasetCatalog.SCHEMA, new_catalog.to_dict())
        if cons_rec is not None and genesis_record_locator is not None:
            self._store.put_json_artifact(DatasetCatalogGenesisConsumptionRecord.SCHEMA, cons_rec.to_dict())
            self._consumed_genesis.add(genesis_record_locator.content_digest)
        receipt_loc = self._store.put_json_artifact(DatasetCatalogCutReceipt.SCHEMA, receipt.to_dict())
        self._used_cut_ids.add(cut_id)
        self._used_linearization_ids.add(cas_linearization_id)
        self._head_locator, self._head_catalog = new_cat_loc, new_catalog
        return new_catalog, new_cat_loc, receipt, receipt_loc


def verify_dataset_catalog_cut_receipt(
    receipt: DatasetCatalogCutReceipt, *, store: CellObjectStorePort, parquet_codec: ParquetLandingCodecPort, require_signed: bool = False
) -> DatasetCatalogCutReceipt:
    """Verify `DatasetCatalogCutReceipt` transition, genesis rules, and Parquet generation."""
    checked_store, checked_codec = _require_store_and_bool(store, require_signed), _require_parquet_codec(parquet_codec)
    fresh_rec = _reparse_exact(receipt, DatasetCatalogCutReceipt, label="receipt", require_signed=require_signed)
    _, _, new_gen = _verify_cut_receipt_metadata(fresh_rec, store=checked_store, require_signed=require_signed)
    verify_generation_manifest(new_gen, store=checked_store, parquet_codec=checked_codec, require_signed=require_signed)
    return fresh_rec


def publish_dataset_snapshot(
    *, snapshot_id: str, created_at: str, cut_receipt_locator: ArtifactLocator,
    store: CellObjectStorePort, integrity: P1Integrity | None = None,
) -> tuple[DatasetSnapshot, ArtifactLocator]:
    """Publish an immutable `DatasetSnapshot` byte-identical to `cut_receipt.new_catalog_locator`."""
    checked_store = _require_store_and_bool(store, False)
    checked_cut_loc = _typed_locator(cut_receipt_locator, field_name="cut_receipt_locator", expected_type=DatasetCatalogCutReceipt.SCHEMA)
    cut_receipt = _load_p1(checked_store, checked_cut_loc, DatasetCatalogCutReceipt, field_name="cut_receipt_locator")
    _, new_catalog, new_gen = _verify_cut_receipt_metadata(cut_receipt, store=checked_store, require_signed=False)
    _verify_generation_for_cas(new_gen, store=checked_store, parquet_codec=None, require_signed=False)
    snapshot = DatasetSnapshot(snapshot_id, new_catalog.catalog_epoch, cut_receipt.new_catalog_locator, checked_cut_loc, created_at, new_catalog.partition_heads, integrity=integrity)
    return snapshot, checked_store.put_json_artifact(DatasetSnapshot.SCHEMA, snapshot.to_dict())


def verify_dataset_snapshot(
    snapshot: DatasetSnapshot, *, store: CellObjectStorePort, parquet_codec: ParquetLandingCodecPort, require_signed: bool = False
) -> DatasetSnapshot:
    """Verify `DatasetSnapshot`, cut receipt, catalog byte-for-byte equality, and all generations."""
    checked_store, checked_codec = _require_store_and_bool(store, require_signed), _require_parquet_codec(parquet_codec)
    fresh_snap = _reparse_exact(snapshot, DatasetSnapshot, label="snapshot", require_signed=require_signed)
    cut_receipt = _load_p1(checked_store, fresh_snap.catalog_cut_receipt_locator, DatasetCatalogCutReceipt, field_name="snapshot.catalog_cut_receipt_locator", require_signed=require_signed)
    if fresh_snap.dataset_catalog_locator != cut_receipt.new_catalog_locator:
        raise ClosedValidationError("dataset_snapshot.dataset_catalog_locator: must equal cut_receipt.new_catalog_locator")
    _, new_catalog, new_gen = _verify_cut_receipt_metadata(cut_receipt, store=checked_store, require_signed=require_signed)
    if (fresh_snap.catalog_epoch, fresh_snap.partition_heads) != (new_catalog.catalog_epoch, new_catalog.partition_heads) or canonicalize_jcs([h.to_dict() for h in fresh_snap.partition_heads]) != canonicalize_jcs([h.to_dict() for h in new_catalog.partition_heads]):
        raise ClosedValidationError("dataset_snapshot: catalog_epoch or partition_heads differ from resolved DatasetCatalog")
    memo: dict[bytes, tuple[AnalyticsLandingRow, ...]] = {}
    _verify_generation_manifest_memo(new_gen, store=checked_store, parquet_codec=checked_codec, require_signed=require_signed, memo=memo, visiting=frozenset())
    for head in fresh_snap.partition_heads:
        head_gen = _load_p1(checked_store, head.generation_manifest_locator, GenerationManifest, field_name="snapshot.partition_heads[].generation_manifest_locator", require_signed=require_signed)
        if head_gen.partition_key != head.partition_key or (head.head_sequence_number == 1) != (head_gen.parent_generation_manifest_locator is None):
            raise ClosedValidationError("dataset_snapshot: partition_head partition_key or sequence/parent mismatch")
        rows = _verify_generation_manifest_memo(head_gen, store=checked_store, parquet_codec=checked_codec, require_signed=require_signed, memo=memo, visiting=frozenset())
        if any(partition_key_for_metric_date(r.fact_key.metric_date) != head.partition_key for r in rows):
            raise ClosedValidationError("dataset_snapshot: decoded row partition_key mismatch")
    return fresh_snap


__all__ = [
    "GlobalDatasetCatalogService", "build_sanitized_candidate_fact_set", "materialize_parquet_generation",
    "publish_dataset_snapshot", "replay_curated_partition_rows", "verify_algorithm_provenance_identity",
    "verify_curation_execution", "verify_dataset_catalog_cut_receipt", "verify_dataset_snapshot",
    "verify_generation_manifest", "verify_operational_read_evidence", "verify_sanitized_candidate_fact_set",
]
