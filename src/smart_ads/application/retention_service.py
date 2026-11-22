"""Transitive retention reachability closure and one-way logical root-set CAS (ADR-0001 §12.4)."""
from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from functools import cache
import hashlib
from types import MappingProxyType
from typing import Any, ClassVar, Final, TypeVar

from smart_ads.analytics import (
    AnalysisExecution, AnalysisPolicy, AnalysisReplayInputBundle, AnalysisResult, AnalysisResultSchema,
    AnalyticalCertificationRecord, CanonicalResultSet, DerivedMetricDefinition, DuckDbBinaryObjectLocator,
    DuckDbExtensionBinaryLocator, Finding, FormulaBundle, RegressionFixtureV1, ReportExecution,
)
from smart_ads.application.curation_pipeline import _load_p1, _reparse_exact, _require_parquet_codec, _require_store_and_bool
from smart_ads.contracts import (
    ADR_P1_DOMAIN_PREFIXES, AdmittedCollection, AnalyticsLandingRow, ArtifactLocator, BaseMetricDefinition,
    CanonicalQueryContract, ClosedValidationError, CollectionResult, GitArtifactProvenance, NormalizedCollectionFact,
    P1Integrity, SemanticObservationProjection, canonicalize_jcs, jcs_sha256, p1_content_digest,
    parse_timestamp_utc_micros, require_exact_keys, require_mapping, validate_envelope_timestamp_utc, validate_sha256_prefixed,
)
from smart_ads.contracts.effects import (
    EFFECT_ACTION_MATRIX, AuthorizationConsumptionRecord, AuthorizationReceipt, AuthorizationReservationRecord,
    EffectProof, ExecutionReceipt, ReservationStatus, RetentionReleaseTarget, RetentionRootAdmissionTarget, _safe_int,
    _sorted_locator_tuple, _sorted_object_ref_tuple, _split_p1_envelope, _strict_id, _strict_str, _typed_locator,
    _validate_nonce, sort_artifact_locators, sort_cell_object_refs, validate_cell_object_ref, verify_four_record_effect_proof,
)
from smart_ads.contracts.negative_security import NegativeSecurityTestReport
from smart_ads.contracts.operational_evidence import OperationalReadEvidence, SanitizedCandidateFactSet
from smart_ads.contracts.retention import (
    RetentionReleaseProof, RetentionReleaseResult, RetentionRoot, RetentionRootAdmissionProof,
    RetentionRootAdmissionResult, RetentionRootSetCasReceipt, RetentionRootSetCasRequestProjection,
    RetentionRootSetHead, compute_object_ref_set_digest, compute_root_locator_set_digest,
)
from smart_ads.domain import (
    CapabilityInvalidationTransition, CapabilityRevalidationTransition, CurationExecution, DatasetCatalog,
    DatasetCatalogCutReceipt, DatasetCatalogGenesisConsumptionRecord, DatasetCatalogGenesisRecord, DatasetSnapshot,
    ExpectedResourceInventory, GenerationManifest, ParquetObjectLocator, PipeboardPhase1Contract, PrivateRegistrySnapshot,
)
from smart_ads.ports.cell_runtime import ClockAttestation
from smart_ads.ports.storage import CellObjectStorePort, ParquetLandingCodecPort

_T = TypeVar("_T")
_RUN_CONTEXT_SCHEMA: Final[str] = "smart_ads/migration_run_context/v1"
_GRAPH_PROJECTION_SCHEMA: Final[str] = "smart_ads/retention_reachability_graph_projection/v1"
_MAX_SCAN_DEPTH: Final[int] = 128
_OTHER_ADR_EFFECT_SPECS: Final[Mapping[str, tuple[str, str, str]]] = MappingProxyType({
    "workload_identity_provision": ("workload_identity_target", "smart_ads/workload_identity_execution_result/v1", "workload_identity_effect_proof"),
    "deployment_config_apply": ("deployment_target", "smart_ads/deployment_config_execution_result/v1", "deployment_config_effect_proof"),
    "shadow_mode_enable": ("shadow_target", "smart_ads/shadow_mode_activation_result/v1", "shadow_mode_effect_proof"),
    "rollback_toggle": ("rollback_target", "smart_ads/rollback_toggle_result/v1", "rollback_test_effect_proof"),
    "incident_rollback": ("incident_rollback_target", "smart_ads/incident_rollback_result/v1", "incident_rollback_effect_proof"),
    "readiness_attestation_sign": ("readiness_attestation_target", "smart_ads/readiness_attestation/v1", "readiness_attestation_effect_proof"),
    "cutover_execution": ("cutover_target", "smart_ads/cutover_execution_result/v1", "cutover_effect_proof"),
    "legacy_read_retirement": ("retirement_target", "smart_ads/retirement_execution_result/v1", "retirement_effect_proof"),
})


@dataclass(frozen=True, slots=True)
class WheelObjectLocator:
    """Closed 5-member `smart_ads/wheel_object_locator/v1` embedded binary locator."""

    SCHEMA: ClassVar[str] = "smart_ads/wheel_object_locator/v1"
    KEYS: ClassVar[frozenset[str]] = frozenset({"$schema", "store_kind", "object_ref", "wheel_digest", "size_bytes"})
    wheel_digest: str
    size_bytes: int
    store_kind: str = "cell_immutable_object"
    object_ref: str = ""

    def __post_init__(self) -> None:
        label = "wheel_object_locator"
        sha = validate_sha256_prefixed(_strict_str(self.wheel_digest, field_name=f"{label}.wheel_digest"), field_name=f"{label}.wheel_digest")
        _safe_int(self.size_bytes, field_name=f"{label}.size_bytes", minimum=1)
        if _strict_str(self.store_kind, field_name=f"{label}.store_kind") != "cell_immutable_object":
            raise ClosedValidationError(f"{label}.store_kind: must equal 'cell_immutable_object'")
        expected_ref = f"cell-object:{sha}"
        raw_ref = _strict_str(self.object_ref, field_name=f"{label}.object_ref")
        if raw_ref == "":
            object.__setattr__(self, "object_ref", expected_ref)
        elif raw_ref != expected_ref:
            raise ClosedValidationError(f"{label}.object_ref: expected {expected_ref!r}, got {raw_ref!r}")

    @classmethod
    def for_wheel_bytes(cls, raw_bytes: bytes) -> WheelObjectLocator:
        """Build a `WheelObjectLocator` over raw immutable wheel bytes."""
        if type(raw_bytes) is not bytes or len(raw_bytes) == 0:
            raise ClosedValidationError("raw_bytes: expected non-empty bytes")
        digest = "sha256:" + hashlib.sha256(raw_bytes).hexdigest()
        return cls(wheel_digest=digest, size_bytes=len(raw_bytes), object_ref=f"cell-object:{digest}")

    def to_dict(self) -> dict[str, Any]:
        return {"$schema": self.SCHEMA, "store_kind": self.store_kind, "object_ref": self.object_ref, "wheel_digest": self.wheel_digest, "size_bytes": self.size_bytes}

    @classmethod
    def from_dict(cls, data: object) -> WheelObjectLocator:
        m = require_exact_keys(data, cls.KEYS, label="wheel_object_locator")
        if type(m["$schema"]) is not str or m["$schema"] != cls.SCHEMA:
            raise ClosedValidationError(f"wheel_object_locator.$schema: expected {cls.SCHEMA!r}")
        return cls(wheel_digest=m["wheel_digest"], size_bytes=m["size_bytes"], store_kind=m["store_kind"], object_ref=validate_cell_object_ref(m["object_ref"], field_name="wheel_object_locator.object_ref"))


_BINARY_LOCATOR_SCHEMAS: Final[frozenset[str]] = frozenset({
    ParquetObjectLocator.SCHEMA, DuckDbBinaryObjectLocator.SCHEMA, DuckDbExtensionBinaryLocator.SCHEMA, WheelObjectLocator.SCHEMA,
})


@dataclass(frozen=True, slots=True)
class ReachabilityClosure:
    """Deterministic transitive reachability closure over `CellObjectStorePort`."""

    root_locators: tuple[ArtifactLocator, ...]
    reachable_object_refs: tuple[str, ...]
    reachable_artifact_locators: tuple[ArtifactLocator, ...]
    reachability_graph_digest: str

    def __post_init__(self) -> None:
        roots = _sorted_locator_tuple(self.root_locators, field_name="reachability_closure.root_locators", allow_empty=True)
        refs = _sorted_object_ref_tuple(self.reachable_object_refs, field_name="reachability_closure.reachable_object_refs", allow_empty=True)
        arts = _sorted_locator_tuple(self.reachable_artifact_locators, field_name="reachability_closure.reachable_artifact_locators", allow_empty=True)
        validate_sha256_prefixed(_strict_str(self.reachability_graph_digest, field_name="reachability_closure.reachability_graph_digest"), field_name="reachability_closure.reachability_graph_digest")
        if not set(roots).issubset(arts) or not {a.object_ref for a in arts}.issubset(refs):
            raise ClosedValidationError("reachability_closure: root/artifact subset invariant violated")
        object.__setattr__(self, "root_locators", roots)
        object.__setattr__(self, "reachable_object_refs", refs)
        object.__setattr__(self, "reachable_artifact_locators", arts)


def _check_store_and_codec(store: object, parquet_codec: object, require_signed: object = False) -> CellObjectStorePort:
    checked_store = _require_store_and_bool(store, require_signed)
    if parquet_codec is not None:
        _require_parquet_codec(parquet_codec)
    return checked_store

def _dedup_sorted_locators(locators: Iterable[ArtifactLocator], *, field_name: str) -> tuple[ArtifactLocator, ...]:
    by_key = {canonicalize_jcs(_typed_locator(loc, field_name=f"{field_name}[{i}]").to_dict()): _typed_locator(loc, field_name=f"{field_name}[{i}]") for i, loc in enumerate(locators)}
    return tuple(by_key[k] for k in sorted(by_key))

def _validate_optional_integrity(value: object, *, label: str, require_signed: bool = False) -> P1Integrity | None:
    if value is None:
        if require_signed:
            raise ClosedValidationError(f"{label}: signed P1Integrity is required")
        return None
    if type(value) is not P1Integrity:
        raise ClosedValidationError(f"{label}: expected P1Integrity, got {type(value).__name__}")
    fresh = P1Integrity.from_dict(value.to_dict(), require_signed=require_signed or value.is_signed)
    if value != fresh:
        raise ClosedValidationError(f"{label}: malformed P1Integrity")
    return fresh

def _validate_non_pr4_effect_envelope(raw_doc: Mapping[str, Any], cls: type[Any], *, require_signed: bool) -> Any:
    action = raw_doc.get("action")
    if type(action) is not str or action in EFFECT_ACTION_MATRIX or action not in _OTHER_ADR_EFFECT_SPECS:
        return cls.from_dict(raw_doc, require_signed=require_signed)
    subj_kind, result_type, exp_slot = _OTHER_ADR_EFFECT_SPECS[action]
    m, integ = _split_p1_envelope(raw_doc, core_keys=cls.CORE_KEYS, schema=cls.SCHEMA, label=cls.SCHEMA, require_signed=require_signed)
    if integ is not None and integ.is_signed and integ.content_digest != p1_content_digest(raw_doc):
        raise ClosedValidationError(f"{cls.SCHEMA}.integrity.content_digest: mismatch")
    if _strict_str(m["dag_slot"], field_name="dag_slot") != exp_slot:
        raise ClosedValidationError(f"{cls.SCHEMA}.dag_slot: expected {exp_slot!r}")
    run_loc = ArtifactLocator.from_dict(m["migration_run_context_locator"], expected_type=_RUN_CONTEXT_SCHEMA)
    if "subject" in m:
        subj = require_mapping(m["subject"], label=f"{cls.SCHEMA}.subject")
        if subj.get("subject_kind") != subj_kind or ArtifactLocator.from_dict(subj.get("migration_run_context_locator"), expected_type=_RUN_CONTEXT_SCHEMA) != run_loc:
            raise ClosedValidationError(f"{cls.SCHEMA}.subject: invalid subject_kind or run context")
    if "single_use_nonce" in m:
        _validate_nonce(m["single_use_nonce"], field_name="single_use_nonce")
    if "action_result_locator" in m:
        ArtifactLocator.from_dict(m["action_result_locator"], expected_type=result_type)
    for ts_k in ("issued_at_utc", "valid_until_utc", "reserved_at_utc", "executed_at_utc", "consumed_at_utc", "verified_at_utc"):
        if ts_k in m:
            validate_envelope_timestamp_utc(m[ts_k], field_name=ts_k)
    return m

@cache
def _schema_parsers() -> Mapping[str, Callable[[Mapping[str, Any], bool], Any]]:
    from smart_ads.reconciliation import Certification7ARecord, Certification7BRecord, NativeRequestProjection, ToleranceProfile
    p1_classes: tuple[type[Any], ...] = (
        AdmittedCollection, CollectionResult, BaseMetricDefinition, GitArtifactProvenance, NegativeSecurityTestReport,
        OperationalReadEvidence, SanitizedCandidateFactSet, RetentionRoot, RetentionRootSetHead,
        RetentionRootSetCasReceipt, RetentionRootAdmissionResult, RetentionRootAdmissionProof,
        RetentionReleaseResult, RetentionReleaseProof, PrivateRegistrySnapshot, ExpectedResourceInventory,
        PipeboardPhase1Contract, CapabilityRevalidationTransition, CapabilityInvalidationTransition,
        CurationExecution, GenerationManifest, DatasetCatalogGenesisRecord, DatasetCatalogGenesisConsumptionRecord,
        DatasetCatalog, DatasetCatalogCutReceipt, DatasetSnapshot, ClockAttestation, FormulaBundle, AnalysisPolicy,
        AnalysisResultSchema, AnalysisResult, AnalysisExecution, Finding, AnalyticalCertificationRecord,
        AnalysisReplayInputBundle, ReportExecution, ToleranceProfile, NativeRequestProjection,
        Certification7BRecord, Certification7ARecord,
    )
    embedded_pairs: tuple[tuple[str, type[Any]], ...] = (
        ("smart_ads/canonical_query_contract/v1", CanonicalQueryContract),
        ("smart_ads/analytics_landing_row/v1", AnalyticsLandingRow),
        ("smart_ads/normalized_collection_fact/v1", NormalizedCollectionFact),
        ("smart_ads/semantic_observation_projection/v1", SemanticObservationProjection),
        (DerivedMetricDefinition.SCHEMA, DerivedMetricDefinition),
        (RegressionFixtureV1.SCHEMA, RegressionFixtureV1),
        (CanonicalResultSet.SCHEMA, CanonicalResultSet),
    )
    effects = (AuthorizationReceipt, AuthorizationReservationRecord, ExecutionReceipt, AuthorizationConsumptionRecord, EffectProof)
    out: dict[str, Callable[[Mapping[str, Any], bool], Any]] = {c.SCHEMA: (lambda d, req, _c=c: _c.from_dict(d, require_signed=req)) for c in p1_classes}
    out.update({sch: (lambda d, _req, _c=c: _c.from_dict(d)) for sch, c in embedded_pairs})
    out.update({c.SCHEMA: (lambda d, req, _c=c: _validate_non_pr4_effect_envelope(d, _c, require_signed=req)) for c in effects})
    return MappingProxyType(out)

def _validate_resolved_json_doc(loc: ArtifactLocator, raw_doc: object, *, require_signed: bool) -> Any:
    mapping = require_mapping(raw_doc, label=f"resolved_artifact[{loc.object_ref!r}]")
    if mapping.get("$schema") != loc.artifact_type:
        raise ClosedValidationError(f"resolved_artifact[{loc.object_ref!r}]: '$schema' != {loc.artifact_type!r}")
    if loc.artifact_type in ADR_P1_DOMAIN_PREFIXES and (require_signed or "integrity" in mapping):
        if "integrity" not in mapping:
            raise ClosedValidationError(f"resolved_artifact[{loc.object_ref!r}]: missing P1 integrity")
        integ = P1Integrity.from_dict(mapping["integrity"], require_signed=require_signed)
        if integ.is_signed and integ.content_digest != p1_content_digest(mapping):
            raise ClosedValidationError(f"resolved_artifact[{loc.object_ref!r}]: P1 content_digest mismatch")
    parser = _schema_parsers().get(loc.artifact_type)
    return None if parser is None else parser(mapping, require_signed)

def _verify_embedded_binary_locator(node: Mapping[str, Any], *, store: CellObjectStorePort, parquet_codec: ParquetLandingCodecPort | None) -> str:
    schema = node.get("$schema")
    if schema == ParquetObjectLocator.SCHEMA:
        pq = ParquetObjectLocator.from_dict(node)
        raw = store.get_bytes(pq.object_ref, expected_size_bytes=pq.size_bytes)
        if len(raw) != pq.size_bytes or "sha256:" + hashlib.sha256(raw).hexdigest() != pq.physical_parquet_digest:
            raise ClosedValidationError("parquet_object_locator: raw SHA-256 or size mismatch")
        if parquet_codec is not None:
            parquet_codec.decode_and_verify_landing_rows(raw, expected_partition_key=pq.partition_key)
        return pq.object_ref
    if schema == DuckDbBinaryObjectLocator.SCHEMA:
        loc_obj: Any = DuckDbBinaryObjectLocator.from_dict(node)
        exp_sha = loc_obj.binary_sha256
    elif schema == DuckDbExtensionBinaryLocator.SCHEMA:
        loc_obj = DuckDbExtensionBinaryLocator.from_dict(node)
        exp_sha = loc_obj.binary_sha256
    else:
        loc_obj = WheelObjectLocator.from_dict(node)
        exp_sha = loc_obj.wheel_digest
    raw = store.get_bytes(loc_obj.object_ref, expected_size_bytes=loc_obj.size_bytes)
    if len(raw) != loc_obj.size_bytes or "sha256:" + hashlib.sha256(raw).hexdigest() != exp_sha:
        raise ClosedValidationError(f"{schema}: raw binary SHA-256 or size mismatch")
    return str(loc_obj.object_ref)

def _scan_json_tree_references(
    node: Any, *, is_root: bool, depth: int, store: CellObjectStorePort,
    parquet_codec: ParquetLandingCodecPort | None, child_locs: list[ArtifactLocator], binary_refs: list[str],
) -> None:
    if depth > _MAX_SCAN_DEPTH:
        raise ClosedValidationError("retention_reachability_graph: maximum JSON nesting depth exceeded")
    if isinstance(node, Mapping):
        if not is_root:
            schema = node.get("$schema")
            if schema == ArtifactLocator.SCHEMA:
                child_locs.append(ArtifactLocator.from_dict(node))
                return
            if type(schema) is str and schema in _BINARY_LOCATOR_SCHEMAS:
                binary_refs.append(_verify_embedded_binary_locator(node, store=store, parquet_codec=parquet_codec))
                return
        for val in node.values():
            _scan_json_tree_references(val, is_root=False, depth=depth + 1, store=store, parquet_codec=parquet_codec, child_locs=child_locs, binary_refs=binary_refs)
    elif isinstance(node, (list, tuple)):
        for item in node:
            _scan_json_tree_references(item, is_root=False, depth=depth + 1, store=store, parquet_codec=parquet_codec, child_locs=child_locs, binary_refs=binary_refs)

def _root_seed_locators(target_loc: ArtifactLocator, run_loc: ArtifactLocator, integrity: P1Integrity | None) -> tuple[ArtifactLocator, ...]:
    return _dedup_sorted_locators([target_loc, run_loc, *(() if integrity is None else (integrity.key_registry_snapshot_locator,))], field_name="retention_root.seeds")

def _verify_visited_retention_root(
    root: RetentionRoot, outer_loc: ArtifactLocator, adjacency: Mapping[bytes, tuple[tuple[ArtifactLocator, ...], tuple[str, ...]]],
) -> None:
    stack = list(_root_seed_locators(root.target_artifact_locator, root.migration_run_context_locator, root.integrity))
    seen_keys: set[bytes] = set()
    sub_refs: set[str] = set()
    while stack:
        cur = stack.pop()
        ck = canonicalize_jcs(cur.to_dict())
        if ck not in seen_keys:
            seen_keys.add(ck)
            children, bins = adjacency[ck]
            sub_refs.update((cur.object_ref, *bins))
            stack.extend(children)
    ordered = sort_cell_object_refs(sub_refs, allow_empty=False, field_name="retention_root.pinned_object_refs")
    if outer_loc.object_ref in sub_refs or root.pinned_object_refs != ordered or root.pinned_object_set_digest != compute_object_ref_set_digest(ordered, allow_empty=False):
        raise ClosedValidationError("retention_root: pinned_object_refs or digest mismatch against transitive closure")

def _visit_locator(
    loc: ArtifactLocator, *, store: CellObjectStorePort, parquet_codec: ParquetLandingCodecPort | None, require_signed: bool,
    visiting: set[bytes], visiting_refs: set[str], visited: dict[bytes, ArtifactLocator],
    adjacency: dict[bytes, tuple[tuple[ArtifactLocator, ...], tuple[str, ...]]], all_object_refs: set[str],
) -> None:
    loc_key = canonicalize_jcs(loc.to_dict())
    if loc_key in visiting or loc.object_ref in visiting_refs:
        raise ClosedValidationError(f"retention_reachability_graph: locator cycle detected at {loc.object_ref!r}")
    if loc_key in visited:
        return
    visiting.add(loc_key)
    visiting_refs.add(loc.object_ref)
    raw_doc = store.get_json_artifact(loc)
    parsed = _validate_resolved_json_doc(loc, raw_doc, require_signed=require_signed)
    raw_children: list[ArtifactLocator] = []
    raw_bins: list[str] = []
    _scan_json_tree_references(raw_doc, is_root=True, depth=0, store=store, parquet_codec=parquet_codec, child_locs=raw_children, binary_refs=raw_bins)
    sorted_children = _dedup_sorted_locators(raw_children, field_name="child_locators")
    sorted_bins = sort_cell_object_refs(set(raw_bins), allow_empty=True, field_name="binary_refs")
    for child_loc in sorted_children:
        _visit_locator(child_loc, store=store, parquet_codec=parquet_codec, require_signed=require_signed, visiting=visiting, visiting_refs=visiting_refs, visited=visited, adjacency=adjacency, all_object_refs=all_object_refs)
    if ArtifactLocator.for_canonical_bytes(loc.artifact_type, canonicalize_jcs(raw_doc)) != loc:
        raise ClosedValidationError(f"retention_reachability_graph: resolved JSON digest mismatch on {loc.object_ref!r}")
    visiting.remove(loc_key)
    visiting_refs.remove(loc.object_ref)
    if isinstance(parsed, RetentionRoot):
        _verify_visited_retention_root(parsed, loc, adjacency)
    visited[loc_key] = loc
    adjacency[loc_key] = (sorted_children, sorted_bins)
    all_object_refs.update((loc.object_ref, *sorted_bins))

def _compute_reachability(
    target_locators: Sequence[ArtifactLocator], *, store: CellObjectStorePort, parquet_codec: ParquetLandingCodecPort | None, require_signed: bool,
) -> ReachabilityClosure:
    if isinstance(target_locators, (str, bytes)) or not isinstance(target_locators, Sequence):
        raise ClosedValidationError("target_locators: expected Sequence of ArtifactLocator")
    ordered_roots = _dedup_sorted_locators(target_locators, field_name="target_locators")
    visiting: set[bytes] = set()
    visiting_refs: set[str] = set()
    visited: dict[bytes, ArtifactLocator] = {}
    adjacency: dict[bytes, tuple[tuple[ArtifactLocator, ...], tuple[str, ...]]] = {}
    all_refs: set[str] = set()
    for root_loc in ordered_roots:
        _visit_locator(root_loc, store=store, parquet_codec=parquet_codec, require_signed=require_signed, visiting=visiting, visiting_refs=visiting_refs, visited=visited, adjacency=adjacency, all_object_refs=all_refs)
    ordered_keys = sorted(visited)
    ordered_arts = tuple(visited[k] for k in ordered_keys)
    ordered_refs = sort_cell_object_refs(all_refs, allow_empty=True, field_name="reachable_object_refs")
    adj_list = [{"artifact_locator": visited[k].to_dict(), "artifact_edges": [c.to_dict() for c in adjacency[k][0]], "binary_object_refs": list(adjacency[k][1])} for k in ordered_keys]
    graph_digest = jcs_sha256({"$schema": _GRAPH_PROJECTION_SCHEMA, "root_locators": [r.to_dict() for r in ordered_roots], "reachable_artifact_locators": [a.to_dict() for a in ordered_arts], "reachable_object_refs": list(ordered_refs), "adjacency": adj_list})
    return ReachabilityClosure(ordered_roots, ordered_refs, ordered_arts, graph_digest)


def compute_retention_reachability_graph(target_locators: Sequence[ArtifactLocator], *, store: CellObjectStorePort, parquet_codec: ParquetLandingCodecPort | None = None) -> ReachabilityClosure:
    """Compute the verified transitive reachability closure of `target_locators` in `store`."""
    return _compute_reachability(target_locators, store=_check_store_and_codec(store, parquet_codec), parquet_codec=parquet_codec, require_signed=False)


def build_retention_root(
    *, root_id: str, cell_ref: str, migration_run_context_locator: ArtifactLocator, target_artifact_locator: ArtifactLocator,
    created_at_utc: str, store: CellObjectStorePort, parquet_codec: ParquetLandingCodecPort | None = None, integrity: P1Integrity | None = None,
) -> tuple[RetentionRoot, ArtifactLocator]:
    """Verify full transitive closure, exclude outer self-ref, and store `RetentionRoot`."""
    checked_store = _check_store_and_codec(store, parquet_codec)
    checked_int = _validate_optional_integrity(integrity, label="integrity")
    run_loc = _typed_locator(migration_run_context_locator, field_name="migration_run_context_locator", expected_type=_RUN_CONTEXT_SCHEMA)
    target_loc = _typed_locator(target_artifact_locator, field_name="target_artifact_locator")
    if target_loc.artifact_type == RetentionRoot.SCHEMA:
        raise ClosedValidationError("target_artifact_locator: retention_root cannot target another retention_root")
    closure = _compute_reachability(_root_seed_locators(target_loc, run_loc, checked_int), store=checked_store, parquet_codec=parquet_codec, require_signed=False)
    root = RetentionRoot(root_id, cell_ref, run_loc, target_loc, closure.reachable_object_refs, created_at_utc, integrity=checked_int)
    if root.locator().object_ref in root.pinned_object_refs or target_loc.object_ref not in root.pinned_object_refs:
        raise ClosedValidationError("retention_root: self-referential cycle or missing 0-hop target ref")
    stored_loc = checked_store.put_json_artifact(RetentionRoot.SCHEMA, root.to_dict())
    verify_retention_root(root, store=checked_store, parquet_codec=parquet_codec, require_signed=bool(checked_int is not None and checked_int.is_signed))
    return root, stored_loc


def verify_retention_root(root: RetentionRoot, *, store: CellObjectStorePort, parquet_codec: ParquetLandingCodecPort | None = None, require_signed: bool = False) -> ReachabilityClosure:
    """Verify `RetentionRoot` 0-hop inclusion, outer self-exclusion, and exact closure equality."""
    checked_store = _check_store_and_codec(store, parquet_codec, require_signed)
    fresh = _reparse_exact(root, RetentionRoot, label="root", require_signed=require_signed)
    seeds = _root_seed_locators(fresh.target_artifact_locator, fresh.migration_run_context_locator, fresh.integrity)
    pinned_set = set(fresh.pinned_object_refs)
    if fresh.locator().object_ref in pinned_set or not {s.object_ref for s in seeds}.issubset(pinned_set):
        raise ClosedValidationError("retention_root: 0-hop target/seed missing or outer object_ref cycle detected")
    closure = _compute_reachability(seeds, store=checked_store, parquet_codec=parquet_codec, require_signed=require_signed)
    if fresh.pinned_object_refs != closure.reachable_object_refs or fresh.pinned_object_set_digest != compute_object_ref_set_digest(closure.reachable_object_refs, allow_empty=False):
        raise ClosedValidationError("retention_root: pinned_object_refs or digest mismatch against recomputed closure")
    return closure

def _head_pinned_object_refs(head: RetentionRootSetHead, *, store: CellObjectStorePort, parquet_codec: ParquetLandingCodecPort | None, require_signed: bool) -> tuple[frozenset[str], str]:
    fresh_head = _reparse_exact(head, RetentionRootSetHead, label="head", require_signed=require_signed)
    closure = _compute_reachability(fresh_head.live_root_locators, store=store, parquet_codec=parquet_codec, require_signed=require_signed)
    resolved = [_load_p1(store, loc, RetentionRoot, field_name="head.live_root_locators[]", require_signed=require_signed) for loc in fresh_head.live_root_locators]
    if any(r.cell_ref != fresh_head.cell_ref for r in resolved):
        raise ClosedValidationError("retention_root_set_head: cross-cell RetentionRoot is forbidden")
    expected_union = {loc.object_ref for loc in fresh_head.live_root_locators} | {ref for r in resolved for ref in r.pinned_object_refs}
    if frozenset(closure.reachable_object_refs) != expected_union:
        raise ClosedValidationError("retention_root_set_head: union of live root pinned_object_refs diverged from graph")
    return frozenset(closure.reachable_object_refs), closure.reachability_graph_digest


def head_pinned_object_refs(head: RetentionRootSetHead, *, store: CellObjectStorePort, parquet_codec: ParquetLandingCodecPort | None = None) -> tuple[frozenset[str], str]:
    """Return `(pinned_object_refs, reachability_graph_digest)` for `head`."""
    return _head_pinned_object_refs(head, store=_check_store_and_codec(store, parquet_codec), parquet_codec=parquet_codec, require_signed=False)


def _validate_integrities_map(integrities: Mapping[str, P1Integrity] | None, *, allowed_keys: frozenset[str], require_signed: bool) -> dict[str, P1Integrity]:
    if integrities is None:
        if require_signed:
            raise ClosedValidationError("integrities: signed P1Integrity mapping required when require_signed=True")
        return {}
    if not isinstance(integrities, Mapping) or any(type(k) is not str or k not in allowed_keys for k in integrities):
        raise ClosedValidationError("integrities: invalid mapping or unsupported envelope key")
    out = {k: _validate_optional_integrity(v, label=f"integrities[{k!r}]", require_signed=require_signed) for k, v in integrities.items()}
    if require_signed and "reservation" not in out:
        raise ClosedValidationError("integrities['reservation']: required when require_signed=True")
    return {k: v for k, v in out.items() if v is not None}

def _check_key_registry_consistency(*envelopes: Any) -> None:
    if len({e.integrity.key_registry_snapshot_locator for e in envelopes if getattr(e, "integrity", None) is not None}) > 1:
        raise ClosedValidationError("retention_service: key_registry_snapshot_locator mismatch across envelopes")

def _utc_micros(ts: str) -> int:
    return parse_timestamp_utc_micros(ts, allow_whole_seconds=True)

def _verify_admission_roots_and_closures(
    *, b_head: RetentionRootSetHead, admitted_locs: tuple[ArtifactLocator, ...], run_loc: ArtifactLocator,
    store: CellObjectStorePort, parquet_codec: ParquetLandingCodecPort | None, require_signed: bool,
) -> tuple[tuple[ArtifactLocator, ...], str, frozenset[str], str, ReachabilityClosure, ReachabilityClosure]:
    if not set(admitted_locs).isdisjoint(b_head.live_root_locators):
        raise ClosedValidationError("retention_root_admission: admitted_root_locators overlaps live_root_locators")
    for r_loc in admitted_locs:
        r_obj = _load_p1(store, r_loc, RetentionRoot, field_name="admitted_root_locators[]", require_signed=require_signed)
        if (r_obj.cell_ref, r_obj.migration_run_context_locator) != (b_head.cell_ref, run_loc):
            raise ClosedValidationError("retention_root_admission: admitted root cell_ref or run mismatch")
    b_objs, b_dig = _head_pinned_object_refs(b_head, store=store, parquet_codec=parquet_codec, require_signed=require_signed)
    adm_closure = _compute_reachability(admitted_locs, store=store, parquet_codec=parquet_codec, require_signed=require_signed)
    proposed = sort_artifact_locators((*b_head.live_root_locators, *admitted_locs), expected_type=RetentionRoot.SCHEMA, allow_empty=False)
    prop_dig = compute_root_locator_set_digest(proposed, allow_empty=False)
    after_closure = _compute_reachability(proposed, store=store, parquet_codec=parquet_codec, require_signed=require_signed)
    if set(after_closure.reachable_object_refs) != (b_objs | set(adm_closure.reachable_object_refs)):
        raise ClosedValidationError("retention_root_admission: after reachability objects diverged from union")
    return proposed, prop_dig, b_objs, b_dig, adm_closure, after_closure

def _verify_release_roots_and_closures(
    *, b_head: RetentionRootSetHead, released_locs: tuple[ArtifactLocator, ...], claimed_rel_refs: tuple[str, ...],
    store: CellObjectStorePort, parquet_codec: ParquetLandingCodecPort | None, require_signed: bool,
) -> tuple[tuple[ArtifactLocator, ...], str, frozenset[str], str, ReachabilityClosure]:
    if not set(released_locs).issubset(b_head.live_root_locators):
        raise ClosedValidationError("retention_release: released_root_locators not subset of live_root_locators")
    exp_retained = sort_artifact_locators([r for r in b_head.live_root_locators if r not in set(released_locs)], expected_type=RetentionRoot.SCHEMA, allow_empty=True)
    b_objs, b_dig = _head_pinned_object_refs(b_head, store=store, parquet_codec=parquet_codec, require_signed=require_signed)
    after_closure = _compute_reachability(exp_retained, store=store, parquet_codec=parquet_codec, require_signed=require_signed)
    ret_objs = frozenset(after_closure.reachable_object_refs)
    if not set(claimed_rel_refs).isdisjoint(ret_objs):
        raise ClosedValidationError("retention_release: released_object_refs overlaps objects reachable from retained roots")
    if set(claimed_rel_refs) != (b_objs - ret_objs):
        raise ClosedValidationError("retention_release: released_object_refs != (before_objects - retained_objects)")
    return exp_retained, compute_root_locator_set_digest(exp_retained, allow_empty=True), b_objs, b_dig, after_closure


class RetentionRootSetService:
    """Linearizable one-way logical root-set CAS service (`absent -> reserved -> consumed | in_doubt`)."""

    def __init__(
        self, store: CellObjectStorePort, initial_head_locator: ArtifactLocator, *,
        parquet_codec: ParquetLandingCodecPort | None = None, require_signed: bool = False,
    ) -> None:
        checked_store = _check_store_and_codec(store, parquet_codec, require_signed)
        init_loc = _typed_locator(initial_head_locator, field_name="initial_head_locator", expected_type=RetentionRootSetHead.SCHEMA)
        init_head = _load_p1(checked_store, init_loc, RetentionRootSetHead, field_name="initial_head_locator", require_signed=require_signed)
        _head_pinned_object_refs(init_head, store=checked_store, parquet_codec=parquet_codec, require_signed=require_signed)
        self._store, self._parquet_codec, self._require_signed = checked_store, parquet_codec, require_signed
        self._head_locator, self._head = init_loc, init_head
        self._nonce_states: dict[str, ReservationStatus] = {}
        self._auth_states: dict[bytes, ReservationStatus] = {}
        self._used_ids: set[str] = {f"head:{init_head.head_id}"}

    def current_head(self) -> tuple[ArtifactLocator, RetentionRootSetHead]:
        """Return the current `(head_locator, RetentionRootSetHead)` pair."""
        return self._head_locator, self._head

    def reservation_status_for(self, authorization_locator: ArtifactLocator) -> ReservationStatus | None:
        """Return `'reserved' | 'consumed' | 'in_doubt'` for `authorization_locator`, or `None` if absent."""
        return self._auth_states.get(canonicalize_jcs(_typed_locator(authorization_locator, field_name="authorization_locator", expected_type=AuthorizationReceipt.SCHEMA).to_dict()))

    def _prepare_and_reserve(
        self, *, authorization_locator: ArtifactLocator, expected_action: str, expected_slot: str, expected_subject_cls: type[Any],
        result_key: str, proof_key: str, reservation_id: str, reserved_at_utc: str, cas_receipt_id: str, cas_linearization_id: str,
        committed_at_utc: str, new_head_id: str, execution_id: str, consumption_id: str, effect_proof_id: str,
        verified_at_utc: str, integrities: Mapping[str, P1Integrity] | None,
    ) -> tuple[ArtifactLocator, bytes, AuthorizationReceipt, AuthorizationReservationRecord, ArtifactLocator, dict[str, P1Integrity], set[str]]:
        post_ids = {f"{p}:{_strict_id(v, field_name=n)}" for p, n, v in (("cas", "cas_receipt_id", cas_receipt_id), ("lin", "cas_linearization_id", cas_linearization_id), ("head", "new_head_id", new_head_id), ("exec", "execution_id", execution_id), ("cons", "consumption_id", consumption_id), ("efp", "effect_proof_id", effect_proof_id))}
        resv_tag = f"resv:{_strict_id(reservation_id, field_name='reservation_id')}"
        if resv_tag in self._used_ids or (post_ids & self._used_ids):
            raise ClosedValidationError("retention_root_set_service: duplicate envelope or linearization ID")
        for nm, ts in (("reserved_at_utc", reserved_at_utc), ("committed_at_utc", committed_at_utc), ("verified_at_utc", verified_at_utc)):
            validate_envelope_timestamp_utc(ts, field_name=nm)
        r_us, c_us, v_us = _utc_micros(reserved_at_utc), _utc_micros(committed_at_utc), _utc_micros(verified_at_utc)
        if not (r_us <= c_us <= v_us):
            raise ClosedValidationError("retention_root_set_service: require reserved_at_utc <= committed_at_utc <= verified_at_utc")
        allowed = frozenset({"reservation", "in_doubt_reservation", "new_head", "cas_receipt", result_key, "execution", "consumption", "effect_proof", proof_key})
        checked_ints = _validate_integrities_map(integrities, allowed_keys=allowed, require_signed=self._require_signed)
        auth_loc = _typed_locator(authorization_locator, field_name="authorization_locator", expected_type=AuthorizationReceipt.SCHEMA)
        auth = _load_p1(self._store, auth_loc, AuthorizationReceipt, field_name="authorization_locator", require_signed=self._require_signed)
        if (auth.action, auth.dag_slot, type(auth.subject)) != (expected_action, expected_slot, expected_subject_cls) or not (_utc_micros(auth.issued_at_utc) <= r_us < _utc_micros(auth.valid_until_utc)):
            raise ClosedValidationError("retention_root_set_service: authorization action, slot, subject, or validity window mismatch")
        auth_key = canonicalize_jcs(auth_loc.to_dict())
        if auth_key in self._auth_states or auth.single_use_nonce in self._nonce_states:
            raise ClosedValidationError(f"retention_root_set_service: nonce {auth.single_use_nonce!r} already reserved/terminal")
        if "in_doubt_reservation" in checked_ints:
            _reparse_exact(AuthorizationReservationRecord(reservation_id, auth.migration_run_context_locator, auth_loc, auth_loc.content_digest, auth.single_use_nonce, auth.action, auth.dag_slot, auth.subject, "in_doubt", "pre_mutation_conflict_or_drift", reserved_at_utc, checked_ints["in_doubt_reservation"]), AuthorizationReservationRecord, label="in_doubt_reservation", require_signed=self._require_signed)
        resv = _reparse_exact(AuthorizationReservationRecord(reservation_id, auth.migration_run_context_locator, auth_loc, auth_loc.content_digest, auth.single_use_nonce, auth.action, auth.dag_slot, auth.subject, "reserved", None, reserved_at_utc, checked_ints.get("reservation")), AuthorizationReservationRecord, label="reservation", require_signed=self._require_signed)
        resv_loc = self._store.put_json_artifact(AuthorizationReservationRecord.SCHEMA, resv.to_dict())
        self._used_ids.add(resv_tag)
        self._nonce_states[auth.single_use_nonce] = "reserved"
        self._auth_states[auth_key] = "reserved"
        return auth_loc, auth_key, auth, resv, resv_loc, checked_ints, post_ids

    def _quarantine_in_doubt(self, auth_key: bytes, auth: AuthorizationReceipt, auth_loc: ArtifactLocator, resv: AuthorizationReservationRecord, ints: Mapping[str, P1Integrity]) -> None:
        self._nonce_states[auth.single_use_nonce] = "in_doubt"
        self._auth_states[auth_key] = "in_doubt"
        fallback_int = None if auth.integrity is None else P1Integrity(auth.integrity.key_id, auth.integrity.key_registry_snapshot_locator)
        in_doubt_rec = AuthorizationReservationRecord(resv.reservation_id, auth.migration_run_context_locator, auth_loc, auth_loc.content_digest, auth.single_use_nonce, auth.action, auth.dag_slot, auth.subject, "in_doubt", "pre_mutation_conflict_or_drift", resv.reserved_at_utc, ints.get("in_doubt_reservation", fallback_int))
        self._store.put_json_artifact(AuthorizationReservationRecord.SCHEMA, in_doubt_rec.to_dict())

    def _build_cas_and_effect_envelopes(
        self, *, op: str, req_roots: tuple[ArtifactLocator, ...], next_roots: tuple[ArtifactLocator, ...], prop_dig: str,
        new_head_id: str, cas_receipt_id: str, cas_linearization_id: str, committed_at_utc: str, verified_at_utc: str,
        action_result_fn: Callable[[RetentionRootSetHead, RetentionRootSetCasReceipt], Any], auth: AuthorizationReceipt,
        auth_loc: ArtifactLocator, resv: AuthorizationReservationRecord, resv_loc: ArtifactLocator,
        execution_id: str, consumption_id: str, effect_proof_id: str, ints: Mapping[str, P1Integrity],
    ) -> tuple[RetentionRootSetHead, RetentionRootSetCasReceipt, Any, ExecutionReceipt, AuthorizationConsumptionRecord, EffectProof]:
        new_head = _reparse_exact(RetentionRootSetHead(new_head_id, self._head.cell_ref, self._head.head_epoch + 1, next_roots, self._head_locator, committed_at_utc, prop_dig, ints.get("new_head")), RetentionRootSetHead, label="new_head", require_signed=self._require_signed)
        proj = RetentionRootSetCasRequestProjection(op, self._head.head_epoch, self._head_locator.content_digest, req_roots, prop_dig)  # type: ignore[arg-type]
        cas_rec = _reparse_exact(RetentionRootSetCasReceipt(cas_receipt_id, self._head.cell_ref, op, proj, self._head_locator, self._head_locator.content_digest, self._head.head_epoch, new_head.locator(), new_head.locator().content_digest, new_head.head_epoch, "committed", cas_linearization_id, committed_at_utc, ints.get("cas_receipt")), RetentionRootSetCasReceipt, label="cas_receipt", require_signed=self._require_signed)  # type: ignore[arg-type]
        act_res = action_result_fn(new_head, cas_rec)
        act_loc = act_res.locator()
        ex = _reparse_exact(ExecutionReceipt(execution_id, auth.migration_run_context_locator, auth_loc, resv_loc, auth.single_use_nonce, auth.action, auth.dag_slot, auth.subject, "succeeded", act_loc, committed_at_utc, ints.get("execution")), ExecutionReceipt, label="execution", require_signed=self._require_signed)
        cn = _reparse_exact(AuthorizationConsumptionRecord(consumption_id, auth.migration_run_context_locator, auth_loc, auth_loc.content_digest, resv_loc, ex.locator(), auth.single_use_nonce, auth.action, auth.dag_slot, "consumed", committed_at_utc, ints.get("consumption")), AuthorizationConsumptionRecord, label="consumption", require_signed=self._require_signed)
        ef = _reparse_exact(EffectProof(effect_proof_id, auth.migration_run_context_locator, auth.action, auth.dag_slot, auth_loc, resv_loc, ex.locator(), cn.locator(), act_loc, verified_at_utc, ints.get("effect_proof")), EffectProof, label="effect_proof", require_signed=self._require_signed)
        verify_four_record_effect_proof(effect_proof=ef, authorization=auth, reservation=resv, execution=ex, consumption=cn, expected_action=auth.action, expected_dag_slot=auth.dag_slot, expected_result_type=act_loc.artifact_type, require_signed=self._require_signed)
        return new_head, cas_rec, act_res, ex, cn, ef

    def _commit_envelopes(
        self, *, new_head: RetentionRootSetHead, prior_envs: Sequence[Any], proof: _T,
        verifier_fn: Callable[..., _T], nonce: str, auth_key: bytes, post_ids: set[str],
    ) -> tuple[_T, ArtifactLocator]:
        for env in (new_head, *prior_envs):
            self._store.put_json_artifact(env.SCHEMA, env.to_dict())
        proof_loc = self._store.put_json_artifact(proof.SCHEMA, proof.to_dict())  # type: ignore[attr-defined]
        verified = verifier_fn(proof, store=self._store, parquet_codec=self._parquet_codec, require_signed=self._require_signed)
        self._head_locator, self._head = new_head.locator(), new_head
        self._nonce_states[nonce] = "consumed"
        self._auth_states[auth_key] = "consumed"
        self._used_ids.update(post_ids)
        return verified, proof_loc

    def _check_expected_head_and_expiry(self, auth: AuthorizationReceipt, target: Any, committed_at_utc: str) -> None:
        if _utc_micros(committed_at_utc) >= _utc_micros(auth.valid_until_utc) or (target.cell_ref, target.expected_root_set_head_locator, target.expected_root_set_head_epoch, target.expected_root_set_head_digest) != (self._head.cell_ref, self._head_locator, self._head.head_epoch, self._head_locator.content_digest):
            raise ClosedValidationError(f"{auth.action}: expired authorization or stale expected_root_set_head")

    def admit_roots(
        self, *, authorization_locator: ArtifactLocator, reservation_id: str, reserved_at_utc: str, cas_receipt_id: str,
        cas_linearization_id: str, committed_at_utc: str, new_head_id: str, execution_id: str, consumption_id: str,
        effect_proof_id: str, verified_at_utc: str, integrities: Mapping[str, P1Integrity] | None = None,
    ) -> tuple[RetentionRootAdmissionProof, ArtifactLocator]:
        """Atomically verify reachability closure, commit live-root admission CAS, and emit proof."""
        auth_loc, auth_key, auth, resv, resv_loc, ints, post_ids = self._prepare_and_reserve(
            authorization_locator=authorization_locator, expected_action="retention_root_admission", expected_slot="retention_root_admission_effect_proof",
            expected_subject_cls=RetentionRootAdmissionTarget, result_key="admission_result", proof_key="admission_proof",
            reservation_id=reservation_id, reserved_at_utc=reserved_at_utc, cas_receipt_id=cas_receipt_id, cas_linearization_id=cas_linearization_id,
            committed_at_utc=committed_at_utc, new_head_id=new_head_id, execution_id=execution_id, consumption_id=consumption_id,
            effect_proof_id=effect_proof_id, verified_at_utc=verified_at_utc, integrities=integrities,
        )
        try:
            target: RetentionRootAdmissionTarget = auth.subject  # type: ignore[assignment]
            self._check_expected_head_and_expiry(auth, target, committed_at_utc)
            proposed, prop_dig, _, b_dig, adm_cl, after_cl = _verify_admission_roots_and_closures(b_head=self._head, admitted_locs=target.admitted_root_locators, run_loc=auth.migration_run_context_locator, store=self._store, parquet_codec=self._parquet_codec, require_signed=self._require_signed)
            if (target.admitted_object_refs, target.before_reachability_graph_digest, target.after_reachability_graph_digest, target.proposed_root_set_digest) != (adm_cl.reachable_object_refs, b_dig, after_cl.reachability_graph_digest, prop_dig):
                raise ClosedValidationError("retention_root_admission: target object set or reachability digest mismatch")
            mk_res = lambda nh, cr: _reparse_exact(RetentionRootAdmissionResult(auth.migration_run_context_locator, self._head.cell_ref, cr.locator(), cr.locator().content_digest, cas_linearization_id, self._head_locator, self._head_locator.content_digest, nh.locator(), nh.locator().content_digest, target.admitted_root_locators, target.admitted_object_refs, "admitted", committed_at_utc, ints.get("admission_result")), RetentionRootAdmissionResult, label="admission_result", require_signed=self._require_signed)  # noqa: E731
            nh, cas_rec, adm_res, ex, cn, ef = self._build_cas_and_effect_envelopes(op="admit_roots", req_roots=target.admitted_root_locators, next_roots=proposed, prop_dig=prop_dig, new_head_id=new_head_id, cas_receipt_id=cas_receipt_id, cas_linearization_id=cas_linearization_id, committed_at_utc=committed_at_utc, verified_at_utc=verified_at_utc, action_result_fn=mk_res, auth=auth, auth_loc=auth_loc, resv=resv, resv_loc=resv_loc, execution_id=execution_id, consumption_id=consumption_id, effect_proof_id=effect_proof_id, ints=ints)
            proof = _reparse_exact(RetentionRootAdmissionProof(auth.migration_run_context_locator, self._head.cell_ref, ef.locator(), adm_res.locator(), cas_rec.locator(), self._head_locator, nh.locator(), target.admitted_root_locators, target.admitted_object_refs, b_dig, after_cl.reachability_graph_digest, verified_at_utc, ints.get("admission_proof")), RetentionRootAdmissionProof, label="admission_proof", require_signed=self._require_signed)
            _check_key_registry_consistency(auth, resv, self._head, nh, cas_rec, adm_res, ex, cn, ef, proof)
        except ClosedValidationError:
            self._quarantine_in_doubt(auth_key, auth, auth_loc, resv, ints)
            raise
        return self._commit_envelopes(new_head=nh, prior_envs=(cas_rec, adm_res, ex, cn, ef), proof=proof, verifier_fn=verify_retention_root_admission_proof, nonce=auth.single_use_nonce, auth_key=auth_key, post_ids=post_ids)

    def release_roots(
        self, *, authorization_locator: ArtifactLocator, reservation_id: str, reserved_at_utc: str, cas_receipt_id: str,
        cas_linearization_id: str, committed_at_utc: str, new_head_id: str, execution_id: str, consumption_id: str,
        effect_proof_id: str, verified_at_utc: str, integrities: Mapping[str, P1Integrity] | None = None,
    ) -> tuple[RetentionReleaseProof, ArtifactLocator]:
        """Atomically verify retained non-reachability, commit logical unpin CAS, and emit proof."""
        auth_loc, auth_key, auth, resv, resv_loc, ints, post_ids = self._prepare_and_reserve(
            authorization_locator=authorization_locator, expected_action="retention_release", expected_slot="retention_release_effect_proof",
            expected_subject_cls=RetentionReleaseTarget, result_key="release_result", proof_key="release_proof",
            reservation_id=reservation_id, reserved_at_utc=reserved_at_utc, cas_receipt_id=cas_receipt_id, cas_linearization_id=cas_linearization_id,
            committed_at_utc=committed_at_utc, new_head_id=new_head_id, execution_id=execution_id, consumption_id=consumption_id,
            effect_proof_id=effect_proof_id, verified_at_utc=verified_at_utc, integrities=integrities,
        )
        try:
            target: RetentionReleaseTarget = auth.subject  # type: ignore[assignment]
            self._check_expected_head_and_expiry(auth, target, committed_at_utc)
            retained_roots, prop_dig, _, b_dig, after_cl = _verify_release_roots_and_closures(b_head=self._head, released_locs=target.released_root_locators, claimed_rel_refs=target.released_object_refs, store=self._store, parquet_codec=self._parquet_codec, require_signed=self._require_signed)
            if (target.retained_root_locators, target.before_reachability_graph_digest, target.after_reachability_graph_digest, target.proposed_root_set_digest) != (retained_roots, b_dig, after_cl.reachability_graph_digest, prop_dig):
                raise ClosedValidationError("retention_release: retained roots or reachability digest mismatch")
            mk_res = lambda nh, cr: _reparse_exact(RetentionReleaseResult(auth.migration_run_context_locator, self._head.cell_ref, cr.locator(), cr.locator().content_digest, cas_linearization_id, self._head_locator, self._head_locator.content_digest, nh.locator(), nh.locator().content_digest, target.released_root_locators, target.released_object_refs, "logically_unpinned", committed_at_utc, ints.get("release_result")), RetentionReleaseResult, label="release_result", require_signed=self._require_signed)  # noqa: E731
            nh, cas_rec, rel_res, ex, cn, ef = self._build_cas_and_effect_envelopes(op="release_roots", req_roots=target.released_root_locators, next_roots=retained_roots, prop_dig=prop_dig, new_head_id=new_head_id, cas_receipt_id=cas_receipt_id, cas_linearization_id=cas_linearization_id, committed_at_utc=committed_at_utc, verified_at_utc=verified_at_utc, action_result_fn=mk_res, auth=auth, auth_loc=auth_loc, resv=resv, resv_loc=resv_loc, execution_id=execution_id, consumption_id=consumption_id, effect_proof_id=effect_proof_id, ints=ints)
            proof = _reparse_exact(RetentionReleaseProof(auth.migration_run_context_locator, self._head.cell_ref, ef.locator(), rel_res.locator(), cas_rec.locator(), self._head_locator, nh.locator(), target.released_root_locators, retained_roots, target.released_object_refs, after_cl.reachable_object_refs, b_dig, after_cl.reachability_graph_digest, True, verified_at_utc, ints.get("release_proof")), RetentionReleaseProof, label="release_proof", require_signed=self._require_signed)
            _check_key_registry_consistency(auth, resv, self._head, nh, cas_rec, rel_res, ex, cn, ef, proof)
        except ClosedValidationError:
            self._quarantine_in_doubt(auth_key, auth, auth_loc, resv, ints)
            raise
        return self._commit_envelopes(new_head=nh, prior_envs=(cas_rec, rel_res, ex, cn, ef), proof=proof, verifier_fn=verify_retention_release_proof, nonce=auth.single_use_nonce, auth_key=auth_key, post_ids=post_ids)


def _load_and_verify_proof_backbone(
    proof: Any, *, result_loc: ArtifactLocator, result_cls: type[_T], expected_action: str,
    expected_slot: str, expected_cas_op: str, store: CellObjectStorePort, require_signed: bool,
) -> tuple[AuthorizationReceipt, _T, RetentionRootSetCasReceipt, RetentionRootSetHead, RetentionRootSetHead]:
    ef = _load_p1(store, proof.effect_proof_locator, EffectProof, field_name="proof.effect_proof_locator", require_signed=require_signed)
    auth = _load_p1(store, ef.authorization_locator, AuthorizationReceipt, field_name="ef.authorization_locator", require_signed=require_signed)
    resv = _load_p1(store, ef.reservation_locator, AuthorizationReservationRecord, field_name="ef.reservation_locator", require_signed=require_signed)
    ex = _load_p1(store, ef.execution_locator, ExecutionReceipt, field_name="ef.execution_locator", require_signed=require_signed)
    cn = _load_p1(store, ef.consumption_locator, AuthorizationConsumptionRecord, field_name="ef.consumption_locator", require_signed=require_signed)
    verify_four_record_effect_proof(effect_proof=ef, authorization=auth, reservation=resv, execution=ex, consumption=cn, expected_action=expected_action, expected_dag_slot=expected_slot, expected_result_type=result_cls.SCHEMA, require_signed=require_signed)  # type: ignore[attr-defined]
    res = _load_p1(store, result_loc, result_cls, field_name="proof.action_result_locator", require_signed=require_signed)
    cas = _load_p1(store, proof.cas_receipt_locator, RetentionRootSetCasReceipt, field_name="proof.cas_receipt_locator", require_signed=require_signed)
    b_head = _load_p1(store, proof.before_head_locator, RetentionRootSetHead, field_name="proof.before_head_locator", require_signed=require_signed)
    a_head = _load_p1(store, proof.after_head_locator, RetentionRootSetHead, field_name="proof.after_head_locator", require_signed=require_signed)
    _check_key_registry_consistency(auth, resv, ex, cn, ef, res, cas, b_head, a_head, proof)
    times = (_utc_micros(auth.issued_at_utc), _utc_micros(resv.reserved_at_utc), _utc_micros(cas.committed_at_utc), _utc_micros(ex.executed_at_utc), _utc_micros(cn.consumed_at_utc), _utc_micros(ef.verified_at_utc), _utc_micros(proof.verified_at_utc))
    chronology_ok = all(times[i] <= times[i + 1] for i in range(len(times) - 1)) and times[3] < _utc_micros(auth.valid_until_utc)
    if (
        not chronology_ok or ef.action_result_locator != result_loc or auth.migration_run_context_locator != proof.migration_run_context_locator
        or (b_head.cell_ref, a_head.cell_ref, cas.cell_ref, res.cell_ref) != (proof.cell_ref,) * 4  # type: ignore[attr-defined]
        or (a_head.head_epoch, a_head.predecessor_head_locator) != (b_head.head_epoch + 1, proof.before_head_locator)
        or (cas.operation, cas.expected_old_head_locator, cas.expected_old_epoch, cas.committed_new_head_locator, cas.committed_new_epoch) != (expected_cas_op, proof.before_head_locator, b_head.head_epoch, proof.after_head_locator, a_head.head_epoch)
        or (res.migration_run_context_locator, res.cas_receipt_locator, res.cas_linearization_id, res.before_head_locator, res.after_head_locator) != (proof.migration_run_context_locator, proof.cas_receipt_locator, cas.cas_linearization_id, proof.before_head_locator, proof.after_head_locator)  # type: ignore[attr-defined]
    ):
        raise ClosedValidationError("retention_proof: chronology, effect chain, head lineage, or CAS receipt mismatch")
    return auth, res, cas, b_head, a_head


def verify_retention_root_admission_proof(
    proof: RetentionRootAdmissionProof, *, store: CellObjectStorePort, parquet_codec: ParquetLandingCodecPort | None = None, require_signed: bool = False,
) -> RetentionRootAdmissionProof:
    """Independently verify `RetentionRootAdmissionProof`, effect chain, CAS, and full reachability."""
    checked_store = _check_store_and_codec(store, parquet_codec, require_signed)
    fresh = _reparse_exact(proof, RetentionRootAdmissionProof, label="proof", require_signed=require_signed)
    auth, res, cas, b_head, a_head = _load_and_verify_proof_backbone(fresh, result_loc=fresh.admission_result_locator, result_cls=RetentionRootAdmissionResult, expected_action="retention_root_admission", expected_slot="retention_root_admission_effect_proof", expected_cas_op="admit_roots", store=checked_store, require_signed=require_signed)
    proposed, prop_dig, b_objs, b_dig, adm_cl, _ = _verify_admission_roots_and_closures(b_head=b_head, admitted_locs=fresh.admitted_root_locators, run_loc=fresh.migration_run_context_locator, store=checked_store, parquet_codec=parquet_codec, require_signed=require_signed)
    a_objs, a_dig = _head_pinned_object_refs(a_head, store=checked_store, parquet_codec=parquet_codec, require_signed=require_signed)
    exp_target = RetentionRootAdmissionTarget(fresh.migration_run_context_locator, fresh.cell_ref, fresh.before_head_locator, b_head.head_epoch, fresh.before_head_locator.content_digest, fresh.admitted_root_locators, adm_cl.reachable_object_refs, b_dig, a_dig, prop_dig)
    exp_proj = RetentionRootSetCasRequestProjection("admit_roots", b_head.head_epoch, fresh.before_head_locator.content_digest, fresh.admitted_root_locators, prop_dig)
    if (a_head.live_root_locators, a_head.root_set_digest, cas.cas_request_projection, auth.subject) != (proposed, prop_dig, exp_proj, exp_target) or (res.admitted_root_locators, res.admitted_object_refs, fresh.admitted_object_refs) != (fresh.admitted_root_locators, adm_cl.reachable_object_refs, adm_cl.reachable_object_refs) or a_objs != (b_objs | set(adm_cl.reachable_object_refs)) or (fresh.before_reachability_graph_digest, fresh.after_reachability_graph_digest) != (b_dig, a_dig):
        raise ClosedValidationError("retention_root_admission_proof: reachability closure or subject mismatch")
    return fresh


def verify_retention_release_proof(
    proof: RetentionReleaseProof, *, store: CellObjectStorePort, parquet_codec: ParquetLandingCodecPort | None = None, require_signed: bool = False,
) -> RetentionReleaseProof:
    """Independently verify `RetentionReleaseProof`, non-vacuous retained non-reachability, and zero deletion."""
    checked_store = _check_store_and_codec(store, parquet_codec, require_signed)
    fresh = _reparse_exact(proof, RetentionReleaseProof, label="proof", require_signed=require_signed)
    auth, res, cas, b_head, a_head = _load_and_verify_proof_backbone(fresh, result_loc=fresh.release_result_locator, result_cls=RetentionReleaseResult, expected_action="retention_release", expected_slot="retention_release_effect_proof", expected_cas_op="release_roots", store=checked_store, require_signed=require_signed)
    exp_retained, prop_dig, b_objs, b_dig, _ = _verify_release_roots_and_closures(b_head=b_head, released_locs=fresh.released_root_locators, claimed_rel_refs=fresh.released_object_refs, store=checked_store, parquet_codec=parquet_codec, require_signed=require_signed)
    ret_objs, a_dig = _head_pinned_object_refs(a_head, store=checked_store, parquet_codec=parquet_codec, require_signed=require_signed)
    exp_rel_refs = sort_cell_object_refs(b_objs - ret_objs, allow_empty=True)
    exp_ret_refs = sort_cell_object_refs(ret_objs, allow_empty=True)
    exp_target = RetentionReleaseTarget(fresh.migration_run_context_locator, fresh.cell_ref, fresh.before_head_locator, b_head.head_epoch, fresh.before_head_locator.content_digest, fresh.released_root_locators, exp_retained, exp_rel_refs, b_dig, a_dig, prop_dig)
    exp_proj = RetentionRootSetCasRequestProjection("release_roots", b_head.head_epoch, fresh.before_head_locator.content_digest, fresh.released_root_locators, prop_dig)
    if (fresh.retained_root_locators, a_head.live_root_locators, a_head.root_set_digest, cas.cas_request_projection, auth.subject) != (exp_retained, exp_retained, prop_dig, exp_proj, exp_target) or (res.released_root_locators, res.released_object_refs, fresh.released_object_refs, fresh.retained_object_refs) != (fresh.released_root_locators, exp_rel_refs, exp_rel_refs, exp_ret_refs) or (fresh.before_reachability_graph_digest, fresh.after_reachability_graph_digest) != (b_dig, a_dig) or any(not checked_store.has_object(ref) for ref in b_objs):
        raise ClosedValidationError("retention_release_proof: non-vacuous release delta, subject, or store integrity mismatch")
    return fresh


__all__ = [
    "ReachabilityClosure", "RetentionRootSetService", "WheelObjectLocator", "build_retention_root",
    "compute_retention_reachability_graph", "head_pinned_object_refs",
    "verify_retention_release_proof", "verify_retention_root", "verify_retention_root_admission_proof",
]
