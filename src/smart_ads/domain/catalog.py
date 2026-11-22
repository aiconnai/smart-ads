"""Parquet object locators, generation manifests, global catalog CAS, and dataset snapshots (ADR-0001 §6.3)."""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
import hashlib
from itertools import pairwise
from typing import Any, ClassVar, Final, Literal

from smart_ads.contracts.effects import (
    _P1EnvelopeBase, _require_json_list, _require_locator_digest_pair, _safe_int,
    _sorted_locator_tuple, _split_p1_envelope, _strict_id, _strict_str, _typed_locator,
    _validate_colon_ref, _verify_p1_integrity, validate_cell_object_ref,
)
from smart_ads.contracts.jcs import (
    ADR_DATA_DOMAIN_PREFIXES, ADR_P1_DOMAIN_PREFIXES, ArtifactLocator, P1Integrity,
    canonicalize_jcs, domain_jcs_sha256, self_digest_jcs_sha256,
)
from smart_ads.contracts.operational_evidence import OperationalReadEvidence
from smart_ads.contracts.scalars import (
    ClosedValidationError, require_exact_keys, require_mapping,
    validate_envelope_timestamp_utc, validate_opaque_ref, validate_sha256_prefixed,
)
from smart_ads.contracts.schemas import AnalyticsLandingRow
from smart_ads.domain.curation import CurationExecution, validate_partition_key

CatalogCasOperation = Literal["add_partition", "replace_partition"]

_RUN_CONTEXT_SCHEMA: Final[str] = "smart_ads/migration_run_context/v1"
_REGISTRY_SNAPSHOT_SCHEMA: Final[str] = "smart_ads/private_registry_snapshot/v1"
_LANDING_ROW_SCHEMA: Final[str] = "smart_ads/analytics_landing_row/v1"
_PARQUET_MEDIA_TYPE: Final[str] = "application/vnd.apache.parquet"
_CATALOG_CAS_OPERATIONS: Final[frozenset[str]] = frozenset({"add_partition", "replace_partition"})


@dataclass(frozen=True, slots=True)
class ParquetObjectLocator:
    """Closed 7-member `smart_ads/parquet_object_locator/v1` embedded locator (ADR-0001 §6.3)."""

    SCHEMA: ClassVar[str] = "smart_ads/parquet_object_locator/v1"
    KEYS: ClassVar[frozenset[str]] = frozenset(
        "$schema partition_key store_kind object_ref media_type physical_parquet_digest size_bytes".split()
    )

    partition_key: str
    physical_parquet_digest: str
    size_bytes: int
    store_kind: str = "cell_immutable_object"
    media_type: str = _PARQUET_MEDIA_TYPE
    object_ref: str = ""

    def __post_init__(self) -> None:
        label = "parquet_object_locator"
        validate_partition_key(self.partition_key, field_name=f"{label}.partition_key")
        validate_sha256_prefixed(_strict_str(self.physical_parquet_digest, field_name=f"{label}.physical_parquet_digest"), field_name=f"{label}.physical_parquet_digest")
        _safe_int(self.size_bytes, field_name=f"{label}.size_bytes", minimum=8)
        if _strict_str(self.store_kind, field_name=f"{label}.store_kind") != "cell_immutable_object":
            raise ClosedValidationError(f"{label}.store_kind: must equal 'cell_immutable_object'")
        if _strict_str(self.media_type, field_name=f"{label}.media_type") != _PARQUET_MEDIA_TYPE:
            raise ClosedValidationError(f"{label}.media_type: must equal {_PARQUET_MEDIA_TYPE!r}")
        expected_ref = f"cell-object:{self.physical_parquet_digest}"
        raw_ref = _strict_str(self.object_ref, field_name=f"{label}.object_ref")
        if raw_ref == "":
            object.__setattr__(self, "object_ref", expected_ref)
        elif raw_ref != expected_ref:
            raise ClosedValidationError(f"{label}.object_ref: expected {expected_ref!r}, got {raw_ref!r}")

    @classmethod
    def for_parquet_bytes(cls, partition_key: str, raw_bytes: bytes) -> ParquetObjectLocator:
        """Build a `ParquetObjectLocator` over raw immutable Parquet bytes."""
        if type(raw_bytes) is not bytes:
            raise ClosedValidationError("raw_bytes: expected bytes")
        digest = "sha256:" + hashlib.sha256(raw_bytes).hexdigest()
        return cls(partition_key=partition_key, physical_parquet_digest=digest, size_bytes=len(raw_bytes), object_ref=f"cell-object:{digest}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "$schema": self.SCHEMA, "partition_key": self.partition_key,
            "store_kind": self.store_kind, "object_ref": self.object_ref,
            "media_type": self.media_type, "physical_parquet_digest": self.physical_parquet_digest,
            "size_bytes": self.size_bytes,
        }

    @classmethod
    def from_dict(cls, data: object) -> ParquetObjectLocator:
        m = require_exact_keys(data, cls.KEYS, label="parquet_object_locator")
        if type(m["$schema"]) is not str or m["$schema"] != cls.SCHEMA:
            raise ClosedValidationError(f"parquet_object_locator.$schema: expected {cls.SCHEMA!r}, got {m['$schema']!r}")
        obj_ref = validate_cell_object_ref(m["object_ref"], field_name="parquet_object_locator.object_ref")
        return cls(
            partition_key=m["partition_key"], store_kind=m["store_kind"], object_ref=obj_ref,
            media_type=m["media_type"], physical_parquet_digest=m["physical_parquet_digest"], size_bytes=m["size_bytes"],
        )


def compute_physical_parquet_set_digest(
    locators: Sequence[ParquetObjectLocator],
) -> tuple[tuple[ParquetObjectLocator, ...], str]:
    """Sort unique `ParquetObjectLocator`s by `RFC8785(locator)` and compute set digest."""
    if isinstance(locators, (str, bytes)) or not isinstance(locators, Sequence) or not locators:
        raise ClosedValidationError("parquet_object_locators: expected non-empty Sequence of ParquetObjectLocator")
    keyed: list[tuple[bytes, ParquetObjectLocator]] = []
    seen: set[bytes] = set()
    for idx, item in enumerate(locators):
        if type(item) is not ParquetObjectLocator:
            raise ClosedValidationError(f"parquet_object_locators[{idx}]: expected ParquetObjectLocator")
        fresh = ParquetObjectLocator.from_dict(item.to_dict())
        key = canonicalize_jcs(fresh.to_dict())
        if key in seen:
            raise ClosedValidationError(f"parquet_object_locators[{idx}]: duplicate ParquetObjectLocator")
        seen.add(key)
        keyed.append((key, fresh))
    keyed.sort(key=lambda pair: pair[0])
    ordered = tuple(loc for _, loc in keyed)
    return ordered, domain_jcs_sha256(ADR_DATA_DOMAIN_PREFIXES["parquet_object_set"], [loc.to_dict() for loc in ordered])


def compute_logical_rows_digest(
    rows: Sequence[AnalyticsLandingRow],
) -> tuple[tuple[AnalyticsLandingRow, ...], str]:
    """Reject duplicate `fact_key`s, sort by `RFC8785(row.fact_key)`, and compute `logical_rows_digest`."""
    if isinstance(rows, (str, bytes)) or not isinstance(rows, Sequence):
        raise ClosedValidationError("rows: expected Sequence of AnalyticsLandingRow")
    keyed: list[tuple[bytes, AnalyticsLandingRow]] = []
    seen_fk: set[bytes] = set()
    for idx, item in enumerate(rows):
        if type(item) is not AnalyticsLandingRow:
            raise ClosedValidationError(f"rows[{idx}]: expected AnalyticsLandingRow")
        fresh = AnalyticsLandingRow.from_dict(item.to_dict())
        fk_bytes = canonicalize_jcs(fresh.fact_key.to_dict())
        if fk_bytes in seen_fk:
            raise ClosedValidationError(f"rows[{idx}]: duplicate fact_key in generation")
        seen_fk.add(fk_bytes)
        keyed.append((fk_bytes, fresh))
    keyed.sort(key=lambda pair: pair[0])
    ordered = tuple(row for _, row in keyed)
    return ordered, domain_jcs_sha256(ADR_DATA_DOMAIN_PREFIXES["logical_rows"], [row.to_dict() for row in ordered])


def _validate_sorted_parquet_locators(
    values: object, *, expected_partition_key: str, field_name: str
) -> tuple[tuple[ParquetObjectLocator, ...], str]:
    if not isinstance(values, (list, tuple)) or not values:
        raise ClosedValidationError(f"{field_name}: expected non-empty list or tuple")
    raw_tuple = tuple(values)
    ordered, set_digest = compute_physical_parquet_set_digest(raw_tuple)
    if raw_tuple != ordered:
        raise ClosedValidationError(f"{field_name}: must already be sorted by RFC 8785 bytes")
    for loc in ordered:
        if loc.partition_key != expected_partition_key:
            raise ClosedValidationError(f"{field_name}: locator partition_key {loc.partition_key!r} != {expected_partition_key!r}")
    return ordered, set_digest


@dataclass(frozen=True, slots=True)
class GenerationManifest(_P1EnvelopeBase):
    """Closed P1 `smart_ads/generation_manifest/v1` envelope (15 core + `integrity` = 16 keys)."""

    SCHEMA: ClassVar[str] = "smart_ads/generation_manifest/v1"
    P1_DOMAIN_PREFIX: ClassVar[str] = ADR_P1_DOMAIN_PREFIXES[SCHEMA]
    CORE_KEYS: ClassVar[frozenset[str]] = frozenset(
        "$schema migration_run_context_locator generation_id partition_key parent_generation_manifest_locator "
        "created_at_utc row_schema row_count logical_rows_digest registry_snapshot_locator "
        "curation_execution_locator base_dataset_catalog_locator operational_read_evidence_locators "
        "parquet_object_locators physical_parquet_set_digest".split()
    )
    KEYS: ClassVar[frozenset[str]] = CORE_KEYS | {"integrity"}

    migration_run_context_locator: ArtifactLocator
    generation_id: str
    partition_key: str
    parent_generation_manifest_locator: ArtifactLocator | None
    created_at_utc: str
    row_count: int
    logical_rows_digest: str
    registry_snapshot_locator: ArtifactLocator
    curation_execution_locator: ArtifactLocator
    base_dataset_catalog_locator: ArtifactLocator
    operational_read_evidence_locators: tuple[ArtifactLocator, ...]
    parquet_object_locators: tuple[ParquetObjectLocator, ...]
    row_schema: str = _LANDING_ROW_SCHEMA
    physical_parquet_set_digest: str = ""
    integrity: P1Integrity | None = None

    def __post_init__(self) -> None:
        label = "generation_manifest"
        _typed_locator(self.migration_run_context_locator, field_name=f"{label}.migration_run_context_locator", expected_type=_RUN_CONTEXT_SCHEMA)
        _strict_id(self.generation_id, field_name=f"{label}.generation_id")
        pk = validate_partition_key(self.partition_key, field_name=f"{label}.partition_key")
        if self.parent_generation_manifest_locator is not None:
            _typed_locator(self.parent_generation_manifest_locator, field_name=f"{label}.parent_generation_manifest_locator", expected_type=self.SCHEMA)
        validate_envelope_timestamp_utc(self.created_at_utc, field_name=f"{label}.created_at_utc")
        if _strict_str(self.row_schema, field_name=f"{label}.row_schema") != _LANDING_ROW_SCHEMA:
            raise ClosedValidationError(f"{label}.row_schema: must equal {_LANDING_ROW_SCHEMA!r}")
        _safe_int(self.row_count, field_name=f"{label}.row_count", minimum=0)
        validate_sha256_prefixed(_strict_str(self.logical_rows_digest, field_name=f"{label}.logical_rows_digest"), field_name=f"{label}.logical_rows_digest")
        _typed_locator(self.registry_snapshot_locator, field_name=f"{label}.registry_snapshot_locator", expected_type=_REGISTRY_SNAPSHOT_SCHEMA)
        _typed_locator(self.curation_execution_locator, field_name=f"{label}.curation_execution_locator", expected_type=CurationExecution.SCHEMA)
        _typed_locator(self.base_dataset_catalog_locator, field_name=f"{label}.base_dataset_catalog_locator", expected_type=DatasetCatalog.SCHEMA)
        object.__setattr__(self, "operational_read_evidence_locators", _sorted_locator_tuple(self.operational_read_evidence_locators, field_name=f"{label}.operational_read_evidence_locators", expected_type=OperationalReadEvidence.SCHEMA, allow_empty=False))
        pq_locs, expected_pq_digest = _validate_sorted_parquet_locators(self.parquet_object_locators, expected_partition_key=pk, field_name=f"{label}.parquet_object_locators")
        object.__setattr__(self, "parquet_object_locators", pq_locs)
        raw_pq_d = _strict_str(self.physical_parquet_set_digest, field_name=f"{label}.physical_parquet_set_digest")
        if raw_pq_d == "":
            object.__setattr__(self, "physical_parquet_set_digest", expected_pq_digest)
        elif validate_sha256_prefixed(raw_pq_d, field_name=f"{label}.physical_parquet_set_digest") != expected_pq_digest:
            raise ClosedValidationError(f"{label}.physical_parquet_set_digest: recomputed {expected_pq_digest!r} != {raw_pq_d!r}")
        _verify_p1_integrity(self.integrity, self.to_dict, label=label)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "$schema": self.SCHEMA, "generation_id": self.generation_id, "partition_key": self.partition_key,
            "migration_run_context_locator": self.migration_run_context_locator.to_dict(),
            "parent_generation_manifest_locator": None if self.parent_generation_manifest_locator is None else self.parent_generation_manifest_locator.to_dict(),
            "created_at_utc": self.created_at_utc, "row_schema": self.row_schema, "row_count": self.row_count,
            "logical_rows_digest": self.logical_rows_digest,
            "registry_snapshot_locator": self.registry_snapshot_locator.to_dict(),
            "curation_execution_locator": self.curation_execution_locator.to_dict(),
            "base_dataset_catalog_locator": self.base_dataset_catalog_locator.to_dict(),
            "operational_read_evidence_locators": [loc.to_dict() for loc in self.operational_read_evidence_locators],
            "parquet_object_locators": [loc.to_dict() for loc in self.parquet_object_locators],
            "physical_parquet_set_digest": self.physical_parquet_set_digest,
        }
        return out if self.integrity is None else {**out, "integrity": self.integrity.to_dict()}

    @classmethod
    def from_dict(cls, data: object, *, require_signed: bool = False) -> GenerationManifest:
        m, integrity = _split_p1_envelope(data, core_keys=cls.CORE_KEYS, schema=cls.SCHEMA, label="generation_manifest", require_signed=require_signed)
        raw_ev = _require_json_list(m, "operational_read_evidence_locators", label="generation_manifest")
        raw_pq = _require_json_list(m, "parquet_object_locators", label="generation_manifest")
        pq_digest = validate_sha256_prefixed(_strict_str(m["physical_parquet_set_digest"], field_name="generation_manifest.physical_parquet_set_digest"), field_name="generation_manifest.physical_parquet_set_digest")
        raw_parent = m["parent_generation_manifest_locator"]
        return cls(
            migration_run_context_locator=ArtifactLocator.from_dict(m["migration_run_context_locator"], expected_type=_RUN_CONTEXT_SCHEMA),
            generation_id=m["generation_id"], partition_key=m["partition_key"],
            parent_generation_manifest_locator=None if raw_parent is None else ArtifactLocator.from_dict(raw_parent, expected_type=cls.SCHEMA),
            created_at_utc=m["created_at_utc"], row_count=m["row_count"], logical_rows_digest=m["logical_rows_digest"],
            registry_snapshot_locator=ArtifactLocator.from_dict(m["registry_snapshot_locator"], expected_type=_REGISTRY_SNAPSHOT_SCHEMA),
            curation_execution_locator=ArtifactLocator.from_dict(m["curation_execution_locator"], expected_type=CurationExecution.SCHEMA),
            base_dataset_catalog_locator=ArtifactLocator.from_dict(m["base_dataset_catalog_locator"], expected_type=DatasetCatalog.SCHEMA),
            operational_read_evidence_locators=tuple(ArtifactLocator.from_dict(e, expected_type=OperationalReadEvidence.SCHEMA) for e in raw_ev),
            parquet_object_locators=tuple(ParquetObjectLocator.from_dict(p) for p in raw_pq),
            row_schema=m["row_schema"], physical_parquet_set_digest=pq_digest, integrity=integrity,
        )


@dataclass(frozen=True, slots=True)
class ActivePartitionHead:
    """Schemaless 3-member `smart_ads/active_partition_head/v1` embedded entry (ADR-0001 §6.3)."""

    SCHEMA: ClassVar[str] = "smart_ads/active_partition_head/v1"
    KEYS: ClassVar[frozenset[str]] = frozenset(
        {"partition_key", "head_sequence_number", "generation_manifest_locator"}
    )

    partition_key: str
    head_sequence_number: int
    generation_manifest_locator: ArtifactLocator

    def __post_init__(self) -> None:
        label = "active_partition_head"
        validate_partition_key(self.partition_key, field_name=f"{label}.partition_key")
        _safe_int(self.head_sequence_number, field_name=f"{label}.head_sequence_number", minimum=1)
        _typed_locator(self.generation_manifest_locator, field_name=f"{label}.generation_manifest_locator", expected_type=GenerationManifest.SCHEMA)

    def to_dict(self) -> dict[str, Any]:
        return {
            "partition_key": self.partition_key,
            "head_sequence_number": self.head_sequence_number,
            "generation_manifest_locator": self.generation_manifest_locator.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: object) -> ActivePartitionHead:
        m = require_exact_keys(data, cls.KEYS, label="active_partition_head")
        return cls(
            partition_key=m["partition_key"], head_sequence_number=m["head_sequence_number"],
            generation_manifest_locator=ArtifactLocator.from_dict(m["generation_manifest_locator"], expected_type=GenerationManifest.SCHEMA),
        )


def _validate_partition_heads(
    values: object, *, allow_empty: bool, field_name: str
) -> tuple[ActivePartitionHead, ...]:
    if not isinstance(values, (list, tuple)):
        raise ClosedValidationError(f"{field_name}: expected list or tuple of ActivePartitionHead")
    heads: list[ActivePartitionHead] = []
    keys: list[bytes] = []
    for idx, item in enumerate(values):
        if type(item) is not ActivePartitionHead:
            raise ClosedValidationError(f"{field_name}[{idx}]: expected ActivePartitionHead")
        fresh = ActivePartitionHead.from_dict(item.to_dict())
        heads.append(fresh)
        keys.append(fresh.partition_key.encode("utf-8"))
    if not allow_empty and not heads:
        raise ClosedValidationError(f"{field_name}: must not be empty")
    if len(set(keys)) != len(keys) or any(left > right for left, right in pairwise(keys)):
        raise ClosedValidationError(f"{field_name}: partition_heads must be unique and sorted by UTF-8 partition_key")
    return tuple(heads)


@dataclass(frozen=True, slots=True)
class DatasetCatalogGenesisRecord(_P1EnvelopeBase):
    """Closed P1 `smart_ads/dataset_catalog_genesis_record/v1` (8 core + `integrity` = 9 keys)."""

    SCHEMA: ClassVar[str] = "smart_ads/dataset_catalog_genesis_record/v1"
    P1_DOMAIN_PREFIX: ClassVar[str] = ADR_P1_DOMAIN_PREFIXES[SCHEMA]
    CORE_KEYS: ClassVar[frozenset[str]] = frozenset(
        "$schema genesis_id cell_ref migration_run_context_locator empty_epoch0_catalog_locator "
        "empty_epoch0_catalog_digest bootstrap_authority_ref issued_at_utc".split()
    )
    KEYS: ClassVar[frozenset[str]] = CORE_KEYS | {"integrity"}

    genesis_id: str
    cell_ref: str
    migration_run_context_locator: ArtifactLocator
    empty_epoch0_catalog_locator: ArtifactLocator
    empty_epoch0_catalog_digest: str
    bootstrap_authority_ref: str
    issued_at_utc: str
    integrity: P1Integrity | None = None

    def __post_init__(self) -> None:
        label = "dataset_catalog_genesis_record"
        _strict_id(self.genesis_id, field_name=f"{label}.genesis_id")
        validate_opaque_ref(_strict_str(self.cell_ref, field_name=f"{label}.cell_ref"), field_name=f"{label}.cell_ref", expected_prefix="cell")
        _typed_locator(self.migration_run_context_locator, field_name=f"{label}.migration_run_context_locator", expected_type=_RUN_CONTEXT_SCHEMA)
        _require_locator_digest_pair(self.empty_epoch0_catalog_locator, self.empty_epoch0_catalog_digest, expected_type=DatasetCatalog.SCHEMA, loc_field=f"{label}.empty_epoch0_catalog_locator", digest_field=f"{label}.empty_epoch0_catalog_digest")
        _validate_colon_ref(self.bootstrap_authority_ref, field_name=f"{label}.bootstrap_authority_ref")
        validate_envelope_timestamp_utc(self.issued_at_utc, field_name=f"{label}.issued_at_utc")
        _verify_p1_integrity(self.integrity, self.to_dict, label=label)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "$schema": self.SCHEMA, "genesis_id": self.genesis_id, "cell_ref": self.cell_ref,
            "migration_run_context_locator": self.migration_run_context_locator.to_dict(),
            "empty_epoch0_catalog_locator": self.empty_epoch0_catalog_locator.to_dict(),
            "empty_epoch0_catalog_digest": self.empty_epoch0_catalog_digest,
            "bootstrap_authority_ref": self.bootstrap_authority_ref, "issued_at_utc": self.issued_at_utc,
        }
        return out if self.integrity is None else {**out, "integrity": self.integrity.to_dict()}

    @classmethod
    def from_dict(cls, data: object, *, require_signed: bool = False) -> DatasetCatalogGenesisRecord:
        m, integrity = _split_p1_envelope(data, core_keys=cls.CORE_KEYS, schema=cls.SCHEMA, label="dataset_catalog_genesis_record", require_signed=require_signed)
        return cls(
            genesis_id=m["genesis_id"], cell_ref=m["cell_ref"],
            migration_run_context_locator=ArtifactLocator.from_dict(m["migration_run_context_locator"], expected_type=_RUN_CONTEXT_SCHEMA),
            empty_epoch0_catalog_locator=ArtifactLocator.from_dict(m["empty_epoch0_catalog_locator"], expected_type=DatasetCatalog.SCHEMA),
            empty_epoch0_catalog_digest=m["empty_epoch0_catalog_digest"],
            bootstrap_authority_ref=m["bootstrap_authority_ref"], issued_at_utc=m["issued_at_utc"], integrity=integrity,
        )


@dataclass(frozen=True, slots=True)
class DatasetCatalogGenesisConsumptionRecord(_P1EnvelopeBase):
    """Closed P1 `smart_ads/dataset_catalog_genesis_consumption_record/v1` (10 core + `integrity` = 11 keys)."""

    SCHEMA: ClassVar[str] = "smart_ads/dataset_catalog_genesis_consumption_record/v1"
    P1_DOMAIN_PREFIX: ClassVar[str] = ADR_P1_DOMAIN_PREFIXES[SCHEMA]
    CORE_KEYS: ClassVar[frozenset[str]] = frozenset(
        "$schema genesis_record_locator genesis_record_digest empty_epoch0_catalog_locator "
        "empty_epoch0_catalog_digest first_successor_catalog_locator first_successor_catalog_digest "
        "preallocated_cut_id cas_linearization_id consumed_at_utc".split()
    )
    KEYS: ClassVar[frozenset[str]] = CORE_KEYS | {"integrity"}

    genesis_record_locator: ArtifactLocator
    genesis_record_digest: str
    empty_epoch0_catalog_locator: ArtifactLocator
    empty_epoch0_catalog_digest: str
    first_successor_catalog_locator: ArtifactLocator
    first_successor_catalog_digest: str
    preallocated_cut_id: str
    cas_linearization_id: str
    consumed_at_utc: str
    integrity: P1Integrity | None = None

    def __post_init__(self) -> None:
        label = "dataset_catalog_genesis_consumption_record"
        _require_locator_digest_pair(self.genesis_record_locator, self.genesis_record_digest, expected_type=DatasetCatalogGenesisRecord.SCHEMA, loc_field=f"{label}.genesis_record_locator", digest_field=f"{label}.genesis_record_digest")
        _, ep0_d = _require_locator_digest_pair(self.empty_epoch0_catalog_locator, self.empty_epoch0_catalog_digest, expected_type=DatasetCatalog.SCHEMA, loc_field=f"{label}.empty_epoch0_catalog_locator", digest_field=f"{label}.empty_epoch0_catalog_digest")
        _, succ_d = _require_locator_digest_pair(self.first_successor_catalog_locator, self.first_successor_catalog_digest, expected_type=DatasetCatalog.SCHEMA, loc_field=f"{label}.first_successor_catalog_locator", digest_field=f"{label}.first_successor_catalog_digest")
        if ep0_d == succ_d:
            raise ClosedValidationError(f"{label}: first_successor_catalog_digest must differ from empty_epoch0_catalog_digest")
        _strict_id(self.preallocated_cut_id, field_name=f"{label}.preallocated_cut_id")
        _strict_id(self.cas_linearization_id, field_name=f"{label}.cas_linearization_id")
        validate_envelope_timestamp_utc(self.consumed_at_utc, field_name=f"{label}.consumed_at_utc")
        _verify_p1_integrity(self.integrity, self.to_dict, label=label)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "$schema": self.SCHEMA, "preallocated_cut_id": self.preallocated_cut_id,
            "genesis_record_locator": self.genesis_record_locator.to_dict(),
            "genesis_record_digest": self.genesis_record_digest,
            "empty_epoch0_catalog_locator": self.empty_epoch0_catalog_locator.to_dict(),
            "empty_epoch0_catalog_digest": self.empty_epoch0_catalog_digest,
            "first_successor_catalog_locator": self.first_successor_catalog_locator.to_dict(),
            "first_successor_catalog_digest": self.first_successor_catalog_digest,
            "cas_linearization_id": self.cas_linearization_id, "consumed_at_utc": self.consumed_at_utc,
        }
        return out if self.integrity is None else {**out, "integrity": self.integrity.to_dict()}

    @classmethod
    def from_dict(cls, data: object, *, require_signed: bool = False) -> DatasetCatalogGenesisConsumptionRecord:
        m, integrity = _split_p1_envelope(data, core_keys=cls.CORE_KEYS, schema=cls.SCHEMA, label="dataset_catalog_genesis_consumption_record", require_signed=require_signed)
        return cls(
            genesis_record_locator=ArtifactLocator.from_dict(m["genesis_record_locator"], expected_type=DatasetCatalogGenesisRecord.SCHEMA),
            genesis_record_digest=m["genesis_record_digest"],
            empty_epoch0_catalog_locator=ArtifactLocator.from_dict(m["empty_epoch0_catalog_locator"], expected_type=DatasetCatalog.SCHEMA),
            empty_epoch0_catalog_digest=m["empty_epoch0_catalog_digest"],
            first_successor_catalog_locator=ArtifactLocator.from_dict(m["first_successor_catalog_locator"], expected_type=DatasetCatalog.SCHEMA),
            first_successor_catalog_digest=m["first_successor_catalog_digest"],
            preallocated_cut_id=m["preallocated_cut_id"], cas_linearization_id=m["cas_linearization_id"],
            consumed_at_utc=m["consumed_at_utc"], integrity=integrity,
        )


@dataclass(frozen=True, slots=True)
class DatasetCatalog(_P1EnvelopeBase):
    """Closed P1 `smart_ads/dataset_catalog/v1` envelope (6 core + `integrity` = 7 keys)."""

    SCHEMA: ClassVar[str] = "smart_ads/dataset_catalog/v1"
    P1_DOMAIN_PREFIX: ClassVar[str] = ADR_P1_DOMAIN_PREFIXES[SCHEMA]
    CORE_KEYS: ClassVar[frozenset[str]] = frozenset(
        "$schema catalog_id cell_ref catalog_epoch created_at_utc partition_heads".split()
    )
    KEYS: ClassVar[frozenset[str]] = CORE_KEYS | {"integrity"}

    catalog_id: str
    cell_ref: str
    catalog_epoch: int
    created_at_utc: str
    partition_heads: tuple[ActivePartitionHead, ...]
    integrity: P1Integrity | None = None

    def __post_init__(self) -> None:
        label = "dataset_catalog"
        _strict_id(self.catalog_id, field_name=f"{label}.catalog_id")
        validate_opaque_ref(_strict_str(self.cell_ref, field_name=f"{label}.cell_ref"), field_name=f"{label}.cell_ref", expected_prefix="cell")
        epoch = _safe_int(self.catalog_epoch, field_name=f"{label}.catalog_epoch", minimum=0)
        validate_envelope_timestamp_utc(self.created_at_utc, field_name=f"{label}.created_at_utc")
        heads = _validate_partition_heads(self.partition_heads, allow_empty=(epoch == 0), field_name=f"{label}.partition_heads")
        if epoch == 0 and heads:
            raise ClosedValidationError(f"{label}: catalog_epoch == 0 requires empty partition_heads")
        object.__setattr__(self, "partition_heads", heads)
        _verify_p1_integrity(self.integrity, self.to_dict, label=label)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "$schema": self.SCHEMA, "catalog_id": self.catalog_id, "cell_ref": self.cell_ref,
            "catalog_epoch": self.catalog_epoch, "created_at_utc": self.created_at_utc,
            "partition_heads": [h.to_dict() for h in self.partition_heads],
        }
        return out if self.integrity is None else {**out, "integrity": self.integrity.to_dict()}

    @classmethod
    def from_dict(cls, data: object, *, require_signed: bool = False) -> DatasetCatalog:
        m, integrity = _split_p1_envelope(data, core_keys=cls.CORE_KEYS, schema=cls.SCHEMA, label="dataset_catalog", require_signed=require_signed)
        raw_heads = _require_json_list(m, "partition_heads", label="dataset_catalog")
        return cls(
            catalog_id=m["catalog_id"], cell_ref=m["cell_ref"], catalog_epoch=m["catalog_epoch"],
            created_at_utc=m["created_at_utc"],
            partition_heads=tuple(ActivePartitionHead.from_dict(h) for h in raw_heads), integrity=integrity,
        )


@dataclass(frozen=True, slots=True)
class CatalogCasRequestProjection:
    """Closed 6-member `cas_request_projection` inside `dataset_catalog_cut_receipt/v1`."""

    KEYS: ClassVar[frozenset[str]] = frozenset(
        "operation expected_old_catalog_epoch expected_old_catalog_digest partition_key "
        "target_head_sequence_number generation_manifest_locator".split()
    )

    operation: CatalogCasOperation
    expected_old_catalog_epoch: int
    expected_old_catalog_digest: str
    partition_key: str
    target_head_sequence_number: int
    generation_manifest_locator: ArtifactLocator

    def __post_init__(self) -> None:
        label = "catalog_cas_request_projection"
        op = _strict_str(self.operation, field_name=f"{label}.operation")
        if op not in _CATALOG_CAS_OPERATIONS:
            raise ClosedValidationError(f"{label}.operation: invalid operation {op!r}")
        _safe_int(self.expected_old_catalog_epoch, field_name=f"{label}.expected_old_catalog_epoch", minimum=1 if op == "replace_partition" else 0)
        validate_sha256_prefixed(_strict_str(self.expected_old_catalog_digest, field_name=f"{label}.expected_old_catalog_digest"), field_name=f"{label}.expected_old_catalog_digest")
        validate_partition_key(self.partition_key, field_name=f"{label}.partition_key")
        seq = _safe_int(self.target_head_sequence_number, field_name=f"{label}.target_head_sequence_number", minimum=1)
        if (op == "add_partition" and seq != 1) or (op == "replace_partition" and seq < 2):
            raise ClosedValidationError(f"{label}: invalid target_head_sequence_number {seq} for {op!r}")
        _typed_locator(self.generation_manifest_locator, field_name=f"{label}.generation_manifest_locator", expected_type=GenerationManifest.SCHEMA)

    def to_dict(self) -> dict[str, Any]:
        return {
            "operation": self.operation, "expected_old_catalog_epoch": self.expected_old_catalog_epoch,
            "expected_old_catalog_digest": self.expected_old_catalog_digest, "partition_key": self.partition_key,
            "target_head_sequence_number": self.target_head_sequence_number,
            "generation_manifest_locator": self.generation_manifest_locator.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: object) -> CatalogCasRequestProjection:
        m = require_exact_keys(data, cls.KEYS, label="catalog_cas_request_projection")
        return cls(
            operation=m["operation"], expected_old_catalog_epoch=m["expected_old_catalog_epoch"],
            expected_old_catalog_digest=m["expected_old_catalog_digest"], partition_key=m["partition_key"],
            target_head_sequence_number=m["target_head_sequence_number"],
            generation_manifest_locator=ArtifactLocator.from_dict(m["generation_manifest_locator"], expected_type=GenerationManifest.SCHEMA),
        )


def _check_cut_genesis_fields(receipt: DatasetCatalogCutReceipt, *, label: str) -> None:
    g_vals = (
        receipt.genesis_record_locator, receipt.genesis_record_digest,
        receipt.genesis_consumption_locator, receipt.genesis_consumption_digest,
    )
    if receipt.old_catalog_epoch == 0:
        if any(val is None for val in g_vals):
            raise ClosedValidationError(f"{label}: old_catalog_epoch == 0 requires all 4 genesis fields")
        _require_locator_digest_pair(receipt.genesis_record_locator, receipt.genesis_record_digest, expected_type=DatasetCatalogGenesisRecord.SCHEMA, loc_field=f"{label}.genesis_record_locator", digest_field=f"{label}.genesis_record_digest")
        _require_locator_digest_pair(receipt.genesis_consumption_locator, receipt.genesis_consumption_digest, expected_type=DatasetCatalogGenesisConsumptionRecord.SCHEMA, loc_field=f"{label}.genesis_consumption_locator", digest_field=f"{label}.genesis_consumption_digest")
        if receipt.cas_request_projection.operation != "add_partition":
            raise ClosedValidationError(f"{label}: epoch-0 cut requires add_partition")
    elif any(val is not None for val in g_vals):
        raise ClosedValidationError(f"{label}: genesis fields are forbidden when old_catalog_epoch >= 1")


@dataclass(frozen=True, slots=True)
class DatasetCatalogCutReceipt(_P1EnvelopeBase):
    """Closed P1 `smart_ads/dataset_catalog_cut_receipt/v1` (13 base + 4 epoch-0 genesis + `integrity`)."""

    SCHEMA: ClassVar[str] = "smart_ads/dataset_catalog_cut_receipt/v1"
    P1_DOMAIN_PREFIX: ClassVar[str] = ADR_P1_DOMAIN_PREFIXES[SCHEMA]
    BASE_CORE_KEYS: ClassVar[frozenset[str]] = frozenset(
        "$schema cut_id cell_ref migration_run_context_locator old_catalog_locator old_catalog_digest "
        "old_catalog_epoch new_catalog_locator new_catalog_digest new_catalog_epoch cas_request_projection "
        "cas_linearization_id committed_at_utc".split()
    )
    GENESIS_KEYS: ClassVar[frozenset[str]] = frozenset(
        "genesis_record_locator genesis_record_digest genesis_consumption_locator genesis_consumption_digest".split()
    )
    CORE_KEYS: ClassVar[frozenset[str]] = BASE_CORE_KEYS | GENESIS_KEYS
    KEYS: ClassVar[frozenset[str]] = CORE_KEYS | {"integrity"}

    cut_id: str
    cell_ref: str
    migration_run_context_locator: ArtifactLocator
    old_catalog_locator: ArtifactLocator
    old_catalog_digest: str
    old_catalog_epoch: int
    new_catalog_locator: ArtifactLocator
    new_catalog_digest: str
    new_catalog_epoch: int
    cas_request_projection: CatalogCasRequestProjection
    cas_linearization_id: str
    committed_at_utc: str
    genesis_record_locator: ArtifactLocator | None = None
    genesis_record_digest: str | None = None
    genesis_consumption_locator: ArtifactLocator | None = None
    genesis_consumption_digest: str | None = None
    integrity: P1Integrity | None = None

    def __post_init__(self) -> None:
        label = "dataset_catalog_cut_receipt"
        _strict_id(self.cut_id, field_name=f"{label}.cut_id")
        validate_opaque_ref(_strict_str(self.cell_ref, field_name=f"{label}.cell_ref"), field_name=f"{label}.cell_ref", expected_prefix="cell")
        _typed_locator(self.migration_run_context_locator, field_name=f"{label}.migration_run_context_locator", expected_type=_RUN_CONTEXT_SCHEMA)
        _, old_d = _require_locator_digest_pair(self.old_catalog_locator, self.old_catalog_digest, expected_type=DatasetCatalog.SCHEMA, loc_field=f"{label}.old_catalog_locator", digest_field=f"{label}.old_catalog_digest")
        _, new_d = _require_locator_digest_pair(self.new_catalog_locator, self.new_catalog_digest, expected_type=DatasetCatalog.SCHEMA, loc_field=f"{label}.new_catalog_locator", digest_field=f"{label}.new_catalog_digest")
        old_ep = _safe_int(self.old_catalog_epoch, field_name=f"{label}.old_catalog_epoch", minimum=0)
        new_ep = _safe_int(self.new_catalog_epoch, field_name=f"{label}.new_catalog_epoch", minimum=1)
        if new_ep != old_ep + 1 or new_d == old_d:
            raise ClosedValidationError(f"{label}: new catalog must advance epoch by +1 with distinct digest")
        if type(self.cas_request_projection) is not CatalogCasRequestProjection:
            raise ClosedValidationError(f"{label}.cas_request_projection: expected CatalogCasRequestProjection")
        proj = CatalogCasRequestProjection.from_dict(self.cas_request_projection.to_dict())
        if (proj.expected_old_catalog_epoch, proj.expected_old_catalog_digest) != (old_ep, old_d):
            raise ClosedValidationError(f"{label}: cas_request_projection disagrees with old catalog identity")
        _strict_id(self.cas_linearization_id, field_name=f"{label}.cas_linearization_id")
        validate_envelope_timestamp_utc(self.committed_at_utc, field_name=f"{label}.committed_at_utc")
        _check_cut_genesis_fields(self, label=label)
        _verify_p1_integrity(self.integrity, self.to_dict, label=label)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "$schema": self.SCHEMA, "cut_id": self.cut_id, "cell_ref": self.cell_ref,
            "migration_run_context_locator": self.migration_run_context_locator.to_dict(),
            "old_catalog_locator": self.old_catalog_locator.to_dict(), "old_catalog_digest": self.old_catalog_digest,
            "old_catalog_epoch": self.old_catalog_epoch, "new_catalog_epoch": self.new_catalog_epoch,
            "new_catalog_locator": self.new_catalog_locator.to_dict(), "new_catalog_digest": self.new_catalog_digest,
            "cas_request_projection": self.cas_request_projection.to_dict(),
            "cas_linearization_id": self.cas_linearization_id, "committed_at_utc": self.committed_at_utc,
        }
        if self.old_catalog_epoch == 0:
            out["genesis_record_locator"] = self.genesis_record_locator.to_dict()  # type: ignore[union-attr]
            out["genesis_record_digest"] = self.genesis_record_digest
            out["genesis_consumption_locator"] = self.genesis_consumption_locator.to_dict()  # type: ignore[union-attr]
            out["genesis_consumption_digest"] = self.genesis_consumption_digest
        return out if self.integrity is None else {**out, "integrity": self.integrity.to_dict()}

    @classmethod
    def from_dict(cls, data: object, *, require_signed: bool = False) -> DatasetCatalogCutReceipt:
        raw_map = require_mapping(data, label="dataset_catalog_cut_receipt")
        if "old_catalog_epoch" not in raw_map:
            require_exact_keys(raw_map, cls.BASE_CORE_KEYS, label="dataset_catalog_cut_receipt")
        old_ep = _safe_int(raw_map["old_catalog_epoch"], field_name="dataset_catalog_cut_receipt.old_catalog_epoch", minimum=0)
        core = cls.CORE_KEYS if old_ep == 0 else cls.BASE_CORE_KEYS
        m, integrity = _split_p1_envelope(raw_map, core_keys=core, schema=cls.SCHEMA, label="dataset_catalog_cut_receipt", require_signed=require_signed)
        gen_rec_loc = ArtifactLocator.from_dict(m["genesis_record_locator"], expected_type=DatasetCatalogGenesisRecord.SCHEMA) if old_ep == 0 else None
        gen_cons_loc = ArtifactLocator.from_dict(m["genesis_consumption_locator"], expected_type=DatasetCatalogGenesisConsumptionRecord.SCHEMA) if old_ep == 0 else None
        return cls(
            cut_id=m["cut_id"], cell_ref=m["cell_ref"], old_catalog_epoch=old_ep, new_catalog_epoch=m["new_catalog_epoch"],
            migration_run_context_locator=ArtifactLocator.from_dict(m["migration_run_context_locator"], expected_type=_RUN_CONTEXT_SCHEMA),
            old_catalog_locator=ArtifactLocator.from_dict(m["old_catalog_locator"], expected_type=DatasetCatalog.SCHEMA),
            old_catalog_digest=m["old_catalog_digest"],
            new_catalog_locator=ArtifactLocator.from_dict(m["new_catalog_locator"], expected_type=DatasetCatalog.SCHEMA),
            new_catalog_digest=m["new_catalog_digest"],
            cas_request_projection=CatalogCasRequestProjection.from_dict(m["cas_request_projection"]),
            cas_linearization_id=m["cas_linearization_id"], committed_at_utc=m["committed_at_utc"],
            genesis_record_locator=gen_rec_loc, genesis_record_digest=m["genesis_record_digest"] if old_ep == 0 else None,
            genesis_consumption_locator=gen_cons_loc, genesis_consumption_digest=m["genesis_consumption_digest"] if old_ep == 0 else None,
            integrity=integrity,
        )


@dataclass(frozen=True, slots=True)
class DatasetSnapshot(_P1EnvelopeBase):
    """Closed P1 `smart_ads/dataset_snapshot/v1` envelope (8 core + `integrity` = 9 keys)."""

    SCHEMA: ClassVar[str] = "smart_ads/dataset_snapshot/v1"
    P1_DOMAIN_PREFIX: ClassVar[str] = ADR_P1_DOMAIN_PREFIXES[SCHEMA]
    CORE_KEYS: ClassVar[frozenset[str]] = frozenset(
        "$schema snapshot_id snapshot_digest catalog_epoch dataset_catalog_locator "
        "catalog_cut_receipt_locator created_at partition_heads".split()
    )
    KEYS: ClassVar[frozenset[str]] = CORE_KEYS | {"integrity"}

    snapshot_id: str
    catalog_epoch: int
    dataset_catalog_locator: ArtifactLocator
    catalog_cut_receipt_locator: ArtifactLocator
    created_at: str
    partition_heads: tuple[ActivePartitionHead, ...]
    snapshot_digest: str = ""
    integrity: P1Integrity | None = None

    def __post_init__(self) -> None:
        label = "dataset_snapshot"
        validate_opaque_ref(_strict_str(self.snapshot_id, field_name=f"{label}.snapshot_id"), field_name=f"{label}.snapshot_id", expected_prefix="snapshot")
        _safe_int(self.catalog_epoch, field_name=f"{label}.catalog_epoch", minimum=1)
        _typed_locator(self.dataset_catalog_locator, field_name=f"{label}.dataset_catalog_locator", expected_type=DatasetCatalog.SCHEMA)
        _typed_locator(self.catalog_cut_receipt_locator, field_name=f"{label}.catalog_cut_receipt_locator", expected_type=DatasetCatalogCutReceipt.SCHEMA)
        validate_envelope_timestamp_utc(self.created_at, field_name=f"{label}.created_at")
        object.__setattr__(self, "partition_heads", _validate_partition_heads(self.partition_heads, allow_empty=False, field_name=f"{label}.partition_heads"))
        raw_sd = _strict_str(self.snapshot_digest, field_name=f"{label}.snapshot_digest")
        expected_sd = self_digest_jcs_sha256(self.to_dict(), digest_member="snapshot_digest", domain_prefix=None, strip_integrity=True)
        if raw_sd == "":
            object.__setattr__(self, "snapshot_digest", expected_sd)
        elif validate_sha256_prefixed(raw_sd, field_name=f"{label}.snapshot_digest") != expected_sd:
            raise ClosedValidationError(f"{label}.snapshot_digest: recomputed {expected_sd!r} != {raw_sd!r}")
        _verify_p1_integrity(self.integrity, self.to_dict, label=label)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "$schema": self.SCHEMA, "snapshot_id": self.snapshot_id, "snapshot_digest": self.snapshot_digest,
            "catalog_epoch": self.catalog_epoch, "created_at": self.created_at,
            "dataset_catalog_locator": self.dataset_catalog_locator.to_dict(),
            "catalog_cut_receipt_locator": self.catalog_cut_receipt_locator.to_dict(),
            "partition_heads": [h.to_dict() for h in self.partition_heads],
        }
        return out if self.integrity is None else {**out, "integrity": self.integrity.to_dict()}

    @classmethod
    def from_dict(cls, data: object, *, require_signed: bool = False) -> DatasetSnapshot:
        m, integrity = _split_p1_envelope(data, core_keys=cls.CORE_KEYS, schema=cls.SCHEMA, label="dataset_snapshot", require_signed=require_signed)
        raw_heads = _require_json_list(m, "partition_heads", label="dataset_snapshot")
        sd = validate_sha256_prefixed(_strict_str(m["snapshot_digest"], field_name="dataset_snapshot.snapshot_digest"), field_name="dataset_snapshot.snapshot_digest")
        return cls(
            snapshot_id=m["snapshot_id"], catalog_epoch=m["catalog_epoch"], created_at=m["created_at"],
            dataset_catalog_locator=ArtifactLocator.from_dict(m["dataset_catalog_locator"], expected_type=DatasetCatalog.SCHEMA),
            catalog_cut_receipt_locator=ArtifactLocator.from_dict(m["catalog_cut_receipt_locator"], expected_type=DatasetCatalogCutReceipt.SCHEMA),
            partition_heads=tuple(ActivePartitionHead.from_dict(h) for h in raw_heads),
            snapshot_digest=sd, integrity=integrity,
        )


__all__ = [
    "ActivePartitionHead", "CatalogCasOperation", "CatalogCasRequestProjection", "DatasetCatalog",
    "DatasetCatalogCutReceipt", "DatasetCatalogGenesisConsumptionRecord", "DatasetCatalogGenesisRecord",
    "DatasetSnapshot", "GenerationManifest", "ParquetObjectLocator",
    "compute_logical_rows_digest", "compute_physical_parquet_set_digest",
]
