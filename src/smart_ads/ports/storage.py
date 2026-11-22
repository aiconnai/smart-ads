"""Pure storage, Parquet v1 codec, and rebuildable DuckDB engine ports (ADR-0001 §§6.3–6.4, 12.4)."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Literal, Protocol, runtime_checkable

from smart_ads.analytics.cells import AnalysisResultSchema, ResultProjection
from smart_ads.analytics.replay_bundle import AnalysisReplayInputBundle
from smart_ads.contracts.jcs import ArtifactLocator
from smart_ads.contracts.schemas import AnalyticsLandingRow
from smart_ads.domain.catalog import ParquetObjectLocator

ParquetCompression = Literal["uncompressed", "gzip"]


@runtime_checkable
class CellObjectStorePort(Protocol):
    """Immutable content-addressed cell object store (no delete or overwrite methods)."""

    def put_bytes(self, raw: bytes) -> str:
        """Persist raw bytes and return canonical `'cell-object:sha256:<64_hex>'` ref."""
        ...

    def get_bytes(
        self, object_ref: str, *, expected_size_bytes: int | None = None
    ) -> bytes:
        """Read and SHA-256/size-verify raw bytes addressed by `object_ref`."""
        ...

    def has_object(self, object_ref: str) -> bool:
        """Return `True` iff `object_ref` exists in the store."""
        ...

    def put_json_artifact(
        self, schema_id: str, payload: Mapping[str, Any]
    ) -> ArtifactLocator:
        """Canonicalize `payload` under RFC 8785, store bytes, and return `ArtifactLocator`."""
        ...

    def get_json_artifact(self, locator: ArtifactLocator) -> dict[str, Any]:
        """Resolve, SHA-256-verify, and strictly parse the JSON artifact at `locator`."""
        ...


@runtime_checkable
class ParquetLandingCodecPort(Protocol):
    """Deterministic Apache Parquet v1 (`PAR1`) codec for `analytics_landing_row/v1`."""

    def encode_landing_rows(
        self,
        rows: Sequence[AnalyticsLandingRow],
        *,
        partition_key: str,
        compression: Literal["uncompressed", "gzip"] = "uncompressed",
    ) -> bytes:
        """Encode `rows` into deterministic gap-free Apache Parquet v1 bytes."""
        ...

    def decode_and_verify_landing_rows(
        self,
        raw_bytes: bytes,
        *,
        expected_partition_key: str,
    ) -> tuple[AnalyticsLandingRow, ...]:
        """Decode and verify contiguity, row digests, partition key, and `fact_key` order."""
        ...


@runtime_checkable
class DuckDbEnginePort(Protocol):
    """Isolated external DuckDB replay query execution port."""

    def execute_replay_queries(
        self,
        *,
        bundle: AnalysisReplayInputBundle,
        duckdb_binary_bytes: bytes,
        extension_binaries: Mapping[str, bytes],
        parquet_objects: Sequence[tuple[ParquetObjectLocator, bytes]],
        resolved_schemas: Mapping[bytes, AnalysisResultSchema],
    ) -> Mapping[str, ResultProjection]:
        """Execute `bundle.queries` in locked-down DuckDB and return `ResultProjection`s."""
        ...


__all__ = [
    "CellObjectStorePort",
    "DuckDbEnginePort",
    "ParquetCompression",
    "ParquetLandingCodecPort",
]
