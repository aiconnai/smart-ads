"""Immutable content-addressed object stores and deterministic Apache Parquet v1 codec (ADR-0001 §§6.1–6.3, 12.4)."""
from __future__ import annotations

from smart_ads.adapters.storage.object_store import (
    FilesystemCellObjectStore,
    InMemoryCellObjectStore,
)
from smart_ads.adapters.storage.parquet import (
    GZIP_RFC1952_HEADER,
    PARQUET_LANDING_COLUMNS,
    StdlibParquetLandingCodec,
    decode_and_verify_landing_parquet,
    encode_landing_parquet,
)

__all__ = [
    "FilesystemCellObjectStore",
    "GZIP_RFC1952_HEADER",
    "InMemoryCellObjectStore",
    "PARQUET_LANDING_COLUMNS",
    "StdlibParquetLandingCodec",
    "decode_and_verify_landing_parquet",
    "encode_landing_parquet",
]
