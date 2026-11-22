"""External SHA-256-verified DuckDB CLI replay adapter (ADR-0001 §6.4)."""
from __future__ import annotations

from smart_ads.adapters.duckdb.cli_engine import CliDuckDbBinaryAdapter

__all__ = [
    "CliDuckDbBinaryAdapter",
]
