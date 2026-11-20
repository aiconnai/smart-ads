"""Strict zero-I/O Pipeboard wire parser, row reducer, private boundary, and offline 7A adapter (ADR-0001 §4.1)."""
from __future__ import annotations

from smart_ads.adapters.pipeboard.adapter import (
    PipeboardFixtureAdapter,
    PrivatePipeboardBindingBoundary,
    RegisteredFixtureCase,
    transform_pipeboard_response_to_batch,
)
from smart_ads.adapters.pipeboard.reducer import (
    META_CAMPAIGN_ID_RE,
    PINNED_PIPEBOARD_ROW_KEYS,
    CanonicalCampaignMetrics,
    PipeboardRowReducer,
    parse_campaign_row_metrics,
    reduce_pipeboard_insights_result,
)
from smart_ads.adapters.pipeboard.wire import (
    DEFAULT_PIPEBOARD_TRANSPORT_LIMITS,
    STATIC_DETAIL_BY_CODE,
    ParsedPipeboardEnvelope,
    PipeboardAdapterError,
    PipeboardWireRejection,
    build_pipeboard_insights_request,
    clean_transport_outcome,
    loads_pipeboard_wire_json,
    make_wire_rejection,
    parse_pipeboard_http_and_mcp_envelope,
    parse_pipeboard_mcp_result,
)

__all__ = [
    "CanonicalCampaignMetrics",
    "DEFAULT_PIPEBOARD_TRANSPORT_LIMITS",
    "META_CAMPAIGN_ID_RE",
    "PINNED_PIPEBOARD_ROW_KEYS",
    "ParsedPipeboardEnvelope",
    "PipeboardAdapterError",
    "PipeboardFixtureAdapter",
    "PipeboardRowReducer",
    "PipeboardWireRejection",
    "PrivatePipeboardBindingBoundary",
    "RegisteredFixtureCase",
    "STATIC_DETAIL_BY_CODE",
    "build_pipeboard_insights_request",
    "clean_transport_outcome",
    "loads_pipeboard_wire_json",
    "make_wire_rejection",
    "parse_campaign_row_metrics",
    "parse_pipeboard_http_and_mcp_envelope",
    "parse_pipeboard_mcp_result",
    "reduce_pipeboard_insights_result",
    "transform_pipeboard_response_to_batch",
]
