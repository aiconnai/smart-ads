"""Pure MCP deny-before-I/O JSON-RPC 2.0 transport boundary (ADR-0001 §3.3)."""
from __future__ import annotations

from smart_ads.transports.mcp.protocol import (
    MAX_MCP_BODY_BYTES,
    MAX_MCP_NESTING_DEPTH,
    JsonRpcRequestId,
    McpProtocolRejection,
    McpRejectionCaseId,
    ParsedJsonRpcEnvelope,
    parse_mcp_wire_bytes,
    serialize_jsonrpc_result,
    validate_jsonrpc_request_envelope,
)

__all__ = [
    "JsonRpcRequestId",
    "MAX_MCP_BODY_BYTES",
    "MAX_MCP_NESTING_DEPTH",
    "McpProtocolRejection",
    "McpRejectionCaseId",
    "ParsedJsonRpcEnvelope",
    "parse_mcp_wire_bytes",
    "serialize_jsonrpc_result",
    "validate_jsonrpc_request_envelope",
]
