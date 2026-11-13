"""Pure MCP deny-before-I/O JSON-RPC 2.0 transport boundary (ADR-0001 §3.3)."""
from __future__ import annotations

from smart_ads.transports.mcp.delegation import (
    McpDelegationContext,
    McpRuntimeContext,
    verify_mcp_delegation_context,
)
from smart_ads.transports.mcp.gateway import (
    AdmittedMcpRequest,
    McpReadHandlerPort,
    McpWireOutcome,
    handle_mcp_request_bytes,
)
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
from smart_ads.transports.mcp.schemas import (
    ALLOWED_FINDING_TYPES,
    ALLOWED_MCP_METHODS,
    IntelligenceFindingsQueryParams,
    McpMethodParams,
    PerformanceQueryParams,
    RecurrentSummaryReportParams,
    validate_mcp_method_params,
)

__all__ = [
    "ALLOWED_FINDING_TYPES",
    "ALLOWED_MCP_METHODS",
    "AdmittedMcpRequest",
    "IntelligenceFindingsQueryParams",
    "JsonRpcRequestId",
    "MAX_MCP_BODY_BYTES",
    "MAX_MCP_NESTING_DEPTH",
    "McpDelegationContext",
    "McpMethodParams",
    "McpProtocolRejection",
    "McpReadHandlerPort",
    "McpRejectionCaseId",
    "McpRuntimeContext",
    "McpWireOutcome",
    "ParsedJsonRpcEnvelope",
    "PerformanceQueryParams",
    "RecurrentSummaryReportParams",
    "handle_mcp_request_bytes",
    "parse_mcp_wire_bytes",
    "serialize_jsonrpc_result",
    "validate_jsonrpc_request_envelope",
    "validate_mcp_method_params",
    "verify_mcp_delegation_context",
]
