"""Zero-I/O MCP JSON-RPC 2.0 admission gateway and post-admission read handler port (ADR-0001 §3.3)."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final, Protocol, runtime_checkable

from smart_ads.contracts.jcs import canonicalize_jcs
from smart_ads.contracts.scalars import ClosedValidationError
from smart_ads.transports.mcp.delegation import (
    McpDelegationContext,
    McpRuntimeContext,
    verify_mcp_delegation_context,
)
from smart_ads.transports.mcp.protocol import (
    JsonRpcRequestId,
    McpProtocolRejection,
    _is_valid_jsonrpc_request_id,
    parse_mcp_wire_bytes,
    serialize_jsonrpc_result,
    validate_jsonrpc_request_envelope,
)
from smart_ads.transports.mcp.schemas import (
    ALLOWED_MCP_METHODS,
    IntelligenceFindingsQueryParams,
    McpMethodParams,
    PerformanceQueryParams,
    RecurrentSummaryReportParams,
    validate_mcp_method_params,
)

_ALLOWED_METHODS_SET: Final[frozenset[str]] = frozenset(ALLOWED_MCP_METHODS)


@dataclass(frozen=True, slots=True)
class AdmittedMcpRequest:
    """Immutable proof token produced only after all MCP deny-before-I/O checks succeed."""

    request_id: JsonRpcRequestId
    method: str
    params: McpMethodParams
    delegation_context: McpDelegationContext
    clock_lower_utc: str
    clock_upper_utc: str

    def __post_init__(self) -> None:
        if not _is_valid_jsonrpc_request_id(self.request_id):
            raise ClosedValidationError(
                "AdmittedMcpRequest.request_id violates JSON-RPC 2.0 ID bounds"
            )
        if type(self.method) is not str or self.method not in _ALLOWED_METHODS_SET:
            raise ClosedValidationError(
                "AdmittedMcpRequest.method must belong to ALLOWED_MCP_METHODS"
            )
        if (
            not isinstance(
                self.params,
                (
                    PerformanceQueryParams,
                    IntelligenceFindingsQueryParams,
                    RecurrentSummaryReportParams,
                ),
            )
            or self.params.method != self.method
        ):
            raise ClosedValidationError(
                "AdmittedMcpRequest.params must match AdmittedMcpRequest.method"
            )
        if type(self.delegation_context) is not McpDelegationContext:
            raise ClosedValidationError(
                "AdmittedMcpRequest.delegation_context must be McpDelegationContext"
            )
        runtime_ctx = McpRuntimeContext(
            clock_lower_utc=self.clock_lower_utc,
            clock_upper_utc=self.clock_upper_utc,
            delegation_context=self.delegation_context,
        )
        lower_us, upper_us = runtime_ctx.validate_clock_bounds()
        issued_us, valid_until_us = self.delegation_context.validate()
        if (
            self.delegation_context.allowed_method != self.method
            or self.delegation_context.tenant_ref != self.params.tenant_ref
            or self.delegation_context.binding_ref != self.params.binding_ref
            or self.delegation_context.resource_scope_ref
            != self.params.resource_scope_ref
            or not (issued_us <= lower_us <= upper_us < valid_until_us)
        ):
            raise ClosedValidationError(
                "AdmittedMcpRequest: delegation context or clock window does not authorize request"
            )


@runtime_checkable
class McpReadHandlerPort(Protocol):
    """Post-admission handler port invoked strictly after all pre-I/O protocol and delegation gates pass."""

    def handle(self, request: AdmittedMcpRequest) -> Mapping[str, Any]: ...


@dataclass(frozen=True, slots=True)
class McpWireOutcome:
    """Deterministic outcome of handling raw MCP wire bytes."""

    wire_bytes: bytes
    rejection: McpProtocolRejection | None
    admitted_request: AdmittedMcpRequest | None

    def __post_init__(self) -> None:
        if type(self.wire_bytes) is not bytes or len(self.wire_bytes) == 0:
            raise ClosedValidationError(
                "McpWireOutcome.wire_bytes must be non-empty bytes"
            )
        if (
            self.rejection is not None
            and type(self.rejection) is not McpProtocolRejection
        ):
            raise ClosedValidationError(
                "McpWireOutcome.rejection must be McpProtocolRejection or None"
            )
        if (
            self.admitted_request is not None
            and type(self.admitted_request) is not AdmittedMcpRequest
        ):
            raise ClosedValidationError(
                "McpWireOutcome.admitted_request must be AdmittedMcpRequest or None"
            )
        if (self.rejection is None) == (self.admitted_request is None):
            raise ClosedValidationError(
                "McpWireOutcome requires exactly one of rejection or admitted_request"
            )


def _serialize_closed_internal_error(request_id: JsonRpcRequestId) -> bytes:
    return canonicalize_jcs(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {
                "code": -32603,
                "message": "Internal error",
            },
        }
    )


def handle_mcp_request_bytes(
    raw_body: bytes,
    runtime_context: McpRuntimeContext | None,
    *,
    handler: McpReadHandlerPort | None = None,
) -> McpWireOutcome:
    """Execute the full zero-I/O MCP validation pipeline before touching `handler`."""
    if handler is not None and (
        not isinstance(handler, McpReadHandlerPort)
        or not callable(getattr(handler, "handle", None))
    ):
        raise ClosedValidationError(
            "handle_mcp_request_bytes: handler must implement McpReadHandlerPort or be None"
        )

    root_or_rej = parse_mcp_wire_bytes(raw_body)
    if isinstance(root_or_rej, McpProtocolRejection):
        return McpWireOutcome(
            wire_bytes=root_or_rej.to_wire_bytes(),
            rejection=root_or_rej,
            admitted_request=None,
        )

    env_or_rej = validate_jsonrpc_request_envelope(root_or_rej)
    if isinstance(env_or_rej, McpProtocolRejection):
        return McpWireOutcome(
            wire_bytes=env_or_rej.to_wire_bytes(),
            rejection=env_or_rej,
            admitted_request=None,
        )

    params_or_rej = validate_mcp_method_params(
        env_or_rej.method,
        env_or_rej.has_params,
        env_or_rej.params_raw,
        request_id=env_or_rej.request_id,
    )
    if isinstance(params_or_rej, McpProtocolRejection):
        return McpWireOutcome(
            wire_bytes=params_or_rej.to_wire_bytes(),
            rejection=params_or_rej,
            admitted_request=None,
        )

    delegation_or_rej = verify_mcp_delegation_context(
        runtime_context,
        method=env_or_rej.method,
        params=params_or_rej,
        request_id=env_or_rej.request_id,
    )
    if isinstance(delegation_or_rej, McpProtocolRejection):
        return McpWireOutcome(
            wire_bytes=delegation_or_rej.to_wire_bytes(),
            rejection=delegation_or_rej,
            admitted_request=None,
        )

    if runtime_context is None:
        raise ClosedValidationError(
            "internal invariant error: runtime_context unexpectedly None after delegation pass"
        )

    admitted = AdmittedMcpRequest(
        request_id=env_or_rej.request_id,
        method=env_or_rej.method,
        params=params_or_rej,
        delegation_context=delegation_or_rej,
        clock_lower_utc=runtime_context.clock_lower_utc,
        clock_upper_utc=runtime_context.clock_upper_utc,
    )

    if handler is None:
        return McpWireOutcome(
            wire_bytes=_serialize_closed_internal_error(admitted.request_id),
            rejection=None,
            admitted_request=admitted,
        )

    try:
        result_obj = handler.handle(admitted)
        wire_bytes = serialize_jsonrpc_result(admitted.request_id, result_obj)
    except Exception:
        wire_bytes = _serialize_closed_internal_error(admitted.request_id)

    return McpWireOutcome(
        wire_bytes=wire_bytes,
        rejection=None,
        admitted_request=admitted,
    )


__all__ = [
    "AdmittedMcpRequest",
    "McpReadHandlerPort",
    "McpWireOutcome",
    "handle_mcp_request_bytes",
]
