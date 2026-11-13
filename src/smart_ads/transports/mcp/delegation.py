"""Out-of-band `/ibvi-ads` delegation verification prior to external I/O (ADR-0001 §2, §3.3, §12.7)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from smart_ads.contracts.jcs import ArtifactLocator
from smart_ads.contracts.scalars import (
    ClosedValidationError,
    parse_timestamp_utc_micros,
    validate_opaque_ref,
    validate_sha256_prefixed,
    validate_timestamp_utc_seconds,
)
from smart_ads.transports.mcp.protocol import (
    JsonRpcRequestId,
    McpProtocolRejection,
    _is_valid_jsonrpc_request_id,
)
from smart_ads.transports.mcp.schemas import (
    ALLOWED_MCP_METHODS,
    IntelligenceFindingsQueryParams,
    McpMethodParams,
    PerformanceQueryParams,
    RecurrentSummaryReportParams,
)

_DELEGATION_CONTEXT_SCHEMA: Final[str] = (
    "smart_ads/ibvi_ads_delegation_context/v1"
)
_IBVI_ADS_ROUTE: Final[str] = "/ibvi-ads"
_ALLOWED_METHODS_SET: Final[frozenset[str]] = frozenset(ALLOWED_MCP_METHODS)
_MAX_NONCE_LEN: Final[int] = 128


def _require_exact_str(value: object, *, field_name: str) -> str:
    if type(value) is not str:
        raise ClosedValidationError(f"{field_name}: expected exact str")
    return value


def _validate_printable_nonce(value: object) -> str:
    checked = _require_exact_str(value, field_name="delegation_context.nonce")
    if not (1 <= len(checked) <= _MAX_NONCE_LEN):
        raise ClosedValidationError(
            "delegation_context.nonce: length must be within [1, 128]"
        )
    for ch in checked:
        code = ord(ch)
        if not (0x21 <= code <= 0x7E):
            raise ClosedValidationError(
                "delegation_context.nonce: must contain printable non-whitespace ASCII only"
            )
    return checked


@dataclass(frozen=True, slots=True)
class McpDelegationContext:
    """Runtime-resolved `smart_ads/ibvi_ads_delegation_context/v1` carrier (never caller-supplied)."""

    schema: str
    route: str
    host_conductor_ref: str
    front_ref: str
    profile_ref: str
    tenant_ref: str
    binding_ref: str
    resource_scope_ref: str
    allowed_method: str
    policy_digest: str
    issued_at_utc: str
    valid_until_utc: str
    nonce: str
    locator: ArtifactLocator

    def validate(self) -> tuple[int, int]:
        """Validate closed delegation schema, route, refs, nonce, locator, and `[issued, valid_until)` window."""
        if (
            type(self.schema) is not str
            or self.schema != _DELEGATION_CONTEXT_SCHEMA
        ):
            raise ClosedValidationError(
                f"delegation_context.schema: expected {_DELEGATION_CONTEXT_SCHEMA!r}"
            )
        if type(self.route) is not str or self.route != _IBVI_ADS_ROUTE:
            raise ClosedValidationError(
                f"delegation_context.route: expected {_IBVI_ADS_ROUTE!r}"
            )
        validate_opaque_ref(
            _require_exact_str(
                self.host_conductor_ref,
                field_name="delegation_context.host_conductor_ref",
            ),
            field_name="delegation_context.host_conductor_ref",
            expected_prefix="conductor",
        )
        validate_opaque_ref(
            _require_exact_str(
                self.front_ref, field_name="delegation_context.front_ref"
            ),
            field_name="delegation_context.front_ref",
            expected_prefix="front",
        )
        validate_opaque_ref(
            _require_exact_str(
                self.profile_ref, field_name="delegation_context.profile_ref"
            ),
            field_name="delegation_context.profile_ref",
            expected_prefix="profile",
        )
        validate_opaque_ref(
            _require_exact_str(
                self.tenant_ref, field_name="delegation_context.tenant_ref"
            ),
            field_name="delegation_context.tenant_ref",
            expected_prefix="tenant",
        )
        validate_opaque_ref(
            _require_exact_str(
                self.binding_ref, field_name="delegation_context.binding_ref"
            ),
            field_name="delegation_context.binding_ref",
            expected_prefix="binding",
        )
        validate_opaque_ref(
            _require_exact_str(
                self.resource_scope_ref,
                field_name="delegation_context.resource_scope_ref",
            ),
            field_name="delegation_context.resource_scope_ref",
            expected_prefix="scope",
        )
        if (
            type(self.allowed_method) is not str
            or self.allowed_method not in _ALLOWED_METHODS_SET
        ):
            raise ClosedValidationError(
                "delegation_context.allowed_method: outside closed MCP allowlist"
            )
        validate_sha256_prefixed(
            _require_exact_str(
                self.policy_digest,
                field_name="delegation_context.policy_digest",
            ),
            field_name="delegation_context.policy_digest",
        )
        issued_str = _require_exact_str(
            self.issued_at_utc, field_name="delegation_context.issued_at_utc"
        )
        valid_until_str = _require_exact_str(
            self.valid_until_utc,
            field_name="delegation_context.valid_until_utc",
        )
        validate_timestamp_utc_seconds(
            issued_str, field_name="delegation_context.issued_at_utc"
        )
        validate_timestamp_utc_seconds(
            valid_until_str, field_name="delegation_context.valid_until_utc"
        )
        issued_us = parse_timestamp_utc_micros(
            issued_str,
            field_name="delegation_context.issued_at_utc",
            allow_whole_seconds=True,
        )
        valid_until_us = parse_timestamp_utc_micros(
            valid_until_str,
            field_name="delegation_context.valid_until_utc",
            allow_whole_seconds=True,
        )
        if not (issued_us < valid_until_us):
            raise ClosedValidationError(
                "delegation_context: issued_at_utc must strictly precede valid_until_utc"
            )
        _validate_printable_nonce(self.nonce)
        if (
            type(self.locator) is not ArtifactLocator
            or self.locator.artifact_type != _DELEGATION_CONTEXT_SCHEMA
        ):
            raise ClosedValidationError(
                "delegation_context.locator: must be an ArtifactLocator for "
                f"{_DELEGATION_CONTEXT_SCHEMA!r}"
            )
        return issued_us, valid_until_us


@dataclass(frozen=True, slots=True)
class McpRuntimeContext:
    """Host-provided authenticated clock interval and out-of-band `/ibvi-ads` delegation context."""

    clock_lower_utc: str
    clock_upper_utc: str
    delegation_context: McpDelegationContext | None

    def validate_clock_bounds(self) -> tuple[int, int]:
        """Validate whole-second UTC clock bounds and require `clock_lower_utc <= clock_upper_utc`."""
        lower_str = _require_exact_str(
            self.clock_lower_utc, field_name="runtime_context.clock_lower_utc"
        )
        upper_str = _require_exact_str(
            self.clock_upper_utc, field_name="runtime_context.clock_upper_utc"
        )
        validate_timestamp_utc_seconds(
            lower_str, field_name="runtime_context.clock_lower_utc"
        )
        validate_timestamp_utc_seconds(
            upper_str, field_name="runtime_context.clock_upper_utc"
        )
        lower_us = parse_timestamp_utc_micros(
            lower_str,
            field_name="runtime_context.clock_lower_utc",
            allow_whole_seconds=True,
        )
        upper_us = parse_timestamp_utc_micros(
            upper_str,
            field_name="runtime_context.clock_upper_utc",
            allow_whole_seconds=True,
        )
        if lower_us > upper_us:
            raise ClosedValidationError(
                "runtime_context: clock_lower_utc must not exceed clock_upper_utc"
            )
        return lower_us, upper_us


def _delegation_rejection(
    request_id: JsonRpcRequestId,
) -> McpProtocolRejection:
    return McpProtocolRejection(
        code=-32600,
        message="Invalid Request",
        request_id=request_id,
        case_id="missing_or_invalid_ibvi_ads_delegation",
    )


def verify_mcp_delegation_context(
    runtime_context: McpRuntimeContext | None,
    *,
    method: str,
    params: McpMethodParams,
    request_id: JsonRpcRequestId,
) -> McpDelegationContext | McpProtocolRejection:
    """Verify out-of-band `/ibvi-ads` delegation and semi-open clock containment prior to any I/O."""
    if not _is_valid_jsonrpc_request_id(request_id):
        raise ClosedValidationError(
            "verify_mcp_delegation_context: request_id violates JSON-RPC 2.0 ID bounds"
        )
    if type(method) is not str or method not in _ALLOWED_METHODS_SET:
        raise ClosedValidationError(
            "verify_mcp_delegation_context: method must belong to ALLOWED_MCP_METHODS"
        )
    if (
        type(params)
        not in (
            PerformanceQueryParams,
            IntelligenceFindingsQueryParams,
            RecurrentSummaryReportParams,
        )
        or params.method != method
    ):
        raise ClosedValidationError(
            "verify_mcp_delegation_context: params must be a validated McpMethodParams matching method"
        )

    if runtime_context is None or type(runtime_context) is not McpRuntimeContext:
        return _delegation_rejection(request_id)

    delegation = runtime_context.delegation_context
    if delegation is None or type(delegation) is not McpDelegationContext:
        return _delegation_rejection(request_id)

    try:
        lower_us, upper_us = runtime_context.validate_clock_bounds()
        issued_us, valid_until_us = delegation.validate()
    except ClosedValidationError:
        return _delegation_rejection(request_id)

    if (
        delegation.route != _IBVI_ADS_ROUTE
        or delegation.allowed_method != method
        or delegation.tenant_ref != params.tenant_ref
        or delegation.binding_ref != params.binding_ref
        or delegation.resource_scope_ref != params.resource_scope_ref
        or not (issued_us <= lower_us <= upper_us < valid_until_us)
    ):
        return _delegation_rejection(request_id)

    return delegation


__all__ = [
    "McpDelegationContext",
    "McpRuntimeContext",
    "verify_mcp_delegation_context",
]
