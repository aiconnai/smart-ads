"""Contract tests for zero-recursion MCP JSON-RPC 2.0 wire parser and deny-before-I/O gateway (ADR-0001 §3.3)."""
from __future__ import annotations

import ast
import base64
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from smart_ads.contracts import (
    MAX_JCS_SAFE_INT,
    MIN_JCS_SAFE_INT,
    ArtifactLocator,
    ClosedValidationError,
    canonicalize_jcs,
    loads_strict_json,
    validate_resource_ref,
)
import smart_ads.transports.mcp as mcp_pkg
from smart_ads.transports.mcp import (
    ALLOWED_FINDING_TYPES,
    ALLOWED_MCP_METHODS,
    MAX_MCP_BODY_BYTES,
    MAX_MCP_NESTING_DEPTH,
    AdmittedMcpRequest,
    IntelligenceFindingsQueryParams,
    McpDelegationContext,
    McpMethodParams,
    McpProtocolRejection,
    McpReadHandlerPort,
    McpRuntimeContext,
    McpWireOutcome,
    ParsedJsonRpcEnvelope,
    PerformanceQueryParams,
    RecurrentSummaryReportParams,
    handle_mcp_request_bytes,
    parse_mcp_wire_bytes,
    serialize_jsonrpc_result,
    validate_jsonrpc_request_envelope,
    validate_mcp_method_params,
    verify_mcp_delegation_context,
)
from smart_ads.transports.mcp.protocol import _NonExactJsonNumber

REPO_ROOT = Path(__file__).resolve().parents[2]
MCP_PKG_DIR = REPO_ROOT / "src" / "smart_ads" / "transports" / "mcp"
PROTOCOL_PATH = MCP_PKG_DIR / "protocol.py"


def test_mcp_package_constants_exports_and_no_json_loads() -> None:
    assert MAX_MCP_BODY_BYTES == 65_536
    assert MAX_MCP_NESTING_DEPTH == 8
    expected_exports = {
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
    }
    assert set(mcp_pkg.__all__) == expected_exports
    assert ALLOWED_MCP_METHODS == (
        "smart_ads.queries.get_ad_performance_v1",
        "smart_ads.queries.get_adset_performance_v1",
        "smart_ads.queries.get_campaign_performance_v1",
        "smart_ads.queries.get_intelligence_findings_v1",
        "smart_ads.reports.generate_recurrent_summary_v1",
    )
    assert tuple(
        sorted(ALLOWED_MCP_METHODS, key=lambda s: s.encode("utf-8"))
    ) == ALLOWED_MCP_METHODS
    assert ALLOWED_FINDING_TYPES == frozenset(
        {"restatement", "saturation", "stalled_delivery", "waste"}
    )

    mcp_py_files = sorted(MCP_PKG_DIR.glob("*.py"))
    assert [p.name for p in mcp_py_files] == [
        "__init__.py",
        "delegation.py",
        "gateway.py",
        "protocol.py",
        "schemas.py",
    ]
    for py_path in mcp_py_files:
        source = py_path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(py_path))
        for node in ast.walk(tree):
            assert not isinstance(node, ast.Assert), f"assert found in {py_path}"
            if isinstance(node, ast.Attribute):
                assert node.attr != "loads", f".loads found in {py_path}"


@pytest.mark.parametrize(
    "bad_input",
    [
        bytearray(b"{}"),
        memoryview(b"{}"),
        "{}",
        None,
        123,
    ],
)
def test_parse_mcp_wire_bytes_rejects_non_bytes_contract_misuse(
    bad_input: object,
) -> None:
    with pytest.raises(ClosedValidationError, match="bytes"):
        parse_mcp_wire_bytes(bad_input)  # type: ignore[arg-type]


def test_body_size_64k_exact_boundary() -> None:
    prefix = b'{"jsonrpc":"2.0","id":1,"method":"x","params":{"p":"'
    suffix = b'"}}'
    filler_len = MAX_MCP_BODY_BYTES - len(prefix) - len(suffix)
    exact_64k = prefix + (b"a" * filler_len) + suffix
    assert len(exact_64k) == 65_536

    parsed = parse_mcp_wire_bytes(exact_64k)
    assert isinstance(parsed, dict)
    assert parsed["id"] == 1
    assert len(parsed["params"]["p"]) == filler_len

    over_64k = prefix + (b"a" * (filler_len + 1)) + suffix
    assert len(over_64k) == 65_537
    assert parse_mcp_wire_bytes(over_64k) == McpProtocolRejection(
        code=-32600,
        message="Invalid Request",
        request_id=None,
        case_id="body_over_64k",
    )

    # Size ceiling precedes UTF-8 decoding
    over_64k_bad_utf8 = b"\xff" * 65_537
    assert parse_mcp_wire_bytes(over_64k_bad_utf8) == McpProtocolRejection(
        code=-32600,
        message="Invalid Request",
        request_id=None,
        case_id="body_over_64k",
    )


@pytest.mark.parametrize(
    "bad_utf8",
    [
        b"\xff\xfe",
        b'{"a":"\xc3"}',
        b"\xc0\xaf",
        b'{"a":"\xed\xa0\x80"}',
    ],
)
def test_invalid_utf8_rejected_as_parse_error(bad_utf8: bytes) -> None:
    rejection = parse_mcp_wire_bytes(bad_utf8)
    assert rejection == McpProtocolRejection(
        code=-32700,
        message="Parse error",
        request_id=None,
        case_id="invalid_utf8",
    )


@pytest.mark.parametrize(
    "malformed_payload",
    [
        b"",
        b"   \t\r\n  ",
        b'{"a":1,"a":',  # truncated after duplicate key -> -32700 wins
        b'{"\\ud800":1',  # truncated after lone surrogate -> -32700 wins
        b"[" * 30_000 + b"INVALID",  # deep unclosed brackets + bad token -> zero RecursionError
        b'{"jsonrpc":"2.0","id":1,"method":"x"} trailing',
        b'{"a":1} {}',
        b"NaN",
        b"Infinity",
        b"-Infinity",
        b'{"a":NaN}',
        b'{"a":Infinity}',
        b'{"a":1,}',
        b"[1,]",
        b"{,}",
        b"[,]",
        b"01",
        b"-01",
        b'{"a":01}',
        b'{"a":-01}',
        b'{"a":1.}',
        b'{"a":1e}',
        b'{"a":+1}',
        b'{"a":"raw\x01ctrl"}',
        b'{"a":"raw\nnewline"}',
        b'{"a":"raw\x00nul"}',
        b'{"a":"\\u12G4"}',
        b'{"a":"\\u123"}',
        b'{"a":"\\x41"}',
        b'{"a":"\\ud800\\u12G4"}',  # high surrogate followed by malformed \u escape -> -32700 wins
        b"[}",
        b'{"a":1]',
        b"\xef\xbb\xbf{}",  # UTF-8 BOM is not RFC 8259 whitespace
        b"\x0c{}",  # form feed is not RFC 8259 whitespace
    ],
)
def test_strict_parse_error_precedence_and_malformed_json(
    malformed_payload: bytes,
) -> None:
    rejection = parse_mcp_wire_bytes(malformed_payload)
    assert rejection == McpProtocolRejection(
        code=-32700,
        message="Parse error",
        request_id=None,
        case_id="malformed_json",
    )


def test_nesting_depth_limits_and_zero_recursion_at_32768() -> None:
    deep_64k = b"[" * 32_768 + b"]" * 32_768
    assert len(deep_64k) == 65_536
    assert parse_mcp_wire_bytes(deep_64k) == McpProtocolRejection(
        code=-32600,
        message="Invalid Request",
        request_id=None,
        case_id="nesting_depth_over_8",
    )

    depth_8_valid = (
        b'{"l2":{"l3":{"l4":{"l5":{"l6":{"l7":{"l8":{"leaf":42}}}}}}}}'
    )
    parsed_8 = parse_mcp_wire_bytes(depth_8_valid)
    assert isinstance(parsed_8, dict)
    assert (
        parsed_8["l2"]["l3"]["l4"]["l5"]["l6"]["l7"]["l8"]["leaf"] == 42
    )

    depth_9_invalid = (
        b'{"l2":{"l3":{"l4":{"l5":{"l6":{"l7":{"l8":{"l9":{"leaf":42}}}}}}}}}'
    )
    assert parse_mcp_wire_bytes(depth_9_invalid) == McpProtocolRejection(
        code=-32600,
        message="Invalid Request",
        request_id=None,
        case_id="nesting_depth_over_8",
    )

    depth_9_empty_obj = (
        b'{"l2":{"l3":{"l4":{"l5":{"l6":{"l7":{"l8":{"l9":{}}}}}}}}}'
    )
    assert parse_mcp_wire_bytes(depth_9_empty_obj) == McpProtocolRejection(
        code=-32600,
        message="Invalid Request",
        request_id=None,
        case_id="nesting_depth_over_8",
    )


def test_duplicate_json_keys_at_root_and_beyond_depth_8() -> None:
    for payload in (
        b'{"a":1,"a":2}',
        b'{"\\u0061":1,"a":2}',
        b'{"a":{"b":{"c":{"d":{"e":{"f":{"g":{"h":{"dup":1,"dup":2}}}}}}}}}',
    ):
        assert parse_mcp_wire_bytes(payload) == McpProtocolRejection(
            code=-32600,
            message="Invalid Request",
            request_id=None,
            case_id="duplicate_json_key",
        )


def test_utf16_surrogates_in_keys_and_values_and_valid_astral_pairs() -> None:
    for lone_in_container in (
        b'{"\\ud800":1}',
        b'{"\\udfff":1}',
        b'{"\\ud800\\u0041":1}',
        b'{"jsonrpc":"2.0","id":"\\ud800","method":"x"}',
        b'{"jsonrpc":"2.0","id":1,"method":"x","params":{"s":"\\udc00"}}',
        b'{"a":{"b":{"c":{"d":{"e":{"f":{"g":{"h":{"s":"\\ud800"}}}}}}}}}',
    ):
        assert parse_mcp_wire_bytes(lone_in_container) == McpProtocolRejection(
            code=-32600,
            message="Invalid Request",
            request_id=None,
            case_id="invalid_jsonrpc_envelope",
        )

    assert parse_mcp_wire_bytes(b'"\\ud800"') == McpProtocolRejection(
        code=-32600,
        message="Invalid Request",
        request_id=None,
        case_id="non_object_request",
    )

    valid_pair = (
        b'{"jsonrpc":"2.0","id":1,"method":"x",'
        b'"params":{"emoji":"\\ud83d\\ude00","esc":"\\"\\\\\\/\\b\\f\\n\\r\\t"}}'
    )
    parsed = parse_mcp_wire_bytes(valid_pair)
    assert isinstance(parsed, dict)
    assert parsed["params"]["emoji"] == "\U0001f600"
    assert parsed["params"]["esc"] == '"\\/\b\f\n\r\t'


@pytest.mark.parametrize(
    "batch_payload",
    [
        b"[]",
        b'[{"jsonrpc":"2.0","id":1,"method":"x"}]',
        b'[{"jsonrpc":"2.0","id":1,"method":"x"},{"jsonrpc":"2.0","id":2,"method":"y"}]',
    ],
)
def test_batch_array_rejected_with_single_error(batch_payload: bytes) -> None:
    assert parse_mcp_wire_bytes(batch_payload) == McpProtocolRejection(
        code=-32600,
        message="Invalid Request",
        request_id=None,
        case_id="batch_array",
    )


@pytest.mark.parametrize(
    "scalar_payload",
    [
        b"123",
        b'"str"',
        b"true",
        b"false",
        b"null",
        b"1.5",
    ],
)
def test_non_object_root_rejected(scalar_payload: bytes) -> None:
    assert parse_mcp_wire_bytes(scalar_payload) == McpProtocolRejection(
        code=-32600,
        message="Invalid Request",
        request_id=None,
        case_id="non_object_request",
    )


def test_rfc8259_exact_and_non_exact_numbers() -> None:
    payload = (
        f'{{"max":{MAX_JCS_SAFE_INT},"min":{MIN_JCS_SAFE_INT},"zero":0,'
        f'"frac":1.5,"exp":1e5,"over":{MAX_JCS_SAFE_INT + 1},'
        f'"under":{MIN_JCS_SAFE_INT - 1},"huge":{"9" * 5000}}}'
    ).encode("utf-8")
    parsed = parse_mcp_wire_bytes(payload)
    assert isinstance(parsed, dict)
    assert parsed["max"] == MAX_JCS_SAFE_INT and type(parsed["max"]) is int
    assert parsed["min"] == MIN_JCS_SAFE_INT and type(parsed["min"]) is int
    assert parsed["zero"] == 0 and type(parsed["zero"]) is int
    assert parsed["frac"] == _NonExactJsonNumber("1.5")
    assert parsed["exp"] == _NonExactJsonNumber("1e5")
    assert parsed["over"] == _NonExactJsonNumber(str(MAX_JCS_SAFE_INT + 1))
    assert parsed["under"] == _NonExactJsonNumber(str(MIN_JCS_SAFE_INT - 1))
    assert parsed["huge"] == _NonExactJsonNumber("9" * 5000)


@pytest.mark.parametrize(
    "valid_id",
    [
        1,
        0,
        -42,
        MAX_JCS_SAFE_INT,
        MIN_JCS_SAFE_INT,
        "req-1",
        "a" * 256,
        "é" * 128,  # 256 UTF-8 bytes
        None,
    ],
)
def test_validate_jsonrpc_request_envelope_accepts_valid_ids(
    valid_id: str | int | None,
) -> None:
    env_no_params = validate_jsonrpc_request_envelope(
        {"jsonrpc": "2.0", "id": valid_id, "method": "smart_ads.queries.get_ad_performance_v1"}
    )
    assert env_no_params == ParsedJsonRpcEnvelope(
        request_id=valid_id,
        method="smart_ads.queries.get_ad_performance_v1",
        has_params=False,
        params_raw=None,
    )

    env_with_params = validate_jsonrpc_request_envelope(
        {
            "jsonrpc": "2.0",
            "id": valid_id,
            "method": "smart_ads.queries.get_ad_performance_v1",
            "params": {"k": "v"},
        }
    )
    assert env_with_params == ParsedJsonRpcEnvelope(
        request_id=valid_id,
        method="smart_ads.queries.get_ad_performance_v1",
        has_params=True,
        params_raw={"k": "v"},
    )


@pytest.mark.parametrize(
    "bad_envelope",
    [
        {"jsonrpc": "2.0", "method": "x"},  # notification (missing id)
        {"id": 1, "method": "x"},  # missing jsonrpc
        {"jsonrpc": "2.0", "id": 1},  # missing method
        {"jsonrpc": "1.0", "id": 1, "method": "x"},
        {"jsonrpc": 2, "id": 1, "method": "x"},
        {"jsonrpc": "2.0", "id": 1, "method": "x", "extra": 1},
        {"jsonrpc": "2.0", "id": True, "method": "x"},
        {"jsonrpc": "2.0", "id": False, "method": "x"},
        {"jsonrpc": "2.0", "id": _NonExactJsonNumber("1.5"), "method": "x"},
        {"jsonrpc": "2.0", "id": _NonExactJsonNumber("1e5"), "method": "x"},
        {"jsonrpc": "2.0", "id": _NonExactJsonNumber("9007199254740992"), "method": "x"},
        {"jsonrpc": "2.0", "id": _NonExactJsonNumber("-9007199254740992"), "method": "x"},
        {"jsonrpc": "2.0", "id": 1.5, "method": "x"},
        {"jsonrpc": "2.0", "id": MAX_JCS_SAFE_INT + 1, "method": "x"},
        {"jsonrpc": "2.0", "id": MIN_JCS_SAFE_INT - 1, "method": "x"},
        {"jsonrpc": "2.0", "id": [], "method": "x"},
        {"jsonrpc": "2.0", "id": {}, "method": "x"},
        {"jsonrpc": "2.0", "id": "", "method": "x"},
        {"jsonrpc": "2.0", "id": "a" * 257, "method": "x"},
        {"jsonrpc": "2.0", "id": "é" * 129, "method": "x"},  # 258 UTF-8 bytes > 256
        {"jsonrpc": "2.0", "id": "req\n1", "method": "x"},
        {"jsonrpc": "2.0", "id": "req\x001", "method": "x"},
        {"jsonrpc": "2.0", "id": "req\x7f1", "method": "x"},
        {"jsonrpc": "2.0", "id": 1, "method": ""},
        {"jsonrpc": "2.0", "id": 1, "method": 123},
        {"jsonrpc": "2.0", "id": 1, "method": None},
        {"jsonrpc": "2.0", "id": 1, "method": "bad\nmethod"},
        {"jsonrpc": "2.0", "id": 1, "method": "bad\x7fmethod"},
    ],
)
def test_validate_jsonrpc_request_envelope_rejects_invalid_envelopes(
    bad_envelope: dict[str, Any],
) -> None:
    assert validate_jsonrpc_request_envelope(bad_envelope) == McpProtocolRejection(
        code=-32600,
        message="Invalid Request",
        request_id=None,
        case_id="invalid_jsonrpc_envelope",
    )


@pytest.mark.parametrize(
    "wire_bad_id",
    [
        b'{"jsonrpc":"2.0","id":1.5,"method":"x"}',
        b'{"jsonrpc":"2.0","id":1e5,"method":"x"}',
        b'{"jsonrpc":"2.0","id":9007199254740992,"method":"x"}',
        b'{"jsonrpc":"2.0","id":-9007199254740992,"method":"x"}',
    ],
)
def test_wire_non_exact_id_parsed_then_rejected_as_invalid_request(
    wire_bad_id: bytes,
) -> None:
    parsed = parse_mcp_wire_bytes(wire_bad_id)
    assert isinstance(parsed, dict)
    assert validate_jsonrpc_request_envelope(parsed) == McpProtocolRejection(
        code=-32600,
        message="Invalid Request",
        request_id=None,
        case_id="invalid_jsonrpc_envelope",
    )


def test_wire_serialization_and_contract_guards() -> None:
    rej_null = McpProtocolRejection(
        code=-32600,
        message="Invalid Request",
        request_id=None,
        case_id="body_over_64k",
    )
    assert rej_null.to_dict() == {
        "jsonrpc": "2.0",
        "id": None,
        "error": {"code": -32600, "message": "Invalid Request"},
    }
    assert (
        rej_null.to_wire_bytes()
        == b'{"error":{"code":-32600,"message":"Invalid Request"},"id":null,"jsonrpc":"2.0"}'
    )

    rej_with_id = McpProtocolRejection(
        code=-32601,
        message="Method not found",
        request_id="req-99",
        case_id="unsupported_method",
    )
    assert (
        rej_with_id.to_wire_bytes()
        == b'{"error":{"code":-32601,"message":"Method not found"},"id":"req-99","jsonrpc":"2.0"}'
    )

    assert (
        serialize_jsonrpc_result("req-1", {"ok": True, "count": 2})
        == b'{"id":"req-1","jsonrpc":"2.0","result":{"count":2,"ok":true}}'
    )

    with pytest.raises(ClosedValidationError):
        validate_jsonrpc_request_envelope([])  # type: ignore[arg-type]
    with pytest.raises(ClosedValidationError):
        serialize_jsonrpc_result(True, {"ok": True})  # type: ignore[arg-type]
    with pytest.raises(ClosedValidationError):
        serialize_jsonrpc_result("req-1", [1, 2])  # type: ignore[arg-type]


@dataclass
class _AdapterSpy:
    name: str
    calls: int = 0

    def touch(self) -> None:
        self.calls += 1


class _SixAdapterIOSpyRig:
    """Spy harness tracking all 6 ADR-0001 §3.3 external I/O adapter surfaces."""

    def __init__(self) -> None:
        self.registry = _AdapterSpy("registry")
        self.audit = _AdapterSpy("audit")
        self.filesystem = _AdapterSpy("filesystem")
        self.credential = _AdapterSpy("credential")
        self.provider = _AdapterSpy("provider")
        self.network = _AdapterSpy("network")

    def counters(self) -> dict[str, int]:
        return {
            "audit_calls": self.audit.calls,
            "credential_calls": self.credential.calls,
            "filesystem_calls": self.filesystem.calls,
            "network_calls": self.network.calls,
            "provider_calls": self.provider.calls,
            "registry_calls": self.registry.calls,
        }


class _SpyMcpReadHandler:
    """Post-admission MCP read handler wired to the 6 external I/O spies."""

    def __init__(self, rig: _SixAdapterIOSpyRig) -> None:
        self._rig = rig
        self.admitted_requests: list[AdmittedMcpRequest] = []

    def handle(self, request: AdmittedMcpRequest) -> Mapping[str, Any]:
        self.admitted_requests.append(request)
        self._rig.registry.touch()
        self._rig.audit.touch()
        self._rig.filesystem.touch()
        self._rig.credential.touch()
        self._rig.provider.touch()
        self._rig.network.touch()
        return {"rows": [], "method": request.method}


def _make_valid_runtime_context(
    *,
    allowed_method: str = "smart_ads.queries.get_campaign_performance_v1",
    route: str = "/ibvi-ads",
    tenant_ref: str = "tenant:ibvi",
    binding_ref: str = "binding:meta-1",
    resource_scope_ref: str = "scope:ibvi-1",
    clock_lower_utc: str = "2026-11-12T12:01:00Z",
    clock_upper_utc: str = "2026-11-12T12:01:02Z",
) -> McpRuntimeContext:
    locator = ArtifactLocator.from_digest(
        "smart_ads/ibvi_ads_delegation_context/v1",
        "sha256:" + ("a" * 64),
    )
    delegation = McpDelegationContext(
        schema="smart_ads/ibvi_ads_delegation_context/v1",
        route=route,
        host_conductor_ref="conductor:hermes-prod",
        front_ref="front:pinna",
        profile_ref="profile:pinna-ops",
        tenant_ref=tenant_ref,
        binding_ref=binding_ref,
        resource_scope_ref=resource_scope_ref,
        allowed_method=allowed_method,
        policy_digest="sha256:" + ("b" * 64),
        issued_at_utc="2026-11-12T12:00:00Z",
        valid_until_utc="2026-11-12T12:15:00Z",
        nonce="nonce-gov1-001",
        locator=locator,
    )
    return McpRuntimeContext(
        clock_lower_utc=clock_lower_utc,
        clock_upper_utc=clock_upper_utc,
        delegation_context=delegation,
    )


def _canonical_resource_ref_for_index(idx: int) -> str:
    raw_32 = idx.to_bytes(32, "big")
    encoded = base64.b32encode(raw_32).decode("ascii").rstrip("=").lower()
    ref = f"resource:{encoded}"
    return validate_resource_ref(ref)


def test_adr0001_section_3_3_eleven_case_rejection_matrix_zero_io() -> None:
    zero_counters = {
        "audit_calls": 0,
        "credential_calls": 0,
        "filesystem_calls": 0,
        "network_calls": 0,
        "provider_calls": 0,
        "registry_calls": 0,
    }
    valid_rt = _make_valid_runtime_context()

    over_64k_prefix = (
        b'{"jsonrpc":"2.0","id":"req-must-not-echo","method":'
        b'"smart_ads.queries.get_campaign_performance_v1","params":{"pad":"'
    )
    over_64k_suffix = b'"}}'
    over_64k_body = (
        over_64k_prefix
        + (b"x" * (MAX_MCP_BODY_BYTES + 1 - len(over_64k_prefix) - len(over_64k_suffix)))
        + over_64k_suffix
    )
    assert len(over_64k_body) == 65_537

    # Exact 11 normative rows in ADR-0001 §3.3 L235-245:
    matrix_cases: list[
        tuple[
            str,
            bytes,
            McpRuntimeContext | None,
            int,
            str,
            str | int | None,
        ]
    ] = [
        (
            "body_over_64k",
            over_64k_body,
            valid_rt,
            -32600,
            "Invalid Request",
            None,
        ),
        (
            "invalid_utf8",
            b'{"jsonrpc":"2.0","id":"req-utf8","bad":"\xff\xfe"}',
            valid_rt,
            -32700,
            "Parse error",
            None,
        ),
        (
            "malformed_json",
            b'{"jsonrpc":"2.0","id":"req-trunc","method":',
            valid_rt,
            -32700,
            "Parse error",
            None,
        ),
        (
            "duplicate_json_key",
            b'{"jsonrpc":"2.0","id":"req-dup","id":"req-dup-2","method":"smart_ads.queries.get_campaign_performance_v1"}',
            valid_rt,
            -32600,
            "Invalid Request",
            None,
        ),
        (
            "nesting_depth_over_8",
            b'{"jsonrpc":"2.0","id":"req-deep","method":"smart_ads.queries.get_campaign_performance_v1","params":{"l3":{"l4":{"l5":{"l6":{"l7":{"l8":{"l9":{"leaf":1}}}}}}}}}',
            valid_rt,
            -32600,
            "Invalid Request",
            None,
        ),
        (
            "batch_array",
            b'[{"jsonrpc":"2.0","id":"req-batch-1","method":"smart_ads.queries.get_campaign_performance_v1"}]',
            valid_rt,
            -32600,
            "Invalid Request",
            None,
        ),
        (
            "non_object_request",
            b'"scalar-secret-do-not-echo"',
            valid_rt,
            -32600,
            "Invalid Request",
            None,
        ),
        (
            "unsupported_method",
            canonicalize_jcs(
                {
                    "jsonrpc": "2.0",
                    "id": "req-unsupported-8",
                    "method": "smart_ads.mutations.update_budget_v1",
                    "params": {},
                }
            ),
            valid_rt,
            -32601,
            "Method not found",
            "req-unsupported-8",
        ),
        (
            "invalid_params",
            canonicalize_jcs(
                {
                    "jsonrpc": "2.0",
                    "id": 909,
                    "method": "smart_ads.queries.get_campaign_performance_v1",
                    "params": {
                        "tenant_ref": "raw-secret-account-12345",
                        "binding_ref": "binding:meta-1",
                        "resource_scope_ref": "scope:ibvi-1",
                        "date_range": {
                            "start_date": "2026-11-10",
                            "end_date": "2026-11-01",
                        },
                    },
                }
            ),
            valid_rt,
            -32602,
            "Invalid params",
            909,
        ),
        (
            "additional_property",
            canonicalize_jcs(
                {
                    "jsonrpc": "2.0",
                    "id": "req-addprop-10",
                    "method": "smart_ads.queries.get_campaign_performance_v1",
                    "params": {
                        "tenant_ref": "tenant:ibvi",
                        "binding_ref": "binding:meta-1",
                        "resource_scope_ref": "scope:ibvi-1",
                        "date_range": {
                            "start_date": "2026-11-01",
                            "end_date": "2026-11-10",
                        },
                        "file_path": "/etc/passwd",
                    },
                }
            ),
            valid_rt,
            -32602,
            "Invalid params",
            "req-addprop-10",
        ),
        (
            "missing_or_invalid_ibvi_ads_delegation",
            canonicalize_jcs(
                {
                    "jsonrpc": "2.0",
                    "id": "req-deleg-11",
                    "method": "smart_ads.queries.get_campaign_performance_v1",
                    "params": {
                        "tenant_ref": "tenant:ibvi",
                        "binding_ref": "binding:meta-1",
                        "resource_scope_ref": "scope:ibvi-1",
                        "date_range": {
                            "start_date": "2026-11-01",
                            "end_date": "2026-11-10",
                        },
                    },
                }
            ),
            _make_valid_runtime_context(route="/ads"),
            -32600,
            "Invalid Request",
            "req-deleg-11",
        ),
    ]

    observed_case_ids: list[str] = []
    for (
        expected_case_id,
        raw_body,
        rt_ctx,
        expected_code,
        expected_message,
        expected_id,
    ) in matrix_cases:
        rig = _SixAdapterIOSpyRig()
        spy_handler = _SpyMcpReadHandler(rig)
        assert isinstance(spy_handler, McpReadHandlerPort)

        outcome = handle_mcp_request_bytes(
            raw_body, rt_ctx, handler=spy_handler
        )
        assert isinstance(outcome, McpWireOutcome)
        assert outcome.admitted_request is None
        assert outcome.rejection is not None
        assert outcome.rejection.case_id == expected_case_id
        assert outcome.rejection.code == expected_code
        assert outcome.rejection.message == expected_message
        assert outcome.rejection.request_id == expected_id
        assert spy_handler.admitted_requests == []
        assert rig.counters() == zero_counters

        decoded_wire = loads_strict_json(outcome.wire_bytes)
        assert set(decoded_wire.keys()) == {"jsonrpc", "id", "error"}
        assert decoded_wire["jsonrpc"] == "2.0"
        assert decoded_wire["id"] == expected_id
        assert set(decoded_wire["error"].keys()) == {"code", "message"}
        assert decoded_wire["error"] == {
            "code": expected_code,
            "message": expected_message,
        }
        assert outcome.wire_bytes == canonicalize_jcs(decoded_wire)
        assert b"/etc/passwd" not in outcome.wire_bytes
        assert b"scalar-secret" not in outcome.wire_bytes
        assert b"raw-secret" not in outcome.wire_bytes
        observed_case_ids.append(outcome.rejection.case_id)

    assert sorted(observed_case_ids, key=lambda s: s.encode("utf-8")) == [
        "additional_property",
        "batch_array",
        "body_over_64k",
        "duplicate_json_key",
        "invalid_params",
        "invalid_utf8",
        "malformed_json",
        "missing_or_invalid_ibvi_ads_delegation",
        "nesting_depth_over_8",
        "non_object_request",
        "unsupported_method",
    ]
    assert len(set(observed_case_ids)) == 11


def test_gateway_accepts_exact_65536_bytes_and_dispatches_to_handler() -> None:
    resource_refs = sorted(
        (_canonical_resource_ref_for_index(i) for i in range(1, 1019)),
        key=lambda s: s.encode("utf-8"),
    )
    base_envelope: dict[str, Any] = {
        "jsonrpc": "2.0",
        "id": "req-",
        "method": "smart_ads.queries.get_campaign_performance_v1",
        "params": {
            "tenant_ref": "tenant:ibvi",
            "binding_ref": "binding:meta-1",
            "resource_scope_ref": "scope:ibvi-1",
            "date_range": {
                "start_date": "2026-11-01",
                "end_date": "2026-11-10",
            },
            "resource_refs": resource_refs,
        },
    }
    base_len = len(canonicalize_jcs(base_envelope))
    delta = MAX_MCP_BODY_BYTES - base_len
    assert 1 <= delta <= 250
    exact_id = "req-" + ("z" * delta)
    base_envelope["id"] = exact_id

    exact_64k_body = canonicalize_jcs(base_envelope)
    assert len(exact_64k_body) == 65_536

    rig = _SixAdapterIOSpyRig()
    spy_handler = _SpyMcpReadHandler(rig)
    valid_rt = _make_valid_runtime_context()

    outcome_ok = handle_mcp_request_bytes(
        exact_64k_body, valid_rt, handler=spy_handler
    )
    assert outcome_ok.rejection is None
    assert outcome_ok.admitted_request is not None
    assert outcome_ok.admitted_request.request_id == exact_id
    assert isinstance(outcome_ok.admitted_request.params, PerformanceQueryParams)
    assert outcome_ok.admitted_request.params.resource_refs == tuple(resource_refs)
    assert len(spy_handler.admitted_requests) == 1
    assert loads_strict_json(outcome_ok.wire_bytes) == {
        "jsonrpc": "2.0",
        "id": exact_id,
        "result": {
            "rows": [],
            "method": "smart_ads.queries.get_campaign_performance_v1",
        },
    }

    # Adding 1 byte -> 65,537 bytes -> rejected before any I/O or handler invocation
    base_envelope["id"] = exact_id + "x"
    over_64k_body = canonicalize_jcs(base_envelope)
    assert len(over_64k_body) == 65_537

    rig_over = _SixAdapterIOSpyRig()
    spy_over = _SpyMcpReadHandler(rig_over)
    outcome_over = handle_mcp_request_bytes(
        over_64k_body, valid_rt, handler=spy_over
    )
    assert outcome_over.admitted_request is None
    assert outcome_over.rejection == McpProtocolRejection(
        code=-32600,
        message="Invalid Request",
        request_id=None,
        case_id="body_over_64k",
    )
    assert spy_over.admitted_requests == []
    assert rig_over.counters() == {
        "audit_calls": 0,
        "credential_calls": 0,
        "filesystem_calls": 0,
        "network_calls": 0,
        "provider_calls": 0,
        "registry_calls": 0,
    }
