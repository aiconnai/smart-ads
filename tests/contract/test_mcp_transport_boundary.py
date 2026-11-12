"""Contract tests for zero-recursion MCP JSON-RPC 2.0 wire parser (ADR-0001 §3.3)."""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from smart_ads.contracts import (
    MAX_JCS_SAFE_INT,
    MIN_JCS_SAFE_INT,
    ClosedValidationError,
)
import smart_ads.transports.mcp as mcp_pkg
from smart_ads.transports.mcp import (
    MAX_MCP_BODY_BYTES,
    MAX_MCP_NESTING_DEPTH,
    McpProtocolRejection,
    ParsedJsonRpcEnvelope,
    parse_mcp_wire_bytes,
    serialize_jsonrpc_result,
    validate_jsonrpc_request_envelope,
)
from smart_ads.transports.mcp.protocol import _NonExactJsonNumber

REPO_ROOT = Path(__file__).resolve().parents[2]
PROTOCOL_PATH = (
    REPO_ROOT / "src" / "smart_ads" / "transports" / "mcp" / "protocol.py"
)


def test_mcp_package_constants_exports_and_no_json_loads() -> None:
    assert MAX_MCP_BODY_BYTES == 65_536
    assert MAX_MCP_NESTING_DEPTH == 8
    expected_exports = {
        "JsonRpcRequestId",
        "MAX_MCP_BODY_BYTES",
        "MAX_MCP_NESTING_DEPTH",
        "McpProtocolRejection",
        "McpRejectionCaseId",
        "ParsedJsonRpcEnvelope",
        "parse_mcp_wire_bytes",
        "serialize_jsonrpc_result",
        "validate_jsonrpc_request_envelope",
    }
    assert set(mcp_pkg.__all__) == expected_exports

    source = PROTOCOL_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(PROTOCOL_PATH))
    for node in ast.walk(tree):
        assert not isinstance(node, ast.Assert)
        if isinstance(node, ast.Attribute):
            assert node.attr != "loads"


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
