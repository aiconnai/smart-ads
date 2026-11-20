"""Unit tests for strict zero-I/O Pipeboard wire request, JSON decoder, and 9-step envelope parser."""
from __future__ import annotations

import ast
from collections.abc import Iterator
import json
from pathlib import Path
import traceback
from typing import Any

import pytest

from smart_ads.adapters.pipeboard import (
    adapter as adapter_mod,
    reducer as reducer_mod,
    wire as wire_mod,
)
from smart_ads.adapters.pipeboard.wire import (
    DEFAULT_PIPEBOARD_TRANSPORT_LIMITS,
    STATIC_DETAIL_BY_CODE,
    ParsedPipeboardEnvelope,
    PipeboardAdapterError,
    PipeboardWireRejection,
    _WireDecimalToken,
    _WireOutOfRangeInt,
    build_pipeboard_insights_request,
    loads_pipeboard_wire_json,
    parse_pipeboard_http_and_mcp_envelope,
    parse_pipeboard_mcp_result,
)
from smart_ads.contracts import ClosedValidationError, TransportOutcome
from smart_ads.domain import FORBIDDEN_PIPEBOARD_ARGUMENTS, PipeboardTransportLimits

SECRET_SENTINEL = "SECRET_WIRE_CANARY_987654321"
JSON_HEADERS: tuple[tuple[str, str], ...] = (("Content-Type", "application/json"),)


def _clean_outcome(**overrides: Any) -> TransportOutcome:
    base: dict[str, Any] = {
        "network_ok": True,
        "http_status": 200,
        "media_and_encoding_valid": True,
        "auth_ok": True,
        "jsonrpc_error": False,
        "payload_schema_valid": True,
        "response_date_mismatch": False,
        "truncated_2mib": False,
        "non_empty_continuation": False,
        "reducer_order_or_count_mismatch": False,
        "duplicate_provider_observation": False,
    }
    base.update(overrides)
    return TransportOutcome(**base)


def _mcp_outer_bytes(
    inner_obj: Any,
    *,
    is_error: Any = None,
    include_is_error: bool = False,
) -> bytes:
    inner_text = (
        inner_obj
        if isinstance(inner_obj, str)
        else json.dumps(inner_obj, separators=(",", ":"))
    )
    result: dict[str, Any] = {"content": [{"type": "text", "text": inner_text}]}
    if include_is_error:
        result["isError"] = is_error
    outer = {"jsonrpc": "2.0", "id": 1, "result": result}
    return json.dumps(outer, separators=(",", ":")).encode("utf-8")


def _assert_value_silent(exc: BaseException) -> None:
    assert isinstance(exc, ClosedValidationError)
    assert isinstance(exc, PipeboardAdapterError)
    assert exc.__cause__ is None
    assert exc.__suppress_context__ is True
    formatted = "".join(traceback.format_exception(exc))
    assert SECRET_SENTINEL not in str(exc)
    assert SECRET_SENTINEL not in repr(exc)
    assert SECRET_SENTINEL not in formatted


BAD_REQUEST_INPUTS: tuple[tuple[Any, Any, Any], ...] = (
    (f"123456_{SECRET_SENTINEL}", "2026-11-10", DEFAULT_PIPEBOARD_TRANSPORT_LIMITS),
    ("act_0123456", "2026-11-10", DEFAULT_PIPEBOARD_TRANSPORT_LIMITS),
    ("act_12345", "2026-11-10", DEFAULT_PIPEBOARD_TRANSPORT_LIMITS),
    ("act_" + ("1" * 33), "2026-11-10", DEFAULT_PIPEBOARD_TRANSPORT_LIMITS),
    (123456, "2026-11-10", DEFAULT_PIPEBOARD_TRANSPORT_LIMITS),
    ("act_123456", f"2026-02-30-{SECRET_SENTINEL}", DEFAULT_PIPEBOARD_TRANSPORT_LIMITS),
    ("act_123456", 20261110, DEFAULT_PIPEBOARD_TRANSPORT_LIMITS),
    ("act_123456", "2026-11-10", "not-limits"),
)

BAD_WIRE_JSON_INPUTS: tuple[str, ...] = (
    "",
    "   \r\n\t ",
    f'{{"a": 1, "a": "{SECRET_SENTINEL}"}}',
    '{"outer": {"dup": 1, "dup": 2}}',
    '{"cpc": ' + ("9" * 65) + "}",
    '{"cpc": ' + ("1" * 4301) + "}",
    '{"cpc": 1e101}',
    '{"cpc": 1e-101}',
    '{"cpc": 0E+101}',
    "NaN",
    "Infinity",
    "-Infinity",
    "01",
    "-01",
    "+1",
    "1.",
    ".5",
    "1e",
    "1e+",
    '"\\uD800"',
    '"\\uDC00"',
    '"\\uD800\\u0041"',
    '"\\uD800x"',
    '"\ud800"',
    '"unterminated',
    '"bad\nescape"',
    '"bad\x00nul"',
    '"\\x41"',
    "{} {}",
    "[1,]",
    '{"a":1,}',
    "\u00a0{}",
)

STEPS_1_TO_7_CASES: tuple[tuple[dict[str, Any], str, str, TransportOutcome], ...] = (
    (
        {"network_ok": False, "http_status": 500, "headers": (), "body_chunks": ()},
        "network_error",
        "network",
        _clean_outcome(network_ok=False, http_status=None),
    ),
    (
        {"network_ok": True, "http_status": None, "headers": JSON_HEADERS, "body_chunks": ()},
        "missing_http_status",
        "transport",
        _clean_outcome(http_status=None),
    ),
    (
        {"network_ok": True, "http_status": 99, "headers": JSON_HEADERS, "body_chunks": ()},
        "invalid_http_status",
        "transport",
        _clean_outcome(http_status=None),
    ),
    (
        {"network_ok": True, "http_status": 1000, "headers": JSON_HEADERS, "body_chunks": ()},
        "invalid_http_status",
        "transport",
        _clean_outcome(http_status=None),
    ),
    (
        {"network_ok": True, "http_status": True, "headers": JSON_HEADERS, "body_chunks": ()},
        "invalid_http_status",
        "transport",
        _clean_outcome(http_status=None),
    ),
    (
        {"network_ok": True, "http_status": 401, "headers": (), "body_chunks": ()},
        "http_auth_error",
        "auth",
        _clean_outcome(http_status=401, auth_ok=False),
    ),
    (
        {"network_ok": True, "http_status": 403, "headers": (), "body_chunks": ()},
        "http_auth_error",
        "auth",
        _clean_outcome(http_status=403, auth_ok=False),
    ),
    (
        {"network_ok": True, "http_status": 201, "headers": (), "body_chunks": ()},
        "http_status_not_200",
        "transport",
        _clean_outcome(http_status=201),
    ),
    (
        {"network_ok": True, "http_status": 503, "headers": (), "body_chunks": ()},
        "http_status_not_200",
        "transport",
        _clean_outcome(http_status=503),
    ),
    (
        {
            "network_ok": True,
            "http_status": 200,
            "headers": (("Bad Header", SECRET_SENTINEL),),
            "body_chunks": (),
        },
        "malformed_http_headers",
        "transport",
        _clean_outcome(media_and_encoding_valid=False),
    ),
    (
        {
            "network_ok": True,
            "http_status": 200,
            "headers": (("Content-Type", f"application/json\r\nX:{SECRET_SENTINEL}"),),
            "body_chunks": (),
        },
        "malformed_http_headers",
        "transport",
        _clean_outcome(media_and_encoding_valid=False),
    ),
    (
        {
            "network_ok": True,
            "http_status": 200,
            "headers": (
                ("Content-Type", "application/json"),
                ("content-type", "application/json"),
            ),
            "body_chunks": (),
        },
        "duplicate_http_header",
        "transport",
        _clean_outcome(media_and_encoding_valid=False),
    ),
    (
        {
            "network_ok": True,
            "http_status": 200,
            "headers": (("Content-Type", "text/event-stream"),),
            "body_chunks": (),
        },
        "invalid_content_type",
        "transport",
        _clean_outcome(media_and_encoding_valid=False),
    ),
    (
        {
            "network_ok": True,
            "http_status": 200,
            "headers": (
                ("Content-Type", "application/json"),
                ("Content-Encoding", "gzip"),
            ),
            "body_chunks": (),
        },
        "forbidden_content_encoding",
        "transport",
        _clean_outcome(media_and_encoding_valid=False),
    ),
    (
        {
            "network_ok": True,
            "http_status": 200,
            "headers": (
                ("Content-Type", "application/json"),
                ("Content-Length", "00"),
            ),
            "body_chunks": (),
        },
        "invalid_content_length",
        "transport",
        _clean_outcome(media_and_encoding_valid=False),
    ),
    (
        {
            "network_ok": True,
            "http_status": 200,
            "headers": JSON_HEADERS,
            "body_chunks": [b"x" * 3_000_000],
        },
        "stream_over_2mib",
        "truncation",
        _clean_outcome(truncated_2mib=True),
    ),
    (
        {
            "network_ok": True,
            "http_status": 200,
            "headers": (
                ("Content-Type", "application/json"),
                ("Content-Length", "10"),
            ),
            "body_chunks": [b"{}"],
        },
        "content_length_mismatch",
        "transport",
        _clean_outcome(media_and_encoding_valid=False),
    ),
)

STEPS_8_AND_9_CASES: tuple[tuple[bytes, str, str, TransportOutcome], ...] = (
    (
        b"\xff\xfe",
        "invalid_outer_json",
        "schema",
        _clean_outcome(payload_schema_valid=False),
    ),
    (
        b'{"jsonrpc":"2.0","id":1,"result":{"x":' + (b"9" * 70) + b"}}",
        "invalid_outer_json",
        "schema",
        _clean_outcome(payload_schema_valid=False),
    ),
    (
        b'[{"jsonrpc":"2.0","id":1,"result":{}}]',
        "invalid_jsonrpc_envelope",
        "schema",
        _clean_outcome(payload_schema_valid=False),
    ),
    (
        b'{"jsonrpc":"2.0","id":true,"result":{"content":[]}}',
        "invalid_jsonrpc_envelope",
        "schema",
        _clean_outcome(payload_schema_valid=False),
    ),
    (
        b'{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":1,"message":"m"}}',
        "invalid_jsonrpc_envelope",
        "schema",
        _clean_outcome(payload_schema_valid=False),
    ),
    (
        b'{"jsonrpc":"2.0","id":1,"error":{"code":true,"message":"bad"}}',
        "malformed_jsonrpc_error",
        "schema",
        _clean_outcome(payload_schema_valid=False),
    ),
    (
        b'{"jsonrpc":"2.0","id":1,"error":{"code":1,"message":"m","extra":1}}',
        "malformed_jsonrpc_error",
        "schema",
        _clean_outcome(payload_schema_valid=False),
    ),
    (
        f'{{"jsonrpc":"2.0","id":1,"error":{{"code":-32000,"message":"{SECRET_SENTINEL}","data":{{"d":1.5}}}}}}'.encode(
            "utf-8"
        ),
        "jsonrpc_error_response",
        "jsonrpc",
        _clean_outcome(jsonrpc_error=True),
    ),
    (
        _mcp_outer_bytes({"data": []}, is_error=True, include_is_error=True),
        "mcp_result_is_error",
        "schema",
        _clean_outcome(payload_schema_valid=False),
    ),
    (
        _mcp_outer_bytes({"data": []}, is_error="false", include_is_error=True),
        "invalid_mcp_content",
        "schema",
        _clean_outcome(payload_schema_valid=False),
    ),
    (
        b'{"jsonrpc":"2.0","id":1,"result":{"content":[]}}',
        "invalid_mcp_content",
        "schema",
        _clean_outcome(payload_schema_valid=False),
    ),
    (
        _mcp_outer_bytes('{"data": [{"cpc": ' + ("9" * 4301) + "}]}",),
        "invalid_inner_json",
        "schema",
        _clean_outcome(payload_schema_valid=False),
    ),
    (
        _mcp_outer_bytes('{"data": [{"cpc": 1e101}]}'),
        "invalid_inner_json",
        "schema",
        _clean_outcome(payload_schema_valid=False),
    ),
    (
        _mcp_outer_bytes({"data": "not-a-list"}),
        "invalid_payload_shape",
        "schema",
        _clean_outcome(payload_schema_valid=False),
    ),
    (
        _mcp_outer_bytes({"data": [], "extra": SECRET_SENTINEL}),
        "invalid_payload_shape",
        "schema",
        _clean_outcome(payload_schema_valid=False),
    ),
    (
        _mcp_outer_bytes({"data": [], "paging": None}),
        "invalid_paging_shape",
        "schema",
        _clean_outcome(payload_schema_valid=False),
    ),
    (
        _mcp_outer_bytes({"data": [], "paging": {"cursors": None}}),
        "invalid_paging_shape",
        "schema",
        _clean_outcome(payload_schema_valid=False),
    ),
    (
        _mcp_outer_bytes({"data": [], "paging": {"cursors": {"before": 123}}}),
        "invalid_paging_shape",
        "schema",
        _clean_outcome(payload_schema_valid=False),
    ),
    (
        _mcp_outer_bytes({"data": [], "paging": {"next": 123}}),
        "invalid_paging_shape",
        "schema",
        _clean_outcome(payload_schema_valid=False),
    ),
    (
        _mcp_outer_bytes(
            {"data": [], "paging": {"next": f"https://example/{SECRET_SENTINEL}"}}
        ),
        "non_empty_paging_next",
        "pagination",
        _clean_outcome(non_empty_continuation=True),
    ),
    (
        _mcp_outer_bytes(
            {"data": [], "paging": {"previous": f"https://example/{SECRET_SENTINEL}"}}
        ),
        "non_empty_paging_previous",
        "pagination",
        _clean_outcome(non_empty_continuation=True),
    ),
    (
        _mcp_outer_bytes(
            {"data": None, "paging": {"next": f"https://example/{SECRET_SENTINEL}"}}
        ),
        "non_empty_paging_next",
        "pagination",
        _clean_outcome(non_empty_continuation=True),
    ),
    (
        _mcp_outer_bytes(
            {"data": None, "paging": {"previous": f"https://example/{SECRET_SENTINEL}"}}
        ),
        "non_empty_paging_previous",
        "pagination",
        _clean_outcome(non_empty_continuation=True),
    ),
    (
        _mcp_outer_bytes({"data": None, "paging": {"next": ""}}),
        "invalid_payload_shape",
        "schema",
        _clean_outcome(payload_schema_valid=False),
    ),
    (
        _mcp_outer_bytes({"data": [{} for _ in range(101)]}),
        "too_many_campaign_rows",
        "schema",
        _clean_outcome(payload_schema_valid=False),
    ),
)


def test_wire_module_contains_zero_float_references_in_ast() -> None:
    wire_path = Path(wire_mod.__file__).resolve()
    tree = ast.parse(wire_path.read_text(encoding="utf-8"), filename=str(wire_path))
    float_nodes = [
        node
        for node in ast.walk(tree)
        if (isinstance(node, ast.Name) and node.id == "float")
        or (isinstance(node, ast.Constant) and isinstance(node.value, float))
    ]
    assert float_nodes == []


def test_build_pipeboard_insights_request_valid_and_forbidden_keys() -> None:
    req = build_pipeboard_insights_request(
        private_object_id="act_123456",
        admitted_day="2026-11-10",
    )
    assert req == {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "get_insights",
            "arguments": {
                "object_id": "act_123456",
                "time_range": {"since": "2026-11-10", "until": "2026-11-10"},
                "level": "campaign",
                "limit": 100,
                "compact": True,
            },
        },
    }
    args = req["params"]["arguments"]
    assert set(args.keys()).isdisjoint(FORBIDDEN_PIPEBOARD_ARGUMENTS)
    max_id = "act_" + ("9" * 32)
    req_max = build_pipeboard_insights_request(
        private_object_id=max_id,
        admitted_day="2026-11-10",
        transport_limits=PipeboardTransportLimits(),
    )
    assert req_max["params"]["arguments"]["object_id"] == max_id


@pytest.mark.parametrize(("bad_object_id", "bad_day", "bad_limits"), BAD_REQUEST_INPUTS)
def test_build_pipeboard_insights_request_rejects_bad_inputs_silently(
    bad_object_id: Any, bad_day: Any, bad_limits: Any
) -> None:
    with pytest.raises(PipeboardAdapterError) as exc_info:
        build_pipeboard_insights_request(
            private_object_id=bad_object_id,
            admitted_day=bad_day,
            transport_limits=bad_limits,
        )
    _assert_value_silent(exc_info.value)


def test_loads_pipeboard_wire_json_numeric_tokens_and_surrogate_pairs() -> None:
    raw = (
        '{"neg_zero":-0,"zero":0,"max_i64":9223372036854775807,'
        '"min_i64":-9223372036854775808,"over_i64":9223372036854775808,'
        '"under_i64":-9223372036854775809,"dec":12.34,"exp":1e100,'
        '"neg_exp":-2.5E-100,"emoji":"\\uD83D\\uDE00","escapes":"\\"\\\\\\/\\b\\f\\n\\r\\t"}'
    )
    parsed = loads_pipeboard_wire_json(raw)
    assert type(parsed["neg_zero"]) is int and parsed["neg_zero"] == 0
    assert type(parsed["zero"]) is int and parsed["zero"] == 0
    assert type(parsed["max_i64"]) is int and parsed["max_i64"] == (1 << 63) - 1
    assert type(parsed["min_i64"]) is int and parsed["min_i64"] == -(1 << 63)
    assert parsed["over_i64"] == _WireOutOfRangeInt(raw="9223372036854775808")
    assert parsed["under_i64"] == _WireOutOfRangeInt(raw="-9223372036854775809")
    assert not isinstance(parsed["over_i64"], int)
    assert parsed["dec"] == _WireDecimalToken(raw="12.34")
    assert parsed["exp"] == _WireDecimalToken(raw="1e100")
    assert parsed["neg_exp"] == _WireDecimalToken(raw="-2.5E-100")
    assert parsed["emoji"] == "\U0001f600"
    assert parsed["escapes"] == '"\\/\b\f\n\r\t'


def test_loads_pipeboard_wire_json_depth_bounds() -> None:
    nested_16_arr = ("[" * 16) + "1" + ("]" * 16)
    nested_17_arr = ("[" * 17) + "1" + ("]" * 17)
    assert isinstance(loads_pipeboard_wire_json(nested_16_arr, max_depth=16), list)
    with pytest.raises(PipeboardAdapterError) as exc_arr:
        loads_pipeboard_wire_json(nested_17_arr, max_depth=16)
    assert exc_arr.value.code == "invalid_wire_json"

    nested_16_obj = '{"a":' * 16 + '"ok"' + "}" * 16
    nested_17_obj = '{"a":' * 17 + '"ok"' + "}" * 17
    assert isinstance(loads_pipeboard_wire_json(nested_16_obj, max_depth=16), dict)
    with pytest.raises(PipeboardAdapterError):
        loads_pipeboard_wire_json(nested_17_obj, max_depth=16)

    assert loads_pipeboard_wire_json('[1, "x", true, false, null]', max_depth=1) == [
        1,
        "x",
        True,
        False,
        None,
    ]
    with pytest.raises(PipeboardAdapterError):
        loads_pipeboard_wire_json("[[]]", max_depth=1)
    with pytest.raises(PipeboardAdapterError):
        loads_pipeboard_wire_json('{"a":{}}', max_depth=1)


@pytest.mark.parametrize("bad_json", BAD_WIRE_JSON_INPUTS)
def test_loads_pipeboard_wire_json_rejects_invalid_tokens_silently(
    bad_json: str,
) -> None:
    with pytest.raises(PipeboardAdapterError) as exc_info:
        loads_pipeboard_wire_json(bad_json)
    assert exc_info.value.code == "invalid_wire_json"
    _assert_value_silent(exc_info.value)


@pytest.mark.parametrize(
    ("raw_arg", "depth_arg"),
    [(b"{}", 16), (None, 16), ("{}", 0), ("{}", -1), ("{}", True), ("{}", "16")],
)
def test_loads_pipeboard_wire_json_preconditions(raw_arg: Any, depth_arg: Any) -> None:
    with pytest.raises(PipeboardAdapterError) as exc_info:
        loads_pipeboard_wire_json(raw_arg, max_depth=depth_arg)
    assert exc_info.value.code == "invalid_wire_json"


def test_parse_pipeboard_envelope_clean_multi_chunk_and_paging_empty() -> None:
    rows = [
        {
            "campaign_id": "12021000000001",
            "date_start": "2026-11-10",
            "date_stop": "2026-11-10",
            "impressions": "100",
            "cpc": 1.25,
        }
    ]
    raw = _mcp_outer_bytes(
        {
            "data": rows,
            "paging": {
                "cursors": {"before": "cur_b", "after": "cur_a"},
                "next": "",
                "previous": None,
            },
        },
        is_error=False,
        include_is_error=True,
    )
    headers = (
        ("Content-Type", "  Application/JSON ; Charset=UTF-8 "),
        ("Content-Encoding", " Identity "),
        ("Content-Length", f" {len(raw)} "),
        ("X-Trace", "ok"),
    )
    parsed = parse_pipeboard_http_and_mcp_envelope(
        network_ok=True,
        http_status=200,
        headers=headers,
        body_chunks=[raw[:17], b"", raw[17:]],
    )
    assert isinstance(parsed, ParsedPipeboardEnvelope)
    assert parsed.has_is_error_false is True
    assert len(parsed.rows) == 1
    assert parsed.rows[0]["cpc"] == _WireDecimalToken(raw="1.25")
    assert parsed.transport_outcome == _clean_outcome()
    for empty_paging in ({"data": []}, {"data": [], "paging": {}}, {"data": [], "paging": {"cursors": {}}}):
        ok_env = parse_pipeboard_http_and_mcp_envelope(network_ok=True, http_status=200, headers=JSON_HEADERS, body_chunks=[_mcp_outer_bytes(empty_paging)])
        assert ok_env.transport_outcome == _clean_outcome()


def test_parse_pipeboard_envelope_preconditions_and_short_circuit_streaming() -> None:
    with pytest.raises(PipeboardAdapterError) as exc_chunk:
        parse_pipeboard_http_and_mcp_envelope(
            network_ok=True,
            http_status=200,
            headers=JSON_HEADERS,
            body_chunks=[b"ok", bytearray(b"bad")],  # type: ignore[list-item]
        )
    assert exc_chunk.value.code == "invalid_chunk_type"

    for kwargs in (
        {"network_ok": 1, "http_status": 200, "headers": JSON_HEADERS, "body_chunks": [b"{}"]},
        {"network_ok": True, "http_status": 200, "headers": "bad", "body_chunks": [b"{}"]},
        {"network_ok": True, "http_status": 200, "headers": JSON_HEADERS, "body_chunks": b"{}"},
        {
            "network_ok": True,
            "http_status": 200,
            "headers": JSON_HEADERS,
            "body_chunks": [b"{}"],
            "transport_limits": "bad",
        },
    ):
        with pytest.raises(PipeboardAdapterError):
            parse_pipeboard_http_and_mcp_envelope(**kwargs)  # type: ignore[arg-type]

    pulled = 0

    def _infinite_stream() -> Iterator[bytes]:
        nonlocal pulled
        while True:
            pulled += 1
            yield b"a" * 65_536

    with pytest.raises(PipeboardWireRejection) as exc_over:
        parse_pipeboard_http_and_mcp_envelope(
            network_ok=True,
            http_status=200,
            headers=JSON_HEADERS,
            body_chunks=_infinite_stream(),
        )
    assert exc_over.value.code == "stream_over_2mib"
    assert pulled == 33


def test_declared_length_over_2mib_does_not_pull_body_chunks() -> None:
    def _must_not_pull() -> Iterator[bytes]:
        raise RuntimeError("body generator should not be consumed")
        yield b""

    with pytest.raises(PipeboardWireRejection) as exc_info:
        parse_pipeboard_http_and_mcp_envelope(
            network_ok=True,
            http_status=200,
            headers=(("Content-Type", "application/json"), ("Content-Length", "2097153")),
            body_chunks=_must_not_pull(),
        )
    assert exc_info.value.code == "declared_length_over_2mib"
    assert exc_info.value.category == "truncation"
    assert exc_info.value.outcome == _clean_outcome(truncated_2mib=True)


def test_decoded_text_over_2mib_in_mcp_result_validator() -> None:
    huge_result = {
        "content": [{"type": "text", "text": "x" * 2_097_153}],
        "isError": False,
    }
    with pytest.raises(PipeboardWireRejection) as exc_info:
        parse_pipeboard_mcp_result(huge_result)
    assert exc_info.value.code == "decoded_text_over_2mib"
    assert exc_info.value.category == "truncation"
    assert exc_info.value.outcome == _clean_outcome(truncated_2mib=True)
    _assert_value_silent(exc_info.value)


@pytest.mark.parametrize(
    ("case_kwargs", "expected_code", "expected_category", "expected_outcome"),
    STEPS_1_TO_7_CASES,
)
def test_parse_pipeboard_envelope_steps_1_to_7_matrix(
    case_kwargs: dict[str, Any],
    expected_code: str,
    expected_category: str,
    expected_outcome: TransportOutcome,
) -> None:
    with pytest.raises(PipeboardWireRejection) as exc_info:
        parse_pipeboard_http_and_mcp_envelope(**case_kwargs)
    err = exc_info.value
    assert err.code == expected_code
    assert err.category == expected_category
    assert err.outcome == expected_outcome
    assert expected_code in STATIC_DETAIL_BY_CODE
    _assert_value_silent(err)


@pytest.mark.parametrize(
    ("raw_body", "expected_code", "expected_category", "expected_outcome"),
    STEPS_8_AND_9_CASES,
)
def test_parse_pipeboard_envelope_steps_8_and_9_matrix(
    raw_body: bytes,
    expected_code: str,
    expected_category: str,
    expected_outcome: TransportOutcome,
) -> None:
    with pytest.raises(PipeboardWireRejection) as exc_info:
        parse_pipeboard_http_and_mcp_envelope(
            network_ok=True,
            http_status=200,
            headers=JSON_HEADERS,
            body_chunks=[raw_body],
        )
    err = exc_info.value
    assert err.code == expected_code
    assert err.category == expected_category
    assert err.outcome == expected_outcome
    assert expected_code in STATIC_DETAIL_BY_CODE
    assert SECRET_SENTINEL not in STATIC_DETAIL_BY_CODE[expected_code]
    _assert_value_silent(err)


def test_adapters_ast_enforces_raise_from_none_everywhere() -> None:
    for mod in (wire_mod, reducer_mod, adapter_mod):
        mod_path = Path(mod.__file__).resolve()
        tree = ast.parse(mod_path.read_text(encoding="utf-8"), filename=str(mod_path))
        bad_raises = [
            (mod_path.name, node.lineno)
            for node in ast.walk(tree)
            if isinstance(node, ast.Raise)
            and not (
                node.exc is not None
                and isinstance(node.cause, ast.Constant)
                and node.cause.value is None
            )
        ]
        assert bad_raises == []


def test_wire_raises_suppress_active_exception_context_and_lone_surrogate() -> None:
    actions: tuple[tuple[Any, str], ...] = (
        (
            lambda: build_pipeboard_insights_request(
                private_object_id=f"bad_{SECRET_SENTINEL}", admitted_day="2026-11-10"
            ),
            "invalid_private_object_id",
        ),
        (lambda: loads_pipeboard_wire_json(f"{{bad:{SECRET_SENTINEL}}}"), "invalid_wire_json"),
        (
            lambda: parse_pipeboard_http_and_mcp_envelope(
                network_ok="bad", http_status=200, headers=(), body_chunks=()  # type: ignore[arg-type]
            ),
            "invalid_envelope_precondition",
        ),
        (
            lambda: parse_pipeboard_http_and_mcp_envelope(
                network_ok=True, http_status=401, headers=(), body_chunks=()
            ),
            "http_auth_error",
        ),
        (
            lambda: parse_pipeboard_mcp_result({"content": [{"type": "text", "text": "\ud800"}]}),
            "invalid_inner_json",
        ),
    )
    for fn, expected_code in actions:
        try:
            raise ValueError(SECRET_SENTINEL)
        except ValueError:
            with pytest.raises(PipeboardAdapterError) as exc_info:
                fn()
            assert exc_info.value.code == expected_code
            _assert_value_silent(exc_info.value)
