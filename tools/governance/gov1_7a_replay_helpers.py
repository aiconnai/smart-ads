"""Passive stdlib Pipeboard wire/reducer, HMAC resource_ref, admission, and U×M completeness helpers."""
from __future__ import annotations

import base64
import bisect
from collections.abc import Callable, Iterable, Mapping, Sequence
import copy
from dataclasses import dataclass
import datetime
import hashlib
import hmac
import json
import re
from types import MappingProxyType
from typing import Any, Final

from tools.governance.gov1_7a_negative import (
    _EPOCH_DATE, _exact_str, _non_empty_nfc_str, _opaque_ref_str, _sha256_str, _strict_int, _strict_str, _utc_sec_micros,
)
from tools.governance.jcs import canonicalize
from tools.governance.locator import exact_fields, json_digest, make_locator

MAX_INT64: Final[int] = (1 << 63) - 1
_MIN_INT64: Final[int] = -(1 << 63)
_MAX_WIRE_NUM_LEN: Final[int] = 64
_MAX_WIRE_EXP_ABS: Final[int] = 100

FORBIDDEN_PIPEBOARD_ARGUMENTS: Final[tuple[str, ...]] = (
    "access_token", "account_id", "action_attribution_windows", "action_breakdowns",
    "ad_id", "adset_id", "after", "breakdown", "campaign_id",
)
DEFAULT_PIPEBOARD_TRANSPORT_LIMITS: Final[Mapping[str, Any]] = MappingProxyType({
    "endpoint_url": "https://meta-ads.mcp.pipeboard.co/", "http_method": "POST", "connect_timeout_seconds": 5,
    "wall_deadline_seconds": 60, "request_content_type": "application/json",
    "request_accept": "application/json, text/event-stream", "request_accept_encoding": "identity",
    "read_chunk_bytes": 65536, "max_streamed_bytes": 2_097_152, "max_decoded_text_bytes": 2_097_152,
    "jsonrpc_method": "tools/call", "tool_name": "get_insights", "level": "campaign", "limit": 100,
    "compact": True, "max_campaign_rows": 100, "forbidden_arguments": list(FORBIDDEN_PIPEBOARD_ARGUMENTS),
})
PIPEBOARD_PHASE1_METRIC_SOURCE_MAPPINGS: Final[Mapping[str, str]] = MappingProxyType({"metric:clicks_v1": "source-metric:provider:pipeboard.clicks:v1", "metric:impressions_v1": "source-metric:provider:pipeboard.impressions:v1", "metric:spend_v1": "source-metric:provider:pipeboard.spend:v1"})
PINNED_PIPEBOARD_ROW_KEYS: Final[frozenset[str]] = frozenset("account_id account_name campaign_id campaign_name impressions clicks spend cpc cpm ctr reach frequency actions action_values conversions unique_clicks cost_per_action_type date_start date_stop".split())
_CLEAN_TRANSPORT_OUTCOME: Final[Mapping[str, Any]] = MappingProxyType({"network_ok": True, "http_status": 200, "media_and_encoding_valid": True, "auth_ok": True, "jsonrpc_error": False, "payload_schema_valid": True, "response_date_mismatch": False, "truncated_2mib": False, "non_empty_continuation": False, "reducer_order_or_count_mismatch": False, "duplicate_provider_observation": False})
_WIRE_REJECTION_SPECS: Final[Mapping[str, tuple[str, str]]] = MappingProxyType({
    "network_error": ("network", "provider transport failed before HTTP status"), "missing_http_status": ("transport", "provider HTTP status code is missing"),
    "invalid_http_status": ("transport", "provider HTTP status code is outside 100..999"), "http_auth_error": ("auth", "provider rejected HTTP authentication or authorization"),
    "http_status_not_200": ("transport", "provider returned non-200 HTTP status"), "malformed_http_headers": ("transport", "provider HTTP headers violated token or CR/LF/NUL rules"),
    "duplicate_http_header": ("transport", "provider repeated a singleton HTTP framing header"), "invalid_content_type": ("transport", "provider Content-Type is not application/json UTF-8"),
    "forbidden_content_encoding": ("transport", "provider Content-Encoding is outside identity"), "invalid_content_length": ("transport", "provider Content-Length header is malformed"),
    "declared_length_over_2mib": ("truncation", "provider Content-Length exceeds 2 MiB ceiling"), "stream_over_2mib": ("truncation", "provider streamed body exceeds 2 MiB ceiling"),
    "content_length_mismatch": ("transport", "provider streamed byte count mismatched Content-Length"), "invalid_outer_json": ("schema", "provider outer body is not valid bounded UTF-8 JSON"),
    "invalid_jsonrpc_envelope": ("schema", "provider outer JSON-RPC 2.0 envelope is invalid"), "malformed_jsonrpc_error": ("schema", "provider JSON-RPC error object violated closed shape"),
    "jsonrpc_error_response": ("jsonrpc", "provider returned sanitized JSON-RPC error response"), "mcp_result_is_error": ("schema", "provider MCP result reported isError=true"),
    "invalid_mcp_content": ("schema", "provider MCP result content envelope is invalid"), "decoded_text_over_2mib": ("truncation", "provider decoded inner text exceeds 2 MiB ceiling"),
    "invalid_inner_json": ("schema", "provider inner MCP text is not valid bounded JSON"), "invalid_payload_shape": ("schema", "provider inner insights payload shape is invalid"),
    "invalid_paging_shape": ("schema", "provider paging object violated closed shape"), "non_empty_paging_next": ("pagination", "provider response carries non-empty paging.next cursor"),
    "non_empty_paging_previous": ("pagination", "provider response carries non-empty paging.previous cursor"), "too_many_campaign_rows": ("schema", "provider campaign row count exceeds 100-row ceiling"),
    "invalid_row_shape": ("schema", "provider campaign row is not a JSON object mapping"), "invalid_row_keys": ("schema", "provider campaign row contains unpinned or forbidden keys"),
    "invalid_campaign_id": ("schema", "provider campaign_id violated closed Meta grammar"), "unknown_campaign_id": ("schema", "provider campaign_id is absent from private resource directory"),
    "unscoped_campaign_resource": ("schema", "provider campaign resource is outside admitted scope"), "invalid_metric_value": ("schema", "provider campaign metric violated bounded numeric grammar"),
    "empty_row_metrics": ("schema", "provider campaign row omitted all Phase 1 base metrics"), "response_date_mismatch": ("date_mismatch", "provider row date_start/date_stop mismatched admitted day"),
    "reducer_output_invalid": ("reducer", "pinned reducer raised or returned malformed record shape"), "reducer_order_or_count_mismatch": ("reducer", "pinned reducer output order or count mismatched validated rows"),
    "duplicate_provider_observation": ("completeness", "provider emitted duplicate (resource_ref, day, metric) observation"),
})

_META_ACCOUNT_RE: Final[re.Pattern[str]] = re.compile(r"\Aact_[1-9][0-9]{5,31}\Z")
_META_CAMPAIGN_RE: Final[re.Pattern[str]] = re.compile(r"\A[1-9][0-9]{5,31}\Z")
_RESOURCE_REF_RE: Final[re.Pattern[str]] = re.compile(r"^resource:[a-z2-7]{51}[aq]$")
_ISO_DATE_RE: Final[re.Pattern[str]] = re.compile(r"\A([0-9]{4})-([0-9]{2})-([0-9]{2})\Z")
_UTC6_RE: Final[re.Pattern[str]] = re.compile(r"\A([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})\.([0-9]{6})Z\Z")
_HEADER_TOKEN_RE: Final[re.Pattern[str]] = re.compile(r"\A[!#$%&'*+\-.^_`|~0-9A-Za-z]+\Z")
_CONTENT_LEN_RE: Final[re.Pattern[str]] = re.compile(r"\A(0|[1-9][0-9]{0,18})\Z")
_WIRE_NUM_RE: Final[re.Pattern[str]] = re.compile(r"\A-?(0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE]([+-]?[0-9]+))?\Z")
_COUNT_STR_RE: Final[re.Pattern[str]] = re.compile(r"\A(0|[1-9][0-9]{0,18})\Z")
_SPEND_STR_RE: Final[re.Pattern[str]] = re.compile(r"\A(0|[1-9][0-9]{0,16})(?:\.([0-9]{1,2}))?\Z")
_UNSIGNED_INT_RE: Final[re.Pattern[str]] = re.compile(r"\A(0|[1-9][0-9]*)\Z")
_RATIO6_RE: Final[re.Pattern[str]] = re.compile(r"\A(0|[1-9][0-9]*)\.[0-9]{6}\Z")
_SOURCE_METRIC_RE: Final[re.Pattern[str]] = re.compile(r"\Asource-metric:(provider:[a-z0-9][a-z0-9._-]{0,127}:v[1-9][0-9]*|formula:sha256:[0-9a-f]{64})\Z")
_SINGLETON_HDRS: Final[frozenset[str]] = frozenset({"content-type", "content-encoding", "content-length"})
_PROVIDER_PRESENCE_SET: Final[frozenset[str]] = frozenset({"observed", "missing", "unproven_zero", "timeout", "not_applicable_at_level", "retracted_tombstone"})
_ALLOWED_ERR_CATS: Final[frozenset[str]] = frozenset("admission network auth transport jsonrpc schema date_mismatch truncation pagination reducer completeness".split())
_REDUCER_TO_METRIC: Final[Mapping[str, tuple[str, str, str, bool]]] = MappingProxyType({
    "clicks": ("metric:clicks_v1", "int64_count", "count", False),
    "impressions": ("metric:impressions_v1", "int64_count", "count", False),
    "spend_minor": ("metric:spend_v1", "int64_minor_currency", "minor_currency", True),
})
_METRIC_SPECS: Final[Mapping[str, tuple[str, str, bool]]] = MappingProxyType({
    "metric:clicks_v1": ("int64_count", "count", False),
    "metric:impressions_v1": ("int64_count", "count", False),
    "metric:spend_v1": ("int64_minor_currency", "minor_currency", True),
})


class Gov1WireRejection(ValueError):
    """Closed stdlib Pipeboard wire rejection carrying `(code, category, outcome)`."""

    def __init__(self, code: str, **outcome_overrides: Any) -> None:
        if code not in _WIRE_REJECTION_SPECS:
            raise ValueError(f"unknown wire rejection code {code!r}")
        cat, detail = _WIRE_REJECTION_SPECS[code]
        super().__init__(f"pipeboard_adapter[{code}]: {detail}")
        self.code, self.category = code, cat
        self.outcome = {**_CLEAN_TRANSPORT_OUTCOME, **outcome_overrides}


@dataclass(frozen=True, slots=True)
class _WireNumSentinel:
    raw: str


def _parse_iso_date(value: object, label: str) -> datetime.date:
    if type(value) is not str or (m := _ISO_DATE_RE.fullmatch(value)) is None:
        raise ValueError(f"{label}: expected YYYY-MM-DD")
    try:
        return datetime.date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
    except ValueError as exc:
        raise ValueError(f"{label}: invalid calendar date") from exc


def parse_utc6_micros(value: object, label: str) -> int:
    if type(value) is not str or (m := _UTC6_RE.fullmatch(value)) is None:
        raise ValueError(f"{label}: expected YYYY-MM-DDTHH:MM:SS.ffffffZ")
    yr, mo, dy, hr, mi, sc, us = (int(m.group(i)) for i in range(1, 8))
    try:
        cal = datetime.date(yr, mo, dy)
    except ValueError as exc:
        raise ValueError(f"{label}: invalid calendar date") from exc
    if not (0 <= hr <= 23 and 0 <= mi <= 59 and 0 <= sc <= 59):
        raise ValueError(f"{label}: invalid HMS")
    return ((((cal - _EPOCH_DATE).days * 24 + hr) * 60 + mi) * 60 + sc) * 1_000_000 + us


def validate_resource_ref_str(value: object, label: str = "resource_ref") -> str:
    if type(value) is not str or "\n" in value or "\r" in value or _RESOURCE_REF_RE.fullmatch(value) is None:
        raise ValueError(f"{label}: invalid canonical resource_ref")
    body = value.split(":", 1)[1]
    try:
        raw = base64.b32decode(body.upper() + "====", casefold=False)
    except Exception as exc:
        raise ValueError(f"{label}: invalid Base32") from exc
    if len(raw) != 32 or base64.b32encode(raw).decode("ascii").rstrip("=").lower() != body:
        raise ValueError(f"{label}: non-canonical 256-bit Base32")
    return value


def derive_resource_ref(
    *, secret_bytes: bytes, mapping_version: str, domain_separator: str = "0x00",
    ad_platform_ref: str = "meta", resource_level: str = "campaign", raw_provider_id: str,
) -> str:
    if type(secret_bytes) is not bytes or len(secret_bytes) < 32:
        raise ValueError("secret_bytes: expected >= 32 bytes")
    _exact_str(domain_separator, "0x00", "domain_separator")
    parts = [_non_empty_nfc_str(mapping_version, "mapping_version"), _non_empty_nfc_str(ad_platform_ref, "ad_platform_ref"), _non_empty_nfc_str(resource_level, "resource_level"), _non_empty_nfc_str(raw_provider_id, "raw_provider_id")]
    mac = hmac.new(secret_bytes, b"\x00".join(p.encode("utf-8") for p in parts), hashlib.sha256).digest()
    return validate_resource_ref_str("resource:" + base64.b32encode(mac).decode("ascii").rstrip("=").lower())


def build_pipeboard_insights_request(
    *, private_object_id: str, admitted_day: str, transport_limits: Mapping[str, Any] = DEFAULT_PIPEBOARD_TRANSPORT_LIMITS
) -> dict[str, Any]:
    if not isinstance(transport_limits, Mapping) or canonicalize(dict(transport_limits)) != canonicalize(dict(DEFAULT_PIPEBOARD_TRANSPORT_LIMITS)):
        raise ValueError("invalid_transport_limits")
    if type(private_object_id) is not str or _META_ACCOUNT_RE.fullmatch(private_object_id) is None:
        raise ValueError("invalid_private_object_id")
    _parse_iso_date(admitted_day, "admitted_day")
    args = {"object_id": private_object_id, "time_range": {"since": admitted_day, "until": admitted_day}, "level": transport_limits["level"], "limit": transport_limits["limit"], "compact": transport_limits["compact"]}
    return {"jsonrpc": "2.0", "id": 1, "method": transport_limits["jsonrpc_method"], "params": {"name": transport_limits["tool_name"], "arguments": args}}


def _check_json_depth_and_surrogates(raw_utf8: str, max_depth: int) -> None:
    depth, in_str, esc = 0, False, False
    for ch in raw_utf8:
        if 0xD800 <= ord(ch) <= 0xDFFF:
            raise ValueError("invalid_wire_json")
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch in ("[", "{"):
            depth += 1
            if depth > max_depth:
                raise ValueError("invalid_wire_json")
        elif ch in ("]", "}"):
            depth -= 1


def _wire_pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out or any(0xD800 <= ord(c) <= 0xDFFF for c in k) or (type(v) is str and any(0xD800 <= ord(c) <= 0xDFFF for c in v)):
            raise ValueError("invalid_wire_json")
        out[k] = v
    return out


def _wire_parse_num(tok: str, *, is_float: bool) -> Any:
    if len(tok) > _MAX_WIRE_NUM_LEN or (m := _WIRE_NUM_RE.fullmatch(tok)) is None or (m.group(2) is not None and abs(int(m.group(2), 10)) > _MAX_WIRE_EXP_ABS):
        raise ValueError("invalid_wire_json")
    if is_float:
        return _WireNumSentinel(tok)
    iv = int(tok, 10)
    return iv if _MIN_INT64 <= iv <= MAX_INT64 else _WireNumSentinel(tok)


def loads_pipeboard_wire_json(raw_utf8: str, *, max_depth: int = 16) -> Any:
    if type(raw_utf8) is not str or type(max_depth) is not int or max_depth < 1:
        raise ValueError("invalid_wire_json")
    _check_json_depth_and_surrogates(raw_utf8, max_depth)
    try:
        parsed = json.loads(
            raw_utf8, object_pairs_hook=_wire_pairs_hook,
            parse_int=lambda t: _wire_parse_num(t, is_float=False),
            parse_float=lambda t: _wire_parse_num(t, is_float=True),
            parse_constant=lambda _t: (_ for _ in ()).throw(ValueError("invalid_wire_json")),
        )
    except (json.JSONDecodeError, ValueError) as exc:
        raise ValueError("invalid_wire_json") from exc
    stack = [parsed]
    while stack:
        cur = stack.pop()
        if type(cur) is str and any(0xD800 <= ord(c) <= 0xDFFF for c in cur):
            raise ValueError("invalid_wire_json")
        elif type(cur) is list:
            stack.extend(cur)
        elif type(cur) is dict:
            stack.extend(cur.values())
    return parsed


def _validate_http_headers(headers: Sequence[tuple[str, str]], *, max_streamed_bytes: int) -> int | None:
    normalized: list[tuple[str, str]] = []
    for item in headers:
        if type(item) is not tuple or len(item) != 2:
            raise Gov1WireRejection("malformed_http_headers", media_and_encoding_valid=False)
        k, v = item
        if type(k) is not str or type(v) is not str or _HEADER_TOKEN_RE.fullmatch(k) is None or any(c in v for c in ("\r", "\n", "\x00")) or any(0xD800 <= ord(c) <= 0xDFFF for c in v):
            raise Gov1WireRejection("malformed_http_headers", media_and_encoding_valid=False)
        normalized.append((k.lower(), v))
    singletons: dict[str, str] = {}
    for lk, v in normalized:
        if lk in _SINGLETON_HDRS:
            if lk in singletons:
                raise Gov1WireRejection("duplicate_http_header", media_and_encoding_valid=False)
            singletons[lk] = v
    raw_ct = singletons.get("content-type")
    parts = [] if raw_ct is None else raw_ct.split(";")
    if not parts or len(parts) > 2 or parts[0].strip(" \t").lower() != "application/json" or (len(parts) == 2 and parts[1].strip(" \t").lower() != "charset=utf-8"):
        raise Gov1WireRejection("invalid_content_type", media_and_encoding_valid=False)
    raw_ce = singletons.get("content-encoding")
    if raw_ce is not None and raw_ce.strip(" \t").lower() not in ("", "identity"):
        raise Gov1WireRejection("forbidden_content_encoding", media_and_encoding_valid=False)
    raw_cl = singletons.get("content-length")
    if raw_cl is None:
        return None
    stripped_cl = raw_cl.strip(" \t")
    if _CONTENT_LEN_RE.fullmatch(stripped_cl) is None:
        raise Gov1WireRejection("invalid_content_length", media_and_encoding_valid=False)
    declared = int(stripped_cl, 10)
    if declared > max_streamed_bytes:
        raise Gov1WireRejection("declared_length_over_2mib", truncated_2mib=True)
    return declared

def _consume_body_and_outer_jsonrpc(
    body_chunks: Iterable[bytes], *, read_chunk_bytes: int, max_streamed_bytes: int, declared_length: int | None
) -> dict[str, Any]:
    buf = bytearray()
    for chunk in body_chunks:
        if type(chunk) is not bytes:
            raise ValueError("invalid_chunk_type")
        for off in range(0, len(chunk), read_chunk_bytes):
            buf.extend(chunk[off : off + read_chunk_bytes])
            if len(buf) > max_streamed_bytes:
                raise Gov1WireRejection("stream_over_2mib", truncated_2mib=True)
    if declared_length is not None and len(buf) != declared_length:
        raise Gov1WireRejection("content_length_mismatch", media_and_encoding_valid=False)
    try:
        outer_obj = loads_pipeboard_wire_json(bytes(buf).decode("utf-8", errors="strict"), max_depth=16)
    except (UnicodeDecodeError, ValueError):
        raise Gov1WireRejection("invalid_outer_json", payload_schema_valid=False) from None
    if type(outer_obj) is not dict or set(outer_obj.keys()) not in ({"jsonrpc", "id", "result"}, {"jsonrpc", "id", "error"}) or outer_obj["jsonrpc"] != "2.0" or type(outer_obj["id"]) is not int or outer_obj["id"] != 1:
        raise Gov1WireRejection("invalid_jsonrpc_envelope", payload_schema_valid=False)
    if "error" in outer_obj:
        err = outer_obj["error"]
        if type(err) is not dict or not ({"code", "message"} <= set(err.keys()) <= {"code", "message", "data"}) or type(err.get("code")) is not int or type(err.get("message")) is not str:
            raise Gov1WireRejection("malformed_jsonrpc_error", payload_schema_valid=False)
        raise Gov1WireRejection("jsonrpc_error_response", jsonrpc_error=True)
    if type(outer_obj["result"]) is not dict:
        raise Gov1WireRejection("invalid_mcp_content", payload_schema_valid=False)
    return outer_obj["result"]

def _validate_paging_dict(paging: Any) -> None:
    if type(paging) is not dict or not set(paging.keys()).issubset({"cursors", "next", "previous"}):
        raise Gov1WireRejection("invalid_paging_shape", payload_schema_valid=False)
    if "cursors" in paging:
        cur = paging["cursors"]
        if type(cur) is not dict or not set(cur.keys()).issubset({"before", "after"}) or any(type(v) is not str for v in cur.values()):
            raise Gov1WireRejection("invalid_paging_shape", payload_schema_valid=False)
    for k in ("next", "previous"):
        if k in paging and paging[k] is not None and type(paging[k]) is not str:
            raise Gov1WireRejection("invalid_paging_shape", payload_schema_valid=False)
    if paging.get("next") not in (None, ""):
        raise Gov1WireRejection("non_empty_paging_next", non_empty_continuation=True)
    if paging.get("previous") not in (None, ""):
        raise Gov1WireRejection("non_empty_paging_previous", non_empty_continuation=True)


def parse_pipeboard_mcp_result(
    result: object, *, transport_limits: Mapping[str, Any] = DEFAULT_PIPEBOARD_TRANSPORT_LIMITS
) -> tuple[str, bool, tuple[Mapping[str, Any], ...]]:
    if not isinstance(transport_limits, Mapping) or canonicalize(dict(transport_limits)) != canonicalize(dict(DEFAULT_PIPEBOARD_TRANSPORT_LIMITS)):
        raise ValueError("invalid_transport_limits")
    if type(result) is not dict or set(result.keys()) not in ({"content"}, {"content", "isError"}):
        raise Gov1WireRejection("invalid_mcp_content", payload_schema_valid=False)
    has_is_error_false = False
    if "isError" in result:
        if result["isError"] is True:
            raise Gov1WireRejection("mcp_result_is_error", payload_schema_valid=False)
        if result["isError"] is not False:
            raise Gov1WireRejection("invalid_mcp_content", payload_schema_valid=False)
        has_is_error_false = True
    content = result["content"]
    if type(content) is not list or len(content) != 1 or type(content[0]) is not dict or set(content[0].keys()) != {"type", "text"} or content[0]["type"] != "text" or type(content[0]["text"]) is not str:
        raise Gov1WireRejection("invalid_mcp_content", payload_schema_valid=False)
    raw_text = content[0]["text"]
    try:
        enc = raw_text.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise Gov1WireRejection("invalid_inner_json", payload_schema_valid=False) from None
    if len(enc) > transport_limits["max_decoded_text_bytes"]:
        raise Gov1WireRejection("decoded_text_over_2mib", truncated_2mib=True)
    try:
        payload = loads_pipeboard_wire_json(raw_text, max_depth=16)
    except ValueError:
        raise Gov1WireRejection("invalid_inner_json", payload_schema_valid=False) from None
    if type(payload) is not dict or "data" not in payload or not set(payload.keys()).issubset({"data", "paging"}):
        raise Gov1WireRejection("invalid_payload_shape", payload_schema_valid=False)
    if "paging" in payload:
        _validate_paging_dict(payload["paging"])
    if type(payload["data"]) is not list:
        raise Gov1WireRejection("invalid_payload_shape", payload_schema_valid=False)
    if len(payload["data"]) > transport_limits["max_campaign_rows"]:
        raise Gov1WireRejection("too_many_campaign_rows", payload_schema_valid=False)
    return raw_text, has_is_error_false, tuple(payload["data"])


def parse_pipeboard_http_and_mcp_envelope(
    *, network_ok: bool, http_status: int | None, headers: Sequence[tuple[str, str]],
    body_chunks: Iterable[bytes], transport_limits: Mapping[str, Any] = DEFAULT_PIPEBOARD_TRANSPORT_LIMITS,
) -> dict[str, Any]:
    if not isinstance(transport_limits, Mapping) or canonicalize(dict(transport_limits)) != canonicalize(dict(DEFAULT_PIPEBOARD_TRANSPORT_LIMITS)):
        raise ValueError("invalid_transport_limits")
    if type(network_ok) is not bool or isinstance(headers, (str, bytes, bytearray)) or not isinstance(headers, Sequence) or isinstance(body_chunks, (str, bytes, bytearray)) or not isinstance(body_chunks, Iterable):
        raise ValueError("invalid_envelope_precondition")
    if not network_ok:
        raise Gov1WireRejection("network_error", network_ok=False, http_status=None)
    if http_status is None:
        raise Gov1WireRejection("missing_http_status", http_status=None)
    if type(http_status) is not int or not (100 <= http_status <= 999):
        raise Gov1WireRejection("invalid_http_status", http_status=None)
    if http_status in (401, 403):
        raise Gov1WireRejection("http_auth_error", http_status=http_status, auth_ok=False)
    if http_status != 200:
        raise Gov1WireRejection("http_status_not_200", http_status=http_status)
    declared_len = _validate_http_headers(headers, max_streamed_bytes=transport_limits["max_streamed_bytes"])
    result = _consume_body_and_outer_jsonrpc(body_chunks, read_chunk_bytes=transport_limits["read_chunk_bytes"], max_streamed_bytes=transport_limits["max_streamed_bytes"], declared_length=declared_len)
    raw_text, has_err_false, rows = parse_pipeboard_mcp_result(result, transport_limits=transport_limits)
    return {"raw_inner_text": raw_text, "has_is_error_false": has_err_false, "rows": rows, "transport_outcome": dict(_CLEAN_TRANSPORT_OUTCOME)}


def parse_campaign_row_metrics(row: Mapping[str, Any]) -> dict[str, int]:
    if not isinstance(row, Mapping):
        raise Gov1WireRejection("invalid_row_shape", payload_schema_valid=False)
    rec: dict[str, int] = {}
    for k in ("impressions", "clicks"):
        if k in row:
            raw = row[k]
            parsed = raw if type(raw) is int else (int(raw, 10) if type(raw) is str and _COUNT_STR_RE.fullmatch(raw) is not None else -1)
            if not (0 <= parsed <= MAX_INT64):
                raise Gov1WireRejection("invalid_metric_value", payload_schema_valid=False)
            rec[k] = parsed
    if "spend" in row:
        raw_s = row["spend"]
        m = _SPEND_STR_RE.fullmatch(raw_s) if type(raw_s) is str else None
        minor = -1 if m is None else int(m.group(1), 10) * 100 + (0 if m.group(2) is None else int(m.group(2).ljust(2, "0"), 10))
        if not (0 <= minor <= MAX_INT64):
            raise Gov1WireRejection("invalid_metric_value", payload_schema_valid=False)
        rec["spend_minor"] = minor
    if not rec:
        raise Gov1WireRejection("empty_row_metrics", payload_schema_valid=False)
    return rec


def reduce_pipeboard_insights_result(mcp_result: dict[str, Any]) -> list[dict[str, int]]:
    _, _, rows = parse_pipeboard_mcp_result(mcp_result)
    out: list[dict[str, int]] = []
    for row in rows:
        if not isinstance(row, Mapping):
            raise Gov1WireRejection("invalid_row_shape", payload_schema_valid=False)
        if not set(row.keys()).issubset(PINNED_PIPEBOARD_ROW_KEYS):
            raise Gov1WireRejection("invalid_row_keys", payload_schema_valid=False)
        if type(row.get("campaign_id")) is not str or _META_CAMPAIGN_RE.fullmatch(row["campaign_id"]) is None:
            raise Gov1WireRejection("invalid_campaign_id", payload_schema_valid=False)
        out.append(parse_campaign_row_metrics(row))
    return out


def _gate1_and_gate2(
    rows: Sequence[Mapping[str, Any]], *, admitted_day: str,
    known_campaign_map: Mapping[str, str], scoped_resource_refs: frozenset[str],
) -> list[tuple[str, str]]:
    for row in rows:
        if not isinstance(row, Mapping):
            raise Gov1WireRejection("invalid_row_shape", payload_schema_valid=False)
        if row.get("date_start") != admitted_day or row.get("date_stop") != admitted_day or type(row.get("date_start")) is not str or type(row.get("date_stop")) is not str:
            raise Gov1WireRejection("response_date_mismatch", response_date_mismatch=True)
    for row in rows:
        if not set(row.keys()).issubset(PINNED_PIPEBOARD_ROW_KEYS):
            raise Gov1WireRejection("invalid_row_keys", payload_schema_valid=False)
    bindings: list[tuple[str, str]] = []
    for row in rows:
        cid = row.get("campaign_id")
        if type(cid) is not str or _META_CAMPAIGN_RE.fullmatch(cid) is None:
            raise Gov1WireRejection("invalid_campaign_id", payload_schema_valid=False)
        rref = known_campaign_map.get(cid)
        if rref is None:
            raise Gov1WireRejection("unknown_campaign_id", payload_schema_valid=False)
        if rref not in scoped_resource_refs:
            raise Gov1WireRejection("unscoped_campaign_resource", payload_schema_valid=False)
        bindings.append((rref, admitted_day))
    return bindings


def _gate3_reduce_and_pair(
    parsed: Mapping[str, Any], *, bindings: list[tuple[str, str]],
    reducer: Callable[[dict[str, Any]], list[dict[str, int]]], currency: str,
) -> list[dict[str, Any]]:
    expected_records = [parse_campaign_row_metrics(row) for row in parsed["rows"]]
    red_in: dict[str, Any] = {"content": [{"type": "text", "text": parsed["raw_inner_text"]}]}
    if parsed["has_is_error_false"]:
        red_in["isError"] = False
    try:
        actual = reducer(red_in)
    except Exception:
        raise Gov1WireRejection("reducer_output_invalid", reducer_order_or_count_mismatch=True) from None
    if type(actual) is not list or any(type(r) is not dict or not r or not set(r.keys()).issubset(_REDUCER_TO_METRIC.keys()) or any(type(v) is not int or not (0 <= v <= MAX_INT64) for v in r.values()) for r in actual):
        raise Gov1WireRejection("reducer_output_invalid", reducer_order_or_count_mismatch=True)
    if canonicalize(actual) != canonicalize(expected_records):
        raise Gov1WireRejection("reducer_order_or_count_mismatch", reducer_order_or_count_mismatch=True)
    seen_triples: set[tuple[str, str, str]] = set()
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for (rref, mdate), rec in zip(bindings, actual, strict=True):
        bucket = grouped.setdefault((rref, mdate), [])
        for r_key, val in rec.items():
            m_ref, v_type, unit, needs_cur = _REDUCER_TO_METRIC[r_key]
            if (rref, mdate, m_ref) in seen_triples:
                raise Gov1WireRejection("duplicate_provider_observation", duplicate_provider_observation=True)
            seen_triples.add((rref, mdate, m_ref))
            bucket.append({"metric_semantic_ref": m_ref, "presence_status": "observed", "value_type": v_type, "raw_numeric_value": str(val), "unit": unit, "currency": currency if needs_cur else None})
    sorted_keys = sorted(grouped.keys(), key=lambda p: (p[0].encode("utf-8"), p[1].encode("utf-8")))
    return [{"resource_ref": r, "metric_date": d, "metric_observations": sorted(grouped[(r, d)], key=lambda m: m["metric_semantic_ref"].encode("utf-8"))} for r, d in sorted_keys]


def transform_pipeboard_response_to_batch_dict(
    *, admitted: Mapping[str, Any], private_object_id: str, known_campaign_map: Mapping[str, str],
    scoped_resource_refs: frozenset[str], transport_limits: Mapping[str, Any] = DEFAULT_PIPEBOARD_TRANSPORT_LIMITS,
    retrieval_context: Mapping[str, Any], network_ok: bool, http_status: int | None,
    headers: Sequence[tuple[str, str]], body_chunks: Iterable[bytes],
    reducer: Callable[[dict[str, Any]], list[dict[str, int]]] = reduce_pipeboard_insights_result,
) -> dict[str, Any]:
    admitted_day = admitted["computed_date_range"]["start_date"]
    build_pipeboard_insights_request(private_object_id=private_object_id, admitted_day=admitted_day, transport_limits=transport_limits)
    zero_io = {"credential_lookups": 0, "token_decryptions": 0, "socket_creations": 0, "provider_rpc_calls": 0}
    rctx = copy.deepcopy(dict(retrieval_context))
    try:
        parsed = parse_pipeboard_http_and_mcp_envelope(network_ok=network_ok, http_status=http_status, headers=headers, body_chunks=body_chunks, transport_limits=transport_limits)
        bindings = _gate1_and_gate2(parsed["rows"], admitted_day=admitted_day, known_campaign_map=known_campaign_map, scoped_resource_refs=scoped_resource_refs)
        res_obs = _gate3_reduce_and_pair(parsed, bindings=bindings, reducer=reducer, currency=admitted["currency"])
    except Gov1WireRejection as rej:
        err = {"error_code": rej.code, "category": rej.category, "sanitized_detail": _WIRE_REJECTION_SPECS[rej.code][1]}
        return {"observed_capabilities": [], "retrieval_context": rctx, "transport_outcome": rej.outcome, "resource_observations": [], "normalized_errors": [err], "io_counters": zero_io}
    return {"observed_capabilities": [admitted["canonical_query_contract"]["requested_capabilities"][0]], "retrieval_context": rctx, "transport_outcome": parsed["transport_outcome"], "resource_observations": res_obs, "normalized_errors": [], "io_counters": zero_io}


def _validate_metric_obs_dict(raw_m: object, label: str) -> None:
    m = dict(raw_m) if isinstance(raw_m, Mapping) else {}
    exact_fields(m, {"metric_semantic_ref", "presence_status", "value_type", "raw_numeric_value", "unit", "currency"}, label)
    m_ref = _opaque_ref_str(m["metric_semantic_ref"], f"{label}.metric_semantic_ref", expected_prefix="metric")
    ps = m["presence_status"]
    if type(ps) is not str or ps not in _PROVIDER_PRESENCE_SET:
        raise ValueError(f"{label}.presence_status: invalid {ps!r}")
    vt, rnv, unit, cur = m["value_type"], m["raw_numeric_value"], m["unit"], m["currency"]
    if ps != "observed":
        if (vt, rnv, unit, cur) != (None, None, None, None):
            raise ValueError(f"{label}: non-observed presence requires null value fields")
        return
    if type(vt) is not str or type(rnv) is not str or type(unit) is not str or (cur is not None and type(cur) is not str):
        raise ValueError(f"{label}: observed metric requires str value_type, raw_numeric_value, and unit")
    if vt == "int64_count" and (unit != "count" or cur is not None or len(rnv) > 20 or _UNSIGNED_INT_RE.fullmatch(rnv) is None or int(rnv, 10) > MAX_INT64):
        raise ValueError(f"{label}: invalid int64_count observation")
    elif vt == "int64_minor_currency" and (unit != "minor_currency" or cur != "BRL" or len(rnv) > 20 or _UNSIGNED_INT_RE.fullmatch(rnv) is None or int(rnv, 10) > MAX_INT64):
        raise ValueError(f"{label}: invalid int64_minor_currency observation")
    elif vt == "decimal_ratio" and (unit != "ratio" or cur is not None or _RATIO6_RE.fullmatch(rnv) is None):
        raise ValueError(f"{label}: invalid decimal_ratio observation")
    elif vt not in {"int64_count", "int64_minor_currency", "decimal_ratio"}:
        raise ValueError(f"{label}.value_type: unsupported {vt!r}")
    if m_ref in _METRIC_SPECS and (vt, unit, cur == "BRL") != _METRIC_SPECS[m_ref]:
        raise ValueError(f"{label}: base metric definition mismatch for {m_ref!r}")


def validate_provider_observation_batch_dict(raw_batch: object, *, label: str = "observation_batch") -> dict[str, Any]:
    b = copy.deepcopy(dict(raw_batch)) if isinstance(raw_batch, Mapping) else {}
    exact_fields(b, {"observed_capabilities", "retrieval_context", "transport_outcome", "resource_observations", "normalized_errors", "io_counters"}, label)
    caps = b["observed_capabilities"]
    if type(caps) is not list or any(type(c) is not str for c in caps):
        raise ValueError(f"{label}.observed_capabilities: expected list[str]")
    for c in caps:
        _opaque_ref_str(c, f"{label}.observed_capabilities", expected_prefix="cap")
    if len(set(caps)) != len(caps) or [c.encode("utf-8") for c in caps] != sorted(c.encode("utf-8") for c in caps):
        raise ValueError(f"{label}.observed_capabilities: must be unique and sorted by UTF-8 bytes")
    rctx = dict(b["retrieval_context"]) if isinstance(b["retrieval_context"], Mapping) else {}
    exact_fields(rctx, {"retrieved_at_utc", "source_observation_ref", "adapter_version", "semantic_version"}, f"{label}.retrieval_context")
    parse_utc6_micros(rctx["retrieved_at_utc"], f"{label}.retrieved_at_utc")
    _opaque_ref_str(rctx["source_observation_ref"], f"{label}.source_observation_ref", expected_prefix="observation")
    _strict_str(rctx["adapter_version"], f"{label}.adapter_version")
    _strict_str(rctx["semantic_version"], f"{label}.semantic_version")
    to_d = dict(b["transport_outcome"]) if isinstance(b["transport_outcome"], Mapping) else {}
    exact_fields(to_d, set(_CLEAN_TRANSPORT_OUTCOME.keys()), f"{label}.transport_outcome")
    if to_d["http_status"] is not None and (type(to_d["http_status"]) is not int or not (100 <= to_d["http_status"] <= 999)):
        raise ValueError(f"{label}.transport_outcome.http_status: expected 100..999 int or None")
    if any(type(to_d[k]) is not bool for k in _CLEAN_TRANSPORT_OUTCOME if k != "http_status"):
        raise ValueError(f"{label}.transport_outcome: boolean flags must have strict bool type")
    io_d = dict(b["io_counters"]) if isinstance(b["io_counters"], Mapping) else {}
    exact_fields(io_d, {"credential_lookups", "token_decryptions", "socket_creations", "provider_rpc_calls"}, f"{label}.io_counters")
    if any(type(v) is not int or v != 0 for v in io_d.values()) or type(b["resource_observations"]) is not list or type(b["normalized_errors"]) is not list:
        raise ValueError(f"{label}: invalid io_counters or observation/error lists")
    for ro in b["resource_observations"]:
        rd = dict(ro) if isinstance(ro, Mapping) else {}
        exact_fields(rd, {"resource_ref", "metric_date", "metric_observations"}, f"{label}.resource_obs")
        validate_resource_ref_str(rd["resource_ref"], f"{label}.resource_ref")
        _parse_iso_date(rd["metric_date"], f"{label}.metric_date")
        if type(rd["metric_observations"]) is not list:
            raise ValueError(f"{label}.metric_observations: expected list")
        for mo in rd["metric_observations"]:
            _validate_metric_obs_dict(mo, f"{label}.metric_obs")
    for err in b["normalized_errors"]:
        ed = dict(err) if isinstance(err, Mapping) else {}
        exact_fields(ed, {"error_code", "category", "sanitized_detail"}, f"{label}.error")
        _strict_str(ed["error_code"], f"{label}.error_code")
        if type(ed["category"]) is not str or ed["category"] not in _ALLOWED_ERR_CATS:
            raise ValueError(f"{label}.category: invalid {ed['category']!r}")
        _strict_str(ed["sanitized_detail"], f"{label}.sanitized_detail")
    return b


def build_canonical_regression_fixture(registry_snapshot_digest: str) -> dict[str, Any]:
    _sha256_str(registry_snapshot_digest, "registry_snapshot_digest")
    return {
        "$schema": "smart_ads/regression_fixture/v1", "fixture_id": "fixture:semantic-metric-65x23-v1",
        "fixture_role": "regression_only", "provider_provenance": "synthetic", "registry_transition": "none",
        "capability_promotion": "none", "before_registry_snapshot_digest": registry_snapshot_digest,
        "after_registry_snapshot_digest": registry_snapshot_digest,
        "truth_vectors": [{"aggregate_conversions": "65", "canonical_leads": "unknown"}, {"aggregate_conversions": "0", "canonical_leads": "23"}, {"aggregate_conversions": "unknown", "canonical_leads": "unknown"}],
        "semantic_refs": {"aggregate_conversions": "metric:aggregate_conversions_v1", "canonical_leads": "metric:canonical_leads_v1"},
    }


def _compute_previous_local_day(tz_snapshot: Mapping[str, Any], lower_us: int, upper_us: int) -> str:
    d = dict(tz_snapshot) if isinstance(tz_snapshot, Mapping) else {}
    exact_fields(d, {"timezone_name", "tzdb_version", "transitions"}, "timezone_snapshot")
    _exact_str(d["timezone_name"], "America/Sao_Paulo", "timezone_snapshot.timezone_name")
    _strict_str(d["tzdb_version"], "timezone_snapshot.tzdb_version")
    trs = d["transitions"]
    if type(trs) is not list or not trs:
        raise ValueError("timezone_snapshot.transitions: expected non-empty list")
    parsed_trs: list[tuple[int, int]] = []
    for item in trs:
        td = dict(item) if isinstance(item, Mapping) else {}
        exact_fields(td, {"effective_from_utc_micros", "utc_offset_seconds"}, "transition")
        eff, off = td["effective_from_utc_micros"], td["utc_offset_seconds"]
        if type(eff) is not int or type(off) is not int or not (-86_400 < off < 86_400) or (parsed_trs and eff <= parsed_trs[-1][0]):
            raise ValueError("timezone_snapshot.transitions: invalid or unsorted transition")
        parsed_trs.append((eff, off))
    starts = [t[0] for t in parsed_trs]
    probes = [lower_us, *[p for eff, _ in parsed_trs if lower_us < eff <= upper_us for p in (eff - 1, eff)], *([] if upper_us == lower_us else [upper_us])]
    dates: set[datetime.date] = set()
    for pt in probes:
        idx = bisect.bisect_right(starts, pt) - 1
        if idx < 0:
            raise ValueError("timezone_snapshot: timestamp precedes earliest transition")
        dates.add(_EPOCH_DATE + datetime.timedelta(days=(pt + parsed_trs[idx][1] * 1_000_000) // 86_400_000_000))
    if len(dates) != 1:
        raise ValueError("timezone_snapshot: clock interval straddles local midnight")
    (only_date,) = tuple(dates)
    return (only_date - datetime.timedelta(days=1)).isoformat()


def _verify_clock_and_compute_day(
    clock_attestation: Mapping[str, Any], configured_max_uncertainty_ms: int, timezone_snapshot: Mapping[str, Any]
) -> tuple[dict[str, Any], str, str, int, int]:
    att = dict(clock_attestation) if isinstance(clock_attestation, Mapping) else {}
    exact_fields(att, {"$schema", "attestation_id", "now_utc", "uncertainty_ms", "issued_at_utc", "valid_until_utc", "maximum_age_seconds"}, "clock_attestation")
    _exact_str(att["$schema"], "smart_ads/clock_attestation/v1", "clock_attestation.$schema")
    _opaque_ref_str(att["attestation_id"], "clock_attestation.attestation_id", expected_prefix="clock")
    now_us = parse_utc6_micros(att["now_utc"], "clock_attestation.now_utc")
    unc_ms = _strict_int(att["uncertainty_ms"], "uncertainty_ms")
    max_unc = _strict_int(configured_max_uncertainty_ms, "configured_max_uncertainty_ms", minimum=1)
    max_age_s = _strict_int(att["maximum_age_seconds"], "maximum_age_seconds", minimum=1)
    issued_us, until_us = _utc_sec_micros(att["issued_at_utc"], "issued"), _utc_sec_micros(att["valid_until_utc"], "valid_until")
    lower_us, upper_us = now_us - unc_ms * 1_000, now_us + unc_ms * 1_000
    if unc_ms > max_unc or issued_us > until_us or lower_us < issued_us or upper_us > until_us or upper_us - issued_us > max_age_s * 1_000_000:
        raise ValueError("clock_attestation: freshness or containment check failed")
    prev_day = _compute_previous_local_day(timezone_snapshot, lower_us, upper_us)
    return make_locator("smart_ads/clock_attestation/v1", canonicalize(att)), att["now_utc"][:19] + "Z", prev_day, lower_us, upper_us


def _resolve_caps_and_cqc(
    req: Mapping[str, Any], req_caps: list[str], tzdb_version: str, prev_day: str,
    bnd: Mapping[str, Any], snap: Mapping[str, Any], drv: Mapping[str, Any], drv_loc: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    cap_map = {(c["capability_ref"], c["resource_scope_ref"]): c for c in snap["capabilities"]}
    resolved_caps, metrics_set = [], set()
    for cap_ref in req_caps:
        cap = cap_map.get((cap_ref, req["resource_scope_ref"]))
        if cap is None or cap["driver_id"] != bnd["driver_id"] or canonicalize(cap["driver_contract_locator"]) != canonicalize(dict(drv_loc)) or cap["state"] not in {"declared", "fixture_certified"}:
            raise ValueError("admission: capability missing, mismatched, or ineligible")
        resolved_caps.append(cap)
        metrics_set.update(cap["required_metrics"])
    req_metrics = sorted(metrics_set, key=lambda s: s.encode("utf-8"))
    if any(m not in drv["metric_source_mappings"] for m in req_metrics):
        raise ValueError("admission: unmapped required metric")
    cqc = {
        "$schema": "smart_ads/canonical_query_contract/v1", "tenant_ref": req["tenant_ref"], "binding_ref": req["binding_ref"],
        "account_ref": bnd["account_ref"], "resource_scope_ref": req["resource_scope_ref"], "ad_platform_ref": "meta",
        "date_rule": "previous_local_day", "date_range": {"start_date": prev_day, "end_date": prev_day, "inclusive": True},
        "reporting_timezone": "America/Sao_Paulo", "tzdb_version": tzdb_version, "resource_level": "campaign",
        "metric_semantic_refs": req_metrics, "requested_capabilities": req_caps, "breakdowns": [], "currency": "BRL",
        "attribution_semantics": "not_applicable_to_selected_metrics", "pagination_semantics": "complete_result_required",
        "aggregation_semantics": "per_campaign_rows_no_cross_campaign_aggregation",
    }
    return resolved_caps, cqc


def recompute_fixture_7a_admission(
    *, collection_request: Mapping[str, Any], admission_id: str, clock_attestation: Mapping[str, Any],
    configured_max_uncertainty_ms: int, timezone_snapshot: Mapping[str, Any],
    registry_snapshot_locator: Mapping[str, Any], registry_snapshot: Mapping[str, Any],
    driver_contract_locator: Mapping[str, Any], driver_contract: Mapping[str, Any],
    sealed_sandbox_profile_locator: Mapping[str, Any], regression_fixture_locator: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    from tools.governance.gov1_7a_runner import validate_private_registry_snapshot_payload

    _opaque_ref_str(admission_id, "admission_id", expected_prefix="admission")
    validate_private_registry_snapshot_payload(registry_snapshot)
    req = dict(collection_request) if isinstance(collection_request, Mapping) else {}
    exact_fields(req, {"request_id", "collection_purpose", "tenant_ref", "binding_ref", "resource_scope_ref", "date_rule", "resource_level", "requested_capabilities", "breakdowns"}, "collection_request")
    _strict_str(req["request_id"], "request_id")
    for pfx, k in (("tenant", "tenant_ref"), ("binding", "binding_ref"), ("scope", "resource_scope_ref")):
        _opaque_ref_str(req[k], f"req.{k}", expected_prefix=pfx)
    if req["collection_purpose"] != "fixture_7a" or req["date_rule"] != "previous_local_day" or req["resource_level"] != "campaign" or type(req["breakdowns"]) is not list or len(req["breakdowns"]) != 0 or type(req["requested_capabilities"]) is not list or not req["requested_capabilities"]:
        raise ValueError("collection_request: invalid fixture_7a request fields")
    req_caps = sorted({_opaque_ref_str(c, "cap", expected_prefix="cap") for c in req["requested_capabilities"]}, key=lambda s: s.encode("utf-8"))
    if len(req_caps) != len(req["requested_capabilities"]):
        raise ValueError("collection_request: duplicate capability")
    clk_loc, admitted_at_utc, prev_day, lower_us, upper_us = _verify_clock_and_compute_day(clock_attestation, configured_max_uncertainty_ms, timezone_snapshot)
    snap_issued, snap_until = _utc_sec_micros(registry_snapshot["issued_at_utc"], "snap.issued"), _utc_sec_micros(registry_snapshot["valid_until_utc"], "snap.until")
    bnd = {b["binding_ref"]: b for b in registry_snapshot["bindings"]}.get(req["binding_ref"])
    if registry_snapshot["tenant_ref"] != req["tenant_ref"] or not (snap_issued <= lower_us and upper_us <= snap_until) or bnd is None or bnd["currency"] != "BRL" or bnd["ad_platform_ref"] != "meta" or bnd["driver_id"] != driver_contract["driver_id"] or not any(s["binding_ref"] == req["binding_ref"] and s["resource_scope_ref"] == req["resource_scope_ref"] for s in registry_snapshot["authorized_scopes"]):
        raise ValueError("admission: snapshot, binding, or scope check failed")
    resolved_caps, cqc = _resolve_caps_and_cqc(req, req_caps, timezone_snapshot["tzdb_version"], prev_day, bnd, registry_snapshot, driver_contract, driver_contract_locator)
    ext_req = {**req, "requested_capabilities": req_caps, "breakdowns": []}
    admitted = {
        "$schema": "smart_ads/admitted_collection/v1", "admission_id": admission_id, "collection_purpose": "fixture_7a",
        "external_request_digest": json_digest(ext_req), "tenant_ref": req["tenant_ref"], "binding_ref": req["binding_ref"],
        "account_ref": bnd["account_ref"], "resource_scope_ref": req["resource_scope_ref"], "resource_level": "campaign",
        "requested_capabilities": req_caps, "admitted_at_utc": admitted_at_utc, "clock_attestation_locator": clk_loc,
        "maximum_clock_uncertainty_ms": configured_max_uncertainty_ms, "tzdb_version": timezone_snapshot["tzdb_version"],
        "reporting_timezone": "America/Sao_Paulo", "computed_date_range": copy.deepcopy(cqc["date_range"]),
        "registry_snapshot_locator": copy.deepcopy(dict(registry_snapshot_locator)), "registry_snapshot_digest": registry_snapshot_locator["content_digest"],
        "currency": "BRL", "driver_id": bnd["driver_id"], "driver_contract_locator": copy.deepcopy(dict(driver_contract_locator)),
        "driver_contract_digest": driver_contract_locator["content_digest"], "driver_capability_snapshot_digest": json_digest(resolved_caps),
        "canonical_query_contract": cqc, "canonical_query_digest": json_digest(cqc),
        "purpose_prerequisite_locators": {"purpose": "fixture_7a", "sealed_sandbox_profile_locator": copy.deepcopy(dict(sealed_sandbox_profile_locator)), "regression_fixture_locator": copy.deepcopy(dict(regression_fixture_locator))},
        "required_effect_roles": [],
    }
    return admitted, make_locator("smart_ads/admitted_collection/v1", canonicalize(admitted))


def _project_batch_facts(
    batch_dict: Mapping[str, Any], admitted_dict: Mapping[str, Any], metric_source_mappings: Mapping[str, str]
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    admitted_day, to_dict, facts = admitted_dict["computed_date_range"]["start_date"], dict(batch_dict["transport_outcome"]), []
    for r_obs in batch_dict["resource_observations"]:
        if r_obs["metric_date"] != admitted_day:
            to_dict["response_date_mismatch"] = True
        for m_obs in r_obs["metric_observations"]:
            src_ref = metric_source_mappings.get(m_obs["metric_semantic_ref"])
            if src_ref is None or m_obs["metric_semantic_ref"] not in _METRIC_SPECS:
                to_dict["reducer_order_or_count_mismatch"] = True
                continue
            fk = {"binding_ref": admitted_dict["binding_ref"], "account_ref": admitted_dict["account_ref"], "resource_ref": r_obs["resource_ref"], "resource_level": admitted_dict["resource_level"], "metric_date": r_obs["metric_date"], "metric_semantic_ref": m_obs["metric_semantic_ref"], "source_metric_ref": src_ref, "attribution_ref": "attribution:not_applicable", "breakdown_signature": "breakdown:none"}
            facts.append({"fact_key": fk, "presence_status": m_obs["presence_status"], "value_type": m_obs["value_type"], "raw_numeric_value": m_obs["raw_numeric_value"], "unit": m_obs["unit"], "currency": m_obs["currency"]})
    return to_dict, facts


def recompute_collection_completeness_dict(
    *, expected_resources: Sequence[Mapping[str, Any]], required_metrics: Sequence[str],
    metric_source_mappings: Mapping[str, str], batch_dict: Mapping[str, Any], admitted_dict: Mapping[str, Any],
) -> dict[str, Any]:
    to_d, facts = _project_batch_facts(batch_dict, admitted_dict, metric_source_mappings)
    failed = [r for flag, r in ((not to_d["network_ok"], "network_failed"), (not to_d["auth_ok"], "auth_failed"), (not to_d["media_and_encoding_valid"], "media_or_encoding_invalid"), (to_d["jsonrpc_error"], "jsonrpc_error")) if flag]
    if to_d["http_status"] is None:
        failed.append("http_status_missing")
    elif to_d["http_status"] != 200:
        failed.append(f"http_status_{to_d['http_status']}")
    sorted_m = sorted(required_metrics, key=lambda s: s.encode("utf-8"))
    if not expected_resources:
        failed.append("empty_expected_inventory")
    elif any(m not in metric_source_mappings or _SOURCE_METRIC_RE.fullmatch(metric_source_mappings[m]) is None or not metric_source_mappings[m].startswith("source-metric:provider:") for m in sorted_m):
        failed.append("invalid_expected_fact_universe")
    if failed:
        return {"status": "failed", "reasons": failed, "normalized_fact_set_digest": None}
    expected_fks = {
        canonicalize({"binding_ref": u["binding_ref"], "account_ref": u["account_ref"], "resource_ref": u["resource_ref"], "resource_level": u["resource_level"], "metric_date": u["metric_date"], "metric_semantic_ref": m, "source_metric_ref": metric_source_mappings[m], "attribution_ref": u["attribution_ref"], "breakdown_signature": u["breakdown_signature"]})
        for u in expected_resources for m in sorted_m
    }
    return _evaluate_partial_or_complete(to_d, facts, expected_fks)


def _evaluate_partial_or_complete(
    to_d: Mapping[str, Any], facts: Sequence[Mapping[str, Any]], expected_fks: set[bytes]
) -> dict[str, Any]:
    partial = [r for flag, r in ((not to_d["payload_schema_valid"], "payload_schema_invalid"), (to_d["response_date_mismatch"], "response_date_mismatch"), (to_d["truncated_2mib"], "truncated_2mib"), (to_d["non_empty_continuation"], "non_empty_continuation"), (to_d["reducer_order_or_count_mismatch"], "reducer_order_or_count_mismatch"), (to_d["duplicate_provider_observation"], "duplicate_provider_observation")) if flag]
    seen_fks, seen_ids, non_comp, has_dup = set(), set(), [], False
    for f in facts:
        fk = f["fact_key"]
        fk_b, id_b = canonicalize(fk), canonicalize([fk["resource_ref"], fk["metric_date"], fk["resource_level"], fk["breakdown_signature"], fk["metric_semantic_ref"]])
        if fk_b in seen_fks or id_b in seen_ids:
            has_dup = True
        seen_fks.add(fk_b)
        seen_ids.add(id_b)
        if f["presence_status"] not in {"observed", "retracted_tombstone"} and f["presence_status"] not in non_comp:
            non_comp.append(f["presence_status"])
    if has_dup:
        partial.append("duplicate_candidate_fact_key")
    if expected_fks - seen_fks:
        partial.append("missing_expected_fact_keys")
    if seen_fks - expected_fks:
        partial.append("unexpected_observed_fact_keys")
    partial.extend(f"non_complete_presence_status:{st}" for st in non_comp)
    if partial:
        return {"status": "partial", "reasons": partial, "normalized_fact_set_digest": None}
    sorted_facts = sorted(facts, key=lambda f: canonicalize([f["fact_key"]["resource_ref"], f["fact_key"]["metric_date"], f["fact_key"]["resource_level"], f["fact_key"]["breakdown_signature"], f["fact_key"]["metric_semantic_ref"]]))
    nfs_bytes = b"SMART-ADS:NORMALIZED-FACT-SET:V1\n\x00" + canonicalize(sorted_facts)
    return {"status": "complete", "reasons": [], "normalized_fact_set_digest": "sha256:" + hashlib.sha256(nfs_bytes).hexdigest()}
