"""Zero-I/O Pipeboard wire request builder, iterative RFC 8259 decoder, and 9-step envelope validator (ADR-0001 §4.1)."""
from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
import re
from types import MappingProxyType
from typing import Any, Final

from smart_ads.contracts.numerics import MAX_INT64
from smart_ads.contracts.scalars import ClosedValidationError, validate_iso_date
from smart_ads.contracts.schemas import ProviderErrorCategory, TransportOutcome
from smart_ads.domain.pipeboard_contract import (
    FORBIDDEN_PIPEBOARD_ARGUMENTS,
    PipeboardTransportLimits,
)

DEFAULT_PIPEBOARD_TRANSPORT_LIMITS: Final[PipeboardTransportLimits] = PipeboardTransportLimits()

_MIN_INT64: Final[int] = -(1 << 63)
_MAX_WIRE_NUM_TOKEN_LEN: Final[int] = 64
_MAX_WIRE_EXPONENT_ABS: Final[int] = 100

_META_ACCOUNT_ID_RE: Final[re.Pattern[str]] = re.compile(r"\Aact_[1-9][0-9]{5,31}\Z")
_HEADER_TOKEN_RE: Final[re.Pattern[str]] = re.compile(r"\A[!#$%&'*+\-.^_`|~0-9A-Za-z]+\Z")
_CONTENT_LENGTH_RE: Final[re.Pattern[str]] = re.compile(r"\A(0|[1-9][0-9]{0,18})\Z")
_WIRE_NUMBER_RE: Final[re.Pattern[str]] = re.compile(
    r"\A-?(0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE]([+-]?[0-9]+))?\Z"
)
_HEX4_RE: Final[re.Pattern[str]] = re.compile(r"\A[0-9A-Fa-f]{4}\Z")

_JSON_WHITESPACE: Final[frozenset[str]] = frozenset({" ", "\t", "\n", "\r"})
_JSON_NUM_TERMINATORS: Final[frozenset[str]] = frozenset({" ", "\t", "\n", "\r", ",", "]", "}"})
_JSON_ESCAPES: Final[Mapping[str, str]] = MappingProxyType(
    {'"': '"', "\\": "\\", "/": "/", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t"}
)
_SINGLETON_HTTP_HEADERS: Final[frozenset[str]] = frozenset(
    {"content-type", "content-encoding", "content-length"}
)

_CLEAN_TRANSPORT_OUTCOME: Final[TransportOutcome] = TransportOutcome(
    network_ok=True,
    http_status=200,
    media_and_encoding_valid=True,
    auth_ok=True,
    jsonrpc_error=False,
    payload_schema_valid=True,
    response_date_mismatch=False,
    truncated_2mib=False,
    non_empty_continuation=False,
    reducer_order_or_count_mismatch=False,
    duplicate_provider_observation=False,
)

_WIRE_REJECTION_SPECS: Final[Mapping[str, tuple[ProviderErrorCategory, str]]] = MappingProxyType(
    {
        "network_error": ("network", "provider transport failed before HTTP status"),
        "missing_http_status": ("transport", "provider HTTP status code is missing"),
        "invalid_http_status": ("transport", "provider HTTP status code is outside 100..999"),
        "http_auth_error": ("auth", "provider rejected HTTP authentication or authorization"),
        "http_status_not_200": ("transport", "provider returned non-200 HTTP status"),
        "malformed_http_headers": ("transport", "provider HTTP headers violated token or CR/LF/NUL rules"),
        "duplicate_http_header": ("transport", "provider repeated a singleton HTTP framing header"),
        "invalid_content_type": ("transport", "provider Content-Type is not application/json UTF-8"),
        "forbidden_content_encoding": ("transport", "provider Content-Encoding is outside identity"),
        "invalid_content_length": ("transport", "provider Content-Length header is malformed"),
        "declared_length_over_2mib": ("truncation", "provider Content-Length exceeds 2 MiB ceiling"),
        "stream_over_2mib": ("truncation", "provider streamed body exceeds 2 MiB ceiling"),
        "content_length_mismatch": ("transport", "provider streamed byte count mismatched Content-Length"),
        "invalid_outer_json": ("schema", "provider outer body is not valid bounded UTF-8 JSON"),
        "invalid_jsonrpc_envelope": ("schema", "provider outer JSON-RPC 2.0 envelope is invalid"),
        "malformed_jsonrpc_error": ("schema", "provider JSON-RPC error object violated closed shape"),
        "jsonrpc_error_response": ("jsonrpc", "provider returned sanitized JSON-RPC error response"),
        "mcp_result_is_error": ("schema", "provider MCP result reported isError=true"),
        "invalid_mcp_content": ("schema", "provider MCP result content envelope is invalid"),
        "decoded_text_over_2mib": ("truncation", "provider decoded inner text exceeds 2 MiB ceiling"),
        "invalid_inner_json": ("schema", "provider inner MCP text is not valid bounded JSON"),
        "invalid_payload_shape": ("schema", "provider inner insights payload shape is invalid"),
        "invalid_paging_shape": ("schema", "provider paging object violated closed shape"),
        "non_empty_paging_next": ("pagination", "provider response carries non-empty paging.next cursor"),
        "non_empty_paging_previous": ("pagination", "provider response carries non-empty paging.previous cursor"),
        "too_many_campaign_rows": ("schema", "provider campaign row count exceeds 100-row ceiling"),
        "invalid_row_shape": ("schema", "provider campaign row is not a JSON object mapping"),
        "invalid_row_keys": ("schema", "provider campaign row contains unpinned or forbidden keys"),
        "invalid_campaign_id": ("schema", "provider campaign_id violated closed Meta grammar"),
        "unknown_campaign_id": ("schema", "provider campaign_id is absent from private resource directory"),
        "unscoped_campaign_resource": ("schema", "provider campaign resource is outside admitted scope"),
        "invalid_metric_value": ("schema", "provider campaign metric violated bounded numeric grammar"),
        "empty_row_metrics": ("schema", "provider campaign row omitted all Phase 1 base metrics"),
        "response_date_mismatch": ("date_mismatch", "provider row date_start/date_stop mismatched admitted day"),
        "reducer_output_invalid": ("reducer", "pinned reducer raised or returned malformed record shape"),
        "reducer_order_or_count_mismatch": ("reducer", "pinned reducer output order or count mismatched validated rows"),
        "duplicate_provider_observation": ("completeness", "provider emitted duplicate (resource_ref, day, metric) observation"),
    }
)

STATIC_DETAIL_BY_CODE: Final[Mapping[str, str]] = MappingProxyType(
    {code: spec[1] for code, spec in _WIRE_REJECTION_SPECS.items()}
)

_PRECONDITION_DETAIL_BY_CODE: Final[Mapping[str, str]] = MappingProxyType(
    {
        "invalid_wire_json": "wire JSON input violated strict bounded RFC 8259 grammar",
        "invalid_transport_limits": "transport_limits mismatched closed PipeboardTransportLimits",
        "invalid_private_object_id": "private_object_id violated closed Meta act_ grammar",
        "invalid_admitted_day": "admitted_day violated closed ISO-8601 calendar grammar",
        "invalid_envelope_precondition": "envelope parser precondition argument type is invalid",
        "invalid_chunk_type": "response body chunk must be exact bytes",
        "invalid_boundary_config": "private Pipeboard binding boundary configuration is invalid",
        "unregistered_private_binding": "admitted binding or scope is absent from private boundary",
        "invalid_fixture_call": "AdmittedFixtureCall failed driver or contract precondition check",
        "fixture_case_not_found": "no fixture case is registered for admitted_collection_locator",
        "duplicate_fixture_case": "conflicting fixture case already registered for locator",
        "recorded_batch_not_found": "no recorded observation batch exists for locator",
        "invalid_retrieval_context": "retrieval_context must be a valid RetrievalContext instance",
        "invalid_admitted_collection": "admitted collection is incompatible with Phase 1 Pipeboard contract",
        "admission_snapshot_mismatch": "admitted collection failed strict private snapshot or inventory binding",
        "invalid_reducer_callable": "reducer must be a callable row reducer",
    }
)


class PipeboardAdapterError(ClosedValidationError):
    """Value-silent precondition or wire error across the Pipeboard adapter boundary."""

    code: str

    def __init__(self, code: str) -> None:
        if type(code) is not str:
            raise ClosedValidationError("pipeboard_adapter_error: code must be str") from None
        detail = _PRECONDITION_DETAIL_BY_CODE.get(code) or STATIC_DETAIL_BY_CODE.get(code)
        if detail is None:
            raise ClosedValidationError(
                "pipeboard_adapter_error: unknown closed error code"
            ) from None
        super().__init__(f"pipeboard_adapter[{code}]: {detail}")
        self.code = code


class PipeboardWireRejection(PipeboardAdapterError):
    """Value-silent terminal provider wire/payload rejection mapped to ProviderObservationBatch."""

    category: ProviderErrorCategory
    outcome: TransportOutcome

    def __init__(
        self,
        code: str,
        category: ProviderErrorCategory,
        outcome: TransportOutcome,
    ) -> None:
        if type(code) is not str or code not in _WIRE_REJECTION_SPECS:
            raise ClosedValidationError(
                "pipeboard_wire_rejection: unknown closed wire rejection code"
            ) from None
        expected_cat = _WIRE_REJECTION_SPECS[code][0]
        if type(category) is not str or category != expected_cat:
            raise ClosedValidationError(
                "pipeboard_wire_rejection: category mismatch for wire rejection code"
            ) from None
        if not isinstance(outcome, TransportOutcome):
            raise ClosedValidationError(
                "pipeboard_wire_rejection: outcome must be TransportOutcome"
            ) from None
        super().__init__(code)
        self.category = category
        self.outcome = outcome


@dataclass(frozen=True, slots=True)
class _WireOutOfRangeInt:
    """Frozen sentinel for integer JSON tokens outside signed int64."""

    raw: str


@dataclass(frozen=True, slots=True)
class _WireDecimalToken:
    """Frozen sentinel for fractional or exponent JSON tokens parsed without binary float."""

    raw: str


@dataclass(slots=True)
class _JsonContainerFrame:
    kind: str
    container: Any
    pending_key: str | None = None


@dataclass(frozen=True, slots=True)
class ParsedPipeboardEnvelope:
    """Validated HTTP + JSON-RPC + MCP outer/inner Pipeboard envelope prior to Gates 1–3."""

    raw_inner_text: str
    has_is_error_false: bool
    rows: tuple[Mapping[str, Any], ...]
    transport_outcome: TransportOutcome

    def __post_init__(self) -> None:
        if (
            type(self.raw_inner_text) is not str
            or type(self.has_is_error_false) is not bool
            or not isinstance(self.rows, tuple)
            or not isinstance(self.transport_outcome, TransportOutcome)
        ):
            raise PipeboardAdapterError("invalid_envelope_precondition") from None


def clean_transport_outcome() -> TransportOutcome:
    """Return the clean HTTP 200 baseline `TransportOutcome`."""
    return _CLEAN_TRANSPORT_OUTCOME


def make_wire_rejection(code: str, **outcome_overrides: Any) -> PipeboardWireRejection:
    """Build a closed `PipeboardWireRejection` from `_WIRE_REJECTION_SPECS` and base outcome."""
    category = _WIRE_REJECTION_SPECS[code][0]
    outcome = (
        replace(_CLEAN_TRANSPORT_OUTCOME, **outcome_overrides)
        if outcome_overrides
        else _CLEAN_TRANSPORT_OUTCOME
    )
    return PipeboardWireRejection(code=code, category=category, outcome=outcome)


def build_pipeboard_insights_request(
    *,
    private_object_id: str,
    admitted_day: str,
    transport_limits: PipeboardTransportLimits = DEFAULT_PIPEBOARD_TRANSPORT_LIMITS,
) -> dict[str, Any]:
    """Construct the sole in-memory JSON-RPC `get_insights` wire request (ADR-0001 §4.1)."""
    if (
        not isinstance(transport_limits, PipeboardTransportLimits)
        or transport_limits != DEFAULT_PIPEBOARD_TRANSPORT_LIMITS
    ):
        raise PipeboardAdapterError("invalid_transport_limits") from None
    if (
        type(private_object_id) is not str
        or _META_ACCOUNT_ID_RE.fullmatch(private_object_id) is None
    ):
        raise PipeboardAdapterError("invalid_private_object_id") from None
    if type(admitted_day) is not str:
        raise PipeboardAdapterError("invalid_admitted_day") from None
    try:
        checked_day = validate_iso_date(admitted_day, field_name="admitted_day")
    except ClosedValidationError:
        raise PipeboardAdapterError("invalid_admitted_day") from None

    arguments: dict[str, Any] = {
        "object_id": private_object_id,
        "time_range": {"since": checked_day, "until": checked_day},
        "level": transport_limits.level,
        "limit": transport_limits.limit,
        "compact": transport_limits.compact,
    }
    if set(arguments.keys()).intersection(FORBIDDEN_PIPEBOARD_ARGUMENTS):
        raise PipeboardAdapterError("invalid_transport_limits") from None
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": transport_limits.jsonrpc_method,
        "params": {"name": transport_limits.tool_name, "arguments": arguments},
    }


def _skip_ws(raw: str, pos: int) -> int:
    n = len(raw)
    while pos < n and raw[pos] in _JSON_WHITESPACE:
        pos += 1
    return pos


def _parse_json_escape(raw: str, esc_pos: int) -> tuple[str, int]:
    if esc_pos >= len(raw):
        raise PipeboardAdapterError("invalid_wire_json") from None
    esc = raw[esc_pos]
    simple = _JSON_ESCAPES.get(esc)
    if simple is not None:
        return simple, esc_pos + 1
    if esc != "u":
        raise PipeboardAdapterError("invalid_wire_json") from None
    hex1 = raw[esc_pos + 1 : esc_pos + 5]
    if len(hex1) != 4 or _HEX4_RE.fullmatch(hex1) is None:
        raise PipeboardAdapterError("invalid_wire_json") from None
    u1 = int(hex1, 16)
    if 0xDC00 <= u1 <= 0xDFFF:
        raise PipeboardAdapterError("invalid_wire_json") from None
    if 0xD800 <= u1 <= 0xDBFF:
        if raw[esc_pos + 5 : esc_pos + 7] != "\\u":
            raise PipeboardAdapterError("invalid_wire_json") from None
        hex2 = raw[esc_pos + 7 : esc_pos + 11]
        if len(hex2) != 4 or _HEX4_RE.fullmatch(hex2) is None:
            raise PipeboardAdapterError("invalid_wire_json") from None
        u2 = int(hex2, 16)
        if not (0xDC00 <= u2 <= 0xDFFF):
            raise PipeboardAdapterError("invalid_wire_json") from None
        return chr(0x10000 + ((u1 - 0xD800) << 10) + (u2 - 0xDC00)), esc_pos + 11
    return chr(u1), esc_pos + 5


def _parse_json_string(raw: str, pos: int) -> tuple[str, int]:
    n = len(raw)
    if pos >= n or raw[pos] != '"':
        raise PipeboardAdapterError("invalid_wire_json") from None
    idx = pos + 1
    chars: list[str] = []
    while idx < n:
        ch = raw[idx]
        if ch == '"':
            return "".join(chars), idx + 1
        if ch == "\\":
            decoded, idx = _parse_json_escape(raw, idx + 1)
            chars.append(decoded)
            continue
        code = ord(ch)
        if code < 0x20 or 0xD800 <= code <= 0xDFFF:
            raise PipeboardAdapterError("invalid_wire_json") from None
        chars.append(ch)
        idx += 1
    raise PipeboardAdapterError("invalid_wire_json") from None


def _parse_json_number(
    raw: str, pos: int
) -> tuple[int | _WireOutOfRangeInt | _WireDecimalToken, int]:
    n = len(raw)
    end = pos
    while end < n and raw[end] not in _JSON_NUM_TERMINATORS:
        end += 1
        if end - pos > _MAX_WIRE_NUM_TOKEN_LEN:
            raise PipeboardAdapterError("invalid_wire_json") from None
    token = raw[pos:end]
    match = _WIRE_NUMBER_RE.fullmatch(token)
    if match is None:
        raise PipeboardAdapterError("invalid_wire_json") from None
    exp_str = match.group(2)
    if exp_str is not None and abs(int(exp_str, 10)) > _MAX_WIRE_EXPONENT_ABS:
        raise PipeboardAdapterError("invalid_wire_json") from None
    if "." in token or exp_str is not None:
        return _WireDecimalToken(raw=token), end
    int_val = int(token, 10)
    if _MIN_INT64 <= int_val <= MAX_INT64:
        return int_val, end
    return _WireOutOfRangeInt(raw=token), end


def _parse_json_scalar(raw: str, pos: int) -> tuple[Any, int]:
    ch = raw[pos]
    if ch == '"':
        return _parse_json_string(raw, pos)
    if ch == "t" and raw[pos : pos + 4] == "true":
        return True, pos + 4
    if ch == "f" and raw[pos : pos + 5] == "false":
        return False, pos + 5
    if ch == "n" and raw[pos : pos + 4] == "null":
        return None, pos + 4
    if ch == "-" or ("0" <= ch <= "9"):
        return _parse_json_number(raw, pos)
    raise PipeboardAdapterError("invalid_wire_json") from None


def _read_object_key_and_colon(
    raw: str, pos: int, frame: _JsonContainerFrame
) -> int:
    key, next_pos = _parse_json_string(raw, pos)
    if key in frame.container:
        raise PipeboardAdapterError("invalid_wire_json") from None
    colon_pos = _skip_ws(raw, next_pos)
    if colon_pos >= len(raw) or raw[colon_pos] != ":":
        raise PipeboardAdapterError("invalid_wire_json") from None
    frame.pending_key = key
    return colon_pos + 1


def _open_container(
    raw: str, pos: int, stack: list[_JsonContainerFrame], max_depth: int
) -> tuple[bool, Any, int]:
    if len(stack) + 1 > max_depth:
        raise PipeboardAdapterError("invalid_wire_json") from None
    opener = raw[pos]
    inner_pos = _skip_ws(raw, pos + 1)
    if inner_pos >= len(raw):
        raise PipeboardAdapterError("invalid_wire_json") from None
    if opener == "[":
        if raw[inner_pos] == "]":
            return True, [], inner_pos + 1
        stack.append(_JsonContainerFrame(kind="array", container=[]))
        return False, None, inner_pos
    if raw[inner_pos] == "}":
        return True, {}, inner_pos + 1
    obj_frame = _JsonContainerFrame(kind="object", container={})
    val_pos = _read_object_key_and_colon(raw, inner_pos, obj_frame)
    stack.append(obj_frame)
    return False, None, val_pos


def _attach_and_step_container(
    raw: str, pos: int, val: Any, stack: list[_JsonContainerFrame]
) -> tuple[str, Any, int]:
    top = stack[-1]
    if top.kind == "array":
        top.container.append(val)
    else:
        key = top.pending_key
        if key is None or key in top.container:
            raise PipeboardAdapterError("invalid_wire_json") from None
        top.container[key] = val
        top.pending_key = None

    delim_pos = _skip_ws(raw, pos)
    if delim_pos >= len(raw):
        raise PipeboardAdapterError("invalid_wire_json") from None
    delim = raw[delim_pos]
    if top.kind == "array":
        if delim == ",":
            return "value", None, delim_pos + 1
        if delim == "]":
            stack.pop()
            return "after_value", top.container, delim_pos + 1
        raise PipeboardAdapterError("invalid_wire_json") from None
    if delim == ",":
        key_pos = _skip_ws(raw, delim_pos + 1)
        next_val_pos = _read_object_key_and_colon(raw, key_pos, top)
        return "value", None, next_val_pos
    if delim == "}":
        stack.pop()
        return "after_value", top.container, delim_pos + 1
    raise PipeboardAdapterError("invalid_wire_json") from None


def loads_pipeboard_wire_json(raw_utf8: str, *, max_depth: int = 16) -> Any:
    """Iterative explicit-stack RFC 8259 wire JSON parser with lexical numeric ceilings."""
    if type(raw_utf8) is not str or type(max_depth) is not int or max_depth < 1:
        raise PipeboardAdapterError("invalid_wire_json") from None
    n = len(raw_utf8)
    pos = _skip_ws(raw_utf8, 0)
    if pos >= n:
        raise PipeboardAdapterError("invalid_wire_json") from None

    stack: list[_JsonContainerFrame] = []
    mode = "value"
    current_val: Any = None
    while True:
        if mode == "value":
            pos = _skip_ws(raw_utf8, pos)
            if pos >= n:
                raise PipeboardAdapterError("invalid_wire_json") from None
            if raw_utf8[pos] in ("[", "{"):
                closed, current_val, pos = _open_container(raw_utf8, pos, stack, max_depth)
                mode = "after_value" if closed else "value"
            else:
                current_val, pos = _parse_json_scalar(raw_utf8, pos)
                mode = "after_value"
        else:
            if not stack:
                break
            mode, current_val, pos = _attach_and_step_container(raw_utf8, pos, current_val, stack)

    if _skip_ws(raw_utf8, pos) != n:
        raise PipeboardAdapterError("invalid_wire_json") from None
    return current_val


def _has_surrogate(text: str) -> bool:
    return any(0xD800 <= ord(ch) <= 0xDFFF for ch in text)


def _validate_content_type(raw_ct: str | None) -> None:
    if raw_ct is None:
        raise make_wire_rejection("invalid_content_type", media_and_encoding_valid=False) from None
    parts = raw_ct.split(";")
    if len(parts) > 2 or parts[0].strip(" \t").lower() != "application/json":
        raise make_wire_rejection("invalid_content_type", media_and_encoding_valid=False) from None
    if len(parts) == 2 and parts[1].strip(" \t").lower() != "charset=utf-8":
        raise make_wire_rejection("invalid_content_type", media_and_encoding_valid=False) from None


def _validate_http_headers(
    headers: Sequence[tuple[str, str]],
    *,
    max_streamed_bytes: int,
) -> int | None:
    normalized: list[tuple[str, str]] = []
    for item in headers:
        if type(item) is not tuple or len(item) != 2:
            raise make_wire_rejection("malformed_http_headers", media_and_encoding_valid=False) from None
        k, v = item
        if (
            type(k) is not str
            or type(v) is not str
            or _HEADER_TOKEN_RE.fullmatch(k) is None
            or "\r" in v
            or "\n" in v
            or "\x00" in v
            or _has_surrogate(v)
        ):
            raise make_wire_rejection("malformed_http_headers", media_and_encoding_valid=False) from None
        normalized.append((k.lower(), v))

    singletons: dict[str, str] = {}
    for lk, v in normalized:
        if lk in _SINGLETON_HTTP_HEADERS:
            if lk in singletons:
                raise make_wire_rejection("duplicate_http_header", media_and_encoding_valid=False) from None
            singletons[lk] = v

    _validate_content_type(singletons.get("content-type"))
    raw_ce = singletons.get("content-encoding")
    if raw_ce is not None and raw_ce.strip(" \t").lower() not in ("", "identity"):
        raise make_wire_rejection("forbidden_content_encoding", media_and_encoding_valid=False) from None

    raw_cl = singletons.get("content-length")
    if raw_cl is None:
        return None
    stripped_cl = raw_cl.strip(" \t")
    if _CONTENT_LENGTH_RE.fullmatch(stripped_cl) is None:
        raise make_wire_rejection("invalid_content_length", media_and_encoding_valid=False) from None
    declared = int(stripped_cl, 10)
    if declared > max_streamed_bytes:
        raise make_wire_rejection("declared_length_over_2mib", truncated_2mib=True) from None
    return declared


def _consume_bounded_body_stream(
    body_chunks: Iterable[bytes],
    *,
    read_chunk_bytes: int,
    max_streamed_bytes: int,
    declared_length: int | None,
) -> bytes:
    buf = bytearray()
    for chunk in body_chunks:
        if type(chunk) is not bytes:
            raise PipeboardAdapterError("invalid_chunk_type") from None
        offset = 0
        chunk_len = len(chunk)
        while offset < chunk_len:
            piece = chunk[offset : offset + read_chunk_bytes]
            buf.extend(piece)
            if len(buf) > max_streamed_bytes:
                raise make_wire_rejection("stream_over_2mib", truncated_2mib=True) from None
            offset += read_chunk_bytes
    if declared_length is not None and len(buf) != declared_length:
        raise make_wire_rejection("content_length_mismatch", media_and_encoding_valid=False) from None
    return bytes(buf)


def _validate_outer_jsonrpc_envelope(raw_bytes: bytes) -> dict[str, Any]:
    try:
        outer_text = raw_bytes.decode("utf-8", errors="strict")
        outer_obj = loads_pipeboard_wire_json(outer_text, max_depth=16)
    except (UnicodeDecodeError, PipeboardAdapterError):
        raise make_wire_rejection("invalid_outer_json", payload_schema_valid=False) from None

    if type(outer_obj) is not dict:
        raise make_wire_rejection("invalid_jsonrpc_envelope", payload_schema_valid=False) from None
    keys = set(outer_obj.keys())
    if (
        keys not in ({"jsonrpc", "id", "result"}, {"jsonrpc", "id", "error"})
        or outer_obj["jsonrpc"] != "2.0"
        or type(outer_obj["id"]) is not int
        or outer_obj["id"] != 1
    ):
        raise make_wire_rejection("invalid_jsonrpc_envelope", payload_schema_valid=False) from None

    if "error" in outer_obj:
        err = outer_obj["error"]
        if (
            type(err) is not dict
            or not ({"code", "message"} <= set(err.keys()) <= {"code", "message", "data"})
            or type(err.get("code")) is not int
            or type(err.get("message")) is not str
        ):
            raise make_wire_rejection("malformed_jsonrpc_error", payload_schema_valid=False) from None
        raise make_wire_rejection("jsonrpc_error_response", jsonrpc_error=True) from None

    result = outer_obj["result"]
    if type(result) is not dict:
        raise make_wire_rejection("invalid_mcp_content", payload_schema_valid=False) from None
    return result


def _validate_paging_object(paging: Any) -> None:
    if paging is None:
        return
    if type(paging) is not dict or not set(paging.keys()).issubset(
        {"cursors", "next", "previous"}
    ):
        raise make_wire_rejection("invalid_paging_shape", payload_schema_valid=False) from None
    if "cursors" in paging and paging["cursors"] is not None:
        cursors = paging["cursors"]
        if (
            type(cursors) is not dict
            or not set(cursors.keys()).issubset({"before", "after"})
            or any(type(v) is not str for v in cursors.values())
        ):
            raise make_wire_rejection("invalid_paging_shape", payload_schema_valid=False) from None
    for field_name in ("next", "previous"):
        if field_name in paging:
            val = paging[field_name]
            if val is not None and type(val) is not str:
                raise make_wire_rejection("invalid_paging_shape", payload_schema_valid=False) from None
    if paging.get("next") not in (None, ""):
        raise make_wire_rejection("non_empty_paging_next", non_empty_continuation=True) from None
    if paging.get("previous") not in (None, ""):
        raise make_wire_rejection("non_empty_paging_previous", non_empty_continuation=True) from None


def _extract_mcp_result_text(
    result: object, *, max_decoded_text_bytes: int
) -> tuple[str, bool]:
    if type(result) is not dict or set(result.keys()) not in (
        {"content"},
        {"content", "isError"},
    ):
        raise make_wire_rejection("invalid_mcp_content", payload_schema_valid=False) from None
    has_is_error_false = False
    if "isError" in result:
        if result["isError"] is True:
            raise make_wire_rejection("mcp_result_is_error", payload_schema_valid=False) from None
        if result["isError"] is not False:
            raise make_wire_rejection("invalid_mcp_content", payload_schema_valid=False) from None
        has_is_error_false = True

    content = result["content"]
    if type(content) is not list or len(content) != 1:
        raise make_wire_rejection("invalid_mcp_content", payload_schema_valid=False) from None
    item = content[0]
    if (
        type(item) is not dict
        or set(item.keys()) != {"type", "text"}
        or item["type"] != "text"
        or type(item["text"]) is not str
    ):
        raise make_wire_rejection("invalid_mcp_content", payload_schema_valid=False) from None
    raw_inner_text = item["text"]
    try:
        encoded_inner = raw_inner_text.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise make_wire_rejection("invalid_inner_json", payload_schema_valid=False) from None
    if len(encoded_inner) > max_decoded_text_bytes:
        raise make_wire_rejection("decoded_text_over_2mib", truncated_2mib=True) from None
    return raw_inner_text, has_is_error_false


def parse_pipeboard_mcp_result(
    result: object,
    *,
    transport_limits: PipeboardTransportLimits = DEFAULT_PIPEBOARD_TRANSPORT_LIMITS,
) -> tuple[str, bool, tuple[Mapping[str, Any], ...]]:
    """Validate Step 9 MCP `result` object and inner `get_insights` payload."""
    if (
        not isinstance(transport_limits, PipeboardTransportLimits)
        or transport_limits != DEFAULT_PIPEBOARD_TRANSPORT_LIMITS
    ):
        raise PipeboardAdapterError("invalid_transport_limits") from None
    raw_inner_text, has_is_error_false = _extract_mcp_result_text(
        result, max_decoded_text_bytes=transport_limits.max_decoded_text_bytes
    )
    try:
        payload = loads_pipeboard_wire_json(raw_inner_text, max_depth=16)
    except PipeboardAdapterError:
        raise make_wire_rejection("invalid_inner_json", payload_schema_valid=False) from None

    if (
        type(payload) is not dict
        or "data" not in payload
        or not set(payload.keys()).issubset({"data", "paging"})
    ):
        raise make_wire_rejection("invalid_payload_shape", payload_schema_valid=False) from None
    if "paging" in payload:
        _validate_paging_object(payload["paging"])
    rows = payload["data"]
    if type(rows) is not list:
        raise make_wire_rejection("invalid_payload_shape", payload_schema_valid=False) from None
    if len(rows) > transport_limits.max_campaign_rows:
        raise make_wire_rejection("too_many_campaign_rows", payload_schema_valid=False) from None
    return raw_inner_text, has_is_error_false, tuple(rows)


def _validate_envelope_preconditions_and_status(
    *,
    network_ok: bool,
    http_status: int | None,
    headers: Sequence[tuple[str, str]],
    body_chunks: Iterable[bytes],
    transport_limits: PipeboardTransportLimits,
) -> None:
    if (
        not isinstance(transport_limits, PipeboardTransportLimits)
        or transport_limits != DEFAULT_PIPEBOARD_TRANSPORT_LIMITS
    ):
        raise PipeboardAdapterError("invalid_transport_limits") from None
    if (
        type(network_ok) is not bool
        or isinstance(headers, (str, bytes, bytearray))
        or not isinstance(headers, Sequence)
        or isinstance(body_chunks, (str, bytes, bytearray))
        or not isinstance(body_chunks, Iterable)
    ):
        raise PipeboardAdapterError("invalid_envelope_precondition") from None
    if not network_ok:
        raise make_wire_rejection("network_error", network_ok=False, http_status=None) from None
    if http_status is None:
        raise make_wire_rejection("missing_http_status", http_status=None) from None
    if type(http_status) is not int or not (100 <= http_status <= 999):
        raise make_wire_rejection("invalid_http_status", http_status=None) from None
    if http_status in (401, 403):
        raise make_wire_rejection("http_auth_error", http_status=http_status, auth_ok=False) from None
    if http_status != 200:
        raise make_wire_rejection("http_status_not_200", http_status=http_status) from None


def parse_pipeboard_http_and_mcp_envelope(
    *,
    network_ok: bool,
    http_status: int | None,
    headers: Sequence[tuple[str, str]],
    body_chunks: Iterable[bytes],
    transport_limits: PipeboardTransportLimits = DEFAULT_PIPEBOARD_TRANSPORT_LIMITS,
) -> ParsedPipeboardEnvelope:
    """Validate Pipeboard HTTP status, headers, 2 MiB stream, JSON-RPC, and MCP result in exact 9-step order."""
    _validate_envelope_preconditions_and_status(
        network_ok=network_ok,
        http_status=http_status,
        headers=headers,
        body_chunks=body_chunks,
        transport_limits=transport_limits,
    )
    declared_len = _validate_http_headers(
        headers, max_streamed_bytes=transport_limits.max_streamed_bytes
    )
    raw_bytes = _consume_bounded_body_stream(
        body_chunks,
        read_chunk_bytes=transport_limits.read_chunk_bytes,
        max_streamed_bytes=transport_limits.max_streamed_bytes,
        declared_length=declared_len,
    )
    result = _validate_outer_jsonrpc_envelope(raw_bytes)
    raw_inner_text, has_is_error_false, rows = parse_pipeboard_mcp_result(
        result, transport_limits=transport_limits
    )
    return ParsedPipeboardEnvelope(
        raw_inner_text=raw_inner_text,
        has_is_error_false=has_is_error_false,
        rows=rows,
        transport_outcome=_CLEAN_TRANSPORT_OUTCOME,
    )


__all__ = [
    "DEFAULT_PIPEBOARD_TRANSPORT_LIMITS",
    "ParsedPipeboardEnvelope",
    "PipeboardAdapterError",
    "PipeboardWireRejection",
    "STATIC_DETAIL_BY_CODE",
    "build_pipeboard_insights_request",
    "clean_transport_outcome",
    "loads_pipeboard_wire_json",
    "make_wire_rejection",
    "parse_pipeboard_http_and_mcp_envelope",
    "parse_pipeboard_mcp_result",
]
