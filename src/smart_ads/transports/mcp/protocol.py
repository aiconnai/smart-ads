"""Zero-recursion RFC 8259 & JSON-RPC 2.0 wire parser for MCP deny-before-I/O (ADR-0001 §3.3)."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import re
from types import MappingProxyType
from typing import Any, Final, Literal, TypeAlias

from smart_ads.contracts.jcs import (
    MAX_JCS_SAFE_INT,
    MIN_JCS_SAFE_INT,
    canonicalize_jcs,
)
from smart_ads.contracts.scalars import ClosedValidationError

MAX_MCP_BODY_BYTES: Final[int] = 65_536
MAX_MCP_NESTING_DEPTH: Final[int] = 8
_MAX_REQUEST_ID_UTF8_BYTES: Final[int] = 256

JsonRpcRequestId: TypeAlias = str | int | None

McpRejectionCaseId: TypeAlias = Literal[
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
    "invalid_jsonrpc_envelope",
]

_ALLOWED_CASE_IDS: Final[frozenset[str]] = frozenset(
    {
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
        "invalid_jsonrpc_envelope",
    }
)

_ALLOWED_ENVELOPE_KEYS: Final[frozenset[str]] = frozenset(
    {"jsonrpc", "id", "method", "params"}
)
_REQUIRED_ENVELOPE_KEYS: Final[frozenset[str]] = frozenset(
    {"jsonrpc", "id", "method"}
)

_WS_RE: Final[re.Pattern[str]] = re.compile(r"[ \t\n\r]*")
_STRING_CHUNK_RE: Final[re.Pattern[str]] = re.compile(r'[^"\\\x00-\x1f]*')
_HEX4_ESC_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-fA-F]{4}")
_NUMBER_RE: Final[re.Pattern[str]] = re.compile(
    r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?"
)

_UNESCAPE_MAP: Final[Mapping[str, str]] = MappingProxyType(
    {
        '"': '"',
        "\\": "\\",
        "/": "/",
        "b": "\b",
        "f": "\f",
        "n": "\n",
        "r": "\r",
        "t": "\t",
    }
)

_MODE_VALUE: Final[int] = 0
_MODE_OBJ_KEY: Final[int] = 1
_MODE_AFTER_VALUE: Final[int] = 2


class _JsonSyntaxError(Exception):
    """Internal sentinel for genuine RFC 8259 JSON syntax violations (-32700)."""


def _has_control_or_surrogate(value: str) -> bool:
    for ch in value:
        code = ord(ch)
        if code < 0x20 or code == 0x7F or (0xD800 <= code <= 0xDFFF):
            return True
    return False


def _has_surrogate(value: str) -> bool:
    for ch in value:
        code = ord(ch)
        if 0xD800 <= code <= 0xDFFF:
            return True
    return False


def _is_valid_jsonrpc_request_id(value: object) -> bool:
    if value is None:
        return True
    if type(value) is int:
        return MIN_JCS_SAFE_INT <= value <= MAX_JCS_SAFE_INT
    if type(value) is str:
        if _has_control_or_surrogate(value):
            return False
        utf8_len = len(value.encode("utf-8"))
        return 1 <= utf8_len <= _MAX_REQUEST_ID_UTF8_BYTES
    return False


def _is_valid_jsonrpc_method_str(value: object) -> bool:
    if type(value) is not str or len(value) == 0:
        return False
    return not _has_control_or_surrogate(value)


@dataclass(frozen=True, slots=True)
class _NonExactJsonNumber:
    """Syntactically valid RFC 8259 number outside exact I-JSON safe integer bounds."""

    raw_lexeme: str

    def __post_init__(self) -> None:
        if type(self.raw_lexeme) is not str or len(self.raw_lexeme) == 0:
            raise ClosedValidationError(
                "_NonExactJsonNumber.raw_lexeme must be a non-empty str"
            )


@dataclass(frozen=True, slots=True)
class McpProtocolRejection:
    """Closed JSON-RPC 2.0 error descriptor without error.data or echoed input."""

    code: int
    message: str
    request_id: JsonRpcRequestId
    case_id: McpRejectionCaseId

    def __post_init__(self) -> None:
        if type(self.code) is not int or not (
            MIN_JCS_SAFE_INT <= self.code <= MAX_JCS_SAFE_INT
        ):
            raise ClosedValidationError(
                "McpProtocolRejection.code must be an exact I-JSON safe int"
            )
        if (
            type(self.message) is not str
            or len(self.message) == 0
            or _has_surrogate(self.message)
        ):
            raise ClosedValidationError(
                "McpProtocolRejection.message must be a non-empty valid UTF-8 str"
            )
        if not _is_valid_jsonrpc_request_id(self.request_id):
            raise ClosedValidationError(
                "McpProtocolRejection.request_id violates JSON-RPC 2.0 ID bounds"
            )
        if type(self.case_id) is not str or self.case_id not in _ALLOWED_CASE_IDS:
            raise ClosedValidationError(
                f"McpProtocolRejection.case_id {self.case_id!r} is outside closed matrix"
            )

    def to_dict(self) -> dict[str, Any]:
        """Build the closed JSON-RPC 2.0 error response dictionary."""
        return {
            "jsonrpc": "2.0",
            "id": self.request_id,
            "error": {
                "code": self.code,
                "message": self.message,
            },
        }

    def to_wire_bytes(self) -> bytes:
        """Serialize the rejection to canonical RFC 8785 JCS UTF-8 wire bytes."""
        return canonicalize_jcs(self.to_dict())


@dataclass(frozen=True, slots=True)
class ParsedJsonRpcEnvelope:
    """Validated JSON-RPC 2.0 request envelope prior to method and parameter checks."""

    request_id: JsonRpcRequestId
    method: str
    has_params: bool
    params_raw: Any

    def __post_init__(self) -> None:
        if not _is_valid_jsonrpc_request_id(self.request_id):
            raise ClosedValidationError(
                "ParsedJsonRpcEnvelope.request_id violates JSON-RPC 2.0 ID bounds"
            )
        if not _is_valid_jsonrpc_method_str(self.method):
            raise ClosedValidationError(
                "ParsedJsonRpcEnvelope.method must be a non-empty non-control str"
            )
        if type(self.has_params) is not bool:
            raise ClosedValidationError(
                "ParsedJsonRpcEnvelope.has_params must be bool"
            )
        if not self.has_params and self.params_raw is not None:
            raise ClosedValidationError(
                "ParsedJsonRpcEnvelope.params_raw must be None when has_params is False"
            )


@dataclass(slots=True)
class _ParseFrame:
    """Explicit iterative stack frame for RFC 8259 container scanning."""

    is_object: bool
    depth: int
    container: dict[str, Any] | list[Any] | None
    seen_keys: set[str] | None
    pending_key: str | None = None


def _skip_ws(text: str, pos: int) -> int:
    match = _WS_RE.match(text, pos)
    return match.end() if match is not None else pos


def _scan_json_string(text: str, pos: int) -> tuple[str, int, bool]:
    n = len(text)
    idx = pos + 1
    first_match = _STRING_CHUNK_RE.match(text, idx)
    end = first_match.end() if first_match is not None else idx
    if end < n and text[end] == '"':
        return text[idx:end], end + 1, False

    chunks: list[str] = []
    if end > idx:
        chunks.append(text[idx:end])
    idx = end
    lone_surrogate = False

    while True:
        chunk_match = _STRING_CHUNK_RE.match(text, idx)
        end = chunk_match.end() if chunk_match is not None else idx
        if end > idx:
            chunks.append(text[idx:end])
        if end >= n:
            raise _JsonSyntaxError("unterminated JSON string")

        stop_ch = text[end]
        if stop_ch == '"':
            return "".join(chunks), end + 1, lone_surrogate
        if ord(stop_ch) < 0x20:
            raise _JsonSyntaxError("unescaped ASCII control character in string")

        # stop_ch == "\\"
        if end + 1 >= n:
            raise _JsonSyntaxError("unterminated string escape")
        esc = text[end + 1]
        mapped = _UNESCAPE_MAP.get(esc)
        if mapped is not None:
            chunks.append(mapped)
            idx = end + 2
            continue
        if esc != "u":
            raise _JsonSyntaxError("invalid JSON escape sequence")

        if end + 6 > n or _HEX4_ESC_RE.fullmatch(text, end + 2, end + 6) is None:
            raise _JsonSyntaxError("invalid \\uXXXX escape sequence")
        code_unit = int(text[end + 2 : end + 6], 16)
        idx = end + 6

        if 0xD800 <= code_unit <= 0xDBFF:
            if (
                idx + 6 <= n
                and text.startswith("\\u", idx)
                and _HEX4_ESC_RE.fullmatch(text, idx + 2, idx + 6) is not None
            ):
                low_unit = int(text[idx + 2 : idx + 6], 16)
                if 0xDC00 <= low_unit <= 0xDFFF:
                    astral = (
                        0x10000
                        + ((code_unit - 0xD800) << 10)
                        + (low_unit - 0xDC00)
                    )
                    chunks.append(chr(astral))
                    idx += 6
                    continue
            lone_surrogate = True
            chunks.append("\ufffd")
        elif 0xDC00 <= code_unit <= 0xDFFF:
            lone_surrogate = True
            chunks.append("\ufffd")
        else:
            chunks.append(chr(code_unit))


def _scan_json_number(
    text: str, pos: int
) -> tuple[int | _NonExactJsonNumber, int]:
    match = _NUMBER_RE.match(text, pos)
    if match is None:
        raise _JsonSyntaxError("invalid JSON number token")
    end = match.end()
    lexeme = text[pos:end]
    if (
        "." not in lexeme
        and "e" not in lexeme
        and "E" not in lexeme
        and len(lexeme) <= 20
    ):
        parsed_int = int(lexeme, 10)
        if MIN_JCS_SAFE_INT <= parsed_int <= MAX_JCS_SAFE_INT:
            return parsed_int, end
    return _NonExactJsonNumber(raw_lexeme=lexeme), end


def _parse_rfc8259_iterative(
    text: str,
) -> tuple[Any, bool, bool, bool, int]:
    n = len(text)
    pos = _skip_ws(text, 0)
    if pos >= n:
        raise _JsonSyntaxError("empty JSON document")

    stack: list[_ParseFrame] = []
    max_depth = 0
    lone_surrogate_seen = False
    duplicate_key_seen = False
    root_is_dict_or_list = False
    current_value: Any = None
    root_value: Any = None
    mode = _MODE_VALUE

    while True:
        if mode == _MODE_VALUE:
            pos = _skip_ws(text, pos)
            if pos >= n:
                raise _JsonSyntaxError("unexpected EOF expecting value")
            ch = text[pos]
            if ch == "{":
                new_depth = len(stack) + 1
                if new_depth > max_depth:
                    max_depth = new_depth
                if new_depth == 1:
                    root_is_dict_or_list = True
                pos = _skip_ws(text, pos + 1)
                if pos >= n:
                    raise _JsonSyntaxError("unterminated JSON object")
                if text[pos] == "}":
                    pos += 1
                    current_value = (
                        {} if new_depth <= MAX_MCP_NESTING_DEPTH else None
                    )
                    mode = _MODE_AFTER_VALUE
                    continue
                stack.append(
                    _ParseFrame(
                        is_object=True,
                        depth=new_depth,
                        container={}
                        if new_depth <= MAX_MCP_NESTING_DEPTH
                        else None,
                        seen_keys=set(),
                    )
                )
                mode = _MODE_OBJ_KEY
                continue

            if ch == "[":
                new_depth = len(stack) + 1
                if new_depth > max_depth:
                    max_depth = new_depth
                if new_depth == 1:
                    root_is_dict_or_list = True
                pos = _skip_ws(text, pos + 1)
                if pos >= n:
                    raise _JsonSyntaxError("unterminated JSON array")
                if text[pos] == "]":
                    pos += 1
                    current_value = (
                        [] if new_depth <= MAX_MCP_NESTING_DEPTH else None
                    )
                    mode = _MODE_AFTER_VALUE
                    continue
                stack.append(
                    _ParseFrame(
                        is_object=False,
                        depth=new_depth,
                        container=[]
                        if new_depth <= MAX_MCP_NESTING_DEPTH
                        else None,
                        seen_keys=None,
                    )
                )
                mode = _MODE_VALUE
                continue

            if ch == '"':
                val_str, pos, had_lone = _scan_json_string(text, pos)
                if had_lone:
                    lone_surrogate_seen = True
                current_value = val_str
                mode = _MODE_AFTER_VALUE
                continue

            if ch == "t":
                if not text.startswith("true", pos):
                    raise _JsonSyntaxError("invalid literal")
                pos += 4
                current_value = True
                mode = _MODE_AFTER_VALUE
                continue

            if ch == "f":
                if not text.startswith("false", pos):
                    raise _JsonSyntaxError("invalid literal")
                pos += 5
                current_value = False
                mode = _MODE_AFTER_VALUE
                continue

            if ch == "n":
                if not text.startswith("null", pos):
                    raise _JsonSyntaxError("invalid literal")
                pos += 4
                current_value = None
                mode = _MODE_AFTER_VALUE
                continue

            if ch == "-" or ("0" <= ch <= "9"):
                current_value, pos = _scan_json_number(text, pos)
                mode = _MODE_AFTER_VALUE
                continue

            raise _JsonSyntaxError("unexpected character in JSON value")

        elif mode == _MODE_OBJ_KEY:
            pos = _skip_ws(text, pos)
            if pos >= n or text[pos] != '"':
                raise _JsonSyntaxError("expected object member key string")
            key_str, pos, had_lone = _scan_json_string(text, pos)
            if had_lone:
                lone_surrogate_seen = True
            top = stack[-1]
            seen = top.seen_keys
            if seen is not None:
                if key_str in seen:
                    duplicate_key_seen = True
                else:
                    seen.add(key_str)
            top.pending_key = key_str

            pos = _skip_ws(text, pos)
            if pos >= n or text[pos] != ":":
                raise _JsonSyntaxError("expected ':' after object member key")
            pos += 1
            mode = _MODE_VALUE
            continue

        else:
            # mode == _MODE_AFTER_VALUE
            if not stack:
                root_value = current_value
                break

            top = stack[-1]
            container = top.container
            if container is not None:
                if top.is_object:
                    key_name = top.pending_key
                    if key_name is None or not isinstance(container, dict):
                        raise ClosedValidationError(
                            "internal parser state error: missing object key or dict"
                        )
                    container[key_name] = current_value
                    top.pending_key = None
                else:
                    if not isinstance(container, list):
                        raise ClosedValidationError(
                            "internal parser state error: expected list container"
                        )
                    container.append(current_value)
            else:
                top.pending_key = None

            pos = _skip_ws(text, pos)
            if pos >= n:
                raise _JsonSyntaxError("unterminated JSON container")
            delim = text[pos]
            if delim == ",":
                pos += 1
                mode = _MODE_OBJ_KEY if top.is_object else _MODE_VALUE
                continue
            if top.is_object and delim == "}":
                pos += 1
                finished = stack.pop()
                current_value = finished.container
                mode = _MODE_AFTER_VALUE
                continue
            if (not top.is_object) and delim == "]":
                pos += 1
                finished = stack.pop()
                current_value = finished.container
                mode = _MODE_AFTER_VALUE
                continue
            raise _JsonSyntaxError("unexpected delimiter in JSON container")

    pos = _skip_ws(text, pos)
    if pos != n:
        raise _JsonSyntaxError("trailing non-whitespace tokens after root value")

    return (
        root_value,
        root_is_dict_or_list,
        lone_surrogate_seen,
        duplicate_key_seen,
        max_depth,
    )


def parse_mcp_wire_bytes(
    raw_body: bytes,
) -> dict[str, Any] | McpProtocolRejection:
    """Enforce 64 KiB, strict UTF-8, iterative RFC 8259, depth<=8, and duplicate-key rejection."""
    if type(raw_body) is not bytes:
        raise ClosedValidationError("raw_body must be bytes")

    if len(raw_body) > MAX_MCP_BODY_BYTES:
        return McpProtocolRejection(
            code=-32600,
            message="Invalid Request",
            request_id=None,
            case_id="body_over_64k",
        )

    try:
        text = raw_body.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return McpProtocolRejection(
            code=-32700,
            message="Parse error",
            request_id=None,
            case_id="invalid_utf8",
        )

    try:
        (
            root_value,
            root_is_dict_or_list,
            lone_surrogate_seen,
            duplicate_key_seen,
            max_depth,
        ) = _parse_rfc8259_iterative(text)
    except _JsonSyntaxError:
        return McpProtocolRejection(
            code=-32700,
            message="Parse error",
            request_id=None,
            case_id="malformed_json",
        )

    if lone_surrogate_seen:
        return McpProtocolRejection(
            code=-32600,
            message="Invalid Request",
            request_id=None,
            case_id="non_object_request"
            if not root_is_dict_or_list
            else "invalid_jsonrpc_envelope",
        )

    if duplicate_key_seen:
        return McpProtocolRejection(
            code=-32600,
            message="Invalid Request",
            request_id=None,
            case_id="duplicate_json_key",
        )

    if max_depth > MAX_MCP_NESTING_DEPTH:
        return McpProtocolRejection(
            code=-32600,
            message="Invalid Request",
            request_id=None,
            case_id="nesting_depth_over_8",
        )

    if isinstance(root_value, list):
        return McpProtocolRejection(
            code=-32600,
            message="Invalid Request",
            request_id=None,
            case_id="batch_array",
        )

    if not isinstance(root_value, dict):
        return McpProtocolRejection(
            code=-32600,
            message="Invalid Request",
            request_id=None,
            case_id="non_object_request",
        )

    return root_value


def validate_jsonrpc_request_envelope(
    root_obj: dict[str, Any],
) -> ParsedJsonRpcEnvelope | McpProtocolRejection:
    """Validate JSON-RPC 2.0 top-level envelope members prior to method/params dispatch."""
    if type(root_obj) is not dict:
        raise ClosedValidationError("root_obj must be dict")
    for key in root_obj:
        if type(key) is not str:
            raise ClosedValidationError("root_obj keys must be str")

    keys = set(root_obj.keys())
    if not _REQUIRED_ENVELOPE_KEYS.issubset(keys) or not keys.issubset(
        _ALLOWED_ENVELOPE_KEYS
    ):
        return McpProtocolRejection(
            code=-32600,
            message="Invalid Request",
            request_id=None,
            case_id="invalid_jsonrpc_envelope",
        )

    jsonrpc_ver = root_obj["jsonrpc"]
    if type(jsonrpc_ver) is not str or jsonrpc_ver != "2.0":
        return McpProtocolRejection(
            code=-32600,
            message="Invalid Request",
            request_id=None,
            case_id="invalid_jsonrpc_envelope",
        )

    req_id = root_obj["id"]
    if not _is_valid_jsonrpc_request_id(req_id):
        return McpProtocolRejection(
            code=-32600,
            message="Invalid Request",
            request_id=None,
            case_id="invalid_jsonrpc_envelope",
        )

    method = root_obj["method"]
    if not _is_valid_jsonrpc_method_str(method):
        return McpProtocolRejection(
            code=-32600,
            message="Invalid Request",
            request_id=None,
            case_id="invalid_jsonrpc_envelope",
        )

    has_params = "params" in root_obj
    return ParsedJsonRpcEnvelope(
        request_id=req_id,
        method=method,
        has_params=has_params,
        params_raw=root_obj.get("params"),
    )


def serialize_jsonrpc_result(
    request_id: JsonRpcRequestId, result: Mapping[str, Any]
) -> bytes:
    """Serialize a successful JSON-RPC 2.0 response envelope to canonical RFC 8785 JCS bytes."""
    if not _is_valid_jsonrpc_request_id(request_id):
        raise ClosedValidationError(
            "serialize_jsonrpc_result: request_id violates JSON-RPC 2.0 ID bounds"
        )
    if not isinstance(result, Mapping):
        raise ClosedValidationError(
            "serialize_jsonrpc_result: result must be a Mapping"
        )
    for key in result:
        if type(key) is not str:
            raise ClosedValidationError(
                "serialize_jsonrpc_result: result keys must be str"
            )
    return canonicalize_jcs(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": dict(result),
        }
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
