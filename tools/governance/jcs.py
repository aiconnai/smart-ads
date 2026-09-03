"""RFC 8785 JSON Canonicalization Scheme (JCS) — dependency-free subset.

Implements the subset of RFC 8785 needed by the Smart Ads P1 signing profile:
dict / list / str / int / bool / None. Object member names are sorted by their
UTF-16 code-unit sequence (RFC 8785 section 3.2.3), not by raw Unicode code
point and not by UTF-8 byte order. Strings are escaped per RFC 8785 section
3.2.2.2. Floats, NaN/Infinity, non-string object keys and any other Python
type are rejected — the Smart Ads envelopes never carry floating point
members, so silently accepting one would hide a modeling bug.
"""
from __future__ import annotations

import json
from typing import Any

_SHORT_ESCAPES = {
    "\\": "\\\\",
    '"': '\\"',
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


def _utf16_key(key: str) -> bytes:
    """UTF-16BE encoding of a member name, used only as a sort key."""
    return key.encode("utf-16-be")


def _escape_string(value: str) -> str:
    out: list[str] = ['"']
    for ch in value:
        if ch in _SHORT_ESCAPES:
            out.append(_SHORT_ESCAPES[ch])
        elif ch <= "\x1f":
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _dump(value: Any, out: list[str]) -> None:
    if value is None:
        out.append("null")
        return
    if isinstance(value, bool):  # must precede the int check — bool subclasses int
        out.append("true" if value else "false")
        return
    if isinstance(value, int):
        out.append(str(value))
        return
    if isinstance(value, float):
        raise ValueError(
            f"jcs.canonicalize: float values are not supported (got {value!r}); "
            "Smart Ads envelopes must not carry floating point members"
        )
    if isinstance(value, str):
        out.append(_escape_string(value))
        return
    if isinstance(value, list):
        out.append("[")
        for i, item in enumerate(value):
            if i:
                out.append(",")
            _dump(item, out)
        out.append("]")
        return
    if isinstance(value, dict):
        _dump_object(value, out)
        return
    raise ValueError(
        f"jcs.canonicalize: unsupported type {type(value).__name__!r} "
        f"for value {value!r}"
    )


def _dump_object(value: dict[Any, Any], out: list[str]) -> None:
    keys: list[str] = []
    for key in value:
        if not isinstance(key, str):
            raise ValueError(
                f"jcs.canonicalize: object keys must be str, got {type(key).__name__!r}"
            )
        keys.append(key)
    sorted_keys = sorted(keys, key=_utf16_key)
    if len(set(sorted_keys)) != len(sorted_keys):
        raise ValueError("jcs.canonicalize: duplicate object keys after sorting")
    out.append("{")
    for i, key in enumerate(sorted_keys):
        if i:
            out.append(",")
        out.append(_escape_string(key))
        out.append(":")
        _dump(value[key], out)
    out.append("}")


def canonicalize(value: Any) -> bytes:
    """Serialize `value` to RFC 8785 canonical JSON bytes (UTF-8, no whitespace)."""
    out: list[str] = []
    _dump(value, out)
    return "".join(out).encode("utf-8")


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, val in pairs:
        if key in result:
            raise ValueError(f"jcs.loads_strict: duplicate key {key!r} in object")
        result[key] = val
    return result


def _reject_float(text: str) -> float:
    raise ValueError(
        f"jcs.loads_strict: floating point literal {text!r} is not allowed"
    )


def loads_strict(text: str) -> Any:
    """Parse JSON, rejecting duplicate object keys and any float literal."""
    try:
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_float=_reject_float,
        )
    except json.JSONDecodeError as exc:
        raise ValueError(f"jcs.loads_strict: invalid JSON: {exc}") from exc
