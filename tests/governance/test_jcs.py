"""Tests for tools.governance.jcs — RFC 8785 JSON Canonicalization Scheme subset."""
from __future__ import annotations

import pytest

from tools.governance.jcs import canonicalize, loads_strict


def test_key_order_rfc8785_section_3_2_3_example() -> None:
    # RFC 8785 §3.2.3 example keys, sorted by UTF-16 code unit order.
    value = {
        "€": "euro-sign",
        "\U00010000": "u10000",
        " ": "space",
        "": "empty",
        "ÿ": "y-diaeresis",
        "＀": "fullwidth",
        "דּ": "hebrew-dalet-dagesh",
    }
    out = canonicalize(value).decode("utf-8")
    expected_order = ["", " ", "ÿ", "דּ", "€", "\U00010000", "＀"]
    positions = []
    for key in expected_order:
        token = '""' if key == "" else canonicalize(key).decode("utf-8")
        idx = out.find(token + ":")
        assert idx != -1, f"key {key!r} not found as {token!r} in {out!r}"
        positions.append(idx)
    assert positions == sorted(positions), out


def test_string_escaping_explicit_vector() -> None:
    value = "\n\t\r\b\f\"\\\x01/€"
    out = canonicalize(value).decode("utf-8")
    assert out == '"\\n\\t\\r\\b\\f\\"\\\\\\u0001/€"'


def test_literals() -> None:
    assert canonicalize(None) == b"null"
    assert canonicalize(True) == b"true"
    assert canonicalize(False) == b"false"
    assert canonicalize(0) == b"0"
    assert canonicalize(-42) == b"-42"


def test_bool_before_int_check() -> None:
    # bool is a subclass of int in Python; must serialize as true/false, not 1/0.
    assert canonicalize([True, False]) == b"[true,false]"


def test_nested_structures() -> None:
    value = {"b": [1, 2, {"a": 1, "c": None}], "a": "x"}
    out = canonicalize(value).decode("utf-8")
    assert out == '{"a":"x","b":[1,2,{"a":1,"c":null}]}'


def test_float_rejected() -> None:
    with pytest.raises(ValueError):
        canonicalize(1.5)


def test_float_in_container_rejected() -> None:
    with pytest.raises(ValueError):
        canonicalize({"a": 1.0})


def test_nan_inf_rejected() -> None:
    with pytest.raises(ValueError):
        canonicalize(float("nan"))
    with pytest.raises(ValueError):
        canonicalize(float("inf"))


def test_unsupported_type_rejected() -> None:
    with pytest.raises(ValueError):
        canonicalize(object())


def test_non_str_keys_rejected() -> None:
    with pytest.raises(ValueError):
        canonicalize({1: "a"})


def test_loads_strict_duplicate_keys_rejected() -> None:
    with pytest.raises(ValueError):
        loads_strict('{"a": 1, "a": 2}')


def test_loads_strict_float_rejected() -> None:
    with pytest.raises(ValueError):
        loads_strict('{"a": 1.5}')


def test_loads_strict_ok() -> None:
    assert loads_strict('{"a": 1, "b": [true, null]}') == {"a": 1, "b": [True, None]}
