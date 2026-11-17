"""Tests for smart_ads.analytics.policy (ADR-0001 section 7, section 12.7 analysis_policy/v1).

Every negative test asserts the closed error `code`, never the message (spec section 4).
"""
from __future__ import annotations

import ast
import base64
from collections.abc import Iterator
import contextlib
import copy
import dataclasses
from decimal import Decimal
import hashlib
import inspect
from pathlib import Path
import pickle
import sys
from typing import Any

import pytest

from smart_ads.analytics import policy as pol
from smart_ads.contracts import numerics
from smart_ads.contracts.jcs import (
    ADR_P1_DOMAIN_PREFIXES,
    MAX_JCS_SAFE_INT,
    ArtifactLocator,
    P1Integrity,
    canonicalize_jcs,
)
from smart_ads.contracts.numerics import MAX_INT64, PHASE1_BASE_METRICS
from smart_ads.contracts.scalars import ClosedValidationError

POLICY_MODULE_PATH = (
    Path(__file__).resolve().parents[2] / "src" / "smart_ads" / "analytics" / "policy.py"
)


@contextlib.contextmanager
def rejects(code: str) -> Iterator[None]:
    """Expect a coded PolicyValidationError carrying exactly `code`."""
    with pytest.raises(pol.PolicyValidationError) as caught:
        yield
    assert caught.value.code == code, f"expected {code!r}, got {caught.value}"


# --------------------------------------------------------------------------------------
# Wire fixtures. Every threshold below is test data, never a module constant.
# int64-valued thresholds are canonical unsigned decimal strings; day counts are JSON ints.
# --------------------------------------------------------------------------------------

SATURATION_WIRE: dict[str, Any] = {
    "rule_id": "rule:saturation-7d",
    "rule_type": "saturation",
    "window_days": 7,
    "spend_metric_ref": "metric:spend_v1",
    "outcome_metric_ref": "metric:aggregate_conversions_v1",
    "min_spend_growth": "0.200000",
    "max_outcome_growth": "0.050000",
    "min_baseline_spend_minor": "10000",
}
WASTE_WIRE: dict[str, Any] = {
    "rule_id": "rule:waste-14d",
    "rule_type": "waste",
    "window_days": 14,
    "spend_metric_ref": "metric:spend_v1",
    "outcome_metric_ref": "metric:aggregate_conversions_v1",
    "min_spend_minor": "50000",
    "max_outcome_count": "0",
}
STALLED_WIRE: dict[str, Any] = {
    "rule_id": "rule:stalled-3d",
    "rule_type": "stalled_delivery",
    "min_consecutive_days": 3,
    "max_impressions": "0",
}
RESTATEMENT_WIRE: dict[str, Any] = {
    "rule_id": "rule:restatement-28d",
    "rule_type": "restatement",
    "lookback_days": 28,
    "restatement_kinds": ["state_flip", "tombstone", "value_change"],
}

RULE_CASES = (
    pytest.param("saturation", pol.SaturationRule, SATURATION_WIRE, id="saturation"),
    pytest.param("waste", pol.WasteRule, WASTE_WIRE, id="waste"),
    pytest.param(
        "stalled_delivery", pol.StalledDeliveryRule, STALLED_WIRE, id="stalled_delivery"
    ),
    pytest.param("restatement", pol.RestatementRule, RESTATEMENT_WIRE, id="restatement"),
)

EXPECTED_RULE_KEYS: dict[str, frozenset[str]] = {
    "saturation": frozenset(
        {
            "rule_id",
            "rule_type",
            "window_days",
            "spend_metric_ref",
            "outcome_metric_ref",
            "min_spend_growth",
            "max_outcome_growth",
            "min_baseline_spend_minor",
        }
    ),
    "waste": frozenset(
        {
            "rule_id",
            "rule_type",
            "window_days",
            "spend_metric_ref",
            "outcome_metric_ref",
            "min_spend_minor",
            "max_outcome_count",
        }
    ),
    "stalled_delivery": frozenset(
        {"rule_id", "rule_type", "min_consecutive_days", "max_impressions"}
    ),
    "restatement": frozenset(
        {"rule_id", "rule_type", "lookback_days", "restatement_kinds"}
    ),
}

# Strict JSON-integer parameters: positive day counts within the JCS-safe range.
DAY_FIELD_CASES = (
    ("saturation", "window_days"),
    ("waste", "window_days"),
    ("stalled_delivery", "min_consecutive_days"),
    ("restatement", "lookback_days"),
)
# Canonical unsigned int64 strings, each with a parsed-int accessor named `<field>_int`.
UINT64_FIELD_CASES = (
    ("saturation", "min_baseline_spend_minor"),
    ("waste", "min_spend_minor"),
    ("waste", "max_outcome_count"),
    ("stalled_delivery", "max_impressions"),
)
RATIO_FIELD_CASES = (
    ("saturation", "min_spend_growth"),
    ("saturation", "max_outcome_growth"),
)
METRIC_FIELD_CASES = (
    ("saturation", "spend_metric_ref"),
    ("saturation", "outcome_metric_ref"),
    ("waste", "spend_metric_ref"),
    ("waste", "outcome_metric_ref"),
)
# The value type each metric slot requires of a Phase-1 base metric.
SLOT_VALUE_TYPES = {
    "spend_metric_ref": "int64_minor_currency",
    "outcome_metric_ref": "int64_count",
}


def _phase1_refs(value_type: str, *, same: bool) -> tuple[str, ...]:
    """Phase-1 base metric refs whose value type is (or is not) `value_type`."""
    return tuple(
        ref
        for ref, definition in PHASE1_BASE_METRICS.items()
        if (definition.value_type == value_type) is same
    )

CLASS_BY_TYPE = {
    "saturation": pol.SaturationRule,
    "waste": pol.WasteRule,
    "stalled_delivery": pol.StalledDeliveryRule,
    "restatement": pol.RestatementRule,
}
WIRE_BY_TYPE = {
    "saturation": SATURATION_WIRE,
    "waste": WASTE_WIRE,
    "stalled_delivery": STALLED_WIRE,
    "restatement": RESTATEMENT_WIRE,
}

MAX_UINT64_TEXT = str(MAX_INT64)  # "9223372036854775807"
FIVE_THOUSAND_DIGITS = "9" * 5000


class _IntSubclass(int):
    """A non-strict int: `type(v) is int` must reject it."""


def _wire(kind: str, /, **overrides: Any) -> dict[str, Any]:
    return {**copy.deepcopy(WIRE_BY_TYPE[kind]), **overrides}


def _without(mapping: dict[str, Any], key: str) -> dict[str, Any]:
    return {k: v for k, v in mapping.items() if k != key}


def _kwargs(kind: str, /, **overrides: Any) -> dict[str, Any]:
    return {k: v for k, v in _wire(kind, **overrides).items() if k != "rule_type"}


@pytest.fixture(params=["interpreter_default", "unlimited"])
def digit_limit(request: pytest.FixtureRequest) -> Iterator[str]:
    """Run a test under the default and under a disabled int/str digit limit."""
    previous = sys.get_int_max_str_digits()
    if request.param == "unlimited":
        sys.set_int_max_str_digits(0)
    try:
        yield request.param
    finally:
        sys.set_int_max_str_digits(previous)


# --------------------------------------------------------------------------------------
# Error types: closed code sets
# --------------------------------------------------------------------------------------


def test_policy_error_codes_are_a_closed_frozenset_disjoint_from_applicability_codes() -> None:
    assert isinstance(pol.POLICY_ERROR_CODES, frozenset)
    assert pol.POLICY_ERROR_CODES == frozenset(
        {
            "invalid_type",
            "invalid_grammar",
            "out_of_range",
            "unknown_member",
            "missing_member",
            "schema_mismatch",
            "unknown_rule_type",
            "empty",
            "duplicate_rule_id",
            "duplicate_restatement_kind",
            "unsorted",
            "unsupported_value",
            "invalid_validity_window",
            "invalid_integrity",
            "content_digest_mismatch",
        }
    )
    assert not pol.POLICY_ERROR_CODES & set(pol.POLICY_NOT_APPLICABLE_CODES)


def test_policy_validation_error_carries_a_code_and_rejects_codes_outside_the_set() -> None:
    assert issubclass(pol.PolicyValidationError, ClosedValidationError)
    for code in sorted(pol.POLICY_ERROR_CODES):
        error = pol.PolicyValidationError(code, "detail")
        assert (error.code, error.detail) == (code, "detail")
        assert code in str(error)
    for bad in ("", "tenant_mismatch", "INVALID_TYPE", None, 1, ["empty"]):
        with pytest.raises(ClosedValidationError) as caught:
            pol.PolicyValidationError(bad, "detail")  # type: ignore[arg-type]
        assert type(caught.value) is ClosedValidationError


def test_both_error_types_survive_copy_and_pickle_with_their_code() -> None:
    errors = (
        pol.PolicyValidationError("out_of_range", "too big"),
        pol.PolicyNotApplicableError("expired", "window closed"),
    )
    for error in errors:
        for clone in (copy.copy(error), copy.deepcopy(error), pickle.loads(pickle.dumps(error))):
            assert type(clone) is type(error)
            assert (clone.code, clone.detail) == (error.code, error.detail)
            assert str(clone) == str(error)


def test_the_two_error_types_are_distinct_siblings() -> None:
    assert not issubclass(pol.PolicyNotApplicableError, pol.PolicyValidationError)
    assert not issubclass(pol.PolicyValidationError, pol.PolicyNotApplicableError)


# --------------------------------------------------------------------------------------
# Closed rule union: round trip, key sets, discriminator
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(("rule_type", "cls", "wire"), RULE_CASES)
def test_rule_round_trips_through_closed_dict_without_touching_input(
    rule_type: str, cls: Any, wire: dict[str, Any]
) -> None:
    before = copy.deepcopy(wire)
    rule = cls.from_dict(wire)
    assert wire == before
    assert rule.to_dict() == wire
    assert cls.from_dict(rule.to_dict()) == rule
    dispatched = pol.rule_from_dict(wire)
    assert type(dispatched) is cls
    assert dispatched == rule
    assert dispatched.RULE_TYPE == rule_type


@pytest.mark.parametrize(("rule_type", "cls", "wire"), RULE_CASES)
def test_rule_to_dict_returns_fresh_objects(
    rule_type: str, cls: Any, wire: dict[str, Any]
) -> None:
    rule = cls.from_dict(wire)
    first = rule.to_dict()
    first["rule_id"] = "rule:tampered"
    if "restatement_kinds" in first:
        first["restatement_kinds"].append("tombstone")
    assert rule.to_dict() == wire


@pytest.mark.parametrize(("rule_type", "cls", "wire"), RULE_CASES)
def test_rule_to_dict_key_set_is_exactly_the_spec_parameters(
    rule_type: str, cls: Any, wire: dict[str, Any]
) -> None:
    assert frozenset(cls.from_dict(wire).to_dict()) == EXPECTED_RULE_KEYS[rule_type]
    assert cls.KEYS == EXPECTED_RULE_KEYS[rule_type]


@pytest.mark.parametrize(("rule_type", "cls", "wire"), RULE_CASES)
def test_rules_are_frozen_and_hashable(
    rule_type: str, cls: Any, wire: dict[str, Any]
) -> None:
    rule = cls.from_dict(wire)
    with pytest.raises(dataclasses.FrozenInstanceError):
        rule.rule_id = "rule:other"
    assert hash(rule) == hash(cls.from_dict(wire))


def test_rule_to_dict_value_types_are_json_int_for_days_and_string_for_int64_and_ratios() -> None:
    for rule_type, field in DAY_FIELD_CASES:
        value = CLASS_BY_TYPE[rule_type].from_dict(WIRE_BY_TYPE[rule_type]).to_dict()[field]
        assert type(value) is int
    for rule_type, field in UINT64_FIELD_CASES + RATIO_FIELD_CASES:
        value = CLASS_BY_TYPE[rule_type].from_dict(WIRE_BY_TYPE[rule_type]).to_dict()[field]
        assert type(value) is str


def test_rule_type_union_is_closed_to_the_four_finding_types() -> None:
    assert set(pol.RULE_TYPES) == {"saturation", "waste", "stalled_delivery", "restatement"}
    assert list(pol.RULE_TYPES) == sorted(pol.RULE_TYPES, key=lambda s: s.encode())
    assert pol.AnalysisRule == (
        pol.SaturationRule | pol.WasteRule | pol.StalledDeliveryRule | pol.RestatementRule
    )


@pytest.mark.parametrize(
    "bad_type",
    ["mutation", "SATURATION", "", " saturation", "saturation ", "stalled-delivery"],
)
def test_rule_from_dict_rejects_unknown_rule_type(bad_type: str) -> None:
    with rejects("unknown_rule_type"):
        pol.rule_from_dict(_wire("saturation", rule_type=bad_type))


@pytest.mark.parametrize("bad_type", [None, 1, True, ["saturation"], {"a": 1}])
def test_rule_from_dict_rejects_non_string_rule_type(bad_type: Any) -> None:
    with rejects("invalid_type"):
        pol.rule_from_dict(_wire("saturation", rule_type=bad_type))


def test_rule_from_dict_rejects_missing_rule_type_and_non_mapping() -> None:
    with rejects("missing_member"):
        pol.rule_from_dict(_without(_wire("saturation"), "rule_type"))
    for bad in (None, [], "saturation", 7):
        with rejects("invalid_type"):
            pol.rule_from_dict(bad)


@pytest.mark.parametrize(("rule_type", "cls", "wire"), RULE_CASES)
def test_each_rule_class_rejects_a_foreign_rule_type(
    rule_type: str, cls: Any, wire: dict[str, Any]
) -> None:
    for other in EXPECTED_RULE_KEYS:
        if other != rule_type:
            with rejects("unknown_rule_type"):
                cls.from_dict({**wire, "rule_type": other})


@pytest.mark.parametrize(("rule_type", "cls", "wire"), RULE_CASES)
def test_rule_rejects_extra_member_and_non_mapping(
    rule_type: str, cls: Any, wire: dict[str, Any]
) -> None:
    with rejects("unknown_member"):
        cls.from_dict({**wire, "extra": 1})
    with rejects("unknown_member"):
        pol.rule_from_dict({**wire, "extra": 1})
    for bad in (None, [], "rule", 7):
        with rejects("invalid_type"):
            cls.from_dict(bad)


MISSING_MEMBER_CASES = [
    pytest.param(rule_type, key, id=f"{rule_type}-{key}")
    for rule_type, keys in EXPECTED_RULE_KEYS.items()
    for key in sorted(keys)
]


@pytest.mark.parametrize(("rule_type", "key"), MISSING_MEMBER_CASES)
def test_rule_rejects_each_missing_member(rule_type: str, key: str) -> None:
    wire = _without(_wire(rule_type), key)
    with rejects("missing_member"):
        CLASS_BY_TYPE[rule_type].from_dict(wire)
    with rejects("missing_member"):
        pol.rule_from_dict(wire)


def test_rule_from_dict_rejects_json_arrays_given_as_tuples() -> None:
    with rejects("invalid_type"):
        pol.rule_from_dict(_wire("restatement", restatement_kinds=("tombstone",)))


# --------------------------------------------------------------------------------------
# rule_id
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("rule_type", sorted(EXPECTED_RULE_KEYS))
def test_rule_rejects_malformed_rule_id_by_grammar_or_type(rule_type: str) -> None:
    cls = CLASS_BY_TYPE[rule_type]
    for bad in (
        "",
        "rule",
        "rule:",
        "Rule:x",
        "policy:x",
        "rule:has space",
        "rule:café",
        "rule:x\n",
    ):
        with rejects("invalid_grammar"):
            cls.from_dict(_wire(rule_type, rule_id=bad))
    for bad in (None, 7, True, ["rule:x"]):
        with rejects("invalid_type"):
            cls.from_dict(_wire(rule_type, rule_id=bad))


# --------------------------------------------------------------------------------------
# Day counts: strict JSON integers >= 1 within the JCS-safe range
# --------------------------------------------------------------------------------------

NON_INT_VALUES: list[Any] = [
    True,
    False,
    1.0,
    7.0,
    "1",
    "",
    None,
    [1],
    {"a": 1},
    Decimal(1),
    _IntSubclass(5),
]


@pytest.mark.parametrize(("rule_type", "field"), DAY_FIELD_CASES)
def test_day_counts_reject_bool_float_str_and_int_subclasses(
    rule_type: str, field: str
) -> None:
    cls = CLASS_BY_TYPE[rule_type]
    for bad in NON_INT_VALUES:
        with rejects("invalid_type"):
            cls.from_dict(_wire(rule_type, **{field: bad}))
        with rejects("invalid_type"):
            cls(**_kwargs(rule_type, **{field: bad}))


@pytest.mark.parametrize(("rule_type", "field"), DAY_FIELD_CASES)
def test_day_counts_are_positive_and_bounded_by_the_jcs_safe_integer(
    rule_type: str, field: str
) -> None:
    cls = CLASS_BY_TYPE[rule_type]
    for good in (1, 2, MAX_JCS_SAFE_INT):
        rule = cls.from_dict(_wire(rule_type, **{field: good}))
        assert rule.to_dict()[field] == good
        canonicalize_jcs(rule.to_dict())
    for bad in (0, -1, -MAX_INT64 - 1, MAX_JCS_SAFE_INT + 1, MAX_INT64):
        with rejects("out_of_range"):
            cls.from_dict(_wire(rule_type, **{field: bad}))


# --------------------------------------------------------------------------------------
# int64-valued thresholds: canonical unsigned decimal strings
# --------------------------------------------------------------------------------------

BAD_UINT64_GRAMMAR: list[str] = [
    "",
    " ",
    "-1",
    "-0",
    "+1",
    "01",
    "00",
    "0x10",
    "1e3",
    "1.0",
    "1,000",
    "1_000",
    " 1",
    "1 ",
    "1\n",
    "\n1",
    "１",
    "NaN",
]
OUT_OF_RANGE_UINT64: list[str] = [
    "9223372036854775808",
    "9999999999999999999",
    "10000000000000000000",
    "1" + "0" * 30,
    FIVE_THOUSAND_DIGITS,
]


@pytest.mark.parametrize(("rule_type", "field"), UINT64_FIELD_CASES)
def test_int64_thresholds_reject_native_numbers_and_other_types(
    rule_type: str, field: str
) -> None:
    cls = CLASS_BY_TYPE[rule_type]
    for bad in (0, 5, 10000, True, False, 1.0, None, [1], {"a": 1}, Decimal(1), _IntSubclass(5)):
        with rejects("invalid_type"):
            cls.from_dict(_wire(rule_type, **{field: bad}))
        with rejects("invalid_type"):
            cls(**_kwargs(rule_type, **{field: bad}))


@pytest.mark.parametrize(("rule_type", "field"), UINT64_FIELD_CASES)
def test_int64_thresholds_reject_non_canonical_strings(rule_type: str, field: str) -> None:
    cls = CLASS_BY_TYPE[rule_type]
    for bad in BAD_UINT64_GRAMMAR:
        with rejects("invalid_grammar"):
            cls.from_dict(_wire(rule_type, **{field: bad}))
        with rejects("invalid_grammar"):
            cls(**_kwargs(rule_type, **{field: bad}))


@pytest.mark.parametrize(("rule_type", "field"), UINT64_FIELD_CASES)
def test_int64_thresholds_accept_exactly_up_to_max_int64(rule_type: str, field: str) -> None:
    cls = CLASS_BY_TYPE[rule_type]
    for good in (
        "0",
        "1",
        "9007199254740991",
        "9007199254740992",
        "9007199254740993",
        MAX_UINT64_TEXT,
    ):
        rule = cls.from_dict(_wire(rule_type, **{field: good}))
        assert rule.to_dict()[field] == good
        canonicalize_jcs(rule.to_dict())
    for bad in OUT_OF_RANGE_UINT64:
        with rejects("out_of_range"):
            cls.from_dict(_wire(rule_type, **{field: bad}))


@pytest.mark.parametrize(("rule_type", "field"), UINT64_FIELD_CASES)
def test_int64_threshold_accessor_returns_the_exact_int_and_is_read_only(
    rule_type: str, field: str
) -> None:
    cls = CLASS_BY_TYPE[rule_type]
    accessor = f"{field}_int"
    for text in ("0", "10000", "9007199254740993", MAX_UINT64_TEXT):
        rule = cls.from_dict(_wire(rule_type, **{field: text}))
        value = getattr(rule, accessor)
        assert type(value) is int
        assert value == int(text)
        assert str(value) == text
    # Read-only: a getter-only property. (A frozen slots dataclass raises TypeError, not
    # FrozenInstanceError, for non-field names because of a CPython dataclass quirk.)
    descriptor = getattr(cls, accessor)
    assert isinstance(descriptor, property)
    assert descriptor.fset is None and descriptor.fdel is None
    with pytest.raises((AttributeError, TypeError)):
        setattr(rule, accessor, 1)
    assert getattr(rule, accessor) == int(MAX_UINT64_TEXT)


def test_int64_bounds_do_not_depend_on_the_interpreter_digit_limit(digit_limit: str) -> None:
    for rule_type, field in UINT64_FIELD_CASES:
        with rejects("out_of_range"):
            CLASS_BY_TYPE[rule_type].from_dict(
                _wire(rule_type, **{field: FIVE_THOUSAND_DIGITS})
            )
    for field in ("min_spend_growth", "max_outcome_growth"):
        with rejects("out_of_range"):
            pol.SaturationRule.from_dict(
                _wire("saturation", **{field: FIVE_THOUSAND_DIGITS + ".000000"})
            )
    with rejects("out_of_range"):
        pol.decimal6_to_micros(FIVE_THOUSAND_DIGITS + ".000000")


# --------------------------------------------------------------------------------------
# decimal6 non-negative ratios: grammar plus an explicit integer-part bound
# --------------------------------------------------------------------------------------

BAD_DECIMAL6_GRAMMAR: list[str] = [
    "",
    "0",
    "1",
    "1.0",
    "1.00000",
    "1.0000000",
    "01.000000",
    "00.500000",
    "-0.500000",
    "-0.000000",
    "-1.000000",
    "+1.000000",
    "1e0",
    "1.000000e0",
    "1.5E-1",
    " 1.000000",
    "1.000000 ",
    "1.000000\n",
    "\n1.000000",
    "1,000000",
    ".500000",
    "1.50000a",
    "１.000000",
    "1.００００００",
    "NaN",
    "Infinity",
    "-Infinity",
]
BAD_DECIMAL6_TYPES: list[Any] = [1, 0, 1.5, True, None, Decimal("1.000000"), ["0.100000"]]
OUT_OF_RANGE_DECIMAL6: list[str] = [
    "9223372036854775808.000000",
    "9999999999999999999.999999",
    "10000000000000000000.000000",
    "123456789012345678901234567890.000001",
    FIVE_THOUSAND_DIGITS + ".000000",
]


@pytest.mark.parametrize(("rule_type", "field"), RATIO_FIELD_CASES)
def test_ratio_parameters_reject_every_non_decimal6_form(rule_type: str, field: str) -> None:
    cls = CLASS_BY_TYPE[rule_type]
    for bad in BAD_DECIMAL6_GRAMMAR:
        with rejects("invalid_grammar"):
            cls.from_dict(_wire(rule_type, **{field: bad}))
        with rejects("invalid_grammar"):
            cls(**_kwargs(rule_type, **{field: bad}))
    for bad in BAD_DECIMAL6_TYPES:
        with rejects("invalid_type"):
            cls.from_dict(_wire(rule_type, **{field: bad}))
        with rejects("invalid_type"):
            cls(**_kwargs(rule_type, **{field: bad}))


@pytest.mark.parametrize(("rule_type", "field"), RATIO_FIELD_CASES)
def test_ratio_parameters_accept_decimal6_up_to_the_int64_integer_bound(
    rule_type: str, field: str
) -> None:
    cls = CLASS_BY_TYPE[rule_type]
    for good in (
        "0.000000",
        "0.000001",
        "1.000000",
        "12.345678",
        "100.500000",
        MAX_UINT64_TEXT + ".000000",
        MAX_UINT64_TEXT + ".999999",
    ):
        rule = cls.from_dict(_wire(rule_type, **{field: good}))
        assert rule.to_dict()[field] == good
    for bad in OUT_OF_RANGE_DECIMAL6:
        with rejects("out_of_range"):
            cls.from_dict(_wire(rule_type, **{field: bad}))
        with rejects("out_of_range"):
            cls(**_kwargs(rule_type, **{field: bad}))


def test_decimal6_to_micros_is_exact_integer_arithmetic_with_the_same_bound() -> None:
    assert pol.decimal6_to_micros("0.000000") == 0
    assert pol.decimal6_to_micros("0.000001") == 1
    assert pol.decimal6_to_micros("1.000000") == 1_000_000
    assert pol.decimal6_to_micros("12.345678") == 12_345_678
    assert pol.decimal6_to_micros("0.200000") == 200_000
    top = MAX_UINT64_TEXT + ".999999"
    assert pol.decimal6_to_micros(top) == int(MAX_UINT64_TEXT + "999999")
    for bad in BAD_DECIMAL6_GRAMMAR:
        with rejects("invalid_grammar"):
            pol.decimal6_to_micros(bad)
    for bad in BAD_DECIMAL6_TYPES:
        with rejects("invalid_type"):
            pol.decimal6_to_micros(bad)
    for bad in OUT_OF_RANGE_DECIMAL6:
        with rejects("out_of_range"):
            pol.decimal6_to_micros(bad)


# --------------------------------------------------------------------------------------
# metric refs
# --------------------------------------------------------------------------------------

BAD_METRIC_REF_GRAMMAR: list[str] = [
    "",
    "impressions",
    "metric:",
    "metric:spend",
    "metric:spend_v0",
    "metric:spend_v01",
    "metric:Spend_v1",
    "metric:1spend_v1",
    "metric:spend-v1",
    "metric:spend_v1\n",
    " metric:spend_v1",
    "source-metric:provider:meta:v1",
    "source-metric:formula:sha256:" + "a" * 64,
    "metric:spend_v1:extra",
    "metric:café_v1",
]


@pytest.mark.parametrize(("rule_type", "field"), METRIC_FIELD_CASES)
def test_metric_ref_parameters_reject_malformed_refs(rule_type: str, field: str) -> None:
    cls = CLASS_BY_TYPE[rule_type]
    for bad in BAD_METRIC_REF_GRAMMAR:
        with rejects("invalid_grammar"):
            cls.from_dict(_wire(rule_type, **{field: bad}))
    for bad in (None, 1, True, ["metric:spend_v1"]):
        with rejects("invalid_type"):
            cls.from_dict(_wire(rule_type, **{field: bad}))


@pytest.mark.parametrize(("rule_type", "field"), METRIC_FIELD_CASES)
def test_metric_ref_parameters_accept_phase1_and_derived_metric_refs(
    rule_type: str, field: str
) -> None:
    cls = CLASS_BY_TYPE[rule_type]
    for good in (
        *_phase1_refs(SLOT_VALUE_TYPES[field], same=True),
        "metric:aggregate_conversions_v1",
        "metric:canonical_leads_v1",
        "metric:cost_per_click_v12",
    ):
        assert cls.from_dict(_wire(rule_type, **{field: good})).to_dict()[field] == good


@pytest.mark.parametrize(("rule_type", "field"), METRIC_FIELD_CASES)
def test_phase1_base_metric_of_the_wrong_value_type_rejects_up_front(
    rule_type: str, field: str
) -> None:
    # Spend must be int64_minor_currency and outcome int64_count: a Phase-1 base metric of the
    # other type is malformed policy evidence whatever data exists, in wire and constructor form.
    cls = CLASS_BY_TYPE[rule_type]
    wrong = _phase1_refs(SLOT_VALUE_TYPES[field], same=False)
    assert wrong
    for ref in wrong:
        wire = _wire(rule_type, **{field: ref})
        with rejects("unsupported_value"):
            cls.from_dict(wire)
        with rejects("unsupported_value"):
            cls(**_kwargs(rule_type, **{field: ref}))
        with rejects("unsupported_value"):
            pol.rule_from_dict(wire)
        rules = [wire if kind == rule_type else _wire(kind) for kind in SORTED_RULE_TYPES]
        with rejects("unsupported_value"):
            pol.AnalysisPolicy.from_dict(_policy_wire(rules=rules))


def test_only_saturation_and_waste_carry_metric_refs() -> None:
    # Stalled delivery is fixed to the impressions base metric; restatement names no metric.
    carrying = {
        rule_type
        for rule_type, cls in CLASS_BY_TYPE.items()
        if any(f.name.endswith("_metric_ref") for f in dataclasses.fields(cls))
    }
    assert carrying == {"saturation", "waste"}
    assert {(rule_type, field) for rule_type, field in METRIC_FIELD_CASES} == {
        (rule_type, field) for rule_type in carrying for field in SLOT_VALUE_TYPES
    }


def test_metric_ref_grammar_is_pinned_to_the_base_metric_definition_regex() -> None:
    # policy.py keeps its own copy because numerics keeps its regex private; the pin makes any
    # drift in pattern or flags a test failure instead of a silent split.
    assert pol.METRIC_REF_PATTERN == numerics._METRIC_SEMANTIC_REF_RE.pattern
    assert pol._METRIC_REF_RE.pattern == numerics._METRIC_SEMANTIC_REF_RE.pattern
    assert pol._METRIC_REF_RE.flags == numerics._METRIC_SEMANTIC_REF_RE.flags


# --------------------------------------------------------------------------------------
# restatement_kinds: subset, order, uniqueness
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "kinds",
    [
        ["state_flip"],
        ["tombstone"],
        ["value_change"],
        ["state_flip", "tombstone"],
        ["state_flip", "value_change"],
        ["tombstone", "value_change"],
        ["state_flip", "tombstone", "value_change"],
    ],
)
def test_restatement_kinds_accept_every_sorted_non_empty_subset(kinds: list[str]) -> None:
    rule = pol.RestatementRule.from_dict(_wire("restatement", restatement_kinds=kinds))
    assert rule.restatement_kinds == tuple(kinds)
    assert rule.to_dict()["restatement_kinds"] == kinds


RESTATEMENT_KIND_CASES = [
    ([], "empty"),
    (["tombstone", "tombstone"], "duplicate_restatement_kind"),
    (["state_flip", "tombstone", "state_flip"], "duplicate_restatement_kind"),
    (["value_change", "tombstone"], "unsorted"),
    (["tombstone", "state_flip", "value_change"], "unsorted"),
    (["value_change", "tombstone", "state_flip"], "unsorted"),
    (["unknown"], "unsupported_value"),
    (["tombstone", "unknown"], "unsupported_value"),
    (["Tombstone"], "unsupported_value"),
    (["state-flip"], "unsupported_value"),
    ([""], "unsupported_value"),
    (["tombstone", None], "invalid_type"),
    (["tombstone", 1], "invalid_type"),
    ([["tombstone"]], "invalid_type"),
    ("tombstone", "invalid_type"),
    (None, "invalid_type"),
    (1, "invalid_type"),
    ({"tombstone": 1}, "invalid_type"),
    ({"tombstone"}, "invalid_type"),
    (b"tombstone", "invalid_type"),
]


@pytest.mark.parametrize(("kinds", "code"), RESTATEMENT_KIND_CASES)
def test_restatement_kinds_reject_with_a_specific_code(kinds: Any, code: str) -> None:
    with rejects(code):
        pol.RestatementRule.from_dict(_wire("restatement", restatement_kinds=kinds))
    with rejects(code):
        pol.RestatementRule(**_kwargs("restatement", restatement_kinds=kinds))


def test_restatement_constructor_takes_tuples_and_copies_into_an_immutable_tuple() -> None:
    rule = pol.RestatementRule(**_kwargs("restatement", restatement_kinds=("tombstone",)))
    assert rule.restatement_kinds == ("tombstone",)
    kinds = ["state_flip", "tombstone"]
    copied = pol.RestatementRule(**_kwargs("restatement", restatement_kinds=kinds))
    kinds.append("value_change")
    assert copied.restatement_kinds == ("state_flip", "tombstone")
    assert isinstance(copied.restatement_kinds, tuple)


def test_restatement_kind_vocabulary_is_the_closed_three() -> None:
    assert set(pol.RESTATEMENT_KINDS) == {"tombstone", "value_change", "state_flip"}
    assert list(pol.RESTATEMENT_KINDS) == sorted(pol.RESTATEMENT_KINDS, key=lambda s: s.encode())


# --------------------------------------------------------------------------------------
# applicability_scope
# --------------------------------------------------------------------------------------

SCOPE_WIRE: dict[str, Any] = {
    "resource_scope_ref": "scope:acme-main",
    "resource_level": "campaign",
    "ad_platform_ref": "meta",
    "currency": "BRL",
}
EXPECTED_SCOPE_KEYS = frozenset(
    {"resource_scope_ref", "resource_level", "ad_platform_ref", "currency"}
)


def test_applicability_scope_round_trips_with_exact_key_set() -> None:
    before = copy.deepcopy(SCOPE_WIRE)
    scope = pol.ApplicabilityScope.from_dict(SCOPE_WIRE)
    assert SCOPE_WIRE == before
    assert scope.to_dict() == SCOPE_WIRE
    assert frozenset(scope.to_dict()) == EXPECTED_SCOPE_KEYS
    assert pol.ApplicabilityScope.KEYS == EXPECTED_SCOPE_KEYS
    assert pol.ApplicabilityScope.from_dict(scope.to_dict()) == scope
    with pytest.raises(dataclasses.FrozenInstanceError):
        scope.currency = "USD"  # type: ignore[misc]


def test_applicability_scope_rejects_extra_missing_and_non_mapping() -> None:
    with rejects("unknown_member"):
        pol.ApplicabilityScope.from_dict({**SCOPE_WIRE, "extra": "x"})
    for key in SCOPE_WIRE:
        with rejects("missing_member"):
            pol.ApplicabilityScope.from_dict(_without(SCOPE_WIRE, key))
    for bad in (None, [], "scope", 7):
        with rejects("invalid_type"):
            pol.ApplicabilityScope.from_dict(bad)


SCOPE_VALUE_CASES = [
    ("resource_scope_ref", "", "invalid_grammar"),
    ("resource_scope_ref", "scope", "invalid_grammar"),
    ("resource_scope_ref", "scope:", "invalid_grammar"),
    ("resource_scope_ref", "tenant:acme", "invalid_grammar"),
    ("resource_scope_ref", "Scope:acme", "invalid_grammar"),
    ("resource_scope_ref", "scope:acme\n", "invalid_grammar"),
    ("resource_scope_ref", None, "invalid_type"),
    ("resource_scope_ref", 7, "invalid_type"),
    ("resource_level", "adset", "unsupported_value"),
    ("resource_level", "ad", "unsupported_value"),
    ("resource_level", "Campaign", "unsupported_value"),
    ("resource_level", "", "unsupported_value"),
    ("resource_level", None, "invalid_type"),
    ("resource_level", 1, "invalid_type"),
    ("ad_platform_ref", "google", "unsupported_value"),
    ("ad_platform_ref", "META", "unsupported_value"),
    ("ad_platform_ref", "", "unsupported_value"),
    ("ad_platform_ref", None, "invalid_type"),
    ("currency", "USD", "unsupported_value"),
    ("currency", "brl", "unsupported_value"),
    ("currency", "BR", "unsupported_value"),
    ("currency", "BRLL", "unsupported_value"),
    ("currency", "", "unsupported_value"),
    ("currency", None, "invalid_type"),
    ("currency", 986, "invalid_type"),
]


@pytest.mark.parametrize(("field", "bad", "code"), SCOPE_VALUE_CASES)
def test_applicability_scope_rejects_each_malformed_or_non_phase1_value(
    field: str, bad: Any, code: str
) -> None:
    with rejects(code):
        pol.ApplicabilityScope.from_dict({**SCOPE_WIRE, field: bad})
    with rejects(code):
        pol.ApplicabilityScope(**{**SCOPE_WIRE, field: bad})


# --------------------------------------------------------------------------------------
# validity window
# --------------------------------------------------------------------------------------

VALIDITY_WIRE: dict[str, Any] = {
    "valid_from_utc": "2026-01-01T00:00:00.000000Z",
    "valid_until_utc": "2026-12-31T23:59:59.999999Z",
}
EXPECTED_VALIDITY_KEYS = frozenset({"valid_from_utc", "valid_until_utc"})


def test_validity_round_trips_with_exact_key_set() -> None:
    before = copy.deepcopy(VALIDITY_WIRE)
    validity = pol.PolicyValidity.from_dict(VALIDITY_WIRE)
    assert VALIDITY_WIRE == before
    assert validity.to_dict() == VALIDITY_WIRE
    assert frozenset(validity.to_dict()) == EXPECTED_VALIDITY_KEYS
    assert pol.PolicyValidity.KEYS == EXPECTED_VALIDITY_KEYS
    assert pol.PolicyValidity.from_dict(validity.to_dict()) == validity
    with pytest.raises(dataclasses.FrozenInstanceError):
        validity.valid_from_utc = "2026-01-02T00:00:00.000000Z"  # type: ignore[misc]


def test_validity_requires_valid_from_strictly_before_valid_until() -> None:
    same = "2026-06-01T12:00:00.000000Z"
    with rejects("invalid_validity_window"):
        pol.PolicyValidity(valid_from_utc=same, valid_until_utc=same)
    with rejects("invalid_validity_window"):
        pol.PolicyValidity(
            valid_from_utc="2026-06-01T12:00:00.000001Z",
            valid_until_utc="2026-06-01T12:00:00.000000Z",
        )
    pol.PolicyValidity(
        valid_from_utc="2026-06-01T12:00:00.000000Z",
        valid_until_utc="2026-06-01T12:00:00.000001Z",
    )
    with rejects("invalid_validity_window"):
        pol.PolicyValidity.from_dict({"valid_from_utc": same, "valid_until_utc": same})


@pytest.mark.parametrize("field", sorted(EXPECTED_VALIDITY_KEYS))
def test_validity_bounds_require_canonical_six_digit_utc_timestamps(field: str) -> None:
    for bad in (
        "2026-06-01T12:00:00Z",
        "2026-06-01T12:00:00.0Z",
        "2026-06-01T12:00:00.000Z",
        "2026-06-01T12:00:00.0000000Z",
        "2026-06-01T12:00:00.000000",
        "2026-06-01T12:00:00.000000+00:00",
        "2026-06-01t12:00:00.000000z",
        "2026-06-01 12:00:00.000000Z",
        "2026-02-30T12:00:00.000000Z",
        "2026-13-01T12:00:00.000000Z",
        "2026-06-01T24:00:00.000000Z",
        "2026-06-01T12:60:00.000000Z",
        "2026-06-01T12:00:60.000000Z",
        "2026-06-01",
        "",
    ):
        with rejects("invalid_grammar"):
            pol.PolicyValidity.from_dict({**VALIDITY_WIRE, field: bad})
        with rejects("invalid_grammar"):
            pol.PolicyValidity(**{**VALIDITY_WIRE, field: bad})
    for bad in (None, 0, 1_780_000_000, True):
        with rejects("invalid_type"):
            pol.PolicyValidity.from_dict({**VALIDITY_WIRE, field: bad})
        with rejects("invalid_type"):
            pol.PolicyValidity(**{**VALIDITY_WIRE, field: bad})


def test_validity_rejects_extra_missing_and_non_mapping() -> None:
    with rejects("unknown_member"):
        pol.PolicyValidity.from_dict({**VALIDITY_WIRE, "extra": "x"})
    for key in VALIDITY_WIRE:
        with rejects("missing_member"):
            pol.PolicyValidity.from_dict(_without(VALIDITY_WIRE, key))
    for bad in (None, [], "validity", 7):
        with rejects("invalid_type"):
            pol.PolicyValidity.from_dict(bad)


# --------------------------------------------------------------------------------------
# analysis_policy/v1 envelope
# --------------------------------------------------------------------------------------

KEY_ID = "key:ed25519:" + "a" * 64
KEY_REGISTRY_LOCATOR = ArtifactLocator.from_digest(
    "smart_ads/key_authorization_registry/v1", "sha256:" + "9" * 64
)
UNSIGNED_INTEGRITY: dict[str, Any] = P1Integrity(
    key_id=KEY_ID, key_registry_snapshot_locator=KEY_REGISTRY_LOCATOR
).to_dict()
FAKE_SIGNATURE_BASE64 = base64.b64encode(bytes(64)).decode("ascii")
EXPECTED_POLICY_CORE_KEYS = frozenset(
    {
        "$schema",
        "policy_id",
        "policy_version",
        "tenant_ref",
        "applicability_scope",
        "validity",
        "rules",
    }
)
EXPECTED_POLICY_KEYS = EXPECTED_POLICY_CORE_KEYS | {"integrity"}
# Byte-sorted by rule_id: restatement < saturation < stalled < waste.
SORTED_RULE_TYPES = ("restatement", "saturation", "stalled_delivery", "waste")


def _policy_wire(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "$schema": "smart_ads/analysis_policy/v1",
        "policy_id": "policy:acme-default",
        "policy_version": "2026.11.1",
        "tenant_ref": "tenant:acme",
        "applicability_scope": copy.deepcopy(SCOPE_WIRE),
        "validity": copy.deepcopy(VALIDITY_WIRE),
        "rules": [_wire(kind) for kind in SORTED_RULE_TYPES],
    }
    return {**base, **overrides}


def _with_unsigned(wire: dict[str, Any]) -> dict[str, Any]:
    return {**wire, "integrity": copy.deepcopy(UNSIGNED_INTEGRITY)}


def _signed_wire(wire: dict[str, Any], signature: str = FAKE_SIGNATURE_BASE64) -> dict[str, Any]:
    digest = pol.AnalysisPolicy.from_dict(_with_unsigned(wire)).p1_content_digest()
    return {
        **wire,
        "integrity": {
            **copy.deepcopy(UNSIGNED_INTEGRITY),
            "content_digest": digest,
            "signature_base64": signature,
        },
    }


def _constructor_kwargs(wire: dict[str, Any]) -> dict[str, Any]:
    return {
        "policy_id": wire["policy_id"],
        "policy_version": wire["policy_version"],
        "tenant_ref": wire["tenant_ref"],
        "applicability_scope": pol.ApplicabilityScope.from_dict(wire["applicability_scope"]),
        "validity": pol.PolicyValidity.from_dict(wire["validity"]),
        "rules": tuple(pol.rule_from_dict(rule) for rule in wire["rules"]),
    }


def test_policy_round_trips_without_integrity_and_without_touching_input() -> None:
    wire = _policy_wire()
    before = copy.deepcopy(wire)
    policy = pol.AnalysisPolicy.from_dict(wire)
    assert wire == before
    assert policy.integrity is None
    assert policy.to_dict() == wire
    assert pol.AnalysisPolicy.from_dict(policy.to_dict()) == policy
    assert tuple(type(rule).RULE_TYPE for rule in policy.rules) == SORTED_RULE_TYPES


def test_policy_round_trips_with_unsigned_and_signed_integrity() -> None:
    unsigned_wire = _with_unsigned(_policy_wire())
    unsigned = pol.AnalysisPolicy.from_dict(unsigned_wire)
    assert unsigned.integrity is not None and not unsigned.integrity.is_signed
    assert unsigned.to_dict() == unsigned_wire

    signed_wire = _signed_wire(_policy_wire())
    signed = pol.AnalysisPolicy.from_dict(signed_wire, require_signed=True)
    assert signed.integrity is not None and signed.integrity.is_signed
    assert signed.to_dict() == signed_wire
    assert pol.AnalysisPolicy.from_dict(signed_wire) == signed


def test_policy_key_sets_are_exactly_the_registered_descriptor_fields() -> None:
    assert pol.AnalysisPolicy.SCHEMA == "smart_ads/analysis_policy/v1"
    assert pol.AnalysisPolicy.CORE_KEYS == EXPECTED_POLICY_CORE_KEYS
    assert pol.AnalysisPolicy.KEYS == EXPECTED_POLICY_KEYS
    bare = pol.AnalysisPolicy.from_dict(_policy_wire())
    assert frozenset(bare.to_dict()) == EXPECTED_POLICY_CORE_KEYS
    with_integrity = pol.AnalysisPolicy.from_dict(_with_unsigned(_policy_wire()))
    assert frozenset(with_integrity.to_dict()) == EXPECTED_POLICY_KEYS


def test_policy_is_frozen_and_rules_are_an_immutable_tuple() -> None:
    policy = pol.AnalysisPolicy.from_dict(_policy_wire())
    assert isinstance(policy.rules, tuple)
    with pytest.raises(dataclasses.FrozenInstanceError):
        policy.policy_id = "policy:other"  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        policy.rules = ()  # type: ignore[misc]


def test_policy_does_not_alias_caller_containers() -> None:
    wire = _policy_wire()
    kwargs = _constructor_kwargs(wire)
    rules = list(kwargs["rules"])
    policy = pol.AnalysisPolicy(**{**kwargs, "rules": rules})
    rules.clear()
    assert len(policy.rules) == len(SORTED_RULE_TYPES)
    first = policy.to_dict()
    first["rules"].clear()
    first["applicability_scope"]["currency"] = "USD"
    assert policy.to_dict() == wire


def test_policy_schema_member_is_required_and_exact() -> None:
    for bad in ("smart_ads/analysis_policy/v2", "analysis_policy", "", None, 1):
        with rejects("schema_mismatch"):
            pol.AnalysisPolicy.from_dict(_policy_wire(**{"$schema": bad}))
    with rejects("missing_member"):
        pol.AnalysisPolicy.from_dict(_without(_policy_wire(), "$schema"))


def test_policy_rejects_extra_and_each_missing_core_member() -> None:
    with rejects("unknown_member"):
        pol.AnalysisPolicy.from_dict(_policy_wire(extra="x"))
    with rejects("unknown_member"):
        pol.AnalysisPolicy.from_dict(_with_unsigned(_policy_wire(extra="x")))
    for key in sorted(EXPECTED_POLICY_CORE_KEYS):
        with rejects("missing_member"):
            pol.AnalysisPolicy.from_dict(_without(_policy_wire(), key))
    for bad in (None, [], "policy", 7):
        with rejects("invalid_type"):
            pol.AnalysisPolicy.from_dict(bad)


IDENTITY_CASES = [
    ("policy_id", "", "invalid_grammar"),
    ("policy_id", "policy", "invalid_grammar"),
    ("policy_id", "policy:", "invalid_grammar"),
    ("policy_id", "tenant:acme", "invalid_grammar"),
    ("policy_id", "Policy:acme", "invalid_grammar"),
    ("policy_id", "policy:acme\n", "invalid_grammar"),
    ("policy_id", None, "invalid_type"),
    ("policy_id", 1, "invalid_type"),
    ("policy_version", "", "invalid_grammar"),
    ("policy_version", "   ", "invalid_grammar"),
    ("policy_version", "v1\u0000", "invalid_grammar"),
    ("policy_version", "café", "invalid_grammar"),
    ("policy_version", None, "invalid_type"),
    ("policy_version", 1, "invalid_type"),
    ("policy_version", 1.0, "invalid_type"),
    ("tenant_ref", "", "invalid_grammar"),
    ("tenant_ref", "tenant", "invalid_grammar"),
    ("tenant_ref", "scope:acme", "invalid_grammar"),
    ("tenant_ref", "Tenant:acme", "invalid_grammar"),
    ("tenant_ref", None, "invalid_type"),
    ("tenant_ref", 1, "invalid_type"),
]


@pytest.mark.parametrize(("field", "bad", "code"), IDENTITY_CASES)
def test_policy_rejects_malformed_identity_members(field: str, bad: Any, code: str) -> None:
    with rejects(code):
        pol.AnalysisPolicy.from_dict(_policy_wire(**{field: bad}))


def test_policy_rejects_malformed_scope_and_validity_members() -> None:
    for bad in (None, [], "scope", 7):
        with rejects("invalid_type"):
            pol.AnalysisPolicy.from_dict(_policy_wire(applicability_scope=bad))
    with rejects("unknown_member"):
        pol.AnalysisPolicy.from_dict(
            _policy_wire(applicability_scope={**SCOPE_WIRE, "extra": 1})
        )
    with rejects("unsupported_value"):
        pol.AnalysisPolicy.from_dict(
            _policy_wire(applicability_scope={**SCOPE_WIRE, "currency": "USD"})
        )
    reversed_window = {
        "valid_from_utc": VALIDITY_WIRE["valid_until_utc"],
        "valid_until_utc": VALIDITY_WIRE["valid_from_utc"],
    }
    for bad in (None, [], "window", 7):
        with rejects("invalid_type"):
            pol.AnalysisPolicy.from_dict(_policy_wire(validity=bad))
    with rejects("unknown_member"):
        pol.AnalysisPolicy.from_dict(_policy_wire(validity={**VALIDITY_WIRE, "extra": 1}))
    with rejects("invalid_validity_window"):
        pol.AnalysisPolicy.from_dict(_policy_wire(validity=reversed_window))


# --------------------------------------------------------------------------------------
# rules array: non-empty, unique, sorted by raw UTF-8 bytes of rule_id
# --------------------------------------------------------------------------------------


def test_policy_rules_must_be_a_non_empty_json_array() -> None:
    with rejects("empty"):
        pol.AnalysisPolicy.from_dict(_policy_wire(rules=[]))
    for bad in (None, "rules", 7, {"rule_id": "rule:x"}, tuple(_wire(k) for k in SORTED_RULE_TYPES)):
        with rejects("invalid_type"):
            pol.AnalysisPolicy.from_dict(_policy_wire(rules=bad))


def test_policy_accepts_a_single_rule_and_several_rules_of_the_same_type() -> None:
    one = pol.AnalysisPolicy.from_dict(_policy_wire(rules=[_wire("waste")]))
    assert len(one.rules) == 1
    first = _wire("waste", rule_id="rule:waste-1d", window_days=1)
    second = _wire("waste", rule_id="rule:waste-7d", window_days=7)
    two = pol.AnalysisPolicy.from_dict(_policy_wire(rules=[first, second]))
    assert [r.window_days for r in two.rules] == [1, 7]


def test_policy_rejects_duplicate_rule_id_even_across_rule_types() -> None:
    waste = _wire("waste", rule_id="rule:shared")
    stalled = _wire("stalled_delivery", rule_id="rule:shared")
    with rejects("duplicate_rule_id"):
        pol.AnalysisPolicy.from_dict(_policy_wire(rules=[waste, stalled]))
    with rejects("duplicate_rule_id"):
        pol.AnalysisPolicy.from_dict(_policy_wire(rules=[waste, copy.deepcopy(waste)]))


def test_policy_rejects_unsorted_rules_in_wire_and_constructor() -> None:
    wire = _policy_wire(rules=[_wire(kind) for kind in reversed(SORTED_RULE_TYPES)])
    with rejects("unsorted"):
        pol.AnalysisPolicy.from_dict(wire)
    kwargs = _constructor_kwargs(_policy_wire())
    for ordering in (
        tuple(reversed(SORTED_RULE_TYPES)),
        ("saturation", "restatement", "stalled_delivery", "waste"),
    ):
        rules = tuple(pol.rule_from_dict(_wire(kind)) for kind in ordering)
        with rejects("unsorted"):
            pol.AnalysisPolicy(**{**kwargs, "rules": rules})


def test_policy_orders_rule_ids_by_raw_utf8_bytes_not_case_folded() -> None:
    upper = _wire("waste", rule_id="rule:Zeta", window_days=3)
    lower = _wire("waste", rule_id="rule:alpha", window_days=5)
    # b"rule:Zeta" < b"rule:alpha" because 0x5A < 0x61.
    parsed = pol.AnalysisPolicy.from_dict(_policy_wire(rules=[upper, lower]))
    assert [r.rule_id for r in parsed.rules] == ["rule:Zeta", "rule:alpha"]
    with rejects("unsorted"):
        pol.AnalysisPolicy.from_dict(_policy_wire(rules=[lower, upper]))


def test_policy_rejects_unknown_rule_type_and_malformed_members_inside_rules() -> None:
    rules = [_wire(kind) for kind in SORTED_RULE_TYPES]
    for index in range(len(rules)):
        for mutate, code in (
            (lambda r: r.update(rule_type="mutation_recommendation"), "unknown_rule_type"),
            (lambda r: r.update(extra=1), "unknown_member"),
            (lambda r: r.update(rule_id=7), "invalid_type"),
        ):
            broken = copy.deepcopy(rules)
            mutate(broken[index])
            with rejects(code):
                pol.AnalysisPolicy.from_dict(_policy_wire(rules=broken))
        non_mapping = copy.deepcopy(rules)
        non_mapping[index] = "rule"
        with rejects("invalid_type"):
            pol.AnalysisPolicy.from_dict(_policy_wire(rules=non_mapping))


def test_policy_constructor_accepts_only_rule_instances_scope_and_validity() -> None:
    kwargs = _constructor_kwargs(_policy_wire())
    for bad_rules in (
        ({"rule_id": "rule:x"},),
        (_wire("waste"),),
        (None,),
        ("rule:x",),
        None,
        "rules",
    ):
        with rejects("invalid_type"):
            pol.AnalysisPolicy(**{**kwargs, "rules": bad_rules})
    with rejects("empty"):
        pol.AnalysisPolicy(**{**kwargs, "rules": ()})
    with rejects("invalid_type"):
        pol.AnalysisPolicy(**{**kwargs, "applicability_scope": SCOPE_WIRE})
    with rejects("invalid_type"):
        pol.AnalysisPolicy(**{**kwargs, "validity": VALIDITY_WIRE})


# --------------------------------------------------------------------------------------
# P1 preimage and content digest
# --------------------------------------------------------------------------------------


def test_p1_domain_prefix_is_the_adr_analysis_policy_prefix() -> None:
    assert ADR_P1_DOMAIN_PREFIXES[pol.AnalysisPolicy.SCHEMA] == "SMART-ADS:ANALYSIS-POLICY:V1\n"
    assert pol.AnalysisPolicy.P1_DOMAIN_PREFIX == "SMART-ADS:ANALYSIS-POLICY:V1\n"


def test_p1_preimage_is_the_envelope_without_digest_and_signature() -> None:
    signed_wire = _signed_wire(_policy_wire())
    policy = pol.AnalysisPolicy.from_dict(signed_wire, require_signed=True)
    expected = copy.deepcopy(signed_wire)
    del expected["integrity"]["content_digest"]
    del expected["integrity"]["signature_base64"]
    assert policy.p1_preimage() == expected
    assert policy.to_dict() == signed_wire  # computing the preimage never mutates the policy


def test_p1_content_digest_is_sha256_of_the_rfc8785_preimage() -> None:
    policy = pol.AnalysisPolicy.from_dict(_with_unsigned(_policy_wire()))
    expected = "sha256:" + hashlib.sha256(canonicalize_jcs(policy.p1_preimage())).hexdigest()
    assert policy.p1_content_digest() == expected
    signed = pol.AnalysisPolicy.from_dict(_signed_wire(_policy_wire()), require_signed=True)
    assert signed.p1_content_digest() == expected
    assert signed.integrity is not None and signed.integrity.content_digest == expected


def test_p1_preimage_matches_hand_written_canonical_json() -> None:
    wire = _with_unsigned(
        _policy_wire(rules=[_wire("restatement", restatement_kinds=["tombstone"])])
    )
    policy = pol.AnalysisPolicy.from_dict(wire)
    locator = KEY_REGISTRY_LOCATOR.content_digest
    expected = (
        '{"$schema":"smart_ads/analysis_policy/v1",'
        '"applicability_scope":{"ad_platform_ref":"meta","currency":"BRL",'
        '"resource_level":"campaign","resource_scope_ref":"scope:acme-main"},'
        f'"integrity":{{"key_id":"{KEY_ID}","key_registry_snapshot_locator":'
        '{"$schema":"smart_ads/artifact_locator/v1",'
        '"artifact_type":"smart_ads/key_authorization_registry/v1",'
        f'"content_digest":"{locator}","object_ref":"cell-object:{locator}",'
        '"serialization":"rfc8785-json","store_kind":"cell_immutable_object"}},'
        '"policy_id":"policy:acme-default","policy_version":"2026.11.1",'
        '"rules":[{"lookback_days":28,"restatement_kinds":["tombstone"],'
        '"rule_id":"rule:restatement-28d","rule_type":"restatement"}],'
        '"tenant_ref":"tenant:acme",'
        '"validity":{"valid_from_utc":"2026-01-01T00:00:00.000000Z",'
        '"valid_until_utc":"2026-12-31T23:59:59.999999Z"}}'
    ).encode("utf-8")
    assert canonicalize_jcs(policy.p1_preimage()) == expected
    assert policy.p1_content_digest() == "sha256:" + hashlib.sha256(expected).hexdigest()


def test_p1_preimage_carries_int64_thresholds_as_strings() -> None:
    wire = _with_unsigned(
        _policy_wire(rules=[_wire("waste", min_spend_minor=MAX_UINT64_TEXT)])
    )
    canonical = canonicalize_jcs(pol.AnalysisPolicy.from_dict(wire).p1_preimage())
    assert b'"min_spend_minor":"9223372036854775807"' in canonical
    assert b'"max_outcome_count":"0"' in canonical
    assert b'"window_days":14' in canonical


THRESHOLD_MUTATIONS = (
    ("saturation", "window_days", 8),
    ("saturation", "min_spend_growth", "0.200001"),
    ("saturation", "max_outcome_growth", "0.050001"),
    ("saturation", "min_baseline_spend_minor", "10001"),
    ("saturation", "spend_metric_ref", "metric:media_spend_v1"),
    ("saturation", "outcome_metric_ref", "metric:impressions_v1"),
    ("waste", "window_days", 15),
    ("waste", "min_spend_minor", "50001"),
    ("waste", "max_outcome_count", "1"),
    ("stalled_delivery", "min_consecutive_days", 4),
    ("stalled_delivery", "max_impressions", "1"),
    ("restatement", "lookback_days", 29),
    ("restatement", "restatement_kinds", ["tombstone"]),
)


def _wire_with_rule_mutation(kind: str, field: str, value: Any, **extra: Any) -> dict[str, Any]:
    rules = [
        _wire(k, **({field: value} if k == kind else {})) for k in SORTED_RULE_TYPES
    ]
    return _policy_wire(rules=rules, **extra)


def test_p1_content_digest_changes_with_any_threshold_and_ignores_the_signature() -> None:
    base = pol.AnalysisPolicy.from_dict(_with_unsigned(_policy_wire())).p1_content_digest()
    other_signature = base64.b64encode(bytes([1]) * 64).decode("ascii")
    resigned = pol.AnalysisPolicy.from_dict(
        _signed_wire(_policy_wire(), signature=other_signature), require_signed=True
    )
    assert resigned.p1_content_digest() == base
    seen = {base}
    for kind, field, value in THRESHOLD_MUTATIONS:
        mutated = pol.AnalysisPolicy.from_dict(
            _with_unsigned(_wire_with_rule_mutation(kind, field, value))
        )
        digest = mutated.p1_content_digest()
        assert digest not in seen
        seen.add(digest)


def test_p1_digest_is_unavailable_without_an_integrity_block() -> None:
    policy = pol.AnalysisPolicy.from_dict(_policy_wire())
    with rejects("missing_member"):
        policy.p1_preimage()
    with rejects("missing_member"):
        policy.p1_content_digest()


def test_signed_policy_with_a_wrong_or_stale_digest_is_rejected() -> None:
    good = _signed_wire(_policy_wire())
    pol.AnalysisPolicy.from_dict(good, require_signed=True)

    wrong = copy.deepcopy(good)
    wrong["integrity"]["content_digest"] = "sha256:" + "0" * 64
    with rejects("content_digest_mismatch"):
        pol.AnalysisPolicy.from_dict(wrong, require_signed=True)

    tampered = copy.deepcopy(good)
    tampered["rules"][2]["max_impressions"] = "1"  # stalled_delivery threshold after signing
    with rejects("content_digest_mismatch"):
        pol.AnalysisPolicy.from_dict(tampered, require_signed=True)

    tampered_scope = copy.deepcopy(good)
    tampered_scope["applicability_scope"]["resource_scope_ref"] = "scope:other"
    with rejects("content_digest_mismatch"):
        pol.AnalysisPolicy.from_dict(tampered_scope)


def test_integrity_states_are_closed() -> None:
    signed = _signed_wire(_policy_wire())
    with rejects("missing_member"):
        pol.AnalysisPolicy.from_dict(_policy_wire(), require_signed=True)
    with rejects("invalid_integrity"):
        pol.AnalysisPolicy.from_dict(_with_unsigned(_policy_wire()), require_signed=True)
    with rejects("invalid_type"):
        pol.AnalysisPolicy.from_dict(signed, require_signed="yes")  # type: ignore[arg-type]
    partial = copy.deepcopy(signed)
    del partial["integrity"]["signature_base64"]
    with rejects("invalid_integrity"):
        pol.AnalysisPolicy.from_dict(partial)
    short_signature = _signed_wire(
        _policy_wire(), signature=base64.b64encode(bytes(63)).decode()
    )
    with rejects("invalid_integrity"):
        pol.AnalysisPolicy.from_dict(short_signature, require_signed=True)
    with rejects("invalid_integrity"):
        pol.AnalysisPolicy.from_dict(_policy_wire(integrity={**UNSIGNED_INTEGRITY, "extra": 1}))
    for bad in (None, [], "integrity"):
        with rejects("invalid_integrity"):
            pol.AnalysisPolicy.from_dict(_policy_wire(integrity=bad))
    with rejects("invalid_integrity"):
        pol.AnalysisPolicy(**{**_constructor_kwargs(_policy_wire()), "integrity": UNSIGNED_INTEGRITY})


def test_policy_with_largest_thresholds_still_has_a_computable_digest() -> None:
    day_fields = {field for _, field in DAY_FIELD_CASES}
    uint_fields = {field for _, field in UINT64_FIELD_CASES}
    rules = []
    for kind in SORTED_RULE_TYPES:
        overrides = {}
        for field in EXPECTED_RULE_KEYS[kind]:
            if field in day_fields:
                overrides[field] = MAX_JCS_SAFE_INT
            elif field in uint_fields:
                overrides[field] = MAX_UINT64_TEXT
        rules.append(_wire(kind, **overrides))
    policy = pol.AnalysisPolicy.from_dict(_with_unsigned(_policy_wire(rules=rules)))
    assert policy.p1_content_digest().startswith("sha256:")


# --------------------------------------------------------------------------------------
# Locator: ArtifactLocator over the canonical bytes of the full envelope
# --------------------------------------------------------------------------------------


def test_locator_is_the_artifact_locator_over_the_canonical_envelope_bytes() -> None:
    for wire in (_policy_wire(), _with_unsigned(_policy_wire()), _signed_wire(_policy_wire())):
        policy = pol.AnalysisPolicy.from_dict(wire)
        locator = policy.locator()
        digest = "sha256:" + hashlib.sha256(canonicalize_jcs(policy.to_dict())).hexdigest()
        assert isinstance(locator, ArtifactLocator)
        assert locator == ArtifactLocator.from_digest(pol.AnalysisPolicy.SCHEMA, digest)
        assert locator == ArtifactLocator.for_canonical_bytes(
            pol.AnalysisPolicy.SCHEMA, canonicalize_jcs(policy.to_dict())
        )
        assert locator.artifact_type == "smart_ads/analysis_policy/v1"
        assert locator.content_digest == digest
        assert locator.object_ref == f"cell-object:{digest}"
        assert pol.AnalysisPolicy.from_dict(policy.to_dict()).locator() == locator
        assert policy.locator() == locator


def _locator_of(wire: dict[str, Any]) -> ArtifactLocator:
    return pol.AnalysisPolicy.from_dict(wire).locator()


def test_locator_changes_when_any_member_changes() -> None:
    base_wire = _with_unsigned(_policy_wire())
    variants = {
        "base": base_wire,
        "policy_id": {**base_wire, "policy_id": "policy:acme-other"},
        "policy_version": {**base_wire, "policy_version": "2026.11.2"},
        "tenant_ref": {**base_wire, "tenant_ref": "tenant:other"},
        "resource_scope_ref": {
            **base_wire,
            "applicability_scope": {**SCOPE_WIRE, "resource_scope_ref": "scope:other"},
        },
        "valid_from_utc": {
            **base_wire,
            "validity": {**VALIDITY_WIRE, "valid_from_utc": "2026-01-01T00:00:00.000001Z"},
        },
        "valid_until_utc": {
            **base_wire,
            "validity": {**VALIDITY_WIRE, "valid_until_utc": "2026-12-31T23:59:59.999998Z"},
        },
        "key_id": {
            **base_wire,
            "integrity": {**UNSIGNED_INTEGRITY, "key_id": "key:ed25519:" + "b" * 64},
        },
        "no_integrity": _policy_wire(),
        "signed": _signed_wire(_policy_wire()),
        "fewer_rules": {**base_wire, "rules": base_wire["rules"][:-1]},
    }
    for kind, field, value in THRESHOLD_MUTATIONS:
        variants[f"{kind}.{field}"] = _with_unsigned(_wire_with_rule_mutation(kind, field, value))
    digests = {name: _locator_of(wire).content_digest for name, wire in variants.items()}
    assert len(set(digests.values())) == len(variants), digests


# --------------------------------------------------------------------------------------
# Applicability and validity: pure, instant passed in, never a clock
# --------------------------------------------------------------------------------------

BEFORE_VALID_FROM = "2025-12-31T23:59:59.999999Z"  # valid_from - 1 microsecond
VALID_FROM = VALIDITY_WIRE["valid_from_utc"]
INSIDE_WINDOW = "2026-06-15T12:30:00.123456Z"
VALID_UNTIL = VALIDITY_WIRE["valid_until_utc"]
AFTER_VALID_UNTIL = "2027-01-01T00:00:00.000000Z"  # valid_until + 1 microsecond

MATCHING_SCOPE_KWARGS: dict[str, str] = {
    "tenant_ref": "tenant:acme",
    "resource_scope_ref": "scope:acme-main",
    "resource_level": "campaign",
    "ad_platform_ref": "meta",
    "currency": "BRL",
}


def _policy() -> pol.AnalysisPolicy:
    return pol.AnalysisPolicy.from_dict(_policy_wire())


def _eval_scope(**overrides: str) -> pol.EvaluationScope:
    return pol.EvaluationScope(**{**MATCHING_SCOPE_KWARGS, **overrides})


def test_applicability_codes_are_the_unchanged_closed_seven() -> None:
    assert pol.POLICY_NOT_APPLICABLE_CODES == (
        "tenant_mismatch",
        "resource_scope_mismatch",
        "resource_level_mismatch",
        "ad_platform_mismatch",
        "currency_mismatch",
        "not_yet_valid",
        "expired",
    )
    assert issubclass(pol.PolicyNotApplicableError, ClosedValidationError)
    for code in pol.POLICY_NOT_APPLICABLE_CODES:
        error = pol.PolicyNotApplicableError(code, "detail")
        assert error.code == code
        assert code in str(error)
    for bad in ("", "tenant", "EXPIRED", "invalid_type", None, 1, ["expired"]):
        with pytest.raises(ClosedValidationError) as caught:
            pol.PolicyNotApplicableError(bad, "detail")  # type: ignore[arg-type]
        assert type(caught.value) is ClosedValidationError


EVAL_SCOPE_CASES = [
    ("tenant_ref", "scope:acme", "invalid_grammar"),
    ("tenant_ref", "", "invalid_grammar"),
    ("tenant_ref", None, "invalid_type"),
    ("resource_scope_ref", "tenant:acme", "invalid_grammar"),
    ("resource_scope_ref", None, "invalid_type"),
    ("resource_level", "", "invalid_grammar"),
    ("resource_level", None, "invalid_type"),
    ("resource_level", 1, "invalid_type"),
    ("ad_platform_ref", "", "invalid_grammar"),
    ("ad_platform_ref", None, "invalid_type"),
    ("currency", "usd", "invalid_grammar"),
    ("currency", "BR", "invalid_grammar"),
    ("currency", None, "invalid_type"),
]


def test_evaluation_scope_requires_well_formed_members_but_not_phase1_values() -> None:
    other = _eval_scope(resource_level="adset", ad_platform_ref="google", currency="USD")
    assert (other.resource_level, other.ad_platform_ref, other.currency) == (
        "adset",
        "google",
        "USD",
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        other.currency = "BRL"  # type: ignore[misc]


@pytest.mark.parametrize(("field", "bad", "code"), EVAL_SCOPE_CASES)
def test_evaluation_scope_rejects_malformed_members(field: str, bad: Any, code: str) -> None:
    with rejects(code):
        _eval_scope(**{field: bad})


def test_matching_scope_inside_the_window_is_applicable() -> None:
    policy = _policy()
    assert pol.policy_applicability_code(policy, _eval_scope(), INSIDE_WINDOW) is None
    assert pol.require_policy_applicable(policy, _eval_scope(), INSIDE_WINDOW) is None


def test_validity_is_a_closed_interval_instant_equal_to_valid_from_is_applicable() -> None:
    policy = _policy()
    assert pol.policy_applicability_code(policy, _eval_scope(), VALID_FROM) is None
    pol.require_policy_applicable(policy, _eval_scope(), VALID_FROM)


def test_validity_is_a_closed_interval_instant_equal_to_valid_until_is_applicable() -> None:
    policy = _policy()
    assert pol.policy_applicability_code(policy, _eval_scope(), VALID_UNTIL) is None
    pol.require_policy_applicable(policy, _eval_scope(), VALID_UNTIL)


def test_instant_one_microsecond_before_valid_from_is_not_yet_valid() -> None:
    policy = _policy()
    assert (
        pol.policy_applicability_code(policy, _eval_scope(), BEFORE_VALID_FROM)
        == "not_yet_valid"
    )
    with pytest.raises(pol.PolicyNotApplicableError) as caught:
        pol.require_policy_applicable(policy, _eval_scope(), BEFORE_VALID_FROM)
    assert caught.value.code == "not_yet_valid"


def test_instant_one_microsecond_after_valid_until_is_expired() -> None:
    policy = _policy()
    assert (
        pol.policy_applicability_code(policy, _eval_scope(), AFTER_VALID_UNTIL) == "expired"
    )
    with pytest.raises(pol.PolicyNotApplicableError) as caught:
        pol.require_policy_applicable(policy, _eval_scope(), AFTER_VALID_UNTIL)
    assert caught.value.code == "expired"


def test_instants_far_outside_the_window_are_classified_by_side() -> None:
    policy = _policy()
    far_past = "1970-01-01T00:00:00.000000Z"
    far_future = "9999-12-31T23:59:59.999999Z"
    assert pol.policy_applicability_code(policy, _eval_scope(), far_past) == "not_yet_valid"
    assert pol.policy_applicability_code(policy, _eval_scope(), far_future) == "expired"


def test_window_comparison_is_chronological_at_microsecond_resolution() -> None:
    policy = pol.AnalysisPolicy.from_dict(
        _policy_wire(
            validity={
                "valid_from_utc": "2026-06-01T12:00:00.000001Z",
                "valid_until_utc": "2026-06-01T12:00:00.000002Z",
            }
        )
    )
    scope = _eval_scope()
    code = pol.policy_applicability_code
    assert code(policy, scope, "2026-06-01T12:00:00.000000Z") == "not_yet_valid"
    assert code(policy, scope, "2026-06-01T12:00:00.000001Z") is None
    assert code(policy, scope, "2026-06-01T12:00:00.000002Z") is None
    assert code(policy, scope, "2026-06-01T12:00:00.000003Z") == "expired"


SCOPE_MISMATCH_CASES = (
    pytest.param("tenant_ref", "tenant:other", "tenant_mismatch", id="tenant"),
    pytest.param(
        "resource_scope_ref", "scope:other", "resource_scope_mismatch", id="resource_scope"
    ),
    pytest.param("resource_level", "adset", "resource_level_mismatch", id="resource_level"),
    pytest.param("ad_platform_ref", "google", "ad_platform_mismatch", id="ad_platform"),
    pytest.param("currency", "USD", "currency_mismatch", id="currency"),
)


@pytest.mark.parametrize(("field", "other", "code"), SCOPE_MISMATCH_CASES)
def test_each_scope_dimension_mismatch_has_its_own_code(
    field: str, other: str, code: str
) -> None:
    policy = _policy()
    scope = _eval_scope(**{field: other})
    assert pol.policy_applicability_code(policy, scope, INSIDE_WINDOW) == code
    with pytest.raises(pol.PolicyNotApplicableError) as caught:
        pol.require_policy_applicable(policy, scope, INSIDE_WINDOW)
    assert caught.value.code == code
    assert isinstance(caught.value, ClosedValidationError)


def test_scope_mismatch_codes_cover_every_closed_code_with_validity_ones() -> None:
    seen = {case.values[2] for case in SCOPE_MISMATCH_CASES} | {"not_yet_valid", "expired"}
    assert seen == set(pol.POLICY_NOT_APPLICABLE_CODES)


def test_scope_mismatch_is_reported_before_validity_and_in_documented_order() -> None:
    policy = _policy()
    everything_wrong = _eval_scope(
        tenant_ref="tenant:other",
        resource_scope_ref="scope:other",
        resource_level="adset",
        ad_platform_ref="google",
        currency="USD",
    )
    code = pol.policy_applicability_code
    assert code(policy, everything_wrong, AFTER_VALID_UNTIL) == "tenant_mismatch"
    no_tenant_error = _eval_scope(
        resource_scope_ref="scope:other",
        resource_level="adset",
        ad_platform_ref="google",
        currency="USD",
    )
    assert code(policy, no_tenant_error, BEFORE_VALID_FROM) == "resource_scope_mismatch"
    assert code(policy, _eval_scope(currency="USD"), AFTER_VALID_UNTIL) == "currency_mismatch"


MALFORMED_INSTANT_CASES = [
    ("", "invalid_grammar"),
    ("2026-06-15T12:30:00Z", "invalid_grammar"),
    ("2026-06-15T12:30:00.123Z", "invalid_grammar"),
    ("2026-06-15T12:30:00.123456", "invalid_grammar"),
    ("2026-06-15T12:30:00.123456+00:00", "invalid_grammar"),
    ("2026-06-15 12:30:00.123456Z", "invalid_grammar"),
    ("2026-02-30T12:30:00.123456Z", "invalid_grammar"),
    ("2026-06-15T12:30:60.123456Z", "invalid_grammar"),
    ("2026-06-15", "invalid_grammar"),
    (None, "invalid_type"),
    (0, "invalid_type"),
    (1_780_000_000, "invalid_type"),
    (True, "invalid_type"),
    (b"2026-06-15T12:30:00.123456Z", "invalid_type"),
]


@pytest.mark.parametrize(("bad_instant", "code"), MALFORMED_INSTANT_CASES)
def test_malformed_instant_is_a_validation_error_not_a_not_applicable_verdict(
    bad_instant: Any, code: str
) -> None:
    policy = _policy()
    with rejects(code):
        pol.policy_applicability_code(policy, _eval_scope(), bad_instant)
    with rejects(code):
        pol.require_policy_applicable(policy, _eval_scope(), bad_instant)


def test_malformed_instant_is_rejected_even_when_the_scope_already_mismatches() -> None:
    with rejects("invalid_grammar"):
        pol.policy_applicability_code(
            _policy(), _eval_scope(tenant_ref="tenant:other"), "not-a-time"
        )


def test_applicability_arguments_must_be_typed_objects() -> None:
    with rejects("invalid_type"):
        pol.policy_applicability_code(_policy_wire(), _eval_scope(), INSIDE_WINDOW)  # type: ignore[arg-type]
    with rejects("invalid_type"):
        pol.policy_applicability_code(_policy(), MATCHING_SCOPE_KWARGS, INSIDE_WINDOW)  # type: ignore[arg-type]
    with rejects("invalid_type"):
        pol.require_policy_applicable(None, _eval_scope(), INSIDE_WINDOW)  # type: ignore[arg-type]


def test_evaluation_instant_is_a_required_argument_never_a_defaulted_clock() -> None:
    for function in (pol.policy_applicability_code, pol.require_policy_applicable):
        parameter = inspect.signature(function).parameters["evaluation_instant_utc"]
        assert parameter.default is inspect.Parameter.empty
        with pytest.raises(TypeError):
            function(_policy(), _eval_scope())  # type: ignore[call-arg]


def test_applicability_is_deterministic_and_leaves_the_policy_untouched() -> None:
    policy = _policy()
    before = policy.to_dict()
    results = {
        pol.policy_applicability_code(policy, _eval_scope(currency="USD"), INSIDE_WINDOW)
        for _ in range(5)
    }
    assert results == {"currency_mismatch"}
    assert policy.to_dict() == before


def test_applicability_does_not_depend_on_rule_parameters() -> None:
    zero_thresholds = pol.AnalysisPolicy.from_dict(
        _policy_wire(
            rules=[_wire("stalled_delivery", min_consecutive_days=1, max_impressions="0")]
        )
    )
    assert pol.policy_applicability_code(zero_thresholds, _eval_scope(), INSIDE_WINDOW) is None
    assert (
        pol.policy_applicability_code(zero_thresholds, _eval_scope(), AFTER_VALID_UNTIL)
        == "expired"
    )


class _AlwaysEq:
    def __eq__(self, other: object) -> bool:
        return True


def test_applicability_revalidates_tampered_policy_and_scope() -> None:
    bad_ts = _policy()
    object.__setattr__(bad_ts.validity, "valid_from_utc", "bad")
    with rejects("invalid_grammar"):
        pol.policy_applicability_code(bad_ts, _eval_scope(), INSIDE_WINDOW)
    with rejects("invalid_grammar"):
        pol.require_policy_applicable(bad_ts, _eval_scope(), INSIDE_WINDOW)

    null_validity = _policy()
    object.__setattr__(null_validity, "validity", None)
    with rejects("invalid_type"):
        pol.policy_applicability_code(null_validity, _eval_scope(), INSIDE_WINDOW)

    inverted_validity = _policy()
    object.__setattr__(
        inverted_validity.validity, "valid_from_utc", inverted_validity.validity.valid_until_utc
    )
    with rejects("invalid_validity_window"):
        pol.policy_applicability_code(inverted_validity, _eval_scope(), INSIDE_WINDOW)

    empty_rules = _policy()
    object.__setattr__(empty_rules, "rules", ())
    with rejects("empty"):
        pol.policy_applicability_code(empty_rules, _eval_scope(), INSIDE_WINDOW)

    bad_scope = _eval_scope()
    object.__setattr__(bad_scope, "currency", "usd")
    with rejects("invalid_grammar"):
        pol.policy_applicability_code(_policy(), bad_scope, INSIDE_WINDOW)

    deleted_scope = _eval_scope()
    object.__delattr__(deleted_scope, "tenant_ref")
    with rejects("invalid_type"):
        pol.require_policy_applicable(_policy(), deleted_scope, INSIDE_WINDOW)


def test_reparsed_rejects_partial_p1_integrity_and_always_eq_locators() -> None:
    signed = pol.AnalysisPolicy.from_dict(_signed_wire(_policy_wire()), require_signed=True)
    assert signed.integrity is not None
    object.__setattr__(signed.integrity, "signature_base64", None)
    with rejects("invalid_type"):
        pol.policy_applicability_code(signed, _eval_scope(), INSIDE_WINDOW)

    for partial_slot in ("content_digest", "signature_base64"):
        clean_unsigned = P1Integrity(
            key_id="key:ed25519:" + "a" * 64,
            key_registry_snapshot_locator=ArtifactLocator(
                "smart_ads/key_authorization_registry/v1",
                "sha256:" + "c" * 64,
                object_ref="cell-object:sha256:" + "c" * 64,
            ),
        )
        object.__setattr__(clean_unsigned, partial_slot, _AlwaysEq())
        unsigned_partial = dataclasses.replace(_policy(), integrity=clean_unsigned)
        with rejects("invalid_type"):
            pol.policy_applicability_code(unsigned_partial, _eval_scope(), INSIDE_WINDOW)
        with rejects("invalid_type"):
            pol._reparsed(pol._fail, "invalid_type", P1Integrity, clean_unsigned)

    bad_reg_loc = ArtifactLocator(
        "smart_ads/key_authorization_registry/v1",
        "sha256:" + "c" * 64,
        store_kind=_AlwaysEq(),  # type: ignore[arg-type]
        object_ref="cell-object:sha256:" + "c" * 64,
    )
    bad_unsigned = P1Integrity(
        key_id="key:ed25519:" + "a" * 64,
        key_registry_snapshot_locator=bad_reg_loc,
    )
    with_always_eq = dataclasses.replace(_policy(), integrity=bad_unsigned)
    with rejects("invalid_type"):
        pol.policy_applicability_code(with_always_eq, _eval_scope(), INSIDE_WINDOW)


# --------------------------------------------------------------------------------------
# Public API surface
# --------------------------------------------------------------------------------------

EXPECTED_PUBLIC_API = frozenset(
    {
        "AnalysisPolicy",
        "AnalysisRule",
        "ApplicabilityScope",
        "EvaluationScope",
        "METRIC_REF_PATTERN",
        "POLICY_ERROR_CODES",
        "POLICY_NOT_APPLICABLE_CODES",
        "PolicyNotApplicableError",
        "PolicyValidationError",
        "PolicyValidity",
        "RESTATEMENT_KINDS",
        "RULE_TYPES",
        "RULE_TYPE_RESTATEMENT",
        "RULE_TYPE_SATURATION",
        "RULE_TYPE_STALLED_DELIVERY",
        "RULE_TYPE_WASTE",
        "RestatementRule",
        "SaturationRule",
        "StalledDeliveryRule",
        "WasteRule",
        "decimal6_to_micros",
        "policy_applicability_code",
        "require_policy_applicable",
        "rule_from_dict",
    }
)


def test_public_api_is_pinned_and_every_export_resolves() -> None:
    assert len(pol.__all__) == len(set(pol.__all__))
    assert set(pol.__all__) == EXPECTED_PUBLIC_API
    for name in pol.__all__:
        assert hasattr(pol, name), name


# --------------------------------------------------------------------------------------
# Module hygiene: no float, no threshold literals, no clock, coded errors only
# --------------------------------------------------------------------------------------


def _policy_ast() -> ast.Module:
    return ast.parse(POLICY_MODULE_PATH.read_text(encoding="utf-8"))


def test_module_contains_no_float_and_no_hardcoded_threshold_literals() -> None:
    tree = _policy_ast()
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant):
            assert not isinstance(node.value, float), "float literal in policy.py"
        if isinstance(node, ast.Name):
            assert node.id != "float", "float referenced in policy.py"
    int_literals = {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and type(node.value) is int
    }
    # Only structural 0 / 1 (lower bounds and indexes) may appear; every threshold is data.
    assert int_literals <= {0, 1}, f"unexpected integer literals: {sorted(int_literals)}"


def test_every_structural_rejection_is_raised_as_a_coded_error() -> None:
    plain_raises = [
        node
        for node in ast.walk(_policy_ast())
        if isinstance(node, ast.Raise)
        and isinstance(node.exc, ast.Call)
        and isinstance(node.exc.func, ast.Name)
        and node.exc.func.id == "ClosedValidationError"
    ]
    # The single plain raise is the unknown-code guard inside the coded base error.
    assert len(plain_raises) == 1
