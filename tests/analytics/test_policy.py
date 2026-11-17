"""Tests for smart_ads.analytics.policy (ADR-0001 section 7, section 12.7 analysis_policy/v1)."""
from __future__ import annotations

import ast
import base64
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

# --------------------------------------------------------------------------------------
# Wire fixtures. Every threshold below is test data, never a module constant.
# --------------------------------------------------------------------------------------

SATURATION_WIRE: dict[str, Any] = {
    "rule_id": "rule:saturation-7d",
    "rule_type": "saturation",
    "window_days": 7,
    "spend_metric_ref": "metric:spend_v1",
    "outcome_metric_ref": "metric:aggregate_conversions_v1",
    "min_spend_growth": "0.200000",
    "max_outcome_growth": "0.050000",
    "min_baseline_spend_minor": 10000,
}
WASTE_WIRE: dict[str, Any] = {
    "rule_id": "rule:waste-14d",
    "rule_type": "waste",
    "window_days": 14,
    "spend_metric_ref": "metric:spend_v1",
    "outcome_metric_ref": "metric:aggregate_conversions_v1",
    "min_spend_minor": 50000,
    "max_outcome_count": 0,
}
STALLED_WIRE: dict[str, Any] = {
    "rule_id": "rule:stalled-3d",
    "rule_type": "stalled_delivery",
    "min_consecutive_days": 3,
    "max_impressions": 0,
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
    pytest.param(
        "restatement", pol.RestatementRule, RESTATEMENT_WIRE, id="restatement"
    ),
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

# (rule_type, field, minimum) for every strict integer parameter of the closed union.
INT_FIELD_CASES = (
    ("saturation", "window_days", 1),
    ("saturation", "min_baseline_spend_minor", 0),
    ("waste", "window_days", 1),
    ("waste", "min_spend_minor", 0),
    ("waste", "max_outcome_count", 0),
    ("stalled_delivery", "min_consecutive_days", 1),
    ("stalled_delivery", "max_impressions", 0),
    ("restatement", "lookback_days", 1),
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


class _IntSubclass(int):
    """A non-strict int: `type(v) is int` must reject it."""


def _wire(kind: str, /, **overrides: Any) -> dict[str, Any]:
    return {**copy.deepcopy(WIRE_BY_TYPE[kind]), **overrides}


def _without(mapping: dict[str, Any], key: str) -> dict[str, Any]:
    return {k: v for k, v in mapping.items() if k != key}


def _kwargs(kind: str, /, **overrides: Any) -> dict[str, Any]:
    return {k: v for k, v in _wire(kind, **overrides).items() if k != "rule_type"}


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
def test_rules_are_frozen(rule_type: str, cls: Any, wire: dict[str, Any]) -> None:
    rule = cls.from_dict(wire)
    with pytest.raises(dataclasses.FrozenInstanceError):
        rule.rule_id = "rule:other"  # type: ignore[misc]


def test_rule_type_union_is_closed_to_the_four_finding_types() -> None:
    assert set(pol.RULE_TYPES) == {
        "saturation",
        "waste",
        "stalled_delivery",
        "restatement",
    }
    assert list(pol.RULE_TYPES) == sorted(pol.RULE_TYPES, key=lambda s: s.encode())
    assert pol.AnalysisRule == (
        pol.SaturationRule | pol.WasteRule | pol.StalledDeliveryRule | pol.RestatementRule
    )


@pytest.mark.parametrize(
    "bad_type",
    ["mutation", "SATURATION", "", " saturation", "saturation ", "stalled-delivery"],
)
def test_rule_from_dict_rejects_unknown_rule_type(bad_type: str) -> None:
    with pytest.raises(ClosedValidationError):
        pol.rule_from_dict(_wire("saturation", rule_type=bad_type))


@pytest.mark.parametrize("bad_type", [None, 1, True, ["saturation"], {"a": 1}])
def test_rule_from_dict_rejects_non_string_rule_type(bad_type: Any) -> None:
    with pytest.raises(ClosedValidationError):
        pol.rule_from_dict(_wire("saturation", rule_type=bad_type))


def test_rule_from_dict_rejects_missing_rule_type_and_non_mapping() -> None:
    with pytest.raises(ClosedValidationError):
        pol.rule_from_dict(_without(_wire("saturation"), "rule_type"))
    for bad in (None, [], "saturation", 7):
        with pytest.raises(ClosedValidationError):
            pol.rule_from_dict(bad)


@pytest.mark.parametrize(("rule_type", "cls", "wire"), RULE_CASES)
def test_each_rule_class_rejects_a_foreign_rule_type(
    rule_type: str, cls: Any, wire: dict[str, Any]
) -> None:
    for other in EXPECTED_RULE_KEYS:
        if other == rule_type:
            continue
        with pytest.raises(ClosedValidationError):
            cls.from_dict({**wire, "rule_type": other})


@pytest.mark.parametrize(("rule_type", "cls", "wire"), RULE_CASES)
def test_rule_rejects_extra_member_and_non_mapping(
    rule_type: str, cls: Any, wire: dict[str, Any]
) -> None:
    with pytest.raises(ClosedValidationError):
        cls.from_dict({**wire, "extra": 1})
    with pytest.raises(ClosedValidationError):
        pol.rule_from_dict({**wire, "extra": 1})
    for bad in (None, [], "rule", 7):
        with pytest.raises(ClosedValidationError):
            cls.from_dict(bad)


MISSING_MEMBER_CASES = [
    pytest.param(rule_type, key, id=f"{rule_type}-{key}")
    for rule_type, keys in EXPECTED_RULE_KEYS.items()
    for key in sorted(keys)
]


@pytest.mark.parametrize(("rule_type", "key"), MISSING_MEMBER_CASES)
def test_rule_rejects_each_missing_member(rule_type: str, key: str) -> None:
    wire = _without(_wire(rule_type), key)
    with pytest.raises(ClosedValidationError):
        CLASS_BY_TYPE[rule_type].from_dict(wire)
    with pytest.raises(ClosedValidationError):
        pol.rule_from_dict(wire)


# --------------------------------------------------------------------------------------
# rule_id
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("rule_type", sorted(EXPECTED_RULE_KEYS))
@pytest.mark.parametrize(
    "bad_id",
    [
        "",
        "rule",
        "rule:",
        "Rule:x",
        "policy:x",
        "rule:has space",
        "rule:café",
        "rule:x\n",
        None,
        7,
        True,
        ["rule:x"],
    ],
)
def test_rule_rejects_malformed_rule_id(rule_type: str, bad_id: Any) -> None:
    with pytest.raises(ClosedValidationError):
        CLASS_BY_TYPE[rule_type].from_dict(_wire(rule_type, rule_id=bad_id))


# --------------------------------------------------------------------------------------
# Strict integers: type, range
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


@pytest.mark.parametrize(("rule_type", "field", "minimum"), INT_FIELD_CASES)
def test_int_parameters_reject_bool_float_str_and_int_subclasses(
    rule_type: str, field: str, minimum: int
) -> None:
    cls = CLASS_BY_TYPE[rule_type]
    for bad in NON_INT_VALUES:
        with pytest.raises(ClosedValidationError):
            cls.from_dict(_wire(rule_type, **{field: bad}))
        with pytest.raises(ClosedValidationError):
            cls(**_kwargs(rule_type, **{field: bad}))


@pytest.mark.parametrize(("rule_type", "field", "minimum"), INT_FIELD_CASES)
def test_int_parameters_enforce_their_lower_bound(
    rule_type: str, field: str, minimum: int
) -> None:
    cls = CLASS_BY_TYPE[rule_type]
    assert getattr(cls.from_dict(_wire(rule_type, **{field: minimum})), field) == minimum
    for below in (minimum - 1, -1, -MAX_INT64 - 1):
        with pytest.raises(ClosedValidationError):
            cls.from_dict(_wire(rule_type, **{field: below}))


@pytest.mark.parametrize(("rule_type", "field", "minimum"), INT_FIELD_CASES)
def test_int_parameters_accept_the_largest_json_safe_integer(
    rule_type: str, field: str, minimum: int
) -> None:
    cls = CLASS_BY_TYPE[rule_type]
    rule = cls.from_dict(_wire(rule_type, **{field: MAX_JCS_SAFE_INT}))
    assert rule.to_dict()[field] == MAX_JCS_SAFE_INT
    canonicalize_jcs(rule.to_dict())


@pytest.mark.parametrize(("rule_type", "field", "minimum"), INT_FIELD_CASES)
def test_int_parameters_above_jcs_safe_integer_are_rejected_not_deferred_to_digest_time(
    rule_type: str, field: str, minimum: int
) -> None:
    # Spec range is 0..MAX_INT64, but RFC 8785 / I-JSON (canonicalize_jcs) cannot carry an
    # integer above 2**53 - 1 as a JSON number, so the P1 preimage of such a policy would be
    # uncomputable. The module rejects at construction instead of failing at digest time.
    cls = CLASS_BY_TYPE[rule_type]
    for too_big in (MAX_JCS_SAFE_INT + 1, MAX_INT64, MAX_INT64 + 1):
        with pytest.raises(ClosedValidationError):
            cls.from_dict(_wire(rule_type, **{field: too_big}))
    with pytest.raises(ClosedValidationError):
        canonicalize_jcs({"v": MAX_JCS_SAFE_INT + 1})


# --------------------------------------------------------------------------------------
# decimal6 non-negative ratios
# --------------------------------------------------------------------------------------

BAD_DECIMAL6: list[Any] = [
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
    1,
    0,
    1.5,
    True,
    None,
    Decimal("1.000000"),
    ["0.100000"],
]


@pytest.mark.parametrize(("rule_type", "field"), RATIO_FIELD_CASES)
def test_ratio_parameters_reject_every_non_decimal6_form(
    rule_type: str, field: str
) -> None:
    cls = CLASS_BY_TYPE[rule_type]
    for bad in BAD_DECIMAL6:
        with pytest.raises(ClosedValidationError):
            cls.from_dict(_wire(rule_type, **{field: bad}))
        with pytest.raises(ClosedValidationError):
            cls(**_kwargs(rule_type, **{field: bad}))


@pytest.mark.parametrize(("rule_type", "field"), RATIO_FIELD_CASES)
@pytest.mark.parametrize(
    "good",
    [
        "0.000000",
        "0.000001",
        "1.000000",
        "12.345678",
        "100.500000",
        "123456789012345678901234567890.000001",
    ],
)
def test_ratio_parameters_accept_non_negative_decimal6(
    rule_type: str, field: str, good: str
) -> None:
    rule = CLASS_BY_TYPE[rule_type].from_dict(_wire(rule_type, **{field: good}))
    assert rule.to_dict()[field] == good


def test_decimal6_to_micros_is_exact_integer_arithmetic() -> None:
    assert pol.decimal6_to_micros("0.000000") == 0
    assert pol.decimal6_to_micros("0.000001") == 1
    assert pol.decimal6_to_micros("1.000000") == 1_000_000
    assert pol.decimal6_to_micros("12.345678") == 12_345_678
    assert pol.decimal6_to_micros("0.200000") == 200_000
    big = "9" * 30 + ".999999"
    assert pol.decimal6_to_micros(big) == int("9" * 30 + "999999")
    for bad in ("-0.500000", "1", "1.5", 1, None, True):
        with pytest.raises(ClosedValidationError):
            pol.decimal6_to_micros(bad)


def test_decimal6_to_micros_rejects_digit_strings_beyond_the_interpreter_int_limit() -> None:
    limit = sys.get_int_max_str_digits()
    if limit == 0:
        pytest.skip("interpreter int/str digit limit disabled")
    for field_name in ("min_spend_growth", "max_outcome_growth"):
        too_long = "9" * limit + ".000000"
        with pytest.raises(ClosedValidationError):
            pol.decimal6_to_micros(too_long)
        with pytest.raises(ClosedValidationError):
            pol.SaturationRule.from_dict(_wire("saturation", **{field_name: too_long}))


# --------------------------------------------------------------------------------------
# metric refs
# --------------------------------------------------------------------------------------

BAD_METRIC_REFS: list[Any] = [
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
    None,
    1,
    True,
    ["metric:spend_v1"],
]


@pytest.mark.parametrize(("rule_type", "field"), METRIC_FIELD_CASES)
def test_metric_ref_parameters_reject_malformed_refs(
    rule_type: str, field: str
) -> None:
    cls = CLASS_BY_TYPE[rule_type]
    for bad in BAD_METRIC_REFS:
        with pytest.raises(ClosedValidationError):
            cls.from_dict(_wire(rule_type, **{field: bad}))


@pytest.mark.parametrize(("rule_type", "field"), METRIC_FIELD_CASES)
def test_metric_ref_parameters_accept_phase1_and_derived_metric_refs(
    rule_type: str, field: str
) -> None:
    cls = CLASS_BY_TYPE[rule_type]
    for good in (
        *PHASE1_BASE_METRICS,
        "metric:aggregate_conversions_v1",
        "metric:canonical_leads_v1",
        "metric:cost_per_click_v12",
    ):
        rule = cls.from_dict(_wire(rule_type, **{field: good}))
        assert rule.to_dict()[field] == good


def test_metric_ref_grammar_is_pinned_to_the_base_metric_definition_grammar() -> None:
    # policy.py keeps its own copy of the grammar because numerics keeps its regex private.
    # This pin makes any drift between the two a test failure instead of a silent split.
    assert pol.METRIC_REF_PATTERN == numerics._METRIC_SEMANTIC_REF_RE.pattern


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
def test_restatement_kinds_accept_every_sorted_non_empty_subset(
    kinds: list[str],
) -> None:
    rule = pol.RestatementRule.from_dict(_wire("restatement", restatement_kinds=kinds))
    assert rule.restatement_kinds == tuple(kinds)
    assert rule.to_dict()["restatement_kinds"] == kinds


@pytest.mark.parametrize(
    "kinds",
    [
        [],
        ["tombstone", "tombstone"],
        ["state_flip", "tombstone", "state_flip"],
        ["value_change", "tombstone"],
        ["tombstone", "state_flip", "value_change"],
        ["value_change", "tombstone", "state_flip"],
        ["unknown"],
        ["tombstone", "unknown"],
        ["Tombstone"],
        ["state-flip"],
        [""],
        ["tombstone", None],
        ["tombstone", 1],
        [["tombstone"]],
    ],
)
def test_restatement_kinds_reject_empty_duplicate_unsorted_and_unknown(
    kinds: list[Any],
) -> None:
    with pytest.raises(ClosedValidationError):
        pol.RestatementRule.from_dict(_wire("restatement", restatement_kinds=kinds))
    with pytest.raises(ClosedValidationError):
        pol.RestatementRule(**_kwargs("restatement", restatement_kinds=kinds))


@pytest.mark.parametrize(
    "bad", ["tombstone", None, 1, {"tombstone": 1}, {"tombstone"}, b"tombstone"]
)
def test_restatement_kinds_must_be_an_array(bad: Any) -> None:
    with pytest.raises(ClosedValidationError):
        pol.RestatementRule.from_dict(_wire("restatement", restatement_kinds=bad))
    with pytest.raises(ClosedValidationError):
        pol.RestatementRule(**_kwargs("restatement", restatement_kinds=bad))


def test_restatement_from_dict_requires_a_json_array_but_constructor_takes_tuples() -> None:
    with pytest.raises(ClosedValidationError):
        pol.RestatementRule.from_dict(
            _wire("restatement", restatement_kinds=("tombstone",))
        )
    rule = pol.RestatementRule(**_kwargs("restatement", restatement_kinds=("tombstone",)))
    assert rule.restatement_kinds == ("tombstone",)


def test_restatement_kinds_are_copied_into_an_immutable_tuple() -> None:
    kinds = ["state_flip", "tombstone"]
    rule = pol.RestatementRule(**_kwargs("restatement", restatement_kinds=kinds))
    kinds.append("value_change")
    assert rule.restatement_kinds == ("state_flip", "tombstone")
    assert isinstance(rule.restatement_kinds, tuple)


def test_restatement_kind_vocabulary_is_the_closed_three() -> None:
    assert set(pol.RESTATEMENT_KINDS) == {"tombstone", "value_change", "state_flip"}
    assert list(pol.RESTATEMENT_KINDS) == sorted(
        pol.RESTATEMENT_KINDS, key=lambda s: s.encode()
    )


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
    with pytest.raises(ClosedValidationError):
        pol.ApplicabilityScope.from_dict({**SCOPE_WIRE, "extra": "x"})
    for key in SCOPE_WIRE:
        with pytest.raises(ClosedValidationError):
            pol.ApplicabilityScope.from_dict(_without(SCOPE_WIRE, key))
    for bad in (None, [], "scope", 7):
        with pytest.raises(ClosedValidationError):
            pol.ApplicabilityScope.from_dict(bad)


@pytest.mark.parametrize(
    ("field", "bad"),
    [
        ("resource_scope_ref", ""),
        ("resource_scope_ref", "scope"),
        ("resource_scope_ref", "scope:"),
        ("resource_scope_ref", "tenant:acme"),
        ("resource_scope_ref", "Scope:acme"),
        ("resource_scope_ref", "scope:acme\n"),
        ("resource_scope_ref", None),
        ("resource_scope_ref", 7),
        ("resource_level", "adset"),
        ("resource_level", "ad"),
        ("resource_level", "Campaign"),
        ("resource_level", ""),
        ("resource_level", None),
        ("resource_level", 1),
        ("ad_platform_ref", "google"),
        ("ad_platform_ref", "META"),
        ("ad_platform_ref", ""),
        ("ad_platform_ref", None),
        ("currency", "USD"),
        ("currency", "brl"),
        ("currency", "BR"),
        ("currency", "BRLL"),
        ("currency", ""),
        ("currency", None),
        ("currency", 986),
    ],
)
def test_applicability_scope_rejects_each_malformed_or_non_phase1_value(
    field: str, bad: Any
) -> None:
    with pytest.raises(ClosedValidationError):
        pol.ApplicabilityScope.from_dict({**SCOPE_WIRE, field: bad})
    with pytest.raises(ClosedValidationError):
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
    with pytest.raises(ClosedValidationError):
        pol.PolicyValidity(valid_from_utc=same, valid_until_utc=same)
    with pytest.raises(ClosedValidationError):
        pol.PolicyValidity(
            valid_from_utc="2026-06-01T12:00:00.000001Z",
            valid_until_utc="2026-06-01T12:00:00.000000Z",
        )
    one_microsecond = pol.PolicyValidity(
        valid_from_utc="2026-06-01T12:00:00.000000Z",
        valid_until_utc="2026-06-01T12:00:00.000001Z",
    )
    assert one_microsecond.valid_until_utc > one_microsecond.valid_from_utc
    with pytest.raises(ClosedValidationError):
        pol.PolicyValidity.from_dict(
            {"valid_from_utc": same, "valid_until_utc": same}
        )


@pytest.mark.parametrize("field", sorted(EXPECTED_VALIDITY_KEYS))
@pytest.mark.parametrize(
    "bad",
    [
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
        None,
        0,
        1_780_000_000,
        True,
    ],
)
def test_validity_bounds_require_canonical_six_digit_utc_timestamps(
    field: str, bad: Any
) -> None:
    with pytest.raises(ClosedValidationError):
        pol.PolicyValidity.from_dict({**VALIDITY_WIRE, field: bad})
    with pytest.raises(ClosedValidationError):
        pol.PolicyValidity(**{**VALIDITY_WIRE, field: bad})


def test_validity_rejects_extra_missing_and_non_mapping() -> None:
    with pytest.raises(ClosedValidationError):
        pol.PolicyValidity.from_dict({**VALIDITY_WIRE, "extra": "x"})
    for key in VALIDITY_WIRE:
        with pytest.raises(ClosedValidationError):
            pol.PolicyValidity.from_dict(_without(VALIDITY_WIRE, key))
    for bad in (None, [], "validity", 7):
        with pytest.raises(ClosedValidationError):
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


def _signed_wire(wire: dict[str, Any], signature: str = FAKE_SIGNATURE_BASE64) -> dict[str, Any]:
    unsigned = {**wire, "integrity": copy.deepcopy(UNSIGNED_INTEGRITY)}
    digest = pol.AnalysisPolicy.from_dict(unsigned).p1_content_digest()
    return {
        **wire,
        "integrity": {
            **copy.deepcopy(UNSIGNED_INTEGRITY),
            "content_digest": digest,
            "signature_base64": signature,
        },
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
    unsigned_wire = _policy_wire(integrity=copy.deepcopy(UNSIGNED_INTEGRITY))
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
    with_integrity = pol.AnalysisPolicy.from_dict(
        _policy_wire(integrity=copy.deepcopy(UNSIGNED_INTEGRITY))
    )
    assert frozenset(with_integrity.to_dict()) == EXPECTED_POLICY_KEYS


def test_policy_is_frozen_and_rules_are_an_immutable_tuple() -> None:
    policy = pol.AnalysisPolicy.from_dict(_policy_wire())
    assert isinstance(policy.rules, tuple)
    with pytest.raises(dataclasses.FrozenInstanceError):
        policy.policy_id = "policy:other"  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        policy.rules = ()  # type: ignore[misc]


def test_policy_does_not_alias_caller_containers() -> None:
    rules = [pol.rule_from_dict(_wire(kind)) for kind in SORTED_RULE_TYPES]
    wire = _policy_wire()
    policy = pol.AnalysisPolicy(
        policy_id=wire["policy_id"],
        policy_version=wire["policy_version"],
        tenant_ref=wire["tenant_ref"],
        applicability_scope=pol.ApplicabilityScope.from_dict(wire["applicability_scope"]),
        validity=pol.PolicyValidity.from_dict(wire["validity"]),
        rules=rules,
    )
    rules.clear()
    assert len(policy.rules) == len(SORTED_RULE_TYPES)
    first = policy.to_dict()
    first["rules"].clear()
    first["applicability_scope"]["currency"] = "USD"
    assert policy.to_dict() == wire


def test_policy_schema_member_is_required_and_exact() -> None:
    for bad in ("smart_ads/analysis_policy/v2", "analysis_policy", "", None, 1):
        with pytest.raises(ClosedValidationError):
            pol.AnalysisPolicy.from_dict(_policy_wire(**{"$schema": bad}))
    with pytest.raises(ClosedValidationError):
        pol.AnalysisPolicy.from_dict(_without(_policy_wire(), "$schema"))


def test_policy_rejects_extra_and_each_missing_core_member() -> None:
    with pytest.raises(ClosedValidationError):
        pol.AnalysisPolicy.from_dict(_policy_wire(extra="x"))
    with pytest.raises(ClosedValidationError):
        pol.AnalysisPolicy.from_dict(
            _policy_wire(integrity=copy.deepcopy(UNSIGNED_INTEGRITY), extra="x")
        )
    for key in sorted(EXPECTED_POLICY_CORE_KEYS):
        with pytest.raises(ClosedValidationError):
            pol.AnalysisPolicy.from_dict(_without(_policy_wire(), key))
    for bad in (None, [], "policy", 7):
        with pytest.raises(ClosedValidationError):
            pol.AnalysisPolicy.from_dict(bad)


@pytest.mark.parametrize(
    ("field", "bad"),
    [
        ("policy_id", ""),
        ("policy_id", "policy"),
        ("policy_id", "policy:"),
        ("policy_id", "tenant:acme"),
        ("policy_id", "Policy:acme"),
        ("policy_id", "policy:acme\n"),
        ("policy_id", None),
        ("policy_id", 1),
        ("policy_version", ""),
        ("policy_version", "   "),
        ("policy_version", "v1\u0000"),
        ("policy_version", "cafe\u0301"),
        ("policy_version", None),
        ("policy_version", 1),
        ("policy_version", 1.0),
        ("tenant_ref", ""),
        ("tenant_ref", "tenant"),
        ("tenant_ref", "scope:acme"),
        ("tenant_ref", "Tenant:acme"),
        ("tenant_ref", None),
        ("tenant_ref", 1),
    ],
)
def test_policy_rejects_malformed_identity_members(field: str, bad: Any) -> None:
    with pytest.raises(ClosedValidationError):
        pol.AnalysisPolicy.from_dict(_policy_wire(**{field: bad}))


def test_policy_rejects_malformed_scope_and_validity_members() -> None:
    for bad in (None, [], "scope", 7, {**SCOPE_WIRE, "extra": 1}, {**SCOPE_WIRE, "currency": "USD"}):
        with pytest.raises(ClosedValidationError):
            pol.AnalysisPolicy.from_dict(_policy_wire(applicability_scope=bad))
    reversed_window = {
        "valid_from_utc": VALIDITY_WIRE["valid_until_utc"],
        "valid_until_utc": VALIDITY_WIRE["valid_from_utc"],
    }
    for bad in (None, [], "window", 7, {**VALIDITY_WIRE, "extra": 1}, reversed_window):
        with pytest.raises(ClosedValidationError):
            pol.AnalysisPolicy.from_dict(_policy_wire(validity=bad))


# --------------------------------------------------------------------------------------
# rules array: non-empty, unique, sorted by raw UTF-8 bytes of rule_id
# --------------------------------------------------------------------------------------


def test_policy_rules_must_be_a_non_empty_json_array() -> None:
    for bad in ([], None, "rules", 7, {"rule_id": "rule:x"}, tuple(_wire(k) for k in SORTED_RULE_TYPES)):
        with pytest.raises(ClosedValidationError):
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
    with pytest.raises(ClosedValidationError):
        pol.AnalysisPolicy.from_dict(_policy_wire(rules=[waste, stalled]))
    with pytest.raises(ClosedValidationError):
        pol.AnalysisPolicy.from_dict(_policy_wire(rules=[waste, copy.deepcopy(waste)]))


def test_policy_rejects_unsorted_rules_in_wire_and_constructor() -> None:
    wire = _policy_wire(rules=[_wire(kind) for kind in reversed(SORTED_RULE_TYPES)])
    with pytest.raises(ClosedValidationError):
        pol.AnalysisPolicy.from_dict(wire)
    good = _policy_wire()
    scope = pol.ApplicabilityScope.from_dict(good["applicability_scope"])
    validity = pol.PolicyValidity.from_dict(good["validity"])
    for ordering in (
        tuple(reversed(SORTED_RULE_TYPES)),
        ("saturation", "restatement", "stalled_delivery", "waste"),
    ):
        with pytest.raises(ClosedValidationError):
            pol.AnalysisPolicy(
                policy_id=good["policy_id"],
                policy_version=good["policy_version"],
                tenant_ref=good["tenant_ref"],
                applicability_scope=scope,
                validity=validity,
                rules=tuple(pol.rule_from_dict(_wire(kind)) for kind in ordering),
            )


def test_policy_orders_rule_ids_by_raw_utf8_bytes_not_case_folded() -> None:
    upper = _wire("waste", rule_id="rule:Zeta", window_days=3)
    lower = _wire("waste", rule_id="rule:alpha", window_days=5)
    # b"rule:Zeta" < b"rule:alpha" because 0x5A < 0x61.
    parsed = pol.AnalysisPolicy.from_dict(_policy_wire(rules=[upper, lower]))
    assert [r.rule_id for r in parsed.rules] == ["rule:Zeta", "rule:alpha"]
    with pytest.raises(ClosedValidationError):
        pol.AnalysisPolicy.from_dict(_policy_wire(rules=[lower, upper]))


def test_policy_rejects_unknown_rule_type_and_malformed_members_inside_rules() -> None:
    rules = [_wire(kind) for kind in SORTED_RULE_TYPES]
    for index in range(len(rules)):
        unknown = copy.deepcopy(rules)
        unknown[index]["rule_type"] = "mutation_recommendation"
        with pytest.raises(ClosedValidationError):
            pol.AnalysisPolicy.from_dict(_policy_wire(rules=unknown))
        extra = copy.deepcopy(rules)
        extra[index]["extra"] = 1
        with pytest.raises(ClosedValidationError):
            pol.AnalysisPolicy.from_dict(_policy_wire(rules=extra))
        non_mapping = copy.deepcopy(rules)
        non_mapping[index] = "rule"
        with pytest.raises(ClosedValidationError):
            pol.AnalysisPolicy.from_dict(_policy_wire(rules=non_mapping))
        bad_threshold = copy.deepcopy(rules)
        bad_threshold[index]["rule_id"] = 7
        with pytest.raises(ClosedValidationError):
            pol.AnalysisPolicy.from_dict(_policy_wire(rules=bad_threshold))


def test_policy_constructor_accepts_only_rule_instances() -> None:
    good = _policy_wire()
    scope = pol.ApplicabilityScope.from_dict(good["applicability_scope"])
    validity = pol.PolicyValidity.from_dict(good["validity"])
    for bad_rules in (
        ({"rule_id": "rule:x"},),
        (_wire("waste"),),
        (None,),
        ("rule:x",),
        (),
        None,
        "rules",
    ):
        with pytest.raises(ClosedValidationError):
            pol.AnalysisPolicy(
                policy_id=good["policy_id"],
                policy_version=good["policy_version"],
                tenant_ref=good["tenant_ref"],
                applicability_scope=scope,
                validity=validity,
                rules=bad_rules,  # type: ignore[arg-type]
            )
    with pytest.raises(ClosedValidationError):
        pol.AnalysisPolicy(
            policy_id=good["policy_id"],
            policy_version=good["policy_version"],
            tenant_ref=good["tenant_ref"],
            applicability_scope=SCOPE_WIRE,  # type: ignore[arg-type]
            validity=validity,
            rules=(pol.rule_from_dict(_wire("waste")),),
        )
    with pytest.raises(ClosedValidationError):
        pol.AnalysisPolicy(
            policy_id=good["policy_id"],
            policy_version=good["policy_version"],
            tenant_ref=good["tenant_ref"],
            applicability_scope=scope,
            validity=VALIDITY_WIRE,  # type: ignore[arg-type]
            rules=(pol.rule_from_dict(_wire("waste")),),
        )


# --------------------------------------------------------------------------------------
# P1 preimage and content digest
# --------------------------------------------------------------------------------------


def test_p1_domain_prefix_is_the_adr_analysis_policy_prefix() -> None:
    assert ADR_P1_DOMAIN_PREFIXES[pol.AnalysisPolicy.SCHEMA] == "SMART-ADS:ANALYSIS-POLICY:V1\n"
    assert pol.AnalysisPolicy.P1_DOMAIN_PREFIX == "SMART-ADS:ANALYSIS-POLICY:V1\n"


def test_p1_preimage_is_the_envelope_without_digest_and_signature() -> None:
    signed_wire = _signed_wire(_policy_wire())
    policy = pol.AnalysisPolicy.from_dict(signed_wire, require_signed=True)
    preimage = policy.p1_preimage()
    expected = copy.deepcopy(signed_wire)
    del expected["integrity"]["content_digest"]
    del expected["integrity"]["signature_base64"]
    assert preimage == expected
    assert policy.to_dict() == signed_wire  # computing the preimage never mutates the policy


def test_p1_content_digest_is_sha256_of_the_rfc8785_preimage() -> None:
    policy = pol.AnalysisPolicy.from_dict(
        _policy_wire(integrity=copy.deepcopy(UNSIGNED_INTEGRITY))
    )
    expected = "sha256:" + hashlib.sha256(canonicalize_jcs(policy.p1_preimage())).hexdigest()
    assert policy.p1_content_digest() == expected
    signed = pol.AnalysisPolicy.from_dict(_signed_wire(_policy_wire()), require_signed=True)
    assert signed.p1_content_digest() == expected
    assert signed.integrity is not None and signed.integrity.content_digest == expected


def test_p1_preimage_matches_hand_written_canonical_json() -> None:
    wire = _policy_wire(
        rules=[_wire("restatement", restatement_kinds=["tombstone"])],
        integrity=copy.deepcopy(UNSIGNED_INTEGRITY),
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


def test_p1_content_digest_changes_with_any_threshold_and_ignores_the_signature() -> None:
    base_wire = _policy_wire(integrity=copy.deepcopy(UNSIGNED_INTEGRITY))
    base = pol.AnalysisPolicy.from_dict(base_wire).p1_content_digest()
    other_signature = base64.b64encode(bytes([1]) * 64).decode("ascii")
    resigned = pol.AnalysisPolicy.from_dict(
        _signed_wire(_policy_wire(), signature=other_signature), require_signed=True
    )
    assert resigned.p1_content_digest() == base

    mutations = (
        ("saturation", "window_days", 8),
        ("saturation", "min_spend_growth", "0.200001"),
        ("saturation", "max_outcome_growth", "0.050001"),
        ("saturation", "min_baseline_spend_minor", 10001),
        ("waste", "min_spend_minor", 50001),
        ("waste", "max_outcome_count", 1),
        ("stalled_delivery", "min_consecutive_days", 4),
        ("stalled_delivery", "max_impressions", 1),
        ("restatement", "lookback_days", 29),
        ("restatement", "restatement_kinds", ["tombstone"]),
    )
    seen = {base}
    for kind, field, value in mutations:
        rules = [
            _wire(k, **({field: value} if k == kind else {})) for k in SORTED_RULE_TYPES
        ]
        mutated = pol.AnalysisPolicy.from_dict(
            _policy_wire(rules=rules, integrity=copy.deepcopy(UNSIGNED_INTEGRITY))
        )
        digest = mutated.p1_content_digest()
        assert digest not in seen
        seen.add(digest)


def test_p1_digest_is_unavailable_without_an_integrity_block() -> None:
    policy = pol.AnalysisPolicy.from_dict(_policy_wire())
    with pytest.raises(ClosedValidationError):
        policy.p1_preimage()
    with pytest.raises(ClosedValidationError):
        policy.p1_content_digest()


def test_signed_policy_with_a_wrong_or_stale_digest_is_rejected() -> None:
    wire = _policy_wire()
    good = _signed_wire(wire)
    pol.AnalysisPolicy.from_dict(good, require_signed=True)

    wrong = copy.deepcopy(good)
    wrong["integrity"]["content_digest"] = "sha256:" + "0" * 64
    with pytest.raises(ClosedValidationError):
        pol.AnalysisPolicy.from_dict(wrong, require_signed=True)

    tampered = copy.deepcopy(good)
    tampered["rules"][2]["max_impressions"] = 1  # stalled_delivery threshold after signing
    with pytest.raises(ClosedValidationError):
        pol.AnalysisPolicy.from_dict(tampered, require_signed=True)

    tampered_scope = copy.deepcopy(good)
    tampered_scope["applicability_scope"]["resource_scope_ref"] = "scope:other"
    with pytest.raises(ClosedValidationError):
        pol.AnalysisPolicy.from_dict(tampered_scope)


def test_integrity_states_are_closed() -> None:
    signed = _signed_wire(_policy_wire())
    with pytest.raises(ClosedValidationError):
        pol.AnalysisPolicy.from_dict(_policy_wire(), require_signed=True)
    with pytest.raises(ClosedValidationError):
        pol.AnalysisPolicy.from_dict(
            _policy_wire(integrity=copy.deepcopy(UNSIGNED_INTEGRITY)), require_signed=True
        )
    with pytest.raises(ClosedValidationError):
        pol.AnalysisPolicy.from_dict(signed, require_signed="yes")  # type: ignore[arg-type]
    partial = copy.deepcopy(signed)
    del partial["integrity"]["signature_base64"]
    with pytest.raises(ClosedValidationError):
        pol.AnalysisPolicy.from_dict(partial)
    short_signature = _signed_wire(_policy_wire(), signature=base64.b64encode(bytes(63)).decode())
    with pytest.raises(ClosedValidationError):
        pol.AnalysisPolicy.from_dict(short_signature, require_signed=True)
    extra_integrity = _policy_wire(integrity={**UNSIGNED_INTEGRITY, "extra": 1})
    with pytest.raises(ClosedValidationError):
        pol.AnalysisPolicy.from_dict(extra_integrity)
    for bad in (None, [], "integrity"):
        with pytest.raises(ClosedValidationError):
            pol.AnalysisPolicy.from_dict(_policy_wire(integrity=bad))


def test_policy_with_largest_json_safe_thresholds_still_has_a_computable_digest() -> None:
    rules = [
        _wire(
            k,
            **{
                field: MAX_JCS_SAFE_INT
                for (kind, field, _minimum) in INT_FIELD_CASES
                if kind == k
            },
        )
        for k in SORTED_RULE_TYPES
    ]
    policy = pol.AnalysisPolicy.from_dict(
        _policy_wire(rules=rules, integrity=copy.deepcopy(UNSIGNED_INTEGRITY))
    )
    assert policy.p1_content_digest().startswith("sha256:")


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


def test_codes_are_a_closed_set_and_the_error_is_a_closed_validation_error() -> None:
    assert set(pol.POLICY_NOT_APPLICABLE_CODES) == {
        "tenant_mismatch",
        "resource_scope_mismatch",
        "resource_level_mismatch",
        "ad_platform_mismatch",
        "currency_mismatch",
        "not_yet_valid",
        "expired",
    }
    assert issubclass(pol.PolicyNotApplicableError, ClosedValidationError)
    for code in pol.POLICY_NOT_APPLICABLE_CODES:
        error = pol.PolicyNotApplicableError(code, "detail")
        assert error.code == code
        assert code in str(error)
        assert isinstance(error, ClosedValidationError)
    for bad in ("", "tenant", "EXPIRED", None, 1, ["expired"]):
        with pytest.raises(ClosedValidationError):
            pol.PolicyNotApplicableError(bad, "detail")  # type: ignore[arg-type]


def test_not_applicable_error_survives_copy_and_pickle_with_its_code() -> None:
    error = pol.PolicyNotApplicableError("expired", "window closed")
    for clone in (copy.copy(error), copy.deepcopy(error), pickle.loads(pickle.dumps(error))):
        assert type(clone) is pol.PolicyNotApplicableError
        assert clone.code == "expired"
        assert clone.detail == "window closed"
        assert str(clone) == str(error)


def test_evaluation_scope_requires_well_formed_members_but_not_phase1_values() -> None:
    other = _eval_scope(resource_level="adset", ad_platform_ref="google", currency="USD")
    assert (other.resource_level, other.ad_platform_ref, other.currency) == (
        "adset",
        "google",
        "USD",
    )
    for field, bad in (
        ("tenant_ref", "scope:acme"),
        ("tenant_ref", ""),
        ("tenant_ref", None),
        ("resource_scope_ref", "tenant:acme"),
        ("resource_scope_ref", None),
        ("resource_level", ""),
        ("resource_level", None),
        ("resource_level", 1),
        ("ad_platform_ref", ""),
        ("ad_platform_ref", None),
        ("currency", "usd"),
        ("currency", "BR"),
        ("currency", None),
    ):
        with pytest.raises(ClosedValidationError):
            _eval_scope(**{field: bad})  # type: ignore[arg-type]
    with pytest.raises(dataclasses.FrozenInstanceError):
        other.currency = "BRL"  # type: ignore[misc]


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
        pol.policy_applicability_code(policy, _eval_scope(), AFTER_VALID_UNTIL)
        == "expired"
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
    assert pol.policy_applicability_code(policy, scope, "2026-06-01T12:00:00.000000Z") == "not_yet_valid"
    assert pol.policy_applicability_code(policy, scope, "2026-06-01T12:00:00.000001Z") is None
    assert pol.policy_applicability_code(policy, scope, "2026-06-01T12:00:00.000002Z") is None
    assert pol.policy_applicability_code(policy, scope, "2026-06-01T12:00:00.000003Z") == "expired"


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
    assert (
        pol.policy_applicability_code(policy, everything_wrong, AFTER_VALID_UNTIL)
        == "tenant_mismatch"
    )
    no_tenant_error = _eval_scope(
        resource_scope_ref="scope:other",
        resource_level="adset",
        ad_platform_ref="google",
        currency="USD",
    )
    assert (
        pol.policy_applicability_code(policy, no_tenant_error, BEFORE_VALID_FROM)
        == "resource_scope_mismatch"
    )
    only_currency = _eval_scope(currency="USD")
    assert (
        pol.policy_applicability_code(policy, only_currency, AFTER_VALID_UNTIL)
        == "currency_mismatch"
    )


@pytest.mark.parametrize(
    "bad_instant",
    [
        "",
        "2026-06-15T12:30:00Z",
        "2026-06-15T12:30:00.123Z",
        "2026-06-15T12:30:00.123456",
        "2026-06-15T12:30:00.123456+00:00",
        "2026-06-15 12:30:00.123456Z",
        "2026-02-30T12:30:00.123456Z",
        "2026-06-15T12:30:60.123456Z",
        "2026-06-15",
        None,
        0,
        1_780_000_000,
        True,
        b"2026-06-15T12:30:00.123456Z",
    ],
)
def test_malformed_instant_is_a_validation_error_not_a_not_applicable_verdict(
    bad_instant: Any,
) -> None:
    policy = _policy()
    with pytest.raises(ClosedValidationError) as caught_code:
        pol.policy_applicability_code(policy, _eval_scope(), bad_instant)
    assert not isinstance(caught_code.value, pol.PolicyNotApplicableError)
    with pytest.raises(ClosedValidationError) as caught_require:
        pol.require_policy_applicable(policy, _eval_scope(), bad_instant)
    assert not isinstance(caught_require.value, pol.PolicyNotApplicableError)


def test_malformed_instant_is_rejected_even_when_the_scope_already_mismatches() -> None:
    with pytest.raises(ClosedValidationError) as caught:
        pol.policy_applicability_code(_policy(), _eval_scope(tenant_ref="tenant:other"), "not-a-time")
    assert not isinstance(caught.value, pol.PolicyNotApplicableError)


def test_applicability_arguments_must_be_typed_objects() -> None:
    with pytest.raises(ClosedValidationError):
        pol.policy_applicability_code(_policy_wire(), _eval_scope(), INSIDE_WINDOW)  # type: ignore[arg-type]
    with pytest.raises(ClosedValidationError):
        pol.policy_applicability_code(_policy(), MATCHING_SCOPE_KWARGS, INSIDE_WINDOW)  # type: ignore[arg-type]
    with pytest.raises(ClosedValidationError):
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
        _policy_wire(rules=[_wire("stalled_delivery", min_consecutive_days=1, max_impressions=0)])
    )
    assert pol.policy_applicability_code(zero_thresholds, _eval_scope(), INSIDE_WINDOW) is None
    assert (
        pol.policy_applicability_code(zero_thresholds, _eval_scope(), AFTER_VALID_UNTIL)
        == "expired"
    )


# --------------------------------------------------------------------------------------
# Module hygiene: no float, no threshold literals, no clock
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
