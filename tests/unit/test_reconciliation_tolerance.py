"""Unit tests for smart_ads.reconciliation.tolerance (ADR-0001 section 5.4).

Covers the closed ``tolerance_profile/v1`` P1 artifact and the pure comparator
that recomputes deltas, outcome and verification status from canonical values.
"""
from __future__ import annotations

import base64
import copy
import dataclasses
from decimal import ROUND_HALF_UP, Decimal, localcontext
import hashlib
from itertools import product
from typing import Any

import pytest

from smart_ads.contracts.jcs import (
    ADR_P1_DOMAIN_PREFIXES,
    ArtifactLocator,
    P1Integrity,
    canonicalize_jcs,
    p1_content_digest,
    p1_preimage,
)
from smart_ads.contracts.numerics import MAX_INT64, PROVIDER_PRESENCE_TO_UNKNOWN_REASON
from smart_ads.contracts.scalars import ClosedValidationError
from smart_ads.reconciliation.tolerance import (
    DECIMAL_SCALE,
    PHASE1_7B_MONEY_CURRENCY,
    REFERENCE_ZERO_RULE,
    ROUNDING_MODE,
    AuthorizationBinding,
    ComparisonSide,
    ToleranceComparison,
    ToleranceProfile,
    compare_sides,
)

CLICKS = "metric:clicks_v1"
IMPRESSIONS = "metric:impressions_v1"
SPEND = "metric:spend_v1"
MIN_INT64 = -(1 << 63)
# Derived from the shared provider presence states (contracts/numerics.py), so a
# state added there is exercised here automatically; a literal pin test below
# fails loudly when the set changes.
NON_OBSERVED = tuple(
    sorted(state for state in PROVIDER_PRESENCE_TO_UNKNOWN_REASON if state != "observed")
)
KEY_ID = "key:ed25519:" + ("a" * 64)
PROFILE_CORE_KEYS = frozenset(
    {
        "$schema",
        "canonical_metric_ref",
        "value_type",
        "max_absolute_delta",
        "max_relative_delta",
        "decimal_scale",
        "rounding_mode",
        "reference_zero_rule",
        "authorization_binding",
    }
)
BINDING_KEYS = frozenset(
    {
        "gate3_selection_locator",
        "canonical_query_digest",
        "authorized_certification_scope",
        "migration_run_context_locator",
    }
)
RESULT_KEYS = frozenset(
    {
        "measured_absolute_delta",
        "measured_relative_delta",
        "relative_delta_status",
        "reconciliation_outcome",
        "metric_verification_status",
    }
)


def _loc(artifact_type: str, fill: str = "a") -> ArtifactLocator:
    return ArtifactLocator.from_digest(artifact_type, "sha256:" + (fill * 64))


def count(raw: int | str) -> ComparisonSide:
    return ComparisonSide(
        presence_status="observed",
        value_type="int64_count",
        raw_numeric_value=str(raw),
        unit="count",
        currency=None,
    )


def money(raw: int | str, currency: str = "BRL") -> ComparisonSide:
    return ComparisonSide(
        presence_status="observed",
        value_type="int64_minor_currency",
        raw_numeric_value=str(raw),
        unit="minor_currency",
        currency=currency,
    )


def ratio(raw: str) -> ComparisonSide:
    return ComparisonSide(
        presence_status="observed",
        value_type="decimal_ratio",
        raw_numeric_value=raw,
        unit="ratio",
        currency=None,
    )


def absent(status: str) -> ComparisonSide:
    return ComparisonSide(
        presence_status=status,
        value_type=None,
        raw_numeric_value=None,
        unit=None,
        currency=None,
    )


def binding() -> AuthorizationBinding:
    return AuthorizationBinding(
        gate3_selection_locator=_loc("smart_ads/gate3_selection_receipt/v1", "1"),
        canonical_query_digest="sha256:" + ("2" * 64),
        authorized_certification_scope="scope:campaigns-active",
        migration_run_context_locator=_loc("smart_ads/migration_run_context/v1", "3"),
    )


def unsigned_integrity() -> P1Integrity:
    return P1Integrity(
        key_id=KEY_ID,
        key_registry_snapshot_locator=_loc("smart_ads/key_authorization_registry/v1", "9"),
    )


def signed_integrity(content_digest: str) -> P1Integrity:
    return P1Integrity(
        key_id=KEY_ID,
        key_registry_snapshot_locator=_loc("smart_ads/key_authorization_registry/v1", "9"),
        content_digest=content_digest,
        signature_base64=base64.b64encode(bytes(64)).decode("ascii"),
    )


def exact_profile(
    metric: str = CLICKS,
    value_type: str = "int64_count",
    integrity: P1Integrity | None = None,
) -> ToleranceProfile:
    return ToleranceProfile(
        canonical_metric_ref=metric,
        value_type=value_type,  # type: ignore[arg-type]
        max_absolute_delta="0",
        max_relative_delta="0.000000",
        authorization_binding=None,
        integrity=integrity,
    )


def loose_profile(
    max_abs: str,
    max_rel: str,
    metric: str = CLICKS,
    value_type: str = "int64_count",
    integrity: P1Integrity | None = None,
) -> ToleranceProfile:
    return ToleranceProfile(
        canonical_metric_ref=metric,
        value_type=value_type,  # type: ignore[arg-type]
        max_absolute_delta=max_abs,
        max_relative_delta=max_rel,
        authorization_binding=binding(),
        integrity=integrity,
    )


def compare(
    candidate: ComparisonSide,
    reference: ComparisonSide,
    profile: ToleranceProfile,
    *,
    metric: str = CLICKS,
) -> ToleranceComparison:
    return compare_sides(candidate, reference, profile, canonical_metric_ref=metric)


def five(result: ToleranceComparison) -> tuple[Any, Any, Any, Any, Any]:
    return (
        result.measured_absolute_delta,
        result.measured_relative_delta,
        result.relative_delta_status,
        result.reconciliation_outcome,
        result.metric_verification_status,
    )


# --------------------------------------------------------------------------- #
# Constants and public contract surface
# --------------------------------------------------------------------------- #


def test_declared_constants_match_the_adr_profile_members() -> None:
    assert DECIMAL_SCALE == 6
    assert type(DECIMAL_SCALE) is int
    assert ROUNDING_MODE == "ROUND_HALF_UP"
    assert REFERENCE_ZERO_RULE == "exact_zero_only"
    assert ToleranceProfile.SCHEMA == "smart_ads/tolerance_profile/v1"
    assert ADR_P1_DOMAIN_PREFIXES[ToleranceProfile.SCHEMA] == "SMART-ADS:TOLERANCE:V1\n"


# --------------------------------------------------------------------------- #
# Truth table, rows 1-5 (both sides observed, same type)
# --------------------------------------------------------------------------- #

ROW_1_2_3 = [
    pytest.param(
        count(0), count(0), exact_profile(),
        ("0", None, "reference_zero", "exact_match", "VERIFIED"),
        id="row1_ref0_cand0",
    ),
    pytest.param(
        count(7), count(0), exact_profile(),
        ("7", None, "reference_zero", "mismatch", "UNRECONCILED"),
        id="row2_ref0_cand_nonzero",
    ),
    pytest.param(
        count(100), count(100), exact_profile(),
        ("0", "0.000000", "computed", "exact_match", "VERIFIED"),
        id="row3_ref_positive_delta0",
    ),
]


@pytest.mark.parametrize(("cand", "ref", "prof", "expected"), ROW_1_2_3)
def test_truth_table_rows_1_to_3(
    cand: ComparisonSide,
    ref: ComparisonSide,
    prof: ToleranceProfile,
    expected: tuple[Any, ...],
) -> None:
    assert five(compare(cand, ref, prof)) == expected


def test_row_1_and_2_hold_with_the_widest_authorized_limits() -> None:
    wide = loose_profile(str(MAX_INT64), "9223372036854775807.000000")
    assert five(compare(count(0), count(0), wide)) == (
        "0", None, "reference_zero", "exact_match", "VERIFIED",
    )
    # exact_zero_only: a non-zero candidate against a zero reference never passes,
    # even when the absolute limit alone would admit the delta.
    assert five(compare(count(5), count(0), wide)) == (
        "5", None, "reference_zero", "mismatch", "UNRECONCILED",
    )


def test_row_4_within_both_limits_is_within_declared_tolerance() -> None:
    result = compare(count(103), count(100), loose_profile("5", "0.050000"))
    assert five(result) == (
        "3", "0.030000", "computed", "within_declared_tolerance", "VERIFIED",
    )


@pytest.mark.parametrize(
    ("cand", "ref", "max_abs", "max_rel", "expected_delta", "expected_rel"),
    [
        pytest.param(1010, 1000, "5", "0.020000", "10", "0.010000", id="abs_fails_rel_passes"),
        pytest.param(12, 10, "5", "0.050000", "2", "0.200000", id="rel_fails_abs_passes"),
        pytest.param(15, 10, "1", "0.010000", "5", "0.500000", id="both_fail"),
    ],
)
def test_row_5_requires_both_limits_to_pass(
    cand: int,
    ref: int,
    max_abs: str,
    max_rel: str,
    expected_delta: str,
    expected_rel: str,
) -> None:
    result = compare(count(cand), count(ref), loose_profile(max_abs, max_rel))
    assert five(result) == (
        expected_delta, expected_rel, "computed", "mismatch", "UNRECONCILED",
    )


def test_row_5_zero_tolerance_profile_rejects_any_difference() -> None:
    for cand in (99, 101):
        result = compare(count(cand), count(100), exact_profile())
        assert five(result) == ("1", "0.010000", "computed", "mismatch", "UNRECONCILED")


def test_limits_are_inclusive_at_the_boundary_and_exclusive_one_step_beyond() -> None:
    prof = loose_profile("10", "0.100000")
    assert five(compare(count(110), count(100), prof))[3] == "within_declared_tolerance"
    assert five(compare(count(111), count(100), prof))[3] == "mismatch"
    # relative limit one micro-unit tighter than the measured delta
    tight = loose_profile("10", "0.099999")
    assert five(compare(count(110), count(100), tight))[3] == "mismatch"


# --------------------------------------------------------------------------- #
# Truth table, row 6 (some side not observed)
# --------------------------------------------------------------------------- #

UNAVAILABLE = (None, None, "not_computable", "not_comparable", "UNAVAILABLE")


@pytest.mark.parametrize("status", NON_OBSERVED)
def test_row_6_non_observed_candidate(status: str) -> None:
    for ref in (count(0), count(5)):
        assert five(compare(absent(status), ref, exact_profile())) == UNAVAILABLE


@pytest.mark.parametrize("status", NON_OBSERVED)
def test_row_6_non_observed_reference_is_never_zero(status: str) -> None:
    # An unknown reference must not be read as zero: candidate 0 would otherwise
    # be an exact_match against a "zero" reference.
    for cand in (count(0), count(5)):
        result = compare(cand, absent(status), exact_profile())
        assert five(result) == UNAVAILABLE
        assert result.reconciliation_outcome != "exact_match"


@pytest.mark.parametrize("cand_status", NON_OBSERVED)
@pytest.mark.parametrize("ref_status", NON_OBSERVED)
def test_row_6_both_sides_non_observed(cand_status: str, ref_status: str) -> None:
    result = compare(absent(cand_status), absent(ref_status), exact_profile())
    assert five(result) == UNAVAILABLE


def test_row_6_applies_to_money_metrics_too() -> None:
    prof = exact_profile(SPEND, "int64_minor_currency")
    for status in NON_OBSERVED:
        assert five(compare(absent(status), money(10), prof, metric=SPEND)) == UNAVAILABLE
        assert five(compare(money(0), absent(status), prof, metric=SPEND)) == UNAVAILABLE


# --------------------------------------------------------------------------- #
# Truth table, row 7 (type / unit / currency divergence, negative value)
# --------------------------------------------------------------------------- #

BLOCKED = (None, None, "not_computable", "not_comparable", "BLOCKED")


def test_row_7_candidate_and_reference_types_diverge() -> None:
    assert five(compare(count(5), money(5), exact_profile())) == BLOCKED
    assert five(compare(money(5), count(5), exact_profile())) == BLOCKED


def test_row_7_both_sides_differ_from_the_profile_value_type() -> None:
    assert five(compare(money(5), money(5), exact_profile())) == BLOCKED
    spend = exact_profile(SPEND, "int64_minor_currency")
    assert five(compare(count(5), count(5), spend, metric=SPEND)) == BLOCKED


def test_row_7_decimal_ratio_sides_are_not_comparable_with_integer_profiles() -> None:
    assert five(compare(ratio("0.500000"), ratio("0.500000"), exact_profile())) == BLOCKED
    assert five(compare(ratio("0.000000"), count(0), exact_profile())) == BLOCKED


def test_7b_money_currency_is_pinned_to_brl_by_the_adr() -> None:
    # ADR-0001 L1150: "spend uses int64_minor_currency/minor_currency/BRL."
    assert PHASE1_7B_MONEY_CURRENCY == "BRL"


@pytest.mark.parametrize(
    ("cand_currency", "ref_currency"),
    [
        pytest.param("BRL", "USD", id="reference_foreign"),
        pytest.param("USD", "BRL", id="candidate_foreign"),
        pytest.param("USD", "USD", id="both_foreign_and_equal"),
        pytest.param("USD", "EUR", id="both_foreign_and_different"),
        pytest.param("EUR", "EUR", id="both_eur"),
    ],
)
def test_row_7_money_in_any_currency_other_than_brl_is_blocked(
    cand_currency: str, ref_currency: str
) -> None:
    spend = exact_profile(SPEND, "int64_minor_currency")
    result = compare(money(5, cand_currency), money(5, ref_currency), spend, metric=SPEND)
    assert five(result) == BLOCKED
    loose = loose_profile("5", "0.500000", SPEND, "int64_minor_currency")
    assert five(compare(money(5, cand_currency), money(5, ref_currency), loose, metric=SPEND)) == BLOCKED


def test_brl_money_on_both_sides_is_verified() -> None:
    spend = exact_profile(SPEND, "int64_minor_currency")
    ok = compare(money(5, "BRL"), money(5, "BRL"), spend, metric=SPEND)
    assert five(ok) == ("0", "0.000000", "computed", "exact_match", "VERIFIED")


def test_the_query_currency_parameter_no_longer_exists() -> None:
    spend = exact_profile(SPEND, "int64_minor_currency")
    with pytest.raises(TypeError):
        compare_sides(  # type: ignore[call-arg]
            money(5, "USD"),
            money(5, "USD"),
            spend,
            canonical_metric_ref=SPEND,
            query_currency="USD",
        )


def test_money_within_declared_tolerance_is_verified_in_brl() -> None:
    spend = loose_profile("5", "0.050000", SPEND, "int64_minor_currency")
    result = compare(money(103), money(100), spend, metric=SPEND)
    assert five(result) == ("3", "0.030000", "computed", "within_declared_tolerance", "VERIFIED")
    over = compare(money(106), money(100), spend, metric=SPEND)
    assert five(over) == ("6", "0.060000", "computed", "mismatch", "UNRECONCILED")
    zero_ref = compare(money(3), money(0), spend, metric=SPEND)
    assert five(zero_ref) == ("3", None, "reference_zero", "mismatch", "UNRECONCILED")


# A non-observed side beats any defect on the other, observed side: the verdict is
# UNAVAILABLE (retry-able evidence gap), never BLOCKED, whichever side is missing.
DEFECTIVE_OBSERVED_SIDES = [
    pytest.param(count(-1), exact_profile(), CLICKS, id="negative_value"),
    pytest.param(ratio("0.500000"), exact_profile(), CLICKS, id="decimal_ratio"),
    pytest.param(money(5), exact_profile(), CLICKS, id="wrong_value_type_for_profile"),
    pytest.param(
        money(5, "USD"),
        exact_profile(SPEND, "int64_minor_currency"),
        SPEND,
        id="foreign_currency",
    ),
    pytest.param(
        money(-5),
        exact_profile(SPEND, "int64_minor_currency"),
        SPEND,
        id="negative_money",
    ),
]


@pytest.mark.parametrize("status", NON_OBSERVED)
@pytest.mark.parametrize(("defective", "prof", "metric"), DEFECTIVE_OBSERVED_SIDES)
def test_non_observed_side_beats_a_defect_on_the_other_side(
    status: str, defective: ComparisonSide, prof: ToleranceProfile, metric: str
) -> None:
    missing = absent(status)
    assert five(compare(missing, defective, prof, metric=metric)) == UNAVAILABLE
    assert five(compare(defective, missing, prof, metric=metric)) == UNAVAILABLE


@pytest.mark.parametrize(("defective", "prof", "metric"), DEFECTIVE_OBSERVED_SIDES)
def test_the_same_defects_are_blocked_when_both_sides_are_observed(
    defective: ComparisonSide, prof: ToleranceProfile, metric: str
) -> None:
    other = money(5) if metric == SPEND else count(5)
    assert five(compare(defective, other, prof, metric=metric)) == BLOCKED
    assert five(compare(other, defective, prof, metric=metric)) == BLOCKED


def test_row_7_profile_metric_must_match_the_compared_metric() -> None:
    assert five(compare(count(5), count(5), exact_profile(CLICKS), metric=IMPRESSIONS)) == BLOCKED
    # also when the evidence is unavailable: an inapplicable profile is a structural defect
    prof = exact_profile(CLICKS)
    assert five(compare(absent("missing"), count(1), prof, metric=SPEND)) == BLOCKED


@pytest.mark.parametrize(
    ("cand", "ref"),
    [
        ("-1", "5"),
        ("5", "-1"),
        ("-3", "-3"),
        (str(MIN_INT64), "0"),
        ("0", str(MIN_INT64)),
    ],
)
def test_row_7_negative_values_are_blocked_not_raised(cand: str, ref: str) -> None:
    assert five(compare(count(cand), count(ref), exact_profile())) == BLOCKED
    spend = exact_profile(SPEND, "int64_minor_currency")
    assert five(compare(money(cand), money(ref), spend, metric=SPEND)) == BLOCKED


def test_row_7_blocked_result_carries_no_deltas() -> None:
    result = compare(count(-1), count(5), exact_profile())
    assert result.measured_absolute_delta is None
    assert result.measured_relative_delta is None


# --------------------------------------------------------------------------- #
# Relative delta: fixed scale 6, exact-integer ROUND_HALF_UP
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("cand", "ref", "expected_rel"),
    [
        pytest.param(150, 100, "0.500000", id="exact_half"),
        pytest.param(3, 1, "2.000000", id="integer_quotient_above_one"),
        pytest.param(0, 8, "1.000000", id="candidate_zero_is_full_delta"),
        pytest.param(2, 3, "0.333333", id="third_rounds_down"),
        pytest.param(4, 3, "0.333333", id="third_from_above"),
        pytest.param(1, 3, "0.666667", id="two_thirds_rounds_up"),
        pytest.param(5, 3, "0.666667", id="two_thirds_from_above"),
        pytest.param(1, 7, "0.857143", id="six_sevenths_rounds_up"),
        pytest.param(8, 7, "0.142857", id="one_seventh_rounds_down"),
        pytest.param(1, 8, "0.875000", id="seven_eighths_terminates"),
        pytest.param(9, 8, "0.125000", id="terminates_before_scale"),
        pytest.param(17, 16, "0.062500", id="terminates_at_fourth_decimal"),
    ],
)
def test_relative_delta_common_values(cand: int, ref: int, expected_rel: str) -> None:
    result = compare(count(cand), count(ref), exact_profile())
    assert result.measured_relative_delta == expected_rel


@pytest.mark.parametrize(
    ("delta", "ref", "expected_rel"),
    [
        # delta * 10^6 / ref lands exactly on k + 0.5: half-up goes to k + 1
        pytest.param(1, 2_000_000, "0.000001", id="half_0_5_micro_rounds_up"),
        pytest.param(3, 2_000_000, "0.000002", id="half_1_5_micro_rounds_up"),
        pytest.param(5, 2_000_000, "0.000003", id="half_2_5_micro_rounds_up_not_to_even"),
        pytest.param(7, 2_000_000, "0.000004", id="half_3_5_micro_rounds_up"),
        # just below and just above the half boundary
        pytest.param(1, 2_000_001, "0.000000", id="just_below_half_rounds_down"),
        pytest.param(1, 1_999_999, "0.000001", id="just_above_half_rounds_up"),
        pytest.param(1, 1_000_000, "0.000001", id="exactly_one_micro"),
        pytest.param(1, 1_000_001, "0.000001", id="slightly_below_one_micro"),
        pytest.param(1, 3_000_000, "0.000000", id="one_third_micro_rounds_down"),
        pytest.param(2, 3_000_000, "0.000001", id="two_thirds_micro_rounds_up"),
    ],
)
def test_relative_delta_half_up_boundaries_at_the_sixth_decimal(
    delta: int, ref: int, expected_rel: str
) -> None:
    result = compare(count(ref + delta), count(ref), exact_profile())
    assert result.measured_relative_delta == expected_rel
    # the same boundary from below the reference
    below = compare(count(ref - delta), count(ref), exact_profile())
    assert below.measured_relative_delta == expected_rel
    assert result.measured_absolute_delta == str(delta)


def test_rounded_relative_delta_is_what_the_limit_is_checked_against() -> None:
    # 1 / 2_000_001 rounds to 0.000000, so a zero relative limit admits it when the
    # absolute limit does; 1 / 2_000_000 rounds half-up to 0.000001 and exceeds it.
    prof = loose_profile("1", "0.000000")
    inside = compare(count(2_000_002), count(2_000_001), prof)
    assert five(inside) == (
        "1", "0.000000", "computed", "within_declared_tolerance", "VERIFIED",
    )
    outside = compare(count(2_000_001), count(2_000_000), prof)
    assert five(outside) == ("1", "0.000001", "computed", "mismatch", "UNRECONCILED")


def test_relative_delta_is_none_only_when_the_reference_is_zero() -> None:
    assert compare(count(5), count(0), exact_profile()).measured_relative_delta is None
    assert compare(count(0), count(5), exact_profile()).measured_relative_delta == "1.000000"


# --------------------------------------------------------------------------- #
# int64 extremes
# --------------------------------------------------------------------------- #


def test_int64_max_on_both_sides_is_an_exact_match() -> None:
    assert five(compare(count(MAX_INT64), count(MAX_INT64), exact_profile())) == (
        "0", "0.000000", "computed", "exact_match", "VERIFIED",
    )


def test_int64_max_candidate_against_zero_reference() -> None:
    result = compare(count(MAX_INT64), count(0), exact_profile())
    assert five(result) == (
        str(MAX_INT64), None, "reference_zero", "mismatch", "UNRECONCILED",
    )


def test_int64_max_reference_against_zero_candidate() -> None:
    result = compare(count(0), count(MAX_INT64), exact_profile())
    assert five(result) == (
        str(MAX_INT64), "1.000000", "computed", "mismatch", "UNRECONCILED",
    )
    full = loose_profile(str(MAX_INT64), "1.000000")
    assert five(compare(count(0), count(MAX_INT64), full)) == (
        str(MAX_INT64), "1.000000", "computed", "within_declared_tolerance", "VERIFIED",
    )


def test_int64_max_candidate_against_unit_reference() -> None:
    result = compare(count(MAX_INT64), count(1), exact_profile())
    assert result.measured_absolute_delta == str(MAX_INT64 - 1)
    assert result.measured_relative_delta == "9223372036854775806.000000"


def test_adjacent_int64_extremes_round_to_zero_relative_delta() -> None:
    result = compare(count(MAX_INT64), count(MAX_INT64 - 1), exact_profile())
    assert five(result) == ("1", "0.000000", "computed", "mismatch", "UNRECONCILED")
    lax = loose_profile("1", "0.000000")
    assert five(compare(count(MAX_INT64), count(MAX_INT64 - 1), lax))[3] == (
        "within_declared_tolerance"
    )


def test_int64_extremes_for_money_values() -> None:
    spend = exact_profile(SPEND, "int64_minor_currency")
    assert five(compare(money(MAX_INT64), money(MAX_INT64), spend, metric=SPEND)) == (
        "0", "0.000000", "computed", "exact_match", "VERIFIED",
    )
    assert five(compare(money(0), money(MAX_INT64), spend, metric=SPEND)) == (
        str(MAX_INT64), "1.000000", "computed", "mismatch", "UNRECONCILED",
    )


@pytest.mark.parametrize("raw", [str(MAX_INT64 + 1), "99999999999999999999", "9" * 40])
def test_values_above_int64_max_are_malformed(raw: str) -> None:
    with pytest.raises(ClosedValidationError):
        count(raw)
    with pytest.raises(ClosedValidationError):
        money(raw)


def test_values_below_int64_min_are_malformed() -> None:
    assert count(str(MIN_INT64)).raw_numeric_value == str(MIN_INT64)
    with pytest.raises(ClosedValidationError):
        count(str(MIN_INT64 - 1))
    with pytest.raises(ClosedValidationError):
        count("-" + "9" * 40)


# --------------------------------------------------------------------------- #
# Oracle sweep: independent decimal-module implementation of the recomputation
# --------------------------------------------------------------------------- #


def _oracle(cand: int, ref: int, max_abs: int, max_rel: str) -> tuple[Any, ...]:
    delta = abs(cand - ref)
    if ref == 0:
        if cand == 0:
            return ("0", None, "reference_zero", "exact_match", "VERIFIED")
        return (str(delta), None, "reference_zero", "mismatch", "UNRECONCILED")
    with localcontext() as ctx:
        ctx.prec = 80
        rel = (Decimal(delta) / Decimal(ref)).quantize(
            Decimal("0.000001"), rounding=ROUND_HALF_UP
        )
        rel_text = format(rel, "f")
        rel_ok = rel <= Decimal(max_rel)
    if delta == 0:
        return ("0", rel_text, "computed", "exact_match", "VERIFIED")
    if delta <= max_abs and rel_ok:
        return (str(delta), rel_text, "computed", "within_declared_tolerance", "VERIFIED")
    return (str(delta), rel_text, "computed", "mismatch", "UNRECONCILED")


SWEEP_VALUES = sorted(
    {
        *range(0, 41),
        1_999_999, 2_000_000, 2_000_001, 3_000_000, 4_000_000, 999_999,
        1_000_000, 2**40 + 1, 2**53, MAX_INT64 - 1, MAX_INT64,
    }
)


@pytest.mark.parametrize(
    ("kind", "metric", "value_type"),
    [
        pytest.param(count, CLICKS, "int64_count", id="count"),
        pytest.param(money, SPEND, "int64_minor_currency", id="money_brl"),
    ],
)
@pytest.mark.parametrize(
    ("max_abs", "max_rel"),
    [("0", "0.000000"), ("3", "0.250000"), ("1", "0.000000"), (str(MAX_INT64), "9999.000000")],
)
def test_comparator_agrees_with_an_independent_decimal_oracle(
    kind: Any, metric: str, value_type: str, max_abs: str, max_rel: str
) -> None:
    if (max_abs, max_rel) == ("0", "0.000000"):
        prof = exact_profile(metric, value_type)
    else:
        prof = loose_profile(max_abs, max_rel, metric, value_type)
    for cand in SWEEP_VALUES:
        for ref in SWEEP_VALUES:
            expected = _oracle(cand, ref, int(max_abs), max_rel)
            assert five(compare(kind(cand), kind(ref), prof, metric=metric)) == expected, (
                cand,
                ref,
            )


# --------------------------------------------------------------------------- #
# Malformed side input raises; legitimate failures never do
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "raw",
    [
        "", " ", "01", "-01", "+1", " 1", "1 ", "1\n", "1.0", "1.", ".5", "1e3", "1E3",
        "0x10", "1_000", "-0", "--1", "-", "NaN", "Infinity", "-Infinity", "٣",
        "１", "1,000",
    ],
)
def test_non_canonical_integer_lexical_forms_are_malformed(raw: str) -> None:
    with pytest.raises(ClosedValidationError):
        count(raw)
    with pytest.raises(ClosedValidationError):
        money(raw)


@pytest.mark.parametrize("raw", [5, True, False, 1.5, b"1", ["1"], {"v": "1"}])
def test_native_non_string_values_are_malformed_including_bool_as_int(raw: Any) -> None:
    with pytest.raises(ClosedValidationError):
        ComparisonSide(
            presence_status="observed",
            value_type="int64_count",
            raw_numeric_value=raw,
            unit="count",
            currency=None,
        )


@pytest.mark.parametrize("raw", ["1", "-0.500000", "0.5", "00.000000", "1.0000000", "1e-1", ".500000"])
def test_decimal_ratio_requires_the_closed_unsigned_decimal6_form(raw: str) -> None:
    with pytest.raises(ClosedValidationError):
        ratio(raw)
    assert ratio("0.000000").raw_numeric_value == "0.000000"
    assert ratio("12.345678").raw_numeric_value == "12.345678"


@pytest.mark.parametrize("status", NON_OBSERVED)
def test_non_observed_side_must_carry_no_value(status: str) -> None:
    for kwargs in (
        {"value_type": "int64_count"},
        {"raw_numeric_value": "0"},
        {"unit": "count"},
        {"currency": "BRL"},
    ):
        fields: dict[str, Any] = {
            "presence_status": status,
            "value_type": None,
            "raw_numeric_value": None,
            "unit": None,
            "currency": None,
        }
        fields.update(kwargs)
        with pytest.raises(ClosedValidationError):
            ComparisonSide(**fields)
    assert absent(status).raw_numeric_value is None


def test_observed_side_requires_a_complete_closed_numeric_union() -> None:
    base: dict[str, Any] = {
        "presence_status": "observed",
        "value_type": "int64_count",
        "raw_numeric_value": "1",
        "unit": "count",
        "currency": None,
    }
    assert ComparisonSide(**base).raw_numeric_value == "1"
    for patch in (
        {"value_type": None},
        {"raw_numeric_value": None},
        {"unit": None},
        {"unit": "minor_currency"},
        {"unit": "ratio"},
        {"currency": "BRL"},
        {"value_type": "int64_float"},
        {"value_type": "null"},
    ):
        with pytest.raises(ClosedValidationError):
            ComparisonSide(**{**base, **patch})
    money_base = {
        **base,
        "value_type": "int64_minor_currency",
        "unit": "minor_currency",
        "currency": "BRL",
    }
    assert ComparisonSide(**money_base).currency == "BRL"
    for patch in ({"currency": None}, {"currency": "brl"}, {"currency": "REAL"}, {"unit": "count"}):
        with pytest.raises(ClosedValidationError):
            ComparisonSide(**{**money_base, **patch})


@pytest.mark.parametrize("status", ["", "OBSERVED", "not_applicable", "computed", None, 1, True])
def test_unknown_presence_status_is_malformed(status: Any) -> None:
    with pytest.raises(ClosedValidationError):
        ComparisonSide(
            presence_status=status,
            value_type=None,
            raw_numeric_value=None,
            unit=None,
            currency=None,
        )


def test_comparator_rejects_malformed_arguments() -> None:
    good = count(1)
    prof = exact_profile()
    for bad in (None, "1", 1, {"presence_status": "observed"}):
        with pytest.raises(ClosedValidationError):
            compare_sides(bad, good, prof, canonical_metric_ref=CLICKS)  # type: ignore[arg-type]
        with pytest.raises(ClosedValidationError):
            compare_sides(good, bad, prof, canonical_metric_ref=CLICKS)  # type: ignore[arg-type]
        with pytest.raises(ClosedValidationError):
            compare_sides(good, good, bad, canonical_metric_ref=CLICKS)  # type: ignore[arg-type]
    for bad_ref in ("", "clicks", "Metric:clicks_v1", "resource:x", None, 5):
        with pytest.raises(ClosedValidationError):
            compare_sides(good, good, prof, canonical_metric_ref=bad_ref)  # type: ignore[arg-type]


def test_comparator_is_pure_deterministic_and_returns_strings_only() -> None:
    cand, ref, prof = count(103), count(100), loose_profile("5", "0.050000")
    before = (dataclasses.asdict(cand), dataclasses.asdict(ref), prof.to_dict())
    first = compare(cand, ref, prof)
    second = compare(cand, ref, prof)
    assert first == second
    assert before == (dataclasses.asdict(cand), dataclasses.asdict(ref), prof.to_dict())
    for value in five(first):
        assert value is None or type(value) is str


def test_side_and_result_and_profile_are_immutable() -> None:
    side = count(1)
    result = compare(side, side, exact_profile())
    prof = exact_profile()
    for obj, attr in (
        (side, "raw_numeric_value"),
        (result, "reconciliation_outcome"),
        (prof, "max_absolute_delta"),
        (binding(), "canonical_query_digest"),
    ):
        with pytest.raises(AttributeError):
            setattr(obj, attr, "x")


# --------------------------------------------------------------------------- #
# ToleranceComparison: the object T7 embeds in fact_reconciliation/v1
# --------------------------------------------------------------------------- #


def test_comparison_to_dict_uses_exactly_the_adr_member_names() -> None:
    result = compare(count(103), count(100), loose_profile("5", "0.050000"))
    assert set(result.to_dict()) == RESULT_KEYS
    assert result.to_dict() == {
        "measured_absolute_delta": "3",
        "measured_relative_delta": "0.030000",
        "relative_delta_status": "computed",
        "reconciliation_outcome": "within_declared_tolerance",
        "metric_verification_status": "VERIFIED",
    }
    assert ToleranceComparison.from_dict(result.to_dict()) == result


def test_comparison_round_trips_every_truth_table_row() -> None:
    cases = [
        compare(count(0), count(0), exact_profile()),
        compare(count(7), count(0), exact_profile()),
        compare(count(9), count(9), exact_profile()),
        compare(count(10), count(9), loose_profile("1", "0.200000")),
        compare(count(10), count(9), exact_profile()),
        compare(absent("missing"), count(9), exact_profile()),
        compare(count(-1), count(9), exact_profile()),
    ]
    assert len({five(c) for c in cases}) == 7
    for case in cases:
        assert ToleranceComparison.from_dict(case.to_dict()) == case


ROWS = {
    "r1": ("0", None, "reference_zero", "exact_match", "VERIFIED"),
    "r2": ("7", None, "reference_zero", "mismatch", "UNRECONCILED"),
    "r3": ("0", "0.000000", "computed", "exact_match", "VERIFIED"),
    "r4": ("3", "0.030000", "computed", "within_declared_tolerance", "VERIFIED"),
    "r5": ("3", "0.030000", "computed", "mismatch", "UNRECONCILED"),
    "r6": (None, None, "not_computable", "not_comparable", "UNAVAILABLE"),
    "r7": (None, None, "not_computable", "not_comparable", "BLOCKED"),
}


@pytest.mark.parametrize("name", sorted(ROWS))
def test_every_legal_row_constructs(name: str) -> None:
    assert five(ToleranceComparison(*ROWS[name])) == ROWS[name]


@pytest.mark.parametrize(
    "bad",
    [
        pytest.param(("0", None, "computed", "exact_match", "VERIFIED"), id="computed_needs_relative"),
        pytest.param(("0", "0.000000", "reference_zero", "exact_match", "VERIFIED"), id="ref_zero_has_no_relative"),
        pytest.param(("5", "0.000000", "computed", "exact_match", "VERIFIED"), id="exact_match_needs_zero_delta"),
        pytest.param(("0", "0.000000", "computed", "mismatch", "UNRECONCILED"), id="mismatch_needs_delta"),
        pytest.param(("0", "0.000000", "computed", "within_declared_tolerance", "VERIFIED"), id="within_needs_delta"),
        pytest.param(("5", "0.010000", "computed", "exact_match", "VERIFIED"), id="exact_match_with_delta"),
        pytest.param(("3", "0.030000", "computed", "mismatch", "VERIFIED"), id="mismatch_cannot_verify"),
        pytest.param(("3", "0.030000", "computed", "within_declared_tolerance", "UNRECONCILED"), id="within_must_verify"),
        pytest.param(("3", "0.030000", "computed", "not_comparable", "BLOCKED"), id="computed_not_comparable"),
        pytest.param((None, None, "not_computable", "not_comparable", "VERIFIED"), id="not_comparable_verified"),
        pytest.param((None, None, "not_computable", "mismatch", "UNRECONCILED"), id="not_computable_mismatch"),
        pytest.param(("0", None, "not_computable", "not_comparable", "BLOCKED"), id="not_computable_has_delta"),
        pytest.param((None, None, "computed", "not_comparable", "UNAVAILABLE"), id="computed_unavailable"),
        pytest.param(("3", "0.03", "computed", "mismatch", "UNRECONCILED"), id="relative_not_decimal6"),
        pytest.param(("3", "-0.030000", "computed", "mismatch", "UNRECONCILED"), id="relative_negative"),
        pytest.param(("03", "0.030000", "computed", "mismatch", "UNRECONCILED"), id="delta_leading_zero"),
        pytest.param(("-3", "0.030000", "computed", "mismatch", "UNRECONCILED"), id="delta_negative"),
        pytest.param((3, "0.030000", "computed", "mismatch", "UNRECONCILED"), id="delta_native_int"),
        pytest.param((True, None, "reference_zero", "mismatch", "UNRECONCILED"), id="delta_bool"),
        pytest.param((str(MAX_INT64 + 1), None, "reference_zero", "mismatch", "UNRECONCILED"), id="delta_overflow"),
        pytest.param(("3", "0.030000", "weird", "mismatch", "UNRECONCILED"), id="status_unknown"),
        pytest.param(("3", "0.030000", "computed", "weird", "UNRECONCILED"), id="outcome_unknown"),
        pytest.param(("3", "0.030000", "computed", "mismatch", "DEGRADED"), id="verification_unknown"),
    ],
)
def test_comparison_rejects_unlisted_combinations(bad: tuple[Any, ...]) -> None:
    with pytest.raises(ClosedValidationError):
        ToleranceComparison(*bad)


# The seven truth-table rows (ADR-0001 section 5.4 / spec T5), as literals that do
# not come from the module under test: triple -> a delta pair that must construct.
TRUTH_TABLE_ROWS: dict[tuple[str, str, str], tuple[str | None, str | None]] = {
    ("reference_zero", "exact_match", "VERIFIED"): ("0", None),
    ("reference_zero", "mismatch", "UNRECONCILED"): ("7", None),
    ("computed", "exact_match", "VERIFIED"): ("0", "0.000000"),
    ("computed", "within_declared_tolerance", "VERIFIED"): ("3", "0.030000"),
    ("computed", "mismatch", "UNRECONCILED"): ("3", "0.030000"),
    ("not_computable", "not_comparable", "UNAVAILABLE"): (None, None),
    ("not_computable", "not_comparable", "BLOCKED"): (None, None),
}
ALL_STATUSES = ("computed", "reference_zero", "not_computable")
ALL_OUTCOMES = ("exact_match", "within_declared_tolerance", "mismatch", "not_comparable")
ALL_VERIFICATIONS = ("VERIFIED", "UNRECONCILED", "UNAVAILABLE", "BLOCKED")
ALL_TRIPLES = list(product(ALL_STATUSES, ALL_OUTCOMES, ALL_VERIFICATIONS))
# every delta shape a wrong extra row could plausibly be registered with
DELTA_SHAPES = list(product((None, "0", "3", "7"), (None, "0.000000", "0.030000", "1.000000")))


def test_the_truth_table_literals_are_seven_distinct_rows_inside_the_48_triples() -> None:
    assert len(TRUTH_TABLE_ROWS) == 7
    assert len(ALL_TRIPLES) == 48
    assert set(TRUTH_TABLE_ROWS) <= set(ALL_TRIPLES)


@pytest.mark.parametrize(
    ("status", "outcome", "verification"),
    [pytest.param(*triple, id="-".join(triple)) for triple in ALL_TRIPLES],
)
def test_exactly_the_seven_truth_table_rows_construct(
    status: str, outcome: str, verification: str
) -> None:
    triple = (status, outcome, verification)
    if triple in TRUTH_TABLE_ROWS:
        absolute, relative = TRUTH_TABLE_ROWS[triple]
        built = ToleranceComparison(absolute, relative, status, outcome, verification)  # type: ignore[arg-type]
        assert five(built) == (absolute, relative, status, outcome, verification)
        return
    for absolute, relative in DELTA_SHAPES:
        with pytest.raises(ClosedValidationError):
            ToleranceComparison(absolute, relative, status, outcome, verification)  # type: ignore[arg-type]


def test_forty_one_of_forty_eight_triples_reject_under_every_delta_shape() -> None:
    constructible = []
    for triple in ALL_TRIPLES:
        for absolute, relative in DELTA_SHAPES:
            try:
                ToleranceComparison(absolute, relative, *triple)  # type: ignore[arg-type]
            except ClosedValidationError:
                continue
            constructible.append(triple)
    assert set(constructible) == set(TRUTH_TABLE_ROWS)
    assert len(ALL_TRIPLES) - len(set(constructible)) == 41


def test_comparator_only_ever_produces_truth_table_triples() -> None:
    seen = set()
    for cand, ref, prof in (
        (count(0), count(0), exact_profile()),
        (count(5), count(0), exact_profile()),
        (count(9), count(9), exact_profile()),
        (count(10), count(9), loose_profile("1", "0.200000")),
        (count(10), count(9), exact_profile()),
        (absent("missing"), count(9), exact_profile()),
        (count(-1), count(9), exact_profile()),
    ):
        result = compare(cand, ref, prof)
        seen.add(
            (
                result.relative_delta_status,
                result.reconciliation_outcome,
                result.metric_verification_status,
            )
        )
    assert seen == set(TRUTH_TABLE_ROWS)


def test_non_observed_states_are_exactly_the_five_non_observed_provider_states() -> None:
    assert set(PROVIDER_PRESENCE_TO_UNKNOWN_REASON) - {"observed"} == set(NON_OBSERVED)
    assert set(NON_OBSERVED) == {
        "missing",
        "unproven_zero",
        "timeout",
        "not_applicable_at_level",
        "retracted_tombstone",
    }
    for status in NON_OBSERVED:
        assert absent(status).presence_status == status


def test_comparison_from_dict_is_closed() -> None:
    good = ToleranceComparison(*ROWS["r4"]).to_dict()
    assert ToleranceComparison.from_dict(good).reconciliation_outcome == "within_declared_tolerance"
    for key in RESULT_KEYS:
        missing = {k: v for k, v in good.items() if k != key}
        with pytest.raises(ClosedValidationError):
            ToleranceComparison.from_dict(missing)
    with pytest.raises(ClosedValidationError):
        ToleranceComparison.from_dict({**good, "extra": "x"})
    with pytest.raises(ClosedValidationError):
        ToleranceComparison.from_dict([good])


# --------------------------------------------------------------------------- #
# ToleranceProfile: closed P1 artifact
# --------------------------------------------------------------------------- #


def test_exact_profile_round_trips_with_null_binding() -> None:
    prof = exact_profile()
    data = prof.to_dict()
    assert data == {
        "$schema": "smart_ads/tolerance_profile/v1",
        "canonical_metric_ref": CLICKS,
        "value_type": "int64_count",
        "max_absolute_delta": "0",
        "max_relative_delta": "0.000000",
        "decimal_scale": 6,
        "rounding_mode": "ROUND_HALF_UP",
        "reference_zero_rule": "exact_zero_only",
        "authorization_binding": None,
    }
    assert set(data) == PROFILE_CORE_KEYS
    assert "authorization_binding" in data
    assert ToleranceProfile.from_dict(data) == prof


def test_authorized_profile_round_trips_and_embeds_the_closed_binding() -> None:
    prof = loose_profile("5", "0.050000", SPEND, "int64_minor_currency")
    data = prof.to_dict()
    assert set(data) == PROFILE_CORE_KEYS
    assert set(data["authorization_binding"]) == BINDING_KEYS
    assert data["authorization_binding"]["gate3_selection_locator"]["artifact_type"] == (
        "smart_ads/gate3_selection_receipt/v1"
    )
    assert data["authorization_binding"]["migration_run_context_locator"]["artifact_type"] == (
        "smart_ads/migration_run_context/v1"
    )
    assert ToleranceProfile.from_dict(data) == prof
    assert canonicalize_jcs(ToleranceProfile.from_dict(data).to_dict()) == canonicalize_jcs(data)


@pytest.mark.parametrize(
    ("max_abs", "max_rel"),
    [("1", "0.000000"), ("0", "0.000001"), ("7", "0.500000"), (str(MAX_INT64), "1.000000")],
)
def test_authorization_binding_is_required_when_any_limit_is_non_zero(
    max_abs: str, max_rel: str
) -> None:
    with pytest.raises(ClosedValidationError):
        ToleranceProfile(
            canonical_metric_ref=CLICKS,
            value_type="int64_count",
            max_absolute_delta=max_abs,
            max_relative_delta=max_rel,
            authorization_binding=None,
        )
    ok = loose_profile(max_abs, max_rel)
    assert ok.authorization_binding == binding()
    raw = ok.to_dict()
    raw["authorization_binding"] = None
    with pytest.raises(ClosedValidationError):
        ToleranceProfile.from_dict(raw)


def test_authorization_binding_must_be_null_when_both_limits_are_zero() -> None:
    with pytest.raises(ClosedValidationError):
        ToleranceProfile(
            canonical_metric_ref=CLICKS,
            value_type="int64_count",
            max_absolute_delta="0",
            max_relative_delta="0.000000",
            authorization_binding=binding(),
        )
    raw = exact_profile().to_dict()
    raw["authorization_binding"] = binding().to_dict()
    with pytest.raises(ClosedValidationError):
        ToleranceProfile.from_dict(raw)


def test_authorization_binding_must_be_the_dataclass_or_none() -> None:
    for bad in ({}, binding().to_dict(), "scope:x", 0, False):
        with pytest.raises(ClosedValidationError):
            ToleranceProfile(
                canonical_metric_ref=CLICKS,
                value_type="int64_count",
                max_absolute_delta="1",
                max_relative_delta="0.000000",
                authorization_binding=bad,  # type: ignore[arg-type]
            )


def test_binding_from_dict_is_closed_and_type_checked() -> None:
    good = binding().to_dict()
    assert AuthorizationBinding.from_dict(good) == binding()
    for key in BINDING_KEYS:
        with pytest.raises(ClosedValidationError):
            AuthorizationBinding.from_dict({k: v for k, v in good.items() if k != key})
    with pytest.raises(ClosedValidationError):
        AuthorizationBinding.from_dict({**good, "extra": "x"})
    with pytest.raises(ClosedValidationError):
        AuthorizationBinding.from_dict(None)
    swapped = {
        **good,
        "gate3_selection_locator": good["migration_run_context_locator"],
        "migration_run_context_locator": good["gate3_selection_locator"],
    }
    with pytest.raises(ClosedValidationError):
        AuthorizationBinding.from_dict(swapped)
    for patch in (
        {"canonical_query_digest": "sha256:" + ("G" * 64)},
        {"canonical_query_digest": "2" * 64},
        {"authorized_certification_scope": "tenant:ibvi"},
        {"authorized_certification_scope": "scope:"},
        {"authorized_certification_scope": "scope"},
    ):
        with pytest.raises(ClosedValidationError):
            AuthorizationBinding.from_dict({**good, **patch})


def test_binding_constructor_rejects_wrongly_typed_locators() -> None:
    with pytest.raises(ClosedValidationError):
        AuthorizationBinding(
            gate3_selection_locator=_loc("smart_ads/migration_run_context/v1"),
            canonical_query_digest="sha256:" + ("2" * 64),
            authorized_certification_scope="scope:campaigns-active",
            migration_run_context_locator=_loc("smart_ads/migration_run_context/v1", "3"),
        )
    with pytest.raises(ClosedValidationError):
        AuthorizationBinding(
            gate3_selection_locator=_loc("smart_ads/gate3_selection_receipt/v1"),
            canonical_query_digest="sha256:" + ("2" * 64),
            authorized_certification_scope="scope:campaigns-active",
            migration_run_context_locator=None,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    "bad_abs",
    ["", "-1", "01", "1.0", " 1", "1 ", "1e3", "+1", str(MAX_INT64 + 1), "9" * 30, 0, 1, True, False, None, 1.0],
)
def test_max_absolute_delta_is_a_canonical_unsigned_int64_string(bad_abs: Any) -> None:
    with pytest.raises(ClosedValidationError):
        ToleranceProfile(
            canonical_metric_ref=CLICKS,
            value_type="int64_count",
            max_absolute_delta=bad_abs,
            max_relative_delta="0.000000",
            authorization_binding=binding(),
        )


@pytest.mark.parametrize(
    "bad_rel",
    [
        "", "0", "0.5", "1.0000000", "-0.000001", "-0.500000", "00.500000", "01.000000",
        ".500000", "1e-3", "0,500000", " 0.500000", "0.500000 ", "9223372036854775808.000000",
        "99999999999999999999.000000", 0, 0.5, True, None,
    ],
)
def test_max_relative_delta_is_a_canonical_unsigned_decimal6_string(bad_rel: Any) -> None:
    with pytest.raises(ClosedValidationError):
        ToleranceProfile(
            canonical_metric_ref=CLICKS,
            value_type="int64_count",
            max_absolute_delta="0",
            max_relative_delta=bad_rel,
            authorization_binding=binding(),
        )


def test_limit_extremes_are_accepted() -> None:
    prof = loose_profile(str(MAX_INT64), "9223372036854775807.000000")
    assert ToleranceProfile.from_dict(prof.to_dict()) == prof


@pytest.mark.parametrize(
    "patch",
    [
        {"decimal_scale": 5},
        {"decimal_scale": 7},
        {"decimal_scale": 0},
        {"decimal_scale": True},
        {"decimal_scale": 1},
        {"decimal_scale": 6.0},
        {"decimal_scale": "6"},
        {"decimal_scale": None},
        {"rounding_mode": "ROUND_HALF_EVEN"},
        {"rounding_mode": "ROUND_DOWN"},
        {"rounding_mode": "round_half_up"},
        {"rounding_mode": None},
        {"reference_zero_rule": "relative_only"},
        {"reference_zero_rule": "exact_zero_only "},
        {"reference_zero_rule": None},
        {"$schema": "smart_ads/tolerance_profile/v2"},
        {"$schema": "smart_ads/finding/v1"},
    ],
)
def test_profile_fixed_members_reject_any_other_value(patch: dict[str, Any]) -> None:
    with pytest.raises(ClosedValidationError):
        ToleranceProfile.from_dict({**exact_profile().to_dict(), **patch})


@pytest.mark.parametrize("bad_value", [6.0, True, 5, "6", None])
def test_decimal_scale_is_a_strict_int_in_the_constructor(bad_value: Any) -> None:
    with pytest.raises(ClosedValidationError):
        ToleranceProfile(
            canonical_metric_ref=CLICKS,
            value_type="int64_count",
            max_absolute_delta="0",
            max_relative_delta="0.000000",
            authorization_binding=None,
            decimal_scale=bad_value,
        )


@pytest.mark.parametrize(
    "bad_ref",
    ["", "clicks", "Metric:clicks_v1", "metric:", "metric: clicks", "resource:abc", None, 1],
)
def test_profile_metric_ref_uses_the_opaque_metric_grammar(bad_ref: Any) -> None:
    with pytest.raises(ClosedValidationError):
        ToleranceProfile(
            canonical_metric_ref=bad_ref,
            value_type="int64_count",
            max_absolute_delta="0",
            max_relative_delta="0.000000",
            authorization_binding=None,
        )


@pytest.mark.parametrize("bad_type", ["decimal_ratio", "null", "int64", "", None, 1])
def test_profile_value_type_is_closed_to_the_two_integer_types(bad_type: Any) -> None:
    with pytest.raises(ClosedValidationError):
        ToleranceProfile(
            canonical_metric_ref="metric:custom_v1",
            value_type=bad_type,
            max_absolute_delta="0",
            max_relative_delta="0.000000",
            authorization_binding=None,
        )


def test_profile_value_type_must_agree_with_a_known_phase1_metric() -> None:
    for metric, wrong in (
        (CLICKS, "int64_minor_currency"),
        (IMPRESSIONS, "int64_minor_currency"),
        (SPEND, "int64_count"),
    ):
        with pytest.raises(ClosedValidationError):
            exact_profile(metric, wrong)
    for metric, right in (
        (CLICKS, "int64_count"),
        (IMPRESSIONS, "int64_count"),
        (SPEND, "int64_minor_currency"),
    ):
        assert exact_profile(metric, right).value_type == right
    # metrics outside the Phase 1 base set are closed only by their declared type
    assert exact_profile("metric:custom_v1", "int64_count").canonical_metric_ref == "metric:custom_v1"


def test_profile_from_dict_is_closed() -> None:
    good = exact_profile().to_dict()
    for key in PROFILE_CORE_KEYS:
        with pytest.raises(ClosedValidationError):
            ToleranceProfile.from_dict({k: v for k, v in good.items() if k != key})
    with pytest.raises(ClosedValidationError):
        ToleranceProfile.from_dict({**good, "extra": "x"})
    with pytest.raises(ClosedValidationError):
        ToleranceProfile.from_dict([good])
    with pytest.raises(ClosedValidationError):
        ToleranceProfile.from_dict(None)


def test_profile_from_dict_does_not_mutate_its_input() -> None:
    data = loose_profile("5", "0.050000", integrity=unsigned_integrity()).to_dict()
    snapshot = copy.deepcopy(data)
    ToleranceProfile.from_dict(data)
    assert data == snapshot


def test_profile_does_not_alias_caller_mutable_input() -> None:
    data = loose_profile("5", "0.050000").to_dict()
    parsed = ToleranceProfile.from_dict(data)
    data["authorization_binding"]["authorized_certification_scope"] = "scope:other"
    assert parsed.authorization_binding is not None
    assert parsed.authorization_binding.authorized_certification_scope == "scope:campaigns-active"
    assert parsed.to_dict()["authorization_binding"]["authorized_certification_scope"] == (
        "scope:campaigns-active"
    )


# --------------------------------------------------------------------------- #
# P1 envelope: preimage and content digest (the wheel never signs)
# --------------------------------------------------------------------------- #


def test_unsigned_integrity_round_trips_and_is_part_of_the_envelope() -> None:
    prof = loose_profile("5", "0.050000", integrity=unsigned_integrity())
    data = prof.to_dict()
    assert set(data) == PROFILE_CORE_KEYS | {"integrity"}
    assert set(data["integrity"]) == {"key_id", "key_registry_snapshot_locator"}
    parsed = ToleranceProfile.from_dict(data)
    assert parsed == prof
    assert parsed.integrity is not None and not parsed.integrity.is_signed
    with pytest.raises(ClosedValidationError):
        ToleranceProfile.from_dict(data, require_signed=True)


def test_profile_without_integrity_omits_the_member() -> None:
    assert "integrity" not in exact_profile().to_dict()
    with pytest.raises(ClosedValidationError):
        ToleranceProfile.from_dict(exact_profile().to_dict(), require_signed=True)
    with pytest.raises(ClosedValidationError):
        ToleranceProfile.from_dict({**exact_profile().to_dict(), "integrity": None})


def test_p1_preimage_drops_only_the_signature_members_and_digest_is_rfc8785_sha256() -> None:
    unsigned = loose_profile("5", "0.050000", integrity=unsigned_integrity())
    digest = p1_content_digest(unsigned.to_dict())
    expected = "sha256:" + hashlib.sha256(canonicalize_jcs(unsigned.to_dict())).hexdigest()
    assert digest == expected

    signed = loose_profile("5", "0.050000", integrity=signed_integrity(digest))
    signed_dict = signed.to_dict()
    assert set(signed_dict["integrity"]) == {
        "key_id",
        "key_registry_snapshot_locator",
        "content_digest",
        "signature_base64",
    }
    preimage = p1_preimage(signed_dict)
    assert preimage == unsigned.to_dict()
    assert "content_digest" not in preimage["integrity"]
    assert "signature_base64" not in preimage["integrity"]
    assert p1_content_digest(signed_dict) == digest
    assert signed_dict["integrity"]["content_digest"] == digest


def test_signed_profile_round_trips_when_the_content_digest_matches() -> None:
    digest = p1_content_digest(
        loose_profile("5", "0.050000", integrity=unsigned_integrity()).to_dict()
    )
    signed = loose_profile("5", "0.050000", integrity=signed_integrity(digest))
    parsed = ToleranceProfile.from_dict(signed.to_dict(), require_signed=True)
    assert parsed == signed
    assert parsed.integrity is not None and parsed.integrity.is_signed


def test_signed_profile_with_a_stale_content_digest_is_rejected() -> None:
    digest = p1_content_digest(
        loose_profile("5", "0.050000", integrity=unsigned_integrity()).to_dict()
    )
    with pytest.raises(ClosedValidationError):
        loose_profile("6", "0.050000", integrity=signed_integrity(digest))
    forged = loose_profile("5", "0.050000", integrity=signed_integrity(digest)).to_dict()
    forged["max_relative_delta"] = "0.060000"
    with pytest.raises(ClosedValidationError):
        ToleranceProfile.from_dict(forged, require_signed=True)
    with pytest.raises(ClosedValidationError):
        loose_profile(
            "5", "0.050000", integrity=signed_integrity("sha256:" + ("0" * 64))
        )


def test_content_digest_changes_with_every_semantic_member() -> None:
    base = loose_profile("5", "0.050000", integrity=unsigned_integrity())
    base_digest = p1_content_digest(base.to_dict())
    variants = [
        loose_profile("6", "0.050000", integrity=unsigned_integrity()),
        loose_profile("5", "0.050001", integrity=unsigned_integrity()),
        loose_profile("5", "0.050000", IMPRESSIONS, integrity=unsigned_integrity()),
        loose_profile("5", "0.050000", "metric:custom_v1", integrity=unsigned_integrity()),
    ]
    digests = {p1_content_digest(v.to_dict()) for v in variants}
    assert base_digest not in digests
    assert len(digests) == len(variants)


def test_integrity_must_be_p1_integrity_or_none() -> None:
    for bad in ({}, unsigned_integrity().to_dict(), "key", 1):
        with pytest.raises(ClosedValidationError):
            ToleranceProfile(
                canonical_metric_ref=CLICKS,
                value_type="int64_count",
                max_absolute_delta="0",
                max_relative_delta="0.000000",
                authorization_binding=None,
                integrity=bad,  # type: ignore[arg-type]
            )


# --------------------------------------------------------------------------- #
# require_bound_to: a non-zero profile must be authorized for this query/scope/run
# --------------------------------------------------------------------------- #

BINDING_MEMBERS = (
    "gate3_selection_locator",
    "canonical_query_digest",
    "authorized_certification_scope",
    "migration_run_context_locator",
)
DIFFERENT_MEMBERS: dict[str, Any] = {
    "gate3_selection_locator": _loc("smart_ads/gate3_selection_receipt/v1", "7"),
    "canonical_query_digest": "sha256:" + ("8" * 64),
    "authorized_certification_scope": "scope:campaigns-paused",
    "migration_run_context_locator": _loc("smart_ads/migration_run_context/v1", "6"),
}


def bound_args(**overrides: Any) -> dict[str, Any]:
    authorized = binding()
    args = {name: getattr(authorized, name) for name in BINDING_MEMBERS}
    return {**args, **overrides}


def test_the_binding_helper_matches_the_four_member_contract() -> None:
    assert set(bound_args()) == set(BINDING_MEMBERS) == _binding_keys()
    for name in BINDING_MEMBERS:
        assert bound_args()[name] != DIFFERENT_MEMBERS[name]


def _binding_keys() -> set[str]:
    return set(binding().to_dict())


@pytest.mark.parametrize(
    "arguments",
    [
        pytest.param(bound_args(), id="same_members_as_a_binding"),
        pytest.param(dict(DIFFERENT_MEMBERS), id="all_four_different"),
        pytest.param(bound_args(**{"canonical_query_digest": DIFFERENT_MEMBERS["canonical_query_digest"]}), id="one_different"),
    ],
)
def test_zero_profile_passes_with_any_well_formed_arguments(arguments: dict[str, Any]) -> None:
    prof = exact_profile()
    assert prof.authorization_binding is None
    assert prof.require_bound_to(**arguments) is None


@pytest.mark.parametrize(
    ("max_abs", "max_rel"),
    [("1", "0.000000"), ("0", "0.000001"), ("5", "0.050000"), (str(MAX_INT64), "1.000000")],
)
def test_non_zero_profile_passes_when_all_four_members_match(max_abs: str, max_rel: str) -> None:
    prof = loose_profile(max_abs, max_rel)
    assert prof.require_bound_to(**bound_args()) is None
    round_tripped = ToleranceProfile.from_dict(prof.to_dict())
    assert round_tripped.require_bound_to(**bound_args()) is None


@pytest.mark.parametrize("member", BINDING_MEMBERS)
def test_non_zero_profile_rejects_each_member_differing_alone(member: str) -> None:
    prof = loose_profile("5", "0.050000")
    with pytest.raises(ClosedValidationError, match=member):
        prof.require_bound_to(**bound_args(**{member: DIFFERENT_MEMBERS[member]}))


@pytest.mark.parametrize("member", ["gate3_selection_locator", "migration_run_context_locator"])
def test_non_zero_profile_rejects_a_locator_differing_in_a_single_member(member: str) -> None:
    prof = loose_profile("5", "0.050000")
    authorized: ArtifactLocator = getattr(binding(), member)
    other_type = (
        "smart_ads/migration_run_context/v1"
        if member == "gate3_selection_locator"
        else "smart_ads/gate3_selection_receipt/v1"
    )
    # same content_digest, different artifact_type
    same_digest_other_type = ArtifactLocator.from_digest(other_type, authorized.content_digest)
    with pytest.raises(ClosedValidationError, match=member):
        prof.require_bound_to(**bound_args(**{member: same_digest_other_type}))
    # same artifact_type, content_digest differing in its last hex digit only
    flipped = authorized.content_digest[:-1] + ("0" if authorized.content_digest[-1] != "0" else "1")
    same_type_other_digest = ArtifactLocator.from_digest(authorized.artifact_type, flipped)
    assert same_type_other_digest.artifact_type == authorized.artifact_type
    with pytest.raises(ClosedValidationError, match=member):
        prof.require_bound_to(**bound_args(**{member: same_type_other_digest}))


def test_the_first_differing_member_in_binding_order_is_named() -> None:
    prof = loose_profile("5", "0.050000")
    with pytest.raises(ClosedValidationError, match="gate3_selection_locator"):
        prof.require_bound_to(**DIFFERENT_MEMBERS)
    later = {name: DIFFERENT_MEMBERS[name] for name in BINDING_MEMBERS[1:]}
    with pytest.raises(ClosedValidationError, match="canonical_query_digest"):
        prof.require_bound_to(**bound_args(**later))
    last_two = {name: DIFFERENT_MEMBERS[name] for name in BINDING_MEMBERS[2:]}
    with pytest.raises(ClosedValidationError, match="authorized_certification_scope"):
        prof.require_bound_to(**bound_args(**last_two))


@pytest.mark.parametrize(
    ("member", "bad"),
    [
        ("gate3_selection_locator", None),
        ("gate3_selection_locator", "sha256:" + ("1" * 64)),
        ("gate3_selection_locator", {"artifact_type": "smart_ads/gate3_selection_receipt/v1"}),
        ("gate3_selection_locator", binding().gate3_selection_locator.to_dict()),
        ("migration_run_context_locator", None),
        ("migration_run_context_locator", 5),
        ("migration_run_context_locator", binding().migration_run_context_locator.to_dict()),
        ("canonical_query_digest", None),
        ("canonical_query_digest", ""),
        ("canonical_query_digest", "2" * 64),
        ("canonical_query_digest", "sha256:" + ("G" * 64)),
        ("canonical_query_digest", "sha256:" + ("2" * 63)),
        ("canonical_query_digest", 5),
        ("authorized_certification_scope", None),
        ("authorized_certification_scope", ""),
        ("authorized_certification_scope", "scope"),
        ("authorized_certification_scope", "scope:"),
        ("authorized_certification_scope", "tenant:ibvi"),
        ("authorized_certification_scope", 5),
    ],
)
@pytest.mark.parametrize("zero", [False, True], ids=["non_zero_profile", "zero_profile"])
def test_malformed_arguments_raise_for_zero_and_non_zero_profiles(
    zero: bool, member: str, bad: Any
) -> None:
    prof = exact_profile() if zero else loose_profile("5", "0.050000")
    with pytest.raises(ClosedValidationError):
        prof.require_bound_to(**bound_args(**{member: bad}))


def test_require_bound_to_takes_keyword_only_arguments_and_all_four() -> None:
    prof = loose_profile("5", "0.050000")
    args = bound_args()
    with pytest.raises(TypeError):
        prof.require_bound_to(*args.values())  # type: ignore[misc]
    for member in BINDING_MEMBERS:
        partial = {k: v for k, v in args.items() if k != member}
        with pytest.raises(TypeError):
            prof.require_bound_to(**partial)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        prof.require_bound_to(**args, extra="x")  # type: ignore[call-arg]


def test_compare_sides_does_not_take_binding_arguments() -> None:
    with pytest.raises(TypeError):
        compare_sides(  # type: ignore[call-arg]
            count(1), count(1), exact_profile(), canonical_metric_ref=CLICKS, **bound_args()
        )


def test_require_bound_to_is_pure_and_does_not_alter_the_profile() -> None:
    prof = loose_profile("5", "0.050000", integrity=unsigned_integrity())
    before = prof.to_dict()
    prof.require_bound_to(**bound_args())
    with pytest.raises(ClosedValidationError):
        prof.require_bound_to(**bound_args(**{"authorized_certification_scope": "scope:other"}))
    assert prof.to_dict() == before
