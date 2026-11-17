"""Truth-table tests for smart_ads.analytics.lattice (ADR-0001 sections 4.3, 5.5, 6.2).

The oracles in this file are written from the ADR text and deliberately do not
import any table from the implementation under test.
"""
from __future__ import annotations

import copy
import dataclasses
import functools
import itertools
from collections.abc import Callable
from typing import Any

import pytest

from smart_ads.analytics.lattice import (
    AGGREGATE_CONVERSIONS_REF,
    CANONICAL_LEADS_REF,
    EXPECTED_TRUTH_VECTORS,
    FIXTURE_ID_65X23,
    RESTATEMENT_KINDS,
    DerivedStateOutcome,
    FixtureSemanticRefs,
    RegressionFixtureV1,
    TruthVector,
    build_derived_row,
    candidate_sort_key,
    carries_value,
    classify_input_state,
    classify_restatement,
    derive_effective_state,
    order_candidates,
    select_winner,
)
from smart_ads.contracts.jcs import canonicalize_jcs
from smart_ads.contracts.numerics import NumericStateRow, validate_numeric_state
from smart_ads.contracts.scalars import ClosedValidationError
from smart_ads.contracts.schemas import AnalyticsLandingRow, FactKey

PROVIDER = "provider_observation"
DERIVED = "derived_formula"

# ---------------------------------------------------------------------------
# ADR-0001 section 4.3: the exhaustive 12-row matrix, transcribed literally.
# (row_id, metric_origin, presence_status, calculation_status, unknown_reason, carries_value)
# ---------------------------------------------------------------------------
MATRIX: tuple[tuple[str, str, str, str, str | None, bool], ...] = (
    ("provider:observed", PROVIDER, "observed", "not_applicable", None, True),
    ("provider:missing", PROVIDER, "missing", "not_applicable", "provider_omitted", False),
    ("provider:unproven_zero", PROVIDER, "unproven_zero", "not_applicable", "zero_not_proven", False),
    ("provider:timeout", PROVIDER, "timeout", "not_applicable", "provider_timeout", False),
    (
        "provider:not_applicable_at_level",
        PROVIDER,
        "not_applicable_at_level",
        "not_applicable",
        "metric_not_applicable_at_level",
        False,
    ),
    (
        "provider:retracted_tombstone",
        PROVIDER,
        "retracted_tombstone",
        "not_applicable",
        "source_retracted",
        False,
    ),
    ("derived:computed", DERIVED, "not_applicable", "computed", None, True),
    ("derived:input_missing", DERIVED, "not_applicable", "input_missing", "input_missing", False),
    ("derived:input_unproven", DERIVED, "not_applicable", "input_unproven", "input_unproven", False),
    (
        "derived:division_by_zero",
        DERIVED,
        "not_applicable",
        "division_by_zero",
        "division_by_zero",
        False,
    ),
    (
        "derived:not_applicable_at_level",
        DERIVED,
        "not_applicable_at_level",
        "not_applicable",
        "metric_not_applicable_at_level",
        False,
    ),
    (
        "derived:retracted_tombstone",
        DERIVED,
        "retracted_tombstone",
        "not_applicable",
        "source_retracted",
        False,
    ),
)
ROW_IDS = tuple(entry[0] for entry in MATRIX)

# ADR section 4.3 precedence, strongest first, with the derived-row outcome each
# tier produces. Upstream derived states are folded into tiers as the spec says:
# input_missing and division_by_zero behave as missing, input_unproven as unproven.
TIER_OF_ROW = {
    "provider:retracted_tombstone": "tombstone",
    "derived:retracted_tombstone": "tombstone",
    "provider:not_applicable_at_level": "not_applicable_at_level",
    "derived:not_applicable_at_level": "not_applicable_at_level",
    "provider:timeout": "timeout_or_missing",
    "provider:missing": "timeout_or_missing",
    "derived:input_missing": "timeout_or_missing",
    "derived:division_by_zero": "timeout_or_missing",
    "provider:unproven_zero": "unproven_zero",
    "derived:input_unproven": "unproven_zero",
    "provider:observed": "value",
    "derived:computed": "value",
}
TIER_RANK = {
    "tombstone": 0,
    "not_applicable_at_level": 1,
    "timeout_or_missing": 2,
    "unproven_zero": 3,
    "value": 4,
}
# tier -> (presence_status, calculation_status, unknown_reason) of the derived row
OUTCOME_OF_TIER: dict[str, tuple[str, str, str | None]] = {
    "tombstone": ("retracted_tombstone", "not_applicable", "source_retracted"),
    "not_applicable_at_level": (
        "not_applicable_at_level",
        "not_applicable",
        "metric_not_applicable_at_level",
    ),
    "timeout_or_missing": ("not_applicable", "input_missing", "input_missing"),
    "unproven_zero": ("not_applicable", "input_unproven", "input_unproven"),
    "value": ("not_applicable", "computed", None),
}
DIVISION_BY_ZERO_OUTCOME = ("not_applicable", "division_by_zero", "division_by_zero")


def matrix_row(row_id: str, *, currency: str | None = None) -> NumericStateRow:
    """Build one validated matrix row; value rows carry an int64 count."""
    for rid, origin, presence, calc, reason, has_value in MATRIX:
        if rid != row_id:
            continue
        return validate_numeric_state(
            metric_origin=origin,
            presence_status=presence,
            calculation_status=calc,
            unknown_reason=reason,
            value_type="int64_count" if has_value else None,
            raw_numeric_value="7" if has_value else None,
            unit="count" if has_value else None,
            currency=currency,
        )
    raise AssertionError(f"unknown matrix row id {row_id!r}")


def outcome_triple(outcome: DerivedStateOutcome) -> tuple[str, str, str | None]:
    return (outcome.presence_status, outcome.calculation_status, outcome.unknown_reason)


ALL_ROWS = {rid: matrix_row(rid) for rid in ROW_IDS}


# ---------------------------------------------------------------------------
# The 12-row matrix is exhaustive (reused from numerics, not duplicated)
# ---------------------------------------------------------------------------
def test_matrix_has_exactly_twelve_rows_and_every_other_combination_rejects() -> None:
    assert len(MATRIX) == 12
    expected = {(m[1], m[2], m[3], m[4]) for m in MATRIX}
    origins = (PROVIDER, DERIVED, "other")
    presences = (
        "observed",
        "missing",
        "unproven_zero",
        "timeout",
        "not_applicable_at_level",
        "retracted_tombstone",
        "not_applicable",
        "bogus",
    )
    calcs = (
        "not_applicable",
        "computed",
        "input_missing",
        "input_unproven",
        "division_by_zero",
        "bogus",
    )
    reasons = (
        None,
        "provider_omitted",
        "provider_timeout",
        "zero_not_proven",
        "metric_not_applicable_at_level",
        "source_retracted",
        "input_missing",
        "input_unproven",
        "division_by_zero",
        "bogus",
    )
    accepted: set[tuple[str, str, str, str | None]] = set()
    for origin, presence, calc, reason in itertools.product(origins, presences, calcs, reasons):
        for payload in (
            (None, None, None, None),
            ("int64_count", "7", "count", None),
        ):
            try:
                validate_numeric_state(
                    metric_origin=origin,
                    presence_status=presence,
                    calculation_status=calc,
                    unknown_reason=reason,
                    value_type=payload[0],
                    raw_numeric_value=payload[1],
                    unit=payload[2],
                    currency=payload[3],
                )
            except ClosedValidationError:
                continue
            accepted.add((origin, presence, calc, reason))
    assert accepted == expected


# ---------------------------------------------------------------------------
# classify_input_state: each of the 12 states lands in exactly one tier
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("row_id", ROW_IDS)
def test_classify_input_state_covers_every_matrix_row(row_id: str) -> None:
    assert classify_input_state(ALL_ROWS[row_id]) == TIER_OF_ROW[row_id]


def test_classify_input_state_rejects_non_rows_and_tampered_rows() -> None:
    for bad in (None, "observed", {"presence_status": "observed"}, ("observed",), 7):
        with pytest.raises(ClosedValidationError):
            classify_input_state(bad)  # type: ignore[arg-type]

    tampered = matrix_row("provider:missing")
    object.__setattr__(tampered, "presence_status", "not_applicable")
    with pytest.raises(ClosedValidationError):
        classify_input_state(tampered)

    forged_value = matrix_row("provider:timeout")
    object.__setattr__(forged_value, "raw_numeric_value", "0")
    with pytest.raises(ClosedValidationError):
        classify_input_state(forged_value)


# ---------------------------------------------------------------------------
# derive_effective_state: every state, every ordered pair, larger sets
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("row_id", ROW_IDS)
def test_each_state_alone_against_an_observed_peer(row_id: str) -> None:
    outcome = derive_effective_state([ALL_ROWS["provider:observed"], ALL_ROWS[row_id]])
    assert outcome_triple(outcome) == OUTCOME_OF_TIER[TIER_OF_ROW[row_id]]


@pytest.mark.parametrize("row_id", ROW_IDS)
def test_single_input_dependency_set(row_id: str) -> None:
    outcome = derive_effective_state([ALL_ROWS[row_id]])
    assert outcome_triple(outcome) == OUTCOME_OF_TIER[TIER_OF_ROW[row_id]]


PAIRS = list(itertools.product(ROW_IDS, ROW_IDS))


@pytest.mark.parametrize(
    ("first", "second"),
    PAIRS,
    ids=[f"{a}>>{b}" for a, b in PAIRS],
)
def test_every_ordered_pair_resolves_to_the_strongest_tier(first: str, second: str) -> None:
    tier_a, tier_b = TIER_OF_ROW[first], TIER_OF_ROW[second]
    winner = tier_a if TIER_RANK[tier_a] <= TIER_RANK[tier_b] else tier_b
    outcome = derive_effective_state([ALL_ROWS[first], ALL_ROWS[second]])
    assert outcome_triple(outcome) == OUTCOME_OF_TIER[winner]


TIERS = tuple(TIER_RANK)
TIER_PAIRS = [
    (stronger, weaker)
    for stronger in TIERS
    for weaker in TIERS
    if TIER_RANK[stronger] < TIER_RANK[weaker]
]


@pytest.mark.parametrize(("stronger", "weaker"), TIER_PAIRS)
def test_strict_precedence_between_tiers_holds_in_both_input_orders(
    stronger: str, weaker: str
) -> None:
    strong_rows = [rid for rid in ROW_IDS if TIER_OF_ROW[rid] == stronger]
    weak_rows = [rid for rid in ROW_IDS if TIER_OF_ROW[rid] == weaker]
    for strong_id, weak_id in itertools.product(strong_rows, weak_rows):
        for ordered in ((strong_id, weak_id), (weak_id, strong_id)):
            outcome = derive_effective_state([ALL_ROWS[rid] for rid in ordered])
            assert outcome_triple(outcome) == OUTCOME_OF_TIER[stronger]


def test_the_precedence_chain_is_exactly_the_adr_chain() -> None:
    # tombstone > not_applicable_at_level > timeout-or-missing > unproven_zero > observed
    chain = [
        "provider:retracted_tombstone",
        "provider:not_applicable_at_level",
        "provider:timeout",
        "provider:unproven_zero",
        "provider:observed",
    ]
    for cut in range(len(chain)):
        suffix = [ALL_ROWS[rid] for rid in chain[cut:]]
        outcome = derive_effective_state(list(reversed(suffix)))
        assert outcome_triple(outcome) == OUTCOME_OF_TIER[TIER_OF_ROW[chain[cut]]]


def test_timeout_and_missing_share_one_tier() -> None:
    both = derive_effective_state([ALL_ROWS["provider:timeout"], ALL_ROWS["provider:missing"]])
    only_timeout = derive_effective_state([ALL_ROWS["provider:timeout"]])
    only_missing = derive_effective_state([ALL_ROWS["provider:missing"]])
    assert outcome_triple(both) == outcome_triple(only_timeout) == outcome_triple(only_missing)
    assert both.calculation_status == "input_missing"


def test_every_ordered_triple_is_order_independent_and_picks_the_strongest_tier() -> None:
    for ids in itertools.product(ROW_IDS, repeat=3):
        best = min((TIER_OF_ROW[rid] for rid in ids), key=TIER_RANK.__getitem__)
        outcome = derive_effective_state([ALL_ROWS[rid] for rid in ids])
        assert outcome_triple(outcome) == OUTCOME_OF_TIER[best]


def test_dependency_set_accepts_any_iterable_without_mutating_it() -> None:
    rows = [ALL_ROWS["provider:observed"], ALL_ROWS["provider:missing"]]
    snapshot = list(rows)
    from_list = derive_effective_state(rows)
    from_tuple = derive_effective_state(tuple(rows))
    from_generator = derive_effective_state(row for row in rows)
    assert rows == snapshot
    assert from_list == from_tuple == from_generator


# ---------------------------------------------------------------------------
# division by zero is only decided when every input carries a value
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("value_row", ["provider:observed", "derived:computed"])
def test_all_inputs_with_values_yield_computed_or_division_by_zero(value_row: str) -> None:
    rows = [ALL_ROWS[value_row], ALL_ROWS["provider:observed"]]
    computed = derive_effective_state(rows)
    assert outcome_triple(computed) == OUTCOME_OF_TIER["value"]
    assert computed.carries_value is True
    zero = derive_effective_state(rows, division_by_zero=True)
    assert outcome_triple(zero) == DIVISION_BY_ZERO_OUTCOME
    assert zero.carries_value is False


@pytest.mark.parametrize("row_id", [rid for rid in ROW_IDS if TIER_OF_ROW[rid] != "value"])
def test_division_by_zero_never_overrides_a_stronger_input_state(row_id: str) -> None:
    outcome = derive_effective_state(
        [ALL_ROWS["provider:observed"], ALL_ROWS[row_id]], division_by_zero=True
    )
    assert outcome_triple(outcome) == OUTCOME_OF_TIER[TIER_OF_ROW[row_id]]
    assert outcome.carries_value is False


@pytest.mark.parametrize("bad_flag", [None, 0, 1, "true", "", [], 0.0])
def test_division_by_zero_flag_must_be_a_strict_bool(bad_flag: object) -> None:
    with pytest.raises(ClosedValidationError):
        derive_effective_state([ALL_ROWS["provider:observed"]], division_by_zero=bad_flag)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# rejection of unlisted states and malformed dependency sets
# ---------------------------------------------------------------------------
def test_empty_dependency_set_rejects() -> None:
    with pytest.raises(ClosedValidationError):
        derive_effective_state([])
    with pytest.raises(ClosedValidationError):
        derive_effective_state(())


@pytest.mark.parametrize(
    "bad_inputs",
    [
        "observed",
        b"observed",
        None,
        7,
        [None],
        ["observed"],
        [{"presence_status": "observed"}],
    ],
)
def test_malformed_dependency_sets_reject(bad_inputs: object) -> None:
    with pytest.raises(ClosedValidationError):
        derive_effective_state(bad_inputs)  # type: ignore[arg-type]


def test_unlisted_input_state_rejects_even_among_valid_peers() -> None:
    forged = matrix_row("provider:observed")
    object.__setattr__(forged, "presence_status", "not_applicable")
    with pytest.raises(ClosedValidationError):
        derive_effective_state([ALL_ROWS["provider:missing"], forged])


# ---------------------------------------------------------------------------
# DerivedStateOutcome and build_derived_row stay inside the derived rows
# ---------------------------------------------------------------------------
def test_outcome_is_frozen_and_closed_over_the_six_derived_rows() -> None:
    outcome = derive_effective_state([ALL_ROWS["provider:missing"]])
    with pytest.raises(dataclasses.FrozenInstanceError):
        outcome.calculation_status = "computed"  # type: ignore[misc]

    legal = {
        ("retracted_tombstone", "not_applicable", "source_retracted"),
        ("not_applicable_at_level", "not_applicable", "metric_not_applicable_at_level"),
        ("not_applicable", "input_missing", "input_missing"),
        ("not_applicable", "input_unproven", "input_unproven"),
        ("not_applicable", "division_by_zero", "division_by_zero"),
        ("not_applicable", "computed", None),
    }
    for triple in legal:
        assert outcome_triple(DerivedStateOutcome(*triple)) in legal
    illegal = [
        ("observed", "not_applicable", None),
        ("missing", "not_applicable", "provider_omitted"),
        ("not_applicable", "computed", "input_missing"),
        ("not_applicable", "input_missing", None),
        ("not_applicable", "not_applicable", None),
        ("retracted_tombstone", "computed", "source_retracted"),
        ("timeout", "not_applicable", "provider_timeout"),
    ]
    for triple in illegal:
        with pytest.raises(ClosedValidationError):
            DerivedStateOutcome(*triple)  # type: ignore[arg-type]


@pytest.mark.parametrize("row_id", ROW_IDS)
def test_build_derived_row_matches_the_derived_matrix_rows(row_id: str) -> None:
    outcome = derive_effective_state([ALL_ROWS[row_id]])
    if outcome.carries_value:
        row = build_derived_row(
            outcome,
            value_type="int64_count",
            raw_numeric_value="11",
            unit="count",
            currency=None,
        )
        assert row.raw_numeric_value == "11"
    else:
        row = build_derived_row(outcome)
        assert (row.value_type, row.raw_numeric_value, row.unit, row.currency) == (
            None,
            None,
            None,
            None,
        )
    assert row.metric_origin == DERIVED
    assert (row.presence_status, row.calculation_status, row.unknown_reason) == outcome_triple(
        outcome
    )
    assert isinstance(row, NumericStateRow)


class StrSubclass(str):
    """Equal and hash-equal to the str it wraps, but not exactly `str`."""


@pytest.mark.parametrize(
    "triple",
    [
        (StrSubclass("not_applicable"), "computed", None),
        ("not_applicable", StrSubclass("computed"), None),
        ("not_applicable", "input_missing", StrSubclass("input_missing")),
        (StrSubclass("retracted_tombstone"), "not_applicable", "source_retracted"),
    ],
    ids=["presence", "calculation", "reason", "tombstone-presence"],
)
def test_derived_state_outcome_rejects_str_subclasses(triple: tuple[object, ...]) -> None:
    with pytest.raises(ClosedValidationError, match="expected str"):
        DerivedStateOutcome(*triple)  # type: ignore[arg-type]


def test_build_derived_row_never_coerces_a_non_computed_state_to_a_value() -> None:
    for row_id in ROW_IDS:
        outcome = derive_effective_state([ALL_ROWS[row_id]])
        if outcome.carries_value:
            continue
        for raw in ("0", "7"):
            with pytest.raises(ClosedValidationError):
                build_derived_row(
                    outcome,
                    value_type="int64_count",
                    raw_numeric_value=raw,
                    unit="count",
                    currency=None,
                )


def test_build_derived_row_computed_requires_a_matrix_valid_value() -> None:
    computed = derive_effective_state([ALL_ROWS["provider:observed"]])
    with pytest.raises(ClosedValidationError):
        build_derived_row(computed)
    with pytest.raises(ClosedValidationError):
        build_derived_row(
            computed,
            value_type="int64_count",
            raw_numeric_value="-1",
            unit="count",
            currency=None,
        )
    money = build_derived_row(
        computed,
        value_type="int64_minor_currency",
        raw_numeric_value="250",
        unit="minor_currency",
        currency="USD",
        query_currency="USD",
    )
    assert money.currency == "USD"
    with pytest.raises(ClosedValidationError):
        build_derived_row("not an outcome")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Section 6.2: candidate ordering and the winner for one fact_key
# ---------------------------------------------------------------------------
RESOURCE_A = "resource:" + ("a" * 52)
RESOURCE_B = "resource:" + ("b" * 51) + "a"
T_EARLY = "2026-11-11T04:15:00.000000Z"
T_LATE = "2026-11-11T04:15:00.000001Z"
T_LATER = "2026-11-12T00:00:00.000000Z"
PROVIDER_REASON = {
    "observed": None,
    "missing": "provider_omitted",
    "unproven_zero": "zero_not_proven",
    "timeout": "provider_timeout",
    "not_applicable_at_level": "metric_not_applicable_at_level",
    "retracted_tombstone": "source_retracted",
}
FORMULA_REF = "source-metric:formula:sha256:" + ("c" * 64)


def make_fact_key(
    *,
    resource: str = RESOURCE_A,
    metric_date: str = "2026-11-10",
    metric: str = "metric:impressions_v1",
    source: str = "source-metric:provider:pipeboard.impressions:v1",
) -> FactKey:
    return FactKey(
        binding_ref="binding:meta-primary",
        account_ref="account:ibvi-01",
        resource_ref=resource,
        resource_level="campaign",
        metric_date=metric_date,
        metric_semantic_ref=metric,
        source_metric_ref=source,
        attribution_ref="attribution:not_applicable",
        breakdown_signature="breakdown:none",
    )


def make_row(
    *,
    presence: str = "observed",
    raw: str = "100",
    at: str = T_EARLY,
    obs: str = "observation:o1",
    key: FactKey | None = None,
    adapter: str = "adapter-1",
    semantic: str = "semantic-1",
) -> AnalyticsLandingRow:
    valued = presence == "observed"
    return AnalyticsLandingRow(
        fact_key=key if key is not None else make_fact_key(),
        value_type="int64_count" if valued else None,
        raw_numeric_value=raw if valued else None,
        unit="count" if valued else None,
        currency=None,
        metric_origin="provider_observation",
        presence_status=presence,  # type: ignore[arg-type]
        unknown_reason=PROVIDER_REASON[presence],  # type: ignore[arg-type]
        calculation_status="not_applicable",
        collected_at_utc=at,
        source_observation_ref=obs,
        adapter_version=adapter,
        semantic_version=semantic,
    )


def make_derived_row(
    *,
    state: str,
    raw: str = "5",
    at: str = T_EARLY,
) -> AnalyticsLandingRow:
    key = make_fact_key(metric="metric:derived_cpc_v1", source=FORMULA_REF)
    presence, calc, reason = {
        "computed": ("not_applicable", "computed", None),
        "input_missing": ("not_applicable", "input_missing", "input_missing"),
        "input_unproven": ("not_applicable", "input_unproven", "input_unproven"),
        "division_by_zero": ("not_applicable", "division_by_zero", "division_by_zero"),
        "not_applicable_at_level": (
            "not_applicable_at_level",
            "not_applicable",
            "metric_not_applicable_at_level",
        ),
        "tombstone": ("retracted_tombstone", "not_applicable", "source_retracted"),
    }[state]
    valued = state == "computed"
    return AnalyticsLandingRow(
        fact_key=key,
        value_type="int64_count" if valued else None,
        raw_numeric_value=raw if valued else None,
        unit="count" if valued else None,
        currency=None,
        metric_origin="derived_formula",
        presence_status=presence,  # type: ignore[arg-type]
        unknown_reason=reason,  # type: ignore[arg-type]
        calculation_status=calc,  # type: ignore[arg-type]
        collected_at_utc=at,
        source_observation_ref="observation:d1",
        adapter_version="adapter-1",
        semantic_version="semantic-1",
    )


# Every one of the 12 matrix rows as a complete landing row, keyed like MATRIX.
LANDING_ROWS: dict[str, AnalyticsLandingRow] = {
    **{
        f"provider:{presence}": make_row(presence=presence)
        for presence in PROVIDER_REASON
    },
    "derived:computed": make_derived_row(state="computed"),
    "derived:input_missing": make_derived_row(state="input_missing"),
    "derived:input_unproven": make_derived_row(state="input_unproven"),
    "derived:division_by_zero": make_derived_row(state="division_by_zero"),
    "derived:not_applicable_at_level": make_derived_row(state="not_applicable_at_level"),
    "derived:retracted_tombstone": make_derived_row(state="tombstone"),
}
VALUE_ROW_IDS = frozenset({"provider:observed", "derived:computed"})


def test_landing_rows_cover_the_twelve_matrix_rows() -> None:
    assert set(LANDING_ROWS) == set(ROW_IDS)


@pytest.mark.parametrize("row_id", ROW_IDS)
def test_carries_value_is_true_only_for_observed_and_computed_rows(row_id: str) -> None:
    result = carries_value(LANDING_ROWS[row_id])
    assert result is (row_id in VALUE_ROW_IDS)
    # One definition of "carries a value": it agrees with the lattice tier.
    assert result is (classify_input_state(ALL_ROWS[row_id]) == "value")


def test_carries_value_is_true_for_zero_and_money_values() -> None:
    zero = make_row(raw="0")
    assert zero.raw_numeric_value == "0"
    assert carries_value(zero) is True  # an observed zero is a value
    money = AnalyticsLandingRow(
        fact_key=make_fact_key(
            metric="metric:spend_v1", source="source-metric:provider:pipeboard.spend:v1"
        ),
        value_type="int64_minor_currency",
        raw_numeric_value="250",
        unit="minor_currency",
        currency="BRL",
        metric_origin="provider_observation",
        presence_status="observed",
        unknown_reason=None,
        calculation_status="not_applicable",
        collected_at_utc=T_EARLY,
        source_observation_ref="observation:o1",
        adapter_version="adapter-1",
        semantic_version="semantic-1",
    )
    assert carries_value(money) is True


def test_carries_value_rejects_non_rows_and_tampered_rows() -> None:
    for bad in (None, "observed", LANDING_ROWS["provider:observed"].to_dict(), ALL_ROWS["provider:observed"]):
        with pytest.raises(ClosedValidationError):
            carries_value(bad)  # type: ignore[arg-type]

    forged_value = make_row(presence="missing")
    object.__setattr__(forged_value, "raw_numeric_value", "5")
    with pytest.raises(ClosedValidationError):
        carries_value(forged_value)  # a missing row never carries a value

    stripped_value = make_row(presence="observed")
    object.__setattr__(stripped_value, "raw_numeric_value", None)
    with pytest.raises(ClosedValidationError):
        carries_value(stripped_value)

    unlisted = make_row(presence="observed")
    object.__setattr__(unlisted, "presence_status", "not_applicable")
    with pytest.raises(ClosedValidationError):
        carries_value(unlisted)


def test_classify_restatement_rejects_tampered_rows() -> None:
    forged = make_row(presence="missing", at=T_LATE, obs="observation:o2")
    object.__setattr__(forged, "raw_numeric_value", "5")
    with pytest.raises(ClosedValidationError):
        classify_restatement(make_row(at=T_EARLY), forged)


def is_tombstone(row: AnalyticsLandingRow) -> bool:
    return row.presence_status == "retracted_tombstone"


def beats(first: AnalyticsLandingRow, second: AnalyticsLandingRow) -> bool:
    """ADR 6.2 precedence written as the three numbered rules, in order."""
    if first.collected_at_utc != second.collected_at_utc:
        return first.collected_at_utc > second.collected_at_utc
    if is_tombstone(first) != is_tombstone(second):
        return is_tombstone(first)
    return first.semantic_observation_digest > second.semantic_observation_digest


def oracle_winner(rows: list[AnalyticsLandingRow]) -> AnalyticsLandingRow:
    undefeated = [
        row for row in rows if all(row is other or beats(row, other) for other in rows)
    ]
    assert len(undefeated) == 1
    return undefeated[0]


def test_candidate_sort_key_is_the_jcs_bytes_of_fact_key_time_and_digest() -> None:
    row = make_row()
    expected = canonicalize_jcs(
        [row.fact_key.to_dict(), row.collected_at_utc, row.semantic_observation_digest]
    )
    assert candidate_sort_key(row) == expected
    assert isinstance(candidate_sort_key(row), bytes)
    with pytest.raises(ClosedValidationError):
        candidate_sort_key(row.to_dict())  # type: ignore[arg-type]


def test_order_candidates_sorts_by_jcs_bytes_and_ignores_input_order() -> None:
    rows = [
        make_row(key=make_fact_key(resource=RESOURCE_B), obs="observation:o1"),
        make_row(key=make_fact_key(resource=RESOURCE_A), obs="observation:o2", at=T_LATE),
        make_row(key=make_fact_key(resource=RESOURCE_A), obs="observation:o3", at=T_EARLY),
        make_row(key=make_fact_key(metric_date="2026-11-09"), obs="observation:o4"),
        make_row(presence="retracted_tombstone", obs="observation:o5", at=T_LATE),
    ]
    expected = tuple(
        sorted(
            rows,
            key=lambda r: canonicalize_jcs(
                [r.fact_key.to_dict(), r.collected_at_utc, r.semantic_observation_digest]
            ),
        )
    )
    for permutation in itertools.permutations(rows):
        assert order_candidates(permutation) == expected
    assert order_candidates(iter(rows)) == expected
    assert order_candidates([]) == ()


def test_order_candidates_within_one_fact_key_is_time_then_digest_ascending() -> None:
    key = make_fact_key()
    rows = [
        make_row(key=key, obs=f"observation:o{i}", at=at, raw=str(i))
        for i, at in enumerate((T_LATE, T_EARLY, T_LATER, T_EARLY), start=1)
    ]
    ordered = order_candidates(rows)
    assert [(r.collected_at_utc, r.semantic_observation_digest) for r in ordered] == sorted(
        (r.collected_at_utc, r.semantic_observation_digest) for r in rows
    )


def test_order_candidates_rejects_duplicates_and_non_rows() -> None:
    row = make_row()
    with pytest.raises(ClosedValidationError):
        order_candidates([row, row])
    twin = AnalyticsLandingRow.from_dict(row.to_dict())
    assert twin == row and twin is not row
    with pytest.raises(ClosedValidationError):
        order_candidates([row, twin])
    for bad in ([row, row.to_dict()], [None], "rows", 7):
        with pytest.raises(ClosedValidationError):
            order_candidates(bad)  # type: ignore[arg-type]


def _same_time_pair(*, tombstone_has_greater_digest: bool) -> tuple[AnalyticsLandingRow, ...]:
    """A tombstone and an observation at one instant, with the requested digest order."""
    for index in range(1, 200):
        tomb = make_row(presence="retracted_tombstone", obs=f"observation:t{index}")
        obs = make_row(obs=f"observation:v{index}")
        greater = tomb.semantic_observation_digest > obs.semantic_observation_digest
        if greater == tombstone_has_greater_digest:
            return tomb, obs
    raise AssertionError("no digest ordering found")


@pytest.mark.parametrize("tombstone_has_greater_digest", [True, False])
def test_winner_rule_2_tombstone_beats_non_tombstone_at_equal_time(
    tombstone_has_greater_digest: bool,
) -> None:
    tomb, obs = _same_time_pair(tombstone_has_greater_digest=tombstone_has_greater_digest)
    for permutation in itertools.permutations((tomb, obs)):
        assert select_winner(permutation) is tomb


@pytest.mark.parametrize("nontombstone", ["observed", "missing", "unproven_zero", "timeout", "not_applicable_at_level"])
def test_winner_rule_2_tombstone_beats_every_non_tombstone_state(nontombstone: str) -> None:
    tomb = make_row(presence="retracted_tombstone", obs="observation:t1")
    other = make_row(presence=nontombstone, obs="observation:v1")
    assert select_winner([other, tomb]) is tomb
    assert select_winner([tomb, other]) is tomb


@pytest.mark.parametrize("earlier_has_greater_digest", [True, False])
def test_winner_rule_1_later_collected_at_wins_regardless_of_digest(
    earlier_has_greater_digest: bool,
) -> None:
    for index in range(1, 200):
        early = make_row(at=T_EARLY, obs=f"observation:e{index}")
        late = make_row(at=T_LATE, obs=f"observation:l{index}")
        if (early.semantic_observation_digest > late.semantic_observation_digest) == (
            earlier_has_greater_digest
        ):
            break
    else:
        raise AssertionError("no digest ordering found")
    assert select_winner([early, late]) is late
    assert select_winner([late, early]) is late


def test_winner_rule_1_beats_the_tombstone_rule() -> None:
    early_tomb = make_row(presence="retracted_tombstone", at=T_EARLY, obs="observation:t1")
    late_obs = make_row(at=T_LATE, obs="observation:v1")
    assert select_winner([early_tomb, late_obs]) is late_obs
    assert select_winner([late_obs, early_tomb]) is late_obs

    early_obs = make_row(at=T_EARLY, obs="observation:v2")
    late_tomb = make_row(presence="retracted_tombstone", at=T_LATE, obs="observation:t2")
    assert select_winner([early_obs, late_tomb]) is late_tomb


@pytest.mark.parametrize(
    ("first_state", "second_state"),
    [
        ("observed", "observed"),
        ("observed", "missing"),
        ("missing", "timeout"),
        ("unproven_zero", "not_applicable_at_level"),
        ("retracted_tombstone", "retracted_tombstone"),
    ],
)
def test_winner_rule_3_greater_semantic_digest_wins_when_time_and_tombstone_tie(
    first_state: str, second_state: str
) -> None:
    first = make_row(presence=first_state, obs="observation:a1", raw="1")
    second = make_row(presence=second_state, obs="observation:b1", raw="2")
    assert first.semantic_observation_digest != second.semantic_observation_digest
    expected = max((first, second), key=lambda r: r.semantic_observation_digest)
    assert select_winner([first, second]) is expected
    assert select_winner([second, first]) is expected


def test_winner_is_not_the_last_candidate_in_canonical_order() -> None:
    # The canonical order is (time, digest) ascending, but a tombstone with the
    # smaller digest still wins an equal-time tie, so max-by-sort-key is wrong.
    tomb, obs = _same_time_pair(tombstone_has_greater_digest=False)
    assert order_candidates([tomb, obs])[-1] is obs
    assert select_winner([tomb, obs]) is tomb


def _exhaustive_candidate_pool() -> list[AnalyticsLandingRow]:
    pool: list[AnalyticsLandingRow] = []
    for at in (T_EARLY, T_LATE):
        for state in ("observed", "missing", "retracted_tombstone"):
            for obs in ("observation:p1", "observation:p2"):
                pool.append(make_row(presence=state, at=at, obs=obs, raw="9"))
    assert len({row.semantic_observation_digest for row in pool}) == len(pool)
    return pool


def test_winner_matches_the_adr_rules_for_every_subset_in_every_order() -> None:
    pool = _exhaustive_candidate_pool()
    for size in (2, 3, 4):
        for subset in itertools.combinations(pool, size):
            expected = oracle_winner(list(subset))
            assert select_winner(subset) is expected
            assert select_winner(tuple(reversed(subset))) is expected


def test_incremental_curation_equals_batch_curation() -> None:
    # Regeneration, compaction, or re-curation cannot change the winner.
    pool = _exhaustive_candidate_pool()
    batch = select_winner(pool)
    folded = functools.reduce(lambda acc, row: select_winner([acc, row]), pool[1:], pool[0])
    reverse_folded = functools.reduce(
        lambda acc, row: select_winner([acc, row]), reversed(pool[:-1]), pool[-1]
    )
    assert folded is batch
    assert reverse_folded is batch
    assert select_winner([batch]) is batch


def test_winner_of_a_single_candidate_is_that_candidate() -> None:
    row = make_row()
    assert select_winner([row]) is row


def test_winner_rejects_empty_mixed_fact_keys_duplicates_and_non_rows() -> None:
    with pytest.raises(ClosedValidationError):
        select_winner([])
    mixed = [
        make_row(key=make_fact_key(resource=RESOURCE_A)),
        make_row(key=make_fact_key(resource=RESOURCE_B), at=T_LATE),
    ]
    with pytest.raises(ClosedValidationError):
        select_winner(mixed)
    other_date = [make_row(), make_row(key=make_fact_key(metric_date="2026-11-09"), at=T_LATE)]
    with pytest.raises(ClosedValidationError):
        select_winner(other_date)
    row = make_row()
    with pytest.raises(ClosedValidationError):
        select_winner([row, row])
    for bad in ([row.to_dict()], None, "row"):
        with pytest.raises(ClosedValidationError):
            select_winner(bad)  # type: ignore[arg-type]


def test_winner_selection_does_not_mutate_or_copy_the_inputs() -> None:
    rows = [make_row(at=T_EARLY, obs="observation:o1"), make_row(at=T_LATE, obs="observation:o2")]
    snapshot = [row.to_dict() for row in rows]
    winner = select_winner(rows)
    assert [row.to_dict() for row in rows] == snapshot
    assert winner is rows[1]


# ---------------------------------------------------------------------------
# Restatement classifier: tombstone, value_change, state_flip
# ---------------------------------------------------------------------------
def test_restatement_kinds_are_the_three_utf8_sorted_kinds() -> None:
    assert RESTATEMENT_KINDS == ("state_flip", "tombstone", "value_change")
    assert list(RESTATEMENT_KINDS) == sorted(RESTATEMENT_KINDS, key=lambda s: s.encode("utf-8"))


STATES = (
    "observed",
    "missing",
    "timeout",
    "unproven_zero",
    "not_applicable_at_level",
    "retracted_tombstone",
)


def expected_restatement(prior_state: str, current_state: str, *, same_value: bool) -> str | None:
    """Spec rule table, written per state pair rather than per rule."""
    if prior_state == current_state == "observed":
        return None if same_value else "value_change"
    if prior_state == current_state:
        return None  # an unchanged unknown state is not a restatement
    if current_state == "retracted_tombstone":
        return "tombstone"
    if "observed" in (prior_state, current_state):
        return "state_flip"
    return None  # unknown -> a different unknown carries no value


@pytest.mark.parametrize("prior_state", STATES)
@pytest.mark.parametrize("current_state", STATES)
@pytest.mark.parametrize("same_value", [True, False])
def test_classify_restatement_for_every_state_pair(
    prior_state: str, current_state: str, same_value: bool
) -> None:
    prior = make_row(presence=prior_state, raw="100", at=T_EARLY, obs="observation:o1")
    current = make_row(
        presence=current_state,
        raw="100" if same_value else "101",
        at=T_LATE,
        obs="observation:o2",
    )
    assert classify_restatement(prior, current) == expected_restatement(
        prior_state, current_state, same_value=same_value
    )


def test_classify_restatement_named_cases() -> None:
    observed = make_row(raw="100", at=T_EARLY)
    assert classify_restatement(observed, make_row(raw="100", at=T_LATE, obs="observation:o2")) is None
    assert classify_restatement(observed, make_row(raw="101", at=T_LATE, obs="observation:o2")) == "value_change"
    assert (
        classify_restatement(observed, make_row(presence="retracted_tombstone", at=T_LATE, obs="observation:o2"))
        == "tombstone"
    )
    assert (
        classify_restatement(observed, make_row(presence="missing", at=T_LATE, obs="observation:o2"))
        == "state_flip"
    )
    assert (
        classify_restatement(
            make_row(presence="timeout", at=T_EARLY), make_row(raw="100", at=T_LATE, obs="observation:o2")
        )
        == "state_flip"
    )
    assert (
        classify_restatement(
            make_row(presence="retracted_tombstone", at=T_EARLY),
            make_row(raw="100", at=T_LATE, obs="observation:o2"),
        )
        == "state_flip"
    )
    # A previously missing fact that is now retracted is still a tombstone restatement.
    assert (
        classify_restatement(
            make_row(presence="missing", at=T_EARLY),
            make_row(presence="retracted_tombstone", at=T_LATE, obs="observation:o2"),
        )
        == "tombstone"
    )
    # Unknown -> a different unknown carries no value and is not a restatement kind.
    assert (
        classify_restatement(
            make_row(presence="missing", at=T_EARLY),
            make_row(presence="timeout", at=T_LATE, obs="observation:o2"),
        )
        is None
    )


def test_classify_restatement_ignores_retrieval_metadata_changes() -> None:
    prior = make_row(raw="100", at=T_EARLY, obs="observation:o1", adapter="adapter-1", semantic="semantic-1")
    current = make_row(raw="100", at=T_LATE, obs="observation:o9", adapter="adapter-2", semantic="semantic-2")
    assert prior.semantic_observation_digest != current.semantic_observation_digest
    assert classify_restatement(prior, current) is None


def test_classify_restatement_works_for_derived_rows() -> None:
    computed_5 = make_derived_row(state="computed", raw="5", at=T_EARLY)
    assert classify_restatement(computed_5, make_derived_row(state="computed", raw="6", at=T_LATE)) == "value_change"
    assert classify_restatement(computed_5, make_derived_row(state="computed", raw="5", at=T_LATE)) is None
    assert classify_restatement(computed_5, make_derived_row(state="input_missing", at=T_LATE)) == "state_flip"
    assert classify_restatement(computed_5, make_derived_row(state="tombstone", at=T_LATE)) == "tombstone"


def test_classify_restatement_requires_one_fact_key_and_landing_rows() -> None:
    row = make_row(at=T_EARLY)
    later = make_row(at=T_LATE, raw="101", obs="observation:o2")
    other_key = make_row(key=make_fact_key(resource=RESOURCE_B), at=T_LATE, raw="101")
    with pytest.raises(ClosedValidationError, match="fact_key"):
        classify_restatement(row, other_key)
    for bad in (None, row.to_dict(), "row"):
        with pytest.raises(ClosedValidationError):
            classify_restatement(bad, later)  # type: ignore[arg-type]
        with pytest.raises(ClosedValidationError):
            classify_restatement(row, bad)  # type: ignore[arg-type]


def test_classify_restatement_rejects_a_current_that_loses_by_time() -> None:
    older = make_row(at=T_EARLY, raw="100", obs="observation:o1")
    newer = make_row(at=T_LATE, raw="101", obs="observation:o2")
    assert classify_restatement(older, newer) == "value_change"
    with pytest.raises(ClosedValidationError, match="section 6.2"):
        classify_restatement(newer, older)
    # Rule 1 outranks rule 2: an older tombstone never beats a newer observation.
    older_tomb = make_row(presence="retracted_tombstone", at=T_EARLY, obs="observation:t1")
    newer_obs = make_row(at=T_LATE, raw="100", obs="observation:o3")
    assert classify_restatement(older_tomb, newer_obs) == "state_flip"
    with pytest.raises(ClosedValidationError, match="section 6.2"):
        classify_restatement(newer_obs, older_tomb)


@pytest.mark.parametrize("tombstone_has_greater_digest", [True, False])
def test_classify_restatement_accepts_a_same_instant_tombstone_winner(
    tombstone_has_greater_digest: bool,
) -> None:
    # ADR 6.2 rule 2: at equal time a tombstone beats a non-tombstone, so the
    # tombstone is a legal winner (current) whatever the digests say.
    tomb, obs = _same_time_pair(tombstone_has_greater_digest=tombstone_has_greater_digest)
    assert tomb.collected_at_utc == obs.collected_at_utc
    assert select_winner([obs, tomb]) is tomb
    assert classify_restatement(obs, tomb) == "tombstone"
    # The observation lost that tie, so it cannot be the restating row.
    with pytest.raises(ClosedValidationError, match="section 6.2"):
        classify_restatement(tomb, obs)


def test_classify_restatement_accepts_a_same_instant_digest_winner() -> None:
    # ADR 6.2 rule 3: equal time, neither a tombstone, greater digest wins.
    first = make_row(raw="100", obs="observation:a1")
    second = make_row(raw="101", obs="observation:b1")
    assert first.collected_at_utc == second.collected_at_utc
    assert first.semantic_observation_digest != second.semantic_observation_digest
    lesser, greater = sorted((first, second), key=lambda r: r.semantic_observation_digest)
    assert select_winner([lesser, greater]) is greater
    assert classify_restatement(lesser, greater) == "value_change"
    with pytest.raises(ClosedValidationError, match="section 6.2"):
        classify_restatement(greater, lesser)


def test_classify_restatement_rejects_the_same_candidate() -> None:
    row = make_row(at=T_EARLY)
    twin = AnalyticsLandingRow.from_dict(row.to_dict())
    assert twin == row and twin is not row
    for same in (row, twin):
        with pytest.raises(ClosedValidationError, match="section 6.2"):
            classify_restatement(row, same)
    tomb = make_row(presence="retracted_tombstone", obs="observation:t1")
    with pytest.raises(ClosedValidationError, match="section 6.2"):
        classify_restatement(tomb, tomb)


def test_classify_restatement_accepts_exactly_the_pairs_select_winner_prefers() -> None:
    # classify_restatement and select_winner share one precedence order.
    pool = _exhaustive_candidate_pool()
    for prior, current in itertools.permutations(pool, 2):
        current_wins = select_winner([prior, current]) is current
        assert current_wins == beats(current, prior)
        if current_wins:
            assert classify_restatement(prior, current) == expected_restatement(
                prior.presence_status, current.presence_status, same_value=True
            )
        else:
            with pytest.raises(ClosedValidationError, match="section 6.2"):
                classify_restatement(prior, current)


@pytest.mark.parametrize("prior_state", STATES)
@pytest.mark.parametrize("current_state", STATES)
@pytest.mark.parametrize("same_value", [True, False])
def test_classify_restatement_for_every_same_instant_state_pair(
    prior_state: str, current_state: str, same_value: bool
) -> None:
    prior = make_row(presence=prior_state, raw="100", obs="observation:o1")
    current = make_row(
        presence=current_state, raw="100" if same_value else "101", obs="observation:o2"
    )
    assert prior.collected_at_utc == current.collected_at_utc
    if beats(current, prior):
        assert classify_restatement(prior, current) == expected_restatement(
            prior_state, current_state, same_value=same_value
        )
    else:
        with pytest.raises(ClosedValidationError, match="section 6.2"):
            classify_restatement(prior, current)


# ---------------------------------------------------------------------------
# Section 5.5: fixture:semantic-metric-65x23-v1
# ---------------------------------------------------------------------------
SNAPSHOT_DIGEST = "sha256:" + ("ab" * 32)
OTHER_DIGEST = "sha256:" + ("cd" * 32)


def adr_fixture_dict() -> dict[str, Any]:
    """The JSON object of ADR-0001 section 5.5, transcribed literally."""
    return {
        "$schema": "smart_ads/regression_fixture/v1",
        "fixture_id": "fixture:semantic-metric-65x23-v1",
        "fixture_role": "regression_only",
        "provider_provenance": "synthetic",
        "registry_transition": "none",
        "capability_promotion": "none",
        "before_registry_snapshot_digest": SNAPSHOT_DIGEST,
        "after_registry_snapshot_digest": SNAPSHOT_DIGEST,
        "truth_vectors": [
            {"aggregate_conversions": "65", "canonical_leads": "unknown"},
            {"aggregate_conversions": "0", "canonical_leads": "23"},
            {"aggregate_conversions": "unknown", "canonical_leads": "unknown"},
        ],
        "semantic_refs": {
            "aggregate_conversions": "metric:aggregate_conversions_v1",
            "canonical_leads": "metric:canonical_leads_v1",
        },
    }


def test_module_constants_match_the_adr_text() -> None:
    assert FIXTURE_ID_65X23 == "fixture:semantic-metric-65x23-v1"
    assert AGGREGATE_CONVERSIONS_REF == "metric:aggregate_conversions_v1"
    assert CANONICAL_LEADS_REF == "metric:canonical_leads_v1"
    assert isinstance(EXPECTED_TRUTH_VECTORS, tuple)
    assert [
        {"aggregate_conversions": v.aggregate_conversions, "canonical_leads": v.canonical_leads}
        for v in EXPECTED_TRUTH_VECTORS
    ] == adr_fixture_dict()["truth_vectors"]


def test_adr_fixture_parses_and_serializes_to_the_same_object() -> None:
    literal = adr_fixture_dict()
    fixture = RegressionFixtureV1.from_dict(literal)
    assert fixture.to_dict() == literal
    assert canonicalize_jcs(fixture.to_dict()) == canonicalize_jcs(literal)
    assert RegressionFixtureV1.from_dict(fixture.to_dict()) == fixture
    assert RegressionFixtureV1.canonical(SNAPSHOT_DIGEST) == fixture
    assert RegressionFixtureV1.SCHEMA == "smart_ads/regression_fixture/v1"
    assert set(fixture.to_dict()) == set(literal)


def test_fixture_carries_no_certification_transition_evidence_or_integrity() -> None:
    keys = set(RegressionFixtureV1.canonical(SNAPSHOT_DIGEST).to_dict())
    assert keys.isdisjoint(
        {"integrity", "certification_record", "certification_record_locator", "provider_evidence_locator"}
    )
    assert len(keys) == 10


def test_fixture_is_frozen_immutable_and_to_dict_returns_fresh_copies() -> None:
    fixture = RegressionFixtureV1.canonical(SNAPSHOT_DIGEST)
    with pytest.raises(dataclasses.FrozenInstanceError):
        fixture.fixture_id = "fixture:other"  # type: ignore[misc]
    assert isinstance(fixture.truth_vectors, tuple)
    exported = fixture.to_dict()
    exported["truth_vectors"][0]["canonical_leads"] = "65"
    exported["semantic_refs"]["canonical_leads"] = exported["semantic_refs"]["aggregate_conversions"]
    assert fixture.to_dict() == adr_fixture_dict()
    assert hash(fixture) == hash(RegressionFixtureV1.canonical(SNAPSHOT_DIGEST))


def test_constructor_accepts_a_list_of_vectors_and_stores_a_tuple() -> None:
    fixture = RegressionFixtureV1(
        fixture_id=FIXTURE_ID_65X23,
        fixture_role="regression_only",
        provider_provenance="synthetic",
        registry_transition="none",
        capability_promotion="none",
        before_registry_snapshot_digest=SNAPSHOT_DIGEST,
        after_registry_snapshot_digest=SNAPSHOT_DIGEST,
        truth_vectors=list(EXPECTED_TRUTH_VECTORS),  # type: ignore[arg-type]
        semantic_refs=FixtureSemanticRefs(AGGREGATE_CONVERSIONS_REF, CANONICAL_LEADS_REF),
    )
    assert fixture.truth_vectors == EXPECTED_TRUTH_VECTORS
    assert fixture == RegressionFixtureV1.canonical(SNAPSHOT_DIGEST)


def test_canonical_builder_validates_its_digest_argument() -> None:
    for bad in ("sha256:" + ("AB" * 32), "ab" * 32, "sha256:" + ("ab" * 31), None, 7):
        with pytest.raises(ClosedValidationError):
            RegressionFixtureV1.canonical(bad)  # type: ignore[arg-type]


def test_registry_digests_may_be_any_valid_digest_but_must_be_equal() -> None:
    for digest in (SNAPSHOT_DIGEST, OTHER_DIGEST, "sha256:" + ("0" * 64)):
        literal = adr_fixture_dict()
        literal["before_registry_snapshot_digest"] = digest
        literal["after_registry_snapshot_digest"] = digest
        assert RegressionFixtureV1.from_dict(literal).to_dict() == literal


Mutator = Callable[[dict[str, Any]], None]


def _set(path: str, value: Any) -> Mutator:
    def apply(data: dict[str, Any]) -> None:
        data[path] = value

    return apply


def _drop(path: str) -> Mutator:
    def apply(data: dict[str, Any]) -> None:
        del data[path]

    return apply


def _set_vector(index: int, member: str, value: Any) -> Mutator:
    def apply(data: dict[str, Any]) -> None:
        data["truth_vectors"][index][member] = value

    return apply


def _set_ref(member: str, value: Any) -> Mutator:
    def apply(data: dict[str, Any]) -> None:
        data["semantic_refs"][member] = value

    return apply


def _swap_vectors(first: int, second: int) -> Mutator:
    def apply(data: dict[str, Any]) -> None:
        vectors = data["truth_vectors"]
        vectors[first], vectors[second] = vectors[second], vectors[first]

    return apply


NEGATIVE_CASES: list[tuple[str, Mutator, str]] = [
    # --- closed object: every member is required, nothing else is allowed
    *[(f"missing-{key}", _drop(key), "closed object key mismatch") for key in adr_fixture_dict()],
    *[
        (f"extra-{key}", _set(key, "x"), "closed object key mismatch")
        for key in (
            "integrity",
            "certification_record",
            "certification_record_locator",
            "capability_state",
            "provider_evidence_locator",
            "live_execution",
            "unexpected",
        )
    ],
    # --- identity and role literals
    ("schema-v2", _set("$schema", "smart_ads/regression_fixture/v2"), r"regression_fixture\.\$schema"),
    ("schema-none", _set("$schema", None), r"regression_fixture\.\$schema"),
    ("fixture-id-v2", _set("fixture_id", "fixture:semantic-metric-65x23-v2"), "fixture_id"),
    ("fixture-id-other", _set("fixture_id", "fixture:other"), "fixture_id"),
    ("fixture-id-empty", _set("fixture_id", ""), "fixture_id"),
    ("role-live", _set("fixture_role", "live"), "fixture_role"),
    ("role-certification", _set("fixture_role", "certification"), "fixture_role"),
    ("role-padded", _set("fixture_role", "regression_only "), "fixture_role"),
    ("provenance-live", _set("provider_provenance", "live"), "provider_provenance"),
    ("provenance-provider", _set("provider_provenance", "provider"), "provider_provenance"),
    ("provenance-none", _set("provider_provenance", None), "provider_provenance"),
    # --- no registry transition and no capability promotion
    ("transition-promote", _set("registry_transition", "promote"), "registry_transition"),
    ("transition-null", _set("registry_transition", None), "registry_transition"),
    ("transition-capitalized", _set("registry_transition", "None"), "registry_transition"),
    ("transition-bool", _set("registry_transition", False), "registry_transition"),
    (
        "promotion-live-certified",
        _set("capability_promotion", "live_certified"),
        "capability_promotion",
    ),
    (
        "promotion-fixture-certified",
        _set("capability_promotion", "fixture_certified"),
        "capability_promotion",
    ),
    ("promotion-null", _set("capability_promotion", None), "capability_promotion"),
    # --- before/after registry snapshot digests must be equal and well formed
    (
        "digest-after-differs",
        _set("after_registry_snapshot_digest", OTHER_DIGEST),
        "registry_snapshot_digest",
    ),
    (
        "digest-before-differs",
        _set("before_registry_snapshot_digest", OTHER_DIGEST),
        "registry_snapshot_digest",
    ),
    (
        "digest-uppercase",
        lambda d: d.update(
            before_registry_snapshot_digest="sha256:" + "AB" * 32,
            after_registry_snapshot_digest="sha256:" + "AB" * 32,
        ),
        "registry_snapshot_digest",
    ),
    (
        "digest-no-prefix",
        lambda d: d.update(
            before_registry_snapshot_digest="ab" * 32, after_registry_snapshot_digest="ab" * 32
        ),
        "registry_snapshot_digest",
    ),
    (
        "digest-short",
        lambda d: d.update(
            before_registry_snapshot_digest="sha256:" + "ab" * 31,
            after_registry_snapshot_digest="sha256:" + "ab" * 31,
        ),
        "registry_snapshot_digest",
    ),
    ("digest-before-none", _set("before_registry_snapshot_digest", None), "registry_snapshot_digest"),
    ("digest-after-int", _set("after_registry_snapshot_digest", 7), "registry_snapshot_digest"),
    # --- exactly the three truth vectors, in order
    ("vectors-empty", _set("truth_vectors", []), "truth_vectors"),
    ("vectors-two", lambda d: d["truth_vectors"].pop(), "truth_vectors"),
    (
        "vectors-four",
        lambda d: d["truth_vectors"].append(copy.deepcopy(d["truth_vectors"][0])),
        "truth_vectors",
    ),
    ("vectors-swapped-0-1", _swap_vectors(0, 1), "truth_vectors"),
    ("vectors-swapped-1-2", _swap_vectors(1, 2), "truth_vectors"),
    ("vectors-reversed", lambda d: d["truth_vectors"].reverse(), "truth_vectors"),
    ("vectors-as-tuple", lambda d: d.update(truth_vectors=tuple(d["truth_vectors"])), "truth_vectors"),
    ("vectors-as-dict", _set("truth_vectors", {"0": {}}), "truth_vectors"),
    ("vectors-as-string", _set("truth_vectors", "65x23"), "truth_vectors"),
    ("vector-not-object", lambda d: d["truth_vectors"].__setitem__(0, ["65", "unknown"]), "truth_vector"),
    ("vector-extra-member", _set_vector(0, "extra", "1"), "truth_vector"),
    (
        "vector-missing-member",
        lambda d: d["truth_vectors"][1].pop("canonical_leads"),
        "truth_vector",
    ),
    # --- truth values: strings only, "unknown" or a canonical unsigned decimal count
    *[
        (f"value-{label}", _set_vector(0, "aggregate_conversions", bad), "truth_vector")
        for label, bad in (
            ("native-int", 65),
            ("bool", True),
            ("none", None),
            ("decimal", "65.0"),
            ("leading-zero", "065"),
            ("negative-zero", "-0"),
            ("negative", "-1"),
            ("plus-sign", "+65"),
            ("capitalized-unknown", "Unknown"),
            ("null-string", "null"),
            ("empty", ""),
            ("padded", " 65"),
            ("above-int64", "9223372036854775808"),
            ("exponent", "6.5e1"),
        )
    ],
    # --- the unknown value is never coerced to zero
    ("unknown-leads-coerced-to-zero", _set_vector(0, "canonical_leads", "0"), "truth_vectors"),
    ("both-unknown-coerced-to-zero", lambda d: d["truth_vectors"][2].update(
        aggregate_conversions="0", canonical_leads="0"), "alias or imputation"),
    ("unknown-conversions-coerced-to-zero", _set_vector(2, "aggregate_conversions", "0"), "truth_vectors"),
    # --- the two metrics are never aliases, fallbacks, or imputations
    ("leads-imputed-from-conversions", _set_vector(0, "canonical_leads", "65"), "alias or imputation"),
    ("conversions-imputed-from-leads", _set_vector(1, "aggregate_conversions", "23"), "alias or imputation"),
    ("vector-values-equal-zero", _set_vector(1, "canonical_leads", "0"), "alias or imputation"),
    ("refs-alias-conversions", _set_ref("canonical_leads", "metric:aggregate_conversions_v1"), "alias"),
    ("refs-alias-leads", _set_ref("aggregate_conversions", "metric:canonical_leads_v1"), "alias"),
    (
        "refs-swapped",
        lambda d: d["semantic_refs"].update(
            aggregate_conversions="metric:canonical_leads_v1",
            canonical_leads="metric:aggregate_conversions_v1",
        ),
        "semantic_refs",
    ),
    ("ref-wrong-version", _set_ref("canonical_leads", "metric:canonical_leads_v2"), "semantic_refs"),
    ("ref-other-metric", _set_ref("aggregate_conversions", "metric:clicks_v1"), "semantic_refs"),
    ("ref-none", _set_ref("aggregate_conversions", None), "semantic_refs"),
    ("ref-padded", _set_ref("canonical_leads", "metric:canonical_leads_v1 "), "semantic_refs"),
    ("refs-extra-member", _set_ref("fallback", "metric:clicks_v1"), "semantic_refs"),
    ("refs-missing-member", lambda d: d["semantic_refs"].pop("canonical_leads"), "semantic_refs"),
    ("refs-not-object", _set("semantic_refs", ["metric:aggregate_conversions_v1"]), "semantic_refs"),
]


@pytest.mark.parametrize(
    ("mutate", "needle"),
    [(mutate, needle) for _, mutate, needle in NEGATIVE_CASES],
    ids=[case_id for case_id, _, _ in NEGATIVE_CASES],
)
def test_65x23_negative_cases_reject(mutate: Mutator, needle: str) -> None:
    data = adr_fixture_dict()
    mutate(data)
    with pytest.raises(ClosedValidationError, match=needle):
        RegressionFixtureV1.from_dict(data)


def test_from_dict_rejects_non_mappings() -> None:
    for bad in (None, [], "fixture", 7, [adr_fixture_dict()]):
        with pytest.raises(ClosedValidationError):
            RegressionFixtureV1.from_dict(bad)


def test_constructor_rejects_the_same_violations_without_going_through_json() -> None:
    kwargs: dict[str, Any] = {
        "fixture_id": FIXTURE_ID_65X23,
        "fixture_role": "regression_only",
        "provider_provenance": "synthetic",
        "registry_transition": "none",
        "capability_promotion": "none",
        "before_registry_snapshot_digest": SNAPSHOT_DIGEST,
        "after_registry_snapshot_digest": SNAPSHOT_DIGEST,
        "truth_vectors": EXPECTED_TRUTH_VECTORS,
        "semantic_refs": FixtureSemanticRefs(AGGREGATE_CONVERSIONS_REF, CANONICAL_LEADS_REF),
    }
    assert RegressionFixtureV1(**kwargs) == RegressionFixtureV1.canonical(SNAPSHOT_DIGEST)
    bad_overrides: list[dict[str, Any]] = [
        {"registry_transition": "promote"},
        {"capability_promotion": "live_certified"},
        {"after_registry_snapshot_digest": OTHER_DIGEST},
        {"truth_vectors": EXPECTED_TRUTH_VECTORS[:2]},
        {"truth_vectors": tuple(reversed(EXPECTED_TRUTH_VECTORS))},
        {"truth_vectors": ({"aggregate_conversions": "65", "canonical_leads": "unknown"},) * 3},
        {"semantic_refs": None},
        {"semantic_refs": {"aggregate_conversions": AGGREGATE_CONVERSIONS_REF}},
        {"fixture_id": 65},
    ]
    for override in bad_overrides:
        with pytest.raises(ClosedValidationError):
            RegressionFixtureV1(**{**kwargs, **override})


@pytest.mark.parametrize(
    ("member", "pinned"),
    [
        ("fixture_id", FIXTURE_ID_65X23),
        ("fixture_role", "regression_only"),
        ("provider_provenance", "synthetic"),
        ("registry_transition", "none"),
        ("capability_promotion", "none"),
    ],
)
def test_pinned_members_reject_str_subclasses(member: str, pinned: str) -> None:
    kwargs = {
        "fixture_id": FIXTURE_ID_65X23,
        "fixture_role": "regression_only",
        "provider_provenance": "synthetic",
        "registry_transition": "none",
        "capability_promotion": "none",
        "before_registry_snapshot_digest": SNAPSHOT_DIGEST,
        "after_registry_snapshot_digest": SNAPSHOT_DIGEST,
        "truth_vectors": EXPECTED_TRUTH_VECTORS,
        "semantic_refs": FixtureSemanticRefs(AGGREGATE_CONVERSIONS_REF, CANONICAL_LEADS_REF),
    }
    wrapped = StrSubclass(pinned)
    assert wrapped == pinned and type(wrapped) is not str
    with pytest.raises(ClosedValidationError, match=member):
        RegressionFixtureV1(**{**kwargs, member: wrapped})


def test_truth_vector_and_semantic_refs_validate_on_their_own() -> None:
    assert TruthVector("65", "unknown").aggregate_conversions == "65"
    for bad in ((65, "unknown"), ("65", None), ("-1", "unknown"), ("unknown", "01"), ("", "unknown")):
        with pytest.raises(ClosedValidationError):
            TruthVector(*bad)  # type: ignore[arg-type]
    assert FixtureSemanticRefs(AGGREGATE_CONVERSIONS_REF, CANONICAL_LEADS_REF)
    with pytest.raises(ClosedValidationError, match="alias"):
        FixtureSemanticRefs(AGGREGATE_CONVERSIONS_REF, AGGREGATE_CONVERSIONS_REF)
    with pytest.raises(ClosedValidationError):
        FixtureSemanticRefs("aggregate_conversions", "canonical_leads")
