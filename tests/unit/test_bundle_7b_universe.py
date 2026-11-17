"""7B row universe U7, pair universe U7M and the four 7B data digests (ADR-0001 5.4).

Every defect asserts its closed ``code``, never the message. At least one
expected digest per 7B data prefix is written out by hand.
"""
from __future__ import annotations

import dataclasses
import hashlib
from typing import Any

import pytest

from smart_ads.contracts.jcs import canonicalize_jcs
from smart_ads.contracts.schemas import compute_fact_projection_digest
from smart_ads.reconciliation import bundle_7b as b7
from smart_ads.reconciliation import bundle_universe
from smart_ads.reconciliation.bundle_7b import (
    Bundle7BDefectError,
    MetricPairKey,
    compute_canonical_fact_key_digest,
    compute_pair_universe,
    compute_row_universe,
    compute_row_universe_digest,
    expected_pair_universe,
)
from tests.unit._bundle_7b_builders import (
    BASE_VALUES,
    CLICKS,
    DAY,
    IMPRESSIONS,
    REF_A,
    REF_B,
    SPEND,
    code_of,
    fact,
    facts_for,
    oracle_domain_digest,
    row_key,
)


def test_row_universe_is_sorted_by_the_k_array_not_by_object_bytes() -> None:
    # K(f) starts with resource_ref; RFC8785(C(f)) starts with breakdown_signature.
    first = row_key(REF_A, breakdown_signature="breakdown:z")
    second = row_key(REF_B, breakdown_signature="breakdown:a")
    assert canonicalize_jcs(second.to_dict()) < canonicalize_jcs(first.to_dict())
    assert compute_row_universe([second, first]) == (first, second)


def test_row_universe_orders_by_raw_bytes_of_each_k_member_in_turn() -> None:
    early = row_key(REF_A, metric_date="2026-11-09")
    late = row_key(REF_A, metric_date="2026-11-10")
    other = row_key(REF_B, metric_date="2026-11-01")
    assert compute_row_universe([other, late, early]) == (early, late, other)


def test_row_universe_collapses_a_duplicate_k_with_identical_bytes() -> None:
    rows = [row_key(REF_B), row_key(REF_A), row_key(REF_B), row_key(REF_A)]
    assert compute_row_universe(rows) == (row_key(REF_A), row_key(REF_B))


def test_row_universe_accepts_closed_raw_objects_and_collapses_them() -> None:
    raw = row_key(REF_A).to_dict()
    assert compute_row_universe([raw, dict(raw), row_key(REF_A)]) == (row_key(REF_A),)


def test_row_universe_rejects_conflicting_c_bytes_for_one_k() -> None:
    raw = row_key(REF_A).to_dict()
    conflicting = dict(raw, extra_member="x")
    with pytest.raises(Bundle7BDefectError) as excinfo:
        compute_row_universe([raw, conflicting])
    assert code_of(excinfo) == "row_universe_conflict"


def test_row_universe_rejects_a_non_closed_single_object() -> None:
    raw = dict(row_key(REF_A).to_dict(), extra_member="x")
    with pytest.raises(Bundle7BDefectError) as excinfo:
        compute_row_universe([raw])
    assert code_of(excinfo) == "malformed_member"


@pytest.mark.parametrize("bad", ["not-a-collection", 7, None, [3], [{"resource_ref": 1}]])
def test_row_universe_rejects_wrongly_typed_input(bad: object) -> None:
    with pytest.raises(Bundle7BDefectError) as excinfo:
        compute_row_universe(bad)  # type: ignore[arg-type]
    assert code_of(excinfo) in {"malformed_argument", "malformed_member"}


def test_row_universe_digest_matches_a_hand_written_preimage() -> None:
    universe = compute_row_universe([row_key(REF_A)])
    literal = (
        '[{"breakdown_signature":"breakdown:none","metric_date":"2026-11-10",'
        '"resource_level":"campaign","resource_ref":"' + REF_A + '"}]'
    ).encode("utf-8")
    expected = "sha256:" + hashlib.sha256(
        b"SMART-ADS:7B-ROW-UNIVERSE:V1\n" + b"\x00" + literal
    ).hexdigest()
    assert compute_row_universe_digest(universe) == expected


def test_row_universe_digest_covers_the_whole_sorted_array() -> None:
    universe = compute_row_universe([row_key(REF_B), row_key(REF_A)])
    expected = oracle_domain_digest(
        "SMART-ADS:7B-ROW-UNIVERSE:V1\n", [row.to_dict() for row in universe]
    )
    assert compute_row_universe_digest(universe) == expected


def test_row_universe_digest_rejects_unsorted_or_duplicate_or_empty_input() -> None:
    for bad, code in (
        ((row_key(REF_B), row_key(REF_A)), "wrong_order"),
        ((row_key(REF_A), row_key(REF_A)), "duplicate_identity"),
        ((), "malformed_argument"),
    ):
        with pytest.raises(Bundle7BDefectError) as excinfo:
            compute_row_universe_digest(bad)
        assert code_of(excinfo) == code


def test_row_universe_digest_requires_k_order_when_object_bytes_disagree() -> None:
    # Same resource; metric_date decides K order, breakdown_signature decides object bytes.
    later = row_key(REF_A, metric_date="2026-11-10", breakdown_signature="breakdown:a")
    earlier = row_key(REF_A, metric_date="2026-11-09", breakdown_signature="breakdown:z")
    assert canonicalize_jcs(later.to_dict()) < canonicalize_jcs(earlier.to_dict())
    assert compute_row_universe([later, earlier]) == (earlier, later)
    expected = oracle_domain_digest(
        "SMART-ADS:7B-ROW-UNIVERSE:V1\n", [earlier.to_dict(), later.to_dict()]
    )
    assert compute_row_universe_digest((earlier, later)) == expected
    with pytest.raises(Bundle7BDefectError) as excinfo:
        compute_row_universe_digest((later, earlier))
    assert code_of(excinfo) == "wrong_order"


def test_pair_universe_is_sorted_by_kfive_and_keeps_distinct_metrics() -> None:
    pairs = compute_pair_universe(facts_for(BASE_VALUES))
    assert len(pairs) == 6
    assert [(p.canonical_fact_key.resource_ref, p.canonical_metric_ref) for p in pairs] == [
        (REF_A, CLICKS),
        (REF_A, IMPRESSIONS),
        (REF_A, SPEND),
        (REF_B, CLICKS),
        (REF_B, IMPRESSIONS),
        (REF_B, SPEND),
    ]
    assert pairs[0].to_dict() == {
        "canonical_fact_key": row_key(REF_A).to_dict(),
        "canonical_metric_ref": CLICKS,
    }


def test_pair_universe_collapses_duplicate_kfive_and_rejects_conflicts() -> None:
    entries = facts_for(BASE_VALUES)
    assert compute_pair_universe(entries + entries[:2]) == compute_pair_universe(entries)
    raw = MetricPairKey(row_key(REF_A), CLICKS).to_dict()
    conflicting = dict(raw, extra_member="x")
    with pytest.raises(Bundle7BDefectError) as excinfo:
        compute_pair_universe([raw, conflicting])
    assert code_of(excinfo) == "pair_universe_conflict"


def test_pair_universe_equals_the_required_metric_cross_product() -> None:
    facts = facts_for(BASE_VALUES)
    rows = compute_row_universe(f.fact_key.reconciliation_row_key for f in facts)
    assert compute_pair_universe(facts) == expected_pair_universe(rows)
    assert len(expected_pair_universe(rows)) == len(rows) * len(b7.REQUIRED_7B_METRICS)


def test_pair_universe_missing_pair_differs_from_the_cross_product() -> None:
    facts = [f for f in facts_for(BASE_VALUES) if f.fact_key.set_identity_array()[4] != SPEND
             or f.fact_key.resource_ref != REF_B]
    rows = compute_row_universe(f.fact_key.reconciliation_row_key for f in facts)
    assert len(rows) == 2
    assert compute_pair_universe(facts) != expected_pair_universe(rows)


def test_pair_universe_extra_metric_differs_from_the_cross_product() -> None:
    facts = facts_for(BASE_VALUES) + [fact(REF_A, "metric:reach_v1", "7")]
    rows = compute_row_universe(f.fact_key.reconciliation_row_key for f in facts)
    assert compute_pair_universe(facts) != expected_pair_universe(rows)


def test_required_metrics_are_the_exact_adr_set_in_record_order() -> None:
    assert b7.REQUIRED_7B_METRICS == (IMPRESSIONS, CLICKS, SPEND)
    assert b7.MAXIMUM_RETRIEVAL_SKEW_SECONDS == 300


def test_canonical_fact_key_digest_matches_a_hand_written_preimage() -> None:
    literal = (
        '{"breakdown_signature":"breakdown:none","metric_date":"2026-11-10",'
        '"resource_level":"campaign","resource_ref":"' + REF_B + '"}'
    ).encode("utf-8")
    expected = "sha256:" + hashlib.sha256(
        b"SMART-ADS:7B-CANONICAL-FACT-KEY:V1\n\x00" + literal
    ).hexdigest()
    assert compute_canonical_fact_key_digest(row_key(REF_B)) == expected


def test_fact_projection_digest_uses_the_complete_normalized_fact() -> None:
    sample = fact(REF_A, SPEND, "50000")
    expected = oracle_domain_digest("SMART-ADS:7B-FACT-PROJECTION:V1\n", sample.to_dict())
    assert compute_fact_projection_digest(sample) == expected
    assert set(sample.to_dict()) == {
        "fact_key", "presence_status", "value_type", "raw_numeric_value", "unit", "currency"
    }


def test_digest_helpers_reject_wrongly_typed_arguments() -> None:
    for call in (
        lambda: compute_canonical_fact_key_digest(row_key().to_dict()),  # type: ignore[arg-type]
        lambda: compute_row_universe_digest([row_key().to_dict()]),  # type: ignore[list-item]
        lambda: expected_pair_universe([1]),  # type: ignore[list-item]
        lambda: compute_pair_universe([1]),  # type: ignore[list-item]
        lambda: MetricPairKey(row_key().to_dict(), CLICKS),  # type: ignore[arg-type]
    ):
        with pytest.raises(Bundle7BDefectError) as excinfo:
            call()
        assert code_of(excinfo) == "malformed_argument"


@pytest.mark.parametrize("name", ["rows", "pairs"])
@pytest.mark.parametrize("shape", [list, iter])
def test_side_universe_members_must_be_tuples(name: str, shape: Any) -> None:
    side = bundle_universe.SideUniverse.of(facts_for(BASE_VALUES))
    assert hash(side) == hash(bundle_universe.SideUniverse.of(facts_for(BASE_VALUES)))
    with pytest.raises(Bundle7BDefectError) as excinfo:
        dataclasses.replace(side, **{name: shape(getattr(side, name))})
    assert code_of(excinfo) == "malformed_member"


def test_side_universe_entries_must_have_the_right_type() -> None:
    side = bundle_universe.SideUniverse.of(facts_for(BASE_VALUES))
    for changes in ({"rows": (row_key().to_dict(),)}, {"pairs": (row_key(),)}):
        with pytest.raises(Bundle7BDefectError) as excinfo:
            dataclasses.replace(side, **changes)
        assert code_of(excinfo) == "malformed_member"


def test_metric_pair_key_round_trips_and_rejects_bad_grammar() -> None:
    pair = MetricPairKey(row_key(REF_A), SPEND)
    assert MetricPairKey.from_dict(pair.to_dict()) == pair
    assert pair.kfive() == [REF_A, DAY, "campaign", "breakdown:none", SPEND]
    for bad, code in (
        (dict(pair.to_dict(), canonical_metric_ref="clicks"), "malformed_member"),
        (dict(pair.to_dict(), extra="x"), "closed_member_set"),
        ({"canonical_fact_key": pair.to_dict()["canonical_fact_key"]}, "closed_member_set"),
        ({1: "x"}, "malformed_member"),
        ("pair", "malformed_member"),
    ):
        with pytest.raises(Bundle7BDefectError) as excinfo:
            MetricPairKey.from_dict(bad)
        assert code_of(excinfo) == code
