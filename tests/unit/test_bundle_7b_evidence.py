"""7B fact evidence selector, reconciliation sides, fact reconciliation, logical digest."""
from __future__ import annotations

import dataclasses
from typing import Any

import pytest

from smart_ads.contracts.jcs import canonicalize_jcs
from smart_ads.contracts.schemas import CollectionResult
from smart_ads.reconciliation import bundle_7b as b7
from smart_ads.reconciliation.bundle_7b import (
    Bundle7BDefectError,
    MetricPairKey,
    compute_canonical_fact_key_digest,
    compute_logical_fact_reconciliation_digest,
    compute_row_universe,
    expected_pair_universe,
)
from smart_ads.reconciliation.tolerance import ToleranceComparison
from tests.unit._bundle_7b_builders import (
    CANDIDATE_AT,
    CLICKS,
    EXACT_ROW,
    REFERENCE_AT,
    collection_result,
    facts_for,
    IMPRESSIONS,
    REF_A,
    REF_B,
    REF_C,
    SPEND,
    cand_result,  # noqa: F401 - pytest fixture
    code_of,
    fact,
    loc,
    oracle_domain_digest,
    oracle_result_locator,
    reconciliation_dict,
    ref_result,  # noqa: F401 - pytest fixture
    row_key,
    side_for,
)

SELECTOR_KEYS = (
    "collection_result_locator",
    "normalized_fact_set_digest",
    "reconciliation_row_key",
    "canonical_metric_ref",
    "fact_projection_digest",
)
SIDE_KEYS = (
    "source_metric_ref",
    "fact_evidence_selector",
    "presence_status",
    "value_type",
    "raw_numeric_value",
    "unit",
    "currency",
)
RECONCILIATION_KEYS = (
    "canonical_fact_key",
    "canonical_fact_key_digest",
    "canonical_metric_ref",
    "candidate",
    "reference",
    "tolerance_profile_locator",
    "measured_absolute_delta",
    "measured_relative_delta",
    "relative_delta_status",
    "reconciliation_outcome",
    "metric_verification_status",
)


def test_collection_result_locator_follows_the_repo_convention(
    cand_result: CollectionResult,
) -> None:
    assert b7.collection_result_locator(cand_result) == oracle_result_locator(cand_result)


def test_select_fact_evidence_builds_the_closed_selector(cand_result: CollectionResult) -> None:
    pair = MetricPairKey(row_key(REF_A), SPEND)
    selector = b7.select_fact_evidence(cand_result, pair)
    assert tuple(selector.to_dict()) == SELECTOR_KEYS
    target = fact(REF_A, SPEND, "50000")
    assert selector.to_dict() == {
        "collection_result_locator": oracle_result_locator(cand_result).to_dict(),
        "normalized_fact_set_digest": cand_result.normalized_fact_set_digest,
        "reconciliation_row_key": row_key(REF_A).to_dict(),
        "canonical_metric_ref": SPEND,
        "fact_projection_digest": oracle_domain_digest(
            "SMART-ADS:7B-FACT-PROJECTION:V1\n", target.to_dict()
        ),
    }
    assert b7.FactEvidenceSelector.from_dict(selector.to_dict()) == selector
    assert b7.resolve_fact_evidence(selector, cand_result) == target


def test_select_fact_evidence_rejects_a_non_addressable_pair(cand_result: CollectionResult) -> None:
    with pytest.raises(Bundle7BDefectError) as excinfo:
        b7.select_fact_evidence(cand_result, MetricPairKey(row_key(REF_C), SPEND))
    assert code_of(excinfo) == "evidence_not_addressable"


def test_selector_resolution_rejects_a_cross_result_container(
    cand_result: CollectionResult, ref_result: CollectionResult
) -> None:
    selector = b7.select_fact_evidence(cand_result, MetricPairKey(row_key(REF_A), CLICKS))
    with pytest.raises(Bundle7BDefectError) as excinfo:
        b7.resolve_fact_evidence(selector, ref_result)
    assert code_of(excinfo) == "evidence_container_mismatch"


@pytest.mark.parametrize(
    ("member", "value", "code"),
    [
        ("normalized_fact_set_digest", "sha256:" + "0" * 64, "normalized_fact_set_digest_mismatch"),
        ("reconciliation_row_key", row_key(REF_C).to_dict(), "evidence_not_addressable"),
        ("canonical_metric_ref", "metric:reach_v1", "evidence_not_addressable"),
        ("fact_projection_digest", "sha256:" + "0" * 64, "fact_projection_digest_mismatch"),
    ],
)
def test_selector_resolution_rejects_each_divergent_member(
    cand_result: CollectionResult, member: str, value: object, code: str
) -> None:
    selector = b7.select_fact_evidence(cand_result, MetricPairKey(row_key(REF_A), CLICKS))
    tampered = b7.FactEvidenceSelector.from_dict(dict(selector.to_dict(), **{member: value}))
    with pytest.raises(Bundle7BDefectError) as excinfo:
        b7.resolve_fact_evidence(tampered, cand_result)
    assert code_of(excinfo) == code


def test_selector_resolution_rejects_an_incomplete_result(cand_result: CollectionResult) -> None:
    selector = b7.select_fact_evidence(cand_result, MetricPairKey(row_key(REF_A), CLICKS))
    partial = dataclasses.replace(
        cand_result, candidates=(), normalized_fact_set=None, normalized_fact_set_digest=None
    )
    for call in (
        lambda: b7.resolve_fact_evidence(selector, partial),
        lambda: b7.select_fact_evidence(partial, MetricPairKey(row_key(REF_A), CLICKS)),
    ):
        with pytest.raises(Bundle7BDefectError) as excinfo:
            call()
        assert code_of(excinfo) == "collection_result_incomplete"


@pytest.mark.parametrize(
    ("patch", "code"),
    [
        ({"extra": "x"}, "closed_member_set"),
        ({"collection_result_locator": None}, "malformed_member"),
        (
            {"collection_result_locator": loc("smart_ads/admitted_collection/v1").to_dict()},
            "malformed_member",
        ),
        ({"normalized_fact_set_digest": "sha256:X"}, "malformed_member"),
        ({"reconciliation_row_key": {"resource_ref": REF_A}}, "malformed_member"),
        ({"canonical_metric_ref": "clicks"}, "malformed_member"),
        ({"fact_projection_digest": 3}, "malformed_member"),
    ],
)
def test_selector_from_dict_is_closed(
    cand_result: CollectionResult, patch: dict[str, Any], code: str
) -> None:
    selector = b7.select_fact_evidence(cand_result, MetricPairKey(row_key(REF_A), CLICKS))
    with pytest.raises(Bundle7BDefectError) as excinfo:
        b7.FactEvidenceSelector.from_dict(dict(selector.to_dict(), **patch))
    assert code_of(excinfo) == code


def test_reconciliation_side_copies_the_fact_value_fields(cand_result: CollectionResult) -> None:
    side = side_for(cand_result, MetricPairKey(row_key(REF_A), SPEND))
    assert tuple(side.to_dict()) == SIDE_KEYS
    assert side.to_dict()["source_metric_ref"] == "source-metric:provider:pipeboard.spend:v1"
    assert (side.value_type, side.raw_numeric_value, side.unit, side.currency) == (
        "int64_minor_currency", "50000", "minor_currency", "BRL"
    )
    assert b7.ReconciliationSide.from_dict(side.to_dict()) == side


@pytest.mark.parametrize(
    "patch",
    [
        {"source_metric_ref": "source-metric:formula:sha256:" + "a" * 64 + "x"},
        {"presence_status": "zero"},
        {"raw_numeric_value": None},
        {"unit": "count"},
        {"currency": None},
        {"raw_numeric_value": 50000},
    ],
)
def test_reconciliation_side_rejects_malformed_value_fields(
    cand_result: CollectionResult, patch: dict[str, Any]
) -> None:
    side = side_for(cand_result, MetricPairKey(row_key(REF_A), SPEND))
    with pytest.raises(Bundle7BDefectError) as excinfo:
        b7.ReconciliationSide.from_dict(dict(side.to_dict(), **patch))
    assert code_of(excinfo) == "malformed_member"


def test_fact_reconciliation_round_trips_with_the_adr_members(
    cand_result: CollectionResult, ref_result: CollectionResult
) -> None:
    data = reconciliation_dict(cand_result, ref_result, MetricPairKey(row_key(REF_A), CLICKS))
    rec = b7.FactReconciliation.from_dict(data)
    assert tuple(rec.to_dict()) == RECONCILIATION_KEYS
    assert rec.to_dict() == data
    assert rec.pair_key() == MetricPairKey(row_key(REF_A), CLICKS)
    assert rec.asserted_comparison == ToleranceComparison.from_dict(EXACT_ROW)


def test_fact_reconciliation_recomputes_the_canonical_fact_key_digest(
    cand_result: CollectionResult, ref_result: CollectionResult
) -> None:
    data = reconciliation_dict(cand_result, ref_result, MetricPairKey(row_key(REF_A), CLICKS))
    data["canonical_fact_key_digest"] = compute_canonical_fact_key_digest(row_key(REF_B))
    with pytest.raises(Bundle7BDefectError) as excinfo:
        b7.FactReconciliation.from_dict(data)
    assert code_of(excinfo) == "canonical_fact_key_digest_mismatch"


@pytest.mark.parametrize("side_name", ["candidate", "reference"])
def test_fact_reconciliation_rejects_a_selector_for_another_identity(
    cand_result: CollectionResult, ref_result: CollectionResult, side_name: str
) -> None:
    data = reconciliation_dict(cand_result, ref_result, MetricPairKey(row_key(REF_A), CLICKS))
    other = MetricPairKey(row_key(REF_A), IMPRESSIONS)
    result = cand_result if side_name == "candidate" else ref_result
    data[side_name] = side_for(result, other).to_dict()
    with pytest.raises(Bundle7BDefectError) as excinfo:
        b7.FactReconciliation.from_dict(data)
    assert code_of(excinfo) == "evidence_selector_mismatch"


@pytest.mark.parametrize(
    ("member", "value"),
    [
        ("measured_absolute_delta", "1"),
        ("measured_relative_delta", None),
        ("relative_delta_status", "reference_zero"),
        ("reconciliation_outcome", "within_declared_tolerance"),
        ("metric_verification_status", "UNRECONCILED"),
        ("metric_verification_status", "verified"),
    ],
)
def test_fact_reconciliation_rejects_an_illegal_asserted_row(
    cand_result: CollectionResult, ref_result: CollectionResult, member: str, value: object
) -> None:
    data = reconciliation_dict(cand_result, ref_result, MetricPairKey(row_key(REF_A), CLICKS))
    data[member] = value
    with pytest.raises(Bundle7BDefectError) as excinfo:
        b7.FactReconciliation.from_dict(data)
    assert code_of(excinfo) == "asserted_comparison_malformed"


@pytest.mark.parametrize(
    ("patch", "code"),
    [
        ({"extra": 1}, "closed_member_set"),
        ({"tolerance_profile_locator": loc("smart_ads/finding/v1").to_dict()}, "malformed_member"),
        ({"canonical_fact_key": {"resource_ref": REF_A}}, "malformed_member"),
        ({"canonical_metric_ref": "spend"}, "malformed_member"),
        ({"candidate": "x"}, "malformed_member"),
    ],
)
def test_fact_reconciliation_is_closed(
    cand_result: CollectionResult,
    ref_result: CollectionResult,
    patch: dict[str, Any],
    code: str,
) -> None:
    data = reconciliation_dict(cand_result, ref_result, MetricPairKey(row_key(REF_A), CLICKS))
    with pytest.raises(Bundle7BDefectError) as excinfo:
        b7.FactReconciliation.from_dict(dict(data, **patch))
    assert code_of(excinfo) == code


def _all_reconciliations(
    cand_result: CollectionResult, ref_result: CollectionResult
) -> list[b7.FactReconciliation]:
    rows = compute_row_universe(
        f.fact_key.reconciliation_row_key for f in cand_result.normalized_fact_set or ()
    )
    return [
        b7.FactReconciliation.from_dict(reconciliation_dict(cand_result, ref_result, pair))
        for pair in expected_pair_universe(rows)
    ]


def test_logical_digest_hashes_the_j_ordered_array(
    cand_result: CollectionResult, ref_result: CollectionResult
) -> None:
    recs = _all_reconciliations(cand_result, ref_result)
    expected = oracle_domain_digest(
        "SMART-ADS:7B-FACT-RECONCILIATIONS:V1\n", [rec.to_dict() for rec in recs]
    )
    assert compute_logical_fact_reconciliation_digest(recs) == expected


def test_logical_digest_requires_j_order_when_object_bytes_disagree() -> None:
    values = {(REF_A, IMPRESSIONS): "1", (REF_A, CLICKS): "2", (REF_A, SPEND): "3"}
    days = ("2026-11-09", "2026-11-10")
    cand = collection_result(
        [f for day in days for f in facts_for(values, metric_date=day)],
        side="candidate", retrieved_at=CANDIDATE_AT,
    )
    ref = collection_result(
        [f for day in days for f in facts_for(values, side="reference", metric_date=day)],
        side="reference", retrieved_at=REFERENCE_AT,
    )
    recs = _all_reconciliations(cand, ref)
    assert [r.canonical_fact_key.metric_date for r in recs] == [days[0]] * 3 + [days[1]] * 3
    by_object_bytes = sorted(recs, key=lambda r: canonicalize_jcs(r.to_dict()))
    assert by_object_bytes != recs
    assert compute_logical_fact_reconciliation_digest(recs) == oracle_domain_digest(
        "SMART-ADS:7B-FACT-RECONCILIATIONS:V1\n", [r.to_dict() for r in recs]
    )
    with pytest.raises(Bundle7BDefectError) as excinfo:
        compute_logical_fact_reconciliation_digest(by_object_bytes)
    assert code_of(excinfo) == "wrong_order"


def test_logical_digest_requires_canonical_unique_non_empty_order(
    cand_result: CollectionResult, ref_result: CollectionResult
) -> None:
    recs = _all_reconciliations(cand_result, ref_result)
    for bad, code in (
        ([recs[1], recs[0], *recs[2:]], "wrong_order"),
        ([recs[0], recs[0], *recs[1:]], "duplicate_identity"),
        ([], "malformed_argument"),
        ("x", "malformed_argument"),
        ([recs[0].to_dict()], "malformed_argument"),
    ):
        with pytest.raises(Bundle7BDefectError) as excinfo:
            compute_logical_fact_reconciliation_digest(bad)  # type: ignore[arg-type]
        assert code_of(excinfo) == code
