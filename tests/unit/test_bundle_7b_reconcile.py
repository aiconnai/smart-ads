"""``reconcile_7b_fact_sets``: failed comparisons are values, malformed evidence raises."""
from __future__ import annotations

import dataclasses
from typing import Any

import pytest

from smart_ads.reconciliation import bundle_7b as b7
from smart_ads.reconciliation.bundle_7b import (
    Bundle7BDefectError,
    MetricPairKey,
    expected_pair_universe,
)
from tests.unit._bundle_7b_builders import (
    BASE_VALUES,
    CANDIDATE_VALUES,
    CLICKS,
    GATE3_LOC,
    IMPRESSIONS,
    REF_A,
    REF_B,
    REF_C,
    SPEND,
    WITHIN_TOLERANCE_ROW,
    code_of,
    default_profiles,
    fact,
    facts_for,
    loc,
    oracle_domain_digest,
    oracle_profile_locator,
    oracle_result_locator,
    profile_dict,
    reconcile,
    results,
    row_key,
    sha,
)

COMPARISON_KEYS = (
    "measured_absolute_delta",
    "measured_relative_delta",
    "relative_delta_status",
    "reconciliation_outcome",
    "metric_verification_status",
)


def test_reconcile_verifies_a_complete_matching_bundle() -> None:
    cand, ref = results()
    result = reconcile(cand, ref)
    assert result.bundle_outcome == "verified"
    assert result.defect_codes == ()
    pairs = [rec.pair_key() for rec in result.fact_reconciliations]
    assert pairs == list(expected_pair_universe([row_key(REF_A), row_key(REF_B)]))
    assert result.candidate_row_count == result.reference_row_count == 6
    universe = [row_key(REF_A).to_dict(), row_key(REF_B).to_dict()]
    expected_u7 = oracle_domain_digest("SMART-ADS:7B-ROW-UNIVERSE:V1\n", universe)
    assert result.candidate_row_universe_digest == expected_u7
    assert result.reference_row_universe_digest == expected_u7
    assert result.logical_fact_reconciliation_digest == oracle_domain_digest(
        "SMART-ADS:7B-FACT-RECONCILIATIONS:V1\n",
        [rec.to_dict() for rec in result.fact_reconciliations],
    )


def test_reconcile_builds_each_member_from_the_resolved_evidence() -> None:
    cand, ref = results()
    result = reconcile(cand, ref)
    clicks = result.fact_reconciliations[0]
    assert clicks.pair_key() == MetricPairKey(row_key(REF_A), CLICKS)
    data = clicks.to_dict()
    assert {k: data[k] for k in COMPARISON_KEYS} == WITHIN_TOLERANCE_ROW
    assert data["tolerance_profile_locator"] == (
        oracle_profile_locator(default_profiles()[CLICKS]).to_dict()
    )
    assert data["candidate"]["raw_numeric_value"] == "101"
    assert data["reference"]["raw_numeric_value"] == "100"
    assert data["candidate"]["fact_evidence_selector"]["collection_result_locator"] == (
        oracle_result_locator(cand).to_dict()
    )
    assert data["reference"]["fact_evidence_selector"]["collection_result_locator"] == (
        oracle_result_locator(ref).to_dict()
    )
    zero_ref = result.fact_reconciliations[3].to_dict()
    assert {k: zero_ref[k] for k in COMPARISON_KEYS} == {
        "measured_absolute_delta": "0",
        "measured_relative_delta": None,
        "relative_delta_status": "reference_zero",
        "reconciliation_outcome": "exact_match",
        "metric_verification_status": "VERIFIED",
    }


def test_reconcile_returns_a_mismatch_as_a_value() -> None:
    cand, ref = results({**CANDIDATE_VALUES, (REF_A, SPEND): "60000"})
    result = reconcile(cand, ref)
    assert result.bundle_outcome == "failed"
    assert result.defect_codes == ("metric_unreconciled",)
    spend = result.fact_reconciliations[2]
    assert spend.metric_verification_status == "UNRECONCILED"
    assert spend.reconciliation_outcome == "mismatch"


def test_reconcile_returns_unavailable_and_blocked_comparisons_as_values() -> None:
    cand_facts = facts_for(CANDIDATE_VALUES)
    ref_facts = [
        fact(REF_A, IMPRESSIONS, None, side="reference", presence_status="retracted_tombstone")
        if (ref, metric) == (REF_A, IMPRESSIONS)
        else fact(ref, SPEND, raw, side="reference", currency="USD")
        if metric == SPEND
        else fact(ref, metric, raw, side="reference")
        for (ref, metric), raw in BASE_VALUES.items()
    ]
    cand, ref = results(cand_facts=cand_facts, ref_facts=ref_facts)
    result = reconcile(cand, ref)
    assert result.bundle_outcome == "failed"
    assert result.defect_codes == ("metric_blocked", "metric_unavailable")
    statuses = {r.pair_key().kfive()[0] + r.canonical_metric_ref: r.metric_verification_status
                for r in result.fact_reconciliations}
    assert statuses[REF_A + IMPRESSIONS] == "UNAVAILABLE"
    assert statuses[REF_A + SPEND] == statuses[REF_B + SPEND] == "BLOCKED"


def test_reconcile_reports_a_missing_pair_on_one_side() -> None:
    ref_values = {k: v for k, v in BASE_VALUES.items() if k != (REF_B, SPEND)}
    cand, ref = results(ref_values=ref_values)
    result = reconcile(cand, ref)
    assert result.bundle_outcome == "failed"
    assert result.defect_codes == ("pair_universe_incomplete", "pair_universe_mismatch")
    assert len(result.fact_reconciliations) == 5
    assert result.reference_row_count == 5


def test_reconcile_reports_an_extra_metric_on_one_side() -> None:
    cand_facts = facts_for(CANDIDATE_VALUES) + [fact(REF_A, "metric:reach_v1", "9")]
    cand, ref = results(cand_facts=cand_facts)
    result = reconcile(cand, ref)
    assert result.defect_codes == ("pair_universe_incomplete", "pair_universe_mismatch")
    assert len(result.fact_reconciliations) == 6


def test_reconcile_reports_a_row_present_on_one_side_only() -> None:
    extra = {(REF_C, IMPRESSIONS): "1", (REF_C, CLICKS): "1", (REF_C, SPEND): "1"}
    cand, ref = results({**CANDIDATE_VALUES, **extra})
    result = reconcile(cand, ref)
    assert result.defect_codes == ("pair_universe_mismatch", "row_universe_mismatch")
    assert result.candidate_row_count == 9 and result.reference_row_count == 6
    assert result.candidate_row_universe_digest != result.reference_row_universe_digest


@pytest.mark.parametrize(
    ("ref_at", "codes"),
    [
        ("2026-11-11T04:20:00.000000Z", ()),
        ("2026-11-11T04:10:00.000000Z", ()),
        ("2026-11-11T04:20:00.000001Z", ("retrieval_skew_exceeded",)),
        ("2026-11-11T04:20:01.000000Z", ("retrieval_skew_exceeded",)),
        ("2026-11-11T04:09:59.000000Z", ("retrieval_skew_exceeded",)),
    ],
)
def test_reconcile_allows_exactly_300_seconds_of_retrieval_skew(
    ref_at: str, codes: tuple[str, ...]
) -> None:
    cand, ref = results(ref_at=ref_at)
    assert reconcile(cand, ref).defect_codes == codes


def test_reconcile_rejects_incomplete_or_wrong_side_results() -> None:
    cand, ref = results()
    partial = dataclasses.replace(
        cand, candidates=(), normalized_fact_set=None, normalized_fact_set_digest=None
    )
    for args, code in (
        ((partial, ref), "collection_result_incomplete"),
        ((ref, cand), "collection_result_mismatch"),
        ((cand, cand), "collection_result_mismatch"),
        ((cand.to_dict(), ref), "malformed_argument"),
    ):
        with pytest.raises(Bundle7BDefectError) as excinfo:
            reconcile(*args)  # type: ignore[arg-type]
        assert code_of(excinfo) == code


def test_reconcile_requires_one_signed_profile_per_required_metric() -> None:
    cand, ref = results()
    loose_unsigned = profile_dict(CLICKS, max_abs="5", max_rel="0.050000", signed=False)
    for profiles, code in (
        ({k: v for k, v in default_profiles().items() if k != SPEND},
         "tolerance_profile_unresolved"),
        (dict(default_profiles(), **{"metric:reach_v1": profile_dict(CLICKS)}),
         "tolerance_profile_unresolved"),
        (dict(default_profiles(), **{SPEND: profile_dict(IMPRESSIONS)}),
         "tolerance_profile_metric_mismatch"),
        (dict(default_profiles(), **{CLICKS: loose_unsigned}), "tolerance_profile_unsigned"),
        (dict(default_profiles(), **{SPEND: profile_dict(SPEND, signed=False)}),
         "tolerance_profile_unsigned"),
        (dict(default_profiles(), **{SPEND: dict(profile_dict(SPEND), decimal_scale=2)}),
         "tolerance_profile_malformed"),
        ([], "malformed_argument"),
    ):
        with pytest.raises(Bundle7BDefectError) as excinfo:
            reconcile(cand, ref, profiles)  # type: ignore[arg-type]
        assert code_of(excinfo) == code


@pytest.mark.parametrize(
    "binding",
    [
        {"query_digest": sha("e")},
        {"scope": "scope:other-scope"},
        {"run": loc("smart_ads/migration_run_context/v1", "e")},
        {"gate3": loc("smart_ads/gate3_selection_receipt/v1", "e")},
    ],
)
def test_reconcile_rejects_a_non_zero_profile_bound_elsewhere(binding: dict[str, Any]) -> None:
    cand, ref = results()
    rebound = profile_dict(CLICKS, max_abs="5", max_rel="0.050000", **binding)
    with pytest.raises(Bundle7BDefectError) as excinfo:
        reconcile(cand, ref, dict(default_profiles(), **{CLICKS: rebound}))
    assert code_of(excinfo) == "tolerance_profile_unbound"


def test_reconcile_rejects_malformed_binding_arguments() -> None:
    cand, ref = results()
    for name, bad in (
        ("canonical_query_digest", "sha256:X"),
        ("authorized_certification_scope", "campaigns"),
        ("gate3_selection_locator", GATE3_LOC.to_dict()),
        ("migration_run_context_locator", None),
    ):
        with pytest.raises(Bundle7BDefectError) as excinfo:
            reconcile(cand, ref, **{name: bad})
        assert code_of(excinfo) == "malformed_argument"


def test_reconcile_result_is_immutable_and_its_codes_are_closed() -> None:
    cand, ref = results()
    result = reconcile(cand, ref)
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.bundle_outcome = "failed"  # type: ignore[misc]
    assert set(b7.RECONCILE_OUTCOME_CODES) <= b7.DEFECT_CODES
