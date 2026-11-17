"""Unit tests for smart_ads.reconciliation.bundle_7b (ADR-0001 section 5.4).

Every defect asserts its closed ``code``, never the message. Expected digests are
recomputed here with ``hashlib`` over the documented preimage (at least one per
7B data prefix written out by hand), never with the helper under test.
"""
from __future__ import annotations

import base64
import copy
import dataclasses
import hashlib
import json
from collections.abc import Callable, Iterator
from typing import Any

import pytest

from smart_ads.contracts.jcs import (
    ArtifactLocator,
    P1Integrity,
    canonicalize_jcs,
    p1_content_digest,
)
from smart_ads.contracts.scalars import ClosedValidationError
from smart_ads.contracts.schemas import (
    AdmittedCollection,
    CanonicalQueryContract,
    CollectionResult,
    DateRange,
    FactKey,
    NormalizedCollectionFact,
    PurposePrerequisiteLocators,
    ReconciliationRowKey,
    RetrievalContext,
    TransportOutcome,
    compute_fact_projection_digest,
    compute_normalized_fact_set_digest,
    project_collection_fact_to_landing_row,
)
from smart_ads.domain.pipeboard_contract import (
    FORBIDDEN_PIPEBOARD_ARGUMENTS,
    PINNED_LEGACY_COMMIT,
    PINNED_LEGACY_REPO,
    PINNED_PIPEBOARD_D26_SPECS,
    PIPEBOARD_PHASE1_METRIC_SOURCE_MAPPINGS,
    LegacySourcePacket,
    PinnedGitArtifactMember,
    PinnedUpstreamReference,
    PipeboardPhase1Contract,
    PipeboardTransportLimits,
)
from smart_ads.ports.cell_runtime import ResolvedGate3SelectionState
from smart_ads.reconciliation import bundle_7b as b7
from smart_ads.reconciliation.bundle_7b import (
    Bundle7BDefectError,
    MetricPairKey,
    compute_canonical_fact_key_digest,
    compute_logical_fact_reconciliation_digest,
    compute_pair_universe,
    compute_row_universe,
    compute_row_universe_digest,
    expected_pair_universe,
)
from smart_ads.reconciliation.tolerance import ToleranceComparison

IMPRESSIONS = "metric:impressions_v1"
CLICKS = "metric:clicks_v1"
SPEND = "metric:spend_v1"
REF_A = "resource:" + ("a" * 51) + "a"
REF_B = "resource:" + ("b" * 51) + "a"
REF_C = "resource:" + ("c" * 51) + "a"
DAY = "2026-11-10"
KEY_ID = "key:ed25519:" + ("a" * 64)


# ---------------------------------------------------------------------------
# Independent oracles (never the helpers under test)
# ---------------------------------------------------------------------------


def oracle_jcs(value: object) -> bytes:
    """RFC 8785 for the ASCII-only, string-and-null documents used in these tests."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def oracle_domain_digest(prefix: str, value: object) -> str:
    payload = prefix.encode("utf-8") + b"\x00" + oracle_jcs(value)
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def code_of(excinfo: pytest.ExceptionInfo[BaseException]) -> str:
    error = excinfo.value
    assert isinstance(error, Bundle7BDefectError)
    assert error.code in b7.DEFECT_CODES
    return error.code


# ---------------------------------------------------------------------------
# Small builders
# ---------------------------------------------------------------------------


def _loc(artifact_type: str, fill: str = "a") -> ArtifactLocator:
    return ArtifactLocator.from_digest(artifact_type, "sha256:" + (fill * 64))


def row_key(
    resource_ref: str = REF_A,
    *,
    metric_date: str = DAY,
    breakdown_signature: str = "breakdown:none",
) -> ReconciliationRowKey:
    return ReconciliationRowKey(
        resource_ref=resource_ref,
        metric_date=metric_date,
        resource_level="campaign",
        breakdown_signature=breakdown_signature,
    )


_SOURCES = {
    "candidate": "pipeboard",
    "reference": "meta",
}


def fact(
    resource_ref: str,
    metric: str,
    raw: str | None,
    *,
    side: str = "candidate",
    presence_status: str = "observed",
    metric_date: str = DAY,
    currency: str = "BRL",
) -> NormalizedCollectionFact:
    short = metric.split(":", 1)[1].rsplit("_", 1)[0]
    source = f"source-metric:provider:{_SOURCES[side]}.{short}:v1"
    is_money = metric == SPEND
    observed = presence_status == "observed"
    return NormalizedCollectionFact(
        fact_key=FactKey(
            binding_ref="binding:meta-primary",
            account_ref="account:ibvi-01",
            resource_ref=resource_ref,
            resource_level="campaign",
            metric_date=metric_date,
            metric_semantic_ref=metric,
            source_metric_ref=source,
            attribution_ref="attribution:not_applicable",
            breakdown_signature="breakdown:none",
        ),
        presence_status=presence_status,  # type: ignore[arg-type]
        value_type=(("int64_minor_currency" if is_money else "int64_count") if observed else None),
        raw_numeric_value=raw if observed else None,
        unit=(("minor_currency" if is_money else "count") if observed else None),
        currency=(currency if is_money and observed else None),
    )


def facts_for(
    values: dict[tuple[str, str], str],
    *,
    side: str = "candidate",
) -> list[NormalizedCollectionFact]:
    return [fact(ref, metric, raw, side=side) for (ref, metric), raw in values.items()]


BASE_VALUES: dict[tuple[str, str], str] = {
    (REF_A, IMPRESSIONS): "1000",
    (REF_A, CLICKS): "100",
    (REF_A, SPEND): "50000",
    (REF_B, IMPRESSIONS): "0",
    (REF_B, CLICKS): "0",
    (REF_B, SPEND): "0",
}


# ===========================================================================
# Slice 1 - row universe U7, pair universe U7M and the four 7B data digests
# ===========================================================================


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


# ===========================================================================
# Slice 2 - Gate-3 certification fingerprint
# ===========================================================================

FINGERPRINT_MEMBERS = (
    "selected_meta_api_version",
    "reference_client_identity_digest",
    "official_source_locators_digest",
    "candidate_driver_contract_digest",
    "canonical_query_digest",
    "parser_code_digest",
    "adapter_code_digest",
    "mapping_rules_digest",
    "schema_bundle_digest",
    "resource_mapping_contract_digest",
    "authorized_certification_scope",
)


def _sha(fill: str) -> str:
    return "sha256:" + (fill * 64)


def fingerprint_dict(**overrides: str) -> dict[str, str]:
    base = {
        "selected_meta_api_version": "v21.0",
        "reference_client_identity_digest": _sha("1"),
        "official_source_locators_digest": _sha("2"),
        "candidate_driver_contract_digest": _sha("3"),
        "canonical_query_digest": _sha("4"),
        "parser_code_digest": _sha("5"),
        "adapter_code_digest": _sha("6"),
        "mapping_rules_digest": _sha("7"),
        "schema_bundle_digest": _sha("8"),
        "resource_mapping_contract_digest": _sha("9"),
        "authorized_certification_scope": "scope:campaigns-active",
    }
    base.update(overrides)
    return base


def _different_value(member: str, value: str) -> str:
    if member == "selected_meta_api_version":
        return "v22.0"
    if member == "authorized_certification_scope":
        return "scope:other-scope"
    return _sha("f") if value != _sha("f") else _sha("e")


def test_fingerprint_has_exactly_the_eleven_adr_members() -> None:
    fp = b7.Gate3CertificationFingerprint.from_dict(fingerprint_dict())
    assert tuple(fp.to_dict()) == FINGERPRINT_MEMBERS
    assert b7.Gate3CertificationFingerprint.from_dict(fp.to_dict()) == fp


@pytest.mark.parametrize("member", FINGERPRINT_MEMBERS)
def test_fingerprint_rejects_a_missing_member(member: str) -> None:
    data = fingerprint_dict()
    del data[member]
    with pytest.raises(Bundle7BDefectError) as excinfo:
        b7.Gate3CertificationFingerprint.from_dict(data)
    assert code_of(excinfo) == "closed_member_set"


def test_fingerprint_rejects_an_extra_member() -> None:
    with pytest.raises(Bundle7BDefectError) as excinfo:
        b7.Gate3CertificationFingerprint.from_dict(dict(fingerprint_dict(), extra=_sha("0")))
    assert code_of(excinfo) == "closed_member_set"


@pytest.mark.parametrize("member", FINGERPRINT_MEMBERS)
@pytest.mark.parametrize("bad", ["", "sha256:ABC", None, 7, "has space"])
def test_fingerprint_rejects_blank_or_malformed_members(member: str, bad: object) -> None:
    with pytest.raises(Bundle7BDefectError) as excinfo:
        b7.Gate3CertificationFingerprint.from_dict(dict(fingerprint_dict(), **{member: bad}))
    assert code_of(excinfo) == "malformed_member"


@pytest.mark.parametrize("member", FINGERPRINT_MEMBERS)
def test_fingerprint_equality_fails_on_any_single_member(member: str) -> None:
    base = b7.Gate3CertificationFingerprint.from_dict(fingerprint_dict())
    changed = b7.Gate3CertificationFingerprint.from_dict(
        fingerprint_dict(**{member: _different_value(member, fingerprint_dict()[member])})
    )
    b7.require_same_fingerprint(base, base, label="same")
    with pytest.raises(Bundle7BDefectError) as excinfo:
        b7.require_same_fingerprint(base, changed, label="different")
    assert code_of(excinfo) == "fingerprint_mismatch"


def test_fingerprint_comparison_rejects_wrong_types() -> None:
    fp = b7.Gate3CertificationFingerprint.from_dict(fingerprint_dict())
    with pytest.raises(Bundle7BDefectError) as excinfo:
        b7.require_same_fingerprint(fp, fingerprint_dict(), label="x")  # type: ignore[arg-type]
    assert code_of(excinfo) == "malformed_argument"


# ===========================================================================
# Slice 3 - fact evidence selector, reconciliation sides, fact reconciliation
# ===========================================================================

CANDIDATE_AT = "2026-11-11T04:15:00.000000Z"
REFERENCE_AT = "2026-11-11T04:17:30.000000Z"
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
COMPARISON_KEYS = RECONCILIATION_KEYS[6:]


def transport_ok() -> TransportOutcome:
    return TransportOutcome(
        network_ok=True,
        http_status=200,
        media_and_encoding_valid=True,
        auth_ok=True,
        jsonrpc_error=False,
        payload_schema_valid=True,
        response_date_mismatch=False,
        truncated_2mib=False,
        non_empty_continuation=False,
        reducer_order_or_count_mismatch=False,
        duplicate_provider_observation=False,
    )


def collection_result(
    facts: list[NormalizedCollectionFact],
    *,
    side: str,
    retrieved_at: str,
    admitted_locator: ArtifactLocator | None = None,
    registry_locator: ArtifactLocator | None = None,
) -> CollectionResult:
    adm = admitted_locator or _loc("smart_ads/admitted_collection/v1", "c")
    reg = registry_locator or _loc("smart_ads/private_registry_snapshot/v1", "d")
    ctx = RetrievalContext(
        retrieved_at_utc=retrieved_at,
        source_observation_ref=f"observation:{side}-001",
        adapter_version=f"{side}-adapter-1.0.0",
        semantic_version="smart-ads-semantic-1.0.0",
    )
    sorted_facts, digest = compute_normalized_fact_set_digest(facts)
    query_currency = next(
        (f.currency for f in sorted_facts if f.value_type == "int64_minor_currency" and f.currency),
        "BRL",
    )
    rows = sorted(
        (
            project_collection_fact_to_landing_row(f, ctx, query_currency=query_currency)
            for f in sorted_facts
        ),
        key=lambda row: row.candidate_sort_key_jcs(),
    )
    return CollectionResult(
        admitted_collection_locator=adm,
        admitted_collection_digest=adm.content_digest,
        call_side=side,  # type: ignore[arg-type]
        registry_snapshot_locator=reg,
        registry_snapshot_digest=reg.content_digest,
        requested_capabilities=("cap:campaign-basic-v1",),
        observed_capabilities=("cap:campaign-basic-v1",),
        retrieval_context=ctx,
        transport_outcome=transport_ok(),
        candidates=tuple(rows),
        normalized_fact_set=sorted_facts,
        normalized_fact_set_digest=digest,
        normalized_errors=(),
    )


def oracle_result_locator(result: CollectionResult) -> ArtifactLocator:
    digest = "sha256:" + hashlib.sha256(oracle_jcs(result.to_dict())).hexdigest()
    return ArtifactLocator.from_digest("smart_ads/collection_result/v1", digest)


@pytest.fixture
def cand_result() -> CollectionResult:
    return collection_result(facts_for(BASE_VALUES), side="candidate", retrieved_at=CANDIDATE_AT)


@pytest.fixture
def ref_result() -> CollectionResult:
    return collection_result(
        facts_for(BASE_VALUES, side="reference"), side="reference", retrieved_at=REFERENCE_AT
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
            {"collection_result_locator": _loc("smart_ads/admitted_collection/v1").to_dict()},
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


def _side(result: CollectionResult, pair: MetricPairKey) -> b7.ReconciliationSide:
    return b7.ReconciliationSide.for_fact(
        b7.resolve_fact_evidence(b7.select_fact_evidence(result, pair), result),
        b7.select_fact_evidence(result, pair),
    )


TOLERANCE_LOC = _loc("smart_ads/tolerance_profile/v1", "7")
EXACT_ROW = {
    "measured_absolute_delta": "0",
    "measured_relative_delta": "0.000000",
    "relative_delta_status": "computed",
    "reconciliation_outcome": "exact_match",
    "metric_verification_status": "VERIFIED",
}


def reconciliation_dict(
    cand_result: CollectionResult,
    ref_result: CollectionResult,
    pair: MetricPairKey,
    comparison: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "canonical_fact_key": pair.canonical_fact_key.to_dict(),
        "canonical_fact_key_digest": compute_canonical_fact_key_digest(pair.canonical_fact_key),
        "canonical_metric_ref": pair.canonical_metric_ref,
        "candidate": _side(cand_result, pair).to_dict(),
        "reference": _side(ref_result, pair).to_dict(),
        "tolerance_profile_locator": TOLERANCE_LOC.to_dict(),
        **(comparison if comparison is not None else EXACT_ROW),
    }


def test_reconciliation_side_copies_the_fact_value_fields(cand_result: CollectionResult) -> None:
    side = _side(cand_result, MetricPairKey(row_key(REF_A), SPEND))
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
    side = _side(cand_result, MetricPairKey(row_key(REF_A), SPEND))
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
    data[side_name] = _side(cand_result if side_name == "candidate" else ref_result, other).to_dict()
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
        ({"tolerance_profile_locator": _loc("smart_ads/finding/v1").to_dict()}, "malformed_member"),
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


# ===========================================================================
# Slice 4 - native_request_projection/v1 (closed, redacted)
# ===========================================================================

NATIVE_KEYS = (
    "$schema",
    "endpoint",
    "http_method",
    "endpoint_version_ref",
    "resource_refs",
    "date_range",
    "resource_level",
    "metrics",
    "breakdowns",
    "pagination",
    "currency",
    "attribution_omission_state",
)


def canonical_query() -> CanonicalQueryContract:
    return CanonicalQueryContract(
        tenant_ref="tenant:ibvi",
        binding_ref="binding:meta-primary",
        account_ref="account:ibvi-01",
        resource_scope_ref="scope:campaigns-active",
        ad_platform_ref="meta",
        date_rule="previous_local_day",
        date_range=DateRange(start_date=DAY, end_date=DAY, inclusive=True),
        reporting_timezone="America/Sao_Paulo",
        tzdb_version="2026a",
        resource_level="campaign",
        metric_semantic_refs=(CLICKS, IMPRESSIONS, SPEND),
        requested_capabilities=("cap:campaign-basic-v1",),
    )


def native_dict(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "$schema": "smart_ads/native_request_projection/v1",
        "endpoint": "/v21.0/insights",
        "http_method": "GET",
        "endpoint_version_ref": "api-version:v21.0",
        "resource_refs": [REF_A, REF_B],
        "date_range": {"start_date": DAY, "end_date": DAY, "inclusive": True},
        "resource_level": "campaign",
        "metrics": ["clicks", "impressions", "spend"],
        "breakdowns": [],
        "pagination": "complete_result_required",
        "currency": "BRL",
        "attribution_omission_state": "omitted",
    }
    base.update(overrides)
    return base


def test_native_projection_round_trips_with_only_the_adr_members() -> None:
    projection = b7.NativeRequestProjection.from_dict(native_dict())
    assert tuple(projection.to_dict()) == NATIVE_KEYS
    assert projection.to_dict() == native_dict()
    expected = "sha256:" + hashlib.sha256(oracle_jcs(native_dict())).hexdigest()
    assert projection.native_request_digest == expected


@pytest.mark.parametrize(
    "extra",
    ["headers", "access_token", "authorization", "raw_response", "provider_payload",
     "time_increment", "limit", "url", "query"],
)
def test_native_projection_rejects_any_extra_member(extra: str) -> None:
    with pytest.raises(Bundle7BDefectError) as excinfo:
        b7.NativeRequestProjection.from_dict(native_dict(**{extra: "x"}))
    assert code_of(excinfo) == "native_projection_not_closed"


@pytest.mark.parametrize("missing", NATIVE_KEYS)
def test_native_projection_rejects_any_missing_member(missing: str) -> None:
    data = native_dict()
    del data[missing]
    with pytest.raises(Bundle7BDefectError) as excinfo:
        b7.NativeRequestProjection.from_dict(data)
    assert code_of(excinfo) == "native_projection_not_closed"


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://graph.facebook.com/v21.0/insights",
        "//graph.facebook.com/v21.0/insights",
        "/v21.0/insights?fields=spend",
        "/v21.0/insights?access_token=secret",
        "/v21.0/insights#fragment",
        "/user:secret@graph.facebook.com/insights",
        "/v21.0/act_1234567890/insights",
        "/v21.0/1234567890/insights",
        "/v21.0/insights/",
        "v21.0/insights",
        "/",
        "",
    ],
)
def test_native_projection_rejects_urls_authority_query_and_raw_ids(endpoint: str) -> None:
    with pytest.raises(Bundle7BDefectError) as excinfo:
        b7.NativeRequestProjection.from_dict(native_dict(endpoint=endpoint))
    assert code_of(excinfo) == "native_projection_forbidden_content"


@pytest.mark.parametrize("raw_ref", ["act_1234567890", "1234567890", "campaign:123"])
def test_native_projection_rejects_raw_provider_identifiers(raw_ref: str) -> None:
    with pytest.raises(Bundle7BDefectError) as excinfo:
        b7.NativeRequestProjection.from_dict(native_dict(resource_refs=[raw_ref]))
    assert code_of(excinfo) == "native_projection_forbidden_content"


@pytest.mark.parametrize(
    ("member", "value", "code"),
    [
        ("metrics", ["impressions", "clicks", "spend"], "wrong_order"),
        ("metrics", ["clicks", "clicks", "spend"], "duplicate_identity"),
        ("resource_refs", [REF_B, REF_A], "wrong_order"),
        ("breakdowns", ["region", "age"], "wrong_order"),
        ("metrics", [], "malformed_member"),
        ("resource_refs", [], "malformed_member"),
        ("metrics", "clicks", "malformed_member"),
        ("metrics", ["Clicks"], "malformed_member"),
        ("http_method", "PUT", "malformed_member"),
        ("endpoint_version_ref", "version:v21.0", "malformed_member"),
        ("currency", "brl", "malformed_member"),
        ("date_range", {"start_date": DAY}, "malformed_member"),
        ("resource_level", "Campaign 1", "malformed_member"),
        ("pagination", "page=2", "malformed_member"),
        ("endpoint", b"/v21.0/insights", "malformed_member"),
        ("attribution_omission_state", "present", "fixed_member_mismatch"),
        ("$schema", "smart_ads/native_request/v1", "fixed_member_mismatch"),
    ],
)
def test_native_projection_member_grammar(member: str, value: object, code: str) -> None:
    with pytest.raises(Bundle7BDefectError) as excinfo:
        b7.NativeRequestProjection.from_dict(native_dict(**{member: value}))
    assert code_of(excinfo) == code


def test_native_projection_rejects_non_mapping_input() -> None:
    for bad in ("x", None, {1: "x"}):
        with pytest.raises(Bundle7BDefectError) as excinfo:
            b7.NativeRequestProjection.from_dict(bad)
        assert code_of(excinfo) == "malformed_member"


def _signature() -> str:
    return base64.b64encode(bytes(64)).decode("ascii")


def _registry_loc() -> ArtifactLocator:
    return _loc("smart_ads/key_authorization_registry/v1", "9")


def test_native_projection_accepts_a_p1_integrity_block_and_checks_it() -> None:
    unsigned = native_dict(integrity={"key_id": KEY_ID, "key_registry_snapshot_locator": _registry_loc().to_dict()})
    projection = b7.NativeRequestProjection.from_dict(unsigned)
    digest = p1_content_digest(projection.to_dict())
    signed = copy.deepcopy(unsigned)
    signed["integrity"].update(content_digest=digest, signature_base64=_signature())
    assert b7.NativeRequestProjection.from_dict(signed).to_dict() == signed
    signed["integrity"]["content_digest"] = _sha("0")
    with pytest.raises(Bundle7BDefectError) as excinfo:
        b7.NativeRequestProjection.from_dict(signed)
    assert code_of(excinfo) == "integrity_digest_mismatch"


ALGORITHM_DIGEST = _sha("a")


def identity_algorithm(
    seen: list[tuple[b7.NativeRequestProjection, str]] | None = None,
) -> Callable[[b7.NativeRequestProjection, str], CanonicalQueryContract]:
    def run(projection: b7.NativeRequestProjection, algorithm_digest: str) -> CanonicalQueryContract:
        if seen is not None:
            seen.append((projection, algorithm_digest))
        return canonical_query()

    return run


def test_native_check_recomputes_the_digest_and_runs_the_pinned_algorithm() -> None:
    projection = b7.NativeRequestProjection.from_dict(native_dict())
    seen: list[tuple[b7.NativeRequestProjection, str]] = []
    b7.check_native_request(
        projection,
        native_request_digest=projection.native_request_digest,
        canonical_query=canonical_query(),
        algorithm_digest=ALGORITHM_DIGEST,
        project_native_request=identity_algorithm(seen),
    )
    assert seen == [(projection, ALGORITHM_DIGEST)]


def test_native_check_rejects_a_divergent_native_digest() -> None:
    projection = b7.NativeRequestProjection.from_dict(native_dict())
    with pytest.raises(Bundle7BDefectError) as excinfo:
        b7.check_native_request(
            projection,
            native_request_digest=_sha("0"),
            canonical_query=canonical_query(),
            algorithm_digest=ALGORITHM_DIGEST,
            project_native_request=identity_algorithm(),
        )
    assert code_of(excinfo) == "native_request_digest_mismatch"


def _raising(projection: b7.NativeRequestProjection, digest: str) -> CanonicalQueryContract:
    raise ClosedValidationError("extra default-valued native parameter")


@pytest.mark.parametrize(
    "algorithm",
    [
        lambda p, d: dataclasses.replace(canonical_query(), metric_semantic_refs=(CLICKS, SPEND)),
        lambda p, d: dataclasses.replace(canonical_query(), tzdb_version="2026b"),
        lambda p, d: canonical_query().to_dict(),
        lambda p, d: None,
        _raising,
    ],
)
def test_native_check_requires_byte_identical_canonical_projection(
    algorithm: Callable[[b7.NativeRequestProjection, str], Any],
) -> None:
    projection = b7.NativeRequestProjection.from_dict(native_dict())
    with pytest.raises(Bundle7BDefectError) as excinfo:
        b7.check_native_request(
            projection,
            native_request_digest=projection.native_request_digest,
            canonical_query=canonical_query(),
            algorithm_digest=ALGORITHM_DIGEST,
            project_native_request=algorithm,
        )
    assert code_of(excinfo) == "native_projection_mismatch"


def test_native_check_rejects_wrongly_typed_arguments() -> None:
    projection = b7.NativeRequestProjection.from_dict(native_dict())
    good: dict[str, Any] = {
        "native_request_digest": projection.native_request_digest,
        "canonical_query": canonical_query(),
        "algorithm_digest": ALGORITHM_DIGEST,
        "project_native_request": identity_algorithm(),
    }
    for name, bad in (
        ("canonical_query", canonical_query().to_dict()),
        ("algorithm_digest", "sha256:X"),
        ("project_native_request", "not-callable"),
        ("native_request_digest", None),
    ):
        with pytest.raises(Bundle7BDefectError) as excinfo:
            b7.check_native_request(projection, **dict(good, **{name: bad}))
        assert code_of(excinfo) in {"malformed_argument", "malformed_member"}
    with pytest.raises(Bundle7BDefectError) as excinfo:
        b7.check_native_request(native_dict(), **good)  # type: ignore[arg-type]
    assert code_of(excinfo) == "malformed_argument"


# ===========================================================================
# Slice 5 - reconcile_7b_fact_sets (failed comparisons are values)
# ===========================================================================

GATE3_LOC = _loc("smart_ads/gate3_selection_receipt/v1", "1")
RUN_LOC = _loc("smart_ads/migration_run_context/v1", "3")
SCOPE = "scope:campaigns-active"
QUERY_DIGEST = canonical_query().canonical_query_digest
CANDIDATE_VALUES = {**BASE_VALUES, (REF_A, CLICKS): "101"}
WITHIN_TOLERANCE_ROW = {
    "measured_absolute_delta": "1",
    "measured_relative_delta": "0.010000",
    "relative_delta_status": "computed",
    "reconciliation_outcome": "within_declared_tolerance",
    "metric_verification_status": "VERIFIED",
}


def profile_dict(
    metric: str,
    *,
    max_abs: str = "0",
    max_rel: str = "0.000000",
    query_digest: str = QUERY_DIGEST,
    scope: str = SCOPE,
    gate3: ArtifactLocator = GATE3_LOC,
    run: ArtifactLocator = RUN_LOC,
    signed: bool = True,
) -> dict[str, Any]:
    exact = max_abs == "0" and max_rel == "0.000000"
    data: dict[str, Any] = {
        "$schema": "smart_ads/tolerance_profile/v1",
        "canonical_metric_ref": metric,
        "value_type": "int64_minor_currency" if metric == SPEND else "int64_count",
        "max_absolute_delta": max_abs,
        "max_relative_delta": max_rel,
        "decimal_scale": 6,
        "rounding_mode": "ROUND_HALF_UP",
        "reference_zero_rule": "exact_zero_only",
        "authorization_binding": None if exact else {
            "gate3_selection_locator": gate3.to_dict(),
            "canonical_query_digest": query_digest,
            "authorized_certification_scope": scope,
            "migration_run_context_locator": run.to_dict(),
        },
    }
    if signed:
        data["integrity"] = {
            "key_id": KEY_ID, "key_registry_snapshot_locator": _registry_loc().to_dict()
        }
        data["integrity"].update(
            content_digest=p1_content_digest(data), signature_base64=_signature()
        )
    return data


def default_profiles() -> dict[str, dict[str, Any]]:
    return {
        IMPRESSIONS: profile_dict(IMPRESSIONS),
        CLICKS: profile_dict(CLICKS, max_abs="5", max_rel="0.050000"),
        SPEND: profile_dict(SPEND),
    }


def oracle_profile_locator(data: dict[str, Any]) -> ArtifactLocator:
    digest = "sha256:" + hashlib.sha256(oracle_jcs(data)).hexdigest()
    return ArtifactLocator.from_digest("smart_ads/tolerance_profile/v1", digest)


def reconcile(
    cand: CollectionResult,
    ref: CollectionResult,
    profiles: dict[str, dict[str, Any]] | None = None,
    **overrides: Any,
) -> b7.Reconciliation7BResult:
    kwargs: dict[str, Any] = {
        "candidate_result": cand,
        "reference_result": ref,
        "tolerance_profiles": default_profiles() if profiles is None else profiles,
        "gate3_selection_locator": GATE3_LOC,
        "canonical_query_digest": QUERY_DIGEST,
        "authorized_certification_scope": SCOPE,
        "migration_run_context_locator": RUN_LOC,
    }
    kwargs.update(overrides)
    return b7.reconcile_7b_fact_sets(**kwargs)


def results(
    cand_values: dict[tuple[str, str], str] = CANDIDATE_VALUES,
    ref_values: dict[tuple[str, str], str] = BASE_VALUES,
    *,
    cand_at: str = CANDIDATE_AT,
    ref_at: str = REFERENCE_AT,
    cand_facts: list[NormalizedCollectionFact] | None = None,
    ref_facts: list[NormalizedCollectionFact] | None = None,
) -> tuple[CollectionResult, CollectionResult]:
    cand = collection_result(
        cand_facts if cand_facts is not None else facts_for(cand_values),
        side="candidate", retrieved_at=cand_at,
    )
    ref = collection_result(
        ref_facts if ref_facts is not None else facts_for(ref_values, side="reference"),
        side="reference", retrieved_at=ref_at,
    )
    return cand, ref


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
    assert result.candidate_row_universe_digest == result.reference_row_universe_digest == expected_u7
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
    assert data["tolerance_profile_locator"] == oracle_profile_locator(default_profiles()[CLICKS]).to_dict()
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
    missing = {k: v for k, v in default_profiles().items() if k != SPEND}
    extra = dict(default_profiles(), **{"metric:reach_v1": profile_dict(CLICKS)})
    swapped = dict(default_profiles(), **{SPEND: profile_dict(IMPRESSIONS)})
    unsigned = dict(default_profiles(), **{CLICKS: profile_dict(CLICKS, max_abs="5", max_rel="0.050000", signed=False)})
    unsigned_exact = dict(default_profiles(), **{SPEND: profile_dict(SPEND, signed=False)})
    malformed = dict(default_profiles(), **{SPEND: dict(profile_dict(SPEND), decimal_scale=2)})
    for profiles, code in (
        (missing, "tolerance_profile_unresolved"),
        (extra, "tolerance_profile_unresolved"),
        (swapped, "tolerance_profile_metric_mismatch"),
        (unsigned, "tolerance_profile_unsigned"),
        (unsigned_exact, "tolerance_profile_unsigned"),
        (malformed, "tolerance_profile_malformed"),
        ([], "malformed_argument"),
    ):
        with pytest.raises(Bundle7BDefectError) as excinfo:
            reconcile(cand, ref, profiles)  # type: ignore[arg-type]
        assert code_of(excinfo) == code


@pytest.mark.parametrize(
    "binding",
    [
        {"query_digest": _sha("e")},
        {"scope": "scope:other-scope"},
        {"run": _loc("smart_ads/migration_run_context/v1", "e")},
        {"gate3": _loc("smart_ads/gate3_selection_receipt/v1", "e")},
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
