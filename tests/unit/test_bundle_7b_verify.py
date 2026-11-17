"""``verify_certification_7b_record``: recompute everything; any failure is fatal."""
from __future__ import annotations

from collections.abc import Callable
import copy
import dataclasses
from typing import Any

import pytest

from smart_ads.contracts.scalars import ClosedValidationError
from smart_ads.contracts.schemas import AdmittedCollection
from smart_ads.ports.cell_runtime import ResolvedGate3SelectionState
from smart_ads.reconciliation import bundle_7b as b7
from smart_ads.reconciliation.bundle_7b import Bundle7BDefectError
from tests.unit._bundle_7b_builders import (
    BASE_VALUES,
    CANDIDATE_AT,
    CANDIDATE_VALUES,
    CLICKS,
    EXACT_ROW,
    FINGERPRINT_MEMBERS,
    IMPRESSIONS,
    REF_A,
    REF_B,
    REF_C,
    SPEND,
    WITHIN_TOLERANCE_ROW,
    canonical_query,
    code_of,
    collection_result,
    default_profiles,
    different_value,
    fact,
    facts_for,
    loc,
    oracle_profile_locator,
    oracle_result_locator,
    profile_dict,
    sha,
)
from tests.unit._bundle_7b_world import (
    World,
    build_world,
    locate,
    make_admission,
    make_pipeboard_contract,
    record_defect,
    reseal,
    tampered,
    verify_defect,
    world,  # noqa: F401 - pytest fixture
)


def _gate3_state(world: World, **changes: Any) -> ResolvedGate3SelectionState:
    return dataclasses.replace(world.kwargs["gate3_selection"], **changes)


def test_verifier_accepts_the_consistent_world(world: World) -> None:
    assert world.verify() is None


def test_verifier_accepts_exactly_300_seconds_of_skew_and_separate_admissions() -> None:
    build_world(ref_at="2026-11-11T04:20:00.000000Z").verify()
    build_world(ref_at="2026-11-11T04:10:00.000000Z").verify()
    build_world(separate_reference_admission=True).verify()


@pytest.mark.parametrize(
    "name",
    [
        "migration_run_context_locator", "gate3_selection", "gate3_certification_fingerprint",
        "driver_contract", "candidate_admission", "reference_admission", "candidate_result",
        "reference_result", "candidate_effect_proof_locator", "candidate_effect_result_locator",
        "reference_effect_proof_locator", "reference_effect_result_locator",
    ],
)
def test_verifier_rejects_wrongly_typed_arguments(world: World, name: str) -> None:
    assert verify_defect(world, **{name: "not-an-artifact"}) == "malformed_argument"


def test_verifier_rejects_a_wrongly_typed_record_or_callable(world: World) -> None:
    with pytest.raises(Bundle7BDefectError) as excinfo:
        b7.verify_certification_7b_record(world.record, **world.kwargs)  # type: ignore[arg-type]
    assert code_of(excinfo) == "malformed_argument"
    assert verify_defect(world, project_native_request=None) == "malformed_argument"
    assert verify_defect(world, tolerance_profiles=[]) == "malformed_argument"


def test_verifier_requires_the_same_run(world: World) -> None:
    other_run = loc("smart_ads/migration_run_context/v1", "e")
    assert verify_defect(world, migration_run_context_locator=other_run) == "run_context_mismatch"


@pytest.mark.parametrize(
    "changes",
    [
        {"locator": loc("smart_ads/gate3_selection_receipt/v1", "e")},
        {"selection_role": "operational_renewal"},
        {"candidate_driver_contract_digest": sha("e")},
        {"canonical_query_digest": sha("e")},
        {"schema_bundle_digest": sha("e")},
        {"resource_mapping_contract_digest": sha("e")},
        {"authorized_certification_scope": "scope:other-scope"},
    ],
)
def test_verifier_requires_the_resolved_certification_role_selection(
    world: World, changes: dict[str, Any]
) -> None:
    assert verify_defect(world, gate3_selection=_gate3_state(world, **changes)) == (
        "gate3_selection_mismatch"
    )


@pytest.mark.parametrize("member", FINGERPRINT_MEMBERS)
def test_verifier_fails_on_any_single_member_of_the_resolved_fingerprint(
    world: World, member: str
) -> None:
    resolved = world.kwargs["gate3_certification_fingerprint"]
    changed = dataclasses.replace(
        resolved, **{member: different_value(member, getattr(resolved, member))}
    )
    assert verify_defect(world, gate3_certification_fingerprint=changed) == "fingerprint_mismatch"


@pytest.mark.parametrize(
    "member",
    ["reference_client_identity_digest", "official_source_locators_digest",
     "schema_bundle_digest", "resource_mapping_contract_digest", "authorized_certification_scope"],
)
def test_verifier_rejects_a_fingerprint_changed_identically_on_both_sides(
    world: World, member: str
) -> None:
    record = world.record
    current = record["candidate_execution"]["gate3_certification_fingerprint"][member]
    value = different_value(member, current)
    for side in ("candidate_execution", "reference_execution"):
        record = tampered(record, (side, "gate3_certification_fingerprint", member), value)
    assert verify_defect(world, record) == "fingerprint_mismatch"


def test_verifier_resolves_the_exact_phase1_driver_contract(world: World) -> None:
    other = dataclasses.replace(make_pipeboard_contract(), contract_id="driver-contract:other-v1")
    assert verify_defect(world, driver_contract=other) == "driver_contract_unresolved"


@pytest.mark.parametrize("side", ["candidate", "reference"])
def test_verifier_resolves_each_side_admission_by_locator(world: World, side: str) -> None:
    other = dataclasses.replace(world.kwargs["candidate_admission"], admission_id="admission:other")
    assert verify_defect(world, **{f"{side}_admission": other}) == "admission_mismatch"


@pytest.mark.parametrize(
    "variant",
    [
        lambda q, d, r: make_admission(q, d, r, purpose="fixture_7a"),
        lambda q, d, r: make_admission(dataclasses.replace(q, tzdb_version="2026b"), d, r),
        lambda q, d, r: make_admission(q, loc("smart_ads/pipeboard_phase1_contract/v1", "e"), r),
        lambda q, d, r: make_admission(q, d, loc("smart_ads/private_registry_snapshot/v1", "f")),
    ],
)
def test_verifier_rejects_a_located_admission_for_another_purpose_query_or_driver(
    world: World, variant: Callable[..., AdmittedCollection]
) -> None:
    base = world.kwargs["candidate_admission"]
    admission = variant(
        canonical_query(), base.driver_contract_locator, base.registry_snapshot_locator
    )
    record = tampered(world.record, ("candidate_execution", "admitted_collection_locator"),
                      locate(AdmittedCollection.SCHEMA, admission).to_dict())
    assert verify_defect(world, record, candidate_admission=admission) == "admission_mismatch"


def test_verifier_rejects_results_from_the_wrong_side_or_admission(world: World) -> None:
    cand, ref = world.kwargs["candidate_result"], world.kwargs["reference_result"]
    assert verify_defect(world, candidate_result=ref) == "collection_result_mismatch"
    assert verify_defect(world, reference_result=cand) == "collection_result_mismatch"
    moved = dataclasses.replace(
        cand,
        admitted_collection_locator=loc("smart_ads/admitted_collection/v1", "e"),
        admitted_collection_digest=sha("e"),
    )
    assert verify_defect(world, candidate_result=moved,
                         candidate_effect_result_locator=oracle_result_locator(moved)) == (
        "collection_result_mismatch"
    )


def test_verifier_binds_the_retrieval_time_and_fact_set_of_each_result(world: World) -> None:
    base = world.kwargs["candidate_result"]
    later = collection_result(facts_for(CANDIDATE_VALUES), side="candidate",
                              retrieved_at="2026-11-11T04:15:01.000000Z",
                              admitted_locator=base.admitted_collection_locator,
                              registry_locator=base.registry_snapshot_locator)
    assert verify_defect(world, candidate_result=later,
                         candidate_effect_result_locator=oracle_result_locator(later)) == (
        "collection_result_mismatch"
    )
    other_values = collection_result(facts_for({**CANDIDATE_VALUES, (REF_B, CLICKS): "1"}),
                                     side="candidate", retrieved_at=CANDIDATE_AT,
                                     admitted_locator=base.admitted_collection_locator,
                                     registry_locator=base.registry_snapshot_locator)
    assert verify_defect(world, candidate_result=other_values,
                         candidate_effect_result_locator=oracle_result_locator(other_values)) == (
        "normalized_fact_set_digest_mismatch"
    )


@pytest.mark.parametrize("side", ["candidate", "reference"])
def test_verifier_binds_each_effect_proof_and_its_result_locator(world: World, side: str) -> None:
    other_proof = loc("smart_ads/effect_proof/v1", "e")
    assert verify_defect(world, **{f"{side}_effect_proof_locator": other_proof}) == (
        "effect_proof_mismatch"
    )
    other_result = loc("smart_ads/collection_result/v1", "e")
    assert verify_defect(world, **{f"{side}_effect_result_locator": other_result}) == (
        "effect_result_mismatch"
    )


def test_verifier_rejects_one_effect_result_for_both_sides(world: World) -> None:
    same = world.kwargs["candidate_effect_result_locator"]
    assert verify_defect(world, reference_effect_result_locator=same) == "effect_proof_not_distinct"


def test_verifier_runs_the_injected_digest_pinned_native_algorithm(world: World) -> None:
    record = tampered(world.record,
                      ("candidate_execution", "native_to_canonical_projection_algorithm_digest"),
                      sha("e"))
    assert verify_defect(world, record) == "native_projection_mismatch"
    narrower = dataclasses.replace(canonical_query(), metric_semantic_refs=(CLICKS, SPEND))
    assert verify_defect(world, project_native_request=lambda p, d: narrower) == (
        "native_projection_mismatch"
    )


def _loose(**binding: Any) -> dict[str, Any]:
    return profile_dict(CLICKS, max_abs="5", max_rel="0.050000", **binding)


@pytest.mark.parametrize(
    ("profiles", "code"),
    [
        ({CLICKS: _loose(signed=False)}, "tolerance_profile_unsigned"),
        ({SPEND: profile_dict(SPEND, signed=False)}, "tolerance_profile_unsigned"),
        ({CLICKS: profile_dict(CLICKS, max_abs="6", max_rel="0.050000")},
         "tolerance_profile_locator_mismatch"),
        ({SPEND: profile_dict(IMPRESSIONS)}, "tolerance_profile_metric_mismatch"),
        ({CLICKS: _loose(query_digest=sha("e"))}, "tolerance_profile_unbound"),
        ({CLICKS: _loose(scope="scope:other")}, "tolerance_profile_unbound"),
        ({CLICKS: _loose(run=loc("smart_ads/migration_run_context/v1", "e"))},
         "tolerance_profile_unbound"),
        ({CLICKS: _loose(gate3=loc("smart_ads/gate3_selection_receipt/v1", "e"))},
         "tolerance_profile_unbound"),
    ],
)
def test_verifier_requires_signed_located_and_bound_tolerance_profiles(
    world: World, profiles: dict[str, Any], code: str
) -> None:
    merged = dict(world.kwargs["tolerance_profiles"], **profiles)
    assert verify_defect(world, tolerance_profiles=merged) == code


def test_verifier_rejects_an_unresolved_tolerance_profile(world: World) -> None:
    profiles = {k: v for k, v in world.kwargs["tolerance_profiles"].items() if k != SPEND}
    assert verify_defect(world, tolerance_profiles=profiles) == "tolerance_profile_unresolved"


def _with_reconciliation(
    world: World, index: int, path: tuple[Any, ...], value: Any
) -> dict[str, Any]:
    return reseal(tampered(world.record, ("fact_reconciliations", index, *path), value))


@pytest.mark.parametrize(
    ("path", "value_from", "code"),
    [
        (("candidate", "fact_evidence_selector", "collection_result_locator"),
         "reference_result_locator", "evidence_container_mismatch"),
        (("reference", "fact_evidence_selector", "collection_result_locator"),
         "candidate_result_locator", "evidence_container_mismatch"),
        (("candidate", "fact_evidence_selector", "normalized_fact_set_digest"),
         "reference_set_digest", "normalized_fact_set_digest_mismatch"),
        (("candidate", "fact_evidence_selector", "fact_projection_digest"),
         "zero_digest", "fact_projection_digest_mismatch"),
        (("candidate", "raw_numeric_value"), "102", "evidence_value_mismatch"),
        (("reference", "source_metric_ref"), "source-metric:provider:meta.reach:v1",
         "evidence_value_mismatch"),
        (("candidate",), "reference_side", "evidence_container_mismatch"),
        (("tolerance_profile_locator",), "spend_profile_locator",
         "tolerance_profile_locator_mismatch"),
    ],
)
def test_verifier_resolves_every_selector_and_copied_field(
    world: World, path: tuple[Any, ...], value_from: str, code: str
) -> None:
    clicks = world.record["fact_reconciliations"][0]
    values = {
        "reference_result_locator": world.kwargs["reference_effect_result_locator"].to_dict(),
        "candidate_result_locator": world.kwargs["candidate_effect_result_locator"].to_dict(),
        "reference_set_digest": world.kwargs["reference_result"].normalized_fact_set_digest,
        "zero_digest": sha("0"),
        "reference_side": clicks["reference"],
        "spend_profile_locator": oracle_profile_locator(default_profiles()[SPEND]).to_dict(),
    }
    value = values.get(value_from, value_from)
    assert verify_defect(world, _with_reconciliation(world, 0, path, value)) == code


@pytest.mark.parametrize(
    ("index", "asserted"),
    [
        # REF_A clicks, recomputed within tolerance: abs 1, rel 0.010000.
        (0, dict(WITHIN_TOLERANCE_ROW, measured_absolute_delta="2")),
        (0, dict(WITHIN_TOLERANCE_ROW, measured_relative_delta="0.020000")),
        # REF_A impressions, recomputed exact_match: assert a tolerance outcome.
        (1, dict(WITHIN_TOLERANCE_ROW, measured_absolute_delta="1",
                 measured_relative_delta="0.001000")),
        # REF_B impressions, recomputed reference_zero: assert a computed status.
        (4, dict(EXACT_ROW)),
    ],
)
def test_verifier_recomputes_asserted_comparison_members(
    world: World, index: int, asserted: dict[str, Any]
) -> None:
    recs = copy.deepcopy(world.record["fact_reconciliations"])
    recs[index].update(asserted)
    assert verify_defect(world, reseal(dict(world.record, fact_reconciliations=recs))) == (
        "asserted_comparison_mismatch"
    )


@pytest.mark.parametrize(
    ("member", "value"),
    [
        ("relative_delta_status", "reference_zero"),
        ("reconciliation_outcome", "exact_match"),
        ("metric_verification_status", "UNRECONCILED"),
        ("measured_absolute_delta", "0"),
        ("measured_relative_delta", None),
    ],
)
def test_single_member_divergence_that_breaks_the_truth_table_is_malformed(
    world: World, member: str, value: Any
) -> None:
    record = _with_reconciliation(world, 0, (member,), value)
    assert record_defect(record) == "asserted_comparison_malformed"


def test_verifier_recomputes_the_status_from_canonical_values() -> None:
    # Candidate 200 vs reference 100 is UNRECONCILED; the record asserts VERIFIED.
    mismatch = build_world({**CANDIDATE_VALUES, (REF_A, CLICKS): "200"}, require_verified=False)
    recs = copy.deepcopy(mismatch.record["fact_reconciliations"])
    assert recs[0]["metric_verification_status"] == "UNRECONCILED"
    recs[0].update(dict(WITHIN_TOLERANCE_ROW, measured_absolute_delta="100",
                        measured_relative_delta="1.000000"))
    record = reseal(dict(mismatch.record, fact_reconciliations=recs))
    assert verify_defect(mismatch, record) == "asserted_comparison_mismatch"


def test_verifier_recomputes_each_side_universe_from_its_result() -> None:
    extra_row = {(REF_C, IMPRESSIONS): "1", (REF_C, CLICKS): "1", (REF_C, SPEND): "1"}
    wider = build_world({**CANDIDATE_VALUES, **extra_row}, require_verified=False)
    assert verify_defect(wider) == "row_universe_digest_mismatch"
    extra_metric = build_world(
        cand_facts=facts_for(CANDIDATE_VALUES) + [fact(REF_A, "metric:reach_v1", "9")],
        require_verified=False,
    )
    assert verify_defect(extra_metric) == "pair_universe_incomplete"


@pytest.mark.parametrize(
    ("path", "value", "code"),
    [
        (("migration_run_context_locator",),
         loc("smart_ads/migration_run_context/v1", "e").to_dict(), "run_context_mismatch"),
        (("gate3_selection_locator",),
         loc("smart_ads/gate3_selection_receipt/v1", "e").to_dict(), "gate3_selection_mismatch"),
        (("candidate_execution", "admitted_collection_locator"),
         loc("smart_ads/admitted_collection/v1", "e").to_dict(), "admission_mismatch"),
        (("reference_execution", "admitted_collection_locator"),
         loc("smart_ads/admitted_collection/v1", "e").to_dict(), "admission_mismatch"),
        (("candidate_execution", "effect_proof_locator"),
         loc("smart_ads/effect_proof/v1", "e").to_dict(), "effect_proof_mismatch"),
        (("reference_execution", "effect_proof_locator"),
         loc("smart_ads/effect_proof/v1", "e").to_dict(), "effect_proof_mismatch"),
        (("candidate_execution", "registry_snapshot_locator"),
         loc("smart_ads/private_registry_snapshot/v1", "f").to_dict(), "admission_mismatch"),
        (("candidate_execution", "retrieved_at_utc"), "2026-11-11T04:15:00.000001Z",
         "collection_result_mismatch"),
        (("reference_execution", "retrieved_at_utc"), "2026-11-11T04:17:30.000001Z",
         "collection_result_mismatch"),
        (("candidate_execution", "normalized_fact_set_digest"), sha("e"),
         "normalized_fact_set_digest_mismatch"),
        (("reference_execution", "normalized_fact_set_digest"), sha("e"),
         "normalized_fact_set_digest_mismatch"),
        (("reference_execution", "native_to_canonical_projection_algorithm_digest"), sha("e"),
         "native_projection_mismatch"),
    ],
)
def test_verifier_binds_each_evidence_member_of_the_record(
    world: World, path: tuple[Any, ...], value: Any, code: str
) -> None:
    assert verify_defect(world, tampered(world.record, path, value)) == code


@pytest.mark.parametrize(
    ("cand_extra", "ref_extra", "code"),
    [
        # A date outside the query window must hold on both sides for a consistent record.
        ({"metric_date": "2026-11-01"}, {"metric_date": "2026-11-01"},
         "fact_outside_query_window"),
        ({"binding_ref": "binding:other"}, {}, "fact_binding_mismatch"),
        ({}, {"binding_ref": "binding:other"}, "fact_binding_mismatch"),
        ({"account_ref": "account:someone-else"}, {}, "fact_account_mismatch"),
        ({}, {"account_ref": "account:someone-else"}, "fact_account_mismatch"),
    ],
)
def test_verifier_requires_every_fact_inside_the_admitted_query(
    cand_extra: dict[str, str], ref_extra: dict[str, str], code: str
) -> None:
    outside = build_world(
        cand_facts=facts_for(CANDIDATE_VALUES, **cand_extra),
        ref_facts=facts_for(BASE_VALUES, side="reference", **ref_extra),
        query_checked=False,
    )
    assert verify_defect(outside) == code


def test_verifier_never_mutates_its_inputs(world: World) -> None:
    before = copy.deepcopy(world.record)
    profiles_before = copy.deepcopy(world.kwargs["tolerance_profiles"])
    world.verify()
    assert world.record == before
    assert world.kwargs["tolerance_profiles"] == profiles_before


def test_every_defect_code_is_documented_and_closed() -> None:
    with pytest.raises(ClosedValidationError):
        Bundle7BDefectError("not_a_code", "x")
    assert all(code == code.lower() and " " not in code for code in b7.DEFECT_CODES)
