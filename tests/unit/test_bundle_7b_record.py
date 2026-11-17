"""7B Gate-3 fingerprint, execution records, row pairing and ``certification_7b_record/v1``."""
from __future__ import annotations

import copy
import dataclasses
from typing import Any

import pytest

from smart_ads.contracts.jcs import p1_content_digest
from smart_ads.reconciliation import bundle_7b as b7
from smart_ads.reconciliation.bundle_7b import Bundle7BDefectError
from tests.unit._bundle_7b_builders import (
    CLICKS,
    FINGERPRINT_MEMBERS,
    GATE3_LOC,
    IMPRESSIONS,
    KEY_ID,
    REF_A,
    REF_B,
    RUN_LOC,
    SPEND,
    WITHIN_TOLERANCE_ROW,
    canonical_query,
    code_of,
    different_value,
    fingerprint_dict,
    loc,
    native_dict,
    oracle_domain_digest,
    registry_loc,
    row_key,
    sha,
    signature,
)
from tests.unit._bundle_7b_world import (
    CAND_EFFECT,
    CANDIDATE_KEYS,
    CANDIDATE_PROVIDER,
    DELETE,
    RECORD_KEYS,
    REFERENCE_KEYS,
    REFERENCE_PROVIDER,
    ROW_PAIRING,
    World,
    record_defect,
    reseal,
    tampered,
    world,  # noqa: F401 - pytest fixture
)

# ---------------------------------------------------------------------------
# Gate-3 certification fingerprint
# ---------------------------------------------------------------------------


def fingerprint_defect(data: object) -> str:
    with pytest.raises(Bundle7BDefectError) as excinfo:
        b7.Gate3CertificationFingerprint.from_dict(data)
    return code_of(excinfo)


def test_fingerprint_has_exactly_the_eleven_adr_members() -> None:
    fp = b7.Gate3CertificationFingerprint.from_dict(fingerprint_dict())
    assert tuple(fp.to_dict()) == FINGERPRINT_MEMBERS
    assert b7.Gate3CertificationFingerprint.from_dict(fp.to_dict()) == fp


@pytest.mark.parametrize("member", FINGERPRINT_MEMBERS)
def test_fingerprint_rejects_a_missing_member(member: str) -> None:
    data = fingerprint_dict()
    del data[member]
    assert fingerprint_defect(data) == "closed_member_set"


def test_fingerprint_rejects_an_extra_member() -> None:
    assert fingerprint_defect(dict(fingerprint_dict(), extra=sha("0"))) == "closed_member_set"


@pytest.mark.parametrize("member", FINGERPRINT_MEMBERS)
@pytest.mark.parametrize("bad", ["", "sha256:ABC", None, 7, "has space"])
def test_fingerprint_rejects_blank_or_malformed_members(member: str, bad: object) -> None:
    assert fingerprint_defect(dict(fingerprint_dict(), **{member: bad})) == "malformed_member"


@pytest.mark.parametrize(
    ("bad_version", "secret"),
    [
        ("act_1234567890", "act_1234567890"),
        ("Bearer:EAAsecretToken123", "EAAsecretToken123"),
        ("21.0", "21.0"),
        ("V21.0", "V21.0"),
        ("v21.", "v21."),
    ],
)
def test_fingerprint_selected_meta_api_version_enforces_closed_grammar_without_echo(
    bad_version: str, secret: str
) -> None:
    with pytest.raises(Bundle7BDefectError) as excinfo:
        b7.Gate3CertificationFingerprint.from_dict(
            fingerprint_dict(selected_meta_api_version=bad_version)
        )
    assert code_of(excinfo) == "malformed_member"
    assert secret not in str(excinfo.value)


@pytest.mark.parametrize("member", FINGERPRINT_MEMBERS)
def test_fingerprint_equality_fails_on_any_single_member(member: str) -> None:
    base = b7.Gate3CertificationFingerprint.from_dict(fingerprint_dict())
    changed = b7.Gate3CertificationFingerprint.from_dict(
        fingerprint_dict(**{member: different_value(member, fingerprint_dict()[member])})
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


# ---------------------------------------------------------------------------
# certification_7b_record/v1 and its execution records
# ---------------------------------------------------------------------------


def test_record_round_trips_with_every_yaml_member(world: World) -> None:
    parsed = world.parsed()
    assert tuple(parsed.to_dict()) == RECORD_KEYS
    assert parsed.to_dict() == world.record
    assert tuple(parsed.candidate_execution.to_dict()) == CANDIDATE_KEYS
    assert tuple(parsed.reference_execution.to_dict()) == REFERENCE_KEYS
    assert parsed.row_pairing.to_dict() == ROW_PAIRING
    assert b7.Certification7BRecord.SCHEMA == "smart_ads/certification_7b_record/v1"


def test_public_key_set_constants_match_every_serialized_object(world: World) -> None:
    parsed = world.parsed()
    recon = parsed.fact_reconciliations[0]
    pairs = [
        (b7.Certification7BRecord.CORE_KEYS, parsed.to_dict()),
        (b7.CandidateExecution.KEYS, parsed.candidate_execution.to_dict()),
        (b7.ReferenceExecution.KEYS, parsed.reference_execution.to_dict()),
        (b7.RowPairing.KEYS, parsed.row_pairing.to_dict()),
        (b7.Gate3CertificationFingerprint.KEYS,
         parsed.candidate_execution.gate3_certification_fingerprint.to_dict()),
        (b7.NativeRequestProjection.CORE_KEYS,
         parsed.reference_execution.native_request_projection.to_dict()),
        (b7.FactReconciliation.KEYS, recon.to_dict()),
        (b7.ReconciliationSide.KEYS, recon.candidate.to_dict()),
        (b7.FactEvidenceSelector.KEYS, recon.candidate.fact_evidence_selector.to_dict()),
        (b7.MetricPairKey.KEYS, recon.pair_key().to_dict()),
    ]
    for keys, serialized in pairs:
        assert isinstance(keys, tuple)
        assert keys == tuple(serialized)
    assert b7.FactReconciliation.SCHEMA == "smart_ads/fact_reconciliation/v1"
    assert b7.FactEvidenceSelector.SCHEMA == "smart_ads/fact_evidence_selector/v1"
    assert b7.NativeRequestProjection.SCHEMA == "smart_ads/native_request_projection/v1"


def test_facade_exports_the_renamed_locator_helper() -> None:
    assert "artifact_locator_for" in b7.__all__
    assert "located" not in b7.__all__
    fp = b7.Gate3CertificationFingerprint.from_dict(fingerprint_dict())
    assert b7.artifact_locator_for("smart_ads/finding/v1", fp).artifact_type == (
        "smart_ads/finding/v1"
    )
    assert "native_projection_not_closed" not in b7.DEFECT_CODES


class _FloatArtifact:
    def to_dict(self) -> dict[str, Any]:
        return {"value": 1.5}


class _NotCallable:
    to_dict = "x"


@pytest.mark.parametrize(
    ("artifact_type", "artifact"),
    [
        ("smart_ads/finding/v1", object()),
        ("smart_ads/finding/v1", {"a": 1}),
        ("smart_ads/finding/v1", _NotCallable()),
        ("smart_ads/finding/v1", _FloatArtifact()),
        ("not a schema id", b7.Gate3CertificationFingerprint.from_dict(fingerprint_dict())),
        (None, b7.Gate3CertificationFingerprint.from_dict(fingerprint_dict())),
    ],
)
def test_artifact_locator_for_raises_only_coded_defects(artifact_type: Any, artifact: Any) -> None:
    with pytest.raises(Bundle7BDefectError) as excinfo:
        b7.artifact_locator_for(artifact_type, artifact)
    assert code_of(excinfo) == "malformed_argument"


def test_record_types_are_immutable(world: World) -> None:
    parsed = world.parsed()
    with pytest.raises(dataclasses.FrozenInstanceError):
        parsed.bundle_outcome = "failed"  # type: ignore[misc]
    assert isinstance(parsed.fact_reconciliations, tuple)
    assert isinstance(parsed.required_metrics, tuple)


@pytest.mark.parametrize("name", ["required_metrics", "fact_reconciliations"])
def test_record_sequence_members_must_be_tuples(world: World, name: str) -> None:
    parsed = world.parsed()
    assert hash(parsed) == hash(world.parsed())
    with pytest.raises(Bundle7BDefectError) as excinfo:
        dataclasses.replace(parsed, **{name: list(getattr(parsed, name))})
    assert code_of(excinfo) == "malformed_member"


@pytest.mark.parametrize(
    ("path", "value", "code"),
    [
        (("$schema",), "smart_ads/certification_7b_record/v2", "fixed_member_mismatch"),
        (("extra",), 1, "closed_member_set"),
        (("bundle_outcome",), DELETE, "closed_member_set"),
        (("bundle_outcome",), "failed", "fixed_member_mismatch"),
        (("required_metrics",), [CLICKS, IMPRESSIONS, SPEND], "fixed_member_mismatch"),
        (("required_metrics",), [IMPRESSIONS, CLICKS], "fixed_member_mismatch"),
        (("required_metrics",), "metric:impressions_v1", "fixed_member_mismatch"),
        (("migration_run_context_locator",), GATE3_LOC.to_dict(), "malformed_member"),
        (("gate3_selection_locator",), RUN_LOC.to_dict(), "malformed_member"),
        (("canonical_query_digest",), sha("e"), "canonical_query_digest_mismatch"),
        (("canonical_query_contract", "tzdb_version"), "2026b", "canonical_query_digest_mismatch"),
        (("canonical_query_contract", "extra"), 1, "malformed_member"),
        (("logical_fact_reconciliation_digest",), sha("e"), "logical_digest_mismatch"),
        (("fact_reconciliations",), [], "malformed_member"),
        (("fact_reconciliations",), "x", "malformed_member"),
        (("fact_reconciliations", 0, "candidate", "raw_numeric_value"), "102",
         "logical_digest_mismatch"),
        (("row_pairing", "canonical_key"), "resource_ref,metric_date", "fixed_member_mismatch"),
        (("row_pairing", "aggregation_rule"), "sum", "fixed_member_mismatch"),
        (("row_pairing", "deduplication_rule"), "none", "fixed_member_mismatch"),
        (("row_pairing", "maximum_retrieval_skew_seconds"), 301, "fixed_member_mismatch"),
        (("row_pairing", "maximum_retrieval_skew_seconds"), "300", "fixed_member_mismatch"),
        (("row_pairing", "maximum_retrieval_skew_seconds"), True, "fixed_member_mismatch"),
        (("row_pairing", "extra"), 1, "closed_member_set"),
    ],
)
def test_record_top_level_members_are_closed_and_recomputed(
    world: World, path: tuple[Any, ...], value: Any, code: str
) -> None:
    assert record_defect(tampered(world.record, path, value)) == code


@pytest.mark.parametrize(
    ("member", "value", "code"),
    [
        ("driver_id", "pipeboard_mcp", "fixed_member_mismatch"),
        ("provider_target_ref", "provider-target:other", "fixed_member_mismatch"),
        ("provider_target_ref", "provider:pipeboard-hosted", "malformed_member"),
        ("admitted_collection_locator", RUN_LOC.to_dict(), "malformed_member"),
        ("effect_proof_locator", GATE3_LOC.to_dict(), "malformed_member"),
        ("registry_snapshot_locator", GATE3_LOC.to_dict(), "malformed_member"),
        ("driver_contract_locator", loc("smart_ads/pipeboard_phase1_contract/v1", "e").to_dict(),
         "driver_contract_digest_mismatch"),
        ("driver_contract_digest", sha("e"), "driver_contract_digest_mismatch"),
        ("source_contract_ref", "opaque-driver-contract:" + sha("e"), "source_contract_mismatch"),
        ("source_contract_ref", sha("e"), "malformed_member"),
        ("wheel_digest", "sha256:XYZ", "malformed_member"),
        ("adapter_code_digest", sha("e"), "fingerprint_member_mismatch"),
        ("parser_code_digest", sha("e"), "fingerprint_member_mismatch"),
        ("mapping_rules_digest", sha("e"), "fingerprint_member_mismatch"),
        ("native_request_projection", native_dict(), "native_version_mismatch"),
        ("native_request_digest", sha("e"), "native_request_digest_mismatch"),
        ("native_to_canonical_projection_algorithm_digest", "x", "malformed_member"),
        ("canonical_query_projection", dict(canonical_query().to_dict(), tzdb_version="2026b"),
         "canonical_query_digest_mismatch"),
        ("canonical_query_projection_digest", sha("e"), "canonical_query_digest_mismatch"),
        ("retrieved_at_utc", "2026-11-11T04:15:00Z", "malformed_member"),
        ("result_status", "partial", "fixed_member_mismatch"),
        ("row_count", 5, "row_count_mismatch"),
        ("row_count", "6", "malformed_member"),
        ("row_count", True, "malformed_member"),
        ("row_count", -1, "malformed_member"),
        ("row_universe_digest", sha("e"), "row_universe_digest_mismatch"),
        ("normalized_fact_set_digest", "sha256:", "malformed_member"),
        ("gate3_certification_fingerprint", {"selected_meta_api_version": "v21.0"},
         "closed_member_set"),
        ("extra", 1, "closed_member_set"),
    ],
)
def test_candidate_execution_members_are_closed_and_cross_checked(
    world: World, member: str, value: Any, code: str
) -> None:
    assert record_defect(tampered(world.record, ("candidate_execution", member), value)) == code


@pytest.mark.parametrize(
    ("member", "value", "code"),
    [
        ("reference_workload_ref", "workload:other", "fixed_member_mismatch"),
        ("provider_target_ref", "provider-target:other", "fixed_member_mismatch"),
        ("admitted_collection_locator", RUN_LOC.to_dict(), "malformed_member"),
        ("effect_proof_locator", RUN_LOC.to_dict(), "malformed_member"),
        ("reference_workload_binary_digest", "x", "malformed_member"),
        ("reference_code_digest", None, "malformed_member"),
        ("source_contract_ref", "api-version:v22.0", "source_contract_mismatch"),
        ("source_contract_ref", "version:v21.0", "malformed_member"),
        ("implementation_kind", "custom_client", "malformed_member"),
        ("native_request_projection", native_dict(endpoint_version_ref="api-version:v22.0"),
         "native_version_mismatch"),
        ("native_request_digest", sha("e"), "native_request_digest_mismatch"),
        ("canonical_query_projection_digest", sha("e"), "canonical_query_digest_mismatch"),
        ("result_status", "complete ", "fixed_member_mismatch"),
        ("row_count", 7, "row_count_mismatch"),
        ("row_universe_digest", sha("e"), "row_universe_digest_mismatch"),
        ("reference_run_digest", "sha256:" + "A" * 64, "malformed_member"),
        ("extra", 1, "closed_member_set"),
    ],
)
def test_reference_execution_members_are_closed_and_cross_checked(
    world: World, member: str, value: Any, code: str
) -> None:
    assert record_defect(tampered(world.record, ("reference_execution", member), value)) == code


def test_record_rejects_a_native_endpoint_version_that_disagrees_with_the_side(
    world: World,
) -> None:
    reference = native_dict(endpoint="/v99.0/insights")
    record = tampered(world.record, ("reference_execution", "native_request_projection"),
                      reference)
    assert record_defect(record) == "native_version_mismatch"
    candidate = copy.deepcopy(world.record["candidate_execution"]["native_request_projection"])
    candidate["endpoint"] = "/v21.0/insights"
    record = tampered(world.record, ("candidate_execution", "native_request_projection"),
                      candidate)
    assert record_defect(record) == "native_version_mismatch"


def test_record_requires_distinct_effect_proofs_and_provider_targets(world: World) -> None:
    same_proof = tampered(world.record, ("reference_execution", "effect_proof_locator"),
                          CAND_EFFECT.to_dict())
    assert record_defect(same_proof) == "effect_proof_not_distinct"
    same_target = tampered(world.record, ("reference_execution", "provider_target_ref"),
                           CANDIDATE_PROVIDER)
    assert record_defect(same_target) == "provider_target_not_distinct"
    swapped = tampered(
        tampered(world.record, ("reference_execution", "provider_target_ref"), CANDIDATE_PROVIDER),
        ("candidate_execution", "provider_target_ref"), REFERENCE_PROVIDER,
    )
    assert record_defect(swapped) == "fixed_member_mismatch"


@pytest.mark.parametrize("member", FINGERPRINT_MEMBERS)
def test_record_fingerprints_must_be_byte_identical_across_sides(world: World, member: str) -> None:
    current = world.record["reference_execution"]["gate3_certification_fingerprint"][member]
    record = tampered(
        world.record,
        ("reference_execution", "gate3_certification_fingerprint", member),
        different_value(member, current),
    )
    expected = "source_contract_mismatch" if member == "selected_meta_api_version" else (
        "fingerprint_mismatch"
    )
    assert record_defect(record) == expected


@pytest.mark.parametrize(
    "member",
    ["candidate_driver_contract_digest", "parser_code_digest", "adapter_code_digest",
     "mapping_rules_digest"],
)
def test_record_per_member_digests_must_equal_the_candidate_fingerprint(
    world: World, member: str
) -> None:
    record = tampered(
        world.record, ("candidate_execution", "gate3_certification_fingerprint", member), sha("e")
    )
    assert record_defect(record) == "fingerprint_member_mismatch"


def test_record_fingerprint_query_digest_must_equal_the_record_query(world: World) -> None:
    record = world.record
    for side in ("candidate_execution", "reference_execution"):
        record = tampered(
            record, (side, "gate3_certification_fingerprint", "canonical_query_digest"), sha("e")
        )
    assert record_defect(record) == "fingerprint_member_mismatch"


def test_record_fingerprint_scope_must_equal_the_record_query_scope(world: World) -> None:
    record = world.record
    for side in ("candidate_execution", "reference_execution"):
        record = tampered(
            record,
            (side, "gate3_certification_fingerprint", "authorized_certification_scope"),
            "scope:other-campaigns",
        )
    assert record_defect(record) == "fingerprint_member_mismatch"


@pytest.mark.parametrize(
    ("ref_at", "code"),
    [
        ("2026-11-11T04:20:00.000000Z", None),
        ("2026-11-11T04:10:00.000000Z", None),
        ("2026-11-11T04:20:01.000000Z", "retrieval_skew_exceeded"),
        ("2026-11-11T04:09:59.999999Z", "retrieval_skew_exceeded"),
    ],
)
def test_record_retrieval_skew_is_at_most_300_seconds(
    world: World, ref_at: str, code: str | None
) -> None:
    record = tampered(world.record, ("reference_execution", "retrieved_at_utc"), ref_at)
    if code is None:
        b7.Certification7BRecord.from_dict(record)
    else:
        assert record_defect(record) == code


def test_record_reconciliations_must_be_complete_ordered_and_unique(world: World) -> None:
    recs = world.record["fact_reconciliations"]
    for bad, code in (
        ([recs[1], recs[0], *recs[2:]], "wrong_order"),
        ([recs[0], *recs], "duplicate_identity"),
        (recs[:-1], "pair_universe_incomplete"),
        ([r for r in recs if r["canonical_metric_ref"] != SPEND], "pair_universe_incomplete"),
    ):
        assert record_defect(reseal(dict(world.record, fact_reconciliations=bad))) == code


def test_record_requires_every_asserted_member_to_be_verified(world: World) -> None:
    unreconciled = dict(
        WITHIN_TOLERANCE_ROW,
        reconciliation_outcome="mismatch",
        metric_verification_status="UNRECONCILED",
    )
    recs = copy.deepcopy(world.record["fact_reconciliations"])
    recs[0].update(unreconciled)
    assert record_defect(reseal(dict(world.record, fact_reconciliations=recs))) == (
        "metric_not_verified"
    )


def test_record_counts_and_row_universe_digests_follow_the_reconciliations(world: World) -> None:
    rows = [row_key(REF_A).to_dict(), row_key(REF_B).to_dict()]
    expected = oracle_domain_digest("SMART-ADS:7B-ROW-UNIVERSE:V1\n", rows)
    assert world.record["candidate_execution"]["row_universe_digest"] == expected
    assert world.record["reference_execution"]["row_count"] == 6


def test_record_requires_the_canonical_query_to_request_exactly_the_sealed_metrics(
    world: World,
) -> None:
    narrower = dataclasses.replace(canonical_query(), metric_semantic_refs=(CLICKS, IMPRESSIONS))
    record = dict(
        world.record,
        canonical_query_contract=narrower.to_dict(),
        canonical_query_digest=narrower.canonical_query_digest,
    )
    assert record_defect(record) == "canonical_query_mismatch"


def test_record_query_metrics_are_checked_even_when_every_projection_agrees(
    world: World,
) -> None:
    narrower = dataclasses.replace(canonical_query(), metric_semantic_refs=(CLICKS, IMPRESSIONS))
    record = dict(
        world.record,
        canonical_query_contract=narrower.to_dict(),
        canonical_query_digest=narrower.canonical_query_digest,
    )
    for side in ("candidate_execution", "reference_execution"):
        record = tampered(record, (side, "canonical_query_projection"), narrower.to_dict())
        record = tampered(
            record, (side, "canonical_query_projection_digest"), narrower.canonical_query_digest
        )
    assert record_defect(record) == "canonical_query_mismatch"


def test_record_candidate_only_version_difference_fails_the_fingerprint(world: World) -> None:
    record = tampered(
        world.record,
        ("candidate_execution", "gate3_certification_fingerprint", "selected_meta_api_version"),
        "v22.0",
    )
    assert record_defect(record) == "fingerprint_mismatch"


def test_record_side_projection_must_equal_the_record_query(world: World) -> None:
    other = dataclasses.replace(canonical_query(), tzdb_version="2026b")
    record = tampered(world.record, ("reference_execution", "canonical_query_projection"),
                      other.to_dict())
    record = tampered(record, ("reference_execution", "canonical_query_projection_digest"),
                      other.canonical_query_digest)
    assert record_defect(record) == "canonical_query_mismatch"


def _sign_p1_dict(data: dict[str, Any]) -> dict[str, Any]:
    signed = copy.deepcopy(data)
    signed["integrity"] = {
        "key_id": KEY_ID,
        "key_registry_snapshot_locator": registry_loc().to_dict(),
    }
    signed["integrity"].update(
        content_digest=p1_content_digest(signed), signature_base64=signature()
    )
    return signed


def _fully_signed_record_dict(record_data: dict[str, Any]) -> dict[str, Any]:
    import hashlib
    from tests.unit._bundle_7b_builders import oracle_jcs

    out = copy.deepcopy(record_data)
    for side in ("candidate_execution", "reference_execution"):
        proj = _sign_p1_dict(out[side]["native_request_projection"])
        out[side]["native_request_projection"] = proj
        out[side]["native_request_digest"] = (
            "sha256:" + hashlib.sha256(oracle_jcs(proj)).hexdigest()
        )
    return _sign_p1_dict(out)


def test_record_p1_integrity_is_recomputed_and_can_be_required(world: World) -> None:
    unsigned = dict(world.record, integrity={
        "key_id": KEY_ID, "key_registry_snapshot_locator": registry_loc().to_dict()
    })
    parsed = b7.Certification7BRecord.from_dict(unsigned)
    assert parsed.to_dict() == unsigned
    with pytest.raises(Bundle7BDefectError) as excinfo:
        b7.Certification7BRecord.from_dict(unsigned, require_signed=True)
    assert code_of(excinfo) == "malformed_member"
    outer_only_signed = _sign_p1_dict(world.record)
    assert b7.Certification7BRecord.from_dict(outer_only_signed).to_dict() == outer_only_signed
    with pytest.raises(Bundle7BDefectError) as excinfo:
        b7.Certification7BRecord.from_dict(outer_only_signed, require_signed=True)
    assert code_of(excinfo) == "closed_member_set"
    signed = _fully_signed_record_dict(world.record)
    assert b7.Certification7BRecord.from_dict(signed, require_signed=True).to_dict() == signed
    for side in ("candidate_execution", "reference_execution"):
        half = copy.deepcopy(world.record)
        for s in ("candidate_execution", "reference_execution"):
            if s != side:
                proj = _sign_p1_dict(half[s]["native_request_projection"])
                half[s]["native_request_projection"] = proj
                half[s]["native_request_digest"] = b7.NativeRequestProjection.from_dict(
                    proj
                ).native_request_digest
            else:
                proj = copy.deepcopy(half[s]["native_request_projection"])
                proj["integrity"] = {
                    "key_id": KEY_ID,
                    "key_registry_snapshot_locator": registry_loc().to_dict(),
                }
                half[s]["native_request_projection"] = proj
                half[s]["native_request_digest"] = b7.NativeRequestProjection.from_dict(
                    proj
                ).native_request_digest
        half_signed = _sign_p1_dict(half)
        with pytest.raises(Bundle7BDefectError) as excinfo:
            b7.Certification7BRecord.from_dict(half_signed, require_signed=True)
        assert code_of(excinfo) == "malformed_member"
    signed["integrity"]["content_digest"] = sha("0")
    assert record_defect(signed) == "integrity_digest_mismatch"


def test_record_from_dict_rejects_non_mappings_and_bad_flags(world: World) -> None:
    for bad in ("record", None, {1: 2}):
        assert record_defect(bad) == "malformed_member"  # type: ignore[arg-type]
    with pytest.raises(Bundle7BDefectError) as excinfo:
        b7.Certification7BRecord.from_dict(
            world.record, require_signed="yes"  # type: ignore[arg-type]
        )
    assert code_of(excinfo) == "malformed_argument"
    for exec_cls, key in (
        (b7.CandidateExecution, "candidate_execution"),
        (b7.ReferenceExecution, "reference_execution"),
    ):
        with pytest.raises(Bundle7BDefectError) as excinfo:
            exec_cls.from_dict(
                world.record[key], require_signed="yes"  # type: ignore[arg-type]
            )
        assert code_of(excinfo) == "malformed_argument"
        with pytest.raises(Bundle7BDefectError) as excinfo:
            exec_cls.from_dict(world.record[key], require_signed=True)
        assert code_of(excinfo) == "closed_member_set"
