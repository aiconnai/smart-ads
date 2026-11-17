"""Tests for smart_ads.analytics.results (ADR-0001 section 6.4, lines 1817-1933)."""
from __future__ import annotations

import base64
import copy
import hashlib
from typing import Any, Callable

import pytest

from smart_ads.analytics.results import (
    AnalysisExecution,
    AnalysisResult,
    AnalysisResultSchema,
    CanonicalResultEntry,
    CanonicalResultSet,
    ResultSetMismatchError,
    verify_analysis_execution,
)
from smart_ads.contracts.jcs import (
    ArtifactLocator,
    P1Integrity,
    canonicalize_jcs,
    p1_content_digest,
)

SCHEMA_TYPE = "smart_ads/analysis_result_schema/v1"
RESULT_TYPE = "smart_ads/analysis_result/v1"
SET_TYPE = "smart_ads/canonical_result_set/v1"
EXECUTION_TYPE = "smart_ads/analysis_execution/v1"


def _raises(code: str, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> None:
    with pytest.raises(ResultSetMismatchError) as info:
        fn(*args, **kwargs)
    assert info.value.code == code, str(info.value)


def _loc(artifact_type: str, seed: str) -> ArtifactLocator:
    return ArtifactLocator.from_digest(artifact_type, "sha256:" + seed * 64)


def _signed(envelope: dict[str, Any]) -> dict[str, Any]:
    """Return a copy with a finalized integrity block over the P1 preimage."""
    out = copy.deepcopy(envelope)
    out["integrity"] = P1Integrity(
        key_id="key:ed25519:" + "b" * 64,
        key_registry_snapshot_locator=_loc("smart_ads/key_authorization_registry/v1", "c"),
    ).to_dict()
    out["integrity"]["content_digest"] = p1_content_digest(out)
    out["integrity"]["signature_base64"] = base64.b64encode(b"\x01" * 64).decode("ascii")
    return out


def _col(name: str, cell_type: str, nullable: bool = False) -> dict[str, Any]:
    return {"name": name, "cell_type": cell_type, "nullable": nullable}


def _schema_dict(
    columns: list[dict[str, Any]], *, kind: str = "relation", unique_key: list[str] | None = None
) -> dict[str, Any]:
    return {
        "$schema": SCHEMA_TYPE,
        "result_kind": kind,
        "columns": copy.deepcopy(columns),
        "unique_key": unique_key,
    }


def _row(ref: str, day: str, spend: str | None) -> list[dict[str, Any]]:
    spend_cell = {"_type": "null", "value": None} if spend is None else {
        "_type": "decimal6",
        "value": spend,
    }
    return [{"_type": "opaque_ref", "value": ref}, {"_type": "date", "value": day}, spend_cell]


REL_COLUMNS = [
    _col("resource_ref", "opaque_ref"),
    _col("day", "date"),
    _col("spend", "decimal6", nullable=True),
]
REL_ROWS = [_row("campaign:b", "2026-11-02", "1.500000"), _row("campaign:a", "2026-11-01", None)]
SCALAR_ROWS = [[{"_type": "int64", "value": "42"}]]
REL_SCHEMA = AnalysisResultSchema.from_dict(
    _schema_dict(REL_COLUMNS, unique_key=["day", "resource_ref"])
)
SCALAR_SCHEMA = AnalysisResultSchema.from_dict(
    _schema_dict([_col("total", "int64")], kind="scalar")
)


def _projection_dict(
    schema: AnalysisResultSchema, rows: list[list[dict[str, Any]]] | None = None
) -> dict[str, Any]:
    body_rows = copy.deepcopy(REL_ROWS if rows is None else rows)
    schema_dict = schema.to_dict()
    return {
        "result_kind": schema_dict["result_kind"],
        "analysis_result_schema_locator": ArtifactLocator.for_canonical_bytes(
            SCHEMA_TYPE, canonicalize_jcs(schema_dict)
        ).to_dict(),
        "columns": copy.deepcopy(schema_dict["columns"]),
        "rows": body_rows,
        "row_count": len(body_rows),
    }


# ---------------------------------------------------------------- analysis_result/v1

BUNDLE = _loc("smart_ads/analysis_replay_input_bundle/v1", "1")
SNAPSHOT = _loc("smart_ads/dataset_snapshot/v1", "2")
RUN = _loc("smart_ads/migration_run_context/v1", "3")
OTHER_BUNDLE = _loc("smart_ads/analysis_replay_input_bundle/v1", "4")
OTHER_SNAPSHOT = _loc("smart_ads/dataset_snapshot/v1", "5")
LOCATOR_MEMBERS = (
    "$schema",
    "artifact_type",
    "content_digest",
    "serialization",
    "store_kind",
    "object_ref",
)


def _result_dict(
    key: str,
    *,
    scalar: bool = False,
    bundle: ArtifactLocator = BUNDLE,
    snapshot: ArtifactLocator = SNAPSHOT,
) -> dict[str, Any]:
    projection = (
        _projection_dict(SCALAR_SCHEMA, SCALAR_ROWS) if scalar else _projection_dict(REL_SCHEMA)
    )
    return {
        "$schema": RESULT_TYPE,
        "migration_run_context_locator": RUN.to_dict(),
        "dataset_snapshot_locator": snapshot.to_dict(),
        "replay_input_bundle_locator": bundle.to_dict(),
        "result_key": key,
        "result_projection": projection,
    }


RESULT_A = AnalysisResult.from_dict(_result_dict("metric:a"))
RESULT_B = AnalysisResult.from_dict(_result_dict("metric:b", scalar=True))
RESULT_C = AnalysisResult.from_dict(_result_dict("metric:c", scalar=True))


def _result_locator(result: AnalysisResult) -> ArtifactLocator:
    return ArtifactLocator.for_canonical_bytes(RESULT_TYPE, canonicalize_jcs(result.to_dict()))


def _entry(result: AnalysisResult) -> dict[str, Any]:
    return {
        "result_key": result.result_key,
        "result_locator": _result_locator(result).to_dict(),
        "result_projection": result.result_projection.to_dict(),
    }


def _digest_of(preimage: object) -> str:
    return "sha256:" + hashlib.sha256(canonicalize_jcs(preimage)).hexdigest()


def _set_dict(
    entries: list[dict[str, Any]], *, bundle: ArtifactLocator = BUNDLE
) -> dict[str, Any]:
    preimage = {
        "$schema": SET_TYPE,
        "analysis_replay_input_bundle_locator": bundle.to_dict(),
        "results": copy.deepcopy(entries),
    }
    return {**preimage, "canonical_result_digest": _digest_of(preimage)}


def _execution_dict(
    set_dict: dict[str, Any] | None = None, *, bundle: ArtifactLocator = BUNDLE
) -> dict[str, Any]:
    if set_dict is None:
        set_dict = _set_dict([_entry(RESULT_A), _entry(RESULT_B)])
    return {
        "$schema": EXECUTION_TYPE,
        "analysis_replay_input_bundle_locator": bundle.to_dict(),
        "canonical_result_set": copy.deepcopy(set_dict),
    }


def _redigest(set_dict: dict[str, Any]) -> dict[str, Any]:
    preimage = {k: v for k, v in set_dict.items() if k != "canonical_result_digest"}
    return {**preimage, "canonical_result_digest": _digest_of(preimage)}


def test_analysis_result_round_trip_and_key_set() -> None:
    data = _result_dict("metric:a")
    result = AnalysisResult.from_dict(data)
    assert result.to_dict() == data
    assert set(data) == {
        "$schema",
        "migration_run_context_locator",
        "dataset_snapshot_locator",
        "replay_input_bundle_locator",
        "result_key",
        "result_projection",
    }
    assert result.locator() == _result_locator(result)
    signed = AnalysisResult.from_dict(_signed(data), require_signed=True)
    assert set(signed.to_dict()) == set(data) | {"integrity"}


@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        (lambda d: d.update(analysis_execution_locator=_loc(EXECUTION_TYPE, "9").to_dict()), "alternate_wrapper"),
        (lambda d: d.pop("migration_run_context_locator"), "alternate_wrapper"),
        (lambda d: d.update({"$schema": SET_TYPE}), "alternate_wrapper"),
        (lambda d: d.update(dataset_snapshot_locator=BUNDLE.to_dict()), "invalid_locator"),
        (lambda d: d.update(replay_input_bundle_locator=SNAPSHOT.to_dict()), "invalid_locator"),
        (lambda d: d.update(migration_run_context_locator=SNAPSHOT.to_dict()), "invalid_locator"),
        (lambda d: d.update(result_key=""), "field_invalid"),
        (lambda d: d.update(result_key=" "), "field_invalid"),
        (lambda d: d.update(result_key=1), "field_invalid"),
        (lambda d: d.update(result_key="café"), "field_invalid"),
        (lambda d: d["result_projection"].update(row_count=9), "row_count_mismatch"),
    ],
)
def test_analysis_result_rejections(mutate: Callable[[dict[str, Any]], Any], code: str) -> None:
    data = _result_dict("metric:a")
    mutate(data)
    _raises(code, AnalysisResult.from_dict, data)


def test_analysis_result_p1_integrity_is_recomputed() -> None:
    signed = _signed(_result_dict("metric:a"))
    signed["result_key"] = "metric:z"
    _raises("integrity_mismatch", AnalysisResult.from_dict, signed)


# ---------------------------------------------------------------- canonical_result_set/v1


def test_result_set_round_trip_key_set_and_digest() -> None:
    data = _set_dict([_entry(RESULT_A), _entry(RESULT_B)])
    result_set = CanonicalResultSet.from_dict(data)
    assert result_set.to_dict() == data
    assert set(data) == {
        "$schema",
        "analysis_replay_input_bundle_locator",
        "results",
        "canonical_result_digest",
    }
    assert set(data["results"][0]) == {"result_key", "result_locator", "result_projection"}
    preimage = {k: v for k, v in data.items() if k != "canonical_result_digest"}
    assert result_set.preimage() == preimage
    assert result_set.canonical_result_digest == _digest_of(preimage)
    built = CanonicalResultSet.build(
        BUNDLE,
        [CanonicalResultEntry.from_result(RESULT_A), CanonicalResultEntry.from_result(RESULT_B)],
    )
    assert built == result_set


def test_result_set_orders_by_raw_utf8_bytes_not_utf16() -> None:
    # U+FF61 < U+1F600 in UTF-8 bytes, but the surrogate pair sorts first in UTF-16.
    low = AnalysisResult.from_dict(_result_dict("k｡", scalar=True))
    high = AnalysisResult.from_dict(_result_dict("k\U0001f600", scalar=True))
    CanonicalResultSet.from_dict(_set_dict([_entry(low), _entry(high)]))
    _raises(
        "results_unordered",
        CanonicalResultSet.from_dict,
        _set_dict([_entry(high), _entry(low)]),
    )


@pytest.mark.parametrize(
    ("build", "code"),
    [
        (lambda: _set_dict([]), "empty_result_set"),
        (lambda: _set_dict([_entry(RESULT_A), _entry(RESULT_A)]), "duplicate_result"),
        (lambda: _set_dict([_entry(RESULT_B), _entry(RESULT_A)]), "results_unordered"),
        (lambda: {**_set_dict([_entry(RESULT_A)]), "canonical_result_digest": "sha256:" + "0" * 64}, "digest_mismatch"),
        (lambda: {**_set_dict([_entry(RESULT_A)]), "canonical_result_digest": None}, "field_invalid"),
        (lambda: {**_set_dict([_entry(RESULT_A)]), "canonical_result_digest": ""}, "field_invalid"),
        (lambda: {**_set_dict([_entry(RESULT_A)]), "result_set_digest": "sha256:" + "0" * 64}, "alternate_wrapper"),
        (lambda: {k: v for k, v in _set_dict([_entry(RESULT_A)]).items() if k != "canonical_result_digest"}, "alternate_wrapper"),
        (lambda: {**_set_dict([_entry(RESULT_A)]), "$schema": EXECUTION_TYPE}, "alternate_wrapper"),
        (lambda: _set_dict([{**_entry(RESULT_A), "result_digest": "sha256:" + "0" * 64}]), "alternate_wrapper"),
        (lambda: _set_dict([{**_entry(RESULT_A), "result_locator": BUNDLE.to_dict()}]), "invalid_locator"),
        (lambda: _redigest({**_set_dict([_entry(RESULT_A)]), "results": "x"}), "field_invalid"),
        (lambda: _set_dict([_entry(RESULT_A)], bundle=SNAPSHOT), "invalid_locator"),
    ],
)
def test_result_set_rejections(build: Callable[[], Any], code: str) -> None:
    _raises(code, CanonicalResultSet.from_dict, build())


@pytest.mark.parametrize(
    "alternate_preimage",
    [
        lambda p: {**p, "canonical_result_digest": None},
        lambda p: {**p, "canonical_result_digest": ""},
        lambda p: {**p, "$schema": "smart_ads/analysis_execution/v1"},
        lambda p: {"canonical_result_set": p},
        lambda p: p["results"],
    ],
)
def test_result_set_rejects_digest_over_alternate_preimage(
    alternate_preimage: Callable[[dict[str, Any]], Any],
) -> None:
    good = _set_dict([_entry(RESULT_A)])
    preimage = {k: v for k, v in good.items() if k != "canonical_result_digest"}
    bad = {**preimage, "canonical_result_digest": _digest_of(alternate_preimage(preimage))}
    _raises("digest_mismatch", CanonicalResultSet.from_dict, bad)


def test_result_set_rejects_domain_separated_digest() -> None:
    good = _set_dict([_entry(RESULT_A)])
    preimage = {k: v for k, v in good.items() if k != "canonical_result_digest"}
    raw = b"SMART-ADS:ANALYSIS-EXECUTION:V1\n\x00" + canonicalize_jcs(preimage)
    bad = {**preimage, "canonical_result_digest": "sha256:" + hashlib.sha256(raw).hexdigest()}
    _raises("digest_mismatch", CanonicalResultSet.from_dict, bad)


# ---------------------------------------------------------------- analysis_execution/v1


def test_execution_round_trip_and_key_set() -> None:
    data = _execution_dict()
    execution = AnalysisExecution.from_dict(data)
    assert execution.to_dict() == data
    assert set(data) == {"$schema", "analysis_replay_input_bundle_locator", "canonical_result_set"}
    assert execution.locator() == ArtifactLocator.for_canonical_bytes(
        EXECUTION_TYPE, canonicalize_jcs(data)
    )
    signed = _signed(data)
    assert set(AnalysisExecution.from_dict(signed, require_signed=True).to_dict()) == set(data) | {
        "integrity"
    }
    tampered = copy.deepcopy(signed)
    tampered["canonical_result_set"] = _set_dict([_entry(RESULT_A)])
    _raises("integrity_mismatch", AnalysisExecution.from_dict, tampered)


@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        (lambda d: d.update(canonical_result_digest=d["canonical_result_set"]["canonical_result_digest"]), "alternate_wrapper"),
        (lambda d: d.update(result_set_digest="sha256:" + "0" * 64), "alternate_wrapper"),
        (lambda d: d.update(analysis_replay_input_bundle_digest=BUNDLE.content_digest), "alternate_wrapper"),
        (lambda d: d.pop("canonical_result_set"), "alternate_wrapper"),
        (lambda d: d.update({"$schema": SET_TYPE}), "alternate_wrapper"),
        (lambda d: d.update(analysis_replay_input_bundle_locator=BUNDLE.content_digest), "invalid_locator"),
        (lambda d: d.update(analysis_replay_input_bundle_locator=OTHER_BUNDLE.to_dict()), "bundle_locator_mismatch"),
    ],
)
def test_execution_rejections(mutate: Callable[[dict[str, Any]], Any], code: str) -> None:
    data = _execution_dict()
    mutate(data)
    _raises(code, AnalysisExecution.from_dict, data)


# ---------------------------------------------------------------- verify_analysis_execution


def test_verifier_accepts_complete_execution_in_any_resolution_order() -> None:
    data = _execution_dict()
    verified = verify_analysis_execution(data, [RESULT_B, RESULT_A], SNAPSHOT)
    assert isinstance(verified, AnalysisExecution)
    assert verified.to_dict() == data
    again = verify_analysis_execution(
        AnalysisExecution.from_dict(data), [RESULT_A.to_dict(), RESULT_B], SNAPSHOT
    )
    assert again == verified


def test_verifier_rejects_duplicate_result_in_set() -> None:
    data = _execution_dict(_set_dict([_entry(RESULT_A), _entry(RESULT_A)]))
    _raises("duplicate_result", verify_analysis_execution, data, [RESULT_A], SNAPSHOT)


def test_verifier_rejects_duplicate_resolved_result() -> None:
    _raises(
        "duplicate_result",
        verify_analysis_execution,
        _execution_dict(),
        [RESULT_A, RESULT_B, RESULT_A],
        SNAPSHOT,
    )


def test_verifier_rejects_reorder() -> None:
    data = _execution_dict(_set_dict([_entry(RESULT_B), _entry(RESULT_A)]))
    _raises("results_unordered", verify_analysis_execution, data, [RESULT_A, RESULT_B], SNAPSHOT)


def test_verifier_rejects_missing_result() -> None:
    _raises(
        "missing_result",
        verify_analysis_execution,
        _execution_dict(),
        [RESULT_A, RESULT_B, RESULT_C],
        SNAPSHOT,
    )


def test_verifier_rejects_extra_result() -> None:
    _raises("extra_result", verify_analysis_execution, _execution_dict(), [RESULT_A], SNAPSHOT)


def test_verifier_rejects_projection_mismatch() -> None:
    entry_b = _entry(RESULT_B)
    entry_b["result_projection"]["rows"][0][0]["value"] = "43"
    data = _execution_dict(_set_dict([_entry(RESULT_A), entry_b]))
    _raises("projection_mismatch", verify_analysis_execution, data, [RESULT_A, RESULT_B], SNAPSHOT)


def test_verifier_rejects_result_locator_mismatch() -> None:
    entry_b = _entry(RESULT_B)
    entry_b["result_locator"] = _result_locator(RESULT_C).to_dict()
    data = _execution_dict(_set_dict([_entry(RESULT_A), entry_b]))
    _raises(
        "result_locator_mismatch", verify_analysis_execution, data, [RESULT_A, RESULT_B], SNAPSHOT
    )


def test_verifier_rejects_cross_snapshot_result() -> None:
    foreign = AnalysisResult.from_dict(_result_dict("metric:b", scalar=True, snapshot=OTHER_SNAPSHOT))
    data = _execution_dict(_set_dict([_entry(RESULT_A), _entry(foreign)]))
    _raises("cross_snapshot_result", verify_analysis_execution, data, [RESULT_A, foreign], SNAPSHOT)
    # the bundle snapshot is the explicit parameter: a different one rejects everything
    _raises(
        "cross_snapshot_result",
        verify_analysis_execution,
        _execution_dict(),
        [RESULT_A, RESULT_B],
        OTHER_SNAPSHOT,
    )


def test_verifier_rejects_result_bound_to_another_bundle() -> None:
    foreign = AnalysisResult.from_dict(_result_dict("metric:b", scalar=True, bundle=OTHER_BUNDLE))
    data = _execution_dict(_set_dict([_entry(RESULT_A), _entry(foreign)]))
    _raises(
        "bundle_locator_mismatch", verify_analysis_execution, data, [RESULT_A, foreign], SNAPSHOT
    )


def test_verifier_rejects_execution_and_set_bundle_disagreement() -> None:
    data = _execution_dict(bundle=OTHER_BUNDLE)
    _raises(
        "bundle_locator_mismatch", verify_analysis_execution, data, [RESULT_A, RESULT_B], SNAPSHOT
    )


def _single_member_variants(locator: ArtifactLocator) -> list[tuple[str, dict[str, Any]]]:
    replacement = {
        "$schema": "smart_ads/artifact_locator/v2",
        "artifact_type": "smart_ads/dataset_catalog/v1",
        "content_digest": "sha256:" + "e" * 64,
        "serialization": "json",
        "store_kind": "git_blob",
        "object_ref": "cell-object:sha256:" + "e" * 64,
    }
    return [(member, {**locator.to_dict(), member: replacement[member]}) for member in LOCATOR_MEMBERS]


@pytest.mark.parametrize("position", ["execution", "result_set", "result"])
@pytest.mark.parametrize("member", LOCATOR_MEMBERS)
def test_verifier_rejects_bundle_locator_differing_in_any_single_member(
    position: str, member: str
) -> None:
    variant = dict(_single_member_variants(BUNDLE))[member]
    data = _execution_dict()
    resolved: list[Any] = [RESULT_A, RESULT_B]
    if position == "execution":
        data["analysis_replay_input_bundle_locator"] = variant
    elif position == "result_set":
        data["canonical_result_set"]["analysis_replay_input_bundle_locator"] = variant
        data["canonical_result_set"] = _redigest(data["canonical_result_set"])
    else:
        raw = RESULT_B.to_dict()
        raw["replay_input_bundle_locator"] = variant
        resolved = [RESULT_A, raw]
    _raises("invalid_locator", verify_analysis_execution, data, resolved, SNAPSHOT)


@pytest.mark.parametrize("member", LOCATOR_MEMBERS)
def test_verifier_rejects_snapshot_locator_differing_in_any_single_member(member: str) -> None:
    variant = dict(_single_member_variants(SNAPSHOT))[member]
    raw = RESULT_B.to_dict()
    raw["dataset_snapshot_locator"] = variant
    _raises("invalid_locator", verify_analysis_execution, _execution_dict(), [RESULT_A, raw], SNAPSHOT)


@pytest.mark.parametrize(
    "snapshot",
    [
        BUNDLE,
        SNAPSHOT.to_dict(),
        SNAPSHOT.content_digest,
        None,
    ],
)
def test_verifier_requires_typed_bundle_snapshot_locator(snapshot: object) -> None:
    _raises(
        "invalid_locator",
        verify_analysis_execution,
        _execution_dict(),
        [RESULT_A, RESULT_B],
        snapshot,
    )


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.update(canonical_result_digest=d["canonical_result_set"]["canonical_result_digest"]),
        lambda d: d["canonical_result_set"].update(result_digest="sha256:" + "0" * 64),
        lambda d: d.update(canonical_result_set={"wrapped": d["canonical_result_set"]}),
    ],
)
def test_verifier_rejects_alternate_wrapper(mutate: Callable[[dict[str, Any]], Any]) -> None:
    data = _execution_dict()
    mutate(data)
    _raises("alternate_wrapper", verify_analysis_execution, data, [RESULT_A, RESULT_B], SNAPSHOT)


def test_verifier_rejects_alternate_preimage_digest() -> None:
    data = _execution_dict()
    result_set = data["canonical_result_set"]
    preimage = {k: v for k, v in result_set.items() if k != "canonical_result_digest"}
    result_set["canonical_result_digest"] = _digest_of({**preimage, "canonical_result_digest": None})
    _raises("digest_mismatch", verify_analysis_execution, data, [RESULT_A, RESULT_B], SNAPSHOT)


@pytest.mark.parametrize(
    "resolved",
    [
        {RESULT_A.locator(): RESULT_A},
        "x",
        None,
        [RESULT_A, 1],
    ],
)
def test_verifier_rejects_malformed_resolved_results(resolved: object) -> None:
    _raises("field_invalid", verify_analysis_execution, _execution_dict(), resolved, SNAPSHOT)


def test_verifier_does_not_mutate_inputs() -> None:
    data = _execution_dict()
    before = copy.deepcopy(data)
    resolved = [RESULT_A.to_dict(), RESULT_B.to_dict()]
    resolved_before = copy.deepcopy(resolved)
    verify_analysis_execution(data, resolved, SNAPSHOT)
    assert data == before
    assert resolved == resolved_before
