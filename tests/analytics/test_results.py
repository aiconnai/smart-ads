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
SCHEMAS = [REL_SCHEMA, SCALAR_SCHEMA]


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
    "$schema", "artifact_type", "content_digest", "serialization", "store_kind", "object_ref",
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
    verified = verify_analysis_execution(data, [RESULT_B, RESULT_A], SCHEMAS, SNAPSHOT)
    assert isinstance(verified, AnalysisExecution)
    assert verified.to_dict() == data
    again = verify_analysis_execution(
        AnalysisExecution.from_dict(data),
        [RESULT_A.to_dict(), RESULT_B],
        [SCALAR_SCHEMA.to_dict(), REL_SCHEMA],
        SNAPSHOT,
    )
    assert again == verified


def test_verifier_rejects_duplicate_result_in_set() -> None:
    data = _execution_dict(_set_dict([_entry(RESULT_A), _entry(RESULT_A)]))
    _raises("duplicate_result", verify_analysis_execution, data, [RESULT_A], SCHEMAS, SNAPSHOT)


def test_verifier_rejects_duplicate_resolved_result() -> None:
    _raises(
        "duplicate_result",
        verify_analysis_execution,
        _execution_dict(),
        [RESULT_A, RESULT_B, RESULT_A],
        SCHEMAS,
        SNAPSHOT,
    )


def test_verifier_rejects_reorder() -> None:
    data = _execution_dict(_set_dict([_entry(RESULT_B), _entry(RESULT_A)]))
    _raises("results_unordered", verify_analysis_execution, data, [RESULT_A, RESULT_B], SCHEMAS, SNAPSHOT)


def test_verifier_rejects_missing_result() -> None:
    _raises(
        "missing_result",
        verify_analysis_execution,
        _execution_dict(),
        [RESULT_A, RESULT_B, RESULT_C],
        SCHEMAS,
        SNAPSHOT,
    )


def test_verifier_rejects_extra_result() -> None:
    _raises("extra_result", verify_analysis_execution, _execution_dict(), [RESULT_A], SCHEMAS, SNAPSHOT)


def test_verifier_rejects_projection_mismatch() -> None:
    entry_b = _entry(RESULT_B)
    entry_b["result_projection"]["rows"][0][0]["value"] = "43"
    data = _execution_dict(_set_dict([_entry(RESULT_A), entry_b]))
    _raises("projection_mismatch", verify_analysis_execution, data, [RESULT_A, RESULT_B], SCHEMAS, SNAPSHOT)


def test_verifier_rejects_result_locator_mismatch() -> None:
    entry_b = _entry(RESULT_B)
    entry_b["result_locator"] = _result_locator(RESULT_C).to_dict()
    data = _execution_dict(_set_dict([_entry(RESULT_A), entry_b]))
    _raises(
        "result_locator_mismatch", verify_analysis_execution, data, [RESULT_A, RESULT_B], SCHEMAS, SNAPSHOT
    )


def test_verifier_rejects_cross_snapshot_result() -> None:
    foreign = AnalysisResult.from_dict(_result_dict("metric:b", scalar=True, snapshot=OTHER_SNAPSHOT))
    data = _execution_dict(_set_dict([_entry(RESULT_A), _entry(foreign)]))
    _raises("cross_snapshot_result", verify_analysis_execution, data, [RESULT_A, foreign], SCHEMAS, SNAPSHOT)
    # the bundle snapshot is the explicit parameter: a different one rejects everything
    _raises(
        "cross_snapshot_result",
        verify_analysis_execution,
        _execution_dict(),
        [RESULT_A, RESULT_B],
        SCHEMAS,
        OTHER_SNAPSHOT,
    )


def test_verifier_rejects_result_bound_to_another_bundle() -> None:
    foreign = AnalysisResult.from_dict(_result_dict("metric:b", scalar=True, bundle=OTHER_BUNDLE))
    data = _execution_dict(_set_dict([_entry(RESULT_A), _entry(foreign)]))
    _raises(
        "bundle_locator_mismatch", verify_analysis_execution, data, [RESULT_A, foreign], SCHEMAS, SNAPSHOT
    )


def test_verifier_rejects_execution_and_set_bundle_disagreement() -> None:
    data = _execution_dict(bundle=OTHER_BUNDLE)
    _raises(
        "bundle_locator_mismatch", verify_analysis_execution, data, [RESULT_A, RESULT_B], SCHEMAS, SNAPSHOT
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
    _raises("invalid_locator", verify_analysis_execution, data, resolved, SCHEMAS, SNAPSHOT)


@pytest.mark.parametrize("member", LOCATOR_MEMBERS)
def test_verifier_rejects_snapshot_locator_differing_in_any_single_member(member: str) -> None:
    variant = dict(_single_member_variants(SNAPSHOT))[member]
    raw = RESULT_B.to_dict()
    raw["dataset_snapshot_locator"] = variant
    _raises("invalid_locator", verify_analysis_execution, _execution_dict(), [RESULT_A, raw], SCHEMAS, SNAPSHOT)


@pytest.mark.parametrize("snapshot", [BUNDLE, SNAPSHOT.to_dict(), SNAPSHOT.content_digest, None])
def test_verifier_requires_typed_bundle_snapshot_locator(snapshot: object) -> None:
    _raises(
        "invalid_locator",
        verify_analysis_execution,
        _execution_dict(),
        [RESULT_A, RESULT_B],
        SCHEMAS,
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
    _raises("alternate_wrapper", verify_analysis_execution, data, [RESULT_A, RESULT_B], SCHEMAS, SNAPSHOT)


def test_verifier_rejects_alternate_preimage_digest() -> None:
    data = _execution_dict()
    result_set = data["canonical_result_set"]
    preimage = {k: v for k, v in result_set.items() if k != "canonical_result_digest"}
    result_set["canonical_result_digest"] = _digest_of({**preimage, "canonical_result_digest": None})
    _raises("digest_mismatch", verify_analysis_execution, data, [RESULT_A, RESULT_B], SCHEMAS, SNAPSHOT)


@pytest.mark.parametrize("resolved", [{RESULT_A.locator(): RESULT_A}, "x", None, [RESULT_A, 1]])
def test_verifier_rejects_malformed_resolved_results(resolved: object) -> None:
    _raises("field_invalid", verify_analysis_execution, _execution_dict(), resolved, SCHEMAS, SNAPSHOT)


def test_verifier_does_not_mutate_inputs() -> None:
    data = _execution_dict()
    before = copy.deepcopy(data)
    resolved = [RESULT_A.to_dict(), RESULT_B.to_dict()]
    resolved_before = copy.deepcopy(resolved)
    verify_analysis_execution(data, resolved, SCHEMAS, SNAPSHOT)
    assert data == before
    assert resolved == resolved_before


# ---------------------------------------------------------------- resolved schemas in the verifier


def _result_with(
    key: str, schema: AnalysisResultSchema, rows: list[Any], *, signed: bool = False
) -> AnalysisResult:
    data = {**_result_dict(key), "result_projection": _projection_dict(schema, rows)}
    return AnalysisResult.from_dict(_signed(data) if signed else data)


def test_verifier_checks_uniqueness_against_resolved_schema() -> None:
    dup = _result_with("metric:a", REL_SCHEMA, [REL_ROWS[0], REL_ROWS[0]])
    data = _execution_dict(_set_dict([_entry(dup), _entry(RESULT_B)]))
    _raises("duplicate_row", verify_analysis_execution, data, [dup, RESULT_B], SCHEMAS, SNAPSHOT)


def test_verifier_rejects_inline_columns_differing_from_resolved_schema() -> None:
    projection = _projection_dict(SCALAR_SCHEMA, SCALAR_ROWS)
    projection["columns"] = [_col("total", "int64", nullable=True)]
    drifted = AnalysisResult.from_dict({**_result_dict("metric:b"), "result_projection": projection})
    data = _execution_dict(_set_dict([_entry(RESULT_A), _entry(drifted)]))
    _raises("schema_mismatch", verify_analysis_execution, data, [RESULT_A, drifted], SCHEMAS, SNAPSHOT)


def test_verifier_rejects_result_whose_schema_was_not_supplied() -> None:
    _raises(
        "schema_unresolved",
        verify_analysis_execution,
        _execution_dict(),
        [RESULT_A, RESULT_B],
        [REL_SCHEMA],
        SNAPSHOT,
    )
    projection = _projection_dict(SCALAR_SCHEMA, SCALAR_ROWS)
    projection["analysis_result_schema_locator"] = _loc(SCHEMA_TYPE, "f").to_dict()
    ghost = AnalysisResult.from_dict({**_result_dict("metric:b"), "result_projection": projection})
    data = _execution_dict(_set_dict([_entry(RESULT_A), _entry(ghost)]))
    _raises("schema_unresolved", verify_analysis_execution, data, [RESULT_A, ghost], SCHEMAS, SNAPSHOT)


def test_verifier_rejects_duplicate_supplied_schema() -> None:
    _raises(
        "duplicate_schema",
        verify_analysis_execution,
        _execution_dict(),
        [RESULT_A, RESULT_B],
        [REL_SCHEMA, SCALAR_SCHEMA, REL_SCHEMA.to_dict()],
        SNAPSHOT,
    )


def test_verifier_rejects_unreferenced_schema() -> None:
    unused = AnalysisResultSchema.from_dict(_schema_dict(REL_COLUMNS))
    _raises(
        "unreferenced_schema",
        verify_analysis_execution,
        _execution_dict(),
        [RESULT_A, RESULT_B],
        [*SCHEMAS, unused],
        SNAPSHOT,
    )


@pytest.mark.parametrize(
    ("schemas", "code"),
    [
        ({REL_SCHEMA.locator(): REL_SCHEMA}, "field_invalid"),
        ("x", "field_invalid"),
        (None, "field_invalid"),
        ([REL_SCHEMA, 1], "field_invalid"),
        ([REL_SCHEMA, {**SCALAR_SCHEMA.to_dict(), "extra": 1}], "alternate_wrapper"),
    ],
)
def test_verifier_rejects_malformed_resolved_schemas(schemas: object, code: str) -> None:
    _raises(code, verify_analysis_execution, _execution_dict(), [RESULT_A, RESULT_B], schemas, SNAPSHOT)


# ---------------------------------------------------------------- signed artifacts


def _signed_world() -> tuple[dict[str, Any], list[AnalysisResult], list[AnalysisResultSchema]]:
    rel = AnalysisResultSchema.from_dict(_signed(REL_SCHEMA.to_dict()))
    scalar = AnalysisResultSchema.from_dict(_signed(SCALAR_SCHEMA.to_dict()))
    result_a = _result_with("metric:a", rel, REL_ROWS, signed=True)
    result_b = _result_with("metric:b", scalar, SCALAR_ROWS, signed=True)
    execution = _signed(_execution_dict(_set_dict([_entry(result_a), _entry(result_b)])))
    return execution, [result_a, result_b], [rel, scalar]


def test_signed_result_locator_hashes_the_full_signed_bytes() -> None:
    _, (signed_a, _), _ = _signed_world()
    assert signed_a.integrity is not None and signed_a.integrity.is_signed
    by_hand = "sha256:" + hashlib.sha256(canonicalize_jcs(signed_a.to_dict())).hexdigest()
    assert signed_a.locator().content_digest == by_hand
    assert signed_a.locator().content_digest != signed_a.integrity.content_digest


def test_verifier_accepts_fully_signed_execution_with_require_signed() -> None:
    execution, results, schemas = _signed_world()
    verified = verify_analysis_execution(execution, results, schemas, SNAPSHOT, require_signed=True)
    assert verified.integrity is not None and verified.integrity.is_signed
    again = verify_analysis_execution(
        verified,
        [r.to_dict() for r in results],
        [s.to_dict() for s in schemas],
        SNAPSHOT,
        require_signed=True,
    )
    assert again == verified
    assert verify_analysis_execution(execution, results, schemas, SNAPSHOT) == verified


@pytest.mark.parametrize("which", ["execution", "result", "schema", "unsigned_integrity"])
def test_require_signed_rejects_parsed_objects_without_signature(which: str) -> None:
    execution, results, schemas = _signed_world()
    parsed: Any = AnalysisExecution.from_dict(execution)
    if which == "execution":
        parsed = AnalysisExecution(
            parsed.analysis_replay_input_bundle_locator, parsed.canonical_result_set
        )
    elif which == "result":
        results = [RESULT_A, results[1]]
    elif which == "schema":
        schemas = [REL_SCHEMA, schemas[1]]
    else:
        unsigned_integrity = P1Integrity.from_dict(
            {k: v for k, v in execution["integrity"].items() if k in ("key_id", "key_registry_snapshot_locator")}
        )
        schemas = [AnalysisResultSchema(s.result_kind, s.columns, s.unique_key, unsigned_integrity) for s in schemas]
    _raises(
        "unsigned_artifact",
        verify_analysis_execution,
        parsed,
        results,
        schemas,
        SNAPSHOT,
        require_signed=True,
    )


@pytest.mark.parametrize("which", ["execution", "result", "schema"])
def test_require_signed_rejects_unsigned_mappings(which: str) -> None:
    execution, results, schemas = _signed_world()
    raw_exec: Any = execution
    raw_results: list[Any] = list(results)
    raw_schemas: list[Any] = list(schemas)
    if which == "execution":
        raw_exec = _execution_dict()
    elif which == "result":
        raw_results = [RESULT_A.to_dict(), results[1]]
    else:
        raw_schemas = [REL_SCHEMA.to_dict(), schemas[1]]
    _raises(
        "alternate_wrapper",
        verify_analysis_execution,
        raw_exec,
        raw_results,
        raw_schemas,
        SNAPSHOT,
        require_signed=True,
    )


@pytest.mark.parametrize("flag", [1, "yes", None])
def test_require_signed_flag_is_a_strict_bool(flag: object) -> None:
    _raises(
        "field_invalid",
        verify_analysis_execution,
        _execution_dict(),
        [RESULT_A, RESULT_B],
        SCHEMAS,
        SNAPSHOT,
        require_signed=flag,
    )


# ---------------------------------------------------------------- additional verifier pins


def test_verifier_rejects_row_reorder_inside_one_projection() -> None:
    entry_a = _entry(RESULT_A)
    entry_a["result_projection"]["rows"].reverse()
    data = _execution_dict(_set_dict([entry_a, _entry(RESULT_B)]))
    _raises("projection_mismatch", verify_analysis_execution, data, [RESULT_A, RESULT_B], SCHEMAS, SNAPSHOT)


def test_verifier_rejects_alternate_wrapper_on_a_resolved_result() -> None:
    raw = {**RESULT_B.to_dict(), "analysis_execution_locator": _loc(EXECUTION_TYPE, "9").to_dict()}
    _raises("alternate_wrapper", verify_analysis_execution, _execution_dict(), [RESULT_A, raw], SCHEMAS, SNAPSHOT)


def test_verifier_rejects_result_set_bundle_differing_from_expected_execution_bundle() -> None:
    data = _execution_dict(_set_dict([_entry(RESULT_A), _entry(RESULT_B)], bundle=OTHER_BUNDLE))
    assert data["analysis_replay_input_bundle_locator"] == BUNDLE.to_dict()
    _raises("bundle_locator_mismatch", verify_analysis_execution, data, [RESULT_A, RESULT_B], SCHEMAS, SNAPSHOT)


def test_mixed_type_keys_reject_with_a_closed_code_through_the_verifier() -> None:
    data: dict[Any, Any] = {**_execution_dict(), 1: 1}
    _raises("alternate_wrapper", verify_analysis_execution, data, [RESULT_A, RESULT_B], SCHEMAS, SNAPSHOT)
    raw: dict[Any, Any] = {**RESULT_B.to_dict(), 1: 1}
    _raises("alternate_wrapper", verify_analysis_execution, _execution_dict(), [RESULT_A, raw], SCHEMAS, SNAPSHOT)
    _raises("alternate_wrapper", CanonicalResultSet.from_dict, {1: 1, "results": []})


GOLDEN_CANONICAL_RESULT_DIGEST = (
    "sha256:66326ba01632301227aa4e1c79d0b11d1aebc6935298587d0c45acb5573f02ae"
)


def test_golden_canonical_result_digest_locks_the_preimage() -> None:
    preimage = {
        "$schema": "smart_ads/canonical_result_set/v1",
        "analysis_replay_input_bundle_locator": _loc("smart_ads/analysis_replay_input_bundle/v1", "1").to_dict(),
        "results": [
            {
                "result_key": "metric:total",
                "result_locator": _loc("smart_ads/analysis_result/v1", "a").to_dict(),
                "result_projection": {
                    "result_kind": "scalar",
                    "analysis_result_schema_locator": _loc(SCHEMA_TYPE, "d").to_dict(),
                    "columns": [{"name": "total", "cell_type": "int64", "nullable": False}],
                    "rows": [[{"_type": "int64", "value": "42"}]],
                    "row_count": 1,
                },
            }
        ],
    }
    parsed = CanonicalResultSet.from_dict(
        {**preimage, "canonical_result_digest": GOLDEN_CANONICAL_RESULT_DIGEST}
    )
    assert parsed.canonical_result_digest == GOLDEN_CANONICAL_RESULT_DIGEST
    built = CanonicalResultSet.build(BUNDLE, [CanonicalResultEntry.from_dict(preimage["results"][0])])
    assert built.canonical_result_digest == GOLDEN_CANONICAL_RESULT_DIGEST


def test_result_set_entry_lookup() -> None:
    result_set = CanonicalResultSet.from_dict(_set_dict([_entry(RESULT_A), _entry(RESULT_B)]))
    assert result_set.entry("metric:b").result_locator == RESULT_B.locator()
    assert result_set.entry("metric:a").result_key == "metric:a"
    _raises("unknown_result_key", result_set.entry, "metric:z")
    _raises("unknown_result_key", result_set.entry, 1)
