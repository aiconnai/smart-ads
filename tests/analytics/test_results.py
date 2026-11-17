"""Tests for smart_ads.analytics.results (ADR-0001 section 6.4, lines 1817-1933)."""
from __future__ import annotations

import base64
import copy
import hashlib
from typing import Any, Callable

import pytest

from smart_ads.analytics.results import (
    CELL_TYPES,
    RESULT_SET_ERROR_CODES,
    AnalysisExecution,
    AnalysisResult,
    AnalysisResultSchema,
    CanonicalResultEntry,
    CanonicalResultSet,
    ResultColumn,
    ResultProjection,
    ResultSetMismatchError,
    TaggedScalarCell,
    verify_analysis_execution,
    verify_result_projection,
)
from smart_ads.contracts.jcs import (
    ArtifactLocator,
    P1Integrity,
    canonicalize_jcs,
    p1_content_digest,
)
from smart_ads.contracts.scalars import (
    ClosedValidationError,
    validate_utf8_nfc,
)

SCHEMA_TYPE = "smart_ads/analysis_result_schema/v1"


def _cell(tag: str, value: object) -> TaggedScalarCell:
    return TaggedScalarCell.from_dict({"_type": tag, "value": value})


def _reject_cell(tag: str, value: object, code: str = "cell_invalid") -> None:
    with pytest.raises(ResultSetMismatchError) as info:
        _cell(tag, value)
    assert info.value.code == code


def _raises(code: str, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> None:
    with pytest.raises(ResultSetMismatchError) as info:
        fn(*args, **kwargs)
    assert info.value.code == code, str(info.value)


def _loc(artifact_type: str, seed: str) -> ArtifactLocator:
    return ArtifactLocator.from_digest(artifact_type, "sha256:" + seed * 64)


def _integrity() -> P1Integrity:
    return P1Integrity(
        key_id="key:ed25519:" + "b" * 64,
        key_registry_snapshot_locator=_loc("smart_ads/key_authorization_registry/v1", "c"),
    )


def _signed(envelope: dict[str, Any]) -> dict[str, Any]:
    """Return a copy with a finalized integrity block over the P1 preimage."""
    out = copy.deepcopy(envelope)
    out["integrity"] = _integrity().to_dict()
    out["integrity"]["content_digest"] = p1_content_digest(out)
    out["integrity"]["signature_base64"] = base64.b64encode(b"\x01" * 64).decode("ascii")
    return out


def _col(name: str, cell_type: str, nullable: bool = False) -> dict[str, Any]:
    return {"name": name, "cell_type": cell_type, "nullable": nullable}


REL_COLUMNS = [
    _col("resource_ref", "opaque_ref"),
    _col("day", "date"),
    _col("spend", "decimal6", nullable=True),
]


def _schema_dict(
    *,
    kind: str = "relation",
    columns: list[dict[str, Any]] | None = None,
    unique_key: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "$schema": SCHEMA_TYPE,
        "result_kind": kind,
        "columns": copy.deepcopy(REL_COLUMNS if columns is None else columns),
        "unique_key": unique_key,
    }


def _row(ref: str, day: str, spend: str | None) -> list[dict[str, Any]]:
    spend_cell = {"_type": "null", "value": None} if spend is None else {
        "_type": "decimal6",
        "value": spend,
    }
    return [
        {"_type": "opaque_ref", "value": ref},
        {"_type": "date", "value": day},
        spend_cell,
    ]


REL_ROWS = [
    _row("campaign:b", "2026-11-02", "1.500000"),
    _row("campaign:a", "2026-11-01", None),
]


def _schema_locator(schema: AnalysisResultSchema) -> ArtifactLocator:
    return ArtifactLocator.for_canonical_bytes(SCHEMA_TYPE, canonicalize_jcs(schema.to_dict()))


def _projection_dict(
    schema: AnalysisResultSchema,
    rows: list[list[dict[str, Any]]] | None = None,
    *,
    row_count: object = None,
) -> dict[str, Any]:
    body_rows = copy.deepcopy(REL_ROWS if rows is None else rows)
    schema_dict = schema.to_dict()
    return {
        "result_kind": schema_dict["result_kind"],
        "analysis_result_schema_locator": _schema_locator(schema).to_dict(),
        "columns": copy.deepcopy(schema_dict["columns"]),
        "rows": body_rows,
        "row_count": len(body_rows) if row_count is None else row_count,
    }


REL_SCHEMA = AnalysisResultSchema.from_dict(_schema_dict(unique_key=["day", "resource_ref"]))
SCALAR_SCHEMA = AnalysisResultSchema.from_dict(
    _schema_dict(kind="scalar", columns=[_col("total", "int64")])
)
SCALAR_ROWS = [[{"_type": "int64", "value": "42"}]]


# ---------------------------------------------------------------- error model


def test_error_is_closed_validation_error_with_closed_code() -> None:
    err = ResultSetMismatchError("duplicate_result", "x")
    assert isinstance(err, ClosedValidationError)
    assert err.code == "duplicate_result"
    assert "duplicate_result" in RESULT_SET_ERROR_CODES


def test_error_rejects_unknown_code() -> None:
    with pytest.raises(ClosedValidationError):
        ResultSetMismatchError("not_a_code", "x")


# ---------------------------------------------------------------- cells


def test_cell_types_are_the_eight_adr_variants() -> None:
    assert CELL_TYPES == (
        "null",
        "boolean",
        "int64",
        "decimal6",
        "utf8",
        "date",
        "timestamp",
        "opaque_ref",
    )


@pytest.mark.parametrize(
    ("tag", "value"),
    [
        ("null", None),
        ("boolean", True),
        ("boolean", False),
        ("int64", "0"),
        ("int64", "7"),
        ("int64", "-7"),
        ("int64", "9223372036854775807"),
        ("int64", "-9223372036854775808"),
        ("decimal6", "0.000000"),
        ("decimal6", "0.500000"),
        ("decimal6", "-1.250000"),
        ("decimal6", "123456789012345678901234567890.000001"),
        ("utf8", ""),
        ("utf8", "café"),
        ("utf8", " padded "),
        ("utf8", "a\x00b"),
        ("date", "2026-02-28"),
        ("date", "2024-02-29"),
        ("timestamp", "2026-11-16T23:59:59.000001Z"),
        ("opaque_ref", "campaign:abc.DEF_1:2-x"),
    ],
)
def test_cell_accepts_canonical_values(tag: str, value: object) -> None:
    cell = _cell(tag, value)
    assert cell.cell_type == tag
    assert cell.value == value
    assert cell.to_dict() == {"_type": tag, "value": value}


@pytest.mark.parametrize(
    ("tag", "value"),
    [
        # null carries only a null value
        ("null", False),
        ("null", ""),
        ("null", 0),
        # boolean uses a JSON boolean, never a string or int
        ("boolean", "true"),
        ("boolean", 1),
        ("boolean", None),
        # int64
        ("int64", 7),
        ("int64", 7.0),
        ("int64", True),
        ("int64", "+7"),
        ("int64", "07"),
        ("int64", "-0"),
        ("int64", "00"),
        ("int64", "1e3"),
        ("int64", "1.0"),
        ("int64", " 7"),
        ("int64", "7\n"),
        ("int64", "1,000"),
        ("int64", "NaN"),
        ("int64", "Infinity"),
        ("int64", "-Infinity"),
        ("int64", "١"),
        ("int64", "9223372036854775808"),
        ("int64", "-9223372036854775809"),
        ("int64", "1" * 400),
        ("int64", ""),
        # decimal6
        ("decimal6", 0.5),
        ("decimal6", 1),
        ("decimal6", "0.5"),
        ("decimal6", "0.5000000"),
        ("decimal6", "1"),
        ("decimal6", ".500000"),
        ("decimal6", "00.500000"),
        ("decimal6", "01.500000"),
        ("decimal6", "+1.500000"),
        ("decimal6", "1.500000e0"),
        ("decimal6", "1e6"),
        ("decimal6", "1,000.000000"),
        ("decimal6", "NaN"),
        ("decimal6", "Infinity"),
        ("decimal6", "1.500000\n"),
        ("decimal6", "1.5000O0"),
        # utf8
        ("utf8", "café"),
        ("utf8", "\ud800"),
        ("utf8", 5),
        ("utf8", None),
        # date
        ("date", "2026-02-30"),
        ("date", "2025-02-29"),
        ("date", "2026-13-01"),
        ("date", "2026-1-01"),
        ("date", "2026-01-01T00:00:00Z"),
        ("date", "20260101"),
        ("date", "2026-01-01\n"),
        ("date", 20260101),
        # timestamp
        ("timestamp", "2026-11-16T23:59:59.000001+00:00"),
        ("timestamp", "2026-11-16T23:59:59.000001-03:00"),
        ("timestamp", "2026-11-16T23:59:59.000001z"),
        ("timestamp", "2026-11-16T23:59:59Z"),
        ("timestamp", "2026-11-16T23:59:59.000Z"),
        ("timestamp", "2026-11-16T23:59:59.0000001Z"),
        ("timestamp", "2026-11-16 23:59:59.000001Z"),
        ("timestamp", "2026-02-30T00:00:00.000000Z"),
        ("timestamp", "2026-11-16T23:59:59.000001Z\n"),
        ("timestamp", 1),
        # opaque_ref
        ("opaque_ref", "Campaign:abc"),
        ("opaque_ref", "campaign"),
        ("opaque_ref", "campaign:"),
        ("opaque_ref", "campaign:a b"),
        ("opaque_ref", "campaign:a\x00"),
        ("opaque_ref", "campaign:abc\n"),
        ("opaque_ref", "1campaign:abc"),
        ("opaque_ref", "camp-aign:abc"),
        ("opaque_ref", "campaign:é"),
    ],
)
def test_cell_rejects_non_canonical_values(tag: str, value: object) -> None:
    _reject_cell(tag, value)


@pytest.mark.parametrize("value", ["-0.500000", "-0.000000", "-0.000001"])
def test_decimal6_follows_literal_adr_regex_rejecting_negative_zero_integer_part(
    value: str,
) -> None:
    # ADR line 1860 regex ^(0|-?[1-9][0-9]*)\.[0-9]{6}$ is followed literally
    # (user-approved decision 2): any negative value with integer part 0 rejects.
    _reject_cell("decimal6", value)


def test_utf8_grammar_differs_from_validate_utf8_nfc_on_empty_and_nul() -> None:
    # ADR utf8 is "any valid UTF-8 string in NFC": empty and C0 (incl. NUL) are valid.
    for value in ("", "a\x00b"):
        assert _cell("utf8", value).value == value
        with pytest.raises(ClosedValidationError):
            validate_utf8_nfc(value, field_name="x")


def test_date_and_timestamp_pin_calendar_validity_beyond_regex() -> None:
    # The regex alone would admit these; proleptic Gregorian validity rejects them.
    _reject_cell("date", "0000-01-01")
    _reject_cell("timestamp", "2026-11-16T24:00:00.000000Z")
    _reject_cell("timestamp", "2026-12-31T23:59:60.000000Z")


@pytest.mark.parametrize(
    "data",
    [
        {"_type": "int64"},
        {"value": "1"},
        {"_type": "int64", "value": "1", "extra": 1},
        {"type": "int64", "value": "1"},
        {"_type": "float", "value": "1.5"},
        {"_type": "Int64", "value": "1"},
        ["int64", "1"],
        "1",
        1,
    ],
)
def test_cell_rejects_alternate_wrappers(data: object) -> None:
    with pytest.raises(ResultSetMismatchError) as info:
        TaggedScalarCell.from_dict(data)
    assert info.value.code == "cell_invalid"


def test_cell_constructor_validates_like_from_dict() -> None:
    with pytest.raises(ResultSetMismatchError) as info:
        TaggedScalarCell("int64", "-0")
    assert info.value.code == "cell_invalid"
    assert TaggedScalarCell("int64", "-1").to_dict() == {"_type": "int64", "value": "-1"}


# ---------------------------------------------------------------- analysis_result_schema/v1


def test_schema_round_trips_and_keeps_column_order() -> None:
    data = _schema_dict(unique_key=["day", "resource_ref"])
    schema = AnalysisResultSchema.from_dict(data)
    assert schema.to_dict() == data
    assert [c.name for c in schema.columns] == ["resource_ref", "day", "spend"]
    assert isinstance(schema.columns[0], ResultColumn)
    assert AnalysisResultSchema.from_dict(_schema_dict()).unique_key is None


def test_schema_key_set() -> None:
    assert set(REL_SCHEMA.to_dict()) == {"$schema", "result_kind", "columns", "unique_key"}
    signed = _signed(REL_SCHEMA.to_dict())
    assert set(AnalysisResultSchema.from_dict(signed).to_dict()) == {
        "$schema",
        "result_kind",
        "columns",
        "unique_key",
        "integrity",
    }


@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        (lambda d: d.update(result_kind="table"), "schema_invalid"),
        (lambda d: d.update(columns=[]), "schema_invalid"),
        (lambda d: d.update(columns="x"), "schema_invalid"),
        (lambda d: d["columns"].append(_col("day", "utf8")), "schema_invalid"),
        (lambda d: d["columns"].append(_col("x", "null", True)), "schema_invalid"),
        (lambda d: d["columns"].append(_col("x", "float")), "schema_invalid"),
        (lambda d: d["columns"].append(_col("", "utf8")), "schema_invalid"),
        (lambda d: d["columns"][0].update(nullable=0), "schema_invalid"),
        (lambda d: d["columns"][0].update(extra=1), "alternate_wrapper"),
        (lambda d: d["columns"][0].pop("nullable"), "alternate_wrapper"),
        (lambda d: d.update(unique_key=["undeclared"]), "schema_invalid"),
        (lambda d: d.update(unique_key=["day", "day"]), "schema_invalid"),
        (lambda d: d.update(unique_key=["resource_ref", "day"]), "schema_invalid"),
        (lambda d: d.update(unique_key=[]), "schema_invalid"),
        (lambda d: d.update(unique_key="day"), "schema_invalid"),
        (lambda d: d.update(extra=1), "alternate_wrapper"),
        (lambda d: d.pop("unique_key"), "alternate_wrapper"),
        (lambda d: d.update({"$schema": "smart_ads/analysis_result/v1"}), "alternate_wrapper"),
    ],
)
def test_schema_rejections(mutate: Callable[[dict[str, Any]], Any], code: str) -> None:
    data = _schema_dict()
    mutate(data)
    _raises(code, AnalysisResultSchema.from_dict, data)


def test_scalar_schema_requires_exactly_one_column() -> None:
    _raises(
        "scalar_shape",
        AnalysisResultSchema.from_dict,
        _schema_dict(kind="scalar", columns=[_col("a", "int64"), _col("b", "int64")]),
    )
    assert len(SCALAR_SCHEMA.columns) == 1


def test_schema_p1_integrity_is_recomputed() -> None:
    signed = _signed(REL_SCHEMA.to_dict())
    assert AnalysisResultSchema.from_dict(signed, require_signed=True).integrity is not None
    tampered = copy.deepcopy(signed)
    tampered["result_kind"] = "scalar"
    tampered["columns"] = [_col("total", "int64")]
    tampered["unique_key"] = None
    _raises("integrity_mismatch", AnalysisResultSchema.from_dict, tampered)
    _raises("alternate_wrapper", AnalysisResultSchema.from_dict, REL_SCHEMA.to_dict(), require_signed=True)
    broken = copy.deepcopy(signed)
    broken["integrity"]["signature_base64"] = None
    _raises("invalid_integrity", AnalysisResultSchema.from_dict, broken)


def test_schema_locator_method_matches_canonical_bytes() -> None:
    assert REL_SCHEMA.locator() == _schema_locator(REL_SCHEMA)


# ---------------------------------------------------------------- result projection


def test_projection_round_trip_preserves_row_order_verbatim() -> None:
    data = _projection_dict(REL_SCHEMA)
    projection = ResultProjection.from_dict(data)
    assert projection.to_dict() == data
    # rows are significant bytes: never re-sorted (campaign:b stays first)
    assert projection.rows[0][0].value == "campaign:b"
    assert set(data) == {
        "result_kind",
        "analysis_result_schema_locator",
        "columns",
        "rows",
        "row_count",
    }
    verify_result_projection(projection, REL_SCHEMA)


def test_projection_reversed_rows_are_a_different_projection() -> None:
    a = ResultProjection.from_dict(_projection_dict(REL_SCHEMA))
    b = ResultProjection.from_dict(_projection_dict(REL_SCHEMA, list(reversed(REL_ROWS))))
    assert canonicalize_jcs(a.to_dict()) != canonicalize_jcs(b.to_dict())


def test_empty_relation_is_allowed() -> None:
    projection = ResultProjection.from_dict(_projection_dict(REL_SCHEMA, []))
    assert projection.row_count == 0
    verify_result_projection(projection, REL_SCHEMA)


@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        (lambda d: d.update(row_count=3), "row_count_mismatch"),
        (lambda d: d.update(row_count=True), "field_invalid"),
        (lambda d: d.update(row_count=-1), "field_invalid"),
        (lambda d: d.update(row_count=2.0), "field_invalid"),
        (lambda d: d.update(row_count="2"), "field_invalid"),
        (lambda d: d["rows"][0].pop(), "row_width_mismatch"),
        (lambda d: d["rows"][0].append({"_type": "utf8", "value": "x"}), "row_width_mismatch"),
        (lambda d: d.update(rows="x"), "field_invalid"),
        (lambda d: d["rows"].__setitem__(0, "x"), "field_invalid"),
        (lambda d: d["rows"][0].__setitem__(1, {"_type": "utf8", "value": "2026-11-02"}), "cell_type_mismatch"),
        (lambda d: d["rows"][0].__setitem__(0, {"_type": "null", "value": None}), "null_not_allowed"),
        (lambda d: d["rows"][0].__setitem__(2, {"_type": "decimal6", "value": 1.5}), "cell_invalid"),
        (lambda d: d["rows"][0].__setitem__(2, {"_type": "decimal6", "value": "-0.500000"}), "cell_invalid"),
        (lambda d: d.update(result_kind="table"), "field_invalid"),
        (lambda d: d.update(columns=[]), "schema_invalid"),
        (lambda d: d.update(extra=1), "alternate_wrapper"),
        (lambda d: d.pop("row_count"), "alternate_wrapper"),
        (lambda d: d.update({"$schema": "smart_ads/result_projection/v1"}), "alternate_wrapper"),
        (
            lambda d: d.update(
                analysis_result_schema_locator=_loc("smart_ads/analysis_result/v1", "d").to_dict()
            ),
            "invalid_locator",
        ),
        (lambda d: d["analysis_result_schema_locator"].update(store_kind="s3"), "invalid_locator"),
    ],
)
def test_projection_rejections(mutate: Callable[[dict[str, Any]], Any], code: str) -> None:
    data = _projection_dict(REL_SCHEMA)
    mutate(data)
    _raises(code, ResultProjection.from_dict, data)


def test_null_cell_is_accepted_only_in_nullable_column() -> None:
    projection = ResultProjection.from_dict(_projection_dict(REL_SCHEMA))
    assert projection.rows[1][2].cell_type == "null"


def test_scalar_projection_is_exactly_one_column_one_row() -> None:
    projection = ResultProjection.from_dict(_projection_dict(SCALAR_SCHEMA, SCALAR_ROWS))
    verify_result_projection(projection, SCALAR_SCHEMA)
    _raises("scalar_shape", ResultProjection.from_dict, _projection_dict(SCALAR_SCHEMA, []))
    _raises(
        "scalar_shape",
        ResultProjection.from_dict,
        _projection_dict(SCALAR_SCHEMA, SCALAR_ROWS + SCALAR_ROWS),
    )
    two_cols = _projection_dict(SCALAR_SCHEMA, [[SCALAR_ROWS[0][0], SCALAR_ROWS[0][0]]])
    two_cols["columns"] = [_col("a", "int64"), _col("b", "int64")]
    _raises("scalar_shape", ResultProjection.from_dict, two_cols)


def test_projection_must_bind_to_resolved_schema_bytes() -> None:
    other = AnalysisResultSchema.from_dict(_schema_dict())
    projection = ResultProjection.from_dict(_projection_dict(REL_SCHEMA))
    _raises("schema_locator_mismatch", verify_result_projection, projection, other)
    _raises("field_invalid", verify_result_projection, projection, REL_SCHEMA.to_dict())


@pytest.mark.parametrize(
    "columns",
    [
        [_col("resource_ref", "opaque_ref"), _col("day", "date"), _col("spend", "decimal6")],
        [_col("resource_ref", "opaque_ref"), _col("day", "date"), _col("cost", "decimal6", True)],
        [_col("day", "date"), _col("resource_ref", "opaque_ref"), _col("spend", "decimal6", True)],
        [_col("resource_ref", "utf8"), _col("day", "date"), _col("spend", "decimal6", True)],
    ],
)
def test_inline_columns_must_equal_schema_byte_for_byte(columns: list[dict[str, Any]]) -> None:
    data = _projection_dict(REL_SCHEMA, [])
    data["columns"] = columns
    projection = ResultProjection.from_dict(data)
    _raises("schema_mismatch", verify_result_projection, projection, REL_SCHEMA)


def test_result_kind_must_equal_schema() -> None:
    one_col = AnalysisResultSchema.from_dict(_schema_dict(columns=[_col("total", "int64")]))
    data = _projection_dict(one_col, SCALAR_ROWS)
    data["result_kind"] = "scalar"
    _raises("schema_mismatch", verify_result_projection, ResultProjection.from_dict(data), one_col)


def test_uniqueness_rejects_duplicate_key_rows() -> None:
    dup_key = [
        _row("campaign:a", "2026-11-01", "1.000000"),
        _row("campaign:a", "2026-11-01", "2.000000"),
    ]
    projection = ResultProjection.from_dict(_projection_dict(REL_SCHEMA, dup_key))
    _raises("duplicate_row", verify_result_projection, projection, REL_SCHEMA)


def test_uniqueness_treats_null_key_cells_as_equal() -> None:
    schema = AnalysisResultSchema.from_dict(_schema_dict(unique_key=["spend"]))
    rows = [_row("campaign:a", "2026-11-01", None), _row("campaign:b", "2026-11-02", None)]
    projection = ResultProjection.from_dict(_projection_dict(schema, rows))
    _raises("duplicate_row", verify_result_projection, projection, schema)


def test_duplicates_are_allowed_without_declared_uniqueness() -> None:
    schema = AnalysisResultSchema.from_dict(_schema_dict())
    rows = [REL_ROWS[0], REL_ROWS[0]]
    verify_result_projection(ResultProjection.from_dict(_projection_dict(schema, rows)), schema)


# ---------------------------------------------------------------- analysis_result/v1

RESULT_TYPE = "smart_ads/analysis_result/v1"
SET_TYPE = "smart_ads/canonical_result_set/v1"
EXECUTION_TYPE = "smart_ads/analysis_execution/v1"
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
