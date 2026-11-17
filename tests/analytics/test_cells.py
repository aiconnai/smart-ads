"""Tests for smart_ads.analytics.cells (ADR-0001 section 6.4, lines 1841-1879)."""
from __future__ import annotations

import base64
import copy
from typing import Any, Callable

import pytest

from smart_ads.analytics.cells import (
    CELL_TYPES,
    RESULT_SET_ERROR_CODES,
    AnalysisResultSchema,
    ResultColumn,
    ResultProjection,
    ResultSetMismatchError,
    TaggedScalarCell,
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


def test_composite_unique_key_uses_every_key_column() -> None:
    # unique_key ["day", "resource_ref"]: rows sharing only one key column are distinct
    rows = [
        _row("campaign:a", "2026-11-01", "1.000000"),
        _row("campaign:b", "2026-11-01", "1.000000"),
        _row("campaign:a", "2026-11-02", "1.000000"),
    ]
    verify_result_projection(ResultProjection.from_dict(_projection_dict(REL_SCHEMA, rows)), REL_SCHEMA)
    full_duplicate = [*rows, _row("campaign:b", "2026-11-01", None)]
    _raises(
        "duplicate_row",
        verify_result_projection,
        ResultProjection.from_dict(_projection_dict(REL_SCHEMA, full_duplicate)),
        REL_SCHEMA,
    )


# ---------------------------------------------------------------- mixed-type keys and helpers


@pytest.mark.parametrize(
    ("parse", "data", "code"),
    [
        (ResultColumn.from_dict, {1: 1, "name": "x"}, "alternate_wrapper"),
        (AnalysisResultSchema.from_dict, {**_schema_dict(), 1: 1}, "alternate_wrapper"),
        (AnalysisResultSchema.from_dict, {1: 1, "integrity": {}}, "alternate_wrapper"),
        (ResultProjection.from_dict, {**_projection_dict(REL_SCHEMA), 1: 1}, "alternate_wrapper"),
        (TaggedScalarCell.from_dict, {1: 1, "_type": "null", "value": None}, "cell_invalid"),
    ],
)
def test_mixed_type_keys_reject_with_a_closed_code(
    parse: Callable[[object], Any], data: object, code: str
) -> None:
    _raises(code, parse, data)


def test_projection_column_index() -> None:
    projection = ResultProjection.from_dict(_projection_dict(REL_SCHEMA))
    assert [projection.column_index(n) for n in ("resource_ref", "day", "spend")] == [0, 1, 2]
    _raises("unknown_column", projection.column_index, "cost")
    _raises("unknown_column", projection.column_index, 0)


class _AlwaysEq:
    def __eq__(self, other: object) -> bool:
        return True


class _DuckCell:
    cell_type = "int64"
    value = "42"

    def to_dict(self) -> dict[str, Any]:
        return {"_type": self.cell_type, "value": self.value}


def test_result_column_check_cell_rejects_non_cells_and_tampered_cells() -> None:
    col = ResultColumn("total", "int64", False)
    nullable_col = ResultColumn("total", "int64", True)
    col.check_cell(_cell("int64", "42"))
    nullable_col.check_cell(_cell("null", None))
    _raises("null_not_allowed", col.check_cell, _cell("null", None))
    _raises("cell_type_mismatch", col.check_cell, _cell("utf8", "42"))

    for bad in (None, {"_type": "int64", "value": "42"}, 42, "42", _DuckCell()):
        _raises("cell_invalid", col.check_cell, bad)  # type: ignore[arg-type]

    tampered_val = _cell("int64", "42")
    object.__setattr__(tampered_val, "value", "not-an-int")
    _raises("cell_invalid", col.check_cell, tampered_val)

    tampered_prim = _cell("int64", "42")
    object.__setattr__(tampered_prim, "value", 42)
    _raises("cell_invalid", col.check_cell, tampered_prim)

    tampered_tag = _cell("int64", "42")
    object.__setattr__(tampered_tag, "cell_type", "float")
    _raises("cell_invalid", col.check_cell, tampered_tag)

    deleted_slot = _cell("int64", "42")
    object.__delattr__(deleted_slot, "value")
    _raises("cell_invalid", col.check_cell, deleted_slot)


def test_verify_result_projection_reparses_tampered_projection_and_schema() -> None:
    bad_count = ResultProjection.from_dict(_projection_dict(REL_SCHEMA))
    object.__setattr__(bad_count, "row_count", 99)
    _raises("row_count_mismatch", verify_result_projection, bad_count, REL_SCHEMA)

    bad_cell_proj = ResultProjection.from_dict(_projection_dict(REL_SCHEMA))
    object.__setattr__(bad_cell_proj.rows[0][1], "value", "not-a-date")
    _raises("cell_invalid", verify_result_projection, bad_cell_proj, REL_SCHEMA)

    duck_proj = ResultProjection.from_dict(_projection_dict(SCALAR_SCHEMA, SCALAR_ROWS))
    object.__setattr__(duck_proj, "rows", ((_DuckCell(),),))
    _raises("cell_invalid", verify_result_projection, duck_proj, SCALAR_SCHEMA)

    always_eq_loc = ArtifactLocator(
        SCHEMA_TYPE,
        "sha256:" + "d" * 64,
        store_kind=_AlwaysEq(),  # type: ignore[arg-type]
        object_ref="cell-object:sha256:" + "d" * 64,
    )
    loc_proj = ResultProjection.from_dict(_projection_dict(REL_SCHEMA))
    object.__setattr__(loc_proj, "analysis_result_schema_locator", always_eq_loc)
    _raises("invalid_locator", verify_result_projection, loc_proj, REL_SCHEMA)

    bad_uk_schema = AnalysisResultSchema.from_dict(_schema_dict(unique_key=["day", "resource_ref"]))
    object.__setattr__(bad_uk_schema, "unique_key", ("undeclared",))
    _raises(
        "schema_invalid",
        verify_result_projection,
        ResultProjection.from_dict(_projection_dict(REL_SCHEMA)),
        bad_uk_schema,
    )

    signed_schema = AnalysisResultSchema.from_dict(_signed(REL_SCHEMA.to_dict()), require_signed=True)
    forged_schema = AnalysisResultSchema.from_dict(_signed(REL_SCHEMA.to_dict()), require_signed=True)
    assert forged_schema.integrity is not None
    object.__setattr__(forged_schema.integrity, "content_digest", "sha256:" + "0" * 64)
    _raises(
        "integrity_mismatch",
        verify_result_projection,
        ResultProjection.from_dict(_projection_dict(signed_schema)),
        forged_schema,
    )

    partial_schema = AnalysisResultSchema.from_dict(_signed(REL_SCHEMA.to_dict()), require_signed=True)
    assert partial_schema.integrity is not None
    object.__setattr__(partial_schema.integrity, "signature_base64", None)
    _raises(
        "invalid_integrity",
        verify_result_projection,
        ResultProjection.from_dict(_projection_dict(signed_schema)),
        partial_schema,
    )
