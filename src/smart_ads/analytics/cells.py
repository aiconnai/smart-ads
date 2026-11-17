"""Tagged scalar cells, result schemas, and result projections (ADR-0001 section 6.4)."""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from itertools import pairwise
import re
from typing import Any, ClassVar, Final, TypeVar
import unicodedata

from smart_ads.contracts.jcs import (
    ArtifactLocator,
    P1Integrity,
    canonicalize_jcs,
    p1_content_digest,
)
from smart_ads.contracts.scalars import (
    ClosedValidationError,
    validate_iso_date,
    validate_non_empty_str,
    validate_opaque_ref,
    validate_timestamp_utc6,
)

_T = TypeVar("_T")

RESULT_SET_ERROR_CODES: Final[frozenset[str]] = frozenset(
    (
        "alternate_wrapper bundle_locator_mismatch cell_invalid cell_type_mismatch "
        "cross_snapshot_result digest_mismatch duplicate_result duplicate_row "
        "duplicate_schema empty_result_set extra_result field_invalid integrity_mismatch "
        "invalid_integrity invalid_locator missing_result null_not_allowed "
        "projection_mismatch result_locator_mismatch results_unordered "
        "row_count_mismatch row_width_mismatch scalar_shape schema_invalid "
        "schema_locator_mismatch schema_mismatch schema_unresolved unknown_column "
        "unknown_result_key unreferenced_schema unsigned_artifact"
    ).split()
)


class ResultSetMismatchError(ClosedValidationError):
    """Closed T3 rejection carrying a `code` from `RESULT_SET_ERROR_CODES`."""

    def __init__(self, code: str, message: str) -> None:
        if code not in RESULT_SET_ERROR_CODES:
            raise ClosedValidationError(f"ResultSetMismatchError: unknown code {code!r}")
        super().__init__(f"[{code}] {message}")
        self.code = code


def _fail(code: str, message: str) -> ResultSetMismatchError:
    return ResultSetMismatchError(code, message)


def _coded(code: str, fn: Callable[..., _T], *args: Any, **kwargs: Any) -> _T:
    """Run a shared validator, re-raising a plain ClosedValidationError under `code`."""
    try:
        return fn(*args, **kwargs)
    except ResultSetMismatchError:
        raise
    except ClosedValidationError as exc:
        raise _fail(code, str(exc)) from exc


# ---------------------------------------------------------------- tagged scalar cells

CELL_TYPES: Final[tuple[str, ...]] = (
    "null", "boolean", "int64", "decimal6", "utf8", "date", "timestamp", "opaque_ref",
)
COLUMN_CELL_TYPES: Final[frozenset[str]] = frozenset(CELL_TYPES) - {"null"}
_CELL_KEYS: Final[frozenset[str]] = frozenset({"_type", "value"})
_INT64_RE: Final[re.Pattern[str]] = re.compile(r"\A(0|-?[1-9][0-9]*)\Z")
_DECIMAL6_RE: Final[re.Pattern[str]] = re.compile(r"\A(0|-?[1-9][0-9]*)\.[0-9]{6}\Z")
_INT64_MIN: Final[int] = -(1 << 63)
_INT64_MAX: Final[int] = (1 << 63) - 1
_INT64_MAX_CHARS: Final[int] = 20


def _check_int64(value: str) -> None:
    if len(value) > _INT64_MAX_CHARS or not _INT64_RE.fullmatch(value):
        raise ClosedValidationError(f"int64: non-canonical value {value!r}")
    if not (_INT64_MIN <= int(value) <= _INT64_MAX):
        raise ClosedValidationError(f"int64: value {value!r} outside signed 64-bit range")


def _check_decimal6(value: str) -> None:
    if not _DECIMAL6_RE.fullmatch(value):
        raise ClosedValidationError(f"decimal6: non-canonical value {value!r}")


def _check_utf8(value: str) -> None:
    if any(0xD800 <= ord(ch) <= 0xDFFF for ch in value):
        raise ClosedValidationError("utf8: lone UTF-16 surrogates are not valid UTF-8")
    if unicodedata.normalize("NFC", value) != value:
        raise ClosedValidationError("utf8: string must be normalized to Unicode NFC")


_STRING_CHECKS: Final[dict[str, Callable[[str], object]]] = {
    "int64": _check_int64,
    "decimal6": _check_decimal6,
    "utf8": _check_utf8,
    "date": lambda v: validate_iso_date(v, field_name="date"),
    "timestamp": lambda v: validate_timestamp_utc6(v, field_name="timestamp"),
    "opaque_ref": lambda v: validate_opaque_ref(v, field_name="opaque_ref"),
}


def _validate_cell(cell_type: object, value: object) -> None:
    if type(cell_type) is not str or cell_type not in CELL_TYPES:
        raise _fail("cell_invalid", f"cell._type: unknown tag {cell_type!r}")
    if cell_type == "null":
        if value is not None:
            raise _fail("cell_invalid", "null cell: value must be JSON null")
        return
    if cell_type == "boolean":
        if type(value) is not bool:
            raise _fail("cell_invalid", "boolean cell: value must be a JSON boolean")
        return
    if type(value) is not str:
        raise _fail(
            "cell_invalid",
            f"{cell_type} cell: value must be a JSON string, got {type(value).__name__}",
        )
    _coded("cell_invalid", _STRING_CHECKS[cell_type], value)


@dataclass(frozen=True, slots=True)
class TaggedScalarCell:
    """Closed tagged scalar `{"_type": <tag>, "value": <null|bool|string>}`."""

    cell_type: str
    value: None | bool | str

    def __post_init__(self) -> None:
        _validate_cell(self.cell_type, self.value)

    @classmethod
    def from_dict(cls, data: object) -> TaggedScalarCell:
        if not isinstance(data, Mapping) or set(data) != _CELL_KEYS:
            raise _fail("cell_invalid", "cell: expected exactly {'_type', 'value'}")
        return cls(cell_type=data["_type"], value=data["value"])

    def to_dict(self) -> dict[str, Any]:
        return {"_type": self.cell_type, "value": self.value}


# ---------------------------------------------------------------- shared closed-object helpers

RESULT_KINDS: Final[frozenset[str]] = frozenset({"scalar", "relation"})
ANALYSIS_RESULT_SCHEMA_TYPE: Final[str] = "smart_ads/analysis_result_schema/v1"
ANALYSIS_RESULT_TYPE: Final[str] = "smart_ads/analysis_result/v1"
CANONICAL_RESULT_SET_TYPE: Final[str] = "smart_ads/canonical_result_set/v1"
ANALYSIS_EXECUTION_TYPE: Final[str] = "smart_ads/analysis_execution/v1"
REPLAY_BUNDLE_TYPE: Final[str] = "smart_ads/analysis_replay_input_bundle/v1"
DATASET_SNAPSHOT_TYPE: Final[str] = "smart_ads/dataset_snapshot/v1"
RUN_CONTEXT_TYPE: Final[str] = "smart_ads/migration_run_context/v1"


def _same_bytes(left: object, right: object) -> bool:
    """Byte-for-byte RFC 8785 equality of two JSON trees."""
    return canonicalize_jcs(left) == canonicalize_jcs(right)


def _locator_of(artifact_type: str, envelope: Mapping[str, Any]) -> ArtifactLocator:
    """Layer-3 locator over the complete canonical bytes of a resolved artifact."""
    return ArtifactLocator.for_canonical_bytes(artifact_type, canonicalize_jcs(envelope))


def _closed(data: object, keys: frozenset[str], *, label: str) -> Mapping[str, Any]:
    if not isinstance(data, Mapping) or set(data) != keys:
        found = sorted(map(repr, data)) if isinstance(data, Mapping) else type(data).__name__
        raise _fail("alternate_wrapper", f"{label}: expected members {sorted(keys)}, got {found}")
    return data


def _split_p1(
    data: object,
    core_keys: frozenset[str],
    *,
    schema_id: str,
    label: str,
    require_signed: bool,
) -> tuple[Mapping[str, Any], P1Integrity | None]:
    """Parse a closed P1 envelope (integrity optional unless `require_signed`)."""
    if type(require_signed) is not bool:
        raise _fail("field_invalid", "require_signed: expected bool")
    with_integrity = require_signed or (isinstance(data, Mapping) and "integrity" in data)
    keys = core_keys | {"integrity"} if with_integrity else core_keys
    mapping = _closed(data, keys, label=label)
    if mapping["$schema"] != schema_id:
        raise _fail("alternate_wrapper", f"{label}.$schema: expected {schema_id!r}")
    if not with_integrity:
        return mapping, None
    integrity = _coded(
        "invalid_integrity",
        P1Integrity.from_dict,
        mapping["integrity"],
        require_signed=require_signed,
    )
    return mapping, integrity


def _check_integrity(integrity: object, envelope: Mapping[str, Any], *, label: str) -> None:
    if integrity is None:
        return
    if not isinstance(integrity, P1Integrity):
        raise _fail("invalid_integrity", f"{label}.integrity: expected P1Integrity or None")
    if integrity.is_signed and integrity.content_digest != p1_content_digest(envelope):
        raise _fail("integrity_mismatch", f"{label}.integrity.content_digest: recomputation differs")


def _require_locator(value: object, expected_type: str, *, label: str) -> None:
    if not isinstance(value, ArtifactLocator) or value.artifact_type != expected_type:
        raise _fail("invalid_locator", f"{label}: expected ArtifactLocator for {expected_type!r}")


def _parse_locator(value: object, expected_type: str) -> ArtifactLocator:
    return _coded("invalid_locator", ArtifactLocator.from_dict, value, expected_type=expected_type)


def _sequence(value: object, *, label: str, code: str = "field_invalid") -> tuple[Any, ...]:
    if not isinstance(value, (list, tuple)):
        raise _fail(code, f"{label}: expected JSON array")
    return tuple(value)


def _with_integrity(core: dict[str, Any], integrity: P1Integrity | None) -> dict[str, Any]:
    if integrity is not None:
        return {**core, "integrity": integrity.to_dict()}
    return core


# ---------------------------------------------------------------- analysis_result_schema/v1

_COLUMN_KEYS: Final[frozenset[str]] = frozenset({"name", "cell_type", "nullable"})
_SCHEMA_CORE_KEYS: Final[frozenset[str]] = frozenset(
    {"$schema", "result_kind", "columns", "unique_key"}
)


@dataclass(frozen=True, slots=True)
class ResultColumn:
    """Closed column definition `{"name", "cell_type", "nullable"}`."""

    name: str
    cell_type: str
    nullable: bool

    def __post_init__(self) -> None:
        _coded("schema_invalid", validate_non_empty_str, self.name, field_name="column.name")
        if type(self.cell_type) is not str or self.cell_type not in COLUMN_CELL_TYPES:
            raise _fail("schema_invalid", f"column.cell_type: unknown type {self.cell_type!r}")
        if type(self.nullable) is not bool:
            raise _fail("schema_invalid", "column.nullable: expected JSON boolean")

    @classmethod
    def from_dict(cls, data: object) -> ResultColumn:
        mapping = _closed(data, _COLUMN_KEYS, label="column")
        return cls(mapping["name"], mapping["cell_type"], mapping["nullable"])

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "cell_type": self.cell_type, "nullable": self.nullable}

    def check_cell(self, cell: TaggedScalarCell) -> None:
        """Raise unless `cell` satisfies this column's type and nullability."""
        if cell.cell_type == "null":
            if not self.nullable:
                raise _fail("null_not_allowed", f"column {self.name!r} is not nullable")
        elif cell.cell_type != self.cell_type:
            raise _fail(
                "cell_type_mismatch",
                f"column {self.name!r}: expected {self.cell_type!r}, got {cell.cell_type!r}",
            )


def _validate_columns(columns: object) -> tuple[ResultColumn, ...]:
    checked = _sequence(columns, label="columns", code="schema_invalid")
    if not checked:
        raise _fail("schema_invalid", "columns: must not be empty")
    if not all(isinstance(col, ResultColumn) for col in checked):
        raise _fail("schema_invalid", "columns: every element must be ResultColumn")
    names = [col.name for col in checked]
    if len(set(names)) != len(names):
        raise _fail("schema_invalid", "columns: column names must be unique")
    return checked


def _parse_columns(raw: object) -> tuple[ResultColumn, ...]:
    return tuple(
        ResultColumn.from_dict(item)
        for item in _sequence(raw, label="columns", code="schema_invalid")
    )


def _validate_result_kind(kind: object, *, code: str) -> None:
    if type(kind) is not str or kind not in RESULT_KINDS:
        raise _fail(code, f"result_kind: expected one of {sorted(RESULT_KINDS)}, got {kind!r}")


def _validate_unique_key(
    unique_key: object, columns: tuple[ResultColumn, ...]
) -> tuple[str, ...] | None:
    if unique_key is None:
        return None
    names = _sequence(unique_key, label="unique_key", code="schema_invalid")
    declared = {col.name for col in columns}
    if not names or any(type(n) is not str or n not in declared for n in names):
        raise _fail("schema_invalid", "unique_key: non-empty array of declared column names")
    encoded = [n.encode("utf-8") for n in names]
    if any(a >= b for a, b in pairwise(encoded)):
        raise _fail("schema_invalid", "unique_key: must be unique and sorted by UTF-8 bytes")
    return names


@dataclass(frozen=True, slots=True)
class AnalysisResultSchema:
    """Closed P1 `smart_ads/analysis_result_schema/v1`."""

    SCHEMA: ClassVar[str] = ANALYSIS_RESULT_SCHEMA_TYPE

    result_kind: str
    columns: tuple[ResultColumn, ...]
    unique_key: tuple[str, ...] | None = None
    integrity: P1Integrity | None = None

    def __post_init__(self) -> None:
        _validate_result_kind(self.result_kind, code="schema_invalid")
        columns = _validate_columns(self.columns)
        object.__setattr__(self, "columns", columns)
        if self.result_kind == "scalar" and len(columns) != 1:
            raise _fail("scalar_shape", "analysis_result_schema: scalar has exactly one column")
        object.__setattr__(self, "unique_key", _validate_unique_key(self.unique_key, columns))
        _check_integrity(self.integrity, self.to_dict(), label="analysis_result_schema")

    @classmethod
    def from_dict(cls, data: object, *, require_signed: bool = False) -> AnalysisResultSchema:
        mapping, integrity = _split_p1(
            data,
            _SCHEMA_CORE_KEYS,
            schema_id=cls.SCHEMA,
            label="analysis_result_schema",
            require_signed=require_signed,
        )
        return cls(
            result_kind=mapping["result_kind"],
            columns=_parse_columns(mapping["columns"]),
            unique_key=mapping["unique_key"],
            integrity=integrity,
        )

    def to_dict(self) -> dict[str, Any]:
        core = {
            "$schema": self.SCHEMA,
            "result_kind": self.result_kind,
            "columns": [col.to_dict() for col in self.columns],
            "unique_key": None if self.unique_key is None else list(self.unique_key),
        }
        return _with_integrity(core, self.integrity)

    def locator(self) -> ArtifactLocator:
        return _locator_of(self.SCHEMA, self.to_dict())


# ---------------------------------------------------------------- result projection

_PROJECTION_KEYS: Final[frozenset[str]] = frozenset(
    {"result_kind", "analysis_result_schema_locator", "columns", "rows", "row_count"}
)


def _validate_rows(
    rows: object, columns: tuple[ResultColumn, ...]
) -> tuple[tuple[TaggedScalarCell, ...], ...]:
    checked_rows = []
    for raw_row in _sequence(rows, label="rows"):
        row = _sequence(raw_row, label="rows[]")
        if len(row) != len(columns):
            raise _fail("row_width_mismatch", f"row has {len(row)} cells, expected {len(columns)}")
        for column, cell in zip(columns, row, strict=True):
            if not isinstance(cell, TaggedScalarCell):
                raise _fail("cell_invalid", "rows: every cell must be TaggedScalarCell")
            column.check_cell(cell)
        checked_rows.append(row)
    return tuple(checked_rows)


@dataclass(frozen=True, slots=True)
class ResultProjection:
    """Closed result projection; row order is significant and never re-sorted."""

    result_kind: str
    analysis_result_schema_locator: ArtifactLocator
    columns: tuple[ResultColumn, ...]
    rows: tuple[tuple[TaggedScalarCell, ...], ...]
    row_count: int

    def __post_init__(self) -> None:
        _validate_result_kind(self.result_kind, code="field_invalid")
        _require_locator(
            self.analysis_result_schema_locator,
            ANALYSIS_RESULT_SCHEMA_TYPE,
            label="result_projection.analysis_result_schema_locator",
        )
        columns = _validate_columns(self.columns)
        object.__setattr__(self, "columns", columns)
        rows = _validate_rows(self.rows, columns)
        object.__setattr__(self, "rows", rows)
        if type(self.row_count) is not int or self.row_count < 0:
            raise _fail("field_invalid", "result_projection.row_count: non-negative int")
        if self.row_count != len(rows):
            raise _fail("row_count_mismatch", f"row_count {self.row_count} != {len(rows)} rows")
        if self.result_kind == "scalar" and (len(columns) != 1 or len(rows) != 1):
            raise _fail("scalar_shape", "scalar projection has exactly one column and one row")

    @classmethod
    def from_dict(cls, data: object) -> ResultProjection:
        mapping = _closed(data, _PROJECTION_KEYS, label="result_projection")
        rows = tuple(
            tuple(TaggedScalarCell.from_dict(c) for c in _sequence(r, label="rows[]"))
            for r in _sequence(mapping["rows"], label="rows")
        )
        return cls(
            result_kind=mapping["result_kind"],
            analysis_result_schema_locator=_parse_locator(
                mapping["analysis_result_schema_locator"], ANALYSIS_RESULT_SCHEMA_TYPE
            ),
            columns=_parse_columns(mapping["columns"]),
            rows=rows,
            row_count=mapping["row_count"],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "result_kind": self.result_kind,
            "analysis_result_schema_locator": self.analysis_result_schema_locator.to_dict(),
            "columns": [col.to_dict() for col in self.columns],
            "rows": [[cell.to_dict() for cell in row] for row in self.rows],
            "row_count": self.row_count,
        }

    def column_index(self, name: str) -> int:
        """Position of the declared column `name` (rejects an undeclared name)."""
        for index, column in enumerate(self.columns):
            if type(name) is str and column.name == name:
                return index
        raise _fail("unknown_column", f"result_projection: undeclared column {name!r}")


def verify_result_projection(
    projection: ResultProjection, resolved_schema: AnalysisResultSchema
) -> None:
    """Check a projection against its resolved schema: locator, kind/columns bytes, uniqueness."""
    if not isinstance(projection, ResultProjection):
        raise _fail("field_invalid", "projection: expected ResultProjection")
    if not isinstance(resolved_schema, AnalysisResultSchema):
        raise _fail("field_invalid", "resolved_schema: expected AnalysisResultSchema")
    if not _same_bytes(
        projection.analysis_result_schema_locator.to_dict(), resolved_schema.locator().to_dict()
    ):
        raise _fail("schema_locator_mismatch", "projection schema locator != resolved schema")
    schema_dict = resolved_schema.to_dict()
    inline = projection.to_dict()
    if not _same_bytes(
        [inline["result_kind"], inline["columns"]],
        [schema_dict["result_kind"], schema_dict["columns"]],
    ):
        raise _fail("schema_mismatch", "inline result_kind/columns differ from resolved schema")
    if resolved_schema.unique_key is None:
        return
    names = [col.name for col in resolved_schema.columns]
    indexes = [names.index(name) for name in resolved_schema.unique_key]
    seen: set[bytes] = set()
    for row in projection.rows:
        key = canonicalize_jcs([row[i].to_dict() for i in indexes])
        if key in seen:
            raise _fail("duplicate_row", "duplicate row under the declared unique_key")
        seen.add(key)


__all__ = [
    "ANALYSIS_EXECUTION_TYPE", "ANALYSIS_RESULT_SCHEMA_TYPE", "ANALYSIS_RESULT_TYPE",
    "CANONICAL_RESULT_SET_TYPE", "CELL_TYPES", "COLUMN_CELL_TYPES", "DATASET_SNAPSHOT_TYPE",
    "REPLAY_BUNDLE_TYPE", "RESULT_KINDS", "RESULT_SET_ERROR_CODES", "RUN_CONTEXT_TYPE",
    "AnalysisResultSchema", "ResultColumn", "ResultProjection", "ResultSetMismatchError",
    "TaggedScalarCell", "verify_result_projection",
]
