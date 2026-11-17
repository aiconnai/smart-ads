"""Tagged scalar cells, result projections, canonical result sets, and analysis executions (ADR-0001 section 6.4)."""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import hashlib
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
    validate_sha256_prefixed,
    validate_timestamp_utc6,
)

_T = TypeVar("_T")

RESULT_SET_ERROR_CODES: Final[frozenset[str]] = frozenset(
    (
        "alternate_wrapper bundle_locator_mismatch cell_invalid cell_type_mismatch "
        "cross_snapshot_result digest_mismatch duplicate_result duplicate_row "
        "empty_result_set extra_result field_invalid integrity_mismatch "
        "invalid_integrity invalid_locator missing_result null_not_allowed "
        "projection_mismatch result_locator_mismatch results_unordered "
        "row_count_mismatch row_width_mismatch scalar_shape schema_invalid "
        "schema_locator_mismatch schema_mismatch"
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
        found = sorted(data) if isinstance(data, Mapping) else type(data).__name__
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


# ---------------------------------------------------------------- analysis_result/v1

_RESULT_CORE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "$schema",
        "migration_run_context_locator",
        "dataset_snapshot_locator",
        "replay_input_bundle_locator",
        "result_key",
        "result_projection",
    }
)


def _validate_result_key(value: object) -> str:
    return _coded("field_invalid", validate_non_empty_str, value, field_name="result_key")


@dataclass(frozen=True, slots=True)
class AnalysisResult:
    """Closed P1 `smart_ads/analysis_result/v1`; references the replay bundle, never the execution."""

    SCHEMA: ClassVar[str] = ANALYSIS_RESULT_TYPE

    migration_run_context_locator: ArtifactLocator
    dataset_snapshot_locator: ArtifactLocator
    replay_input_bundle_locator: ArtifactLocator
    result_key: str
    result_projection: ResultProjection
    integrity: P1Integrity | None = None

    def __post_init__(self) -> None:
        label = "analysis_result"
        _require_locator(self.migration_run_context_locator, RUN_CONTEXT_TYPE, label=label)
        _require_locator(self.dataset_snapshot_locator, DATASET_SNAPSHOT_TYPE, label=label)
        _require_locator(self.replay_input_bundle_locator, REPLAY_BUNDLE_TYPE, label=label)
        _validate_result_key(self.result_key)
        if not isinstance(self.result_projection, ResultProjection):
            raise _fail("field_invalid", f"{label}.result_projection: expected ResultProjection")
        _check_integrity(self.integrity, self.to_dict(), label=label)

    @classmethod
    def from_dict(cls, data: object, *, require_signed: bool = False) -> AnalysisResult:
        mapping, integrity = _split_p1(
            data,
            _RESULT_CORE_KEYS,
            schema_id=cls.SCHEMA,
            label="analysis_result",
            require_signed=require_signed,
        )
        return cls(
            migration_run_context_locator=_parse_locator(
                mapping["migration_run_context_locator"], RUN_CONTEXT_TYPE
            ),
            dataset_snapshot_locator=_parse_locator(
                mapping["dataset_snapshot_locator"], DATASET_SNAPSHOT_TYPE
            ),
            replay_input_bundle_locator=_parse_locator(
                mapping["replay_input_bundle_locator"], REPLAY_BUNDLE_TYPE
            ),
            result_key=mapping["result_key"],
            result_projection=ResultProjection.from_dict(mapping["result_projection"]),
            integrity=integrity,
        )

    def to_dict(self) -> dict[str, Any]:
        core = {
            "$schema": self.SCHEMA,
            "migration_run_context_locator": self.migration_run_context_locator.to_dict(),
            "dataset_snapshot_locator": self.dataset_snapshot_locator.to_dict(),
            "replay_input_bundle_locator": self.replay_input_bundle_locator.to_dict(),
            "result_key": self.result_key,
            "result_projection": self.result_projection.to_dict(),
        }
        return _with_integrity(core, self.integrity)

    def locator(self) -> ArtifactLocator:
        return _locator_of(self.SCHEMA, self.to_dict())


# ---------------------------------------------------------------- canonical_result_set/v1

_ENTRY_KEYS: Final[frozenset[str]] = frozenset(
    {"result_key", "result_locator", "result_projection"}
)
_SET_KEYS: Final[frozenset[str]] = frozenset(
    {"$schema", "analysis_replay_input_bundle_locator", "results", "canonical_result_digest"}
)


@dataclass(frozen=True, slots=True)
class CanonicalResultEntry:
    """Closed result-set entry `{result_key, result_locator, result_projection}`."""

    result_key: str
    result_locator: ArtifactLocator
    result_projection: ResultProjection

    def __post_init__(self) -> None:
        _validate_result_key(self.result_key)
        _require_locator(self.result_locator, ANALYSIS_RESULT_TYPE, label="result_locator")
        if not isinstance(self.result_projection, ResultProjection):
            raise _fail("field_invalid", "result_projection: expected ResultProjection")

    @classmethod
    def from_result(cls, result: AnalysisResult) -> CanonicalResultEntry:
        """Build the entry a resolved `analysis_result/v1` must appear as."""
        if not isinstance(result, AnalysisResult):
            raise _fail("field_invalid", "from_result: expected AnalysisResult")
        return cls(result.result_key, result.locator(), result.result_projection)

    @classmethod
    def from_dict(cls, data: object) -> CanonicalResultEntry:
        mapping = _closed(data, _ENTRY_KEYS, label="canonical_result_set.results[]")
        return cls(
            result_key=mapping["result_key"],
            result_locator=_parse_locator(mapping["result_locator"], ANALYSIS_RESULT_TYPE),
            result_projection=ResultProjection.from_dict(mapping["result_projection"]),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "result_key": self.result_key,
            "result_locator": self.result_locator.to_dict(),
            "result_projection": self.result_projection.to_dict(),
        }


def _validate_entries(results: object) -> tuple[CanonicalResultEntry, ...]:
    entries = _sequence(results, label="canonical_result_set.results")
    if not entries:
        raise _fail("empty_result_set", "canonical_result_set.results: must not be empty")
    if not all(isinstance(e, CanonicalResultEntry) for e in entries):
        raise _fail("field_invalid", "results: every element must be CanonicalResultEntry")
    keys = [e.result_key.encode("utf-8") for e in entries]
    if len(set(keys)) != len(keys):
        raise _fail("duplicate_result", "canonical_result_set.results: duplicate result_key")
    if any(a > b for a, b in pairwise(keys)):
        raise _fail("results_unordered", "results: must be sorted by raw UTF-8 result_key bytes")
    return entries


def _digest_preimage(preimage: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonicalize_jcs(preimage)).hexdigest()


@dataclass(frozen=True, slots=True)
class CanonicalResultSet:
    """Embedded `smart_ads/canonical_result_set/v1`; digest = SHA-256(RFC8785(P))."""

    SCHEMA: ClassVar[str] = CANONICAL_RESULT_SET_TYPE

    analysis_replay_input_bundle_locator: ArtifactLocator
    results: tuple[CanonicalResultEntry, ...]
    canonical_result_digest: str

    def __post_init__(self) -> None:
        _require_locator(
            self.analysis_replay_input_bundle_locator,
            REPLAY_BUNDLE_TYPE,
            label="canonical_result_set.analysis_replay_input_bundle_locator",
        )
        object.__setattr__(self, "results", _validate_entries(self.results))
        _coded(
            "field_invalid",
            validate_sha256_prefixed,
            self.canonical_result_digest,
            field_name="canonical_result_digest",
        )
        if self.canonical_result_digest != _digest_preimage(self.preimage()):
            raise _fail("digest_mismatch", "canonical_result_digest != SHA-256(RFC8785(P))")

    @classmethod
    def build(
        cls, bundle_locator: ArtifactLocator, results: tuple[CanonicalResultEntry, ...] | list
    ) -> CanonicalResultSet:
        """Compute the digest for already-sorted entries (never re-sorts)."""
        _require_locator(bundle_locator, REPLAY_BUNDLE_TYPE, label="bundle_locator")
        entries = _validate_entries(results)
        preimage = {
            "$schema": cls.SCHEMA,
            "analysis_replay_input_bundle_locator": bundle_locator.to_dict(),
            "results": [entry.to_dict() for entry in entries],
        }
        return cls(bundle_locator, entries, _digest_preimage(preimage))

    @classmethod
    def from_dict(cls, data: object) -> CanonicalResultSet:
        mapping = _closed(data, _SET_KEYS, label="canonical_result_set")
        if mapping["$schema"] != cls.SCHEMA:
            raise _fail("alternate_wrapper", f"canonical_result_set.$schema: expected {cls.SCHEMA!r}")
        return cls(
            analysis_replay_input_bundle_locator=_parse_locator(
                mapping["analysis_replay_input_bundle_locator"], REPLAY_BUNDLE_TYPE
            ),
            results=tuple(
                CanonicalResultEntry.from_dict(item)
                for item in _sequence(mapping["results"], label="canonical_result_set.results")
            ),
            canonical_result_digest=mapping["canonical_result_digest"],
        )

    def preimage(self) -> dict[str, Any]:
        """`P`: the complete object with exactly `/canonical_result_digest` deleted."""
        return {
            "$schema": self.SCHEMA,
            "analysis_replay_input_bundle_locator": self.analysis_replay_input_bundle_locator.to_dict(),
            "results": [entry.to_dict() for entry in self.results],
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.preimage(), "canonical_result_digest": self.canonical_result_digest}


# ---------------------------------------------------------------- analysis_execution/v1

_EXECUTION_CORE_KEYS: Final[frozenset[str]] = frozenset(
    {"$schema", "analysis_replay_input_bundle_locator", "canonical_result_set"}
)


@dataclass(frozen=True, slots=True)
class AnalysisExecution:
    """Closed P1 `smart_ads/analysis_execution/v1`: one bundle locator, one embedded result set."""

    SCHEMA: ClassVar[str] = ANALYSIS_EXECUTION_TYPE

    analysis_replay_input_bundle_locator: ArtifactLocator
    canonical_result_set: CanonicalResultSet
    integrity: P1Integrity | None = None

    def __post_init__(self) -> None:
        _require_locator(
            self.analysis_replay_input_bundle_locator,
            REPLAY_BUNDLE_TYPE,
            label="analysis_execution.analysis_replay_input_bundle_locator",
        )
        if not isinstance(self.canonical_result_set, CanonicalResultSet):
            raise _fail("field_invalid", "analysis_execution.canonical_result_set: expected set")
        if not _same_bytes(
            self.analysis_replay_input_bundle_locator.to_dict(),
            self.canonical_result_set.analysis_replay_input_bundle_locator.to_dict(),
        ):
            raise _fail("bundle_locator_mismatch", "execution bundle locator != result-set locator")
        _check_integrity(self.integrity, self.to_dict(), label="analysis_execution")

    @classmethod
    def from_dict(cls, data: object, *, require_signed: bool = False) -> AnalysisExecution:
        mapping, integrity = _split_p1(
            data,
            _EXECUTION_CORE_KEYS,
            schema_id=cls.SCHEMA,
            label="analysis_execution",
            require_signed=require_signed,
        )
        return cls(
            analysis_replay_input_bundle_locator=_parse_locator(
                mapping["analysis_replay_input_bundle_locator"], REPLAY_BUNDLE_TYPE
            ),
            canonical_result_set=CanonicalResultSet.from_dict(mapping["canonical_result_set"]),
            integrity=integrity,
        )

    def to_dict(self) -> dict[str, Any]:
        core = {
            "$schema": self.SCHEMA,
            "analysis_replay_input_bundle_locator": self.analysis_replay_input_bundle_locator.to_dict(),
            "canonical_result_set": self.canonical_result_set.to_dict(),
        }
        return _with_integrity(core, self.integrity)

    def locator(self) -> ArtifactLocator:
        return _locator_of(self.SCHEMA, self.to_dict())


# ---------------------------------------------------------------- verifier


def _index_resolved(resolved_results: object) -> dict[str, AnalysisResult]:
    """Parse resolved results (objects or closed mappings) keyed by unique `result_key`."""
    indexed: dict[str, AnalysisResult] = {}
    for item in _sequence(resolved_results, label="resolved_results"):
        if isinstance(item, AnalysisResult):
            result = item
        elif isinstance(item, Mapping):
            result = AnalysisResult.from_dict(item)
        else:
            raise _fail("field_invalid", "resolved_results: expected AnalysisResult elements")
        if result.result_key in indexed:
            raise _fail("duplicate_result", f"resolved_results: duplicate {result.result_key!r}")
        indexed[result.result_key] = result
    return indexed


def _check_resolved_identity(
    result: AnalysisResult, bundle: ArtifactLocator, snapshot: ArtifactLocator
) -> None:
    if not _same_bytes(result.replay_input_bundle_locator.to_dict(), bundle.to_dict()):
        raise _fail(
            "bundle_locator_mismatch",
            f"result {result.result_key!r}: replay_input_bundle_locator != execution bundle",
        )
    if not _same_bytes(result.dataset_snapshot_locator.to_dict(), snapshot.to_dict()):
        raise _fail(
            "cross_snapshot_result",
            f"result {result.result_key!r}: dataset_snapshot_locator != bundle snapshot",
        )


def _check_entry(entry: CanonicalResultEntry, result: AnalysisResult) -> None:
    if not _same_bytes(entry.result_locator.to_dict(), result.locator().to_dict()):
        raise _fail("result_locator_mismatch", f"entry {entry.result_key!r}: locator differs")
    if not _same_bytes(entry.result_projection.to_dict(), result.result_projection.to_dict()):
        raise _fail("projection_mismatch", f"entry {entry.result_key!r}: projection differs")


def verify_analysis_execution(
    execution: AnalysisExecution | Mapping[str, Any],
    resolved_results: tuple[AnalysisResult | Mapping[str, Any], ...] | list,
    bundle_dataset_snapshot_locator: ArtifactLocator,
) -> AnalysisExecution:
    """Rebuild `P` from the resolved results and require byte equality (ADR section 6.4).

    `resolved_results` are the in-memory `analysis_result/v1` objects the caller
    resolved; `bundle_dataset_snapshot_locator` is the replay bundle's exact
    `dataset_snapshot_locator`. Returns the verified execution; never mutates input.
    """
    parsed = (
        execution
        if isinstance(execution, AnalysisExecution)
        else AnalysisExecution.from_dict(execution)
    )
    _require_locator(
        bundle_dataset_snapshot_locator,
        DATASET_SNAPSHOT_TYPE,
        label="bundle_dataset_snapshot_locator",
    )
    resolved = _index_resolved(resolved_results)
    bundle = parsed.analysis_replay_input_bundle_locator
    for result in resolved.values():
        _check_resolved_identity(result, bundle, bundle_dataset_snapshot_locator)
    entries = {entry.result_key: entry for entry in parsed.canonical_result_set.results}
    missing = sorted(set(resolved) - set(entries))
    if missing:
        raise _fail("missing_result", f"result set lacks resolved results {missing}")
    extra = sorted(set(entries) - set(resolved))
    if extra:
        raise _fail("extra_result", f"result set entries without a resolved result {extra}")
    for key, entry in entries.items():
        _check_entry(entry, resolved[key])
    ordered = sorted(resolved, key=lambda k: k.encode("utf-8"))
    rebuilt = CanonicalResultSet.build(
        bundle, [CanonicalResultEntry.from_result(resolved[k]) for k in ordered]
    )
    if not _same_bytes(rebuilt.to_dict(), parsed.canonical_result_set.to_dict()):
        raise _fail("digest_mismatch", "rebuilt canonical_result_set differs from the execution")
    return parsed


__all__ = [
    "ANALYSIS_EXECUTION_TYPE", "ANALYSIS_RESULT_SCHEMA_TYPE", "ANALYSIS_RESULT_TYPE",
    "CANONICAL_RESULT_SET_TYPE", "CELL_TYPES", "COLUMN_CELL_TYPES", "DATASET_SNAPSHOT_TYPE",
    "REPLAY_BUNDLE_TYPE", "RESULT_KINDS", "RESULT_SET_ERROR_CODES", "RUN_CONTEXT_TYPE",
    "AnalysisExecution", "AnalysisResult", "AnalysisResultSchema", "CanonicalResultEntry",
    "CanonicalResultSet", "ResultColumn", "ResultProjection", "ResultSetMismatchError",
    "TaggedScalarCell", "verify_analysis_execution", "verify_result_projection",
]
