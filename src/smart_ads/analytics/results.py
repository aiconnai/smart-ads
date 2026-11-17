"""Tagged scalar cells, result projections, canonical result sets, and analysis executions (ADR-0001 section 6.4)."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
from itertools import pairwise
from typing import Any, ClassVar, Final, TypeVar

from smart_ads.analytics.cells import (
    ANALYSIS_EXECUTION_TYPE,
    ANALYSIS_RESULT_SCHEMA_TYPE,
    ANALYSIS_RESULT_TYPE,
    CANONICAL_RESULT_SET_TYPE,
    CELL_TYPES,
    COLUMN_CELL_TYPES,
    DATASET_SNAPSHOT_TYPE,
    REPLAY_BUNDLE_TYPE,
    RESULT_KINDS,
    RESULT_SET_ERROR_CODES,
    RUN_CONTEXT_TYPE,
    AnalysisResultSchema,
    ResultColumn,
    ResultProjection,
    ResultSetMismatchError,
    TaggedScalarCell,
    _check_integrity,
    _closed,
    _coded,
    _fail,
    _guard_rs,
    _locator_of,
    _parse_locator,
    _reparse_p1,
    _require_locator,
    _same_bytes,
    _sequence,
    _split_p1,
    _with_integrity,
    verify_result_projection,
)
from smart_ads.contracts.jcs import ArtifactLocator, P1Integrity, canonicalize_jcs
from smart_ads.contracts.scalars import validate_non_empty_str, validate_sha256_prefixed

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

    def entry(self, result_key: str) -> CanonicalResultEntry:
        """The entry for `result_key` (rejects an unknown key)."""
        for candidate in self.results:
            if type(result_key) is str and candidate.result_key == result_key:
                return candidate
        raise _fail("unknown_result_key", f"canonical_result_set: no entry {result_key!r}")


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


_P1Artifact = TypeVar("_P1Artifact", AnalysisExecution, AnalysisResult, AnalysisResultSchema)


def _resolve(item: object, cls: type[_P1Artifact], require_signed: bool) -> _P1Artifact:
    """Accept a parsed object or a closed mapping; enforce a finalized signature if asked."""
    if isinstance(item, cls):
        fresh = _reparse_p1(item, cls)
        if require_signed and (fresh.integrity is None or not fresh.integrity.is_signed):
            raise _fail("unsigned_artifact", f"{cls.SCHEMA}: finalized P1 signature required")
        return fresh
    if isinstance(item, Mapping):
        parsed = _guard_rs("field_invalid", lambda: cls.from_dict(item, require_signed=require_signed))
        _guard_rs("field_invalid", lambda: canonicalize_jcs(parsed.to_dict()))
        return parsed
    raise _fail("field_invalid", f"expected {cls.__name__} or mapping, got {type(item).__name__}")


def _resolve_run_locator(locator: object) -> ArtifactLocator | None:
    if locator is None:
        return None
    if isinstance(locator, ArtifactLocator):
        return _require_locator(
            locator, RUN_CONTEXT_TYPE, label="bundle_migration_run_context_locator"
        )
    if isinstance(locator, Mapping):
        return _parse_locator(locator, RUN_CONTEXT_TYPE)
    raise _fail("invalid_locator", "bundle_migration_run_context_locator: expected locator")


def _index_resolved(resolved_results: object, require_signed: bool) -> dict[str, AnalysisResult]:
    """Parse resolved results keyed by unique `result_key`."""
    indexed: dict[str, AnalysisResult] = {}
    for item in _sequence(resolved_results, label="resolved_results"):
        result = _resolve(item, AnalysisResult, require_signed)
        if result.result_key in indexed:
            raise _fail("duplicate_result", f"resolved_results: duplicate {result.result_key!r}")
        indexed[result.result_key] = result
    return indexed


def _index_schemas(resolved_schemas: object, require_signed: bool) -> dict[bytes, AnalysisResultSchema]:
    """Parse resolved schemas keyed by the canonical bytes of their locator."""
    indexed: dict[bytes, AnalysisResultSchema] = {}
    for item in _sequence(resolved_schemas, label="resolved_schemas"):
        schema = _resolve(item, AnalysisResultSchema, require_signed)
        key = canonicalize_jcs(schema.locator().to_dict())
        if key in indexed:
            raise _fail("duplicate_schema", "resolved_schemas: the same schema is supplied twice")
        indexed[key] = schema
    return indexed


def _check_projection_schemas(
    resolved: Mapping[str, AnalysisResult], schemas: Mapping[bytes, AnalysisResultSchema]
) -> None:
    """Every result's projection checks against its supplied schema; no schema is unused."""
    referenced: set[bytes] = set()
    for key, result in resolved.items():
        projection = result.result_projection
        locator_key = canonicalize_jcs(projection.analysis_result_schema_locator.to_dict())
        schema = schemas.get(locator_key)
        if schema is None:
            raise _fail("schema_unresolved", f"result {key!r}: result schema was not supplied")
        verify_result_projection(projection, schema)
        referenced.add(locator_key)
    if set(schemas) - referenced:
        raise _fail("unreferenced_schema", "resolved_schemas: a supplied schema is not referenced")


def _check_resolved_identity(
    result: AnalysisResult,
    bundle: ArtifactLocator,
    snapshot: ArtifactLocator,
    run_context: ArtifactLocator,
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
    if not _same_bytes(result.migration_run_context_locator.to_dict(), run_context.to_dict()):
        raise _fail(
            "cross_run_result",
            f"result {result.result_key!r}: migration_run_context_locator != run context",
        )


def _check_entry(entry: CanonicalResultEntry, result: AnalysisResult) -> None:
    if not _same_bytes(entry.result_locator.to_dict(), result.locator().to_dict()):
        raise _fail("result_locator_mismatch", f"entry {entry.result_key!r}: locator differs")
    if not _same_bytes(entry.result_projection.to_dict(), result.result_projection.to_dict()):
        raise _fail("projection_mismatch", f"entry {entry.result_key!r}: projection differs")


def _parse_execution(execution: object, require_signed: bool) -> AnalysisExecution:
    if isinstance(execution, AnalysisExecution):
        return _resolve(execution, AnalysisExecution, require_signed)
    parsed = _guard_rs(
        "field_invalid", lambda: AnalysisExecution.from_dict(execution, require_signed=require_signed)
    )
    _guard_rs("field_invalid", lambda: canonicalize_jcs(parsed.to_dict()))
    return parsed


def _check_all_identities(
    resolved: Mapping[str, AnalysisResult],
    bundle: ArtifactLocator,
    snapshot: ArtifactLocator,
    expected_run: ArtifactLocator | None,
) -> None:
    if not resolved:
        return
    run_loc = (
        expected_run
        if expected_run is not None
        else next(iter(resolved.values())).migration_run_context_locator
    )
    for result in resolved.values():
        _check_resolved_identity(result, bundle, snapshot, run_loc)


def verify_analysis_execution(
    execution: AnalysisExecution | Mapping[str, Any],
    resolved_results: tuple[AnalysisResult | Mapping[str, Any], ...] | list,
    resolved_schemas: tuple[AnalysisResultSchema | Mapping[str, Any], ...] | list,
    bundle_dataset_snapshot_locator: ArtifactLocator,
    *,
    require_signed: bool = False,
    bundle_migration_run_context_locator: ArtifactLocator | Mapping[str, Any] | None = None,
) -> AnalysisExecution:
    """Rebuild `P` from resolved results and enforce bundle, snapshot, and run bindings (ADR 6.4)."""
    if type(require_signed) is not bool:
        raise _fail("field_invalid", "require_signed: expected bool")
    parsed = _parse_execution(execution, require_signed)
    snapshot = _require_locator(
        bundle_dataset_snapshot_locator,
        DATASET_SNAPSHOT_TYPE,
        label="bundle_dataset_snapshot_locator",
    )
    expected_run = _resolve_run_locator(bundle_migration_run_context_locator)
    resolved = _index_resolved(resolved_results, require_signed)
    schemas = _index_schemas(resolved_schemas, require_signed)
    bundle = parsed.analysis_replay_input_bundle_locator
    _check_all_identities(resolved, bundle, snapshot, expected_run)
    entries = {entry.result_key: entry for entry in parsed.canonical_result_set.results}
    missing = sorted(set(resolved) - set(entries))
    if missing:
        raise _fail("missing_result", f"result set lacks resolved results {missing}")
    extra = sorted(set(entries) - set(resolved))
    if extra:
        raise _fail("extra_result", f"result set entries without a resolved result {extra}")
    for key, entry in entries.items():
        _check_entry(entry, resolved[key])
    _check_projection_schemas(resolved, schemas)
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
