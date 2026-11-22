"""Closed DuckDB binary locators, view/query specs, and `analysis_replay_input_bundle/v1` (ADR-0001 §6.4)."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from itertools import pairwise
import re
from typing import Any, ClassVar, Final, Literal, TypeVar

from smart_ads.analytics.cells import (
    ANALYSIS_RESULT_SCHEMA_TYPE, DATASET_SNAPSHOT_TYPE, REPLAY_BUNDLE_TYPE, RUN_CONTEXT_TYPE,
    AnalysisResultSchema, ResultColumn, TaggedScalarCell,
)
from smart_ads.analytics.policy import AnalysisPolicy
from smart_ads.contracts.effects import (
    _P1EnvelopeBase, _require_json_list, _safe_int, _sorted_locator_tuple, _split_p1_envelope,
    _strict_id, _strict_str, _typed_locator, _verify_p1_integrity, validate_cell_object_ref,
)
from smart_ads.contracts.jcs import ADR_P1_DOMAIN_PREFIXES, ArtifactLocator, P1Integrity, canonicalize_jcs
from smart_ads.contracts.scalars import (
    ClosedValidationError, require_exact_keys, validate_non_empty_str, validate_sha256_prefixed,
)

_T = TypeVar("_T")
DuckDbExtensionLoadMode = Literal["statically_linked", "explicit_local_binary"]

DUCKDB_BINARY_LOCATOR_SCHEMA: Final[str] = "smart_ads/duckdb_binary_object_locator/v1"
DUCKDB_EXT_BINARY_LOCATOR_SCHEMA: Final[str] = "smart_ads/duckdb_extension_binary_locator/v1"
FORBIDDEN_DUCKDB_SESSION_SETTINGS: Final[frozenset[str]] = frozenset(
    {"enable_external_access", "autoinstall_known_extensions", "autoload_known_extensions", "lock_configuration"}
)

_ENGINE_MEDIA_TYPE: Final[str] = "application/x-executable"
_EXT_MEDIA_TYPE: Final[str] = "application/x-duckdb-extension"
_RESERVED_LANDING_TABLE: Final[str] = "__smart_ads_landing"
_IDENT_RE: Final[re.Pattern[str]] = re.compile(r"\A[a-z][a-z0-9_]{0,62}\Z")
_SEMVER_RE: Final[re.Pattern[str]] = re.compile(r"\A[0-9]+\.[0-9]+\.[0-9]+\Z")
_EXT_VERSION_RE: Final[re.Pattern[str]] = re.compile(r"\A[0-9A-Za-z][0-9A-Za-z._+-]{0,63}\Z")
_UNPINNED_VERSION_TOKENS: Final[frozenset[str]] = frozenset(
    {"auto", "default", "head", "latest", "main", "master", "unpinned"}
)
_EXT_LOAD_MODES: Final[frozenset[str]] = frozenset({"statically_linked", "explicit_local_binary"})
_ALLOWED_SETTING_CELL_TYPES: Final[frozenset[str]] = frozenset({"boolean", "int64", "utf8"})
_SQL_QUERY_HEAD_RE: Final[re.Pattern[str]] = re.compile(r"\A\s*\(*\s*(?:SELECT|WITH)\b", re.IGNORECASE)
_BINARY_LOCATOR_KEYS: Final[frozenset[str]] = frozenset(
    {"$schema", "store_kind", "object_ref", "media_type", "binary_sha256", "size_bytes"}
)


def _validate_identifier(value: object, *, field_name: str) -> str:
    checked = _strict_str(value, field_name=field_name)
    if _IDENT_RE.fullmatch(checked) is None:
        raise ClosedValidationError(
            f"{field_name}: expected lowercase identifier '^[a-z][a-z0-9_]{{0,62}}$', got {checked!r}"
        )
    return checked


def _validate_sql_query_body(value: object, *, field_name: str) -> str:
    checked = validate_non_empty_str(_strict_str(value, field_name=field_name), field_name=field_name)
    if ";" in checked:
        raise ClosedValidationError(f"{field_name}: ';' statement terminators are forbidden")
    if _SQL_QUERY_HEAD_RE.match(checked) is None:
        raise ClosedValidationError(f"{field_name}: expected single SELECT or WITH query expression")
    return checked


def _sorted_typed_items(
    values: object, cls: type[_T], key_fn: Any, *, allow_empty: bool, field_name: str
) -> tuple[_T, ...]:
    if not isinstance(values, (list, tuple)):
        raise ClosedValidationError(f"{field_name}: expected list or tuple of {cls.__name__}")
    items: list[_T] = []
    keys: list[bytes] = []
    for idx, raw in enumerate(values):
        if type(raw) is not cls:
            raise ClosedValidationError(f"{field_name}[{idx}]: expected {cls.__name__}, got {type(raw).__name__}")
        fresh: _T = cls.from_dict(raw.to_dict())  # type: ignore[attr-defined]
        items.append(fresh)
        keys.append(key_fn(fresh).encode("utf-8"))
    if not allow_empty and not items:
        raise ClosedValidationError(f"{field_name}: must not be empty")
    if len(set(keys)) != len(keys):
        raise ClosedValidationError(f"{field_name}: duplicate identifier")
    if any(left > right for left, right in pairwise(keys)):
        raise ClosedValidationError(f"{field_name}: elements must be sorted by ascending raw UTF-8 key bytes")
    return tuple(items)


class _BinaryLocatorBase:
    """Shared validation, serialization, and byte factory for DuckDB binary object locators."""

    __slots__ = ()
    SCHEMA: ClassVar[str]
    KEYS: ClassVar[frozenset[str]] = _BINARY_LOCATOR_KEYS
    _EXPECTED_MEDIA_TYPE: ClassVar[str]
    _LABEL: ClassVar[str]

    def _validate_locator(self) -> None:
        label = self._LABEL
        sha = validate_sha256_prefixed(
            _strict_str(self.binary_sha256, field_name=f"{label}.binary_sha256"),  # type: ignore[attr-defined]
            field_name=f"{label}.binary_sha256",
        )
        _safe_int(self.size_bytes, field_name=f"{label}.size_bytes", minimum=1)  # type: ignore[attr-defined]
        if _strict_str(self.store_kind, field_name=f"{label}.store_kind") != "cell_immutable_object":  # type: ignore[attr-defined]
            raise ClosedValidationError(f"{label}.store_kind: must equal 'cell_immutable_object'")
        if _strict_str(self.media_type, field_name=f"{label}.media_type") != self._EXPECTED_MEDIA_TYPE:  # type: ignore[attr-defined]
            raise ClosedValidationError(f"{label}.media_type: must equal {self._EXPECTED_MEDIA_TYPE!r}")
        expected_ref = f"cell-object:{sha}"
        raw_ref = _strict_str(self.object_ref, field_name=f"{label}.object_ref")  # type: ignore[attr-defined]
        if raw_ref == "":
            object.__setattr__(self, "object_ref", expected_ref)
        elif raw_ref != expected_ref:
            raise ClosedValidationError(f"{label}.object_ref: expected {expected_ref!r}, got {raw_ref!r}")

    @classmethod
    def for_binary_bytes(cls: type[_T], raw_bytes: bytes) -> _T:
        if type(raw_bytes) is not bytes or len(raw_bytes) == 0:
            raise ClosedValidationError("raw_bytes: expected non-empty bytes")
        digest = "sha256:" + hashlib.sha256(raw_bytes).hexdigest()
        return cls(binary_sha256=digest, size_bytes=len(raw_bytes), object_ref=f"cell-object:{digest}")  # type: ignore[call-arg]

    def to_dict(self) -> dict[str, Any]:
        return {
            "$schema": self.SCHEMA,
            "store_kind": self.store_kind,  # type: ignore[attr-defined]
            "object_ref": self.object_ref,  # type: ignore[attr-defined]
            "media_type": self.media_type,  # type: ignore[attr-defined]
            "binary_sha256": self.binary_sha256,  # type: ignore[attr-defined]
            "size_bytes": self.size_bytes,  # type: ignore[attr-defined]
        }

    @classmethod
    def from_dict(cls: type[_T], data: object) -> _T:
        label: str = cls._LABEL  # type: ignore[attr-defined]
        schema: str = cls.SCHEMA  # type: ignore[attr-defined]
        m = require_exact_keys(data, _BINARY_LOCATOR_KEYS, label=label)
        if type(m["$schema"]) is not str or m["$schema"] != schema:
            raise ClosedValidationError(f"{label}.$schema: expected {schema!r}")
        ref = validate_cell_object_ref(m["object_ref"], field_name=f"{label}.object_ref")
        return cls(  # type: ignore[call-arg]
            binary_sha256=m["binary_sha256"], size_bytes=m["size_bytes"],
            store_kind=m["store_kind"], media_type=m["media_type"], object_ref=ref,
        )


@dataclass(frozen=True, slots=True)
class DuckDbBinaryObjectLocator(_BinaryLocatorBase):
    """Closed 6-member `smart_ads/duckdb_binary_object_locator/v1` embedded locator."""

    SCHEMA: ClassVar[str] = DUCKDB_BINARY_LOCATOR_SCHEMA
    _EXPECTED_MEDIA_TYPE: ClassVar[str] = _ENGINE_MEDIA_TYPE
    _LABEL: ClassVar[str] = "duckdb_binary_object_locator"

    binary_sha256: str
    size_bytes: int
    store_kind: str = "cell_immutable_object"
    media_type: str = _ENGINE_MEDIA_TYPE
    object_ref: str = ""

    def __post_init__(self) -> None:
        self._validate_locator()


@dataclass(frozen=True, slots=True)
class DuckDbExtensionBinaryLocator(_BinaryLocatorBase):
    """Closed 6-member `smart_ads/duckdb_extension_binary_locator/v1` embedded locator."""

    SCHEMA: ClassVar[str] = DUCKDB_EXT_BINARY_LOCATOR_SCHEMA
    _EXPECTED_MEDIA_TYPE: ClassVar[str] = _EXT_MEDIA_TYPE
    _LABEL: ClassVar[str] = "duckdb_extension_binary_locator"

    binary_sha256: str
    size_bytes: int
    store_kind: str = "cell_immutable_object"
    media_type: str = _EXT_MEDIA_TYPE
    object_ref: str = ""

    def __post_init__(self) -> None:
        self._validate_locator()


@dataclass(frozen=True, slots=True)
class DuckDbExtensionSpec:
    """Closed 4-member DuckDB extension specification."""

    KEYS: ClassVar[frozenset[str]] = frozenset(
        {"extension_name", "extension_version", "load_mode", "binary_locator"}
    )

    extension_name: str
    extension_version: str
    load_mode: DuckDbExtensionLoadMode
    binary_locator: DuckDbExtensionBinaryLocator | None = None

    def __post_init__(self) -> None:
        label = "duckdb_extension_spec"
        _validate_identifier(self.extension_name, field_name=f"{label}.extension_name")
        ver = _strict_str(self.extension_version, field_name=f"{label}.extension_version")
        if _EXT_VERSION_RE.fullmatch(ver) is None or ver.lower() in _UNPINNED_VERSION_TOKENS:
            raise ClosedValidationError(f"{label}.extension_version: expected exact pinned version, got {ver!r}")
        mode = _strict_str(self.load_mode, field_name=f"{label}.load_mode")
        if mode not in _EXT_LOAD_MODES:
            raise ClosedValidationError(f"{label}.load_mode: invalid load_mode {mode!r}")
        if mode == "statically_linked":
            if self.binary_locator is not None:
                raise ClosedValidationError(f"{label}.binary_locator: must be None when load_mode='statically_linked'")
        else:
            if type(self.binary_locator) is not DuckDbExtensionBinaryLocator:
                raise ClosedValidationError(f"{label}.binary_locator: required when load_mode='explicit_local_binary'")
            DuckDbExtensionBinaryLocator.from_dict(self.binary_locator.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "extension_name": self.extension_name,
            "extension_version": self.extension_version,
            "load_mode": self.load_mode,
            "binary_locator": None if self.binary_locator is None else self.binary_locator.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: object) -> DuckDbExtensionSpec:
        m = require_exact_keys(data, cls.KEYS, label="duckdb_extension_spec")
        raw_loc = m["binary_locator"]
        return cls(
            extension_name=m["extension_name"],
            extension_version=m["extension_version"],
            load_mode=m["load_mode"],
            binary_locator=None if raw_loc is None else DuckDbExtensionBinaryLocator.from_dict(raw_loc),
        )


@dataclass(frozen=True, slots=True)
class DuckDbSessionSetting:
    """Closed 2-member DuckDB session setting rejecting security lockdown overrides."""

    KEYS: ClassVar[frozenset[str]] = frozenset({"setting_name", "setting_value"})

    setting_name: str
    setting_value: TaggedScalarCell

    def __post_init__(self) -> None:
        label = "duckdb_session_setting"
        raw_name = _strict_str(self.setting_name, field_name=f"{label}.setting_name")
        if raw_name.strip().lower() in FORBIDDEN_DUCKDB_SESSION_SETTINGS:
            raise ClosedValidationError(f"{label}.setting_name: security setting {raw_name!r} cannot be overridden")
        _validate_identifier(raw_name, field_name=f"{label}.setting_name")
        if type(self.setting_value) is not TaggedScalarCell:
            raise ClosedValidationError(f"{label}.setting_value: expected TaggedScalarCell")
        fresh_val = TaggedScalarCell.from_dict(self.setting_value.to_dict())
        if fresh_val.cell_type not in _ALLOWED_SETTING_CELL_TYPES:
            raise ClosedValidationError(f"{label}.setting_value: unsupported cell_type {fresh_val.cell_type!r}")
        object.__setattr__(self, "setting_value", fresh_val)

    def to_dict(self) -> dict[str, Any]:
        return {"setting_name": self.setting_name, "setting_value": self.setting_value.to_dict()}

    @classmethod
    def from_dict(cls, data: object) -> DuckDbSessionSetting:
        m = require_exact_keys(data, cls.KEYS, label="duckdb_session_setting")
        return cls(setting_name=m["setting_name"], setting_value=TaggedScalarCell.from_dict(m["setting_value"]))


@dataclass(frozen=True, slots=True)
class DuckDbViewDefinition:
    """Closed 3-member temporary view definition in `analysis_replay_input_bundle/v1`."""

    KEYS: ClassVar[frozenset[str]] = frozenset({"view_name", "sql_utf8", "depends_on_views"})

    view_name: str
    sql_utf8: str
    depends_on_views: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        label = "duckdb_view_definition"
        raw_name = _strict_str(self.view_name, field_name=f"{label}.view_name")
        if raw_name.strip().lower() == _RESERVED_LANDING_TABLE:
            raise ClosedValidationError(f"{label}.view_name: {_RESERVED_LANDING_TABLE!r} is reserved")
        _validate_identifier(raw_name, field_name=f"{label}.view_name")
        _validate_sql_query_body(self.sql_utf8, field_name=f"{label}.sql_utf8")
        if not isinstance(self.depends_on_views, (list, tuple)):
            raise ClosedValidationError(f"{label}.depends_on_views: expected list or tuple of view names")
        deps = tuple(_validate_identifier(dep, field_name=f"{label}.depends_on_views") for dep in self.depends_on_views)
        if self.view_name in deps:
            raise ClosedValidationError(f"{label}.depends_on_views: view {self.view_name!r} cannot depend on itself")
        dep_bytes = [d.encode("utf-8") for d in deps]
        if len(set(dep_bytes)) != len(dep_bytes) or any(left > right for left, right in pairwise(dep_bytes)):
            raise ClosedValidationError(f"{label}.depends_on_views: must be unique and sorted by raw UTF-8 bytes")
        object.__setattr__(self, "depends_on_views", deps)

    def to_dict(self) -> dict[str, Any]:
        return {"view_name": self.view_name, "sql_utf8": self.sql_utf8, "depends_on_views": list(self.depends_on_views)}

    @classmethod
    def from_dict(cls, data: object) -> DuckDbViewDefinition:
        m = require_exact_keys(data, cls.KEYS, label="duckdb_view_definition")
        raw_deps = _require_json_list(m, "depends_on_views", label="duckdb_view_definition")
        return cls(view_name=m["view_name"], sql_utf8=m["sql_utf8"], depends_on_views=tuple(raw_deps))


def _compute_topological_views(views: tuple[DuckDbViewDefinition, ...]) -> tuple[DuckDbViewDefinition, ...]:
    by_name = {v.view_name: v for v in views}
    indegree: dict[str, int] = {v.view_name: len(v.depends_on_views) for v in views}
    dependents: dict[str, list[str]] = {v.view_name: [] for v in views}
    for view in views:
        for dep in view.depends_on_views:
            if dep not in by_name:
                raise ClosedValidationError(f"views: {view.view_name!r} depends on undeclared view {dep!r}")
            dependents[dep].append(view.view_name)
    ready = [name for name, deg in indegree.items() if deg == 0]
    ordered: list[DuckDbViewDefinition] = []
    while ready:
        curr = min(ready, key=lambda n: n.encode("utf-8"))
        ready.remove(curr)
        ordered.append(by_name[curr])
        for child in dependents[curr]:
            indegree[child] -= 1
            if indegree[child] == 0:
                ready.append(child)
    if len(ordered) != len(views):
        emitted = {v.view_name for v in ordered}
        stuck = sorted((name for name in by_name if name not in emitted), key=lambda n: n.encode("utf-8"))
        raise ClosedValidationError(f"views: dependency cycle detected across {stuck!r}")
    return tuple(ordered)


def _validate_order_by(
    order_by: object, *, result_kind: str, declared_names: frozenset[str], label: str
) -> tuple[str, ...]:
    if not isinstance(order_by, (list, tuple)):
        raise ClosedValidationError(f"{label}.deterministic_order_by: expected list or tuple")
    cols = tuple(_strict_str(col, field_name=f"{label}.deterministic_order_by") for col in order_by)
    if result_kind == "scalar":
        if cols:
            raise ClosedValidationError(f"{label}.deterministic_order_by: must be empty for scalar query")
        return ()
    if not cols or len(set(cols)) != len(cols) or any(c not in declared_names for c in cols):
        raise ClosedValidationError(f"{label}.deterministic_order_by: relation query requires unique declared column names")
    return cols


@dataclass(frozen=True, slots=True)
class DuckDbQueryDefinition:
    """Closed 8-member query definition in `analysis_replay_input_bundle/v1`."""

    KEYS: ClassVar[frozenset[str]] = frozenset(
        "result_key query_id sql_utf8 analysis_result_schema_locator inline_result_kind "
        "inline_columns inline_unique_key deterministic_order_by".split()
    )

    result_key: str
    query_id: str
    sql_utf8: str
    analysis_result_schema_locator: ArtifactLocator
    inline_result_kind: Literal["scalar", "relation"]
    inline_columns: tuple[ResultColumn, ...]
    inline_unique_key: tuple[str, ...] | None = None
    deterministic_order_by: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        label = "duckdb_query_definition"
        _strict_id(self.result_key, field_name=f"{label}.result_key")
        _strict_id(self.query_id, field_name=f"{label}.query_id")
        _validate_sql_query_body(self.sql_utf8, field_name=f"{label}.sql_utf8")
        _typed_locator(
            self.analysis_result_schema_locator,
            field_name=f"{label}.analysis_result_schema_locator",
            expected_type=ANALYSIS_RESULT_SCHEMA_TYPE,
        )
        if not isinstance(self.inline_columns, (list, tuple)):
            raise ClosedValidationError(f"{label}.inline_columns: expected list or tuple")
        cols = tuple(ResultColumn.from_dict(c.to_dict()) if type(c) is ResultColumn else c for c in self.inline_columns)
        inline_schema = AnalysisResultSchema(
            result_kind=self.inline_result_kind, columns=cols, unique_key=self.inline_unique_key
        )
        object.__setattr__(self, "inline_columns", inline_schema.columns)
        object.__setattr__(self, "inline_unique_key", inline_schema.unique_key)
        declared = frozenset(c.name for c in inline_schema.columns)
        order_cols = _validate_order_by(
            self.deterministic_order_by, result_kind=inline_schema.result_kind, declared_names=declared, label=label
        )
        object.__setattr__(self, "deterministic_order_by", order_cols)

    def verify_against_schema(self, resolved_schema: AnalysisResultSchema) -> None:
        """Verify locator and inline kind/columns/unique_key against `resolved_schema`."""
        if type(resolved_schema) is not AnalysisResultSchema:
            raise ClosedValidationError("resolved_schema: expected AnalysisResultSchema")
        fresh = AnalysisResultSchema.from_dict(resolved_schema.to_dict())
        if canonicalize_jcs(self.analysis_result_schema_locator.to_dict()) != canonicalize_jcs(fresh.locator().to_dict()):
            raise ClosedValidationError(f"query {self.result_key!r}: schema locator differs from resolved schema")
        if (self.inline_result_kind, self.inline_columns, self.inline_unique_key) != (
            fresh.result_kind, fresh.columns, fresh.unique_key
        ):
            raise ClosedValidationError(f"query {self.result_key!r}: inline schema differs from resolved schema")

    def to_dict(self) -> dict[str, Any]:
        return {
            "result_key": self.result_key,
            "query_id": self.query_id,
            "sql_utf8": self.sql_utf8,
            "analysis_result_schema_locator": self.analysis_result_schema_locator.to_dict(),
            "inline_result_kind": self.inline_result_kind,
            "inline_columns": [col.to_dict() for col in self.inline_columns],
            "inline_unique_key": None if self.inline_unique_key is None else list(self.inline_unique_key),
            "deterministic_order_by": list(self.deterministic_order_by),
        }

    @classmethod
    def from_dict(cls, data: object) -> DuckDbQueryDefinition:
        m = require_exact_keys(data, cls.KEYS, label="duckdb_query_definition")
        raw_cols = _require_json_list(m, "inline_columns", label="duckdb_query_definition")
        raw_order = _require_json_list(m, "deterministic_order_by", label="duckdb_query_definition")
        raw_ukey = m["inline_unique_key"]
        if raw_ukey is not None and not isinstance(raw_ukey, list):
            raise ClosedValidationError("duckdb_query_definition.inline_unique_key: expected JSON array list or null")
        return cls(
            result_key=m["result_key"],
            query_id=m["query_id"],
            sql_utf8=m["sql_utf8"],
            analysis_result_schema_locator=ArtifactLocator.from_dict(
                m["analysis_result_schema_locator"], expected_type=ANALYSIS_RESULT_SCHEMA_TYPE
            ),
            inline_result_kind=m["inline_result_kind"],
            inline_columns=tuple(ResultColumn.from_dict(c) for c in raw_cols),
            inline_unique_key=None if raw_ukey is None else tuple(raw_ukey),
            deterministic_order_by=tuple(raw_order),
        )


@dataclass(frozen=True, slots=True)
class AnalysisReplayInputBundle(_P1EnvelopeBase):
    """Closed P1 `smart_ads/analysis_replay_input_bundle/v1` (12 core + `integrity` = 13 keys)."""

    SCHEMA: ClassVar[str] = REPLAY_BUNDLE_TYPE
    P1_DOMAIN_PREFIX: ClassVar[str] = ADR_P1_DOMAIN_PREFIXES[REPLAY_BUNDLE_TYPE]
    CORE_KEYS: ClassVar[frozenset[str]] = frozenset(
        "$schema bundle_id migration_run_context_locator dataset_snapshot_locator duckdb_engine_version "
        "duckdb_binary_locator extensions session_settings views queries analysis_policy_locator "
        "build_input_locators".split()
    )
    KEYS: ClassVar[frozenset[str]] = CORE_KEYS | {"integrity"}

    bundle_id: str
    migration_run_context_locator: ArtifactLocator
    dataset_snapshot_locator: ArtifactLocator
    duckdb_engine_version: str
    duckdb_binary_locator: DuckDbBinaryObjectLocator
    extensions: tuple[DuckDbExtensionSpec, ...]
    session_settings: tuple[DuckDbSessionSetting, ...]
    views: tuple[DuckDbViewDefinition, ...]
    queries: tuple[DuckDbQueryDefinition, ...]
    analysis_policy_locator: ArtifactLocator
    build_input_locators: tuple[ArtifactLocator, ...]
    integrity: P1Integrity | None = None

    def __post_init__(self) -> None:
        label = "analysis_replay_input_bundle"
        _strict_id(self.bundle_id, field_name=f"{label}.bundle_id")
        _typed_locator(self.migration_run_context_locator, field_name=f"{label}.migration_run_context_locator", expected_type=RUN_CONTEXT_TYPE)
        _typed_locator(self.dataset_snapshot_locator, field_name=f"{label}.dataset_snapshot_locator", expected_type=DATASET_SNAPSHOT_TYPE)
        ver = _strict_str(self.duckdb_engine_version, field_name=f"{label}.duckdb_engine_version")
        if _SEMVER_RE.fullmatch(ver) is None:
            raise ClosedValidationError(f"{label}.duckdb_engine_version: expected 'X.Y.Z' semver, got {ver!r}")
        if type(self.duckdb_binary_locator) is not DuckDbBinaryObjectLocator:
            raise ClosedValidationError(f"{label}.duckdb_binary_locator: expected DuckDbBinaryObjectLocator")
        object.__setattr__(self, "duckdb_binary_locator", DuckDbBinaryObjectLocator.from_dict(self.duckdb_binary_locator.to_dict()))
        self._validate_collections(label)
        _typed_locator(self.analysis_policy_locator, field_name=f"{label}.analysis_policy_locator", expected_type=AnalysisPolicy.SCHEMA)
        object.__setattr__(self, "build_input_locators", _sorted_locator_tuple(self.build_input_locators, field_name=f"{label}.build_input_locators", allow_empty=False))
        _verify_p1_integrity(self.integrity, self.to_dict, label=label)

    def _validate_collections(self, label: str) -> None:
        object.__setattr__(self, "extensions", _sorted_typed_items(self.extensions, DuckDbExtensionSpec, lambda e: e.extension_name, allow_empty=True, field_name=f"{label}.extensions"))
        object.__setattr__(self, "session_settings", _sorted_typed_items(self.session_settings, DuckDbSessionSetting, lambda s: s.setting_name, allow_empty=True, field_name=f"{label}.session_settings"))
        checked_views = _sorted_typed_items(self.views, DuckDbViewDefinition, lambda v: v.view_name, allow_empty=True, field_name=f"{label}.views")
        _compute_topological_views(checked_views)
        object.__setattr__(self, "views", checked_views)
        checked_queries = _sorted_typed_items(self.queries, DuckDbQueryDefinition, lambda q: q.result_key, allow_empty=False, field_name=f"{label}.queries")
        qids = [q.query_id for q in checked_queries]
        if len(set(qids)) != len(qids):
            raise ClosedValidationError(f"{label}.queries: duplicate query_id")
        object.__setattr__(self, "queries", checked_queries)

    def topological_views(self) -> tuple[DuckDbViewDefinition, ...]:
        """Return `self.views` in deterministic topological execution order."""
        return _compute_topological_views(self.views)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "$schema": self.SCHEMA,
            "bundle_id": self.bundle_id,
            "migration_run_context_locator": self.migration_run_context_locator.to_dict(),
            "dataset_snapshot_locator": self.dataset_snapshot_locator.to_dict(),
            "duckdb_engine_version": self.duckdb_engine_version,
            "duckdb_binary_locator": self.duckdb_binary_locator.to_dict(),
            "extensions": [ext.to_dict() for ext in self.extensions],
            "session_settings": [s.to_dict() for s in self.session_settings],
            "views": [v.to_dict() for v in self.views],
            "queries": [q.to_dict() for q in self.queries],
            "analysis_policy_locator": self.analysis_policy_locator.to_dict(),
            "build_input_locators": [loc.to_dict() for loc in self.build_input_locators],
        }
        return out if self.integrity is None else {**out, "integrity": self.integrity.to_dict()}

    @classmethod
    def from_dict(cls, data: object, *, require_signed: bool = False) -> AnalysisReplayInputBundle:
        m, integrity = _split_p1_envelope(
            data, core_keys=cls.CORE_KEYS, schema=cls.SCHEMA, label="analysis_replay_input_bundle", require_signed=require_signed
        )
        raw_exts = _require_json_list(m, "extensions", label="analysis_replay_input_bundle")
        raw_sets = _require_json_list(m, "session_settings", label="analysis_replay_input_bundle")
        raw_views = _require_json_list(m, "views", label="analysis_replay_input_bundle")
        raw_queries = _require_json_list(m, "queries", label="analysis_replay_input_bundle")
        raw_builds = _require_json_list(m, "build_input_locators", label="analysis_replay_input_bundle")
        return cls(
            bundle_id=m["bundle_id"],
            migration_run_context_locator=ArtifactLocator.from_dict(m["migration_run_context_locator"], expected_type=RUN_CONTEXT_TYPE),
            dataset_snapshot_locator=ArtifactLocator.from_dict(m["dataset_snapshot_locator"], expected_type=DATASET_SNAPSHOT_TYPE),
            duckdb_engine_version=m["duckdb_engine_version"],
            duckdb_binary_locator=DuckDbBinaryObjectLocator.from_dict(m["duckdb_binary_locator"]),
            extensions=tuple(DuckDbExtensionSpec.from_dict(e) for e in raw_exts),
            session_settings=tuple(DuckDbSessionSetting.from_dict(s) for s in raw_sets),
            views=tuple(DuckDbViewDefinition.from_dict(v) for v in raw_views),
            queries=tuple(DuckDbQueryDefinition.from_dict(q) for q in raw_queries),
            analysis_policy_locator=ArtifactLocator.from_dict(m["analysis_policy_locator"], expected_type=AnalysisPolicy.SCHEMA),
            build_input_locators=tuple(ArtifactLocator.from_dict(b) for b in raw_builds),
            integrity=integrity,
        )


__all__ = [
    "AnalysisReplayInputBundle",
    "DUCKDB_BINARY_LOCATOR_SCHEMA",
    "DUCKDB_EXT_BINARY_LOCATOR_SCHEMA",
    "DuckDbBinaryObjectLocator",
    "DuckDbExtensionBinaryLocator",
    "DuckDbExtensionLoadMode",
    "DuckDbExtensionSpec",
    "DuckDbQueryDefinition",
    "DuckDbSessionSetting",
    "DuckDbViewDefinition",
    "FORBIDDEN_DUCKDB_SESSION_SETTINGS",
]
