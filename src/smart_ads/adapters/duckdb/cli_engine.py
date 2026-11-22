"""Empirically hardened external DuckDB CLI replay engine adapter (ADR-0001 §6.4)."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
from types import MappingProxyType
from typing import Any, Final
import unicodedata

from smart_ads.analytics.cells import (
    AnalysisResultSchema,
    ResultColumn,
    ResultProjection,
    TaggedScalarCell,
    verify_result_projection,
)
from smart_ads.analytics.replay_bundle import (
    FORBIDDEN_DUCKDB_SESSION_SETTINGS,
    AnalysisReplayInputBundle,
    DuckDbExtensionBinaryLocator,
    DuckDbQueryDefinition,
    DuckDbSessionSetting,
)
from smart_ads.contracts.jcs import canonicalize_jcs, loads_strict_json
from smart_ads.contracts.scalars import ClosedValidationError
from smart_ads.domain.catalog import ParquetObjectLocator
from smart_ads.ports.storage import DuckDbEnginePort

_DUCKDB_VERSION_RE: Final[re.Pattern[str]] = re.compile(
    r"\Av([0-9]+\.[0-9]+\.[0-9]+)(?:\s|\Z)"
)
_DECIMAL6_DUCK_TYPE_RE: Final[re.Pattern[str]] = re.compile(
    r"\ADECIMAL\(([1-9][0-9]*),\s*6\)\Z"
)
_INT64_DUCK_TYPES: Final[frozenset[str]] = frozenset(
    {"TINYINT", "SMALLINT", "INTEGER", "BIGINT", "HUGEINT"}
)
_TIMESTAMP_DUCK_TYPES: Final[frozenset[str]] = frozenset(
    {"TIMESTAMP", "TIMESTAMP WITH TIME ZONE"}
)
_IDENT_RE: Final[re.Pattern[str]] = re.compile(r"\A[a-z][a-z0-9_]{0,62}\Z")
_INT64_LIT_RE: Final[re.Pattern[str]] = re.compile(r"\A(0|-?[1-9][0-9]{0,18})\Z")
_EXTRA_LOCKED_SETTINGS: Final[frozenset[str]] = frozenset(
    {
        "allow_community_extensions",
        "allow_unsigned_extensions",
        "allowed_directories",
        "allowed_paths",
        "autoinstall_extension_repository",
        "custom_extension_repository",
        "disabled_filesystems",
        "extension_directory",
        "home_directory",
        "secret_directory",
        "temp_directory",
    }
)


def _verify_blob_digest_and_size(
    raw: object, *, expected_sha256: str, expected_size: int, label: str
) -> bytes:
    if type(raw) is not bytes:
        raise ClosedValidationError(f"{label}: expected bytes, got {type(raw).__name__}")
    if len(raw) != expected_size:
        raise ClosedValidationError(
            f"{label}: size mismatch (expected {expected_size}, got {len(raw)})"
        )
    actual_sha = "sha256:" + hashlib.sha256(raw).hexdigest()
    if actual_sha != expected_sha256:
        raise ClosedValidationError(
            f"{label}: SHA-256 mismatch (expected {expected_sha256}, got {actual_sha})"
        )
    return raw


def _verify_extension_blobs(
    bundle: AnalysisReplayInputBundle, extension_binaries: object
) -> dict[str, bytes]:
    if not isinstance(extension_binaries, Mapping):
        raise ClosedValidationError("extension_binaries: expected Mapping[str, bytes]")
    expected: dict[str, DuckDbExtensionBinaryLocator] = {}
    for ext in bundle.extensions:
        if ext.load_mode == "explicit_local_binary":
            if ext.binary_locator is None:
                raise ClosedValidationError(f"extension {ext.extension_name!r}: missing binary_locator")
            expected[ext.extension_name] = ext.binary_locator
    if any(type(k) is not str for k in extension_binaries) or set(extension_binaries) != set(expected):
        raise ClosedValidationError("extension_binaries: keys do not match explicit_local_binary extensions")
    verified: dict[str, bytes] = {}
    for name in sorted(expected):
        loc = expected[name]
        verified[name] = _verify_blob_digest_and_size(
            extension_binaries[name],
            expected_sha256=loc.binary_sha256,
            expected_size=loc.size_bytes,
            label=f"extension_binaries[{name!r}]",
        )
    return verified


def _verify_parquet_inputs(
    parquet_objects: object,
) -> tuple[tuple[ParquetObjectLocator, bytes], ...]:
    if isinstance(parquet_objects, (str, bytes)) or not isinstance(parquet_objects, Sequence) or not parquet_objects:
        raise ClosedValidationError("parquet_objects: expected non-empty Sequence of (ParquetObjectLocator, bytes)")
    checked: list[tuple[ParquetObjectLocator, bytes]] = []
    for idx, item in enumerate(parquet_objects):
        if not isinstance(item, tuple) or len(item) != 2 or type(item[0]) is not ParquetObjectLocator:
            raise ClosedValidationError(f"parquet_objects[{idx}]: expected (ParquetObjectLocator, bytes)")
        fresh_loc = ParquetObjectLocator.from_dict(item[0].to_dict())
        if item[0] != fresh_loc:
            raise ClosedValidationError(f"parquet_objects[{idx}]: corrupted ParquetObjectLocator")
        raw_pq = _verify_blob_digest_and_size(
            item[1],
            expected_sha256=fresh_loc.physical_parquet_digest,
            expected_size=fresh_loc.size_bytes,
            label=f"parquet_objects[{idx}]",
        )
        checked.append((fresh_loc, raw_pq))
    return tuple(checked)


def _verify_resolved_schemas_map(
    bundle: AnalysisReplayInputBundle, resolved_schemas: object
) -> dict[bytes, AnalysisResultSchema]:
    if not isinstance(resolved_schemas, Mapping):
        raise ClosedValidationError("resolved_schemas: expected Mapping[bytes, AnalysisResultSchema]")
    checked: dict[bytes, AnalysisResultSchema] = {}
    for key, schema in resolved_schemas.items():
        if type(key) is not bytes or type(schema) is not AnalysisResultSchema:
            raise ClosedValidationError("resolved_schemas: expected bytes keys and AnalysisResultSchema values")
        fresh_s = AnalysisResultSchema.from_dict(schema.to_dict())
        if schema != fresh_s or canonicalize_jcs(fresh_s.locator().to_dict()) != key:
            raise ClosedValidationError("resolved_schemas: schema locator key mismatch")
        checked[key] = fresh_s
    referenced: set[bytes] = set()
    for q in bundle.queries:
        s_key = canonicalize_jcs(q.analysis_result_schema_locator.to_dict())
        target_s = checked.get(s_key)
        if target_s is None:
            raise ClosedValidationError(f"resolved_schemas: missing schema for query {q.result_key!r}")
        q.verify_against_schema(target_s)
        referenced.add(s_key)
    if set(checked) != referenced:
        raise ClosedValidationError("resolved_schemas: unreferenced schema supplied")
    return checked


def _write_staged_file(path: Path, raw: bytes, mode: int) -> Path:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, mode)
    except OSError as exc:
        raise ClosedValidationError(f"duckdb staging: failed to create {path.name}: {exc}") from exc
    try:
        view = memoryview(raw)
        written = 0
        while written < len(raw):
            written += os.write(fd, view[written:])
        os.fchmod(fd, mode)
    except OSError as exc:
        raise ClosedValidationError(f"duckdb staging: failed to write {path.name}: {exc}") from exc
    finally:
        os.close(fd)
    return path


def _quote_sql_string(value: str, *, label: str) -> str:
    if "\x00" in value:
        raise ClosedValidationError(f"{label}: NUL byte is forbidden in SQL string literal")
    return "'" + value.replace("'", "''") + "'"


def _quote_sql_path(path: Path, *, label: str) -> str:
    posix_path = path.as_posix()
    if any(ch in posix_path for ch in ("\x00", "\r", "\n")):
        raise ClosedValidationError(f"{label}: control characters forbidden in staged path")
    return _quote_sql_string(posix_path, label=label)


def _quote_sql_ident(name: str, *, label: str) -> str:
    if not name or "\x00" in name:
        raise ClosedValidationError(f"{label}: invalid SQL identifier")
    return '"' + name.replace('"', '""') + '"'


def _format_session_setting_sql(setting: DuckDbSessionSetting) -> str:
    sname = setting.setting_name
    low = sname.lower()
    if low in FORBIDDEN_DUCKDB_SESSION_SETTINGS or low in _EXTRA_LOCKED_SETTINGS or _IDENT_RE.fullmatch(sname) is None:
        raise ClosedValidationError(f"session_settings: forbidden or invalid setting {sname!r}")
    cell = setting.setting_value
    if cell.cell_type == "boolean":
        if type(cell.value) is not bool:
            raise ClosedValidationError(f"session_settings[{sname!r}]: expected bool")
        lit = "true" if cell.value else "false"
    elif cell.cell_type == "int64":
        if type(cell.value) is not str or _INT64_LIT_RE.fullmatch(cell.value) is None:
            raise ClosedValidationError(f"session_settings[{sname!r}]: invalid int64 literal")
        lit = cell.value
    elif cell.cell_type == "utf8":
        if type(cell.value) is not str:
            raise ClosedValidationError(f"session_settings[{sname!r}]: expected str")
        lit = _quote_sql_string(cell.value, label=f"session_settings[{sname!r}]")
    else:
        raise ClosedValidationError(f"session_settings[{sname!r}]: unsupported cell_type {cell.cell_type!r}")
    return f"SET {_quote_sql_ident(sname, label='setting_name')} = {lit};"


def _build_lockdown_preamble_sql(
    bundle: AnalysisReplayInputBundle,
    staged_exts: Mapping[str, Path],
    staged_parquets: Sequence[Path],
    *,
    home_dir: Path,
    tmp_dir: Path,
) -> str:
    lines = [
        "SET autoinstall_known_extensions = false;",
        "SET autoload_known_extensions = false;",
    ]
    for ext in bundle.extensions:
        if ext.load_mode == "explicit_local_binary":
            lines.append(f"LOAD {_quote_sql_path(staged_exts[ext.extension_name], label='ext_path')};")
    pq_list = ", ".join(_quote_sql_path(p, label="parquet_path") for p in staged_parquets)
    lines.append(f"CREATE TEMP TABLE __smart_ads_landing AS SELECT * FROM read_parquet([{pq_list}]);")
    for setting in bundle.session_settings:
        lines.append(_format_session_setting_sql(setting))
    lines.append(f"SET home_directory = {_quote_sql_path(home_dir, label='home_dir')};")
    lines.append(f"SET temp_directory = {_quote_sql_path(tmp_dir, label='tmp_dir')};")
    lines.append("SET enable_external_access = false;")
    lines.append("SET lock_configuration = true;")
    for view in bundle.topological_views():
        if ";" in view.sql_utf8 or "\x00" in view.sql_utf8:
            raise ClosedValidationError(f"view {view.view_name!r}: ';' or NUL forbidden")
        lines.append(f"CREATE TEMP VIEW {_quote_sql_ident(view.view_name, label='view_name')} AS (\n{view.sql_utf8}\n);")
    return "\n".join(lines)


def _run_duckdb_subprocess(
    args: Sequence[str], *, cwd: Path, env: Mapping[str, str], timeout_seconds: int, label: str
) -> str:
    try:
        proc = subprocess.run(
            list(args),
            stdin=subprocess.DEVNULL,
            cwd=str(cwd),
            env=dict(env),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            timeout=timeout_seconds,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired, UnicodeDecodeError) as exc:
        raise ClosedValidationError(f"{label}: DuckDB subprocess execution failed: {exc}") from exc
    if proc.returncode != 0:
        err_snippet = proc.stderr.strip()[:240]
        raise ClosedValidationError(
            f"{label}: DuckDB exited with status {proc.returncode}: {err_snippet}"
        )
    return proc.stdout


def _verify_duckdb_cli_version(
    binary_path: Path, expected_version: str, *, cwd: Path, env: Mapping[str, str], timeout_seconds: int
) -> None:
    stdout = _run_duckdb_subprocess(
        [str(binary_path), "--version"],
        cwd=cwd,
        env=env,
        timeout_seconds=timeout_seconds,
        label="duckdb --version",
    )
    match = _DUCKDB_VERSION_RE.match(stdout.strip())
    if match is None or match.group(1) != expected_version:
        raise ClosedValidationError(
            f"duckdb --version: expected engine version {expected_version!r}, got {stdout.strip()!r}"
        )


def _check_duckdb_type_compatibility(
    duck_type: str, declared_col: ResultColumn, *, query_key: str
) -> str:
    ctype = declared_col.cell_type
    norm = duck_type.strip().upper()
    ok = False
    if ctype == "boolean":
        ok = norm == "BOOLEAN"
    elif ctype == "int64":
        ok = norm in _INT64_DUCK_TYPES
    elif ctype == "decimal6":
        m = _DECIMAL6_DUCK_TYPE_RE.fullmatch(norm)
        ok = m is not None and 6 <= int(m.group(1)) <= 38
    elif ctype in {"utf8", "opaque_ref"}:
        ok = norm == "VARCHAR"
    elif ctype == "date":
        ok = norm == "DATE"
    elif ctype == "timestamp":
        ok = norm in _TIMESTAMP_DUCK_TYPES
    if not ok:
        raise ClosedValidationError(
            f"query {query_key!r} column {declared_col.name!r}: "
            f"DuckDB type {duck_type!r} is incompatible with {ctype!r}"
        )
    return norm


def _describe_and_verify_query_columns(
    q: DuckDbQueryDefinition,
    *,
    preamble_sql: str,
    sql_path: Path,
    binary_path: Path,
    cwd: Path,
    env: Mapping[str, str],
    timeout_seconds: int,
) -> tuple[str, ...]:
    if ";" in q.sql_utf8 or "\x00" in q.sql_utf8:
        raise ClosedValidationError(f"query {q.result_key!r}: ';' or NUL forbidden")
    _write_staged_file(sql_path, (preamble_sql + f"\nDESCRIBE (\n{q.sql_utf8}\n);\n").encode("utf-8"), 0o400)
    raw_out = _run_duckdb_subprocess(
        [str(binary_path), "-json", "-f", str(sql_path)],
        cwd=cwd,
        env=env,
        timeout_seconds=timeout_seconds,
        label=f"DESCRIBE {q.result_key!r}",
    )
    parsed = loads_strict_json(raw_out)
    if type(parsed) is not list or len(parsed) != len(q.inline_columns):
        raise ClosedValidationError(
            f"query {q.result_key!r}: DESCRIBE returned {len(parsed) if type(parsed) is list else 'non-list'} "
            f"columns, expected {len(q.inline_columns)}"
        )
    duck_types: list[str] = []
    for desc_row, col in zip(parsed, q.inline_columns, strict=True):
        if type(desc_row) is not dict or type(desc_row.get("column_name")) is not str or type(desc_row.get("column_type")) is not str:
            raise ClosedValidationError(f"query {q.result_key!r}: malformed DESCRIBE JSON row")
        if desc_row["column_name"] != col.name:
            raise ClosedValidationError(
                f"query {q.result_key!r}: column {desc_row['column_name']!r} != declared {col.name!r}"
            )
        duck_types.append(_check_duckdb_type_compatibility(desc_row["column_type"], col, query_key=q.result_key))
    return tuple(duck_types)


def _build_projected_wrapper_sql(
    q: DuckDbQueryDefinition, duck_types: tuple[str, ...]
) -> str:
    select_exprs: list[str] = []
    for idx, (col, duck_type) in enumerate(zip(q.inline_columns, duck_types, strict=True)):
        q_col = f"__smart_ads_q.{_quote_sql_ident(col.name, label='column.name')}"
        alias = f'"c{idx}"'
        if col.cell_type in {"boolean", "utf8", "opaque_ref"}:
            select_exprs.append(f"{q_col} AS {alias}")
        elif col.cell_type in {"int64", "date"}:
            select_exprs.append(f"CAST({q_col} AS VARCHAR) AS {alias}")
        elif col.cell_type == "decimal6":
            select_exprs.append(f"CAST(CAST({q_col} AS DECIMAL(38, 6)) AS VARCHAR) AS {alias}")
        elif duck_type == "TIMESTAMP WITH TIME ZONE":
            select_exprs.append(
                f"strftime(({q_col}) AT TIME ZONE 'UTC', '%Y-%m-%dT%H:%M:%S.%fZ') AS {alias}"
            )
        else:
            select_exprs.append(f"strftime({q_col}, '%Y-%m-%dT%H:%M:%S.%fZ') AS {alias}")
    order_sql = ""
    if q.deterministic_order_by:
        order_terms = [
            f"__smart_ads_q.{_quote_sql_ident(cname, label='order_by')} ASC NULLS FIRST"
            for cname in q.deterministic_order_by
        ]
        order_sql = " ORDER BY " + ", ".join(order_terms)
    return f"SELECT {', '.join(select_exprs)} FROM (\n{q.sql_utf8}\n) AS __smart_ads_q{order_sql};"


def _convert_json_cell(raw_val: Any, col: ResultColumn) -> TaggedScalarCell:
    if raw_val is None:
        cell = TaggedScalarCell("null", None)
    elif col.cell_type == "boolean":
        if type(raw_val) is not bool:
            raise ClosedValidationError(f"column {col.name!r}: expected JSON boolean")
        cell = TaggedScalarCell("boolean", raw_val)
    else:
        if type(raw_val) is not str:
            raise ClosedValidationError(f"column {col.name!r}: expected JSON string")
        norm_val = unicodedata.normalize("NFC", raw_val) if col.cell_type == "utf8" else raw_val
        cell = TaggedScalarCell(col.cell_type, norm_val)
    col.check_cell(cell)
    return cell


def _execute_projected_query(
    q: DuckDbQueryDefinition,
    duck_types: tuple[str, ...],
    resolved_schema: AnalysisResultSchema,
    *,
    preamble_sql: str,
    sql_path: Path,
    binary_path: Path,
    cwd: Path,
    env: Mapping[str, str],
    timeout_seconds: int,
) -> ResultProjection:
    wrapper_sql = _build_projected_wrapper_sql(q, duck_types)
    _write_staged_file(sql_path, (preamble_sql + "\n" + wrapper_sql + "\n").encode("utf-8"), 0o400)
    raw_out = _run_duckdb_subprocess(
        [str(binary_path), "-json", "-f", str(sql_path)],
        cwd=cwd,
        env=env,
        timeout_seconds=timeout_seconds,
        label=f"SELECT {q.result_key!r}",
    )
    parsed_rows = loads_strict_json(raw_out)
    if type(parsed_rows) is not list:
        raise ClosedValidationError(f"query {q.result_key!r}: expected JSON array of row objects")
    expected_keys = {f"c{idx}" for idx in range(len(q.inline_columns))}
    rows: list[tuple[TaggedScalarCell, ...]] = []
    for row_obj in parsed_rows:
        if type(row_obj) is not dict or set(row_obj) != expected_keys:
            raise ClosedValidationError(f"query {q.result_key!r}: malformed JSON row object")
        rows.append(
            tuple(_convert_json_cell(row_obj[f"c{idx}"], col) for idx, col in enumerate(q.inline_columns))
        )
    projection = ResultProjection(
        result_kind=q.inline_result_kind,
        analysis_result_schema_locator=q.analysis_result_schema_locator,
        columns=q.inline_columns,
        rows=tuple(rows),
        row_count=len(rows),
    )
    verify_result_projection(projection, resolved_schema)
    return projection


def _stage_isolated_workspace(
    work_root: Path,
    duckdb_binary_bytes: bytes,
    verified_exts: Mapping[str, bytes],
    verified_pqs: Sequence[tuple[ParquetObjectLocator, bytes]],
) -> tuple[Path, Path, dict[str, Path], tuple[Path, ...], Path, dict[str, str]]:
    st = os.lstat(work_root)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise ClosedValidationError("duckdb staging: temporary root must be a non-symlink directory")
    subdirs = {name: work_root / name for name in ("home", "tmp", "bin", "ext", "parquet", "sql")}
    for sub in subdirs.values():
        sub.mkdir(mode=0o700, exist_ok=False)
    binary_path = _write_staged_file(subdirs["bin"] / "duckdb", duckdb_binary_bytes, 0o500)
    ext_paths = {
        name: _write_staged_file(subdirs["ext"] / f"{name}.duckdb_extension", raw, 0o400)
        for name, raw in sorted(verified_exts.items())
    }
    pq_paths = tuple(
        _write_staged_file(subdirs["parquet"] / f"part_{idx:06d}.parquet", raw_pq, 0o400)
        for idx, (_, raw_pq) in enumerate(verified_pqs)
    )
    env = {
        "HOME": str(subdirs["home"]),
        "TMPDIR": str(subdirs["tmp"]),
        "TZ": "UTC",
        "LC_ALL": "C",
        "LANG": "C",
        "PATH": "/usr/bin:/bin",
    }
    return binary_path, subdirs["home"], ext_paths, pq_paths, subdirs["sql"], env


class CliDuckDbBinaryAdapter(DuckDbEnginePort):
    """External SHA-256-verified DuckDB CLI replay adapter (ADR-0001 §6.4)."""

    def __init__(self, *, timeout_seconds: int = 30) -> None:
        if type(timeout_seconds) is not int or not (1 <= timeout_seconds <= 300):
            raise ClosedValidationError("timeout_seconds: expected int in [1, 300]")
        self._timeout_seconds = timeout_seconds

    def execute_replay_queries(
        self,
        *,
        bundle: AnalysisReplayInputBundle,
        duckdb_binary_bytes: bytes,
        extension_binaries: Mapping[str, bytes],
        parquet_objects: Sequence[tuple[ParquetObjectLocator, bytes]],
        resolved_schemas: Mapping[bytes, AnalysisResultSchema],
    ) -> Mapping[str, ResultProjection]:
        """Execute `bundle.queries` inside an isolated locked-down DuckDB CLI process."""
        if type(bundle) is not AnalysisReplayInputBundle:
            raise ClosedValidationError("bundle: expected AnalysisReplayInputBundle")
        fresh_bundle = AnalysisReplayInputBundle.from_dict(bundle.to_dict())
        if bundle != fresh_bundle:
            raise ClosedValidationError("bundle: corrupted AnalysisReplayInputBundle")
        _verify_blob_digest_and_size(
            duckdb_binary_bytes,
            expected_sha256=fresh_bundle.duckdb_binary_locator.binary_sha256,
            expected_size=fresh_bundle.duckdb_binary_locator.size_bytes,
            label="duckdb_binary_bytes",
        )
        verified_exts = _verify_extension_blobs(fresh_bundle, extension_binaries)
        verified_pqs = _verify_parquet_inputs(parquet_objects)
        checked_schemas = _verify_resolved_schemas_map(fresh_bundle, resolved_schemas)
        with tempfile.TemporaryDirectory(prefix="smart-ads-duckdb-") as raw_tmp:
            bin_path, home_dir, ext_paths, pq_paths, sql_dir, env = _stage_isolated_workspace(
                Path(raw_tmp).resolve(), duckdb_binary_bytes, verified_exts, verified_pqs
            )
            _verify_duckdb_cli_version(
                bin_path, fresh_bundle.duckdb_engine_version, cwd=home_dir, env=env, timeout_seconds=self._timeout_seconds
            )
            preamble = _build_lockdown_preamble_sql(
                fresh_bundle, ext_paths, pq_paths, home_dir=home_dir, tmp_dir=Path(env["TMPDIR"])
            )
            projections: dict[str, ResultProjection] = {}
            for q_idx, q in enumerate(fresh_bundle.queries):
                s_key = canonicalize_jcs(q.analysis_result_schema_locator.to_dict())
                duck_types = _describe_and_verify_query_columns(
                    q, preamble_sql=preamble, sql_path=sql_dir / f"describe_{q_idx:04d}.sql",
                    binary_path=bin_path, cwd=home_dir, env=env, timeout_seconds=self._timeout_seconds,
                )
                projections[q.result_key] = _execute_projected_query(
                    q, duck_types, checked_schemas[s_key], preamble_sql=preamble,
                    sql_path=sql_dir / f"select_{q_idx:04d}.sql", binary_path=bin_path,
                    cwd=home_dir, env=env, timeout_seconds=self._timeout_seconds,
                )
            return MappingProxyType(projections)


__all__ = [
    "CliDuckDbBinaryAdapter",
]
