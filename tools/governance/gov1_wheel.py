"""Deterministic Git-object wheel build provenance, executed-backend binding, and boundary verification.

Implements ADR-0001 sections 10 and 12.5 (`smart_ads/wheel_object_locator/v1`,
`smart_ads/wheel_build_provenance/v1`, and `smart_ads/wheel_boundary_report/v1`):
- Offline Git object materialization (`run_git_offline`) immune to working-tree and index dirtiness;
- Executed PEP 517 closure verification against `PINNED_UV_LOCK_CLOSURE_SPECS` (8 packages),
  `.dist-info/RECORD`, and optional local `backend_wheel_dir` `.whl` bytes;
- Hermetic double-staged PEP 517 wheel build under `python -I -B -S` in both driver and hook
  runner, defeating `PYTHONPATH`, `.pth`, `sitecustomize.py`, and `.pyc` shadowing;
- Strict PEP 427 `RECORD` + ZIP central-directory uniqueness/allowlist + Tier 1/Tier 2 AST
  static scan + outside-repo clean-venv `python -I` import boundary verification.
"""
from __future__ import annotations

import ast
import base64
from collections.abc import Mapping
import copy
import csv
from dataclasses import dataclass
import hashlib
import io
import os
from pathlib import Path
import re
import subprocess
import sys
import sysconfig
import tempfile
import tomllib
from types import MappingProxyType
from typing import Any, Final
import venv
import zipfile

from tools.governance import p1
from tools.governance.decomposition_scope import run_git_offline
from tools.governance.gov1_sandbox import (
    LOCAL_CANDIDATE_KIND,
    unwrap_local_candidate,
    verify_local_candidate_ref,
    wrap_local_candidate,
)
from tools.governance.jcs import canonicalize, loads_strict
from tools.governance.locator import (
    digest,
    exact_fields,
    json_digest,
    source_path,
    timestamp,
    validate_locator,
)

WHEEL_OBJECT_LOCATOR_SCHEMA: Final[str] = "smart_ads/wheel_object_locator/v1"
WHEEL_BUILD_PROVENANCE_SCHEMA: Final[str] = "smart_ads/wheel_build_provenance/v1"
WHEEL_BOUNDARY_REPORT_SCHEMA: Final[str] = "smart_ads/wheel_boundary_report/v1"

_RUN_CONTEXT_SCHEMA: Final[str] = "smart_ads/migration_run_context/v1"
_KEY_REGISTRY_SCHEMA: Final[str] = "smart_ads/key_authorization_registry/v1"

DEFAULT_REPOSITORY: Final[str] = "aiconnai/smart-ads"
DEFAULT_SOURCE_DATE_EPOCH: Final[int] = 1_700_000_000
EXPECTED_PYTHON_ABI_TAG: Final[str] = "cp312"
EXPECTED_BUILD_BACKEND: Final[str] = "hatchling.build"
EXPECTED_BUILD_BACKEND_PACKAGE: Final[str] = "hatchling"
EXPECTED_BUILD_BACKEND_VERSION: Final[str] = "1.33.0"
EXPECTED_WHEEL_FILENAME: Final[str] = "smart_ads-0.1.0-py3-none-any.whl"
EXPECTED_SELF_RECORD_PATH: Final[str] = "smart_ads-0.1.0.dist-info/RECORD"

MAX_JCS_SAFE_INT: Final[int] = (1 << 53) - 1

# Exact empirically verified PEP 517 closure specs:
# lock_pkg_name -> (version, uv_lock_wheel_sha256, dist_info_dir, module_dir, unpacked_tree_sha256)
PINNED_UV_LOCK_CLOSURE_SPECS: Final[Mapping[str, tuple[str, str, str, str, str]]] = (
    MappingProxyType(
        {
            "build": (
                "1.6.1",
                "sha256:ecd351a4be9d35a9eaaba244a7687143c9c7d4aea6ac964e7e7ddab20cbcf4e7",
                "build-1.6.1.dist-info",
                "build",
                "sha256:843f71a703227f3cfeaba06f99d8abe14392f9d56d3dd8666469fae2be2fe88b",
            ),
            "hatchling": (
                "1.33.0",
                "sha256:415290b84f464d2884303fca8974d38e7b85579069fab02a15db0828fbb1446d",
                "hatchling-1.33.0.dist-info",
                "hatchling",
                "sha256:0861b02d94d4bc9edab5d82f9c320e4cc9bd531df524e79c61456eb88c10d466",
            ),
            "packaging": (
                "26.3",
                "sha256:d7193f7c8e4e93f444fde0262bf90af30e16fa0ad0ad44cb553c87339b23cd1c",
                "packaging-26.3.dist-info",
                "packaging",
                "sha256:19f385dcdbf46b5ca084972b64755637f045ec8ac63b45ac2d26add64c8330d4",
            ),
            "pathspec": (
                "1.1.1",
                "sha256:a00ce642f577bf7f473932318056212bc4f8bfdf53128c78bbd5af0b9b20b189",
                "pathspec-1.1.1.dist-info",
                "pathspec",
                "sha256:cc8104a1a7ef50c5dcfbd5e96ec71688a8f44d7cd1e8602f34ef7f9272e36a3c",
            ),
            "pluggy": (
                "1.7.0",
                "sha256:7dd7b0d8832ba3cb632c306926ded123429211b83641b35dc5c41ad2d34f9bec",
                "pluggy-1.7.0.dist-info",
                "pluggy",
                "sha256:0788272fbd5dbb0ecc9de571af137afa0a13d014e49c9a947ca3b61843d6b8b4",
            ),
            "pyproject-hooks": (
                "1.3.3",
                "sha256:5fc53fdac9f7bd63fbcdc868fb5f90b4784d78a53a3d3388cd738b807441a20b",
                "pyproject_hooks-1.3.3.dist-info",
                "pyproject_hooks",
                "sha256:d4d3f604dd1e2685604d5021e8df31cc5f677bc84d989bc58a015b02d49f34bb",
            ),
            "tomlkit": (
                "0.15.2",
                "sha256:05562412163a3037b94497385fb7f9204c637bc605af7a48199e41cf2272f437",
                "tomlkit-0.15.2.dist-info",
                "tomlkit",
                "sha256:9cfb3eef187eb16979c04e50fca7bf7e124a224b05cea315fc0b357a22f97a60",
            ),
            "trove-classifiers": (
                "2026.9.21.13",
                "sha256:8b1ff4f9c191b1040b71c37f1e445ab99732911e3cd91de52838453a854d7a17",
                "trove_classifiers-2026.9.21.13.dist-info",
                "trove_classifiers",
                "sha256:5ce3f3d8354f3b7481db34845ba15795f0ca85117b0d50938a7e96d9b1d32ba8",
            ),
        }
    )
)

EXPECTED_PACKAGED_MODULES: Final[frozenset[str]] = frozenset(
    {
        "smart_ads",
        "smart_ads.contracts",
        "smart_ads.contracts.jcs",
        "smart_ads.contracts.numerics",
        "smart_ads.contracts.scalars",
        "smart_ads.contracts.schemas",
        "smart_ads.domain",
        "smart_ads.domain.capabilities",
        "smart_ads.domain.pipeboard_contract",
        "smart_ads.domain.registry",
        "smart_ads.domain.resource_ref",
        "smart_ads.ports",
        "smart_ads.ports.cell_runtime",
        "smart_ads.ports.provider",
        "smart_ads.application",
        "smart_ads.application.admission",
        "smart_ads.application.collection",
        "smart_ads.application.completeness",
        "smart_ads.transports",
        "smart_ads.transports.mcp",
        "smart_ads.transports.mcp.delegation",
        "smart_ads.transports.mcp.gateway",
        "smart_ads.transports.mcp.protocol",
        "smart_ads.transports.mcp.schemas",
    }
)

_WHEEL_ALLOWLIST_RE: Final[re.Pattern[str]] = re.compile(
    r"\A(smart_ads(/[a-z0-9_]+)+\.py|smart_ads-0\.1\.0\.dist-info/(METADATA|WHEEL|RECORD))\Z"
)
_SHA256_PREFIXED_RE: Final[re.Pattern[str]] = re.compile(r"\Asha256:[0-9a-f]{64}\Z")
_GIT_OID_RE: Final[re.Pattern[str]] = re.compile(r"\A[0-9a-f]{40}\Z")
_NONNEG_INT_STR_RE: Final[re.Pattern[str]] = re.compile(r"\A(0|[1-9][0-9]*)\Z")

_INSTALLER_DIST_INFO_SKIP: Final[frozenset[str]] = frozenset(
    {"RECORD", "INSTALLER", "REQUESTED", "direct_url.json"}
)
_WINDOWS_ONLY_MARKERS: Final[frozenset[str]] = frozenset(
    {"os_name == 'nt'", "sys_platform == 'win32'"}
)
_FORBIDDEN_HATCH_FILENAMES: Final[frozenset[str]] = frozenset(
    {"hatch.toml", ".hatch.toml", "hatch_build.py"}
)

_WHEEL_WIDE_FORBIDDEN_TOP_IMPORTS: Final[frozenset[str]] = frozenset(
    {"tools", "tooling", "importlib", "runpy", "builtins", "ctypes"}
)
_WHEEL_WIDE_FORBIDDEN_DYNAMIC_NAMES: Final[frozenset[str]] = frozenset(
    {"__import__", "__builtins__", "builtins", "eval", "exec", "compile"}
)
_PURE_LAYER_SUBPACKAGES: Final[frozenset[str]] = frozenset(
    {
        "contracts",
        "domain",
        "ports",
        "application",
        "analytics",
        "reconciliation",
        "transports",
    }
)
_PURE_LAYER_ALLOWED_TOP_IMPORTS: Final[frozenset[str]] = frozenset(
    {
        "__future__",
        "base64",
        "bisect",
        "collections",
        "copy",
        "dataclasses",
        "datetime",
        "decimal",
        "enum",
        "functools",
        "hashlib",
        "hmac",
        "itertools",
        "json",
        "math",
        "operator",
        "re",
        "types",
        "typing",
        "unicodedata",
        "smart_ads",
    }
)
_PURE_LAYER_FORBIDDEN_FILE_ATTRS: Final[frozenset[str]] = frozenset(
    {"open", "read_bytes", "read_text", "write_bytes", "write_text"}
)
_PURE_LAYER_FORBIDDEN_AMBIENT_TIME_ATTRS: Final[frozenset[str]] = frozenset(
    {
        "now",
        "utcnow",
        "today",
        "fromtimestamp",
        "utcfromtimestamp",
        "astimezone",
    }
)

_WHEEL_OBJECT_LOCATOR_FIELDS: Final[set[str]] = {
    "$schema",
    "store_kind",
    "object_ref",
    "wheel_digest",
    "size_bytes",
}
_PROVENANCE_PAYLOAD_FIELDS: Final[set[str]] = {
    "migration_run_context_locator",
    "build_run_id",
    "built_at_utc",
    "repository",
    "source_commit_sha",
    "source_tree_oid",
    "source_date_epoch",
    "python_abi_tag",
    "build_backend",
    "build_backend_version",
    "build_backend_digest",
    "pyproject_sha256",
    "uv_lock_sha256",
    "schema_bundle_digest",
    "wheel",
    "wheel_digest",
}
_PROVENANCE_ENVELOPE_FIELDS: Final[set[str]] = (
    {"$schema", "integrity"} | _PROVENANCE_PAYLOAD_FIELDS
)

_BOUNDARY_COMMON_PAYLOAD_FIELDS: Final[set[str]] = {
    "migration_run_context_locator",
    "build_run_id",
    "verified_at_utc",
    "repository",
    "source_commit_sha",
    "wheel_digest",
    "build_backend_digest",
    "schema_bundle_digest",
    "sorted_record_entries",
    "sorted_record_digest",
    "archive_allowlist_passed",
    "ast_boundary_scan_passed",
    "isolated_venv_import_passed",
    "packaged_modules",
}
_BOUNDARY_CANDIDATE_PAYLOAD_FIELDS: Final[set[str]] = (
    _BOUNDARY_COMMON_PAYLOAD_FIELDS | {"wheel_build_provenance_candidate_ref"}
)
_BOUNDARY_ENVELOPE_PAYLOAD_FIELDS: Final[set[str]] = (
    _BOUNDARY_COMMON_PAYLOAD_FIELDS | {"wheel_build_provenance_locator"}
)
_BOUNDARY_ENVELOPE_FIELDS: Final[set[str]] = (
    {"$schema", "integrity"} | _BOUNDARY_ENVELOPE_PAYLOAD_FIELDS
)

_INSPECTION_FIELDS: Final[set[str]] = {
    "wheel_digest",
    "schema_bundle_digest",
    "sorted_record_entries",
    "sorted_record_digest",
    "archive_allowlist_passed",
    "ast_boundary_scan_passed",
    "isolated_venv_import_passed",
    "packaged_modules",
}
_UNSIGNED_INTEGRITY_FIELDS: Final[set[str]] = {
    "key_id",
    "key_registry_snapshot_locator",
}
_SIGNED_INTEGRITY_FIELDS: Final[set[str]] = _UNSIGNED_INTEGRITY_FIELDS | {
    "content_digest",
    "signature_base64",
}

_DEFAULT_SYSTEM_BIN_DIRS: Final[tuple[str, ...]] = (
    "/opt/homebrew/bin",
    "/usr/local/bin",
    "/usr/bin",
    "/bin",
)

# Zero-assert isolated PEP 517 hook runner bootstrap executed under `python -I -B -S -c`.
_PEP517_RUNNER_BOOTSTRAP: Final[str] = """
import importlib
from pathlib import Path
import runpy
import sys
import sysconfig

if sys.implementation.name != "cpython" or tuple(sys.version_info[:2]) != (3, 12):
    raise RuntimeError("PEP 517 hook runner requires CPython 3.12")
if "site" in sys.modules:
    raise RuntimeError("site module must not be loaded in isolated PEP 517 hook runner")
if (
    sys.flags.isolated != 1
    or sys.flags.dont_write_bytecode != 1
    or sys.flags.no_site != 1
):
    raise RuntimeError("PEP 517 hook runner requires -I -B -S flags")
if len(sys.argv) != 6:
    raise RuntimeError("unexpected PEP 517 hook runner argv length")

backend_site = Path(sys.argv[1]).resolve()
closure_mods = sys.argv[2].split(",")
script_path = sys.argv[3]
hook_name = sys.argv[4]
control_dir = sys.argv[5]

stdlib_roots = {
    Path(sys.base_prefix).resolve(),
    Path(sys.base_exec_prefix).resolve(),
    Path(sysconfig.get_path("stdlib")).resolve(),
    Path(sysconfig.get_path("platstdlib")).resolve(),
}
forbidden_site_parts = {"site-packages", "dist-packages"}
for entry in list(sys.path):
    if entry == "":
        raise RuntimeError("empty entry forbidden in PEP 517 hook sys.path")
    raw_entry_parts = set(Path(entry).parts)
    resolved_entry = Path(entry).resolve()
    if (
        raw_entry_parts.intersection(forbidden_site_parts)
        or set(resolved_entry.parts).intersection(forbidden_site_parts)
    ):
        raise RuntimeError(f"site-packages path leaked into hook sys.path: {entry!r}")
    if not any(resolved_entry.is_relative_to(root) for root in stdlib_roots):
        raise RuntimeError(f"non-stdlib path leaked into hook sys.path: {entry!r}")

sys.path.append(str(backend_site))

for mod_name in closure_mods:
    mod = importlib.import_module(mod_name)
    mod_file = getattr(mod, "__file__", None)
    if type(mod_file) is not str or mod_file.endswith((".pyc", ".pyo")):
        raise RuntimeError(f"invalid module file for {mod_name!r}: {mod_file!r}")
    if not Path(mod_file).resolve().is_relative_to(backend_site):
        raise RuntimeError(
            f"closure module {mod_name!r} resolved outside verified backend dir: {mod_file!r}"
        )

sys.argv = [script_path, hook_name, control_dir]
runpy.run_path(script_path, run_name="__main__")
"""

# Zero-assert isolated PEP 517 driver executed under `python -I -B -S -c`.
_PEP517_DRIVER_SCRIPT: Final[str] = """
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
import sysconfig

if sys.implementation.name != "cpython" or tuple(sys.version_info[:2]) != (3, 12):
    raise RuntimeError("PEP 517 driver requires CPython 3.12")
if "site" in sys.modules:
    raise RuntimeError("site module must not be loaded in isolated PEP 517 driver")
if (
    sys.flags.isolated != 1
    or sys.flags.dont_write_bytecode != 1
    or sys.flags.no_site != 1
):
    raise RuntimeError("PEP 517 driver requires -I -B -S flags")
if len(sys.argv) != 8:
    raise RuntimeError("unexpected PEP 517 driver argv length")

backend_site = Path(sys.argv[1]).resolve()
closure_mods_csv = sys.argv[2]
stage_dir = Path(sys.argv[3]).resolve()
wheel_out_dir = Path(sys.argv[4]).resolve()
tmp_dir = Path(sys.argv[5]).resolve()
source_date_epoch = sys.argv[6]
runner_bootstrap = sys.argv[7]

stdlib_roots = {
    Path(sys.base_prefix).resolve(),
    Path(sys.base_exec_prefix).resolve(),
    Path(sysconfig.get_path("stdlib")).resolve(),
    Path(sysconfig.get_path("platstdlib")).resolve(),
}
forbidden_site_parts = {"site-packages", "dist-packages"}
for entry in list(sys.path):
    if entry == "":
        raise RuntimeError("empty entry forbidden in PEP 517 driver sys.path")
    raw_entry_parts = set(Path(entry).parts)
    resolved_entry = Path(entry).resolve()
    if (
        raw_entry_parts.intersection(forbidden_site_parts)
        or set(resolved_entry.parts).intersection(forbidden_site_parts)
    ):
        raise RuntimeError(f"site-packages path leaked into driver sys.path: {entry!r}")
    if not any(resolved_entry.is_relative_to(root) for root in stdlib_roots):
        raise RuntimeError(f"non-stdlib path leaked into driver sys.path: {entry!r}")

sys.path.append(str(backend_site))

closure_mods = closure_mods_csv.split(",")
for mod_name in closure_mods:
    mod = importlib.import_module(mod_name)
    mod_file = getattr(mod, "__file__", None)
    if type(mod_file) is not str or mod_file.endswith((".pyc", ".pyo")):
        raise RuntimeError(f"invalid module file for {mod_name!r}: {mod_file!r}")
    if not Path(mod_file).resolve().is_relative_to(backend_site):
        raise RuntimeError(
            f"closure module {mod_name!r} resolved outside verified backend dir: {mod_file!r}"
        )

from pyproject_hooks import BuildBackendHookCaller

base_env = {
    "HOME": "/nonexistent",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONNOUSERSITE": "1",
    "PYTHONSAFEPATH": "1",
    "SOURCE_DATE_EPOCH": source_date_epoch,
    "TMPDIR": str(tmp_dir),
    "TZ": "UTC",
}
allowed_extra_keys = {
    "_PYPROJECT_HOOKS_BUILD_BACKEND",
    "_PYPROJECT_HOOKS_BACKEND_PATH_JSON",
}

def isolated_hook_runner(cmd, cwd=None, extra_environ=None):
    if len(cmd) != 4 or cmd[0] != sys.executable:
        raise RuntimeError(f"unexpected pyproject_hooks command: {cmd!r}")
    hook_env = dict(base_env)
    if extra_environ:
        for k, v in extra_environ.items():
            if k not in allowed_extra_keys:
                raise RuntimeError(f"disallowed extra_environ key: {k!r}")
            hook_env[k] = str(v)
    proc = subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            "-S",
            "-c",
            runner_bootstrap,
            str(backend_site),
            closure_mods_csv,
            str(cmd[1]),
            str(cmd[2]),
            str(cmd[3]),
        ],
        cwd=cwd,
        env=hook_env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"isolated PEP 517 hook {cmd[2]!r} failed (rc={proc.returncode}): {proc.stderr.strip()}"
        )

stage_top_names = {p.name for p in stage_dir.iterdir()}
if stage_top_names != {"pyproject.toml", "uv.lock", "src"}:
    raise RuntimeError(
        f"unexpected top-level entries in PEP 517 stage_dir: {sorted(stage_top_names)!r}"
    )

caller = BuildBackendHookCaller(
    source_dir=str(stage_dir),
    build_backend="hatchling.build",
    runner=isolated_hook_runner,
    python_executable=sys.executable,
)
extra_reqs = list(caller.get_requires_for_build_wheel())
if extra_reqs:
    raise RuntimeError(f"unexpected dynamic wheel build requirements: {extra_reqs!r}")
wheel_name = caller.build_wheel(wheel_directory=str(wheel_out_dir))
sys.stdout.write(json.dumps({"wheel_name": wheel_name}))
"""

# Zero-assert isolated clean-venv import probe executed under `python -I -B -c`.
_CLEAN_VENV_PROBE_SCRIPT: Final[str] = """
import importlib
import importlib.metadata as metadata
import json
from pathlib import Path
import pkgutil
import sys

expected_purelib = Path(sys.argv[1]).resolve()
expected_modules = json.loads(sys.argv[2])

if "" in sys.path:
    raise RuntimeError("empty string leaked into isolated venv sys.path")

import smart_ads

if getattr(smart_ads, "__version__", None) != "0.1.0":
    raise RuntimeError("unexpected smart_ads.__version__")
if metadata.requires("smart-ads"):
    raise RuntimeError("smart-ads runtime dependencies must be empty")

walked = {"smart_ads"}
for mod_info in pkgutil.walk_packages(smart_ads.__path__, prefix="smart_ads."):
    importlib.import_module(mod_info.name)
    walked.add(mod_info.name)

sorted_walked = sorted(walked, key=lambda s: s.encode("utf-8"))
if sorted_walked != expected_modules:
    raise RuntimeError(f"packaged_modules mismatch: {sorted_walked!r} != {expected_modules!r}")

for mod_name in sorted_walked:
    mod = sys.modules.get(mod_name)
    mod_file = getattr(mod, "__file__", None)
    if type(mod_file) is not str or not Path(mod_file).resolve().is_relative_to(expected_purelib):
        raise RuntimeError(f"module {mod_name!r} imported outside clean venv purelib: {mod_file!r}")

for forbidden_mod in ("tools", "tooling"):
    try:
        importlib.import_module(forbidden_mod)
    except ModuleNotFoundError:
        pass
    else:
        raise RuntimeError(f"{forbidden_mod!r} unexpectedly importable inside clean venv")

from smart_ads.contracts.schemas import compute_schema_bundle_digest

sys.stdout.write(
    json.dumps(
        {
            "packaged_modules": sorted_walked,
            "schema_bundle_digest": compute_schema_bundle_digest(),
        }
    )
)
"""


def _require_sha256_digest(value: object, label: str) -> str:
    if type(value) is not str or _SHA256_PREFIXED_RE.fullmatch(value) is None:
        raise ValueError(f"{label}: expected 'sha256:<64_lowercase_hex>'")
    return value


def _require_git_oid(value: object, label: str) -> str:
    if type(value) is not str or _GIT_OID_RE.fullmatch(value) is None:
        raise ValueError(f"{label}: expected 40-character lowercase hex Git OID")
    return value


def _require_strict_str(value: object, label: str) -> str:
    if (
        type(value) is not str
        or not value.strip()
        or value != value.strip()
        or "\x00" in value
    ):
        raise ValueError(f"{label}: expected non-empty stripped string without NUL")
    return value


def _require_exact_str(value: object, expected: str, label: str) -> str:
    if type(value) is not str or value != expected:
        raise ValueError(f"{label}: expected exact string {expected!r}")
    return value


def _require_exact_bool(value: object, expected: bool, label: str) -> bool:
    if type(value) is not bool or value is not expected:
        raise ValueError(f"{label}: expected exact boolean {expected!r}")
    return value


def _require_safe_nonneg_int(
    value: object, label: str, *, minimum: int = 0
) -> int:
    if type(value) is not int or value < minimum or value > MAX_JCS_SAFE_INT:
        raise ValueError(
            f"{label}: expected integer in [{minimum}, {MAX_JCS_SAFE_INT}]"
        )
    return value


def _pep427_record_hash(raw: bytes) -> str:
    b64_nopad = (
        base64.urlsafe_b64encode(hashlib.sha256(raw).digest())
        .rstrip(b"=")
        .decode("ascii")
    )
    return f"sha256={b64_nopad}"


def _verify_cpython_312_runtime() -> str:
    impl_name = getattr(sys.implementation, "name", None)
    ver_info = sys.version_info
    if (
        impl_name != "cpython"
        or len(ver_info) < 2
        or (ver_info[0], ver_info[1]) != (3, 12)
    ):
        raise ValueError(
            "gov1_wheel: requires CPython 3.12 ('cp312'), "
            f"got implementation={impl_name!r}, version_info={tuple(ver_info[:3])!r}"
        )
    return EXPECTED_PYTHON_ABI_TAG


def _clean_system_path() -> str:
    py_dir = str(Path(sys.executable).parent)
    candidates = [
        d for d in (py_dir, *_DEFAULT_SYSTEM_BIN_DIRS) if d and os.path.isabs(d)
    ]
    return os.pathsep.join(dict.fromkeys(candidates))


def _reject_forbidden_hatch_filename(rel_path: str, *, label: str) -> None:
    leaf = rel_path.rsplit("/", 1)[-1].lower()
    if leaf in _FORBIDDEN_HATCH_FILENAMES:
        raise ValueError(
            f"{label}: forbidden Hatch override or hook file {rel_path!r}"
        )


def _is_allowed_snapshot_stage_path(rel_path: str) -> bool:
    return rel_path in {"pyproject.toml", "uv.lock"} or rel_path.startswith(
        "src/smart_ads/"
    )


@dataclass(frozen=True, slots=True)
class GitBuildSnapshot:
    """Immutable in-memory Git commit snapshot bound to executed PEP 517 backend."""

    commit_sha: str
    tree_oid: str
    files: dict[str, bytes]
    modes: dict[str, str]
    pyproject_sha256: str
    uv_lock_sha256: str
    build_backend: str
    build_backend_version: str
    build_backend_digest: str

    def __post_init__(self) -> None:
        _require_git_oid(self.commit_sha, "GitBuildSnapshot.commit_sha")
        _require_git_oid(self.tree_oid, "GitBuildSnapshot.tree_oid")
        if (
            not isinstance(self.files, dict)
            or not isinstance(self.modes, dict)
            or not self.files
            or set(self.files.keys()) != set(self.modes.keys())
        ):
            raise ValueError(
                "GitBuildSnapshot: files and modes must be non-empty dicts with equal keys"
            )
        for rel_path, raw in self.files.items():
            source_path(rel_path)
            _reject_forbidden_hatch_filename(rel_path, label="GitBuildSnapshot.files")
            if not _is_allowed_snapshot_stage_path(rel_path):
                raise ValueError(
                    f"GitBuildSnapshot.files[{rel_path!r}]: path outside staging allowlist "
                    "({'pyproject.toml', 'uv.lock', 'src/smart_ads/**'})"
                )
            if type(raw) is not bytes:
                raise ValueError(
                    f"GitBuildSnapshot.files[{rel_path!r}]: expected bytes"
                )
            if self.modes[rel_path] not in {"100644", "100755"}:
                raise ValueError(
                    f"GitBuildSnapshot.modes[{rel_path!r}]: forbidden Git mode {self.modes[rel_path]!r}"
                )
        if (
            "pyproject.toml" not in self.files
            or "uv.lock" not in self.files
            or "src/smart_ads/__init__.py" not in self.files
        ):
            raise ValueError(
                "GitBuildSnapshot: commit must contain 'pyproject.toml', 'uv.lock', "
                "and 'src/smart_ads/__init__.py'"
            )
        _require_sha256_digest(
            self.pyproject_sha256, "GitBuildSnapshot.pyproject_sha256"
        )
        _require_sha256_digest(self.uv_lock_sha256, "GitBuildSnapshot.uv_lock_sha256")
        if digest(self.files["pyproject.toml"]) != self.pyproject_sha256:
            raise ValueError("GitBuildSnapshot: pyproject_sha256 mismatch")
        if digest(self.files["uv.lock"]) != self.uv_lock_sha256:
            raise ValueError("GitBuildSnapshot: uv_lock_sha256 mismatch")
        _require_exact_str(
            self.build_backend,
            EXPECTED_BUILD_BACKEND,
            "GitBuildSnapshot.build_backend",
        )
        _require_exact_str(
            self.build_backend_version,
            EXPECTED_BUILD_BACKEND_VERSION,
            "GitBuildSnapshot.build_backend_version",
        )
        _require_sha256_digest(
            self.build_backend_digest, "GitBuildSnapshot.build_backend_digest"
        )


# ---------------------------------------------------------------------------
# PEP 517 Runtime Environment & Executed Backend Closure Verification
# ---------------------------------------------------------------------------


def _normalize_closure_specs(
    closure_specs: Mapping[str, tuple[str, ...]],
) -> dict[str, tuple[str, str, str, str, str]]:
    if not isinstance(closure_specs, Mapping) or len(closure_specs) == 0:
        raise ValueError("closure_specs: expected non-empty mapping")
    normalized: dict[str, tuple[str, str, str, str, str]] = {}
    for raw_name, spec in closure_specs.items():
        pkg_name = _require_strict_str(raw_name, "closure_specs.key")
        if not isinstance(spec, tuple):
            raise ValueError(f"closure_specs[{pkg_name!r}]: expected tuple")
        if len(spec) == 5:
            ver, whl_sha, dist_info_dir, module_dir, tree_sha = spec
        elif len(spec) == 3:
            ver, whl_sha, tree_sha = spec
            module_dir = pkg_name.replace("-", "_")
            dist_info_dir = f"{module_dir}-{ver}.dist-info"
        else:
            raise ValueError(
                f"closure_specs[{pkg_name!r}]: expected 5-tuple or 3-tuple, got {len(spec)}"
            )
        _require_strict_str(ver, f"closure_specs[{pkg_name!r}].version")
        _require_sha256_digest(whl_sha, f"closure_specs[{pkg_name!r}].wheel_sha256")
        source_path(dist_info_dir)
        source_path(module_dir)
        if "/" in dist_info_dir or "/" in module_dir:
            raise ValueError(
                f"closure_specs[{pkg_name!r}]: dist_info_dir and module_dir must be single path segments"
            )
        _require_sha256_digest(
            tree_sha, f"closure_specs[{pkg_name!r}].unpacked_tree_sha256"
        )
        normalized[pkg_name] = (ver, whl_sha, dist_info_dir, module_dir, tree_sha)
    return normalized


def _parse_uv_lock_packages(uv_lock_bytes: bytes) -> dict[str, dict[str, Any]]:
    if type(uv_lock_bytes) is not bytes:
        raise ValueError("uv_lock_bytes: expected bytes")
    try:
        lock_data = tomllib.loads(uv_lock_bytes.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ValueError(f"uv.lock: invalid UTF-8 or TOML: {exc}") from exc
    raw_packages = lock_data.get("package")
    if not isinstance(raw_packages, list) or len(raw_packages) == 0:
        raise ValueError("uv.lock: missing non-empty [[package]] list")
    packages_by_name: dict[str, dict[str, Any]] = {}
    for idx, pkg in enumerate(raw_packages):
        if not isinstance(pkg, dict):
            raise ValueError(f"uv.lock: package[{idx}] must be a table")
        name = _require_strict_str(pkg.get("name"), f"uv.lock.package[{idx}].name")
        if name in packages_by_name:
            raise ValueError(f"uv.lock: duplicate package entry {name!r}")
        packages_by_name[name] = pkg
    return packages_by_name


def _compute_tree_digest_from_files(files_by_rel_path: dict[str, bytes]) -> str:
    entries = sorted(
        [
            {
                "path": rel_path,
                "sha256": hashlib.sha256(raw).hexdigest(),
                "size": len(raw),
            }
            for rel_path, raw in files_by_rel_path.items()
        ],
        key=lambda e: e["path"].encode("utf-8"),
    )
    return json_digest(entries)


def _read_and_verify_site_packages_closure_pkg(
    site_packages_root: Path,
    *,
    pkg_name: str,
    dist_info_dir: str,
    module_dir: str,
    expected_tree_sha256: str,
) -> dict[str, bytes]:
    pkg_files: dict[str, bytes] = {}
    for sub_name in (module_dir, dist_info_dir):
        sub_root = site_packages_root / sub_name
        if sub_root.is_symlink() or not sub_root.is_dir():
            raise ValueError(
                f"site_packages[{pkg_name!r}]: missing or symlink directory {sub_root}"
            )
        for curr_root, dirnames, filenames in os.walk(sub_root, followlinks=False):
            curr_path = Path(curr_root)
            if curr_path.is_symlink():
                raise ValueError(
                    f"site_packages[{pkg_name!r}]: symlink directory forbidden: {curr_path}"
                )
            kept_dirs: list[str] = []
            for dname in sorted(dirnames):
                dpath = curr_path / dname
                if dpath.is_symlink():
                    raise ValueError(
                        f"site_packages[{pkg_name!r}]: symlink directory forbidden: {dpath}"
                    )
                if dname == "__pycache__":
                    continue
                kept_dirs.append(dname)
            dirnames[:] = kept_dirs

            for fname in sorted(filenames):
                fpath = curr_path / fname
                if fpath.is_symlink() or not fpath.is_file():
                    raise ValueError(
                        f"site_packages[{pkg_name!r}]: symlink or non-regular file forbidden: {fpath}"
                    )
                rel_parts = fpath.relative_to(site_packages_root).parts
                if "__pycache__" in rel_parts or fpath.suffix in {".pyc", ".pyo"}:
                    continue
                if (
                    rel_parts[0] == dist_info_dir
                    and len(rel_parts) == 2
                    and rel_parts[1] in _INSTALLER_DIST_INFO_SKIP
                ):
                    continue
                rel_posix = "/".join(rel_parts)
                source_path(rel_posix)
                pkg_files[rel_posix] = fpath.read_bytes()

    record_file = site_packages_root / dist_info_dir / "RECORD"
    if record_file.is_symlink() or not record_file.is_file():
        raise ValueError(
            f"site_packages[{pkg_name!r}]: missing or symlink RECORD at {record_file}"
        )
    try:
        record_text = record_file.read_bytes().decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(
            f"site_packages[{pkg_name!r}]: non-UTF-8 RECORD file"
        ) from exc
    if "\x00" in record_text:
        raise ValueError(f"site_packages[{pkg_name!r}]: NUL byte in RECORD")

    seen_record_paths: set[str] = set()
    checked_record_paths: set[str] = set()
    self_record_entry = f"{dist_info_dir}/RECORD"
    found_self_record = False

    reader = csv.reader(io.StringIO(record_text, newline=""))
    for row in reader:
        if len(row) != 3:
            raise ValueError(
                f"site_packages[{pkg_name!r}]: malformed 3-column CSV row in RECORD: {row!r}"
            )
        rec_path, rec_hash, rec_size = row
        if rec_path in seen_record_paths:
            raise ValueError(
                f"site_packages[{pkg_name!r}]: duplicate path in RECORD: {rec_path!r}"
            )
        seen_record_paths.add(rec_path)

        if rec_path == self_record_entry:
            if rec_hash != "" or rec_size != "":
                raise ValueError(
                    f"site_packages[{pkg_name!r}]: RECORD self-entry must have empty hash and size"
                )
            found_self_record = True
            continue
        if rec_path.startswith("../"):
            continue
        source_path(rec_path)
        rec_parts = rec_path.split("/")
        if "__pycache__" in rec_parts or rec_path.endswith((".pyc", ".pyo")):
            continue
        if (
            rec_parts[0] == dist_info_dir
            and len(rec_parts) == 2
            and rec_parts[1] in _INSTALLER_DIST_INFO_SKIP
        ):
            continue
        if rec_parts[0] not in {module_dir, dist_info_dir}:
            raise ValueError(
                f"site_packages[{pkg_name!r}]: unexpected RECORD path outside package roots: {rec_path!r}"
            )
        if rec_path not in pkg_files:
            raise ValueError(
                f"site_packages[{pkg_name!r}]: file listed in RECORD missing on disk: {rec_path!r}"
            )
        raw_bytes = pkg_files[rec_path]
        if (
            rec_hash != _pep427_record_hash(raw_bytes)
            or _NONNEG_INT_STR_RE.fullmatch(rec_size) is None
            or int(rec_size) != len(raw_bytes)
        ):
            raise ValueError(
                f"site_packages[{pkg_name!r}]: RECORD hash/size mismatch for {rec_path!r}"
            )
        checked_record_paths.add(rec_path)

    if not found_self_record:
        raise ValueError(
            f"site_packages[{pkg_name!r}]: missing self-entry {self_record_entry!r} in RECORD"
        )
    if set(pkg_files.keys()) != checked_record_paths:
        extra_on_disk = sorted(set(pkg_files.keys()) - checked_record_paths)
        raise ValueError(
            f"site_packages[{pkg_name!r}]: unrecorded extra files on disk: {extra_on_disk!r}"
        )

    actual_tree_sha256 = _compute_tree_digest_from_files(pkg_files)
    if actual_tree_sha256 != expected_tree_sha256:
        raise ValueError(
            f"site_packages[{pkg_name!r}]: unpacked_tree_sha256 mismatch "
            f"(expected {expected_tree_sha256!r}, got {actual_tree_sha256!r})"
        )
    return pkg_files


def _read_and_verify_wheelhouse_closure_pkg(
    backend_wheel_dir: Path,
    *,
    pkg_name: str,
    version: str,
    wheel_filename: str,
    expected_wheel_sha256: str,
    dist_info_dir: str,
    module_dir: str,
    expected_tree_sha256: str,
) -> dict[str, bytes]:
    whl_path = backend_wheel_dir / wheel_filename
    if whl_path.is_symlink() or not whl_path.is_file():
        raise ValueError(
            f"backend_wheel_dir[{pkg_name!r}]: missing or symlink wheel {whl_path}"
        )
    whl_bytes = whl_path.read_bytes()
    actual_whl_sha = digest(whl_bytes)
    if actual_whl_sha != expected_wheel_sha256:
        raise ValueError(
            f"backend_wheel_dir[{pkg_name!r}]: wheel SHA-256 mismatch for {wheel_filename!r} "
            f"(expected {expected_wheel_sha256!r}, got {actual_whl_sha!r})"
        )

    try:
        zf_ctx = zipfile.ZipFile(io.BytesIO(whl_bytes), "r")
    except zipfile.BadZipFile as exc:
        raise ValueError(
            f"backend_wheel_dir[{pkg_name!r}]: corrupt wheel archive {wheel_filename!r}"
        ) from exc

    raw_members: dict[str, bytes] = {}
    with zf_ctx as zf:
        for info in zf.infolist():
            if info.is_dir() or info.filename.endswith("/"):
                raise ValueError(
                    f"backend_wheel_dir[{pkg_name!r}]: directory entry forbidden in wheel: {info.filename!r}"
                )
            unix_type = (info.external_attr >> 16) & 0o170000
            if unix_type == 0o120000 or (unix_type != 0 and unix_type != 0o100000):
                raise ValueError(
                    f"backend_wheel_dir[{pkg_name!r}]: non-regular/symlink ZIP entry forbidden: {info.filename!r}"
                )
            source_path(info.filename)
            if info.filename in raw_members:
                raise ValueError(
                    f"backend_wheel_dir[{pkg_name!r}]: duplicate ZIP entry {info.filename!r}"
                )
            data = zf.read(info)
            if len(data) != info.file_size:
                raise ValueError(
                    f"backend_wheel_dir[{pkg_name!r}]: ZIP size mismatch on {info.filename!r}"
                )
            raw_members[info.filename] = data

    self_record_entry = f"{dist_info_dir}/RECORD"
    if self_record_entry not in raw_members:
        raise ValueError(
            f"backend_wheel_dir[{pkg_name!r}]: missing {self_record_entry!r} in wheel"
        )
    try:
        rec_text = raw_members[self_record_entry].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(
            f"backend_wheel_dir[{pkg_name!r}]: non-UTF-8 RECORD in wheel"
        ) from exc

    seen_rec: set[str] = set()
    for row in csv.reader(io.StringIO(rec_text, newline="")):
        if len(row) != 3:
            raise ValueError(
                f"backend_wheel_dir[{pkg_name!r}]: malformed RECORD row {row!r}"
            )
        r_path, r_hash, r_size = row
        if r_path in seen_rec or r_path not in raw_members:
            raise ValueError(
                f"backend_wheel_dir[{pkg_name!r}]: duplicate or unknown RECORD entry {r_path!r}"
            )
        seen_rec.add(r_path)
        if r_path == self_record_entry:
            if r_hash != "" or r_size != "":
                raise ValueError(
                    f"backend_wheel_dir[{pkg_name!r}]: non-empty hash/size on RECORD self-entry"
                )
        else:
            b = raw_members[r_path]
            if (
                r_hash != _pep427_record_hash(b)
                or _NONNEG_INT_STR_RE.fullmatch(r_size) is None
                or int(r_size) != len(b)
            ):
                raise ValueError(
                    f"backend_wheel_dir[{pkg_name!r}]: wheel RECORD hash/size mismatch on {r_path!r}"
                )
    if seen_rec != set(raw_members.keys()):
        raise ValueError(
            f"backend_wheel_dir[{pkg_name!r}]: wheel members do not match RECORD entries"
        )

    data_prefix = f"{module_dir}-{version}.data/"
    alt_data_prefix = f"{pkg_name}-{version}.data/"
    pkg_files: dict[str, bytes] = {}
    for m_path, m_bytes in raw_members.items():
        if m_path.startswith((data_prefix, alt_data_prefix)):
            continue
        parts = m_path.split("/")
        if "__pycache__" in parts or m_path.endswith((".pyc", ".pyo")):
            raise ValueError(
                f"backend_wheel_dir[{pkg_name!r}]: bytecode forbidden in wheel: {m_path!r}"
            )
        if (
            parts[0] == dist_info_dir
            and len(parts) == 2
            and parts[1] in _INSTALLER_DIST_INFO_SKIP
        ):
            continue
        if parts[0] not in {module_dir, dist_info_dir}:
            raise ValueError(
                f"backend_wheel_dir[{pkg_name!r}]: unexpected purelib wheel member {m_path!r}"
            )
        pkg_files[m_path] = m_bytes

    actual_tree_sha256 = _compute_tree_digest_from_files(pkg_files)
    if actual_tree_sha256 != expected_tree_sha256:
        raise ValueError(
            f"backend_wheel_dir[{pkg_name!r}]: unpacked_tree_sha256 mismatch "
            f"(expected {expected_tree_sha256!r}, got {actual_tree_sha256!r})"
        )
    return pkg_files


def _materialize_verified_backend_site(
    target_dir: Path, verified_files: dict[str, bytes]
) -> None:
    if target_dir.is_symlink():
        raise ValueError("target_backend_site_dir: symlink forbidden")
    if target_dir.exists():
        if not target_dir.is_dir() or any(target_dir.iterdir()):
            raise ValueError(
                "target_backend_site_dir: existing target directory must be empty"
            )
    else:
        target_dir.mkdir(parents=True, exist_ok=False)

    resolved_root = target_dir.resolve()
    for rel_path in sorted(verified_files.keys(), key=lambda s: s.encode("utf-8")):
        source_path(rel_path)
        if (
            rel_path.endswith((".pyc", ".pyo", ".pth"))
            or "__pycache__" in rel_path.split("/")
            or rel_path in {"sitecustomize.py", "usercustomize.py"}
        ):
            raise ValueError(
                f"target_backend_site_dir: forbidden file type in closure: {rel_path!r}"
            )
        dest = (resolved_root / rel_path).resolve()
        if not dest.is_relative_to(resolved_root):
            raise ValueError(
                f"target_backend_site_dir: path traversal rejected for {rel_path!r}"
            )
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(verified_files[rel_path])


def _assert_clean_backend_site_tree(target_dir: Path) -> None:
    resolved_root = target_dir.resolve()
    for curr_root, dirnames, filenames in os.walk(resolved_root, followlinks=False):
        curr = Path(curr_root)
        if curr.is_symlink():
            raise ValueError("verified_backend_site_dir: unexpected symlink directory")
        for dname in dirnames:
            if dname == "__pycache__" or (curr / dname).is_symlink():
                raise ValueError(
                    f"verified_backend_site_dir: forbidden directory {dname!r}"
                )
        for fname in filenames:
            fpath = curr / fname
            if fpath.is_symlink() or fname.endswith((".pyc", ".pyo", ".pth")) or fname in {
                "sitecustomize.py",
                "usercustomize.py",
            }:
                raise ValueError(
                    f"verified_backend_site_dir: forbidden file {fname!r}"
                )


def verify_build_runtime_environment(
    uv_lock_bytes: bytes,
    *,
    target_backend_site_dir: Path | None = None,
    site_packages_dir: Path | None = None,
    backend_wheel_dir: Path | None = None,
    closure_specs: Mapping[str, tuple[str, ...]] = PINNED_UV_LOCK_CLOSURE_SPECS,
) -> tuple[str, dict[str, str]]:
    """Verify CPython 3.12 ABI and executed PEP 517 closure bytes without TOCTOU."""
    python_abi_tag = _verify_cpython_312_runtime()
    norm_specs = _normalize_closure_specs(closure_specs)
    lock_packages = _parse_uv_lock_packages(uv_lock_bytes)

    # Verify dependency closure in uv.lock contains no unpinned non-Windows package
    queue = list(norm_specs.keys())
    visited: set[str] = set()
    while queue:
        curr = queue.pop()
        if curr in visited:
            continue
        if curr not in lock_packages:
            raise ValueError(f"uv.lock: missing required closure package {curr!r}")
        if curr not in norm_specs:
            raise ValueError(
                f"uv.lock: transitive dependency {curr!r} missing from closure_specs"
            )
        visited.add(curr)
        for dep in lock_packages[curr].get("dependencies", []):
            if not isinstance(dep, dict):
                raise ValueError(f"uv.lock: malformed dependency entry under {curr!r}")
            if dep.get("marker") in _WINDOWS_ONLY_MARKERS:
                continue
            dep_name = _require_strict_str(dep.get("name"), f"uv.lock[{curr!r}].dep")
            queue.append(dep_name)

    wheel_filenames: dict[str, str] = {}
    for pkg_name, (expected_ver, expected_whl_sha, _, _, _) in norm_specs.items():
        pkg = lock_packages[pkg_name]
        if pkg.get("version") != expected_ver:
            raise ValueError(
                f"uv.lock[{pkg_name!r}]: expected version {expected_ver!r}, got {pkg.get('version')!r}"
            )
        wheels = pkg.get("wheels")
        if not isinstance(wheels, list) or len(wheels) != 1 or not isinstance(wheels[0], dict):
            raise ValueError(
                f"uv.lock[{pkg_name!r}]: expected single universal py3-none-any wheel"
            )
        actual_whl_hash = _require_sha256_digest(
            wheels[0].get("hash"), f"uv.lock[{pkg_name!r}].wheels[0].hash"
        )
        if actual_whl_hash != expected_whl_sha:
            raise ValueError(
                f"uv.lock[{pkg_name!r}]: wheel hash mismatch "
                f"(expected {expected_whl_sha!r}, got {actual_whl_hash!r})"
            )
        url = _require_strict_str(
            wheels[0].get("url"), f"uv.lock[{pkg_name!r}].wheels[0].url"
        )
        whl_fname = url.rsplit("/", 1)[-1]
        source_path(whl_fname)
        if "/" in whl_fname or not whl_fname.endswith("-py3-none-any.whl"):
            raise ValueError(
                f"uv.lock[{pkg_name!r}]: expected universal '-py3-none-any.whl', got {whl_fname!r}"
            )
        wheel_filenames[pkg_name] = whl_fname

    all_verified_files: dict[str, bytes] = {}
    closure_tree_digests: dict[str, str] = {}

    if backend_wheel_dir is not None:
        whl_dir_path = Path(backend_wheel_dir)
        if whl_dir_path.is_symlink() or not whl_dir_path.is_dir():
            raise ValueError("backend_wheel_dir: must be a non-symlink existing directory")

    eff_sp_dir: Path | None = None
    if backend_wheel_dir is None or site_packages_dir is not None:
        eff_sp_dir = (
            Path(sysconfig.get_path("purelib"))
            if site_packages_dir is None
            else Path(site_packages_dir)
        )
        if not eff_sp_dir.is_dir():
            raise ValueError(
                f"site_packages_dir: directory does not exist: {eff_sp_dir}"
            )

    for pkg_name in sorted(norm_specs.keys(), key=lambda s: s.encode("utf-8")):
        ver, whl_sha, dist_info_dir, module_dir, expected_tree_sha = norm_specs[
            pkg_name
        ]
        whl_pkg_files: dict[str, bytes] | None = None
        sp_pkg_files: dict[str, bytes] | None = None

        if backend_wheel_dir is not None:
            whl_pkg_files = _read_and_verify_wheelhouse_closure_pkg(
                Path(backend_wheel_dir),
                pkg_name=pkg_name,
                version=ver,
                wheel_filename=wheel_filenames[pkg_name],
                expected_wheel_sha256=whl_sha,
                dist_info_dir=dist_info_dir,
                module_dir=module_dir,
                expected_tree_sha256=expected_tree_sha,
            )

        if eff_sp_dir is not None:
            sp_pkg_files = _read_and_verify_site_packages_closure_pkg(
                eff_sp_dir,
                pkg_name=pkg_name,
                dist_info_dir=dist_info_dir,
                module_dir=module_dir,
                expected_tree_sha256=expected_tree_sha,
            )

        if whl_pkg_files is not None and sp_pkg_files is not None:
            if whl_pkg_files != sp_pkg_files:
                raise ValueError(
                    f"verify_build_runtime_environment[{pkg_name!r}]: "
                    "site_packages_dir bytes diverge from backend_wheel_dir wheel"
                )

        chosen_files = whl_pkg_files if whl_pkg_files is not None else sp_pkg_files
        if chosen_files is None:
            raise ValueError(
                f"verify_build_runtime_environment[{pkg_name!r}]: no verified source bytes"
            )
        for rel_p, raw_b in chosen_files.items():
            if rel_p in all_verified_files:
                raise ValueError(
                    f"verify_build_runtime_environment: overlapping closure path {rel_p!r}"
                )
            all_verified_files[rel_p] = raw_b
        closure_tree_digests[pkg_name] = expected_tree_sha

    if target_backend_site_dir is not None:
        target_path = Path(target_backend_site_dir)
        _materialize_verified_backend_site(target_path, all_verified_files)
        _assert_clean_backend_site_tree(target_path)

    return python_abi_tag, closure_tree_digests


def compute_build_backend_digest(
    pyproject_bytes: bytes,
    uv_lock_bytes: bytes,
    *,
    site_packages_dir: Path | None = None,
    backend_wheel_dir: Path | None = None,
) -> tuple[str, str, str]:
    """Validate `pyproject.toml` + `uv.lock` + executed closure and compute canonical backend digest."""
    if type(pyproject_bytes) is not bytes or type(uv_lock_bytes) is not bytes:
        raise ValueError(
            "compute_build_backend_digest: pyproject_bytes and uv_lock_bytes must be bytes"
        )
    try:
        pyproject_data = tomllib.loads(pyproject_bytes.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ValueError(f"pyproject.toml: invalid UTF-8 or TOML: {exc}") from exc

    allowed_top_keys = {"build-system", "project", "dependency-groups", "tool"}
    required_top_keys = {"build-system", "project", "tool"}
    if not required_top_keys.issubset(pyproject_data.keys()) or not set(
        pyproject_data.keys()
    ).issubset(allowed_top_keys):
        raise ValueError(
            "pyproject.toml: top-level tables must contain {'build-system', 'project', 'tool'} "
            "and allow at most {'build-system', 'project', 'dependency-groups', 'tool'}"
        )
    if "dependency-groups" in pyproject_data and not isinstance(
        pyproject_data["dependency-groups"], dict
    ):
        raise ValueError("pyproject.toml: [dependency-groups] must be a table")

    build_sys = pyproject_data.get("build-system")
    if not isinstance(build_sys, dict) or set(build_sys.keys()) != {
        "requires",
        "build-backend",
    }:
        raise ValueError(
            "pyproject.toml: [build-system] must contain exclusively "
            "{'requires', 'build-backend'} (backend-path forbidden)"
        )
    build_backend = _require_exact_str(
        build_sys.get("build-backend"),
        EXPECTED_BUILD_BACKEND,
        "pyproject.build-system.build-backend",
    )
    if build_sys.get("requires") != [
        f"{EXPECTED_BUILD_BACKEND_PACKAGE}=={EXPECTED_BUILD_BACKEND_VERSION}"
    ]:
        raise ValueError(
            "pyproject.toml: build-system.requires must equal ['hatchling==1.33.0']"
        )

    expected_project_keys = {
        "name",
        "version",
        "description",
        "requires-python",
        "dependencies",
        "license-files",
    }
    project_tbl = pyproject_data.get("project")
    if (
        not isinstance(project_tbl, dict)
        or "dynamic" in project_tbl
        or set(project_tbl.keys()) != expected_project_keys
    ):
        raise ValueError(
            "pyproject.toml: [project] must contain exclusively "
            "{'name', 'version', 'description', 'requires-python', 'dependencies', 'license-files'}"
        )
    _require_exact_str(
        project_tbl.get("name"), "smart-ads", "pyproject.project.name"
    )
    _require_exact_str(
        project_tbl.get("version"), "0.1.0", "pyproject.project.version"
    )
    proj_desc = project_tbl.get("description")
    proj_req_py = project_tbl.get("requires-python")
    if (
        type(proj_desc) is not str
        or not proj_desc.strip()
        or "\x00" in proj_desc
        or type(proj_req_py) is not str
        or not proj_req_py.strip()
        or "\x00" in proj_req_py
    ):
        raise ValueError(
            "pyproject.toml: [project].description and [project].requires-python must be non-empty strings"
        )
    if (
        type(project_tbl.get("dependencies")) is not list
        or len(project_tbl["dependencies"]) != 0
        or type(project_tbl.get("license-files")) is not list
        or len(project_tbl["license-files"]) != 0
    ):
        raise ValueError(
            "pyproject.toml: [project] must pin dependencies=[] and license-files=[]"
        )

    tool_tbl = pyproject_data.get("tool")
    if (
        not isinstance(tool_tbl, dict)
        or "hatch" not in tool_tbl
        or not set(tool_tbl.keys()).issubset({"hatch", "pytest"})
    ):
        raise ValueError(
            "pyproject.toml: [tool] must contain 'hatch' and allow at most {'hatch', 'pytest'}"
        )
    if "pytest" in tool_tbl and not isinstance(tool_tbl["pytest"], dict):
        raise ValueError("pyproject.toml: [tool.pytest] must be a table")
    tool_hatch = tool_tbl.get("hatch")
    if not isinstance(tool_hatch, dict) or set(tool_hatch.keys()) != {"build"}:
        raise ValueError(
            "pyproject.toml: [tool.hatch] must contain exclusively {'build'}"
        )
    hatch_build = tool_hatch["build"]
    if (
        not isinstance(hatch_build, dict)
        or set(hatch_build.keys()) != {"ignore-vcs", "targets"}
        or type(hatch_build.get("ignore-vcs")) is not bool
        or hatch_build["ignore-vcs"] is not True
    ):
        raise ValueError(
            "pyproject.toml: [tool.hatch.build] must contain exclusively "
            "{'ignore-vcs': true, 'targets': ...} (hooks forbidden)"
        )
    targets = hatch_build["targets"]
    if (
        not isinstance(targets, dict)
        or "wheel" not in targets
        or not set(targets.keys()).issubset({"wheel", "sdist"})
    ):
        raise ValueError(
            "pyproject.toml: [tool.hatch.build.targets] must contain 'wheel' and "
            "allow at most {'wheel', 'sdist'}"
        )
    if "sdist" in targets:
        sdist_target = targets["sdist"]
        if (
            not isinstance(sdist_target, dict)
            or "hooks" in sdist_target
            or not set(sdist_target.keys()).issubset({"only-include", "sources"})
            or sdist_target.get("only-include") != ["src/smart_ads"]
            or (
                "sources" in sdist_target
                and sdist_target["sources"] != ["src"]
            )
        ):
            raise ValueError(
                "pyproject.toml: [tool.hatch.build.targets.sdist] must be hook-free and "
                "pin only-include=['src/smart_ads'] (and optional sources=['src'])"
            )
    wheel_target = targets["wheel"]
    if (
        not isinstance(wheel_target, dict)
        or set(wheel_target.keys()) != {"only-include", "sources"}
        or wheel_target["only-include"] != ["src/smart_ads"]
        or wheel_target["sources"] != ["src"]
    ):
        raise ValueError(
            "pyproject.toml: [tool.hatch.build.targets.wheel] must contain exclusively "
            "only-include=['src/smart_ads'] and sources=['src'] (hooks forbidden)"
        )

    _, closure_tree_digests = verify_build_runtime_environment(
        uv_lock_bytes,
        site_packages_dir=site_packages_dir,
        backend_wheel_dir=backend_wheel_dir,
    )
    lock_packages = _parse_uv_lock_packages(uv_lock_bytes)
    hatchling_pkg = lock_packages.get(EXPECTED_BUILD_BACKEND_PACKAGE)
    if not isinstance(hatchling_pkg, dict):
        raise ValueError("uv.lock: missing 'hatchling' package entry")
    version = _require_exact_str(
        hatchling_pkg.get("version"),
        EXPECTED_BUILD_BACKEND_VERSION,
        "uv.lock[hatchling].version",
    )
    sdist_tbl = hatchling_pkg.get("sdist")
    if not isinstance(sdist_tbl, dict):
        raise ValueError("uv.lock[hatchling]: missing sdist hash table")
    sdist_hash = _require_sha256_digest(
        sdist_tbl.get("hash"), "uv.lock[hatchling].sdist.hash"
    )
    sorted_wheel_hashes = sorted(
        {
            _require_sha256_digest(w.get("hash"), "uv.lock[hatchling].wheels.hash")
            for w in hatchling_pkg.get("wheels", [])
            if isinstance(w, dict)
        },
        key=lambda s: s.encode("utf-8"),
    )
    if not sorted_wheel_hashes:
        raise ValueError("uv.lock[hatchling]: missing wheel hashes")

    backend_digest = json_digest(
        {
            "build_backend": EXPECTED_BUILD_BACKEND,
            "closure_unpacked_trees": closure_tree_digests,
            "package": EXPECTED_BUILD_BACKEND_PACKAGE,
            "sdist_hash": sdist_hash,
            "version": EXPECTED_BUILD_BACKEND_VERSION,
            "wheel_hashes": sorted_wheel_hashes,
        }
    )
    return build_backend, version, backend_digest


# ---------------------------------------------------------------------------
# Offline Git Object Snapshot Materialization & Reproducible PEP 517 Wheel Build
# ---------------------------------------------------------------------------


def materialize_git_build_snapshot(
    repo_root: Path,
    *,
    commit_ref: str = "HEAD",
    site_packages_dir: Path | None = None,
    backend_wheel_dir: Path | None = None,
) -> GitBuildSnapshot:
    """Materialize a committed Git tree snapshot exclusively via `run_git_offline`."""
    repo_path = Path(repo_root)
    if not repo_path.is_dir():
        raise ValueError(f"repo_root: directory does not exist: {repo_path}")
    checked_ref = _require_strict_str(commit_ref, "commit_ref")
    if checked_ref.startswith("-"):
        raise ValueError("commit_ref: must not start with '-'")

    commit_sha = (
        run_git_offline(
            repo_path, "rev-parse", "--verify", f"{checked_ref}^{{commit}}"
        )
        .stdout.decode("ascii")
        .strip()
    )
    _require_git_oid(commit_sha, "commit_sha")

    tree_oid = (
        run_git_offline(
            repo_path, "rev-parse", "--verify", f"{commit_sha}^{{tree}}"
        )
        .stdout.decode("ascii")
        .strip()
    )
    _require_git_oid(tree_oid, "tree_oid")

    ls_tree_raw = run_git_offline(repo_path, "ls-tree", "-r", "-z", commit_sha).stdout
    seen_tree_paths: set[str] = set()
    staged_records: dict[str, tuple[str, str]] = {}
    for entry in ls_tree_raw.split(b"\0"):
        if not entry:
            continue
        if b"\t" not in entry:
            raise ValueError("git ls-tree: malformed entry without tab separator")
        meta, raw_path = entry.split(b"\t", 1)
        meta_parts = meta.decode("ascii").split()
        if len(meta_parts) != 3:
            raise ValueError("git ls-tree: malformed metadata tuple")
        mode, kind, oid = meta_parts
        try:
            rel_path = raw_path.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("git ls-tree: non-UTF-8 path forbidden") from exc
        source_path(rel_path)
        _require_git_oid(oid, f"git.ls_tree[{rel_path!r}].oid")
        if rel_path in seen_tree_paths:
            raise ValueError(f"git ls-tree: duplicate path {rel_path!r}")
        seen_tree_paths.add(rel_path)
        if kind != "blob" or mode not in {"100644", "100755"}:
            raise ValueError(
                f"git ls-tree: forbidden object kind={kind!r} mode={mode!r} at {rel_path!r}"
            )
        _reject_forbidden_hatch_filename(rel_path, label="git ls-tree")
        if _is_allowed_snapshot_stage_path(rel_path):
            staged_records[rel_path] = (mode, oid)

    if not seen_tree_paths:
        raise ValueError("git ls-tree: empty commit tree")
    if (
        "pyproject.toml" not in staged_records
        or "uv.lock" not in staged_records
        or "src/smart_ads/__init__.py" not in staged_records
    ):
        raise ValueError(
            "materialize_git_build_snapshot: commit must include 'pyproject.toml', "
            "'uv.lock', and 'src/smart_ads/__init__.py'"
        )

    blob_cache: dict[str, bytes] = {}
    files: dict[str, bytes] = {}
    modes: dict[str, str] = {}
    for rel_path in sorted(staged_records.keys(), key=lambda s: s.encode("utf-8")):
        mode, oid = staged_records[rel_path]
        if oid not in blob_cache:
            blob_cache[oid] = run_git_offline(
                repo_path, "cat-file", "blob", oid
            ).stdout
        files[rel_path] = blob_cache[oid]
        modes[rel_path] = mode

    pyproject_bytes = files["pyproject.toml"]
    uv_lock_bytes = files["uv.lock"]
    build_backend, build_backend_version, build_backend_digest = (
        compute_build_backend_digest(
            pyproject_bytes,
            uv_lock_bytes,
            site_packages_dir=site_packages_dir,
            backend_wheel_dir=backend_wheel_dir,
        )
    )
    return GitBuildSnapshot(
        commit_sha=commit_sha,
        tree_oid=tree_oid,
        files=files,
        modes=modes,
        pyproject_sha256=digest(pyproject_bytes),
        uv_lock_sha256=digest(uv_lock_bytes),
        build_backend=build_backend,
        build_backend_version=build_backend_version,
        build_backend_digest=build_backend_digest,
    )


def _stage_git_snapshot_tree(stage_dir: Path, snapshot: GitBuildSnapshot) -> None:
    stage_dir.mkdir(parents=True, exist_ok=False)
    resolved_stage = stage_dir.resolve()
    for rel_path in sorted(snapshot.files.keys(), key=lambda s: s.encode("utf-8")):
        source_path(rel_path)
        _reject_forbidden_hatch_filename(rel_path, label="_stage_git_snapshot_tree")
        if not _is_allowed_snapshot_stage_path(rel_path):
            raise ValueError(
                f"_stage_git_snapshot_tree: forbidden path outside build inputs: {rel_path!r}"
            )
        dest = (resolved_stage / rel_path).resolve()
        if not dest.is_relative_to(resolved_stage):
            raise ValueError(f"staging path escaped root: {rel_path!r}")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(snapshot.files[rel_path])
        os.chmod(dest, 0o755 if snapshot.modes[rel_path] == "100755" else 0o644)


def _run_isolated_pep517_wheel_build(
    *,
    stage_dir: Path,
    wheel_out_dir: Path,
    verified_backend_site_dir: Path,
    tmp_dir: Path,
    source_date_epoch: int,
) -> tuple[str, bytes]:
    wheel_out_dir.mkdir(parents=True, exist_ok=False)
    tmp_dir.mkdir(parents=True, exist_ok=False)

    closure_modules = sorted(
        {
            spec[3]
            for spec in PINNED_UV_LOCK_CLOSURE_SPECS.values()
        }
        | {EXPECTED_BUILD_BACKEND},
        key=lambda s: s.encode("utf-8"),
    )
    closure_mods_csv = ",".join(closure_modules)

    clean_env = {
        "HOME": "/nonexistent",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": _clean_system_path(),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "PYTHONSAFEPATH": "1",
        "SOURCE_DATE_EPOCH": str(source_date_epoch),
        "TMPDIR": str(tmp_dir.resolve()),
        "TZ": "UTC",
    }

    try:
        proc = subprocess.run(
            [
                sys.executable,
                "-I",
                "-B",
                "-S",
                "-c",
                _PEP517_DRIVER_SCRIPT,
                str(verified_backend_site_dir.resolve()),
                closure_mods_csv,
                str(stage_dir.resolve()),
                str(wheel_out_dir.resolve()),
                str(tmp_dir.resolve()),
                str(source_date_epoch),
                _PEP517_RUNNER_BOOTSTRAP,
            ],
            cwd=str(stage_dir.resolve()),
            env=clean_env,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError(f"isolated PEP 517 build failed or timed out: {exc}") from exc

    if proc.returncode != 0:
        raise ValueError(
            f"isolated PEP 517 build failed (rc={proc.returncode}): {proc.stderr.strip()}"
        )

    parsed = loads_strict(proc.stdout)
    if not isinstance(parsed, dict) or type(parsed.get("wheel_name")) is not str:
        raise ValueError("isolated PEP 517 driver returned malformed JSON output")
    wheel_name = parsed["wheel_name"]
    _require_exact_str(
        wheel_name, EXPECTED_WHEEL_FILENAME, "isolated_pep517.wheel_name"
    )

    built_wheels = list(wheel_out_dir.glob("*.whl"))
    if len(built_wheels) != 1 or built_wheels[0].name != wheel_name:
        raise ValueError("isolated PEP 517 build did not emit unique expected wheel")
    return wheel_name, built_wheels[0].read_bytes()


def build_reproducible_wheel(
    repo_root: Path,
    out_dir: Path,
    *,
    commit_ref: str = "HEAD",
    source_date_epoch: int = DEFAULT_SOURCE_DATE_EPOCH,
    backend_wheel_dir: Path | None = None,
    site_packages_dir: Path | None = None,
) -> tuple[Path, GitBuildSnapshot]:
    """Build `smart-ads` wheel twice in isolated `python -I -B -S` staging and verify byte identity."""
    _verify_cpython_312_runtime()
    _require_safe_nonneg_int(source_date_epoch, "source_date_epoch", minimum=0)

    snapshot = materialize_git_build_snapshot(
        repo_root,
        commit_ref=commit_ref,
        site_packages_dir=site_packages_dir,
        backend_wheel_dir=backend_wheel_dir,
    )

    with tempfile.TemporaryDirectory(prefix="gov1-pep517-") as raw_tmp:
        work_root = Path(raw_tmp).resolve()
        verified_backend_site_dir = work_root / "verified_backend_site"
        verify_build_runtime_environment(
            snapshot.files["uv.lock"],
            target_backend_site_dir=verified_backend_site_dir,
            site_packages_dir=site_packages_dir,
            backend_wheel_dir=backend_wheel_dir,
        )

        stage_1 = work_root / "stage_1"
        stage_2 = work_root / "stage_2"
        _stage_git_snapshot_tree(stage_1, snapshot)
        _stage_git_snapshot_tree(stage_2, snapshot)

        wheel_name_1, wheel_bytes_1 = _run_isolated_pep517_wheel_build(
            stage_dir=stage_1,
            wheel_out_dir=work_root / "wheel_out_1",
            verified_backend_site_dir=verified_backend_site_dir,
            tmp_dir=work_root / "tmp_1",
            source_date_epoch=source_date_epoch,
        )
        wheel_name_2, wheel_bytes_2 = _run_isolated_pep517_wheel_build(
            stage_dir=stage_2,
            wheel_out_dir=work_root / "wheel_out_2",
            verified_backend_site_dir=verified_backend_site_dir,
            tmp_dir=work_root / "tmp_2",
            source_date_epoch=source_date_epoch,
        )

        _assert_clean_backend_site_tree(verified_backend_site_dir)

    if wheel_name_1 != wheel_name_2 or wheel_bytes_1 != wheel_bytes_2:
        raise ValueError(
            "build_reproducible_wheel: non-deterministic wheel output across double build"
        )

    out_path = Path(out_dir)
    if out_path.is_symlink():
        raise ValueError("out_dir: symlink forbidden")
    out_path.mkdir(parents=True, exist_ok=True)
    final_wheel_path = out_path / wheel_name_1
    if final_wheel_path.is_symlink():
        raise ValueError("out_dir: target wheel path is a symlink")
    final_wheel_path.write_bytes(wheel_bytes_1)
    if final_wheel_path.read_bytes() != wheel_bytes_1:
        raise ValueError("build_reproducible_wheel: wheel writeback verification failed")
    return final_wheel_path, snapshot


# ---------------------------------------------------------------------------
# Wheel Object Locator (`smart_ads/wheel_object_locator/v1`)
# ---------------------------------------------------------------------------


def build_wheel_object_locator(wheel_bytes: bytes) -> dict[str, Any]:
    """Build closed 5-member `smart_ads/wheel_object_locator/v1`."""
    if type(wheel_bytes) is not bytes or len(wheel_bytes) == 0:
        raise ValueError("wheel_bytes: expected non-empty bytes")
    _require_safe_nonneg_int(len(wheel_bytes), "wheel_bytes.size_bytes", minimum=1)
    wheel_digest = digest(wheel_bytes)
    obj = {
        "$schema": WHEEL_OBJECT_LOCATOR_SCHEMA,
        "store_kind": "cell_immutable_object",
        "object_ref": f"cell-object:{wheel_digest}",
        "wheel_digest": wheel_digest,
        "size_bytes": len(wheel_bytes),
    }
    verify_wheel_object_locator(obj, expected_wheel_bytes=wheel_bytes)
    return obj


def verify_wheel_object_locator(
    obj: dict[str, Any], *, expected_wheel_bytes: bytes | None = None
) -> None:
    """Validate `smart_ads/wheel_object_locator/v1` structure and optional byte identity."""
    exact_fields(obj, _WHEEL_OBJECT_LOCATOR_FIELDS, "wheel_object_locator")
    _require_exact_str(
        obj["$schema"], WHEEL_OBJECT_LOCATOR_SCHEMA, "wheel_object_locator.$schema"
    )
    _require_exact_str(
        obj["store_kind"],
        "cell_immutable_object",
        "wheel_object_locator.store_kind",
    )
    whl_digest = _require_sha256_digest(
        obj["wheel_digest"], "wheel_object_locator.wheel_digest"
    )
    _require_exact_str(
        obj["object_ref"],
        f"cell-object:{whl_digest}",
        "wheel_object_locator.object_ref",
    )
    size_bytes = _require_safe_nonneg_int(
        obj["size_bytes"], "wheel_object_locator.size_bytes", minimum=1
    )
    loads_strict(canonicalize(obj).decode("utf-8"))

    if expected_wheel_bytes is not None:
        if type(expected_wheel_bytes) is not bytes:
            raise ValueError("expected_wheel_bytes: expected bytes")
        if digest(expected_wheel_bytes) != whl_digest:
            raise ValueError(
                "wheel_object_locator.wheel_digest: mismatch against expected_wheel_bytes"
            )
        if len(expected_wheel_bytes) != size_bytes:
            raise ValueError(
                "wheel_object_locator.size_bytes: mismatch against expected_wheel_bytes"
            )


# ---------------------------------------------------------------------------
# Wheel Archive, PEP 427 RECORD, Static AST & Clean-Venv Boundary Inspection
# ---------------------------------------------------------------------------


def _scan_wheel_python_ast_violations(source: str, *, filename: str) -> list[str]:
    try:
        tree = ast.parse(source, filename=filename)
    except SyntaxError as exc:
        return [f"{filename}:{exc.lineno}: syntax error in wheel Python source: {exc.msg}"]

    violations: list[str] = []
    forbidden_attr_strings = (
        _WHEEL_WIDE_FORBIDDEN_DYNAMIC_NAMES | _WHEEL_WIDE_FORBIDDEN_TOP_IMPORTS
    )

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname == "re" and alias.name != "re":
                    violations.append(
                        f"{filename}:{node.lineno}: forbidden import alias 're' for {alias.name!r}"
                    )
                top = alias.name.split(".")[0]
                if top in _WHEEL_WIDE_FORBIDDEN_TOP_IMPORTS:
                    violations.append(
                        f"{filename}:{node.lineno}: forbidden wheel-wide import {alias.name!r}"
                    )
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                top = node.module.split(".")[0]
                if top in _WHEEL_WIDE_FORBIDDEN_TOP_IMPORTS:
                    violations.append(
                        f"{filename}:{node.lineno}: forbidden wheel-wide from-import {node.module!r}"
                    )
            for alias in node.names:
                if alias.name in _WHEEL_WIDE_FORBIDDEN_DYNAMIC_NAMES:
                    violations.append(
                        f"{filename}:{node.lineno}: forbidden wheel-wide imported symbol {alias.name!r}"
                    )
                if alias.asname == "re":
                    violations.append(
                        f"{filename}:{node.lineno}: forbidden shadowing alias 're'"
                    )
                if (
                    alias.asname is not None
                    and alias.asname in _WHEEL_WIDE_FORBIDDEN_DYNAMIC_NAMES
                ):
                    violations.append(
                        f"{filename}:{node.lineno}: forbidden wheel-wide alias {alias.asname!r}"
                    )
        elif isinstance(node, ast.Name):
            if node.id == "re" and isinstance(node.ctx, (ast.Store, ast.Del)):
                violations.append(
                    f"{filename}:{node.lineno}: forbidden rebinding of 're'"
                )
            if node.id in _WHEEL_WIDE_FORBIDDEN_DYNAMIC_NAMES:
                violations.append(
                    f"{filename}:{node.lineno}: forbidden dynamic builtin name {node.id!r}"
                )
        elif isinstance(node, ast.Attribute):
            if node.attr in _WHEEL_WIDE_FORBIDDEN_DYNAMIC_NAMES:
                is_stdlib_re_compile = (
                    node.attr == "compile"
                    and isinstance(node.value, ast.Name)
                    and node.value.id == "re"
                )
                if not is_stdlib_re_compile:
                    violations.append(
                        f"{filename}:{node.lineno}: forbidden dynamic attribute {node.attr!r}"
                    )
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in {
                "getattr",
                "setattr",
                "hasattr",
                "delattr",
            }:
                if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
                    attr_lit = node.args[1].value
                    if isinstance(attr_lit, str) and attr_lit in forbidden_attr_strings:
                        violations.append(
                            f"{filename}:{node.lineno}: forbidden {node.func.id} literal {attr_lit!r}"
                        )
        elif isinstance(node, ast.Subscript):
            if isinstance(node.slice, ast.Constant) and isinstance(
                node.slice.value, str
            ):
                if node.slice.value in forbidden_attr_strings:
                    violations.append(
                        f"{filename}:{node.lineno}: forbidden subscript literal {node.slice.value!r}"
                    )
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            if node.value in {"__import__", "__builtins__"}:
                violations.append(
                    f"{filename}:{node.lineno}: forbidden dynamic import string literal {node.value!r}"
                )
        elif isinstance(node, ast.Assert):
            violations.append(
                f"{filename}:{node.lineno}: forbidden assert statement in wheel source"
            )

    # Pure-layer checks (smart_ads/__init__.py and pure subpackages)
    rel_parts = filename.split("/")[1:]
    is_pure_layer = (
        len(rel_parts) == 1 and rel_parts[0] == "__init__.py"
    ) or (len(rel_parts) >= 2 and rel_parts[0] in _PURE_LAYER_SUBPACKAGES)
    if is_pure_layer:
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top = alias.name.split(".")[0]
                    if top not in _PURE_LAYER_ALLOWED_TOP_IMPORTS:
                        violations.append(
                            f"{filename}:{node.lineno}: import {alias.name!r} outside pure-layer allowlist"
                        )
            elif isinstance(node, ast.ImportFrom):
                if node.level == 0:
                    if not node.module:
                        violations.append(
                            f"{filename}:{node.lineno}: empty absolute from-import module"
                        )
                    else:
                        top = node.module.split(".")[0]
                        if top not in _PURE_LAYER_ALLOWED_TOP_IMPORTS:
                            violations.append(
                                f"{filename}:{node.lineno}: from-import {node.module!r} outside pure-layer allowlist"
                            )
                for alias in node.names:
                    if (
                        alias.name == "open"
                        or alias.asname == "open"
                        or alias.name in _PURE_LAYER_FORBIDDEN_FILE_ATTRS
                        or alias.name in _PURE_LAYER_FORBIDDEN_AMBIENT_TIME_ATTRS
                    ):
                        violations.append(
                            f"{filename}:{node.lineno}: forbidden pure-layer symbol {alias.name!r}"
                        )
            elif isinstance(node, ast.Name) and node.id == "open":
                violations.append(
                    f"{filename}:{node.lineno}: forbidden pure-layer builtin 'open'"
                )
            elif isinstance(node, ast.Attribute):
                if node.attr in _PURE_LAYER_FORBIDDEN_FILE_ATTRS:
                    violations.append(
                        f"{filename}:{node.lineno}: forbidden pure-layer file I/O attribute {node.attr!r}"
                    )
                if node.attr in _PURE_LAYER_FORBIDDEN_AMBIENT_TIME_ATTRS:
                    violations.append(
                        f"{filename}:{node.lineno}: forbidden ambient time attribute {node.attr!r}"
                    )

    return violations


def _read_and_validate_wheel_archive(
    wheel_bytes: bytes,
) -> tuple[dict[str, bytes], list[dict[str, Any]], str, list[str]]:
    try:
        zf_ctx = zipfile.ZipFile(io.BytesIO(wheel_bytes), "r")
    except zipfile.BadZipFile as exc:
        raise ValueError(f"wheel archive: invalid ZIP format: {exc}") from exc

    members: dict[str, bytes] = {}
    with zf_ctx as zf:
        infos = zf.infolist()
        if not infos:
            raise ValueError("wheel archive: empty ZIP central directory")
        for info in infos:
            if info.is_dir() or info.filename.endswith("/"):
                raise ValueError(
                    f"wheel archive: directory entry forbidden: {info.filename!r}"
                )
            unix_type = (info.external_attr >> 16) & 0o170000
            if unix_type == 0o120000 or (unix_type != 0 and unix_type != 0o100000):
                raise ValueError(
                    f"wheel archive: symlink or special entry forbidden: {info.filename!r}"
                )
            source_path(info.filename)
            if info.filename in members:
                raise ValueError(
                    f"wheel archive: duplicate central-directory entry {info.filename!r}"
                )
            if _WHEEL_ALLOWLIST_RE.fullmatch(info.filename) is None:
                raise ValueError(
                    f"wheel archive: member violates strict allowlist: {info.filename!r}"
                )
            raw = zf.read(info)
            if len(raw) != info.file_size:
                raise ValueError(
                    f"wheel archive: declared file_size mismatch on {info.filename!r}"
                )
            members[info.filename] = raw

    for mandatory in (
        "smart_ads/__init__.py",
        "smart_ads-0.1.0.dist-info/METADATA",
        "smart_ads-0.1.0.dist-info/WHEEL",
        EXPECTED_SELF_RECORD_PATH,
    ):
        if mandatory not in members:
            raise ValueError(f"wheel archive: missing mandatory member {mandatory!r}")

    try:
        record_text = members[EXPECTED_SELF_RECORD_PATH].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("wheel RECORD: invalid UTF-8") from exc
    if "\x00" in record_text or not record_text.strip():
        raise ValueError("wheel RECORD: empty or contains NUL byte")

    for raw_line in record_text.splitlines():
        if not raw_line:
            raise ValueError("wheel RECORD: blank lines are forbidden")

    seen_record_paths: set[str] = set()
    record_entries: list[dict[str, Any]] = []
    for row in csv.reader(io.StringIO(record_text, newline="")):
        if len(row) != 3:
            raise ValueError(f"wheel RECORD: expected 3 CSV columns, got {row!r}")
        rec_path, rec_hash, rec_size = row
        source_path(rec_path)
        if rec_path in seen_record_paths:
            raise ValueError(f"wheel RECORD: duplicate row for {rec_path!r}")
        if rec_path not in members:
            raise ValueError(
                f"wheel RECORD: row references nonexistent archive member {rec_path!r}"
            )
        seen_record_paths.add(rec_path)

        if rec_path == EXPECTED_SELF_RECORD_PATH:
            if rec_hash != "" or rec_size != "":
                raise ValueError(
                    "wheel RECORD: self-referential RECORD row must have empty hash and empty size"
                )
            record_entries.append(
                {
                    "path": EXPECTED_SELF_RECORD_PATH,
                    "record_hash": "",
                    "record_size": None,
                }
            )
        else:
            raw_member = members[rec_path]
            expected_hash = _pep427_record_hash(raw_member)
            if rec_hash == "" or rec_hash != expected_hash:
                raise ValueError(
                    f"wheel RECORD: hash mismatch for {rec_path!r} "
                    f"(expected {expected_hash!r}, got {rec_hash!r})"
                )
            if (
                _NONNEG_INT_STR_RE.fullmatch(rec_size) is None
                or int(rec_size) != len(raw_member)
            ):
                raise ValueError(
                    f"wheel RECORD: size mismatch for {rec_path!r} "
                    f"(expected {len(raw_member)}, got {rec_size!r})"
                )
            record_entries.append(
                {
                    "path": rec_path,
                    "record_hash": expected_hash,
                    "record_size": len(raw_member),
                }
            )

    if seen_record_paths != set(members.keys()):
        missing = sorted(set(members.keys()) - seen_record_paths)
        raise ValueError(f"wheel RECORD: archive members omitted from RECORD: {missing!r}")

    sorted_record_entries = sorted(
        record_entries, key=lambda e: e["path"].encode("utf-8")
    )
    sorted_record_digest = json_digest(sorted_record_entries)

    derived_modules: set[str] = set()
    for member_path in sorted(members.keys(), key=lambda s: s.encode("utf-8")):
        if not member_path.endswith(".py"):
            continue
        try:
            py_source = members[member_path].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(
                f"wheel AST scan: non-UTF-8 Python file {member_path!r}"
            ) from exc
        violations = _scan_wheel_python_ast_violations(
            py_source, filename=member_path
        )
        if violations:
            raise ValueError(
                "wheel AST boundary scan failed:\n" + "\n".join(violations)
            )
        stem = member_path[:-3]
        if stem.endswith("/__init__"):
            mod_name = stem[: -len("/__init__")].replace("/", ".")
        else:
            parent_init = member_path.rsplit("/", 1)[0] + "/__init__.py"
            if parent_init not in members:
                raise ValueError(
                    f"wheel archive: missing package __init__.py for {member_path!r}"
                )
            mod_name = stem.replace("/", ".")
        derived_modules.add(mod_name)

    if derived_modules != EXPECTED_PACKAGED_MODULES:
        raise ValueError(
            "wheel archive: packaged module set does not match expected 24 modules: "
            f"{sorted(derived_modules)!r}"
        )

    sorted_modules = sorted(derived_modules, key=lambda s: s.encode("utf-8"))
    return members, sorted_record_entries, sorted_record_digest, sorted_modules


def inspect_wheel_boundary(wheel_path: Path) -> dict[str, Any]:
    """Verify wheel allowlist, PEP 427 RECORD, AST boundary, and outside-repo clean-venv `python -I` import."""
    _verify_cpython_312_runtime()
    whl_file = Path(wheel_path)
    if whl_file.is_symlink() or not whl_file.is_file():
        raise ValueError(f"wheel_path: expected regular non-symlink file at {whl_file}")
    wheel_bytes = whl_file.read_bytes()
    wheel_digest = digest(wheel_bytes)

    members, sorted_record_entries, sorted_record_digest, expected_modules = (
        _read_and_validate_wheel_archive(wheel_bytes)
    )

    governance_repo_root = Path(__file__).resolve().parents[2]
    with tempfile.TemporaryDirectory(prefix="gov1-clean-venv-") as raw_tmp:
        tmp_root = Path(raw_tmp).resolve()
        if tmp_root.is_relative_to(governance_repo_root):
            raise ValueError("clean_venv: temporary directory must reside outside repository")

        venv_dir = tmp_root / "venv"
        probe_cwd = tmp_root / "cwd"
        probe_cwd.mkdir(parents=True, exist_ok=True)
        venv.EnvBuilder(
            system_site_packages=False,
            with_pip=False,
            clear=True,
            symlinks=os.name != "nt",
        ).create(venv_dir)
        venv_python = venv_dir / (
            "Scripts/python.exe" if os.name == "nt" else "bin/python"
        )

        clean_env = {
            "HOME": "/nonexistent",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": _clean_system_path(),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            "PYTHONSAFEPATH": "1",
            "TMPDIR": str(probe_cwd),
            "TZ": "UTC",
        }

        purelib_proc = subprocess.run(
            [
                str(venv_python),
                "-I",
                "-B",
                "-c",
                "import sysconfig; print(sysconfig.get_path('purelib'))",
            ],
            cwd=str(probe_cwd),
            env=clean_env,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if purelib_proc.returncode != 0:
            raise ValueError(
                f"clean_venv: failed to query purelib: {purelib_proc.stderr.strip()}"
            )
        purelib_path = Path(purelib_proc.stdout.strip()).resolve()
        if not purelib_path.is_relative_to(venv_dir.resolve()):
            raise ValueError("clean_venv: purelib resolved outside venv root")

        # Safe materialization of verified regular-file wheel members into purelib
        for rel_path, raw_bytes in members.items():
            dest = (purelib_path / rel_path).resolve()
            if not dest.is_relative_to(purelib_path):
                raise ValueError(f"clean_venv: path traversal rejected for {rel_path!r}")
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(raw_bytes)

        probe_proc = subprocess.run(
            [
                str(venv_python),
                "-I",
                "-B",
                "-c",
                _CLEAN_VENV_PROBE_SCRIPT,
                str(purelib_path),
                canonicalize(expected_modules).decode("utf-8"),
            ],
            cwd=str(probe_cwd),
            env=clean_env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        if probe_proc.returncode != 0:
            raise ValueError(
                f"clean_venv: isolated import probe failed: {probe_proc.stderr.strip()}"
            )

    probe_out = loads_strict(probe_proc.stdout)
    if not isinstance(probe_out, dict):
        raise ValueError("clean_venv: probe returned non-object JSON")
    packaged_modules = probe_out.get("packaged_modules")
    if packaged_modules != expected_modules:
        raise ValueError("clean_venv: packaged_modules mismatch")
    schema_bundle_digest = _require_sha256_digest(
        probe_out.get("schema_bundle_digest"), "clean_venv.schema_bundle_digest"
    )

    return {
        "wheel_digest": wheel_digest,
        "schema_bundle_digest": schema_bundle_digest,
        "sorted_record_entries": sorted_record_entries,
        "sorted_record_digest": sorted_record_digest,
        "archive_allowlist_passed": True,
        "ast_boundary_scan_passed": True,
        "isolated_venv_import_passed": True,
        "packaged_modules": packaged_modules,
    }


# ---------------------------------------------------------------------------
# P1 Envelope Integrity Helper
# ---------------------------------------------------------------------------


def _verify_envelope_integrity(envelope: dict[str, Any], *, label: str) -> None:
    integrity = envelope.get("integrity")
    if not isinstance(integrity, dict):
        raise ValueError(f"{label}.integrity: expected JSON object")
    keys = set(integrity.keys())
    if keys not in (_UNSIGNED_INTEGRITY_FIELDS, _SIGNED_INTEGRITY_FIELDS):
        raise ValueError(
            f"{label}.integrity: expected unsigned or signed P1 integrity fields"
        )
    _require_strict_str(integrity["key_id"], f"{label}.integrity.key_id")
    validate_locator(
        integrity["key_registry_snapshot_locator"], _KEY_REGISTRY_SCHEMA
    )
    if keys == _SIGNED_INTEGRITY_FIELDS:
        declared_digest = _require_sha256_digest(
            integrity["content_digest"], f"{label}.integrity.content_digest"
        )
        expected_digest = p1.content_digest(envelope)
        if declared_digest != expected_digest:
            raise ValueError(
                f"{label}.integrity.content_digest: mismatch against P1 preimage"
            )
        sig_b64 = integrity["signature_base64"]
        if type(sig_b64) is not str:
            raise ValueError(f"{label}.integrity.signature_base64: expected string")
        sig_bytes = p1._strict_base64_decode(sig_b64)
        if len(sig_bytes) != 64:
            raise ValueError(
                f"{label}.integrity.signature_base64: expected 64-byte Ed25519 signature"
            )


# ---------------------------------------------------------------------------
# `smart_ads/wheel_build_provenance/v1` Builders & Material Verifier
# ---------------------------------------------------------------------------


def _build_provenance_payload(
    *,
    migration_run_context_locator: dict[str, Any],
    build_run_id: str,
    built_at_utc: str,
    snapshot: GitBuildSnapshot,
    source_date_epoch: int,
    schema_bundle_digest: str,
    wheel_bytes: bytes,
    repository: str,
) -> dict[str, Any]:
    validate_locator(migration_run_context_locator, _RUN_CONTEXT_SCHEMA)
    _require_strict_str(build_run_id, "build_run_id")
    timestamp(built_at_utc)
    _require_exact_str(repository, DEFAULT_REPOSITORY, "repository")
    if not isinstance(snapshot, GitBuildSnapshot):
        raise ValueError("snapshot: expected GitBuildSnapshot")
    _require_safe_nonneg_int(source_date_epoch, "source_date_epoch", minimum=0)
    _require_sha256_digest(schema_bundle_digest, "schema_bundle_digest")
    wheel_obj = build_wheel_object_locator(wheel_bytes)
    payload = {
        "migration_run_context_locator": copy.deepcopy(migration_run_context_locator),
        "build_run_id": build_run_id,
        "built_at_utc": built_at_utc,
        "repository": repository,
        "source_commit_sha": snapshot.commit_sha,
        "source_tree_oid": snapshot.tree_oid,
        "source_date_epoch": source_date_epoch,
        "python_abi_tag": EXPECTED_PYTHON_ABI_TAG,
        "build_backend": snapshot.build_backend,
        "build_backend_version": snapshot.build_backend_version,
        "build_backend_digest": snapshot.build_backend_digest,
        "pyproject_sha256": snapshot.pyproject_sha256,
        "uv_lock_sha256": snapshot.uv_lock_sha256,
        "schema_bundle_digest": schema_bundle_digest,
        "wheel": wheel_obj,
        "wheel_digest": wheel_obj["wheel_digest"],
    }
    loads_strict(canonicalize(payload).decode("utf-8"))
    return payload


def build_wheel_build_provenance_envelope(
    *,
    migration_run_context_locator: dict[str, Any],
    build_run_id: str,
    built_at_utc: str,
    snapshot: GitBuildSnapshot,
    source_date_epoch: int,
    schema_bundle_digest: str,
    wheel_bytes: bytes,
    registry_locator: dict[str, Any],
    signer_key_id: str,
    repository: str = DEFAULT_REPOSITORY,
) -> dict[str, Any]:
    """Build an unsigned P1 `smart_ads/wheel_build_provenance/v1` envelope."""
    payload = _build_provenance_payload(
        migration_run_context_locator=migration_run_context_locator,
        build_run_id=build_run_id,
        built_at_utc=built_at_utc,
        snapshot=snapshot,
        source_date_epoch=source_date_epoch,
        schema_bundle_digest=schema_bundle_digest,
        wheel_bytes=wheel_bytes,
        repository=repository,
    )
    validate_locator(registry_locator, _KEY_REGISTRY_SCHEMA)
    _require_strict_str(signer_key_id, "signer_key_id")
    return {
        "$schema": WHEEL_BUILD_PROVENANCE_SCHEMA,
        **payload,
        "integrity": {
            "key_id": signer_key_id,
            "key_registry_snapshot_locator": copy.deepcopy(registry_locator),
        },
    }


def build_wheel_build_provenance_candidate(
    *,
    migration_run_context_locator: dict[str, Any],
    build_run_id: str,
    built_at_utc: str,
    snapshot: GitBuildSnapshot,
    source_date_epoch: int,
    schema_bundle_digest: str,
    wheel_bytes: bytes,
    repository: str = DEFAULT_REPOSITORY,
) -> dict[str, Any]:
    """Build a non-signable `gov1_local_candidate` for `wheel_build_provenance/v1`."""
    payload = _build_provenance_payload(
        migration_run_context_locator=migration_run_context_locator,
        build_run_id=build_run_id,
        built_at_utc=built_at_utc,
        snapshot=snapshot,
        source_date_epoch=source_date_epoch,
        schema_bundle_digest=schema_bundle_digest,
        wheel_bytes=wheel_bytes,
        repository=repository,
    )
    return wrap_local_candidate(WHEEL_BUILD_PROVENANCE_SCHEMA, payload)


def verify_wheel_build_provenance(
    artifact: dict[str, Any],
    *,
    repo_root: Path,
    wheel_path: Path,
    backend_wheel_dir: Path | None = None,
    site_packages_dir: Path | None = None,
) -> dict[str, Any]:
    """Materially verify `wheel_build_provenance/v1` by reconciling Git blobs and rebuilding the wheel."""
    if not isinstance(artifact, dict):
        raise ValueError("verify_wheel_build_provenance: artifact must be a JSON object")

    if artifact.get("artifact_kind") == LOCAL_CANDIDATE_KIND:
        if "$schema" in artifact or "integrity" in artifact:
            raise ValueError(
                "verify_wheel_build_provenance: local candidate must not contain envelope fields"
            )
        payload = unwrap_local_candidate(
            artifact, expected_schema=WHEEL_BUILD_PROVENANCE_SCHEMA
        )
        mode = "candidate"
    elif (
        artifact.get("$schema") == WHEEL_BUILD_PROVENANCE_SCHEMA
        and "artifact_kind" not in artifact
    ):
        exact_fields(
            artifact, _PROVENANCE_ENVELOPE_FIELDS, "wheel_build_provenance_envelope"
        )
        _verify_envelope_integrity(artifact, label="wheel_build_provenance")
        payload = {
            k: copy.deepcopy(v)
            for k, v in artifact.items()
            if k not in {"$schema", "integrity"}
        }
        mode = "envelope"
    else:
        raise ValueError(
            "verify_wheel_build_provenance: expected wheel_build_provenance/v1 envelope or gov1_local_candidate"
        )

    exact_fields(payload, _PROVENANCE_PAYLOAD_FIELDS, "wheel_build_provenance_payload")
    validate_locator(payload["migration_run_context_locator"], _RUN_CONTEXT_SCHEMA)
    _require_strict_str(payload["build_run_id"], "provenance.build_run_id")
    timestamp(payload["built_at_utc"])
    _require_exact_str(
        payload["repository"], DEFAULT_REPOSITORY, "provenance.repository"
    )
    source_commit_sha = _require_git_oid(
        payload["source_commit_sha"], "provenance.source_commit_sha"
    )
    source_tree_oid = _require_git_oid(
        payload["source_tree_oid"], "provenance.source_tree_oid"
    )
    source_date_epoch = _require_safe_nonneg_int(
        payload["source_date_epoch"], "provenance.source_date_epoch", minimum=0
    )
    _require_exact_str(
        payload["python_abi_tag"],
        EXPECTED_PYTHON_ABI_TAG,
        "provenance.python_abi_tag",
    )
    _require_exact_str(
        payload["build_backend"],
        EXPECTED_BUILD_BACKEND,
        "provenance.build_backend",
    )
    _require_exact_str(
        payload["build_backend_version"],
        EXPECTED_BUILD_BACKEND_VERSION,
        "provenance.build_backend_version",
    )
    _require_sha256_digest(
        payload["build_backend_digest"], "provenance.build_backend_digest"
    )
    _require_sha256_digest(payload["pyproject_sha256"], "provenance.pyproject_sha256")
    _require_sha256_digest(payload["uv_lock_sha256"], "provenance.uv_lock_sha256")
    _require_sha256_digest(
        payload["schema_bundle_digest"], "provenance.schema_bundle_digest"
    )
    declared_wheel_digest = _require_sha256_digest(
        payload["wheel_digest"], "provenance.wheel_digest"
    )

    whl_file = Path(wheel_path)
    if whl_file.is_symlink() or not whl_file.is_file():
        raise ValueError(f"wheel_path: expected regular non-symlink file at {whl_file}")
    wheel_bytes = whl_file.read_bytes()
    verify_wheel_object_locator(payload["wheel"], expected_wheel_bytes=wheel_bytes)
    if payload["wheel"]["wheel_digest"] != declared_wheel_digest:
        raise ValueError("provenance: wheel.wheel_digest != wheel_digest")

    inspection = inspect_wheel_boundary(whl_file)
    if inspection["wheel_digest"] != declared_wheel_digest:
        raise ValueError("provenance: wheel_digest mismatch against wheel_path")
    if inspection["schema_bundle_digest"] != payload["schema_bundle_digest"]:
        raise ValueError(
            "provenance: schema_bundle_digest mismatch against isolated wheel import"
        )

    members, _, _, _ = _read_and_validate_wheel_archive(wheel_bytes)
    snapshot = materialize_git_build_snapshot(
        repo_root,
        commit_ref=source_commit_sha,
        site_packages_dir=site_packages_dir,
        backend_wheel_dir=backend_wheel_dir,
    )
    if snapshot.commit_sha != source_commit_sha or snapshot.tree_oid != source_tree_oid:
        raise ValueError(
            "provenance: source_commit_sha or source_tree_oid mismatch against Git object store"
        )
    if snapshot.pyproject_sha256 != payload["pyproject_sha256"]:
        raise ValueError("provenance: pyproject_sha256 mismatch against source_commit_sha")
    if snapshot.uv_lock_sha256 != payload["uv_lock_sha256"]:
        raise ValueError("provenance: uv_lock_sha256 mismatch against source_commit_sha")
    if snapshot.build_backend_digest != payload["build_backend_digest"]:
        raise ValueError(
            "provenance: build_backend_digest mismatch against executed PEP 517 closure"
        )

    # 1. Byte-for-byte reconciliation of every smart_ads/**/*.py member against Git commit blobs
    wheel_py_members = {p: b for p, b in members.items() if p.endswith(".py")}
    git_py_blobs = {
        p[len("src/") :]: b
        for p, b in snapshot.files.items()
        if p.startswith("src/smart_ads/") and p.endswith(".py")
    }
    if set(wheel_py_members.keys()) != set(git_py_blobs.keys()):
        raise ValueError(
            "provenance: .py member set in wheel diverges from src/smart_ads/**/*.py at source_commit_sha"
        )
    for rel_mod_path, mod_bytes in wheel_py_members.items():
        if mod_bytes != git_py_blobs[rel_mod_path]:
            raise ValueError(
                f"provenance: byte mismatch between wheel member {rel_mod_path!r} "
                f"and Git blob 'src/{rel_mod_path}' at {source_commit_sha}"
            )

    # 2. Full hermetic rebuild from source_commit_sha and source_date_epoch
    with tempfile.TemporaryDirectory(prefix="gov1-prov-rebuild-") as tmp_out:
        rebuilt_wheel_path, _ = build_reproducible_wheel(
            repo_root,
            Path(tmp_out) / "dist",
            commit_ref=source_commit_sha,
            source_date_epoch=source_date_epoch,
            backend_wheel_dir=backend_wheel_dir,
            site_packages_dir=site_packages_dir,
        )
        rebuilt_bytes = rebuilt_wheel_path.read_bytes()

    if rebuilt_bytes != wheel_bytes:
        raise ValueError(
            "provenance: rebuilt wheel bytes from source_commit_sha do not match wheel_path bytes"
        )

    return {
        "mode": mode,
        "schema": WHEEL_BUILD_PROVENANCE_SCHEMA,
        "wheel_digest": declared_wheel_digest,
        "source_commit_sha": source_commit_sha,
        "build_backend_digest": payload["build_backend_digest"],
        "schema_bundle_digest": payload["schema_bundle_digest"],
        "payload": copy.deepcopy(payload),
    }


# ---------------------------------------------------------------------------
# `smart_ads/wheel_boundary_report/v1` Builders & Material Verifier
# ---------------------------------------------------------------------------


def _validate_sorted_record_entries(entries: object, label: str) -> list[dict[str, Any]]:
    if type(entries) is not list or len(entries) == 0:
        raise ValueError(f"{label}: expected non-empty list")
    seen_paths: list[str] = []
    found_self = False
    for idx, item in enumerate(entries):
        exact_fields(
            item, {"path", "record_hash", "record_size"}, f"{label}[{idx}]"
        )
        p = source_path(item["path"])
        if _WHEEL_ALLOWLIST_RE.fullmatch(p) is None:
            raise ValueError(f"{label}[{idx}].path: violates allowlist: {p!r}")
        seen_paths.append(p)
        if p == EXPECTED_SELF_RECORD_PATH:
            _require_exact_str(item["record_hash"], "", f"{label}[{idx}].record_hash")
            if item["record_size"] is not None:
                raise ValueError(
                    f"{label}[{idx}].record_size: self RECORD entry must have record_size=None"
                )
            found_self = True
        else:
            r_hash = _require_strict_str(
                item["record_hash"], f"{label}[{idx}].record_hash"
            )
            if not r_hash.startswith("sha256="):
                raise ValueError(
                    f"{label}[{idx}].record_hash: expected 'sha256=<urlsafe_b64>'"
                )
            _require_safe_nonneg_int(
                item["record_size"], f"{label}[{idx}].record_size", minimum=0
            )
    if not found_self:
        raise ValueError(f"{label}: missing {EXPECTED_SELF_RECORD_PATH!r} entry")
    if len(set(seen_paths)) != len(seen_paths):
        raise ValueError(f"{label}: duplicate paths in sorted_record_entries")
    if seen_paths != sorted(seen_paths, key=lambda s: s.encode("utf-8")):
        raise ValueError(f"{label}: entries must be sorted by UTF-8 path bytes")
    return copy.deepcopy(entries)


def _validate_inspection_dict(inspection: dict[str, Any]) -> dict[str, Any]:
    exact_fields(inspection, _INSPECTION_FIELDS, "inspection")
    whl_digest = _require_sha256_digest(
        inspection["wheel_digest"], "inspection.wheel_digest"
    )
    schema_digest = _require_sha256_digest(
        inspection["schema_bundle_digest"], "inspection.schema_bundle_digest"
    )
    entries = _validate_sorted_record_entries(
        inspection["sorted_record_entries"], "inspection.sorted_record_entries"
    )
    rec_digest = _require_sha256_digest(
        inspection["sorted_record_digest"], "inspection.sorted_record_digest"
    )
    if rec_digest != json_digest(entries):
        raise ValueError(
            "inspection.sorted_record_digest: mismatch against sorted_record_entries"
        )
    _require_exact_bool(
        inspection["archive_allowlist_passed"],
        True,
        "inspection.archive_allowlist_passed",
    )
    _require_exact_bool(
        inspection["ast_boundary_scan_passed"],
        True,
        "inspection.ast_boundary_scan_passed",
    )
    _require_exact_bool(
        inspection["isolated_venv_import_passed"],
        True,
        "inspection.isolated_venv_import_passed",
    )
    expected_mods = sorted(
        EXPECTED_PACKAGED_MODULES, key=lambda s: s.encode("utf-8")
    )
    mods = inspection["packaged_modules"]
    if (
        type(mods) is not list
        or any(type(m) is not str for m in mods)
        or mods != expected_mods
    ):
        raise ValueError(
            "inspection.packaged_modules: expected exact sorted 24 packaged modules"
        )
    return {
        "wheel_digest": whl_digest,
        "schema_bundle_digest": schema_digest,
        "sorted_record_entries": entries,
        "sorted_record_digest": rec_digest,
        "archive_allowlist_passed": True,
        "ast_boundary_scan_passed": True,
        "isolated_venv_import_passed": True,
        "packaged_modules": list(mods),
    }


def _build_boundary_common_payload(
    *,
    migration_run_context_locator: dict[str, Any],
    build_run_id: str,
    verified_at_utc: str,
    source_commit_sha: str,
    build_backend_digest: str,
    inspection: dict[str, Any],
    repository: str,
) -> dict[str, Any]:
    validate_locator(migration_run_context_locator, _RUN_CONTEXT_SCHEMA)
    _require_strict_str(build_run_id, "build_run_id")
    timestamp(verified_at_utc)
    _require_exact_str(repository, DEFAULT_REPOSITORY, "repository")
    _require_git_oid(source_commit_sha, "source_commit_sha")
    _require_sha256_digest(build_backend_digest, "build_backend_digest")
    checked_insp = _validate_inspection_dict(inspection)
    return {
        "migration_run_context_locator": copy.deepcopy(migration_run_context_locator),
        "build_run_id": build_run_id,
        "verified_at_utc": verified_at_utc,
        "repository": repository,
        "source_commit_sha": source_commit_sha,
        "wheel_digest": checked_insp["wheel_digest"],
        "build_backend_digest": build_backend_digest,
        "schema_bundle_digest": checked_insp["schema_bundle_digest"],
        "sorted_record_entries": checked_insp["sorted_record_entries"],
        "sorted_record_digest": checked_insp["sorted_record_digest"],
        "archive_allowlist_passed": True,
        "ast_boundary_scan_passed": True,
        "isolated_venv_import_passed": True,
        "packaged_modules": checked_insp["packaged_modules"],
    }


def build_wheel_boundary_report_envelope(
    *,
    migration_run_context_locator: dict[str, Any],
    build_run_id: str,
    verified_at_utc: str,
    source_commit_sha: str,
    build_backend_digest: str,
    wheel_build_provenance_locator: dict[str, Any],
    inspection: dict[str, Any],
    registry_locator: dict[str, Any],
    signer_key_id: str,
    repository: str = DEFAULT_REPOSITORY,
) -> dict[str, Any]:
    """Build an unsigned P1 `smart_ads/wheel_boundary_report/v1` envelope."""
    validate_locator(wheel_build_provenance_locator, WHEEL_BUILD_PROVENANCE_SCHEMA)
    validate_locator(registry_locator, _KEY_REGISTRY_SCHEMA)
    _require_strict_str(signer_key_id, "signer_key_id")
    common = _build_boundary_common_payload(
        migration_run_context_locator=migration_run_context_locator,
        build_run_id=build_run_id,
        verified_at_utc=verified_at_utc,
        source_commit_sha=source_commit_sha,
        build_backend_digest=build_backend_digest,
        inspection=inspection,
        repository=repository,
    )
    envelope = {
        "$schema": WHEEL_BOUNDARY_REPORT_SCHEMA,
        **common,
        "wheel_build_provenance_locator": copy.deepcopy(
            wheel_build_provenance_locator
        ),
        "integrity": {
            "key_id": signer_key_id,
            "key_registry_snapshot_locator": copy.deepcopy(registry_locator),
        },
    }
    loads_strict(canonicalize(envelope).decode("utf-8"))
    return envelope


def build_wheel_boundary_report_candidate(
    *,
    migration_run_context_locator: dict[str, Any],
    build_run_id: str,
    verified_at_utc: str,
    source_commit_sha: str,
    build_backend_digest: str,
    wheel_build_provenance_candidate_ref: dict[str, Any],
    inspection: dict[str, Any],
    repository: str = DEFAULT_REPOSITORY,
) -> dict[str, Any]:
    """Build a non-signable `gov1_local_candidate` for `wheel_boundary_report/v1`."""
    verify_local_candidate_ref(
        wheel_build_provenance_candidate_ref,
        expected_schema=WHEEL_BUILD_PROVENANCE_SCHEMA,
    )
    common = _build_boundary_common_payload(
        migration_run_context_locator=migration_run_context_locator,
        build_run_id=build_run_id,
        verified_at_utc=verified_at_utc,
        source_commit_sha=source_commit_sha,
        build_backend_digest=build_backend_digest,
        inspection=inspection,
        repository=repository,
    )
    payload = {
        **common,
        "wheel_build_provenance_candidate_ref": copy.deepcopy(
            wheel_build_provenance_candidate_ref
        ),
    }
    return wrap_local_candidate(WHEEL_BOUNDARY_REPORT_SCHEMA, payload)


def verify_wheel_boundary_report(
    artifact: dict[str, Any], *, wheel_path: Path
) -> dict[str, Any]:
    """Materially verify `wheel_boundary_report/v1` by re-running `inspect_wheel_boundary`."""
    if not isinstance(artifact, dict):
        raise ValueError("verify_wheel_boundary_report: artifact must be a JSON object")

    if artifact.get("artifact_kind") == LOCAL_CANDIDATE_KIND:
        if "$schema" in artifact or "integrity" in artifact:
            raise ValueError(
                "verify_wheel_boundary_report: local candidate must not contain envelope fields"
            )
        payload = unwrap_local_candidate(
            artifact, expected_schema=WHEEL_BOUNDARY_REPORT_SCHEMA
        )
        exact_fields(
            payload,
            _BOUNDARY_CANDIDATE_PAYLOAD_FIELDS,
            "wheel_boundary_report_candidate_payload",
        )
        verify_local_candidate_ref(
            payload["wheel_build_provenance_candidate_ref"],
            expected_schema=WHEEL_BUILD_PROVENANCE_SCHEMA,
        )
        mode = "candidate"
    elif (
        artifact.get("$schema") == WHEEL_BOUNDARY_REPORT_SCHEMA
        and "artifact_kind" not in artifact
    ):
        exact_fields(
            artifact, _BOUNDARY_ENVELOPE_FIELDS, "wheel_boundary_report_envelope"
        )
        _verify_envelope_integrity(artifact, label="wheel_boundary_report")
        payload = {
            k: copy.deepcopy(v)
            for k, v in artifact.items()
            if k not in {"$schema", "integrity"}
        }
        exact_fields(
            payload,
            _BOUNDARY_ENVELOPE_PAYLOAD_FIELDS,
            "wheel_boundary_report_envelope_payload",
        )
        validate_locator(
            payload["wheel_build_provenance_locator"], WHEEL_BUILD_PROVENANCE_SCHEMA
        )
        mode = "envelope"
    else:
        raise ValueError(
            "verify_wheel_boundary_report: expected wheel_boundary_report/v1 envelope or gov1_local_candidate"
        )

    validate_locator(payload["migration_run_context_locator"], _RUN_CONTEXT_SCHEMA)
    _require_strict_str(payload["build_run_id"], "boundary_report.build_run_id")
    timestamp(payload["verified_at_utc"])
    _require_exact_str(
        payload["repository"], DEFAULT_REPOSITORY, "boundary_report.repository"
    )
    _require_git_oid(
        payload["source_commit_sha"], "boundary_report.source_commit_sha"
    )
    _require_sha256_digest(
        payload["build_backend_digest"], "boundary_report.build_backend_digest"
    )

    declared_inspection = _validate_inspection_dict(
        {k: payload[k] for k in _INSPECTION_FIELDS}
    )
    live_inspection = inspect_wheel_boundary(wheel_path)
    if canonicalize(declared_inspection) != canonicalize(live_inspection):
        raise ValueError(
            "verify_wheel_boundary_report: declared report diverges from live wheel boundary inspection"
        )

    return {
        "mode": mode,
        "schema": WHEEL_BOUNDARY_REPORT_SCHEMA,
        "wheel_digest": live_inspection["wheel_digest"],
        "schema_bundle_digest": live_inspection["schema_bundle_digest"],
        "sorted_record_digest": live_inspection["sorted_record_digest"],
        "payload": copy.deepcopy(payload),
    }
