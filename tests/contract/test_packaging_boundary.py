from __future__ import annotations

import ast
import hashlib
import io
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tomllib
import venv
import zipfile
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_SMART_ADS = REPO_ROOT / "src" / "smart_ads"
PYPROJECT_PATH = REPO_ROOT / "pyproject.toml"
UV_LOCK_PATH = REPO_ROOT / "uv.lock"
PYTEST_WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "pytest.yml"

EXPECTED_PR1_SUBPACKAGES = frozenset(
    {"contracts", "domain", "ports", "application"}
)
EXPECTED_PACKAGED_MODULES = frozenset(
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
    }
)

WHEEL_ALLOWLIST_RE = re.compile(
    r"^(smart_ads(/[a-z0-9_]+)+\.py|smart_ads-0\.1\.0\.dist-info/(METADATA|WHEEL|RECORD))$"
)
SDIST_ALLOWLIST_RE = re.compile(
    r"^smart_ads-0\.1\.0/(PKG-INFO|pyproject\.toml|src/smart_ads(/[a-z0-9_]+)+\.py)$"
)

# Tier 1 (wheel-wide across ALL src/smart_ads/**/*.py): zero tooling & zero dynamic execution/import
WHEEL_WIDE_FORBIDDEN_TOP_IMPORTS = frozenset(
    {"tools", "tooling", "importlib", "runpy", "builtins", "ctypes"}
)
WHEEL_WIDE_FORBIDDEN_DYNAMIC_NAMES = frozenset(
    {"__import__", "builtins", "eval", "exec", "compile"}
)

# Tier 2 (pure layers: contracts, domain, ports, application, analytics, reconciliation + root __init__.py)
PURE_LAYER_SUBPACKAGES = frozenset(
    {
        "contracts",
        "domain",
        "ports",
        "application",
        "analytics",
        "reconciliation",
    }
)
PURE_LAYER_ALLOWED_TOP_IMPORTS = frozenset(
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
PURE_LAYER_FORBIDDEN_FILE_ATTRS = frozenset(
    {"open", "read_bytes", "read_text", "write_bytes", "write_text"}
)
PURE_LAYER_FORBIDDEN_AMBIENT_TIME_ATTRS = frozenset(
    {
        "now",
        "utcnow",
        "today",
        "fromtimestamp",
        "utcfromtimestamp",
        "astimezone",
    }
)
WINDOWS_ONLY_MARKERS = frozenset(
    {"os_name == 'nt'", "sys_platform == 'win32'"}
)


def scan_wheel_wide_ast_violations(
    source: str, *, filename: str = "<snippet>"
) -> list[str]:
    """Scan Python source for wheel-wide forbidden tooling or dynamic import/exec constructs."""
    tree = ast.parse(source, filename=filename)
    violations: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname == "re" and alias.name != "re":
                    violations.append(
                        f"{filename}:{node.lineno}: forbidden import alias 're' for {alias.name!r}"
                    )
                top = alias.name.split(".")[0]
                if top in WHEEL_WIDE_FORBIDDEN_TOP_IMPORTS:
                    violations.append(
                        f"{filename}:{node.lineno}: forbidden wheel-wide import {alias.name!r}"
                    )
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                top = node.module.split(".")[0]
                if top in WHEEL_WIDE_FORBIDDEN_TOP_IMPORTS:
                    violations.append(
                        f"{filename}:{node.lineno}: forbidden wheel-wide from-import {node.module!r}"
                    )
            for alias in node.names:
                if alias.name in WHEEL_WIDE_FORBIDDEN_DYNAMIC_NAMES:
                    violations.append(
                        f"{filename}:{node.lineno}: forbidden wheel-wide imported symbol {alias.name!r}"
                    )
                if alias.asname == "re":
                    violations.append(
                        f"{filename}:{node.lineno}: forbidden shadowing alias 're'"
                    )
                if (
                    alias.asname is not None
                    and alias.asname in WHEEL_WIDE_FORBIDDEN_DYNAMIC_NAMES
                ):
                    violations.append(
                        f"{filename}:{node.lineno}: forbidden wheel-wide alias {alias.asname!r}"
                    )
        elif isinstance(node, ast.Name):
            if node.id == "re" and isinstance(node.ctx, (ast.Store, ast.Del)):
                violations.append(
                    f"{filename}:{node.lineno}: forbidden rebinding of 're'"
                )
            if node.id in WHEEL_WIDE_FORBIDDEN_DYNAMIC_NAMES:
                violations.append(
                    f"{filename}:{node.lineno}: forbidden dynamic builtin name {node.id!r}"
                )
        elif isinstance(node, ast.Attribute):
            if node.attr in WHEEL_WIDE_FORBIDDEN_DYNAMIC_NAMES:
                is_stdlib_re_compile = (
                    node.attr == "compile"
                    and isinstance(node.value, ast.Name)
                    and node.value.id == "re"
                )
                if not is_stdlib_re_compile:
                    violations.append(
                        f"{filename}:{node.lineno}: forbidden dynamic attribute {node.attr!r}"
                    )
    return violations


def scan_pure_layer_ast_violations(
    source: str, *, filename: str = "<snippet>"
) -> list[str]:
    """Scan Python source in pure layers for closed stdlib allowlist, zero file I/O, and zero ambient clock/tz."""
    violations = list(
        scan_wheel_wide_ast_violations(source, filename=filename)
    )
    tree = ast.parse(source, filename=filename)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                if top not in PURE_LAYER_ALLOWED_TOP_IMPORTS:
                    violations.append(
                        f"{filename}:{node.lineno}: import {alias.name!r} outside closed pure-layer allowlist"
                    )
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0:
                if not node.module:
                    violations.append(
                        f"{filename}:{node.lineno}: empty absolute from-import module"
                    )
                else:
                    top = node.module.split(".")[0]
                    if top not in PURE_LAYER_ALLOWED_TOP_IMPORTS:
                        violations.append(
                            f"{filename}:{node.lineno}: from-import {node.module!r} outside closed pure-layer allowlist"
                        )
            for alias in node.names:
                if (
                    alias.name == "open"
                    or alias.asname == "open"
                    or alias.name in PURE_LAYER_FORBIDDEN_FILE_ATTRS
                    or alias.name in PURE_LAYER_FORBIDDEN_AMBIENT_TIME_ATTRS
                ):
                    violations.append(
                        f"{filename}:{node.lineno}: forbidden pure-layer imported symbol {alias.name!r}"
                    )
        elif isinstance(node, ast.Name):
            if node.id == "open":
                violations.append(
                    f"{filename}:{node.lineno}: forbidden pure-layer file builtin 'open'"
                )
        elif isinstance(node, ast.Attribute):
            if node.attr in PURE_LAYER_FORBIDDEN_FILE_ATTRS:
                violations.append(
                    f"{filename}:{node.lineno}: forbidden pure-layer file I/O attribute {node.attr!r}"
                )
            if node.attr in PURE_LAYER_FORBIDDEN_AMBIENT_TIME_ATTRS:
                violations.append(
                    f"{filename}:{node.lineno}: forbidden ambient clock/timezone attribute {node.attr!r}"
                )
    return violations


def validate_sdist_archive_members(sdist_path: Path) -> list[str]:
    """Verify every non-directory tar member is a regular file matching SDIST_ALLOWLIST_RE."""
    regular_files: list[str] = []
    with tarfile.open(sdist_path, "r:gz") as tf:
        for member in tf.getmembers():
            if member.isdir():
                continue
            assert member.isfile(), f"Non-regular tar member: {member.name}"
            assert SDIST_ALLOWLIST_RE.fullmatch(member.name), (
                f"Forbidden sdist member: {member.name}"
            )
            regular_files.append(member.name)
    return sorted(regular_files)


def build_linux_locked_dev_requirements(
    pyproject_data: dict[str, Any],
    lock_data: dict[str, Any],
) -> list[str]:
    """Validate pyproject.toml <-> uv.lock sync and emit hash-pinned Linux dev requirements."""
    assert pyproject_data["project"]["dependencies"] == [], (
        "smart-ads runtime dependencies must remain empty"
    )
    build_requires = set(pyproject_data["build-system"]["requires"])
    dev_group = set(pyproject_data["dependency-groups"]["dev"])
    assert build_requires, "build-system.requires must be non-empty"
    assert build_requires.issubset(dev_group), (
        "build-system.requires must be pinned inside dependency-groups.dev"
    )

    packages_by_name: dict[str, dict[str, Any]] = {}
    for pkg in lock_data["package"]:
        name = pkg["name"]
        assert name not in packages_by_name, f"Duplicate package in uv.lock: {name}"
        packages_by_name[name] = pkg

    root_pkg = packages_by_name["smart-ads"]
    assert root_pkg.get("source") == {"editable": "."}
    locked_requires_dev = {
        f"{entry['name']}{entry['specifier']}"
        for entry in root_pkg["metadata"]["requires-dev"]["dev"]
    }
    assert dev_group == locked_requires_dev, (
        f"pyproject dev group {sorted(dev_group)} != uv.lock {sorted(locked_requires_dev)}"
    )

    # Every non-editable package in uv.lock MUST carry sha256 wheel hashes
    for name, pkg in packages_by_name.items():
        if pkg.get("source") == {"editable": "."}:
            continue
        wheels = pkg.get("wheels", [])
        assert wheels, f"Locked package {name!r} has no wheels in uv.lock"
        for wheel in wheels:
            wheel_hash = wheel.get("hash", "")
            assert re.fullmatch(r"sha256:[0-9a-f]{64}", wheel_hash), (
                f"Invalid wheel sha256 hash on {name!r}: {wheel_hash!r}"
            )

    # Traverse Linux-applicable dependency graph from smart-ads dev-dependencies
    queue: list[str] = [
        dep["name"]
        for dep in root_pkg["dev-dependencies"]["dev"]
        if dep.get("marker") not in WINDOWS_ONLY_MARKERS
    ]
    selected: set[str] = set()
    while queue:
        curr = queue.pop()
        if curr in selected:
            continue
        pkg = packages_by_name[curr]
        if pkg.get("source") == {"editable": "."}:
            continue
        selected.add(curr)
        for dep in pkg.get("dependencies", []):
            if dep.get("marker") in WINDOWS_ONLY_MARKERS:
                continue
            queue.append(dep["name"])

    lines: list[str] = []
    for name in sorted(selected):
        pkg = packages_by_name[name]
        wheel_hashes = sorted(
            {w["hash"] for w in pkg["wheels"]}
        )
        hash_flags = " ".join(f"--hash={h}" for h in wheel_hashes)
        lines.append(f"{name}=={pkg['version']} {hash_flags}")
    return lines


def _stage_clean_tree(dest: Path) -> Path:
    staged = dest / "repo"
    staged.mkdir(parents=True)
    shutil.copy2(REPO_ROOT / "pyproject.toml", staged / "pyproject.toml")
    shutil.copytree(
        REPO_ROOT / "src",
        staged / "src",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.egg-info"),
    )
    # Plant decoys that MUST be excluded from both wheel and sdist (ADR-0001 §10 L2298)
    (staged / "README.md").write_text("# Decoy README\n", encoding="utf-8")
    (staged / "LICENSE").write_text("Decoy LICENSE\n", encoding="utf-8")
    (staged / "GLOSSARY.md").write_text("# Decoy GLOSSARY\n", encoding="utf-8")
    (staged / "MIGRATION_DECOMPOSITION_MANIFEST.json").write_text("{}\n", encoding="utf-8")
    (staged / "tools").mkdir()
    (staged / "tools" / "decoy.py").write_text("X = 1\n", encoding="utf-8")
    (staged / "tooling").mkdir()
    (staged / "tooling" / "decoy.py").write_text("X = 1\n", encoding="utf-8")
    (staged / "tests").mkdir()
    (staged / "tests" / "test_decoy.py").write_text("def test_x(): pass\n", encoding="utf-8")
    (staged / "docs").mkdir()
    (staged / "docs" / "decoy.md").write_text("doc\n", encoding="utf-8")
    return staged


def _build_distributions(staged_repo: Path, out_dir: Path) -> tuple[Path, Path]:
    env = dict(os.environ)
    env["SOURCE_DATE_EPOCH"] = "1700000000"
    subprocess.run(
        [
            sys.executable,
            "-m",
            "build",
            "--no-isolation",
            "--outdir",
            str(out_dir),
            str(staged_repo),
        ],
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    wheels = list(out_dir.glob("*.whl"))
    sdists = list(out_dir.glob("*.tar.gz"))
    assert len(wheels) == 1
    assert len(sdists) == 1
    return wheels[0], sdists[0]


def test_pr1_inhabited_top_level_subpackages_exact_set() -> None:
    inhabited_dirs = {
        entry.name
        for entry in SRC_SMART_ADS.iterdir()
        if entry.is_dir() and entry.name != "__pycache__"
    }
    assert inhabited_dirs == EXPECTED_PR1_SUBPACKAGES


def test_wheel_and_sdist_strict_allowlist_and_reproducibility(tmp_path: Path) -> None:
    staged_a = _stage_clean_tree(tmp_path / "a")
    staged_b = _stage_clean_tree(tmp_path / "b")
    whl_a, sdist_a = _build_distributions(staged_a, tmp_path / "out_a")
    whl_b, sdist_b = _build_distributions(staged_b, tmp_path / "out_b")

    assert (
        hashlib.sha256(whl_a.read_bytes()).hexdigest()
        == hashlib.sha256(whl_b.read_bytes()).hexdigest()
    )
    assert (
        hashlib.sha256(sdist_a.read_bytes()).hexdigest()
        == hashlib.sha256(sdist_b.read_bytes()).hexdigest()
    )

    with zipfile.ZipFile(whl_a) as zf:
        wheel_members = sorted(zf.namelist())
    assert "smart_ads/__init__.py" in wheel_members
    for member in wheel_members:
        assert WHEEL_ALLOWLIST_RE.fullmatch(member), f"Forbidden wheel member: {member}"

    sdist_files = validate_sdist_archive_members(sdist_a)
    assert "smart_ads-0.1.0/src/smart_ads/__init__.py" in sdist_files

    # Verify non-regular tar members (e.g., symlinks) are rejected
    bad_tar = tmp_path / "symlink_sdist.tar.gz"
    with tarfile.open(bad_tar, "w:gz") as tf:
        reg_info = tarfile.TarInfo("smart_ads-0.1.0/pyproject.toml")
        payload = b"[project]\nname = 'smart-ads'\n"
        reg_info.size = len(payload)
        tf.addfile(reg_info, io.BytesIO(payload))

        sym_info = tarfile.TarInfo("smart_ads-0.1.0/src/smart_ads/leak.py")
        sym_info.type = tarfile.SYMTYPE
        sym_info.linkname = "/etc/passwd"
        tf.addfile(sym_info)

    with pytest.raises(AssertionError, match="Non-regular tar member"):
        validate_sdist_archive_members(bad_tar)


def test_clean_venv_outside_repo_isolated_import(tmp_path: Path) -> None:
    staged = _stage_clean_tree(tmp_path / "build_src")
    whl_path, _ = _build_distributions(staged, tmp_path / "dist")

    venv_dir = tmp_path / "clean_venv"
    venv.EnvBuilder(with_pip=False, clear=True, symlinks=os.name != "nt").create(venv_dir)
    venv_python = venv_dir / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    purelib = subprocess.check_output(
        [
            str(venv_python),
            "-I",
            "-c",
            "import sysconfig; print(sysconfig.get_path('purelib'))",
        ],
        text=True,
    ).strip()
    with zipfile.ZipFile(whl_path) as zf:
        zf.extractall(purelib)

    expected_mods_literal = repr(sorted(EXPECTED_PACKAGED_MODULES))
    repo_root_literal = repr(str(REPO_ROOT))
    repo_src_literal = repr(str(REPO_ROOT / "src"))

    probe = (
        "import importlib, importlib.metadata as m, os, pkgutil, sys\n"
        "import smart_ads\n"
        f"expected = {expected_mods_literal}\n"
        f"forbidden_paths = {{os.path.abspath('.'), os.path.abspath('src'), {repo_root_literal}, {repo_src_literal}}}\n"
        "actual_paths = {os.path.abspath(p) for p in sys.path if p != ''}\n"
        "assert not (actual_paths & forbidden_paths), f'Repo path leaked into sys.path: {actual_paths & forbidden_paths}'\n"
        "assert '' not in sys.path\n"
        "assert smart_ads.__version__ == '0.1.0'\n"
        "assert not m.requires('smart-ads')\n"
        "walked = {'smart_ads'}\n"
        "for mod_info in pkgutil.walk_packages(smart_ads.__path__, prefix='smart_ads.'):\n"
        "    importlib.import_module(mod_info.name)\n"
        "    walked.add(mod_info.name)\n"
        "assert sorted(walked) == expected, f'Walked mismatch: {sorted(walked)} != {expected}'\n"
        "for mod_name in expected:\n"
        "    assert mod_name in sys.modules, f'Missing module in sys.modules: {mod_name}'\n"
        "from smart_ads.contracts import canonicalize_jcs, validate_resource_ref\n"
        "from smart_ads.domain import TenantResourceKeyHandle, derive_resource_ref\n"
        "from smart_ads.ports import ExternalIOCounters\n"
        "assert canonicalize_jcs({'b': 1, 'a': 2}) == b'{\"a\":2,\"b\":1}'\n"
        "kh = TenantResourceKeyHandle('tenant:ibvi', 'key:ibvi-v1', b'0123456789abcdef0123456789abcdef')\n"
        "rref = derive_resource_ref(key_handle=kh, mapping_version='hmac-sha256-b32-v1', domain_separator='0x00', ad_platform_ref='meta', resource_level='campaign', raw_provider_id='123')\n"
        "assert validate_resource_ref(rref) == rref\n"
        "assert ExternalIOCounters.zero().is_zero is True\n"
        "for mod in ('tools', 'tooling'):\n"
        "    try:\n"
        "        __import__(mod)\n"
        "    except ModuleNotFoundError:\n"
        "        pass\n"
        "    else:\n"
        "        raise AssertionError(f'{mod} unexpectedly importable')\n"
    )
    subprocess.run(
        [str(venv_python), "-I", "-c", probe],
        cwd=str(tmp_path),
        check=True,
        capture_output=True,
        text=True,
    )


def test_ast_zero_io_and_zero_tooling_imports_in_src() -> None:
    py_files = sorted(SRC_SMART_ADS.rglob("*.py"))
    assert len(py_files) == len(EXPECTED_PACKAGED_MODULES)

    for path in py_files:
        source = path.read_text(encoding="utf-8")
        rel_parts = path.relative_to(SRC_SMART_ADS).parts
        wheel_violations = scan_wheel_wide_ast_violations(
            source, filename=str(path)
        )
        assert not wheel_violations, "\n".join(wheel_violations)

        is_pure_layer = (
            len(rel_parts) == 1 and rel_parts[0] == "__init__.py"
        ) or (len(rel_parts) >= 2 and rel_parts[0] in PURE_LAYER_SUBPACKAGES)
        if is_pure_layer:
            pure_violations = scan_pure_layer_ast_violations(
                source, filename=str(path)
            )
            assert not pure_violations, "\n".join(pure_violations)


@pytest.mark.parametrize(
    "bad_snippet",
    [
        "import datetime\ndatetime.datetime.now(datetime.UTC)\n",
        "import datetime\ndatetime.date.today()\n",
        "from datetime import datetime as dt\ndt.now()\n",
        "from datetime import datetime\ndatetime.fromtimestamp(0)\n",
        "from datetime import datetime\ndatetime.utcfromtimestamp(0)\n",
        "def conv(dt):\n    return dt.astimezone()\n",
        "from os import getenv\n",
        "import os\nos.environ.get('X')\n",
        "from time import time\n",
        "import zoneinfo\n",
        "from io import open\n",
        "def f(p):\n    return open(p)\n",
        "def f(p):\n    return p.read_text()\n",
        "def f(p):\n    return p.read_bytes()\n",
        "import builtins\nbuiltins.__import__('tooling')\n",
        "fn = __import__\n",
        "compile('1+1', '<x>', 'eval')\n",
        "obj.compile('1+1')\n",
        "import ctypes\n",
        "import importlib\n",
        "import runpy\n",
        "import tools.governance.jcs\n",
        "from tooling import helper\n",
        "from builtins import eval as ev\n",
    ],
)
def test_ast_boundary_scanner_rejects_violating_snippets(bad_snippet: str) -> None:
    violations = scan_pure_layer_ast_violations(
        bad_snippet, filename="<synthetic>"
    )
    assert violations, f"Expected AST scanner to reject snippet:\n{bad_snippet}"
    assert not scan_pure_layer_ast_violations(
        "import re\nPAT = re.compile(r'^a+$')\n", filename="<ok>"
    )


def test_pyproject_uv_lock_and_ci_workflow_hash_pinning(tmp_path: Path) -> None:
    pyproject_data = tomllib.loads(PYPROJECT_PATH.read_text(encoding="utf-8"))
    lock_data = tomllib.loads(UV_LOCK_PATH.read_text(encoding="utf-8"))
    req_lines = build_linux_locked_dev_requirements(pyproject_data, lock_data)

    assert any(line.startswith("build==1.6.1 --hash=sha256:") for line in req_lines)
    assert any(line.startswith("hatchling==1.33.0 --hash=sha256:") for line in req_lines)
    assert any(line.startswith("pytest==9.2.0 --hash=sha256:") for line in req_lines)
    assert not any(line.startswith("colorama==") for line in req_lines)

    workflow_text = PYTEST_WORKFLOW_PATH.read_text(encoding="utf-8")
    uses_actions = re.findall(r"^\s*-\s*uses:\s*(\S+)", workflow_text, flags=re.MULTILINE)
    assert uses_actions == ["actions/checkout@v4", "actions/setup-python@v5"]
    assert "permissions:\n  contents: read" in workflow_text
    assert "uv.lock" in workflow_text
    assert "--require-hashes" in workflow_text
    assert "--no-deps" in workflow_text
    assert "pip install --upgrade pip" not in workflow_text

    match = re.search(
        r"python3 - <<'PY'\n(.*?)\n\s*PY",
        workflow_text,
        flags=re.DOTALL,
    )
    assert match is not None, "Expected inline python3 - <<'PY' block in pytest.yml"
    raw_script = "\n".join(
        line[10:] if line.startswith("          ") else line
        for line in match.group(1).splitlines()
    )
    out_req = tmp_path / "ci-locked-dev.txt"
    script_under_test = raw_script.replace(
        "/tmp/ci-locked-dev.txt", str(out_req)
    )
    subprocess.run(
        [sys.executable, "-c", script_under_test],
        cwd=str(REPO_ROOT),
        check=True,
        capture_output=True,
        text=True,
    )
    emitted_lines = out_req.read_text(encoding="utf-8").strip().splitlines()
    assert emitted_lines == req_lines
