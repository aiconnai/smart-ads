from __future__ import annotations

import ast
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tarfile
import venv
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_SMART_ADS = REPO_ROOT / "src" / "smart_ads"

WHEEL_ALLOWLIST_RE = re.compile(
    r"^(smart_ads(/[a-z0-9_]+)+\.py|smart_ads-0\.1\.0\.dist-info/(METADATA|WHEEL|RECORD))$"
)
SDIST_ALLOWLIST_RE = re.compile(
    r"^smart_ads-0\.1\.0/(PKG-INFO|pyproject\.toml|src/smart_ads(/[a-z0-9_]+)+\.py)$"
)

FORBIDDEN_TOP_IMPORTS = {
    "tools",
    "tooling",
    "importlib",
    "runpy",
    "subprocess",
    "socket",
    "ssl",
    "urllib",
    "http",
    "zoneinfo",
    "tempfile",
    "shutil",
}
FORBIDDEN_BUILTINS = {"__import__", "open", "eval", "exec", "compile"}
FORBIDDEN_ATTR_CALLS = {
    ("os", "environ"),
    ("os", "getenv"),
    ("datetime", "now"),
    ("datetime", "utcnow"),
    ("time", "time"),
    ("io", "open"),
}
FORBIDDEN_PATH_METHODS = {
    "open",
    "read_bytes",
    "read_text",
    "write_bytes",
    "write_text",
}


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

    with tarfile.open(sdist_a, "r:gz") as tf:
        sdist_files = sorted(m.name for m in tf.getmembers() if m.isfile())
    assert "smart_ads-0.1.0/src/smart_ads/__init__.py" in sdist_files
    for member in sdist_files:
        assert SDIST_ALLOWLIST_RE.fullmatch(member), f"Forbidden sdist member: {member}"


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

    probe = (
        "import importlib.metadata as m, smart_ads\n"
        "assert smart_ads.__version__ == '0.1.0'\n"
        "assert not m.requires('smart-ads')\n"
        "for mod in ('tools', 'tooling'):\n"
        "    try:\n"
        "        __import__(mod)\n"
        "    except ModuleNotFoundError:\n"
        "        pass\n"
        "    else:\n"
        "        raise AssertionError(f'{mod} unexpectedly importable')"
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
    assert py_files, "src/smart_ads must contain at least __init__.py"
    for path in py_files:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top = alias.name.split(".")[0]
                    assert top not in FORBIDDEN_TOP_IMPORTS, (
                        f"{path}: forbidden import {alias.name}"
                    )
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    top = node.module.split(".")[0]
                    assert top not in FORBIDDEN_TOP_IMPORTS, (
                        f"{path}: forbidden from-import {node.module}"
                    )
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in FORBIDDEN_BUILTINS, (
                    f"{path}: forbidden builtin {node.func.id}"
                )
            elif isinstance(node, ast.Attribute):
                if isinstance(node.value, ast.Name):
                    assert (node.value.id, node.attr) not in FORBIDDEN_ATTR_CALLS, (
                        f"{path}: forbidden attribute {node.value.id}.{node.attr}"
                    )
                assert node.attr not in FORBIDDEN_PATH_METHODS, (
                    f"{path}: forbidden I/O attr {node.attr}"
                )
