"""Tests for tools.governance.gov1_wheel — Git-object provenance, backend binding, and wheel boundary."""
from __future__ import annotations

import ast
import base64
import copy
import csv
import hashlib
import io
from pathlib import Path
import py_compile
import shutil
import subprocess
import sys
import sysconfig
from typing import Any
import warnings
import zipfile

import pytest

from smart_ads.contracts.schemas import compute_schema_bundle_digest
from tools.governance import decomposition_admission, p1
from tools.governance.decomposition_scope import run_git_offline
import tools.governance.gov1_sandbox as gov1_sandbox
import tools.governance.gov1_wheel as gov1_wheel
from tools.governance.locator import Store, digest, json_digest, make_locator
from tests.contract.test_packaging_boundary import EXPECTED_PACKAGED_MODULES

REPO_ROOT = Path(__file__).resolve().parents[2]
ADR_PATH = REPO_ROOT / "docs" / "adr" / "ADR-0001-smart-ads-read-gateway.md"
UV_LOCK_PATH = REPO_ROOT / "uv.lock"
PYPROJECT_PATH = REPO_ROOT / "pyproject.toml"
EXPECTED_ADR_SHA256 = (
    "sha256:239b53e0af44c176b78c363dc271c9fd882910bd4ab2ffb6844cb8fb2458640e"
)

RUN_CONTEXT_LOCATOR = make_locator(
    "smart_ads/migration_run_context/v1", b'{"run":"gov1-task4"}'
)
REGISTRY_LOCATOR = make_locator(
    "smart_ads/key_authorization_registry/v1", b'{"reg":"gov1-task4"}'
)
SIGNER_KEY_ID = "key:ed25519:" + "b" * 64
BUILT_AT_UTC = "2026-11-12T12:00:00Z"
VERIFIED_AT_UTC = "2026-11-12T12:05:00Z"
BUILD_RUN_ID = "build-run-gov1-001"


def _record_hash_and_size(raw: bytes) -> tuple[str, str]:
    b64 = (
        base64.urlsafe_b64encode(hashlib.sha256(raw).digest())
        .rstrip(b"=")
        .decode("ascii")
    )
    return f"sha256={b64}", str(len(raw))


def _rebuild_wheel_from_dict(
    dest: Path,
    members: dict[str, bytes],
    *,
    custom_record_text: str | None = None,
) -> Path:
    all_members = dict(members)
    if custom_record_text is None:
        buf = io.StringIO()
        writer = csv.writer(buf, lineterminator="\n")
        for path in sorted(
            (p for p in all_members if p != "smart_ads-0.1.0.dist-info/RECORD"),
            key=lambda s: s.encode("utf-8"),
        ):
            rec_hash, rec_size = _record_hash_and_size(all_members[path])
            writer.writerow([path, rec_hash, rec_size])
        writer.writerow(["smart_ads-0.1.0.dist-info/RECORD", "", ""])
        all_members["smart_ads-0.1.0.dist-info/RECORD"] = buf.getvalue().encode(
            "utf-8"
        )
    else:
        all_members["smart_ads-0.1.0.dist-info/RECORD"] = custom_record_text.encode(
            "utf-8"
        )

    with zipfile.ZipFile(dest, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(all_members, key=lambda s: s.encode("utf-8")):
            zi = zipfile.ZipInfo(path, date_time=(2023, 11, 14, 22, 13, 20))
            zi.external_attr = 0o100644 << 16
            zf.writestr(zi, all_members[path])
    return dest


def _read_wheel_members(wheel_path: Path) -> dict[str, bytes]:
    with zipfile.ZipFile(wheel_path, "r") as zf:
        return {info.filename: zf.read(info) for info in zf.infolist()}


def _init_temp_git_repo(dest: Path) -> Path:
    dest.mkdir(parents=True, exist_ok=True)
    shutil.copy2(PYPROJECT_PATH, dest / "pyproject.toml")
    shutil.copy2(UV_LOCK_PATH, dest / "uv.lock")
    shutil.copytree(
        REPO_ROOT / "src",
        dest / "src",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo", "*.egg-info"),
    )
    # Include repository-root/tooling decoys in the committed tree to prove exclusion
    (dest / "README.md").write_text("# Temp Repo\n", encoding="utf-8")
    (dest / "tools").mkdir()
    (dest / "tools" / "decoy.py").write_text("X = 1\n", encoding="utf-8")

    run_git_offline(dest, "init", "-q")
    run_git_offline(dest, "config", "user.name", "Gov1 Test")
    run_git_offline(dest, "config", "user.email", "gov1@example.invalid")
    run_git_offline(dest, "add", ".")
    run_git_offline(dest, "commit", "-q", "-m", "initial clean commit")
    return dest


def _copy_closure_site_packages(dest: Path) -> Path:
    src_sp = Path(sysconfig.get_path("purelib"))
    dest.mkdir(parents=True, exist_ok=True)
    for _, (_, _, dist_info_dir, module_dir, _) in (
        gov1_wheel.PINNED_UV_LOCK_CLOSURE_SPECS.items()
    ):
        shutil.copytree(src_sp / module_dir, dest / module_dir)
        shutil.copytree(src_sp / dist_info_dir, dest / dist_info_dir)
    return dest


@pytest.fixture(scope="module")
def baseline_build(
    tmp_path_factory: pytest.TempPathFactory,
) -> tuple[Path, gov1_wheel.GitBuildSnapshot, bytes, dict[str, Any]]:
    out_dir = tmp_path_factory.mktemp("baseline_wheel")
    wheel_path, snapshot = gov1_wheel.build_reproducible_wheel(REPO_ROOT, out_dir)
    wheel_bytes = wheel_path.read_bytes()
    inspection = gov1_wheel.inspect_wheel_boundary(wheel_path)
    return wheel_path, snapshot, wheel_bytes, inspection


@pytest.fixture()
def keypair(tmp_path: Path) -> tuple[Path, bytes]:
    priv = tmp_path / "wheel_verifier.pem"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(priv)],
        check=True,
        capture_output=True,
    )
    raw32 = p1.raw_public_key_from_pem(priv)
    return priv, raw32


def test_constants_immutability_and_zero_ast_assert_in_gov1_wheel() -> None:
    assert (
        gov1_wheel.WHEEL_OBJECT_LOCATOR_SCHEMA == "smart_ads/wheel_object_locator/v1"
    )
    assert (
        gov1_wheel.WHEEL_BUILD_PROVENANCE_SCHEMA
        == "smart_ads/wheel_build_provenance/v1"
    )
    assert (
        gov1_wheel.WHEEL_BOUNDARY_REPORT_SCHEMA
        == "smart_ads/wheel_boundary_report/v1"
    )
    assert set(gov1_wheel.PINNED_UV_LOCK_CLOSURE_SPECS.keys()) == {
        "build",
        "hatchling",
        "packaging",
        "pathspec",
        "pluggy",
        "pyproject-hooks",
        "tomlkit",
        "trove-classifiers",
    }
    with pytest.raises(TypeError):
        gov1_wheel.PINNED_UV_LOCK_CLOSURE_SPECS["extra"] = ("0", "", "", "", "")  # type: ignore[index]

    mod_path = REPO_ROOT / "tools" / "governance" / "gov1_wheel.py"
    source = mod_path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(mod_path))
    assert [n for n in ast.walk(tree) if isinstance(n, ast.Assert)] == []

    # Also verify embedded subprocess scripts inside gov1_wheel contain zero assert
    embedded_scripts = (
        "_PEP517_RUNNER_BOOTSTRAP",
        "_PEP517_DRIVER_SCRIPT",
        "_CLEAN_VENV_PROBE_SCRIPT",
    )
    for attr_name in embedded_scripts:
        val = getattr(gov1_wheel, attr_name)
        assert isinstance(val, str) and val.strip()
        sub_tree = ast.parse(val, filename=f"gov1_wheel.{attr_name}")
        assert [n for n in ast.walk(sub_tree) if isinstance(n, ast.Assert)] == []

    assert digest(ADR_PATH.read_bytes()) == EXPECTED_ADR_SHA256
    assert len(p1.DOMAIN_PREFIXES) == 7


def test_deterministic_build_and_full_candidate_and_p1_envelope_roundtrip(
    tmp_path: Path,
    baseline_build: tuple[Path, gov1_wheel.GitBuildSnapshot, bytes, dict[str, Any]],
    keypair: tuple[Path, bytes],
) -> None:
    wheel_path, snapshot, wheel_bytes, inspection = baseline_build
    expected_schema_digest = compute_schema_bundle_digest()

    # Second independent build over REPO_ROOT produces byte-identical wheel & snapshot
    wheel_path_2, snapshot_2 = gov1_wheel.build_reproducible_wheel(
        REPO_ROOT, tmp_path / "rebuild_check"
    )
    assert wheel_path_2.read_bytes() == wheel_bytes
    assert snapshot_2.commit_sha == snapshot.commit_sha
    assert snapshot_2.tree_oid == snapshot.tree_oid
    assert snapshot_2.build_backend == "hatchling.build"
    assert snapshot_2.build_backend_version == "1.33.0"
    assert snapshot_2.build_backend_digest == snapshot.build_backend_digest

    # Wheel object locator validation
    whl_loc = gov1_wheel.build_wheel_object_locator(wheel_bytes)
    assert whl_loc == {
        "$schema": "smart_ads/wheel_object_locator/v1",
        "store_kind": "cell_immutable_object",
        "object_ref": f"cell-object:{digest(wheel_bytes)}",
        "wheel_digest": digest(wheel_bytes),
        "size_bytes": len(wheel_bytes),
    }
    gov1_wheel.verify_wheel_object_locator(whl_loc)
    gov1_wheel.verify_wheel_object_locator(whl_loc, expected_wheel_bytes=wheel_bytes)
    with pytest.raises(ValueError):
        gov1_wheel.verify_wheel_object_locator(
            whl_loc, expected_wheel_bytes=wheel_bytes + b"x"
        )
    bad_size_loc = copy.deepcopy(whl_loc)
    bad_size_loc["size_bytes"] = True
    with pytest.raises(ValueError):
        gov1_wheel.verify_wheel_object_locator(bad_size_loc)

    # Boundary inspection checks
    assert inspection["wheel_digest"] == digest(wheel_bytes)
    assert inspection["schema_bundle_digest"] == expected_schema_digest
    assert inspection["packaged_modules"] == sorted(
        EXPECTED_PACKAGED_MODULES, key=lambda s: s.encode("utf-8")
    )
    assert len(inspection["packaged_modules"]) == 24
    assert inspection["archive_allowlist_passed"] is True
    assert inspection["ast_boundary_scan_passed"] is True
    assert inspection["isolated_venv_import_passed"] is True
    assert (
        {
            "path": "smart_ads-0.1.0.dist-info/RECORD",
            "record_hash": "",
            "record_size": None,
        }
        in inspection["sorted_record_entries"]
    )
    assert inspection["sorted_record_digest"] == json_digest(
        inspection["sorted_record_entries"]
    )

    # 1) Local Candidate path (non-signable, uses wheel_build_provenance_candidate_ref)
    prov_cand = gov1_wheel.build_wheel_build_provenance_candidate(
        migration_run_context_locator=RUN_CONTEXT_LOCATOR,
        build_run_id=BUILD_RUN_ID,
        built_at_utc=BUILT_AT_UTC,
        snapshot=snapshot,
        source_date_epoch=1_700_000_000,
        schema_bundle_digest=expected_schema_digest,
        wheel_bytes=wheel_bytes,
    )
    prov_cand_res = gov1_wheel.verify_wheel_build_provenance(
        prov_cand, repo_root=REPO_ROOT, wheel_path=wheel_path
    )
    assert prov_cand_res == {
        "mode": "candidate",
        "schema": gov1_wheel.WHEEL_BUILD_PROVENANCE_SCHEMA,
        "wheel_digest": digest(wheel_bytes),
        "source_commit_sha": snapshot.commit_sha,
        "build_backend_digest": snapshot.build_backend_digest,
        "schema_bundle_digest": expected_schema_digest,
        "payload": prov_cand["payload"],
    }

    prov_cand_ref = gov1_sandbox.build_local_candidate_ref(prov_cand)
    rep_cand = gov1_wheel.build_wheel_boundary_report_candidate(
        migration_run_context_locator=RUN_CONTEXT_LOCATOR,
        build_run_id=BUILD_RUN_ID,
        verified_at_utc=VERIFIED_AT_UTC,
        source_commit_sha=snapshot.commit_sha,
        build_backend_digest=snapshot.build_backend_digest,
        wheel_build_provenance_candidate_ref=prov_cand_ref,
        inspection=inspection,
    )
    rep_cand_res = gov1_wheel.verify_wheel_boundary_report(
        rep_cand, wheel_path=wheel_path
    )
    assert rep_cand_res == {
        "mode": "candidate",
        "schema": gov1_wheel.WHEEL_BOUNDARY_REPORT_SCHEMA,
        "wheel_digest": digest(wheel_bytes),
        "schema_bundle_digest": expected_schema_digest,
        "sorted_record_digest": inspection["sorted_record_digest"],
        "payload": rep_cand["payload"],
    }

    # 2) P1 Signed Envelope path (uses wheel_build_provenance_locator + Store)
    priv, raw32 = keypair
    signer_id = p1.key_id_for(raw32)
    profiles = {
        row["schema"]: row
        for row in decomposition_admission.profile_proposals(ADR_PATH.read_bytes())
    }
    prov_prefix = profiles[gov1_wheel.WHEEL_BUILD_PROVENANCE_SCHEMA]["domain_prefix"]
    rep_prefix = profiles[gov1_wheel.WHEEL_BOUNDARY_REPORT_SCHEMA]["domain_prefix"]
    assert prov_prefix == "SMART-ADS:WHEEL-BUILD:V1\n"
    assert rep_prefix == "SMART-ADS:WHEEL-BOUNDARY:V1\n"

    prov_env_unsigned = gov1_wheel.build_wheel_build_provenance_envelope(
        migration_run_context_locator=RUN_CONTEXT_LOCATOR,
        build_run_id=BUILD_RUN_ID,
        built_at_utc=BUILT_AT_UTC,
        snapshot=snapshot,
        source_date_epoch=1_700_000_000,
        schema_bundle_digest=expected_schema_digest,
        wheel_bytes=wheel_bytes,
        registry_locator=REGISTRY_LOCATOR,
        signer_key_id=signer_id,
    )
    assert (
        gov1_wheel.verify_wheel_build_provenance(
            prov_env_unsigned, repo_root=REPO_ROOT, wheel_path=wheel_path
        )["mode"]
        == "envelope"
    )

    prov_env_signed = p1.sign_envelope(prov_env_unsigned, prov_prefix, priv)
    p1.verify_envelope(prov_env_signed, prov_prefix, raw32)

    store = Store(tmp_path / "store")
    prov_locator = store.put(prov_env_signed)
    loaded_prov = store.get(prov_locator, gov1_wheel.WHEEL_BUILD_PROVENANCE_SCHEMA)
    prov_env_res = gov1_wheel.verify_wheel_build_provenance(
        loaded_prov, repo_root=REPO_ROOT, wheel_path=wheel_path
    )
    assert prov_env_res["mode"] == "envelope"
    assert prov_env_res["wheel_digest"] == digest(wheel_bytes)

    rep_env_unsigned = gov1_wheel.build_wheel_boundary_report_envelope(
        migration_run_context_locator=RUN_CONTEXT_LOCATOR,
        build_run_id=BUILD_RUN_ID,
        verified_at_utc=VERIFIED_AT_UTC,
        source_commit_sha=snapshot.commit_sha,
        build_backend_digest=snapshot.build_backend_digest,
        wheel_build_provenance_locator=prov_locator,
        inspection=inspection,
        registry_locator=REGISTRY_LOCATOR,
        signer_key_id=signer_id,
    )
    rep_env_signed = p1.sign_envelope(rep_env_unsigned, rep_prefix, priv)
    p1.verify_envelope(rep_env_signed, rep_prefix, raw32)
    rep_locator = store.put(rep_env_signed)
    loaded_rep = store.get(rep_locator, gov1_wheel.WHEEL_BOUNDARY_REPORT_SCHEMA)
    rep_env_res = gov1_wheel.verify_wheel_boundary_report(
        loaded_rep, wheel_path=wheel_path
    )
    assert rep_env_res["mode"] == "envelope"
    assert rep_env_res["sorted_record_digest"] == inspection["sorted_record_digest"]


def test_working_tree_and_git_index_dirtiness_immunity_f03(tmp_path: Path) -> None:
    repo = _init_temp_git_repo(tmp_path / "git_repo")
    clean_whl, clean_snap = gov1_wheel.build_reproducible_wheel(
        repo, tmp_path / "clean_out"
    )
    clean_bytes = clean_whl.read_bytes()

    # Dirty tracked file AND stage into Git index (without committing)
    init_py = repo / "src" / "smart_ads" / "__init__.py"
    original_init = init_py.read_text(encoding="utf-8")
    init_py.write_text(
        original_init + '\nSTAGED_DIRT = "must_not_enter_wheel"\n', encoding="utf-8"
    )
    run_git_offline(repo, "add", "src/smart_ads/__init__.py")

    # Further dirty the working tree unstaged + add untracked Python file inside src/smart_ads
    init_py.write_text(
        original_init + '\nWORKTREE_DIRT = "must_not_enter_wheel"\n', encoding="utf-8"
    )
    (repo / "src" / "smart_ads" / "untracked_leak.py").write_text(
        "LEAK = True\n", encoding="utf-8"
    )

    dirty_whl, dirty_snap = gov1_wheel.build_reproducible_wheel(
        repo, tmp_path / "dirty_out"
    )
    assert dirty_snap.commit_sha == clean_snap.commit_sha
    assert dirty_snap.tree_oid == clean_snap.tree_oid
    assert dirty_whl.read_bytes() == clean_bytes

    members = _read_wheel_members(dirty_whl)
    assert "smart_ads/untracked_leak.py" not in members
    assert b"STAGED_DIRT" not in members["smart_ads/__init__.py"]
    assert b"WORKTREE_DIRT" not in members["smart_ads/__init__.py"]


def test_git_snapshot_rejects_committed_symlinks(tmp_path: Path) -> None:
    repo = _init_temp_git_repo(tmp_path / "symlink_repo")
    (repo / "docs_link").symlink_to("README.md")
    run_git_offline(repo, "add", "docs_link")
    run_git_offline(repo, "commit", "-q", "-m", "commit symlink")

    with pytest.raises(ValueError):
        gov1_wheel.materialize_git_build_snapshot(repo, commit_ref="HEAD")


def test_runtime_abi_site_packages_and_backend_wheel_dir_binding_f04(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    uv_lock_bytes = UV_LOCK_PATH.read_bytes()
    pyproject_bytes = PYPROJECT_PATH.read_bytes()

    # 1. Simulate Python 3.14.7 -> ValueError
    with monkeypatch.context() as m:
        m.setattr(sys, "version_info", (3, 14, 7))
        with pytest.raises(ValueError):
            gov1_wheel.verify_build_runtime_environment(uv_lock_bytes)
        with pytest.raises(ValueError):
            gov1_wheel.compute_build_backend_digest(pyproject_bytes, uv_lock_bytes)

    with monkeypatch.context() as m:
        m.setattr(sys.implementation, "name", "pypy")
        with pytest.raises(ValueError):
            gov1_wheel.verify_build_runtime_environment(uv_lock_bytes)

    # 2. Copy closure site-packages; baseline passes
    sp_copy = _copy_closure_site_packages(tmp_path / "sp_clean")
    abi_tag, closure_digests = gov1_wheel.verify_build_runtime_environment(
        uv_lock_bytes, site_packages_dir=sp_copy
    )
    assert abi_tag == "cp312"
    assert len(closure_digests) == 8

    # 3. Tamper hatchling/build.py AND update hatchling .dist-info/RECORD consistently -> ValueError
    sp_tampered = _copy_closure_site_packages(tmp_path / "sp_tampered")
    build_py = sp_tampered / "hatchling" / "build.py"
    tampered_bytes = build_py.read_bytes() + b"\n# tampered backend\n"
    build_py.write_bytes(tampered_bytes)
    rec_path = sp_tampered / "hatchling-1.33.0.dist-info" / "RECORD"
    rows = list(csv.reader(rec_path.read_text(encoding="utf-8").splitlines()))
    out_buf = io.StringIO()
    writer = csv.writer(out_buf, lineterminator="\n")
    for row in rows:
        if row[0] == "hatchling/build.py":
            new_h, new_sz = _record_hash_and_size(tampered_bytes)
            writer.writerow(["hatchling/build.py", new_h, new_sz])
        else:
            writer.writerow(row)
    rec_path.write_text(out_buf.getvalue(), encoding="utf-8")

    with pytest.raises(ValueError):
        gov1_wheel.verify_build_runtime_environment(
            uv_lock_bytes, site_packages_dir=sp_tampered
        )

    # 4. Inject extra .py file omitted from RECORD -> ValueError
    sp_extra = _copy_closure_site_packages(tmp_path / "sp_extra")
    (sp_extra / "hatchling" / "unrecorded_extra.py").write_text(
        "EXTRA = 1\n", encoding="utf-8"
    )
    with pytest.raises(ValueError):
        gov1_wheel.verify_build_runtime_environment(
            uv_lock_bytes, site_packages_dir=sp_extra
        )

    # 5. Symlink inside site-packages closure -> ValueError
    sp_sym = _copy_closure_site_packages(tmp_path / "sp_sym")
    (sp_sym / "hatchling" / "sym.py").symlink_to(sp_sym / "hatchling" / "build.py")
    with pytest.raises(ValueError):
        gov1_wheel.verify_build_runtime_environment(
            uv_lock_bytes, site_packages_dir=sp_sym
        )

    # 6. backend_wheel_dir with valid synthetic .whl vs adulterated .whl
    whl_dir = tmp_path / "wheelhouse"
    whl_dir.mkdir()
    synth_whl_path = whl_dir / "synth_pkg-1.0.0-py3-none-any.whl"
    init_bytes = b"VALUE = 42\n"
    meta_bytes = b"Metadata-Version: 2.1\nName: synth-pkg\nVersion: 1.0.0\n"
    wheel_meta_bytes = b"Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
    rec_buf = io.StringIO()
    rec_writer = csv.writer(rec_buf, lineterminator="\n")
    for rel_p, raw_b in (
        ("synth_pkg/__init__.py", init_bytes),
        ("synth_pkg-1.0.0.dist-info/METADATA", meta_bytes),
        ("synth_pkg-1.0.0.dist-info/WHEEL", wheel_meta_bytes),
    ):
        rh, rsz = _record_hash_and_size(raw_b)
        rec_writer.writerow([rel_p, rh, rsz])
    rec_writer.writerow(["synth_pkg-1.0.0.dist-info/RECORD", "", ""])
    with zipfile.ZipFile(synth_whl_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("synth_pkg/__init__.py", init_bytes)
        zf.writestr("synth_pkg-1.0.0.dist-info/METADATA", meta_bytes)
        zf.writestr("synth_pkg-1.0.0.dist-info/WHEEL", wheel_meta_bytes)
        zf.writestr("synth_pkg-1.0.0.dist-info/RECORD", rec_buf.getvalue())

    synth_whl_sha = digest(synth_whl_path.read_bytes())
    synth_entries = sorted(
        [
            {
                "path": p,
                "sha256": hashlib.sha256(b).hexdigest(),
                "size": len(b),
            }
            for p, b in (
                ("synth_pkg/__init__.py", init_bytes),
                ("synth_pkg-1.0.0.dist-info/METADATA", meta_bytes),
                ("synth_pkg-1.0.0.dist-info/WHEEL", wheel_meta_bytes),
            )
        ],
        key=lambda e: e["path"].encode("utf-8"),
    )
    synth_tree_sha = json_digest(synth_entries)
    synth_lock = (
        'version = 1\nrequires-python = ">=3.12"\n\n'
        '[[package]]\nname = "synth-pkg"\nversion = "1.0.0"\n'
        'wheels = [{ url = "https://example.invalid/synth_pkg-1.0.0-py3-none-any.whl", '
        f'hash = "{synth_whl_sha}" }}]\n'
    ).encode("utf-8")
    synth_specs = {
        "synth-pkg": (
            "1.0.0",
            synth_whl_sha,
            "synth_pkg-1.0.0.dist-info",
            "synth_pkg",
            synth_tree_sha,
        )
    }

    materialized_dir = tmp_path / "materialized_synth"
    abi, synth_digests = gov1_wheel.verify_build_runtime_environment(
        synth_lock,
        backend_wheel_dir=whl_dir,
        target_backend_site_dir=materialized_dir,
        closure_specs=synth_specs,
    )
    assert abi == "cp312"
    assert synth_digests == {"synth-pkg": synth_tree_sha}
    assert (materialized_dir / "synth_pkg" / "__init__.py").read_bytes() == init_bytes

    # Tampered site_packages_dir (with internally consistent RECORD) paired with valid backend_wheel_dir -> ValueError
    synth_sp_tampered = tmp_path / "synth_sp_tampered"
    (synth_sp_tampered / "synth_pkg").mkdir(parents=True)
    (synth_sp_tampered / "synth_pkg-1.0.0.dist-info").mkdir(parents=True)
    tampered_init = b"VALUE = 999\n"
    (synth_sp_tampered / "synth_pkg" / "__init__.py").write_bytes(tampered_init)
    (synth_sp_tampered / "synth_pkg-1.0.0.dist-info" / "METADATA").write_bytes(meta_bytes)
    (synth_sp_tampered / "synth_pkg-1.0.0.dist-info" / "WHEEL").write_bytes(wheel_meta_bytes)
    t_rec_buf = io.StringIO()
    t_rec_writer = csv.writer(t_rec_buf, lineterminator="\n")
    for rel_p, raw_b in (
        ("synth_pkg/__init__.py", tampered_init),
        ("synth_pkg-1.0.0.dist-info/METADATA", meta_bytes),
        ("synth_pkg-1.0.0.dist-info/WHEEL", wheel_meta_bytes),
    ):
        rh, rsz = _record_hash_and_size(raw_b)
        t_rec_writer.writerow([rel_p, rh, rsz])
    t_rec_writer.writerow(["synth_pkg-1.0.0.dist-info/RECORD", "", ""])
    (synth_sp_tampered / "synth_pkg-1.0.0.dist-info" / "RECORD").write_text(
        t_rec_buf.getvalue(), encoding="utf-8"
    )
    with pytest.raises(ValueError):
        gov1_wheel.verify_build_runtime_environment(
            synth_lock,
            site_packages_dir=synth_sp_tampered,
            backend_wheel_dir=whl_dir,
            closure_specs=synth_specs,
        )

    # Adulterate the .whl on disk -> rejected by SHA-256 verification against uv.lock
    synth_whl_path.write_bytes(synth_whl_path.read_bytes() + b"tamper")
    with pytest.raises(ValueError):
        gov1_wheel.verify_build_runtime_environment(
            synth_lock,
            backend_wheel_dir=whl_dir,
            closure_specs=synth_specs,
        )


def test_isolated_pep517_build_defeats_pythonpath_pth_sitecustomize_and_pyc_shadowing_f04(
    tmp_path: Path,
    baseline_build: tuple[Path, gov1_wheel.GitBuildSnapshot, bytes, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, _, expected_wheel_bytes, _ = baseline_build

    # 1. Malicious PYTHONPATH shadowing hatchling.build
    evil_pp = tmp_path / "evil_pythonpath"
    (evil_pp / "hatchling").mkdir(parents=True)
    (evil_pp / "hatchling" / "__init__.py").write_text(
        'raise RuntimeError("SHADOWED_VIA_PYTHONPATH")\n', encoding="utf-8"
    )
    (evil_pp / "hatchling" / "build.py").write_text(
        'raise RuntimeError("SHADOWED_VIA_PYTHONPATH")\n', encoding="utf-8"
    )

    # 2. Poisoned site-packages with .pth, sitecustomize.py, usercustomize.py, AND poisoned .pyc
    poisoned_sp = _copy_closure_site_packages(tmp_path / "poisoned_sp")
    (poisoned_sp / "00_evil.pth").write_text(
        'import sys; raise RuntimeError("EVIL_PTH_EXECUTED")\n', encoding="utf-8"
    )
    (poisoned_sp / "sitecustomize.py").write_text(
        'raise RuntimeError("EVIL_SITECUSTOMIZE_EXECUTED")\n', encoding="utf-8"
    )
    (poisoned_sp / "usercustomize.py").write_text(
        'raise RuntimeError("EVIL_USERCUSTOMIZE_EXECUTED")\n', encoding="utf-8"
    )

    # Forge a bytecode .pyc with valid source stat header for hatchling/build.py
    real_build_py = poisoned_sp / "hatchling" / "build.py"
    real_bytes = real_build_py.read_bytes()
    real_stat = real_build_py.stat()
    pycache_dir = poisoned_sp / "hatchling" / "__pycache__"
    pycache_dir.mkdir(exist_ok=True)
    poisoned_pyc = pycache_dir / f"build.{sys.implementation.cache_tag}.pyc"
    # Temporarily write malicious source with exact mtime to compile matching .pyc, then restore clean .py
    evil_src = b'raise RuntimeError("POISONED_PYC_EXECUTED")\n'
    real_build_py.write_bytes(evil_src)
    py_compile.compile(str(real_build_py), cfile=str(poisoned_pyc), doraise=True)
    real_build_py.write_bytes(real_bytes)
    os_utime_ns = (real_stat.st_atime_ns, real_stat.st_mtime_ns)
    import os

    os.utime(real_build_py, ns=os_utime_ns)
    assert poisoned_pyc.is_file()

    monkeypatch.setenv("PYTHONPATH", str(evil_pp))
    monkeypatch.setenv("PYTHONSTARTUP", str(poisoned_sp / "sitecustomize.py"))

    built_whl, _ = gov1_wheel.build_reproducible_wheel(
        REPO_ROOT,
        tmp_path / "shadow_out",
        site_packages_dir=poisoned_sp,
    )
    assert built_whl.read_bytes() == expected_wheel_bytes


def test_commit_to_wheel_reconciliation_rejects_cross_commit_or_epoch_forgery_f08(
    tmp_path: Path,
) -> None:
    repo = _init_temp_git_repo(tmp_path / "f08_repo")
    whl_1, snap_1 = gov1_wheel.build_reproducible_wheel(repo, tmp_path / "out_c1")

    # Commit 2: change only the module docstring of src/smart_ads/__init__.py
    init_py = repo / "src" / "smart_ads" / "__init__.py"
    orig_lines = init_py.read_text(encoding="utf-8").splitlines(keepends=True)
    assert orig_lines[0].startswith('"""') and orig_lines[0].strip().endswith('"""')
    orig_lines[0] = '"""Modified docstring in commit 2 (ADR-0001)."""\n'
    init_py.write_text("".join(orig_lines), encoding="utf-8")
    run_git_offline(repo, "add", "src/smart_ads/__init__.py")
    run_git_offline(repo, "commit", "-q", "-m", "commit 2 docstring update")

    whl_2, snap_2 = gov1_wheel.build_reproducible_wheel(repo, tmp_path / "out_c2")
    assert snap_2.commit_sha != snap_1.commit_sha
    assert whl_2.read_bytes() != whl_1.read_bytes()

    # whl_2 is valid on its own for commit 2
    insp_2 = gov1_wheel.inspect_wheel_boundary(whl_2)
    valid_c2 = gov1_wheel.build_wheel_build_provenance_candidate(
        migration_run_context_locator=RUN_CONTEXT_LOCATOR,
        build_run_id=BUILD_RUN_ID,
        built_at_utc=BUILT_AT_UTC,
        snapshot=snap_2,
        source_date_epoch=1_700_000_000,
        schema_bundle_digest=insp_2["schema_bundle_digest"],
        wheel_bytes=whl_2.read_bytes(),
    )
    assert (
        gov1_wheel.verify_wheel_build_provenance(
            valid_c2, repo_root=repo, wheel_path=whl_2
        )["source_commit_sha"]
        == snap_2.commit_sha
    )

    # Forgery 1: whl_2 bytes + valid RECORD/digest, but claiming snap_1 (commit 1)!
    forged_cand = gov1_wheel.build_wheel_build_provenance_candidate(
        migration_run_context_locator=RUN_CONTEXT_LOCATOR,
        build_run_id=BUILD_RUN_ID,
        built_at_utc=BUILT_AT_UTC,
        snapshot=snap_1,
        source_date_epoch=1_700_000_000,
        schema_bundle_digest=insp_2["schema_bundle_digest"],
        wheel_bytes=whl_2.read_bytes(),
    )
    with pytest.raises(ValueError):
        gov1_wheel.verify_wheel_build_provenance(
            forged_cand, repo_root=repo, wheel_path=whl_2
        )

    forged_env = gov1_wheel.build_wheel_build_provenance_envelope(
        migration_run_context_locator=RUN_CONTEXT_LOCATOR,
        build_run_id=BUILD_RUN_ID,
        built_at_utc=BUILT_AT_UTC,
        snapshot=snap_1,
        source_date_epoch=1_700_000_000,
        schema_bundle_digest=insp_2["schema_bundle_digest"],
        wheel_bytes=whl_2.read_bytes(),
        registry_locator=REGISTRY_LOCATOR,
        signer_key_id=SIGNER_KEY_ID,
    )
    with pytest.raises(ValueError):
        gov1_wheel.verify_wheel_build_provenance(
            forged_env, repo_root=repo, wheel_path=whl_2
        )

    # Forgery 2: same commit_1 .py blobs, but built with different source_date_epoch -> rebuild catches it!
    whl_1_alt_epoch, _ = gov1_wheel.build_reproducible_wheel(
        repo,
        tmp_path / "out_c1_epoch",
        commit_ref=snap_1.commit_sha,
        source_date_epoch=1_700_086_400,
    )
    assert whl_1_alt_epoch.read_bytes() != whl_1.read_bytes()
    forged_epoch_cand = gov1_wheel.build_wheel_build_provenance_candidate(
        migration_run_context_locator=RUN_CONTEXT_LOCATOR,
        build_run_id=BUILD_RUN_ID,
        built_at_utc=BUILT_AT_UTC,
        snapshot=snap_1,
        source_date_epoch=1_700_000_000,
        schema_bundle_digest=insp_2["schema_bundle_digest"],
        wheel_bytes=whl_1_alt_epoch.read_bytes(),
    )
    with pytest.raises(ValueError):
        gov1_wheel.verify_wheel_build_provenance(
            forged_epoch_cand, repo_root=repo, wheel_path=whl_1_alt_epoch
        )


def test_pep427_record_zip_ast_and_candidate_ref_boundary_rejections_f02(
    tmp_path: Path,
    baseline_build: tuple[Path, gov1_wheel.GitBuildSnapshot, bytes, dict[str, Any]],
) -> None:
    wheel_path, snapshot, wheel_bytes, inspection = baseline_build
    base_members = _read_wheel_members(wheel_path)
    base_record = base_members["smart_ads-0.1.0.dist-info/RECORD"].decode("utf-8")

    # 1. Non-empty hash on RECORD self-row -> ValueError
    bad_self_hash = base_record.replace(
        "smart_ads-0.1.0.dist-info/RECORD,,",
        "smart_ads-0.1.0.dist-info/RECORD,sha256=47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU,0",
    )
    whl_self_hash = _rebuild_wheel_from_dict(
        tmp_path / "bad_self_hash.whl", base_members, custom_record_text=bad_self_hash
    )
    with pytest.raises(ValueError):
        gov1_wheel.inspect_wheel_boundary(whl_self_hash)

    # 2. Empty hash on a .py member in RECORD -> ValueError
    rows = list(csv.reader(base_record.splitlines()))
    buf_empty_py = io.StringIO()
    w = csv.writer(buf_empty_py, lineterminator="\n")
    for r in rows:
        if r[0] == "smart_ads/__init__.py":
            w.writerow(["smart_ads/__init__.py", "", ""])
        else:
            w.writerow(r)
    whl_empty_py = _rebuild_wheel_from_dict(
        tmp_path / "bad_empty_py.whl",
        base_members,
        custom_record_text=buf_empty_py.getvalue(),
    )
    with pytest.raises(ValueError):
        gov1_wheel.inspect_wheel_boundary(whl_empty_py)

    # 3. Duplicate CSV row in RECORD -> ValueError
    dup_record = rows[0][0] + "," + rows[0][1] + "," + rows[0][2] + "\n" + base_record
    whl_dup_rec = _rebuild_wheel_from_dict(
        tmp_path / "bad_dup_rec.whl", base_members, custom_record_text=dup_record
    )
    with pytest.raises(ValueError):
        gov1_wheel.inspect_wheel_boundary(whl_dup_rec)

    # 4. Omit member from RECORD -> ValueError
    omitted_record = "\n".join(
        line
        for line in base_record.splitlines()
        if not line.startswith("smart_ads/__init__.py,")
    ) + "\n"
    whl_omit_rec = _rebuild_wheel_from_dict(
        tmp_path / "bad_omit_rec.whl", base_members, custom_record_text=omitted_record
    )
    with pytest.raises(ValueError):
        gov1_wheel.inspect_wheel_boundary(whl_omit_rec)

    # 5. Duplicate central-directory ZIP entry -> ValueError
    whl_dup_zip = tmp_path / "bad_dup_zip.whl"
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(whl_dup_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for p, b in sorted(base_members.items()):
                zf.writestr(p, b)
            zf.writestr("smart_ads/__init__.py", base_members["smart_ads/__init__.py"])
    with pytest.raises(ValueError):
        gov1_wheel.inspect_wheel_boundary(whl_dup_zip)

    # 6. Symlink ZIP entry -> ValueError
    whl_sym_zip = tmp_path / "bad_sym_zip.whl"
    with zipfile.ZipFile(whl_sym_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for p, b in sorted(base_members.items()):
            zf.writestr(p, b)
        sym_zi = zipfile.ZipInfo("smart_ads/symlink_mod.py")
        sym_zi.external_attr = 0o120777 << 16
        zf.writestr(sym_zi, b"/etc/passwd")
    with pytest.raises(ValueError):
        gov1_wheel.inspect_wheel_boundary(whl_sym_zip)

    # 7. Directory ZIP entry -> ValueError
    whl_dir_zip = tmp_path / "bad_dir_zip.whl"
    with zipfile.ZipFile(whl_dir_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("smart_ads/", b"")
        for p, b in sorted(base_members.items()):
            zf.writestr(p, b)
    with pytest.raises(ValueError):
        gov1_wheel.inspect_wheel_boundary(whl_dir_zip)

    # 8. Path traversal & tooling/leak.py ZIP entries -> ValueError
    for bad_member_name in ("smart_ads/../evil.py", "tooling/leak.py", "tools/leak.py"):
        mut = dict(base_members)
        mut[bad_member_name] = b"X = 1\n"
        bad_whl = _rebuild_wheel_from_dict(
            tmp_path / f"bad_{bad_member_name.replace('/', '_')}.whl", mut
        )
        with pytest.raises(ValueError):
            gov1_wheel.inspect_wheel_boundary(bad_whl)

    # 9. Forbidden AST constructs inside wheel .py (even with recomputed valid RECORD!)
    for idx, snippet in enumerate(
        [
            b"\nassert True\n",
            b"\nimport tooling\n",
            b"\nimport importlib\n",
            b'\ndef _f(x):\n    return getattr(x, "__import__")\n',
            b"\nfrom tools.governance import jcs\n",
            b"\ndef _f():\n    return eval('1+1')\n",
        ]
    ):
        mut = dict(base_members)
        mut["smart_ads/__init__.py"] = mut["smart_ads/__init__.py"] + snippet
        bad_ast_whl = _rebuild_wheel_from_dict(tmp_path / f"bad_ast_{idx}.whl", mut)
        with pytest.raises(ValueError):
            gov1_wheel.inspect_wheel_boundary(bad_ast_whl)

    # 10. Non-interchangeability between gov1_local_candidate_ref and artifact_locator/v1
    prov_cand = gov1_wheel.build_wheel_build_provenance_candidate(
        migration_run_context_locator=RUN_CONTEXT_LOCATOR,
        build_run_id=BUILD_RUN_ID,
        built_at_utc=BUILT_AT_UTC,
        snapshot=snapshot,
        source_date_epoch=1_700_000_000,
        schema_bundle_digest=inspection["schema_bundle_digest"],
        wheel_bytes=wheel_bytes,
    )
    cand_ref = gov1_sandbox.build_local_candidate_ref(prov_cand)
    real_prov_locator = make_locator(
        gov1_wheel.WHEEL_BUILD_PROVENANCE_SCHEMA, b'{"prov":1}'
    )

    # Passing gov1_local_candidate_ref to P1 envelope builder -> ValueError
    with pytest.raises(ValueError):
        gov1_wheel.build_wheel_boundary_report_envelope(
            migration_run_context_locator=RUN_CONTEXT_LOCATOR,
            build_run_id=BUILD_RUN_ID,
            verified_at_utc=VERIFIED_AT_UTC,
            source_commit_sha=snapshot.commit_sha,
            build_backend_digest=snapshot.build_backend_digest,
            wheel_build_provenance_locator=cand_ref,
            inspection=inspection,
            registry_locator=REGISTRY_LOCATOR,
            signer_key_id=SIGNER_KEY_ID,
        )

    # Passing artifact_locator/v1 to local candidate builder -> ValueError
    with pytest.raises(ValueError):
        gov1_wheel.build_wheel_boundary_report_candidate(
            migration_run_context_locator=RUN_CONTEXT_LOCATOR,
            build_run_id=BUILD_RUN_ID,
            verified_at_utc=VERIFIED_AT_UTC,
            source_commit_sha=snapshot.commit_sha,
            build_backend_digest=snapshot.build_backend_digest,
            wheel_build_provenance_candidate_ref=real_prov_locator,
            inspection=inspection,
        )

    # Tampering boundary report fields fails verify_wheel_boundary_report recomputation
    valid_rep_env = gov1_wheel.build_wheel_boundary_report_envelope(
        migration_run_context_locator=RUN_CONTEXT_LOCATOR,
        build_run_id=BUILD_RUN_ID,
        verified_at_utc=VERIFIED_AT_UTC,
        source_commit_sha=snapshot.commit_sha,
        build_backend_digest=snapshot.build_backend_digest,
        wheel_build_provenance_locator=real_prov_locator,
        inspection=inspection,
        registry_locator=REGISTRY_LOCATOR,
        signer_key_id=SIGNER_KEY_ID,
    )
    for field, bad_val in (
        ("archive_allowlist_passed", False),
        ("ast_boundary_scan_passed", 1),
        ("isolated_venv_import_passed", False),
        ("sorted_record_digest", "sha256:" + "0" * 64),
        ("wheel_digest", "sha256:" + "0" * 64),
        ("wheel_build_provenance_locator", cand_ref),
    ):
        tampered = copy.deepcopy(valid_rep_env)
        tampered[field] = bad_val
        with pytest.raises(ValueError):
            gov1_wheel.verify_wheel_boundary_report(tampered, wheel_path=wheel_path)


def test_staging_isolation_and_hatch_override_and_hook_rejections(
    tmp_path: Path,
) -> None:
    uv_lock_bytes = UV_LOCK_PATH.read_bytes()
    base_pyproject_text = PYPROJECT_PATH.read_text(encoding="utf-8")

    # 1. Closed hook-free pyproject.toml validation in compute_build_backend_digest
    forbidden_pyproject_mutations = [
        # build-system.backend-path
        base_pyproject_text.replace(
            'build-backend = "hatchling.build"',
            'build-backend = "hatchling.build"\nbackend-path = ["tools"]',
        ),
        # project.dynamic
        base_pyproject_text.replace(
            'license-files = []',
            'license-files = []\ndynamic = ["classifiers"]',
        ),
        # [tool.hatch.metadata]
        base_pyproject_text + "\n[tool.hatch.metadata]\nallow-direct-references = true\n",
        # [tool.hatch.version]
        base_pyproject_text + '\n[tool.hatch.version]\npath = "src/smart_ads/__init__.py"\n',
        # [tool.hatch.build.hooks.custom]
        base_pyproject_text + '\n[tool.hatch.build.hooks.custom]\npath = "tools/hook.py"\n',
        # [tool.hatch.build.targets.wheel.hooks.custom]
        base_pyproject_text + '\n[tool.hatch.build.targets.wheel.hooks.custom]\npath = "tools/hook.py"\n',
        # [tool.hatch.build.targets.sdist.hooks.custom]
        base_pyproject_text + '\n[tool.hatch.build.targets.sdist.hooks.custom]\npath = "tools/hook.py"\n',
        # [tool.hatch.build.targets.custom]
        base_pyproject_text + '\n[tool.hatch.build.targets.custom]\nonly-include = ["src/smart_ads"]\n',
        # ignore-vcs non-bool (e.g. integer 1)
        base_pyproject_text.replace("ignore-vcs = true", "ignore-vcs = 1"),
    ]
    for mutated_toml in forbidden_pyproject_mutations:
        with pytest.raises(ValueError):
            gov1_wheel.compute_build_backend_digest(
                mutated_toml.encode("utf-8"), uv_lock_bytes
            )

    # 2. Snapshot materializes EXCLUSIVELY pyproject.toml, uv.lock, and src/smart_ads/**
    repo = _init_temp_git_repo(tmp_path / "hatch_guard_repo")
    clean_whl, clean_snap = gov1_wheel.build_reproducible_wheel(
        repo, tmp_path / "clean_out"
    )
    clean_insp = gov1_wheel.inspect_wheel_boundary(clean_whl)
    assert "README.md" not in clean_snap.files
    assert "tools/decoy.py" not in clean_snap.files
    assert all(
        p in {"pyproject.toml", "uv.lock"} or p.startswith("src/smart_ads/")
        for p in clean_snap.files
    )

    # 3. Commits introducing hatch.toml, .hatch.toml, or hatch_build.py (root or nested)
    #    fail closed BEFORE any PEP 517 build or hook execution (including in verify_wheel_build_provenance!)
    marker_file = tmp_path / "hook_executed_marker.txt"
    hook_payload = (
        "from hatchling.builders.hooks.plugin.interface import BuildHookInterface\n"
        "from pathlib import Path\n"
        "class CustomBuildHook(BuildHookInterface):\n"
        "    def initialize(self, version, build_data):\n"
        f"        Path({str(marker_file)!r}).write_text('pwned', encoding='utf-8')\n"
    )
    (repo / "tools" / "evil_hook.py").write_text(hook_payload, encoding="utf-8")
    (repo / "hatch.toml").write_text(
        '[build.hooks.custom]\npath = "tools/evil_hook.py"\n',
        encoding="utf-8",
    )
    run_git_offline(repo, "add", "tools/evil_hook.py", "hatch.toml")
    run_git_offline(repo, "commit", "-q", "-m", "add hatch.toml custom hook")

    evil_commit_sha = (
        run_git_offline(repo, "rev-parse", "--verify", "HEAD^{commit}")
        .stdout.decode("ascii")
        .strip()
    )
    evil_tree_oid = (
        run_git_offline(repo, "rev-parse", "--verify", f"{evil_commit_sha}^{{tree}}")
        .stdout.decode("ascii")
        .strip()
    )

    with pytest.raises(ValueError):
        gov1_wheel.materialize_git_build_snapshot(repo, commit_ref=evil_commit_sha)
    with pytest.raises(ValueError):
        gov1_wheel.build_reproducible_wheel(
            repo, tmp_path / "evil_out", commit_ref=evil_commit_sha
        )

    # Forged provenance pointing to evil_commit_sha while reusing clean_whl bytes (which match src/smart_ads/**/*.py!)
    valid_cand = gov1_wheel.build_wheel_build_provenance_candidate(
        migration_run_context_locator=RUN_CONTEXT_LOCATOR,
        build_run_id=BUILD_RUN_ID,
        built_at_utc=BUILT_AT_UTC,
        snapshot=clean_snap,
        source_date_epoch=1_700_000_000,
        schema_bundle_digest=clean_insp["schema_bundle_digest"],
        wheel_bytes=clean_whl.read_bytes(),
    )
    forged_payload = copy.deepcopy(valid_cand["payload"])
    forged_payload["source_commit_sha"] = evil_commit_sha
    forged_payload["source_tree_oid"] = evil_tree_oid
    forged_cand = gov1_sandbox.wrap_local_candidate(
        gov1_wheel.WHEEL_BUILD_PROVENANCE_SCHEMA, forged_payload
    )
    with pytest.raises(ValueError):
        gov1_wheel.verify_wheel_build_provenance(
            forged_cand, repo_root=repo, wheel_path=clean_whl
        )
    assert not marker_file.exists(), "Custom Hatch hook must NEVER execute!"

    # Also test .hatch.toml, hatch_build.py, and nested paths
    for forbidden_rel in (
        ".hatch.toml",
        "hatch_build.py",
        "tools/hatch.toml",
        "src/smart_ads/hatch_build.py",
    ):
        run_git_offline(repo, "checkout", "-q", clean_snap.commit_sha)
        target_f = repo / forbidden_rel
        target_f.parent.mkdir(parents=True, exist_ok=True)
        target_f.write_text("# forbidden\n", encoding="utf-8")
        run_git_offline(repo, "add", forbidden_rel)
        run_git_offline(repo, "commit", "-q", "-m", f"add {forbidden_rel}")
        with pytest.raises(ValueError):
            gov1_wheel.materialize_git_build_snapshot(repo, commit_ref="HEAD")


def test_closed_pyproject_project_tool_and_toplevel_tables_rejections(
    tmp_path: Path,
) -> None:
    uv_lock_bytes = UV_LOCK_PATH.read_bytes()
    base_pyproject_text = PYPROJECT_PATH.read_text(encoding="utf-8")

    # Baseline repo pyproject.toml (with and without optional [dependency-groups] / [tool.pytest]) passes
    assert gov1_wheel.compute_build_backend_digest(
        base_pyproject_text.encode("utf-8"), uv_lock_bytes
    )[0] == "hatchling.build"

    closed_table_mutations = [
        # 1. Host-file read via [project.license] file = "/etc/hosts"
        base_pyproject_text + '\n[project.license]\nfile = "/etc/hosts"\n',
        # 2. Host-file read via [project.readme] file = "/etc/hosts"
        base_pyproject_text + '\n[project.readme]\nfile = "/etc/hosts"\n',
        # 3. Traversal glob in license-files = ["../*"]
        base_pyproject_text.replace(
            "license-files = []", 'license-files = ["../*"]'
        ),
        # 4. Omitted license-files (re-enabling Hatchling default globs)
        base_pyproject_text.replace("license-files = []\n", ""),
        # 5. Hatchling context formatting in [project.optional-dependencies]
        base_pyproject_text
        + '\n[project.optional-dependencies]\nextra = ["pkg @ file://{root:real}"]\n',
        # 6. [project.scripts], [project.gui-scripts], [project.entry-points]
        base_pyproject_text + '\n[project.scripts]\nsmart-ads = "smart_ads:main"\n',
        base_pyproject_text + '\n[project.gui-scripts]\nsmart-ads = "smart_ads:main"\n',
        base_pyproject_text
        + '\n[project.entry-points."console_scripts"]\nsmart-ads = "smart_ads:main"\n',
        # 7. Unknown key in [project] + blank/non-string description / requires-python
        base_pyproject_text.replace(
            "license-files = []", 'license-files = []\nkeywords = ["ads"]'
        ),
        base_pyproject_text.replace(
            'description = "Smart Ads Read Gateway core contracts, registry domain, and zero-I/O ProviderPort (ADR-0001)."',
            'description = "   "',
        ),
        base_pyproject_text.replace(
            'requires-python = ">=3.12"', 'requires-python = ""'
        ),
        # 8. Unknown top-level table [extra]
        base_pyproject_text + "\n[extra]\nflag = true\n",
        # 9. Unknown [tool.other] table
        base_pyproject_text + "\n[tool.other]\nflag = true\n",
        # 10. Modified or omitted targets.sdist.only-include / invalid targets.sdist.sources
        base_pyproject_text.replace(
            '[tool.hatch.build.targets.sdist]\nonly-include = ["src/smart_ads"]',
            '[tool.hatch.build.targets.sdist]\nonly-include = ["src"]',
        ),
        base_pyproject_text.replace(
            '[tool.hatch.build.targets.sdist]\nonly-include = ["src/smart_ads"]',
            "[tool.hatch.build.targets.sdist]\n",
        ),
        base_pyproject_text.replace(
            '[tool.hatch.build.targets.sdist]\nonly-include = ["src/smart_ads"]',
            '[tool.hatch.build.targets.sdist]\nonly-include = ["src/smart_ads"]\nsources = ["other"]',
        ),
    ]
    for idx, mutated_toml in enumerate(closed_table_mutations):
        with pytest.raises(ValueError, match=r".+"):
            gov1_wheel.compute_build_backend_digest(
                mutated_toml.encode("utf-8"),
                uv_lock_bytes,
            )

    # Also prove a commit attempting [project.license] file = "/etc/hosts" is rejected before PEP 517 runs
    repo = _init_temp_git_repo(tmp_path / "closed_pyproject_repo")
    (repo / "pyproject.toml").write_text(
        base_pyproject_text + '\n[project.license]\nfile = "/etc/hosts"\n',
        encoding="utf-8",
    )
    run_git_offline(repo, "add", "pyproject.toml")
    run_git_offline(repo, "commit", "-q", "-m", "attempt host file read via project.license")
    with pytest.raises(ValueError):
        gov1_wheel.build_reproducible_wheel(repo, tmp_path / "blocked_out")


