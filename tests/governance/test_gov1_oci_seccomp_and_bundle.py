"""Tests for Task 1: `gov1_oci_seccomp_bpf.py` and `gov1_oci_image.py`."""
from __future__ import annotations

import ast
import base64
import copy
import gzip
import io
import os
from pathlib import Path
import struct
import tarfile
from types import MappingProxyType
from typing import Any

import pytest

from tools.governance import gov1_7a_runner, gov1_oci_image, gov1_oci_seccomp_bpf, gov1_sandbox, gov1_wheel
from tools.governance.jcs import canonicalize, loads_strict
from tools.governance.locator import digest, json_digest

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES_DIR = REPO_ROOT / "tests" / "certification_7a" / "fixtures"
PINNED_D26_JSON = FIXTURES_DIR / "pinned_d26c73d_blobs.json"
CORPUS_JSON = FIXTURES_DIR / "pipeboard_7a_corpus_v1.json"
_FORBIDDEN_NET_MODULES = frozenset({"urllib", "http", "socket", "ssl", "ftplib", "poplib", "imaplib", "smtplib", "xmlrpc"})


def _decode_d26_fixture() -> dict[str, bytes]:
    doc = loads_strict(PINNED_D26_JSON.read_text(encoding="utf-8"))
    return {
        rel_path: base64.b64decode(doc["blobs"][f"{role}__{Path(rel_path).name}"])
        for role, rel_path, _, _ in gov1_7a_runner.PINNED_PIPEBOARD_D26_SPECS
    }


@pytest.fixture(scope="module")
def head_wheel_bytes(tmp_path_factory: pytest.TempPathFactory) -> bytes:
    out_dir = tmp_path_factory.mktemp("task1_wheel")
    wheel_path, _ = gov1_wheel.build_reproducible_wheel(REPO_ROOT, out_dir)
    return wheel_path.read_bytes()


def _make_tar_gz_layer(specs: list[tuple[str, str, int, bytes | str]]) -> tuple[bytes, str, str]:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tf:
        for kind, name, mode, payload in specs:
            ti = tarfile.TarInfo(name="pax_entry" if "\x00" in name else name)
            ti.mtime, ti.uid, ti.gid, ti.uname, ti.gname = 0, 0, 0, "", ""
            if "\x00" in name:
                ti.pax_headers = {"path": name}
            ti.mode = mode
            if kind == "dir":
                ti.type = tarfile.DIRTYPE
                tf.addfile(ti)
            elif kind == "sym":
                ti.type = tarfile.SYMTYPE
                ti.linkname = str(payload)
                tf.addfile(ti)
            elif kind == "lnk":
                ti.type = tarfile.LNKTYPE
                ti.linkname = str(payload)
                tf.addfile(ti)
            elif kind == "chr":
                ti.type = tarfile.CHRTYPE
                ti.devmajor, ti.devminor = 1, 3
                tf.addfile(ti)
            else:
                raw = payload if isinstance(payload, bytes) else payload.encode("utf-8")
                ti.type, ti.size = tarfile.REGTYPE, len(raw)
                tf.addfile(ti, io.BytesIO(raw))
    tar_bytes = buf.getvalue()
    gz_bytes = gzip.compress(tar_bytes, compresslevel=9, mtime=0)
    return gz_bytes, digest(gz_bytes), digest(tar_bytes)


def _write_synthetic_oci_layout(
    layout_dir: Path,
    layers: list[tuple[bytes, str, str]],
    *,
    nested_index: bool = False,
    arch: str = "amd64",
    os_name: str = "linux",
) -> dict[str, Any]:
    blobs_dir = layout_dir / "blobs" / "sha256"
    blobs_dir.mkdir(parents=True, exist_ok=True)
    (layout_dir / "oci-layout").write_bytes(canonicalize({"imageLayoutVersion": "1.0.0"}))
    diff_ids = [diff_id for _, _, diff_id in layers]
    layer_descs: list[dict[str, Any]] = []
    for gz_bytes, layer_dig, _ in layers:
        (blobs_dir / layer_dig.split(":")[1]).write_bytes(gz_bytes)
        layer_descs.append({"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": layer_dig, "size": len(gz_bytes)})
    cfg_obj = {"architecture": arch, "os": os_name, "rootfs": {"type": "layers", "diff_ids": diff_ids}, "history": [{"created": "1970-01-01T00:00:00Z", "created_by": f"layer-{i}"} for i in range(len(layers))]}
    cfg_bytes = canonicalize(cfg_obj)
    cfg_dig = digest(cfg_bytes)
    (blobs_dir / cfg_dig.split(":")[1]).write_bytes(cfg_bytes)
    man_obj = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": cfg_dig, "size": len(cfg_bytes)}, "layers": layer_descs}
    man_bytes = canonicalize(man_obj)
    man_dig = digest(man_bytes)
    (blobs_dir / man_dig.split(":")[1]).write_bytes(man_bytes)
    man_desc = {"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": man_dig, "size": len(man_bytes), "platform": {"architecture": arch, "os": os_name}}
    if nested_index:
        sub_idx_bytes = canonicalize({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": [man_desc]})
        sub_idx_dig = digest(sub_idx_bytes)
        (blobs_dir / sub_idx_dig.split(":")[1]).write_bytes(sub_idx_bytes)
        top_manifests = [{"mediaType": "application/vnd.oci.image.index.v1+json", "digest": sub_idx_dig, "size": len(sub_idx_bytes)}]
    else:
        top_manifests = [man_desc]
    (layout_dir / "index.json").write_bytes(canonicalize({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": top_manifests}))
    return {"manifest_digest": man_dig, "config_digest": cfg_dig, "layer_digests": tuple(d for _, d, _ in layers), "diff_ids": tuple(diff_ids)}


def test_task1_modules_ast_purity_budgets_and_no_network_imports() -> None:
    specs = (
        (REPO_ROOT / "tools" / "governance" / "gov1_oci_seccomp_bpf.py", 420, True, False),
        (REPO_ROOT / "tools" / "governance" / "gov1_oci_image.py", 550, True, True),
        (Path(__file__), 400, False, False),
    )
    for path, max_lines, is_gov1, forbid_net in specs:
        src = path.read_text(encoding="utf-8")
        assert len(src.splitlines()) <= max_lines, f"{path.name} exceeds {max_lines} lines"
        tree = ast.parse(src, filename=str(path))
        if is_gov1:
            assert [n for n in ast.walk(tree) if isinstance(n, ast.Assert)] == []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                span = (node.end_lineno or node.lineno) - node.lineno + 1
                assert span < 50, f"{path.name}:{node.name} is {span} lines (>= 50)"
            elif is_gov1 and isinstance(node, ast.Import):
                roots = {a.name.split(".")[0] for a in node.names}
                assert "smart_ads" not in roots
                if forbid_net:
                    assert not (roots & _FORBIDDEN_NET_MODULES)
            elif is_gov1 and isinstance(node, ast.ImportFrom):
                root = (node.module or "").split(".")[0]
                assert root != "smart_ads"
                if forbid_net:
                    assert root not in _FORBIDDEN_NET_MODULES


def test_seccomp_constants_and_x86_64_syscall_numbers() -> None:
    assert gov1_oci_seccomp_bpf.AUDIT_ARCH_X86_64 == 0xC000003E
    assert gov1_oci_seccomp_bpf.SECCOMP_RET_ALLOW == 0x7FFF0000
    assert gov1_oci_seccomp_bpf.SECCOMP_RET_ERRNO_EPERM == 0x00050001
    assert gov1_oci_seccomp_bpf.SECCOMP_RET_KILL_PROCESS == 0x80000000
    assert gov1_oci_seccomp_bpf.SECCOMP_RET_KILL_THREAD == 0x00000000
    assert gov1_oci_seccomp_bpf.BPF_MAXINSNS == 4096
    tbl = gov1_oci_seccomp_bpf.X86_64_SYSCALL_NUMBERS
    assert isinstance(tbl, MappingProxyType)
    assert len(set(tbl.values())) == len(tbl)
    required = (
        set(gov1_sandbox._DEFAULT_7A_ALLOWED_SYSCALLS)
        | set(gov1_sandbox.MANDATORY_DENIED_SYSCALLS)
        | set(gov1_sandbox.KERNEL_BYPASS_DENIED_SYSCALLS)
        | set(gov1_oci_seccomp_bpf.STAGE7_PEP517_EXTRA_SYSCALLS)
    )
    assert required <= set(tbl.keys())
    expected_pairs = {
        "read": 0, "write": 1, "mmap": 9, "select": 23, "nanosleep": 35, "sendfile": 40, "socket": 41,
        "clone": 56, "fork": 57, "vfork": 58, "execve": 59, "kill": 62, "flock": 73, "fsync": 74,
        "fdatasync": 75, "umask": 95, "sysinfo": 99, "ptrace": 101, "getpgrp": 111, "setsid": 112,
        "getresuid": 118, "getresgid": 120, "getpgid": 121, "pivot_root": 155, "prctl": 157, "mount": 165,
        "clock_nanosleep": 230, "tgkill": 234, "waitid": 247, "keyctl": 250, "pselect6": 270, "ppoll": 271,
        "unshare": 272, "epoll_pwait": 281, "fallocate": 285, "open_by_handle_at": 304, "setns": 308,
        "renameat2": 316, "getrandom": 318, "memfd_create": 319, "bpf": 321, "execveat": 322,
        "copy_file_range": 326, "statx": 332, "rseq": 334, "io_uring_setup": 425, "io_uring_enter": 426,
        "io_uring_register": 427, "clone3": 435, "close_range": 436, "faccessat2": 439, "epoll_pwait2": 441,
    }
    for name, expected_nr in expected_pairs.items():
        assert tbl[name] == expected_nr, f"syscall {name}: expected {expected_nr}, got {tbl.get(name)}"


def test_compile_default_7a_seccomp_profile_and_header_guards() -> None:
    profile = gov1_sandbox.build_default_7a_seccomp_profile()
    sec_digest, bpf_bytes = gov1_oci_seccomp_bpf.compile_seccomp_profile_to_bpf(profile)
    assert sec_digest == gov1_sandbox.verify_seccomp_profile(profile)
    assert len(bpf_bytes) % 8 == 0 and 1 <= (len(bpf_bytes) // 8) <= 4096
    eval_bpf = gov1_oci_seccomp_bpf.evaluate_seccomp_bpf
    arch_x64 = gov1_oci_seccomp_bpf.AUDIT_ARCH_X86_64
    assert eval_bpf(bpf_bytes, arch=0x40000003, nr=0) == gov1_oci_seccomp_bpf.SECCOMP_RET_KILL_PROCESS
    assert eval_bpf(bpf_bytes, arch=0xC00000B7, nr=0) == gov1_oci_seccomp_bpf.SECCOMP_RET_KILL_PROCESS
    assert eval_bpf(bpf_bytes, arch=arch_x64, nr=0x40000000) == gov1_oci_seccomp_bpf.SECCOMP_RET_KILL_PROCESS
    assert eval_bpf(bpf_bytes, arch=arch_x64, nr=0x7FFFFFFF) == gov1_oci_seccomp_bpf.SECCOMP_RET_KILL_PROCESS
    assert eval_bpf(bpf_bytes, arch=arch_x64, nr=0x80000000) == gov1_oci_seccomp_bpf.SECCOMP_RET_ERRNO_EPERM
    assert eval_bpf(bpf_bytes, arch=arch_x64, nr=-1) == gov1_oci_seccomp_bpf.SECCOMP_RET_ERRNO_EPERM
    tbl = gov1_oci_seccomp_bpf.X86_64_SYSCALL_NUMBERS
    for allowed_name in gov1_sandbox._DEFAULT_7A_ALLOWED_SYSCALLS:
        assert eval_bpf(bpf_bytes, arch=arch_x64, nr=tbl[allowed_name]) == gov1_oci_seccomp_bpf.SECCOMP_RET_ALLOW
    for denied_name in (*gov1_sandbox.MANDATORY_DENIED_SYSCALLS, *gov1_sandbox.KERNEL_BYPASS_DENIED_SYSCALLS):
        assert eval_bpf(bpf_bytes, arch=arch_x64, nr=tbl[denied_name]) == gov1_oci_seccomp_bpf.SECCOMP_RET_ERRNO_EPERM
    bad_unknown = copy.deepcopy(profile)
    bad_unknown["syscalls"].append({"names": ["nonexistent_syscall_xyz"], "action": "SCMP_ACT_ALLOW"})
    with pytest.raises(ValueError):
        gov1_oci_seccomp_bpf.compile_seccomp_profile_to_bpf(bad_unknown)


def test_seccomp_all_seven_64bit_comparators_and_large_rule_jumps() -> None:
    arch_x64 = gov1_oci_seccomp_bpf.AUDIT_ARCH_X86_64
    tbl = gov1_oci_seccomp_bpf.X86_64_SYSCALL_NUMBERS
    val = (5 << 32) | 0x00000100
    profile = {
        "defaultAction": "SCMP_ACT_ERRNO",
        "architectures": ["SCMP_ARCH_X86_64"],
        "syscalls": [
            {"names": ["ioctl"], "action": "SCMP_ACT_ALLOW", "args": [{"index": 1, "value": val, "op": "SCMP_CMP_EQ"}]},
            {"names": ["fcntl"], "action": "SCMP_ACT_ALLOW", "args": [{"index": 2, "value": val, "op": "SCMP_CMP_NE"}]},
            {"names": ["lseek"], "action": "SCMP_ACT_ALLOW", "args": [{"index": 1, "value": val, "op": "SCMP_CMP_GT"}]},
            {"names": ["pread64"], "action": "SCMP_ACT_ALLOW", "args": [{"index": 3, "value": val, "op": "SCMP_CMP_GE"}]},
            {"names": ["pwrite64"], "action": "SCMP_ACT_ALLOW", "args": [{"index": 3, "value": val, "op": "SCMP_CMP_LT"}]},
            {"names": ["ftruncate"], "action": "SCMP_ACT_ALLOW", "args": [{"index": 1, "value": val, "op": "SCMP_CMP_LE"}]},
            {"names": ["mmap"], "action": "SCMP_ACT_ALLOW", "args": [{"index": 3, "value": (0xF << 32) | 0xFF, "valueTwo": (0xA << 32) | 0x12, "op": "SCMP_CMP_MASKED_EQ"}]},
            {"names": ["socket"], "action": "SCMP_ACT_KILL_PROCESS"},
            {"names": ["ptrace"], "action": "SCMP_ACT_KILL_THREAD"},
            *[{"names": ["read"], "action": "SCMP_ACT_ERRNO", "args": [{"index": 0, "value": 9000 + i, "op": "SCMP_CMP_EQ"}]} for i in range(270)],
            {"names": ["read"], "action": "SCMP_ACT_ALLOW"},
        ],
    }
    _, bpf = gov1_oci_seccomp_bpf.compile_seccomp_profile_to_bpf(profile)
    ev = gov1_oci_seccomp_bpf.evaluate_seccomp_bpf
    allow, eperm = gov1_oci_seccomp_bpf.SECCOMP_RET_ALLOW, gov1_oci_seccomp_bpf.SECCOMP_RET_ERRNO_EPERM
    assert ev(bpf, arch=arch_x64, nr=tbl["ioctl"], args=(0, val, 0, 0, 0, 0)) == allow
    assert ev(bpf, arch=arch_x64, nr=tbl["ioctl"], args=(0, (6 << 32) | 0x100, 0, 0, 0, 0)) == eperm
    assert ev(bpf, arch=arch_x64, nr=tbl["fcntl"], args=(0, 0, val, 0, 0, 0)) == eperm
    assert ev(bpf, arch=arch_x64, nr=tbl["fcntl"], args=(0, 0, val + 1, 0, 0, 0)) == allow
    assert ev(bpf, arch=arch_x64, nr=tbl["lseek"], args=(0, (6 << 32), 0, 0, 0, 0)) == allow
    assert ev(bpf, arch=arch_x64, nr=tbl["lseek"], args=(0, (4 << 32) | 0xFFFFFFFF, 0, 0, 0, 0)) == eperm
    assert ev(bpf, arch=arch_x64, nr=tbl["pread64"], args=(0, 0, 0, val, 0, 0)) == allow
    assert ev(bpf, arch=arch_x64, nr=tbl["pread64"], args=(0, 0, 0, val - 1, 0, 0)) == eperm
    assert ev(bpf, arch=arch_x64, nr=tbl["pwrite64"], args=(0, 0, 0, (4 << 32) | 0xFFFFFFFF, 0, 0)) == allow
    assert ev(bpf, arch=arch_x64, nr=tbl["pwrite64"], args=(0, 0, 0, val, 0, 0)) == eperm
    assert ev(bpf, arch=arch_x64, nr=tbl["ftruncate"], args=(0, val, 0, 0, 0, 0)) == allow
    assert ev(bpf, arch=arch_x64, nr=tbl["ftruncate"], args=(0, val + 1, 0, 0, 0, 0)) == eperm
    assert ev(bpf, arch=arch_x64, nr=tbl["mmap"], args=(0, 0, 0, (0xFA << 32) | 0x912, 0, 0)) == allow
    assert ev(bpf, arch=arch_x64, nr=tbl["mmap"], args=(0, 0, 0, (0xFB << 32) | 0x912, 0, 0)) == eperm
    assert ev(bpf, arch=arch_x64, nr=tbl["socket"]) == gov1_oci_seccomp_bpf.SECCOMP_RET_KILL_PROCESS
    assert ev(bpf, arch=arch_x64, nr=tbl["ptrace"]) == gov1_oci_seccomp_bpf.SECCOMP_RET_KILL_THREAD
    assert ev(bpf, arch=arch_x64, nr=tbl["read"], args=(9150, 0, 0, 0, 0, 0)) == eperm
    assert ev(bpf, arch=arch_x64, nr=tbl["read"], args=(0, 0, 0, 0, 0, 0)) == allow


def test_stage7_pep517_seccomp_bpf_and_vm_bounds_validation() -> None:
    bpf = gov1_oci_seccomp_bpf.compile_stage7_pep517_seccomp_bpf()
    arch_x64 = gov1_oci_seccomp_bpf.AUDIT_ARCH_X86_64
    tbl = gov1_oci_seccomp_bpf.X86_64_SYSCALL_NUMBERS
    ev = gov1_oci_seccomp_bpf.evaluate_seccomp_bpf
    assert ev(bpf, arch=0x40000003, nr=tbl["read"]) == gov1_oci_seccomp_bpf.SECCOMP_RET_KILL_PROCESS
    assert ev(bpf, arch=arch_x64, nr=0x4000003B) == gov1_oci_seccomp_bpf.SECCOMP_RET_KILL_PROCESS
    for allowed in ("read", "write", "clone", "clone3", "execve", "fork", "vfork", "wait4", "close_range"):
        assert ev(bpf, arch=arch_x64, nr=tbl[allowed]) == gov1_oci_seccomp_bpf.SECCOMP_RET_ALLOW
    for forbidden in ("socket", "connect", "mount", "pivot_root", "setns", "unshare", "ptrace", "bpf", "keyctl", "io_uring_setup"):
        assert ev(bpf, arch=arch_x64, nr=tbl[forbidden]) == gov1_oci_seccomp_bpf.SECCOMP_RET_ERRNO_EPERM
    with pytest.raises(ValueError):
        ev(b"\x00\x01\x02", arch=arch_x64, nr=0)
    with pytest.raises(ValueError):
        ev(struct.pack("<HBBI", 0x05, 0, 0, 5), arch=arch_x64, nr=0)
    with pytest.raises(ValueError):
        ev(struct.pack("<HBBI", 0x20, 0, 0, 2) + struct.pack("<HBBI", 0x06, 0, 0, 0), arch=arch_x64, nr=0)


def test_verify_pinned_base_oci_layout_direct_nested_and_tampering(tmp_path: Path) -> None:
    assert gov1_oci_image.PINNED_BASE_OCI_IMAGE_REF == "docker.io/library/python:3.12-slim-bookworm"
    assert gov1_oci_image.PINNED_BASE_OCI_MANIFEST_DIGEST.startswith("sha256:0f086103b026")
    assert len(gov1_oci_image.PINNED_BASE_OCI_LAYER_DIGESTS) == 4
    assert len(gov1_oci_image.PINNED_BASE_OCI_DIFF_IDS) == 4
    layer0 = _make_tar_gz_layer([("dir", "usr/local/bin", 0o755, b""), ("reg", "usr/local/bin/python3.12", 0o755, b"\x7fELF-py312")])
    for mode_name, nested in (("direct", False), ("nested", True)):
        base_dir = tmp_path / f"base_{mode_name}"
        meta = _write_synthetic_oci_layout(base_dir, [layer0], nested_index=nested)
        verified = gov1_oci_image.verify_pinned_base_oci_layout(
            base_dir,
            expected_manifest_digest=meta["manifest_digest"],
            expected_config_digest=meta["config_digest"],
            expected_layer_digests=meta["layer_digests"],
            expected_diff_ids=meta["diff_ids"],
        )
        assert verified["manifest_digest"] == meta["manifest_digest"]
    sym_dir = tmp_path / "sym_base"
    sym_dir.symlink_to(tmp_path / "base_direct")
    with pytest.raises(ValueError):
        gov1_oci_image.verify_pinned_base_oci_layout(sym_dir, expected_manifest_digest=meta["manifest_digest"], expected_config_digest=meta["config_digest"], expected_layer_digests=meta["layer_digests"], expected_diff_ids=meta["diff_ids"])
    with pytest.raises(ValueError):
        gov1_oci_image.verify_pinned_base_oci_layout(tmp_path / "base_direct", expected_manifest_digest=meta["manifest_digest"], expected_config_digest=meta["config_digest"], expected_layer_digests=meta["layer_digests"], expected_diff_ids=("sha256:" + "0" * 64,))
    bad_arch_dir = tmp_path / "bad_arch"
    bad_meta = _write_synthetic_oci_layout(bad_arch_dir, [layer0], arch="arm64")
    with pytest.raises(ValueError):
        gov1_oci_image.verify_pinned_base_oci_layout(bad_arch_dir, expected_manifest_digest=bad_meta["manifest_digest"], expected_config_digest=bad_meta["config_digest"], expected_layer_digests=bad_meta["layer_digests"], expected_diff_ids=bad_meta["diff_ids"])


def test_build_composite_7a_oci_layout_materialize_and_cleanup(
    tmp_path: Path, head_wheel_bytes: bytes
) -> None:
    elf_bytes = b"\x7fELF-python3.12-amd64-stub"
    layer0 = _make_tar_gz_layer([
        ("dir", "etc", 0o755, b""), ("reg", "etc/shadow", 0o640, b"root:*:19000:0:99999:7:::\n"),
        ("dir", "var", 0o755, b""), ("sym", "var/run", 0o777, "/run"),
        ("dir", "usr", 0o755, b""), ("dir", "usr/bin", 0o755, b""), ("sym", "bin", 0o777, "usr/bin"),
        ("dir", "usr/local/bin", 0o755, b""), ("reg", "usr/local/bin/python3.12", 0o4755, elf_bytes),
    ])
    base_dir = tmp_path / "base_oci"
    meta = _write_synthetic_oci_layout(base_dir, [layer0])
    d26_blobs = _decode_d26_fixture()
    corpus_bytes = CORPUS_JSON.read_bytes()
    seccomp = gov1_sandbox.build_default_7a_seccomp_profile()
    runner_py = b"#!/usr/bin/env python3\nprint('7a')\n"
    kw: dict[str, Any] = {
        "base_oci_dir": base_dir, "wheel_bytes": head_wheel_bytes, "corpus_bytes": corpus_bytes,
        "replay_context_obj": {"b": 2, "a": 1}, "resolved_d26_blobs": d26_blobs,
        "seccomp_profile": seccomp, "runner_py_bytes": runner_py,
        "expected_manifest_digest": meta["manifest_digest"], "expected_config_digest": meta["config_digest"],
        "expected_layer_digests": meta["layer_digests"], "expected_diff_ids": meta["diff_ids"],
    }
    spec1 = gov1_oci_image.build_composite_7a_oci_layout(output_layout_dir=tmp_path / "out1", **kw)
    spec2 = gov1_oci_image.build_composite_7a_oci_layout(output_layout_dir=tmp_path / "out2", **kw)
    assert spec1.oci_image_digest == spec2.oci_image_digest
    assert spec1.python_elf_sha256 == digest(elf_bytes)
    assert spec1.runner_script_sha256 == digest(runner_py)
    assert spec1.runner_binary_digest == json_digest({"kind": "smart_ads/7a_oci_runner_binary/v1", "python_elf_sha256": digest(elf_bytes), "runner_script_sha256": digest(runner_py)})
    paths = gov1_oci_image.materialize_runc_bundle_trees(composite_spec=spec1, bundle_dir=tmp_path / "bundle", extra_app_files={"probe/flag.txt": b"ok"})
    assert paths["rootfs"].joinpath("var/run").is_dir() and not paths["rootfs"].joinpath("var/run").is_symlink()
    assert (paths["rootfs"].joinpath("etc/shadow").stat().st_mode & 0o777) == 0o440
    assert (paths["rootfs"].joinpath("usr/local/bin/python3.12").stat().st_mode & 0o7777) == 0o555
    assert os.readlink(paths["rootfs"] / "usr/bin/python3") == "/usr/local/bin/python3.12"
    assert paths["app"].joinpath("probe/flag.txt").read_bytes() == b"ok"
    assert dict(gov1_7a_runner.resolve_pinned_pipeboard_d26_blobs(legacy_blobs_dir=paths["app"] / "d26")) == d26_blobs
    assert paths["fixtures"].joinpath("replay_context_v1.json").read_bytes() == b'{"a":1,"b":2}'
    gov1_oci_image.cleanup_runc_bundle_trees(tmp_path / "bundle")
    assert not (tmp_path / "bundle").exists()


def test_safe_tar_extraction_confines_symlinks_and_applies_whiteouts(
    tmp_path: Path, head_wheel_bytes: bytes
) -> None:
    l_base = _make_tar_gz_layer([
        ("dir", "usr/bin", 0o755, b""), ("sym", "bin", 0o777, "usr/bin"),
        ("dir", "dir_opq", 0o755, b""), ("reg", "dir_opq/stale.txt", 0o644, b"old"),
        ("sym", "leaf_sym", 0o777, "/usr/bin/target"),
        ("dir", "usr/local/bin", 0o755, b""), ("reg", "usr/local/bin/python3.12", 0o755, b"\x7fELF"),
    ])
    l_top = _make_tar_gz_layer([
        ("reg", "bin/hello", 0o755, b"via-usrmerge"),
        ("reg", "dir_opq/.wh..wh..opq", 0o644, b""), ("reg", "dir_opq/fresh.txt", 0o644, b"new"),
        ("reg", "leaf_sym", 0o644, b"replaced-leaf"),
    ])
    ok_base = tmp_path / "ok_base"
    ok_meta = _write_synthetic_oci_layout(ok_base, [l_base, l_top])
    spec = gov1_oci_image.build_composite_7a_oci_layout(
        base_oci_dir=ok_base, output_layout_dir=tmp_path / "ok_out", wheel_bytes=head_wheel_bytes,
        corpus_bytes=b"{}", replay_context_obj={}, resolved_d26_blobs=_decode_d26_fixture(),
        seccomp_profile=gov1_sandbox.build_default_7a_seccomp_profile(), runner_py_bytes=b"print(1)\n",
        expected_manifest_digest=ok_meta["manifest_digest"], expected_config_digest=ok_meta["config_digest"],
        expected_layer_digests=ok_meta["layer_digests"], expected_diff_ids=ok_meta["diff_ids"],
    )
    paths = gov1_oci_image.materialize_runc_bundle_trees(composite_spec=spec, bundle_dir=tmp_path / "ok_b")
    assert paths["rootfs"].joinpath("usr/bin/hello").read_bytes() == b"via-usrmerge"
    assert not paths["rootfs"].joinpath("dir_opq/stale.txt").exists() and paths["rootfs"].joinpath("dir_opq/fresh.txt").read_bytes() == b"new"
    assert not paths["rootfs"].joinpath("leaf_sym").is_symlink() and paths["rootfs"].joinpath("leaf_sym").read_bytes() == b"replaced-leaf"
    with pytest.raises(ValueError):
        gov1_oci_image.materialize_runc_bundle_trees(composite_spec=spec, bundle_dir=tmp_path / "bad_extra", extra_app_files={"../escape": b"x"})
    gov1_oci_image.cleanup_runc_bundle_trees(tmp_path / "ok_b")


def test_safe_tar_extraction_rejects_missing_python_and_escape_vectors(
    tmp_path: Path, head_wheel_bytes: bytes
) -> None:
    no_py_base = tmp_path / "no_py_base"
    no_py_meta = _write_synthetic_oci_layout(no_py_base, [_make_tar_gz_layer([("dir", "etc", 0o755, b"")])])
    with pytest.raises(ValueError):
        gov1_oci_image.build_composite_7a_oci_layout(
            base_oci_dir=no_py_base, output_layout_dir=tmp_path / "fail_out", wheel_bytes=head_wheel_bytes,
            corpus_bytes=b"{}", replay_context_obj={}, resolved_d26_blobs=_decode_d26_fixture(),
            seccomp_profile=gov1_sandbox.build_default_7a_seccomp_profile(), runner_py_bytes=b"print(1)\n",
            expected_manifest_digest=no_py_meta["manifest_digest"], expected_config_digest=no_py_meta["config_digest"],
            expected_layer_digests=no_py_meta["layer_digests"], expected_diff_ids=no_py_meta["diff_ids"],
        )
    outside_victim = tmp_path / "victim.txt"
    outside_victim.write_bytes(b"untouched")
    l_py = _make_tar_gz_layer([("dir", "usr/local/bin", 0o755, b""), ("reg", "usr/local/bin/python3.12", 0o755, b"\x7fELF")])
    bad_layers = [
        [("reg", "../escape", 0o644, b"x")],
        [("reg", "bad\x00name", 0o644, b"x")],
        [("chr", "dev/null", 0o666, b"")],
        [("sym", "esc", 0o777, "../../victim.txt")],
        [("lnk", "hl", 0o644, str(outside_victim))],
        [("sym", "loop_a", 0o777, "loop_b"), ("sym", "loop_b", 0o777, "loop_a"), ("reg", "loop_a/x", 0o644, b"1")],
    ]
    for idx, bad_entries in enumerate(bad_layers):
        bad_b = tmp_path / f"bad_b_{idx}"
        bm = _write_synthetic_oci_layout(bad_b, [l_py, _make_tar_gz_layer(bad_entries)])
        with pytest.raises(ValueError):
            bs = gov1_oci_image.build_composite_7a_oci_layout(base_oci_dir=bad_b, output_layout_dir=tmp_path / f"bad_o_{idx}", wheel_bytes=head_wheel_bytes, corpus_bytes=b"{}", replay_context_obj={}, resolved_d26_blobs=_decode_d26_fixture(), seccomp_profile=gov1_sandbox.build_default_7a_seccomp_profile(), runner_py_bytes=b"print(1)\n", expected_manifest_digest=bm["manifest_digest"], expected_config_digest=bm["config_digest"], expected_layer_digests=bm["layer_digests"], expected_diff_ids=bm["diff_ids"])
            gov1_oci_image.materialize_runc_bundle_trees(composite_spec=bs, bundle_dir=tmp_path / f"bad_m_{idx}")
    assert outside_victim.read_bytes() == b"untouched"
