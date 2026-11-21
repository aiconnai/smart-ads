"""Tests for Task 1 & Task 2: seccomp BPF, OCI bundle layout, container runner, and readback."""
from __future__ import annotations

import ast
import base64
import copy
import errno
import gzip
import io
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys
import tarfile
import types
from types import MappingProxyType
from typing import Any

import pytest

from tools.governance import (
    gov1_7a_certification, gov1_7a_negative, gov1_7a_runner, gov1_oci_container_runner,
    gov1_oci_image, gov1_oci_readback, gov1_oci_seccomp_bpf, gov1_sandbox, gov1_wheel,
)
from tools.governance.jcs import canonicalize, loads_strict
from tools.governance.locator import digest, json_digest, make_locator

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
        (REPO_ROOT / "tools" / "governance" / "gov1_oci_image.py", 580, True, True),
        (REPO_ROOT / "tools" / "governance" / "gov1_oci_container_runner.py", 620, True, True),
        (REPO_ROOT / "tools" / "governance" / "gov1_oci_readback.py", 615, True, True),
        (Path(__file__), 700, False, False),
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
    assert {"clock_nanosleep", "nanosleep"} <= gov1_oci_seccomp_bpf.STAGE7_PEP517_EXTRA_SYSCALLS
    for allowed in ("read", "write", "clone", "clone3", "execve", "fork", "vfork", "wait4", "close_range", "clock_nanosleep", "nanosleep"):
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


def test_container_runner_constants_framing_and_ast_source_verifier() -> None:
    assert (gov1_oci_container_runner.PREMASK_BANNER, gov1_oci_container_runner.READY_BANNER, gov1_oci_container_runner.GO_BYTE) == (b"SMART-ADS-OCI-PREMASK\n", b"SMART-ADS-OCI-READY\n", b"\x02")
    gov1_oci_container_runner.verify_embedded_runner_sources()
    f_neg = gov1_oci_container_runner.encode_go_task_frame({"kind": "neg", "case_id": "socket_denied"})
    assert f_neg[0:1] == b"\x02" and struct.unpack(">I", f_neg[1:5])[0] == len(f_neg) - 5
    f_pep = gov1_oci_container_runner.encode_go_task_frame({"kind": "pep517_build", "driver_script": "x" * 10000})
    assert len(f_pep) > 10005
    for bad_spec in ({}, {"kind": "neg", "case_id": "x" * 4200}, {"kind": "pep517_build", "driver_script": "x" * 70000}):
        with pytest.raises(ValueError):
            gov1_oci_container_runner.encode_go_task_frame(bad_spec)
    for bad_src in (
        "import ctypes, os\nlibc = ctypes.CDLL(None)\nos.closerange(3, 65536)\nassert True\n",
        "import ctypes, os\nos.closerange(3, 65536)\nlibc = ctypes.CDLL(None)\n",
        "import ctypes, os\nlibc = ctypes.CDLL(None)\nos.closerange(3, 65536)\ndef big():\n" + ("    x = 1\n" * 50),
    ):
        with pytest.raises(ValueError):
            gov1_oci_container_runner._verify_single_embedded_source(bad_src, "test")


class _ExitIntercept(BaseException):
    def __init__(self, code: int) -> None:
        self.code = code


def _run_embedded_source(
    source_code: str, stdin_bytes: bytes, *, root_dir: Path | None = None,
    env_override: dict[str, str] | None = None, prctl_rc: int = 0, extra_patches: Any = None,
) -> tuple[bytes, int, list[Any]]:
    events, in_buf, out_buf, err_box = [], io.BytesIO(stdin_bytes), bytearray(), [0]
    mod = types.ModuleType("_embedded_test")
    exec(compile(source_code, "<embedded>", "exec"), mod.__dict__)
    fake_os = types.SimpleNamespace(**{k: getattr(os, k) for k in dir(os)})
    fake_os.closerange = lambda lo, hi: events.append(("closerange", lo, hi))
    fake_os.read = lambda fd, n: in_buf.read(n) if fd == 0 else os.read(fd, n)
    fake_os.write = lambda fd, data: (out_buf.extend(data), len(data))[1] if fd == 1 else os.write(fd, data)
    fake_os._exit = lambda code: (_ for _ in ()).throw(_ExitIntercept(code))
    fake_os.fstat = lambda fd: (_ for _ in ()).throw(OSError(errno.EBADF, "bad fd")) if fd >= 3 else os.fstat(fd)
    fake_os.open = lambda p, fl, m=0o777: (_ for _ in ()).throw(OSError(errno.EROFS, "ro")) if (fl & (os.O_CREAT | os.O_WRONLY | os.O_RDWR)) and Path(p).parent.is_dir() and (Path(p).parent.stat().st_mode & 0o222) == 0 else os.open(p, fl, m)
    if env_override is not None:
        fake_os.environ = env_override
    fake_libc = types.SimpleNamespace(
        prctl=lambda opt, a2, *_r: (events.append(("prctl", opt, int(a2) if isinstance(a2, int) else a2)), prctl_rc)[1],
        syscall=lambda nr, *_a: (events.append(("syscall", nr)), err_box.__setitem__(0, errno.EPERM), -1)[2],
    )
    fake_ctypes = types.SimpleNamespace(**{k: getattr(mod.ctypes, k) for k in dir(mod.ctypes)})
    fake_ctypes.CDLL = lambda *_a, **_k: (events.append(("CDLL",)), fake_libc)[1]
    fake_ctypes.set_errno = lambda v: err_box.__setitem__(0, v)
    fake_ctypes.get_errno = lambda: err_box[0]
    mod.os, mod.ctypes = fake_os, fake_ctypes
    if root_dir is not None and hasattr(mod, "_configure_roots_for_test"):
        mod._configure_roots_for_test(str(root_dir))
    if extra_patches is not None:
        extra_patches(mod, fake_os, events)
    orig_argv, orig_stdout, fd1_txt = sys.argv[:], sys.stdout, io.StringIO()
    sys.stdout = fd1_txt
    try:
        mod.main()
        rc = 0
    except _ExitIntercept as ex:
        rc = ex.code
    finally:
        sys.stdout, sys.argv = orig_stdout, orig_argv
    out_buf.extend(fd1_txt.getvalue().encode("utf-8"))
    return bytes(out_buf), rc, events


def test_container_runner_handshake_seccomp_modes_and_denial_cases(tmp_path: Path) -> None:
    root = tmp_path / "croot"
    for d in ("app", "fixtures", "tmp", "dev", "proc", "sys", "home", "etc", "usr", "var", "run", "var/run"):
        (root / d).mkdir(parents=True, exist_ok=True)
    _, bpf7a = gov1_oci_seccomp_bpf.compile_seccomp_profile_to_bpf(gov1_sandbox.build_default_7a_seccomp_profile())
    (root / "app/seccomp_filter.bpf").write_bytes(bpf7a)
    (root / "app/pep517_seccomp.bpf").write_bytes(gov1_oci_seccomp_bpf.compile_stage7_pep517_seccomp_bpf())
    for ro_d in ("dev", "home", "app", "fixtures", "etc", "usr", "var/run", "run", "var", "proc", "sys"):
        os.chmod(root / ro_d, 0o555)
    os.chmod(root, 0o555)
    src = gov1_oci_container_runner.CONTAINER_RUNNER_SOURCE
    out_eof, rc_eof, ev_eof = _run_embedded_source(src, b"\x01", root_dir=root)
    assert rc_eof == 0 and out_eof == b"SMART-ADS-OCI-PREMASK\nSMART-ADS-OCI-READY\n" and [e[0] for e in ev_eof[:4]] == ["CDLL", "closerange", "prctl", "prctl"]
    _, rc_noop, ev_s7 = _run_embedded_source(src, b"\x03" + gov1_oci_container_runner.encode_go_task_frame({"kind": "preflight_noop"}), root_dir=root)
    assert rc_noop == 0 and ("prctl", 22, 2) in ev_s7
    _, rc_skip, ev_skip = _run_embedded_source(src, b"\x00", root_dir=root)
    assert rc_skip == 0 and all(e[0] != "prctl" for e in ev_skip)
    for bad_in, bad_rc in ((b"\x09", 0), (b"\x01", -1)):
        with pytest.raises(RuntimeError):
            _run_embedded_source(src, bad_in, root_dir=root, prctl_rc=bad_rc)
    exact_env = dict(gov1_7a_negative._EXACT_ENV)
    for cid in sorted([*gov1_7a_negative._EXACT_DENIAL_OBS, *gov1_7a_negative._COUNTED_DENIAL_OBS]):
        out, rc, _ = _run_embedded_source(src, b"\x01" + gov1_oci_container_runner.encode_go_task_frame({"kind": "neg", "case_id": cid}), root_dir=root, env_override=dict(exact_env))
        assert rc == 0
        obs = loads_strict(out.split(b"SMART-ADS-OCI-READY\n", 1)[1].decode("utf-8"))
        if cid in gov1_7a_negative._EXACT_DENIAL_OBS:
            assert obs == dict(gov1_7a_negative._EXACT_DENIAL_OBS[cid])
        else:
            p_id, min_c = gov1_7a_negative._COUNTED_DENIAL_OBS[cid]
            assert obs["probe_set_id"] == p_id and obs["denied_probe_count"] >= min_c
    gov1_oci_image.cleanup_runc_bundle_trees(root)


def test_container_runner_pos_7a_pep517_and_venv_bootstrap(tmp_path: Path, head_wheel_bytes: bytes) -> None:
    from tests.governance.test_gov1_7a_verifiers import _stage_leaf_envelopes_in_store
    from tools.governance.locator import Store

    d26 = _decode_d26_fixture()
    commit_sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, check=True, capture_output=True, text=True).stdout.strip()
    git_blobs = gov1_7a_certification.resolve_7a_smart_ads_git_blobs(REPO_ROOT, commit_sha)
    reg_state, _, inv_pair = _stage_leaf_envelopes_in_store(Store(tmp_path / "store"), commit_sha=commit_sha, git_blobs=git_blobs, d26_blobs=d26)
    replay_ctx = {"snapshot": reg_state.snapshot.to_dict(), "snapshot_locator": reg_state.locator.to_dict(), "driver_contract": reg_state.driver_contract.to_dict(), "driver_contract_locator": reg_state.driver_contract_locator.to_dict(), "expected_inventory": inv_pair[1].to_dict(), "expected_inventory_locator": inv_pair[0].to_dict()}
    root = tmp_path / "pos_root"
    for rel_p, raw_b in gov1_wheel._read_and_validate_wheel_archive(head_wheel_bytes)[0].items():
        dst = root / "app/venv/lib/python3.12/site-packages" / rel_p
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(raw_b)
    for d in ("app/d26", "fixtures", "tmp"):
        (root / d).mkdir(parents=True, exist_ok=True)
    for role, rel_p, _, _ in gov1_7a_runner.PINNED_PIPEBOARD_D26_SPECS:
        (root / f"app/d26/{role}__{Path(rel_p).name}").write_bytes(d26[rel_p])
    (root / "app/seccomp_filter.bpf").write_bytes(gov1_oci_seccomp_bpf.compile_seccomp_profile_to_bpf(gov1_sandbox.build_default_7a_seccomp_profile())[1])
    (root / "fixtures/pipeboard_7a_corpus_v1.json").write_bytes(CORPUS_JSON.read_bytes())
    (root / "fixtures/replay_context_v1.json").write_bytes(canonicalize(replay_ctx))
    sbx_loc = make_locator(gov1_sandbox.SANDBOX_PROFILE_SCHEMA, b'{"sbx":1}')
    statuses = [loads_strict(_run_embedded_source(gov1_oci_container_runner.CONTAINER_RUNNER_SOURCE, b"\x01" + gov1_oci_container_runner.encode_go_task_frame({"kind": "pos_7a_case", "case_id": c["case_id"], "sealed_sandbox_profile_locator": sbx_loc}), root_dir=root)[0].split(b"SMART-ADS-OCI-READY\n", 1)[1].decode("utf-8"))["observed_completeness_status"] for c in loads_strict(CORPUS_JSON.read_text(encoding="utf-8"))["cases"]]
    assert statuses == ["complete", "failed", "partial", "partial"]
    drv_stub = "import json, pathlib, sys\n(pathlib.Path(sys.argv[4]) / 'demo.whl').write_bytes(b'PK-demo')\nsys.stdout.write(json.dumps({'wheel_name': 'demo.whl'}))\n"
    p_out, p_rc, _ = _run_embedded_source(gov1_oci_container_runner.CONTAINER_RUNNER_SOURCE, b"\x01" + gov1_oci_container_runner.encode_go_task_frame({"kind": "pep517_build", "closure_mods_csv": "hatchling", "source_date_epoch": 1700000000, "runner_bootstrap": "pass", "driver_script": drv_stub}), root_dir=root)
    assert p_rc == 0 and loads_strict(p_out.split(b"SMART-ADS-OCI-READY\n", 1)[1].decode("utf-8")) == {"wheel_name": "demo.whl", "wheel_b64": base64.b64encode(b"PK-demo").decode("ascii")}
    v_out, v_rc, _ = _run_embedded_source(gov1_oci_container_runner.VENV_PROBE_BOOTSTRAP_SOURCE, b"\x01" + gov1_oci_container_runner.encode_go_task_frame({"probe_argv": ["probe.py", "ok-val"], "probe_script": "import json, sys; sys.stdout.write(json.dumps({'arg': sys.argv[1]}))"}), root_dir=root)
    assert v_rc == 0 and loads_strict(v_out.split(b"SMART-ADS-OCI-READY\n", 1)[1].decode("utf-8")) == {"arg": "ok-val"}


def test_container_runner_resource_ceiling_cases(tmp_path: Path) -> None:
    root = tmp_path / "res_root"
    for d in ("app", "tmp"):
        (root / d).mkdir(parents=True, exist_ok=True)
    (root / "app/seccomp_filter.bpf").write_bytes(gov1_oci_seccomp_bpf.compile_seccomp_profile_to_bpf(gov1_sandbox.build_default_7a_seccomp_profile())[1])
    src = gov1_oci_container_runner.CONTAINER_RUNNER_SOURCE

    def _patch_fsize(mod: Any, fake_os: Any, _ev: list[Any]) -> None:
        handlers, written, orig_w, orig_r = {}, [0], fake_os.write, fake_os.read
        mod.signal = types.SimpleNamespace(SIGXFSZ=signal.SIGXFSZ, SIGXCPU=signal.SIGXCPU, signal=lambda s, h: handlers.__setitem__(s, h))
        fake_os.write = lambda fd, data: orig_w(fd, data) if fd in (1, 2) else ((handlers[signal.SIGXFSZ](signal.SIGXFSZ, None), (_ for _ in ()).throw(OSError(errno.EFBIG, "fbig")))[1] if written[0] >= 67_108_864 else (written.__setitem__(0, written[0] + len(data)), len(data))[1])
        fake_os.pipe = lambda: (99, 100)
        fake_os.read = lambda fd, n: (_ for _ in ()).throw(_ExitIntercept(0)) if fd == 99 else orig_r(fd, n)

    f_out, _, _ = _run_embedded_source(src, b"\x01" + gov1_oci_container_runner.encode_go_task_frame({"kind": "neg", "case_id": "file_size_limit_enforced"}), root_dir=root, extra_patches=_patch_fsize)
    assert f_out.endswith(b'{"sigxfsz":true}\n')

    def _patch_pids(_mod: Any, fake_os: Any, _ev: list[Any]) -> None:
        forks, orig_r = [0], fake_os.read
        fake_os.fork = lambda: (forks.__setitem__(0, forks[0] + 1), (_ for _ in ()).throw(OSError(errno.EAGAIN, "pids")) if forks[0] > 5 else 1000 + forks[0])[1]
        fake_os.pipe = lambda: (98, 99)
        fake_os.read = lambda fd, n: (_ for _ in ()).throw(_ExitIntercept(0)) if fd == 98 else orig_r(fd, n)

    p_out, _, _ = _run_embedded_source(src, b"\x00" + gov1_oci_container_runner.encode_go_task_frame({"kind": "neg", "case_id": "pids_limit_enforced"}), root_dir=root, extra_patches=_patch_pids)
    assert p_out.endswith(b'{"pids_eagain":true}\n')


def test_probe_7a_oci_host_and_create_7a_leaf_cgroup(tmp_path: Path) -> None:
    cg_root = tmp_path / "cgroup"
    cg_root.mkdir()
    (cg_root / "cgroup.controllers").write_text("cpu io memory pids\n", encoding="utf-8")
    for fname in ("memory.swap.max", "memory.peak", "pids.peak"):
        (cg_root / fname).write_text("0\n", encoding="utf-8")
    blocked = gov1_oci_readback.probe_7a_oci_host(cgroup_root=cg_root, runc_binary=sys.executable, sys_platform="darwin", machine="arm64", euid=501)
    assert blocked["status"] == "BLOCKED" and blocked["eligible"] is False and blocked["runc_available"] is True and "euid_not_root" in blocked["reasons"]
    elig = gov1_oci_readback.probe_7a_oci_host(cgroup_root=cg_root, runc_binary=sys.executable, sys_platform="linux", machine="x86_64", euid=0)
    assert elig["status"] == "ELIGIBLE" and elig["eligible"] is True and elig["runc_available"] is True and elig["cgroup_v2_available"] is True
    bad_oci = gov1_oci_readback.probe_7a_oci_host(base_oci_dir=tmp_path / "missing_oci", cgroup_root=cg_root, runc_binary=sys.executable, sys_platform="linux", machine="x86_64", euid=0)
    assert bad_oci["status"] == "BLOCKED" and bad_oci["base_oci_verified"] is False
    for bad_id in ("", "../bad", "a/b", "space id"):
        with pytest.raises(ValueError):
            gov1_oci_readback.create_7a_leaf_cgroup(bad_id, cgroup_root=cg_root)
    lease = gov1_oci_readback.create_7a_leaf_cgroup("inst-01", cgroup_root=cg_root)
    assert lease.cgroup_rel_path == "/smart_ads_7a/inst-01"
    assert [(lease.cgroup_dir / f).read_text(encoding="utf-8") for f in ("cpu.max", "memory.max", "memory.swap.max", "pids.max")] == ["100000 100000\n", "1073741824\n", "0\n", "32\n"]


def _build_synthetic_live_proc_and_bundle(
    tmp_path: Path, head_wheel_bytes: bytes
) -> tuple[Path, gov1_oci_readback.CgroupV2Lease, gov1_oci_image.CompositeOciBundleSpec, dict[str, Path]]:
    elf, base_dir, cg_root, proc_root = b"\x7fELF-python3.12-test", tmp_path / "base_rb", tmp_path / "cg_rb", tmp_path / "proc"
    meta = _write_synthetic_oci_layout(base_dir, [_make_tar_gz_layer([("dir", "usr/local/bin", 0o755, b""), ("reg", "usr/local/bin/python3.12", 0o755, elf)])])
    spec = gov1_oci_image.build_composite_7a_oci_layout(
        base_oci_dir=base_dir, output_layout_dir=tmp_path / "comp_rb", wheel_bytes=head_wheel_bytes, corpus_bytes=CORPUS_JSON.read_bytes(),
        replay_context_obj={"ok": 1}, resolved_d26_blobs=_decode_d26_fixture(), seccomp_profile=gov1_sandbox.build_default_7a_seccomp_profile(),
        runner_py_bytes=gov1_oci_container_runner.CONTAINER_RUNNER_SOURCE.encode("utf-8"), venv_probe_bootstrap_bytes=gov1_oci_container_runner.VENV_PROBE_BOOTSTRAP_SOURCE.encode("utf-8"),
        expected_manifest_digest=meta["manifest_digest"], expected_config_digest=meta["config_digest"], expected_layer_digests=meta["layer_digests"], expected_diff_ids=meta["diff_ids"],
    )
    trees = gov1_oci_image.materialize_runc_bundle_trees(composite_spec=spec, bundle_dir=tmp_path / "bun_rb")
    os.chmod(trees["rootfs"], 0o755)
    for sub in ("app", "fixtures"):
        (trees["rootfs"] / sub).rmdir()
        (trees["rootfs"] / sub).symlink_to(trees[sub])
    os.chmod(trees["rootfs"], 0o555)
    cg_root.mkdir()
    (cg_root / "cgroup.controllers").write_text("cpu memory pids\n", encoding="utf-8")
    lease = gov1_oci_readback.create_7a_leaf_cgroup("sbx-42", cgroup_root=cg_root)
    pid_d, self_d = proc_root / "4242", proc_root / "self"
    for d in (pid_d / "ns", self_d / "ns", pid_d / "fd", pid_d / "net", pid_d / "sys/class/net/lo"):
        d.mkdir(parents=True, exist_ok=True)
    for ns in ("mnt", "net", "pid", "ipc", "uts", "user"):
        (pid_d / "ns" / ns).symlink_to(f"{ns}:[40001]")
        (self_d / "ns" / ns).symlink_to(f"{ns}:[10001]")
    for fd_n in ("0", "1", "2"):
        (pid_d / "fd" / fd_n).write_text("", encoding="utf-8")
    (pid_d / "status").write_text("Name:\tpython3.12\nNoNewPrivs:\t1\nSeccomp:\t2\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\n", encoding="utf-8")
    (pid_d / "net/dev").write_text("Inter-|Receive\n face |bytes\n    lo: 0 0 0 0\n", encoding="utf-8")
    (pid_d / "net/if_inet6").write_text("", encoding="utf-8")
    (pid_d / "net/fib_trie").write_text("Main:\nLocal:\n", encoding="utf-8")
    (pid_d / "sys/class/net/lo/flags").write_text("0x8\n", encoding="utf-8")
    (pid_d / "limits").write_text("Limit                     Soft Limit           Hard Limit           Units\nMax cpu time              120                  120                  seconds\nMax file size             67108864             67108864             bytes\n", encoding="utf-8")
    (pid_d / "exe").write_bytes(elf)
    (pid_d / "environ").write_bytes(b"\x00".join(f"{k}={v}".encode("utf-8") for k, v in sorted(gov1_7a_negative._EXACT_ENV.items())) + b"\x00")
    (pid_d / "root").symlink_to(trees["rootfs"])
    mi = ["10 1 8:1 / / ro,relatime - ext4 /dev/sda1 ro", "11 10 8:1 /app /app ro,nosuid,nodev - ext4 /dev/sda1 ro", "12 10 8:1 /fix /fixtures ro,nosuid,nodev - ext4 /dev/sda1 ro", "13 10 0:25 / /tmp rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=262144k,nr_inodes=4096", *[f"{20 + i} 10 0:{30 + i} / {m} ro,nosuid,nodev,noexec - tmpfs tmpfs ro,size=4k,nr_inodes=16" for i, m in enumerate(gov1_7a_negative._EXACT_MASKED_MOUNTS)]]
    (pid_d / "mountinfo").write_text("\n".join(mi) + "\n", encoding="utf-8")
    return proc_root, lease, spec, trees


def test_readback_live_container_state_and_tamper_rejections(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, head_wheel_bytes: bytes
) -> None:
    proc_root, lease, spec, trees = _build_synthetic_live_proc_and_bundle(tmp_path, head_wheel_bytes)
    monkeypatch.setattr(os, "fstatvfs", lambda _fd: os.statvfs_result((4096, 4096, 65536, 65536, 65536, 4096, 4095, 4095, 0, 255)))
    rb = gov1_oci_readback.readback_live_container_state(container_pid=4242, lease=lease, composite_spec=spec, bundle_trees=trees, expect_seccomp=True, proc_root=proc_root)
    os.close(rb.tmp_fd)
    assert rb.runtime_readback["seccomp_enforced_before_entry"] is True and rb.runtime_readback["runner_binary_digest"] == spec.runner_binary_digest
    open_before = sum(1 for fd in range(3, 512) if _fd_is_open(fd))
    monkeypatch.setattr(os, "fstatvfs", lambda _fd: os.statvfs_result((4096, 4096, 100, 100, 100, 4096, 4095, 4095, 0, 255)))
    with pytest.raises(ValueError):
        gov1_oci_readback.readback_live_container_state(container_pid=4242, lease=lease, composite_spec=spec, bundle_trees=trees, expect_seccomp=True, proc_root=proc_root)
    assert sum(1 for fd in range(3, 512) if _fd_is_open(fd)) == open_before
    monkeypatch.setattr(os, "fstatvfs", lambda _fd: os.statvfs_result((4096, 4096, 65536, 65536, 65536, 4096, 4095, 4095, 0, 255)))
    pid_d = proc_root / "4242"
    with pytest.raises(ValueError):
        gov1_oci_readback.readback_live_container_state(container_pid=4242, lease=lease, composite_spec=spec, bundle_trees=trees, expect_seccomp=False, proc_root=proc_root)
    for rel_f, bad_txt, ok_txt in (("net/fib_trie", "Local:\n  |-- 127.0.0.1\n", "Main:\nLocal:\n"), ("sys/class/net/lo/flags", "0x9\n", "0x8\n")):
        (pid_d / rel_f).write_text(bad_txt, encoding="utf-8")
        with pytest.raises(ValueError):
            gov1_oci_readback.readback_live_container_state(container_pid=4242, lease=lease, composite_spec=spec, bundle_trees=trees, expect_seccomp=True, proc_root=proc_root)
        (pid_d / rel_f).write_text(ok_txt, encoding="utf-8")
    (pid_d / "exe").write_bytes(b"\x7fELF-tampered")
    with pytest.raises(ValueError):
        gov1_oci_readback.readback_live_container_state(container_pid=4242, lease=lease, composite_spec=spec, bundle_trees=trees, expect_seccomp=True, proc_root=proc_root)
    gov1_oci_image.cleanup_runc_bundle_trees(trees["bundle_dir"])


def _fd_is_open(fd: int) -> bool:
    try:
        os.fstat(fd)
        return True
    except OSError:
        return False


def test_seal_premask_harvest_usage_and_terminate_whole_cgroup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    seen_cmd, killed_pids = [], []
    monkeypatch.setattr(subprocess, "run", lambda cmd, **kw: (seen_cmd.append(list(cmd)), subprocess.CompletedProcess(cmd, 0, "", ""))[1])
    gov1_oci_readback.seal_container_premask_namespaces(4242)
    assert seen_cmd and seen_cmd[0][:4] == [sys.executable, "-I", "-B", "-S"] and seen_cmd[0][-1] == "4242"
    with pytest.raises(ValueError):
        gov1_oci_readback.seal_container_premask_namespaces(1)
    cg_root = tmp_path / "cg_u"
    cg_root.mkdir()
    lease = gov1_oci_readback.create_7a_leaf_cgroup("inst-u", cgroup_root=cg_root)
    for f, v in (("cpu.stat", "usage_usec 45678\n"), ("memory.peak", "52428800\n"), ("pids.peak", "3\n"), ("memory.events", "oom 2\noom_kill 1\n"), ("pids.events", "max 4\n")):
        (lease.cgroup_dir / f).write_text(v, encoding="utf-8")
    tmp_d = tmp_path / "tmp_u"
    (tmp_d / "sub").mkdir(parents=True)
    (tmp_d / "sub/big.bin").write_bytes(b"x" * 12345)
    (tmp_d / "sym").symlink_to(tmp_d / "sub/big.bin")
    monkeypatch.setattr(os, "fstatvfs", lambda _fd: os.statvfs_result((4096, 4096, 65536, 65500, 65500, 4096, 4000, 4000, 0, 255)))
    t_fd = os.open(tmp_d, os.O_RDONLY | os.O_DIRECTORY)
    try:
        u = gov1_oci_readback.harvest_cgroup_and_tmp_usage(lease=lease, tmp_fd=t_fd, stdout_bytes=128, stderr_bytes=64)
        assert os.fstat(t_fd).st_ino == tmp_d.stat().st_ino
    finally:
        os.close(t_fd)
    assert (u["cpu_time_us"], u["memory_peak_bytes"], u["pids_peak"], u["oom_delta"], u["oom_kill_delta"], u["pids_max_delta"], u["tmpfs_peak_bytes"], u["tmpfs_peak_inodes"], u["max_file_bytes"], u["stdout_bytes"], u["stderr_bytes"]) == (45678, 52428800, 3, 2, 1, 4, 36 * 4096, 96, 12345, 128, 64)
    (lease.cgroup_dir / "cgroup.procs").write_text("55555\n", encoding="utf-8")
    monkeypatch.setattr(os, "kill", lambda p, s: (killed_pids.append((p, s)), (lease.cgroup_dir / "cgroup.procs").write_text("", encoding="utf-8")))
    assert gov1_oci_readback.terminate_whole_cgroup(lease) is True and killed_pids == [(55555, signal.SIGKILL)]
    (lease.cgroup_dir / "cgroup.kill").write_text("0\n", encoding="utf-8")
    (lease.cgroup_dir / "cgroup.procs").write_text("", encoding="utf-8")
    assert gov1_oci_readback.terminate_whole_cgroup(lease) is True and (lease.cgroup_dir / "cgroup.kill").read_text(encoding="utf-8") == "1\n"
    (lease.cgroup_dir / "cgroup.procs").write_text("99999\n", encoding="utf-8")
    monkeypatch.setattr("time.sleep", lambda _s: None)
    ticks = iter([0.0, 0.5, 1.5])
    monkeypatch.setattr("time.monotonic", lambda: next(ticks))
    with pytest.raises(ValueError, match="whole_cgroup_empty invariant violated"):
        gov1_oci_readback.terminate_whole_cgroup(lease)
