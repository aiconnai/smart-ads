"""Host OCI/cgroup-v2 eligibility probe, premask namespace sealer, and live kernel readback."""
from __future__ import annotations

import ast
from collections.abc import Mapping
from dataclasses import dataclass
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import stat
import subprocess
import sys
import time
from typing import Any, Final

from tools.governance.gov1_7a_negative import (
    _EXACT_ENV, _EXACT_MASKED_MOUNTS, _EXACT_NAMESPACES, _EXACT_RO_MOUNTS,
    _EXACT_TMP_FLAGS, _EXACT_TMPFS_MOUNTS, _validate_resource_limits_dict, _validate_runtime_readback_dict,
)
from tools.governance.gov1_oci_image import CompositeOciBundleSpec, verify_pinned_base_oci_layout
from tools.governance.gov1_oci_seccomp_bpf import _unpack_and_validate_bpf_insns, compile_seccomp_profile_to_bpf
from tools.governance.gov1_sandbox import (
    SANDBOX_PROFILE_ID, SANDBOX_RESOURCES_VERSION, build_default_7a_seccomp_profile, probe_7a_host_eligibility,
)
from tools.governance.locator import digest, json_digest

_INSTANCE_ID_RE: Final[re.Pattern[str]] = re.compile(r"\A[A-Za-z0-9._-]+\Z")
_SIZE_OPT_RE: Final[re.Pattern[str]] = re.compile(r"\A([0-9]+)([kKmMgG]?)\Z")
_REQUIRED_CONTROLLERS: Final[frozenset[str]] = frozenset({"cpu", "memory", "pids"})
_EXPECTED_10_MOUNTPOINTS: Final[frozenset[str]] = frozenset({"/", "/app", "/fixtures", "/tmp", *_EXACT_MASKED_MOUNTS})
_NS_PROC_FILES: Final[tuple[str, ...]] = ("mnt", "net", "pid", "ipc", "uts", "user")
_CAP_STATUS_KEYS: Final[tuple[str, ...]] = ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")

_PREMASK_SEAL_HELPER_SOURCE: Final[str] = '''from __future__ import annotations
import ctypes, errno, fcntl, os, socket, struct, sys

def _seal_mnt_ns(libc: ctypes.CDLL, mnt_fd: int) -> None:
    if libc.setns(mnt_fd, 0x00020000) != 0:
        raise RuntimeError(f"setns(CLONE_NEWNS) failed: errno={ctypes.get_errno()}")
    ro_flags, remount_bind_ro = (1 | 2 | 4 | 8), (32 | 4096 | 1 | 2 | 4 | 8)
    for target in (b"/proc", b"/dev"):
        if libc.umount2(target, 2) != 0:
            raise RuntimeError(f"umount2({target!r}, MNT_DETACH) failed: errno={ctypes.get_errno()}")
        if libc.mount(b"tmpfs", target, b"tmpfs", ro_flags, b"size=4096,nr_inodes=16,mode=0555") != 0:
            raise RuntimeError(f"mount(tmpfs -> {target!r}) failed: errno={ctypes.get_errno()}")
        if libc.mount(b"tmpfs", target, None, remount_bind_ro, None) != 0:
            raise RuntimeError(f"remount(MS_BIND|MS_RDONLY -> {target!r}) failed: errno={ctypes.get_errno()}")

def _seal_net_ns(libc: ctypes.CDLL, net_fd: int) -> None:
    if libc.setns(net_fd, 0x40000000) != 0:
        raise RuntimeError(f"setns(CLONE_NEWNET) failed: errno={ctypes.get_errno()}")
    io_sock, nl_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0), socket.socket(16, socket.SOCK_RAW, 0)
    try:
        lo_idx = struct.unpack_from("16si", fcntl.ioctl(io_sock.fileno(), 0x8933, struct.pack("16s24s", b"lo", b"\\x00" * 24)), 0)[1]
        nl_sock.bind((0, 0))
        ifa = struct.pack("<BBBBI", 2, 8, 0, 0, lo_idx)
        rta = struct.pack("<HH4s", 8, 2, b"\\x7f\\x00\\x00\\x01") + struct.pack("<HH4s", 8, 1, b"\\x7f\\x00\\x00\\x01")
        nl_sock.sendall(struct.pack("<IHHII", 16 + len(ifa) + len(rta), 21, 0x0005, 1, 0) + ifa + rta)
        ack = nl_sock.recv(4096)
        if len(ack) < 20:
            raise RuntimeError("short netlink ACK on RTM_DELADDR")
        _, r_type, _, _, _, nl_err = struct.unpack_from("<IHHIIi", ack, 0)
        if r_type != 2 or nl_err not in (0, -errno.EADDRNOTAVAIL):
            raise RuntimeError(f"RTM_DELADDR(127.0.0.1/8) failed: type={r_type} err={nl_err}")
        flags = struct.unpack_from("<H", fcntl.ioctl(io_sock.fileno(), 0x8913, struct.pack("16s24s", b"lo", b"\\x00" * 24)), 16)[0]
        fcntl.ioctl(io_sock.fileno(), 0x8914, struct.pack("16sH22s", b"lo", flags & ~0x1, b"\\x00" * 22))
    finally:
        nl_sock.close()
        io_sock.close()

def main() -> None:
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise RuntimeError("seal_container_premask_namespaces requires euid == 0")
    pid, libc = int(sys.argv[1]), ctypes.CDLL(None, use_errno=True)
    libc.setns.argtypes, libc.setns.restype = [ctypes.c_int, ctypes.c_int], ctypes.c_int
    libc.umount2.argtypes, libc.umount2.restype = [ctypes.c_char_p, ctypes.c_int], ctypes.c_int
    libc.mount.argtypes, libc.mount.restype = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_char_p], ctypes.c_int
    mnt_fd, net_fd = os.open(f"/proc/{pid}/ns/mnt", os.O_RDONLY), os.open(f"/proc/{pid}/ns/net", os.O_RDONLY)
    try:
        _seal_mnt_ns(libc, mnt_fd)
        _seal_net_ns(libc, net_fd)
    finally:
        os.close(net_fd)
        os.close(mnt_fd)

if __name__ == "__main__":
    main()
'''

_NETNS_LO_FLAGS_HELPER_SOURCE: Final[str] = '''from __future__ import annotations
import ctypes, fcntl, os, socket, struct, sys

def main() -> None:
    pid, libc = int(sys.argv[1]), ctypes.CDLL(None, use_errno=True)
    libc.setns.argtypes, libc.setns.restype = [ctypes.c_int, ctypes.c_int], ctypes.c_int
    net_fd = os.open(f"/proc/{pid}/ns/net", os.O_RDONLY)
    try:
        if libc.setns(net_fd, 0x40000000) != 0:
            raise RuntimeError("setns(CLONE_NEWNET) failed")
    finally:
        os.close(net_fd)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
    try:
        raw = fcntl.ioctl(sock.fileno(), 0x8913, struct.pack("16s24s", b"lo", b"\\x00" * 24))
        sys.stdout.write(f"0x{struct.unpack_from(\'<H\', raw, 16)[0]:x}\\n")
    finally:
        sock.close()

if __name__ == "__main__":
    main()
'''


@dataclass(frozen=True, slots=True)
class CgroupV2Lease:
    instance_id: str
    cgroup_dir: Path
    cgroup_rel_path: str
    baseline_oom: int
    baseline_oom_kill: int
    baseline_pids_max: int


@dataclass(frozen=True, slots=True)
class LiveContainerReadback:
    runtime_readback: dict[str, Any]
    effective_resource_limits: dict[str, Any]
    tmp_fd: int


def _verify_helper_scripts() -> None:
    for label, src in (("_PREMASK_SEAL_HELPER_SOURCE", _PREMASK_SEAL_HELPER_SOURCE), ("_NETNS_LO_FLAGS_HELPER_SOURCE", _NETNS_LO_FLAGS_HELPER_SOURCE)):
        for node in ast.walk(ast.parse(src, filename=label)):
            if isinstance(node, ast.Assert):
                raise ValueError(f"{label}: ast.Assert is forbidden")
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and (node.end_lineno or node.lineno) - node.lineno + 1 >= 50:
                raise ValueError(f"{label}:{node.name} exceeds 49 lines")


def _probe_runc_binary(runc_binary: str) -> tuple[bool, str | None]:
    resolved = shutil.which(runc_binary)
    if resolved is None:
        return False, None
    try:
        proc = subprocess.run([resolved, "--version"], capture_output=True, text=True, timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return False, None
    return (True, proc.stdout.splitlines()[0].strip()) if proc.returncode == 0 and proc.stdout.strip() else (False, None)


def _probe_cgroup_v2(cg_root: Path, eff_euid: int) -> tuple[bool, list[str], list[str]]:
    ctrl_file = cg_root / "cgroup.controllers"
    if ctrl_file.is_symlink() or not ctrl_file.is_file():
        return False, [], []
    try:
        controllers = sorted(set(ctrl_file.read_text(encoding="utf-8").split()))
    except OSError:
        return False, [], []
    if not _REQUIRED_CONTROLLERS.issubset(controllers):
        return False, controllers, ["missing_cgroup_controllers"]
    swap_ok = (cg_root / "memory.swap.max").is_file() or (cg_root / "smart_ads_7a/memory.swap.max").is_file()
    if not swap_ok:
        try:
            swap_ok = any(p.is_dir() and not p.is_symlink() and (p / "memory.swap.max").is_file() for p in cg_root.iterdir())
        except OSError:
            swap_ok = False
    if not swap_ok and eff_euid == 0:
        parent, probe_leaf = cg_root / "smart_ads_7a", cg_root / "smart_ads_7a" / f".swap_probe_{os.getpid()}"
        try:
            parent.mkdir(mode=0o755, exist_ok=True)
            for sc in (cg_root / "cgroup.subtree_control", parent / "cgroup.subtree_control"):
                if sc.exists():
                    sc.write_text("+cpu +memory +pids\n", encoding="utf-8")
            probe_leaf.mkdir(mode=0o755, exist_ok=True)
            swap_ok = (probe_leaf / "memory.swap.max").exists()
        except OSError:
            swap_ok = False
        finally:
            try:
                if probe_leaf.exists():
                    os.rmdir(probe_leaf)
            except OSError:
                pass
    return swap_ok, controllers, ([] if swap_ok else ["memory_swap_max_unavailable"])


def probe_7a_oci_host(
    *, base_oci_dir: Path | None = None, cgroup_root: Path = Path("/sys/fs/cgroup"),
    runc_binary: str = "runc", sys_platform: str | None = None,
    machine: str | None = None, euid: int | None = None,
) -> dict[str, Any]:
    """Probe Linux amd64 root, `runc`, cgroup-v2 controllers + swap, and optional base OCI layout."""
    if (sys_platform is not None and type(sys_platform) is not str) or (machine is not None and type(machine) is not str):
        raise ValueError("sys_platform and machine must be str or None")
    if (euid is not None and type(euid) is not int) or type(runc_binary) is not str or not runc_binary.strip():
        raise ValueError("euid must be strict int or None and runc_binary must be non-empty str")
    eff_platform = sys.platform if sys_platform is None else sys_platform
    eff_machine = platform.machine() if machine is None else machine
    eff_euid = (os.geteuid() if hasattr(os, "geteuid") else -1) if euid is None else euid
    runc_ok, runc_ver = _probe_runc_binary(runc_binary)
    cg_ok, controllers, cg_reasons = _probe_cgroup_v2(Path(cgroup_root), eff_euid)
    base_probe = probe_7a_host_eligibility(sys_platform=eff_platform, machine=eff_machine, in_sealed_oci_supervisor=(eff_euid == 0 and runc_ok), cgroup_v2_available=cg_ok)
    reasons = list(base_probe["reasons"])
    for extra in (*(("euid_not_root",) if eff_euid != 0 else ()), *(("runc_unavailable",) if not runc_ok else ()), *cg_reasons):
        if extra not in reasons:
            reasons.append(extra)
    base_verified: bool | None = None
    if base_oci_dir is not None:
        try:
            verify_pinned_base_oci_layout(Path(base_oci_dir))
            base_verified = True
        except (ValueError, OSError):
            base_verified = False
            reasons.append("base_oci_verification_failed")
    eligible = len(reasons) == 0
    return {
        "status": "ELIGIBLE" if eligible else "BLOCKED", "eligible": eligible, "profile_id": SANDBOX_PROFILE_ID,
        "sys_platform": eff_platform, "machine": eff_machine, "euid": eff_euid, "runc_available": runc_ok,
        "runc_version": runc_ver, "cgroup_v2_available": cg_ok, "cgroup_controllers": controllers,
        "base_oci_verified": base_verified, "reasons": reasons,
    }


def _parse_cgroup_kv_int_file(path: Path, label: str) -> dict[str, int]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label}: missing cgroup file {path}")
    return {p[0]: int(p[1]) for ln in path.read_text(encoding="utf-8").splitlines() if len(p := ln.strip().split()) == 2 and p[1].isascii() and p[1].isdigit()}


def _write_cgroup_attr(path: Path, text: str, *, real_cgroupfs: bool) -> None:
    if path.is_symlink():
        raise ValueError(f"cgroup attribute symlink forbidden: {path}")
    data = text.encode("utf-8")
    fd = os.open(path, os.O_WRONLY if real_cgroupfs else (os.O_WRONLY | os.O_CREAT | os.O_TRUNC), 0o644)
    try:
        if os.write(fd, data) != len(data):
            raise ValueError(f"short write on cgroup attribute {path}")
    finally:
        os.close(fd)


def create_7a_leaf_cgroup(instance_id: str, *, cgroup_root: Path = Path("/sys/fs/cgroup")) -> CgroupV2Lease:
    """Create `/smart_ads_7a/<instance_id>` leaf cgroup with pinned 7A limits and baseline counters."""
    if type(instance_id) is not str or instance_id in {".", ".."} or _INSTANCE_ID_RE.fullmatch(instance_id) is None:
        raise ValueError(f"instance_id: invalid identifier {instance_id!r}")
    cg_root = Path(cgroup_root)
    if cg_root.is_symlink() or not cg_root.is_dir():
        raise ValueError(f"cgroup_root: expected non-symlink directory at {cg_root}")
    real_cgfs = sys.platform == "linux" and cg_root.resolve() == Path("/sys/fs/cgroup").resolve()
    parent = cg_root / "smart_ads_7a"
    if parent.is_symlink():
        raise ValueError("cgroup parent symlink forbidden")
    parent.mkdir(mode=0o755, exist_ok=True)
    for sc in (cg_root / "cgroup.subtree_control", parent / "cgroup.subtree_control"):
        if sc.exists() or not real_cgfs:
            _write_cgroup_attr(sc, "+cpu +memory +pids\n", real_cgroupfs=real_cgfs and sc.exists())
    leaf = parent / instance_id
    if leaf.exists() or leaf.is_symlink():
        raise ValueError(f"cgroup leaf already exists: {leaf}")
    leaf.mkdir(mode=0o755, exist_ok=False)
    for fname, val in (("cpu.max", "100000 100000\n"), ("memory.max", "1073741824\n"), ("memory.swap.max", "0\n"), ("pids.max", "32\n")):
        _write_cgroup_attr(leaf / fname, val, real_cgroupfs=real_cgfs)
    if not real_cgfs:
        for s_name, s_val in (("memory.events", "oom 0\noom_kill 0\n"), ("pids.events", "max 0\n"), ("cpu.stat", "usage_usec 0\n"), ("memory.peak", "0\n"), ("pids.peak", "0\n"), ("cgroup.procs", "")):
            if not (leaf / s_name).exists():
                (leaf / s_name).write_text(s_val, encoding="utf-8")
    mem_ev, pids_ev = _parse_cgroup_kv_int_file(leaf / "memory.events", "memory.events"), _parse_cgroup_kv_int_file(leaf / "pids.events", "pids.events")
    if "oom" not in mem_ev or "oom_kill" not in mem_ev or "max" not in pids_ev:
        raise ValueError("cgroup baseline events missing oom, oom_kill, or pids max")
    return CgroupV2Lease(instance_id, leaf, f"/smart_ads_7a/{instance_id}", mem_ev["oom"], mem_ev["oom_kill"], pids_ev["max"])


def seal_container_premask_namespaces(container_pid: int) -> None:
    """Detach `/proc` and `/dev` replacing with ro empty tmpfs and down/purge `lo` in container netns."""
    if type(container_pid) is not int or container_pid <= 1:
        raise ValueError(f"container_pid: expected int > 1, got {container_pid!r}")
    try:
        proc = subprocess.run([sys.executable, "-I", "-B", "-S", "-c", _PREMASK_SEAL_HELPER_SOURCE, str(container_pid)], capture_output=True, text=True, timeout=15, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError(f"seal_container_premask_namespaces subprocess failed: {exc}") from exc
    if proc.returncode != 0:
        raise ValueError(f"seal_container_premask_namespaces failed (rc={proc.returncode}): {proc.stderr.strip()}")


def _check_namespaces_status_and_fds(pid_dir: Path, self_dir: Path, *, expect_seccomp: bool) -> None:
    for ns_name in _NS_PROC_FILES:
        cont_ns, host_ns = os.readlink(pid_dir / "ns" / ns_name), os.readlink(self_dir / "ns" / ns_name)
        if not cont_ns or not host_ns or cont_ns == host_ns:
            raise ValueError(f"namespace {ns_name!r} is not isolated from supervisor")
    status_kv = {ln.split(":", 1)[0].strip(): ln.split(":", 1)[1].strip() for ln in (pid_dir / "status").read_text(encoding="utf-8").splitlines() if ":" in ln}
    if any(status_kv.get(k) != "0000000000000000" for k in _CAP_STATUS_KEYS):
        raise ValueError("status capability masks are non-zero")
    if status_kv.get("NoNewPrivs") != "1" or status_kv.get("Seccomp") != ("2" if expect_seccomp else "0"):
        raise ValueError("status.NoNewPrivs or status.Seccomp mismatch")
    raw_fds = os.listdir(pid_dir / "fd")
    if any(not (x.isascii() and x.isdigit()) for x in raw_fds) or not ({int(x) for x in raw_fds} <= {0, 1, 2}):
        raise ValueError(f"container has open FDs above 2: {sorted(raw_fds)!r}")
    if (pid_dir / "environ").is_file():
        items = [seg.decode("utf-8") for seg in (pid_dir / "environ").read_bytes().split(b"\x00") if seg]
        if any("=" not in it for it in items) or dict(it.split("=", 1) for it in items) != dict(_EXACT_ENV):
            raise ValueError("proc/environ mismatch against exact 7A environment")


def _check_netns_and_loopback_absent(pid_dir: Path, proc_root: Path, container_pid: int) -> None:
    dev_lines = (pid_dir / "net/dev").read_text(encoding="utf-8").splitlines()
    if [ln.split(":", 1)[0].strip() for ln in dev_lines[2:] if ln.strip()] != ["lo"]:
        raise ValueError("net/dev: expected only ['lo']")
    if (pid_dir / "net/if_inet6").read_text(encoding="utf-8").strip() != "":
        raise ValueError("net/if_inet6: expected empty IPv6 address table")
    fib_text = (pid_dir / "net/fib_trie").read_text(encoding="utf-8")
    if "127.0.0.1" in fib_text or "/32 host LOCAL" in fib_text:
        raise ValueError("net/fib_trie: loopback IPv4 address still present")
    flags_file = pid_dir / "sys/class/net/lo/flags"
    if flags_file.is_file():
        if (int(flags_file.read_text(encoding="utf-8").strip(), 16) & 0x1) != 0:
            raise ValueError("loopback interface 'lo' has IFF_UP flag set")
    elif sys.platform == "linux" and proc_root.resolve() == Path("/proc").resolve() and hasattr(os, "geteuid") and os.geteuid() == 0:
        proc = subprocess.run([sys.executable, "-I", "-B", "-S", "-c", _NETNS_LO_FLAGS_HELPER_SOURCE, str(container_pid)], capture_output=True, text=True, timeout=10, check=False)
        if proc.returncode != 0 or (int(proc.stdout.strip(), 16) & 0x1) != 0:
            raise ValueError("netns ioctl confirmed 'lo' is UP or unreadable")


def _parse_size_opt_bytes(raw_val: str) -> int:
    if (m := _SIZE_OPT_RE.fullmatch(raw_val)) is None:
        raise ValueError(f"mountinfo /tmp invalid size= option: {raw_val!r}")
    num, unit = int(m.group(1)), m.group(2).lower()
    return num * (1 if unit == "" else (1024 if unit == "k" else (1048576 if unit == "m" else 1073741824)))


def _check_mountinfo_and_masks(pid_dir: Path, bundle_trees: Mapping[str, Path]) -> tuple[int, int, list[str]]:
    mounts: dict[str, tuple[set[str], list[str]]] = {}
    for ln in (pid_dir / "mountinfo").read_text(encoding="utf-8").splitlines():
        if not ln.strip():
            continue
        if " - " not in ln:
            raise ValueError(f"malformed mountinfo line: {ln!r}")
        pre_f, post_f = (seg.split() for seg in ln.split(" - ", 1))
        if len(pre_f) < 6 or len(post_f) < 3 or pre_f[4] in mounts:
            raise ValueError(f"invalid or duplicate mountpoint in mountinfo: {ln!r}")
        mounts[pre_f[4]] = (set(pre_f[5].split(",")), post_f[2].split(","))
    if set(mounts.keys()) != _EXPECTED_10_MOUNTPOINTS:
        raise ValueError(f"mountinfo mountpoints mismatch: {sorted(mounts.keys())!r}")
    for mp, (vfs_opts, _) in mounts.items():
        if mp == "/tmp" and ("rw" not in vfs_opts or "ro" in vfs_opts or not set(_EXACT_TMP_FLAGS).issubset(vfs_opts)):
            raise ValueError(f"mountinfo /tmp VFS flags invalid: {sorted(vfs_opts)!r}")
        if mp != "/tmp" and ("ro" not in vfs_opts or "rw" in vfs_opts or (mp in _EXACT_MASKED_MOUNTS and not set(_EXACT_TMP_FLAGS).issubset(vfs_opts))):
            raise ValueError(f"mountinfo {mp} read-only/masked VFS flags invalid")
    tmp_sb = {kv.split("=", 1)[0]: kv.split("=", 1)[1] for kv in mounts["/tmp"][1] if "=" in kv}
    if "size" not in tmp_sb or "nr_inodes" not in tmp_sb or not tmp_sb["nr_inodes"].isdigit():
        raise ValueError("mountinfo /tmp superblock missing size= or nr_inodes=")
    cont_root = pid_dir / "root"
    for masked in _EXACT_MASKED_MOUNTS:
        m_dir = cont_root / masked.lstrip("/")
        if m_dir.is_symlink() or not m_dir.is_dir() or os.listdir(m_dir) != []:
            raise ValueError(f"masked mount {masked} is symlink, non-dir, or non-empty")
    for rel, tree_key in (("", "rootfs"), ("app", "app"), ("fixtures", "fixtures")):
        c_st, b_st = os.stat(cont_root / rel if rel else cont_root), os.stat(bundle_trees[tree_key])
        if (c_st.st_dev, c_st.st_ino) != (b_st.st_dev, b_st.st_ino):
            raise ValueError(f"container /{rel} (st_dev, st_ino) mismatch against bundle_trees[{tree_key!r}]")
    return _parse_size_opt_bytes(tmp_sb["size"]), int(tmp_sb["nr_inodes"]), sorted(_EXACT_TMP_FLAGS)


def _check_runner_and_seccomp_digests(
    pid_dir: Path, composite_spec: CompositeOciBundleSpec,
    bundle_trees: Mapping[str, Path], seccomp_profile: dict[str, Any] | None,
) -> str:
    exe_sha = digest((pid_dir / "exe").read_bytes())
    runner_path, bpf_path = pid_dir / "root/app/runner.py", pid_dir / "root/app/seccomp_filter.bpf"
    if runner_path.is_symlink() or not runner_path.is_file() or bpf_path.is_symlink() or not bpf_path.is_file():
        raise ValueError("container /app/runner.py or /app/seccomp_filter.bpf missing or symlink")
    runner_sha = digest(runner_path.read_bytes())
    recomputed = json_digest({"kind": "smart_ads/7a_oci_runner_binary/v1", "python_elf_sha256": exe_sha, "runner_script_sha256": runner_sha})
    if (exe_sha, runner_sha, recomputed) != (composite_spec.python_elf_sha256, composite_spec.runner_script_sha256, composite_spec.runner_binary_digest):
        raise ValueError("live container exe/runner.py digest mismatch against composite_spec")
    bpf_bytes = bpf_path.read_bytes()
    _unpack_and_validate_bpf_insns(bpf_bytes)
    if bpf_bytes != (bundle_trees["app"] / "seccomp_filter.bpf").read_bytes():
        raise ValueError("container /app/seccomp_filter.bpf diverges from materialized app tree")
    if seccomp_profile is not None:
        prof_dig, exp_bpf = compile_seccomp_profile_to_bpf(seccomp_profile)
        if prof_dig != composite_spec.seccomp_profile_digest or bpf_bytes != exp_bpf:
            raise ValueError("container /app/seccomp_filter.bpf mismatch against seccomp_profile")
    else:
        def_dig, def_bpf = compile_seccomp_profile_to_bpf(build_default_7a_seccomp_profile())
        if (bpf_bytes == def_bpf) != (composite_spec.seccomp_profile_digest == def_dig):
            raise ValueError("container /app/seccomp_filter.bpf mismatch against default 7A seccomp digest")
    return recomputed


def _read_cgroup_and_rlimits(pid_dir: Path, lease: CgroupV2Lease) -> tuple[int, int, int, int, int, int, int]:
    cpu_parts = (lease.cgroup_dir / "cpu.max").read_text(encoding="utf-8").strip().split()
    if len(cpu_parts) != 2 or not all(p.isascii() and p.isdigit() for p in cpu_parts):
        raise ValueError(f"cgroup cpu.max invalid: {cpu_parts!r}")
    raw_vals: list[int] = []
    for fname in ("memory.max", "memory.swap.max", "pids.max"):
        txt = (lease.cgroup_dir / fname).read_text(encoding="utf-8").strip()
        if not (txt.isascii() and txt.isdigit()):
            raise ValueError(f"cgroup {fname} invalid integer: {txt!r}")
        raw_vals.append(int(txt))
    cpu_soft, fsize_soft, fsize_hard = -1, -1, -1
    for ln in (pid_dir / "limits").read_text(encoding="utf-8").splitlines():
        if ln.startswith("Max cpu time") and len(cols := ln[len("Max cpu time") :].split()) >= 2 and cols[0].isdigit():
            cpu_soft = int(cols[0])
        elif ln.startswith("Max file size") and len(cols := ln[len("Max file size") :].split()) >= 2 and cols[0].isdigit() and cols[1].isdigit():
            fsize_soft, fsize_hard = int(cols[0]), int(cols[1])
    if (cpu_soft, fsize_soft, fsize_hard) != (120, 67_108_864, 67_108_864):
        raise ValueError("proc/limits mismatch: expected cpu_soft=120 and fsize=67108864")
    return int(cpu_parts[0]), int(cpu_parts[1]), raw_vals[0], raw_vals[1], raw_vals[2], cpu_soft, fsize_hard


def readback_live_container_state(
    *, container_pid: int, lease: CgroupV2Lease, composite_spec: CompositeOciBundleSpec,
    bundle_trees: Mapping[str, Path], expect_seccomp: bool,
    proc_root: Path = Path("/proc"), self_pid_label: str = "self",
    seccomp_profile: dict[str, Any] | None = None,
) -> LiveContainerReadback:
    """Verify live container `/proc/<pid>` and cgroup-v2 state before delivering `GO`."""
    if type(container_pid) is not int or container_pid <= 0 or type(expect_seccomp) is not bool:
        raise ValueError("container_pid must be positive int and expect_seccomp must be bool")
    if not isinstance(lease, CgroupV2Lease) or not isinstance(composite_spec, CompositeOciBundleSpec) or not isinstance(bundle_trees, Mapping) or not {"rootfs", "app", "fixtures"}.issubset(bundle_trees.keys()):
        raise ValueError("lease, composite_spec, or bundle_trees type/key mismatch")
    p_root = Path(proc_root)
    pid_dir, self_dir = p_root / str(container_pid), p_root / self_pid_label
    try:
        _check_namespaces_status_and_fds(pid_dir, self_dir, expect_seccomp=expect_seccomp)
        _check_netns_and_loopback_absent(pid_dir, p_root, container_pid)
        tmp_size, tmp_inodes, tmp_flags = _check_mountinfo_and_masks(pid_dir, bundle_trees)
        runner_digest = _check_runner_and_seccomp_digests(pid_dir, composite_spec, bundle_trees, seccomp_profile)
        quota_us, period_us, mem_max, swap_max, pids_max, cpu_soft, fsize_hard = _read_cgroup_and_rlimits(pid_dir, lease)
        tmp_fd = os.open(pid_dir / "root/tmp", os.O_RDONLY | os.O_DIRECTORY)
    except OSError as exc:
        raise ValueError(f"live container readback I/O failed: {exc}") from exc
    try:
        vfs = os.fstatvfs(tmp_fd)
        if vfs.f_blocks * vfs.f_frsize != 268_435_456 or vfs.f_files != 4096:
            raise ValueError("fstatvfs(/tmp) size_bytes or inodes_max mismatch")
        rb = _validate_runtime_readback_dict({"profile_id": SANDBOX_PROFILE_ID, "runtime_kind": "oci", "platform": "linux/amd64", "rootfs_read_only": True, "oci_image_digest": composite_spec.oci_image_digest, "runner_binary_digest": runner_digest, "exact_environment": dict(_EXACT_ENV), "namespaces": list(_EXACT_NAMESPACES), "read_only_mounts": list(_EXACT_RO_MOUNTS), "fresh_tmpfs_mounts": list(_EXACT_TMPFS_MOUNTS), "masked_empty_mounts": list(_EXACT_MASKED_MOUNTS), "host_bind_mounts_forbidden": True, "all_capabilities_dropped": True, "no_new_privs": True, "inherited_fds_above_2_closed": True, "seccomp_profile_digest": composite_spec.seccomp_profile_digest, "effective_writable_mounts": ["/tmp"], "seccomp_enforced_before_entry": expect_seccomp, "network_absent": True, "loopback_absent": True}, "runtime_readback")
        lim = _validate_resource_limits_dict({"profile_version": SANDBOX_RESOURCES_VERSION, "cgroup_version": 2, "cpu_max": {"quota_us": quota_us, "period_us": period_us}, "cpu_time_limit_seconds": cpu_soft, "memory_max_bytes": mem_max, "memory_swap_max_bytes": swap_max, "pids_max": pids_max, "tmpfs_limits": {"/tmp": {"size_bytes": tmp_size, "inodes_max": tmp_inodes, "mount_flags": tmp_flags}}, "rlimit_fsize_bytes": fsize_hard, "stdout_max_bytes": 8_388_608, "stderr_max_bytes": 8_388_608, "wall_clock_timeout_seconds": 300, "termination_grace_ms": 1000}, "effective_resource_limits")
    except BaseException:
        os.close(tmp_fd)
        raise
    return LiveContainerReadback(runtime_readback=rb, effective_resource_limits=lim, tmp_fd=tmp_fd)


def _walk_tmp_max_regular_file_bytes(tmp_fd: int) -> int:
    max_bytes, stack, no_follow = 0, [os.dup(tmp_fd)], getattr(os, "O_NOFOLLOW", 0)
    try:
        while stack:
            cur_fd = stack.pop()
            try:
                with os.scandir(os.dup(cur_fd)) as entries:
                    for entry in entries:
                        st = os.stat(entry.name, dir_fd=cur_fd, follow_symlinks=False)
                        if stat.S_ISREG(st.st_mode) and st.st_size > max_bytes:
                            max_bytes = st.st_size
                        elif stat.S_ISDIR(st.st_mode):
                            stack.append(os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | no_follow, dir_fd=cur_fd))
            finally:
                os.close(cur_fd)
    finally:
        for rem_fd in stack:
            os.close(rem_fd)
    return max_bytes


def harvest_cgroup_and_tmp_usage(
    *, lease: CgroupV2Lease, tmp_fd: int, stdout_bytes: int, stderr_bytes: int
) -> dict[str, int]:
    """Harvest cumulative cgroup-v2 peak/event deltas and `/tmp` byte/inode/file usage."""
    if not isinstance(lease, CgroupV2Lease) or type(tmp_fd) is not int or tmp_fd < 0:
        raise ValueError("invalid lease or tmp_fd")
    if type(stdout_bytes) is not int or stdout_bytes < 0 or type(stderr_bytes) is not int or stderr_bytes < 0:
        raise ValueError("stdout_bytes and stderr_bytes must be non-negative ints")
    cpu_stat = _parse_cgroup_kv_int_file(lease.cgroup_dir / "cpu.stat", "cpu.stat")
    mem_ev = _parse_cgroup_kv_int_file(lease.cgroup_dir / "memory.events", "memory.events")
    pids_ev = _parse_cgroup_kv_int_file(lease.cgroup_dir / "pids.events", "pids.events")
    if "usage_usec" not in cpu_stat or "oom" not in mem_ev or "oom_kill" not in mem_ev or "max" not in pids_ev:
        raise ValueError("cgroup stat/events missing required keys")
    mem_peak = int((lease.cgroup_dir / "memory.peak").read_text(encoding="utf-8").strip())
    pids_peak = int((lease.cgroup_dir / "pids.peak").read_text(encoding="utf-8").strip())
    oom_delta, oom_kill_delta, pids_max_delta = mem_ev["oom"] - lease.baseline_oom, mem_ev["oom_kill"] - lease.baseline_oom_kill, pids_ev["max"] - lease.baseline_pids_max
    if oom_delta < 0 or oom_kill_delta < 0 or pids_max_delta < 0:
        raise ValueError("monotonic cgroup event delta regression")
    vfs = os.fstatvfs(tmp_fd)
    return {
        "cpu_time_us": cpu_stat["usage_usec"], "memory_peak_bytes": mem_peak, "pids_peak": pids_peak,
        "tmpfs_peak_bytes": (vfs.f_blocks - vfs.f_bfree) * vfs.f_frsize, "tmpfs_peak_inodes": vfs.f_files - vfs.f_ffree,
        "max_file_bytes": _walk_tmp_max_regular_file_bytes(tmp_fd), "stdout_bytes": stdout_bytes, "stderr_bytes": stderr_bytes,
        "oom_delta": oom_delta, "oom_kill_delta": oom_kill_delta, "pids_max_delta": pids_max_delta,
    }


def terminate_whole_cgroup(lease: CgroupV2Lease) -> bool:
    """Kill all processes in `lease.cgroup_dir` and verify `cgroup.procs` empties within 1000ms."""
    if not isinstance(lease, CgroupV2Lease):
        raise ValueError("lease: expected CgroupV2Lease")
    kill_path, procs_path = lease.cgroup_dir / "cgroup.kill", lease.cgroup_dir / "cgroup.procs"
    if kill_path.exists():
        fd = os.open(kill_path, os.O_WRONLY)
        try:
            os.write(fd, b"1\n")
        finally:
            os.close(fd)
    elif procs_path.exists():
        for tok in procs_path.read_text(encoding="utf-8").split():
            if tok.isascii() and tok.isdigit():
                try:
                    os.kill(int(tok), signal.SIGKILL)
                except ProcessLookupError:
                    pass
    deadline = time.monotonic() + 1.0
    while True:
        if not [t for t in procs_path.read_text(encoding="utf-8").split() if t.strip()]:
            return True
        if time.monotonic() >= deadline:
            raise ValueError("whole_cgroup_empty invariant violated")
        time.sleep(0.01)


_verify_helper_scripts()

__all__ = [
    "CgroupV2Lease", "LiveContainerReadback", "create_7a_leaf_cgroup", "harvest_cgroup_and_tmp_usage",
    "probe_7a_oci_host", "readback_live_container_state", "seal_container_premask_namespaces", "terminate_whole_cgroup",
]
