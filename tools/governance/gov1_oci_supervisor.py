"""Linux amd64 `runc --keep` + cgroup-v2 7A supervisor and isolated Stage-7 wheel probe runner."""
from __future__ import annotations

import base64, binascii, contextlib, copy, datetime, os, re, selectors, subprocess, time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Final

from tools.governance import (
    gov1_7a_certification as cert7a, gov1_7a_negative as neg7a, gov1_7a_replay_helpers as replay7a,
    gov1_7a_runner as runner7a, gov1_mcp, gov1_oci_container_runner as crun,
    gov1_oci_image as oci_img, gov1_oci_readback as oci_rb, gov1_oci_seccomp_bpf as sec_bpf, gov1_sandbox, gov1_wheel,
)
from tools.governance.gov1_7a_runner import SealedOciSupervisorPort
from tools.governance.gov1_oci_image import CompositeOciBundleSpec
from tools.governance.gov1_oci_readback import CgroupV2Lease, LiveContainerReadback
from tools.governance.gov1_wheel import IsolatedWheelProbeRunner
from tools.governance.jcs import canonicalize, loads_strict
from tools.governance.locator import digest, exact_fields, json_digest, make_locator, source_path, validate_locator

_MAX_PIPE_BYTES, _PIPE_CHUNK_BYTES, _STARTUP_TIMEOUT_S, _POLL_INTERVAL_S = 8_388_608, 65_536, 30.0, 0.020
_WATCHDOG_LIMIT_MS, _CPU_LIMIT_US, _FSIZE_LIMIT_BYTES, _TMPFS_INODES_LIMIT = 300_000, 120_000_000, 67_108_864, 4096
_RUNNER_ARGV: Final[tuple[str, ...]] = ("/usr/local/bin/python3.12", "-I", "-B", "-S", "/app/runner.py")
_VENV_PROBE_ARGV: Final[tuple[str, ...]] = ("/app/venv/bin/python", "-I", "-B", "/app/venv_probe_bootstrap.py")
_SAFE_ID_RE: Final[re.Pattern[str]] = re.compile(r"[^A-Za-z0-9._-]+")
_ZERO_SHA256: Final[str] = "sha256:" + ("0" * 64)
_DENIAL_CASE_IDS: Final[frozenset[str]] = frozenset(neg7a._EXACT_DENIAL_OBS) | frozenset(neg7a._COUNTED_DENIAL_OBS)
_RESOURCE_SUBRUN_SPECS: Final[Mapping[tuple[str, int], tuple[str, Mapping[str, Any]]]] = MappingProxyType({
    **{(cid, 0): (spec[3], spec[4]) for cid, spec in neg7a._STATIC_RESOURCE_SPECS.items()},
    ("output_limit_enforced", 0): ("stdout_limit", MappingProxyType({"stream": "stdout", "first_ceiling_reached": True})),
    ("output_limit_enforced", 1): ("stderr_limit", MappingProxyType({"stream": "stderr", "first_ceiling_reached": True})),
    ("tmpfs_limit_enforced", 0): ("tmpfs_enospc", MappingProxyType({"ceiling_kind": "inodes", "errno": "ENOSPC"})),
})

def _default_spawn_runc(cmd: Sequence[str], *, stdin_fd: int, stdout_fd: int, stderr_fd: int, **_kw: Any) -> Any:
    return subprocess.Popen(list(cmd), stdin=stdin_fd, stdout=stdout_fd, stderr=stderr_fd, close_fds=True)

def _default_delete_runc(cmd: Sequence[str]) -> None:
    subprocess.run(list(cmd), capture_output=True, timeout=15, check=False)

@dataclass(frozen=True, slots=True)
class RuncSubrunHooks:
    create_cgroup: Callable[..., CgroupV2Lease] = oci_rb.create_7a_leaf_cgroup
    materialize_bundle: Callable[..., dict[str, Path]] = oci_img.materialize_runc_bundle_trees
    spawn_runc: Callable[..., Any] = _default_spawn_runc
    seal_premask: Callable[[int], None] = oci_rb.seal_container_premask_namespaces
    readback_state: Callable[..., LiveContainerReadback] = oci_rb.readback_live_container_state
    harvest_usage: Callable[..., dict[str, int]] = oci_rb.harvest_cgroup_and_tmp_usage
    terminate_cgroup: Callable[[CgroupV2Lease], bool] = oci_rb.terminate_whole_cgroup
    delete_runc: Callable[[Sequence[str]], None] = _default_delete_runc
    cleanup_bundle: Callable[[Path], None] = oci_img.cleanup_runc_bundle_trees
    monotonic_ns: Callable[[], int] = time.monotonic_ns

@dataclass(frozen=True, slots=True)
class SubrunExecutionResult:
    instance_id: str
    started_at_utc: str
    ended_at_utc: str
    runtime_readback: dict[str, Any]
    effective_resource_limits: dict[str, Any]
    usage: dict[str, int]
    termination: dict[str, Any]
    stdout_data: bytes
    stderr_data: bytes

def build_runc_oci_config_json(*, cgroup_rel_path: str, bundle_trees: Mapping[str, Path], process_args: Sequence[str], process_env: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Build deterministic OCI Runtime Spec `1.0.2` `config.json` for a sealed 7A bundle."""
    if type(cgroup_rel_path) is not str or not cgroup_rel_path.startswith("/") or len(cgroup_rel_path) < 2 or "\x00" in cgroup_rel_path:
        raise ValueError(f"cgroup_rel_path: expected absolute cgroup path, got {cgroup_rel_path!r}")
    if not isinstance(bundle_trees, Mapping) or not {"rootfs", "app", "fixtures"}.issubset(bundle_trees.keys()):
        raise ValueError("bundle_trees: expected Mapping containing 'rootfs', 'app', and 'fixtures'")
    if isinstance(process_args, (str, bytes, bytearray)) or not isinstance(process_args, Sequence) or not process_args or any(type(a) is not str or not a or "\x00" in a for a in process_args):
        raise ValueError("process_args: expected non-empty Sequence of non-empty strings")
    env_map = neg7a._EXACT_ENV if process_env is None else process_env
    if not isinstance(env_map, Mapping) or not env_map or any(type(k) is not str or not k or "=" in k or "\x00" in k or type(v) is not str or "\x00" in v for k, v in env_map.items()):
        raise ValueError("process_env: expected non-empty Mapping[str, str] without '=' in keys or NUL")
    ro_empty = ["ro", "nosuid", "nodev", "noexec", "size=4096", "nr_inodes=16", "mode=0555"]
    mounts = [
        {"destination": "/proc", "type": "proc", "source": "proc", "options": ["nosuid", "noexec", "nodev"]},
        {"destination": "/dev", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "strictatime", "mode=755", "size=65536k"]},
        {"destination": "/app", "type": "bind", "source": str(bundle_trees["app"]), "options": ["rbind", "ro", "nosuid", "nodev"]},
        {"destination": "/fixtures", "type": "bind", "source": str(bundle_trees["fixtures"]), "options": ["rbind", "ro", "nosuid", "nodev"]},
        {"destination": "/tmp", "type": "tmpfs", "source": "tmpfs", "options": ["rw", "nosuid", "nodev", "noexec", "size=268435456", "nr_inodes=4096", "mode=1777"]},
        *[{"destination": d, "type": "tmpfs", "source": "tmpfs", "options": list(ro_empty)} for d in ("/sys", "/home", "/run", "/var/run")],
    ]
    return {
        "ociVersion": "1.0.2", "root": {"path": str(bundle_trees["rootfs"]), "readonly": True}, "hostname": "smart-ads-7a",
        "process": {"terminal": False, "user": {"uid": 1, "gid": 1}, "args": list(process_args), "env": [f"{k}={v}" for k, v in sorted(env_map.items())], "cwd": "/tmp", "capabilities": {"bounding": [], "effective": [], "inheritable": [], "permitted": [], "ambient": []}, "rlimits": [{"type": "RLIMIT_CPU", "soft": 120, "hard": 125}, {"type": "RLIMIT_FSIZE", "soft": _FSIZE_LIMIT_BYTES, "hard": _FSIZE_LIMIT_BYTES}], "noNewPrivileges": True},
        "mounts": mounts,
        "linux": {"uidMappings": [{"containerID": 0, "hostID": 100000, "size": 2}], "gidMappings": [{"containerID": 0, "hostID": 100000, "size": 2}], "cgroupsPath": cgroup_rel_path, "namespaces": [{"type": ns} for ns in neg7a._EXACT_NAMESPACES], "maskedPaths": [], "readonlyPaths": []},
    }

def _close_tracked_fd(fds: dict[str, int | None], key: str) -> None:
    if (fd := fds.get(key)) is not None:
        fds[key] = None
        with contextlib.suppress(OSError):
            os.close(fd)

def _write_all_fd(fd: int, payload: bytes) -> None:
    view, sent = memoryview(payload), 0
    while sent < len(view):
        if (n := os.write(fd, view[sent:])) <= 0:
            raise ValueError("short write on supervisor stdin pipe")
        sent += n

def _read_banner_with_deadline(stdout_r: int, stderr_r: int | None, expected: bytes, deadline: float, label: str) -> None:
    buf = bytearray()
    with selectors.DefaultSelector() as sel:
        sel.register(stdout_r, selectors.EVENT_READ)
        while len(buf) < len(expected):
            if (rem_s := deadline - time.monotonic()) <= 0:
                raise ValueError(f"{label}: timed out waiting for container banner")
            if not sel.select(min(0.05, rem_s)):
                continue
            if not (chunk := os.read(stdout_r, len(expected) - len(buf))):
                err_s = ""
                if stderr_r is not None:
                    with contextlib.suppress(OSError):
                        os.set_blocking(stderr_r, False)
                        err_s = os.read(stderr_r, 512).decode("utf-8", errors="replace").strip()
                raise ValueError(f"{label}: unexpected EOF before banner ({err_s})")
            buf.extend(chunk)
    if bytes(buf) != expected:
        raise ValueError(f"{label}: invalid container banner {bytes(buf)!r}")

def _drain_clamped_fd(fd: int, buf: bytearray) -> tuple[bool, bool]:
    while len(buf) < _MAX_PIPE_BYTES:
        try:
            chunk = os.read(fd, min(_PIPE_CHUNK_BYTES, _MAX_PIPE_BYTES - len(buf)))
        except BlockingIOError:
            return False, False
        if not chunk:
            return True, False
        buf.extend(chunk)
        if len(buf) >= _MAX_PIPE_BYTES:
            return False, True
    return False, True

def _detect_non_output_ceiling_cause(watchdog_elapsed_ms: int, usage: Mapping[str, int], stdout_buf: bytes | bytearray) -> str | None:
    checks = (
        (watchdog_elapsed_ms >= _WATCHDOG_LIMIT_MS, "wall_clock_watchdog"),
        (usage["cpu_time_us"] >= _CPU_LIMIT_US, "cpu_time_limit"),
        (usage["oom_kill_delta"] >= 1, "memory_oom"),
        (usage["pids_max_delta"] >= 1, "pids_max_limit"),
        (b'{"sigxfsz":true}' in stdout_buf and usage["max_file_bytes"] >= _FSIZE_LIMIT_BYTES, "rlimit_fsize"),
        (b'{"tmpfs_enospc":true}' in stdout_buf and usage["tmpfs_peak_inodes"] >= _TMPFS_INODES_LIMIT, "tmpfs_enospc"),
    )
    return next((cause for fired, cause in checks if fired), None)

def _poll_post_go_execution(*, proc: Any, stdout_r: int, stderr_r: int, lease: CgroupV2Lease, tmp_fd: int, go_ns: int, hooks: RuncSubrunHooks) -> tuple[str | None, int, bytearray, bytearray]:
    stdout_buf, stderr_buf, cause, watchdog_ms = bytearray(), bytearray(), None, 0
    os.set_blocking(stdout_r, False)
    os.set_blocking(stderr_r, False)
    with selectors.DefaultSelector() as sel:
        sel.register(stdout_r, selectors.EVENT_READ, "stdout")
        sel.register(stderr_r, selectors.EVENT_READ, "stderr")
        while True:
            if sel.get_map():
                for key, _ in sel.select(_POLL_INTERVAL_S):
                    eof, hit = _drain_clamped_fd(int(key.fd), stdout_buf if key.data == "stdout" else stderr_buf)
                    if hit:
                        cause = "stdout_limit" if key.data == "stdout" else "stderr_limit"
                        break
                    if eof:
                        sel.unregister(key.fd)
                if cause is not None:
                    return cause, max(0, (hooks.monotonic_ns() - go_ns) // 1_000_000), stdout_buf, stderr_buf
            elif proc.poll() is not None:
                break
            else:
                time.sleep(_POLL_INTERVAL_S)
            watchdog_ms = max(0, (hooks.monotonic_ns() - go_ns) // 1_000_000)
            cur_u = hooks.harvest_usage(lease=lease, tmp_fd=tmp_fd, stdout_bytes=len(stdout_buf), stderr_bytes=len(stderr_buf))
            if (cause := _detect_non_output_ceiling_cause(watchdog_ms, cur_u, stdout_buf)) is not None:
                break
    return cause, watchdog_ms, stdout_buf, stderr_buf

def _wait_or_kill_proc(proc: Any) -> int:
    try:
        return 0 if (rc := proc.wait(timeout=5.0)) is None else int(rc)
    except subprocess.TimeoutExpired:
        proc.kill()
        return 137 if (rc := proc.wait(timeout=5.0)) is None else int(rc)

def _await_runc_pid_file(pid_file: Path, proc: Any, deadline: float) -> int:
    while True:
        if pid_file.is_symlink():
            raise ValueError(f"runc pid-file symlink forbidden at {pid_file}")
        if pid_file.is_file():
            break
        if proc.poll() is not None and not pid_file.is_file():
            raise ValueError(f"runc exited before creating pid-file at {pid_file}")
        if time.monotonic() >= deadline:
            raise ValueError(f"timed out waiting for runc pid-file at {pid_file}")
        time.sleep(0.005)
    if pid_file.is_symlink():
        raise ValueError(f"runc pid-file symlink forbidden at {pid_file}")
    raw_pid = pid_file.read_text(encoding="utf-8").strip()
    if not (raw_pid.isascii() and raw_pid.isdigit()) or int(raw_pid) <= 1:
        raise ValueError(f"invalid container PID in pid-file: {raw_pid!r}")
    return int(raw_pid)

def _handshake_and_ready_gate(*, proc: Any, fds: dict[str, int | None], pid_file: Path, lease: CgroupV2Lease, composite_spec: CompositeOciBundleSpec, bundle_trees: Mapping[str, Path], seccomp_mode_byte: bytes, seccomp_profile: dict[str, Any] | None, ready_validator: Callable[[LiveContainerReadback], None] | None, hooks: RuncSubrunHooks) -> LiveContainerReadback:
    deadline, stdout_r, stdin_w = time.monotonic() + _STARTUP_TIMEOUT_S, fds["stdout_r"], fds["stdin_w"]
    if stdout_r is None or stdin_w is None:
        raise ValueError("missing supervisor handshake pipe FDs")
    _read_banner_with_deadline(stdout_r, fds["stderr_r"], crun.PREMASK_BANNER, deadline, "PREMASK")
    cont_pid = _await_runc_pid_file(pid_file, proc, deadline)
    hooks.seal_premask(cont_pid)
    _write_all_fd(stdin_w, seccomp_mode_byte)
    _read_banner_with_deadline(stdout_r, fds["stderr_r"], crun.READY_BANNER, deadline, "READY")
    live_rb = hooks.readback_state(container_pid=cont_pid, lease=lease, composite_spec=composite_spec, bundle_trees=bundle_trees, expect_seccomp=(seccomp_mode_byte != crun.SECCOMP_MODE_SKIP), seccomp_profile=seccomp_profile)
    fds["tmp_fd"] = live_rb.tmp_fd
    if ready_validator is not None:
        try:
            ready_validator(live_rb)
        except BaseException:
            _close_tracked_fd(fds, "stdin_w")
            hooks.terminate_cgroup(lease)
            _wait_or_kill_proc(proc)
            raise
    return live_rb

def _finalize_post_go_subrun(*, proc: Any, lease: CgroupV2Lease, tmp_fd: int, started_dt: datetime.datetime, go_ns: int, cause: str | None, watchdog_ms: int, stdout_buf: bytearray, stderr_buf: bytearray, live_rb: LiveContainerReadback, instance_id: str, hooks: RuncSubrunHooks) -> SubrunExecutionResult:
    rc, usage = (-1, {})
    if cause is None:
        rc = _wait_or_kill_proc(proc)
        watchdog_ms = max(0, (hooks.monotonic_ns() - go_ns) // 1_000_000)
        usage = hooks.harvest_usage(lease=lease, tmp_fd=tmp_fd, stdout_bytes=len(stdout_buf), stderr_bytes=len(stderr_buf))
        cause = _detect_non_output_ceiling_cause(watchdog_ms, usage, stdout_buf)
    hooks.terminate_cgroup(lease)
    if cause is not None:
        _wait_or_kill_proc(proc)
        ended_dt = max(started_dt, datetime.datetime.now(datetime.UTC).replace(microsecond=0))
        usage = hooks.harvest_usage(lease=lease, tmp_fd=tmp_fd, stdout_bytes=len(stdout_buf), stderr_bytes=len(stderr_buf))
        term = {"cause": cause, "supervisor_terminated_cgroup": True, "exit_code": None, "signal": "SIGKILL", "watchdog_elapsed_ms": watchdog_ms, "grace_elapsed_ms": 0, "whole_cgroup_empty": True, "force_kill_used": True}
    else:
        ended_dt = max(started_dt, datetime.datetime.now(datetime.UTC).replace(microsecond=0))
        if rc != 0:
            raise ValueError(f"container {instance_id!r} exited non-zero without ceiling breach (rc={rc}): {bytes(stderr_buf[:512]).decode('utf-8', errors='replace').strip()}")
        term = {"cause": "clean_exit", "supervisor_terminated_cgroup": False, "exit_code": 0, "signal": None, "watchdog_elapsed_ms": watchdog_ms, "grace_elapsed_ms": 0, "whole_cgroup_empty": True, "force_kill_used": False}
        if any(neg7a.evaluate_breach_predicates(usage, term).values()):
            raise ValueError(f"container {instance_id!r} breached resource predicate on clean exit")
    checked_u, checked_t = neg7a._validate_usage_and_termination(usage, term, f"subrun[{instance_id}]")
    return SubrunExecutionResult(instance_id, started_dt.strftime("%Y-%m-%dT%H:%M:%SZ"), ended_dt.strftime("%Y-%m-%dT%H:%M:%SZ"), live_rb.runtime_readback, live_rb.effective_resource_limits, checked_u, checked_t, bytes(stdout_buf), bytes(stderr_buf))

def _cleanup_subrun_resources(*, fds: dict[str, int | None], proc: Any | None, lease: CgroupV2Lease | None, bundle_dir: Path, runc_binary: str, runc_root_dir: Path, instance_id: str, hooks: RuncSubrunHooks) -> None:
    for k in ("stdin_r", "stdin_w", "stdout_r", "stdout_w", "stderr_r", "stderr_w"):
        _close_tracked_fd(fds, k)
    if lease is not None and (lease.cgroup_dir.exists() or (proc is not None and proc.poll() is None)):
        with contextlib.suppress(BaseException):
            hooks.terminate_cgroup(lease)
    if proc is not None and proc.poll() is None:
        _wait_or_kill_proc(proc)
    _close_tracked_fd(fds, "tmp_fd")
    if proc is not None:
        hooks.delete_runc([runc_binary, "--root", str(runc_root_dir), "delete", "--force", instance_id])
    if lease is not None and lease.cgroup_dir.exists():
        with contextlib.suppress(BaseException):
            hooks.terminate_cgroup(lease)
        with contextlib.suppress(OSError):
            os.rmdir(lease.cgroup_dir)
    if bundle_dir.is_symlink() or bundle_dir.exists():
        hooks.cleanup_bundle(bundle_dir)

def _execute_runc_subrun(*, instance_id: str, composite_spec: CompositeOciBundleSpec, bundles_root: Path, runc_root_dir: Path, cgroup_root: Path, runc_binary: str, process_args: Sequence[str], seccomp_mode_byte: bytes, task_spec: Mapping[str, Any] | None = None, ready_only: bool = False, extra_app_files: Mapping[str, bytes] | None = None, extra_app_modes: Mapping[str, int] | None = None, seccomp_profile: dict[str, Any] | None = None, ready_validator: Callable[[LiveContainerReadback], None] | None = None, hooks: RuncSubrunHooks = RuncSubrunHooks()) -> SubrunExecutionResult:
    if seccomp_mode_byte not in (crun.SECCOMP_MODE_7A, crun.SECCOMP_MODE_SKIP, crun.SECCOMP_MODE_STAGE7_PEP517):
        raise ValueError(f"unsupported seccomp_mode_byte: {seccomp_mode_byte!r}")
    bundle_dir = bundles_root / instance_id
    fds: dict[str, int | None] = dict.fromkeys(("stdin_r", "stdin_w", "stdout_r", "stdout_w", "stderr_r", "stderr_w", "tmp_fd"))
    lease, proc = None, None
    try:
        lease = hooks.create_cgroup(instance_id, cgroup_root=cgroup_root)
        mat_kw = {"extra_app_modes": extra_app_modes} if extra_app_modes is not None else {}
        trees = hooks.materialize_bundle(composite_spec=composite_spec, bundle_dir=bundle_dir, extra_app_files=extra_app_files, **mat_kw)
        (bundle_dir / "config.json").write_bytes(canonicalize(build_runc_oci_config_json(cgroup_rel_path=lease.cgroup_rel_path, bundle_trees=trees, process_args=process_args)))
        os.chmod(bundle_dir / "config.json", 0o444)
        fds["stdin_r"], fds["stdin_w"] = os.pipe()
        fds["stdout_r"], fds["stdout_w"] = os.pipe()
        fds["stderr_r"], fds["stderr_w"] = os.pipe()
        pid_file = bundle_dir / "container.pid"
        cmd = [runc_binary, "--root", str(runc_root_dir), "run", "--keep", "--pid-file", str(pid_file), "--bundle", str(bundle_dir), instance_id]
        proc = hooks.spawn_runc(cmd, stdin_fd=fds["stdin_r"], stdout_fd=fds["stdout_w"], stderr_fd=fds["stderr_w"], pid_file=pid_file, bundle_dir=bundle_dir, lease=lease)
        for ck in ("stdin_r", "stdout_w", "stderr_w"):
            _close_tracked_fd(fds, ck)
        live_rb = _handshake_and_ready_gate(proc=proc, fds=fds, pid_file=pid_file, lease=lease, composite_spec=composite_spec, bundle_trees=trees, seccomp_mode_byte=seccomp_mode_byte, seccomp_profile=seccomp_profile, ready_validator=ready_validator, hooks=hooks)
        if ready_only:
            _close_tracked_fd(fds, "stdin_w")
            hooks.terminate_cgroup(lease)
            _wait_or_kill_proc(proc)
            now_s = datetime.datetime.now(datetime.UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")
            return SubrunExecutionResult(instance_id, now_s, now_s, live_rb.runtime_readback, live_rb.effective_resource_limits, {}, {}, b"", b"")
        if task_spec is None:
            raise ValueError("task_spec is required when ready_only is False")
        started_dt, go_ns = datetime.datetime.now(datetime.UTC).replace(microsecond=0), hooks.monotonic_ns()
        _write_all_fd(int(fds["stdin_w"]), crun.encode_go_task_frame(task_spec))  # type: ignore[arg-type]
        _close_tracked_fd(fds, "stdin_w")
        cause, watchdog_ms, out_b, err_b = _poll_post_go_execution(proc=proc, stdout_r=int(fds["stdout_r"]), stderr_r=int(fds["stderr_r"]), lease=lease, tmp_fd=live_rb.tmp_fd, go_ns=go_ns, hooks=hooks)  # type: ignore[arg-type]
        return _finalize_post_go_subrun(proc=proc, lease=lease, tmp_fd=live_rb.tmp_fd, started_dt=started_dt, go_ns=go_ns, cause=cause, watchdog_ms=watchdog_ms, stdout_buf=out_b, stderr_buf=err_b, live_rb=live_rb, instance_id=instance_id, hooks=hooks)
    finally:
        _cleanup_subrun_resources(fds=fds, proc=proc, lease=lease, bundle_dir=bundle_dir, runc_binary=runc_binary, runc_root_dir=runc_root_dir, instance_id=instance_id, hooks=hooks)

def _prepare_supervisor_work_dirs(work_dir: Path, *, require_exec_traversable: bool = False) -> tuple[Path, Path, Path]:
    w_root = Path(work_dir)
    bundles_dir, runc_root = w_root / "bundles", w_root / "runc-root"
    if w_root.is_symlink() or bundles_dir.is_symlink() or runc_root.is_symlink():
        raise ValueError(f"work_dir or subdirectories must not be symlinks: {w_root}")
    existed = w_root.exists()
    for d, mode in ((w_root, 0o755), (bundles_dir, 0o755), (runc_root, 0o700)):
        d.mkdir(parents=(d is w_root), mode=mode, exist_ok=True)
        os.chmod(d, mode)
    if require_exec_traversable:
        try:
            oci_rb.select_exec_work_root_parent(w_root)
        except ValueError:
            if not existed:
                oci_img.cleanup_runc_bundle_trees(w_root)
            raise
    return w_root, bundles_dir, runc_root

def _validate_sandbox_profile_payload(sandbox_profile_payload: object) -> tuple[str, bytes, bytes]:
    if not isinstance(sandbox_profile_payload, Mapping) or not neg7a._SPEC_17_FIELDS.issubset(sandbox_profile_payload.keys()) or "resource_limits" not in sandbox_profile_payload:
        raise ValueError("sandbox_profile_payload: missing required 17 sandbox spec fields")
    lim = neg7a._validate_resource_limits_dict(sandbox_profile_payload["resource_limits"], "sandbox_profile.resource_limits")
    return json_digest({k: sandbox_profile_payload[k] for k in neg7a._SPEC_17_FIELDS}), canonicalize({k: sandbox_profile_payload[k] for k in neg7a._SHARED_RUNTIME_16_FIELDS}), canonicalize(lim)

def _make_profile_ready_validator(sandbox_profile_payload: Mapping[str, Any], *, expect_seccomp: bool) -> Callable[[LiveContainerReadback], None]:
    _, exp_shared, exp_limits = _validate_sandbox_profile_payload(sandbox_profile_payload)

    def _validate(live_rb: LiveContainerReadback) -> None:
        rb = neg7a._validate_runtime_readback_dict(live_rb.runtime_readback, "ready_readback")
        lim = neg7a._validate_resource_limits_dict(live_rb.effective_resource_limits, "ready_limits")
        if rb["seccomp_enforced_before_entry"] is not expect_seccomp or rb["network_absent"] is not True or rb["loopback_absent"] is not True:
            raise ValueError("ready_readback: seccomp or network/loopback invariant mismatch before GO")
        if canonicalize({k: rb[k] for k in neg7a._SHARED_RUNTIME_16_FIELDS}) != exp_shared or canonicalize(lim) != exp_limits:
            raise ValueError("ready_readback: live container state diverged from sealed_sandbox_profile/v1 before GO")

    return _validate

def _parse_bundle_replay_context(raw_rctx: bytes) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any], list[tuple[dict[str, Any], dict[str, Any]]]]:
    rctx = loads_strict(raw_rctx.decode("utf-8"))
    if not isinstance(rctx, Mapping):
        raise ValueError("replay_context_v1.json: expected JSON object")
    snap_d = dict(rctx["snapshot"] if "snapshot" in rctx else rctx["registry_snapshot"])
    snap_loc = dict(rctx["snapshot_locator"] if "snapshot_locator" in rctx else rctx["registry_snapshot_locator"])
    drv_d, drv_loc = dict(rctx["driver_contract"]), dict(rctx["driver_contract_locator"])
    validate_locator(snap_loc, runner7a.PRIVATE_REGISTRY_SNAPSHOT_SCHEMA)
    validate_locator(drv_loc, cert7a.PIPEBOARD_CONTRACT_SCHEMA)
    inv_pairs = [(dict(it["locator"] if "locator" in it else it["expected_inventory_locator"]), dict(it["inventory"] if "inventory" in it else it["expected_inventory"])) for it in rctx["expected_inventories"]] if "expected_inventories" in rctx else [(dict(rctx["expected_inventory_locator"]), dict(rctx["expected_inventory"]))]
    for loc_d, _ in inv_pairs:
        validate_locator(loc_d, cert7a.EXPECTED_RESOURCE_INVENTORY_SCHEMA)
    return snap_d, snap_loc, drv_d, drv_loc, inv_pairs

def _anchor_7a_case_window(retrieved_at_utc: str, watchdog_elapsed_ms: int) -> tuple[str, str]:
    ret_us = replay7a.parse_utc6_micros(retrieved_at_utc, "retrieved_at_utc")
    start_dt = datetime.datetime(1970, 1, 1, tzinfo=datetime.UTC) + datetime.timedelta(seconds=ret_us // 1_000_000)
    end_dt = start_dt + datetime.timedelta(seconds=max(1, (max(0, watchdog_elapsed_ms) + 999) // 1000))
    return start_dt.strftime("%Y-%m-%dT%H:%M:%SZ"), end_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

class LinuxRuncSealedOciSupervisor(SealedOciSupervisorPort):
    """Concrete Linux amd64 `runc --keep` + cgroup-v2 `SealedOciSupervisorPort`."""

    def __init__(self, *, composite_spec: CompositeOciBundleSpec, work_dir: Path, build_run_id: str, seccomp_profile: dict[str, Any] | None = None, sealed_sandbox_profile_locator: Mapping[str, Any] | None = None, cgroup_root: Path = Path("/sys/fs/cgroup"), runc_binary: str = "runc", hooks: RuncSubrunHooks | None = None) -> None:
        if not isinstance(composite_spec, CompositeOciBundleSpec) or type(runc_binary) is not str or not runc_binary.strip():
            raise ValueError("composite_spec must be CompositeOciBundleSpec and runc_binary non-empty str")
        self.composite_spec, self.build_run_id = composite_spec, neg7a._strict_str(build_run_id, "build_run_id")
        neg7a._opaque_ref_str(f"sandbox:oci-pos-7a-{self.build_run_id}-00", "build_run_id", expected_prefix="sandbox")
        self._work_dir, self._bundles_dir, self._runc_root = _prepare_supervisor_work_dirs(work_dir, require_exec_traversable=(hooks is None))
        self._seccomp_profile = copy.deepcopy(seccomp_profile) if seccomp_profile is not None else None
        self._cgroup_root, self._runc_binary = Path(cgroup_root), runc_binary
        self._hooks = RuncSubrunHooks() if hooks is None else hooks
        self._seq, self._cached_preflight, self._sbx_locator = 0, None, None
        if sealed_sandbox_profile_locator is not None:
            self.set_sealed_sandbox_profile_locator(sealed_sandbox_profile_locator)

    @property
    def sealed_sandbox_profile_locator(self) -> dict[str, Any] | None:
        return copy.deepcopy(self._sbx_locator) if self._sbx_locator is not None else None

    def set_sealed_sandbox_profile_locator(self, locator: Mapping[str, Any]) -> None:
        loc_d = copy.deepcopy(dict(locator)) if isinstance(locator, Mapping) else {}
        validate_locator(loc_d, gov1_sandbox.SANDBOX_PROFILE_SCHEMA)
        self._sbx_locator = loc_d

    def _next_instance_id(self, prefix: str) -> str:
        self._seq += 1
        return f"{prefix}-{(_SAFE_ID_RE.sub('_', self.build_run_id).strip('._-')[:24] or 'run')}-{self._seq:04d}"

    def _run_container_task(self, *, task_spec: Mapping[str, Any] | None = None, seccomp_mode_byte: bytes = crun.SECCOMP_MODE_7A, ready_only: bool = False, ready_validator: Callable[[LiveContainerReadback], None] | None = None, instance_prefix: str = "sa7a") -> SubrunExecutionResult:
        return _execute_runc_subrun(instance_id=self._next_instance_id(instance_prefix), composite_spec=self.composite_spec, bundles_root=self._bundles_dir, runc_root_dir=self._runc_root, cgroup_root=self._cgroup_root, runc_binary=self._runc_binary, process_args=_RUNNER_ARGV, seccomp_mode_byte=seccomp_mode_byte, task_spec=task_spec, ready_only=ready_only, seccomp_profile=self._seccomp_profile, ready_validator=ready_validator, hooks=self._hooks)

    def _ensure_preflight_readback(self) -> tuple[dict[str, Any], dict[str, Any]]:
        if self._cached_preflight is None:
            res = self._run_container_task(ready_only=True, seccomp_mode_byte=crun.SECCOMP_MODE_7A, instance_prefix="sa7a-pre")
            self._cached_preflight = (copy.deepcopy(res.runtime_readback), copy.deepcopy(res.effective_resource_limits))
        return self._cached_preflight

    def readback_sandbox_environment(self) -> Mapping[str, Any]:
        return copy.deepcopy(self._ensure_preflight_readback()[0])

    def readback_effective_resource_limits(self) -> Mapping[str, Any]:
        return copy.deepcopy(self._ensure_preflight_readback()[1])

    def _execute_single_negative_subrun(self, *, cid: str, c_idx: int, s_idx: int, run_id: str, wheel_digest: str, sbx_spec_digest: str, sandbox_profile_payload: Mapping[str, Any]) -> dict[str, Any]:
        expect_sec = cid != "pids_limit_enforced"
        res = self._run_container_task(task_spec={"kind": "neg", "case_id": cid, "subrun_index": s_idx}, seccomp_mode_byte=(crun.SECCOMP_MODE_7A if expect_sec else crun.SECCOMP_MODE_SKIP), ready_validator=_make_profile_ready_validator(sandbox_profile_payload, expect_seccomp=expect_sec), instance_prefix=f"neg-{c_idx:02d}-{s_idx}")
        if cid in _DENIAL_CASE_IDS:
            if not isinstance(obs := loads_strict(res.stdout_data.decode("utf-8")), dict):
                raise ValueError(f"negative case {cid!r}: expected JSON object observation")
        else:
            exp_cause, exp_obs = _RESOURCE_SUBRUN_SPECS[(cid, s_idx)]
            if res.termination["cause"] != exp_cause:
                raise ValueError(f"negative case {cid!r}[{s_idx}]: expected cause {exp_cause!r}, got {res.termination['cause']!r}")
            obs = dict(exp_obs)
        draft = {"sandbox_instance_ref": f"sandbox:oci-neg-{run_id}-{c_idx:02d}-{s_idx}", "execution_binding_digest": _ZERO_SHA256, "started_at_utc": res.started_at_utc, "ended_at_utc": res.ended_at_utc, "runtime_readback": res.runtime_readback, "effective_resource_limits": res.effective_resource_limits, "usage": res.usage, "termination": res.termination, "observation": obs}
        draft["execution_binding_digest"] = neg7a.compute_negative_run_execution_binding_digest(case_id=cid, subrun_index=s_idx, run=draft, wheel_digest=wheel_digest, test_suite_digest=neg7a.PINNED_7A_NEGATIVE_SUITE_DIGEST, sealed_sandbox_profile_digest=sbx_spec_digest)
        return draft

    def execute_negative_security_suite(self, *, wheel_digest: str, sandbox_profile_payload: Mapping[str, Any], build_run_id: str | None = None) -> list[dict[str, Any]]:
        neg7a._sha256_str(wheel_digest, "wheel_digest")
        sbx_spec_digest = _validate_sandbox_profile_payload(sandbox_profile_payload)[0]
        run_id = self.build_run_id if build_run_id is None else neg7a._strict_str(build_run_id, "build_run_id")
        neg7a._opaque_ref_str(f"sandbox:oci-neg-{run_id}-00-0", "build_run_id", expected_prefix="sandbox")
        cases_out: list[dict[str, Any]] = []
        for c_idx, cid in enumerate(neg7a.MANDATORY_7A_NEGATIVE_CASES):
            runs = [self._execute_single_negative_subrun(cid=cid, c_idx=c_idx, s_idx=s_idx, run_id=run_id, wheel_digest=wheel_digest, sbx_spec_digest=sbx_spec_digest, sandbox_profile_payload=sandbox_profile_payload) for s_idx in range(2 if cid == "output_limit_enforced" else 1)]
            neg7a._check_denial_run(cid, runs[0], f"neg[{cid}]") if cid in _DENIAL_CASE_IDS else neg7a._check_resource_case(cid, runs, f"neg[{cid}]")
            cases_out.append({"case_id": cid, "outcome": "passed", "runs": runs})
        return cases_out

    def _read_sealed_bundle_fixtures(self, verified_d26: Mapping[str, bytes]) -> tuple[bytes, bytes, bytes]:
        inspect_dir = self._bundles_dir / self._next_instance_id("sa7a-fix")
        try:
            trees = self._hooks.materialize_bundle(composite_spec=self.composite_spec, bundle_dir=inspect_dir, extra_app_files=None)
            for role, rel, _, _ in runner7a.PINNED_PIPEBOARD_D26_SPECS:
                d26_p = trees["app"] / f"d26/{role}__{Path(rel).name}"
                if d26_p.is_symlink() or not d26_p.is_file() or d26_p.read_bytes() != verified_d26[rel]:
                    raise ValueError(f"execute_7a_corpus: sealed OCI bundle d26 mismatch for {rel!r}")
            req_files = (trees["app"] / "wheel" / gov1_wheel.EXPECTED_WHEEL_FILENAME, trees["fixtures"] / "pipeboard_7a_corpus_v1.json", trees["fixtures"] / "replay_context_v1.json")
            if any(p.is_symlink() or not p.is_file() for p in req_files):
                raise ValueError("execute_7a_corpus: missing sealed wheel or fixture file in OCI bundle")
            return req_files[0].read_bytes(), req_files[1].read_bytes(), req_files[2].read_bytes()
        finally:
            if inspect_dir.is_symlink() or inspect_dir.exists():
                self._hooks.cleanup_bundle(inspect_dir)

    def _execute_single_7a_case(self, *, idx: int, cc: Mapping[str, Any], corpus_doc: Mapping[str, Any], rctx_parts: Any, priv_map: Mapping[tuple[str, str], str], cmap: Mapping[str, str], sbx_loc: Mapping[str, Any], sandbox_profile_payload: Mapping[str, Any], sbx_spec_digest: str, whl_digest: str, corpus_digest: str, reducer: Callable[[dict[str, Any]], list[dict[str, int]]]) -> dict[str, Any]:
        snap_d, snap_loc, drv_d, drv_loc, inv_pairs = rctx_parts
        res = self._run_container_task(task_spec={"kind": "pos_7a_case", "case_id": cc["case_id"], "sealed_sandbox_profile_locator": dict(sbx_loc)}, seccomp_mode_byte=crun.SECCOMP_MODE_7A, ready_validator=_make_profile_ready_validator(sandbox_profile_payload, expect_seccomp=True), instance_prefix=f"pos7a-{idx:02d}")
        if not isinstance(cont_out := loads_strict(res.stdout_data.decode("utf-8")), dict):
            raise ValueError("pos_7a_case: container stdout must decode to JSON object")
        exact_fields(cont_out, {"case_id", "admitted_collection_digest", "observation_batch", "observed_completeness_status", "normalized_fact_set_digest"}, "pos_7a_case")
        reg_fix_loc = make_locator("smart_ads/regression_fixture/v1", canonicalize(replay7a.build_canonical_regression_fixture(snap_loc["content_digest"])))
        adm, adm_loc = replay7a.recompute_fixture_7a_admission(collection_request=cc["collection_request"], admission_id=cc["admission_id"], clock_attestation=cc["clock_reading"]["attestation"], configured_max_uncertainty_ms=cc["clock_reading"]["configured_max_uncertainty_ms"], timezone_snapshot=corpus_doc["timezone_snapshot"], registry_snapshot_locator=snap_loc, registry_snapshot=snap_d, driver_contract_locator=drv_loc, driver_contract=drv_d, sealed_sandbox_profile_locator=sbx_loc, regression_fixture_locator=reg_fix_loc)
        inv_matches = [(l_d, i_d) for l_d, i_d in inv_pairs if (i_d["tenant_ref"], i_d["binding_ref"], i_d["account_ref"], i_d["resource_scope_ref"], i_d["date_range"]) == (adm["tenant_ref"], adm["binding_ref"], adm["account_ref"], adm["resource_scope_ref"], adm["computed_date_range"])]
        if len(inv_matches) != 1:
            raise ValueError(f"pos_7a_case[{cc['case_id']}]: missing unique matching expected_resource_inventory")
        inv_loc, inv_d = inv_matches[0]
        hr = cc["http_response"]
        host_batch = replay7a.transform_pipeboard_response_to_batch_dict(admitted=adm, private_object_id=priv_map[(adm["binding_ref"], adm["account_ref"])], known_campaign_map=cmap, scoped_resource_refs=frozenset(u["resource_ref"] for u in inv_d["expected_resources"]), retrieval_context=cc["retrieval_context"], network_ok=hr["network_ok"], http_status=hr["http_status"], headers=[(h[0], h[1]) for h in hr["headers"]], body_chunks=[hr["body_utf8"].encode("utf-8")], reducer=reducer)
        host_comp = replay7a.recompute_collection_completeness_dict(expected_resources=inv_d["expected_resources"], required_metrics=adm["canonical_query_contract"]["metric_semantic_refs"], metric_source_mappings=drv_d["metric_source_mappings"], batch_dict=host_batch, admitted_dict=adm)
        if cont_out["case_id"] != cc["case_id"] or cont_out["admitted_collection_digest"] != adm_loc["content_digest"] or canonicalize(cont_out["observation_batch"]) != canonicalize(host_batch) or cont_out["observed_completeness_status"] != host_comp["status"] or host_comp["status"] != cc["expected_completeness_status"] or cont_out["normalized_fact_set_digest"] != host_comp["normalized_fact_set_digest"]:
            raise ValueError(f"pos_7a_case[{cc['case_id']}]: container/host reducer parity mismatch")
        s_utc, e_utc = _anchor_7a_case_window(cc["retrieval_context"]["retrieved_at_utc"], res.termination["watchdog_elapsed_ms"])
        draft = {"case_id": cc["case_id"], "admitted_collection_digest": cont_out["admitted_collection_digest"], "expected_resource_inventory_locator": inv_loc, "source_contract_ref": f"opaque-driver-contract:{drv_loc['content_digest']}", "sandbox_instance_ref": f"sandbox:oci-pos-7a-{self.build_run_id}-{idx:02d}", "execution_binding_digest": _ZERO_SHA256, "started_at_utc": s_utc, "ended_at_utc": e_utc, "runtime_readback": res.runtime_readback, "effective_resource_limits": res.effective_resource_limits, "usage": res.usage, "termination": res.termination, "observation_batch": cont_out["observation_batch"], "expected_completeness_status": cc["expected_completeness_status"], "observed_completeness_status": cont_out["observed_completeness_status"], "normalized_fact_set_digest": cont_out["normalized_fact_set_digest"]}
        draft["execution_binding_digest"] = cert7a.compute_7a_case_execution_binding_digest(case=draft, wheel_digest=whl_digest, corpus_digest=corpus_digest, sealed_sandbox_profile_digest=sbx_spec_digest)
        return cert7a._validate_7a_case_dict(draft, f"pos_7a[{idx}]")

    def execute_7a_corpus(self, *, wheel_bytes: bytes, corpus_bytes: bytes, sandbox_profile_payload: Mapping[str, Any], resolved_d26_blobs: Mapping[str, bytes], reducer: Callable[[dict[str, Any]], list[dict[str, int]]]) -> Mapping[str, Any]:
        if self._sbx_locator is None or not callable(reducer):
            raise ValueError("execute_7a_corpus requires sealed_sandbox_profile_locator and callable reducer")
        if type(wheel_bytes) is not bytes or not wheel_bytes or type(corpus_bytes) is not bytes or not corpus_bytes:
            raise ValueError("execute_7a_corpus: wheel_bytes and corpus_bytes must be non-empty bytes")
        sbx_spec_digest, verified_d26 = _validate_sandbox_profile_payload(sandbox_profile_payload)[0], runner7a._verify_d26_blob_map(resolved_d26_blobs)
        img_whl, img_corp, rctx_raw = self._read_sealed_bundle_fixtures(verified_d26)
        if wheel_bytes != img_whl or corpus_bytes != img_corp:
            raise ValueError("execute_7a_corpus: wheel_bytes or corpus_bytes mismatch against sealed OCI bundle")
        rctx_parts = _parse_bundle_replay_context(rctx_raw)
        if not isinstance(corpus_doc := loads_strict(corpus_bytes.decode("utf-8")), Mapping) or corpus_doc.get("$schema") != cert7a.PIPEBOARD_7A_CORPUS_SCHEMA:
            raise ValueError("corpus_bytes: invalid pipeboard_7a_corpus/v1 document")
        secret, priv_map = bytes.fromhex(corpus_doc["tenant_hmac_key_hex"]), {(b["binding_ref"], b["account_ref"]): b["private_object_id"] for b in corpus_doc["private_account_bindings"]}
        cmap: dict[str, str] = {}
        for pair in corpus_doc["verified_campaign_pairs"]:
            rref = replay7a.validate_resource_ref_str(pair["resource_ref"])
            if replay7a.derive_resource_ref(secret_bytes=secret, mapping_version=rctx_parts[0]["resource_ref_mapping_version"], domain_separator=rctx_parts[0]["domain_separator"], raw_provider_id=pair["raw_campaign_id"]) != rref:
                raise ValueError("corpus_bytes: campaign resource_ref HMAC derivation mismatch")
            cmap[pair["raw_campaign_id"]] = rref
        whl_digest, corpus_digest = digest(wheel_bytes), digest(corpus_bytes)
        cases_out = [self._execute_single_7a_case(idx=idx, cc=cc, corpus_doc=corpus_doc, rctx_parts=rctx_parts, priv_map=priv_map, cmap=cmap, sbx_loc=self._sbx_locator, sandbox_profile_payload=sandbox_profile_payload, sbx_spec_digest=sbx_spec_digest, whl_digest=whl_digest, corpus_digest=corpus_digest, reducer=reducer) for idx, cc in enumerate(corpus_doc["cases"])]
        return {"cases": cases_out, "statuses": [c["observed_completeness_status"] for c in cases_out]}

def _stage_verified_wheel_extra_files(wheel_bytes: bytes, expected_member_paths: frozenset[str], label: str) -> dict[str, bytes]:
    if type(wheel_bytes) is not bytes or not wheel_bytes or not isinstance(expected_member_paths, frozenset):
        raise ValueError(f"{label}: invalid wheel_bytes or expected_member_paths")
    members = gov1_wheel._read_and_validate_wheel_archive(wheel_bytes)[0]
    if frozenset(members.keys()) != expected_member_paths:
        raise ValueError(f"{label}: archive members diverge from expected_member_paths")
    return {f"venv/lib/python3.12/site-packages/{rel}": raw for rel, raw in members.items()}

class OciIsolatedWheelProbeRunner(IsolatedWheelProbeRunner):
    """Concrete Linux amd64 `runc --keep` `IsolatedWheelProbeRunner` (`os_isolated = True`)."""
    os_isolated: bool = True

    def __init__(self, *, base_oci_dir: Path, work_dir: Path, seccomp_profile: dict[str, Any] | None = None, cgroup_root: Path = Path("/sys/fs/cgroup"), runc_binary: str = "runc", hooks: RuncSubrunHooks | None = None, expected_manifest_digest: str = oci_img.PINNED_BASE_OCI_MANIFEST_DIGEST, expected_config_digest: str = oci_img.PINNED_BASE_OCI_CONFIG_DIGEST, expected_layer_digests: tuple[str, ...] = oci_img.PINNED_BASE_OCI_LAYER_DIGESTS, expected_diff_ids: tuple[str, ...] = oci_img.PINNED_BASE_OCI_DIFF_IDS) -> None:
        if type(runc_binary) is not str or not runc_binary.strip():
            raise ValueError("runc_binary: expected non-empty str")
        self._base_oci_dir = Path(base_oci_dir)
        self._work_dir, self._bundles_dir, self._runc_root = _prepare_supervisor_work_dirs(work_dir, require_exec_traversable=(hooks is None))
        self._seccomp_profile = copy.deepcopy(seccomp_profile) if seccomp_profile is not None else gov1_sandbox.build_default_7a_seccomp_profile()
        self._cgroup_root, self._runc_binary, self._hooks = Path(cgroup_root), runc_binary, (RuncSubrunHooks() if hooks is None else hooks)
        self._base_exp = (expected_manifest_digest, expected_config_digest, expected_layer_digests, expected_diff_ids)
        self._probe_spec: CompositeOciBundleSpec | None = None
        self._seq = 0

    def _ensure_probe_composite_spec(self) -> CompositeOciBundleSpec:
        if self._probe_spec is not None:
            return self._probe_spec
        exp_man, exp_cfg, exp_layers, exp_diffs = self._base_exp
        v_base = oci_img.verify_pinned_base_oci_layout(self._base_oci_dir, expected_manifest_digest=exp_man, expected_config_digest=exp_cfg, expected_layer_digests=exp_layers, expected_diff_ids=exp_diffs)
        sec_dig, bpf_raw = sec_bpf.compile_seccomp_profile_to_bpf(self._seccomp_profile)
        runner_b, boot_b = crun.CONTAINER_RUNNER_SOURCE.encode("utf-8"), crun.VENV_PROBE_BOOTSTRAP_SOURCE.encode("utf-8")
        py_sha, run_sha = digest(oci_img._extract_python_elf_from_base_layers(v_base["layer_paths"])), digest(runner_b)
        run_bin_dig = json_digest({"kind": "smart_ads/7a_oci_runner_binary/v1", "python_elf_sha256": py_sha, "runner_script_sha256": run_sha})
        shim = {**{d: ("dir", 0o555, b"") for d in ("app", "dev", "fixtures", "home", "proc", "run", "sys", "tmp", "usr", "usr/bin", "var", "var/run")}, "var/.wh.run": ("reg", 0o444, b""), "usr/bin/python3": ("sym", 0o777, "/usr/local/bin/python3.12")}
        app = {**{d: ("dir", 0o555, b"") for d in ("app", "app/venv", "app/venv/bin", "app/venv/lib", "app/venv/lib/python3.12", "app/venv/lib/python3.12/site-packages")}, "app/runner.py": ("reg", 0o555, runner_b), "app/venv_probe_bootstrap.py": ("reg", 0o555, boot_b), "app/seccomp_filter.bpf": ("reg", 0o444, bpf_raw), "app/venv/pyvenv.cfg": ("reg", 0o444, oci_img._PYVENV_CFG_BYTES), "app/venv/bin/python": ("sym", 0o777, "/usr/local/bin/python3.12"), "app/venv/bin/python3": ("sym", 0o777, "/usr/local/bin/python3.12")}
        out_dir = self._work_dir / "stage7-probe-oci"
        if out_dir.is_symlink() or out_dir.exists():
            oci_img.cleanup_runc_bundle_trees(out_dir)
        overlays = (oci_img._build_deterministic_tar_gz_layer(shim), oci_img._build_deterministic_tar_gz_layer(app), oci_img._build_deterministic_tar_gz_layer({"fixtures": ("dir", 0o555, b"")}))
        self._probe_spec = CompositeOciBundleSpec(out_dir, oci_img._write_composite_oci_files(out_dir, v_base, overlays), run_bin_dig, sec_dig, py_sha, run_sha)
        return self._probe_spec

    def _run_probe(self, *, prefix: str, process_args: Sequence[str], seccomp_mode_byte: bytes, task_spec: Mapping[str, Any], extra_app_files: Mapping[str, bytes], extra_app_modes: Mapping[str, int] | None = None) -> dict[str, Any]:
        self._seq += 1
        res = _execute_runc_subrun(instance_id=f"s7-{prefix}-{self._seq:04d}", composite_spec=self._ensure_probe_composite_spec(), bundles_root=self._bundles_dir, runc_root_dir=self._runc_root, cgroup_root=self._cgroup_root, runc_binary=self._runc_binary, process_args=process_args, seccomp_mode_byte=seccomp_mode_byte, task_spec=task_spec, extra_app_files=extra_app_files, extra_app_modes=extra_app_modes, seccomp_profile=self._seccomp_profile, hooks=self._hooks)
        if res.termination["cause"] != "clean_exit" or res.termination["exit_code"] != 0:
            raise ValueError(f"Stage-7 probe {prefix!r} did not exit cleanly: {res.termination!r}")
        if not isinstance(parsed := loads_strict(res.stdout_data.decode("utf-8")), dict):
            raise ValueError(f"Stage-7 probe {prefix!r} returned non-object JSON")
        return parsed

    def run_wheel_import_probe(self, *, wheel_bytes: bytes, expected_member_paths: frozenset[str], expected_modules: Sequence[str]) -> dict[str, Any]:
        if isinstance(expected_modules, (str, bytes, bytearray)) or not isinstance(expected_modules, Sequence) or any(type(m) is not str for m in expected_modules):
            raise ValueError("run_wheel_import_probe: expected_modules must be Sequence[str]")
        extra = _stage_verified_wheel_extra_files(wheel_bytes, expected_member_paths, "run_wheel_import_probe")
        task = {"kind": "venv_probe", "probe_script": gov1_wheel._CLEAN_VENV_PROBE_SCRIPT, "probe_argv": ["/app/venv/bin/python", "/app/venv/lib/python3.12/site-packages", canonicalize(list(expected_modules)).decode("utf-8")]}
        out = self._run_probe(prefix="imp", process_args=_VENV_PROBE_ARGV, seccomp_mode_byte=crun.SECCOMP_MODE_7A, task_spec=task, extra_app_files=extra)
        exact_fields(out, {"packaged_modules", "schema_bundle_digest"}, "wheel_import_probe")
        return out

    def run_mcp_matrix_probe(self, *, wheel_bytes: bytes, expected_member_paths: frozenset[str], expected_schema_bundle_digest: str) -> dict[str, Any]:
        neg7a._sha256_str(expected_schema_bundle_digest, "expected_schema_bundle_digest")
        extra = _stage_verified_wheel_extra_files(wheel_bytes, expected_member_paths, "run_mcp_matrix_probe")
        task = {"kind": "venv_probe", "probe_script": gov1_mcp._MCP_MATRIX_PROBE_SCRIPT, "probe_argv": ["/app/venv/bin/python", "/app/venv/lib/python3.12/site-packages", "/nonexistent_repo", "/nonexistent_repo/src", expected_schema_bundle_digest]}
        out = self._run_probe(prefix="mcp", process_args=_VENV_PROBE_ARGV, seccomp_mode_byte=crun.SECCOMP_MODE_7A, task_spec=task, extra_app_files=extra)
        exact_fields(out, {"schema_bundle_digest", "allowed_methods", "body_64k_boundary_verified", "cases"}, "mcp_matrix_probe")
        return out

    def _stage_pep517_extra_files(self, snapshot_files: Mapping[str, bytes], snapshot_modes: Mapping[str, str], verified_backend_site_dir: Path) -> dict[str, bytes]:
        if not isinstance(snapshot_files, Mapping) or not isinstance(snapshot_modes, Mapping) or not snapshot_files or set(snapshot_files.keys()) != set(snapshot_modes.keys()):
            raise ValueError("snapshot_files and snapshot_modes must be non-empty Mappings with matching keys")
        b_dir = Path(verified_backend_site_dir)
        if b_dir.is_symlink() or not b_dir.is_dir():
            raise ValueError("verified_backend_site_dir: expected non-symlink directory")
        gov1_wheel._assert_clean_backend_site_tree(b_dir)
        extra: dict[str, bytes] = {"pep517_seccomp.bpf": sec_bpf.compile_stage7_pep517_seccomp_bpf()}
        for rel_p, raw in snapshot_files.items():
            source_path(rel_p)
            gov1_wheel._reject_forbidden_hatch_filename(rel_p, label="run_pep517_wheel_build")
            if not gov1_wheel._is_allowed_snapshot_stage_path(rel_p) or type(raw) is not bytes or type(snapshot_modes[rel_p]) is not str or snapshot_modes[rel_p] not in {"100644", "100755"}:
                raise ValueError(f"run_pep517_wheel_build: invalid staged snapshot entry {rel_p!r}")
            extra[f"stage/{rel_p}"] = raw
        b_root = b_dir.resolve()
        for curr_root, _, filenames in os.walk(b_root, followlinks=False):
            for fname in sorted(filenames):
                fpath = Path(curr_root) / fname
                extra[f"backend_site/{source_path(fpath.relative_to(b_root).as_posix())}"] = fpath.read_bytes()
        return extra

    def run_pep517_wheel_build(self, *, snapshot_files: Mapping[str, bytes], snapshot_modes: Mapping[str, str], verified_backend_site_dir: Path, source_date_epoch: int) -> tuple[str, bytes]:
        if type(source_date_epoch) is not int or not (0 <= source_date_epoch <= gov1_wheel.MAX_JCS_SAFE_INT):
            raise ValueError("source_date_epoch: expected non-negative safe integer")
        extra = self._stage_pep517_extra_files(snapshot_files, snapshot_modes, verified_backend_site_dir)
        modes = {f"stage/{rel_p}": (0o555 if snapshot_modes[rel_p] == "100755" else 0o444) for rel_p in snapshot_files}
        closure_mods = sorted({spec[3] for spec in gov1_wheel.PINNED_UV_LOCK_CLOSURE_SPECS.values()} | {gov1_wheel.EXPECTED_BUILD_BACKEND}, key=lambda s: s.encode("utf-8"))
        task = {"kind": "pep517_build", "source_date_epoch": source_date_epoch, "closure_mods_csv": ",".join(closure_mods), "runner_bootstrap": gov1_wheel._PEP517_RUNNER_BOOTSTRAP, "driver_script": gov1_wheel._PEP517_DRIVER_SCRIPT}
        out = self._run_probe(prefix="pep517", process_args=_RUNNER_ARGV, seccomp_mode_byte=crun.SECCOMP_MODE_STAGE7_PEP517, task_spec=task, extra_app_files=extra, extra_app_modes=modes)
        exact_fields(out, {"wheel_name", "wheel_b64"}, "pep517_wheel_build")
        if out["wheel_name"] != gov1_wheel.EXPECTED_WHEEL_FILENAME or type(out["wheel_b64"]) is not str:
            raise ValueError(f"pep517_wheel_build: unexpected wheel_name {out.get('wheel_name')!r}")
        try:
            whl_bytes = base64.b64decode(out["wheel_b64"].encode("ascii"), validate=True)
        except (UnicodeEncodeError, binascii.Error) as exc:
            raise ValueError(f"pep517_wheel_build: invalid base64 wheel payload: {exc}") from exc
        if not whl_bytes:
            raise ValueError("pep517_wheel_build: empty wheel payload")
        return out["wheel_name"], whl_bytes

__all__ = ["LinuxRuncSealedOciSupervisor", "OciIsolatedWheelProbeRunner", "RuncSubrunHooks", "SubrunExecutionResult", "build_runc_oci_config_json"]
