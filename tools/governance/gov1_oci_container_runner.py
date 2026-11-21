"""Hermetic OCI container bootstrap runner and venv probe bootstrap sources."""
from __future__ import annotations

import ast
from collections.abc import Mapping
import struct
from typing import Any, Final

from tools.governance.jcs import canonicalize, loads_strict

PREMASK_BANNER: Final[bytes] = b"SMART-ADS-OCI-PREMASK\n"
READY_BANNER: Final[bytes] = b"SMART-ADS-OCI-READY\n"
GO_BYTE: Final[bytes] = b"\x02"
SECCOMP_MODE_SKIP: Final[bytes] = b"\x00"
SECCOMP_MODE_7A: Final[bytes] = b"\x01"
SECCOMP_MODE_STAGE7_PEP517: Final[bytes] = b"\x03"

_SEVEN_A_TASK_KINDS: Final[frozenset[str]] = frozenset({"preflight_noop", "neg", "pos_7a_case"})
_STAGE7_SCRIPT_KINDS: Final[frozenset[str]] = frozenset({"pep517_build", "venv_probe"})

CONTAINER_RUNNER_SOURCE: Final[str] = '''from __future__ import annotations

import __future__
import ast
import base64
import builtins
from collections.abc import Mapping
import ctypes
import decimal
import errno
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import re
import signal
import struct
import sys
from typing import Any, Final, cast


class _SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]


_ACTIVE_BPF_HOLD: list[Any] = []
_APP_ROOT, _FIXTURES_ROOT, _TMP_ROOT = "/app", "/fixtures", "/tmp"
_DEV_ROOT, _PROC_ROOT, _SYS_ROOT, _HOME_ROOT, _NONEXISTENT_HOME = "/dev", "/proc", "/sys", "/home", "/nonexistent"
_RAW_CRED_PATHS: tuple[str, ...] = (
    "/root/.aws/credentials", "/root/.ssh/id_rsa", "/home/.aws/credentials", "/nonexistent/.aws/credentials",
    "/run/secrets/token", "/var/run/secrets/kubernetes.io/serviceaccount/token", "/etc/shadow",
)
_RAW_NON_TMP_PROBES: tuple[str, ...] = (
    "/probe", "/app/probe", "/fixtures/probe", "/etc/probe", "/usr/probe", "/var/probe", "/run/probe", "/var/run/probe",
)
_CREDENTIAL_PATHS, _NON_TMP_PROBES = _RAW_CRED_PATHS, _RAW_NON_TMP_PROBES
_EXACT_ENV: dict[str, str] = {
    "HOME": "/nonexistent", "LANG": "C.UTF-8", "PATH": "/usr/bin:/bin",
    "PYTHONNOUSERSITE": "1", "PYTHONSAFEPATH": "1", "TMPDIR": "/tmp", "TZ": "UTC",
}
_RESTRICTED_BUILTINS: dict[str, Any] = {
    "__build_class__": builtins.__build_class__, "Exception": Exception, "ValueError": ValueError,
    "bool": bool, "dict": dict, "frozenset": frozenset, "int": int, "isinstance": isinstance,
    "len": len, "list": list, "set": set, "str": str, "tuple": tuple,
}


def _configure_roots_for_test(root: str) -> None:
    global _APP_ROOT, _FIXTURES_ROOT, _TMP_ROOT, _DEV_ROOT, _PROC_ROOT
    global _SYS_ROOT, _HOME_ROOT, _NONEXISTENT_HOME, _CREDENTIAL_PATHS, _NON_TMP_PROBES
    _APP_ROOT, _FIXTURES_ROOT, _TMP_ROOT = f"{root}/app", f"{root}/fixtures", f"{root}/tmp"
    _DEV_ROOT, _PROC_ROOT, _SYS_ROOT = f"{root}/dev", f"{root}/proc", f"{root}/sys"
    _HOME_ROOT, _NONEXISTENT_HOME = f"{root}/home", f"{root}/nonexistent"
    _CREDENTIAL_PATHS = tuple(f"{root}{p}" for p in _RAW_CRED_PATHS)
    _NON_TMP_PROBES = tuple(f"{root}{p}" for p in _RAW_NON_TMP_PROBES)


def _write_all(fd: int, data: bytes) -> None:
    view, sent = memoryview(data), 0
    while sent < len(view):
        n = os.write(fd, view[sent:])
        if n <= 0:
            raise RuntimeError("short write on pipe")
        sent += n


def _read_exact(fd: int, size: int) -> bytes:
    chunks, rem = [], size
    while rem > 0:
        chunk = os.read(fd, rem)
        if not chunk:
            raise RuntimeError("unexpected EOF on pipe")
        chunks.append(chunk)
        rem -= len(chunk)
    return b"".join(chunks)


def _install_seccomp_bpf(libc: Any, bpf_path: str) -> None:
    bpf_raw = Path(bpf_path).read_bytes()
    if len(bpf_raw) == 0 or len(bpf_raw) % 8 != 0 or (len(bpf_raw) // 8) > 4096 or ctypes.sizeof(_SockFprog) != 16:
        raise RuntimeError("invalid seccomp BPF image or _SockFprog size")
    bpf_buf = ctypes.create_string_buffer(bpf_raw, len(bpf_raw))
    prog = _SockFprog(len(bpf_raw) // 8, ctypes.cast(bpf_buf, ctypes.c_void_p).value)
    _ACTIVE_BPF_HOLD.extend((bpf_buf, prog))
    libc.prctl.restype = ctypes.c_int
    if libc.prctl(38, 1, 0, 0, 0) != 0:
        raise RuntimeError("prctl(PR_SET_NO_NEW_PRIVS) failed")
    if libc.prctl(22, 2, ctypes.byref(prog), 0, 0) != 0:
        raise RuntimeError("prctl(PR_SET_SECCOMP) failed")


def _startup_handshake() -> tuple[Any, dict[str, Any]]:
    libc = ctypes.CDLL(None, use_errno=True)
    os.closerange(3, 65536)
    _write_all(1, b"SMART-ADS-OCI-PREMASK\\n")
    seccomp_mode = os.read(0, 1)
    if seccomp_mode == b"\\x01":
        _install_seccomp_bpf(libc, f"{_APP_ROOT}/seccomp_filter.bpf")
    elif seccomp_mode == b"\\x03":
        _install_seccomp_bpf(libc, f"{_APP_ROOT}/pep517_seccomp.bpf")
    elif seccomp_mode != b"\\x00":
        raise RuntimeError(f"unsupported seccomp_mode byte: {seccomp_mode!r}")
    _write_all(1, b"SMART-ADS-OCI-READY\\n")
    go_byte = os.read(0, 1)
    if go_byte == b"":
        os._exit(0)
    if go_byte != b"\\x02":
        raise RuntimeError(f"invalid GO byte: {go_byte!r}")
    u32_len = struct.unpack(">I", _read_exact(0, 4))[0]
    if not (1 <= u32_len <= 131072):
        raise RuntimeError(f"task payload length out of bounds: {u32_len}")
    task_spec = json.loads(_read_exact(0, u32_len).decode("utf-8"))
    if not isinstance(task_spec, dict):
        raise RuntimeError("task_spec must decode to a JSON object")
    return libc, task_spec


def _require_open_denied(paths: tuple[str, ...], flags: int, allowed_errnos: tuple[int, ...] | None = None) -> int:
    for p in paths:
        try:
            fd = os.open(p, flags, 0o600)
        except OSError as exc:
            if allowed_errnos is not None and exc.errno not in allowed_errnos:
                raise RuntimeError(f"unexpected errno {exc.errno} on {p!r}") from exc
        else:
            os.close(fd)
            raise RuntimeError(f"expected denial on {p!r}, but open succeeded")
    return len(paths)


def _run_fs_and_env_denial_case(case_id: str) -> dict[str, Any]:
    if case_id == "credential_paths_denied":
        return {"probe_set_id": "credential_paths_v1", "denied_probe_count": _require_open_denied(_CREDENTIAL_PATHS, os.O_RDONLY, (errno.ENOENT, errno.EACCES, errno.EPERM))}
    if case_id == "env_is_exact_allowlist":
        if dict(os.environ) != _EXACT_ENV:
            raise RuntimeError("container environment does not match exact allowlist")
        return {"environment_matches": True}
    if case_id == "host_dev_denied":
        if os.listdir(_DEV_ROOT) != []:
            raise RuntimeError("/dev is not empty")
        _require_open_denied(tuple(f"{_DEV_ROOT}/{n}" for n in ("null", "zero", "urandom", "mem", "kmsg")), os.O_RDONLY)
        _require_open_denied((f"{_DEV_ROOT}/probe",), os.O_CREAT | os.O_WRONLY)
        return {"mount": "/dev", "host_access_denied": True}
    if case_id == "host_home_denied":
        if os.listdir(_HOME_ROOT) != [] or os.path.exists(_NONEXISTENT_HOME):
            raise RuntimeError("/home not empty or /nonexistent exists")
        _require_open_denied((f"{_HOME_ROOT}/probe",), os.O_CREAT | os.O_WRONLY)
        return {"mount": "/home", "host_access_denied": True}
    if case_id == "host_proc_denied":
        if os.listdir(_PROC_ROOT) != []:
            raise RuntimeError("/proc is not empty")
        _require_open_denied((f"{_PROC_ROOT}/self/environ", f"{_PROC_ROOT}/1/cmdline", f"{_PROC_ROOT}/mounts"), os.O_RDONLY)
        return {"mount": "/proc", "host_access_denied": True}
    if case_id == "host_sys_denied":
        if os.listdir(_SYS_ROOT) != []:
            raise RuntimeError("/sys is not empty")
        _require_open_denied((f"{_SYS_ROOT}/fs/cgroup", f"{_SYS_ROOT}/kernel"), os.O_RDONLY)
        return {"mount": "/sys", "host_access_denied": True}
    if case_id == "inherited_fd_denied":
        for fd in range(3, 4096):
            try:
                os.fstat(fd)
            except OSError as exc:
                if exc.errno != errno.EBADF:
                    raise RuntimeError(f"unexpected fstat errno {exc.errno} on fd {fd}") from exc
            else:
                raise RuntimeError(f"inherited fd {fd} remained open")
        return {"probe_set_id": "inherited_fds_above_2_v1", "inherited_fd_count_above_2": 0}
    _require_open_denied(_NON_TMP_PROBES, os.O_CREAT | os.O_WRONLY, (errno.EROFS, errno.EACCES, errno.EPERM))
    return {"probe_target_id": "rootfs_non_tmp_v1", "creation_denied": True}


def _run_seccomp_denial_case(libc: Any, case_id: str) -> dict[str, Any]:
    libc.syscall.restype = ctypes.c_long
    if case_id == "process_creation_denied":
        py_p = ctypes.c_char_p(b"/usr/bin/python3")
        probes: tuple[tuple[Any, ...], ...] = ((57,), (58,), (56, 0, 0, 0, 0, 0), (435, 0, 0), (59, py_p, 0, 0), (322, -100, py_p, 0, 0, 0))
        for args in probes:
            ctypes.set_errno(0)
            res = libc.syscall(*args)
            if res == 0:
                os._exit(1)
            if res != -1 or ctypes.get_errno() != errno.EPERM:
                raise RuntimeError(f"process creation syscall {args[0]} not denied with EPERM")
        return {"probe_set_id": "seccomp_process_creation_v1", "denied_probe_count": 6}
    sv_arr = (ctypes.c_int * 2)()
    for args in ((41, 2, 1, 0), (41, 1, 1, 0), (53, 1, 1, 0, sv_arr)):
        ctypes.set_errno(0)
        if libc.syscall(*args) != -1 or ctypes.get_errno() != errno.EPERM:
            raise RuntimeError(f"socket syscall {args[0]} not denied with EPERM")
    return {"probe_set_id": "seccomp_socket_v1", "denied_probe_count": 3}


def _block_forever() -> None:
    r_fd, _w_fd = os.pipe()
    os.read(r_fd, 1)


def _run_fsize_ceiling() -> None:
    got_sig: list[int] = []
    signal.signal(signal.SIGXFSZ, lambda s, _f: got_sig.append(s))
    fd = os.open(f"{_TMP_ROOT}/fsize.bin", os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
    chunk = b"\\x00" * 1048576
    for _ in range(64):
        _write_all(fd, chunk)
    try:
        os.write(fd, b"X")
    except OSError as exc:
        os.close(fd)
        if exc.errno != errno.EFBIG or not got_sig:
            raise RuntimeError("expected EFBIG and SIGXFSZ at 64 MiB ceiling") from exc
    else:
        os.close(fd)
        raise RuntimeError("write past RLIMIT_FSIZE unexpectedly succeeded")
    _write_all(1, b\'{"sigxfsz":true}\\n\')
    _block_forever()


def _run_pids_or_tmpfs_ceiling(case_id: str) -> None:
    if case_id == "pids_limit_enforced":
        hold_r, _hold_w = os.pipe()
        hit_eagain = False
        for _ in range(48):
            try:
                pid = os.fork()
            except OSError as exc:
                if exc.errno == errno.EAGAIN:
                    hit_eagain = True
                    break
                raise
            if pid == 0:
                try:
                    os.read(hold_r, 1)
                except BaseException:
                    pass
                os._exit(0)
        if not hit_eagain:
            raise RuntimeError("pids.max did not trigger EAGAIN")
        _write_all(1, b\'{"pids_eagain":true}\\n\')
        os.read(hold_r, 1)
        return
    hit_enospc = False
    for idx in range(5001):
        try:
            fd = os.open(f"{_TMP_ROOT}/in_{idx:04d}", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
        except OSError as exc:
            if exc.errno == errno.ENOSPC:
                hit_enospc = True
                break
            raise
    if not hit_enospc:
        raise RuntimeError("tmpfs limit did not trigger ENOSPC")
    _write_all(1, b\'{"tmpfs_enospc":true}\\n\')
    _block_forever()


def _run_neg_case(libc: Any, task_spec: Mapping[str, Any]) -> None:
    case_id = str(task_spec["case_id"])
    raw_sub = task_spec.get("subrun_index", 0)
    if type(raw_sub) is not int:
        raise RuntimeError("subrun_index must be strict int")
    subrun_index = raw_sub
    if case_id in ("process_creation_denied", "socket_denied"):
        _write_all(1, json.dumps(_run_seccomp_denial_case(libc, case_id), sort_keys=True).encode("utf-8") + b"\\n")
        os._exit(0)
    if case_id in ("credential_paths_denied", "env_is_exact_allowlist", "host_dev_denied", "host_home_denied", "host_proc_denied", "host_sys_denied", "inherited_fd_denied", "write_outside_tmp_denied"):
        _write_all(1, json.dumps(_run_fs_and_env_denial_case(case_id), sort_keys=True).encode("utf-8") + b"\\n")
        os._exit(0)
    if case_id == "cpu_limit_enforced":
        signal.signal(signal.SIGXCPU, lambda _s, _f: None)
        while True:
            pass
    if case_id == "memory_limit_enforced":
        chunks: list[bytearray] = []
        for _ in range(80):
            buf = bytearray(16 * 1024 * 1024)
            for off in range(0, len(buf), 4096):
                buf[off] = 1
            chunks.append(buf)
        _block_forever()
    elif case_id == "output_limit_enforced":
        if subrun_index not in (0, 1):
            raise RuntimeError("output_limit_enforced: invalid subrun_index")
        out_fd, blk = (1 if subrun_index == 0 else 2), b"A" * 65536
        try:
            while True:
                os.write(out_fd, blk)
        except BrokenPipeError:
            pass
        _block_forever()
    elif case_id == "wall_clock_limit_enforced":
        _block_forever()
    elif case_id == "file_size_limit_enforced":
        _run_fsize_ceiling()
    elif case_id in ("pids_limit_enforced", "tmpfs_limit_enforced"):
        _run_pids_or_tmpfs_ceiling(case_id)
    else:
        raise RuntimeError(f"unknown negative case_id: {case_id!r}")


def _verify_git_blob_and_sha(raw: bytes, exp_oid: str, exp_sha: str) -> None:
    oid = hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\\x00" + raw).hexdigest()
    if oid != exp_oid or ("sha256:" + hashlib.sha256(raw).hexdigest()) != exp_sha:
        raise RuntimeError("pinned d26c73d blob OID or SHA-256 mismatch")


def _compile_container_d26_reducer() -> Any:
    raw_lim = (Path(_APP_ROOT) / "d26/transport_limits__pipeboard_limits.py").read_bytes()
    raw_red = (Path(_APP_ROOT) / "d26/reducer__meta_daily_contract.py").read_bytes()
    _verify_git_blob_and_sha(raw_lim, "306d2b1f5eae7084f5c1daca7f042e1b1d89350b", "sha256:cb1b73273d1942fdc9fc334639bd74eaddcf6af3e65a02a29eb8b60f94ff0ce5")
    _verify_git_blob_and_sha(raw_red, "0dbdfede6c4a9eaffb35197118e80d8d72507335", "sha256:9e5b2f24a05029980748a9e7a8ae40e00fedc30b9bdf07be532d8a55a7eab9c9")
    lim_ns: dict[str, Any] = {"__builtins__": dict(_RESTRICTED_BUILTINS), "Final": Final}
    lim_nodes = [s for s in ast.parse(raw_lim.decode("utf-8"), filename="scripts/pipeboard_limits.py").body if (isinstance(s, ast.Assign) and len(s.targets) == 1 and isinstance(s.targets[0], ast.Name) and s.targets[0].id == "MAX_RESPONSE_BYTES") or (isinstance(s, ast.AnnAssign) and isinstance(s.target, ast.Name) and s.target.id == "MAX_RESPONSE_BYTES")]
    builtins.exec(builtins.compile(ast.Module(body=lim_nodes, type_ignores=[]), "pipeboard_limits.py", "exec", flags=__future__.annotations.compiler_flag, dont_inherit=True), lim_ns)
    allowed_assigns = {"MAX_ROWS", "_INTEGER_TEXT", "_MONEY_TEXT", "_META_CAMPAIGN_ID", "_ROW_KEYS"}
    allowed_funcs = {"_load_text_payload", "_integer_metric", "_spend_minor", "normalize_meta_result"}
    red_nodes = [s for s in ast.parse(raw_red.decode("utf-8"), filename="scripts/operator/meta_daily_contract.py").body if (isinstance(s, ast.Assign) and len(s.targets) == 1 and isinstance(s.targets[0], ast.Name) and s.targets[0].id in allowed_assigns) or (isinstance(s, ast.AnnAssign) and isinstance(s.target, ast.Name) and s.target.id in allowed_assigns) or (isinstance(s, ast.ClassDef) and s.name == "MetaDailyContractError") or (isinstance(s, ast.FunctionDef) and s.name in allowed_funcs)]
    ns: dict[str, Any] = {"__name__": "_pinned_0dbdfede", "__builtins__": dict(_RESTRICTED_BUILTINS), "Any": Any, "Decimal": decimal.Decimal, "Final": Final, "InvalidOperation": decimal.InvalidOperation, "MAX_RESPONSE_BYTES": lim_ns["MAX_RESPONSE_BYTES"], "Mapping": Mapping, "cast": cast, "json": json, "re": re}
    builtins.exec(builtins.compile(ast.Module(body=red_nodes, type_ignores=[]), "meta_daily_contract.py", "exec", flags=__future__.annotations.compiler_flag, dont_inherit=True), ns)
    fn = ns["normalize_meta_result"]

    def _reducer(mcp_result: dict[str, Any]) -> list[dict[str, int]]:
        detached = json.loads(json.dumps(mcp_result))
        with decimal.localcontext(decimal.Context(prec=28)):
            out = fn(detached)
        return [dict(item) for item in out["records"]]

    return _reducer


def _load_7a_replay_objects(mods: Mapping[str, Any]) -> tuple[dict[str, Any], Any, Any]:
    loads_jcs, ArtifactLocator = mods["jcs"].loads_strict_json, mods["jcs"].ArtifactLocator
    corpus_doc = loads_jcs((Path(_FIXTURES_ROOT) / "pipeboard_7a_corpus_v1.json").read_bytes())
    rctx = loads_jcs((Path(_FIXTURES_ROOT) / "replay_context_v1.json").read_bytes())
    snap_d = rctx["snapshot"] if "snapshot" in rctx else rctx["registry_snapshot"]
    snap_loc_d = rctx["snapshot_locator"] if "snapshot_locator" in rctx else rctx["registry_snapshot_locator"]
    reg_state = mods["cr"].ResolvedRegistryState(ArtifactLocator.from_dict(snap_loc_d), mods["reg"].PrivateRegistrySnapshot.from_dict(snap_d), ArtifactLocator.from_dict(rctx["driver_contract_locator"]), mods["pb_c"].PipeboardPhase1Contract.from_dict(rctx["driver_contract"]))
    if "expected_inventories" in rctx:
        inv_pairs = [(ArtifactLocator.from_dict(it["locator"] if "locator" in it else it["expected_inventory_locator"]), mods["reg"].ExpectedResourceInventory.from_dict(it["inventory"] if "inventory" in it else it["expected_inventory"])) for it in rctx["expected_inventories"]]
    else:
        inv_pairs = [(ArtifactLocator.from_dict(rctx["expected_inventory_locator"]), mods["reg"].ExpectedResourceInventory.from_dict(rctx["expected_inventory"]))]
    kh = mods["rref"].TenantResourceKeyHandle(corpus_doc["tenant_ref"], corpus_doc["key_identity"], bytes.fromhex(corpus_doc["tenant_hmac_key_hex"]))
    priv_map = {(b["binding_ref"], b["account_ref"]): b["private_object_id"] for b in corpus_doc["private_account_bindings"]}
    bnd = mods["pb"].PrivatePipeboardBindingBoundary(resolved_registry=reg_state, key_handle=kh, private_account_bindings=priv_map, authenticated_inventories=inv_pairs)
    for pair in corpus_doc["verified_campaign_pairs"]:
        bnd.register_verified_campaign_pair(pair["raw_campaign_id"], pair["resource_ref"])
    return corpus_doc, reg_state, bnd


def _run_pos_7a_case(task_spec: Mapping[str, Any]) -> None:
    site_pkg = f"{_APP_ROOT}/venv/lib/python3.12/site-packages"
    if site_pkg not in sys.path:
        sys.path.insert(0, site_pkg)
    mods = {k: importlib.import_module(m) for k, m in (("pb", "smart_ads.adapters.pipeboard"), ("lat", "smart_ads.analytics.lattice"), ("app", "smart_ads.application"), ("jcs", "smart_ads.contracts.jcs"), ("sch", "smart_ads.contracts.schemas"), ("pb_c", "smart_ads.domain.pipeboard_contract"), ("reg", "smart_ads.domain.registry"), ("rref", "smart_ads.domain.resource_ref"), ("cr", "smart_ads.ports.cell_runtime"))}
    pinned_reducer = _compile_container_d26_reducer()
    corpus_doc, reg_state, bnd = _load_7a_replay_objects(mods)
    matches = [c for c in corpus_doc["cases"] if c["case_id"] == task_spec["case_id"]]
    if len(matches) != 1:
        raise RuntimeError(f"unknown or duplicate 7A case_id: {task_spec.get(\'case_id\')!r}")
    c = matches[0]
    ArtifactLocator, canon_jcs = mods["jcs"].ArtifactLocator, mods["jcs"].canonicalize_jcs
    sbx_loc = ArtifactLocator.from_dict(task_spec["sealed_sandbox_profile_locator"])
    reg_fix = mods["lat"].RegressionFixtureV1.canonical(reg_state.locator.content_digest)
    reg_fix_loc = ArtifactLocator.for_canonical_bytes(mods["lat"].RegressionFixtureV1.SCHEMA, canon_jcs(reg_fix.to_dict()))
    tz_snap = mods["cr"].TimezoneRuleSnapshot.from_dict(corpus_doc["timezone_snapshot"])
    att = mods["cr"].ClockAttestation.from_dict(c["clock_reading"]["attestation"])
    clk = mods["cr"].ResolvedClockState(ArtifactLocator.for_canonical_bytes(mods["cr"].ClockAttestation.SCHEMA, canon_jcs(att.to_dict())), att, c["clock_reading"]["configured_max_uncertainty_ms"])
    prereq = mods["cr"].ResolvedPrerequisiteBundle(mods["sch"].PurposePrerequisiteLocators("fixture_7a", sealed_sandbox_profile_locator=sbx_loc, regression_fixture_locator=reg_fix_loc))
    sp = type("_SP", (), {"get_authenticated_clock": lambda _s: clk, "get_reporting_timezone_rules": lambda _s: tz_snap, "get_active_registry": lambda _s, *, tenant_ref: reg_state, "resolve_prerequisites": lambda _s, **_k: prereq})()
    ports, req = mods["cr"].CellRuntimePorts(sp, sp, sp, sp), mods["sch"].CollectionRequest.from_dict(c["collection_request"])
    adm, hr = mods["app"].admit_collection(req, ports, admission_id=c["admission_id"]), c["http_response"]
    adapter = mods["pb"].PipeboardFixtureAdapter(boundary=bnd, reducer=pinned_reducer)
    adapter.register_fixture_case(admitted=adm.admitted, retrieval_context=mods["sch"].RetrievalContext.from_dict(c["retrieval_context"]), network_ok=hr["network_ok"], http_status=hr["http_status"], headers=[(h[0], h[1]) for h in hr["headers"]], body_chunks=[hr["body_utf8"].encode("utf-8")])
    ev = mods["app"].evaluate_fixture_collection(req, admission_id=c["admission_id"], cell_ports=ports, fixture_port=adapter, inventory_port=bnd)
    out = {"case_id": c["case_id"], "admitted_collection_digest": adm.locator.content_digest, "observation_batch": adapter.get_recorded_batch(ev.admitted_locator).to_dict(), "observed_completeness_status": ev.completeness.status, "normalized_fact_set_digest": ev.completeness.normalized_fact_set_digest}
    _write_all(1, canon_jcs(out) + b"\\n")
    os._exit(0)


def _run_pep517_build(task_spec: Mapping[str, Any]) -> None:
    if type(task_spec.get("source_date_epoch")) is not int:
        raise RuntimeError("source_date_epoch must be strict int")
    wheel_out, pep_tmp = Path(_TMP_ROOT) / "wheel_out", Path(_TMP_ROOT) / "pep517_tmp"
    wheel_out.mkdir(parents=True, exist_ok=True)
    pep_tmp.mkdir(parents=True, exist_ok=True)
    orig_argv, orig_stdout, cap_buf = sys.argv, sys.stdout, io.StringIO()
    sys.argv = [sys.executable, f"{_APP_ROOT}/backend_site", str(task_spec["closure_mods_csv"]), f"{_APP_ROOT}/stage", str(wheel_out), str(pep_tmp), str(task_spec["source_date_epoch"]), str(task_spec["runner_bootstrap"])]
    sys.stdout = cap_buf
    try:
        builtins.exec(builtins.compile(str(task_spec["driver_script"]), "<pep517_driver>", "exec"), {"__name__": "__main__"})
    finally:
        sys.stdout, sys.argv = orig_stdout, orig_argv
    wheel_name = json.loads(cap_buf.getvalue()).get("wheel_name")
    if type(wheel_name) is not str or Path(wheel_name).name != wheel_name or wheel_name in ("", ".", ".."):
        raise RuntimeError(f"invalid PEP 517 wheel_name: {wheel_name!r}")
    whl_bytes = (wheel_out / wheel_name).read_bytes()
    _write_all(1, json.dumps({"wheel_name": wheel_name, "wheel_b64": base64.b64encode(whl_bytes).decode("ascii")}, sort_keys=True).encode("utf-8") + b"\\n")
    os._exit(0)


def main() -> None:
    libc, task_spec = _startup_handshake()
    kind = task_spec.get("kind")
    if kind == "preflight_noop":
        os._exit(0)
    elif kind == "neg":
        _run_neg_case(libc, task_spec)
    elif kind == "pos_7a_case":
        _run_pos_7a_case(task_spec)
    elif kind == "pep517_build":
        _run_pep517_build(task_spec)
    else:
        raise RuntimeError(f"unsupported container task kind: {kind!r}")


if __name__ == "__main__":
    main()
'''

VENV_PROBE_BOOTSTRAP_SOURCE: Final[str] = '''from __future__ import annotations

import builtins
import ctypes
import json
import os
from pathlib import Path
import struct
import sys
from typing import Any


class _SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]


_ACTIVE_BPF_HOLD: list[Any] = []
_SECCOMP_BPF_PATH = "/app/seccomp_filter.bpf"


def _configure_roots_for_test(root: str) -> None:
    global _SECCOMP_BPF_PATH
    _SECCOMP_BPF_PATH = f"{root}/app/seccomp_filter.bpf"


def _write_all(fd: int, data: bytes) -> None:
    view, sent = memoryview(data), 0
    while sent < len(view):
        n = os.write(fd, view[sent:])
        if n <= 0:
            raise RuntimeError("short write on pipe")
        sent += n


def _read_exact(fd: int, size: int) -> bytes:
    chunks, rem = [], size
    while rem > 0:
        chunk = os.read(fd, rem)
        if not chunk:
            raise RuntimeError("unexpected EOF on pipe")
        chunks.append(chunk)
        rem -= len(chunk)
    return b"".join(chunks)


def _startup_venv_handshake() -> dict[str, Any]:
    libc = ctypes.CDLL(None, use_errno=True)
    os.closerange(3, 65536)
    _write_all(1, b"SMART-ADS-OCI-PREMASK\\n")
    seccomp_mode = os.read(0, 1)
    if seccomp_mode != b"\\x01":
        raise RuntimeError(f"venv probe requires 0x01 7A seccomp mode, got {seccomp_mode!r}")
    bpf_raw = Path(_SECCOMP_BPF_PATH).read_bytes()
    if len(bpf_raw) == 0 or len(bpf_raw) % 8 != 0 or (len(bpf_raw) // 8) > 4096 or ctypes.sizeof(_SockFprog) != 16:
        raise RuntimeError("invalid 7A seccomp BPF image")
    bpf_buf = ctypes.create_string_buffer(bpf_raw, len(bpf_raw))
    prog = _SockFprog(len(bpf_raw) // 8, ctypes.cast(bpf_buf, ctypes.c_void_p).value)
    _ACTIVE_BPF_HOLD.extend((bpf_buf, prog))
    libc.prctl.restype = ctypes.c_int
    if libc.prctl(38, 1, 0, 0, 0) != 0 or libc.prctl(22, 2, ctypes.byref(prog), 0, 0) != 0:
        raise RuntimeError("prctl seccomp installation failed")
    _write_all(1, b"SMART-ADS-OCI-READY\\n")
    go_byte = os.read(0, 1)
    if go_byte == b"":
        os._exit(0)
    if go_byte != b"\\x02":
        raise RuntimeError(f"invalid GO byte: {go_byte!r}")
    u32_len = struct.unpack(">I", _read_exact(0, 4))[0]
    if not (1 <= u32_len <= 131072):
        raise RuntimeError(f"venv probe task length out of bounds: {u32_len}")
    task_spec = json.loads(_read_exact(0, u32_len).decode("utf-8"))
    if not isinstance(task_spec, dict):
        raise RuntimeError("venv probe task_spec must be JSON object")
    return task_spec


def main() -> None:
    task_spec = _startup_venv_handshake()
    probe_argv, probe_script = task_spec.get("probe_argv"), task_spec.get("probe_script")
    if type(probe_argv) is not list or not probe_argv or any(type(x) is not str for x in probe_argv) or type(probe_script) is not str or not probe_script:
        raise RuntimeError("venv probe requires non-empty probe_argv list[str] and probe_script str")
    sys.argv = list(probe_argv)
    builtins.exec(builtins.compile(probe_script, "<probe>", "exec"), {"__name__": "__main__"})
    sys.stdout.flush()
    os._exit(0)


if __name__ == "__main__":
    main()
'''


def encode_go_task_frame(task_spec: Mapping[str, Any]) -> bytes:
    """Encode `GO_BYTE + u32_be(len) + canonical_jcs(task_spec)` enforcing 4 KiB / 64 KiB bounds."""
    if not isinstance(task_spec, Mapping) or len(task_spec) == 0:
        raise ValueError("task_spec: expected non-empty Mapping")
    spec_dict = dict(task_spec)
    raw = canonicalize(spec_dict)
    loads_strict(raw.decode("utf-8"))
    kind = spec_dict.get("kind")
    is_stage7_script = kind not in _SEVEN_A_TASK_KINDS and (
        kind in _STAGE7_SCRIPT_KINDS or "driver_script" in spec_dict or "probe_script" in spec_dict
    )
    max_bytes = 65_536 if is_stage7_script else 4096
    if not (1 <= len(raw) <= max_bytes):
        raise ValueError(f"task_spec: canonical JCS size {len(raw)} exceeds ceiling {max_bytes}")
    return GO_BYTE + struct.pack(">I", len(raw)) + raw


def _call_func_name(call_node: ast.Call) -> str | None:
    if isinstance(call_node.func, ast.Name):
        return call_node.func.id
    return call_node.func.attr if isinstance(call_node.func, ast.Attribute) else None


def _verify_single_embedded_source(source: str, label: str) -> None:
    if type(source) is not str or not source.strip():
        raise ValueError(f"{label}: expected non-empty Python source string")
    tree = ast.parse(source, filename=label)
    cdll_positions: list[tuple[int, int]] = []
    closerange_positions: list[tuple[int, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assert):
            raise ValueError(f"{label}: ast.Assert is forbidden")
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            span = (node.end_lineno or node.lineno) - node.lineno + 1
            if span >= 50:
                raise ValueError(f"{label}:{node.name} has {span} lines (must be < 50)")
        elif isinstance(node, ast.Import) and any(a.name.split(".")[0] == "smart_ads" for a in node.names):
            raise ValueError(f"{label}: direct import smart_ads is forbidden")
        elif isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] == "smart_ads":
            raise ValueError(f"{label}: direct from smart_ads import is forbidden")
        elif isinstance(node, ast.Call):
            cname = _call_func_name(node)
            if cname == "CDLL":
                cdll_positions.append((node.lineno, node.col_offset))
            elif cname == "closerange":
                closerange_positions.append((node.lineno, node.col_offset))
    if not cdll_positions or not closerange_positions or min(cdll_positions) >= min(closerange_positions):
        raise ValueError(f"{label}: ctypes.CDLL must precede os.closerange in startup order")


def verify_embedded_runner_sources() -> None:
    """Verify AST purity, `< 50` line function budgets, and `CDLL` -> `closerange` ordering."""
    _verify_single_embedded_source(CONTAINER_RUNNER_SOURCE, "CONTAINER_RUNNER_SOURCE")
    _verify_single_embedded_source(VENV_PROBE_BOOTSTRAP_SOURCE, "VENV_PROBE_BOOTSTRAP_SOURCE")


verify_embedded_runner_sources()

__all__ = [
    "CONTAINER_RUNNER_SOURCE", "GO_BYTE", "PREMASK_BANNER", "READY_BANNER",
    "SECCOMP_MODE_7A", "SECCOMP_MODE_SKIP", "SECCOMP_MODE_STAGE7_PEP517",
    "VENV_PROBE_BOOTSTRAP_SOURCE", "encode_go_task_frame", "verify_embedded_runner_sources",
]
