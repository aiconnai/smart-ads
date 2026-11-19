"""Passive stdlib builder and verifier for `smart_ads/negative_security_test_report/v1` (ADR-0001 §3.2)."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
import copy
import datetime
import re
from types import MappingProxyType
from typing import Any, Final
import unicodedata

from tools.governance import p1
from tools.governance.gov1_sandbox import (
    LOCAL_CANDIDATE_KIND, SANDBOX_PROFILE_ID, SANDBOX_PROFILE_SCHEMA, SANDBOX_RESOURCES_VERSION,
    build_local_candidate_ref, unwrap_local_candidate, verify_local_candidate_ref, wrap_local_candidate,
)
from tools.governance.gov1_wheel import (
    DEFAULT_REPOSITORY, EXPECTED_BUILD_BACKEND, EXPECTED_BUILD_BACKEND_VERSION, EXPECTED_PYTHON_ABI_TAG,
    MAX_JCS_SAFE_INT, WHEEL_BUILD_PROVENANCE_SCHEMA, verify_wheel_object_locator,
)
from tools.governance.jcs import canonicalize, loads_strict
from tools.governance.locator import digest, exact_fields, json_digest, make_locator, validate_locator

NEGATIVE_SECURITY_REPORT_SCHEMA: Final[str] = "smart_ads/negative_security_test_report/v1"
_RUN_CONTEXT_SCHEMA: Final[str] = "smart_ads/migration_run_context/v1"
_KEY_REGISTRY_SCHEMA: Final[str] = "smart_ads/key_authorization_registry/v1"

MANDATORY_7A_NEGATIVE_CASES: Final[tuple[str, ...]] = tuple(
    "cpu_limit_enforced credential_paths_denied env_is_exact_allowlist file_size_limit_enforced "
    "host_dev_denied host_home_denied host_proc_denied host_sys_denied inherited_fd_denied "
    "memory_limit_enforced output_limit_enforced pids_limit_enforced process_creation_denied "
    "socket_denied tmpfs_limit_enforced wall_clock_limit_enforced write_outside_tmp_denied".split()
)
PINNED_7A_NEGATIVE_SUITE_DIGEST: Final[str] = json_digest({
    "suite_id": "smart_ads/7a_negative_security_suite/v1",
    "profile_id": SANDBOX_PROFILE_ID,
    "cases": list(MANDATORY_7A_NEGATIVE_CASES),
})

_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"\Asha256:[0-9a-f]{64}\Z")
_HEX40_RE: Final[re.Pattern[str]] = re.compile(r"\A[0-9a-f]{40}\Z")
_KEY_ID_RE: Final[re.Pattern[str]] = re.compile(r"\Akey:ed25519:[0-9a-f]{64}\Z")
_OPAQUE_REF_RE: Final[re.Pattern[str]] = re.compile(r"\A[a-z][a-z0-9_]*:[A-Za-z0-9._:-]+\Z")
_UTC_SEC_RE: Final[re.Pattern[str]] = re.compile(r"\A([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z\Z")
_EPOCH_DATE: Final[datetime.date] = datetime.date(1970, 1, 1)

_EXACT_ENV: Final[Mapping[str, str]] = MappingProxyType({
    "HOME": "/nonexistent", "LANG": "C.UTF-8", "PATH": "/usr/bin:/bin",
    "PYTHONNOUSERSITE": "1", "PYTHONSAFEPATH": "1", "TMPDIR": "/tmp", "TZ": "UTC",
})
_EXACT_NAMESPACES: Final[tuple[str, ...]] = ("mount", "network", "pid", "ipc", "uts", "user")
_EXACT_RO_MOUNTS: Final[tuple[str, ...]] = ("/app", "/fixtures")
_EXACT_TMPFS_MOUNTS: Final[tuple[str, ...]] = ("/tmp",)
_EXACT_MASKED_MOUNTS: Final[tuple[str, ...]] = ("/proc", "/sys", "/dev", "/home", "/run", "/var/run")
_EXACT_TMP_FLAGS: Final[tuple[str, ...]] = ("nodev", "noexec", "nosuid")
_ALLOWED_CAUSES: Final[frozenset[str]] = frozenset(
    "clean_exit cpu_time_limit memory_oom pids_max_limit tmpfs_enospc rlimit_fsize stdout_limit stderr_limit wall_clock_watchdog".split()
)
_ALLOWED_SIGNALS: Final[frozenset[str]] = frozenset({"SIGKILL", "SIGXCPU", "SIGXFSZ", "SIGTERM"})
_SHARED_RUNTIME_16_FIELDS: Final[frozenset[str]] = frozenset(
    "profile_id runtime_kind platform rootfs_read_only oci_image_digest runner_binary_digest "
    "exact_environment namespaces read_only_mounts fresh_tmpfs_mounts masked_empty_mounts "
    "host_bind_mounts_forbidden all_capabilities_dropped no_new_privs inherited_fds_above_2_closed seccomp_profile_digest".split()
)
_SPEC_17_FIELDS: Final[frozenset[str]] = _SHARED_RUNTIME_16_FIELDS | {"resource_limits"}
_SANDBOX_PAYLOAD_20_KEYS: Final[set[str]] = set(_SPEC_17_FIELDS) | {"migration_run_context_locator", "issued_at_utc", "validity"}
_WHEEL_PROVENANCE_16_KEYS: Final[set[str]] = set(
    "migration_run_context_locator build_run_id built_at_utc repository source_commit_sha source_tree_oid "
    "source_date_epoch python_abi_tag build_backend build_backend_version build_backend_digest "
    "pyproject_sha256 uv_lock_sha256 schema_bundle_digest wheel wheel_digest".split()
)
_PINNED_INT_LIMITS: Final[tuple[tuple[str, int], ...]] = (
    ("cgroup_version", 2), ("cpu_time_limit_seconds", 120), ("memory_max_bytes", 1_073_741_824),
    ("memory_swap_max_bytes", 0), ("pids_max", 32), ("rlimit_fsize_bytes", 67_108_864),
    ("stdout_max_bytes", 8_388_608), ("stderr_max_bytes", 8_388_608), ("wall_clock_timeout_seconds", 300), ("termination_grace_ms", 1000),
)
_RESOURCE_LIMITS_KEYS: Final[set[str]] = {"profile_version", "cpu_max", "tmpfs_limits"} | {k for k, _ in _PINNED_INT_LIMITS}
_READBACK_KEYS: Final[set[str]] = set(_SHARED_RUNTIME_16_FIELDS) | {"effective_writable_mounts", "seccomp_enforced_before_entry", "network_absent", "loopback_absent"}
_USAGE_KEYS: Final[set[str]] = set("cpu_time_us memory_peak_bytes pids_peak tmpfs_peak_bytes tmpfs_peak_inodes max_file_bytes stdout_bytes stderr_bytes oom_delta oom_kill_delta pids_max_delta".split())
_TERM_KEYS: Final[set[str]] = set("cause supervisor_terminated_cgroup exit_code signal watchdog_elapsed_ms grace_elapsed_ms whole_cgroup_empty force_kill_used".split())
_RUN_KEYS: Final[set[str]] = set("sandbox_instance_ref execution_binding_digest started_at_utc ended_at_utc runtime_readback effective_resource_limits usage termination observation".split())
_NEG_COMMON_12_KEYS: Final[set[str]] = set("migration_run_context_locator build_run_id executed_at_utc source_commit_sha build_backend_digest schema_bundle_digest wheel_digest oci_image_digest runner_binary_digest test_suite_digest declared_resource_limits cases".split())
_NEG_CANDIDATE_14_KEYS: Final[set[str]] = _NEG_COMMON_12_KEYS | {"sealed_sandbox_profile_candidate_ref", "wheel_build_provenance_candidate_ref"}
_NEG_ENVELOPE_PAYLOAD_14_KEYS: Final[set[str]] = _NEG_COMMON_12_KEYS | {"sealed_sandbox_profile_locator", "wheel_build_provenance_locator"}
_NEG_ENVELOPE_16_KEYS: Final[set[str]] = _NEG_ENVELOPE_PAYLOAD_14_KEYS | {"$schema", "integrity"}

_EXACT_DENIAL_OBS: Final[Mapping[str, Mapping[str, Any]]] = MappingProxyType({
    "env_is_exact_allowlist": MappingProxyType({"environment_matches": True}),
    "host_dev_denied": MappingProxyType({"mount": "/dev", "host_access_denied": True}),
    "host_home_denied": MappingProxyType({"mount": "/home", "host_access_denied": True}),
    "host_proc_denied": MappingProxyType({"mount": "/proc", "host_access_denied": True}),
    "host_sys_denied": MappingProxyType({"mount": "/sys", "host_access_denied": True}),
    "inherited_fd_denied": MappingProxyType({"probe_set_id": "inherited_fds_above_2_v1", "inherited_fd_count_above_2": 0}),
    "write_outside_tmp_denied": MappingProxyType({"probe_target_id": "rootfs_non_tmp_v1", "creation_denied": True}),
})
_COUNTED_DENIAL_OBS: Final[Mapping[str, tuple[str, int]]] = MappingProxyType({
    "credential_paths_denied": ("credential_paths_v1", 1),
    "process_creation_denied": ("seccomp_process_creation_v1", 4),
    "socket_denied": ("seccomp_socket_v1", 2),
})
_STATIC_RESOURCE_SPECS: Final[Mapping[str, tuple[str, bool, frozenset[str], str, Mapping[str, Any]]]] = MappingProxyType({
    "cpu_limit_enforced": ("B_cpu", True, frozenset({"SIGXCPU", "SIGKILL"}), "cpu_time_limit", MappingProxyType({"quota_readback_matched": True, "cpu_time_exhausted": True})),
    "file_size_limit_enforced": ("B_fsize", True, frozenset({"SIGXFSZ", "SIGKILL"}), "rlimit_fsize", MappingProxyType({"file_size_at_ceiling": True, "limit_signal_observed": True})),
    "memory_limit_enforced": ("B_mem", True, frozenset({"SIGKILL"}), "memory_oom", MappingProxyType({"controller": "memory", "event": "oom_kill"})),
    "pids_limit_enforced": ("B_pids", False, frozenset({"SIGTERM", "SIGKILL"}), "pids_max_limit", MappingProxyType({"probe_phase": "pre_seccomp_trusted_harness", "event": "pids_max"})),
    "wall_clock_limit_enforced": ("B_wall", True, frozenset({"SIGKILL"}), "wall_clock_watchdog", MappingProxyType({"watchdog_fired": True, "whole_cgroup_terminated": True})),
})


def _strict_str(value: object, label: str) -> str:
    if type(value) is not str or not value or value != value.strip() or any(0xD800 <= ord(c) <= 0xDFFF or ord(c) < 32 or ord(c) == 127 for c in value) or not unicodedata.is_normalized("NFC", value):
        raise ValueError(f"{label}: expected non-empty stripped NFC string without ASCII control chars")
    return value


def _exact_str(value: object, expected: str, label: str) -> str:
    if type(value) is not str or value != expected:
        raise ValueError(f"{label}: expected exact string {expected!r}")
    return value


def _exact_bool(value: object, expected: bool, label: str) -> bool:
    if type(value) is not bool or value is not expected:
        raise ValueError(f"{label}: expected exact bool {expected!r}")
    return expected


def _strict_int(value: object, label: str, *, minimum: int = 0, maximum: int = MAX_JCS_SAFE_INT) -> int:
    if type(value) is not int or not (minimum <= value <= maximum):
        raise ValueError(f"{label}: expected int in [{minimum}, {maximum}]")
    return value


def _sha256_str(value: object, label: str) -> str:
    checked = _strict_str(value, label)
    if _SHA256_RE.fullmatch(checked) is None:
        raise ValueError(f"{label}: expected 'sha256:<64_lowercase_hex>'")
    return checked


def _hex40_str(value: object, label: str) -> str:
    checked = _strict_str(value, label)
    if _HEX40_RE.fullmatch(checked) is None:
        raise ValueError(f"{label}: expected 40 lowercase hex chars")
    return checked


def _key_id_str(value: object, label: str) -> str:
    checked = _strict_str(value, label)
    if _KEY_ID_RE.fullmatch(checked) is None:
        raise ValueError(f"{label}: expected 'key:ed25519:<64_lowercase_hex>'")
    return checked


def _opaque_ref_str(value: object, label: str, *, expected_prefix: str | None = None) -> str:
    checked = _strict_str(value, label)
    if _OPAQUE_REF_RE.fullmatch(checked) is None or (expected_prefix is not None and checked.split(":", 1)[0] != expected_prefix):
        raise ValueError(f"{label}: invalid opaque_ref {checked!r}")
    return checked


def _utc_sec_micros(value: object, label: str) -> int:
    if type(value) is not str or (m := _UTC_SEC_RE.fullmatch(value)) is None:
        raise ValueError(f"{label}: expected YYYY-MM-DDTHH:MM:SSZ")
    yr, mo, dy, hr, mi, sc = (int(m.group(i)) for i in range(1, 7))
    try:
        cal = datetime.date(yr, mo, dy)
    except ValueError as exc:
        raise ValueError(f"{label}: invalid calendar date") from exc
    if not (0 <= hr <= 23 and 0 <= mi <= 59 and 0 <= sc <= 59):
        raise ValueError(f"{label}: invalid HMS")
    return ((((cal - _EPOCH_DATE).days * 24 + hr) * 60 + mi) * 60 + sc) * 1_000_000


def _exact_str_list(value: object, expected: tuple[str, ...], label: str) -> list[str]:
    if type(value) is not list or any(type(x) is not str for x in value) or tuple(value) != expected:
        raise ValueError(f"{label}: expected exact list {list(expected)!r}")
    return list(expected)


def _exact_typed_dict(value: object, expected: Mapping[str, Any], label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{label}: expected Mapping")
    as_dict = dict(value)
    exact_fields(as_dict, set(expected.keys()), label)
    for k, exp_v in expected.items():
        if type(as_dict[k]) is not type(exp_v) or as_dict[k] != exp_v:
            raise ValueError(f"{label}.{k}: expected {exp_v!r}")
    return copy.deepcopy(as_dict)


def _verify_p1_integrity(envelope: Mapping[str, Any], *, label: str, require_signed: bool = False) -> None:
    integ = envelope.get("integrity")
    if not isinstance(integ, Mapping):
        raise ValueError(f"{label}.integrity: expected JSON object")
    keys, unsigned_keys = set(integ.keys()), {"key_id", "key_registry_snapshot_locator"}
    signed_keys = unsigned_keys | {"content_digest", "signature_base64"}
    if keys not in ((signed_keys,) if require_signed else (unsigned_keys, signed_keys)):
        raise ValueError(f"{label}.integrity: invalid P1 integrity key set")
    _key_id_str(integ["key_id"], f"{label}.integrity.key_id")
    if not isinstance(integ["key_registry_snapshot_locator"], Mapping):
        raise ValueError(f"{label}.integrity.key_registry_snapshot_locator: expected Mapping")
    validate_locator(dict(integ["key_registry_snapshot_locator"]), _KEY_REGISTRY_SCHEMA)
    if keys == signed_keys:
        if _sha256_str(integ["content_digest"], f"{label}.integrity.content_digest") != p1.content_digest(dict(envelope)):
            raise ValueError(f"{label}.integrity.content_digest: mismatch against P1 preimage")
        sig_b64 = integ["signature_base64"]
        if type(sig_b64) is not str or len(p1._strict_base64_decode(sig_b64)) != 64:
            raise ValueError(f"{label}.integrity.signature_base64: expected 64-byte base64 signature")


def _validate_resource_limits_dict(raw: object, label: str) -> dict[str, Any]:
    d = dict(raw) if isinstance(raw, Mapping) else {}
    exact_fields(d, _RESOURCE_LIMITS_KEYS, label)
    _exact_str(d["profile_version"], SANDBOX_RESOURCES_VERSION, f"{label}.profile_version")
    _exact_typed_dict(d["cpu_max"], {"quota_us": 100_000, "period_us": 100_000}, f"{label}.cpu_max")
    tmp_outer = dict(d["tmpfs_limits"]) if isinstance(d["tmpfs_limits"], Mapping) else {}
    exact_fields(tmp_outer, {"/tmp"}, f"{label}.tmpfs_limits")
    tmp_inner = dict(tmp_outer["/tmp"]) if isinstance(tmp_outer["/tmp"], Mapping) else {}
    exact_fields(tmp_inner, {"size_bytes", "inodes_max", "mount_flags"}, f"{label}.tmpfs_limits./tmp")
    _strict_int(tmp_inner["size_bytes"], f"{label}.size_bytes", minimum=268_435_456, maximum=268_435_456)
    _strict_int(tmp_inner["inodes_max"], f"{label}.inodes_max", minimum=4096, maximum=4096)
    _exact_str_list(tmp_inner["mount_flags"], _EXACT_TMP_FLAGS, f"{label}.mount_flags")
    for k, exp_i in _PINNED_INT_LIMITS:
        _strict_int(d[k], f"{label}.{k}", minimum=exp_i, maximum=exp_i)
    return copy.deepcopy(d)


def _validate_shared_runtime_16(m: Mapping[str, Any], label: str) -> None:
    for k, exp_s in (("profile_id", SANDBOX_PROFILE_ID), ("runtime_kind", "oci"), ("platform", "linux/amd64")):
        _exact_str(m[k], exp_s, f"{label}.{k}")
    for k in ("rootfs_read_only", "host_bind_mounts_forbidden", "all_capabilities_dropped", "no_new_privs", "inherited_fds_above_2_closed"):
        _exact_bool(m[k], True, f"{label}.{k}")
    for k in ("oci_image_digest", "runner_binary_digest", "seccomp_profile_digest"):
        _sha256_str(m[k], f"{label}.{k}")
    _exact_typed_dict(m["exact_environment"], _EXACT_ENV, f"{label}.exact_environment")
    for k, exp_seq in (("namespaces", _EXACT_NAMESPACES), ("read_only_mounts", _EXACT_RO_MOUNTS), ("fresh_tmpfs_mounts", _EXACT_TMPFS_MOUNTS), ("masked_empty_mounts", _EXACT_MASKED_MOUNTS)):
        _exact_str_list(m[k], exp_seq, f"{label}.{k}")


def _validate_runtime_readback_dict(raw: object, label: str) -> dict[str, Any]:
    d = dict(raw) if isinstance(raw, Mapping) else {}
    exact_fields(d, _READBACK_KEYS, label)
    _validate_shared_runtime_16(d, label)
    _exact_str_list(d["effective_writable_mounts"], _EXACT_TMPFS_MOUNTS, f"{label}.effective_writable_mounts")
    if type(d["seccomp_enforced_before_entry"]) is not bool:
        raise ValueError(f"{label}.seccomp_enforced_before_entry: expected bool")
    _exact_bool(d["network_absent"], True, f"{label}.network_absent")
    _exact_bool(d["loopback_absent"], True, f"{label}.loopback_absent")
    return copy.deepcopy(d)


def _validate_usage_and_termination(raw_u: object, raw_t: object, label: str) -> tuple[dict[str, int], dict[str, Any]]:
    if not isinstance(raw_u, Mapping) or not isinstance(raw_t, Mapping):
        raise ValueError(f"{label}: usage and termination must be Mappings")
    u, t = dict(raw_u), dict(raw_t)
    exact_fields(u, _USAGE_KEYS, f"{label}.usage")
    exact_fields(t, _TERM_KEYS, f"{label}.termination")
    for k in _USAGE_KEYS:
        _strict_int(u[k], f"{label}.usage.{k}")
    if type(t["cause"]) is not str or t["cause"] not in _ALLOWED_CAUSES or type(t["supervisor_terminated_cgroup"]) is not bool or type(t["force_kill_used"]) is not bool:
        raise ValueError(f"{label}.termination: invalid cause or bool flags")
    if t["exit_code"] is not None:
        _strict_int(t["exit_code"], f"{label}.termination.exit_code", minimum=0, maximum=255)
    if t["signal"] is not None and (type(t["signal"]) is not str or t["signal"] not in _ALLOWED_SIGNALS):
        raise ValueError(f"{label}.termination.signal: invalid {t['signal']!r}")
    _strict_int(t["watchdog_elapsed_ms"], f"{label}.termination.watchdog_elapsed_ms")
    _strict_int(t["grace_elapsed_ms"], f"{label}.termination.grace_elapsed_ms", minimum=0, maximum=1000)
    _exact_bool(t["whole_cgroup_empty"], True, f"{label}.termination.whole_cgroup_empty")
    if t["force_kill_used"] and t["signal"] != "SIGKILL":
        raise ValueError(f"{label}.termination.force_kill_used: True requires signal == 'SIGKILL'")
    return copy.deepcopy(u), copy.deepcopy(t)


def evaluate_breach_predicates(usage: Mapping[str, Any], termination: Mapping[str, Any]) -> dict[str, bool]:
    u, t = _validate_usage_and_termination(usage, termination, "breach_predicates")
    return {
        "B_cpu": u["cpu_time_us"] >= 120_000_000,
        "B_mem": u["memory_peak_bytes"] >= 1_073_741_824 or u["oom_delta"] > 0 or u["oom_kill_delta"] > 0,
        "B_pids": u["pids_max_delta"] > 0 or u["pids_peak"] > 32,
        "B_tmpfs_bytes": u["tmpfs_peak_bytes"] >= 268_435_456, "B_tmpfs_inodes": u["tmpfs_peak_inodes"] >= 4096,
        "B_fsize": u["max_file_bytes"] >= 67_108_864,
        "B_stdout": u["stdout_bytes"] >= 8_388_608, "B_stderr": u["stderr_bytes"] >= 8_388_608,
        "B_wall": t["watchdog_elapsed_ms"] >= 300_000,
    }


def _validate_observation_dict(raw_obs: object, label: str) -> dict[str, Any]:
    if not isinstance(raw_obs, Mapping) or not raw_obs:
        raise ValueError(f"{label}: expected non-empty observation mapping")
    out: dict[str, Any] = {}
    for k, v in raw_obs.items():
        _strict_str(k, f"{label}.key")
        if type(v) is bool:
            out[k] = v
        elif type(v) is int:
            out[k] = _strict_int(v, f"{label}.{k}")
        elif type(v) is str:
            out[k] = _strict_str(v, f"{label}.{k}")
        else:
            raise ValueError(f"{label}.{k}: unsupported value type")
    return out


def _validate_run_dict(raw_run: object, label: str) -> dict[str, Any]:
    r = dict(raw_run) if isinstance(raw_run, Mapping) else {}
    exact_fields(r, _RUN_KEYS, label)
    _opaque_ref_str(r["sandbox_instance_ref"], f"{label}.sandbox_instance_ref")
    _sha256_str(r["execution_binding_digest"], f"{label}.execution_binding_digest")
    if _utc_sec_micros(r["started_at_utc"], f"{label}.start") > _utc_sec_micros(r["ended_at_utc"], f"{label}.end"):
        raise ValueError(f"{label}: started_at_utc > ended_at_utc")
    rb = _validate_runtime_readback_dict(r["runtime_readback"], f"{label}.runtime_readback")
    lim = _validate_resource_limits_dict(r["effective_resource_limits"], f"{label}.effective_resource_limits")
    u, t = _validate_usage_and_termination(r["usage"], r["termination"], label)
    obs = _validate_observation_dict(r["observation"], f"{label}.observation")
    return {"sandbox_instance_ref": r["sandbox_instance_ref"], "execution_binding_digest": r["execution_binding_digest"], "started_at_utc": r["started_at_utc"], "ended_at_utc": r["ended_at_utc"], "runtime_readback": rb, "effective_resource_limits": lim, "usage": u, "termination": t, "observation": obs}


def compute_negative_run_execution_binding_digest(
    *, case_id: str, subrun_index: int, run: Mapping[str, Any],
    wheel_digest: str, test_suite_digest: str, sealed_sandbox_profile_digest: str,
) -> str:
    _strict_str(case_id, "case_id")
    _strict_int(subrun_index, "subrun_index")
    r = _validate_run_dict(run, "run")
    for name, val in (("wheel_digest", wheel_digest), ("test_suite_digest", test_suite_digest), ("sealed_sandbox_profile_digest", sealed_sandbox_profile_digest)):
        _sha256_str(val, name)
    return json_digest({
        "case_id": case_id, "subrun_index": subrun_index, "sandbox_instance_ref": r["sandbox_instance_ref"],
        "started_at_utc": r["started_at_utc"], "ended_at_utc": r["ended_at_utc"], "wheel_digest": wheel_digest,
        "test_suite_digest": test_suite_digest, "sealed_sandbox_profile_digest": sealed_sandbox_profile_digest,
        "runtime_readback": r["runtime_readback"], "effective_resource_limits": r["effective_resource_limits"],
        "usage": r["usage"], "termination": r["termination"], "observation": r["observation"],
    })


def _check_denial_run(case_id: str, run: Mapping[str, Any], label: str) -> None:
    t = run["termination"]
    if any(evaluate_breach_predicates(run["usage"], t).values()) or run["runtime_readback"]["seccomp_enforced_before_entry"] is not True or t["supervisor_terminated_cgroup"] is not False or t["cause"] != "clean_exit" or t["exit_code"] != 0 or t["signal"] is not None or t["force_kill_used"] is not False:
        raise ValueError(f"{label}: invalid clean-exit/seccomp/ceiling state for denial case")
    if case_id in _EXACT_DENIAL_OBS:
        _exact_typed_dict(run["observation"], _EXACT_DENIAL_OBS[case_id], f"{label}.observation")
        return
    probe_set_id, min_cnt = _COUNTED_DENIAL_OBS[case_id]
    obs = dict(run["observation"])
    exact_fields(obs, {"probe_set_id", "denied_probe_count"}, f"{label}.observation")
    _exact_str(obs["probe_set_id"], probe_set_id, f"{label}.probe_set_id")
    _strict_int(obs["denied_probe_count"], f"{label}.denied_probe_count", minimum=min_cnt)


def _check_resource_common(run: Mapping[str, Any], *, label: str, breach_key: str, seccomp: bool, signals: frozenset[str], cause: str) -> None:
    fired = [k for k, v in evaluate_breach_predicates(run["usage"], run["termination"]).items() if v]
    t = run["termination"]
    if fired != [breach_key] or run["runtime_readback"]["seccomp_enforced_before_entry"] is not seccomp or t["supervisor_terminated_cgroup"] is not True or t["exit_code"] is not None or t["signal"] is None or t["signal"] not in signals or t["cause"] != cause:
        raise ValueError(f"{label}: one-hot breach or resource termination/seccomp invariant violated")


def _check_resource_case(case_id: str, runs: list[dict[str, Any]], label: str) -> None:
    if case_id == "output_limit_enforced":
        sigs = frozenset({"SIGTERM", "SIGKILL"})
        for idx, b_k, attr, cause, stream in ((0, "B_stdout", "stdout_bytes", "stdout_limit", "stdout"), (1, "B_stderr", "stderr_bytes", "stderr_limit", "stderr")):
            _check_resource_common(runs[idx], label=f"{label}[{idx}]", breach_key=b_k, seccomp=True, signals=sigs, cause=cause)
            _strict_int(runs[idx]["usage"][attr], f"{label}[{idx}].{attr}", minimum=8_388_608, maximum=8_388_608)
            _exact_typed_dict(runs[idx]["observation"], {"stream": stream, "first_ceiling_reached": True}, f"{label}[{idx}].obs")
        return
    run, u = runs[0], runs[0]["usage"]
    if case_id == "tmpfs_limit_enforced":
        obs = dict(run["observation"])
        exact_fields(obs, {"ceiling_kind", "errno"}, f"{label}.obs")
        _exact_str(obs["errno"], "ENOSPC", f"{label}.obs.errno")
        if obs["ceiling_kind"] not in {"bytes", "inodes"}:
            raise ValueError(f"{label}.obs.ceiling_kind: invalid {obs['ceiling_kind']!r}")
        b_k = "B_tmpfs_bytes" if obs["ceiling_kind"] == "bytes" else "B_tmpfs_inodes"
        _check_resource_common(run, label=label, breach_key=b_k, seccomp=True, signals=frozenset({"SIGTERM", "SIGKILL"}), cause="tmpfs_enospc")
        return
    b_k, seccomp, sigs, cause, exp_obs = _STATIC_RESOURCE_SPECS[case_id]
    _check_resource_common(run, label=label, breach_key=b_k, seccomp=seccomp, signals=sigs, cause=cause)
    _exact_typed_dict(run["observation"], exp_obs, f"{label}.obs")
    if case_id == "file_size_limit_enforced":
        _strict_int(u["max_file_bytes"], f"{label}.max_file_bytes", minimum=67_108_864, maximum=67_108_864)
    elif case_id == "memory_limit_enforced" and (u["oom_kill_delta"] < 1 or not (u["memory_peak_bytes"] >= 1_073_741_824 or u["oom_delta"] >= 1)):
        raise ValueError(f"{label}: missing memory OOM cgroup counters")
    elif case_id == "pids_limit_enforced" and (u["pids_max_delta"] < 1 or u["pids_peak"] > 32):
        raise ValueError(f"{label}: invalid pids.max counters")


def _validate_cases_list(cases: object, *, declared_limits: Mapping[str, Any], oci_digest: str, runner_digest: str, executed_us: int) -> list[dict[str, Any]]:
    if type(cases) is not list:
        raise ValueError("negative_security_test_report.cases: expected JSON array list")
    checked_cases, seen_refs, decl_b = [], set(), canonicalize(dict(declared_limits))
    for idx, raw_case in enumerate(cases):
        lbl = f"negative_security_test_report.cases[{idx}]"
        c = dict(raw_case) if isinstance(raw_case, Mapping) else {}
        exact_fields(c, {"case_id", "outcome", "runs"}, lbl)
        cid = _strict_str(c["case_id"], f"{lbl}.case_id")
        if cid not in MANDATORY_7A_NEGATIVE_CASES:
            raise ValueError(f"{lbl}.case_id: unknown case {cid!r}")
        _exact_str(c["outcome"], "passed", f"{lbl}.outcome")
        if type(c["runs"]) is not list or len(c["runs"]) != (2 if cid == "output_limit_enforced" else 1):
            raise ValueError(f"{lbl}.runs: invalid subrun count")
        runs = [_validate_run_dict(r, f"{lbl}.runs[{i}]") for i, r in enumerate(c["runs"])]
        _check_denial_run(cid, runs[0], lbl) if (cid in _EXACT_DENIAL_OBS or cid in _COUNTED_DENIAL_OBS) else _check_resource_case(cid, runs, lbl)
        for r in runs:
            if r["sandbox_instance_ref"] in seen_refs:
                raise ValueError(f"duplicate sandbox_instance_ref {r['sandbox_instance_ref']!r}")
            seen_refs.add(r["sandbox_instance_ref"])
            if canonicalize(r["effective_resource_limits"]) != decl_b or r["runtime_readback"]["oci_image_digest"] != oci_digest or r["runtime_readback"]["runner_binary_digest"] != runner_digest or _utc_sec_micros(r["ended_at_utc"], "end") > executed_us:
                raise ValueError(f"{lbl}: run limits, digests, or executed_at_utc chronology mismatch")
        checked_cases.append({"case_id": cid, "outcome": "passed", "runs": runs})
    if [c["case_id"] for c in checked_cases] != list(MANDATORY_7A_NEGATIVE_CASES):
        raise ValueError("negative_security_test_report.cases: must match exact 17 lexical cases")
    return checked_cases


def _build_neg_common_payload(**kw: Any) -> dict[str, Any]:
    run_ctx = copy.deepcopy(dict(kw["migration_run_context_locator"]))
    validate_locator(run_ctx, _RUN_CONTEXT_SCHEMA)
    _strict_str(kw["build_run_id"], "build_run_id")
    executed_us = _utc_sec_micros(kw["executed_at_utc"], "executed_at_utc")
    _hex40_str(kw["source_commit_sha"], "source_commit_sha")
    for k in ("build_backend_digest", "schema_bundle_digest", "wheel_digest", "oci_image_digest", "runner_binary_digest", "test_suite_digest"):
        _sha256_str(kw[k], k)
    _exact_str(kw["test_suite_digest"], PINNED_7A_NEGATIVE_SUITE_DIGEST, "test_suite_digest")
    checked_limits = _validate_resource_limits_dict(kw["declared_resource_limits"], "declared_resource_limits")
    checked_cases = _validate_cases_list(list(kw["cases"]), declared_limits=checked_limits, oci_digest=kw["oci_image_digest"], runner_digest=kw["runner_binary_digest"], executed_us=executed_us)
    return {
        "migration_run_context_locator": run_ctx, "build_run_id": kw["build_run_id"], "executed_at_utc": kw["executed_at_utc"],
        "source_commit_sha": kw["source_commit_sha"], "build_backend_digest": kw["build_backend_digest"],
        "schema_bundle_digest": kw["schema_bundle_digest"], "wheel_digest": kw["wheel_digest"],
        "oci_image_digest": kw["oci_image_digest"], "runner_binary_digest": kw["runner_binary_digest"],
        "test_suite_digest": kw["test_suite_digest"], "declared_resource_limits": checked_limits, "cases": checked_cases,
    }


def build_negative_security_test_report_envelope(
    *, migration_run_context_locator: Mapping[str, Any], sealed_sandbox_profile_locator: Mapping[str, Any],
    wheel_build_provenance_locator: Mapping[str, Any], build_run_id: str, executed_at_utc: str,
    source_commit_sha: str, build_backend_digest: str, schema_bundle_digest: str, wheel_digest: str,
    oci_image_digest: str, runner_binary_digest: str, declared_resource_limits: Mapping[str, Any],
    cases: Sequence[Mapping[str, Any]], registry_locator: Mapping[str, Any], signer_key_id: str,
    test_suite_digest: str = PINNED_7A_NEGATIVE_SUITE_DIGEST,
) -> dict[str, Any]:
    sbx_loc, prov_loc, reg_loc = copy.deepcopy(dict(sealed_sandbox_profile_locator)), copy.deepcopy(dict(wheel_build_provenance_locator)), copy.deepcopy(dict(registry_locator))
    validate_locator(sbx_loc, SANDBOX_PROFILE_SCHEMA)
    validate_locator(prov_loc, WHEEL_BUILD_PROVENANCE_SCHEMA)
    validate_locator(reg_loc, _KEY_REGISTRY_SCHEMA)
    _key_id_str(signer_key_id, "signer_key_id")
    common = _build_neg_common_payload(
        migration_run_context_locator=migration_run_context_locator, build_run_id=build_run_id, executed_at_utc=executed_at_utc,
        source_commit_sha=source_commit_sha, build_backend_digest=build_backend_digest, schema_bundle_digest=schema_bundle_digest,
        wheel_digest=wheel_digest, oci_image_digest=oci_image_digest, runner_binary_digest=runner_binary_digest,
        declared_resource_limits=declared_resource_limits, cases=cases, test_suite_digest=test_suite_digest,
    )
    env = {"$schema": NEGATIVE_SECURITY_REPORT_SCHEMA, **common, "sealed_sandbox_profile_locator": sbx_loc, "wheel_build_provenance_locator": prov_loc, "integrity": {"key_id": signer_key_id, "key_registry_snapshot_locator": reg_loc}}
    loads_strict(canonicalize(env).decode("utf-8"))
    return env


def build_negative_security_test_report_candidate(
    *, migration_run_context_locator: Mapping[str, Any], sealed_sandbox_profile_candidate_ref: Mapping[str, Any],
    wheel_build_provenance_candidate_ref: Mapping[str, Any], build_run_id: str, executed_at_utc: str,
    source_commit_sha: str, build_backend_digest: str, schema_bundle_digest: str, wheel_digest: str,
    oci_image_digest: str, runner_binary_digest: str, declared_resource_limits: Mapping[str, Any],
    cases: Sequence[Mapping[str, Any]], test_suite_digest: str = PINNED_7A_NEGATIVE_SUITE_DIGEST,
) -> dict[str, Any]:
    sbx_ref, prov_ref = copy.deepcopy(dict(sealed_sandbox_profile_candidate_ref)), copy.deepcopy(dict(wheel_build_provenance_candidate_ref))
    verify_local_candidate_ref(sbx_ref, expected_schema=SANDBOX_PROFILE_SCHEMA)
    verify_local_candidate_ref(prov_ref, expected_schema=WHEEL_BUILD_PROVENANCE_SCHEMA)
    common = _build_neg_common_payload(
        migration_run_context_locator=migration_run_context_locator, build_run_id=build_run_id, executed_at_utc=executed_at_utc,
        source_commit_sha=source_commit_sha, build_backend_digest=build_backend_digest, schema_bundle_digest=schema_bundle_digest,
        wheel_digest=wheel_digest, oci_image_digest=oci_image_digest, runner_binary_digest=runner_binary_digest,
        declared_resource_limits=declared_resource_limits, cases=cases, test_suite_digest=test_suite_digest,
    )
    payload = {**common, "sealed_sandbox_profile_candidate_ref": sbx_ref, "wheel_build_provenance_candidate_ref": prov_ref}
    loads_strict(canonicalize(payload).decode("utf-8"))
    return wrap_local_candidate(NEGATIVE_SECURITY_REPORT_SCHEMA, payload)


def extract_provenance_payload(prov_obj: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(prov_obj, Mapping):
        raise ValueError("wheel_provenance: expected Mapping")
    d = dict(prov_obj)
    if d.get("artifact_kind") == LOCAL_CANDIDATE_KIND:
        if "$schema" in d or "integrity" in d:
            raise ValueError("wheel_provenance: candidate must not carry envelope fields")
        payload = unwrap_local_candidate(d, expected_schema=WHEEL_BUILD_PROVENANCE_SCHEMA)
    elif "$schema" in d or "integrity" in d:
        if "artifact_kind" in d:
            raise ValueError("wheel_provenance: mixed candidate/envelope fields")
        exact_fields(d, _WHEEL_PROVENANCE_16_KEYS | {"$schema", "integrity"}, "wheel_provenance")
        _exact_str(d["$schema"], WHEEL_BUILD_PROVENANCE_SCHEMA, "wheel_provenance.$schema")
        _verify_p1_integrity(d, label="wheel_provenance")
        payload = {k: copy.deepcopy(v) for k, v in d.items() if k not in {"$schema", "integrity"}}
    else:
        payload = copy.deepcopy(d)
    exact_fields(payload, _WHEEL_PROVENANCE_16_KEYS, "wheel_provenance_payload")
    validate_locator(dict(payload["migration_run_context_locator"]), _RUN_CONTEXT_SCHEMA)
    _strict_str(payload["build_run_id"], "wheel_provenance.build_run_id")
    _utc_sec_micros(payload["built_at_utc"], "wheel_provenance.built_at_utc")
    for k, exp in (("repository", DEFAULT_REPOSITORY), ("python_abi_tag", EXPECTED_PYTHON_ABI_TAG), ("build_backend", EXPECTED_BUILD_BACKEND), ("build_backend_version", EXPECTED_BUILD_BACKEND_VERSION)):
        _exact_str(payload[k], exp, f"wheel_provenance.{k}")
    for k in ("source_commit_sha", "source_tree_oid"):
        _hex40_str(payload[k], f"wheel_provenance.{k}")
    _strict_int(payload["source_date_epoch"], "wheel_provenance.source_date_epoch")
    for k in ("build_backend_digest", "pyproject_sha256", "uv_lock_sha256", "schema_bundle_digest", "wheel_digest"):
        _sha256_str(payload[k], f"wheel_provenance.{k}")
    verify_wheel_object_locator(dict(payload["wheel"]))
    _exact_str(payload["wheel"]["wheel_digest"], payload["wheel_digest"], "wheel_provenance.wheel.wheel_digest")
    loads_strict(canonicalize(payload).decode("utf-8"))
    return payload


def _extract_sandbox_payload_for_mode(
    sbx_obj: Mapping[str, Any], *, mode: str, expected_bind: Mapping[str, Any]
) -> tuple[dict[str, Any], dict[str, Any], str, int, int, int]:
    if not isinstance(sbx_obj, Mapping):
        raise ValueError("sandbox_profile: expected Mapping")
    d = dict(sbx_obj)
    if mode == "candidate":
        sbx_cand = d if d.get("artifact_kind") == LOCAL_CANDIDATE_KIND else wrap_local_candidate(SANDBOX_PROFILE_SCHEMA, copy.deepcopy(d))
        if "$schema" in sbx_cand or "integrity" in sbx_cand:
            raise ValueError("sandbox_profile: candidate mode forbids P1 envelope")
        payload = unwrap_local_candidate(sbx_cand, expected_schema=SANDBOX_PROFILE_SCHEMA)
        if canonicalize(build_local_candidate_ref(sbx_cand)) != canonicalize(dict(expected_bind)):
            raise ValueError("sandbox_profile: candidate_ref mismatch against report")
    else:
        if "artifact_kind" in d:
            raise ValueError("sandbox_profile: envelope mode forbids gov1_local_candidate")
        if "$schema" in d or "integrity" in d:
            exact_fields(d, _SANDBOX_PAYLOAD_20_KEYS | {"$schema", "integrity"}, "sandbox_profile")
            _exact_str(d["$schema"], SANDBOX_PROFILE_SCHEMA, "sandbox_profile.$schema")
            _verify_p1_integrity(d, label="sandbox_profile")
            if canonicalize(make_locator(SANDBOX_PROFILE_SCHEMA, canonicalize(d))) != canonicalize(dict(expected_bind)):
                raise ValueError("sandbox_profile: envelope locator mismatch against report")
            payload = {k: copy.deepcopy(v) for k, v in d.items() if k not in {"$schema", "integrity"}}
        else:
            payload = copy.deepcopy(d)
    exact_fields(payload, _SANDBOX_PAYLOAD_20_KEYS, "sandbox_profile_payload")
    _validate_shared_runtime_16(payload, "sandbox_profile")
    limits = _validate_resource_limits_dict(payload["resource_limits"], "sandbox_profile.resource_limits")
    validate_locator(dict(payload["migration_run_context_locator"]), _RUN_CONTEXT_SCHEMA)
    issued_us = _utc_sec_micros(payload["issued_at_utc"], "sandbox_profile.issued_at_utc")
    val_d = dict(payload["validity"]) if isinstance(payload["validity"], Mapping) else {}
    exact_fields(val_d, {"from", "until"}, "sandbox_profile.validity")
    from_us, until_us = _utc_sec_micros(val_d["from"], "validity.from"), _utc_sec_micros(val_d["until"], "validity.until")
    if not (from_us <= issued_us < until_us):
        raise ValueError("sandbox_profile.validity: require from <= issued_at_utc < until")
    return payload, limits, json_digest({k: payload[k] for k in _SPEC_17_FIELDS}), issued_us, from_us, until_us


def _extract_provenance_for_mode(
    prov_obj: Mapping[str, Any], *, mode: str, expected_bind: Mapping[str, Any], wheel_bytes: bytes
) -> tuple[dict[str, Any], str, int]:
    prov_payload = extract_provenance_payload(prov_obj)
    d = dict(prov_obj)
    if mode == "candidate":
        if "$schema" in d or "integrity" in d:
            raise ValueError("wheel_provenance: candidate mode forbids P1 envelope")
        cand = d if d.get("artifact_kind") == LOCAL_CANDIDATE_KIND else wrap_local_candidate(WHEEL_BUILD_PROVENANCE_SCHEMA, prov_payload)
        if canonicalize(build_local_candidate_ref(cand)) != canonicalize(dict(expected_bind)):
            raise ValueError("wheel_provenance: candidate_ref mismatch against report")
    else:
        if "artifact_kind" in d:
            raise ValueError("wheel_provenance: envelope mode forbids gov1_local_candidate")
        if ("$schema" in d or "integrity" in d) and canonicalize(make_locator(WHEEL_BUILD_PROVENANCE_SCHEMA, canonicalize(d))) != canonicalize(dict(expected_bind)):
            raise ValueError("wheel_provenance: envelope locator mismatch against report")
    verify_wheel_object_locator(dict(prov_payload["wheel"]), expected_wheel_bytes=wheel_bytes)
    actual_whl_digest = digest(wheel_bytes)
    _exact_str(prov_payload["wheel_digest"], actual_whl_digest, "wheel_provenance.wheel_digest")
    return prov_payload, actual_whl_digest, _utc_sec_micros(prov_payload["built_at_utc"], "built_at_utc")


def _unwrap_neg_report(artifact: Mapping[str, Any]) -> tuple[str, dict[str, Any]]:
    d = dict(artifact) if isinstance(artifact, Mapping) else {}
    if d.get("artifact_kind") == LOCAL_CANDIDATE_KIND:
        if "$schema" in d or "integrity" in d:
            raise ValueError("negative_security_test_report: candidate must not contain envelope fields")
        payload = unwrap_local_candidate(d, expected_schema=NEGATIVE_SECURITY_REPORT_SCHEMA)
        exact_fields(payload, _NEG_CANDIDATE_14_KEYS, "negative_security_candidate_payload")
        verify_local_candidate_ref(payload["sealed_sandbox_profile_candidate_ref"], expected_schema=SANDBOX_PROFILE_SCHEMA)
        verify_local_candidate_ref(payload["wheel_build_provenance_candidate_ref"], expected_schema=WHEEL_BUILD_PROVENANCE_SCHEMA)
        return "candidate", payload
    if d.get("$schema") == NEGATIVE_SECURITY_REPORT_SCHEMA and "artifact_kind" not in d:
        exact_fields(d, _NEG_ENVELOPE_16_KEYS, "negative_security_envelope")
        _verify_p1_integrity(d, label="negative_security_test_report")
        payload = {k: copy.deepcopy(v) for k, v in d.items() if k not in {"$schema", "integrity"}}
        exact_fields(payload, _NEG_ENVELOPE_PAYLOAD_14_KEYS, "negative_security_envelope_payload")
        validate_locator(payload["sealed_sandbox_profile_locator"], SANDBOX_PROFILE_SCHEMA)
        validate_locator(payload["wheel_build_provenance_locator"], WHEEL_BUILD_PROVENANCE_SCHEMA)
        return "envelope", payload
    raise ValueError("negative_security_test_report: expected P1 envelope or gov1_local_candidate")


def _verify_neg_runs_and_cross_bindings(
    payload: Mapping[str, Any], sbx_payload: Mapping[str, Any], prov_payload: Mapping[str, Any],
    *, sbx_limits: Mapping[str, Any], sbx_digest: str, actual_whl_digest: str, floor_us: int, from_us: int, until_us: int,
) -> None:
    sbx_shared_b = canonicalize({k: sbx_payload[k] for k in _SHARED_RUNTIME_16_FIELDS})
    if (
        (payload["build_run_id"], payload["wheel_digest"], payload["source_commit_sha"], payload["build_backend_digest"], payload["schema_bundle_digest"])
        != (prov_payload["build_run_id"], actual_whl_digest, prov_payload["source_commit_sha"], prov_payload["build_backend_digest"], prov_payload["schema_bundle_digest"])
        or canonicalize(payload["migration_run_context_locator"]) != canonicalize(prov_payload["migration_run_context_locator"])
        or canonicalize(payload["migration_run_context_locator"]) != canonicalize(sbx_payload["migration_run_context_locator"])
        or canonicalize(payload["declared_resource_limits"]) != canonicalize(dict(sbx_limits))
        or (payload["oci_image_digest"], payload["runner_binary_digest"]) != (sbx_payload["oci_image_digest"], sbx_payload["runner_binary_digest"])
    ):
        raise ValueError("negative_security_test_report: cross-artifact binding mismatch")
    executed_us = _utc_sec_micros(payload["executed_at_utc"], "executed_at_utc")
    if not (floor_us <= executed_us and from_us <= executed_us < until_us):
        raise ValueError("negative_security_test_report.executed_at_utc: chronology violation")
    for case in payload["cases"]:
        for sub_idx, run in enumerate(case["runs"]):
            if canonicalize({k: run["runtime_readback"][k] for k in _SHARED_RUNTIME_16_FIELDS}) != sbx_shared_b:
                raise ValueError("negative_security_test_report: runtime_readback mismatch against sandbox_profile")
            s_us, e_us = _utc_sec_micros(run["started_at_utc"], "start"), _utc_sec_micros(run["ended_at_utc"], "end")
            if not (floor_us <= s_us <= e_us <= executed_us and from_us <= s_us <= e_us < until_us):
                raise ValueError("negative_security_test_report: run chronology violation")
            if run["execution_binding_digest"] != compute_negative_run_execution_binding_digest(case_id=case["case_id"], subrun_index=sub_idx, run=run, wheel_digest=payload["wheel_digest"], test_suite_digest=payload["test_suite_digest"], sealed_sandbox_profile_digest=sbx_digest):
                raise ValueError("negative_security_test_report: run execution_binding_digest mismatch")


def verify_negative_security_test_report(
    artifact: Mapping[str, Any], *, sandbox_profile: Mapping[str, Any], wheel_provenance: Mapping[str, Any], wheel_bytes: bytes
) -> dict[str, Any]:
    if type(wheel_bytes) is not bytes or len(wheel_bytes) == 0:
        raise ValueError("verify_negative_security_test_report: wheel_bytes must be non-empty bytes")
    mode, raw_payload = _unwrap_neg_report(artifact)
    checked_common = _build_neg_common_payload(**{k: raw_payload[k] for k in _NEG_COMMON_12_KEYS})
    sbx_key = "sealed_sandbox_profile_candidate_ref" if mode == "candidate" else "sealed_sandbox_profile_locator"
    prov_key = "wheel_build_provenance_candidate_ref" if mode == "candidate" else "wheel_build_provenance_locator"
    sbx_payload, sbx_limits, sbx_digest, issued_us, from_us, until_us = _extract_sandbox_payload_for_mode(sandbox_profile, mode=mode, expected_bind=raw_payload[sbx_key])
    prov_payload, actual_whl_digest, built_us = _extract_provenance_for_mode(wheel_provenance, mode=mode, expected_bind=raw_payload[prov_key], wheel_bytes=wheel_bytes)
    _verify_neg_runs_and_cross_bindings(checked_common, sbx_payload, prov_payload, sbx_limits=sbx_limits, sbx_digest=sbx_digest, actual_whl_digest=actual_whl_digest, floor_us=max(issued_us, built_us), from_us=from_us, until_us=until_us)
    return {
        "mode": mode, "schema": NEGATIVE_SECURITY_REPORT_SCHEMA, "wheel_digest": actual_whl_digest,
        "schema_bundle_digest": checked_common["schema_bundle_digest"], "executed_at_utc": checked_common["executed_at_utc"],
        "negative_cases": list(MANDATORY_7A_NEGATIVE_CASES), "payload": copy.deepcopy(raw_payload),
    }
