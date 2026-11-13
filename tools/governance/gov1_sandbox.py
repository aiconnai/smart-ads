"""Governance primitives for the 7A sealed sandbox, mandatory seccomp, and local candidates.

Implements ADR-0001 section 3.2 (`smart_ads/sealed_sandbox_profile/v1`,
`smart_ads_7a_hermetic_linux_amd64_oci_v1`, `smart_ads_7a_resources_v1`),
mandatory allowlist seccomp verification blocking all 26 prohibited syscalls,
7A host eligibility probing, and non-authoritative local candidate wrappers
(`gov1_local_candidate`) and references (`gov1_local_candidate_ref`) that can
never be confused with P1-signed envelopes or `artifact_locator/v1` objects.
"""
from __future__ import annotations

import copy
import platform
import re
import sys
from typing import Any, Final

from tools.governance import p1
from tools.governance.jcs import canonicalize, loads_strict
from tools.governance.locator import (
    digest,
    exact_fields,
    json_digest,
    timestamp,
    validate_locator,
)

SANDBOX_PROFILE_SCHEMA: Final[str] = "smart_ads/sealed_sandbox_profile/v1"
SANDBOX_PROFILE_ID: Final[str] = "smart_ads_7a_hermetic_linux_amd64_oci_v1"
SANDBOX_RESOURCES_VERSION: Final[str] = "smart_ads_7a_resources_v1"
LOCAL_CANDIDATE_KIND: Final[str] = "gov1_local_candidate"
LOCAL_CANDIDATE_REF_KIND: Final[str] = "gov1_local_candidate_ref"

_RUN_CONTEXT_SCHEMA: Final[str] = "smart_ads/migration_run_context/v1"
_KEY_REGISTRY_SCHEMA: Final[str] = "smart_ads/key_authorization_registry/v1"

MANDATORY_DENIED_SYSCALLS: Final[tuple[str, ...]] = (
    "accept",
    "accept4",
    "bind",
    "bpf",
    "clone",
    "clone3",
    "connect",
    "execve",
    "execveat",
    "fork",
    "keyctl",
    "listen",
    "mount",
    "open_by_handle_at",
    "pivot_root",
    "ptrace",
    "recvfrom",
    "recvmsg",
    "sendmsg",
    "sendto",
    "setns",
    "socket",
    "socketpair",
    "umount2",
    "unshare",
    "vfork",
)
_MANDATORY_DENIED_SYSCALLS_SET: Final[frozenset[str]] = frozenset(
    MANDATORY_DENIED_SYSCALLS
)
KERNEL_BYPASS_DENIED_SYSCALLS: Final[tuple[str, ...]] = (
    "io_uring_enter",
    "io_uring_register",
    "io_uring_setup",
)
_ALL_DENIED_SYSCALLS_SET: Final[frozenset[str]] = (
    _MANDATORY_DENIED_SYSCALLS_SET | frozenset(KERNEL_BYPASS_DENIED_SYSCALLS)
)
MAX_JCS_SAFE_INT: Final[int] = (1 << 53) - 1

_DEFAULT_7A_ALLOWED_SYSCALLS: Final[tuple[str, ...]] = (
    "access",
    "arch_prctl",
    "brk",
    "clock_gettime",
    "close",
    "dup",
    "dup2",
    "epoll_create1",
    "epoll_ctl",
    "epoll_wait",
    "exit",
    "exit_group",
    "fcntl",
    "fstat",
    "fsync",
    "ftruncate",
    "futex",
    "getcwd",
    "getdents64",
    "getegid",
    "geteuid",
    "getgid",
    "getpid",
    "getppid",
    "getrandom",
    "getrlimit",
    "gettid",
    "getuid",
    "ioctl",
    "lseek",
    "lstat",
    "madvise",
    "mkdir",
    "mmap",
    "mprotect",
    "munmap",
    "newfstatat",
    "openat",
    "pipe2",
    "poll",
    "pread64",
    "prlimit64",
    "pwrite64",
    "read",
    "readlink",
    "readlinkat",
    "rename",
    "renameat2",
    "rmdir",
    "rseq",
    "rt_sigaction",
    "rt_sigprocmask",
    "rt_sigreturn",
    "sched_getaffinity",
    "set_robust_list",
    "set_tid_address",
    "sigaltstack",
    "stat",
    "statx",
    "umask",
    "uname",
    "unlink",
    "unlinkat",
    "write",
    "writev",
)

_DENYING_SECCOMP_ACTIONS: Final[frozenset[str]] = frozenset(
    {
        "SCMP_ACT_ERRNO",
        "SCMP_ACT_KILL",
        "SCMP_ACT_KILL_PROCESS",
        "SCMP_ACT_KILL_THREAD",
    }
)
_ALLOWED_7A_SECCOMP_ACTIONS: Final[frozenset[str]] = (
    frozenset({"SCMP_ACT_ALLOW"}) | _DENYING_SECCOMP_ACTIONS
)
_VALID_SECCOMP_OPS: Final[frozenset[str]] = frozenset(
    {
        "SCMP_CMP_NE",
        "SCMP_CMP_LT",
        "SCMP_CMP_LE",
        "SCMP_CMP_EQ",
        "SCMP_CMP_GE",
        "SCMP_CMP_GT",
        "SCMP_CMP_MASKED_EQ",
    }
)

_EXACT_ENVIRONMENT: Final[dict[str, str]] = {
    "HOME": "/nonexistent",
    "LANG": "C.UTF-8",
    "PATH": "/usr/bin:/bin",
    "PYTHONNOUSERSITE": "1",
    "PYTHONSAFEPATH": "1",
    "TMPDIR": "/tmp",
    "TZ": "UTC",
}
_EXACT_NAMESPACES: Final[tuple[str, ...]] = (
    "mount",
    "network",
    "pid",
    "ipc",
    "uts",
    "user",
)
_EXACT_READ_ONLY_MOUNTS: Final[tuple[str, ...]] = ("/app", "/fixtures")
_EXACT_FRESH_TMPFS_MOUNTS: Final[tuple[str, ...]] = ("/tmp",)
_EXACT_MASKED_EMPTY_MOUNTS: Final[tuple[str, ...]] = (
    "/proc",
    "/sys",
    "/dev",
    "/home",
    "/run",
    "/var/run",
)
_EXACT_TMP_MOUNT_FLAGS: Final[tuple[str, ...]] = ("nodev", "noexec", "nosuid")

_SPEC_17_FIELDS: Final[set[str]] = {
    "profile_id",
    "runtime_kind",
    "platform",
    "rootfs_read_only",
    "oci_image_digest",
    "runner_binary_digest",
    "exact_environment",
    "namespaces",
    "read_only_mounts",
    "fresh_tmpfs_mounts",
    "masked_empty_mounts",
    "host_bind_mounts_forbidden",
    "all_capabilities_dropped",
    "no_new_privs",
    "inherited_fds_above_2_closed",
    "seccomp_profile_digest",
    "resource_limits",
}
_SPEC_18_FIELDS: Final[set[str]] = {"$schema"} | _SPEC_17_FIELDS
_PAYLOAD_20_FIELDS: Final[set[str]] = _SPEC_17_FIELDS | {
    "migration_run_context_locator",
    "issued_at_utc",
    "validity",
}
_ENVELOPE_22_FIELDS: Final[set[str]] = {"$schema", "integrity"} | _PAYLOAD_20_FIELDS

_RESOURCE_LIMITS_FIELDS: Final[set[str]] = {
    "profile_version",
    "cgroup_version",
    "cpu_max",
    "cpu_time_limit_seconds",
    "memory_max_bytes",
    "memory_swap_max_bytes",
    "pids_max",
    "tmpfs_limits",
    "rlimit_fsize_bytes",
    "stdout_max_bytes",
    "stderr_max_bytes",
    "wall_clock_timeout_seconds",
    "termination_grace_ms",
}

_LOCAL_CANDIDATE_FIELDS: Final[set[str]] = {
    "artifact_kind",
    "target_schema",
    "signable",
    "authority",
    "payload",
    "payload_digest",
}
_LOCAL_CANDIDATE_REF_FIELDS: Final[set[str]] = {
    "ref_kind",
    "target_schema",
    "candidate_digest",
    "payload_digest",
    "authority",
}
_UNSIGNED_INTEGRITY_FIELDS: Final[set[str]] = {
    "key_id",
    "key_registry_snapshot_locator",
}
_SIGNED_INTEGRITY_FIELDS: Final[set[str]] = _UNSIGNED_INTEGRITY_FIELDS | {
    "content_digest",
    "signature_base64",
}

_SHA256_PREFIXED_RE: Final[re.Pattern[str]] = re.compile(r"\Asha256:[0-9a-f]{64}\Z")
_SCHEMA_ID_RE: Final[re.Pattern[str]] = re.compile(
    r"\Asmart_ads/[a-z0-9_]+/v[1-9][0-9]*\Z"
)
_SYSCALL_NAME_RE: Final[re.Pattern[str]] = re.compile(r"\A[a-z0-9_]+\Z")


def _require_sha256_digest(value: object, label: str) -> str:
    if type(value) is not str or _SHA256_PREFIXED_RE.fullmatch(value) is None:
        raise ValueError(f"{label}: expected 'sha256:<64_lowercase_hex>'")
    return value


def _require_schema_id(value: object, label: str) -> str:
    if type(value) is not str or _SCHEMA_ID_RE.fullmatch(value) is None:
        raise ValueError(f"{label}: expected canonical 'smart_ads/<name>/v<N>' schema")
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


def _require_exact_int(value: object, expected: int, label: str) -> int:
    if type(value) is not int or value != expected:
        raise ValueError(f"{label}: expected exact integer {expected!r}")
    return value


def _require_exact_str_list(
    value: object, expected: tuple[str, ...], label: str
) -> None:
    if (
        type(value) is not list
        or len(value) != len(expected)
        or any(type(item) is not str for item in value)
        or tuple(value) != expected
    ):
        raise ValueError(f"{label}: expected exact list {list(expected)!r}")


# ---------------------------------------------------------------------------
# Local Candidate & Non-Authoritative Candidate References
# ---------------------------------------------------------------------------


def wrap_local_candidate(
    target_schema: str, payload: dict[str, Any]
) -> dict[str, Any]:
    """Wrap an unsigned, non-authoritative payload in `gov1_local_candidate`."""
    _require_schema_id(target_schema, "wrap_local_candidate.target_schema")
    if not isinstance(payload, dict):
        raise ValueError("wrap_local_candidate: payload must be a JSON object")
    if "$schema" in payload or "integrity" in payload:
        raise ValueError(
            "wrap_local_candidate: local candidate payload must not contain '$schema' or 'integrity'"
        )
    payload_copy = copy.deepcopy(payload)
    payload_digest = json_digest(payload_copy)
    return {
        "artifact_kind": LOCAL_CANDIDATE_KIND,
        "target_schema": target_schema,
        "signable": False,
        "authority": "none",
        "payload": payload_copy,
        "payload_digest": payload_digest,
    }


def unwrap_local_candidate(
    candidate: dict[str, Any], *, expected_schema: str
) -> dict[str, Any]:
    """Validate a `gov1_local_candidate` wrapper and return a deep-copied payload."""
    _require_schema_id(expected_schema, "unwrap_local_candidate.expected_schema")
    exact_fields(candidate, _LOCAL_CANDIDATE_FIELDS, "local_candidate")
    _require_exact_str(
        candidate["artifact_kind"], LOCAL_CANDIDATE_KIND, "local_candidate.artifact_kind"
    )
    _require_exact_str(
        candidate["target_schema"], expected_schema, "local_candidate.target_schema"
    )
    _require_exact_bool(candidate["signable"], False, "local_candidate.signable")
    _require_exact_str(candidate["authority"], "none", "local_candidate.authority")

    payload = candidate["payload"]
    if not isinstance(payload, dict) or "$schema" in payload or "integrity" in payload:
        raise ValueError(
            "local_candidate.payload: must be a JSON object without '$schema' or 'integrity'"
        )
    expected_digest = _require_sha256_digest(
        candidate["payload_digest"], "local_candidate.payload_digest"
    )
    actual_digest = json_digest(payload)
    if actual_digest != expected_digest:
        raise ValueError(
            "local_candidate.payload_digest: digest mismatch against canonical payload"
        )
    return copy.deepcopy(payload)


def build_local_candidate_ref(candidate: dict[str, Any]) -> dict[str, Any]:
    """Build a `gov1_local_candidate_ref` from a validated `gov1_local_candidate`."""
    exact_fields(candidate, _LOCAL_CANDIDATE_FIELDS, "local_candidate")
    target_schema = _require_schema_id(
        candidate["target_schema"], "local_candidate.target_schema"
    )
    unwrap_local_candidate(candidate, expected_schema=target_schema)
    cand_digest = digest(canonicalize(candidate))
    return {
        "ref_kind": LOCAL_CANDIDATE_REF_KIND,
        "target_schema": target_schema,
        "candidate_digest": cand_digest,
        "payload_digest": candidate["payload_digest"],
        "authority": "none",
    }


def verify_local_candidate_ref(
    ref: dict[str, Any],
    *,
    expected_schema: str,
    expected_candidate: dict[str, Any] | None = None,
) -> None:
    """Validate a `gov1_local_candidate_ref` (never interchangeable with `artifact_locator/v1`)."""
    _require_schema_id(expected_schema, "verify_local_candidate_ref.expected_schema")
    exact_fields(ref, _LOCAL_CANDIDATE_REF_FIELDS, "local_candidate_ref")
    _require_exact_str(
        ref["ref_kind"], LOCAL_CANDIDATE_REF_KIND, "local_candidate_ref.ref_kind"
    )
    _require_exact_str(
        ref["target_schema"], expected_schema, "local_candidate_ref.target_schema"
    )
    _require_exact_str(ref["authority"], "none", "local_candidate_ref.authority")
    _require_sha256_digest(
        ref["candidate_digest"], "local_candidate_ref.candidate_digest"
    )
    _require_sha256_digest(ref["payload_digest"], "local_candidate_ref.payload_digest")

    if expected_candidate is not None:
        unwrap_local_candidate(expected_candidate, expected_schema=expected_schema)
        if ref["candidate_digest"] != json_digest(expected_candidate):
            raise ValueError(
                "local_candidate_ref.candidate_digest: mismatch against expected_candidate"
            )
        if ref["payload_digest"] != expected_candidate["payload_digest"]:
            raise ValueError(
                "local_candidate_ref.payload_digest: mismatch against expected_candidate"
            )


# ---------------------------------------------------------------------------
# 7A Allowlist Seccomp Profile Builder & Verifier
# ---------------------------------------------------------------------------


def build_default_7a_seccomp_profile(
    *, allowed_syscalls: list[str] | tuple[str, ...] = _DEFAULT_7A_ALLOWED_SYSCALLS
) -> dict[str, Any]:
    """Build a canonical OCI x86_64 allowlist seccomp profile for the 7A sandbox."""
    if not isinstance(allowed_syscalls, (list, tuple)) or len(allowed_syscalls) == 0:
        raise ValueError(
            "build_default_7a_seccomp_profile: allowed_syscalls must be a non-empty list or tuple"
        )
    for name in allowed_syscalls:
        _require_strict_str(name, "allowed_syscalls")
        if _SYSCALL_NAME_RE.fullmatch(name) is None:
            raise ValueError(
                f"build_default_7a_seccomp_profile: invalid syscall identifier {name!r}"
            )
    sorted_names = sorted(set(allowed_syscalls), key=lambda s: s.encode("utf-8"))
    profile: dict[str, Any] = {
        "defaultAction": "SCMP_ACT_ERRNO",
        "architectures": ["SCMP_ARCH_X86_64"],
        "syscalls": [
            {
                "names": sorted_names,
                "action": "SCMP_ACT_ALLOW",
            }
        ],
    }
    verify_seccomp_profile(profile)
    return profile


def verify_seccomp_profile(seccomp_profile: dict[str, Any]) -> str:
    """Verify 7A allowlist seccomp invariants and return JCS `sha256:<hex>` digest."""
    exact_fields(
        seccomp_profile,
        {"defaultAction", "architectures", "syscalls"},
        "seccomp_profile",
    )
    _require_exact_str(
        seccomp_profile["defaultAction"],
        "SCMP_ACT_ERRNO",
        "seccomp_profile.defaultAction",
    )
    _require_exact_str_list(
        seccomp_profile["architectures"],
        ("SCMP_ARCH_X86_64",),
        "seccomp_profile.architectures",
    )

    syscalls = seccomp_profile["syscalls"]
    if type(syscalls) is not list:
        raise ValueError("seccomp_profile.syscalls: expected list")

    for idx, rule in enumerate(syscalls):
        if not isinstance(rule, dict):
            raise ValueError(f"seccomp_profile.syscalls[{idx}]: expected JSON object")
        rule_keys = set(rule.keys())
        if rule_keys not in ({"names", "action"}, {"names", "action", "args"}):
            raise ValueError(
                f"seccomp_profile.syscalls[{idx}]: expected keys {{'names', 'action'}} "
                "with optional 'args'"
            )
        names = rule["names"]
        if type(names) is not list or len(names) == 0:
            raise ValueError(
                f"seccomp_profile.syscalls[{idx}].names: expected non-empty list"
            )
        for name in names:
            _require_strict_str(name, f"seccomp_profile.syscalls[{idx}].names")
            if _SYSCALL_NAME_RE.fullmatch(name) is None:
                raise ValueError(
                    f"seccomp_profile.syscalls[{idx}].names: invalid syscall {name!r}"
                )

        action = rule["action"]
        if type(action) is not str or action not in _ALLOWED_7A_SECCOMP_ACTIONS:
            raise ValueError(
                f"seccomp_profile.syscalls[{idx}].action: invalid or non-hermetic seccomp action {action!r}"
            )

        if "args" in rule:
            args_list = rule["args"]
            if type(args_list) is not list:
                raise ValueError(
                    f"seccomp_profile.syscalls[{idx}].args: expected list"
                )
            for arg_idx, arg_spec in enumerate(args_list):
                if not isinstance(arg_spec, dict):
                    raise ValueError(
                        f"seccomp_profile.syscalls[{idx}].args[{arg_idx}]: expected JSON object"
                    )
                arg_keys = set(arg_spec.keys())
                if arg_keys not in (
                    {"index", "value", "op"},
                    {"index", "value", "op", "valueTwo"},
                ):
                    raise ValueError(
                        f"seccomp_profile.syscalls[{idx}].args[{arg_idx}]: expected keys "
                        "{'index', 'value', 'op'} with optional 'valueTwo'"
                    )
                arg_index = arg_spec["index"]
                if type(arg_index) is not int or not (0 <= arg_index <= 5):
                    raise ValueError(
                        f"seccomp_profile.syscalls[{idx}].args[{arg_idx}].index: "
                        "expected strict int in x86_64 register range 0..5"
                    )
                arg_val = arg_spec["value"]
                if type(arg_val) is not int or not (0 <= arg_val <= MAX_JCS_SAFE_INT):
                    raise ValueError(
                        f"seccomp_profile.syscalls[{idx}].args[{arg_idx}].value: "
                        f"expected strict int in [0, {MAX_JCS_SAFE_INT}]"
                    )
                if "valueTwo" in arg_spec:
                    arg_val2 = arg_spec["valueTwo"]
                    if type(arg_val2) is not int or not (
                        0 <= arg_val2 <= MAX_JCS_SAFE_INT
                    ):
                        raise ValueError(
                            f"seccomp_profile.syscalls[{idx}].args[{arg_idx}].valueTwo: "
                            f"expected strict int in [0, {MAX_JCS_SAFE_INT}]"
                        )
                arg_op = arg_spec["op"]
                if type(arg_op) is not str or arg_op not in _VALID_SECCOMP_OPS:
                    raise ValueError(
                        f"seccomp_profile.syscalls[{idx}].args[{arg_idx}].op: "
                        f"invalid seccomp comparator {arg_op!r}"
                    )

        if action not in _DENYING_SECCOMP_ACTIONS:
            forbidden = sorted(set(names) & _ALL_DENIED_SYSCALLS_SET)
            if forbidden:
                raise ValueError(
                    f"seccomp_profile.syscalls[{idx}]: action {action!r} permits "
                    f"denied syscalls {forbidden}"
                )

    canonical_bytes = canonicalize(seccomp_profile)
    loads_strict(canonical_bytes.decode("utf-8"))
    return digest(canonical_bytes)


# ---------------------------------------------------------------------------
# Sealed Sandbox Profile Spec, P1 Envelope, Candidate & Verifier
# ---------------------------------------------------------------------------


def _default_spec_17_fields(
    *,
    oci_image_digest: str,
    runner_binary_digest: str,
    seccomp_profile_digest: str,
) -> dict[str, Any]:
    return {
        "profile_id": SANDBOX_PROFILE_ID,
        "runtime_kind": "oci",
        "platform": "linux/amd64",
        "rootfs_read_only": True,
        "oci_image_digest": oci_image_digest,
        "runner_binary_digest": runner_binary_digest,
        "exact_environment": copy.deepcopy(_EXACT_ENVIRONMENT),
        "namespaces": list(_EXACT_NAMESPACES),
        "read_only_mounts": list(_EXACT_READ_ONLY_MOUNTS),
        "fresh_tmpfs_mounts": list(_EXACT_FRESH_TMPFS_MOUNTS),
        "masked_empty_mounts": list(_EXACT_MASKED_EMPTY_MOUNTS),
        "host_bind_mounts_forbidden": True,
        "all_capabilities_dropped": True,
        "no_new_privs": True,
        "inherited_fds_above_2_closed": True,
        "seccomp_profile_digest": seccomp_profile_digest,
        "resource_limits": {
            "profile_version": SANDBOX_RESOURCES_VERSION,
            "cgroup_version": 2,
            "cpu_max": {"quota_us": 100000, "period_us": 100000},
            "cpu_time_limit_seconds": 120,
            "memory_max_bytes": 1073741824,
            "memory_swap_max_bytes": 0,
            "pids_max": 32,
            "tmpfs_limits": {
                "/tmp": {
                    "size_bytes": 268435456,
                    "inodes_max": 4096,
                    "mount_flags": list(_EXACT_TMP_MOUNT_FLAGS),
                }
            },
            "rlimit_fsize_bytes": 67108864,
            "stdout_max_bytes": 8388608,
            "stderr_max_bytes": 8388608,
            "wall_clock_timeout_seconds": 300,
            "termination_grace_ms": 1000,
        },
    }


def verify_sandbox_profile_spec(
    spec: dict[str, Any], *, seccomp_profile: dict[str, Any] | None = None
) -> None:
    """Verify the exact 18-field `ADR-0001 §3.2` sealed sandbox profile specification."""
    exact_fields(spec, _SPEC_18_FIELDS, "sealed_sandbox_profile")
    _require_exact_str(spec["$schema"], SANDBOX_PROFILE_SCHEMA, "spec.$schema")
    _require_exact_str(spec["profile_id"], SANDBOX_PROFILE_ID, "spec.profile_id")
    _require_exact_str(spec["runtime_kind"], "oci", "spec.runtime_kind")
    _require_exact_str(spec["platform"], "linux/amd64", "spec.platform")
    _require_exact_bool(spec["rootfs_read_only"], True, "spec.rootfs_read_only")
    _require_sha256_digest(spec["oci_image_digest"], "spec.oci_image_digest")
    _require_sha256_digest(spec["runner_binary_digest"], "spec.runner_binary_digest")

    env = spec["exact_environment"]
    exact_fields(env, set(_EXACT_ENVIRONMENT.keys()), "spec.exact_environment")
    for env_key, expected_val in _EXACT_ENVIRONMENT.items():
        _require_exact_str(
            env[env_key], expected_val, f"spec.exact_environment.{env_key}"
        )

    _require_exact_str_list(spec["namespaces"], _EXACT_NAMESPACES, "spec.namespaces")
    _require_exact_str_list(
        spec["read_only_mounts"], _EXACT_READ_ONLY_MOUNTS, "spec.read_only_mounts"
    )
    _require_exact_str_list(
        spec["fresh_tmpfs_mounts"],
        _EXACT_FRESH_TMPFS_MOUNTS,
        "spec.fresh_tmpfs_mounts",
    )
    _require_exact_str_list(
        spec["masked_empty_mounts"],
        _EXACT_MASKED_EMPTY_MOUNTS,
        "spec.masked_empty_mounts",
    )

    _require_exact_bool(
        spec["host_bind_mounts_forbidden"], True, "spec.host_bind_mounts_forbidden"
    )
    _require_exact_bool(
        spec["all_capabilities_dropped"], True, "spec.all_capabilities_dropped"
    )
    _require_exact_bool(spec["no_new_privs"], True, "spec.no_new_privs")
    _require_exact_bool(
        spec["inherited_fds_above_2_closed"], True, "spec.inherited_fds_above_2_closed"
    )
    _require_sha256_digest(
        spec["seccomp_profile_digest"], "spec.seccomp_profile_digest"
    )

    rl = spec["resource_limits"]
    exact_fields(rl, _RESOURCE_LIMITS_FIELDS, "spec.resource_limits")
    _require_exact_str(
        rl["profile_version"],
        SANDBOX_RESOURCES_VERSION,
        "spec.resource_limits.profile_version",
    )
    _require_exact_int(rl["cgroup_version"], 2, "spec.resource_limits.cgroup_version")

    cpu_max = rl["cpu_max"]
    exact_fields(cpu_max, {"quota_us", "period_us"}, "spec.resource_limits.cpu_max")
    _require_exact_int(
        cpu_max["quota_us"], 100000, "spec.resource_limits.cpu_max.quota_us"
    )
    _require_exact_int(
        cpu_max["period_us"], 100000, "spec.resource_limits.cpu_max.period_us"
    )

    _require_exact_int(
        rl["cpu_time_limit_seconds"], 120, "spec.resource_limits.cpu_time_limit_seconds"
    )
    _require_exact_int(
        rl["memory_max_bytes"], 1073741824, "spec.resource_limits.memory_max_bytes"
    )
    _require_exact_int(
        rl["memory_swap_max_bytes"], 0, "spec.resource_limits.memory_swap_max_bytes"
    )
    _require_exact_int(rl["pids_max"], 32, "spec.resource_limits.pids_max")

    tmpfs_limits = rl["tmpfs_limits"]
    exact_fields(tmpfs_limits, {"/tmp"}, "spec.resource_limits.tmpfs_limits")
    tmp_spec = tmpfs_limits["/tmp"]
    exact_fields(
        tmp_spec,
        {"size_bytes", "inodes_max", "mount_flags"},
        "spec.resource_limits.tmpfs_limits./tmp",
    )
    _require_exact_int(
        tmp_spec["size_bytes"],
        268435456,
        "spec.resource_limits.tmpfs_limits./tmp.size_bytes",
    )
    _require_exact_int(
        tmp_spec["inodes_max"],
        4096,
        "spec.resource_limits.tmpfs_limits./tmp.inodes_max",
    )
    _require_exact_str_list(
        tmp_spec["mount_flags"],
        _EXACT_TMP_MOUNT_FLAGS,
        "spec.resource_limits.tmpfs_limits./tmp.mount_flags",
    )

    _require_exact_int(
        rl["rlimit_fsize_bytes"], 67108864, "spec.resource_limits.rlimit_fsize_bytes"
    )
    _require_exact_int(
        rl["stdout_max_bytes"], 8388608, "spec.resource_limits.stdout_max_bytes"
    )
    _require_exact_int(
        rl["stderr_max_bytes"], 8388608, "spec.resource_limits.stderr_max_bytes"
    )
    _require_exact_int(
        rl["wall_clock_timeout_seconds"],
        300,
        "spec.resource_limits.wall_clock_timeout_seconds",
    )
    _require_exact_int(
        rl["termination_grace_ms"], 1000, "spec.resource_limits.termination_grace_ms"
    )

    canonical_bytes = canonicalize(spec)
    loads_strict(canonical_bytes.decode("utf-8"))

    if seccomp_profile is not None:
        computed_digest = verify_seccomp_profile(seccomp_profile)
        if computed_digest != spec["seccomp_profile_digest"]:
            raise ValueError(
                "spec.seccomp_profile_digest: does not match canonical seccomp_profile digest"
            )


def _validate_issuance_and_validity(
    *, issued_at_utc: object, validity_obj: object
) -> None:
    issued_dt = timestamp(issued_at_utc)
    exact_fields(validity_obj, {"from", "until"}, "validity")
    if not isinstance(validity_obj, dict):
        raise ValueError("validity: expected JSON object")
    from_dt = timestamp(validity_obj["from"])
    until_dt = timestamp(validity_obj["until"])
    if not (from_dt <= issued_dt < until_dt):
        raise ValueError(
            "validity: require validity.from <= issued_at_utc < validity.until"
        )


def _build_sandbox_payload(
    *,
    migration_run_context_locator: dict[str, Any],
    oci_image_digest: str,
    runner_binary_digest: str,
    seccomp_profile: dict[str, Any],
    issued_at_utc: str,
    valid_from_utc: str,
    valid_until_utc: str,
) -> dict[str, Any]:
    validate_locator(migration_run_context_locator, _RUN_CONTEXT_SCHEMA)
    _require_sha256_digest(oci_image_digest, "oci_image_digest")
    _require_sha256_digest(runner_binary_digest, "runner_binary_digest")
    seccomp_digest = verify_seccomp_profile(seccomp_profile)
    validity_obj = {"from": valid_from_utc, "until": valid_until_utc}
    _validate_issuance_and_validity(
        issued_at_utc=issued_at_utc, validity_obj=validity_obj
    )

    spec_17 = _default_spec_17_fields(
        oci_image_digest=oci_image_digest,
        runner_binary_digest=runner_binary_digest,
        seccomp_profile_digest=seccomp_digest,
    )
    verify_sandbox_profile_spec(
        {"$schema": SANDBOX_PROFILE_SCHEMA, **spec_17},
        seccomp_profile=seccomp_profile,
    )
    return {
        **spec_17,
        "migration_run_context_locator": copy.deepcopy(migration_run_context_locator),
        "issued_at_utc": issued_at_utc,
        "validity": validity_obj,
    }


def build_sealed_sandbox_profile_envelope(
    *,
    migration_run_context_locator: dict[str, Any],
    oci_image_digest: str,
    runner_binary_digest: str,
    seccomp_profile: dict[str, Any],
    issued_at_utc: str,
    valid_from_utc: str,
    valid_until_utc: str,
    registry_locator: dict[str, Any],
    signer_key_id: str,
) -> dict[str, Any]:
    """Build an unsigned P1 `smart_ads/sealed_sandbox_profile/v1` envelope."""
    payload = _build_sandbox_payload(
        migration_run_context_locator=migration_run_context_locator,
        oci_image_digest=oci_image_digest,
        runner_binary_digest=runner_binary_digest,
        seccomp_profile=seccomp_profile,
        issued_at_utc=issued_at_utc,
        valid_from_utc=valid_from_utc,
        valid_until_utc=valid_until_utc,
    )
    validate_locator(registry_locator, _KEY_REGISTRY_SCHEMA)
    _require_strict_str(signer_key_id, "signer_key_id")
    return {
        "$schema": SANDBOX_PROFILE_SCHEMA,
        **payload,
        "integrity": {
            "key_id": signer_key_id,
            "key_registry_snapshot_locator": copy.deepcopy(registry_locator),
        },
    }


def build_sealed_sandbox_profile_candidate(
    *,
    migration_run_context_locator: dict[str, Any],
    oci_image_digest: str,
    runner_binary_digest: str,
    seccomp_profile: dict[str, Any],
    issued_at_utc: str,
    valid_from_utc: str,
    valid_until_utc: str,
) -> dict[str, Any]:
    """Build a non-signable `gov1_local_candidate` for `sealed_sandbox_profile/v1`."""
    payload = _build_sandbox_payload(
        migration_run_context_locator=migration_run_context_locator,
        oci_image_digest=oci_image_digest,
        runner_binary_digest=runner_binary_digest,
        seccomp_profile=seccomp_profile,
        issued_at_utc=issued_at_utc,
        valid_from_utc=valid_from_utc,
        valid_until_utc=valid_until_utc,
    )
    return wrap_local_candidate(SANDBOX_PROFILE_SCHEMA, payload)


def _verify_envelope_integrity(envelope: dict[str, Any]) -> None:
    integrity = envelope.get("integrity")
    if not isinstance(integrity, dict):
        raise ValueError("sealed_sandbox_profile.integrity: expected JSON object")
    keys = set(integrity.keys())
    if keys not in (_UNSIGNED_INTEGRITY_FIELDS, _SIGNED_INTEGRITY_FIELDS):
        raise ValueError(
            "sealed_sandbox_profile.integrity: expected unsigned or signed P1 integrity fields"
        )
    _require_strict_str(integrity["key_id"], "sealed_sandbox_profile.integrity.key_id")
    validate_locator(
        integrity["key_registry_snapshot_locator"], _KEY_REGISTRY_SCHEMA
    )
    if keys == _SIGNED_INTEGRITY_FIELDS:
        declared_digest = _require_sha256_digest(
            integrity["content_digest"],
            "sealed_sandbox_profile.integrity.content_digest",
        )
        expected_digest = p1.content_digest(envelope)
        if declared_digest != expected_digest:
            raise ValueError(
                "sealed_sandbox_profile.integrity.content_digest: mismatch against P1 preimage"
            )
        sig_b64 = integrity["signature_base64"]
        if type(sig_b64) is not str:
            raise ValueError(
                "sealed_sandbox_profile.integrity.signature_base64: expected string"
            )
        sig_bytes = p1._strict_base64_decode(sig_b64)
        if len(sig_bytes) != 64:
            raise ValueError(
                "sealed_sandbox_profile.integrity.signature_base64: expected 64-byte Ed25519 signature"
            )


def verify_sealed_sandbox_profile(
    artifact: dict[str, Any], *, seccomp_profile: dict[str, Any]
) -> dict[str, Any]:
    """Materially verify a `sealed_sandbox_profile/v1` P1 envelope or local candidate."""
    if not isinstance(artifact, dict):
        raise ValueError("verify_sealed_sandbox_profile: artifact must be a JSON object")
    computed_seccomp_digest = verify_seccomp_profile(seccomp_profile)

    if artifact.get("artifact_kind") == LOCAL_CANDIDATE_KIND:
        if "$schema" in artifact or "integrity" in artifact:
            raise ValueError(
                "verify_sealed_sandbox_profile: local candidate must not mix envelope fields"
            )
        payload = unwrap_local_candidate(
            artifact, expected_schema=SANDBOX_PROFILE_SCHEMA
        )
        mode = "candidate"
    elif (
        artifact.get("$schema") == SANDBOX_PROFILE_SCHEMA
        and "artifact_kind" not in artifact
    ):
        exact_fields(artifact, _ENVELOPE_22_FIELDS, "sealed_sandbox_profile_envelope")
        _verify_envelope_integrity(artifact)
        payload = {
            k: copy.deepcopy(v)
            for k, v in artifact.items()
            if k not in {"$schema", "integrity"}
        }
        mode = "envelope"
    else:
        raise ValueError(
            "verify_sealed_sandbox_profile: expected sealed_sandbox_profile/v1 envelope "
            "or gov1_local_candidate"
        )

    exact_fields(payload, _PAYLOAD_20_FIELDS, "sealed_sandbox_profile_payload")
    spec_18 = {
        "$schema": SANDBOX_PROFILE_SCHEMA,
        **{k: payload[k] for k in _SPEC_17_FIELDS},
    }
    verify_sandbox_profile_spec(spec_18, seccomp_profile=seccomp_profile)
    validate_locator(payload["migration_run_context_locator"], _RUN_CONTEXT_SCHEMA)
    _validate_issuance_and_validity(
        issued_at_utc=payload["issued_at_utc"],
        validity_obj=payload["validity"],
    )

    return {
        "mode": mode,
        "schema": SANDBOX_PROFILE_SCHEMA,
        "profile_id": SANDBOX_PROFILE_ID,
        "migration_run_context_locator": copy.deepcopy(
            payload["migration_run_context_locator"]
        ),
        "issued_at_utc": payload["issued_at_utc"],
        "validity": copy.deepcopy(payload["validity"]),
        "oci_image_digest": payload["oci_image_digest"],
        "runner_binary_digest": payload["runner_binary_digest"],
        "seccomp_profile_digest": computed_seccomp_digest,
        "payload": copy.deepcopy(payload),
    }


# ---------------------------------------------------------------------------
# 7A Host Eligibility Probe
# ---------------------------------------------------------------------------


def probe_7a_host_eligibility(
    *,
    sys_platform: str | None = None,
    machine: str | None = None,
    in_sealed_oci_supervisor: bool = False,
    cgroup_v2_available: bool = False,
) -> dict[str, Any]:
    """Probe whether the host environment satisfies all 7A hermetic OCI prerequisites."""
    if sys_platform is not None and type(sys_platform) is not str:
        raise ValueError("probe_7a_host_eligibility: sys_platform must be str or None")
    if machine is not None and type(machine) is not str:
        raise ValueError("probe_7a_host_eligibility: machine must be str or None")
    if type(in_sealed_oci_supervisor) is not bool:
        raise ValueError(
            "probe_7a_host_eligibility: in_sealed_oci_supervisor must be bool"
        )
    if type(cgroup_v2_available) is not bool:
        raise ValueError("probe_7a_host_eligibility: cgroup_v2_available must be bool")

    eff_sys_platform = sys.platform if sys_platform is None else sys_platform
    eff_machine = platform.machine() if machine is None else machine

    reasons: list[str] = []
    if eff_sys_platform != "linux":
        reasons.append("unsupported_sys_platform")
    if eff_machine.lower() not in {"x86_64", "amd64"}:
        reasons.append("unsupported_machine")
    if not in_sealed_oci_supervisor:
        reasons.append("not_in_sealed_oci_supervisor")
    if not cgroup_v2_available:
        reasons.append("cgroup_v2_unavailable")

    return {
        "status": "ELIGIBLE" if not reasons else "BLOCKED",
        "eligible": len(reasons) == 0,
        "profile_id": SANDBOX_PROFILE_ID,
        "sys_platform": eff_sys_platform,
        "machine": eff_machine,
        "in_sealed_oci_supervisor": in_sealed_oci_supervisor,
        "cgroup_v2_available": cgroup_v2_available,
        "reasons": reasons,
    }
