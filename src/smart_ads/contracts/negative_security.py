"""Closed P1 `smart_ads/negative_security_test_report/v1` and 7A sandbox invariants (ADR-0001 §3.2)."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
import hashlib
from types import MappingProxyType
from typing import Any, ClassVar, Final, TypeVar

_T = TypeVar("_T")

from smart_ads.contracts.jcs import (
    ADR_P1_DOMAIN_PREFIXES, MAX_JCS_SAFE_INT, ArtifactLocator, P1Integrity,
    canonicalize_jcs, jcs_sha256, p1_content_digest,
)
from smart_ads.contracts.scalars import (
    ClosedValidationError, parse_timestamp_utc_micros, require_exact_keys,
    require_mapping, validate_hex40, validate_non_empty_str, validate_opaque_ref,
    validate_sha256_prefixed, validate_timestamp_utc_seconds,
)

SANDBOX_PROFILE_ID: Final[str] = "smart_ads_7a_hermetic_linux_amd64_oci_v1"
SANDBOX_RESOURCES_VERSION: Final[str] = "smart_ads_7a_resources_v1"
_SANDBOX_PROFILE_SCHEMA: Final[str] = "smart_ads/sealed_sandbox_profile/v1"
_WHEEL_PROVENANCE_SCHEMA: Final[str] = "smart_ads/wheel_build_provenance/v1"
_WHEEL_OBJECT_LOCATOR_SCHEMA: Final[str] = "smart_ads/wheel_object_locator/v1"
_RUN_CONTEXT_SCHEMA: Final[str] = "smart_ads/migration_run_context/v1"
_NEGATIVE_REPORT_SCHEMA: Final[str] = "smart_ads/negative_security_test_report/v1"

MANDATORY_7A_NEGATIVE_CASES: Final[tuple[str, ...]] = tuple(
    "cpu_limit_enforced credential_paths_denied env_is_exact_allowlist "
    "file_size_limit_enforced host_dev_denied host_home_denied host_proc_denied "
    "host_sys_denied inherited_fd_denied memory_limit_enforced output_limit_enforced "
    "pids_limit_enforced process_creation_denied socket_denied tmpfs_limit_enforced "
    "wall_clock_limit_enforced write_outside_tmp_denied".split()
)
PINNED_7A_NEGATIVE_SUITE_DIGEST: Final[str] = jcs_sha256({
    "suite_id": "smart_ads/7a_negative_security_suite/v1",
    "profile_id": SANDBOX_PROFILE_ID, "cases": list(MANDATORY_7A_NEGATIVE_CASES),
})
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
    "clean_exit cpu_time_limit memory_oom pids_max_limit tmpfs_enospc "
    "rlimit_fsize stdout_limit stderr_limit wall_clock_watchdog".split()
)
_ALLOWED_SIGNALS: Final[frozenset[str]] = frozenset({"SIGKILL", "SIGXCPU", "SIGXFSZ", "SIGTERM"})
_SHARED_RUNTIME_16_FIELDS: Final[frozenset[str]] = frozenset(
    "profile_id runtime_kind platform rootfs_read_only oci_image_digest runner_binary_digest "
    "exact_environment namespaces read_only_mounts fresh_tmpfs_mounts masked_empty_mounts "
    "host_bind_mounts_forbidden all_capabilities_dropped no_new_privs "
    "inherited_fds_above_2_closed seccomp_profile_digest".split()
)
_SPEC_17_FIELDS: Final[frozenset[str]] = _SHARED_RUNTIME_16_FIELDS | {"resource_limits"}
_SANDBOX_PAYLOAD_20_KEYS: Final[frozenset[str]] = _SPEC_17_FIELDS | {"migration_run_context_locator", "issued_at_utc", "validity"}
_WHEEL_PROVENANCE_16_KEYS: Final[frozenset[str]] = frozenset(
    "migration_run_context_locator build_run_id built_at_utc repository source_commit_sha "
    "source_tree_oid source_date_epoch python_abi_tag build_backend build_backend_version "
    "build_backend_digest pyproject_sha256 uv_lock_sha256 schema_bundle_digest wheel wheel_digest".split()
)
_PINNED_INT_LIMITS: Final[tuple[tuple[str, int], ...]] = (
    ("cgroup_version", 2), ("cpu_time_limit_seconds", 120), ("memory_max_bytes", 1_073_741_824),
    ("memory_swap_max_bytes", 0), ("pids_max", 32), ("rlimit_fsize_bytes", 67_108_864),
    ("stdout_max_bytes", 8_388_608), ("stderr_max_bytes", 8_388_608),
    ("wall_clock_timeout_seconds", 300), ("termination_grace_ms", 1000),
)


def _reparse(obj: object, cls: type[_T], *, label: str) -> _T:
    if type(obj) is not cls:
        raise ClosedValidationError(f"{label}: expected {cls.__name__}, got {type(obj).__name__}")
    try:
        raw = obj.to_dict()  # type: ignore[attr-defined]
    except Exception as exc:
        raise ClosedValidationError(f"{label}: corrupted {cls.__name__}: {exc}") from None
    return cls.from_dict(raw)  # type: ignore[attr-defined,no-any-return]

def _strict_bool(value: object, *, label: str) -> bool:
    if type(value) is not bool:
        raise ClosedValidationError(f"{label}: expected bool, got {type(value).__name__}")
    return value

def _exact_bool(value: object, expected: bool, *, label: str) -> bool:
    if _strict_bool(value, label=label) is not expected:
        raise ClosedValidationError(f"{label}: expected {expected!r}, got {value!r}")
    return expected

def _strict_int(value: object, *, label: str, minimum: int = 0, maximum: int = MAX_JCS_SAFE_INT) -> int:
    if type(value) is not int or not (minimum <= value <= maximum):
        raise ClosedValidationError(f"{label}: expected int in [{minimum}, {maximum}], got {value!r}")
    return value

def _exact_int(value: object, expected: int, *, label: str) -> int:
    return _strict_int(value, label=label, minimum=expected, maximum=expected)

def _strict_str(value: object, *, label: str) -> str:
    if type(value) is not str:
        raise ClosedValidationError(f"{label}: expected str, got {type(value).__name__}")
    checked = validate_non_empty_str(value, field_name=label)
    if checked != checked.strip() or any(ord(c) <= 0x1F or 0x7F <= ord(c) <= 0x9F for c in checked):
        raise ClosedValidationError(f"{label}: leading/trailing whitespace or control char")
    return checked

def _exact_str(value: object, expected: str, *, label: str) -> str:
    if type(value) is not str or value != expected:
        raise ClosedValidationError(f"{label}: expected {expected!r}, got {value!r}")
    return value

def _exact_str_seq(value: object, expected: tuple[str, ...], *, label: str, list_only: bool = False) -> tuple[str, ...]:
    if list_only and type(value) is not list:
        raise ClosedValidationError(f"{label}: expected JSON array list")
    if type(value) not in (list, tuple) or any(type(i) is not str for i in value) or tuple(value) != expected:
        raise ClosedValidationError(f"{label}: expected exact {list(expected)!r}")
    return expected

def _exact_typed_dict(mapping: object, expected: Mapping[str, Any], *, label: str) -> None:
    checked = require_exact_keys(mapping, set(expected.keys()), label=label)
    for key, exp_val in expected.items():
        if type(checked[key]) is not type(exp_val) or checked[key] != exp_val:
            raise ClosedValidationError(f"{label}.{key}: expected {exp_val!r}, got {checked[key]!r}")

def _utc_sec_micros(value: object, *, label: str) -> int:
    if type(value) is not str:
        raise ClosedValidationError(f"{label}: expected str, got {type(value).__name__}")
    validate_timestamp_utc_seconds(value, field_name=label)
    return parse_timestamp_utc_micros(value, field_name=label, allow_whole_seconds=True)

def _validate_tmpfs_limits(value: object, *, label: str, list_only: bool = False) -> Mapping[str, Mapping[str, Any]]:
    outer = require_exact_keys(value, {"/tmp"}, label=label)
    tmp = require_exact_keys(outer["/tmp"], {"size_bytes", "inodes_max", "mount_flags"}, label=f"{label}./tmp")
    _exact_int(tmp["size_bytes"], 268_435_456, label=f"{label}./tmp.size_bytes")
    _exact_int(tmp["inodes_max"], 4096, label=f"{label}./tmp.inodes_max")
    _exact_str_seq(tmp["mount_flags"], _EXACT_TMP_FLAGS, label=f"{label}./tmp.mount_flags", list_only=list_only)
    return MappingProxyType({"/tmp": MappingProxyType({"size_bytes": 268_435_456, "inodes_max": 4096, "mount_flags": _EXACT_TMP_FLAGS})})


@dataclass(frozen=True, slots=True)
class SandboxResourceLimits:
    """Closed 13-key `smart_ads_7a_resources_v1` resource ceiling block."""

    KEYS: ClassVar[frozenset[str]] = frozenset(
        "profile_version cgroup_version cpu_max cpu_time_limit_seconds memory_max_bytes "
        "memory_swap_max_bytes pids_max tmpfs_limits rlimit_fsize_bytes stdout_max_bytes "
        "stderr_max_bytes wall_clock_timeout_seconds termination_grace_ms".split()
    )
    profile_version: str = SANDBOX_RESOURCES_VERSION
    cgroup_version: int = 2
    cpu_max: Mapping[str, int] = field(default_factory=lambda: MappingProxyType({"quota_us": 100_000, "period_us": 100_000}))
    cpu_time_limit_seconds: int = 120
    memory_max_bytes: int = 1_073_741_824
    memory_swap_max_bytes: int = 0
    pids_max: int = 32
    tmpfs_limits: Mapping[str, Mapping[str, Any]] = field(
        default_factory=lambda: MappingProxyType({"/tmp": MappingProxyType({"size_bytes": 268_435_456, "inodes_max": 4096, "mount_flags": _EXACT_TMP_FLAGS})})
    )
    rlimit_fsize_bytes: int = 67_108_864
    stdout_max_bytes: int = 8_388_608
    stderr_max_bytes: int = 8_388_608
    wall_clock_timeout_seconds: int = 300
    termination_grace_ms: int = 1000

    def __post_init__(self) -> None:
        lbl = "sandbox_resource_limits"
        _exact_str(self.profile_version, SANDBOX_RESOURCES_VERSION, label=f"{lbl}.profile_version")
        _exact_typed_dict(self.cpu_max, {"quota_us": 100_000, "period_us": 100_000}, label=f"{lbl}.cpu_max")
        object.__setattr__(self, "cpu_max", MappingProxyType({"quota_us": 100_000, "period_us": 100_000}))
        object.__setattr__(self, "tmpfs_limits", _validate_tmpfs_limits(self.tmpfs_limits, label=f"{lbl}.tmpfs_limits"))
        for attr, expected in _PINNED_INT_LIMITS:
            _exact_int(getattr(self, attr), expected, label=f"{lbl}.{attr}")

    @classmethod
    def canonical(cls) -> SandboxResourceLimits:
        return cls()

    def to_dict(self) -> dict[str, Any]:
        tmp = self.tmpfs_limits["/tmp"]
        out: dict[str, Any] = {
            "profile_version": self.profile_version,
            "cpu_max": {"quota_us": self.cpu_max["quota_us"], "period_us": self.cpu_max["period_us"]},
            "tmpfs_limits": {"/tmp": {"size_bytes": tmp["size_bytes"], "inodes_max": tmp["inodes_max"], "mount_flags": list(tmp["mount_flags"])}},
        }
        for attr, _ in _PINNED_INT_LIMITS:
            out[attr] = getattr(self, attr)
        return out

    @classmethod
    def from_dict(cls, data: object) -> SandboxResourceLimits:
        m = require_exact_keys(data, cls.KEYS, label="sandbox_resource_limits")
        _validate_tmpfs_limits(m["tmpfs_limits"], label="sandbox_resource_limits.tmpfs_limits", list_only=True)
        return cls(**{k: m[k] for k in cls.KEYS})


def _validate_shared_runtime_fields(m: Mapping[str, Any], *, label: str, list_only: bool) -> None:
    for k, exp_s in (("profile_id", SANDBOX_PROFILE_ID), ("runtime_kind", "oci"), ("platform", "linux/amd64")):
        _exact_str(m[k], exp_s, label=f"{label}.{k}")
    for k in ("rootfs_read_only", "host_bind_mounts_forbidden", "all_capabilities_dropped", "no_new_privs", "inherited_fds_above_2_closed"):
        _exact_bool(m[k], True, label=f"{label}.{k}")
    for k in ("oci_image_digest", "runner_binary_digest", "seccomp_profile_digest"):
        validate_sha256_prefixed(_strict_str(m[k], label=f"{label}.{k}"), field_name=f"{label}.{k}")
    _exact_typed_dict(m["exact_environment"], _EXACT_ENV, label=f"{label}.exact_environment")
    for k, exp_seq in (("namespaces", _EXACT_NAMESPACES), ("read_only_mounts", _EXACT_RO_MOUNTS), ("fresh_tmpfs_mounts", _EXACT_TMPFS_MOUNTS), ("masked_empty_mounts", _EXACT_MASKED_MOUNTS)):
        _exact_str_seq(m[k], exp_seq, label=f"{label}.{k}", list_only=list_only)


@dataclass(frozen=True, slots=True)
class SandboxRuntimeReadback:
    """Closed 20-key outer-supervisor runtime readback for a 7A sandbox run."""

    KEYS: ClassVar[frozenset[str]] = _SHARED_RUNTIME_16_FIELDS | {
        "effective_writable_mounts", "seccomp_enforced_before_entry", "network_absent", "loopback_absent",
    }
    profile_id: str
    runtime_kind: str
    platform: str
    rootfs_read_only: bool
    oci_image_digest: str
    runner_binary_digest: str
    exact_environment: Mapping[str, str]
    namespaces: tuple[str, ...]
    read_only_mounts: tuple[str, ...]
    fresh_tmpfs_mounts: tuple[str, ...]
    masked_empty_mounts: tuple[str, ...]
    host_bind_mounts_forbidden: bool
    all_capabilities_dropped: bool
    no_new_privs: bool
    inherited_fds_above_2_closed: bool
    seccomp_profile_digest: str
    effective_writable_mounts: tuple[str, ...]
    seccomp_enforced_before_entry: bool
    network_absent: bool
    loopback_absent: bool

    def __post_init__(self) -> None:
        lbl = "sandbox_runtime_readback"
        _validate_shared_runtime_fields({k: getattr(self, k) for k in _SHARED_RUNTIME_16_FIELDS}, label=lbl, list_only=False)
        object.__setattr__(self, "exact_environment", MappingProxyType(dict(_EXACT_ENV)))
        for attr, exp_seq in (("namespaces", _EXACT_NAMESPACES), ("read_only_mounts", _EXACT_RO_MOUNTS), ("fresh_tmpfs_mounts", _EXACT_TMPFS_MOUNTS), ("masked_empty_mounts", _EXACT_MASKED_MOUNTS)):
            object.__setattr__(self, attr, exp_seq)
        _exact_str_seq(self.effective_writable_mounts, _EXACT_TMPFS_MOUNTS, label=f"{lbl}.effective_writable_mounts")
        object.__setattr__(self, "effective_writable_mounts", _EXACT_TMPFS_MOUNTS)
        _strict_bool(self.seccomp_enforced_before_entry, label=f"{lbl}.seccomp_enforced_before_entry")
        _exact_bool(self.network_absent, True, label=f"{lbl}.network_absent")
        _exact_bool(self.loopback_absent, True, label=f"{lbl}.loopback_absent")

    def to_dict(self) -> dict[str, Any]:
        seq_keys = {"namespaces", "read_only_mounts", "fresh_tmpfs_mounts", "masked_empty_mounts", "effective_writable_mounts"}
        out: dict[str, Any] = {"exact_environment": dict(self.exact_environment)}
        for k in self.KEYS - {"exact_environment"}:
            val = getattr(self, k)
            out[k] = list(val) if k in seq_keys else val
        return out

    @classmethod
    def from_dict(cls, data: object) -> SandboxRuntimeReadback:
        m = require_exact_keys(data, cls.KEYS, label="sandbox_runtime_readback")
        return cls(**{k: m[k] for k in cls.KEYS})


@dataclass(frozen=True, slots=True)
class SandboxUsageCounters:
    """Closed 11-key cgroup/rlimit/pipe usage counter tuple."""

    KEYS: ClassVar[frozenset[str]] = frozenset(
        "cpu_time_us memory_peak_bytes pids_peak tmpfs_peak_bytes tmpfs_peak_inodes "
        "max_file_bytes stdout_bytes stderr_bytes oom_delta oom_kill_delta pids_max_delta".split()
    )
    cpu_time_us: int = 0
    memory_peak_bytes: int = 0
    pids_peak: int = 0
    tmpfs_peak_bytes: int = 0
    tmpfs_peak_inodes: int = 0
    max_file_bytes: int = 0
    stdout_bytes: int = 0
    stderr_bytes: int = 0
    oom_delta: int = 0
    oom_kill_delta: int = 0
    pids_max_delta: int = 0

    def __post_init__(self) -> None:
        for name in self.KEYS:
            _strict_int(getattr(self, name), label=f"sandbox_usage_counters.{name}")

    def to_dict(self) -> dict[str, int]:
        return {name: getattr(self, name) for name in sorted(self.KEYS)}

    @classmethod
    def from_dict(cls, data: object) -> SandboxUsageCounters:
        m = require_exact_keys(data, cls.KEYS, label="sandbox_usage_counters")
        return cls(**{k: m[k] for k in cls.KEYS})


@dataclass(frozen=True, slots=True)
class SandboxTermination:
    """Closed 8-key outer-supervisor cgroup termination evidence."""

    KEYS: ClassVar[frozenset[str]] = frozenset(
        "cause supervisor_terminated_cgroup exit_code signal watchdog_elapsed_ms "
        "grace_elapsed_ms whole_cgroup_empty force_kill_used".split()
    )
    cause: str
    supervisor_terminated_cgroup: bool
    exit_code: int | None
    signal: str | None
    watchdog_elapsed_ms: int
    grace_elapsed_ms: int
    whole_cgroup_empty: bool
    force_kill_used: bool

    def __post_init__(self) -> None:
        lbl = "sandbox_termination"
        if type(self.cause) is not str or self.cause not in _ALLOWED_CAUSES:
            raise ClosedValidationError(f"{lbl}.cause: invalid cause {self.cause!r}")
        _strict_bool(self.supervisor_terminated_cgroup, label=f"{lbl}.supervisor_terminated_cgroup")
        if self.exit_code is not None:
            _strict_int(self.exit_code, label=f"{lbl}.exit_code", minimum=0, maximum=255)
        if self.signal is not None and (type(self.signal) is not str or self.signal not in _ALLOWED_SIGNALS):
            raise ClosedValidationError(f"{lbl}.signal: invalid signal {self.signal!r}")
        _strict_int(self.watchdog_elapsed_ms, label=f"{lbl}.watchdog_elapsed_ms")
        _strict_int(self.grace_elapsed_ms, label=f"{lbl}.grace_elapsed_ms", minimum=0, maximum=1000)
        _exact_bool(self.whole_cgroup_empty, True, label=f"{lbl}.whole_cgroup_empty")
        if _strict_bool(self.force_kill_used, label=f"{lbl}.force_kill_used") and self.signal != "SIGKILL":
            raise ClosedValidationError(f"{lbl}.force_kill_used: True requires signal == 'SIGKILL'")

    def to_dict(self) -> dict[str, Any]:
        return {k: getattr(self, k) for k in sorted(self.KEYS)}

    @classmethod
    def from_dict(cls, data: object) -> SandboxTermination:
        m = require_exact_keys(data, cls.KEYS, label="sandbox_termination")
        return cls(**{k: m[k] for k in cls.KEYS})


def evaluate_breach_predicates(usage: SandboxUsageCounters, termination: SandboxTermination) -> dict[str, bool]:
    """Evaluate the 9 closed 7A resource-ceiling breach predicates."""
    u, t = _reparse(usage, SandboxUsageCounters, label="usage"), _reparse(termination, SandboxTermination, label="termination")
    return {
        "B_cpu": u.cpu_time_us >= 120_000_000,
        "B_mem": u.memory_peak_bytes >= 1_073_741_824 or u.oom_delta > 0 or u.oom_kill_delta > 0,
        "B_pids": u.pids_max_delta > 0 or u.pids_peak > 32,
        "B_tmpfs_bytes": u.tmpfs_peak_bytes >= 268_435_456, "B_tmpfs_inodes": u.tmpfs_peak_inodes >= 4096,
        "B_fsize": u.max_file_bytes >= 67_108_864,
        "B_stdout": u.stdout_bytes >= 8_388_608, "B_stderr": u.stderr_bytes >= 8_388_608,
        "B_wall": t.watchdog_elapsed_ms >= 300_000,
    }

def _freeze_observation(obs: object, *, label: str) -> Mapping[str, Any]:
    checked = require_mapping(obs, label=label)
    if not checked:
        raise ClosedValidationError(f"{label}: observation mapping must not be empty")
    out: dict[str, Any] = {}
    for k, v in checked.items():
        _strict_str(k, label=f"{label}.key")
        if type(v) is bool:
            out[k] = v
        elif type(v) is int:
            out[k] = _strict_int(v, label=f"{label}.{k}")
        elif type(v) is str:
            out[k] = _strict_str(v, label=f"{label}.{k}")
        else:
            raise ClosedValidationError(f"{label}.{k}: unsupported type {type(v).__name__}")
    return MappingProxyType(out)


@dataclass(frozen=True, slots=True)
class NegativeSecurityRun:
    """Closed 9-key single sandbox subrun evidence record."""

    KEYS: ClassVar[frozenset[str]] = frozenset(
        "sandbox_instance_ref execution_binding_digest started_at_utc ended_at_utc "
        "runtime_readback effective_resource_limits usage termination observation".split()
    )
    sandbox_instance_ref: str
    execution_binding_digest: str
    started_at_utc: str
    ended_at_utc: str
    runtime_readback: SandboxRuntimeReadback
    effective_resource_limits: SandboxResourceLimits
    usage: SandboxUsageCounters
    termination: SandboxTermination
    observation: Mapping[str, Any]

    def __post_init__(self) -> None:
        lbl = "negative_security_run"
        validate_opaque_ref(_strict_str(self.sandbox_instance_ref, label=f"{lbl}.ref"), field_name=f"{lbl}.ref")
        validate_sha256_prefixed(_strict_str(self.execution_binding_digest, label=f"{lbl}.bind"), field_name=f"{lbl}.bind")
        if _utc_sec_micros(self.started_at_utc, label=f"{lbl}.start") > _utc_sec_micros(self.ended_at_utc, label=f"{lbl}.end"):
            raise ClosedValidationError(f"{lbl}: started_at_utc > ended_at_utc")
        for attr, cls_t in (("runtime_readback", SandboxRuntimeReadback), ("effective_resource_limits", SandboxResourceLimits), ("usage", SandboxUsageCounters), ("termination", SandboxTermination)):
            object.__setattr__(self, attr, _reparse(getattr(self, attr), cls_t, label=f"{lbl}.{attr}"))
        object.__setattr__(self, "observation", _freeze_observation(self.observation, label=f"{lbl}.observation"))

    def to_dict(self) -> dict[str, Any]:
        return {
            "sandbox_instance_ref": self.sandbox_instance_ref, "execution_binding_digest": self.execution_binding_digest,
            "started_at_utc": self.started_at_utc, "ended_at_utc": self.ended_at_utc,
            "runtime_readback": self.runtime_readback.to_dict(), "effective_resource_limits": self.effective_resource_limits.to_dict(),
            "usage": self.usage.to_dict(), "termination": self.termination.to_dict(), "observation": dict(self.observation),
        }

    @classmethod
    def from_dict(cls, data: object) -> NegativeSecurityRun:
        m = require_exact_keys(data, cls.KEYS, label="negative_security_run")
        return cls(
            sandbox_instance_ref=m["sandbox_instance_ref"], execution_binding_digest=m["execution_binding_digest"],
            started_at_utc=m["started_at_utc"], ended_at_utc=m["ended_at_utc"],
            runtime_readback=SandboxRuntimeReadback.from_dict(m["runtime_readback"]),
            effective_resource_limits=SandboxResourceLimits.from_dict(m["effective_resource_limits"]),
            usage=SandboxUsageCounters.from_dict(m["usage"]),
            termination=SandboxTermination.from_dict(m["termination"]), observation=m["observation"],
        )

_EXACT_DENIAL_OBS: Final[Mapping[str, Mapping[str, Any]]] = MappingProxyType({
    "env_is_exact_allowlist": MappingProxyType({"environment_matches": True}),
    "host_dev_denied": MappingProxyType({"mount": "/dev", "host_access_denied": True}),
    "host_home_denied": MappingProxyType({"mount": "/home", "host_access_denied": True}),
    "host_proc_denied": MappingProxyType({"mount": "/proc", "host_access_denied": True}),
    "host_sys_denied": MappingProxyType({"mount": "/sys", "host_access_denied": True}),
    "inherited_fd_denied": MappingProxyType({"probe_set_id": "inherited_fds_above_2_v1", "inherited_fd_count_above_2": 0}),
    "write_outside_tmp_denied": MappingProxyType({"probe_target_id": "rootfs_non_tmp_v1", "creation_denied": True}),
})
_COUNTED_DENIAL_OBS: Final[Mapping[str, tuple[str, int]]] = MappingProxyType(
    {"credential_paths_denied": ("credential_paths_v1", 1), "process_creation_denied": ("seccomp_process_creation_v1", 4), "socket_denied": ("seccomp_socket_v1", 2)}
)
_STATIC_RESOURCE_SPECS: Final[Mapping[str, tuple[str, bool, frozenset[str], str, Mapping[str, Any]]]] = MappingProxyType({
    "cpu_limit_enforced": ("B_cpu", True, frozenset({"SIGXCPU", "SIGKILL"}), "cpu_time_limit", MappingProxyType({"quota_readback_matched": True, "cpu_time_exhausted": True})),
    "file_size_limit_enforced": ("B_fsize", True, frozenset({"SIGXFSZ", "SIGKILL"}), "rlimit_fsize", MappingProxyType({"file_size_at_ceiling": True, "limit_signal_observed": True})),
    "memory_limit_enforced": ("B_mem", True, frozenset({"SIGKILL"}), "memory_oom", MappingProxyType({"controller": "memory", "event": "oom_kill"})),
    "pids_limit_enforced": ("B_pids", False, frozenset({"SIGTERM", "SIGKILL"}), "pids_max_limit", MappingProxyType({"probe_phase": "pre_seccomp_trusted_harness", "event": "pids_max"})),
    "wall_clock_limit_enforced": ("B_wall", True, frozenset({"SIGKILL"}), "wall_clock_watchdog", MappingProxyType({"watchdog_fired": True, "whole_cgroup_terminated": True})),
})


def _validate_denial_case_run(case_id: str, run: NegativeSecurityRun) -> None:
    lbl, t = f"negative_security_case[{case_id}]", run.termination
    if any(evaluate_breach_predicates(run.usage, t).values()):
        raise ClosedValidationError(f"{lbl}: denial case must have all B_* == False")
    if (
        run.runtime_readback.seccomp_enforced_before_entry is not True
        or t.supervisor_terminated_cgroup is not False
        or t.cause != "clean_exit" or t.exit_code != 0 or t.signal is not None
        or t.force_kill_used is not False or t.whole_cgroup_empty is not True
    ):
        raise ClosedValidationError(f"{lbl}: invalid clean-exit/seccomp state for denial case")
    if case_id in _EXACT_DENIAL_OBS:
        _exact_typed_dict(run.observation, _EXACT_DENIAL_OBS[case_id], label=f"{lbl}.observation")
        return
    probe_set_id, min_count = _COUNTED_DENIAL_OBS[case_id]
    obs = require_exact_keys(run.observation, {"probe_set_id", "denied_probe_count"}, label=f"{lbl}.observation")
    _exact_str(obs["probe_set_id"], probe_set_id, label=f"{lbl}.observation.probe_set_id")
    _strict_int(obs["denied_probe_count"], label=f"{lbl}.observation.denied_probe_count", minimum=min_count)

def _require_resource_common(
    run: NegativeSecurityRun, *, label: str, breach_key: str, seccomp: bool, signals: frozenset[str], cause: str
) -> None:
    fired = [k for k, v in evaluate_breach_predicates(run.usage, run.termination).items() if v]
    if fired != [breach_key]:
        raise ClosedValidationError(f"{label}: expected one-hot breach [{breach_key!r}], got {fired!r}")
    t = run.termination
    if (
        run.runtime_readback.seccomp_enforced_before_entry is not seccomp
        or t.supervisor_terminated_cgroup is not True or t.exit_code is not None
        or t.signal is None or t.signal not in signals
        or t.cause != cause or t.whole_cgroup_empty is not True
    ):
        raise ClosedValidationError(f"{label}: resource termination/seccomp invariant violated")

def _validate_single_resource_run(case_id: str, run: NegativeSecurityRun) -> None:
    lbl, u = f"negative_security_case[{case_id}]", run.usage
    if case_id == "tmpfs_limit_enforced":
        obs = require_exact_keys(run.observation, {"ceiling_kind", "errno"}, label=f"{lbl}.obs")
        _exact_str(obs["errno"], "ENOSPC", label=f"{lbl}.obs.errno")
        if obs["ceiling_kind"] not in {"bytes", "inodes"}:
            raise ClosedValidationError(f"{lbl}.obs.ceiling_kind: invalid {obs['ceiling_kind']!r}")
        b_key = "B_tmpfs_bytes" if obs["ceiling_kind"] == "bytes" else "B_tmpfs_inodes"
        _require_resource_common(run, label=lbl, breach_key=b_key, seccomp=True, signals=frozenset({"SIGTERM", "SIGKILL"}), cause="tmpfs_enospc")
        return
    b_key, seccomp, sigs, cause, exp_obs = _STATIC_RESOURCE_SPECS[case_id]
    _require_resource_common(run, label=lbl, breach_key=b_key, seccomp=seccomp, signals=sigs, cause=cause)
    _exact_typed_dict(run.observation, exp_obs, label=f"{lbl}.obs")
    if case_id == "file_size_limit_enforced":
        _exact_int(u.max_file_bytes, 67_108_864, label=f"{lbl}.usage.max_file_bytes")
    elif case_id == "memory_limit_enforced" and (u.oom_kill_delta < 1 or not (u.memory_peak_bytes >= 1_073_741_824 or u.oom_delta >= 1)):
        raise ClosedValidationError(f"{lbl}: missing memory OOM cgroup counters")
    elif case_id == "pids_limit_enforced" and (u.pids_max_delta < 1 or u.pids_peak > 32):
        raise ClosedValidationError(f"{lbl}: invalid pids.max counters")

def _validate_output_limit_runs(runs: tuple[NegativeSecurityRun, ...]) -> None:
    sigs = frozenset({"SIGTERM", "SIGKILL"})
    for idx, b_key, attr, cause, stream_name in ((0, "B_stdout", "stdout_bytes", "stdout_limit", "stdout"), (1, "B_stderr", "stderr_bytes", "stderr_limit", "stderr")):
        lbl = f"negative_security_case[output_limit_enforced][{idx}]"
        _require_resource_common(runs[idx], label=lbl, breach_key=b_key, seccomp=True, signals=sigs, cause=cause)
        _exact_int(getattr(runs[idx].usage, attr), 8_388_608, label=f"{lbl}.usage.{attr}")
        _exact_typed_dict(runs[idx].observation, {"stream": stream_name, "first_ceiling_reached": True}, label=f"{lbl}.obs")


@dataclass(frozen=True, slots=True)
class NegativeSecurityCase:
    """Closed 3-key 7A negative security case entry (`{case_id, outcome, runs}`)."""

    KEYS: ClassVar[frozenset[str]] = frozenset({"case_id", "outcome", "runs"})
    case_id: str
    outcome: str
    runs: tuple[NegativeSecurityRun, ...]

    def __post_init__(self) -> None:
        if type(self.case_id) is not str or self.case_id not in MANDATORY_7A_NEGATIVE_CASES:
            raise ClosedValidationError(f"negative_security_case.case_id: invalid {self.case_id!r}")
        _exact_str(self.outcome, "passed", label="negative_security_case.outcome")
        if not isinstance(self.runs, (list, tuple)) or any(not isinstance(r, NegativeSecurityRun) for r in self.runs):
            raise ClosedValidationError("negative_security_case.runs: expected NegativeSecurityRun sequence")
        runs_tup = tuple(self.runs)
        object.__setattr__(self, "runs", runs_tup)
        expected_len = 2 if self.case_id == "output_limit_enforced" else 1
        if len(runs_tup) != expected_len:
            raise ClosedValidationError(f"negative_security_case[{self.case_id}].runs: expected {expected_len}")
        if self.case_id in _EXACT_DENIAL_OBS or self.case_id in _COUNTED_DENIAL_OBS:
            _validate_denial_case_run(self.case_id, runs_tup[0])
        elif self.case_id == "output_limit_enforced":
            _validate_output_limit_runs(runs_tup)
        else:
            _validate_single_resource_run(self.case_id, runs_tup[0])

    def to_dict(self) -> dict[str, Any]:
        return {"case_id": self.case_id, "outcome": self.outcome, "runs": [r.to_dict() for r in self.runs]}

    @classmethod
    def from_dict(cls, data: object) -> NegativeSecurityCase:
        m = require_exact_keys(data, cls.KEYS, label="negative_security_case")
        if type(m["runs"]) is not list:
            raise ClosedValidationError("negative_security_case.runs: expected JSON array list")
        return cls(case_id=m["case_id"], outcome=m["outcome"], runs=tuple(NegativeSecurityRun.from_dict(r) for r in m["runs"]))


def _require_typed_locator(loc: object, expected_type: str, *, label: str) -> ArtifactLocator:
    if type(loc) is not ArtifactLocator:
        raise ClosedValidationError(f"{label}: expected ArtifactLocator")
    try:
        raw = loc.to_dict()
    except Exception as exc:
        raise ClosedValidationError(f"{label}: corrupted ArtifactLocator: {exc}") from None
    return ArtifactLocator.from_dict(raw, expected_type=expected_type)

def _validate_report_cases_and_runs(report: NegativeSecurityTestReport, executed_us: int) -> None:
    if [c.case_id for c in report.cases] != list(MANDATORY_7A_NEGATIVE_CASES):
        raise ClosedValidationError("negative_security_test_report.cases: must match MANDATORY_7A_NEGATIVE_CASES")
    seen_refs: set[str] = set()
    for case in report.cases:
        checked_case = _reparse(case, NegativeSecurityCase, label="negative_security_test_report.case")
        for run in checked_case.runs:
            if run.sandbox_instance_ref in seen_refs:
                raise ClosedValidationError(f"duplicate sandbox_instance_ref {run.sandbox_instance_ref!r}")
            seen_refs.add(run.sandbox_instance_ref)
            start_us = _utc_sec_micros(run.started_at_utc, label="run.started_at_utc")
            end_us = _utc_sec_micros(run.ended_at_utc, label="run.ended_at_utc")
            if (
                run.effective_resource_limits != report.declared_resource_limits
                or run.runtime_readback.oci_image_digest != report.oci_image_digest
                or run.runtime_readback.runner_binary_digest != report.runner_binary_digest
                or not (start_us <= end_us <= executed_us)
            ):
                raise ClosedValidationError("negative_security_test_report: run/report invariant mismatch")


@dataclass(frozen=True, slots=True)
class NegativeSecurityTestReport:
    """Closed P1 `smart_ads/negative_security_test_report/v1` envelope."""

    SCHEMA: ClassVar[str] = _NEGATIVE_REPORT_SCHEMA
    P1_DOMAIN_PREFIX: ClassVar[str] = ADR_P1_DOMAIN_PREFIXES[_NEGATIVE_REPORT_SCHEMA]
    CORE_KEYS: ClassVar[frozenset[str]] = frozenset(
        "$schema build_backend_digest build_run_id cases declared_resource_limits executed_at_utc "
        "migration_run_context_locator oci_image_digest runner_binary_digest schema_bundle_digest "
        "sealed_sandbox_profile_locator source_commit_sha test_suite_digest "
        "wheel_build_provenance_locator wheel_digest".split()
    )
    KEYS: ClassVar[frozenset[str]] = CORE_KEYS | {"integrity"}

    migration_run_context_locator: ArtifactLocator
    sealed_sandbox_profile_locator: ArtifactLocator
    wheel_build_provenance_locator: ArtifactLocator
    build_run_id: str
    executed_at_utc: str
    source_commit_sha: str
    build_backend_digest: str
    schema_bundle_digest: str
    wheel_digest: str
    oci_image_digest: str
    runner_binary_digest: str
    test_suite_digest: str
    declared_resource_limits: SandboxResourceLimits
    cases: tuple[NegativeSecurityCase, ...]
    integrity: P1Integrity | None = None

    def __post_init__(self) -> None:
        lbl = "negative_security_test_report"
        _require_typed_locator(self.migration_run_context_locator, _RUN_CONTEXT_SCHEMA, label=f"{lbl}.run_ctx")
        _require_typed_locator(self.sealed_sandbox_profile_locator, _SANDBOX_PROFILE_SCHEMA, label=f"{lbl}.sbx_loc")
        _require_typed_locator(self.wheel_build_provenance_locator, _WHEEL_PROVENANCE_SCHEMA, label=f"{lbl}.prov_loc")
        _strict_str(self.build_run_id, label=f"{lbl}.build_run_id")
        executed_us = _utc_sec_micros(self.executed_at_utc, label=f"{lbl}.executed_at_utc")
        validate_hex40(_strict_str(self.source_commit_sha, label=f"{lbl}.commit"), field_name=f"{lbl}.commit")
        for d_attr in ("build_backend_digest", "schema_bundle_digest", "wheel_digest", "oci_image_digest", "runner_binary_digest", "test_suite_digest"):
            validate_sha256_prefixed(_strict_str(getattr(self, d_attr), label=f"{lbl}.{d_attr}"), field_name=f"{lbl}.{d_attr}")
        _exact_str(self.test_suite_digest, PINNED_7A_NEGATIVE_SUITE_DIGEST, label=f"{lbl}.test_suite_digest")
        if not isinstance(self.declared_resource_limits, SandboxResourceLimits):
            raise ClosedValidationError(f"{lbl}.declared_resource_limits: expected SandboxResourceLimits")
        if not isinstance(self.cases, (list, tuple)) or any(not isinstance(c, NegativeSecurityCase) for c in self.cases):
            raise ClosedValidationError(f"{lbl}.cases: expected NegativeSecurityCase sequence")
        object.__setattr__(self, "cases", tuple(self.cases))
        _validate_report_cases_and_runs(self, executed_us)
        if self.integrity is not None and not isinstance(self.integrity, P1Integrity):
            raise ClosedValidationError(f"{lbl}.integrity: expected P1Integrity or None")
        if self.integrity is not None and self.integrity.is_signed and self.integrity.content_digest != p1_content_digest(self.to_dict()):
            raise ClosedValidationError(f"{lbl}.integrity.content_digest: mismatch against P1 preimage")

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "$schema": self.SCHEMA,
            "migration_run_context_locator": self.migration_run_context_locator.to_dict(),
            "sealed_sandbox_profile_locator": self.sealed_sandbox_profile_locator.to_dict(),
            "wheel_build_provenance_locator": self.wheel_build_provenance_locator.to_dict(),
            "declared_resource_limits": self.declared_resource_limits.to_dict(),
            "cases": [c.to_dict() for c in self.cases],
        }
        for s_attr in ("build_run_id", "executed_at_utc", "source_commit_sha", "build_backend_digest", "schema_bundle_digest", "wheel_digest", "oci_image_digest", "runner_binary_digest", "test_suite_digest"):
            out[s_attr] = getattr(self, s_attr)
        if self.integrity is not None:
            out["integrity"] = self.integrity.to_dict()
        return out

    @classmethod
    def from_dict(cls, data: object, *, require_signed: bool = False) -> NegativeSecurityTestReport:
        _strict_bool(require_signed, label="require_signed")
        m = require_mapping(data, label="negative_security_test_report")
        if require_signed or "integrity" in m:
            require_exact_keys(m, cls.KEYS, label="negative_security_test_report")
            integrity: P1Integrity | None = P1Integrity.from_dict(m["integrity"], require_signed=require_signed)
        else:
            require_exact_keys(m, cls.CORE_KEYS, label="negative_security_test_report")
            integrity = None
        _exact_str(m["$schema"], cls.SCHEMA, label="negative_security_test_report.$schema")
        if type(m["cases"]) is not list:
            raise ClosedValidationError("negative_security_test_report.cases: expected JSON array list")
        scalars = {k: m[k] for k in ("build_run_id", "executed_at_utc", "source_commit_sha", "build_backend_digest", "schema_bundle_digest", "wheel_digest", "oci_image_digest", "runner_binary_digest", "test_suite_digest")}
        return cls(
            migration_run_context_locator=ArtifactLocator.from_dict(m["migration_run_context_locator"], expected_type=_RUN_CONTEXT_SCHEMA),
            sealed_sandbox_profile_locator=ArtifactLocator.from_dict(m["sealed_sandbox_profile_locator"], expected_type=_SANDBOX_PROFILE_SCHEMA),
            wheel_build_provenance_locator=ArtifactLocator.from_dict(m["wheel_build_provenance_locator"], expected_type=_WHEEL_PROVENANCE_SCHEMA),
            declared_resource_limits=SandboxResourceLimits.from_dict(m["declared_resource_limits"]),
            cases=tuple(NegativeSecurityCase.from_dict(c) for c in m["cases"]), integrity=integrity, **scalars,
        )


def compute_negative_run_execution_binding_digest(
    *, case_id: str, subrun_index: int, run: NegativeSecurityRun,
    wheel_digest: str, test_suite_digest: str, sealed_sandbox_profile_digest: str,
) -> str:
    """Compute canonical JCS SHA-256 execution binding digest for one negative security run."""
    _strict_str(case_id, label="case_id")
    _strict_int(subrun_index, label="subrun_index")
    r = _reparse(run, NegativeSecurityRun, label="run")
    for name, val in (("wheel_digest", wheel_digest), ("test_suite_digest", test_suite_digest), ("sealed_sandbox_profile_digest", sealed_sandbox_profile_digest)):
        validate_sha256_prefixed(_strict_str(val, label=name), field_name=name)
    return jcs_sha256({
        "case_id": case_id, "subrun_index": subrun_index, "sandbox_instance_ref": r.sandbox_instance_ref,
        "started_at_utc": r.started_at_utc, "ended_at_utc": r.ended_at_utc, "wheel_digest": wheel_digest,
        "test_suite_digest": test_suite_digest, "sealed_sandbox_profile_digest": sealed_sandbox_profile_digest,
        "runtime_readback": r.runtime_readback.to_dict(), "effective_resource_limits": r.effective_resource_limits.to_dict(),
        "usage": r.usage.to_dict(), "termination": r.termination.to_dict(), "observation": dict(r.observation),
    })


def _unwrap_p1_or_payload(
    raw: Mapping[str, Any], *, expected_schema: str, payload_keys: frozenset[str], expected_locator: ArtifactLocator, label: str
) -> dict[str, Any]:
    checked = require_mapping(raw, label=label)
    if "$schema" in checked or "integrity" in checked:
        require_exact_keys(checked, payload_keys | {"$schema", "integrity"}, label=label)
        _exact_str(checked["$schema"], expected_schema, label=f"{label}.$schema")
        integ = P1Integrity.from_dict(checked["integrity"])
        if integ.is_signed and integ.content_digest != p1_content_digest(checked):
            raise ClosedValidationError(f"{label}.integrity.content_digest: mismatch")
        if ArtifactLocator.for_canonical_bytes(expected_schema, canonicalize_jcs(checked)) != expected_locator:
            raise ClosedValidationError(f"{label}: envelope locator mismatch against report")
        return {k: v for k, v in checked.items() if k not in {"$schema", "integrity"}}
    require_exact_keys(checked, payload_keys, label=label)
    canonicalize_jcs(checked)
    return dict(checked)

def _validate_sandbox_profile_payload(
    payload: Mapping[str, Any],
) -> tuple[ArtifactLocator, SandboxResourceLimits, str, int, int, int]:
    _validate_shared_runtime_fields(payload, label="sandbox_profile", list_only=True)
    limits = SandboxResourceLimits.from_dict(payload["resource_limits"])
    run_ctx = ArtifactLocator.from_dict(payload["migration_run_context_locator"], expected_type=_RUN_CONTEXT_SCHEMA)
    issued_us = _utc_sec_micros(payload["issued_at_utc"], label="sandbox_profile.issued_at_utc")
    val_obj = require_exact_keys(payload["validity"], {"from", "until"}, label="sandbox_profile.validity")
    from_us, until_us = _utc_sec_micros(val_obj["from"], label="validity.from"), _utc_sec_micros(val_obj["until"], label="validity.until")
    if not (from_us <= issued_us < until_us):
        raise ClosedValidationError("sandbox_profile.validity: require from <= issued_at_utc < until")
    return run_ctx, limits, jcs_sha256({k: payload[k] for k in _SPEC_17_FIELDS}), issued_us, from_us, until_us

def _validate_wheel_provenance_payload(prov: Mapping[str, Any], wheel_bytes: bytes) -> tuple[ArtifactLocator, str, int]:
    run_ctx = ArtifactLocator.from_dict(prov["migration_run_context_locator"], expected_type=_RUN_CONTEXT_SCHEMA)
    _strict_str(prov["build_run_id"], label="wheel_provenance.build_run_id")
    built_us = _utc_sec_micros(prov["built_at_utc"], label="wheel_provenance.built_at_utc")
    for k, exp in (("repository", "aiconnai/smart-ads"), ("python_abi_tag", "cp312"), ("build_backend", "hatchling.build"), ("build_backend_version", "1.33.0")):
        _exact_str(prov[k], exp, label=f"wheel_provenance.{k}")
    for k in ("source_commit_sha", "source_tree_oid"):
        validate_hex40(_strict_str(prov[k], label=k), field_name=k)
    _strict_int(prov["source_date_epoch"], label="wheel_provenance.source_date_epoch")
    for k in ("build_backend_digest", "pyproject_sha256", "uv_lock_sha256", "schema_bundle_digest", "wheel_digest"):
        validate_sha256_prefixed(_strict_str(prov[k], label=k), field_name=k)
    actual_whl_digest = "sha256:" + hashlib.sha256(wheel_bytes).hexdigest()
    _exact_typed_dict(
        prov["wheel"],
        {"$schema": _WHEEL_OBJECT_LOCATOR_SCHEMA, "store_kind": "cell_immutable_object", "object_ref": f"cell-object:{actual_whl_digest}", "wheel_digest": actual_whl_digest, "size_bytes": len(wheel_bytes)},
        label="wheel_provenance.wheel",
    )
    _exact_str(prov["wheel_digest"], actual_whl_digest, label="wheel_provenance.wheel_digest")
    return run_ctx, actual_whl_digest, built_us

def _verify_runs_against_profile(
    report: NegativeSecurityTestReport, sandbox_payload: Mapping[str, Any],
    *, sbx_digest: str, floor_us: int, from_us: int, until_us: int, executed_us: int,
) -> None:
    if not (floor_us <= executed_us and from_us <= executed_us < until_us):
        raise ClosedValidationError("negative_security_test_report.executed_at_utc: chronology violation")
    for case in report.cases:
        for sub_idx, run in enumerate(case.runs):
            rb_dict = run.runtime_readback.to_dict()
            if any(rb_dict[k] != sandbox_payload[k] for k in _SHARED_RUNTIME_16_FIELDS):
                raise ClosedValidationError("run.runtime_readback: mismatch against sandbox_profile")
            start_us, end_us = _utc_sec_micros(run.started_at_utc, label="start"), _utc_sec_micros(run.ended_at_utc, label="end")
            if not (floor_us <= start_us <= end_us <= executed_us and from_us <= start_us <= end_us < until_us):
                raise ClosedValidationError("run: chronology violation against profile/provenance/validity")
            expected_bind = compute_negative_run_execution_binding_digest(
                case_id=case.case_id, subrun_index=sub_idx, run=run,
                wheel_digest=report.wheel_digest, test_suite_digest=report.test_suite_digest,
                sealed_sandbox_profile_digest=sbx_digest,
            )
            if run.execution_binding_digest != expected_bind:
                raise ClosedValidationError("run.execution_binding_digest: mismatch against recomputed binding")

def _assert_report_cross_artifact_equality(
    report: NegativeSecurityTestReport, sbx_payload: Mapping[str, Any], prov_payload: Mapping[str, Any],
    *, sbx_ctx: ArtifactLocator, prov_ctx: ArtifactLocator, sbx_limits: SandboxResourceLimits, actual_whl_digest: str,
) -> None:
    if (
        report.build_run_id != prov_payload["build_run_id"]
        or report.wheel_digest != actual_whl_digest
        or report.source_commit_sha != prov_payload["source_commit_sha"]
        or report.build_backend_digest != prov_payload["build_backend_digest"]
        or report.schema_bundle_digest != prov_payload["schema_bundle_digest"]
        or report.migration_run_context_locator != prov_ctx
        or report.migration_run_context_locator != sbx_ctx
        or report.declared_resource_limits != sbx_limits
        or report.oci_image_digest != sbx_payload["oci_image_digest"]
        or report.runner_binary_digest != sbx_payload["runner_binary_digest"]
    ):
        raise ClosedValidationError("negative_security_test_report: cross-artifact binding mismatch")


def verify_negative_security_report_against_profile(
    report: NegativeSecurityTestReport, *, sandbox_profile: Mapping[str, Any],
    wheel_provenance_payload: Mapping[str, Any], wheel_bytes: bytes,
) -> None:
    """Materially verify `report` against `sealed_sandbox_profile/v1`, wheel provenance, and `wheel_bytes`."""
    if type(wheel_bytes) is not bytes or len(wheel_bytes) == 0:
        raise ClosedValidationError("verify_negative_security_report_against_profile: expected non-empty bytes")
    checked = _reparse(report, NegativeSecurityTestReport, label="report")
    sbx_payload = _unwrap_p1_or_payload(sandbox_profile, expected_schema=_SANDBOX_PROFILE_SCHEMA, payload_keys=_SANDBOX_PAYLOAD_20_KEYS, expected_locator=checked.sealed_sandbox_profile_locator, label="sandbox_profile")
    prov_payload = _unwrap_p1_or_payload(wheel_provenance_payload, expected_schema=_WHEEL_PROVENANCE_SCHEMA, payload_keys=_WHEEL_PROVENANCE_16_KEYS, expected_locator=checked.wheel_build_provenance_locator, label="wheel_provenance_payload")
    sbx_ctx, sbx_limits, sbx_digest, issued_us, from_us, until_us = _validate_sandbox_profile_payload(sbx_payload)
    prov_ctx, actual_whl_digest, built_us = _validate_wheel_provenance_payload(prov_payload, wheel_bytes)
    _assert_report_cross_artifact_equality(checked, sbx_payload, prov_payload, sbx_ctx=sbx_ctx, prov_ctx=prov_ctx, sbx_limits=sbx_limits, actual_whl_digest=actual_whl_digest)
    _verify_runs_against_profile(checked, sbx_payload, sbx_digest=sbx_digest, floor_us=max(issued_us, built_us), from_us=from_us, until_us=until_us, executed_us=_utc_sec_micros(checked.executed_at_utc, label="executed_at_utc"))


__all__ = [
    "MANDATORY_7A_NEGATIVE_CASES", "NegativeSecurityCase", "NegativeSecurityRun",
    "NegativeSecurityTestReport", "PINNED_7A_NEGATIVE_SUITE_DIGEST", "SANDBOX_PROFILE_ID",
    "SANDBOX_RESOURCES_VERSION", "SandboxResourceLimits", "SandboxRuntimeReadback",
    "SandboxTermination", "SandboxUsageCounters",
    "compute_negative_run_execution_binding_digest", "evaluate_breach_predicates",
    "verify_negative_security_report_against_profile",
]
