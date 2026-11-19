"""Unit tests for `git_artifact_provenance/v1` and `negative_security_test_report/v1`."""
from __future__ import annotations

import base64
import copy
import dataclasses
import hashlib
from typing import Any

import pytest

import smart_ads.contracts as contracts_pkg
from smart_ads.contracts.git_provenance import (
    GitArtifactProvenance,
    compute_git_blob_oid,
    sort_git_provenance_locators,
    verify_git_provenance_against_bytes,
)
from smart_ads.contracts.jcs import (
    ADR_P1_DOMAIN_PREFIXES,
    MAX_JCS_SAFE_INT,
    ArtifactLocator,
    P1Integrity,
    canonicalize_jcs,
    jcs_sha256,
    p1_content_digest,
)
from smart_ads.contracts.negative_security import (
    MANDATORY_7A_NEGATIVE_CASES,
    PINNED_7A_NEGATIVE_SUITE_DIGEST,
    SANDBOX_PROFILE_ID,
    SANDBOX_RESOURCES_VERSION,
    NegativeSecurityCase,
    NegativeSecurityRun,
    NegativeSecurityTestReport,
    SandboxResourceLimits,
    SandboxRuntimeReadback,
    SandboxTermination,
    SandboxUsageCounters,
    compute_negative_run_execution_binding_digest,
    evaluate_breach_predicates,
    verify_negative_security_report_against_profile,
)
from smart_ads.contracts.scalars import ClosedValidationError

_SIG_B64 = base64.b64encode(b"\x11" * 64).decode("ascii")
_KEY_ID = "key:ed25519:" + ("a" * 64)
_REG_LOC = ArtifactLocator.from_digest(
    "smart_ads/key_authorization_registry/v1", "sha256:" + ("b" * 64)
)
_RUN_CTX_LOC = ArtifactLocator.from_digest(
    "smart_ads/migration_run_context/v1", "sha256:" + ("c" * 64)
)
_OCI_DIGEST = "sha256:" + ("1" * 64)
_RUNNER_DIGEST = "sha256:" + ("2" * 64)
_SECCOMP_DIGEST = "sha256:" + ("3" * 64)
_BACKEND_DIGEST = "sha256:" + ("4" * 64)
_SCHEMA_DIGEST = "sha256:" + ("5" * 64)
_PYPROJECT_DIGEST = "sha256:" + ("6" * 64)
_UVLOCK_DIGEST = "sha256:" + ("7" * 64)
_COMMIT_SHA = "abcde" * 8
_TREE_OID = "12345" * 8
_WHEEL_BYTES = b"PK\x03\x04deterministic-wheel-bytes-v1"
_WHEEL_DIGEST = "sha256:" + hashlib.sha256(_WHEEL_BYTES).hexdigest()
_EXACT_ENV = {
    "HOME": "/nonexistent",
    "LANG": "C.UTF-8",
    "PATH": "/usr/bin:/bin",
    "PYTHONNOUSERSITE": "1",
    "PYTHONSAFEPATH": "1",
    "TMPDIR": "/tmp",
    "TZ": "UTC",
}
_SPEC_17_KEYS = {
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


def _sign_envelope_dict(unsigned_dict: dict[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(unsigned_dict)
    out["integrity"] = {
        "key_id": _KEY_ID,
        "key_registry_snapshot_locator": _REG_LOC.to_dict(),
    }
    digest_val = p1_content_digest(out)
    out["integrity"]["content_digest"] = digest_val
    out["integrity"]["signature_base64"] = _SIG_B64
    return out


def _make_readback(*, seccomp_enforced: bool = True) -> SandboxRuntimeReadback:
    return SandboxRuntimeReadback.from_dict(
        {
            "profile_id": SANDBOX_PROFILE_ID,
            "runtime_kind": "oci",
            "platform": "linux/amd64",
            "rootfs_read_only": True,
            "oci_image_digest": _OCI_DIGEST,
            "runner_binary_digest": _RUNNER_DIGEST,
            "exact_environment": dict(_EXACT_ENV),
            "namespaces": ["mount", "network", "pid", "ipc", "uts", "user"],
            "read_only_mounts": ["/app", "/fixtures"],
            "fresh_tmpfs_mounts": ["/tmp"],
            "masked_empty_mounts": ["/proc", "/sys", "/dev", "/home", "/run", "/var/run"],
            "host_bind_mounts_forbidden": True,
            "all_capabilities_dropped": True,
            "no_new_privs": True,
            "inherited_fds_above_2_closed": True,
            "seccomp_profile_digest": _SECCOMP_DIGEST,
            "effective_writable_mounts": ["/tmp"],
            "seccomp_enforced_before_entry": seccomp_enforced,
            "network_absent": True,
            "loopback_absent": True,
        }
    )


def _make_sandbox_payload() -> dict[str, Any]:
    rb = _make_readback(seccomp_enforced=True).to_dict()
    spec_16 = {k: v for k, v in rb.items() if k in _SPEC_17_KEYS}
    return {
        **spec_16,
        "resource_limits": SandboxResourceLimits.canonical().to_dict(),
        "migration_run_context_locator": _RUN_CTX_LOC.to_dict(),
        "issued_at_utc": "2026-11-12T11:55:00Z",
        "validity": {"from": "2026-11-12T11:50:00Z", "until": "2026-11-12T13:00:00Z"},
    }


def _make_wheel_provenance_payload() -> dict[str, Any]:
    return {
        "migration_run_context_locator": _RUN_CTX_LOC.to_dict(),
        "build_run_id": "build-run-7a-001",
        "built_at_utc": "2026-11-12T12:00:00Z",
        "repository": "aiconnai/smart-ads",
        "source_commit_sha": _COMMIT_SHA,
        "source_tree_oid": _TREE_OID,
        "source_date_epoch": 1_700_000_000,
        "python_abi_tag": "cp312",
        "build_backend": "hatchling.build",
        "build_backend_version": "1.33.0",
        "build_backend_digest": _BACKEND_DIGEST,
        "pyproject_sha256": _PYPROJECT_DIGEST,
        "uv_lock_sha256": _UVLOCK_DIGEST,
        "schema_bundle_digest": _SCHEMA_DIGEST,
        "wheel": {
            "$schema": "smart_ads/wheel_object_locator/v1",
            "store_kind": "cell_immutable_object",
            "object_ref": f"cell-object:{_WHEEL_DIGEST}",
            "wheel_digest": _WHEEL_DIGEST,
            "size_bytes": len(_WHEEL_BYTES),
        },
        "wheel_digest": _WHEEL_DIGEST,
    }


_DENIAL_OBSERVATIONS: dict[str, dict[str, Any]] = {
    "credential_paths_denied": {"probe_set_id": "credential_paths_v1", "denied_probe_count": 3},
    "env_is_exact_allowlist": {"environment_matches": True},
    "host_dev_denied": {"mount": "/dev", "host_access_denied": True},
    "host_home_denied": {"mount": "/home", "host_access_denied": True},
    "host_proc_denied": {"mount": "/proc", "host_access_denied": True},
    "host_sys_denied": {"mount": "/sys", "host_access_denied": True},
    "inherited_fd_denied": {
        "probe_set_id": "inherited_fds_above_2_v1",
        "inherited_fd_count_above_2": 0,
    },
    "process_creation_denied": {
        "probe_set_id": "seccomp_process_creation_v1",
        "denied_probe_count": 5,
    },
    "socket_denied": {"probe_set_id": "seccomp_socket_v1", "denied_probe_count": 2},
    "write_outside_tmp_denied": {
        "probe_target_id": "rootfs_non_tmp_v1",
        "creation_denied": True,
    },
}


def _resource_run_specs(
    case_id: str,
) -> list[tuple[bool, SandboxUsageCounters, SandboxTermination, dict[str, Any]]]:
    u = SandboxUsageCounters
    t = SandboxTermination
    specs: dict[str, list[tuple[bool, SandboxUsageCounters, SandboxTermination, dict[str, Any]]]] = {
        "cpu_limit_enforced": [(
            True, u(cpu_time_us=120_000_000, pids_peak=1),
            t("cpu_time_limit", True, None, "SIGXCPU", 121_000, 10, True, False),
            {"quota_readback_matched": True, "cpu_time_exhausted": True},
        )],
        "file_size_limit_enforced": [(
            True, u(max_file_bytes=67_108_864, pids_peak=1),
            t("rlimit_fsize", True, None, "SIGXFSZ", 500, 5, True, False),
            {"file_size_at_ceiling": True, "limit_signal_observed": True},
        )],
        "memory_limit_enforced": [(
            True, u(memory_peak_bytes=1_073_741_824, oom_delta=1, oom_kill_delta=1, pids_peak=1),
            t("memory_oom", True, None, "SIGKILL", 800, 0, True, True),
            {"controller": "memory", "event": "oom_kill"},
        )],
        "output_limit_enforced": [
            (True, u(stdout_bytes=8_388_608, pids_peak=1),
             t("stdout_limit", True, None, "SIGTERM", 300, 15, True, False),
             {"stream": "stdout", "first_ceiling_reached": True}),
            (True, u(stderr_bytes=8_388_608, pids_peak=1),
             t("stderr_limit", True, None, "SIGKILL", 310, 1000, True, True),
             {"stream": "stderr", "first_ceiling_reached": True}),
        ],
        "pids_limit_enforced": [(
            False, u(pids_peak=32, pids_max_delta=1),
            t("pids_max_limit", True, None, "SIGTERM", 250, 20, True, False),
            {"probe_phase": "pre_seccomp_trusted_harness", "event": "pids_max"},
        )],
        "tmpfs_limit_enforced": [(
            True, u(tmpfs_peak_bytes=268_435_456, pids_peak=1),
            t("tmpfs_enospc", True, None, "SIGTERM", 400, 12, True, False),
            {"ceiling_kind": "bytes", "errno": "ENOSPC"},
        )],
        "wall_clock_limit_enforced": [(
            True, u(pids_peak=1),
            t("wall_clock_watchdog", True, None, "SIGKILL", 300_000, 1000, True, True),
            {"watchdog_fired": True, "whole_cgroup_terminated": True},
        )],
    }
    return specs[case_id]


def _build_bound_run(
    case_id: str,
    subrun_idx: int,
    ref: str,
    *,
    seccomp_enforced: bool,
    usage: SandboxUsageCounters,
    termination: SandboxTermination,
    observation: dict[str, Any],
    sbx_digest: str,
) -> NegativeSecurityRun:
    placeholder = NegativeSecurityRun(
        sandbox_instance_ref=ref,
        execution_binding_digest="sha256:" + ("0" * 64),
        started_at_utc="2026-11-12T12:01:00Z",
        ended_at_utc="2026-11-12T12:06:00Z",
        runtime_readback=_make_readback(seccomp_enforced=seccomp_enforced),
        effective_resource_limits=SandboxResourceLimits.canonical(),
        usage=usage,
        termination=termination,
        observation=observation,
    )
    binding = compute_negative_run_execution_binding_digest(
        case_id=case_id,
        subrun_index=subrun_idx,
        run=placeholder,
        wheel_digest=_WHEEL_DIGEST,
        test_suite_digest=PINNED_7A_NEGATIVE_SUITE_DIGEST,
        sealed_sandbox_profile_digest=sbx_digest,
    )
    return dataclasses.replace(placeholder, execution_binding_digest=binding)


def _build_all_17_cases(sbx_digest: str) -> tuple[NegativeSecurityCase, ...]:
    cases: list[NegativeSecurityCase] = []
    seq = 0
    clean_term = SandboxTermination("clean_exit", False, 0, None, 40, 0, True, False)
    clean_usage = SandboxUsageCounters(cpu_time_us=500, memory_peak_bytes=4096, pids_peak=1)
    for cid in MANDATORY_7A_NEGATIVE_CASES:
        if cid in _DENIAL_OBSERVATIONS:
            seq += 1
            run = _build_bound_run(
                cid, 0, f"sandbox:run-{seq:03d}", seccomp_enforced=True,
                usage=clean_usage, termination=clean_term,
                observation=_DENIAL_OBSERVATIONS[cid], sbx_digest=sbx_digest,
            )
            cases.append(NegativeSecurityCase(case_id=cid, outcome="passed", runs=(run,)))
        else:
            runs: list[NegativeSecurityRun] = []
            for sub_idx, (seccomp, usage, term, obs) in enumerate(_resource_run_specs(cid)):
                seq += 1
                runs.append(_build_bound_run(
                    cid, sub_idx, f"sandbox:run-{seq:03d}", seccomp_enforced=seccomp,
                    usage=usage, termination=term, observation=obs, sbx_digest=sbx_digest,
                ))
            cases.append(NegativeSecurityCase(case_id=cid, outcome="passed", runs=tuple(runs)))
    return tuple(cases)


def _build_valid_world() -> tuple[NegativeSecurityTestReport, dict[str, Any], dict[str, Any]]:
    sbx_payload = _make_sandbox_payload()
    sbx_env = _sign_envelope_dict({"$schema": "smart_ads/sealed_sandbox_profile/v1", **sbx_payload})
    prov_payload = _make_wheel_provenance_payload()
    prov_env = _sign_envelope_dict({"$schema": "smart_ads/wheel_build_provenance/v1", **prov_payload})
    sbx_digest = jcs_sha256({k: sbx_payload[k] for k in _SPEC_17_KEYS})
    sbx_loc = ArtifactLocator.for_canonical_bytes(
        "smart_ads/sealed_sandbox_profile/v1", canonicalize_jcs(sbx_env)
    )
    prov_loc = ArtifactLocator.for_canonical_bytes(
        "smart_ads/wheel_build_provenance/v1", canonicalize_jcs(prov_env)
    )
    report = NegativeSecurityTestReport(
        migration_run_context_locator=_RUN_CTX_LOC,
        sealed_sandbox_profile_locator=sbx_loc,
        wheel_build_provenance_locator=prov_loc,
        build_run_id="build-run-7a-001",
        executed_at_utc="2026-11-12T12:10:00Z",
        source_commit_sha=_COMMIT_SHA,
        build_backend_digest=_BACKEND_DIGEST,
        schema_bundle_digest=_SCHEMA_DIGEST,
        wheel_digest=_WHEEL_DIGEST,
        oci_image_digest=_OCI_DIGEST,
        runner_binary_digest=_RUNNER_DIGEST,
        test_suite_digest=PINNED_7A_NEGATIVE_SUITE_DIGEST,
        declared_resource_limits=SandboxResourceLimits.canonical(),
        cases=_build_all_17_cases(sbx_digest),
    )
    return report, sbx_env, prov_env


def test_git_blob_oid_and_git_artifact_provenance_roundtrip() -> None:
    assert compute_git_blob_oid(b"") == "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"
    raw = b"from __future__ import annotations\n"
    blob_oid = compute_git_blob_oid(raw)
    sha256_str = "sha256:" + hashlib.sha256(raw).hexdigest()
    for bad_bytes in ("text", bytearray(b"a"), memoryview(b"a"), 123, None):
        with pytest.raises(ClosedValidationError):
            compute_git_blob_oid(bad_bytes)  # type: ignore[arg-type]

    prov = GitArtifactProvenance(
        repository="aiconnai/smart-ads",
        commit_sha=_COMMIT_SHA,
        path="src/smart_ads/contracts/git_provenance.py",
        git_blob_oid=blob_oid,
        file_content_sha256=sha256_str,
        resolved_at_utc="2026-11-12T12:00:00Z",
    )
    assert GitArtifactProvenance.SCHEMA == "smart_ads/git_artifact_provenance/v1"
    assert ADR_P1_DOMAIN_PREFIXES[prov.SCHEMA] == "SMART-ADS:GIT-ARTIFACT:V1\n"
    assert len(GitArtifactProvenance.CORE_KEYS) == 7
    assert GitArtifactProvenance.KEYS == GitArtifactProvenance.CORE_KEYS | {"integrity"}
    assert GitArtifactProvenance.from_dict(prov.to_dict()) == prov
    verify_git_provenance_against_bytes(prov, raw)

    signed_dict = _sign_envelope_dict(prov.to_dict())
    signed_prov = GitArtifactProvenance.from_dict(signed_dict, require_signed=True)
    assert signed_prov.to_dict() == signed_dict
    with pytest.raises(ClosedValidationError):
        GitArtifactProvenance.from_dict(prov.to_dict(), require_signed=True)


@pytest.mark.parametrize(
    ("field", "bad_value"),
    [
        ("repository", ""),
        ("repository", "noslash"),
        ("repository", "/aiconnai/smart-ads"),
        ("repository", "aiconnai/smart-ads/"),
        ("repository", "aiconnai/smart/ads"),
        ("repository", "aiconnai/smart ads"),
        ("repository", "aiconnai/.."),
        ("commit_sha", "A" * 40),
        ("path", "/abs/path.py"),
        ("path", "trailing/"),
        ("path", "a//b.py"),
        ("path", "a/../b.py"),
        ("path", "a/./b.py"),
        ("path", "a\\b.py"),
        ("git_blob_oid", "0" * 39),
        ("file_content_sha256", "sha256:bad"),
        ("resolved_at_utc", "2026-11-12T12:00:00.000000Z"),
    ],
)
def test_git_artifact_provenance_rejects_malformed_fields(
    field: str, bad_value: object
) -> None:
    raw = b"payload"
    valid = {
        "$schema": "smart_ads/git_artifact_provenance/v1",
        "repository": "mbras-tech/mbras-campaigns",
        "commit_sha": _COMMIT_SHA,
        "path": "scripts/pipeboard_limits.py",
        "git_blob_oid": compute_git_blob_oid(raw),
        "file_content_sha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
        "resolved_at_utc": "2026-11-12T12:00:00Z",
    }
    valid[field] = bad_value
    with pytest.raises(ClosedValidationError):
        GitArtifactProvenance.from_dict(valid)


def test_git_provenance_locator_sorting_and_byte_verification() -> None:
    loc_hi = ArtifactLocator.from_digest(
        GitArtifactProvenance.SCHEMA, "sha256:" + ("f" * 64)
    )
    loc_lo = ArtifactLocator.from_digest(
        GitArtifactProvenance.SCHEMA, "sha256:" + ("0" * 64)
    )
    assert sort_git_provenance_locators([loc_hi, loc_lo]) == (loc_lo, loc_hi)
    assert sort_git_provenance_locators(()) == ()

    wrong_type = ArtifactLocator.from_digest(
        "smart_ads/collection_result/v1", "sha256:" + ("1" * 64)
    )
    for bad_seq in ("str", b"bytes", {loc_lo}, [loc_lo, loc_lo], [wrong_type], [123]):
        with pytest.raises(ClosedValidationError):
            sort_git_provenance_locators(bad_seq)  # type: ignore[arg-type]

    raw = b"exact-content"
    prov = GitArtifactProvenance(
        repository="aiconnai/smart-ads",
        commit_sha=_COMMIT_SHA,
        path="src/smart_ads/__init__.py",
        git_blob_oid=compute_git_blob_oid(raw),
        file_content_sha256="sha256:" + hashlib.sha256(raw).hexdigest(),
        resolved_at_utc="2026-11-12T12:00:00Z",
    )
    with pytest.raises(ClosedValidationError):
        verify_git_provenance_against_bytes(prov, b"tampered")
    bad_sha_prov = dataclasses.replace(prov, file_content_sha256="sha256:" + ("9" * 64))
    with pytest.raises(ClosedValidationError):
        verify_git_provenance_against_bytes(bad_sha_prov, raw)
    corrupted_prov = dataclasses.replace(prov)
    object.__setattr__(corrupted_prov, "integrity", 123)
    with pytest.raises(ClosedValidationError):
        verify_git_provenance_against_bytes(corrupted_prov, raw)


def test_pinned_7a_constants_and_subobject_strict_types() -> None:
    assert len(MANDATORY_7A_NEGATIVE_CASES) == 17
    assert list(MANDATORY_7A_NEGATIVE_CASES) == sorted(
        MANDATORY_7A_NEGATIVE_CASES, key=lambda s: s.encode("utf-8")
    )
    assert (
        PINNED_7A_NEGATIVE_SUITE_DIGEST
        == "sha256:8f2f561a8b6e3a75a960c04a747261ec31651e19f14457d78f915817523ec82d"
    )
    assert SANDBOX_RESOURCES_VERSION == "smart_ads_7a_resources_v1"

    limits = SandboxResourceLimits.canonical()
    assert len(limits.to_dict()) == 13
    assert SandboxResourceLimits.from_dict(limits.to_dict()) == limits
    with pytest.raises(TypeError):
        limits.cpu_max["quota_us"] = 1  # type: ignore[index]

    bad_limits = limits.to_dict()
    bad_limits["memory_swap_max_bytes"] = False
    with pytest.raises(ClosedValidationError):
        SandboxResourceLimits.from_dict(bad_limits)

    rb = _make_readback(seccomp_enforced=True)
    assert len(rb.to_dict()) == 20
    assert SandboxRuntimeReadback.from_dict(rb.to_dict()) == rb
    bad_rb = rb.to_dict()
    bad_rb["seccomp_enforced_before_entry"] = 1
    with pytest.raises(ClosedValidationError):
        SandboxRuntimeReadback.from_dict(bad_rb)

    usage = SandboxUsageCounters()
    assert len(usage.to_dict()) == 11
    with pytest.raises(ClosedValidationError):
        SandboxUsageCounters(cpu_time_us=True)  # type: ignore[arg-type]
    with pytest.raises(ClosedValidationError):
        SandboxUsageCounters(cpu_time_us=MAX_JCS_SAFE_INT + 1)


def test_termination_and_breach_predicate_equations() -> None:
    clean = SandboxTermination("clean_exit", False, 0, None, 0, 0, True, False)
    assert len(clean.to_dict()) == 8
    assert SandboxTermination.from_dict(clean.to_dict()) == clean
    assert all(v is False for v in evaluate_breach_predicates(SandboxUsageCounters(), clean).values())

    for bad_kwargs in (
        {"cause": "unknown"},
        {"whole_cgroup_empty": False},
        {"force_kill_used": True, "signal": "SIGTERM"},
        {"grace_elapsed_ms": 1001},
        {"exit_code": 256},
        {"exit_code": True},
        {"signal": "SIGINT"},
    ):
        d = clean.to_dict()
        d.update(bad_kwargs)
        with pytest.raises(ClosedValidationError):
            SandboxTermination.from_dict(d)

    assert evaluate_breach_predicates(SandboxUsageCounters(cpu_time_us=120_000_000), clean)["B_cpu"]
    assert evaluate_breach_predicates(SandboxUsageCounters(oom_delta=1), clean)["B_mem"]
    assert evaluate_breach_predicates(SandboxUsageCounters(pids_peak=33), clean)["B_pids"]
    assert evaluate_breach_predicates(SandboxUsageCounters(tmpfs_peak_bytes=268_435_456), clean)["B_tmpfs_bytes"]
    assert evaluate_breach_predicates(SandboxUsageCounters(tmpfs_peak_inodes=4096), clean)["B_tmpfs_inodes"]
    assert evaluate_breach_predicates(SandboxUsageCounters(max_file_bytes=67_108_864), clean)["B_fsize"]
    assert evaluate_breach_predicates(SandboxUsageCounters(stdout_bytes=8_388_608), clean)["B_stdout"]
    assert evaluate_breach_predicates(SandboxUsageCounters(stderr_bytes=8_388_608), clean)["B_stderr"]
    wall_term = dataclasses.replace(clean, watchdog_elapsed_ms=300_000)
    assert evaluate_breach_predicates(SandboxUsageCounters(), wall_term)["B_wall"]


def test_denial_and_resource_case_row_invariants_reject_violations() -> None:
    report, _, _ = _build_valid_world()
    by_id = {c.case_id: c.to_dict() for c in report.cases}

    # Denial case rejects bool-as-int in observation, any breach, or seccomp=False
    fd_case = copy.deepcopy(by_id["inherited_fd_denied"])
    fd_case["runs"][0]["observation"]["inherited_fd_count_above_2"] = False
    with pytest.raises(ClosedValidationError):
        NegativeSecurityCase.from_dict(fd_case)

    proc_case = copy.deepcopy(by_id["process_creation_denied"])
    proc_case["runs"][0]["observation"]["denied_probe_count"] = 3
    with pytest.raises(ClosedValidationError):
        NegativeSecurityCase.from_dict(proc_case)

    env_case = copy.deepcopy(by_id["env_is_exact_allowlist"])
    env_case["runs"][0]["usage"]["cpu_time_us"] = 120_000_000
    with pytest.raises(ClosedValidationError):
        NegativeSecurityCase.from_dict(env_case)

    # pids_limit_enforced requires seccomp=False; other resource cases require seccomp=True
    pids_case = copy.deepcopy(by_id["pids_limit_enforced"])
    pids_case["runs"][0]["runtime_readback"]["seccomp_enforced_before_entry"] = True
    with pytest.raises(ClosedValidationError):
        NegativeSecurityCase.from_dict(pids_case)

    cpu_case = copy.deepcopy(by_id["cpu_limit_enforced"])
    cpu_case["runs"][0]["runtime_readback"]["seccomp_enforced_before_entry"] = False
    with pytest.raises(ClosedValidationError):
        NegativeSecurityCase.from_dict(cpu_case)


def test_resource_ceiling_onehot_and_subrun_rejections() -> None:
    report, _, _ = _build_valid_world()
    by_id = {c.case_id: c.to_dict() for c in report.cases}

    # file_size_limit_enforced requires exact ceiling == 67_108_864
    fsize = copy.deepcopy(by_id["file_size_limit_enforced"])
    fsize["runs"][0]["usage"]["max_file_bytes"] = 67_108_865
    with pytest.raises(ClosedValidationError):
        NegativeSecurityCase.from_dict(fsize)

    # output_limit_enforced requires 2 runs (stdout then stderr at exact 8 MiB ceiling)
    out_case = copy.deepcopy(by_id["output_limit_enforced"])
    with pytest.raises(ClosedValidationError):
        NegativeSecurityCase.from_dict({**out_case, "runs": out_case["runs"][:1]})
    swapped = copy.deepcopy(out_case)
    swapped["runs"] = [out_case["runs"][1], out_case["runs"][0]]
    with pytest.raises(ClosedValidationError):
        NegativeSecurityCase.from_dict(swapped)

    # tmpfs_limit_enforced supports ceiling_kind="inodes" when B_tmpfs_inodes is one-hot
    tmpfs_inodes = copy.deepcopy(by_id["tmpfs_limit_enforced"])
    tmpfs_inodes["runs"][0]["observation"]["ceiling_kind"] = "inodes"
    tmpfs_inodes["runs"][0]["usage"]["tmpfs_peak_bytes"] = 0
    tmpfs_inodes["runs"][0]["usage"]["tmpfs_peak_inodes"] = 4096
    assert NegativeSecurityCase.from_dict(tmpfs_inodes).case_id == "tmpfs_limit_enforced"

    # Multiply-attributed breach (both bytes and inodes True) must fail closed
    tmpfs_both = copy.deepcopy(tmpfs_inodes)
    tmpfs_both["runs"][0]["usage"]["tmpfs_peak_bytes"] = 268_435_456
    with pytest.raises(ClosedValidationError):
        NegativeSecurityCase.from_dict(tmpfs_both)


def test_report_envelope_and_profile_verifier_roundtrip() -> None:
    report, sbx_env, prov_env = _build_valid_world()
    assert NegativeSecurityTestReport.SCHEMA == "smart_ads/negative_security_test_report/v1"
    assert (
        ADR_P1_DOMAIN_PREFIXES[report.SCHEMA] == "SMART-ADS:NEGATIVE-SECURITY:V1\n"
    )
    assert len(NegativeSecurityTestReport.CORE_KEYS) == 15
    assert len(NegativeSecurityTestReport.KEYS) == 16
    assert NegativeSecurityTestReport.from_dict(report.to_dict()) == report

    signed_dict = _sign_envelope_dict(report.to_dict())
    signed_report = NegativeSecurityTestReport.from_dict(signed_dict, require_signed=True)
    assert signed_report.to_dict() == signed_dict

    # Verifies against full signed envelopes AND against stripped payloads
    verify_negative_security_report_against_profile(
        signed_report,
        sandbox_profile=sbx_env,
        wheel_provenance_payload=prov_env,
        wheel_bytes=_WHEEL_BYTES,
    )
    sbx_stripped = {k: v for k, v in sbx_env.items() if k not in {"$schema", "integrity"}}
    prov_stripped = {k: v for k, v in prov_env.items() if k not in {"$schema", "integrity"}}
    verify_negative_security_report_against_profile(
        report,
        sandbox_profile=sbx_stripped,
        wheel_provenance_payload=prov_stripped,
        wheel_bytes=_WHEEL_BYTES,
    )


def test_report_and_verifier_reject_binding_chronology_and_locator_tampering() -> None:
    report, sbx_env, prov_env = _build_valid_world()

    dup_dict = report.to_dict()
    dup_dict["cases"][1]["runs"][0]["sandbox_instance_ref"] = (
        dup_dict["cases"][0]["runs"][0]["sandbox_instance_ref"]
    )
    with pytest.raises(ClosedValidationError):
        NegativeSecurityTestReport.from_dict(dup_dict)

    with pytest.raises(ClosedValidationError):
        verify_negative_security_report_against_profile(
            report, sandbox_profile=sbx_env, wheel_provenance_payload=prov_env, wheel_bytes=_WHEEL_BYTES + b"x"
        )

    bad_bind_dict = report.to_dict()
    bad_bind_dict["cases"][0]["runs"][0]["execution_binding_digest"] = "sha256:" + ("e" * 64)
    bad_bind_report = NegativeSecurityTestReport.from_dict(bad_bind_dict)
    with pytest.raises(ClosedValidationError):
        verify_negative_security_report_against_profile(
            bad_bind_report, sandbox_profile=sbx_env, wheel_provenance_payload=prov_env, wheel_bytes=_WHEEL_BYTES
        )

    late_prov = {k: v for k, v in prov_env.items() if k not in {"$schema", "integrity"}}
    late_prov["built_at_utc"] = "2026-11-12T12:02:00Z"
    with pytest.raises(ClosedValidationError):
        verify_negative_security_report_against_profile(
            report, sandbox_profile=sbx_env, wheel_provenance_payload=late_prov, wheel_bytes=_WHEEL_BYTES
        )

    corrupted_rep = dataclasses.replace(report)
    object.__setattr__(corrupted_rep, "declared_resource_limits", 123)
    with pytest.raises(ClosedValidationError):
        verify_negative_security_report_against_profile(
            corrupted_rep, sandbox_profile=sbx_env, wheel_provenance_payload=prov_env, wheel_bytes=_WHEEL_BYTES
        )


def test_contracts_package_reexports_all_task1_symbols() -> None:
    expected = (
        "GitArtifactProvenance",
        "MANDATORY_7A_NEGATIVE_CASES",
        "NegativeSecurityCase",
        "NegativeSecurityRun",
        "NegativeSecurityTestReport",
        "PINNED_7A_NEGATIVE_SUITE_DIGEST",
        "SANDBOX_PROFILE_ID",
        "SANDBOX_RESOURCES_VERSION",
        "SandboxResourceLimits",
        "SandboxRuntimeReadback",
        "SandboxTermination",
        "SandboxUsageCounters",
        "compute_git_blob_oid",
        "compute_negative_run_execution_binding_digest",
        "evaluate_breach_predicates",
        "sort_git_provenance_locators",
        "verify_git_provenance_against_bytes",
        "verify_negative_security_report_against_profile",
    )
    for symbol in expected:
        assert symbol in contracts_pkg.__all__
        assert hasattr(contracts_pkg, symbol)
    assert contracts_pkg.__all__ == sorted(
        contracts_pkg.__all__, key=lambda s: s.encode("utf-8")
    )
