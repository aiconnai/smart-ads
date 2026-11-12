"""Tests for tools.governance.gov1_sandbox — 7A sealed sandbox, seccomp, and local candidates."""
from __future__ import annotations

import ast
import copy
import hashlib
from pathlib import Path
import re
import subprocess
from typing import Any

import pytest

from tools.governance import decomposition_admission, p1
import tools.governance.gov1_sandbox as gov1_sandbox
from tools.governance.jcs import canonicalize, loads_strict
from tools.governance.locator import Store, json_digest, make_locator, validate_locator

REPO_ROOT = Path(__file__).resolve().parents[2]
ADR_PATH = REPO_ROOT / "docs" / "adr" / "ADR-0001-smart-ads-read-gateway.md"
EXPECTED_ADR_SHA256 = (
    "sha256:239b53e0af44c176b78c363dc271c9fd882910bd4ab2ffb6844cb8fb2458640e"
)

OCI_IMAGE_DIGEST = "sha256:" + "1" * 64
RUNNER_BINARY_DIGEST = "sha256:" + "2" * 64
ISSUED_AT_UTC = "2026-11-12T12:00:00Z"
VALID_FROM_UTC = "2026-11-01T00:00:00Z"
VALID_UNTIL_UTC = "2027-11-01T00:00:00Z"

RUN_CONTEXT_LOCATOR = make_locator(
    "smart_ads/migration_run_context/v1", b'{"run":"ctx"}'
)
REGISTRY_LOCATOR = make_locator(
    "smart_ads/key_authorization_registry/v1", b'{"reg":"snap"}'
)
SIGNER_KEY_ID = "key:ed25519:" + "a" * 64

EXPECTED_26_SYSCALLS = (
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


@pytest.fixture()
def keypair(tmp_path: Path) -> tuple[Path, bytes]:
    priv = tmp_path / "sandbox_owner.pem"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(priv)],
        check=True,
        capture_output=True,
    )
    raw32 = p1.raw_public_key_from_pem(priv)
    return priv, raw32


def _extract_adr_literal_sandbox_lines() -> str:
    lines = ADR_PATH.read_text(encoding="utf-8").splitlines()
    # ADR-0001 §3.2 L85-132 (1-indexed inclusive -> slice [84:132])
    block = "\n".join(lines[84:132])
    assert block.startswith("{") and block.endswith("}")
    return block


def test_constants_and_adr_syscalls_exact_match() -> None:
    assert gov1_sandbox.SANDBOX_PROFILE_SCHEMA == "smart_ads/sealed_sandbox_profile/v1"
    assert (
        gov1_sandbox.SANDBOX_PROFILE_ID
        == "smart_ads_7a_hermetic_linux_amd64_oci_v1"
    )
    assert gov1_sandbox.SANDBOX_RESOURCES_VERSION == "smart_ads_7a_resources_v1"
    assert gov1_sandbox.LOCAL_CANDIDATE_KIND == "gov1_local_candidate"
    assert gov1_sandbox.LOCAL_CANDIDATE_REF_KIND == "gov1_local_candidate_ref"
    assert gov1_sandbox.MANDATORY_DENIED_SYSCALLS == EXPECTED_26_SYSCALLS
    assert len(gov1_sandbox.MANDATORY_DENIED_SYSCALLS) == 26
    assert list(gov1_sandbox.MANDATORY_DENIED_SYSCALLS) == sorted(
        gov1_sandbox.MANDATORY_DENIED_SYSCALLS, key=lambda s: s.encode("utf-8")
    )

    # Cross-check directly against ADR-0001 §3.2 L139-142 prose list
    adr_lines = ADR_PATH.read_text(encoding="utf-8").splitlines()
    prose = "\n".join(adr_lines[138:142])
    extracted = tuple(
        sorted(re.findall(r"`([a-z0-9_]+)`", prose), key=lambda s: s.encode("utf-8"))
    )
    assert extracted == gov1_sandbox.MANDATORY_DENIED_SYSCALLS


def test_no_ast_assert_in_gov1_sandbox_and_global_invariants() -> None:
    mod_path = REPO_ROOT / "tools" / "governance" / "gov1_sandbox.py"
    tree = ast.parse(mod_path.read_text(encoding="utf-8"), filename=str(mod_path))
    assert_nodes = [n for n in ast.walk(tree) if isinstance(n, ast.Assert)]
    assert assert_nodes == []

    adr_digest = "sha256:" + hashlib.sha256(ADR_PATH.read_bytes()).hexdigest()
    assert adr_digest == EXPECTED_ADR_SHA256
    assert len(p1.DOMAIN_PREFIXES) == 7


def test_adr_literal_18_field_block_passes_verify_sandbox_profile_spec() -> None:
    raw_block = _extract_adr_literal_sandbox_lines()
    unreplaced = loads_strict(raw_block)
    assert len(unreplaced) == 18
    with pytest.raises(ValueError):
        gov1_sandbox.verify_sandbox_profile_spec(unreplaced)

    seccomp = gov1_sandbox.build_default_7a_seccomp_profile()
    seccomp_digest = gov1_sandbox.verify_seccomp_profile(seccomp)

    concrete = copy.deepcopy(unreplaced)
    concrete["oci_image_digest"] = OCI_IMAGE_DIGEST
    concrete["runner_binary_digest"] = RUNNER_BINARY_DIGEST
    concrete["seccomp_profile_digest"] = seccomp_digest

    gov1_sandbox.verify_sandbox_profile_spec(concrete)
    gov1_sandbox.verify_sandbox_profile_spec(concrete, seccomp_profile=seccomp)

    built_spec, _ = _valid_spec_and_seccomp()
    assert canonicalize(concrete) == canonicalize(built_spec)

    mismatched_spec = copy.deepcopy(concrete)
    mismatched_spec["seccomp_profile_digest"] = "sha256:" + "f" * 64
    with pytest.raises(ValueError):
        gov1_sandbox.verify_sandbox_profile_spec(
            mismatched_spec, seccomp_profile=seccomp
        )


def test_default_seccomp_profile_is_allowlist_and_blocks_all_26_syscalls() -> None:
    seccomp = gov1_sandbox.build_default_7a_seccomp_profile()
    assert seccomp["defaultAction"] == "SCMP_ACT_ERRNO"
    assert seccomp["architectures"] == ["SCMP_ARCH_X86_64"]
    assert isinstance(seccomp["syscalls"], list) and len(seccomp["syscalls"]) >= 1

    digest_val = gov1_sandbox.verify_seccomp_profile(seccomp)
    assert digest_val == json_digest(seccomp)

    non_denying_names: set[str] = set()
    for rule in seccomp["syscalls"]:
        if rule["action"] not in {
            "SCMP_ACT_ERRNO",
            "SCMP_ACT_KILL",
            "SCMP_ACT_KILL_PROCESS",
            "SCMP_ACT_KILL_THREAD",
        }:
            non_denying_names.update(rule["names"])
    for denied in gov1_sandbox.MANDATORY_DENIED_SYSCALLS:
        assert denied not in non_denying_names

    # Explicit kill/errno rules naming mandatory denied syscalls remain valid
    explicit_deny = copy.deepcopy(seccomp)
    explicit_deny["syscalls"].append(
        {"names": list(gov1_sandbox.MANDATORY_DENIED_SYSCALLS), "action": "SCMP_ACT_KILL_PROCESS"}
    )
    assert gov1_sandbox.verify_seccomp_profile(explicit_deny) == json_digest(explicit_deny)


@pytest.mark.parametrize("syscall_name", EXPECTED_26_SYSCALLS)
@pytest.mark.parametrize(
    "permissive_action",
    [
        "SCMP_ACT_ALLOW",
        "SCMP_ACT_LOG",
        "SCMP_ACT_TRACE",
        "SCMP_ACT_NOTIFY",
        "SCMP_ACT_TRAP",
    ],
)
def test_seccomp_rejects_every_mandatory_denied_syscall_under_non_denying_action(
    syscall_name: str, permissive_action: str
) -> None:
    seccomp = gov1_sandbox.build_default_7a_seccomp_profile()
    seccomp["syscalls"].append({"names": [syscall_name], "action": permissive_action})
    with pytest.raises(ValueError):
        gov1_sandbox.verify_seccomp_profile(seccomp)

    envelope = gov1_sandbox.build_sealed_sandbox_profile_envelope(
        migration_run_context_locator=RUN_CONTEXT_LOCATOR,
        oci_image_digest=OCI_IMAGE_DIGEST,
        runner_binary_digest=RUNNER_BINARY_DIGEST,
        seccomp_profile=gov1_sandbox.build_default_7a_seccomp_profile(),
        issued_at_utc=ISSUED_AT_UTC,
        valid_from_utc=VALID_FROM_UTC,
        valid_until_utc=VALID_UNTIL_UTC,
        registry_locator=REGISTRY_LOCATOR,
        signer_key_id=SIGNER_KEY_ID,
    )
    envelope["seccomp_profile_digest"] = json_digest(seccomp)
    with pytest.raises(ValueError):
        gov1_sandbox.verify_sealed_sandbox_profile(envelope, seccomp_profile=seccomp)


@pytest.mark.parametrize(
    "mutator",
    [
        lambda s: s.__setitem__("defaultAction", "SCMP_ACT_ALLOW"),
        lambda s: s.__setitem__("defaultAction", "SCMP_ACT_LOG"),
        lambda s: s.__setitem__("architectures", ["SCMP_ARCH_AARCH64"]),
        lambda s: s.__setitem__("architectures", ["SCMP_ARCH_X86_64", "SCMP_ARCH_X86"]),
        lambda s: s.__setitem__("architectures", []),
        lambda s: s.__setitem__("extra", 1),
        lambda s: s.pop("syscalls"),
        lambda s: s["syscalls"].append({"names": [], "action": "SCMP_ACT_ALLOW"}),
        lambda s: s["syscalls"].append({"names": [""], "action": "SCMP_ACT_ALLOW"}),
        lambda s: s["syscalls"].append({"names": ["read"], "action": "SCMP_ACT_UNKNOWN"}),
        lambda s: s["syscalls"].append(
            {"names": ["read"], "action": "SCMP_ACT_ALLOW", "extra": True}
        ),
        lambda s: s["syscalls"].append(
            {"names": ["read"], "action": "SCMP_ACT_ALLOW", "args": "not-a-list"}
        ),
        lambda s: s["syscalls"].append(
            {"names": ["read"], "action": "SCMP_ACT_ALLOW", "args": ["not-a-dict"]}
        ),
    ],
)
def test_seccomp_rejects_malformed_structures(mutator: Any) -> None:
    seccomp = gov1_sandbox.build_default_7a_seccomp_profile()
    mutator(seccomp)
    with pytest.raises(ValueError):
        gov1_sandbox.verify_seccomp_profile(seccomp)


def test_build_default_seccomp_rejects_denied_or_empty_allowed_syscalls() -> None:
    with pytest.raises(ValueError):
        gov1_sandbox.build_default_7a_seccomp_profile(allowed_syscalls=["read", "socket"])
    with pytest.raises(ValueError):
        gov1_sandbox.build_default_7a_seccomp_profile(allowed_syscalls=[])


def _valid_spec_and_seccomp() -> tuple[dict[str, Any], dict[str, Any]]:
    seccomp = gov1_sandbox.build_default_7a_seccomp_profile()
    envelope = gov1_sandbox.build_sealed_sandbox_profile_envelope(
        migration_run_context_locator=RUN_CONTEXT_LOCATOR,
        oci_image_digest=OCI_IMAGE_DIGEST,
        runner_binary_digest=RUNNER_BINARY_DIGEST,
        seccomp_profile=seccomp,
        issued_at_utc=ISSUED_AT_UTC,
        valid_from_utc=VALID_FROM_UTC,
        valid_until_utc=VALID_UNTIL_UTC,
        registry_locator=REGISTRY_LOCATOR,
        signer_key_id=SIGNER_KEY_ID,
    )
    spec = {
        k: copy.deepcopy(v)
        for k, v in envelope.items()
        if k not in {"migration_run_context_locator", "issued_at_utc", "validity", "integrity"}
    }
    return spec, seccomp


@pytest.mark.parametrize(
    "mutator",
    [
        lambda sp: sp.__setitem__("$schema", "smart_ads/sealed_sandbox_profile/v2"),
        lambda sp: sp.__setitem__("profile_id", "fallback_profile"),
        lambda sp: sp.__setitem__("runtime_kind", "docker"),
        lambda sp: sp.__setitem__("platform", "linux/arm64"),
        lambda sp: sp.__setitem__("rootfs_read_only", False),
        lambda sp: sp.__setitem__("rootfs_read_only", 1),
        lambda sp: sp.__setitem__("oci_image_digest", "sha256:" + "A" * 64),
        lambda sp: sp.__setitem__("runner_binary_digest", "sha256:1234"),
        lambda sp: sp["exact_environment"].__setitem__("HOME", "/root"),
        lambda sp: sp["exact_environment"].__setitem__("EXTRA", "1"),
        lambda sp: sp["exact_environment"].pop("PYTHONSAFEPATH"),
        lambda sp: sp["namespaces"].remove("network"),
        lambda sp: sp.__setitem__(
            "namespaces", ["network", "mount", "pid", "ipc", "uts", "user"]
        ),
        lambda sp: sp["read_only_mounts"].append("/etc"),
        lambda sp: sp.__setitem__("fresh_tmpfs_mounts", ["/var/tmp"]),
        lambda sp: sp["masked_empty_mounts"].remove("/proc"),
        lambda sp: sp.__setitem__("host_bind_mounts_forbidden", False),
        lambda sp: sp.__setitem__("all_capabilities_dropped", 1),
        lambda sp: sp.__setitem__("no_new_privs", False),
        lambda sp: sp.__setitem__("inherited_fds_above_2_closed", False),
        lambda sp: sp["resource_limits"].__setitem__("profile_version", "v2"),
        lambda sp: sp["resource_limits"].__setitem__("cgroup_version", 1),
        lambda sp: sp["resource_limits"].__setitem__("cgroup_version", True),
        lambda sp: sp["resource_limits"]["cpu_max"].__setitem__("quota_us", 200000),
        lambda sp: sp["resource_limits"]["cpu_max"].__setitem__("period_us", True),
        lambda sp: sp["resource_limits"].__setitem__("cpu_time_limit_seconds", 121),
        lambda sp: sp["resource_limits"].__setitem__("memory_max_bytes", 2147483648),
        lambda sp: sp["resource_limits"].__setitem__("memory_swap_max_bytes", 1),
        lambda sp: sp["resource_limits"].__setitem__("memory_swap_max_bytes", False),
        lambda sp: sp["resource_limits"].__setitem__("pids_max", True),
        lambda sp: sp["resource_limits"]["tmpfs_limits"]["/tmp"].__setitem__(
            "mount_flags", ["nodev", "nosuid"]
        ),
        lambda sp: sp["resource_limits"]["tmpfs_limits"]["/tmp"].__setitem__(
            "mount_flags", ["noexec", "nodev", "nosuid"]
        ),
        lambda sp: sp["resource_limits"]["tmpfs_limits"]["/tmp"].__setitem__(
            "size_bytes", False
        ),
        lambda sp: sp["resource_limits"]["tmpfs_limits"]["/tmp"].__setitem__(
            "inodes_max", 8192
        ),
        lambda sp: sp["resource_limits"].__setitem__("rlimit_fsize_bytes", 0),
        lambda sp: sp["resource_limits"].__setitem__("stdout_max_bytes", 0),
        lambda sp: sp["resource_limits"].__setitem__("stderr_max_bytes", 0),
        lambda sp: sp["resource_limits"].__setitem__("wall_clock_timeout_seconds", 301),
        lambda sp: sp["resource_limits"].__setitem__("termination_grace_ms", True),
        lambda sp: sp.__setitem__("extra_field", "forbidden"),
    ],
)
def test_verify_sandbox_profile_spec_negative_mutations(mutator: Any) -> None:
    spec, seccomp = _valid_spec_and_seccomp()
    mutator(spec)
    with pytest.raises(ValueError):
        gov1_sandbox.verify_sandbox_profile_spec(spec, seccomp_profile=seccomp)


def test_verify_sealed_sandbox_profile_requires_seccomp_and_matching_digest() -> None:
    seccomp = gov1_sandbox.build_default_7a_seccomp_profile()
    envelope = gov1_sandbox.build_sealed_sandbox_profile_envelope(
        migration_run_context_locator=RUN_CONTEXT_LOCATOR,
        oci_image_digest=OCI_IMAGE_DIGEST,
        runner_binary_digest=RUNNER_BINARY_DIGEST,
        seccomp_profile=seccomp,
        issued_at_utc=ISSUED_AT_UTC,
        valid_from_utc=VALID_FROM_UTC,
        valid_until_utc=VALID_UNTIL_UTC,
        registry_locator=REGISTRY_LOCATOR,
        signer_key_id=SIGNER_KEY_ID,
    )

    with pytest.raises(TypeError):
        gov1_sandbox.verify_sealed_sandbox_profile(envelope)  # type: ignore[call-arg]

    with pytest.raises(ValueError):
        gov1_sandbox.verify_sealed_sandbox_profile(
            envelope, seccomp_profile=None  # type: ignore[arg-type]
        )

    other_seccomp = gov1_sandbox.build_default_7a_seccomp_profile(
        allowed_syscalls=["exit_group", "read", "write"]
    )
    with pytest.raises(ValueError):
        gov1_sandbox.verify_sealed_sandbox_profile(
            envelope, seccomp_profile=other_seccomp
        )


@pytest.mark.parametrize(
    ("issued", "v_from", "v_until"),
    [
        ("2026-11-12T12:00:00Z", "2026-11-12T12:00:00Z", "2026-11-12T12:00:00Z"),
        ("2026-11-12T12:00:00Z", "2026-11-13T00:00:00Z", "2026-11-12T00:00:00Z"),
        ("2026-10-31T23:59:59Z", "2026-11-01T00:00:00Z", "2027-11-01T00:00:00Z"),
        ("2027-11-01T00:00:00Z", "2026-11-01T00:00:00Z", "2027-11-01T00:00:00Z"),
        ("2027-11-02T00:00:00Z", "2026-11-01T00:00:00Z", "2027-11-01T00:00:00Z"),
        ("2026-11-12T12:00:00.000000Z", "2026-11-01T00:00:00Z", "2027-11-01T00:00:00Z"),
    ],
)
def test_validity_interval_rejections(issued: str, v_from: str, v_until: str) -> None:
    seccomp = gov1_sandbox.build_default_7a_seccomp_profile()
    with pytest.raises(ValueError):
        gov1_sandbox.build_sealed_sandbox_profile_envelope(
            migration_run_context_locator=RUN_CONTEXT_LOCATOR,
            oci_image_digest=OCI_IMAGE_DIGEST,
            runner_binary_digest=RUNNER_BINARY_DIGEST,
            seccomp_profile=seccomp,
            issued_at_utc=issued,
            valid_from_utc=v_from,
            valid_until_utc=v_until,
            registry_locator=REGISTRY_LOCATOR,
            signer_key_id=SIGNER_KEY_ID,
        )
    with pytest.raises(ValueError):
        gov1_sandbox.build_sealed_sandbox_profile_candidate(
            migration_run_context_locator=RUN_CONTEXT_LOCATOR,
            oci_image_digest=OCI_IMAGE_DIGEST,
            runner_binary_digest=RUNNER_BINARY_DIGEST,
            seccomp_profile=seccomp,
            issued_at_utc=issued,
            valid_from_utc=v_from,
            valid_until_utc=v_until,
        )


def test_p1_envelope_sign_store_and_verify_roundtrip(
    tmp_path: Path, keypair: tuple[Path, bytes]
) -> None:
    priv, raw32 = keypair
    key_id = p1.key_id_for(raw32)
    seccomp = gov1_sandbox.build_default_7a_seccomp_profile()

    unsigned = gov1_sandbox.build_sealed_sandbox_profile_envelope(
        migration_run_context_locator=RUN_CONTEXT_LOCATOR,
        oci_image_digest=OCI_IMAGE_DIGEST,
        runner_binary_digest=RUNNER_BINARY_DIGEST,
        seccomp_profile=seccomp,
        issued_at_utc=ISSUED_AT_UTC,
        valid_from_utc=VALID_FROM_UTC,
        valid_until_utc=VALID_UNTIL_UTC,
        registry_locator=REGISTRY_LOCATOR,
        signer_key_id=key_id,
    )
    unsigned_summary = gov1_sandbox.verify_sealed_sandbox_profile(
        unsigned, seccomp_profile=seccomp
    )
    assert unsigned_summary["mode"] == "envelope"
    assert unsigned_summary["schema"] == gov1_sandbox.SANDBOX_PROFILE_SCHEMA
    assert unsigned_summary["profile_id"] == gov1_sandbox.SANDBOX_PROFILE_ID
    assert unsigned_summary["seccomp_profile_digest"] == json_digest(seccomp)

    profiles = {
        row["schema"]: row
        for row in decomposition_admission.profile_proposals(ADR_PATH.read_bytes())
    }
    domain_prefix = profiles[gov1_sandbox.SANDBOX_PROFILE_SCHEMA]["domain_prefix"]
    assert domain_prefix == "SMART-ADS:SANDBOX:V1\n"

    signed = p1.sign_envelope(unsigned, domain_prefix, priv)
    p1.verify_envelope(signed, domain_prefix, raw32)

    store = Store(tmp_path / "store")
    loc = store.put(signed)
    loaded = store.get(loc, gov1_sandbox.SANDBOX_PROFILE_SCHEMA)
    signed_summary = gov1_sandbox.verify_sealed_sandbox_profile(
        loaded, seccomp_profile=seccomp
    )
    assert signed_summary["mode"] == "envelope"
    assert signed_summary["payload"] == unsigned_summary["payload"]

    # Tampered content_digest on signed envelope must fail verify_sealed_sandbox_profile
    bad_digest_env = copy.deepcopy(signed)
    bad_digest_env["integrity"]["content_digest"] = "sha256:" + "0" * 64
    with pytest.raises(ValueError):
        gov1_sandbox.verify_sealed_sandbox_profile(
            bad_digest_env, seccomp_profile=seccomp
        )


def test_local_candidate_and_ref_non_interchangeability_with_p1_and_locator(
    tmp_path: Path,
) -> None:
    seccomp = gov1_sandbox.build_default_7a_seccomp_profile()
    candidate = gov1_sandbox.build_sealed_sandbox_profile_candidate(
        migration_run_context_locator=RUN_CONTEXT_LOCATOR,
        oci_image_digest=OCI_IMAGE_DIGEST,
        runner_binary_digest=RUNNER_BINARY_DIGEST,
        seccomp_profile=seccomp,
        issued_at_utc=ISSUED_AT_UTC,
        valid_from_utc=VALID_FROM_UTC,
        valid_until_utc=VALID_UNTIL_UTC,
    )
    assert candidate["artifact_kind"] == "gov1_local_candidate"
    assert candidate["target_schema"] == gov1_sandbox.SANDBOX_PROFILE_SCHEMA
    assert candidate["signable"] is False
    assert candidate["authority"] == "none"
    assert "$schema" not in candidate["payload"]
    assert "integrity" not in candidate["payload"]

    cand_summary = gov1_sandbox.verify_sealed_sandbox_profile(
        candidate, seccomp_profile=seccomp
    )
    assert cand_summary["mode"] == "candidate"
    assert cand_summary["payload"] == candidate["payload"]

    ref = gov1_sandbox.build_local_candidate_ref(candidate)
    assert ref == {
        "ref_kind": "gov1_local_candidate_ref",
        "target_schema": gov1_sandbox.SANDBOX_PROFILE_SCHEMA,
        "candidate_digest": json_digest(candidate),
        "payload_digest": json_digest(candidate["payload"]),
        "authority": "none",
    }
    gov1_sandbox.verify_local_candidate_ref(
        ref,
        expected_schema=gov1_sandbox.SANDBOX_PROFILE_SCHEMA,
        expected_candidate=candidate,
    )

    store = Store(tmp_path / "store")
    for non_authoritative_obj in (candidate, candidate["payload"], ref):
        with pytest.raises(ValueError):
            p1.preimage(non_authoritative_obj)
        with pytest.raises(ValueError):
            validate_locator(non_authoritative_obj)
        with pytest.raises(ValueError):
            store.put(non_authoritative_obj)

    # Reverse non-interchangeability: artifact_locator/v1 rejected as candidate or candidate_ref
    real_locator = make_locator(gov1_sandbox.SANDBOX_PROFILE_SCHEMA, b'{"x":1}')
    with pytest.raises(ValueError):
        gov1_sandbox.verify_local_candidate_ref(
            real_locator, expected_schema=gov1_sandbox.SANDBOX_PROFILE_SCHEMA
        )
    with pytest.raises(ValueError):
        gov1_sandbox.unwrap_local_candidate(
            real_locator, expected_schema=gov1_sandbox.SANDBOX_PROFILE_SCHEMA
        )

    # Payload smuggling ($schema / integrity) and signable=0 (int instead of bool) rejected
    with pytest.raises(ValueError):
        gov1_sandbox.wrap_local_candidate(
            gov1_sandbox.SANDBOX_PROFILE_SCHEMA,
            {"$schema": gov1_sandbox.SANDBOX_PROFILE_SCHEMA},
        )
    with pytest.raises(ValueError):
        gov1_sandbox.wrap_local_candidate(
            gov1_sandbox.SANDBOX_PROFILE_SCHEMA,
            {"integrity": {"key_id": SIGNER_KEY_ID}},
        )
    tampered_candidate = copy.deepcopy(candidate)
    tampered_candidate["signable"] = 0
    with pytest.raises(ValueError):
        gov1_sandbox.unwrap_local_candidate(
            tampered_candidate, expected_schema=gov1_sandbox.SANDBOX_PROFILE_SCHEMA
        )


def test_defensive_copy_isolation() -> None:
    seccomp = gov1_sandbox.build_default_7a_seccomp_profile()
    run_loc = copy.deepcopy(RUN_CONTEXT_LOCATOR)
    reg_loc = copy.deepcopy(REGISTRY_LOCATOR)
    envelope = gov1_sandbox.build_sealed_sandbox_profile_envelope(
        migration_run_context_locator=run_loc,
        oci_image_digest=OCI_IMAGE_DIGEST,
        runner_binary_digest=RUNNER_BINARY_DIGEST,
        seccomp_profile=seccomp,
        issued_at_utc=ISSUED_AT_UTC,
        valid_from_utc=VALID_FROM_UTC,
        valid_until_utc=VALID_UNTIL_UTC,
        registry_locator=reg_loc,
        signer_key_id=SIGNER_KEY_ID,
    )
    run_loc["store_kind"] = "mutated"
    reg_loc["store_kind"] = "mutated"
    assert envelope["migration_run_context_locator"]["store_kind"] == "cell_immutable_object"
    assert (
        envelope["integrity"]["key_registry_snapshot_locator"]["store_kind"]
        == "cell_immutable_object"
    )


def test_probe_7a_host_eligibility() -> None:
    # Eligible only on Linux x86_64/amd64 inside sealed OCI supervisor with cgroup v2
    for arch in ("x86_64", "amd64", "AMD64"):
        res = gov1_sandbox.probe_7a_host_eligibility(
            sys_platform="linux",
            machine=arch,
            in_sealed_oci_supervisor=True,
            cgroup_v2_available=True,
        )
        assert res == {
            "status": "ELIGIBLE",
            "eligible": True,
            "profile_id": gov1_sandbox.SANDBOX_PROFILE_ID,
            "sys_platform": "linux",
            "machine": arch,
            "in_sealed_oci_supervisor": True,
            "cgroup_v2_available": True,
            "reasons": [],
        }

    # Blocked combinations
    macos_res = gov1_sandbox.probe_7a_host_eligibility(
        sys_platform="darwin",
        machine="arm64",
        in_sealed_oci_supervisor=False,
        cgroup_v2_available=False,
    )
    assert macos_res["status"] == "BLOCKED"
    assert macos_res["eligible"] is False
    assert macos_res["reasons"] == [
        "unsupported_sys_platform",
        "unsupported_machine",
        "not_in_sealed_oci_supervisor",
        "cgroup_v2_unavailable",
    ]

    linux_unsealed = gov1_sandbox.probe_7a_host_eligibility(
        sys_platform="linux",
        machine="x86_64",
        in_sealed_oci_supervisor=False,
        cgroup_v2_available=True,
    )
    assert linux_unsealed["status"] == "BLOCKED"
    assert linux_unsealed["eligible"] is False
    assert linux_unsealed["reasons"] == ["not_in_sealed_oci_supervisor"]

    linux_no_cg2 = gov1_sandbox.probe_7a_host_eligibility(
        sys_platform="linux",
        machine="x86_64",
        in_sealed_oci_supervisor=True,
        cgroup_v2_available=False,
    )
    assert linux_no_cg2["status"] == "BLOCKED"
    assert linux_no_cg2["eligible"] is False
    assert linux_no_cg2["reasons"] == ["cgroup_v2_unavailable"]

    # Rejects int in place of bool
    with pytest.raises(ValueError):
        gov1_sandbox.probe_7a_host_eligibility(
            sys_platform="linux",
            machine="x86_64",
            in_sealed_oci_supervisor=1,  # type: ignore[arg-type]
            cgroup_v2_available=True,
        )
    with pytest.raises(ValueError):
        gov1_sandbox.probe_7a_host_eligibility(
            sys_platform="linux",
            machine="x86_64",
            in_sealed_oci_supervisor=True,
            cgroup_v2_available=0,  # type: ignore[arg-type]
        )


def test_tampered_envelope_and_candidate_ref_edges() -> None:
    seccomp = gov1_sandbox.build_default_7a_seccomp_profile()
    # Allowed rule with conditional args on allowed syscall passes; on denied syscall fails
    seccomp_with_args = copy.deepcopy(seccomp)
    seccomp_with_args["syscalls"].append(
        {
            "names": ["ioctl"],
            "action": "SCMP_ACT_ALLOW",
            "args": [{"index": 1, "value": 21505, "op": "SCMP_CMP_EQ"}],
        }
    )
    assert gov1_sandbox.verify_seccomp_profile(seccomp_with_args) == json_digest(
        seccomp_with_args
    )
    seccomp_conditional_clone = copy.deepcopy(seccomp)
    seccomp_conditional_clone["syscalls"].append(
        {
            "names": ["clone"],
            "action": "SCMP_ACT_ALLOW",
            "args": [{"index": 0, "value": 0, "op": "SCMP_CMP_EQ"}],
        }
    )
    with pytest.raises(ValueError):
        gov1_sandbox.verify_seccomp_profile(seccomp_conditional_clone)

    envelope = gov1_sandbox.build_sealed_sandbox_profile_envelope(
        migration_run_context_locator=RUN_CONTEXT_LOCATOR,
        oci_image_digest=OCI_IMAGE_DIGEST,
        runner_binary_digest=RUNNER_BINARY_DIGEST,
        seccomp_profile=seccomp,
        issued_at_utc=ISSUED_AT_UTC,
        valid_from_utc=VALID_FROM_UTC,
        valid_until_utc=VALID_UNTIL_UTC,
        registry_locator=REGISTRY_LOCATOR,
        signer_key_id=SIGNER_KEY_ID,
    )
    inverted = copy.deepcopy(envelope)
    inverted["validity"] = {
        "from": "2027-11-01T00:00:00Z",
        "until": "2026-11-01T00:00:00Z",
    }
    with pytest.raises(ValueError):
        gov1_sandbox.verify_sealed_sandbox_profile(inverted, seccomp_profile=seccomp)

    candidate = gov1_sandbox.build_sealed_sandbox_profile_candidate(
        migration_run_context_locator=RUN_CONTEXT_LOCATOR,
        oci_image_digest=OCI_IMAGE_DIGEST,
        runner_binary_digest=RUNNER_BINARY_DIGEST,
        seccomp_profile=seccomp,
        issued_at_utc=ISSUED_AT_UTC,
        valid_from_utc=VALID_FROM_UTC,
        valid_until_utc=VALID_UNTIL_UTC,
    )
    hybrid = copy.deepcopy(candidate)
    hybrid["$schema"] = gov1_sandbox.SANDBOX_PROFILE_SCHEMA
    with pytest.raises(ValueError):
        gov1_sandbox.verify_sealed_sandbox_profile(hybrid, seccomp_profile=seccomp)

    ref = gov1_sandbox.build_local_candidate_ref(candidate)
    other_candidate = gov1_sandbox.build_sealed_sandbox_profile_candidate(
        migration_run_context_locator=RUN_CONTEXT_LOCATOR,
        oci_image_digest="sha256:" + "9" * 64,
        runner_binary_digest=RUNNER_BINARY_DIGEST,
        seccomp_profile=seccomp,
        issued_at_utc=ISSUED_AT_UTC,
        valid_from_utc=VALID_FROM_UTC,
        valid_until_utc=VALID_UNTIL_UTC,
    )
    with pytest.raises(ValueError):
        gov1_sandbox.verify_local_candidate_ref(
            ref,
            expected_schema=gov1_sandbox.SANDBOX_PROFILE_SCHEMA,
            expected_candidate=other_candidate,
        )
    with pytest.raises(ValueError):
        gov1_sandbox.verify_local_candidate_ref(
            ref,
            expected_schema="smart_ads/wheel_boundary_report/v1",
        )

