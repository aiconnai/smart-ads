"""Tests for tools.governance.gov1_mcp — executable zero-I/O MCP rejection matrix report."""
from __future__ import annotations

import ast
import base64
import copy
import csv
import hashlib
import io
from pathlib import Path
import re
import subprocess
from typing import Any
import zipfile

import pytest

from smart_ads.contracts.schemas import compute_schema_bundle_digest
from smart_ads.transports.mcp import ALLOWED_MCP_METHODS
from tools.governance import decomposition_admission, p1
import tools.governance.gov1_mcp as gov1_mcp
import tools.governance.gov1_sandbox as gov1_sandbox
import tools.governance.gov1_wheel as gov1_wheel
from tools.governance.jcs import canonicalize
from tools.governance.locator import Store, digest, json_digest, make_locator

REPO_ROOT = Path(__file__).resolve().parents[2]
ADR_PATH = REPO_ROOT / "docs" / "adr" / "ADR-0001-smart-ads-read-gateway.md"
EXPECTED_ADR_SHA256 = (
    "sha256:239b53e0af44c176b78c363dc271c9fd882910bd4ab2ffb6844cb8fb2458640e"
)

RUN_CONTEXT_LOCATOR = make_locator(
    "smart_ads/migration_run_context/v1", b'{"run":"gov1-task5"}'
)
REGISTRY_LOCATOR = make_locator(
    "smart_ads/key_authorization_registry/v1", b'{"reg":"gov1-task5"}'
)
OCI_IMAGE_DIGEST = "sha256:" + ("1" * 64)
RUNNER_BINARY_DIGEST = "sha256:" + ("2" * 64)
ISSUED_AT_UTC = "2026-11-12T12:00:00Z"
VALID_FROM_UTC = "2026-11-01T00:00:00Z"
VALID_UNTIL_UTC = "2027-11-01T00:00:00Z"
EXECUTED_AT_UTC = "2026-11-12T12:10:00Z"
BUILD_RUN_ID = "build-run-gov1-005"

EXPECTED_11_SPECS: tuple[dict[str, Any], ...] = (
    {
        "case_id": "additional_property",
        "expected_code": -32602,
        "expected_message": "Invalid params",
        "expected_id_policy": "validated_request_id",
    },
    {
        "case_id": "batch_array",
        "expected_code": -32600,
        "expected_message": "Invalid Request",
        "expected_id_policy": "null",
    },
    {
        "case_id": "body_over_64k",
        "expected_code": -32600,
        "expected_message": "Invalid Request",
        "expected_id_policy": "null",
    },
    {
        "case_id": "duplicate_json_key",
        "expected_code": -32600,
        "expected_message": "Invalid Request",
        "expected_id_policy": "null",
    },
    {
        "case_id": "invalid_params",
        "expected_code": -32602,
        "expected_message": "Invalid params",
        "expected_id_policy": "validated_request_id",
    },
    {
        "case_id": "invalid_utf8",
        "expected_code": -32700,
        "expected_message": "Parse error",
        "expected_id_policy": "null",
    },
    {
        "case_id": "malformed_json",
        "expected_code": -32700,
        "expected_message": "Parse error",
        "expected_id_policy": "null",
    },
    {
        "case_id": "missing_or_invalid_ibvi_ads_delegation",
        "expected_code": -32600,
        "expected_message": "Invalid Request",
        "expected_id_policy": "validated_request_id",
    },
    {
        "case_id": "nesting_depth_over_8",
        "expected_code": -32600,
        "expected_message": "Invalid Request",
        "expected_id_policy": "null",
    },
    {
        "case_id": "non_object_request",
        "expected_code": -32600,
        "expected_message": "Invalid Request",
        "expected_id_policy": "null",
    },
    {
        "case_id": "unsupported_method",
        "expected_code": -32601,
        "expected_message": "Method not found",
        "expected_id_policy": "validated_request_id",
    },
)

SIX_IO_COUNTER_KEYS: tuple[str, ...] = (
    "audit_calls",
    "credential_calls",
    "filesystem_calls",
    "network_calls",
    "provider_calls",
    "registry_calls",
)


def _record_hash_and_size(raw: bytes) -> tuple[str, str]:
    b64 = (
        base64.urlsafe_b64encode(hashlib.sha256(raw).digest())
        .rstrip(b"=")
        .decode("ascii")
    )
    return f"sha256={b64}", str(len(raw))


def _read_wheel_members(wheel_path: Path) -> dict[str, bytes]:
    with zipfile.ZipFile(wheel_path, "r") as zf:
        return {info.filename: zf.read(info) for info in zf.infolist()}


def _rebuild_wheel_from_dict(dest: Path, members: dict[str, bytes]) -> Path:
    all_members = dict(members)
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    for path in sorted(
        (p for p in all_members if p != "smart_ads-0.1.0.dist-info/RECORD"),
        key=lambda s: s.encode("utf-8"),
    ):
        rec_hash, rec_size = _record_hash_and_size(all_members[path])
        writer.writerow([path, rec_hash, rec_size])
    writer.writerow(["smart_ads-0.1.0.dist-info/RECORD", "", ""])
    all_members["smart_ads-0.1.0.dist-info/RECORD"] = buf.getvalue().encode("utf-8")

    with zipfile.ZipFile(dest, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(all_members, key=lambda s: s.encode("utf-8")):
            zi = zipfile.ZipInfo(path, date_time=(2023, 11, 14, 22, 13, 20))
            zi.external_attr = 0o100644 << 16
            zf.writestr(zi, all_members[path])
    return dest


def _recompute_candidate_digest(candidate: dict[str, Any]) -> dict[str, Any]:
    updated = copy.deepcopy(candidate)
    updated["payload_digest"] = json_digest(updated["payload"])
    return updated


@pytest.fixture(scope="module")
def baseline_mcp_bundle(
    tmp_path_factory: pytest.TempPathFactory,
) -> tuple[Path, gov1_wheel.GitBuildSnapshot, bytes, dict[str, Any]]:
    out_dir = tmp_path_factory.mktemp("gov1_mcp_wheel")
    wheel_path, snapshot = gov1_wheel.build_reproducible_wheel(REPO_ROOT, out_dir)
    wheel_bytes = wheel_path.read_bytes()
    execution = gov1_mcp.execute_mcp_rejection_matrix_on_wheel(wheel_path)
    return wheel_path, snapshot, wheel_bytes, execution


@pytest.fixture()
def keypair(tmp_path: Path) -> tuple[Path, bytes]:
    priv = tmp_path / "mcp_security_verifier.pem"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(priv)],
        check=True,
        capture_output=True,
    )
    raw32 = p1.raw_public_key_from_pem(priv)
    return priv, raw32


@pytest.fixture()
def sandbox_refs(
    tmp_path: Path, keypair: tuple[Path, bytes]
) -> tuple[dict[str, Any], dict[str, Any], Store]:
    priv, raw32 = keypair
    signer_id = p1.key_id_for(raw32)
    seccomp = gov1_sandbox.build_default_7a_seccomp_profile()

    sbx_cand = gov1_sandbox.build_sealed_sandbox_profile_candidate(
        migration_run_context_locator=RUN_CONTEXT_LOCATOR,
        oci_image_digest=OCI_IMAGE_DIGEST,
        runner_binary_digest=RUNNER_BINARY_DIGEST,
        seccomp_profile=seccomp,
        issued_at_utc=ISSUED_AT_UTC,
        valid_from_utc=VALID_FROM_UTC,
        valid_until_utc=VALID_UNTIL_UTC,
    )
    sbx_cand_ref = gov1_sandbox.build_local_candidate_ref(sbx_cand)

    profiles = {
        row["schema"]: row
        for row in decomposition_admission.profile_proposals(ADR_PATH.read_bytes())
    }
    sbx_prefix = profiles[gov1_sandbox.SANDBOX_PROFILE_SCHEMA]["domain_prefix"]
    sbx_env_unsigned = gov1_sandbox.build_sealed_sandbox_profile_envelope(
        migration_run_context_locator=RUN_CONTEXT_LOCATOR,
        oci_image_digest=OCI_IMAGE_DIGEST,
        runner_binary_digest=RUNNER_BINARY_DIGEST,
        seccomp_profile=seccomp,
        issued_at_utc=ISSUED_AT_UTC,
        valid_from_utc=VALID_FROM_UTC,
        valid_until_utc=VALID_UNTIL_UTC,
        registry_locator=REGISTRY_LOCATOR,
        signer_key_id=signer_id,
    )
    sbx_env_signed = p1.sign_envelope(sbx_env_unsigned, sbx_prefix, priv)
    store = Store(tmp_path / "store")
    sbx_locator = store.put(sbx_env_signed)
    return sbx_cand_ref, sbx_locator, store


def test_constants_adr_alignment_and_zero_ast_assert_in_gov1_mcp() -> None:
    assert (
        gov1_mcp.MCP_REJECTION_REPORT_SCHEMA
        == "smart_ads/mcp_rejection_matrix_report/v1"
    )
    assert isinstance(gov1_mcp.EXPECTED_MCP_MATRIX_SPECS, tuple)
    assert len(gov1_mcp.EXPECTED_MCP_MATRIX_SPECS) == 11
    assert gov1_mcp.EXPECTED_MCP_MATRIX_SPECS == EXPECTED_11_SPECS
    assert [s["case_id"] for s in gov1_mcp.EXPECTED_MCP_MATRIX_SPECS] == sorted(
        [s["case_id"] for s in gov1_mcp.EXPECTED_MCP_MATRIX_SPECS],
        key=lambda s: s.encode("utf-8"),
    )

    # Cross-check against ADR-0001 §3.3 L235-245 table rows
    adr_lines = ADR_PATH.read_text(encoding="utf-8").splitlines()
    parsed_adr_rows: list[dict[str, Any]] = []
    for raw_line in adr_lines[234:245]:
        m = re.fullmatch(
            r"\|\s*`([a-z0-9_]+)`\s*\|\s*`(-[0-9]+)`\s*\|\s*`([^`]+)`\s*\|\s*(.+?)\s*\|",
            raw_line,
        )
        assert m is not None, f"Failed to parse ADR row: {raw_line!r}"
        id_cell = m.group(4)
        id_policy = "null" if id_cell == "`null`" else "validated_request_id"
        parsed_adr_rows.append(
            {
                "case_id": m.group(1),
                "expected_code": int(m.group(2)),
                "expected_message": m.group(3),
                "expected_id_policy": id_policy,
            }
        )
    parsed_adr_sorted = tuple(
        sorted(parsed_adr_rows, key=lambda r: r["case_id"].encode("utf-8"))
    )
    assert parsed_adr_sorted == gov1_mcp.EXPECTED_MCP_MATRIX_SPECS

    # Verify zero ast.Assert in gov1_mcp.py AND inside embedded subprocess script
    mod_path = REPO_ROOT / "tools" / "governance" / "gov1_mcp.py"
    source = mod_path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(mod_path))
    assert [n for n in ast.walk(tree) if isinstance(n, ast.Assert)] == []

    probe_script = getattr(gov1_mcp, "_MCP_MATRIX_PROBE_SCRIPT", None)
    assert isinstance(probe_script, str) and probe_script.strip()
    probe_tree = ast.parse(probe_script, filename="gov1_mcp._MCP_MATRIX_PROBE_SCRIPT")
    assert [n for n in ast.walk(probe_tree) if isinstance(n, ast.Assert)] == []

    assert digest(ADR_PATH.read_bytes()) == EXPECTED_ADR_SHA256
    assert len(p1.DOMAIN_PREFIXES) == 7


def test_real_wheel_execution_and_candidate_and_p1_envelope_roundtrip(
    baseline_mcp_bundle: tuple[Path, gov1_wheel.GitBuildSnapshot, bytes, dict[str, Any]],
    keypair: tuple[Path, bytes],
    sandbox_refs: tuple[dict[str, Any], dict[str, Any], Store],
) -> None:
    wheel_path, snapshot, wheel_bytes, execution = baseline_mcp_bundle
    sbx_cand_ref, sbx_locator, store = sandbox_refs
    priv, raw32 = keypair
    signer_id = p1.key_id_for(raw32)
    expected_schema_digest = compute_schema_bundle_digest()

    assert set(execution.keys()) == {
        "wheel_digest",
        "schema_bundle_digest",
        "allowed_methods",
        "body_64k_boundary_verified",
        "cases",
    }
    assert execution["wheel_digest"] == digest(wheel_bytes)
    assert execution["schema_bundle_digest"] == expected_schema_digest
    assert execution["allowed_methods"] == list(ALLOWED_MCP_METHODS)
    assert execution["body_64k_boundary_verified"] is True
    assert len(execution["cases"]) == 11
    assert [c["case_id"] for c in execution["cases"]] == [
        s["case_id"] for s in EXPECTED_11_SPECS
    ]

    for case, spec in zip(execution["cases"], EXPECTED_11_SPECS, strict=True):
        assert set(case.keys()) == {
            "case_id",
            "expected_code",
            "observed_code",
            "expected_message",
            "observed_message",
            "expected_id_policy",
            "observed_id_matches_policy",
            "response_shape_valid",
            "io_counters",
        }
        assert case["case_id"] == spec["case_id"]
        assert case["expected_code"] == spec["expected_code"]
        assert case["observed_code"] == spec["expected_code"]
        assert case["expected_message"] == spec["expected_message"]
        assert case["observed_message"] == spec["expected_message"]
        assert case["expected_id_policy"] == spec["expected_id_policy"]
        assert case["observed_id_matches_policy"] is True
        assert case["response_shape_valid"] is True
        assert case["io_counters"] == {k: 0 for k in SIX_IO_COUNTER_KEYS}

    # 1) Local Candidate path
    cand = gov1_mcp.build_mcp_rejection_matrix_report_candidate(
        migration_run_context_locator=RUN_CONTEXT_LOCATOR,
        build_run_id=BUILD_RUN_ID,
        executed_at_utc=EXECUTED_AT_UTC,
        source_commit_sha=snapshot.commit_sha,
        build_backend_digest=snapshot.build_backend_digest,
        sealed_sandbox_profile_candidate_ref=sbx_cand_ref,
        execution=execution,
    )
    assert cand["artifact_kind"] == gov1_sandbox.LOCAL_CANDIDATE_KIND
    assert cand["signable"] is False
    assert cand["authority"] == "none"
    assert "sealed_sandbox_profile_candidate_ref" in cand["payload"]
    assert "sealed_sandbox_profile_locator" not in cand["payload"]

    cand_res = gov1_mcp.verify_mcp_rejection_matrix_report(cand, wheel_path=wheel_path)
    assert cand_res == {
        "mode": "candidate",
        "schema": gov1_mcp.MCP_REJECTION_REPORT_SCHEMA,
        "wheel_digest": digest(wheel_bytes),
        "schema_bundle_digest": expected_schema_digest,
        "executed_at_utc": EXECUTED_AT_UTC,
        "payload": cand["payload"],
    }

    # 2) P1 Envelope path (unsigned + signed + Store round-trip)
    profiles = {
        row["schema"]: row
        for row in decomposition_admission.profile_proposals(ADR_PATH.read_bytes())
    }
    mcp_prefix = profiles[gov1_mcp.MCP_REJECTION_REPORT_SCHEMA]["domain_prefix"]
    assert mcp_prefix == "SMART-ADS:MCP-REJECTION:V1\n"

    env_unsigned = gov1_mcp.build_mcp_rejection_matrix_report_envelope(
        migration_run_context_locator=RUN_CONTEXT_LOCATOR,
        build_run_id=BUILD_RUN_ID,
        executed_at_utc=EXECUTED_AT_UTC,
        source_commit_sha=snapshot.commit_sha,
        build_backend_digest=snapshot.build_backend_digest,
        sealed_sandbox_profile_locator=sbx_locator,
        execution=execution,
        registry_locator=REGISTRY_LOCATOR,
        signer_key_id=signer_id,
    )
    assert "sealed_sandbox_profile_locator" in env_unsigned
    assert "sealed_sandbox_profile_candidate_ref" not in env_unsigned

    unsigned_res = gov1_mcp.verify_mcp_rejection_matrix_report(
        env_unsigned, wheel_path=wheel_path
    )
    assert unsigned_res["mode"] == "envelope"
    assert unsigned_res["wheel_digest"] == digest(wheel_bytes)

    env_signed = p1.sign_envelope(env_unsigned, mcp_prefix, priv)
    p1.verify_envelope(env_signed, mcp_prefix, raw32)
    mcp_locator = store.put(env_signed)
    loaded_env = store.get(mcp_locator, gov1_mcp.MCP_REJECTION_REPORT_SCHEMA)

    signed_res = gov1_mcp.verify_mcp_rejection_matrix_report(
        loaded_env, wheel_path=wheel_path
    )
    expected_env_payload = {
        k: v for k, v in loaded_env.items() if k not in {"$schema", "integrity"}
    }
    assert signed_res == {
        "mode": "envelope",
        "schema": gov1_mcp.MCP_REJECTION_REPORT_SCHEMA,
        "wheel_digest": digest(wheel_bytes),
        "schema_bundle_digest": expected_schema_digest,
        "executed_at_utc": EXECUTED_AT_UTC,
        "payload": expected_env_payload,
    }


def test_negative_case_set_and_utf8_order_counterexamples_rejected(
    baseline_mcp_bundle: tuple[Path, gov1_wheel.GitBuildSnapshot, bytes, dict[str, Any]],
    sandbox_refs: tuple[dict[str, Any], dict[str, Any], Store],
) -> None:
    wheel_path, snapshot, _, execution = baseline_mcp_bundle
    sbx_cand_ref, sbx_locator, _ = sandbox_refs

    base_cand = gov1_mcp.build_mcp_rejection_matrix_report_candidate(
        migration_run_context_locator=RUN_CONTEXT_LOCATOR,
        build_run_id=BUILD_RUN_ID,
        executed_at_utc=EXECUTED_AT_UTC,
        source_commit_sha=snapshot.commit_sha,
        build_backend_digest=snapshot.build_backend_digest,
        sealed_sandbox_profile_candidate_ref=sbx_cand_ref,
        execution=execution,
    )
    base_env = gov1_mcp.build_mcp_rejection_matrix_report_envelope(
        migration_run_context_locator=RUN_CONTEXT_LOCATOR,
        build_run_id=BUILD_RUN_ID,
        executed_at_utc=EXECUTED_AT_UTC,
        source_commit_sha=snapshot.commit_sha,
        build_backend_digest=snapshot.build_backend_digest,
        sealed_sandbox_profile_locator=sbx_locator,
        execution=execution,
        registry_locator=REGISTRY_LOCATOR,
        signer_key_id="key:ed25519:" + ("c" * 64),
    )

    def _assert_tampered_cases_rejected(mutated_cases: list[dict[str, Any]]) -> None:
        bad_exec = copy.deepcopy(execution)
        bad_exec["cases"] = copy.deepcopy(mutated_cases)
        with pytest.raises(ValueError):
            gov1_mcp.build_mcp_rejection_matrix_report_candidate(
                migration_run_context_locator=RUN_CONTEXT_LOCATOR,
                build_run_id=BUILD_RUN_ID,
                executed_at_utc=EXECUTED_AT_UTC,
                source_commit_sha=snapshot.commit_sha,
                build_backend_digest=snapshot.build_backend_digest,
                sealed_sandbox_profile_candidate_ref=sbx_cand_ref,
                execution=bad_exec,
            )

        cand_bad = copy.deepcopy(base_cand)
        cand_bad["payload"]["cases"] = copy.deepcopy(mutated_cases)
        cand_bad = _recompute_candidate_digest(cand_bad)
        with pytest.raises(ValueError):
            gov1_mcp.verify_mcp_rejection_matrix_report(cand_bad, wheel_path=wheel_path)

        env_bad = copy.deepcopy(base_env)
        env_bad["cases"] = copy.deepcopy(mutated_cases)
        with pytest.raises(ValueError):
            gov1_mcp.verify_mcp_rejection_matrix_report(env_bad, wheel_path=wheel_path)

    # 1. Omit 1 case (10 cases)
    _assert_tampered_cases_rejected(execution["cases"][:-1])

    # 2. Add 1 extra case (12 cases, even inserted in UTF-8 lexical order)
    extra_case = copy.deepcopy(execution["cases"][0])
    extra_case["case_id"] = "zzz_extra_case"
    _assert_tampered_cases_rejected([*execution["cases"], extra_case])

    # 3a. Duplicate case replacing another (11 cases with duplicate)
    dup_11 = copy.deepcopy(execution["cases"])
    dup_11[1] = copy.deepcopy(dup_11[0])
    _assert_tampered_cases_rejected(dup_11)

    # 3b. Duplicate case appended/adjacent (12 cases)
    dup_12 = [execution["cases"][0], *execution["cases"]]
    _assert_tampered_cases_rejected(dup_12)

    # 4. Invert UTF-8 order of two valid cases
    swapped = copy.deepcopy(execution["cases"])
    swapped[0], swapped[1] = swapped[1], swapped[0]
    _assert_tampered_cases_rejected(swapped)


@pytest.mark.parametrize("counter_key", SIX_IO_COUNTER_KEYS)
def test_negative_each_io_counter_nonzero_or_boolean_rejected(
    counter_key: str,
    baseline_mcp_bundle: tuple[Path, gov1_wheel.GitBuildSnapshot, bytes, dict[str, Any]],
    sandbox_refs: tuple[dict[str, Any], dict[str, Any], Store],
) -> None:
    wheel_path, snapshot, _, execution = baseline_mcp_bundle
    sbx_cand_ref, sbx_locator, _ = sandbox_refs

    base_env = gov1_mcp.build_mcp_rejection_matrix_report_envelope(
        migration_run_context_locator=RUN_CONTEXT_LOCATOR,
        build_run_id=BUILD_RUN_ID,
        executed_at_utc=EXECUTED_AT_UTC,
        source_commit_sha=snapshot.commit_sha,
        build_backend_digest=snapshot.build_backend_digest,
        sealed_sandbox_profile_locator=sbx_locator,
        execution=execution,
        registry_locator=REGISTRY_LOCATOR,
        signer_key_id="key:ed25519:" + ("d" * 64),
    )
    base_cand = gov1_mcp.build_mcp_rejection_matrix_report_candidate(
        migration_run_context_locator=RUN_CONTEXT_LOCATOR,
        build_run_id=BUILD_RUN_ID,
        executed_at_utc=EXECUTED_AT_UTC,
        source_commit_sha=snapshot.commit_sha,
        build_backend_digest=snapshot.build_backend_digest,
        sealed_sandbox_profile_candidate_ref=sbx_cand_ref,
        execution=execution,
    )

    for bad_val in (1, -1, False, True):
        env_bad = copy.deepcopy(base_env)
        env_bad["cases"][3]["io_counters"][counter_key] = bad_val
        with pytest.raises(ValueError):
            gov1_mcp.verify_mcp_rejection_matrix_report(env_bad, wheel_path=wheel_path)

        cand_bad = copy.deepcopy(base_cand)
        cand_bad["payload"]["cases"][3]["io_counters"][counter_key] = bad_val
        cand_bad = _recompute_candidate_digest(cand_bad)
        with pytest.raises(ValueError):
            gov1_mcp.verify_mcp_rejection_matrix_report(cand_bad, wheel_path=wheel_path)


def test_negative_field_mutations_rejected(
    baseline_mcp_bundle: tuple[Path, gov1_wheel.GitBuildSnapshot, bytes, dict[str, Any]],
    sandbox_refs: tuple[dict[str, Any], dict[str, Any], Store],
) -> None:
    wheel_path, snapshot, _, execution = baseline_mcp_bundle
    sbx_cand_ref, sbx_locator, _ = sandbox_refs

    base_env = gov1_mcp.build_mcp_rejection_matrix_report_envelope(
        migration_run_context_locator=RUN_CONTEXT_LOCATOR,
        build_run_id=BUILD_RUN_ID,
        executed_at_utc=EXECUTED_AT_UTC,
        source_commit_sha=snapshot.commit_sha,
        build_backend_digest=snapshot.build_backend_digest,
        sealed_sandbox_profile_locator=sbx_locator,
        execution=execution,
        registry_locator=REGISTRY_LOCATOR,
        signer_key_id="key:ed25519:" + ("e" * 64),
    )
    base_cand = gov1_mcp.build_mcp_rejection_matrix_report_candidate(
        migration_run_context_locator=RUN_CONTEXT_LOCATOR,
        build_run_id=BUILD_RUN_ID,
        executed_at_utc=EXECUTED_AT_UTC,
        source_commit_sha=snapshot.commit_sha,
        build_backend_digest=snapshot.build_backend_digest,
        sealed_sandbox_profile_candidate_ref=sbx_cand_ref,
        execution=execution,
    )

    def _assert_payload_mutation_rejected(mutator: Any) -> None:
        env_bad = copy.deepcopy(base_env)
        mutator(env_bad)
        with pytest.raises(ValueError):
            gov1_mcp.verify_mcp_rejection_matrix_report(env_bad, wheel_path=wheel_path)

        cand_bad = copy.deepcopy(base_cand)
        mutator(cand_bad["payload"])
        cand_bad = _recompute_candidate_digest(cand_bad)
        with pytest.raises(ValueError):
            gov1_mcp.verify_mcp_rejection_matrix_report(cand_bad, wheel_path=wheel_path)

    # observed_code altered
    _assert_payload_mutation_rejected(
        lambda p: p["cases"][0].__setitem__("observed_code", -32600)
    )
    # expected_code altered (even if observed_code is altered to match — producer cannot pick expected)
    def _alter_both_codes(p: dict[str, Any]) -> None:
        p["cases"][10]["expected_code"] = -32600
        p["cases"][10]["observed_code"] = -32600

    _assert_payload_mutation_rejected(_alter_both_codes)

    # expected_message / observed_message altered
    _assert_payload_mutation_rejected(
        lambda p: p["cases"][5].__setitem__("expected_message", "Invalid Request")
    )
    _assert_payload_mutation_rejected(
        lambda p: p["cases"][5].__setitem__("observed_message", "Invalid Request")
    )

    # expected_id_policy altered
    _assert_payload_mutation_rejected(
        lambda p: p["cases"][0].__setitem__("expected_id_policy", "null")
    )

    # observed_id_matches_policy=False or int 1
    _assert_payload_mutation_rejected(
        lambda p: p["cases"][0].__setitem__("observed_id_matches_policy", False)
    )
    _assert_payload_mutation_rejected(
        lambda p: p["cases"][0].__setitem__("observed_id_matches_policy", 1)
    )

    # response_shape_valid=False or int 1
    _assert_payload_mutation_rejected(
        lambda p: p["cases"][2].__setitem__("response_shape_valid", False)
    )
    _assert_payload_mutation_rejected(
        lambda p: p["cases"][2].__setitem__("response_shape_valid", 1)
    )

    # body_64k_boundary_verified=False or int 1
    _assert_payload_mutation_rejected(
        lambda p: p.__setitem__("body_64k_boundary_verified", False)
    )
    _assert_payload_mutation_rejected(
        lambda p: p.__setitem__("body_64k_boundary_verified", 1)
    )

    # allowed_methods divergent (missing, extra, unsorted)
    _assert_payload_mutation_rejected(
        lambda p: p.__setitem__("allowed_methods", list(ALLOWED_MCP_METHODS[:-1]))
    )
    _assert_payload_mutation_rejected(
        lambda p: p.__setitem__(
            "allowed_methods",
            [*ALLOWED_MCP_METHODS, "smart_ads.reports.z_extra_v1"],
        )
    )
    _assert_payload_mutation_rejected(
        lambda p: p.__setitem__(
            "allowed_methods", list(reversed(ALLOWED_MCP_METHODS))
        )
    )

    # io_counters missing or extra key
    _assert_payload_mutation_rejected(
        lambda p: p["cases"][0]["io_counters"].pop("network_calls")
    )
    _assert_payload_mutation_rejected(
        lambda p: p["cases"][0]["io_counters"].__setitem__("extra_calls", 0)
    )


def test_negative_wheel_digest_mismatch_and_candidate_envelope_confusion(
    tmp_path: Path,
    baseline_mcp_bundle: tuple[Path, gov1_wheel.GitBuildSnapshot, bytes, dict[str, Any]],
    keypair: tuple[Path, bytes],
    sandbox_refs: tuple[dict[str, Any], dict[str, Any], Store],
) -> None:
    wheel_path, snapshot, _, execution = baseline_mcp_bundle
    sbx_cand_ref, sbx_locator, _ = sandbox_refs
    priv, _ = keypair
    signer_id = "key:ed25519:" + ("f" * 64)

    valid_env = gov1_mcp.build_mcp_rejection_matrix_report_envelope(
        migration_run_context_locator=RUN_CONTEXT_LOCATOR,
        build_run_id=BUILD_RUN_ID,
        executed_at_utc=EXECUTED_AT_UTC,
        source_commit_sha=snapshot.commit_sha,
        build_backend_digest=snapshot.build_backend_digest,
        sealed_sandbox_profile_locator=sbx_locator,
        execution=execution,
        registry_locator=REGISTRY_LOCATOR,
        signer_key_id=signer_id,
    )
    valid_cand = gov1_mcp.build_mcp_rejection_matrix_report_candidate(
        migration_run_context_locator=RUN_CONTEXT_LOCATOR,
        build_run_id=BUILD_RUN_ID,
        executed_at_utc=EXECUTED_AT_UTC,
        source_commit_sha=snapshot.commit_sha,
        build_backend_digest=snapshot.build_backend_digest,
        sealed_sandbox_profile_candidate_ref=sbx_cand_ref,
        execution=execution,
    )

    # 1. Valid wheel whose bytes/digest differ from report's wheel_digest -> ValueError
    members = _read_wheel_members(wheel_path)
    members["smart_ads/__init__.py"] = (
        members["smart_ads/__init__.py"] + b"\n# benign comment changing wheel digest\n"
    )
    different_wheel = _rebuild_wheel_from_dict(
        tmp_path / "different_digest.whl", members
    )
    assert digest(different_wheel.read_bytes()) != execution["wheel_digest"]

    with pytest.raises(ValueError, match="wheel_digest"):
        gov1_mcp.verify_mcp_rejection_matrix_report(
            valid_env, wheel_path=different_wheel
        )
    with pytest.raises(ValueError, match="wheel_digest"):
        gov1_mcp.verify_mcp_rejection_matrix_report(
            valid_cand, wheel_path=different_wheel
        )

    # Nonexistent or symlink wheel_path -> ValueError
    with pytest.raises(ValueError):
        gov1_mcp.verify_mcp_rejection_matrix_report(
            valid_env, wheel_path=tmp_path / "missing.whl"
        )
    sym_wheel = tmp_path / "symlink.whl"
    sym_wheel.symlink_to(wheel_path)
    with pytest.raises(ValueError):
        gov1_mcp.verify_mcp_rejection_matrix_report(valid_env, wheel_path=sym_wheel)

    # 2. Passing gov1_local_candidate_ref in P1 envelope -> ValueError
    with pytest.raises(ValueError):
        gov1_mcp.build_mcp_rejection_matrix_report_envelope(
            migration_run_context_locator=RUN_CONTEXT_LOCATOR,
            build_run_id=BUILD_RUN_ID,
            executed_at_utc=EXECUTED_AT_UTC,
            source_commit_sha=snapshot.commit_sha,
            build_backend_digest=snapshot.build_backend_digest,
            sealed_sandbox_profile_locator=sbx_cand_ref,
            execution=execution,
            registry_locator=REGISTRY_LOCATOR,
            signer_key_id=signer_id,
        )

    env_with_cand_ref_value = copy.deepcopy(valid_env)
    env_with_cand_ref_value["sealed_sandbox_profile_locator"] = copy.deepcopy(
        sbx_cand_ref
    )
    with pytest.raises(ValueError):
        gov1_mcp.verify_mcp_rejection_matrix_report(
            env_with_cand_ref_value, wheel_path=wheel_path
        )

    env_with_cand_ref_key = copy.deepcopy(valid_env)
    env_with_cand_ref_key.pop("sealed_sandbox_profile_locator")
    env_with_cand_ref_key["sealed_sandbox_profile_candidate_ref"] = copy.deepcopy(
        sbx_cand_ref
    )
    with pytest.raises(ValueError):
        gov1_mcp.verify_mcp_rejection_matrix_report(
            env_with_cand_ref_key, wheel_path=wheel_path
        )

    # 3. Passing artifact_locator/v1 in local candidate -> ValueError
    with pytest.raises(ValueError):
        gov1_mcp.build_mcp_rejection_matrix_report_candidate(
            migration_run_context_locator=RUN_CONTEXT_LOCATOR,
            build_run_id=BUILD_RUN_ID,
            executed_at_utc=EXECUTED_AT_UTC,
            source_commit_sha=snapshot.commit_sha,
            build_backend_digest=snapshot.build_backend_digest,
            sealed_sandbox_profile_candidate_ref=sbx_locator,
            execution=execution,
        )

    cand_with_locator = copy.deepcopy(valid_cand)
    cand_with_locator["payload"]["sealed_sandbox_profile_candidate_ref"] = (
        copy.deepcopy(sbx_locator)
    )
    cand_with_locator = _recompute_candidate_digest(cand_with_locator)
    with pytest.raises(ValueError):
        gov1_mcp.verify_mcp_rejection_matrix_report(
            cand_with_locator, wheel_path=wheel_path
        )

    # 4. Tampered P1 content_digest on signed envelope -> ValueError
    signed_env = p1.sign_envelope(
        valid_env, "SMART-ADS:MCP-REJECTION:V1\n", priv
    )
    signed_env["build_run_id"] = "tampered-after-signing"
    with pytest.raises(ValueError, match="content_digest"):
        gov1_mcp.verify_mcp_rejection_matrix_report(signed_env, wheel_path=wheel_path)

    # 5. Tampered schema_bundle_digest while wheel_digest matches wheel_path -> ValueError on recomputation
    env_bad_schema_digest = copy.deepcopy(valid_env)
    env_bad_schema_digest["schema_bundle_digest"] = "sha256:" + ("0" * 64)
    with pytest.raises(ValueError, match="diverges from live wheel matrix execution"):
        gov1_mcp.verify_mcp_rejection_matrix_report(
            env_bad_schema_digest, wheel_path=wheel_path
        )

    cand_bad_schema_digest = copy.deepcopy(valid_cand)
    cand_bad_schema_digest["payload"]["schema_bundle_digest"] = "sha256:" + ("0" * 64)
    cand_bad_schema_digest = _recompute_candidate_digest(cand_bad_schema_digest)
    with pytest.raises(ValueError, match="diverges from live wheel matrix execution"):
        gov1_mcp.verify_mcp_rejection_matrix_report(
            cand_bad_schema_digest, wheel_path=wheel_path
        )

    # 6. Envelope / candidate structural & scalar guards
    for non_obj in ([], "str", None, 42):
        with pytest.raises(ValueError):
            gov1_mcp.verify_mcp_rejection_matrix_report(
                non_obj, wheel_path=wheel_path  # type: ignore[arg-type]
            )

    mixed_cand = copy.deepcopy(valid_cand)
    mixed_cand["$schema"] = gov1_mcp.MCP_REJECTION_REPORT_SCHEMA
    with pytest.raises(ValueError):
        gov1_mcp.verify_mcp_rejection_matrix_report(mixed_cand, wheel_path=wheel_path)

    bad_sig_env = copy.deepcopy(valid_env)
    bad_sig_env["integrity"]["content_digest"] = p1.content_digest(bad_sig_env)
    bad_sig_env["integrity"]["signature_base64"] = base64.b64encode(b"x" * 32).decode(
        "ascii"
    )
    with pytest.raises(ValueError, match="64-byte"):
        gov1_mcp.verify_mcp_rejection_matrix_report(bad_sig_env, wheel_path=wheel_path)

    for bad_ts in ("2026-11-12T12:10:00.123456Z", "2026-11-12T12:10:00+00:00", 123):
        with pytest.raises(ValueError):
            gov1_mcp.build_mcp_rejection_matrix_report_candidate(
                migration_run_context_locator=RUN_CONTEXT_LOCATOR,
                build_run_id=BUILD_RUN_ID,
                executed_at_utc=bad_ts,  # type: ignore[arg-type]
                source_commit_sha=snapshot.commit_sha,
                build_backend_digest=snapshot.build_backend_digest,
                sealed_sandbox_profile_candidate_ref=sbx_cand_ref,
                execution=execution,
            )

    for bad_oid in ("HEAD", "A" * 40, "a" * 64, 123):
        with pytest.raises(ValueError):
            gov1_mcp.build_mcp_rejection_matrix_report_candidate(
                migration_run_context_locator=RUN_CONTEXT_LOCATOR,
                build_run_id=BUILD_RUN_ID,
                executed_at_utc=EXECUTED_AT_UTC,
                source_commit_sha=bad_oid,  # type: ignore[arg-type]
                build_backend_digest=snapshot.build_backend_digest,
                sealed_sandbox_profile_candidate_ref=sbx_cand_ref,
                execution=execution,
            )

    for bad_run_id in ("", "  ", " pad", "nul\x00id", 123):
        with pytest.raises(ValueError):
            gov1_mcp.build_mcp_rejection_matrix_report_candidate(
                migration_run_context_locator=RUN_CONTEXT_LOCATOR,
                build_run_id=bad_run_id,  # type: ignore[arg-type]
                executed_at_utc=EXECUTED_AT_UTC,
                source_commit_sha=snapshot.commit_sha,
                build_backend_digest=snapshot.build_backend_digest,
                sealed_sandbox_profile_candidate_ref=sbx_cand_ref,
                execution=execution,
            )


def test_isolated_clean_venv_executes_wheel_not_repo_src_under_hostile_pythonpath(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    baseline_mcp_bundle: tuple[Path, gov1_wheel.GitBuildSnapshot, bytes, dict[str, Any]],
) -> None:
    wheel_path, _, _, baseline_execution = baseline_mcp_bundle
    monkeypatch.setenv("PYTHONPATH", str(REPO_ROOT / "src"))
    monkeypatch.setenv("PYTHONSTARTUP", str(tmp_path / "poison_startup.py"))

    # Baseline wheel still executes deterministically and matches canonical output
    poison_env_exec = gov1_mcp.execute_mcp_rejection_matrix_on_wheel(wheel_path)
    assert canonicalize(poison_env_exec) == canonicalize(baseline_execution)

    base_members = _read_wheel_members(wheel_path)

    # Sabotaged Wheel A: passes inspect_wheel_boundary, breaks 64 KiB boundary (65537 allowed)
    members_a = dict(base_members)
    proto_src = members_a["smart_ads/transports/mcp/protocol.py"].decode("utf-8")
    assert "MAX_MCP_BODY_BYTES: Final[int] = 65_536" in proto_src
    members_a["smart_ads/transports/mcp/protocol.py"] = proto_src.replace(
        "MAX_MCP_BODY_BYTES: Final[int] = 65_536",
        "MAX_MCP_BODY_BYTES: Final[int] = 65_537",
        1,
    ).encode("utf-8")
    wheel_a = _rebuild_wheel_from_dict(tmp_path / "sabotaged_64k.whl", members_a)
    assert gov1_wheel.inspect_wheel_boundary(wheel_a)["isolated_venv_import_passed"] is True
    with pytest.raises(ValueError):
        gov1_mcp.execute_mcp_rejection_matrix_on_wheel(wheel_a)

    # Sabotaged Wheel B: passes inspect_wheel_boundary, wrong error code on unsupported_method
    members_b = dict(base_members)
    schemas_src = members_b["smart_ads/transports/mcp/schemas.py"].decode("utf-8")
    assert "code=-32601," in schemas_src
    members_b["smart_ads/transports/mcp/schemas.py"] = schemas_src.replace(
        "code=-32601,",
        "code=-32600,",
        1,
    ).encode("utf-8")
    wheel_b = _rebuild_wheel_from_dict(tmp_path / "sabotaged_code.whl", members_b)
    assert gov1_wheel.inspect_wheel_boundary(wheel_b)["isolated_venv_import_passed"] is True
    with pytest.raises(ValueError):
        gov1_mcp.execute_mcp_rejection_matrix_on_wheel(wheel_b)

    # Sabotaged Wheel C: passes inspect_wheel_boundary, touches handler before delegation rejection
    members_c = dict(base_members)
    gw_src = members_c["smart_ads/transports/mcp/gateway.py"].decode("utf-8")
    target_snippet = "    if isinstance(delegation_or_rej, McpProtocolRejection):\n"
    leak_snippet = (
        "    if isinstance(delegation_or_rej, McpProtocolRejection):\n"
        "        if handler is not None:\n"
        "            handler.handle(None)  # type: ignore[arg-type]\n"
    )
    assert target_snippet in gw_src
    members_c["smart_ads/transports/mcp/gateway.py"] = gw_src.replace(
        target_snippet,
        leak_snippet,
        1,
    ).encode("utf-8")
    wheel_c = _rebuild_wheel_from_dict(tmp_path / "sabotaged_io_leak.whl", members_c)
    assert gov1_wheel.inspect_wheel_boundary(wheel_c)["isolated_venv_import_passed"] is True
    with pytest.raises(ValueError):
        gov1_mcp.execute_mcp_rejection_matrix_on_wheel(wheel_c)

    # Sabotaged Wheel D: fails inspect_wheel_boundary (contains forbidden assert) -> rejected before execution
    members_d = dict(base_members)
    members_d["smart_ads/__init__.py"] = (
        members_d["smart_ads/__init__.py"] + b"\nassert True\n"
    )
    wheel_d = _rebuild_wheel_from_dict(tmp_path / "sabotaged_assert.whl", members_d)
    with pytest.raises(ValueError, match="assert"):
        gov1_mcp.execute_mcp_rejection_matrix_on_wheel(wheel_d)


def test_mcp_wheel_extraction_rejects_corrupt_member_and_prepended_polyglot(
    tmp_path: Path,
    baseline_mcp_bundle: tuple[Path, gov1_wheel.GitBuildSnapshot, bytes, dict[str, Any]],
) -> None:
    import struct
    import zlib

    wheel_path, _, _, _ = baseline_mcp_bundle
    orig_bytes = wheel_path.read_bytes()
    expected_paths = set(_read_wheel_members(wheel_path).keys())

    # 1. Corrupt compressed payload byte -> ValueError in both helper and top-level runner
    fname_len, extra_len = struct.unpack_from("<HH", orig_bytes, 26)
    corrupt_bytes = bytearray(orig_bytes)
    corrupt_bytes[30 + fname_len + extra_len] ^= 0xFF
    purelib_a = tmp_path / "purelib_a"
    purelib_a.mkdir()
    with pytest.raises(ValueError):
        gov1_mcp._extract_verified_wheel_to_purelib(
            bytes(corrupt_bytes), purelib_a, expected_paths
        )
    corrupt_whl = tmp_path / "corrupt_mcp.whl"
    corrupt_whl.write_bytes(bytes(corrupt_bytes))
    with pytest.raises(ValueError):
        gov1_mcp.execute_mcp_rejection_matrix_on_wheel(corrupt_whl)

    # 2. Prepended unreferenced PK\x03\x04 tooling/injected.py entry -> ValueError
    inj_name = b"tooling/injected.py"
    inj_payload = b"INJECTED = 1\n"
    crc = zlib.crc32(inj_payload) & 0xFFFFFFFF
    lfh = (
        struct.pack(
            "<4sHHHHHIIIHH",
            b"PK\x03\x04",
            20,
            0,
            0,
            0,
            0,
            crc,
            len(inj_payload),
            len(inj_payload),
            len(inj_name),
            0,
        )
        + inj_name
        + inj_payload
    )
    shift = len(lfh)
    (
        eocd_sig,
        disk_no,
        cd_start_disk,
        disk_entries,
        cd_count,
        cd_size,
        cd_offset,
        comment_len,
    ) = struct.unpack("<4sHHHHIIH", orig_bytes[-22:])
    cd_region = bytearray(orig_bytes[cd_offset : cd_offset + cd_size])
    cur = 0
    for _ in range(cd_count):
        fn_l, ex_l, cm_l = struct.unpack_from("<HHH", cd_region, cur + 28)
        old_off = struct.unpack_from("<I", cd_region, cur + 42)[0]
        struct.pack_into("<I", cd_region, cur + 42, old_off + shift)
        cur += 46 + fn_l + ex_l + cm_l
    new_eocd = struct.pack(
        "<4sHHHHIIH",
        eocd_sig,
        disk_no,
        cd_start_disk,
        disk_entries,
        cd_count,
        cd_size,
        cd_offset + shift,
        comment_len,
    )
    polyglot_bytes = lfh + orig_bytes[:cd_offset] + bytes(cd_region) + new_eocd

    purelib_b = tmp_path / "purelib_b"
    purelib_b.mkdir()
    with pytest.raises(ValueError):
        gov1_mcp._extract_verified_wheel_to_purelib(
            polyglot_bytes, purelib_b, expected_paths
        )
    polyglot_whl = tmp_path / "polyglot_mcp.whl"
    polyglot_whl.write_bytes(polyglot_bytes)
    with pytest.raises(ValueError):
        gov1_mcp.execute_mcp_rejection_matrix_on_wheel(polyglot_whl)

