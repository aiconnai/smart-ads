"""Tests for tools.governance.cli — subprocess roundtrip of the argparse CLI."""
from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]


def run_cli(*args: str, cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "tools.governance.cli", *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
    )


@pytest.fixture()
def anchor_key(tmp_path: Path) -> Path:
    priv = tmp_path / "anchor.pem"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(priv)],
        check=True,
        capture_output=True,
    )
    return priv


@pytest.fixture()
def operator_key(tmp_path: Path) -> Path:
    priv = tmp_path / "operator.pem"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(priv)],
        check=True,
        capture_output=True,
    )
    return priv


def _raw32_b64(pem: Path) -> str:
    proc = subprocess.run(
        ["openssl", "pkey", "-in", str(pem), "-pubout", "-outform", "DER"],
        check=True,
        capture_output=True,
    )
    der = proc.stdout
    raw32 = der[12:]
    return base64.b64encode(raw32).decode("ascii")


def _key_id(raw32_b64: str) -> str:
    raw = base64.b64decode(raw32_b64)
    return "key:ed25519:" + hashlib.sha256(raw).hexdigest()


def test_keygen_instructions_prints_openssl_commands(tmp_path: Path) -> None:
    proc = run_cli("keygen-instructions", cwd=REPO_ROOT)
    assert proc.returncode == 0
    assert "openssl genpkey" in proc.stdout
    assert "ed25519" in proc.stdout


def test_key_id_command(tmp_path: Path, anchor_key: Path) -> None:
    proc = run_cli("key-id", "--pubkey-pem", str(anchor_key), cwd=REPO_ROOT)
    assert proc.returncode == 0
    out = json.loads(proc.stdout)
    assert out["key_id"].startswith("key:ed25519:")
    assert "public_key_base64" in out
    assert out["public_key_sha256"].startswith("sha256:")


def test_full_roundtrip(tmp_path: Path, anchor_key: Path, operator_key: Path) -> None:
    anchor_raw32_b64 = _raw32_b64(anchor_key)
    anchor_key_id = _key_id(anchor_raw32_b64)
    operator_raw32_b64 = _raw32_b64(operator_key)
    operator_key_id = _key_id(operator_raw32_b64)

    # 1. build trust anchor config
    ta_params = tmp_path / "ta_params.json"
    ta_params.write_text(json.dumps({
        "anchor_id": "trust-anchor:governance-root",
        "anchor_public_key_base64": anchor_raw32_b64,
        "valid_from_utc": "2026-01-01T00:00:00Z",
        "valid_until_utc": "2027-01-01T00:00:00Z",
        "allowed_registry_artifact_types": ["smart_ads/key_authorization_registry/v1"],
    }))
    ta_out = tmp_path / "trust_anchor.json"
    proc = run_cli(
        "build-trust-anchor", "--params", str(ta_params), "--out", str(ta_out), cwd=REPO_ROOT
    )
    assert proc.returncode == 0, proc.stderr
    assert ta_out.stat().st_size > 0

    # 2. build registry (unsigned) referencing the operator key
    reg_params = tmp_path / "reg_params.json"
    reg_params.write_text(json.dumps({
        "trust_anchor_id": "trust-anchor:governance-root",
        "epoch": 1,
        "issued_at_utc": "2026-01-01T00:00:00Z",
        "signer_key_id": anchor_key_id,
        "entries": [{
            "key_id": operator_key_id,
            "public_key_base64": operator_raw32_b64,
            "public_key_sha256": "sha256:" + hashlib.sha256(base64.b64decode(operator_raw32_b64)).hexdigest(),
            "principal": "principal:ronaldo",
            "tenant": "tenant:mbras",
            "role": "gate2_approver",
            "validity": {"from": "2026-01-01T00:00:00Z", "until": "2027-01-01T00:00:00Z"},
            "lifecycle_state": "active",
            "allowed_actions": [{"schema": "gate2_approval_receipt/v1", "action": "gate2_approve"}],
        }],
    }))
    reg_out = tmp_path / "registry_unsigned.json"
    proc = run_cli(
        "build-registry", "--params", str(reg_params), "--out", str(reg_out), cwd=REPO_ROOT
    )
    assert proc.returncode == 0, proc.stderr

    # 3. sign registry with anchor key
    reg_signed = tmp_path / "registry_signed.json"
    proc = run_cli(
        "sign", "--schema", "key_authorization_registry/v1",
        "--key", str(anchor_key), "--in", str(reg_out), "--out", str(reg_signed),
        cwd=REPO_ROOT,
    )
    assert proc.returncode == 0, proc.stderr

    # 4. verify
    proc = run_cli(
        "verify", "--schema", "key_authorization_registry/v1",
        "--pubkey-raw-base64", anchor_raw32_b64, "--in", str(reg_signed),
        cwd=REPO_ROOT,
    )
    assert proc.returncode == 0, proc.stderr

    # 5. store-put
    store_root = tmp_path / "store"
    proc = run_cli(
        "store-put", "--root", str(store_root), "--in", str(reg_signed), cwd=REPO_ROOT
    )
    assert proc.returncode == 0, proc.stderr
    registry_locator = json.loads(proc.stdout)
    registry_locator_path = tmp_path / "registry_locator.json"
    registry_locator_path.write_text(json.dumps(registry_locator))

    # store-get roundtrip
    proc = run_cli(
        "store-get", "--root", str(store_root), "--locator", str(registry_locator_path),
        cwd=REPO_ROOT,
    )
    assert proc.returncode == 0, proc.stderr
    fetched = json.loads(proc.stdout)
    assert fetched["$schema"] == "smart_ads/key_authorization_registry/v1"

    # 6. build policy referencing the registry locator
    policy_params = tmp_path / "policy_params.json"
    policy_params.write_text(json.dumps({
        "repository": "aiconnai/smart-ads",
        "protected_ref": "main",
        "adr_path": "docs/adr/ADR-0001-smart-ads-read-gateway.md",
        "ci_review_policy_digest": "sha256:" + ("a" * 64),
        "designated_principals": ["principal:ronaldo"],
        "registry_locator": registry_locator,
        "signer_key_id": anchor_key_id,
    }))
    policy_out = tmp_path / "policy_unsigned.json"
    proc = run_cli(
        "build-policy", "--params", str(policy_params), "--out", str(policy_out), cwd=REPO_ROOT
    )
    assert proc.returncode == 0, proc.stderr

    # 7. sign + verify policy
    policy_signed = tmp_path / "policy_signed.json"
    proc = run_cli(
        "sign", "--schema", "gate2_authority_policy/v1",
        "--key", str(anchor_key), "--in", str(policy_out), "--out", str(policy_signed),
        cwd=REPO_ROOT,
    )
    assert proc.returncode == 0, proc.stderr
    proc = run_cli(
        "verify", "--schema", "gate2_authority_policy/v1",
        "--pubkey-raw-base64", anchor_raw32_b64, "--in", str(policy_signed),
        cwd=REPO_ROOT,
    )
    assert proc.returncode == 0, proc.stderr


def test_verify_fails_with_wrong_key(tmp_path: Path, anchor_key: Path, operator_key: Path) -> None:
    anchor_raw32_b64 = _raw32_b64(anchor_key)
    operator_raw32_b64 = _raw32_b64(operator_key)
    anchor_key_id = _key_id(anchor_raw32_b64)

    policy_params = tmp_path / "policy_params.json"
    policy_params.write_text(json.dumps({
        "repository": "aiconnai/smart-ads",
        "protected_ref": "main",
        "adr_path": "docs/adr/ADR-0001-smart-ads-read-gateway.md",
        "ci_review_policy_digest": "sha256:" + ("a" * 64),
        "designated_principals": ["principal:ronaldo"],
        "registry_locator": {
            "$schema": "smart_ads/artifact_locator/v1",
            "artifact_type": "smart_ads/key_authorization_registry/v1",
            "content_digest": "sha256:" + ("0" * 64),
            "serialization": "rfc8785-json",
            "store_kind": "cell_immutable_object",
            "object_ref": "cell-object:sha256:" + ("0" * 64),
        },
        "signer_key_id": anchor_key_id,
    }))
    policy_out = tmp_path / "policy_unsigned.json"
    run_cli("build-policy", "--params", str(policy_params), "--out", str(policy_out), cwd=REPO_ROOT)

    policy_signed = tmp_path / "policy_signed.json"
    run_cli(
        "sign", "--schema", "gate2_authority_policy/v1",
        "--key", str(anchor_key), "--in", str(policy_out), "--out", str(policy_signed),
        cwd=REPO_ROOT,
    )
    proc = run_cli(
        "verify", "--schema", "gate2_authority_policy/v1",
        "--pubkey-raw-base64", operator_raw32_b64, "--in", str(policy_signed),
        cwd=REPO_ROOT,
    )
    assert proc.returncode == 1


def test_build_merge_evidence_fails_without_protection(tmp_path: Path) -> None:
    protection_json = tmp_path / "protection.json"
    protection_json.write_text(json.dumps({"protected": False}))
    params = tmp_path / "merge_params.json"
    params.write_text(json.dumps(_merge_params()))
    out = tmp_path / "evidence.json"
    proc = run_cli(
        "build-merge-evidence", "--params", str(params),
        "--protection-json", str(protection_json),
        "--offline-protection-ack", "I_UNDERSTAND_THIS_IS_NOT_LIVE_EVIDENCE",
        "--out", str(out),
        cwd=REPO_ROOT,
    )
    assert proc.returncode != 0
    assert "protected_branch_not_verified" in (proc.stdout + proc.stderr)
    assert not out.exists()


def test_build_merge_evidence_succeeds_with_protection(tmp_path: Path) -> None:
    protection_json = tmp_path / "protection.json"
    protection_json.write_text(json.dumps({"protected": True}))
    params = tmp_path / "merge_params.json"
    params.write_text(json.dumps(_merge_params()))
    out = tmp_path / "evidence.json"
    proc = run_cli(
        "build-merge-evidence", "--params", str(params),
        "--protection-json", str(protection_json),
        "--offline-protection-ack", "I_UNDERSTAND_THIS_IS_NOT_LIVE_EVIDENCE",
        "--out", str(out),
        cwd=REPO_ROOT,
    )
    assert proc.returncode == 0, proc.stderr
    assert out.stat().st_size > 0
    assert "offline" in proc.stderr.lower() or "warning" in proc.stderr.lower()


def test_build_merge_evidence_rejects_protection_json_without_ack(tmp_path: Path) -> None:
    protection_json = tmp_path / "protection.json"
    protection_json.write_text(json.dumps({"protected": True}))
    params = tmp_path / "merge_params.json"
    params.write_text(json.dumps(_merge_params()))
    out = tmp_path / "evidence.json"
    proc = run_cli(
        "build-merge-evidence", "--params", str(params),
        "--protection-json", str(protection_json), "--out", str(out),
        cwd=REPO_ROOT,
    )
    assert proc.returncode != 0
    assert "--offline-protection-ack" in (proc.stdout + proc.stderr)
    assert not out.exists()


def test_build_merge_evidence_rejects_wrong_ack_literal(tmp_path: Path) -> None:
    protection_json = tmp_path / "protection.json"
    protection_json.write_text(json.dumps({"protected": True}))
    params = tmp_path / "merge_params.json"
    params.write_text(json.dumps(_merge_params()))
    out = tmp_path / "evidence.json"
    proc = run_cli(
        "build-merge-evidence", "--params", str(params),
        "--protection-json", str(protection_json),
        "--offline-protection-ack", "yes-i-am-sure",
        "--out", str(out),
        cwd=REPO_ROOT,
    )
    assert proc.returncode != 0
    assert not out.exists()


def test_build_merge_evidence_requires_repository_and_ref_without_protection_json(
    tmp_path: Path,
) -> None:
    # Without --protection-json, the CLI takes the live gh path, which requires
    # --repository/--ref. Omitting them must fail with a usage/argument error
    # (exit 2), never fall back to a silent offline default.
    params = tmp_path / "merge_params.json"
    params.write_text(json.dumps(_merge_params()))
    out = tmp_path / "evidence.json"
    proc = run_cli(
        "build-merge-evidence", "--params", str(params), "--out", str(out),
        cwd=REPO_ROOT,
    )
    assert proc.returncode == 2
    assert not out.exists()


def _merge_params() -> dict:
    locator = {
        "$schema": "smart_ads/artifact_locator/v1",
        "artifact_type": "smart_ads/gate2_authority_policy/v1",
        "content_digest": "sha256:" + ("1" * 64),
        "serialization": "rfc8785-json",
        "store_kind": "cell_immutable_object",
        "object_ref": "cell-object:sha256:" + ("1" * 64),
    }
    registry_locator = dict(locator, artifact_type="smart_ads/key_authorization_registry/v1")
    return {
        "repository": "aiconnai/smart-ads",
        "protected_branch": "main",
        "pr_number": 1,
        "reviewed_head_sha": "d" * 40,
        "protected_merge_sha": "e" * 40,
        "adr_git_identity": {
            "repository": "aiconnai/smart-ads",
            "commit_sha": "a" * 40,
            "path": "docs/adr/ADR-0001-smart-ads-read-gateway.md",
            "git_blob_oid": "b" * 40,
            "file_content_sha256": "sha256:" + ("c" * 64),
        },
        "required_ci_results": [{"check": "tests", "status": "success"}],
        "exact_head_review_evidence": [{"reviewer": "principal:ronaldo", "verdict": "approve"}],
        "branch_protection_policy": {"locator": locator, "digest": "sha256:" + ("f" * 64)},
        "signer_key_id": "key:ed25519:" + ("2" * 64),
        "registry_locator": registry_locator,
    }


# ---------------------------------------------------------------------------
# build-run-context / build-delivery-mode end-to-end
# ---------------------------------------------------------------------------


def _locator_for(artifact_type: str, payload: bytes) -> dict:
    from tools.governance.locator import make_locator

    return make_locator(artifact_type, payload)


def test_build_run_context_and_delivery_mode_sign_and_verify(
    tmp_path: Path, anchor_key: Path, operator_key: Path
) -> None:
    """Full chain: build both envelopes, sign, verify, and reject a domain swap.

    The realistic failure mode for these two artifacts is a domain-prefix mix-up,
    since they are adjacent in the flow and share most of their fields. The test
    asserts that a signature made under RUN-CONTEXT does not verify under
    DELIVERY-MODE.
    """
    repo_root = Path(__file__).resolve().parents[2]
    anchor_b64 = _raw32_b64(anchor_key)
    anchor_kid = _key_id(anchor_b64)

    adr_identity = {
        "repository": "aiconnai/smart-ads",
        "commit_sha": "a" * 40,
        "path": "docs/adr/ADR-0001-smart-ads-read-gateway.md",
        "git_blob_oid": "b" * 40,
        "file_content_sha256": "sha256:" + "c" * 64,
    }
    registry_loc = _locator_for("smart_ads/key_authorization_registry/v1", b"reg")
    receipt_loc = _locator_for("smart_ads/gate2_approval_receipt/v1", b"rec")

    run_params = tmp_path / "run_params.json"
    run_params.write_text(
        json.dumps(
            {
                "gate2_receipt_locator": receipt_loc,
                "approved_adr_git_identity": adr_identity,
                "legacy_source_identity": {
                    "repository": "mbras-tech/mbras-campaigns",
                    "commit_sha": "d26c73d8508c7c3d43161fe36a80c44a46bf0f2d",
                },
                "tenant_ref": "tenant:aiconnai",
                "cell_ref": "cell:smart-ads-migration",
                "run_id": "run:" + "0" * 32,
                "created_at_utc": "2026-09-04T14:00:00Z",
                "key_registry_snapshot_locator": registry_loc,
                "signer_key_id": anchor_kid,
            }
        )
    )
    run_out = tmp_path / "run_context.json"
    r = run_cli(
        "build-run-context", "--params", str(run_params), "--out", str(run_out),
        cwd=repo_root,
    )
    assert r.returncode == 0, r.stderr

    run_signed = tmp_path / "run_context_signed.json"
    r = run_cli(
        "sign", "--schema", "migration_run_context/v1", "--key", str(anchor_key),
        "--in", str(run_out), "--out", str(run_signed), cwd=repo_root,
    )
    assert r.returncode == 0, r.stderr

    r = run_cli(
        "verify", "--schema", "migration_run_context/v1",
        "--pubkey-raw-base64", anchor_b64, "--in", str(run_signed), cwd=repo_root,
    )
    assert r.returncode == 0, r.stderr

    # Domain separation: the same signature must NOT verify under the
    # delivery-mode domain prefix.
    r = run_cli(
        "verify", "--schema", "delivery_mode_decision_receipt/v1",
        "--pubkey-raw-base64", anchor_b64, "--in", str(run_signed), cwd=repo_root,
    )
    assert r.returncode != 0

    # The run context locator must address the signed run-context bytes.
    run_ctx_bytes = run_signed.read_bytes()
    run_ctx_loc = _locator_for("smart_ads/migration_run_context/v1", run_ctx_bytes)

    del_params = tmp_path / "del_params.json"
    del_params.write_text(
        json.dumps(
            {
                "gate2_receipt_locator": receipt_loc,
                "approved_adr_git_identity": adr_identity,
                "run_context_locator": run_ctx_loc,
                "decided_by_principal_ref": "principal:ronaldo",
                "decided_at_utc": "2026-09-04T14:05:00Z",
                "key_registry_snapshot_locator": registry_loc,
                "signer_key_id": _key_id(_raw32_b64(operator_key)),
            }
        )
    )
    del_out = tmp_path / "delivery.json"
    r = run_cli(
        "build-delivery-mode", "--params", str(del_params), "--out", str(del_out),
        cwd=repo_root,
    )
    assert r.returncode == 0, r.stderr
    assert json.loads(del_out.read_text())["delivery_mode"] == "manual"

    del_signed = tmp_path / "delivery_signed.json"
    r = run_cli(
        "sign", "--schema", "delivery_mode_decision_receipt/v1",
        "--key", str(operator_key), "--in", str(del_out),
        "--out", str(del_signed), cwd=repo_root,
    )
    assert r.returncode == 0, r.stderr

    r = run_cli(
        "verify", "--schema", "delivery_mode_decision_receipt/v1",
        "--pubkey-raw-base64", _raw32_b64(operator_key),
        "--in", str(del_signed), cwd=repo_root,
    )
    assert r.returncode == 0, r.stderr

    # Negative: the delivery-mode receipt must not verify under the anchor key.
    r = run_cli(
        "verify", "--schema", "delivery_mode_decision_receipt/v1",
        "--pubkey-raw-base64", anchor_b64, "--in", str(del_signed), cwd=repo_root,
    )
    assert r.returncode != 0


def test_build_delivery_mode_rejects_wrong_run_context_locator_type(
    tmp_path: Path, anchor_key: Path
) -> None:
    """A locator resolving the wrong artifact type must be refused."""
    repo_root = Path(__file__).resolve().parents[2]
    anchor_kid = _key_id(_raw32_b64(anchor_key))
    params = tmp_path / "bad.json"
    params.write_text(
        json.dumps(
            {
                "gate2_receipt_locator": _locator_for(
                    "smart_ads/gate2_approval_receipt/v1", b"rec"
                ),
                "approved_adr_git_identity": {
                    "repository": "aiconnai/smart-ads",
                    "commit_sha": "a" * 40,
                    "path": "docs/adr/ADR-0001-smart-ads-read-gateway.md",
                    "git_blob_oid": "b" * 40,
                    "file_content_sha256": "sha256:" + "c" * 64,
                },
                # wrong type: a policy locator where a run context is required
                "run_context_locator": _locator_for(
                    "smart_ads/gate2_authority_policy/v1", b"pol"
                ),
                "decided_by_principal_ref": "principal:ronaldo",
                "decided_at_utc": "2026-09-04T14:05:00Z",
                "key_registry_snapshot_locator": _locator_for(
                    "smart_ads/key_authorization_registry/v1", b"reg"
                ),
                "signer_key_id": anchor_kid,
            }
        )
    )
    r = run_cli(
        "build-delivery-mode", "--params", str(params),
        "--out", str(tmp_path / "out.json"), cwd=repo_root,
    )
    assert r.returncode != 0
    assert "artifact_type" in r.stderr
