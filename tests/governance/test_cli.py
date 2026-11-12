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


@pytest.mark.parametrize(
    "subcommand,base_params,extra_args",
    [
        (
            "build-trust-anchor",
            {
                "anchor_id": "trust-anchor:governance-root",
                "anchor_public_key_base64": None,  # filled in test
                "valid_from_utc": "2026-01-01T00:00:00Z",
                "valid_until_utc": "2027-01-01T00:00:00Z",
                "allowed_registry_artifact_types": ["smart_ads/key_authorization_registry/v1"],
            },
            [],
        ),
        (
            "build-registry",
            {
                "trust_anchor_id": "trust-anchor:governance-root",
                "epoch": 1,
                "issued_at_utc": "2026-09-01T00:00:00Z",
                "entries": [],
                "signer_key_id": "key:ed25519:" + "0" * 64,
            },
            [],
        ),
        (
            "build-policy",
            {
                "repository": "aiconnai/smart-ads",
                "protected_ref": "refs/heads/main",
                "adr_path": "docs/adr/ADR-0001-smart-ads-read-gateway.md",
                "ci_review_policy_digest": "sha256:" + "a" * 64,
                "designated_principals": ["principal:ronaldo"],
                "registry_locator": {},
                "signer_key_id": "key:ed25519:" + "0" * 64,
            },
            [],
        ),
        (
            "build-merge-evidence",
            {
                "repository": "aiconnai/smart-ads",
                "protected_branch": "main",
                "pr_number": 1,
                "reviewed_head_sha": "a" * 40,
                "protected_merge_sha": "b" * 40,
                "adr_git_identity": {},
                "required_ci_results": [],
                "exact_head_review_evidence": [],
                "branch_protection_policy": {},
                "signer_key_id": "key:ed25519:" + "0" * 64,
                "registry_locator": {},
            },
            [],
        ),
        (
            "build-receipt",
            {
                "approved_adr_git_identity": {},
                "legacy_source_identity": {},
                "protected_merge_evidence_locator": {},
                "protected_merge_sha": "a" * 40,
                "gate2_authority_policy_locator": {},
                "approver_principal_ref": "principal:ronaldo",
                "approved_at_utc": "2026-09-03T00:00:00Z",
                "key_registry_snapshot_locator": {},
                "signer_key_id": "key:ed25519:" + "0" * 64,
            },
            [],
        ),
        (
            "build-run-context",
            {
                "gate2_receipt_locator": {},
                "approved_adr_git_identity": {},
                "legacy_source_identity": {},
                "tenant_ref": "tenant:aiconnai",
                "cell_ref": "cell:smart-ads",
                "run_id": "run:" + "0" * 32,
                "created_at_utc": "2026-09-04T00:00:00Z",
                "key_registry_snapshot_locator": {},
                "signer_key_id": "key:ed25519:" + "0" * 64,
            },
            [],
        ),
        (
            "build-delivery-mode",
            {
                "gate2_receipt_locator": {},
                "approved_adr_git_identity": {},
                "run_context_locator": {},
                "decided_by_principal_ref": "principal:ronaldo",
                "decided_at_utc": "2026-09-04T14:05:00Z",
                "key_registry_snapshot_locator": {},
                "signer_key_id": "key:ed25519:" + "0" * 64,
            },
            [],
        ),
        (
            "build-legacy-step2-evidence",
            {
                "facts": {},
                "resolved_at_utc": "2026-09-07T12:00:00Z",
                "key_registry_snapshot_locator": {},
                "signer_key_id": "key:ed25519:" + "0" * 64,
            },
            [],
        ),
        (
            "build-legacy-step2-evidence",
            {
                "facts_path": "unused.json",
                "resolved_at_utc": "2026-09-07T12:00:00Z",
                "key_registry_snapshot_locator": {},
                "signer_key_id": "key:ed25519:" + "0" * 64,
            },
            [],
        ),
    ],
)
def test_cli_rejects_extra_fields_in_params(
    tmp_path: Path, anchor_key: Path, subcommand: str, base_params: dict, extra_args: list[str]
) -> None:
    payload = dict(base_params)
    if payload.get("anchor_public_key_base64") is None and "anchor_public_key_base64" in payload:
        payload["anchor_public_key_base64"] = _raw32_b64(anchor_key)
    payload["unexpected_extra_field"] = True

    params_file = tmp_path / f"{subcommand}_extra.json"
    params_file.write_text(json.dumps(payload), encoding="utf-8")
    out = tmp_path / f"{subcommand}_out.json"
    proc = run_cli(
        subcommand, "--params", str(params_file), "--out", str(out), *extra_args, cwd=REPO_ROOT
    )
    assert proc.returncode == 1
    assert "expected exactly" in proc.stderr
    assert not out.exists()


def test_write_json_file_allow_overwrite_replaces_existing_and_sets_0644(
    tmp_path: Path,
) -> None:
    import stat
    from tools.governance import cli
    from tools.governance.jcs import canonicalize

    target = tmp_path / "nested" / "artifact.json"
    first_meta = cli._write_json_file(str(target), {"step": 1}, allow_overwrite=True)
    assert set(first_meta.keys()) == {"path", "size", "sha256"}
    assert "signable" not in first_meta
    assert stat.S_IMODE(target.stat().st_mode) == 0o644

    # Tighten mode to 0o600 first to prove overwrite resets target mode to 0o644 via temp file.
    target.chmod(0o600)
    second_payload = {"step": 2, "replaced": True}
    second_meta = cli._write_json_file(str(target), second_payload, allow_overwrite=True)
    expected_bytes = canonicalize(second_payload)
    assert target.read_bytes() == expected_bytes
    assert stat.S_IMODE(target.stat().st_mode) == 0o644
    assert second_meta == {
        "path": str(target),
        "size": len(expected_bytes),
        "sha256": hashlib.sha256(expected_bytes).hexdigest(),
    }
    assert list(target.parent.glob(".decomposition-*")) == []


# ---------------------------------------------------------------------------
# GOV 1 Subcommands End-to-End Pipeline & Quarantine Guards
# ---------------------------------------------------------------------------


def test_gov1_cli_full_candidate_pipeline_quarantine_and_envelope_modes(
    tmp_path: Path, anchor_key: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from tools.governance import cli, gov1_sandbox
    from tools.governance.jcs import canonicalize

    run_ctx_loc = _locator_for("smart_ads/migration_run_context/v1", b'{"run":"cli-gov1"}')
    reg_loc = _locator_for("smart_ads/key_authorization_registry/v1", b'{"reg":"cli-gov1"}')
    reg_loc_path = tmp_path / "reg_loc.json"
    reg_loc_path.write_bytes(canonicalize(reg_loc))

    seccomp = gov1_sandbox.build_default_7a_seccomp_profile()
    seccomp_path = tmp_path / "seccomp_7a.json"
    seccomp_path.write_bytes(canonicalize(seccomp))

    # 1. build-sealed-sandbox-profile (default candidate mode) + verify
    sbx_params_path = tmp_path / "sbx_params.json"
    sbx_params_path.write_text(
        json.dumps(
            {
                "migration_run_context_locator": run_ctx_loc,
                "oci_image_digest": "sha256:" + ("1" * 64),
                "runner_binary_digest": "sha256:" + ("2" * 64),
                "issued_at_utc": "2026-11-12T12:00:00Z",
                "valid_from_utc": "2026-11-01T00:00:00Z",
                "valid_until_utc": "2027-11-01T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    sbx_cand_path = tmp_path / "sandbox_candidate.json"
    assert (
        cli.main(
            [
                "build-sealed-sandbox-profile",
                "--params",
                str(sbx_params_path),
                "--seccomp-profile",
                str(seccomp_path),
                "--out",
                str(sbx_cand_path),
            ]
        )
        == 0
    )
    sbx_meta = json.loads(capsys.readouterr().out)
    assert sbx_meta["signable"] is False
    assert sbx_cand_path.stat().st_size > 0

    # Candidate refuses overwriting existing --out
    sbx_original_bytes = sbx_cand_path.read_bytes()
    assert (
        cli.main(
            [
                "build-sealed-sandbox-profile",
                "--params",
                str(sbx_params_path),
                "--seccomp-profile",
                str(seccomp_path),
                "--out",
                str(sbx_cand_path),
            ]
        )
        == 1
    )
    capsys.readouterr()
    assert sbx_cand_path.read_bytes() == sbx_original_bytes

    # Candidate refuses cli.main(["sign", ...]) and cli.main(["store-put", ...])
    forged_signed = tmp_path / "forged_signed.json"
    assert (
        cli.main(
            [
                "sign",
                "--schema",
                "sealed_sandbox_profile/v1",
                "--key",
                str(anchor_key),
                "--in",
                str(sbx_cand_path),
                "--out",
                str(forged_signed),
            ]
        )
        == 2
    )
    capsys.readouterr()
    assert (
        cli.main(
            [
                "sign",
                "--schema",
                "migration_run_context/v1",
                "--key",
                str(anchor_key),
                "--in",
                str(sbx_cand_path),
                "--out",
                str(forged_signed),
            ]
        )
        == 1
    )
    capsys.readouterr()
    assert not forged_signed.exists()
    assert (
        cli.main(
            [
                "store-put",
                "--root",
                str(tmp_path / "forbidden_store"),
                "--in",
                str(sbx_cand_path),
            ]
        )
        == 1
    )
    capsys.readouterr()

    assert (
        cli.main(
            [
                "verify-sealed-sandbox-profile",
                "--in",
                str(sbx_cand_path),
                "--seccomp-profile",
                str(seccomp_path),
            ]
        )
        == 0
    )
    sbx_ver_out = json.loads(capsys.readouterr().out)
    assert sbx_ver_out["status"] == "PASS"
    assert sbx_ver_out["mode"] == "candidate"

    # 2. build-wheel-provenance + verify-wheel-provenance
    prov_params_path = tmp_path / "prov_params.json"
    prov_params_path.write_text(
        json.dumps(
            {
                "migration_run_context_locator": run_ctx_loc,
                "build_run_id": "cli-build-run-001",
                "built_at_utc": "2026-11-12T12:01:00Z",
            }
        ),
        encoding="utf-8",
    )
    built_wheel_path = tmp_path / "dist" / "smart_ads-0.1.0-py3-none-any.whl"
    prov_cand_path = tmp_path / "wheel_provenance_candidate.json"
    assert (
        cli.main(
            [
                "build-wheel-provenance",
                "--repo",
                str(REPO_ROOT),
                "--wheel-out",
                str(built_wheel_path),
                "--params",
                str(prov_params_path),
                "--out",
                str(prov_cand_path),
            ]
        )
        == 0
    )
    prov_meta = json.loads(capsys.readouterr().out)
    assert prov_meta["signable"] is False
    assert built_wheel_path.is_file() and built_wheel_path.stat().st_size > 0
    prov_cand = json.loads(prov_cand_path.read_text(encoding="utf-8"))

    assert (
        cli.main(
            [
                "verify-wheel-provenance",
                "--in",
                str(prov_cand_path),
                "--repo",
                str(REPO_ROOT),
                "--wheel",
                str(built_wheel_path),
            ]
        )
        == 0
    )
    prov_ver_out = json.loads(capsys.readouterr().out)
    assert prov_ver_out["status"] == "PASS"

    # 3. build-wheel-boundary-report + verify-wheel-boundary-report
    bound_params_path = tmp_path / "bound_params.json"
    bound_params_path.write_text(
        json.dumps(
            {
                "migration_run_context_locator": run_ctx_loc,
                "build_run_id": "cli-build-run-001",
                "verified_at_utc": "2026-11-12T12:02:00Z",
                "source_commit_sha": prov_cand["payload"]["source_commit_sha"],
                "build_backend_digest": prov_cand["payload"]["build_backend_digest"],
            }
        ),
        encoding="utf-8",
    )
    bound_cand_path = tmp_path / "wheel_boundary_candidate.json"
    assert (
        cli.main(
            [
                "build-wheel-boundary-report",
                "--wheel",
                str(built_wheel_path),
                "--provenance",
                str(prov_cand_path),
                "--params",
                str(bound_params_path),
                "--out",
                str(bound_cand_path),
            ]
        )
        == 0
    )
    bound_meta = json.loads(capsys.readouterr().out)
    assert bound_meta["signable"] is False

    assert (
        cli.main(
            [
                "verify-wheel-boundary-report",
                "--in",
                str(bound_cand_path),
                "--wheel",
                str(built_wheel_path),
            ]
        )
        == 0
    )
    bound_ver_out = json.loads(capsys.readouterr().out)
    assert bound_ver_out["status"] == "PASS"

    # 4. build-mcp-rejection-report + verify-mcp-rejection-report
    mcp_params_path = tmp_path / "mcp_params.json"
    mcp_params_path.write_text(
        json.dumps(
            {
                "migration_run_context_locator": run_ctx_loc,
                "build_run_id": "cli-build-run-001",
                "executed_at_utc": "2026-11-12T12:03:00Z",
                "source_commit_sha": prov_cand["payload"]["source_commit_sha"],
                "build_backend_digest": prov_cand["payload"]["build_backend_digest"],
            }
        ),
        encoding="utf-8",
    )
    mcp_cand_path = tmp_path / "mcp_rejection_candidate.json"
    assert (
        cli.main(
            [
                "build-mcp-rejection-report",
                "--wheel",
                str(built_wheel_path),
                "--sandbox-profile",
                str(sbx_cand_path),
                "--params",
                str(mcp_params_path),
                "--out",
                str(mcp_cand_path),
            ]
        )
        == 0
    )
    mcp_meta = json.loads(capsys.readouterr().out)
    assert mcp_meta["signable"] is False

    assert (
        cli.main(
            [
                "verify-mcp-rejection-report",
                "--in",
                str(mcp_cand_path),
                "--wheel",
                str(built_wheel_path),
            ]
        )
        == 0
    )
    mcp_ver_out = json.loads(capsys.readouterr().out)
    assert mcp_ver_out["status"] == "PASS"

    # 5. verify-pr1-gov1-convergence with atomic --out write & verified re-read
    gate_out_path = tmp_path / "convergence_gate_receipt.json"
    assert (
        cli.main(
            [
                "verify-pr1-gov1-convergence",
                "--repo",
                str(REPO_ROOT),
                "--wheel",
                str(built_wheel_path),
                "--seccomp-profile",
                str(seccomp_path),
                "--sandbox-profile",
                str(sbx_cand_path),
                "--wheel-provenance",
                str(prov_cand_path),
                "--wheel-boundary-report",
                str(bound_cand_path),
                "--mcp-rejection-report",
                str(mcp_cand_path),
                "--out",
                str(gate_out_path),
            ]
        )
        == 0
    )
    gate_meta = json.loads(capsys.readouterr().out)
    assert gate_meta["gate_status"] == "PASS"
    assert gate_meta["signable"] is False
    gate_receipt = json.loads(gate_out_path.read_text(encoding="utf-8"))
    assert gate_receipt["artifact_kind"] == "pr1_gov1_pre_pr2_convergence_gate"
    assert gate_receipt["gate_status"] == "PASS"
    assert gate_receipt["final_gov1_convergence_emitted"] is False
    assert gate_receipt["signable"] is False
    assert gate_out_path.read_bytes() == canonicalize(gate_receipt)

    # Gate receipt also refuses overwriting existing --out
    assert (
        cli.main(
            [
                "verify-pr1-gov1-convergence",
                "--repo",
                str(REPO_ROOT),
                "--wheel",
                str(built_wheel_path),
                "--seccomp-profile",
                str(seccomp_path),
                "--sandbox-profile",
                str(sbx_cand_path),
                "--wheel-provenance",
                str(prov_cand_path),
                "--wheel-boundary-report",
                str(bound_cand_path),
                "--mcp-rejection-report",
                str(mcp_cand_path),
                "--out",
                str(gate_out_path),
            ]
        )
        == 1
    )
    capsys.readouterr()

    # 6. Explicit --mode envelope with --signer-key-id and --registry-locator allows overwrite
    anchor_kid = _key_id(_raw32_b64(anchor_key))
    sbx_env_path = tmp_path / "sandbox_envelope.json"
    sbx_env_path.write_text('{"placeholder": true}', encoding="utf-8")
    assert (
        cli.main(
            [
                "build-sealed-sandbox-profile",
                "--mode",
                "envelope",
                "--signer-key-id",
                anchor_kid,
                "--registry-locator",
                str(reg_loc_path),
                "--params",
                str(sbx_params_path),
                "--seccomp-profile",
                str(seccomp_path),
                "--out",
                str(sbx_env_path),
            ]
        )
        == 0
    )
    sbx_env_meta = json.loads(capsys.readouterr().out)
    assert "signable" not in sbx_env_meta
    sbx_env = json.loads(sbx_env_path.read_text(encoding="utf-8"))
    assert sbx_env["$schema"] == "smart_ads/sealed_sandbox_profile/v1"
    assert sbx_env["integrity"]["key_id"] == anchor_kid


def test_gov1_cli_rejects_extra_fields_missing_files_and_envelope_mode_mixing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from tools.governance import cli, gov1_sandbox
    from tools.governance.jcs import canonicalize

    seccomp_path = tmp_path / "seccomp.json"
    seccomp_path.write_bytes(
        canonicalize(gov1_sandbox.build_default_7a_seccomp_profile())
    )
    dummy_wheel = tmp_path / "dummy.whl"
    dummy_wheel.write_bytes(b"not-a-wheel")

    cases: list[tuple[list[str], dict[str, object]]] = [
        (
            [
                "build-sealed-sandbox-profile",
                "--seccomp-profile",
                str(seccomp_path),
            ],
            {
                "migration_run_context_locator": {},
                "oci_image_digest": "sha256:" + ("1" * 64),
                "runner_binary_digest": "sha256:" + ("2" * 64),
                "issued_at_utc": "2026-11-12T12:00:00Z",
                "valid_from_utc": "2026-11-01T00:00:00Z",
                "valid_until_utc": "2027-11-01T00:00:00Z",
                "unexpected_extra": True,
            },
        ),
        (
            [
                "build-wheel-provenance",
                "--repo",
                str(REPO_ROOT),
                "--wheel-out",
                str(tmp_path / "w.whl"),
            ],
            {
                "migration_run_context_locator": {},
                "build_run_id": "run-1",
                "built_at_utc": "2026-11-12T12:00:00Z",
                "unexpected_extra": True,
            },
        ),
        (
            [
                "build-wheel-boundary-report",
                "--wheel",
                str(dummy_wheel),
            ],
            {
                "migration_run_context_locator": {},
                "build_run_id": "run-1",
                "verified_at_utc": "2026-11-12T12:00:00Z",
                "source_commit_sha": "a" * 40,
                "build_backend_digest": "sha256:" + ("3" * 64),
                "unexpected_extra": True,
            },
        ),
        (
            [
                "build-mcp-rejection-report",
                "--wheel",
                str(dummy_wheel),
            ],
            {
                "migration_run_context_locator": {},
                "build_run_id": "run-1",
                "executed_at_utc": "2026-11-12T12:00:00Z",
                "source_commit_sha": "a" * 40,
                "build_backend_digest": "sha256:" + ("3" * 64),
                "unexpected_extra": True,
            },
        ),
    ]

    for idx, (prefix_args, bad_params) in enumerate(cases):
        p_file = tmp_path / f"bad_params_{idx}.json"
        p_file.write_text(json.dumps(bad_params), encoding="utf-8")
        out_file = tmp_path / f"bad_out_{idx}.json"
        rc = cli.main([*prefix_args, "--params", str(p_file), "--out", str(out_file)])
        captured = capsys.readouterr()
        assert rc == 1
        assert "expected exactly" in captured.err
        assert not out_file.exists()

    # Missing file path wraps OSError into ValueError -> exit code 1 cleanly
    rc_missing = cli.main(
        [
            "verify-sealed-sandbox-profile",
            "--in",
            str(tmp_path / "does_not_exist.json"),
            "--seccomp-profile",
            str(seccomp_path),
        ]
    )
    err_missing = capsys.readouterr().err
    assert rc_missing == 1
    assert "FileNotFoundError" in err_missing


