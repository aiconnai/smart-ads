"""Tests for tools.governance.artifacts — builders for the five governance artifacts."""
from __future__ import annotations

import copy

import pytest

from tools.governance import artifacts
from tools.governance.locator import make_locator

ANCHOR_RAW32 = b"\x01" * 32
ANCHOR_KEY_ID = "key:ed25519:" + __import__("hashlib").sha256(ANCHOR_RAW32).hexdigest()

REGISTRY_LOCATOR = make_locator("smart_ads/key_authorization_registry/v1", b"registry-bytes")
POLICY_LOCATOR = make_locator("smart_ads/gate2_authority_policy/v1", b"policy-bytes")
MERGE_EVIDENCE_LOCATOR = make_locator("smart_ads/protected_merge_evidence/v1", b"merge-bytes")

VALID_ADR_IDENTITY = {
    "repository": "aiconnai/smart-ads",
    "commit_sha": "a" * 40,
    "path": "docs/adr/ADR-0001-smart-ads-read-gateway.md",
    "git_blob_oid": "b" * 40,
    "file_content_sha256": "sha256:" + "c" * 64,
}

LEGACY_SOURCE_IDENTITY = {
    "repository": "mbras-tech/mbras-campaigns",
    "commit_sha": "d26c73d8508c7c3d43161fe36a80c44a46bf0f2d",
}


# ---------------------------------------------------------------------------
# build_trust_anchor_config
# ---------------------------------------------------------------------------


def test_build_trust_anchor_config_happy_path() -> None:
    cfg = artifacts.build_trust_anchor_config(
        anchor_id="trust-anchor:governance-root",
        anchor_public_raw32=ANCHOR_RAW32,
        valid_from_utc="2026-01-01T00:00:00Z",
        valid_until_utc="2027-01-01T00:00:00Z",
        allowed_registry_artifact_types=[
            "smart_ads/key_authorization_registry/v1",
            "smart_ads/gate2_authority_policy/v1",
        ],
    )
    assert cfg["$schema"] == "smart_ads/cell_trust_anchor_config/v1"
    assert set(cfg.keys()) == {
        "$schema",
        "trust_anchor_id",
        "public_key_base64",
        "public_key_sha256",
        "validity",
        "allowed_registry_artifact_types",
    }
    assert cfg["validity"] == {"from": "2026-01-01T00:00:00Z", "until": "2027-01-01T00:00:00Z"}
    assert cfg["allowed_registry_artifact_types"] == [
        "smart_ads/gate2_authority_policy/v1",
        "smart_ads/key_authorization_registry/v1",
    ]
    assert "integrity" not in cfg


def test_build_trust_anchor_config_dedupes_and_sorts_types() -> None:
    cfg = artifacts.build_trust_anchor_config(
        anchor_id="a",
        anchor_public_raw32=ANCHOR_RAW32,
        valid_from_utc="2026-01-01T00:00:00Z",
        valid_until_utc="2027-01-01T00:00:00Z",
        allowed_registry_artifact_types=["z/1", "a/1", "a/1"],
    )
    assert cfg["allowed_registry_artifact_types"] == ["a/1", "z/1"]


def test_build_trust_anchor_config_bad_key_length() -> None:
    with pytest.raises(ValueError):
        artifacts.build_trust_anchor_config(
            anchor_id="a",
            anchor_public_raw32=b"short",
            valid_from_utc="2026-01-01T00:00:00Z",
            valid_until_utc="2027-01-01T00:00:00Z",
            allowed_registry_artifact_types=["a/1"],
        )


def test_trust_anchor_pin_is_stable_hash() -> None:
    cfg = artifacts.build_trust_anchor_config(
        anchor_id="a",
        anchor_public_raw32=ANCHOR_RAW32,
        valid_from_utc="2026-01-01T00:00:00Z",
        valid_until_utc="2027-01-01T00:00:00Z",
        allowed_registry_artifact_types=["a/1"],
    )
    pin1 = artifacts.trust_anchor_pin(cfg)
    pin2 = artifacts.trust_anchor_pin(copy.deepcopy(cfg))
    assert pin1 == pin2
    assert pin1.startswith("sha256:")


# ---------------------------------------------------------------------------
# build_key_registry
# ---------------------------------------------------------------------------


def _entry(raw32: bytes, principal: str = "principal:ronaldo") -> dict:
    import hashlib

    key_id = "key:ed25519:" + hashlib.sha256(raw32).hexdigest()
    import base64

    return {
        "key_id": key_id,
        "public_key_base64": base64.b64encode(raw32).decode("ascii"),
        "public_key_sha256": "sha256:" + hashlib.sha256(raw32).hexdigest(),
        "principal": principal,
        "tenant": "tenant:mbras",
        "role": "gate2_approver",
        "validity": {"from": "2026-01-01T00:00:00Z", "until": "2027-01-01T00:00:00Z"},
        "lifecycle_state": "active",
        "allowed_actions": [
            {"schema": "gate2_approval_receipt/v1", "action": "gate2_approve"}
        ],
    }


def test_build_key_registry_happy_path() -> None:
    entry = _entry(b"\x02" * 32)
    reg = artifacts.build_key_registry(
        trust_anchor_id="trust-anchor:governance-root",
        epoch=1,
        issued_at_utc="2026-01-01T00:00:00Z",
        entries=[entry],
        signer_key_id=ANCHOR_KEY_ID,
    )
    assert reg["$schema"] == "smart_ads/key_authorization_registry/v1"
    assert reg["trust_anchor_id"] == "trust-anchor:governance-root"
    assert reg["epoch"] == 1
    assert reg["entries"] == [entry]
    assert reg["integrity"]["key_registry_snapshot_locator"] is None
    assert reg["integrity"]["key_id"] == ANCHOR_KEY_ID
    assert set(reg.keys()) == {
        "$schema",
        "trust_anchor_id",
        "epoch",
        "issued_at_utc",
        "entries",
        "integrity",
    }
    assert set(reg["integrity"].keys()) == {"key_id", "key_registry_snapshot_locator"}


def test_build_key_registry_sorts_entries_by_key_id() -> None:
    e1 = _entry(b"\x02" * 32)
    e2 = _entry(b"\x01" * 32)
    reg = artifacts.build_key_registry(
        trust_anchor_id="a", epoch=1, issued_at_utc="2026-01-01T00:00:00Z", entries=[e1, e2]
    )
    key_ids = [e["key_id"] for e in reg["entries"]]
    assert key_ids == sorted(key_ids)


def test_build_key_registry_rejects_bad_epoch() -> None:
    with pytest.raises(ValueError):
        artifacts.build_key_registry(
            trust_anchor_id="a", epoch=0, issued_at_utc="x", entries=[_entry(b"\x03" * 32)]
        )


def test_build_key_registry_rejects_duplicate_key_id() -> None:
    entry = _entry(b"\x04" * 32)
    with pytest.raises(ValueError):
        artifacts.build_key_registry(
            trust_anchor_id="a",
            epoch=1,
            issued_at_utc="x",
            entries=[entry, copy.deepcopy(entry)],
        )


def test_build_key_registry_rejects_key_id_mismatch() -> None:
    entry = _entry(b"\x05" * 32)
    entry["key_id"] = "key:ed25519:" + "0" * 64
    with pytest.raises(ValueError):
        artifacts.build_key_registry(
            trust_anchor_id="a", epoch=1, issued_at_utc="x", entries=[entry]
        )


def test_build_key_registry_rejects_sha256_mismatch() -> None:
    entry = _entry(b"\x06" * 32)
    entry["public_key_sha256"] = "sha256:" + "0" * 64
    with pytest.raises(ValueError):
        artifacts.build_key_registry(
            trust_anchor_id="a", epoch=1, issued_at_utc="x", entries=[entry]
        )


def test_build_key_registry_rejects_bad_lifecycle_state() -> None:
    entry = _entry(b"\x07" * 32)
    entry["lifecycle_state"] = "banana"
    with pytest.raises(ValueError):
        artifacts.build_key_registry(
            trust_anchor_id="a", epoch=1, issued_at_utc="x", entries=[entry]
        )


def test_build_key_registry_input_entries_not_mutated() -> None:
    entries = [_entry(b"\x08" * 32)]
    original = copy.deepcopy(entries)
    artifacts.build_key_registry(
        trust_anchor_id="a", epoch=1, issued_at_utc="x", entries=entries
    )
    assert entries == original


# ---------------------------------------------------------------------------
# build_gate2_authority_policy
# ---------------------------------------------------------------------------


def test_build_gate2_authority_policy_happy_path() -> None:
    policy = artifacts.build_gate2_authority_policy(
        repository="aiconnai/smart-ads",
        protected_ref="main",
        adr_path="docs/adr/ADR-0001-smart-ads-read-gateway.md",
        ci_review_policy_digest="sha256:" + "a" * 64,
        designated_principals=["principal:ronaldo", "principal:ronaldo", "principal:alex"],
        registry_locator=REGISTRY_LOCATOR,
        signer_key_id=ANCHOR_KEY_ID,
    )
    assert policy["$schema"] == "smart_ads/gate2_authority_policy/v1"
    assert policy["designated_principals"] == ["principal:alex", "principal:ronaldo"]
    assert policy["integrity"]["key_id"] == ANCHOR_KEY_ID
    assert policy["integrity"]["key_registry_snapshot_locator"] == REGISTRY_LOCATOR
    assert set(policy.keys()) == {
        "$schema",
        "repository",
        "protected_ref",
        "adr_path",
        "ci_review_policy_digest",
        "designated_principals",
        "integrity",
    }
    assert set(policy["integrity"].keys()) == {"key_id", "key_registry_snapshot_locator"}


def test_build_gate2_authority_policy_rejects_bad_digest_format() -> None:
    with pytest.raises(ValueError):
        artifacts.build_gate2_authority_policy(
            repository="r",
            protected_ref="main",
            adr_path="p",
            ci_review_policy_digest="not-a-digest",
            designated_principals=["principal:x"],
            registry_locator=REGISTRY_LOCATOR,
            signer_key_id=ANCHOR_KEY_ID,
        )


def test_build_gate2_authority_policy_rejects_empty_principals() -> None:
    with pytest.raises(ValueError):
        artifacts.build_gate2_authority_policy(
            repository="r",
            protected_ref="main",
            adr_path="p",
            ci_review_policy_digest="sha256:" + "a" * 64,
            designated_principals=[],
            registry_locator=REGISTRY_LOCATOR,
            signer_key_id=ANCHOR_KEY_ID,
        )


def test_build_gate2_authority_policy_rejects_blank_principal() -> None:
    with pytest.raises(ValueError):
        artifacts.build_gate2_authority_policy(
            repository="r",
            protected_ref="main",
            adr_path="p",
            ci_review_policy_digest="sha256:" + "a" * 64,
            designated_principals=["  "],
            registry_locator=REGISTRY_LOCATOR,
            signer_key_id=ANCHOR_KEY_ID,
        )


# ---------------------------------------------------------------------------
# build_protected_merge_evidence
# ---------------------------------------------------------------------------


def _merge_evidence_kwargs(**overrides):
    base = dict(
        repository="aiconnai/smart-ads",
        protected_branch="main",
        pr_number=42,
        reviewed_head_sha="d" * 40,
        protected_merge_sha="e" * 40,
        adr_git_identity=VALID_ADR_IDENTITY,
        required_ci_results=[{"check": "tests", "status": "success"}],
        exact_head_review_evidence=[{"reviewer": "principal:ronaldo", "verdict": "approve"}],
        branch_protection_policy={"locator": POLICY_LOCATOR, "digest": "sha256:" + "f" * 64},
        signer_key_id=ANCHOR_KEY_ID,
        registry_locator=REGISTRY_LOCATOR,
        branch_protection_verified=True,
    )
    base.update(overrides)
    return base


def test_build_protected_merge_evidence_requires_explicit_true() -> None:
    kwargs = _merge_evidence_kwargs()
    del kwargs["branch_protection_verified"]
    with pytest.raises(TypeError):
        artifacts.build_protected_merge_evidence(**kwargs)


def test_build_protected_merge_evidence_raises_when_not_verified() -> None:
    kwargs = _merge_evidence_kwargs(branch_protection_verified=False)
    with pytest.raises(ValueError, match="protected_branch_not_verified"):
        artifacts.build_protected_merge_evidence(**kwargs)


def test_build_protected_merge_evidence_happy_path() -> None:
    kwargs = _merge_evidence_kwargs()
    evidence = artifacts.build_protected_merge_evidence(**kwargs)
    assert evidence["$schema"] == "smart_ads/protected_merge_evidence/v1"
    assert evidence["pr_number"] == 42
    assert evidence["adr_git_identity"] == VALID_ADR_IDENTITY
    assert evidence["required_ci_results"]
    assert evidence["exact_head_review_evidence"]
    assert set(evidence.keys()) == {
        "$schema",
        "repository",
        "protected_branch",
        "pr_number",
        "reviewed_head_sha",
        "protected_merge_sha",
        "adr_git_identity",
        "required_ci_results",
        "exact_head_review_evidence",
        "branch_protection_policy",
        "integrity",
    }
    assert set(evidence["integrity"].keys()) == {"key_id", "key_registry_snapshot_locator"}


def test_build_protected_merge_evidence_rejects_empty_ci_results() -> None:
    kwargs = _merge_evidence_kwargs(required_ci_results=[])
    with pytest.raises(ValueError):
        artifacts.build_protected_merge_evidence(**kwargs)


def test_build_protected_merge_evidence_rejects_empty_review_evidence() -> None:
    kwargs = _merge_evidence_kwargs(exact_head_review_evidence=[])
    with pytest.raises(ValueError):
        artifacts.build_protected_merge_evidence(**kwargs)


def test_build_protected_merge_evidence_is_under_50_lines() -> None:
    import inspect

    source_lines = inspect.getsource(artifacts.build_protected_merge_evidence).splitlines()
    assert len(source_lines) < 50, (
        f"build_protected_merge_evidence has {len(source_lines)} lines; "
        "extract validation into a helper to keep it under 50"
    )


def test_check_branch_protection_via_gh_parses_json(monkeypatch) -> None:
    import subprocess

    def fake_run(cmd, *a, **kw):
        class R:
            stdout = '{"protected": true, "other": 1}'
            returncode = 0

        assert cmd[0] == "gh"
        return R()

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = artifacts.check_branch_protection_via_gh("aiconnai/smart-ads", "main")
    assert result["protected"] is True


# ---------------------------------------------------------------------------
# build_gate2_receipt
# ---------------------------------------------------------------------------


def _receipt_kwargs(**overrides):
    base = dict(
        approved_adr_git_identity=VALID_ADR_IDENTITY,
        legacy_source_identity=LEGACY_SOURCE_IDENTITY,
        protected_merge_evidence_locator=MERGE_EVIDENCE_LOCATOR,
        protected_merge_sha=VALID_ADR_IDENTITY["commit_sha"],
        gate2_authority_policy_locator=POLICY_LOCATOR,
        approver_principal_ref="principal:ronaldo",
        approved_at_utc="2026-09-03T00:00:00Z",
        key_registry_snapshot_locator=REGISTRY_LOCATOR,
        signer_key_id=ANCHOR_KEY_ID,
    )
    base.update(overrides)
    return base


def test_build_gate2_receipt_happy_path() -> None:
    receipt = artifacts.build_gate2_receipt(**_receipt_kwargs())
    assert receipt["$schema"] == "smart_ads/gate2_approval_receipt/v1"
    assert receipt["approval_status"] == "approved"
    assert receipt["approved_adr_git_identity"] == VALID_ADR_IDENTITY
    assert receipt["legacy_source_identity"] == LEGACY_SOURCE_IDENTITY
    assert receipt["integrity"]["key_registry_snapshot_locator"] == REGISTRY_LOCATOR
    # ADR-0001 L2843-2875: exactly these top-level members, no more, no less.
    assert set(receipt.keys()) == {
        "$schema",
        "approved_adr_git_identity",
        "legacy_source_identity",
        "protected_merge_evidence_locator",
        "protected_merge_sha",
        "gate2_authority_policy_locator",
        "approval_status",
        "approver_principal_ref",
        "approved_at_utc",
        "integrity",
    }
    assert set(receipt["integrity"].keys()) == {"key_id", "key_registry_snapshot_locator"}


def test_build_gate2_receipt_rejects_bad_sha_length() -> None:
    bad_identity = dict(VALID_ADR_IDENTITY, commit_sha="short")
    with pytest.raises(ValueError):
        artifacts.build_gate2_receipt(
            **_receipt_kwargs(
                approved_adr_git_identity=bad_identity, protected_merge_sha="short"
            )
        )


def test_build_gate2_receipt_rejects_wrong_legacy_source_identity() -> None:
    with pytest.raises(ValueError):
        artifacts.build_gate2_receipt(
            **_receipt_kwargs(legacy_source_identity={"repository": "wrong/repo", "commit_sha": "a" * 40})
        )


def test_build_gate2_receipt_rejects_mismatched_merge_sha() -> None:
    with pytest.raises(ValueError):
        artifacts.build_gate2_receipt(**_receipt_kwargs(protected_merge_sha="f" * 40))


def test_build_gate2_receipt_rejects_bad_locator() -> None:
    bad_locator = dict(REGISTRY_LOCATOR)
    bad_locator["extra"] = "x"
    with pytest.raises(ValueError):
        artifacts.build_gate2_receipt(
            **_receipt_kwargs(key_registry_snapshot_locator=bad_locator)
        )


def test_build_gate2_receipt_rejects_bad_file_content_sha256_prefix() -> None:
    bad_identity = dict(VALID_ADR_IDENTITY, file_content_sha256="deadbeef")
    with pytest.raises(ValueError):
        artifacts.build_gate2_receipt(
            **_receipt_kwargs(approved_adr_git_identity=bad_identity)
        )


def test_build_gate2_receipt_rejects_wrong_path() -> None:
    bad_identity = dict(VALID_ADR_IDENTITY, path="docs/adr/WRONG.md")
    with pytest.raises(ValueError):
        artifacts.build_gate2_receipt(
            **_receipt_kwargs(approved_adr_git_identity=bad_identity)
        )


def test_build_gate2_receipt_inputs_not_mutated() -> None:
    kwargs = _receipt_kwargs()
    identity_copy = copy.deepcopy(kwargs["approved_adr_git_identity"])
    artifacts.build_gate2_receipt(**kwargs)
    assert kwargs["approved_adr_git_identity"] == identity_copy


# ---------------------------------------------------------------------------
# build_migration_run_context — ADR-0001 L2891-2893, domain SMART-ADS:RUN-CONTEXT:V1
# ---------------------------------------------------------------------------

GATE2_RECEIPT_LOCATOR = make_locator(
    "smart_ads/gate2_approval_receipt/v1", b"receipt-bytes"
)


def _run_context_kwargs(**overrides):
    base = dict(
        gate2_receipt_locator=GATE2_RECEIPT_LOCATOR,
        approved_adr_git_identity=VALID_ADR_IDENTITY,
        legacy_source_identity=LEGACY_SOURCE_IDENTITY,
        tenant_ref="tenant:aiconnai",
        cell_ref="cell:smart-ads-migration",
        run_id="run:" + "0" * 32,
        created_at_utc="2026-09-04T14:00:00Z",
        key_registry_snapshot_locator=REGISTRY_LOCATOR,
        signer_key_id=ANCHOR_KEY_ID,
    )
    base.update(overrides)
    return base


def test_build_migration_run_context_happy_path() -> None:
    ctx = artifacts.build_migration_run_context(**_run_context_kwargs())
    assert ctx["$schema"] == "smart_ads/migration_run_context/v1"
    assert ctx["gate2_receipt_locator"] == GATE2_RECEIPT_LOCATOR
    assert ctx["approved_adr_git_identity"] == VALID_ADR_IDENTITY
    assert ctx["legacy_source_identity"] == LEGACY_SOURCE_IDENTITY
    # ADR-0001 L2891-2893: binds receipt locator, exact ADR identity, separate
    # legacy source identity, tenant, cell, key-registry snapshot, creation time.
    assert set(ctx.keys()) == {
        "$schema",
        "gate2_receipt_locator",
        "approved_adr_git_identity",
        "legacy_source_identity",
        "tenant_ref",
        "cell_ref",
        "run_id",
        "created_at_utc",
        "integrity",
    }
    assert set(ctx["integrity"].keys()) == {"key_id", "key_registry_snapshot_locator"}


def test_build_migration_run_context_rejects_wrong_legacy_source_identity() -> None:
    with pytest.raises(ValueError):
        artifacts.build_migration_run_context(
            **_run_context_kwargs(
                legacy_source_identity={"repository": "x/y", "commit_sha": "d" * 40}
            )
        )


def test_build_migration_run_context_rejects_bad_adr_identity() -> None:
    with pytest.raises(ValueError):
        artifacts.build_migration_run_context(
            **_run_context_kwargs(
                approved_adr_git_identity=dict(VALID_ADR_IDENTITY, commit_sha="short")
            )
        )


def test_build_migration_run_context_rejects_empty_tenant_or_cell() -> None:
    for field in ("tenant_ref", "cell_ref", "run_id"):
        with pytest.raises(ValueError):
            artifacts.build_migration_run_context(**_run_context_kwargs(**{field: ""}))


def test_build_migration_run_context_does_not_mutate_inputs() -> None:
    identity = copy.deepcopy(VALID_ADR_IDENTITY)
    locator = copy.deepcopy(GATE2_RECEIPT_LOCATOR)
    ctx = artifacts.build_migration_run_context(
        **_run_context_kwargs(
            approved_adr_git_identity=identity, gate2_receipt_locator=locator
        )
    )
    ctx["approved_adr_git_identity"]["commit_sha"] = "f" * 40
    ctx["gate2_receipt_locator"]["content_digest"] = "sha256:" + "0" * 64
    assert identity == VALID_ADR_IDENTITY
    assert locator == GATE2_RECEIPT_LOCATOR


# ---------------------------------------------------------------------------
# build_delivery_mode_decision — ADR-0001 L2895-2900, domain SMART-ADS:DELIVERY-MODE:V1
# ---------------------------------------------------------------------------

RUN_CONTEXT_LOCATOR = make_locator(
    "smart_ads/migration_run_context/v1", b"run-context-bytes"
)


def _delivery_kwargs(**overrides):
    base = dict(
        gate2_receipt_locator=GATE2_RECEIPT_LOCATOR,
        approved_adr_git_identity=VALID_ADR_IDENTITY,
        run_context_locator=RUN_CONTEXT_LOCATOR,
        decided_by_principal_ref="principal:ronaldo",
        decided_at_utc="2026-09-04T14:05:00Z",
        key_registry_snapshot_locator=REGISTRY_LOCATOR,
        signer_key_id=ANCHOR_KEY_ID,
    )
    base.update(overrides)
    return base


def test_build_delivery_mode_decision_happy_path() -> None:
    rec = artifacts.build_delivery_mode_decision(**_delivery_kwargs())
    assert rec["$schema"] == "smart_ads/delivery_mode_decision_receipt/v1"
    # ADR-0001 L2895-2900: delivery_mode is manual, and only manual.
    assert rec["delivery_mode"] == "manual"
    assert rec["gate2_receipt_locator"] == GATE2_RECEIPT_LOCATOR
    assert rec["approved_adr_git_identity"] == VALID_ADR_IDENTITY
    assert rec["run_context_locator"] == RUN_CONTEXT_LOCATOR
    assert set(rec.keys()) == {
        "$schema",
        "gate2_receipt_locator",
        "approved_adr_git_identity",
        "run_context_locator",
        "delivery_mode",
        "decided_by_principal_ref",
        "decided_at_utc",
        "integrity",
    }
    # ADR-0001 L2899: "The v1 schema has no autonomous evidence field."
    assert "autonomous_evidence" not in rec
    assert not any("autonomous" in k for k in rec)


def test_build_delivery_mode_decision_rejects_non_manual_mode() -> None:
    """delivery_mode is not a caller-supplied value; manual is the only legal mode."""
    with pytest.raises(TypeError):
        artifacts.build_delivery_mode_decision(
            **_delivery_kwargs(), delivery_mode="autonomous"
        )


def test_build_delivery_mode_decision_rejects_bad_adr_identity() -> None:
    with pytest.raises(ValueError):
        artifacts.build_delivery_mode_decision(
            **_delivery_kwargs(
                approved_adr_git_identity=dict(VALID_ADR_IDENTITY, git_blob_oid="nope")
            )
        )


def test_build_delivery_mode_decision_rejects_wrong_locator_type() -> None:
    """run_context_locator must resolve a migration_run_context/v1, not anything else."""
    with pytest.raises(ValueError):
        artifacts.build_delivery_mode_decision(
            **_delivery_kwargs(run_context_locator=POLICY_LOCATOR)
        )


def test_build_delivery_mode_decision_does_not_mutate_inputs() -> None:
    identity = copy.deepcopy(VALID_ADR_IDENTITY)
    rec = artifacts.build_delivery_mode_decision(
        **_delivery_kwargs(approved_adr_git_identity=identity)
    )
    rec["approved_adr_git_identity"]["path"] = "tampered"
    assert identity == VALID_ADR_IDENTITY
