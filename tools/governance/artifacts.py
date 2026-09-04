"""Pure builders for the five Smart Ads Gate 2 governance artifacts.

Every builder returns a brand-new dict (no input mutation) representing an
UNSIGNED envelope: where the schema is P1-signed, the `integrity` object is
present with `key_id` and `key_registry_snapshot_locator` already filled in,
but WITHOUT the `content_digest` / `signature_base64` members — those are
added later by `tools.governance.p1.sign_envelope`.

Assumption (documented further in RUNBOOK.md): `key_authorization_registry/v1`
is the bootstrap artifact signed directly by the external trust anchor, not by
a registry snapshot of itself (ADR-0001 section 12.1: "A registry never
self-authenticates with one of its own keys"). Its own
`integrity.key_registry_snapshot_locator` is therefore `None` by construction,
verified against the trust anchor out of band, never against a registry.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
import subprocess
from typing import Any

from tools.governance.locator import validate_locator

_SHA256_PREFIXED = re.compile(r"^sha256:[0-9a-f]{64}$")
_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_LIFECYCLE_STATES = {"active", "revoked", "expired"}
_LEGACY_SOURCE_IDENTITY = {
    "repository": "mbras-tech/mbras-campaigns",
    "commit_sha": "d26c73d8508c7c3d43161fe36a80c44a46bf0f2d",
}
_ADR_PATH = "docs/adr/ADR-0001-smart-ads-read-gateway.md"


# ---------------------------------------------------------------------------
# cell_trust_anchor_config/v1 — NOT P1-signed (out-of-band, pinned by hash)
# ---------------------------------------------------------------------------


def build_trust_anchor_config(
    anchor_id: str,
    anchor_public_raw32: bytes,
    valid_from_utc: str,
    valid_until_utc: str,
    allowed_registry_artifact_types: list[str],
) -> dict[str, Any]:
    if len(anchor_public_raw32) != 32:
        raise ValueError(
            "build_trust_anchor_config: anchor_public_raw32 must be exactly 32 bytes, "
            f"got {len(anchor_public_raw32)}"
        )
    if not anchor_id:
        raise ValueError("build_trust_anchor_config: anchor_id must be non-empty")
    import base64

    return {
        "$schema": "smart_ads/cell_trust_anchor_config/v1",
        "trust_anchor_id": anchor_id,
        "public_key_base64": base64.b64encode(anchor_public_raw32).decode("ascii"),
        "public_key_sha256": "sha256:" + hashlib.sha256(anchor_public_raw32).hexdigest(),
        "validity": {"from": valid_from_utc, "until": valid_until_utc},
        "allowed_registry_artifact_types": sorted(set(allowed_registry_artifact_types)),
    }


def trust_anchor_pin(config: dict[str, Any]) -> str:
    from tools.governance.jcs import canonicalize

    return "sha256:" + hashlib.sha256(canonicalize(config)).hexdigest()


# ---------------------------------------------------------------------------
# key_authorization_registry/v1
# ---------------------------------------------------------------------------


def _validate_registry_entry(entry: dict[str, Any]) -> None:
    import base64

    required = {
        "key_id", "public_key_base64", "public_key_sha256", "principal", "tenant",
        "role", "validity", "lifecycle_state", "allowed_actions",
    }
    missing = required - set(entry.keys())
    if missing:
        raise ValueError(f"build_key_registry: entry missing members {sorted(missing)}")

    raw = base64.b64decode(entry["public_key_base64"], validate=True)
    if len(raw) != 32:
        raise ValueError("build_key_registry: entry public key must decode to 32 bytes")
    expected_key_id = "key:ed25519:" + hashlib.sha256(raw).hexdigest()
    if entry["key_id"] != expected_key_id:
        raise ValueError(
            f"build_key_registry: key_id {entry['key_id']!r} does not match "
            f"derived {expected_key_id!r}"
        )
    expected_sha = "sha256:" + hashlib.sha256(raw).hexdigest()
    if entry["public_key_sha256"] != expected_sha:
        raise ValueError("build_key_registry: public_key_sha256 does not match public key bytes")
    if entry["lifecycle_state"] not in _LIFECYCLE_STATES:
        raise ValueError(
            f"build_key_registry: lifecycle_state must be one of {sorted(_LIFECYCLE_STATES)}"
        )


def build_key_registry(
    trust_anchor_id: str,
    epoch: int,
    issued_at_utc: str,
    entries: list[dict[str, Any]],
    signer_key_id: str | None = None,
) -> dict[str, Any]:
    if epoch < 1:
        raise ValueError(f"build_key_registry: epoch must be >= 1, got {epoch}")

    entries_copy = copy.deepcopy(entries)
    for entry in entries_copy:
        _validate_registry_entry(entry)

    key_ids = [e["key_id"] for e in entries_copy]
    if len(set(key_ids)) != len(key_ids):
        raise ValueError("build_key_registry: duplicate key_id across entries")
    pubkeys = [e["public_key_base64"] for e in entries_copy]
    if len(set(pubkeys)) != len(pubkeys):
        raise ValueError("build_key_registry: duplicate public key across entries")

    sorted_entries = sorted(entries_copy, key=lambda e: e["key_id"])

    # Bootstrap assumption (see module docstring / RUNBOOK.md): the registry
    # is signed by the trust anchor's own Ed25519 key, resolved out of band
    # via cell_trust_anchor_config/v1 — never via a registry snapshot of
    # itself. `signer_key_id` must be the trust anchor's real key_id (as
    # produced by `p1.key_id_for`); it cannot be derived from the
    # human-readable `trust_anchor_id` label.
    return {
        "$schema": "smart_ads/key_authorization_registry/v1",
        "trust_anchor_id": trust_anchor_id,
        "epoch": epoch,
        "issued_at_utc": issued_at_utc,
        "entries": sorted_entries,
        "integrity": {
            "key_id": signer_key_id,
            "key_registry_snapshot_locator": None,
        },
    }


# ---------------------------------------------------------------------------
# gate2_authority_policy/v1
# ---------------------------------------------------------------------------


def build_gate2_authority_policy(
    repository: str,
    protected_ref: str,
    adr_path: str,
    ci_review_policy_digest: str,
    designated_principals: list[str],
    registry_locator: dict[str, Any],
    signer_key_id: str,
) -> dict[str, Any]:
    if not _SHA256_PREFIXED.match(ci_review_policy_digest):
        raise ValueError(
            "build_gate2_authority_policy: ci_review_policy_digest must match "
            "^sha256:[0-9a-f]{64}$"
        )
    if not designated_principals:
        raise ValueError("build_gate2_authority_policy: designated_principals must be non-empty")
    if any((not isinstance(p, str)) or (not p.strip()) for p in designated_principals):
        raise ValueError(
            "build_gate2_authority_policy: designated_principals must be non-blank strings"
        )
    cleaned = sorted({p.strip() for p in designated_principals})

    validate_locator(registry_locator)

    return {
        "$schema": "smart_ads/gate2_authority_policy/v1",
        "repository": repository,
        "protected_ref": protected_ref,
        "adr_path": adr_path,
        "ci_review_policy_digest": ci_review_policy_digest,
        "designated_principals": cleaned,
        "integrity": {
            "key_id": signer_key_id,
            "key_registry_snapshot_locator": copy.deepcopy(registry_locator),
        },
    }


# ---------------------------------------------------------------------------
# protected_merge_evidence/v1
# ---------------------------------------------------------------------------


def check_branch_protection_via_gh(repository: str, ref: str) -> dict[str, Any]:
    """Query GitHub branch protection for `repository`/`ref` via the `gh` CLI."""
    proc = subprocess.run(
        ["gh", "api", f"repos/{repository}/branches/{ref}"],
        capture_output=True,
        text=True,
        check=True,
    )
    data = json.loads(proc.stdout)
    protection = data.get("protection") or {}
    return {
        "protected": bool(data.get("protected", False)),
        "raw": data,
        "protection_enabled": bool(protection.get("enabled", False)),
    }


def _validate_merge_evidence_inputs(
    *,
    branch_protection_verified: bool,
    reviewed_head_sha: str,
    protected_merge_sha: str,
    adr_git_identity: dict[str, Any],
    required_ci_results: list[dict[str, Any]],
    exact_head_review_evidence: list[dict[str, Any]],
    branch_protection_policy: dict[str, Any],
    registry_locator: dict[str, Any],
) -> None:
    if branch_protection_verified is not True:
        raise ValueError(
            "protected_branch_not_verified: build_protected_merge_evidence refuses to "
            "produce evidence unless the caller explicitly proves the branch is protected "
            "(branch_protection_verified=True); main is unprotected today"
        )
    if not _HEX40.match(reviewed_head_sha):
        raise ValueError("build_protected_merge_evidence: reviewed_head_sha must be 40 lowercase hex")
    if not _HEX40.match(protected_merge_sha):
        raise ValueError("build_protected_merge_evidence: protected_merge_sha must be 40 lowercase hex")
    _validate_adr_git_identity(adr_git_identity)
    if not required_ci_results:
        raise ValueError("build_protected_merge_evidence: required_ci_results must be non-empty")
    if not exact_head_review_evidence:
        raise ValueError("build_protected_merge_evidence: exact_head_review_evidence must be non-empty")
    validate_locator(branch_protection_policy["locator"])
    if not _SHA256_PREFIXED.match(branch_protection_policy["digest"]):
        raise ValueError("build_protected_merge_evidence: branch_protection_policy.digest malformed")
    validate_locator(registry_locator)


def build_protected_merge_evidence(
    *,
    repository: str,
    protected_branch: str,
    pr_number: int,
    reviewed_head_sha: str,
    protected_merge_sha: str,
    adr_git_identity: dict[str, Any],
    required_ci_results: list[dict[str, Any]],
    exact_head_review_evidence: list[dict[str, Any]],
    branch_protection_policy: dict[str, Any],
    signer_key_id: str,
    registry_locator: dict[str, Any],
    branch_protection_verified: bool,
) -> dict[str, Any]:
    _validate_merge_evidence_inputs(
        branch_protection_verified=branch_protection_verified,
        reviewed_head_sha=reviewed_head_sha,
        protected_merge_sha=protected_merge_sha,
        adr_git_identity=adr_git_identity,
        required_ci_results=required_ci_results,
        exact_head_review_evidence=exact_head_review_evidence,
        branch_protection_policy=branch_protection_policy,
        registry_locator=registry_locator,
    )

    return {
        "$schema": "smart_ads/protected_merge_evidence/v1",
        "repository": repository,
        "protected_branch": protected_branch,
        "pr_number": pr_number,
        "reviewed_head_sha": reviewed_head_sha,
        "protected_merge_sha": protected_merge_sha,
        "adr_git_identity": copy.deepcopy(adr_git_identity),
        "required_ci_results": copy.deepcopy(required_ci_results),
        "exact_head_review_evidence": copy.deepcopy(exact_head_review_evidence),
        "branch_protection_policy": copy.deepcopy(branch_protection_policy),
        "integrity": {
            "key_id": signer_key_id,
            "key_registry_snapshot_locator": copy.deepcopy(registry_locator),
        },
    }


# ---------------------------------------------------------------------------
# gate2_approval_receipt/v1
# ---------------------------------------------------------------------------


def _validate_adr_git_identity(identity: dict[str, Any]) -> None:
    required = {"repository", "commit_sha", "path", "git_blob_oid", "file_content_sha256"}
    missing = required - set(identity.keys())
    if missing:
        raise ValueError(f"adr_git_identity missing members {sorted(missing)}")
    if not _HEX40.match(identity["commit_sha"]):
        raise ValueError("adr_git_identity.commit_sha must be 40 lowercase hex")
    if not _HEX40.match(identity["git_blob_oid"]):
        raise ValueError("adr_git_identity.git_blob_oid must be 40 lowercase hex")
    if not _SHA256_PREFIXED.match(identity["file_content_sha256"]):
        raise ValueError("adr_git_identity.file_content_sha256 must be 'sha256:<64 hex>'")
    if identity["path"] != _ADR_PATH:
        raise ValueError(f"adr_git_identity.path must be exactly {_ADR_PATH!r}")


def build_gate2_receipt(
    *,
    approved_adr_git_identity: dict[str, Any],
    legacy_source_identity: dict[str, Any],
    protected_merge_evidence_locator: dict[str, Any],
    protected_merge_sha: str,
    gate2_authority_policy_locator: dict[str, Any],
    approver_principal_ref: str,
    approved_at_utc: str,
    key_registry_snapshot_locator: dict[str, Any],
    signer_key_id: str,
) -> dict[str, Any]:
    _validate_adr_git_identity(approved_adr_git_identity)
    if legacy_source_identity != _LEGACY_SOURCE_IDENTITY:
        raise ValueError(
            f"build_gate2_receipt: legacy_source_identity must equal exactly "
            f"{_LEGACY_SOURCE_IDENTITY!r}, got {legacy_source_identity!r}"
        )
    if not _HEX40.match(protected_merge_sha):
        raise ValueError("build_gate2_receipt: protected_merge_sha must be 40 lowercase hex")
    if protected_merge_sha != approved_adr_git_identity["commit_sha"]:
        raise ValueError(
            "build_gate2_receipt: protected_merge_sha must equal "
            "approved_adr_git_identity.commit_sha"
        )
    validate_locator(protected_merge_evidence_locator)
    validate_locator(gate2_authority_policy_locator)
    validate_locator(key_registry_snapshot_locator)
    if not approver_principal_ref:
        raise ValueError("build_gate2_receipt: approver_principal_ref must be non-empty")

    return {
        "$schema": "smart_ads/gate2_approval_receipt/v1",
        "approved_adr_git_identity": copy.deepcopy(approved_adr_git_identity),
        "legacy_source_identity": copy.deepcopy(legacy_source_identity),
        "protected_merge_evidence_locator": copy.deepcopy(protected_merge_evidence_locator),
        "protected_merge_sha": protected_merge_sha,
        "gate2_authority_policy_locator": copy.deepcopy(gate2_authority_policy_locator),
        "approval_status": "approved",
        "approver_principal_ref": approver_principal_ref,
        "approved_at_utc": approved_at_utc,
        "integrity": {
            "key_registry_snapshot_locator": copy.deepcopy(key_registry_snapshot_locator),
            "key_id": signer_key_id,
        },
    }


# ---------------------------------------------------------------------------
# migration_run_context/v1 — P1 domain SMART-ADS:RUN-CONTEXT:V1
# ---------------------------------------------------------------------------


def _require_locator_type(
    locator: dict[str, Any], expected_artifact_type: str, where: str
) -> None:
    """Validate `locator` shape and pin its artifact_type.

    `validate_locator` checks structural well-formedness but accepts any
    non-empty artifact_type, so a locator resolving the wrong object kind would
    pass. Slots in these envelopes are typed, so the type is pinned here.
    """
    validate_locator(locator)
    if locator["artifact_type"] != expected_artifact_type:
        raise ValueError(
            f"{where}: locator artifact_type must be {expected_artifact_type!r}, "
            f"got {locator['artifact_type']!r}"
        )


def build_migration_run_context(
    *,
    gate2_receipt_locator: dict[str, Any],
    approved_adr_git_identity: dict[str, Any],
    legacy_source_identity: dict[str, Any],
    tenant_ref: str,
    cell_ref: str,
    run_id: str,
    created_at_utc: str,
    key_registry_snapshot_locator: dict[str, Any],
    signer_key_id: str,
) -> dict[str, Any]:
    """Build an unsigned `migration_run_context/v1` envelope.

    ADR-0001 L2891-2893: the run context is initialized from the Gate-2 receipt
    and binds its locator, the exact ADR identity, the separate legacy source
    identity, tenant, cell, the immutable key-registry snapshot, and creation
    time. A run not derived from a Gate-2 receipt cannot be initialized.
    """
    _validate_adr_git_identity(approved_adr_git_identity)
    if legacy_source_identity != _LEGACY_SOURCE_IDENTITY:
        raise ValueError(
            f"build_migration_run_context: legacy_source_identity must equal exactly "
            f"{_LEGACY_SOURCE_IDENTITY!r}, got {legacy_source_identity!r}"
        )
    _require_locator_type(
        gate2_receipt_locator,
        "smart_ads/gate2_approval_receipt/v1",
        "build_migration_run_context",
    )
    _require_locator_type(
        key_registry_snapshot_locator,
        "smart_ads/key_authorization_registry/v1",
        "build_migration_run_context",
    )
    for name, value in (
        ("tenant_ref", tenant_ref),
        ("cell_ref", cell_ref),
        ("run_id", run_id),
        ("created_at_utc", created_at_utc),
        ("signer_key_id", signer_key_id),
    ):
        if not isinstance(value, str) or not value:
            raise ValueError(
                f"build_migration_run_context: {name} must be a non-empty string"
            )

    return {
        "$schema": "smart_ads/migration_run_context/v1",
        "gate2_receipt_locator": copy.deepcopy(gate2_receipt_locator),
        "approved_adr_git_identity": copy.deepcopy(approved_adr_git_identity),
        "legacy_source_identity": copy.deepcopy(legacy_source_identity),
        "tenant_ref": tenant_ref,
        "cell_ref": cell_ref,
        "run_id": run_id,
        "created_at_utc": created_at_utc,
        "integrity": {
            "key_registry_snapshot_locator": copy.deepcopy(key_registry_snapshot_locator),
            "key_id": signer_key_id,
        },
    }


# ---------------------------------------------------------------------------
# delivery_mode_decision_receipt/v1 — P1 domain SMART-ADS:DELIVERY-MODE:V1
# ---------------------------------------------------------------------------


def build_delivery_mode_decision(
    *,
    gate2_receipt_locator: dict[str, Any],
    approved_adr_git_identity: dict[str, Any],
    run_context_locator: dict[str, Any],
    decided_by_principal_ref: str,
    decided_at_utc: str,
    key_registry_snapshot_locator: dict[str, Any],
    signer_key_id: str,
) -> dict[str, Any]:
    """Build an unsigned `delivery_mode_decision_receipt/v1` envelope.

    ADR-0001 L2895-2900: contains the exact Gate-2 receipt locator, the
    byte-identical approved ADR Git identity, the run-context locator, and
    `delivery_mode: manual`.

    `delivery_mode` is deliberately NOT a parameter. The v1 schema admits manual
    and only manual, and has no autonomous evidence field, so accepting a caller
    value would let a non-conforming mode be requested at all. Passing one is a
    TypeError, not a rejected value.
    """
    _validate_adr_git_identity(approved_adr_git_identity)
    _require_locator_type(
        gate2_receipt_locator,
        "smart_ads/gate2_approval_receipt/v1",
        "build_delivery_mode_decision",
    )
    _require_locator_type(
        run_context_locator,
        "smart_ads/migration_run_context/v1",
        "build_delivery_mode_decision",
    )
    _require_locator_type(
        key_registry_snapshot_locator,
        "smart_ads/key_authorization_registry/v1",
        "build_delivery_mode_decision",
    )
    for name, value in (
        ("decided_by_principal_ref", decided_by_principal_ref),
        ("decided_at_utc", decided_at_utc),
        ("signer_key_id", signer_key_id),
    ):
        if not isinstance(value, str) or not value:
            raise ValueError(
                f"build_delivery_mode_decision: {name} must be a non-empty string"
            )

    return {
        "$schema": "smart_ads/delivery_mode_decision_receipt/v1",
        "gate2_receipt_locator": copy.deepcopy(gate2_receipt_locator),
        "approved_adr_git_identity": copy.deepcopy(approved_adr_git_identity),
        "run_context_locator": copy.deepcopy(run_context_locator),
        "delivery_mode": "manual",
        "decided_by_principal_ref": decided_by_principal_ref,
        "decided_at_utc": decided_at_utc,
        "integrity": {
            "key_registry_snapshot_locator": copy.deepcopy(key_registry_snapshot_locator),
            "key_id": signer_key_id,
        },
    }
