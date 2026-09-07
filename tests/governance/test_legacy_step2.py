"""Tests for tools.governance.legacy_step2 — legacy_step2_implementation_evidence/v1.

ADR-0001 L2412-2426, L3159-3161, profile row L3549: this artifact is
NON-AUTHORIZING historical evidence. It resolves the exact Git identities and
protected-merge provenance of the two legacy documentation files, requires
state `STEP2_IMPLEMENTATION_AUTHORIZED_RUNTIME_BLOCKED`, and binds the W1-GATE
protected merge. It carries no migration-run authority, so the envelope must
never reference a run context or a Gate-2 receipt.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import sys
import subprocess
from pathlib import Path

import pytest

from tools.governance import artifacts, legacy_step2, p1
from tools.governance.locator import make_locator

REGISTRY_LOCATOR = make_locator("smart_ads/key_authorization_registry/v1", b"registry-bytes")
POLICY_LOCATOR = make_locator("smart_ads/gate2_authority_policy/v1", b"policy-bytes")
REPO_ROOT = Path(__file__).resolve().parents[2]


def _git(cwd: Path, *args: str, env: dict | None = None) -> str:
    proc = subprocess.run(
        ["git", *args], cwd=str(cwd), capture_output=True, text=True, check=True, env=env
    )
    return proc.stdout.strip()


def _run_cli(*args: str, cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "tools.governance.cli", *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
    )


@pytest.fixture()
def legacy_repo(tmp_path: Path) -> dict:
    """A throwaway git repo reproducing the real shape at a smaller scale.

    Three "wave-1" commits (W1A, W1B-G, W1B-P) precede a commit that
    introduces READINESS.md (with the required state string, PR #18), a
    second commit that modifies READINESS.md and introduces AUTHORIZATION.md
    (with the Decision: Authorized marker, PR #19), and a final unrelated
    "baseline" commit.
    """
    repo = tmp_path / "legacy_repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    # Hermeticity: disable commit/tag signing locally so the suite passes on a
    # machine with global commit.gpgsign=true (no signing key is configured
    # for this throwaway fixture repo, so a real sign attempt would fail).
    _git(repo, "config", "user.email", "t@example.com")
    _git(repo, "config", "user.name", "t")
    _git(repo, "config", "commit.gpgsign", "false")
    _git(repo, "config", "tag.gpgsign", "false")

    readiness_path = repo / legacy_step2.READINESS_PATH
    authorization_path = repo / legacy_step2.AUTHORIZATION_PATH
    readiness_path.parent.mkdir(parents=True, exist_ok=True)
    authorization_path.parent.mkdir(parents=True, exist_ok=True)

    (repo / "w1a.txt").write_text("w1a\n", encoding="utf-8")
    _git(repo, "add", "w1a.txt")
    _git(repo, "commit", "-q", "-m", "w1a wave1 merge")
    w1a_sha = _git(repo, "rev-parse", "HEAD")

    (repo / "w1bg.txt").write_text("w1bg\n", encoding="utf-8")
    _git(repo, "add", "w1bg.txt")
    _git(repo, "commit", "-q", "-m", "w1bg wave1 merge")
    w1bg_sha = _git(repo, "rev-parse", "HEAD")

    (repo / "w1bp.txt").write_text("w1bp\n", encoding="utf-8")
    _git(repo, "add", "w1bp.txt")
    _git(repo, "commit", "-q", "-m", "w1bp wave1 merge")
    w1bp_sha = _git(repo, "rev-parse", "HEAD")

    readiness_v1 = (
        "state: STEP2_IMPLEMENTATION_AUTHORIZED_RUNTIME_BLOCKED\n"
    )
    readiness_path.write_text(readiness_v1, encoding="utf-8")
    _git(repo, "add", legacy_step2.READINESS_PATH)
    _git(
        repo, "commit", "-q", "-m",
        "docs(operator): assemble Step 2 readiness evidence (#18)",
    )
    w1_gate_sha = _git(repo, "rev-parse", "HEAD")
    readiness_blob_at_gate = _git(
        repo, "rev-parse", f"{w1_gate_sha}:{legacy_step2.READINESS_PATH}"
    )

    readiness_v2 = (
        "state: STEP2_IMPLEMENTATION_AUTHORIZED_RUNTIME_BLOCKED (v2)\n"
    )
    readiness_path.write_text(readiness_v2, encoding="utf-8")
    authorization_path.write_text("**Decision:** Authorized\n", encoding="utf-8")
    _git(repo, "add", legacy_step2.READINESS_PATH, legacy_step2.AUTHORIZATION_PATH)
    _git(
        repo, "commit", "-q", "-m",
        "docs(governance): authorize Wave 2 implementation (#19)",
    )
    authorization_intro_sha = _git(repo, "rev-parse", "HEAD")

    (repo / "unrelated.txt").write_text("unrelated\n", encoding="utf-8")
    _git(repo, "add", "unrelated.txt")
    _git(repo, "commit", "-q", "-m", "baseline commit")
    baseline_sha = _git(repo, "rev-parse", "HEAD")

    return {
        "root": repo,
        "baseline_sha": baseline_sha,
        "w1a_sha": w1a_sha,
        "w1bg_sha": w1bg_sha,
        "w1bp_sha": w1bp_sha,
        "w1_gate_sha": w1_gate_sha,
        "authorization_intro_sha": authorization_intro_sha,
        "readiness_v1_bytes": readiness_v1.encode("utf-8"),
        "readiness_v2_bytes": readiness_v2.encode("utf-8"),
        "authorization_bytes": b"**Decision:** Authorized\n",
        "readiness_blob_at_gate": readiness_blob_at_gate,
    }


def test_legacy_repo_fixture_is_hermetic_against_global_gpgsign(tmp_path: Path) -> None:
    """The legacy_repo fixture must build and commit even when the machine's
    global git config has commit.gpgsign=true and no usable signing key —
    which is exactly what a developer machine with commit signing enabled
    looks like. Every fixture commit is made with commit.gpgsign/tag.gpgsign
    disabled locally, so a hostile global config (simulated here via a
    throwaway HOME pointing at a broken gpg.program) must not break it.
    """
    hostile_home = tmp_path / "hostile_home"
    hostile_home.mkdir()
    (hostile_home / ".gitconfig").write_text(
        "[commit]\n\tgpgsign = true\n"
        "[tag]\n\tgpgsign = true\n"
        "[gpg]\n\tprogram = /nonexistent/gpg-binary-that-does-not-exist\n",
        encoding="utf-8",
    )
    hostile_env = dict(os.environ, HOME=str(hostile_home))

    repo = tmp_path / "hostile_repo"
    repo.mkdir()
    _git(repo, "init", "-q", env=hostile_env)
    _git(repo, "config", "user.email", "t@example.com", env=hostile_env)
    _git(repo, "config", "user.name", "t", env=hostile_env)
    _git(repo, "config", "commit.gpgsign", "false", env=hostile_env)
    _git(repo, "config", "tag.gpgsign", "false", env=hostile_env)
    (repo / "f.txt").write_text("hi\n", encoding="utf-8")
    _git(repo, "add", "f.txt", env=hostile_env)
    # This is the operation that fails with "fatal: failed to write commit
    # object" if commit.gpgsign is not disabled locally first.
    _git(repo, "commit", "-q", "-m", "hermetic test commit", env=hostile_env)
    sha = _git(repo, "rev-parse", "HEAD", env=hostile_env)
    assert len(sha) == 40


# ---------------------------------------------------------------------------
# resolve_legacy_step2_facts
# ---------------------------------------------------------------------------


def test_resolve_legacy_step2_facts_happy_path(legacy_repo: dict) -> None:
    facts = legacy_step2.resolve_legacy_step2_facts(
        legacy_repo["root"],
        legacy_repo["baseline_sha"],
        w1_gate_sha=legacy_repo["w1_gate_sha"],
        wave1_merges={
            "W1A": legacy_repo["w1a_sha"],
            "W1B-G": legacy_repo["w1bg_sha"],
            "W1B-P": legacy_repo["w1bp_sha"],
        },
    )

    readiness = facts["readiness_evidence"]
    assert readiness["path"] == legacy_step2.READINESS_PATH
    assert readiness["byte_length"] == len(legacy_repo["readiness_v2_bytes"])
    assert (
        readiness["file_content_sha256"]
        == "sha256:" + hashlib.sha256(legacy_repo["readiness_v2_bytes"]).hexdigest()
    )
    assert readiness["state_present"] is True
    assert readiness["introduced_by_commit"] == legacy_repo["w1_gate_sha"]
    assert readiness["introducing_pull_request"] == 18
    assert readiness["last_modified_by_commit"] == legacy_repo["authorization_intro_sha"]
    assert readiness["present_in_w1_gate_tree"] is True
    assert readiness["w1_gate_tree_blob_oid"] == legacy_repo["readiness_blob_at_gate"]

    authorization = facts["authorization_record"]
    assert authorization["path"] == legacy_step2.AUTHORIZATION_PATH
    assert authorization["byte_length"] == len(legacy_repo["authorization_bytes"])
    assert (
        authorization["file_content_sha256"]
        == "sha256:" + hashlib.sha256(legacy_repo["authorization_bytes"]).hexdigest()
    )
    assert authorization["decision_authorized"] is True
    assert authorization["introduced_by_commit"] == legacy_repo["authorization_intro_sha"]
    assert authorization["introducing_pull_request"] == 19
    assert authorization["last_modified_by_commit"] == legacy_repo["authorization_intro_sha"]
    assert authorization["present_in_w1_gate_tree"] is False
    assert authorization["w1_gate_tree_blob_oid"] is None

    assert facts["w1_gate"]["sha"] == legacy_repo["w1_gate_sha"]
    assert facts["w1_gate"]["is_ancestor"] is True
    assert facts["w1_gate"]["type"] == "commit"

    wave1 = facts["wave1_protected_merges"]
    assert wave1["W1A"] == {"sha": legacy_repo["w1a_sha"], "is_ancestor": True}
    assert wave1["W1B-G"] == {"sha": legacy_repo["w1bg_sha"], "is_ancestor": True}
    assert wave1["W1B-P"] == {"sha": legacy_repo["w1bp_sha"], "is_ancestor": True}


def test_resolve_legacy_step2_facts_records_the_canonical_baseline(legacy_repo: dict) -> None:
    """H1: the facts must carry the commit the resolver actually read, as the
    canonical 40-hex id, even when the caller passed an abbreviated ref."""
    facts = legacy_step2.resolve_legacy_step2_facts(
        legacy_repo["root"], legacy_repo["baseline_sha"][:7],
        w1_gate_sha=legacy_repo["w1_gate_sha"],
        wave1_merges={"W1A": legacy_repo["w1a_sha"], "W1B-G": legacy_repo["w1bg_sha"],
                      "W1B-P": legacy_repo["w1bp_sha"]},
    )
    assert "resolved_baseline" in facts, sorted(facts)
    assert facts["resolved_baseline"] == {"commit_sha": legacy_repo["baseline_sha"]}


def test_resolve_legacy_step2_facts_state_absent_when_not_present(
    legacy_repo: dict,
) -> None:
    """A baseline that predates the readiness commit must show state_present False."""
    facts = legacy_step2.resolve_legacy_step2_facts(
        legacy_repo["root"],
        legacy_repo["w1a_sha"],
        w1_gate_sha=legacy_repo["w1a_sha"],
        wave1_merges={
            "W1A": legacy_repo["w1a_sha"],
            "W1B-G": legacy_repo["w1a_sha"],
            "W1B-P": legacy_repo["w1a_sha"],
        },
    )
    assert facts["readiness_evidence"] is None
    assert facts["authorization_record"] is None


def test_resolve_legacy_step2_facts_rejects_bad_baseline(legacy_repo: dict) -> None:
    with pytest.raises(ValueError):
        legacy_step2.resolve_legacy_step2_facts(
            legacy_repo["root"],
            "0" * 40,
            w1_gate_sha=legacy_repo["w1_gate_sha"],
            wave1_merges={
                "W1A": legacy_repo["w1a_sha"],
                "W1B-G": legacy_repo["w1bg_sha"],
                "W1B-P": legacy_repo["w1bp_sha"],
            },
        )


def test_resolve_legacy_step2_facts_non_ancestor_w1_gate(legacy_repo: dict) -> None:
    """If the baseline predates the W1 gate, is_ancestor must be False, not raise."""
    facts = legacy_step2.resolve_legacy_step2_facts(
        legacy_repo["root"],
        legacy_repo["w1a_sha"],
        w1_gate_sha=legacy_repo["w1_gate_sha"],
        wave1_merges={
            "W1A": legacy_repo["w1a_sha"],
            "W1B-G": legacy_repo["w1bg_sha"],
            "W1B-P": legacy_repo["w1bp_sha"],
        },
    )
    assert facts["w1_gate"]["is_ancestor"] is False
    assert facts["wave1_protected_merges"]["W1B-G"]["is_ancestor"] is False


def test_resolve_legacy_step2_facts_defaults_to_real_constants(
    legacy_repo: dict,
) -> None:
    """Without explicit w1_gate_sha/wave1_merges, the real ADR-pinned constants are used.

    The tiny fixture repo does not contain the real, pinned upstream SHAs, so
    `git cat-file -t <W1_GATE_MERGE_SHA>` legitimately fails to resolve —
    this proves the default was substituted (a fixture-local SHA would have
    resolved and produced a boolean, not an error) and that the resolver
    surfaces the git failure as ValueError rather than crashing uncaught.
    """
    with pytest.raises(ValueError, match=legacy_step2.W1_GATE_MERGE_SHA):
        legacy_step2.resolve_legacy_step2_facts(
            legacy_repo["root"], legacy_repo["baseline_sha"]
        )


def test_default_wave1_merges_match_module_constants() -> None:
    """The default parameter values must be the real ADR-pinned SHAs."""
    assert legacy_step2._DEFAULT_WAVE1_MERGES == {
        "W1A": "b4d4537f4df56248df872c51ab3cd7e3d1aed098",
        "W1B-G": "020d3e0c4a48ef9f059645eeb07968f68499c43b",
        "W1B-P": "a26f055dc7f9a4847310f21d34ba019da87bcca6",
    }
    assert legacy_step2.W1_GATE_MERGE_SHA == "25cc756c5f46db9ee67f17844196c4301c977ad6"


# ---------------------------------------------------------------------------
# build_legacy_step2_evidence
# ---------------------------------------------------------------------------


def _valid_facts() -> dict:
    return {
        "resolved_baseline": {"commit_sha": artifacts._LEGACY_SOURCE_IDENTITY["commit_sha"]},
        "readiness_evidence": {
            "path": legacy_step2.READINESS_PATH,
            "git_blob_oid": "a" * 40,
            "file_content_sha256": "sha256:" + "b" * 64,
            "byte_length": 4743,
            "state_present": True,
            "introduced_by_commit": "c" * 40,
            "introducing_pull_request": 18,
            "last_modified_by_commit": "d" * 40,
            "present_in_w1_gate_tree": True,
            "w1_gate_tree_blob_oid": "e" * 40,
        },
        "authorization_record": {
            "path": legacy_step2.AUTHORIZATION_PATH,
            "git_blob_oid": "f" * 40,
            "file_content_sha256": "sha256:" + "1" * 64,
            "byte_length": 1988,
            "decision_authorized": True,
            "introduced_by_commit": "2" * 40,
            "introducing_pull_request": 19,
            "last_modified_by_commit": "2" * 40,
            "present_in_w1_gate_tree": False,
            "w1_gate_tree_blob_oid": None,
        },
        "w1_gate": {
            "sha": legacy_step2.W1_GATE_MERGE_SHA,
            "is_ancestor": True,
            "type": "commit",
        },
        "wave1_protected_merges": {
            label: {"sha": sha, "is_ancestor": True}
            for label, sha in legacy_step2._DEFAULT_WAVE1_MERGES.items()
        },
    }


def _build_kwargs(**overrides):
    base = dict(
        facts=_valid_facts(),
        resolved_at_utc="2026-09-07T12:00:00Z",
        key_registry_snapshot_locator=REGISTRY_LOCATOR,
        signer_key_id="key:ed25519:" + "0" * 64,
    )
    base.update(overrides)
    return base


def test_build_legacy_step2_evidence_happy_path() -> None:
    env = legacy_step2.build_legacy_step2_evidence(**_build_kwargs())
    assert env["$schema"] == "smart_ads/legacy_step2_implementation_evidence/v1"
    assert env["legacy_source_identity"] == artifacts._LEGACY_SOURCE_IDENTITY
    assert env["required_state"] == legacy_step2.LEGACY_STATE
    assert env["w1_gate_protected_merge_sha"] == legacy_step2.W1_GATE_MERGE_SHA

    assert set(env.keys()) == {
        "$schema",
        "legacy_source_identity",
        "required_state",
        "readiness_evidence",
        "authorization_record",
        "w1_gate_protected_merge_sha",
        "wave1_protected_merges",
        "authority",
        "resolved_at_utc",
        "integrity",
    }
    assert set(env["readiness_evidence"].keys()) == {
        "path", "git_blob_oid", "file_content_sha256", "byte_length",
        "state_present", "introduced_by_commit", "introducing_pull_request",
        "last_modified_by_commit", "present_in_w1_gate_tree",
        "w1_gate_tree_blob_oid",
    }
    assert set(env["authorization_record"].keys()) == {
        "path", "git_blob_oid", "file_content_sha256", "byte_length",
        "decision_authorized", "introduced_by_commit", "introducing_pull_request",
        "last_modified_by_commit", "present_in_w1_gate_tree",
        "w1_gate_tree_blob_oid",
    }
    assert set(env["wave1_protected_merges"].keys()) == {"W1A", "W1B-G", "W1B-P"}
    assert env["authority"] == {
        "non_authorizing": True,
        "same_run": False,
        "expiry": None,
        "nonce": None,
        "reservation": None,
        "credential": None,
        "provider_call": None,
        "deployment": None,
        "execution": None,
        "slot_eligibility": "legacy_provenance_only",
    }
    assert set(env["integrity"].keys()) == {"key_registry_snapshot_locator", "key_id"}
    assert env["integrity"]["key_id"] == "key:ed25519:" + "0" * 64
    assert env["integrity"]["key_registry_snapshot_locator"] == REGISTRY_LOCATOR


def test_build_legacy_step2_evidence_has_no_run_or_gate2_keys() -> None:
    """ADR: 'no migration-run authority' — no run_context/Gate-2-receipt reference anywhere.

    `authority.same_run` is itself the explicit ADR-required declaration that
    this artifact has no same-run authority, so "run" as a whole word (or as
    part of "run_context"/"run_id"/"gate2_receipt") is forbidden, but the
    literal key `same_run` is allowed by name.
    """
    env = legacy_step2.build_legacy_step2_evidence(**_build_kwargs())
    forbidden_keys = {"run_context", "run_context_locator", "run_id", "gate2_receipt_locator"}

    def _walk(value):
        if isinstance(value, dict):
            for k, v in value.items():
                assert k not in forbidden_keys, f"unexpected run-context/gate2 key: {k}"
                assert "gate2" not in k.lower(), f"unexpected gate2 key: {k}"
                _walk(v)
        elif isinstance(value, list):
            for item in value:
                _walk(item)

    _walk(env)


@pytest.mark.parametrize(
    "mutator",
    [
        lambda f: f["readiness_evidence"].update(path="wrong/path.md"),
        lambda f: f["authorization_record"].update(path="wrong/path.md"),
        lambda f: f["readiness_evidence"].update(git_blob_oid="not-hex"),
        lambda f: f["authorization_record"].update(git_blob_oid="not-hex"),
        lambda f: f["readiness_evidence"].update(file_content_sha256="deadbeef"),
        lambda f: f["authorization_record"].update(file_content_sha256="deadbeef"),
        lambda f: f["readiness_evidence"].update(byte_length=0),
        lambda f: f["authorization_record"].update(byte_length=-1),
        lambda f: f["readiness_evidence"].update(state_present=False),
        lambda f: f["authorization_record"].update(decision_authorized=False),
        lambda f: f["w1_gate"].update(sha="0" * 40),
        lambda f: f["w1_gate"].update(is_ancestor=False),
        lambda f: f["w1_gate"].update(type="tree"),
        lambda f: f["wave1_protected_merges"]["W1A"].update(is_ancestor=False),
        lambda f: f["wave1_protected_merges"]["W1B-G"].update(sha="not-hex"),
    ],
)
def test_build_legacy_step2_evidence_rejects_invalid_facts(mutator) -> None:
    facts = _valid_facts()
    mutator(facts)
    with pytest.raises(ValueError):
        legacy_step2.build_legacy_step2_evidence(**{**_build_kwargs(), "facts": facts})


_PINNED = artifacts._LEGACY_SOURCE_IDENTITY["commit_sha"]


@pytest.mark.parametrize(
    "mutator",
    [
        lambda f: f.pop("resolved_baseline"),
        lambda f: f.update(resolved_baseline=None),
        lambda f: f.update(resolved_baseline=_PINNED),
        lambda f: f.update(resolved_baseline={}),
        lambda f: f.update(resolved_baseline={"commit_sha": "0" * 40}),
        lambda f: f.update(resolved_baseline={"commit_sha": _PINNED + "\n"}),
        lambda f: f.update(resolved_baseline={"commit_sha": _PINNED.upper()}),
        lambda f: f.update(resolved_baseline={"commit_sha": _PINNED[:7]}),
        lambda f: f.update(resolved_baseline={"commit_sha": True}),
        lambda f: f.update(resolved_baseline={"commit_sha": {"run_id": _PINNED}}),
    ],
    ids=["missing", "null", "string-not-object", "empty", "other-commit", "trailing-newline",
         "uppercase", "abbreviated", "bool", "object"],
)
def test_build_legacy_step2_evidence_rejects_unbound_or_divergent_baseline(mutator) -> None:
    """H1: the builder declares the pinned identity, so the facts must prove they
    were resolved at exactly that commit. RED on 01d8056: every case builds."""
    facts = _valid_facts()
    mutator(facts)
    with pytest.raises(ValueError) as ei:
        legacy_step2.build_legacy_step2_evidence(**{**_build_kwargs(), "facts": facts})
    assert "resolved_baseline" in str(ei.value)


@pytest.mark.parametrize("label", ["W1A", "W1B-G", "W1B-P"])
def test_build_legacy_step2_evidence_rejects_wrong_wave1_sha(label: str) -> None:
    """Each wave1_protected_merges[label].sha must equal the ADR/legacy-pinned
    constant in _DEFAULT_WAVE1_MERGES, exactly like w1_gate.sha is compared to
    W1_GATE_MERGE_SHA. A different, well-formed 40-hex SHA (even with
    is_ancestor True) must be rejected."""
    facts = _valid_facts()
    facts["wave1_protected_merges"][label]["sha"] = "9" * 40
    with pytest.raises(ValueError, match=label):
        legacy_step2.build_legacy_step2_evidence(**{**_build_kwargs(), "facts": facts})


def test_build_legacy_step2_evidence_rejects_bad_locator() -> None:
    with pytest.raises(ValueError):
        legacy_step2.build_legacy_step2_evidence(
            **{**_build_kwargs(), "key_registry_snapshot_locator": POLICY_LOCATOR}
        )


def test_build_legacy_step2_evidence_rejects_empty_signer_key_id() -> None:
    with pytest.raises(ValueError):
        legacy_step2.build_legacy_step2_evidence(
            **{**_build_kwargs(), "signer_key_id": ""}
        )


def test_build_legacy_step2_evidence_rejects_empty_resolved_at_utc() -> None:
    with pytest.raises(ValueError):
        legacy_step2.build_legacy_step2_evidence(
            **{**_build_kwargs(), "resolved_at_utc": ""}
        )


def test_build_legacy_step2_evidence_does_not_mutate_inputs() -> None:
    facts = _valid_facts()
    facts_copy = copy.deepcopy(facts)
    locator_copy = copy.deepcopy(REGISTRY_LOCATOR)
    env = legacy_step2.build_legacy_step2_evidence(
        **{**_build_kwargs(), "facts": facts}
    )
    env["readiness_evidence"]["path"] = "tampered"
    env["integrity"]["key_registry_snapshot_locator"]["content_digest"] = "sha256:" + "0" * 64
    assert facts == facts_copy
    assert REGISTRY_LOCATOR == locator_copy


# ---------------------------------------------------------------------------
# P1 sign/verify roundtrip — domain SMART-ADS:LEGACY-STEP2-EVIDENCE:V1
# ---------------------------------------------------------------------------


@pytest.fixture()
def signing_key(tmp_path: Path) -> tuple[Path, bytes]:
    priv = tmp_path / "verifier.pem"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(priv)],
        check=True,
        capture_output=True,
    )
    raw32 = p1.raw_public_key_from_pem(priv)
    return priv, raw32


def test_domain_prefix_registered() -> None:
    assert (
        p1.DOMAIN_PREFIXES["legacy_step2_implementation_evidence/v1"]
        == "SMART-ADS:LEGACY-STEP2-EVIDENCE:V1\n"
    )


def test_p1_sign_and_verify_roundtrip(signing_key: tuple[Path, bytes]) -> None:
    priv, raw32 = signing_key
    key_id = p1.key_id_for(raw32)
    env = legacy_step2.build_legacy_step2_evidence(
        **{**_build_kwargs(), "signer_key_id": key_id}
    )
    prefix = p1.DOMAIN_PREFIXES["legacy_step2_implementation_evidence/v1"]
    signed = p1.sign_envelope(env, prefix, priv)
    p1.verify_envelope(signed, prefix, raw32)  # must not raise


def test_p1_verify_rejects_wrong_domain_prefix(signing_key: tuple[Path, bytes]) -> None:
    priv, raw32 = signing_key
    key_id = p1.key_id_for(raw32)
    env = legacy_step2.build_legacy_step2_evidence(
        **{**_build_kwargs(), "signer_key_id": key_id}
    )
    prefix = p1.DOMAIN_PREFIXES["legacy_step2_implementation_evidence/v1"]
    signed = p1.sign_envelope(env, prefix, priv)
    wrong_prefix = p1.DOMAIN_PREFIXES["gate2_approval_receipt/v1"]
    with pytest.raises(ValueError):
        p1.verify_envelope(signed, wrong_prefix, raw32)


# ---------------------------------------------------------------------------
# CLI: resolve-legacy-step2 -> build-legacy-step2-evidence -> sign -> verify -> store-put
# ---------------------------------------------------------------------------


def test_cli_resolve_build_sign_verify_store_roundtrip(
    tmp_path: Path, legacy_repo: dict
) -> None:
    verifier_key = tmp_path / "verifier.pem"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(verifier_key)],
        check=True,
        capture_output=True,
    )
    der = subprocess.run(
        ["openssl", "pkey", "-in", str(verifier_key), "-pubout", "-outform", "DER"],
        check=True,
        capture_output=True,
    ).stdout
    raw32_b64 = base64.b64encode(der[12:]).decode("ascii")
    key_id = "key:ed25519:" + hashlib.sha256(der[12:]).hexdigest()

    wave1_merges_path = tmp_path / "wave1_merges.json"
    wave1_merges_path.write_text(
        json.dumps(
            {
                "W1A": legacy_repo["w1a_sha"],
                "W1B-G": legacy_repo["w1bg_sha"],
                "W1B-P": legacy_repo["w1bp_sha"],
            }
        )
    )

    facts_out = tmp_path / "facts.json"
    r = _run_cli(
        "resolve-legacy-step2",
        "--legacy-repo", str(legacy_repo["root"]),
        "--baseline", legacy_repo["baseline_sha"],
        "--w1-gate-sha", legacy_repo["w1_gate_sha"],
        "--wave1-merges", str(wave1_merges_path),
        "--out", str(facts_out),
        cwd=REPO_ROOT,
    )
    assert r.returncode == 0, r.stderr
    facts = json.loads(facts_out.read_text())
    assert facts["readiness_evidence"]["state_present"] is True

    # H1: the resolver reports the fixture baseline it actually read; the
    # builder pins the real legacy commit, so — exactly like the W1-GATE/wave-1
    # swap below — the fixture identity is replaced by the pinned constant.
    assert facts["resolved_baseline"] == {"commit_sha": legacy_repo["baseline_sha"]}
    facts["resolved_baseline"]["commit_sha"] = artifacts._LEGACY_SOURCE_IDENTITY["commit_sha"]

    # The fixture repo cannot reproduce the real ADR-pinned W1-GATE/wave-1
    # SHAs by construction (Git SHAs are content-derived), so the resolver
    # was exercised end-to-end above against fixture SHAs to prove the CLI
    # plumbing works; here the W1-GATE/wave-1 identities are swapped for the
    # real constants the builder pins, matching how a real resolve (against
    # the actual mbras-campaigns clone) would report them.
    facts["w1_gate"]["sha"] = legacy_step2.W1_GATE_MERGE_SHA
    for label, sha in legacy_step2._DEFAULT_WAVE1_MERGES.items():
        facts["wave1_protected_merges"][label]["sha"] = sha
    facts_out.write_text(json.dumps(facts))

    build_params = tmp_path / "build_params.json"
    build_params.write_text(
        json.dumps(
            {
                "facts_path": str(facts_out),
                "resolved_at_utc": "2026-09-07T12:00:00Z",
                "key_registry_snapshot_locator": REGISTRY_LOCATOR,
                "signer_key_id": key_id,
            }
        )
    )
    evidence_out = tmp_path / "evidence.json"
    r = _run_cli(
        "build-legacy-step2-evidence",
        "--params", str(build_params),
        "--out", str(evidence_out),
        cwd=REPO_ROOT,
    )
    assert r.returncode == 0, r.stderr
    evidence = json.loads(evidence_out.read_text())
    assert evidence["$schema"] == "smart_ads/legacy_step2_implementation_evidence/v1"
    assert evidence["required_state"] == legacy_step2.LEGACY_STATE

    signed_out = tmp_path / "evidence_signed.json"
    r = _run_cli(
        "sign",
        "--schema", "legacy_step2_implementation_evidence/v1",
        "--key", str(verifier_key),
        "--in", str(evidence_out),
        "--out", str(signed_out),
        cwd=REPO_ROOT,
    )
    assert r.returncode == 0, r.stderr

    r = _run_cli(
        "verify",
        "--schema", "legacy_step2_implementation_evidence/v1",
        "--pubkey-raw-base64", raw32_b64,
        "--in", str(signed_out),
        cwd=REPO_ROOT,
    )
    assert r.returncode == 0, r.stderr

    store_root = tmp_path / "store"
    r = _run_cli(
        "store-put", "--root", str(store_root), "--in", str(signed_out), cwd=REPO_ROOT
    )
    assert r.returncode == 0, r.stderr
    locator = json.loads(r.stdout)
    assert locator["artifact_type"] == "smart_ads/legacy_step2_implementation_evidence/v1"

    locator_path = tmp_path / "locator.json"
    locator_path.write_text(json.dumps(locator))
    r = _run_cli(
        "store-get", "--root", str(store_root), "--locator", str(locator_path), cwd=REPO_ROOT
    )
    assert r.returncode == 0, r.stderr
    fetched = json.loads(r.stdout)
    assert fetched["$schema"] == "smart_ads/legacy_step2_implementation_evidence/v1"


def test_cli_refuses_facts_resolved_at_a_descendant_of_the_baseline(
    tmp_path: Path, legacy_repo: dict
) -> None:
    """H1 (review, High): a commit AFTER the baseline that edits the readiness
    file — keeping the required state and every W1 ancestor — resolves fine,
    but the builder must refuse to emit those facts under the pinned identity.
    RED on 01d8056: build exits 0 and the envelope carries the descendant's blob."""
    repo = legacy_repo["root"]
    readiness = repo / legacy_step2.READINESS_PATH
    readiness.write_text(
        readiness.read_text(encoding="utf-8") + "\nReview-only change after the baseline.\n",
        encoding="utf-8",
    )
    _git(repo, "add", legacy_step2.READINESS_PATH)
    _git(repo, "commit", "-q", "-m", "docs: post-baseline edit that must not be pinned")
    descendant = _git(repo, "rev-parse", "HEAD")
    assert descendant != legacy_repo["baseline_sha"]

    wave1_merges_path = tmp_path / "wave1_merges.json"
    wave1_merges_path.write_text(json.dumps({
        "W1A": legacy_repo["w1a_sha"], "W1B-G": legacy_repo["w1bg_sha"], "W1B-P": legacy_repo["w1bp_sha"],
    }))
    facts_out = tmp_path / "facts.json"
    r = _run_cli(
        "resolve-legacy-step2",
        "--legacy-repo", str(repo), "--baseline", descendant,
        "--w1-gate-sha", legacy_repo["w1_gate_sha"], "--wave1-merges", str(wave1_merges_path),
        "--out", str(facts_out), cwd=REPO_ROOT,
    )
    assert r.returncode == 0, r.stderr
    facts = json.loads(facts_out.read_text())
    assert facts["readiness_evidence"]["last_modified_by_commit"] == descendant
    assert facts["readiness_evidence"]["state_present"] is True
    # Same W1-GATE/wave-1 identity swap as the roundtrip test; the resolved
    # baseline is deliberately left as the resolver reported it.
    facts["w1_gate"]["sha"] = legacy_step2.W1_GATE_MERGE_SHA
    for label, sha in legacy_step2._DEFAULT_WAVE1_MERGES.items():
        facts["wave1_protected_merges"][label]["sha"] = sha
    facts_out.write_text(json.dumps(facts))

    build_params = tmp_path / "build_params.json"
    build_params.write_text(json.dumps({
        "facts_path": str(facts_out), "resolved_at_utc": "2026-09-07T12:00:00Z",
        "key_registry_snapshot_locator": REGISTRY_LOCATOR, "signer_key_id": "key:ed25519:" + "0" * 64,
    }))
    evidence_out = tmp_path / "evidence.json"
    r = _run_cli("build-legacy-step2-evidence", "--params", str(build_params), "--out", str(evidence_out), cwd=REPO_ROOT)
    assert r.returncode != 0, "builder emitted evidence for facts resolved at a descendant of the pinned baseline"
    assert "resolved_baseline" in r.stderr and descendant in r.stderr, r.stderr
    assert not evidence_out.exists()
    assert facts["resolved_baseline"] == {"commit_sha": descendant}


def test_cli_build_legacy_step2_evidence_requires_facts_or_facts_path(
    tmp_path: Path,
) -> None:
    params = tmp_path / "bad_params.json"
    params.write_text(
        json.dumps(
            {
                "resolved_at_utc": "2026-09-07T12:00:00Z",
                "key_registry_snapshot_locator": REGISTRY_LOCATOR,
                "signer_key_id": "key:ed25519:" + "0" * 64,
            }
        )
    )
    r = _run_cli(
        "build-legacy-step2-evidence",
        "--params", str(params),
        "--out", str(tmp_path / "out.json"),
        cwd=REPO_ROOT,
    )
    assert r.returncode != 0
    assert "facts" in r.stderr
