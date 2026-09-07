"""Builder + Git resolver for `legacy_step2_implementation_evidence/v1`.

ADR-0001 L2412-2426, L3159-3161, profile row L3549: this artifact is
NON-AUTHORIZING historical evidence. It resolves the exact Git identities and
protected-merge provenance of `DOCUMENTATION/IBVI_ADS_STEP2_READINESS_EVIDENCE.md`
and `DOCUMENTATION/IBVI_ADS_STEP2_AUTHORIZATION.md` in the pinned legacy repo,
requires state `STEP2_IMPLEMENTATION_AUTHORIZED_RUNTIME_BLOCKED`, and binds
W1-GATE protected merge `25cc756c5f46db9ee67f17844196c4301c977ad6`. It has no
same-run, expiry, nonce, reservation, credential, provider-call, deployment,
or execution authority and cannot occupy an authorization or effect-proof
slot. It carries the pinned legacy Git identity and no migration-run
authority — the envelope therefore never references a run context or a
Gate-2 receipt.

`resolve_legacy_step2_facts` is a pure Git-plumbing reader: it shells out to
`git` (list-argv subprocess, no shell, no network) against an already-cloned
`legacy_repo` and returns a plain `dict` of facts. `build_legacy_step2_evidence`
is a pure builder that turns those facts into the unsigned envelope.
"""
from __future__ import annotations

import copy
import hashlib
import re
import subprocess
from pathlib import Path
from typing import Any

from tools.governance.artifacts import _LEGACY_SOURCE_IDENTITY, _require_locator_type

LEGACY_STATE = "STEP2_IMPLEMENTATION_AUTHORIZED_RUNTIME_BLOCKED"
READINESS_PATH = "DOCUMENTATION/IBVI_ADS_STEP2_READINESS_EVIDENCE.md"
AUTHORIZATION_PATH = "DOCUMENTATION/IBVI_ADS_STEP2_AUTHORIZATION.md"
W1_GATE_MERGE_SHA = "25cc756c5f46db9ee67f17844196c4301c977ad6"

_DEFAULT_WAVE1_MERGES = {
    "W1A": "b4d4537f4df56248df872c51ab3cd7e3d1aed098",
    "W1B-G": "020d3e0c4a48ef9f059645eeb07968f68499c43b",
    "W1B-P": "a26f055dc7f9a4847310f21d34ba019da87bcca6",
}

_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_SHA256_PREFIXED = re.compile(r"^sha256:[0-9a-f]{64}$")
_DECISION_MARKER = b"**Decision:** Authorized"
_PR_NUMBER_RE = re.compile(r"\(#(\d+)\)\s*$")


def _run_git(legacy_repo: Path, args: list[str]) -> str:
    proc = subprocess.run(
        ["git", *args],
        cwd=str(legacy_repo),
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise ValueError(
            f"legacy_step2._run_git: 'git {' '.join(args)}' failed: {proc.stderr.strip()}"
        )
    return proc.stdout


def _blob_at(legacy_repo: Path, ref: str, path: str) -> str | None:
    proc = subprocess.run(
        ["git", "rev-parse", "-q", "--verify", f"{ref}:{path}"],
        cwd=str(legacy_repo),
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        return None
    return proc.stdout.strip()


def _introducing_pr(subject: str) -> int | None:
    match = _PR_NUMBER_RE.search(subject)
    return int(match.group(1)) if match else None


def _resolve_path_evidence(
    legacy_repo: Path, baseline_sha: str, path: str, *, presence_key: str
) -> dict[str, Any] | None:
    blob_oid = _blob_at(legacy_repo, baseline_sha, path)
    if blob_oid is None:
        return None

    content = subprocess.run(
        ["git", "cat-file", "-p", blob_oid],
        cwd=str(legacy_repo),
        capture_output=True,
        check=True,
    ).stdout

    introduced_log = _run_git(
        legacy_repo,
        ["log", "--diff-filter=A", "--format=%H", baseline_sha, "--", path],
    ).splitlines()
    if not introduced_log:
        raise ValueError(
            f"legacy_step2._resolve_path_evidence: no introducing commit found for {path!r}"
        )
    introduced_by_commit = introduced_log[-1]

    last_modified_log = _run_git(
        legacy_repo, ["log", "-1", "--format=%H", baseline_sha, "--", path]
    ).strip()

    subject = _run_git(
        legacy_repo, ["log", "-1", "--format=%s", introduced_by_commit]
    ).strip()

    evidence = {
        "path": path,
        "git_blob_oid": blob_oid,
        "file_content_sha256": "sha256:" + hashlib.sha256(content).hexdigest(),
        "byte_length": len(content),
        presence_key: (
            LEGACY_STATE.encode("ascii") in content
            if presence_key == "state_present"
            else _DECISION_MARKER in content
        ),
        "introduced_by_commit": introduced_by_commit,
        "introducing_pull_request": _introducing_pr(subject),
        "last_modified_by_commit": last_modified_log,
    }
    return evidence


def _resolve_w1_gate_presence(
    legacy_repo: Path, w1_gate_sha: str, path: str
) -> tuple[bool, str | None]:
    blob = _blob_at(legacy_repo, w1_gate_sha, path)
    return (blob is not None, blob)


def _is_ancestor(legacy_repo: Path, ancestor_sha: str, descendant_sha: str) -> bool:
    return (
        subprocess.run(
            ["git", "merge-base", "--is-ancestor", ancestor_sha, descendant_sha],
            cwd=str(legacy_repo),
            capture_output=True,
        ).returncode
        == 0
    )


def _apply_w1_gate_presence(
    legacy_repo: Path, evidence: dict[str, Any] | None, w1_gate_sha: str, path: str
) -> None:
    if evidence is None:
        return
    present, blob = _resolve_w1_gate_presence(legacy_repo, w1_gate_sha, path)
    evidence["present_in_w1_gate_tree"] = present
    evidence["w1_gate_tree_blob_oid"] = blob


def _resolve_wave1_facts(
    legacy_repo: Path, baseline_sha: str, merges: dict[str, str]
) -> dict[str, Any]:
    return {
        label: {"sha": sha, "is_ancestor": _is_ancestor(legacy_repo, sha, baseline_sha)}
        for label, sha in merges.items()
    }


def resolve_legacy_step2_facts(
    legacy_repo: Path,
    baseline_sha: str,
    *,
    w1_gate_sha: str = W1_GATE_MERGE_SHA,
    wave1_merges: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Resolve Git-plumbing facts for the two legacy Step 2 evidence files.

    OFFLINE, Git-only: every value is read via `git` subprocess calls against
    `legacy_repo` (already cloned locally); no network calls are made.
    `w1_gate_sha` and `wave1_merges` default to the real ADR-pinned constants
    but are accepted as parameters so tests can substitute fixture SHAs.
    Raises ValueError (wrapping the `git` stderr) if `baseline_sha` cannot be
    resolved in `legacy_repo`.

    IMPORTANT: the BUILDER always pins `wave1_protected_merges`/
    `w1_gate_protected_merge_sha` to the real `_DEFAULT_WAVE1_MERGES`/
    `W1_GATE_MERGE_SHA` constants and rejects any other SHA. A facts dict
    resolved against a fixture repo (via the overrides above) must have its
    `sha` values substituted back to the real constants before build — the
    CLI end-to-end test already does this.

    The returned facts carry `resolved_baseline.commit_sha`, the canonical id
    actually read; `build_legacy_step2_evidence` refuses facts whose resolved
    baseline is not the pinned legacy commit.
    """
    merges = dict(_DEFAULT_WAVE1_MERGES if wave1_merges is None else wave1_merges)

    # H1: keep the canonical 40-hex id the verification actually resolved (the
    # caller may have passed an abbreviated ref) and use it for every read, so
    # the facts can carry the identity the builder must compare to the pin.
    canonical_baseline = _run_git(
        legacy_repo, ["rev-parse", "--verify", f"{baseline_sha}^{{commit}}"]
    ).strip()
    if not _HEX40.fullmatch(canonical_baseline):
        raise ValueError(
            f"legacy_step2.resolve_legacy_step2_facts: rev-parse returned {canonical_baseline!r}, "
            "not a 40-hex commit id"
        )
    baseline_sha = canonical_baseline

    readiness = _resolve_path_evidence(
        legacy_repo, baseline_sha, READINESS_PATH, presence_key="state_present"
    )
    authorization = _resolve_path_evidence(
        legacy_repo, baseline_sha, AUTHORIZATION_PATH, presence_key="decision_authorized"
    )

    _apply_w1_gate_presence(legacy_repo, readiness, w1_gate_sha, READINESS_PATH)
    _apply_w1_gate_presence(legacy_repo, authorization, w1_gate_sha, AUTHORIZATION_PATH)

    w1_gate_is_ancestor = _is_ancestor(legacy_repo, w1_gate_sha, baseline_sha)
    w1_gate_type = _run_git(legacy_repo, ["cat-file", "-t", w1_gate_sha]).strip()
    wave1_facts = _resolve_wave1_facts(legacy_repo, baseline_sha, merges)

    return {
        "resolved_baseline": {"commit_sha": canonical_baseline},
        "readiness_evidence": readiness,
        "authorization_record": authorization,
        "w1_gate": {"sha": w1_gate_sha, "is_ancestor": w1_gate_is_ancestor, "type": w1_gate_type},
        "wave1_protected_merges": wave1_facts,
    }


# ---------------------------------------------------------------------------
# build_legacy_step2_evidence — P1 domain SMART-ADS:LEGACY-STEP2-EVIDENCE:V1
# ---------------------------------------------------------------------------


def _require_hex40(value: Any, where: str, key: str) -> None:
    """Exact type + fullmatch: `str` only, 40 lowercase hex, no trailing newline
    (`re.match` with `$` would accept one)."""
    if not isinstance(value, str) or not _HEX40.fullmatch(value):
        raise ValueError(f"{where}: {key} must be a string of 40 lowercase hex, got {value!r}")


def _validate_path_evidence(evidence: dict[str, Any], expected_path: str, where: str) -> None:
    if evidence.get("path") != expected_path:
        raise ValueError(f"{where}: path must be exactly {expected_path!r}")
    _require_hex40(evidence.get("git_blob_oid"), where, "git_blob_oid")
    digest = evidence.get("file_content_sha256")
    if not isinstance(digest, str) or not _SHA256_PREFIXED.fullmatch(digest):
        raise ValueError(f"{where}: file_content_sha256 must be 'sha256:<64 hex>'")
    byte_length = evidence.get("byte_length")
    if not isinstance(byte_length, int) or isinstance(byte_length, bool) or byte_length <= 0:
        raise ValueError(f"{where}: byte_length must be an int > 0")
    for key in ("introduced_by_commit", "last_modified_by_commit"):
        _require_hex40(evidence.get(key), where, key)
    pull_request = evidence.get("introducing_pull_request")
    if pull_request is not None and (
        isinstance(pull_request, bool) or not isinstance(pull_request, int) or pull_request <= 0
    ):
        raise ValueError(
            f"{where}: introducing_pull_request must be a positive int or null, got {pull_request!r}"
        )
    present = evidence.get("present_in_w1_gate_tree")
    if present is not True and present is not False:
        raise ValueError(
            f"{where}: present_in_w1_gate_tree must be exactly true or false, got {present!r}"
        )
    if present is True:
        _require_hex40(evidence.get("w1_gate_tree_blob_oid"), where, "w1_gate_tree_blob_oid")
    elif evidence.get("w1_gate_tree_blob_oid") is not None:
        raise ValueError(
            f"{where}: w1_gate_tree_blob_oid must be null when present_in_w1_gate_tree is false"
        )


_AUTHORITY_BLOCK: dict[str, Any] = {
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


_FORBIDDEN_KEY_NAMES = {"run", "run_context", "run_id"}
_ALLOWED_KEY_NAMES = frozenset({"same_run"})


def _reject_run_or_gate2_keys(value: Any, path: str = "$") -> None:
    """RUNBOOK §11: the envelope never references a run context or a Gate-2
    receipt. Walk every mapping and list/tuple/set; refuse any key containing
    'gate2' or named/prefixed 'run'/'run_' — hyphens are normalized to
    underscores before the check (so `run-id`/`Run-Context` are refused too)
    — except the keys in `_ALLOWED_KEY_NAMES`, an explicit allowlist for the
    declarative `same_run` flag of the authority block, which is the
    ADR-required statement that no same-run authority exists. A suffix like
    `my_run_id` or a word like `runtime`/`rerun` is not a match, by design."""
    if isinstance(value, dict):
        for key, child in value.items():
            lowered = str(key).lower().replace("-", "_")
            if lowered in _ALLOWED_KEY_NAMES:
                _reject_run_or_gate2_keys(child, f"{path}.{key}")
                continue
            if "gate2" in lowered or lowered in _FORBIDDEN_KEY_NAMES or lowered.startswith("run_"):
                raise ValueError(
                    f"build_legacy_step2_evidence: forbidden run/gate2 key {key!r} at {path}"
                )
            _reject_run_or_gate2_keys(child, f"{path}.{key}")
    elif isinstance(value, (list, tuple, set, frozenset)):
        for index, child in enumerate(value):
            _reject_run_or_gate2_keys(child, f"{path}[{index}]")


def _validate_resolved_baseline(facts: dict[str, Any]) -> None:
    """H1 (review of 01d8056): the envelope declares the pinned legacy identity,
    so the facts must prove they were resolved at exactly that commit. Facts
    resolved anywhere else — e.g. a descendant of the baseline that edits the
    readiness file — would otherwise be emitted under an identity they do not
    have. Missing, malformed or divergent identities are refused."""
    pinned = _LEGACY_SOURCE_IDENTITY["commit_sha"]
    resolved = facts.get("resolved_baseline")
    if not isinstance(resolved, dict):
        raise ValueError(
            "build_legacy_step2_evidence: facts.resolved_baseline must be an object "
            "{'commit_sha': <40 hex>} written by resolve_legacy_step2_facts; refusing to "
            f"pin an identity the facts do not carry; expected the pinned legacy baseline {pinned!r}"
        )
    commit_sha = resolved.get("commit_sha")
    if not isinstance(commit_sha, str) or not _HEX40.fullmatch(commit_sha):
        raise ValueError(
            "build_legacy_step2_evidence: facts.resolved_baseline.commit_sha must be 40 "
            f"lowercase hex, got {commit_sha!r}; expected the pinned legacy baseline {pinned!r}"
        )
    if commit_sha != pinned:
        raise ValueError(
            f"build_legacy_step2_evidence: facts.resolved_baseline.commit_sha {commit_sha!r} is "
            f"not the pinned legacy baseline {pinned!r}; refusing to emit evidence under the "
            "pinned identity"
        )


def _validate_facts_top_level(facts: dict[str, Any]) -> tuple[dict, dict, dict, dict]:
    readiness = facts.get("readiness_evidence")
    authorization = facts.get("authorization_record")
    w1_gate = facts.get("w1_gate")
    wave1 = facts.get("wave1_protected_merges")

    if not isinstance(readiness, dict):
        raise ValueError(
            "build_legacy_step2_evidence: facts.readiness_evidence must be an object "
            "(readiness must be present at the baseline; state_present is required True)"
        )
    if not isinstance(authorization, dict):
        raise ValueError(
            "build_legacy_step2_evidence: facts.authorization_record must be an object "
            "(decision_authorized is required True)"
        )
    if not isinstance(w1_gate, dict):
        raise ValueError("build_legacy_step2_evidence: facts.w1_gate must be an object")
    if not isinstance(wave1, dict) or set(wave1.keys()) != {"W1A", "W1B-G", "W1B-P"}:
        raise ValueError(
            "build_legacy_step2_evidence: facts.wave1_protected_merges must have exactly "
            "the members {'W1A', 'W1B-G', 'W1B-P'}"
        )
    return readiness, authorization, w1_gate, wave1


def _validate_readiness_and_authorization(readiness: dict, authorization: dict) -> None:
    _validate_path_evidence(readiness, READINESS_PATH, "build_legacy_step2_evidence")
    if readiness.get("state_present") is not True:
        raise ValueError(
            "build_legacy_step2_evidence: readiness_evidence.state_present must be True "
            f"(the ADR requires state {LEGACY_STATE!r} to be present)"
        )

    _validate_path_evidence(authorization, AUTHORIZATION_PATH, "build_legacy_step2_evidence")
    if authorization.get("decision_authorized") is not True:
        raise ValueError(
            "build_legacy_step2_evidence: authorization_record.decision_authorized must be True"
        )


def _validate_w1_gate_and_wave1(w1_gate: dict, wave1: dict) -> None:
    _require_hex40(w1_gate.get("sha"), "build_legacy_step2_evidence", "w1_gate.sha")
    if w1_gate.get("sha") != W1_GATE_MERGE_SHA:
        raise ValueError(
            f"build_legacy_step2_evidence: w1_gate.sha must equal {W1_GATE_MERGE_SHA!r}, "
            f"got {w1_gate.get('sha')!r}"
        )
    if w1_gate.get("is_ancestor") is not True:
        raise ValueError(
            "build_legacy_step2_evidence: w1_gate.is_ancestor must be True "
            "(W1-GATE must be an ancestor of the resolved baseline)"
        )
    if w1_gate.get("type") != "commit":
        raise ValueError("build_legacy_step2_evidence: w1_gate.type must be 'commit'")

    for label in ("W1A", "W1B-G", "W1B-P"):
        merge = wave1[label]
        if not isinstance(merge, dict):
            raise ValueError(
                f"build_legacy_step2_evidence: wave1_protected_merges[{label!r}] must be an object"
            )
        _require_hex40(
            merge.get("sha"),
            "build_legacy_step2_evidence",
            f"wave1_protected_merges[{label!r}].sha",
        )
        expected_sha = _DEFAULT_WAVE1_MERGES[label]
        if merge["sha"] != expected_sha:
            raise ValueError(
                f"build_legacy_step2_evidence: wave1_protected_merges[{label!r}].sha must "
                f"equal the ADR/legacy-pinned constant {expected_sha!r}, got {merge['sha']!r}"
            )
        if merge.get("is_ancestor") is not True:
            raise ValueError(
                f"build_legacy_step2_evidence: wave1_protected_merges[{label!r}].is_ancestor "
                "must be True"
            )


def _validate_evidence_scalars(
    key_registry_snapshot_locator: dict[str, Any], signer_key_id: str, resolved_at_utc: str
) -> None:
    _require_locator_type(
        key_registry_snapshot_locator,
        "smart_ads/key_authorization_registry/v1",
        "build_legacy_step2_evidence",
    )
    if not isinstance(signer_key_id, str) or not signer_key_id:
        raise ValueError("build_legacy_step2_evidence: signer_key_id must be a non-empty string")
    if not isinstance(resolved_at_utc, str) or not resolved_at_utc:
        raise ValueError(
            "build_legacy_step2_evidence: resolved_at_utc must be a non-empty string"
        )


def _shape_path_evidence_output(evidence: dict, presence_key: str) -> dict[str, Any]:
    return {
        "path": evidence["path"],
        "git_blob_oid": evidence["git_blob_oid"],
        "file_content_sha256": evidence["file_content_sha256"],
        "byte_length": evidence["byte_length"],
        presence_key: True,
        "introduced_by_commit": evidence["introduced_by_commit"],
        "introducing_pull_request": evidence.get("introducing_pull_request"),
        "last_modified_by_commit": evidence["last_modified_by_commit"],
        "present_in_w1_gate_tree": evidence["present_in_w1_gate_tree"],
        "w1_gate_tree_blob_oid": evidence["w1_gate_tree_blob_oid"],
    }


def _shape_wave1_output(wave1: dict[str, Any]) -> dict[str, Any]:
    """Emit the ADR/legacy-pinned constants (not the caller's values) for each
    wave1_protected_merges[label].sha, mirroring how w1_gate_protected_merge_sha
    is always the W1_GATE_MERGE_SHA constant rather than the caller's w1_gate.sha.
    `_validate_w1_gate_and_wave1` has already proven equality, so this is a pure
    reshape, not a silent substitution of unverified data.
    """
    return {
        label: {"sha": _DEFAULT_WAVE1_MERGES[label], "is_ancestor": wave1[label]["is_ancestor"]}
        for label in ("W1A", "W1B-G", "W1B-P")
    }


def build_legacy_step2_evidence(
    *,
    facts: dict[str, Any],
    resolved_at_utc: str,
    key_registry_snapshot_locator: dict[str, Any],
    signer_key_id: str,
) -> dict[str, Any]:
    """Build an unsigned `legacy_step2_implementation_evidence/v1` envelope.

    ADR-0001 L2412-2426: non-authorizing historical evidence binding the exact
    Git identities of the two legacy documentation files and the W1-GATE
    protected merge. `legacy_source_identity` and `required_state` are fixed
    by construction (not caller-supplied) since the artifact pins a single
    historical fact, not a parameterized claim. The facts must carry
    `resolved_baseline.commit_sha` equal to the pinned commit (H1).
    """
    _validate_resolved_baseline(facts)
    readiness, authorization, w1_gate, wave1 = _validate_facts_top_level(facts)
    _validate_readiness_and_authorization(readiness, authorization)
    _validate_w1_gate_and_wave1(w1_gate, wave1)
    _validate_evidence_scalars(key_registry_snapshot_locator, signer_key_id, resolved_at_utc)

    envelope = {
        "$schema": "smart_ads/legacy_step2_implementation_evidence/v1",
        "legacy_source_identity": copy.deepcopy(_LEGACY_SOURCE_IDENTITY),
        "required_state": LEGACY_STATE,
        "readiness_evidence": _shape_path_evidence_output(readiness, "state_present"),
        "authorization_record": _shape_path_evidence_output(
            authorization, "decision_authorized"
        ),
        "w1_gate_protected_merge_sha": W1_GATE_MERGE_SHA,
        "wave1_protected_merges": _shape_wave1_output(wave1),
        "authority": dict(_AUTHORITY_BLOCK),
        "resolved_at_utc": resolved_at_utc,
        "integrity": {
            "key_registry_snapshot_locator": copy.deepcopy(key_registry_snapshot_locator),
            "key_id": signer_key_id,
        },
    }
    _reject_run_or_gate2_keys(envelope)
    return envelope
