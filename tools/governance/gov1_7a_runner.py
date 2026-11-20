"""Pinned legacy `d26c73d` blob resolver, isolated `0dbdfede` AST reducer, and 7A OCI runner."""
from __future__ import annotations

import __future__
import ast
import builtins
from collections.abc import Callable, Mapping, Sequence
import copy
import datetime
import decimal
import hashlib
import json
import os
from pathlib import Path
import re
from types import MappingProxyType
from typing import Any, Final, Protocol, cast, runtime_checkable
import unicodedata

from tools.governance import p1
from tools.governance.decomposition_scope import run_git_offline
from tools.governance.gov1_7a_negative import (
    _KEY_REGISTRY_SCHEMA, _SHARED_RUNTIME_16_FIELDS, _exact_str, _hex40_str, _key_id_str,
    _non_empty_nfc_str, _opaque_ref_str, _sha256_str, _strict_str, _utc_sec_micros,
    _validate_resource_limits_dict, _validate_runtime_readback_dict, _verify_p1_integrity,
)
from tools.governance.gov1_7a_replay_helpers import _parse_iso_date, validate_resource_ref_str
from tools.governance.gov1_sandbox import verify_sealed_sandbox_profile
from tools.governance.jcs import canonicalize, loads_strict
from tools.governance.locator import digest, exact_fields, validate_locator

GIT_ARTIFACT_PROVENANCE_SCHEMA: Final[str] = "smart_ads/git_artifact_provenance/v1"
EXPECTED_RESOURCE_INVENTORY_SCHEMA: Final[str] = "smart_ads/expected_resource_inventory/v1"
PRIVATE_REGISTRY_SNAPSHOT_SCHEMA: Final[str] = "smart_ads/private_registry_snapshot/v1"

PINNED_LEGACY_REPO: Final[str] = "mbras-tech/mbras-campaigns"
PINNED_LEGACY_COMMIT: Final[str] = "d26c73d8508c7c3d43161fe36a80c44a46bf0f2d"
PINNED_PIPEBOARD_D26_SPECS: Final[tuple[tuple[str, str, str, str], ...]] = (
    ("reducer", "scripts/operator/meta_daily_contract.py", "0dbdfede6c4a9eaffb35197118e80d8d72507335", "sha256:9e5b2f24a05029980748a9e7a8ae40e00fedc30b9bdf07be532d8a55a7eab9c9"),
    ("frozen_config", "config/operator/meta_daily_get_insights_v1.yaml", "e0c86c24b0a5ac2aa761406bd6df7c4643b99af9", "sha256:08591f51a13424115dc1f138753cbee140403ae8c132848e495d367ec71f480e"),
    ("generic_gate_limitations", "scripts/meta_ads/pipeboard_mcp.py", "434be6136972c4316a4593f3fc63250b79eb8f95", "sha256:b2fd1efd242067f08a7e0d4445076179736c5cd3e8adfc3181af0778ed7b4206"),
    ("strict_transport", "scripts/operator/daily_strict_transports.py", "dfcaab5c2fa5c57384cfc5052acbf9aedf3d8ae1", "sha256:252c078d83ccf7eb726a19aaf226882731d55389c2c8f907491f955b8535e6ac"),
    ("transport_limits", "scripts/pipeboard_limits.py", "306d2b1f5eae7084f5c1daca7f042e1b1d89350b", "sha256:cb1b73273d1942fdc9fc334639bd74eaddcf6af3e65a02a29eb8b60f94ff0ce5"),
)
_LIMITS_SPEC: Final[tuple[str, str, str]] = ("scripts/pipeboard_limits.py", "306d2b1f5eae7084f5c1daca7f042e1b1d89350b", "sha256:cb1b73273d1942fdc9fc334639bd74eaddcf6af3e65a02a29eb8b60f94ff0ce5")
_REDUCER_SPEC: Final[tuple[str, str, str]] = ("scripts/operator/meta_daily_contract.py", "0dbdfede6c4a9eaffb35197118e80d8d72507335", "sha256:9e5b2f24a05029980748a9e7a8ae40e00fedc30b9bdf07be532d8a55a7eab9c9")
_ALLOWED_REDUCER_ASSIGNS: Final[frozenset[str]] = frozenset({"MAX_ROWS", "_INTEGER_TEXT", "_MONEY_TEXT", "_META_CAMPAIGN_ID", "_ROW_KEYS"})
_ALLOWED_REDUCER_FUNCS: Final[frozenset[str]] = frozenset({"_load_text_payload", "_integer_metric", "_spend_minor", "normalize_meta_result"})
_RESTRICTED_REDUCER_BUILTINS: Final[Mapping[str, Any]] = MappingProxyType({
    "__build_class__": builtins.__build_class__, "Exception": Exception, "ValueError": ValueError, "bool": bool,
    "dict": dict, "frozenset": frozenset, "int": int, "isinstance": isinstance, "len": len, "list": list,
    "set": set, "str": str, "tuple": tuple,
})


@runtime_checkable
class SealedOciSupervisorPort(Protocol):
    """Outer Linux OCI cgroup-v2 supervisor port for hermetic 7A execution."""

    def readback_sandbox_environment(self) -> Mapping[str, Any]: ...

    def readback_effective_resource_limits(self) -> Mapping[str, Any]: ...

    def execute_7a_corpus(
        self,
        *,
        wheel_bytes: bytes,
        corpus_bytes: bytes,
        sandbox_profile_payload: Mapping[str, Any],
        resolved_d26_blobs: Mapping[str, bytes],
        reducer: Callable[[dict[str, Any]], list[dict[str, int]]],
    ) -> Mapping[str, Any]: ...


def compute_git_blob_oid(raw_bytes: bytes) -> str:
    """Compute lowercase 40-hex Git blob SHA-1 OID for `raw_bytes`."""
    if type(raw_bytes) is not bytes:
        raise ValueError(f"raw_bytes: expected bytes, got {type(raw_bytes).__name__}")
    header = b"blob " + str(len(raw_bytes)).encode("ascii") + b"\x00"
    return hashlib.sha1(header + raw_bytes).hexdigest()


def _verify_d26_blob_map(raw_map: Mapping[str, bytes]) -> dict[str, bytes]:
    if not isinstance(raw_map, Mapping):
        raise ValueError("resolved_d26_blobs: expected Mapping[str, bytes]")
    expected_paths = {rel_path for _, rel_path, _, _ in PINNED_PIPEBOARD_D26_SPECS}
    if set(raw_map.keys()) != expected_paths:
        raise ValueError("resolved_d26_blobs: exact 5 pinned d26c73d paths required")
    verified: dict[str, bytes] = {}
    for role, rel_path, expected_oid, expected_sha in PINNED_PIPEBOARD_D26_SPECS:
        raw = raw_map[rel_path]
        if type(raw) is not bytes:
            raise ValueError(f"resolved_d26_blobs[{rel_path!r}]: expected bytes")
        if compute_git_blob_oid(raw) != expected_oid or digest(raw) != expected_sha:
            raise ValueError(f"d26c73d[{role}]: Git blob OID or SHA-256 mismatch for {rel_path!r}")
        verified[rel_path] = raw
    return verified


def _read_d26_from_git_repo(repo_dir: Path) -> dict[str, bytes]:
    if repo_dir.is_symlink() or not repo_dir.is_dir():
        raise ValueError(f"legacy_repo: expected non-symlink directory at {repo_dir}")
    rev_proc = run_git_offline(repo_dir, "rev-parse", "--verify", f"{PINNED_LEGACY_COMMIT}^{{commit}}")
    resolved_commit = rev_proc.stdout.decode("utf-8", errors="replace").strip()
    if resolved_commit != PINNED_LEGACY_COMMIT:
        raise ValueError(f"legacy_repo: commit {PINNED_LEGACY_COMMIT} verification failed")
    out: dict[str, bytes] = {}
    for _, rel_path, _, _ in PINNED_PIPEBOARD_D26_SPECS:
        blob_proc = run_git_offline(repo_dir, "cat-file", "blob", f"{PINNED_LEGACY_COMMIT}:{rel_path}")
        out[rel_path] = blob_proc.stdout
    return out


def _read_regular_non_symlink_under(base_dir: Path, target: Path) -> bytes:
    cur = base_dir
    for part in target.relative_to(base_dir).parts:
        cur = cur / part
        if cur.is_symlink():
            raise ValueError(f"legacy_blobs_dir: symlink forbidden at {cur}")
    if not target.is_file():
        raise ValueError(f"legacy_blobs_dir: expected regular file at {target}")
    return target.read_bytes()


def _read_d26_from_blobs_dir(blobs_dir: Path) -> dict[str, bytes]:
    if blobs_dir.is_symlink() or not blobs_dir.is_dir():
        raise ValueError(f"legacy_blobs_dir: expected non-symlink directory at {blobs_dir}")
    out: dict[str, bytes] = {}
    for role, rel_path, _, _ in PINNED_PIPEBOARD_D26_SPECS:
        rel_cand = blobs_dir / rel_path
        flat_cand = blobs_dir / f"{role}__{Path(rel_path).name}"
        has_rel = rel_cand.exists() or rel_cand.is_symlink()
        has_flat = flat_cand.exists() or flat_cand.is_symlink()
        if has_rel == has_flat:
            raise ValueError(
                f"legacy_blobs_dir: require <rel_path> XOR <role>__<basename> for {rel_path!r}"
            )
        chosen = rel_cand if has_rel else flat_cand
        out[rel_path] = _read_regular_non_symlink_under(blobs_dir, chosen)
    return out


def resolve_pinned_pipeboard_d26_blobs(
    *,
    legacy_repo: Path | None = None,
    legacy_blobs_dir: Path | None = None,
) -> Mapping[str, bytes]:
    """Resolve and cryptographically verify all 5 pinned `d26c73d` legacy Pipeboard blobs."""
    if (legacy_repo is None) == (legacy_blobs_dir is None):
        raise ValueError("resolve_pinned_pipeboard_d26_blobs: provide legacy_repo XOR legacy_blobs_dir")
    if legacy_repo is not None:
        if not isinstance(legacy_repo, (str, os.PathLike)):
            raise ValueError("legacy_repo: expected filesystem path")
        raw_map = _read_d26_from_git_repo(Path(legacy_repo))
    else:
        if not isinstance(legacy_blobs_dir, (str, os.PathLike)):
            raise ValueError("legacy_blobs_dir: expected filesystem path")
        raw_map = _read_d26_from_blobs_dir(Path(legacy_blobs_dir))
    return MappingProxyType(_verify_d26_blob_map(raw_map))


def _assign_target_name(stmt: ast.stmt) -> str | None:
    if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
        return stmt.targets[0].id
    if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
        return stmt.target.id
    return None


def _extract_pinned_max_response_bytes(raw_limits: bytes) -> int:
    path, exp_oid, exp_sha = _LIMITS_SPEC
    if compute_git_blob_oid(raw_limits) != exp_oid or digest(raw_limits) != exp_sha:
        raise ValueError("pinned pipeboard_limits.py OID or SHA-256 mismatch")
    tree = ast.parse(raw_limits.decode("utf-8"), filename=path)
    assigns = [s for s in tree.body if _assign_target_name(s) == "MAX_RESPONSE_BYTES"]
    if len(assigns) != 1:
        raise ValueError("pinned pipeboard_limits.py missing unique MAX_RESPONSE_BYTES")
    mod = ast.Module(body=assigns, type_ignores=[])
    code_obj = builtins.compile(
        mod, filename=path, mode="exec", flags=__future__.annotations.compiler_flag, dont_inherit=True
    )
    ns: dict[str, Any] = {"__builtins__": dict(_RESTRICTED_REDUCER_BUILTINS), "Final": Final}
    builtins.exec(code_obj, ns)
    max_resp = ns.get("MAX_RESPONSE_BYTES")
    if type(max_resp) is not int or max_resp != 2_097_152:
        raise ValueError(f"unexpected MAX_RESPONSE_BYTES: {max_resp!r}")
    return max_resp


def _extract_pinned_reducer_ast_nodes(raw_reducer: bytes) -> list[ast.stmt]:
    path, exp_oid, exp_sha = _REDUCER_SPEC
    if compute_git_blob_oid(raw_reducer) != exp_oid or digest(raw_reducer) != exp_sha:
        raise ValueError("pinned meta_daily_contract.py OID or SHA-256 mismatch")
    tree = ast.parse(raw_reducer.decode("utf-8"), filename=path)
    selected: list[ast.stmt] = []
    seen_names: set[str] = set()
    for stmt in tree.body:
        t_name = _assign_target_name(stmt)
        if t_name in _ALLOWED_REDUCER_ASSIGNS:
            selected.append(stmt)
            seen_names.add(t_name)
        elif isinstance(stmt, ast.ClassDef) and stmt.name == "MetaDailyContractError":
            selected.append(stmt)
            seen_names.add(stmt.name)
        elif isinstance(stmt, ast.FunctionDef) and stmt.name in _ALLOWED_REDUCER_FUNCS:
            selected.append(stmt)
            seen_names.add(stmt.name)
    expected_all = _ALLOWED_REDUCER_ASSIGNS | _ALLOWED_REDUCER_FUNCS | {"MetaDailyContractError"}
    if seen_names != expected_all:
        raise ValueError("pinned meta_daily_contract.py missing expected pure AST symbols")
    return selected


def _wrap_pinned_meta_reducer(
    fn: Callable[[dict[str, Any]], Any],
) -> Callable[[dict[str, Any]], list[dict[str, int]]]:
    def _wrapped(mcp_result: dict[str, Any]) -> list[dict[str, int]]:
        detached = json.loads(json.dumps(mcp_result))
        with decimal.localcontext(decimal.Context(prec=28)):
            out = fn(detached)
        if (
            not isinstance(out, dict)
            or set(out.keys()) != {"records"}
            or not isinstance(out["records"], list)
        ):
            raise ValueError("pinned_meta_reducer: expected exact {'records': [...]} return shape")
        return [dict(item) for item in out["records"]]

    return _wrapped


def load_isolated_pinned_meta_reducer(
    resolved_d26_blobs: Mapping[str, bytes],
) -> Callable[[dict[str, Any]], list[dict[str, int]]]:
    """Compile the pure `0dbdfede` `normalize_meta_result` subset without `__import__` or host I/O."""
    if not isinstance(resolved_d26_blobs, Mapping):
        raise ValueError("resolved_d26_blobs: expected Mapping[str, bytes]")
    raw_limits = resolved_d26_blobs.get(_LIMITS_SPEC[0])
    raw_reducer = resolved_d26_blobs.get(_REDUCER_SPEC[0])
    if type(raw_limits) is not bytes or type(raw_reducer) is not bytes:
        raise ValueError("resolved_d26_blobs: missing pipeboard_limits.py or meta_daily_contract.py bytes")
    max_resp = _extract_pinned_max_response_bytes(raw_limits)
    nodes = _extract_pinned_reducer_ast_nodes(raw_reducer)
    mod = ast.Module(body=nodes, type_ignores=[])
    code_obj = builtins.compile(
        mod,
        filename=_REDUCER_SPEC[0],
        mode="exec",
        flags=__future__.annotations.compiler_flag,
        dont_inherit=True,
    )
    ns: dict[str, Any] = {
        "__name__": "_pinned_meta_daily_contract_0dbdfede",
        "__builtins__": dict(_RESTRICTED_REDUCER_BUILTINS),
        "Any": Any,
        "Decimal": decimal.Decimal,
        "Final": Final,
        "InvalidOperation": decimal.InvalidOperation,
        "MAX_RESPONSE_BYTES": max_resp,
        "Mapping": Mapping,
        "cast": cast,
        "json": json,
        "re": re,
    }
    builtins.exec(code_obj, ns)
    fn = ns.get("normalize_meta_result")
    if not callable(fn):
        raise ValueError("pinned meta_daily_contract.py did not define callable normalize_meta_result")
    return _wrap_pinned_meta_reducer(fn)


def _verify_oci_readback_matches_profile(
    readback: object, sandbox_payload: Mapping[str, Any]
) -> dict[str, Any]:
    checked_rb = _validate_runtime_readback_dict(readback, "oci_readback")
    if checked_rb["seccomp_enforced_before_entry"] is not True:
        raise ValueError("oci_readback: seccomp_enforced_before_entry must be True")
    rb_proj = {k: checked_rb[k] for k in _SHARED_RUNTIME_16_FIELDS}
    sbx_proj = {k: sandbox_payload[k] for k in _SHARED_RUNTIME_16_FIELDS}
    if canonicalize(rb_proj) != canonicalize(sbx_proj):
        raise ValueError("oci_readback: canonical byte mismatch against sealed_sandbox_profile/v1")
    return checked_rb


def run_7a_hermetic_execution(
    *, wheel_bytes: bytes, corpus_bytes: bytes, sandbox_profile: dict[str, Any],
    seccomp_profile: dict[str, Any], resolved_d26_blobs: Mapping[str, bytes],
    sandbox_pubkey_raw32: bytes, supervisor: SealedOciSupervisorPort | None = None,
) -> dict[str, Any]:
    """Execute 7A corpus in a verified Linux OCI sandbox with injected `0dbdfede` reducer, or fail-closed `BLOCKED`."""
    if type(wheel_bytes) is not bytes or len(wheel_bytes) == 0 or type(corpus_bytes) is not bytes or len(corpus_bytes) == 0:
        raise ValueError("wheel_bytes and corpus_bytes: expected non-empty bytes")
    if type(sandbox_pubkey_raw32) is not bytes or len(sandbox_pubkey_raw32) != 32:
        raise ValueError("sandbox_pubkey_raw32: expected 32-byte raw Ed25519 public key")
    sbx_res = verify_sealed_sandbox_profile(sandbox_profile, seccomp_profile=seccomp_profile)
    if sbx_res["mode"] != "envelope" or not isinstance(sandbox_profile, Mapping):
        raise ValueError("sandbox_profile: expected signed sealed_sandbox_profile/v1 P1 envelope")
    sbx_env = dict(sandbox_profile)
    _verify_p1_integrity(sbx_env, label="sealed_sandbox_profile", require_signed=True)
    p1.verify_envelope(sbx_env, "SMART-ADS:SANDBOX-PROFILE:V1\n", sandbox_pubkey_raw32)
    sbx_payload = sbx_res["payload"]
    verified_d26 = _verify_d26_blob_map(resolved_d26_blobs)
    if supervisor is None or not isinstance(supervisor, SealedOciSupervisorPort):
        return {"status": "BLOCKED", "reason": "sealed Linux amd64 OCI cgroup-v2 supervisor is unavailable"}
    try:
        checked_rb = _verify_oci_readback_matches_profile(supervisor.readback_sandbox_environment(), sbx_payload)
        checked_limits = _validate_resource_limits_dict(supervisor.readback_effective_resource_limits(), "oci_effective_resource_limits")
        if canonicalize(checked_limits) != canonicalize(sbx_payload["resource_limits"]):
            raise ValueError("oci_effective_resource_limits: canonical byte mismatch against sealed_sandbox_profile/v1")
    except (ValueError, OSError) as exc:
        return {"status": "BLOCKED", "reason": str(exc)}
    pinned_reducer = load_isolated_pinned_meta_reducer(verified_d26)
    exec_out = supervisor.execute_7a_corpus(
        wheel_bytes=wheel_bytes, corpus_bytes=corpus_bytes, sandbox_profile_payload=copy.deepcopy(sbx_payload),
        resolved_d26_blobs=MappingProxyType(verified_d26), reducer=pinned_reducer,
    )
    if not isinstance(exec_out, Mapping):
        raise ValueError("supervisor.execute_7a_corpus: expected Mapping result")
    return {"status": "EXECUTED", "runtime_readback": checked_rb, "effective_resource_limits": checked_limits, "execution": copy.deepcopy(dict(exec_out))}


def _has_c0_or_c1_control(value: str) -> bool:
    return any(unicodedata.category(ch) == "Cc" or ord(ch) <= 0x1F or 0x7F <= ord(ch) <= 0x9F for ch in value)


def _validate_git_slug_and_path(repository: object, path: object) -> tuple[str, str]:
    repo, rel = _strict_str(repository, "git.repository"), _strict_str(path, "git.path")
    parts = repo.split("/")
    if _has_c0_or_c1_control(repo) or any(ch.isspace() or ch == "\\" for ch in repo) or len(parts) != 2 or any(p in {"", ".", ".."} for p in parts):
        raise ValueError("git_artifact_provenance.repository: invalid '<owner>/<repo>' slug or C0/C1 control")
    if "\\" in rel or _has_c0_or_c1_control(rel) or any(seg in {"", ".", ".."} for seg in rel.split("/")):
        raise ValueError("git_artifact_provenance.path: invalid relative POSIX path or C0/C1 control")
    return repo, rel


def sort_git_provenance_locators(locators: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    if isinstance(locators, (str, bytes, bytearray)) or not isinstance(locators, Sequence):
        raise ValueError("locators: expected Sequence of locator dicts")
    keyed, seen = [], set()
    for idx, loc in enumerate(locators):
        d = copy.deepcopy(dict(loc)) if isinstance(loc, Mapping) else {}
        validate_locator(d, GIT_ARTIFACT_PROVENANCE_SCHEMA)
        jb = canonicalize(d)
        if jb in seen:
            raise ValueError(f"locators[{idx}]: duplicate git_artifact_provenance/v1 locator")
        seen.add(jb)
        keyed.append((jb, d))
    return [d for _, d in sorted(keyed, key=lambda p: p[0])]


def build_git_artifact_provenance_envelope(
    *, repository: str, commit_sha: str, path: str, raw_bytes: bytes,
    resolved_at_utc: str, registry_locator: Mapping[str, Any], signer_key_id: str,
) -> dict[str, Any]:
    repo, rel = _validate_git_slug_and_path(repository, path)
    _hex40_str(commit_sha, "commit_sha")
    if type(raw_bytes) is not bytes:
        raise ValueError("raw_bytes: expected bytes")
    _utc_sec_micros(resolved_at_utc, "resolved_at_utc")
    reg_loc = copy.deepcopy(dict(registry_locator))
    validate_locator(reg_loc, _KEY_REGISTRY_SCHEMA)
    _key_id_str(signer_key_id, "signer_key_id")
    env = {
        "$schema": GIT_ARTIFACT_PROVENANCE_SCHEMA, "repository": repo, "commit_sha": commit_sha, "path": rel,
        "git_blob_oid": compute_git_blob_oid(raw_bytes), "file_content_sha256": digest(raw_bytes),
        "resolved_at_utc": resolved_at_utc, "integrity": {"key_id": signer_key_id, "key_registry_snapshot_locator": reg_loc},
    }
    loads_strict(canonicalize(env).decode("utf-8"))
    return env


def verify_git_artifact_provenance_envelope(
    envelope: Mapping[str, Any], *, expected_bytes: bytes | None = None, require_signed: bool = False
) -> dict[str, Any]:
    if not isinstance(envelope, Mapping):
        raise ValueError("git_artifact_provenance: expected Mapping")
    d = copy.deepcopy(dict(envelope))
    exact_fields(d, {"$schema", "repository", "commit_sha", "path", "git_blob_oid", "file_content_sha256", "resolved_at_utc", "integrity"}, "git_artifact_provenance")
    _exact_str(d["$schema"], GIT_ARTIFACT_PROVENANCE_SCHEMA, "$schema")
    _validate_git_slug_and_path(d["repository"], d["path"])
    _hex40_str(d["commit_sha"], "commit_sha")
    _hex40_str(d["git_blob_oid"], "git_blob_oid")
    _sha256_str(d["file_content_sha256"], "file_content_sha256")
    _utc_sec_micros(d["resolved_at_utc"], "resolved_at_utc")
    _verify_p1_integrity(d, label="git_artifact_provenance", require_signed=require_signed)
    if expected_bytes is not None and (type(expected_bytes) is not bytes or compute_git_blob_oid(expected_bytes) != d["git_blob_oid"] or digest(expected_bytes) != d["file_content_sha256"]):
        raise ValueError("git_artifact_provenance: git_blob_oid or file_content_sha256 mismatch")
    return d


def _validate_expected_resource_items(
    items: Sequence[Mapping[str, Any]], *, binding_ref: str, account_ref: str,
    start_cal: datetime.date, end_cal: datetime.date, require_sorted: bool,
) -> list[dict[str, Any]]:
    if isinstance(items, (str, bytes, bytearray)) or not isinstance(items, Sequence) or not items:
        raise ValueError("expected_resources: expected non-empty sequence")
    keyed, seen = [], set()
    for raw_u in items:
        u = dict(raw_u) if isinstance(raw_u, Mapping) else {}
        exact_fields(u, {"binding_ref", "account_ref", "resource_ref", "resource_level", "metric_date", "attribution_ref", "breakdown_signature"}, "expected_resource_key")
        if (u["binding_ref"], u["account_ref"], u["resource_level"], u["attribution_ref"], u["breakdown_signature"]) != (binding_ref, account_ref, "campaign", "attribution:not_applicable", "breakdown:none"):
            raise ValueError("expected_resource_key: Phase 1 field mismatch")
        validate_resource_ref_str(u["resource_ref"], "resource_ref")
        if not (start_cal <= _parse_iso_date(u["metric_date"], "metric_date") <= end_cal):
            raise ValueError("expected_resource_key: metric_date outside inventory date_range")
        id_b = canonicalize([u["binding_ref"], u["account_ref"], u["resource_ref"], u["resource_level"], u["metric_date"], u["attribution_ref"], u["breakdown_signature"]])
        if id_b in seen:
            raise ValueError("expected_resources: duplicate expected resource key")
        seen.add(id_b)
        keyed.append((id_b, copy.deepcopy(u)))
    if require_sorted and [k for k, _ in keyed] != sorted(k for k, _ in keyed):
        raise ValueError("expected_resources: must be sorted by ascending JCS identity")
    return [u for _, u in sorted(keyed, key=lambda p: p[0])]


def build_expected_resource_inventory_envelope(
    *, inventory_id: str, registry_snapshot_locator: Mapping[str, Any], tenant_ref: str, binding_ref: str, account_ref: str,
    resource_scope_ref: str, date_range: Mapping[str, Any], expected_resources: Sequence[Mapping[str, Any]],
    registry_locator: Mapping[str, Any], signer_key_id: str,
) -> dict[str, Any]:
    _opaque_ref_str(inventory_id, "inventory_id", expected_prefix="inventory")
    snap_loc, reg_loc = copy.deepcopy(dict(registry_snapshot_locator)), copy.deepcopy(dict(registry_locator))
    validate_locator(snap_loc, PRIVATE_REGISTRY_SNAPSHOT_SCHEMA)
    validate_locator(reg_loc, _KEY_REGISTRY_SCHEMA)
    _key_id_str(signer_key_id, "signer_key_id")
    for pfx, val in (("tenant", tenant_ref), ("binding", binding_ref), ("account", account_ref), ("scope", resource_scope_ref)):
        _opaque_ref_str(val, pfx, expected_prefix=pfx)
    dr = dict(date_range)
    exact_fields(dr, {"start_date", "end_date", "inclusive"}, "date_range")
    s_cal, e_cal = _parse_iso_date(dr["start_date"], "start"), _parse_iso_date(dr["end_date"], "end")
    if dr["inclusive"] is not True or s_cal > e_cal:
        raise ValueError("date_range: invalid inclusive calendar range")
    sorted_u = _validate_expected_resource_items(expected_resources, binding_ref=binding_ref, account_ref=account_ref, start_cal=s_cal, end_cal=e_cal, require_sorted=False)
    env = {
        "$schema": EXPECTED_RESOURCE_INVENTORY_SCHEMA, "inventory_id": inventory_id, "registry_snapshot_locator": snap_loc,
        "registry_snapshot_digest": snap_loc["content_digest"], "tenant_ref": tenant_ref, "binding_ref": binding_ref,
        "account_ref": account_ref, "resource_scope_ref": resource_scope_ref, "date_range": copy.deepcopy(dr),
        "expected_resources": sorted_u, "integrity": {"key_id": signer_key_id, "key_registry_snapshot_locator": reg_loc},
    }
    loads_strict(canonicalize(env).decode("utf-8"))
    return env


def verify_expected_resource_inventory_envelope(envelope: Mapping[str, Any], *, require_signed: bool = False) -> dict[str, Any]:
    if not isinstance(envelope, Mapping):
        raise ValueError("expected_resource_inventory: expected Mapping")
    d = copy.deepcopy(dict(envelope))
    exact_fields(d, {"$schema", "inventory_id", "registry_snapshot_locator", "registry_snapshot_digest", "tenant_ref", "binding_ref", "account_ref", "resource_scope_ref", "date_range", "expected_resources", "integrity"}, "expected_resource_inventory")
    _exact_str(d["$schema"], EXPECTED_RESOURCE_INVENTORY_SCHEMA, "$schema")
    _opaque_ref_str(d["inventory_id"], "inventory_id", expected_prefix="inventory")
    validate_locator(dict(d["registry_snapshot_locator"]), PRIVATE_REGISTRY_SNAPSHOT_SCHEMA)
    _exact_str(d["registry_snapshot_digest"], d["registry_snapshot_locator"]["content_digest"], "registry_snapshot_digest")
    for pfx, k in (("tenant", "tenant_ref"), ("binding", "binding_ref"), ("account", "account_ref"), ("scope", "resource_scope_ref")):
        _opaque_ref_str(d[k], k, expected_prefix=pfx)
    dr = dict(d["date_range"]) if isinstance(d["date_range"], Mapping) else {}
    exact_fields(dr, {"start_date", "end_date", "inclusive"}, "date_range")
    s_cal, e_cal = _parse_iso_date(dr["start_date"], "start"), _parse_iso_date(dr["end_date"], "end")
    if dr["inclusive"] is not True or s_cal > e_cal or type(d["expected_resources"]) is not list:
        raise ValueError("expected_resource_inventory: invalid date_range or expected_resources")
    _validate_expected_resource_items(d["expected_resources"], binding_ref=d["binding_ref"], account_ref=d["account_ref"], start_cal=s_cal, end_cal=e_cal, require_sorted=True)
    _verify_p1_integrity(d, label="expected_resource_inventory", require_signed=require_signed)
    return d


_CAP_STATES: Final[frozenset[str]] = frozenset({"declared", "fixture_certified", "live_certified", "unavailable", "deferred", "invalidated", "revalidation_pending"})
_SCHEMA_ID_RE: Final[re.Pattern[str]] = re.compile(r"\Asmart_ads/[a-z0-9_]+/v[1-9][0-9]*\Z")


def _validate_snapshot_bindings_and_scopes(bnds: object, scopes: object) -> None:
    if type(bnds) is not list or not bnds or type(scopes) is not list or not scopes:
        raise ValueError("private_registry_snapshot: bindings and authorized_scopes must be non-empty lists")
    seen_b, seen_a, b_keys = set(), set(), []
    for raw_b in bnds:
        b = dict(raw_b) if isinstance(raw_b, Mapping) else {}
        exact_fields(b, {"binding_ref", "account_ref", "transport_provider_ref", "ad_platform_ref", "currency", "driver_id"}, "private_registry_snapshot.binding")
        br = _opaque_ref_str(b["binding_ref"], "private_registry_snapshot.binding_ref", expected_prefix="binding")
        ar = _opaque_ref_str(b["account_ref"], "private_registry_snapshot.account_ref", expected_prefix="account")
        _opaque_ref_str(b["transport_provider_ref"], "private_registry_snapshot.transport_provider_ref", expected_prefix="provider")
        drv_id = _non_empty_nfc_str(b["driver_id"], "private_registry_snapshot.driver_id")
        if type(b["ad_platform_ref"]) is not str or b["ad_platform_ref"] != "meta" or type(b["currency"]) is not str or b["currency"] != "BRL" or any(ch.isspace() for ch in drv_id) or br in seen_b or ar in seen_a:
            raise ValueError("private_registry_snapshot.bindings: invalid field or duplicate binding_ref/account_ref")
        seen_b.add(br)
        seen_a.add(ar)
        b_keys.append(br.encode("utf-8"))
    s_keys: list[bytes] = []
    for raw_s in scopes:
        s = dict(raw_s) if isinstance(raw_s, Mapping) else {}
        exact_fields(s, {"front_ref", "profile_ref", "binding_ref", "resource_scope_ref"}, "private_registry_snapshot.authorized_scope")
        fr = _opaque_ref_str(s["front_ref"], "private_registry_snapshot.front_ref", expected_prefix="front")
        pr = _opaque_ref_str(s["profile_ref"], "private_registry_snapshot.profile_ref", expected_prefix="profile")
        sbr = _opaque_ref_str(s["binding_ref"], "private_registry_snapshot.scope.binding_ref", expected_prefix="binding")
        sr = _opaque_ref_str(s["resource_scope_ref"], "private_registry_snapshot.resource_scope_ref", expected_prefix="scope")
        sk = canonicalize([fr, pr, sbr, sr])
        if sbr not in seen_b or sk in s_keys:
            raise ValueError("private_registry_snapshot.authorized_scopes: unknown binding_ref or duplicate scope")
        s_keys.append(sk)
    if b_keys != sorted(b_keys) or s_keys != sorted(s_keys):
        raise ValueError("private_registry_snapshot: bindings or authorized_scopes not canonically sorted")


def validate_private_registry_snapshot_payload(snap: Mapping[str, Any]) -> None:
    d = dict(snap) if isinstance(snap, Mapping) else {}
    core = {"snapshot_id", "tenant_ref", "issued_at_utc", "valid_until_utc", "resource_ref_mapping_version", "key_identity", "domain_separator", "resource_mapping_contract_digest", "bindings", "authorized_scopes", "capabilities"}
    exact_fields(d, core | ({"$schema", "integrity"} & set(d)), "private_registry_snapshot")
    if "$schema" in d:
        _exact_str(d["$schema"], PRIVATE_REGISTRY_SNAPSHOT_SCHEMA, "private_registry_snapshot.$schema")
    if type(d["snapshot_id"]) is not str or re.fullmatch(r"\Aregistry-snapshot:[A-Za-z0-9._:-]+\Z", d["snapshot_id"]) is None or type(d["domain_separator"]) is not str or d["domain_separator"] != "0x00" or _utc_sec_micros(d["issued_at_utc"], "private_registry_snapshot.issued_at_utc") >= _utc_sec_micros(d["valid_until_utc"], "private_registry_snapshot.valid_until_utc"):
        raise ValueError("private_registry_snapshot: invalid snapshot_id, domain_separator, or validity")
    rmc_pre = b"SMART-ADS:RESOURCE-MAPPING-CONTRACT:V1\n\x00" + canonicalize({"domain_separator": "0x00", "key_identity": _opaque_ref_str(d["key_identity"], "private_registry_snapshot.key_identity", expected_prefix="key"), "resource_ref_mapping_version": _non_empty_nfc_str(d["resource_ref_mapping_version"], "private_registry_snapshot.resource_ref_mapping_version"), "tenant_ref": _opaque_ref_str(d["tenant_ref"], "private_registry_snapshot.tenant_ref", expected_prefix="tenant")})
    if _sha256_str(d["resource_mapping_contract_digest"], "private_registry_snapshot.resource_mapping_contract_digest") != "sha256:" + hashlib.sha256(rmc_pre).hexdigest():
        raise ValueError("private_registry_snapshot: resource_mapping_contract_digest mismatch")
    _validate_snapshot_bindings_and_scopes(d["bindings"], d["authorized_scopes"])
    if type(d["capabilities"]) is not list or not d["capabilities"]:
        raise ValueError("private_registry_snapshot.capabilities: expected non-empty list")
    c_keys: list[bytes] = []
    for raw_c in d["capabilities"]:
        c = dict(raw_c) if isinstance(raw_c, Mapping) else {}
        exact_fields(c, {"capability_ref", "capability_semantic_version", "driver_id", "driver_contract_locator", "driver_contract_digest", "resource_scope_ref", "state", "required_metrics"}, "private_registry_snapshot.capability_entry")
        cr, cs = _opaque_ref_str(c["capability_ref"], "private_registry_snapshot.capability_ref", expected_prefix="cap"), _opaque_ref_str(c["resource_scope_ref"], "private_registry_snapshot.resource_scope_ref", expected_prefix="scope")
        _non_empty_nfc_str(c["capability_semantic_version"], "private_registry_snapshot.capability_semantic_version")
        cd_id = _non_empty_nfc_str(c["driver_id"], "private_registry_snapshot.driver_id")
        loc = dict(c["driver_contract_locator"]) if isinstance(c["driver_contract_locator"], Mapping) else {}
        try:
            validate_locator(loc)
        except ValueError as exc:
            raise ValueError(f"private_registry_snapshot.capabilities.driver_contract_locator: {exc}") from exc
        rm = c["required_metrics"]
        if _SCHEMA_ID_RE.fullmatch(loc["artifact_type"]) is None or any(ch.isspace() for ch in cd_id) or _sha256_str(c["driver_contract_digest"], "private_registry_snapshot.driver_contract_digest") != loc["content_digest"] or type(c["state"]) is not str or c["state"] not in _CAP_STATES or type(rm) is not list or not rm:
            raise ValueError("private_registry_snapshot.capabilities: invalid capability entry or driver_contract_locator.artifact_type")
        ms = [_opaque_ref_str(m, "private_registry_snapshot.metric", expected_prefix="metric") for m in rm]
        ck = canonicalize([cr, cs])
        if len(set(ms)) != len(ms) or [m.encode("utf-8") for m in ms] != sorted(m.encode("utf-8") for m in ms) or ck in c_keys:
            raise ValueError("private_registry_snapshot.capabilities: duplicate or unsorted capability/metrics")
        c_keys.append(ck)
    if c_keys != sorted(c_keys):
        raise ValueError("private_registry_snapshot.capabilities: not canonically sorted")


def verify_private_registry_snapshot_envelope(envelope: Mapping[str, Any], *, require_signed: bool = False) -> dict[str, Any]:
    d = copy.deepcopy(dict(envelope)) if isinstance(envelope, Mapping) else {}
    if "$schema" not in d or "integrity" not in d:
        raise ValueError("private_registry_snapshot: expected P1 envelope")
    validate_private_registry_snapshot_payload(d)
    _verify_p1_integrity(d, label="private_registry_snapshot", require_signed=require_signed)
    return d
