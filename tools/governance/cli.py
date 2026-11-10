"""argparse CLI for the Smart Ads governance toolkit.

Every command prints JSON to stdout on success, or writes a file and prints
its path, size and sha256. All file writes are atomic and verified: size must
be > 0 and the bytes are re-read after write before the command reports
success. Exit code 0 = success, 1 = expected/validated failure (verify failed,
guard rejected the input), 2 = usage error, 5 = incomplete decomposition
candidate.

Run as: `python3 -m tools.governance.cli <command> ...`
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from typing import Any

from tools.governance import artifacts, decomposition as dec, legacy_step2, p1
from tools.governance.decomposition_governance import inspect_governance
from tools.governance.decomposition_review import build_review_bundle
from tools.governance.decomposition_scope import resolve_scope
from tools.governance.jcs import canonicalize, loads_strict
from tools.governance.locator import Store, digest, exact_fields

KEYGEN_INSTRUCTIONS = """\
# Gerar chave Ed25519 (trust anchor OU operador) — executar OFFLINE.
openssl genpkey -algorithm ed25519 -out <nome>.pem
chmod 600 <nome>.pem

# Extrair a chave publica raw (32 bytes) em base64 e o key_id:
python3 -m tools.governance.cli key-id --pubkey-pem <nome>.pem

# Nunca commitar a chave privada. Guarde-a fora do repositorio
# (cofre de segredos, HSM ou disco criptografado offline).
"""


def _read_json_file(path: str) -> dict[str, Any]:
    text = Path(path).read_text(encoding="utf-8")
    value = loads_strict(text)
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected a JSON object")
    return value


def _write_json_file(
    path: str, value: dict[str, Any], *, allow_overwrite: bool
) -> dict[str, Any]:
    canonical = canonicalize(value)
    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if not allow_overwrite and out_path.exists():
        raise ValueError("decomposition: output exists; choose a fresh output path")
    fd, temp = tempfile.mkstemp(prefix=".decomposition-", dir=out_path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(canonical)
            stream.flush()
            os.fsync(stream.fileno())
        if allow_overwrite:
            os.chmod(temp, 0o644)
            os.replace(temp, out_path)
        else:
            os.link(temp, out_path)  # Atomic create, never overwrite a concurrently created file.
        directory = os.open(out_path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(temp).unlink(missing_ok=True)
    written = out_path.read_bytes()
    if len(written) == 0 or written != canonical:
        raise ValueError(f"cli: write verification failed for {path}")
    if allow_overwrite:
        return {
            "path": str(out_path),
            "size": len(written),
            "sha256": hashlib.sha256(written).hexdigest(),
        }
    return {
        "path": str(out_path),
        "size": len(written),
        "sha256": digest(written),
        "signable": False,
    }


def _print_json(value: Any) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


def cmd_keygen_instructions(_args: argparse.Namespace) -> int:
    print(KEYGEN_INSTRUCTIONS)
    return 0


def cmd_key_id(args: argparse.Namespace) -> int:
    raw32 = p1.raw_public_key_from_pem(Path(args.pubkey_pem))
    _print_json({
        "public_key_base64": base64.b64encode(raw32).decode("ascii"),
        "public_key_sha256": "sha256:" + hashlib.sha256(raw32).hexdigest(),
        "key_id": p1.key_id_for(raw32),
    })
    return 0


def cmd_digest(args: argparse.Namespace) -> int:
    envelope = _read_json_file(args.envelope)
    result: dict[str, Any] = {}
    if "integrity" in envelope and isinstance(envelope["integrity"], dict):
        result["p1_content_digest"] = p1.content_digest(envelope)
    canonical = canonicalize(envelope)
    result["locator_content_digest"] = "sha256:" + hashlib.sha256(canonical).hexdigest()
    _print_json(result)
    return 0


def cmd_sign(args: argparse.Namespace) -> int:
    prefix = p1.DOMAIN_PREFIXES.get(args.schema)
    if prefix is None:
        print(f"error: unknown schema {args.schema!r}", file=sys.stderr)
        return 2
    envelope = _read_json_file(args.input)
    signed = p1.sign_envelope(envelope, prefix, Path(args.key))
    info = _write_json_file(args.out, signed, allow_overwrite=True)
    _print_json(info)
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    prefix = p1.DOMAIN_PREFIXES.get(args.schema)
    if prefix is None:
        print(f"error: unknown schema {args.schema!r}", file=sys.stderr)
        return 2
    envelope = _read_json_file(args.input)
    raw32 = base64.b64decode(args.pubkey_raw_base64, validate=True)
    try:
        p1.verify_envelope(envelope, prefix, raw32)
    except ValueError as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 1
    print("PASS")
    return 0


def cmd_store_put(args: argparse.Namespace) -> int:
    envelope = _read_json_file(args.input)
    store = Store(Path(args.root))
    locator = store.put(envelope)
    _print_json(locator)
    return 0


def cmd_store_get(args: argparse.Namespace) -> int:
    locator = _read_json_file(args.locator)
    store = Store(Path(args.root))
    envelope = store.get(locator)
    _print_json(envelope)
    return 0


def cmd_build_trust_anchor(args: argparse.Namespace) -> int:
    params = _read_json_file(args.params)
    exact_fields(
        params,
        {
            "anchor_id",
            "anchor_public_key_base64",
            "valid_from_utc",
            "valid_until_utc",
            "allowed_registry_artifact_types",
        },
        "build-trust-anchor params",
    )
    raw32 = base64.b64decode(params["anchor_public_key_base64"], validate=True)
    config = artifacts.build_trust_anchor_config(
        anchor_id=params["anchor_id"],
        anchor_public_raw32=raw32,
        valid_from_utc=params["valid_from_utc"],
        valid_until_utc=params["valid_until_utc"],
        allowed_registry_artifact_types=params["allowed_registry_artifact_types"],
    )
    info = _write_json_file(args.out, config, allow_overwrite=True)
    info["trust_anchor_pin"] = artifacts.trust_anchor_pin(config)
    _print_json(info)
    return 0


def cmd_build_registry(args: argparse.Namespace) -> int:
    params = _read_json_file(args.params)
    exact_fields(
        params,
        {"trust_anchor_id", "epoch", "issued_at_utc", "entries", "signer_key_id"},
        "build-registry params",
    )
    registry = artifacts.build_key_registry(
        trust_anchor_id=params["trust_anchor_id"],
        epoch=params["epoch"],
        issued_at_utc=params["issued_at_utc"],
        entries=params["entries"],
        signer_key_id=params["signer_key_id"],
    )
    info = _write_json_file(args.out, registry, allow_overwrite=True)
    _print_json(info)
    return 0


def cmd_build_policy(args: argparse.Namespace) -> int:
    params = _read_json_file(args.params)
    exact_fields(
        params,
        {
            "repository",
            "protected_ref",
            "adr_path",
            "ci_review_policy_digest",
            "designated_principals",
            "registry_locator",
            "signer_key_id",
        },
        "build-policy params",
    )
    policy = artifacts.build_gate2_authority_policy(
        repository=params["repository"],
        protected_ref=params["protected_ref"],
        adr_path=params["adr_path"],
        ci_review_policy_digest=params["ci_review_policy_digest"],
        designated_principals=params["designated_principals"],
        registry_locator=params["registry_locator"],
        signer_key_id=params["signer_key_id"],
    )
    info = _write_json_file(args.out, policy, allow_overwrite=True)
    _print_json(info)
    return 0


_OFFLINE_ACK_LITERAL = "I_UNDERSTAND_THIS_IS_NOT_LIVE_EVIDENCE"


def _resolve_branch_protection(args: argparse.Namespace) -> bool:
    """Return whether the branch is protected, live by default.

    The live path (default) calls `gh api repos/<repo>/branches/<ref>` via
    `artifacts.check_branch_protection_via_gh`. The offline substitute
    (`--protection-json`) requires an explicit, literal acknowledgement via
    `--offline-protection-ack` so it can never be used casually in place of
    real evidence.
    """
    if args.protection_json is not None:
        if args.offline_protection_ack != _OFFLINE_ACK_LITERAL:
            print(
                "error: --protection-json requires --offline-protection-ack "
                f"{_OFFLINE_ACK_LITERAL!r} (got {args.offline_protection_ack!r}); "
                "the offline path cannot be used casually",
                file=sys.stderr,
            )
            raise SystemExit(1)
        print(
            "WARNING: using --protection-json offline substitute, not live "
            "'gh api' branch-protection evidence. Only valid for dry-run "
            "preparation, never as real Gate 2 evidence.",
            file=sys.stderr,
        )
        protection = _read_json_file(args.protection_json)
        return bool(protection.get("protected", False))

    if not args.repository or not args.ref:
        print(
            "error: build-merge-evidence needs --repository and --ref for the "
            "live 'gh api' branch-protection check (or --protection-json plus "
            "--offline-protection-ack for the offline substitute)",
            file=sys.stderr,
        )
        raise SystemExit(2)
    protection = artifacts.check_branch_protection_via_gh(args.repository, args.ref)
    return bool(protection.get("protected", False))


def cmd_build_merge_evidence(args: argparse.Namespace) -> int:
    params = _read_json_file(args.params)
    exact_fields(
        params,
        {
            "repository",
            "protected_branch",
            "pr_number",
            "reviewed_head_sha",
            "protected_merge_sha",
            "adr_git_identity",
            "required_ci_results",
            "exact_head_review_evidence",
            "branch_protection_policy",
            "signer_key_id",
            "registry_locator",
        },
        "build-merge-evidence params",
    )
    verified = _resolve_branch_protection(args)
    try:
        evidence = artifacts.build_protected_merge_evidence(
            repository=params["repository"],
            protected_branch=params["protected_branch"],
            pr_number=params["pr_number"],
            reviewed_head_sha=params["reviewed_head_sha"],
            protected_merge_sha=params["protected_merge_sha"],
            adr_git_identity=params["adr_git_identity"],
            required_ci_results=params["required_ci_results"],
            exact_head_review_evidence=params["exact_head_review_evidence"],
            branch_protection_policy=params["branch_protection_policy"],
            signer_key_id=params["signer_key_id"],
            registry_locator=params["registry_locator"],
            branch_protection_verified=verified,
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    info = _write_json_file(args.out, evidence, allow_overwrite=True)
    _print_json(info)
    return 0


def cmd_build_receipt(args: argparse.Namespace) -> int:
    params = _read_json_file(args.params)
    exact_fields(
        params,
        {
            "approved_adr_git_identity",
            "legacy_source_identity",
            "protected_merge_evidence_locator",
            "protected_merge_sha",
            "gate2_authority_policy_locator",
            "approver_principal_ref",
            "approved_at_utc",
            "key_registry_snapshot_locator",
            "signer_key_id",
        },
        "build-receipt params",
    )
    receipt = artifacts.build_gate2_receipt(
        approved_adr_git_identity=params["approved_adr_git_identity"],
        legacy_source_identity=params["legacy_source_identity"],
        protected_merge_evidence_locator=params["protected_merge_evidence_locator"],
        protected_merge_sha=params["protected_merge_sha"],
        gate2_authority_policy_locator=params["gate2_authority_policy_locator"],
        approver_principal_ref=params["approver_principal_ref"],
        approved_at_utc=params["approved_at_utc"],
        key_registry_snapshot_locator=params["key_registry_snapshot_locator"],
        signer_key_id=params["signer_key_id"],
    )
    info = _write_json_file(args.out, receipt, allow_overwrite=True)
    _print_json(info)
    return 0


def cmd_build_run_context(args: argparse.Namespace) -> int:
    params = _read_json_file(args.params)
    exact_fields(
        params,
        {
            "gate2_receipt_locator",
            "approved_adr_git_identity",
            "legacy_source_identity",
            "tenant_ref",
            "cell_ref",
            "run_id",
            "created_at_utc",
            "key_registry_snapshot_locator",
            "signer_key_id",
        },
        "build-run-context params",
    )
    ctx = artifacts.build_migration_run_context(
        gate2_receipt_locator=params["gate2_receipt_locator"],
        approved_adr_git_identity=params["approved_adr_git_identity"],
        legacy_source_identity=params["legacy_source_identity"],
        tenant_ref=params["tenant_ref"],
        cell_ref=params["cell_ref"],
        run_id=params["run_id"],
        created_at_utc=params["created_at_utc"],
        key_registry_snapshot_locator=params["key_registry_snapshot_locator"],
        signer_key_id=params["signer_key_id"],
    )
    info = _write_json_file(args.out, ctx, allow_overwrite=True)
    _print_json(info)
    return 0


def cmd_build_delivery_mode(args: argparse.Namespace) -> int:
    params = _read_json_file(args.params)
    exact_fields(
        params,
        {
            "gate2_receipt_locator",
            "approved_adr_git_identity",
            "run_context_locator",
            "decided_by_principal_ref",
            "decided_at_utc",
            "key_registry_snapshot_locator",
            "signer_key_id",
        },
        "build-delivery-mode params",
    )
    rec = artifacts.build_delivery_mode_decision(
        gate2_receipt_locator=params["gate2_receipt_locator"],
        approved_adr_git_identity=params["approved_adr_git_identity"],
        run_context_locator=params["run_context_locator"],
        decided_by_principal_ref=params["decided_by_principal_ref"],
        decided_at_utc=params["decided_at_utc"],
        key_registry_snapshot_locator=params["key_registry_snapshot_locator"],
        signer_key_id=params["signer_key_id"],
    )
    info = _write_json_file(args.out, rec, allow_overwrite=True)
    _print_json(info)
    return 0


def cmd_resolve_legacy_step2(args: argparse.Namespace) -> int:
    kwargs: dict[str, Any] = {}
    if args.w1_gate_sha is not None:
        kwargs["w1_gate_sha"] = args.w1_gate_sha
    if args.wave1_merges is not None:
        kwargs["wave1_merges"] = _read_json_file(args.wave1_merges)
    facts = legacy_step2.resolve_legacy_step2_facts(
        Path(args.legacy_repo), args.baseline, **kwargs
    )
    info = _write_json_file(args.out, facts, allow_overwrite=True)
    _print_json(info)
    return 0


def cmd_build_legacy_step2_evidence(args: argparse.Namespace) -> int:
    params = _read_json_file(args.params)
    base_keys = {"resolved_at_utc", "key_registry_snapshot_locator", "signer_key_id"}
    if "facts" in params and "facts_path" not in params:
        exact_fields(params, base_keys | {"facts"}, "build-legacy-step2-evidence params")
        facts = params["facts"]
    elif "facts_path" in params and "facts" not in params:
        exact_fields(params, base_keys | {"facts_path"}, "build-legacy-step2-evidence params")
        facts = _read_json_file(params["facts_path"])
    else:
        raise ValueError(
            "build-legacy-step2-evidence: params must contain either 'facts' or 'facts_path'"
        )
    evidence = legacy_step2.build_legacy_step2_evidence(
        facts=facts,
        resolved_at_utc=params["resolved_at_utc"],
        key_registry_snapshot_locator=params["key_registry_snapshot_locator"],
        signer_key_id=params["signer_key_id"],
    )
    info = _write_json_file(args.out, evidence, allow_overwrite=True)
    _print_json(info)
    return 0


def run_decomposition(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    try:
        return _run_decomposition(args)
    except (OSError, TypeError, UnicodeError) as exc:
        raise ValueError(
            f"decomposition: invalid input or local I/O failure ({type(exc).__name__})"
        ) from exc


def _run_decomposition(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    source = resolve_scope(Path(args.legacy_repo))
    if args.command in ("prepare-decomposition-review", "prepare-decomposition-dispositions"):
        inventory, value = build_review_bundle(source)
        if args.command == "prepare-decomposition-dispositions":
            value = dec.review_inputs(source, inventory, value["unit_review"])
        return _write_json_file(args.out, value, allow_overwrite=False), 0
    if args.command == "resolve-decomposition-inventory":
        inventory = dec.resolve_inventory(source)
        value = {
            "artifact_kind": "decomposition_inputs_draft",
            "draft_contract": dec.CONTRACT,
            "inventory": inventory,
            "entries": dec.decision_template(inventory),
        }
        return _write_json_file(args.out, value, allow_overwrite=False), 0
    if args.command == "build-decomposition-manifest":
        inputs = _read_json_file(args.params)
        exact_fields(
            inputs,
            {"artifact_kind", "draft_contract", "inventory", "entries"},
            "decomposition inputs",
        )
        if (
            inputs["artifact_kind"] != "decomposition_inputs_draft"
            or inputs["draft_contract"] not in (dec.CONTRACT, dec.LEGACY_CONTRACT)
        ):
            raise ValueError("decomposition: unsupported input contract")
        candidate = dec.build_candidate(
            source,
            inputs["inventory"],
            inputs["entries"],
            args.generated_at,
            inputs["draft_contract"],
        )
        governance = inspect_governance()
        result = _write_json_file(args.out, candidate, allow_overwrite=False)
        result.update(
            {"validation_status": candidate["validation_status"], "governance": governance}
        )
        return result, 0
    candidate = _read_json_file(args.input)
    dec.verify_candidate(source, candidate)
    governance = inspect_governance()
    return {
        "candidate_matches_recomputation": True,
        "validation_status": "INCOMPLETE",
        "pending_decision_count": candidate["pending_decision_count"],
        "admission_blockers": candidate["admission_blockers"],
        "governance": governance,
        "signable": False,
    }, 5


def cmd_decomposition(args: argparse.Namespace) -> int:
    result, code = run_decomposition(args)
    _print_json(result)
    return code


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python3 -m tools.governance.cli")
    sub = parser.add_subparsers(dest="command", required=True)

    p_keygen = sub.add_parser("keygen-instructions")
    p_keygen.set_defaults(func=cmd_keygen_instructions)

    p_keyid = sub.add_parser("key-id")
    p_keyid.add_argument("--pubkey-pem", required=True)
    p_keyid.set_defaults(func=cmd_key_id)

    p_digest = sub.add_parser("digest")
    p_digest.add_argument("envelope")
    p_digest.set_defaults(func=cmd_digest)

    p_sign = sub.add_parser("sign")
    p_sign.add_argument("--schema", required=True)
    p_sign.add_argument("--key", required=True)
    p_sign.add_argument("--in", dest="input", required=True)
    p_sign.add_argument("--out", required=True)
    p_sign.set_defaults(func=cmd_sign)

    p_verify = sub.add_parser("verify")
    p_verify.add_argument("--schema", required=True)
    p_verify.add_argument("--pubkey-raw-base64", required=True)
    p_verify.add_argument("--in", dest="input", required=True)
    p_verify.set_defaults(func=cmd_verify)

    p_put = sub.add_parser("store-put")
    p_put.add_argument("--root", required=True)
    p_put.add_argument("--in", dest="input", required=True)
    p_put.set_defaults(func=cmd_store_put)

    p_get = sub.add_parser("store-get")
    p_get.add_argument("--root", required=True)
    p_get.add_argument("--locator", required=True)
    p_get.set_defaults(func=cmd_store_get)

    p_ta = sub.add_parser("build-trust-anchor")
    p_ta.add_argument("--params", required=True)
    p_ta.add_argument("--out", required=True)
    p_ta.set_defaults(func=cmd_build_trust_anchor)

    p_reg = sub.add_parser("build-registry")
    p_reg.add_argument("--params", required=True)
    p_reg.add_argument("--out", required=True)
    p_reg.set_defaults(func=cmd_build_registry)

    p_pol = sub.add_parser("build-policy")
    p_pol.add_argument("--params", required=True)
    p_pol.add_argument("--out", required=True)
    p_pol.set_defaults(func=cmd_build_policy)

    p_merge = sub.add_parser("build-merge-evidence")
    p_merge.add_argument("--params", required=True)
    p_merge.add_argument(
        "--protection-json",
        help=(
            "Offline substitute for the live 'gh api' branch-protection check. "
            "Requires --offline-protection-ack; use only when the live check is "
            "genuinely unavailable."
        ),
    )
    p_merge.add_argument(
        "--offline-protection-ack",
        help=(
            "Required alongside --protection-json. Must be the literal string "
            "I_UNDERSTAND_THIS_IS_NOT_LIVE_EVIDENCE, so the offline path cannot "
            "be used casually."
        ),
    )
    p_merge.add_argument(
        "--repository",
        help="owner/repo used for the live 'gh api repos/<repo>/branches/<ref>' check",
    )
    p_merge.add_argument(
        "--ref",
        help="branch ref used for the live 'gh api repos/<repo>/branches/<ref>' check",
    )
    p_merge.add_argument("--out", required=True)
    p_merge.set_defaults(func=cmd_build_merge_evidence)

    p_receipt = sub.add_parser("build-receipt")
    p_receipt.add_argument("--params", required=True)
    p_receipt.add_argument("--out", required=True)
    p_receipt.set_defaults(func=cmd_build_receipt)

    p_runctx = sub.add_parser("build-run-context")
    p_runctx.add_argument("--params", required=True)
    p_runctx.add_argument("--out", required=True)
    p_runctx.set_defaults(func=cmd_build_run_context)

    p_delivery = sub.add_parser("build-delivery-mode")
    p_delivery.add_argument("--params", required=True)
    p_delivery.add_argument("--out", required=True)
    p_delivery.set_defaults(func=cmd_build_delivery_mode)

    p_resolve_legacy = sub.add_parser("resolve-legacy-step2")
    p_resolve_legacy.add_argument("--legacy-repo", required=True)
    p_resolve_legacy.add_argument("--baseline", required=True)
    p_resolve_legacy.add_argument(
        "--w1-gate-sha",
        default=None,
        help=(
            "Override the W1-GATE protected-merge SHA used to resolve ancestry and "
            "tree presence. Defaults to the real ADR-pinned constant; only meant to "
            "be overridden by tests against a fixture repo."
        ),
    )
    p_resolve_legacy.add_argument(
        "--wave1-merges",
        default=None,
        help=(
            "Path to a JSON object {'W1A':sha,'W1B-G':sha,'W1B-P':sha} overriding the "
            "wave-1 protected-merge SHAs. Defaults to the real ADR-pinned constants; "
            "only meant to be overridden by tests against a fixture repo."
        ),
    )
    p_resolve_legacy.add_argument("--out", required=True)
    p_resolve_legacy.set_defaults(func=cmd_resolve_legacy_step2)

    p_build_legacy = sub.add_parser("build-legacy-step2-evidence")
    p_build_legacy.add_argument("--params", required=True)
    p_build_legacy.add_argument("--out", required=True)
    p_build_legacy.set_defaults(func=cmd_build_legacy_step2_evidence)

    for command in (
        "resolve-decomposition-inventory",
        "build-decomposition-manifest",
        "verify-decomposition-manifest",
        "prepare-decomposition-review",
        "prepare-decomposition-dispositions",
    ):
        p_dec = sub.add_parser(
            command, help="local unratified draft; never a signable envelope"
        )
        p_dec.add_argument("--legacy-repo", required=True)
        if command != "verify-decomposition-manifest":
            p_dec.add_argument("--out", required=True)
        if command == "build-decomposition-manifest":
            p_dec.add_argument("--params", required=True)
            p_dec.add_argument("--generated-at", required=True)
        elif command == "verify-decomposition-manifest":
            p_dec.add_argument("--in", dest="input", required=True)
        p_dec.set_defaults(func=cmd_decomposition)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (KeyError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
