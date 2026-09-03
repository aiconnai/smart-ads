"""argparse CLI for the Smart Ads governance toolkit.

Every command prints JSON to stdout on success, or writes a file and prints
its path, size and sha256. All file writes are verified: size must be > 0 and
the bytes are re-read after write before the command reports success. Exit
code 0 = success, 1 = expected/validated failure (verify failed, guard
rejected the input), 2 = usage error.

Run as: `python3 -m tools.governance.cli <command> ...`
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from tools.governance import artifacts, p1
from tools.governance.jcs import canonicalize, loads_strict
from tools.governance.locator import Store, validate_locator

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


def _write_json_file(path: str, value: dict[str, Any]) -> dict[str, Any]:
    canonical = canonicalize(value)
    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(canonical)
    written = out_path.read_bytes()
    if len(written) == 0 or written != canonical:
        raise ValueError(f"cli: write verification failed for {path}")
    digest = hashlib.sha256(written).hexdigest()
    return {"path": str(out_path), "size": len(written), "sha256": digest}


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
    info = _write_json_file(args.out, signed)
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
    raw32 = base64.b64decode(params["anchor_public_key_base64"], validate=True)
    config = artifacts.build_trust_anchor_config(
        anchor_id=params["anchor_id"],
        anchor_public_raw32=raw32,
        valid_from_utc=params["valid_from_utc"],
        valid_until_utc=params["valid_until_utc"],
        allowed_registry_artifact_types=params["allowed_registry_artifact_types"],
    )
    info = _write_json_file(args.out, config)
    info["trust_anchor_pin"] = artifacts.trust_anchor_pin(config)
    _print_json(info)
    return 0


def cmd_build_registry(args: argparse.Namespace) -> int:
    params = _read_json_file(args.params)
    registry = artifacts.build_key_registry(
        trust_anchor_id=params["trust_anchor_id"],
        epoch=params["epoch"],
        issued_at_utc=params["issued_at_utc"],
        entries=params["entries"],
        signer_key_id=params["signer_key_id"],
    )
    info = _write_json_file(args.out, registry)
    _print_json(info)
    return 0


def cmd_build_policy(args: argparse.Namespace) -> int:
    params = _read_json_file(args.params)
    policy = artifacts.build_gate2_authority_policy(
        repository=params["repository"],
        protected_ref=params["protected_ref"],
        adr_path=params["adr_path"],
        ci_review_policy_digest=params["ci_review_policy_digest"],
        designated_principals=params["designated_principals"],
        registry_locator=params["registry_locator"],
        signer_key_id=params["signer_key_id"],
    )
    info = _write_json_file(args.out, policy)
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
    info = _write_json_file(args.out, evidence)
    _print_json(info)
    return 0


def cmd_build_receipt(args: argparse.Namespace) -> int:
    params = _read_json_file(args.params)
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
    info = _write_json_file(args.out, receipt)
    _print_json(info)
    return 0


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
