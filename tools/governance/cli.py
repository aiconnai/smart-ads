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

from smart_ads.contracts.jcs import ADR_P1_DOMAIN_PREFIXES
from tools.governance import (
    artifacts,
    decomposition as dec,
    gov1_convergence,
    gov1_mcp,
    gov1_sandbox,
    gov1_wheel,
    legacy_step2,
    p1,
)
from tools.governance.decomposition_governance import inspect_governance
from tools.governance.decomposition_review import build_review_bundle
from tools.governance.decomposition_runtime import validity
from tools.governance.decomposition_scope import resolve_scope
from tools.governance.jcs import canonicalize, loads_strict
from tools.governance.locator import Store, digest, exact_fields, make_locator, timestamp

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
    if out_path.is_symlink():
        raise ValueError(f"cli: symlink output path forbidden: {path}")
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


def _write_binary_file(
    path: str, raw: bytes, *, allow_overwrite: bool
) -> dict[str, Any]:
    if type(raw) is not bytes or len(raw) == 0:
        raise ValueError("cli: expected non-empty binary payload")
    out_path = Path(path)
    if out_path.is_symlink():
        raise ValueError(f"gov1: symlink output path forbidden: {path}")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if not allow_overwrite and out_path.exists():
        raise ValueError("gov1: output exists; choose a fresh output path")
    fd, temp = tempfile.mkstemp(prefix=".gov1-", dir=out_path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temp, 0o644)
        if allow_overwrite:
            os.replace(temp, out_path)
        else:
            os.link(temp, out_path)
        directory = os.open(out_path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(temp).unlink(missing_ok=True)
    written = out_path.read_bytes()
    if len(written) == 0 or written != raw:
        raise ValueError(f"cli: binary write verification failed for {path}")
    return {
        "path": str(out_path),
        "size": len(written),
        "sha256": digest(written),
    }


def _exact_with_optional_fields(
    value: object,
    required: set[str],
    optional: set[str],
    label: str,
) -> None:
    present_optional = (set(value) & optional) if isinstance(value, dict) else set()
    exact_fields(value, required | present_optional, label)


def _resolve_gov1_envelope_signing_meta(
    args: argparse.Namespace, params: dict[str, Any], label: str
) -> tuple[str, dict[str, Any]]:
    cli_kid = getattr(args, "signer_key_id", None)
    param_kid = params.get("signer_key_id")
    if cli_kid is not None and param_kid is not None and cli_kid != param_kid:
        raise ValueError(f"{label}: conflicting --signer-key-id and params.signer_key_id")
    signer_key_id = cli_kid if cli_kid is not None else param_kid
    if type(signer_key_id) is not str or not signer_key_id.strip():
        raise ValueError(f"{label}: --mode envelope requires --signer-key-id (or params.signer_key_id)")

    cli_reg_path = getattr(args, "registry_locator", None)
    cli_reg = _read_json_file(cli_reg_path) if cli_reg_path is not None else None
    param_reg = params.get("registry_locator")
    if cli_reg is not None and param_reg is not None:
        if canonicalize(cli_reg) != canonicalize(param_reg):
            raise ValueError(
                f"{label}: conflicting --registry-locator and params.registry_locator"
            )
    registry_locator = cli_reg if cli_reg is not None else param_reg
    if not isinstance(registry_locator, dict):
        raise ValueError(
            f"{label}: --mode envelope requires --registry-locator (or params.registry_locator)"
        )
    return signer_key_id, registry_locator


def _reject_envelope_flags_in_candidate_mode(
    args: argparse.Namespace, label: str
) -> None:
    if getattr(args, "signer_key_id", None) is not None or getattr(
        args, "registry_locator", None
    ) is not None:
        raise ValueError(
            f"{label}: --signer-key-id and --registry-locator require --mode envelope"
        )


def _guard_gov1_output_path(path: str, *, allow_overwrite: bool) -> Path:
    out_path = Path(path)
    if out_path.is_symlink():
        raise ValueError(f"gov1: symlink output path forbidden: {path}")
    if not allow_overwrite and out_path.exists():
        raise ValueError("gov1: output exists; choose a fresh output path")
    return out_path


def _decode_ed25519_pubkey_b64(
    pubkey_b64: object, *, cmd: str, flag_name: str
) -> bytes:
    if type(pubkey_b64) is not str or not pubkey_b64:
        raise ValueError(
            f"{cmd}: P1 envelope verification requires {flag_name} (or D4 Gov1AdmissionVerifier)"
        )
    raw32 = p1._strict_base64_decode(pubkey_b64)
    if len(raw32) != 32:
        raise ValueError(
            f"{cmd}: {flag_name} must decode to a 32-byte raw Ed25519 public key"
        )
    return raw32


def _verify_cli_p1_envelope_signature(
    envelope: dict[str, Any],
    *,
    schema: str,
    pubkey_b64: object,
    cmd: str,
    flag_name: str = "--pubkey-raw-base64",
) -> None:
    raw32 = _decode_ed25519_pubkey_b64(pubkey_b64, cmd=cmd, flag_name=flag_name)
    domain_prefix = ADR_P1_DOMAIN_PREFIXES.get(schema)
    if domain_prefix is None:
        raise ValueError(
            f"{cmd}: unknown GOV 1 P1 domain prefix for schema {schema!r}"
        )
    integrity = envelope.get("integrity")
    if not isinstance(integrity, dict) or integrity.get("key_id") != p1.key_id_for(
        raw32
    ):
        raise ValueError(
            f"{cmd}: envelope integrity.key_id mismatch against {flag_name}"
        )
    p1.verify_envelope(envelope, domain_prefix, raw32)


def _verify_boundary_provenance_cross_bindings(
    boundary_obj: dict[str, Any],
    prov_obj: dict[str, Any],
    *,
    cmd: str,
) -> None:
    if canonicalize(boundary_obj["migration_run_context_locator"]) != canonicalize(
        prov_obj["migration_run_context_locator"]
    ):
        raise ValueError(
            f"{cmd}: migration_run_context_locator mismatch against --provenance"
        )
    for field in (
        "build_run_id",
        "repository",
        "source_commit_sha",
        "wheel_digest",
        "build_backend_digest",
        "schema_bundle_digest",
    ):
        if boundary_obj[field] != prov_obj[field]:
            raise ValueError(f"{cmd}: {field} mismatch against --provenance")
    if timestamp(boundary_obj["verified_at_utc"]) < timestamp(prov_obj["built_at_utc"]):
        raise ValueError(f"{cmd}: verified_at_utc precedes provenance built_at_utc")


def run_gov1(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    try:
        return _run_gov1(args)
    except (OSError, TypeError, UnicodeError) as exc:
        raise ValueError(
            f"gov1: invalid input or local I/O failure ({type(exc).__name__})"
        ) from exc


def _run_gov1(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    cmd = args.command

    if cmd == "build-sealed-sandbox-profile":
        mode = args.mode
        _guard_gov1_output_path(args.out, allow_overwrite=(mode == "envelope"))
        params = _read_json_file(args.params)
        req = {
            "migration_run_context_locator",
            "oci_image_digest",
            "runner_binary_digest",
            "issued_at_utc",
            "valid_from_utc",
            "valid_until_utc",
        }
        opt = {"signer_key_id", "registry_locator"} if mode == "envelope" else set()
        _exact_with_optional_fields(params, req, opt, "build-sealed-sandbox-profile params")
        seccomp = _read_json_file(args.seccomp_profile)
        if mode == "candidate":
            _reject_envelope_flags_in_candidate_mode(args, cmd)
            artifact = gov1_sandbox.build_sealed_sandbox_profile_candidate(
                migration_run_context_locator=params["migration_run_context_locator"],
                oci_image_digest=params["oci_image_digest"],
                runner_binary_digest=params["runner_binary_digest"],
                seccomp_profile=seccomp,
                issued_at_utc=params["issued_at_utc"],
                valid_from_utc=params["valid_from_utc"],
                valid_until_utc=params["valid_until_utc"],
            )
            return _write_json_file(args.out, artifact, allow_overwrite=False), 0
        signer_key_id, registry_locator = _resolve_gov1_envelope_signing_meta(
            args, params, cmd
        )
        artifact = gov1_sandbox.build_sealed_sandbox_profile_envelope(
            migration_run_context_locator=params["migration_run_context_locator"],
            oci_image_digest=params["oci_image_digest"],
            runner_binary_digest=params["runner_binary_digest"],
            seccomp_profile=seccomp,
            issued_at_utc=params["issued_at_utc"],
            valid_from_utc=params["valid_from_utc"],
            valid_until_utc=params["valid_until_utc"],
            registry_locator=registry_locator,
            signer_key_id=signer_key_id,
        )
        return _write_json_file(args.out, artifact, allow_overwrite=True), 0

    if cmd == "verify-sealed-sandbox-profile":
        artifact = _read_json_file(args.input)
        seccomp = _read_json_file(args.seccomp_profile)
        verified = gov1_sandbox.verify_sealed_sandbox_profile(
            artifact, seccomp_profile=seccomp
        )
        if verified["mode"] == "candidate":
            if args.pubkey_raw_base64 is not None:
                raise ValueError(f"{cmd}: --pubkey-raw-base64 requires envelope input")
            return {
                "status": "PASS",
                "mode": "candidate",
                "signable": False,
                "authority": "none",
                "schema": verified["schema"],
                "profile_id": verified["profile_id"],
                "seccomp_profile_digest": verified["seccomp_profile_digest"],
            }, 0
        _verify_cli_p1_envelope_signature(
            artifact,
            schema=verified["schema"],
            pubkey_b64=args.pubkey_raw_base64,
            cmd=cmd,
        )
        return {
            "status": "PASS",
            "mode": "envelope",
            "signature_verified": True,
            "d4_authority_verified": False,
            "authority": "none",
            "schema": verified["schema"],
            "profile_id": verified["profile_id"],
            "seccomp_profile_digest": verified["seccomp_profile_digest"],
        }, 0

    if cmd == "build-wheel-provenance":
        mode = args.mode
        params = _read_json_file(args.params)
        req = {"migration_run_context_locator", "build_run_id", "built_at_utc"}
        opt = {"commit_ref", "source_date_epoch", "repository", "wheel_out"}
        if mode == "envelope":
            opt = opt | {"signer_key_id", "registry_locator"}
        _exact_with_optional_fields(params, req, opt, "build-wheel-provenance params")

        cli_wheel_out = args.wheel_out
        param_wheel_out = params.get("wheel_out")
        if (
            cli_wheel_out is not None
            and param_wheel_out is not None
            and cli_wheel_out != param_wheel_out
        ):
            raise ValueError(
                "build-wheel-provenance: conflicting --wheel-out and params.wheel_out"
            )
        wheel_out_str = cli_wheel_out if cli_wheel_out is not None else param_wheel_out
        if type(wheel_out_str) is not str or not wheel_out_str.strip():
            raise ValueError(
                "build-wheel-provenance: require --wheel-out (or params.wheel_out)"
            )

        allow_overwrite = mode == "envelope"
        _guard_gov1_output_path(args.out, allow_overwrite=allow_overwrite)
        _guard_gov1_output_path(wheel_out_str, allow_overwrite=allow_overwrite)
        if (
            Path(os.path.abspath(args.out)) == Path(os.path.abspath(wheel_out_str))
            or Path(args.out).resolve() == Path(wheel_out_str).resolve()
        ):
            raise ValueError(
                "build-wheel-provenance: --out and --wheel-out must refer to distinct paths"
            )
        if not allow_overwrite:
            _reject_envelope_flags_in_candidate_mode(args, cmd)
        else:
            signer_key_id, registry_locator = _resolve_gov1_envelope_signing_meta(
                args, params, cmd
            )

        commit_ref = params.get("commit_ref", "HEAD")
        if type(commit_ref) is not str or not commit_ref.strip():
            raise ValueError("build-wheel-provenance: commit_ref must be a non-empty string")
        source_date_epoch = params.get(
            "source_date_epoch", gov1_wheel.DEFAULT_SOURCE_DATE_EPOCH
        )
        if type(source_date_epoch) is not int:
            raise ValueError("build-wheel-provenance: source_date_epoch must be an int")
        repository = params.get("repository", gov1_wheel.DEFAULT_REPOSITORY)

        with tempfile.TemporaryDirectory(prefix="gov1-cli-wheel-") as stage_root:
            staged_whl, snapshot = gov1_wheel.build_reproducible_wheel(
                Path(args.repo),
                Path(stage_root) / "dist",
                commit_ref=commit_ref,
                source_date_epoch=source_date_epoch,
            )
            inspection = gov1_wheel.inspect_wheel_boundary(staged_whl)
            wheel_bytes = staged_whl.read_bytes()

        if mode == "candidate":
            artifact = gov1_wheel.build_wheel_build_provenance_candidate(
                migration_run_context_locator=params["migration_run_context_locator"],
                build_run_id=params["build_run_id"],
                built_at_utc=params["built_at_utc"],
                snapshot=snapshot,
                source_date_epoch=source_date_epoch,
                schema_bundle_digest=inspection["schema_bundle_digest"],
                wheel_bytes=wheel_bytes,
                repository=repository,
            )
        else:
            artifact = gov1_wheel.build_wheel_build_provenance_envelope(
                migration_run_context_locator=params["migration_run_context_locator"],
                build_run_id=params["build_run_id"],
                built_at_utc=params["built_at_utc"],
                snapshot=snapshot,
                source_date_epoch=source_date_epoch,
                schema_bundle_digest=inspection["schema_bundle_digest"],
                wheel_bytes=wheel_bytes,
                registry_locator=registry_locator,
                signer_key_id=signer_key_id,
                repository=repository,
            )

        wheel_meta = _write_binary_file(
            wheel_out_str, wheel_bytes, allow_overwrite=allow_overwrite
        )
        try:
            info = _write_json_file(args.out, artifact, allow_overwrite=allow_overwrite)
        except Exception:
            if not allow_overwrite:
                Path(wheel_out_str).unlink(missing_ok=True)
            raise
        info["wheel_path"] = wheel_meta["path"]
        info["wheel_size"] = wheel_meta["size"]
        info["wheel_sha256"] = wheel_meta["sha256"]
        return info, 0

    if cmd == "verify-wheel-provenance":
        artifact = _read_json_file(args.input)
        if artifact.get("artifact_kind") == gov1_sandbox.LOCAL_CANDIDATE_KIND:
            if args.pubkey_raw_base64 is not None:
                raise ValueError(f"{cmd}: --pubkey-raw-base64 requires envelope input")
        elif artifact.get("$schema") == gov1_wheel.WHEEL_BUILD_PROVENANCE_SCHEMA:
            _verify_cli_p1_envelope_signature(
                artifact,
                schema=gov1_wheel.WHEEL_BUILD_PROVENANCE_SCHEMA,
                pubkey_b64=args.pubkey_raw_base64,
                cmd=cmd,
            )
        verified = gov1_wheel.verify_wheel_build_provenance(
            artifact,
            repo_root=Path(args.repo),
            wheel_path=Path(args.wheel),
        )
        if verified["mode"] == "candidate":
            if args.pubkey_raw_base64 is not None:
                raise ValueError(f"{cmd}: --pubkey-raw-base64 requires envelope input")
            return {
                "status": "PASS",
                "mode": "candidate",
                "signable": False,
                "authority": "none",
                "schema": verified["schema"],
                "wheel_digest": verified["wheel_digest"],
                "source_commit_sha": verified["source_commit_sha"],
                "build_backend_digest": verified["build_backend_digest"],
                "schema_bundle_digest": verified["schema_bundle_digest"],
            }, 0
        _verify_cli_p1_envelope_signature(
            artifact,
            schema=verified["schema"],
            pubkey_b64=args.pubkey_raw_base64,
            cmd=cmd,
        )
        return {
            "status": "PASS",
            "mode": "envelope",
            "signature_verified": True,
            "d4_authority_verified": False,
            "authority": "none",
            "schema": verified["schema"],
            "wheel_digest": verified["wheel_digest"],
            "source_commit_sha": verified["source_commit_sha"],
            "build_backend_digest": verified["build_backend_digest"],
            "schema_bundle_digest": verified["schema_bundle_digest"],
        }, 0

    if cmd == "build-wheel-boundary-report":
        mode = args.mode
        _guard_gov1_output_path(args.out, allow_overwrite=(mode == "envelope"))
        params = _read_json_file(args.params)
        req = {
            "migration_run_context_locator",
            "build_run_id",
            "verified_at_utc",
            "source_commit_sha",
            "build_backend_digest",
        }
        if mode == "candidate":
            opt = {"repository", "wheel_build_provenance_candidate_ref"}
            _exact_with_optional_fields(
                params, req, opt, "build-wheel-boundary-report params"
            )
            _reject_envelope_flags_in_candidate_mode(args, cmd)
            if args.provenance_locator is not None:
                raise ValueError(
                    "build-wheel-boundary-report: --provenance-locator requires --mode envelope"
                )
            cli_ref = (
                gov1_sandbox.build_local_candidate_ref(_read_json_file(args.provenance))
                if args.provenance is not None
                else None
            )
            param_ref = params.get("wheel_build_provenance_candidate_ref")
            if cli_ref is not None and param_ref is not None:
                if canonicalize(cli_ref) != canonicalize(param_ref):
                    raise ValueError(
                        "build-wheel-boundary-report: conflicting --provenance and params.wheel_build_provenance_candidate_ref"
                    )
            prov_ref = cli_ref if cli_ref is not None else param_ref
            if not isinstance(prov_ref, dict):
                raise ValueError(
                    "build-wheel-boundary-report: require --provenance (or params.wheel_build_provenance_candidate_ref)"
                )
            inspection = gov1_wheel.inspect_wheel_boundary(Path(args.wheel))
            artifact = gov1_wheel.build_wheel_boundary_report_candidate(
                migration_run_context_locator=params["migration_run_context_locator"],
                build_run_id=params["build_run_id"],
                verified_at_utc=params["verified_at_utc"],
                source_commit_sha=params["source_commit_sha"],
                build_backend_digest=params["build_backend_digest"],
                wheel_build_provenance_candidate_ref=prov_ref,
                inspection=inspection,
                repository=params.get("repository", gov1_wheel.DEFAULT_REPOSITORY),
            )
            return _write_json_file(args.out, artifact, allow_overwrite=False), 0

        opt = {
            "repository",
            "wheel_build_provenance_locator",
            "signer_key_id",
            "registry_locator",
        }
        _exact_with_optional_fields(
            params, req, opt, "build-wheel-boundary-report params"
        )
        if args.provenance is not None:
            raise ValueError(
                "build-wheel-boundary-report: --provenance is for candidate mode; use --provenance-locator in envelope mode"
            )
        signer_key_id, registry_locator = _resolve_gov1_envelope_signing_meta(
            args, params, cmd
        )
        cli_loc = (
            _read_json_file(args.provenance_locator)
            if args.provenance_locator is not None
            else None
        )
        param_loc = params.get("wheel_build_provenance_locator")
        if cli_loc is not None and param_loc is not None:
            if canonicalize(cli_loc) != canonicalize(param_loc):
                raise ValueError(
                    "build-wheel-boundary-report: conflicting --provenance-locator and params.wheel_build_provenance_locator"
                )
        prov_loc = cli_loc if cli_loc is not None else param_loc
        if not isinstance(prov_loc, dict):
            raise ValueError(
                "build-wheel-boundary-report: --mode envelope requires --provenance-locator (or params.wheel_build_provenance_locator)"
            )
        inspection = gov1_wheel.inspect_wheel_boundary(Path(args.wheel))
        artifact = gov1_wheel.build_wheel_boundary_report_envelope(
            migration_run_context_locator=params["migration_run_context_locator"],
            build_run_id=params["build_run_id"],
            verified_at_utc=params["verified_at_utc"],
            source_commit_sha=params["source_commit_sha"],
            build_backend_digest=params["build_backend_digest"],
            wheel_build_provenance_locator=prov_loc,
            inspection=inspection,
            registry_locator=registry_locator,
            signer_key_id=signer_key_id,
            repository=params.get("repository", gov1_wheel.DEFAULT_REPOSITORY),
        )
        return _write_json_file(args.out, artifact, allow_overwrite=True), 0

    if cmd == "verify-wheel-boundary-report":
        artifact = _read_json_file(args.input)
        if artifact.get("artifact_kind") == gov1_sandbox.LOCAL_CANDIDATE_KIND:
            if (
                args.pubkey_raw_base64 is not None
                or args.provenance_pubkey_raw_base64 is not None
            ):
                raise ValueError(f"{cmd}: --pubkey-raw-base64 requires envelope input")
            if (args.provenance is not None) != (args.repo is not None):
                raise ValueError(
                    f"{cmd}: --provenance and --repo must be supplied together"
                )
        elif artifact.get("$schema") == gov1_wheel.WHEEL_BOUNDARY_REPORT_SCHEMA:
            _verify_cli_p1_envelope_signature(
                artifact,
                schema=gov1_wheel.WHEEL_BOUNDARY_REPORT_SCHEMA,
                pubkey_b64=args.pubkey_raw_base64,
                cmd=cmd,
            )
            if (
                args.provenance is None
                or args.repo is None
                or args.provenance_pubkey_raw_base64 is None
            ):
                raise ValueError(
                    f"{cmd}: envelope verification requires --provenance, --repo, and --provenance-pubkey-raw-base64"
                )
            prov_pre = _read_json_file(args.provenance)
            if (
                "artifact_kind" in prov_pre
                or prov_pre.get("$schema") != gov1_wheel.WHEEL_BUILD_PROVENANCE_SCHEMA
            ):
                raise ValueError(
                    f"{cmd}: envelope boundary report requires P1 envelope --provenance"
                )
            _verify_cli_p1_envelope_signature(
                prov_pre,
                schema=gov1_wheel.WHEEL_BUILD_PROVENANCE_SCHEMA,
                pubkey_b64=args.provenance_pubkey_raw_base64,
                cmd=cmd,
                flag_name="--provenance-pubkey-raw-base64",
            )
        verified = gov1_wheel.verify_wheel_boundary_report(
            artifact, wheel_path=Path(args.wheel)
        )
        if verified["mode"] == "candidate":
            if (
                args.pubkey_raw_base64 is not None
                or args.provenance_pubkey_raw_base64 is not None
            ):
                raise ValueError(f"{cmd}: --pubkey-raw-base64 requires envelope input")
            if (args.provenance is not None) != (args.repo is not None):
                raise ValueError(
                    f"{cmd}: --provenance and --repo must be supplied together"
                )
            if args.provenance is not None:
                prov_cand = _read_json_file(args.provenance)
                if prov_cand.get("artifact_kind") != gov1_sandbox.LOCAL_CANDIDATE_KIND:
                    raise ValueError(
                        f"{cmd}: candidate boundary report requires candidate --provenance"
                    )
                gov1_sandbox.verify_local_candidate_ref(
                    artifact["payload"]["wheel_build_provenance_candidate_ref"],
                    expected_schema=gov1_wheel.WHEEL_BUILD_PROVENANCE_SCHEMA,
                    expected_candidate=prov_cand,
                )
                _verify_boundary_provenance_cross_bindings(
                    artifact["payload"], prov_cand["payload"], cmd=cmd
                )
                gov1_wheel.verify_wheel_build_provenance(
                    prov_cand,
                    repo_root=Path(args.repo),
                    wheel_path=Path(args.wheel),
                )
            return {
                "status": "PASS",
                "mode": "candidate",
                "signable": False,
                "authority": "none",
                "schema": verified["schema"],
                "wheel_digest": verified["wheel_digest"],
                "schema_bundle_digest": verified["schema_bundle_digest"],
                "sorted_record_digest": verified["sorted_record_digest"],
            }, 0

        _verify_cli_p1_envelope_signature(
            artifact,
            schema=verified["schema"],
            pubkey_b64=args.pubkey_raw_base64,
            cmd=cmd,
        )
        if (
            args.provenance is None
            or args.repo is None
            or args.provenance_pubkey_raw_base64 is None
        ):
            raise ValueError(
                f"{cmd}: envelope verification requires --provenance, --repo, and --provenance-pubkey-raw-base64"
            )
        prov_env = _read_json_file(args.provenance)
        if (
            "artifact_kind" in prov_env
            or prov_env.get("$schema") != gov1_wheel.WHEEL_BUILD_PROVENANCE_SCHEMA
        ):
            raise ValueError(
                f"{cmd}: envelope boundary report requires P1 envelope --provenance"
            )
        _verify_cli_p1_envelope_signature(
            prov_env,
            schema=gov1_wheel.WHEEL_BUILD_PROVENANCE_SCHEMA,
            pubkey_b64=args.provenance_pubkey_raw_base64,
            cmd=cmd,
            flag_name="--provenance-pubkey-raw-base64",
        )
        expected_prov_loc = make_locator(
            gov1_wheel.WHEEL_BUILD_PROVENANCE_SCHEMA, canonicalize(prov_env)
        )
        if canonicalize(artifact["wheel_build_provenance_locator"]) != canonicalize(
            expected_prov_loc
        ):
            raise ValueError(
                f"{cmd}: wheel_build_provenance_locator mismatch against --provenance"
            )
        _verify_boundary_provenance_cross_bindings(artifact, prov_env, cmd=cmd)
        gov1_wheel.verify_wheel_build_provenance(
            prov_env,
            repo_root=Path(args.repo),
            wheel_path=Path(args.wheel),
        )
        return {
            "status": "PASS",
            "mode": "envelope",
            "signature_verified": True,
            "d4_authority_verified": False,
            "authority": "none",
            "schema": verified["schema"],
            "wheel_digest": verified["wheel_digest"],
            "schema_bundle_digest": verified["schema_bundle_digest"],
            "sorted_record_digest": verified["sorted_record_digest"],
        }, 0

    if cmd == "build-mcp-rejection-report":
        mode = args.mode
        _guard_gov1_output_path(args.out, allow_overwrite=(mode == "envelope"))
        params = _read_json_file(args.params)
        req = {
            "migration_run_context_locator",
            "build_run_id",
            "executed_at_utc",
            "source_commit_sha",
            "build_backend_digest",
        }
        if mode == "candidate":
            opt = {"sealed_sandbox_profile_candidate_ref"}
            _exact_with_optional_fields(
                params, req, opt, "build-mcp-rejection-report params"
            )
            _reject_envelope_flags_in_candidate_mode(args, cmd)
            if args.sandbox_profile_locator is not None:
                raise ValueError(
                    "build-mcp-rejection-report: --sandbox-profile-locator requires --mode envelope"
                )
            cli_ref = (
                gov1_sandbox.build_local_candidate_ref(
                    _read_json_file(args.sandbox_profile)
                )
                if args.sandbox_profile is not None
                else None
            )
            param_ref = params.get("sealed_sandbox_profile_candidate_ref")
            if cli_ref is not None and param_ref is not None:
                if canonicalize(cli_ref) != canonicalize(param_ref):
                    raise ValueError(
                        "build-mcp-rejection-report: conflicting --sandbox-profile and params.sealed_sandbox_profile_candidate_ref"
                    )
            sbx_ref = cli_ref if cli_ref is not None else param_ref
            if not isinstance(sbx_ref, dict):
                raise ValueError(
                    "build-mcp-rejection-report: require --sandbox-profile (or params.sealed_sandbox_profile_candidate_ref)"
                )
            execution = gov1_mcp.execute_mcp_rejection_matrix_on_wheel(Path(args.wheel))
            artifact = gov1_mcp.build_mcp_rejection_matrix_report_candidate(
                migration_run_context_locator=params["migration_run_context_locator"],
                build_run_id=params["build_run_id"],
                executed_at_utc=params["executed_at_utc"],
                source_commit_sha=params["source_commit_sha"],
                build_backend_digest=params["build_backend_digest"],
                sealed_sandbox_profile_candidate_ref=sbx_ref,
                execution=execution,
            )
            return _write_json_file(args.out, artifact, allow_overwrite=False), 0

        opt = {
            "sealed_sandbox_profile_locator",
            "signer_key_id",
            "registry_locator",
        }
        _exact_with_optional_fields(
            params, req, opt, "build-mcp-rejection-report params"
        )
        if args.sandbox_profile is not None:
            raise ValueError(
                "build-mcp-rejection-report: --sandbox-profile is for candidate mode; use --sandbox-profile-locator in envelope mode"
            )
        signer_key_id, registry_locator = _resolve_gov1_envelope_signing_meta(
            args, params, cmd
        )
        cli_loc = (
            _read_json_file(args.sandbox_profile_locator)
            if args.sandbox_profile_locator is not None
            else None
        )
        param_loc = params.get("sealed_sandbox_profile_locator")
        if cli_loc is not None and param_loc is not None:
            if canonicalize(cli_loc) != canonicalize(param_loc):
                raise ValueError(
                    "build-mcp-rejection-report: conflicting --sandbox-profile-locator and params.sealed_sandbox_profile_locator"
                )
        sbx_loc = cli_loc if cli_loc is not None else param_loc
        if not isinstance(sbx_loc, dict):
            raise ValueError(
                "build-mcp-rejection-report: --mode envelope requires --sandbox-profile-locator (or params.sealed_sandbox_profile_locator)"
            )
        execution = gov1_mcp.execute_mcp_rejection_matrix_on_wheel(Path(args.wheel))
        artifact = gov1_mcp.build_mcp_rejection_matrix_report_envelope(
            migration_run_context_locator=params["migration_run_context_locator"],
            build_run_id=params["build_run_id"],
            executed_at_utc=params["executed_at_utc"],
            source_commit_sha=params["source_commit_sha"],
            build_backend_digest=params["build_backend_digest"],
            sealed_sandbox_profile_locator=sbx_loc,
            execution=execution,
            registry_locator=registry_locator,
            signer_key_id=signer_key_id,
        )
        return _write_json_file(args.out, artifact, allow_overwrite=True), 0

    if cmd == "verify-mcp-rejection-report":
        artifact = _read_json_file(args.input)
        if artifact.get("artifact_kind") == gov1_sandbox.LOCAL_CANDIDATE_KIND:
            if (
                args.pubkey_raw_base64 is not None
                or args.sandbox_pubkey_raw_base64 is not None
            ):
                raise ValueError(f"{cmd}: --pubkey-raw-base64 requires envelope input")
            if (args.sandbox_profile is not None) != (
                args.seccomp_profile is not None
            ):
                raise ValueError(
                    f"{cmd}: --sandbox-profile and --seccomp-profile must be supplied together"
                )
        elif artifact.get("$schema") == gov1_mcp.MCP_REJECTION_REPORT_SCHEMA:
            _verify_cli_p1_envelope_signature(
                artifact,
                schema=gov1_mcp.MCP_REJECTION_REPORT_SCHEMA,
                pubkey_b64=args.pubkey_raw_base64,
                cmd=cmd,
            )
            if (
                args.sandbox_profile is None
                or args.seccomp_profile is None
                or args.sandbox_pubkey_raw_base64 is None
            ):
                raise ValueError(
                    f"{cmd}: envelope verification requires --sandbox-profile, --seccomp-profile, and --sandbox-pubkey-raw-base64"
                )
            sbx_pre = _read_json_file(args.sandbox_profile)
            if (
                "artifact_kind" in sbx_pre
                or sbx_pre.get("$schema") != gov1_sandbox.SANDBOX_PROFILE_SCHEMA
            ):
                raise ValueError(
                    f"{cmd}: envelope MCP report requires P1 envelope --sandbox-profile"
                )
            _verify_cli_p1_envelope_signature(
                sbx_pre,
                schema=gov1_sandbox.SANDBOX_PROFILE_SCHEMA,
                pubkey_b64=args.sandbox_pubkey_raw_base64,
                cmd=cmd,
                flag_name="--sandbox-pubkey-raw-base64",
            )
        verified = gov1_mcp.verify_mcp_rejection_matrix_report(
            artifact, wheel_path=Path(args.wheel)
        )
        if verified["mode"] == "candidate":
            if (
                args.pubkey_raw_base64 is not None
                or args.sandbox_pubkey_raw_base64 is not None
            ):
                raise ValueError(f"{cmd}: --pubkey-raw-base64 requires envelope input")
            if (args.sandbox_profile is not None) != (
                args.seccomp_profile is not None
            ):
                raise ValueError(
                    f"{cmd}: --sandbox-profile and --seccomp-profile must be supplied together"
                )
            if args.sandbox_profile is not None:
                sbx_cand = _read_json_file(args.sandbox_profile)
                seccomp = _read_json_file(args.seccomp_profile)
                if sbx_cand.get("artifact_kind") != gov1_sandbox.LOCAL_CANDIDATE_KIND:
                    raise ValueError(
                        f"{cmd}: candidate MCP report requires candidate --sandbox-profile"
                    )
                gov1_sandbox.verify_local_candidate_ref(
                    artifact["payload"]["sealed_sandbox_profile_candidate_ref"],
                    expected_schema=gov1_sandbox.SANDBOX_PROFILE_SCHEMA,
                    expected_candidate=sbx_cand,
                )
                gov1_sandbox.verify_sealed_sandbox_profile(
                    sbx_cand, seccomp_profile=seccomp
                )
                if canonicalize(
                    artifact["payload"]["migration_run_context_locator"]
                ) != canonicalize(sbx_cand["payload"]["migration_run_context_locator"]):
                    raise ValueError(
                        f"{cmd}: migration_run_context_locator mismatch against --sandbox-profile"
                    )
                validity(
                    sbx_cand["payload"]["validity"],
                    artifact["payload"]["executed_at_utc"],
                )
            return {
                "status": "PASS",
                "mode": "candidate",
                "signable": False,
                "authority": "none",
                "schema": verified["schema"],
                "wheel_digest": verified["wheel_digest"],
                "schema_bundle_digest": verified["schema_bundle_digest"],
                "executed_at_utc": verified["executed_at_utc"],
            }, 0

        _verify_cli_p1_envelope_signature(
            artifact,
            schema=verified["schema"],
            pubkey_b64=args.pubkey_raw_base64,
            cmd=cmd,
        )
        if (
            args.sandbox_profile is None
            or args.seccomp_profile is None
            or args.sandbox_pubkey_raw_base64 is None
        ):
            raise ValueError(
                f"{cmd}: envelope verification requires --sandbox-profile, --seccomp-profile, and --sandbox-pubkey-raw-base64"
            )
        sbx_env = _read_json_file(args.sandbox_profile)
        seccomp = _read_json_file(args.seccomp_profile)
        if (
            "artifact_kind" in sbx_env
            or sbx_env.get("$schema") != gov1_sandbox.SANDBOX_PROFILE_SCHEMA
        ):
            raise ValueError(
                f"{cmd}: envelope MCP report requires P1 envelope --sandbox-profile"
            )
        _verify_cli_p1_envelope_signature(
            sbx_env,
            schema=gov1_sandbox.SANDBOX_PROFILE_SCHEMA,
            pubkey_b64=args.sandbox_pubkey_raw_base64,
            cmd=cmd,
            flag_name="--sandbox-pubkey-raw-base64",
        )
        expected_sbx_loc = make_locator(
            gov1_sandbox.SANDBOX_PROFILE_SCHEMA, canonicalize(sbx_env)
        )
        if canonicalize(artifact["sealed_sandbox_profile_locator"]) != canonicalize(
            expected_sbx_loc
        ):
            raise ValueError(
                f"{cmd}: sealed_sandbox_profile_locator mismatch against --sandbox-profile"
            )
        gov1_sandbox.verify_sealed_sandbox_profile(sbx_env, seccomp_profile=seccomp)
        if canonicalize(artifact["migration_run_context_locator"]) != canonicalize(
            sbx_env["migration_run_context_locator"]
        ):
            raise ValueError(
                f"{cmd}: migration_run_context_locator mismatch against --sandbox-profile"
            )
        validity(sbx_env["validity"], artifact["executed_at_utc"])
        return {
            "status": "PASS",
            "mode": "envelope",
            "signature_verified": True,
            "d4_authority_verified": False,
            "authority": "none",
            "schema": verified["schema"],
            "wheel_digest": verified["wheel_digest"],
            "schema_bundle_digest": verified["schema_bundle_digest"],
            "executed_at_utc": verified["executed_at_utc"],
        }, 0

    if cmd == "verify-pr1-gov1-convergence":
        if args.out is not None:
            _guard_gov1_output_path(args.out, allow_overwrite=False)
        seccomp = _read_json_file(args.seccomp_profile)
        sandbox_profile = _read_json_file(args.sandbox_profile)
        wheel_provenance = _read_json_file(args.wheel_provenance)
        wheel_boundary_report = _read_json_file(args.wheel_boundary_report)
        mcp_rejection_report = _read_json_file(args.mcp_rejection_report)
        receipt = gov1_convergence.verify_pr1_gov1_convergence(
            sandbox_profile=sandbox_profile,
            wheel_provenance=wheel_provenance,
            wheel_boundary_report=wheel_boundary_report,
            mcp_rejection_report=mcp_rejection_report,
            seccomp_profile=seccomp,
            wheel_path=Path(args.wheel),
            repo_root=Path(args.repo),
        )
        if args.out is None:
            return receipt, 0
        info = _write_json_file(args.out, receipt, allow_overwrite=False)
        info["gate_status"] = receipt["gate_status"]
        info["mode"] = receipt["mode"]
        info["final_gov1_convergence_emitted"] = receipt[
            "final_gov1_convergence_emitted"
        ]
        info["wheel_digest"] = receipt["wheel_digest"]
        return info, 0

    raise ValueError(f"gov1: unsupported subcommand {cmd!r}")


def cmd_gov1(args: argparse.Namespace) -> int:
    result, code = run_gov1(args)
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

    p_build_sbx = sub.add_parser("build-sealed-sandbox-profile")
    p_build_sbx.add_argument("--params", required=True)
    p_build_sbx.add_argument("--seccomp-profile", required=True)
    p_build_sbx.add_argument(
        "--mode", choices=("candidate", "envelope"), default="candidate"
    )
    p_build_sbx.add_argument("--signer-key-id", default=None)
    p_build_sbx.add_argument("--registry-locator", default=None)
    p_build_sbx.add_argument("--out", required=True)
    p_build_sbx.set_defaults(func=cmd_gov1)

    p_verify_sbx = sub.add_parser("verify-sealed-sandbox-profile")
    p_verify_sbx.add_argument("--in", dest="input", required=True)
    p_verify_sbx.add_argument("--seccomp-profile", required=True)
    p_verify_sbx.add_argument("--pubkey-raw-base64", default=None)
    p_verify_sbx.set_defaults(func=cmd_gov1)

    p_build_prov = sub.add_parser("build-wheel-provenance")
    p_build_prov.add_argument("--repo", required=True)
    p_build_prov.add_argument("--wheel-out", default=None)
    p_build_prov.add_argument("--params", required=True)
    p_build_prov.add_argument(
        "--mode", choices=("candidate", "envelope"), default="candidate"
    )
    p_build_prov.add_argument("--signer-key-id", default=None)
    p_build_prov.add_argument("--registry-locator", default=None)
    p_build_prov.add_argument("--out", required=True)
    p_build_prov.set_defaults(func=cmd_gov1)

    p_verify_prov = sub.add_parser("verify-wheel-provenance")
    p_verify_prov.add_argument("--in", dest="input", required=True)
    p_verify_prov.add_argument("--repo", required=True)
    p_verify_prov.add_argument("--wheel", required=True)
    p_verify_prov.add_argument("--pubkey-raw-base64", default=None)
    p_verify_prov.set_defaults(func=cmd_gov1)

    p_build_bound = sub.add_parser("build-wheel-boundary-report")
    p_build_bound.add_argument("--wheel", required=True)
    p_build_bound.add_argument("--provenance", default=None)
    p_build_bound.add_argument("--provenance-locator", default=None)
    p_build_bound.add_argument("--params", required=True)
    p_build_bound.add_argument(
        "--mode", choices=("candidate", "envelope"), default="candidate"
    )
    p_build_bound.add_argument("--signer-key-id", default=None)
    p_build_bound.add_argument("--registry-locator", default=None)
    p_build_bound.add_argument("--out", required=True)
    p_build_bound.set_defaults(func=cmd_gov1)

    p_verify_bound = sub.add_parser("verify-wheel-boundary-report")
    p_verify_bound.add_argument("--in", dest="input", required=True)
    p_verify_bound.add_argument("--wheel", required=True)
    p_verify_bound.add_argument("--pubkey-raw-base64", default=None)
    p_verify_bound.add_argument("--provenance", default=None)
    p_verify_bound.add_argument("--repo", default=None)
    p_verify_bound.add_argument("--provenance-pubkey-raw-base64", default=None)
    p_verify_bound.set_defaults(func=cmd_gov1)

    p_build_mcp = sub.add_parser("build-mcp-rejection-report")
    p_build_mcp.add_argument("--wheel", required=True)
    p_build_mcp.add_argument("--sandbox-profile", default=None)
    p_build_mcp.add_argument("--sandbox-profile-locator", default=None)
    p_build_mcp.add_argument("--params", required=True)
    p_build_mcp.add_argument(
        "--mode", choices=("candidate", "envelope"), default="candidate"
    )
    p_build_mcp.add_argument("--signer-key-id", default=None)
    p_build_mcp.add_argument("--registry-locator", default=None)
    p_build_mcp.add_argument("--out", required=True)
    p_build_mcp.set_defaults(func=cmd_gov1)

    p_verify_mcp = sub.add_parser("verify-mcp-rejection-report")
    p_verify_mcp.add_argument("--in", dest="input", required=True)
    p_verify_mcp.add_argument("--wheel", required=True)
    p_verify_mcp.add_argument("--pubkey-raw-base64", default=None)
    p_verify_mcp.add_argument("--sandbox-profile", default=None)
    p_verify_mcp.add_argument("--seccomp-profile", default=None)
    p_verify_mcp.add_argument("--sandbox-pubkey-raw-base64", default=None)
    p_verify_mcp.set_defaults(func=cmd_gov1)

    p_verify_conv = sub.add_parser("verify-pr1-gov1-convergence")
    p_verify_conv.add_argument("--repo", required=True)
    p_verify_conv.add_argument("--wheel", required=True)
    p_verify_conv.add_argument("--seccomp-profile", required=True)
    p_verify_conv.add_argument("--sandbox-profile", required=True)
    p_verify_conv.add_argument("--wheel-provenance", required=True)
    p_verify_conv.add_argument("--wheel-boundary-report", required=True)
    p_verify_conv.add_argument("--mcp-rejection-report", required=True)
    p_verify_conv.add_argument("--out", default=None)
    p_verify_conv.set_defaults(func=cmd_gov1)

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
