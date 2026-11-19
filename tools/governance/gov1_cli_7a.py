"""CLI subparsers and handlers for the 6 PR 3 (Etapa 10/11) 7A and convergence subcommands.

Remains 100% CPython 3.12 stdlib-only (`tools.governance.*`), with zero imports from
`smart_ads`, zero `assert` statements, and mandatory trusted Git + legacy `d26c73d`
preflights on all four 7A/convergence build and verify commands.
"""
from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping
import os
from pathlib import Path
import tempfile
from typing import Any, Final

from tools.governance import (
    gov1_7a_certification,
    gov1_7a_runner,
    gov1_convergence,
    gov1_mcp,
    gov1_sandbox,
    gov1_wheel,
)
from tools.governance.gov1_7a_certification import (
    CERTIFICATION_7A_RECORD_SCHEMA,
    SevenAConstituentVerifier,
    build_certification_7a_record_candidate,
    build_certification_7a_record_envelope,
)
from tools.governance.gov1_7a_negative import (
    NEGATIVE_SECURITY_REPORT_SCHEMA,
    PINNED_7A_NEGATIVE_SUITE_DIGEST,
    build_negative_security_test_report_candidate,
    build_negative_security_test_report_envelope,
    verify_negative_security_test_report,
)
from tools.governance.gov1_d4_helpers import (
    _read_nonempty_regular_file,
    _run_disposable_stage7_material_handoff,
    build_gov1_convergence_record_candidate,
    verify_gov1_convergence_candidate,
)
from tools.governance.jcs import canonicalize, loads_strict
from tools.governance.locator import Store, digest, exact_fields, make_locator, validate_locator

SEVEN_A_CLI_COMMANDS: Final[frozenset[str]] = frozenset(
    (
        "build-negative-security-report", "verify-negative-security-report",
        "build-certification-7a-record", "verify-certification-7a-record",
        "build-gov1-convergence-record", "verify-gov1-convergence-record",
    )
)

_NEG_REQUIRED_PARAMS: Final[frozenset[str]] = frozenset(
    "migration_run_context_locator build_run_id executed_at_utc source_commit_sha "
    "build_backend_digest schema_bundle_digest wheel_digest oci_image_digest "
    "runner_binary_digest declared_resource_limits cases".split()
)

_CERT_REQUIRED_PARAMS: Final[frozenset[str]] = frozenset(
    "migration_run_context_locator build_run_id certified_at_utc source_commit_sha "
    "build_backend_digest schema_bundle_digest wheel_digest resource_mapping_contract_digest "
    "capability parser_artifact_locators parser_code_digest adapter_artifact_locators "
    "adapter_code_digest mapping_artifact_locators mapping_rules_digest fixture_evidence".split()
)

_CONV_REQUIRED_PARAMS: Final[frozenset[str]] = frozenset(
    "migration_run_context_locator build_run_id converged_at_utc source_commit_sha "
    "wheel_digest build_backend_digest schema_bundle_digest".split()
)


def _add_legacy_source_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--legacy-repo", default=None)
    parser.add_argument("--legacy-blobs-dir", default=None)


def _add_mode_and_signing_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--mode", choices=("candidate", "envelope"), default="candidate")
    parser.add_argument("--signer-key-id", default=None)
    parser.add_argument("--registry-locator", default=None)
    parser.add_argument("--out", required=True)


def _register_negative_subparsers(
    sub: argparse._SubParsersAction[Any], cmd_handler: Callable[[argparse.Namespace], int]
) -> None:
    p_build = sub.add_parser("build-negative-security-report")
    p_build.add_argument("--params", required=True)
    p_build.add_argument("--wheel", default=None)
    p_build.add_argument("--sandbox-profile", default=None)
    p_build.add_argument("--sandbox-profile-locator", default=None)
    p_build.add_argument("--provenance", default=None)
    p_build.add_argument("--provenance-locator", default=None)
    _add_mode_and_signing_args(p_build)
    p_build.set_defaults(func=cmd_handler)

    p_verify = sub.add_parser("verify-negative-security-report")
    p_verify.add_argument("--in", dest="input", required=True)
    p_verify.add_argument("--wheel", required=True)
    p_verify.add_argument("--sandbox-profile", required=True)
    p_verify.add_argument("--seccomp-profile", required=True)
    p_verify.add_argument("--provenance", required=True)
    p_verify.add_argument("--repo", default=None)
    p_verify.add_argument("--pubkey-raw-base64", default=None)
    p_verify.add_argument("--sandbox-pubkey-raw-base64", default=None)
    p_verify.add_argument("--provenance-pubkey-raw-base64", default=None)
    p_verify.set_defaults(func=cmd_handler)


def _register_certification_7a_subparsers(
    sub: argparse._SubParsersAction[Any], cmd_handler: Callable[[argparse.Namespace], int]
) -> None:
    p_build = sub.add_parser("build-certification-7a-record")
    p_build.add_argument("--params", required=True)
    p_build.add_argument("--store-root", required=True)
    p_build.add_argument("--wheel", required=True)
    p_build.add_argument("--corpus", required=True)
    p_build.add_argument("--repo", required=True)
    _add_legacy_source_args(p_build)
    p_build.add_argument("--sandbox-profile", default=None)
    p_build.add_argument("--sandbox-profile-locator", default=None)
    p_build.add_argument("--provenance", default=None)
    p_build.add_argument("--provenance-locator", default=None)
    p_build.add_argument("--boundary-report", default=None)
    p_build.add_argument("--boundary-report-locator", default=None)
    p_build.add_argument("--negative-report", default=None)
    p_build.add_argument("--negative-report-locator", default=None)
    _add_mode_and_signing_args(p_build)
    p_build.set_defaults(func=cmd_handler)

    p_verify = sub.add_parser("verify-certification-7a-record")
    p_verify.add_argument("--in", dest="input", required=True)
    p_verify.add_argument("--store-root", required=True)
    p_verify.add_argument("--wheel", required=True)
    p_verify.add_argument("--corpus", required=True)
    p_verify.add_argument("--repo", required=True)
    _add_legacy_source_args(p_verify)
    p_verify.add_argument("--pubkey-raw-base64", default=None)
    p_verify.add_argument("--sandbox-profile", default=None)
    p_verify.add_argument("--provenance", default=None)
    p_verify.add_argument("--boundary-report", default=None)
    p_verify.add_argument("--negative-report", default=None)
    p_verify.set_defaults(func=cmd_handler)


def _register_convergence_subparsers(
    sub: argparse._SubParsersAction[Any], cmd_handler: Callable[[argparse.Namespace], int]
) -> None:
    p_build = sub.add_parser("build-gov1-convergence-record")
    p_build.add_argument("--params", required=True)
    p_build.add_argument("--store-root", required=True)
    p_build.add_argument("--wheel", required=True)
    p_build.add_argument("--corpus", required=True)
    p_build.add_argument("--repo", required=True)
    p_build.add_argument("--seccomp-profile", required=True)
    _add_legacy_source_args(p_build)
    p_build.add_argument("--sandbox-profile", default=None)
    p_build.add_argument("--sandbox-profile-locator", default=None)
    p_build.add_argument("--provenance", default=None)
    p_build.add_argument("--boundary-report", default=None)
    p_build.add_argument("--boundary-report-locator", default=None)
    p_build.add_argument("--mcp-rejection-report", default=None)
    p_build.add_argument("--mcp-rejection-report-locator", default=None)
    p_build.add_argument("--negative-report", default=None)
    p_build.add_argument("--negative-report-locator", default=None)
    p_build.add_argument("--certification-7a-record", default=None)
    p_build.add_argument("--certification-7a-record-locator", default=None)
    _add_mode_and_signing_args(p_build)
    p_build.set_defaults(func=cmd_handler)

    p_verify = sub.add_parser("verify-gov1-convergence-record")
    p_verify.add_argument("--in", dest="input", required=True)
    p_verify.add_argument("--store-root", required=True)
    p_verify.add_argument("--wheel", required=True)
    p_verify.add_argument("--corpus", required=True)
    p_verify.add_argument("--repo", required=True)
    p_verify.add_argument("--seccomp-profile", required=True)
    _add_legacy_source_args(p_verify)
    p_verify.add_argument("--pubkey-raw-base64", default=None)
    p_verify.add_argument("--sandbox-profile", default=None)
    p_verify.add_argument("--provenance", default=None)
    p_verify.add_argument("--boundary-report", default=None)
    p_verify.add_argument("--mcp-rejection-report", default=None)
    p_verify.add_argument("--negative-report", default=None)
    p_verify.add_argument("--certification-7a-record", default=None)
    p_verify.set_defaults(func=cmd_handler)


def register_7a_subparsers(
    sub: argparse._SubParsersAction[Any], cmd_handler: Callable[[argparse.Namespace], int]
) -> None:
    _register_negative_subparsers(sub, cmd_handler)
    _register_certification_7a_subparsers(sub, cmd_handler)
    _register_convergence_subparsers(sub, cmd_handler)


def _read_json(path_str: str) -> dict[str, Any]:
    path = Path(path_str)
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"gov1: expected regular non-symlink JSON file: {path_str}")
    loaded = loads_strict(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError(f"gov1: expected top-level JSON object in {path_str}")
    return loaded


def _guard_out(path_str: str, *, allow_overwrite: bool) -> Path:
    out_path = Path(path_str)
    if out_path.is_symlink():
        raise ValueError(f"gov1: symlink output path forbidden: {path_str}")
    if not allow_overwrite and out_path.exists():
        raise ValueError("gov1: output exists; choose a fresh output path")
    return out_path


def _write_json(path_str: str, obj: dict[str, Any], *, allow_overwrite: bool) -> dict[str, Any]:
    out_path = _guard_out(path_str, allow_overwrite=allow_overwrite)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    raw = canonicalize(obj)
    fd, temp = tempfile.mkstemp(prefix=".gov1-7a-", dir=out_path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temp, 0o644)
        os.replace(temp, out_path) if allow_overwrite else os.link(temp, out_path)
    finally:
        Path(temp).unlink(missing_ok=True)
    if out_path.read_bytes() != raw:
        raise ValueError(f"gov1: output write verification failed for {path_str}")
    return {"path": str(out_path), "size": len(raw), "sha256": digest(raw)}


def _exact_with_opt(value: object, req: frozenset[str], opt: set[str], label: str) -> None:
    present_opt = (set(value) & opt) if isinstance(value, dict) else set()
    exact_fields(value, set(req) | present_opt, label)


def _resolve_signing_meta(
    args: argparse.Namespace, params: Mapping[str, Any], cmd: str
) -> tuple[str, dict[str, Any]]:
    cli_kid, param_kid = getattr(args, "signer_key_id", None), params.get("signer_key_id")
    if cli_kid is not None and param_kid is not None and cli_kid != param_kid:
        raise ValueError(f"{cmd}: conflicting --signer-key-id and params.signer_key_id")
    signer_key_id = cli_kid if cli_kid is not None else param_kid
    if type(signer_key_id) is not str or not signer_key_id.strip():
        raise ValueError(f"{cmd}: --mode envelope requires --signer-key-id")
    cli_reg = _read_json(args.registry_locator) if args.registry_locator is not None else None
    param_reg = params.get("registry_locator")
    if cli_reg is not None and param_reg is not None:
        if not isinstance(param_reg, dict) or canonicalize(cli_reg) != canonicalize(param_reg):
            raise ValueError(f"{cmd}: conflicting --registry-locator and params.registry_locator")
    reg_loc = cli_reg if cli_reg is not None else param_reg
    if not isinstance(reg_loc, dict):
        raise ValueError(f"{cmd}: --mode envelope requires --registry-locator")
    return signer_key_id, reg_loc


def _forbid_flags(args: argparse.Namespace, attr_names: tuple[str, ...], *, cmd: str, reason: str) -> None:
    for name in attr_names:
        if getattr(args, name, None) is not None:
            raise ValueError(f"{cmd}: --{name.replace('_', '-')} {reason}")


def _resolve_candidate_ref(
    cli_path: str | None,
    param_ref: object,
    *,
    cmd: str,
    flag_name: str,
    expected_schema: str,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    cand_obj = _read_json(cli_path) if cli_path is not None else None
    cli_ref = gov1_sandbox.build_local_candidate_ref(cand_obj) if cand_obj is not None else None
    if cli_ref is not None and param_ref is not None:
        if not isinstance(param_ref, dict) or canonicalize(cli_ref) != canonicalize(param_ref):
            raise ValueError(f"{cmd}: conflicting {flag_name} and params candidate_ref")
    chosen = cli_ref if cli_ref is not None else param_ref
    if not isinstance(chosen, dict):
        raise ValueError(f"{cmd}: candidate mode requires {flag_name}")
    gov1_sandbox.verify_local_candidate_ref(chosen, expected_schema=expected_schema)
    return chosen, cand_obj


def _resolve_locator_arg(
    cli_loc_path: str | None,
    param_loc: object,
    *,
    cmd: str,
    flag_name: str,
    expected_schema: str,
) -> dict[str, Any]:
    cli_loc = _read_json(cli_loc_path) if cli_loc_path is not None else None
    if cli_loc is not None and param_loc is not None:
        if not isinstance(param_loc, dict) or canonicalize(cli_loc) != canonicalize(param_loc):
            raise ValueError(f"{cmd}: conflicting {flag_name} and params locator")
    chosen = cli_loc if cli_loc is not None else param_loc
    if not isinstance(chosen, dict):
        raise ValueError(f"{cmd}: --mode envelope requires {flag_name}")
    validate_locator(chosen, expected_schema)
    return chosen


def _resolve_trusted_7a_preflights(
    args: argparse.Namespace, *, source_commit_sha: str, cmd: str
) -> tuple[Mapping[str, bytes], Mapping[str, bytes]]:
    if (args.legacy_repo is None) == (args.legacy_blobs_dir is None):
        raise ValueError(f"{cmd}: specify exactly one of --legacy-repo or --legacy-blobs-dir")
    git_blobs = gov1_7a_certification.resolve_7a_smart_ads_git_blobs(Path(args.repo), source_commit_sha)
    d26_blobs = gov1_7a_runner.resolve_pinned_pipeboard_d26_blobs(
        legacy_repo=Path(args.legacy_repo) if args.legacy_repo is not None else None,
        legacy_blobs_dir=Path(args.legacy_blobs_dir) if args.legacy_blobs_dir is not None else None,
    )
    return git_blobs, d26_blobs


def _build_negative_report(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    cmd, mode = args.command, args.mode
    _guard_out(args.out, allow_overwrite=(mode == "envelope"))
    params = _read_json(args.params)
    whl_bytes = _read_nonempty_regular_file(Path(args.wheel), "wheel")[1] if args.wheel is not None else None
    if whl_bytes is not None and params.get("wheel_digest") != digest(whl_bytes):
        raise ValueError(f"{cmd}: params.wheel_digest mismatch against --wheel")
    suite = params.get("test_suite_digest", PINNED_7A_NEGATIVE_SUITE_DIGEST)
    common_kw = {k: params[k] for k in _NEG_REQUIRED_PARAMS if k in params}
    if mode == "candidate":
        _forbid_flags(
            args,
            ("signer_key_id", "registry_locator", "sandbox_profile_locator", "provenance_locator"),
            cmd=cmd, reason="requires --mode envelope",
        )
        _exact_with_opt(
            params, _NEG_REQUIRED_PARAMS,
            {"test_suite_digest", "sealed_sandbox_profile_candidate_ref", "wheel_build_provenance_candidate_ref"},
            f"{cmd} params",
        )
        sbx_ref, sbx_c = _resolve_candidate_ref(args.sandbox_profile, params.get("sealed_sandbox_profile_candidate_ref"), cmd=cmd, flag_name="--sandbox-profile", expected_schema=gov1_sandbox.SANDBOX_PROFILE_SCHEMA)
        prov_ref, prov_c = _resolve_candidate_ref(args.provenance, params.get("wheel_build_provenance_candidate_ref"), cmd=cmd, flag_name="--provenance", expected_schema=gov1_wheel.WHEEL_BUILD_PROVENANCE_SCHEMA)
        art = build_negative_security_test_report_candidate(**common_kw, test_suite_digest=suite, sealed_sandbox_profile_candidate_ref=sbx_ref, wheel_build_provenance_candidate_ref=prov_ref)
        if whl_bytes is not None and sbx_c is not None and prov_c is not None:
            verify_negative_security_test_report(art, sandbox_profile=sbx_c, wheel_provenance=prov_c, wheel_bytes=whl_bytes)
        return _write_json(args.out, art, allow_overwrite=False), 0
    _forbid_flags(args, ("sandbox_profile", "provenance"), cmd=cmd, reason="is for candidate mode")
    _exact_with_opt(
        params, _NEG_REQUIRED_PARAMS,
        {"test_suite_digest", "sealed_sandbox_profile_locator", "wheel_build_provenance_locator", "signer_key_id", "registry_locator"},
        f"{cmd} params",
    )
    kid, reg_loc = _resolve_signing_meta(args, params, cmd)
    sbx_loc = _resolve_locator_arg(args.sandbox_profile_locator, params.get("sealed_sandbox_profile_locator"), cmd=cmd, flag_name="--sandbox-profile-locator", expected_schema=gov1_sandbox.SANDBOX_PROFILE_SCHEMA)
    prov_loc = _resolve_locator_arg(args.provenance_locator, params.get("wheel_build_provenance_locator"), cmd=cmd, flag_name="--provenance-locator", expected_schema=gov1_wheel.WHEEL_BUILD_PROVENANCE_SCHEMA)
    art = build_negative_security_test_report_envelope(**common_kw, test_suite_digest=suite, sealed_sandbox_profile_locator=sbx_loc, wheel_build_provenance_locator=prov_loc, signer_key_id=kid, registry_locator=reg_loc)
    return _write_json(args.out, art, allow_overwrite=True), 0


def _verify_negative_report(
    args: argparse.Namespace, verify_sig_fn: Callable[..., None]
) -> tuple[dict[str, Any], int]:
    cmd = args.command
    artifact = _read_json(args.input)
    sbx_obj, seccomp, prov_obj = _read_json(args.sandbox_profile), _read_json(args.seccomp_profile), _read_json(args.provenance)
    _, whl_bytes = _read_nonempty_regular_file(Path(args.wheel), "wheel")
    if artifact.get("artifact_kind") == gov1_sandbox.LOCAL_CANDIDATE_KIND:
        _forbid_flags(
            args, ("pubkey_raw_base64", "sandbox_pubkey_raw_base64", "provenance_pubkey_raw_base64"),
            cmd=cmd, reason="requires envelope input",
        )
        sbx_v = gov1_sandbox.verify_sealed_sandbox_profile(sbx_obj, seccomp_profile=seccomp)
        if sbx_v["mode"] != "candidate":
            raise ValueError(f"{cmd}: candidate report requires candidate --sandbox-profile")
        if args.repo is not None:
            gov1_wheel.verify_wheel_build_provenance(prov_obj, repo_root=Path(args.repo), wheel_path=Path(args.wheel))
        res = verify_negative_security_test_report(artifact, sandbox_profile=sbx_obj, wheel_provenance=prov_obj, wheel_bytes=whl_bytes)
        return {"status": "PASS", "mode": "candidate", "signable": False, "authority": "none", "schema": res["schema"], "wheel_digest": res["wheel_digest"], "executed_at_utc": res["executed_at_utc"]}, 0
    verify_sig_fn(artifact, schema=NEGATIVE_SECURITY_REPORT_SCHEMA, pubkey_b64=args.pubkey_raw_base64, cmd=cmd)
    if args.sandbox_pubkey_raw_base64 is not None:
        verify_sig_fn(sbx_obj, schema=gov1_sandbox.SANDBOX_PROFILE_SCHEMA, pubkey_b64=args.sandbox_pubkey_raw_base64, cmd=cmd, flag_name="--sandbox-pubkey-raw-base64")
    if args.provenance_pubkey_raw_base64 is not None:
        verify_sig_fn(prov_obj, schema=gov1_wheel.WHEEL_BUILD_PROVENANCE_SCHEMA, pubkey_b64=args.provenance_pubkey_raw_base64, cmd=cmd, flag_name="--provenance-pubkey-raw-base64")
    sbx_v = gov1_sandbox.verify_sealed_sandbox_profile(sbx_obj, seccomp_profile=seccomp)
    if sbx_v["mode"] != "envelope" or prov_obj.get("$schema") != gov1_wheel.WHEEL_BUILD_PROVENANCE_SCHEMA:
        raise ValueError(f"{cmd}: envelope report requires P1 envelope --sandbox-profile and --provenance")
    if args.repo is not None:
        gov1_wheel.verify_wheel_build_provenance(prov_obj, repo_root=Path(args.repo), wheel_path=Path(args.wheel))
    res = verify_negative_security_test_report(artifact, sandbox_profile=sbx_obj, wheel_provenance=prov_obj, wheel_bytes=whl_bytes)
    return {"status": "PASS", "mode": "envelope", "signature_verified": True, "d4_authority_verified": False, "authority": "none", "schema": res["schema"], "wheel_digest": res["wheel_digest"], "executed_at_utc": res["executed_at_utc"]}, 0


def _build_cert7a_candidate_mode(
    args: argparse.Namespace, params: dict[str, Any], store: Store,
    whl_bytes: bytes, corpus_bytes: bytes, git_blobs: Mapping[str, bytes], d26_blobs: Mapping[str, bytes],
) -> tuple[dict[str, Any], int]:
    cmd = args.command
    _forbid_flags(
        args,
        ("signer_key_id", "registry_locator", "sandbox_profile_locator", "provenance_locator", "boundary_report_locator", "negative_report_locator"),
        cmd=cmd, reason="requires --mode envelope",
    )
    _exact_with_opt(
        params, _CERT_REQUIRED_PARAMS,
        {"certified_state", "sealed_sandbox_profile_candidate_ref", "wheel_build_provenance_candidate_ref", "wheel_boundary_report_candidate_ref", "negative_security_test_report_candidate_ref"},
        f"{cmd} params",
    )
    sbx_ref, sbx_c = _resolve_candidate_ref(args.sandbox_profile, params.get("sealed_sandbox_profile_candidate_ref"), cmd=cmd, flag_name="--sandbox-profile", expected_schema=gov1_sandbox.SANDBOX_PROFILE_SCHEMA)
    prov_ref, prov_c = _resolve_candidate_ref(args.provenance, params.get("wheel_build_provenance_candidate_ref"), cmd=cmd, flag_name="--provenance", expected_schema=gov1_wheel.WHEEL_BUILD_PROVENANCE_SCHEMA)
    bound_ref, bound_c = _resolve_candidate_ref(args.boundary_report, params.get("wheel_boundary_report_candidate_ref"), cmd=cmd, flag_name="--boundary-report", expected_schema=gov1_wheel.WHEEL_BOUNDARY_REPORT_SCHEMA)
    neg_ref, neg_c = _resolve_candidate_ref(args.negative_report, params.get("negative_security_test_report_candidate_ref"), cmd=cmd, flag_name="--negative-report", expected_schema=NEGATIVE_SECURITY_REPORT_SCHEMA)
    if sbx_c is None or prov_c is None or bound_c is None or neg_c is None:
        raise ValueError(f"{cmd}: candidate mode requires --sandbox-profile, --provenance, --boundary-report, and --negative-report")
    art = build_certification_7a_record_candidate(
        **{k: params[k] for k in _CERT_REQUIRED_PARAMS},
        certified_state=params.get("certified_state", "fixture_certified"),
        sealed_sandbox_profile_candidate_ref=sbx_ref, wheel_build_provenance_candidate_ref=prov_ref,
        wheel_boundary_report_candidate_ref=bound_ref, negative_security_test_report_candidate_ref=neg_ref,
    )
    gov1_7a_certification.verify_certification_7a_replay_bytes(
        art, store=store, wheel_bytes=whl_bytes, corpus_bytes=corpus_bytes,
        resolved_git_blobs=git_blobs, resolved_d26_blobs=d26_blobs,
        sandbox_profile=sbx_c, wheel_provenance=prov_c, wheel_boundary_report=bound_c, negative_security_report=neg_c,
    )
    return _write_json(args.out, art, allow_overwrite=False), 0


def _build_certification_7a_record(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    cmd = args.command
    _guard_out(args.out, allow_overwrite=(args.mode == "envelope"))
    params = _read_json(args.params)
    store = Store(Path(args.store_root))
    _, whl_bytes = _read_nonempty_regular_file(Path(args.wheel), "wheel")
    _, corpus_bytes = _read_nonempty_regular_file(Path(args.corpus), "corpus")
    src_sha = params.get("source_commit_sha")
    if type(src_sha) is not str:
        raise ValueError(f"{cmd}: params.source_commit_sha must be string")
    git_blobs, d26_blobs = _resolve_trusted_7a_preflights(args, source_commit_sha=src_sha, cmd=cmd)
    if args.mode == "candidate":
        return _build_cert7a_candidate_mode(args, params, store, whl_bytes, corpus_bytes, git_blobs, d26_blobs)
    _forbid_flags(args, ("sandbox_profile", "provenance", "boundary_report", "negative_report"), cmd=cmd, reason="is for candidate mode")
    _exact_with_opt(
        params, _CERT_REQUIRED_PARAMS,
        {"certified_state", "sealed_sandbox_profile_locator", "wheel_build_provenance_locator", "wheel_boundary_report_locator", "negative_security_test_report_locator", "signer_key_id", "registry_locator"},
        f"{cmd} params",
    )
    kid, reg_loc = _resolve_signing_meta(args, params, cmd)
    sbx_loc = _resolve_locator_arg(args.sandbox_profile_locator, params.get("sealed_sandbox_profile_locator"), cmd=cmd, flag_name="--sandbox-profile-locator", expected_schema=gov1_sandbox.SANDBOX_PROFILE_SCHEMA)
    prov_loc = _resolve_locator_arg(args.provenance_locator, params.get("wheel_build_provenance_locator"), cmd=cmd, flag_name="--provenance-locator", expected_schema=gov1_wheel.WHEEL_BUILD_PROVENANCE_SCHEMA)
    bound_loc = _resolve_locator_arg(args.boundary_report_locator, params.get("wheel_boundary_report_locator"), cmd=cmd, flag_name="--boundary-report-locator", expected_schema=gov1_wheel.WHEEL_BOUNDARY_REPORT_SCHEMA)
    neg_loc = _resolve_locator_arg(args.negative_report_locator, params.get("negative_security_test_report_locator"), cmd=cmd, flag_name="--negative-report-locator", expected_schema=NEGATIVE_SECURITY_REPORT_SCHEMA)
    art = build_certification_7a_record_envelope(
        **{k: params[k] for k in _CERT_REQUIRED_PARAMS},
        certified_state=params.get("certified_state", "fixture_certified"),
        sealed_sandbox_profile_locator=sbx_loc, wheel_build_provenance_locator=prov_loc,
        wheel_boundary_report_locator=bound_loc, negative_security_test_report_locator=neg_loc,
        signer_key_id=kid, registry_locator=reg_loc,
    )
    gov1_7a_certification.verify_certification_7a_replay_bytes(
        art, store=store, wheel_bytes=whl_bytes, corpus_bytes=corpus_bytes,
        resolved_git_blobs=git_blobs, resolved_d26_blobs=d26_blobs,
    )
    return _write_json(args.out, art, allow_overwrite=True), 0


def _verify_certification_7a_record(
    args: argparse.Namespace, verify_sig_fn: Callable[..., None]
) -> tuple[dict[str, Any], int]:
    cmd = args.command
    artifact = _read_json(args.input)
    store = Store(Path(args.store_root))
    _, whl_bytes = _read_nonempty_regular_file(Path(args.wheel), "wheel")
    _, corpus_bytes = _read_nonempty_regular_file(Path(args.corpus), "corpus")
    is_cand = artifact.get("artifact_kind") == gov1_sandbox.LOCAL_CANDIDATE_KIND
    if is_cand:
        _forbid_flags(args, ("pubkey_raw_base64",), cmd=cmd, reason="requires envelope input")
        src_sha = artifact.get("payload", {}).get("source_commit_sha") if isinstance(artifact.get("payload"), dict) else None
    else:
        verify_sig_fn(artifact, schema=CERTIFICATION_7A_RECORD_SCHEMA, pubkey_b64=args.pubkey_raw_base64, cmd=cmd)
        src_sha = artifact.get("source_commit_sha")
    if type(src_sha) is not str:
        raise ValueError(f"{cmd}: missing source_commit_sha")
    git_blobs, d26_blobs = _resolve_trusted_7a_preflights(args, source_commit_sha=src_sha, cmd=cmd)
    sbx_o = _read_json(args.sandbox_profile) if args.sandbox_profile is not None else None
    prov_o = _read_json(args.provenance) if args.provenance is not None else None
    bound_o = _read_json(args.boundary_report) if args.boundary_report is not None else None
    neg_o = _read_json(args.negative_report) if args.negative_report is not None else None
    res = gov1_7a_certification.verify_certification_7a_replay_bytes(
        artifact, store=store, wheel_bytes=whl_bytes, corpus_bytes=corpus_bytes,
        resolved_git_blobs=git_blobs, resolved_d26_blobs=d26_blobs,
        sandbox_profile=sbx_o, wheel_provenance=prov_o, wheel_boundary_report=bound_o, negative_security_report=neg_o,
    )
    if res["mode"] == "candidate":
        return {"status": "PASS", "mode": "candidate", "signable": False, "authority": "none", "schema": res["schema"], "wheel_digest": res["wheel_digest"], "certified_at_utc": res["certified_at_utc"]}, 0
    return {"status": "PASS", "mode": "envelope", "signature_verified": True, "d4_authority_verified": False, "authority": "none", "schema": res["schema"], "wheel_digest": res["wheel_digest"], "certified_at_utc": res["certified_at_utc"]}, 0


def _build_conv_candidate_mode(
    args: argparse.Namespace, params: dict[str, Any], store: Store, seccomp: dict[str, Any]
) -> tuple[dict[str, Any], int]:
    cmd = args.command
    _forbid_flags(
        args,
        ("signer_key_id", "registry_locator", "sandbox_profile_locator", "boundary_report_locator", "mcp_rejection_report_locator", "negative_report_locator", "certification_7a_record_locator"),
        cmd=cmd, reason="requires --mode envelope",
    )
    _exact_with_opt(params, _CONV_REQUIRED_PARAMS, {"convergence_status"}, f"{cmd} params")
    for req_flag in ("sandbox_profile", "provenance", "boundary_report", "mcp_rejection_report", "negative_report", "certification_7a_record"):
        if getattr(args, req_flag, None) is None:
            raise ValueError(f"{cmd}: candidate mode requires --{req_flag.replace('_', '-')}")
    sbx_c, prov_c = _read_json(args.sandbox_profile), _read_json(args.provenance)
    bound_c, mcp_c = _read_json(args.boundary_report), _read_json(args.mcp_rejection_report)
    neg_c, cert_c = _read_json(args.negative_report), _read_json(args.certification_7a_record)
    art = build_gov1_convergence_record_candidate(
        **{k: params[k] for k in _CONV_REQUIRED_PARAMS},
        convergence_status=params.get("convergence_status", "PASS"),
        sealed_sandbox_profile_candidate_ref=gov1_sandbox.build_local_candidate_ref(sbx_c),
        wheel_boundary_report_candidate_ref=gov1_sandbox.build_local_candidate_ref(bound_c),
        mcp_rejection_matrix_report_candidate_ref=gov1_sandbox.build_local_candidate_ref(mcp_c),
        negative_security_test_report_candidate_ref=gov1_sandbox.build_local_candidate_ref(neg_c),
        certification_7a_record_candidate_ref=gov1_sandbox.build_local_candidate_ref(cert_c),
    )
    verify_gov1_convergence_candidate(
        repo_root=Path(args.repo), wheel_path=Path(args.wheel), corpus_path=Path(args.corpus),
        seccomp_profile=seccomp, sandbox_profile=sbx_c, wheel_provenance=prov_c,
        wheel_boundary_report=bound_c, mcp_rejection_report=mcp_c, negative_security_report=neg_c,
        certification_7a_record=cert_c, convergence_candidate=art, store=store,
        legacy_repo=Path(args.legacy_repo) if args.legacy_repo is not None else None,
        legacy_blobs_dir=Path(args.legacy_blobs_dir) if args.legacy_blobs_dir is not None else None,
    )
    return _write_json(args.out, art, allow_overwrite=False), 0


def _resolve_conv_envelope_locators(
    args: argparse.Namespace, params: Mapping[str, Any], cmd: str
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    return (
        _resolve_locator_arg(args.sandbox_profile_locator, params.get("sealed_sandbox_profile_locator"), cmd=cmd, flag_name="--sandbox-profile-locator", expected_schema=gov1_sandbox.SANDBOX_PROFILE_SCHEMA),
        _resolve_locator_arg(args.boundary_report_locator, params.get("wheel_boundary_report_locator"), cmd=cmd, flag_name="--boundary-report-locator", expected_schema=gov1_wheel.WHEEL_BOUNDARY_REPORT_SCHEMA),
        _resolve_locator_arg(args.mcp_rejection_report_locator, params.get("mcp_rejection_matrix_report_locator"), cmd=cmd, flag_name="--mcp-rejection-report-locator", expected_schema=gov1_mcp.MCP_REJECTION_REPORT_SCHEMA),
        _resolve_locator_arg(args.negative_report_locator, params.get("negative_security_test_report_locator"), cmd=cmd, flag_name="--negative-report-locator", expected_schema=NEGATIVE_SECURITY_REPORT_SCHEMA),
        _resolve_locator_arg(args.certification_7a_record_locator, params.get("certification_7a_record_locator"), cmd=cmd, flag_name="--certification-7a-record-locator", expected_schema=CERTIFICATION_7A_RECORD_SCHEMA),
    )


def _build_gov1_convergence_record(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    cmd = args.command
    _guard_out(args.out, allow_overwrite=(args.mode == "envelope"))
    params, seccomp = _read_json(args.params), _read_json(args.seccomp_profile)
    store = Store(Path(args.store_root))
    if args.mode == "candidate":
        return _build_conv_candidate_mode(args, params, store, seccomp)
    _forbid_flags(args, ("sandbox_profile", "provenance", "boundary_report", "mcp_rejection_report", "negative_report", "certification_7a_record"), cmd=cmd, reason="is for candidate mode")
    _exact_with_opt(params, _CONV_REQUIRED_PARAMS, {"convergence_status", "sealed_sandbox_profile_locator", "wheel_boundary_report_locator", "mcp_rejection_matrix_report_locator", "negative_security_test_report_locator", "certification_7a_record_locator", "signer_key_id", "registry_locator"}, f"{cmd} params")
    kid, reg_loc = _resolve_signing_meta(args, params, cmd)
    sbx_loc, bound_loc, mcp_loc, neg_loc, cert_loc = _resolve_conv_envelope_locators(args, params, cmd)
    _, whl_bytes = _read_nonempty_regular_file(Path(args.wheel), "wheel")
    _, corpus_bytes = _read_nonempty_regular_file(Path(args.corpus), "corpus")
    git_blobs, d26_blobs = _resolve_trusted_7a_preflights(args, source_commit_sha=params["source_commit_sha"], cmd=cmd)
    if corpus_bytes != git_blobs.get(gov1_7a_certification.CORPUS_GIT_PATH[1]):
        raise ValueError(f"{cmd}: corpus bytes disagree with Git blob at source_commit_sha")
    bound_env = store.get(bound_loc, expected_type=gov1_wheel.WHEEL_BOUNDARY_REPORT_SCHEMA)
    prov_env = store.get(bound_env["wheel_build_provenance_locator"], expected_type=gov1_wheel.WHEEL_BUILD_PROVENANCE_SCHEMA)
    _, _, prov_res, _, _ = _run_disposable_stage7_material_handoff(
        wheel_bytes=whl_bytes, seccomp_profile=seccomp,
        sandbox_obj=store.get(sbx_loc, expected_type=gov1_sandbox.SANDBOX_PROFILE_SCHEMA),
        prov_obj=prov_env, bound_obj=bound_env,
        mcp_obj=store.get(mcp_loc, expected_type=gov1_mcp.MCP_REJECTION_REPORT_SCHEMA),
        repo_dir=Path(args.repo), backend_wheel_dir=None, site_packages_dir=None, probe_runner=None,
    )
    pr3_v = SevenAConstituentVerifier(
        wheel_bytes=whl_bytes, corpus_bytes=corpus_bytes, stripped_provenance_payload=prov_res["payload"],
        resolved_git_blobs=git_blobs, resolved_d26_blobs=d26_blobs,
    )
    art = gov1_convergence.build_gov1_convergence_record_envelope(
        **{k: params[k] for k in _CONV_REQUIRED_PARAMS}, convergence_status=params.get("convergence_status", "PASS"),
        sealed_sandbox_profile_locator=sbx_loc, wheel_boundary_report_locator=bound_loc,
        mcp_rejection_matrix_report_locator=mcp_loc, negative_security_test_report_locator=neg_loc,
        certification_7a_record_locator=cert_loc, registry_locator=reg_loc, signer_key_id=kid,
        store=store, pr3_verifier=pr3_v,
    )
    return _write_json(args.out, art, allow_overwrite=True), 0


def _check_optional_conv_envelope_overrides(
    args: argparse.Namespace, artifact: Mapping[str, Any], store: Store, cmd: str
) -> None:
    bound_env = store.get(artifact["wheel_boundary_report_locator"], expected_type=gov1_wheel.WHEEL_BOUNDARY_REPORT_SCHEMA)
    checks = (
        (args.sandbox_profile, artifact["sealed_sandbox_profile_locator"], gov1_sandbox.SANDBOX_PROFILE_SCHEMA, "--sandbox-profile"),
        (args.provenance, bound_env["wheel_build_provenance_locator"], gov1_wheel.WHEEL_BUILD_PROVENANCE_SCHEMA, "--provenance"),
        (args.boundary_report, artifact["wheel_boundary_report_locator"], gov1_wheel.WHEEL_BOUNDARY_REPORT_SCHEMA, "--boundary-report"),
        (args.mcp_rejection_report, artifact["mcp_rejection_matrix_report_locator"], gov1_mcp.MCP_REJECTION_REPORT_SCHEMA, "--mcp-rejection-report"),
        (args.negative_report, artifact["negative_security_test_report_locator"], NEGATIVE_SECURITY_REPORT_SCHEMA, "--negative-report"),
        (args.certification_7a_record, artifact["certification_7a_record_locator"], CERTIFICATION_7A_RECORD_SCHEMA, "--certification-7a-record"),
    )
    for opt_path, exp_loc, schema, flag in checks:
        if opt_path is not None:
            obj = _read_json(opt_path)
            if canonicalize(make_locator(schema, canonicalize(obj))) != canonicalize(exp_loc):
                raise ValueError(f"{cmd}: {flag} diverges from Store locator")


def _verify_gov1_convergence_record(
    args: argparse.Namespace, verify_sig_fn: Callable[..., None]
) -> tuple[dict[str, Any], int]:
    cmd = args.command
    artifact, seccomp = _read_json(args.input), _read_json(args.seccomp_profile)
    store = Store(Path(args.store_root))
    leg_repo = Path(args.legacy_repo) if args.legacy_repo is not None else None
    leg_blobs = Path(args.legacy_blobs_dir) if args.legacy_blobs_dir is not None else None
    if artifact.get("artifact_kind") == gov1_sandbox.LOCAL_CANDIDATE_KIND:
        _forbid_flags(args, ("pubkey_raw_base64",), cmd=cmd, reason="requires envelope input")
        for req_flag in ("sandbox_profile", "provenance", "boundary_report", "mcp_rejection_report", "negative_report", "certification_7a_record"):
            if getattr(args, req_flag, None) is None:
                raise ValueError(f"{cmd}: candidate verification requires --{req_flag.replace('_', '-')}")
        res = verify_gov1_convergence_candidate(
            repo_root=Path(args.repo), wheel_path=Path(args.wheel), corpus_path=Path(args.corpus),
            seccomp_profile=seccomp, sandbox_profile=_read_json(args.sandbox_profile),
            wheel_provenance=_read_json(args.provenance), wheel_boundary_report=_read_json(args.boundary_report),
            mcp_rejection_report=_read_json(args.mcp_rejection_report), negative_security_report=_read_json(args.negative_report),
            certification_7a_record=_read_json(args.certification_7a_record), convergence_candidate=artifact,
            store=store, legacy_repo=leg_repo, legacy_blobs_dir=leg_blobs,
        )
        return {"status": "PASS", "mode": "candidate", "signable": False, "authority": "none", "schema": res["schema"], "wheel_digest": res["wheel_digest"], "converged_at_utc": res["converged_at_utc"]}, 0
    verify_sig_fn(artifact, schema=gov1_convergence.GOV1_CONVERGENCE_SCHEMA, pubkey_b64=args.pubkey_raw_base64, cmd=cmd)
    _check_optional_conv_envelope_overrides(args, artifact, store, cmd)
    res = gov1_convergence._verify_convergence_envelope_core(
        artifact, store=store, seccomp_profile=seccomp, wheel_path=Path(args.wheel),
        corpus_path=Path(args.corpus), repo_root=Path(args.repo),
        legacy_repo=leg_repo, legacy_blobs_dir=leg_blobs,
        backend_wheel_dir=None, site_packages_dir=None, pr3_verifier=None, probe_runner=None, cli_auto_pr3=True,
    )
    return {"status": "PASS", "mode": "envelope", "signature_verified": True, "d4_authority_verified": False, "authority": res["authority"], "schema": res["schema"], "wheel_digest": res["wheel_digest"], "converged_at_utc": res["payload"]["converged_at_utc"]}, 0


def dispatch_7a_cli_command(
    args: argparse.Namespace, *, verify_sig_fn: Callable[..., None]
) -> tuple[dict[str, Any], int]:
    cmd = args.command
    if cmd == "build-negative-security-report":
        return _build_negative_report(args)
    if cmd == "verify-negative-security-report":
        return _verify_negative_report(args, verify_sig_fn)
    if cmd == "build-certification-7a-record":
        return _build_certification_7a_record(args)
    if cmd == "verify-certification-7a-record":
        return _verify_certification_7a_record(args, verify_sig_fn)
    if cmd == "build-gov1-convergence-record":
        return _build_gov1_convergence_record(args)
    if cmd == "verify-gov1-convergence-record":
        return _verify_gov1_convergence_record(args, verify_sig_fn)
    raise ValueError(f"gov1: unsupported 7A subcommand {cmd!r}")


__all__ = [
    "SEVEN_A_CLI_COMMANDS",
    "dispatch_7a_cli_command",
    "register_7a_subparsers",
]
