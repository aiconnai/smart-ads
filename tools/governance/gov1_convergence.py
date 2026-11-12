"""Etapa 8 pre-PR2 material convergence gate, D4 Etapa 7 verifier, and Etapa 11 fail-closed block.

Implements ADR-0001 sections 3.2, 10, and 12.7:
- `verify_pr1_gov1_convergence`: mandatory pre-PR2 material recomputation and cross-binding
  convergence gate over `sealed_sandbox_profile/v1`, `wheel_build_provenance/v1`,
  `wheel_boundary_report/v1`, and `mcp_rejection_matrix_report/v1` (in either quarantined
  `gov1_local_candidate` mode or D4-verified P1 envelope mode);
- `Gov1AdmissionVerifier`: D4 `ProtectedRuntime` cryptographic + material verifier for the
  four Etapa 7 profiles preserving full anti-TOCTOU discipline before `compare_and_swap`
  and `observe_head_and_clock`;
- `build_gov1_convergence_record_envelope` / `verify_gov1_convergence_record`: structural
  and anti-backdating contract for `smart_ads/gov1_convergence_record/v1` (Etapa 11),
  failing closed in Etapa 8 while `Pr3SevenAConstituentVerifier` (PR 3 / Etapa 10) is absent.
"""
from __future__ import annotations

from collections.abc import Mapping
import copy
import os
from pathlib import Path
import re
from types import MappingProxyType
from typing import Any, Final, Protocol, runtime_checkable

from tools.governance import p1
from tools.governance.decomposition_governance import historical_prerequisites
from tools.governance.decomposition_runtime import (
    CHECKPOINT,
    HEAD,
    INVENTORY,
    STATE,
    AdmissionVerifier,
    ClockInterval,
    Floor,
    InstallationPins,
    ProtectedRuntime,
    fresh,
    historical,
    load_object,
    require,
    validity,
)
from tools.governance.gov1_mcp import (
    MCP_REJECTION_REPORT_SCHEMA,
    verify_mcp_rejection_matrix_report,
)
from tools.governance.gov1_sandbox import (
    LOCAL_CANDIDATE_KIND,
    SANDBOX_PROFILE_SCHEMA,
    build_local_candidate_ref,
    unwrap_local_candidate,
    verify_local_candidate_ref,
    verify_sandbox_profile_spec,
    verify_seccomp_profile,
    verify_sealed_sandbox_profile,
)
from tools.governance.gov1_wheel import (
    DEFAULT_REPOSITORY,
    EXPECTED_BUILD_BACKEND,
    EXPECTED_BUILD_BACKEND_VERSION,
    EXPECTED_PYTHON_ABI_TAG,
    MAX_JCS_SAFE_INT,
    WHEEL_BOUNDARY_REPORT_SCHEMA,
    WHEEL_BUILD_PROVENANCE_SCHEMA,
    verify_wheel_boundary_report,
    verify_wheel_build_provenance,
    verify_wheel_object_locator,
)
from tools.governance.jcs import canonicalize, loads_strict
from tools.governance.locator import (
    Store,
    digest,
    exact_fields,
    make_locator,
    timestamp,
    validate_locator,
)

GOV1_CONVERGENCE_SCHEMA: Final[str] = "smart_ads/gov1_convergence_record/v1"
NEGATIVE_SECURITY_SCHEMA: Final[str] = "smart_ads/negative_security_test_report/v1"
CERTIFICATION_7A_SCHEMA: Final[str] = "smart_ads/certification_7a_record/v1"
PRE_PR2_CONVERGENCE_GATE_KIND: Final[str] = "pr1_gov1_pre_pr2_convergence_gate"

_RUN_CONTEXT_SCHEMA: Final[str] = "smart_ads/migration_run_context/v1"
_KEY_REGISTRY_SCHEMA: Final[str] = "smart_ads/key_authorization_registry/v1"

MANDATORY_7A_NEGATIVE_SECURITY_CASES: Final[tuple[str, ...]] = (
    "cpu_limit_enforced",
    "credential_paths_denied",
    "env_is_exact_allowlist",
    "file_size_limit_enforced",
    "host_dev_denied",
    "host_home_denied",
    "host_proc_denied",
    "host_sys_denied",
    "inherited_fd_denied",
    "memory_limit_enforced",
    "output_limit_enforced",
    "pids_limit_enforced",
    "process_creation_denied",
    "socket_denied",
    "tmpfs_limit_enforced",
    "wall_clock_limit_enforced",
    "write_outside_tmp_denied",
)

_PENDING_PR3_CONSTITUENTS: Final[tuple[str, str]] = (
    CERTIFICATION_7A_SCHEMA,
    NEGATIVE_SECURITY_SCHEMA,
)

# ADR-0001 §12.7 exact D4 registry role and allowed_actions mapping for GOV 1 schemas.
_GOV1_ROLE_ACTION_SPECS: Final[Mapping[str, tuple[str, str]]] = MappingProxyType(
    {
        SANDBOX_PROFILE_SCHEMA: ("security_owner", "sealed_sandbox_profile_issue"),
        WHEEL_BUILD_PROVENANCE_SCHEMA: (
            "build_provenance_verifier",
            "wheel_build_provenance_issue",
        ),
        WHEEL_BOUNDARY_REPORT_SCHEMA: (
            "build_boundary_verifier",
            "wheel_boundary_report_issue",
        ),
        MCP_REJECTION_REPORT_SCHEMA: (
            "security_verifier",
            "mcp_rejection_matrix_report_issue",
        ),
        GOV1_CONVERGENCE_SCHEMA: (
            "gov1_convergence_verifier",
            "gov1_convergence_record_issue",
        ),
    }
)

_GOV1_CONVERGENCE_PAYLOAD_FIELDS: Final[set[str]] = {
    "migration_run_context_locator",
    "wheel_boundary_report_locator",
    "sealed_sandbox_profile_locator",
    "negative_security_test_report_locator",
    "mcp_rejection_matrix_report_locator",
    "certification_7a_record_locator",
    "build_run_id",
    "converged_at_utc",
    "source_commit_sha",
    "wheel_digest",
    "build_backend_digest",
    "schema_bundle_digest",
    "convergence_status",
}
_GOV1_CONVERGENCE_ENVELOPE_FIELDS: Final[set[str]] = (
    {"$schema", "integrity"} | _GOV1_CONVERGENCE_PAYLOAD_FIELDS
)

_SANDBOX_SPEC_17_FIELDS: Final[set[str]] = {
    "profile_id",
    "runtime_kind",
    "platform",
    "rootfs_read_only",
    "oci_image_digest",
    "runner_binary_digest",
    "exact_environment",
    "namespaces",
    "read_only_mounts",
    "fresh_tmpfs_mounts",
    "masked_empty_mounts",
    "host_bind_mounts_forbidden",
    "all_capabilities_dropped",
    "no_new_privs",
    "inherited_fds_above_2_closed",
    "seccomp_profile_digest",
    "resource_limits",
}
_SANDBOX_ENVELOPE_22_FIELDS: Final[set[str]] = (
    {"$schema", "integrity", "migration_run_context_locator", "issued_at_utc", "validity"}
    | _SANDBOX_SPEC_17_FIELDS
)

_PROVENANCE_ENVELOPE_18_FIELDS: Final[set[str]] = {
    "$schema",
    "integrity",
    "migration_run_context_locator",
    "build_run_id",
    "built_at_utc",
    "repository",
    "source_commit_sha",
    "source_tree_oid",
    "source_date_epoch",
    "python_abi_tag",
    "build_backend",
    "build_backend_version",
    "build_backend_digest",
    "pyproject_sha256",
    "uv_lock_sha256",
    "schema_bundle_digest",
    "wheel",
    "wheel_digest",
}

_BOUNDARY_ENVELOPE_16_FIELDS: Final[set[str]] = {
    "$schema",
    "integrity",
    "migration_run_context_locator",
    "wheel_build_provenance_locator",
    "build_run_id",
    "verified_at_utc",
    "repository",
    "source_commit_sha",
    "wheel_digest",
    "build_backend_digest",
    "schema_bundle_digest",
    "sorted_record_entries",
    "sorted_record_digest",
    "archive_allowlist_passed",
    "ast_boundary_scan_passed",
    "isolated_venv_import_passed",
    "packaged_modules",
}

_MCP_ENVELOPE_13_FIELDS: Final[set[str]] = {
    "$schema",
    "integrity",
    "migration_run_context_locator",
    "sealed_sandbox_profile_locator",
    "build_run_id",
    "executed_at_utc",
    "source_commit_sha",
    "wheel_digest",
    "build_backend_digest",
    "schema_bundle_digest",
    "allowed_methods",
    "body_64k_boundary_verified",
    "cases",
}

_UNSIGNED_INTEGRITY_FIELDS: Final[set[str]] = {
    "key_id",
    "key_registry_snapshot_locator",
}
_SIGNED_INTEGRITY_FIELDS: Final[set[str]] = _UNSIGNED_INTEGRITY_FIELDS | {
    "content_digest",
    "signature_base64",
}

_SHA256_PREFIXED_RE: Final[re.Pattern[str]] = re.compile(r"\Asha256:[0-9a-f]{64}\Z")
_GIT_OID_RE: Final[re.Pattern[str]] = re.compile(r"\A[0-9a-f]{40}\Z")


@runtime_checkable
class Pr3SevenAConstituentVerifier(Protocol):
    """Outer-supervisor semantic verifier protocol for PR 3 (Etapa 10) 7A constituents.

    Unavailable (`None`) in GOV 1 (Etapa 8), blocking emission, verification, and D4
    admission of `smart_ads/gov1_convergence_record/v1` fail-closed until PR 3 lands.
    """

    def verify_7a_constituents(
        self,
        *,
        negative_security_test_report_locator: dict[str, Any],
        certification_7a_record_locator: dict[str, Any],
        migration_run_context_locator: dict[str, Any],
        sealed_sandbox_profile_locator: dict[str, Any],
        wheel_boundary_report_locator: dict[str, Any],
        mcp_rejection_matrix_report_locator: dict[str, Any],
        build_run_id: str,
        source_commit_sha: str,
        wheel_digest: str,
        build_backend_digest: str,
        schema_bundle_digest: str,
        converged_at_utc: str,
        store: Store | None = None,
    ) -> Mapping[str, Any]: ...


def _require_sha256_digest(value: object, label: str) -> str:
    if type(value) is not str or _SHA256_PREFIXED_RE.fullmatch(value) is None:
        raise ValueError(f"{label}: expected 'sha256:<64_lowercase_hex>'")
    return value


def _require_git_oid(value: object, label: str) -> str:
    if type(value) is not str or _GIT_OID_RE.fullmatch(value) is None:
        raise ValueError(f"{label}: expected 40-character lowercase hex Git OID")
    return value


def _require_strict_str(value: object, label: str) -> str:
    if (
        type(value) is not str
        or not value.strip()
        or value != value.strip()
        or "\x00" in value
    ):
        raise ValueError(f"{label}: expected non-empty stripped string without NUL")
    return value


def _require_exact_str(value: object, expected: str, label: str) -> str:
    if type(value) is not str or value != expected:
        raise ValueError(f"{label}: expected exact string {expected!r}")
    return value


def _require_path(value: object, label: str) -> Path:
    if not isinstance(value, (str, os.PathLike)):
        raise ValueError(f"{label}: expected filesystem path")
    return Path(value)


def _verify_envelope_integrity(envelope: dict[str, Any], *, label: str) -> None:
    integrity = envelope.get("integrity")
    if not isinstance(integrity, dict):
        raise ValueError(f"{label}.integrity: expected JSON object")
    keys = set(integrity.keys())
    if keys not in (_UNSIGNED_INTEGRITY_FIELDS, _SIGNED_INTEGRITY_FIELDS):
        raise ValueError(
            f"{label}.integrity: expected unsigned or signed P1 integrity fields"
        )
    _require_strict_str(integrity["key_id"], f"{label}.integrity.key_id")
    validate_locator(
        integrity["key_registry_snapshot_locator"], _KEY_REGISTRY_SCHEMA
    )
    if keys == _SIGNED_INTEGRITY_FIELDS:
        declared_digest = _require_sha256_digest(
            integrity["content_digest"], f"{label}.integrity.content_digest"
        )
        expected_digest = p1.content_digest(envelope)
        if declared_digest != expected_digest:
            raise ValueError(
                f"{label}.integrity.content_digest: mismatch against P1 preimage"
            )
        sig_b64 = integrity["signature_base64"]
        if type(sig_b64) is not str:
            raise ValueError(f"{label}.integrity.signature_base64: expected string")
        sig_bytes = p1._strict_base64_decode(sig_b64)
        if len(sig_bytes) != 64:
            raise ValueError(
                f"{label}.integrity.signature_base64: expected 64-byte Ed25519 signature"
            )


def _detect_artifact_mode(
    artifact: object, *, expected_schema: str, label: str
) -> str:
    if not isinstance(artifact, dict):
        raise ValueError(f"{label}: expected JSON object")
    if artifact.get("artifact_kind") == LOCAL_CANDIDATE_KIND:
        if "$schema" in artifact or "integrity" in artifact:
            raise ValueError(
                f"{label}: local candidate must not contain '$schema' or 'integrity'"
            )
        unwrap_local_candidate(artifact, expected_schema=expected_schema)
        return "candidate"
    if artifact.get("$schema") == expected_schema and "artifact_kind" not in artifact:
        return "envelope"
    raise ValueError(
        f"{label}: expected {expected_schema!r} P1 envelope or {LOCAL_CANDIDATE_KIND!r}"
    )


def _extract_artifact_payload_for_binding(
    artifact: dict[str, Any], *, expected_schema: str, mode: str, label: str
) -> dict[str, Any]:
    if mode == "candidate":
        return unwrap_local_candidate(artifact, expected_schema=expected_schema)
    _verify_envelope_integrity(artifact, label=label)
    return {
        k: copy.deepcopy(v)
        for k, v in artifact.items()
        if k not in {"$schema", "integrity"}
    }


def _enforce_etapa7_cross_binding_matrix(
    *,
    sandbox_payload: dict[str, Any],
    provenance_payload: dict[str, Any],
    boundary_payload: dict[str, Any],
    mcp_payload: dict[str, Any],
) -> None:
    """Enforce exact ADR-0001 §10 cross-binding matrix across the 4 Etapa 7 artifacts (`F-05`)."""
    validate_locator(
        sandbox_payload.get("migration_run_context_locator"), _RUN_CONTEXT_SCHEMA
    )
    validate_locator(
        provenance_payload.get("migration_run_context_locator"), _RUN_CONTEXT_SCHEMA
    )
    validate_locator(
        boundary_payload.get("migration_run_context_locator"), _RUN_CONTEXT_SCHEMA
    )
    validate_locator(
        mcp_payload.get("migration_run_context_locator"), _RUN_CONTEXT_SCHEMA
    )

    run_ctx_canonical = canonicalize(sandbox_payload["migration_run_context_locator"])
    for name, payload in (
        ("wheel_provenance", provenance_payload),
        ("wheel_boundary_report", boundary_payload),
        ("mcp_rejection_report", mcp_payload),
    ):
        if canonicalize(payload["migration_run_context_locator"]) != run_ctx_canonical:
            raise ValueError(
                f"convergence cross-binding: migration_run_context_locator mismatch in {name}"
            )

    if provenance_payload.get("repository") != boundary_payload.get("repository"):
        raise ValueError(
            "convergence cross-binding: repository mismatch between wheel_provenance and wheel_boundary_report"
        )

    for field_name, validator in (
        ("build_run_id", _require_strict_str),
        ("source_commit_sha", _require_git_oid),
        ("wheel_digest", _require_sha256_digest),
        ("build_backend_digest", _require_sha256_digest),
        ("schema_bundle_digest", _require_sha256_digest),
    ):
        expected_val = validator(
            provenance_payload.get(field_name), f"wheel_provenance.{field_name}"
        )
        bound_val = validator(
            boundary_payload.get(field_name), f"wheel_boundary_report.{field_name}"
        )
        mcp_val = validator(
            mcp_payload.get(field_name), f"mcp_rejection_report.{field_name}"
        )
        if bound_val != expected_val:
            raise ValueError(
                f"convergence cross-binding: {field_name} mismatch in wheel_boundary_report"
            )
        if mcp_val != expected_val:
            raise ValueError(
                f"convergence cross-binding: {field_name} mismatch in mcp_rejection_report"
            )

    sbx_validity = sandbox_payload.get("validity")
    exact_fields(sbx_validity, {"from", "until"}, "sandbox_profile.validity")
    sbx_from = timestamp(sbx_validity["from"])
    sbx_until = timestamp(sbx_validity["until"])
    mcp_exec = timestamp(mcp_payload.get("executed_at_utc"))
    if not (sbx_from <= mcp_exec < sbx_until):
        raise ValueError(
            "convergence cross-binding: mcp_rejection_report.executed_at_utc outside "
            "[sandbox_profile.validity.from, sandbox_profile.validity.until)"
        )
    prov_built = timestamp(provenance_payload.get("built_at_utc"))
    bound_verified = timestamp(boundary_payload.get("verified_at_utc"))
    if bound_verified < prov_built:
        raise ValueError(
            "convergence cross-binding: wheel_boundary_report.verified_at_utc precedes "
            "wheel_provenance.built_at_utc"
        )


# ---------------------------------------------------------------------------
# Closed Envelope Structural Validators (Pre-Subscript Guarding)
# ---------------------------------------------------------------------------


def _validate_sandbox_envelope_structure(envelope: object) -> dict[str, Any]:
    exact_fields(
        envelope, _SANDBOX_ENVELOPE_22_FIELDS, "sealed_sandbox_profile_envelope"
    )
    env = envelope  # type: ignore[assignment]
    _require_exact_str(
        env["$schema"], SANDBOX_PROFILE_SCHEMA, "sealed_sandbox_profile.$schema"
    )
    _verify_envelope_integrity(env, label="sealed_sandbox_profile")
    validate_locator(env["migration_run_context_locator"], _RUN_CONTEXT_SCHEMA)
    issued_dt = timestamp(env["issued_at_utc"])
    exact_fields(env["validity"], {"from", "until"}, "sealed_sandbox_profile.validity")
    from_dt = timestamp(env["validity"]["from"])
    until_dt = timestamp(env["validity"]["until"])
    if not (from_dt <= issued_dt < until_dt):
        raise ValueError(
            "sealed_sandbox_profile.validity: require validity.from <= issued_at_utc < validity.until"
        )
    spec_18 = {
        "$schema": SANDBOX_PROFILE_SCHEMA,
        **{k: env[k] for k in _SANDBOX_SPEC_17_FIELDS},
    }
    verify_sandbox_profile_spec(spec_18)
    return env


def _validate_provenance_envelope_structure(envelope: object) -> dict[str, Any]:
    exact_fields(
        envelope, _PROVENANCE_ENVELOPE_18_FIELDS, "wheel_build_provenance_envelope"
    )
    env = envelope  # type: ignore[assignment]
    _require_exact_str(
        env["$schema"],
        WHEEL_BUILD_PROVENANCE_SCHEMA,
        "wheel_build_provenance.$schema",
    )
    _verify_envelope_integrity(env, label="wheel_build_provenance")
    validate_locator(env["migration_run_context_locator"], _RUN_CONTEXT_SCHEMA)
    _require_strict_str(env["build_run_id"], "provenance.build_run_id")
    timestamp(env["built_at_utc"])
    _require_exact_str(
        env["repository"], DEFAULT_REPOSITORY, "provenance.repository"
    )
    _require_git_oid(env["source_commit_sha"], "provenance.source_commit_sha")
    _require_git_oid(env["source_tree_oid"], "provenance.source_tree_oid")
    sde = env["source_date_epoch"]
    if type(sde) is not int or sde < 0 or sde > MAX_JCS_SAFE_INT:
        raise ValueError("provenance.source_date_epoch: expected non-negative safe int")
    _require_exact_str(
        env["python_abi_tag"], EXPECTED_PYTHON_ABI_TAG, "provenance.python_abi_tag"
    )
    _require_exact_str(
        env["build_backend"], EXPECTED_BUILD_BACKEND, "provenance.build_backend"
    )
    _require_exact_str(
        env["build_backend_version"],
        EXPECTED_BUILD_BACKEND_VERSION,
        "provenance.build_backend_version",
    )
    _require_sha256_digest(
        env["build_backend_digest"], "provenance.build_backend_digest"
    )
    _require_sha256_digest(env["pyproject_sha256"], "provenance.pyproject_sha256")
    _require_sha256_digest(env["uv_lock_sha256"], "provenance.uv_lock_sha256")
    _require_sha256_digest(
        env["schema_bundle_digest"], "provenance.schema_bundle_digest"
    )
    declared_wheel_digest = _require_sha256_digest(
        env["wheel_digest"], "provenance.wheel_digest"
    )
    if not isinstance(env["wheel"], dict):
        raise ValueError("provenance.wheel: expected wheel_object_locator/v1 object")
    verify_wheel_object_locator(env["wheel"])
    if env["wheel"]["wheel_digest"] != declared_wheel_digest:
        raise ValueError("provenance: wheel.wheel_digest != wheel_digest")
    return env


def _validate_boundary_envelope_structure(envelope: object) -> dict[str, Any]:
    exact_fields(
        envelope, _BOUNDARY_ENVELOPE_16_FIELDS, "wheel_boundary_report_envelope"
    )
    env = envelope  # type: ignore[assignment]
    _require_exact_str(
        env["$schema"],
        WHEEL_BOUNDARY_REPORT_SCHEMA,
        "wheel_boundary_report.$schema",
    )
    _verify_envelope_integrity(env, label="wheel_boundary_report")
    validate_locator(env["migration_run_context_locator"], _RUN_CONTEXT_SCHEMA)
    validate_locator(
        env["wheel_build_provenance_locator"], WHEEL_BUILD_PROVENANCE_SCHEMA
    )
    _require_strict_str(env["build_run_id"], "boundary_report.build_run_id")
    timestamp(env["verified_at_utc"])
    _require_exact_str(
        env["repository"], DEFAULT_REPOSITORY, "boundary_report.repository"
    )
    _require_git_oid(env["source_commit_sha"], "boundary_report.source_commit_sha")
    _require_sha256_digest(env["wheel_digest"], "boundary_report.wheel_digest")
    _require_sha256_digest(
        env["build_backend_digest"], "boundary_report.build_backend_digest"
    )
    _require_sha256_digest(
        env["schema_bundle_digest"], "boundary_report.schema_bundle_digest"
    )
    _require_sha256_digest(
        env["sorted_record_digest"], "boundary_report.sorted_record_digest"
    )
    return env


def _validate_mcp_envelope_structure(envelope: object) -> dict[str, Any]:
    exact_fields(
        envelope, _MCP_ENVELOPE_13_FIELDS, "mcp_rejection_matrix_report_envelope"
    )
    env = envelope  # type: ignore[assignment]
    _require_exact_str(
        env["$schema"],
        MCP_REJECTION_REPORT_SCHEMA,
        "mcp_rejection_matrix_report.$schema",
    )
    _verify_envelope_integrity(env, label="mcp_rejection_matrix_report")
    validate_locator(env["migration_run_context_locator"], _RUN_CONTEXT_SCHEMA)
    validate_locator(env["sealed_sandbox_profile_locator"], SANDBOX_PROFILE_SCHEMA)
    _require_strict_str(env["build_run_id"], "mcp_report.build_run_id")
    timestamp(env["executed_at_utc"])
    _require_git_oid(env["source_commit_sha"], "mcp_report.source_commit_sha")
    _require_sha256_digest(env["wheel_digest"], "mcp_report.wheel_digest")
    _require_sha256_digest(
        env["build_backend_digest"], "mcp_report.build_backend_digest"
    )
    _require_sha256_digest(
        env["schema_bundle_digest"], "mcp_report.schema_bundle_digest"
    )
    return env


# ---------------------------------------------------------------------------
# Etapa 11 (`smart_ads/gov1_convergence_record/v1`) — Fail-Closed in Etapa 8
# ---------------------------------------------------------------------------


def _validate_gov1_convergence_structural_fields(
    payload: dict[str, Any],
    *,
    store: Store | None = None,
) -> dict[str, Any]:
    exact_fields(
        payload, _GOV1_CONVERGENCE_PAYLOAD_FIELDS, "gov1_convergence_record_payload"
    )
    validate_locator(
        payload["migration_run_context_locator"], _RUN_CONTEXT_SCHEMA
    )
    validate_locator(
        payload["wheel_boundary_report_locator"], WHEEL_BOUNDARY_REPORT_SCHEMA
    )
    validate_locator(
        payload["sealed_sandbox_profile_locator"], SANDBOX_PROFILE_SCHEMA
    )
    validate_locator(
        payload["negative_security_test_report_locator"], NEGATIVE_SECURITY_SCHEMA
    )
    validate_locator(
        payload["mcp_rejection_matrix_report_locator"], MCP_REJECTION_REPORT_SCHEMA
    )
    validate_locator(
        payload["certification_7a_record_locator"], CERTIFICATION_7A_SCHEMA
    )

    build_run_id = _require_strict_str(payload["build_run_id"], "build_run_id")
    converged_dt = timestamp(payload["converged_at_utc"])
    converged_at_utc = payload["converged_at_utc"]
    source_commit_sha = _require_git_oid(
        payload["source_commit_sha"], "source_commit_sha"
    )
    wheel_digest = _require_sha256_digest(payload["wheel_digest"], "wheel_digest")
    build_backend_digest = _require_sha256_digest(
        payload["build_backend_digest"], "build_backend_digest"
    )
    schema_bundle_digest = _require_sha256_digest(
        payload["schema_bundle_digest"], "schema_bundle_digest"
    )
    _require_exact_str(
        payload["convergence_status"], "PASS", "convergence_status"
    )

    if store is not None:
        if not isinstance(store, Store):
            raise ValueError("store: expected locator.Store instance")
        bound_obj = _validate_boundary_envelope_structure(
            store.get(
                payload["wheel_boundary_report_locator"],
                expected_type=WHEEL_BOUNDARY_REPORT_SCHEMA,
            )
        )
        sbx_obj = _validate_sandbox_envelope_structure(
            store.get(
                payload["sealed_sandbox_profile_locator"],
                expected_type=SANDBOX_PROFILE_SCHEMA,
            )
        )
        mcp_obj = _validate_mcp_envelope_structure(
            store.get(
                payload["mcp_rejection_matrix_report_locator"],
                expected_type=MCP_REJECTION_REPORT_SCHEMA,
            )
        )
        prov_obj = _validate_provenance_envelope_structure(
            store.get(
                bound_obj["wheel_build_provenance_locator"],
                expected_type=WHEEL_BUILD_PROVENANCE_SCHEMA,
            )
        )

        run_ctx_bytes = canonicalize(payload["migration_run_context_locator"])
        for label, constituent in (
            ("sealed_sandbox_profile", sbx_obj),
            ("wheel_build_provenance", prov_obj),
            ("wheel_boundary_report", bound_obj),
            ("mcp_rejection_matrix_report", mcp_obj),
        ):
            if (
                canonicalize(constituent["migration_run_context_locator"])
                != run_ctx_bytes
            ):
                raise ValueError(
                    f"gov1_convergence_record: migration_run_context_locator mismatch against {label}"
                )

        if canonicalize(mcp_obj["sealed_sandbox_profile_locator"]) != canonicalize(
            payload["sealed_sandbox_profile_locator"]
        ):
            raise ValueError(
                "gov1_convergence_record: mcp_rejection_matrix_report sealed_sandbox_profile_locator mismatch"
            )

        if prov_obj["repository"] != bound_obj["repository"]:
            raise ValueError(
                "gov1_convergence_record: repository mismatch between wheel_build_provenance and wheel_boundary_report"
            )

        for label, constituent in (
            ("wheel_build_provenance", prov_obj),
            ("wheel_boundary_report", bound_obj),
            ("mcp_rejection_matrix_report", mcp_obj),
        ):
            if constituent["build_run_id"] != build_run_id:
                raise ValueError(
                    f"gov1_convergence_record: build_run_id mismatch against {label}"
                )
            if constituent["source_commit_sha"] != source_commit_sha:
                raise ValueError(
                    f"gov1_convergence_record: source_commit_sha mismatch against {label}"
                )
            if constituent["wheel_digest"] != wheel_digest:
                raise ValueError(
                    f"gov1_convergence_record: wheel_digest mismatch against {label}"
                )
            if constituent["build_backend_digest"] != build_backend_digest:
                raise ValueError(
                    f"gov1_convergence_record: build_backend_digest mismatch against {label}"
                )
            if constituent["schema_bundle_digest"] != schema_bundle_digest:
                raise ValueError(
                    f"gov1_convergence_record: schema_bundle_digest mismatch against {label}"
                )

        # Sandbox validity window vs MCP execution + provenance/boundary/convergence anti-backdating
        validity(sbx_obj["validity"], mcp_obj["executed_at_utc"])
        if timestamp(bound_obj["verified_at_utc"]) < timestamp(
            prov_obj["built_at_utc"]
        ):
            raise ValueError(
                "gov1_convergence_record: wheel_boundary_report.verified_at_utc precedes wheel_build_provenance.built_at_utc"
            )

        for ts_label, ts_val in (
            ("sealed_sandbox_profile.issued_at_utc", sbx_obj["issued_at_utc"]),
            ("wheel_build_provenance.built_at_utc", prov_obj["built_at_utc"]),
            ("wheel_boundary_report.verified_at_utc", bound_obj["verified_at_utc"]),
            (
                "mcp_rejection_matrix_report.executed_at_utc",
                mcp_obj["executed_at_utc"],
            ),
        ):
            if converged_dt < timestamp(ts_val):
                raise ValueError(
                    f"gov1_convergence_record: converged_at_utc is backdated before {ts_label}"
                )

    validated = copy.deepcopy(payload)
    validated["converged_at_utc"] = converged_at_utc
    loads_strict(canonicalize(validated).decode("utf-8"))
    return validated


def _enforce_pr3_verifier_gate(
    *,
    payload: dict[str, Any],
    store: Store | None,
    pr3_verifier: Pr3SevenAConstituentVerifier | None,
) -> Mapping[str, Any]:
    if pr3_verifier is None:
        raise ValueError(
            "gov1_convergence_record/v1: fail-closed in Etapa 8; "
            "Pr3SevenAConstituentVerifier (PR 3 / Etapa 10) is absent"
        )
    if not isinstance(pr3_verifier, Pr3SevenAConstituentVerifier):
        raise ValueError(
            "gov1_convergence_record/v1: fail-closed; pr3_verifier does not satisfy "
            "Pr3SevenAConstituentVerifier"
        )
    if not isinstance(store, Store):
        raise ValueError(
            "gov1_convergence_record/v1: fail-closed; Store is required to resolve and cross-bind "
            "Etapa 7 constituents when pr3_verifier is provided"
        )
    pr3_outcome = pr3_verifier.verify_7a_constituents(
        negative_security_test_report_locator=copy.deepcopy(
            payload["negative_security_test_report_locator"]
        ),
        certification_7a_record_locator=copy.deepcopy(
            payload["certification_7a_record_locator"]
        ),
        migration_run_context_locator=copy.deepcopy(
            payload["migration_run_context_locator"]
        ),
        sealed_sandbox_profile_locator=copy.deepcopy(
            payload["sealed_sandbox_profile_locator"]
        ),
        wheel_boundary_report_locator=copy.deepcopy(
            payload["wheel_boundary_report_locator"]
        ),
        mcp_rejection_matrix_report_locator=copy.deepcopy(
            payload["mcp_rejection_matrix_report_locator"]
        ),
        build_run_id=payload["build_run_id"],
        source_commit_sha=payload["source_commit_sha"],
        wheel_digest=payload["wheel_digest"],
        build_backend_digest=payload["build_backend_digest"],
        schema_bundle_digest=payload["schema_bundle_digest"],
        converged_at_utc=payload["converged_at_utc"],
        store=store,
    )
    if (
        not isinstance(pr3_outcome, Mapping)
        or pr3_outcome.get("certified") is not True
    ):
        raise ValueError(
            "gov1_convergence_record/v1: fail-closed; PR 3 7A constituent verifier did not certify PASS"
        )
    observed_cases = pr3_outcome.get("negative_cases")
    if (
        not isinstance(observed_cases, (list, tuple))
        or any(type(c) is not str for c in observed_cases)
        or tuple(observed_cases) != MANDATORY_7A_NEGATIVE_SECURITY_CASES
    ):
        raise ValueError(
            "gov1_convergence_record/v1: fail-closed; PR 3 7A negative case set does not match "
            "exact 17 lexical cases of ADR-0001 §3.2"
        )
    converged_dt = timestamp(payload["converged_at_utc"])
    for ts_key in ("negative_executed_at_utc", "certified_at_utc"):
        if ts_key in pr3_outcome and pr3_outcome[ts_key] is not None:
            if converged_dt < timestamp(pr3_outcome[ts_key]):
                raise ValueError(
                    f"gov1_convergence_record/v1: converged_at_utc is backdated before {ts_key}"
                )
    return pr3_outcome


def build_gov1_convergence_record_envelope(
    *,
    migration_run_context_locator: dict[str, Any],
    wheel_boundary_report_locator: dict[str, Any],
    sealed_sandbox_profile_locator: dict[str, Any],
    negative_security_test_report_locator: dict[str, Any],
    mcp_rejection_matrix_report_locator: dict[str, Any],
    certification_7a_record_locator: dict[str, Any],
    build_run_id: str,
    converged_at_utc: str,
    source_commit_sha: str,
    wheel_digest: str,
    build_backend_digest: str,
    schema_bundle_digest: str,
    registry_locator: dict[str, Any],
    signer_key_id: str,
    convergence_status: str = "PASS",
    store: Store | None = None,
    pr3_verifier: Pr3SevenAConstituentVerifier | None = None,
) -> dict[str, Any]:
    """Validate `smart_ads/gov1_convergence_record/v1` fields and fail closed without PR 3 verifier."""
    validate_locator(registry_locator, _KEY_REGISTRY_SCHEMA)
    _require_strict_str(signer_key_id, "signer_key_id")
    payload = _validate_gov1_convergence_structural_fields(
        {
            "migration_run_context_locator": migration_run_context_locator,
            "wheel_boundary_report_locator": wheel_boundary_report_locator,
            "sealed_sandbox_profile_locator": sealed_sandbox_profile_locator,
            "negative_security_test_report_locator": negative_security_test_report_locator,
            "mcp_rejection_matrix_report_locator": mcp_rejection_matrix_report_locator,
            "certification_7a_record_locator": certification_7a_record_locator,
            "build_run_id": build_run_id,
            "converged_at_utc": converged_at_utc,
            "source_commit_sha": source_commit_sha,
            "wheel_digest": wheel_digest,
            "build_backend_digest": build_backend_digest,
            "schema_bundle_digest": schema_bundle_digest,
            "convergence_status": convergence_status,
        },
        store=store,
    )
    _enforce_pr3_verifier_gate(
        payload=payload, store=store, pr3_verifier=pr3_verifier
    )
    envelope = {
        "$schema": GOV1_CONVERGENCE_SCHEMA,
        **payload,
        "integrity": {
            "key_id": signer_key_id,
            "key_registry_snapshot_locator": copy.deepcopy(registry_locator),
        },
    }
    loads_strict(canonicalize(envelope).decode("utf-8"))
    return envelope


def verify_gov1_convergence_record(
    envelope: dict[str, Any],
    *,
    store: Store | None = None,
    seccomp_profile: dict[str, Any] | None = None,
    wheel_path: Path | None = None,
    repo_root: Path | None = None,
    backend_wheel_dir: Path | None = None,
    site_packages_dir: Path | None = None,
    pr3_verifier: Pr3SevenAConstituentVerifier | None = None,
) -> dict[str, Any]:
    """Verify `smart_ads/gov1_convergence_record/v1` and fail closed in Etapa 8 (`pr3_verifier=None`)."""
    if not isinstance(envelope, dict) or "artifact_kind" in envelope:
        raise ValueError(
            "verify_gov1_convergence_record: expected gov1_convergence_record/v1 P1 envelope"
        )
    exact_fields(
        envelope, _GOV1_CONVERGENCE_ENVELOPE_FIELDS, "gov1_convergence_record_envelope"
    )
    _require_exact_str(
        envelope["$schema"],
        GOV1_CONVERGENCE_SCHEMA,
        "gov1_convergence_record.$schema",
    )
    _verify_envelope_integrity(envelope, label="gov1_convergence_record")

    payload = {
        k: copy.deepcopy(v)
        for k, v in envelope.items()
        if k not in {"$schema", "integrity"}
    }
    validated = _validate_gov1_convergence_structural_fields(payload, store=store)

    if store is not None:
        if seccomp_profile is not None:
            sbx_obj = store.get(
                validated["sealed_sandbox_profile_locator"],
                expected_type=SANDBOX_PROFILE_SCHEMA,
            )
            verify_sealed_sandbox_profile(sbx_obj, seccomp_profile=seccomp_profile)
        if wheel_path is not None:
            whl_file = _require_path(wheel_path, "wheel_path")
            bound_obj = store.get(
                validated["wheel_boundary_report_locator"],
                expected_type=WHEEL_BOUNDARY_REPORT_SCHEMA,
            )
            mcp_obj = store.get(
                validated["mcp_rejection_matrix_report_locator"],
                expected_type=MCP_REJECTION_REPORT_SCHEMA,
            )
            verify_wheel_boundary_report(bound_obj, wheel_path=whl_file)
            verify_mcp_rejection_matrix_report(mcp_obj, wheel_path=whl_file)
            if repo_root is not None:
                prov_obj = store.get(
                    bound_obj["wheel_build_provenance_locator"],
                    expected_type=WHEEL_BUILD_PROVENANCE_SCHEMA,
                )
                verify_wheel_build_provenance(
                    prov_obj,
                    repo_root=_require_path(repo_root, "repo_root"),
                    wheel_path=whl_file,
                    backend_wheel_dir=backend_wheel_dir,
                    site_packages_dir=site_packages_dir,
                )

    _enforce_pr3_verifier_gate(
        payload=validated, store=store, pr3_verifier=pr3_verifier
    )
    return {
        "schema": GOV1_CONVERGENCE_SCHEMA,
        "convergence_status": "PASS",
        "wheel_digest": validated["wheel_digest"],
        "payload": validated,
    }


# ---------------------------------------------------------------------------
# D4 `ProtectedRuntime` Verifier for Etapa 7 Profiles (`Gov1AdmissionVerifier`)
# ---------------------------------------------------------------------------


class Gov1AdmissionVerifier(AdmissionVerifier):
    """D4 verifier for the four Etapa 7 profiles; fails closed on Etapa 11 until PR 3."""

    def __init__(
        self,
        runtime: ProtectedRuntime,
        pins: InstallationPins,
        store: Store,
        adr: bytes,
        *,
        inventory_locator: dict[str, Any] | None = None,
        pr3_verifier: Pr3SevenAConstituentVerifier | None = None,
    ) -> None:
        require(isinstance(pins, InstallationPins), "invalid installation pins")
        require(isinstance(store, Store), "invalid immutable object store")
        require(type(adr) is bytes, "ADR bytes required")
        require(
            isinstance(pins.owner_principal, str)
            and bool(pins.owner_principal.strip())
            and isinstance(pins.owner_tenant, str)
            and bool(pins.owner_tenant.strip()),
            "missing installation owner/tenant pin",
        )
        super().__init__(runtime, pins, store, adr)
        if inventory_locator is not None:
            validate_locator(inventory_locator, expected_type=INVENTORY)
            self.inventory_locator: dict[str, Any] | None = copy.deepcopy(
                inventory_locator
            )
        else:
            self.inventory_locator = None

        if pr3_verifier is not None and not isinstance(
            pr3_verifier, Pr3SevenAConstituentVerifier
        ):
            raise ValueError(
                "admission: pr3_verifier must satisfy Pr3SevenAConstituentVerifier"
            )
        self.pr3_verifier = pr3_verifier

    def _resolve_inventory_locator(
        self, inventory_locator: dict[str, Any] | None
    ) -> dict[str, Any]:
        loc = (
            inventory_locator
            if inventory_locator is not None
            else self.inventory_locator
        )
        require(
            isinstance(loc, dict),
            "inventory_locator is required for D4 contract inventory verification",
        )
        validate_locator(loc, expected_type=INVENTORY)
        return loc

    def _bootstrap_d4_authority(
        self, inventory_locator: dict[str, Any]
    ) -> tuple[
        dict[str, Any],
        ClockInterval,
        dict[str, Any],
        dict[str, Any],
        dict[str, Any],
        Floor,
        dict[str, Any],
        dict[str, Any],
        dict[str, Any],
        dict[str, Any],
        list[dict[str, Any]],
    ]:
        prerequisites = historical_prerequisites()
        clock = self.runtime.authenticated_clock()
        config = self._configuration(clock)
        inventory, inventory_history = self._inventory(
            inventory_locator, config, clock
        )
        checkpoint, floor = self._checkpoint(config, clock)

        checkpoint_rows = [
            p for p in inventory["profiles"] if p["schema"] == CHECKPOINT
        ]
        require(
            len(checkpoint_rows) == 1
            and canonicalize(checkpoint_rows[0])
            == canonicalize(config["anti_rollback_checkpoint_profile"]),
            "checkpoint row differs",
        )

        head_locator = self.runtime.read_head(config["head_register"])
        head, state, reg = self._chain(
            head_locator, config, checkpoint, floor, clock
        )

        anchors: list[dict[str, Any]] = []
        for historic_inventory in inventory_history:
            anchor, historical_reg = historical(
                self.store,
                historic_inventory,
                config,
                self.profiles,
                "contract_inventory_issue",
                "trust_anchor",
                historic_inventory["issued_at_utc"],
            )
            require(
                historical_reg["epoch"] <= reg["epoch"],
                "inventory registry newer than current authority",
            )
            if historical_reg["epoch"] == reg["epoch"]:
                require(
                    canonicalize(historical_reg) == canonicalize(reg),
                    "inventory registry fork",
                )
            self._current(
                anchor,
                reg,
                clock,
                [
                    (INVENTORY, "contract_inventory_issue"),
                    (HEAD, "current_key_state_head_issue"),
                    (STATE, "current_key_state_issue"),
                ],
            )
            anchors.append(anchor)

        return (
            prerequisites,
            clock,
            config,
            inventory,
            checkpoint,
            floor,
            head_locator,
            head,
            state,
            reg,
            anchors,
        )

    def _verify_signer_authority(
        self,
        envelope: dict[str, Any],
        *,
        schema: str,
        event_time_utc: object,
        config: dict[str, Any],
        reg: dict[str, Any],
        clock: ClockInterval,
    ) -> tuple[dict[str, Any], str]:
        role_action = _GOV1_ROLE_ACTION_SPECS.get(schema)
        require(role_action is not None, f"unsupported GOV1 schema {schema!r}")
        role, action = role_action
        require(isinstance(event_time_utc, str), f"{schema}: missing timestamp")
        event_dt = timestamp(event_time_utc)
        signer, historical_reg = historical(
            self.store,
            envelope,
            config,
            self.profiles,
            action,
            role,
            event_time_utc,
        )
        require(
            historical_reg["epoch"] <= reg["epoch"],
            f"{schema} registry newer than current authority",
        )
        if historical_reg["epoch"] == reg["epoch"]:
            require(
                canonicalize(historical_reg) == canonicalize(reg),
                f"{schema} registry fork",
            )
        self._current(signer, reg, clock, [(schema, action)])
        require(
            event_dt <= clock.bounds()[0],
            f"{schema} timestamp in future relative to authenticated clock",
        )
        return signer, action

    def _commit_cas_and_observe_final(
        self,
        *,
        clock: ClockInterval,
        config: dict[str, Any],
        inventory: dict[str, Any],
        checkpoint: dict[str, Any],
        floor: Floor,
        head_locator: dict[str, Any],
        head: dict[str, Any],
        state: dict[str, Any],
        reg: dict[str, Any],
        anchors: list[dict[str, Any]],
        signer_requirements: list[tuple[dict[str, Any], str, str]],
        active_sandbox_validities: list[dict[str, Any]],
    ) -> Floor:
        new_floor = Floor(head["epoch"], head_locator["content_digest"], floor.version)
        require(
            self.runtime.compare_and_swap(
                config["checkpoint_register"],
                floor,
                new_floor,
                config["head_register"],
                head_locator,
            )
            is True,
            "protected CAS conflict",
        )
        final_head, final_clock = self.runtime.observe_head_and_clock(
            config["head_register"]
        )
        require(
            final_clock.bounds()[0] >= clock.bounds()[0],
            "authenticated clock moved backwards",
        )
        validity(config["validity"], final_clock.lower_utc)
        validity(config["validity"], final_clock.upper_utc)
        for proof in (inventory, checkpoint, head, state):
            fresh(proof, final_clock)
        for anchor in anchors:
            self._current(
                anchor,
                reg,
                final_clock,
                [
                    (INVENTORY, "contract_inventory_issue"),
                    (HEAD, "current_key_state_head_issue"),
                    (STATE, "current_key_state_issue"),
                ],
            )
        for signer_entry, schema, action in signer_requirements:
            self._current(signer_entry, reg, final_clock, [(schema, action)])
        for sbx_val in active_sandbox_validities:
            validity(sbx_val, final_clock.lower_utc)
            validity(sbx_val, final_clock.upper_utc)
        require(
            canonicalize(final_head) == canonicalize(head_locator),
            "head advanced after validation; retry full verification",
        )
        return new_floor

    def verify_artifact(
        self,
        artifact_locator: dict[str, Any],
        *,
        inventory_locator: dict[str, Any] | None = None,
        seccomp_profile: dict[str, Any] | None = None,
        wheel_path: Path | None = None,
        repo_root: Path | None = None,
        backend_wheel_dir: Path | None = None,
        site_packages_dir: Path | None = None,
    ) -> dict[str, Any]:
        """Cryptographically and materially verify one GOV 1 P1 artifact under D4."""
        validate_locator(artifact_locator)
        schema = artifact_locator["artifact_type"]
        require(
            schema in _GOV1_ROLE_ACTION_SPECS,
            f"unsupported GOV1 artifact_type {schema!r}",
        )
        inv_loc = self._resolve_inventory_locator(inventory_locator)
        (
            prerequisites,
            clock,
            config,
            inventory,
            checkpoint,
            floor,
            head_locator,
            head,
            state,
            reg,
            anchors,
        ) = self._bootstrap_d4_authority(inv_loc)

        envelope = load_object(self.store, artifact_locator, schema)
        signer_reqs: list[tuple[dict[str, Any], str, str]] = []
        active_sbx_validities: list[dict[str, Any]] = []

        if schema == SANDBOX_PROFILE_SCHEMA:
            require(
                isinstance(seccomp_profile, dict),
                "seccomp_profile is required for sealed_sandbox_profile/v1 verification",
            )
            _validate_sandbox_envelope_structure(envelope)
            signer, action = self._verify_signer_authority(
                envelope,
                schema=schema,
                event_time_utc=envelope["issued_at_utc"],
                config=config,
                reg=reg,
                clock=clock,
            )
            validity(envelope["validity"], clock.lower_utc)
            validity(envelope["validity"], clock.upper_utc)
            material = verify_sealed_sandbox_profile(
                envelope, seccomp_profile=seccomp_profile  # type: ignore[arg-type]
            )
            signer_reqs.append((signer, schema, action))
            active_sbx_validities.append(envelope["validity"])

        elif schema == WHEEL_BUILD_PROVENANCE_SCHEMA:
            whl_file = _require_path(wheel_path, "wheel_path")
            repo_dir = _require_path(repo_root, "repo_root")
            _validate_provenance_envelope_structure(envelope)
            signer, action = self._verify_signer_authority(
                envelope,
                schema=schema,
                event_time_utc=envelope["built_at_utc"],
                config=config,
                reg=reg,
                clock=clock,
            )
            material = verify_wheel_build_provenance(
                envelope,
                repo_root=repo_dir,
                wheel_path=whl_file,
                backend_wheel_dir=backend_wheel_dir,
                site_packages_dir=site_packages_dir,
            )
            signer_reqs.append((signer, schema, action))

        elif schema == WHEEL_BOUNDARY_REPORT_SCHEMA:
            whl_file = _require_path(wheel_path, "wheel_path")
            _validate_boundary_envelope_structure(envelope)
            signer, action = self._verify_signer_authority(
                envelope,
                schema=schema,
                event_time_utc=envelope["verified_at_utc"],
                config=config,
                reg=reg,
                clock=clock,
            )
            prov_env = _validate_provenance_envelope_structure(
                load_object(
                    self.store,
                    envelope["wheel_build_provenance_locator"],
                    WHEEL_BUILD_PROVENANCE_SCHEMA,
                )
            )
            prov_signer, prov_action = self._verify_signer_authority(
                prov_env,
                schema=WHEEL_BUILD_PROVENANCE_SCHEMA,
                event_time_utc=prov_env["built_at_utc"],
                config=config,
                reg=reg,
                clock=clock,
            )
            require(
                timestamp(envelope["verified_at_utc"])
                >= timestamp(prov_env["built_at_utc"]),
                "wheel_boundary_report verified_at_utc precedes provenance built_at_utc",
            )
            require(
                canonicalize(envelope["migration_run_context_locator"])
                == canonicalize(prov_env["migration_run_context_locator"]),
                "wheel_boundary_report migration_run_context_locator mismatch against provenance",
            )
            for eq_field in (
                "build_run_id",
                "repository",
                "source_commit_sha",
                "wheel_digest",
                "build_backend_digest",
                "schema_bundle_digest",
            ):
                require(
                    envelope[eq_field] == prov_env[eq_field],
                    f"wheel_boundary_report {eq_field} mismatch against provenance",
                )
            if repo_root is not None:
                verify_wheel_build_provenance(
                    prov_env,
                    repo_root=_require_path(repo_root, "repo_root"),
                    wheel_path=whl_file,
                    backend_wheel_dir=backend_wheel_dir,
                    site_packages_dir=site_packages_dir,
                )
            material = verify_wheel_boundary_report(envelope, wheel_path=whl_file)
            signer_reqs.extend(
                [
                    (signer, schema, action),
                    (prov_signer, WHEEL_BUILD_PROVENANCE_SCHEMA, prov_action),
                ]
            )

        elif schema == MCP_REJECTION_REPORT_SCHEMA:
            whl_file = _require_path(wheel_path, "wheel_path")
            _validate_mcp_envelope_structure(envelope)
            signer, action = self._verify_signer_authority(
                envelope,
                schema=schema,
                event_time_utc=envelope["executed_at_utc"],
                config=config,
                reg=reg,
                clock=clock,
            )
            sbx_env = _validate_sandbox_envelope_structure(
                load_object(
                    self.store,
                    envelope["sealed_sandbox_profile_locator"],
                    SANDBOX_PROFILE_SCHEMA,
                )
            )
            sbx_signer, sbx_action = self._verify_signer_authority(
                sbx_env,
                schema=SANDBOX_PROFILE_SCHEMA,
                event_time_utc=sbx_env["issued_at_utc"],
                config=config,
                reg=reg,
                clock=clock,
            )
            require(
                canonicalize(envelope["migration_run_context_locator"])
                == canonicalize(sbx_env["migration_run_context_locator"]),
                "mcp_rejection_matrix_report migration_run_context_locator mismatch against sandbox",
            )
            validity(sbx_env["validity"], envelope["executed_at_utc"])
            validity(sbx_env["validity"], clock.lower_utc)
            validity(sbx_env["validity"], clock.upper_utc)
            if seccomp_profile is not None:
                verify_sealed_sandbox_profile(
                    sbx_env, seccomp_profile=seccomp_profile
                )
            material = verify_mcp_rejection_matrix_report(
                envelope, wheel_path=whl_file
            )
            signer_reqs.extend(
                [
                    (signer, schema, action),
                    (sbx_signer, SANDBOX_PROFILE_SCHEMA, sbx_action),
                ]
            )
            active_sbx_validities.append(sbx_env["validity"])

        else:
            exact_fields(
                envelope,
                _GOV1_CONVERGENCE_ENVELOPE_FIELDS,
                "gov1_convergence_record_envelope",
            )
            _require_exact_str(
                envelope["$schema"],
                GOV1_CONVERGENCE_SCHEMA,
                "gov1_convergence_record.$schema",
            )
            _verify_envelope_integrity(envelope, label="gov1_convergence_record")
            signer, action = self._verify_signer_authority(
                envelope,
                schema=GOV1_CONVERGENCE_SCHEMA,
                event_time_utc=envelope["converged_at_utc"],
                config=config,
                reg=reg,
                clock=clock,
            )
            conv_payload = {
                k: copy.deepcopy(v)
                for k, v in envelope.items()
                if k not in {"$schema", "integrity"}
            }
            _validate_gov1_convergence_structural_fields(
                conv_payload, store=self.store
            )
            if self.pr3_verifier is None:
                raise ValueError(
                    "gov1_convergence_record/v1: fail-closed in Etapa 8; "
                    "Pr3SevenAConstituentVerifier (PR 3 / Etapa 10) is absent"
                )
            require(
                isinstance(seccomp_profile, dict),
                "seccomp_profile is required for gov1_convergence_record/v1 verification",
            )
            whl_file = _require_path(wheel_path, "wheel_path")
            repo_dir = _require_path(repo_root, "repo_root")

            sbx_env = _validate_sandbox_envelope_structure(
                load_object(
                    self.store,
                    envelope["sealed_sandbox_profile_locator"],
                    SANDBOX_PROFILE_SCHEMA,
                )
            )
            bound_env = _validate_boundary_envelope_structure(
                load_object(
                    self.store,
                    envelope["wheel_boundary_report_locator"],
                    WHEEL_BOUNDARY_REPORT_SCHEMA,
                )
            )
            mcp_env = _validate_mcp_envelope_structure(
                load_object(
                    self.store,
                    envelope["mcp_rejection_matrix_report_locator"],
                    MCP_REJECTION_REPORT_SCHEMA,
                )
            )
            prov_env = _validate_provenance_envelope_structure(
                load_object(
                    self.store,
                    bound_env["wheel_build_provenance_locator"],
                    WHEEL_BUILD_PROVENANCE_SCHEMA,
                )
            )

            sbx_signer, sbx_action = self._verify_signer_authority(
                sbx_env,
                schema=SANDBOX_PROFILE_SCHEMA,
                event_time_utc=sbx_env["issued_at_utc"],
                config=config,
                reg=reg,
                clock=clock,
            )
            validity(sbx_env["validity"], clock.lower_utc)
            validity(sbx_env["validity"], clock.upper_utc)

            prov_signer, prov_action = self._verify_signer_authority(
                prov_env,
                schema=WHEEL_BUILD_PROVENANCE_SCHEMA,
                event_time_utc=prov_env["built_at_utc"],
                config=config,
                reg=reg,
                clock=clock,
            )
            bound_signer, bound_action = self._verify_signer_authority(
                bound_env,
                schema=WHEEL_BOUNDARY_REPORT_SCHEMA,
                event_time_utc=bound_env["verified_at_utc"],
                config=config,
                reg=reg,
                clock=clock,
            )
            mcp_signer, mcp_action = self._verify_signer_authority(
                mcp_env,
                schema=MCP_REJECTION_REPORT_SCHEMA,
                event_time_utc=mcp_env["executed_at_utc"],
                config=config,
                reg=reg,
                clock=clock,
            )

            material = verify_gov1_convergence_record(
                envelope,
                store=self.store,
                seccomp_profile=seccomp_profile,  # type: ignore[arg-type]
                wheel_path=whl_file,
                repo_root=repo_dir,
                backend_wheel_dir=backend_wheel_dir,
                site_packages_dir=site_packages_dir,
                pr3_verifier=self.pr3_verifier,
            )
            signer_reqs.extend(
                [
                    (signer, GOV1_CONVERGENCE_SCHEMA, action),
                    (sbx_signer, SANDBOX_PROFILE_SCHEMA, sbx_action),
                    (prov_signer, WHEEL_BUILD_PROVENANCE_SCHEMA, prov_action),
                    (bound_signer, WHEEL_BOUNDARY_REPORT_SCHEMA, bound_action),
                    (mcp_signer, MCP_REJECTION_REPORT_SCHEMA, mcp_action),
                ]
            )
            active_sbx_validities.append(sbx_env["validity"])

        new_floor = self._commit_cas_and_observe_final(
            clock=clock,
            config=config,
            inventory=inventory,
            checkpoint=checkpoint,
            floor=floor,
            head_locator=head_locator,
            head=head,
            state=state,
            reg=reg,
            anchors=anchors,
            signer_requirements=signer_reqs,
            active_sandbox_validities=active_sbx_validities,
        )
        return {
            "verification_status": "VERIFIED",
            "schema": schema,
            "artifact_locator": copy.deepcopy(artifact_locator),
            "inventory_locator": copy.deepcopy(inv_loc),
            "head_locator": copy.deepcopy(head_locator),
            "authority_epoch": head["epoch"],
            "effect_authorized": False,
            "historical_prerequisites": prerequisites[
                "predecessor_signatures_and_links"
            ],
            "floor_before": {
                "epoch": floor.epoch,
                "head_digest": floor.head_digest,
            },
            "floor_after": {
                "epoch": new_floor.epoch,
                "head_digest": new_floor.head_digest,
            },
            "material": material,
        }

    def admit_etapa7_bundle(
        self,
        *,
        sandbox_profile_locator: dict[str, Any],
        wheel_provenance_locator: dict[str, Any],
        wheel_boundary_report_locator: dict[str, Any],
        mcp_rejection_report_locator: dict[str, Any],
        seccomp_profile: dict[str, Any],
        wheel_path: Path,
        repo_root: Path,
        inventory_locator: dict[str, Any] | None = None,
        backend_wheel_dir: Path | None = None,
        site_packages_dir: Path | None = None,
    ) -> dict[str, Any]:
        """Atomically verify all 4 Etapa 7 P1 envelopes + material recomputations under D4."""
        if not isinstance(seccomp_profile, dict):
            raise ValueError("seccomp_profile: expected JSON object")
        whl_file = _require_path(wheel_path, "wheel_path")
        repo_dir = _require_path(repo_root, "repo_root")
        inv_loc = self._resolve_inventory_locator(inventory_locator)

        (
            prerequisites,
            clock,
            config,
            inventory,
            checkpoint,
            floor,
            head_locator,
            head,
            state,
            reg,
            anchors,
        ) = self._bootstrap_d4_authority(inv_loc)

        sbx_env = _validate_sandbox_envelope_structure(
            load_object(self.store, sandbox_profile_locator, SANDBOX_PROFILE_SCHEMA)
        )
        prov_env = _validate_provenance_envelope_structure(
            load_object(
                self.store, wheel_provenance_locator, WHEEL_BUILD_PROVENANCE_SCHEMA
            )
        )
        bound_env = _validate_boundary_envelope_structure(
            load_object(
                self.store,
                wheel_boundary_report_locator,
                WHEEL_BOUNDARY_REPORT_SCHEMA,
            )
        )
        mcp_env = _validate_mcp_envelope_structure(
            load_object(
                self.store,
                mcp_rejection_report_locator,
                MCP_REJECTION_REPORT_SCHEMA,
            )
        )

        sbx_signer, sbx_action = self._verify_signer_authority(
            sbx_env,
            schema=SANDBOX_PROFILE_SCHEMA,
            event_time_utc=sbx_env["issued_at_utc"],
            config=config,
            reg=reg,
            clock=clock,
        )
        validity(sbx_env["validity"], clock.lower_utc)
        validity(sbx_env["validity"], clock.upper_utc)

        prov_signer, prov_action = self._verify_signer_authority(
            prov_env,
            schema=WHEEL_BUILD_PROVENANCE_SCHEMA,
            event_time_utc=prov_env["built_at_utc"],
            config=config,
            reg=reg,
            clock=clock,
        )
        bound_signer, bound_action = self._verify_signer_authority(
            bound_env,
            schema=WHEEL_BOUNDARY_REPORT_SCHEMA,
            event_time_utc=bound_env["verified_at_utc"],
            config=config,
            reg=reg,
            clock=clock,
        )
        mcp_signer, mcp_action = self._verify_signer_authority(
            mcp_env,
            schema=MCP_REJECTION_REPORT_SCHEMA,
            event_time_utc=mcp_env["executed_at_utc"],
            config=config,
            reg=reg,
            clock=clock,
        )

        require(
            canonicalize(bound_env["wheel_build_provenance_locator"])
            == canonicalize(wheel_provenance_locator),
            "wheel_boundary_report.wheel_build_provenance_locator mismatch against wheel_provenance",
        )
        require(
            canonicalize(mcp_env["sealed_sandbox_profile_locator"])
            == canonicalize(sandbox_profile_locator),
            "mcp_rejection_matrix_report.sealed_sandbox_profile_locator mismatch against sandbox_profile",
        )

        sbx_payload = _extract_artifact_payload_for_binding(
            sbx_env,
            expected_schema=SANDBOX_PROFILE_SCHEMA,
            mode="envelope",
            label="sealed_sandbox_profile",
        )
        prov_payload = _extract_artifact_payload_for_binding(
            prov_env,
            expected_schema=WHEEL_BUILD_PROVENANCE_SCHEMA,
            mode="envelope",
            label="wheel_build_provenance",
        )
        bound_payload = _extract_artifact_payload_for_binding(
            bound_env,
            expected_schema=WHEEL_BOUNDARY_REPORT_SCHEMA,
            mode="envelope",
            label="wheel_boundary_report",
        )
        mcp_payload = _extract_artifact_payload_for_binding(
            mcp_env,
            expected_schema=MCP_REJECTION_REPORT_SCHEMA,
            mode="envelope",
            label="mcp_rejection_matrix_report",
        )
        _enforce_etapa7_cross_binding_matrix(
            sandbox_payload=sbx_payload,
            provenance_payload=prov_payload,
            boundary_payload=bound_payload,
            mcp_payload=mcp_payload,
        )

        # Complete ALL material recomputations before CAS and final head/clock observation.
        seccomp_digest = verify_seccomp_profile(seccomp_profile)
        sbx_res = verify_sealed_sandbox_profile(
            sbx_env, seccomp_profile=seccomp_profile
        )
        prov_res = verify_wheel_build_provenance(
            prov_env,
            repo_root=repo_dir,
            wheel_path=whl_file,
            backend_wheel_dir=backend_wheel_dir,
            site_packages_dir=site_packages_dir,
        )
        bound_res = verify_wheel_boundary_report(bound_env, wheel_path=whl_file)
        mcp_res = verify_mcp_rejection_matrix_report(mcp_env, wheel_path=whl_file)

        new_floor = self._commit_cas_and_observe_final(
            clock=clock,
            config=config,
            inventory=inventory,
            checkpoint=checkpoint,
            floor=floor,
            head_locator=head_locator,
            head=head,
            state=state,
            reg=reg,
            anchors=anchors,
            signer_requirements=[
                (sbx_signer, SANDBOX_PROFILE_SCHEMA, sbx_action),
                (prov_signer, WHEEL_BUILD_PROVENANCE_SCHEMA, prov_action),
                (bound_signer, WHEEL_BOUNDARY_REPORT_SCHEMA, bound_action),
                (mcp_signer, MCP_REJECTION_REPORT_SCHEMA, mcp_action),
            ],
            active_sandbox_validities=[sbx_env["validity"]],
        )
        return {
            "verification_status": "VERIFIED",
            "authority_epoch": head["epoch"],
            "effect_authorized": False,
            "historical_prerequisites": prerequisites[
                "predecessor_signatures_and_links"
            ],
            "floor_before": {
                "epoch": floor.epoch,
                "head_digest": floor.head_digest,
            },
            "floor_after": {
                "epoch": new_floor.epoch,
                "head_digest": new_floor.head_digest,
            },
            "seccomp_profile_digest": seccomp_digest,
            "sandbox_result": sbx_res,
            "provenance_result": prov_res,
            "boundary_result": bound_res,
            "mcp_result": mcp_res,
        }


# ---------------------------------------------------------------------------
# Etapa 8 (`verify_pr1_gov1_convergence` — Pre-PR2 Convergence Gate)
# ---------------------------------------------------------------------------


def verify_pr1_gov1_convergence(
    *,
    sandbox_profile: dict[str, Any],
    wheel_provenance: dict[str, Any],
    wheel_boundary_report: dict[str, Any],
    mcp_rejection_report: dict[str, Any],
    seccomp_profile: dict[str, Any],
    wheel_path: Path,
    repo_root: Path,
    admission_verifier: Gov1AdmissionVerifier | None = None,
    store: Store | None = None,
    inventory_locator: dict[str, Any] | None = None,
    backend_wheel_dir: Path | None = None,
    site_packages_dir: Path | None = None,
) -> dict[str, Any]:
    """Execute the Etapa 8 PR1+GOV1 pre-PR2 convergence gate with mandatory material recomputation."""
    if not isinstance(seccomp_profile, dict):
        raise ValueError("verify_pr1_gov1_convergence: seccomp_profile must be a JSON object")
    whl_file = _require_path(wheel_path, "wheel_path")
    repo_dir = _require_path(repo_root, "repo_root")

    modes = (
        _detect_artifact_mode(
            sandbox_profile,
            expected_schema=SANDBOX_PROFILE_SCHEMA,
            label="sandbox_profile",
        ),
        _detect_artifact_mode(
            wheel_provenance,
            expected_schema=WHEEL_BUILD_PROVENANCE_SCHEMA,
            label="wheel_provenance",
        ),
        _detect_artifact_mode(
            wheel_boundary_report,
            expected_schema=WHEEL_BOUNDARY_REPORT_SCHEMA,
            label="wheel_boundary_report",
        ),
        _detect_artifact_mode(
            mcp_rejection_report,
            expected_schema=MCP_REJECTION_REPORT_SCHEMA,
            label="mcp_rejection_report",
        ),
    )
    if len(set(modes)) != 1:
        raise ValueError(
            "verify_pr1_gov1_convergence: mixing gov1_local_candidate and P1 envelope modes is forbidden"
        )
    mode = modes[0]

    if mode == "candidate":
        if (
            admission_verifier is not None
            or store is not None
            or inventory_locator is not None
        ):
            raise ValueError(
                "verify_pr1_gov1_convergence: candidate mode cannot be combined with D4 admission_verifier or store"
            )

        sbx_payload = _extract_artifact_payload_for_binding(
            sandbox_profile,
            expected_schema=SANDBOX_PROFILE_SCHEMA,
            mode="candidate",
            label="sandbox_profile",
        )
        prov_payload = _extract_artifact_payload_for_binding(
            wheel_provenance,
            expected_schema=WHEEL_BUILD_PROVENANCE_SCHEMA,
            mode="candidate",
            label="wheel_provenance",
        )
        bound_payload = _extract_artifact_payload_for_binding(
            wheel_boundary_report,
            expected_schema=WHEEL_BOUNDARY_REPORT_SCHEMA,
            mode="candidate",
            label="wheel_boundary_report",
        )
        mcp_payload = _extract_artifact_payload_for_binding(
            mcp_rejection_report,
            expected_schema=MCP_REJECTION_REPORT_SCHEMA,
            mode="candidate",
            label="mcp_rejection_report",
        )

        if (
            "wheel_build_provenance_locator" in bound_payload
            or "wheel_build_provenance_candidate_ref" not in bound_payload
        ):
            raise ValueError(
                "verify_pr1_gov1_convergence: candidate wheel_boundary_report must use wheel_build_provenance_candidate_ref"
            )
        verify_local_candidate_ref(
            bound_payload["wheel_build_provenance_candidate_ref"],
            expected_schema=WHEEL_BUILD_PROVENANCE_SCHEMA,
            expected_candidate=wheel_provenance,
        )
        if canonicalize(
            bound_payload["wheel_build_provenance_candidate_ref"]
        ) != canonicalize(build_local_candidate_ref(wheel_provenance)):
            raise ValueError(
                "verify_pr1_gov1_convergence: wheel_build_provenance_candidate_ref mismatch"
            )

        if (
            "sealed_sandbox_profile_locator" in mcp_payload
            or "sealed_sandbox_profile_candidate_ref" not in mcp_payload
        ):
            raise ValueError(
                "verify_pr1_gov1_convergence: candidate mcp_rejection_report must use sealed_sandbox_profile_candidate_ref"
            )
        verify_local_candidate_ref(
            mcp_payload["sealed_sandbox_profile_candidate_ref"],
            expected_schema=SANDBOX_PROFILE_SCHEMA,
            expected_candidate=sandbox_profile,
        )
        if canonicalize(
            mcp_payload["sealed_sandbox_profile_candidate_ref"]
        ) != canonicalize(build_local_candidate_ref(sandbox_profile)):
            raise ValueError(
                "verify_pr1_gov1_convergence: sealed_sandbox_profile_candidate_ref mismatch"
            )

        _enforce_etapa7_cross_binding_matrix(
            sandbox_payload=sbx_payload,
            provenance_payload=prov_payload,
            boundary_payload=bound_payload,
            mcp_payload=mcp_payload,
        )

        seccomp_digest = verify_seccomp_profile(seccomp_profile)
        sbx_res = verify_sealed_sandbox_profile(
            sandbox_profile, seccomp_profile=seccomp_profile
        )
        prov_res = verify_wheel_build_provenance(
            wheel_provenance,
            repo_root=repo_dir,
            wheel_path=whl_file,
            backend_wheel_dir=backend_wheel_dir,
            site_packages_dir=site_packages_dir,
        )
        bound_res = verify_wheel_boundary_report(
            wheel_boundary_report, wheel_path=whl_file
        )
        mcp_res = verify_mcp_rejection_matrix_report(
            mcp_rejection_report, wheel_path=whl_file
        )

    else:
        if not isinstance(admission_verifier, Gov1AdmissionVerifier) or not isinstance(
            store, Store
        ):
            raise ValueError(
                "verify_pr1_gov1_convergence: P1 envelope mode requires both Gov1AdmissionVerifier and Store"
            )
        if (
            admission_verifier.store is not store
            and admission_verifier.store.root.resolve() != store.root.resolve()
        ):
            raise ValueError(
                "verify_pr1_gov1_convergence: store does not match admission_verifier.store"
            )

        if (
            "wheel_build_provenance_candidate_ref" in wheel_boundary_report
            or "wheel_build_provenance_locator" not in wheel_boundary_report
        ):
            raise ValueError(
                "verify_pr1_gov1_convergence: P1 wheel_boundary_report must use wheel_build_provenance_locator"
            )
        if (
            "sealed_sandbox_profile_candidate_ref" in mcp_rejection_report
            or "sealed_sandbox_profile_locator" not in mcp_rejection_report
        ):
            raise ValueError(
                "verify_pr1_gov1_convergence: P1 mcp_rejection_report must use sealed_sandbox_profile_locator"
            )

        sbx_loc = make_locator(SANDBOX_PROFILE_SCHEMA, canonicalize(sandbox_profile))
        prov_loc = make_locator(
            WHEEL_BUILD_PROVENANCE_SCHEMA, canonicalize(wheel_provenance)
        )
        bound_loc = make_locator(
            WHEEL_BOUNDARY_REPORT_SCHEMA, canonicalize(wheel_boundary_report)
        )
        mcp_loc = make_locator(
            MCP_REJECTION_REPORT_SCHEMA, canonicalize(mcp_rejection_report)
        )

        validate_locator(
            wheel_boundary_report["wheel_build_provenance_locator"],
            WHEEL_BUILD_PROVENANCE_SCHEMA,
        )
        if canonicalize(
            wheel_boundary_report["wheel_build_provenance_locator"]
        ) != canonicalize(prov_loc):
            raise ValueError(
                "verify_pr1_gov1_convergence: wheel_build_provenance_locator mismatch against wheel_provenance"
            )
        validate_locator(
            mcp_rejection_report["sealed_sandbox_profile_locator"],
            SANDBOX_PROFILE_SCHEMA,
        )
        if canonicalize(
            mcp_rejection_report["sealed_sandbox_profile_locator"]
        ) != canonicalize(sbx_loc):
            raise ValueError(
                "verify_pr1_gov1_convergence: sealed_sandbox_profile_locator mismatch against sandbox_profile"
            )

        admitted = admission_verifier.admit_etapa7_bundle(
            sandbox_profile_locator=sbx_loc,
            wheel_provenance_locator=prov_loc,
            wheel_boundary_report_locator=bound_loc,
            mcp_rejection_report_locator=mcp_loc,
            seccomp_profile=seccomp_profile,
            wheel_path=whl_file,
            repo_root=repo_dir,
            inventory_locator=inventory_locator,
            backend_wheel_dir=backend_wheel_dir,
            site_packages_dir=site_packages_dir,
        )
        seccomp_digest = admitted["seccomp_profile_digest"]
        sbx_res = admitted["sandbox_result"]
        prov_res = admitted["provenance_result"]
        bound_res = admitted["boundary_result"]
        mcp_res = admitted["mcp_result"]

    checked_sbx_p = sbx_res["payload"]
    checked_prov_p = prov_res["payload"]
    checked_bound_p = bound_res["payload"]
    checked_mcp_p = mcp_res["payload"]

    _enforce_etapa7_cross_binding_matrix(
        sandbox_payload=checked_sbx_p,
        provenance_payload=checked_prov_p,
        boundary_payload=checked_bound_p,
        mcp_payload=checked_mcp_p,
    )
    if seccomp_digest != checked_sbx_p["seccomp_profile_digest"]:
        raise ValueError(
            "verify_pr1_gov1_convergence: seccomp_profile_digest mismatch after recomputation"
        )
    if digest(whl_file.read_bytes()) != checked_prov_p["wheel_digest"]:
        raise ValueError(
            "verify_pr1_gov1_convergence: wheel_path digest mismatch after recomputation"
        )

    receipt: dict[str, Any] = {
        "artifact_kind": PRE_PR2_CONVERGENCE_GATE_KIND,
        "gate_status": "PASS",
        "mode": mode,
        "final_gov1_convergence_emitted": False,
        "pending_pr3_constituents": list(_PENDING_PR3_CONSTITUENTS),
        "signable": False,
        "authority": "none",
        "migration_run_context_locator": copy.deepcopy(
            checked_sbx_p["migration_run_context_locator"]
        ),
        "build_run_id": checked_prov_p["build_run_id"],
        "source_commit_sha": checked_prov_p["source_commit_sha"],
        "wheel_digest": checked_prov_p["wheel_digest"],
        "build_backend_digest": checked_prov_p["build_backend_digest"],
        "schema_bundle_digest": checked_prov_p["schema_bundle_digest"],
        "seccomp_profile_digest": seccomp_digest,
        "sorted_record_digest": bound_res["sorted_record_digest"],
    }
    loads_strict(canonicalize(receipt).decode("utf-8"))
    return receipt


__all__ = [
    "CERTIFICATION_7A_SCHEMA",
    "GOV1_CONVERGENCE_SCHEMA",
    "MANDATORY_7A_NEGATIVE_SECURITY_CASES",
    "NEGATIVE_SECURITY_SCHEMA",
    "PRE_PR2_CONVERGENCE_GATE_KIND",
    "Gov1AdmissionVerifier",
    "Pr3SevenAConstituentVerifier",
    "build_gov1_convergence_record_envelope",
    "verify_gov1_convergence_record",
    "verify_pr1_gov1_convergence",
]
