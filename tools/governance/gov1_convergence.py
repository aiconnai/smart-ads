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
    _validate_execution_dict,
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
    _validate_inspection_dict,
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

# ADR-0001 §12.7 exact D4 registry role and allowed_actions mapping for GOV 1 and 7A schemas.
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
        NEGATIVE_SECURITY_SCHEMA: (
            "7a_verifier",
            "negative_security_test_report_issue",
        ),
        CERTIFICATION_7A_SCHEMA: (
            "independent_7a_verifier",
            "certification_7a_record_issue",
        ),
        GOV1_CONVERGENCE_SCHEMA: (
            "gov1_convergence_verifier",
            "gov1_convergence_record_issue",
        ),
    }
)

_DIRECT_ADMIT_GOV1_SCHEMAS: Final[frozenset[str]] = frozenset(
    {
        SANDBOX_PROFILE_SCHEMA,
        WHEEL_BUILD_PROVENANCE_SCHEMA,
        WHEEL_BOUNDARY_REPORT_SCHEMA,
        MCP_REJECTION_REPORT_SCHEMA,
        GOV1_CONVERGENCE_SCHEMA,
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

_BOUNDARY_ENVELOPE_17_FIELDS: Final[set[str]] = {
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
    if keys != _SIGNED_INTEGRITY_FIELDS:
        raise ValueError(
            f"{label}.integrity: expected signed 4-field P1 integrity"
        )
    _require_strict_str(integrity["key_id"], f"{label}.integrity.key_id")
    validate_locator(
        integrity["key_registry_snapshot_locator"], _KEY_REGISTRY_SCHEMA
    )
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
        envelope, _BOUNDARY_ENVELOPE_17_FIELDS, "wheel_boundary_report_envelope"
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
    _require_sha256_digest(
        env["build_backend_digest"], "boundary_report.build_backend_digest"
    )
    _validate_inspection_dict(
        {
            "wheel_digest": env["wheel_digest"],
            "schema_bundle_digest": env["schema_bundle_digest"],
            "sorted_record_entries": env["sorted_record_entries"],
            "sorted_record_digest": env["sorted_record_digest"],
            "archive_allowlist_passed": env["archive_allowlist_passed"],
            "ast_boundary_scan_passed": env["ast_boundary_scan_passed"],
            "isolated_venv_import_passed": env["isolated_venv_import_passed"],
            "packaged_modules": env["packaged_modules"],
        }
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
    _require_sha256_digest(
        env["build_backend_digest"], "mcp_report.build_backend_digest"
    )
    _validate_execution_dict(
        {
            "wheel_digest": env["wheel_digest"],
            "schema_bundle_digest": env["schema_bundle_digest"],
            "allowed_methods": env["allowed_methods"],
            "body_64k_boundary_verified": env["body_64k_boundary_verified"],
            "cases": env["cases"],
        },
        label="mcp_report",
    )
    return env


from collections.abc import Callable
from dataclasses import dataclass

from tools.governance import gov1_7a_runner
from tools.governance.gov1_7a_negative import _NEG_ENVELOPE_16_KEYS
from tools.governance.gov1_d4_helpers import (
    Gov1InstallationPins,
    SnapshotStore,
    _D4_SCHEMA_ROLE_ACTION_SPECS,
    _authenticate_d4_7a_leaf_envelopes,
    _cert7a_mod,
    _disposable_wheel_path,
    _enforce_pinned_run_context_locator,
    _read_nonempty_regular_file,
    _reconstruct_d4_registry_chain,
    _reload_and_verify_d4_external_7a_inputs,
    _resolve_d4_pins,
    _run_disposable_stage7_material_handoff,
    _verify_d4_registry_lineage_step,
    _verify_d4_registry_membership,
    build_gov1_convergence_record_candidate,
    verify_gov1_convergence_candidate,
)
from tools.governance.gov1_wheel import IsolatedWheelProbeRunner

_CERT_ENVELOPE_23_FIELDS: Final[set[str]] = set(
    "$schema integrity migration_run_context_locator sealed_sandbox_profile_locator "
    "wheel_build_provenance_locator wheel_boundary_report_locator "
    "negative_security_test_report_locator build_run_id certified_at_utc certified_state "
    "source_commit_sha build_backend_digest schema_bundle_digest wheel_digest "
    "resource_mapping_contract_digest capability parser_artifact_locators parser_code_digest "
    "adapter_artifact_locators adapter_code_digest mapping_artifact_locators "
    "mapping_rules_digest fixture_evidence".split()
)


def _validate_negative_security_envelope_structure(envelope: object) -> dict[str, Any]:
    if not isinstance(envelope, dict) or "artifact_kind" in envelope:
        raise ValueError("negative_security_test_report: expected signed P1 envelope")
    exact_fields(envelope, _NEG_ENVELOPE_16_KEYS, "negative_security_test_report_envelope")
    _require_exact_str(
        envelope["$schema"], NEGATIVE_SECURITY_SCHEMA, "negative_security_test_report.$schema"
    )
    _verify_envelope_integrity(envelope, label="negative_security_test_report")
    validate_locator(envelope["migration_run_context_locator"], _RUN_CONTEXT_SCHEMA)
    validate_locator(envelope["sealed_sandbox_profile_locator"], SANDBOX_PROFILE_SCHEMA)
    validate_locator(envelope["wheel_build_provenance_locator"], WHEEL_BUILD_PROVENANCE_SCHEMA)
    timestamp(envelope["executed_at_utc"])
    loads_strict(canonicalize(envelope).decode("utf-8"))
    return envelope


def _validate_certification_7a_envelope_structure(envelope: object) -> dict[str, Any]:
    if not isinstance(envelope, dict) or "artifact_kind" in envelope or "generation" in envelope:
        raise ValueError("certification_7a_record: expected signed P1 envelope without generation")
    exact_fields(envelope, _CERT_ENVELOPE_23_FIELDS, "certification_7a_record_envelope")
    _require_exact_str(
        envelope["$schema"], CERTIFICATION_7A_SCHEMA, "certification_7a_record.$schema"
    )
    _verify_envelope_integrity(envelope, label="certification_7a_record")
    validate_locator(envelope["migration_run_context_locator"], _RUN_CONTEXT_SCHEMA)
    validate_locator(envelope["sealed_sandbox_profile_locator"], SANDBOX_PROFILE_SCHEMA)
    validate_locator(envelope["wheel_build_provenance_locator"], WHEEL_BUILD_PROVENANCE_SCHEMA)
    validate_locator(envelope["wheel_boundary_report_locator"], WHEEL_BOUNDARY_REPORT_SCHEMA)
    validate_locator(envelope["negative_security_test_report_locator"], NEGATIVE_SECURITY_SCHEMA)
    timestamp(envelope["certified_at_utc"])
    loads_strict(canonicalize(envelope).decode("utf-8"))
    return envelope


def _verify_optional_7a_cross_bindings(
    constituent: dict[str, Any],
    *,
    label: str,
    payload: dict[str, Any],
) -> None:
    locator_bindings = (
        ("migration_run_context_locator", _RUN_CONTEXT_SCHEMA),
        ("sealed_sandbox_profile_locator", SANDBOX_PROFILE_SCHEMA),
        ("negative_security_test_report_locator", NEGATIVE_SECURITY_SCHEMA),
        ("wheel_boundary_report_locator", WHEEL_BOUNDARY_REPORT_SCHEMA),
        ("mcp_rejection_matrix_report_locator", MCP_REJECTION_REPORT_SCHEMA),
    )
    for loc_field, expected_schema in locator_bindings:
        if loc_field in constituent:
            validate_locator(constituent[loc_field], expected_schema)
            if canonicalize(constituent[loc_field]) != canonicalize(payload[loc_field]):
                raise ValueError(
                    f"gov1_convergence_record: {loc_field} mismatch against {label}"
                )
    for scalar_field in (
        "build_run_id",
        "source_commit_sha",
        "wheel_digest",
        "build_backend_digest",
        "schema_bundle_digest",
    ):
        if scalar_field in constituent and constituent[scalar_field] != payload[scalar_field]:
            raise ValueError(
                f"gov1_convergence_record: {scalar_field} mismatch against {label}"
            )


# ---------------------------------------------------------------------------
# Etapa 11 (`smart_ads/gov1_convergence_record/v1`)
# ---------------------------------------------------------------------------


def _validate_convergence_top_fields(payload: dict[str, Any]) -> None:
    exact_fields(payload, _GOV1_CONVERGENCE_PAYLOAD_FIELDS, "gov1_convergence_record_payload")
    validate_locator(payload["migration_run_context_locator"], _RUN_CONTEXT_SCHEMA)
    validate_locator(payload["wheel_boundary_report_locator"], WHEEL_BOUNDARY_REPORT_SCHEMA)
    validate_locator(payload["sealed_sandbox_profile_locator"], SANDBOX_PROFILE_SCHEMA)
    validate_locator(payload["negative_security_test_report_locator"], NEGATIVE_SECURITY_SCHEMA)
    validate_locator(payload["mcp_rejection_matrix_report_locator"], MCP_REJECTION_REPORT_SCHEMA)
    validate_locator(payload["certification_7a_record_locator"], CERTIFICATION_7A_SCHEMA)
    _require_strict_str(payload["build_run_id"], "build_run_id")
    timestamp(payload["converged_at_utc"])
    _require_git_oid(payload["source_commit_sha"], "source_commit_sha")
    _require_sha256_digest(payload["wheel_digest"], "wheel_digest")
    _require_sha256_digest(payload["build_backend_digest"], "build_backend_digest")
    _require_sha256_digest(payload["schema_bundle_digest"], "schema_bundle_digest")
    _require_exact_str(payload["convergence_status"], "PASS", "convergence_status")


def _load_six_convergence_constituents(
    store: Store, payload: Mapping[str, Any]
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    bound_obj = _validate_boundary_envelope_structure(
        load_object(store, payload["wheel_boundary_report_locator"], WHEEL_BOUNDARY_REPORT_SCHEMA)
    )
    sbx_obj = _validate_sandbox_envelope_structure(
        load_object(store, payload["sealed_sandbox_profile_locator"], SANDBOX_PROFILE_SCHEMA)
    )
    mcp_obj = _validate_mcp_envelope_structure(
        load_object(store, payload["mcp_rejection_matrix_report_locator"], MCP_REJECTION_REPORT_SCHEMA)
    )
    prov_obj = _validate_provenance_envelope_structure(
        load_object(store, bound_obj["wheel_build_provenance_locator"], WHEEL_BUILD_PROVENANCE_SCHEMA)
    )
    neg_obj = _validate_negative_security_envelope_structure(
        load_object(store, payload["negative_security_test_report_locator"], NEGATIVE_SECURITY_SCHEMA)
    )
    cert7a_obj = _validate_certification_7a_envelope_structure(
        load_object(store, payload["certification_7a_record_locator"], CERTIFICATION_7A_SCHEMA)
    )
    return sbx_obj, prov_obj, bound_obj, mcp_obj, neg_obj, cert7a_obj


def _check_store_constituent_bindings_and_chronology(
    payload: dict[str, Any], store: Store
) -> None:
    if not isinstance(store, Store):
        raise ValueError("store: expected locator.Store instance")
    sbx_obj, prov_obj, bound_obj, mcp_obj, neg_obj, cert7a_obj = _load_six_convergence_constituents(
        store, payload
    )
    run_ctx_b = canonicalize(payload["migration_run_context_locator"])
    for lbl, obj in (
        ("sealed_sandbox_profile", sbx_obj),
        ("wheel_build_provenance", prov_obj),
        ("wheel_boundary_report", bound_obj),
        ("mcp_rejection_matrix_report", mcp_obj),
    ):
        if canonicalize(obj["migration_run_context_locator"]) != run_ctx_b:
            raise ValueError(f"gov1_convergence_record: migration_run_context_locator mismatch against {lbl}")
    prov_loc_b = canonicalize(bound_obj["wheel_build_provenance_locator"])
    if (
        canonicalize(mcp_obj["sealed_sandbox_profile_locator"]) != canonicalize(payload["sealed_sandbox_profile_locator"])
        or canonicalize(neg_obj["wheel_build_provenance_locator"]) != prov_loc_b
        or canonicalize(cert7a_obj["wheel_build_provenance_locator"]) != prov_loc_b
        or prov_obj["repository"] != bound_obj["repository"]
    ):
        raise ValueError("gov1_convergence_record: locator or repository cross-binding mismatch")
    for lbl, obj in (("wheel_build_provenance", prov_obj), ("wheel_boundary_report", bound_obj), ("mcp_rejection_matrix_report", mcp_obj)):
        for fld in ("build_run_id", "source_commit_sha", "wheel_digest", "build_backend_digest", "schema_bundle_digest"):
            if obj[fld] != payload[fld]:
                raise ValueError(f"gov1_convergence_record: {fld} mismatch against {lbl}")
    _verify_optional_7a_cross_bindings(neg_obj, label="negative_security_test_report", payload=payload)
    _verify_optional_7a_cross_bindings(cert7a_obj, label="certification_7a_record", payload=payload)
    _check_constituent_timestamps(payload["converged_at_utc"], sbx_obj, prov_obj, bound_obj, mcp_obj, neg_obj, cert7a_obj)


def _check_constituent_timestamps(
    converged_at_utc: str,
    sbx_obj: Mapping[str, Any],
    prov_obj: Mapping[str, Any],
    bound_obj: Mapping[str, Any],
    mcp_obj: Mapping[str, Any],
    neg_obj: Mapping[str, Any],
    cert7a_obj: Mapping[str, Any],
) -> None:
    validity(dict(sbx_obj["validity"]), mcp_obj["executed_at_utc"])
    validity(dict(sbx_obj["validity"]), neg_obj["executed_at_utc"])
    if timestamp(bound_obj["verified_at_utc"]) < timestamp(prov_obj["built_at_utc"]):
        raise ValueError("gov1_convergence_record: wheel_boundary_report.verified_at_utc precedes wheel_build_provenance.built_at_utc")
    if timestamp(cert7a_obj["certified_at_utc"]) < timestamp(neg_obj["executed_at_utc"]):
        raise ValueError("gov1_convergence_record: certification_7a_record.certified_at_utc precedes negative_security_test_report.executed_at_utc")
    conv_dt = timestamp(converged_at_utc)
    for ts_lbl, ts_val in (
        ("sealed_sandbox_profile.issued_at_utc", sbx_obj["issued_at_utc"]),
        ("wheel_build_provenance.built_at_utc", prov_obj["built_at_utc"]),
        ("wheel_boundary_report.verified_at_utc", bound_obj["verified_at_utc"]),
        ("mcp_rejection_matrix_report.executed_at_utc", mcp_obj["executed_at_utc"]),
        ("negative_security_test_report.executed_at_utc", neg_obj["executed_at_utc"]),
        ("certification_7a_record.certified_at_utc", cert7a_obj["certified_at_utc"]),
    ):
        if conv_dt < timestamp(ts_val):
            raise ValueError(f"gov1_convergence_record: converged_at_utc is backdated before {ts_lbl}")


def _validate_gov1_convergence_structural_fields(
    payload: dict[str, Any],
    *,
    store: Store | None = None,
) -> dict[str, Any]:
    _validate_convergence_top_fields(payload)
    if store is not None:
        _check_store_constituent_bindings_and_chronology(payload, store)
    validated = copy.deepcopy(payload)
    loads_strict(canonicalize(validated).decode("utf-8"))
    return validated


def _validate_pr3_outcome_fields(
    pr3_outcome: object,
    *,
    payload: Mapping[str, Any],
    sbx_env: Mapping[str, Any],
    neg_env: Mapping[str, Any],
    cert7a_env: Mapping[str, Any],
) -> Mapping[str, Any]:
    if not isinstance(pr3_outcome, Mapping) or pr3_outcome.get("certified") is not True:
        raise ValueError("gov1_convergence_record/v1: fail-closed; PR 3 7A constituent verifier did not certify PASS")
    obs_cases = pr3_outcome.get("negative_cases")
    if (
        not isinstance(obs_cases, (list, tuple))
        or any(type(c) is not str for c in obs_cases)
        or tuple(obs_cases) != MANDATORY_7A_NEGATIVE_SECURITY_CASES
    ):
        raise ValueError("gov1_convergence_record/v1: fail-closed; PR 3 7A negative case set mismatch")
    neg_exec_utc, cert_utc = pr3_outcome.get("negative_executed_at_utc"), pr3_outcome.get("certified_at_utc")
    if type(neg_exec_utc) is not str or type(cert_utc) is not str:
        raise ValueError("gov1_convergence_record/v1: fail-closed; mandatory RFC 3339 timestamps missing")
    neg_dt, cert_dt, conv_dt = timestamp(neg_exec_utc), timestamp(cert_utc), timestamp(payload["converged_at_utc"])
    if neg_env["executed_at_utc"] != neg_exec_utc or cert7a_env["certified_at_utc"] != cert_utc:
        raise ValueError("gov1_convergence_record/v1: 7A timestamps mismatch against pr3_verifier outcome")
    validity(dict(sbx_env["validity"]), neg_exec_utc)
    if cert_dt < neg_dt or conv_dt < neg_dt or conv_dt < cert_dt:
        raise ValueError("gov1_convergence_record/v1: converged_at_utc or certified_at_utc is backdated")
    return pr3_outcome


def _require_exact_seven_a_verifier(pr3_verifier: object, cert7a: Any) -> Any:
    if type(pr3_verifier) is not cert7a.SevenAConstituentVerifier or any(
        attr in getattr(pr3_verifier, "__dict__", {})
        for attr in ("verify_7a_constituents", "verify_bound_preflight_inputs")
    ):
        raise ValueError("gov1_convergence_record/v1: fail-closed; pr3_verifier must be exact unshadowed SevenAConstituentVerifier")
    return pr3_verifier


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
        raise ValueError("gov1_convergence_record/v1: fail-closed; pr3_verifier does not satisfy Pr3SevenAConstituentVerifier")
    if not isinstance(store, Store):
        raise ValueError("gov1_convergence_record/v1: fail-closed; Store is required when pr3_verifier is provided")
    sbx_env = _validate_sandbox_envelope_structure(load_object(store, payload["sealed_sandbox_profile_locator"], SANDBOX_PROFILE_SCHEMA))
    neg_env = _validate_negative_security_envelope_structure(load_object(store, payload["negative_security_test_report_locator"], NEGATIVE_SECURITY_SCHEMA))
    cert7a_env = _validate_certification_7a_envelope_structure(load_object(store, payload["certification_7a_record_locator"], CERTIFICATION_7A_SCHEMA))
    cert7a = _cert7a_mod()
    call_kw = {
        "negative_security_test_report_locator": copy.deepcopy(payload["negative_security_test_report_locator"]),
        "certification_7a_record_locator": copy.deepcopy(payload["certification_7a_record_locator"]),
        "migration_run_context_locator": copy.deepcopy(payload["migration_run_context_locator"]),
        "sealed_sandbox_profile_locator": copy.deepcopy(payload["sealed_sandbox_profile_locator"]),
        "wheel_boundary_report_locator": copy.deepcopy(payload["wheel_boundary_report_locator"]),
        "mcp_rejection_matrix_report_locator": copy.deepcopy(payload["mcp_rejection_matrix_report_locator"]),
        "build_run_id": payload["build_run_id"],
        "source_commit_sha": payload["source_commit_sha"],
        "wheel_digest": payload["wheel_digest"],
        "build_backend_digest": payload["build_backend_digest"],
        "schema_bundle_digest": payload["schema_bundle_digest"],
        "converged_at_utc": payload["converged_at_utc"],
        "store": store,
    }
    if type(pr3_verifier) is cert7a.SevenAConstituentVerifier:
        _require_exact_seven_a_verifier(pr3_verifier, cert7a)
        pr3_outcome = cert7a.SevenAConstituentVerifier.verify_7a_constituents(pr3_verifier, **call_kw)
    else:
        pr3_outcome = pr3_verifier.verify_7a_constituents(**call_kw)
    return _validate_pr3_outcome_fields(
        pr3_outcome, payload=payload, sbx_env=sbx_env, neg_env=neg_env, cert7a_env=cert7a_env
    )


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
    raw_payload = {
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
    }
    payload = _validate_gov1_convergence_structural_fields(raw_payload, store=store)
    _enforce_pr3_verifier_gate(payload=payload, store=store, pr3_verifier=pr3_verifier)
    envelope = {
        "$schema": GOV1_CONVERGENCE_SCHEMA,
        **payload,
        "integrity": {"key_id": signer_key_id, "key_registry_snapshot_locator": copy.deepcopy(registry_locator)},
    }
    loads_strict(canonicalize(envelope).decode("utf-8"))
    return envelope


def _capture_envelope_pr3_preflight_inputs(
    pr3_verifier: Pr3SevenAConstituentVerifier | None,
    *,
    wheel_bytes: bytes,
    repo_dir: Path,
    source_commit_sha: str,
    corpus_path: Path | None,
    legacy_repo: Path | None,
    legacy_blobs_dir: Path | None,
    require_external: bool = False,
) -> tuple[bytes, Mapping[str, bytes], Mapping[str, bytes]]:
    cert7a = _cert7a_mod()
    has_ext = require_external or corpus_path is not None or legacy_repo is not None or legacy_blobs_dir is not None
    if has_ext:
        if corpus_path is None or (legacy_repo is None) == (legacy_blobs_dir is None):
            raise ValueError("verify_gov1_convergence_record: require corpus_path and (legacy_repo XOR legacy_blobs_dir)")
        _, corpus_bytes = _read_nonempty_regular_file(corpus_path, "corpus_path")
        git_blobs = cert7a.resolve_7a_smart_ads_git_blobs(repo_dir, source_commit_sha)
        if corpus_bytes != git_blobs.get(cert7a.CORPUS_GIT_PATH[1]):
            raise ValueError("verify_gov1_convergence_record: corpus_path bytes disagree with Git blob at source_commit_sha")
        d26_blobs = gov1_7a_runner.resolve_pinned_pipeboard_d26_blobs(legacy_repo=legacy_repo, legacy_blobs_dir=legacy_blobs_dir)
        if not require_external:
            v_checked = _require_exact_seven_a_verifier(pr3_verifier, cert7a)
            if wheel_bytes != v_checked._wheel_bytes or corpus_bytes != v_checked._corpus_bytes or dict(git_blobs) != dict(v_checked._resolved_git_blobs) or dict(d26_blobs) != dict(v_checked._resolved_d26_blobs):
                raise ValueError("verify_gov1_convergence_record: preflight inputs diverged from bound SevenAConstituentVerifier")
        return corpus_bytes, git_blobs, d26_blobs
    v_checked = _require_exact_seven_a_verifier(pr3_verifier, cert7a)
    git_blobs = cert7a.resolve_7a_smart_ads_git_blobs(repo_dir, source_commit_sha)
    d26_blobs = gov1_7a_runner._verify_d26_blob_map(v_checked._resolved_d26_blobs)
    if wheel_bytes != v_checked._wheel_bytes or v_checked._corpus_bytes != git_blobs.get(cert7a.CORPUS_GIT_PATH[1]) or dict(git_blobs) != dict(v_checked._resolved_git_blobs):
        raise ValueError("verify_gov1_convergence_record: wheel_bytes, corpus_bytes, or git_blobs diverged from bound SevenAConstituentVerifier")
    return v_checked._corpus_bytes, git_blobs, d26_blobs


def _parse_convergence_envelope_header(envelope: object) -> dict[str, Any]:
    if not isinstance(envelope, dict) or "artifact_kind" in envelope:
        raise ValueError("verify_gov1_convergence_record: expected gov1_convergence_record/v1 P1 envelope")
    exact_fields(envelope, _GOV1_CONVERGENCE_ENVELOPE_FIELDS, "gov1_convergence_record_envelope")
    _require_exact_str(envelope["$schema"], GOV1_CONVERGENCE_SCHEMA, "gov1_convergence_record.$schema")
    _verify_envelope_integrity(envelope, label="gov1_convergence_record")
    payload = {k: copy.deepcopy(v) for k, v in envelope.items() if k not in {"$schema", "integrity"}}
    _validate_gov1_convergence_structural_fields(payload, store=None)
    return payload


def _verify_convergence_envelope_core(
    envelope: dict[str, Any], *, store: Store | None, seccomp_profile: dict[str, Any] | None,
    wheel_path: Path | None, corpus_path: Path | None, repo_root: Path | None,
    legacy_repo: Path | None, legacy_blobs_dir: Path | None, backend_wheel_dir: Path | None,
    site_packages_dir: Path | None, pr3_verifier: Pr3SevenAConstituentVerifier | None,
    probe_runner: IsolatedWheelProbeRunner | None, cli_auto_pr3: bool = False,
) -> dict[str, Any]:
    payload = _parse_convergence_envelope_header(envelope)
    cert7a = _cert7a_mod()
    if not cli_auto_pr3:
        if pr3_verifier is None:
            raise ValueError("gov1_convergence_record/v1: fail-closed in Etapa 8; Pr3SevenAConstituentVerifier (PR 3 / Etapa 10) is absent")
        _require_exact_seven_a_verifier(pr3_verifier, cert7a)
    if not isinstance(store, Store) or not isinstance(seccomp_profile, dict):
        raise ValueError("verify_gov1_convergence_record: Store and seccomp_profile are required")
    _, wheel_bytes = _read_nonempty_regular_file(_require_path(wheel_path, "wheel_path"), "wheel_path")
    repo_dir = _require_path(repo_root, "repo_root")
    validated = _validate_gov1_convergence_structural_fields(payload, store=store)
    sbx_obj, prov_obj, bound_obj, mcp_obj, _, _ = _load_six_convergence_constituents(store, validated)
    preflight = _capture_envelope_pr3_preflight_inputs(
        pr3_verifier, wheel_bytes=wheel_bytes, repo_dir=repo_dir, source_commit_sha=validated["source_commit_sha"],
        corpus_path=corpus_path, legacy_repo=legacy_repo, legacy_blobs_dir=legacy_blobs_dir, require_external=cli_auto_pr3,
    )
    _, _, prov_res, _, _ = _run_disposable_stage7_material_handoff(
        wheel_bytes=wheel_bytes, seccomp_profile=seccomp_profile, sandbox_obj=sbx_obj, prov_obj=prov_obj,
        bound_obj=bound_obj, mcp_obj=mcp_obj, repo_dir=repo_dir,
        backend_wheel_dir=backend_wheel_dir, site_packages_dir=site_packages_dir, probe_runner=probe_runner,
    )
    active_pr3 = (
        cert7a.SevenAConstituentVerifier(
            wheel_bytes=wheel_bytes, corpus_bytes=preflight[0], stripped_provenance_payload=prov_res["payload"],
            resolved_git_blobs=preflight[1], resolved_d26_blobs=preflight[2],
        )
        if cli_auto_pr3 else _require_exact_seven_a_verifier(pr3_verifier, cert7a)
    )
    cert7a.SevenAConstituentVerifier.verify_bound_preflight_inputs(
        active_pr3, wheel_bytes=wheel_bytes, corpus_bytes=preflight[0], stripped_provenance_payload=prov_res["payload"],
        resolved_git_blobs=preflight[1], resolved_d26_blobs=preflight[2],
    )
    _enforce_pr3_verifier_gate(payload=validated, store=store, pr3_verifier=active_pr3)
    return {"schema": GOV1_CONVERGENCE_SCHEMA, "convergence_status": "PASS", "authority": "none", "wheel_digest": validated["wheel_digest"], "payload": validated}


def verify_gov1_convergence_record(
    envelope: dict[str, Any],
    *,
    store: Store | None = None,
    seccomp_profile: dict[str, Any] | None = None,
    wheel_path: Path | None = None,
    corpus_path: Path | None = None,
    repo_root: Path | None = None,
    legacy_repo: Path | None = None,
    legacy_blobs_dir: Path | None = None,
    backend_wheel_dir: Path | None = None,
    site_packages_dir: Path | None = None,
    pr3_verifier: Pr3SevenAConstituentVerifier | None = None,
    probe_runner: IsolatedWheelProbeRunner | None = None,
) -> dict[str, Any]:
    """Verify `smart_ads/gov1_convergence_record/v1` with preflight -> Stage-7 -> passive 7A replay."""
    return _verify_convergence_envelope_core(
        envelope, store=store, seccomp_profile=seccomp_profile, wheel_path=wheel_path, corpus_path=corpus_path,
        repo_root=repo_root, legacy_repo=legacy_repo, legacy_blobs_dir=legacy_blobs_dir,
        backend_wheel_dir=backend_wheel_dir, site_packages_dir=site_packages_dir,
        pr3_verifier=pr3_verifier, probe_runner=probe_runner, cli_auto_pr3=False,
    )


# ---------------------------------------------------------------------------
# D4 `ProtectedRuntime` Verifier (`Gov1AdmissionVerifier`)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _D4AuthorityContext:
    prerequisites: dict[str, Any]
    clock: ClockInterval
    config: dict[str, Any]
    inventory: dict[str, Any]
    checkpoint: dict[str, Any]
    floor: Floor
    head_locator: dict[str, Any]
    head: dict[str, Any]
    state: dict[str, Any]
    reg: dict[str, Any]
    anchors: list[dict[str, Any]]
    pinned_run_ctx_loc: dict[str, Any]
    chain_registries_by_epoch: Mapping[int, bytes]


class Gov1AdmissionVerifier(AdmissionVerifier):
    """D4 verifier enforcing OS-isolated probes, monotonic registry lineage `1..tip_reg`, and 4 leaf classes."""

    def __init__(
        self,
        runtime: ProtectedRuntime,
        pins: InstallationPins,
        store: Store,
        adr: bytes,
        *,
        inventory_locator: dict[str, Any] | None = None,
        pr3_verifier: Pr3SevenAConstituentVerifier | None = None,
        isolated_probe_runner: IsolatedWheelProbeRunner | None = None,
        corpus_path: Path | None = None,
        legacy_repo: Path | None = None,
        legacy_blobs_dir: Path | None = None,
    ) -> None:
        require(isinstance(pins, InstallationPins), "invalid installation pins")
        require(isinstance(store, Store), "invalid immutable object store")
        require(type(adr) is bytes, "ADR bytes required")
        require(
            isinstance(pins.owner_principal, str) and bool(pins.owner_principal.strip())
            and isinstance(pins.owner_tenant, str) and bool(pins.owner_tenant.strip()),
            "missing installation owner/tenant pin",
        )
        super().__init__(runtime, pins, store, adr)
        if inventory_locator is not None:
            validate_locator(inventory_locator, expected_type=INVENTORY)
            self.inventory_locator: dict[str, Any] | None = copy.deepcopy(inventory_locator)
        else:
            self.inventory_locator = None
        if pr3_verifier is not None:
            _require_exact_seven_a_verifier(pr3_verifier, _cert7a_mod())
        self.pr3_verifier = pr3_verifier
        self.isolated_probe_runner = isolated_probe_runner
        self.corpus_path = corpus_path
        self.legacy_repo = legacy_repo
        self.legacy_blobs_dir = legacy_blobs_dir

    def _require_os_isolated_probe_runner(self) -> IsolatedWheelProbeRunner:
        runner = self.isolated_probe_runner
        if (
            runner is None
            or not isinstance(runner, IsolatedWheelProbeRunner)
            or type(runner.os_isolated) is not bool
            or runner.os_isolated is not True
        ):
            raise ValueError("admission: isolated_probe_runner with strict os_isolated=True is required")
        return runner

    def _resolve_inventory_locator(
        self, inventory_locator: dict[str, Any] | None
    ) -> dict[str, Any]:
        loc = inventory_locator if inventory_locator is not None else self.inventory_locator
        require(isinstance(loc, dict), "inventory_locator is required for D4 contract inventory verification")
        validate_locator(loc, expected_type=INVENTORY)
        return loc

    def _verify_inventory_history_anchors(
        self,
        inventory_history: list[dict[str, Any]],
        *,
        config: dict[str, Any],
        reg: dict[str, Any],
        clock: ClockInterval,
        chain_registries_by_epoch: Mapping[int, bytes],
    ) -> list[dict[str, Any]]:
        anchors: list[dict[str, Any]] = []
        anchor_actions = [
            (INVENTORY, "contract_inventory_issue"),
            (HEAD, "current_key_state_head_issue"),
            (STATE, "current_key_state_issue"),
        ]
        for historic_inv in inventory_history:
            anchor, historical_reg = historical(
                self.store, historic_inv, config, self.profiles,
                "contract_inventory_issue", "trust_anchor", historic_inv["issued_at_utc"],
            )
            _verify_d4_registry_membership(historical_reg, chain_registries_by_epoch, label=INVENTORY)
            require(historical_reg["epoch"] <= reg["epoch"], "inventory registry newer than current authority")
            self._current(anchor, reg, clock, anchor_actions)
            anchors.append(anchor)
        return anchors

    def _bootstrap_d4_authority(
        self, inventory_locator: dict[str, Any]
    ) -> _D4AuthorityContext:
        prerequisites = historical_prerequisites()
        clock = self.runtime.authenticated_clock()
        config = self._configuration(clock)
        inventory, inventory_history = self._inventory(inventory_locator, config, clock)
        checkpoint, floor = self._checkpoint(config, clock)
        checkpoint_rows = [p for p in inventory["profiles"] if p["schema"] == CHECKPOINT]
        require(
            len(checkpoint_rows) == 1
            and canonicalize(checkpoint_rows[0]) == canonicalize(config["anti_rollback_checkpoint_profile"]),
            "checkpoint row differs",
        )
        head_locator = self.runtime.read_head(config["head_register"])
        head, state, reg = self._chain(head_locator, config, checkpoint, floor, clock)
        pinned_run_ctx, chain_regs = _reconstruct_d4_registry_chain(
            self.store, head_locator=head_locator, pins=self.pins, config=config, profiles=self.profiles
        )
        anchors = self._verify_inventory_history_anchors(
            inventory_history, config=config, reg=reg, clock=clock, chain_registries_by_epoch=chain_regs
        )
        return _D4AuthorityContext(
            prerequisites, clock, config, inventory, checkpoint, floor,
            head_locator, head, state, reg, anchors, pinned_run_ctx, chain_regs,
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
        chain_registries_by_epoch: Mapping[int, bytes],
    ) -> tuple[dict[str, Any], str]:
        spec = _D4_SCHEMA_ROLE_ACTION_SPECS.get(schema)
        require(spec is not None, f"unsupported D4 GOV1/7A schema {schema!r}")
        profile_role, role, action = spec
        require(self.profiles[schema]["signer_role"] == profile_role, f"{schema} ADR signer_role mismatch")
        require(isinstance(event_time_utc, str), f"{schema}: missing timestamp")
        event_dt = timestamp(event_time_utc)
        signer, historical_reg = historical(
            self.store, envelope, config, self.profiles, action, role, event_time_utc
        )
        require(signer["tenant"] == self.pins.owner_tenant, f"{schema} signer tenant mismatch against installation pins")
        _verify_d4_registry_membership(historical_reg, chain_registries_by_epoch, label=schema)
        require(historical_reg["epoch"] <= reg["epoch"], f"{schema} registry newer than current authority")
        self._current(signer, reg, clock, [(schema, action)])
        require(event_dt <= clock.bounds()[0], f"{schema} timestamp in future relative to authenticated clock")
        return signer, action

    def _reload_store_envelopes_post_cas(
        self,
        auth: _D4AuthorityContext,
        refreshed_config: dict[str, Any],
        admitted_envelopes: list[tuple[dict[str, Any], dict[str, Any], str, str]],
        post_cas_reload_fn: Callable[[], None] | None,
    ) -> None:
        for loc, pre_env, env_schema, ev_time in admitted_envelopes:
            reloaded_env = load_object(self.store, loc, env_schema)
            require(
                canonicalize(reloaded_env) == canonicalize(pre_env),
                f"{env_schema} store object mutated during admission",
            )
            _enforce_pinned_run_context_locator(reloaded_env, auth.pinned_run_ctx_loc, env_schema)
            self._verify_signer_authority(
                reloaded_env, schema=env_schema, event_time_utc=ev_time, config=refreshed_config,
                reg=auth.reg, clock=auth.clock, chain_registries_by_epoch=auth.chain_registries_by_epoch,
            )
        if post_cas_reload_fn is not None:
            post_cas_reload_fn()

    def _commit_cas_and_observe_final(
        self,
        auth: _D4AuthorityContext,
        *,
        signer_requirements: list[tuple[dict[str, Any], str, str]],
        active_sandbox_validities: list[dict[str, Any]],
        admitted_envelopes: list[tuple[dict[str, Any], dict[str, Any], str, str]],
        post_cas_reload_fn: Callable[[], None] | None = None,
    ) -> Floor:
        new_floor = Floor(auth.head["epoch"], auth.head_locator["content_digest"], auth.floor.version)
        require(
            self.runtime.compare_and_swap(
                auth.config["checkpoint_register"], auth.floor, new_floor, auth.config["head_register"], auth.head_locator
            )
            is True,
            "protected CAS conflict",
        )
        refreshed_config = self._configuration(auth.clock)
        require(canonicalize(refreshed_config) == canonicalize(auth.config), "protected configuration changed during admission")
        self._reload_store_envelopes_post_cas(auth, refreshed_config, admitted_envelopes, post_cas_reload_fn)
        final_head, final_clock = self.runtime.observe_head_and_clock(refreshed_config["head_register"])
        require(final_clock.bounds()[0] >= auth.clock.bounds()[0], "authenticated clock moved backwards")
        validity(refreshed_config["validity"], final_clock.lower_utc)
        validity(refreshed_config["validity"], final_clock.upper_utc)
        for proof in (auth.inventory, auth.checkpoint, auth.head, auth.state):
            fresh(proof, final_clock)
        anchor_actions = [(INVENTORY, "contract_inventory_issue"), (HEAD, "current_key_state_head_issue"), (STATE, "current_key_state_issue")]
        for anchor in auth.anchors:
            self._current(anchor, auth.reg, final_clock, anchor_actions)
        for signer_entry, schema, action in signer_requirements:
            self._current(signer_entry, auth.reg, final_clock, [(schema, action)])
        for sbx_val in active_sandbox_validities:
            validity(sbx_val, final_clock.lower_utc)
            validity(sbx_val, final_clock.upper_utc)
        require(canonicalize(final_head) == canonicalize(auth.head_locator), "head advanced after validation; retry full verification")
        return new_floor

    def _admit_sandbox_artifact(
        self,
        artifact_locator: dict[str, Any],
        envelope: dict[str, Any],
        auth: _D4AuthorityContext,
        seccomp_profile: dict[str, Any] | None,
    ) -> tuple[dict[str, Any], list[tuple[dict[str, Any], str, str]], list[dict[str, Any]], list[tuple[dict[str, Any], dict[str, Any], str, str]], Callable[[], None] | None]:
        require(isinstance(seccomp_profile, dict), "seccomp_profile is required for sealed_sandbox_profile/v1 verification")
        _validate_sandbox_envelope_structure(envelope)
        _enforce_pinned_run_context_locator(envelope, auth.pinned_run_ctx_loc, SANDBOX_PROFILE_SCHEMA)
        signer, action = self._verify_signer_authority(
            envelope, schema=SANDBOX_PROFILE_SCHEMA, event_time_utc=envelope["issued_at_utc"],
            config=auth.config, reg=auth.reg, clock=auth.clock, chain_registries_by_epoch=auth.chain_registries_by_epoch,
        )
        validity(envelope["validity"], auth.clock.lower_utc)
        validity(envelope["validity"], auth.clock.upper_utc)
        material = verify_sealed_sandbox_profile(envelope, seccomp_profile=seccomp_profile)  # type: ignore[arg-type]
        return (
            material,
            [(signer, SANDBOX_PROFILE_SCHEMA, action)],
            [envelope["validity"]],
            [(artifact_locator, envelope, SANDBOX_PROFILE_SCHEMA, envelope["issued_at_utc"])],
            None,
        )

    def _admit_provenance_artifact(
        self,
        artifact_locator: dict[str, Any],
        envelope: dict[str, Any],
        auth: _D4AuthorityContext,
        *,
        runner: IsolatedWheelProbeRunner,
        wheel_path: Path | None,
        repo_root: Path | None,
        backend_wheel_dir: Path | None,
        site_packages_dir: Path | None,
    ) -> tuple[dict[str, Any], list[tuple[dict[str, Any], str, str]], list[dict[str, Any]], list[tuple[dict[str, Any], dict[str, Any], str, str]], Callable[[], None] | None]:
        whl_file, wheel_bytes = _read_nonempty_regular_file(_require_path(wheel_path, "wheel_path"), "wheel_path")
        repo_dir = _require_path(repo_root, "repo_root")
        _validate_provenance_envelope_structure(envelope)
        _enforce_pinned_run_context_locator(envelope, auth.pinned_run_ctx_loc, WHEEL_BUILD_PROVENANCE_SCHEMA)
        signer, action = self._verify_signer_authority(
            envelope, schema=WHEEL_BUILD_PROVENANCE_SCHEMA, event_time_utc=envelope["built_at_utc"],
            config=auth.config, reg=auth.reg, clock=auth.clock, chain_registries_by_epoch=auth.chain_registries_by_epoch,
        )
        with _disposable_wheel_path(wheel_bytes) as disposable_whl:
            material = verify_wheel_build_provenance(
                envelope, repo_root=repo_dir, wheel_path=disposable_whl,
                backend_wheel_dir=backend_wheel_dir, site_packages_dir=site_packages_dir, probe_runner=runner,
            )
        require(material["wheel_digest"] == digest(wheel_bytes), "wheel_build_provenance wheel_digest mismatch against captured wheel_bytes")
        return (
            material,
            [(signer, WHEEL_BUILD_PROVENANCE_SCHEMA, action)],
            [],
            [(artifact_locator, envelope, WHEEL_BUILD_PROVENANCE_SCHEMA, envelope["built_at_utc"])],
            lambda: require(_read_nonempty_regular_file(whl_file, "wheel_path")[1] == wheel_bytes, "wheel_path mutated"),
        )

    def _admit_boundary_artifact(
        self,
        artifact_locator: dict[str, Any],
        envelope: dict[str, Any],
        auth: _D4AuthorityContext,
        *,
        runner: IsolatedWheelProbeRunner,
        wheel_path: Path | None,
        repo_root: Path | None,
        backend_wheel_dir: Path | None,
        site_packages_dir: Path | None,
    ) -> tuple[dict[str, Any], list[tuple[dict[str, Any], str, str]], list[dict[str, Any]], list[tuple[dict[str, Any], dict[str, Any], str, str]], Callable[[], None] | None]:
        whl_file, wheel_bytes = _read_nonempty_regular_file(_require_path(wheel_path, "wheel_path"), "wheel_path")
        repo_dir = _require_path(repo_root, "repo_root")
        _validate_boundary_envelope_structure(envelope)
        _enforce_pinned_run_context_locator(envelope, auth.pinned_run_ctx_loc, WHEEL_BOUNDARY_REPORT_SCHEMA)
        signer, action = self._verify_signer_authority(
            envelope, schema=WHEEL_BOUNDARY_REPORT_SCHEMA, event_time_utc=envelope["verified_at_utc"],
            config=auth.config, reg=auth.reg, clock=auth.clock, chain_registries_by_epoch=auth.chain_registries_by_epoch,
        )
        prov_loc = envelope["wheel_build_provenance_locator"]
        prov_env = _validate_provenance_envelope_structure(load_object(self.store, prov_loc, WHEEL_BUILD_PROVENANCE_SCHEMA))
        _enforce_pinned_run_context_locator(prov_env, auth.pinned_run_ctx_loc, WHEEL_BUILD_PROVENANCE_SCHEMA)
        prov_signer, prov_action = self._verify_signer_authority(
            prov_env, schema=WHEEL_BUILD_PROVENANCE_SCHEMA, event_time_utc=prov_env["built_at_utc"],
            config=auth.config, reg=auth.reg, clock=auth.clock, chain_registries_by_epoch=auth.chain_registries_by_epoch,
        )
        require(timestamp(envelope["verified_at_utc"]) >= timestamp(prov_env["built_at_utc"]), "wheel_boundary_report verified_at_utc precedes provenance built_at_utc")
        for eq_field in ("build_run_id", "repository", "source_commit_sha", "wheel_digest", "build_backend_digest", "schema_bundle_digest"):
            require(envelope[eq_field] == prov_env[eq_field], f"wheel_boundary_report {eq_field} mismatch against provenance")
        with _disposable_wheel_path(wheel_bytes) as disposable_whl:
            prov_mat = verify_wheel_build_provenance(
                prov_env, repo_root=repo_dir, wheel_path=disposable_whl,
                backend_wheel_dir=backend_wheel_dir, site_packages_dir=site_packages_dir, probe_runner=runner,
            )
            material = verify_wheel_boundary_report(envelope, wheel_path=disposable_whl, probe_runner=runner)
        require(prov_mat["wheel_digest"] == digest(wheel_bytes) and material["wheel_digest"] == digest(wheel_bytes), "wheel_boundary_report wheel_digest mismatch against captured wheel_bytes")
        return (
            material,
            [(signer, WHEEL_BOUNDARY_REPORT_SCHEMA, action), (prov_signer, WHEEL_BUILD_PROVENANCE_SCHEMA, prov_action)],
            [],
            [(artifact_locator, envelope, WHEEL_BOUNDARY_REPORT_SCHEMA, envelope["verified_at_utc"]), (prov_loc, prov_env, WHEEL_BUILD_PROVENANCE_SCHEMA, prov_env["built_at_utc"])],
            lambda: require(_read_nonempty_regular_file(whl_file, "wheel_path")[1] == wheel_bytes, "wheel_path mutated"),
        )

    def _admit_mcp_artifact(
        self,
        artifact_locator: dict[str, Any],
        envelope: dict[str, Any],
        auth: _D4AuthorityContext,
        *,
        runner: IsolatedWheelProbeRunner,
        wheel_path: Path | None,
        seccomp_profile: dict[str, Any] | None,
    ) -> tuple[dict[str, Any], list[tuple[dict[str, Any], str, str]], list[dict[str, Any]], list[tuple[dict[str, Any], dict[str, Any], str, str]], Callable[[], None] | None]:
        whl_file, wheel_bytes = _read_nonempty_regular_file(_require_path(wheel_path, "wheel_path"), "wheel_path")
        require(isinstance(seccomp_profile, dict), "seccomp_profile is required for mcp_rejection_matrix_report/v1 verification")
        _validate_mcp_envelope_structure(envelope)
        _enforce_pinned_run_context_locator(envelope, auth.pinned_run_ctx_loc, MCP_REJECTION_REPORT_SCHEMA)
        signer, action = self._verify_signer_authority(
            envelope, schema=MCP_REJECTION_REPORT_SCHEMA, event_time_utc=envelope["executed_at_utc"],
            config=auth.config, reg=auth.reg, clock=auth.clock, chain_registries_by_epoch=auth.chain_registries_by_epoch,
        )
        sbx_loc = envelope["sealed_sandbox_profile_locator"]
        sbx_env = _validate_sandbox_envelope_structure(load_object(self.store, sbx_loc, SANDBOX_PROFILE_SCHEMA))
        _enforce_pinned_run_context_locator(sbx_env, auth.pinned_run_ctx_loc, SANDBOX_PROFILE_SCHEMA)
        sbx_signer, sbx_action = self._verify_signer_authority(
            sbx_env, schema=SANDBOX_PROFILE_SCHEMA, event_time_utc=sbx_env["issued_at_utc"],
            config=auth.config, reg=auth.reg, clock=auth.clock, chain_registries_by_epoch=auth.chain_registries_by_epoch,
        )
        validity(sbx_env["validity"], envelope["executed_at_utc"])
        validity(sbx_env["validity"], auth.clock.lower_utc)
        validity(sbx_env["validity"], auth.clock.upper_utc)
        verify_sealed_sandbox_profile(sbx_env, seccomp_profile=seccomp_profile)  # type: ignore[arg-type]
        with _disposable_wheel_path(wheel_bytes) as disposable_whl:
            material = verify_mcp_rejection_matrix_report(envelope, wheel_path=disposable_whl, probe_runner=runner)
        require(material["wheel_digest"] == digest(wheel_bytes), "mcp_rejection_matrix_report wheel_digest mismatch against captured wheel_bytes")
        return (
            material,
            [(signer, MCP_REJECTION_REPORT_SCHEMA, action), (sbx_signer, SANDBOX_PROFILE_SCHEMA, sbx_action)],
            [sbx_env["validity"]],
            [(artifact_locator, envelope, MCP_REJECTION_REPORT_SCHEMA, envelope["executed_at_utc"]), (sbx_loc, sbx_env, SANDBOX_PROFILE_SCHEMA, sbx_env["issued_at_utc"])],
            lambda: require(_read_nonempty_regular_file(whl_file, "wheel_path")[1] == wheel_bytes, "wheel_path mutated"),
        )

    def _authenticate_six_convergence_constituents(
        self,
        envelope: dict[str, Any],
        validated_conv_payload: dict[str, Any],
        auth: _D4AuthorityContext,
        top_signer_req: tuple[dict[str, Any], str, str],
        artifact_locator: dict[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any], SnapshotStore, list[tuple[dict[str, Any], str, str]], list[tuple[dict[str, Any], dict[str, Any], str, str]]]:
        sbx_env, prov_env, bound_env, mcp_env, neg_env, cert7a_env = _load_six_convergence_constituents(
            self.store, validated_conv_payload
        )
        prov_loc = bound_env["wheel_build_provenance_locator"]
        constituent_specs = (
            (validated_conv_payload["sealed_sandbox_profile_locator"], sbx_env, SANDBOX_PROFILE_SCHEMA, sbx_env["issued_at_utc"]),
            (prov_loc, prov_env, WHEEL_BUILD_PROVENANCE_SCHEMA, prov_env["built_at_utc"]),
            (validated_conv_payload["wheel_boundary_report_locator"], bound_env, WHEEL_BOUNDARY_REPORT_SCHEMA, bound_env["verified_at_utc"]),
            (validated_conv_payload["mcp_rejection_matrix_report_locator"], mcp_env, MCP_REJECTION_REPORT_SCHEMA, mcp_env["executed_at_utc"]),
            (validated_conv_payload["negative_security_test_report_locator"], neg_env, NEGATIVE_SECURITY_SCHEMA, neg_env["executed_at_utc"]),
            (validated_conv_payload["certification_7a_record_locator"], cert7a_env, CERTIFICATION_7A_SCHEMA, cert7a_env["certified_at_utc"]),
        )
        signer_reqs = [top_signer_req]
        admitted = [(artifact_locator, envelope, GOV1_CONVERGENCE_SCHEMA, envelope["converged_at_utc"])]
        signers_by_schema: dict[str, dict[str, Any]] = {}
        for c_loc, c_env, c_schema, c_time in constituent_specs:
            _enforce_pinned_run_context_locator(c_env, auth.pinned_run_ctx_loc, c_schema)
            c_signer, c_act = self._verify_signer_authority(
                c_env, schema=c_schema, event_time_utc=c_time,
                config=auth.config, reg=auth.reg, clock=auth.clock, chain_registries_by_epoch=auth.chain_registries_by_epoch,
            )
            signers_by_schema[c_schema] = c_signer
            signer_reqs.append((c_signer, c_schema, c_act))
            admitted.append((c_loc, c_env, c_schema, c_time))
        validity(sbx_env["validity"], auth.clock.lower_utc)
        validity(sbx_env["validity"], auth.clock.upper_utc)
        neg_s, cert_s = signers_by_schema[NEGATIVE_SECURITY_SCHEMA], signers_by_schema[CERTIFICATION_7A_SCHEMA]
        require(
            cert_s["principal"] != neg_s["principal"] and cert_s["key_id"] != neg_s["key_id"],
            "independent_7a_verifier must have distinct principal and key_id from 7a_verifier",
        )
        leaf_reqs, leaf_admitted, leaf_objs = _authenticate_d4_7a_leaf_envelopes(
            self, cert7a_env, config=auth.config, reg=auth.reg, clock=auth.clock, chain_registries_by_epoch=auth.chain_registries_by_epoch
        )
        snap_store = SnapshotStore([envelope, sbx_env, prov_env, bound_env, mcp_env, neg_env, cert7a_env, *leaf_objs])
        return sbx_env, prov_env, bound_env, mcp_env, snap_store, [*signer_reqs, *leaf_reqs], [*admitted, *leaf_admitted]

    def _admit_convergence_artifact(
        self, artifact_locator: dict[str, Any], envelope: dict[str, Any], auth: _D4AuthorityContext, *,
        runner: IsolatedWheelProbeRunner, seccomp_profile: dict[str, Any] | None, wheel_path: Path | None,
        repo_root: Path | None, backend_wheel_dir: Path | None, site_packages_dir: Path | None,
    ) -> tuple[dict[str, Any], list[tuple[dict[str, Any], str, str]], list[dict[str, Any]], list[tuple[dict[str, Any], dict[str, Any], str, str]], Callable[[], None] | None]:
        exact_fields(envelope, _GOV1_CONVERGENCE_ENVELOPE_FIELDS, "gov1_convergence_record_envelope")
        _require_exact_str(envelope["$schema"], GOV1_CONVERGENCE_SCHEMA, "gov1_convergence_record.$schema")
        _verify_envelope_integrity(envelope, label="gov1_convergence_record")
        _enforce_pinned_run_context_locator(envelope, auth.pinned_run_ctx_loc, GOV1_CONVERGENCE_SCHEMA)
        signer, action = self._verify_signer_authority(
            envelope, schema=GOV1_CONVERGENCE_SCHEMA, event_time_utc=envelope["converged_at_utc"],
            config=auth.config, reg=auth.reg, clock=auth.clock, chain_registries_by_epoch=auth.chain_registries_by_epoch,
        )
        conv_payload = {k: copy.deepcopy(v) for k, v in envelope.items() if k not in {"$schema", "integrity"}}
        _validate_gov1_convergence_structural_fields(conv_payload, store=None)
        if self.pr3_verifier is None:
            raise ValueError("gov1_convergence_record/v1: fail-closed in Etapa 8; Pr3SevenAConstituentVerifier (PR 3 / Etapa 10) is absent")
        cert7a = _cert7a_mod()
        v_pr3 = _require_exact_seven_a_verifier(self.pr3_verifier, cert7a)
        require(isinstance(seccomp_profile, dict), "seccomp_profile is required for gov1_convergence_record/v1 verification")
        whl_file, wheel_bytes = _read_nonempty_regular_file(_require_path(wheel_path, "wheel_path"), "wheel_path")
        corpus_file, corpus_bytes = _read_nonempty_regular_file(_require_path(self.corpus_path, "corpus_path"), "corpus_path")
        repo_dir = _require_path(repo_root, "repo_root")
        validated = _validate_gov1_convergence_structural_fields(conv_payload, store=self.store)
        sbx_env, prov_env, bound_env, mcp_env, snap_store, signer_reqs, admitted = self._authenticate_six_convergence_constituents(
            envelope, validated, auth, (signer, GOV1_CONVERGENCE_SCHEMA, action), artifact_locator
        )
        git_blobs = cert7a.resolve_7a_smart_ads_git_blobs(repo_dir, validated["source_commit_sha"])
        require(corpus_bytes == git_blobs.get(cert7a.CORPUS_GIT_PATH[1]), "corpus_path bytes disagree with Git blob at source_commit_sha")
        d26_blobs = gov1_7a_runner.resolve_pinned_pipeboard_d26_blobs(legacy_repo=self.legacy_repo, legacy_blobs_dir=self.legacy_blobs_dir)
        _, _, prov_res, _, _ = _run_disposable_stage7_material_handoff(
            wheel_bytes=wheel_bytes, seccomp_profile=seccomp_profile, sandbox_obj=sbx_env, prov_obj=prov_env,  # type: ignore[arg-type]
            bound_obj=bound_env, mcp_obj=mcp_env, repo_dir=repo_dir, backend_wheel_dir=backend_wheel_dir,
            site_packages_dir=site_packages_dir, probe_runner=runner,
        )
        cert7a.SevenAConstituentVerifier.verify_bound_preflight_inputs(
            v_pr3, wheel_bytes=wheel_bytes, corpus_bytes=corpus_bytes, stripped_provenance_payload=prov_res["payload"],
            resolved_git_blobs=git_blobs, resolved_d26_blobs=d26_blobs,
        )
        _enforce_pr3_verifier_gate(payload=validated, store=snap_store, pr3_verifier=v_pr3)
        material = {"schema": GOV1_CONVERGENCE_SCHEMA, "convergence_status": "PASS", "wheel_digest": validated["wheel_digest"], "payload": validated}
        reload_fn = lambda: _reload_and_verify_d4_external_7a_inputs(
            wheel_path=whl_file, expected_wheel_bytes=wheel_bytes, corpus_path=corpus_file, expected_corpus_bytes=corpus_bytes,
            repo_dir=repo_dir, source_commit_sha=validated["source_commit_sha"], expected_git_blobs=git_blobs,
            legacy_repo=self.legacy_repo, legacy_blobs_dir=self.legacy_blobs_dir, expected_d26_blobs=d26_blobs,
        )
        return material, signer_reqs, [sbx_env["validity"]], admitted, reload_fn

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
        require(schema in _DIRECT_ADMIT_GOV1_SCHEMAS, f"unsupported GOV1 artifact_type {schema!r}")
        runner = None if schema == SANDBOX_PROFILE_SCHEMA else self._require_os_isolated_probe_runner()
        inv_loc = self._resolve_inventory_locator(inventory_locator)
        auth = self._bootstrap_d4_authority(inv_loc)
        envelope = load_object(self.store, artifact_locator, schema)
        if schema == SANDBOX_PROFILE_SCHEMA:
            material, reqs, sbx_vals, admitted, reload_fn = self._admit_sandbox_artifact(artifact_locator, envelope, auth, seccomp_profile)
        elif schema == WHEEL_BUILD_PROVENANCE_SCHEMA:
            material, reqs, sbx_vals, admitted, reload_fn = self._admit_provenance_artifact(artifact_locator, envelope, auth, runner=runner, wheel_path=wheel_path, repo_root=repo_root, backend_wheel_dir=backend_wheel_dir, site_packages_dir=site_packages_dir)  # type: ignore[arg-type]
        elif schema == WHEEL_BOUNDARY_REPORT_SCHEMA:
            material, reqs, sbx_vals, admitted, reload_fn = self._admit_boundary_artifact(artifact_locator, envelope, auth, runner=runner, wheel_path=wheel_path, repo_root=repo_root, backend_wheel_dir=backend_wheel_dir, site_packages_dir=site_packages_dir)  # type: ignore[arg-type]
        elif schema == MCP_REJECTION_REPORT_SCHEMA:
            material, reqs, sbx_vals, admitted, reload_fn = self._admit_mcp_artifact(artifact_locator, envelope, auth, runner=runner, wheel_path=wheel_path, seccomp_profile=seccomp_profile)  # type: ignore[arg-type]
        else:
            material, reqs, sbx_vals, admitted, reload_fn = self._admit_convergence_artifact(artifact_locator, envelope, auth, runner=runner, seccomp_profile=seccomp_profile, wheel_path=wheel_path, repo_root=repo_root, backend_wheel_dir=backend_wheel_dir, site_packages_dir=site_packages_dir)  # type: ignore[arg-type]
        new_floor = self._commit_cas_and_observe_final(
            auth, signer_requirements=reqs, active_sandbox_validities=sbx_vals,
            admitted_envelopes=admitted, post_cas_reload_fn=reload_fn,
        )
        return {
            "verification_status": "VERIFIED", "schema": schema,
            "artifact_locator": copy.deepcopy(artifact_locator), "inventory_locator": copy.deepcopy(inv_loc),
            "head_locator": copy.deepcopy(auth.head_locator), "authority_epoch": auth.head["epoch"],
            "effect_authorized": False, "historical_prerequisites": auth.prerequisites["predecessor_signatures_and_links"],
            "floor_before": {"epoch": auth.floor.epoch, "head_digest": auth.floor.head_digest},
            "floor_after": {"epoch": new_floor.epoch, "head_digest": new_floor.head_digest},
            "material": material,
        }

    def _authenticate_etapa7_bundle_envelopes(
        self,
        auth: _D4AuthorityContext,
        *,
        sandbox_profile_locator: dict[str, Any],
        wheel_provenance_locator: dict[str, Any],
        wheel_boundary_report_locator: dict[str, Any],
        mcp_rejection_report_locator: dict[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any], list[tuple[dict[str, Any], str, str]], list[tuple[dict[str, Any], dict[str, Any], str, str]]]:
        sbx_env = _validate_sandbox_envelope_structure(load_object(self.store, sandbox_profile_locator, SANDBOX_PROFILE_SCHEMA))
        prov_env = _validate_provenance_envelope_structure(load_object(self.store, wheel_provenance_locator, WHEEL_BUILD_PROVENANCE_SCHEMA))
        bound_env = _validate_boundary_envelope_structure(load_object(self.store, wheel_boundary_report_locator, WHEEL_BOUNDARY_REPORT_SCHEMA))
        mcp_env = _validate_mcp_envelope_structure(load_object(self.store, mcp_rejection_report_locator, MCP_REJECTION_REPORT_SCHEMA))
        specs = (
            (sandbox_profile_locator, sbx_env, SANDBOX_PROFILE_SCHEMA, sbx_env["issued_at_utc"]),
            (wheel_provenance_locator, prov_env, WHEEL_BUILD_PROVENANCE_SCHEMA, prov_env["built_at_utc"]),
            (wheel_boundary_report_locator, bound_env, WHEEL_BOUNDARY_REPORT_SCHEMA, bound_env["verified_at_utc"]),
            (mcp_rejection_report_locator, mcp_env, MCP_REJECTION_REPORT_SCHEMA, mcp_env["executed_at_utc"]),
        )
        reqs: list[tuple[dict[str, Any], str, str]] = []
        admitted: list[tuple[dict[str, Any], dict[str, Any], str, str]] = []
        for loc, env, schema, ev_t in specs:
            _enforce_pinned_run_context_locator(env, auth.pinned_run_ctx_loc, schema)
            s, act = self._verify_signer_authority(
                env, schema=schema, event_time_utc=ev_t,
                config=auth.config, reg=auth.reg, clock=auth.clock, chain_registries_by_epoch=auth.chain_registries_by_epoch,
            )
            reqs.append((s, schema, act))
            admitted.append((loc, env, schema, ev_t))
        validity(sbx_env["validity"], auth.clock.lower_utc)
        validity(sbx_env["validity"], auth.clock.upper_utc)
        require(canonicalize(bound_env["wheel_build_provenance_locator"]) == canonicalize(wheel_provenance_locator), "wheel_boundary_report.wheel_build_provenance_locator mismatch")
        require(canonicalize(mcp_env["sealed_sandbox_profile_locator"]) == canonicalize(sandbox_profile_locator), "mcp_rejection_matrix_report.sealed_sandbox_profile_locator mismatch")
        _enforce_etapa7_cross_binding_matrix(
            sandbox_payload=_extract_artifact_payload_for_binding(sbx_env, expected_schema=SANDBOX_PROFILE_SCHEMA, mode="envelope", label="sbx"),
            provenance_payload=_extract_artifact_payload_for_binding(prov_env, expected_schema=WHEEL_BUILD_PROVENANCE_SCHEMA, mode="envelope", label="prov"),
            boundary_payload=_extract_artifact_payload_for_binding(bound_env, expected_schema=WHEEL_BOUNDARY_REPORT_SCHEMA, mode="envelope", label="bound"),
            mcp_payload=_extract_artifact_payload_for_binding(mcp_env, expected_schema=MCP_REJECTION_REPORT_SCHEMA, mode="envelope", label="mcp"),
        )
        return sbx_env, prov_env, bound_env, mcp_env, reqs, admitted

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
        runner = self._require_os_isolated_probe_runner()
        if not isinstance(seccomp_profile, dict):
            raise ValueError("seccomp_profile: expected JSON object")
        whl_file, wheel_bytes = _read_nonempty_regular_file(_require_path(wheel_path, "wheel_path"), "wheel_path")
        repo_dir = _require_path(repo_root, "repo_root")
        inv_loc = self._resolve_inventory_locator(inventory_locator)
        auth = self._bootstrap_d4_authority(inv_loc)
        sbx_env, prov_env, bound_env, mcp_env, reqs, admitted = self._authenticate_etapa7_bundle_envelopes(
            auth, sandbox_profile_locator=sandbox_profile_locator, wheel_provenance_locator=wheel_provenance_locator,
            wheel_boundary_report_locator=wheel_boundary_report_locator, mcp_rejection_report_locator=mcp_rejection_report_locator,
        )
        seccomp_digest, sbx_res, prov_res, bound_res, mcp_res = _run_disposable_stage7_material_handoff(
            wheel_bytes=wheel_bytes, seccomp_profile=seccomp_profile, sandbox_obj=sbx_env,
            prov_obj=prov_env, bound_obj=bound_env, mcp_obj=mcp_env, repo_dir=repo_dir,
            backend_wheel_dir=backend_wheel_dir, site_packages_dir=site_packages_dir, probe_runner=runner,
        )
        new_floor = self._commit_cas_and_observe_final(
            auth, signer_requirements=reqs, active_sandbox_validities=[sbx_env["validity"]], admitted_envelopes=admitted,
            post_cas_reload_fn=lambda: require(_read_nonempty_regular_file(whl_file, "wheel_path")[1] == wheel_bytes, "wheel_path mutated"),
        )
        return {
            "verification_status": "VERIFIED", "authority_epoch": auth.head["epoch"], "effect_authorized": False,
            "historical_prerequisites": auth.prerequisites["predecessor_signatures_and_links"],
            "floor_before": {"epoch": auth.floor.epoch, "head_digest": auth.floor.head_digest},
            "floor_after": {"epoch": new_floor.epoch, "head_digest": new_floor.head_digest},
            "seccomp_profile_digest": seccomp_digest, "sandbox_result": sbx_res,
            "provenance_result": prov_res, "boundary_result": bound_res, "mcp_result": mcp_res,
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
    "Gov1InstallationPins",
    "Pr3SevenAConstituentVerifier",
    "SnapshotStore",
    "build_gov1_convergence_record_candidate",
    "build_gov1_convergence_record_envelope",
    "verify_gov1_convergence_candidate",
    "verify_gov1_convergence_record",
    "verify_pr1_gov1_convergence",
]
