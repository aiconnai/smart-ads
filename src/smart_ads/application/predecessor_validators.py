"""Pure predecessor, decomposition tip, Git parent ancestry, and canonical build-chain validators (ADR-0001 §§9.2, 10, 12.6)."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
import hashlib
import re
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Final, TypeVar

from smart_ads.application.curation_pipeline import verify_algorithm_provenance_identity
from smart_ads.contracts.effects import _safe_int, _strict_id, _strict_str, _typed_locator, validate_cell_object_ref
from smart_ads.contracts.git_provenance import (
    GitArtifactProvenance,
    _validate_relative_posix_path,
    _validate_repository_slug,
)
from smart_ads.contracts.jcs import (
    ADR_P1_DOMAIN_PREFIXES,
    ArtifactLocator,
    P1Integrity,
    canonicalize_jcs,
    jcs_sha256,
    p1_content_digest,
    self_digest_jcs_sha256,
    sort_utf8_strings,
)
from smart_ads.contracts.operational_evidence import AlgorithmProvenanceIdentity
from smart_ads.contracts.scalars import (
    ClosedValidationError,
    require_exact_keys,
    require_mapping,
    validate_envelope_timestamp_utc,
    validate_hex40,
    validate_opaque_ref,
    validate_sha256_prefixed,
)
from smart_ads.contracts.seam import (
    GitParentEdge,
    GitReleaseIdentity,
    LegacyBaselineIdentity,
    WheelObjectLocator,
    _validate_parent_edge_chain,
)
from smart_ads.ports.consumer import P1SignatureVerifierPort
from smart_ads.ports.storage import CellObjectStorePort

if TYPE_CHECKING:
    from smart_ads.reconciliation.certification_7a import Certification7ARecord

_T = TypeVar("_T")

_RUN_CONTEXT_SCHEMA: Final[str] = "smart_ads/migration_run_context/v1"
_PROTECTED_MERGE_SCHEMA: Final[str] = "smart_ads/protected_merge_evidence/v1"
_DECOMP_MANIFEST_SCHEMA: Final[str] = "smart_ads/decomposition_manifest/v1"
_DECOMP_HEAD_SCHEMA: Final[str] = "smart_ads/decomposition_manifest_head/v1"
_DEPLOYMENT_RESULT_SCHEMA: Final[str] = "smart_ads/deployment_config_execution_result/v1"
_GATE2_RECEIPT_SCHEMA: Final[str] = "smart_ads/gate2_approval_receipt/v1"
_GATE2_POLICY_SCHEMA: Final[str] = "smart_ads/gate2_authority_policy/v1"
_WHEEL_PROVENANCE_SCHEMA: Final[str] = "smart_ads/wheel_build_provenance/v1"
_WHEEL_BOUNDARY_SCHEMA: Final[str] = "smart_ads/wheel_boundary_report/v1"
_CERTIFICATION_7A_SCHEMA: Final[str] = "smart_ads/certification_7a_record/v1"
_GOV1_CONVERGENCE_SCHEMA: Final[str] = "smart_ads/gov1_convergence_record/v1"
_MCP_REJECTION_SCHEMA: Final[str] = "smart_ads/mcp_rejection_matrix_report/v1"

_ADR_REL_PATH: Final[str] = "docs/adr/ADR-0001-smart-ads-read-gateway.md"
_LEGACY_REPO: Final[str] = "mbras-tech/mbras-campaigns"
_LEGACY_COMMIT: Final[str] = "d26c73d8508c7c3d43161fe36a80c44a46bf0f2d"
_LEGACY_TREE: Final[str] = "68ff6d6dbd6d7ecaafa3bca7d5de85a54d705798"
_PRE_SEAM_LEGACY_COMMITS: Final[frozenset[str]] = frozenset({
    "d26c73d8508c7c3d43161fe36a80c44a46bf0f2d",
    "25cc756c5f46db9ee67f17844196c4301c977ad6",
    "b4d4537f4df56248df872c51ab3cd7e3d1aed098",
    "020d3e0c4a48ef9f059645eeb07968f68499c43b",
    "a26f055dc7f9a4847310f21d34ba019da87bcca6",
})
_CANONICAL_REPO: Final[str] = "aiconnai/smart-ads"
_CONSUMER_REPO: Final[str] = "limaronaldo/hermes-ronaldo"
_POS_DEC_BYTES_RE: Final[re.Pattern[bytes]] = re.compile(rb"\A[1-9][0-9]*\Z")

PREDECESSOR_P1_DOMAIN_PREFIXES: Final[Mapping[str, str]] = MappingProxyType({
    _RUN_CONTEXT_SCHEMA: "SMART-ADS:RUN-CONTEXT:V1\n",
    _PROTECTED_MERGE_SCHEMA: "SMART-ADS:PROTECTED-MERGE:V1\n",
    _DECOMP_MANIFEST_SCHEMA: "SMART-ADS:DECOMPOSITION:V1\n",
    _DECOMP_HEAD_SCHEMA: "SMART-ADS:DECOMPOSITION-HEAD:V1\n",
    _DEPLOYMENT_RESULT_SCHEMA: "SMART-ADS:DEPLOYMENT-RESULT:V1\n",
})

_RUN_CTX_CORE_KEYS: Final[frozenset[str]] = frozenset(
    "$schema gate2_receipt_locator approved_adr_git_identity legacy_source_identity "
    "tenant_ref cell_ref run_id created_at_utc".split()
)
_MERGE_EV_CORE_KEYS: Final[frozenset[str]] = frozenset(
    "$schema repository protected_branch pr_number reviewed_head_sha protected_merge_sha "
    "adr_git_identity required_ci_results exact_head_review_evidence branch_protection_policy".split()
)
_DECOMP_HEAD_CORE_KEYS: Final[frozenset[str]] = frozenset(
    "$schema repository commit_sha source_tree_oid scope_digest head_epoch active_manifest_locator "
    "active_manifest_digest previous_head_locator previous_head_digest update_kind updated_at_utc".split()
)
_DECOMP_MANIFEST_CORE_KEYS: Final[frozenset[str]] = frozenset(
    "$schema manifest_digest generated_at supersedes_manifest_locator supersedes_digest "
    "correction_reason source_inventory coverage_assertion entries".split()
)
_SOURCE_INVENTORY_KEYS: Final[frozenset[str]] = frozenset(
    "$schema repository commit_sha inventory_scope declared_paths declared_paths_digest inventory_digest items".split()
)
_COVERAGE_ASSERTION_KEYS: Final[frozenset[str]] = frozenset(
    "inventory_item_count entry_count assigned_item_count unassigned_item_count duplicate_assignment_count conflict_count".split()
)
_WHEEL_PROVENANCE_CORE_KEYS: Final[frozenset[str]] = frozenset(
    "$schema migration_run_context_locator build_run_id built_at_utc repository source_commit_sha "
    "source_tree_oid source_date_epoch python_abi_tag build_backend build_backend_version "
    "build_backend_digest pyproject_sha256 uv_lock_sha256 schema_bundle_digest wheel wheel_digest".split()
)
_WHEEL_BOUNDARY_CORE_KEYS: Final[frozenset[str]] = frozenset(
    "$schema migration_run_context_locator build_run_id verified_at_utc repository source_commit_sha "
    "wheel_digest build_backend_digest schema_bundle_digest sorted_record_entries sorted_record_digest "
    "archive_allowlist_passed ast_boundary_scan_passed isolated_venv_import_passed packaged_modules wheel_build_provenance_locator".split()
)
_GOV1_CONVERGENCE_CORE_KEYS: Final[frozenset[str]] = frozenset(
    "$schema migration_run_context_locator wheel_boundary_report_locator sealed_sandbox_profile_locator "
    "negative_security_test_report_locator mcp_rejection_matrix_report_locator certification_7a_record_locator "
    "build_run_id converged_at_utc source_commit_sha wheel_digest build_backend_digest schema_bundle_digest convergence_status".split()
)
_DEPLOYMENT_RESULT_CORE_KEYS: Final[frozenset[str]] = frozenset(
    "$schema migration_run_context_locator consumer_repository consumer_commit_sha "
    "deployed_release_id runtime_binary_sha256 verification_status verified_at_utc".split()
)
_ADR_GIT_IDENTITY_KEYS: Final[frozenset[str]] = frozenset(
    {"repository", "commit_sha", "path", "git_blob_oid", "file_content_sha256"}
)


def _check_store_and_verifier(
    store: object, signature_verifier: object, require_signed: object
) -> tuple[CellObjectStorePort, P1SignatureVerifierPort | None, bool]:
    if not isinstance(store, CellObjectStorePort):
        raise ClosedValidationError(f"store: expected CellObjectStorePort, got {type(store).__name__}")
    if type(require_signed) is not bool:
        raise ClosedValidationError("require_signed: expected bool")
    if require_signed and signature_verifier is None:
        raise ClosedValidationError("signature_verifier: P1SignatureVerifierPort required when require_signed=True")
    if signature_verifier is not None and (
        not isinstance(signature_verifier, P1SignatureVerifierPort)
        or not callable(getattr(signature_verifier, "verify_p1_envelope_signature", None))
    ):
        raise ClosedValidationError("signature_verifier: expected P1SignatureVerifierPort")
    return store, signature_verifier, require_signed


def _domain_for_schema(schema_id: str) -> str:
    domain = ADR_P1_DOMAIN_PREFIXES.get(schema_id) or PREDECESSOR_P1_DOMAIN_PREFIXES.get(schema_id)
    if domain is None:
        raise ClosedValidationError(f"unprofiled P1 schema {schema_id!r}")
    return domain


def _invoke_sig_verifier(
    verifier: P1SignatureVerifierPort, *, envelope: Mapping[str, Any], domain_prefix: str, store: CellObjectStorePort
) -> None:
    try:
        verifier.verify_p1_envelope_signature(envelope=envelope, domain_prefix=domain_prefix, store=store)
    except ClosedValidationError:
        raise
    except Exception as exc:
        raise ClosedValidationError(f"P1 signature verification failed: {exc}") from exc


def _load_verified_p1_dict(
    store: CellObjectStorePort,
    locator: ArtifactLocator,
    *,
    expected_schema: str,
    core_keys: frozenset[str] | None,
    signature_verifier: P1SignatureVerifierPort | None,
    require_signed: bool,
    label: str,
) -> dict[str, Any]:
    checked_store, checked_ver, checked_req = _check_store_and_verifier(store, signature_verifier, require_signed)
    checked_loc = _typed_locator(locator, field_name=label, expected_type=expected_schema)
    try:
        raw_dict = checked_store.get_json_artifact(checked_loc)
    except ClosedValidationError:
        raise
    except Exception as exc:
        raise ClosedValidationError(f"{label}: failed to resolve artifact: {exc}") from exc
    m = require_mapping(raw_dict, label=label)
    if core_keys is not None:
        exp_keys = (core_keys | {"integrity"}) if (checked_req or "integrity" in m) else core_keys
        require_exact_keys(m, exp_keys, label=label)
    if type(m.get("$schema")) is not str or m["$schema"] != expected_schema:
        raise ClosedValidationError(f"{label}.$schema: expected {expected_schema!r}")
    if ArtifactLocator.for_canonical_bytes(expected_schema, canonicalize_jcs(m)) != checked_loc:
        raise ClosedValidationError(f"{label}: Layer-3 canonical JCS digest mismatch against locator")
    if checked_req or "integrity" in m:
        integ = P1Integrity.from_dict(m.get("integrity"), require_signed=checked_req)
        if integ.is_signed and integ.content_digest != p1_content_digest(m):
            raise ClosedValidationError(f"{label}.integrity.content_digest: Layer-2 preimage mismatch")
        if checked_ver is not None and (checked_req or integ.is_signed):
            _invoke_sig_verifier(checked_ver, envelope=m, domain_prefix=_domain_for_schema(expected_schema), store=checked_store)
    return dict(m)


def _load_verified_p1_model(
    store: CellObjectStorePort,
    model_or_locator: _T | ArtifactLocator,
    cls: type[_T],
    *,
    signature_verifier: P1SignatureVerifierPort | None,
    require_signed: bool,
    label: str,
) -> _T:
    checked_store, checked_ver, checked_req = _check_store_and_verifier(store, signature_verifier, require_signed)
    schema_id: str = cls.SCHEMA  # type: ignore[attr-defined]
    if type(model_or_locator) is ArtifactLocator:
        raw_dict = _load_verified_p1_dict(
            checked_store, model_or_locator, expected_schema=schema_id, core_keys=None,
            signature_verifier=checked_ver, require_signed=checked_req, label=label,
        )
        parsed: _T = cls.from_dict(raw_dict, require_signed=checked_req)  # type: ignore[attr-defined]
        if canonicalize_jcs(parsed.to_dict()) != canonicalize_jcs(raw_dict):  # type: ignore[attr-defined]
            raise ClosedValidationError(f"{label}: parsed canonical bytes diverged")
        return parsed
    if type(model_or_locator) is not cls:
        raise ClosedValidationError(f"{label}: expected {cls.__name__} or ArtifactLocator")
    raw_in = model_or_locator.to_dict()  # type: ignore[attr-defined]
    fresh: _T = cls.from_dict(raw_in, require_signed=checked_req)  # type: ignore[attr-defined]
    if fresh != model_or_locator:
        raise ClosedValidationError(f"{label}: corrupted in-memory {cls.__name__}")
    loc = ArtifactLocator.for_canonical_bytes(schema_id, canonicalize_jcs(raw_in))
    if checked_store.has_object(loc.object_ref):
        _load_verified_p1_dict(
            checked_store, loc, expected_schema=schema_id, core_keys=None,
            signature_verifier=checked_ver, require_signed=checked_req, label=label,
        )
    elif checked_ver is not None and fresh.integrity is not None and (checked_req or fresh.integrity.is_signed):  # type: ignore[attr-defined]
        _invoke_sig_verifier(checked_ver, envelope=raw_in, domain_prefix=_domain_for_schema(schema_id), store=checked_store)
    return fresh


def _verify_algorithm_with_sig(
    identity: AlgorithmProvenanceIdentity,
    *,
    expected_schema_id: str,
    store: CellObjectStorePort,
    signature_verifier: P1SignatureVerifierPort | None,
    require_signed: bool,
    label: str,
) -> AlgorithmProvenanceIdentity:
    if type(identity) is not AlgorithmProvenanceIdentity:
        raise ClosedValidationError(f"{label}: expected AlgorithmProvenanceIdentity")
    fresh_id = AlgorithmProvenanceIdentity.from_dict(identity.to_dict())
    if fresh_id != identity or fresh_id.schema_id != expected_schema_id:
        raise ClosedValidationError(f"{label}.schema_id: expected {expected_schema_id!r}")
    git_prov = _load_verified_p1_model(
        store, fresh_id.git_artifact_provenance_locator, GitArtifactProvenance,
        signature_verifier=signature_verifier, require_signed=require_signed, label=f"{label}.git_provenance",
    )
    verify_algorithm_provenance_identity(fresh_id, git_prov)
    return fresh_id


def _validate_adr_git_identity_dict(data: object, *, label: str) -> dict[str, str]:
    m = require_exact_keys(data, _ADR_GIT_IDENTITY_KEYS, label=label)
    repo = _validate_repository_slug(m["repository"], field_name=f"{label}.repository")
    c_sha = validate_hex40(_strict_str(m["commit_sha"], field_name=f"{label}.commit_sha"), field_name=f"{label}.commit_sha")
    if _strict_str(m["path"], field_name=f"{label}.path") != _ADR_REL_PATH:
        raise ClosedValidationError(f"{label}.path: must equal {_ADR_REL_PATH!r}")
    blob = validate_hex40(_strict_str(m["git_blob_oid"], field_name=f"{label}.git_blob_oid"), field_name=f"{label}.git_blob_oid")
    f_sha = validate_sha256_prefixed(_strict_str(m["file_content_sha256"], field_name=f"{label}.file_content_sha256"), field_name=f"{label}.file_content_sha256")
    return {"repository": repo, "commit_sha": c_sha, "path": _ADR_REL_PATH, "git_blob_oid": blob, "file_content_sha256": f_sha}


def verify_stored_migration_run_context(
    store: CellObjectStorePort,
    locator: ArtifactLocator,
    *,
    signature_verifier: P1SignatureVerifierPort | None = None,
    require_signed: bool = True,
) -> dict[str, Any]:
    """Verify stored `smart_ads/migration_run_context/v1` P1 envelope and baseline pins."""
    raw = _load_verified_p1_dict(
        store, locator, expected_schema=_RUN_CONTEXT_SCHEMA, core_keys=_RUN_CTX_CORE_KEYS,
        signature_verifier=signature_verifier, require_signed=require_signed, label="migration_run_context",
    )
    ArtifactLocator.from_dict(raw["gate2_receipt_locator"], expected_type=_GATE2_RECEIPT_SCHEMA)
    _validate_adr_git_identity_dict(raw["approved_adr_git_identity"], label="migration_run_context.approved_adr_git_identity")
    leg = require_exact_keys(raw["legacy_source_identity"], frozenset({"repository", "commit_sha"}), label="migration_run_context.legacy_source_identity")
    if _strict_str(leg["repository"], field_name="legacy_source_identity.repository") != _LEGACY_REPO:
        raise ClosedValidationError("migration_run_context.legacy_source_identity.repository: mismatch")
    if _strict_str(leg["commit_sha"], field_name="legacy_source_identity.commit_sha") != _LEGACY_COMMIT:
        raise ClosedValidationError("migration_run_context.legacy_source_identity.commit_sha: mismatch")
    validate_opaque_ref(_strict_str(raw["tenant_ref"], field_name="tenant_ref"), field_name="tenant_ref", expected_prefix="tenant")
    validate_opaque_ref(_strict_str(raw["cell_ref"], field_name="cell_ref"), field_name="cell_ref", expected_prefix="cell")
    validate_opaque_ref(_strict_str(raw["run_id"], field_name="run_id"), field_name="run_id", expected_prefix="run")
    validate_envelope_timestamp_utc(raw["created_at_utc"], field_name="migration_run_context.created_at_utc")
    return raw


def _validate_ci_and_review_lists(
    ci_raw: object, rev_raw: object, *, expected_reviewed_head_sha: str
) -> None:
    if type(ci_raw) is not list or not ci_raw:
        raise ClosedValidationError("protected_merge_evidence.required_ci_results: expected non-empty list")
    for idx, entry in enumerate(ci_raw):
        cm = require_mapping(entry, label=f"required_ci_results[{idx}]")
        chk = cm.get("check") if "check" in cm else (cm.get("name") if "name" in cm else cm.get("check_name"))
        _strict_id(chk, field_name=f"required_ci_results[{idx}].check")
        statuses = [cm[k] for k in ("status", "conclusion") if k in cm]
        if not statuses or any(type(s) is not str or s not in {"success", "passed"} for s in statuses):
            raise ClosedValidationError(f"required_ci_results[{idx}]: CI check did not pass")
    if type(rev_raw) is not list or not rev_raw:
        raise ClosedValidationError("protected_merge_evidence.exact_head_review_evidence: expected non-empty list")
    for idx, entry in enumerate(rev_raw):
        rm = require_mapping(entry, label=f"exact_head_review_evidence[{idx}]")
        if _strict_str(rm.get("reviewed_head_sha"), field_name=f"exact_head_review_evidence[{idx}].reviewed_head_sha") != expected_reviewed_head_sha:
            raise ClosedValidationError(f"exact_head_review_evidence[{idx}]: reviewed_head_sha mismatch")
        states = [rm[k] for k in ("state", "status") if k in rm]
        if not states or any(type(s) is not str or s not in {"APPROVED", "approved"} for s in states):
            raise ClosedValidationError(f"exact_head_review_evidence[{idx}]: review not approved")


def _branch_matches_ref(protected_branch: str, expected_ref: str) -> bool:
    if not protected_branch or not expected_ref or protected_branch == "refs/heads/" or expected_ref == "refs/heads/":
        return False
    norm_branch = protected_branch.removeprefix("refs/heads/")
    norm_exp = expected_ref.removeprefix("refs/heads/")
    return bool(norm_branch and norm_branch == norm_exp and protected_branch in {norm_branch, f"refs/heads/{norm_branch}"} and expected_ref in {norm_exp, f"refs/heads/{norm_exp}"})


def verify_stored_legacy_merge_evidence(
    store: CellObjectStorePort, locator: ArtifactLocator, *, expected_repository: str, expected_protected_ref: str,
    expected_pr_number: int, expected_reviewed_head_sha: str, expected_protected_merge_sha: str,
    expected_adr_git_identity: Mapping[str, Any], expected_branch_policy_digest: str,
    signature_verifier: P1SignatureVerifierPort | None = None, require_signed: bool = True,
) -> dict[str, Any]:
    """Verify stored `smart_ads/protected_merge_evidence/v1` for a legacy seam release."""
    raw = _load_verified_p1_dict(
        store, locator, expected_schema=_PROTECTED_MERGE_SCHEMA, core_keys=_MERGE_EV_CORE_KEYS,
        signature_verifier=signature_verifier, require_signed=require_signed, label="protected_merge_evidence",
    )
    exp_repo = _strict_str(expected_repository, field_name="expected_repository")
    if exp_repo != _LEGACY_REPO or _strict_str(raw["repository"], field_name="protected_merge_evidence.repository") != _LEGACY_REPO:
        raise ClosedValidationError("protected_merge_evidence.repository: must equal 'mbras-tech/mbras-campaigns'")
    p_branch = _strict_id(raw["protected_branch"], field_name="protected_merge_evidence.protected_branch")
    exp_ref = _strict_id(expected_protected_ref, field_name="expected_protected_ref")
    if not _branch_matches_ref(p_branch, exp_ref):
        raise ClosedValidationError("protected_merge_evidence.protected_branch: mismatch against expected_protected_ref")
    exp_pr = _safe_int(expected_pr_number, field_name="expected_pr_number", minimum=1)
    if _safe_int(raw["pr_number"], field_name="protected_merge_evidence.pr_number", minimum=1) != exp_pr:
        raise ClosedValidationError("protected_merge_evidence.pr_number: mismatch")
    exp_rev = validate_hex40(_strict_str(expected_reviewed_head_sha, field_name="expected_reviewed_head_sha"), field_name="expected_reviewed_head_sha")
    exp_mrg = validate_hex40(_strict_str(expected_protected_merge_sha, field_name="expected_protected_merge_sha"), field_name="expected_protected_merge_sha")
    if exp_mrg in _PRE_SEAM_LEGACY_COMMITS:
        raise ClosedValidationError("protected_merge_evidence.protected_merge_sha: pre-seam historical commit reuse forbidden")
    if validate_hex40(_strict_str(raw["reviewed_head_sha"], field_name="reviewed_head_sha"), field_name="reviewed_head_sha") != exp_rev:
        raise ClosedValidationError("protected_merge_evidence.reviewed_head_sha: mismatch")
    if validate_hex40(_strict_str(raw["protected_merge_sha"], field_name="protected_merge_sha"), field_name="protected_merge_sha") != exp_mrg:
        raise ClosedValidationError("protected_merge_evidence.protected_merge_sha: mismatch")
    actual_adr = _validate_adr_git_identity_dict(raw["adr_git_identity"], label="protected_merge_evidence.adr_git_identity")
    exp_adr = _validate_adr_git_identity_dict(expected_adr_git_identity, label="expected_adr_git_identity")
    if canonicalize_jcs(actual_adr) != canonicalize_jcs(exp_adr):
        raise ClosedValidationError("protected_merge_evidence.adr_git_identity: mismatch")
    _validate_ci_and_review_lists(raw["required_ci_results"], raw["exact_head_review_evidence"], expected_reviewed_head_sha=exp_rev)
    bpp = require_exact_keys(raw["branch_protection_policy"], frozenset({"locator", "digest"}), label="branch_protection_policy")
    pol_loc = ArtifactLocator.from_dict(bpp["locator"], expected_type=_GATE2_POLICY_SCHEMA)
    exp_pol_d = validate_sha256_prefixed(_strict_str(expected_branch_policy_digest, field_name="expected_branch_policy_digest"), field_name="expected_branch_policy_digest")
    pol_d = validate_sha256_prefixed(_strict_str(bpp["digest"], field_name="branch_protection_policy.digest"), field_name="branch_protection_policy.digest")
    if pol_d != pol_loc.content_digest or pol_d != exp_pol_d:
        raise ClosedValidationError("protected_merge_evidence.branch_protection_policy: digest mismatch")
    return raw


def _validate_decomposition_head_fields(
    head: Mapping[str, Any], *, head_locator: ArtifactLocator, manifest_locator: ArtifactLocator, expected_manifest_digest: str
) -> None:
    if (
        _strict_str(head["repository"], field_name="head.repository") != _LEGACY_REPO
        or _strict_str(head["commit_sha"], field_name="head.commit_sha") != _LEGACY_COMMIT
        or _strict_str(head["source_tree_oid"], field_name="head.source_tree_oid") != _LEGACY_TREE
    ):
        raise ClosedValidationError("decomposition_manifest_head: pinned legacy baseline mismatch")
    validate_sha256_prefixed(_strict_str(head["scope_digest"], field_name="head.scope_digest"), field_name="head.scope_digest")
    epoch = _safe_int(head["head_epoch"], field_name="head.head_epoch", minimum=1)
    act_loc = ArtifactLocator.from_dict(head["active_manifest_locator"], expected_type=_DECOMP_MANIFEST_SCHEMA)
    act_dig = validate_sha256_prefixed(_strict_str(head["active_manifest_digest"], field_name="head.active_manifest_digest"), field_name="head.active_manifest_digest")
    if act_loc != manifest_locator or act_dig != manifest_locator.content_digest or act_dig != expected_manifest_digest:
        raise ClosedValidationError("decomposition_manifest_head: active manifest locator/digest mismatch")
    validate_envelope_timestamp_utc(head["updated_at_utc"], field_name="head.updated_at_utc")
    kind = _strict_str(head["update_kind"], field_name="head.update_kind")
    if kind not in {"genesis", "correction", "rebase"}:
        raise ClosedValidationError(f"decomposition_manifest_head.update_kind: invalid {kind!r}")
    if kind == "genesis":
        if epoch != 1 or head["previous_head_locator"] is not None or head["previous_head_digest"] is not None:
            raise ClosedValidationError("decomposition_manifest_head: genesis requires epoch==1 and null previous head")
    else:
        if epoch < 2 or head["previous_head_locator"] is None or head["previous_head_digest"] is None:
            raise ClosedValidationError("decomposition_manifest_head: non-genesis requires epoch>=2 and previous head")
        prev_loc = ArtifactLocator.from_dict(head["previous_head_locator"], expected_type=_DECOMP_HEAD_SCHEMA)
        prev_dig = validate_sha256_prefixed(_strict_str(head["previous_head_digest"], field_name="head.previous_head_digest"), field_name="head.previous_head_digest")
        if prev_loc == head_locator or prev_dig != prev_loc.content_digest:
            raise ClosedValidationError("decomposition_manifest_head: previous head cycle or digest mismatch")


def _validate_decomposition_manifest_fields(
    manifest: Mapping[str, Any], *, manifest_locator: ArtifactLocator, update_kind: str
) -> None:
    validate_envelope_timestamp_utc(manifest["generated_at"], field_name="manifest.generated_at")
    exp_m_dig = self_digest_jcs_sha256(manifest, digest_member="manifest_digest", strip_integrity=True)
    if validate_sha256_prefixed(_strict_str(manifest["manifest_digest"], field_name="manifest.manifest_digest"), field_name="manifest.manifest_digest") != exp_m_dig:
        raise ClosedValidationError("decomposition_manifest.manifest_digest: D1 semantic digest mismatch")
    sup_loc_raw, sup_dig_raw, reason_raw = manifest["supersedes_manifest_locator"], manifest["supersedes_digest"], manifest["correction_reason"]
    if update_kind == "genesis":
        if sup_loc_raw is not None or sup_dig_raw is not None or reason_raw is not None:
            raise ClosedValidationError("decomposition_manifest: genesis manifest forbids supersedes fields")
    else:
        sup_loc = ArtifactLocator.from_dict(sup_loc_raw, expected_type=_DECOMP_MANIFEST_SCHEMA)
        sup_dig = validate_sha256_prefixed(_strict_str(sup_dig_raw, field_name="manifest.supersedes_digest"), field_name="manifest.supersedes_digest")
        _strict_id(reason_raw, field_name="manifest.correction_reason")
        if sup_loc == manifest_locator or sup_dig == exp_m_dig:
            raise ClosedValidationError("decomposition_manifest: non-genesis manifest cannot supersede itself")
    inv = require_exact_keys(manifest["source_inventory"], _SOURCE_INVENTORY_KEYS, label="manifest.source_inventory")
    scope = require_mapping(inv["inventory_scope"], label="source_inventory.inventory_scope")
    if _strict_str(inv["$schema"], field_name="inv.$schema") != "smart_ads/source_inventory/v1" or _strict_str(inv["repository"], field_name="inv.repository") != _LEGACY_REPO or _strict_str(inv["commit_sha"], field_name="inv.commit_sha") != _LEGACY_COMMIT or _strict_str(scope.get("source_tree_oid"), field_name="scope.source_tree_oid") != _LEGACY_TREE:
        raise ClosedValidationError("decomposition_manifest.source_inventory: repository/commit/tree mismatch")
    if type(inv["declared_paths"]) is not list or not inv["declared_paths"]:
        raise ClosedValidationError("source_inventory.declared_paths: expected non-empty list")
    sorted_paths = sort_utf8_strings(inv["declared_paths"], field_name="declared_paths", validator=lambda s: _validate_relative_posix_path(s, field_name="declared_paths[]"))
    if tuple(inv["declared_paths"]) != sorted_paths or inv["declared_paths_digest"] != jcs_sha256(inv["declared_paths"]) or inv["inventory_digest"] != self_digest_jcs_sha256(inv, digest_member="inventory_digest", strip_integrity=False):
        raise ClosedValidationError("source_inventory: declared_paths_digest or inventory_digest mismatch")
    items, entries = inv["items"], manifest["entries"]
    if type(items) is not list or not items or type(entries) is not list or len(entries) != len(items):
        raise ClosedValidationError("decomposition_manifest: items/entries must be equal-length non-empty lists")
    item_ids = [_strict_id(require_mapping(i, label="item").get("inventory_id"), field_name="item.inventory_id") for i in items]
    entry_maps = [require_mapping(e, label="entry") for e in entries]
    entry_ids = [_strict_id(em.get("inventory_id"), field_name="entry.inventory_id") for em in entry_maps]
    if len(set(item_ids)) != len(item_ids) or set(entry_ids) != set(item_ids) or any(em.get("decision_status") not in {"approved", "deferred", "rejected"} or bool(em.get("blocking_defects")) for em in entry_maps):
        raise ClosedValidationError("decomposition_manifest: inventory_id bijection, pending status, or blocking_defects violation")
    cov = require_exact_keys(manifest["coverage_assertion"], _COVERAGE_ASSERTION_KEYS, label="manifest.coverage_assertion")
    if any(_safe_int(cov[z], field_name=f"cov.{z}", minimum=0) != 0 for z in ("unassigned_item_count", "duplicate_assignment_count", "conflict_count")) or any(_safe_int(cov[c], field_name=f"cov.{c}", minimum=1) != len(entries) for c in ("inventory_item_count", "entry_count", "assigned_item_count")):
        raise ClosedValidationError("decomposition_manifest.coverage_assertion: count mismatch")


def verify_stored_decomposition_tip(
    store: CellObjectStorePort,
    *,
    head_locator: ArtifactLocator,
    expected_active_head_locator: ArtifactLocator,
    manifest_locator: ArtifactLocator,
    expected_manifest_digest: str,
    signature_verifier: P1SignatureVerifierPort | None = None,
    require_signed: bool = True,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Verify active `decomposition_manifest_head/v1` CAS tip and `decomposition_manifest/v1`."""
    checked_head_loc = _typed_locator(head_locator, field_name="head_locator", expected_type=_DECOMP_HEAD_SCHEMA)
    checked_exp_head = _typed_locator(expected_active_head_locator, field_name="expected_active_head_locator", expected_type=_DECOMP_HEAD_SCHEMA)
    checked_man_loc = _typed_locator(manifest_locator, field_name="manifest_locator", expected_type=_DECOMP_MANIFEST_SCHEMA)
    exp_man_dig = validate_sha256_prefixed(_strict_str(expected_manifest_digest, field_name="expected_manifest_digest"), field_name="expected_manifest_digest")
    if checked_head_loc != checked_exp_head:
        raise ClosedValidationError("decomposition_manifest_head: stale or mismatched head_locator against active CAS tip")
    if checked_man_loc.content_digest != exp_man_dig:
        raise ClosedValidationError("decomposition_manifest: manifest_locator.content_digest != expected_manifest_digest")
    head_dict = _load_verified_p1_dict(
        store, checked_head_loc, expected_schema=_DECOMP_HEAD_SCHEMA, core_keys=_DECOMP_HEAD_CORE_KEYS,
        signature_verifier=signature_verifier, require_signed=require_signed, label="decomposition_manifest_head",
    )
    _validate_decomposition_head_fields(
        head_dict, head_locator=checked_head_loc, manifest_locator=checked_man_loc, expected_manifest_digest=exp_man_dig
    )
    manifest_dict = _load_verified_p1_dict(
        store, checked_man_loc, expected_schema=_DECOMP_MANIFEST_SCHEMA, core_keys=_DECOMP_MANIFEST_CORE_KEYS,
        signature_verifier=signature_verifier, require_signed=require_signed, label="decomposition_manifest",
    )
    _validate_decomposition_manifest_fields(
        manifest_dict, manifest_locator=checked_man_loc, update_kind=head_dict["update_kind"]
    )
    if head_dict["scope_digest"] != jcs_sha256(manifest_dict["source_inventory"]["inventory_scope"]):
        raise ClosedValidationError("decomposition_manifest_head.scope_digest: mismatch against inventory_scope")
    return head_dict, manifest_dict


def _parse_verified_raw_git_commit(
    raw_bytes: bytes, *, expected_commit_sha: str
) -> tuple[str, tuple[str, ...]]:
    if type(raw_bytes) is not bytes:
        raise ClosedValidationError("raw_git_commit: expected bytes")
    exp_sha = validate_hex40(_strict_str(expected_commit_sha, field_name="expected_commit_sha"), field_name="expected_commit_sha")
    if not raw_bytes.startswith(b"commit ") or b"\x00" not in raw_bytes:
        raise ClosedValidationError("raw_git_commit: missing canonical 'commit <len>\\x00' header")
    header, body = raw_bytes.split(b"\x00", 1)
    len_bytes = header[7:]
    if _POS_DEC_BYTES_RE.fullmatch(len_bytes) is None or int(len_bytes.decode("ascii")) != len(body):
        raise ClosedValidationError("raw_git_commit: non-canonical or mismatched commit body length")
    if hashlib.sha1(raw_bytes).hexdigest() != exp_sha:
        raise ClosedValidationError(f"raw_git_commit: SHA-1 mismatch against {exp_sha!r}")
    if b"\n\n" not in body:
        raise ClosedValidationError("raw_git_commit: missing header/message '\\n\\n' separator")
    raw_hdr_block, _ = body.split(b"\n\n", 1)
    if b"\r" in raw_hdr_block or b"\x00" in raw_hdr_block:
        raise ClosedValidationError("raw_git_commit: CR or NUL forbidden in commit headers")
    try:
        hdr_lines = raw_hdr_block.decode("utf-8", errors="strict").split("\n")
    except UnicodeDecodeError as exc:
        raise ClosedValidationError("raw_git_commit: non-UTF-8 commit headers") from exc
    if not hdr_lines or not hdr_lines[0].startswith("tree ") or len(hdr_lines[0]) != 45:
        raise ClosedValidationError("raw_git_commit: first header line must be 'tree <40_hex>'")
    tree_oid = validate_hex40(hdr_lines[0][5:], field_name="raw_git_commit.tree")
    parents: list[str] = []
    idx = 1
    while idx < len(hdr_lines) and hdr_lines[idx].startswith("parent "):
        if len(hdr_lines[idx]) != 47:
            raise ClosedValidationError("raw_git_commit: malformed parent header line")
        p_oid = validate_hex40(hdr_lines[idx][7:], field_name="raw_git_commit.parent")
        if p_oid in parents:
            raise ClosedValidationError("raw_git_commit: duplicate parent OID in commit header")
        parents.append(p_oid)
        idx += 1
    tail = hdr_lines[idx:]
    if len(tail) < 2 or not tail[0].startswith("author ") or not tail[1].startswith("committer "):
        raise ClosedValidationError("raw_git_commit: missing canonical author/committer headers")
    if any(ln.startswith(("tree ", "parent ")) for ln in tail):
        raise ClosedValidationError("raw_git_commit: out-of-order tree or parent header after author")
    return tree_oid, tuple(parents)


def verify_git_commit_parent_chain(
    store: CellObjectStorePort,
    edges: Sequence[GitParentEdge],
    *,
    release_identity: GitReleaseIdentity,
    baseline_identity: LegacyBaselineIdentity,
    baseline_commit_object_ref: str,
) -> None:
    """Materially verify loose Git commit objects along `edges` from release to pinned baseline."""
    if not isinstance(store, CellObjectStorePort):
        raise ClosedValidationError("store: expected CellObjectStorePort")
    if type(release_identity) is not GitReleaseIdentity or type(baseline_identity) is not LegacyBaselineIdentity:
        raise ClosedValidationError("verify_git_commit_parent_chain: expected GitReleaseIdentity and LegacyBaselineIdentity")
    rel_id = GitReleaseIdentity.from_dict(release_identity.to_dict())
    base_id = LegacyBaselineIdentity.from_dict(baseline_identity.to_dict())
    checked_base_ref = validate_cell_object_ref(baseline_commit_object_ref, field_name="baseline_commit_object_ref")
    if isinstance(edges, (str, bytes)) or not isinstance(edges, Sequence):
        raise ClosedValidationError("edges: expected Sequence of GitParentEdge")
    checked_edges = _validate_parent_edge_chain(
        edges, release_sha=rel_id.commit_sha, baseline_sha=base_id.commit_sha, field_name="edges"
    )
    for idx, edge in enumerate(checked_edges):
        raw_commit = store.get_bytes(edge.child_commit_object_ref)
        tree_oid, parent_oids = _parse_verified_raw_git_commit(raw_commit, expected_commit_sha=edge.child_sha)
        if edge.parent_sha not in parent_oids:
            raise ClosedValidationError(f"edges[{idx}]: declared parent_sha absent from verified commit parents")
        if idx == 0 and tree_oid != rel_id.tree_oid:
            raise ClosedValidationError("edges[0]: release commit tree_oid mismatch against release_identity")
    raw_base = store.get_bytes(checked_base_ref)
    base_tree_oid, _ = _parse_verified_raw_git_commit(raw_base, expected_commit_sha=base_id.commit_sha)
    if base_tree_oid != base_id.source_tree_oid:
        raise ClosedValidationError("baseline_commit: tree_oid mismatch against pinned source_tree_oid")


def _verify_stored_wheel_build_provenance(
    store: CellObjectStorePort,
    locator: ArtifactLocator,
    *,
    expected_run_locator: ArtifactLocator,
    expected_wheel_digest: str,
    signature_verifier: P1SignatureVerifierPort | None,
    require_signed: bool,
) -> tuple[dict[str, Any], WheelObjectLocator]:
    prov = _load_verified_p1_dict(
        store, locator, expected_schema=_WHEEL_PROVENANCE_SCHEMA, core_keys=_WHEEL_PROVENANCE_CORE_KEYS,
        signature_verifier=signature_verifier, require_signed=require_signed, label="wheel_build_provenance",
    )
    if ArtifactLocator.from_dict(prov["migration_run_context_locator"], expected_type=_RUN_CONTEXT_SCHEMA) != expected_run_locator:
        raise ClosedValidationError("wheel_build_provenance: migration_run_context_locator mismatch")
    if _strict_str(prov["repository"], field_name="prov.repository") != _CANONICAL_REPO:
        raise ClosedValidationError("wheel_build_provenance.repository: must equal 'aiconnai/smart-ads'")
    _strict_id(prov["build_run_id"], field_name="prov.build_run_id")
    validate_envelope_timestamp_utc(prov["built_at_utc"], field_name="prov.built_at_utc")
    validate_hex40(_strict_str(prov["source_commit_sha"], field_name="prov.source_commit_sha"), field_name="prov.source_commit_sha")
    validate_hex40(_strict_str(prov["source_tree_oid"], field_name="prov.source_tree_oid"), field_name="prov.source_tree_oid")
    _safe_int(prov["source_date_epoch"], field_name="prov.source_date_epoch", minimum=0)
    if _strict_str(prov["python_abi_tag"], field_name="prov.python_abi_tag") != "cp312" or _strict_str(prov["build_backend"], field_name="prov.build_backend") != "hatchling.build":
        raise ClosedValidationError("wheel_build_provenance: python_abi_tag or build_backend mismatch")
    _strict_id(prov["build_backend_version"], field_name="prov.build_backend_version")
    for k in ("build_backend_digest", "pyproject_sha256", "uv_lock_sha256", "schema_bundle_digest", "wheel_digest"):
        validate_sha256_prefixed(_strict_str(prov[k], field_name=f"prov.{k}"), field_name=f"prov.{k}")
    whl_loc = WheelObjectLocator.from_dict(prov["wheel"])
    if prov["wheel_digest"] != expected_wheel_digest or whl_loc.wheel_digest != expected_wheel_digest:
        raise ClosedValidationError("wheel_build_provenance: wheel_digest mismatch")
    raw_whl = store.get_bytes(whl_loc.object_ref, expected_size_bytes=whl_loc.size_bytes)
    if len(raw_whl) != whl_loc.size_bytes or "sha256:" + hashlib.sha256(raw_whl).hexdigest() != expected_wheel_digest:
        raise ClosedValidationError("wheel_build_provenance: stored wheel bytes SHA-256 or size mismatch")
    return prov, whl_loc


def _verify_boundary_and_convergence_dicts(
    bound: Mapping[str, Any],
    conv: Mapping[str, Any],
    cert7a: Certification7ARecord,
    *,
    prov_loc: ArtifactLocator,
    bound_loc: ArtifactLocator,
    cert7a_loc: ArtifactLocator,
    expected_run_loc: ArtifactLocator,
) -> None:
    if (
        ArtifactLocator.from_dict(bound["migration_run_context_locator"], expected_type=_RUN_CONTEXT_SCHEMA) != expected_run_loc
        or ArtifactLocator.from_dict(bound["wheel_build_provenance_locator"], expected_type=_WHEEL_PROVENANCE_SCHEMA) != prov_loc
        or _strict_str(bound["repository"], field_name="bound.repository") != _CANONICAL_REPO
        or any(type(bound[f]) is not bool or bound[f] is not True for f in ("archive_allowlist_passed", "ast_boundary_scan_passed", "isolated_venv_import_passed"))
    ):
        raise ClosedValidationError("wheel_boundary_report: run/provenance/repository or pass-flag mismatch")
    validate_envelope_timestamp_utc(bound["verified_at_utc"], field_name="bound.verified_at_utc")
    validate_sha256_prefixed(_strict_str(bound["sorted_record_digest"], field_name="bound.sorted_record_digest"), field_name="bound.sorted_record_digest")
    if type(bound["sorted_record_entries"]) is not list or not bound["sorted_record_entries"] or type(bound["packaged_modules"]) is not list or not bound["packaged_modules"]:
        raise ClosedValidationError("wheel_boundary_report: empty sorted_record_entries or packaged_modules")
    if bound["sorted_record_digest"] != jcs_sha256(bound["sorted_record_entries"]):
        raise ClosedValidationError("wheel_boundary_report.sorted_record_digest: mismatch against sorted_record_entries")
    validate_envelope_timestamp_utc(conv["converged_at_utc"], field_name="conv.converged_at_utc")
    if type(conv["convergence_status"]) is not str or conv["convergence_status"] not in {"PASS", "PASSED"}:
        raise ClosedValidationError(f"gov1_convergence_record.convergence_status: invalid {conv['convergence_status']!r}")
    ArtifactLocator.from_dict(conv["mcp_rejection_matrix_report_locator"], expected_type=_MCP_REJECTION_SCHEMA)
    if (
        ArtifactLocator.from_dict(conv["migration_run_context_locator"], expected_type=_RUN_CONTEXT_SCHEMA) != expected_run_loc
        or ArtifactLocator.from_dict(conv["wheel_boundary_report_locator"], expected_type=_WHEEL_BOUNDARY_SCHEMA) != bound_loc
        or ArtifactLocator.from_dict(conv["certification_7a_record_locator"], expected_type=_CERTIFICATION_7A_SCHEMA) != cert7a_loc
        or ArtifactLocator.from_dict(conv["sealed_sandbox_profile_locator"], expected_type="smart_ads/sealed_sandbox_profile/v1") != cert7a.sealed_sandbox_profile_locator
        or ArtifactLocator.from_dict(conv["negative_security_test_report_locator"], expected_type="smart_ads/negative_security_test_report/v1") != cert7a.negative_security_test_report_locator
    ):
        raise ClosedValidationError("gov1_convergence_record: constituent locator cross-binding mismatch")


def verify_stored_canonical_build_chain(
    store: CellObjectStorePort, *, wheel_locator: WheelObjectLocator, wheel_digest: str,
    build_provenance_locator: ArtifactLocator, wheel_boundary_report_locator: ArtifactLocator,
    certification_7a_locator: ArtifactLocator, gov1_convergence_locator: ArtifactLocator,
    expected_run_locator: ArtifactLocator, expected_commit_sha: str,
    signature_verifier: P1SignatureVerifierPort | None = None, require_signed: bool = True,
) -> dict[str, Any]:
    """Verify wheel bytes + 4-record canonical build chain (`provenance`, `boundary`, `7A`, `GOV1`)."""
    from smart_ads.reconciliation.certification_7a import Certification7ARecord

    if type(wheel_locator) is not WheelObjectLocator:
        raise ClosedValidationError("wheel_locator: expected WheelObjectLocator")
    checked_whl = WheelObjectLocator.from_dict(wheel_locator.to_dict())
    checked_wdig = validate_sha256_prefixed(_strict_str(wheel_digest, field_name="wheel_digest"), field_name="wheel_digest")
    if checked_wdig != checked_whl.wheel_digest:
        raise ClosedValidationError("wheel_digest: must equal wheel_locator.wheel_digest")
    exp_run = _typed_locator(expected_run_locator, field_name="expected_run_locator", expected_type=_RUN_CONTEXT_SCHEMA)
    exp_sha = validate_hex40(_strict_str(expected_commit_sha, field_name="expected_commit_sha"), field_name="expected_commit_sha")
    prov_loc = _typed_locator(build_provenance_locator, field_name="build_provenance_locator", expected_type=_WHEEL_PROVENANCE_SCHEMA)
    bound_loc = _typed_locator(wheel_boundary_report_locator, field_name="wheel_boundary_report_locator", expected_type=_WHEEL_BOUNDARY_SCHEMA)
    cert7a_loc = _typed_locator(certification_7a_locator, field_name="certification_7a_locator", expected_type=_CERTIFICATION_7A_SCHEMA)
    conv_loc = _typed_locator(gov1_convergence_locator, field_name="gov1_convergence_locator", expected_type=_GOV1_CONVERGENCE_SCHEMA)
    prov, prov_whl = _verify_stored_wheel_build_provenance(
        store, prov_loc, expected_run_locator=exp_run, expected_wheel_digest=checked_wdig,
        signature_verifier=signature_verifier, require_signed=require_signed,
    )
    if prov_whl != checked_whl:
        raise ClosedValidationError("wheel_build_provenance.wheel: mismatch against wheel_locator")
    bound = _load_verified_p1_dict(store, bound_loc, expected_schema=_WHEEL_BOUNDARY_SCHEMA, core_keys=_WHEEL_BOUNDARY_CORE_KEYS, signature_verifier=signature_verifier, require_signed=require_signed, label="wheel_boundary_report")
    cert7a = _load_verified_p1_model(store, cert7a_loc, Certification7ARecord, signature_verifier=signature_verifier, require_signed=require_signed, label="certification_7a_record")
    conv = _load_verified_p1_dict(store, conv_loc, expected_schema=_GOV1_CONVERGENCE_SCHEMA, core_keys=_GOV1_CONVERGENCE_CORE_KEYS, signature_verifier=signature_verifier, require_signed=require_signed, label="gov1_convergence_record")
    _verify_boundary_and_convergence_dicts(bound, conv, cert7a, prov_loc=prov_loc, bound_loc=bound_loc, cert7a_loc=cert7a_loc, expected_run_loc=exp_run)
    shared = (exp_sha, prov["build_run_id"], checked_wdig, prov["build_backend_digest"], prov["schema_bundle_digest"])
    if (
        (cert7a.migration_run_context_locator, cert7a.wheel_build_provenance_locator, cert7a.wheel_boundary_report_locator) != (exp_run, prov_loc, bound_loc)
        or any((d["source_commit_sha"], d["build_run_id"], d["wheel_digest"], d["build_backend_digest"], d["schema_bundle_digest"]) != shared for d in (prov, bound, conv))
        or (cert7a.source_commit_sha, cert7a.build_run_id, cert7a.wheel_digest, cert7a.build_backend_digest, cert7a.schema_bundle_digest) != shared
    ):
        raise ClosedValidationError("canonical_build_chain: cross-record commit/run/wheel/backend/schema mismatch")
    return {"wheel_build_provenance": prov, "wheel_boundary_report": bound, "certification_7a_record": cert7a, "gov1_convergence_record": conv}


def verify_stored_deployment_config_result(
    store: CellObjectStorePort,
    locator: ArtifactLocator,
    *,
    expected_run_locator: ArtifactLocator,
    expected_consumer_repo: str,
    expected_consumer_commit_sha: str,
    expected_deployed_release_id: str,
    expected_runtime_binary_sha256: str,
    signature_verifier: P1SignatureVerifierPort | None = None,
    require_signed: bool = True,
) -> dict[str, Any]:
    """Verify stored `smart_ads/deployment_config_execution_result/v1` P1 envelope."""
    exp_run = _typed_locator(expected_run_locator, field_name="expected_run_locator", expected_type=_RUN_CONTEXT_SCHEMA)
    exp_repo = _strict_str(expected_consumer_repo, field_name="expected_consumer_repo")
    if exp_repo != _CONSUMER_REPO:
        raise ClosedValidationError(f"expected_consumer_repo: must equal {_CONSUMER_REPO!r}")
    exp_sha = validate_hex40(_strict_str(expected_consumer_commit_sha, field_name="expected_consumer_commit_sha"), field_name="expected_consumer_commit_sha")
    exp_rel = _strict_id(expected_deployed_release_id, field_name="expected_deployed_release_id")
    exp_bin = validate_sha256_prefixed(_strict_str(expected_runtime_binary_sha256, field_name="expected_runtime_binary_sha256"), field_name="expected_runtime_binary_sha256")
    raw = _load_verified_p1_dict(
        store, locator, expected_schema=_DEPLOYMENT_RESULT_SCHEMA, core_keys=_DEPLOYMENT_RESULT_CORE_KEYS,
        signature_verifier=signature_verifier, require_signed=require_signed, label="deployment_config_execution_result",
    )
    validate_envelope_timestamp_utc(raw["verified_at_utc"], field_name="deployment_config_execution_result.verified_at_utc")
    if (
        ArtifactLocator.from_dict(raw["migration_run_context_locator"], expected_type=_RUN_CONTEXT_SCHEMA) != exp_run
        or _strict_str(raw["consumer_repository"], field_name="consumer_repository") != exp_repo
        or validate_hex40(_strict_str(raw["consumer_commit_sha"], field_name="consumer_commit_sha"), field_name="consumer_commit_sha") != exp_sha
        or _strict_id(raw["deployed_release_id"], field_name="deployed_release_id") != exp_rel
        or validate_sha256_prefixed(_strict_str(raw["runtime_binary_sha256"], field_name="runtime_binary_sha256"), field_name="runtime_binary_sha256") != exp_bin
        or _strict_str(raw["verification_status"], field_name="verification_status") != "VERIFIED"
    ):
        raise ClosedValidationError("deployment_config_execution_result: status or expected deployment identity mismatch")
    return raw


__all__ = [
    "PREDECESSOR_P1_DOMAIN_PREFIXES",
    "verify_git_commit_parent_chain",
    "verify_stored_canonical_build_chain",
    "verify_stored_decomposition_tip",
    "verify_stored_deployment_config_result",
    "verify_stored_legacy_merge_evidence",
    "verify_stored_migration_run_context",
]
