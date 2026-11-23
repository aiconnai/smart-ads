"""Unit and 1-to-1 governance-builder parity tests for predecessor, seam parity, consumer, and tripartite verifiers."""
from __future__ import annotations

import ast
import base64
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
import hashlib
import hmac
from pathlib import Path
from typing import Any

import pytest

from smart_ads.adapters.consumer.routing_analyzer import Cpython312AstConsumerRoutingAnalyzer
from smart_ads.adapters.storage import InMemoryCellObjectStore
import smart_ads.application as application_pkg
from smart_ads.application import (
    VerifiedStoreMcpReadHandler,
    build_seam_parity_record,
    verify_consumer_deployment_readback,
    verify_consumer_feature_flag_contract,
    verify_git_commit_parent_chain,
    verify_ibvi_ads_delegation_contract,
    verify_legacy_seam_contract,
    verify_legacy_seam_release,
    verify_seam_parity_record,
    verify_stored_canonical_build_chain,
    verify_stored_decomposition_tip,
    verify_stored_deployment_config_result,
    verify_stored_legacy_merge_evidence,
    verify_stored_migration_run_context,
    verify_tripartite_target,
)
import smart_ads.application.consumer_verification as consumer_verification_mod
import smart_ads.application.predecessor_validators as predecessor_validators_mod
import smart_ads.application.seam_parity as seam_parity_mod
from smart_ads.contracts import (
    ADR_P1_DOMAIN_PREFIXES,
    AlgorithmProvenanceIdentity,
    ArtifactLocator,
    ClosedValidationError,
    CompatibilitySurfaceSpec,
    ConsumerDeploymentReadback,
    ConsumerFeatureFlagContract,
    GitArtifactProvenance,
    GitParentEdge,
    GitReleaseIdentity,
    IbviAdsDelegationContext,
    IbviAdsDelegationContract,
    LegacyBaselineIdentity,
    LegacySeamContract,
    LegacySeamRelease,
    P1Integrity,
    ReadEntrypointSelector,
    SeamGitArtifactRef,
    SeamParityRecord,
    SurfaceParityComparison,
    TripartiteCanonicalSide,
    TripartiteConsumerSide,
    TripartiteGitArtifactRef,
    TripartiteLegacySide,
    TripartiteTarget,
    WheelObjectLocator,
    canonicalize_jcs,
    compute_consumer_contract_digest,
    compute_git_blob_oid,
    compute_tripartite_digest,
    jcs_sha256,
    loads_strict_json,
    p1_content_digest,
    p1_signing_message,
)
from smart_ads.ports import (
    CellObjectStorePort,
    ConsumerRoutingAnalysis,
    ConsumerRoutingAnalyzerPort,
    EntrypointRouteFacts,
    P1SignatureVerifierPort,
    SeamDualProjectionCase,
    SeamLegacyProjectorPort,
)
from smart_ads.ports.cell_runtime import ClockAttestation
from smart_ads.transports.mcp import (
    ALLOWED_MCP_METHODS,
    McpRuntimeContext,
    handle_mcp_request_bytes,
    project_delegation_envelope_to_mcp_context,
)
from tests.contract.test_packaging_boundary import PURE_LAYER_ALLOWED_TOP_IMPORTS, scan_pure_layer_ast_violations
from tests.unit.test_certification_7a_record import build_valid_7a_world
from tests.unit.test_mcp_read_handler import McpHandlerWorld
from tools.governance import artifacts as gov_artifacts
from tools.governance import decomposition as gov_decomp
from tools.governance import decomposition_scope as gov_scope
from tools.governance import gov1_convergence, gov1_wheel, p1 as gov_p1

_KEY_ID = "key:ed25519:" + ("9" * 64)
_MAC_SECRET = b"smart-ads-task4-domain-separated-p1-secret"
_PREDECESSOR_DOMAINS: dict[str, str] = {
    "smart_ads/migration_run_context/v1": "SMART-ADS:RUN-CONTEXT:V1\n",
    "smart_ads/protected_merge_evidence/v1": "SMART-ADS:PROTECTED-MERGE:V1\n",
    "smart_ads/decomposition_manifest/v1": "SMART-ADS:DECOMPOSITION:V1\n",
    "smart_ads/decomposition_manifest_head/v1": "SMART-ADS:DECOMPOSITION-HEAD:V1\n",
    "smart_ads/deployment_config_execution_result/v1": "SMART-ADS:DEPLOYMENT-RESULT:V1\n",
}
_ALL_DOMAINS: dict[str, str] = {
    **{f"smart_ads/{k}": v for k, v in gov_p1.DOMAIN_PREFIXES.items()},
    **ADR_P1_DOMAIN_PREFIXES,
    **_PREDECESSOR_DOMAINS,
}
_ADR_IDENTITY: dict[str, str] = {
    "repository": "aiconnai/smart-ads",
    "commit_sha": "a3f19ef668748c64c5c679710c231426c5e05f6a",
    "path": "docs/adr/ADR-0001-smart-ads-read-gateway.md",
    "git_blob_oid": "1" * 40,
    "file_content_sha256": "sha256:239b53e0af44c176b78c363dc271c9fd882910bd4ab2ffb6844cb8fb2458640e",
}
PINNED_D26C73D_RAW_COMMIT_BYTES: bytes = (
    b"commit 1226\x00tree 68ff6d6dbd6d7ecaafa3bca7d5de85a54d705798\n"
    b"parent 3b8df601bd39773e181b53b8136fc52cb2eb6f38\n"
    b"parent d10a3536cc4c8901ae90a2675d734c79ae3951b5\n"
    b"author Ronaldo Martins <ron@ldinho.com.br> 1787952987 -0300\n"
    b"committer GitHub <noreply@github.com> 1787952987 -0300\n"
    b"gpgsig -----BEGIN PGP SIGNATURE-----\n"
    b" \n"
    b" wsFcBAABCAAQBQJqkf9bCRC1aQ7uu5UhlAAAsAYQACcTpM1McKkf41rZe1fQN3fh\n"
    b" W+9Ce3u8hwME6Up90yOZIxQ8pXEvwOVhfth5umbGxEq4XlNj3K7JvqvfyeLGO3ez\n"
    b" /eMITrG3KYnPf7w7AgjJvutz3J3Tyvbui7jkBy0Gt2VVKkpvgwFlPvYKv52XsxXB\n"
    b" LodviegUZ21Kq40e3qfJgABjP4n/8VjRwqrSP/Q3TPCLFRK4BjQOSG0041EbMtcA\n"
    b" ri3lI6nQE7Kk2+wmz/WwJpoiSOGdmsT/+/OHBqt7HEKeIrMUDp8EBleFnHQjM4HA\n"
    b" DP1xy/53/g++czDRdseYXIpfPyQZdv+PDMWrilccZKqgDY0BVw0aWbJetm4Tbc+i\n"
    b" JjgWacHN+woKw6JBK7X4AhIr8WL03inbCprOPPQTGoxOxsZbiqRuOm6tBgwD7vlE\n"
    b" j55r+oOzscZwjWwBaYycZRQN8tG4OOaGkMr70anz51YzwJfAzxEIuRKpKrvDTxYY\n"
    b" 0ircstR0jZFhCYKYDDSlKtOAgiL5CMD3c+T7oSfTmxMf9dbl2YFJfdFpMXAkfqsR\n"
    b" c9UHlKh9bgtP93KZjKu1GeiPDaxxAWX2cyYlvVzuti1OrELSmWk2SkxYt/Hxrh1M\n"
    b" 6IvwPnJ/OWmCrltvQLCpHxvMqg4xRW3cqLnRAouqhP32ovbX406LGfYBKayQMmPB\n"
    b" Od3sAFACXN3WrPJVjG/3\n"
    b" =cDnn\n"
    b" -----END PGP SIGNATURE-----\n"
    b" \n\n"
    b"Merge pull request #129 from mbras-tech/fix/norm-name-spec-compliance\n\n"
    b"refactor(customer-match): remover normalizadores de nome n\xc3\xa3o utilizados"
)


def _sign_dict(unsigned: Mapping[str, Any], key_reg_loc: ArtifactLocator) -> dict[str, Any]:
    schema = str(unsigned["$schema"])
    base = {**dict(unsigned), "integrity": P1Integrity(_KEY_ID, key_reg_loc).to_dict()}
    digest = p1_content_digest(base)
    msg = p1_signing_message(base, _ALL_DOMAINS[schema])
    mac32 = hmac.new(_MAC_SECRET, msg, hashlib.sha256).digest()
    sig_b64 = base64.b64encode(mac32 + mac32).decode("ascii")
    return {**base, "integrity": P1Integrity(_KEY_ID, key_reg_loc, digest, sig_b64).to_dict()}


def _put_signed_dict(
    store: InMemoryCellObjectStore, payload: Mapping[str, Any], key_reg_loc: ArtifactLocator
) -> tuple[dict[str, Any], ArtifactLocator]:
    signed = _sign_dict(payload, key_reg_loc)
    loc = store.put_json_artifact(str(signed["$schema"]), signed)
    return signed, loc


def _put_signed_model(
    store: InMemoryCellObjectStore, obj: Any, key_reg_loc: ArtifactLocator
) -> tuple[Any, ArtifactLocator]:
    signed_dict, loc = _put_signed_dict(store, obj.to_dict(), key_reg_loc)
    return type(obj).from_dict(signed_dict, require_signed=True), loc


class FullDomainP1Verifier(P1SignatureVerifierPort):
    """Strict domain-separated P1 signature verifier covering ADR + predecessor schemas."""

    def __init__(self) -> None:
        self.verified_schemas: list[str] = []

    def verify_p1_envelope_signature(
        self, *, envelope: Mapping[str, Any], domain_prefix: str, store: CellObjectStorePort
    ) -> None:
        schema_id = envelope.get("$schema")
        if type(schema_id) is not str or _ALL_DOMAINS.get(schema_id) != domain_prefix:
            raise ClosedValidationError(f"P1 verifier: domain mismatch for {schema_id!r}")
        integ = P1Integrity.from_dict(envelope.get("integrity"), require_signed=True)
        reg = store.get_json_artifact(integ.key_registry_snapshot_locator)
        if integ.key_id not in reg.get("keys", ()):
            raise ClosedValidationError("P1 verifier: unauthorized key_id")
        if integ.content_digest != p1_content_digest(envelope):
            raise ClosedValidationError("P1 verifier: content_digest mismatch")
        msg = p1_signing_message(envelope, domain_prefix)
        mac32 = hmac.new(_MAC_SECRET, msg, hashlib.sha256).digest()
        if integ.signature_base64 != base64.b64encode(mac32 + mac32).decode("ascii"):
            raise ClosedValidationError("P1 verifier: Ed25519/MAC signature mismatch")
        self.verified_schemas.append(schema_id)


def _make_raw_git_commit(tree_oid: str, parent_oids: Sequence[str], message: str) -> tuple[str, bytes]:
    lines = [f"tree {tree_oid}", *(f"parent {p}" for p in parent_oids)]
    lines.append("author Ronaldo <ronaldo@example.com> 1700000000 +0000")
    lines.append("committer Ronaldo <ronaldo@example.com> 1700000000 +0000")
    body = ("\n".join(lines) + f"\n\n{message}\n").encode("utf-8")
    raw = b"commit " + str(len(body)).encode("ascii") + b"\x00" + body
    return hashlib.sha1(raw).hexdigest(), raw


def _put_git_prov(
    store: InMemoryCellObjectStore, key_reg_loc: ArtifactLocator, repo: str, commit_sha: str, path: str, raw: bytes
) -> tuple[GitArtifactProvenance, ArtifactLocator]:
    prov = GitArtifactProvenance(
        repo, commit_sha, path, compute_git_blob_oid(raw),
        "sha256:" + hashlib.sha256(raw).hexdigest(), "2026-11-11T02:58:00Z",
    )
    return _put_signed_model(store, prov, key_reg_loc)


def _build_real_decomposition_artifacts(
    store: InMemoryCellObjectStore, key_reg_loc: ArtifactLocator
) -> tuple[ArtifactLocator, ArtifactLocator, dict[str, Any], dict[str, Any]]:
    snap = gov_scope.SourceSnapshot(
        {"scripts/operator/conductor.py": b"def run_conductor():\n    return 1\n"},
        {"scripts/operator/conductor.py": "100644"},
    )
    inv = gov_decomp.resolve_inventory(snap)
    tmpl = gov_decomp.decision_template(inv)
    tmpl[0].update({
        "system_owner": "principal:ronaldo", "target_repository": "aiconnai/smart-ads",
        "target_layer": "core_engine", "target_path": "src/smart_ads/application/seam_parity.py",
        "migration_mode": "reimplement_clean", "decision_status": "approved",
        "preserved_invariants": ["inv:seam"], "required_tests": ["tests/unit/test_seam_and_tripartite_verification.py"],
    })
    cand = gov_decomp.build_candidate(snap, inv, tmpl, "2026-09-07T00:00:00Z")
    manifest_unsigned = {"$schema": "smart_ads/decomposition_manifest/v1", **cand["payload"]}
    manifest_unsigned["manifest_digest"] = gov_decomp.manifest_digest(manifest_unsigned)
    manifest_signed, manifest_loc = _put_signed_dict(store, manifest_unsigned, key_reg_loc)
    head_unsigned = {
        "$schema": "smart_ads/decomposition_manifest_head/v1",
        "repository": "mbras-tech/mbras-campaigns",
        "commit_sha": "d26c73d8508c7c3d43161fe36a80c44a46bf0f2d",
        "source_tree_oid": "68ff6d6dbd6d7ecaafa3bca7d5de85a54d705798",
        "scope_digest": jcs_sha256(inv["inventory_scope"]),
        "head_epoch": 1,
        "active_manifest_locator": manifest_loc.to_dict(),
        "active_manifest_digest": manifest_loc.content_digest,
        "previous_head_locator": None,
        "previous_head_digest": None,
        "update_kind": "genesis",
        "updated_at_utc": "2026-09-07T00:05:00Z",
    }
    head_signed, head_loc = _put_signed_dict(store, head_unsigned, key_reg_loc)
    return head_loc, manifest_loc, head_signed, manifest_signed


def _build_run_and_merge_artifacts(
    store: InMemoryCellObjectStore, key_reg_loc: ArtifactLocator, *, release_sha: str, reviewed_sha: str
) -> tuple[ArtifactLocator, ArtifactLocator, str]:
    g2_pol = gov_artifacts.build_gate2_authority_policy(
        "mbras-tech/mbras-campaigns", "refs/heads/main", "docs/adr/ADR-0001-smart-ads-read-gateway.md",
        "sha256:" + ("4" * 64), ["principal:ronaldo"], key_reg_loc.to_dict(), _KEY_ID,
    )
    _, pol_loc = _put_signed_dict(store, g2_pol, key_reg_loc)
    g2_rec_loc = ArtifactLocator.from_digest("smart_ads/gate2_approval_receipt/v1", "sha256:" + ("5" * 64))
    run_unsigned = gov_artifacts.build_migration_run_context(
        gate2_receipt_locator=g2_rec_loc.to_dict(), approved_adr_git_identity=_ADR_IDENTITY,
        legacy_source_identity=gov_scope.LEGACY_SOURCE_IDENTITY, tenant_ref="tenant:ibvi",
        cell_ref="cell:ibvi-primary", run_id="run:pr5-task4", created_at_utc="2026-11-10T00:00:00Z",
        key_registry_snapshot_locator=key_reg_loc.to_dict(), signer_key_id=_KEY_ID,
    )
    _, run_loc = _put_signed_dict(store, run_unsigned, key_reg_loc)
    merge_unsigned = gov_artifacts.build_protected_merge_evidence(
        repository="mbras-tech/mbras-campaigns", protected_branch="main", pr_number=77,
        reviewed_head_sha=reviewed_sha, protected_merge_sha=release_sha, adr_git_identity=_ADR_IDENTITY,
        required_ci_results=[{"check": "pytest", "status": "success"}],
        exact_head_review_evidence=[{"reviewer": "principal:ronaldo", "reviewed_head_sha": reviewed_sha, "state": "APPROVED"}],
        branch_protection_policy={"locator": pol_loc.to_dict(), "digest": pol_loc.content_digest},
        signer_key_id=_KEY_ID, registry_locator=key_reg_loc.to_dict(), branch_protection_verified=True,
    )
    _, merge_loc = _put_signed_dict(store, merge_unsigned, key_reg_loc)
    return run_loc, merge_loc, pol_loc.content_digest


def _build_legacy_seam_artifacts(
    store: InMemoryCellObjectStore, key_reg_loc: ArtifactLocator, run_loc: ArtifactLocator,
    head_loc: ArtifactLocator, manifest_loc: ArtifactLocator,
) -> tuple[LegacySeamContract, ArtifactLocator, LegacySeamRelease, ArtifactLocator, bytes]:
    base_id = LegacyBaselineIdentity()
    base_ref = store.put_bytes(PINNED_D26C73D_RAW_COMMIT_BYTES)
    mid_sha, mid_raw = _make_raw_git_commit("2" * 40, (base_id.commit_sha,), "mid commit")
    mid_ref = store.put_bytes(mid_raw)
    rel_tree = "3" * 40
    rel_sha, rel_raw = _make_raw_git_commit(rel_tree, (mid_sha,), "protected release")
    rel_ref = store.put_bytes(rel_raw)
    rel_id = GitReleaseIdentity("mbras-tech/mbras-campaigns", rel_sha, rel_tree)
    seam_bytes = b"def project_seam(payload):\n    return payload\n"
    seam_prov, seam_prov_loc = _put_git_prov(
        store, key_reg_loc, "mbras-tech/mbras-campaigns", rel_sha, "scripts/operator/seam_adapter.py", seam_bytes
    )
    _, merge_loc, pol_digest = _build_run_and_merge_artifacts(
        store, key_reg_loc, release_sha=rel_sha, reviewed_sha="6" * 40
    )
    surfaces = tuple(
        CompatibilitySurfaceSpec(m, "smart_ads/collection_result/v1", "smart_ads/finding/v1", f"mapping:{i}")
        for i, m in enumerate(ALLOWED_MCP_METHODS)
    )
    con_u = LegacySeamContract(
        run_loc, base_id, rel_id, manifest_loc, manifest_loc.content_digest,
        seam_prov_loc, seam_prov.file_content_sha256, "seam-v1", surfaces,
    )
    con_s, con_loc = _put_signed_model(store, con_u, key_reg_loc)
    edges = (GitParentEdge(rel_sha, mid_sha, rel_ref), GitParentEdge(mid_sha, base_id.commit_sha, mid_ref))
    seam_art = SeamGitArtifactRef(seam_prov.path, seam_prov.git_blob_oid, seam_prov.file_content_sha256, seam_prov_loc)
    rel_u = LegacySeamRelease(
        run_loc, base_id, base_ref, head_loc, manifest_loc, manifest_loc.content_digest, rel_id, edges,
        "refs/heads/main", 77, "6" * 40, rel_sha, merge_loc, pol_digest, seam_art, con_loc, con_loc.content_digest,
    )
    rel_s, rel_loc = _put_signed_model(store, rel_u, key_reg_loc)
    return con_s, con_loc, rel_s, rel_loc, seam_bytes


@dataclass(frozen=True)
class MirrorLegacyProjector(SeamLegacyProjectorPort):
    """Deterministic legacy compatibility projector returning precomputed wire payloads."""

    override_by_case: Mapping[str, Mapping[str, Any]] | None = None

    def project_legacy_surface(
        self, *, surface_id: str, mapping_contract_ref: str, case: SeamDualProjectionCase
    ) -> Mapping[str, Any]:
        if self.override_by_case and case.case_id in self.override_by_case:
            return self.override_by_case[case.case_id]
        return dict(case.legacy_input_payload["expected_wire"])


def _build_mcp_cases_and_handler() -> tuple[VerifiedStoreMcpReadHandler, dict[str, tuple[SeamDualProjectionCase, ...]]]:
    mcp_world = McpHandlerWorld()
    handler = mcp_world.default_handler
    snap_loc = mcp_world.default_index.active_dataset_snapshot_locator
    cases: dict[str, tuple[SeamDualProjectionCase, ...]] = {}
    for idx, method in enumerate(ALLOWED_MCP_METHODS):
        del_env = IbviAdsDelegationContext(
            "/ibvi-ads", "conductor:hermes", "front:pinna", "profile:pinna-ops",
            "tenant:ibvi", "binding:meta-primary", "scope:campaigns-active", method,
            "sha256:" + ("8" * 64), "2026-11-11T02:55:00Z", "2026-11-11T04:00:00Z", f"nonce-s-{idx}",
        )
        mcp_ctx = project_delegation_envelope_to_mcp_context(del_env)
        rt = McpRuntimeContext("2026-11-11T03:00:00Z", "2026-11-11T03:00:02Z", mcp_ctx)
        if "performance" in method:
            params: dict[str, Any] = {
                "tenant_ref": "tenant:ibvi", "binding_ref": "binding:meta-primary",
                "resource_scope_ref": "scope:campaigns-active",
                "date_range": {"start_date": "2026-11-09", "end_date": "2026-11-10"},
            }
        elif "findings" in method:
            params = {
                "tenant_ref": "tenant:ibvi", "binding_ref": "binding:meta-primary",
                "resource_scope_ref": "scope:campaigns-active", "dataset_snapshot_locator": snap_loc.to_dict(),
            }
        else:
            params = {
                "tenant_ref": "tenant:ibvi", "binding_ref": "binding:meta-primary",
                "resource_scope_ref": "scope:campaigns-active", "dataset_snapshot_locator": snap_loc.to_dict(),
                "cadence": "daily", "period_start_date": "2026-11-10", "period_end_date": "2026-11-10",
            }
        wire = canonicalize_jcs({"jsonrpc": "2.0", "id": f"req-{idx}", "method": method, "params": params})
        expected = loads_strict_json(handle_mcp_request_bytes(wire, rt, handler=handler).wire_bytes)
        cases[method] = (SeamDualProjectionCase(f"case-{idx:02d}", method, wire, rt, {"expected_wire": expected}),)
    return handler, cases


def _build_canonical_chain_in_store(
    store: InMemoryCellObjectStore, key_reg_loc: ArtifactLocator, run_loc: ArtifactLocator
) -> dict[str, Any]:
    w7a = build_valid_7a_world()
    whl_bytes, commit_sha = w7a.wheel_bytes, w7a.record.source_commit_sha
    store.put_bytes(whl_bytes)
    whl_obj = WheelObjectLocator.for_wheel_bytes(whl_bytes)
    pyp_b, uvl_b = b"[project]\nname = 'smart-ads'\n", b"version = 1\n"
    s_files = {"pyproject.toml": pyp_b, "uv.lock": uvl_b, "src/smart_ads/__init__.py": b""}
    s_modes = {k: "100644" for k in s_files}
    snap = gov1_wheel.GitBuildSnapshot(commit_sha, "a" * 40, s_files, s_modes, "sha256:" + hashlib.sha256(pyp_b).hexdigest(), "sha256:" + hashlib.sha256(uvl_b).hexdigest(), "hatchling.build", "1.33.0", w7a.record.build_backend_digest)
    prov_u = gov1_wheel.build_wheel_build_provenance_envelope(migration_run_context_locator=run_loc.to_dict(), build_run_id=w7a.record.build_run_id, built_at_utc="2026-09-07T10:00:05Z", snapshot=snap, source_date_epoch=1_700_000_000, schema_bundle_digest=w7a.record.schema_bundle_digest, wheel_bytes=whl_bytes, registry_locator=key_reg_loc.to_dict(), signer_key_id=_KEY_ID)
    _, prov_loc = _put_signed_dict(store, prov_u, key_reg_loc)
    entries = [{"path": "smart_ads-0.1.0.dist-info/RECORD", "record_hash": "", "record_size": None}]
    bound_u = {"$schema": "smart_ads/wheel_boundary_report/v1", "migration_run_context_locator": run_loc.to_dict(), "build_run_id": w7a.record.build_run_id, "verified_at_utc": "2026-09-07T10:00:10Z", "repository": "aiconnai/smart-ads", "source_commit_sha": commit_sha, "wheel_digest": whl_obj.wheel_digest, "build_backend_digest": w7a.record.build_backend_digest, "schema_bundle_digest": w7a.record.schema_bundle_digest, "sorted_record_entries": entries, "sorted_record_digest": jcs_sha256(entries), "archive_allowlist_passed": True, "ast_boundary_scan_passed": True, "isolated_venv_import_passed": True, "packaged_modules": ["smart_ads"], "wheel_build_provenance_locator": prov_loc.to_dict()}
    _, bound_loc = _put_signed_dict(store, bound_u, key_reg_loc)
    rec7a_s, cert7a_loc = _put_signed_model(store, replace(w7a.record, migration_run_context_locator=run_loc, wheel_build_provenance_locator=prov_loc, wheel_boundary_report_locator=bound_loc, wheel_digest=whl_obj.wheel_digest, integrity=None), key_reg_loc)
    mcp_rep_loc = ArtifactLocator.from_digest("smart_ads/mcp_rejection_matrix_report/v1", "sha256:" + ("8" * 64))
    conv_u = {"$schema": gov1_convergence.GOV1_CONVERGENCE_SCHEMA, "migration_run_context_locator": run_loc.to_dict(), "wheel_boundary_report_locator": bound_loc.to_dict(), "sealed_sandbox_profile_locator": rec7a_s.sealed_sandbox_profile_locator.to_dict(), "negative_security_test_report_locator": rec7a_s.negative_security_test_report_locator.to_dict(), "mcp_rejection_matrix_report_locator": mcp_rep_loc.to_dict(), "certification_7a_record_locator": cert7a_loc.to_dict(), "build_run_id": rec7a_s.build_run_id, "converged_at_utc": "2026-09-07T10:01:00Z", "source_commit_sha": commit_sha, "wheel_digest": whl_obj.wheel_digest, "build_backend_digest": rec7a_s.build_backend_digest, "schema_bundle_digest": rec7a_s.schema_bundle_digest, "convergence_status": "PASS"}
    _, conv_loc = _put_signed_dict(store, conv_u, key_reg_loc)
    return {"whl_obj": whl_obj, "whl_bytes": whl_bytes, "commit_sha": commit_sha, "prov_loc": prov_loc, "bound_loc": bound_loc, "bound_u": bound_u, "cert7a_loc": cert7a_loc, "conv_loc": conv_loc, "conv_u": conv_u}


def _build_consumer_artifacts(
    store: InMemoryCellObjectStore, key_reg_loc: ArtifactLocator, run_loc: ArtifactLocator
) -> dict[str, Any]:
    c_sha, cond_bytes = "7" * 40, b"# hermes /ibvi-ads conductor policy\n"
    adp_bytes = (
        b"FLAG_KEY = 'ibvi_ads.smart_ads_read_v1'\n"
        b"def fetch_campaigns(flags, smart_client, legacy_client, payload):\n"
        b"    if flags.is_enabled(FLAG_KEY):\n"
        b"        return smart_client.call('/ibvi-ads', 'smart_ads.queries.get_campaign_performance_v1', payload)\n"
        b"    else:\n"
        b"        return legacy_client.call('legacy:mbras_direct', payload)\n"
    )
    flag_bytes = canonicalize_jcs({"flag_key": "ibvi_ads.smart_ads_read_v1", "default_enabled": False, "disabled_legacy_route": "legacy:mbras_direct", "enabled_smart_ads_route": "/ibvi-ads"})
    store.put_bytes(adp_bytes)
    store.put_bytes(flag_bytes)
    _, cond_loc = _put_git_prov(store, key_reg_loc, "limaronaldo/hermes-ronaldo", c_sha, "conductor/ibvi_ads.py", cond_bytes)
    adp_p, adp_loc = _put_git_prov(store, key_reg_loc, "limaronaldo/hermes-ronaldo", c_sha, "ibvi_ads/adapter.py", adp_bytes)
    flg_p, flg_loc = _put_git_prov(store, key_reg_loc, "limaronaldo/hermes-ronaldo", c_sha, "ibvi_ads/flags.json", flag_bytes)
    alg_p, alg_loc = _put_git_prov(store, key_reg_loc, "aiconnai/smart-ads", "b" * 40, "src/smart_ads/adapters/consumer/routing_analyzer.py", b"# analyzer")
    del_s, del_loc = _put_signed_model(store, IbviAdsDelegationContract(run_loc, "limaronaldo/hermes-ronaldo", c_sha, cond_loc, "conductor:hermes", "front:pinna", "/ibvi-ads", "sha256:" + ("8" * 64), ALLOWED_MCP_METHODS, True), key_reg_loc)
    adp_art = TripartiteGitArtifactRef(adp_p.path, adp_p.git_blob_oid, adp_p.file_content_sha256, adp_loc)
    flg_art = TripartiteGitArtifactRef(flg_p.path, flg_p.git_blob_oid, flg_p.file_content_sha256, flg_loc)
    rv_alg = AlgorithmProvenanceIdentity("algorithm:ast-router-v1", "1.0.0", alg_loc, alg_p.repository, alg_p.commit_sha, alg_p.path, alg_p.git_blob_oid, alg_p.file_content_sha256, "cpython-3.12", ConsumerFeatureFlagContract.SCHEMA)
    ff_s, ff_loc = _put_signed_model(store, ConsumerFeatureFlagContract(run_loc, "limaronaldo/hermes-ronaldo", c_sha, adp_art, flg_art, "ibvi_ads.smart_ads_read_v1", False, "legacy:mbras_direct", "/ibvi-ads", (ReadEntrypointSelector("fetch_campaigns", "smart_ads.queries.get_campaign_performance_v1"),), rv_alg, del_loc), key_reg_loc)
    _, dep_res_loc = _put_signed_dict(store, {"$schema": "smart_ads/deployment_config_execution_result/v1", "migration_run_context_locator": run_loc.to_dict(), "consumer_repository": "limaronaldo/hermes-ronaldo", "consumer_commit_sha": c_sha, "deployed_release_id": "release:hermes-001", "runtime_binary_sha256": "sha256:" + ("c" * 64), "verification_status": "VERIFIED", "verified_at_utc": "2026-11-11T02:59:00Z"}, key_reg_loc)
    _, clk_loc = _put_signed_model(store, ClockAttestation("clock:rb-001", "2026-11-11T03:00:00.500000Z", 200, "2026-11-11T02:59:55Z", "2026-11-11T03:00:30Z", 60), key_reg_loc)
    rb_s, rb_loc = _put_signed_model(store, ConsumerDeploymentReadback(run_loc, "limaronaldo/hermes-ronaldo", c_sha, dep_res_loc, "release:hermes-001", "sha256:" + ("c" * 64), clk_loc, "2026-11-11T03:00:00.500000Z", replace(rv_alg, schema_id=ConsumerDeploymentReadback.SCHEMA), "sha256:" + ("d" * 64), adp_art, f"cell-object:{adp_art.file_content_sha256}", flg_art, f"cell-object:{flg_art.file_content_sha256}", "ibvi_ads.smart_ads_read_v1", False, "legacy:mbras_direct", "/ibvi-ads", ff_loc, ff_loc.content_digest, del_loc, del_loc.content_digest), key_reg_loc)
    return {"c_sha": c_sha, "cond_bytes": cond_bytes, "adp_bytes": adp_bytes, "flag_bytes": flag_bytes, "del_s": del_s, "del_loc": del_loc, "ff_s": ff_s, "ff_loc": ff_loc, "rb_s": rb_s, "rb_loc": rb_loc, "dep_res_loc": dep_res_loc}


def test_predecessor_validators_run_context_merge_evidence_and_decomposition_tip() -> None:
    store, verifier = InMemoryCellObjectStore(), FullDomainP1Verifier()
    key_reg_loc = store.put_json_artifact("smart_ads/key_authorization_registry/v1", {"$schema": "smart_ads/key_authorization_registry/v1", "keys": [_KEY_ID]})
    head_loc, manifest_loc, head_s, manifest_s = _build_real_decomposition_artifacts(store, key_reg_loc)
    run_loc, merge_loc, pol_digest = _build_run_and_merge_artifacts(store, key_reg_loc, release_sha="e" * 40, reviewed_sha="d" * 40)

    run_out = verify_stored_migration_run_context(store, run_loc, signature_verifier=verifier)
    assert run_out["run_id"] == "run:pr5-task4"
    with pytest.raises(ClosedValidationError):
        verify_stored_migration_run_context(store, run_loc, signature_verifier=None, require_signed=True)

    merge_out = verify_stored_legacy_merge_evidence(
        store, merge_loc, expected_repository="mbras-tech/mbras-campaigns",
        expected_protected_ref="refs/heads/main", expected_pr_number=77, expected_reviewed_head_sha="d" * 40,
        expected_protected_merge_sha="e" * 40, expected_adr_git_identity=_ADR_IDENTITY,
        expected_branch_policy_digest=pol_digest, signature_verifier=verifier,
    )
    assert merge_out["repository"] == "mbras-tech/mbras-campaigns"
    _, bad_merge_loc = _put_signed_dict(store, {**merge_out, "repository": "aiconnai/smart-ads"}, key_reg_loc)
    with pytest.raises(ClosedValidationError):
        verify_stored_legacy_merge_evidence(
            store, bad_merge_loc, expected_repository="mbras-tech/mbras-campaigns",
            expected_protected_ref="main", expected_pr_number=77, expected_reviewed_head_sha="d" * 40,
            expected_protected_merge_sha="e" * 40, expected_adr_git_identity=_ADR_IDENTITY,
            expected_branch_policy_digest=pol_digest, signature_verifier=verifier,
        )

    h_out, m_out = verify_stored_decomposition_tip(
        store, head_locator=head_loc, expected_active_head_locator=head_loc,
        manifest_locator=manifest_loc, expected_manifest_digest=manifest_loc.content_digest, signature_verifier=verifier,
    )
    assert h_out["head_epoch"] == 1 and m_out["manifest_digest"] == manifest_s["manifest_digest"]
    stale_loc = ArtifactLocator.from_digest("smart_ads/decomposition_manifest_head/v1", "sha256:" + ("0" * 64))
    with pytest.raises(ClosedValidationError):
        verify_stored_decomposition_tip(
            store, head_locator=head_loc, expected_active_head_locator=stale_loc,
            manifest_locator=manifest_loc, expected_manifest_digest=manifest_loc.content_digest, signature_verifier=verifier,
        )
    _, bad_m_loc = _put_signed_dict(store, {**manifest_s, "manifest_digest": "sha256:" + ("0" * 64)}, key_reg_loc)
    _, bad_h_loc = _put_signed_dict(store, {**head_s, "active_manifest_locator": bad_m_loc.to_dict(), "active_manifest_digest": bad_m_loc.content_digest}, key_reg_loc)
    with pytest.raises(ClosedValidationError):
        verify_stored_decomposition_tip(
            store, head_locator=bad_h_loc, expected_active_head_locator=bad_h_loc,
            manifest_locator=bad_m_loc, expected_manifest_digest=bad_m_loc.content_digest, signature_verifier=verifier,
        )


def test_git_commit_parent_chain_and_tamper_rejections() -> None:
    store = InMemoryCellObjectStore()
    base = LegacyBaselineIdentity()
    base_ref = store.put_bytes(PINNED_D26C73D_RAW_COMMIT_BYTES)
    mid_sha, mid_raw = _make_raw_git_commit("2" * 40, (base.commit_sha,), "mid")
    mid_ref = store.put_bytes(mid_raw)
    rel_sha, rel_raw = _make_raw_git_commit("3" * 40, (mid_sha,), "release")
    rel_ref = store.put_bytes(rel_raw)
    edges = (GitParentEdge(rel_sha, mid_sha, rel_ref), GitParentEdge(mid_sha, base.commit_sha, mid_ref))
    rel_id = GitReleaseIdentity("mbras-tech/mbras-campaigns", rel_sha, "3" * 40)

    verify_git_commit_parent_chain(
        store, edges, release_identity=rel_id, baseline_identity=base, baseline_commit_object_ref=base_ref
    )
    # Leading-zero commit length header must fail closed:
    bad_body = b"tree " + (b"3" * 40) + b"\nparent " + mid_sha.encode() + b"\nauthor A <a@b> 1 +0000\ncommitter A <a@b> 1 +0000\n\nmsg\n"
    bad_lead = b"commit 0" + str(len(bad_body)).encode() + b"\x00" + bad_body
    bad_sha = hashlib.sha1(bad_lead).hexdigest()
    bad_ref = store.put_bytes(bad_lead)
    with pytest.raises(ClosedValidationError):
        verify_git_commit_parent_chain(
            store, (GitParentEdge(bad_sha, mid_sha, bad_ref), edges[1]),
            release_identity=GitReleaseIdentity("mbras-tech/mbras-campaigns", bad_sha, "3" * 40),
            baseline_identity=base, baseline_commit_object_ref=base_ref,
        )
    # Wrong release tree_oid must fail closed:
    with pytest.raises(ClosedValidationError):
        verify_git_commit_parent_chain(
            store, edges, release_identity=GitReleaseIdentity("mbras-tech/mbras-campaigns", rel_sha, "9" * 40),
            baseline_identity=base, baseline_commit_object_ref=base_ref,
        )


def test_canonical_build_chain_and_deployment_result_validators() -> None:
    store, verifier = InMemoryCellObjectStore(), FullDomainP1Verifier()
    key_reg_loc = store.put_json_artifact("smart_ads/key_authorization_registry/v1", {"$schema": "smart_ads/key_authorization_registry/v1", "keys": [_KEY_ID]})
    run_loc, _, _ = _build_run_and_merge_artifacts(store, key_reg_loc, release_sha="e" * 40, reviewed_sha="d" * 40)
    can = _build_canonical_chain_in_store(store, key_reg_loc, run_loc)

    res = verify_stored_canonical_build_chain(
        store, wheel_locator=can["whl_obj"], wheel_digest=can["whl_obj"].wheel_digest,
        build_provenance_locator=can["prov_loc"], wheel_boundary_report_locator=can["bound_loc"],
        certification_7a_locator=can["cert7a_loc"], gov1_convergence_locator=can["conv_loc"],
        expected_run_locator=run_loc, expected_commit_sha=can["commit_sha"], signature_verifier=verifier,
    )
    assert res["wheel_build_provenance"]["wheel_digest"] == can["whl_obj"].wheel_digest

    _, bad_conv_loc = _put_signed_dict(store, {**can["conv_u"], "convergence_status": "FAIL"}, key_reg_loc)
    with pytest.raises(ClosedValidationError):
        verify_stored_canonical_build_chain(
            store, wheel_locator=can["whl_obj"], wheel_digest=can["whl_obj"].wheel_digest,
            build_provenance_locator=can["prov_loc"], wheel_boundary_report_locator=can["bound_loc"],
            certification_7a_locator=can["cert7a_loc"], gov1_convergence_locator=bad_conv_loc,
            expected_run_locator=run_loc, expected_commit_sha=can["commit_sha"], signature_verifier=verifier,
        )

    cons = _build_consumer_artifacts(store, key_reg_loc, run_loc)
    dep_out = verify_stored_deployment_config_result(
        store, cons["dep_res_loc"], expected_run_locator=run_loc, expected_consumer_repo="limaronaldo/hermes-ronaldo",
        expected_consumer_commit_sha=cons["c_sha"], expected_deployed_release_id="release:hermes-001",
        expected_runtime_binary_sha256="sha256:" + ("c" * 64), signature_verifier=verifier,
    )
    assert dep_out["verification_status"] == "VERIFIED"
    with pytest.raises(ClosedValidationError):
        verify_stored_deployment_config_result(
            store, cons["dep_res_loc"], expected_run_locator=run_loc, expected_consumer_repo="limaronaldo/hermes-ronaldo",
            expected_consumer_commit_sha=cons["c_sha"], expected_deployed_release_id="release:wrong",
            expected_runtime_binary_sha256="sha256:" + ("c" * 64), signature_verifier=verifier,
        )


def test_seam_contract_release_and_dual_projection_parity() -> None:
    store, verifier = InMemoryCellObjectStore(), FullDomainP1Verifier()
    key_reg_loc = store.put_json_artifact("smart_ads/key_authorization_registry/v1", {"$schema": "smart_ads/key_authorization_registry/v1", "keys": [_KEY_ID]})
    head_loc, manifest_loc, _, _ = _build_real_decomposition_artifacts(store, key_reg_loc)
    run_loc, _, _ = _build_run_and_merge_artifacts(store, key_reg_loc, release_sha="e" * 40, reviewed_sha="d" * 40)
    con_s, con_loc, rel_s, rel_loc, seam_bytes = _build_legacy_seam_artifacts(store, key_reg_loc, run_loc, head_loc, manifest_loc)
    can = _build_canonical_chain_in_store(store, key_reg_loc, run_loc)
    alg_p, alg_loc = _put_git_prov(store, key_reg_loc, "aiconnai/smart-ads", can["commit_sha"], "src/smart_ads/application/seam_parity.py", b"# seam")
    seam_alg = AlgorithmProvenanceIdentity("algorithm:seam-parity-v1", "1.0.0", alg_loc, alg_p.repository, alg_p.commit_sha, alg_p.path, alg_p.git_blob_oid, alg_p.file_content_sha256, "cpython-3.12", SeamParityRecord.SCHEMA)

    assert verify_legacy_seam_contract(con_loc, seam_raw_bytes=seam_bytes, active_decomposition_head_locator=head_loc, store=store, signature_verifier=verifier) == con_s
    assert verify_legacy_seam_release(rel_loc, expected_active_decomposition_head_locator=head_loc, seam_raw_bytes=seam_bytes, store=store, signature_verifier=verifier) == rel_s

    handler, cases = _build_mcp_cases_and_handler()
    unsigned_rec, _ = build_seam_parity_record(
        legacy_seam_release_locator=rel_loc, expected_active_decomposition_head_locator=head_loc,
        wheel_build_provenance_locator=can["prov_loc"], wheel_digest=can["whl_obj"].wheel_digest,
        seam_adapter_algorithm_identity=seam_alg, evaluated_at_utc="2026-11-11T03:10:00Z",
        seam_raw_bytes=seam_bytes, cases_by_surface=cases, canonical_handler=handler,
        legacy_projector=MirrorLegacyProjector(), store=store,
        integrity=P1Integrity(_KEY_ID, key_reg_loc), signature_verifier=verifier,
    )
    signed_rec, signed_loc = _put_signed_model(store, unsigned_rec, key_reg_loc)
    verified = verify_seam_parity_record(
        signed_loc, expected_active_decomposition_head_locator=head_loc, seam_raw_bytes=seam_bytes,
        cases_by_surface=cases, canonical_handler=handler, legacy_projector=MirrorLegacyProjector(),
        store=store, signature_verifier=verifier,
    )
    assert verified == signed_rec and len(verified.surface_comparisons) == len(ALLOWED_MCP_METHODS)

    bad_proj = MirrorLegacyProjector(override_by_case={"case-00": {"jsonrpc": "2.0", "id": "req-0", "result": {"tampered": 1}}})
    with pytest.raises(ClosedValidationError):
        build_seam_parity_record(
            legacy_seam_release_locator=rel_loc, expected_active_decomposition_head_locator=head_loc,
            wheel_build_provenance_locator=can["prov_loc"], wheel_digest=can["whl_obj"].wheel_digest,
            seam_adapter_algorithm_identity=seam_alg, evaluated_at_utc="2026-11-11T03:10:00Z",
            seam_raw_bytes=seam_bytes, cases_by_surface=cases, canonical_handler=handler,
            legacy_projector=bad_proj, store=store, integrity=P1Integrity(_KEY_ID, key_reg_loc), signature_verifier=verifier,
        )


def test_consumer_delegation_feature_flag_readback_and_tripartite_verifiers() -> None:
    store, verifier = InMemoryCellObjectStore(), FullDomainP1Verifier()
    analyzer = Cpython312AstConsumerRoutingAnalyzer()
    key_reg_loc = store.put_json_artifact("smart_ads/key_authorization_registry/v1", {"$schema": "smart_ads/key_authorization_registry/v1", "keys": [_KEY_ID]})
    head_loc, manifest_loc, _, _ = _build_real_decomposition_artifacts(store, key_reg_loc)
    run_loc, _, _ = _build_run_and_merge_artifacts(store, key_reg_loc, release_sha="e" * 40, reviewed_sha="d" * 40)
    con_s, con_loc, rel_s, rel_loc, seam_bytes = _build_legacy_seam_artifacts(store, key_reg_loc, run_loc, head_loc, manifest_loc)
    can = _build_canonical_chain_in_store(store, key_reg_loc, run_loc)
    cons = _build_consumer_artifacts(store, key_reg_loc, run_loc)

    assert verify_ibvi_ads_delegation_contract(cons["del_loc"], conductor_raw_bytes=cons["cond_bytes"], store=store, signature_verifier=verifier) == cons["del_s"]
    assert verify_consumer_feature_flag_contract(
        cons["ff_loc"], adapter_raw_bytes=cons["adp_bytes"], feature_flag_raw_bytes=cons["flag_bytes"],
        conductor_raw_bytes=cons["cond_bytes"], routing_analyzer=analyzer, store=store, signature_verifier=verifier,
    ) == cons["ff_s"]
    assert verify_consumer_deployment_readback(
        cons["rb_loc"], max_clock_uncertainty_ms=500, max_capture_age_seconds=60,
        conductor_raw_bytes=cons["cond_bytes"], routing_analyzer=analyzer, store=store, signature_verifier=verifier,
    ) == cons["rb_s"]
    with pytest.raises(ClosedValidationError):
        verify_consumer_deployment_readback(
            cons["rb_loc"], max_clock_uncertainty_ms=100, max_capture_age_seconds=60,
            conductor_raw_bytes=cons["cond_bytes"], routing_analyzer=analyzer, store=store, signature_verifier=verifier,
        )

    cons_dig = compute_consumer_contract_digest(
        adapter_git_artifact=cons["ff_s"].adapter_git_artifact, feature_flag_git_artifact=cons["ff_s"].feature_flag_git_artifact,
        resolved_feature_flag_contract_envelope=store.get_json_artifact(cons["ff_loc"]),
        resolved_delegation_contract_envelope=store.get_json_artifact(cons["del_loc"]),
    )
    target = TripartiteTarget(
        TripartiteLegacySide("mbras-tech/mbras-campaigns", rel_s.protected_release_identity.commit_sha, rel_loc, rel_s.seam_git_artifact, con_loc, con_loc.content_digest),
        TripartiteCanonicalSide("aiconnai/smart-ads", can["commit_sha"], can["whl_obj"], can["whl_obj"].wheel_digest, can["prov_loc"]),
        TripartiteConsumerSide("limaronaldo/hermes-ronaldo", cons["c_sha"], cons["ff_s"].adapter_git_artifact, cons["ff_s"].feature_flag_git_artifact, cons["ff_loc"], cons["del_loc"], cons_dig),
    )
    assert verify_tripartite_target(
        target, expected_run_locator=run_loc, expected_active_decomposition_head_locator=head_loc,
        wheel_boundary_report_locator=can["bound_loc"], certification_7a_locator=can["cert7a_loc"],
        gov1_convergence_locator=can["conv_loc"], seam_raw_bytes=seam_bytes, conductor_raw_bytes=cons["cond_bytes"],
        adapter_raw_bytes=cons["adp_bytes"], feature_flag_raw_bytes=cons["flag_bytes"],
        routing_analyzer=analyzer, store=store, deployment_readback_locator=cons["rb_loc"], signature_verifier=verifier,
    ) == target
    # Also verify tripartite target without deployment_readback_locator (resolving raw bytes from store):
    assert verify_tripartite_target(
        target, expected_run_locator=run_loc, expected_active_decomposition_head_locator=head_loc,
        wheel_boundary_report_locator=can["bound_loc"], certification_7a_locator=can["cert7a_loc"],
        gov1_convergence_locator=can["conv_loc"], seam_raw_bytes=seam_bytes, conductor_raw_bytes=cons["cond_bytes"],
        routing_analyzer=analyzer, store=store, signature_verifier=verifier,
    ) == target


def test_negative_matrix_across_decomposition_parity_readback_and_tripartite() -> None:
    store, verifier = InMemoryCellObjectStore(), FullDomainP1Verifier()
    analyzer = Cpython312AstConsumerRoutingAnalyzer()
    key_reg_loc = store.put_json_artifact("smart_ads/key_authorization_registry/v1", {"$schema": "smart_ads/key_authorization_registry/v1", "keys": [_KEY_ID]})
    head_loc, manifest_loc, head_s, manifest_s = _build_real_decomposition_artifacts(store, key_reg_loc)
    run_loc, merge_loc, pol_dig = _build_run_and_merge_artifacts(store, key_reg_loc, release_sha="e" * 40, reviewed_sha="d" * 40)
    con_s, con_loc, rel_s, rel_loc, seam_bytes = _build_legacy_seam_artifacts(store, key_reg_loc, run_loc, head_loc, manifest_loc)
    can = _build_canonical_chain_in_store(store, key_reg_loc, run_loc)
    cons = _build_consumer_artifacts(store, key_reg_loc, run_loc)

    # Valid epoch-2 correction decomposition head superseding epoch-1 genesis:
    corr_u = {k: v for k, v in manifest_s.items() if k not in {"manifest_digest", "integrity"}}
    corr_u.update({"generated_at": "2026-09-08T00:00:00Z", "supersedes_manifest_locator": manifest_loc.to_dict(), "supersedes_digest": manifest_s["manifest_digest"], "correction_reason": "reason:refine"})
    corr_u["manifest_digest"] = gov_decomp.manifest_digest(corr_u)
    _, corr_loc = _put_signed_dict(store, corr_u, key_reg_loc)
    _, h2_loc = _put_signed_dict(store, {**head_s, "head_epoch": 2, "active_manifest_locator": corr_loc.to_dict(), "active_manifest_digest": corr_loc.content_digest, "previous_head_locator": head_loc.to_dict(), "previous_head_digest": head_loc.content_digest, "update_kind": "correction"}, key_reg_loc)
    h2_out, _ = verify_stored_decomposition_tip(store, head_locator=h2_loc, expected_active_head_locator=h2_loc, manifest_locator=corr_loc, expected_manifest_digest=corr_loc.content_digest, signature_verifier=verifier)
    assert h2_out["head_epoch"] == 2

    # Failed CI & wrong review head in merge evidence must fail closed:
    merge_raw = store.get_json_artifact(merge_loc)
    for patch in ({"required_ci_results": [{"check": "pytest", "status": "failure"}]}, {"exact_head_review_evidence": [{"reviewer": "r", "reviewed_head_sha": "0" * 40, "state": "APPROVED"}]}):
        _, bad_m = _put_signed_dict(store, {**merge_raw, **patch}, key_reg_loc)
        with pytest.raises(ClosedValidationError):
            verify_stored_legacy_merge_evidence(store, bad_m, expected_repository="mbras-tech/mbras-campaigns", expected_protected_ref="main", expected_pr_number=77, expected_reviewed_head_sha="d" * 40, expected_protected_merge_sha="e" * 40, expected_adr_git_identity=_ADR_IDENTITY, expected_branch_policy_digest=pol_dig, signature_verifier=verifier)

    # Stale capture age & out-of-window captured_at_utc on readback must fail closed:
    with pytest.raises(ClosedValidationError):
        verify_consumer_deployment_readback(cons["rb_loc"], max_clock_uncertainty_ms=500, max_capture_age_seconds=2, conductor_raw_bytes=cons["cond_bytes"], routing_analyzer=analyzer, store=store, signature_verifier=verifier)

    # Swapped role consumer_contract_digest on tripartite target must fail closed:
    swapped_dig = compute_consumer_contract_digest(adapter_git_artifact=cons["ff_s"].feature_flag_git_artifact, feature_flag_git_artifact=cons["ff_s"].adapter_git_artifact, resolved_feature_flag_contract_envelope=store.get_json_artifact(cons["ff_loc"]), resolved_delegation_contract_envelope=store.get_json_artifact(cons["del_loc"]))
    bad_target = TripartiteTarget(
        TripartiteLegacySide("mbras-tech/mbras-campaigns", rel_s.protected_release_identity.commit_sha, rel_loc, rel_s.seam_git_artifact, con_loc, con_loc.content_digest),
        TripartiteCanonicalSide("aiconnai/smart-ads", can["commit_sha"], can["whl_obj"], can["whl_obj"].wheel_digest, can["prov_loc"]),
        TripartiteConsumerSide("limaronaldo/hermes-ronaldo", cons["c_sha"], cons["ff_s"].adapter_git_artifact, cons["ff_s"].feature_flag_git_artifact, cons["ff_loc"], cons["del_loc"], swapped_dig),
    )
    with pytest.raises(ClosedValidationError):
        verify_tripartite_target(bad_target, expected_run_locator=run_loc, expected_active_decomposition_head_locator=head_loc, wheel_boundary_report_locator=can["bound_loc"], certification_7a_locator=can["cert7a_loc"], gov1_convergence_locator=can["conv_loc"], seam_raw_bytes=seam_bytes, conductor_raw_bytes=cons["cond_bytes"], routing_analyzer=analyzer, store=store, signature_verifier=verifier)


def test_task4_modules_pure_layer_ast_and_application_exports() -> None:
    expected_exports = (
        "build_seam_parity_record", "verify_consumer_deployment_readback", "verify_consumer_feature_flag_contract",
        "verify_git_commit_parent_chain", "verify_ibvi_ads_delegation_contract", "verify_legacy_seam_contract",
        "verify_legacy_seam_release", "verify_seam_parity_record", "verify_stored_canonical_build_chain",
        "verify_stored_decomposition_tip", "verify_stored_deployment_config_result",
        "verify_stored_legacy_merge_evidence", "verify_stored_migration_run_context", "verify_tripartite_target",
    )
    for sym in expected_exports:
        assert sym in application_pkg.__all__ and callable(getattr(application_pkg, sym))

    for mod, rel_name in (
        (predecessor_validators_mod, "smart_ads/application/predecessor_validators.py"),
        (seam_parity_mod, "smart_ads/application/seam_parity.py"),
        (consumer_verification_mod, "smart_ads/application/consumer_verification.py"),
    ):
        src = Path(mod.__file__).read_text(encoding="utf-8")
        lines = src.splitlines()
        assert len(lines) <= 800
        assert scan_pure_layer_ast_violations(src, filename=rel_name) == []
        assert gov1_wheel._scan_wheel_python_ast_violations(src, filename=rel_name) == []
        tree = ast.parse(src, filename=rel_name)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                start = min([node.lineno, *(d.lineno for d in node.decorator_list)])
                assert (node.end_lineno or node.lineno) - start + 1 <= 49
