"""Unit and replay tests for `smart_ads/certification_7a_record/v1` and 7A fixtures."""
from __future__ import annotations

import base64
from collections.abc import Mapping
import copy
from dataclasses import dataclass, replace
import hashlib
import io
from pathlib import Path
from typing import Any
import zipfile

import pytest

from smart_ads.adapters.pipeboard import PipeboardFixtureAdapter, PrivatePipeboardBindingBoundary
from smart_ads.analytics.lattice import RegressionFixtureV1
from smart_ads.application import admit_collection, evaluate_fixture_collection
from smart_ads.contracts.git_provenance import (
    GitArtifactProvenance, compute_git_blob_oid, sort_git_provenance_locators,
)
from smart_ads.contracts.jcs import (
    ADR_P1_DOMAIN_PREFIXES, ArtifactLocator, canonicalize_jcs,
    jcs_sha256, loads_strict_json, p1_content_digest,
)
from smart_ads.contracts.negative_security import (
    MANDATORY_7A_NEGATIVE_CASES, PINNED_7A_NEGATIVE_SUITE_DIGEST,
    NegativeSecurityCase, NegativeSecurityRun, NegativeSecurityTestReport,
    SandboxResourceLimits, SandboxRuntimeReadback, SandboxTermination,
    SandboxUsageCounters, compute_negative_run_execution_binding_digest,
)
from smart_ads.contracts.scalars import ClosedValidationError
from smart_ads.contracts.schemas import (
    CollectionRequest, DateRange, PurposePrerequisiteLocators,
    RetrievalContext, compute_schema_bundle_digest,
)
from smart_ads.domain.pipeboard_contract import (
    FORBIDDEN_PIPEBOARD_ARGUMENTS, PINNED_LEGACY_COMMIT, PINNED_LEGACY_REPO,
    PINNED_PIPEBOARD_D26_SPECS, PIPEBOARD_PHASE1_METRIC_SOURCE_MAPPINGS,
    LegacySourcePacket, PinnedGitArtifactMember, PinnedUpstreamReference,
    PipeboardPhase1Contract, PipeboardTransportLimits,
)
from smart_ads.domain.registry import (
    AuthorizedScopeRelation, DriverCapabilityEntry, ExpectedResourceInventory,
    ExpectedResourceKey, PrivateRegistrySnapshot, RegistryBinding,
)
from smart_ads.domain.resource_ref import TenantResourceKeyHandle
from smart_ads.ports.cell_runtime import (
    CellRuntimePorts, ClockAttestation, ResolvedClockState,
    ResolvedPrerequisiteBundle, ResolvedRegistryState, TimezoneRuleSnapshot,
)
from smart_ads.ports.provider import ExternalIOCounters
import smart_ads.reconciliation as reconciliation_pkg
from smart_ads.reconciliation.certification_7a import (
    ADAPTER_ARTIFACT_PATHS, CERTIFICATION_7A_RECORD_SCHEMA, CORPUS_GIT_PATH,
    MAPPING_ARTIFACT_PATHS, PARSER_ARTIFACT_PATHS, PIPEBOARD_7A_CORPUS_SCHEMA,
    Certification7ACapabilityBinding, Certification7AFixtureCase,
    Certification7AFixtureEvidence, Certification7ARecord,
    compute_7a_case_execution_binding_digest, compute_adapter_code_digest,
    compute_mapping_rules_digest, compute_parser_code_digest,
    verify_certification_7a_record,
)
from tests.unit.test_negative_security_7a import (
    _DENIAL_OBSERVATIONS, _SPEC_17_KEYS, _make_readback, _resource_run_specs,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES_DIR = REPO_ROOT / "tests" / "certification_7a" / "fixtures"
PINNED_D26_PATH = FIXTURES_DIR / "pinned_d26c73d_blobs.json"
CORPUS_PATH = FIXTURES_DIR / "pipeboard_7a_corpus_v1.json"

_SIG_B64 = base64.b64encode(b"\x22" * 64).decode("ascii")
_KEY_ID = "key:ed25519:" + ("a" * 64)
_KEY_REG_LOC = ArtifactLocator.from_digest(
    "smart_ads/key_authorization_registry/v1", "sha256:" + ("b" * 64)
)
_RUN_CTX_LOC = ArtifactLocator.from_digest(
    "smart_ads/migration_run_context/v1", "sha256:" + ("c" * 64)
)
_OCI_DIGEST = "sha256:" + ("1" * 64)
_RUNNER_DIGEST = "sha256:" + ("2" * 64)
_BACKEND_DIGEST = "sha256:" + ("4" * 64)
_PYPROJECT_DIGEST = "sha256:" + ("6" * 64)
_UVLOCK_DIGEST = "sha256:" + ("7" * 64)
_COMMIT_SHA = "abcde" * 8
_TREE_OID = "12345" * 8
_BUILD_RUN_ID = "build-run-7a-cert-001"
_RECORD_REL_PATH = "smart_ads-0.1.0.dist-info/RECORD"


@dataclass(frozen=True)
class Valid7AWorld:
    record: Certification7ARecord
    negative_report: NegativeSecurityTestReport
    store: dict[ArtifactLocator, dict[str, Any]]
    wheel_bytes: bytes
    wheel_members: dict[str, bytes]
    corpus_bytes: bytes
    resolved_git_blobs: dict[str, bytes]
    resolved_d26_blobs: dict[str, bytes]
    sbx_spec_digest: str
    bound_prov_locator: ArtifactLocator


def _build_deterministic_wheel_archive(
    git_blobs: Mapping[str, bytes],
    *,
    overrides: Mapping[str, bytes] | None = None,
    include_record: bool = True,
    patch_cd_flag_bits: int = 0,
) -> tuple[bytes, dict[str, bytes]]:
    members: dict[str, bytes] = {
        src_path[4:]: raw for src_path, raw in sorted(git_blobs.items()) if src_path.startswith("src/")
    }
    if overrides:
        members.update(overrides)
    if include_record:
        rec_lines = [
            f"{rel},sha256={base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).rstrip(b'=').decode('ascii')},{len(raw)}"
            for rel, raw in sorted(members.items())
        ]
        rec_lines.append(f"{_RECORD_REL_PATH},,")
        members[_RECORD_REL_PATH] = ("\n".join(rec_lines) + "\n").encode("utf-8")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w") as zf:
        for rel_path, raw in sorted(members.items()):
            info = zipfile.ZipInfo(filename=rel_path, date_time=(2026, 9, 7, 10, 0, 5))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            zf.writestr(info, raw)
    raw_whl = bytearray(buf.getvalue())
    if patch_cd_flag_bits:
        cd_off = int.from_bytes(raw_whl[-6:-2], "little")
        cur_flags = int.from_bytes(raw_whl[cd_off + 8 : cd_off + 10], "little")
        raw_whl[cd_off + 8 : cd_off + 10] = (cur_flags | patch_cd_flag_bits).to_bytes(2, "little")
    return bytes(raw_whl), members


def _sign_env(unsigned: dict[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(unsigned)
    out["integrity"] = {"key_id": _KEY_ID, "key_registry_snapshot_locator": _KEY_REG_LOC.to_dict()}
    out["integrity"]["content_digest"] = p1_content_digest(out)
    out["integrity"]["signature_base64"] = _SIG_B64
    return out


def _put_signed(
    store: dict[ArtifactLocator, dict[str, Any]], unsigned: dict[str, Any]
) -> tuple[ArtifactLocator, dict[str, Any]]:
    signed = _sign_env(unsigned)
    loc = ArtifactLocator.for_canonical_bytes(signed["$schema"], canonicalize_jcs(signed))
    store[loc] = signed
    return loc, signed


def _load_d26_and_git_blobs() -> tuple[bytes, dict[str, bytes], dict[str, bytes]]:
    d26_doc = loads_strict_json(PINNED_D26_PATH.read_bytes())
    d26_blobs = {
        rel_path: base64.b64decode(d26_doc["blobs"][f"{role}__{Path(rel_path).name}"])
        for role, rel_path, _, _ in PINNED_PIPEBOARD_D26_SPECS
    }
    corpus_bytes = CORPUS_PATH.read_bytes()
    smart_ads_paths = [
        p for r, p in (*PARSER_ARTIFACT_PATHS, *ADAPTER_ARTIFACT_PATHS, *MAPPING_ARTIFACT_PATHS)
        if r == "aiconnai/smart-ads"
    ]
    git_blobs = {p: (REPO_ROOT / p).read_bytes() for p in smart_ads_paths}
    git_blobs[CORPUS_GIT_PATH[1]] = corpus_bytes
    return corpus_bytes, git_blobs, d26_blobs


def _build_neg_cases(sbx_digest: str, whl_digest: str) -> tuple[NegativeSecurityCase, ...]:
    out: list[NegativeSecurityCase] = []
    for c_idx, cid in enumerate(MANDATORY_7A_NEGATIVE_CASES):
        if cid in _DENIAL_OBSERVATIONS:
            specs = [(True, SandboxUsageCounters(cpu_time_us=1000, pids_peak=1), SandboxTermination("clean_exit", False, 0, None, 40, 0, True, False), _DENIAL_OBSERVATIONS[cid])]
        else:
            specs = _resource_run_specs(cid)
        runs: list[NegativeSecurityRun] = []
        for s_idx, (seccomp, usage, term, obs) in enumerate(specs):
            draft = NegativeSecurityRun(
                f"sandbox:neg-{c_idx:02d}-{s_idx}", "sha256:" + ("0" * 64),
                "2026-09-07T10:00:06Z", "2026-09-07T10:00:10Z",
                _make_readback(seccomp_enforced=seccomp), SandboxResourceLimits.canonical(),
                usage, term, obs,
            )
            bind = compute_negative_run_execution_binding_digest(
                case_id=cid, subrun_index=s_idx, run=draft, wheel_digest=whl_digest,
                test_suite_digest=PINNED_7A_NEGATIVE_SUITE_DIGEST, sealed_sandbox_profile_digest=sbx_digest,
            )
            runs.append(replace(draft, execution_binding_digest=bind))
        out.append(NegativeSecurityCase(cid, "passed", tuple(runs)))
    return tuple(out)


def _stage_sandbox_and_wheel_envelopes(
    store: dict[ArtifactLocator, dict[str, Any]], *, wheel_bytes: bytes,
    commit_sha: str, build_run_id: str, sbx_until_utc: str = "2027-01-01T00:00:00Z",
) -> tuple[ArtifactLocator, ArtifactLocator, ArtifactLocator, str, str, str]:
    whl_digest = "sha256:" + hashlib.sha256(wheel_bytes).hexdigest()
    schema_digest = compute_schema_bundle_digest()
    rb_dict = _make_readback(seccomp_enforced=True).to_dict()
    spec_17 = {k: rb_dict[k] for k in _SPEC_17_KEYS if k in rb_dict}
    spec_17["resource_limits"] = SandboxResourceLimits.canonical().to_dict()
    sbx_spec_digest = jcs_sha256(spec_17)
    sbx_loc, _ = _put_signed(store, {
        "$schema": "smart_ads/sealed_sandbox_profile/v1", **spec_17,
        "migration_run_context_locator": _RUN_CTX_LOC.to_dict(),
        "issued_at_utc": "2026-09-07T10:00:00Z",
        "validity": {"from": "2026-01-01T00:00:00Z", "until": sbx_until_utc},
    })
    prov_loc, _ = _put_signed(store, {
        "$schema": "smart_ads/wheel_build_provenance/v1",
        "migration_run_context_locator": _RUN_CTX_LOC.to_dict(), "build_run_id": build_run_id,
        "built_at_utc": "2026-09-07T10:00:05Z", "repository": "aiconnai/smart-ads",
        "source_commit_sha": commit_sha, "source_tree_oid": _TREE_OID, "source_date_epoch": 1_700_000_000,
        "python_abi_tag": "cp312", "build_backend": "hatchling.build", "build_backend_version": "1.33.0",
        "build_backend_digest": _BACKEND_DIGEST, "pyproject_sha256": _PYPROJECT_DIGEST,
        "uv_lock_sha256": _UVLOCK_DIGEST, "schema_bundle_digest": schema_digest, "wheel_digest": whl_digest,
        "wheel": {"$schema": "smart_ads/wheel_object_locator/v1", "store_kind": "cell_immutable_object", "object_ref": f"cell-object:{whl_digest}", "wheel_digest": whl_digest, "size_bytes": len(wheel_bytes)},
    })
    entries = [{"path": _RECORD_REL_PATH, "record_hash": "", "record_size": None}]
    bound_loc, _ = _put_signed(store, {
        "$schema": "smart_ads/wheel_boundary_report/v1",
        "migration_run_context_locator": _RUN_CTX_LOC.to_dict(), "build_run_id": build_run_id,
        "verified_at_utc": "2026-09-07T10:00:10Z", "repository": "aiconnai/smart-ads",
        "source_commit_sha": commit_sha, "wheel_digest": whl_digest, "build_backend_digest": _BACKEND_DIGEST,
        "schema_bundle_digest": schema_digest, "sorted_record_entries": entries,
        "sorted_record_digest": jcs_sha256(entries), "archive_allowlist_passed": True,
        "ast_boundary_scan_passed": True, "isolated_venv_import_passed": True,
        "packaged_modules": ["smart_ads"], "wheel_build_provenance_locator": prov_loc.to_dict(),
    })
    return sbx_loc, prov_loc, bound_loc, sbx_spec_digest, whl_digest, schema_digest


def _stage_git_and_registry_envelopes(
    store: dict[ArtifactLocator, dict[str, Any]], *, commit_sha: str,
    git_blobs: dict[str, bytes], d26_blobs: dict[str, bytes], cap_state: str = "declared",
) -> tuple[ResolvedRegistryState, dict[tuple[str, str], tuple[ArtifactLocator, GitArtifactProvenance]]]:
    prov_map: dict[tuple[str, str], tuple[ArtifactLocator, GitArtifactProvenance]] = {}
    d26_members: list[PinnedGitArtifactMember] = []
    for role, rel_path, oid, sha in PINNED_PIPEBOARD_D26_SPECS:
        p = GitArtifactProvenance(PINNED_LEGACY_REPO, PINNED_LEGACY_COMMIT, rel_path, oid, sha, "2026-09-07T10:00:00Z")
        loc, signed = _put_signed(store, p.to_dict())
        prov_map[(PINNED_LEGACY_REPO, rel_path)] = (loc, GitArtifactProvenance.from_dict(signed, require_signed=True))
        d26_members.append(PinnedGitArtifactMember(role, PINNED_LEGACY_REPO, PINNED_LEGACY_COMMIT, rel_path, oid, sha, loc))
    for rel_path, raw in sorted(git_blobs.items()):
        p = GitArtifactProvenance(
            "aiconnai/smart-ads", commit_sha, rel_path, compute_git_blob_oid(raw),
            "sha256:" + hashlib.sha256(raw).hexdigest(), "2026-09-07T10:00:04Z",
        )
        loc, signed = _put_signed(store, p.to_dict())
        prov_map[("aiconnai/smart-ads", rel_path)] = (loc, GitArtifactProvenance.from_dict(signed, require_signed=True))
    drv_unsigned = PipeboardPhase1Contract(
        "driver-contract:pipeboard-phase1-v1", "pipeboard_hosted",
        LegacySourcePacket(PINNED_LEGACY_REPO, PINNED_LEGACY_COMMIT, tuple(d26_members)),
        PinnedUpstreamReference(), PipeboardTransportLimits(forbidden_arguments=FORBIDDEN_PIPEBOARD_ARGUMENTS),
        dict(PIPEBOARD_PHASE1_METRIC_SOURCE_MAPPINGS),
    )
    drv_loc, drv_signed = _put_signed(store, drv_unsigned.to_dict())
    drv = PipeboardPhase1Contract.from_dict(drv_signed, require_signed=True)
    snap_unsigned = PrivateRegistrySnapshot(
        "registry-snapshot:2026-09-07-001", "tenant:ibvi", "2026-09-07T10:00:00Z", "2027-01-01T00:00:00Z",
        "hmac-sha256-b32-v1", "key:7a-fixture-hmac-v1",
        (RegistryBinding("binding:meta-primary", "account:ibvi-01", "provider:pipeboard", "meta", "BRL", "pipeboard_hosted"),),
        (AuthorizedScopeRelation("front:ibvi", "profile:reader", "binding:meta-primary", "scope:campaigns-active"),),
        (DriverCapabilityEntry("cap:campaign-basic-v1", "1.0.0", "pipeboard_hosted", drv_loc, drv_loc.content_digest, "scope:campaigns-active", cap_state, ("metric:clicks_v1", "metric:impressions_v1", "metric:spend_v1")),),  # type: ignore[arg-type]
    )
    snap_loc, snap_signed = _put_signed(store, snap_unsigned.to_dict())
    return ResolvedRegistryState(snap_loc, PrivateRegistrySnapshot.from_dict(snap_signed, require_signed=True), drv_loc, drv), prov_map


@dataclass(frozen=True)
class _CasePorts:
    clk_state: ResolvedClockState
    tz_snap: TimezoneRuleSnapshot
    reg_state: ResolvedRegistryState
    prereq: ResolvedPrerequisiteBundle

    def get_authenticated_clock(self) -> ResolvedClockState: return self.clk_state
    def get_reporting_timezone_rules(self) -> TimezoneRuleSnapshot: return self.tz_snap
    def get_active_registry(self, *, tenant_ref: str) -> ResolvedRegistryState: return self.reg_state
    def resolve_prerequisites(self, **kw: Any) -> ResolvedPrerequisiteBundle: return self.prereq


def _run_single_corpus_case(
    idx: int, c: dict[str, Any], *, boundary: PrivatePipeboardBindingBoundary,
    reg_state: ResolvedRegistryState, tz_snap: TimezoneRuleSnapshot, inv_loc: ArtifactLocator,
    sbx_loc: ArtifactLocator, reg_fix_loc: ArtifactLocator,
    sbx_spec_digest: str, whl_digest: str, corpus_digest: str,
) -> Certification7AFixtureCase:
    att = ClockAttestation.from_dict(c["clock_reading"]["attestation"])
    att_loc = ArtifactLocator.for_canonical_bytes(ClockAttestation.SCHEMA, canonicalize_jcs(att.to_dict()))
    clk_state = ResolvedClockState(att_loc, att, c["clock_reading"]["configured_max_uncertainty_ms"])
    prereq = ResolvedPrerequisiteBundle(PurposePrerequisiteLocators("fixture_7a", sealed_sandbox_profile_locator=sbx_loc, regression_fixture_locator=reg_fix_loc))
    cp = _CasePorts(clk_state, tz_snap, reg_state, prereq)
    ports = CellRuntimePorts(cp, cp, cp, cp)
    req = CollectionRequest.from_dict(c["collection_request"])
    adm_bundle = admit_collection(req, ports, admission_id=c["admission_id"])
    adapter = PipeboardFixtureAdapter(boundary=boundary)
    hr = c["http_response"]
    adapter.register_fixture_case(
        admitted=adm_bundle.admitted, retrieval_context=RetrievalContext.from_dict(c["retrieval_context"]),
        network_ok=hr["network_ok"], http_status=hr["http_status"],
        headers=[(h[0], h[1]) for h in hr["headers"]], body_chunks=[hr["body_utf8"].encode("utf-8")],
    )
    ev = evaluate_fixture_collection(req, admission_id=c["admission_id"], cell_ports=ports, fixture_port=adapter, inventory_port=boundary)
    batch = adapter.get_recorded_batch(ev.admitted_locator)
    draft = Certification7AFixtureCase(
        c["case_id"], adm_bundle.locator.content_digest, inv_loc,
        f"opaque-driver-contract:{reg_state.driver_contract_locator.content_digest}",
        f"sandbox:pos-7a-{idx:02d}", "sha256:" + ("0" * 64),
        f"2026-09-07T10:00:{10 + idx:02d}Z", f"2026-09-07T10:00:{11 + idx:02d}Z",
        _make_readback(seccomp_enforced=True), SandboxResourceLimits.canonical(),
        SandboxUsageCounters(cpu_time_us=2500, pids_peak=1),
        SandboxTermination("clean_exit", False, 0, None, 25, 0, True, False),
        batch, c["expected_completeness_status"], ev.completeness.status, ev.completeness.normalized_fact_set_digest,
    )
    bind = compute_7a_case_execution_binding_digest(
        case=draft, wheel_digest=whl_digest, corpus_digest=corpus_digest, sealed_sandbox_profile_digest=sbx_spec_digest,
    )
    return replace(draft, execution_binding_digest=bind)


def _build_fixture_cases_from_corpus(
    store: dict[ArtifactLocator, dict[str, Any]], *, corpus_doc: dict[str, Any],
    reg_state: ResolvedRegistryState, sbx_loc: ArtifactLocator,
    sbx_spec_digest: str, whl_digest: str, corpus_digest: str,
) -> tuple[RegressionFixtureV1, tuple[Certification7AFixtureCase, ...]]:
    refs = sorted(p["resource_ref"] for p in corpus_doc["verified_campaign_pairs"])
    inv_unsigned = ExpectedResourceInventory(
        "inventory:7a-2026-09-06", reg_state.locator, reg_state.locator.content_digest,
        "tenant:ibvi", "binding:meta-primary", "account:ibvi-01", "scope:campaigns-active",
        DateRange("2026-09-06", "2026-09-06", True),
        tuple(ExpectedResourceKey("binding:meta-primary", "account:ibvi-01", r, "campaign", "2026-09-06") for r in refs),
    )
    inv_loc, inv_signed = _put_signed(store, inv_unsigned.to_dict())
    inv = ExpectedResourceInventory.from_dict(inv_signed, require_signed=True)
    kh = TenantResourceKeyHandle("tenant:ibvi", "key:7a-fixture-hmac-v1", bytes.fromhex(corpus_doc["tenant_hmac_key_hex"]))
    boundary = PrivatePipeboardBindingBoundary(
        resolved_registry=reg_state, key_handle=kh,
        private_account_bindings={("binding:meta-primary", "account:ibvi-01"): "act_5544332211"},
        authenticated_inventories=[(inv_loc, inv)],
    )
    for pair in corpus_doc["verified_campaign_pairs"]:
        boundary.register_verified_campaign_pair(pair["raw_campaign_id"], pair["resource_ref"])
    reg_fix = RegressionFixtureV1.canonical(reg_state.locator.content_digest)
    reg_fix_loc = ArtifactLocator.for_canonical_bytes(RegressionFixtureV1.SCHEMA, canonicalize_jcs(reg_fix.to_dict()))
    tz_snap = TimezoneRuleSnapshot.from_dict(corpus_doc["timezone_snapshot"])
    built = tuple(
        _run_single_corpus_case(
            idx, c, boundary=boundary, reg_state=reg_state, tz_snap=tz_snap, inv_loc=inv_loc,
            sbx_loc=sbx_loc, reg_fix_loc=reg_fix_loc, sbx_spec_digest=sbx_spec_digest,
            whl_digest=whl_digest, corpus_digest=corpus_digest,
        )
        for idx, c in enumerate(corpus_doc["cases"], start=1)
    )
    return reg_fix, built


def build_valid_7a_world(
    *, wheel_bytes: bytes | None = None, wheel_members: Mapping[str, bytes] | None = None,
    build_run_id: str = _BUILD_RUN_ID,
    neg_executed_at_utc: str = "2026-09-07T10:00:15Z", certified_at_utc: str = "2026-09-07T10:00:16Z",
) -> Valid7AWorld:
    store: dict[ArtifactLocator, dict[str, Any]] = {}
    corpus_bytes, git_blobs, d26_blobs = _load_d26_and_git_blobs()
    built_whl_bytes, built_whl_members = _build_deterministic_wheel_archive(git_blobs)
    eff_whl_bytes = built_whl_bytes if wheel_bytes is None else wheel_bytes
    eff_whl_members = dict(built_whl_members if wheel_members is None else wheel_members)
    corpus_doc = loads_strict_json(corpus_bytes)
    corpus_digest = "sha256:" + hashlib.sha256(corpus_bytes).hexdigest()
    sbx_loc, prov_loc, bound_loc, sbx_spec_digest, whl_digest, schema_digest = _stage_sandbox_and_wheel_envelopes(
        store, wheel_bytes=eff_whl_bytes, commit_sha=_COMMIT_SHA, build_run_id=build_run_id,
    )
    neg_unsigned = NegativeSecurityTestReport(
        _RUN_CTX_LOC, sbx_loc, prov_loc, build_run_id, neg_executed_at_utc, _COMMIT_SHA,
        _BACKEND_DIGEST, schema_digest, whl_digest, _OCI_DIGEST, _RUNNER_DIGEST,
        PINNED_7A_NEGATIVE_SUITE_DIGEST, SandboxResourceLimits.canonical(), _build_neg_cases(sbx_spec_digest, whl_digest),
    )
    neg_loc, neg_signed = _put_signed(store, neg_unsigned.to_dict())
    neg_rep = NegativeSecurityTestReport.from_dict(neg_signed, require_signed=True)
    reg_state, prov_map = _stage_git_and_registry_envelopes(
        store, commit_sha=_COMMIT_SHA, git_blobs=git_blobs, d26_blobs=d26_blobs,
    )
    reg_fix, cases = _build_fixture_cases_from_corpus(
        store, corpus_doc=corpus_doc, reg_state=reg_state, sbx_loc=sbx_loc,
        sbx_spec_digest=sbx_spec_digest, whl_digest=whl_digest, corpus_digest=corpus_digest,
    )
    cap = Certification7ACapabilityBinding(
        "cap:campaign-basic-v1", "scope:campaigns-active", "pipeboard_hosted",
        reg_state.driver_contract_locator, reg_state.driver_contract_locator.content_digest,
        reg_state.locator, ("metric:clicks_v1", "metric:impressions_v1", "metric:spend_v1"),
    )
    ev = Certification7AFixtureEvidence(prov_map[CORPUS_GIT_PATH][0], corpus_digest, reg_fix, cases)
    rec = Certification7ARecord(
        _RUN_CTX_LOC, sbx_loc, prov_loc, bound_loc, neg_loc, build_run_id,
        certified_at_utc, "fixture_certified", _COMMIT_SHA, _BACKEND_DIGEST,
        schema_digest, whl_digest, reg_state.snapshot.resource_mapping_contract_digest, cap,
        sort_git_provenance_locators([prov_map[k][0] for k in PARSER_ARTIFACT_PATHS]),
        compute_parser_code_digest([prov_map[k][1] for k in PARSER_ARTIFACT_PATHS]),
        sort_git_provenance_locators([prov_map[k][0] for k in ADAPTER_ARTIFACT_PATHS]),
        compute_adapter_code_digest([prov_map[k][1] for k in ADAPTER_ARTIFACT_PATHS]),
        sort_git_provenance_locators([prov_map[k][0] for k in MAPPING_ARTIFACT_PATHS]),
        compute_mapping_rules_digest([prov_map[k][1] for k in MAPPING_ARTIFACT_PATHS], reg_state.driver_contract.metric_source_mappings),
        ev,
    )
    return Valid7AWorld(rec, neg_rep, store, eff_whl_bytes, eff_whl_members, corpus_bytes, git_blobs, d26_blobs, sbx_spec_digest, prov_loc)


def _verify_world(w: Valid7AWorld, **overrides: Any) -> None:
    kw: dict[str, Any] = {
        "object_resolver": w.store.__getitem__,
        "wheel_bytes": w.wheel_bytes,
        "wheel_members": w.wheel_members,
        "corpus_bytes": w.corpus_bytes,
        "resolved_git_blobs": w.resolved_git_blobs,
        "resolved_d26_blobs": w.resolved_d26_blobs,
    }
    rec = overrides.pop("record", w.record)
    kw.update(overrides)
    verify_certification_7a_record(rec, **kw)


def test_fixtures_line_budgets_and_pinned_d26_hashes() -> None:
    assert len(PINNED_D26_PATH.read_text(encoding="utf-8").splitlines()) <= 40
    assert len(CORPUS_PATH.read_text(encoding="utf-8").splitlines()) <= 450
    d26_doc = loads_strict_json(PINNED_D26_PATH.read_bytes())
    assert d26_doc["schema"] == "smart_ads/test_pinned_d26c73d_blobs/v1"
    assert d26_doc["commit_sha"] == PINNED_LEGACY_COMMIT
    for role, rel_path, exp_oid, exp_sha in PINNED_PIPEBOARD_D26_SPECS:
        raw = base64.b64decode(d26_doc["blobs"][f"{role}__{Path(rel_path).name}"])
        assert compute_git_blob_oid(raw) == exp_oid
        assert "sha256:" + hashlib.sha256(raw).hexdigest() == exp_sha
    corpus_doc = loads_strict_json(CORPUS_PATH.read_bytes())
    assert corpus_doc["$schema"] == PIPEBOARD_7A_CORPUS_SCHEMA
    assert [c["case_id"] for c in corpus_doc["cases"]] == [
        "case_01_complete_two_campaigns", "case_02_failed_http_401",
        "case_03_partial_date_mismatch", "case_04_partial_non_empty_paging_next",
    ]


def test_record_schema_p1_roundtrip_and_forbids_generation() -> None:
    w = build_valid_7a_world()
    assert Certification7ARecord.SCHEMA == CERTIFICATION_7A_RECORD_SCHEMA
    assert ADR_P1_DOMAIN_PREFIXES[CERTIFICATION_7A_RECORD_SCHEMA] == "SMART-ADS:CERTIFICATION-7A:V1\n"
    assert len(Certification7ARecord.CORE_KEYS) == 22
    assert len(Certification7ARecord.KEYS) == 23
    assert "generation" not in Certification7ARecord.KEYS
    assert Certification7ARecord.from_dict(w.record.to_dict()) == w.record
    with pytest.raises(ClosedValidationError):
        Certification7ARecord.from_dict({**w.record.to_dict(), "generation": 1})
    signed_dict = _sign_env(w.record.to_dict())
    assert Certification7ARecord.from_dict(signed_dict, require_signed=True).to_dict() == signed_dict
    with pytest.raises(ClosedValidationError):
        Certification7ARecord.from_dict({**signed_dict, "certified_at_utc": "2026-09-07T10:00:17Z"}, require_signed=True)


def test_code_and_mapping_digests_are_invariant_to_resolved_at_and_integrity() -> None:
    _, git_blobs, d26_blobs = _load_d26_and_git_blobs()
    store: dict[ArtifactLocator, dict[str, Any]] = {}
    reg_state, prov_map = _stage_git_and_registry_envelopes(
        store, commit_sha=_COMMIT_SHA, git_blobs=git_blobs, d26_blobs=d26_blobs,
    )
    p_signed = [prov_map[k][1] for k in PARSER_ARTIFACT_PATHS]
    p_alt = [replace(p, resolved_at_utc="2026-10-01T00:00:00Z", integrity=None) for p in reversed(p_signed)]
    assert compute_parser_code_digest(p_signed) == compute_parser_code_digest(p_alt)
    with pytest.raises(ClosedValidationError):
        compute_parser_code_digest(p_signed[:2])
    with pytest.raises(ClosedValidationError):
        compute_adapter_code_digest([*p_signed[:2]])
    m_signed = [prov_map[k][1] for k in MAPPING_ARTIFACT_PATHS]
    d1 = compute_mapping_rules_digest(m_signed, reg_state.driver_contract.metric_source_mappings)
    alt_mappings = {**dict(reg_state.driver_contract.metric_source_mappings), "metric:clicks_v1": "source-metric:provider:pipeboard.clicks:v2"}
    assert compute_mapping_rules_digest(m_signed, alt_mappings) != d1


def test_subobject_invariants_reject_malformed_cases_and_evidence() -> None:
    w = build_valid_7a_world()
    c0_dict = w.record.fixture_evidence.cases[0].to_dict()
    for mut_key, mut_val in (
        ("observed_completeness_status", "partial"),
        ("normalized_fact_set_digest", None),
        ("source_contract_ref", "opaque-driver-contract:bad"),
        ("started_at_utc", "2026-09-07T10:00:15Z"),
    ):
        with pytest.raises(ClosedValidationError):
            Certification7AFixtureCase.from_dict({**c0_dict, mut_key: mut_val})
    bad_io = copy.deepcopy(c0_dict)
    bad_io["observation_batch"]["io_counters"] = ExternalIOCounters(credential_lookups=1).to_dict()
    with pytest.raises(ClosedValidationError):
        Certification7AFixtureCase.from_dict(bad_io)
    bad_breach = copy.deepcopy(c0_dict)
    bad_breach["usage"]["cpu_time_us"] = 120_000_000
    with pytest.raises(ClosedValidationError):
        Certification7AFixtureCase.from_dict(bad_breach)
    ev_dict = w.record.fixture_evidence.to_dict()
    with pytest.raises(ClosedValidationError):
        Certification7AFixtureEvidence.from_dict({**ev_dict, "cases": ev_dict["cases"][:2]})


def test_positive_replay_c1_build_run_id_and_reconciliation_reexports() -> None:
    w = build_valid_7a_world()
    _verify_world(w, boundary_report_wheel_provenance_locator=w.bound_prov_locator)
    w_c1 = build_valid_7a_world(build_run_id="build\x80run-7a")
    _verify_world(w_c1)
    for sym in (
        "Certification7ARecord", "Certification7ACapabilityBinding",
        "Certification7AFixtureCase", "Certification7AFixtureEvidence",
        "verify_certification_7a_record", "PARSER_ARTIFACT_PATHS",
    ):
        assert hasattr(reconciliation_pkg, sym) and sym in reconciliation_pkg.__all__


def test_verifier_enforces_wheel_zip_central_directory_and_member_binding() -> None:
    # (a) Non-ZIP wheel_bytes rejected even when wheel_digest matches across all Stage 7/7A envelopes
    w_nonzip = build_valid_7a_world(wheel_bytes=b"PK\x03\x04non-zip-payload-without-eocd")
    with pytest.raises(ClosedValidationError, match="wheel"):
        _verify_world(w_nonzip)

    # (b) wheel_members forged to disagree with wheel_bytes central-directory CRC-32/size or key set
    w = build_valid_7a_world()
    wire_rel = "smart_ads/adapters/pipeboard/wire.py"
    orig_wire = w.wheel_members[wire_rel]
    same_len_flip = bytes([orig_wire[0] ^ 0x01]) + orig_wire[1:]
    for bad_members in (
        {**w.wheel_members, wire_rel: orig_wire + b"\n"},
        {**w.wheel_members, wire_rel: same_len_flip},
        {k: v for k, v in w.wheel_members.items() if k != wire_rel},
        {**w.wheel_members, "smart_ads/extra.py": b"# extra\n"},
    ):
        with pytest.raises(ClosedValidationError, match="wheel_members"):
            _verify_world(w, wheel_members=bad_members)

    # Missing dist-info/RECORD, forbidden ZIP bitflags (bit 0 / bit 3), or traversal/dir member names
    no_rec_bytes, no_rec_members = _build_deterministic_wheel_archive(w.resolved_git_blobs, include_record=False)
    with pytest.raises(ClosedValidationError, match="RECORD"):
        _verify_world(build_valid_7a_world(wheel_bytes=no_rec_bytes, wheel_members=no_rec_members))
    for bad_kw in (
        {"patch_cd_flag_bits": 0x01},
        {"patch_cd_flag_bits": 0x08},
        {"overrides": {"../evil.py": b"x"}},
        {"overrides": {"smart_ads/dir/": b""}},
    ):
        bad_b, bad_m = _build_deterministic_wheel_archive(w.resolved_git_blobs, **bad_kw)  # type: ignore[arg-type]
        with pytest.raises(ClosedValidationError, match="wheel"):
            _verify_world(build_valid_7a_world(wheel_bytes=bad_b, wheel_members=bad_m))

    # (c) Real .whl archive (matching wheel_digest + matching wheel_members) whose Python member != git_blobs
    tampered_whl, tampered_members = _build_deterministic_wheel_archive(
        w.resolved_git_blobs, overrides={wire_rel: orig_wire + b"\n# tampered inside wheel\n"}
    )
    w_divergent = build_valid_7a_world(wheel_bytes=tampered_whl, wheel_members=tampered_members)
    with pytest.raises(ClosedValidationError, match="wheel_members"):
        _verify_world(w_divergent)


def test_verifier_rejects_non_declared_state_and_rmc_digest_mismatch() -> None:
    w = build_valid_7a_world()
    bad_rmc = Certification7ARecord.from_dict({**w.record.to_dict(), "resource_mapping_contract_digest": "sha256:" + ("e" * 64)})
    with pytest.raises(ClosedValidationError):
        _verify_world(w, record=bad_rmc)
    store2 = dict(w.store)
    reg_fc, _ = _stage_git_and_registry_envelopes(
        store2, commit_sha=_COMMIT_SHA, git_blobs=w.resolved_git_blobs,
        d26_blobs=w.resolved_d26_blobs, cap_state="fixture_certified",
    )
    cap_fc = replace(w.record.capability, registry_snapshot_locator=reg_fc.locator)
    ev_fc = replace(w.record.fixture_evidence, regression_fixture=RegressionFixtureV1.canonical(reg_fc.locator.content_digest))
    with pytest.raises(ClosedValidationError):
        _verify_world(w, record=replace(w.record, capability=cap_fc, fixture_evidence=ev_fc), object_resolver=store2.__getitem__)


def test_verifier_checks_admitted_digest_before_execution_binding_digest() -> None:
    w = build_valid_7a_world()
    c0 = w.record.fixture_evidence.cases[0]
    forged_draft = replace(c0, admitted_collection_digest="sha256:" + ("f" * 64))
    forged_bind = compute_7a_case_execution_binding_digest(
        case=forged_draft, wheel_digest=w.record.wheel_digest,
        corpus_digest=w.record.fixture_evidence.corpus_digest, sealed_sandbox_profile_digest=w.sbx_spec_digest,
    )
    forged_case = replace(forged_draft, execution_binding_digest=forged_bind)
    bad_rec = replace(w.record, fixture_evidence=replace(w.record.fixture_evidence, cases=(forged_case, *w.record.fixture_evidence.cases[1:])))
    with pytest.raises(ClosedValidationError, match="admitted_collection_digest"):
        _verify_world(w, record=bad_rec)


def test_verifier_rejects_regression_fixture_and_inventory_date_mismatch() -> None:
    w = build_valid_7a_world()
    rec_dict = w.record.to_dict()
    rec_dict["fixture_evidence"]["regression_fixture"] = RegressionFixtureV1.canonical("sha256:" + ("9" * 64)).to_dict()
    with pytest.raises(ClosedValidationError):
        Certification7ARecord.from_dict(rec_dict)

    store_bad_inv = dict(w.store)
    old_inv = ExpectedResourceInventory.from_dict(store_bad_inv[w.record.fixture_evidence.cases[0].expected_resource_inventory_locator])
    wrong_day_inv = ExpectedResourceInventory(
        "inventory:7a-2026-09-05", old_inv.registry_snapshot_locator, old_inv.registry_snapshot_digest,
        old_inv.tenant_ref, old_inv.binding_ref, old_inv.account_ref, old_inv.resource_scope_ref,
        DateRange("2026-09-05", "2026-09-05", True),
        tuple(replace(r, metric_date="2026-09-05") for r in old_inv.expected_resources),
    )
    wrong_inv_loc, _ = _put_signed(store_bad_inv, wrong_day_inv.to_dict())
    c0_wrong = replace(w.record.fixture_evidence.cases[0], expected_resource_inventory_locator=wrong_inv_loc)
    bad_rec = replace(w.record, fixture_evidence=replace(w.record.fixture_evidence, cases=(c0_wrong, *w.record.fixture_evidence.cases[1:])))
    with pytest.raises(ClosedValidationError):
        _verify_world(w, record=bad_rec, object_resolver=store_bad_inv.__getitem__)


def test_verifier_rejects_cross_scope_hmac_and_batch_tampering() -> None:
    w = build_valid_7a_world()
    for field_mut in ("scope", "hmac"):
        corpus_doc = loads_strict_json(w.corpus_bytes)
        if field_mut == "scope":
            corpus_doc["cases"][0]["collection_request"]["resource_scope_ref"] = "scope:other-scope"
        else:
            corpus_doc["tenant_hmac_key_hex"] = "ff" * 32
        bad_bytes = canonicalize_jcs(corpus_doc)
        store2 = dict(w.store)
        p = GitArtifactProvenance(
            CORPUS_GIT_PATH[0], _COMMIT_SHA, CORPUS_GIT_PATH[1], compute_git_blob_oid(bad_bytes),
            "sha256:" + hashlib.sha256(bad_bytes).hexdigest(), "2026-09-07T10:00:04Z",
        )
        c_loc, _ = _put_signed(store2, p.to_dict())
        bad_ev = replace(w.record.fixture_evidence, corpus_git_locator=c_loc, corpus_digest=p.file_content_sha256)
        with pytest.raises(ClosedValidationError):
            _verify_world(
                w, record=replace(w.record, fixture_evidence=bad_ev), object_resolver=store2.__getitem__,
                corpus_bytes=bad_bytes, resolved_git_blobs={**w.resolved_git_blobs, CORPUS_GIT_PATH[1]: bad_bytes},
            )

    c1 = w.record.fixture_evidence.cases[1]
    alt_draft = replace(c1, observation_batch=replace(c1.observation_batch, retrieval_context=replace(c1.observation_batch.retrieval_context, adapter_version="tampered/9.9.9")))
    alt_bind = compute_7a_case_execution_binding_digest(
        case=alt_draft, wheel_digest=w.record.wheel_digest,
        corpus_digest=w.record.fixture_evidence.corpus_digest, sealed_sandbox_profile_digest=w.sbx_spec_digest,
    )
    cases_t = (w.record.fixture_evidence.cases[0], replace(alt_draft, execution_binding_digest=alt_bind), *w.record.fixture_evidence.cases[2:])
    with pytest.raises(ClosedValidationError):
        _verify_world(w, record=replace(w.record, fixture_evidence=replace(w.record.fixture_evidence, cases=cases_t)))


def test_verifier_rejects_sandbox_provenance_readback_and_chronology_violations() -> None:
    w_late = build_valid_7a_world(neg_executed_at_utc="2026-09-07T10:00:17Z", certified_at_utc="2026-09-07T10:00:16Z")
    with pytest.raises(ClosedValidationError):
        _verify_world(w_late)
    w = build_valid_7a_world()
    for bad_whl in (b"", w.wheel_bytes + b"x"):
        with pytest.raises(ClosedValidationError):
            _verify_world(w, wheel_bytes=bad_whl)
    wrong_prov = ArtifactLocator.from_digest("smart_ads/wheel_build_provenance/v1", "sha256:" + ("d" * 64))
    with pytest.raises(ClosedValidationError):
        _verify_world(w, boundary_report_wheel_provenance_locator=wrong_prov)
    c0_bad_rb = replace(w.record.fixture_evidence.cases[0], runtime_readback=SandboxRuntimeReadback.from_dict({**_make_readback().to_dict(), "oci_image_digest": "sha256:" + ("8" * 64)}))
    with pytest.raises(ClosedValidationError):
        _verify_world(w, record=replace(w.record, fixture_evidence=replace(w.record.fixture_evidence, cases=(c0_bad_rb, *w.record.fixture_evidence.cases[1:]))))
    c0_collide = replace(w.record.fixture_evidence.cases[0], sandbox_instance_ref="sandbox:neg-00-0")
    with pytest.raises(ClosedValidationError):
        _verify_world(w, record=replace(w.record, fixture_evidence=replace(w.record.fixture_evidence, cases=(c0_collide, *w.record.fixture_evidence.cases[1:]))))


def test_verifier_rejects_corpus_or_legacy_d26_blob_tampering() -> None:
    w = build_valid_7a_world()
    with pytest.raises(ClosedValidationError):
        _verify_world(w, corpus_bytes=b"{not-json")
    for _, rel_path, _, _ in PINNED_PIPEBOARD_D26_SPECS:
        missing_d26 = {k: v for k, v in w.resolved_d26_blobs.items() if k != rel_path}
        with pytest.raises(ClosedValidationError):
            _verify_world(w, resolved_d26_blobs=missing_d26)
        corrupt_d26 = {**w.resolved_d26_blobs, rel_path: w.resolved_d26_blobs[rel_path] + b"\n"}
        with pytest.raises(ClosedValidationError):
            _verify_world(w, resolved_d26_blobs=corrupt_d26)
