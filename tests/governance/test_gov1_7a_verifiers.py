"""Tests for Etapa 7 IsolatedWheelProbeRunner, pinned d26 runner, and passive 7A verifiers."""
from __future__ import annotations

import ast
import base64
from collections.abc import Callable, Mapping, Sequence
import copy
from dataclasses import dataclass, replace
import decimal
import io
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tracemalloc
from typing import Any
import zipfile
import zlib

import pytest

from smart_ads.adapters.pipeboard import DEFAULT_PIPEBOARD_TRANSPORT_LIMITS, PipeboardAdapterError, PipeboardFixtureAdapter, PipeboardWireRejection, PrivatePipeboardBindingBoundary, build_pipeboard_insights_request as wheel_build_insights_request, loads_pipeboard_wire_json as wheel_loads_wire_json, parse_pipeboard_http_and_mcp_envelope as wheel_parse_envelope, transform_pipeboard_response_to_batch
from smart_ads.analytics.lattice import RegressionFixtureV1
from smart_ads.application import admit_collection, evaluate_fixture_collection
from smart_ads.application.collection import _reduce_batch_to_candidates_and_completeness
from smart_ads.contracts.git_provenance import GitArtifactProvenance, sort_git_provenance_locators as wheel_sort_git_locators
from smart_ads.contracts.jcs import ArtifactLocator, canonicalize_jcs, jcs_sha256, loads_strict_json
from smart_ads.contracts.negative_security import MANDATORY_7A_NEGATIVE_CASES as WHEEL_17_NEG_CASES, PINNED_7A_NEGATIVE_SUITE_DIGEST as WHEEL_NEG_SUITE_DIGEST, NegativeSecurityCase, NegativeSecurityRun, NegativeSecurityTestReport, SandboxResourceLimits, SandboxRuntimeReadback, SandboxTermination, SandboxUsageCounters, compute_negative_run_execution_binding_digest as wheel_neg_bind_digest, verify_negative_security_report_against_profile
from smart_ads.contracts.schemas import CollectionRequest, PurposePrerequisiteLocators, RetrievalContext
from smart_ads.domain.pipeboard_contract import FORBIDDEN_PIPEBOARD_ARGUMENTS, PINNED_LEGACY_COMMIT, PINNED_LEGACY_REPO, PINNED_PIPEBOARD_D26_SPECS, PIPEBOARD_PHASE1_METRIC_SOURCE_MAPPINGS, LegacySourcePacket, PinnedGitArtifactMember, PinnedUpstreamReference, PipeboardPhase1Contract, PipeboardTransportLimits
from smart_ads.domain.registry import AuthorizedScopeRelation, DriverCapabilityEntry, ExpectedResourceInventory, ExpectedResourceKey, PrivateRegistrySnapshot, RegistryBinding
from smart_ads.domain.resource_ref import TenantResourceKeyHandle
from smart_ads.ports.cell_runtime import CellRuntimePorts, ClockAttestation, ResolvedClockState, ResolvedPrerequisiteBundle, ResolvedRegistryState, TimezoneRuleSnapshot
from smart_ads.reconciliation.certification_7a import ADAPTER_ARTIFACT_PATHS, CORPUS_GIT_PATH, MAPPING_ARTIFACT_PATHS, PARSER_ARTIFACT_PATHS, Certification7ACapabilityBinding, Certification7AFixtureCase, Certification7ARecord, compute_7a_case_execution_binding_digest as wheel_7a_bind_digest, compute_adapter_code_digest, compute_mapping_rules_digest, compute_parser_code_digest, verify_certification_7a_record as wheel_verify_cert_7a
from tests.unit.test_negative_security_7a import _DENIAL_OBSERVATIONS, _resource_run_specs
from tools.governance import decomposition_governance, gov1_mcp, gov1_sandbox, gov1_wheel, p1
import tools.governance.gov1_7a_runner as gov1_7a_runner
import tools.governance.gov1_7a_negative as gov1_7a_negative
import tools.governance.gov1_7a_replay_helpers as gov1_7a_replay_helpers
import tools.governance.gov1_7a_certification as gov1_7a_certification
from tools.governance.jcs import canonicalize
from tools.governance.locator import Store, digest, json_digest, make_locator

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES_DIR = REPO_ROOT / "tests" / "certification_7a" / "fixtures"
PINNED_D26_JSON = FIXTURES_DIR / "pinned_d26c73d_blobs.json"
CORPUS_JSON = FIXTURES_DIR / "pipeboard_7a_corpus_v1.json"

_SIG_B64 = base64.b64encode(b"\x33" * 64).decode("ascii")
_SIGNER_KEY_ID = "key:ed25519:" + ("a" * 64)
_KEY_REG_DICT = make_locator("smart_ads/key_authorization_registry/v1", b'{"reg":"k"}')
_OCI_DIGEST = "sha256:" + ("1" * 64)
_RUNNER_DIGEST = "sha256:" + ("2" * 64)
_BUILD_RUN_ID = "build-run-gov1-7a-001"


def _fake_sign_dict(unsigned_env: Mapping[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(dict(unsigned_env))
    out["integrity"] = {"key_id": _SIGNER_KEY_ID, "key_registry_snapshot_locator": copy.deepcopy(_KEY_REG_DICT)}
    out["integrity"]["content_digest"] = p1.content_digest(out)
    out["integrity"]["signature_base64"] = _SIG_B64
    return out


def _decode_d26_fixture() -> dict[str, bytes]:
    doc = loads_strict_json(PINNED_D26_JSON.read_bytes())
    return {rel_path: base64.b64decode(doc["blobs"][f"{role}__{Path(rel_path).name}"]) for role, rel_path, _, _ in PINNED_PIPEBOARD_D26_SPECS}


@pytest.fixture(scope="module")
def built_head_wheel(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    out_dir = tmp_path_factory.mktemp("gov1_7a_wheel")
    wheel_path, snapshot = gov1_wheel.build_reproducible_wheel(REPO_ROOT, out_dir)
    inspection = gov1_wheel.inspect_wheel_boundary(wheel_path)
    mcp_exec = gov1_mcp.execute_mcp_rejection_matrix_on_wheel(wheel_path)
    return {"wheel_path": wheel_path, "wheel_bytes": wheel_path.read_bytes(), "snapshot": snapshot, "inspection": inspection, "mcp_execution": mcp_exec}


def test_new_gov1_7a_modules_ast_purity_no_assert_and_no_smart_ads_imports() -> None:
    budgets = (("gov1_7a_runner.py", 580), ("gov1_7a_negative.py", 650), ("gov1_7a_replay_helpers.py", 760), ("gov1_7a_certification.py", 760))
    for name, max_lines in budgets:
        mod_path = REPO_ROOT / "tools" / "governance" / name
        src = mod_path.read_text(encoding="utf-8")
        assert len(src.splitlines()) <= max_lines, f"{name} exceeds {max_lines} lines"
        tree = ast.parse(src, filename=str(mod_path))
        assert [n for n in ast.walk(tree) if isinstance(n, ast.Assert)] == []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert all(not a.name.startswith("smart_ads") for a in node.names)
            elif isinstance(node, ast.ImportFrom):
                assert not (node.module or "").startswith("smart_ads")
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                span = (node.end_lineno or node.lineno) - node.lineno + 1
                assert span < 50, f"{name}:{node.name} is {span} lines (>= 50)"


def test_verified_run_context_identity_verifies_epochs_1_2_3_and_preserves_prereqs(tmp_path: Path) -> None:
    prereq_before = decomposition_governance.historical_prerequisites(REPO_ROOT)
    ident = decomposition_governance.verified_run_context_identity(REPO_ROOT)
    assert set(ident.keys()) == {"run_context_locator", "gate2_registry_locator", "run_registry_locator", "prerequisite_epoch3_registry_locator"}
    store = Store(REPO_ROOT / "docs" / "governance" / "cell-objects")
    assert store.get(ident["gate2_registry_locator"])["epoch"] == 1
    assert store.get(ident["run_registry_locator"])["epoch"] == 2
    assert store.get(ident["prerequisite_epoch3_registry_locator"])["epoch"] == 3
    assert ident["prerequisite_epoch3_registry_locator"] == prereq_before["registry_locator"]
    assert decomposition_governance.historical_prerequisites(REPO_ROOT) == prereq_before

    copied_gov = tmp_path / "docs" / "governance"
    shutil.copytree(REPO_ROOT / "docs", tmp_path / "docs")
    shutil.copy2(copied_gov / "legacy-step2/params/registry_epoch3_store_put.out", copied_gov / "run-context/params/registry_epoch2_store_put.out")
    with pytest.raises(ValueError):
        decomposition_governance.verified_run_context_identity(tmp_path)


class _RecordingProbeRunner:
    os_isolated: bool = True

    def __init__(self, *, wheel_bytes: bytes, inspection: dict[str, Any], mcp_exec: dict[str, Any]) -> None:
        self._wheel_bytes, self._inspection, self._mcp_exec, self.calls = wheel_bytes, inspection, mcp_exec, []

    def run_wheel_import_probe(self, *, wheel_bytes: bytes, expected_member_paths: frozenset[str], expected_modules: Sequence[str]) -> dict[str, Any]:
        self.calls.append("import")
        assert wheel_bytes == self._wheel_bytes and len(expected_member_paths) >= 54 and list(expected_modules) == self._inspection["packaged_modules"]
        return {"packaged_modules": list(expected_modules), "schema_bundle_digest": self._inspection["schema_bundle_digest"]}

    def run_mcp_matrix_probe(self, *, wheel_bytes: bytes, expected_member_paths: frozenset[str], expected_schema_bundle_digest: str) -> dict[str, Any]:
        self.calls.append("mcp")
        assert wheel_bytes == self._wheel_bytes and expected_schema_bundle_digest == self._mcp_exec["schema_bundle_digest"]
        return {"schema_bundle_digest": expected_schema_bundle_digest, "allowed_methods": copy.deepcopy(self._mcp_exec["allowed_methods"]), "body_64k_boundary_verified": True, "cases": copy.deepcopy(self._mcp_exec["cases"])}

    def run_pep517_wheel_build(self, *, snapshot_files: Mapping[str, bytes], snapshot_modes: Mapping[str, str], verified_backend_site_dir: Path, source_date_epoch: int) -> tuple[str, bytes]:
        self.calls.append("pep517")
        assert "pyproject.toml" in snapshot_files and verified_backend_site_dir.is_dir() and source_date_epoch >= 0
        return gov1_wheel.EXPECTED_WHEEL_FILENAME, self._wheel_bytes


def _forbid_local_probe_helpers(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("local subprocess helper called despite probe_runner")

    monkeypatch.setattr(gov1_wheel, "_run_local_clean_venv_import_probe", _boom)
    monkeypatch.setattr(gov1_wheel, "_run_local_pep517_subprocess", _boom)
    monkeypatch.setattr(gov1_mcp, "_run_local_clean_venv_mcp_probe", _boom)


def test_probe_runner_propagates_across_all_wheel_and_mcp_entrypoints(built_head_wheel: dict[str, Any], monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _forbid_local_probe_helpers(monkeypatch)
    whl_path, snap = built_head_wheel["wheel_path"], built_head_wheel["snapshot"]
    insp, mcp_exec = built_head_wheel["inspection"], built_head_wheel["mcp_execution"]
    runner = _RecordingProbeRunner(wheel_bytes=built_head_wheel["wheel_bytes"], inspection=insp, mcp_exec=mcp_exec)
    assert isinstance(runner, gov1_wheel.IsolatedWheelProbeRunner)
    assert gov1_wheel.inspect_wheel_boundary(whl_path, probe_runner=runner) == insp
    rebuilt_path, _ = gov1_wheel.build_reproducible_wheel(REPO_ROOT, tmp_path / "dist", probe_runner=runner)
    assert rebuilt_path.read_bytes() == built_head_wheel["wheel_bytes"]
    run_ctx = decomposition_governance.verified_run_context_identity(REPO_ROOT)["run_context_locator"]
    prov_env = gov1_wheel.build_wheel_build_provenance_envelope(migration_run_context_locator=run_ctx, build_run_id=_BUILD_RUN_ID, built_at_utc="2026-09-07T10:00:05Z", snapshot=snap, source_date_epoch=gov1_wheel.DEFAULT_SOURCE_DATE_EPOCH, schema_bundle_digest=insp["schema_bundle_digest"], wheel_bytes=built_head_wheel["wheel_bytes"], registry_locator=_KEY_REG_DICT, signer_key_id=_SIGNER_KEY_ID)
    prov_loc = make_locator(gov1_wheel.WHEEL_BUILD_PROVENANCE_SCHEMA, canonicalize(prov_env))
    bound_env = gov1_wheel.build_wheel_boundary_report_envelope(migration_run_context_locator=run_ctx, build_run_id=_BUILD_RUN_ID, verified_at_utc="2026-09-07T10:00:10Z", source_commit_sha=snap.commit_sha, build_backend_digest=snap.build_backend_digest, wheel_build_provenance_locator=prov_loc, inspection=insp, registry_locator=_KEY_REG_DICT, signer_key_id=_SIGNER_KEY_ID)
    sbx_loc = make_locator(gov1_sandbox.SANDBOX_PROFILE_SCHEMA, b'{"sbx":1}')
    mcp_env = gov1_mcp.build_mcp_rejection_matrix_report_envelope(migration_run_context_locator=run_ctx, build_run_id=_BUILD_RUN_ID, executed_at_utc="2026-09-07T10:00:12Z", source_commit_sha=snap.commit_sha, build_backend_digest=snap.build_backend_digest, sealed_sandbox_profile_locator=sbx_loc, execution=mcp_exec, registry_locator=_KEY_REG_DICT, signer_key_id=_SIGNER_KEY_ID)
    gov1_wheel.verify_wheel_boundary_report(bound_env, wheel_path=whl_path, probe_runner=runner)
    gov1_wheel.verify_wheel_build_provenance(prov_env, repo_root=REPO_ROOT, wheel_path=whl_path, probe_runner=runner)
    gov1_mcp.verify_mcp_rejection_matrix_report(mcp_env, wheel_path=whl_path, probe_runner=runner)
    assert runner.calls == ["import", "pep517", "pep517", "import", "import", "pep517", "pep517", "import", "mcp"]
    with pytest.raises(ValueError):
        gov1_wheel.inspect_wheel_boundary(whl_path, probe_runner="not-a-runner")  # type: ignore[arg-type]


def test_resolve_pinned_d26_blobs_dir_layouts_xor_and_symlink_rejection(tmp_path: Path) -> None:
    d26 = _decode_d26_fixture()
    with pytest.raises(ValueError):
        gov1_7a_runner.resolve_pinned_pipeboard_d26_blobs()
    with pytest.raises(ValueError):
        gov1_7a_runner.resolve_pinned_pipeboard_d26_blobs(legacy_repo=tmp_path, legacy_blobs_dir=tmp_path)
    rel_dir, flat_dir, sym_dir = tmp_path / "rel", tmp_path / "flat", tmp_path / "sym"
    for d in (rel_dir, flat_dir, sym_dir):
        d.mkdir()
    for idx, (role, rel_path, _, _) in enumerate(PINNED_PIPEBOARD_D26_SPECS):
        dest_rel = rel_dir / rel_path
        dest_rel.parent.mkdir(parents=True, exist_ok=True)
        dest_rel.write_bytes(d26[rel_path])
        flat_f = flat_dir / f"{role}__{Path(rel_path).name}"
        flat_f.write_bytes(d26[rel_path])
        sym_f = sym_dir / f"{role}__{Path(rel_path).name}"
        sym_f.symlink_to(flat_f) if idx == 0 else sym_f.write_bytes(d26[rel_path])
    assert dict(gov1_7a_runner.resolve_pinned_pipeboard_d26_blobs(legacy_blobs_dir=rel_dir)) == d26
    assert dict(gov1_7a_runner.resolve_pinned_pipeboard_d26_blobs(legacy_blobs_dir=flat_dir)) == d26
    role0, rel0, _, _ = PINNED_PIPEBOARD_D26_SPECS[0]
    (rel_dir / f"{role0}__{Path(rel0).name}").write_bytes(d26[rel0])
    for bad_dir in (rel_dir, sym_dir):
        with pytest.raises(ValueError):
            gov1_7a_runner.resolve_pinned_pipeboard_d26_blobs(legacy_blobs_dir=bad_dir)


def test_resolve_pinned_d26_blobs_git_modes_and_optional_real_repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    empty_repo = tmp_path / "empty_git"
    empty_repo.mkdir()
    subprocess.run(["git", "init", "-q", str(empty_repo)], check=True)
    with pytest.raises(ValueError):
        gov1_7a_runner.resolve_pinned_pipeboard_d26_blobs(legacy_repo=empty_repo)
    d26, seen_git_args = _decode_d26_fixture(), []

    def fake_d26_git_runner(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
        assert repo == empty_repo and check is True
        seen_git_args.append(args)
        if args == ("rev-parse", "--verify", f"{PINNED_LEGACY_COMMIT}^{{commit}}"):
            return subprocess.CompletedProcess(args, 0, stdout=(PINNED_LEGACY_COMMIT + "\n").encode("ascii"), stderr=b"")
        assert len(args) == 3 and args[:2] == ("cat-file", "blob") and args[2].startswith(f"{PINNED_LEGACY_COMMIT}:")
        return subprocess.CompletedProcess(args, 0, stdout=d26[args[2][len(PINNED_LEGACY_COMMIT) + 1 :]], stderr=b"")

    monkeypatch.setattr(gov1_7a_runner, "run_git_offline", fake_d26_git_runner)
    assert dict(gov1_7a_runner.resolve_pinned_pipeboard_d26_blobs(legacy_repo=empty_repo)) == d26
    assert seen_git_args == [("rev-parse", "--verify", f"{PINNED_LEGACY_COMMIT}^{{commit}}"), *[("cat-file", "blob", f"{PINNED_LEGACY_COMMIT}:{rel}") for _, rel, _, _ in PINNED_PIPEBOARD_D26_SPECS]]


@pytest.mark.skipif(not bool(os.environ.get("SMART_ADS_LEGACY_MBRAS_REPO")), reason="SMART_ADS_LEGACY_MBRAS_REPO not set")
def test_resolve_pinned_d26_blobs_against_real_legacy_repo() -> None:
    repo_env = Path(os.environ["SMART_ADS_LEGACY_MBRAS_REPO"])
    assert dict(gov1_7a_runner.resolve_pinned_pipeboard_d26_blobs(legacy_repo=repo_env)) == _decode_d26_fixture()


def test_load_isolated_pinned_meta_reducer_ast_builtins_and_prec28() -> None:
    d26 = _decode_d26_fixture()
    reducer = gov1_7a_runner.load_isolated_pinned_meta_reducer(d26)
    iso_builtins = reducer.__closure__[0].cell_contents.__globals__["__builtins__"]  # type: ignore[index]
    assert all(f not in iso_builtins for f in ("__import__", "open", "eval", "exec", "compile"))
    mcp_in = {"content": [{"type": "text", "text": '{"data":[{"campaign_id":"12021000000001","impressions":"150000","clicks":"4200","spend":"92233720368547758.07"}]}'}], "isError": False}
    with decimal.localcontext(decimal.Context(prec=16)):
        assert reducer(mcp_in) == [{"impressions": 150000, "clicks": 4200, "spend_minor": 9223372036854775807}]
    for bad_key in ("scripts/pipeboard_limits.py", "scripts/operator/meta_daily_contract.py"):
        with pytest.raises(ValueError):
            gov1_7a_runner.load_isolated_pinned_meta_reducer({**d26, bad_key: d26[bad_key] + b"\n"})
    with pytest.raises(ValueError):
        gov1_7a_runner._wrap_pinned_meta_reducer(lambda _x: {"wrong": []})(mcp_in)


class _FakeSealedOciSupervisorPort:
    def __init__(self, *, sbx_payload: Mapping[str, Any], reg_state: ResolvedRegistryState, inv_pair: tuple[ArtifactLocator, ExpectedResourceInventory], tamper_val: Any = "none", tamper_limits: Any = "none") -> None:
        self._sbx, self._reg_state, self._inv_pair = dict(sbx_payload), reg_state, inv_pair
        self._tamper, self._tamper_limits, self.execute_calls, self.reducer_calls = tamper_val, tamper_limits, 0, 0

    def readback_sandbox_environment(self) -> Mapping[str, Any]:
        shared = {k: copy.deepcopy(self._sbx[k]) for k in self._sbx if k not in {"resource_limits", "migration_run_context_locator", "issued_at_utc", "validity"}}
        if self._tamper != "none":
            shared["rootfs_read_only"] = self._tamper
        return {**shared, "effective_writable_mounts": ["/tmp"], "seccomp_enforced_before_entry": True, "network_absent": True, "loopback_absent": True}

    def readback_effective_resource_limits(self) -> Mapping[str, Any]:
        if isinstance(self._tamper_limits, BaseException):
            raise self._tamper_limits
        lim = copy.deepcopy(dict(self._sbx["resource_limits"]))
        return lim if self._tamper_limits == "none" else (self._tamper_limits if not isinstance(self._tamper_limits, Mapping) or len(self._tamper_limits) == 0 else {**lim, **copy.deepcopy(dict(self._tamper_limits))})

    def execute_7a_corpus(self, *, wheel_bytes: bytes, corpus_bytes: bytes, sandbox_profile_payload: Mapping[str, Any], resolved_d26_blobs: Mapping[str, bytes], reducer: Callable[[dict[str, Any]], list[dict[str, int]]]) -> Mapping[str, Any]:
        self.execute_calls += 1
        assert len(wheel_bytes) > 0 and sandbox_profile_payload["profile_id"] == gov1_sandbox.SANDBOX_PROFILE_ID
        corpus_doc = loads_strict_json(corpus_bytes)
        kh = TenantResourceKeyHandle("tenant:ibvi", "key:7a-fixture-hmac-v1", bytes.fromhex(corpus_doc["tenant_hmac_key_hex"]))
        bnd = PrivatePipeboardBindingBoundary(resolved_registry=self._reg_state, key_handle=kh, private_account_bindings={("binding:meta-primary", "account:ibvi-01"): "act_5544332211"}, authenticated_inventories=[self._inv_pair])
        for pair in corpus_doc["verified_campaign_pairs"]:
            bnd.register_verified_campaign_pair(pair["raw_campaign_id"], pair["resource_ref"])
        def spy_reducer(mcp_res: dict[str, Any]) -> list[dict[str, int]]:
            self.reducer_calls += 1
            return reducer(mcp_res)
        return {"statuses": _run_corpus_through_adapter(corpus_doc, self._reg_state, bnd, spy_reducer), "reducer_calls": self.reducer_calls}


def _run_corpus_through_adapter(corpus_doc: Mapping[str, Any], reg_state: ResolvedRegistryState, bnd: PrivatePipeboardBindingBoundary, reducer: Callable[[dict[str, Any]], list[dict[str, int]]]) -> list[str]:
    sbx_loc = ArtifactLocator.from_digest(gov1_sandbox.SANDBOX_PROFILE_SCHEMA, "sha256:" + ("9" * 64))
    reg_fix = RegressionFixtureV1.canonical(reg_state.locator.content_digest)
    reg_fix_loc = ArtifactLocator.for_canonical_bytes(RegressionFixtureV1.SCHEMA, canonicalize_jcs(reg_fix.to_dict()))
    tz_snap, adapter, statuses = TimezoneRuleSnapshot.from_dict(corpus_doc["timezone_snapshot"]), PipeboardFixtureAdapter(boundary=bnd, reducer=reducer), []
    for c in corpus_doc["cases"]:
        att = ClockAttestation.from_dict(c["clock_reading"]["attestation"])
        clk = ResolvedClockState(ArtifactLocator.for_canonical_bytes(ClockAttestation.SCHEMA, canonicalize_jcs(att.to_dict())), att, c["clock_reading"]["configured_max_uncertainty_ms"])
        ports = _make_static_cell_ports(clk, tz_snap, reg_state, ResolvedPrerequisiteBundle(PurposePrerequisiteLocators("fixture_7a", sealed_sandbox_profile_locator=sbx_loc, regression_fixture_locator=reg_fix_loc)))
        req = CollectionRequest.from_dict(c["collection_request"])
        adm, hr = admit_collection(req, ports, admission_id=c["admission_id"]), c["http_response"]
        adapter.register_fixture_case(admitted=adm.admitted, retrieval_context=RetrievalContext.from_dict(c["retrieval_context"]), network_ok=hr["network_ok"], http_status=hr["http_status"], headers=[(h[0], h[1]) for h in hr["headers"]], body_chunks=[hr["body_utf8"].encode("utf-8")])
        statuses.append(evaluate_fixture_collection(req, admission_id=c["admission_id"], cell_ports=ports, fixture_port=adapter, inventory_port=bnd).completeness.status)
    return statuses


@dataclass(frozen=True)
class _StaticPorts:
    clk: ResolvedClockState
    tz: TimezoneRuleSnapshot
    reg: ResolvedRegistryState
    prereq: ResolvedPrerequisiteBundle
    def get_authenticated_clock(self) -> ResolvedClockState: return self.clk
    def get_reporting_timezone_rules(self) -> TimezoneRuleSnapshot: return self.tz
    def get_active_registry(self, *, tenant_ref: str) -> ResolvedRegistryState: return self.reg
    def resolve_prerequisites(self, **kw: Any) -> ResolvedPrerequisiteBundle: return self.prereq


def _make_static_cell_ports(clk: ResolvedClockState, tz: TimezoneRuleSnapshot, reg: ResolvedRegistryState, prereq: ResolvedPrerequisiteBundle) -> CellRuntimePorts:
    sp = _StaticPorts(clk, tz, reg, prereq)
    return CellRuntimePorts(sp, sp, sp, sp)


def _build_neg_cases_dicts(sbx_payload: Mapping[str, Any], sbx_spec_digest: str, whl_digest: str) -> list[dict[str, Any]]:
    shared_16 = {k: copy.deepcopy(sbx_payload[k]) for k in sbx_payload if k not in {"resource_limits", "migration_run_context_locator", "issued_at_utc", "validity"}}
    limits = SandboxResourceLimits.canonical()
    out: list[dict[str, Any]] = []
    for c_idx, cid in enumerate(WHEEL_17_NEG_CASES):
        specs = [(True, SandboxUsageCounters(cpu_time_us=1000, pids_peak=1), SandboxTermination("clean_exit", False, 0, None, 40, 0, True, False), _DENIAL_OBSERVATIONS[cid])] if cid in _DENIAL_OBSERVATIONS else _resource_run_specs(cid)
        runs: list[NegativeSecurityRun] = []
        for s_idx, (seccomp, usage, term, obs) in enumerate(specs):
            rb = SandboxRuntimeReadback.from_dict({**shared_16, "effective_writable_mounts": ["/tmp"], "seccomp_enforced_before_entry": seccomp, "network_absent": True, "loopback_absent": True})
            draft = NegativeSecurityRun(f"sandbox:neg-{c_idx:02d}-{s_idx}", "sha256:" + ("0" * 64), "2026-09-07T10:00:06Z", "2026-09-07T10:00:10Z", rb, limits, usage, term, obs)
            bind = wheel_neg_bind_digest(case_id=cid, subrun_index=s_idx, run=draft, wheel_digest=whl_digest, test_suite_digest=WHEEL_NEG_SUITE_DIGEST, sealed_sandbox_profile_digest=sbx_spec_digest)
            runs.append(replace(draft, execution_binding_digest=bind))
        out.append(NegativeSecurityCase(cid, "passed", tuple(runs)).to_dict())
    return out


def _stage_leaf_envelopes_in_store(store: Store, *, commit_sha: str, git_blobs: Mapping[str, bytes], d26_blobs: Mapping[str, bytes]) -> tuple[ResolvedRegistryState, dict[tuple[str, str], tuple[ArtifactLocator, GitArtifactProvenance]], tuple[ArtifactLocator, ExpectedResourceInventory]]:
    prov_map: dict[tuple[str, str], tuple[ArtifactLocator, GitArtifactProvenance]] = {}
    d26_members: list[PinnedGitArtifactMember] = []
    for role, rel_path, oid, sha in PINNED_PIPEBOARD_D26_SPECS:
        signed_p = _fake_sign_dict(gov1_7a_certification.build_git_artifact_provenance_envelope(repository=PINNED_LEGACY_REPO, commit_sha=PINNED_LEGACY_COMMIT, path=rel_path, raw_bytes=d26_blobs[rel_path], resolved_at_utc="2026-09-07T10:00:00Z", registry_locator=_KEY_REG_DICT, signer_key_id=_SIGNER_KEY_ID))
        aloc = ArtifactLocator.from_dict(store.put(signed_p))
        prov_map[(PINNED_LEGACY_REPO, rel_path)] = (aloc, GitArtifactProvenance.from_dict(signed_p, require_signed=True))
        d26_members.append(PinnedGitArtifactMember(role, PINNED_LEGACY_REPO, PINNED_LEGACY_COMMIT, rel_path, oid, sha, aloc))
    for rel_path, raw in sorted(git_blobs.items()):
        signed_g = _fake_sign_dict(gov1_7a_certification.build_git_artifact_provenance_envelope(repository="aiconnai/smart-ads", commit_sha=commit_sha, path=rel_path, raw_bytes=raw, resolved_at_utc="2026-09-07T10:00:04Z", registry_locator=_KEY_REG_DICT, signer_key_id=_SIGNER_KEY_ID))
        prov_map[("aiconnai/smart-ads", rel_path)] = (ArtifactLocator.from_dict(store.put(signed_g)), GitArtifactProvenance.from_dict(signed_g, require_signed=True))
    return _finalize_registry_and_inventory(store, d26_members, prov_map)


def _finalize_registry_and_inventory(store: Store, d26_members: Sequence[PinnedGitArtifactMember], prov_map: dict[tuple[str, str], tuple[ArtifactLocator, GitArtifactProvenance]]) -> tuple[ResolvedRegistryState, dict[tuple[str, str], tuple[ArtifactLocator, GitArtifactProvenance]], tuple[ArtifactLocator, ExpectedResourceInventory]]:
    drv_u = PipeboardPhase1Contract("driver-contract:pipeboard-phase1-v1", "pipeboard_hosted", LegacySourcePacket(PINNED_LEGACY_REPO, PINNED_LEGACY_COMMIT, tuple(d26_members)), PinnedUpstreamReference(), PipeboardTransportLimits(forbidden_arguments=FORBIDDEN_PIPEBOARD_ARGUMENTS), dict(PIPEBOARD_PHASE1_METRIC_SOURCE_MAPPINGS))
    drv_s = _fake_sign_dict(drv_u.to_dict())
    drv_loc = ArtifactLocator.from_dict(store.put(drv_s))
    snap_u = PrivateRegistrySnapshot("registry-snapshot:2026-09-07-001", "tenant:ibvi", "2026-09-07T10:00:00Z", "2027-01-01T00:00:00Z", "hmac-sha256-b32-v1", "key:7a-fixture-hmac-v1", (RegistryBinding("binding:meta-primary", "account:ibvi-01", "provider:pipeboard", "meta", "BRL", "pipeboard_hosted"),), (AuthorizedScopeRelation("front:ibvi", "profile:reader", "binding:meta-primary", "scope:campaigns-active"),), (DriverCapabilityEntry("cap:campaign-basic-v1", "1.0.0", "pipeboard_hosted", drv_loc, drv_loc.content_digest, "scope:campaigns-active", "declared", ("metric:clicks_v1", "metric:impressions_v1", "metric:spend_v1")),))
    snap_s = _fake_sign_dict(snap_u.to_dict())
    snap_loc = ArtifactLocator.from_dict(store.put(snap_s))
    reg_state = ResolvedRegistryState(snap_loc, PrivateRegistrySnapshot.from_dict(snap_s, require_signed=True), drv_loc, PipeboardPhase1Contract.from_dict(drv_s, require_signed=True))
    refs = sorted(p["resource_ref"] for p in loads_strict_json(CORPUS_JSON.read_bytes())["verified_campaign_pairs"])
    inv_s = _fake_sign_dict(gov1_7a_certification.build_expected_resource_inventory_envelope(inventory_id="inventory:7a-2026-09-06", registry_snapshot_locator=snap_loc.to_dict(), tenant_ref="tenant:ibvi", binding_ref="binding:meta-primary", account_ref="account:ibvi-01", resource_scope_ref="scope:campaigns-active", date_range={"start_date": "2026-09-06", "end_date": "2026-09-06", "inclusive": True}, expected_resources=[ExpectedResourceKey("binding:meta-primary", "account:ibvi-01", r, "campaign", "2026-09-06").to_dict() for r in refs], registry_locator=_KEY_REG_DICT, signer_key_id=_SIGNER_KEY_ID))
    return reg_state, prov_map, (ArtifactLocator.from_dict(store.put(inv_s)), ExpectedResourceInventory.from_dict(inv_s, require_signed=True))


def _build_7a_cases_dicts(*, corpus_doc: Mapping[str, Any], reg_state: ResolvedRegistryState, inv_pair: tuple[ArtifactLocator, ExpectedResourceInventory], sbx_loc: ArtifactLocator, sbx_payload: Mapping[str, Any], sbx_spec_digest: str, whl_digest: str, corpus_digest: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    kh = TenantResourceKeyHandle("tenant:ibvi", "key:7a-fixture-hmac-v1", bytes.fromhex(corpus_doc["tenant_hmac_key_hex"]))
    bnd = PrivatePipeboardBindingBoundary(resolved_registry=reg_state, key_handle=kh, private_account_bindings={("binding:meta-primary", "account:ibvi-01"): "act_5544332211"}, authenticated_inventories=[inv_pair])
    for pair in corpus_doc["verified_campaign_pairs"]:
        bnd.register_verified_campaign_pair(pair["raw_campaign_id"], pair["resource_ref"])
    reg_fix = RegressionFixtureV1.canonical(reg_state.locator.content_digest)
    reg_fix_loc, tz_snap = ArtifactLocator.for_canonical_bytes(RegressionFixtureV1.SCHEMA, canonicalize_jcs(reg_fix.to_dict())), TimezoneRuleSnapshot.from_dict(corpus_doc["timezone_snapshot"])
    shared_16 = {k: copy.deepcopy(sbx_payload[k]) for k in sbx_payload if k not in {"resource_limits", "migration_run_context_locator", "issued_at_utc", "validity"}}
    rb = SandboxRuntimeReadback.from_dict({**shared_16, "effective_writable_mounts": ["/tmp"], "seccomp_enforced_before_entry": True, "network_absent": True, "loopback_absent": True})
    return reg_fix.to_dict(), [_build_single_7a_case_dict(idx, c, bnd, reg_state, tz_snap, inv_pair[0], sbx_loc, reg_fix_loc, rb, sbx_spec_digest, whl_digest, corpus_digest) for idx, c in enumerate(corpus_doc["cases"], start=1)]


def _build_single_7a_case_dict(idx: int, c: Mapping[str, Any], bnd: PrivatePipeboardBindingBoundary, reg_state: ResolvedRegistryState, tz_snap: TimezoneRuleSnapshot, inv_loc: ArtifactLocator, sbx_loc: ArtifactLocator, reg_fix_loc: ArtifactLocator, rb: SandboxRuntimeReadback, sbx_spec_digest: str, whl_digest: str, corpus_digest: str) -> dict[str, Any]:
    att = ClockAttestation.from_dict(c["clock_reading"]["attestation"])
    clk = ResolvedClockState(ArtifactLocator.for_canonical_bytes(ClockAttestation.SCHEMA, canonicalize_jcs(att.to_dict())), att, c["clock_reading"]["configured_max_uncertainty_ms"])
    ports = _make_static_cell_ports(clk, tz_snap, reg_state, ResolvedPrerequisiteBundle(PurposePrerequisiteLocators("fixture_7a", sealed_sandbox_profile_locator=sbx_loc, regression_fixture_locator=reg_fix_loc)))
    req = CollectionRequest.from_dict(c["collection_request"])
    adm = admit_collection(req, ports, admission_id=c["admission_id"])
    adapter = PipeboardFixtureAdapter(boundary=bnd)
    hr = c["http_response"]
    adapter.register_fixture_case(admitted=adm.admitted, retrieval_context=RetrievalContext.from_dict(c["retrieval_context"]), network_ok=hr["network_ok"], http_status=hr["http_status"], headers=[(h[0], h[1]) for h in hr["headers"]], body_chunks=[hr["body_utf8"].encode("utf-8")])
    ev = evaluate_fixture_collection(req, admission_id=c["admission_id"], cell_ports=ports, fixture_port=adapter, inventory_port=bnd)
    batch = adapter.get_recorded_batch(ev.admitted_locator)
    draft = Certification7AFixtureCase(c["case_id"], adm.locator.content_digest, inv_loc, f"opaque-driver-contract:{reg_state.driver_contract_locator.content_digest}", f"sandbox:pos-7a-{idx:02d}", "sha256:" + ("0" * 64), f"2026-09-07T10:00:{10 + idx:02d}Z", f"2026-09-07T10:00:{11 + idx:02d}Z", rb, SandboxResourceLimits.canonical(), SandboxUsageCounters(cpu_time_us=2500, pids_peak=1), SandboxTermination("clean_exit", False, 0, None, 25, 0, True, False), batch, c["expected_completeness_status"], ev.completeness.status, ev.completeness.normalized_fact_set_digest)
    bind = wheel_7a_bind_digest(case=draft, wheel_digest=whl_digest, corpus_digest=corpus_digest, sealed_sandbox_profile_digest=sbx_spec_digest)
    return replace(draft, execution_binding_digest=bind).to_dict()


@pytest.fixture()
def world_7a(built_head_wheel: dict[str, Any], tmp_path: Path) -> dict[str, Any]:
    store = Store(tmp_path / "cell-objects")
    snap, whl_bytes, insp, mcp_exec = built_head_wheel["snapshot"], built_head_wheel["wheel_bytes"], built_head_wheel["inspection"], built_head_wheel["mcp_execution"]
    git_blobs, d26_blobs = gov1_7a_certification.resolve_7a_smart_ads_git_blobs(REPO_ROOT, snap.commit_sha), _decode_d26_fixture()
    corpus_bytes, run_ctx, seccomp = git_blobs[CORPUS_GIT_PATH[1]], decomposition_governance.verified_run_context_identity(REPO_ROOT)["run_context_locator"], gov1_sandbox.build_default_7a_seccomp_profile()
    sbx_cand = gov1_sandbox.build_sealed_sandbox_profile_candidate(migration_run_context_locator=run_ctx, oci_image_digest=_OCI_DIGEST, runner_binary_digest=_RUNNER_DIGEST, seccomp_profile=seccomp, issued_at_utc="2026-09-07T10:00:00Z", valid_from_utc="2026-01-01T00:00:00Z", valid_until_utc="2027-01-01T00:00:00Z")
    sbx_env = _fake_sign_dict(gov1_sandbox.build_sealed_sandbox_profile_envelope(migration_run_context_locator=run_ctx, oci_image_digest=_OCI_DIGEST, runner_binary_digest=_RUNNER_DIGEST, seccomp_profile=seccomp, issued_at_utc="2026-09-07T10:00:00Z", valid_from_utc="2026-01-01T00:00:00Z", valid_until_utc="2027-01-01T00:00:00Z", registry_locator=_KEY_REG_DICT, signer_key_id=_SIGNER_KEY_ID))
    return _assemble_world_7a_artifacts(store, run_ctx, seccomp, sbx_cand, sbx_env, store.put(sbx_env), snap, whl_bytes, insp, mcp_exec, corpus_bytes, digest(corpus_bytes), git_blobs, d26_blobs)


def _assemble_world_7a_artifacts(store: Store, run_ctx: dict[str, Any], seccomp: dict[str, Any], sbx_cand: dict[str, Any], sbx_env: dict[str, Any], sbx_loc: dict[str, Any], snap: Any, whl_bytes: bytes, insp: dict[str, Any], mcp_exec: dict[str, Any], corpus_bytes: bytes, corpus_digest: str, git_blobs: Mapping[str, bytes], d26_blobs: Mapping[str, bytes]) -> dict[str, Any]:
    prov_cand = gov1_wheel.build_wheel_build_provenance_candidate(migration_run_context_locator=run_ctx, build_run_id=_BUILD_RUN_ID, built_at_utc="2026-09-07T10:00:05Z", snapshot=snap, source_date_epoch=gov1_wheel.DEFAULT_SOURCE_DATE_EPOCH, schema_bundle_digest=insp["schema_bundle_digest"], wheel_bytes=whl_bytes)
    prov_env = _fake_sign_dict(gov1_wheel.build_wheel_build_provenance_envelope(migration_run_context_locator=run_ctx, build_run_id=_BUILD_RUN_ID, built_at_utc="2026-09-07T10:00:05Z", snapshot=snap, source_date_epoch=gov1_wheel.DEFAULT_SOURCE_DATE_EPOCH, schema_bundle_digest=insp["schema_bundle_digest"], wheel_bytes=whl_bytes, registry_locator=_KEY_REG_DICT, signer_key_id=_SIGNER_KEY_ID))
    prov_loc = store.put(prov_env)
    bound_cand = gov1_wheel.build_wheel_boundary_report_candidate(migration_run_context_locator=run_ctx, build_run_id=_BUILD_RUN_ID, verified_at_utc="2026-09-07T10:00:10Z", source_commit_sha=snap.commit_sha, build_backend_digest=snap.build_backend_digest, wheel_build_provenance_candidate_ref=gov1_sandbox.build_local_candidate_ref(prov_cand), inspection=insp)
    bound_env = _fake_sign_dict(gov1_wheel.build_wheel_boundary_report_envelope(migration_run_context_locator=run_ctx, build_run_id=_BUILD_RUN_ID, verified_at_utc="2026-09-07T10:00:10Z", source_commit_sha=snap.commit_sha, build_backend_digest=snap.build_backend_digest, wheel_build_provenance_locator=prov_loc, inspection=insp, registry_locator=_KEY_REG_DICT, signer_key_id=_SIGNER_KEY_ID))
    mcp_loc = store.put(_fake_sign_dict(gov1_mcp.build_mcp_rejection_matrix_report_envelope(migration_run_context_locator=run_ctx, build_run_id=_BUILD_RUN_ID, executed_at_utc="2026-09-07T10:00:12Z", source_commit_sha=snap.commit_sha, build_backend_digest=snap.build_backend_digest, sealed_sandbox_profile_locator=sbx_loc, execution=mcp_exec, registry_locator=_KEY_REG_DICT, signer_key_id=_SIGNER_KEY_ID)))
    return _assemble_neg_and_cert7a_artifacts(store, run_ctx, seccomp, sbx_cand, sbx_env, sbx_loc, prov_cand, prov_env, prov_loc, bound_cand, bound_env, store.put(bound_env), mcp_loc, snap, whl_bytes, insp, corpus_bytes, corpus_digest, git_blobs, d26_blobs)


def _assemble_neg_and_cert7a_artifacts(store: Store, run_ctx: dict[str, Any], seccomp: dict[str, Any], sbx_cand: dict[str, Any], sbx_env: dict[str, Any], sbx_loc: dict[str, Any], prov_cand: dict[str, Any], prov_env: dict[str, Any], prov_loc: dict[str, Any], bound_cand: dict[str, Any], bound_env: dict[str, Any], bound_loc: dict[str, Any], mcp_loc: dict[str, Any], snap: Any, whl_bytes: bytes, insp: dict[str, Any], corpus_bytes: bytes, corpus_digest: str, git_blobs: Mapping[str, bytes], d26_blobs: Mapping[str, bytes]) -> dict[str, Any]:
    sbx_spec_digest = jcs_sha256({k: sbx_cand["payload"][k] for k in sbx_cand["payload"] if k not in {"migration_run_context_locator", "issued_at_utc", "validity"}})
    whl_digest = insp["wheel_digest"]
    neg_cases = _build_neg_cases_dicts(sbx_cand["payload"], sbx_spec_digest, whl_digest)
    neg_common = {"migration_run_context_locator": run_ctx, "build_run_id": _BUILD_RUN_ID, "executed_at_utc": "2026-09-07T10:00:15Z", "source_commit_sha": snap.commit_sha, "build_backend_digest": snap.build_backend_digest, "schema_bundle_digest": insp["schema_bundle_digest"], "wheel_digest": whl_digest, "oci_image_digest": _OCI_DIGEST, "runner_binary_digest": _RUNNER_DIGEST, "declared_resource_limits": SandboxResourceLimits.canonical().to_dict(), "cases": neg_cases}
    neg_cand = gov1_7a_negative.build_negative_security_test_report_candidate(**neg_common, sealed_sandbox_profile_candidate_ref=gov1_sandbox.build_local_candidate_ref(sbx_cand), wheel_build_provenance_candidate_ref=gov1_sandbox.build_local_candidate_ref(prov_cand))
    neg_env = _fake_sign_dict(gov1_7a_negative.build_negative_security_test_report_envelope(**neg_common, sealed_sandbox_profile_locator=sbx_loc, wheel_build_provenance_locator=prov_loc, registry_locator=_KEY_REG_DICT, signer_key_id=_SIGNER_KEY_ID))
    neg_loc = store.put(neg_env)
    reg_state, prov_map, inv_pair = _stage_leaf_envelopes_in_store(store, commit_sha=snap.commit_sha, git_blobs=git_blobs, d26_blobs=d26_blobs)
    reg_fix_dict, cases_dicts = _build_7a_cases_dicts(corpus_doc=loads_strict_json(corpus_bytes), reg_state=reg_state, inv_pair=inv_pair, sbx_loc=ArtifactLocator.from_dict(sbx_loc), sbx_payload=sbx_cand["payload"], sbx_spec_digest=sbx_spec_digest, whl_digest=whl_digest, corpus_digest=corpus_digest)
    cap_dict = Certification7ACapabilityBinding("cap:campaign-basic-v1", "scope:campaigns-active", "pipeboard_hosted", reg_state.driver_contract_locator, reg_state.driver_contract_locator.content_digest, reg_state.locator, ("metric:clicks_v1", "metric:impressions_v1", "metric:spend_v1")).to_dict()
    ev_dict = {"corpus_git_locator": prov_map[CORPUS_GIT_PATH][0].to_dict(), "corpus_digest": corpus_digest, "regression_fixture": reg_fix_dict, "cases": cases_dicts}
    cert_common = {"migration_run_context_locator": run_ctx, "build_run_id": _BUILD_RUN_ID, "certified_at_utc": "2026-09-07T10:00:16Z", "source_commit_sha": snap.commit_sha, "build_backend_digest": snap.build_backend_digest, "schema_bundle_digest": insp["schema_bundle_digest"], "wheel_digest": whl_digest, "resource_mapping_contract_digest": reg_state.snapshot.resource_mapping_contract_digest, "capability": cap_dict, "parser_artifact_locators": [loc.to_dict() for loc in wheel_sort_git_locators([prov_map[k][0] for k in PARSER_ARTIFACT_PATHS])], "parser_code_digest": compute_parser_code_digest([prov_map[k][1] for k in PARSER_ARTIFACT_PATHS]), "adapter_artifact_locators": [loc.to_dict() for loc in wheel_sort_git_locators([prov_map[k][0] for k in ADAPTER_ARTIFACT_PATHS])], "adapter_code_digest": compute_adapter_code_digest([prov_map[k][1] for k in ADAPTER_ARTIFACT_PATHS]), "mapping_artifact_locators": [loc.to_dict() for loc in wheel_sort_git_locators([prov_map[k][0] for k in MAPPING_ARTIFACT_PATHS])], "mapping_rules_digest": compute_mapping_rules_digest([prov_map[k][1] for k in MAPPING_ARTIFACT_PATHS], reg_state.driver_contract.metric_source_mappings), "fixture_evidence": ev_dict}
    cert_cand = gov1_7a_certification.build_certification_7a_record_candidate(**cert_common, sealed_sandbox_profile_candidate_ref=gov1_sandbox.build_local_candidate_ref(sbx_cand), wheel_build_provenance_candidate_ref=gov1_sandbox.build_local_candidate_ref(prov_cand), wheel_boundary_report_candidate_ref=gov1_sandbox.build_local_candidate_ref(bound_cand), negative_security_test_report_candidate_ref=gov1_sandbox.build_local_candidate_ref(neg_cand))
    cert_env = _fake_sign_dict(gov1_7a_certification.build_certification_7a_record_envelope(**cert_common, sealed_sandbox_profile_locator=sbx_loc, wheel_build_provenance_locator=prov_loc, wheel_boundary_report_locator=bound_loc, negative_security_test_report_locator=neg_loc, registry_locator=_KEY_REG_DICT, signer_key_id=_SIGNER_KEY_ID))
    return {"store": store, "run_ctx": run_ctx, "seccomp": seccomp, "sbx_cand": sbx_cand, "sbx_env": sbx_env, "sbx_loc": sbx_loc, "sbx_spec_digest": sbx_spec_digest, "prov_cand": prov_cand, "prov_env": prov_env, "prov_loc": prov_loc, "bound_cand": bound_cand, "bound_env": bound_env, "bound_loc": bound_loc, "mcp_loc": mcp_loc, "neg_cand": neg_cand, "neg_env": neg_env, "neg_loc": neg_loc, "cert_cand": cert_cand, "cert_env": cert_env, "cert_loc": store.put(cert_env), "wheel_bytes": whl_bytes, "corpus_bytes": corpus_bytes, "git_blobs": git_blobs, "d26_blobs": d26_blobs, "reg_state": reg_state, "inv_pair": inv_pair}


def test_hermetic_execution_blocked_without_oci_and_injects_pinned_reducer_in_oci(world_7a: dict[str, Any]) -> None:
    kw = {"wheel_bytes": world_7a["wheel_bytes"], "corpus_bytes": world_7a["corpus_bytes"], "sandbox_profile": world_7a["sbx_env"], "seccomp_profile": world_7a["seccomp"], "resolved_d26_blobs": world_7a["d26_blobs"]}
    good_sup = _FakeSealedOciSupervisorPort(sbx_payload=world_7a["sbx_cand"]["payload"], reg_state=world_7a["reg_state"], inv_pair=world_7a["inv_pair"])
    assert gov1_7a_runner.run_7a_hermetic_execution(**kw, supervisor=None)["status"] == "BLOCKED"
    class _MissingLimitsSup:
        def readback_sandbox_environment(self) -> Mapping[str, Any]: return copy.deepcopy(dict(good_sup.readback_sandbox_environment()))
        def execute_7a_corpus(self, **_k: Any) -> Mapping[str, Any]: raise AssertionError("unreachable")
    assert gov1_7a_runner.run_7a_hermetic_execution(**kw, supervisor=_MissingLimitsSup())["status"] == "BLOCKED"  # type: ignore[arg-type]
    for bad_val in (False, 1):
        bad_sup = _FakeSealedOciSupervisorPort(sbx_payload=world_7a["sbx_cand"]["payload"], reg_state=world_7a["reg_state"], inv_pair=world_7a["inv_pair"], tamper_val=bad_val)
        assert gov1_7a_runner.run_7a_hermetic_execution(**kw, supervisor=bad_sup)["status"] == "BLOCKED" and (bad_sup.execute_calls, bad_sup.reducer_calls) == (0, 0)
    for bad_lim in (None, {}, {"pids_max": 65}, {"memory_max_bytes": 1_073_741_825}, {"cpu_max": {"quota_us": 100_001, "period_us": 100_000}}, OSError("cgroup pids.max unreadable")):
        lim_sup = _FakeSealedOciSupervisorPort(sbx_payload=world_7a["sbx_cand"]["payload"], reg_state=world_7a["reg_state"], inv_pair=world_7a["inv_pair"], tamper_limits=bad_lim)
        res = gov1_7a_runner.run_7a_hermetic_execution(**kw, supervisor=lim_sup)
        assert res["status"] == "BLOCKED" and (lim_sup.execute_calls, lim_sup.reducer_calls) == (0, 0) and (not isinstance(bad_lim, OSError) or "pids.max" in res["reason"])
    executed = gov1_7a_runner.run_7a_hermetic_execution(**kw, supervisor=good_sup)
    assert executed["status"] == "EXECUTED" and good_sup.execute_calls == 1 and good_sup.reducer_calls >= 1 and executed["effective_resource_limits"] == world_7a["sbx_cand"]["payload"]["resource_limits"] and executed["execution"]["statuses"] == ["complete", "failed", "partial", "partial"]


def test_replay_helpers_differential_parity_across_wire_outcomes_and_completeness(world_7a: dict[str, Any]) -> None:
    assert wheel_build_insights_request(private_object_id="act_5544332211", admitted_day="2026-09-06") == gov1_7a_replay_helpers.build_pipeboard_insights_request(private_object_id="act_5544332211", admitted_day="2026-09-06")
    for ok_json in ('{"z":-0,"n":9223372036854775807}', '{"s":"quote \\"' + ("[" * 25) + '"}'):
        assert wheel_loads_wire_json(ok_json) == gov1_7a_replay_helpers.loads_pipeboard_wire_json(ok_json)
    depth25_esc = '{"k\\\\":' + ("[" * 25) + ("]" * 25) + "}"
    assert isinstance(json.loads(depth25_esc), dict)
    for bad_json in ('{"a":' + ("9" * 65) + "}", '{"a":1e101}', '{"k":1,"k":2}', depth25_esc):
        with pytest.raises(PipeboardAdapterError):
            wheel_loads_wire_json(bad_json)
        with pytest.raises(ValueError):
            gov1_7a_replay_helpers.loads_pipeboard_wire_json(bad_json)

    hdr_ok = [("Content-Type", "application/json")]
    dup_and_bad_hdr = [("Content-Type", "application/json"), ("Content-Type", "application/json"), ("Bad Header", "x")]
    dup_only_hdr = [("Content-Type", "application/json"), ("content-type", "application/json")]
    null_paging = b'{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\\"data\\":[],\\"paging\\":null}"}]}}'
    null_cursors = b'{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\\"data\\":[],\\"paging\\":{\\"cursors\\":null}}"}]}}'
    overlap_next = b'{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\\"data\\":{},\\"paging\\":{\\"next\\":\\"https://x\\"}}"}]}}'
    wire_matrix = [
        (False, None, hdr_ok, [b"{}"]), (True, None, hdr_ok, [b"{}"]), (True, 401, hdr_ok, [b"{}"]), (True, 503, hdr_ok, [b"{}"]),
        (True, 200, [("Content-Type", "text/html")], [b"{}"]), (True, 200, [("Content-Type", "application/json"), ("Content-Length", "10")], [b"{}"]),
        (True, 200, dup_and_bad_hdr, [b"{}"]), (True, 200, dup_only_hdr, [b"{}"]),
        (True, 200, hdr_ok, [b'{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"err"}}']),
        (True, 200, [("Content-Type", "application/json"), ("Content-Length", "2097153")], [b"{}"]),
        (True, 200, hdr_ok, [null_paging]), (True, 200, hdr_ok, [null_cursors]),
        (True, 200, hdr_ok, [b'{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\\"data\\":[],\\"paging\\":{\\"next\\":\\"cur\\"}}"}]}}']),
        (True, 200, hdr_ok, [overlap_next]), (True, 200, hdr_ok, [b'{"jsonrpc":"2.0","id":1,"extra":1,"result":{}}']),
    ]
    for net_ok, status, hdrs, chunks in wire_matrix:
        with pytest.raises(PipeboardWireRejection) as w_exc:
            wheel_parse_envelope(network_ok=net_ok, http_status=status, headers=hdrs, body_chunks=chunks)
        with pytest.raises(gov1_7a_replay_helpers.Gov1WireRejection) as g_exc:
            gov1_7a_replay_helpers.parse_pipeboard_http_and_mcp_envelope(network_ok=net_ok, http_status=status, headers=hdrs, body_chunks=chunks)
        assert (w_exc.value.code, w_exc.value.category, w_exc.value.outcome.to_dict()) == (g_exc.value.code, g_exc.value.category, g_exc.value.outcome)
        if hdrs == dup_and_bad_hdr:
            assert g_exc.value.code == "malformed_http_headers"
        elif hdrs == dup_only_hdr:
            assert g_exc.value.code == "duplicate_http_header"
        elif chunks in ([null_paging], [null_cursors]):
            assert g_exc.value.code == "invalid_paging_shape" and g_exc.value.outcome["payload_schema_valid"] is False
        elif chunks == [overlap_next]:
            assert g_exc.value.code == "non_empty_paging_next"
    _assert_gates_1_to_3_differential_parity(world_7a)


def _assert_gates_1_to_3_differential_parity(world_7a: dict[str, Any]) -> None:
    corpus_doc = loads_strict_json(world_7a["corpus_bytes"])
    reg_state, inv_pair = world_7a["reg_state"], world_7a["inv_pair"]
    kh = TenantResourceKeyHandle("tenant:ibvi", "key:7a-fixture-hmac-v1", bytes.fromhex(corpus_doc["tenant_hmac_key_hex"]))
    bnd = PrivatePipeboardBindingBoundary(resolved_registry=reg_state, key_handle=kh, private_account_bindings={("binding:meta-primary", "account:ibvi-01"): "act_5544332211"}, authenticated_inventories=[inv_pair])
    cmap = {p["raw_campaign_id"]: p["resource_ref"] for p in corpus_doc["verified_campaign_pairs"]}
    for cid, rref in cmap.items():
        bnd.register_verified_campaign_pair(cid, rref)
    c0 = corpus_doc["cases"][0]
    att = ClockAttestation.from_dict(c0["clock_reading"]["attestation"])
    clk = ResolvedClockState(ArtifactLocator.for_canonical_bytes(ClockAttestation.SCHEMA, canonicalize_jcs(att.to_dict())), att, 1000)
    reg_fix = RegressionFixtureV1.canonical(reg_state.locator.content_digest)
    prereq = ResolvedPrerequisiteBundle(PurposePrerequisiteLocators("fixture_7a", sealed_sandbox_profile_locator=ArtifactLocator.from_dict(world_7a["sbx_loc"]), regression_fixture_locator=ArtifactLocator.for_canonical_bytes(RegressionFixtureV1.SCHEMA, canonicalize_jcs(reg_fix.to_dict()))))
    adm_bundle = admit_collection(CollectionRequest.from_dict(c0["collection_request"]), _make_static_cell_ports(clk, TimezoneRuleSnapshot.from_dict(corpus_doc["timezone_snapshot"]), reg_state, prereq), admission_id=c0["admission_id"])
    adm = adm_bundle.admitted
    rctx = RetrievalContext.from_dict(c0["retrieval_context"])
    scoped = frozenset(u.resource_ref for u in inv_pair[1].expected_resources)
    esc_quote_brackets_row = canonicalize({"data": [{"campaign_id": "12021000000001", "campaign_name": 'Promo "' + ("[" * 25), "date_start": "2026-09-06", "date_stop": "2026-09-06", "impressions": "10", "clicks": "2", "spend": "1.50"}]}).decode("utf-8")
    two_camp_complete = canonicalize({"data": [{"campaign_id": cid, "date_start": "2026-09-06", "date_stop": "2026-09-06", "impressions": "10", "clicks": "2", "spend": "1.50"} for cid in sorted(cmap)]}).decode("utf-8")
    gate_payloads = [
        (esc_quote_brackets_row, None), (two_camp_complete, None),
        ('{"data":[{"campaign_id":"12021000000001","date_start":"2026-09-05","date_stop":"2026-09-05","adset_id":"bad"}]}', None),
        ('{"data":[{"campaign_id":"12021000000001","date_start":"2026-09-06","date_stop":"2026-09-06","impressions":"10"},{"campaign_id":"12021000000001","date_start":"2026-09-06","date_stop":"2026-09-06","impressions":"20"}]}', None),
        ('{"data":[{"campaign_id":"12021000000001","date_start":"2026-09-06","date_stop":"2026-09-06","impressions":"10"}]}', lambda _x: []),
    ]
    for inner_txt, custom_red in gate_payloads:
        outer = canonicalize({"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": inner_txt}]}})
        kw_red = {} if custom_red is None else {"reducer": custom_red}
        wb = transform_pipeboard_response_to_batch(admitted=adm, boundary=bnd, retrieval_context=rctx, network_ok=True, http_status=200, headers=[("Content-Type", "application/json")], body_chunks=[outer], **kw_red)
        gb = gov1_7a_replay_helpers.transform_pipeboard_response_to_batch_dict(admitted=adm.to_dict(), private_object_id="act_5544332211", known_campaign_map=cmap, scoped_resource_refs=scoped, transport_limits=DEFAULT_PIPEBOARD_TRANSPORT_LIMITS.to_dict(), retrieval_context=rctx.to_dict(), network_ok=True, http_status=200, headers=[("Content-Type", "application/json")], body_chunks=[outer], **kw_red)
        assert canonicalize(wb.to_dict()) == canonicalize(gb) and (inner_txt != esc_quote_brackets_row or len(gb["resource_observations"]) == 1)
        _, w_rows, wc = _reduce_batch_to_candidates_and_completeness(bundle=adm_bundle, batch=wb, inventory_port=bnd)
        gc = gov1_7a_replay_helpers.recompute_collection_completeness_dict(expected_resources=[u.to_dict() for u in inv_pair[1].expected_resources], required_metrics=adm.canonical_query_contract.metric_semantic_refs, metric_source_mappings=reg_state.driver_contract.metric_source_mappings, batch_dict=gb, admitted_dict=adm.to_dict())
        assert (wc.status, wc.reasons, wc.normalized_fact_set_digest) == (gc["status"], tuple(gc["reasons"]), gc["normalized_fact_set_digest"])
        if inner_txt == esc_quote_brackets_row:
            assert len(w_rows) == 3
            off_wb = replace(wb, resource_observations=(replace(wb.resource_observations[0], metric_date="2026-09-05"),))
            _, _, off_wc = _reduce_batch_to_candidates_and_completeness(bundle=adm_bundle, batch=off_wb, inventory_port=bnd)
            off_gc = gov1_7a_replay_helpers.recompute_collection_completeness_dict(expected_resources=[u.to_dict() for u in inv_pair[1].expected_resources], required_metrics=adm.canonical_query_contract.metric_semantic_refs, metric_source_mappings=reg_state.driver_contract.metric_source_mappings, batch_dict=off_wb.to_dict(), admitted_dict=adm.to_dict())
            assert off_wc.reasons == tuple(off_gc["reasons"]) and "unexpected_observed_fact_keys" in off_wc.reasons
        elif inner_txt == two_camp_complete:
            assert wc.status == "complete" and wc.normalized_fact_set_digest is not None


def test_negative_report_and_leaf_verifiers_parity_c1_and_key_counts(world_7a: dict[str, Any]) -> None:
    assert gov1_7a_negative.PINNED_7A_NEGATIVE_SUITE_DIGEST == WHEEL_NEG_SUITE_DIGEST == "sha256:8f2f561a8b6e3a75a960c04a747261ec31651e19f14457d78f915817523ec82d"
    assert (len(world_7a["neg_cand"]["payload"]), len(world_7a["neg_env"]), len(world_7a["cert_cand"]["payload"]), len(world_7a["cert_env"])) == (14, 16, 21, 23)
    with pytest.raises(ValueError):
        gov1_7a_certification.build_git_artifact_provenance_envelope(repository="aiconnai/smart-ads", commit_sha="a" * 40, path="src/bad\x80.py", raw_bytes=b"x", resolved_at_utc="2026-09-07T10:00:00Z", registry_locator=_KEY_REG_DICT, signer_key_id=_SIGNER_KEY_ID)
    c1_prov_s = _fake_sign_dict({**copy.deepcopy(world_7a["prov_env"]), "build_run_id": "build-\x80-ok"})
    c1_neg = {**copy.deepcopy(world_7a["neg_env"]), "build_run_id": "build-\x80-ok", "wheel_build_provenance_locator": make_locator(gov1_wheel.WHEEL_BUILD_PROVENANCE_SCHEMA, canonicalize(c1_prov_s))}
    gov1_7a_negative.verify_negative_security_test_report(_fake_sign_dict(c1_neg), sandbox_profile=world_7a["sbx_env"], wheel_provenance=c1_prov_s, wheel_bytes=world_7a["wheel_bytes"])
    with pytest.raises(ValueError):
        gov1_7a_negative.verify_negative_security_test_report(_fake_sign_dict({**copy.deepcopy(world_7a["neg_env"]), "build_run_id": "build-\x7f-bad"}), sandbox_profile=world_7a["sbx_env"], wheel_provenance=world_7a["prov_env"], wheel_bytes=world_7a["wheel_bytes"])
    wheel_neg = NegativeSecurityTestReport.from_dict(world_7a["neg_env"], require_signed=True)
    verify_negative_security_report_against_profile(wheel_neg, sandbox_profile=world_7a["sbx_env"], wheel_provenance_payload=world_7a["prov_env"], wheel_bytes=world_7a["wheel_bytes"])
    gov1_7a_negative.verify_negative_security_test_report(world_7a["neg_cand"], sandbox_profile=world_7a["sbx_cand"], wheel_provenance=world_7a["prov_cand"]["payload"], wheel_bytes=world_7a["wheel_bytes"])
    gov1_7a_negative.verify_negative_security_test_report(world_7a["neg_env"], sandbox_profile=world_7a["sbx_env"], wheel_provenance=world_7a["prov_env"], wheel_bytes=world_7a["wheel_bytes"])
    with pytest.raises(ValueError):
        gov1_7a_negative.verify_negative_security_test_report(world_7a["neg_env"], sandbox_profile=world_7a["sbx_env"], wheel_provenance=world_7a["prov_env"], wheel_bytes=b"")
    _assert_neg_tmpfs_ceiling_and_unsigned_envelope_guards(world_7a)


def _assert_neg_tmpfs_ceiling_and_unsigned_envelope_guards(world_7a: dict[str, Any]) -> None:
    tmp_idx = WHEEL_17_NEG_CASES.index("tmpfs_limit_enforced")
    for kind, p_bytes, p_inodes in (("inodes", 0, 4097), ("bytes", 268_435_457, 1)):
        neg_m = copy.deepcopy(world_7a["neg_env"])
        r0 = NegativeSecurityRun.from_dict({**neg_m["cases"][tmp_idx]["runs"][0], "usage": SandboxUsageCounters(cpu_time_us=1000, pids_peak=1, tmpfs_peak_bytes=p_bytes, tmpfs_peak_inodes=p_inodes).to_dict(), "observation": {"ceiling_kind": kind, "errno": "ENOSPC"}})
        rebound = wheel_neg_bind_digest(case_id="tmpfs_limit_enforced", subrun_index=0, run=r0, wheel_digest=neg_m["wheel_digest"], test_suite_digest=WHEEL_NEG_SUITE_DIGEST, sealed_sandbox_profile_digest=world_7a["sbx_spec_digest"])
        neg_m["cases"][tmp_idx]["runs"][0] = replace(r0, execution_binding_digest=rebound).to_dict()
        with pytest.raises(ValueError, match="tmpfs_peak"):
            gov1_7a_negative.verify_negative_security_test_report(_fake_sign_dict(neg_m), sandbox_profile=world_7a["sbx_env"], wheel_provenance=world_7a["prov_env"], wheel_bytes=world_7a["wheel_bytes"])
    uns_int = {"key_id": _SIGNER_KEY_ID, "key_registry_snapshot_locator": copy.deepcopy(_KEY_REG_DICT)}
    for bad_neg, bad_sbx, bad_prov in (
        ({**copy.deepcopy(world_7a["neg_env"]), "integrity": copy.deepcopy(uns_int)}, world_7a["sbx_env"], world_7a["prov_env"]),
        (world_7a["neg_env"], {**copy.deepcopy(world_7a["sbx_env"]), "integrity": copy.deepcopy(uns_int)}, world_7a["prov_env"]),
        (world_7a["neg_env"], world_7a["sbx_env"], {**copy.deepcopy(world_7a["prov_env"]), "integrity": copy.deepcopy(uns_int)}),
    ):
        with pytest.raises(ValueError, match="integrity|signed|signature|content_digest"):
            gov1_7a_negative.verify_negative_security_test_report(bad_neg, sandbox_profile=bad_sbx, wheel_provenance=bad_prov, wheel_bytes=world_7a["wheel_bytes"])


def test_passive_7a_certification_candidate_envelope_and_seven_a_constituent_verifier(world_7a: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    wheel_rec = Certification7ARecord.from_dict(world_7a["cert_env"], require_signed=True)
    wheel_verify_cert_7a(wheel_rec, object_resolver=lambda loc: world_7a["store"].get(loc.to_dict()), wheel_bytes=world_7a["wheel_bytes"], corpus_bytes=world_7a["corpus_bytes"], resolved_git_blobs=world_7a["git_blobs"], resolved_d26_blobs=world_7a["d26_blobs"])

    def _forbid_subproc(*_a: Any, **_k: Any) -> Any:
        raise AssertionError("passive 7A replay must never spawn subprocesses or call Stage 7 probes")

    for mod, attr in ((subprocess, "run"), (gov1_wheel, "inspect_wheel_boundary"), (gov1_wheel, "verify_wheel_build_provenance"), (gov1_7a_certification, "run_git_offline")):
        monkeypatch.setattr(mod, attr, _forbid_subproc)
    cand_res = gov1_7a_certification.verify_certification_7a_replay_bytes(world_7a["cert_cand"], store=world_7a["store"], wheel_bytes=world_7a["wheel_bytes"], corpus_bytes=world_7a["corpus_bytes"], resolved_git_blobs=world_7a["git_blobs"], resolved_d26_blobs=world_7a["d26_blobs"], sandbox_profile=world_7a["sbx_cand"], wheel_provenance=world_7a["prov_cand"]["payload"], wheel_boundary_report=world_7a["bound_cand"], negative_security_report=world_7a["neg_cand"])
    env_res = gov1_7a_certification.verify_certification_7a_record(world_7a["cert_env"], store=world_7a["store"], wheel_bytes=world_7a["wheel_bytes"], corpus_bytes=world_7a["corpus_bytes"], resolved_git_blobs=world_7a["git_blobs"], resolved_d26_blobs=world_7a["d26_blobs"])
    assert cand_res["mode"] == "candidate" and env_res["mode"] == "envelope"
    _assert_seven_a_constituent_verifier_and_tamper_guards(world_7a)
    _assert_store_locator_typed_batch_and_pinned_mapping_guards(world_7a)
    _assert_wheel_bomb_and_digest_gate_guards(world_7a, monkeypatch)
    _assert_run_ctx_registry_inventory_member_and_signed_guards(world_7a)


def _assert_seven_a_constituent_verifier_and_tamper_guards(world_7a: dict[str, Any]) -> None:
    stripped_prov = gov1_7a_negative.extract_provenance_payload(world_7a["prov_env"])
    mut_git, mut_d26 = dict(world_7a["git_blobs"]), dict(world_7a["d26_blobs"])
    verifier = gov1_7a_certification.SevenAConstituentVerifier(wheel_bytes=world_7a["wheel_bytes"], corpus_bytes=world_7a["corpus_bytes"], stripped_provenance_payload=stripped_prov, resolved_git_blobs=mut_git, resolved_d26_blobs=mut_d26)
    mut_git[CORPUS_GIT_PATH[1]] = b"mutated-after-init"
    verifier.verify_bound_preflight_inputs(wheel_bytes=world_7a["wheel_bytes"], corpus_bytes=world_7a["corpus_bytes"], stripped_provenance_payload=stripped_prov, resolved_git_blobs=world_7a["git_blobs"], resolved_d26_blobs=world_7a["d26_blobs"])
    with pytest.raises(ValueError):
        verifier.verify_bound_preflight_inputs(wheel_bytes=world_7a["wheel_bytes"], corpus_bytes=world_7a["corpus_bytes"], stripped_provenance_payload=stripped_prov, resolved_git_blobs=mut_git, resolved_d26_blobs=world_7a["d26_blobs"])
    out = verifier.verify_7a_constituents(negative_security_test_report_locator=world_7a["neg_loc"], certification_7a_record_locator=world_7a["cert_loc"], migration_run_context_locator=world_7a["run_ctx"], sealed_sandbox_profile_locator=world_7a["sbx_loc"], wheel_boundary_report_locator=world_7a["bound_loc"], mcp_rejection_matrix_report_locator=world_7a["mcp_loc"], build_run_id=_BUILD_RUN_ID, source_commit_sha=stripped_prov["source_commit_sha"], wheel_digest=stripped_prov["wheel_digest"], build_backend_digest=stripped_prov["build_backend_digest"], schema_bundle_digest=stripped_prov["schema_bundle_digest"], converged_at_utc="2026-09-07T10:00:20Z", store=world_7a["store"])
    assert out["certified"] is True and tuple(out["negative_cases"]) == WHEEL_17_NEG_CASES
    bad_cert = copy.deepcopy(world_7a["cert_env"])
    c0_obj = Certification7AFixtureCase.from_dict({**bad_cert["fixture_evidence"]["cases"][0], "admitted_collection_digest": "sha256:" + ("f" * 64)})
    rebound = wheel_7a_bind_digest(case=c0_obj, wheel_digest=bad_cert["wheel_digest"], corpus_digest=bad_cert["fixture_evidence"]["corpus_digest"], sealed_sandbox_profile_digest=world_7a["sbx_spec_digest"])
    bad_cert["fixture_evidence"]["cases"][0] = replace(c0_obj, execution_binding_digest=rebound).to_dict()
    with pytest.raises(ValueError, match="admitted_collection_digest"):
        gov1_7a_certification.verify_certification_7a_replay_bytes(_fake_sign_dict(bad_cert), store=world_7a["store"], wheel_bytes=world_7a["wheel_bytes"], corpus_bytes=world_7a["corpus_bytes"], resolved_git_blobs=world_7a["git_blobs"], resolved_d26_blobs=world_7a["d26_blobs"])
    with pytest.raises(ValueError, match="corpus_bytes"):
        gov1_7a_certification.verify_certification_7a_replay_bytes(world_7a["cert_env"], store=world_7a["store"], wheel_bytes=world_7a["wheel_bytes"], corpus_bytes=b"{invalid-json", resolved_git_blobs=world_7a["git_blobs"], resolved_d26_blobs=world_7a["d26_blobs"])


def _assert_store_locator_typed_batch_and_pinned_mapping_guards(world_7a: dict[str, Any]) -> None:
    store = world_7a["store"]
    kw = {"store": store, "wheel_bytes": world_7a["wheel_bytes"], "corpus_bytes": world_7a["corpus_bytes"], "resolved_git_blobs": world_7a["git_blobs"], "resolved_d26_blobs": world_7a["d26_blobs"]}
    for loc_field, schema in (("wheel_boundary_report_locator", gov1_wheel.WHEEL_BOUNDARY_REPORT_SCHEMA), ("negative_security_test_report_locator", gov1_7a_negative.NEGATIVE_SECURITY_REPORT_SCHEMA)):
        bad_loc_cert = copy.deepcopy(world_7a["cert_env"])
        bad_loc_cert[loc_field] = make_locator(schema, b'{"unresolvable":1}')
        with pytest.raises(ValueError):
            gov1_7a_certification.verify_certification_7a_replay_bytes(_fake_sign_dict(bad_loc_cert), **kw, wheel_boundary_report=world_7a["bound_env"], negative_security_report=world_7a["neg_env"])
    alt_bound = _fake_sign_dict({**copy.deepcopy(world_7a["bound_env"]), "verified_at_utc": "2026-09-07T10:00:11Z"})
    with pytest.raises(ValueError, match="diverges from Store"):
        gov1_7a_certification.verify_certification_7a_replay_bytes(world_7a["cert_env"], **kw, wheel_boundary_report=alt_bound)

    bad_batch_cert = copy.deepcopy(world_7a["cert_env"])
    c0 = bad_batch_cert["fixture_evidence"]["cases"][0]
    c0["observation_batch"]["transport_outcome"]["network_ok"] = 1
    c0["execution_binding_digest"] = json_digest({"case_id": c0["case_id"], "sandbox_instance_ref": c0["sandbox_instance_ref"], "started_at_utc": c0["started_at_utc"], "ended_at_utc": c0["ended_at_utc"], "wheel_digest": bad_batch_cert["wheel_digest"], "corpus_digest": bad_batch_cert["fixture_evidence"]["corpus_digest"], "admitted_collection_digest": c0["admitted_collection_digest"], "expected_resource_inventory_digest": c0["expected_resource_inventory_locator"]["content_digest"], "sealed_sandbox_profile_digest": world_7a["sbx_spec_digest"], "runtime_readback": c0["runtime_readback"], "effective_resource_limits": c0["effective_resource_limits"], "usage": c0["usage"], "termination": c0["termination"], "observation_batch": c0["observation_batch"]})
    with pytest.raises(ValueError):
        gov1_7a_certification.verify_certification_7a_replay_bytes(_fake_sign_dict(bad_batch_cert), **kw)

    alt_drv = copy.deepcopy(store.get(world_7a["cert_env"]["capability"]["driver_contract_locator"]))
    alt_drv["metric_source_mappings"]["metric:spend_v1"] = "source-metric:provider:pipeboard.spend_alt:v1"
    alt_drv_loc = store.put(_fake_sign_dict(alt_drv))
    alt_snap = copy.deepcopy(store.get(world_7a["cert_env"]["capability"]["registry_snapshot_locator"]))
    alt_snap["capabilities"][0]["driver_contract_locator"] = alt_drv_loc
    alt_snap["capabilities"][0]["driver_contract_digest"] = alt_drv_loc["content_digest"]
    alt_snap_loc = store.put(_fake_sign_dict(alt_snap))
    alt_cert = copy.deepcopy(world_7a["cert_env"])
    alt_cert["capability"].update({"driver_contract_locator": alt_drv_loc, "driver_contract_digest": alt_drv_loc["content_digest"], "registry_snapshot_locator": alt_snap_loc})
    alt_cert["fixture_evidence"]["regression_fixture"] = gov1_7a_replay_helpers.build_canonical_regression_fixture(alt_snap_loc["content_digest"])
    for case_d in alt_cert["fixture_evidence"]["cases"]:
        case_d["source_contract_ref"] = f"opaque-driver-contract:{alt_drv_loc['content_digest']}"
    alt_cert["mapping_rules_digest"] = gov1_7a_certification.compute_mapping_rules_digest([store.get(l) for l in alt_cert["mapping_artifact_locators"]], alt_drv["metric_source_mappings"])
    with pytest.raises(ValueError, match="pinned contract invariants"):
        gov1_7a_certification.verify_certification_7a_replay_bytes(_fake_sign_dict(alt_cert), **kw)


def _mut_local_cand(cand: Mapping[str, Any], **updates: Any) -> dict[str, Any]:
    payload = {**copy.deepcopy(cand["payload"]), **updates}
    return {**copy.deepcopy(dict(cand)), "payload": payload, "payload_digest": json_digest(payload)}


def _build_malformed_wheels_for_ceils() -> tuple[tuple[bytes, str], ...]:
    def _zip_bytes(entries: Sequence[tuple[str, bytes, int]]) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            for name, raw, comp in entries:
                zf.writestr(zipfile.ZipInfo(name), raw, compress_type=comp)
        return buf.getvalue()

    def _patch_uncomp(raw_zip: bytes, prefix: bytes) -> bytes:
        ba = bytearray(raw_zip)
        cd, crc, sz = ba.rfind(b"PK\x01\x02"), struct.pack("<I", zlib.crc32(prefix) & 0xFFFFFFFF), struct.pack("<I", len(prefix))
        ba[14:18], ba[22:26], ba[cd + 16 : cd + 20], ba[cd + 24 : cd + 28] = crc, sz, crc, sz
        return bytes(ba)

    ok_zero = _zip_bytes([("smart_ads/__init__.py", b"", zipfile.ZIP_STORED), ("smart_ads-0.1.0.dist-info/METADATA", b"", zipfile.ZIP_DEFLATED), ("smart_ads-0.1.0.dist-info/WHEEL", b"w", zipfile.ZIP_STORED), (gov1_wheel.EXPECTED_SELF_RECORD_PATH, b"", zipfile.ZIP_DEFLATED)])
    assert gov1_wheel._extract_wheel_zip_members(ok_zero)["smart_ads/__init__.py"] == b"" and gov1_wheel._extract_wheel_zip_members(ok_zero)["smart_ads-0.1.0.dist-info/METADATA"] == b""
    return (
        (_zip_bytes([("smart_ads/big.py", b"\x00" * 8_388_609, zipfile.ZIP_DEFLATED)]), "> 8 MiB"),
        (_zip_bytes([(f"smart_ads/m{i}.py", b"\x00" * 7_000_000, zipfile.ZIP_DEFLATED) for i in range(5)]), "32 MiB"),
        (_zip_bytes([(f"smart_ads/e{i}.py", b"x", zipfile.ZIP_STORED) for i in range(513)]), "> 512"),
        (_patch_uncomp(_zip_bytes([("smart_ads/clip.py", b"hello!", zipfile.ZIP_DEFLATED)]), b"hello"), "oversized DEFLATE stream"),
        (_patch_uncomp(_zip_bytes([("smart_ads/bomb.py", b"\x00" * (12 * 1024 * 1024), zipfile.ZIP_DEFLATED)]), b"\x00" * 64), "oversized DEFLATE stream"),
    )


def _assert_wheel_bomb_and_digest_gate_guards(world_7a: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    kw_base = {"store": world_7a["store"], "corpus_bytes": world_7a["corpus_bytes"], "resolved_git_blobs": world_7a["git_blobs"], "resolved_d26_blobs": world_7a["d26_blobs"]}
    archive_calls: list[int] = []
    with monkeypatch.context() as mp:
        mp.setattr(gov1_7a_certification, "_read_and_validate_wheel_archive", lambda b: archive_calls.append(len(b)))
        bc_lst, nc_dct = _mut_local_cand(world_7a["bound_cand"], wheel_digest=[]), _mut_local_cand(world_7a["neg_cand"], wheel_digest={})
        cc_lst = _mut_local_cand(world_7a["cert_cand"], wheel_boundary_report_candidate_ref=gov1_sandbox.build_local_candidate_ref(bc_lst))
        cc_dct = _mut_local_cand(world_7a["cert_cand"], negative_security_test_report_candidate_ref=gov1_sandbox.build_local_candidate_ref(nc_dct))
        for fn in (
            lambda: gov1_7a_certification.verify_certification_7a_replay_bytes(world_7a["cert_env"], **kw_base, wheel_bytes=world_7a["wheel_bytes"] + b"x"),
            lambda: gov1_7a_certification.verify_certification_7a_replay_bytes(world_7a["cert_cand"], **kw_base, wheel_bytes=world_7a["wheel_bytes"] + b"x", sandbox_profile=world_7a["sbx_cand"], wheel_provenance=world_7a["prov_cand"]["payload"], wheel_boundary_report=world_7a["bound_cand"], negative_security_report=world_7a["neg_cand"]),
            lambda: gov1_7a_certification.verify_certification_7a_replay_bytes(cc_lst, **kw_base, wheel_bytes=world_7a["wheel_bytes"], sandbox_profile=world_7a["sbx_cand"], wheel_provenance=world_7a["prov_cand"]["payload"], wheel_boundary_report=bc_lst, negative_security_report=world_7a["neg_cand"]),
            lambda: gov1_7a_certification.verify_certification_7a_replay_bytes(cc_dct, **kw_base, wheel_bytes=world_7a["wheel_bytes"], sandbox_profile=world_7a["sbx_cand"], wheel_provenance=world_7a["prov_cand"]["payload"], wheel_boundary_report=world_7a["bound_cand"], negative_security_report=nc_dct),
        ):
            with pytest.raises(ValueError, match="wheel_digest"):
                fn()
    assert archive_calls == []
    for bad_whl, err_pat in _build_malformed_wheels_for_ceils():
        wd = digest(bad_whl)
        pc = _mut_local_cand(world_7a["prov_cand"], wheel_digest=wd, wheel=gov1_wheel.build_wheel_object_locator(bad_whl))
        pr = gov1_sandbox.build_local_candidate_ref(pc)
        bc = _mut_local_cand(world_7a["bound_cand"], wheel_digest=wd, wheel_build_provenance_candidate_ref=pr)
        nc = _mut_local_cand(world_7a["neg_cand"], wheel_digest=wd, wheel_build_provenance_candidate_ref=pr)
        cc = _mut_local_cand(world_7a["cert_cand"], wheel_digest=wd, wheel_build_provenance_candidate_ref=pr, wheel_boundary_report_candidate_ref=gov1_sandbox.build_local_candidate_ref(bc), negative_security_test_report_candidate_ref=gov1_sandbox.build_local_candidate_ref(nc))
        tracemalloc.start()
        try:
            with pytest.raises(ValueError, match=err_pat):
                gov1_7a_certification.verify_certification_7a_replay_bytes(cc, **kw_base, wheel_bytes=bad_whl, sandbox_profile=world_7a["sbx_cand"], wheel_provenance=pc["payload"], wheel_boundary_report=bc, negative_security_report=nc)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        assert err_pat != "oversized DEFLATE stream" or peak < 1_048_576


def _assert_run_ctx_registry_inventory_member_and_signed_guards(world_7a: dict[str, Any]) -> None:
    store = world_7a["store"]
    kw = {"store": store, "wheel_bytes": world_7a["wheel_bytes"], "corpus_bytes": world_7a["corpus_bytes"], "resolved_git_blobs": world_7a["git_blobs"], "resolved_d26_blobs": world_7a["d26_blobs"]}
    alt_ctx = make_locator("smart_ads/migration_run_context/v1", b'{"run":"ctx-b"}')
    bc_ctx = _mut_local_cand(world_7a["bound_cand"], migration_run_context_locator=alt_ctx)
    cc_ctx = _mut_local_cand(world_7a["cert_cand"], migration_run_context_locator=alt_ctx, wheel_boundary_report_candidate_ref=gov1_sandbox.build_local_candidate_ref(bc_ctx))
    with pytest.raises(ValueError, match="migration_run_context_locator"):
        gov1_7a_certification.verify_certification_7a_replay_bytes(cc_ctx, **kw, sandbox_profile=world_7a["sbx_cand"], wheel_provenance=world_7a["prov_cand"]["payload"], wheel_boundary_report=bc_ctx, negative_security_report=world_7a["neg_cand"])
    be_loc = store.put(_fake_sign_dict({**copy.deepcopy(world_7a["bound_env"]), "migration_run_context_locator": alt_ctx}))
    with pytest.raises(ValueError, match="migration_run_context_locator"):
        gov1_7a_certification.verify_certification_7a_record(_fake_sign_dict({**copy.deepcopy(world_7a["cert_env"]), "migration_run_context_locator": alt_ctx, "wheel_boundary_report_locator": be_loc}), **kw)
    snap0 = copy.deepcopy(store.get(world_7a["cert_env"]["capability"]["registry_snapshot_locator"]))
    b0, c0 = snap0["bindings"][0], snap0["capabilities"][0]
    for bad_snap in ({**copy.deepcopy(snap0), "bindings": [{**b0, "account_ref": "account:ibvi-00"}, b0]}, {**copy.deepcopy(snap0), "bindings": [{**b0, "binding_ref": "binding:meta-a"}, b0]}, {**copy.deepcopy(snap0), "capabilities": [{**c0, "state": []}]}, {**copy.deepcopy(snap0), "capabilities": [{**c0, "capability_semantic_version": "   "}]}):
        s_s = _fake_sign_dict(bad_snap)
        s_loc = store.put(s_s)
        c_bad = {**copy.deepcopy(world_7a["cert_env"]), "capability": {**copy.deepcopy(world_7a["cert_env"]["capability"]), "registry_snapshot_locator": s_loc}, "fixture_evidence": {**copy.deepcopy(world_7a["cert_env"]["fixture_evidence"]), "regression_fixture": gov1_7a_replay_helpers.build_canonical_regression_fixture(s_loc["content_digest"])}}
        for fn in (lambda: gov1_7a_certification.verify_certification_7a_record(_fake_sign_dict(c_bad), **kw), lambda: gov1_7a_replay_helpers.recompute_fixture_7a_admission(collection_request={}, admission_id="admission:1", clock_attestation={}, configured_max_uncertainty_ms=1000, timezone_snapshot={}, registry_snapshot=s_s, registry_snapshot_locator=s_loc, driver_contract={}, driver_contract_locator=world_7a["cert_env"]["capability"]["driver_contract_locator"], sealed_sandbox_profile_locator=world_7a["sbx_loc"], regression_fixture_locator=world_7a["sbx_loc"])):
            with pytest.raises(ValueError):
                fn()
    with pytest.raises(ValueError):
        PrivateRegistrySnapshot.from_dict(_fake_sign_dict({**copy.deepcopy(snap0), "capabilities": [{**c0, "capability_semantic_version": "   "}]}), require_signed=True)
    pad_s = _fake_sign_dict({**copy.deepcopy(snap0), "capabilities": [{**c0, "capability_semantic_version": " 1.0.0 "}]})
    pad_loc = store.put(pad_s)
    pad_reg = ResolvedRegistryState(ArtifactLocator.from_dict(pad_loc), PrivateRegistrySnapshot.from_dict(pad_s, require_signed=True), world_7a["reg_state"].driver_contract_locator, world_7a["reg_state"].driver_contract)
    pad_inv_s = _fake_sign_dict({**{k: v for k, v in copy.deepcopy(store.get(world_7a["inv_pair"][0].to_dict())).items() if k != "integrity"}, "registry_snapshot_locator": pad_loc, "registry_snapshot_digest": pad_loc["content_digest"]})
    pad_rf, pad_cases = _build_7a_cases_dicts(corpus_doc=loads_strict_json(world_7a["corpus_bytes"]), reg_state=pad_reg, inv_pair=(ArtifactLocator.from_dict(store.put(pad_inv_s)), ExpectedResourceInventory.from_dict(pad_inv_s, require_signed=True)), sbx_loc=ArtifactLocator.from_dict(world_7a["sbx_loc"]), sbx_payload=world_7a["sbx_cand"]["payload"], sbx_spec_digest=world_7a["sbx_spec_digest"], whl_digest=world_7a["cert_env"]["wheel_digest"], corpus_digest=world_7a["cert_env"]["fixture_evidence"]["corpus_digest"])
    gov1_7a_runner.validate_private_registry_snapshot_payload(pad_s)
    assert pad_reg.snapshot.capabilities[0].capability_semantic_version == " 1.0.0 " and gov1_7a_certification.verify_certification_7a_record(_fake_sign_dict({**copy.deepcopy(world_7a["cert_env"]), "capability": {**copy.deepcopy(world_7a["cert_env"]["capability"]), "registry_snapshot_locator": pad_loc}, "fixture_evidence": {**copy.deepcopy(world_7a["cert_env"]["fixture_evidence"]), "regression_fixture": pad_rf, "cases": pad_cases}}), **kw)["mode"] == "envelope"
    _assert_inventory_member_and_unsigned_store_guards(world_7a, kw)


def _assert_inventory_member_and_unsigned_store_guards(world_7a: dict[str, Any], kw: Mapping[str, Any]) -> None:
    store: Store = world_7a["store"]
    alt_inv_loc = store.put(_fake_sign_dict({**copy.deepcopy(store.get(world_7a["inv_pair"][0].to_dict())), "inventory_id": "inventory:7a-2026-09-06-alt"}))
    c_inv = copy.deepcopy(world_7a["cert_env"])
    c2_obj = Certification7AFixtureCase.from_dict({**c_inv["fixture_evidence"]["cases"][2], "expected_resource_inventory_locator": alt_inv_loc})
    c_inv["fixture_evidence"]["cases"][2] = replace(c2_obj, execution_binding_digest=wheel_7a_bind_digest(case=c2_obj, wheel_digest=c_inv["wheel_digest"], corpus_digest=c_inv["fixture_evidence"]["corpus_digest"], sealed_sandbox_profile_digest=world_7a["sbx_spec_digest"])).to_dict()
    with pytest.raises(ValueError, match="conflicting inventory locators"):
        gov1_7a_certification.verify_certification_7a_record(_fake_sign_dict(c_inv), **kw)
    drv_m = copy.deepcopy(store.get(world_7a["cert_env"]["capability"]["driver_contract_locator"]))
    drv_m["legacy_source_packet"]["members"][0]["extra"] = 1
    drv_m["legacy_source_packet"]["packet_digest"] = json_digest({k: v for k, v in drv_m["legacy_source_packet"].items() if k != "packet_digest"})
    drv_m_loc = store.put(_fake_sign_dict(drv_m))
    snap_m = copy.deepcopy(store.get(world_7a["cert_env"]["capability"]["registry_snapshot_locator"]))
    snap_m["capabilities"][0].update({"driver_contract_locator": drv_m_loc, "driver_contract_digest": drv_m_loc["content_digest"]})
    snap_m_loc = store.put(_fake_sign_dict(snap_m))
    c_mem = copy.deepcopy(world_7a["cert_env"])
    c_mem["capability"].update({"driver_contract_locator": drv_m_loc, "driver_contract_digest": drv_m_loc["content_digest"], "registry_snapshot_locator": snap_m_loc})
    c_mem["fixture_evidence"]["regression_fixture"] = gov1_7a_replay_helpers.build_canonical_regression_fixture(snap_m_loc["content_digest"])
    for case_d in c_mem["fixture_evidence"]["cases"]:
        case_d["source_contract_ref"] = f"opaque-driver-contract:{drv_m_loc['content_digest']}"
    with pytest.raises(ValueError, match="legacy_source_packet.member"):
        gov1_7a_certification.verify_certification_7a_record(_fake_sign_dict(c_mem), **kw)
    uns_int = {"key_id": _SIGNER_KEY_ID, "key_registry_snapshot_locator": copy.deepcopy(_KEY_REG_DICT)}
    uns_bound = store.put({**copy.deepcopy(world_7a["bound_env"]), "integrity": copy.deepcopy(uns_int)})
    uns_git = store.put({**copy.deepcopy(store.get(world_7a["cert_env"]["fixture_evidence"]["corpus_git_locator"])), "integrity": copy.deepcopy(uns_int)})
    c_uns_git = {**copy.deepcopy(world_7a["cert_env"]), "fixture_evidence": {**copy.deepcopy(world_7a["cert_env"]["fixture_evidence"]), "corpus_git_locator": uns_git}}
    for bad_cert in ({**copy.deepcopy(world_7a["cert_env"]), "integrity": copy.deepcopy(uns_int)}, _fake_sign_dict({**copy.deepcopy(world_7a["cert_env"]), "wheel_boundary_report_locator": uns_bound}), _fake_sign_dict(c_uns_git)):
        with pytest.raises(ValueError, match="integrity|signed|signature|content_digest"):
            gov1_7a_certification.verify_certification_7a_record(bad_cert, **kw)
