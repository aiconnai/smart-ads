"""Tests for Etapa 11 convergence unlock, D4 lineage `1..tip_reg`, 4 leaf classes, and 6 CLI subcommands."""
from __future__ import annotations

import base64
from collections.abc import Callable, Mapping
import copy
import json
from pathlib import Path
import subprocess
import tracemalloc
from types import MappingProxyType
from typing import Any

import pytest

from smart_ads.domain.pipeboard_contract import PINNED_LEGACY_COMMIT, PINNED_PIPEBOARD_D26_SPECS
from smart_ads.reconciliation.certification_7a import CORPUS_GIT_PATH
from tests.governance.test_gov1_convergence import (
    ALT_RUN_CONTEXT_LOCATOR, BUILD_RUN_ID, CONVERGED_AT_UTC, EXECUTED_AT_UTC, ISSUED_AT_UTC, REPO_ROOT,
    RUN_CONTEXT_LOCATOR, FakeOsIsolatedWheelProbeRunner, Gov1D4World, MemoryProtectedRuntime,
    _StructuralFakePr3Verifier, _make_conv_base_kwargs, _recompute_candidate_digest,
    baseline_artifacts, synthetic_gov1_keys,
)
from tools.governance import cli, decomposition_governance, gov1_7a_certification, gov1_7a_negative, gov1_7a_runner, gov1_convergence, gov1_mcp, gov1_sandbox, gov1_wheel, p1
from tools.governance.decomposition_runtime import CHECKPOINT, INVENTORY, REGISTRY, InstallationPins
from tools.governance.gov1_d4_helpers import (
    Gov1InstallationPins, SnapshotStore, _resolve_d4_pins, _verify_d4_registry_lineage_step,
    _verify_d4_registry_membership, build_gov1_convergence_record_candidate, verify_gov1_convergence_candidate,
)
from tools.governance.jcs import canonicalize
from tools.governance.locator import Store, digest, make_locator

__all__ = ["baseline_artifacts", "synthetic_gov1_keys"]


def _forbid_local_stage7_probes(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(*_a: Any, **_kw: Any) -> Any:
        raise AssertionError("local Stage-7 subprocess probe invoked unexpectedly")

    monkeypatch.setattr(gov1_wheel, "_run_local_clean_venv_import_probe", _boom)
    monkeypatch.setattr(gov1_wheel, "_run_local_pep517_subprocess", _boom)
    monkeypatch.setattr(gov1_mcp, "_run_local_clean_venv_mcp_probe", _boom)


def _stage_d26_blobs_dir(dest: Path, d26_blobs: Mapping[str, bytes]) -> Path:
    dest.mkdir(parents=True, exist_ok=True)
    for role, rel_path, _, _ in PINNED_PIPEBOARD_D26_SPECS:
        (dest / f"{role}__{Path(rel_path).name}").write_bytes(d26_blobs[rel_path])
    return dest


def _install_fake_d26_git_runner(
    monkeypatch: pytest.MonkeyPatch, target_repo: Path, staged_dir: Path, seen_queries: list[tuple[str, ...]]
) -> None:
    role_by_path = {rel: role for role, rel, _, _ in PINNED_PIPEBOARD_D26_SPECS}

    def _fake_runner(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
        assert repo == target_repo and check is True
        seen_queries.append(args)
        if args == ("rev-parse", "--verify", f"{PINNED_LEGACY_COMMIT}^{{commit}}"):
            return subprocess.CompletedProcess(args, 0, stdout=f"{PINNED_LEGACY_COMMIT}\n".encode("ascii"), stderr=b"")
        prefix = f"{PINNED_LEGACY_COMMIT}:"
        assert len(args) == 3 and args[:2] == ("cat-file", "blob") and args[2].startswith(prefix)
        rel = args[2][len(prefix) :]
        raw = (staged_dir / f"{role_by_path[rel]}__{Path(rel).name}").read_bytes()
        return subprocess.CompletedProcess(args, 0, stdout=raw, stderr=b"")

    monkeypatch.setattr(gov1_7a_runner, "run_git_offline", _fake_runner)


def _build_signed_conv_in_world(
    world: Gov1D4World, keys: dict[str, tuple[Path, bytes, str]], baseline: Mapping[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    pr3_v = world.make_pr3_verifier()
    conv_u = gov1_convergence.build_gov1_convergence_record_envelope(
        **_make_conv_base_kwargs(world, keys, baseline), store=world.store, pr3_verifier=pr3_v
    )
    conv_s = p1.sign_envelope(
        conv_u, world.profiles[gov1_convergence.GOV1_CONVERGENCE_SCHEMA]["domain_prefix"], keys["gov1_convergence_verifier"][0]
    )
    return conv_s, world.store.put(conv_s)


def _make_conv_candidate(world: Gov1D4World, baseline: Mapping[str, Any]) -> dict[str, Any]:
    snap: gov1_wheel.GitBuildSnapshot = baseline["snapshot"]
    return build_gov1_convergence_record_candidate(
        migration_run_context_locator=RUN_CONTEXT_LOCATOR,
        wheel_boundary_report_candidate_ref=gov1_sandbox.build_local_candidate_ref(baseline["boundary_cand"]),
        sealed_sandbox_profile_candidate_ref=baseline["sandbox_cand_ref"],
        negative_security_test_report_candidate_ref=gov1_sandbox.build_local_candidate_ref(baseline["neg_cand"]),
        mcp_rejection_matrix_report_candidate_ref=gov1_sandbox.build_local_candidate_ref(baseline["mcp_cand"]),
        certification_7a_record_candidate_ref=gov1_sandbox.build_local_candidate_ref(world.cert_cand),
        build_run_id=BUILD_RUN_ID, converged_at_utc=CONVERGED_AT_UTC, source_commit_sha=snap.commit_sha,
        wheel_digest=digest(baseline["wheel_bytes"]), build_backend_digest=snap.build_backend_digest,
        schema_bundle_digest=baseline["inspection"]["schema_bundle_digest"],
    )


def test_ordered_handoff_in_candidate_and_envelope_modes_blocks_before_7a_replay(
    tmp_path: Path, baseline_artifacts: dict[str, Any], synthetic_gov1_keys: dict[str, tuple[Path, bytes, str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    _forbid_local_stage7_probes(monkeypatch)
    world = Gov1D4World(tmp_path, synthetic_gov1_keys, baseline_artifacts)
    conv_cand = _make_conv_candidate(world, baseline_artifacts)
    cand_kw: dict[str, Any] = {
        "repo_root": REPO_ROOT, "wheel_path": baseline_artifacts["wheel_path"], "corpus_path": world.corpus_path,
        "seccomp_profile": baseline_artifacts["seccomp_profile"], "sandbox_profile": baseline_artifacts["sandbox_cand"],
        "wheel_provenance": baseline_artifacts["prov_cand"], "wheel_boundary_report": baseline_artifacts["boundary_cand"],
        "mcp_rejection_report": baseline_artifacts["mcp_cand"], "negative_security_report": baseline_artifacts["neg_cand"],
        "certification_7a_record": world.cert_cand, "convergence_candidate": conv_cand, "store": world.store,
        "legacy_blobs_dir": world.legacy_blobs_dir, "probe_runner": world.probe_runner,
    }
    res = verify_gov1_convergence_candidate(**cand_kw)
    assert res["convergence_status"] == "PASS" and res["mode"] == "candidate" and res["signable"] is False

    _assert_candidate_tamper_stops_before_7a(monkeypatch, cand_kw, world, baseline_artifacts)
    _assert_envelope_tamper_stops_before_7a(monkeypatch, world, synthetic_gov1_keys, baseline_artifacts)


def _mut_cand(cand: Mapping[str, Any], **payload_updates: Any) -> dict[str, Any]:
    cloned = copy.deepcopy(dict(cand))
    cloned["payload"].update(payload_updates)
    return _recompute_candidate_digest(cloned)


def _assert_candidate_tamper_stops_before_7a(
    monkeypatch: pytest.MonkeyPatch, cand_kw: Mapping[str, Any], world: Gov1D4World, baseline: Mapping[str, Any]
) -> None:
    replay_calls: list[str] = []
    orig_replay = gov1_7a_certification.verify_certification_7a_replay_bytes
    monkeypatch.setattr(gov1_7a_certification, "verify_certification_7a_replay_bytes", lambda *a, **kw: (replay_calls.append("7a"), orig_replay(*a, **kw))[1])
    bad_prov = _mut_cand(baseline["prov_cand"], pyproject_sha256="sha256:" + ("e" * 64))
    bad_prov_ref = gov1_sandbox.build_local_candidate_ref(bad_prov)
    bad_bound = _mut_cand(baseline["boundary_cand"], wheel_build_provenance_candidate_ref=bad_prov_ref)
    bad_neg = _mut_cand(baseline["neg_cand"], wheel_build_provenance_candidate_ref=bad_prov_ref)
    bad_cert = _mut_cand(world.cert_cand, wheel_build_provenance_candidate_ref=bad_prov_ref, wheel_boundary_report_candidate_ref=gov1_sandbox.build_local_candidate_ref(bad_bound), negative_security_test_report_candidate_ref=gov1_sandbox.build_local_candidate_ref(bad_neg))
    bad_conv = _mut_cand(cand_kw["convergence_candidate"], wheel_boundary_report_candidate_ref=gov1_sandbox.build_local_candidate_ref(bad_bound), negative_security_test_report_candidate_ref=gov1_sandbox.build_local_candidate_ref(bad_neg), certification_7a_record_candidate_ref=gov1_sandbox.build_local_candidate_ref(bad_cert))
    with pytest.raises(ValueError):
        verify_gov1_convergence_candidate(**{**cand_kw, "wheel_provenance": bad_prov, "wheel_boundary_report": bad_bound, "negative_security_report": bad_neg, "certification_7a_record": bad_cert, "convergence_candidate": bad_conv})
    div_conv = _mut_cand(cand_kw["convergence_candidate"], negative_security_test_report_candidate_ref=gov1_sandbox.build_local_candidate_ref(bad_neg))
    with pytest.raises(ValueError):
        verify_gov1_convergence_candidate(**{**cand_kw, "negative_security_report": bad_neg, "convergence_candidate": div_conv})
    assert replay_calls == []


def _assert_envelope_tamper_stops_before_7a(
    monkeypatch: pytest.MonkeyPatch, world: Gov1D4World, keys: dict[str, tuple[Path, bytes, str]], baseline: Mapping[str, Any]
) -> None:
    conv_s, _ = _build_signed_conv_in_world(world, keys, baseline)
    pr3_v = world.make_pr3_verifier()
    ok_res = gov1_convergence.verify_gov1_convergence_record(
        conv_s, store=world.store, seccomp_profile=baseline["seccomp_profile"], wheel_path=baseline["wheel_path"],
        corpus_path=world.corpus_path, repo_root=REPO_ROOT, legacy_blobs_dir=world.legacy_blobs_dir,
        pr3_verifier=pr3_v, probe_runner=world.probe_runner,
    )
    assert ok_res["convergence_status"] == "PASS" and ok_res["authority"] == "none"

    calls: list[str] = []
    orig_v7a = pr3_v.verify_7a_constituents
    monkeypatch.setattr(pr3_v, "verify_7a_constituents", lambda **kw: (calls.append("v7a"), orig_v7a(**kw))[1])
    bad_whl = world.store.root.parent / "bad_envelope.whl"
    bad_whl.write_bytes(baseline["wheel_bytes"] + b"tamper")
    with pytest.raises(ValueError):
        gov1_convergence.verify_gov1_convergence_record(
            conv_s, store=world.store, seccomp_profile=baseline["seccomp_profile"], wheel_path=bad_whl,
            corpus_path=world.corpus_path, repo_root=REPO_ROOT, legacy_blobs_dir=world.legacy_blobs_dir,
            pr3_verifier=pr3_v, probe_runner=world.probe_runner,
        )
    assert calls == []
    _assert_envelope_bad_preflight_stops_before_stage7(monkeypatch, conv_s, world, pr3_v, baseline)


def _assert_envelope_bad_preflight_stops_before_stage7(
    monkeypatch: pytest.MonkeyPatch, conv_s: dict[str, Any], world: Gov1D4World,
    pr3_v: gov1_7a_certification.SevenAConstituentVerifier, baseline: Mapping[str, Any],
) -> None:
    spy_runner = FakeOsIsolatedWheelProbeRunner(
        wheel_bytes=baseline["wheel_bytes"], inspection=baseline["inspection"],
        mcp_exec=baseline["execution"], snapshot_files=baseline["snapshot"].files,
    )
    bad_blobs = _stage_d26_blobs_dir(world.store.root.parent / "bad_env_d26", baseline["d26_blobs"])
    role0, rel0, _, _ = PINNED_PIPEBOARD_D26_SPECS[0]
    (bad_blobs / f"{role0}__{Path(rel0).name}").write_bytes(b"corrupted")
    bad_corpus = world.store.root.parent / "nonempty_divergent_corpus.json"
    bad_corpus.write_bytes(baseline["corpus_bytes"] + b"\n")
    base_kw: dict[str, Any] = {
        "store": world.store, "seccomp_profile": baseline["seccomp_profile"], "wheel_path": baseline["wheel_path"],
        "corpus_path": world.corpus_path, "repo_root": REPO_ROOT, "legacy_blobs_dir": world.legacy_blobs_dir,
        "pr3_verifier": pr3_v, "probe_runner": spy_runner,
    }
    for bad_over in ({"corpus_path": world.store.root.parent / "missing_corpus.json"}, {"corpus_path": bad_corpus}, {"legacy_blobs_dir": bad_blobs}):
        with pytest.raises(ValueError):
            gov1_convergence.verify_gov1_convergence_record(conv_s, **{**base_kw, **bad_over})
        assert spy_runner.calls == []
    with pytest.raises(ValueError, match="corpus_path bytes disagree with Git blob"):
        gov1_convergence._verify_convergence_envelope_core(
            conv_s, store=world.store, seccomp_profile=baseline["seccomp_profile"], wheel_path=baseline["wheel_path"],
            corpus_path=bad_corpus, repo_root=REPO_ROOT, legacy_repo=None, legacy_blobs_dir=world.legacy_blobs_dir,
            backend_wheel_dir=None, site_packages_dir=None, pr3_verifier=None, probe_runner=spy_runner, cli_auto_pr3=True,
        )
    assert spy_runner.calls == []
    orig_git = gov1_7a_certification.resolve_7a_smart_ads_git_blobs
    monkeypatch.setattr(gov1_7a_certification, "resolve_7a_smart_ads_git_blobs", lambda r, sha: {**dict(orig_git(r, sha)), CORPUS_GIT_PATH[1]: b"tampered"})
    with pytest.raises(ValueError):
        gov1_convergence.verify_gov1_convergence_record(conv_s, **base_kw)
    assert spy_runner.calls == []
    monkeypatch.setattr(gov1_7a_certification, "resolve_7a_smart_ads_git_blobs", orig_git)


def test_d4_rejects_protocol_fakes_stale_preflights_and_enforces_snapshot_store(
    tmp_path: Path, baseline_artifacts: dict[str, Any], synthetic_gov1_keys: dict[str, tuple[Path, bytes, str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    _forbid_local_stage7_probes(monkeypatch)
    world = Gov1D4World(tmp_path, synthetic_gov1_keys, baseline_artifacts)
    _, conv_loc = _build_signed_conv_in_world(world, synthetic_gov1_keys, baseline_artifacts)
    with pytest.raises(ValueError):
        gov1_convergence.Gov1AdmissionVerifier(
            world.runtime, world.pins, world.store, world.adr, inventory_locator=world.inventory_loc,
            pr3_verifier=_StructuralFakePr3Verifier(), isolated_probe_runner=world.probe_runner,
            corpus_path=world.corpus_path, legacy_blobs_dir=world.legacy_blobs_dir,
        )
    assert world.runtime.cas_calls == 0
    _assert_d4_rejects_all_5_divergent_preflight_inputs(world, baseline_artifacts, conv_loc)
    _assert_d4_passes_only_snapshot_store(world, baseline_artifacts, conv_loc, monkeypatch)


def _assert_d4_rejects_all_5_divergent_preflight_inputs(
    world: Gov1D4World, baseline: Mapping[str, Any], conv_loc: dict[str, Any]
) -> None:
    prov_p = gov1_7a_negative.extract_provenance_payload(world.prov_env)
    single_attr_mutations: tuple[tuple[str, Any, str], ...] = (
        ("_wheel_bytes", baseline["wheel_bytes"] + b"alt", "wheel_bytes or corpus_bytes diverged"),
        ("_corpus_bytes", baseline["corpus_bytes"] + b"\n", "wheel_bytes or corpus_bytes diverged"),
        ("_stripped_provenance_payload", {**prov_p, "built_at_utc": "2026-09-07T10:00:06Z"}, "stripped_provenance_payload diverged"),
        ("_resolved_git_blobs", MappingProxyType({**dict(baseline["git_blobs"]), "src/smart_ads/adapters/pipeboard/__init__.py": b"# tampered\n"}), "resolved_git_blobs or resolved_d26_blobs diverged"),
        ("_resolved_d26_blobs", MappingProxyType({**dict(baseline["d26_blobs"]), PINNED_PIPEBOARD_D26_SPECS[0][1]: b"diverged"}), "resolved_git_blobs or resolved_d26_blobs diverged"),
    )
    for attr_name, mutated_val, expected_msg in single_attr_mutations:
        bad_v = world.make_pr3_verifier()
        object.__setattr__(bad_v, attr_name, mutated_val)
        with pytest.raises(ValueError, match=expected_msg):
            world.make_verifier(pr3_verifier=bad_v).verify_artifact(conv_loc, seccomp_profile=baseline["seccomp_profile"], wheel_path=baseline["wheel_path"], repo_root=REPO_ROOT)
        assert world.runtime.cas_calls == 0


def _assert_d4_passes_only_snapshot_store(
    world: Gov1D4World, baseline: Mapping[str, Any], conv_loc: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    unauth_loc = world.store.put({"$schema": "smart_ads/unauthenticated_dummy/v1", "x": 1})
    pr3_ok = world.make_pr3_verifier()
    seen_stores: list[Store] = []
    orig_v7a = pr3_ok.verify_7a_constituents

    def _spy_v7a(**kw: Any) -> Mapping[str, Any]:
        st = kw["store"]
        seen_stores.append(st)
        assert isinstance(st, SnapshotStore) and isinstance(st, Store) and st is not world.store
        with pytest.raises(ValueError):
            st.put({"$schema": "smart_ads/x/v1"})
        with pytest.raises(ValueError):
            st.get(unauth_loc)
        return orig_v7a(**kw)

    monkeypatch.setattr(pr3_ok, "verify_7a_constituents", _spy_v7a)
    res = world.make_verifier(pr3_verifier=pr3_ok).verify_artifact(
        conv_loc, seccomp_profile=baseline["seccomp_profile"],
        wheel_path=baseline["wheel_path"], repo_root=REPO_ROOT,
    )
    assert res["verification_status"] == "VERIFIED" and len(seen_stores) == 1 and world.runtime.cas_calls == 1


def test_all_five_d4_probe_entrypoints_require_os_isolated_probe_runner(
    tmp_path: Path, baseline_artifacts: dict[str, Any], synthetic_gov1_keys: dict[str, tuple[Path, bytes, str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    _forbid_local_stage7_probes(monkeypatch)
    world = Gov1D4World(tmp_path, synthetic_gov1_keys, baseline_artifacts)
    _, conv_loc = _build_signed_conv_in_world(world, synthetic_gov1_keys, baseline_artifacts)
    pr3_ok = world.make_pr3_verifier()

    bad_runners: tuple[Any, ...] = (
        None,
        FakeOsIsolatedWheelProbeRunner(wheel_bytes=baseline_artifacts["wheel_bytes"], inspection=baseline_artifacts["inspection"], mcp_exec=baseline_artifacts["execution"], os_isolated=False),
        FakeOsIsolatedWheelProbeRunner(wheel_bytes=baseline_artifacts["wheel_bytes"], inspection=baseline_artifacts["inspection"], mcp_exec=baseline_artifacts["execution"], os_isolated=1),
    )
    for bad_runner in bad_runners:
        v = gov1_convergence.Gov1AdmissionVerifier(
            world.runtime, world.pins, world.store, world.adr,
            inventory_locator=world.inventory_loc, pr3_verifier=pr3_ok,
            isolated_probe_runner=bad_runner, corpus_path=world.corpus_path, legacy_blobs_dir=world.legacy_blobs_dir,
        )
        _assert_five_d4_calls_fail_closed(v, world, baseline_artifacts, conv_loc)
    assert world.runtime.cas_calls == 0

    v_ok = world.make_verifier(pr3_verifier=pr3_ok)
    assert v_ok.verify_artifact(world.prov_loc, wheel_path=baseline_artifacts["wheel_path"], repo_root=REPO_ROOT)["verification_status"] == "VERIFIED"
    assert v_ok.verify_artifact(world.boundary_loc, wheel_path=baseline_artifacts["wheel_path"], repo_root=REPO_ROOT)["verification_status"] == "VERIFIED"
    assert v_ok.verify_artifact(world.mcp_loc, wheel_path=baseline_artifacts["wheel_path"], seccomp_profile=baseline_artifacts["seccomp_profile"])["verification_status"] == "VERIFIED"
    assert v_ok.verify_artifact(conv_loc, seccomp_profile=baseline_artifacts["seccomp_profile"], wheel_path=baseline_artifacts["wheel_path"], repo_root=REPO_ROOT)["verification_status"] == "VERIFIED"
    assert v_ok.admit_etapa7_bundle(sandbox_profile_locator=world.sandbox_loc, wheel_provenance_locator=world.prov_loc, wheel_boundary_report_locator=world.boundary_loc, mcp_rejection_report_locator=world.mcp_loc, seccomp_profile=baseline_artifacts["seccomp_profile"], wheel_path=baseline_artifacts["wheel_path"], repo_root=REPO_ROOT)["verification_status"] == "VERIFIED"


def _assert_five_d4_calls_fail_closed(
    verifier: gov1_convergence.Gov1AdmissionVerifier, world: Gov1D4World, baseline: Mapping[str, Any], conv_loc: dict[str, Any]
) -> None:
    calls: list[Callable[[], Any]] = [
        lambda: verifier.verify_artifact(world.prov_loc, wheel_path=baseline["wheel_path"], repo_root=REPO_ROOT),
        lambda: verifier.verify_artifact(world.boundary_loc, wheel_path=baseline["wheel_path"], repo_root=REPO_ROOT),
        lambda: verifier.verify_artifact(world.mcp_loc, wheel_path=baseline["wheel_path"], seccomp_profile=baseline["seccomp_profile"]),
        lambda: verifier.verify_artifact(conv_loc, seccomp_profile=baseline["seccomp_profile"], wheel_path=baseline["wheel_path"], repo_root=REPO_ROOT),
        lambda: verifier.admit_etapa7_bundle(sandbox_profile_locator=world.sandbox_loc, wheel_provenance_locator=world.prov_loc, wheel_boundary_report_locator=world.boundary_loc, mcp_rejection_report_locator=world.mcp_loc, seccomp_profile=baseline["seccomp_profile"], wheel_path=baseline["wheel_path"], repo_root=REPO_ROOT),
    ]
    for fn in calls:
        with pytest.raises(ValueError, match="isolated_probe_runner|os_isolated"):
            fn()


def test_installation_pins_fallback_and_gov1_installation_pins_from_repo(
    tmp_path: Path, baseline_artifacts: dict[str, Any], synthetic_gov1_keys: dict[str, tuple[Path, bytes, str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    _forbid_local_stage7_probes(monkeypatch)
    ident = decomposition_governance.verified_run_context_identity(REPO_ROOT)
    raw_anchor = json.loads((REPO_ROOT / "docs/governance/trust-anchor/cell_trust_anchor_config.json").read_text(encoding="utf-8"))
    with pytest.raises(ValueError, match="exactly one"):
        Gov1InstallationPins.from_repo_prerequisites(REPO_ROOT)
    with pytest.raises(ValueError):
        Gov1InstallationPins.from_repo_prerequisites(REPO_ROOT, runtime_config=raw_anchor)
    with pytest.raises(ValueError, match="installation_authority"):
        Gov1InstallationPins.from_repo_prerequisites(REPO_ROOT, configuration_digest="sha256:" + ("a" * 64))

    base_pins = InstallationPins("sha256:" + ("a" * 64), "auth", "cell", "head:1", "chk:1", "principal:ronaldo", "mbras")
    anchor_cfg = {"public_key_base64": decomposition_governance.ANCHOR_PUBLIC}
    for ep in (1, 2, 3, 4):
        r_ctx, pre_locs = _resolve_d4_pins(base_pins, config=anchor_cfg, head_1_reg={"epoch": ep}, repo_root=REPO_ROOT)
        assert canonicalize(r_ctx) == canonicalize(ident["run_context_locator"]) and len(pre_locs) == ep - 1
    with pytest.raises(ValueError, match="ANCHOR_PUBLIC|anchor"):
        _resolve_d4_pins(base_pins, config={"public_key_base64": base64.b64encode(b"x" * 32).decode("ascii")}, head_1_reg={"epoch": 4}, repo_root=REPO_ROOT)
    with pytest.raises(ValueError, match="epoch"):
        _resolve_d4_pins(base_pins, config=anchor_cfg, head_1_reg={"epoch": 5}, repo_root=REPO_ROOT)
    _assert_from_repo_prerequisites_d4_bootstrap(tmp_path, baseline_artifacts, synthetic_gov1_keys, raw_anchor, ident, monkeypatch)


def _assert_from_repo_prerequisites_d4_bootstrap(
    tmp_path: Path, baseline: dict[str, Any], keys: dict[str, tuple[Path, bytes, str]],
    raw_anchor: Mapping[str, Any], ident: Mapping[str, Any], monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = Gov1D4World(tmp_path / "pins_d4", keys, baseline)
    deployed_cfg = {
        "$schema": "smart_ads/cell_trust_anchor_config/v1", "trust_anchor_id": raw_anchor["trust_anchor_id"],
        "public_key_base64": raw_anchor["public_key_base64"], "public_key_sha256": raw_anchor["public_key_sha256"],
        "validity": raw_anchor["validity"], "allowed_registry_artifact_types": [REGISTRY, INVENTORY],
        "inventory_bootstrap_profile": world.profiles[INVENTORY], "anti_rollback_checkpoint_profile": world.profiles[CHECKPOINT],
        "cell_id": "synthetic-gov1-cell", "head_register": "head:gov1-synthetic",
        "checkpoint_register": "checkpoint:gov1-synthetic", "installation_authority": "synthetic-gov1-installation",
    }
    for bad_cfg, bad_match in (
        ({**deployed_cfg, "trust_anchor_id": "   "}, "trust_anchor_id"),
        ({**deployed_cfg, "trust_anchor_id": "anchor:other"}, "trust_anchor_id|anchor"),
        ({**deployed_cfg, "validity": {"from": "2028-01-01T00:00:00Z", "until": "2027-01-01T00:00:00Z"}}, "validity"),
        ({**deployed_cfg, "validity": {"from": "2026-09-04T00:00:00Z", "until": "2027-09-02T00:00:00Z"}}, "validity"),
        ({**deployed_cfg, "validity": {"from": "2026-09-03T00:00:00Z", "until": "2026-09-07T00:00:00Z"}}, "validity"),
        ({**deployed_cfg, "inventory_bootstrap_profile": {**world.profiles[INVENTORY], "domain_prefix": "WRONG\n"}}, "protected profile mismatch"),
        ({**deployed_cfg, "anti_rollback_checkpoint_profile": {**world.profiles[CHECKPOINT], "domain_prefix": "WRONG\n"}}, "protected profile mismatch"),
    ):
        with pytest.raises(ValueError, match=bad_match):
            Gov1InstallationPins.from_repo_prerequisites(REPO_ROOT, runtime_config=bad_cfg)
    pins_cfg = Gov1InstallationPins.from_repo_prerequisites(REPO_ROOT, runtime_config=deployed_cfg)
    pins_dig = Gov1InstallationPins.from_repo_prerequisites(
        REPO_ROOT, configuration_digest=digest(canonicalize(deployed_cfg)), installation_authority="synthetic-gov1-installation",
        cell_id="synthetic-gov1-cell", head_register="head:gov1-synthetic", checkpoint_register="checkpoint:gov1-synthetic",
    )
    assert pins_cfg == pins_dig and canonicalize(pins_cfg.pinned_run_context_locator) == canonicalize(ident["run_context_locator"])
    rt_real = MemoryProtectedRuntime(deployed_cfg, world.head_loc, world.checkpoint_loc)
    v_real = gov1_convergence.Gov1AdmissionVerifier(rt_real, pins_cfg, Store(REPO_ROOT / "docs/governance/cell-objects"), world.adr)
    assert canonicalize(v_real._configuration(rt_real.authenticated_clock())) == canonicalize(deployed_cfg)
    narrow_cfg = {**deployed_cfg, "validity": {"from": "2026-09-03T00:00:00Z", "until": "2027-09-02T00:00:00Z"}}
    pins_narrow = Gov1InstallationPins.from_repo_prerequisites(REPO_ROOT, runtime_config=narrow_cfg)
    rt_narrow = MemoryProtectedRuntime(narrow_cfg, world.head_loc, world.checkpoint_loc)
    assert canonicalize(gov1_convergence.Gov1AdmissionVerifier(rt_narrow, pins_narrow, Store(REPO_ROOT / "docs/governance/cell-objects"), world.adr)._configuration(rt_narrow.authenticated_clock())) == canonicalize(narrow_cfg)
    _assert_e2e_admission_via_repo_pins(tmp_path, world, keys, baseline, monkeypatch)


def _assert_e2e_admission_via_repo_pins(
    tmp_path: Path, world: Gov1D4World, keys: dict[str, tuple[Path, bytes, str]], baseline: Mapping[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    _, conv_loc = _build_signed_conv_in_world(world, keys, baseline)
    syn_root = tmp_path / "syn_repo_root"
    orig_vrc = decomposition_governance.verified_run_context_identity
    monkeypatch.setattr(decomposition_governance, "verified_run_context_identity", lambda r=REPO_ROOT: {"run_context_locator": RUN_CONTEXT_LOCATOR, "gate2_registry_locator": world.pre_head_reg_locs[0], "run_registry_locator": world.pre_head_reg_locs[1], "prerequisite_epoch3_registry_locator": world.pre_head_reg_locs[2]} if Path(r) == syn_root else orig_vrc(r))
    pins_e2e = Gov1InstallationPins.from_repo_prerequisites(syn_root, configuration_digest=digest(world.runtime.config), installation_authority="synthetic-gov1-installation", cell_id="synthetic-gov1-cell", head_register="head:gov1-synthetic", checkpoint_register="checkpoint:gov1-synthetic", owner_tenant="synthetic-tenant")
    v_e2e = gov1_convergence.Gov1AdmissionVerifier(world.runtime, pins_e2e, world.store, world.adr, inventory_locator=world.inventory_loc, pr3_verifier=world.make_pr3_verifier(), isolated_probe_runner=world.probe_runner, corpus_path=world.corpus_path, legacy_blobs_dir=world.legacy_blobs_dir)
    assert v_e2e.verify_artifact(conv_loc, seccomp_profile=baseline["seccomp_profile"], wheel_path=baseline["wheel_path"], repo_root=REPO_ROOT)["verification_status"] == "VERIFIED"
    assert world.runtime.cas_calls == 1


def test_d4_lineage_permits_unused_action_withdrawal_and_rejects_gaps_and_resurrection(
    tmp_path: Path, baseline_artifacts: dict[str, Any], synthetic_gov1_keys: dict[str, tuple[Path, bytes, str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    _forbid_local_stage7_probes(monkeypatch)
    w_retire = Gov1D4World(
        tmp_path / "retire_ok", synthetic_gov1_keys, baseline_artifacts,
        registry_mutation=lambda reg: reg["entries"][1]["allowed_actions"].append({"schema": "smart_ads/tolerance_profile/v1", "action": "unused_historical_action"}),
    )
    _, conv_loc = _build_signed_conv_in_world(w_retire, synthetic_gov1_keys, baseline_artifacts)
    w_retire.advance_current_registry(
        lambda reg: reg["entries"][1].update(allowed_actions=[{"schema": gov1_sandbox.SANDBOX_PROFILE_SCHEMA, "action": "sealed_sandbox_profile_issue"}])
    )
    res = w_retire.make_verifier(pr3_verifier=w_retire.make_pr3_verifier()).verify_artifact(
        conv_loc, seccomp_profile=baseline_artifacts["seccomp_profile"],
        wheel_path=baseline_artifacts["wheel_path"], repo_root=REPO_ROOT,
    )
    assert res["verification_status"] == "VERIFIED" and res["authority_epoch"] == 2

    gap_pins = Gov1InstallationPins(
        configuration_digest=w_retire.pins.configuration_digest, installation_authority=w_retire.pins.installation_authority,
        cell_id=w_retire.pins.cell_id, head_register=w_retire.pins.head_register, checkpoint_register=w_retire.pins.checkpoint_register,
        owner_principal=w_retire.pins.owner_principal, owner_tenant=w_retire.pins.owner_tenant,
        pinned_run_context_locator=RUN_CONTEXT_LOCATOR, pinned_pre_head_registry_locators=w_retire.pre_head_reg_locs[:2],
    )
    v_gap = gov1_convergence.Gov1AdmissionVerifier(
        w_retire.runtime, gap_pins, w_retire.store, w_retire.adr,
        inventory_locator=w_retire.inventory_loc, isolated_probe_runner=w_retire.probe_runner,
    )
    with pytest.raises(ValueError, match="epoch|pre-head"):
        v_gap.verify_artifact(w_retire.sandbox_loc, seccomp_profile=baseline_artifacts["seccomp_profile"])

    _assert_resurrection_and_step_helper_fail_closed(tmp_path, synthetic_gov1_keys, baseline_artifacts)


def _assert_resurrection_and_step_helper_fail_closed(
    tmp_path: Path, keys: dict[str, tuple[Path, bytes, str]], baseline: dict[str, Any]
) -> None:
    w_huge = Gov1D4World(tmp_path / "huge_epoch_gap", keys, baseline)
    w_huge.advance_current_registry(lambda reg: reg.update(epoch=10**9))
    tracemalloc.start()
    try:
        with pytest.raises(ValueError, match="non-contiguous D4 registry epoch"):
            w_huge.make_verifier().verify_artifact(w_huge.sandbox_loc, seccomp_profile=baseline["seccomp_profile"])
        _, peak_bytes = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak_bytes < 1_048_576 and w_huge.runtime.cas_calls == 0

    w_res = Gov1D4World(
        tmp_path / "resurrect", keys, baseline,
        registry_mutation=lambda reg: reg["entries"][8].update(lifecycle_state="revoked"),
    )
    w_res.advance_current_registry(lambda reg: reg["entries"][8].update(lifecycle_state="active"))
    with pytest.raises(ValueError, match="lifecycle|monotonic|revoked"):
        w_res.make_verifier().verify_artifact(w_res.sandbox_loc, seccomp_profile=baseline["seccomp_profile"])

    reg4 = w_res.store.get(w_res.pre_head_reg_locs[2])
    reg5_exp = {**copy.deepcopy(reg4), "epoch": 4, "integrity": {"key_id": keys["trust_anchor"][2], "key_registry_snapshot_locator": None}}
    reg5_exp["entries"][8]["lifecycle_state"] = "expired"
    reg5_exp_s = p1.sign_envelope(reg5_exp, w_res.profiles[REGISTRY]["domain_prefix"], keys["trust_anchor"][0])
    reg6_rev = {**copy.deepcopy(reg5_exp_s), "epoch": 5, "integrity": {"key_id": keys["trust_anchor"][2], "key_registry_snapshot_locator": None}}
    reg6_rev["entries"][8]["lifecycle_state"] = "revoked"
    reg6_rev_s = p1.sign_envelope(reg6_rev, w_res.profiles[REGISTRY]["domain_prefix"], keys["trust_anchor"][0])
    with pytest.raises(ValueError, match="lifecycle|monotonic"):
        _verify_d4_registry_lineage_step(reg5_exp_s, reg6_rev_s, w_res.config)


def test_d4_registry_membership_run_context_and_leaf_authentication(
    tmp_path: Path, baseline_artifacts: dict[str, Any], synthetic_gov1_keys: dict[str, tuple[Path, bytes, str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    _forbid_local_stage7_probes(monkeypatch)
    world = Gov1D4World(tmp_path, synthetic_gov1_keys, baseline_artifacts)
    fork_reg = {**copy.deepcopy(world.store.get(world.pre_head_reg_locs[1])), "issued_at_utc": "2026-09-05T01:00:00Z", "integrity": {"key_id": synthetic_gov1_keys["trust_anchor"][2], "key_registry_snapshot_locator": None}}
    fork_reg_s = p1.sign_envelope(fork_reg, world.profiles[REGISTRY]["domain_prefix"], synthetic_gov1_keys["trust_anchor"][0])
    fork_reg_loc = world.store.put(fork_reg_s)
    with pytest.raises(ValueError, match="chain_registries_by_epoch"):
        _verify_d4_registry_membership(fork_reg_s, {2: canonicalize(world.store.get(world.pre_head_reg_locs[1]))}, label="fork")
    fork_inv = {**copy.deepcopy(world.objects["inventory"]), "integrity": {"key_id": synthetic_gov1_keys["trust_anchor"][2], "key_registry_snapshot_locator": fork_reg_loc}}
    fork_inv_loc = world.store.put(p1.sign_envelope(fork_inv, world.profiles[INVENTORY]["domain_prefix"], synthetic_gov1_keys["trust_anchor"][0]))
    with pytest.raises(ValueError, match="chain_registries_by_epoch"):
        world.make_verifier().verify_artifact(world.sandbox_loc, inventory_locator=fork_inv_loc, seccomp_profile=baseline_artifacts["seccomp_profile"])
    alt_pins = Gov1InstallationPins(world.pins.configuration_digest, world.pins.installation_authority, world.pins.cell_id, world.pins.head_register, world.pins.checkpoint_register, world.pins.owner_principal, world.pins.owner_tenant, ALT_RUN_CONTEXT_LOCATOR, world.pre_head_reg_locs)
    v_alt_ctx = gov1_convergence.Gov1AdmissionVerifier(world.runtime, alt_pins, world.store, world.adr, inventory_locator=world.inventory_loc, isolated_probe_runner=world.probe_runner)
    with pytest.raises(ValueError, match="migration_run_context_locator"):
        v_alt_ctx.verify_artifact(world.sandbox_loc, seccomp_profile=baseline_artifacts["seccomp_profile"])
    _assert_leaf_fork_and_role_rejections_in_d4(tmp_path, synthetic_gov1_keys, baseline_artifacts, fork_reg_loc)


def _resign_on_fork(world: Gov1D4World, env: Mapping[str, Any], role: str, fk_loc: dict[str, Any]) -> dict[str, Any]:
    u = {k: copy.deepcopy(v) for k, v in env.items() if k != "integrity"}
    u["integrity"] = {"key_id": world.keys[role][2], "key_registry_snapshot_locator": fk_loc}
    return world.store.put(p1.sign_envelope(u, world.profiles[u["$schema"]]["domain_prefix"], world.keys[role][0]))


def _assert_leaf_fork_and_role_rejections_in_d4(
    tmp_path: Path, keys: dict[str, tuple[Path, bytes, str]], baseline: dict[str, Any], fork_reg_loc: dict[str, Any]
) -> None:
    for role_idx in (8, 9, 10, 11):
        w_leaf = Gov1D4World(tmp_path / f"leaf_rev_{role_idx}", keys, baseline)
        _, conv_loc = _build_signed_conv_in_world(w_leaf, keys, baseline)
        w_leaf.advance_current_registry(lambda reg, i=role_idx: reg["entries"][i].update(lifecycle_state="revoked"))
        with pytest.raises(ValueError, match="authority key currently revoked or expired"):
            w_leaf.make_verifier(pr3_verifier=w_leaf.make_pr3_verifier()).verify_artifact(
                conv_loc, seccomp_profile=baseline["seccomp_profile"], wheel_path=baseline["wheel_path"], repo_root=REPO_ROOT
            )
        assert w_leaf.runtime.cas_calls == 0

    w_fk = Gov1D4World(tmp_path / "all_forks", keys, baseline)
    fk_reg = {**copy.deepcopy(w_fk.store.get(w_fk.pre_head_reg_locs[1])), "issued_at_utc": "2026-09-05T01:00:00Z", "integrity": {"key_id": keys["trust_anchor"][2], "key_registry_snapshot_locator": None}}
    fk_loc = w_fk.store.put(p1.sign_envelope(fk_reg, w_fk.profiles[REGISTRY]["domain_prefix"], keys["trust_anchor"][0]))
    _ = fork_reg_loc
    conv_s, _ = _build_signed_conv_in_world(w_fk, keys, baseline)
    v_fk = w_fk.make_verifier(pr3_verifier=w_fk.make_pr3_verifier())
    direct_forks = [
        (_resign_on_fork(w_fk, w_fk.sandbox_env, "security_owner", fk_loc), {"seccomp_profile": baseline["seccomp_profile"]}),
        (_resign_on_fork(w_fk, w_fk.prov_env, "build_provenance_verifier", fk_loc), {"wheel_path": baseline["wheel_path"], "repo_root": REPO_ROOT}),
        (_resign_on_fork(w_fk, w_fk.boundary_env, "build_boundary_verifier", fk_loc), {"wheel_path": baseline["wheel_path"], "repo_root": REPO_ROOT}),
        (_resign_on_fork(w_fk, w_fk.mcp_env, "security_verifier", fk_loc), {"wheel_path": baseline["wheel_path"], "seccomp_profile": baseline["seccomp_profile"]}),
        (_resign_on_fork(w_fk, conv_s, "gov1_convergence_verifier", fk_loc), {"seccomp_profile": baseline["seccomp_profile"], "wheel_path": baseline["wheel_path"], "repo_root": REPO_ROOT}),
    ]
    for bad_loc, call_kw in direct_forks:
        with pytest.raises(ValueError, match="chain_registries_by_epoch"):
            v_fk.verify_artifact(bad_loc, **call_kw)
    _assert_indirect_7a_and_four_leaf_forks_rejected(w_fk, v_fk, keys, baseline, fk_loc)
    assert w_fk.runtime.cas_calls == 0


def _assert_indirect_7a_and_four_leaf_forks_rejected(
    w_fk: Gov1D4World, v_fk: gov1_convergence.Gov1AdmissionVerifier,
    keys: dict[str, tuple[Path, bytes, str]], baseline: Mapping[str, Any], fk_loc: dict[str, Any],
) -> None:
    fake_pr3 = _StructuralFakePr3Verifier(neg_ts=EXECUTED_AT_UTC, cert_ts=EXECUTED_AT_UTC)
    fk_sbx_loc = _resign_on_fork(w_fk, w_fk.sandbox_env, "security_owner", fk_loc)
    mcp_for_sbx = _resign_on_fork(w_fk, {**copy.deepcopy(w_fk.mcp_env), "sealed_sandbox_profile_locator": fk_sbx_loc}, "security_verifier", w_fk.registry_loc)
    neg_for_sbx = _resign_on_fork(w_fk, {**copy.deepcopy(w_fk.neg_env), "sealed_sandbox_profile_locator": fk_sbx_loc}, "7a_verifier", w_fk.registry_loc)
    cert_for_sbx = _resign_on_fork(w_fk, {**copy.deepcopy(w_fk.cert7a_env), "sealed_sandbox_profile_locator": fk_sbx_loc, "negative_security_test_report_locator": neg_for_sbx}, "independent_7a_verifier", w_fk.registry_loc)
    fk_prov_loc = _resign_on_fork(w_fk, w_fk.prov_env, "build_provenance_verifier", fk_loc)
    bound_for_prov = _resign_on_fork(w_fk, {**copy.deepcopy(w_fk.boundary_env), "wheel_build_provenance_locator": fk_prov_loc}, "build_boundary_verifier", w_fk.registry_loc)
    neg_for_prov = _resign_on_fork(w_fk, {**copy.deepcopy(w_fk.neg_env), "wheel_build_provenance_locator": fk_prov_loc}, "7a_verifier", w_fk.registry_loc)
    cert_for_prov = _resign_on_fork(w_fk, {**copy.deepcopy(w_fk.cert7a_env), "wheel_build_provenance_locator": fk_prov_loc, "wheel_boundary_report_locator": bound_for_prov, "negative_security_test_report_locator": neg_for_prov}, "independent_7a_verifier", w_fk.registry_loc)
    fk_bound_loc = _resign_on_fork(w_fk, w_fk.boundary_env, "build_boundary_verifier", fk_loc)
    cert_for_bound = _resign_on_fork(w_fk, {**copy.deepcopy(w_fk.cert7a_env), "wheel_boundary_report_locator": fk_bound_loc}, "independent_7a_verifier", w_fk.registry_loc)
    fk_mcp_loc = _resign_on_fork(w_fk, w_fk.mcp_env, "security_verifier", fk_loc)
    fk_neg_loc = _resign_on_fork(w_fk, w_fk.neg_env, "7a_verifier", fk_loc)
    cert_for_neg = _resign_on_fork(w_fk, {**copy.deepcopy(w_fk.cert7a_env), "negative_security_test_report_locator": fk_neg_loc}, "independent_7a_verifier", w_fk.registry_loc)
    fk_cert_loc = _resign_on_fork(w_fk, w_fk.cert7a_env, "independent_7a_verifier", fk_loc)
    conv_overrides: list[dict[str, Any]] = [
        {"sealed_sandbox_profile_locator": fk_sbx_loc, "mcp_rejection_matrix_report_locator": mcp_for_sbx, "negative_security_test_report_locator": neg_for_sbx, "certification_7a_record_locator": cert_for_sbx},
        {"wheel_boundary_report_locator": bound_for_prov, "negative_security_test_report_locator": neg_for_prov, "certification_7a_record_locator": cert_for_prov},
        {"wheel_boundary_report_locator": fk_bound_loc, "certification_7a_record_locator": cert_for_bound},
        {"mcp_rejection_matrix_report_locator": fk_mcp_loc},
        {"negative_security_test_report_locator": fk_neg_loc, "certification_7a_record_locator": cert_for_neg},
        {"certification_7a_record_locator": fk_cert_loc},
        *_build_four_leaf_fork_conv_overrides(w_fk, fk_loc),
    ]
    for ov in conv_overrides:
        conv_u = gov1_convergence.build_gov1_convergence_record_envelope(**{**_make_conv_base_kwargs(w_fk, keys, baseline), **ov}, store=w_fk.store, pr3_verifier=fake_pr3)
        conv_l = w_fk.store.put(p1.sign_envelope(conv_u, w_fk.profiles[gov1_convergence.GOV1_CONVERGENCE_SCHEMA]["domain_prefix"], keys["gov1_convergence_verifier"][0]))
        with pytest.raises(ValueError, match="chain_registries_by_epoch"):
            v_fk.verify_artifact(conv_l, seccomp_profile=baseline["seccomp_profile"], wheel_path=baseline["wheel_path"], repo_root=REPO_ROOT)


def _build_four_leaf_fork_conv_overrides(w_fk: Gov1D4World, fk_loc: dict[str, Any]) -> list[dict[str, Any]]:
    drv_fk = _resign_on_fork(w_fk, w_fk.store.get(w_fk.cert7a_env["capability"]["driver_contract_locator"]), "provider_port_policy_owner", fk_loc)
    snap_fk = _resign_on_fork(w_fk, w_fk.store.get(w_fk.cert7a_env["capability"]["registry_snapshot_locator"]), "registry_publisher", fk_loc)
    inv_fk = _resign_on_fork(w_fk, w_fk.store.get(w_fk.cert7a_env["fixture_evidence"]["cases"][0]["expected_resource_inventory_locator"]), "private_registry_publisher", fk_loc)
    git_fk = _resign_on_fork(w_fk, w_fk.store.get(w_fk.cert7a_env["fixture_evidence"]["corpus_git_locator"]), "git_provenance_verifier", fk_loc)
    muts: list[Callable[[dict[str, Any]], None]] = [
        lambda c: c["capability"].update(driver_contract_locator=drv_fk),
        lambda c: c["capability"].update(registry_snapshot_locator=snap_fk),
        lambda c: c["fixture_evidence"]["cases"][0].update(expected_resource_inventory_locator=inv_fk),
        lambda c: c["fixture_evidence"].update(corpus_git_locator=git_fk),
    ]
    out: list[dict[str, Any]] = []
    for mut_fn in muts:
        cert_m = copy.deepcopy(w_fk.cert7a_env)
        mut_fn(cert_m)
        out.append({"certification_7a_record_locator": _resign_on_fork(w_fk, cert_m, "independent_7a_verifier", w_fk.registry_loc)})
    return out


@pytest.mark.parametrize("legacy_mode", ["blobs_dir", "git_repo"])
@pytest.mark.parametrize("mutation_kind", ["store_leaf", "wheel_file", "corpus_file", "git_repo_blob", "legacy_source"])
def test_post_cas_mutations_fail_closed_before_observe_head_and_clock(
    tmp_path: Path, baseline_artifacts: dict[str, Any], synthetic_gov1_keys: dict[str, tuple[Path, bytes, str]],
    monkeypatch: pytest.MonkeyPatch, legacy_mode: str, mutation_kind: str,
) -> None:
    _forbid_local_stage7_probes(monkeypatch)
    tag = f"{legacy_mode}_{mutation_kind}"
    world = Gov1D4World(tmp_path / tag, synthetic_gov1_keys, baseline_artifacts)
    _, conv_loc = _build_signed_conv_in_world(world, synthetic_gov1_keys, baseline_artifacts)
    whl_copy, corpus_copy = tmp_path / f"{tag}.whl", tmp_path / f"{tag}_corpus.json"
    whl_copy.write_bytes(baseline_artifacts["wheel_bytes"])
    corpus_copy.write_bytes(baseline_artifacts["corpus_bytes"])
    blobs_dir = _stage_d26_blobs_dir(tmp_path / f"{tag}_blobs", baseline_artifacts["d26_blobs"])
    fake_leg_repo = tmp_path / f"{tag}_leg_git"
    fake_leg_repo.mkdir()
    seen_d26_git: list[tuple[str, ...]] = []
    if legacy_mode == "git_repo":
        _install_fake_d26_git_runner(monkeypatch, fake_leg_repo, blobs_dir, seen_d26_git)

    _attach_post_cas_mutation_hook(monkeypatch, world, mutation_kind, whl_copy, corpus_copy, blobs_dir, baseline_artifacts)
    v = gov1_convergence.Gov1AdmissionVerifier(
        world.runtime, world.pins, world.store, world.adr,
        inventory_locator=world.inventory_loc, pr3_verifier=world.make_pr3_verifier(),
        isolated_probe_runner=world.probe_runner, corpus_path=corpus_copy,
        legacy_repo=fake_leg_repo if legacy_mode == "git_repo" else None,
        legacy_blobs_dir=None if legacy_mode == "git_repo" else blobs_dir,
    )
    expected_err = {
        "store_leaf": "locator must address canonical envelope bytes|store object mutated during admission",
        "wheel_file": "wheel_path bytes mutated during admission",
        "corpus_file": "corpus_path bytes mutated during admission",
        "git_repo_blob": "smart_ads Git blobs mutated during admission",
        "legacy_source": "Git blob OID or SHA-256 mismatch|pinned d26 legacy blobs mutated during admission",
    }
    with pytest.raises(ValueError, match=expected_err[mutation_kind]):
        v.verify_artifact(conv_loc, seccomp_profile=baseline_artifacts["seccomp_profile"], wheel_path=whl_copy, repo_root=REPO_ROOT)
    assert world.runtime.cas_calls == 1 and world.runtime.observe_calls == 0
    if legacy_mode == "git_repo":
        assert len(seen_d26_git) == (12 if mutation_kind == "legacy_source" else 6)


def _attach_post_cas_mutation_hook(
    monkeypatch: pytest.MonkeyPatch, world: Gov1D4World, mutation_kind: str,
    whl_copy: Path, corpus_copy: Path, blobs_dir: Path, baseline: Mapping[str, Any],
) -> None:
    if mutation_kind == "store_leaf":
        corpus_git_loc = world.cert7a_env["fixture_evidence"]["corpus_git_locator"]
        orig_get = world.store.get
        monkeypatch.setattr(world.store, "get", lambda loc, expected_type=None: ({**orig_get(loc, expected_type=expected_type), "resolved_at_utc": "2026-09-07T10:00:05Z"} if world.runtime.cas_calls and canonicalize(loc) == canonicalize(corpus_git_loc) else orig_get(loc, expected_type=expected_type)))
    elif mutation_kind == "wheel_file":
        world.runtime.post_cas_hook = lambda: whl_copy.write_bytes(baseline["wheel_bytes"] + b"m")
    elif mutation_kind == "corpus_file":
        world.runtime.post_cas_hook = lambda: corpus_copy.write_bytes(baseline["corpus_bytes"] + b"\n")
    elif mutation_kind == "git_repo_blob":
        orig_git = gov1_7a_certification.resolve_7a_smart_ads_git_blobs
        monkeypatch.setattr(gov1_7a_certification, "resolve_7a_smart_ads_git_blobs", lambda r, sha: ({**dict(orig_git(r, sha)), CORPUS_GIT_PATH[1]: baseline["corpus_bytes"] + b"\n"} if world.runtime.cas_calls else orig_git(r, sha)))
    else:
        role0, rel0, _, _ = PINNED_PIPEBOARD_D26_SPECS[0]
        target = blobs_dir / f"{role0}__{Path(rel0).name}"
        world.runtime.post_cas_hook = lambda: target.write_bytes(baseline["d26_blobs"][rel0] + b"\n")


def _write_cli_json(path: Path, data: Mapping[str, Any]) -> Path:
    path.write_bytes(canonicalize(dict(data)))
    return path


def _prepare_cli_fixture_files(tmp_path: Path, world: Gov1D4World, baseline: Mapping[str, Any]) -> dict[str, Any]:
    d = tmp_path / "cli_files"
    d.mkdir(parents=True, exist_ok=True)
    snap: gov1_wheel.GitBuildSnapshot = baseline["snapshot"]
    neg_p = {
        "migration_run_context_locator": RUN_CONTEXT_LOCATOR, "build_run_id": BUILD_RUN_ID, "executed_at_utc": EXECUTED_AT_UTC,
        "source_commit_sha": snap.commit_sha, "build_backend_digest": snap.build_backend_digest,
        "schema_bundle_digest": baseline["inspection"]["schema_bundle_digest"], "wheel_digest": baseline["inspection"]["wheel_digest"],
        "oci_image_digest": "sha256:" + ("1" * 64), "runner_binary_digest": "sha256:" + ("2" * 64),
        "declared_resource_limits": baseline["sandbox_cand"]["payload"]["resource_limits"], "cases": baseline["neg_cases"],
    }
    conv_p = {
        "migration_run_context_locator": RUN_CONTEXT_LOCATOR, "build_run_id": BUILD_RUN_ID, "converged_at_utc": CONVERGED_AT_UTC,
        "source_commit_sha": snap.commit_sha, "wheel_digest": baseline["inspection"]["wheel_digest"],
        "build_backend_digest": snap.build_backend_digest, "schema_bundle_digest": baseline["inspection"]["schema_bundle_digest"],
    }
    raw_items = {
        "seccomp": baseline["seccomp_profile"], "sbx_c": baseline["sandbox_cand"], "prov_c": baseline["prov_cand"],
        "bound_c": baseline["boundary_cand"], "mcp_c": baseline["mcp_cand"], "sbx_e": world.sandbox_env, "prov_e": world.prov_env,
        "reg_loc": world.registry_loc, "sbx_loc": world.sandbox_loc, "prov_loc": world.prov_loc,
        "bound_loc": world.boundary_loc, "mcp_loc": world.mcp_loc, "neg_params": neg_p, "cert_params": world.cert_common, "conv_params": conv_p,
    }
    return {"dir": d, **{k: _write_cli_json(d / f"{k}.json", v) for k, v in raw_items.items()}}


def test_six_new_cli_subcommands_candidate_and_envelope_roundtrip(
    tmp_path: Path, baseline_artifacts: dict[str, Any], synthetic_gov1_keys: dict[str, tuple[Path, bytes, str]], capsys: pytest.CaptureFixture[str]
) -> None:
    world = Gov1D4World(tmp_path / "cli_world", synthetic_gov1_keys, baseline_artifacts)
    f = _prepare_cli_fixture_files(tmp_path, world, baseline_artifacts)
    _run_cli_candidate_flow(f, world, baseline_artifacts, capsys)
    _run_cli_envelope_flow(f, world, synthetic_gov1_keys, baseline_artifacts, capsys)


def _run_cli_candidate_flow(
    f: Mapping[str, Any], world: Gov1D4World, baseline: Mapping[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    d: Path = f["dir"]
    neg_c_out, cert_c_out, conv_c_out = d / "neg_out_c.json", d / "cert_out_c.json", d / "conv_out_c.json"
    assert cli.main(["build-negative-security-report", "--params", str(f["neg_params"]), "--wheel", str(baseline["wheel_path"]), "--sandbox-profile", str(f["sbx_c"]), "--provenance", str(f["prov_c"]), "--out", str(neg_c_out)]) == 0
    assert cli.main(["verify-negative-security-report", "--in", str(neg_c_out), "--wheel", str(baseline["wheel_path"]), "--sandbox-profile", str(f["sbx_c"]), "--seccomp-profile", str(f["seccomp"]), "--provenance", str(f["prov_c"])]) == 0
    assert cli.main(["build-certification-7a-record", "--params", str(f["cert_params"]), "--store-root", str(world.store.root), "--wheel", str(baseline["wheel_path"]), "--corpus", str(world.corpus_path), "--repo", str(REPO_ROOT), "--legacy-blobs-dir", str(world.legacy_blobs_dir), "--sandbox-profile", str(f["sbx_c"]), "--provenance", str(f["prov_c"]), "--boundary-report", str(f["bound_c"]), "--negative-report", str(neg_c_out), "--out", str(cert_c_out)]) == 0
    assert cli.main(["verify-certification-7a-record", "--in", str(cert_c_out), "--store-root", str(world.store.root), "--wheel", str(baseline["wheel_path"]), "--corpus", str(world.corpus_path), "--repo", str(REPO_ROOT), "--legacy-blobs-dir", str(world.legacy_blobs_dir), "--sandbox-profile", str(f["sbx_c"]), "--provenance", str(f["prov_c"]), "--boundary-report", str(f["bound_c"]), "--negative-report", str(neg_c_out)]) == 0
    assert cli.main(["build-gov1-convergence-record", "--params", str(f["conv_params"]), "--store-root", str(world.store.root), "--wheel", str(baseline["wheel_path"]), "--corpus", str(world.corpus_path), "--repo", str(REPO_ROOT), "--seccomp-profile", str(f["seccomp"]), "--legacy-blobs-dir", str(world.legacy_blobs_dir), "--sandbox-profile", str(f["sbx_c"]), "--provenance", str(f["prov_c"]), "--boundary-report", str(f["bound_c"]), "--mcp-rejection-report", str(f["mcp_c"]), "--negative-report", str(neg_c_out), "--certification-7a-record", str(cert_c_out), "--out", str(conv_c_out)]) == 0
    capsys.readouterr()
    assert cli.main(["verify-gov1-convergence-record", "--in", str(conv_c_out), "--store-root", str(world.store.root), "--wheel", str(baseline["wheel_path"]), "--corpus", str(world.corpus_path), "--repo", str(REPO_ROOT), "--seccomp-profile", str(f["seccomp"]), "--legacy-blobs-dir", str(world.legacy_blobs_dir), "--sandbox-profile", str(f["sbx_c"]), "--provenance", str(f["prov_c"]), "--boundary-report", str(f["bound_c"]), "--mcp-rejection-report", str(f["mcp_c"]), "--negative-report", str(neg_c_out), "--certification-7a-record", str(cert_c_out)]) == 0
    out_doc = json.loads(capsys.readouterr().out)
    assert out_doc["status"] == "PASS" and out_doc["mode"] == "candidate" and out_doc["signable"] is False


def _run_cli_envelope_flow(
    f: Mapping[str, Any], world: Gov1D4World, keys: dict[str, tuple[Path, bytes, str]], baseline: Mapping[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    d: Path = f["dir"]
    neg_u_p, cert_u_p, conv_u_p = d / "neg_u.json", d / "cert_u.json", d / "conv_u.json"
    assert cli.main(["build-negative-security-report", "--mode", "envelope", "--params", str(f["neg_params"]), "--wheel", str(baseline["wheel_path"]), "--sandbox-profile-locator", str(f["sbx_loc"]), "--provenance-locator", str(f["prov_loc"]), "--signer-key-id", keys["7a_verifier"][2], "--registry-locator", str(f["reg_loc"]), "--out", str(neg_u_p)]) == 0
    neg_s = p1.sign_envelope(json.loads(neg_u_p.read_text(encoding="utf-8")), world.profiles[gov1_convergence.NEGATIVE_SECURITY_SCHEMA]["domain_prefix"], keys["7a_verifier"][0])
    neg_s_p, neg_loc_p = _write_cli_json(d / "neg_s.json", neg_s), _write_cli_json(d / "neg_loc.json", world.store.put(neg_s))
    assert cli.main(["verify-negative-security-report", "--in", str(neg_s_p), "--wheel", str(baseline["wheel_path"]), "--sandbox-profile", str(f["sbx_e"]), "--seccomp-profile", str(f["seccomp"]), "--provenance", str(f["prov_e"]), "--pubkey-raw-base64", base64.b64encode(keys["7a_verifier"][1]).decode("ascii")]) == 0
    assert cli.main(["build-certification-7a-record", "--mode", "envelope", "--params", str(f["cert_params"]), "--store-root", str(world.store.root), "--wheel", str(baseline["wheel_path"]), "--corpus", str(world.corpus_path), "--repo", str(REPO_ROOT), "--legacy-blobs-dir", str(world.legacy_blobs_dir), "--sandbox-profile-locator", str(f["sbx_loc"]), "--provenance-locator", str(f["prov_loc"]), "--boundary-report-locator", str(f["bound_loc"]), "--negative-report-locator", str(neg_loc_p), "--signer-key-id", keys["independent_7a_verifier"][2], "--registry-locator", str(f["reg_loc"]), "--out", str(cert_u_p)]) == 0
    cert_s = p1.sign_envelope(json.loads(cert_u_p.read_text(encoding="utf-8")), world.profiles[gov1_convergence.CERTIFICATION_7A_SCHEMA]["domain_prefix"], keys["independent_7a_verifier"][0])
    cert_s_p, cert_loc_p = _write_cli_json(d / "cert_s.json", cert_s), _write_cli_json(d / "cert_loc.json", world.store.put(cert_s))
    assert cli.main(["verify-certification-7a-record", "--in", str(cert_s_p), "--store-root", str(world.store.root), "--wheel", str(baseline["wheel_path"]), "--corpus", str(world.corpus_path), "--repo", str(REPO_ROOT), "--legacy-blobs-dir", str(world.legacy_blobs_dir), "--pubkey-raw-base64", base64.b64encode(keys["independent_7a_verifier"][1]).decode("ascii")]) == 0
    assert cli.main(["build-gov1-convergence-record", "--mode", "envelope", "--params", str(f["conv_params"]), "--store-root", str(world.store.root), "--wheel", str(baseline["wheel_path"]), "--corpus", str(world.corpus_path), "--repo", str(REPO_ROOT), "--seccomp-profile", str(f["seccomp"]), "--legacy-blobs-dir", str(world.legacy_blobs_dir), "--sandbox-profile-locator", str(f["sbx_loc"]), "--boundary-report-locator", str(f["bound_loc"]), "--mcp-rejection-report-locator", str(f["mcp_loc"]), "--negative-report-locator", str(neg_loc_p), "--certification-7a-record-locator", str(cert_loc_p), "--signer-key-id", keys["gov1_convergence_verifier"][2], "--registry-locator", str(f["reg_loc"]), "--out", str(conv_u_p)]) == 0
    conv_s_p = _write_cli_json(d / "conv_s.json", p1.sign_envelope(json.loads(conv_u_p.read_text(encoding="utf-8")), world.profiles[gov1_convergence.GOV1_CONVERGENCE_SCHEMA]["domain_prefix"], keys["gov1_convergence_verifier"][0]))
    capsys.readouterr()
    assert cli.main(["verify-gov1-convergence-record", "--in", str(conv_s_p), "--store-root", str(world.store.root), "--wheel", str(baseline["wheel_path"]), "--corpus", str(world.corpus_path), "--repo", str(REPO_ROOT), "--seccomp-profile", str(f["seccomp"]), "--legacy-blobs-dir", str(world.legacy_blobs_dir), "--pubkey-raw-base64", base64.b64encode(keys["gov1_convergence_verifier"][1]).decode("ascii")]) == 0
    env_out = json.loads(capsys.readouterr().out)
    assert env_out["status"] == "PASS" and env_out["mode"] == "envelope" and env_out["signature_verified"] is True and env_out["d4_authority_verified"] is False


def test_cli_four_7a_and_convergence_commands_fail_exit_1_on_git_or_legacy_tamper(
    tmp_path: Path, baseline_artifacts: dict[str, Any], synthetic_gov1_keys: dict[str, tuple[Path, bytes, str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    world = Gov1D4World(tmp_path / "cli_tamper", synthetic_gov1_keys, baseline_artifacts)
    f = _prepare_cli_fixture_files(tmp_path / "cli_tamper_f", world, baseline_artifacts)
    d: Path = f["dir"]
    cert_p = _write_cli_json(d / "cert_s.json", world.cert7a_env)
    conv_s, _ = _build_signed_conv_in_world(world, synthetic_gov1_keys, baseline_artifacts)
    conv_p, neg_loc_p, cert_loc_p = _write_cli_json(d / "conv_s.json", conv_s), _write_cli_json(d / "neg_loc.json", world.neg_loc), _write_cli_json(d / "cert_loc.json", world.cert7a_loc)
    empty_git, fake_leg, bad_corpus = tmp_path / "empty_legacy_git", tmp_path / "fake_leg_repo", tmp_path / "bad_corpus.json"
    empty_git.mkdir()
    fake_leg.mkdir()
    bad_corpus.write_bytes(baseline_artifacts["corpus_bytes"] + b"\n")
    subprocess.run(["git", "init", "-q", str(empty_git)], check=True)
    bad_blobs = _stage_d26_blobs_dir(tmp_path / "bad_blobs", baseline_artifacts["d26_blobs"])
    role0, rel0, _, _ = PINNED_PIPEBOARD_D26_SPECS[0]
    (bad_blobs / f"{role0}__{Path(rel0).name}").write_bytes(b"corrupted-legacy-blob")
    good_blobs = _stage_d26_blobs_dir(tmp_path / "good_blobs", baseline_artifacts["d26_blobs"])
    cmds = _make_four_7a_cli_arg_builders(d, f, world, synthetic_gov1_keys, baseline_artifacts, cert_p, conv_p, neg_loc_p, cert_loc_p)
    seen: list[tuple[str, ...]] = []
    with monkeypatch.context() as mp:
        _forbid_local_stage7_probes(mp)
        for idx, build_argv in enumerate(cmds):
            assert cli.main(build_argv(["--legacy-repo", str(empty_git)], repo_dir=REPO_ROOT, tag=f"eg{idx}")) == 1
            assert cli.main(build_argv(["--legacy-blobs-dir", str(bad_blobs)], repo_dir=REPO_ROOT, tag=f"bb{idx}")) == 1
            argv_bc = build_argv(["--legacy-blobs-dir", str(good_blobs)], repo_dir=REPO_ROOT, tag=f"bc{idx}")
            argv_bc[argv_bc.index("--corpus") + 1] = str(bad_corpus)
            assert cli.main(argv_bc) == 1
        _install_fake_d26_git_runner(mp, fake_leg, bad_blobs, seen)
        for idx, build_argv in enumerate(cmds):
            assert cli.main(build_argv(["--legacy-repo", str(fake_leg)], repo_dir=REPO_ROOT, tag=f"fl{idx}")) == 1
    assert len(seen) >= 4
    orig_git = gov1_7a_certification.resolve_7a_smart_ads_git_blobs
    monkeypatch.setattr(gov1_7a_certification, "resolve_7a_smart_ads_git_blobs", lambda r, sha: {**dict(orig_git(r, sha)), "src/smart_ads/adapters/pipeboard/wire.py": b"# tampered git blob\n"})
    for idx, build_argv in enumerate(cmds):
        assert cli.main(build_argv(["--legacy-blobs-dir", str(good_blobs)], repo_dir=REPO_ROOT, tag=f"gt{idx}")) == 1


def _make_four_7a_cli_arg_builders(
    d: Path, f: Mapping[str, Any], world: Gov1D4World, keys: dict[str, tuple[Path, bytes, str]], baseline: Mapping[str, Any],
    cert_p: Path, conv_p: Path, neg_loc_p: Path, cert_loc_p: Path,
) -> list[Callable[..., list[str]]]:
    cert_pub = base64.b64encode(keys["independent_7a_verifier"][1]).decode("ascii")
    conv_pub = base64.b64encode(keys["gov1_convergence_verifier"][1]).decode("ascii")
    common_st = ["--store-root", str(world.store.root), "--wheel", str(baseline["wheel_path"]), "--corpus", str(world.corpus_path)]
    return [
        lambda leg, repo_dir, tag: ["build-certification-7a-record", "--mode", "envelope", "--params", str(f["cert_params"]), *common_st, "--repo", str(repo_dir), *leg, "--sandbox-profile-locator", str(f["sbx_loc"]), "--provenance-locator", str(f["prov_loc"]), "--boundary-report-locator", str(f["bound_loc"]), "--negative-report-locator", str(neg_loc_p), "--signer-key-id", keys["independent_7a_verifier"][2], "--registry-locator", str(f["reg_loc"]), "--out", str(d / f"out_c_{tag}.json")],
        lambda leg, repo_dir, tag: ["verify-certification-7a-record", "--in", str(cert_p), *common_st, "--repo", str(repo_dir), *leg, "--pubkey-raw-base64", cert_pub],
        lambda leg, repo_dir, tag: ["build-gov1-convergence-record", "--mode", "envelope", "--params", str(f["conv_params"]), *common_st, "--repo", str(repo_dir), "--seccomp-profile", str(f["seccomp"]), *leg, "--sandbox-profile-locator", str(f["sbx_loc"]), "--boundary-report-locator", str(f["bound_loc"]), "--mcp-rejection-report-locator", str(f["mcp_loc"]), "--negative-report-locator", str(neg_loc_p), "--certification-7a-record-locator", str(cert_loc_p), "--signer-key-id", keys["gov1_convergence_verifier"][2], "--registry-locator", str(f["reg_loc"]), "--out", str(d / f"out_v_{tag}.json")],
        lambda leg, repo_dir, tag: ["verify-gov1-convergence-record", "--in", str(conv_p), *common_st, "--repo", str(repo_dir), "--seccomp-profile", str(f["seccomp"]), *leg, "--pubkey-raw-base64", conv_pub],
    ]
