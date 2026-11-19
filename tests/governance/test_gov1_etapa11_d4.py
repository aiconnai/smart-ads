"""Tests for Etapa 11 convergence unlock, D4 lineage `1..tip_reg`, 4 leaf classes, and 6 CLI subcommands."""
from __future__ import annotations

import base64
from collections.abc import Callable, Mapping
import copy
import json
from pathlib import Path
import shutil
import subprocess
from typing import Any

import pytest

from smart_ads.domain.pipeboard_contract import PINNED_LEGACY_COMMIT, PINNED_PIPEBOARD_D26_SPECS
from smart_ads.reconciliation.certification_7a import CORPUS_GIT_PATH
from tests.governance.test_gov1_convergence import (
    ALT_RUN_CONTEXT_LOCATOR, BUILD_RUN_ID, CONVERGED_AT_UTC, EXECUTED_AT_UTC, ISSUED_AT_UTC, REPO_ROOT,
    RUN_CONTEXT_LOCATOR, FakeOsIsolatedWheelProbeRunner, Gov1D4World, _StructuralFakePr3Verifier,
    _make_conv_base_kwargs, _recompute_candidate_digest, baseline_artifacts, synthetic_gov1_keys,
)
from tools.governance import cli, decomposition_governance, gov1_7a_certification, gov1_7a_negative, gov1_7a_runner, gov1_convergence, gov1_mcp, gov1_sandbox, gov1_wheel, p1
from tools.governance.decomposition_runtime import INVENTORY, REGISTRY, InstallationPins
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


def _assert_candidate_tamper_stops_before_7a(
    monkeypatch: pytest.MonkeyPatch, cand_kw: Mapping[str, Any], world: Gov1D4World, baseline: Mapping[str, Any]
) -> None:
    replay_calls: list[str] = []
    orig_replay = gov1_7a_certification.verify_certification_7a_replay_bytes
    monkeypatch.setattr(
        gov1_7a_certification,
        "verify_certification_7a_replay_bytes",
        lambda *a, **kw: (replay_calls.append("7a"), orig_replay(*a, **kw))[1],
    )
    bad_prov = copy.deepcopy(baseline["prov_cand"])
    bad_prov["payload"]["pyproject_sha256"] = "sha256:" + ("e" * 64)
    bad_prov = _recompute_candidate_digest(bad_prov)
    bad_bound = copy.deepcopy(baseline["boundary_cand"])
    bad_bound["payload"]["wheel_build_provenance_candidate_ref"] = gov1_sandbox.build_local_candidate_ref(bad_prov)
    bad_bound = _recompute_candidate_digest(bad_bound)
    bad_neg = copy.deepcopy(baseline["neg_cand"])
    bad_neg["payload"]["wheel_build_provenance_candidate_ref"] = gov1_sandbox.build_local_candidate_ref(bad_prov)
    bad_neg = _recompute_candidate_digest(bad_neg)
    bad_cert = copy.deepcopy(world.cert_cand)
    bad_cert["payload"]["wheel_build_provenance_candidate_ref"] = gov1_sandbox.build_local_candidate_ref(bad_prov)
    bad_cert["payload"]["wheel_boundary_report_candidate_ref"] = gov1_sandbox.build_local_candidate_ref(bad_bound)
    bad_cert["payload"]["negative_security_test_report_candidate_ref"] = gov1_sandbox.build_local_candidate_ref(bad_neg)
    bad_cert = _recompute_candidate_digest(bad_cert)
    bad_conv = copy.deepcopy(cand_kw["convergence_candidate"])
    bad_conv["payload"]["wheel_boundary_report_candidate_ref"] = gov1_sandbox.build_local_candidate_ref(bad_bound)
    bad_conv["payload"]["negative_security_test_report_candidate_ref"] = gov1_sandbox.build_local_candidate_ref(bad_neg)
    bad_conv["payload"]["certification_7a_record_candidate_ref"] = gov1_sandbox.build_local_candidate_ref(bad_cert)
    bad_conv = _recompute_candidate_digest(bad_conv)
    with pytest.raises(ValueError):
        verify_gov1_convergence_candidate(
            **{**cand_kw, "wheel_provenance": bad_prov, "wheel_boundary_report": bad_bound, "negative_security_report": bad_neg, "certification_7a_record": bad_cert, "convergence_candidate": bad_conv}
        )
    assert replay_calls == []

    div_neg = copy.deepcopy(baseline["neg_cand"])
    div_neg["payload"]["wheel_build_provenance_candidate_ref"] = gov1_sandbox.build_local_candidate_ref(bad_prov)
    div_neg = _recompute_candidate_digest(div_neg)
    div_conv = copy.deepcopy(cand_kw["convergence_candidate"])
    div_conv["payload"]["negative_security_test_report_candidate_ref"] = gov1_sandbox.build_local_candidate_ref(div_neg)
    div_conv = _recompute_candidate_digest(div_conv)
    with pytest.raises(ValueError):
        verify_gov1_convergence_candidate(**{**cand_kw, "negative_security_report": div_neg, "convergence_candidate": div_conv})
    assert replay_calls == []


def _assert_envelope_tamper_stops_before_7a(
    monkeypatch: pytest.MonkeyPatch, world: Gov1D4World, keys: dict[str, tuple[Path, bytes, str]], baseline: Mapping[str, Any]
) -> None:
    conv_s, _ = _build_signed_conv_in_world(world, keys, baseline)
    pr3_v = world.make_pr3_verifier()
    calls: list[str] = []
    orig_v7a = pr3_v.verify_7a_constituents
    monkeypatch.setattr(pr3_v, "verify_7a_constituents", lambda **kw: (calls.append("v7a"), orig_v7a(**kw))[1])

    bad_whl = world.store.root.parent / "bad_envelope.whl"
    bad_whl.write_bytes(baseline["wheel_bytes"] + b"tamper")
    with pytest.raises(ValueError):
        gov1_convergence.verify_gov1_convergence_record(
            conv_s, store=world.store, seccomp_profile=baseline["seccomp_profile"],
            wheel_path=bad_whl, corpus_path=world.corpus_path, repo_root=REPO_ROOT,
            legacy_blobs_dir=world.legacy_blobs_dir, pr3_verifier=pr3_v, probe_runner=world.probe_runner,
        )
    assert calls == []


def test_d4_rejects_protocol_fakes_stale_preflights_and_enforces_snapshot_store(
    tmp_path: Path,
    baseline_artifacts: dict[str, Any],
    synthetic_gov1_keys: dict[str, tuple[Path, bytes, str]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _forbid_local_stage7_probes(monkeypatch)
    world = Gov1D4World(tmp_path, synthetic_gov1_keys, baseline_artifacts)
    _, conv_loc = _build_signed_conv_in_world(world, synthetic_gov1_keys, baseline_artifacts)

    with pytest.raises(ValueError):
        gov1_convergence.Gov1AdmissionVerifier(
            world.runtime, world.pins, world.store, world.adr,
            inventory_locator=world.inventory_loc, pr3_verifier=_StructuralFakePr3Verifier(),
            isolated_probe_runner=world.probe_runner, corpus_path=world.corpus_path, legacy_blobs_dir=world.legacy_blobs_dir,
        )
    assert world.runtime.cas_calls == 0

    _assert_d4_rejects_all_5_divergent_preflight_inputs(world, baseline_artifacts, conv_loc)
    _assert_d4_passes_only_snapshot_store(world, baseline_artifacts, conv_loc, monkeypatch)


def _assert_d4_rejects_all_5_divergent_preflight_inputs(
    world: Gov1D4World, baseline: Mapping[str, Any], conv_loc: dict[str, Any]
) -> None:
    prov_p = gov1_7a_negative.extract_provenance_payload(world.prov_env)
    alt_prov_p = {**prov_p, "built_at_utc": "2026-09-07T10:00:06Z"}
    alt_corpus = baseline["corpus_bytes"] + b"\n"
    alt_git = {**dict(baseline["git_blobs"]), CORPUS_GIT_PATH[1]: alt_corpus}
    bad_verifiers = [
        gov1_7a_certification.SevenAConstituentVerifier(
            wheel_bytes=baseline["wheel_bytes"], corpus_bytes=alt_corpus, stripped_provenance_payload=prov_p,
            resolved_git_blobs=alt_git, resolved_d26_blobs=baseline["d26_blobs"],
        ),
        gov1_7a_certification.SevenAConstituentVerifier(
            wheel_bytes=baseline["wheel_bytes"], corpus_bytes=baseline["corpus_bytes"], stripped_provenance_payload=alt_prov_p,
            resolved_git_blobs=baseline["git_blobs"], resolved_d26_blobs=baseline["d26_blobs"],
        ),
        gov1_7a_certification.SevenAConstituentVerifier(
            wheel_bytes=baseline["wheel_bytes"], corpus_bytes=baseline["corpus_bytes"], stripped_provenance_payload=prov_p,
            resolved_git_blobs={**dict(baseline["git_blobs"]), "src/smart_ads/adapters/pipeboard/__init__.py": b"# tampered\n"},
            resolved_d26_blobs=baseline["d26_blobs"],
        ),
    ]
    for bad_v in bad_verifiers:
        v = world.make_verifier(pr3_verifier=bad_v)
        with pytest.raises(ValueError, match="diverged from bound preflight"):
            v.verify_artifact(
                conv_loc, seccomp_profile=baseline["seccomp_profile"],
                wheel_path=baseline["wheel_path"], repo_root=REPO_ROOT,
            )
        assert world.runtime.cas_calls == 0

    pr3_ok = world.make_pr3_verifier()
    with pytest.raises(ValueError, match="wheel_bytes"):
        pr3_ok.verify_bound_preflight_inputs(
            wheel_bytes=baseline["wheel_bytes"] + b"x", corpus_bytes=baseline["corpus_bytes"],
            stripped_provenance_payload=prov_p, resolved_git_blobs=baseline["git_blobs"], resolved_d26_blobs=baseline["d26_blobs"],
        )
    with pytest.raises(ValueError, match="resolved_d26_blobs"):
        pr3_ok.verify_bound_preflight_inputs(
            wheel_bytes=baseline["wheel_bytes"], corpus_bytes=baseline["corpus_bytes"],
            stripped_provenance_payload=prov_p, resolved_git_blobs=baseline["git_blobs"], resolved_d26_blobs={},
        )


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
    verifier: gov1_convergence.Gov1AdmissionVerifier,
    world: Gov1D4World,
    baseline: Mapping[str, Any],
    conv_loc: dict[str, Any],
) -> None:
    calls: list[Callable[[], Any]] = [
        lambda: verifier.verify_artifact(world.prov_loc, wheel_path=baseline["wheel_path"], repo_root=REPO_ROOT),
        lambda: verifier.verify_artifact(world.boundary_loc, wheel_path=baseline["wheel_path"], repo_root=REPO_ROOT),
        lambda: verifier.verify_artifact(world.mcp_loc, wheel_path=baseline["wheel_path"], seccomp_profile=baseline["seccomp_profile"]),
        lambda: verifier.verify_artifact(conv_loc, seccomp_profile=baseline["seccomp_profile"], wheel_path=baseline["wheel_path"], repo_root=REPO_ROOT),
        lambda: verifier.admit_etapa7_bundle(
            sandbox_profile_locator=world.sandbox_loc, wheel_provenance_locator=world.prov_loc,
            wheel_boundary_report_locator=world.boundary_loc, mcp_rejection_report_locator=world.mcp_loc,
            seccomp_profile=baseline["seccomp_profile"], wheel_path=baseline["wheel_path"], repo_root=REPO_ROOT,
        ),
    ]
    for fn in calls:
        with pytest.raises(ValueError, match="isolated_probe_runner|os_isolated"):
            fn()


def test_installation_pins_fallback_and_gov1_installation_pins_from_repo() -> None:
    ident = decomposition_governance.verified_run_context_identity(REPO_ROOT)
    pins_repo = Gov1InstallationPins.from_repo_prerequisites(REPO_ROOT)
    assert canonicalize(pins_repo.pinned_run_context_locator) == canonicalize(ident["run_context_locator"])
    assert len(pins_repo.pinned_pre_head_registry_locators) == 3

    base_pins = InstallationPins(
        configuration_digest="sha256:" + ("a" * 64), installation_authority="auth", cell_id="cell",
        head_register="head:1", checkpoint_register="chk:1", owner_principal="principal:ronaldo", owner_tenant="mbras",
    )
    anchor_cfg = {"public_key_base64": decomposition_governance.ANCHOR_PUBLIC}
    for ep in (1, 2, 3, 4):
        r_ctx, pre_locs = _resolve_d4_pins(base_pins, config=anchor_cfg, head_1_reg={"epoch": ep}, repo_root=REPO_ROOT)
        assert canonicalize(r_ctx) == canonicalize(ident["run_context_locator"])
        assert len(pre_locs) == ep - 1

    with pytest.raises(ValueError, match="ANCHOR_PUBLIC|anchor"):
        _resolve_d4_pins(base_pins, config={"public_key_base64": base64.b64encode(b"x" * 32).decode("ascii")}, head_1_reg={"epoch": 4}, repo_root=REPO_ROOT)
    with pytest.raises(ValueError, match="epoch"):
        _resolve_d4_pins(base_pins, config=anchor_cfg, head_1_reg={"epoch": 5}, repo_root=REPO_ROOT)


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
    w_res = Gov1D4World(
        tmp_path / "resurrect", keys, baseline,
        registry_mutation=lambda reg: reg["entries"][8].update(lifecycle_state="revoked"),
    )
    w_res.advance_current_registry(lambda reg: reg["entries"][8].update(lifecycle_state="active"))
    with pytest.raises(ValueError, match="lifecycle|monotonic|revoked"):
        w_res.make_verifier().verify_artifact(w_res.sandbox_loc, seccomp_profile=baseline["seccomp_profile"])

    reg4 = w_res.store.get(w_res.pre_head_reg_locs[2])
    reg5_exp = copy.deepcopy(reg4)
    reg5_exp["epoch"] = 4
    reg5_exp["entries"][8]["lifecycle_state"] = "expired"
    reg5_exp["integrity"] = {"key_id": keys["trust_anchor"][2], "key_registry_snapshot_locator": None}
    reg5_exp_s = p1.sign_envelope(reg5_exp, w_res.profiles[REGISTRY]["domain_prefix"], keys["trust_anchor"][0])
    reg6_rev = copy.deepcopy(reg5_exp_s)
    reg6_rev["epoch"] = 5
    reg6_rev["entries"][8]["lifecycle_state"] = "revoked"
    reg6_rev["integrity"] = {"key_id": keys["trust_anchor"][2], "key_registry_snapshot_locator": None}
    reg6_rev_s = p1.sign_envelope(reg6_rev, w_res.profiles[REGISTRY]["domain_prefix"], keys["trust_anchor"][0])
    with pytest.raises(ValueError, match="lifecycle|monotonic"):
        _verify_d4_registry_lineage_step(reg5_exp_s, reg6_rev_s, w_res.config)


def test_d4_registry_membership_run_context_and_leaf_authentication(
    tmp_path: Path,
    baseline_artifacts: dict[str, Any],
    synthetic_gov1_keys: dict[str, tuple[Path, bytes, str]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _forbid_local_stage7_probes(monkeypatch)
    world = Gov1D4World(tmp_path, synthetic_gov1_keys, baseline_artifacts)
    fork_reg = copy.deepcopy(world.store.get(world.pre_head_reg_locs[1]))
    fork_reg["issued_at_utc"] = "2026-09-05T01:00:00Z"
    fork_reg["integrity"] = {"key_id": synthetic_gov1_keys["trust_anchor"][2], "key_registry_snapshot_locator": None}
    fork_reg_s = p1.sign_envelope(fork_reg, world.profiles[REGISTRY]["domain_prefix"], synthetic_gov1_keys["trust_anchor"][0])
    fork_reg_loc = world.store.put(fork_reg_s)
    with pytest.raises(ValueError, match="chain_registries_by_epoch"):
        _verify_d4_registry_membership(fork_reg_s, {2: canonicalize(world.store.get(world.pre_head_reg_locs[1]))}, label="fork")

    fork_inv = copy.deepcopy(world.objects["inventory"])
    fork_inv["integrity"] = {"key_id": synthetic_gov1_keys["trust_anchor"][2], "key_registry_snapshot_locator": fork_reg_loc}
    fork_inv_loc = world.store.put(
        p1.sign_envelope(fork_inv, world.profiles[INVENTORY]["domain_prefix"], synthetic_gov1_keys["trust_anchor"][0])
    )
    with pytest.raises(ValueError, match="chain_registries_by_epoch"):
        world.make_verifier().verify_artifact(world.sandbox_loc, inventory_locator=fork_inv_loc, seccomp_profile=baseline_artifacts["seccomp_profile"])

    alt_pins = Gov1InstallationPins(
        configuration_digest=world.pins.configuration_digest, installation_authority=world.pins.installation_authority,
        cell_id=world.pins.cell_id, head_register=world.pins.head_register, checkpoint_register=world.pins.checkpoint_register,
        owner_principal=world.pins.owner_principal, owner_tenant=world.pins.owner_tenant,
        pinned_run_context_locator=ALT_RUN_CONTEXT_LOCATOR, pinned_pre_head_registry_locators=world.pre_head_reg_locs,
    )
    v_alt_ctx = gov1_convergence.Gov1AdmissionVerifier(
        world.runtime, alt_pins, world.store, world.adr,
        inventory_locator=world.inventory_loc, isolated_probe_runner=world.probe_runner,
    )
    with pytest.raises(ValueError, match="migration_run_context_locator"):
        v_alt_ctx.verify_artifact(world.sandbox_loc, seccomp_profile=baseline_artifacts["seccomp_profile"])

    _assert_leaf_fork_and_role_rejections_in_d4(tmp_path, synthetic_gov1_keys, baseline_artifacts, fork_reg_loc)


def _assert_leaf_fork_and_role_rejections_in_d4(
    tmp_path: Path, keys: dict[str, tuple[Path, bytes, str]], baseline: dict[str, Any], fork_reg_loc: dict[str, Any]
) -> None:
    _ = fork_reg_loc
    for role_idx in (8, 9, 10, 11):
        w_leaf = Gov1D4World(tmp_path / f"leaf_rev_{role_idx}", keys, baseline)
        _, conv_loc = _build_signed_conv_in_world(w_leaf, keys, baseline)
        w_leaf.advance_current_registry(lambda reg, i=role_idx: reg["entries"][i].update(lifecycle_state="revoked"))
        with pytest.raises(ValueError, match="authority key currently revoked or expired"):
            w_leaf.make_verifier(pr3_verifier=w_leaf.make_pr3_verifier()).verify_artifact(
                conv_loc, seccomp_profile=baseline["seccomp_profile"], wheel_path=baseline["wheel_path"], repo_root=REPO_ROOT
            )
        assert w_leaf.runtime.cas_calls == 0

    w_fork_git = Gov1D4World(tmp_path / "leaf_fork_git", keys, baseline)
    fork_reg_obj = {**copy.deepcopy(w_fork_git.store.get(w_fork_git.pre_head_reg_locs[1])), "issued_at_utc": "2026-09-05T01:00:00Z", "integrity": {"key_id": keys["trust_anchor"][2], "key_registry_snapshot_locator": None}}
    fk_loc = w_fork_git.store.put(p1.sign_envelope(fork_reg_obj, w_fork_git.profiles[REGISTRY]["domain_prefix"], keys["trust_anchor"][0]))
    corpus_git_u = gov1_7a_certification.build_git_artifact_provenance_envelope(
        repository="aiconnai/smart-ads", commit_sha=baseline["snapshot"].commit_sha, path=CORPUS_GIT_PATH[1],
        raw_bytes=baseline["corpus_bytes"], resolved_at_utc="2026-09-07T10:00:04Z", registry_locator=fk_loc, signer_key_id=keys["git_provenance_verifier"][2],
    )
    corpus_git_loc = w_fork_git.store.put(p1.sign_envelope(corpus_git_u, w_fork_git.profiles[gov1_7a_runner.GIT_ARTIFACT_PROVENANCE_SCHEMA]["domain_prefix"], keys["git_provenance_verifier"][0]))
    cert_fk = copy.deepcopy(w_fork_git.cert7a_env)
    cert_fk["fixture_evidence"]["corpus_git_locator"] = corpus_git_loc
    cert_fk["integrity"] = {"key_id": keys["independent_7a_verifier"][2], "key_registry_snapshot_locator": w_fork_git.registry_loc}
    cert_fk_loc = w_fork_git.store.put(p1.sign_envelope(cert_fk, w_fork_git.profiles[gov1_convergence.CERTIFICATION_7A_SCHEMA]["domain_prefix"], keys["independent_7a_verifier"][0]))
    conv_fk = p1.sign_envelope(
        gov1_convergence.build_gov1_convergence_record_envelope(
            **{**_make_conv_base_kwargs(w_fork_git, keys, baseline), "certification_7a_record_locator": cert_fk_loc},
            store=w_fork_git.store, pr3_verifier=w_fork_git.make_pr3_verifier(),
        ),
        w_fork_git.profiles[gov1_convergence.GOV1_CONVERGENCE_SCHEMA]["domain_prefix"], keys["gov1_convergence_verifier"][0],
    )
    with pytest.raises(ValueError, match="chain_registries_by_epoch"):
        w_fork_git.make_verifier(pr3_verifier=w_fork_git.make_pr3_verifier()).verify_artifact(
            w_fork_git.store.put(conv_fk), seccomp_profile=baseline["seccomp_profile"], wheel_path=baseline["wheel_path"], repo_root=REPO_ROOT
        )
    assert w_fork_git.runtime.cas_calls == 0


@pytest.mark.parametrize("mutation_kind", ["store_leaf", "wheel_file", "corpus_file", "git_repo_blob", "legacy_blobs_dir", "legacy_repo"])
def test_post_cas_mutations_fail_closed_before_observe_head_and_clock(
    tmp_path: Path, baseline_artifacts: dict[str, Any], synthetic_gov1_keys: dict[str, tuple[Path, bytes, str]], monkeypatch: pytest.MonkeyPatch, mutation_kind: str
) -> None:
    _forbid_local_stage7_probes(monkeypatch)
    world = Gov1D4World(tmp_path / mutation_kind, synthetic_gov1_keys, baseline_artifacts)
    _, conv_loc = _build_signed_conv_in_world(world, synthetic_gov1_keys, baseline_artifacts)
    whl_copy = tmp_path / f"{mutation_kind}.whl"
    whl_copy.write_bytes(baseline_artifacts["wheel_bytes"])
    corpus_copy = tmp_path / f"{mutation_kind}_corpus.json"
    corpus_copy.write_bytes(baseline_artifacts["corpus_bytes"])
    blobs_dir = _stage_d26_blobs_dir(tmp_path / f"{mutation_kind}_blobs", baseline_artifacts["d26_blobs"])
    fake_leg_repo = tmp_path / f"{mutation_kind}_leg_git"
    fake_leg_repo.mkdir()
    seen_d26_git: list[tuple[str, ...]] = []
    if mutation_kind == "legacy_repo":
        _install_fake_d26_git_runner(monkeypatch, fake_leg_repo, blobs_dir, seen_d26_git)

    _attach_post_cas_mutation_hook(monkeypatch, world, mutation_kind, whl_copy, corpus_copy, blobs_dir, baseline_artifacts)
    v = gov1_convergence.Gov1AdmissionVerifier(
        world.runtime, world.pins, world.store, world.adr,
        inventory_locator=world.inventory_loc, pr3_verifier=world.make_pr3_verifier(),
        isolated_probe_runner=world.probe_runner, corpus_path=corpus_copy,
        legacy_repo=fake_leg_repo if mutation_kind == "legacy_repo" else None,
        legacy_blobs_dir=None if mutation_kind == "legacy_repo" else blobs_dir,
    )
    with pytest.raises(ValueError):
        v.verify_artifact(conv_loc, seccomp_profile=baseline_artifacts["seccomp_profile"], wheel_path=whl_copy, repo_root=REPO_ROOT)
    assert world.runtime.cas_calls == 1 and world.runtime.observe_calls == 0
    if mutation_kind == "legacy_repo":
        assert len(seen_d26_git) == 12


def _attach_post_cas_mutation_hook(
    monkeypatch: pytest.MonkeyPatch,
    world: Gov1D4World,
    mutation_kind: str,
    whl_copy: Path,
    corpus_copy: Path,
    blobs_dir: Path,
    baseline: Mapping[str, Any],
) -> None:
    if mutation_kind == "store_leaf":
        corpus_git_loc = world.cert7a_env["fixture_evidence"]["corpus_git_locator"]
        orig_get = world.store.get
        monkeypatch.setattr(
            world.store, "get",
            lambda loc, expected_type=None: (
                {**orig_get(loc, expected_type=expected_type), "resolved_at_utc": "2026-09-07T10:00:05Z"}
                if world.runtime.cas_calls and canonicalize(loc) == canonicalize(corpus_git_loc)
                else orig_get(loc, expected_type=expected_type)
            ),
        )
    elif mutation_kind == "wheel_file":
        world.runtime.post_cas_hook = lambda: whl_copy.write_bytes(baseline["wheel_bytes"] + b"m")
    elif mutation_kind == "corpus_file":
        world.runtime.post_cas_hook = lambda: corpus_copy.write_bytes(baseline["corpus_bytes"] + b"\n")
    elif mutation_kind == "git_repo_blob":
        orig_git = gov1_7a_certification.resolve_7a_smart_ads_git_blobs
        monkeypatch.setattr(
            gov1_7a_certification, "resolve_7a_smart_ads_git_blobs",
            lambda r, sha: (
                {**dict(orig_git(r, sha)), CORPUS_GIT_PATH[1]: baseline["corpus_bytes"] + b"\n"}
                if world.runtime.cas_calls
                else orig_git(r, sha)
            ),
        )
    else:
        role0, rel0, _, _ = PINNED_PIPEBOARD_D26_SPECS[0]
        target = blobs_dir / f"{role0}__{Path(rel0).name}"
        world.runtime.post_cas_hook = lambda: target.write_bytes(baseline["d26_blobs"][rel0] + b"\n")


# ---------------------------------------------------------------------------
# 6. End-to-End Tests for All 6 CLI Subcommands & Tampered Git/Legacy Rejections
# ---------------------------------------------------------------------------


def _write_cli_json(path: Path, data: Mapping[str, Any]) -> Path:
    path.write_bytes(canonicalize(dict(data)))
    return path


def _prepare_cli_fixture_files(
    tmp_path: Path, world: Gov1D4World, baseline: Mapping[str, Any]
) -> dict[str, Any]:
    d = tmp_path / "cli_files"
    d.mkdir(parents=True, exist_ok=True)
    seccomp_p = _write_cli_json(d / "seccomp.json", baseline["seccomp_profile"])
    sbx_c_p = _write_cli_json(d / "sbx_cand.json", baseline["sandbox_cand"])
    prov_c_p = _write_cli_json(d / "prov_cand.json", baseline["prov_cand"])
    bound_c_p = _write_cli_json(d / "bound_cand.json", baseline["boundary_cand"])
    mcp_c_p = _write_cli_json(d / "mcp_cand.json", baseline["mcp_cand"])
    sbx_e_p = _write_cli_json(d / "sbx_env.json", world.sandbox_env)
    prov_e_p = _write_cli_json(d / "prov_env.json", world.prov_env)
    reg_loc_p = _write_cli_json(d / "reg_loc.json", world.registry_loc)
    sbx_loc_p = _write_cli_json(d / "sbx_loc.json", world.sandbox_loc)
    prov_loc_p = _write_cli_json(d / "prov_loc.json", world.prov_loc)
    bound_loc_p = _write_cli_json(d / "bound_loc.json", world.boundary_loc)
    mcp_loc_p = _write_cli_json(d / "mcp_loc.json", world.mcp_loc)
    snap: gov1_wheel.GitBuildSnapshot = baseline["snapshot"]
    neg_params_p = _write_cli_json(
        d / "neg_params.json",
        {
            "migration_run_context_locator": RUN_CONTEXT_LOCATOR, "build_run_id": BUILD_RUN_ID,
            "executed_at_utc": EXECUTED_AT_UTC, "source_commit_sha": snap.commit_sha,
            "build_backend_digest": snap.build_backend_digest, "schema_bundle_digest": baseline["inspection"]["schema_bundle_digest"],
            "wheel_digest": baseline["inspection"]["wheel_digest"], "oci_image_digest": "sha256:" + ("1" * 64),
            "runner_binary_digest": "sha256:" + ("2" * 64),
            "declared_resource_limits": baseline["sandbox_cand"]["payload"]["resource_limits"],
            "cases": baseline["neg_cases"],
        },
    )
    cert_params_p = _write_cli_json(d / "cert_params.json", world.cert_common)
    conv_params_p = _write_cli_json(
        d / "conv_params.json",
        {
            "migration_run_context_locator": RUN_CONTEXT_LOCATOR, "build_run_id": BUILD_RUN_ID,
            "converged_at_utc": CONVERGED_AT_UTC, "source_commit_sha": snap.commit_sha,
            "wheel_digest": baseline["inspection"]["wheel_digest"], "build_backend_digest": snap.build_backend_digest,
            "schema_bundle_digest": baseline["inspection"]["schema_bundle_digest"],
        },
    )
    return {
        "dir": d, "seccomp": seccomp_p, "sbx_c": sbx_c_p, "prov_c": prov_c_p, "bound_c": bound_c_p, "mcp_c": mcp_c_p,
        "sbx_e": sbx_e_p, "prov_e": prov_e_p, "reg_loc": reg_loc_p, "sbx_loc": sbx_loc_p, "prov_loc": prov_loc_p,
        "bound_loc": bound_loc_p, "mcp_loc": mcp_loc_p, "neg_params": neg_params_p, "cert_params": cert_params_p, "conv_params": conv_params_p,
    }


def test_six_new_cli_subcommands_candidate_and_envelope_roundtrip(
    tmp_path: Path,
    baseline_artifacts: dict[str, Any],
    synthetic_gov1_keys: dict[str, tuple[Path, bytes, str]],
    capsys: pytest.CaptureFixture[str],
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
    f: Mapping[str, Any],
    world: Gov1D4World,
    keys: dict[str, tuple[Path, bytes, str]],
    baseline: Mapping[str, Any],
    capsys: pytest.CaptureFixture[str],
) -> None:
    d: Path = f["dir"]
    neg_u_p, cert_u_p, conv_u_p = d / "neg_u.json", d / "cert_u.json", d / "conv_u.json"
    assert cli.main(["build-negative-security-report", "--mode", "envelope", "--params", str(f["neg_params"]), "--wheel", str(baseline["wheel_path"]), "--sandbox-profile-locator", str(f["sbx_loc"]), "--provenance-locator", str(f["prov_loc"]), "--signer-key-id", keys["7a_verifier"][2], "--registry-locator", str(f["reg_loc"]), "--out", str(neg_u_p)]) == 0
    neg_s = p1.sign_envelope(json.loads(neg_u_p.read_text(encoding="utf-8")), world.profiles[gov1_convergence.NEGATIVE_SECURITY_SCHEMA]["domain_prefix"], keys["7a_verifier"][0])
    neg_s_p = _write_cli_json(d / "neg_s.json", neg_s)
    neg_loc_p = _write_cli_json(d / "neg_loc.json", world.store.put(neg_s))
    assert cli.main(["verify-negative-security-report", "--in", str(neg_s_p), "--wheel", str(baseline["wheel_path"]), "--sandbox-profile", str(f["sbx_e"]), "--seccomp-profile", str(f["seccomp"]), "--provenance", str(f["prov_e"]), "--pubkey-raw-base64", base64.b64encode(keys["7a_verifier"][1]).decode("ascii")]) == 0

    assert cli.main(["build-certification-7a-record", "--mode", "envelope", "--params", str(f["cert_params"]), "--store-root", str(world.store.root), "--wheel", str(baseline["wheel_path"]), "--corpus", str(world.corpus_path), "--repo", str(REPO_ROOT), "--legacy-blobs-dir", str(world.legacy_blobs_dir), "--sandbox-profile-locator", str(f["sbx_loc"]), "--provenance-locator", str(f["prov_loc"]), "--boundary-report-locator", str(f["bound_loc"]), "--negative-report-locator", str(neg_loc_p), "--signer-key-id", keys["independent_7a_verifier"][2], "--registry-locator", str(f["reg_loc"]), "--out", str(cert_u_p)]) == 0
    cert_s = p1.sign_envelope(json.loads(cert_u_p.read_text(encoding="utf-8")), world.profiles[gov1_convergence.CERTIFICATION_7A_SCHEMA]["domain_prefix"], keys["independent_7a_verifier"][0])
    cert_s_p = _write_cli_json(d / "cert_s.json", cert_s)
    cert_loc_p = _write_cli_json(d / "cert_loc.json", world.store.put(cert_s))
    assert cli.main(["verify-certification-7a-record", "--in", str(cert_s_p), "--store-root", str(world.store.root), "--wheel", str(baseline["wheel_path"]), "--corpus", str(world.corpus_path), "--repo", str(REPO_ROOT), "--legacy-blobs-dir", str(world.legacy_blobs_dir), "--pubkey-raw-base64", base64.b64encode(keys["independent_7a_verifier"][1]).decode("ascii")]) == 0

    assert cli.main(["build-gov1-convergence-record", "--mode", "envelope", "--params", str(f["conv_params"]), "--store-root", str(world.store.root), "--wheel", str(baseline["wheel_path"]), "--corpus", str(world.corpus_path), "--repo", str(REPO_ROOT), "--seccomp-profile", str(f["seccomp"]), "--legacy-blobs-dir", str(world.legacy_blobs_dir), "--sandbox-profile-locator", str(f["sbx_loc"]), "--boundary-report-locator", str(f["bound_loc"]), "--mcp-rejection-report-locator", str(f["mcp_loc"]), "--negative-report-locator", str(neg_loc_p), "--certification-7a-record-locator", str(cert_loc_p), "--signer-key-id", keys["gov1_convergence_verifier"][2], "--registry-locator", str(f["reg_loc"]), "--out", str(conv_u_p)]) == 0
    conv_s = p1.sign_envelope(json.loads(conv_u_p.read_text(encoding="utf-8")), world.profiles[gov1_convergence.GOV1_CONVERGENCE_SCHEMA]["domain_prefix"], keys["gov1_convergence_verifier"][0])
    conv_s_p = _write_cli_json(d / "conv_s.json", conv_s)
    capsys.readouterr()
    assert cli.main(["verify-gov1-convergence-record", "--in", str(conv_s_p), "--store-root", str(world.store.root), "--wheel", str(baseline["wheel_path"]), "--corpus", str(world.corpus_path), "--repo", str(REPO_ROOT), "--seccomp-profile", str(f["seccomp"]), "--legacy-blobs-dir", str(world.legacy_blobs_dir), "--pubkey-raw-base64", base64.b64encode(keys["gov1_convergence_verifier"][1]).decode("ascii")]) == 0
    env_out = json.loads(capsys.readouterr().out)
    assert env_out["status"] == "PASS" and env_out["mode"] == "envelope" and env_out["signature_verified"] is True and env_out["d4_authority_verified"] is False


def test_cli_four_7a_and_convergence_commands_fail_exit_1_on_git_or_legacy_tamper(
    tmp_path: Path,
    baseline_artifacts: dict[str, Any],
    synthetic_gov1_keys: dict[str, tuple[Path, bytes, str]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = Gov1D4World(tmp_path / "cli_tamper", synthetic_gov1_keys, baseline_artifacts)
    f = _prepare_cli_fixture_files(tmp_path / "cli_tamper_f", world, baseline_artifacts)
    d: Path = f["dir"]
    cert_p = _write_cli_json(d / "cert_s.json", world.cert7a_env)
    conv_s, _ = _build_signed_conv_in_world(world, synthetic_gov1_keys, baseline_artifacts)
    conv_p = _write_cli_json(d / "conv_s.json", conv_s)
    neg_loc_p = _write_cli_json(d / "neg_loc.json", world.neg_loc)
    cert_loc_p = _write_cli_json(d / "cert_loc.json", world.cert7a_loc)
    empty_git = tmp_path / "empty_legacy_git"
    empty_git.mkdir()
    subprocess.run(["git", "init", "-q", str(empty_git)], check=True)
    bad_blobs = _stage_d26_blobs_dir(tmp_path / "bad_blobs", baseline_artifacts["d26_blobs"])
    role0, rel0, _, _ = PINNED_PIPEBOARD_D26_SPECS[0]
    (bad_blobs / f"{role0}__{Path(rel0).name}").write_bytes(b"corrupted-legacy-blob")

    cmds = _make_four_7a_cli_arg_builders(d, f, world, synthetic_gov1_keys, baseline_artifacts, cert_p, conv_p, neg_loc_p, cert_loc_p)
    for idx, build_argv in enumerate(cmds):
        assert cli.main(build_argv(["--legacy-repo", str(empty_git)], repo_dir=REPO_ROOT, tag=f"eg{idx}")) == 1
        assert cli.main(build_argv(["--legacy-blobs-dir", str(bad_blobs)], repo_dir=REPO_ROOT, tag=f"bb{idx}")) == 1

    fake_leg = tmp_path / "fake_leg_repo"
    fake_leg.mkdir()
    seen: list[tuple[str, ...]] = []
    _install_fake_d26_git_runner(monkeypatch, fake_leg, bad_blobs, seen)
    for idx, build_argv in enumerate(cmds):
        assert cli.main(build_argv(["--legacy-repo", str(fake_leg)], repo_dir=REPO_ROOT, tag=f"fl{idx}")) == 1
    assert len(seen) >= 4

    good_blobs = _stage_d26_blobs_dir(tmp_path / "good_blobs", baseline_artifacts["d26_blobs"])
    orig_git = gov1_7a_certification.resolve_7a_smart_ads_git_blobs
    monkeypatch.setattr(
        gov1_7a_certification, "resolve_7a_smart_ads_git_blobs",
        lambda r, sha: {**dict(orig_git(r, sha)), "src/smart_ads/adapters/pipeboard/wire.py": b"# tampered git blob\n"},
    )
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
