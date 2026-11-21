"""Portable contract tests and live Linux amd64 root runc tests for `gov1_oci_supervisor`."""
from __future__ import annotations

import ast, base64, datetime, os, subprocess, tempfile, threading
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from _pytest.outcomes import Failed
import pytest

from tests.governance.test_gov1_7a_verifiers import _stage_leaf_envelopes_in_store
from tests.governance.test_gov1_convergence import ADR_PATH, Gov1InstallationPins, MemoryProtectedRuntime, RUN_CONTEXT_LOCATOR
from tests.governance.test_gov1_oci_seccomp_and_bundle import _make_tar_gz_layer, _write_synthetic_oci_layout
from tools.governance import (
    decomposition_governance, gov1_7a_certification, gov1_7a_negative, gov1_7a_runner, gov1_convergence, gov1_mcp,
    gov1_oci_container_runner, gov1_oci_image, gov1_oci_readback, gov1_oci_supervisor, gov1_sandbox, gov1_wheel, p1,
)
from tools.governance.jcs import canonicalize, loads_strict
from tools.governance.locator import Store, digest, make_locator

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES_DIR = REPO_ROOT / "tests" / "certification_7a" / "fixtures"
PINNED_D26_JSON, CORPUS_JSON = FIXTURES_DIR / "pinned_d26c73d_blobs.json", FIXTURES_DIR / "pipeboard_7a_corpus_v1.json"
_FORBIDDEN_NET = frozenset({"urllib", "http", "socket", "ssl", "ftplib", "poplib", "imaplib", "smtplib", "xmlrpc"})
_DENIAL_OBS: dict[str, dict[str, Any]] = {
    **{k: dict(v) for k, v in gov1_7a_negative._EXACT_DENIAL_OBS.items()},
    "credential_paths_denied": {"probe_set_id": "credential_paths_v1", "denied_probe_count": 7},
    "process_creation_denied": {"probe_set_id": "seccomp_process_creation_v1", "denied_probe_count": 6},
    "socket_denied": {"probe_set_id": "seccomp_socket_v1", "denied_probe_count": 3},
}

def _decode_d26() -> dict[str, bytes]:
    doc = loads_strict(PINNED_D26_JSON.read_text(encoding="utf-8"))
    return {rel: base64.b64decode(doc["blobs"][f"{role}__{Path(rel).name}"]) for role, rel, _, _ in gov1_7a_runner.PINNED_PIPEBOARD_D26_SPECS}

def _require_live_oci_prereqs(*, env: Mapping[str, str] | None = None, probe_fn: Any = gov1_oci_readback.probe_7a_oci_host) -> Path | None:
    eff_env = os.environ if env is None else env
    if eff_env.get("SMART_ADS_LIVE_OCI_TESTS") != "1":
        return None
    raw_base = eff_env.get("SMART_ADS_BASE_OCI_DIR", "").strip()
    if not raw_base:
        pytest.fail("SMART_ADS_LIVE_OCI_TESTS=1 requires SMART_ADS_BASE_OCI_DIR")
    base_dir = Path(raw_base)
    probe = probe_fn(base_oci_dir=base_dir)
    if not probe.get("eligible"):
        pytest.fail(f"SMART_ADS_LIVE_OCI_TESTS=1 host ineligible: {probe!r}")
    return base_dir

@pytest.fixture(scope="module")
def portable_oci_fixture(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    root = tmp_path_factory.mktemp("task3_oci")
    priv_pem = root / "sbx.pem"
    subprocess.run(["openssl", "genpkey", "-algorithm", "Ed25519", "-out", str(priv_pem)], check=True, capture_output=True)
    pub_raw32 = p1.raw_public_key_from_pem(priv_pem)
    wheel_path, snapshot = gov1_wheel.build_reproducible_wheel(REPO_ROOT, root / "whl")
    whl_bytes = wheel_path.read_bytes()
    insp, mcp_exec = gov1_wheel.inspect_wheel_boundary(wheel_path), gov1_mcp.execute_mcp_rejection_matrix_on_wheel(wheel_path)
    base_dir = root / "base_oci"
    base_meta = _write_synthetic_oci_layout(base_dir, [_make_tar_gz_layer([("dir", "usr/local/bin", 0o755, b""), ("reg", "usr/local/bin/python3.12", 0o755, b"\x7fELF-py312")])])
    d26, git_blobs = _decode_d26(), gov1_7a_certification.resolve_7a_smart_ads_git_blobs(REPO_ROOT, snapshot.commit_sha)
    store = Store(root / "store")
    reg_state, prov_map, inv_pair = _stage_leaf_envelopes_in_store(store, commit_sha=snapshot.commit_sha, git_blobs=git_blobs, d26_blobs=d26)
    rctx = {"snapshot": reg_state.snapshot.to_dict(), "snapshot_locator": reg_state.locator.to_dict(), "driver_contract": reg_state.driver_contract.to_dict(), "driver_contract_locator": reg_state.driver_contract_locator.to_dict(), "expected_inventory": inv_pair[1].to_dict(), "expected_inventory_locator": inv_pair[0].to_dict()}
    seccomp = gov1_sandbox.build_default_7a_seccomp_profile()
    comp_spec = gov1_oci_image.build_composite_7a_oci_layout(base_oci_dir=base_dir, output_layout_dir=root / "comp_oci", wheel_bytes=whl_bytes, corpus_bytes=CORPUS_JSON.read_bytes(), replay_context_obj=rctx, resolved_d26_blobs=d26, seccomp_profile=seccomp, runner_py_bytes=gov1_oci_container_runner.CONTAINER_RUNNER_SOURCE.encode("utf-8"), venv_probe_bootstrap_bytes=gov1_oci_container_runner.VENV_PROBE_BOOTSTRAP_SOURCE.encode("utf-8"), expected_manifest_digest=base_meta["manifest_digest"], expected_config_digest=base_meta["config_digest"], expected_layer_digests=base_meta["layer_digests"], expected_diff_ids=base_meta["diff_ids"])
    return {"root": root, "priv_pem": priv_pem, "pub_raw32": pub_raw32, "key_id": p1.key_id_for(pub_raw32), "wheel_path": wheel_path, "wheel_bytes": whl_bytes, "snapshot": snapshot, "inspection": insp, "mcp_exec": mcp_exec, "base_dir": base_dir, "base_meta": base_meta, "d26": d26, "git_blobs": git_blobs, "store": store, "reg_state": reg_state, "prov_map": prov_map, "inv_pair": inv_pair, "seccomp": seccomp, "comp_spec": comp_spec}

class _PipeContainerSim:
    def __init__(self, stdin_fd: int, stdout_fd: int, stderr_fd: int, stop_ev: threading.Event, events: list[Any], handler: Any) -> None:
        self._in, self._out, self._err = os.dup(stdin_fd), os.dup(stdout_fd), os.dup(stderr_fd)
        self._stop, self._events, self._handler, self.returncode = stop_ev, events, handler, None
        self._thr = threading.Thread(target=self._run, daemon=True)
        self._thr.start()

    def _run(self) -> None:
        try:
            os.write(self._out, gov1_oci_container_runner.PREMASK_BANNER)
            sec = os.read(self._in, 1)
            os.write(self._out, gov1_oci_container_runner.READY_BANNER)
            hdr = os.read(self._in, 5)
            if not hdr:
                self._events.append(("eof_before_go", sec))
                self.returncode = 0
                return
            rem, chunks = int.from_bytes(hdr[1:5], "big"), []
            while rem > 0 and (ch := os.read(self._in, rem)):
                chunks.append(ch)
                rem -= len(ch)
            spec = loads_strict(b"".join(chunks).decode("utf-8"))
            self._events.append(("go", sec, spec))
            self.returncode = self._handler(spec, self._out, self._err, self._stop)
        except BrokenPipeError:
            self.returncode = 141
        finally:
            for fd in (self._in, self._out, self._err):
                os.close(fd)

    def poll(self) -> int | None: return self.returncode
    def wait(self, timeout: float | None = None) -> int:
        self._thr.join(timeout=timeout)
        return 0 if self.returncode is None else self.returncode
    def kill(self) -> None:
        self._stop.set()
        self._thr.join(timeout=2.0)

def _make_portable_hooks(comp_spec: gov1_oci_image.CompositeOciBundleSpec, handler: Any, *, usage_fn: Any = None, rb_mutator: Any = None, on_spawn: Any = None, clock_fn: Any = None) -> tuple[gov1_oci_supervisor.RuncSubrunHooks, list[Any]]:
    events: list[Any] = []
    stops: dict[str, threading.Event] = {}
    clk_ns = [1_000_000_000]

    def _spawn(cmd: Any, *, stdin_fd: int, stdout_fd: int, stderr_fd: int, pid_file: Path, bundle_dir: Path, lease: gov1_oci_readback.CgroupV2Lease) -> _PipeContainerSim:
        if on_spawn is not None:
            on_spawn()
        events.append(("spawn", list(cmd), (bundle_dir / "config.json").is_file()))
        pid_file.write_text("4242\n", encoding="utf-8")
        ev = threading.Event()
        stops[lease.instance_id] = ev
        return _PipeContainerSim(stdin_fd, stdout_fd, stderr_fd, ev, events, handler)

    def _readback(*, container_pid: int, lease: Any, composite_spec: Any, bundle_trees: Any, expect_seccomp: bool, seccomp_profile: Any) -> gov1_oci_readback.LiveContainerReadback:
        events.append(("readback", container_pid, expect_seccomp))
        rb = {"profile_id": gov1_sandbox.SANDBOX_PROFILE_ID, "runtime_kind": "oci", "platform": "linux/amd64", "rootfs_read_only": True, "oci_image_digest": composite_spec.oci_image_digest, "runner_binary_digest": composite_spec.runner_binary_digest, "exact_environment": dict(gov1_7a_negative._EXACT_ENV), "namespaces": list(gov1_7a_negative._EXACT_NAMESPACES), "read_only_mounts": list(gov1_7a_negative._EXACT_RO_MOUNTS), "fresh_tmpfs_mounts": list(gov1_7a_negative._EXACT_TMPFS_MOUNTS), "masked_empty_mounts": list(gov1_7a_negative._EXACT_MASKED_MOUNTS), "host_bind_mounts_forbidden": True, "all_capabilities_dropped": True, "no_new_privs": True, "inherited_fds_above_2_closed": True, "seccomp_profile_digest": composite_spec.seccomp_profile_digest, "effective_writable_mounts": ["/tmp"], "seccomp_enforced_before_entry": expect_seccomp, "network_absent": True, "loopback_absent": True}
        lim = gov1_7a_negative._validate_resource_limits_dict({"profile_version": gov1_sandbox.SANDBOX_RESOURCES_VERSION, "cgroup_version": 2, "cpu_max": {"quota_us": 100_000, "period_us": 100_000}, "cpu_time_limit_seconds": 120, "memory_max_bytes": 1_073_741_824, "memory_swap_max_bytes": 0, "pids_max": 32, "tmpfs_limits": {"/tmp": {"size_bytes": 268_435_456, "inodes_max": 4096, "mount_flags": ["nodev", "noexec", "nosuid"]}}, "rlimit_fsize_bytes": 67_108_864, "stdout_max_bytes": 8_388_608, "stderr_max_bytes": 8_388_608, "wall_clock_timeout_seconds": 300, "termination_grace_ms": 1000}, "lim")
        if rb_mutator is not None:
            rb_mutator(rb, lim)
        r_fd, w_fd = os.pipe()
        os.close(w_fd)
        return gov1_oci_readback.LiveContainerReadback(rb, lim, r_fd)

    def _harvest(*, lease: Any, tmp_fd: int, stdout_bytes: int, stderr_bytes: int) -> dict[str, int]:
        os.fstat(tmp_fd)
        events.append(("harvest", lease.instance_id, stdout_bytes, stderr_bytes))
        base = {"cpu_time_us": 1200, "memory_peak_bytes": 8_388_608, "pids_peak": 1, "tmpfs_peak_bytes": 0, "tmpfs_peak_inodes": 1, "max_file_bytes": 0, "stdout_bytes": stdout_bytes, "stderr_bytes": stderr_bytes, "oom_delta": 0, "oom_kill_delta": 0, "pids_max_delta": 0}
        return usage_fn(base, lease) if usage_fn is not None else base

    mono = clock_fn if clock_fn is not None else lambda: (clk_ns.__setitem__(0, clk_ns[0] + 5_000_000), clk_ns[0])[1]
    hooks = gov1_oci_supervisor.RuncSubrunHooks(
        spawn_runc=_spawn, seal_premask=lambda pid: events.append(("seal", pid)), readback_state=_readback, harvest_usage=_harvest,
        terminate_cgroup=lambda lease: (events.append(("terminate", lease.instance_id)), stops.get(lease.instance_id, threading.Event()).set(), True)[2],
        delete_runc=lambda cmd: events.append(("delete", list(cmd))),
        cleanup_bundle=lambda b_dir: (events.append(("cleanup", b_dir.name)), gov1_oci_image.cleanup_runc_bundle_trees(b_dir))[1],
        monotonic_ns=mono,
    )
    return hooks, events

def test_task3_ast_purity_budgets_and_live_prereq_fail_hard() -> None:
    sup_path = REPO_ROOT / "tools" / "governance" / "gov1_oci_supervisor.py"
    for path, budget, is_gov in ((sup_path, 580, True), (Path(__file__), 650, False)):
        src = path.read_text(encoding="utf-8")
        assert len(src.splitlines()) <= budget, f"{path.name} has {len(src.splitlines())} lines > {budget}"
        tree = ast.parse(src, filename=str(path))
        if is_gov:
            assert [n for n in ast.walk(tree) if isinstance(n, ast.Assert)] == []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                assert (node.end_lineno or node.lineno) - node.lineno + 1 < 50, f"{path.name}:{node.name}"
            elif is_gov and isinstance(node, ast.Import):
                roots = {a.name.split(".")[0] for a in node.names}
                assert "smart_ads" not in roots and not (roots & _FORBIDDEN_NET)
            elif is_gov and isinstance(node, ast.ImportFrom):
                root = (node.module or "").split(".")[0]
                assert root != "smart_ads" and root not in _FORBIDDEN_NET
    assert len(Path(__file__).read_text(encoding="utf-8").splitlines()) <= 380
    assert _require_live_oci_prereqs(env={}) is None and _require_live_oci_prereqs(env={"SMART_ADS_LIVE_OCI_TESTS": "0"}) is None
    with pytest.raises(Failed, match="SMART_ADS_BASE_OCI_DIR"):
        _require_live_oci_prereqs(env={"SMART_ADS_LIVE_OCI_TESTS": "1"})
    with pytest.raises(Failed, match="ineligible"):
        _require_live_oci_prereqs(env={"SMART_ADS_LIVE_OCI_TESTS": "1", "SMART_ADS_BASE_OCI_DIR": "/tmp/x"}, probe_fn=lambda **_k: {"eligible": False, "reasons": ["euid_not_root"]})

def test_build_runc_oci_config_json_exact_contract(tmp_path: Path) -> None:
    trees = {"rootfs": tmp_path / "r", "app": tmp_path / "a", "fixtures": tmp_path / "f"}
    cfg = gov1_oci_supervisor.build_runc_oci_config_json(cgroup_rel_path="/smart_ads_7a/i1", bundle_trees=trees, process_args=["/usr/local/bin/python3.12", "-I", "-B", "-S", "/app/runner.py"])
    assert cfg["ociVersion"] == "1.0.2" and cfg["hostname"] == "smart-ads-7a" and cfg["root"] == {"path": str(trees["rootfs"]), "readonly": True}
    proc = cfg["process"]
    assert proc["terminal"] is False and proc["user"] == {"uid": 1, "gid": 1} and proc["cwd"] == "/tmp" and proc["noNewPrivileges"] is True
    assert proc["rlimits"] == [{"type": "RLIMIT_CPU", "soft": 120, "hard": 125}, {"type": "RLIMIT_FSIZE", "soft": 67_108_864, "hard": 67_108_864}]
    assert proc["env"] == [f"{k}={v}" for k, v in sorted(gov1_7a_negative._EXACT_ENV.items())]
    assert all(proc["capabilities"][k] == [] for k in ("bounding", "effective", "inheritable", "permitted", "ambient"))
    mps = {m["destination"]: m for m in cfg["mounts"]}
    assert set(mps) == {"/proc", "/dev", "/app", "/fixtures", "/tmp", "/sys", "/home", "/run", "/var/run"}
    assert "size=268435456" in mps["/tmp"]["options"] and "nr_inodes=4096" in mps["/tmp"]["options"]
    lnx = cfg["linux"]
    assert lnx["cgroupsPath"] == "/smart_ads_7a/i1" and [n["type"] for n in lnx["namespaces"]] == list(gov1_7a_negative._EXACT_NAMESPACES)
    assert lnx["uidMappings"] == [{"containerID": 0, "hostID": 100000, "size": 2}] and lnx["maskedPaths"] == [] and lnx["readonlyPaths"] == []
    for bad_cg, bad_args in (("", ["p"]), ("rel/path", ["p"]), ("/ok", [])):
        with pytest.raises(ValueError):
            gov1_oci_supervisor.build_runc_oci_config_json(cgroup_rel_path=bad_cg, bundle_trees=trees, process_args=bad_args)

def test_subrun_pre_go_abort_clamping_priority_and_cleanup_order(tmp_path: Path, portable_oci_fixture: dict[str, Any]) -> None:
    comp_spec, cg_root = portable_oci_fixture["comp_spec"], tmp_path / "cg"
    cg_root.mkdir()
    (cg_root / "cgroup.controllers").write_text("cpu memory pids\n", encoding="utf-8")

    def _flood_or_rc(spec: dict[str, Any], out_fd: int, err_fd: int, stop_ev: threading.Event) -> int:
        if spec.get("fail_rc"):
            return 2
        target_fd, blk = (out_fd if spec.get("stream") == "stdout" else err_fd), b"Z" * 65536
        while not stop_ev.is_set():
            os.write(target_fd, blk)
        return 137

    hooks, events = _make_portable_hooks(comp_spec, _flood_or_rc)
    sup = gov1_oci_supervisor.LinuxRuncSealedOciSupervisor(composite_spec=comp_spec, work_dir=tmp_path / "w1", build_run_id="r1", cgroup_root=cg_root, hooks=hooks)
    assert sup.readback_sandbox_environment()["oci_image_digest"] == comp_spec.oci_image_digest and ("eof_before_go", b"\x01") in events
    events.clear()
    res_out = sup._run_container_task(task_spec={"kind": "neg", "case_id": "output_limit_enforced", "stream": "stdout"})
    res_err = sup._run_container_task(task_spec={"kind": "neg", "case_id": "output_limit_enforced", "stream": "stderr"})
    assert (res_out.usage["stdout_bytes"], res_out.termination["cause"], res_out.stdout_data) == (8_388_608, "stdout_limit", b"Z" * 8_388_608)
    assert (res_err.usage["stderr_bytes"], res_err.termination["cause"], res_err.stderr_data) == (8_388_608, "stderr_limit", b"Z" * 8_388_608)
    tags = [e[0] for e in events]
    assert tags.index("harvest") < tags.index("delete") < tags.index("cleanup")
    with pytest.raises(ValueError, match="exited non-zero"):
        sup._run_container_task(task_spec={"kind": "neg", "fail_rc": True})
    assert [e[0] for e in events[-3:]] == ["delete", "terminate", "cleanup"] and pytest.raises(ValueError, gov1_oci_supervisor._make_profile_ready_validator, None, expect_seccomp=True)
    bad_hooks, bad_ev = _make_portable_hooks(comp_spec, _flood_or_rc, rb_mutator=lambda rb_d, _l: rb_d.__setitem__("network_absent", False))
    bad_sup = gov1_oci_supervisor.LinuxRuncSealedOciSupervisor(composite_spec=comp_spec, work_dir=tmp_path / "w2", build_run_id="r2", cgroup_root=cg_root, hooks=bad_hooks)
    run_ctx = decomposition_governance.verified_run_context_identity(REPO_ROOT)["run_context_locator"]
    sbx_env = p1.sign_envelope(gov1_sandbox.build_sealed_sandbox_profile_envelope(migration_run_context_locator=run_ctx, oci_image_digest=comp_spec.oci_image_digest, runner_binary_digest=comp_spec.runner_binary_digest, seccomp_profile=portable_oci_fixture["seccomp"], issued_at_utc="2026-09-07T10:00:00Z", valid_from_utc="2026-01-01T00:00:00Z", valid_until_utc="2028-01-01T00:00:00Z", registry_locator=make_locator("smart_ads/key_authorization_registry/v1", b'{"k":1}'), signer_key_id=portable_oci_fixture["key_id"]), "SMART-ADS:SANDBOX:V1\n", portable_oci_fixture["priv_pem"])
    blocked = gov1_7a_runner.run_7a_hermetic_execution(wheel_bytes=portable_oci_fixture["wheel_bytes"], corpus_bytes=CORPUS_JSON.read_bytes(), sandbox_profile=sbx_env, seccomp_profile=portable_oci_fixture["seccomp"], resolved_d26_blobs=portable_oci_fixture["d26"], sandbox_pubkey_raw32=portable_oci_fixture["pub_raw32"], supervisor=bad_sup)
    assert blocked["status"] == "BLOCKED" and not [e for e in bad_ev if e[0] == "go"]
    assert gov1_oci_supervisor._detect_non_output_ceiling_cause(300_000, {"cpu_time_us": 120_000_000, "oom_kill_delta": 1, "pids_max_delta": 1, "max_file_bytes": 67_108_864, "tmpfs_peak_inodes": 4096}, b'{"sigxfsz":true}\n{"tmpfs_enospc":true}\n') == "wall_clock_watchdog"
    assert gov1_oci_supervisor._detect_non_output_ceiling_cause(100, {"cpu_time_us": 120_000_000, "oom_kill_delta": 1, "pids_max_delta": 1, "max_file_bytes": 0, "tmpfs_peak_inodes": 1}, b"") == "cpu_time_limit"

def _sim_neg_and_7a_container(fx: dict[str, Any]) -> tuple[Any, Any, list[tuple[str, int]]]:
    active_case: list[tuple[str, int]] = [("", 0)]
    corpus_doc = loads_strict(CORPUS_JSON.read_text(encoding="utf-8"))
    reducer = gov1_7a_runner.load_isolated_pinned_meta_reducer(fx["d26"])

    def _handler(spec: dict[str, Any], out_fd: int, err_fd: int, stop_ev: threading.Event) -> int:
        if spec["kind"] == "neg":
            cid, s_idx = spec["case_id"], spec.get("subrun_index", 0)
            active_case[0] = (cid, s_idx)
            if cid in _DENIAL_OBS:
                os.write(out_fd, canonicalize(_DENIAL_OBS[cid]) + b"\n")
                return 0
            if cid == "output_limit_enforced":
                fd = out_fd if s_idx == 0 else err_fd
                while not stop_ev.is_set():
                    os.write(fd, b"A" * 65536)
                return 137
            if cid in ("file_size_limit_enforced", "tmpfs_limit_enforced"):
                os.write(out_fd, b'{"sigxfsz":true}\n' if cid == "file_size_limit_enforced" else b'{"tmpfs_enospc":true}\n')
            stop_ev.wait(timeout=2.0)
            return 137
        c = [x for x in corpus_doc["cases"] if x["case_id"] == spec["case_id"]][0]
        active_case[0] = ("pos_7a", 0)
        reg_st, inv_p = fx["reg_state"], fx["inv_pair"]
        reg_fix = gov1_7a_certification.build_canonical_regression_fixture(reg_st.locator.content_digest)
        adm, adm_loc = gov1_7a_certification.recompute_fixture_7a_admission(collection_request=c["collection_request"], admission_id=c["admission_id"], clock_attestation=c["clock_reading"]["attestation"], configured_max_uncertainty_ms=c["clock_reading"]["configured_max_uncertainty_ms"], timezone_snapshot=corpus_doc["timezone_snapshot"], registry_snapshot_locator=reg_st.locator.to_dict(), registry_snapshot=reg_st.snapshot.to_dict(), driver_contract_locator=reg_st.driver_contract_locator.to_dict(), driver_contract=reg_st.driver_contract.to_dict(), sealed_sandbox_profile_locator=spec["sealed_sandbox_profile_locator"], regression_fixture_locator=make_locator("smart_ads/regression_fixture/v1", canonicalize(reg_fix)))
        hr, cmap = c["http_response"], {p["raw_campaign_id"]: p["resource_ref"] for p in corpus_doc["verified_campaign_pairs"]}
        batch = gov1_7a_certification.transform_pipeboard_response_to_batch_dict(admitted=adm, private_object_id="act_5544332211", known_campaign_map=cmap, scoped_resource_refs=frozenset(u.resource_ref for u in inv_p[1].expected_resources), retrieval_context=c["retrieval_context"], network_ok=hr["network_ok"], http_status=hr["http_status"], headers=[(h[0], h[1]) for h in hr["headers"]], body_chunks=[hr["body_utf8"].encode("utf-8")], reducer=reducer)
        comp = gov1_7a_certification.recompute_collection_completeness_dict(expected_resources=[u.to_dict() for u in inv_p[1].expected_resources], required_metrics=adm["canonical_query_contract"]["metric_semantic_refs"], metric_source_mappings=reg_st.driver_contract.metric_source_mappings, batch_dict=batch, admitted_dict=adm)
        os.write(out_fd, canonicalize({"case_id": c["case_id"], "admitted_collection_digest": adm_loc["content_digest"], "observation_batch": batch, "observed_completeness_status": comp["status"], "normalized_fact_set_digest": comp["normalized_fact_set_digest"]}) + b"\n")
        return 0

    def _usage(base: dict[str, int], _lease: Any) -> dict[str, int]:
        overrides: dict[str, dict[str, int]] = {"cpu_limit_enforced": {"cpu_time_us": 120_050_000}, "memory_limit_enforced": {"memory_peak_bytes": 1_073_741_824, "oom_delta": 1, "oom_kill_delta": 1}, "pids_limit_enforced": {"pids_peak": 32, "pids_max_delta": 1}, "file_size_limit_enforced": {"max_file_bytes": 67_108_864, "tmpfs_peak_bytes": 67_108_864}, "tmpfs_limit_enforced": {"tmpfs_peak_inodes": 4096}}
        return {**base, **overrides.get(active_case[0][0], {})}

    return _handler, _usage, active_case

def test_supervisor_negative_suite_and_7a_corpus_end_to_end(tmp_path: Path, portable_oci_fixture: dict[str, Any]) -> None:
    fx, cg_root = portable_oci_fixture, tmp_path / "cg"
    cg_root.mkdir()
    (cg_root / "cgroup.controllers").write_text("cpu memory pids\n", encoding="utf-8")
    handler, usage_fn, active_case = _sim_neg_and_7a_container(fx)
    clk = [1_000_000_000]
    hooks, _ = _make_portable_hooks(fx["comp_spec"], handler, usage_fn=usage_fn, on_spawn=lambda: active_case.__setitem__(0, ("", 0)), clock_fn=lambda: (clk.__setitem__(0, clk[0] + (300_005_000_000 if active_case[0][0] == "wall_clock_limit_enforced" else 5_000_000)), clk[0])[1])
    run_ctx = decomposition_governance.verified_run_context_identity(REPO_ROOT)["run_context_locator"]
    until_utc = (datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=400)).strftime("%Y-%m-%dT%H:%M:%SZ")
    sbx_cand = gov1_sandbox.build_sealed_sandbox_profile_candidate(migration_run_context_locator=run_ctx, oci_image_digest=fx["comp_spec"].oci_image_digest, runner_binary_digest=fx["comp_spec"].runner_binary_digest, seccomp_profile=fx["seccomp"], issued_at_utc="2026-09-07T10:00:00Z", valid_from_utc="2026-01-01T00:00:00Z", valid_until_utc=until_utc)
    sbx_env = p1.sign_envelope(gov1_sandbox.build_sealed_sandbox_profile_envelope(migration_run_context_locator=run_ctx, oci_image_digest=fx["comp_spec"].oci_image_digest, runner_binary_digest=fx["comp_spec"].runner_binary_digest, seccomp_profile=fx["seccomp"], issued_at_utc="2026-09-07T10:00:00Z", valid_from_utc="2026-01-01T00:00:00Z", valid_until_utc=until_utc, registry_locator=make_locator("smart_ads/key_authorization_registry/v1", b'{"reg":1}'), signer_key_id=fx["key_id"]), "SMART-ADS:SANDBOX:V1\n", fx["priv_pem"])
    sbx_loc = fx["store"].put(sbx_env)
    sup = gov1_oci_supervisor.LinuxRuncSealedOciSupervisor(composite_spec=fx["comp_spec"], work_dir=tmp_path / "work", build_run_id="run-t3", seccomp_profile=fx["seccomp"], cgroup_root=cg_root, hooks=hooks)
    assert isinstance(sup, gov1_7a_runner.SealedOciSupervisorPort)
    sup.set_sealed_sandbox_profile_locator(sbx_loc)
    neg_cases = sup.execute_negative_security_suite(wheel_digest=fx["inspection"]["wheel_digest"], sandbox_profile_payload=sbx_cand["payload"])
    assert len(neg_cases) == 17 and sum(len(c["runs"]) for c in neg_cases) == 18
    now_utc = datetime.datetime.now(datetime.UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")
    prov_cand = gov1_wheel.build_wheel_build_provenance_candidate(migration_run_context_locator=run_ctx, build_run_id="run-t3", built_at_utc="2026-09-07T10:00:05Z", snapshot=fx["snapshot"], source_date_epoch=gov1_wheel.DEFAULT_SOURCE_DATE_EPOCH, schema_bundle_digest=fx["inspection"]["schema_bundle_digest"], wheel_bytes=fx["wheel_bytes"])
    neg_cand = gov1_7a_negative.build_negative_security_test_report_candidate(migration_run_context_locator=run_ctx, sealed_sandbox_profile_candidate_ref=gov1_sandbox.build_local_candidate_ref(sbx_cand), wheel_build_provenance_candidate_ref=gov1_sandbox.build_local_candidate_ref(prov_cand), build_run_id="run-t3", executed_at_utc=now_utc, source_commit_sha=fx["snapshot"].commit_sha, build_backend_digest=fx["snapshot"].build_backend_digest, schema_bundle_digest=fx["inspection"]["schema_bundle_digest"], wheel_digest=fx["inspection"]["wheel_digest"], oci_image_digest=fx["comp_spec"].oci_image_digest, runner_binary_digest=fx["comp_spec"].runner_binary_digest, declared_resource_limits=sbx_cand["payload"]["resource_limits"], cases=neg_cases)
    assert gov1_7a_negative.verify_negative_security_test_report(neg_cand, sandbox_profile=sbx_cand, wheel_provenance=prov_cand, wheel_bytes=fx["wheel_bytes"])["mode"] == "candidate"
    pos_res = gov1_7a_runner.run_7a_hermetic_execution(wheel_bytes=fx["wheel_bytes"], corpus_bytes=CORPUS_JSON.read_bytes(), sandbox_profile=sbx_env, seccomp_profile=fx["seccomp"], resolved_d26_blobs=fx["d26"], sandbox_pubkey_raw32=fx["pub_raw32"], supervisor=sup)
    assert pos_res["status"] == "EXECUTED" and pos_res["execution"]["statuses"] == ["complete", "failed", "partial", "partial"]
    assert pos_res["execution"]["cases"][0]["started_at_utc"] == "2026-09-07T10:00:11Z" and pos_res["execution"]["cases"][0]["ended_at_utc"] == "2026-09-07T10:00:12Z"
    bound_cand = gov1_wheel.build_wheel_boundary_report_candidate(migration_run_context_locator=run_ctx, build_run_id="run-t3", verified_at_utc=now_utc, source_commit_sha=fx["snapshot"].commit_sha, build_backend_digest=fx["snapshot"].build_backend_digest, wheel_build_provenance_candidate_ref=gov1_sandbox.build_local_candidate_ref(prov_cand), inspection=fx["inspection"])
    reg_st, pmap = fx["reg_state"], fx["prov_map"]
    cap_d = {"capability_ref": "cap:campaign-basic-v1", "resource_scope_ref": "scope:campaigns-active", "driver_id": "pipeboard_hosted", "driver_contract_locator": reg_st.driver_contract_locator.to_dict(), "driver_contract_digest": reg_st.driver_contract_locator.content_digest, "registry_snapshot_locator": reg_st.locator.to_dict(), "required_metrics": ["metric:clicks_v1", "metric:impressions_v1", "metric:spend_v1"]}
    ev_d = {"corpus_git_locator": pmap[gov1_7a_certification.CORPUS_GIT_PATH][0].to_dict(), "corpus_digest": gov1_7a_certification.digest(CORPUS_JSON.read_bytes()), "regression_fixture": gov1_7a_certification.build_canonical_regression_fixture(reg_st.locator.content_digest), "cases": pos_res["execution"]["cases"]}
    p_l, a_l, m_l = [gov1_7a_certification.sort_git_provenance_locators([pmap[k][0].to_dict() for k in grp]) for grp in (gov1_7a_certification.PARSER_ARTIFACT_PATHS, gov1_7a_certification.ADAPTER_ARTIFACT_PATHS, gov1_7a_certification.MAPPING_ARTIFACT_PATHS)]
    cert_cand = gov1_7a_certification.build_certification_7a_record_candidate(migration_run_context_locator=run_ctx, sealed_sandbox_profile_candidate_ref=gov1_sandbox.build_local_candidate_ref(sbx_cand), wheel_build_provenance_candidate_ref=gov1_sandbox.build_local_candidate_ref(prov_cand), wheel_boundary_report_candidate_ref=gov1_sandbox.build_local_candidate_ref(bound_cand), negative_security_test_report_candidate_ref=gov1_sandbox.build_local_candidate_ref(neg_cand), build_run_id="run-t3", certified_at_utc=now_utc, source_commit_sha=fx["snapshot"].commit_sha, build_backend_digest=fx["snapshot"].build_backend_digest, schema_bundle_digest=fx["inspection"]["schema_bundle_digest"], wheel_digest=fx["inspection"]["wheel_digest"], resource_mapping_contract_digest=reg_st.snapshot.resource_mapping_contract_digest, capability=cap_d, parser_artifact_locators=p_l, parser_code_digest=gov1_7a_certification.compute_parser_code_digest([pmap[k][1].to_dict() for k in gov1_7a_certification.PARSER_ARTIFACT_PATHS]), adapter_artifact_locators=a_l, adapter_code_digest=gov1_7a_certification.compute_adapter_code_digest([pmap[k][1].to_dict() for k in gov1_7a_certification.ADAPTER_ARTIFACT_PATHS]), mapping_artifact_locators=m_l, mapping_rules_digest=gov1_7a_certification.compute_mapping_rules_digest([pmap[k][1].to_dict() for k in gov1_7a_certification.MAPPING_ARTIFACT_PATHS], reg_st.driver_contract.metric_source_mappings), fixture_evidence=ev_d)
    assert gov1_7a_certification.verify_certification_7a_replay_bytes(cert_cand, store=fx["store"], wheel_bytes=fx["wheel_bytes"], corpus_bytes=CORPUS_JSON.read_bytes(), resolved_git_blobs=fx["git_blobs"], resolved_d26_blobs=fx["d26"], sandbox_profile=sbx_cand, wheel_provenance=prov_cand, wheel_boundary_report=bound_cand, negative_security_report=neg_cand, sealed_sandbox_profile_store_locator=sbx_loc)["mode"] == "candidate"
    with pytest.raises(ValueError, match="parity|mismatch|reducer"):
        sup.execute_7a_corpus(wheel_bytes=fx["wheel_bytes"], corpus_bytes=CORPUS_JSON.read_bytes(), sandbox_profile_payload=sbx_cand["payload"], resolved_d26_blobs=fx["d26"], reducer=lambda _m: [])
    for bad_kw in ({"wheel_bytes": bytearray(fx["wheel_bytes"])}, {"corpus_bytes": bytearray(CORPUS_JSON.read_bytes())}, {"sandbox_profile_payload": {}}):
        with pytest.raises(ValueError):
            sup.execute_7a_corpus(**{"wheel_bytes": fx["wheel_bytes"], "corpus_bytes": CORPUS_JSON.read_bytes(), "sandbox_profile_payload": sbx_cand["payload"], "resolved_d26_blobs": fx["d26"], "reducer": lambda _m: [], **bad_kw})  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="d26 mismatch"):
        sup._read_sealed_bundle_fixtures({**fx["d26"], "scripts/pipeboard_limits.py": b"tampered"})

def test_oci_isolated_wheel_probe_runner_portable(tmp_path: Path, portable_oci_fixture: dict[str, Any]) -> None:
    fx, cg_root = portable_oci_fixture, tmp_path / "cg"
    cg_root.mkdir()
    (cg_root / "cgroup.controllers").write_text("cpu memory pids\n", encoding="utf-8")

    def _probe_handler(spec: dict[str, Any], out_fd: int, _err_fd: int, _stop: threading.Event) -> int:
        if spec["kind"] == "pep517_build":
            payload = {"wheel_name": gov1_wheel.EXPECTED_WHEEL_FILENAME, "wheel_b64": base64.b64encode(fx["wheel_bytes"]).decode("ascii")}
        elif len(spec["probe_argv"]) == 3:
            payload = {"packaged_modules": fx["inspection"]["packaged_modules"], "schema_bundle_digest": fx["inspection"]["schema_bundle_digest"]}
        else:
            payload = {k: fx["mcp_exec"][k] for k in ("schema_bundle_digest", "allowed_methods", "body_64k_boundary_verified", "cases")}
        os.write(out_fd, canonicalize(payload) + b"\n")
        return 0

    hooks, events = _make_portable_hooks(fx["comp_spec"], _probe_handler)
    bm = fx["base_meta"]
    runner = gov1_oci_supervisor.OciIsolatedWheelProbeRunner(base_oci_dir=fx["base_dir"], work_dir=tmp_path / "probe_work", cgroup_root=cg_root, hooks=hooks, expected_manifest_digest=bm["manifest_digest"], expected_config_digest=bm["config_digest"], expected_layer_digests=bm["layer_digests"], expected_diff_ids=bm["diff_ids"])
    rt = MemoryProtectedRuntime({"k": 1}, {}, {})
    pins = Gov1InstallationPins(configuration_digest=digest(rt.config), installation_authority="synthetic-gov1-installation", cell_id="c", head_register="h", checkpoint_register="ck", owner_principal="principal:r", owner_tenant="t", pinned_run_context_locator=RUN_CONTEXT_LOCATOR)
    assert runner.os_isolated is True and gov1_convergence.Gov1AdmissionVerifier(rt, pins, fx["store"], ADR_PATH.read_bytes(), isolated_probe_runner=runner)._require_os_isolated_probe_runner() is runner
    members = frozenset(e["path"] for e in fx["inspection"]["sorted_record_entries"])
    assert runner.run_wheel_import_probe(wheel_bytes=fx["wheel_bytes"], expected_member_paths=members, expected_modules=fx["inspection"]["packaged_modules"])["schema_bundle_digest"] == fx["inspection"]["schema_bundle_digest"]
    mcp_out = runner.run_mcp_matrix_probe(wheel_bytes=fx["wheel_bytes"], expected_member_paths=members, expected_schema_bundle_digest=fx["inspection"]["schema_bundle_digest"])
    assert mcp_out["body_64k_boundary_verified"] is True and len(mcp_out["cases"]) == 11
    b_site = tmp_path / "b_site"
    gov1_wheel.verify_build_runtime_environment(fx["snapshot"].files["uv.lock"], target_backend_site_dir=b_site)
    assert runner.run_pep517_wheel_build(snapshot_files=fx["snapshot"].files, snapshot_modes=fx["snapshot"].modes, verified_backend_site_dir=b_site, source_date_epoch=gov1_wheel.DEFAULT_SOURCE_DATE_EPOCH) == (gov1_wheel.EXPECTED_WHEEL_FILENAME, fx["wheel_bytes"])
    assert [e[1] for e in events if e[0] == "go"] == [b"\x01", b"\x01", b"\x03"]
    with pytest.raises(ValueError):
        runner.run_wheel_import_probe(wheel_bytes=fx["wheel_bytes"], expected_member_paths=frozenset({"only.py"}), expected_modules=fx["inspection"]["packaged_modules"])
    with pytest.raises(ValueError):
        runner.run_pep517_wheel_build(snapshot_files=fx["snapshot"].files, snapshot_modes={**fx["snapshot"].modes, "pyproject.toml": "120000"}, verified_backend_site_dir=b_site, source_date_epoch=gov1_wheel.DEFAULT_SOURCE_DATE_EPOCH)
    sym_runner = gov1_oci_supervisor.OciIsolatedWheelProbeRunner(base_oci_dir=fx["base_dir"], work_dir=tmp_path / "sym_work", cgroup_root=cg_root, hooks=hooks, expected_manifest_digest=bm["manifest_digest"], expected_config_digest=bm["config_digest"], expected_layer_digests=bm["layer_digests"], expected_diff_ids=bm["diff_ids"])
    os.symlink(tmp_path / "missing_target", tmp_path / "sym_work" / "stage7-probe-oci")
    with pytest.raises(ValueError, match="symlink"):
        sym_runner._ensure_probe_composite_spec()

@pytest.fixture(scope="module")
def live_oci_suite_result() -> dict[str, Any] | None:
    base_oci_dir = _require_live_oci_prereqs()
    if base_oci_dir is None:
        return None
    work_root = Path(tempfile.mkdtemp(prefix="smart-ads-live-oci-", dir="/tmp"))
    os.chmod(work_root, 0o755)
    try:
        probe_runner = gov1_oci_supervisor.OciIsolatedWheelProbeRunner(base_oci_dir=base_oci_dir, work_dir=work_root / "stage7")
        whl_path, snap = gov1_wheel.build_reproducible_wheel(REPO_ROOT, work_root / "wheel_out", probe_runner=probe_runner)
        insp, mcp_exec = gov1_wheel.inspect_wheel_boundary(whl_path, probe_runner=probe_runner), gov1_mcp.execute_mcp_rejection_matrix_on_wheel(whl_path, probe_runner=probe_runner)
        d26, git_blobs = _decode_d26(), gov1_7a_certification.resolve_7a_smart_ads_git_blobs(REPO_ROOT, snap.commit_sha)
        store = Store(work_root / "store")
        reg_state, _, inv_pair = _stage_leaf_envelopes_in_store(store, commit_sha=snap.commit_sha, git_blobs=git_blobs, d26_blobs=d26)
        rctx = {"snapshot": reg_state.snapshot.to_dict(), "snapshot_locator": reg_state.locator.to_dict(), "driver_contract": reg_state.driver_contract.to_dict(), "driver_contract_locator": reg_state.driver_contract_locator.to_dict(), "expected_inventory": inv_pair[1].to_dict(), "expected_inventory_locator": inv_pair[0].to_dict()}
        seccomp = gov1_sandbox.build_default_7a_seccomp_profile()
        comp = gov1_oci_image.build_composite_7a_oci_layout(base_oci_dir=base_oci_dir, output_layout_dir=work_root / "comp_oci", wheel_bytes=whl_path.read_bytes(), corpus_bytes=CORPUS_JSON.read_bytes(), replay_context_obj=rctx, resolved_d26_blobs=d26, seccomp_profile=seccomp, runner_py_bytes=gov1_oci_container_runner.CONTAINER_RUNNER_SOURCE.encode("utf-8"), venv_probe_bootstrap_bytes=gov1_oci_container_runner.VENV_PROBE_BOOTSTRAP_SOURCE.encode("utf-8"))
        priv_pem = work_root / "sbx.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "Ed25519", "-out", str(priv_pem)], check=True, capture_output=True)
        pub_raw32 = p1.raw_public_key_from_pem(priv_pem)
        run_ctx = decomposition_governance.verified_run_context_identity(REPO_ROOT)["run_context_locator"]
        until_utc = (datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=400)).strftime("%Y-%m-%dT%H:%M:%SZ")
        sbx_env = p1.sign_envelope(gov1_sandbox.build_sealed_sandbox_profile_envelope(migration_run_context_locator=run_ctx, oci_image_digest=comp.oci_image_digest, runner_binary_digest=comp.runner_binary_digest, seccomp_profile=seccomp, issued_at_utc="2026-09-07T10:00:00Z", valid_from_utc="2026-01-01T00:00:00Z", valid_until_utc=until_utc, registry_locator=make_locator("smart_ads/key_authorization_registry/v1", b'{"r":1}'), signer_key_id=p1.key_id_for(pub_raw32)), "SMART-ADS:SANDBOX:V1\n", priv_pem)
        sbx_loc = store.put(sbx_env)
        sbx_payload = {k: v for k, v in sbx_env.items() if k not in {"$schema", "integrity"}}
        sup = gov1_oci_supervisor.LinuxRuncSealedOciSupervisor(composite_spec=comp, work_dir=work_root / "sup", build_run_id="live-oci-t3", seccomp_profile=seccomp, sealed_sandbox_profile_locator=sbx_loc)
        neg_cases = sup.execute_negative_security_suite(wheel_digest=insp["wheel_digest"], sandbox_profile_payload=sbx_payload)
        pos_res = gov1_7a_runner.run_7a_hermetic_execution(wheel_bytes=whl_path.read_bytes(), corpus_bytes=CORPUS_JSON.read_bytes(), sandbox_profile=sbx_env, seccomp_profile=seccomp, resolved_d26_blobs=d26, sandbox_pubkey_raw32=pub_raw32, supervisor=sup)
        return {"inspection": insp, "mcp_exec": mcp_exec, "neg_cases": neg_cases, "pos_res": pos_res}
    finally:
        gov1_oci_image.cleanup_runc_bundle_trees(work_root)

def test_live_linux_amd64_oci_stage7_probes_negative_suite_and_7a_corpus(live_oci_suite_result: dict[str, Any] | None) -> None:
    if live_oci_suite_result is None:
        return
    assert live_oci_suite_result["inspection"]["isolated_venv_import_passed"] is True
    assert live_oci_suite_result["mcp_exec"]["body_64k_boundary_verified"] is True
    assert len(live_oci_suite_result["neg_cases"]) == 17 and sum(len(c["runs"]) for c in live_oci_suite_result["neg_cases"]) == 18
    assert live_oci_suite_result["pos_res"]["status"] == "EXECUTED"
    assert live_oci_suite_result["pos_res"]["execution"]["statuses"] == ["complete", "failed", "partial", "partial"]
