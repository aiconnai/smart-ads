"""Portable contract tests and live Linux amd64 root runc tests for `gov1_oci_supervisor`."""
from __future__ import annotations

import ast, base64, datetime, errno, functools, gzip, os, stat, subprocess, sys, tempfile, threading, time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from _pytest.outcomes import Failed
import pytest

from tests.governance.test_gov1_7a_verifiers import _stage_leaf_envelopes_in_store
from tests.governance.test_gov1_convergence import ADR_PATH, Gov1InstallationPins, MemoryProtectedRuntime, RUN_CONTEXT_LOCATOR
from tests.governance.test_gov1_oci_seccomp_and_bundle import _build_synthetic_live_proc_and_bundle, _fd_is_open, _make_tar_gz_layer, _write_synthetic_oci_layout
from tools.governance import (
    cli, decomposition_governance, gov1_7a_certification, gov1_7a_negative, gov1_7a_runner, gov1_convergence, gov1_mcp,
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
        events.append(("spawn", list(cmd), (bundle_dir / "config.json").is_file(), bundle_dir))
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

def test_task3_and_task4_ast_purity_budgets_and_live_prereq_fail_hard() -> None:
    sup_path = REPO_ROOT / "tools" / "governance" / "gov1_oci_supervisor.py"
    cli_oci_path = REPO_ROOT / "tools" / "governance" / "gov1_cli_oci.py"
    for path, budget, is_gov in ((sup_path, 615, True), (cli_oci_path, 550, True), (Path(__file__), 700, False)):
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
    cli_tree = ast.parse((REPO_ROOT / "tools" / "governance" / "cli.py").read_text(encoding="utf-8"))
    bp = [n for n in ast.walk(cli_tree) if isinstance(n, ast.FunctionDef) and n.name == "build_parser"][0]
    assert (bp.end_lineno or bp.lineno) - bp.lineno + 1 < 20
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

def _stage_d26_blobs_dir(dest: Path, d26: Mapping[str, bytes]) -> Path:
    dest.mkdir(parents=True, exist_ok=True)
    for role, rel_path, _, _ in gov1_7a_runner.PINNED_PIPEBOARD_D26_SPECS:
        (dest / f"{role}__{Path(rel_path).name}").write_bytes(d26[rel_path])
    return dest

def _verify_conv_cli_argv(out_dir: Path, blobs_dir: Path) -> list[str]:
    c_dir = out_dir / "candidates"
    return [
        "verify-gov1-convergence-record", "--in", str(c_dir / "gov1_convergence_record.candidate.json"),
        "--store-root", str(out_dir / "ephemeral-store"), "--wheel", str(out_dir / "wheel" / gov1_wheel.EXPECTED_WHEEL_FILENAME),
        "--corpus", str(CORPUS_JSON), "--repo", str(REPO_ROOT), "--seccomp-profile", str(out_dir / "seccomp_profile.json"),
        "--legacy-blobs-dir", str(blobs_dir), "--sandbox-profile", str(c_dir / "sealed_sandbox_profile.candidate.json"),
        "--provenance", str(c_dir / "wheel_build_provenance.candidate.json"),
        "--boundary-report", str(c_dir / "wheel_boundary_report.candidate.json"),
        "--mcp-rejection-report", str(c_dir / "mcp_rejection_matrix_report.candidate.json"),
        "--negative-report", str(c_dir / "negative_security_test_report.candidate.json"),
        "--certification-7a-record", str(c_dir / "certification_7a_record.candidate.json"),
    ]

def _make_pipeline_sim_hooks(fx: dict[str, Any], *, crash_on_neg: bool = False) -> gov1_oci_supervisor.RuncSubrunHooks:
    neg_handler, usage_fn, active_case = _sim_neg_and_7a_container(fx)
    corpus_doc = loads_strict(CORPUS_JSON.read_text(encoding="utf-8"))
    reducer = gov1_7a_runner.load_isolated_pinned_meta_reducer(fx["d26"])
    events_ref: list[list[Any]] = [[]]
    clk = [1_000_000_000]

    def _handler(spec: dict[str, Any], out_fd: int, err_fd: int, stop_ev: threading.Event) -> int:
        if spec["kind"] == "pep517_build":
            os.write(out_fd, canonicalize({"wheel_name": gov1_wheel.EXPECTED_WHEEL_FILENAME, "wheel_b64": base64.b64encode(fx["wheel_bytes"]).decode("ascii")}) + b"\n")
            return 0
        if spec["kind"] == "venv_probe":
            payload = {"packaged_modules": fx["inspection"]["packaged_modules"], "schema_bundle_digest": fx["inspection"]["schema_bundle_digest"]} if len(spec["probe_argv"]) == 3 else {k: fx["mcp_exec"][k] for k in ("schema_bundle_digest", "allowed_methods", "body_64k_boundary_verified", "cases")}
            os.write(out_fd, canonicalize(payload) + b"\n")
            return 0
        if spec["kind"] == "neg":
            if crash_on_neg:
                return 9
            return neg_handler(spec, out_fd, err_fd, stop_ev)
        active_case[0] = ("pos_7a", 0)
        b_dir = [e[3] for e in events_ref[0] if e[0] == "spawn"][-1]
        rctx = loads_strict((b_dir / "oci_extracted/fixtures/replay_context_v1.json").read_text(encoding="utf-8"))
        c = [x for x in corpus_doc["cases"] if x["case_id"] == spec["case_id"]][0]
        reg_fix = gov1_7a_certification.build_canonical_regression_fixture(rctx["snapshot_locator"]["content_digest"])
        adm, adm_loc = gov1_7a_certification.recompute_fixture_7a_admission(collection_request=c["collection_request"], admission_id=c["admission_id"], clock_attestation=c["clock_reading"]["attestation"], configured_max_uncertainty_ms=c["clock_reading"]["configured_max_uncertainty_ms"], timezone_snapshot=corpus_doc["timezone_snapshot"], registry_snapshot_locator=rctx["snapshot_locator"], registry_snapshot=rctx["snapshot"], driver_contract_locator=rctx["driver_contract_locator"], driver_contract=rctx["driver_contract"], sealed_sandbox_profile_locator=spec["sealed_sandbox_profile_locator"], regression_fixture_locator=make_locator("smart_ads/regression_fixture/v1", canonicalize(reg_fix)))
        hr, cmap = c["http_response"], {p["raw_campaign_id"]: p["resource_ref"] for p in corpus_doc["verified_campaign_pairs"]}
        batch = gov1_7a_certification.transform_pipeboard_response_to_batch_dict(admitted=adm, private_object_id="act_5544332211", known_campaign_map=cmap, scoped_resource_refs=frozenset(u["resource_ref"] for u in rctx["expected_inventory"]["expected_resources"]), retrieval_context=c["retrieval_context"], network_ok=hr["network_ok"], http_status=hr["http_status"], headers=[(h[0], h[1]) for h in hr["headers"]], body_chunks=[hr["body_utf8"].encode("utf-8")], reducer=reducer)
        comp = gov1_7a_certification.recompute_collection_completeness_dict(expected_resources=rctx["expected_inventory"]["expected_resources"], required_metrics=adm["canonical_query_contract"]["metric_semantic_refs"], metric_source_mappings=rctx["driver_contract"]["metric_source_mappings"], batch_dict=batch, admitted_dict=adm)
        os.write(out_fd, canonicalize({"case_id": c["case_id"], "admitted_collection_digest": adm_loc["content_digest"], "observation_batch": batch, "observed_completeness_status": comp["status"], "normalized_fact_set_digest": comp["normalized_fact_set_digest"]}) + b"\n")
        return 0

    hooks, ev = _make_portable_hooks(fx["comp_spec"], _handler, usage_fn=usage_fn, on_spawn=lambda: active_case.__setitem__(0, ("", 0)), clock_fn=lambda: (clk.__setitem__(0, clk[0] + (300_005_000_000 if active_case[0][0] == "wall_clock_limit_enforced" else 5_000_000)), clk[0])[1])
    events_ref[0] = ev
    return hooks

def test_cli_probe_7a_oci_host_and_blocked_pipeline_fail_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    from tools.governance import gov1_cli_oci

    assert gov1_cli_oci.OCI_CLI_COMMANDS == frozenset({"probe-7a-oci-host", "run-etapa11-oci-candidates"})
    monkeypatch.setattr(gov1_cli_oci, "probe_7a_oci_host", lambda **_kw: {"status": "ELIGIBLE", "eligible": True, "reasons": []})
    out_ok = tmp_path / "probe_ok.json"
    assert cli.main(["probe-7a-oci-host", "--base-oci-dir", str(tmp_path), "--out", str(out_ok)]) == 0
    assert out_ok.read_bytes() == canonicalize({"status": "ELIGIBLE", "eligible": True, "reasons": []})
    assert loads_strict(capsys.readouterr().out.strip())["status"] == "ELIGIBLE"
    assert cli.main(["probe-7a-oci-host", "--out", str(out_ok)]) == 1
    capsys.readouterr()
    monkeypatch.setattr(gov1_cli_oci, "probe_7a_oci_host", lambda **_kw: {"status": "BLOCKED", "eligible": False, "reasons": ["euid_not_root"]})
    out_blk = tmp_path / "probe_blk.json"
    assert cli.main(["probe-7a-oci-host", "--out", str(out_blk)]) == 1
    assert loads_strict(capsys.readouterr().out.strip()) == {"eligible": False, "reasons": ["euid_not_root"], "status": "BLOCKED"}
    blobs_dir = _stage_d26_blobs_dir(tmp_path / "blobs", _decode_d26())
    cand_out = tmp_path / "blocked_out"
    assert cli.main(["run-etapa11-oci-candidates", "--repo", str(REPO_ROOT), "--base-oci-dir", str(tmp_path), "--out-dir", str(cand_out), "--legacy-blobs-dir", str(blobs_dir)]) == 1
    assert loads_strict(capsys.readouterr().out.strip())["status"] == "BLOCKED" and not cand_out.exists()
    assert cli.main(["run-etapa11-oci-candidates", "--repo", str(REPO_ROOT), "--base-oci-dir", str(tmp_path), "--out-dir", str(tmp_path / "bad"), "--legacy-repo", str(tmp_path), "--legacy-blobs-dir", str(blobs_dir)]) == 1
    capsys.readouterr()

def test_pipeline_ephemeral_d4_pem_cleanup_even_on_failure(tmp_path: Path, portable_oci_fixture: dict[str, Any]) -> None:
    from tools.governance import gov1_cli_oci

    seen_key_dirs: list[Path] = []
    with pytest.raises(RuntimeError, match="boom"):
        with gov1_cli_oci._ephemeral_d4_keyring("2028-01-01T00:00:00Z", key_root_parent=tmp_path) as (k_dir, keys):
            seen_key_dirs.append(k_dir)
            assert len(keys) == 12 and len(list(k_dir.glob("*.pem"))) == 12
            assert keys["independent_7a_verifier"][2] != keys["7a_verifier"][2]
            raise RuntimeError("boom")
    assert seen_key_dirs and not seen_key_dirs[0].exists() and list(tmp_path.rglob("*.pem")) == []
    cg_root = tmp_path / "cg"
    cg_root.mkdir()
    (cg_root / "cgroup.controllers").write_text("cpu memory pids\n", encoding="utf-8")
    blobs_dir = _stage_d26_blobs_dir(tmp_path / "blobs", portable_oci_fixture["d26"])
    crash_hooks = _make_pipeline_sim_hooks(portable_oci_fixture, crash_on_neg=True)
    with pytest.raises(ValueError, match="exited non-zero"):
        gov1_cli_oci.run_etapa11_oci_candidates_pipeline(repo_root=REPO_ROOT, base_oci_dir=portable_oci_fixture["base_dir"], out_dir=tmp_path / "fail_out", legacy_blobs_dir=blobs_dir, build_run_id="fail-run", verify_ephemeral_d4=True, cgroup_root=cg_root, host_probe_fn=lambda **_kw: {"status": "ELIGIBLE", "eligible": True, "reasons": []}, subrun_hooks=crash_hooks, base_oci_expectations=portable_oci_fixture["base_meta"], work_root_parent=tmp_path, key_root_parent=tmp_path)
    assert list(tmp_path.rglob("*.pem")) == [] and list(tmp_path.glob("smart-ads-etapa11-oci-*")) == []

def test_run_git_offline_fsmonitor_and_root_safe_directory(monkeypatch: pytest.MonkeyPatch) -> None:
    from tools.governance import decomposition_scope

    scope_tree = ast.parse((REPO_ROOT / "tools" / "governance" / "decomposition_scope.py").read_text(encoding="utf-8"))
    rgo = [n for n in ast.walk(scope_tree) if isinstance(n, ast.FunctionDef) and n.name == "run_git_offline"][0]
    assert (rgo.end_lineno or rgo.lineno) - rgo.lineno + 1 < 50
    real_euid = os.geteuid() if hasattr(os, "geteuid") else 1001
    real_run, seen = decomposition_scope.subprocess.run, []
    monkeypatch.setattr(decomposition_scope.subprocess, "run", lambda cmd, *a, **kw: (seen.append(list(cmd)), real_run(cmd, *a, **kw))[1])
    monkeypatch.setattr(decomposition_scope.os, "geteuid", lambda: 1001)
    decomposition_scope.run_git_offline(REPO_ROOT, "rev-parse", "HEAD", check=(real_euid == REPO_ROOT.stat().st_uid))
    assert seen[-1][1:7] == ["-c", "protocol.allow=never", "-c", "credential.helper=", "-c", "core.fsmonitor=false"] and not any(a.startswith("safe.directory=") for a in seen[-1])
    monkeypatch.setattr(decomposition_scope.os, "geteuid", lambda: 0)
    assert len(decomposition_scope.run_git_offline(REPO_ROOT, "rev-parse", "HEAD").stdout.strip()) == 40
    assert seen[-1][1:9] == ["-c", "protocol.allow=never", "-c", "credential.helper=", "-c", "core.fsmonitor=false", "-c", f"safe.directory={REPO_ROOT.resolve().as_posix()}"] and seen[-1][9:] == ["-C", str(REPO_ROOT), "rev-parse", "HEAD"]

def test_pipeline_portable_end_to_end_candidates_d4_and_cli_verify(tmp_path: Path, portable_oci_fixture: dict[str, Any], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    from tools.governance import gov1_cli_oci

    cg_root, out_dir = tmp_path / "cg", tmp_path / "etapa11_out"
    cg_root.mkdir()
    (cg_root / "cgroup.controllers").write_text("cpu memory pids\n", encoding="utf-8")
    blobs_dir = _stage_d26_blobs_dir(tmp_path / "blobs", portable_oci_fixture["d26"])
    summary = gov1_cli_oci.run_etapa11_oci_candidates_pipeline(repo_root=REPO_ROOT, base_oci_dir=portable_oci_fixture["base_dir"], out_dir=out_dir, legacy_blobs_dir=blobs_dir, build_run_id="portable-e11", verify_ephemeral_d4=True, cgroup_root=cg_root, host_probe_fn=lambda **_kw: {"status": "ELIGIBLE", "eligible": True, "reasons": []}, subrun_hooks=_make_pipeline_sim_hooks(portable_oci_fixture), base_oci_expectations=portable_oci_fixture["base_meta"], work_root_parent=tmp_path, key_root_parent=tmp_path)
    assert summary["status"] == "PASS" and summary["ephemeral_d4_verified"] is True and summary["ephemeral_d4_cas_calls"] == 1
    assert list(tmp_path.rglob("*.pem")) == [] and (out_dir / "etapa11_oci_summary.json").is_file()
    assert len([p for p in (out_dir / "ephemeral-store/sha256").glob("*.json") if loads_strict(p.read_text(encoding="utf-8")).get("$schema") == gov1_sandbox.SANDBOX_PROFILE_SCHEMA]) == 1
    names = ("sealed_sandbox_profile", "wheel_build_provenance", "wheel_boundary_report", "mcp_rejection_matrix_report", "negative_security_test_report", "certification_7a_record", "gov1_convergence_record")
    cands = {n: loads_strict((out_dir / "candidates" / f"{n}.candidate.json").read_text(encoding="utf-8")) for n in names}
    assert all(c["artifact_kind"] == gov1_sandbox.LOCAL_CANDIDATE_KIND and c["signable"] is False and c["authority"] == "none" and "$schema" not in c and "integrity" not in c for c in cands.values())
    assert cands["sealed_sandbox_profile"]["payload"]["issued_at_utc"] == "2026-09-07T10:00:00Z" and cands["wheel_build_provenance"]["payload"]["built_at_utc"] == "2026-09-07T10:00:05Z"
    ts_seq = [cands[k]["payload"][f] for k, f in (("sealed_sandbox_profile", "issued_at_utc"), ("wheel_build_provenance", "built_at_utc"), ("wheel_boundary_report", "verified_at_utc"), ("mcp_rejection_matrix_report", "executed_at_utc"), ("negative_security_test_report", "executed_at_utc"), ("certification_7a_record", "certified_at_utc"), ("gov1_convergence_record", "converged_at_utc"))]
    assert ts_seq == sorted(ts_seq) and cli.main(_verify_conv_cli_argv(out_dir, blobs_dir)) == 0
    assert loads_strict(capsys.readouterr().out)["status"] == "PASS"
    out_nod4, cg_root2 = tmp_path / "etapa11_nod4", tmp_path / "cg2"
    cg_root2.mkdir()
    (cg_root2 / "cgroup.controllers").write_text("cpu memory pids\n", encoding="utf-8")
    sum_nod4 = gov1_cli_oci.run_etapa11_oci_candidates_pipeline(repo_root=REPO_ROOT, base_oci_dir=portable_oci_fixture["base_dir"], out_dir=out_nod4, legacy_blobs_dir=blobs_dir, verify_ephemeral_d4=False, cgroup_root=cg_root2, host_probe_fn=lambda **_kw: {"status": "ELIGIBLE", "eligible": True, "reasons": []}, subrun_hooks=_make_pipeline_sim_hooks(portable_oci_fixture), base_oci_expectations=portable_oci_fixture["base_meta"], work_root_parent=tmp_path, key_root_parent=tmp_path)
    assert sum_nod4["ephemeral_d4_verified"] is False and sum_nod4["ephemeral_d4_cas_calls"] == 0 and list(tmp_path.rglob("*.pem")) == [] and cli.main(_verify_conv_cli_argv(out_nod4, blobs_dir)) == 0
    capsys.readouterr()
    monkeypatch.setattr(gov1_cli_oci, "run_etapa11_oci_candidates_pipeline", lambda **_kw: summary)
    assert cli.main(["run-etapa11-oci-candidates", "--repo", str(REPO_ROOT), "--base-oci-dir", str(portable_oci_fixture["base_dir"]), "--out-dir", str(tmp_path / "cli_out"), "--legacy-blobs-dir", str(blobs_dir), "--verify-ephemeral-d4"]) == 0
    assert loads_strict(capsys.readouterr().out.strip())["ephemeral_d4_verified"] is True

def test_workflow_gov1_etapa11_oci_yaml_contract() -> None:
    wf_path = REPO_ROOT / ".github" / "workflows" / "gov1-etapa11-oci.yml"
    wf_text = wf_path.read_text(encoding="utf-8")
    for token in ("name: gov1-etapa11-oci", "pull_request:", "push:", "workflow_dispatch:", "contents: read", "etapa11-oci-linux-amd64:", "runs-on: ubuntu-latest", "timeout-minutes: 45", "actions/checkout@v4", "astral-sh/setup-uv@v5", "missing_pkgs=()", "--preserve-digests", "-o cache_dir=/tmp/pytest-cache-live-oci", "runc", "skopeo", gov1_oci_image.PINNED_BASE_OCI_MANIFEST_DIGEST, "SMART_ADS_LIVE_OCI_TESTS=1", "probe-7a-oci-host", "run-etapa11-oci-candidates", "--verify-ephemeral-d4", "verify-gov1-convergence-record", "git status --porcelain", "actions/upload-artifact@v4"):
        assert token in wf_text, f"missing {token!r} in gov1-etapa11-oci.yml"

@pytest.fixture(scope="module")
def live_oci_suite_result() -> dict[str, Any] | None:
    base_oci_dir = _require_live_oci_prereqs()
    if base_oci_dir is None:
        return None
    from tools.governance import gov1_cli_oci

    exec_parent = gov1_oci_readback.select_exec_work_root_parent()
    work_root = Path(tempfile.mkdtemp(prefix="smart-ads-live-oci-", dir=str(exec_parent)))
    try:
        os.chmod(work_root, 0o755)
        blobs_dir = _stage_d26_blobs_dir(work_root / "d26_blobs", _decode_d26())
        out_dir = work_root / "etapa11_out"
        summary = gov1_cli_oci.run_etapa11_oci_candidates_pipeline(
            repo_root=REPO_ROOT, base_oci_dir=base_oci_dir, out_dir=out_dir,
            legacy_blobs_dir=blobs_dir, build_run_id="live-oci-t4", verify_ephemeral_d4=True,
        )
        c_dir = out_dir / "candidates"
        cands = {n: loads_strict((c_dir / f"{n}.candidate.json").read_text(encoding="utf-8")) for n in ("wheel_boundary_report", "mcp_rejection_matrix_report", "negative_security_test_report", "certification_7a_record")}
        cli_rc = cli.main(_verify_conv_cli_argv(out_dir, blobs_dir))
        probe_rc = cli.main(["probe-7a-oci-host", "--base-oci-dir", str(base_oci_dir)])
        pem_left = [str(p) for p in work_root.rglob("*.pem")]
        return {"summary": summary, "cands": cands, "cli_rc": cli_rc, "probe_rc": probe_rc, "pem_left": pem_left}
    finally:
        gov1_oci_image.cleanup_runc_bundle_trees(work_root)

def test_live_linux_amd64_oci_stage7_probes_negative_suite_and_7a_corpus(live_oci_suite_result: dict[str, Any] | None) -> None:
    if live_oci_suite_result is None:
        return
    cands = live_oci_suite_result["cands"]
    assert cands["wheel_boundary_report"]["payload"]["isolated_venv_import_passed"] is True
    assert cands["mcp_rejection_matrix_report"]["payload"]["body_64k_boundary_verified"] is True
    neg_cases = cands["negative_security_test_report"]["payload"]["cases"]
    assert len(neg_cases) == 17 and sum(len(c["runs"]) for c in neg_cases) == 18
    pos_cases = cands["certification_7a_record"]["payload"]["fixture_evidence"]["cases"]
    assert [c["observed_completeness_status"] for c in pos_cases] == ["complete", "failed", "partial", "partial"]

def test_live_etapa11_cli_and_pipeline_convergence(live_oci_suite_result: dict[str, Any] | None) -> None:
    if live_oci_suite_result is None:
        return
    summary = live_oci_suite_result["summary"]
    assert summary["status"] == "PASS" and summary["ephemeral_d4_verified"] is True and summary["ephemeral_d4_cas_calls"] == 1
    assert live_oci_suite_result["probe_rc"] == 0 and live_oci_suite_result["cli_rc"] == 0 and live_oci_suite_result["pem_left"] == []

def test_corrupt_gzip_deflate_and_malformed_tar_layers_fail_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, portable_oci_fixture: dict[str, Any]) -> None:
    corrupt_gz = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03\xff\xff\xff\xff"
    gz_dir, cg_root = tmp_path / "bad_deflate", tmp_path / "cg"
    cg_root.mkdir()
    (cg_root / "cgroup.controllers").write_text("cpu memory pids\n", encoding="utf-8")
    for fn in ("memory.swap.max", "memory.peak", "pids.peak"):
        (cg_root / fn).write_text("0\n", encoding="utf-8")
    m1 = _write_synthetic_oci_layout(gz_dir, [(corrupt_gz, digest(corrupt_gz), "sha256:" + "0" * 64)])
    v_kw = {"expected_manifest_digest": m1["manifest_digest"], "expected_config_digest": m1["config_digest"], "expected_layer_digests": m1["layer_digests"], "expected_diff_ids": m1["diff_ids"]}
    with pytest.raises(ValueError, match="layer gzip stream invalid"):
        gov1_oci_image.verify_pinned_base_oci_layout(gz_dir, **v_kw)
    monkeypatch.setattr(gov1_oci_readback, "verify_pinned_base_oci_layout", functools.partial(gov1_oci_image.verify_pinned_base_oci_layout, **v_kw))
    pr = gov1_oci_readback.probe_7a_oci_host(base_oci_dir=gz_dir, cgroup_root=cg_root, runc_binary=sys.executable, sys_platform="linux", machine="x86_64", euid=0)
    assert pr["status"] == "BLOCKED" and pr["base_oci_verified"] is False and "base_oci_verification_failed" in pr["reasons"]
    bad_tar_raw = b"NOT-A-VALID-TAR-HEADER!" * 40
    bad_tar_gz = gzip.compress(bad_tar_raw, compresslevel=9, mtime=0)
    tar_dir = tmp_path / "bad_tar"
    m2 = _write_synthetic_oci_layout(tar_dir, [(bad_tar_gz, digest(bad_tar_gz), digest(bad_tar_raw))])
    bad_blob = tar_dir / "blobs/sha256" / m2["layer_digests"][0].split(":")[1]
    calls = (lambda: gov1_oci_image._scan_single_layer_for_target(bad_blob, "usr/local/bin/python3.12"), lambda: gov1_oci_image._extract_gzip_tar_layers([bad_blob], tmp_path / "ext_tar"), lambda: gov1_oci_image._extract_gzip_tar_layers([gz_dir / "blobs/sha256" / m1["layer_digests"][0].split(":")[1]], tmp_path / "ext_gz"), lambda: gov1_oci_image.build_composite_7a_oci_layout(base_oci_dir=tar_dir, output_layout_dir=tmp_path / "c_out", wheel_bytes=portable_oci_fixture["wheel_bytes"], corpus_bytes=b"{}", replay_context_obj={}, resolved_d26_blobs=portable_oci_fixture["d26"], seccomp_profile=portable_oci_fixture["seccomp"], runner_py_bytes=b"print(1)\n", expected_manifest_digest=m2["manifest_digest"], expected_config_digest=m2["config_digest"], expected_layer_digests=m2["layer_digests"], expected_diff_ids=m2["diff_ids"]))
    for fn_call in calls:
        with pytest.raises(ValueError, match="layer tar/gzip stream invalid"):
            fn_call()

def test_tmp_walk_concurrent_unlink_and_cgroup_peak_gates(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    scan_d = tmp_path / "scan"
    for sub in ("gone_d", "not_d", "loop_d"):
        (scan_d / sub).mkdir(parents=True)
    (scan_d / "keep.bin").write_bytes(b"k" * 777)
    (scan_d / "gone.bin").write_bytes(b"g" * 99999)
    real_stat, real_open, err_map = os.stat, os.open, {"gone_d": errno.ENOENT, "not_d": errno.ENOTDIR, "loop_d": errno.ELOOP}
    monkeypatch.setattr(os, "stat", lambda p, *a, **kw: (_ for _ in ()).throw(OSError(errno.ENOENT, "gone")) if p == "gone.bin" and kw.get("dir_fd") is not None else real_stat(p, *a, **kw))
    monkeypatch.setattr(os, "open", lambda p, fl, *a, **kw: (_ for _ in ()).throw(OSError(err_map[p], "race")) if isinstance(p, str) and p in err_map and kw.get("dir_fd") is not None else real_open(p, fl, *a, **kw))
    fds_before, t_fd = sum(1 for fd in range(3, 512) if _fd_is_open(fd)), real_open(scan_d, os.O_RDONLY | os.O_DIRECTORY)
    try:
        assert gov1_oci_readback._walk_tmp_max_regular_file_bytes(t_fd) == 777
        monkeypatch.setattr(os, "stat", lambda p, *a, **kw: (_ for _ in ()).throw(OSError(errno.EIO, "io")) if p == "keep.bin" and kw.get("dir_fd") is not None else real_stat(p, *a, **kw))
        pytest.raises(OSError, gov1_oci_readback._walk_tmp_max_regular_file_bytes, t_fd)
    finally:
        os.close(t_fd)
    assert sum(1 for fd in range(3, 512) if _fd_is_open(fd)) == fds_before
    monkeypatch.setattr(os, "stat", real_stat)
    monkeypatch.setattr(os, "open", real_open)
    cg_np = tmp_path / "cg_np"
    cg_np.mkdir()
    for fn, val in (("cgroup.controllers", "cpu memory pids\n"), ("memory.swap.max", "0\n"), ("memory.peak", "0\n")):
        (cg_np / fn).write_text(val, encoding="utf-8")
    pr_np = gov1_oci_readback.probe_7a_oci_host(cgroup_root=cg_np, runc_binary=sys.executable, sys_platform="linux", machine="x86_64", euid=0)
    assert pr_np["status"] == "BLOCKED" and "cgroup_peak_files_unavailable" in pr_np["reasons"] and "memory_swap_max_unavailable" not in pr_np["reasons"]
    (cg_np / "memory.swap.max").unlink()
    assert {"memory_swap_max_unavailable", "cgroup_peak_files_unavailable"} <= set(gov1_oci_readback.probe_7a_oci_host(cgroup_root=cg_np, runc_binary=sys.executable, sys_platform="linux", machine="x86_64", euid=0)["reasons"])

def test_proc_environ_and_live_cgroup_peak_readback_rejections(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, portable_oci_fixture: dict[str, Any]) -> None:
    proc_root, lease, spec, trees = _build_synthetic_live_proc_and_bundle(tmp_path / "rb_env", portable_oci_fixture["wheel_bytes"])
    ok_vfs = os.statvfs_result((4096, 4096, 65536, 65536, 65536, 4096, 4095, 4095, 0, 255))
    monkeypatch.setattr(os, "fstatvfs", lambda _fd: ok_vfs)
    for pk in ("memory.peak", "pids.peak"):
        (lease.cgroup_dir / pk).unlink()
        with pytest.raises(ValueError, match=pk):
            gov1_oci_readback.readback_live_container_state(container_pid=4242, lease=lease, composite_spec=spec, bundle_trees=trees, expect_seccomp=True, proc_root=proc_root)
        (lease.cgroup_dir / pk).write_text("0\n", encoding="utf-8")
    monkeypatch.setattr(os, "fstatvfs", lambda _fd: (_ for _ in ()).throw(OSError(errno.EBADF, "bad fd")))
    with pytest.raises(ValueError, match="harvest I/O failed"):
        gov1_oci_readback.harvest_cgroup_and_tmp_usage(lease=lease, tmp_fd=999, stdout_bytes=0, stderr_bytes=0)
    monkeypatch.setattr(os, "fstatvfs", lambda _fd: ok_vfs)
    env_p, decoy = proc_root / "4242/environ", tmp_path / "decoy_env"
    ok_env = env_p.read_bytes()
    decoy.write_bytes(ok_env)
    env_p.unlink()
    with pytest.raises(ValueError, match="environ"):
        gov1_oci_readback.readback_live_container_state(container_pid=4242, lease=lease, composite_spec=spec, bundle_trees=trees, expect_seccomp=True, proc_root=proc_root)
    env_p.symlink_to(decoy)
    with pytest.raises(ValueError, match="environ"):
        gov1_oci_readback.readback_live_container_state(container_pid=4242, lease=lease, composite_spec=spec, bundle_trees=trees, expect_seccomp=True, proc_root=proc_root)
    env_p.unlink()
    for bad_env in (b"PATH=/evil\x00" + ok_env, b"PATH=/evil\x00" + ok_env.replace(b"TZ=UTC\x00", b""), ok_env + b"\x00", b""):
        env_p.write_bytes(bad_env)
        with pytest.raises(ValueError, match="environ"):
            gov1_oci_readback.readback_live_container_state(container_pid=4242, lease=lease, composite_spec=spec, bundle_trees=trees, expect_seccomp=True, proc_root=proc_root)
    env_p.write_bytes(ok_env[:-1])
    rb = gov1_oci_readback.readback_live_container_state(container_pid=4242, lease=lease, composite_spec=spec, bundle_trees=trees, expect_seccomp=True, proc_root=proc_root)
    os.close(rb.tmp_fd)
    gov1_oci_image.cleanup_runc_bundle_trees(trees["bundle_dir"])

def test_delayed_runc_pid_file_and_executable_snapshot_mode_staging(tmp_path: Path, portable_oci_fixture: dict[str, Any]) -> None:
    fx, cg_root = portable_oci_fixture, tmp_path / "cg"
    cg_root.mkdir()
    (cg_root / "cgroup.controllers").write_text("cpu memory pids\n", encoding="utf-8")
    seen_modes: dict[str, int] = {}

    def _delayed_spawn(_cmd: Any, *, stdin_fd: int, stdout_fd: int, stderr_fd: int, pid_file: Path, bundle_dir: Path, lease: Any) -> _PipeContainerSim:
        st_dir = bundle_dir / "oci_extracted/app/stage"
        if st_dir.is_dir():
            seen_modes.update({r: (st_dir / r).stat().st_mode & 0o777 for r in ("pyproject.toml", "src/smart_ads/__init__.py") if (st_dir / r).is_file()})
        def _write_later() -> None:
            time.sleep(0.025)
            tmp_pf = pid_file.with_suffix(".tmp")
            tmp_pf.write_text("4242\n", encoding="utf-8")
            os.replace(tmp_pf, pid_file)
        threading.Thread(target=_write_later, daemon=True).start()
        return _PipeContainerSim(stdin_fd, stdout_fd, stderr_fd, threading.Event(), [], lambda _s, o_fd, _e, _st: (os.write(o_fd, canonicalize({"wheel_name": gov1_wheel.EXPECTED_WHEEL_FILENAME, "wheel_b64": base64.b64encode(fx["wheel_bytes"]).decode("ascii")}) + b"\n"), 0)[1])

    base_hooks, events = _make_portable_hooks(fx["comp_spec"], lambda *_a: 0)
    d_hooks = gov1_oci_supervisor.RuncSubrunHooks(**{**{f: getattr(base_hooks, f) for f in base_hooks.__dataclass_fields__}, "spawn_runc": _delayed_spawn})
    sup = gov1_oci_supervisor.LinuxRuncSealedOciSupervisor(composite_spec=fx["comp_spec"], work_dir=tmp_path / "w_d", build_run_id="rd", cgroup_root=cg_root, hooks=d_hooks)
    assert sup.readback_sandbox_environment()["runtime_kind"] == "oci" and ("seal", 4242) in events
    for mode_kind in ("symlink", "exited"):
        def _bad_spawn(_c: Any, *, stdout_fd: int, pid_file: Path, _mk: str = mode_kind, **_k: Any) -> Any:
            os.write(stdout_fd, gov1_oci_container_runner.PREMASK_BANNER)
            if _mk == "symlink":
                pid_file.symlink_to(tmp_path / "missing_pid")
            return type("_Dead", (), {"poll": lambda _s: None if _mk == "symlink" else 1, "wait": lambda _s, timeout=None: 1, "kill": lambda _s: None})()
        bh = gov1_oci_supervisor.RuncSubrunHooks(**{**{f: getattr(base_hooks, f) for f in base_hooks.__dataclass_fields__}, "spawn_runc": _bad_spawn})
        with pytest.raises(ValueError, match="pid-file"):
            gov1_oci_supervisor.LinuxRuncSealedOciSupervisor(composite_spec=fx["comp_spec"], work_dir=tmp_path / f"wb_{mode_kind}", build_run_id=f"rb-{mode_kind}", cgroup_root=cg_root, hooks=bh).readback_sandbox_environment()
    with pytest.raises(ValueError, match="extra_app_modes"):
        gov1_oci_image.materialize_runc_bundle_trees(composite_spec=fx["comp_spec"], bundle_dir=tmp_path / "bad_m", extra_app_files={"a.py": b"1"}, extra_app_modes={"a.py": 0o755})
    b_site, bm = tmp_path / "b_site", fx["base_meta"]
    gov1_wheel.verify_build_runtime_environment(fx["snapshot"].files["uv.lock"], target_backend_site_dir=b_site)
    runner = gov1_oci_supervisor.OciIsolatedWheelProbeRunner(base_oci_dir=fx["base_dir"], work_dir=tmp_path / "pw", cgroup_root=cg_root, hooks=d_hooks, expected_manifest_digest=bm["manifest_digest"], expected_config_digest=bm["config_digest"], expected_layer_digests=bm["layer_digests"], expected_diff_ids=bm["diff_ids"])
    runner.run_pep517_wheel_build(snapshot_files=fx["snapshot"].files, snapshot_modes={**fx["snapshot"].modes, "pyproject.toml": "100644", "src/smart_ads/__init__.py": "100755"}, verified_backend_site_dir=b_site, source_date_epoch=gov1_wheel.DEFAULT_SOURCE_DATE_EPOCH)
    assert seen_modes == {"pyproject.toml": 0o444, "src/smart_ads/__init__.py": 0o555}

def test_select_exec_work_root_parent_noexec_fallback_and_cli_flag(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], portable_oci_fixture: dict[str, Any]) -> None:
    from tools.governance import gov1_cli_oci

    monkeypatch.setattr(os, "ST_NOEXEC", 8, raising=False)
    real_stat, real_access, real_statvfs = os.stat, os.access, os.statvfs
    modes = {"/": stat.S_IFDIR | 0o755, "/tmp": stat.S_IFDIR | 0o1777, "/var": stat.S_IFDIR | 0o755, "/var/tmp": stat.S_IFDIR | 0o1777}
    flags = {"/tmp": 8, "/var/tmp": 0}
    monkeypatch.setattr(os, "stat", lambda p, *a, **kw: os.stat_result((modes[os.fspath(p)], 1, 1, 1, 0, 0, 0, 0, 0, 0)) if os.fspath(p) in modes else real_stat(p, *a, **kw))
    monkeypatch.setattr(os, "access", lambda p, m: True if os.fspath(p) in ("/tmp", "/var/tmp") else real_access(p, m))
    monkeypatch.setattr(os, "statvfs", lambda p: os.statvfs_result((4096, 4096, 1000, 1000, 1000, 1000, 1000, 1000, flags[os.fspath(p)], 255)) if os.fspath(p) in flags else real_statvfs(p))
    assert gov1_oci_readback.select_exec_work_root_parent() == Path("/var/tmp")
    flags["/var/tmp"] = 8
    with pytest.raises(ValueError, match="ST_NOEXEC"):
        gov1_oci_readback.select_exec_work_root_parent()
    cg_ok, blobs_d = tmp_path / "cg_ok", _stage_d26_blobs_dir(tmp_path / "blobs9", portable_oci_fixture["d26"])
    cg_ok.mkdir()
    (cg_ok / "cgroup.controllers").write_text("cpu memory pids\n", encoding="utf-8")
    for fn in ("memory.swap.max", "memory.peak", "pids.peak"):
        (cg_ok / fn).write_text("0\n", encoding="utf-8")
    pr_blk = gov1_oci_readback.probe_7a_oci_host(cgroup_root=cg_ok, runc_binary=sys.executable, sys_platform="linux", machine="x86_64", euid=0, work_root_parent=Path("/tmp"))
    assert pr_blk["status"] == "BLOCKED" and "work_root_noexec_or_untraversable" in pr_blk["reasons"]
    pipe_blk = gov1_cli_oci.run_etapa11_oci_candidates_pipeline(repo_root=REPO_ROOT, base_oci_dir=portable_oci_fixture["base_dir"], out_dir=tmp_path / "blk_o", legacy_blobs_dir=blobs_d, cgroup_root=cg_ok, host_probe_fn=lambda **_k: {"status": "ELIGIBLE", "eligible": True, "reasons": []}, subrun_hooks=None)
    assert pipe_blk["status"] == "BLOCKED" and "work_root_noexec_or_untraversable" in pipe_blk["host_probe"]["reasons"]
    flags["/var/tmp"], modes["/var"] = 0, stat.S_IFDIR | 0o700
    with pytest.raises(ValueError, match="world-execute"):
        gov1_oci_readback.select_exec_work_root_parent(Path("/var/tmp"))
    priv_anc = tmp_path / "priv_700"
    priv_anc.mkdir(mode=0o700)
    os.chmod(priv_anc, 0o700)
    with pytest.raises(ValueError):
        gov1_oci_supervisor.LinuxRuncSealedOciSupervisor(composite_spec=portable_oci_fixture["comp_spec"], work_dir=priv_anc / "live_w", build_run_id="r9", cgroup_root=cg_ok, hooks=None)
    assert not (priv_anc / "live_w").exists()
    seen_wp: list[Any] = []
    monkeypatch.setattr(gov1_cli_oci, "run_etapa11_oci_candidates_pipeline", lambda **kw: (seen_wp.append(kw.get("work_root_parent")), {"status": "PASS"})[1])
    assert cli.main(["run-etapa11-oci-candidates", "--repo", str(REPO_ROOT), "--base-oci-dir", str(portable_oci_fixture["base_dir"]), "--out-dir", str(tmp_path / "c9"), "--legacy-blobs-dir", str(blobs_d), "--work-root-parent", "/var/tmp"]) == 0
    capsys.readouterr()
    assert seen_wp == [Path("/var/tmp")]
