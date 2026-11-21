"""CLI subparsers and candidate-mode orchestration pipeline for Etapa 11 Linux amd64 OCI execution."""
from __future__ import annotations

import argparse, base64, contextlib, copy, datetime, os, subprocess, sys, tempfile
from collections.abc import Callable, Iterator, Mapping, Sequence
from pathlib import Path
from typing import Any, Final

from tools.governance import (
    decomposition_governance, gov1_7a_certification as cert7a, gov1_7a_negative as neg7a,
    gov1_7a_replay_helpers as replay7a, gov1_7a_runner as runner7a, gov1_convergence, gov1_mcp,
    gov1_oci_container_runner as crun, gov1_oci_image as oci_img, gov1_oci_readback as oci_rb,
    gov1_sandbox, gov1_wheel, p1,
)
from tools.governance.decomposition_admission import profile_proposals
from tools.governance.decomposition_runtime import CHECKPOINT, HEAD, INVENTORY, REGISTRY, STATE, ClockInterval, Floor
from tools.governance.gov1_d4_helpers import (
    Gov1InstallationPins, _D4_SCHEMA_ROLE_ACTION_SPECS,
    build_gov1_convergence_record_candidate, verify_gov1_convergence_candidate,
)
from tools.governance.gov1_oci_readback import probe_7a_oci_host
from tools.governance.gov1_oci_supervisor import LinuxRuncSealedOciSupervisor, OciIsolatedWheelProbeRunner, RuncSubrunHooks
from tools.governance.jcs import canonicalize, loads_strict
from tools.governance.locator import Store, digest, json_digest, timestamp

OCI_CLI_COMMANDS: Final[frozenset[str]] = frozenset({"probe-7a-oci-host", "run-etapa11-oci-candidates"})

_VALID_FROM_UTC, _MIN_VALID_UNTIL_UTC = "2026-01-01T00:00:00Z", "2028-01-01T00:00:00Z"
_SBX_ISSUED_AT_UTC, _GIT_RESOLVED_AT_UTC, _PROV_BUILT_AT_UTC = "2026-09-07T10:00:00Z", "2026-09-07T10:00:04Z", "2026-09-07T10:00:05Z"
_EPHEMERAL_ANCHOR_ID, _EPHEMERAL_CELL_ID = "ephemeral-etapa11-trust-anchor", "ephemeral-etapa11-cell"
_EPHEMERAL_TENANT, _EPHEMERAL_INSTALL_AUTH = "ephemeral-etapa11-tenant", "ephemeral-etapa11-installation"
_EPHEMERAL_HEAD_REG, _EPHEMERAL_CHK_REG = "head:ephemeral-etapa11", "checkpoint:ephemeral-etapa11"
_UPSTREAM_REF: Final[dict[str, Any]] = {
    "repository": "pipeboard-co/meta-ads-mcp", "commit_sha": "2ef198e266ca6a37b6dc2c42335f0a0885002771",
    "path": "meta_ads_mcp/core/insights.py", "symbol": "get_insights", "hosted_parity_proven": False,
}


def _write_bytes_atomic(out_path: Path, raw: bytes, *, allow_overwrite: bool = False) -> dict[str, Any]:
    if type(raw) is not bytes or len(raw) == 0:
        raise ValueError("gov1: expected non-empty bytes payload")
    if out_path.is_symlink():
        raise ValueError(f"gov1: symlink output path forbidden: {out_path}")
    if not allow_overwrite and out_path.exists():
        raise ValueError(f"gov1: output exists; choose a fresh output path: {out_path}")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix=".gov1-oci-", dir=out_path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temp, 0o644)
        os.replace(temp, out_path) if allow_overwrite else os.link(temp, out_path)
    finally:
        Path(temp).unlink(missing_ok=True)
    if out_path.read_bytes() != raw:
        raise ValueError(f"gov1: output write verification failed for {out_path}")
    return {"path": str(out_path), "size": len(raw), "sha256": digest(raw)}


def _write_json_atomic(out_path: Path, obj: Mapping[str, Any], *, allow_overwrite: bool = False) -> dict[str, Any]:
    return _write_bytes_atomic(out_path, canonicalize(dict(obj)), allow_overwrite=allow_overwrite)


def _print_canonical_json(obj: Mapping[str, Any]) -> None:
    sys.stdout.write(canonicalize(dict(obj)).decode("utf-8") + "\n")
    sys.stdout.flush()


def _clamp_now_utc(*floors: str) -> str:
    best = datetime.datetime.now(datetime.UTC).replace(microsecond=0)
    for floor_s in floors:
        if (floor_dt := timestamp(floor_s)) > best:
            best = floor_dt
    return best.strftime("%Y-%m-%dT%H:%M:%SZ")


def _compute_valid_until_utc(now_utc: datetime.datetime | None = None) -> str:
    ref = datetime.datetime.now(datetime.UTC) if now_utc is None else now_utc
    plus_year = (ref + datetime.timedelta(days=365)).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")
    return plus_year if timestamp(plus_year) > timestamp(_MIN_VALID_UNTIL_UTC) else _MIN_VALID_UNTIL_UTC


def _d4_role_specs() -> list[tuple[str, list[dict[str, str]]]]:
    anchor_actions = [
        {"schema": INVENTORY, "action": "contract_inventory_issue"},
        {"schema": HEAD, "action": "current_key_state_head_issue"},
        {"schema": STATE, "action": "current_key_state_issue"},
    ]
    specs: list[tuple[str, list[dict[str, str]]]] = [("trust_anchor", anchor_actions)]
    for schema, (_prof_role, role_name, action_name) in sorted(_D4_SCHEMA_ROLE_ACTION_SPECS.items()):
        specs.append((role_name, [{"schema": schema, "action": action_name}]))
    if len(specs) != 12 or len({r for r, _ in specs}) != 12:
        raise ValueError("gov1: expected exact 12 distinct ephemeral D4 roles")
    return specs


@contextlib.contextmanager
def _ephemeral_d4_keyring(valid_until_utc: str, *, key_root_parent: Path | None = None) -> Iterator[tuple[Path, dict[str, tuple[Path, bytes, str]]]]:
    if timestamp(_VALID_FROM_UTC) >= timestamp(valid_until_utc):
        raise ValueError("gov1: invalid ephemeral D4 validity window")
    key_dir = Path(tempfile.mkdtemp(prefix="gov1-ephem-d4-keys-", dir=str(key_root_parent) if key_root_parent is not None else None))
    os.chmod(key_dir, 0o700)
    pem_paths: list[Path] = []
    try:
        keys: dict[str, tuple[Path, bytes, str]] = {}
        for role_name, _ in _d4_role_specs():
            pem_path = key_dir / f"{role_name}.pem"
            pem_paths.append(pem_path)
            subprocess.run(["openssl", "genpkey", "-algorithm", "Ed25519", "-out", str(pem_path)], check=True, capture_output=True, timeout=15)
            os.chmod(pem_path, 0o600)
            raw32 = p1.raw_public_key_from_pem(pem_path)
            keys[role_name] = (pem_path, raw32, p1.key_id_for(raw32))
        yield key_dir, keys
    finally:
        for pem_path in pem_paths:
            pem_path.unlink(missing_ok=True)
        if key_dir.exists() and not key_dir.is_symlink():
            for stray in list(key_dir.iterdir()):
                if stray.is_symlink() or not stray.is_dir():
                    stray.unlink(missing_ok=True)
            with contextlib.suppress(OSError):
                os.rmdir(key_dir)


def _mint_ephemeral_registry_and_config(
    store: Store, profiles: Mapping[str, Any], keys: Mapping[str, tuple[Path, bytes, str]], valid_until_utc: str
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    val_w = {"from": _VALID_FROM_UTC, "until": valid_until_utc}
    _, anchor_raw, anchor_kid = keys["trust_anchor"]
    config = {
        "$schema": "smart_ads/cell_trust_anchor_config/v1", "trust_anchor_id": _EPHEMERAL_ANCHOR_ID,
        "public_key_base64": base64.b64encode(anchor_raw).decode("ascii"), "public_key_sha256": digest(anchor_raw),
        "validity": copy.deepcopy(val_w), "allowed_registry_artifact_types": [REGISTRY, INVENTORY],
        "inventory_bootstrap_profile": copy.deepcopy(dict(profiles[INVENTORY])),
        "anti_rollback_checkpoint_profile": copy.deepcopy(dict(profiles[CHECKPOINT])),
        "cell_id": _EPHEMERAL_CELL_ID, "head_register": _EPHEMERAL_HEAD_REG,
        "checkpoint_register": _EPHEMERAL_CHK_REG, "installation_authority": _EPHEMERAL_INSTALL_AUTH,
    }
    entries = [
        {
            "key_id": keys[r][2], "public_key_base64": base64.b64encode(keys[r][1]).decode("ascii"),
            "public_key_sha256": digest(keys[r][1]), "principal": f"principal:ephemeral-{r}",
            "tenant": _EPHEMERAL_TENANT, "role": r, "validity": copy.deepcopy(val_w),
            "lifecycle_state": "active", "allowed_actions": acts,
        }
        for r, acts in _d4_role_specs()
    ]
    reg_u = {"$schema": REGISTRY, "trust_anchor_id": _EPHEMERAL_ANCHOR_ID, "epoch": 1, "issued_at_utc": _SBX_ISSUED_AT_UTC, "entries": entries, "integrity": {"key_id": anchor_kid, "key_registry_snapshot_locator": None}}
    reg_s = p1.sign_envelope(reg_u, profiles[REGISTRY]["domain_prefix"], keys["trust_anchor"][0])
    return config, reg_s, store.put(reg_s)


def _mint_ephemeral_bootstrap_chain(
    store: Store, profiles: Mapping[str, Any], keys: Mapping[str, tuple[Path, bytes, str]],
    reg_signed: Mapping[str, Any], reg_loc: dict[str, Any], *, issued_at_utc: str, valid_until_utc: str,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    anchor_pem, _, anchor_kid = keys["trust_anchor"]
    common = {"trust_anchor_id": _EPHEMERAL_ANCHOR_ID, "cell_id": _EPHEMERAL_CELL_ID, "issued_at_utc": issued_at_utc, "valid_until_utc": valid_until_utc, "maximum_age_seconds": 300}
    key_states = [{"key_id": e["key_id"], "public_key_sha256": e["public_key_sha256"], "lifecycle_state": e["lifecycle_state"]} for e in reg_signed["entries"]]
    state_s = p1.sign_envelope({**common, "$schema": STATE, "epoch": 1, "registry_locator": reg_loc, "predecessor_state_locator": None, "key_states": key_states, "integrity": {"key_id": anchor_kid, "key_registry_snapshot_locator": reg_loc}}, profiles[STATE]["domain_prefix"], anchor_pem)
    state_loc = store.put(state_s)
    head_s = p1.sign_envelope({**common, "$schema": HEAD, "epoch": 1, "current_state_locator": state_loc, "current_state_digest": state_loc["content_digest"], "predecessor_head_locator": None, "predecessor_head_digest": None, "integrity": {"key_id": anchor_kid, "key_registry_snapshot_locator": reg_loc}}, profiles[HEAD]["domain_prefix"], anchor_pem)
    chk_s = p1.sign_envelope({**common, "$schema": CHECKPOINT, "highest_seen_epoch": 0, "head_digest": None, "integrity": {"key_id": anchor_kid, "key_registry_snapshot_locator": None}}, profiles[CHECKPOINT]["domain_prefix"], anchor_pem)
    inv_s = p1.sign_envelope({**common, "$schema": INVENTORY, "epoch": 1, "predecessor_inventory_locator": None, "profiles": list(profiles.values()), "integrity": {"key_id": anchor_kid, "key_registry_snapshot_locator": reg_loc}}, profiles[INVENTORY]["domain_prefix"], anchor_pem)
    return store.put(head_s), store.put(chk_s), store.put(inv_s)


def _seed_7a_git_provenances(
    store: Store, profiles: Mapping[str, Any], keys: Mapping[str, tuple[Path, bytes, str]], reg_loc: Mapping[str, Any],
    *, source_commit_sha: str, git_blobs: Mapping[str, bytes], d26_blobs: Mapping[str, bytes],
) -> tuple[list[dict[str, Any]], dict[tuple[str, str], tuple[dict[str, Any], dict[str, Any]]]]:
    git_pem, _, git_kid = keys["git_provenance_verifier"]
    git_dom = profiles[runner7a.GIT_ARTIFACT_PROVENANCE_SCHEMA]["domain_prefix"]
    prov_map: dict[tuple[str, str], tuple[dict[str, Any], dict[str, Any]]] = {}
    d26_members: list[dict[str, Any]] = []
    for role, rel_path, oid, sha in runner7a.PINNED_PIPEBOARD_D26_SPECS:
        u_env = runner7a.build_git_artifact_provenance_envelope(repository=runner7a.PINNED_LEGACY_REPO, commit_sha=runner7a.PINNED_LEGACY_COMMIT, path=rel_path, raw_bytes=d26_blobs[rel_path], resolved_at_utc=_SBX_ISSUED_AT_UTC, registry_locator=reg_loc, signer_key_id=git_kid)
        s_env = p1.sign_envelope(u_env, git_dom, git_pem)
        loc = store.put(s_env)
        prov_map[(runner7a.PINNED_LEGACY_REPO, rel_path)] = (loc, s_env)
        d26_members.append({"role": role, "repository": runner7a.PINNED_LEGACY_REPO, "commit_sha": runner7a.PINNED_LEGACY_COMMIT, "path": rel_path, "git_blob_oid": oid, "file_content_sha256": sha, "git_artifact_provenance_locator": loc})
    for rel_path, raw in sorted(git_blobs.items()):
        u_env = runner7a.build_git_artifact_provenance_envelope(repository=gov1_wheel.DEFAULT_REPOSITORY, commit_sha=source_commit_sha, path=rel_path, raw_bytes=raw, resolved_at_utc=_GIT_RESOLVED_AT_UTC, registry_locator=reg_loc, signer_key_id=git_kid)
        s_env = p1.sign_envelope(u_env, git_dom, git_pem)
        prov_map[(gov1_wheel.DEFAULT_REPOSITORY, rel_path)] = (store.put(s_env), s_env)
    return d26_members, prov_map


def _seed_7a_contract_snapshot_and_inventory(
    store: Store, profiles: Mapping[str, Any], keys: Mapping[str, tuple[Path, bytes, str]], reg_loc: Mapping[str, Any],
    *, d26_members: Sequence[Mapping[str, Any]], corpus_doc: Mapping[str, Any], valid_until_utc: str,
) -> dict[str, Any]:
    pkt_core = {"repository": runner7a.PINNED_LEGACY_REPO, "commit_sha": runner7a.PINNED_LEGACY_COMMIT, "members": [dict(m) for m in d26_members]}
    drv_u = {"$schema": cert7a.PIPEBOARD_CONTRACT_SCHEMA, "contract_id": "driver-contract:pipeboard-phase1-v1", "driver_id": "pipeboard_hosted", "legacy_source_packet": {**pkt_core, "packet_digest": json_digest(pkt_core)}, "upstream_reference": copy.deepcopy(_UPSTREAM_REF), "transport_limits": copy.deepcopy(dict(replay7a.DEFAULT_PIPEBOARD_TRANSPORT_LIMITS)), "metric_source_mappings": dict(replay7a.PIPEBOARD_PHASE1_METRIC_SOURCE_MAPPINGS), "integrity": {"key_id": keys["provider_port_policy_owner"][2], "key_registry_snapshot_locator": copy.deepcopy(dict(reg_loc))}}
    drv_s = p1.sign_envelope(drv_u, profiles[cert7a.PIPEBOARD_CONTRACT_SCHEMA]["domain_prefix"], keys["provider_port_policy_owner"][0])
    drv_loc = store.put(drv_s)
    rmc_pre = b"SMART-ADS:RESOURCE-MAPPING-CONTRACT:V1\n\x00" + canonicalize({"domain_separator": "0x00", "key_identity": "key:7a-fixture-hmac-v1", "resource_ref_mapping_version": "hmac-sha256-b32-v1", "tenant_ref": "tenant:ibvi"})
    snap_u = {"$schema": runner7a.PRIVATE_REGISTRY_SNAPSHOT_SCHEMA, "snapshot_id": "registry-snapshot:2026-09-07-001", "tenant_ref": "tenant:ibvi", "issued_at_utc": _SBX_ISSUED_AT_UTC, "valid_until_utc": valid_until_utc, "resource_ref_mapping_version": "hmac-sha256-b32-v1", "key_identity": "key:7a-fixture-hmac-v1", "domain_separator": "0x00", "resource_mapping_contract_digest": digest(rmc_pre), "bindings": [{"binding_ref": "binding:meta-primary", "account_ref": "account:ibvi-01", "transport_provider_ref": "provider:pipeboard", "ad_platform_ref": "meta", "currency": "BRL", "driver_id": "pipeboard_hosted"}], "authorized_scopes": [{"front_ref": "front:ibvi", "profile_ref": "profile:reader", "binding_ref": "binding:meta-primary", "resource_scope_ref": "scope:campaigns-active"}], "capabilities": [{"capability_ref": "cap:campaign-basic-v1", "capability_semantic_version": "1.0.0", "driver_id": "pipeboard_hosted", "driver_contract_locator": drv_loc, "driver_contract_digest": drv_loc["content_digest"], "resource_scope_ref": "scope:campaigns-active", "state": "declared", "required_metrics": ["metric:clicks_v1", "metric:impressions_v1", "metric:spend_v1"]}], "integrity": {"key_id": keys["registry_publisher"][2], "key_registry_snapshot_locator": copy.deepcopy(dict(reg_loc))}}
    snap_s = runner7a.verify_private_registry_snapshot_envelope(p1.sign_envelope(snap_u, profiles[runner7a.PRIVATE_REGISTRY_SNAPSHOT_SCHEMA]["domain_prefix"], keys["registry_publisher"][0]), require_signed=True)
    snap_loc = store.put(snap_s)
    exp_res = [{"binding_ref": "binding:meta-primary", "account_ref": "account:ibvi-01", "resource_ref": r, "resource_level": "campaign", "metric_date": "2026-09-06", "attribution_ref": "attribution:not_applicable", "breakdown_signature": "breakdown:none"} for r in sorted(p["resource_ref"] for p in corpus_doc["verified_campaign_pairs"])]
    inv_u = runner7a.build_expected_resource_inventory_envelope(inventory_id="inventory:7a-2026-09-06", registry_snapshot_locator=snap_loc, tenant_ref="tenant:ibvi", binding_ref="binding:meta-primary", account_ref="account:ibvi-01", resource_scope_ref="scope:campaigns-active", date_range={"start_date": "2026-09-06", "end_date": "2026-09-06", "inclusive": True}, expected_resources=exp_res, registry_locator=reg_loc, signer_key_id=keys["private_registry_publisher"][2])
    inv_s = p1.sign_envelope(inv_u, profiles[runner7a.EXPECTED_RESOURCE_INVENTORY_SCHEMA]["domain_prefix"], keys["private_registry_publisher"][0])
    return {"snapshot": snap_s, "snapshot_locator": snap_loc, "driver_contract": drv_s, "driver_contract_locator": drv_loc, "expected_inventory": inv_s, "expected_inventory_locator": store.put(inv_s)}


def _build_cert7a_common_kwargs(
    *, run_ctx: Mapping[str, Any], build_run_id: str, certified_at_utc: str, snapshot: gov1_wheel.GitBuildSnapshot,
    inspection: Mapping[str, Any], rctx: Mapping[str, Any], prov_map: Mapping[tuple[str, str], tuple[dict[str, Any], dict[str, Any]]],
    corpus_bytes: bytes, pos_cases: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    drv_loc, snap_loc = rctx["driver_contract_locator"], rctx["snapshot_locator"]
    cap = {"capability_ref": "cap:campaign-basic-v1", "resource_scope_ref": "scope:campaigns-active", "driver_id": "pipeboard_hosted", "driver_contract_locator": drv_loc, "driver_contract_digest": drv_loc["content_digest"], "registry_snapshot_locator": snap_loc, "required_metrics": ["metric:clicks_v1", "metric:impressions_v1", "metric:spend_v1"]}
    ev = {"corpus_git_locator": prov_map[cert7a.CORPUS_GIT_PATH][0], "corpus_digest": digest(corpus_bytes), "regression_fixture": replay7a.build_canonical_regression_fixture(snap_loc["content_digest"]), "cases": list(pos_cases)}
    p_locs = runner7a.sort_git_provenance_locators([prov_map[k][0] for k in cert7a.PARSER_ARTIFACT_PATHS])
    a_locs = runner7a.sort_git_provenance_locators([prov_map[k][0] for k in cert7a.ADAPTER_ARTIFACT_PATHS])
    m_locs = runner7a.sort_git_provenance_locators([prov_map[k][0] for k in cert7a.MAPPING_ARTIFACT_PATHS])
    return {
        "migration_run_context_locator": dict(run_ctx), "build_run_id": build_run_id, "certified_at_utc": certified_at_utc,
        "source_commit_sha": snapshot.commit_sha, "build_backend_digest": snapshot.build_backend_digest,
        "schema_bundle_digest": inspection["schema_bundle_digest"], "wheel_digest": inspection["wheel_digest"],
        "resource_mapping_contract_digest": rctx["snapshot"]["resource_mapping_contract_digest"],
        "capability": cap, "parser_artifact_locators": p_locs,
        "parser_code_digest": cert7a.compute_parser_code_digest([prov_map[k][1] for k in cert7a.PARSER_ARTIFACT_PATHS]),
        "adapter_artifact_locators": a_locs,
        "adapter_code_digest": cert7a.compute_adapter_code_digest([prov_map[k][1] for k in cert7a.ADAPTER_ARTIFACT_PATHS]),
        "mapping_artifact_locators": m_locs,
        "mapping_rules_digest": cert7a.compute_mapping_rules_digest([prov_map[k][1] for k in cert7a.MAPPING_ARTIFACT_PATHS], rctx["driver_contract"]["metric_source_mappings"]),
        "fixture_evidence": ev,
    }


def _build_and_persist_seven_candidates(candidates_dir: Path, run_ctx: dict[str, Any], build_run_id: str, st: Mapping[str, Any]) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    sbx_cand, snap, insp, times = st["sbx_cand"], st["snapshot"], st["inspection"], st["times"]
    sbx_ref = gov1_sandbox.build_local_candidate_ref(sbx_cand)
    prov_cand = gov1_wheel.build_wheel_build_provenance_candidate(migration_run_context_locator=run_ctx, build_run_id=build_run_id, built_at_utc=_PROV_BUILT_AT_UTC, snapshot=snap, source_date_epoch=gov1_wheel.DEFAULT_SOURCE_DATE_EPOCH, schema_bundle_digest=insp["schema_bundle_digest"], wheel_bytes=st["wheel_bytes"])
    prov_ref = gov1_sandbox.build_local_candidate_ref(prov_cand)
    bound_cand = gov1_wheel.build_wheel_boundary_report_candidate(migration_run_context_locator=run_ctx, build_run_id=build_run_id, verified_at_utc=times["bound"], source_commit_sha=snap.commit_sha, build_backend_digest=snap.build_backend_digest, wheel_build_provenance_candidate_ref=prov_ref, inspection=insp)
    bound_ref = gov1_sandbox.build_local_candidate_ref(bound_cand)
    mcp_cand = gov1_mcp.build_mcp_rejection_matrix_report_candidate(migration_run_context_locator=run_ctx, build_run_id=build_run_id, executed_at_utc=times["mcp"], source_commit_sha=snap.commit_sha, build_backend_digest=snap.build_backend_digest, sealed_sandbox_profile_candidate_ref=sbx_ref, execution=st["mcp_exec"])
    neg_cand = neg7a.build_negative_security_test_report_candidate(migration_run_context_locator=run_ctx, sealed_sandbox_profile_candidate_ref=sbx_ref, wheel_build_provenance_candidate_ref=prov_ref, build_run_id=build_run_id, executed_at_utc=times["neg"], source_commit_sha=snap.commit_sha, build_backend_digest=snap.build_backend_digest, schema_bundle_digest=insp["schema_bundle_digest"], wheel_digest=insp["wheel_digest"], oci_image_digest=st["comp_spec"].oci_image_digest, runner_binary_digest=st["comp_spec"].runner_binary_digest, declared_resource_limits=sbx_cand["payload"]["resource_limits"], cases=st["neg_cases"])
    neg_ref = gov1_sandbox.build_local_candidate_ref(neg_cand)
    cert_cand = cert7a.build_certification_7a_record_candidate(**st["cert_common"], sealed_sandbox_profile_candidate_ref=sbx_ref, wheel_build_provenance_candidate_ref=prov_ref, wheel_boundary_report_candidate_ref=bound_ref, negative_security_test_report_candidate_ref=neg_ref)
    conv_cand = build_gov1_convergence_record_candidate(migration_run_context_locator=run_ctx, wheel_boundary_report_candidate_ref=bound_ref, sealed_sandbox_profile_candidate_ref=sbx_ref, negative_security_test_report_candidate_ref=neg_ref, mcp_rejection_matrix_report_candidate_ref=gov1_sandbox.build_local_candidate_ref(mcp_cand), certification_7a_record_candidate_ref=gov1_sandbox.build_local_candidate_ref(cert_cand), build_run_id=build_run_id, converged_at_utc=times["conv"], source_commit_sha=snap.commit_sha, wheel_digest=insp["wheel_digest"], build_backend_digest=snap.build_backend_digest, schema_bundle_digest=insp["schema_bundle_digest"])
    ordered = (("sealed_sandbox_profile", sbx_cand), ("wheel_build_provenance", prov_cand), ("wheel_boundary_report", bound_cand), ("mcp_rejection_matrix_report", mcp_cand), ("negative_security_test_report", neg_cand), ("certification_7a_record", cert_cand), ("gov1_convergence_record", conv_cand))
    files_meta = {name: {**_write_json_atomic(candidates_dir / f"{name}.candidate.json", obj), "payload_digest": obj["payload_digest"]} for name, obj in ordered}
    return dict(ordered), files_meta


class _EphemeralProtectedRuntime:
    def __init__(self, config: Mapping[str, Any], head_loc: Mapping[str, Any], chk_loc: Mapping[str, Any], now_utc: str) -> None:
        self._cfg_bytes = canonicalize(dict(config))
        self._head, self._chk = copy.deepcopy(dict(head_loc)), copy.deepcopy(dict(chk_loc))
        self._clock, self.floor, self.cas_calls = ClockInterval(now_utc, now_utc), Floor(0, None, "v0"), 0

    def configuration_bytes(self) -> bytes:
        return self._cfg_bytes

    def installation_authority(self) -> str:
        return _EPHEMERAL_INSTALL_AUTH

    def authenticated_clock(self) -> ClockInterval:
        return self._clock

    def read_head(self, register: str) -> dict[str, Any]:
        if register != _EPHEMERAL_HEAD_REG:
            raise ValueError(f"unexpected head register: {register!r}")
        return copy.deepcopy(self._head)

    def observe_head_and_clock(self, register: str) -> tuple[dict[str, Any], ClockInterval]:
        return self.read_head(register), self._clock

    def read_checkpoint(self, register: str) -> tuple[dict[str, Any], Floor]:
        if register != _EPHEMERAL_CHK_REG:
            raise ValueError(f"unexpected checkpoint register: {register!r}")
        return copy.deepcopy(self._chk), self.floor

    def compare_and_swap(self, register: str, expected: Floor, new: Floor, head_register: str, expected_head_locator: dict[str, Any]) -> bool:
        if register != _EPHEMERAL_CHK_REG or head_register != _EPHEMERAL_HEAD_REG:
            raise ValueError("unexpected CAS register")
        self.cas_calls += 1
        if expected != self.floor or canonicalize(expected_head_locator) != canonicalize(self._head):
            return False
        self.floor = Floor(new.epoch, new.head_digest, f"v{self.cas_calls}")
        return True


def _verify_ephemeral_d4_admission(
    *, store: Store, profiles: Mapping[str, Any], keys: Mapping[str, tuple[Path, bytes, str]], config: Mapping[str, Any],
    reg_loc: dict[str, Any], boot_locs: tuple[dict[str, Any], dict[str, Any], dict[str, Any]], run_ctx: dict[str, Any],
    build_run_id: str, st: Mapping[str, Any], adr_bytes: bytes, repo_dir: Path, leg_repo: Path | None, leg_blobs: Path | None,
) -> int:
    snap, insp, times, sbx_loc = st["snapshot"], st["inspection"], st["times"], st["sbx_loc"]
    prov_u = gov1_wheel.build_wheel_build_provenance_envelope(migration_run_context_locator=run_ctx, build_run_id=build_run_id, built_at_utc=_PROV_BUILT_AT_UTC, snapshot=snap, source_date_epoch=gov1_wheel.DEFAULT_SOURCE_DATE_EPOCH, schema_bundle_digest=insp["schema_bundle_digest"], wheel_bytes=st["wheel_bytes"], registry_locator=reg_loc, signer_key_id=keys["build_provenance_verifier"][2])
    prov_env = p1.sign_envelope(prov_u, profiles[gov1_wheel.WHEEL_BUILD_PROVENANCE_SCHEMA]["domain_prefix"], keys["build_provenance_verifier"][0])
    prov_loc = store.put(prov_env)
    bound_u = gov1_wheel.build_wheel_boundary_report_envelope(migration_run_context_locator=run_ctx, build_run_id=build_run_id, verified_at_utc=times["bound"], source_commit_sha=snap.commit_sha, build_backend_digest=snap.build_backend_digest, wheel_build_provenance_locator=prov_loc, inspection=insp, registry_locator=reg_loc, signer_key_id=keys["build_boundary_verifier"][2])
    bound_loc = store.put(p1.sign_envelope(bound_u, profiles[gov1_wheel.WHEEL_BOUNDARY_REPORT_SCHEMA]["domain_prefix"], keys["build_boundary_verifier"][0]))
    mcp_u = gov1_mcp.build_mcp_rejection_matrix_report_envelope(migration_run_context_locator=run_ctx, build_run_id=build_run_id, executed_at_utc=times["mcp"], source_commit_sha=snap.commit_sha, build_backend_digest=snap.build_backend_digest, sealed_sandbox_profile_locator=sbx_loc, execution=st["mcp_exec"], registry_locator=reg_loc, signer_key_id=keys["security_verifier"][2])
    mcp_loc = store.put(p1.sign_envelope(mcp_u, profiles[gov1_mcp.MCP_REJECTION_REPORT_SCHEMA]["domain_prefix"], keys["security_verifier"][0]))
    neg_u = neg7a.build_negative_security_test_report_envelope(migration_run_context_locator=run_ctx, sealed_sandbox_profile_locator=sbx_loc, wheel_build_provenance_locator=prov_loc, build_run_id=build_run_id, executed_at_utc=times["neg"], source_commit_sha=snap.commit_sha, build_backend_digest=snap.build_backend_digest, schema_bundle_digest=insp["schema_bundle_digest"], wheel_digest=insp["wheel_digest"], oci_image_digest=st["comp_spec"].oci_image_digest, runner_binary_digest=st["comp_spec"].runner_binary_digest, declared_resource_limits=st["sbx_cand"]["payload"]["resource_limits"], cases=st["neg_cases"], registry_locator=reg_loc, signer_key_id=keys["7a_verifier"][2])
    neg_loc = store.put(p1.sign_envelope(neg_u, profiles[gov1_convergence.NEGATIVE_SECURITY_SCHEMA]["domain_prefix"], keys["7a_verifier"][0]))
    cert_u = cert7a.build_certification_7a_record_envelope(**st["cert_common"], sealed_sandbox_profile_locator=sbx_loc, wheel_build_provenance_locator=prov_loc, wheel_boundary_report_locator=bound_loc, negative_security_test_report_locator=neg_loc, registry_locator=reg_loc, signer_key_id=keys["independent_7a_verifier"][2])
    cert_loc = store.put(p1.sign_envelope(cert_u, profiles[gov1_convergence.CERTIFICATION_7A_SCHEMA]["domain_prefix"], keys["independent_7a_verifier"][0]))
    pr3_v = cert7a.SevenAConstituentVerifier(wheel_bytes=st["wheel_bytes"], corpus_bytes=st["corpus_bytes"], stripped_provenance_payload=neg7a.extract_provenance_payload(prov_env), resolved_git_blobs=st["git_blobs"], resolved_d26_blobs=st["d26_blobs"])
    conv_u = gov1_convergence.build_gov1_convergence_record_envelope(migration_run_context_locator=run_ctx, wheel_boundary_report_locator=bound_loc, sealed_sandbox_profile_locator=sbx_loc, negative_security_test_report_locator=neg_loc, mcp_rejection_matrix_report_locator=mcp_loc, certification_7a_record_locator=cert_loc, build_run_id=build_run_id, converged_at_utc=times["conv"], source_commit_sha=snap.commit_sha, wheel_digest=insp["wheel_digest"], build_backend_digest=snap.build_backend_digest, schema_bundle_digest=insp["schema_bundle_digest"], registry_locator=reg_loc, signer_key_id=keys["gov1_convergence_verifier"][2], store=store, pr3_verifier=pr3_v)
    conv_loc = store.put(p1.sign_envelope(conv_u, profiles[gov1_convergence.GOV1_CONVERGENCE_SCHEMA]["domain_prefix"], keys["gov1_convergence_verifier"][0]))
    head_loc, chk_loc, inv_loc = boot_locs
    runtime = _EphemeralProtectedRuntime(config, head_loc, chk_loc, now_utc=times["conv"])
    pins = Gov1InstallationPins(configuration_digest=digest(runtime.configuration_bytes()), installation_authority=_EPHEMERAL_INSTALL_AUTH, cell_id=_EPHEMERAL_CELL_ID, head_register=_EPHEMERAL_HEAD_REG, checkpoint_register=_EPHEMERAL_CHK_REG, owner_principal="principal:ephemeral-trust_anchor", owner_tenant=_EPHEMERAL_TENANT, pinned_run_context_locator=run_ctx, pinned_pre_head_registry_locators=())
    verifier = gov1_convergence.Gov1AdmissionVerifier(runtime, pins, store, adr_bytes, inventory_locator=inv_loc, pr3_verifier=pr3_v, isolated_probe_runner=st["probe_runner"], corpus_path=st["corpus_path"], legacy_repo=leg_repo, legacy_blobs_dir=leg_blobs)
    d4_res = verifier.verify_artifact(conv_loc, seccomp_profile=st["seccomp_profile"], wheel_path=st["out_wheel_path"], repo_root=repo_dir)
    if d4_res.get("verification_status") != "VERIFIED" or runtime.cas_calls != 1:
        raise ValueError("gov1: ephemeral D4 admission verification failed")
    return runtime.cas_calls


def _validate_pipeline_inputs(
    *, repo_root: Path, base_oci_dir: Path, out_dir: Path,
    legacy_repo: Path | None, legacy_blobs_dir: Path | None, build_run_id: str | None,
) -> tuple[Path, Path, Path, Path | None, Path | None, str]:
    if (legacy_repo is None) == (legacy_blobs_dir is None):
        raise ValueError("run-etapa11-oci-candidates: specify exactly one of --legacy-repo or --legacy-blobs-dir")
    repo_dir, base_dir, out_path = Path(repo_root), Path(base_oci_dir), Path(out_dir)
    if repo_dir.is_symlink() or not repo_dir.is_dir():
        raise ValueError(f"run-etapa11-oci-candidates: invalid --repo directory {repo_dir}")
    if base_dir.is_symlink():
        raise ValueError(f"run-etapa11-oci-candidates: symlink --base-oci-dir forbidden: {base_dir}")
    if out_path.is_symlink() or (out_path.exists() and (not out_path.is_dir() or any(out_path.iterdir()))):
        raise ValueError(f"run-etapa11-oci-candidates: --out-dir must be a fresh or empty non-symlink directory: {out_path}")
    eff_run_id = f"etapa11-oci-{datetime.datetime.now(datetime.UTC).strftime('%Y%m%dT%H%M%SZ')}" if build_run_id is None else neg7a._strict_str(build_run_id, "build_run_id")
    neg7a._opaque_ref_str(f"sandbox:oci-pos-7a-{eff_run_id}-00", "build_run_id", expected_prefix="sandbox")
    return repo_dir, base_dir, out_path, (Path(legacy_repo) if legacy_repo is not None else None), (Path(legacy_blobs_dir) if legacy_blobs_dir is not None else None), eff_run_id


def _oci_exp_kwargs(base_oci_expectations: Mapping[str, Any] | None) -> dict[str, Any]:
    if base_oci_expectations is None:
        return {}
    return {
        "expected_manifest_digest": base_oci_expectations["manifest_digest"],
        "expected_config_digest": base_oci_expectations["config_digest"],
        "expected_layer_digests": tuple(base_oci_expectations["layer_digests"]),
        "expected_diff_ids": tuple(base_oci_expectations["diff_ids"]),
    }


def _execute_oci_stages(
    *, repo_dir: Path, base_dir: Path, out_path: Path, work_root: Path, store: Store, profiles: Mapping[str, Any],
    keys: Mapping[str, tuple[Path, bytes, str]], reg_loc: dict[str, Any], run_ctx: dict[str, Any], eff_run_id: str,
    valid_until_utc: str, leg_repo: Path | None, leg_blobs: Path | None, cgroup_root: Path, runc_binary: str,
    subrun_hooks: RuncSubrunHooks | None, exp_kw: Mapping[str, Any],
) -> dict[str, Any]:
    seccomp_profile = gov1_sandbox.build_default_7a_seccomp_profile()
    probe_runner = OciIsolatedWheelProbeRunner(base_oci_dir=base_dir, work_dir=work_root / "stage7", seccomp_profile=seccomp_profile, cgroup_root=cgroup_root, runc_binary=runc_binary, hooks=subrun_hooks, **exp_kw)
    built_whl, snapshot = gov1_wheel.build_reproducible_wheel(repo_dir, work_root / "built_wheel", probe_runner=probe_runner)
    wheel_bytes, out_wheel_path, seccomp_out_path = built_whl.read_bytes(), out_path / "wheel" / gov1_wheel.EXPECTED_WHEEL_FILENAME, out_path / "seccomp_profile.json"
    _write_bytes_atomic(out_wheel_path, wheel_bytes)
    _write_json_atomic(seccomp_out_path, seccomp_profile)
    inspection = gov1_wheel.inspect_wheel_boundary(out_wheel_path, probe_runner=probe_runner)
    t_bound = _clamp_now_utc(_PROV_BUILT_AT_UTC)
    mcp_exec = gov1_mcp.execute_mcp_rejection_matrix_on_wheel(out_wheel_path, probe_runner=probe_runner)
    t_mcp = _clamp_now_utc(t_bound)
    git_blobs = cert7a.resolve_7a_smart_ads_git_blobs(repo_dir, snapshot.commit_sha)
    d26_blobs = runner7a.resolve_pinned_pipeboard_d26_blobs(legacy_repo=leg_repo, legacy_blobs_dir=leg_blobs)
    corpus_path, corpus_bytes = repo_dir / cert7a.CORPUS_GIT_PATH[1], git_blobs[cert7a.CORPUS_GIT_PATH[1]]
    corpus_doc = loads_strict(corpus_bytes.decode("utf-8"))
    d26_members, prov_map = _seed_7a_git_provenances(store, profiles, keys, reg_loc, source_commit_sha=snapshot.commit_sha, git_blobs=git_blobs, d26_blobs=d26_blobs)
    rctx = _seed_7a_contract_snapshot_and_inventory(store, profiles, keys, reg_loc, d26_members=d26_members, corpus_doc=corpus_doc, valid_until_utc=valid_until_utc)
    comp_spec = oci_img.build_composite_7a_oci_layout(base_oci_dir=base_dir, output_layout_dir=work_root / "comp_oci", wheel_bytes=wheel_bytes, corpus_bytes=corpus_bytes, replay_context_obj=rctx, resolved_d26_blobs=d26_blobs, seccomp_profile=seccomp_profile, runner_py_bytes=crun.CONTAINER_RUNNER_SOURCE.encode("utf-8"), venv_probe_bootstrap_bytes=crun.VENV_PROBE_BOOTSTRAP_SOURCE.encode("utf-8"), **exp_kw)
    sbx_cand = gov1_sandbox.build_sealed_sandbox_profile_candidate(migration_run_context_locator=run_ctx, oci_image_digest=comp_spec.oci_image_digest, runner_binary_digest=comp_spec.runner_binary_digest, seccomp_profile=seccomp_profile, issued_at_utc=_SBX_ISSUED_AT_UTC, valid_from_utc=_VALID_FROM_UTC, valid_until_utc=valid_until_utc)
    sbx_u = gov1_sandbox.build_sealed_sandbox_profile_envelope(migration_run_context_locator=run_ctx, oci_image_digest=comp_spec.oci_image_digest, runner_binary_digest=comp_spec.runner_binary_digest, seccomp_profile=seccomp_profile, issued_at_utc=_SBX_ISSUED_AT_UTC, valid_from_utc=_VALID_FROM_UTC, valid_until_utc=valid_until_utc, registry_locator=reg_loc, signer_key_id=keys["security_owner"][2])
    sbx_env = p1.sign_envelope(sbx_u, profiles[gov1_sandbox.SANDBOX_PROFILE_SCHEMA]["domain_prefix"], keys["security_owner"][0])
    sbx_loc = store.put(sbx_env)
    sup = LinuxRuncSealedOciSupervisor(composite_spec=comp_spec, work_dir=work_root / "supervisor", build_run_id=eff_run_id, seccomp_profile=seccomp_profile, sealed_sandbox_profile_locator=sbx_loc, cgroup_root=cgroup_root, runc_binary=runc_binary, hooks=subrun_hooks)
    neg_cases = sup.execute_negative_security_suite(wheel_digest=inspection["wheel_digest"], sandbox_profile_payload=sbx_cand["payload"])
    t_neg = _clamp_now_utc(t_mcp, *(r["ended_at_utc"] for c in neg_cases for r in c["runs"]))
    pos_res = runner7a.run_7a_hermetic_execution(wheel_bytes=wheel_bytes, corpus_bytes=corpus_bytes, sandbox_profile=sbx_env, seccomp_profile=seccomp_profile, resolved_d26_blobs=d26_blobs, sandbox_pubkey_raw32=keys["security_owner"][1], supervisor=sup)
    if pos_res.get("status") != "EXECUTED":
        raise ValueError(f"gov1: 7A hermetic execution failed: {pos_res!r}")
    pos_cases = pos_res["execution"]["cases"]
    t_cert = _clamp_now_utc(t_neg, *(c["ended_at_utc"] for c in pos_cases))
    times = {"bound": t_bound, "mcp": t_mcp, "neg": t_neg, "cert": t_cert, "conv": _clamp_now_utc(t_bound, t_mcp, t_neg, t_cert)}
    cert_common = _build_cert7a_common_kwargs(run_ctx=run_ctx, build_run_id=eff_run_id, certified_at_utc=t_cert, snapshot=snapshot, inspection=inspection, rctx=rctx, prov_map=prov_map, corpus_bytes=corpus_bytes, pos_cases=pos_cases)
    return {"seccomp_profile": seccomp_profile, "seccomp_out_path": seccomp_out_path, "probe_runner": probe_runner, "snapshot": snapshot, "wheel_bytes": wheel_bytes, "out_wheel_path": out_wheel_path, "inspection": inspection, "mcp_exec": mcp_exec, "git_blobs": git_blobs, "d26_blobs": d26_blobs, "corpus_path": corpus_path, "corpus_bytes": corpus_bytes, "comp_spec": comp_spec, "sbx_cand": sbx_cand, "sbx_loc": sbx_loc, "neg_cases": neg_cases, "cert_common": cert_common, "times": times}


def _build_pipeline_summary(*, out_path: Path, eff_run_id: str, run_ctx: Mapping[str, Any], st: Mapping[str, Any], cand_files: Mapping[str, Any], conv_res: Mapping[str, Any], verify_ephemeral_d4: bool, cas_calls: int, probe_res: Mapping[str, Any]) -> dict[str, Any]:
    summary = {
        "status": "PASS", "mode": "candidate", "signable": False, "authority": "none", "build_run_id": eff_run_id,
        "source_commit_sha": st["snapshot"].commit_sha, "migration_run_context_locator": dict(run_ctx),
        "wheel_path": str(st["out_wheel_path"]), "wheel_digest": st["inspection"]["wheel_digest"],
        "build_backend_digest": st["snapshot"].build_backend_digest, "schema_bundle_digest": st["inspection"]["schema_bundle_digest"],
        "oci_image_digest": st["comp_spec"].oci_image_digest, "runner_binary_digest": st["comp_spec"].runner_binary_digest,
        "seccomp_profile_path": str(st["seccomp_out_path"]), "seccomp_profile_digest": st["comp_spec"].seccomp_profile_digest,
        "ephemeral_store_root": str(out_path / "ephemeral-store"), "candidates": dict(cand_files),
        "converged_at_utc": conv_res["converged_at_utc"], "candidate_convergence_verified": True,
        "ephemeral_d4_verified": bool(verify_ephemeral_d4), "ephemeral_d4_cas_calls": cas_calls, "host_probe": dict(probe_res),
    }
    _write_json_atomic(out_path / "etapa11_oci_summary.json", summary)
    return summary


def run_etapa11_oci_candidates_pipeline(
    *, repo_root: Path, base_oci_dir: Path, out_dir: Path, legacy_repo: Path | None = None,
    legacy_blobs_dir: Path | None = None, build_run_id: str | None = None, verify_ephemeral_d4: bool = False,
    cgroup_root: Path = Path("/sys/fs/cgroup"), runc_binary: str = "runc",
    host_probe_fn: Callable[..., dict[str, Any]] = oci_rb.probe_7a_oci_host,
    subrun_hooks: RuncSubrunHooks | None = None, base_oci_expectations: Mapping[str, Any] | None = None,
    work_root_parent: Path | None = None, key_root_parent: Path | None = None,
) -> dict[str, Any]:
    """Execute the full Etapa 11 OCI candidate convergence pipeline without touching `docs/**`."""
    repo_dir, base_dir, out_path, leg_repo, leg_blobs, eff_run_id = _validate_pipeline_inputs(repo_root=repo_root, base_oci_dir=base_oci_dir, out_dir=out_dir, legacy_repo=legacy_repo, legacy_blobs_dir=legacy_blobs_dir, build_run_id=build_run_id)
    probe_res = host_probe_fn(base_oci_dir=base_dir, cgroup_root=Path(cgroup_root), runc_binary=runc_binary)
    if probe_res.get("status") != "ELIGIBLE":
        return {"status": "BLOCKED", "host_probe": probe_res}
    run_ctx = decomposition_governance.verified_run_context_identity(repo_dir)["run_context_locator"]
    adr_bytes = (repo_dir / "docs" / "adr" / "ADR-0001-smart-ads-read-gateway.md").read_bytes()
    profiles, valid_until_utc = {p["schema"]: p for p in profile_proposals(adr_bytes)}, _compute_valid_until_utc()
    w_parent = str(work_root_parent) if work_root_parent is not None else ("/tmp" if Path("/tmp").is_dir() else None)
    work_root = Path(tempfile.mkdtemp(prefix="smart-ads-etapa11-oci-", dir=w_parent))
    try:
        os.chmod(work_root, 0o755)
        out_path.mkdir(parents=True, exist_ok=True)
        store = Store(out_path / "ephemeral-store")
        with _ephemeral_d4_keyring(valid_until_utc, key_root_parent=key_root_parent) as (_key_dir, keys):
            config, reg_s, reg_loc = _mint_ephemeral_registry_and_config(store, profiles, keys, valid_until_utc)
            st = _execute_oci_stages(repo_dir=repo_dir, base_dir=base_dir, out_path=out_path, work_root=work_root, store=store, profiles=profiles, keys=keys, reg_loc=reg_loc, run_ctx=run_ctx, eff_run_id=eff_run_id, valid_until_utc=valid_until_utc, leg_repo=leg_repo, leg_blobs=leg_blobs, cgroup_root=Path(cgroup_root), runc_binary=runc_binary, subrun_hooks=subrun_hooks, exp_kw=_oci_exp_kwargs(base_oci_expectations))
            cands, cand_files = _build_and_persist_seven_candidates(out_path / "candidates", run_ctx, eff_run_id, st)
            conv_res = verify_gov1_convergence_candidate(repo_root=repo_dir, wheel_path=st["out_wheel_path"], corpus_path=st["corpus_path"], seccomp_profile=st["seccomp_profile"], sandbox_profile=cands["sealed_sandbox_profile"], wheel_provenance=cands["wheel_build_provenance"], wheel_boundary_report=cands["wheel_boundary_report"], mcp_rejection_report=cands["mcp_rejection_matrix_report"], negative_security_report=cands["negative_security_test_report"], certification_7a_record=cands["certification_7a_record"], convergence_candidate=cands["gov1_convergence_record"], store=store, legacy_repo=leg_repo, legacy_blobs_dir=leg_blobs, probe_runner=st["probe_runner"])
            boot_locs = _mint_ephemeral_bootstrap_chain(store, profiles, keys, reg_s, reg_loc, issued_at_utc=st["times"]["conv"], valid_until_utc=valid_until_utc)
            cas_calls = _verify_ephemeral_d4_admission(store=store, profiles=profiles, keys=keys, config=config, reg_loc=reg_loc, boot_locs=boot_locs, run_ctx=run_ctx, build_run_id=eff_run_id, st=st, adr_bytes=adr_bytes, repo_dir=repo_dir, leg_repo=leg_repo, leg_blobs=leg_blobs) if verify_ephemeral_d4 else 0
    finally:
        oci_img.cleanup_runc_bundle_trees(work_root)
    return _build_pipeline_summary(out_path=out_path, eff_run_id=eff_run_id, run_ctx=run_ctx, st=st, cand_files=cand_files, conv_res=conv_res, verify_ephemeral_d4=verify_ephemeral_d4, cas_calls=cas_calls, probe_res=probe_res)


def register_oci_subparsers(sub: argparse._SubParsersAction[Any]) -> None:
    p_probe = sub.add_parser("probe-7a-oci-host")
    p_probe.add_argument("--base-oci-dir", default=None)
    p_probe.add_argument("--cgroup-root", default="/sys/fs/cgroup")
    p_probe.add_argument("--runc-binary", default="runc")
    p_probe.add_argument("--out", default=None)
    p_probe.set_defaults(func=cmd_oci)

    p_run = sub.add_parser("run-etapa11-oci-candidates")
    p_run.add_argument("--repo", required=True)
    p_run.add_argument("--base-oci-dir", required=True)
    p_run.add_argument("--out-dir", required=True)
    p_run.add_argument("--legacy-repo", default=None)
    p_run.add_argument("--legacy-blobs-dir", default=None)
    p_run.add_argument("--build-run-id", default=None)
    p_run.add_argument("--verify-ephemeral-d4", action="store_true")
    p_run.set_defaults(func=cmd_oci)


def cmd_oci(args: argparse.Namespace) -> int:
    try:
        if args.command == "probe-7a-oci-host":
            result = probe_7a_oci_host(base_oci_dir=Path(args.base_oci_dir) if args.base_oci_dir is not None else None, cgroup_root=Path(args.cgroup_root), runc_binary=args.runc_binary)
            if args.out is not None:
                _write_json_atomic(Path(args.out), result, allow_overwrite=False)
            _print_canonical_json(result)
            return 0 if result.get("status") == "ELIGIBLE" else 1
        if args.command == "run-etapa11-oci-candidates":
            summary = run_etapa11_oci_candidates_pipeline(repo_root=Path(args.repo), base_oci_dir=Path(args.base_oci_dir), out_dir=Path(args.out_dir), legacy_repo=Path(args.legacy_repo) if args.legacy_repo is not None else None, legacy_blobs_dir=Path(args.legacy_blobs_dir) if args.legacy_blobs_dir is not None else None, build_run_id=args.build_run_id, verify_ephemeral_d4=bool(args.verify_ephemeral_d4))
            _print_canonical_json(summary)
            return 0 if summary.get("status") == "PASS" else 1
        raise ValueError(f"gov1: unsupported OCI subcommand {args.command!r}")
    except (KeyError, OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired, TypeError, UnicodeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


__all__ = ["OCI_CLI_COMMANDS", "cmd_oci", "probe_7a_oci_host", "register_oci_subparsers", "run_etapa11_oci_candidates_pipeline"]
