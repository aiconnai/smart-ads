"""Passive stdlib 7A certification record, leaf P1 envelopes, and `SevenAConstituentVerifier`."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
import copy
import hashlib
import os
from pathlib import Path
import re
from types import MappingProxyType
from typing import Any, Final

from tools.governance.decomposition_scope import run_git_offline
from tools.governance.gov1_7a_negative import (
    MANDATORY_7A_NEGATIVE_CASES, NEGATIVE_SECURITY_REPORT_SCHEMA, _KEY_REGISTRY_SCHEMA, _RUN_CONTEXT_SCHEMA,
    _SHARED_RUNTIME_16_FIELDS, _SPEC_17_FIELDS, _exact_str, _hex40_str, _key_id_str, _opaque_ref_str,
    _sha256_str, _strict_str, _utc_sec_micros, _validate_resource_limits_dict, _validate_runtime_readback_dict,
    _validate_usage_and_termination, _verify_p1_integrity, evaluate_breach_predicates, extract_provenance_payload,
    verify_negative_security_test_report,
)
from tools.governance.gov1_7a_replay_helpers import (
    DEFAULT_PIPEBOARD_TRANSPORT_LIMITS, PIPEBOARD_PHASE1_METRIC_SOURCE_MAPPINGS, _SOURCE_METRIC_RE,
    build_canonical_regression_fixture, derive_resource_ref, parse_utc6_micros,
    recompute_collection_completeness_dict, recompute_fixture_7a_admission,
    transform_pipeboard_response_to_batch_dict, validate_provider_observation_batch_dict,
)
from tools.governance.gov1_7a_runner import (
    EXPECTED_RESOURCE_INVENTORY_SCHEMA, GIT_ARTIFACT_PROVENANCE_SCHEMA, PINNED_LEGACY_COMMIT, PINNED_LEGACY_REPO,
    PINNED_PIPEBOARD_D26_SPECS, PRIVATE_REGISTRY_SNAPSHOT_SCHEMA, _verify_d26_blob_map,
    build_expected_resource_inventory_envelope, build_git_artifact_provenance_envelope,
    compute_git_blob_oid, sort_git_provenance_locators, validate_private_registry_snapshot_payload,
    verify_expected_resource_inventory_envelope, verify_git_artifact_provenance_envelope,
)
from tools.governance.gov1_convergence import Pr3SevenAConstituentVerifier
from tools.governance.gov1_mcp import MCP_REJECTION_REPORT_SCHEMA
from tools.governance.gov1_sandbox import (
    LOCAL_CANDIDATE_KIND, SANDBOX_PROFILE_SCHEMA, build_local_candidate_ref,
    unwrap_local_candidate, verify_local_candidate_ref, wrap_local_candidate,
)
from tools.governance.gov1_wheel import (
    DEFAULT_REPOSITORY, WHEEL_BOUNDARY_REPORT_SCHEMA, WHEEL_BUILD_PROVENANCE_SCHEMA,
    _BOUNDARY_CANDIDATE_PAYLOAD_FIELDS, _BOUNDARY_ENVELOPE_FIELDS, _INSPECTION_FIELDS,
    _read_and_validate_wheel_archive, _validate_inspection_dict,
)
from tools.governance.jcs import canonicalize, loads_strict
from tools.governance.locator import Store, digest, exact_fields, json_digest, make_locator, validate_locator

CERTIFICATION_7A_RECORD_SCHEMA: Final[str] = "smart_ads/certification_7a_record/v1"
PIPEBOARD_CONTRACT_SCHEMA: Final[str] = "smart_ads/pipeboard_phase1_contract/v1"
PIPEBOARD_7A_CORPUS_SCHEMA: Final[str] = "smart_ads/pipeboard_7a_corpus/v1"

PARSER_ARTIFACT_PATHS: Final[tuple[tuple[str, str], ...]] = (
    ("mbras-tech/mbras-campaigns", "scripts/operator/meta_daily_contract.py"),
    ("aiconnai/smart-ads", "src/smart_ads/adapters/pipeboard/reducer.py"),
    ("aiconnai/smart-ads", "src/smart_ads/adapters/pipeboard/wire.py"),
)
ADAPTER_ARTIFACT_PATHS: Final[tuple[tuple[str, str], ...]] = (
    ("aiconnai/smart-ads", "src/smart_ads/adapters/pipeboard/__init__.py"),
    ("aiconnai/smart-ads", "src/smart_ads/adapters/pipeboard/adapter.py"),
)
MAPPING_ARTIFACT_PATHS: Final[tuple[tuple[str, str], ...]] = (
    ("aiconnai/smart-ads", "src/smart_ads/application/collection.py"),
    ("aiconnai/smart-ads", "src/smart_ads/domain/pipeboard_contract.py"),
    ("aiconnai/smart-ads", "src/smart_ads/domain/resource_ref.py"),
)
CORPUS_GIT_PATH: Final[tuple[str, str]] = ("aiconnai/smart-ads", "tests/certification_7a/fixtures/pipeboard_7a_corpus_v1.json")
SMART_ADS_7A_GIT_PATHS: Final[tuple[str, ...]] = tuple(sorted({
    p for r, p in (*PARSER_ARTIFACT_PATHS, *ADAPTER_ARTIFACT_PATHS, *MAPPING_ARTIFACT_PATHS, CORPUS_GIT_PATH) if r == "aiconnai/smart-ads"
}))
_PHASE1_METRICS: Final[tuple[str, ...]] = ("metric:clicks_v1", "metric:impressions_v1", "metric:spend_v1")
_COMPLETENESS_SET: Final[frozenset[str]] = frozenset({"complete", "partial", "failed"})
_SRC_CONTRACT_RE: Final[re.Pattern[str]] = re.compile(r"\Aopaque-driver-contract:sha256:[0-9a-f]{64}\Z")
_HEX64_RE: Final[re.Pattern[str]] = re.compile(r"\A[0-9a-f]{64}\Z")
_SNAP_ID_RE: Final[re.Pattern[str]] = re.compile(r"\Aregistry-snapshot:[A-Za-z0-9._:-]+\Z")
_DRV_ID_RE: Final[re.Pattern[str]] = re.compile(r"\Adriver-contract:[A-Za-z0-9._:-]+\Z")
_CASE_16_KEYS: Final[set[str]] = set(
    "case_id admitted_collection_digest expected_resource_inventory_locator source_contract_ref sandbox_instance_ref "
    "execution_binding_digest started_at_utc ended_at_utc runtime_readback effective_resource_limits usage termination "
    "observation_batch expected_completeness_status observed_completeness_status normalized_fact_set_digest".split()
)
_CERT_COMMON_17_KEYS: Final[set[str]] = set(
    "migration_run_context_locator build_run_id certified_at_utc certified_state source_commit_sha build_backend_digest "
    "schema_bundle_digest wheel_digest resource_mapping_contract_digest capability parser_artifact_locators parser_code_digest "
    "adapter_artifact_locators adapter_code_digest mapping_artifact_locators mapping_rules_digest fixture_evidence".split()
)
_CERT_CAND_21_KEYS: Final[set[str]] = _CERT_COMMON_17_KEYS | {
    "sealed_sandbox_profile_candidate_ref", "wheel_build_provenance_candidate_ref",
    "wheel_boundary_report_candidate_ref", "negative_security_test_report_candidate_ref",
}
_CERT_ENV_PAYLOAD_21_KEYS: Final[set[str]] = _CERT_COMMON_17_KEYS | {
    "sealed_sandbox_profile_locator", "wheel_build_provenance_locator",
    "wheel_boundary_report_locator", "negative_security_test_report_locator",
}
_CERT_ENV_23_KEYS: Final[set[str]] = _CERT_ENV_PAYLOAD_21_KEYS | {"$schema", "integrity"}


def _artifact_identities(provs: Sequence[Mapping[str, Any]], expected_paths: tuple[tuple[str, str], ...], label: str) -> list[dict[str, str]]:
    if isinstance(provs, (str, bytes, bytearray)) or not isinstance(provs, Sequence):
        raise ValueError(f"{label}: expected Sequence")
    checked = [verify_git_artifact_provenance_envelope(p) for p in provs]
    pairs = [(p["repository"], p["path"]) for p in checked]
    if len(pairs) != len(expected_paths) or set(pairs) != set(expected_paths):
        raise ValueError(f"{label}: (repository, path) set mismatch")
    ordered = sorted(checked, key=lambda p: canonicalize([p["repository"], p["path"]]))
    return [{k: p[k] for k in ("repository", "commit_sha", "path", "git_blob_oid", "file_content_sha256")} for p in ordered]


def compute_parser_code_digest(provs: Sequence[Mapping[str, Any]]) -> str:
    return json_digest({"kind": "smart_ads/parser_code_digest/v1", "artifacts": _artifact_identities(provs, PARSER_ARTIFACT_PATHS, "parser_provs")})


def compute_adapter_code_digest(provs: Sequence[Mapping[str, Any]]) -> str:
    return json_digest({"kind": "smart_ads/adapter_code_digest/v1", "artifacts": _artifact_identities(provs, ADAPTER_ARTIFACT_PATHS, "adapter_provs")})


def compute_mapping_rules_digest(provs: Sequence[Mapping[str, Any]], metric_source_mappings: Mapping[str, str]) -> str:
    if not isinstance(metric_source_mappings, Mapping) or not metric_source_mappings:
        raise ValueError("metric_source_mappings: expected non-empty Mapping")
    norm = {_opaque_ref_str(k, "metric", expected_prefix="metric"): _strict_str(v, "src_metric") for k, v in metric_source_mappings.items()}
    if any(_SOURCE_METRIC_RE.fullmatch(v) is None for v in norm.values()):
        raise ValueError("metric_source_mappings: invalid source_metric_ref")
    return json_digest({"kind": "smart_ads/mapping_rules_digest/v1", "artifacts": _artifact_identities(provs, MAPPING_ARTIFACT_PATHS, "mapping_provs"), "metric_source_mappings": norm})


def resolve_7a_smart_ads_git_blobs(repo_root: Path, source_commit_sha: str) -> Mapping[str, bytes]:
    if not isinstance(repo_root, (str, os.PathLike)):
        raise ValueError("repo_root: expected filesystem path")
    repo_dir = Path(repo_root)
    if repo_dir.is_symlink() or not repo_dir.is_dir():
        raise ValueError(f"repo_root: expected non-symlink directory at {repo_dir}")
    _hex40_str(source_commit_sha, "source_commit_sha")
    if run_git_offline(repo_dir, "rev-parse", "--verify", f"{source_commit_sha}^{{commit}}").stdout.decode("utf-8", errors="replace").strip() != source_commit_sha:
        raise ValueError(f"source_commit_sha {source_commit_sha} not found in {repo_dir}")
    return MappingProxyType({rel: run_git_offline(repo_dir, "cat-file", "blob", f"{source_commit_sha}:{rel}").stdout for rel in SMART_ADS_7A_GIT_PATHS})


def _validate_7a_case_dict(raw_case: object, label: str) -> dict[str, Any]:
    c = dict(raw_case) if isinstance(raw_case, Mapping) else {}
    exact_fields(c, _CASE_16_KEYS, label)
    _strict_str(c["case_id"], f"{label}.case_id")
    _sha256_str(c["admitted_collection_digest"], f"{label}.admitted_collection_digest")
    inv_loc = copy.deepcopy(dict(c["expected_resource_inventory_locator"])) if isinstance(c["expected_resource_inventory_locator"], Mapping) else {}
    validate_locator(inv_loc, EXPECTED_RESOURCE_INVENTORY_SCHEMA)
    if type(c["source_contract_ref"]) is not str or _SRC_CONTRACT_RE.fullmatch(c["source_contract_ref"]) is None:
        raise ValueError(f"{label}.source_contract_ref: invalid")
    _opaque_ref_str(c["sandbox_instance_ref"], f"{label}.sandbox_instance_ref")
    _sha256_str(c["execution_binding_digest"], f"{label}.execution_binding_digest")
    if _utc_sec_micros(c["started_at_utc"], "start") > _utc_sec_micros(c["ended_at_utc"], "end"):
        raise ValueError(f"{label}: started_at_utc > ended_at_utc")
    rb = _validate_runtime_readback_dict(c["runtime_readback"], f"{label}.runtime_readback")
    lim = _validate_resource_limits_dict(c["effective_resource_limits"], f"{label}.effective_resource_limits")
    u, t = _validate_usage_and_termination(c["usage"], c["termination"], label)
    if rb["seccomp_enforced_before_entry"] is not True or t["supervisor_terminated_cgroup"] is not False or t["cause"] != "clean_exit" or t["exit_code"] != 0 or t["signal"] is not None or t["force_kill_used"] is not False or any(evaluate_breach_predicates(u, t).values()):
        raise ValueError(f"{label}: positive 7A sandbox run violated clean-exit/seccomp/ceiling invariants")
    batch = validate_provider_observation_batch_dict(c["observation_batch"], label=f"{label}.observation_batch")
    if c["expected_completeness_status"] not in _COMPLETENESS_SET or c["observed_completeness_status"] != c["expected_completeness_status"]:
        raise ValueError(f"{label}: completeness status invalid or mismatched")
    if c["observed_completeness_status"] == "complete":
        _sha256_str(c["normalized_fact_set_digest"], f"{label}.normalized_fact_set_digest")
    elif c["normalized_fact_set_digest"] is not None:
        raise ValueError(f"{label}.normalized_fact_set_digest: must be None when status != 'complete'")
    return {**c, "expected_resource_inventory_locator": inv_loc, "runtime_readback": rb, "effective_resource_limits": lim, "usage": u, "termination": t, "observation_batch": batch}


def compute_7a_case_execution_binding_digest(*, case: Mapping[str, Any], wheel_digest: str, corpus_digest: str, sealed_sandbox_profile_digest: str) -> str:
    c = _validate_7a_case_dict(case, "case")
    for name, val in (("wheel_digest", wheel_digest), ("corpus_digest", corpus_digest), ("sealed_sandbox_profile_digest", sealed_sandbox_profile_digest)):
        _sha256_str(val, name)
    return json_digest({
        "case_id": c["case_id"], "sandbox_instance_ref": c["sandbox_instance_ref"], "started_at_utc": c["started_at_utc"], "ended_at_utc": c["ended_at_utc"],
        "wheel_digest": wheel_digest, "corpus_digest": corpus_digest, "admitted_collection_digest": c["admitted_collection_digest"],
        "expected_resource_inventory_digest": c["expected_resource_inventory_locator"]["content_digest"], "sealed_sandbox_profile_digest": sealed_sandbox_profile_digest,
        "runtime_readback": c["runtime_readback"], "effective_resource_limits": c["effective_resource_limits"], "usage": c["usage"], "termination": c["termination"], "observation_batch": c["observation_batch"],
    })


def _validate_capability_and_evidence(cap_raw: object, ev_raw: object, certified_us: int) -> tuple[dict[str, Any], dict[str, Any]]:
    cap = dict(cap_raw) if isinstance(cap_raw, Mapping) else {}
    exact_fields(cap, {"capability_ref", "resource_scope_ref", "driver_id", "driver_contract_locator", "driver_contract_digest", "registry_snapshot_locator", "required_metrics"}, "capability")
    _opaque_ref_str(cap["capability_ref"], "capability_ref", expected_prefix="cap")
    _opaque_ref_str(cap["resource_scope_ref"], "resource_scope_ref", expected_prefix="scope")
    _exact_str(cap["driver_id"], "pipeboard_hosted", "driver_id")
    validate_locator(dict(cap["driver_contract_locator"]), PIPEBOARD_CONTRACT_SCHEMA)
    validate_locator(dict(cap["registry_snapshot_locator"]), PRIVATE_REGISTRY_SNAPSHOT_SCHEMA)
    _exact_str(cap["driver_contract_digest"], cap["driver_contract_locator"]["content_digest"], "driver_contract_digest")
    if type(cap["required_metrics"]) is not list or any(type(m) is not str for m in cap["required_metrics"]) or cap["required_metrics"] != list(_PHASE1_METRICS):
        raise ValueError("capability.required_metrics: expected exact Phase 1 sorted metrics")
    ev = dict(ev_raw) if isinstance(ev_raw, Mapping) else {}
    exact_fields(ev, {"corpus_git_locator", "corpus_digest", "regression_fixture", "cases"}, "fixture_evidence")
    validate_locator(dict(ev["corpus_git_locator"]), GIT_ARTIFACT_PROVENANCE_SCHEMA)
    _sha256_str(ev["corpus_digest"], "corpus_digest")
    exp_reg_fix = build_canonical_regression_fixture(cap["registry_snapshot_locator"]["content_digest"])
    if not isinstance(ev["regression_fixture"], Mapping) or canonicalize(dict(ev["regression_fixture"])) != canonicalize(exp_reg_fix) or type(ev["cases"]) is not list or not ev["cases"]:
        raise ValueError("fixture_evidence: regression_fixture or cases invalid")
    cases = [_validate_7a_case_dict(c, f"cases[{i}]") for i, c in enumerate(ev["cases"])]
    ids = [c["case_id"].encode("utf-8") for c in cases]
    if ids != sorted(ids) or len(set(ids)) != len(ids) or len({c["sandbox_instance_ref"] for c in cases}) != len(cases) or not _COMPLETENESS_SET.issubset({c["observed_completeness_status"] for c in cases}):
        raise ValueError("fixture_evidence.cases: ordering, uniqueness, or status coverage violation")
    exp_src = f"opaque-driver-contract:{cap['driver_contract_digest']}"
    for c in cases:
        if c["source_contract_ref"] != exp_src or not (_utc_sec_micros(c["started_at_utc"], "s") <= parse_utc6_micros(c["observation_batch"]["retrieval_context"]["retrieved_at_utc"], "r") <= _utc_sec_micros(c["ended_at_utc"], "e") <= certified_us):
            raise ValueError("fixture_evidence.cases: source_contract_ref or chronology mismatch")
    return copy.deepcopy(cap), {"corpus_git_locator": copy.deepcopy(dict(ev["corpus_git_locator"])), "corpus_digest": ev["corpus_digest"], "regression_fixture": exp_reg_fix, "cases": cases}


def _build_cert_common_payload(**kw: Any) -> dict[str, Any]:
    run_ctx = copy.deepcopy(dict(kw["migration_run_context_locator"]))
    validate_locator(run_ctx, _RUN_CONTEXT_SCHEMA)
    _strict_str(kw["build_run_id"], "build_run_id")
    cert_us = _utc_sec_micros(kw["certified_at_utc"], "certified_at_utc")
    _exact_str(kw.get("certified_state", "fixture_certified"), "fixture_certified", "certified_state")
    _hex40_str(kw["source_commit_sha"], "source_commit_sha")
    for k in ("build_backend_digest", "schema_bundle_digest", "wheel_digest", "resource_mapping_contract_digest", "parser_code_digest", "adapter_code_digest", "mapping_rules_digest"):
        _sha256_str(kw[k], k)
    p_locs, a_locs, m_locs = sort_git_provenance_locators(kw["parser_artifact_locators"]), sort_git_provenance_locators(kw["adapter_artifact_locators"]), sort_git_provenance_locators(kw["mapping_artifact_locators"])
    if (len(p_locs), len(a_locs), len(m_locs)) != (len(PARSER_ARTIFACT_PATHS), len(ADAPTER_ARTIFACT_PATHS), len(MAPPING_ARTIFACT_PATHS)) or [canonicalize(dict(x)) for x in kw["parser_artifact_locators"]] != [canonicalize(x) for x in p_locs] or [canonicalize(dict(x)) for x in kw["adapter_artifact_locators"]] != [canonicalize(x) for x in a_locs] or [canonicalize(dict(x)) for x in kw["mapping_artifact_locators"]] != [canonicalize(x) for x in m_locs]:
        raise ValueError("certification_7a_record: git provenance locator arrays must be pre-sorted with exact arity")
    cap, ev = _validate_capability_and_evidence(kw["capability"], kw["fixture_evidence"], cert_us)
    return {
        "migration_run_context_locator": run_ctx, "build_run_id": kw["build_run_id"], "certified_at_utc": kw["certified_at_utc"],
        "certified_state": "fixture_certified", "source_commit_sha": kw["source_commit_sha"], "build_backend_digest": kw["build_backend_digest"],
        "schema_bundle_digest": kw["schema_bundle_digest"], "wheel_digest": kw["wheel_digest"], "resource_mapping_contract_digest": kw["resource_mapping_contract_digest"],
        "capability": cap, "parser_artifact_locators": p_locs, "parser_code_digest": kw["parser_code_digest"],
        "adapter_artifact_locators": a_locs, "adapter_code_digest": kw["adapter_code_digest"],
        "mapping_artifact_locators": m_locs, "mapping_rules_digest": kw["mapping_rules_digest"], "fixture_evidence": ev,
    }


def build_certification_7a_record_envelope(
    *, migration_run_context_locator: Mapping[str, Any], sealed_sandbox_profile_locator: Mapping[str, Any],
    wheel_build_provenance_locator: Mapping[str, Any], wheel_boundary_report_locator: Mapping[str, Any],
    negative_security_test_report_locator: Mapping[str, Any], build_run_id: str, certified_at_utc: str,
    source_commit_sha: str, build_backend_digest: str, schema_bundle_digest: str, wheel_digest: str,
    resource_mapping_contract_digest: str, capability: Mapping[str, Any], parser_artifact_locators: Sequence[Mapping[str, Any]],
    parser_code_digest: str, adapter_artifact_locators: Sequence[Mapping[str, Any]], adapter_code_digest: str,
    mapping_artifact_locators: Sequence[Mapping[str, Any]], mapping_rules_digest: str, fixture_evidence: Mapping[str, Any],
    registry_locator: Mapping[str, Any], signer_key_id: str, certified_state: str = "fixture_certified",
) -> dict[str, Any]:
    locs = {
        "sealed_sandbox_profile_locator": (copy.deepcopy(dict(sealed_sandbox_profile_locator)), SANDBOX_PROFILE_SCHEMA),
        "wheel_build_provenance_locator": (copy.deepcopy(dict(wheel_build_provenance_locator)), WHEEL_BUILD_PROVENANCE_SCHEMA),
        "wheel_boundary_report_locator": (copy.deepcopy(dict(wheel_boundary_report_locator)), WHEEL_BOUNDARY_REPORT_SCHEMA),
        "negative_security_test_report_locator": (copy.deepcopy(dict(negative_security_test_report_locator)), NEGATIVE_SECURITY_REPORT_SCHEMA),
    }
    for d_loc, exp_t in locs.values():
        validate_locator(d_loc, exp_t)
    reg_loc = copy.deepcopy(dict(registry_locator))
    validate_locator(reg_loc, _KEY_REGISTRY_SCHEMA)
    _key_id_str(signer_key_id, "signer_key_id")
    common = _build_cert_common_payload(
        migration_run_context_locator=migration_run_context_locator, build_run_id=build_run_id, certified_at_utc=certified_at_utc,
        source_commit_sha=source_commit_sha, build_backend_digest=build_backend_digest, schema_bundle_digest=schema_bundle_digest,
        wheel_digest=wheel_digest, resource_mapping_contract_digest=resource_mapping_contract_digest, capability=capability,
        parser_artifact_locators=parser_artifact_locators, parser_code_digest=parser_code_digest,
        adapter_artifact_locators=adapter_artifact_locators, adapter_code_digest=adapter_code_digest,
        mapping_artifact_locators=mapping_artifact_locators, mapping_rules_digest=mapping_rules_digest,
        fixture_evidence=fixture_evidence, certified_state=certified_state,
    )
    env = {"$schema": CERTIFICATION_7A_RECORD_SCHEMA, **common, **{k: v[0] for k, v in locs.items()}, "integrity": {"key_id": signer_key_id, "key_registry_snapshot_locator": reg_loc}}
    loads_strict(canonicalize(env).decode("utf-8"))
    return env


def build_certification_7a_record_candidate(
    *, migration_run_context_locator: Mapping[str, Any], sealed_sandbox_profile_candidate_ref: Mapping[str, Any],
    wheel_build_provenance_candidate_ref: Mapping[str, Any], wheel_boundary_report_candidate_ref: Mapping[str, Any],
    negative_security_test_report_candidate_ref: Mapping[str, Any], build_run_id: str, certified_at_utc: str,
    source_commit_sha: str, build_backend_digest: str, schema_bundle_digest: str, wheel_digest: str,
    resource_mapping_contract_digest: str, capability: Mapping[str, Any], parser_artifact_locators: Sequence[Mapping[str, Any]],
    parser_code_digest: str, adapter_artifact_locators: Sequence[Mapping[str, Any]], adapter_code_digest: str,
    mapping_artifact_locators: Sequence[Mapping[str, Any]], mapping_rules_digest: str, fixture_evidence: Mapping[str, Any],
    certified_state: str = "fixture_certified",
) -> dict[str, Any]:
    refs = {
        "sealed_sandbox_profile_candidate_ref": (copy.deepcopy(dict(sealed_sandbox_profile_candidate_ref)), SANDBOX_PROFILE_SCHEMA),
        "wheel_build_provenance_candidate_ref": (copy.deepcopy(dict(wheel_build_provenance_candidate_ref)), WHEEL_BUILD_PROVENANCE_SCHEMA),
        "wheel_boundary_report_candidate_ref": (copy.deepcopy(dict(wheel_boundary_report_candidate_ref)), WHEEL_BOUNDARY_REPORT_SCHEMA),
        "negative_security_test_report_candidate_ref": (copy.deepcopy(dict(negative_security_test_report_candidate_ref)), NEGATIVE_SECURITY_REPORT_SCHEMA),
    }
    for d_ref, exp_t in refs.values():
        verify_local_candidate_ref(d_ref, expected_schema=exp_t)
    common = _build_cert_common_payload(
        migration_run_context_locator=migration_run_context_locator, build_run_id=build_run_id, certified_at_utc=certified_at_utc,
        source_commit_sha=source_commit_sha, build_backend_digest=build_backend_digest, schema_bundle_digest=schema_bundle_digest,
        wheel_digest=wheel_digest, resource_mapping_contract_digest=resource_mapping_contract_digest, capability=capability,
        parser_artifact_locators=parser_artifact_locators, parser_code_digest=parser_code_digest,
        adapter_artifact_locators=adapter_artifact_locators, adapter_code_digest=adapter_code_digest,
        mapping_artifact_locators=mapping_artifact_locators, mapping_rules_digest=mapping_rules_digest,
        fixture_evidence=fixture_evidence, certified_state=certified_state,
    )
    payload = {**common, **{k: v[0] for k, v in refs.items()}}
    loads_strict(canonicalize(payload).decode("utf-8"))
    return wrap_local_candidate(CERTIFICATION_7A_RECORD_SCHEMA, payload)


def _get_verified_store_envelope(store: Store, locator: Mapping[str, Any], expected_schema: str, *, require_signed: bool = True) -> dict[str, Any]:
    loc_d = dict(locator)
    validate_locator(loc_d, expected_schema)
    obj = store.get(loc_d, expected_type=expected_schema)
    _verify_p1_integrity(obj, label=expected_schema, require_signed=require_signed)
    return copy.deepcopy(obj)


def _verify_registry_and_contract_from_store(store: Store, cap: Mapping[str, Any], rmc_digest: str) -> tuple[dict[str, Any], dict[str, Any]]:
    snap = _get_verified_store_envelope(store, cap["registry_snapshot_locator"], PRIVATE_REGISTRY_SNAPSHOT_SCHEMA)
    validate_private_registry_snapshot_payload(snap)
    if rmc_digest != snap["resource_mapping_contract_digest"]:
        raise ValueError("private_registry_snapshot: resource_mapping_contract_digest mismatch")
    drv = _get_verified_store_envelope(store, cap["driver_contract_locator"], PIPEBOARD_CONTRACT_SCHEMA)
    exact_fields(drv, {"$schema", "contract_id", "driver_id", "legacy_source_packet", "upstream_reference", "transport_limits", "metric_source_mappings", "integrity"}, "pipeboard_phase1_contract")
    pkt = dict(drv["legacy_source_packet"]) if isinstance(drv["legacy_source_packet"], Mapping) else {}
    exact_fields(pkt, {"repository", "commit_sha", "members", "packet_digest"}, "legacy_source_packet")
    exp_up = {"repository": "pipeboard-co/meta-ads-mcp", "commit_sha": "2ef198e266ca6a37b6dc2c42335f0a0885002771", "path": "meta_ads_mcp/core/insights.py", "symbol": "get_insights", "hosted_parity_proven": False}
    if (
        _DRV_ID_RE.fullmatch(_strict_str(drv["contract_id"], "cid")) is None or drv["driver_id"] != "pipeboard_hosted"
        or pkt["repository"] != PINNED_LEGACY_REPO or pkt["commit_sha"] != PINNED_LEGACY_COMMIT
        or pkt["packet_digest"] != json_digest({k: pkt[k] for k in ("repository", "commit_sha", "members")})
        or not isinstance(drv["upstream_reference"], Mapping) or canonicalize(dict(drv["upstream_reference"])) != canonicalize(exp_up)
        or not isinstance(drv["transport_limits"], Mapping) or canonicalize(dict(drv["transport_limits"])) != canonicalize(dict(DEFAULT_PIPEBOARD_TRANSPORT_LIMITS))
        or not isinstance(drv["metric_source_mappings"], Mapping) or canonicalize(dict(drv["metric_source_mappings"])) != canonicalize(dict(PIPEBOARD_PHASE1_METRIC_SOURCE_MAPPINGS))
    ):
        raise ValueError("pipeboard_phase1_contract: pinned contract invariants violated")
    mc = [e for e in snap["capabilities"] if e["capability_ref"] == cap["capability_ref"] and e["resource_scope_ref"] == cap["resource_scope_ref"]]
    if len(mc) != 1 or mc[0]["state"] != "declared" or mc[0]["driver_id"] != "pipeboard_hosted" or canonicalize(mc[0]["driver_contract_locator"]) != canonicalize(cap["driver_contract_locator"]) or mc[0]["driver_contract_digest"] != cap["driver_contract_digest"] or canonicalize(mc[0]["required_metrics"]) != canonicalize(cap["required_metrics"]):
        raise ValueError("certification_7a_record.capability: snapshot capability mismatch")
    return snap, drv


def _verify_all_13_git_provenances(
    store: Store, payload: Mapping[str, Any], drv: Mapping[str, Any], *, wheel_members: Mapping[str, bytes],
    corpus_bytes: bytes, git_blobs: Mapping[str, bytes], d26_blobs: Mapping[str, bytes], certified_us: int,
) -> list[dict[str, Any]]:
    c_repo, c_path = CORPUS_GIT_PATH
    if c_path not in git_blobs or corpus_bytes != git_blobs[c_path] or digest(corpus_bytes) != payload["fixture_evidence"]["corpus_digest"]:
        raise ValueError("corpus_bytes: mismatch against resolved_git_blobs or fixture_evidence.corpus_digest")
    c_loc = payload["fixture_evidence"]["corpus_git_locator"]
    c_prov = verify_git_artifact_provenance_envelope(_get_verified_store_envelope(store, c_loc, GIT_ARTIFACT_PROVENANCE_SCHEMA), expected_bytes=corpus_bytes)
    if (c_prov["repository"], c_prov["path"], c_prov["commit_sha"]) != (c_repo, c_path, payload["source_commit_sha"]) or _utc_sec_micros(c_prov["resolved_at_utc"], "c.res") > certified_us:
        raise ValueError("corpus_git_locator: provenance metadata mismatch")
    unique_locs: dict[bytes, dict[str, Any]] = {canonicalize(c_loc): copy.deepcopy(c_loc)}
    reducer_loc_b, members = b"", drv["legacy_source_packet"]["members"]
    if type(members) is not list or len(members) != len(PINNED_PIPEBOARD_D26_SPECS):
        raise ValueError("legacy_source_packet.members: expected 5 pinned members")
    for m, (role, r_path, oid, sha) in zip(members, PINNED_PIPEBOARD_D26_SPECS, strict=True):
        if not isinstance(m, Mapping):
            raise ValueError("legacy_source_packet.member: expected Mapping")
        exact_fields(dict(m), {"role", "repository", "commit_sha", "path", "git_blob_oid", "file_content_sha256", "git_artifact_provenance_locator"}, "legacy_source_packet.member")
        m_loc = m["git_artifact_provenance_locator"]
        d_prov = verify_git_artifact_provenance_envelope(_get_verified_store_envelope(store, m_loc, GIT_ARTIFACT_PROVENANCE_SCHEMA), expected_bytes=d26_blobs[r_path], require_signed=True)
        if (m["role"], m["repository"], m["commit_sha"], m["path"], m["git_blob_oid"], m["file_content_sha256"]) != (role, PINNED_LEGACY_REPO, PINNED_LEGACY_COMMIT, r_path, oid, sha) or (d_prov["repository"], d_prov["commit_sha"], d_prov["path"], d_prov["git_blob_oid"], d_prov["file_content_sha256"]) != (PINNED_LEGACY_REPO, PINNED_LEGACY_COMMIT, r_path, oid, sha) or _utc_sec_micros(d_prov["resolved_at_utc"], "d.res") > certified_us:
            raise ValueError(f"d26[{role}]: pinned legacy provenance mismatch")
        unique_locs[canonicalize(m_loc)] = copy.deepcopy(m_loc)
        if role == "reducer":
            reducer_loc_b = canonicalize(m_loc)
    return _verify_code_provenance_groups(store, payload, drv, wheel_members, git_blobs, d26_blobs, certified_us, reducer_loc_b, unique_locs)


def _verify_code_provenance_groups(
    store: Store, payload: Mapping[str, Any], drv: Mapping[str, Any], wheel_members: Mapping[str, bytes],
    git_blobs: Mapping[str, bytes], d26_blobs: Mapping[str, bytes], certified_us: int,
    reducer_loc_b: bytes, unique_locs: dict[bytes, dict[str, Any]],
) -> list[dict[str, Any]]:
    if not reducer_loc_b or reducer_loc_b not in {canonicalize(x) for x in payload["parser_artifact_locators"]}:
        raise ValueError("parser_artifact_locators: missing legacy reducer provenance locator")
    groups: dict[str, list[dict[str, Any]]] = {}
    for g_key in ("parser_artifact_locators", "adapter_artifact_locators", "mapping_artifact_locators"):
        provs: list[dict[str, Any]] = []
        for loc in payload[g_key]:
            prov = verify_git_artifact_provenance_envelope(_get_verified_store_envelope(store, loc, GIT_ARTIFACT_PROVENANCE_SCHEMA))
            if _utc_sec_micros(prov["resolved_at_utc"], "res") > certified_us:
                raise ValueError(f"{g_key}: resolved_at_utc > certified_at_utc")
            if (prov["repository"], prov["path"]) == (PINNED_LEGACY_REPO, "scripts/operator/meta_daily_contract.py"):
                if canonicalize(loc) != reducer_loc_b or prov["commit_sha"] != PINNED_LEGACY_COMMIT:
                    raise ValueError(f"{g_key}: legacy reducer provenance mismatch")
                verify_git_artifact_provenance_envelope(prov, expected_bytes=d26_blobs[prov["path"]])
            else:
                rel = prov["path"][4:] if prov["path"].startswith("src/") else ""
                if prov["repository"] != DEFAULT_REPOSITORY or prov["commit_sha"] != payload["source_commit_sha"] or prov["path"] not in git_blobs or rel not in wheel_members or wheel_members[rel] != git_blobs[prov["path"]]:
                    raise ValueError(f"{g_key}: wheel member or git blob mismatch for {prov['path']!r}")
                verify_git_artifact_provenance_envelope(prov, expected_bytes=wheel_members[rel])
            unique_locs[canonicalize(loc)] = copy.deepcopy(loc)
            provs.append(prov)
        groups[g_key] = provs
    if len(unique_locs) != 13 or payload["parser_code_digest"] != compute_parser_code_digest(groups["parser_artifact_locators"]) or payload["adapter_code_digest"] != compute_adapter_code_digest(groups["adapter_artifact_locators"]) or payload["mapping_rules_digest"] != compute_mapping_rules_digest(groups["mapping_artifact_locators"], drv["metric_source_mappings"]):
        raise ValueError("certification_7a_record: 13 git provenances or code/mapping digest mismatch")
    return [unique_locs[k] for k in sorted(unique_locs.keys())]


def _resolve_store_sandbox_locator_for_candidate(store: Store, sbx_payload: Mapping[str, Any], explicit_loc: Mapping[str, Any] | None) -> dict[str, Any]:
    target = json_digest(dict(sbx_payload))
    if explicit_loc is not None:
        env = _get_verified_store_envelope(store, explicit_loc, SANDBOX_PROFILE_SCHEMA)
        if json_digest({k: v for k, v in env.items() if k not in {"$schema", "integrity"}}) != target:
            raise ValueError("sealed_sandbox_profile_store_locator: payload digest mismatch against candidate")
        return copy.deepcopy(dict(explicit_loc))
    sha_dir = store.root / "sha256"
    matches: list[dict[str, Any]] = []
    for p in sorted(sha_dir.glob("*.json")) if sha_dir.is_dir() else ():
        obj = loads_strict(p.read_text(encoding="utf-8"))
        if isinstance(obj, dict) and obj.get("$schema") == SANDBOX_PROFILE_SCHEMA and isinstance(obj.get("integrity"), Mapping) and "signature_base64" in obj["integrity"]:
            if json_digest({k: v for k, v in obj.items() if k not in {"$schema", "integrity"}}) == target:
                loc = make_locator(SANDBOX_PROFILE_SCHEMA, canonicalize(obj))
                _get_verified_store_envelope(store, loc, SANDBOX_PROFILE_SCHEMA)
                matches.append(loc)
    if len(matches) != 1:
        raise ValueError("store: expected unique matching sealed_sandbox_profile/v1 envelope for candidate replay")
    return matches[0]


def _resolve_envelope_stage7_from_store(
    store: Store, raw_payload: Mapping[str, Any], *, sandbox_profile: Mapping[str, Any] | None,
    wheel_provenance: Mapping[str, Any] | None, wheel_boundary_report: Mapping[str, Any] | None,
    negative_security_report: Mapping[str, Any] | None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    sbx_loc = copy.deepcopy(raw_payload["sealed_sandbox_profile_locator"])
    sbx_obj = _get_verified_store_envelope(store, sbx_loc, SANDBOX_PROFILE_SCHEMA)
    prov_obj = _get_verified_store_envelope(store, raw_payload["wheel_build_provenance_locator"], WHEEL_BUILD_PROVENANCE_SCHEMA)
    bound_obj = _get_verified_store_envelope(store, raw_payload["wheel_boundary_report_locator"], WHEEL_BOUNDARY_REPORT_SCHEMA)
    neg_obj = _get_verified_store_envelope(store, raw_payload["negative_security_test_report_locator"], NEGATIVE_SECURITY_REPORT_SCHEMA)
    for caller_obj, stored_obj, lbl in (
        (sandbox_profile, sbx_obj, "sandbox_profile"),
        (wheel_provenance, prov_obj, "wheel_provenance"),
        (wheel_boundary_report, bound_obj, "wheel_boundary_report"),
        (negative_security_report, neg_obj, "negative_security_report"),
    ):
        if caller_obj is not None and (not isinstance(caller_obj, Mapping) or canonicalize(dict(caller_obj)) != canonicalize(stored_obj)):
            raise ValueError(f"{lbl}: caller-supplied envelope diverges from Store locator object")
    exact_fields(dict(bound_obj), _BOUNDARY_ENVELOPE_FIELDS, "wheel_boundary_report")
    bound_payload = {k: bound_obj[k] for k in bound_obj if k not in {"$schema", "integrity"}}
    if canonicalize(bound_payload["wheel_build_provenance_locator"]) != canonicalize(raw_payload["wheel_build_provenance_locator"]) or canonicalize(raw_payload["wheel_build_provenance_locator"]) != canonicalize(neg_obj["wheel_build_provenance_locator"]) or canonicalize(sbx_loc) != canonicalize(neg_obj["sealed_sandbox_profile_locator"]):
        raise ValueError("certification_7a_record: Stage 7 envelope locator cross-binding mismatch")
    return sbx_loc, sbx_obj, prov_obj, bound_obj, neg_obj, bound_payload


def _verify_stage7_and_wheel_archive_passively(
    mode: str, raw_payload: Mapping[str, Any], store: Store, wheel_bytes: bytes, *,
    sandbox_profile: Mapping[str, Any] | None, wheel_provenance: Mapping[str, Any] | None,
    wheel_boundary_report: Mapping[str, Any] | None, negative_security_report: Mapping[str, Any] | None,
    explicit_sbx_store_loc: Mapping[str, Any] | None,
) -> tuple[dict[str, bytes], dict[str, Any], dict[str, Any], dict[str, Any], str, dict[str, Any]]:
    whl_digest = digest(wheel_bytes)
    if mode == "envelope":
        sbx_loc, sbx_obj, prov_obj, bound_obj, neg_obj, bound_payload = _resolve_envelope_stage7_from_store(
            store, raw_payload, sandbox_profile=sandbox_profile, wheel_provenance=wheel_provenance,
            wheel_boundary_report=wheel_boundary_report, negative_security_report=negative_security_report,
        )
        neg_meta: Mapping[str, Any] = neg_obj
    else:
        if sandbox_profile is None or wheel_provenance is None or wheel_boundary_report is None or negative_security_report is None:
            raise ValueError("candidate mode requires sandbox_profile, wheel_provenance, wheel_boundary_report, and negative_security_report")
        sbx_obj, prov_obj, bound_obj, neg_obj = sandbox_profile, wheel_provenance, wheel_boundary_report, negative_security_report
        bound_payload = unwrap_local_candidate(dict(bound_obj), expected_schema=WHEEL_BOUNDARY_REPORT_SCHEMA)
        exact_fields(bound_payload, _BOUNDARY_CANDIDATE_PAYLOAD_FIELDS, "wheel_boundary_report_candidate")
        neg_cand_p = unwrap_local_candidate(dict(neg_obj), expected_schema=NEGATIVE_SECURITY_REPORT_SCHEMA)
        if canonicalize(build_local_candidate_ref(dict(bound_obj))) != canonicalize(raw_payload["wheel_boundary_report_candidate_ref"]) or canonicalize(build_local_candidate_ref(dict(neg_obj))) != canonicalize(raw_payload["negative_security_test_report_candidate_ref"]) or canonicalize(bound_payload["wheel_build_provenance_candidate_ref"]) != canonicalize(raw_payload["wheel_build_provenance_candidate_ref"]) or canonicalize(raw_payload["wheel_build_provenance_candidate_ref"]) != canonicalize(neg_cand_p["wheel_build_provenance_candidate_ref"]) or canonicalize(raw_payload["sealed_sandbox_profile_candidate_ref"]) != canonicalize(neg_cand_p["sealed_sandbox_profile_candidate_ref"]):
            raise ValueError("certification_7a_record: Stage 7 candidate_ref cross-binding mismatch")
        sbx_cand_p = unwrap_local_candidate(dict(sbx_obj), expected_schema=SANDBOX_PROFILE_SCHEMA) if sbx_obj.get("artifact_kind") == LOCAL_CANDIDATE_KIND else dict(sbx_obj)
        sbx_loc, neg_meta = _resolve_store_sandbox_locator_for_candidate(store, sbx_cand_p, explicit_sbx_store_loc), neg_cand_p
    prov_p = extract_provenance_payload(prov_obj)
    ctx_b = canonicalize(raw_payload["migration_run_context_locator"])
    if not ({raw_payload["wheel_digest"], prov_p["wheel_digest"], bound_payload.get("wheel_digest"), neg_meta.get("wheel_digest")} == {whl_digest} and all(isinstance(x, Mapping) and canonicalize(dict(x)) == ctx_b for x in (prov_p["migration_run_context_locator"], bound_payload.get("migration_run_context_locator"), neg_meta.get("migration_run_context_locator")))):
        raise ValueError("certification_7a_record: wheel_digest or migration_run_context_locator mismatch before archive extraction")
    members, rec_entries, rec_digest, mods = _read_and_validate_wheel_archive(wheel_bytes)
    neg_p = _check_passive_boundary_and_negative(raw_payload, bound_payload, sbx_obj, prov_obj, prov_p, neg_obj, wheel_bytes, whl_digest, rec_entries, rec_digest, mods)
    sbx_p = unwrap_local_candidate(dict(sbx_obj), expected_schema=SANDBOX_PROFILE_SCHEMA) if sbx_obj.get("artifact_kind") == LOCAL_CANDIDATE_KIND else {k: sbx_obj[k] for k in sbx_obj if k not in {"$schema", "integrity"}}
    return members, sbx_p, prov_p, neg_p, json_digest({k: sbx_p[k] for k in _SPEC_17_FIELDS}), sbx_loc


def _check_passive_boundary_and_negative(
    raw_payload: Mapping[str, Any], bound_payload: Mapping[str, Any], sbx_obj: Mapping[str, Any],
    prov_obj: Mapping[str, Any], prov_p: Mapping[str, Any], neg_obj: Mapping[str, Any], wheel_bytes: bytes, whl_digest: str,
    rec_entries: list[dict[str, Any]], rec_digest: str, mods: list[str],
) -> dict[str, Any]:
    checked_insp = _validate_inspection_dict({k: bound_payload[k] for k in _INSPECTION_FIELDS})
    _utc_sec_micros(bound_payload["verified_at_utc"], "bound.verified_at_utc")
    if (
        checked_insp["wheel_digest"] != whl_digest or canonicalize(checked_insp["sorted_record_entries"]) != canonicalize(rec_entries)
        or checked_insp["sorted_record_digest"] != rec_digest or canonicalize(checked_insp["packaged_modules"]) != canonicalize(mods)
        or bound_payload["repository"] != DEFAULT_REPOSITORY or raw_payload["wheel_digest"] != whl_digest
        or any(raw_payload[k] != prov_p[k] or bound_payload[k] != raw_payload[k] for k in ("build_run_id", "source_commit_sha", "build_backend_digest", "schema_bundle_digest"))
    ):
        raise ValueError("certification_7a_record: passive wheel archive / boundary / provenance mismatch")
    neg_res = verify_negative_security_test_report(neg_obj, sandbox_profile=sbx_obj, wheel_provenance=prov_obj, wheel_bytes=wheel_bytes)
    if _utc_sec_micros(neg_res["executed_at_utc"], "neg.exec") > _utc_sec_micros(raw_payload["certified_at_utc"], "cert"):
        raise ValueError("certification_7a_record: negative_report.executed_at_utc > certified_at_utc")
    return neg_res["payload"]


def _parse_corpus_and_inventories(
    corpus_bytes: bytes, store: Store, snap: Mapping[str, Any], cases: Sequence[Mapping[str, Any]]
) -> tuple[dict[str, Any], dict[tuple[str, str], str], dict[str, str], dict[bytes, dict[str, Any]]]:
    doc = loads_strict(corpus_bytes.decode("utf-8"))
    m = dict(doc) if isinstance(doc, Mapping) else {}
    exact_fields(m, {"$schema", "corpus_id", "key_identity", "private_account_bindings", "tenant_hmac_key_hex", "tenant_ref", "timezone_snapshot", "verified_campaign_pairs", "cases"}, "corpus")
    _exact_str(m["$schema"], PIPEBOARD_7A_CORPUS_SCHEMA, "corpus.$schema")
    _opaque_ref_str(m["corpus_id"], "corpus_id", expected_prefix="corpus")
    if m["tenant_ref"] != snap["tenant_ref"] or m["key_identity"] != snap["key_identity"] or type(m["tenant_hmac_key_hex"]) is not str or _HEX64_RE.fullmatch(m["tenant_hmac_key_hex"]) is None or type(m["private_account_bindings"]) is not list or not m["private_account_bindings"] or type(m["verified_campaign_pairs"]) is not list or len(m["verified_campaign_pairs"]) < 2 or type(m["cases"]) is not list or not m["cases"]:
        raise ValueError("corpus: top-level identity, key, bindings, or cases invalid")
    secret, snap_bnds = bytes.fromhex(m["tenant_hmac_key_hex"]), {b["binding_ref"]: b for b in snap["bindings"]}
    priv_map: dict[tuple[str, str], str] = {}
    for rb in m["private_account_bindings"]:
        bd = dict(rb) if isinstance(rb, Mapping) else {}
        exact_fields(bd, {"binding_ref", "account_ref", "private_object_id"}, "corpus.binding")
        sb = snap_bnds.get(bd["binding_ref"])
        if sb is None or sb["account_ref"] != bd["account_ref"] or sb["driver_id"] != "pipeboard_hosted" or (bd["binding_ref"], bd["account_ref"]) in priv_map:
            raise ValueError("corpus: invalid or duplicate private_account_binding")
        priv_map[(bd["binding_ref"], bd["account_ref"])] = _strict_str(bd["private_object_id"], "obj_id")
    cmap: dict[str, str] = {}
    for rp in m["verified_campaign_pairs"]:
        pd = dict(rp) if isinstance(rp, Mapping) else {}
        exact_fields(pd, {"raw_campaign_id", "resource_ref"}, "corpus.pair")
        if derive_resource_ref(secret_bytes=secret, mapping_version=snap["resource_ref_mapping_version"], domain_separator=snap["domain_separator"], raw_provider_id=pd["raw_campaign_id"]) != pd["resource_ref"] or pd["raw_campaign_id"] in cmap or pd["resource_ref"] in cmap.values():
            raise ValueError("corpus: HMAC resource_ref derivation or bijection collision")
        cmap[pd["raw_campaign_id"]] = pd["resource_ref"]
    return m, priv_map, cmap, _load_verified_inventories(store, snap, set(cmap.values()), cases)


def _load_verified_inventories(store: Store, snap: Mapping[str, Any], known_refs: set[str], cases: Sequence[Mapping[str, Any]]) -> dict[bytes, dict[str, Any]]:
    auth_scopes = {(s["binding_ref"], s["resource_scope_ref"]) for s in snap["authorized_scopes"]}
    snap_bnds = {b["binding_ref"]: b for b in snap["bindings"]}
    inv_map: dict[bytes, dict[str, Any]] = {}
    seen_inv_by_scope_key: dict[tuple[str, str, str, str, str], bytes] = {}
    for c in cases:
        loc = c["expected_resource_inventory_locator"]
        lb = canonicalize(loc)
        if lb not in inv_map:
            inv = verify_expected_resource_inventory_envelope(_get_verified_store_envelope(store, loc, EXPECTED_RESOURCE_INVENTORY_SCHEMA), require_signed=True)
            sb = snap_bnds.get(inv["binding_ref"])
            if inv["tenant_ref"] != snap["tenant_ref"] or sb is None or sb["account_ref"] != inv["account_ref"] or (inv["binding_ref"], inv["resource_scope_ref"]) not in auth_scopes or inv["date_range"]["start_date"] != inv["date_range"]["end_date"] or any(u["resource_ref"] not in known_refs for u in inv["expected_resources"]):
                raise ValueError("expected_resource_inventory: snapshot/scope/resource_ref mismatch")
            inv_map[lb] = inv
        inv = inv_map[lb]
        sk = (inv["binding_ref"], inv["account_ref"], inv["resource_scope_ref"], inv["date_range"]["start_date"], inv["date_range"]["end_date"])
        if seen_inv_by_scope_key.get(sk, lb) != lb:
            raise ValueError("expected_resource_inventory: conflicting inventory locators for admitted scope/date tuple")
        seen_inv_by_scope_key[sk] = lb
    return inv_map


def _replay_all_7a_cases(
    checked_common: Mapping[str, Any], corpus_doc: Mapping[str, Any], snap: Mapping[str, Any], drv: Mapping[str, Any],
    priv_map: Mapping[tuple[str, str], str], cmap: Mapping[str, str], inv_map: Mapping[bytes, dict[str, Any]], ctx: Mapping[str, Any],
) -> None:
    c_cases, r_cases = corpus_doc["cases"], checked_common["fixture_evidence"]["cases"]
    if len(c_cases) != len(r_cases) or len({c.get("admission_id") for c in c_cases if isinstance(c, Mapping)}) != len(c_cases):
        raise ValueError("corpus.cases: count or duplicate admission_id mismatch")
    for cc_raw, rc in zip(c_cases, r_cases, strict=True):
        cc = dict(cc_raw) if isinstance(cc_raw, Mapping) else {}
        exact_fields(cc, {"case_id", "admission_id", "clock_reading", "collection_request", "retrieval_context", "http_response", "expected_completeness_status", "expected_reasons", "expected_error_code"}, "corpus.case")
        cr = dict(cc["clock_reading"]) if isinstance(cc["clock_reading"], Mapping) else {}
        hr = dict(cc["http_response"]) if isinstance(cc["http_response"], Mapping) else {}
        exact_fields(cr, {"attestation", "configured_max_uncertainty_ms"}, "clock_reading")
        exact_fields(hr, {"network_ok", "http_status", "headers", "body_utf8"}, "http_response")
        if cc["case_id"] != rc["case_id"] or rc["sandbox_instance_ref"] in ctx["neg_refs"]:
            raise ValueError("case: case_id mismatch or sandbox_instance_ref collision")
        adm, adm_loc = recompute_fixture_7a_admission(
            collection_request=cc["collection_request"], admission_id=cc["admission_id"], clock_attestation=cr["attestation"],
            configured_max_uncertainty_ms=cr["configured_max_uncertainty_ms"], timezone_snapshot=corpus_doc["timezone_snapshot"],
            registry_snapshot_locator=checked_common["capability"]["registry_snapshot_locator"], registry_snapshot=snap,
            driver_contract_locator=checked_common["capability"]["driver_contract_locator"], driver_contract=drv,
            sealed_sandbox_profile_locator=ctx["sbx_loc"], regression_fixture_locator=ctx["reg_fix_loc"],
        )
        if rc["admitted_collection_digest"] != adm_loc["content_digest"]:
            raise ValueError(f"case[{rc['case_id']}].admitted_collection_digest: mismatch against recomputed admission")
        _verify_single_replayed_case(checked_common, cc, hr, rc, adm, priv_map, cmap, inv_map[canonicalize(rc["expected_resource_inventory_locator"])], drv, ctx)


def _verify_single_replayed_case(
    checked_common: Mapping[str, Any], cc: Mapping[str, Any], hr: Mapping[str, Any], rc: Mapping[str, Any],
    adm: Mapping[str, Any], priv_map: Mapping[tuple[str, str], str], cmap: Mapping[str, str],
    inv: Mapping[str, Any], drv: Mapping[str, Any], ctx: Mapping[str, Any],
) -> None:
    if (
        canonicalize(inv["registry_snapshot_locator"]) != canonicalize(adm["registry_snapshot_locator"])
        or (inv["tenant_ref"], inv["binding_ref"], inv["account_ref"], inv["resource_scope_ref"]) != (adm["tenant_ref"], adm["binding_ref"], adm["account_ref"], adm["resource_scope_ref"])
        or canonicalize(inv["date_range"]) != canonicalize(adm["computed_date_range"])
        or adm["resource_scope_ref"] != checked_common["capability"]["resource_scope_ref"]
        or canonicalize(adm["canonical_query_contract"]["requested_capabilities"]) != canonicalize([checked_common["capability"]["capability_ref"]])
        or canonicalize(adm["canonical_query_contract"]["metric_semantic_refs"]) != canonicalize(checked_common["capability"]["required_metrics"])
        or canonicalize(rc["effective_resource_limits"]) != canonicalize(ctx["sbx_limits"])
        or canonicalize({k: rc["runtime_readback"][k] for k in _SHARED_RUNTIME_16_FIELDS}) != canonicalize({k: ctx["sbx_p"][k] for k in _SHARED_RUNTIME_16_FIELDS})
    ):
        raise ValueError(f"case[{rc['case_id']}]: inventory, capability, or sandbox readback mismatch")
    s_us, e_us = _utc_sec_micros(rc["started_at_utc"], "start"), _utc_sec_micros(rc["ended_at_utc"], "end")
    r_us = parse_utc6_micros(rc["observation_batch"]["retrieval_context"]["retrieved_at_utc"], "ret")
    floor_us = max(ctx["sbx_issued_us"], ctx["prov_built_us"], ctx["snap_issued_us"], _utc_sec_micros(adm["admitted_at_utc"], "adm"))
    if not (floor_us <= s_us <= r_us <= e_us <= ctx["cert_us"] and ctx["sbx_from_us"] <= s_us <= e_us < ctx["sbx_until_us"] and ctx["snap_issued_us"] <= s_us <= e_us <= ctx["cert_us"] < ctx["snap_until_us"]):
        raise ValueError(f"case[{rc['case_id']}]: chronology or validity window violation")
    if rc["execution_binding_digest"] != compute_7a_case_execution_binding_digest(case=rc, wheel_digest=checked_common["wheel_digest"], corpus_digest=checked_common["fixture_evidence"]["corpus_digest"], sealed_sandbox_profile_digest=ctx["sbx_digest"]):
        raise ValueError(f"case[{rc['case_id']}].execution_binding_digest: mismatch")
    priv_id = priv_map.get((adm["binding_ref"], adm["account_ref"]))
    if priv_id is None or type(hr["network_ok"]) is not bool or (hr["http_status"] is not None and type(hr["http_status"]) is not int) or type(hr["headers"]) is not list or any(type(h) is not list or len(h) != 2 for h in hr["headers"]) or type(hr["body_utf8"]) is not str or type(cc["expected_reasons"]) is not list or any(type(r) is not str for r in cc["expected_reasons"]) or (cc["expected_error_code"] is not None and type(cc["expected_error_code"]) is not str):
        raise ValueError(f"case[{rc['case_id']}]: invalid private binding or corpus http_response/expectations")
    batch = transform_pipeboard_response_to_batch_dict(admitted=adm, private_object_id=priv_id, known_campaign_map=cmap, scoped_resource_refs=frozenset(u["resource_ref"] for u in inv["expected_resources"]), retrieval_context=cc["retrieval_context"], network_ok=hr["network_ok"], http_status=hr["http_status"], headers=[(h[0], h[1]) for h in hr["headers"]], body_chunks=[hr["body_utf8"].encode("utf-8")])
    comp = recompute_collection_completeness_dict(expected_resources=inv["expected_resources"], required_metrics=adm["canonical_query_contract"]["metric_semantic_refs"], metric_source_mappings=drv["metric_source_mappings"], batch_dict=batch, admitted_dict=adm)
    exp_errs = [] if cc["expected_error_code"] is None else [cc["expected_error_code"]]
    if canonicalize(batch) != canonicalize(rc["observation_batch"]) or canonicalize([e["error_code"] for e in batch["normalized_errors"]]) != canonicalize(exp_errs) or comp["status"] != rc["observed_completeness_status"] or comp["status"] != cc["expected_completeness_status"] or canonicalize(comp["reasons"]) != canonicalize(cc["expected_reasons"]) or comp["normalized_fact_set_digest"] != rc["normalized_fact_set_digest"]:
        raise ValueError(f"case[{rc['case_id']}]: deterministic offline 7A replay mismatch")


def _unwrap_cert_record(artifact: Mapping[str, Any], *, require_signed_envelope: bool = True) -> tuple[str, dict[str, Any]]:
    if not isinstance(artifact, Mapping):
        raise ValueError("certification_7a_record: expected Mapping")
    d = dict(artifact)
    if d.get("artifact_kind") == LOCAL_CANDIDATE_KIND:
        if "$schema" in d or "integrity" in d:
            raise ValueError("certification_7a_record: candidate must not contain envelope fields")
        payload = unwrap_local_candidate(d, expected_schema=CERTIFICATION_7A_RECORD_SCHEMA)
        exact_fields(payload, _CERT_CAND_21_KEYS, "certification_7a_candidate_payload")
        return "candidate", payload
    if d.get("$schema") == CERTIFICATION_7A_RECORD_SCHEMA and "artifact_kind" not in d:
        exact_fields(d, _CERT_ENV_23_KEYS, "certification_7a_envelope")
        _verify_p1_integrity(d, label="certification_7a_record", require_signed=require_signed_envelope)
        payload = {k: copy.deepcopy(v) for k, v in d.items() if k not in {"$schema", "integrity"}}
        exact_fields(payload, _CERT_ENV_PAYLOAD_21_KEYS, "certification_7a_envelope_payload")
        return "envelope", payload
    raise ValueError("certification_7a_record: expected P1 envelope or gov1_local_candidate")


def verify_certification_7a_replay_bytes(
    artifact: Mapping[str, Any], *, store: Store, wheel_bytes: bytes, corpus_bytes: bytes,
    resolved_git_blobs: Mapping[str, bytes], resolved_d26_blobs: Mapping[str, bytes],
    sandbox_profile: Mapping[str, Any] | None = None, wheel_provenance: Mapping[str, Any] | None = None,
    wheel_boundary_report: Mapping[str, Any] | None = None, negative_security_report: Mapping[str, Any] | None = None,
    sealed_sandbox_profile_store_locator: Mapping[str, Any] | None = None, require_signed_envelope: bool = True,
) -> dict[str, Any]:
    if not isinstance(store, Store) or type(wheel_bytes) is not bytes or not wheel_bytes or type(corpus_bytes) is not bytes or not corpus_bytes or type(require_signed_envelope) is not bool:
        raise ValueError("verify_certification_7a_replay_bytes: invalid Store/require_signed_envelope or empty wheel_bytes/corpus_bytes")
    if not isinstance(resolved_git_blobs, Mapping) or any(type(k) is not str or type(v) is not bytes for k, v in resolved_git_blobs.items()):
        raise ValueError("resolved_git_blobs: expected Mapping[str, bytes]")
    d26_blobs = _verify_d26_blob_map(resolved_d26_blobs)
    mode, raw_payload = _unwrap_cert_record(artifact, require_signed_envelope=require_signed_envelope)
    checked_common = _build_cert_common_payload(**{k: raw_payload[k] for k in _CERT_COMMON_17_KEYS})
    wheel_members, sbx_p, prov_p, neg_p, sbx_digest, sbx_loc = _verify_stage7_and_wheel_archive_passively(
        mode, raw_payload, store, wheel_bytes, sandbox_profile=sandbox_profile, wheel_provenance=wheel_provenance,
        wheel_boundary_report=wheel_boundary_report, negative_security_report=negative_security_report, explicit_sbx_store_loc=sealed_sandbox_profile_store_locator,
    )
    snap, drv = _verify_registry_and_contract_from_store(store, checked_common["capability"], checked_common["resource_mapping_contract_digest"])
    cert_us = _utc_sec_micros(checked_common["certified_at_utc"], "certified_at_utc")
    git_locs_13 = _verify_all_13_git_provenances(store, checked_common, drv, wheel_members=wheel_members, corpus_bytes=corpus_bytes, git_blobs=resolved_git_blobs, d26_blobs=d26_blobs, certified_us=cert_us)
    corpus_doc, priv_map, cmap, inv_map = _parse_corpus_and_inventories(corpus_bytes, store, snap, checked_common["fixture_evidence"]["cases"])
    ctx = {
        "sbx_p": sbx_p, "sbx_limits": sbx_p["resource_limits"], "sbx_digest": sbx_digest, "sbx_loc": sbx_loc,
        "sbx_issued_us": _utc_sec_micros(sbx_p["issued_at_utc"], "sbx.i"), "sbx_from_us": _utc_sec_micros(sbx_p["validity"]["from"], "sbx.f"),
        "sbx_until_us": _utc_sec_micros(sbx_p["validity"]["until"], "sbx.u"), "prov_built_us": _utc_sec_micros(prov_p["built_at_utc"], "prov.b"),
        "snap_issued_us": _utc_sec_micros(snap["issued_at_utc"], "snap.i"), "snap_until_us": _utc_sec_micros(snap["valid_until_utc"], "snap.u"),
        "cert_us": cert_us, "reg_fix_loc": make_locator("smart_ads/regression_fixture/v1", canonicalize(checked_common["fixture_evidence"]["regression_fixture"])),
        "neg_refs": {r["sandbox_instance_ref"] for c in neg_p["cases"] for r in c["runs"]},
    }
    _replay_all_7a_cases(checked_common, corpus_doc, snap, drv, priv_map, cmap, inv_map, ctx)
    dedup_invs = [d for _, d in sorted({canonicalize(c["expected_resource_inventory_locator"]): copy.deepcopy(c["expected_resource_inventory_locator"]) for c in checked_common["fixture_evidence"]["cases"]}.items(), key=lambda p: p[0])]
    return {
        "mode": mode, "schema": CERTIFICATION_7A_RECORD_SCHEMA, "certified_at_utc": checked_common["certified_at_utc"],
        "wheel_digest": checked_common["wheel_digest"], "schema_bundle_digest": checked_common["schema_bundle_digest"],
        "leaf_locators": {"registry_snapshot_locator": copy.deepcopy(checked_common["capability"]["registry_snapshot_locator"]), "driver_contract_locator": copy.deepcopy(checked_common["capability"]["driver_contract_locator"]), "expected_resource_inventory_locators": dedup_invs, "git_artifact_provenance_locators": git_locs_13, "sealed_sandbox_profile_store_locator": sbx_loc},
        "payload": copy.deepcopy(raw_payload),
    }


def verify_certification_7a_record(
    envelope: Mapping[str, Any], *, store: Store, wheel_bytes: bytes, corpus_bytes: bytes,
    resolved_git_blobs: Mapping[str, bytes], resolved_d26_blobs: Mapping[str, bytes],
) -> dict[str, Any]:
    if not isinstance(envelope, Mapping) or "artifact_kind" in envelope or envelope.get("$schema") != CERTIFICATION_7A_RECORD_SCHEMA:
        raise ValueError("verify_certification_7a_record: expected certification_7a_record/v1 P1 envelope")
    return verify_certification_7a_replay_bytes(envelope, store=store, wheel_bytes=wheel_bytes, corpus_bytes=corpus_bytes, resolved_git_blobs=resolved_git_blobs, resolved_d26_blobs=resolved_d26_blobs)


def _freeze_smart_ads_git_blobs(raw_git: Mapping[str, bytes]) -> Mapping[str, bytes]:
    if not isinstance(raw_git, Mapping) or set(raw_git.keys()) != set(SMART_ADS_7A_GIT_PATHS) or any(type(v) is not bytes for v in raw_git.values()):
        raise ValueError("resolved_git_blobs: expected exact 8 SMART_ADS_7A_GIT_PATHS -> bytes")
    return MappingProxyType({k: bytes(raw_git[k]) for k in SMART_ADS_7A_GIT_PATHS})


class SevenAConstituentVerifier(Pr3SevenAConstituentVerifier):
    """Concrete PR 3 implementation of `Pr3SevenAConstituentVerifier` bound to frozen preflight inputs."""

    def __init__(
        self, *, wheel_bytes: bytes, corpus_bytes: bytes, stripped_provenance_payload: Mapping[str, Any],
        resolved_git_blobs: Mapping[str, bytes], resolved_d26_blobs: Mapping[str, bytes],
    ) -> None:
        if type(wheel_bytes) is not bytes or not wheel_bytes or type(corpus_bytes) is not bytes or not corpus_bytes:
            raise ValueError("SevenAConstituentVerifier: wheel_bytes and corpus_bytes must be non-empty bytes")
        prov_p = extract_provenance_payload(stripped_provenance_payload)
        if set(stripped_provenance_payload.keys()) != set(prov_p.keys()) or prov_p["wheel_digest"] != digest(wheel_bytes):
            raise ValueError("SevenAConstituentVerifier: stripped_provenance_payload must be 16-key payload matching wheel_bytes")
        git_frozen = _freeze_smart_ads_git_blobs(resolved_git_blobs)
        if corpus_bytes != git_frozen[CORPUS_GIT_PATH[1]]:
            raise ValueError("SevenAConstituentVerifier: corpus_bytes mismatch against resolved_git_blobs")
        self._wheel_bytes, self._corpus_bytes = bytes(wheel_bytes), bytes(corpus_bytes)
        self._stripped_provenance_payload = copy.deepcopy(prov_p)
        self._resolved_git_blobs = git_frozen
        self._resolved_d26_blobs = MappingProxyType(_verify_d26_blob_map(resolved_d26_blobs))

    def verify_bound_preflight_inputs(
        self, *, wheel_bytes: bytes, corpus_bytes: bytes, stripped_provenance_payload: Mapping[str, Any],
        resolved_git_blobs: Mapping[str, bytes], resolved_d26_blobs: Mapping[str, bytes],
    ) -> None:
        if type(wheel_bytes) is not bytes or wheel_bytes != self._wheel_bytes or type(corpus_bytes) is not bytes or corpus_bytes != self._corpus_bytes:
            raise ValueError("SevenAConstituentVerifier: wheel_bytes or corpus_bytes diverged from bound preflight")
        if not isinstance(stripped_provenance_payload, Mapping) or set(stripped_provenance_payload.keys()) != set(self._stripped_provenance_payload.keys()) or canonicalize(dict(stripped_provenance_payload)) != canonicalize(self._stripped_provenance_payload):
            raise ValueError("SevenAConstituentVerifier: stripped_provenance_payload diverged from bound preflight")
        if not isinstance(resolved_git_blobs, Mapping) or dict(resolved_git_blobs) != dict(self._resolved_git_blobs) or not isinstance(resolved_d26_blobs, Mapping) or dict(resolved_d26_blobs) != dict(self._resolved_d26_blobs):
            raise ValueError("SevenAConstituentVerifier: resolved_git_blobs or resolved_d26_blobs diverged from bound preflight")

    def verify_7a_constituents(
        self, *, negative_security_test_report_locator: dict[str, Any], certification_7a_record_locator: dict[str, Any],
        migration_run_context_locator: dict[str, Any], sealed_sandbox_profile_locator: dict[str, Any],
        wheel_boundary_report_locator: dict[str, Any], mcp_rejection_matrix_report_locator: dict[str, Any],
        build_run_id: str, source_commit_sha: str, wheel_digest: str, build_backend_digest: str,
        schema_bundle_digest: str, converged_at_utc: str, store: Store | None = None,
    ) -> Mapping[str, Any]:
        if not isinstance(store, Store):
            raise ValueError("SevenAConstituentVerifier: Store is required")
        sbx_env = _get_verified_store_envelope(store, sealed_sandbox_profile_locator, SANDBOX_PROFILE_SCHEMA, require_signed=True)
        bound_env = _get_verified_store_envelope(store, wheel_boundary_report_locator, WHEEL_BOUNDARY_REPORT_SCHEMA, require_signed=True)
        mcp_env = _get_verified_store_envelope(store, mcp_rejection_matrix_report_locator, MCP_REJECTION_REPORT_SCHEMA, require_signed=True)
        neg_env = _get_verified_store_envelope(store, negative_security_test_report_locator, NEGATIVE_SECURITY_REPORT_SCHEMA, require_signed=True)
        cert_env = _get_verified_store_envelope(store, certification_7a_record_locator, CERTIFICATION_7A_RECORD_SCHEMA, require_signed=True)
        prov_env = _get_verified_store_envelope(store, bound_env["wheel_build_provenance_locator"], WHEEL_BUILD_PROVENANCE_SCHEMA, require_signed=True)
        return self._verify_loaded_7a_constituents(
            store=store, sbx_env=sbx_env, prov_env=prov_env, bound_env=bound_env, mcp_env=mcp_env, neg_env=neg_env, cert_env=cert_env,
            run_ctx=migration_run_context_locator, sbx_loc=sealed_sandbox_profile_locator, bound_loc=wheel_boundary_report_locator,
            neg_loc=negative_security_test_report_locator, build_run_id=build_run_id, source_commit_sha=source_commit_sha,
            wheel_digest=wheel_digest, build_backend_digest=build_backend_digest, schema_bundle_digest=schema_bundle_digest, converged_at_utc=converged_at_utc,
        )

    def _verify_loaded_7a_constituents(
        self, *, store: Store, sbx_env: dict[str, Any], prov_env: dict[str, Any], bound_env: dict[str, Any],
        mcp_env: dict[str, Any], neg_env: dict[str, Any], cert_env: dict[str, Any], run_ctx: dict[str, Any],
        sbx_loc: dict[str, Any], bound_loc: dict[str, Any], neg_loc: dict[str, Any], build_run_id: str,
        source_commit_sha: str, wheel_digest: str, build_backend_digest: str, schema_bundle_digest: str, converged_at_utc: str,
    ) -> Mapping[str, Any]:
        if canonicalize(extract_provenance_payload(prov_env)) != canonicalize(self._stripped_provenance_payload):
            raise ValueError("SevenAConstituentVerifier: store wheel_build_provenance diverges from bound preflight")
        if (
            canonicalize(cert_env["migration_run_context_locator"]) != canonicalize(run_ctx)
            or canonicalize(mcp_env["migration_run_context_locator"]) != canonicalize(run_ctx)
            or canonicalize(cert_env["sealed_sandbox_profile_locator"]) != canonicalize(sbx_loc)
            or canonicalize(mcp_env["sealed_sandbox_profile_locator"]) != canonicalize(sbx_loc)
            or canonicalize(cert_env["wheel_boundary_report_locator"]) != canonicalize(bound_loc)
            or canonicalize(cert_env["negative_security_test_report_locator"]) != canonicalize(neg_loc)
            or (cert_env["build_run_id"], cert_env["source_commit_sha"], cert_env["wheel_digest"], cert_env["build_backend_digest"], cert_env["schema_bundle_digest"]) != (build_run_id, source_commit_sha, wheel_digest, build_backend_digest, schema_bundle_digest)
            or (mcp_env["build_run_id"], mcp_env["source_commit_sha"], mcp_env["wheel_digest"], mcp_env["build_backend_digest"], mcp_env["schema_bundle_digest"]) != (build_run_id, source_commit_sha, wheel_digest, build_backend_digest, schema_bundle_digest)
        ):
            raise ValueError("SevenAConstituentVerifier: convergence cross-binding mismatch")
        neg_res = verify_negative_security_test_report(neg_env, sandbox_profile=sbx_env, wheel_provenance=prov_env, wheel_bytes=self._wheel_bytes)
        cert_res = verify_certification_7a_replay_bytes(cert_env, store=store, wheel_bytes=self._wheel_bytes, corpus_bytes=self._corpus_bytes, resolved_git_blobs=self._resolved_git_blobs, resolved_d26_blobs=self._resolved_d26_blobs, sandbox_profile=sbx_env, wheel_provenance=prov_env, wheel_boundary_report=bound_env, negative_security_report=neg_env)
        sbx_from_us, sbx_until_us = _utc_sec_micros(sbx_env["validity"]["from"], "sbx.from"), _utc_sec_micros(sbx_env["validity"]["until"], "sbx.until")
        neg_us, cert_us, conv_us = _utc_sec_micros(neg_res["executed_at_utc"], "neg"), _utc_sec_micros(cert_res["certified_at_utc"], "cert"), _utc_sec_micros(converged_at_utc, "conv")
        if not (sbx_from_us <= neg_us <= cert_us < sbx_until_us and neg_us <= cert_us <= conv_us):
            raise ValueError("SevenAConstituentVerifier: chronology or sandbox validity violation across negative, 7A, and convergence")
        return {"certified": True, "negative_cases": list(MANDATORY_7A_NEGATIVE_CASES), "negative_executed_at_utc": neg_res["executed_at_utc"], "certified_at_utc": cert_res["certified_at_utc"], "leaf_locators": cert_res["leaf_locators"]}
