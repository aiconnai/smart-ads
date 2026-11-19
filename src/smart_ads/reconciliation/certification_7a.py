"""Closed P1 `smart_ads/certification_7a_record/v1`, digests, corpus parser, and replay (ADR-0001 §§3.2, 4.1, 5.1)."""
from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
import hashlib
import re
from typing import Any, ClassVar, Final

from smart_ads.adapters.pipeboard import PipeboardFixtureAdapter, PrivatePipeboardBindingBoundary
from smart_ads.analytics.lattice import RegressionFixtureV1
from smart_ads.application.admission import AdmittedCollectionBundle, admit_collection
from smart_ads.application.collection import evaluate_fixture_collection
from smart_ads.contracts.git_provenance import GitArtifactProvenance, sort_git_provenance_locators, verify_git_provenance_against_bytes
from smart_ads.contracts.jcs import ADR_P1_DOMAIN_PREFIXES, MAX_JCS_SAFE_INT, ArtifactLocator, P1Integrity, canonicalize_jcs, jcs_sha256, loads_strict_json, p1_content_digest, sort_utf8_strings
from smart_ads.contracts.negative_security import (
    _RUN_CONTEXT_SCHEMA, _SANDBOX_PROFILE_SCHEMA, _SHARED_RUNTIME_16_FIELDS, _SPEC_17_FIELDS, _WHEEL_PROVENANCE_SCHEMA,
    NegativeSecurityTestReport, SandboxResourceLimits, SandboxRuntimeReadback, SandboxTermination, SandboxUsageCounters,
    _exact_str, _reparse, _require_typed_locator, _strict_bool, _strict_str, _utc_sec_micros, evaluate_breach_predicates, verify_negative_security_report_against_profile,
)
from smart_ads.contracts.scalars import ClosedValidationError, parse_timestamp_utc_micros, require_exact_keys, require_mapping, validate_hex40, validate_opaque_ref, validate_sha256_prefixed
from smart_ads.contracts.schemas import CollectionRequest, PurposePrerequisiteLocators, RetrievalContext, validate_source_metric_ref
from smart_ads.domain.pipeboard_contract import PINNED_LEGACY_COMMIT, PINNED_LEGACY_REPO, PINNED_PIPEBOARD_D26_SPECS, PipeboardPhase1Contract
from smart_ads.domain.registry import ExpectedResourceInventory, PrivateRegistrySnapshot
from smart_ads.domain.resource_ref import BidirectionalResourceDirectory, TenantResourceKeyHandle, derive_resource_ref
from smart_ads.ports.cell_runtime import CellRuntimePorts, ClockAttestation, ResolvedClockState, ResolvedPrerequisiteBundle, ResolvedRegistryState, TimezoneRuleSnapshot
from smart_ads.ports.provider import ProviderObservationBatch

CERTIFICATION_7A_RECORD_SCHEMA: Final[str] = "smart_ads/certification_7a_record/v1"
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

# Closed deterministic JSON corpus structure shared with `tools/governance/gov1_7a_certification.py`:
CORPUS_TOP_LEVEL_KEYS: Final[frozenset[str]] = frozenset("$schema corpus_id key_identity private_account_bindings tenant_hmac_key_hex tenant_ref timezone_snapshot verified_campaign_pairs cases".split())
CORPUS_PRIVATE_BINDING_KEYS: Final[frozenset[str]] = frozenset({"binding_ref", "account_ref", "private_object_id"})
CORPUS_CAMPAIGN_PAIR_KEYS: Final[frozenset[str]] = frozenset({"raw_campaign_id", "resource_ref"})
CORPUS_CLOCK_READING_KEYS: Final[frozenset[str]] = frozenset({"attestation", "configured_max_uncertainty_ms"})
CORPUS_HTTP_RESPONSE_KEYS: Final[frozenset[str]] = frozenset({"network_ok", "http_status", "headers", "body_utf8"})
CORPUS_CASE_KEYS: Final[frozenset[str]] = frozenset("case_id admission_id clock_reading collection_request retrieval_context http_response expected_completeness_status expected_reasons expected_error_code".split())

_WHEEL_BOUNDARY_SCHEMA: Final[str] = "smart_ads/wheel_boundary_report/v1"
_PHASE1_REQUIRED_METRICS: Final[tuple[str, ...]] = ("metric:clicks_v1", "metric:impressions_v1", "metric:spend_v1")
_COMPLETENESS_STATUSES: Final[frozenset[str]] = frozenset({"complete", "partial", "failed"})
_SOURCE_CONTRACT_REF_RE: Final[re.Pattern[str]] = re.compile(r"\Aopaque-driver-contract:sha256:[0-9a-f]{64}\Z")
_HEX64_RE: Final[re.Pattern[str]] = re.compile(r"\A[0-9a-f]{64}\Z")
_WHEEL_BOUNDARY_ENVELOPE_17_KEYS: Final[frozenset[str]] = frozenset(
    "$schema integrity migration_run_context_locator build_run_id verified_at_utc repository source_commit_sha wheel_digest "
    "build_backend_digest schema_bundle_digest sorted_record_entries sorted_record_digest archive_allowlist_passed "
    "ast_boundary_scan_passed isolated_venv_import_passed packaged_modules wheel_build_provenance_locator".split()
)
_CASE_SUBOBJ_TYPES: Final[tuple[tuple[str, type[Any]], ...]] = (
    ("runtime_readback", SandboxRuntimeReadback), ("effective_resource_limits", SandboxResourceLimits),
    ("usage", SandboxUsageCounters), ("termination", SandboxTermination), ("observation_batch", ProviderObservationBatch),
)
_CASE_SCALAR_KEYS: Final[tuple[str, ...]] = (
    "case_id", "admitted_collection_digest", "source_contract_ref", "sandbox_instance_ref", "execution_binding_digest",
    "started_at_utc", "ended_at_utc", "expected_completeness_status", "observed_completeness_status", "normalized_fact_set_digest",
)
_RECORD_LOCATOR_SPECS: Final[tuple[tuple[str, str], ...]] = (
    ("migration_run_context_locator", _RUN_CONTEXT_SCHEMA), ("sealed_sandbox_profile_locator", _SANDBOX_PROFILE_SCHEMA),
    ("wheel_build_provenance_locator", _WHEEL_PROVENANCE_SCHEMA), ("wheel_boundary_report_locator", _WHEEL_BOUNDARY_SCHEMA),
    ("negative_security_test_report_locator", NegativeSecurityTestReport.SCHEMA),
)
_RECORD_SCALAR_KEYS: Final[tuple[str, ...]] = (
    "build_run_id", "certified_at_utc", "certified_state", "source_commit_sha", "build_backend_digest", "schema_bundle_digest",
    "wheel_digest", "resource_mapping_contract_digest", "parser_code_digest", "adapter_code_digest", "mapping_rules_digest",
)


def _require_sorted_git_locators(locators: object, expected_len: int, *, label: str) -> tuple[ArtifactLocator, ...]:
    if isinstance(locators, (str, bytes, bytearray, memoryview)) or not isinstance(locators, (list, tuple)):
        raise ClosedValidationError(f"{label}: expected list or tuple of ArtifactLocator")
    sorted_locs = sort_git_provenance_locators(locators)
    if len(sorted_locs) != expected_len or tuple(locators) != sorted_locs:
        raise ClosedValidationError(f"{label}: expected {expected_len} unique sorted git_artifact_provenance/v1 locators")
    return sorted_locs

def _artifact_identities(provs: Sequence[GitArtifactProvenance], expected_paths: tuple[tuple[str, str], ...], *, label: str) -> list[dict[str, str]]:
    if isinstance(provs, (str, bytes, bytearray, memoryview)) or not isinstance(provs, Sequence):
        raise ClosedValidationError(f"{label}: expected Sequence of GitArtifactProvenance")
    checked = [_reparse(p, GitArtifactProvenance, label=f"{label}[{i}]") for i, p in enumerate(provs)]
    actual_pairs = [(p.repository, p.path) for p in checked]
    if len(actual_pairs) != len(expected_paths) or set(actual_pairs) != set(expected_paths):
        raise ClosedValidationError(f"{label}: (repository, path) set mismatch against pinned {expected_paths!r}")
    ordered = sorted(checked, key=lambda p: canonicalize_jcs([p.repository, p.path]))
    return [{"repository": p.repository, "commit_sha": p.commit_sha, "path": p.path, "git_blob_oid": p.git_blob_oid, "file_content_sha256": p.file_content_sha256} for p in ordered]

def compute_parser_code_digest(provs: Sequence[GitArtifactProvenance]) -> str:
    """Compute canonical `parser_code_digest` over `PARSER_ARTIFACT_PATHS`."""
    return jcs_sha256({"kind": "smart_ads/parser_code_digest/v1", "artifacts": _artifact_identities(provs, PARSER_ARTIFACT_PATHS, label="parser_provs")})

def compute_adapter_code_digest(provs: Sequence[GitArtifactProvenance]) -> str:
    """Compute canonical `adapter_code_digest` over `ADAPTER_ARTIFACT_PATHS`."""
    return jcs_sha256({"kind": "smart_ads/adapter_code_digest/v1", "artifacts": _artifact_identities(provs, ADAPTER_ARTIFACT_PATHS, label="adapter_provs")})

def compute_mapping_rules_digest(provs: Sequence[GitArtifactProvenance], metric_source_mappings: Mapping[str, str]) -> str:
    """Compute canonical `mapping_rules_digest` over `MAPPING_ARTIFACT_PATHS` and metric mappings."""
    checked_map = require_mapping(metric_source_mappings, label="metric_source_mappings")
    if not checked_map:
        raise ClosedValidationError("metric_source_mappings: must not be empty")
    normalized = {
        validate_opaque_ref(_strict_str(k, label="metric_key"), field_name="metric_key", expected_prefix="metric"):
        validate_source_metric_ref(_strict_str(v, label="source_metric_ref"), field_name="source_metric_ref")
        for k, v in checked_map.items()
    }
    return jcs_sha256({"kind": "smart_ads/mapping_rules_digest/v1", "artifacts": _artifact_identities(provs, MAPPING_ARTIFACT_PATHS, label="mapping_provs"), "metric_source_mappings": normalized})


@dataclass(frozen=True, slots=True)
class Certification7ACapabilityBinding:
    """Closed 7-key capability binding block inside `Certification7ARecord`."""

    KEYS: ClassVar[frozenset[str]] = frozenset("capability_ref resource_scope_ref driver_id driver_contract_locator driver_contract_digest registry_snapshot_locator required_metrics".split())
    capability_ref: str
    resource_scope_ref: str
    driver_id: str
    driver_contract_locator: ArtifactLocator
    driver_contract_digest: str
    registry_snapshot_locator: ArtifactLocator
    required_metrics: tuple[str, ...]

    def __post_init__(self) -> None:
        lbl = "certification_7a_capability_binding"
        validate_opaque_ref(_strict_str(self.capability_ref, label=f"{lbl}.cap"), field_name=f"{lbl}.cap", expected_prefix="cap")
        validate_opaque_ref(_strict_str(self.resource_scope_ref, label=f"{lbl}.scope"), field_name=f"{lbl}.scope", expected_prefix="scope")
        _exact_str(self.driver_id, "pipeboard_hosted", label=f"{lbl}.driver_id")
        drv_loc = _require_typed_locator(self.driver_contract_locator, PipeboardPhase1Contract.SCHEMA, label=f"{lbl}.drv_loc")
        validate_sha256_prefixed(_strict_str(self.driver_contract_digest, label=f"{lbl}.drv_digest"), field_name=f"{lbl}.drv_digest")
        if self.driver_contract_digest != drv_loc.content_digest:
            raise ClosedValidationError(f"{lbl}.driver_contract_digest: must equal driver_contract_locator.content_digest")
        _require_typed_locator(self.registry_snapshot_locator, PrivateRegistrySnapshot.SCHEMA, label=f"{lbl}.snap_loc")
        if not isinstance(self.required_metrics, (list, tuple)):
            raise ClosedValidationError(f"{lbl}.required_metrics: expected list or tuple")
        metrics = sort_utf8_strings(self.required_metrics, field_name=f"{lbl}.required_metrics", allow_empty=False, validator=lambda s: validate_opaque_ref(s, field_name=f"{lbl}.required_metrics", expected_prefix="metric"))
        if tuple(self.required_metrics) != metrics or metrics != _PHASE1_REQUIRED_METRICS:
            raise ClosedValidationError(f"{lbl}.required_metrics: expected sorted {list(_PHASE1_REQUIRED_METRICS)!r}")
        object.__setattr__(self, "required_metrics", metrics)

    def to_dict(self) -> dict[str, Any]:
        return {"capability_ref": self.capability_ref, "resource_scope_ref": self.resource_scope_ref, "driver_id": self.driver_id, "driver_contract_locator": self.driver_contract_locator.to_dict(), "driver_contract_digest": self.driver_contract_digest, "registry_snapshot_locator": self.registry_snapshot_locator.to_dict(), "required_metrics": list(self.required_metrics)}

    @classmethod
    def from_dict(cls, data: object) -> Certification7ACapabilityBinding:
        m = require_exact_keys(data, cls.KEYS, label="certification_7a_capability_binding")
        if type(m["required_metrics"]) is not list:
            raise ClosedValidationError("certification_7a_capability_binding.required_metrics: expected JSON array list")
        return cls(m["capability_ref"], m["resource_scope_ref"], m["driver_id"], ArtifactLocator.from_dict(m["driver_contract_locator"], expected_type=PipeboardPhase1Contract.SCHEMA), m["driver_contract_digest"], ArtifactLocator.from_dict(m["registry_snapshot_locator"], expected_type=PrivateRegistrySnapshot.SCHEMA), tuple(m["required_metrics"]))


def _validate_positive_sandbox_evidence(rb: SandboxRuntimeReadback, usage: SandboxUsageCounters, term: SandboxTermination, *, label: str) -> None:
    if (
        rb.seccomp_enforced_before_entry is not True or rb.effective_writable_mounts != ("/tmp",) or rb.network_absent is not True
        or rb.loopback_absent is not True or term.supervisor_terminated_cgroup is not False or term.cause != "clean_exit"
        or term.exit_code != 0 or term.signal is not None or term.force_kill_used is not False
        or term.whole_cgroup_empty is not True or any(evaluate_breach_predicates(usage, term).values())
    ):
        raise ClosedValidationError(f"{label}: positive 7A sandbox run violated clean-exit/seccomp/ceiling invariants")


@dataclass(frozen=True, slots=True)
class Certification7AFixtureCase:
    """Closed 16-key offline 7A fixture case execution evidence."""

    KEYS: ClassVar[frozenset[str]] = frozenset("case_id admitted_collection_digest expected_resource_inventory_locator source_contract_ref sandbox_instance_ref execution_binding_digest started_at_utc ended_at_utc runtime_readback effective_resource_limits usage termination observation_batch expected_completeness_status observed_completeness_status normalized_fact_set_digest".split())
    case_id: str
    admitted_collection_digest: str
    expected_resource_inventory_locator: ArtifactLocator
    source_contract_ref: str
    sandbox_instance_ref: str
    execution_binding_digest: str
    started_at_utc: str
    ended_at_utc: str
    runtime_readback: SandboxRuntimeReadback
    effective_resource_limits: SandboxResourceLimits
    usage: SandboxUsageCounters
    termination: SandboxTermination
    observation_batch: ProviderObservationBatch
    expected_completeness_status: str
    observed_completeness_status: str
    normalized_fact_set_digest: str | None

    def __post_init__(self) -> None:
        lbl = "certification_7a_fixture_case"
        _strict_str(self.case_id, label=f"{lbl}.case_id")
        validate_sha256_prefixed(_strict_str(self.admitted_collection_digest, label=f"{lbl}.adm_digest"), field_name=f"{lbl}.adm_digest")
        _require_typed_locator(self.expected_resource_inventory_locator, ExpectedResourceInventory.SCHEMA, label=f"{lbl}.inv_loc")
        if type(self.source_contract_ref) is not str or _SOURCE_CONTRACT_REF_RE.fullmatch(self.source_contract_ref) is None:
            raise ClosedValidationError(f"{lbl}.source_contract_ref: invalid {self.source_contract_ref!r}")
        validate_opaque_ref(_strict_str(self.sandbox_instance_ref, label=f"{lbl}.sbx_ref"), field_name=f"{lbl}.sbx_ref")
        validate_sha256_prefixed(_strict_str(self.execution_binding_digest, label=f"{lbl}.bind"), field_name=f"{lbl}.bind")
        if _utc_sec_micros(self.started_at_utc, label=f"{lbl}.start") > _utc_sec_micros(self.ended_at_utc, label=f"{lbl}.end"):
            raise ClosedValidationError(f"{lbl}: started_at_utc > ended_at_utc")
        for attr, cls_t in _CASE_SUBOBJ_TYPES:
            object.__setattr__(self, attr, _reparse(getattr(self, attr), cls_t, label=f"{lbl}.{attr}"))
        _validate_positive_sandbox_evidence(self.runtime_readback, self.usage, self.termination, label=lbl)
        if not self.observation_batch.io_counters.is_zero:
            raise ClosedValidationError(f"{lbl}.observation_batch.io_counters: must be all zero")
        if type(self.expected_completeness_status) is not str or self.expected_completeness_status not in _COMPLETENESS_STATUSES:
            raise ClosedValidationError(f"{lbl}.expected_completeness_status: invalid {self.expected_completeness_status!r}")
        _exact_str(self.observed_completeness_status, self.expected_completeness_status, label=f"{lbl}.observed_completeness_status")
        if self.observed_completeness_status == "complete":
            validate_sha256_prefixed(_strict_str(self.normalized_fact_set_digest, label=f"{lbl}.fact_digest"), field_name=f"{lbl}.fact_digest")
        elif self.normalized_fact_set_digest is not None:
            raise ClosedValidationError(f"{lbl}.normalized_fact_set_digest: must be None when status != 'complete'")

    def to_dict(self) -> dict[str, Any]:
        return {"expected_resource_inventory_locator": self.expected_resource_inventory_locator.to_dict(), **{attr: getattr(self, attr).to_dict() for attr, _ in _CASE_SUBOBJ_TYPES}, **{s_key: getattr(self, s_key) for s_key in _CASE_SCALAR_KEYS}}

    @classmethod
    def from_dict(cls, data: object) -> Certification7AFixtureCase:
        m = require_exact_keys(data, cls.KEYS, label="certification_7a_fixture_case")
        return cls(expected_resource_inventory_locator=ArtifactLocator.from_dict(m["expected_resource_inventory_locator"], expected_type=ExpectedResourceInventory.SCHEMA), **{attr: cls_t.from_dict(m[attr]) for attr, cls_t in _CASE_SUBOBJ_TYPES}, **{s_key: m[s_key] for s_key in _CASE_SCALAR_KEYS})


def compute_7a_case_execution_binding_digest(*, case: Certification7AFixtureCase, wheel_digest: str, corpus_digest: str, sealed_sandbox_profile_digest: str) -> str:
    """Compute canonical JCS SHA-256 execution binding digest for one 7A fixture case."""
    c = _reparse(case, Certification7AFixtureCase, label="case")
    for name, val in (("wheel_digest", wheel_digest), ("corpus_digest", corpus_digest), ("sealed_sandbox_profile_digest", sealed_sandbox_profile_digest)):
        validate_sha256_prefixed(_strict_str(val, label=name), field_name=name)
    return jcs_sha256({"case_id": c.case_id, "sandbox_instance_ref": c.sandbox_instance_ref, "started_at_utc": c.started_at_utc, "ended_at_utc": c.ended_at_utc, "wheel_digest": wheel_digest, "corpus_digest": corpus_digest, "admitted_collection_digest": c.admitted_collection_digest, "expected_resource_inventory_digest": c.expected_resource_inventory_locator.content_digest, "sealed_sandbox_profile_digest": sealed_sandbox_profile_digest, **{attr: getattr(c, attr).to_dict() for attr, _ in _CASE_SUBOBJ_TYPES}})


@dataclass(frozen=True, slots=True)
class Certification7AFixtureEvidence:
    """Closed 4-key fixture evidence block inside `Certification7ARecord`."""

    KEYS: ClassVar[frozenset[str]] = frozenset({"corpus_git_locator", "corpus_digest", "regression_fixture", "cases"})
    corpus_git_locator: ArtifactLocator
    corpus_digest: str
    regression_fixture: RegressionFixtureV1
    cases: tuple[Certification7AFixtureCase, ...]

    def __post_init__(self) -> None:
        lbl = "certification_7a_fixture_evidence"
        _require_typed_locator(self.corpus_git_locator, GitArtifactProvenance.SCHEMA, label=f"{lbl}.corpus_loc")
        validate_sha256_prefixed(_strict_str(self.corpus_digest, label=f"{lbl}.corpus_digest"), field_name=f"{lbl}.corpus_digest")
        object.__setattr__(self, "regression_fixture", _reparse(self.regression_fixture, RegressionFixtureV1, label=f"{lbl}.regression_fixture"))
        if not isinstance(self.cases, (list, tuple)) or len(self.cases) == 0:
            raise ClosedValidationError(f"{lbl}.cases: expected non-empty sequence of Certification7AFixtureCase")
        checked_cases = tuple(_reparse(c, Certification7AFixtureCase, label=f"{lbl}.cases[{i}]") for i, c in enumerate(self.cases))
        id_bytes = [c.case_id.encode("utf-8") for c in checked_cases]
        if id_bytes != sorted(id_bytes) or len(set(id_bytes)) != len(id_bytes):
            raise ClosedValidationError(f"{lbl}.cases: case_id values must be unique and UTF-8 sorted")
        if len({c.sandbox_instance_ref for c in checked_cases}) != len(checked_cases):
            raise ClosedValidationError(f"{lbl}.cases: duplicate sandbox_instance_ref")
        if not _COMPLETENESS_STATUSES.issubset({c.observed_completeness_status for c in checked_cases}):
            raise ClosedValidationError(f"{lbl}.cases: must include >= 1 complete, >= 1 partial, and >= 1 failed case")
        object.__setattr__(self, "cases", checked_cases)

    def to_dict(self) -> dict[str, Any]:
        return {"corpus_git_locator": self.corpus_git_locator.to_dict(), "corpus_digest": self.corpus_digest, "regression_fixture": self.regression_fixture.to_dict(), "cases": [c.to_dict() for c in self.cases]}

    @classmethod
    def from_dict(cls, data: object) -> Certification7AFixtureEvidence:
        m = require_exact_keys(data, cls.KEYS, label="certification_7a_fixture_evidence")
        if type(m["cases"]) is not list:
            raise ClosedValidationError("certification_7a_fixture_evidence.cases: expected JSON array list")
        return cls(ArtifactLocator.from_dict(m["corpus_git_locator"], expected_type=GitArtifactProvenance.SCHEMA), m["corpus_digest"], RegressionFixtureV1.from_dict(m["regression_fixture"]), tuple(Certification7AFixtureCase.from_dict(c) for c in m["cases"]))


def _validate_record_internal_bindings(record: Certification7ARecord, certified_us: int) -> None:
    if record.fixture_evidence.regression_fixture != RegressionFixtureV1.canonical(record.capability.registry_snapshot_locator.content_digest):
        raise ClosedValidationError("certification_7a_record.fixture_evidence.regression_fixture: canonical 65x23 mismatch")
    expected_src_ref = f"opaque-driver-contract:{record.capability.driver_contract_digest}"
    for c in record.fixture_evidence.cases:
        start_us = _utc_sec_micros(c.started_at_utc, label="case.started_at_utc")
        ret_us = parse_timestamp_utc_micros(c.observation_batch.retrieval_context.retrieved_at_utc, field_name="case.retrieved_at_utc")
        end_us = _utc_sec_micros(c.ended_at_utc, label="case.ended_at_utc")
        if c.source_contract_ref != expected_src_ref or not (start_us <= ret_us <= end_us <= certified_us):
            raise ClosedValidationError("certification_7a_record.cases: source_contract_ref or chronology mismatch")


@dataclass(frozen=True, slots=True)
class Certification7ARecord:
    """Closed P1 `smart_ads/certification_7a_record/v1` envelope (`generation` forbidden)."""

    SCHEMA: ClassVar[str] = CERTIFICATION_7A_RECORD_SCHEMA
    P1_DOMAIN_PREFIX: ClassVar[str] = ADR_P1_DOMAIN_PREFIXES[CERTIFICATION_7A_RECORD_SCHEMA]
    CORE_KEYS: ClassVar[frozenset[str]] = frozenset("$schema adapter_artifact_locators adapter_code_digest build_backend_digest build_run_id capability certified_at_utc certified_state fixture_evidence mapping_artifact_locators mapping_rules_digest migration_run_context_locator negative_security_test_report_locator parser_artifact_locators parser_code_digest resource_mapping_contract_digest schema_bundle_digest sealed_sandbox_profile_locator source_commit_sha wheel_boundary_report_locator wheel_build_provenance_locator wheel_digest".split())
    KEYS: ClassVar[frozenset[str]] = CORE_KEYS | {"integrity"}

    migration_run_context_locator: ArtifactLocator
    sealed_sandbox_profile_locator: ArtifactLocator
    wheel_build_provenance_locator: ArtifactLocator
    wheel_boundary_report_locator: ArtifactLocator
    negative_security_test_report_locator: ArtifactLocator
    build_run_id: str
    certified_at_utc: str
    certified_state: str
    source_commit_sha: str
    build_backend_digest: str
    schema_bundle_digest: str
    wheel_digest: str
    resource_mapping_contract_digest: str
    capability: Certification7ACapabilityBinding
    parser_artifact_locators: tuple[ArtifactLocator, ...]
    parser_code_digest: str
    adapter_artifact_locators: tuple[ArtifactLocator, ...]
    adapter_code_digest: str
    mapping_artifact_locators: tuple[ArtifactLocator, ...]
    mapping_rules_digest: str
    fixture_evidence: Certification7AFixtureEvidence
    integrity: P1Integrity | None = None

    def __post_init__(self) -> None:
        lbl = "certification_7a_record"
        for attr, exp_schema in _RECORD_LOCATOR_SPECS:
            _require_typed_locator(getattr(self, attr), exp_schema, label=f"{lbl}.{attr}")
        _strict_str(self.build_run_id, label=f"{lbl}.build_run_id")
        certified_us = _utc_sec_micros(self.certified_at_utc, label=f"{lbl}.certified_at_utc")
        _exact_str(self.certified_state, "fixture_certified", label=f"{lbl}.certified_state")
        validate_hex40(_strict_str(self.source_commit_sha, label=f"{lbl}.commit"), field_name=f"{lbl}.commit")
        for d_attr in _RECORD_SCALAR_KEYS[4:]:
            validate_sha256_prefixed(_strict_str(getattr(self, d_attr), label=f"{lbl}.{d_attr}"), field_name=f"{lbl}.{d_attr}")
        object.__setattr__(self, "capability", _reparse(self.capability, Certification7ACapabilityBinding, label=f"{lbl}.capability"))
        object.__setattr__(self, "parser_artifact_locators", _require_sorted_git_locators(self.parser_artifact_locators, len(PARSER_ARTIFACT_PATHS), label=f"{lbl}.parser_locators"))
        object.__setattr__(self, "adapter_artifact_locators", _require_sorted_git_locators(self.adapter_artifact_locators, len(ADAPTER_ARTIFACT_PATHS), label=f"{lbl}.adapter_locators"))
        object.__setattr__(self, "mapping_artifact_locators", _require_sorted_git_locators(self.mapping_artifact_locators, len(MAPPING_ARTIFACT_PATHS), label=f"{lbl}.mapping_locators"))
        object.__setattr__(self, "fixture_evidence", _reparse(self.fixture_evidence, Certification7AFixtureEvidence, label=f"{lbl}.fixture_evidence"))
        _validate_record_internal_bindings(self, certified_us)
        if self.integrity is not None and not isinstance(self.integrity, P1Integrity):
            raise ClosedValidationError(f"{lbl}.integrity: expected P1Integrity or None")
        if self.integrity is not None and self.integrity.is_signed and self.integrity.content_digest != p1_content_digest(self.to_dict()):
            raise ClosedValidationError(f"{lbl}.integrity.content_digest: mismatch against P1 preimage")

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "$schema": self.SCHEMA, "capability": self.capability.to_dict(), "fixture_evidence": self.fixture_evidence.to_dict(),
            "parser_artifact_locators": [loc.to_dict() for loc in self.parser_artifact_locators],
            "adapter_artifact_locators": [loc.to_dict() for loc in self.adapter_artifact_locators],
            "mapping_artifact_locators": [loc.to_dict() for loc in self.mapping_artifact_locators],
            **{attr: getattr(self, attr).to_dict() for attr, _ in _RECORD_LOCATOR_SPECS},
            **{s_attr: getattr(self, s_attr) for s_attr in _RECORD_SCALAR_KEYS},
        }
        if self.integrity is not None:
            out["integrity"] = self.integrity.to_dict()
        return out

    @classmethod
    def from_dict(cls, data: object, *, require_signed: bool = False) -> Certification7ARecord:
        _strict_bool(require_signed, label="require_signed")
        m = require_mapping(data, label="certification_7a_record")
        if require_signed or "integrity" in m:
            require_exact_keys(m, cls.KEYS, label="certification_7a_record")
            integrity: P1Integrity | None = P1Integrity.from_dict(m["integrity"], require_signed=require_signed)
        else:
            require_exact_keys(m, cls.CORE_KEYS, label="certification_7a_record")
            integrity = None
        _exact_str(m["$schema"], cls.SCHEMA, label="certification_7a_record.$schema")
        for seq_k in ("parser_artifact_locators", "adapter_artifact_locators", "mapping_artifact_locators"):
            if type(m[seq_k]) is not list:
                raise ClosedValidationError(f"certification_7a_record.{seq_k}: expected JSON array list")
        locs = {attr: ArtifactLocator.from_dict(m[attr], expected_type=exp_t) for attr, exp_t in _RECORD_LOCATOR_SPECS}
        return cls(
            capability=Certification7ACapabilityBinding.from_dict(m["capability"]),
            parser_artifact_locators=tuple(ArtifactLocator.from_dict(x, expected_type=GitArtifactProvenance.SCHEMA) for x in m["parser_artifact_locators"]),
            adapter_artifact_locators=tuple(ArtifactLocator.from_dict(x, expected_type=GitArtifactProvenance.SCHEMA) for x in m["adapter_artifact_locators"]),
            mapping_artifact_locators=tuple(ArtifactLocator.from_dict(x, expected_type=GitArtifactProvenance.SCHEMA) for x in m["mapping_artifact_locators"]),
            fixture_evidence=Certification7AFixtureEvidence.from_dict(m["fixture_evidence"]),
            integrity=integrity, **locs, **{k: m[k] for k in _RECORD_SCALAR_KEYS},
        )


def _parse_corpus_case(raw_case: object, *, idx: int) -> dict[str, Any]:
    lbl = f"corpus.cases[{idx}]"
    m = require_exact_keys(raw_case, CORPUS_CASE_KEYS, label=lbl)
    cid = _strict_str(m["case_id"], label=f"{lbl}.case_id")
    adm_id = validate_opaque_ref(_strict_str(m["admission_id"], label=f"{lbl}.adm_id"), field_name=f"{lbl}.adm_id", expected_prefix="admission")
    cr = require_exact_keys(m["clock_reading"], CORPUS_CLOCK_READING_KEYS, label=f"{lbl}.clock_reading")
    att, max_unc = ClockAttestation.from_dict(cr["attestation"]), cr["configured_max_uncertainty_ms"]
    if att.integrity is not None or type(max_unc) is not int or not (1 <= max_unc <= MAX_JCS_SAFE_INT):
        raise ClosedValidationError(f"{lbl}.clock_reading: invalid clock attestation or uncertainty ceiling")
    req, rctx = CollectionRequest.from_dict(m["collection_request"]), RetrievalContext.from_dict(m["retrieval_context"])
    if req.collection_purpose != "fixture_7a":
        raise ClosedValidationError(f"{lbl}.collection_request: must have collection_purpose == 'fixture_7a'")
    hr = require_exact_keys(m["http_response"], CORPUS_HTTP_RESPONSE_KEYS, label=f"{lbl}.http_response")
    net_ok, st = _strict_bool(hr["network_ok"], label=f"{lbl}.net_ok"), hr["http_status"]
    if st is not None and (type(st) is not int or not (100 <= st <= 999)):
        raise ClosedValidationError(f"{lbl}.http_response.http_status: invalid {st!r}")
    if type(hr["headers"]) is not list or any(type(h) is not list or len(h) != 2 or type(h[0]) is not str or type(h[1]) is not str for h in hr["headers"]):
        raise ClosedValidationError(f"{lbl}.http_response.headers: expected list of [str, str] pairs")
    if type(hr["body_utf8"]) is not str or type(m["expected_completeness_status"]) is not str or m["expected_completeness_status"] not in _COMPLETENESS_STATUSES:
        raise ClosedValidationError(f"{lbl}: invalid body_utf8 or expected_completeness_status")
    if type(m["expected_reasons"]) is not list or any(type(r) is not str or not r for r in m["expected_reasons"]):
        raise ClosedValidationError(f"{lbl}.expected_reasons: expected list of non-empty strings")
    if m["expected_error_code"] is not None:
        _strict_str(m["expected_error_code"], label=f"{lbl}.expected_error_code")
    return {"case_id": cid, "admission_id": adm_id, "clock_attestation": att, "configured_max_uncertainty_ms": max_unc, "collection_request": req, "retrieval_context": rctx, "network_ok": net_ok, "http_status": st, "headers": tuple((h[0], h[1]) for h in hr["headers"]), "body_chunks": (hr["body_utf8"].encode("utf-8"),), "expected_completeness_status": m["expected_completeness_status"], "expected_reasons": tuple(m["expected_reasons"]), "expected_error_code": m["expected_error_code"]}

def _parse_pipeboard_7a_corpus(corpus_bytes: bytes) -> dict[str, Any]:
    m = require_exact_keys(loads_strict_json(corpus_bytes), CORPUS_TOP_LEVEL_KEYS, label="corpus")
    _exact_str(m["$schema"], PIPEBOARD_7A_CORPUS_SCHEMA, label="corpus.$schema")
    validate_opaque_ref(_strict_str(m["corpus_id"], label="corpus.id"), field_name="corpus.id", expected_prefix="corpus")
    tenant_ref = validate_opaque_ref(_strict_str(m["tenant_ref"], label="corpus.tenant"), field_name="corpus.tenant", expected_prefix="tenant")
    key_identity = validate_opaque_ref(_strict_str(m["key_identity"], label="corpus.key"), field_name="corpus.key", expected_prefix="key")
    if type(m["tenant_hmac_key_hex"]) is not str or _HEX64_RE.fullmatch(m["tenant_hmac_key_hex"]) is None:
        raise ClosedValidationError("corpus.tenant_hmac_key_hex: expected 64 lowercase hex chars")
    if type(m["private_account_bindings"]) is not list or len(m["private_account_bindings"]) == 0:
        raise ClosedValidationError("corpus.private_account_bindings: expected non-empty JSON list")
    bindings = tuple((_strict_str(bm["binding_ref"], label="b"), _strict_str(bm["account_ref"], label="a"), _strict_str(bm["private_object_id"], label="id")) for i, raw_b in enumerate(m["private_account_bindings"]) for bm in (require_exact_keys(raw_b, CORPUS_PRIVATE_BINDING_KEYS, label=f"corpus.bindings[{i}]"),))
    if type(m["verified_campaign_pairs"]) is not list or len(m["verified_campaign_pairs"]) < 2:
        raise ClosedValidationError("corpus.verified_campaign_pairs: expected JSON list of >= 2 pairs")
    pairs = tuple((_strict_str(pm["raw_campaign_id"], label="cid"), _strict_str(pm["resource_ref"], label="rref")) for i, raw_p in enumerate(m["verified_campaign_pairs"]) for pm in (require_exact_keys(raw_p, CORPUS_CAMPAIGN_PAIR_KEYS, label=f"corpus.pairs[{i}]"),))
    if type(m["cases"]) is not list or len(m["cases"]) == 0:
        raise ClosedValidationError("corpus.cases: expected non-empty JSON list")
    parsed_cases = tuple(_parse_corpus_case(c, idx=i) for i, c in enumerate(m["cases"]))
    if len({c["admission_id"] for c in parsed_cases}) != len(parsed_cases):
        raise ClosedValidationError("corpus.cases: duplicate admission_id")
    return {"tenant_ref": tenant_ref, "key_identity": key_identity, "secret_bytes": bytes.fromhex(m["tenant_hmac_key_hex"]), "private_bindings": bindings, "campaign_pairs": pairs, "timezone_snapshot": TimezoneRuleSnapshot.from_dict(m["timezone_snapshot"]), "cases": parsed_cases}

def _check_blob_map(blobs: object, *, label: str) -> Mapping[str, bytes]:
    checked = require_mapping(blobs, label=label)
    if any(type(k) is not str or type(v) is not bytes for k, v in checked.items()):
        raise ClosedValidationError(f"{label}: expected Mapping[str, bytes]")
    return checked

def _resolve_verified_object(resolver: Callable[[ArtifactLocator], Mapping[str, Any]], locator: ArtifactLocator, *, label: str) -> Mapping[str, Any]:
    try:
        raw = resolver(locator)
    except ClosedValidationError:
        raise
    except Exception:
        raise ClosedValidationError(f"{label}: failed to resolve store object for {locator.artifact_type!r}") from None
    checked = require_mapping(raw, label=label)
    if "$schema" not in checked or checked["$schema"] != locator.artifact_type or "integrity" not in checked:
        raise ClosedValidationError(f"{label}: expected P1 envelope for {locator.artifact_type!r}")
    integ = P1Integrity.from_dict(checked["integrity"])
    if integ.is_signed and integ.content_digest != p1_content_digest(checked):
        raise ClosedValidationError(f"{label}.integrity.content_digest: mismatch against P1 preimage")
    if ArtifactLocator.for_canonical_bytes(locator.artifact_type, canonicalize_jcs(checked)) != locator:
        raise ClosedValidationError(f"{label}: canonical JCS digest mismatch against ArtifactLocator")
    return checked


def _verify_stage7_and_negative_report(record: Certification7ARecord, resolver: Callable[[ArtifactLocator], Mapping[str, Any]], wheel_bytes: bytes, boundary_prov_loc: ArtifactLocator | None, certified_us: int) -> tuple[NegativeSecurityTestReport, dict[str, Any], SandboxResourceLimits, str, int, int, int, int]:
    sbx_env = _resolve_verified_object(resolver, record.sealed_sandbox_profile_locator, label="sealed_sandbox_profile")
    prov_env = _resolve_verified_object(resolver, record.wheel_build_provenance_locator, label="wheel_build_provenance")
    bound_env = _resolve_verified_object(resolver, record.wheel_boundary_report_locator, label="wheel_boundary_report")
    require_exact_keys(bound_env, _WHEEL_BOUNDARY_ENVELOPE_17_KEYS, label="wheel_boundary_report")
    neg_report = NegativeSecurityTestReport.from_dict(_resolve_verified_object(resolver, record.negative_security_test_report_locator, label="negative_security_test_report"))
    bound_prov_loc = ArtifactLocator.from_dict(bound_env["wheel_build_provenance_locator"], expected_type=_WHEEL_PROVENANCE_SCHEMA)
    bound_ctx = ArtifactLocator.from_dict(bound_env["migration_run_context_locator"], expected_type=_RUN_CONTEXT_SCHEMA)
    _utc_sec_micros(bound_env["verified_at_utc"], label="wheel_boundary_report.verified_at_utc")
    actual_whl_digest = "sha256:" + hashlib.sha256(wheel_bytes).hexdigest()
    if (
        record.wheel_build_provenance_locator != neg_report.wheel_build_provenance_locator or record.wheel_build_provenance_locator != bound_prov_loc
        or (boundary_prov_loc is not None and record.wheel_build_provenance_locator != boundary_prov_loc)
        or record.sealed_sandbox_profile_locator != neg_report.sealed_sandbox_profile_locator
        or record.migration_run_context_locator != neg_report.migration_run_context_locator or record.migration_run_context_locator != bound_ctx
        or record.build_run_id != prov_env["build_run_id"] or bound_env["build_run_id"] != record.build_run_id
        or record.wheel_digest != prov_env["wheel_digest"] or record.wheel_digest != actual_whl_digest
        or bound_env["wheel_digest"] != actual_whl_digest or bound_env["repository"] != "aiconnai/smart-ads"
        or record.source_commit_sha != prov_env["source_commit_sha"] or bound_env["source_commit_sha"] != record.source_commit_sha
        or record.build_backend_digest != prov_env["build_backend_digest"] or bound_env["build_backend_digest"] != record.build_backend_digest
        or record.schema_bundle_digest != prov_env["schema_bundle_digest"] or bound_env["schema_bundle_digest"] != record.schema_bundle_digest
        or any(bound_env[f] is not True for f in ("archive_allowlist_passed", "ast_boundary_scan_passed", "isolated_venv_import_passed"))
    ):
        raise ClosedValidationError("certification_7a_record: Stage 7 / negative report cross-artifact mismatch")
    verify_negative_security_report_against_profile(neg_report, sandbox_profile=sbx_env, wheel_provenance_payload=prov_env, wheel_bytes=wheel_bytes)
    if _utc_sec_micros(neg_report.executed_at_utc, label="neg_report.executed_at_utc") > certified_us:
        raise ClosedValidationError("certification_7a_record: negative_report.executed_at_utc > certified_at_utc")
    sbx_payload = {k: v for k, v in sbx_env.items() if k not in {"$schema", "integrity"}}
    return (neg_report, sbx_payload, SandboxResourceLimits.from_dict(sbx_payload["resource_limits"]), jcs_sha256({k: sbx_payload[k] for k in _SPEC_17_FIELDS}), _utc_sec_micros(sbx_payload["issued_at_utc"], label="sbx.issued"), _utc_sec_micros(sbx_payload["validity"]["from"], label="sbx.from"), _utc_sec_micros(sbx_payload["validity"]["until"], label="sbx.until"), _utc_sec_micros(prov_env["built_at_utc"], label="prov.built"))

def _verify_registry_and_contract(record: Certification7ARecord, resolver: Callable[[ArtifactLocator], Mapping[str, Any]]) -> ResolvedRegistryState:
    snapshot = PrivateRegistrySnapshot.from_dict(_resolve_verified_object(resolver, record.capability.registry_snapshot_locator, label="registry_snapshot"))
    driver_contract = PipeboardPhase1Contract.from_dict(_resolve_verified_object(resolver, record.capability.driver_contract_locator, label="driver_contract"))
    entry = snapshot.get_capability(record.capability.capability_ref, record.capability.resource_scope_ref)
    if (
        entry.state != "declared" or entry.driver_id != record.capability.driver_id or entry.driver_contract_locator != record.capability.driver_contract_locator
        or entry.driver_contract_digest != record.capability.driver_contract_digest or entry.required_metrics != record.capability.required_metrics
        or record.resource_mapping_contract_digest != snapshot.resource_mapping_contract_digest
    ):
        raise ClosedValidationError("certification_7a_record.capability: snapshot capability/contract mismatch")
    return ResolvedRegistryState(record.capability.registry_snapshot_locator, snapshot, record.capability.driver_contract_locator, driver_contract)

def _verify_corpus_and_d26_provenances(record: Certification7ARecord, driver_contract: PipeboardPhase1Contract, resolver: Callable[[ArtifactLocator], Mapping[str, Any]], corpus_bytes: bytes, git_blobs: Mapping[str, bytes], d26_blobs: Mapping[str, bytes], certified_us: int) -> tuple[set[ArtifactLocator], ArtifactLocator]:
    corpus_repo, corpus_path = CORPUS_GIT_PATH
    if corpus_path not in git_blobs or corpus_bytes != git_blobs[corpus_path]:
        raise ClosedValidationError("corpus_bytes: byte mismatch against resolved_git_blobs")
    if "sha256:" + hashlib.sha256(corpus_bytes).hexdigest() != record.fixture_evidence.corpus_digest:
        raise ClosedValidationError("corpus_bytes: SHA-256 mismatch against fixture_evidence.corpus_digest")
    c_prov = GitArtifactProvenance.from_dict(_resolve_verified_object(resolver, record.fixture_evidence.corpus_git_locator, label="corpus_git_prov"))
    if (c_prov.repository, c_prov.path) != (corpus_repo, corpus_path) or c_prov.commit_sha != record.source_commit_sha or _utc_sec_micros(c_prov.resolved_at_utc, label="corpus.resolved") > certified_us:
        raise ClosedValidationError("corpus_git_locator: provenance metadata mismatch")
    verify_git_provenance_against_bytes(c_prov, corpus_bytes)
    unique_locs: set[ArtifactLocator] = {record.fixture_evidence.corpus_git_locator}
    reducer_loc: ArtifactLocator | None = None
    for member, (exp_role, exp_path, exp_oid, exp_sha) in zip(driver_contract.legacy_source_packet.members, PINNED_PIPEBOARD_D26_SPECS, strict=True):
        if exp_path not in d26_blobs:
            raise ClosedValidationError(f"resolved_d26_blobs: missing pinned legacy path {exp_path!r}")
        d26_prov = GitArtifactProvenance.from_dict(_resolve_verified_object(resolver, member.git_artifact_provenance_locator, label=f"d26[{exp_role}]"))
        if (d26_prov.repository, d26_prov.commit_sha, d26_prov.path, d26_prov.git_blob_oid, d26_prov.file_content_sha256) != (PINNED_LEGACY_REPO, PINNED_LEGACY_COMMIT, exp_path, exp_oid, exp_sha) or _utc_sec_micros(d26_prov.resolved_at_utc, label="d26.resolved") > certified_us:
            raise ClosedValidationError(f"d26[{exp_role}]: pinned legacy provenance mismatch")
        verify_git_provenance_against_bytes(d26_prov, d26_blobs[exp_path])
        unique_locs.add(member.git_artifact_provenance_locator)
        if exp_role == "reducer":
            reducer_loc = member.git_artifact_provenance_locator
    if reducer_loc is None or reducer_loc not in record.parser_artifact_locators:
        raise ClosedValidationError("parser_artifact_locators: missing legacy reducer provenance locator")
    return unique_locs, reducer_loc

def _resolve_code_group_provs(locators: tuple[ArtifactLocator, ...], *, resolver: Callable[[ArtifactLocator], Mapping[str, Any]], source_commit_sha: str, reducer_loc: ArtifactLocator, git_blobs: Mapping[str, bytes], d26_blobs: Mapping[str, bytes], certified_us: int, unique_locs: set[ArtifactLocator], label: str) -> list[GitArtifactProvenance]:
    provs: list[GitArtifactProvenance] = []
    for loc in locators:
        prov = GitArtifactProvenance.from_dict(_resolve_verified_object(resolver, loc, label=label))
        if _utc_sec_micros(prov.resolved_at_utc, label=f"{label}.resolved") > certified_us:
            raise ClosedValidationError(f"{label}: resolved_at_utc > certified_at_utc")
        if (prov.repository, prov.path) == (PINNED_LEGACY_REPO, "scripts/operator/meta_daily_contract.py"):
            if loc != reducer_loc or prov.commit_sha != PINNED_LEGACY_COMMIT or prov.path not in d26_blobs:
                raise ClosedValidationError(f"{label}: legacy reducer provenance locator mismatch")
            verify_git_provenance_against_bytes(prov, d26_blobs[prov.path])
        else:
            if prov.repository != "aiconnai/smart-ads" or prov.commit_sha != source_commit_sha or prov.path not in git_blobs:
                raise ClosedValidationError(f"{label}: smart-ads git provenance commit or blob missing")
            verify_git_provenance_against_bytes(prov, git_blobs[prov.path])
        unique_locs.add(loc)
        provs.append(prov)
    return provs

def _verify_all_13_git_provenances(record: Certification7ARecord, *, driver_contract: PipeboardPhase1Contract, resolver: Callable[[ArtifactLocator], Mapping[str, Any]], corpus_bytes: bytes, git_blobs: Mapping[str, bytes], d26_blobs: Mapping[str, bytes], certified_us: int) -> None:
    unique_locs, reducer_loc = _verify_corpus_and_d26_provenances(record, driver_contract, resolver, corpus_bytes, git_blobs, d26_blobs, certified_us)
    kw = {"resolver": resolver, "source_commit_sha": record.source_commit_sha, "reducer_loc": reducer_loc, "git_blobs": git_blobs, "d26_blobs": d26_blobs, "certified_us": certified_us, "unique_locs": unique_locs}
    p_provs = _resolve_code_group_provs(record.parser_artifact_locators, label="parser_prov", **kw)  # type: ignore[arg-type]
    a_provs = _resolve_code_group_provs(record.adapter_artifact_locators, label="adapter_prov", **kw)  # type: ignore[arg-type]
    m_provs = _resolve_code_group_provs(record.mapping_artifact_locators, label="mapping_prov", **kw)  # type: ignore[arg-type]
    if len(unique_locs) != 13 or record.parser_code_digest != compute_parser_code_digest(p_provs) or record.adapter_code_digest != compute_adapter_code_digest(a_provs) or record.mapping_rules_digest != compute_mapping_rules_digest(m_provs, driver_contract.metric_source_mappings):
        raise ClosedValidationError("certification_7a_record: git provenance count or code/mapping digest mismatch")


@dataclass(frozen=True, slots=True)
class _StaticCaseRuntimePorts:
    clock_state: ResolvedClockState
    timezone_snapshot: TimezoneRuleSnapshot
    resolved_registry: ResolvedRegistryState
    prereq_bundle: ResolvedPrerequisiteBundle

    def get_authenticated_clock(self) -> ResolvedClockState: return self.clock_state
    def get_reporting_timezone_rules(self) -> TimezoneRuleSnapshot: return self.timezone_snapshot
    def get_active_registry(self, *, tenant_ref: str) -> ResolvedRegistryState: return self.resolved_registry
    def resolve_prerequisites(self, **kw: Any) -> ResolvedPrerequisiteBundle: return self.prereq_bundle


def _build_verified_boundary_and_inventories(record: Certification7ARecord, corpus: Mapping[str, Any], resolved_registry: ResolvedRegistryState, resolver: Callable[[ArtifactLocator], Mapping[str, Any]]) -> tuple[PrivatePipeboardBindingBoundary, dict[ArtifactLocator, ExpectedResourceInventory]]:
    snap = resolved_registry.snapshot
    if corpus["tenant_ref"] != snap.tenant_ref or corpus["key_identity"] != snap.key_identity:
        raise ClosedValidationError("corpus: tenant_ref or key_identity mismatch against PrivateRegistrySnapshot")
    key_handle = TenantResourceKeyHandle(corpus["tenant_ref"], corpus["key_identity"], corpus["secret_bytes"])
    directory = BidirectionalResourceDirectory(key_handle, snap.resource_ref_mapping_version, snap.domain_separator, "meta", "campaign")
    boundary = PrivatePipeboardBindingBoundary(resolved_registry=resolved_registry, resource_directory=directory)
    for binding_ref, account_ref, private_obj_id in corpus["private_bindings"]:
        boundary.register_private_binding(binding_ref=binding_ref, account_ref=account_ref, private_object_id=private_obj_id)
    for raw_cid, resource_ref in corpus["campaign_pairs"]:
        if derive_resource_ref(key_handle=key_handle, mapping_version=snap.resource_ref_mapping_version, domain_separator=snap.domain_separator, ad_platform_ref="meta", resource_level="campaign", raw_provider_id=raw_cid) != resource_ref:
            raise ClosedValidationError("corpus.verified_campaign_pairs: HMAC resource_ref derivation mismatch")
        boundary.register_verified_campaign_pair(raw_cid, resource_ref)
    known_refs = set(boundary.resource_directory.known_resource_refs())
    inv_locs = sorted({c.expected_resource_inventory_locator for c in record.fixture_evidence.cases}, key=lambda l: canonicalize_jcs(l.to_dict()))
    inv_map: dict[ArtifactLocator, ExpectedResourceInventory] = {}
    for inv_loc in inv_locs:
        inv = ExpectedResourceInventory.from_dict(_resolve_verified_object(resolver, inv_loc, label="expected_resource_inventory"))
        if len(inv.expected_resources) < 1 or any(u.resource_ref not in known_refs for u in inv.expected_resources):
            raise ClosedValidationError("expected_resource_inventory: empty or unverified resource_ref in U")
        boundary.register_authenticated_inventory(inv_loc, inv)
        inv_map[inv_loc] = inv
    return boundary, inv_map

def _verify_case_readback_chronology_and_binding(record: Certification7ARecord, rec_case: Certification7AFixtureCase, *, admitted_at_utc: str, ctx: Mapping[str, Any]) -> None:
    rb_dict = rec_case.runtime_readback.to_dict()
    if rec_case.effective_resource_limits != ctx["sbx_limits"] or any(rb_dict[k] != ctx["sbx_payload"][k] for k in _SHARED_RUNTIME_16_FIELDS):
        raise ClosedValidationError(f"case[{rec_case.case_id}]: runtime_readback or effective_resource_limits mismatch")
    adm_us, start_us = _utc_sec_micros(admitted_at_utc, label="admitted"), _utc_sec_micros(rec_case.started_at_utc, label="start")
    ret_us = parse_timestamp_utc_micros(rec_case.observation_batch.retrieval_context.retrieved_at_utc, field_name="retrieved_at_utc")
    end_us, floor_us = _utc_sec_micros(rec_case.ended_at_utc, label="end"), max(ctx["sbx_issued_us"], ctx["prov_built_us"], ctx["snap_issued_us"], adm_us)
    if not (floor_us <= start_us <= ret_us <= end_us <= ctx["certified_us"] and ctx["sbx_from_us"] <= start_us <= end_us < ctx["sbx_until_us"] and ctx["snap_issued_us"] <= start_us <= end_us <= ctx["certified_us"] < ctx["snap_until_us"]):
        raise ClosedValidationError(f"case[{rec_case.case_id}]: chronology or validity window violation")
    if rec_case.execution_binding_digest != compute_7a_case_execution_binding_digest(case=rec_case, wheel_digest=record.wheel_digest, corpus_digest=record.fixture_evidence.corpus_digest, sealed_sandbox_profile_digest=ctx["sbx_digest"]):
        raise ClosedValidationError(f"case[{rec_case.case_id}].execution_binding_digest: mismatch against recomputed binding")

def _admit_and_verify_case_bindings(record: Certification7ARecord, corpus: Mapping[str, Any], corpus_case: Mapping[str, Any], rec_case: Certification7AFixtureCase, *, resolved_registry: ResolvedRegistryState, boundary: PrivatePipeboardBindingBoundary, inv: ExpectedResourceInventory, ctx: Mapping[str, Any]) -> tuple[CellRuntimePorts, AdmittedCollectionBundle]:
    att = corpus_case["clock_attestation"]
    clk_state = ResolvedClockState(ArtifactLocator.for_canonical_bytes(ClockAttestation.SCHEMA, canonicalize_jcs(att.to_dict())), att, corpus_case["configured_max_uncertainty_ms"])
    prereq = ResolvedPrerequisiteBundle(PurposePrerequisiteLocators(purpose="fixture_7a", sealed_sandbox_profile_locator=record.sealed_sandbox_profile_locator, regression_fixture_locator=ctx["expected_reg_loc"]))
    sp = _StaticCaseRuntimePorts(clk_state, corpus["timezone_snapshot"], resolved_registry, prereq)
    cell_ports = CellRuntimePorts(sp, sp, sp, sp)
    adm_bundle = admit_collection(corpus_case["collection_request"], cell_ports, admission_id=corpus_case["admission_id"])
    adm = adm_bundle.admitted
    if rec_case.admitted_collection_digest != adm_bundle.locator.content_digest:
        raise ClosedValidationError(f"case[{rec_case.case_id}].admitted_collection_digest: mismatch against recomputed admission")
    resolved_inv_loc, _ = boundary.resolve_authenticated_inventory(binding_ref=adm.binding_ref, account_ref=adm.account_ref, resource_scope_ref=adm.resource_scope_ref, date_range=adm.computed_date_range)
    if (
        resolved_inv_loc != rec_case.expected_resource_inventory_locator
        or inv.registry_snapshot_locator != adm.registry_snapshot_locator or adm.registry_snapshot_locator != record.capability.registry_snapshot_locator
        or inv.resource_scope_ref != adm.resource_scope_ref or adm.resource_scope_ref != adm.canonical_query_contract.resource_scope_ref
        or adm.resource_scope_ref != record.capability.resource_scope_ref or adm.driver_contract_locator != record.capability.driver_contract_locator
        or rec_case.source_contract_ref != f"opaque-driver-contract:{record.capability.driver_contract_digest}"
        or (inv.tenant_ref, inv.binding_ref, inv.account_ref, inv.date_range) != (adm.tenant_ref, adm.binding_ref, adm.account_ref, adm.computed_date_range)
        or adm.canonical_query_contract.requested_capabilities != (record.capability.capability_ref,)
        or adm.canonical_query_contract.metric_semantic_refs != record.capability.required_metrics
        or adm.purpose_prerequisite_locators.sealed_sandbox_profile_locator != record.sealed_sandbox_profile_locator
        or adm.purpose_prerequisite_locators.regression_fixture_locator != ctx["expected_reg_loc"]
    ):
        raise ClosedValidationError(f"case[{rec_case.case_id}]: snapshot/scope/inventory/query prerequisite mismatch")
    _verify_case_readback_chronology_and_binding(record, rec_case, admitted_at_utc=adm.admitted_at_utc, ctx=ctx)
    return cell_ports, adm_bundle

def _verify_and_replay_single_case(record: Certification7ARecord, corpus: Mapping[str, Any], corpus_case: Mapping[str, Any], rec_case: Certification7AFixtureCase, *, resolved_registry: ResolvedRegistryState, boundary: PrivatePipeboardBindingBoundary, inv: ExpectedResourceInventory, ctx: Mapping[str, Any]) -> None:
    cell_ports, adm_bundle = _admit_and_verify_case_bindings(record, corpus, corpus_case, rec_case, resolved_registry=resolved_registry, boundary=boundary, inv=inv, ctx=ctx)
    adapter = PipeboardFixtureAdapter(boundary=boundary)
    reg_loc = adapter.register_fixture_case(admitted=adm_bundle.admitted, retrieval_context=corpus_case["retrieval_context"], network_ok=corpus_case["network_ok"], http_status=corpus_case["http_status"], headers=corpus_case["headers"], body_chunks=corpus_case["body_chunks"])
    ev = evaluate_fixture_collection(corpus_case["collection_request"], admission_id=corpus_case["admission_id"], cell_ports=cell_ports, fixture_port=adapter, inventory_port=boundary)
    recorded_batch = adapter.get_recorded_batch(ev.admitted_locator)
    exp_errs = () if corpus_case["expected_error_code"] is None else (corpus_case["expected_error_code"],)
    if (
        reg_loc != adm_bundle.locator or ev.admitted_locator != adm_bundle.locator or recorded_batch != rec_case.observation_batch
        or tuple(e.error_code for e in recorded_batch.normalized_errors) != exp_errs or ev.completeness.status != rec_case.observed_completeness_status
        or ev.completeness.status != corpus_case["expected_completeness_status"] or ev.completeness.reasons != corpus_case["expected_reasons"]
        or ev.completeness.normalized_fact_set_digest != rec_case.normalized_fact_set_digest
    ):
        raise ClosedValidationError(f"case[{rec_case.case_id}]: deterministic offline 7A replay mismatch")


def verify_certification_7a_record(record: Certification7ARecord, *, object_resolver: Callable[[ArtifactLocator], Mapping[str, Any]], wheel_bytes: bytes, corpus_bytes: bytes, resolved_git_blobs: Mapping[str, bytes], resolved_d26_blobs: Mapping[str, bytes], boundary_report_wheel_provenance_locator: ArtifactLocator | None = None) -> None:
    """Materially verify `record` against Store envelopes, Git/d26 blobs, and offline 7A replay."""
    checked = _reparse(record, Certification7ARecord, label="record")
    if not callable(object_resolver) or type(wheel_bytes) is not bytes or len(wheel_bytes) == 0 or type(corpus_bytes) is not bytes or len(corpus_bytes) == 0:
        raise ClosedValidationError("verify_certification_7a_record: invalid resolver or empty wheel/corpus bytes")
    git_blobs, d26_blobs = _check_blob_map(resolved_git_blobs, label="resolved_git_blobs"), _check_blob_map(resolved_d26_blobs, label="resolved_d26_blobs")
    if boundary_report_wheel_provenance_locator is not None:
        _require_typed_locator(boundary_report_wheel_provenance_locator, _WHEEL_PROVENANCE_SCHEMA, label="boundary_report_wheel_provenance_locator")
    certified_us = _utc_sec_micros(checked.certified_at_utc, label="record.certified_at_utc")
    neg_rep, sbx_payload, sbx_limits, sbx_digest, sbx_issued_us, sbx_from_us, sbx_until_us, prov_built_us = _verify_stage7_and_negative_report(checked, object_resolver, wheel_bytes, boundary_report_wheel_provenance_locator, certified_us)
    resolved_registry = _verify_registry_and_contract(checked, object_resolver)
    _verify_all_13_git_provenances(checked, driver_contract=resolved_registry.driver_contract, resolver=object_resolver, corpus_bytes=corpus_bytes, git_blobs=git_blobs, d26_blobs=d26_blobs, certified_us=certified_us)
    expected_reg_loc = ArtifactLocator.for_canonical_bytes(RegressionFixtureV1.SCHEMA, canonicalize_jcs(checked.fixture_evidence.regression_fixture.to_dict()))
    corpus = _parse_pipeboard_7a_corpus(corpus_bytes)
    if [c["case_id"] for c in corpus["cases"]] != [c.case_id for c in checked.fixture_evidence.cases]:
        raise ClosedValidationError("fixture_evidence.cases: case_id list diverges from corpus")
    boundary, inv_map = _build_verified_boundary_and_inventories(checked, corpus, resolved_registry, object_resolver)
    neg_refs = {r.sandbox_instance_ref for c in neg_rep.cases for r in c.runs}
    ctx = {"sbx_payload": sbx_payload, "sbx_limits": sbx_limits, "sbx_digest": sbx_digest, "sbx_issued_us": sbx_issued_us, "sbx_from_us": sbx_from_us, "sbx_until_us": sbx_until_us, "prov_built_us": prov_built_us, "snap_issued_us": _utc_sec_micros(resolved_registry.snapshot.issued_at_utc, label="snap.issued"), "snap_until_us": _utc_sec_micros(resolved_registry.snapshot.valid_until_utc, label="snap.until"), "certified_us": certified_us, "expected_reg_loc": expected_reg_loc}
    for corpus_case, rec_case in zip(corpus["cases"], checked.fixture_evidence.cases, strict=True):
        if rec_case.sandbox_instance_ref in neg_refs:
            raise ClosedValidationError(f"case[{rec_case.case_id}]: sandbox_instance_ref collides with negative report")
        _verify_and_replay_single_case(checked, corpus, corpus_case, rec_case, resolved_registry=resolved_registry, boundary=boundary, inv=inv_map[rec_case.expected_resource_inventory_locator], ctx=ctx)


__all__ = [
    "ADAPTER_ARTIFACT_PATHS", "CERTIFICATION_7A_RECORD_SCHEMA", "CORPUS_CAMPAIGN_PAIR_KEYS", "CORPUS_CASE_KEYS",
    "CORPUS_CLOCK_READING_KEYS", "CORPUS_GIT_PATH", "CORPUS_HTTP_RESPONSE_KEYS", "CORPUS_PRIVATE_BINDING_KEYS",
    "CORPUS_TOP_LEVEL_KEYS", "Certification7ACapabilityBinding", "Certification7AFixtureCase",
    "Certification7AFixtureEvidence", "Certification7ARecord", "MAPPING_ARTIFACT_PATHS", "PARSER_ARTIFACT_PATHS",
    "PIPEBOARD_7A_CORPUS_SCHEMA", "compute_7a_case_execution_binding_digest", "compute_adapter_code_digest",
    "compute_mapping_rules_digest", "compute_parser_code_digest", "verify_certification_7a_record",
]
