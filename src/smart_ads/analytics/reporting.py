"""Closed `report_execution/v1`, deterministic report rendering, and full-chain verifier (ADR-0001 §§6.4, 11.1)."""
from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from itertools import pairwise
from typing import Any, ClassVar, Final, TypeVar

from smart_ads.analytics.cells import ANALYSIS_EXECUTION_TYPE, DATASET_SNAPSHOT_TYPE, REPLAY_BUNDLE_TYPE, RUN_CONTEXT_TYPE, AnalysisResultSchema
from smart_ads.analytics.certification import CERTIFICATION_RECORD_SCHEMA, AnalyticalCertificationRecord, AttestedCertificationInput, verify_certification_record
from smart_ads.analytics.formulas import CertificationInput, DerivedCertificationStatus
from smart_ads.analytics.intelligence import FINDING_DETECTED, FINDING_INCONCLUSIVE, FINDING_SCHEMA, FINDING_STATUSES, FINDING_TYPES, AnalysisEvidence, EvaluationContext, Finding
from smart_ads.analytics.policy import AnalysisPolicy
from smart_ads.analytics.replay_bundle import AnalysisReplayInputBundle
from smart_ads.analytics.results import AnalysisExecution, AnalysisResult, verify_analysis_execution
from smart_ads.contracts.effects import EffectProof, _loc_from, _P1EnvelopeBase, _reparse_p1, _require_json_list, _safe_int, _sorted_locator_tuple, _split_p1_envelope, _strict_id, _strict_str, _typed_locator, _verify_p1_integrity, sort_artifact_locators
from smart_ads.contracts.git_provenance import GitArtifactProvenance
from smart_ads.contracts.jcs import ADR_P1_DOMAIN_PREFIXES, ArtifactLocator, P1Integrity, canonicalize_jcs, jcs_sha256, sort_utf8_strings
from smart_ads.contracts.operational_evidence import AlgorithmProvenanceIdentity, OperationalReadEvidence
from smart_ads.contracts.scalars import ClosedValidationError, require_exact_keys, validate_envelope_timestamp_utc, validate_iso_date, validate_sha256_prefixed, validate_timestamp_utc6
from smart_ads.domain.catalog import DatasetSnapshot, GenerationManifest
from smart_ads.domain.curation import CurationExecution
from smart_ads.domain.registry import ExpectedResourceInventory

_T = TypeVar("_T")
REPORT_EXECUTION_SCHEMA: Final[str] = "smart_ads/report_execution/v1"
_ATTESTED_INPUT_KEYS: Final[frozenset[str]] = frozenset({"status", "origin", "independently_validated"})


def _resolve_digest(current: object, expected: str, *, field_name: str) -> str:
    raw = _strict_str(current, field_name=field_name)
    if raw == "":
        return expected
    if validate_sha256_prefixed(raw, field_name=field_name) != expected:
        raise ClosedValidationError(f"{field_name}: recomputed {expected!r} != asserted {raw!r}")
    return raw


def _serialize_attested_input(item: AttestedCertificationInput) -> dict[str, Any]:
    return {"status": item.certification_input.status.value, "origin": item.certification_input.origin, "independently_validated": item.independently_validated}


def _parse_attested_input(data: object, *, label: str) -> AttestedCertificationInput:
    m = require_exact_keys(data, _ATTESTED_INPUT_KEYS, label=label)
    if type(m["independently_validated"]) is not bool:
        raise ClosedValidationError(f"{label}.independently_validated: expected bool")
    cert_in = CertificationInput(status=DerivedCertificationStatus.from_wire(m["status"]), origin=m["origin"])
    return AttestedCertificationInput(certification_input=cert_in, independently_validated=m["independently_validated"])


def _validate_attested_inputs(values: object, *, field_name: str) -> tuple[AttestedCertificationInput, ...]:
    if not isinstance(values, (list, tuple)) or not values:
        raise ClosedValidationError(f"{field_name}: expected non-empty list or tuple of AttestedCertificationInput")
    out: list[AttestedCertificationInput] = []
    for idx, item in enumerate(values):
        if type(item) is not AttestedCertificationInput:
            raise ClosedValidationError(f"{field_name}[{idx}]: expected AttestedCertificationInput")
        out.append(_parse_attested_input(_serialize_attested_input(item), label=f"{field_name}[{idx}]"))
    return tuple(out)


def _union_artifact_locators(
    locators: Iterable[ArtifactLocator], *, expected_type: str, field_name: str
) -> tuple[ArtifactLocator, ...]:
    unique = {canonicalize_jcs(_typed_locator(loc, field_name=field_name, expected_type=expected_type).to_dict()): loc for loc in locators}
    if not unique:
        raise ClosedValidationError(f"{field_name}: transitive locator union is empty")
    return tuple(_typed_locator(unique[k], field_name=field_name, expected_type=expected_type) for k in sorted(unique))


def _validate_report_header_scalars(obj: CanonicalReportInput | CanonicalReportResult, *, label: str) -> None:
    validate_sha256_prefixed(_strict_str(obj.dataset_snapshot_digest, field_name=f"{label}.dataset_snapshot_digest"), field_name=f"{label}.dataset_snapshot_digest")
    validate_sha256_prefixed(_strict_str(obj.canonical_result_digest, field_name=f"{label}.canonical_result_digest"), field_name=f"{label}.canonical_result_digest")
    validate_timestamp_utc6(_strict_str(obj.evaluation_instant_utc, field_name=f"{label}.evaluation_instant_utc"), field_name=f"{label}.evaluation_instant_utc")
    validate_iso_date(_strict_str(obj.window_end_date, field_name=f"{label}.window_end_date"), field_name=f"{label}.window_end_date")
    _strict_id(obj.metrics_result_key, field_name=f"{label}.metrics_result_key")
    if not isinstance(obj.derived_certification_status, DerivedCertificationStatus):
        raise ClosedValidationError(f"{label}.derived_certification_status: expected DerivedCertificationStatus")
    if type(obj.mutation_recommendations_blocked) is not bool:
        raise ClosedValidationError(f"{label}.mutation_recommendations_blocked: expected bool")


@dataclass(frozen=True, slots=True)
class CanonicalReportInput:
    """Closed 12-member `canonical_report_input` bound inside `report_execution/v1`."""

    KEYS: ClassVar[frozenset[str]] = frozenset(
        "dataset_snapshot_digest canonical_result_digest evaluation_instant_utc window_end_date "
        "metrics_result_key expected_resource_inventory_locator curation_execution_locator "
        "restatement_history_generation_locators attested_certification_inputs finding_digests "
        "derived_certification_status mutation_recommendations_blocked".split()
    )

    dataset_snapshot_digest: str
    canonical_result_digest: str
    evaluation_instant_utc: str
    window_end_date: str
    metrics_result_key: str
    expected_resource_inventory_locator: ArtifactLocator
    curation_execution_locator: ArtifactLocator
    restatement_history_generation_locators: tuple[ArtifactLocator, ...]
    attested_certification_inputs: tuple[AttestedCertificationInput, ...]
    finding_digests: tuple[str, ...]
    derived_certification_status: DerivedCertificationStatus
    mutation_recommendations_blocked: bool

    def __post_init__(self) -> None:
        label = "canonical_report_input"
        _validate_report_header_scalars(self, label=label)
        _typed_locator(self.expected_resource_inventory_locator, field_name=f"{label}.expected_resource_inventory_locator", expected_type=ExpectedResourceInventory.SCHEMA)
        _typed_locator(self.curation_execution_locator, field_name=f"{label}.curation_execution_locator", expected_type=CurationExecution.SCHEMA)
        object.__setattr__(self, "restatement_history_generation_locators", _sorted_locator_tuple(self.restatement_history_generation_locators, field_name=f"{label}.restatement_history_generation_locators", expected_type=GenerationManifest.SCHEMA, allow_empty=True))
        object.__setattr__(self, "attested_certification_inputs", _validate_attested_inputs(self.attested_certification_inputs, field_name=f"{label}.attested_certification_inputs"))
        if not isinstance(self.finding_digests, (list, tuple)):
            raise ClosedValidationError(f"{label}.finding_digests: expected list or tuple")
        raw_digests = tuple(_strict_str(d, field_name=f"{label}.finding_digests") for d in self.finding_digests)
        sorted_digests = sort_utf8_strings(raw_digests, field_name=f"{label}.finding_digests", allow_empty=True, validator=lambda d: validate_sha256_prefixed(d, field_name=f"{label}.finding_digests"))
        if raw_digests != sorted_digests:
            raise ClosedValidationError(f"{label}.finding_digests: must already be sorted by raw UTF-8 bytes")
        if self.mutation_recommendations_blocked and not sorted_digests:
            raise ClosedValidationError(f"{label}: empty finding_digests cannot block mutation recommendations")
        object.__setattr__(self, "finding_digests", sorted_digests)

    def digest(self) -> str:
        return jcs_sha256(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "dataset_snapshot_digest": self.dataset_snapshot_digest, "canonical_result_digest": self.canonical_result_digest,
            "evaluation_instant_utc": self.evaluation_instant_utc, "window_end_date": self.window_end_date,
            "metrics_result_key": self.metrics_result_key,
            "expected_resource_inventory_locator": self.expected_resource_inventory_locator.to_dict(),
            "curation_execution_locator": self.curation_execution_locator.to_dict(),
            "restatement_history_generation_locators": [loc.to_dict() for loc in self.restatement_history_generation_locators],
            "attested_certification_inputs": [_serialize_attested_input(item) for item in self.attested_certification_inputs],
            "finding_digests": list(self.finding_digests),
            "derived_certification_status": self.derived_certification_status.value,
            "mutation_recommendations_blocked": self.mutation_recommendations_blocked,
        }

    @classmethod
    def from_dict(cls, data: object) -> CanonicalReportInput:
        m = require_exact_keys(data, cls.KEYS, label="canonical_report_input")
        raw_hist = _require_json_list(m, "restatement_history_generation_locators", label="canonical_report_input")
        raw_att = _require_json_list(m, "attested_certification_inputs", label="canonical_report_input")
        raw_fdigs = _require_json_list(m, "finding_digests", label="canonical_report_input")
        return cls(
            m["dataset_snapshot_digest"], m["canonical_result_digest"], m["evaluation_instant_utc"],
            m["window_end_date"], m["metrics_result_key"],
            _loc_from(m, "expected_resource_inventory_locator", ExpectedResourceInventory.SCHEMA),
            _loc_from(m, "curation_execution_locator", CurationExecution.SCHEMA),
            tuple(ArtifactLocator.from_dict(h, expected_type=GenerationManifest.SCHEMA) for h in raw_hist),
            tuple(_parse_attested_input(a, label="canonical_report_input.attested_certification_inputs[]") for a in raw_att),
            tuple(raw_fdigs), DerivedCertificationStatus.from_wire(m["derived_certification_status"]),
            m["mutation_recommendations_blocked"],
        )


@dataclass(frozen=True, slots=True)
class ReportFindingSummary:
    """Closed 5-member finding summary inside `CanonicalReportResult`."""

    KEYS: ClassVar[frozenset[str]] = frozenset(
        "finding_key finding_type finding_status mutation_recommendation_blocked finding_digest".split()
    )

    finding_key: str
    finding_type: str
    finding_status: str
    mutation_recommendation_blocked: bool
    finding_digest: str

    def __post_init__(self) -> None:
        label = "report_finding_summary"
        key = _strict_id(self.finding_key, field_name=f"{label}.finding_key")
        if not key.startswith("finding:sha256:"):
            raise ClosedValidationError(f"{label}.finding_key: invalid prefix")
        validate_sha256_prefixed(key.removeprefix("finding:"), field_name=f"{label}.finding_key")
        if _strict_str(self.finding_type, field_name=f"{label}.finding_type") not in FINDING_TYPES:
            raise ClosedValidationError(f"{label}.finding_type: invalid {self.finding_type!r}")
        if _strict_str(self.finding_status, field_name=f"{label}.finding_status") not in FINDING_STATUSES:
            raise ClosedValidationError(f"{label}.finding_status: invalid {self.finding_status!r}")
        if type(self.mutation_recommendation_blocked) is not bool:
            raise ClosedValidationError(f"{label}.mutation_recommendation_blocked: expected bool")
        validate_sha256_prefixed(_strict_str(self.finding_digest, field_name=f"{label}.finding_digest"), field_name=f"{label}.finding_digest")

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_key": self.finding_key, "finding_type": self.finding_type,
            "finding_status": self.finding_status, "mutation_recommendation_blocked": self.mutation_recommendation_blocked,
            "finding_digest": self.finding_digest,
        }

    @classmethod
    def from_dict(cls, data: object) -> ReportFindingSummary:
        m = require_exact_keys(data, cls.KEYS, label="report_finding_summary")
        return cls(m["finding_key"], m["finding_type"], m["finding_status"], m["mutation_recommendation_blocked"], m["finding_digest"])


def _raise_summary_type(label: str) -> Any:
    raise ClosedValidationError(f"{label}.finding_summaries: expected ReportFindingSummary")


@dataclass(frozen=True, slots=True)
class CanonicalReportResult:
    """Closed 11-member deterministic output of `render_canonical_report_result`."""

    KEYS: ClassVar[frozenset[str]] = frozenset(
        "dataset_snapshot_digest canonical_result_digest evaluation_instant_utc window_end_date "
        "metrics_result_key derived_certification_status mutation_recommendations_blocked "
        "finding_count detected_finding_count inconclusive_finding_count finding_summaries".split()
    )

    dataset_snapshot_digest: str
    canonical_result_digest: str
    evaluation_instant_utc: str
    window_end_date: str
    metrics_result_key: str
    derived_certification_status: DerivedCertificationStatus
    mutation_recommendations_blocked: bool
    finding_count: int
    detected_finding_count: int
    inconclusive_finding_count: int
    finding_summaries: tuple[ReportFindingSummary, ...]

    def __post_init__(self) -> None:
        label = "canonical_report_result"
        _validate_report_header_scalars(self, label=label)
        if not isinstance(self.finding_summaries, (list, tuple)):
            raise ClosedValidationError(f"{label}.finding_summaries: expected list or tuple")
        items = tuple(
            ReportFindingSummary.from_dict(s.to_dict()) if type(s) is ReportFindingSummary else _raise_summary_type(label)
            for s in self.finding_summaries
        )
        keys = [s.finding_key.encode("utf-8") for s in items]
        if len(set(keys)) != len(keys) or any(a > b for a, b in pairwise(keys)):
            raise ClosedValidationError(f"{label}.finding_summaries: must be unique and sorted by raw UTF-8 finding_key")
        object.__setattr__(self, "finding_summaries", items)
        f_cnt = _safe_int(self.finding_count, field_name=f"{label}.finding_count", minimum=0)
        d_cnt = _safe_int(self.detected_finding_count, field_name=f"{label}.detected_finding_count", minimum=0)
        i_cnt = _safe_int(self.inconclusive_finding_count, field_name=f"{label}.inconclusive_finding_count", minimum=0)
        exp_d = sum(1 for s in items if s.finding_status == FINDING_DETECTED)
        exp_i = sum(1 for s in items if s.finding_status == FINDING_INCONCLUSIVE)
        if (f_cnt, d_cnt, i_cnt) != (len(items), exp_d, exp_i):
            raise ClosedValidationError(f"{label}: finding count fields disagree with summaries")
        if self.mutation_recommendations_blocked != any(s.mutation_recommendation_blocked for s in items):
            raise ClosedValidationError(f"{label}: mutation_recommendations_blocked disagrees with finding_summaries")

    def digest(self) -> str:
        return jcs_sha256(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "dataset_snapshot_digest": self.dataset_snapshot_digest, "canonical_result_digest": self.canonical_result_digest,
            "evaluation_instant_utc": self.evaluation_instant_utc, "window_end_date": self.window_end_date,
            "metrics_result_key": self.metrics_result_key,
            "derived_certification_status": self.derived_certification_status.value,
            "mutation_recommendations_blocked": self.mutation_recommendations_blocked,
            "finding_count": self.finding_count, "detected_finding_count": self.detected_finding_count,
            "inconclusive_finding_count": self.inconclusive_finding_count,
            "finding_summaries": [s.to_dict() for s in self.finding_summaries],
        }

    @classmethod
    def from_dict(cls, data: object) -> CanonicalReportResult:
        m = require_exact_keys(data, cls.KEYS, label="canonical_report_result")
        raw_sums = _require_json_list(m, "finding_summaries", label="canonical_report_result")
        return cls(
            m["dataset_snapshot_digest"], m["canonical_result_digest"], m["evaluation_instant_utc"],
            m["window_end_date"], m["metrics_result_key"],
            DerivedCertificationStatus.from_wire(m["derived_certification_status"]),
            m["mutation_recommendations_blocked"], m["finding_count"], m["detected_finding_count"],
            m["inconclusive_finding_count"], tuple(ReportFindingSummary.from_dict(s) for s in raw_sums),
        )


def _check_findings_against_input(
    fresh_input: CanonicalReportInput, findings: Sequence[Finding]
) -> tuple[ReportFindingSummary, ...]:
    if isinstance(findings, (str, bytes)) or not isinstance(findings, Sequence):
        raise ClosedValidationError("findings: expected Sequence of Finding")
    checked: list[Finding] = []
    seen_keys: set[str] = set()
    for idx, item in enumerate(findings):
        if type(item) is not Finding:
            raise ClosedValidationError(f"findings[{idx}]: expected Finding")
        fresh_f = Finding.from_dict(item.to_dict())
        if fresh_f.finding_key in seen_keys or fresh_f.result_key != fresh_input.metrics_result_key:
            raise ClosedValidationError(f"findings[{idx}]: duplicate finding_key or result_key mismatch")
        seen_keys.add(fresh_f.finding_key)
        checked.append(fresh_f)
    ordered = tuple(sorted(checked, key=lambda f: f.finding_key.encode("utf-8")))
    if tuple(sorted((f.finding_digest for f in ordered), key=lambda d: d.encode("utf-8"))) != fresh_input.finding_digests:
        raise ClosedValidationError("findings: finding_digest set differs from report_input.finding_digests")
    return tuple(
        ReportFindingSummary(f.finding_key, f.finding_type, f.finding_status, f.mutation_recommendation_blocked, f.finding_digest)
        for f in ordered
    )


def render_canonical_report_result(
    report_input: CanonicalReportInput, findings: Sequence[Finding]
) -> CanonicalReportResult:
    """Deterministically render `CanonicalReportResult` from `report_input` and `findings`."""
    if type(report_input) is not CanonicalReportInput:
        raise ClosedValidationError("report_input: expected CanonicalReportInput")
    fresh_in = CanonicalReportInput.from_dict(report_input.to_dict())
    summaries = _check_findings_against_input(fresh_in, findings)
    return CanonicalReportResult(
        fresh_in.dataset_snapshot_digest, fresh_in.canonical_result_digest,
        fresh_in.evaluation_instant_utc, fresh_in.window_end_date, fresh_in.metrics_result_key,
        fresh_in.derived_certification_status, fresh_in.mutation_recommendations_blocked,
        len(summaries), sum(1 for s in summaries if s.finding_status == FINDING_DETECTED),
        sum(1 for s in summaries if s.finding_status == FINDING_INCONCLUSIVE), summaries,
    )


@dataclass(frozen=True, slots=True)
class ReportExecution(_P1EnvelopeBase):
    """Closed P1 `smart_ads/report_execution/v1` envelope (19 core + `integrity` = 20 keys)."""

    SCHEMA: ClassVar[str] = REPORT_EXECUTION_SCHEMA
    P1_DOMAIN_PREFIX: ClassVar[str] = ADR_P1_DOMAIN_PREFIXES[REPORT_EXECUTION_SCHEMA]
    CORE_KEYS: ClassVar[frozenset[str]] = frozenset(
        "$schema report_id migration_run_context_locator dataset_snapshot_locator "
        "analysis_replay_input_bundle_locator analysis_execution_locator analysis_policy_locator "
        "finding_locators certification_record_locators operational_read_evidence_locators "
        "operational_read_effect_proof_locators operational_read_effect_proof_set_digest "
        "report_template_provenance_locator render_algorithm_identity canonical_report_input "
        "canonical_report_input_digest canonical_report_result canonical_report_result_digest "
        "executed_at_utc".split()
    )
    KEYS: ClassVar[frozenset[str]] = CORE_KEYS | {"integrity"}

    report_id: str
    migration_run_context_locator: ArtifactLocator
    dataset_snapshot_locator: ArtifactLocator
    analysis_replay_input_bundle_locator: ArtifactLocator
    analysis_execution_locator: ArtifactLocator
    analysis_policy_locator: ArtifactLocator
    finding_locators: tuple[ArtifactLocator, ...]
    certification_record_locators: tuple[ArtifactLocator, ...]
    operational_read_evidence_locators: tuple[ArtifactLocator, ...]
    operational_read_effect_proof_locators: tuple[ArtifactLocator, ...]
    report_template_provenance_locator: ArtifactLocator
    render_algorithm_identity: AlgorithmProvenanceIdentity
    canonical_report_input: CanonicalReportInput
    canonical_report_result: CanonicalReportResult
    executed_at_utc: str
    operational_read_effect_proof_set_digest: str = ""
    canonical_report_input_digest: str = ""
    canonical_report_result_digest: str = ""
    integrity: P1Integrity | None = None

    def __post_init__(self) -> None:
        label = "report_execution"
        _strict_id(self.report_id, field_name=f"{label}.report_id")
        self._validate_locators(label)
        if type(self.render_algorithm_identity) is not AlgorithmProvenanceIdentity:
            raise ClosedValidationError(f"{label}.render_algorithm_identity: expected AlgorithmProvenanceIdentity")
        AlgorithmProvenanceIdentity.from_dict(self.render_algorithm_identity.to_dict())
        self._validate_report_payloads(label)
        validate_envelope_timestamp_utc(self.executed_at_utc, field_name=f"{label}.executed_at_utc")
        _verify_p1_integrity(self.integrity, self.to_dict, label=label)

    def _validate_locators(self, label: str) -> None:
        _typed_locator(self.migration_run_context_locator, field_name=f"{label}.migration_run_context_locator", expected_type=RUN_CONTEXT_TYPE)
        _typed_locator(self.dataset_snapshot_locator, field_name=f"{label}.dataset_snapshot_locator", expected_type=DATASET_SNAPSHOT_TYPE)
        _typed_locator(self.analysis_replay_input_bundle_locator, field_name=f"{label}.analysis_replay_input_bundle_locator", expected_type=REPLAY_BUNDLE_TYPE)
        _typed_locator(self.analysis_execution_locator, field_name=f"{label}.analysis_execution_locator", expected_type=ANALYSIS_EXECUTION_TYPE)
        _typed_locator(self.analysis_policy_locator, field_name=f"{label}.analysis_policy_locator", expected_type=AnalysisPolicy.SCHEMA)
        _typed_locator(self.report_template_provenance_locator, field_name=f"{label}.report_template_provenance_locator", expected_type=GitArtifactProvenance.SCHEMA)
        object.__setattr__(self, "finding_locators", _sorted_locator_tuple(self.finding_locators, field_name=f"{label}.finding_locators", expected_type=FINDING_SCHEMA, allow_empty=True))
        object.__setattr__(self, "certification_record_locators", _sorted_locator_tuple(self.certification_record_locators, field_name=f"{label}.certification_record_locators", expected_type=CERTIFICATION_RECORD_SCHEMA, allow_empty=False))
        object.__setattr__(self, "operational_read_evidence_locators", _sorted_locator_tuple(self.operational_read_evidence_locators, field_name=f"{label}.operational_read_evidence_locators", expected_type=OperationalReadEvidence.SCHEMA, allow_empty=False))
        pf_locs = _sorted_locator_tuple(self.operational_read_effect_proof_locators, field_name=f"{label}.operational_read_effect_proof_locators", expected_type=EffectProof.SCHEMA, allow_empty=False)
        object.__setattr__(self, "operational_read_effect_proof_locators", pf_locs)
        object.__setattr__(self, "operational_read_effect_proof_set_digest", _resolve_digest(self.operational_read_effect_proof_set_digest, jcs_sha256([loc.to_dict() for loc in pf_locs]), field_name=f"{label}.operational_read_effect_proof_set_digest"))

    def _validate_report_payloads(self, label: str) -> None:
        if type(self.canonical_report_input) is not CanonicalReportInput or type(self.canonical_report_result) is not CanonicalReportResult:
            raise ClosedValidationError(f"{label}: expected CanonicalReportInput and CanonicalReportResult")
        fresh_in = CanonicalReportInput.from_dict(self.canonical_report_input.to_dict())
        fresh_res = CanonicalReportResult.from_dict(self.canonical_report_result.to_dict())
        object.__setattr__(self, "canonical_report_input", fresh_in)
        object.__setattr__(self, "canonical_report_result", fresh_res)
        object.__setattr__(self, "canonical_report_input_digest", _resolve_digest(self.canonical_report_input_digest, fresh_in.digest(), field_name=f"{label}.canonical_report_input_digest"))
        object.__setattr__(self, "canonical_report_result_digest", _resolve_digest(self.canonical_report_result_digest, fresh_res.digest(), field_name=f"{label}.canonical_report_result_digest"))
        in_tuple = (fresh_in.dataset_snapshot_digest, fresh_in.canonical_result_digest, fresh_in.evaluation_instant_utc, fresh_in.window_end_date, fresh_in.metrics_result_key, fresh_in.derived_certification_status, fresh_in.mutation_recommendations_blocked, len(fresh_in.finding_digests))
        res_tuple = (fresh_res.dataset_snapshot_digest, fresh_res.canonical_result_digest, fresh_res.evaluation_instant_utc, fresh_res.window_end_date, fresh_res.metrics_result_key, fresh_res.derived_certification_status, fresh_res.mutation_recommendations_blocked, fresh_res.finding_count)
        if in_tuple != res_tuple or len(self.finding_locators) != fresh_res.finding_count:
            raise ClosedValidationError(f"{label}: canonical_report_input, canonical_report_result, and finding_locators disagree")

    @classmethod
    def from_dict(cls, data: object, *, require_signed: bool = False) -> ReportExecution:
        m, integrity = _split_p1_envelope(data, core_keys=cls.CORE_KEYS, schema=cls.SCHEMA, label="report_execution", require_signed=require_signed)
        f_locs = _require_json_list(m, "finding_locators", label="report_execution")
        c_locs = _require_json_list(m, "certification_record_locators", label="report_execution")
        ev_locs = _require_json_list(m, "operational_read_evidence_locators", label="report_execution")
        pf_locs = _require_json_list(m, "operational_read_effect_proof_locators", label="report_execution")
        pf_d = validate_sha256_prefixed(_strict_str(m["operational_read_effect_proof_set_digest"], field_name="report_execution.operational_read_effect_proof_set_digest"), field_name="report_execution.operational_read_effect_proof_set_digest")
        in_d = validate_sha256_prefixed(_strict_str(m["canonical_report_input_digest"], field_name="report_execution.canonical_report_input_digest"), field_name="report_execution.canonical_report_input_digest")
        res_d = validate_sha256_prefixed(_strict_str(m["canonical_report_result_digest"], field_name="report_execution.canonical_report_result_digest"), field_name="report_execution.canonical_report_result_digest")
        return cls(
            m["report_id"], _loc_from(m, "migration_run_context_locator", RUN_CONTEXT_TYPE),
            _loc_from(m, "dataset_snapshot_locator", DATASET_SNAPSHOT_TYPE),
            _loc_from(m, "analysis_replay_input_bundle_locator", REPLAY_BUNDLE_TYPE),
            _loc_from(m, "analysis_execution_locator", ANALYSIS_EXECUTION_TYPE),
            _loc_from(m, "analysis_policy_locator", AnalysisPolicy.SCHEMA),
            tuple(ArtifactLocator.from_dict(x, expected_type=FINDING_SCHEMA) for x in f_locs),
            tuple(ArtifactLocator.from_dict(x, expected_type=CERTIFICATION_RECORD_SCHEMA) for x in c_locs),
            tuple(ArtifactLocator.from_dict(x, expected_type=OperationalReadEvidence.SCHEMA) for x in ev_locs),
            tuple(ArtifactLocator.from_dict(x, expected_type=EffectProof.SCHEMA) for x in pf_locs),
            _loc_from(m, "report_template_provenance_locator", GitArtifactProvenance.SCHEMA),
            AlgorithmProvenanceIdentity.from_dict(m["render_algorithm_identity"]),
            CanonicalReportInput.from_dict(m["canonical_report_input"]),
            CanonicalReportResult.from_dict(m["canonical_report_result"]), m["executed_at_utc"],
            operational_read_effect_proof_set_digest=pf_d, canonical_report_input_digest=in_d,
            canonical_report_result_digest=res_d, integrity=integrity,
        )


def _reparse_seq(items: object, cls: type[_T], *, label: str, require_signed: bool) -> tuple[_T, ...]:
    if isinstance(items, (str, bytes)) or not isinstance(items, Sequence):
        raise ClosedValidationError(f"{label}: expected Sequence of {cls.__name__}")
    return tuple(_reparse_p1(item, cls, label=f"{label}[{i}]", require_signed=require_signed) for i, item in enumerate(items))


def _verify_snapshot_and_operational_lineage(
    report: ReportExecution, snapshot: DatasetSnapshot,
    generations: tuple[GenerationManifest, ...], evidences: tuple[OperationalReadEvidence, ...],
) -> None:
    gen_by_key: dict[bytes, GenerationManifest] = {}
    for gm in generations:
        key = canonicalize_jcs(gm.locator().to_dict())
        if key in gen_by_key:
            raise ClosedValidationError("generation_manifests: duplicate GenerationManifest")
        gen_by_key[key] = gm
    active_gens: list[GenerationManifest] = []
    active_keys: set[bytes] = set()
    for head in snapshot.partition_heads:
        hkey = canonicalize_jcs(head.generation_manifest_locator.to_dict())
        gm = gen_by_key.get(hkey)
        if gm is None or gm.partition_key != head.partition_key:
            raise ClosedValidationError("generation_manifests: missing or mismatched active partition head")
        active_gens.append(gm)
        active_keys.add(hkey)
    hist_keys = {canonicalize_jcs(loc.to_dict()) for loc in report.canonical_report_input.restatement_history_generation_locators}
    if set(gen_by_key) - (active_keys | hist_keys):
        raise ClosedValidationError("generation_manifests: unreferenced GenerationManifest supplied")
    if canonicalize_jcs(report.canonical_report_input.curation_execution_locator.to_dict()) not in {canonicalize_jcs(gm.curation_execution_locator.to_dict()) for gm in active_gens}:
        raise ClosedValidationError("report_execution: curation_execution_locator not in active snapshot generations")
    expected_ev_locs = _union_artifact_locators(
        (loc for gm in active_gens for loc in gm.operational_read_evidence_locators),
        expected_type=OperationalReadEvidence.SCHEMA, field_name="operational_read_evidence_locators",
    )
    if report.operational_read_evidence_locators != expected_ev_locs:
        raise ClosedValidationError("report_execution: operational_read_evidence_locators != active generation union")
    if sort_artifact_locators([ev.locator() for ev in evidences], expected_type=OperationalReadEvidence.SCHEMA, field_name="operational_evidences") != expected_ev_locs:
        raise ClosedValidationError("operational_evidences: resolved evidences differ from transitive union")
    if any(ev.migration_run_context_locator != report.migration_run_context_locator for ev in evidences):
        raise ClosedValidationError("operational_evidences: cross-run OperationalReadEvidence is forbidden")
    if report.operational_read_effect_proof_locators != sort_artifact_locators([ev.effect_proof_locator for ev in evidences], expected_type=EffectProof.SCHEMA, field_name="operational_read_effect_proof_locators"):
        raise ClosedValidationError("report_execution: operational_read_effect_proof_locators mismatch")


def _verify_provenance_and_bundle_bindings(
    report: ReportExecution, snapshot: DatasetSnapshot, bundle: AnalysisReplayInputBundle,
    execution: AnalysisExecution, schemas: tuple[AnalysisResultSchema, ...],
    policy_obj: AnalysisPolicy, tmpl_prov: GitArtifactProvenance, rnd_prov: GitArtifactProvenance,
) -> None:
    snap_loc, bundle_loc, pol_loc = snapshot.locator(), bundle.locator(), policy_obj.locator()
    if (
        report.dataset_snapshot_locator != snap_loc
        or bundle.dataset_snapshot_locator != snap_loc
        or bundle.migration_run_context_locator != report.migration_run_context_locator
        or report.analysis_replay_input_bundle_locator != bundle_loc
        or execution.analysis_replay_input_bundle_locator != bundle_loc
        or report.analysis_execution_locator != execution.locator()
        or report.analysis_policy_locator != pol_loc
        or bundle.analysis_policy_locator != pol_loc
    ):
        raise ClosedValidationError("report_execution: run/snapshot/bundle/execution/policy locator mismatch")
    tmpl_loc = ArtifactLocator.for_canonical_bytes(GitArtifactProvenance.SCHEMA, canonicalize_jcs(tmpl_prov.to_dict()))
    rnd_loc = ArtifactLocator.for_canonical_bytes(GitArtifactProvenance.SCHEMA, canonicalize_jcs(rnd_prov.to_dict()))
    alg = report.render_algorithm_identity
    if (
        report.report_template_provenance_locator != tmpl_loc
        or alg.git_artifact_provenance_locator != rnd_loc
        or (alg.repository, alg.commit_sha, alg.path, alg.git_blob_oid, alg.file_content_sha256)
        != (rnd_prov.repository, rnd_prov.commit_sha, rnd_prov.path, rnd_prov.git_blob_oid, rnd_prov.file_content_sha256)
    ):
        raise ClosedValidationError("report_execution: template or render Git provenance mismatch")
    schema_by_key = {canonicalize_jcs(s.locator().to_dict()): s for s in schemas}
    for q in bundle.queries:
        resolved_s = schema_by_key.get(canonicalize_jcs(q.analysis_result_schema_locator.to_dict()))
        if resolved_s is None:
            raise ClosedValidationError(f"replay_bundle: missing AnalysisResultSchema for {q.result_key!r}")
        q.verify_against_schema(resolved_s)
    if {q.result_key for q in bundle.queries} != {e.result_key for e in execution.canonical_result_set.results}:
        raise ClosedValidationError("replay_bundle: query result_key set differs from AnalysisExecution")


def _verify_certified_findings_and_render(
    fresh_rep: ReportExecution, fresh_snap: DatasetSnapshot, fresh_exec: AnalysisExecution,
    fresh_pol: AnalysisPolicy, fresh_res: tuple[AnalysisResult, ...],
    fresh_schemas: tuple[AnalysisResultSchema, ...], fresh_findings: tuple[Finding, ...],
    fresh_certs: tuple[AnalyticalCertificationRecord, ...], evaluation_context: EvaluationContext,
    checked_attested: tuple[AttestedCertificationInput, ...], *, require_signed: bool,
) -> None:
    evidence = AnalysisEvidence(
        fresh_exec, fresh_res, fresh_schemas, fresh_snap.locator(),
        fresh_pol.locator(), require_signed, fresh_rep.migration_run_context_locator,
    )
    if sort_artifact_locators([c.locator() for c in fresh_certs], expected_type=CERTIFICATION_RECORD_SCHEMA, field_name="certifications") != fresh_rep.certification_record_locators:
        raise ClosedValidationError("report_execution: certification_record_locators mismatch")
    for cert in fresh_certs:
        verify_certification_record(cert, evaluation_context, evidence, list(fresh_findings), list(checked_attested))
    if sort_artifact_locators([f.locator() for f in fresh_findings], expected_type=FINDING_SCHEMA, allow_empty=True, field_name="findings") != fresh_rep.finding_locators:
        raise ClosedValidationError("report_execution: finding_locators mismatch")
    inv_loc = ArtifactLocator.for_canonical_bytes(ExpectedResourceInventory.SCHEMA, canonicalize_jcs(evaluation_context.inventory.to_dict()))
    exp_in = CanonicalReportInput(
        fresh_snap.snapshot_digest, fresh_exec.canonical_result_set.canonical_result_digest,
        evaluation_context.evaluation_instant_utc, evaluation_context.window_end_date,
        evaluation_context.metrics_result_key, inv_loc, fresh_rep.canonical_report_input.curation_execution_locator,
        fresh_rep.canonical_report_input.restatement_history_generation_locators, checked_attested,
        tuple(sorted((f.finding_digest for f in fresh_findings), key=lambda s: s.encode("utf-8"))),
        fresh_certs[0].derived_certification_status, fresh_certs[0].mutation_recommendations_blocked,
    )
    exp_res = render_canonical_report_result(exp_in, fresh_findings)
    if canonicalize_jcs(fresh_rep.canonical_report_input.to_dict()) != canonicalize_jcs(exp_in.to_dict()) or canonicalize_jcs(fresh_rep.canonical_report_result.to_dict()) != canonicalize_jcs(exp_res.to_dict()):
        raise ClosedValidationError("report_execution: canonical_report_input or canonical_report_result mismatch")


def verify_report_execution(
    report: ReportExecution, *, snapshot: DatasetSnapshot,
    generation_manifests: Sequence[GenerationManifest], operational_evidences: Sequence[OperationalReadEvidence],
    replay_bundle: AnalysisReplayInputBundle, execution: AnalysisExecution,
    results: Sequence[AnalysisResult], result_schemas: Sequence[AnalysisResultSchema],
    policy_obj: AnalysisPolicy, findings: Sequence[Finding],
    certifications: Sequence[AnalyticalCertificationRecord], evaluation_context: EvaluationContext,
    attested_inputs: Sequence[AttestedCertificationInput], template_provenance: GitArtifactProvenance,
    render_provenance: GitArtifactProvenance, require_signed: bool = False,
) -> ReportExecution:
    """Verify full snapshot -> operational proofs -> replay -> findings -> certification -> report chain."""
    if type(require_signed) is not bool:
        raise ClosedValidationError("require_signed: expected bool")
    fresh_rep = _reparse_p1(report, ReportExecution, label="report", require_signed=require_signed)
    if report != fresh_rep or type(evaluation_context) is not EvaluationContext:
        raise ClosedValidationError("report_execution: malformed report or EvaluationContext")
    fresh_snap = _reparse_p1(snapshot, DatasetSnapshot, label="snapshot", require_signed=require_signed)
    fresh_bundle = _reparse_p1(replay_bundle, AnalysisReplayInputBundle, label="replay_bundle", require_signed=require_signed)
    fresh_exec = _reparse_p1(execution, AnalysisExecution, label="execution", require_signed=require_signed)
    fresh_pol = _reparse_p1(policy_obj, AnalysisPolicy, label="policy_obj", require_signed=require_signed)
    fresh_tmpl = _reparse_p1(template_provenance, GitArtifactProvenance, label="template_provenance", require_signed=require_signed)
    fresh_rnd = _reparse_p1(render_provenance, GitArtifactProvenance, label="render_provenance", require_signed=require_signed)
    fresh_gens = _reparse_seq(generation_manifests, GenerationManifest, label="generation_manifests", require_signed=require_signed)
    fresh_evs = _reparse_seq(operational_evidences, OperationalReadEvidence, label="operational_evidences", require_signed=require_signed)
    fresh_res = _reparse_seq(results, AnalysisResult, label="results", require_signed=require_signed)
    fresh_schemas = _reparse_seq(result_schemas, AnalysisResultSchema, label="result_schemas", require_signed=require_signed)
    fresh_findings = _reparse_seq(findings, Finding, label="findings", require_signed=require_signed)
    fresh_certs = _reparse_seq(certifications, AnalyticalCertificationRecord, label="certifications", require_signed=require_signed)
    checked_attested = _validate_attested_inputs(attested_inputs, field_name="attested_inputs")
    _verify_provenance_and_bundle_bindings(fresh_rep, fresh_snap, fresh_bundle, fresh_exec, fresh_schemas, fresh_pol, fresh_tmpl, fresh_rnd)
    _verify_snapshot_and_operational_lineage(fresh_rep, fresh_snap, fresh_gens, fresh_evs)
    verify_analysis_execution(fresh_exec, list(fresh_res), list(fresh_schemas), fresh_snap.locator(), require_signed=require_signed, bundle_migration_run_context_locator=fresh_rep.migration_run_context_locator)
    _verify_certified_findings_and_render(
        fresh_rep, fresh_snap, fresh_exec, fresh_pol, fresh_res, fresh_schemas,
        fresh_findings, fresh_certs, evaluation_context, checked_attested, require_signed=require_signed,
    )
    return report


__all__ = [
    "CanonicalReportInput", "CanonicalReportResult", "REPORT_EXECUTION_SCHEMA", "ReportExecution",
    "ReportFindingSummary", "render_canonical_report_result", "verify_report_execution",
]
