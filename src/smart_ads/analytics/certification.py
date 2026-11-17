"""Analytical `certification_record/v1` over recomputed findings (ADR-0001 sections 5.6, 6.4, 7).

Distinct from `certification_7a_record/v1` and `certification_7b_record/v1` (ADR section 5.1).
This module imports from `smart_ads.analytics.intelligence`; never the reverse.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, ClassVar, Final

from smart_ads.analytics.formulas import (
    CertificationInput, DerivedCertificationStatus, combine_derived_certification,
)
from smart_ads.analytics.intelligence import (
    FINDING_SCHEMA, AnalysisEvidence, EvaluationContext, Finding, _check_integrity, _digest_member,
    _evaluate, _fail, _integrity_type, _is_signed, _list_member, _locator_array, _member,
    _P1Artifact, _parse_locator, _require, _sorted_unique_locators, _split_envelope, _strict,
    _typed_tuple, _with_integrity,
)
from smart_ads.analytics.policy import _recheck, _reparsed
from smart_ads.contracts.jcs import ADR_P1_DOMAIN_PREFIXES, ArtifactLocator, P1Integrity, canonicalize_jcs

CERTIFICATION_RECORD_SCHEMA: Final[str] = "smart_ads/certification_record/v1"
_STATUS_NAMES: Final[tuple[str, ...]] = tuple(status.value for status in DerivedCertificationStatus)


@dataclass(frozen=True, slots=True)
class AttestedCertificationInput:
    """One input's certification status plus whether it was independently validated.

    `independently_validated` is a caller-asserted flag: the wheel cannot verify an independent
    validation, it only refuses DEGRADED unless some DEGRADED derived input carries the flag.
    """

    certification_input: CertificationInput
    independently_validated: bool

    def __post_init__(self) -> None:
        _require(self.certification_input, CertificationInput, "attested_input.certification_input")
        _strict(self.independently_validated, bool, "attested_input.independently_validated")


_CertificationInputs = tuple[AttestedCertificationInput, ...] | list[AttestedCertificationInput]


def _derive_certification_status(inputs: _CertificationInputs) -> DerivedCertificationStatus:
    """Minimum input status (T2 combiner) with the ADR section 5.6 DEGRADED preconditions.

    DEGRADED needs an independently validated `derived_input` that is already DEGRADED; the
    combiner cannot express that, so it is checked here. The other precondition, successful
    recomputation, holds only on the public path: `build_certification_record` re-verifies the
    execution and re-evaluates the findings before calling this. Keep it private.
    """
    items = _typed_tuple(inputs, AttestedCertificationInput, "certification_inputs")
    status = combine_derived_certification(tuple(item.certification_input for item in items))
    degraded = DerivedCertificationStatus.DEGRADED
    if status is degraded and not any(
        item.independently_validated
        and item.certification_input.status is degraded
        and item.certification_input.origin == "derived_input"
        for item in items
    ):
        raise _fail("degraded_not_permitted", "no independently validated DEGRADED derived input")
    return status


@dataclass(frozen=True, slots=True)
class AnalyticalCertificationRecord(_P1Artifact):
    """Closed P1 `smart_ads/certification_record/v1`.

    `output_digest` equals the certified execution's `canonical_result_digest`, so a record
    with no findings is still bound to its analysis; the ADR names the member without fixing its
    preimage, so this is a choice (open decision).
    """

    SCHEMA: ClassVar[str] = CERTIFICATION_RECORD_SCHEMA
    P1_DOMAIN_PREFIX: ClassVar[str] = ADR_P1_DOMAIN_PREFIXES[CERTIFICATION_RECORD_SCHEMA]
    CORE_KEYS: ClassVar[frozenset[str]] = frozenset(
        "$schema finding_locators derived_certification_status mutation_recommendations_blocked "
        "output_digest".split()
    )
    KEYS: ClassVar[frozenset[str]] = CORE_KEYS | {"integrity"}

    finding_locators: tuple[ArtifactLocator, ...]
    derived_certification_status: DerivedCertificationStatus
    mutation_recommendations_blocked: bool
    output_digest: str
    integrity: P1Integrity | None = None

    def __post_init__(self) -> None:
        label = "certification_record"
        _integrity_type(self.integrity, label)
        locators = _locator_array(self.finding_locators, FINDING_SCHEMA, f"{label}.finding_locators")
        object.__setattr__(self, "finding_locators", locators)
        _require(self.derived_certification_status, DerivedCertificationStatus, f"{label}.status")
        blocked = _strict(self.mutation_recommendations_blocked, bool, f"{label}.blocked")
        if blocked and not locators:
            raise _fail("mutation_blocked_mismatch", f"{label}: an empty finding set blocks nothing")
        _digest_member(self.output_digest, f"{label}.output_digest")
        _check_integrity(self.integrity, self.to_dict(), label)

    def to_dict(self) -> dict[str, Any]:
        core = {
            "$schema": self.SCHEMA,
            "finding_locators": [locator.to_dict() for locator in self.finding_locators],
            "derived_certification_status": self.derived_certification_status.value,
            "mutation_recommendations_blocked": self.mutation_recommendations_blocked,
            "output_digest": self.output_digest,
        }
        return _with_integrity(core, self.integrity)

    @classmethod
    def from_dict(cls, data: object, *, require_signed: bool = False) -> AnalyticalCertificationRecord:
        label = "certification_record"
        m, integrity = _split_envelope(data, cls.CORE_KEYS, cls.SCHEMA, label, require_signed)
        status = _member(m["derived_certification_status"], _STATUS_NAMES, f"{label}.status")
        locators = _list_member(m, "finding_locators", label)
        return cls(
            finding_locators=tuple(_parse_locator(item, FINDING_SCHEMA) for item in locators),
            derived_certification_status=DerivedCertificationStatus(status),
            mutation_recommendations_blocked=m["mutation_recommendations_blocked"],
            output_digest=m["output_digest"],
            integrity=integrity,
        )


def _without_integrity(envelope: dict[str, Any]) -> bytes:
    return canonicalize_jcs({key: value for key, value in envelope.items() if key != "integrity"})


def _fresh_inputs(inputs: _CertificationInputs) -> tuple[AttestedCertificationInput, ...]:
    """Each attested input, and its CertificationInput, re-constructed so rebound fields are checked."""
    def fresh(item: AttestedCertificationInput) -> AttestedCertificationInput:
        status = replace(item.certification_input)  # CertificationInput raises FormulaGraphError
        return AttestedCertificationInput(status, item.independently_validated)

    items = _typed_tuple(inputs, AttestedCertificationInput, "certification_inputs")
    return tuple(_recheck(_fail, "invalid_type", fresh, item) for item in items)


def build_certification_record(
    context: EvaluationContext,
    evidence: AnalysisEvidence,
    findings: tuple[Finding, ...] | list[Finding],
    certification_inputs: _CertificationInputs,
    *,
    integrity: P1Integrity | None = None,
) -> AnalyticalCertificationRecord:
    """Re-verify and re-evaluate, require `findings` to be exactly that result, and certify them.

    `findings` may carry integrity blocks (finalized when `evidence.require_signed`); everything
    but integrity must equal the recomputation byte for byte, in `finding_key` order. The record
    binds the supplied envelopes' locators and, as `output_digest`, the verified execution's
    `canonical_result_digest`. Every argument is checked again first (see `_fresh_context`):
    supplied findings are re-parsed from their wire form, attested inputs re-constructed.
    """
    execution, expected = _evaluate(context, evidence)
    supplied = tuple(
        _reparsed(_fail, "invalid_type", Finding, finding)
        for finding in _typed_tuple(findings, Finding, "findings")
    )
    if evidence.require_signed and not all(_is_signed(finding.integrity) for finding in supplied):
        raise _fail("unsigned_artifact", "findings must carry finalized P1 signatures")
    if [_without_integrity(f.to_dict()) for f in supplied] != [
        _without_integrity(f.to_dict()) for f in expected
    ]:
        raise _fail("findings_mismatch", "supplied findings differ from the recomputed findings")
    return AnalyticalCertificationRecord(
        finding_locators=_sorted_unique_locators(finding.locator() for finding in supplied),
        derived_certification_status=_derive_certification_status(_fresh_inputs(certification_inputs)),
        mutation_recommendations_blocked=any(f.mutation_recommendation_blocked for f in supplied),
        output_digest=execution.canonical_result_set.canonical_result_digest,
        integrity=integrity,
    )


def verify_certification_record(
    record: AnalyticalCertificationRecord,
    context: EvaluationContext,
    evidence: AnalysisEvidence,
    findings: tuple[Finding, ...] | list[Finding],
    certification_inputs: _CertificationInputs,
) -> AnalyticalCertificationRecord:
    """Recompute the record `build_certification_record` produces and require byte equality.

    Everything but `integrity` must match: finding locators, derived status, the blocking flag
    (a record that certifies a blocking finding with `mutation_recommendations_blocked: false`
    is rejected) and `output_digest`. The record's own signed digest was already checked when it
    was constructed. With `evidence.require_signed` the record must be signed too. The record is
    compared as its wire form re-parses; the object returned is the one supplied.
    """
    _require(record, AnalyticalCertificationRecord, "record")
    _require(evidence, AnalysisEvidence, "evidence")
    fresh = _reparsed(_fail, "invalid_type", AnalyticalCertificationRecord, record)
    if _strict(evidence.require_signed, bool, "evidence.require_signed") and not _is_signed(fresh.integrity):
        raise _fail("unsigned_artifact", "certification_record must carry a finalized P1 signature")
    expected = build_certification_record(context, evidence, findings, certification_inputs)
    if _without_integrity(fresh.to_dict()) != _without_integrity(expected.to_dict()):
        raise _fail("record_mismatch", "certification_record differs from the recomputed record")
    return record


__all__ = [
    "CERTIFICATION_RECORD_SCHEMA", "AnalyticalCertificationRecord", "AttestedCertificationInput",
    "build_certification_record", "verify_certification_record",
]
