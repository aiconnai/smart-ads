"""``certification_7b_record/v1``: the complete P1 record of a verified 7B (ADR-0001 5.4).

Only ``bundle_outcome: verified`` with ``result_status: complete`` on both sides
is representable; a failed 7B never yields a record. The constructor
recomputes every member that is intrinsic to the record; bindings to resolved
evidence are checked by ``verify_certification_7b_record``.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, ClassVar, Final

from smart_ads.contracts.jcs import ArtifactLocator, P1Integrity
from smart_ads.contracts.schemas import CanonicalQueryContract, ReconciliationRowKey
from smart_ads.contracts.scalars import require_mapping
from smart_ads.reconciliation.bundle_common import (
    CERTIFICATION_7B_RECORD_SCHEMA,
    GATE3_SELECTION_SCHEMA,
    REQUIRED_7B_METRICS,
    RUN_CONTEXT_SCHEMA,
    Bundle7BDefectError,
    check_integrity,
    closed,
    guard,
    member_locator,
    parse_integrity,
    parse_member_locator,
    parse_query,
    query_bytes,
    require_bool,
    require_member,
    sha256_member,
    within_skew,
)
from smart_ads.reconciliation.bundle_evidence import (
    FactReconciliation,
    logical_digest,
    require_reconciliations,
)
from smart_ads.reconciliation.bundle_executions import (
    CANDIDATE_PROVIDER_TARGET_REF,
    REFERENCE_PROVIDER_TARGET_REF,
    CandidateExecution,
    ReferenceExecution,
    RowPairing,
    require_same_fingerprint,
)
from smart_ads.reconciliation.bundle_universe import (
    build_expected_pairs,
    build_row_universe,
    digest_row_universe,
)

_BUNDLE_OUTCOME_VERIFIED: Final[str] = "verified"


@dataclass(frozen=True, slots=True)
class Certification7BRecord:
    """Complete ``certification_7b_record/v1``; only a verified, complete 7B is representable."""

    SCHEMA: ClassVar[str] = CERTIFICATION_7B_RECORD_SCHEMA
    CORE_KEYS: ClassVar[tuple[str, ...]] = (
        "$schema",
        "migration_run_context_locator",
        "gate3_selection_locator",
        "canonical_query_contract",
        "canonical_query_digest",
        "required_metrics",
        "candidate_execution",
        "reference_execution",
        "row_pairing",
        "fact_reconciliations",
        "logical_fact_reconciliation_digest",
        "bundle_outcome",
    )

    migration_run_context_locator: ArtifactLocator
    gate3_selection_locator: ArtifactLocator
    canonical_query_contract: CanonicalQueryContract
    canonical_query_digest: str
    required_metrics: tuple[str, ...]
    candidate_execution: CandidateExecution
    reference_execution: ReferenceExecution
    row_pairing: RowPairing
    fact_reconciliations: tuple[FactReconciliation, ...]
    logical_fact_reconciliation_digest: str
    bundle_outcome: str = _BUNDLE_OUTCOME_VERIFIED
    integrity: P1Integrity | None = None

    def __post_init__(self) -> None:
        self._check_types()
        self._check_query()
        self._check_effect_chain()
        self._check_fingerprints()
        cand, ref = self.candidate_execution, self.reference_execution
        if not within_skew(cand.retrieved_at_utc, ref.retrieved_at_utc):
            raise Bundle7BDefectError(
                "retrieval_skew_exceeded", "certification_7b_record: retrieval skew > 300 s"
            )
        self._check_reconciliations()
        self._check_counts()
        check_integrity(self.integrity, self.to_dict, label="certification_7b_record")

    def _check_types(self) -> None:
        label = "certification_7b_record"
        member_locator(self, "migration_run_context_locator", RUN_CONTEXT_SCHEMA, label=label)
        member_locator(self, "gate3_selection_locator", GATE3_SELECTION_SCHEMA, label=label)
        for name, expected in (
            ("canonical_query_contract", CanonicalQueryContract),
            ("candidate_execution", CandidateExecution),
            ("reference_execution", ReferenceExecution),
            ("row_pairing", RowPairing),
        ):
            require_member(getattr(self, name), expected, label=f"{label}.{name}")
        # Frozen and hashable: sequence members are tuples, never lists.
        require_member(self.required_metrics, tuple, label=f"{label}.required_metrics")
        _require_required_metrics(self.required_metrics, label=label)
        if self.bundle_outcome != _BUNDLE_OUTCOME_VERIFIED:
            raise Bundle7BDefectError(
                "fixed_member_mismatch", f"{label}.bundle_outcome: only 'verified' is recordable"
            )
        for name in ("canonical_query_digest", "logical_fact_reconciliation_digest"):
            sha256_member(getattr(self, name), label=f"{label}.{name}")

    def _check_query(self) -> None:
        label = "certification_7b_record"
        query = self.canonical_query_contract
        if query.canonical_query_digest != self.canonical_query_digest:
            raise Bundle7BDefectError(
                "canonical_query_digest_mismatch", f"{label}.canonical_query_digest differs"
            )
        if set(query.metric_semantic_refs) != set(REQUIRED_7B_METRICS):
            raise Bundle7BDefectError(
                "canonical_query_mismatch", f"{label}: query must request the sealed metrics"
            )
        for side in (self.candidate_execution, self.reference_execution):
            if query_bytes(side.canonical_query_projection) != query_bytes(query):
                raise Bundle7BDefectError(
                    "canonical_query_mismatch", f"{label}: side projection differs from query"
                )

    def _check_effect_chain(self) -> None:
        cand, ref = self.candidate_execution, self.reference_execution
        if cand.effect_proof_locator == ref.effect_proof_locator:
            raise Bundle7BDefectError(
                "effect_proof_not_distinct", "one effect proof cannot satisfy both sides"
            )
        if cand.provider_target_ref == ref.provider_target_ref:
            raise Bundle7BDefectError(
                "provider_target_not_distinct", "both sides name one provider target"
            )
        if (cand.provider_target_ref, ref.provider_target_ref) != (
            CANDIDATE_PROVIDER_TARGET_REF,
            REFERENCE_PROVIDER_TARGET_REF,
        ):
            raise Bundle7BDefectError(
                "fixed_member_mismatch", "provider_target_ref: ADR literals required"
            )

    def _check_fingerprints(self) -> None:
        cand = self.candidate_execution.gate3_certification_fingerprint
        ref = self.reference_execution.gate3_certification_fingerprint
        require_same_fingerprint(cand, ref, label="execution fingerprints")
        if cand.canonical_query_digest != self.canonical_query_digest:
            raise Bundle7BDefectError(
                "fingerprint_member_mismatch", "fingerprint canonical_query_digest differs"
            )
        if cand.authorized_certification_scope != self.canonical_query_contract.resource_scope_ref:
            raise Bundle7BDefectError(
                "fingerprint_member_mismatch",
                "fingerprint authorized_certification_scope differs",
            )

    def _check_reconciliations(self) -> None:
        label = "certification_7b_record.fact_reconciliations"
        items = self.fact_reconciliations
        if not isinstance(items, tuple) or not items:
            raise Bundle7BDefectError("malformed_member", f"{label}: non-empty array required")
        require_reconciliations(items, label=label)
        if any(item.metric_verification_status != "VERIFIED" for item in items):
            raise Bundle7BDefectError(
                "metric_not_verified", f"{label}: every member must be VERIFIED"
            )
        pairs = tuple(item.pair_key() for item in items)
        if pairs != build_expected_pairs(self.row_universe):
            raise Bundle7BDefectError(
                "pair_universe_incomplete", f"{label}: not U7 x required_metrics"
            )
        digest = logical_digest(items)
        if digest != self.logical_fact_reconciliation_digest:
            raise Bundle7BDefectError(
                "logical_digest_mismatch", "logical_fact_reconciliation_digest differs"
            )

    def _check_counts(self) -> None:
        expected_digest = digest_row_universe(self.row_universe)
        for name in ("candidate_execution", "reference_execution"):
            side = getattr(self, name)
            if side.row_count != len(self.fact_reconciliations):
                raise Bundle7BDefectError(
                    "row_count_mismatch", f"{name}.row_count: must equal length(U7M)"
                )
            if side.row_universe_digest != expected_digest:
                raise Bundle7BDefectError(
                    "row_universe_digest_mismatch", f"{name}.row_universe_digest differs"
                )

    @property
    def row_universe(self) -> tuple[ReconciliationRowKey, ...]:
        """The common ``U7`` carried by the reconciliations."""
        return build_row_universe(item.canonical_fact_key for item in self.fact_reconciliations)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "$schema": self.SCHEMA,
            "migration_run_context_locator": self.migration_run_context_locator.to_dict(),
            "gate3_selection_locator": self.gate3_selection_locator.to_dict(),
            "canonical_query_contract": self.canonical_query_contract.to_dict(),
            "canonical_query_digest": self.canonical_query_digest,
            "required_metrics": list(self.required_metrics),
            "candidate_execution": self.candidate_execution.to_dict(),
            "reference_execution": self.reference_execution.to_dict(),
            "row_pairing": self.row_pairing.to_dict(),
            "fact_reconciliations": [item.to_dict() for item in self.fact_reconciliations],
            "logical_fact_reconciliation_digest": self.logical_fact_reconciliation_digest,
            "bundle_outcome": self.bundle_outcome,
        }
        if self.integrity is not None:
            out["integrity"] = self.integrity.to_dict()
        return out

    @classmethod
    def from_dict(cls, data: object, *, require_signed: bool = False) -> Certification7BRecord:
        require_bool(require_signed, label="require_signed")
        label = "certification_7b_record"
        mapping = guard("malformed_member", label, lambda: require_mapping(data, label=label))
        has_integrity = require_signed or "integrity" in mapping
        keys = frozenset(cls.CORE_KEYS) | ({"integrity"} if has_integrity else set())
        mapping = closed(mapping, keys, label=label)
        if mapping["$schema"] != cls.SCHEMA:
            raise Bundle7BDefectError(
                "fixed_member_mismatch", f"{label}.$schema: expected {cls.SCHEMA!r}"
            )
        integrity = parse_integrity(mapping, label=label, require_signed=require_signed)
        return cls(
            **_parse_record_members(mapping, label=label, require_signed=require_signed),
            integrity=integrity,
        )


def _require_required_metrics(value: object, *, label: str) -> None:
    """Exactly ``[impressions, clicks, spend]``: the ADR's YAML order, a choice it does not
    fix beyond the literal (not UTF-8 sorted)."""
    if not isinstance(value, (list, tuple)) or tuple(value) != REQUIRED_7B_METRICS:
        raise Bundle7BDefectError(
            "fixed_member_mismatch",
            f"{label}.required_metrics: must be {list(REQUIRED_7B_METRICS)}",
        )


def _parse_record_members(
    mapping: Mapping[str, Any], *, label: str, require_signed: bool = False
) -> dict[str, Any]:
    metrics = mapping["required_metrics"]
    _require_required_metrics(metrics if isinstance(metrics, list) else None, label=label)
    reconciliations = mapping["fact_reconciliations"]
    if not isinstance(reconciliations, list) or not reconciliations:
        raise Bundle7BDefectError(
            "malformed_member", f"{label}.fact_reconciliations: non-empty array required"
        )
    return {
        "migration_run_context_locator": parse_member_locator(
            mapping, "migration_run_context_locator", RUN_CONTEXT_SCHEMA, label=label
        ),
        "gate3_selection_locator": parse_member_locator(
            mapping, "gate3_selection_locator", GATE3_SELECTION_SCHEMA, label=label
        ),
        "canonical_query_contract": parse_query(
            mapping["canonical_query_contract"], label=f"{label}.canonical_query_contract"
        ),
        "canonical_query_digest": mapping["canonical_query_digest"],
        "required_metrics": tuple(metrics),
        "candidate_execution": CandidateExecution.from_dict(
            mapping["candidate_execution"], require_signed=require_signed
        ),
        "reference_execution": ReferenceExecution.from_dict(
            mapping["reference_execution"], require_signed=require_signed
        ),
        "row_pairing": RowPairing.from_dict(mapping["row_pairing"]),
        "fact_reconciliations": tuple(
            FactReconciliation.from_dict(item) for item in reconciliations
        ),
        "logical_fact_reconciliation_digest": mapping["logical_fact_reconciliation_digest"],
        "bundle_outcome": mapping["bundle_outcome"],
    }
