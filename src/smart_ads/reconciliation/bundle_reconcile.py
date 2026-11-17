"""Tolerance profile resolution and ``reconcile_7b_fact_sets`` (ADR-0001 section 5.4)."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Final

from smart_ads.contracts.jcs import ArtifactLocator
from smart_ads.contracts.schemas import (
    CanonicalQueryContract,
    CollectionResult,
    NormalizedCollectionFact,
)
from smart_ads.reconciliation.bundle_common import (
    GATE3_SELECTION_SCHEMA,
    REQUIRED_7B_METRICS,
    RUN_CONTEXT_SCHEMA,
    Bundle7BDefectError,
    artifact_locator_for,
    checked_argument_locator,
    guard,
    reparsed,
    require_count,
    require_tuple_of,
    require_type,
    scope_ref,
    sha256_member,
    within_skew,
)
from smart_ads.reconciliation.bundle_evidence import (
    FactReconciliation,
    ReconciliationSide,
    ResultIndex,
    addressed_fact,
    checked_result,
    complete_facts,
    logical_digest,
    require_reconciliations,
    select_indexed_evidence,
)
from smart_ads.reconciliation.bundle_universe import (
    MetricPairKey,
    SideUniverse,
    digest_fact_key,
    require_facts_in_query,
)
from smart_ads.reconciliation.tolerance import ToleranceProfile, compare_sides

RECONCILE_OUTCOME_CODES: Final[tuple[str, ...]] = (
    "metric_blocked",
    "metric_unavailable",
    "metric_unreconciled",
    "pair_universe_incomplete",
    "pair_universe_mismatch",
    "retrieval_skew_exceeded",
    "row_universe_mismatch",
)
_BUNDLE_OUTCOMES: Final[frozenset[str]] = frozenset({"verified", "failed"})
_STATUS_OUTCOME_CODES: Final[Mapping[str, str]] = MappingProxyType(
    {
        "UNRECONCILED": "metric_unreconciled",
        "UNAVAILABLE": "metric_unavailable",
        "BLOCKED": "metric_blocked",
    }
)

ResolvedProfiles = dict[str, tuple[ToleranceProfile, ArtifactLocator]]


def binding_members(
    *,
    gate3_selection_locator: object,
    canonical_query_digest: object,
    authorized_certification_scope: object,
    migration_run_context_locator: object,
) -> dict[str, Any]:
    """Validate the four binding members (the same-named members of the 7B record).

    The two locators are re-parsed from their wire forms; the returned copies are
    what callers bind to (a tampered locator is ``malformed_member``).
    """
    locators = {
        name: checked_argument_locator(value, artifact_type, label=name)
        for name, value, artifact_type in (
            ("gate3_selection_locator", gate3_selection_locator, GATE3_SELECTION_SCHEMA),
            ("migration_run_context_locator", migration_run_context_locator, RUN_CONTEXT_SCHEMA),
        )
    }
    try:
        sha256_member(canonical_query_digest, label="canonical_query_digest")
        scope_ref(authorized_certification_scope, label="authorized_certification_scope")
    except Bundle7BDefectError as exc:
        raise Bundle7BDefectError("malformed_argument", str(exc)) from exc
    return {
        "gate3_selection_locator": locators["gate3_selection_locator"],
        "canonical_query_digest": canonical_query_digest,
        "authorized_certification_scope": authorized_certification_scope,
        "migration_run_context_locator": locators["migration_run_context_locator"],
    }


def _resolve_profile(
    metric: str, raw: object, binding: Mapping[str, Any]
) -> tuple[ToleranceProfile, ArtifactLocator]:
    label = f"tolerance_profiles[{metric}]"
    parsed = guard("tolerance_profile_malformed", label, lambda: ToleranceProfile.from_dict(raw))
    if parsed.integrity is None or not parsed.integrity.is_signed:
        raise Bundle7BDefectError(
            "tolerance_profile_unsigned", f"{label}: protected profile must be signed"
        )
    profile = guard(
        "tolerance_profile_malformed",
        label,
        lambda: ToleranceProfile.from_dict(raw, require_signed=True),
    )
    if profile.canonical_metric_ref != metric:
        raise Bundle7BDefectError(
            "tolerance_profile_metric_mismatch", f"{label}: profile closes another metric"
        )
    guard("tolerance_profile_unbound", label, lambda: profile.require_bound_to(**binding))
    return profile, artifact_locator_for(ToleranceProfile.SCHEMA, profile)


def resolve_profiles(tolerance_profiles: object, binding: Mapping[str, Any]) -> ResolvedProfiles:
    """One resolved, signed and bound profile per required metric, keyed by metric ref."""
    if not isinstance(tolerance_profiles, Mapping):
        raise Bundle7BDefectError("malformed_argument", "tolerance_profiles: expected a mapping")
    if set(tolerance_profiles) != set(REQUIRED_7B_METRICS):
        raise Bundle7BDefectError(
            "tolerance_profile_unresolved", "tolerance_profiles: exactly one per required metric"
        )
    return {
        metric: _resolve_profile(metric, tolerance_profiles[metric], binding)
        for metric in REQUIRED_7B_METRICS
    }


def side_facts(result: object, call_side: str) -> tuple[NormalizedCollectionFact, ...]:
    """The complete fact set of a result produced by ``call_side`` (``result`` is trusted)."""
    label = f"{call_side}_result"
    require_type(result, CollectionResult, label=label)
    if result.call_side != call_side:
        raise Bundle7BDefectError(
            "collection_result_mismatch", f"{label}: call_side must be {call_side!r}"
        )
    return complete_facts(result)


def checked_side(
    result: object, call_side: str
) -> tuple[CollectionResult, tuple[NormalizedCollectionFact, ...]]:
    """``result`` re-parsed from its wire form, with its complete fact set; use the copy."""
    fresh = checked_result(result, label=f"{call_side}_result")
    return fresh, side_facts(fresh, call_side)


def _universe_codes(cand: SideUniverse, ref: SideUniverse) -> set[str]:
    codes: set[str] = set()
    if not (cand.is_complete and ref.is_complete):
        codes.add("pair_universe_incomplete")
    if cand.rows != ref.rows:
        codes.add("row_universe_mismatch")
    if cand.pairs != ref.pairs:
        codes.add("pair_universe_mismatch")
    return codes


def _set_codes(
    cand: SideUniverse,
    ref: SideUniverse,
    cand_result: CollectionResult,
    ref_result: CollectionResult,
) -> set[str]:
    """Universe defects and retrieval skew between the two sides."""
    codes = _universe_codes(cand, ref)
    if not within_skew(
        cand_result.retrieval_context.retrieved_at_utc,
        ref_result.retrieval_context.retrieved_at_utc,
    ):
        codes.add("retrieval_skew_exceeded")
    return codes


def _evidence_side(index: ResultIndex, pair: MetricPairKey) -> ReconciliationSide:
    selector = select_indexed_evidence(index, pair)
    return ReconciliationSide.for_fact(addressed_fact(index, pair), selector)


def _reconcile_pair(
    pair: MetricPairKey,
    candidate_result: ResultIndex,
    reference_result: ResultIndex,
    resolved: tuple[ToleranceProfile, ArtifactLocator],
) -> FactReconciliation:
    profile, profile_locator = resolved
    candidate = _evidence_side(candidate_result, pair)
    reference = _evidence_side(reference_result, pair)
    comparison = compare_sides(
        candidate.comparison_side(),
        reference.comparison_side(),
        profile,
        canonical_metric_ref=pair.canonical_metric_ref,
    )
    return FactReconciliation(
        canonical_fact_key=pair.canonical_fact_key,
        canonical_fact_key_digest=digest_fact_key(pair.canonical_fact_key),
        canonical_metric_ref=pair.canonical_metric_ref,
        candidate=candidate,
        reference=reference,
        tolerance_profile_locator=profile_locator,
        **comparison.to_dict(),
    )


@dataclass(frozen=True, slots=True)
class Reconciliation7BResult:
    """In-memory outcome of ``reconcile_7b_fact_sets``; a failed 7B never yields a record."""

    bundle_outcome: str
    defect_codes: tuple[str, ...]
    fact_reconciliations: tuple[FactReconciliation, ...]
    logical_fact_reconciliation_digest: str | None
    candidate_row_universe_digest: str
    reference_row_universe_digest: str
    candidate_row_count: int
    reference_row_count: int

    def __post_init__(self) -> None:
        label = "reconciliation_7b_result"
        if self.bundle_outcome not in _BUNDLE_OUTCOMES:
            raise Bundle7BDefectError("malformed_member", f"{label}.bundle_outcome: closed set")
        codes = require_tuple_of(self.defect_codes, str, label=f"{label}.defect_codes")
        if not set(codes) <= set(RECONCILE_OUTCOME_CODES):
            raise Bundle7BDefectError("malformed_member", f"{label}.defect_codes: closed set")
        require_tuple_of(
            self.fact_reconciliations, FactReconciliation, label=f"{label}.fact_reconciliations"
        )
        if self.logical_fact_reconciliation_digest is not None:
            sha256_member(self.logical_fact_reconciliation_digest, label=f"{label}.logical")
        for side in ("candidate", "reference"):
            sha256_member(
                getattr(self, f"{side}_row_universe_digest"), label=f"{label}.{side}_digest"
            )
            require_count(getattr(self, f"{side}_row_count"), label=f"{label}.{side}_row_count")


def reconcile_7b_fact_sets(
    *,
    candidate_result: CollectionResult,
    reference_result: CollectionResult,
    tolerance_profiles: Mapping[str, Mapping[str, Any]],
    gate3_selection_locator: ArtifactLocator,
    canonical_query_contract: CanonicalQueryContract,
    authorized_certification_scope: str,
    migration_run_context_locator: ArtifactLocator,
) -> Reconciliation7BResult:
    """Build every ``fact_reconciliation/v1`` from two complete normalized fact sets.

    Malformed evidence, a fact outside the admitted query (window, binding or
    account) or an unresolved, unsigned or unbound tolerance profile raises
    ``Bundle7BDefectError``; profiles are bound to the digest of
    ``canonical_query_contract``. Set defects, retrieval skew and comparisons
    that are not ``VERIFIED`` are returned as sorted ``defect_codes`` with
    ``bundle_outcome == "failed"``. Reconciliations cover the required pairs
    present on both sides.

    Both results, the query and the locators are re-parsed from their wire forms
    first and only the copies are used: a tampered frozen object is
    ``malformed_member``, never a bare error and never an accept.
    """
    cand_result, cand_facts = checked_side(candidate_result, "candidate")
    ref_result, ref_facts = checked_side(reference_result, "reference")
    query = reparsed(canonical_query_contract, CanonicalQueryContract, label="canonical_query")
    require_facts_in_query(cand_facts, query, label="candidate_result")
    require_facts_in_query(ref_facts, query, label="reference_result")
    binding = binding_members(
        gate3_selection_locator=gate3_selection_locator,
        canonical_query_digest=query.canonical_query_digest,
        authorized_certification_scope=authorized_certification_scope,
        migration_run_context_locator=migration_run_context_locator,
    )
    profiles = resolve_profiles(tolerance_profiles, binding)
    cand, ref = SideUniverse.of(cand_facts), SideUniverse.of(ref_facts)
    codes = _set_codes(cand, ref, cand_result, ref_result)
    common = set(ref.pairs)
    cand_index, ref_index = ResultIndex.of(cand_result), ResultIndex.of(ref_result)
    reconciliations = tuple(
        _reconcile_pair(pair, cand_index, ref_index, profiles[pair.canonical_metric_ref])
        for pair in cand.pairs
        if pair in common and pair.canonical_metric_ref in profiles
    )
    return _reconciliation_result(cand, ref, reconciliations, codes)


def _reconciliation_result(
    cand: SideUniverse,
    ref: SideUniverse,
    reconciliations: tuple[FactReconciliation, ...],
    set_codes: set[str],
) -> Reconciliation7BResult:
    codes = set_codes | {
        _STATUS_OUTCOME_CODES[rec.metric_verification_status]
        for rec in reconciliations
        if rec.metric_verification_status != "VERIFIED"
    }
    digest = (
        logical_digest(require_reconciliations(reconciliations, label="fact_reconciliations"))
        if reconciliations
        else None
    )
    return Reconciliation7BResult(
        bundle_outcome="failed" if codes or not reconciliations else "verified",
        defect_codes=tuple(sorted(codes)),
        fact_reconciliations=reconciliations,
        logical_fact_reconciliation_digest=digest,
        candidate_row_universe_digest=cand.row_universe_digest,
        reference_row_universe_digest=ref.row_universe_digest,
        candidate_row_count=len(cand.pairs),
        reference_row_count=len(ref.pairs),
    )
