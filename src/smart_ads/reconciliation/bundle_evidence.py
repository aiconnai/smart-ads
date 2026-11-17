"""7B fact evidence: ``fact_evidence_selector/v1`` and ``fact_reconciliation/v1`` (ADR 5.4).

Both are embedded closed value objects of ``certification_7b_record/v1``. A
selector addresses exactly one normalized fact inside one side's complete
``collection_result/v1``; ``X(f)`` for the projection digest is the complete
``normalized_collection_fact/v1`` (a choice the ADR's prose leaves loose; its
normative sentence names the complete object). Asserted comparison members are
never trusted: they must form a legal truth-table row and are recomputed later.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, ClassVar, Final

from smart_ads.contracts.jcs import (
    ADR_DATA_DOMAIN_PREFIXES,
    ArtifactLocator,
    canonicalize_jcs,
    domain_jcs_sha256,
)
from smart_ads.contracts.schemas import (
    CollectionResult,
    NormalizedCollectionFact,
    ReconciliationRowKey,
    compute_fact_projection_digest,
    validate_source_metric_ref,
)
from smart_ads.reconciliation.bundle_common import (
    FACT_EVIDENCE_SELECTOR_SCHEMA,
    FACT_RECONCILIATION_SCHEMA,
    Bundle7BDefectError,
    closed,
    guard,
    located,
    metric_ref,
    parse_locator,
    require_collection,
    require_locator,
    require_member,
    require_strictly_ascending,
    require_type,
    sha256_member,
)
from smart_ads.reconciliation.bundle_universe import (
    MetricPairKey,
    as_row_key,
    compute_canonical_fact_key_digest,
    pair_of,
)
from smart_ads.reconciliation.tolerance import (
    ComparisonSide,
    ToleranceComparison,
    ToleranceProfile,
)

SIDE_VALUE_MEMBERS: Final[tuple[str, ...]] = (
    "presence_status",
    "value_type",
    "raw_numeric_value",
    "unit",
    "currency",
)
COMPARISON_MEMBERS: Final[tuple[str, ...]] = (
    "measured_absolute_delta",
    "measured_relative_delta",
    "relative_delta_status",
    "reconciliation_outcome",
    "metric_verification_status",
)


def collection_result_locator(result: CollectionResult) -> ArtifactLocator:
    """The content-addressed ``collection_result/v1`` locator of a resolved result."""
    require_type(result, CollectionResult, label="collection_result")
    return located(CollectionResult.SCHEMA, result)


def complete_facts(result: CollectionResult) -> tuple[NormalizedCollectionFact, ...]:
    """The complete normalized fact set; a partial result is malformed 7B evidence.

    Raising ``collection_result_incomplete`` (instead of returning a failed value)
    is a choice the ADR does not fix.
    """
    require_type(result, CollectionResult, label="collection_result")
    if result.normalized_fact_set is None:
        raise Bundle7BDefectError(
            "collection_result_incomplete", "collection_result: no complete normalized_fact_set"
        )
    return result.normalized_fact_set


def _require_digest_present(result: CollectionResult) -> str:
    complete_facts(result)
    digest = result.normalized_fact_set_digest
    if digest is None:
        raise Bundle7BDefectError(
            "collection_result_incomplete", "collection_result: no set digest"
        )
    return digest


@dataclass(frozen=True, slots=True)
class ResultIndex:
    """A complete result with its locator, set digest and facts indexed by pair, built once.

    Canonicalizing a whole ``collection_result/v1`` per pair is quadratic; every
    caller resolving many selectors against one result shares one index.
    """

    result: CollectionResult
    locator: ArtifactLocator
    set_digest: str
    facts_by_pair: Mapping[MetricPairKey, tuple[NormalizedCollectionFact, ...]]

    @classmethod
    def of(cls, result: CollectionResult | ResultIndex) -> ResultIndex:
        if isinstance(result, ResultIndex):
            return result
        facts = complete_facts(result)
        grouped: dict[MetricPairKey, list[NormalizedCollectionFact]] = {}
        for fact in facts:
            grouped.setdefault(pair_of(fact), []).append(fact)
        return cls(
            result=result,
            locator=collection_result_locator(result),
            set_digest=_require_digest_present(result),
            facts_by_pair=MappingProxyType({k: tuple(v) for k, v in grouped.items()}),
        )


def addressed_fact(
    result: CollectionResult | ResultIndex, pair: MetricPairKey
) -> NormalizedCollectionFact:
    matches = ResultIndex.of(result).facts_by_pair.get(pair, ())
    if len(matches) != 1:
        raise Bundle7BDefectError(
            "evidence_not_addressable",
            f"fact_evidence_selector: {len(matches)} facts carry identity {pair.kfive()}",
        )
    return matches[0]


@dataclass(frozen=True, slots=True)
class FactEvidenceSelector:
    """Closed ``fact_evidence_selector/v1``: exactly one fact inside one side's result."""

    SCHEMA: ClassVar[str] = FACT_EVIDENCE_SELECTOR_SCHEMA
    KEYS: ClassVar[tuple[str, ...]] = (
        "collection_result_locator",
        "normalized_fact_set_digest",
        "reconciliation_row_key",
        "canonical_metric_ref",
        "fact_projection_digest",
    )

    collection_result_locator: ArtifactLocator
    normalized_fact_set_digest: str
    reconciliation_row_key: ReconciliationRowKey
    canonical_metric_ref: str
    fact_projection_digest: str

    def __post_init__(self) -> None:
        label = "fact_evidence_selector"
        require_locator(
            self.collection_result_locator,
            CollectionResult.SCHEMA,
            label=f"{label}.collection_result_locator",
        )
        sha256_member(
            self.normalized_fact_set_digest, label=f"{label}.normalized_fact_set_digest"
        )
        require_member(
            self.reconciliation_row_key,
            ReconciliationRowKey,
            label=f"{label}.reconciliation_row_key",
        )
        metric_ref(self.canonical_metric_ref, label=f"{label}.canonical_metric_ref")
        sha256_member(self.fact_projection_digest, label=f"{label}.fact_projection_digest")

    def pair_key(self) -> MetricPairKey:
        return MetricPairKey(self.reconciliation_row_key, self.canonical_metric_ref)

    def to_dict(self) -> dict[str, Any]:
        return {
            "collection_result_locator": self.collection_result_locator.to_dict(),
            "normalized_fact_set_digest": self.normalized_fact_set_digest,
            "reconciliation_row_key": self.reconciliation_row_key.to_dict(),
            "canonical_metric_ref": self.canonical_metric_ref,
            "fact_projection_digest": self.fact_projection_digest,
        }

    @classmethod
    def from_dict(cls, data: object) -> FactEvidenceSelector:
        label = "fact_evidence_selector"
        mapping = closed(data, frozenset(cls.KEYS), label=label)
        return cls(
            collection_result_locator=parse_locator(
                mapping["collection_result_locator"],
                CollectionResult.SCHEMA,
                label=f"{label}.collection_result_locator",
            ),
            normalized_fact_set_digest=mapping["normalized_fact_set_digest"],
            reconciliation_row_key=as_row_key(
                mapping["reconciliation_row_key"], label=f"{label}.reconciliation_row_key"
            ),
            canonical_metric_ref=mapping["canonical_metric_ref"],
            fact_projection_digest=mapping["fact_projection_digest"],
        )


def select_fact_evidence(
    result: CollectionResult | ResultIndex, pair: MetricPairKey
) -> FactEvidenceSelector:
    """Build the selector addressing exactly one fact of ``pair`` inside ``result``."""
    require_type(pair, MetricPairKey, label="pair")
    index = ResultIndex.of(result)
    target = addressed_fact(index, pair)
    return FactEvidenceSelector(
        collection_result_locator=index.locator,
        normalized_fact_set_digest=index.set_digest,
        reconciliation_row_key=pair.canonical_fact_key,
        canonical_metric_ref=pair.canonical_metric_ref,
        fact_projection_digest=compute_fact_projection_digest(target),
    )


def resolve_fact_evidence(
    selector: FactEvidenceSelector, result: CollectionResult | ResultIndex
) -> NormalizedCollectionFact:
    """Resolve a selector against the side's resolved result; every member is recomputed."""
    require_type(selector, FactEvidenceSelector, label="fact_evidence_selector")
    index = ResultIndex.of(result)
    if selector.collection_result_locator != index.locator:
        raise Bundle7BDefectError(
            "evidence_container_mismatch", "fact_evidence_selector: container is another result"
        )
    if selector.normalized_fact_set_digest != index.set_digest:
        raise Bundle7BDefectError(
            "normalized_fact_set_digest_mismatch", "fact_evidence_selector: set digest differs"
        )
    target = addressed_fact(index, selector.pair_key())
    if compute_fact_projection_digest(target) != selector.fact_projection_digest:
        raise Bundle7BDefectError(
            "fact_projection_digest_mismatch", "fact_evidence_selector: projection digest differs"
        )
    return target


@dataclass(frozen=True, slots=True)
class ReconciliationSide:
    """One side of a reconciliation: source ref, selector and the five copied value fields."""

    KEYS: ClassVar[tuple[str, ...]] = (
        "source_metric_ref",
        "fact_evidence_selector",
        *SIDE_VALUE_MEMBERS,
    )

    source_metric_ref: str
    fact_evidence_selector: FactEvidenceSelector
    presence_status: str
    value_type: str | None
    raw_numeric_value: str | None
    unit: str | None
    currency: str | None

    def __post_init__(self) -> None:
        label = "reconciliation_side"
        field = f"{label}.source_metric_ref"
        guard(
            "malformed_member",
            field,
            lambda: validate_source_metric_ref(self.source_metric_ref, field_name=field),
        )
        require_member(
            self.fact_evidence_selector,
            FactEvidenceSelector,
            label=f"{label}.fact_evidence_selector",
        )
        self.comparison_side()

    def comparison_side(self) -> ComparisonSide:
        """The tolerance comparator input carried by this side (validated on construction)."""
        values = {name: getattr(self, name) for name in SIDE_VALUE_MEMBERS}
        return guard("malformed_member", "reconciliation_side", lambda: ComparisonSide(**values))

    @classmethod
    def for_fact(
        cls, fact: NormalizedCollectionFact, selector: FactEvidenceSelector
    ) -> ReconciliationSide:
        """Copy source/value/state fields byte-for-byte from the resolved fact."""
        require_type(fact, NormalizedCollectionFact, label="fact")
        return cls(
            source_metric_ref=fact.fact_key.source_metric_ref,
            fact_evidence_selector=selector,
            **{name: getattr(fact, name) for name in SIDE_VALUE_MEMBERS},
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_metric_ref": self.source_metric_ref,
            "fact_evidence_selector": self.fact_evidence_selector.to_dict(),
            **{name: getattr(self, name) for name in SIDE_VALUE_MEMBERS},
        }

    @classmethod
    def from_dict(cls, data: object) -> ReconciliationSide:
        mapping = closed(data, frozenset(cls.KEYS), label="reconciliation_side")
        selector = FactEvidenceSelector.from_dict(mapping["fact_evidence_selector"])
        return cls(
            source_metric_ref=mapping["source_metric_ref"],
            fact_evidence_selector=selector,
            **{name: mapping[name] for name in SIDE_VALUE_MEMBERS},
        )


def _parse_side(value: object, *, label: str) -> ReconciliationSide:
    if not isinstance(value, Mapping):
        raise Bundle7BDefectError("malformed_member", f"{label}: expected object")
    return ReconciliationSide.from_dict(value)


@dataclass(frozen=True, slots=True)
class FactReconciliation:
    """Closed ``fact_reconciliation/v1``; asserted comparison members are never trusted."""

    SCHEMA: ClassVar[str] = FACT_RECONCILIATION_SCHEMA
    KEYS: ClassVar[tuple[str, ...]] = (
        "canonical_fact_key",
        "canonical_fact_key_digest",
        "canonical_metric_ref",
        "candidate",
        "reference",
        "tolerance_profile_locator",
        *COMPARISON_MEMBERS,
    )

    canonical_fact_key: ReconciliationRowKey
    canonical_fact_key_digest: str
    canonical_metric_ref: str
    candidate: ReconciliationSide
    reference: ReconciliationSide
    tolerance_profile_locator: ArtifactLocator
    measured_absolute_delta: str | None
    measured_relative_delta: str | None
    relative_delta_status: str
    reconciliation_outcome: str
    metric_verification_status: str

    def __post_init__(self) -> None:
        label = "fact_reconciliation"
        key = self.canonical_fact_key
        require_member(key, ReconciliationRowKey, label=f"{label}.canonical_fact_key")
        sha256_member(self.canonical_fact_key_digest, label=f"{label}.canonical_fact_key_digest")
        if compute_canonical_fact_key_digest(key) != self.canonical_fact_key_digest:
            raise Bundle7BDefectError(
                "canonical_fact_key_digest_mismatch", f"{label}: recomputed key digest differs"
            )
        pair = MetricPairKey(key, self.canonical_metric_ref)
        for name in ("candidate", "reference"):
            side = getattr(self, name)
            require_member(side, ReconciliationSide, label=f"{label}.{name}")
            if side.fact_evidence_selector.pair_key() != pair:
                raise Bundle7BDefectError(
                    "evidence_selector_mismatch",
                    f"{label}.{name}: selector addresses another identity",
                )
        require_locator(
            self.tolerance_profile_locator,
            ToleranceProfile.SCHEMA,
            label=f"{label}.tolerance_profile_locator",
        )
        _ = self.asserted_comparison

    @property
    def asserted_comparison(self) -> ToleranceComparison:
        """The five asserted members as a legal truth-table row (malformed rows are defects)."""
        members = {name: getattr(self, name) for name in COMPARISON_MEMBERS}
        return guard(
            "asserted_comparison_malformed",
            "fact_reconciliation",
            lambda: ToleranceComparison.from_dict(members),
        )

    def pair_key(self) -> MetricPairKey:
        return MetricPairKey(self.canonical_fact_key, self.canonical_metric_ref)

    def to_dict(self) -> dict[str, Any]:
        return {
            "canonical_fact_key": self.canonical_fact_key.to_dict(),
            "canonical_fact_key_digest": self.canonical_fact_key_digest,
            "canonical_metric_ref": self.canonical_metric_ref,
            "candidate": self.candidate.to_dict(),
            "reference": self.reference.to_dict(),
            "tolerance_profile_locator": self.tolerance_profile_locator.to_dict(),
            **{name: getattr(self, name) for name in COMPARISON_MEMBERS},
        }

    @classmethod
    def from_dict(cls, data: object) -> FactReconciliation:
        label = "fact_reconciliation"
        mapping = closed(data, frozenset(cls.KEYS), label=label)
        return cls(
            canonical_fact_key=as_row_key(
                mapping["canonical_fact_key"], label=f"{label}.canonical_fact_key"
            ),
            canonical_fact_key_digest=mapping["canonical_fact_key_digest"],
            canonical_metric_ref=metric_ref(
                mapping["canonical_metric_ref"], label=f"{label}.canonical_metric_ref"
            ),
            candidate=_parse_side(mapping["candidate"], label=f"{label}.candidate"),
            reference=_parse_side(mapping["reference"], label=f"{label}.reference"),
            tolerance_profile_locator=parse_locator(
                mapping["tolerance_profile_locator"],
                ToleranceProfile.SCHEMA,
                label=f"{label}.tolerance_profile_locator",
            ),
            **{name: mapping[name] for name in COMPARISON_MEMBERS},
        )


def require_reconciliations(value: object, *, label: str) -> tuple[FactReconciliation, ...]:
    """A non-empty array of reconciliations in strictly ascending ``RFC8785(J(x))`` order."""
    items = require_collection(value, label=label)
    if not items:
        raise Bundle7BDefectError("malformed_argument", f"{label}: must not be empty")
    for item in items:
        require_type(item, FactReconciliation, label=f"{label}.entry")
    require_strictly_ascending(
        [canonicalize_jcs(item.pair_key().kfive()) for item in items], label=label
    )
    return items


def compute_logical_fact_reconciliation_digest(
    reconciliations: Sequence[FactReconciliation],
) -> str:
    """``logical_fact_reconciliation_digest`` over the complete ``J(x)``-ordered array ``Z``."""
    items = require_reconciliations(reconciliations, label="fact_reconciliations")
    return domain_jcs_sha256(
        ADR_DATA_DOMAIN_PREFIXES["7b_fact_reconciliations"], [item.to_dict() for item in items]
    )
