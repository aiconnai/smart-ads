"""Effective-state precedence lattice, deterministic candidate winner, and 65x23 regression fixture (ADR-0001 sections 4.3, 5.5, 6.2)."""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
import re
from types import MappingProxyType
from typing import Any, ClassVar, Final, Literal

from smart_ads.contracts.jcs import canonicalize_jcs, sort_by_jcs_key
from smart_ads.contracts.numerics import (
    MAX_INT64,
    CalculationStatus,
    NumericStateRow,
    PresenceStatus,
    UnitType,
    UnknownReason,
    ValueType,
    validate_numeric_state,
)
from smart_ads.contracts.scalars import (
    ClosedValidationError,
    require_exact_keys,
    validate_opaque_ref,
    validate_sha256_prefixed,
)
from smart_ads.contracts.schemas import AnalyticsLandingRow

# ---------------------------------------------------------------------------
# Section 4.3: effective-state precedence over a dependency set
# ---------------------------------------------------------------------------
InputStateClass = Literal[
    "tombstone",
    "not_applicable_at_level",
    "timeout_or_missing",
    "unproven_zero",
    "value",
]

# Strongest first: retracted_tombstone > not_applicable_at_level >
# timeout-or-missing > unproven_zero > (observed or computed).
INPUT_STATE_PRECEDENCE: Final[tuple[InputStateClass, ...]] = (
    "tombstone",
    "not_applicable_at_level",
    "timeout_or_missing",
    "unproven_zero",
    "value",
)
_TIER_RANK: Final[Mapping[str, int]] = MappingProxyType(
    {tier: rank for rank, tier in enumerate(INPUT_STATE_PRECEDENCE)}
)

_PROVIDER: Final[str] = "provider_observation"
_DERIVED: Final[str] = "derived_formula"

# (metric_origin, presence_status, calculation_status) of each of the 12 matrix
# rows -> tier. The ADR names the provider states and leaves upstream derived
# states unclassified; per the approved design an upstream input_missing or
# division_by_zero carries no value like a missing input, and an upstream
# input_unproven is as unproven as unproven_zero.
_TIER_BY_STATE: Final[Mapping[tuple[str, str, str], InputStateClass]] = MappingProxyType(
    {
        (_PROVIDER, "observed", "not_applicable"): "value",
        (_PROVIDER, "missing", "not_applicable"): "timeout_or_missing",
        (_PROVIDER, "unproven_zero", "not_applicable"): "unproven_zero",
        (_PROVIDER, "timeout", "not_applicable"): "timeout_or_missing",
        (_PROVIDER, "not_applicable_at_level", "not_applicable"): "not_applicable_at_level",
        (_PROVIDER, "retracted_tombstone", "not_applicable"): "tombstone",
        (_DERIVED, "not_applicable", "computed"): "value",
        (_DERIVED, "not_applicable", "input_missing"): "timeout_or_missing",
        (_DERIVED, "not_applicable", "input_unproven"): "unproven_zero",
        (_DERIVED, "not_applicable", "division_by_zero"): "timeout_or_missing",
        (_DERIVED, "not_applicable_at_level", "not_applicable"): "not_applicable_at_level",
        (_DERIVED, "retracted_tombstone", "not_applicable"): "tombstone",
    }
)

# tier -> (presence_status, calculation_status, unknown_reason) of the derived row.
_OUTCOME_BY_TIER: Final[Mapping[str, tuple[str, str, str | None]]] = MappingProxyType(
    {
        "tombstone": ("retracted_tombstone", "not_applicable", "source_retracted"),
        "not_applicable_at_level": (
            "not_applicable_at_level",
            "not_applicable",
            "metric_not_applicable_at_level",
        ),
        "timeout_or_missing": ("not_applicable", "input_missing", "input_missing"),
        "unproven_zero": ("not_applicable", "input_unproven", "input_unproven"),
        "value": ("not_applicable", "computed", None),
    }
)
_DIVISION_BY_ZERO_OUTCOME: Final[tuple[str, str, str | None]] = (
    "not_applicable",
    "division_by_zero",
    "division_by_zero",
)
_DERIVED_OUTCOMES: Final[frozenset[tuple[str, str, str | None]]] = frozenset(
    {*_OUTCOME_BY_TIER.values(), _DIVISION_BY_ZERO_OUTCOME}
)


@dataclass(frozen=True, slots=True)
class DerivedStateOutcome:
    """Presence/calculation/reason triple of one of the six derived matrix rows."""

    presence_status: PresenceStatus
    calculation_status: CalculationStatus
    unknown_reason: UnknownReason | None

    def __post_init__(self) -> None:
        for name in ("presence_status", "calculation_status"):
            if type(getattr(self, name)) is not str:
                raise ClosedValidationError(
                    f"derived_state_outcome.{name}: expected str, "
                    f"got {type(getattr(self, name)).__name__}"
                )
        if self.unknown_reason is not None and type(self.unknown_reason) is not str:
            raise ClosedValidationError(
                "derived_state_outcome.unknown_reason: expected str or None, "
                f"got {type(self.unknown_reason).__name__}"
            )
        triple = (self.presence_status, self.calculation_status, self.unknown_reason)
        if triple not in _DERIVED_OUTCOMES:
            raise ClosedValidationError(
                f"derived_state_outcome: {triple!r} is not a derived_formula matrix row"
            )

    @property
    def carries_value(self) -> bool:
        """True only for `calculation_status: computed`, the sole valued derived state."""
        return self.calculation_status == "computed"


def _checked_input_row(row: object) -> NumericStateRow:
    if not isinstance(row, NumericStateRow):
        raise ClosedValidationError(
            f"dependency input: expected NumericStateRow, got {type(row).__name__}"
        )
    # A row mutated after construction must not classify: re-run the 12-row matrix.
    validate_numeric_state(
        metric_origin=row.metric_origin,
        presence_status=row.presence_status,
        calculation_status=row.calculation_status,
        unknown_reason=row.unknown_reason,
        value_type=row.value_type,
        raw_numeric_value=row.raw_numeric_value,
        unit=row.unit,
        currency=row.currency,
        query_currency=row.currency if row.currency is not None else "BRL",
    )
    return row


def classify_input_state(row: NumericStateRow) -> InputStateClass:
    """Place one dependency input in its precedence tier (ADR-0001 section 4.3)."""
    checked = _checked_input_row(row)
    key = (checked.metric_origin, checked.presence_status, checked.calculation_status)
    tier = _TIER_BY_STATE.get(key)
    if tier is None:
        raise ClosedValidationError(
            f"dependency input: state {key!r} is outside the closed 12-row matrix"
        )
    return tier


def _materialize_inputs(inputs: object) -> tuple[NumericStateRow, ...]:
    if isinstance(inputs, (str, bytes)) or not isinstance(inputs, Iterable):
        raise ClosedValidationError(
            "dependency set: expected an iterable of NumericStateRow, "
            f"got {type(inputs).__name__}"
        )
    rows = tuple(inputs)
    if not rows:
        raise ClosedValidationError("dependency set: must contain at least one input")
    return rows


def derive_effective_state(
    inputs: Iterable[NumericStateRow],
    *,
    division_by_zero: bool = False,
) -> DerivedStateOutcome:
    """Resolve the derived row for a dependency set (ADR-0001 section 4.3).

    The strongest tier among the inputs decides; `division_by_zero` is only
    honoured when every input carries a value, otherwise the first matching
    stronger state wins.
    """
    if type(division_by_zero) is not bool:
        raise ClosedValidationError(
            f"division_by_zero: expected bool, got {type(division_by_zero).__name__}"
        )
    rows = _materialize_inputs(inputs)
    tier = min((classify_input_state(row) for row in rows), key=_TIER_RANK.__getitem__)
    if tier == "value" and division_by_zero:
        return DerivedStateOutcome(*_DIVISION_BY_ZERO_OUTCOME)  # type: ignore[arg-type]
    return DerivedStateOutcome(*_OUTCOME_BY_TIER[tier])  # type: ignore[arg-type]


def build_derived_row(
    outcome: DerivedStateOutcome,
    *,
    value_type: ValueType | None = None,
    raw_numeric_value: str | None = None,
    unit: UnitType | None = None,
    currency: str | None = None,
    query_currency: str = "BRL",
) -> NumericStateRow:
    """Materialize a `derived_formula` matrix row; a non-computed state never carries a value."""
    if not isinstance(outcome, DerivedStateOutcome):
        raise ClosedValidationError(
            f"outcome: expected DerivedStateOutcome, got {type(outcome).__name__}"
        )
    return validate_numeric_state(
        metric_origin=_DERIVED,
        presence_status=outcome.presence_status,
        calculation_status=outcome.calculation_status,
        unknown_reason=outcome.unknown_reason,
        value_type=value_type,
        raw_numeric_value=raw_numeric_value,
        unit=unit,
        currency=currency,
        query_currency=query_currency,
    )


# ---------------------------------------------------------------------------
# Section 6.2: deterministic candidate ordering and winner for one fact_key
# ---------------------------------------------------------------------------
_TOMBSTONE_PRESENCE: Final[str] = "retracted_tombstone"


def _require_landing_row(value: object, *, label: str) -> AnalyticsLandingRow:
    if not isinstance(value, AnalyticsLandingRow):
        raise ClosedValidationError(
            f"{label}: expected AnalyticsLandingRow, got {type(value).__name__}"
        )
    return value


def _sort_key_array(row: AnalyticsLandingRow) -> list[object]:
    return [row.fact_key.to_dict(), row.collected_at_utc, row.semantic_observation_digest]


def candidate_sort_key(row: AnalyticsLandingRow) -> bytes:
    """RFC 8785 bytes of `K = [fact_key, collected_at_utc, semantic_observation_digest]`."""
    return canonicalize_jcs(_sort_key_array(_require_landing_row(row, label="candidate")))


def order_candidates(
    candidates: Iterable[AnalyticsLandingRow],
) -> tuple[AnalyticsLandingRow, ...]:
    """Order a unique candidate set by the RFC 8785 bytes of `K` (ADR-0001 section 6.2)."""
    if isinstance(candidates, (str, bytes)) or not isinstance(candidates, Iterable):
        raise ClosedValidationError(
            "candidates: expected an iterable of AnalyticsLandingRow, "
            f"got {type(candidates).__name__}"
        )
    rows = tuple(_require_landing_row(item, label="candidate") for item in candidates)
    ordered = sort_by_jcs_key(rows, _sort_key_array)
    keys = [candidate_sort_key(row) for row in ordered]
    if any(left == right for left, right in zip(keys, keys[1:])):
        raise ClosedValidationError(
            "candidates: the candidate set must be unique (duplicate sort key K)"
        )
    return ordered


def _winner_precedence(row: AnalyticsLandingRow) -> tuple[bytes, bool, bytes]:
    # 1. later collected_at_utc (fixed width, so byte order is chronological);
    # 2. at equal time, a retracted_tombstone over a non-tombstone;
    # 3. otherwise the lexicographically greater semantic_observation_digest.
    return (
        row.collected_at_utc.encode("utf-8"),
        row.presence_status == _TOMBSTONE_PRESENCE,
        row.semantic_observation_digest.encode("utf-8"),
    )


def order_by_winner(
    candidates: Iterable[AnalyticsLandingRow],
) -> tuple[AnalyticsLandingRow, ...]:
    """Order candidates of one `fact_key` by the section 6.2 precedence, winner last.

    One sort on the winner precedence; rejects what `select_winner` rejects (no
    candidate, a non-row, several fact keys, or a duplicate candidate).
    """
    ordered = order_candidates(candidates)
    if not ordered:
        raise ClosedValidationError("candidates: at least one candidate is required")
    fact_key = ordered[0].fact_key
    if any(row.fact_key != fact_key for row in ordered[1:]):
        raise ClosedValidationError(
            "candidates: a winner is defined for one fact_key; found several"
        )
    return tuple(sorted(ordered, key=_winner_precedence))


def select_winner(candidates: Iterable[AnalyticsLandingRow]) -> AnalyticsLandingRow:
    """Return the section 6.2 winner among candidates that share one `fact_key`."""
    return order_by_winner(candidates)[-1]


# ---------------------------------------------------------------------------
# Restatement classification (pure; kinds consumed by RestatementRule in T4)
# ---------------------------------------------------------------------------
RestatementKind = Literal["tombstone", "value_change", "state_flip"]

# Ascending UTF-8 byte order, the order policy arrays use.
RESTATEMENT_KINDS: Final[tuple[RestatementKind, ...]] = (
    "state_flip",
    "tombstone",
    "value_change",
)


def _state_and_value(row: AnalyticsLandingRow) -> tuple[object, ...]:
    return (
        row.metric_origin,
        row.presence_status,
        row.calculation_status,
        row.unknown_reason,
        row.value_type,
        row.raw_numeric_value,
        row.unit,
        row.currency,
    )


def carries_value(row: AnalyticsLandingRow) -> bool:
    """True iff the landing row is `observed` or `computed`, the only valued matrix rows.

    Defined through `classify_input_state`, so it re-runs the 12-row matrix on the
    row's own fields: a non-observed state never reads as a value (an observed
    zero does), and a tampered row rejects instead of answering.
    """
    checked = _require_landing_row(row, label="row")
    state = NumericStateRow(
        metric_origin=checked.metric_origin,
        presence_status=checked.presence_status,
        calculation_status=checked.calculation_status,
        unknown_reason=checked.unknown_reason,
        value_type=checked.value_type,
        raw_numeric_value=checked.raw_numeric_value,
        unit=checked.unit,
        currency=checked.currency,
    )
    return classify_input_state(state) == "value"


def classify_restatement(
    prior: AnalyticsLandingRow,
    current: AnalyticsLandingRow,
) -> RestatementKind | None:
    """Classify how `current` restates `prior` for one `fact_key`.

    `current` must beat `prior` under the ADR-0001 section 6.2 winner order,
    the same precedence `select_winner` applies: later `collected_at_utc`, then
    a tombstone over a non-tombstone, then the greater
    `semantic_observation_digest`. A `current` that loses to `prior`, or is the
    same candidate (equal precedence), rejects. A winner chosen by rule 2 or
    rule 3 at an equal instant is therefore classified, not rejected.

    `tombstone`: the current row is a retraction and the prior row was not.
    `state_flip`: the pair crosses valued <-> unknown (observed or computed vs
    any no-value state). `value_change`: both carry a value and the value, type,
    unit, or currency differs. Anything else, including unchanged state and
    unknown -> a different unknown, is not a restatement (`None`).
    Retrieval metadata (observation ref, adapter and semantic versions, digests)
    never counts as a change.
    """
    earlier = _require_landing_row(prior, label="prior")
    later = _require_landing_row(current, label="current")
    if earlier.fact_key != later.fact_key:
        raise ClosedValidationError("restatement: prior and current must share one fact_key")
    if not _winner_precedence(later) > _winner_precedence(earlier):
        raise ClosedValidationError(
            "restatement: current must beat prior under the ADR-0001 section 6.2 "
            "winner order (later collected_at_utc, then tombstone, then greater digest)"
        )
    if _state_and_value(earlier) == _state_and_value(later):
        return None
    if (
        later.presence_status == _TOMBSTONE_PRESENCE
        and earlier.presence_status != _TOMBSTONE_PRESENCE
    ):
        return "tombstone"
    prior_known, current_known = carries_value(earlier), carries_value(later)
    if prior_known != current_known:
        return "state_flip"
    if prior_known:
        return "value_change"
    return None


# ---------------------------------------------------------------------------
# Section 5.5: synthetic 65x23 regression law (fixture:semantic-metric-65x23-v1)
# ---------------------------------------------------------------------------
FIXTURE_ID_65X23: Final[str] = "fixture:semantic-metric-65x23-v1"
AGGREGATE_CONVERSIONS_REF: Final[str] = "metric:aggregate_conversions_v1"
CANONICAL_LEADS_REF: Final[str] = "metric:canonical_leads_v1"
TRUTH_UNKNOWN: Final[str] = "unknown"

_TRUTH_COUNT_RE: Final[re.Pattern[str]] = re.compile(r"\A(0|[1-9][0-9]*)\Z")
_MAX_INT64_DIGITS: Final[int] = len(str(MAX_INT64))

_FIXTURE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "$schema",
        "fixture_id",
        "fixture_role",
        "provider_provenance",
        "registry_transition",
        "capability_promotion",
        "before_registry_snapshot_digest",
        "after_registry_snapshot_digest",
        "truth_vectors",
        "semantic_refs",
    }
)
_METRIC_PAIR_KEYS: Final[frozenset[str]] = frozenset(
    {"aggregate_conversions", "canonical_leads"}
)
# Members that the law pins to one literal: regression only, synthetic, and
# neither a registry transition nor a capability promotion.
_PINNED_MEMBERS: Final[tuple[tuple[str, str], ...]] = (
    ("fixture_id", FIXTURE_ID_65X23),
    ("fixture_role", "regression_only"),
    ("provider_provenance", "synthetic"),
    ("registry_transition", "none"),
    ("capability_promotion", "none"),
)


def _validate_truth_value(value: object, *, field_name: str) -> str:
    """A truth value is the string `unknown` or a canonical unsigned int64 count."""
    if type(value) is not str:
        raise ClosedValidationError(
            f"{field_name}: expected str, got {type(value).__name__}"
        )
    if value == TRUTH_UNKNOWN:
        return value
    if (
        _TRUTH_COUNT_RE.fullmatch(value) is None
        or len(value) > _MAX_INT64_DIGITS
        or int(value) > MAX_INT64
    ):
        raise ClosedValidationError(
            f"{field_name}: expected 'unknown' or a canonical int64 count, got {value!r}"
        )
    return value


@dataclass(frozen=True, slots=True)
class TruthVector:
    """One `{aggregate_conversions, canonical_leads}` truth vector of section 5.5."""

    aggregate_conversions: str
    canonical_leads: str

    def __post_init__(self) -> None:
        _validate_truth_value(
            self.aggregate_conversions, field_name="truth_vector.aggregate_conversions"
        )
        _validate_truth_value(
            self.canonical_leads, field_name="truth_vector.canonical_leads"
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "aggregate_conversions": self.aggregate_conversions,
            "canonical_leads": self.canonical_leads,
        }

    @classmethod
    def from_dict(cls, data: object) -> TruthVector:
        mapping = require_exact_keys(
            data, _METRIC_PAIR_KEYS, label="regression_fixture.truth_vector"
        )
        return cls(
            aggregate_conversions=mapping["aggregate_conversions"],
            canonical_leads=mapping["canonical_leads"],
        )


# The three vectors of ADR-0001 section 5.5, in order.
EXPECTED_TRUTH_VECTORS: Final[tuple[TruthVector, ...]] = (
    TruthVector("65", TRUTH_UNKNOWN),
    TruthVector("0", "23"),
    TruthVector(TRUTH_UNKNOWN, TRUTH_UNKNOWN),
)


@dataclass(frozen=True, slots=True)
class FixtureSemanticRefs:
    """The two metric refs of the fixture, which are never aliases of each other."""

    aggregate_conversions: str
    canonical_leads: str

    def __post_init__(self) -> None:
        validate_opaque_ref(
            self.aggregate_conversions,
            field_name="regression_fixture.semantic_refs.aggregate_conversions",
            expected_prefix="metric",
        )
        validate_opaque_ref(
            self.canonical_leads,
            field_name="regression_fixture.semantic_refs.canonical_leads",
            expected_prefix="metric",
        )
        if self.aggregate_conversions == self.canonical_leads:
            raise ClosedValidationError(
                "regression_fixture.semantic_refs: aggregate_conversions and "
                "canonical_leads must be distinct metrics (alias is forbidden)"
            )

    def to_dict(self) -> dict[str, str]:
        return {
            "aggregate_conversions": self.aggregate_conversions,
            "canonical_leads": self.canonical_leads,
        }

    @classmethod
    def from_dict(cls, data: object) -> FixtureSemanticRefs:
        mapping = require_exact_keys(
            data, _METRIC_PAIR_KEYS, label="regression_fixture.semantic_refs"
        )
        return cls(
            aggregate_conversions=mapping["aggregate_conversions"],
            canonical_leads=mapping["canonical_leads"],
        )


def _require_pinned_members(fixture: RegressionFixtureV1) -> None:
    for name, expected in _PINNED_MEMBERS:
        value = getattr(fixture, name)
        if type(value) is not str or value != expected:
            raise ClosedValidationError(
                f"regression_fixture.{name}: expected {expected!r}, got {value!r}"
            )


def _require_equal_snapshot_digests(before: object, after: object) -> None:
    validate_sha256_prefixed(
        before, field_name="regression_fixture.before_registry_snapshot_digest"
    )
    validate_sha256_prefixed(
        after, field_name="regression_fixture.after_registry_snapshot_digest"
    )
    if before != after:
        raise ClosedValidationError(
            "regression_fixture: before_registry_snapshot_digest != "
            "after_registry_snapshot_digest (the registry must not change)"
        )


def _require_expected_refs(refs: object) -> None:
    if not isinstance(refs, FixtureSemanticRefs):
        raise ClosedValidationError(
            "regression_fixture.semantic_refs: expected FixtureSemanticRefs, "
            f"got {type(refs).__name__}"
        )
    if (refs.aggregate_conversions, refs.canonical_leads) != (
        AGGREGATE_CONVERSIONS_REF,
        CANONICAL_LEADS_REF,
    ):
        raise ClosedValidationError(
            "regression_fixture.semantic_refs: expected "
            f"({AGGREGATE_CONVERSIONS_REF!r}, {CANONICAL_LEADS_REF!r})"
        )


def _checked_truth_vectors(value: object) -> tuple[TruthVector, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Iterable):
        raise ClosedValidationError(
            f"regression_fixture.truth_vectors: expected a sequence, got {type(value).__name__}"
        )
    vectors = tuple(value)
    if not all(isinstance(vector, TruthVector) for vector in vectors):
        raise ClosedValidationError(
            "regression_fixture.truth_vectors: every member must be a TruthVector"
        )
    for vector in vectors:
        if vector.aggregate_conversions == vector.canonical_leads != TRUTH_UNKNOWN:
            raise ClosedValidationError(
                "regression_fixture.truth_vectors: alias or imputation, both metrics "
                f"carry the same value {vector.canonical_leads!r}"
            )
    if vectors != EXPECTED_TRUTH_VECTORS:
        raise ClosedValidationError(
            "regression_fixture.truth_vectors: must be exactly the three ADR-0001 "
            "section 5.5 vectors, in order; unknown is never coerced to zero"
        )
    return vectors


@dataclass(frozen=True, slots=True)
class RegressionFixtureV1:
    """Closed `smart_ads/regression_fixture/v1` for `fixture:semantic-metric-65x23-v1`."""

    SCHEMA: ClassVar[str] = "smart_ads/regression_fixture/v1"

    fixture_id: str
    fixture_role: str
    provider_provenance: str
    registry_transition: str
    capability_promotion: str
    before_registry_snapshot_digest: str
    after_registry_snapshot_digest: str
    truth_vectors: tuple[TruthVector, ...]
    semantic_refs: FixtureSemanticRefs

    def __post_init__(self) -> None:
        _require_pinned_members(self)
        _require_equal_snapshot_digests(
            self.before_registry_snapshot_digest, self.after_registry_snapshot_digest
        )
        _require_expected_refs(self.semantic_refs)
        object.__setattr__(
            self, "truth_vectors", _checked_truth_vectors(self.truth_vectors)
        )

    @classmethod
    def canonical(cls, registry_snapshot_digest: str) -> RegressionFixtureV1:
        """The ADR-0001 section 5.5 fixture around one unchanged registry snapshot digest."""
        return cls(
            fixture_id=FIXTURE_ID_65X23,
            fixture_role="regression_only",
            provider_provenance="synthetic",
            registry_transition="none",
            capability_promotion="none",
            before_registry_snapshot_digest=registry_snapshot_digest,
            after_registry_snapshot_digest=registry_snapshot_digest,
            truth_vectors=EXPECTED_TRUTH_VECTORS,
            semantic_refs=FixtureSemanticRefs(
                AGGREGATE_CONVERSIONS_REF, CANONICAL_LEADS_REF
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "$schema": self.SCHEMA,
            "fixture_id": self.fixture_id,
            "fixture_role": self.fixture_role,
            "provider_provenance": self.provider_provenance,
            "registry_transition": self.registry_transition,
            "capability_promotion": self.capability_promotion,
            "before_registry_snapshot_digest": self.before_registry_snapshot_digest,
            "after_registry_snapshot_digest": self.after_registry_snapshot_digest,
            "truth_vectors": [vector.to_dict() for vector in self.truth_vectors],
            "semantic_refs": self.semantic_refs.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: object) -> RegressionFixtureV1:
        mapping = require_exact_keys(data, _FIXTURE_KEYS, label="regression_fixture")
        if mapping["$schema"] != cls.SCHEMA:
            raise ClosedValidationError(
                f"regression_fixture.$schema: expected {cls.SCHEMA!r}, got {mapping['$schema']!r}"
            )
        raw_vectors = mapping["truth_vectors"]
        if not isinstance(raw_vectors, list):
            raise ClosedValidationError(
                "regression_fixture.truth_vectors: expected JSON array list, "
                f"got {type(raw_vectors).__name__}"
            )
        return cls(
            fixture_id=mapping["fixture_id"],
            fixture_role=mapping["fixture_role"],
            provider_provenance=mapping["provider_provenance"],
            registry_transition=mapping["registry_transition"],
            capability_promotion=mapping["capability_promotion"],
            before_registry_snapshot_digest=mapping["before_registry_snapshot_digest"],
            after_registry_snapshot_digest=mapping["after_registry_snapshot_digest"],
            truth_vectors=tuple(TruthVector.from_dict(item) for item in raw_vectors),
            semantic_refs=FixtureSemanticRefs.from_dict(mapping["semantic_refs"]),
        )


__all__ = [
    "AGGREGATE_CONVERSIONS_REF",
    "CANONICAL_LEADS_REF",
    "DerivedStateOutcome",
    "EXPECTED_TRUTH_VECTORS",
    "FIXTURE_ID_65X23",
    "FixtureSemanticRefs",
    "INPUT_STATE_PRECEDENCE",
    "InputStateClass",
    "RESTATEMENT_KINDS",
    "RegressionFixtureV1",
    "RestatementKind",
    "TRUTH_UNKNOWN",
    "TruthVector",
    "build_derived_row",
    "candidate_sort_key",
    "carries_value",
    "classify_input_state",
    "classify_restatement",
    "derive_effective_state",
    "order_by_winner",
    "order_candidates",
    "select_winner",
]
