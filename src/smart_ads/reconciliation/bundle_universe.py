"""7B row universe ``U7``, metric-pair universe ``U7M`` and their digests (ADR-0001 5.4)."""
from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, ClassVar, Final

from smart_ads.contracts.jcs import ADR_DATA_DOMAIN_PREFIXES, canonicalize_jcs, domain_jcs_sha256
from smart_ads.contracts.schemas import (
    CanonicalQueryContract,
    NormalizedCollectionFact,
    ReconciliationRowKey,
)
from smart_ads.contracts.scalars import require_mapping
from smart_ads.reconciliation.bundle_common import (
    REQUIRED_7B_METRICS,
    T,
    Bundle7BDefectError,
    closed,
    guard,
    jcs_bytes,
    metric_ref,
    require_collection,
    require_strictly_ascending,
    require_tuple_of,
    require_type,
)

_ROW_KEY_MEMBERS: Final[tuple[str, ...]] = (
    "resource_ref",
    "metric_date",
    "resource_level",
    "breakdown_signature",
)


def row_k(row: ReconciliationRowKey) -> list[str]:
    """``K(f)``: the exact four-member ordering array of a canonical row key."""
    return [row.resource_ref, row.metric_date, row.resource_level, row.breakdown_signature]


def _raw_members(raw: object, members: Sequence[str], *, label: str) -> list[Any]:
    mapping = guard("malformed_member", label, lambda: require_mapping(raw, label=label))
    missing = [name for name in members if name not in mapping]
    if missing:
        raise Bundle7BDefectError("malformed_member", f"{label}: missing members {missing}")
    return [mapping[name] for name in members]


def _collapse(
    entries: Iterable[tuple[bytes, bytes, T]], *, conflict_code: str, label: str
) -> list[T]:
    """Keep one entry per ordering key; conflicting object bytes for one key reject."""
    seen: dict[bytes, tuple[bytes, T]] = {}
    for key, object_bytes, item in entries:
        prior = seen.get(key)
        if prior is None:
            seen[key] = (object_bytes, item)
        elif prior[0] != object_bytes:
            raise Bundle7BDefectError(conflict_code, f"{label}: conflicting bytes for one key")
    return [seen[key][1] for key in sorted(seen)]


def _row_entry(item: object) -> tuple[bytes, bytes, object]:
    label = "row_universe.entry"
    if isinstance(item, ReconciliationRowKey):
        return canonicalize_jcs(row_k(item)), canonicalize_jcs(item.to_dict()), item
    if isinstance(item, Mapping):
        k = _raw_members(item, _ROW_KEY_MEMBERS, label=label)
        return jcs_bytes(k, label=label), jcs_bytes(item, label=label), item
    raise Bundle7BDefectError(
        "malformed_argument", f"{label}: expected ReconciliationRowKey or mapping"
    )


def as_row_key(item: object, *, label: str) -> ReconciliationRowKey:
    if isinstance(item, ReconciliationRowKey):
        return item
    return guard("malformed_member", label, lambda: ReconciliationRowKey.from_dict(item))


def compute_row_universe(
    row_keys: Iterable[ReconciliationRowKey | Mapping[str, Any]],
) -> tuple[ReconciliationRowKey, ...]:
    """``U7``: unique complete ``C(f)`` objects sorted by raw bytes of ``RFC8785(K(f))``.

    A duplicate ``K(f)`` with identical ``C(f)`` bytes is one row; conflicting
    bytes for one ``K(f)`` reject before any closure check.
    """
    items = require_collection(row_keys, label="row_universe")
    unique = _collapse(
        (_row_entry(item) for item in items),
        conflict_code="row_universe_conflict",
        label="row_universe",
    )
    return tuple(as_row_key(item, label="row_universe.entry") for item in unique)


def _require_row_keys(universe: object, *, label: str) -> tuple[ReconciliationRowKey, ...]:
    rows = require_collection(universe, label=label)
    if not rows:
        raise Bundle7BDefectError("malformed_argument", f"{label}: must not be empty")
    for row in rows:
        require_type(row, ReconciliationRowKey, label=f"{label}.entry")
    return rows


def compute_row_universe_digest(universe: Sequence[ReconciliationRowKey]) -> str:
    """``row_universe_digest`` over a non-empty, already sorted, unique ``U7``."""
    rows = _require_row_keys(universe, label="row_universe")
    require_strictly_ascending(
        [canonicalize_jcs(row_k(row)) for row in rows], label="row_universe"
    )
    return domain_jcs_sha256(
        ADR_DATA_DOMAIN_PREFIXES["7b_row_universe"], [row.to_dict() for row in rows]
    )


def compute_canonical_fact_key_digest(canonical_fact_key: ReconciliationRowKey) -> str:
    """``canonical_fact_key_digest`` of one closed four-member ``C`` object."""
    require_type(canonical_fact_key, ReconciliationRowKey, label="canonical_fact_key")
    return domain_jcs_sha256(
        ADR_DATA_DOMAIN_PREFIXES["7b_canonical_fact_key"], canonical_fact_key.to_dict()
    )


@dataclass(frozen=True, slots=True)
class MetricPairKey:
    """One ``U7M`` entry ``{canonical_fact_key: C(f), canonical_metric_ref}``."""

    KEYS: ClassVar[tuple[str, ...]] = ("canonical_fact_key", "canonical_metric_ref")

    canonical_fact_key: ReconciliationRowKey
    canonical_metric_ref: str

    def __post_init__(self) -> None:
        require_type(
            self.canonical_fact_key, ReconciliationRowKey, label="pair.canonical_fact_key"
        )
        metric_ref(self.canonical_metric_ref, label="pair.canonical_metric_ref")

    def kfive(self) -> list[str]:
        """``Kfive(f)`` / ``J(x)``: ``K(f)`` followed by the canonical metric ref."""
        return [*row_k(self.canonical_fact_key), self.canonical_metric_ref]

    def to_dict(self) -> dict[str, Any]:
        return {
            "canonical_fact_key": self.canonical_fact_key.to_dict(),
            "canonical_metric_ref": self.canonical_metric_ref,
        }

    @classmethod
    def from_dict(cls, data: object) -> MetricPairKey:
        mapping = closed(data, frozenset(cls.KEYS), label="metric_pair_key")
        return cls(
            canonical_fact_key=as_row_key(
                mapping["canonical_fact_key"], label="metric_pair_key.canonical_fact_key"
            ),
            canonical_metric_ref=mapping["canonical_metric_ref"],
        )


def pair_of(fact: NormalizedCollectionFact) -> MetricPairKey:
    """The ``U7M`` entry of a fact (``canonical_metric_ref`` is ``metric_semantic_ref``)."""
    return MetricPairKey(fact.fact_key.reconciliation_row_key, fact.fact_key.metric_semantic_ref)


def _pair_entry(item: object) -> tuple[bytes, bytes, object]:
    label = "pair_universe.entry"
    if isinstance(item, NormalizedCollectionFact):
        item = pair_of(item)
    if isinstance(item, MetricPairKey):
        return canonicalize_jcs(item.kfive()), canonicalize_jcs(item.to_dict()), item
    if isinstance(item, Mapping):
        key, metric = _raw_members(item, MetricPairKey.KEYS, label=label)
        k = _raw_members(key, _ROW_KEY_MEMBERS, label=f"{label}.canonical_fact_key")
        return jcs_bytes([*k, metric], label=label), jcs_bytes(item, label=label), item
    raise Bundle7BDefectError(
        "malformed_argument",
        f"{label}: expected NormalizedCollectionFact, MetricPairKey or mapping",
    )


def compute_pair_universe(
    entries: Iterable[NormalizedCollectionFact | MetricPairKey | Mapping[str, Any]],
) -> tuple[MetricPairKey, ...]:
    """``U7M``: unique metric-scoped entries sorted by raw bytes of ``RFC8785(Kfive(f))``."""
    items = require_collection(entries, label="pair_universe")
    unique = _collapse(
        (_pair_entry(item) for item in items),
        conflict_code="pair_universe_conflict",
        label="pair_universe",
    )
    return tuple(
        item if isinstance(item, MetricPairKey) else MetricPairKey.from_dict(item)
        for item in unique
    )


def expected_pair_universe(
    row_universe: Sequence[ReconciliationRowKey],
) -> tuple[MetricPairKey, ...]:
    """``U7 x required_metrics`` in ``Kfive`` order (the only valid ``U7M``)."""
    rows = _require_row_keys(row_universe, label="row_universe")
    return compute_pair_universe(
        MetricPairKey(row, metric) for row in rows for metric in REQUIRED_7B_METRICS
    )


def require_facts_in_query(
    facts: Sequence[NormalizedCollectionFact], query: CanonicalQueryContract, *, label: str
) -> None:
    """Every fact belongs to the admitted query window, binding and account (ADR L1078-1079,
    L1117-1118); ``C(f)`` drops binding and account, so they are checked here explicitly."""
    require_type(query, CanonicalQueryContract, label="canonical_query_contract")
    window = query.date_range
    for fact in facts:
        key = fact.fact_key
        # Validated `YYYY-MM-DD` strings order chronologically.
        if not window.start_date <= key.metric_date <= window.end_date:
            raise Bundle7BDefectError(
                "fact_outside_query_window", f"{label}: metric_date {key.metric_date} outside"
            )
        if key.binding_ref != query.binding_ref:
            raise Bundle7BDefectError("fact_binding_mismatch", f"{label}: another binding_ref")
        if key.account_ref != query.account_ref:
            raise Bundle7BDefectError("fact_account_mismatch", f"{label}: another account_ref")


@dataclass(frozen=True, slots=True)
class SideUniverse:
    """One side's recomputed ``U7`` and ``U7M``."""

    rows: tuple[ReconciliationRowKey, ...]
    pairs: tuple[MetricPairKey, ...]

    def __post_init__(self) -> None:
        require_tuple_of(self.rows, ReconciliationRowKey, label="side_universe.rows")
        require_tuple_of(self.pairs, MetricPairKey, label="side_universe.pairs")

    @classmethod
    def of(cls, facts: Sequence[NormalizedCollectionFact]) -> SideUniverse:
        return cls(
            rows=compute_row_universe(f.fact_key.reconciliation_row_key for f in facts),
            pairs=compute_pair_universe(facts),
        )

    @property
    def is_complete(self) -> bool:
        return self.pairs == expected_pair_universe(self.rows)

    @property
    def row_universe_digest(self) -> str:
        return compute_row_universe_digest(self.rows)
