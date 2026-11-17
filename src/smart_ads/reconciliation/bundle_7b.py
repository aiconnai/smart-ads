"""Recomputable 7B bundle: row universes, fact reconciliations, and the sealed certification record (ADR-0001 section 5.4).

The module is organised in two halves separated by a marked seam so that it can
be split mechanically:

* first half - defect model, the row universe ``U7``, the metric-pair universe
  ``U7M``, the four 7B data digests, the Gate-3 certification fingerprint, the
  native request projection, the fact evidence selector and the fact
  reconciliation value objects;
* second half - the execution records, the ``certification_7b_record/v1`` P1
  artifact, ``reconcile_7b_fact_sets`` and ``verify_certification_7b_record``.

Malformed evidence (grammar, extra or missing member, wrong order, divergent
digest, failed binding) raises ``Bundle7BDefectError`` with a closed ``code``.
Legitimate failed comparisons (``mismatch``, ``not_comparable``) are values.
No float, clock, I/O or signature verification is involved.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
import re
from types import MappingProxyType
from typing import Any, ClassVar, Final, TypeVar

from smart_ads.contracts.jcs import (
    ADR_DATA_DOMAIN_PREFIXES,
    ArtifactLocator,
    P1Integrity,
    canonicalize_jcs,
    domain_jcs_sha256,
    jcs_sha256,
    p1_content_digest,
)
from smart_ads.contracts.schemas import (
    CanonicalQueryContract,
    CollectionResult,
    DateRange,
    NormalizedCollectionFact,
    ReconciliationRowKey,
    compute_fact_projection_digest,
    validate_source_metric_ref,
)
from smart_ads.contracts.scalars import (
    ClosedValidationError,
    parse_timestamp_utc_micros,
    require_mapping,
    validate_currency_iso4217,
    validate_opaque_ref,
    validate_resource_ref,
    validate_sha256_prefixed,
)
from smart_ads.reconciliation.tolerance import (
    ComparisonSide,
    ToleranceComparison,
    ToleranceProfile,
    compare_sides,
)

T = TypeVar("T")

REQUIRED_7B_METRICS: Final[tuple[str, ...]] = (
    "metric:impressions_v1",
    "metric:clicks_v1",
    "metric:spend_v1",
)
MAXIMUM_RETRIEVAL_SKEW_SECONDS: Final[int] = 300

DEFECT_CODES: Final[frozenset[str]] = frozenset(
    {
        # structure
        "malformed_argument",
        "malformed_member",
        "closed_member_set",
        "fixed_member_mismatch",
        "wrong_order",
        "duplicate_identity",
        # universes and counts
        "row_universe_conflict",
        "pair_universe_conflict",
        "row_universe_mismatch",
        "pair_universe_incomplete",
        "pair_universe_mismatch",
        "row_universe_digest_mismatch",
        "row_count_mismatch",
        "retrieval_skew_exceeded",
        # Gate-3 fingerprint
        "fingerprint_mismatch",
        # fact evidence and reconciliations
        "collection_result_incomplete",
        "evidence_container_mismatch",
        "evidence_not_addressable",
        "evidence_selector_mismatch",
        "normalized_fact_set_digest_mismatch",
        "fact_projection_digest_mismatch",
        "canonical_fact_key_digest_mismatch",
        "asserted_comparison_malformed",
        # native request projection and P1 integrity
        "native_projection_not_closed",
        "native_projection_forbidden_content",
        "native_projection_mismatch",
        "native_request_digest_mismatch",
        "integrity_digest_mismatch",
        # reconciliation outcomes (returned as values by reconcile_7b_fact_sets)
        "metric_unreconciled",
        "metric_unavailable",
        "metric_blocked",
        "collection_result_mismatch",
        # tolerance profiles
        "tolerance_profile_malformed",
        "tolerance_profile_unresolved",
        "tolerance_profile_unsigned",
        "tolerance_profile_metric_mismatch",
        "tolerance_profile_unbound",
    }
)

_ROW_KEY_MEMBERS: Final[tuple[str, ...]] = (
    "resource_ref",
    "metric_date",
    "resource_level",
    "breakdown_signature",
)
_PAIR_KEYS: Final[frozenset[str]] = frozenset({"canonical_fact_key", "canonical_metric_ref"})


class Bundle7BDefectError(ClosedValidationError):
    """Malformed or unverifiable 7B evidence; ``code`` is a member of ``DEFECT_CODES``."""

    def __init__(self, code: str, detail: str) -> None:
        if not isinstance(code, str) or code not in DEFECT_CODES:
            raise ClosedValidationError(f"bundle_7b: unknown defect code {code!r}")
        self.code = code
        super().__init__(f"{code}: {detail}")


def _guard(code: str, label: str, build: Callable[[], T]) -> T:
    """Run ``build`` and re-raise a plain ``ClosedValidationError`` as a coded defect."""
    try:
        return build()
    except Bundle7BDefectError:
        raise
    except ClosedValidationError as exc:
        raise Bundle7BDefectError(code, f"{label}: {exc}") from exc


def _require_type(value: object, expected: type, *, label: str) -> None:
    if not isinstance(value, expected):
        raise Bundle7BDefectError(
            "malformed_argument",
            f"{label}: expected {expected.__name__}, got {type(value).__name__}",
        )


def _closed(data: object, keys: frozenset[str], *, label: str) -> Mapping[str, Any]:
    """Require a str-keyed mapping with exactly ``keys`` (this module's closed objects)."""
    mapping = _guard("malformed_member", label, lambda: require_mapping(data, label=label))
    actual = set(mapping)
    if actual != keys:
        raise Bundle7BDefectError(
            "closed_member_set",
            f"{label}: missing={sorted(keys - actual)} extra={sorted(actual - keys)}",
        )
    return mapping


def _require_collection(value: object, *, label: str) -> tuple[Any, ...]:
    if isinstance(value, (str, bytes, Mapping)) or not isinstance(value, Iterable):
        raise Bundle7BDefectError(
            "malformed_argument", f"{label}: expected an iterable collection"
        )
    return tuple(value)


def _metric_ref(value: object, *, label: str) -> str:
    return _guard(
        "malformed_member",
        label,
        lambda: validate_opaque_ref(value, field_name=label, expected_prefix="metric"),
    )


def _jcs(value: object, *, label: str) -> bytes:
    return _guard("malformed_member", label, lambda: canonicalize_jcs(value))


def _require_strictly_ascending(keys: Sequence[bytes], *, label: str) -> None:
    for previous, current in zip(keys, keys[1:]):
        if previous == current:
            raise Bundle7BDefectError("duplicate_identity", f"{label}: duplicate identity")
        if previous > current:
            raise Bundle7BDefectError("wrong_order", f"{label}: not in canonical order")


# ---------------------------------------------------------------------------
# Row universe U7 and metric-pair universe U7M
# ---------------------------------------------------------------------------


def _row_k(row: ReconciliationRowKey) -> list[str]:
    """``K(f)``: the exact four-member ordering array of a canonical row key."""
    return [row.resource_ref, row.metric_date, row.resource_level, row.breakdown_signature]


def _raw_members(raw: object, members: Sequence[str], *, label: str) -> list[Any]:
    mapping = _guard("malformed_member", label, lambda: require_mapping(raw, label=label))
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
        return canonicalize_jcs(_row_k(item)), canonicalize_jcs(item.to_dict()), item
    if isinstance(item, Mapping):
        k = _raw_members(item, _ROW_KEY_MEMBERS, label=label)
        return _jcs(k, label=label), _jcs(item, label=label), item
    raise Bundle7BDefectError(
        "malformed_argument", f"{label}: expected ReconciliationRowKey or mapping"
    )


def _as_row_key(item: object, *, label: str) -> ReconciliationRowKey:
    if isinstance(item, ReconciliationRowKey):
        return item
    return _guard("malformed_member", label, lambda: ReconciliationRowKey.from_dict(item))


def compute_row_universe(
    row_keys: Iterable[ReconciliationRowKey | Mapping[str, Any]],
) -> tuple[ReconciliationRowKey, ...]:
    """``U7``: unique complete ``C(f)`` objects sorted by raw bytes of ``RFC8785(K(f))``.

    A duplicate ``K(f)`` with identical ``C(f)`` bytes is one row; conflicting
    bytes for one ``K(f)`` reject before any closure check.
    """
    items = _require_collection(row_keys, label="row_universe")
    unique = _collapse(
        (_row_entry(item) for item in items),
        conflict_code="row_universe_conflict",
        label="row_universe",
    )
    return tuple(_as_row_key(item, label="row_universe.entry") for item in unique)


def _require_row_keys(universe: object, *, label: str) -> tuple[ReconciliationRowKey, ...]:
    rows = _require_collection(universe, label=label)
    if not rows:
        raise Bundle7BDefectError("malformed_argument", f"{label}: must not be empty")
    for row in rows:
        _require_type(row, ReconciliationRowKey, label=f"{label}.entry")
    return rows


def compute_row_universe_digest(universe: Sequence[ReconciliationRowKey]) -> str:
    """``row_universe_digest`` over a non-empty, already sorted, unique ``U7``."""
    rows = _require_row_keys(universe, label="row_universe")
    _require_strictly_ascending(
        [canonicalize_jcs(_row_k(row)) for row in rows], label="row_universe"
    )
    return domain_jcs_sha256(
        ADR_DATA_DOMAIN_PREFIXES["7b_row_universe"], [row.to_dict() for row in rows]
    )


def compute_canonical_fact_key_digest(canonical_fact_key: ReconciliationRowKey) -> str:
    """``canonical_fact_key_digest`` of one closed four-member ``C`` object."""
    _require_type(canonical_fact_key, ReconciliationRowKey, label="canonical_fact_key")
    return domain_jcs_sha256(
        ADR_DATA_DOMAIN_PREFIXES["7b_canonical_fact_key"], canonical_fact_key.to_dict()
    )


@dataclass(frozen=True, slots=True)
class MetricPairKey:
    """One ``U7M`` entry ``{canonical_fact_key: C(f), canonical_metric_ref}``."""

    canonical_fact_key: ReconciliationRowKey
    canonical_metric_ref: str

    def __post_init__(self) -> None:
        _require_type(self.canonical_fact_key, ReconciliationRowKey, label="pair.canonical_fact_key")
        _metric_ref(self.canonical_metric_ref, label="pair.canonical_metric_ref")

    def kfive(self) -> list[str]:
        """``Kfive(f)`` / ``J(x)``: ``K(f)`` followed by the canonical metric ref."""
        return [*_row_k(self.canonical_fact_key), self.canonical_metric_ref]

    def to_dict(self) -> dict[str, Any]:
        return {
            "canonical_fact_key": self.canonical_fact_key.to_dict(),
            "canonical_metric_ref": self.canonical_metric_ref,
        }

    @classmethod
    def from_dict(cls, data: object) -> MetricPairKey:
        mapping = _closed(data, _PAIR_KEYS, label="metric_pair_key")
        return cls(
            canonical_fact_key=_as_row_key(
                mapping["canonical_fact_key"], label="metric_pair_key.canonical_fact_key"
            ),
            canonical_metric_ref=mapping["canonical_metric_ref"],
        )


def _pair_entry(item: object) -> tuple[bytes, bytes, object]:
    label = "pair_universe.entry"
    if isinstance(item, NormalizedCollectionFact):
        item = MetricPairKey(item.fact_key.reconciliation_row_key, item.fact_key.metric_semantic_ref)
    if isinstance(item, MetricPairKey):
        return canonicalize_jcs(item.kfive()), canonicalize_jcs(item.to_dict()), item
    if isinstance(item, Mapping):
        key, metric = _raw_members(item, ("canonical_fact_key", "canonical_metric_ref"), label=label)
        k = _raw_members(key, _ROW_KEY_MEMBERS, label=f"{label}.canonical_fact_key")
        return _jcs([*k, metric], label=label), _jcs(item, label=label), item
    raise Bundle7BDefectError(
        "malformed_argument", f"{label}: expected NormalizedCollectionFact, MetricPairKey or mapping"
    )


def compute_pair_universe(
    entries: Iterable[NormalizedCollectionFact | MetricPairKey | Mapping[str, Any]],
) -> tuple[MetricPairKey, ...]:
    """``U7M``: unique metric-scoped entries sorted by raw bytes of ``RFC8785(Kfive(f))``."""
    items = _require_collection(entries, label="pair_universe")
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


# ---------------------------------------------------------------------------
# Gate-3 certification fingerprint (ADR-0001 sections 5.3 and 5.4)
# ---------------------------------------------------------------------------

_FINGERPRINT_DIGEST_MEMBERS: Final[tuple[str, ...]] = (
    "reference_client_identity_digest",
    "official_source_locators_digest",
    "candidate_driver_contract_digest",
    "canonical_query_digest",
    "parser_code_digest",
    "adapter_code_digest",
    "mapping_rules_digest",
    "schema_bundle_digest",
    "resource_mapping_contract_digest",
)
_FINGERPRINT_KEYS: Final[frozenset[str]] = frozenset(
    {"selected_meta_api_version", "authorized_certification_scope", *_FINGERPRINT_DIGEST_MEMBERS}
)
# The selected version is copied into `api-version:<v>`, which must stay an opaque_ref.
_API_VERSION_RE: Final[re.Pattern[str]] = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")


# ADR 7B literals such as `api-version:<v>`, `opaque-driver-contract:<digest>` and
# `provider-target:<name>` carry hyphenated prefixes, which the repo `opaque_ref`
# grammar (`^[a-z][a-z0-9_]*:`) does not admit; the body keeps the opaque_ref alphabet.
_HYPHEN_REF_RE: Final[re.Pattern[str]] = re.compile(r"\A([a-z][a-z0-9-]*):[A-Za-z0-9._:-]+\Z")


def _hyphen_ref(value: object, *, prefixes: frozenset[str], label: str) -> str:
    match = _HYPHEN_REF_RE.fullmatch(value) if isinstance(value, str) else None
    if match is None or match.group(1) not in prefixes:
        raise Bundle7BDefectError(
            "malformed_member", f"{label}: expected a ref with prefix in {sorted(prefixes)}"
        )
    return value


def _sha256(value: object, *, label: str) -> str:
    return _guard(
        "malformed_member", label, lambda: validate_sha256_prefixed(value, field_name=label)
    )


def _scope_ref(value: object, *, label: str) -> str:
    return _guard(
        "malformed_member",
        label,
        lambda: validate_opaque_ref(value, field_name=label, expected_prefix="scope"),
    )


@dataclass(frozen=True, slots=True)
class Gate3CertificationFingerprint:
    """The complete eleven-member ``certification_fingerprint`` of a certification-role selection."""

    selected_meta_api_version: str
    reference_client_identity_digest: str
    official_source_locators_digest: str
    candidate_driver_contract_digest: str
    canonical_query_digest: str
    parser_code_digest: str
    adapter_code_digest: str
    mapping_rules_digest: str
    schema_bundle_digest: str
    resource_mapping_contract_digest: str
    authorized_certification_scope: str

    def __post_init__(self) -> None:
        label = "gate3_certification_fingerprint"
        version = self.selected_meta_api_version
        if not isinstance(version, str) or _API_VERSION_RE.fullmatch(version) is None:
            raise Bundle7BDefectError(
                "malformed_member", f"{label}.selected_meta_api_version: invalid version"
            )
        for name in _FINGERPRINT_DIGEST_MEMBERS:
            _sha256(getattr(self, name), label=f"{label}.{name}")
        _scope_ref(self.authorized_certification_scope, label=f"{label}.authorized_certification_scope")

    def to_dict(self) -> dict[str, str]:
        return {
            "selected_meta_api_version": self.selected_meta_api_version,
            **{name: getattr(self, name) for name in _FINGERPRINT_DIGEST_MEMBERS},
            "authorized_certification_scope": self.authorized_certification_scope,
        }

    @classmethod
    def from_dict(cls, data: object) -> Gate3CertificationFingerprint:
        mapping = _closed(data, _FINGERPRINT_KEYS, label="gate3_certification_fingerprint")
        return cls(**{name: mapping[name] for name in _FINGERPRINT_KEYS})


def require_same_fingerprint(
    left: Gate3CertificationFingerprint,
    right: Gate3CertificationFingerprint,
    *,
    label: str,
) -> None:
    """Byte-for-byte equality of two complete fingerprints; any one member differing fails 7B."""
    _require_type(left, Gate3CertificationFingerprint, label=f"{label}.left")
    _require_type(right, Gate3CertificationFingerprint, label=f"{label}.right")
    if canonicalize_jcs(left.to_dict()) != canonicalize_jcs(right.to_dict()):
        differing = [n for n in _FINGERPRINT_KEYS if getattr(left, n) != getattr(right, n)]
        raise Bundle7BDefectError(
            "fingerprint_mismatch", f"{label}: members differ: {sorted(differing)}"
        )


# ---------------------------------------------------------------------------
# fact_evidence_selector/v1 (embedded closed value object)
# ---------------------------------------------------------------------------

_SELECTOR_KEYS: Final[frozenset[str]] = frozenset(
    {
        "collection_result_locator",
        "normalized_fact_set_digest",
        "reconciliation_row_key",
        "canonical_metric_ref",
        "fact_projection_digest",
    }
)


def _parse_integrity(mapping: Mapping[str, Any], *, label: str) -> P1Integrity | None:
    if "integrity" not in mapping:
        return None
    return _guard(
        "malformed_member", f"{label}.integrity", lambda: P1Integrity.from_dict(mapping["integrity"])
    )


def _check_integrity(integrity: object, envelope: Callable[[], dict[str, Any]], *, label: str) -> None:
    """A signed P1 block must carry the recomputed preimage digest (the wheel never verifies Ed25519)."""
    if integrity is None:
        return
    if not isinstance(integrity, P1Integrity):
        raise Bundle7BDefectError("malformed_member", f"{label}.integrity: expected P1Integrity")
    if integrity.is_signed and integrity.content_digest != p1_content_digest(envelope()):
        raise Bundle7BDefectError("integrity_digest_mismatch", f"{label}.integrity: digest differs")


def _locator(value: object, artifact_type: str, *, label: str) -> ArtifactLocator:
    if not isinstance(value, ArtifactLocator) or value.artifact_type != artifact_type:
        raise Bundle7BDefectError(
            "malformed_member", f"{label}: expected ArtifactLocator for {artifact_type!r}"
        )
    return value


def _parse_locator(value: object, artifact_type: str, *, label: str) -> ArtifactLocator:
    return _guard(
        "malformed_member",
        label,
        lambda: ArtifactLocator.from_dict(value, expected_type=artifact_type),
    )


def located(artifact_type: str, artifact: Any) -> ArtifactLocator:
    """Repo locator convention: ``for_canonical_bytes(type, RFC8785(artifact.to_dict()))``."""
    return ArtifactLocator.for_canonical_bytes(artifact_type, canonicalize_jcs(artifact.to_dict()))


def collection_result_locator(result: CollectionResult) -> ArtifactLocator:
    """The content-addressed ``collection_result/v1`` locator of a resolved result."""
    _require_type(result, CollectionResult, label="collection_result")
    return located(CollectionResult.SCHEMA, result)


def _complete_facts(result: CollectionResult) -> tuple[NormalizedCollectionFact, ...]:
    _require_type(result, CollectionResult, label="collection_result")
    if result.normalized_fact_set is None:
        raise Bundle7BDefectError(
            "collection_result_incomplete", "collection_result: no complete normalized_fact_set"
        )
    return result.normalized_fact_set


def _pair_of(fact: NormalizedCollectionFact) -> MetricPairKey:
    return MetricPairKey(fact.fact_key.reconciliation_row_key, fact.fact_key.metric_semantic_ref)


def _addressed_fact(result: CollectionResult, pair: MetricPairKey) -> NormalizedCollectionFact:
    matches = [fact for fact in _complete_facts(result) if _pair_of(fact) == pair]
    if len(matches) != 1:
        raise Bundle7BDefectError(
            "evidence_not_addressable",
            f"fact_evidence_selector: {len(matches)} facts carry identity {pair.kfive()}",
        )
    return matches[0]


@dataclass(frozen=True, slots=True)
class FactEvidenceSelector:
    """Closed ``fact_evidence_selector/v1``: exactly one fact inside one side's result container."""

    collection_result_locator: ArtifactLocator
    normalized_fact_set_digest: str
    reconciliation_row_key: ReconciliationRowKey
    canonical_metric_ref: str
    fact_projection_digest: str

    def __post_init__(self) -> None:
        label = "fact_evidence_selector"
        _locator(self.collection_result_locator, CollectionResult.SCHEMA, label=f"{label}.collection_result_locator")
        _sha256(self.normalized_fact_set_digest, label=f"{label}.normalized_fact_set_digest")
        if not isinstance(self.reconciliation_row_key, ReconciliationRowKey):
            raise Bundle7BDefectError("malformed_member", f"{label}.reconciliation_row_key: expected ReconciliationRowKey")
        _metric_ref(self.canonical_metric_ref, label=f"{label}.canonical_metric_ref")
        _sha256(self.fact_projection_digest, label=f"{label}.fact_projection_digest")

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
        mapping = _closed(data, _SELECTOR_KEYS, label=label)
        return cls(
            collection_result_locator=_parse_locator(
                mapping["collection_result_locator"], CollectionResult.SCHEMA, label=f"{label}.collection_result_locator"
            ),
            normalized_fact_set_digest=mapping["normalized_fact_set_digest"],
            reconciliation_row_key=_as_row_key(mapping["reconciliation_row_key"], label=f"{label}.reconciliation_row_key"),
            canonical_metric_ref=mapping["canonical_metric_ref"],
            fact_projection_digest=mapping["fact_projection_digest"],
        )


def select_fact_evidence(result: CollectionResult, pair: MetricPairKey) -> FactEvidenceSelector:
    """Build the selector addressing exactly one fact of ``pair`` inside ``result``."""
    _require_type(pair, MetricPairKey, label="pair")
    target = _addressed_fact(result, pair)
    return FactEvidenceSelector(
        collection_result_locator=collection_result_locator(result),
        normalized_fact_set_digest=_require_digest_present(result),
        reconciliation_row_key=pair.canonical_fact_key,
        canonical_metric_ref=pair.canonical_metric_ref,
        fact_projection_digest=compute_fact_projection_digest(target),
    )


def _require_digest_present(result: CollectionResult) -> str:
    _complete_facts(result)
    digest = result.normalized_fact_set_digest
    if digest is None:
        raise Bundle7BDefectError("collection_result_incomplete", "collection_result: no set digest")
    return digest


def resolve_fact_evidence(
    selector: FactEvidenceSelector, result: CollectionResult
) -> NormalizedCollectionFact:
    """Resolve a selector against the side's resolved result; every member is recomputed."""
    _require_type(selector, FactEvidenceSelector, label="fact_evidence_selector")
    set_digest = _require_digest_present(result)
    if selector.collection_result_locator != collection_result_locator(result):
        raise Bundle7BDefectError(
            "evidence_container_mismatch", "fact_evidence_selector: container is another result"
        )
    if selector.normalized_fact_set_digest != set_digest:
        raise Bundle7BDefectError(
            "normalized_fact_set_digest_mismatch", "fact_evidence_selector: set digest differs"
        )
    target = _addressed_fact(result, selector.pair_key())
    if compute_fact_projection_digest(target) != selector.fact_projection_digest:
        raise Bundle7BDefectError(
            "fact_projection_digest_mismatch", "fact_evidence_selector: projection digest differs"
        )
    return target


# ---------------------------------------------------------------------------
# fact_reconciliation/v1 (embedded closed value object) and its two sides
# ---------------------------------------------------------------------------

_SIDE_VALUE_MEMBERS: Final[tuple[str, ...]] = (
    "presence_status",
    "value_type",
    "raw_numeric_value",
    "unit",
    "currency",
)
_SIDE_KEYS: Final[frozenset[str]] = frozenset(
    {"source_metric_ref", "fact_evidence_selector", *_SIDE_VALUE_MEMBERS}
)
_COMPARISON_MEMBERS: Final[tuple[str, ...]] = (
    "measured_absolute_delta",
    "measured_relative_delta",
    "relative_delta_status",
    "reconciliation_outcome",
    "metric_verification_status",
)
_RECONCILIATION_KEYS: Final[frozenset[str]] = frozenset(
    {
        "canonical_fact_key",
        "canonical_fact_key_digest",
        "canonical_metric_ref",
        "candidate",
        "reference",
        "tolerance_profile_locator",
        *_COMPARISON_MEMBERS,
    }
)


@dataclass(frozen=True, slots=True)
class ReconciliationSide:
    """One side of a reconciliation: source ref, selector and the five copied value fields."""

    source_metric_ref: str
    fact_evidence_selector: FactEvidenceSelector
    presence_status: str
    value_type: str | None
    raw_numeric_value: str | None
    unit: str | None
    currency: str | None

    def __post_init__(self) -> None:
        label = "reconciliation_side"
        _guard(
            "malformed_member",
            f"{label}.source_metric_ref",
            lambda: validate_source_metric_ref(self.source_metric_ref, field_name=f"{label}.source_metric_ref"),
        )
        if not isinstance(self.fact_evidence_selector, FactEvidenceSelector):
            raise Bundle7BDefectError("malformed_member", f"{label}.fact_evidence_selector: expected selector")
        self.comparison_side()

    def comparison_side(self) -> ComparisonSide:
        """The tolerance comparator input carried by this side (validated on construction)."""
        return _guard(
            "malformed_member",
            "reconciliation_side",
            lambda: ComparisonSide(**{name: getattr(self, name) for name in _SIDE_VALUE_MEMBERS}),
        )

    @classmethod
    def for_fact(
        cls, fact: NormalizedCollectionFact, selector: FactEvidenceSelector
    ) -> ReconciliationSide:
        """Copy source/value/state fields byte-for-byte from the resolved fact."""
        _require_type(fact, NormalizedCollectionFact, label="fact")
        return cls(
            source_metric_ref=fact.fact_key.source_metric_ref,
            fact_evidence_selector=selector,
            **{name: getattr(fact, name) for name in _SIDE_VALUE_MEMBERS},
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_metric_ref": self.source_metric_ref,
            "fact_evidence_selector": self.fact_evidence_selector.to_dict(),
            **{name: getattr(self, name) for name in _SIDE_VALUE_MEMBERS},
        }

    @classmethod
    def from_dict(cls, data: object) -> ReconciliationSide:
        mapping = _closed(data, _SIDE_KEYS, label="reconciliation_side")
        return cls(
            source_metric_ref=mapping["source_metric_ref"],
            fact_evidence_selector=FactEvidenceSelector.from_dict(mapping["fact_evidence_selector"]),
            **{name: mapping[name] for name in _SIDE_VALUE_MEMBERS},
        )


def _parse_side(value: object, *, label: str) -> ReconciliationSide:
    if not isinstance(value, Mapping):
        raise Bundle7BDefectError("malformed_member", f"{label}: expected object")
    return ReconciliationSide.from_dict(value)


@dataclass(frozen=True, slots=True)
class FactReconciliation:
    """Closed ``fact_reconciliation/v1``; asserted comparison members are never trusted."""

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
        _require_type(self.canonical_fact_key, ReconciliationRowKey, label=f"{label}.canonical_fact_key")
        _sha256(self.canonical_fact_key_digest, label=f"{label}.canonical_fact_key_digest")
        if compute_canonical_fact_key_digest(self.canonical_fact_key) != self.canonical_fact_key_digest:
            raise Bundle7BDefectError(
                "canonical_fact_key_digest_mismatch", f"{label}: recomputed key digest differs"
            )
        pair = MetricPairKey(self.canonical_fact_key, self.canonical_metric_ref)
        for name in ("candidate", "reference"):
            side = getattr(self, name)
            _require_type(side, ReconciliationSide, label=f"{label}.{name}")
            if side.fact_evidence_selector.pair_key() != pair:
                raise Bundle7BDefectError(
                    "evidence_selector_mismatch", f"{label}.{name}: selector addresses another identity"
                )
        _locator(self.tolerance_profile_locator, ToleranceProfile.SCHEMA, label=f"{label}.tolerance_profile_locator")
        _ = self.asserted_comparison

    @property
    def asserted_comparison(self) -> ToleranceComparison:
        """The five asserted members as a legal truth-table row (malformed rows are defects)."""
        return _guard(
            "asserted_comparison_malformed",
            "fact_reconciliation",
            lambda: ToleranceComparison.from_dict({n: getattr(self, n) for n in _COMPARISON_MEMBERS}),
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
            **{name: getattr(self, name) for name in _COMPARISON_MEMBERS},
        }

    @classmethod
    def from_dict(cls, data: object) -> FactReconciliation:
        label = "fact_reconciliation"
        mapping = _closed(data, _RECONCILIATION_KEYS, label=label)
        return cls(
            canonical_fact_key=_as_row_key(mapping["canonical_fact_key"], label=f"{label}.canonical_fact_key"),
            canonical_fact_key_digest=mapping["canonical_fact_key_digest"],
            canonical_metric_ref=_metric_ref(mapping["canonical_metric_ref"], label=f"{label}.canonical_metric_ref"),
            candidate=_parse_side(mapping["candidate"], label=f"{label}.candidate"),
            reference=_parse_side(mapping["reference"], label=f"{label}.reference"),
            tolerance_profile_locator=_parse_locator(
                mapping["tolerance_profile_locator"], ToleranceProfile.SCHEMA, label=f"{label}.tolerance_profile_locator"
            ),
            **{name: mapping[name] for name in _COMPARISON_MEMBERS},
        )


def _require_reconciliations(value: object, *, label: str) -> tuple[FactReconciliation, ...]:
    items = _require_collection(value, label=label)
    if not items:
        raise Bundle7BDefectError("malformed_argument", f"{label}: must not be empty")
    for item in items:
        _require_type(item, FactReconciliation, label=f"{label}.entry")
    _require_strictly_ascending(
        [canonicalize_jcs(item.pair_key().kfive()) for item in items], label=label
    )
    return items


def compute_logical_fact_reconciliation_digest(
    reconciliations: Sequence[FactReconciliation],
) -> str:
    """``logical_fact_reconciliation_digest`` over the complete ``J(x)``-ordered array ``Z``."""
    items = _require_reconciliations(reconciliations, label="fact_reconciliations")
    return domain_jcs_sha256(
        ADR_DATA_DOMAIN_PREFIXES["7b_fact_reconciliations"], [item.to_dict() for item in items]
    )


# ---------------------------------------------------------------------------
# native_request_projection/v1 (closed, redacted P1 artifact)
# ---------------------------------------------------------------------------

NATIVE_REQUEST_PROJECTION_SCHEMA: Final[str] = "smart_ads/native_request_projection/v1"
_NATIVE_CORE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "$schema",
        "endpoint",
        "http_method",
        "endpoint_version_ref",
        "resource_refs",
        "date_range",
        "resource_level",
        "metrics",
        "breakdowns",
        "pagination",
        "currency",
        "attribution_omission_state",
    }
)
_NATIVE_ARRAY_MEMBERS: Final[tuple[str, ...]] = ("resource_refs", "metrics", "breakdowns")
_HTTP_METHODS: Final[frozenset[str]] = frozenset({"GET", "POST"})
_ENDPOINT_VERSION_PREFIXES: Final[frozenset[str]] = frozenset(
    {"api-version", "opaque-driver-contract"}
)
_ATTRIBUTION_OMITTED: Final[str] = "omitted"
# Path only: no scheme, authority, userinfo, query or fragment. A segment is either an
# API version (`v21.0`) or a lowercase name without digits, so raw numeric provider
# identifiers (`act_123`, `1234`) cannot appear in the endpoint.
_ENDPOINT_PATH_RE: Final[re.Pattern[str]] = re.compile(
    r"\A(?:/(?:v[0-9]+(?:\.[0-9]+)*|[a-z][a-z_-]*))+\Z"
)
_NATIVE_NAME_RE: Final[re.Pattern[str]] = re.compile(r"\A[a-z][a-z_]*\Z")


def _native_name(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _NATIVE_NAME_RE.fullmatch(value) is None:
        raise Bundle7BDefectError("malformed_member", f"{label}: invalid native name")
    return value


def _native_name_checker(label: str) -> Callable[[object], str]:
    def check(value: object) -> str:
        return _native_name(value, label=label)

    return check


def _sorted_native_array(
    values: object, *, label: str, check: Callable[[object], str], allow_empty: bool
) -> tuple[str, ...]:
    if not isinstance(values, tuple):
        raise Bundle7BDefectError("malformed_member", f"{label}: expected an array")
    if not values and not allow_empty:
        raise Bundle7BDefectError("malformed_member", f"{label}: must not be empty")
    checked = tuple(check(value) for value in values)
    _require_strictly_ascending([value.encode("utf-8") for value in checked], label=label)
    return checked


def _canonical_resource_ref(value: object) -> str:
    try:
        return validate_resource_ref(value, field_name="native_request_projection.resource_refs")
    except ClosedValidationError as exc:
        raise Bundle7BDefectError(
            "native_projection_forbidden_content",
            "native_request_projection.resource_refs: only tenant-scoped resource refs are allowed",
        ) from exc


def _check_endpoint(endpoint: object) -> None:
    label = "native_request_projection.endpoint"
    if not isinstance(endpoint, str):
        raise Bundle7BDefectError("malformed_member", f"{label}: expected str")
    if _ENDPOINT_PATH_RE.fullmatch(endpoint) is None:
        raise Bundle7BDefectError(
            "native_projection_forbidden_content",
            f"{label}: only an authority-free, query-free path without raw identifiers is allowed",
        )


@dataclass(frozen=True, slots=True)
class NativeRequestProjection:
    """Closed redacted ``native_request_projection/v1`` (``additionalProperties: false``)."""

    SCHEMA: ClassVar[str] = NATIVE_REQUEST_PROJECTION_SCHEMA

    endpoint: str
    http_method: str
    endpoint_version_ref: str
    resource_refs: tuple[str, ...]
    date_range: DateRange
    resource_level: str
    metrics: tuple[str, ...]
    breakdowns: tuple[str, ...]
    pagination: str
    currency: str
    attribution_omission_state: str
    integrity: P1Integrity | None = None

    def __post_init__(self) -> None:
        label = "native_request_projection"
        _check_endpoint(self.endpoint)
        if not isinstance(self.http_method, str) or self.http_method not in _HTTP_METHODS:
            raise Bundle7BDefectError("malformed_member", f"{label}.http_method: expected GET or POST")
        self._check_version_ref()
        _sorted_native_array(self.resource_refs, label=f"{label}.resource_refs", check=_canonical_resource_ref, allow_empty=False)
        if not isinstance(self.date_range, DateRange):
            raise Bundle7BDefectError("malformed_member", f"{label}.date_range: expected DateRange")
        _native_name(self.resource_level, label=f"{label}.resource_level")
        for name, allow_empty in (("metrics", False), ("breakdowns", True)):
            _sorted_native_array(
                getattr(self, name),
                label=f"{label}.{name}",
                check=_native_name_checker(f"{label}.{name}"),
                allow_empty=allow_empty,
            )
        _native_name(self.pagination, label=f"{label}.pagination")
        _guard("malformed_member", f"{label}.currency", lambda: validate_currency_iso4217(self.currency, field_name=f"{label}.currency"))
        if self.attribution_omission_state != _ATTRIBUTION_OMITTED:
            raise Bundle7BDefectError("fixed_member_mismatch", f"{label}.attribution_omission_state: must be 'omitted'")
        _check_integrity(self.integrity, self.to_dict, label=label)

    def _check_version_ref(self) -> None:
        _hyphen_ref(
            self.endpoint_version_ref,
            prefixes=_ENDPOINT_VERSION_PREFIXES,
            label="native_request_projection.endpoint_version_ref",
        )

    @property
    def native_request_digest(self) -> str:
        """``sha256:`` over the RFC 8785 bytes of the complete projection."""
        return jcs_sha256(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "$schema": self.SCHEMA,
            "endpoint": self.endpoint,
            "http_method": self.http_method,
            "endpoint_version_ref": self.endpoint_version_ref,
            "resource_refs": list(self.resource_refs),
            "date_range": self.date_range.to_dict(),
            "resource_level": self.resource_level,
            "metrics": list(self.metrics),
            "breakdowns": list(self.breakdowns),
            "pagination": self.pagination,
            "currency": self.currency,
            "attribution_omission_state": self.attribution_omission_state,
        }
        if self.integrity is not None:
            out["integrity"] = self.integrity.to_dict()
        return out

    @classmethod
    def from_dict(cls, data: object) -> NativeRequestProjection:
        label = "native_request_projection"
        mapping = _guard("malformed_member", label, lambda: require_mapping(data, label=label))
        keys = _NATIVE_CORE_KEYS | ({"integrity"} if "integrity" in mapping else set())
        if set(mapping) != keys:
            raise Bundle7BDefectError(
                "native_projection_not_closed",
                f"{label}: missing={sorted(keys - set(mapping))} extra={sorted(set(mapping) - keys)}",
            )
        if mapping["$schema"] != cls.SCHEMA:
            raise Bundle7BDefectError("fixed_member_mismatch", f"{label}.$schema: expected {cls.SCHEMA!r}")
        arrays = {name: _json_array(mapping[name], label=f"{label}.{name}") for name in _NATIVE_ARRAY_MEMBERS}
        scalars = {
            name: mapping[name]
            for name in _NATIVE_CORE_KEYS - {"$schema", "date_range", *_NATIVE_ARRAY_MEMBERS}
        }
        return cls(
            date_range=_guard("malformed_member", f"{label}.date_range", lambda: DateRange.from_dict(mapping["date_range"])),
            integrity=_parse_integrity(mapping, label=label),
            **arrays,
            **scalars,
        )


def _json_array(value: object, *, label: str) -> tuple[Any, ...]:
    if not isinstance(value, list):
        raise Bundle7BDefectError("malformed_member", f"{label}: expected a JSON array")
    return tuple(value)


NativeToCanonicalAlgorithm = Callable[[NativeRequestProjection, str], CanonicalQueryContract]


def check_native_request(
    projection: NativeRequestProjection,
    *,
    native_request_digest: str,
    canonical_query: CanonicalQueryContract,
    algorithm_digest: str,
    project_native_request: NativeToCanonicalAlgorithm,
) -> None:
    """Recompute ``native_request_digest`` and run the injected, digest-pinned projection.

    The resulting complete canonical projection must equal ``canonical_query``
    byte-for-byte; any other result (including a rejection by the algorithm of
    an extra or default-valued native parameter) fails 7B.
    """
    _require_type(projection, NativeRequestProjection, label="native_request_projection")
    _require_type(canonical_query, CanonicalQueryContract, label="canonical_query")
    _sha256(native_request_digest, label="native_request_digest")
    _sha256(algorithm_digest, label="native_to_canonical_projection_algorithm_digest")
    if not callable(project_native_request):
        raise Bundle7BDefectError("malformed_argument", "project_native_request: expected a callable")
    if projection.native_request_digest != native_request_digest:
        raise Bundle7BDefectError("native_request_digest_mismatch", "native_request_digest differs")
    try:
        projected = project_native_request(projection, algorithm_digest)
    except ClosedValidationError as exc:
        raise Bundle7BDefectError("native_projection_mismatch", f"algorithm rejected: {exc}") from exc
    if not isinstance(projected, CanonicalQueryContract) or canonicalize_jcs(
        projected.to_dict()
    ) != canonicalize_jcs(canonical_query.to_dict()):
        raise Bundle7BDefectError(
            "native_projection_mismatch", "projected canonical query is not byte-identical"
        )


# =============================================================================
# ============================  SEAM: SECOND HALF  ============================
# Everything above is self-contained value objects and digests. Everything below
# (tolerance resolution, reconcile_7b_fact_sets, the execution records, the
# certification_7b_record/v1 artifact and the verifier) depends only on it and
# on the shared contracts; it can move verbatim to a sibling module.
# =============================================================================

RECONCILE_OUTCOME_CODES: Final[tuple[str, ...]] = (
    "metric_blocked",
    "metric_unavailable",
    "metric_unreconciled",
    "pair_universe_incomplete",
    "pair_universe_mismatch",
    "retrieval_skew_exceeded",
    "row_universe_mismatch",
)
_STATUS_OUTCOME_CODES: Final[Mapping[str, str]] = MappingProxyType(
    {
        "UNRECONCILED": "metric_unreconciled",
        "UNAVAILABLE": "metric_unavailable",
        "BLOCKED": "metric_blocked",
    }
)
_GATE3_SELECTION_SCHEMA: Final[str] = "smart_ads/gate3_selection_receipt/v1"
_RUN_CONTEXT_SCHEMA: Final[str] = "smart_ads/migration_run_context/v1"
_MICROS_PER_SECOND: Final[int] = 1_000_000


# ---------------------------------------------------------------------------
# Tolerance profile resolution (protected, content addressed, signed and bound)
# ---------------------------------------------------------------------------


def _binding_members(
    *,
    gate3_selection_locator: object,
    canonical_query_digest: object,
    authorized_certification_scope: object,
    migration_run_context_locator: object,
) -> dict[str, Any]:
    """Validate the four binding members (the same-named members of the 7B record)."""
    checks = (
        ("gate3_selection_locator", gate3_selection_locator, _GATE3_SELECTION_SCHEMA),
        ("migration_run_context_locator", migration_run_context_locator, _RUN_CONTEXT_SCHEMA),
    )
    for name, value, artifact_type in checks:
        if not isinstance(value, ArtifactLocator) or value.artifact_type != artifact_type:
            raise Bundle7BDefectError("malformed_argument", f"{name}: expected {artifact_type!r} locator")
    try:
        _sha256(canonical_query_digest, label="canonical_query_digest")
        _scope_ref(authorized_certification_scope, label="authorized_certification_scope")
    except Bundle7BDefectError as exc:
        raise Bundle7BDefectError("malformed_argument", str(exc)) from exc
    return {
        "gate3_selection_locator": gate3_selection_locator,
        "canonical_query_digest": canonical_query_digest,
        "authorized_certification_scope": authorized_certification_scope,
        "migration_run_context_locator": migration_run_context_locator,
    }


def _resolve_profile(
    metric: str, raw: object, binding: Mapping[str, Any]
) -> tuple[ToleranceProfile, ArtifactLocator]:
    label = f"tolerance_profiles[{metric}]"
    parsed = _guard("tolerance_profile_malformed", label, lambda: ToleranceProfile.from_dict(raw))
    if parsed.integrity is None or not parsed.integrity.is_signed:
        raise Bundle7BDefectError("tolerance_profile_unsigned", f"{label}: protected profile must be signed")
    profile = _guard(
        "tolerance_profile_malformed", label, lambda: ToleranceProfile.from_dict(raw, require_signed=True)
    )
    if profile.canonical_metric_ref != metric:
        raise Bundle7BDefectError("tolerance_profile_metric_mismatch", f"{label}: profile closes another metric")
    _guard("tolerance_profile_unbound", label, lambda: profile.require_bound_to(**binding))
    return profile, located(ToleranceProfile.SCHEMA, profile)


def _resolve_profiles(
    tolerance_profiles: object, binding: Mapping[str, Any]
) -> dict[str, tuple[ToleranceProfile, ArtifactLocator]]:
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


# ---------------------------------------------------------------------------
# Per-side universes and reconcile_7b_fact_sets
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _SideUniverse:
    rows: tuple[ReconciliationRowKey, ...]
    pairs: tuple[MetricPairKey, ...]

    @classmethod
    def of(cls, facts: Sequence[NormalizedCollectionFact]) -> _SideUniverse:
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


def _side_facts(result: object, call_side: str) -> tuple[NormalizedCollectionFact, ...]:
    label = f"{call_side}_result"
    _require_type(result, CollectionResult, label=label)
    if result.call_side != call_side:
        raise Bundle7BDefectError("collection_result_mismatch", f"{label}: call_side must be {call_side!r}")
    return _complete_facts(result)


def _within_skew(candidate_at: str, reference_at: str) -> bool:
    cand = _guard("malformed_member", "retrieved_at_utc", lambda: parse_timestamp_utc_micros(candidate_at))
    ref = _guard("malformed_member", "retrieved_at_utc", lambda: parse_timestamp_utc_micros(reference_at))
    return abs(cand - ref) <= MAXIMUM_RETRIEVAL_SKEW_SECONDS * _MICROS_PER_SECOND


def _universe_codes(cand: _SideUniverse, ref: _SideUniverse) -> set[str]:
    codes: set[str] = set()
    if not (cand.is_complete and ref.is_complete):
        codes.add("pair_universe_incomplete")
    if cand.rows != ref.rows:
        codes.add("row_universe_mismatch")
    if cand.pairs != ref.pairs:
        codes.add("pair_universe_mismatch")
    return codes


def _evidence_side(result: CollectionResult, pair: MetricPairKey) -> ReconciliationSide:
    return ReconciliationSide.for_fact(_addressed_fact(result, pair), select_fact_evidence(result, pair))


def _reconcile_pair(
    pair: MetricPairKey,
    candidate_result: CollectionResult,
    reference_result: CollectionResult,
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
        canonical_fact_key_digest=compute_canonical_fact_key_digest(pair.canonical_fact_key),
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


def reconcile_7b_fact_sets(
    *,
    candidate_result: CollectionResult,
    reference_result: CollectionResult,
    tolerance_profiles: Mapping[str, Mapping[str, Any]],
    gate3_selection_locator: ArtifactLocator,
    canonical_query_digest: str,
    authorized_certification_scope: str,
    migration_run_context_locator: ArtifactLocator,
) -> Reconciliation7BResult:
    """Build every ``fact_reconciliation/v1`` from two complete normalized fact sets.

    Malformed evidence or an unresolved, unsigned or unbound tolerance profile
    raises ``Bundle7BDefectError``. Set defects, retrieval skew and comparisons
    that are not ``VERIFIED`` are returned as sorted ``defect_codes`` with
    ``bundle_outcome == "failed"``. Reconciliations cover the required pairs
    present on both sides.
    """
    cand_facts = _side_facts(candidate_result, "candidate")
    ref_facts = _side_facts(reference_result, "reference")
    binding = _binding_members(
        gate3_selection_locator=gate3_selection_locator,
        canonical_query_digest=canonical_query_digest,
        authorized_certification_scope=authorized_certification_scope,
        migration_run_context_locator=migration_run_context_locator,
    )
    profiles = _resolve_profiles(tolerance_profiles, binding)
    cand, ref = _SideUniverse.of(cand_facts), _SideUniverse.of(ref_facts)
    codes = _universe_codes(cand, ref)
    if not _within_skew(
        candidate_result.retrieval_context.retrieved_at_utc,
        reference_result.retrieval_context.retrieved_at_utc,
    ):
        codes.add("retrieval_skew_exceeded")
    common = set(ref.pairs)
    reconciliations = tuple(
        _reconcile_pair(pair, candidate_result, reference_result, profiles[pair.canonical_metric_ref])
        for pair in cand.pairs
        if pair in common and pair.canonical_metric_ref in profiles
    )
    codes |= {
        _STATUS_OUTCOME_CODES[rec.metric_verification_status]
        for rec in reconciliations
        if rec.metric_verification_status != "VERIFIED"
    }
    return Reconciliation7BResult(
        bundle_outcome="failed" if codes or not reconciliations else "verified",
        defect_codes=tuple(sorted(codes)),
        fact_reconciliations=reconciliations,
        logical_fact_reconciliation_digest=(
            compute_logical_fact_reconciliation_digest(reconciliations) if reconciliations else None
        ),
        candidate_row_universe_digest=cand.row_universe_digest,
        reference_row_universe_digest=ref.row_universe_digest,
        candidate_row_count=len(cand.pairs),
        reference_row_count=len(ref.pairs),
    )
