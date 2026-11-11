"""Response-independent U x M completeness verifier (`failed -> partial -> complete`, ADR-0001 §4.2)."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Final, Literal

from smart_ads.contracts.jcs import canonicalize_jcs, sort_utf8_strings
from smart_ads.contracts.scalars import (
    ClosedValidationError,
    require_mapping,
    validate_non_empty_str,
    validate_opaque_ref,
    validate_sha256_prefixed,
)
from smart_ads.contracts.schemas import (
    FactKey,
    NormalizedCollectionFact,
    TransportOutcome,
    compute_normalized_fact_set_digest,
    validate_source_metric_ref,
)
from smart_ads.domain.registry import ExpectedResourceInventory

CompletenessStatus = Literal["failed", "partial", "complete"]

_ALLOWED_STATUSES: Final[frozenset[str]] = frozenset(
    {"failed", "partial", "complete"}
)
_COMPLETE_PERMITTED_PRESENCE_STATUSES: Final[frozenset[str]] = frozenset(
    {"observed", "retracted_tombstone"}
)


@dataclass(frozen=True, slots=True)
class CompletenessEvaluation:
    """Recomputed mutually-exclusive collection completeness evaluation (ADR-0001 §4.2 L610–628)."""

    status: CompletenessStatus
    reasons: tuple[str, ...]
    expected_fact_keys: frozenset[FactKey]
    normalized_fact_set: tuple[NormalizedCollectionFact, ...] | None
    normalized_fact_set_digest: str | None

    def __post_init__(self) -> None:
        if (
            not isinstance(self.status, str)
            or self.status not in _ALLOWED_STATUSES
        ):
            raise ClosedValidationError(
                f"completeness_evaluation.status: invalid status {self.status!r}"
            )
        if not isinstance(self.reasons, (list, tuple)):
            raise ClosedValidationError(
                "completeness_evaluation.reasons: expected list or tuple of strings"
            )
        checked_reasons = tuple(
            validate_non_empty_str(
                r, field_name="completeness_evaluation.reasons"
            )
            for r in self.reasons
        )
        object.__setattr__(self, "reasons", checked_reasons)

        if not isinstance(self.expected_fact_keys, frozenset):
            raise ClosedValidationError(
                "completeness_evaluation.expected_fact_keys: expected frozenset of FactKey"
            )
        for fk in self.expected_fact_keys:
            if not isinstance(fk, FactKey):
                raise ClosedValidationError(
                    "completeness_evaluation.expected_fact_keys: every element must be FactKey"
                )

        if self.status == "complete":
            if len(checked_reasons) != 0:
                raise ClosedValidationError(
                    "completeness_evaluation: complete status requires empty reasons tuple"
                )
            if (
                self.normalized_fact_set is None
                or self.normalized_fact_set_digest is None
            ):
                raise ClosedValidationError(
                    "completeness_evaluation: complete status requires non-null "
                    "normalized_fact_set and normalized_fact_set_digest"
                )
            validate_sha256_prefixed(
                self.normalized_fact_set_digest,
                field_name="completeness_evaluation.normalized_fact_set_digest",
            )
            fact_tuple = tuple(self.normalized_fact_set)
            sorted_facts, recomputed_digest = (
                compute_normalized_fact_set_digest(fact_tuple)
            )
            if (
                fact_tuple != sorted_facts
                or self.normalized_fact_set_digest != recomputed_digest
            ):
                raise ClosedValidationError(
                    "completeness_evaluation: normalized_fact_set must be canonically "
                    "sorted and match normalized_fact_set_digest"
                )
            object.__setattr__(self, "normalized_fact_set", fact_tuple)
        else:
            if len(checked_reasons) == 0:
                raise ClosedValidationError(
                    f"completeness_evaluation: {self.status!r} status requires at least one reason"
                )
            if (
                self.normalized_fact_set is not None
                or self.normalized_fact_set_digest is not None
            ):
                raise ClosedValidationError(
                    f"completeness_evaluation: {self.status!r} status requires "
                    "normalized_fact_set=None and normalized_fact_set_digest=None"
                )


def build_expected_fact_universe(
    *,
    inventory: ExpectedResourceInventory,
    required_metrics: Sequence[str],
    metric_source_mappings: Mapping[str, str],
) -> tuple[FactKey, ...]:
    """Construct complete 9-field `FactKey` universe for `U x M` (ADR-0001 §4.2 L589–609)."""
    if not isinstance(inventory, ExpectedResourceInventory):
        raise ClosedValidationError(
            f"inventory: expected ExpectedResourceInventory, got {type(inventory).__name__}"
        )
    if len(inventory.expected_resources) == 0:
        raise ClosedValidationError(
            "inventory.expected_resources: expected non-empty resource universe U"
        )
    if isinstance(required_metrics, (str, bytes)) or not isinstance(
        required_metrics, Sequence
    ):
        raise ClosedValidationError(
            f"required_metrics: expected Sequence of metric refs, got {type(required_metrics).__name__}"
        )
    sorted_metrics = sort_utf8_strings(
        required_metrics,
        field_name="required_metrics",
        allow_empty=False,
        validator=lambda s: validate_opaque_ref(
            s, field_name="required_metrics", expected_prefix="metric"
        ),
    )
    checked_mappings = require_mapping(
        metric_source_mappings, label="metric_source_mappings"
    )
    resolved_sources: dict[str, str] = {}
    for metric_ref in sorted_metrics:
        if metric_ref not in checked_mappings:
            raise ClosedValidationError(
                f"metric_source_mappings: unmapped metric_semantic_ref {metric_ref!r}"
            )
        source_ref = validate_source_metric_ref(
            checked_mappings[metric_ref],
            field_name="metric_source_mappings.source_metric_ref",
        )
        if not source_ref.startswith("source-metric:provider:"):
            raise ClosedValidationError(
                f"metric_source_mappings: expected provider source_metric_ref for "
                f"{metric_ref!r}, got {source_ref!r}"
            )
        resolved_sources[metric_ref] = source_ref

    universe: list[FactKey] = []
    for u in inventory.expected_resources:
        for metric_ref in sorted_metrics:
            universe.append(
                FactKey(
                    binding_ref=u.binding_ref,
                    account_ref=u.account_ref,
                    resource_ref=u.resource_ref,
                    resource_level=u.resource_level,
                    metric_date=u.metric_date,
                    metric_semantic_ref=metric_ref,
                    source_metric_ref=resolved_sources[metric_ref],
                    attribution_ref=u.attribution_ref,
                    breakdown_signature=u.breakdown_signature,
                )
            )
    return tuple(universe)


def recompute_collection_completeness(
    *,
    admission_succeeded: bool,
    inventory: ExpectedResourceInventory | None,
    required_metrics: Sequence[str],
    metric_source_mappings: Mapping[str, str],
    transport_outcome: TransportOutcome,
    candidate_facts: Sequence[NormalizedCollectionFact],
) -> CompletenessEvaluation:
    """Evaluate mutually-exclusive completeness strictly in order `failed -> partial -> complete`."""
    if not isinstance(admission_succeeded, bool):
        raise ClosedValidationError(
            f"admission_succeeded: expected bool, got {type(admission_succeeded).__name__}"
        )
    if not isinstance(transport_outcome, TransportOutcome):
        raise ClosedValidationError(
            f"transport_outcome: expected TransportOutcome, got {type(transport_outcome).__name__}"
        )
    if isinstance(candidate_facts, (str, bytes)) or not isinstance(
        candidate_facts, Sequence
    ):
        raise ClosedValidationError(
            f"candidate_facts: expected Sequence of NormalizedCollectionFact, "
            f"got {type(candidate_facts).__name__}"
        )
    for item in candidate_facts:
        if not isinstance(item, NormalizedCollectionFact):
            raise ClosedValidationError(
                "candidate_facts: every item must be NormalizedCollectionFact"
            )
    if inventory is not None and not isinstance(
        inventory, ExpectedResourceInventory
    ):
        raise ClosedValidationError(
            f"inventory: expected ExpectedResourceInventory or None, got {type(inventory).__name__}"
        )

    # 1. Evaluate `failed` predicate first
    failed_reasons: list[str] = []
    if not admission_succeeded:
        failed_reasons.append("admission_failed")
    if not transport_outcome.network_ok:
        failed_reasons.append("network_failed")
    if not transport_outcome.auth_ok:
        failed_reasons.append("auth_failed")
    if not transport_outcome.media_and_encoding_valid:
        failed_reasons.append("media_or_encoding_invalid")
    if transport_outcome.jsonrpc_error:
        failed_reasons.append("jsonrpc_error")
    if (
        transport_outcome.http_status is not None
        and transport_outcome.http_status != 200
    ):
        failed_reasons.append(f"http_status_{transport_outcome.http_status}")

    expected_set: frozenset[FactKey] = frozenset()
    if inventory is None:
        failed_reasons.append("missing_expected_inventory")
    elif len(inventory.expected_resources) == 0:
        failed_reasons.append("empty_expected_inventory")
    else:
        try:
            universe = build_expected_fact_universe(
                inventory=inventory,
                required_metrics=required_metrics,
                metric_source_mappings=metric_source_mappings,
            )
            expected_set = frozenset(universe)
        except ClosedValidationError:
            failed_reasons.append("invalid_expected_fact_universe")

    if failed_reasons:
        return CompletenessEvaluation(
            status="failed",
            reasons=tuple(failed_reasons),
            expected_fact_keys=expected_set,
            normalized_fact_set=None,
            normalized_fact_set_digest=None,
        )

    # 2. Evaluate `partial` predicate iff `failed` is false
    partial_reasons: list[str] = []
    if not transport_outcome.payload_schema_valid:
        partial_reasons.append("payload_schema_invalid")
    if transport_outcome.response_date_mismatch:
        partial_reasons.append("response_date_mismatch")
    if transport_outcome.truncated_2mib:
        partial_reasons.append("truncated_2mib")
    if transport_outcome.non_empty_continuation:
        partial_reasons.append("non_empty_continuation")
    if transport_outcome.reducer_order_or_count_mismatch:
        partial_reasons.append("reducer_order_or_count_mismatch")
    if transport_outcome.duplicate_provider_observation:
        partial_reasons.append("duplicate_provider_observation")

    seen_fact_keys: set[FactKey] = set()
    seen_identities: set[bytes] = set()
    has_duplicate = False
    non_complete_presences: list[str] = []
    seen_non_complete_presences: set[str] = set()

    for fact in candidate_facts:
        identity_bytes = canonicalize_jcs(fact.fact_key.set_identity_array())
        if fact.fact_key in seen_fact_keys or identity_bytes in seen_identities:
            has_duplicate = True
        seen_fact_keys.add(fact.fact_key)
        seen_identities.add(identity_bytes)

        if fact.presence_status not in _COMPLETE_PERMITTED_PRESENCE_STATUSES:
            if fact.presence_status not in seen_non_complete_presences:
                seen_non_complete_presences.add(fact.presence_status)
                non_complete_presences.append(fact.presence_status)

    if has_duplicate:
        partial_reasons.append("duplicate_candidate_fact_key")

    missing_keys = expected_set - seen_fact_keys
    extra_keys = seen_fact_keys - expected_set
    if missing_keys:
        partial_reasons.append("missing_expected_fact_keys")
    if extra_keys:
        partial_reasons.append("unexpected_observed_fact_keys")

    for status_name in non_complete_presences:
        partial_reasons.append(f"non_complete_presence_status:{status_name}")

    if partial_reasons:
        return CompletenessEvaluation(
            status="partial",
            reasons=tuple(partial_reasons),
            expected_fact_keys=expected_set,
            normalized_fact_set=None,
            normalized_fact_set_digest=None,
        )

    # 3. `complete`: `failed` and `partial` are false, exact 1-to-1 equality with `U x M`
    sorted_facts, digest = compute_normalized_fact_set_digest(candidate_facts)
    return CompletenessEvaluation(
        status="complete",
        reasons=(),
        expected_fact_keys=expected_set,
        normalized_fact_set=sorted_facts,
        normalized_fact_set_digest=digest,
    )


__all__ = [
    "CompletenessEvaluation",
    "CompletenessStatus",
    "build_expected_fact_universe",
    "recompute_collection_completeness",
]
