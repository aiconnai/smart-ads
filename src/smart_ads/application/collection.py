"""Purpose-discriminated collection orchestration (`collect`, `evaluate_fixture_collection`, `execute_admitted_call`)."""
from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Final

from smart_ads.application.admission import (
    AdmissionError,
    AdmittedCollectionBundle,
    admit_collection,
)
from smart_ads.application.completeness import (
    CompletenessEvaluation,
    recompute_collection_completeness,
)
from smart_ads.contracts.jcs import (
    ADR_P1_DOMAIN_PREFIXES,
    ArtifactLocator,
    canonicalize_jcs,
)
from smart_ads.contracts.numerics import PHASE1_BASE_METRICS
from smart_ads.contracts.scalars import ClosedValidationError
from smart_ads.contracts.schemas import (
    AdmittedCollection,
    AnalyticsLandingRow,
    CallSide,
    CollectionRequest,
    CollectionResult,
    FactKey,
    NormalizedCollectionFact,
    TransportOutcome,
    project_collection_fact_to_landing_row,
)
from smart_ads.domain.registry import ExpectedResourceInventory
from smart_ads.ports.cell_runtime import (
    CellRuntimePorts,
    EnvelopeSignerPort,
    ExpectedInventoryPort,
    ReservationPort,
)
from smart_ads.ports.provider import (
    AdmittedFixtureCall,
    AdmittedProviderCall,
    ExternalIOCounters,
    FixtureObservationPort,
    ProviderObservationBatch,
    ProviderPort,
)

_RESERVATION_RECORD_SCHEMA: Final[str] = (
    "smart_ads/authorization_reservation_record/v1"
)
_ALLOWED_CALL_SIDES: Final[frozenset[str]] = frozenset(
    {"candidate", "reference", "operational"}
)


class PurposeEntrypointMismatchError(ClosedValidationError):
    """Raised when a collection entrypoint is called with an incompatible purpose or call_side."""


@dataclass(frozen=True, slots=True)
class LiveCallExecutionOutcome:
    """Outcome of one reserved live provider call (`candidate`, `reference`, or `operational`)."""

    result: CollectionResult
    result_locator: ArtifactLocator
    completeness: CompletenessEvaluation
    io_counters: ExternalIOCounters

    def __post_init__(self) -> None:
        if not isinstance(self.result, CollectionResult):
            raise ClosedValidationError(
                "live_call_execution_outcome.result: expected CollectionResult"
            )
        if (
            not isinstance(self.result_locator, ArtifactLocator)
            or self.result_locator.artifact_type != CollectionResult.SCHEMA
        ):
            raise ClosedValidationError(
                "live_call_execution_outcome.result_locator: expected ArtifactLocator "
                f"for {CollectionResult.SCHEMA!r}"
            )
        if not isinstance(self.completeness, CompletenessEvaluation):
            raise ClosedValidationError(
                "live_call_execution_outcome.completeness: expected CompletenessEvaluation"
            )
        if not isinstance(self.io_counters, ExternalIOCounters):
            raise ClosedValidationError(
                "live_call_execution_outcome.io_counters: expected ExternalIOCounters"
            )
        if (
            self.result.normalized_fact_set
            != self.completeness.normalized_fact_set
            or self.result.normalized_fact_set_digest
            != self.completeness.normalized_fact_set_digest
        ):
            raise ClosedValidationError(
                "live_call_execution_outcome: CollectionResult normalized_fact_set "
                "must agree with CompletenessEvaluation"
            )


@dataclass(frozen=True, slots=True)
class FixtureCollectionEvaluation:
    """Offline 7A fixture evaluation with zero live `call_side` and zero external I/O counters."""

    admitted: AdmittedCollection
    admitted_locator: ArtifactLocator
    candidates: tuple[AnalyticsLandingRow, ...]
    completeness: CompletenessEvaluation
    io_counters: ExternalIOCounters

    def __post_init__(self) -> None:
        if (
            not isinstance(self.admitted, AdmittedCollection)
            or self.admitted.collection_purpose != "fixture_7a"
        ):
            raise ClosedValidationError(
                "fixture_collection_evaluation.admitted: expected AdmittedCollection "
                "with collection_purpose == 'fixture_7a'"
            )
        if (
            not isinstance(self.admitted_locator, ArtifactLocator)
            or self.admitted_locator.artifact_type != AdmittedCollection.SCHEMA
        ):
            raise ClosedValidationError(
                "fixture_collection_evaluation.admitted_locator: expected "
                f"ArtifactLocator for {AdmittedCollection.SCHEMA!r}"
            )
        if not isinstance(self.candidates, (list, tuple)):
            raise ClosedValidationError(
                "fixture_collection_evaluation.candidates: expected list or tuple"
            )
        for row in self.candidates:
            if not isinstance(row, AnalyticsLandingRow):
                raise ClosedValidationError(
                    "fixture_collection_evaluation.candidates: every element "
                    "must be AnalyticsLandingRow"
                )
        sorted_candidates = tuple(
            sorted(self.candidates, key=lambda r: r.candidate_sort_key_jcs())
        )
        object.__setattr__(self, "candidates", sorted_candidates)

        if not isinstance(self.completeness, CompletenessEvaluation):
            raise ClosedValidationError(
                "fixture_collection_evaluation.completeness: expected CompletenessEvaluation"
            )
        if (
            not isinstance(self.io_counters, ExternalIOCounters)
            or not self.io_counters.is_zero
        ):
            raise ClosedValidationError(
                "fixture_collection_evaluation.io_counters: offline 7A evaluation "
                "requires all ExternalIOCounters equal to zero"
            )


def _reduce_batch_to_candidates_and_completeness(
    *,
    bundle: AdmittedCollectionBundle,
    batch: ProviderObservationBatch,
    inventory_port: ExpectedInventoryPort,
) -> tuple[
    TransportOutcome,
    tuple[AnalyticsLandingRow, ...],
    CompletenessEvaluation,
]:
    if not isinstance(batch, ProviderObservationBatch):
        raise ClosedValidationError(
            f"batch: expected ProviderObservationBatch, got {type(batch).__name__}"
        )
    admitted = bundle.admitted
    if not isinstance(inventory_port, ExpectedInventoryPort):
        inventory: ExpectedResourceInventory | None = None
    else:
        try:
            resolved_inv = inventory_port.resolve_expected_inventory(
                registry_snapshot_locator=admitted.registry_snapshot_locator,
                tenant_ref=admitted.tenant_ref,
                binding_ref=admitted.binding_ref,
                account_ref=admitted.account_ref,
                resource_scope_ref=admitted.resource_scope_ref,
                date_range=admitted.computed_date_range,
            )
        except ClosedValidationError:
            resolved_inv = None
        inventory = (
            resolved_inv
            if isinstance(resolved_inv, ExpectedResourceInventory)
            else None
        )
    if inventory is not None and (
        inventory.registry_snapshot_locator != admitted.registry_snapshot_locator
        or inventory.tenant_ref != admitted.tenant_ref
        or inventory.binding_ref != admitted.binding_ref
        or inventory.account_ref != admitted.account_ref
        or inventory.resource_scope_ref != admitted.resource_scope_ref
        or inventory.date_range != admitted.computed_date_range
    ):
        inventory = None

    admitted_day = admitted.computed_date_range.start_date
    date_mismatch_detected = False
    unmapped_metric_detected = False
    candidate_facts: list[NormalizedCollectionFact] = []
    candidate_rows: list[AnalyticsLandingRow] = []

    for resource_obs in batch.resource_observations:
        if resource_obs.metric_date != admitted_day:
            date_mismatch_detected = True
        for metric_obs in resource_obs.metric_observations:
            source_metric_ref = bundle.driver_contract.metric_source_mappings.get(
                metric_obs.metric_semantic_ref
            )
            if (
                source_metric_ref is None
                or metric_obs.metric_semantic_ref not in PHASE1_BASE_METRICS
            ):
                unmapped_metric_detected = True
                continue
            fact_key = FactKey(
                binding_ref=admitted.binding_ref,
                account_ref=admitted.account_ref,
                resource_ref=resource_obs.resource_ref,
                resource_level=admitted.resource_level,
                metric_date=resource_obs.metric_date,
                metric_semantic_ref=metric_obs.metric_semantic_ref,
                source_metric_ref=source_metric_ref,
                attribution_ref="attribution:not_applicable",
                breakdown_signature="breakdown:none",
            )
            fact = NormalizedCollectionFact(
                fact_key=fact_key,
                presence_status=metric_obs.presence_status,
                value_type=metric_obs.value_type,
                raw_numeric_value=metric_obs.raw_numeric_value,
                unit=metric_obs.unit,
                currency=metric_obs.currency,
            )
            row = project_collection_fact_to_landing_row(
                fact,
                batch.retrieval_context,
                query_currency=admitted.currency,
            )
            candidate_facts.append(fact)
            candidate_rows.append(row)

    effective_transport = batch.transport_outcome
    if (
        date_mismatch_detected
        and not effective_transport.response_date_mismatch
    ):
        effective_transport = replace(
            effective_transport, response_date_mismatch=True
        )
    if (
        unmapped_metric_detected
        and not effective_transport.reducer_order_or_count_mismatch
    ):
        effective_transport = replace(
            effective_transport, reducer_order_or_count_mismatch=True
        )

    sorted_candidates = tuple(
        sorted(candidate_rows, key=lambda r: r.candidate_sort_key_jcs())
    )
    completeness = recompute_collection_completeness(
        admission_succeeded=True,
        inventory=inventory,
        required_metrics=admitted.canonical_query_contract.metric_semantic_refs,
        metric_source_mappings=bundle.driver_contract.metric_source_mappings,
        transport_outcome=effective_transport,
        candidate_facts=candidate_facts,
    )
    return effective_transport, sorted_candidates, completeness


def execute_admitted_call(
    *,
    bundle: AdmittedCollectionBundle,
    call_side: CallSide,
    reservation_locator: ArtifactLocator,
    provider_port: ProviderPort,
    inventory_port: ExpectedInventoryPort,
    signer_port: EnvelopeSignerPort | None = None,
) -> LiveCallExecutionOutcome:
    """Execute one pre-reserved live call (`candidate`, `reference`, or `operational`)."""
    if not isinstance(bundle, AdmittedCollectionBundle):
        raise ClosedValidationError(
            f"bundle: expected AdmittedCollectionBundle, got {type(bundle).__name__}"
        )
    if not isinstance(call_side, str) or call_side not in _ALLOWED_CALL_SIDES:
        raise PurposeEntrypointMismatchError(
            f"execute_admitted_call: invalid call_side {call_side!r}"
        )

    purpose = bundle.admitted.collection_purpose
    if purpose == "fixture_7a":
        raise PurposeEntrypointMismatchError(
            "execute_admitted_call: fixture_7a forbids live provider calls"
        )
    if purpose == "live_verification_7b" and call_side not in {
        "candidate",
        "reference",
    }:
        raise PurposeEntrypointMismatchError(
            "execute_admitted_call: live_verification_7b requires "
            f"call_side in {{'candidate', 'reference'}}, got {call_side!r}"
        )
    if purpose == "operational_read" and call_side != "operational":
        raise PurposeEntrypointMismatchError(
            "execute_admitted_call: operational_read requires "
            f"call_side == 'operational', got {call_side!r}"
        )

    if (
        not isinstance(reservation_locator, ArtifactLocator)
        or reservation_locator.artifact_type != _RESERVATION_RECORD_SCHEMA
    ):
        raise ClosedValidationError(
            "execute_admitted_call.reservation_locator: expected ArtifactLocator "
            f"for {_RESERVATION_RECORD_SCHEMA!r}"
        )
    if not isinstance(provider_port, ProviderPort):
        raise ClosedValidationError(
            f"execute_admitted_call.provider_port: expected ProviderPort, got {type(provider_port).__name__}"
        )
    if not isinstance(inventory_port, ExpectedInventoryPort):
        raise ClosedValidationError(
            f"execute_admitted_call.inventory_port: expected ExpectedInventoryPort, got {type(inventory_port).__name__}"
        )
    if signer_port is not None and not isinstance(
        signer_port, EnvelopeSignerPort
    ):
        raise ClosedValidationError(
            f"execute_admitted_call.signer_port: expected EnvelopeSignerPort or None, got {type(signer_port).__name__}"
        )

    admitted = bundle.admitted
    provider_call = AdmittedProviderCall(
        admitted_collection_locator=bundle.locator,
        admitted_collection_digest=bundle.locator.content_digest,
        call_side=call_side,
        driver_id=admitted.driver_id,
        driver_contract_digest=admitted.driver_contract_digest,
        canonical_query=admitted.canonical_query_contract,
        reservation_locator=reservation_locator,
    )
    batch = provider_port.fetch_observations(provider_call)
    effective_transport, sorted_candidates, completeness = (
        _reduce_batch_to_candidates_and_completeness(
            bundle=bundle,
            batch=batch,
            inventory_port=inventory_port,
        )
    )

    result = CollectionResult(
        admitted_collection_locator=bundle.locator,
        admitted_collection_digest=bundle.locator.content_digest,
        call_side=call_side,
        registry_snapshot_locator=admitted.registry_snapshot_locator,
        registry_snapshot_digest=admitted.registry_snapshot_digest,
        requested_capabilities=admitted.requested_capabilities,
        observed_capabilities=batch.observed_capabilities,
        retrieval_context=batch.retrieval_context,
        transport_outcome=effective_transport,
        candidates=sorted_candidates,
        normalized_fact_set=completeness.normalized_fact_set,
        normalized_fact_set_digest=completeness.normalized_fact_set_digest,
        normalized_errors=batch.normalized_errors,
    )

    if signer_port is not None:
        unsigned_result = result
        domain_prefix = ADR_P1_DOMAIN_PREFIXES[CollectionResult.SCHEMA]
        sign_out = signer_port.sign_and_store(
            unsigned_result.to_dict(), domain_prefix=domain_prefix
        )
        if not isinstance(sign_out, tuple) or len(sign_out) != 2:
            raise ClosedValidationError(
                "execute_admitted_call: signer_port.sign_and_store must return "
                "a 2-tuple of (signed_dict, ArtifactLocator)"
            )
        signed_dict, result_locator = sign_out
        result = CollectionResult.from_dict(signed_dict, require_signed=True)
        if replace(result, integrity=None) != unsigned_result:
            raise ClosedValidationError(
                "execute_admitted_call: signer_port mutated CollectionResult "
                "payload fields outside integrity"
            )
        expected_loc = ArtifactLocator.for_canonical_bytes(
            CollectionResult.SCHEMA,
            canonicalize_jcs(result.to_dict()),
        )
        if result_locator != expected_loc:
            raise ClosedValidationError(
                "execute_admitted_call: signer_port returned an ArtifactLocator "
                "inconsistent with signed CollectionResult"
            )
    else:
        result_locator = ArtifactLocator.for_canonical_bytes(
            CollectionResult.SCHEMA,
            canonicalize_jcs(result.to_dict()),
        )

    return LiveCallExecutionOutcome(
        result=result,
        result_locator=result_locator,
        completeness=completeness,
        io_counters=batch.io_counters,
    )


def evaluate_fixture_collection(
    request: CollectionRequest,
    *,
    admission_id: str,
    cell_ports: CellRuntimePorts,
    fixture_port: FixtureObservationPort,
    inventory_port: ExpectedInventoryPort,
) -> FixtureCollectionEvaluation:
    """Admit and evaluate an offline `fixture_7a` collection with zero live call_side or I/O."""
    if not isinstance(request, CollectionRequest):
        raise ClosedValidationError(
            f"request: expected CollectionRequest, got {type(request).__name__}"
        )
    if request.collection_purpose != "fixture_7a":
        raise PurposeEntrypointMismatchError(
            "evaluate_fixture_collection requires collection_purpose == 'fixture_7a', "
            f"got {request.collection_purpose!r}"
        )

    bundle = admit_collection(request, cell_ports, admission_id=admission_id)
    regression_fixture_locator = (
        bundle.admitted.purpose_prerequisite_locators.regression_fixture_locator
    )
    if regression_fixture_locator is None:
        raise ClosedValidationError(
            "evaluate_fixture_collection: admitted fixture_7a collection is "
            "missing regression_fixture_locator"
        )

    fixture_call = AdmittedFixtureCall(
        admitted_collection_locator=bundle.locator,
        admitted_collection_digest=bundle.locator.content_digest,
        driver_id=bundle.admitted.driver_id,
        driver_contract_digest=bundle.admitted.driver_contract_digest,
        canonical_query=bundle.admitted.canonical_query_contract,
        regression_fixture_locator=regression_fixture_locator,
    )
    batch = fixture_port.load_fixture_observations(fixture_call)
    if not isinstance(batch, ProviderObservationBatch):
        raise ClosedValidationError(
            f"fixture_port: expected ProviderObservationBatch, got {type(batch).__name__}"
        )
    if not batch.io_counters.is_zero:
        raise ClosedValidationError(
            "evaluate_fixture_collection: offline 7A batch violated zero-I/O invariant"
        )

    _, sorted_candidates, completeness = (
        _reduce_batch_to_candidates_and_completeness(
            bundle=bundle,
            batch=batch,
            inventory_port=inventory_port,
        )
    )
    return FixtureCollectionEvaluation(
        admitted=bundle.admitted,
        admitted_locator=bundle.locator,
        candidates=sorted_candidates,
        completeness=completeness,
        io_counters=batch.io_counters,
    )


def collect(
    request: CollectionRequest,
    *,
    admission_id: str,
    cell_ports: CellRuntimePorts,
    reservation_port: ReservationPort,
    provider_port: ProviderPort,
    inventory_port: ExpectedInventoryPort,
) -> CollectionResult:
    """Admit, reserve, and execute an `operational_read` collection (ADR-0001 §4.2 L388)."""
    if not isinstance(request, CollectionRequest):
        raise AdmissionError(
            "invalid_request",
            f"expected CollectionRequest, got {type(request).__name__}",
            counters=ExternalIOCounters.zero(),
        )
    if request.collection_purpose != "operational_read":
        raise PurposeEntrypointMismatchError(
            f"collect requires collection_purpose == 'operational_read', "
            f"got {request.collection_purpose!r}"
        )
    if (
        not isinstance(reservation_port, ReservationPort)
        or not isinstance(provider_port, ProviderPort)
        or not isinstance(inventory_port, ExpectedInventoryPort)
    ):
        raise AdmissionError(
            "invalid_collection_ports",
            "collect requires valid ReservationPort, ProviderPort, and ExpectedInventoryPort",
            counters=ExternalIOCounters.zero(),
        )

    bundle = admit_collection(request, cell_ports, admission_id=admission_id)
    try:
        reservation_locator = reservation_port.reserve_admitted_call(
            admitted_collection_locator=bundle.locator,
            call_side="operational",
        )
    except AdmissionError:
        raise
    except ClosedValidationError as exc:
        raise AdmissionError(
            "reservation_failed",
            str(exc),
            counters=ExternalIOCounters.zero(),
        ) from exc

    if (
        not isinstance(reservation_locator, ArtifactLocator)
        or reservation_locator.artifact_type != _RESERVATION_RECORD_SCHEMA
    ):
        raise AdmissionError(
            "invalid_reservation_locator",
            f"expected ArtifactLocator for {_RESERVATION_RECORD_SCHEMA!r}",
            counters=ExternalIOCounters.zero(),
        )

    outcome = execute_admitted_call(
        bundle=bundle,
        call_side="operational",
        reservation_locator=reservation_locator,
        provider_port=provider_port,
        inventory_port=inventory_port,
        signer_port=cell_ports.signer_port,
    )
    return outcome.result


__all__ = [
    "FixtureCollectionEvaluation",
    "LiveCallExecutionOutcome",
    "PurposeEntrypointMismatchError",
    "collect",
    "evaluate_fixture_collection",
    "execute_admitted_call",
]
