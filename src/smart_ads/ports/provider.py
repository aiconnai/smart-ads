"""Zero-I/O ProviderPort, offline 7A FixtureObservationPort, and sanitized observation batches (ADR-0001 §§4.1, 4.2)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Final, Protocol, runtime_checkable

from smart_ads.contracts.jcs import (
    MAX_JCS_SAFE_INT,
    ArtifactLocator,
    sort_utf8_strings,
)
from smart_ads.contracts.numerics import (
    PHASE1_BASE_METRICS,
    PROVIDER_PRESENCE_TO_UNKNOWN_REASON,
    ProviderPresenceStatus,
    UnitType,
    ValueType,
    validate_numeric_state,
)
from smart_ads.contracts.scalars import (
    ClosedValidationError,
    require_exact_keys,
    validate_iso_date,
    validate_non_empty_str,
    validate_opaque_ref,
    validate_sha256_prefixed,
)
from smart_ads.contracts.schemas import (
    AdmittedCollection,
    CallSide,
    CanonicalQueryContract,
    NormalizedProviderError,
    RetrievalContext,
    TransportOutcome,
)
from smart_ads.domain.resource_ref import validate_resource_ref

_ALLOWED_CALL_SIDES: Final[frozenset[str]] = frozenset(
    {"candidate", "reference", "operational"}
)
_RESERVATION_RECORD_SCHEMA: Final[str] = (
    "smart_ads/authorization_reservation_record/v1"
)
_REGRESSION_FIXTURE_SCHEMA: Final[str] = "smart_ads/regression_fixture/v1"

_IO_COUNTERS_KEYS: Final[frozenset[str]] = frozenset(
    {
        "credential_lookups",
        "token_decryptions",
        "socket_creations",
        "provider_rpc_calls",
    }
)
_SANITIZED_METRIC_OBS_KEYS: Final[frozenset[str]] = frozenset(
    {
        "metric_semantic_ref",
        "presence_status",
        "value_type",
        "raw_numeric_value",
        "unit",
        "currency",
    }
)
_SANITIZED_RESOURCE_OBS_KEYS: Final[frozenset[str]] = frozenset(
    {
        "resource_ref",
        "metric_date",
        "metric_observations",
    }
)
_ADMITTED_PROVIDER_CALL_KEYS: Final[frozenset[str]] = frozenset(
    {
        "admitted_collection_locator",
        "admitted_collection_digest",
        "call_side",
        "driver_id",
        "driver_contract_digest",
        "canonical_query",
        "reservation_locator",
    }
)
_ADMITTED_FIXTURE_CALL_KEYS: Final[frozenset[str]] = frozenset(
    {
        "admitted_collection_locator",
        "admitted_collection_digest",
        "driver_id",
        "driver_contract_digest",
        "canonical_query",
        "regression_fixture_locator",
    }
)
_PROVIDER_OBSERVATION_BATCH_KEYS: Final[frozenset[str]] = frozenset(
    {
        "observed_capabilities",
        "retrieval_context",
        "transport_outcome",
        "resource_observations",
        "normalized_errors",
        "io_counters",
    }
)


def _validate_non_negative_counter(value: object, *, field_name: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not (0 <= value <= MAX_JCS_SAFE_INT)
    ):
        raise ClosedValidationError(
            f"{field_name}: expected non-negative safe int, got {value!r}"
        )
    return value


def _validate_driver_id(value: object, *, field_name: str) -> str:
    checked = validate_non_empty_str(value, field_name=field_name)
    if any(ch.isspace() for ch in checked):
        raise ClosedValidationError(f"{field_name}: whitespace is forbidden")
    return checked


def _require_typed_locator(
    value: object,
    *,
    field_name: str,
    expected_type: str,
) -> ArtifactLocator:
    if not isinstance(value, ArtifactLocator):
        raise ClosedValidationError(
            f"{field_name}: expected ArtifactLocator, got {type(value).__name__}"
        )
    if value.artifact_type != expected_type:
        raise ClosedValidationError(
            f"{field_name}: expected artifact_type {expected_type!r}, "
            f"got {value.artifact_type!r}"
        )
    return value


@dataclass(frozen=True, slots=True)
class ExternalIOCounters:
    """Closed 4-field external I/O counter tuple (ADR-0001 §4.2 L506, L515–516)."""

    credential_lookups: int = 0
    token_decryptions: int = 0
    socket_creations: int = 0
    provider_rpc_calls: int = 0

    def __post_init__(self) -> None:
        _validate_non_negative_counter(
            self.credential_lookups,
            field_name="external_io_counters.credential_lookups",
        )
        _validate_non_negative_counter(
            self.token_decryptions,
            field_name="external_io_counters.token_decryptions",
        )
        _validate_non_negative_counter(
            self.socket_creations,
            field_name="external_io_counters.socket_creations",
        )
        _validate_non_negative_counter(
            self.provider_rpc_calls,
            field_name="external_io_counters.provider_rpc_calls",
        )

    @classmethod
    def zero(cls) -> ExternalIOCounters:
        """Return an `ExternalIOCounters` instance with all four counters set to zero."""
        return cls()

    @property
    def is_zero(self) -> bool:
        """Return True iff every external I/O counter equals zero."""
        return (
            self.credential_lookups == 0
            and self.token_decryptions == 0
            and self.socket_creations == 0
            and self.provider_rpc_calls == 0
        )

    def to_dict(self) -> dict[str, int]:
        return {
            "credential_lookups": self.credential_lookups,
            "token_decryptions": self.token_decryptions,
            "socket_creations": self.socket_creations,
            "provider_rpc_calls": self.provider_rpc_calls,
        }

    @classmethod
    def from_dict(cls, data: object) -> ExternalIOCounters:
        mapping = require_exact_keys(
            data, _IO_COUNTERS_KEYS, label="external_io_counters"
        )
        return cls(
            credential_lookups=mapping["credential_lookups"],
            token_decryptions=mapping["token_decryptions"],
            socket_creations=mapping["socket_creations"],
            provider_rpc_calls=mapping["provider_rpc_calls"],
        )


@dataclass(frozen=True, slots=True)
class SanitizedMetricObservation:
    """Narrow sanitized metric observation crossing `ProviderPort` (ADR-0001 §§4.1, 4.3)."""

    metric_semantic_ref: str
    presence_status: ProviderPresenceStatus
    value_type: ValueType | None
    raw_numeric_value: str | None
    unit: UnitType | None
    currency: str | None

    def __post_init__(self) -> None:
        validate_opaque_ref(
            self.metric_semantic_ref,
            field_name="sanitized_metric_observation.metric_semantic_ref",
            expected_prefix="metric",
        )
        if (
            not isinstance(self.presence_status, str)
            or self.presence_status not in PROVIDER_PRESENCE_TO_UNKNOWN_REASON
        ):
            raise ClosedValidationError(
                "sanitized_metric_observation.presence_status: invalid provider "
                f"presence_status {self.presence_status!r}"
            )
        validate_numeric_state(
            metric_origin="provider_observation",
            presence_status=self.presence_status,
            calculation_status="not_applicable",
            unknown_reason=PROVIDER_PRESENCE_TO_UNKNOWN_REASON[self.presence_status],
            value_type=self.value_type,
            raw_numeric_value=self.raw_numeric_value,
            unit=self.unit,
            currency=self.currency,
            query_currency="BRL",
        )
        defn = PHASE1_BASE_METRICS.get(self.metric_semantic_ref)
        if defn is not None and self.value_type is not None:
            if self.value_type != defn.value_type or self.unit != defn.unit:
                raise ClosedValidationError(
                    f"sanitized_metric_observation: {self.metric_semantic_ref!r} requires "
                    f"(value_type={defn.value_type!r}, unit={defn.unit!r}), "
                    f"got (value_type={self.value_type!r}, unit={self.unit!r})"
                )
            if defn.currency_rule == "must_be_null" and self.currency is not None:
                raise ClosedValidationError(
                    f"sanitized_metric_observation: {self.metric_semantic_ref!r} "
                    "requires currency=None"
                )
            if (
                defn.currency_rule == "must_be_query_currency"
                and self.currency != "BRL"
            ):
                raise ClosedValidationError(
                    f"sanitized_metric_observation: {self.metric_semantic_ref!r} "
                    "requires currency='BRL'"
                )

    def to_dict(self) -> dict[str, Any]:
        return {
            "metric_semantic_ref": self.metric_semantic_ref,
            "presence_status": self.presence_status,
            "value_type": self.value_type,
            "raw_numeric_value": self.raw_numeric_value,
            "unit": self.unit,
            "currency": self.currency,
        }

    @classmethod
    def from_dict(cls, data: object) -> SanitizedMetricObservation:
        mapping = require_exact_keys(
            data,
            _SANITIZED_METRIC_OBS_KEYS,
            label="sanitized_metric_observation",
        )
        return cls(
            metric_semantic_ref=mapping["metric_semantic_ref"],
            presence_status=mapping["presence_status"],
            value_type=mapping["value_type"],
            raw_numeric_value=mapping["raw_numeric_value"],
            unit=mapping["unit"],
            currency=mapping["currency"],
        )


@dataclass(frozen=True, slots=True)
class SanitizedResourceObservation:
    """Narrow resource observation tuple with zero raw provider IDs, URLs, headers, or tokens."""

    resource_ref: str
    metric_date: str
    metric_observations: tuple[SanitizedMetricObservation, ...]

    def __post_init__(self) -> None:
        validate_resource_ref(
            self.resource_ref,
            field_name="sanitized_resource_observation.resource_ref",
        )
        validate_iso_date(
            self.metric_date,
            field_name="sanitized_resource_observation.metric_date",
        )
        if not isinstance(self.metric_observations, (list, tuple)):
            raise ClosedValidationError(
                "sanitized_resource_observation.metric_observations: expected list or tuple"
            )
        for item in self.metric_observations:
            if not isinstance(item, SanitizedMetricObservation):
                raise ClosedValidationError(
                    "sanitized_resource_observation.metric_observations: every item "
                    "must be SanitizedMetricObservation"
                )
        object.__setattr__(
            self, "metric_observations", tuple(self.metric_observations)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "resource_ref": self.resource_ref,
            "metric_date": self.metric_date,
            "metric_observations": [
                obs.to_dict() for obs in self.metric_observations
            ],
        }

    @classmethod
    def from_dict(cls, data: object) -> SanitizedResourceObservation:
        mapping = require_exact_keys(
            data,
            _SANITIZED_RESOURCE_OBS_KEYS,
            label="sanitized_resource_observation",
        )
        if not isinstance(mapping["metric_observations"], list):
            raise ClosedValidationError(
                "sanitized_resource_observation.metric_observations: expected JSON array list"
            )
        return cls(
            resource_ref=mapping["resource_ref"],
            metric_date=mapping["metric_date"],
            metric_observations=tuple(
                SanitizedMetricObservation.from_dict(item)
                for item in mapping["metric_observations"]
            ),
        )


@dataclass(frozen=True, slots=True)
class AdmittedProviderCall:
    """Immutable admitted provider call descriptor bound to a pre-I/O reservation locator."""

    admitted_collection_locator: ArtifactLocator
    admitted_collection_digest: str
    call_side: CallSide
    driver_id: str
    driver_contract_digest: str
    canonical_query: CanonicalQueryContract
    reservation_locator: ArtifactLocator

    def __post_init__(self) -> None:
        _require_typed_locator(
            self.admitted_collection_locator,
            field_name="admitted_provider_call.admitted_collection_locator",
            expected_type=AdmittedCollection.SCHEMA,
        )
        validate_sha256_prefixed(
            self.admitted_collection_digest,
            field_name="admitted_provider_call.admitted_collection_digest",
        )
        if (
            self.admitted_collection_digest
            != self.admitted_collection_locator.content_digest
        ):
            raise ClosedValidationError(
                "admitted_provider_call.admitted_collection_digest: must equal "
                "admitted_collection_locator.content_digest"
            )
        if (
            not isinstance(self.call_side, str)
            or self.call_side not in _ALLOWED_CALL_SIDES
        ):
            raise ClosedValidationError(
                f"admitted_provider_call.call_side: expected one of "
                f"{sorted(_ALLOWED_CALL_SIDES)}, got {self.call_side!r}"
            )
        _validate_driver_id(
            self.driver_id, field_name="admitted_provider_call.driver_id"
        )
        validate_sha256_prefixed(
            self.driver_contract_digest,
            field_name="admitted_provider_call.driver_contract_digest",
        )
        if not isinstance(self.canonical_query, CanonicalQueryContract):
            raise ClosedValidationError(
                "admitted_provider_call.canonical_query: expected CanonicalQueryContract"
            )
        _require_typed_locator(
            self.reservation_locator,
            field_name="admitted_provider_call.reservation_locator",
            expected_type=_RESERVATION_RECORD_SCHEMA,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "admitted_collection_locator": self.admitted_collection_locator.to_dict(),
            "admitted_collection_digest": self.admitted_collection_digest,
            "call_side": self.call_side,
            "driver_id": self.driver_id,
            "driver_contract_digest": self.driver_contract_digest,
            "canonical_query": self.canonical_query.to_dict(),
            "reservation_locator": self.reservation_locator.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: object) -> AdmittedProviderCall:
        mapping = require_exact_keys(
            data, _ADMITTED_PROVIDER_CALL_KEYS, label="admitted_provider_call"
        )
        return cls(
            admitted_collection_locator=ArtifactLocator.from_dict(
                mapping["admitted_collection_locator"],
                expected_type=AdmittedCollection.SCHEMA,
            ),
            admitted_collection_digest=mapping["admitted_collection_digest"],
            call_side=mapping["call_side"],
            driver_id=mapping["driver_id"],
            driver_contract_digest=mapping["driver_contract_digest"],
            canonical_query=CanonicalQueryContract.from_dict(
                mapping["canonical_query"]
            ),
            reservation_locator=ArtifactLocator.from_dict(
                mapping["reservation_locator"],
                expected_type=_RESERVATION_RECORD_SCHEMA,
            ),
        )


@dataclass(frozen=True, slots=True)
class ProviderObservationBatch:
    """Sanitized observation batch returned across `ProviderPort` or `FixtureObservationPort`."""

    observed_capabilities: tuple[str, ...]
    retrieval_context: RetrievalContext
    transport_outcome: TransportOutcome
    resource_observations: tuple[SanitizedResourceObservation, ...]
    normalized_errors: tuple[NormalizedProviderError, ...]
    io_counters: ExternalIOCounters

    def __post_init__(self) -> None:
        if not isinstance(self.observed_capabilities, (list, tuple)):
            raise ClosedValidationError(
                "provider_observation_batch.observed_capabilities: expected list or tuple"
            )
        sorted_caps = sort_utf8_strings(
            self.observed_capabilities,
            field_name="provider_observation_batch.observed_capabilities",
            allow_empty=True,
            validator=lambda s: validate_opaque_ref(
                s,
                field_name="provider_observation_batch.observed_capabilities",
                expected_prefix="cap",
            ),
        )
        object.__setattr__(self, "observed_capabilities", sorted_caps)

        if not isinstance(self.retrieval_context, RetrievalContext):
            raise ClosedValidationError(
                "provider_observation_batch.retrieval_context: expected RetrievalContext"
            )
        if not isinstance(self.transport_outcome, TransportOutcome):
            raise ClosedValidationError(
                "provider_observation_batch.transport_outcome: expected TransportOutcome"
            )
        if not isinstance(self.resource_observations, (list, tuple)):
            raise ClosedValidationError(
                "provider_observation_batch.resource_observations: expected list or tuple"
            )
        for obs in self.resource_observations:
            if not isinstance(obs, SanitizedResourceObservation):
                raise ClosedValidationError(
                    "provider_observation_batch.resource_observations: every item "
                    "must be SanitizedResourceObservation"
                )
        object.__setattr__(
            self, "resource_observations", tuple(self.resource_observations)
        )

        if not isinstance(self.normalized_errors, (list, tuple)):
            raise ClosedValidationError(
                "provider_observation_batch.normalized_errors: expected list or tuple"
            )
        for err in self.normalized_errors:
            if not isinstance(err, NormalizedProviderError):
                raise ClosedValidationError(
                    "provider_observation_batch.normalized_errors: every item "
                    "must be NormalizedProviderError"
                )
        object.__setattr__(
            self, "normalized_errors", tuple(self.normalized_errors)
        )

        if not isinstance(self.io_counters, ExternalIOCounters):
            raise ClosedValidationError(
                "provider_observation_batch.io_counters: expected ExternalIOCounters"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "observed_capabilities": list(self.observed_capabilities),
            "retrieval_context": self.retrieval_context.to_dict(),
            "transport_outcome": self.transport_outcome.to_dict(),
            "resource_observations": [
                obs.to_dict() for obs in self.resource_observations
            ],
            "normalized_errors": [
                err.to_dict() for err in self.normalized_errors
            ],
            "io_counters": self.io_counters.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: object) -> ProviderObservationBatch:
        mapping = require_exact_keys(
            data,
            _PROVIDER_OBSERVATION_BATCH_KEYS,
            label="provider_observation_batch",
        )
        if not isinstance(mapping["observed_capabilities"], list):
            raise ClosedValidationError(
                "provider_observation_batch.observed_capabilities: expected JSON array list"
            )
        if not isinstance(mapping["resource_observations"], list):
            raise ClosedValidationError(
                "provider_observation_batch.resource_observations: expected JSON array list"
            )
        if not isinstance(mapping["normalized_errors"], list):
            raise ClosedValidationError(
                "provider_observation_batch.normalized_errors: expected JSON array list"
            )
        sorted_caps = sort_utf8_strings(
            mapping["observed_capabilities"],
            field_name="provider_observation_batch.observed_capabilities",
            allow_empty=True,
            validator=lambda s: validate_opaque_ref(
                s,
                field_name="provider_observation_batch.observed_capabilities",
                expected_prefix="cap",
            ),
        )
        if tuple(mapping["observed_capabilities"]) != sorted_caps:
            raise ClosedValidationError(
                "provider_observation_batch.observed_capabilities: array must be "
                "canonically sorted by UTF-8 bytes"
            )
        return cls(
            observed_capabilities=sorted_caps,
            retrieval_context=RetrievalContext.from_dict(
                mapping["retrieval_context"]
            ),
            transport_outcome=TransportOutcome.from_dict(
                mapping["transport_outcome"]
            ),
            resource_observations=tuple(
                SanitizedResourceObservation.from_dict(item)
                for item in mapping["resource_observations"]
            ),
            normalized_errors=tuple(
                NormalizedProviderError.from_dict(item)
                for item in mapping["normalized_errors"]
            ),
            io_counters=ExternalIOCounters.from_dict(mapping["io_counters"]),
        )


@runtime_checkable
class ProviderPort(Protocol):
    """Pure zero-I/O protocol boundary for reserved live provider calls."""

    def fetch_observations(
        self, call: AdmittedProviderCall
    ) -> ProviderObservationBatch: ...


@dataclass(frozen=True, slots=True)
class AdmittedFixtureCall:
    """Offline 7A fixture call descriptor with zero `call_side` and zero `reservation_locator`."""

    admitted_collection_locator: ArtifactLocator
    admitted_collection_digest: str
    driver_id: str
    driver_contract_digest: str
    canonical_query: CanonicalQueryContract
    regression_fixture_locator: ArtifactLocator

    def __post_init__(self) -> None:
        _require_typed_locator(
            self.admitted_collection_locator,
            field_name="admitted_fixture_call.admitted_collection_locator",
            expected_type=AdmittedCollection.SCHEMA,
        )
        validate_sha256_prefixed(
            self.admitted_collection_digest,
            field_name="admitted_fixture_call.admitted_collection_digest",
        )
        if (
            self.admitted_collection_digest
            != self.admitted_collection_locator.content_digest
        ):
            raise ClosedValidationError(
                "admitted_fixture_call.admitted_collection_digest: must equal "
                "admitted_collection_locator.content_digest"
            )
        _validate_driver_id(
            self.driver_id, field_name="admitted_fixture_call.driver_id"
        )
        validate_sha256_prefixed(
            self.driver_contract_digest,
            field_name="admitted_fixture_call.driver_contract_digest",
        )
        if not isinstance(self.canonical_query, CanonicalQueryContract):
            raise ClosedValidationError(
                "admitted_fixture_call.canonical_query: expected CanonicalQueryContract"
            )
        _require_typed_locator(
            self.regression_fixture_locator,
            field_name="admitted_fixture_call.regression_fixture_locator",
            expected_type=_REGRESSION_FIXTURE_SCHEMA,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "admitted_collection_locator": self.admitted_collection_locator.to_dict(),
            "admitted_collection_digest": self.admitted_collection_digest,
            "driver_id": self.driver_id,
            "driver_contract_digest": self.driver_contract_digest,
            "canonical_query": self.canonical_query.to_dict(),
            "regression_fixture_locator": self.regression_fixture_locator.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: object) -> AdmittedFixtureCall:
        mapping = require_exact_keys(
            data, _ADMITTED_FIXTURE_CALL_KEYS, label="admitted_fixture_call"
        )
        return cls(
            admitted_collection_locator=ArtifactLocator.from_dict(
                mapping["admitted_collection_locator"],
                expected_type=AdmittedCollection.SCHEMA,
            ),
            admitted_collection_digest=mapping["admitted_collection_digest"],
            driver_id=mapping["driver_id"],
            driver_contract_digest=mapping["driver_contract_digest"],
            canonical_query=CanonicalQueryContract.from_dict(
                mapping["canonical_query"]
            ),
            regression_fixture_locator=ArtifactLocator.from_dict(
                mapping["regression_fixture_locator"],
                expected_type=_REGRESSION_FIXTURE_SCHEMA,
            ),
        )


@runtime_checkable
class FixtureObservationPort(Protocol):
    """Pure offline 7A fixture port with zero live network/credential side effects."""

    def load_fixture_observations(
        self, call: AdmittedFixtureCall
    ) -> ProviderObservationBatch: ...


__all__ = [
    "AdmittedFixtureCall",
    "AdmittedProviderCall",
    "ExternalIOCounters",
    "FixtureObservationPort",
    "ProviderObservationBatch",
    "ProviderPort",
    "SanitizedMetricObservation",
    "SanitizedResourceObservation",
]
