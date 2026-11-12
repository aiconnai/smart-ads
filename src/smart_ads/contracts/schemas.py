"""Closed read-intent, admission, normalized-fact, landing-row, and result schemas (ADR-0001)."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import re
from types import MappingProxyType
from typing import Any, ClassVar, Final, Literal

from smart_ads.contracts.jcs import (
    ADR_DATA_DOMAIN_PREFIXES,
    ADR_P1_DOMAIN_PREFIXES,
    MAX_JCS_SAFE_INT,
    SUPPLEMENTAL_DOMAIN_PREFIXES,
    ArtifactLocator,
    P1Integrity,
    canonicalize_jcs,
    domain_jcs_sha256,
    jcs_sha256,
    p1_content_digest,
    self_digest_jcs_sha256,
    sort_utf8_strings,
)
from smart_ads.contracts.numerics import (
    PHASE1_BASE_METRICS,
    PROVIDER_PRESENCE_TO_UNKNOWN_REASON,
    CalculationStatus,
    MetricOrigin,
    PresenceStatus,
    ProviderPresenceStatus,
    UnitType,
    UnknownReason,
    ValueType,
    validate_numeric_state,
)
from smart_ads.contracts.scalars import (
    ClosedValidationError,
    parse_iso_date,
    require_exact_keys,
    require_mapping,
    validate_currency_iso4217,
    validate_iso_date,
    validate_non_empty_str,
    validate_opaque_ref,
    validate_resource_ref,
    validate_sha256_prefixed,
    validate_timestamp_utc6,
    validate_timestamp_utc_seconds,
)

CollectionPurpose = Literal[
    "fixture_7a",
    "live_verification_7b",
    "operational_read",
]
CallSide = Literal["candidate", "reference", "operational"]
EffectRole = Literal[
    "candidate_7b_call",
    "reference_7b_call",
    "operational_provider_read",
]
ProviderErrorCategory = Literal[
    "admission",
    "network",
    "auth",
    "transport",
    "jsonrpc",
    "schema",
    "date_mismatch",
    "truncation",
    "pagination",
    "reducer",
    "completeness",
]

PURPOSE_REQUIRED_EFFECT_ROLES: Final[Mapping[str, tuple[EffectRole, ...]]] = (
    MappingProxyType(
        {
            "fixture_7a": (),
            "live_verification_7b": ("candidate_7b_call", "reference_7b_call"),
            "operational_read": ("operational_provider_read",),
        }
    )
)

_ALLOWED_PURPOSES: Final[frozenset[str]] = frozenset(
    PURPOSE_REQUIRED_EFFECT_ROLES.keys()
)
_ALLOWED_CALL_SIDES: Final[frozenset[str]] = frozenset(
    {"candidate", "reference", "operational"}
)
_ALLOWED_ERROR_CATEGORIES: Final[frozenset[str]] = frozenset(
    {
        "admission",
        "network",
        "auth",
        "transport",
        "jsonrpc",
        "schema",
        "date_mismatch",
        "truncation",
        "pagination",
        "reducer",
        "completeness",
    }
)
_SOURCE_METRIC_REF_RE: Final[re.Pattern[str]] = re.compile(
    r"\Asource-metric:(provider:[a-z0-9][a-z0-9._-]{0,127}:v[1-9][0-9]*|formula:sha256:[0-9a-f]{64})\Z"
)

_COLLECTION_REQUEST_KEYS: Final[frozenset[str]] = frozenset(
    {
        "request_id",
        "collection_purpose",
        "tenant_ref",
        "binding_ref",
        "resource_scope_ref",
        "date_rule",
        "resource_level",
        "requested_capabilities",
        "breakdowns",
    }
)
_DATE_RANGE_KEYS: Final[frozenset[str]] = frozenset(
    {"start_date", "end_date", "inclusive"}
)
_CANONICAL_QUERY_KEYS: Final[frozenset[str]] = frozenset(
    {
        "$schema",
        "tenant_ref",
        "binding_ref",
        "account_ref",
        "resource_scope_ref",
        "ad_platform_ref",
        "date_rule",
        "date_range",
        "reporting_timezone",
        "tzdb_version",
        "resource_level",
        "metric_semantic_refs",
        "requested_capabilities",
        "breakdowns",
        "currency",
        "attribution_semantics",
        "pagination_semantics",
        "aggregation_semantics",
    }
)
_PREREQ_FIXTURE_7A_SPEC: Final[tuple[tuple[str, str, bool], ...]] = (
    ("sealed_sandbox_profile_locator", "smart_ads/sealed_sandbox_profile/v1", True),
    ("regression_fixture_locator", "smart_ads/regression_fixture/v1", True),
)
_PREREQ_LIVE_7B_SPEC: Final[tuple[tuple[str, str, bool], ...]] = (
    (
        "legacy_step2_evidence_locator",
        "smart_ads/legacy_step2_implementation_evidence/v1",
        True,
    ),
    (
        "live_read_activation_receipt_locator",
        "smart_ads/smart_ads_live_read_activation_receipt/v1",
        True,
    ),
    (
        "gate3_selection_receipt_locator",
        "smart_ads/gate3_selection_receipt/v1",
        True,
    ),
    ("workload_identity_effect_proof_locator", "smart_ads/effect_proof/v1", True),
    ("deployment_effect_proof_locator", "smart_ads/effect_proof/v1", True),
)
_PREREQ_OPERATIONAL_SPEC: Final[tuple[tuple[str, str, bool], ...]] = (
    (
        "legacy_step2_evidence_locator",
        "smart_ads/legacy_step2_implementation_evidence/v1",
        True,
    ),
    (
        "live_read_activation_receipt_locator",
        "smart_ads/smart_ads_live_read_activation_receipt/v1",
        True,
    ),
    (
        "live_certification_head_locator",
        "smart_ads/live_certification_head/v1",
        True,
    ),
    (
        "live_certification_transition_locator",
        "smart_ads/live_certification_transition/v1",
        True,
    ),
    (
        "live_certification_certificate_locator",
        "smart_ads/live_certification_certificate/v1",
        True,
    ),
    (
        "gate3_operational_renewal_locator",
        "smart_ads/gate3_selection_receipt/v1",
        True,
    ),
    ("workload_identity_effect_proof_locator", "smart_ads/effect_proof/v1", True),
    ("deployment_effect_proof_locator", "smart_ads/effect_proof/v1", True),
    (
        "delegation_context_locator",
        "smart_ads/ibvi_ads_delegation_context/v1",
        False,
    ),
)
_PREREQ_SPECS_BY_PURPOSE: Final[
    Mapping[str, tuple[tuple[str, str, bool], ...]]
] = MappingProxyType(
    {
        "fixture_7a": _PREREQ_FIXTURE_7A_SPEC,
        "live_verification_7b": _PREREQ_LIVE_7B_SPEC,
        "operational_read": _PREREQ_OPERATIONAL_SPEC,
    }
)
_ALL_PREREQ_LOCATOR_FIELDS: Final[tuple[str, ...]] = (
    "sealed_sandbox_profile_locator",
    "regression_fixture_locator",
    "legacy_step2_evidence_locator",
    "live_read_activation_receipt_locator",
    "gate3_selection_receipt_locator",
    "live_certification_head_locator",
    "live_certification_transition_locator",
    "live_certification_certificate_locator",
    "gate3_operational_renewal_locator",
    "workload_identity_effect_proof_locator",
    "deployment_effect_proof_locator",
    "delegation_context_locator",
)
_ADMITTED_COLLECTION_CORE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "$schema",
        "admission_id",
        "collection_purpose",
        "external_request_digest",
        "tenant_ref",
        "binding_ref",
        "account_ref",
        "resource_scope_ref",
        "resource_level",
        "requested_capabilities",
        "admitted_at_utc",
        "clock_attestation_locator",
        "maximum_clock_uncertainty_ms",
        "tzdb_version",
        "reporting_timezone",
        "computed_date_range",
        "registry_snapshot_locator",
        "registry_snapshot_digest",
        "currency",
        "driver_id",
        "driver_contract_locator",
        "driver_contract_digest",
        "driver_capability_snapshot_digest",
        "canonical_query_contract",
        "canonical_query_digest",
        "purpose_prerequisite_locators",
        "required_effect_roles",
    }
)
_RECONCILIATION_ROW_KEY_KEYS: Final[frozenset[str]] = frozenset(
    {"resource_ref", "metric_date", "resource_level", "breakdown_signature"}
)
_FACT_KEY_KEYS: Final[frozenset[str]] = frozenset(
    {
        "binding_ref",
        "account_ref",
        "resource_ref",
        "resource_level",
        "metric_date",
        "metric_semantic_ref",
        "source_metric_ref",
        "attribution_ref",
        "breakdown_signature",
    }
)
_NORMALIZED_FACT_KEYS: Final[frozenset[str]] = frozenset(
    {
        "fact_key",
        "presence_status",
        "value_type",
        "raw_numeric_value",
        "unit",
        "currency",
    }
)
_RETRIEVAL_CONTEXT_KEYS: Final[frozenset[str]] = frozenset(
    {
        "retrieved_at_utc",
        "source_observation_ref",
        "adapter_version",
        "semantic_version",
    }
)
_SEMANTIC_PROJECTION_KEYS: Final[frozenset[str]] = frozenset(
    {
        "$schema",
        "fact_key",
        "numeric",
        "unit",
        "currency",
        "metric_origin",
        "presence_status",
        "unknown_reason",
        "calculation_status",
        "collected_at_utc",
        "source_observation_ref",
        "adapter_version",
        "semantic_version",
    }
)
_NUMERIC_BOX_KEYS: Final[frozenset[str]] = frozenset({"_type", "value"})
_LANDING_ROW_KEYS: Final[frozenset[str]] = frozenset(
    {
        "$schema",
        "fact_key",
        "value_type",
        "raw_numeric_value",
        "unit",
        "currency",
        "metric_origin",
        "presence_status",
        "unknown_reason",
        "calculation_status",
        "collected_at_utc",
        "source_observation_ref",
        "adapter_version",
        "semantic_version",
        "semantic_observation_digest",
        "row_digest",
    }
)
_TRANSPORT_OUTCOME_KEYS: Final[frozenset[str]] = frozenset(
    {
        "network_ok",
        "http_status",
        "media_and_encoding_valid",
        "auth_ok",
        "jsonrpc_error",
        "payload_schema_valid",
        "response_date_mismatch",
        "truncated_2mib",
        "non_empty_continuation",
        "reducer_order_or_count_mismatch",
        "duplicate_provider_observation",
    }
)
_NORMALIZED_ERROR_KEYS: Final[frozenset[str]] = frozenset(
    {"error_code", "category", "sanitized_detail"}
)
_COLLECTION_RESULT_CORE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "$schema",
        "admitted_collection_locator",
        "admitted_collection_digest",
        "call_side",
        "registry_snapshot_locator",
        "registry_snapshot_digest",
        "requested_capabilities",
        "observed_capabilities",
        "retrieval_context",
        "transport_outcome",
        "candidates",
        "normalized_fact_set",
        "normalized_fact_set_digest",
        "normalized_errors",
    }
)


class UnsupportedDerivedCollectionFactError(ClosedValidationError):
    """Raised when `normalized_collection_fact/v1` is given a `source-metric:formula:...` ref."""


def validate_source_metric_ref(
    value: object,
    *,
    field_name: str = "source_metric_ref",
) -> str:
    """Validate `source_metric_ref` closed lexical union (ADR-0001 §5.6 L1375)."""
    if not isinstance(value, str) or not _SOURCE_METRIC_REF_RE.fullmatch(value):
        raise ClosedValidationError(
            f"{field_name}: invalid source_metric_ref {value!r}"
        )
    return value


def _require_locator_instance(
    value: object,
    *,
    field_name: str,
    expected_type: str | None = None,
) -> ArtifactLocator:
    if not isinstance(value, ArtifactLocator):
        raise ClosedValidationError(
            f"{field_name}: expected ArtifactLocator, got {type(value).__name__}"
        )
    if expected_type is not None and value.artifact_type != expected_type:
        raise ClosedValidationError(
            f"{field_name}: expected artifact_type {expected_type!r}, got {value.artifact_type!r}"
        )
    return value


def _validate_sorted_opaque_refs(
    values: object,
    *,
    field_name: str,
    expected_prefix: str,
    allow_empty: bool = False,
    require_already_sorted: bool = False,
) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple)):
        raise ClosedValidationError(
            f"{field_name}: expected list or tuple of strings, got {type(values).__name__}"
        )
    sorted_vals = sort_utf8_strings(
        values,
        field_name=field_name,
        allow_empty=allow_empty,
        validator=lambda s: validate_opaque_ref(
            s, field_name=field_name, expected_prefix=expected_prefix
        ),
    )
    if require_already_sorted and tuple(values) != sorted_vals:
        raise ClosedValidationError(
            f"{field_name}: array must already be canonically sorted by UTF-8 bytes"
        )
    return sorted_vals


def _validate_empty_phase1_breakdowns(
    values: object,
    *,
    field_name: str,
) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple)):
        raise ClosedValidationError(
            f"{field_name}: expected empty list or tuple, got {type(values).__name__}"
        )
    if len(values) != 0:
        raise ClosedValidationError(
            f"{field_name}: must be empty [] in Phase 1, got {len(values)} item(s)"
        )
    return ()


def _enforce_base_metric_compatibility(
    *,
    metric_semantic_ref: str,
    value_type: ValueType | None,
    unit: UnitType | None,
    currency: str | None,
    label: str,
) -> None:
    defn = PHASE1_BASE_METRICS.get(metric_semantic_ref)
    if defn is None or value_type is None:
        return
    if value_type != defn.value_type or unit != defn.unit:
        raise ClosedValidationError(
            f"{label}: {metric_semantic_ref!r} requires "
            f"(value_type={defn.value_type!r}, unit={defn.unit!r}), "
            f"got (value_type={value_type!r}, unit={unit!r})"
        )
    if defn.currency_rule == "must_be_null" and currency is not None:
        raise ClosedValidationError(
            f"{label}: {metric_semantic_ref!r} requires currency=None"
        )
    if defn.currency_rule == "must_be_query_currency" and currency is None:
        raise ClosedValidationError(
            f"{label}: {metric_semantic_ref!r} requires non-null query currency"
        )


def _enforce_origin_vs_source_metric_ref(
    *,
    metric_origin: MetricOrigin,
    source_metric_ref: str,
    label: str,
) -> None:
    is_provider = source_metric_ref.startswith("source-metric:provider:")
    is_formula = source_metric_ref.startswith("source-metric:formula:")
    if metric_origin == "provider_observation" and not is_provider:
        raise ClosedValidationError(
            f"{label}: metric_origin='provider_observation' requires 'source-metric:provider:...', "
            f"got {source_metric_ref!r}"
        )
    if metric_origin == "derived_formula" and not is_formula:
        raise ClosedValidationError(
            f"{label}: metric_origin='derived_formula' requires 'source-metric:formula:...', "
            f"got {source_metric_ref!r}"
        )


@dataclass(frozen=True, slots=True)
class CollectionRequest:
    """External intent-only collection request (ADR-0001 §4.2 L394–404)."""

    request_id: str
    collection_purpose: CollectionPurpose
    tenant_ref: str
    binding_ref: str
    resource_scope_ref: str
    date_rule: str
    resource_level: str
    requested_capabilities: tuple[str, ...]
    breakdowns: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        validate_non_empty_str(
            self.request_id, field_name="collection_request.request_id"
        )
        if (
            not isinstance(self.collection_purpose, str)
            or self.collection_purpose not in _ALLOWED_PURPOSES
        ):
            raise ClosedValidationError(
                f"collection_request.collection_purpose: invalid purpose {self.collection_purpose!r}"
            )
        validate_opaque_ref(
            self.tenant_ref,
            field_name="collection_request.tenant_ref",
            expected_prefix="tenant",
        )
        validate_opaque_ref(
            self.binding_ref,
            field_name="collection_request.binding_ref",
            expected_prefix="binding",
        )
        validate_opaque_ref(
            self.resource_scope_ref,
            field_name="collection_request.resource_scope_ref",
            expected_prefix="scope",
        )
        if self.date_rule != "previous_local_day":
            raise ClosedValidationError(
                "collection_request.date_rule: must equal 'previous_local_day'"
            )
        if self.resource_level != "campaign":
            raise ClosedValidationError(
                "collection_request.resource_level: must equal 'campaign'"
            )
        sorted_caps = _validate_sorted_opaque_refs(
            self.requested_capabilities,
            field_name="collection_request.requested_capabilities",
            expected_prefix="cap",
            allow_empty=False,
        )
        object.__setattr__(self, "requested_capabilities", sorted_caps)
        checked_breakdowns = _validate_empty_phase1_breakdowns(
            self.breakdowns, field_name="collection_request.breakdowns"
        )
        object.__setattr__(self, "breakdowns", checked_breakdowns)

    @property
    def external_request_digest(self) -> str:
        """Compute canonical JCS SHA-256 digest of the external intent."""
        return jcs_sha256(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "collection_purpose": self.collection_purpose,
            "tenant_ref": self.tenant_ref,
            "binding_ref": self.binding_ref,
            "resource_scope_ref": self.resource_scope_ref,
            "date_rule": self.date_rule,
            "resource_level": self.resource_level,
            "requested_capabilities": list(self.requested_capabilities),
            "breakdowns": list(self.breakdowns),
        }

    @classmethod
    def from_dict(cls, data: object) -> CollectionRequest:
        mapping = require_exact_keys(
            data, _COLLECTION_REQUEST_KEYS, label="collection_request"
        )
        if not isinstance(mapping["requested_capabilities"], list):
            raise ClosedValidationError(
                "collection_request.requested_capabilities: expected JSON array list"
            )
        if not isinstance(mapping["breakdowns"], list):
            raise ClosedValidationError(
                "collection_request.breakdowns: expected JSON array list"
            )
        return cls(
            request_id=mapping["request_id"],
            collection_purpose=mapping["collection_purpose"],
            tenant_ref=mapping["tenant_ref"],
            binding_ref=mapping["binding_ref"],
            resource_scope_ref=mapping["resource_scope_ref"],
            date_rule=mapping["date_rule"],
            resource_level=mapping["resource_level"],
            requested_capabilities=tuple(mapping["requested_capabilities"]),
            breakdowns=tuple(mapping["breakdowns"]),
        )


@dataclass(frozen=True, slots=True)
class DateRange:
    """Closed inclusive calendar date range (`start_date <= end_date`)."""

    start_date: str
    end_date: str
    inclusive: bool = True

    def __post_init__(self) -> None:
        start = parse_iso_date(self.start_date, field_name="date_range.start_date")
        end = parse_iso_date(self.end_date, field_name="date_range.end_date")
        if not isinstance(self.inclusive, bool) or self.inclusive is not True:
            raise ClosedValidationError("date_range.inclusive: must be bool True")
        if start > end:
            raise ClosedValidationError(
                f"date_range: start_date {self.start_date!r} > end_date {self.end_date!r}"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "start_date": self.start_date,
            "end_date": self.end_date,
            "inclusive": self.inclusive,
        }

    @classmethod
    def from_dict(cls, data: object, *, label: str = "date_range") -> DateRange:
        mapping = require_exact_keys(data, _DATE_RANGE_KEYS, label=label)
        return cls(
            start_date=mapping["start_date"],
            end_date=mapping["end_date"],
            inclusive=mapping["inclusive"],
        )


@dataclass(frozen=True, slots=True)
class CanonicalQueryContract:
    """Closed `smart_ads/canonical_query_contract/v1` (ADR-0001 §5.2)."""

    SCHEMA: ClassVar[str] = "smart_ads/canonical_query_contract/v1"

    tenant_ref: str
    binding_ref: str
    account_ref: str
    resource_scope_ref: str
    ad_platform_ref: str
    date_rule: str
    date_range: DateRange
    reporting_timezone: str
    tzdb_version: str
    resource_level: str
    metric_semantic_refs: tuple[str, ...]
    requested_capabilities: tuple[str, ...]
    breakdowns: tuple[str, ...] = ()
    currency: str = "BRL"
    attribution_semantics: str = "not_applicable_to_selected_metrics"
    pagination_semantics: str = "complete_result_required"
    aggregation_semantics: str = "per_campaign_rows_no_cross_campaign_aggregation"

    def __post_init__(self) -> None:
        validate_opaque_ref(
            self.tenant_ref,
            field_name="canonical_query_contract.tenant_ref",
            expected_prefix="tenant",
        )
        validate_opaque_ref(
            self.binding_ref,
            field_name="canonical_query_contract.binding_ref",
            expected_prefix="binding",
        )
        validate_opaque_ref(
            self.account_ref,
            field_name="canonical_query_contract.account_ref",
            expected_prefix="account",
        )
        validate_opaque_ref(
            self.resource_scope_ref,
            field_name="canonical_query_contract.resource_scope_ref",
            expected_prefix="scope",
        )
        if self.ad_platform_ref != "meta":
            raise ClosedValidationError(
                "canonical_query_contract.ad_platform_ref: must equal 'meta'"
            )
        if self.date_rule != "previous_local_day":
            raise ClosedValidationError(
                "canonical_query_contract.date_rule: must equal 'previous_local_day'"
            )
        if not isinstance(self.date_range, DateRange):
            raise ClosedValidationError(
                "canonical_query_contract.date_range: expected DateRange"
            )
        if self.date_range.start_date != self.date_range.end_date:
            raise ClosedValidationError(
                "canonical_query_contract.date_range: previous_local_day requires start_date == end_date"
            )
        if self.reporting_timezone != "America/Sao_Paulo":
            raise ClosedValidationError(
                "canonical_query_contract.reporting_timezone: must equal 'America/Sao_Paulo'"
            )
        validate_non_empty_str(
            self.tzdb_version, field_name="canonical_query_contract.tzdb_version"
        )
        if self.resource_level != "campaign":
            raise ClosedValidationError(
                "canonical_query_contract.resource_level: must equal 'campaign'"
            )
        sorted_metrics = _validate_sorted_opaque_refs(
            self.metric_semantic_refs,
            field_name="canonical_query_contract.metric_semantic_refs",
            expected_prefix="metric",
            allow_empty=False,
        )
        object.__setattr__(self, "metric_semantic_refs", sorted_metrics)

        sorted_caps = _validate_sorted_opaque_refs(
            self.requested_capabilities,
            field_name="canonical_query_contract.requested_capabilities",
            expected_prefix="cap",
            allow_empty=False,
        )
        object.__setattr__(self, "requested_capabilities", sorted_caps)

        checked_breakdowns = _validate_empty_phase1_breakdowns(
            self.breakdowns, field_name="canonical_query_contract.breakdowns"
        )
        object.__setattr__(self, "breakdowns", checked_breakdowns)

        validate_currency_iso4217(
            self.currency, field_name="canonical_query_contract.currency"
        )
        if self.currency != "BRL":
            raise ClosedValidationError(
                "canonical_query_contract.currency: must equal 'BRL' in Phase 1"
            )
        if self.attribution_semantics != "not_applicable_to_selected_metrics":
            raise ClosedValidationError(
                "canonical_query_contract.attribution_semantics: must equal "
                "'not_applicable_to_selected_metrics'"
            )
        if self.pagination_semantics != "complete_result_required":
            raise ClosedValidationError(
                "canonical_query_contract.pagination_semantics: must equal "
                "'complete_result_required'"
            )
        if (
            self.aggregation_semantics
            != "per_campaign_rows_no_cross_campaign_aggregation"
        ):
            raise ClosedValidationError(
                "canonical_query_contract.aggregation_semantics: must equal "
                "'per_campaign_rows_no_cross_campaign_aggregation'"
            )

    @property
    def canonical_query_digest(self) -> str:
        """Compute `SHA-256(RFC8785(canonical_query_contract))` (ADR-0001 §5.2 L805)."""
        return jcs_sha256(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "$schema": self.SCHEMA,
            "tenant_ref": self.tenant_ref,
            "binding_ref": self.binding_ref,
            "account_ref": self.account_ref,
            "resource_scope_ref": self.resource_scope_ref,
            "ad_platform_ref": self.ad_platform_ref,
            "date_rule": self.date_rule,
            "date_range": self.date_range.to_dict(),
            "reporting_timezone": self.reporting_timezone,
            "tzdb_version": self.tzdb_version,
            "resource_level": self.resource_level,
            "metric_semantic_refs": list(self.metric_semantic_refs),
            "requested_capabilities": list(self.requested_capabilities),
            "breakdowns": list(self.breakdowns),
            "currency": self.currency,
            "attribution_semantics": self.attribution_semantics,
            "pagination_semantics": self.pagination_semantics,
            "aggregation_semantics": self.aggregation_semantics,
        }

    @classmethod
    def from_dict(cls, data: object) -> CanonicalQueryContract:
        mapping = require_exact_keys(
            data, _CANONICAL_QUERY_KEYS, label="canonical_query_contract"
        )
        if mapping["$schema"] != cls.SCHEMA:
            raise ClosedValidationError(
                f"canonical_query_contract.$schema: expected {cls.SCHEMA!r}, "
                f"got {mapping['$schema']!r}"
            )
        if not isinstance(mapping["metric_semantic_refs"], list):
            raise ClosedValidationError(
                "canonical_query_contract.metric_semantic_refs: expected JSON array list"
            )
        if not isinstance(mapping["requested_capabilities"], list):
            raise ClosedValidationError(
                "canonical_query_contract.requested_capabilities: expected JSON array list"
            )
        if not isinstance(mapping["breakdowns"], list):
            raise ClosedValidationError(
                "canonical_query_contract.breakdowns: expected JSON array list"
            )
        metrics = _validate_sorted_opaque_refs(
            mapping["metric_semantic_refs"],
            field_name="canonical_query_contract.metric_semantic_refs",
            expected_prefix="metric",
            allow_empty=False,
            require_already_sorted=True,
        )
        caps = _validate_sorted_opaque_refs(
            mapping["requested_capabilities"],
            field_name="canonical_query_contract.requested_capabilities",
            expected_prefix="cap",
            allow_empty=False,
            require_already_sorted=True,
        )
        return cls(
            tenant_ref=mapping["tenant_ref"],
            binding_ref=mapping["binding_ref"],
            account_ref=mapping["account_ref"],
            resource_scope_ref=mapping["resource_scope_ref"],
            ad_platform_ref=mapping["ad_platform_ref"],
            date_rule=mapping["date_rule"],
            date_range=DateRange.from_dict(
                mapping["date_range"], label="canonical_query_contract.date_range"
            ),
            reporting_timezone=mapping["reporting_timezone"],
            tzdb_version=mapping["tzdb_version"],
            resource_level=mapping["resource_level"],
            metric_semantic_refs=metrics,
            requested_capabilities=caps,
            breakdowns=tuple(mapping["breakdowns"]),
            currency=mapping["currency"],
            attribution_semantics=mapping["attribution_semantics"],
            pagination_semantics=mapping["pagination_semantics"],
            aggregation_semantics=mapping["aggregation_semantics"],
        )


@dataclass(frozen=True, slots=True)
class PurposePrerequisiteLocators:
    """Purpose-discriminated prerequisite locators with zero current-call effect locators."""

    purpose: CollectionPurpose
    sealed_sandbox_profile_locator: ArtifactLocator | None = None
    regression_fixture_locator: ArtifactLocator | None = None
    legacy_step2_evidence_locator: ArtifactLocator | None = None
    live_read_activation_receipt_locator: ArtifactLocator | None = None
    gate3_selection_receipt_locator: ArtifactLocator | None = None
    live_certification_head_locator: ArtifactLocator | None = None
    live_certification_transition_locator: ArtifactLocator | None = None
    live_certification_certificate_locator: ArtifactLocator | None = None
    gate3_operational_renewal_locator: ArtifactLocator | None = None
    workload_identity_effect_proof_locator: ArtifactLocator | None = None
    deployment_effect_proof_locator: ArtifactLocator | None = None
    delegation_context_locator: ArtifactLocator | None = None

    def __post_init__(self) -> None:
        if (
            not isinstance(self.purpose, str)
            or self.purpose not in _PREREQ_SPECS_BY_PURPOSE
        ):
            raise ClosedValidationError(
                f"purpose_prerequisite_locators.purpose: invalid purpose {self.purpose!r}"
            )
        spec = _PREREQ_SPECS_BY_PURPOSE[self.purpose]
        allowed_fields = {field_name for field_name, _, _ in spec}
        for field_name, expected_type, is_required in spec:
            val = getattr(self, field_name)
            if val is None:
                if is_required:
                    raise ClosedValidationError(
                        f"purpose_prerequisite_locators.{field_name}: required for purpose {self.purpose!r}"
                    )
            else:
                _require_locator_instance(
                    val,
                    field_name=f"purpose_prerequisite_locators.{field_name}",
                    expected_type=expected_type,
                )
        for field_name in _ALL_PREREQ_LOCATOR_FIELDS:
            if field_name not in allowed_fields and getattr(self, field_name) is not None:
                raise ClosedValidationError(
                    f"purpose_prerequisite_locators.{field_name}: forbidden for purpose {self.purpose!r}"
                )

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"purpose": self.purpose}
        for field_name, _, _ in _PREREQ_SPECS_BY_PURPOSE[self.purpose]:
            val = getattr(self, field_name)
            out[field_name] = None if val is None else val.to_dict()
        return out

    @classmethod
    def from_dict(cls, data: object) -> PurposePrerequisiteLocators:
        mapping = require_mapping(data, label="purpose_prerequisite_locators")
        purpose = mapping.get("purpose")
        if not isinstance(purpose, str) or purpose not in _PREREQ_SPECS_BY_PURPOSE:
            raise ClosedValidationError(
                f"purpose_prerequisite_locators.purpose: invalid purpose {purpose!r}"
            )
        spec = _PREREQ_SPECS_BY_PURPOSE[purpose]
        expected_keys = {"purpose"} | {field_name for field_name, _, _ in spec}
        require_exact_keys(
            mapping, expected_keys, label="purpose_prerequisite_locators"
        )
        kwargs: dict[str, Any] = {"purpose": purpose}
        for field_name, expected_type, is_required in spec:
            raw_loc = mapping[field_name]
            if raw_loc is None and not is_required:
                kwargs[field_name] = None
            else:
                kwargs[field_name] = ArtifactLocator.from_dict(
                    raw_loc, expected_type=expected_type
                )
        return cls(**kwargs)


@dataclass(frozen=True, slots=True)
class AdmittedCollection:
    """Closed `smart_ads/admitted_collection/v1` envelope (ADR-0001 §§4.2, 12.7)."""

    SCHEMA: ClassVar[str] = "smart_ads/admitted_collection/v1"

    admission_id: str
    collection_purpose: CollectionPurpose
    external_request_digest: str
    tenant_ref: str
    binding_ref: str
    account_ref: str
    resource_scope_ref: str
    resource_level: str
    requested_capabilities: tuple[str, ...]
    admitted_at_utc: str
    clock_attestation_locator: ArtifactLocator
    maximum_clock_uncertainty_ms: int
    tzdb_version: str
    reporting_timezone: str
    computed_date_range: DateRange
    registry_snapshot_locator: ArtifactLocator
    registry_snapshot_digest: str
    currency: str
    driver_id: str
    driver_contract_locator: ArtifactLocator
    driver_contract_digest: str
    driver_capability_snapshot_digest: str
    canonical_query_contract: CanonicalQueryContract
    canonical_query_digest: str
    purpose_prerequisite_locators: PurposePrerequisiteLocators
    required_effect_roles: tuple[EffectRole, ...]
    integrity: P1Integrity | None = None

    def __post_init__(self) -> None:
        validate_opaque_ref(
            self.admission_id,
            field_name="admitted_collection.admission_id",
            expected_prefix="admission",
        )
        if (
            not isinstance(self.collection_purpose, str)
            or self.collection_purpose not in _ALLOWED_PURPOSES
        ):
            raise ClosedValidationError(
                f"admitted_collection.collection_purpose: invalid purpose {self.collection_purpose!r}"
            )
        validate_sha256_prefixed(
            self.external_request_digest,
            field_name="admitted_collection.external_request_digest",
        )
        validate_opaque_ref(
            self.tenant_ref,
            field_name="admitted_collection.tenant_ref",
            expected_prefix="tenant",
        )
        validate_opaque_ref(
            self.binding_ref,
            field_name="admitted_collection.binding_ref",
            expected_prefix="binding",
        )
        validate_opaque_ref(
            self.account_ref,
            field_name="admitted_collection.account_ref",
            expected_prefix="account",
        )
        validate_opaque_ref(
            self.resource_scope_ref,
            field_name="admitted_collection.resource_scope_ref",
            expected_prefix="scope",
        )
        if self.resource_level != "campaign":
            raise ClosedValidationError(
                "admitted_collection.resource_level: must equal 'campaign'"
            )
        sorted_caps = _validate_sorted_opaque_refs(
            self.requested_capabilities,
            field_name="admitted_collection.requested_capabilities",
            expected_prefix="cap",
            allow_empty=False,
        )
        object.__setattr__(self, "requested_capabilities", sorted_caps)

        validate_timestamp_utc_seconds(
            self.admitted_at_utc, field_name="admitted_collection.admitted_at_utc"
        )
        _require_locator_instance(
            self.clock_attestation_locator,
            field_name="admitted_collection.clock_attestation_locator",
            expected_type="smart_ads/clock_attestation/v1",
        )
        if (
            isinstance(self.maximum_clock_uncertainty_ms, bool)
            or not isinstance(self.maximum_clock_uncertainty_ms, int)
            or not (0 < self.maximum_clock_uncertainty_ms <= MAX_JCS_SAFE_INT)
        ):
            raise ClosedValidationError(
                "admitted_collection.maximum_clock_uncertainty_ms: must be positive safe int"
            )
        validate_non_empty_str(
            self.tzdb_version, field_name="admitted_collection.tzdb_version"
        )
        if self.reporting_timezone != "America/Sao_Paulo":
            raise ClosedValidationError(
                "admitted_collection.reporting_timezone: must equal 'America/Sao_Paulo'"
            )
        if not isinstance(self.computed_date_range, DateRange):
            raise ClosedValidationError(
                "admitted_collection.computed_date_range: expected DateRange"
            )
        if self.computed_date_range.start_date != self.computed_date_range.end_date:
            raise ClosedValidationError(
                "admitted_collection.computed_date_range: start_date must equal end_date"
            )

        _require_locator_instance(
            self.registry_snapshot_locator,
            field_name="admitted_collection.registry_snapshot_locator",
            expected_type="smart_ads/private_registry_snapshot/v1",
        )
        validate_sha256_prefixed(
            self.registry_snapshot_digest,
            field_name="admitted_collection.registry_snapshot_digest",
        )
        if (
            self.registry_snapshot_digest
            != self.registry_snapshot_locator.content_digest
        ):
            raise ClosedValidationError(
                "admitted_collection.registry_snapshot_digest: must equal "
                "registry_snapshot_locator.content_digest"
            )

        validate_currency_iso4217(
            self.currency, field_name="admitted_collection.currency"
        )
        if self.currency != "BRL":
            raise ClosedValidationError(
                "admitted_collection.currency: must equal 'BRL'"
            )
        checked_driver_id = validate_non_empty_str(
            self.driver_id, field_name="admitted_collection.driver_id"
        )
        if any(ch.isspace() for ch in checked_driver_id):
            raise ClosedValidationError(
                "admitted_collection.driver_id: whitespace is forbidden"
            )
        _require_locator_instance(
            self.driver_contract_locator,
            field_name="admitted_collection.driver_contract_locator",
        )
        validate_sha256_prefixed(
            self.driver_contract_digest,
            field_name="admitted_collection.driver_contract_digest",
        )
        if self.driver_contract_digest != self.driver_contract_locator.content_digest:
            raise ClosedValidationError(
                "admitted_collection.driver_contract_digest: must equal "
                "driver_contract_locator.content_digest"
            )
        validate_sha256_prefixed(
            self.driver_capability_snapshot_digest,
            field_name="admitted_collection.driver_capability_snapshot_digest",
        )

        if not isinstance(self.canonical_query_contract, CanonicalQueryContract):
            raise ClosedValidationError(
                "admitted_collection.canonical_query_contract: expected CanonicalQueryContract"
            )
        validate_sha256_prefixed(
            self.canonical_query_digest,
            field_name="admitted_collection.canonical_query_digest",
        )
        if (
            self.canonical_query_digest
            != self.canonical_query_contract.canonical_query_digest
        ):
            raise ClosedValidationError(
                "admitted_collection.canonical_query_digest: must equal "
                "canonical_query_contract.canonical_query_digest"
            )

        cqc = self.canonical_query_contract
        if (
            self.tenant_ref != cqc.tenant_ref
            or self.binding_ref != cqc.binding_ref
            or self.account_ref != cqc.account_ref
            or self.resource_scope_ref != cqc.resource_scope_ref
            or self.resource_level != cqc.resource_level
            or self.requested_capabilities != cqc.requested_capabilities
            or self.tzdb_version != cqc.tzdb_version
            or self.reporting_timezone != cqc.reporting_timezone
            or self.computed_date_range != cqc.date_range
            or self.currency != cqc.currency
        ):
            raise ClosedValidationError(
                "admitted_collection: top-level fields must agree with canonical_query_contract"
            )

        if not isinstance(
            self.purpose_prerequisite_locators, PurposePrerequisiteLocators
        ):
            raise ClosedValidationError(
                "admitted_collection.purpose_prerequisite_locators: expected PurposePrerequisiteLocators"
            )
        if self.purpose_prerequisite_locators.purpose != self.collection_purpose:
            raise ClosedValidationError(
                "admitted_collection.purpose_prerequisite_locators.purpose: must equal collection_purpose"
            )

        if not isinstance(self.required_effect_roles, (list, tuple)):
            raise ClosedValidationError(
                "admitted_collection.required_effect_roles: expected list or tuple"
            )
        roles_tuple = tuple(self.required_effect_roles)
        expected_roles = PURPOSE_REQUIRED_EFFECT_ROLES[self.collection_purpose]
        if roles_tuple != expected_roles:
            raise ClosedValidationError(
                f"admitted_collection.required_effect_roles: expected {expected_roles!r}, "
                f"got {roles_tuple!r}"
            )
        object.__setattr__(self, "required_effect_roles", roles_tuple)

        if self.integrity is not None and not isinstance(self.integrity, P1Integrity):
            raise ClosedValidationError(
                "admitted_collection.integrity: expected P1Integrity or None"
            )
        if self.integrity is not None and self.integrity.is_signed:
            expected_p1 = p1_content_digest(self.to_dict())
            if self.integrity.content_digest != expected_p1:
                raise ClosedValidationError(
                    "admitted_collection.integrity.content_digest: recomputed "
                    f"{expected_p1!r} != asserted {self.integrity.content_digest!r}"
                )

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "$schema": self.SCHEMA,
            "admission_id": self.admission_id,
            "collection_purpose": self.collection_purpose,
            "external_request_digest": self.external_request_digest,
            "tenant_ref": self.tenant_ref,
            "binding_ref": self.binding_ref,
            "account_ref": self.account_ref,
            "resource_scope_ref": self.resource_scope_ref,
            "resource_level": self.resource_level,
            "requested_capabilities": list(self.requested_capabilities),
            "admitted_at_utc": self.admitted_at_utc,
            "clock_attestation_locator": self.clock_attestation_locator.to_dict(),
            "maximum_clock_uncertainty_ms": self.maximum_clock_uncertainty_ms,
            "tzdb_version": self.tzdb_version,
            "reporting_timezone": self.reporting_timezone,
            "computed_date_range": self.computed_date_range.to_dict(),
            "registry_snapshot_locator": self.registry_snapshot_locator.to_dict(),
            "registry_snapshot_digest": self.registry_snapshot_digest,
            "currency": self.currency,
            "driver_id": self.driver_id,
            "driver_contract_locator": self.driver_contract_locator.to_dict(),
            "driver_contract_digest": self.driver_contract_digest,
            "driver_capability_snapshot_digest": self.driver_capability_snapshot_digest,
            "canonical_query_contract": self.canonical_query_contract.to_dict(),
            "canonical_query_digest": self.canonical_query_digest,
            "purpose_prerequisite_locators": self.purpose_prerequisite_locators.to_dict(),
            "required_effect_roles": list(self.required_effect_roles),
        }
        if self.integrity is not None:
            out["integrity"] = self.integrity.to_dict()
        return out

    @classmethod
    def from_dict(
        cls,
        data: object,
        *,
        require_signed: bool = False,
    ) -> AdmittedCollection:
        if not isinstance(require_signed, bool):
            raise ClosedValidationError("require_signed: expected bool")
        mapping = require_mapping(data, label="admitted_collection")
        if require_signed or "integrity" in mapping:
            require_exact_keys(
                mapping,
                _ADMITTED_COLLECTION_CORE_KEYS | {"integrity"},
                label="admitted_collection",
            )
            integrity: P1Integrity | None = P1Integrity.from_dict(
                mapping["integrity"], require_signed=require_signed
            )
        else:
            require_exact_keys(
                mapping, _ADMITTED_COLLECTION_CORE_KEYS, label="admitted_collection"
            )
            integrity = None

        if mapping["$schema"] != cls.SCHEMA:
            raise ClosedValidationError(
                f"admitted_collection.$schema: expected {cls.SCHEMA!r}, got {mapping['$schema']!r}"
            )
        if not isinstance(mapping["requested_capabilities"], list):
            raise ClosedValidationError(
                "admitted_collection.requested_capabilities: expected JSON array list"
            )
        if not isinstance(mapping["required_effect_roles"], list):
            raise ClosedValidationError(
                "admitted_collection.required_effect_roles: expected JSON array list"
            )
        caps = _validate_sorted_opaque_refs(
            mapping["requested_capabilities"],
            field_name="admitted_collection.requested_capabilities",
            expected_prefix="cap",
            allow_empty=False,
            require_already_sorted=True,
        )
        return cls(
            admission_id=mapping["admission_id"],
            collection_purpose=mapping["collection_purpose"],
            external_request_digest=mapping["external_request_digest"],
            tenant_ref=mapping["tenant_ref"],
            binding_ref=mapping["binding_ref"],
            account_ref=mapping["account_ref"],
            resource_scope_ref=mapping["resource_scope_ref"],
            resource_level=mapping["resource_level"],
            requested_capabilities=caps,
            admitted_at_utc=mapping["admitted_at_utc"],
            clock_attestation_locator=ArtifactLocator.from_dict(
                mapping["clock_attestation_locator"],
                expected_type="smart_ads/clock_attestation/v1",
            ),
            maximum_clock_uncertainty_ms=mapping["maximum_clock_uncertainty_ms"],
            tzdb_version=mapping["tzdb_version"],
            reporting_timezone=mapping["reporting_timezone"],
            computed_date_range=DateRange.from_dict(
                mapping["computed_date_range"],
                label="admitted_collection.computed_date_range",
            ),
            registry_snapshot_locator=ArtifactLocator.from_dict(
                mapping["registry_snapshot_locator"],
                expected_type="smart_ads/private_registry_snapshot/v1",
            ),
            registry_snapshot_digest=mapping["registry_snapshot_digest"],
            currency=mapping["currency"],
            driver_id=mapping["driver_id"],
            driver_contract_locator=ArtifactLocator.from_dict(
                mapping["driver_contract_locator"]
            ),
            driver_contract_digest=mapping["driver_contract_digest"],
            driver_capability_snapshot_digest=mapping[
                "driver_capability_snapshot_digest"
            ],
            canonical_query_contract=CanonicalQueryContract.from_dict(
                mapping["canonical_query_contract"]
            ),
            canonical_query_digest=mapping["canonical_query_digest"],
            purpose_prerequisite_locators=PurposePrerequisiteLocators.from_dict(
                mapping["purpose_prerequisite_locators"]
            ),
            required_effect_roles=tuple(mapping["required_effect_roles"]),
            integrity=integrity,
        )


@dataclass(frozen=True, slots=True)
class ReconciliationRowKey:
    """Derived 4-field row-level projection of `FactKey` (ADR-0001 §4.2 L553–558)."""

    resource_ref: str
    metric_date: str
    resource_level: str
    breakdown_signature: str

    def __post_init__(self) -> None:
        validate_resource_ref(
            self.resource_ref,
            field_name="reconciliation_row_key.resource_ref",
        )
        validate_iso_date(
            self.metric_date, field_name="reconciliation_row_key.metric_date"
        )
        if self.resource_level != "campaign":
            raise ClosedValidationError(
                "reconciliation_row_key.resource_level: must equal 'campaign'"
            )
        validate_opaque_ref(
            self.breakdown_signature,
            field_name="reconciliation_row_key.breakdown_signature",
            expected_prefix="breakdown",
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "resource_ref": self.resource_ref,
            "metric_date": self.metric_date,
            "resource_level": self.resource_level,
            "breakdown_signature": self.breakdown_signature,
        }

    @classmethod
    def from_dict(cls, data: object) -> ReconciliationRowKey:
        mapping = require_exact_keys(
            data, _RECONCILIATION_ROW_KEY_KEYS, label="reconciliation_row_key"
        )
        return cls(
            resource_ref=mapping["resource_ref"],
            metric_date=mapping["metric_date"],
            resource_level=mapping["resource_level"],
            breakdown_signature=mapping["breakdown_signature"],
        )


@dataclass(frozen=True, slots=True)
class FactKey:
    """Complete 9-field canonical fact key (ADR-0001 §6.1 L1450–1452)."""

    binding_ref: str
    account_ref: str
    resource_ref: str
    resource_level: str
    metric_date: str
    metric_semantic_ref: str
    source_metric_ref: str
    attribution_ref: str
    breakdown_signature: str

    def __post_init__(self) -> None:
        validate_opaque_ref(
            self.binding_ref,
            field_name="fact_key.binding_ref",
            expected_prefix="binding",
        )
        validate_opaque_ref(
            self.account_ref,
            field_name="fact_key.account_ref",
            expected_prefix="account",
        )
        validate_resource_ref(
            self.resource_ref,
            field_name="fact_key.resource_ref",
        )
        if self.resource_level != "campaign":
            raise ClosedValidationError(
                "fact_key.resource_level: must equal 'campaign'"
            )
        validate_iso_date(self.metric_date, field_name="fact_key.metric_date")
        validate_opaque_ref(
            self.metric_semantic_ref,
            field_name="fact_key.metric_semantic_ref",
            expected_prefix="metric",
        )
        validate_source_metric_ref(
            self.source_metric_ref, field_name="fact_key.source_metric_ref"
        )
        validate_opaque_ref(
            self.attribution_ref,
            field_name="fact_key.attribution_ref",
            expected_prefix="attribution",
        )
        validate_opaque_ref(
            self.breakdown_signature,
            field_name="fact_key.breakdown_signature",
            expected_prefix="breakdown",
        )

    @property
    def reconciliation_row_key(self) -> ReconciliationRowKey:
        return ReconciliationRowKey(
            resource_ref=self.resource_ref,
            metric_date=self.metric_date,
            resource_level=self.resource_level,
            breakdown_signature=self.breakdown_signature,
        )

    @property
    def canonical_metric_ref(self) -> str:
        return self.metric_semantic_ref

    def set_identity_array(self) -> list[str]:
        """Return `I(f)` exact 5-element JSON array (ADR-0001 §4.2 L569–573)."""
        return [
            self.resource_ref,
            self.metric_date,
            self.resource_level,
            self.breakdown_signature,
            self.metric_semantic_ref,
        ]

    def to_dict(self) -> dict[str, Any]:
        return {
            "binding_ref": self.binding_ref,
            "account_ref": self.account_ref,
            "resource_ref": self.resource_ref,
            "resource_level": self.resource_level,
            "metric_date": self.metric_date,
            "metric_semantic_ref": self.metric_semantic_ref,
            "source_metric_ref": self.source_metric_ref,
            "attribution_ref": self.attribution_ref,
            "breakdown_signature": self.breakdown_signature,
        }

    @classmethod
    def from_dict(cls, data: object) -> FactKey:
        mapping = require_exact_keys(data, _FACT_KEY_KEYS, label="fact_key")
        return cls(
            binding_ref=mapping["binding_ref"],
            account_ref=mapping["account_ref"],
            resource_ref=mapping["resource_ref"],
            resource_level=mapping["resource_level"],
            metric_date=mapping["metric_date"],
            metric_semantic_ref=mapping["metric_semantic_ref"],
            source_metric_ref=mapping["source_metric_ref"],
            attribution_ref=mapping["attribution_ref"],
            breakdown_signature=mapping["breakdown_signature"],
        )


@dataclass(frozen=True, slots=True)
class NormalizedCollectionFact:
    """Embedded 6-member `normalized_collection_fact/v1` object (ADR-0001 §4.2 L538–549)."""

    fact_key: FactKey
    presence_status: ProviderPresenceStatus
    value_type: ValueType | None
    raw_numeric_value: str | None
    unit: UnitType | None
    currency: str | None

    def __post_init__(self) -> None:
        if not isinstance(self.fact_key, FactKey):
            raise ClosedValidationError(
                "normalized_collection_fact.fact_key: expected FactKey"
            )
        if self.fact_key.source_metric_ref.startswith("source-metric:formula:"):
            raise UnsupportedDerivedCollectionFactError(
                "normalized_collection_fact: derived formula source_metric_ref is forbidden "
                f"in provider collection facts ({self.fact_key.source_metric_ref!r})"
            )
        if (
            not isinstance(self.presence_status, str)
            or self.presence_status not in PROVIDER_PRESENCE_TO_UNKNOWN_REASON
        ):
            raise ClosedValidationError(
                "normalized_collection_fact.presence_status: invalid provider presence_status "
                f"{self.presence_status!r}"
            )
        inferred_qc = (
            self.currency
            if isinstance(self.currency, str) and len(self.currency) > 0
            else "BRL"
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
            query_currency=inferred_qc,
        )
        _enforce_base_metric_compatibility(
            metric_semantic_ref=self.fact_key.metric_semantic_ref,
            value_type=self.value_type,
            unit=self.unit,
            currency=self.currency,
            label="normalized_collection_fact",
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "fact_key": self.fact_key.to_dict(),
            "presence_status": self.presence_status,
            "value_type": self.value_type,
            "raw_numeric_value": self.raw_numeric_value,
            "unit": self.unit,
            "currency": self.currency,
        }

    @classmethod
    def from_dict(cls, data: object) -> NormalizedCollectionFact:
        mapping = require_exact_keys(
            data, _NORMALIZED_FACT_KEYS, label="normalized_collection_fact"
        )
        return cls(
            fact_key=FactKey.from_dict(mapping["fact_key"]),
            presence_status=mapping["presence_status"],
            value_type=mapping["value_type"],
            raw_numeric_value=mapping["raw_numeric_value"],
            unit=mapping["unit"],
            currency=mapping["currency"],
        )


def compute_normalized_fact_set_digest(
    facts: Sequence[NormalizedCollectionFact],
) -> tuple[tuple[NormalizedCollectionFact, ...], str]:
    """Validate, sort by `RFC8785(I(f))`, and hash a complete `normalized_fact_set`."""
    if isinstance(facts, (str, bytes)) or not isinstance(facts, Sequence):
        raise ClosedValidationError(
            f"normalized_fact_set: expected non-empty Sequence of NormalizedCollectionFact, "
            f"got {type(facts).__name__}"
        )
    if len(facts) == 0:
        raise ClosedValidationError(
            "normalized_fact_set: complete normalized fact set must not be empty"
        )
    keyed: list[tuple[bytes, NormalizedCollectionFact]] = []
    seen_identities: set[bytes] = set()
    for item in facts:
        if not isinstance(item, NormalizedCollectionFact):
            raise ClosedValidationError(
                "normalized_fact_set: every item must be NormalizedCollectionFact"
            )
        if item.presence_status not in {"observed", "retracted_tombstone"}:
            raise ClosedValidationError(
                "normalized_fact_set: complete facts require presence_status in "
                f"{{'observed', 'retracted_tombstone'}}, got {item.presence_status!r}"
            )
        if item.fact_key.attribution_ref != "attribution:not_applicable":
            raise ClosedValidationError(
                "normalized_fact_set: Phase 1 facts must use single "
                "'attribution:not_applicable' attribution_ref"
            )
        identity_bytes = canonicalize_jcs(item.fact_key.set_identity_array())
        if identity_bytes in seen_identities:
            raise ClosedValidationError(
                f"normalized_fact_set: duplicate I(f) identity {identity_bytes!r}"
            )
        seen_identities.add(identity_bytes)
        keyed.append((identity_bytes, item))

    keyed.sort(key=lambda pair: pair[0])
    sorted_facts = tuple(fact for _, fact in keyed)
    digest = domain_jcs_sha256(
        ADR_DATA_DOMAIN_PREFIXES["normalized_fact_set"],
        [fact.to_dict() for fact in sorted_facts],
    )
    return sorted_facts, digest


def compute_fact_projection_digest(fact: NormalizedCollectionFact) -> str:
    """Compute 7B `fact_projection_digest` over complete `X(f)` (ADR-0001 §5.4 L1178–1182)."""
    if not isinstance(fact, NormalizedCollectionFact):
        raise ClosedValidationError(
            f"fact: expected NormalizedCollectionFact, got {type(fact).__name__}"
        )
    return domain_jcs_sha256(
        ADR_DATA_DOMAIN_PREFIXES["7b_fact_projection"],
        fact.to_dict(),
    )


@dataclass(frozen=True, slots=True)
class RetrievalContext:
    """Enclosing collection retrieval provenance (ADR-0001 §§4.2, 6.1)."""

    retrieved_at_utc: str
    source_observation_ref: str
    adapter_version: str
    semantic_version: str

    def __post_init__(self) -> None:
        validate_timestamp_utc6(
            self.retrieved_at_utc, field_name="retrieval_context.retrieved_at_utc"
        )
        validate_opaque_ref(
            self.source_observation_ref,
            field_name="retrieval_context.source_observation_ref",
            expected_prefix="observation",
        )
        validate_non_empty_str(
            self.adapter_version, field_name="retrieval_context.adapter_version"
        )
        validate_non_empty_str(
            self.semantic_version, field_name="retrieval_context.semantic_version"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "retrieved_at_utc": self.retrieved_at_utc,
            "source_observation_ref": self.source_observation_ref,
            "adapter_version": self.adapter_version,
            "semantic_version": self.semantic_version,
        }

    @classmethod
    def from_dict(cls, data: object) -> RetrievalContext:
        mapping = require_exact_keys(
            data, _RETRIEVAL_CONTEXT_KEYS, label="retrieval_context"
        )
        return cls(
            retrieved_at_utc=mapping["retrieved_at_utc"],
            source_observation_ref=mapping["source_observation_ref"],
            adapter_version=mapping["adapter_version"],
            semantic_version=mapping["semantic_version"],
        )


@dataclass(frozen=True, slots=True)
class SemanticObservationProjection:
    """Closed 13-member `smart_ads/semantic_observation_projection/v1` (ADR-0001 §6.1 L1526–1553)."""

    SCHEMA: ClassVar[str] = "smart_ads/semantic_observation_projection/v1"

    fact_key: FactKey
    value_type: ValueType | None
    raw_numeric_value: str | None
    unit: UnitType | None
    currency: str | None
    metric_origin: MetricOrigin
    presence_status: PresenceStatus
    unknown_reason: UnknownReason | None
    calculation_status: CalculationStatus
    collected_at_utc: str
    source_observation_ref: str
    adapter_version: str
    semantic_version: str

    def __post_init__(self) -> None:
        if not isinstance(self.fact_key, FactKey):
            raise ClosedValidationError(
                "semantic_observation_projection.fact_key: expected FactKey"
            )
        inferred_qc = (
            self.currency
            if isinstance(self.currency, str) and len(self.currency) > 0
            else "BRL"
        )
        validate_numeric_state(
            metric_origin=self.metric_origin,
            presence_status=self.presence_status,
            calculation_status=self.calculation_status,
            unknown_reason=self.unknown_reason,
            value_type=self.value_type,
            raw_numeric_value=self.raw_numeric_value,
            unit=self.unit,
            currency=self.currency,
            query_currency=inferred_qc,
        )
        _enforce_origin_vs_source_metric_ref(
            metric_origin=self.metric_origin,
            source_metric_ref=self.fact_key.source_metric_ref,
            label="semantic_observation_projection",
        )
        _enforce_base_metric_compatibility(
            metric_semantic_ref=self.fact_key.metric_semantic_ref,
            value_type=self.value_type,
            unit=self.unit,
            currency=self.currency,
            label="semantic_observation_projection",
        )
        validate_timestamp_utc6(
            self.collected_at_utc,
            field_name="semantic_observation_projection.collected_at_utc",
        )
        validate_opaque_ref(
            self.source_observation_ref,
            field_name="semantic_observation_projection.source_observation_ref",
            expected_prefix="observation",
        )
        validate_non_empty_str(
            self.adapter_version,
            field_name="semantic_observation_projection.adapter_version",
        )
        validate_non_empty_str(
            self.semantic_version,
            field_name="semantic_observation_projection.semantic_version",
        )

    def compute_digest(self) -> str:
        """Compute `SMART-ADS:SEMANTIC-OBSERVATION:V1\\n` JCS SHA-256 digest."""
        return domain_jcs_sha256(
            ADR_DATA_DOMAIN_PREFIXES["semantic_observation"],
            self.to_dict(),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "$schema": self.SCHEMA,
            "fact_key": self.fact_key.to_dict(),
            "numeric": {
                "_type": self.value_type,
                "value": self.raw_numeric_value,
            },
            "unit": self.unit,
            "currency": self.currency,
            "metric_origin": self.metric_origin,
            "presence_status": self.presence_status,
            "unknown_reason": self.unknown_reason,
            "calculation_status": self.calculation_status,
            "collected_at_utc": self.collected_at_utc,
            "source_observation_ref": self.source_observation_ref,
            "adapter_version": self.adapter_version,
            "semantic_version": self.semantic_version,
        }

    @classmethod
    def from_dict(cls, data: object) -> SemanticObservationProjection:
        mapping = require_exact_keys(
            data,
            _SEMANTIC_PROJECTION_KEYS,
            label="semantic_observation_projection",
        )
        if mapping["$schema"] != cls.SCHEMA:
            raise ClosedValidationError(
                f"semantic_observation_projection.$schema: expected {cls.SCHEMA!r}, "
                f"got {mapping['$schema']!r}"
            )
        numeric_box = require_exact_keys(
            mapping["numeric"],
            _NUMERIC_BOX_KEYS,
            label="semantic_observation_projection.numeric",
        )
        return cls(
            fact_key=FactKey.from_dict(mapping["fact_key"]),
            value_type=numeric_box["_type"],
            raw_numeric_value=numeric_box["value"],
            unit=mapping["unit"],
            currency=mapping["currency"],
            metric_origin=mapping["metric_origin"],
            presence_status=mapping["presence_status"],
            unknown_reason=mapping["unknown_reason"],
            calculation_status=mapping["calculation_status"],
            collected_at_utc=mapping["collected_at_utc"],
            source_observation_ref=mapping["source_observation_ref"],
            adapter_version=mapping["adapter_version"],
            semantic_version=mapping["semantic_version"],
        )


@dataclass(frozen=True, slots=True)
class AnalyticsLandingRow:
    """Sole canonical 16-member `smart_ads/analytics_landing_row/v1` (ADR-0001 §6.1)."""

    SCHEMA: ClassVar[str] = "smart_ads/analytics_landing_row/v1"

    fact_key: FactKey
    value_type: ValueType | None
    raw_numeric_value: str | None
    unit: UnitType | None
    currency: str | None
    metric_origin: MetricOrigin
    presence_status: PresenceStatus
    unknown_reason: UnknownReason | None
    calculation_status: CalculationStatus
    collected_at_utc: str
    source_observation_ref: str
    adapter_version: str
    semantic_version: str
    semantic_observation_digest: str = ""
    row_digest: str = ""

    def __post_init__(self) -> None:
        projection = SemanticObservationProjection(
            fact_key=self.fact_key,
            value_type=self.value_type,
            raw_numeric_value=self.raw_numeric_value,
            unit=self.unit,
            currency=self.currency,
            metric_origin=self.metric_origin,
            presence_status=self.presence_status,
            unknown_reason=self.unknown_reason,
            calculation_status=self.calculation_status,
            collected_at_utc=self.collected_at_utc,
            source_observation_ref=self.source_observation_ref,
            adapter_version=self.adapter_version,
            semantic_version=self.semantic_version,
        )
        if not isinstance(self.semantic_observation_digest, str):
            raise ClosedValidationError(
                "analytics_landing_row.semantic_observation_digest: expected str"
            )
        if not isinstance(self.row_digest, str):
            raise ClosedValidationError(
                "analytics_landing_row.row_digest: expected str"
            )

        expected_sem_digest = projection.compute_digest()
        if self.semantic_observation_digest == "":
            object.__setattr__(
                self, "semantic_observation_digest", expected_sem_digest
            )
        else:
            validate_sha256_prefixed(
                self.semantic_observation_digest,
                field_name="analytics_landing_row.semantic_observation_digest",
            )
            if self.semantic_observation_digest != expected_sem_digest:
                raise ClosedValidationError(
                    "analytics_landing_row.semantic_observation_digest: recomputed "
                    f"{expected_sem_digest!r} != asserted {self.semantic_observation_digest!r}"
                )

        expected_row_digest = self_digest_jcs_sha256(
            self.to_dict(),
            digest_member="row_digest",
            domain_prefix=ADR_DATA_DOMAIN_PREFIXES["row"],
            strip_integrity=False,
        )
        if self.row_digest == "":
            object.__setattr__(self, "row_digest", expected_row_digest)
        else:
            validate_sha256_prefixed(
                self.row_digest,
                field_name="analytics_landing_row.row_digest",
            )
            if self.row_digest != expected_row_digest:
                raise ClosedValidationError(
                    "analytics_landing_row.row_digest: recomputed "
                    f"{expected_row_digest!r} != asserted {self.row_digest!r}"
                )

    def candidate_sort_key_jcs(self) -> bytes:
        """Return RFC 8785 bytes of `K = [fact_key, collected_at_utc, semantic_observation_digest]`."""
        return canonicalize_jcs(
            [
                self.fact_key.to_dict(),
                self.collected_at_utc,
                self.semantic_observation_digest,
            ]
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "$schema": self.SCHEMA,
            "fact_key": self.fact_key.to_dict(),
            "value_type": self.value_type,
            "raw_numeric_value": self.raw_numeric_value,
            "unit": self.unit,
            "currency": self.currency,
            "metric_origin": self.metric_origin,
            "presence_status": self.presence_status,
            "unknown_reason": self.unknown_reason,
            "calculation_status": self.calculation_status,
            "collected_at_utc": self.collected_at_utc,
            "source_observation_ref": self.source_observation_ref,
            "adapter_version": self.adapter_version,
            "semantic_version": self.semantic_version,
            "semantic_observation_digest": self.semantic_observation_digest,
            "row_digest": self.row_digest,
        }

    @classmethod
    def from_dict(cls, data: object) -> AnalyticsLandingRow:
        mapping = require_exact_keys(
            data, _LANDING_ROW_KEYS, label="analytics_landing_row"
        )
        if mapping["$schema"] != cls.SCHEMA:
            raise ClosedValidationError(
                f"analytics_landing_row.$schema: expected {cls.SCHEMA!r}, got {mapping['$schema']!r}"
            )
        sem_digest = validate_sha256_prefixed(
            mapping["semantic_observation_digest"],
            field_name="analytics_landing_row.semantic_observation_digest",
        )
        r_digest = validate_sha256_prefixed(
            mapping["row_digest"],
            field_name="analytics_landing_row.row_digest",
        )
        return cls(
            fact_key=FactKey.from_dict(mapping["fact_key"]),
            value_type=mapping["value_type"],
            raw_numeric_value=mapping["raw_numeric_value"],
            unit=mapping["unit"],
            currency=mapping["currency"],
            metric_origin=mapping["metric_origin"],
            presence_status=mapping["presence_status"],
            unknown_reason=mapping["unknown_reason"],
            calculation_status=mapping["calculation_status"],
            collected_at_utc=mapping["collected_at_utc"],
            source_observation_ref=mapping["source_observation_ref"],
            adapter_version=mapping["adapter_version"],
            semantic_version=mapping["semantic_version"],
            semantic_observation_digest=sem_digest,
            row_digest=r_digest,
        )


def project_collection_fact_to_landing_row(
    fact: NormalizedCollectionFact,
    retrieval_context: RetrievalContext,
    *,
    query_currency: str = "BRL",
) -> AnalyticsLandingRow:
    """Deterministically project one `NormalizedCollectionFact` + `RetrievalContext` to `AnalyticsLandingRow`."""
    if not isinstance(fact, NormalizedCollectionFact):
        raise ClosedValidationError(
            f"fact: expected NormalizedCollectionFact, got {type(fact).__name__}"
        )
    if not isinstance(retrieval_context, RetrievalContext):
        raise ClosedValidationError(
            f"retrieval_context: expected RetrievalContext, got {type(retrieval_context).__name__}"
        )
    unknown_reason = PROVIDER_PRESENCE_TO_UNKNOWN_REASON[fact.presence_status]
    validate_numeric_state(
        metric_origin="provider_observation",
        presence_status=fact.presence_status,
        calculation_status="not_applicable",
        unknown_reason=unknown_reason,
        value_type=fact.value_type,
        raw_numeric_value=fact.raw_numeric_value,
        unit=fact.unit,
        currency=fact.currency,
        query_currency=query_currency,
    )
    return AnalyticsLandingRow(
        fact_key=fact.fact_key,
        value_type=fact.value_type,
        raw_numeric_value=fact.raw_numeric_value,
        unit=fact.unit,
        currency=fact.currency,
        metric_origin="provider_observation",
        presence_status=fact.presence_status,
        unknown_reason=unknown_reason,
        calculation_status="not_applicable",
        collected_at_utc=retrieval_context.retrieved_at_utc,
        source_observation_ref=retrieval_context.source_observation_ref,
        adapter_version=retrieval_context.adapter_version,
        semantic_version=retrieval_context.semantic_version,
    )


@dataclass(frozen=True, slots=True)
class TransportOutcome:
    """Closed 11-field sanitized transport outcome."""

    network_ok: bool
    http_status: int | None
    media_and_encoding_valid: bool
    auth_ok: bool
    jsonrpc_error: bool
    payload_schema_valid: bool
    response_date_mismatch: bool
    truncated_2mib: bool
    non_empty_continuation: bool
    reducer_order_or_count_mismatch: bool
    duplicate_provider_observation: bool

    def __post_init__(self) -> None:
        if self.http_status is not None and (
            isinstance(self.http_status, bool)
            or not isinstance(self.http_status, int)
            or not (100 <= self.http_status <= 999)
        ):
            raise ClosedValidationError(
                f"transport_outcome.http_status: expected 3-digit HTTP int or None, "
                f"got {self.http_status!r}"
            )
        for flag_name in (
            "network_ok",
            "media_and_encoding_valid",
            "auth_ok",
            "jsonrpc_error",
            "payload_schema_valid",
            "response_date_mismatch",
            "truncated_2mib",
            "non_empty_continuation",
            "reducer_order_or_count_mismatch",
            "duplicate_provider_observation",
        ):
            val = getattr(self, flag_name)
            if not isinstance(val, bool):
                raise ClosedValidationError(
                    f"transport_outcome.{flag_name}: expected bool, got {type(val).__name__}"
                )

    def to_dict(self) -> dict[str, Any]:
        return {
            "network_ok": self.network_ok,
            "http_status": self.http_status,
            "media_and_encoding_valid": self.media_and_encoding_valid,
            "auth_ok": self.auth_ok,
            "jsonrpc_error": self.jsonrpc_error,
            "payload_schema_valid": self.payload_schema_valid,
            "response_date_mismatch": self.response_date_mismatch,
            "truncated_2mib": self.truncated_2mib,
            "non_empty_continuation": self.non_empty_continuation,
            "reducer_order_or_count_mismatch": self.reducer_order_or_count_mismatch,
            "duplicate_provider_observation": self.duplicate_provider_observation,
        }

    @classmethod
    def from_dict(cls, data: object) -> TransportOutcome:
        mapping = require_exact_keys(
            data, _TRANSPORT_OUTCOME_KEYS, label="transport_outcome"
        )
        return cls(
            network_ok=mapping["network_ok"],
            http_status=mapping["http_status"],
            media_and_encoding_valid=mapping["media_and_encoding_valid"],
            auth_ok=mapping["auth_ok"],
            jsonrpc_error=mapping["jsonrpc_error"],
            payload_schema_valid=mapping["payload_schema_valid"],
            response_date_mismatch=mapping["response_date_mismatch"],
            truncated_2mib=mapping["truncated_2mib"],
            non_empty_continuation=mapping["non_empty_continuation"],
            reducer_order_or_count_mismatch=mapping["reducer_order_or_count_mismatch"],
            duplicate_provider_observation=mapping["duplicate_provider_observation"],
        )


@dataclass(frozen=True, slots=True)
class NormalizedProviderError:
    """Sanitized 3-field provider error descriptor."""

    error_code: str
    category: ProviderErrorCategory
    sanitized_detail: str

    def __post_init__(self) -> None:
        validate_non_empty_str(
            self.error_code, field_name="normalized_provider_error.error_code"
        )
        if (
            not isinstance(self.category, str)
            or self.category not in _ALLOWED_ERROR_CATEGORIES
        ):
            raise ClosedValidationError(
                f"normalized_provider_error.category: invalid category {self.category!r}"
            )
        validate_non_empty_str(
            self.sanitized_detail,
            field_name="normalized_provider_error.sanitized_detail",
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "error_code": self.error_code,
            "category": self.category,
            "sanitized_detail": self.sanitized_detail,
        }

    @classmethod
    def from_dict(cls, data: object) -> NormalizedProviderError:
        mapping = require_exact_keys(
            data, _NORMALIZED_ERROR_KEYS, label="normalized_provider_error"
        )
        return cls(
            error_code=mapping["error_code"],
            category=mapping["category"],
            sanitized_detail=mapping["sanitized_detail"],
        )


@dataclass(frozen=True, slots=True)
class CollectionResult:
    """Closed `smart_ads/collection_result/v1` with NO `status` member (ADR-0001 §4.2)."""

    SCHEMA: ClassVar[str] = "smart_ads/collection_result/v1"

    admitted_collection_locator: ArtifactLocator
    admitted_collection_digest: str
    call_side: CallSide
    registry_snapshot_locator: ArtifactLocator
    registry_snapshot_digest: str
    requested_capabilities: tuple[str, ...]
    observed_capabilities: tuple[str, ...]
    retrieval_context: RetrievalContext
    transport_outcome: TransportOutcome
    candidates: tuple[AnalyticsLandingRow, ...]
    normalized_fact_set: tuple[NormalizedCollectionFact, ...] | None
    normalized_fact_set_digest: str | None
    normalized_errors: tuple[NormalizedProviderError, ...]
    integrity: P1Integrity | None = None

    def __post_init__(self) -> None:
        _require_locator_instance(
            self.admitted_collection_locator,
            field_name="collection_result.admitted_collection_locator",
            expected_type="smart_ads/admitted_collection/v1",
        )
        validate_sha256_prefixed(
            self.admitted_collection_digest,
            field_name="collection_result.admitted_collection_digest",
        )
        if (
            self.admitted_collection_digest
            != self.admitted_collection_locator.content_digest
        ):
            raise ClosedValidationError(
                "collection_result.admitted_collection_digest: must equal "
                "admitted_collection_locator.content_digest"
            )

        if not isinstance(self.call_side, str) or self.call_side not in _ALLOWED_CALL_SIDES:
            raise ClosedValidationError(
                f"collection_result.call_side: expected one of {sorted(_ALLOWED_CALL_SIDES)}, "
                f"got {self.call_side!r}"
            )

        _require_locator_instance(
            self.registry_snapshot_locator,
            field_name="collection_result.registry_snapshot_locator",
            expected_type="smart_ads/private_registry_snapshot/v1",
        )
        validate_sha256_prefixed(
            self.registry_snapshot_digest,
            field_name="collection_result.registry_snapshot_digest",
        )
        if (
            self.registry_snapshot_digest
            != self.registry_snapshot_locator.content_digest
        ):
            raise ClosedValidationError(
                "collection_result.registry_snapshot_digest: must equal "
                "registry_snapshot_locator.content_digest"
            )

        sorted_req_caps = _validate_sorted_opaque_refs(
            self.requested_capabilities,
            field_name="collection_result.requested_capabilities",
            expected_prefix="cap",
            allow_empty=False,
        )
        object.__setattr__(self, "requested_capabilities", sorted_req_caps)

        sorted_obs_caps = _validate_sorted_opaque_refs(
            self.observed_capabilities,
            field_name="collection_result.observed_capabilities",
            expected_prefix="cap",
            allow_empty=True,
        )
        object.__setattr__(self, "observed_capabilities", sorted_obs_caps)

        if not isinstance(self.retrieval_context, RetrievalContext):
            raise ClosedValidationError(
                "collection_result.retrieval_context: expected RetrievalContext"
            )
        if not isinstance(self.transport_outcome, TransportOutcome):
            raise ClosedValidationError(
                "collection_result.transport_outcome: expected TransportOutcome"
            )

        if not isinstance(self.candidates, (list, tuple)):
            raise ClosedValidationError(
                "collection_result.candidates: expected list or tuple of AnalyticsLandingRow"
            )
        candidate_tuple = tuple(self.candidates)
        candidate_sort_keys: list[bytes] = []
        for row in candidate_tuple:
            if not isinstance(row, AnalyticsLandingRow):
                raise ClosedValidationError(
                    "collection_result.candidates: every element must be AnalyticsLandingRow"
                )
            if row.collected_at_utc != self.retrieval_context.retrieved_at_utc:
                raise ClosedValidationError(
                    "collection_result.candidates: row.collected_at_utc must equal "
                    "retrieval_context.retrieved_at_utc"
                )
            if row.source_observation_ref != self.retrieval_context.source_observation_ref:
                raise ClosedValidationError(
                    "collection_result.candidates: row.source_observation_ref must equal "
                    "retrieval_context.source_observation_ref"
                )
            if row.adapter_version != self.retrieval_context.adapter_version:
                raise ClosedValidationError(
                    "collection_result.candidates: row.adapter_version must equal "
                    "retrieval_context.adapter_version"
                )
            if row.semantic_version != self.retrieval_context.semantic_version:
                raise ClosedValidationError(
                    "collection_result.candidates: row.semantic_version must equal "
                    "retrieval_context.semantic_version"
                )
            candidate_sort_keys.append(row.candidate_sort_key_jcs())

        for prev_key, curr_key in zip(candidate_sort_keys, candidate_sort_keys[1:]):
            if not (prev_key <= curr_key):
                raise ClosedValidationError(
                    "collection_result.candidates: candidates must be sorted in "
                    "non-decreasing candidate_sort_key_jcs() order"
                )

        candidate_currencies = {
            r.currency
            for r in candidate_tuple
            if r.value_type == "int64_minor_currency"
        }
        if len(candidate_currencies) > 1:
            raise ClosedValidationError(
                "collection_result.candidates: multiple currencies across candidate rows "
                "are forbidden"
            )
        object.__setattr__(self, "candidates", candidate_tuple)

        if self.normalized_fact_set is None:
            if self.normalized_fact_set_digest is not None:
                raise ClosedValidationError(
                    "collection_result: normalized_fact_set and normalized_fact_set_digest "
                    "must both be None or both be non-None"
                )
        else:
            if self.normalized_fact_set_digest is None:
                raise ClosedValidationError(
                    "collection_result: normalized_fact_set and normalized_fact_set_digest "
                    "must both be None or both be non-None"
                )
            if not isinstance(self.normalized_fact_set, (list, tuple)):
                raise ClosedValidationError(
                    "collection_result.normalized_fact_set: expected list or tuple"
                )
            validate_sha256_prefixed(
                self.normalized_fact_set_digest,
                field_name="collection_result.normalized_fact_set_digest",
            )
            to = self.transport_outcome
            if not (
                to.network_ok is True
                and to.http_status == 200
                and to.media_and_encoding_valid is True
                and to.auth_ok is True
                and to.jsonrpc_error is False
                and to.payload_schema_valid is True
                and to.response_date_mismatch is False
                and to.truncated_2mib is False
                and to.non_empty_continuation is False
                and to.reducer_order_or_count_mismatch is False
                and to.duplicate_provider_observation is False
            ):
                raise ClosedValidationError(
                    "collection_result: non-null normalized_fact_set requires all "
                    "transport_outcome complete-eligibility flags to be clean"
                )
            fact_tuple = tuple(self.normalized_fact_set)
            sorted_facts, recomputed_digest = compute_normalized_fact_set_digest(
                fact_tuple
            )
            if fact_tuple != sorted_facts:
                raise ClosedValidationError(
                    "collection_result.normalized_fact_set: must already be sorted by RFC8785(I(f))"
                )
            if self.normalized_fact_set_digest != recomputed_digest:
                raise ClosedValidationError(
                    "collection_result.normalized_fact_set_digest: recomputed "
                    f"{recomputed_digest!r} != asserted {self.normalized_fact_set_digest!r}"
                )
            for prev_key, curr_key in zip(
                candidate_sort_keys, candidate_sort_keys[1:]
            ):
                if not (prev_key < curr_key):
                    raise ClosedValidationError(
                        "collection_result.candidates: complete result requires strictly "
                        "increasing unique candidate_sort_key_jcs() keys"
                    )
            if len(candidate_tuple) != len(fact_tuple) or len(candidate_tuple) == 0:
                raise ClosedValidationError(
                    "collection_result.candidates: complete result requires non-empty "
                    "1-to-1 candidate count matching normalized_fact_set"
                )
            fact_currencies = {
                f.currency
                for f in fact_tuple
                if f.value_type == "int64_minor_currency" and f.currency is not None
            }
            if len(fact_currencies) > 1:
                raise ClosedValidationError(
                    "collection_result.normalized_fact_set: multiple currencies across "
                    "facts are forbidden"
                )
            inferred_qc = next(iter(fact_currencies), "BRL")
            expected_candidates = tuple(
                sorted(
                    (
                        project_collection_fact_to_landing_row(
                            f,
                            retrieval_context=self.retrieval_context,
                            query_currency=inferred_qc,
                        )
                        for f in fact_tuple
                    ),
                    key=lambda r: r.candidate_sort_key_jcs(),
                )
            )
            if candidate_tuple != expected_candidates:
                raise ClosedValidationError(
                    "collection_result.candidates: complete result requires exact 1-to-1 "
                    "equality between candidates and projected normalized_fact_set rows"
                )
            object.__setattr__(self, "normalized_fact_set", fact_tuple)

        if not isinstance(self.normalized_errors, (list, tuple)):
            raise ClosedValidationError(
                "collection_result.normalized_errors: expected list or tuple"
            )
        for err in self.normalized_errors:
            if not isinstance(err, NormalizedProviderError):
                raise ClosedValidationError(
                    "collection_result.normalized_errors: every element must be NormalizedProviderError"
                )
        object.__setattr__(self, "normalized_errors", tuple(self.normalized_errors))

        if self.integrity is not None and not isinstance(self.integrity, P1Integrity):
            raise ClosedValidationError(
                "collection_result.integrity: expected P1Integrity or None"
            )
        if self.integrity is not None and self.integrity.is_signed:
            expected_p1 = p1_content_digest(self.to_dict())
            if self.integrity.content_digest != expected_p1:
                raise ClosedValidationError(
                    "collection_result.integrity.content_digest: recomputed "
                    f"{expected_p1!r} != asserted {self.integrity.content_digest!r}"
                )

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "$schema": self.SCHEMA,
            "admitted_collection_locator": self.admitted_collection_locator.to_dict(),
            "admitted_collection_digest": self.admitted_collection_digest,
            "call_side": self.call_side,
            "registry_snapshot_locator": self.registry_snapshot_locator.to_dict(),
            "registry_snapshot_digest": self.registry_snapshot_digest,
            "requested_capabilities": list(self.requested_capabilities),
            "observed_capabilities": list(self.observed_capabilities),
            "retrieval_context": self.retrieval_context.to_dict(),
            "transport_outcome": self.transport_outcome.to_dict(),
            "candidates": [row.to_dict() for row in self.candidates],
            "normalized_fact_set": (
                None
                if self.normalized_fact_set is None
                else [fact.to_dict() for fact in self.normalized_fact_set]
            ),
            "normalized_fact_set_digest": self.normalized_fact_set_digest,
            "normalized_errors": [err.to_dict() for err in self.normalized_errors],
        }
        if self.integrity is not None:
            out["integrity"] = self.integrity.to_dict()
        return out

    @classmethod
    def from_dict(
        cls,
        data: object,
        *,
        require_signed: bool = False,
    ) -> CollectionResult:
        if not isinstance(require_signed, bool):
            raise ClosedValidationError("require_signed: expected bool")
        mapping = require_mapping(data, label="collection_result")
        if require_signed or "integrity" in mapping:
            require_exact_keys(
                mapping,
                _COLLECTION_RESULT_CORE_KEYS | {"integrity"},
                label="collection_result",
            )
            integrity: P1Integrity | None = P1Integrity.from_dict(
                mapping["integrity"], require_signed=require_signed
            )
        else:
            require_exact_keys(
                mapping, _COLLECTION_RESULT_CORE_KEYS, label="collection_result"
            )
            integrity = None

        if mapping["$schema"] != cls.SCHEMA:
            raise ClosedValidationError(
                f"collection_result.$schema: expected {cls.SCHEMA!r}, got {mapping['$schema']!r}"
            )
        if not isinstance(mapping["requested_capabilities"], list):
            raise ClosedValidationError(
                "collection_result.requested_capabilities: expected JSON array list"
            )
        if not isinstance(mapping["observed_capabilities"], list):
            raise ClosedValidationError(
                "collection_result.observed_capabilities: expected JSON array list"
            )
        if not isinstance(mapping["candidates"], list):
            raise ClosedValidationError(
                "collection_result.candidates: expected JSON array list"
            )
        if not isinstance(mapping["normalized_errors"], list):
            raise ClosedValidationError(
                "collection_result.normalized_errors: expected JSON array list"
            )

        req_caps = _validate_sorted_opaque_refs(
            mapping["requested_capabilities"],
            field_name="collection_result.requested_capabilities",
            expected_prefix="cap",
            allow_empty=False,
            require_already_sorted=True,
        )
        obs_caps = _validate_sorted_opaque_refs(
            mapping["observed_capabilities"],
            field_name="collection_result.observed_capabilities",
            expected_prefix="cap",
            allow_empty=True,
            require_already_sorted=True,
        )
        parsed_candidates = tuple(
            AnalyticsLandingRow.from_dict(item) for item in mapping["candidates"]
        )
        candidate_keys = [row.candidate_sort_key_jcs() for row in parsed_candidates]
        if candidate_keys != sorted(candidate_keys):
            raise ClosedValidationError(
                "collection_result.candidates: candidates must be sorted by ascending K"
            )

        raw_fact_set = mapping["normalized_fact_set"]
        if raw_fact_set is None:
            parsed_fact_set: tuple[NormalizedCollectionFact, ...] | None = None
        else:
            if not isinstance(raw_fact_set, list):
                raise ClosedValidationError(
                    "collection_result.normalized_fact_set: expected JSON array list or null"
                )
            parsed_fact_set = tuple(
                NormalizedCollectionFact.from_dict(item) for item in raw_fact_set
            )

        parsed_errors = tuple(
            NormalizedProviderError.from_dict(item)
            for item in mapping["normalized_errors"]
        )
        return cls(
            admitted_collection_locator=ArtifactLocator.from_dict(
                mapping["admitted_collection_locator"],
                expected_type="smart_ads/admitted_collection/v1",
            ),
            admitted_collection_digest=mapping["admitted_collection_digest"],
            call_side=mapping["call_side"],
            registry_snapshot_locator=ArtifactLocator.from_dict(
                mapping["registry_snapshot_locator"],
                expected_type="smart_ads/private_registry_snapshot/v1",
            ),
            registry_snapshot_digest=mapping["registry_snapshot_digest"],
            requested_capabilities=req_caps,
            observed_capabilities=obs_caps,
            retrieval_context=RetrievalContext.from_dict(mapping["retrieval_context"]),
            transport_outcome=TransportOutcome.from_dict(mapping["transport_outcome"]),
            candidates=parsed_candidates,
            normalized_fact_set=parsed_fact_set,
            normalized_fact_set_digest=mapping["normalized_fact_set_digest"],
            normalized_errors=parsed_errors,
            integrity=integrity,
        )


def _build_descriptor(schema_id: str, fields: Sequence[str]) -> Mapping[str, Any]:
    sorted_fields = tuple(sorted(fields, key=lambda s: s.encode("utf-8")))
    return MappingProxyType(
        {
            "schema_id": schema_id,
            "fields": sorted_fields,
            "p1_domain_prefix": ADR_P1_DOMAIN_PREFIXES.get(schema_id),
        }
    )


_RAW_CORE_SCHEMAS: Final[tuple[tuple[str, tuple[str, ...]], ...]] = (
    (
        "smart_ads/artifact_locator/v1",
        (
            "$schema",
            "artifact_type",
            "content_digest",
            "object_ref",
            "serialization",
            "store_kind",
        ),
    ),
    (
        "smart_ads/base_metric_definition/v1",
        (
            "$schema",
            "aggregation_semantics",
            "canonical_name",
            "currency_rule",
            "dimensions",
            "integrity",
            "metric_definition_digest",
            "metric_semantic_ref",
            "unit",
            "value_type",
        ),
    ),
    (
        "smart_ads/canonical_query_contract/v1",
        tuple(_CANONICAL_QUERY_KEYS),
    ),
    (
        "smart_ads/admitted_collection/v1",
        tuple(_ADMITTED_COLLECTION_CORE_KEYS | {"integrity"}),
    ),
    (
        "smart_ads/normalized_collection_fact/v1",
        tuple(_NORMALIZED_FACT_KEYS),
    ),
    (
        "smart_ads/semantic_observation_projection/v1",
        tuple(_SEMANTIC_PROJECTION_KEYS),
    ),
    (
        "smart_ads/analytics_landing_row/v1",
        tuple(_LANDING_ROW_KEYS),
    ),
    (
        "smart_ads/collection_result/v1",
        tuple(_COLLECTION_RESULT_CORE_KEYS | {"integrity"}),
    ),
    (
        "smart_ads/private_registry_snapshot/v1",
        (
            "$schema",
            "authorized_scopes",
            "bindings",
            "capabilities",
            "domain_separator",
            "integrity",
            "issued_at_utc",
            "key_identity",
            "resource_mapping_contract_digest",
            "resource_ref_mapping_version",
            "snapshot_id",
            "tenant_ref",
            "valid_until_utc",
        ),
    ),
    (
        "smart_ads/expected_resource_inventory/v1",
        (
            "$schema",
            "account_ref",
            "binding_ref",
            "date_range",
            "expected_resources",
            "integrity",
            "inventory_id",
            "registry_snapshot_digest",
            "registry_snapshot_locator",
            "resource_scope_ref",
            "tenant_ref",
        ),
    ),
    (
        "smart_ads/capability_revalidation_transition/v1",
        (
            "$schema",
            "capability_ref",
            "capability_semantic_version",
            "cas_sequence",
            "driver_contract_digest",
            "fresh_evidence_locators",
            "integrity",
            "new_snapshot_digest",
            "new_snapshot_locator",
            "new_state",
            "pinned_source_digest",
            "prior_snapshot_digest",
            "prior_snapshot_locator",
            "prior_state",
            "reason",
            "required_metrics",
            "resource_scope_ref",
            "signer_principal_ref",
            "transition_id",
            "transition_kind",
            "transitioned_at_utc",
        ),
    ),
    (
        "smart_ads/capability_invalidation_transition/v1",
        (
            "$schema",
            "capability_ref",
            "cas_sequence",
            "disqualifying_evidence_locators",
            "integrity",
            "invalidated_live_certification_head_locator",
            "new_snapshot_digest",
            "new_snapshot_locator",
            "new_state",
            "prior_snapshot_digest",
            "prior_snapshot_locator",
            "prior_state",
            "reason",
            "signer_principal_ref",
            "transition_id",
            "transition_kind",
            "transitioned_at_utc",
        ),
    ),
    (
        "smart_ads/pipeboard_phase1_contract/v1",
        (
            "$schema",
            "contract_id",
            "driver_id",
            "integrity",
            "legacy_source_packet",
            "metric_source_mappings",
            "transport_limits",
            "upstream_reference",
        ),
    ),
)

CORE_SCHEMA_DESCRIPTORS: Final[tuple[Mapping[str, Any], ...]] = tuple(
    _build_descriptor(schema_id, fields)
    for schema_id, fields in sorted(
        _RAW_CORE_SCHEMAS, key=lambda pair: pair[0].encode("utf-8")
    )
)


def compute_schema_bundle_digest() -> str:
    """Compute canonical Gate-3 `schema_bundle_digest` over `CORE_SCHEMA_DESCRIPTORS`."""
    return domain_jcs_sha256(
        SUPPLEMENTAL_DOMAIN_PREFIXES["schema_bundle"],
        list(CORE_SCHEMA_DESCRIPTORS),
    )


__all__ = [
    "AdmittedCollection",
    "AnalyticsLandingRow",
    "CORE_SCHEMA_DESCRIPTORS",
    "CallSide",
    "CanonicalQueryContract",
    "CollectionPurpose",
    "CollectionRequest",
    "CollectionResult",
    "DateRange",
    "EffectRole",
    "FactKey",
    "NormalizedCollectionFact",
    "NormalizedProviderError",
    "PURPOSE_REQUIRED_EFFECT_ROLES",
    "ProviderErrorCategory",
    "PurposePrerequisiteLocators",
    "ReconciliationRowKey",
    "RetrievalContext",
    "SemanticObservationProjection",
    "TransportOutcome",
    "UnsupportedDerivedCollectionFactError",
    "compute_fact_projection_digest",
    "compute_normalized_fact_set_digest",
    "compute_schema_bundle_digest",
    "project_collection_fact_to_landing_row",
    "validate_source_metric_ref",
]
