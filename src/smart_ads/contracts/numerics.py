"""12-row closed numeric union and base metric definitions (ADR-0001 §§4.3, 5.5.1)."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import re
from types import MappingProxyType
from typing import Any, ClassVar, Final, Literal

from smart_ads.contracts.jcs import (
    P1Integrity,
    p1_content_digest,
    self_digest_jcs_sha256,
    sort_utf8_strings,
)
from smart_ads.contracts.scalars import (
    ClosedValidationError,
    require_exact_keys,
    require_mapping,
    validate_currency_iso4217,
    validate_sha256_prefixed,
)

MAX_INT64: Final[int] = (1 << 63) - 1

ValueType = Literal["int64_count", "int64_minor_currency", "decimal_ratio"]
UnitType = Literal["count", "minor_currency", "ratio"]
MetricOrigin = Literal["provider_observation", "derived_formula"]
PresenceStatus = Literal[
    "observed",
    "missing",
    "unproven_zero",
    "timeout",
    "not_applicable_at_level",
    "retracted_tombstone",
    "not_applicable",
]
ProviderPresenceStatus = Literal[
    "observed",
    "missing",
    "unproven_zero",
    "timeout",
    "not_applicable_at_level",
    "retracted_tombstone",
]
CalculationStatus = Literal[
    "not_applicable",
    "computed",
    "input_missing",
    "input_unproven",
    "division_by_zero",
]
UnknownReason = Literal[
    "provider_omitted",
    "provider_timeout",
    "zero_not_proven",
    "metric_not_applicable_at_level",
    "source_retracted",
    "input_missing",
    "input_unproven",
    "division_by_zero",
]
CurrencyRule = Literal["must_be_null", "must_be_query_currency"]
AggregationSemantics = Literal[
    "additive_across_none",
    "additive_within_resource",
    "non_additive",
]

_UNSIGNED_INT_RE: Final[re.Pattern[str]] = re.compile(r"\A(0|[1-9][0-9]*)\Z")
_DECIMAL_RATIO6_RE: Final[re.Pattern[str]] = re.compile(
    r"\A(0|[1-9][0-9]*)\.[0-9]{6}\Z"
)
_BRL_DECIMAL_RE: Final[re.Pattern[str]] = re.compile(
    r"\A(0|[1-9][0-9]*)(?:\.([0-9]{1,2}))?\Z"
)
_METRIC_SEMANTIC_REF_RE: Final[re.Pattern[str]] = re.compile(
    r"\Ametric:[a-z][a-z0-9_]*_v[1-9][0-9]*\Z"
)
_CANONICAL_NAME_RE: Final[re.Pattern[str]] = re.compile(r"\A[a-z][a-z0-9_]*\Z")

_VALUE_STATE_ROWS: Final[frozenset[tuple[str, str, str, None]]] = frozenset(
    {
        ("provider_observation", "observed", "not_applicable", None),
        ("derived_formula", "not_applicable", "computed", None),
    }
)
_NULL_STATE_ROWS: Final[frozenset[tuple[str, str, str, str]]] = frozenset(
    {
        ("provider_observation", "missing", "not_applicable", "provider_omitted"),
        ("provider_observation", "unproven_zero", "not_applicable", "zero_not_proven"),
        ("provider_observation", "timeout", "not_applicable", "provider_timeout"),
        (
            "provider_observation",
            "not_applicable_at_level",
            "not_applicable",
            "metric_not_applicable_at_level",
        ),
        (
            "provider_observation",
            "retracted_tombstone",
            "not_applicable",
            "source_retracted",
        ),
        ("derived_formula", "not_applicable", "input_missing", "input_missing"),
        ("derived_formula", "not_applicable", "input_unproven", "input_unproven"),
        ("derived_formula", "not_applicable", "division_by_zero", "division_by_zero"),
        (
            "derived_formula",
            "not_applicable_at_level",
            "not_applicable",
            "metric_not_applicable_at_level",
        ),
        (
            "derived_formula",
            "retracted_tombstone",
            "not_applicable",
            "source_retracted",
        ),
    }
)

PROVIDER_PRESENCE_TO_UNKNOWN_REASON: Final[Mapping[str, UnknownReason | None]] = (
    MappingProxyType(
        {
            "observed": None,
            "missing": "provider_omitted",
            "unproven_zero": "zero_not_proven",
            "timeout": "provider_timeout",
            "not_applicable_at_level": "metric_not_applicable_at_level",
            "retracted_tombstone": "source_retracted",
        }
    )
)

PHASE1_DIMENSIONS: Final[tuple[str, ...]] = (
    "attribution_ref",
    "breakdown_signature",
    "metric_date",
    "resource_level",
    "resource_ref",
)
_ALLOWED_METRIC_DIMENSIONS: Final[frozenset[str]] = frozenset(PHASE1_DIMENSIONS)
_ALLOWED_METRIC_TRIPLES: Final[frozenset[tuple[str, str, str]]] = frozenset(
    {
        ("int64_count", "count", "must_be_null"),
        ("int64_minor_currency", "minor_currency", "must_be_query_currency"),
        ("decimal_ratio", "ratio", "must_be_null"),
    }
)
_ALLOWED_AGGREGATION_SEMANTICS: Final[frozenset[str]] = frozenset(
    {"additive_across_none", "additive_within_resource", "non_additive"}
)
_BASE_METRIC_CORE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "$schema",
        "metric_semantic_ref",
        "canonical_name",
        "value_type",
        "unit",
        "currency_rule",
        "dimensions",
        "aggregation_semantics",
        "metric_definition_digest",
    }
)


def _check_numeric_matrix(
    *,
    metric_origin: object,
    presence_status: object,
    calculation_status: object,
    unknown_reason: object,
    value_type: object,
    raw_numeric_value: object,
    unit: object,
    currency: object,
    query_currency: str,
) -> tuple[
    MetricOrigin,
    PresenceStatus,
    CalculationStatus,
    UnknownReason | None,
    ValueType | None,
    str | None,
    UnitType | None,
    str | None,
]:
    if isinstance(raw_numeric_value, (bool, int, float)):
        raise ClosedValidationError(
            "raw_numeric_value: native bool/int/float values are forbidden; "
            f"got {type(raw_numeric_value).__name__}"
        )
    if raw_numeric_value is not None and not isinstance(raw_numeric_value, str):
        raise ClosedValidationError(
            f"raw_numeric_value: expected str or None, got {type(raw_numeric_value).__name__}"
        )

    validated_qc = validate_currency_iso4217(
        query_currency, field_name="query_currency"
    )

    if not isinstance(metric_origin, str):
        raise ClosedValidationError(
            f"metric_origin: expected str, got {type(metric_origin).__name__}"
        )
    if not isinstance(presence_status, str):
        raise ClosedValidationError(
            f"presence_status: expected str, got {type(presence_status).__name__}"
        )
    if not isinstance(calculation_status, str):
        raise ClosedValidationError(
            f"calculation_status: expected str, got {type(calculation_status).__name__}"
        )
    if unknown_reason is not None and not isinstance(unknown_reason, str):
        raise ClosedValidationError(
            f"unknown_reason: expected str or None, got {type(unknown_reason).__name__}"
        )
    if value_type is not None and not isinstance(value_type, str):
        raise ClosedValidationError(
            f"value_type: expected str or None, got {type(value_type).__name__}"
        )
    if unit is not None and not isinstance(unit, str):
        raise ClosedValidationError(
            f"unit: expected str or None, got {type(unit).__name__}"
        )
    if currency is not None and not isinstance(currency, str):
        raise ClosedValidationError(
            f"currency: expected str or None, got {type(currency).__name__}"
        )

    state_tuple = (metric_origin, presence_status, calculation_status, unknown_reason)
    if state_tuple in _VALUE_STATE_ROWS:
        if value_type is None or raw_numeric_value is None or unit is None:
            raise ClosedValidationError(
                "numeric_state: non-null value row requires non-null "
                "value_type, raw_numeric_value, and unit"
            )
        if value_type == "int64_count":
            if unit != "count" or currency is not None:
                raise ClosedValidationError(
                    "numeric_state: int64_count requires unit='count' and currency=None"
                )
            if not _UNSIGNED_INT_RE.fullmatch(raw_numeric_value):
                raise ClosedValidationError(
                    f"raw_numeric_value: invalid int64_count lexical form {raw_numeric_value!r}"
                )
            parsed_int = int(raw_numeric_value, 10)
            if not (0 <= parsed_int <= MAX_INT64):
                raise ClosedValidationError(
                    f"raw_numeric_value: int64_count {parsed_int} exceeds MAX_INT64"
                )
        elif value_type == "int64_minor_currency":
            if unit != "minor_currency" or currency != validated_qc:
                raise ClosedValidationError(
                    "numeric_state: int64_minor_currency requires "
                    f"unit='minor_currency' and currency={validated_qc!r}, got unit={unit!r}, currency={currency!r}"
                )
            if not _UNSIGNED_INT_RE.fullmatch(raw_numeric_value):
                raise ClosedValidationError(
                    f"raw_numeric_value: invalid int64_minor_currency lexical form {raw_numeric_value!r}"
                )
            parsed_money = int(raw_numeric_value, 10)
            if not (0 <= parsed_money <= MAX_INT64):
                raise ClosedValidationError(
                    f"raw_numeric_value: int64_minor_currency {parsed_money} exceeds MAX_INT64"
                )
        elif value_type == "decimal_ratio":
            if unit != "ratio" or currency is not None:
                raise ClosedValidationError(
                    "numeric_state: decimal_ratio requires unit='ratio' and currency=None"
                )
            if not _DECIMAL_RATIO6_RE.fullmatch(raw_numeric_value):
                raise ClosedValidationError(
                    f"raw_numeric_value: invalid decimal_ratio lexical form {raw_numeric_value!r}"
                )
        else:
            raise ClosedValidationError(
                f"value_type: unsupported closed value_type {value_type!r}"
            )
        return (
            metric_origin,  # type: ignore[return-value]
            presence_status,  # type: ignore[return-value]
            calculation_status,  # type: ignore[return-value]
            None,
            value_type,  # type: ignore[return-value]
            raw_numeric_value,
            unit,  # type: ignore[return-value]
            currency,
        )

    if state_tuple in _NULL_STATE_ROWS:
        if not (
            value_type is None
            and raw_numeric_value is None
            and unit is None
            and currency is None
        ):
            raise ClosedValidationError(
                f"numeric_state: null state {state_tuple!r} requires all of "
                "(value_type, raw_numeric_value, unit, currency) to be None"
            )
        return (
            metric_origin,  # type: ignore[return-value]
            presence_status,  # type: ignore[return-value]
            calculation_status,  # type: ignore[return-value]
            unknown_reason,  # type: ignore[return-value]
            None,
            None,
            None,
            None,
        )

    raise ClosedValidationError(
        f"numeric_state: combination {state_tuple!r} is outside the closed 12-row matrix"
    )


@dataclass(frozen=True, slots=True)
class NumericStateRow:
    """Validated row of the ADR-0001 §4.3 12-row closed numeric union."""

    metric_origin: MetricOrigin
    presence_status: PresenceStatus
    calculation_status: CalculationStatus
    unknown_reason: UnknownReason | None
    value_type: ValueType | None
    raw_numeric_value: str | None
    unit: UnitType | None
    currency: str | None

    def __post_init__(self) -> None:
        inferred_qc = (
            self.currency
            if isinstance(self.currency, str) and len(self.currency) > 0
            else "BRL"
        )
        _check_numeric_matrix(
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


def validate_numeric_state(
    *,
    metric_origin: object,
    presence_status: object,
    calculation_status: object,
    unknown_reason: object,
    value_type: object,
    raw_numeric_value: object,
    unit: object,
    currency: object,
    query_currency: str = "BRL",
) -> NumericStateRow:
    """Validate all 8 numeric/state fields against the exhaustive 12-row matrix (ADR-0001 §4.3)."""
    checked = _check_numeric_matrix(
        metric_origin=metric_origin,
        presence_status=presence_status,
        calculation_status=calculation_status,
        unknown_reason=unknown_reason,
        value_type=value_type,
        raw_numeric_value=raw_numeric_value,
        unit=unit,
        currency=currency,
        query_currency=query_currency,
    )
    return NumericStateRow(*checked)


def parse_brl_decimal_to_minor_units(raw: object) -> str:
    """Convert canonical unsigned BRL decimal string (`0`, `12.3`, `12.34`) to minor-unit int64 str."""
    if not isinstance(raw, str):
        raise ClosedValidationError(
            f"brl_decimal: expected str, got {type(raw).__name__}"
        )
    match = _BRL_DECIMAL_RE.fullmatch(raw)
    if match is None:
        raise ClosedValidationError(
            f"brl_decimal: expected canonical unsigned BRL decimal with <=2 fractional digits, got {raw!r}"
        )
    major = int(match.group(1), 10)
    frac_str = match.group(2)
    if frac_str is None:
        minor = 0
    elif len(frac_str) == 1:
        minor = int(frac_str, 10) * 10
    else:
        minor = int(frac_str, 10)
    cents = major * 100 + minor
    if not (0 <= cents <= MAX_INT64):
        raise ClosedValidationError(
            f"brl_decimal: minor units {cents} exceed MAX_INT64 ({MAX_INT64})"
        )
    return str(cents)


def _validate_dimension_member(value: str) -> str:
    if value not in _ALLOWED_METRIC_DIMENSIONS:
        raise ClosedValidationError(
            f"base_metric_definition.dimensions: unsupported dimension {value!r}"
        )
    return value


@dataclass(frozen=True, slots=True)
class BaseMetricDefinition:
    """Closed `smart_ads/base_metric_definition/v1` contract (ADR-0001 §5.5.1)."""

    SCHEMA: ClassVar[str] = "smart_ads/base_metric_definition/v1"

    metric_semantic_ref: str
    canonical_name: str
    value_type: ValueType
    unit: UnitType
    currency_rule: CurrencyRule
    dimensions: tuple[str, ...]
    aggregation_semantics: AggregationSemantics
    metric_definition_digest: str = ""
    integrity: P1Integrity | None = None

    def __post_init__(self) -> None:
        if not isinstance(
            self.metric_semantic_ref, str
        ) or not _METRIC_SEMANTIC_REF_RE.fullmatch(self.metric_semantic_ref):
            raise ClosedValidationError(
                "base_metric_definition.metric_semantic_ref: expected "
                f"'metric:<name>_v<n>', got {self.metric_semantic_ref!r}"
            )
        if not isinstance(
            self.canonical_name, str
        ) or not _CANONICAL_NAME_RE.fullmatch(self.canonical_name):
            raise ClosedValidationError(
                "base_metric_definition.canonical_name: expected lowercase snake_case "
                f"identifier, got {self.canonical_name!r}"
            )
        if (
            not isinstance(self.value_type, str)
            or not isinstance(self.unit, str)
            or not isinstance(self.currency_rule, str)
            or (self.value_type, self.unit, self.currency_rule)
            not in _ALLOWED_METRIC_TRIPLES
        ):
            raise ClosedValidationError(
                "base_metric_definition: invalid (value_type, unit, currency_rule) triple "
                f"{(self.value_type, self.unit, self.currency_rule)!r}"
            )
        if not isinstance(self.dimensions, (list, tuple)):
            raise ClosedValidationError(
                "base_metric_definition.dimensions: expected list or tuple of strings"
            )
        sorted_dims = sort_utf8_strings(
            self.dimensions,
            field_name="base_metric_definition.dimensions",
            allow_empty=False,
            validator=_validate_dimension_member,
        )
        object.__setattr__(self, "dimensions", sorted_dims)

        if (
            not isinstance(self.aggregation_semantics, str)
            or self.aggregation_semantics not in _ALLOWED_AGGREGATION_SEMANTICS
        ):
            raise ClosedValidationError(
                "base_metric_definition.aggregation_semantics: invalid value "
                f"{self.aggregation_semantics!r}"
            )
        if self.integrity is not None and not isinstance(self.integrity, P1Integrity):
            raise ClosedValidationError(
                "base_metric_definition.integrity: expected P1Integrity or None"
            )
        if not isinstance(self.metric_definition_digest, str):
            raise ClosedValidationError(
                "base_metric_definition.metric_definition_digest: expected str"
            )

        expected_digest = self_digest_jcs_sha256(
            self._pre_digest_dict(),
            digest_member="metric_definition_digest",
            strip_integrity=True,
        )
        if self.metric_definition_digest == "":
            object.__setattr__(self, "metric_definition_digest", expected_digest)
        else:
            validate_sha256_prefixed(
                self.metric_definition_digest,
                field_name="base_metric_definition.metric_definition_digest",
            )
            if self.metric_definition_digest != expected_digest:
                raise ClosedValidationError(
                    "base_metric_definition.metric_definition_digest: recomputed "
                    f"{expected_digest!r} != asserted {self.metric_definition_digest!r}"
                )

        if self.integrity is not None and self.integrity.is_signed:
            expected_p1 = p1_content_digest(self.to_dict())
            if self.integrity.content_digest != expected_p1:
                raise ClosedValidationError(
                    "base_metric_definition.integrity.content_digest: recomputed "
                    f"{expected_p1!r} != asserted {self.integrity.content_digest!r}"
                )

    def _pre_digest_dict(self) -> dict[str, Any]:
        return {
            "$schema": self.SCHEMA,
            "metric_semantic_ref": self.metric_semantic_ref,
            "canonical_name": self.canonical_name,
            "value_type": self.value_type,
            "unit": self.unit,
            "currency_rule": self.currency_rule,
            "dimensions": list(self.dimensions),
            "aggregation_semantics": self.aggregation_semantics,
        }

    def to_dict(self) -> dict[str, Any]:
        """Serialize `base_metric_definition/v1` to a closed JSON dictionary."""
        out = self._pre_digest_dict()
        out["metric_definition_digest"] = self.metric_definition_digest
        if self.integrity is not None:
            out["integrity"] = self.integrity.to_dict()
        return out

    @classmethod
    def from_dict(
        cls,
        data: object,
        *,
        require_signed: bool = False,
    ) -> BaseMetricDefinition:
        """Validate and parse a closed `smart_ads/base_metric_definition/v1` mapping."""
        if not isinstance(require_signed, bool):
            raise ClosedValidationError("require_signed: expected bool")
        mapping = require_mapping(data, label="base_metric_definition")
        if require_signed or "integrity" in mapping:
            require_exact_keys(
                mapping,
                _BASE_METRIC_CORE_KEYS | {"integrity"},
                label="base_metric_definition",
            )
            integrity: P1Integrity | None = P1Integrity.from_dict(
                mapping["integrity"], require_signed=require_signed
            )
        else:
            require_exact_keys(
                mapping, _BASE_METRIC_CORE_KEYS, label="base_metric_definition"
            )
            integrity = None

        if mapping["$schema"] != cls.SCHEMA:
            raise ClosedValidationError(
                f"base_metric_definition.$schema: expected {cls.SCHEMA!r}, got {mapping['$schema']!r}"
            )
        raw_dims = mapping["dimensions"]
        if not isinstance(raw_dims, list):
            raise ClosedValidationError(
                "base_metric_definition.dimensions: expected JSON array list"
            )
        sorted_dims = sort_utf8_strings(
            raw_dims,
            field_name="base_metric_definition.dimensions",
            allow_empty=False,
            validator=_validate_dimension_member,
        )
        if tuple(raw_dims) != sorted_dims:
            raise ClosedValidationError(
                "base_metric_definition.dimensions: array must be canonically sorted by UTF-8 bytes"
            )
        digest_raw = validate_sha256_prefixed(
            mapping["metric_definition_digest"],
            field_name="base_metric_definition.metric_definition_digest",
        )
        return cls(
            metric_semantic_ref=mapping["metric_semantic_ref"],
            canonical_name=mapping["canonical_name"],
            value_type=mapping["value_type"],
            unit=mapping["unit"],
            currency_rule=mapping["currency_rule"],
            dimensions=sorted_dims,
            aggregation_semantics=mapping["aggregation_semantics"],
            metric_definition_digest=digest_raw,
            integrity=integrity,
        )


PHASE1_BASE_METRICS: Final[Mapping[str, BaseMetricDefinition]] = MappingProxyType(
    {
        "metric:clicks_v1": BaseMetricDefinition(
            metric_semantic_ref="metric:clicks_v1",
            canonical_name="clicks",
            value_type="int64_count",
            unit="count",
            currency_rule="must_be_null",
            dimensions=PHASE1_DIMENSIONS,
            aggregation_semantics="additive_across_none",
        ),
        "metric:impressions_v1": BaseMetricDefinition(
            metric_semantic_ref="metric:impressions_v1",
            canonical_name="impressions",
            value_type="int64_count",
            unit="count",
            currency_rule="must_be_null",
            dimensions=PHASE1_DIMENSIONS,
            aggregation_semantics="additive_across_none",
        ),
        "metric:spend_v1": BaseMetricDefinition(
            metric_semantic_ref="metric:spend_v1",
            canonical_name="spend",
            value_type="int64_minor_currency",
            unit="minor_currency",
            currency_rule="must_be_query_currency",
            dimensions=PHASE1_DIMENSIONS,
            aggregation_semantics="additive_across_none",
        ),
    }
)

PHASE1_METRIC_NAME_TO_REF: Final[Mapping[str, str]] = MappingProxyType(
    {
        defn.canonical_name: ref
        for ref, defn in sorted(
            PHASE1_BASE_METRICS.items(),
            key=lambda kv: kv[1].canonical_name.encode("utf-8"),
        )
    }
)

PHASE1_METRIC_REF_TO_NAME: Final[Mapping[str, str]] = MappingProxyType(
    {ref: defn.canonical_name for ref, defn in PHASE1_BASE_METRICS.items()}
)

__all__ = [
    "AggregationSemantics",
    "BaseMetricDefinition",
    "CalculationStatus",
    "CurrencyRule",
    "MAX_INT64",
    "MetricOrigin",
    "NumericStateRow",
    "PHASE1_BASE_METRICS",
    "PHASE1_DIMENSIONS",
    "PHASE1_METRIC_NAME_TO_REF",
    "PHASE1_METRIC_REF_TO_NAME",
    "PROVIDER_PRESENCE_TO_UNKNOWN_REASON",
    "PresenceStatus",
    "ProviderPresenceStatus",
    "UnitType",
    "UnknownReason",
    "ValueType",
    "parse_brl_decimal_to_minor_units",
    "validate_numeric_state",
]
