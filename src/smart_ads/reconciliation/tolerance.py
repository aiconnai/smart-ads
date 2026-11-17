"""Tolerance profile and recomputed candidate/reference comparison (ADR-0001 section 5.4).

The 7B verifier ignores asserted deltas and outcomes: it resolves the content
addressed ``tolerance_profile/v1`` and recomputes every comparison from the two
canonical values. This module holds the closed profile artifact and the pure
comparator. Counts and money use exact Python integers; the relative delta uses
exact-integer ROUND_HALF_UP at fixed scale 6 and is rendered as an ASCII string.
No float, clock, or I/O is involved, and the wheel never signs.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import re
from types import MappingProxyType
from typing import Any, ClassVar, Final, Literal

from smart_ads.contracts.jcs import ArtifactLocator, P1Integrity, p1_content_digest
from smart_ads.contracts.numerics import (
    MAX_INT64,
    PHASE1_BASE_METRICS,
    PROVIDER_PRESENCE_TO_UNKNOWN_REASON,
    ProviderPresenceStatus,
    UnitType,
    ValueType,
)
from smart_ads.contracts.scalars import (
    ClosedValidationError,
    require_exact_keys,
    require_mapping,
    validate_currency_iso4217,
    validate_opaque_ref,
    validate_sha256_prefixed,
)

ComparableValueType = Literal["int64_count", "int64_minor_currency"]
RelativeDeltaStatus = Literal["computed", "reference_zero", "not_computable"]
ReconciliationOutcome = Literal[
    "exact_match", "within_declared_tolerance", "mismatch", "not_comparable"
]
MetricVerificationStatus = Literal["VERIFIED", "UNRECONCILED", "UNAVAILABLE", "BLOCKED"]

DECIMAL_SCALE: Final[int] = 6
ROUNDING_MODE: Final[str] = "ROUND_HALF_UP"
REFERENCE_ZERO_RULE: Final[str] = "exact_zero_only"
# ADR-0001 section 5.4 (L1150): "spend uses int64_minor_currency/minor_currency/BRL."
# The 7B money currency is fixed by the ADR, not chosen by the caller.
PHASE1_7B_MONEY_CURRENCY: Final[str] = "BRL"

_SCALE_FACTOR: Final[int] = 10**DECIMAL_SCALE
_MAX_INT64_DIGITS: Final[int] = len(str(MAX_INT64))
_MIN_INT64: Final[int] = -MAX_INT64 - 1
_MAX_SIGNED_TEXT_LEN: Final[int] = _MAX_INT64_DIGITS + 1

_UNSIGNED_INT_RE: Final[re.Pattern[str]] = re.compile(r"\A(0|[1-9][0-9]*)\Z")
_SIGNED_INT_RE: Final[re.Pattern[str]] = re.compile(r"\A(0|-?[1-9][0-9]*)\Z")
_DECIMAL6_RE: Final[re.Pattern[str]] = re.compile(r"\A(0|[1-9][0-9]*)\.[0-9]{6}\Z")

_COMPARABLE_VALUE_TYPES: Final[frozenset[str]] = frozenset(
    {"int64_count", "int64_minor_currency"}
)
_UNIT_BY_VALUE_TYPE: Final[Mapping[str, str]] = MappingProxyType(
    {
        "int64_count": "count",
        "int64_minor_currency": "minor_currency",
        "decimal_ratio": "ratio",
    }
)
_PROVIDER_PRESENCE: Final[frozenset[str]] = frozenset(PROVIDER_PRESENCE_TO_UNKNOWN_REASON)
_SIDE_VALUE_FIELDS: Final[tuple[str, ...]] = (
    "value_type",
    "raw_numeric_value",
    "unit",
    "currency",
)

_GATE3_SELECTION_TYPE: Final[str] = "smart_ads/gate3_selection_receipt/v1"
_RUN_CONTEXT_TYPE: Final[str] = "smart_ads/migration_run_context/v1"
_BINDING_KEYS: Final[frozenset[str]] = frozenset(
    {
        "gate3_selection_locator",
        "canonical_query_digest",
        "authorized_certification_scope",
        "migration_run_context_locator",
    }
)
_PROFILE_CORE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "$schema",
        "canonical_metric_ref",
        "value_type",
        "max_absolute_delta",
        "max_relative_delta",
        "decimal_scale",
        "rounding_mode",
        "reference_zero_rule",
        "authorization_binding",
    }
)
_RESULT_KEYS: Final[frozenset[str]] = frozenset(
    {
        "measured_absolute_delta",
        "measured_relative_delta",
        "relative_delta_status",
        "reconciliation_outcome",
        "metric_verification_status",
    }
)

# (relative_delta_status, reconciliation_outcome, metric_verification_status)
# -> (absolute delta shape, relative delta shape). Closed 7-row truth table.
_ROW_SHAPES: Final[
    Mapping[tuple[str, str, str], tuple[str | None, str | None]]
] = MappingProxyType(
    {
        ("reference_zero", "exact_match", "VERIFIED"): ("zero", None),
        ("reference_zero", "mismatch", "UNRECONCILED"): ("positive", None),
        ("computed", "exact_match", "VERIFIED"): ("zero", "zero"),
        ("computed", "within_declared_tolerance", "VERIFIED"): ("positive", "any"),
        ("computed", "mismatch", "UNRECONCILED"): ("positive", "any"),
        ("not_computable", "not_comparable", "UNAVAILABLE"): (None, None),
        ("not_computable", "not_comparable", "BLOCKED"): (None, None),
    }
)


def _show(value: object) -> str:
    text = repr(value)
    return text if len(text) <= 80 else text[:77] + "..."


def _require_str_or_none(value: object, *, field_name: str) -> str | None:
    if value is not None and not isinstance(value, str):
        raise ClosedValidationError(
            f"{field_name}: expected str or None, got {type(value).__name__}"
        )
    return value


def _parse_unsigned_int64(raw: object, *, field_name: str) -> int:
    """Parse a canonical `^(0|[1-9][0-9]*)$` string in `0..MAX_INT64`."""
    if not isinstance(raw, str):
        raise ClosedValidationError(
            f"{field_name}: expected canonical unsigned int64 str, got {type(raw).__name__}"
        )
    if _UNSIGNED_INT_RE.fullmatch(raw) is None or len(raw) > _MAX_INT64_DIGITS:
        raise ClosedValidationError(
            f"{field_name}: expected canonical unsigned int64 string, got {_show(raw)}"
        )
    value = int(raw, 10)
    if value > MAX_INT64:
        raise ClosedValidationError(f"{field_name}: {value} exceeds MAX_INT64")
    return value


def _parse_signed_int64(raw: object, *, field_name: str) -> int:
    """Parse a canonical `^(0|-?[1-9][0-9]*)$` string in the int64 range."""
    if not isinstance(raw, str):
        raise ClosedValidationError(
            f"{field_name}: expected canonical int64 str, got {type(raw).__name__}"
        )
    if _SIGNED_INT_RE.fullmatch(raw) is None or len(raw) > _MAX_SIGNED_TEXT_LEN:
        raise ClosedValidationError(
            f"{field_name}: expected canonical int64 string, got {_show(raw)}"
        )
    value = int(raw, 10)
    if not (_MIN_INT64 <= value <= MAX_INT64):
        raise ClosedValidationError(f"{field_name}: {value} is outside the int64 range")
    return value


def _parse_decimal6_micros(raw: object, *, field_name: str) -> int:
    """Parse canonical unsigned decimal6 and return it as an integer count of 10^-6."""
    if not isinstance(raw, str):
        raise ClosedValidationError(
            f"{field_name}: expected canonical decimal6 str, got {type(raw).__name__}"
        )
    if _DECIMAL6_RE.fullmatch(raw) is None:
        raise ClosedValidationError(
            f"{field_name}: expected canonical unsigned decimal6 string, got {_show(raw)}"
        )
    integer_part, fraction = raw.split(".")
    if len(integer_part) > _MAX_INT64_DIGITS or int(integer_part) > MAX_INT64:
        raise ClosedValidationError(
            f"{field_name}: integer part exceeds MAX_INT64, got {_show(raw)}"
        )
    return int(integer_part) * _SCALE_FACTOR + int(fraction)


def _format_decimal6(micros: int) -> str:
    if type(micros) is not int or micros < 0:
        raise ClosedValidationError("decimal6: scaled value must be a non-negative int")
    whole, fraction = divmod(micros, _SCALE_FACTOR)
    return f"{whole}.{fraction:0{DECIMAL_SCALE}d}"


def _round_half_up_div(numerator: int, denominator: int) -> int:
    """Exact-integer ROUND_HALF_UP of `numerator / denominator` (non-negative operands)."""
    if numerator < 0 or denominator <= 0:
        raise ClosedValidationError(
            "round_half_up: requires numerator >= 0 and denominator > 0"
        )
    return (2 * numerator + denominator) // (2 * denominator)


def _require_locator(value: object, artifact_type: str, *, field_name: str) -> ArtifactLocator:
    if not isinstance(value, ArtifactLocator) or value.artifact_type != artifact_type:
        raise ClosedValidationError(
            f"{field_name}: expected ArtifactLocator for {artifact_type!r}"
        )
    return value


def _describe_binding_value(value: object) -> str:
    if isinstance(value, ArtifactLocator):
        return f"<{value.artifact_type} {value.content_digest}>"
    return _show(value)


def _validated_binding_members(
    *,
    gate3_selection_locator: object,
    canonical_query_digest: object,
    authorized_certification_scope: object,
    migration_run_context_locator: object,
) -> tuple[tuple[str, object], ...]:
    """Check the four supplied members are well formed; return them in binding order.

    Locators are only required to be `ArtifactLocator` values here: a locator of a
    different artifact type is a well-formed value that differs from the binding.
    """
    label = "tolerance_profile.require_bound_to"
    for name, locator in (
        ("gate3_selection_locator", gate3_selection_locator),
        ("migration_run_context_locator", migration_run_context_locator),
    ):
        if not isinstance(locator, ArtifactLocator):
            raise ClosedValidationError(
                f"{label}.{name}: expected ArtifactLocator, got {type(locator).__name__}"
            )
    validate_sha256_prefixed(
        canonical_query_digest, field_name=f"{label}.canonical_query_digest"
    )
    validate_opaque_ref(
        authorized_certification_scope,
        field_name=f"{label}.authorized_certification_scope",
        expected_prefix="scope",
    )
    return (
        ("gate3_selection_locator", gate3_selection_locator),
        ("canonical_query_digest", canonical_query_digest),
        ("authorized_certification_scope", authorized_certification_scope),
        ("migration_run_context_locator", migration_run_context_locator),
    )


@dataclass(frozen=True, slots=True)
class ComparisonSide:
    """One side's value fields of a `fact_reconciliation/v1` member (ADR-0001 section 5.4).

    Only the closed numeric union is modelled here (presence, type, raw value,
    unit, currency). A canonical negative integer is accepted on purpose: the
    comparator reports it as a BLOCKED comparison instead of raising, because
    negative evidence fails the 7B bundle rather than the process.
    """

    presence_status: ProviderPresenceStatus
    value_type: ValueType | None
    raw_numeric_value: str | None
    unit: UnitType | None
    currency: str | None

    def __post_init__(self) -> None:
        status = self.presence_status
        if not isinstance(status, str) or status not in _PROVIDER_PRESENCE:
            raise ClosedValidationError(
                f"comparison_side.presence_status: invalid provider state {_show(status)}"
            )
        for name in _SIDE_VALUE_FIELDS:
            _require_str_or_none(getattr(self, name), field_name=f"comparison_side.{name}")
        if status != "observed":
            if any(getattr(self, name) is not None for name in _SIDE_VALUE_FIELDS):
                raise ClosedValidationError(
                    f"comparison_side: non-observed state {status!r} must carry no value"
                )
            return
        self._check_observed_value()

    def _check_observed_value(self) -> None:
        value_type = self.value_type
        expected_unit = _UNIT_BY_VALUE_TYPE.get(value_type) if value_type else None
        if expected_unit is None or self.raw_numeric_value is None:
            raise ClosedValidationError(
                "comparison_side: observed state requires a closed value_type and raw value, "
                f"got value_type={_show(value_type)}"
            )
        if self.unit != expected_unit:
            raise ClosedValidationError(
                f"comparison_side.unit: {value_type!r} requires unit {expected_unit!r}, "
                f"got {_show(self.unit)}"
            )
        if value_type == "int64_minor_currency":
            validate_currency_iso4217(self.currency, field_name="comparison_side.currency")
        elif self.currency is not None:
            raise ClosedValidationError(
                f"comparison_side.currency: {value_type!r} requires currency=None"
            )
        if value_type == "decimal_ratio":
            if _DECIMAL6_RE.fullmatch(self.raw_numeric_value) is None:
                raise ClosedValidationError(
                    "comparison_side.raw_numeric_value: invalid decimal_ratio form "
                    f"{_show(self.raw_numeric_value)}"
                )
        else:
            _parse_signed_int64(
                self.raw_numeric_value, field_name="comparison_side.raw_numeric_value"
            )


@dataclass(frozen=True, slots=True)
class ToleranceComparison:
    """The five recomputed `fact_reconciliation/v1` members, with the exact ADR names."""

    measured_absolute_delta: str | None
    measured_relative_delta: str | None
    relative_delta_status: RelativeDeltaStatus
    reconciliation_outcome: ReconciliationOutcome
    metric_verification_status: MetricVerificationStatus

    def __post_init__(self) -> None:
        triple = (
            self.relative_delta_status,
            self.reconciliation_outcome,
            self.metric_verification_status,
        )
        if not all(isinstance(member, str) for member in triple) or triple not in _ROW_SHAPES:
            raise ClosedValidationError(
                f"tolerance_comparison: state combination {_show(triple)} is outside the "
                "closed 7-row truth table"
            )
        absolute_shape, relative_shape = _ROW_SHAPES[triple]
        self._check_absolute(absolute_shape)
        self._check_relative(relative_shape)

    def _check_absolute(self, shape: str | None) -> None:
        value = self.measured_absolute_delta
        if shape is None:
            if value is not None:
                raise ClosedValidationError(
                    "tolerance_comparison.measured_absolute_delta: must be null for this row"
                )
            return
        parsed = _parse_unsigned_int64(
            value, field_name="tolerance_comparison.measured_absolute_delta"
        )
        if (parsed == 0) != (shape == "zero"):
            raise ClosedValidationError(
                "tolerance_comparison.measured_absolute_delta: "
                f"{value!r} contradicts the {self.reconciliation_outcome!r} outcome"
            )

    def _check_relative(self, shape: str | None) -> None:
        value = self.measured_relative_delta
        if shape is None:
            if value is not None:
                raise ClosedValidationError(
                    "tolerance_comparison.measured_relative_delta: must be null for this row"
                )
            return
        micros = _parse_decimal6_micros(
            value, field_name="tolerance_comparison.measured_relative_delta"
        )
        if shape == "zero" and micros != 0:
            raise ClosedValidationError(
                "tolerance_comparison.measured_relative_delta: must be 0.000000 for exact_match"
            )

    def to_dict(self) -> dict[str, Any]:
        """Serialize the five members under their exact ADR-0001 section 5.4 names."""
        return {
            "measured_absolute_delta": self.measured_absolute_delta,
            "measured_relative_delta": self.measured_relative_delta,
            "relative_delta_status": self.relative_delta_status,
            "reconciliation_outcome": self.reconciliation_outcome,
            "metric_verification_status": self.metric_verification_status,
        }

    @classmethod
    def from_dict(cls, data: object) -> ToleranceComparison:
        """Validate a closed five-member mapping (for example asserted evidence)."""
        mapping = require_exact_keys(data, _RESULT_KEYS, label="tolerance_comparison")
        return cls(
            measured_absolute_delta=mapping["measured_absolute_delta"],
            measured_relative_delta=mapping["measured_relative_delta"],
            relative_delta_status=mapping["relative_delta_status"],
            reconciliation_outcome=mapping["reconciliation_outcome"],
            metric_verification_status=mapping["metric_verification_status"],
        )


@dataclass(frozen=True, slots=True)
class AuthorizationBinding:
    """Gate-3 authorization a non-zero tolerance is bound to (query, scope, and run)."""

    gate3_selection_locator: ArtifactLocator
    canonical_query_digest: str
    authorized_certification_scope: str
    migration_run_context_locator: ArtifactLocator

    def __post_init__(self) -> None:
        _require_locator(
            self.gate3_selection_locator,
            _GATE3_SELECTION_TYPE,
            field_name="authorization_binding.gate3_selection_locator",
        )
        validate_sha256_prefixed(
            self.canonical_query_digest,
            field_name="authorization_binding.canonical_query_digest",
        )
        validate_opaque_ref(
            self.authorized_certification_scope,
            field_name="authorization_binding.authorized_certification_scope",
            expected_prefix="scope",
        )
        _require_locator(
            self.migration_run_context_locator,
            _RUN_CONTEXT_TYPE,
            field_name="authorization_binding.migration_run_context_locator",
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "gate3_selection_locator": self.gate3_selection_locator.to_dict(),
            "canonical_query_digest": self.canonical_query_digest,
            "authorized_certification_scope": self.authorized_certification_scope,
            "migration_run_context_locator": self.migration_run_context_locator.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: object) -> AuthorizationBinding:
        mapping = require_exact_keys(data, _BINDING_KEYS, label="authorization_binding")
        return cls(
            gate3_selection_locator=ArtifactLocator.from_dict(
                mapping["gate3_selection_locator"], expected_type=_GATE3_SELECTION_TYPE
            ),
            canonical_query_digest=mapping["canonical_query_digest"],
            authorized_certification_scope=mapping["authorized_certification_scope"],
            migration_run_context_locator=ArtifactLocator.from_dict(
                mapping["migration_run_context_locator"], expected_type=_RUN_CONTEXT_TYPE
            ),
        )


@dataclass(frozen=True, slots=True)
class ToleranceProfile:
    """Closed `smart_ads/tolerance_profile/v1` P1 artifact (ADR-0001 sections 5.4, 12.7).

    Limits are canonical strings because int64 amounts exceed the RFC 8785 safe
    integer range and native JSON numbers are forbidden for metric-domain values:
    `max_absolute_delta` is an unsigned int64 string, `max_relative_delta` an
    unsigned decimal6 string. `authorization_binding` is required exactly when a
    limit is non-zero and is null when both limits are zero.
    """

    SCHEMA: ClassVar[str] = "smart_ads/tolerance_profile/v1"

    canonical_metric_ref: str
    value_type: ComparableValueType
    max_absolute_delta: str
    max_relative_delta: str
    authorization_binding: AuthorizationBinding | None
    decimal_scale: int = DECIMAL_SCALE
    rounding_mode: str = ROUNDING_MODE
    reference_zero_rule: str = REFERENCE_ZERO_RULE
    integrity: P1Integrity | None = None

    def __post_init__(self) -> None:
        self._check_metric_and_type()
        self._check_fixed_members()
        self._check_authorization_binding()
        self._check_integrity()

    @property
    def absolute_limit(self) -> int:
        """`max_absolute_delta` as an exact int (count or minor-currency units)."""
        return _parse_unsigned_int64(
            self.max_absolute_delta, field_name="tolerance_profile.max_absolute_delta"
        )

    @property
    def relative_limit_micros(self) -> int:
        """`max_relative_delta` as an exact integer count of 10^-6."""
        return _parse_decimal6_micros(
            self.max_relative_delta, field_name="tolerance_profile.max_relative_delta"
        )

    def _check_metric_and_type(self) -> None:
        validate_opaque_ref(
            self.canonical_metric_ref,
            field_name="tolerance_profile.canonical_metric_ref",
            expected_prefix="metric",
        )
        if (
            not isinstance(self.value_type, str)
            or self.value_type not in _COMPARABLE_VALUE_TYPES
        ):
            raise ClosedValidationError(
                "tolerance_profile.value_type: expected 'int64_count' or "
                f"'int64_minor_currency', got {_show(self.value_type)}"
            )
        base = PHASE1_BASE_METRICS.get(self.canonical_metric_ref)
        if base is not None and base.value_type != self.value_type:
            raise ClosedValidationError(
                f"tolerance_profile.value_type: {self.canonical_metric_ref!r} requires "
                f"{base.value_type!r}, got {self.value_type!r}"
            )

    def _check_fixed_members(self) -> None:
        if type(self.decimal_scale) is not int or self.decimal_scale != DECIMAL_SCALE:
            raise ClosedValidationError(
                f"tolerance_profile.decimal_scale: must be the int {DECIMAL_SCALE}"
            )
        if self.rounding_mode != ROUNDING_MODE:
            raise ClosedValidationError(
                f"tolerance_profile.rounding_mode: must equal {ROUNDING_MODE!r}"
            )
        if self.reference_zero_rule != REFERENCE_ZERO_RULE:
            raise ClosedValidationError(
                f"tolerance_profile.reference_zero_rule: must equal {REFERENCE_ZERO_RULE!r}"
            )

    def _check_authorization_binding(self) -> None:
        binding = self.authorization_binding
        if binding is not None and not isinstance(binding, AuthorizationBinding):
            raise ClosedValidationError(
                "tolerance_profile.authorization_binding: expected AuthorizationBinding or None"
            )
        is_exact = self.absolute_limit == 0 and self.relative_limit_micros == 0
        if is_exact and binding is not None:
            raise ClosedValidationError(
                "tolerance_profile.authorization_binding: must be null when both limits are zero"
            )
        if not is_exact and binding is None:
            raise ClosedValidationError(
                "tolerance_profile.authorization_binding: a non-zero limit requires a "
                "Gate-3 authorization binding"
            )

    def _check_integrity(self) -> None:
        if self.integrity is not None and not isinstance(self.integrity, P1Integrity):
            raise ClosedValidationError(
                "tolerance_profile.integrity: expected P1Integrity or None"
            )
        if self.integrity is not None and self.integrity.is_signed:
            expected_p1 = p1_content_digest(self.to_dict())
            if self.integrity.content_digest != expected_p1:
                raise ClosedValidationError(
                    "tolerance_profile.integrity.content_digest: recomputed "
                    f"{expected_p1!r} != asserted {self.integrity.content_digest!r}"
                )

    def require_bound_to(
        self,
        *,
        gate3_selection_locator: ArtifactLocator,
        canonical_query_digest: str,
        authorized_certification_scope: str,
        migration_run_context_locator: ArtifactLocator,
    ) -> None:
        """Require this profile to be authorized for the given query, scope, and run.

        ADR-0001 section 5.4: "any non-zero limit requires an explicit
        Gate-3-authorized profile bound to the same query, scope, and run."
        The four arguments (the same-named members of the 7B record) are always
        validated: a malformed argument raises `ClosedValidationError`, even for a
        zero profile. A zero profile (null binding) then passes without comparing
        anything. A non-zero profile requires each binding member to equal the
        argument exactly (locators as whole values) and raises
        `ClosedValidationError` naming the first member, in binding order, that
        differs.
        """
        supplied = _validated_binding_members(
            gate3_selection_locator=gate3_selection_locator,
            canonical_query_digest=canonical_query_digest,
            authorized_certification_scope=authorized_certification_scope,
            migration_run_context_locator=migration_run_context_locator,
        )
        authorized = self.authorization_binding
        if authorized is None:
            return
        for name, value in supplied:
            expected = getattr(authorized, name)
            if expected != value:
                raise ClosedValidationError(
                    f"tolerance_profile.authorization_binding.{name}: profile is bound to "
                    f"{_describe_binding_value(expected)} but this {name} is "
                    f"{_describe_binding_value(value)}"
                )

    def to_dict(self) -> dict[str, Any]:
        """Serialize `tolerance_profile/v1`; `integrity` is present only when set."""
        binding = self.authorization_binding
        out: dict[str, Any] = {
            "$schema": self.SCHEMA,
            "canonical_metric_ref": self.canonical_metric_ref,
            "value_type": self.value_type,
            "max_absolute_delta": self.max_absolute_delta,
            "max_relative_delta": self.max_relative_delta,
            "decimal_scale": self.decimal_scale,
            "rounding_mode": self.rounding_mode,
            "reference_zero_rule": self.reference_zero_rule,
            "authorization_binding": None if binding is None else binding.to_dict(),
        }
        if self.integrity is not None:
            out["integrity"] = self.integrity.to_dict()
        return out

    @classmethod
    def from_dict(cls, data: object, *, require_signed: bool = False) -> ToleranceProfile:
        """Validate and parse a closed `smart_ads/tolerance_profile/v1` mapping."""
        if not isinstance(require_signed, bool):
            raise ClosedValidationError("require_signed: expected bool")
        mapping = require_mapping(data, label="tolerance_profile")
        if require_signed or "integrity" in mapping:
            require_exact_keys(
                mapping, _PROFILE_CORE_KEYS | {"integrity"}, label="tolerance_profile"
            )
            integrity: P1Integrity | None = P1Integrity.from_dict(
                mapping["integrity"], require_signed=require_signed
            )
        else:
            require_exact_keys(mapping, _PROFILE_CORE_KEYS, label="tolerance_profile")
            integrity = None
        if mapping["$schema"] != cls.SCHEMA:
            raise ClosedValidationError(
                f"tolerance_profile.$schema: expected {cls.SCHEMA!r}, got {_show(mapping['$schema'])}"
            )
        raw_binding = mapping["authorization_binding"]
        return cls(
            canonical_metric_ref=mapping["canonical_metric_ref"],
            value_type=mapping["value_type"],
            max_absolute_delta=mapping["max_absolute_delta"],
            max_relative_delta=mapping["max_relative_delta"],
            authorization_binding=(
                None if raw_binding is None else AuthorizationBinding.from_dict(raw_binding)
            ),
            decimal_scale=mapping["decimal_scale"],
            rounding_mode=mapping["rounding_mode"],
            reference_zero_rule=mapping["reference_zero_rule"],
            integrity=integrity,
        )


_UNAVAILABLE: Final[ToleranceComparison] = ToleranceComparison(
    None, None, "not_computable", "not_comparable", "UNAVAILABLE"
)
_BLOCKED: Final[ToleranceComparison] = ToleranceComparison(
    None, None, "not_computable", "not_comparable", "BLOCKED"
)


def _sides_are_blocked(
    candidate: ComparisonSide,
    reference: ComparisonSide,
    profile: ToleranceProfile,
) -> bool:
    """True when type/unit/currency diverge between the sides or from the profile and the ADR.

    Money must be `PHASE1_7B_MONEY_CURRENCY` on both sides; every other currency
    (including two equal foreign currencies) is not comparable.
    """
    if (candidate.value_type, candidate.unit, candidate.currency) != (
        reference.value_type,
        reference.unit,
        reference.currency,
    ):
        return True
    if candidate.value_type != profile.value_type:
        return True
    is_money = profile.value_type == "int64_minor_currency"
    expected_currency = PHASE1_7B_MONEY_CURRENCY if is_money else None
    return candidate.currency != expected_currency


def _recompute(candidate: int, reference: int, profile: ToleranceProfile) -> ToleranceComparison:
    """Rows 1-5 of the truth table for two observed, non-negative, same-type integers."""
    delta = abs(candidate - reference)
    if reference == 0:
        if candidate == 0:
            return ToleranceComparison("0", None, "reference_zero", "exact_match", "VERIFIED")
        return ToleranceComparison(
            str(delta), None, "reference_zero", "mismatch", "UNRECONCILED"
        )
    relative = _round_half_up_div(delta * _SCALE_FACTOR, reference)
    outcome: ReconciliationOutcome
    status: MetricVerificationStatus
    if delta == 0:
        outcome, status = "exact_match", "VERIFIED"
    elif delta <= profile.absolute_limit and relative <= profile.relative_limit_micros:
        outcome, status = "within_declared_tolerance", "VERIFIED"
    else:
        outcome, status = "mismatch", "UNRECONCILED"
    return ToleranceComparison(str(delta), _format_decimal6(relative), "computed", outcome, status)


def compare_sides(
    candidate: ComparisonSide,
    reference: ComparisonSide,
    profile: ToleranceProfile,
    *,
    canonical_metric_ref: str,
) -> ToleranceComparison:
    """Recompute deltas, outcome, and verification status per ADR-0001 section 5.4.

    Legitimate failed comparisons (`mismatch`, `not_comparable`) are returned as
    values; only malformed arguments raise `ClosedValidationError`. Precedence:
    a profile that does not apply to `canonical_metric_ref` is BLOCKED; otherwise
    any non-observed side is UNAVAILABLE (an unknown reference is never zero) and
    beats any defect on the other side; otherwise type/unit divergence, a money
    currency other than `PHASE1_7B_MONEY_CURRENCY`, or a negative value is
    BLOCKED; otherwise the delta rows 1-5 apply. Both the absolute and the
    relative limit must pass for `within_declared_tolerance`; a zero reference
    admits only an exactly zero candidate (`reference_zero_rule: exact_zero_only`).
    Whether a non-zero profile was authorized for this query, scope, and run is
    checked separately by `ToleranceProfile.require_bound_to`.
    """
    for name, value, expected in (
        ("candidate", candidate, ComparisonSide),
        ("reference", reference, ComparisonSide),
        ("profile", profile, ToleranceProfile),
    ):
        if not isinstance(value, expected):
            raise ClosedValidationError(
                f"compare_sides.{name}: expected {expected.__name__}, got {type(value).__name__}"
            )
    validate_opaque_ref(
        canonical_metric_ref, field_name="canonical_metric_ref", expected_prefix="metric"
    )
    if profile.canonical_metric_ref != canonical_metric_ref:
        return _BLOCKED
    if candidate.presence_status != "observed" or reference.presence_status != "observed":
        return _UNAVAILABLE
    if _sides_are_blocked(candidate, reference, profile):
        return _BLOCKED
    field = "comparison_side.raw_numeric_value"
    candidate_value = _parse_signed_int64(candidate.raw_numeric_value, field_name=field)
    reference_value = _parse_signed_int64(reference.raw_numeric_value, field_name=field)
    if candidate_value < 0 or reference_value < 0:
        return _BLOCKED
    return _recompute(candidate_value, reference_value, profile)


__all__ = [
    "AuthorizationBinding",
    "ComparableValueType",
    "ComparisonSide",
    "DECIMAL_SCALE",
    "MetricVerificationStatus",
    "PHASE1_7B_MONEY_CURRENCY",
    "REFERENCE_ZERO_RULE",
    "ROUNDING_MODE",
    "ReconciliationOutcome",
    "RelativeDeltaStatus",
    "ToleranceComparison",
    "ToleranceProfile",
    "compare_sides",
]
