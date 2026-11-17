"""Versioned tenant analysis policy with a closed union of typed threshold rules (ADR-0001 section 7)."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import re
from types import MappingProxyType
from typing import Any, ClassVar, Final

from smart_ads.contracts.jcs import (
    ADR_P1_DOMAIN_PREFIXES,
    MAX_JCS_SAFE_INT,
    P1Integrity,
    p1_content_digest as _p1_content_digest,
    p1_preimage as _p1_preimage,
    sort_utf8_strings,
)
from smart_ads.contracts.numerics import MAX_INT64
from smart_ads.contracts.scalars import (
    ClosedValidationError,
    parse_timestamp_utc_micros,
    require_exact_keys,
    require_mapping,
    validate_currency_iso4217,
    validate_non_empty_str,
    validate_opaque_ref,
)

RULE_TYPE_SATURATION: Final[str] = "saturation"
RULE_TYPE_WASTE: Final[str] = "waste"
RULE_TYPE_STALLED_DELIVERY: Final[str] = "stalled_delivery"
RULE_TYPE_RESTATEMENT: Final[str] = "restatement"
RULE_TYPES: Final[tuple[str, ...]] = tuple(
    sorted(
        (
            RULE_TYPE_SATURATION,
            RULE_TYPE_WASTE,
            RULE_TYPE_STALLED_DELIVERY,
            RULE_TYPE_RESTATEMENT,
        ),
        key=lambda name: name.encode("utf-8"),
    )
)
RESTATEMENT_KINDS: Final[tuple[str, ...]] = ("state_flip", "tombstone", "value_change")
POLICY_NOT_APPLICABLE_CODES: Final[tuple[str, ...]] = (
    "tenant_mismatch",
    "resource_scope_mismatch",
    "resource_level_mismatch",
    "ad_platform_mismatch",
    "currency_mismatch",
    "not_yet_valid",
    "expired",
)

# Metric reference grammar of `base_metric_definition/v1`; numerics.py keeps its regex private,
# so the pattern is mirrored here and pinned to the original by a test.
METRIC_REF_PATTERN: Final[str] = r"\Ametric:[a-z][a-z0-9_]*_v[1-9][0-9]*\Z"
_METRIC_REF_RE: Final[re.Pattern[str]] = re.compile(METRIC_REF_PATTERN)
_DECIMAL6_RE: Final[re.Pattern[str]] = re.compile(r"\A(0|[1-9][0-9]*)\.[0-9]{6}\Z")

# Phase-1 closed scope values, identical to the ones `canonical_query_contract/v1` enforces.
_PHASE1_RESOURCE_LEVEL: Final[str] = "campaign"
_PHASE1_AD_PLATFORM_REF: Final[str] = "meta"
_PHASE1_CURRENCY: Final[str] = "BRL"

# The spec range is 0..MAX_INT64, but RFC 8785 (I-JSON) cannot carry an integer above
# 2**53 - 1 as a JSON number, so the P1 preimage of a larger threshold is uncomputable.
_MAX_POLICY_INT: Final[int] = min(MAX_INT64, MAX_JCS_SAFE_INT)


def _strict_int(value: object, *, field_name: str, minimum: int) -> int:
    if type(value) is not int:
        raise ClosedValidationError(
            f"{field_name}: expected strict int, got {type(value).__name__}"
        )
    if not (minimum <= value <= _MAX_POLICY_INT):
        raise ClosedValidationError(
            f"{field_name}: expected integer in {minimum}..{_MAX_POLICY_INT} "
            f"(0..MAX_INT64 narrowed to the RFC 8785 safe-integer limit), got {value}"
        )
    return value


def _threshold_int(value: object, *, field_name: str) -> int:
    return _strict_int(value, field_name=field_name, minimum=0)


def _day_count(value: object, *, field_name: str) -> int:
    return _strict_int(value, field_name=field_name, minimum=1)


def decimal6_to_micros(value: object, *, field_name: str = "decimal6") -> int:
    """Validate a non-negative `decimal6` string and return its exact value in millionths."""
    if not isinstance(value, str) or _DECIMAL6_RE.fullmatch(value) is None:
        raise ClosedValidationError(
            f"{field_name}: expected non-negative decimal6 '<int>.<6 digits>', got {value!r}"
        )
    try:
        return int(value.replace(".", ""))
    except ValueError as exc:
        raise ClosedValidationError(
            f"{field_name}: decimal6 digit string exceeds the interpreter integer limit"
        ) from exc


def _metric_ref(value: object, *, field_name: str) -> str:
    if not isinstance(value, str) or _METRIC_REF_RE.fullmatch(value) is None:
        raise ClosedValidationError(
            f"{field_name}: expected 'metric:<name>_v<n>', got {value!r}"
        )
    return value


def _rule_id(value: object, *, label: str) -> str:
    return validate_opaque_ref(
        value, field_name=f"{label}.rule_id", expected_prefix="rule"
    )


def _known_restatement_kind(value: str) -> str:
    if value not in RESTATEMENT_KINDS:
        raise ClosedValidationError(
            f"restatement_rule.restatement_kinds: unknown kind {value!r} "
            f"(expected a subset of {list(RESTATEMENT_KINDS)})"
        )
    return value


def _restatement_kinds(values: object, *, field_name: str) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple)):
        raise ClosedValidationError(
            f"{field_name}: expected array of kinds, got {type(values).__name__}"
        )
    ordered = sort_utf8_strings(
        values,
        field_name=field_name,
        allow_empty=False,
        validator=_known_restatement_kind,
    )
    if tuple(values) != ordered:
        raise ClosedValidationError(
            f"{field_name}: array must already be sorted by UTF-8 bytes"
        )
    return ordered


def _closed_rule_mapping(data: object, rule_cls: Any) -> Mapping[str, Any]:
    label = f"{rule_cls.RULE_TYPE}_rule"
    mapping = require_exact_keys(data, rule_cls.KEYS, label=label)
    if mapping["rule_type"] != rule_cls.RULE_TYPE:
        raise ClosedValidationError(
            f"{label}.rule_type: expected {rule_cls.RULE_TYPE!r}, "
            f"got {mapping['rule_type']!r}"
        )
    return mapping


@dataclass(frozen=True, slots=True)
class SaturationRule:
    """Spend grew by at least `min_spend_growth` while outcome grew by at most `max_outcome_growth`."""

    RULE_TYPE: ClassVar[str] = RULE_TYPE_SATURATION
    KEYS: ClassVar[frozenset[str]] = frozenset(
        {
            "rule_id",
            "rule_type",
            "window_days",
            "spend_metric_ref",
            "outcome_metric_ref",
            "min_spend_growth",
            "max_outcome_growth",
            "min_baseline_spend_minor",
        }
    )

    rule_id: str
    window_days: int
    spend_metric_ref: str
    outcome_metric_ref: str
    min_spend_growth: str
    max_outcome_growth: str
    min_baseline_spend_minor: int

    def __post_init__(self) -> None:
        label = "saturation_rule"
        _rule_id(self.rule_id, label=label)
        _day_count(self.window_days, field_name=f"{label}.window_days")
        _metric_ref(self.spend_metric_ref, field_name=f"{label}.spend_metric_ref")
        _metric_ref(self.outcome_metric_ref, field_name=f"{label}.outcome_metric_ref")
        decimal6_to_micros(self.min_spend_growth, field_name=f"{label}.min_spend_growth")
        decimal6_to_micros(
            self.max_outcome_growth, field_name=f"{label}.max_outcome_growth"
        )
        _threshold_int(
            self.min_baseline_spend_minor,
            field_name=f"{label}.min_baseline_spend_minor",
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_type": self.RULE_TYPE,
            "window_days": self.window_days,
            "spend_metric_ref": self.spend_metric_ref,
            "outcome_metric_ref": self.outcome_metric_ref,
            "min_spend_growth": self.min_spend_growth,
            "max_outcome_growth": self.max_outcome_growth,
            "min_baseline_spend_minor": self.min_baseline_spend_minor,
        }

    @classmethod
    def from_dict(cls, data: object) -> SaturationRule:
        mapping = _closed_rule_mapping(data, cls)
        return cls(
            rule_id=mapping["rule_id"],
            window_days=mapping["window_days"],
            spend_metric_ref=mapping["spend_metric_ref"],
            outcome_metric_ref=mapping["outcome_metric_ref"],
            min_spend_growth=mapping["min_spend_growth"],
            max_outcome_growth=mapping["max_outcome_growth"],
            min_baseline_spend_minor=mapping["min_baseline_spend_minor"],
        )


@dataclass(frozen=True, slots=True)
class WasteRule:
    """Spend reached `min_spend_minor` while the outcome count stayed at or below `max_outcome_count`."""

    RULE_TYPE: ClassVar[str] = RULE_TYPE_WASTE
    KEYS: ClassVar[frozenset[str]] = frozenset(
        {
            "rule_id",
            "rule_type",
            "window_days",
            "spend_metric_ref",
            "outcome_metric_ref",
            "min_spend_minor",
            "max_outcome_count",
        }
    )

    rule_id: str
    window_days: int
    spend_metric_ref: str
    outcome_metric_ref: str
    min_spend_minor: int
    max_outcome_count: int

    def __post_init__(self) -> None:
        label = "waste_rule"
        _rule_id(self.rule_id, label=label)
        _day_count(self.window_days, field_name=f"{label}.window_days")
        _metric_ref(self.spend_metric_ref, field_name=f"{label}.spend_metric_ref")
        _metric_ref(self.outcome_metric_ref, field_name=f"{label}.outcome_metric_ref")
        _threshold_int(self.min_spend_minor, field_name=f"{label}.min_spend_minor")
        _threshold_int(self.max_outcome_count, field_name=f"{label}.max_outcome_count")

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_type": self.RULE_TYPE,
            "window_days": self.window_days,
            "spend_metric_ref": self.spend_metric_ref,
            "outcome_metric_ref": self.outcome_metric_ref,
            "min_spend_minor": self.min_spend_minor,
            "max_outcome_count": self.max_outcome_count,
        }

    @classmethod
    def from_dict(cls, data: object) -> WasteRule:
        mapping = _closed_rule_mapping(data, cls)
        return cls(
            rule_id=mapping["rule_id"],
            window_days=mapping["window_days"],
            spend_metric_ref=mapping["spend_metric_ref"],
            outcome_metric_ref=mapping["outcome_metric_ref"],
            min_spend_minor=mapping["min_spend_minor"],
            max_outcome_count=mapping["max_outcome_count"],
        )


@dataclass(frozen=True, slots=True)
class StalledDeliveryRule:
    """Impressions stayed at or below `max_impressions` for `min_consecutive_days` days in a row."""

    RULE_TYPE: ClassVar[str] = RULE_TYPE_STALLED_DELIVERY
    KEYS: ClassVar[frozenset[str]] = frozenset(
        {"rule_id", "rule_type", "min_consecutive_days", "max_impressions"}
    )

    rule_id: str
    min_consecutive_days: int
    max_impressions: int

    def __post_init__(self) -> None:
        label = "stalled_delivery_rule"
        _rule_id(self.rule_id, label=label)
        _day_count(
            self.min_consecutive_days, field_name=f"{label}.min_consecutive_days"
        )
        _threshold_int(self.max_impressions, field_name=f"{label}.max_impressions")

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_type": self.RULE_TYPE,
            "min_consecutive_days": self.min_consecutive_days,
            "max_impressions": self.max_impressions,
        }

    @classmethod
    def from_dict(cls, data: object) -> StalledDeliveryRule:
        mapping = _closed_rule_mapping(data, cls)
        return cls(
            rule_id=mapping["rule_id"],
            min_consecutive_days=mapping["min_consecutive_days"],
            max_impressions=mapping["max_impressions"],
        )


@dataclass(frozen=True, slots=True)
class RestatementRule:
    """Restatements of the listed kinds within `lookback_days` days block mutation recommendations."""

    RULE_TYPE: ClassVar[str] = RULE_TYPE_RESTATEMENT
    KEYS: ClassVar[frozenset[str]] = frozenset(
        {"rule_id", "rule_type", "lookback_days", "restatement_kinds"}
    )

    rule_id: str
    lookback_days: int
    restatement_kinds: tuple[str, ...]

    def __post_init__(self) -> None:
        label = "restatement_rule"
        _rule_id(self.rule_id, label=label)
        _day_count(self.lookback_days, field_name=f"{label}.lookback_days")
        object.__setattr__(
            self,
            "restatement_kinds",
            _restatement_kinds(
                self.restatement_kinds, field_name=f"{label}.restatement_kinds"
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_type": self.RULE_TYPE,
            "lookback_days": self.lookback_days,
            "restatement_kinds": list(self.restatement_kinds),
        }

    @classmethod
    def from_dict(cls, data: object) -> RestatementRule:
        mapping = _closed_rule_mapping(data, cls)
        if not isinstance(mapping["restatement_kinds"], list):
            raise ClosedValidationError(
                "restatement_rule.restatement_kinds: expected JSON array list"
            )
        return cls(
            rule_id=mapping["rule_id"],
            lookback_days=mapping["lookback_days"],
            restatement_kinds=tuple(mapping["restatement_kinds"]),
        )


AnalysisRule = SaturationRule | WasteRule | StalledDeliveryRule | RestatementRule

_RULE_CLASSES: Final[Mapping[str, type[AnalysisRule]]] = MappingProxyType(
    {
        rule_cls.RULE_TYPE: rule_cls
        for rule_cls in (
            SaturationRule,
            WasteRule,
            StalledDeliveryRule,
            RestatementRule,
        )
    }
)


def rule_from_dict(data: object) -> AnalysisRule:
    """Parse one member of the closed rule union, dispatching on `rule_type`."""
    mapping = require_mapping(data, label="analysis_rule")
    rule_type = mapping.get("rule_type")
    if not isinstance(rule_type, str) or rule_type not in _RULE_CLASSES:
        raise ClosedValidationError(
            f"analysis_rule.rule_type: unknown rule_type {rule_type!r} "
            f"(expected one of {list(RULE_TYPES)})"
        )
    return _RULE_CLASSES[rule_type].from_dict(mapping)


def _require_phase1_literal(value: object, expected: str, *, field_name: str) -> None:
    if not isinstance(value, str) or value != expected:
        raise ClosedValidationError(
            f"{field_name}: must equal {expected!r} in Phase 1, got {value!r}"
        )


@dataclass(frozen=True, slots=True)
class ApplicabilityScope:
    """Closed scope a policy applies to; mirrors the Phase-1 canonical query scope members."""

    KEYS: ClassVar[frozenset[str]] = frozenset(
        {"resource_scope_ref", "resource_level", "ad_platform_ref", "currency"}
    )

    resource_scope_ref: str
    resource_level: str
    ad_platform_ref: str
    currency: str

    def __post_init__(self) -> None:
        label = "applicability_scope"
        validate_opaque_ref(
            self.resource_scope_ref,
            field_name=f"{label}.resource_scope_ref",
            expected_prefix="scope",
        )
        _require_phase1_literal(
            self.resource_level,
            _PHASE1_RESOURCE_LEVEL,
            field_name=f"{label}.resource_level",
        )
        _require_phase1_literal(
            self.ad_platform_ref,
            _PHASE1_AD_PLATFORM_REF,
            field_name=f"{label}.ad_platform_ref",
        )
        validate_currency_iso4217(self.currency, field_name=f"{label}.currency")
        _require_phase1_literal(
            self.currency, _PHASE1_CURRENCY, field_name=f"{label}.currency"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "resource_scope_ref": self.resource_scope_ref,
            "resource_level": self.resource_level,
            "ad_platform_ref": self.ad_platform_ref,
            "currency": self.currency,
        }

    @classmethod
    def from_dict(
        cls, data: object, *, label: str = "applicability_scope"
    ) -> ApplicabilityScope:
        mapping = require_exact_keys(data, cls.KEYS, label=label)
        return cls(
            resource_scope_ref=mapping["resource_scope_ref"],
            resource_level=mapping["resource_level"],
            ad_platform_ref=mapping["ad_platform_ref"],
            currency=mapping["currency"],
        )


@dataclass(frozen=True, slots=True)
class PolicyValidity:
    """Validity window with `valid_from_utc` strictly before `valid_until_utc` (6-digit UTC)."""

    KEYS: ClassVar[frozenset[str]] = frozenset({"valid_from_utc", "valid_until_utc"})

    valid_from_utc: str
    valid_until_utc: str

    def __post_init__(self) -> None:
        start = parse_timestamp_utc_micros(
            self.valid_from_utc, field_name="validity.valid_from_utc"
        )
        end = parse_timestamp_utc_micros(
            self.valid_until_utc, field_name="validity.valid_until_utc"
        )
        if not start < end:
            raise ClosedValidationError(
                f"validity: valid_from_utc {self.valid_from_utc!r} must be strictly "
                f"before valid_until_utc {self.valid_until_utc!r}"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid_from_utc": self.valid_from_utc,
            "valid_until_utc": self.valid_until_utc,
        }

    @classmethod
    def from_dict(cls, data: object, *, label: str = "validity") -> PolicyValidity:
        mapping = require_exact_keys(data, cls.KEYS, label=label)
        return cls(
            valid_from_utc=mapping["valid_from_utc"],
            valid_until_utc=mapping["valid_until_utc"],
        )


def _validate_rules(rules: object, *, field_name: str) -> tuple[AnalysisRule, ...]:
    if not isinstance(rules, (list, tuple)) or len(rules) == 0:
        raise ClosedValidationError(f"{field_name}: expected a non-empty array of rules")
    for index, rule in enumerate(rules):
        if not isinstance(rule, tuple(_RULE_CLASSES.values())):
            raise ClosedValidationError(
                f"{field_name}[{index}]: expected a member of the closed rule union, "
                f"got {type(rule).__name__}"
            )
    rule_ids = [rule.rule_id for rule in rules]
    if len(set(rule_ids)) != len(rule_ids):
        raise ClosedValidationError(f"{field_name}: duplicate rule_id")
    byte_keys = [rule_id.encode("utf-8") for rule_id in rule_ids]
    if byte_keys != sorted(byte_keys):
        raise ClosedValidationError(
            f"{field_name}: rules must be sorted by the raw UTF-8 bytes of rule_id"
        )
    return tuple(rules)


@dataclass(frozen=True, slots=True)
class AnalysisPolicy:
    """Closed `smart_ads/analysis_policy/v1` P1 artifact: versioned thresholds for one scope."""

    SCHEMA: ClassVar[str] = "smart_ads/analysis_policy/v1"
    P1_DOMAIN_PREFIX: ClassVar[str] = ADR_P1_DOMAIN_PREFIXES[SCHEMA]
    CORE_KEYS: ClassVar[frozenset[str]] = frozenset(
        {
            "$schema",
            "policy_id",
            "policy_version",
            "tenant_ref",
            "applicability_scope",
            "validity",
            "rules",
        }
    )
    KEYS: ClassVar[frozenset[str]] = CORE_KEYS | {"integrity"}

    policy_id: str
    policy_version: str
    tenant_ref: str
    applicability_scope: ApplicabilityScope
    validity: PolicyValidity
    rules: tuple[AnalysisRule, ...]
    integrity: P1Integrity | None = None

    def __post_init__(self) -> None:
        label = "analysis_policy"
        validate_opaque_ref(
            self.policy_id, field_name=f"{label}.policy_id", expected_prefix="policy"
        )
        validate_non_empty_str(
            self.policy_version, field_name=f"{label}.policy_version"
        )
        validate_opaque_ref(
            self.tenant_ref, field_name=f"{label}.tenant_ref", expected_prefix="tenant"
        )
        if not isinstance(self.applicability_scope, ApplicabilityScope):
            raise ClosedValidationError(
                f"{label}.applicability_scope: expected ApplicabilityScope"
            )
        if not isinstance(self.validity, PolicyValidity):
            raise ClosedValidationError(f"{label}.validity: expected PolicyValidity")
        object.__setattr__(
            self, "rules", _validate_rules(self.rules, field_name=f"{label}.rules")
        )
        if self.integrity is not None and not isinstance(self.integrity, P1Integrity):
            raise ClosedValidationError(
                f"{label}.integrity: expected P1Integrity or None"
            )
        if self.integrity is not None and self.integrity.is_signed:
            expected = self.p1_content_digest()
            if self.integrity.content_digest != expected:
                raise ClosedValidationError(
                    f"{label}.integrity.content_digest: recomputed {expected!r} "
                    f"!= asserted {self.integrity.content_digest!r}"
                )

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "$schema": self.SCHEMA,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "tenant_ref": self.tenant_ref,
            "applicability_scope": self.applicability_scope.to_dict(),
            "validity": self.validity.to_dict(),
            "rules": [rule.to_dict() for rule in self.rules],
        }
        if self.integrity is not None:
            out["integrity"] = self.integrity.to_dict()
        return out

    def p1_preimage(self) -> dict[str, Any]:
        """Return the P1 preimage: this envelope without `integrity.content_digest/signature_base64`."""
        return _p1_preimage(self.to_dict())

    def p1_content_digest(self) -> str:
        """Compute `'sha256:' + hex(SHA-256(RFC8785(P1 preimage)))`; the wheel never signs."""
        return _p1_content_digest(self.to_dict())

    @classmethod
    def from_dict(
        cls,
        data: object,
        *,
        require_signed: bool = False,
    ) -> AnalysisPolicy:
        if not isinstance(require_signed, bool):
            raise ClosedValidationError("require_signed: expected bool")
        mapping = require_mapping(data, label="analysis_policy")
        if require_signed or "integrity" in mapping:
            require_exact_keys(mapping, cls.KEYS, label="analysis_policy")
            integrity: P1Integrity | None = P1Integrity.from_dict(
                mapping["integrity"], require_signed=require_signed
            )
        else:
            require_exact_keys(mapping, cls.CORE_KEYS, label="analysis_policy")
            integrity = None
        if mapping["$schema"] != cls.SCHEMA:
            raise ClosedValidationError(
                f"analysis_policy.$schema: expected {cls.SCHEMA!r}, "
                f"got {mapping['$schema']!r}"
            )
        if not isinstance(mapping["rules"], list):
            raise ClosedValidationError("analysis_policy.rules: expected JSON array list")
        return cls(
            policy_id=mapping["policy_id"],
            policy_version=mapping["policy_version"],
            tenant_ref=mapping["tenant_ref"],
            applicability_scope=ApplicabilityScope.from_dict(
                mapping["applicability_scope"], label="analysis_policy.applicability_scope"
            ),
            validity=PolicyValidity.from_dict(
                mapping["validity"], label="analysis_policy.validity"
            ),
            rules=tuple(rule_from_dict(rule) for rule in mapping["rules"]),
            integrity=integrity,
        )


class PolicyNotApplicableError(ClosedValidationError):
    """A well-formed policy does not apply to the evaluation scope or instant; `code` is closed."""

    def __init__(self, code: str, detail: str) -> None:
        if not isinstance(code, str) or code not in POLICY_NOT_APPLICABLE_CODES:
            raise ClosedValidationError(
                f"policy_not_applicable.code: unknown code {code!r} "
                f"(expected one of {list(POLICY_NOT_APPLICABLE_CODES)})"
            )
        super().__init__(code, detail)
        self.code = code
        self.detail = detail

    def __str__(self) -> str:
        return f"{self.code}: {self.detail}"


@dataclass(frozen=True, slots=True)
class EvaluationScope:
    """Scope of the analysis a policy is checked against; values need only be well formed."""

    tenant_ref: str
    resource_scope_ref: str
    resource_level: str
    ad_platform_ref: str
    currency: str

    def __post_init__(self) -> None:
        label = "evaluation_scope"
        validate_opaque_ref(
            self.tenant_ref, field_name=f"{label}.tenant_ref", expected_prefix="tenant"
        )
        validate_opaque_ref(
            self.resource_scope_ref,
            field_name=f"{label}.resource_scope_ref",
            expected_prefix="scope",
        )
        validate_non_empty_str(self.resource_level, field_name=f"{label}.resource_level")
        validate_non_empty_str(
            self.ad_platform_ref, field_name=f"{label}.ad_platform_ref"
        )
        validate_currency_iso4217(self.currency, field_name=f"{label}.currency")


def _scope_mismatch_code(policy: AnalysisPolicy, scope: EvaluationScope) -> str | None:
    declared = policy.applicability_scope
    checks = (
        ("tenant_mismatch", policy.tenant_ref, scope.tenant_ref),
        (
            "resource_scope_mismatch",
            declared.resource_scope_ref,
            scope.resource_scope_ref,
        ),
        ("resource_level_mismatch", declared.resource_level, scope.resource_level),
        ("ad_platform_mismatch", declared.ad_platform_ref, scope.ad_platform_ref),
        ("currency_mismatch", declared.currency, scope.currency),
    )
    for code, expected, actual in checks:
        if expected != actual:
            return code
    return None


def _validity_code(validity: PolicyValidity, instant_micros: int) -> str | None:
    start = parse_timestamp_utc_micros(
        validity.valid_from_utc, field_name="validity.valid_from_utc"
    )
    end = parse_timestamp_utc_micros(
        validity.valid_until_utc, field_name="validity.valid_until_utc"
    )
    if instant_micros < start:
        return "not_yet_valid"
    if instant_micros > end:
        return "expired"
    return None


def policy_applicability_code(
    policy: AnalysisPolicy,
    scope: EvaluationScope,
    evaluation_instant_utc: str,
) -> str | None:
    """Return the first closed reason `policy` does not apply, or None when it applies.

    Pure: the instant is an argument (6-digit UTC timestamp), never read from a clock. Scope
    members are checked in the order of POLICY_NOT_APPLICABLE_CODES (tenant, resource scope,
    resource level, ad platform, currency) before the validity window. The window is a closed
    interval: an instant equal to `valid_from_utc` or `valid_until_utc` is inside it.
    """
    if not isinstance(policy, AnalysisPolicy):
        raise ClosedValidationError(
            f"policy: expected AnalysisPolicy, got {type(policy).__name__}"
        )
    if not isinstance(scope, EvaluationScope):
        raise ClosedValidationError(
            f"scope: expected EvaluationScope, got {type(scope).__name__}"
        )
    instant = parse_timestamp_utc_micros(
        evaluation_instant_utc, field_name="evaluation_instant_utc"
    )
    return _scope_mismatch_code(policy, scope) or _validity_code(policy.validity, instant)


def require_policy_applicable(
    policy: AnalysisPolicy,
    scope: EvaluationScope,
    evaluation_instant_utc: str,
) -> None:
    """Raise PolicyNotApplicableError (closed `code`) unless `policy` applies; see the code function."""
    code = policy_applicability_code(policy, scope, evaluation_instant_utc)
    if code is not None:
        raise PolicyNotApplicableError(
            code,
            f"policy {policy.policy_id!r} version {policy.policy_version!r} "
            f"does not apply at {evaluation_instant_utc!r}",
        )


__all__ = [
    "AnalysisPolicy",
    "AnalysisRule",
    "ApplicabilityScope",
    "EvaluationScope",
    "METRIC_REF_PATTERN",
    "POLICY_NOT_APPLICABLE_CODES",
    "PolicyNotApplicableError",
    "PolicyValidity",
    "RESTATEMENT_KINDS",
    "RULE_TYPES",
    "RestatementRule",
    "SaturationRule",
    "StalledDeliveryRule",
    "WasteRule",
    "decimal6_to_micros",
    "policy_applicability_code",
    "require_policy_applicable",
    "rule_from_dict",
]
