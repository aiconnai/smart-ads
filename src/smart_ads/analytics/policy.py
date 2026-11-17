"""Versioned tenant analysis policy with a closed union of typed threshold rules (ADR-0001 section 7)."""
from __future__ import annotations

from collections.abc import Callable, Collection, Mapping
from dataclasses import dataclass, fields
import re
from types import MappingProxyType
from typing import Any, ClassVar, Final, Self

from smart_ads.contracts.jcs import (
    ADR_P1_DOMAIN_PREFIXES,
    MAX_JCS_SAFE_INT,
    ArtifactLocator,
    P1Integrity,
    canonicalize_jcs,
    p1_content_digest as _p1_content_digest,
    p1_preimage as _p1_preimage,
)
from smart_ads.contracts.numerics import MAX_INT64
from smart_ads.contracts.scalars import (
    ClosedValidationError,
    parse_timestamp_utc_micros,
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
POLICY_ERROR_CODES: Final[frozenset[str]] = frozenset(
    {
        "invalid_type",  # wrong JSON type for a member or argument (bool/float/native int as int64, ...)
        "invalid_grammar",  # string fails its closed grammar (refs, int64/decimal6 text, timestamps)
        "out_of_range",  # integer, int64 string or decimal6 integer part outside its closed bound
        "unknown_member",  # extra member in a closed object
        "missing_member",  # required member absent (including a missing integrity block)
        "schema_mismatch",  # `$schema` is not smart_ads/analysis_policy/v1
        "unknown_rule_type",  # `rule_type` outside the closed union, or not the one of this class
        "empty",  # rules or restatement_kinds array is empty
        "duplicate_rule_id",  # two rules share a rule_id
        "duplicate_restatement_kind",  # a restatement kind is repeated
        "unsorted",  # rules or restatement_kinds not in raw UTF-8 byte order
        "unsupported_value",  # well-formed value outside a closed set (Phase-1 scope, kinds)
        "invalid_validity_window",  # valid_from_utc is not strictly before valid_until_utc
        "invalid_integrity",  # integrity block malformed, partial or in the wrong state
        "content_digest_mismatch",  # signed integrity.content_digest != recomputed P1 digest
    }
)

# Metric reference grammar of `base_metric_definition/v1`; numerics.py keeps its regex private,
# so the pattern is mirrored here and pinned to the original by a test.
METRIC_REF_PATTERN: Final[str] = r"\Ametric:[a-z][a-z0-9_]*_v[1-9][0-9]*\Z"
_METRIC_REF_RE: Final[re.Pattern[str]] = re.compile(METRIC_REF_PATTERN)
_UINT64_RE: Final[re.Pattern[str]] = re.compile(r"\A(0|[1-9][0-9]*)\Z")
_DECIMAL6_RE: Final[re.Pattern[str]] = re.compile(r"\A(0|[1-9][0-9]*)\.[0-9]{6}\Z")
# int64-valued thresholds and the integer part of decimal6 ratios are bounded explicitly (digit
# count first, then value) so validity never depends on the interpreter's int/str digit limit.
_MAX_INT64_DIGITS: Final[int] = len(str(MAX_INT64))
# Phase-1 closed scope values, identical to the ones `canonical_query_contract/v1` enforces.
_PHASE1_SCOPE_VALUES: Final[tuple[tuple[str, str], ...]] = (
    ("resource_level", "campaign"),
    ("ad_platform_ref", "meta"),
    ("currency", "BRL"),
)
_Check = Callable[..., Any]


class _CodedError(ClosedValidationError):
    """ClosedValidationError carrying a `code` that must belong to the closed set `CODES`."""

    CODES: ClassVar[Collection[str]] = ()

    def __init__(self, code: str, detail: str) -> None:
        if not isinstance(code, str) or code not in self.CODES:
            raise ClosedValidationError(
                f"{type(self).__name__}.code: unknown code {code!r} "
                f"(expected one of {sorted(self.CODES)})"
            )
        super().__init__(code, detail)
        self.code = code
        self.detail = detail

    def __str__(self) -> str:
        return f"{self.code}: {self.detail}"


class PolicyValidationError(_CodedError):
    """Malformed policy evidence; `code` is a member of POLICY_ERROR_CODES."""

    CODES: ClassVar[Collection[str]] = POLICY_ERROR_CODES


class PolicyNotApplicableError(_CodedError):
    """A well-formed policy does not apply to the evaluation scope or instant; `code` is closed."""

    CODES: ClassVar[Collection[str]] = POLICY_NOT_APPLICABLE_CODES


def _fail(code: str, detail: str) -> PolicyValidationError:
    return PolicyValidationError(code, detail)


def _require_str(value: object, field_name: str) -> str:
    if not isinstance(value, str):
        raise _fail("invalid_type", f"{field_name}: expected str, got {type(value).__name__}")
    return value


def _shared(check: _Check, value: object, *, field_name: str, **kwargs: Any) -> Any:
    """Run a shared scalar validator, reporting its rejection as a coded `invalid_grammar`."""
    _require_str(value, field_name)
    try:
        return check(value, field_name=field_name, **kwargs)
    except ClosedValidationError as exc:
        raise _fail("invalid_grammar", str(exc)) from exc


def _closed_mapping(data: object, keys: frozenset[str], *, label: str) -> Mapping[str, Any]:
    if not isinstance(data, Mapping) or not all(isinstance(key, str) for key in data):
        raise _fail("invalid_type", f"{label}: expected a JSON object with string keys")
    present = set(data)
    if keys - present:
        raise _fail("missing_member", f"{label}: missing members {sorted(keys - present)}")
    if present - keys:
        raise _fail("unknown_member", f"{label}: unknown members {sorted(present - keys)}")
    return data


def _day_count(value: object, *, field_name: str) -> int:
    """Strict JSON integer >= 1 within the RFC 8785 safe-integer range."""
    if type(value) is not int:
        raise _fail(
            "invalid_type", f"{field_name}: expected strict int, got {type(value).__name__}"
        )
    if not 1 <= value <= MAX_JCS_SAFE_INT:
        raise _fail("out_of_range", f"{field_name}: expected 1..{MAX_JCS_SAFE_INT}, got {value}")
    return value


def _bound_int64_digits(digits: str, *, field_name: str) -> None:
    if len(digits) > _MAX_INT64_DIGITS or int(digits) > MAX_INT64:
        raise _fail("out_of_range", f"{field_name}: exceeds MAX_INT64 {MAX_INT64}")


def _uint64(value: object, *, field_name: str) -> str:
    """Canonical unsigned int64 string `^(0|[1-9][0-9]*)$`, at most MAX_INT64."""
    text = _require_str(value, field_name)
    if _UINT64_RE.fullmatch(text) is None:
        raise _fail(
            "invalid_grammar", f"{field_name}: expected canonical uint64 text, got {text!r:.80}"
        )
    _bound_int64_digits(text, field_name=field_name)
    return text


def decimal6_to_micros(value: object, *, field_name: str = "decimal6") -> int:
    """Validate a non-negative `decimal6` string (integer part <= MAX_INT64) and return millionths."""
    text = _require_str(value, field_name)
    match = _DECIMAL6_RE.fullmatch(text)
    if match is None:
        raise _fail(
            "invalid_grammar",
            f"{field_name}: expected decimal6 '<int>.<6 digits>', got {text!r:.80}",
        )
    _bound_int64_digits(match.group(1), field_name=field_name)
    return int(text.replace(".", ""))


def _decimal6(value: object, *, field_name: str) -> str:
    decimal6_to_micros(value, field_name=field_name)
    return str(value)


def _metric_ref(value: object, *, field_name: str) -> str:
    text = _require_str(value, field_name)
    if _METRIC_REF_RE.fullmatch(text) is None:
        raise _fail(
            "invalid_grammar",
            f"{field_name}: expected 'metric:<name>_v<n>', got {text!r:.80}",
        )
    return text


def _restatement_kinds(values: object, *, field_name: str) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple)):
        raise _fail("invalid_type", f"{field_name}: expected array, got {type(values).__name__}")
    if not values:
        raise _fail("empty", f"{field_name}: at least one restatement kind is required")
    for kind in values:
        _require_str(kind, field_name)
        if kind not in RESTATEMENT_KINDS:
            raise _fail("unsupported_value", f"{field_name}: unknown kind {kind!r:.80}")
    if len(set(values)) != len(values):
        raise _fail("duplicate_restatement_kind", f"{field_name}: duplicate kind")
    if list(values) != sorted(values, key=lambda kind: kind.encode("utf-8")):
        raise _fail("unsorted", f"{field_name}: kinds must be sorted by raw UTF-8 bytes")
    return tuple(values)


def _rule_keys(checks: tuple[tuple[str, _Check], ...]) -> frozenset[str]:
    return frozenset({"rule_id", "rule_type", *(name for name, _ in checks)})


@dataclass(frozen=True, slots=True)
class _Rule:
    """Shared envelope of the closed rule union: `rule_id`, `rule_type` and per-member checks."""

    RULE_TYPE: ClassVar[str]
    CHECKS: ClassVar[tuple[tuple[str, _Check], ...]]
    KEYS: ClassVar[frozenset[str]]

    rule_id: str

    def __post_init__(self) -> None:
        label = f"{self.RULE_TYPE}_rule"
        _shared(
            validate_opaque_ref,
            self.rule_id,
            field_name=f"{label}.rule_id",
            expected_prefix="rule",
        )
        for name, check in self.CHECKS:
            checked = check(getattr(self, name), field_name=f"{label}.{name}")
            object.__setattr__(self, name, checked)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"rule_id": self.rule_id, "rule_type": self.RULE_TYPE}
        for name, _ in self.CHECKS:
            value = getattr(self, name)
            out[name] = list(value) if isinstance(value, tuple) else value
        return out

    @classmethod
    def from_dict(cls, data: object) -> Self:
        label = f"{cls.RULE_TYPE}_rule"
        mapping = _closed_mapping(data, cls.KEYS, label=label)
        if mapping["rule_type"] != cls.RULE_TYPE:
            raise _fail(
                "unknown_rule_type",
                f"{label}.rule_type: expected {cls.RULE_TYPE!r}, got {mapping['rule_type']!r:.80}",
            )
        members = {name: mapping[name] for name in cls.KEYS - {"rule_type"}}
        if any(isinstance(value, tuple) for value in members.values()):
            raise _fail("invalid_type", f"{label}: JSON arrays must be lists, not tuples")
        return cls(**members)


@dataclass(frozen=True, slots=True)
class SaturationRule(_Rule):
    """Spend grew by at least `min_spend_growth` while outcome grew by at most `max_outcome_growth`."""

    RULE_TYPE: ClassVar[str] = RULE_TYPE_SATURATION
    CHECKS: ClassVar[tuple[tuple[str, _Check], ...]] = (
        ("window_days", _day_count),
        ("spend_metric_ref", _metric_ref),
        ("outcome_metric_ref", _metric_ref),
        ("min_spend_growth", _decimal6),
        ("max_outcome_growth", _decimal6),
        ("min_baseline_spend_minor", _uint64),
    )
    KEYS: ClassVar[frozenset[str]] = _rule_keys(CHECKS)

    window_days: int
    spend_metric_ref: str
    outcome_metric_ref: str
    min_spend_growth: str
    max_outcome_growth: str
    min_baseline_spend_minor: str

    @property
    def min_baseline_spend_minor_int(self) -> int:
        """Exact int value of the validated `min_baseline_spend_minor` string."""
        return int(self.min_baseline_spend_minor)


@dataclass(frozen=True, slots=True)
class WasteRule(_Rule):
    """Spend reached `min_spend_minor` while the outcome count stayed at or below `max_outcome_count`."""

    RULE_TYPE: ClassVar[str] = RULE_TYPE_WASTE
    CHECKS: ClassVar[tuple[tuple[str, _Check], ...]] = (
        ("window_days", _day_count),
        ("spend_metric_ref", _metric_ref),
        ("outcome_metric_ref", _metric_ref),
        ("min_spend_minor", _uint64),
        ("max_outcome_count", _uint64),
    )
    KEYS: ClassVar[frozenset[str]] = _rule_keys(CHECKS)

    window_days: int
    spend_metric_ref: str
    outcome_metric_ref: str
    min_spend_minor: str
    max_outcome_count: str

    @property
    def min_spend_minor_int(self) -> int:
        """Exact int value of the validated `min_spend_minor` string."""
        return int(self.min_spend_minor)

    @property
    def max_outcome_count_int(self) -> int:
        """Exact int value of the validated `max_outcome_count` string."""
        return int(self.max_outcome_count)


@dataclass(frozen=True, slots=True)
class StalledDeliveryRule(_Rule):
    """Impressions stayed at or below `max_impressions` for `min_consecutive_days` days in a row."""

    RULE_TYPE: ClassVar[str] = RULE_TYPE_STALLED_DELIVERY
    CHECKS: ClassVar[tuple[tuple[str, _Check], ...]] = (
        ("min_consecutive_days", _day_count),
        ("max_impressions", _uint64),
    )
    KEYS: ClassVar[frozenset[str]] = _rule_keys(CHECKS)

    min_consecutive_days: int
    max_impressions: str

    @property
    def max_impressions_int(self) -> int:
        """Exact int value of the validated `max_impressions` string."""
        return int(self.max_impressions)


@dataclass(frozen=True, slots=True)
class RestatementRule(_Rule):
    """Restatements of the listed kinds within `lookback_days` days block mutation recommendations."""

    RULE_TYPE: ClassVar[str] = RULE_TYPE_RESTATEMENT
    CHECKS: ClassVar[tuple[tuple[str, _Check], ...]] = (
        ("lookback_days", _day_count),
        ("restatement_kinds", _restatement_kinds),
    )
    KEYS: ClassVar[frozenset[str]] = _rule_keys(CHECKS)

    lookback_days: int
    restatement_kinds: tuple[str, ...]


AnalysisRule = SaturationRule | WasteRule | StalledDeliveryRule | RestatementRule

_RULE_CLASSES: Final[Mapping[str, type[AnalysisRule]]] = MappingProxyType(
    {
        rule_cls.RULE_TYPE: rule_cls
        for rule_cls in (SaturationRule, WasteRule, StalledDeliveryRule, RestatementRule)
    }
)


def rule_from_dict(data: object) -> AnalysisRule:
    """Parse one member of the closed rule union, dispatching on `rule_type`."""
    if not isinstance(data, Mapping):
        raise _fail(
            "invalid_type", f"analysis_rule: expected a JSON object, got {type(data).__name__}"
        )
    if "rule_type" not in data:
        raise _fail("missing_member", "analysis_rule: missing member 'rule_type'")
    rule_type = data["rule_type"]
    _require_str(rule_type, "analysis_rule.rule_type")
    rule_cls = _RULE_CLASSES.get(rule_type)
    if rule_cls is None:
        raise _fail(
            "unknown_rule_type",
            f"analysis_rule.rule_type: {rule_type!r:.80} is not one of {list(RULE_TYPES)}",
        )
    return rule_cls.from_dict(data)


def _require_phase1(value: object, expected: str, *, field_name: str) -> None:
    if _require_str(value, field_name) != expected:
        raise _fail(
            "unsupported_value",
            f"{field_name}: must equal {expected!r} in Phase 1, got {value!r:.80}",
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
        _shared(
            validate_opaque_ref,
            self.resource_scope_ref,
            field_name=f"{label}.resource_scope_ref",
            expected_prefix="scope",
        )
        for name, expected in _PHASE1_SCOPE_VALUES:
            _require_phase1(getattr(self, name), expected, field_name=f"{label}.{name}")

    def to_dict(self) -> dict[str, Any]:
        return {f.name: getattr(self, f.name) for f in fields(self)}

    @classmethod
    def from_dict(cls, data: object, *, label: str = "applicability_scope") -> Self:
        return cls(**_closed_mapping(data, cls.KEYS, label=label))


@dataclass(frozen=True, slots=True)
class PolicyValidity:
    """Validity window with `valid_from_utc` strictly before `valid_until_utc` (6-digit UTC)."""

    KEYS: ClassVar[frozenset[str]] = frozenset({"valid_from_utc", "valid_until_utc"})

    valid_from_utc: str
    valid_until_utc: str

    def __post_init__(self) -> None:
        start = _shared(
            parse_timestamp_utc_micros, self.valid_from_utc, field_name="validity.valid_from_utc"
        )
        end = _shared(
            parse_timestamp_utc_micros, self.valid_until_utc, field_name="validity.valid_until_utc"
        )
        if not start < end:
            raise _fail(
                "invalid_validity_window",
                f"validity: valid_from_utc {self.valid_from_utc!r} must be strictly "
                f"before valid_until_utc {self.valid_until_utc!r}",
            )

    def to_dict(self) -> dict[str, Any]:
        return {f.name: getattr(self, f.name) for f in fields(self)}

    @classmethod
    def from_dict(cls, data: object, *, label: str = "validity") -> Self:
        return cls(**_closed_mapping(data, cls.KEYS, label=label))


def _validate_rules(rules: object, *, field_name: str) -> tuple[AnalysisRule, ...]:
    if not isinstance(rules, (list, tuple)):
        raise _fail("invalid_type", f"{field_name}: expected array, got {type(rules).__name__}")
    if not rules:
        raise _fail("empty", f"{field_name}: at least one rule is required")
    for index, rule in enumerate(rules):
        if not isinstance(rule, tuple(_RULE_CLASSES.values())):
            raise _fail(
                "invalid_type",
                f"{field_name}[{index}]: expected a rule, got {type(rule).__name__}",
            )
    rule_ids = [rule.rule_id for rule in rules]
    if len(set(rule_ids)) != len(rule_ids):
        raise _fail("duplicate_rule_id", f"{field_name}: duplicate rule_id")
    if rule_ids != sorted(rule_ids, key=lambda rule_id: rule_id.encode("utf-8")):
        raise _fail("unsorted", f"{field_name}: rules must be sorted by raw UTF-8 bytes of rule_id")
    return tuple(rules)


def _parse_integrity(raw: object, *, require_signed: bool) -> P1Integrity:
    try:
        return P1Integrity.from_dict(raw, require_signed=require_signed)
    except ClosedValidationError as exc:
        raise _fail("invalid_integrity", str(exc)) from exc


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
        _shared(
            validate_opaque_ref,
            self.policy_id,
            field_name=f"{label}.policy_id",
            expected_prefix="policy",
        )
        _shared(validate_non_empty_str, self.policy_version, field_name=f"{label}.policy_version")
        _shared(
            validate_opaque_ref,
            self.tenant_ref,
            field_name=f"{label}.tenant_ref",
            expected_prefix="tenant",
        )
        if not isinstance(self.applicability_scope, ApplicabilityScope):
            raise _fail("invalid_type", f"{label}.applicability_scope: expected ApplicabilityScope")
        if not isinstance(self.validity, PolicyValidity):
            raise _fail("invalid_type", f"{label}.validity: expected PolicyValidity")
        object.__setattr__(self, "rules", _validate_rules(self.rules, field_name=f"{label}.rules"))
        if self.integrity is not None and not isinstance(self.integrity, P1Integrity):
            raise _fail("invalid_integrity", f"{label}.integrity: expected P1Integrity or None")
        if self.integrity is not None and self.integrity.is_signed:
            expected = self.p1_content_digest()
            if self.integrity.content_digest != expected:
                raise _fail(
                    "content_digest_mismatch",
                    f"{label}.integrity.content_digest: recomputed {expected!r} "
                    f"!= asserted {self.integrity.content_digest!r}",
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

    def _p1_envelope(self) -> dict[str, Any]:
        if self.integrity is None:
            raise _fail(
                "missing_member",
                "analysis_policy.integrity: the P1 preimage and digest need an integrity block",
            )
        return self.to_dict()

    def p1_preimage(self) -> dict[str, Any]:
        """Return the P1 preimage: this envelope without `integrity.content_digest/signature_base64`."""
        return _p1_preimage(self._p1_envelope())

    def p1_content_digest(self) -> str:
        """Compute `'sha256:' + hex(SHA-256(RFC8785(P1 preimage)))`; the wheel never signs."""
        return _p1_content_digest(self._p1_envelope())

    def locator(self) -> ArtifactLocator:
        """Typed locator over the RFC 8785 bytes of the full envelope (as `application/admission.py`)."""
        return ArtifactLocator.for_canonical_bytes(self.SCHEMA, canonicalize_jcs(self.to_dict()))

    @classmethod
    def from_dict(cls, data: object, *, require_signed: bool = False) -> Self:
        if not isinstance(require_signed, bool):
            raise _fail("invalid_type", "require_signed: expected bool")
        has_integrity = require_signed or (isinstance(data, Mapping) and "integrity" in data)
        mapping = _closed_mapping(
            data, cls.KEYS if has_integrity else cls.CORE_KEYS, label="analysis_policy"
        )
        if mapping["$schema"] != cls.SCHEMA:
            raise _fail(
                "schema_mismatch",
                f"analysis_policy.$schema: expected {cls.SCHEMA!r}, got {mapping['$schema']!r:.80}",
            )
        if not isinstance(mapping["rules"], list):
            raise _fail("invalid_type", "analysis_policy.rules: expected JSON array list")
        integrity = (
            _parse_integrity(mapping["integrity"], require_signed=require_signed)
            if has_integrity
            else None
        )
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
        _shared(
            validate_opaque_ref,
            self.tenant_ref,
            field_name=f"{label}.tenant_ref",
            expected_prefix="tenant",
        )
        _shared(
            validate_opaque_ref,
            self.resource_scope_ref,
            field_name=f"{label}.resource_scope_ref",
            expected_prefix="scope",
        )
        _shared(validate_non_empty_str, self.resource_level, field_name=f"{label}.resource_level")
        _shared(validate_non_empty_str, self.ad_platform_ref, field_name=f"{label}.ad_platform_ref")
        _shared(validate_currency_iso4217, self.currency, field_name=f"{label}.currency")


def _scope_mismatch_code(policy: AnalysisPolicy, scope: EvaluationScope) -> str | None:
    declared = policy.applicability_scope
    checks = (
        ("tenant_mismatch", policy.tenant_ref, scope.tenant_ref),
        ("resource_scope_mismatch", declared.resource_scope_ref, scope.resource_scope_ref),
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
    interval: an instant equal to `valid_from_utc` or `valid_until_utc` is inside it. A malformed
    argument raises PolicyValidationError; "does not apply" is a return value, never that error.
    """
    if not isinstance(policy, AnalysisPolicy):
        raise _fail("invalid_type", f"policy: expected AnalysisPolicy, got {type(policy).__name__}")
    if not isinstance(scope, EvaluationScope):
        raise _fail("invalid_type", f"scope: expected EvaluationScope, got {type(scope).__name__}")
    instant = _shared(
        parse_timestamp_utc_micros, evaluation_instant_utc, field_name="evaluation_instant_utc"
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
    "POLICY_ERROR_CODES",
    "POLICY_NOT_APPLICABLE_CODES",
    "PolicyNotApplicableError",
    "PolicyValidationError",
    "PolicyValidity",
    "RESTATEMENT_KINDS",
    "RULE_TYPES",
    "RULE_TYPE_RESTATEMENT",
    "RULE_TYPE_SATURATION",
    "RULE_TYPE_STALLED_DELIVERY",
    "RULE_TYPE_WASTE",
    "RestatementRule",
    "SaturationRule",
    "StalledDeliveryRule",
    "WasteRule",
    "decimal6_to_micros",
    "policy_applicability_code",
    "require_policy_applicable",
    "rule_from_dict",
]
