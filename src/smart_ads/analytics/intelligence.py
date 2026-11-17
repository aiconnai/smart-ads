"""Pure policy evaluator emitting findings and analytical certification records (ADR-0001 sections 6.4, 7).

Analysis is a pure function of a verified `analysis_execution/v1` and a versioned tenant
`analysis_policy/v1`: no clock, no I/O, no randomness, and no threshold literal in this module.

Input contract: the result named by `EvaluationContext.metrics_result_key` is a `relation`
whose columns are exactly METRIC_WINDOW_COLUMNS. Each row carries the section 4.3 numeric state
of one metric over one inclusive window `[window_start_date, window_end_date]` of one resource.
The evaluator never sums rows (Phase-1 metrics are `additive_across_none`); window values come
from the bound query, and a window the relation does not carry is absent, never zero.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
import datetime
from itertools import pairwise
import re
from types import MappingProxyType
from typing import Any, ClassVar, Final, TypeVar

from smart_ads.analytics.cells import (
    ANALYSIS_EXECUTION_TYPE, ANALYSIS_RESULT_TYPE, DATASET_SNAPSHOT_TYPE,
)
from smart_ads.analytics.formulas import (
    CertificationInput, DerivedCertificationStatus, combine_derived_certification,
    divide_count_by_count, divide_money_by_money,
)
from smart_ads.analytics.lattice import (
    classify_input_state, classify_restatement, order_candidates, select_winner,
)
from smart_ads.analytics.policy import (
    RULE_TYPE_RESTATEMENT, RULE_TYPES, AnalysisPolicy, AnalysisRule, EvaluationScope,
    RestatementRule, SaturationRule, StalledDeliveryRule, WasteRule, decimal6_to_micros,
    require_policy_applicable,
)
from smart_ads.analytics.results import (
    AnalysisExecution, AnalysisResult, AnalysisResultSchema, ResultProjection,
    verify_analysis_execution,
)
from smart_ads.contracts.jcs import (
    ArtifactLocator, P1Integrity, canonicalize_jcs, jcs_sha256,
    p1_content_digest as _p1_content_digest, p1_preimage as _p1_preimage, self_digest_jcs_sha256,
)
from smart_ads.contracts.numerics import (
    PHASE1_METRIC_NAME_TO_REF, NumericStateRow, validate_numeric_state,
)
from smart_ads.contracts.scalars import (
    ClosedValidationError, parse_iso_date, validate_non_empty_str, validate_sha256_prefixed,
    validate_timestamp_utc6,
)
from smart_ads.contracts.schemas import AnalyticsLandingRow
from smart_ads.domain.registry import ExpectedResourceInventory

_T = TypeVar("_T")

FINDING_SCHEMA: Final[str] = "smart_ads/finding/v1"
CERTIFICATION_RECORD_SCHEMA: Final[str] = "smart_ads/certification_record/v1"
FINDING_TYPES: Final[tuple[str, ...]] = RULE_TYPES
FINDING_DETECTED: Final[str] = "detected"
FINDING_INCONCLUSIVE: Final[str] = "inconclusive"
FINDING_STATUSES: Final[tuple[str, ...]] = (FINDING_DETECTED, FINDING_INCONCLUSIVE)
INTELLIGENCE_ERROR_CODES: Final[frozenset[str]] = frozenset(
    (
        # closed parsing of finding/v1, certification_record/v1 and the evaluation arguments
        "invalid_type invalid_grammar out_of_range unknown_value unknown_member missing_member "
        "schema_mismatch invalid_locator invalid_integrity content_digest_mismatch "
        "finding_digest_mismatch empty duplicate unsorted mutation_blocked_mismatch "
        # bindings between policy, bundle, inventory, scope and signatures
        "unsigned_artifact policy_locator_mismatch inventory_scope_mismatch "
        "lookback_exceeds_curation "
        # the metric-window relation and the restatement history
        "result_columns_mismatch invalid_metric_row duplicate_metric_row metric_type_mismatch "
        "resource_not_in_inventory history_scope_mismatch invalid_history window_out_of_range "
        # certification
        "findings_mismatch degraded_not_permitted"
    ).split()
)

METRIC_WINDOW_COLUMNS: Final[tuple[tuple[str, str, bool], ...]] = (
    ("resource_ref", "opaque_ref", False),
    ("window_start_date", "date", False),
    ("window_end_date", "date", False),
    ("metric_semantic_ref", "opaque_ref", False),
    ("metric_origin", "utf8", False),
    ("presence_status", "utf8", False),
    ("calculation_status", "utf8", False),
    ("unknown_reason", "utf8", True),
    ("value_type", "utf8", True),
    ("raw_numeric_value", "int64", True),
    ("unit", "utf8", True),
    ("currency", "utf8", True),
)
_COLUMN_NAMES: Final[tuple[str, ...]] = tuple(name for name, _, _ in METRIC_WINDOW_COLUMNS)
_KEY_COLUMNS: Final[tuple[str, ...]] = (
    "resource_ref", "window_start_date", "window_end_date", "metric_semantic_ref",
)
_STATE_COLUMNS: Final[tuple[str, ...]] = tuple(n for n in _COLUMN_NAMES if n not in _KEY_COLUMNS)
_MONEY: Final[str] = "int64_minor_currency"
_COUNT: Final[str] = "int64_count"
_FINDING_KEY_RE: Final[re.Pattern[str]] = re.compile(r"\Afinding:sha256:[0-9a-f]{64}\Z")
# StalledDeliveryRule names no metric: delivery is the Phase-1 base metric `impressions`.
_IMPRESSIONS_REF: Final[str] = PHASE1_METRIC_NAME_TO_REF["impressions"]
# One, in millionths, exactly as the T2 ratio operator scales it (no scale literal here).
_ONE_MICROS: Final[int] = decimal6_to_micros(divide_count_by_count(1, 1).raw_numeric_value)

_MetricKey = tuple[str, str, str, str]
_Window = tuple[str, str]
# (finding_status, window_start_date, window_end_date, evidence_locators)
_Outcome = tuple[str, str, str, tuple[ArtifactLocator, ...]]


class IntelligenceError(ClosedValidationError):
    """Closed T6 rejection carrying a `code` from INTELLIGENCE_ERROR_CODES."""

    def __init__(self, code: str, detail: str) -> None:
        if not isinstance(code, str) or code not in INTELLIGENCE_ERROR_CODES:
            raise ClosedValidationError(f"IntelligenceError: unknown code {code!r}")
        super().__init__(f"{code}: {detail}")
        self.code = code


def _fail(code: str, detail: str) -> IntelligenceError:
    return IntelligenceError(code, detail)


def _guard(code: str, fn: Callable[..., _T], *args: Any, **kwargs: Any) -> _T:
    """Run a shared validator; a plain ClosedValidationError becomes `code`, typed ones propagate."""
    try:
        return fn(*args, **kwargs)
    except ClosedValidationError as exc:
        if type(exc) is not ClosedValidationError:
            raise
        raise _fail(code, str(exc)) from exc


# ---------------------------------------------------------------- closed-value helpers


def _require(value: object, cls: type[_T], label: str) -> _T:
    if not isinstance(value, cls):
        raise _fail("invalid_type", f"{label}: expected {cls.__name__}, got {type(value).__name__}")
    return value


def _strict(value: object, cls: type[_T], label: str) -> _T:
    """Exact-type check: rejects bool for int and subclasses for str/bool."""
    if type(value) is not cls:
        raise _fail("invalid_type", f"{label}: expected {cls.__name__}, got {type(value).__name__}")
    return value  # type: ignore[return-value]


def _member(value: object, allowed: tuple[str, ...], label: str) -> str:
    if _strict(value, str, label) not in allowed:
        raise _fail("unknown_value", f"{label}: {value!r:.80} is not one of {list(allowed)}")
    return value  # type: ignore[return-value]


def _typed_tuple(values: object, cls: type[_T], label: str) -> tuple[_T, ...]:
    if not isinstance(values, (list, tuple)):
        raise _fail("invalid_type", f"{label}: expected a sequence, got {type(values).__name__}")
    for item in values:
        _require(item, cls, f"{label}[]")
    return tuple(values)


def _locator(value: object, artifact_type: str | None, label: str) -> ArtifactLocator:
    if not isinstance(value, ArtifactLocator) or (
        artifact_type is not None and value.artifact_type != artifact_type
    ):
        raise _fail("invalid_locator", f"{label}: expected ArtifactLocator for {artifact_type!r}")
    return value


def _parse_locator(raw: object, artifact_type: str | None) -> ArtifactLocator:
    return _guard("invalid_locator", ArtifactLocator.from_dict, raw, expected_type=artifact_type)


def _jcs_key(locator: ArtifactLocator) -> bytes:
    return canonicalize_jcs(locator.to_dict())


def _locator_array(values: object, artifact_type: str | None, label: str) -> tuple[ArtifactLocator, ...]:
    """Unique locators sorted by the RFC 8785 bytes of each locator object."""
    items = tuple(_locator(v, artifact_type, f"{label}[]") for v in _typed_tuple(values, object, label))
    keys = [_jcs_key(item) for item in items]
    if len(set(keys)) != len(keys):
        raise _fail("duplicate", f"{label}: duplicate locator")
    if any(left > right for left, right in pairwise(keys)):
        raise _fail("unsorted", f"{label}: locators must be sorted by RFC 8785 bytes")
    return items


def _sorted_unique_locators(values: Iterable[ArtifactLocator]) -> tuple[ArtifactLocator, ...]:
    unique = {_jcs_key(locator): locator for locator in values}
    return tuple(unique[key] for key in sorted(unique))


def _list_member(mapping: Mapping[str, Any], name: str, label: str) -> list[Any]:
    if not isinstance(mapping[name], list):
        raise _fail("invalid_type", f"{label}.{name}: expected JSON array list")
    return mapping[name]


def _digest_member(value: object, label: str) -> str:
    text = _strict(value, str, label)
    return _guard("invalid_grammar", validate_sha256_prefixed, text, field_name=label)


def _non_empty_str(value: object, label: str) -> str:
    text = _strict(value, str, label)
    return _guard("invalid_grammar", validate_non_empty_str, text, field_name=label)


# ---------------------------------------------------------------- P1 envelope helpers


def _closed_mapping(data: object, keys: frozenset[str], label: str) -> Mapping[str, Any]:
    if not isinstance(data, Mapping) or not all(isinstance(key, str) for key in data):
        raise _fail("invalid_type", f"{label}: expected a JSON object with string keys")
    if keys - set(data):
        raise _fail("missing_member", f"{label}: missing members {sorted(keys - set(data))}")
    if set(data) - keys:
        raise _fail("unknown_member", f"{label}: unknown members {sorted(set(data) - keys)}")
    return data


def _split_envelope(
    data: object, core_keys: frozenset[str], schema: str, label: str, require_signed: object
) -> tuple[Mapping[str, Any], P1Integrity | None]:
    """Parse a closed P1 envelope; integrity is optional unless `require_signed`."""
    _strict(require_signed, bool, "require_signed")
    with_integrity = require_signed or (isinstance(data, Mapping) and "integrity" in data)
    mapping = _closed_mapping(data, core_keys | {"integrity"} if with_integrity else core_keys, label)
    if mapping["$schema"] != schema:
        raise _fail("schema_mismatch", f"{label}.$schema: expected {schema!r}")
    if not with_integrity:
        return mapping, None
    integrity = _guard(
        "invalid_integrity", P1Integrity.from_dict, mapping["integrity"], require_signed=require_signed
    )
    return mapping, integrity


def _integrity_type(integrity: object, label: str) -> None:
    """Checked before any `to_dict()`, which serializes the integrity block."""
    if integrity is not None and not isinstance(integrity, P1Integrity):
        raise _fail("invalid_integrity", f"{label}.integrity: expected P1Integrity or None")


def _check_integrity(integrity: P1Integrity | None, envelope: Mapping[str, Any], label: str) -> None:
    if integrity is None or not integrity.is_signed:
        return
    if integrity.content_digest != _p1_content_digest(envelope):
        raise _fail("content_digest_mismatch", f"{label}.integrity.content_digest differs")


def _with_integrity(core: dict[str, Any], integrity: P1Integrity | None) -> dict[str, Any]:
    return core if integrity is None else {**core, "integrity": integrity.to_dict()}


def _is_signed(integrity: P1Integrity | None) -> bool:
    return integrity is not None and integrity.is_signed


class _P1Artifact:
    """Locator and P1 preimage/digest over `to_dict()`; the wheel never signs."""

    __slots__ = ()
    SCHEMA: ClassVar[str]

    def to_dict(self) -> dict[str, Any]:
        raise NotImplementedError

    def locator(self) -> ArtifactLocator:
        """Typed locator over the RFC 8785 bytes of the complete envelope."""
        return ArtifactLocator.for_canonical_bytes(self.SCHEMA, canonicalize_jcs(self.to_dict()))

    def _envelope(self) -> dict[str, Any]:
        envelope = self.to_dict()
        if "integrity" not in envelope:
            raise _fail("missing_member", f"{self.SCHEMA}: the P1 preimage needs an integrity block")
        return envelope

    def p1_preimage(self) -> dict[str, Any]:
        """The envelope without `integrity.content_digest` and `integrity.signature_base64`."""
        return _p1_preimage(self._envelope())

    def p1_content_digest(self) -> str:
        """`'sha256:' + hex(SHA-256(RFC8785(P1 preimage)))`."""
        return _p1_content_digest(self._envelope())


# ---------------------------------------------------------------- finding/v1


def _blocks_mutation(finding_type: str, finding_status: str) -> bool:
    """Restatement always blocks; an inconclusive finding never licenses a mutation either."""
    return finding_type == RULE_TYPE_RESTATEMENT or finding_status == FINDING_INCONCLUSIVE


_FINDING_CORE_KEYS: Final[frozenset[str]] = frozenset(
    (
        "$schema analysis_execution_locator result_locator result_key finding_key finding_type "
        "finding_status mutation_recommendation_blocked evidence_locators analysis_policy_locator "
        "finding_digest"
    ).split()
)


@dataclass(frozen=True, slots=True)
class Finding(_P1Artifact):
    """Closed P1 `smart_ads/finding/v1`; an empty `finding_digest` is computed on construction."""

    SCHEMA: ClassVar[str] = FINDING_SCHEMA

    analysis_execution_locator: ArtifactLocator
    result_locator: ArtifactLocator
    result_key: str
    finding_key: str
    finding_type: str
    finding_status: str
    mutation_recommendation_blocked: bool
    evidence_locators: tuple[ArtifactLocator, ...]
    analysis_policy_locator: ArtifactLocator
    finding_digest: str = ""
    integrity: P1Integrity | None = None

    def __post_init__(self) -> None:
        label = "finding"
        _integrity_type(self.integrity, label)
        _locator(self.analysis_execution_locator, ANALYSIS_EXECUTION_TYPE, f"{label}.execution")
        _locator(self.result_locator, ANALYSIS_RESULT_TYPE, f"{label}.result_locator")
        _locator(self.analysis_policy_locator, AnalysisPolicy.SCHEMA, f"{label}.policy_locator")
        _non_empty_str(self.result_key, f"{label}.result_key")
        if _FINDING_KEY_RE.fullmatch(_strict(self.finding_key, str, f"{label}.finding_key")) is None:
            raise _fail("invalid_grammar", f"{label}.finding_key: expected 'finding:sha256:<hex>'")
        _member(self.finding_type, FINDING_TYPES, f"{label}.finding_type")
        _member(self.finding_status, FINDING_STATUSES, f"{label}.finding_status")
        blocked = _strict(self.mutation_recommendation_blocked, bool, f"{label}.blocked")
        if blocked != _blocks_mutation(self.finding_type, self.finding_status):
            raise _fail("mutation_blocked_mismatch", f"{label}: blocked flag contradicts type/status")
        evidence = _locator_array(self.evidence_locators, None, f"{label}.evidence_locators")
        if not evidence:
            raise _fail("empty", f"{label}.evidence_locators: at least one locator is required")
        object.__setattr__(self, "evidence_locators", evidence)
        self._resolve_digest(label)
        _check_integrity(self.integrity, self.to_dict(), label)

    def _resolve_digest(self, label: str) -> None:
        expected = self_digest_jcs_sha256(self.to_dict(), digest_member="finding_digest")
        if self.finding_digest == "":
            object.__setattr__(self, "finding_digest", expected)
        elif _digest_member(self.finding_digest, f"{label}.finding_digest") != expected:
            raise _fail("finding_digest_mismatch", f"{label}.finding_digest: recomputed {expected!r}")

    def to_dict(self) -> dict[str, Any]:
        core = {
            "$schema": self.SCHEMA,
            "analysis_execution_locator": self.analysis_execution_locator.to_dict(),
            "result_locator": self.result_locator.to_dict(),
            "result_key": self.result_key,
            "finding_key": self.finding_key,
            "finding_type": self.finding_type,
            "finding_status": self.finding_status,
            "mutation_recommendation_blocked": self.mutation_recommendation_blocked,
            "evidence_locators": [locator.to_dict() for locator in self.evidence_locators],
            "analysis_policy_locator": self.analysis_policy_locator.to_dict(),
            "finding_digest": self.finding_digest,
        }
        return _with_integrity(core, self.integrity)

    @classmethod
    def from_dict(cls, data: object, *, require_signed: bool = False) -> Finding:
        label = "finding"
        m, integrity = _split_envelope(data, _FINDING_CORE_KEYS, cls.SCHEMA, label, require_signed)
        evidence = _list_member(m, "evidence_locators", label)
        execution = _parse_locator(m["analysis_execution_locator"], ANALYSIS_EXECUTION_TYPE)
        return cls(
            analysis_execution_locator=execution,
            result_locator=_parse_locator(m["result_locator"], ANALYSIS_RESULT_TYPE),
            result_key=m["result_key"],
            finding_key=m["finding_key"],
            finding_type=m["finding_type"],
            finding_status=m["finding_status"],
            mutation_recommendation_blocked=m["mutation_recommendation_blocked"],
            evidence_locators=tuple(_parse_locator(item, None) for item in evidence),
            analysis_policy_locator=_parse_locator(m["analysis_policy_locator"], AnalysisPolicy.SCHEMA),
            finding_digest=_digest_member(m["finding_digest"], f"{label}.finding_digest"),
            integrity=integrity,
        )


# ---------------------------------------------------------------- evaluation inputs


@dataclass(frozen=True, slots=True)
class AnalysisEvidence:
    """Resolved inputs of `verify_analysis_execution` plus the bundle's snapshot and policy locators."""

    execution: AnalysisExecution
    resolved_results: tuple[AnalysisResult, ...]
    resolved_schemas: tuple[AnalysisResultSchema, ...]
    bundle_dataset_snapshot_locator: ArtifactLocator
    bundle_analysis_policy_locator: ArtifactLocator
    require_signed: bool = False

    def __post_init__(self) -> None:
        label = "evidence"
        _require(self.execution, AnalysisExecution, f"{label}.execution")
        results = _typed_tuple(self.resolved_results, AnalysisResult, f"{label}.resolved_results")
        schemas = _typed_tuple(self.resolved_schemas, AnalysisResultSchema, f"{label}.resolved_schemas")
        object.__setattr__(self, "resolved_results", results)
        object.__setattr__(self, "resolved_schemas", schemas)
        _locator(self.bundle_dataset_snapshot_locator, DATASET_SNAPSHOT_TYPE, f"{label}.snapshot")
        _locator(self.bundle_analysis_policy_locator, AnalysisPolicy.SCHEMA, f"{label}.policy")
        _strict(self.require_signed, bool, f"{label}.require_signed")


@dataclass(frozen=True, slots=True)
class EvaluationContext:
    """Policy, scope, explicit instant/window end and the inputs restatement needs."""

    policy: AnalysisPolicy
    scope: EvaluationScope
    evaluation_instant_utc: str
    window_end_date: str
    curation_restatement_lookback_days: int
    inventory: ExpectedResourceInventory
    metrics_result_key: str
    restatement_history: tuple[AnalyticsLandingRow, ...] = ()

    def __post_init__(self) -> None:
        label = "context"
        _require(self.policy, AnalysisPolicy, f"{label}.policy")
        _require(self.scope, EvaluationScope, f"{label}.scope")
        _require(self.inventory, ExpectedResourceInventory, f"{label}.inventory")
        instant = _strict(self.evaluation_instant_utc, str, f"{label}.instant")
        _guard("invalid_grammar", validate_timestamp_utc6, instant, field_name=f"{label}.instant")
        end = _strict(self.window_end_date, str, f"{label}.window_end_date")
        _guard("invalid_grammar", parse_iso_date, end, field_name=f"{label}.window_end_date")
        if _strict(self.curation_restatement_lookback_days, int, f"{label}.curation_days") < 1:
            raise _fail("out_of_range", f"{label}.curation_restatement_lookback_days: must be >= 1")
        _non_empty_str(self.metrics_result_key, f"{label}.metrics_result_key")
        history = _typed_tuple(self.restatement_history, AnalyticsLandingRow, f"{label}.history")
        object.__setattr__(self, "restatement_history", history)


@dataclass(frozen=True, slots=True)
class _RuleInputs:
    table: Mapping[_MetricKey, NumericStateRow]
    end: datetime.date
    currency: str
    result_locator: ArtifactLocator
    history: tuple[AnalyticsLandingRow, ...]


# ---------------------------------------------------------------- metric relation


def _metric_table(
    projection: ResultProjection, resources: frozenset[str], currency: str
) -> Mapping[_MetricKey, NumericStateRow]:
    """Index the metric-window relation by (resource, window start, window end, metric)."""
    declared = tuple((c.name, c.cell_type, c.nullable) for c in projection.columns)
    if projection.result_kind != "relation" or declared != METRIC_WINDOW_COLUMNS:
        raise _fail("result_columns_mismatch", "metric result must be the METRIC_WINDOW_COLUMNS relation")
    table: dict[_MetricKey, NumericStateRow] = {}
    for row in projection.rows:
        values = dict(zip(_COLUMN_NAMES, (cell.value for cell in row), strict=True))
        key: _MetricKey = tuple(values[name] for name in _KEY_COLUMNS)  # type: ignore[assignment]
        resource, start, end, _ = key
        if resource not in resources:
            raise _fail("resource_not_in_inventory", f"metric row for {resource!r}")
        if start > end:  # fixed-width ISO dates: byte order is calendar order
            raise _fail("invalid_metric_row", f"window {start!r}..{end!r} is reversed")
        if key in table:
            raise _fail("duplicate_metric_row", f"two rows for {key!r}")
        state = {name: values[name] for name in _STATE_COLUMNS}
        table[key] = _guard("invalid_metric_row", validate_numeric_state, query_currency=currency, **state)
    return MappingProxyType(table)


def _shift(day: datetime.date, back_days: int) -> datetime.date:
    try:
        return day - datetime.timedelta(days=back_days)
    except OverflowError as exc:
        raise _fail("window_out_of_range", f"{back_days} days before {day.isoformat()}") from exc


def _window(end: datetime.date, days: int) -> _Window:
    """The inclusive window of `days` calendar dates ending at `end`."""
    return _shift(end, days - 1).isoformat(), end.isoformat()


def _amount(
    inputs: _RuleInputs, resource: str, window: _Window, metric_ref: str, value_type: str
) -> int | None:
    """The exact integer a valued row carries; None when the row is absent or carries no value."""
    state = inputs.table.get((resource, window[0], window[1], metric_ref))
    if state is None or classify_input_state(state) != "value":
        return None
    if state.value_type != value_type:
        raise _fail("metric_type_mismatch", f"{metric_ref}: expected {value_type}")
    return int(state.raw_numeric_value)  # type: ignore[arg-type]


def _outcome(status: str, window: _Window, inputs: _RuleInputs) -> _Outcome:
    return status, window[0], window[1], (inputs.result_locator,)


# ---------------------------------------------------------------- rules


def _waste(rule: WasteRule, resource: str, inputs: _RuleInputs) -> _Outcome | None:
    """spend >= min_spend_minor and outcome <= max_outcome_count over the trailing window."""
    window = _window(inputs.end, rule.window_days)
    spend = _amount(inputs, resource, window, rule.spend_metric_ref, _MONEY)
    outcome = _amount(inputs, resource, window, rule.outcome_metric_ref, _COUNT)
    if spend is None or outcome is None:
        return _outcome(FINDING_INCONCLUSIVE, window, inputs)
    if spend >= rule.min_spend_minor_int and outcome <= rule.max_outcome_count_int:
        return _outcome(FINDING_DETECTED, window, inputs)
    return None


def _growth_micros(ratio: NumericStateRow) -> int | None:
    """`current / baseline - 1` in millionths, the ratio rounded half-up by the T2 operator."""
    if classify_input_state(ratio) != "value":
        return None
    return decimal6_to_micros(ratio.raw_numeric_value) - _ONE_MICROS


def _saturation(rule: SaturationRule, resource: str, inputs: _RuleInputs) -> _Outcome | None:
    """Baseline spend >= min, spend growth >= min_spend_growth, outcome growth <= max_outcome_growth."""
    current = _window(inputs.end, rule.window_days)
    baseline = _window(_shift(inputs.end, rule.window_days), rule.window_days)
    window = (baseline[0], current[1])
    windows = (baseline, current)
    spends = [_amount(inputs, resource, w, rule.spend_metric_ref, _MONEY) for w in windows]
    outcomes = [_amount(inputs, resource, w, rule.outcome_metric_ref, _COUNT) for w in windows]
    if None in spends or None in outcomes:
        return _outcome(FINDING_INCONCLUSIVE, window, inputs)
    (spend_b, spend_c), (outcome_b, outcome_c) = spends, outcomes
    if spend_b < rule.min_baseline_spend_minor_int:  # type: ignore[operator]
        return None
    ccy = inputs.currency
    spend_ratio = divide_money_by_money(
        spend_c, spend_b, numerator_currency=ccy, denominator_currency=ccy  # type: ignore[arg-type]
    )
    spend_growth = _growth_micros(spend_ratio)
    outcome_growth = _growth_micros(divide_count_by_count(outcome_c, outcome_b))  # type: ignore[arg-type]
    if spend_growth is None or outcome_growth is None:
        return _outcome(FINDING_INCONCLUSIVE, window, inputs)
    if spend_growth >= decimal6_to_micros(rule.min_spend_growth) and (
        outcome_growth <= decimal6_to_micros(rule.max_outcome_growth)
    ):
        return _outcome(FINDING_DETECTED, window, inputs)
    return None


def _stalled_delivery(rule: StalledDeliveryRule, resource: str, inputs: _RuleInputs) -> _Outcome | None:
    """Daily impressions <= max_impressions on each of the trailing `min_consecutive_days` days."""
    window = _window(inputs.end, rule.min_consecutive_days)
    quiet = True
    for back in range(rule.min_consecutive_days):
        day = _shift(inputs.end, back).isoformat()
        impressions = _amount(inputs, resource, (day, day), _IMPRESSIONS_REF, _COUNT)
        if impressions is None:
            return _outcome(FINDING_INCONCLUSIVE, window, inputs)
        quiet = quiet and impressions <= rule.max_impressions_int
    return _outcome(FINDING_DETECTED, window, inputs) if quiet else None


def _row_locator(row: AnalyticsLandingRow) -> ArtifactLocator:
    return ArtifactLocator.for_canonical_bytes(row.SCHEMA, canonicalize_jcs(row.to_dict()))


def _winner_chain(rows: list[AnalyticsLandingRow]) -> tuple[AnalyticsLandingRow, ...]:
    """Candidates of one fact_key, oldest first, by repeated section 6.2 `select_winner`."""
    remaining, newest_first = list(rows), []
    while remaining:
        winner = _guard("invalid_history", select_winner, remaining)
        newest_first.append(winner)
        remaining = [row for row in remaining if row is not winner]
    return tuple(reversed(newest_first))


def _restatement(rule: RestatementRule, resource: str, inputs: _RuleInputs) -> _Outcome | None:
    """Successive winners of one fact_key, metric_date in the lookback, restated by a listed kind."""
    start, end = _window(inputs.end, rule.lookback_days)
    groups: dict[bytes, list[AnalyticsLandingRow]] = {}
    for row in inputs.history:
        key = row.fact_key
        if key.resource_ref == resource and start <= key.metric_date <= end:
            groups.setdefault(canonicalize_jcs(key.to_dict()), []).append(row)
    evidence: list[ArtifactLocator] = []
    for rows in groups.values():
        for prior, current in pairwise(_winner_chain(rows)):
            if _guard("invalid_history", classify_restatement, prior, current) in rule.restatement_kinds:
                evidence += [_row_locator(prior), _row_locator(current)]
    if not evidence:
        return None
    return FINDING_DETECTED, start, end, _sorted_unique_locators(evidence)


_RULE_EVALUATORS: Final[Mapping[type, Callable[[Any, str, _RuleInputs], _Outcome | None]]] = (
    MappingProxyType(
        {WasteRule: _waste, SaturationRule: _saturation, StalledDeliveryRule: _stalled_delivery,
         RestatementRule: _restatement}
    )
)


def _effective_rules(context: EvaluationContext) -> tuple[AnalysisRule, ...]:
    """The rules evaluated: exactly the policy's rules.

    Restatement is opt-in: a policy without a RestatementRule yields no restatement finding.
    Switching restatement to "always on" is local to this function: when no RestatementRule is
    listed, append a synthesized `RestatementRule(lookback_days=
    context.curation_restatement_lookback_days, restatement_kinds=RESTATEMENT_KINDS)`.
    """
    return context.policy.rules


# ---------------------------------------------------------------- pipeline


def _check_bindings(context: EvaluationContext, evidence: AnalysisEvidence) -> None:
    policy, inventory = context.policy, context.inventory
    if _jcs_key(policy.locator()) != _jcs_key(evidence.bundle_analysis_policy_locator):
        raise _fail("policy_locator_mismatch", "policy differs from the replay bundle policy locator")
    if evidence.require_signed and not (_is_signed(policy.integrity) and _is_signed(inventory.integrity)):
        raise _fail("unsigned_artifact", "policy and inventory must carry finalized P1 signatures")
    scope = context.scope
    if (inventory.tenant_ref, inventory.resource_scope_ref) != (scope.tenant_ref, scope.resource_scope_ref):
        raise _fail("inventory_scope_mismatch", "inventory tenant/resource scope differs from scope")
    curation_days = context.curation_restatement_lookback_days
    for rule in policy.rules:
        if isinstance(rule, RestatementRule) and rule.lookback_days > curation_days:
            raise _fail("lookback_exceeds_curation", f"{rule.rule_id}: lookback beyond curation")


def _check_history(context: EvaluationContext, resources: frozenset[str]) -> None:
    """History rows are unique candidates of the inventory's binding, account and resources."""
    _guard("invalid_history", order_candidates, context.restatement_history)
    inventory = context.inventory
    for row in context.restatement_history:
        key = row.fact_key
        if (key.binding_ref, key.account_ref) != (inventory.binding_ref, inventory.account_ref):
            raise _fail("history_scope_mismatch", "history row of another binding/account")
        if key.resource_ref not in resources:
            raise _fail("resource_not_in_inventory", f"history row for {key.resource_ref!r}")


@dataclass(frozen=True, slots=True)
class _Binding:
    execution_locator: ArtifactLocator
    result_locator: ArtifactLocator
    result_key: str
    policy: AnalysisPolicy
    policy_locator: ArtifactLocator


def _finding_key(binding: _Binding, rule: AnalysisRule, resource: str, start: str, end: str) -> str:
    identity = {
        "policy_id": binding.policy.policy_id,
        "policy_version": binding.policy.policy_version,
        "rule_id": rule.rule_id,
        "finding_type": rule.RULE_TYPE,
        "result_key": binding.result_key,
        "resource_ref": resource,
        "window_start_date": start,
        "window_end_date": end,
    }
    return "finding:" + jcs_sha256(identity)


def _finding(binding: _Binding, rule: AnalysisRule, resource: str, outcome: _Outcome) -> Finding:
    status, start, end, evidence = outcome
    return Finding(
        analysis_execution_locator=binding.execution_locator,
        result_locator=binding.result_locator,
        result_key=binding.result_key,
        finding_key=_finding_key(binding, rule, resource, start, end),
        finding_type=rule.RULE_TYPE,
        finding_status=status,
        mutation_recommendation_blocked=_blocks_mutation(rule.RULE_TYPE, status),
        evidence_locators=evidence,
        analysis_policy_locator=binding.policy_locator,
    )


def _evaluate(
    context: EvaluationContext, evidence: AnalysisEvidence
) -> tuple[AnalysisExecution, tuple[Finding, ...]]:
    _require(context, EvaluationContext, "context")
    _require(evidence, AnalysisEvidence, "evidence")
    require_policy_applicable(context.policy, context.scope, context.evaluation_instant_utc)
    _check_bindings(context, evidence)
    execution = verify_analysis_execution(
        evidence.execution,
        evidence.resolved_results,
        evidence.resolved_schemas,
        evidence.bundle_dataset_snapshot_locator,
        require_signed=evidence.require_signed,
    )
    entry = execution.canonical_result_set.entry(context.metrics_result_key)
    resources = tuple(sorted({u.resource_ref for u in context.inventory.expected_resources}))
    _check_history(context, frozenset(resources))
    inputs = _RuleInputs(
        table=_metric_table(entry.result_projection, frozenset(resources), context.scope.currency),
        end=parse_iso_date(context.window_end_date, field_name="window_end_date"),
        currency=context.scope.currency,
        result_locator=entry.result_locator,
        history=context.restatement_history,
    )
    binding = _Binding(
        execution.locator(), entry.result_locator, entry.result_key, context.policy, context.policy.locator()
    )
    findings = []
    for rule in _effective_rules(context):
        for resource in resources:
            outcome = _RULE_EVALUATORS[type(rule)](rule, resource, inputs)
            if outcome is not None:
                findings.append(_finding(binding, rule, resource, outcome))
    return execution, tuple(sorted(findings, key=lambda f: f.finding_key.encode("utf-8")))


def evaluate_findings(context: EvaluationContext, evidence: AnalysisEvidence) -> tuple[Finding, ...]:
    """Verify the execution, require the policy applicable, and return findings by `finding_key`."""
    return _evaluate(context, evidence)[1]


# ---------------------------------------------------------------- certification_record/v1

_STATUS_NAMES: Final[tuple[str, ...]] = tuple(status.value for status in DerivedCertificationStatus)
_RECORD_CORE_KEYS: Final[frozenset[str]] = frozenset(
    "$schema finding_locators derived_certification_status mutation_recommendations_blocked "
    "output_digest".split()
)


@dataclass(frozen=True, slots=True)
class AttestedCertificationInput:
    """One input's certification status plus whether it was independently validated."""

    certification_input: CertificationInput
    independently_validated: bool

    def __post_init__(self) -> None:
        _require(self.certification_input, CertificationInput, "attested_input.certification_input")
        _strict(self.independently_validated, bool, "attested_input.independently_validated")


def derive_certification_status(
    inputs: tuple[AttestedCertificationInput, ...] | list[AttestedCertificationInput],
) -> DerivedCertificationStatus:
    """Minimum input status (T2 combiner) with the ADR section 5.6 DEGRADED preconditions.

    DEGRADED needs an independently validated `derived_input` that is already DEGRADED; the
    combiner cannot express that, so it is checked here. Its other precondition, successful
    recomputation, holds because `build_certification_record` re-verifies the execution first.
    """
    items = _typed_tuple(inputs, AttestedCertificationInput, "certification_inputs")
    status = combine_derived_certification(tuple(item.certification_input for item in items))
    degraded = DerivedCertificationStatus.DEGRADED
    if status is degraded and not any(
        item.independently_validated
        and item.certification_input.status is degraded
        and item.certification_input.origin == "derived_input"
        for item in items
    ):
        raise _fail("degraded_not_permitted", "no independently validated DEGRADED derived input")
    return status


@dataclass(frozen=True, slots=True)
class AnalyticalCertificationRecord(_P1Artifact):
    """Closed P1 `smart_ads/certification_record/v1` (not the 7A or 7B certification record)."""

    SCHEMA: ClassVar[str] = CERTIFICATION_RECORD_SCHEMA

    finding_locators: tuple[ArtifactLocator, ...]
    derived_certification_status: DerivedCertificationStatus
    mutation_recommendations_blocked: bool
    output_digest: str
    integrity: P1Integrity | None = None

    def __post_init__(self) -> None:
        label = "certification_record"
        _integrity_type(self.integrity, label)
        locators = _locator_array(self.finding_locators, FINDING_SCHEMA, f"{label}.finding_locators")
        object.__setattr__(self, "finding_locators", locators)
        _require(self.derived_certification_status, DerivedCertificationStatus, f"{label}.status")
        blocked = _strict(self.mutation_recommendations_blocked, bool, f"{label}.blocked")
        if blocked and not locators:
            raise _fail("mutation_blocked_mismatch", f"{label}: an empty finding set blocks nothing")
        _digest_member(self.output_digest, f"{label}.output_digest")
        _check_integrity(self.integrity, self.to_dict(), label)

    def to_dict(self) -> dict[str, Any]:
        core = {
            "$schema": self.SCHEMA,
            "finding_locators": [locator.to_dict() for locator in self.finding_locators],
            "derived_certification_status": self.derived_certification_status.value,
            "mutation_recommendations_blocked": self.mutation_recommendations_blocked,
            "output_digest": self.output_digest,
        }
        return _with_integrity(core, self.integrity)

    @classmethod
    def from_dict(cls, data: object, *, require_signed: bool = False) -> AnalyticalCertificationRecord:
        label = "certification_record"
        m, integrity = _split_envelope(data, _RECORD_CORE_KEYS, cls.SCHEMA, label, require_signed)
        status = _member(m["derived_certification_status"], _STATUS_NAMES, f"{label}.status")
        locators = _list_member(m, "finding_locators", label)
        return cls(
            finding_locators=tuple(_parse_locator(item, FINDING_SCHEMA) for item in locators),
            derived_certification_status=DerivedCertificationStatus(status),
            mutation_recommendations_blocked=m["mutation_recommendations_blocked"],
            output_digest=m["output_digest"],
            integrity=integrity,
        )


def _without_integrity(finding: Finding) -> bytes:
    envelope = finding.to_dict()
    envelope.pop("integrity", None)
    return canonicalize_jcs(envelope)


def build_certification_record(
    context: EvaluationContext,
    evidence: AnalysisEvidence,
    findings: tuple[Finding, ...] | list[Finding],
    certification_inputs: tuple[AttestedCertificationInput, ...] | list[AttestedCertificationInput],
    *,
    integrity: P1Integrity | None = None,
) -> AnalyticalCertificationRecord:
    """Re-verify and re-evaluate, require `findings` to be exactly that result, and certify them.

    `findings` may carry integrity blocks (finalized when `evidence.require_signed`); everything
    but integrity must equal the recomputation byte for byte, in `finding_key` order. The record
    binds the supplied envelopes' locators and, as `output_digest`, the verified execution's
    `canonical_result_digest`.
    """
    execution, expected = _evaluate(context, evidence)
    supplied = _typed_tuple(findings, Finding, "findings")
    if evidence.require_signed and not all(_is_signed(finding.integrity) for finding in supplied):
        raise _fail("unsigned_artifact", "findings must carry finalized P1 signatures")
    if [_without_integrity(f) for f in supplied] != [_without_integrity(f) for f in expected]:
        raise _fail("findings_mismatch", "supplied findings differ from the recomputed findings")
    return AnalyticalCertificationRecord(
        finding_locators=_sorted_unique_locators(finding.locator() for finding in supplied),
        derived_certification_status=derive_certification_status(certification_inputs),
        mutation_recommendations_blocked=any(f.mutation_recommendation_blocked for f in supplied),
        output_digest=execution.canonical_result_set.canonical_result_digest,
        integrity=integrity,
    )


__all__ = [
    "CERTIFICATION_RECORD_SCHEMA", "FINDING_DETECTED", "FINDING_INCONCLUSIVE", "FINDING_SCHEMA",
    "FINDING_STATUSES", "FINDING_TYPES", "INTELLIGENCE_ERROR_CODES", "METRIC_WINDOW_COLUMNS",
    "AnalysisEvidence", "AnalyticalCertificationRecord", "AttestedCertificationInput",
    "EvaluationContext", "Finding", "IntelligenceError", "build_certification_record",
    "derive_certification_status", "evaluate_findings",
]
