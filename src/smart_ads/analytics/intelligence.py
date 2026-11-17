"""Pure policy evaluator emitting `finding/v1` artifacts (ADR-0001 sections 6.4, 7).

Analysis is a pure function of a verified `analysis_execution/v1` and a versioned tenant
`analysis_policy/v1`: no clock, no I/O, no randomness, and no threshold literal in this module.
`EvaluationContext.metrics_result_key` names a `METRIC_WINDOW_COLUMNS` relation (one row per
resource, inclusive window, and metric); missing windows remain absent, never zero.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, replace
import datetime
from itertools import pairwise
import re
from types import MappingProxyType
from typing import Any, ClassVar, Final, TypeVar

from smart_ads.analytics.cells import (
    ANALYSIS_EXECUTION_TYPE, ANALYSIS_RESULT_TYPE, DATASET_SNAPSHOT_TYPE, RUN_CONTEXT_TYPE,
)
from smart_ads.analytics.formulas import divide_count_by_count, divide_money_by_money
from smart_ads.analytics.lattice import (
    classify_input_state, classify_restatement, order_by_winner, order_candidates,
)
from smart_ads.analytics.policy import (
    METRIC_REF_PATTERN, RULE_TYPE_RESTATEMENT, RULE_TYPES, AnalysisPolicy, AnalysisRule,
    EvaluationScope, PolicyValidationError, RestatementRule, SaturationRule, StalledDeliveryRule,
    WasteRule, _recheck, _reparsed, decimal6_to_micros, require_policy_applicable,
)
from smart_ads.analytics.results import (
    AnalysisExecution, AnalysisResult, AnalysisResultSchema, ResultProjection,
    ResultSetMismatchError, verify_analysis_execution,
)
from smart_ads.contracts.jcs import (
    ADR_P1_DOMAIN_PREFIXES, ArtifactLocator, P1Integrity, canonicalize_jcs, jcs_sha256,
    p1_content_digest as _p1_content_digest, p1_preimage as _p1_preimage, self_digest_jcs_sha256,
)
from smart_ads.contracts.numerics import (
    PHASE1_BASE_METRICS, PHASE1_METRIC_NAME_TO_REF, NumericStateRow, validate_numeric_state,
)
from smart_ads.contracts.scalars import (
    ClosedValidationError, parse_iso_date, validate_non_empty_str, validate_resource_ref,
    validate_sha256_prefixed, validate_timestamp_utc6,
)
from smart_ads.contracts.schemas import AnalyticsLandingRow
from smart_ads.domain.registry import ExpectedResourceInventory

_T = TypeVar("_T")

FINDING_SCHEMA: Final[str] = "smart_ads/finding/v1"
FINDING_TYPES: Final[tuple[str, ...]] = RULE_TYPES
FINDING_DETECTED: Final[str] = "detected"
FINDING_INCONCLUSIVE: Final[str] = "inconclusive"
FINDING_STATUSES: Final[tuple[str, ...]] = (FINDING_DETECTED, FINDING_INCONCLUSIVE)
INTELLIGENCE_ERROR_CODES: Final[frozenset[str]] = frozenset(
    (
        "invalid_type invalid_grammar out_of_range unknown_value unknown_member missing_member "
        "schema_mismatch invalid_locator invalid_integrity content_digest_mismatch "
        "finding_digest_mismatch empty duplicate unsorted mutation_blocked_mismatch "
        "unsigned_artifact policy_locator_mismatch inventory_scope_mismatch "
        "inventory_window_mismatch invalid_inventory lookback_exceeds_curation window_after_instant "
        "result_columns_mismatch invalid_metric_row duplicate_metric_row metric_type_mismatch "
        "resource_not_in_inventory history_scope_mismatch invalid_history window_out_of_range "
        "findings_mismatch degraded_not_permitted record_mismatch"
    ).split()
)

METRIC_WINDOW_COLUMNS: Final[tuple[tuple[str, str, bool], ...]] = (
    ("resource_ref", "opaque_ref", False), ("window_start_date", "date", False),
    ("window_end_date", "date", False), ("metric_semantic_ref", "opaque_ref", False),
    ("metric_origin", "utf8", False), ("presence_status", "utf8", False),
    ("calculation_status", "utf8", False), ("unknown_reason", "utf8", True),
    ("value_type", "utf8", True), ("raw_numeric_value", "int64", True),
    ("unit", "utf8", True), ("currency", "utf8", True),
)
_COLUMN_NAMES: Final[tuple[str, ...]] = tuple(name for name, _, _ in METRIC_WINDOW_COLUMNS)
_KEY_COLUMNS: Final[tuple[str, ...]] = (
    "resource_ref", "window_start_date", "window_end_date", "metric_semantic_ref",
)
_STATE_COLUMNS: Final[tuple[str, ...]] = tuple(n for n in _COLUMN_NAMES if n not in _KEY_COLUMNS)
_MONEY: Final[str] = "int64_minor_currency"
_COUNT: Final[str] = "int64_count"
_FINDING_KEY_RE: Final[re.Pattern[str]] = re.compile(r"\Afinding:sha256:[0-9a-f]{64}\Z")
_METRIC_REF_RE: Final[re.Pattern[str]] = re.compile(METRIC_REF_PATTERN)
_IMPRESSIONS_REF: Final[str] = PHASE1_METRIC_NAME_TO_REF["impressions"]
_ONE_MICROS: Final[int] = decimal6_to_micros("1.000000")
EVIDENCE_ARTIFACT_TYPES: Final[tuple[str, ...]] = (ANALYSIS_RESULT_TYPE, DATASET_SNAPSHOT_TYPE)

_MetricKey = tuple[str, str, str, str]
_Window = tuple[str, str]
# (finding_status, window_start_date, window_end_date, evidence_locators)
_Outcome = tuple[str, str, str, tuple[ArtifactLocator, ...]]
_Chains = Mapping[str, tuple[tuple[AnalyticsLandingRow, ...], ...]]


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
    """Run a shared validator; a plain ClosedValidationError (or raw error) becomes `code`."""
    return _recheck(_fail, code, lambda: fn(*args, **kwargs))


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


def _locator(value: object, artifact_type: str | tuple[str, ...], label: str) -> ArtifactLocator:
    """A copy re-parsed from the locator's wire form, so a rebound member is checked again."""
    allowed = (artifact_type,) if isinstance(artifact_type, str) else artifact_type
    if not isinstance(value, ArtifactLocator) or value.artifact_type not in allowed:
        raise _fail("invalid_locator", f"{label}: expected ArtifactLocator for {allowed!r}")
    return _reparsed(_fail, "invalid_locator", ArtifactLocator, value)


def _parse_locator(raw: object, artifact_type: str | None) -> ArtifactLocator:
    return _guard("invalid_locator", ArtifactLocator.from_dict, raw, expected_type=artifact_type)


def _jcs_key(locator: ArtifactLocator) -> bytes:
    return canonicalize_jcs(locator.to_dict())


def _locator_array(
    values: object, artifact_type: str | tuple[str, ...], label: str
) -> tuple[ArtifactLocator, ...]:
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


def _date(value: object, label: str) -> datetime.date:
    text = _strict(value, str, label)
    return _guard("invalid_grammar", parse_iso_date, text, field_name=label)


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
    raw = mapping["integrity"]
    return mapping, _guard("invalid_integrity", P1Integrity.from_dict, raw, require_signed=require_signed)


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
    """Restatement and inconclusive findings block mutation recommendations (ADR section 7)."""
    return finding_type == RULE_TYPE_RESTATEMENT or finding_status == FINDING_INCONCLUSIVE


@dataclass(frozen=True, slots=True)
class Finding(_P1Artifact):
    """Closed P1 `smart_ads/finding/v1`; an empty `finding_digest` is computed on construction."""

    SCHEMA: ClassVar[str] = FINDING_SCHEMA
    P1_DOMAIN_PREFIX: ClassVar[str] = ADR_P1_DOMAIN_PREFIXES[FINDING_SCHEMA]
    CORE_KEYS: ClassVar[frozenset[str]] = frozenset(
        (
            "$schema analysis_execution_locator result_locator result_key finding_key finding_type "
            "finding_status mutation_recommendation_blocked evidence_locators "
            "analysis_policy_locator finding_digest"
        ).split()
    )
    KEYS: ClassVar[frozenset[str]] = CORE_KEYS | {"integrity"}

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
        evidence = _locator_array(self.evidence_locators, EVIDENCE_ARTIFACT_TYPES, f"{label}.evidence")
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
        m, integrity = _split_envelope(data, cls.CORE_KEYS, cls.SCHEMA, label, require_signed)
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
    """Resolved inputs of `verify_analysis_execution` plus snapshot, policy, and optional run locators."""

    execution: AnalysisExecution
    resolved_results: tuple[AnalysisResult, ...]
    resolved_schemas: tuple[AnalysisResultSchema, ...]
    bundle_dataset_snapshot_locator: ArtifactLocator
    bundle_analysis_policy_locator: ArtifactLocator
    require_signed: bool = False
    bundle_migration_run_context_locator: ArtifactLocator | None = None

    def __post_init__(self) -> None:
        label = "evidence"
        _require(self.execution, AnalysisExecution, f"{label}.execution")
        snapshot, policy = self.bundle_dataset_snapshot_locator, self.bundle_analysis_policy_locator
        run_ctx = self.bundle_migration_run_context_locator
        members = {
            "resolved_results": _typed_tuple(self.resolved_results, AnalysisResult, f"{label}.results"),
            "resolved_schemas": _typed_tuple(self.resolved_schemas, AnalysisResultSchema, f"{label}.schemas"),
            "bundle_dataset_snapshot_locator": _locator(snapshot, DATASET_SNAPSHOT_TYPE, f"{label}.snapshot"),
            "bundle_analysis_policy_locator": _locator(policy, AnalysisPolicy.SCHEMA, f"{label}.policy"),
            "bundle_migration_run_context_locator": (
                None if run_ctx is None else _locator(run_ctx, RUN_CONTEXT_TYPE, f"{label}.run_context")
            ),
        }
        for name, value in members.items():
            object.__setattr__(self, name, value)
        _strict(self.require_signed, bool, f"{label}.require_signed")


@dataclass(frozen=True, slots=True)
class EvaluationContext:
    """Policy, scope, explicit instant/window end, covering inventory, and restatement inputs.

    `window_end_date` may not follow the instant's UTC date, `inventory.date_range` must cover
    every active rule window, and every RestatementRule window must lie inside `[anchor - (N - 1), anchor]`.
    """

    policy: AnalysisPolicy
    scope: EvaluationScope
    evaluation_instant_utc: str
    window_end_date: str
    curation_restatement_lookback_days: int
    curation_anchor_date: str
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
        end = _date(self.window_end_date, f"{label}.window_end_date")
        if end > _date(instant.partition("T")[0], f"{label}.instant"):
            raise _fail("window_after_instant", f"{label}.window_end_date: after the instant UTC date")
        if _strict(self.curation_restatement_lookback_days, int, f"{label}.curation_days") < 1:
            raise _fail("out_of_range", f"{label}.curation_restatement_lookback_days: must be >= 1")
        _date(self.curation_anchor_date, f"{label}.curation_anchor_date")
        _non_empty_str(self.metrics_result_key, f"{label}.metrics_result_key")
        history = _typed_tuple(self.restatement_history, AnalyticsLandingRow, f"{label}.history")
        object.__setattr__(self, "restatement_history", history)


@dataclass(frozen=True, slots=True)
class _RuleInputs:
    table: Mapping[_MetricKey, NumericStateRow]
    end: datetime.date
    currency: str
    result_locator: ArtifactLocator
    snapshot_locator: ArtifactLocator
    history: _Chains


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
        resource, start, end, metric_ref = key
        _guard("invalid_metric_row", validate_resource_ref, resource, field_name="metric_row.resource_ref")
        if resource not in resources:
            raise _fail("resource_not_in_inventory", f"metric row for {resource!r}")
        if _METRIC_REF_RE.fullmatch(metric_ref) is None:
            raise _fail("invalid_metric_row", "metric_row.metric_semantic_ref: invalid metric ref")
        if start > end:  # fixed-width ISO dates: byte order is calendar order
            raise _fail("invalid_metric_row", f"window {start!r}..{end!r} is reversed")
        if key in table:
            raise _fail("duplicate_metric_row", f"two rows for {key!r}")
        state_vals = {name: values[name] for name in _STATE_COLUMNS}
        state = _guard("invalid_metric_row", validate_numeric_state, query_currency=currency, **state_vals)
        base = PHASE1_BASE_METRICS.get(metric_ref)
        if base is not None and classify_input_state(state) == "value" and state.value_type != base.value_type:
            raise _fail("invalid_metric_row", f"{metric_ref}: expected {base.value_type}")
        table[key] = state
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
#
# "Unknown dominates" (a convention the ADR does not fix; open decision): in every threshold rule,
# any required input that is absent or carries no value makes the finding `inconclusive`, even when
# a known value alone would already rule the finding out. A non-valued input is never read as zero.


def _waste(rule: WasteRule, resource: str, inputs: _RuleInputs) -> _Outcome | None:
    """spend >= min_spend_minor and outcome <= max_outcome_count over the trailing window.

    Unknown dominates: a known spend below the minimum or a known outcome above the maximum
    still yields `inconclusive` when the other input is non-valued.
    """
    window = _window(inputs.end, rule.window_days)
    spend = _amount(inputs, resource, window, rule.spend_metric_ref, _MONEY)
    outcome = _amount(inputs, resource, window, rule.outcome_metric_ref, _COUNT)
    if spend is None or outcome is None:
        return _outcome(FINDING_INCONCLUSIVE, window, inputs)
    if spend >= rule.min_spend_minor_int and outcome <= rule.max_outcome_count_int:
        return _outcome(FINDING_DETECTED, window, inputs)
    return None


def _growth_micros(ratio: NumericStateRow) -> int | None:
    """`current / baseline - 1` in millionths (None when `division_by_zero` or non-valued)."""
    if classify_input_state(ratio) != "value":
        return None
    return decimal6_to_micros(ratio.raw_numeric_value) - _ONE_MICROS


def _saturation(rule: SaturationRule, resource: str, inputs: _RuleInputs) -> _Outcome | None:
    """Baseline spend >= min, spend growth >= min_spend_growth, outcome growth <= max_outcome_growth.

    Unknown dominates: any of the four window inputs non-valued yields `inconclusive` before the
    baseline gate or either growth is looked at. A zero baseline (spend or outcome) gives a
    `division_by_zero` ratio and so `inconclusive` (open decision).
    """
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


def _history_chains(history: tuple[AnalyticsLandingRow, ...]) -> _Chains:
    """Index history once: per resource, each fact key's candidates in section 6.2 order."""
    groups: dict[bytes, list[AnalyticsLandingRow]] = {}
    for row in history:
        groups.setdefault(canonicalize_jcs(row.fact_key.to_dict()), []).append(row)
    chains: dict[str, list[tuple[AnalyticsLandingRow, ...]]] = {}
    for rows in groups.values():
        chain = _guard("invalid_history", order_by_winner, rows)
        chains.setdefault(chain[0].fact_key.resource_ref, []).append(chain)
    return MappingProxyType({resource: tuple(found) for resource, found in chains.items()})


def _restatement(rule: RestatementRule, resource: str, inputs: _RuleInputs) -> _Outcome | None:
    """Successive winners of one fact_key, metric_date in the lookback, restated by a listed kind.

    Evidence is the containing artifacts only (metric result and dataset snapshot); the
    finding_key names resource and window. The history rows are caller-supplied: nothing
    verifies that they belong to the cited snapshot.
    """
    start, end = _window(inputs.end, rule.lookback_days)
    for chain in inputs.history.get(resource, ()):
        if not start <= chain[0].fact_key.metric_date <= end:
            continue
        for prior, current in pairwise(chain):
            if _guard("invalid_history", classify_restatement, prior, current) in rule.restatement_kinds:
                evidence = _sorted_unique_locators((inputs.result_locator, inputs.snapshot_locator))
                return FINDING_DETECTED, start, end, evidence
    return None


_RULE_EVALUATORS: Final[Mapping[type, Callable[[Any, str, _RuleInputs], _Outcome | None]]] = MappingProxyType(
    {WasteRule: _waste, SaturationRule: _saturation, StalledDeliveryRule: _stalled_delivery,
     RestatementRule: _restatement}
)


def _effective_rules(context: EvaluationContext) -> tuple[AnalysisRule, ...]:
    """The rules evaluated: exactly the policy's rules."""
    return context.policy.rules


# ---------------------------------------------------------------- pipeline


def _rule_span(rule: AnalysisRule) -> int:
    if isinstance(rule, SaturationRule):
        return rule.window_days + rule.window_days
    if isinstance(rule, WasteRule):
        return rule.window_days
    if isinstance(rule, StalledDeliveryRule):
        return rule.min_consecutive_days
    return rule.lookback_days


def _check_inventory_window(context: EvaluationContext) -> None:
    """Require `inventory.date_range` to cover every active rule's evaluated date window."""
    inv_range = context.inventory.date_range
    end = _date(context.window_end_date, "context.window_end_date")
    for rule in _effective_rules(context):
        start, stop = _window(end, _rule_span(rule))
        if start < inv_range.start_date or stop > inv_range.end_date:
            raise _fail("inventory_window_mismatch", f"{rule.rule_id}: window outside inventory")


def _check_bindings(context: EvaluationContext, evidence: AnalysisEvidence) -> None:
    policy, inventory = context.policy, context.inventory
    if _jcs_key(policy.locator()) != _jcs_key(evidence.bundle_analysis_policy_locator):
        raise _fail("policy_locator_mismatch", "policy differs from the replay bundle policy locator")
    if evidence.require_signed and not (_is_signed(policy.integrity) and _is_signed(inventory.integrity)):
        raise _fail("unsigned_artifact", "policy and inventory must carry finalized P1 signatures")
    scope = context.scope
    if (inventory.tenant_ref, inventory.resource_scope_ref) != (scope.tenant_ref, scope.resource_scope_ref):
        raise _fail("inventory_scope_mismatch", "inventory tenant/resource scope differs from scope")
    _check_curation_window(context)
    _check_inventory_window(context)


def _check_curation_window(context: EvaluationContext) -> None:
    """Every RestatementRule window must lie inside the curation window (section 6.2)."""
    rules = [rule for rule in _effective_rules(context) if isinstance(rule, RestatementRule)]
    if not rules:
        return
    anchor = _date(context.curation_anchor_date, "context.curation_anchor_date")
    curation_start, curation_end = _window(anchor, context.curation_restatement_lookback_days)
    end = _date(context.window_end_date, "context.window_end_date")
    for rule in rules:
        start, stop = _window(end, rule.lookback_days)
        if start < curation_start or stop > curation_end:
            raise _fail("lookback_exceeds_curation", f"{rule.rule_id}: window outside curation")


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
        "policy_id": binding.policy.policy_id, "policy_version": binding.policy.policy_version,
        "rule_id": rule.rule_id, "finding_type": rule.RULE_TYPE, "result_key": binding.result_key,
        "resource_ref": resource, "window_start_date": start, "window_end_date": end,
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


def _fresh_context(context: object) -> EvaluationContext:
    """Rebuild `context` and re-parse its policy, scope, inventory, and history rows at the seam."""
    shell = _recheck(_fail, "invalid_type", replace, _require(context, EvaluationContext, "context"))
    policy = _reparsed(PolicyValidationError, "invalid_type", AnalysisPolicy, shell.policy)
    if any(type(rule) not in _RULE_EVALUATORS for rule in shell.policy.rules):
        raise _fail("invalid_type", "context.policy.rules: a rule outside the closed rule classes")
    rows = shell.restatement_history
    return replace(
        shell, policy=policy, scope=_recheck(PolicyValidationError, "invalid_type", replace, shell.scope),
        inventory=_reparsed(_fail, "invalid_inventory", ExpectedResourceInventory, shell.inventory),
        restatement_history=tuple(_reparsed(_fail, "invalid_history", AnalyticsLandingRow, r) for r in rows),
    )


def _evaluate(context: object, evidence: object) -> tuple[AnalysisExecution, tuple[Finding, ...]]:
    context = _fresh_context(context)
    evidence = _recheck(_fail, "invalid_type", replace, _require(evidence, AnalysisEvidence, "evidence"))
    require_policy_applicable(context.policy, context.scope, context.evaluation_instant_utc)
    _check_bindings(context, evidence)
    execution = _recheck(ResultSetMismatchError, "field_invalid", lambda: verify_analysis_execution(
        evidence.execution,
        evidence.resolved_results,
        evidence.resolved_schemas,
        evidence.bundle_dataset_snapshot_locator,
        require_signed=evidence.require_signed,
        bundle_migration_run_context_locator=evidence.bundle_migration_run_context_locator,
    ))
    entry = execution.canonical_result_set.entry(context.metrics_result_key)
    resources = tuple(sorted({u.resource_ref for u in context.inventory.expected_resources}))
    _check_history(context, frozenset(resources))
    inputs = _RuleInputs(
        table=_metric_table(entry.result_projection, frozenset(resources), context.scope.currency),
        end=_date(context.window_end_date, "context.window_end_date"),
        currency=context.scope.currency,
        result_locator=entry.result_locator,
        snapshot_locator=evidence.bundle_dataset_snapshot_locator,
        history=_history_chains(context.restatement_history),
    )
    policy = context.policy
    binding = _Binding(execution.locator(), entry.result_locator, entry.result_key, policy, policy.locator())
    findings = []
    for rule in _effective_rules(context):
        for resource in resources:
            outcome = _RULE_EVALUATORS[type(rule)](rule, resource, inputs)
            if outcome is not None:
                findings.append(_finding(binding, rule, resource, outcome))
    return execution, tuple(sorted(findings, key=lambda f: f.finding_key.encode("utf-8")))


def evaluate_findings(context: EvaluationContext, evidence: AnalysisEvidence) -> tuple[Finding, ...]:
    """Verify execution, require applicable policy and covering inventory, and return findings."""
    return _evaluate(context, evidence)[1]


__all__ = [
    "EVIDENCE_ARTIFACT_TYPES", "FINDING_DETECTED", "FINDING_INCONCLUSIVE", "FINDING_SCHEMA",
    "FINDING_STATUSES", "FINDING_TYPES", "INTELLIGENCE_ERROR_CODES", "METRIC_WINDOW_COLUMNS",
    "AnalysisEvidence", "EvaluationContext", "Finding", "IntelligenceError", "evaluate_findings",
]
