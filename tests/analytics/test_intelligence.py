"""Tests for smart_ads.analytics.intelligence (ADR-0001 sections 6.4 and 7).

Every expected digest, locator and finding key is recomputed here with plain `json` +
`hashlib` (all fixture values are ASCII, so sorted-key compact JSON is the RFC 8785 form).
"""
from __future__ import annotations

import ast
import base64
import dataclasses
import datetime
import hashlib
import itertools
import json
from pathlib import Path
from typing import Any, Callable

import pytest

from smart_ads.analytics import intelligence
from smart_ads.analytics.intelligence import (
    INTELLIGENCE_ERROR_CODES,
    METRIC_WINDOW_COLUMNS,
    AnalysisEvidence,
    EvaluationContext,
    Finding,
    IntelligenceError,
    evaluate_findings,
)
from smart_ads.analytics.policy import SaturationRule, WasteRule
from smart_ads.analytics.policy import (
    AnalysisPolicy,
    EvaluationScope,
    PolicyNotApplicableError,
)
from smart_ads.analytics.results import (
    AnalysisExecution,
    AnalysisResult,
    AnalysisResultSchema,
    CanonicalResultEntry,
    CanonicalResultSet,
    ResultSetMismatchError,
)
from smart_ads.contracts.jcs import ArtifactLocator, P1Integrity
from smart_ads.contracts.schemas import AnalyticsLandingRow, DateRange, FactKey
from smart_ads.domain.registry import ExpectedResourceInventory, ExpectedResourceKey

MAX_INT64 = 9223372036854775807
END = "2026-11-10"
INSTANT = "2026-11-11T00:00:00.000000Z"
METRICS_KEY = "metrics:window_states"
SPEND = "metric:spend_v1"
CLICKS = "metric:clicks_v1"
IMPRESSIONS = "metric:impressions_v1"
FINDING_TYPE = "smart_ads/finding/v1"
RESULT_TYPE = "smart_ads/analysis_result/v1"
EXECUTION_TYPE = "smart_ads/analysis_execution/v1"
POLICY_TYPE = "smart_ads/analysis_policy/v1"
LANDING_TYPE = "smart_ads/analytics_landing_row/v1"
LOCATOR_SCHEMA = "smart_ads/artifact_locator/v1"


# ------------------------------------------------------------------ independent hashing


def _jcs(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def _sha(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_jcs(value)).hexdigest()


def _locator_dict(artifact_type: str, envelope: Any) -> dict[str, Any]:
    digest = _sha(envelope)
    return {
        "$schema": LOCATOR_SCHEMA,
        "artifact_type": artifact_type,
        "content_digest": digest,
        "serialization": "rfc8785-json",
        "store_kind": "cell_immutable_object",
        "object_ref": "cell-object:" + digest,
    }


def _expected_key(rule_id: str, rule_type: str, resource: str, start: str, end: str) -> str:
    identity = {
        "policy_id": "policy:p1",
        "policy_version": "1",
        "rule_id": rule_id,
        "finding_type": rule_type,
        "result_key": METRICS_KEY,
        "resource_ref": resource,
        "window_start_date": start,
        "window_end_date": end,
    }
    return "finding:" + _sha(identity)


def _raises(code: str, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> IntelligenceError:
    with pytest.raises(IntelligenceError) as info:
        fn(*args, **kwargs)
    assert info.value.code == code, str(info.value)
    return info.value


# ------------------------------------------------------------------ fixture builders


def _resource(seed: int) -> str:
    body = base64.b32encode(bytes([seed]) * 32).decode("ascii").lower().rstrip("=")
    return "resource:" + body


RES = tuple(sorted(_resource(seed) for seed in (1, 2, 3)))


def _day(back: int) -> str:
    return (datetime.date.fromisoformat(END) - datetime.timedelta(days=back)).isoformat()


def _loc(artifact_type: str, seed: str) -> ArtifactLocator:
    return ArtifactLocator.from_digest(artifact_type, "sha256:" + seed * 64)


BUNDLE = _loc("smart_ads/analysis_replay_input_bundle/v1", "a")
SNAPSHOT = _loc("smart_ads/dataset_snapshot/v1", "b")
RUN = _loc("smart_ads/migration_run_context/v1", "e")
KEY_REGISTRY = _loc("smart_ads/key_authorization_registry/v1", "c")
REGISTRY_SNAPSHOT = _loc("smart_ads/private_registry_snapshot/v1", "d")
SIGNATURE = base64.b64encode(b"\x01" * 64).decode("ascii")


def _unsigned_integrity() -> P1Integrity:
    return P1Integrity(key_id="key:ed25519:" + "b" * 64, key_registry_snapshot_locator=KEY_REGISTRY)


def _signed_integrity(content_digest: str) -> P1Integrity:
    return P1Integrity(
        key_id="key:ed25519:" + "b" * 64,
        key_registry_snapshot_locator=KEY_REGISTRY,
        content_digest=content_digest,
        signature_base64=SIGNATURE,
    )


def _sign(artifact: Any) -> Any:
    """Return a copy carrying a finalized integrity block over its P1 preimage."""
    unsigned = dataclasses.replace(artifact, integrity=_unsigned_integrity())
    return dataclasses.replace(unsigned, integrity=_signed_integrity(_sha(unsigned.to_dict())))


# Non-value rows of the 12-row matrix: (metric_origin, presence, calculation, unknown_reason).
NON_VALUE_STATES: dict[str, tuple[str, str, str, str]] = {
    "provider:missing": ("provider_observation", "missing", "not_applicable", "provider_omitted"),
    "provider:unproven_zero": (
        "provider_observation", "unproven_zero", "not_applicable", "zero_not_proven",
    ),
    "provider:timeout": ("provider_observation", "timeout", "not_applicable", "provider_timeout"),
    "provider:not_applicable_at_level": (
        "provider_observation", "not_applicable_at_level", "not_applicable",
        "metric_not_applicable_at_level",
    ),
    "provider:retracted_tombstone": (
        "provider_observation", "retracted_tombstone", "not_applicable", "source_retracted",
    ),
    "derived:input_missing": ("derived_formula", "not_applicable", "input_missing", "input_missing"),
    "derived:input_unproven": (
        "derived_formula", "not_applicable", "input_unproven", "input_unproven",
    ),
    "derived:division_by_zero": (
        "derived_formula", "not_applicable", "division_by_zero", "division_by_zero",
    ),
    "derived:not_applicable_at_level": (
        "derived_formula", "not_applicable_at_level", "not_applicable",
        "metric_not_applicable_at_level",
    ),
    "derived:retracted_tombstone": (
        "derived_formula", "retracted_tombstone", "not_applicable", "source_retracted",
    ),
}
ABSENT = "absent"
NON_VALUE_CASES = (*NON_VALUE_STATES, ABSENT)

NULL = {"_type": "null", "value": None}


def _cell(cell_type: str, value: str | None) -> dict[str, Any]:
    return NULL if value is None else {"_type": cell_type, "value": value}


def _mrow(
    resource: str, start: str, end: str, metric: str, value: str = "0", state: str = "observed"
) -> list[dict[str, Any]]:
    """One row of the metric-window relation carrying `state` (and `value` when valued)."""
    money = metric == SPEND
    if state in ("observed", "computed"):
        origin, presence, calc = (
            ("provider_observation", "observed", "not_applicable")
            if state == "observed"
            else ("derived_formula", "not_applicable", "computed")
        )
        reason = None
        numeric = (
            ("int64_minor_currency", value, "minor_currency", "BRL")
            if money
            else ("int64_count", value, "count", None)
        )
    else:
        origin, presence, calc, reason = NON_VALUE_STATES[state]
        numeric = (None, None, None, None)
    value_type, raw, unit, currency = numeric
    return [
        _cell("opaque_ref", resource),
        _cell("date", start),
        _cell("date", end),
        _cell("opaque_ref", metric),
        _cell("utf8", origin),
        _cell("utf8", presence),
        _cell("utf8", calc),
        _cell("utf8", reason),
        _cell("utf8", value_type),
        _cell("int64", raw),
        _cell("utf8", unit),
        _cell("utf8", currency),
    ]


def _metric(
    resource: str, window: tuple[str, str], metric: str, value: str, state: str = "observed"
) -> list[list[dict[str, Any]]]:
    """Zero or one rows: `absent` produces no row at all."""
    if state == ABSENT:
        return []
    return [_mrow(resource, window[0], window[1], metric, value, state)]


COLUMNS = [
    {"name": "resource_ref", "cell_type": "opaque_ref", "nullable": False},
    {"name": "window_start_date", "cell_type": "date", "nullable": False},
    {"name": "window_end_date", "cell_type": "date", "nullable": False},
    {"name": "metric_semantic_ref", "cell_type": "opaque_ref", "nullable": False},
    {"name": "metric_origin", "cell_type": "utf8", "nullable": False},
    {"name": "presence_status", "cell_type": "utf8", "nullable": False},
    {"name": "calculation_status", "cell_type": "utf8", "nullable": False},
    {"name": "unknown_reason", "cell_type": "utf8", "nullable": True},
    {"name": "value_type", "cell_type": "utf8", "nullable": True},
    {"name": "raw_numeric_value", "cell_type": "int64", "nullable": True},
    {"name": "unit", "cell_type": "utf8", "nullable": True},
    {"name": "currency", "cell_type": "utf8", "nullable": True},
]


def _schema(columns: list[dict[str, Any]] | None = None, kind: str = "relation") -> AnalysisResultSchema:
    return AnalysisResultSchema.from_dict(
        {
            "$schema": "smart_ads/analysis_result_schema/v1",
            "result_kind": kind,
            "columns": columns if columns is not None else COLUMNS,
            "unique_key": None,
        }
    )


def _result(key: str, rows: list[Any], schema: AnalysisResultSchema) -> AnalysisResult:
    schema_dict = schema.to_dict()
    return AnalysisResult.from_dict(
        {
            "$schema": RESULT_TYPE,
            "migration_run_context_locator": RUN.to_dict(),
            "dataset_snapshot_locator": SNAPSHOT.to_dict(),
            "replay_input_bundle_locator": BUNDLE.to_dict(),
            "result_key": key,
            "result_projection": {
                "result_kind": schema_dict["result_kind"],
                "analysis_result_schema_locator": schema.locator().to_dict(),
                "columns": schema_dict["columns"],
                "rows": rows,
                "row_count": len(rows),
            },
        }
    )


EXTRA_SCHEMA = _schema([{"name": "total", "cell_type": "int64", "nullable": False}], "scalar")


def _execution(results: tuple[AnalysisResult, ...]) -> AnalysisExecution:
    ordered = sorted(results, key=lambda result: result.result_key.encode("utf-8"))
    entries = [CanonicalResultEntry.from_result(result) for result in ordered]
    return AnalysisExecution(BUNDLE, CanonicalResultSet.build(BUNDLE, entries))


def _waste_rule(
    rule_id: str = "rule:waste", window: int = 3, min_spend: str = "1000", max_outcome: str = "0"
) -> dict[str, Any]:
    return {
        "rule_id": rule_id,
        "rule_type": "waste",
        "window_days": window,
        "spend_metric_ref": SPEND,
        "outcome_metric_ref": CLICKS,
        "min_spend_minor": min_spend,
        "max_outcome_count": max_outcome,
    }


def _saturation_rule(
    rule_id: str = "rule:saturation",
    window: int = 2,
    min_growth: str = "0.500000",
    max_growth: str = "0.100000",
    min_baseline: str = "100",
) -> dict[str, Any]:
    return {
        "rule_id": rule_id,
        "rule_type": "saturation",
        "window_days": window,
        "spend_metric_ref": SPEND,
        "outcome_metric_ref": CLICKS,
        "min_spend_growth": min_growth,
        "max_outcome_growth": max_growth,
        "min_baseline_spend_minor": min_baseline,
    }


def _stalled_rule(
    rule_id: str = "rule:stalled", days: int = 3, max_impressions: str = "10"
) -> dict[str, Any]:
    return {
        "rule_id": rule_id,
        "rule_type": "stalled_delivery",
        "min_consecutive_days": days,
        "max_impressions": max_impressions,
    }


def _restatement_rule(
    rule_id: str = "rule:restatement",
    lookback: int = 7,
    kinds: tuple[str, ...] = ("state_flip", "tombstone", "value_change"),
) -> dict[str, Any]:
    return {
        "rule_id": rule_id,
        "rule_type": "restatement",
        "lookback_days": lookback,
        "restatement_kinds": list(kinds),
    }


def _policy(
    *rules: dict[str, Any],
    valid_from: str = "2026-01-01T00:00:00.000000Z",
    valid_until: str = "2027-01-01T00:00:00.000000Z",
) -> AnalysisPolicy:
    return AnalysisPolicy.from_dict(
        {
            "$schema": POLICY_TYPE,
            "policy_id": "policy:p1",
            "policy_version": "1",
            "tenant_ref": "tenant:t1",
            "applicability_scope": {
                "resource_scope_ref": "scope:s1",
                "resource_level": "campaign",
                "ad_platform_ref": "meta",
                "currency": "BRL",
            },
            "validity": {"valid_from_utc": valid_from, "valid_until_utc": valid_until},
            "rules": sorted(rules, key=lambda rule: rule["rule_id"].encode("utf-8")),
        }
    )


SCOPE = EvaluationScope(
    tenant_ref="tenant:t1",
    resource_scope_ref="scope:s1",
    resource_level="campaign",
    ad_platform_ref="meta",
    currency="BRL",
)


def _inventory(
    resources: tuple[str, ...] = RES[:1], *, tenant: str = "tenant:t1", scope: str = "scope:s1"
) -> ExpectedResourceInventory:
    return ExpectedResourceInventory(
        inventory_id="inventory:i1",
        registry_snapshot_locator=REGISTRY_SNAPSHOT,
        registry_snapshot_digest=REGISTRY_SNAPSHOT.content_digest,
        tenant_ref=tenant,
        binding_ref="binding:b1",
        account_ref="account:a1",
        resource_scope_ref=scope,
        date_range=DateRange(start_date=_day(29), end_date=END),
        expected_resources=tuple(
            ExpectedResourceKey(
                binding_ref="binding:b1",
                account_ref="account:a1",
                resource_ref=resource,
                resource_level="campaign",
                metric_date=END,
            )
            for resource in resources
        ),
    )


def _build(
    rules: tuple[dict[str, Any], ...],
    rows: list[Any],
    *,
    history: tuple[AnalyticsLandingRow, ...] = (),
    resources: tuple[str, ...] = RES[:1],
    scope: EvaluationScope = SCOPE,
    instant: str = INSTANT,
    curation: int = 30,
    anchor: str = END,
    end: str = END,
    policy: AnalysisPolicy | None = None,
    inventory: ExpectedResourceInventory | None = None,
    signed: bool = False,
    columns: list[dict[str, Any]] | None = None,
) -> tuple[EvaluationContext, AnalysisEvidence]:
    """A verified scenario; `signed` finalizes every P1 input and sets `require_signed`."""
    seal: Callable[[Any], Any] = _sign if signed else (lambda artifact: artifact)
    chosen = seal(policy if policy is not None else _policy(*rules))
    schema, extra_schema = seal(_schema(columns)), seal(EXTRA_SCHEMA)
    extra = seal(_result("aaa:extra", [[{"_type": "int64", "value": "7"}]], extra_schema))
    results = (extra, seal(_result(METRICS_KEY, rows, schema)))
    context = EvaluationContext(
        policy=chosen,
        scope=scope,
        evaluation_instant_utc=instant,
        window_end_date=end,
        curation_restatement_lookback_days=curation,
        curation_anchor_date=anchor,
        inventory=seal(inventory if inventory is not None else _inventory(resources)),
        metrics_result_key=METRICS_KEY,
        restatement_history=history,
    )
    evidence = AnalysisEvidence(
        execution=seal(_execution(results)),
        resolved_results=results,
        resolved_schemas=(extra_schema, schema),
        bundle_dataset_snapshot_locator=SNAPSHOT,
        bundle_analysis_policy_locator=chosen.locator(),
        require_signed=signed,
    )
    return context, evidence


def _run(rules: tuple[dict[str, Any], ...], rows: list[Any], **kwargs: Any) -> tuple[Finding, ...]:
    return evaluate_findings(*_build(rules, rows, **kwargs))


def _verdicts(findings: tuple[Finding, ...]) -> list[tuple[str, str]]:
    return [(finding.finding_type, finding.finding_status) for finding in findings]


R0 = RES[0]
W3 = (_day(2), END)


def _waste_rows(spend: str, clicks: str, spend_state: str = "observed", clicks_state: str = "observed") -> list[Any]:
    return _metric(R0, W3, SPEND, spend, spend_state) + _metric(R0, W3, CLICKS, clicks, clicks_state)


# ------------------------------------------------------------------ error type


def test_error_codes_are_closed_and_carried() -> None:
    assert issubclass(IntelligenceError, intelligence.ClosedValidationError)
    for code in INTELLIGENCE_ERROR_CODES:
        assert IntelligenceError(code, "detail").code == code
    with pytest.raises(intelligence.ClosedValidationError) as info:
        IntelligenceError("not_a_code", "detail")
    assert not isinstance(info.value, IntelligenceError)


def test_metric_window_columns_constant_matches_the_contract() -> None:
    assert [
        {"name": name, "cell_type": cell_type, "nullable": nullable}
        for name, cell_type, nullable in METRIC_WINDOW_COLUMNS
    ] == COLUMNS


# ------------------------------------------------------------------ waste


@pytest.mark.parametrize(
    ("spend", "clicks", "expected"),
    [
        ("1000", "0", [("waste", "detected")]),  # both at threshold
        ("999", "0", []),  # spend just below min_spend_minor
        ("1001", "0", [("waste", "detected")]),  # spend just above
        ("1000", "1", []),  # outcome just above max_outcome_count
        ("0", "0", []),
    ],
)
def test_waste_threshold_boundaries(spend: str, clicks: str, expected: list[Any]) -> None:
    assert _verdicts(_run((_waste_rule(),), _waste_rows(spend, clicks))) == expected


@pytest.mark.parametrize(
    ("clicks", "expected"),
    [("4", [("waste", "detected")]), ("5", [("waste", "detected")]), ("6", [])],
)
def test_waste_outcome_threshold_boundaries(clicks: str, expected: list[Any]) -> None:
    rule = _waste_rule(max_outcome="5")
    assert _verdicts(_run((rule,), _waste_rows("1000", clicks))) == expected


@pytest.mark.parametrize(
    ("min_spend", "max_outcome", "spend", "clicks", "fires"),
    [
        (str(MAX_INT64), "0", str(MAX_INT64), "0", True),
        (str(MAX_INT64), "0", str(MAX_INT64 - 1), "0", False),
        ("0", str(MAX_INT64), "0", str(MAX_INT64), True),
        ("0", str(MAX_INT64 - 1), "0", str(MAX_INT64), False),
        ("0", "0", "0", "0", True),
    ],
)
def test_waste_int64_extremes(
    min_spend: str, max_outcome: str, spend: str, clicks: str, fires: bool
) -> None:
    rule = _waste_rule(min_spend=min_spend, max_outcome=max_outcome)
    expected = [("waste", "detected")] if fires else []
    assert _verdicts(_run((rule,), _waste_rows(spend, clicks))) == expected


def test_waste_computed_input_carries_a_value() -> None:
    rows = _waste_rows("5000", "0", spend_state="computed", clicks_state="computed")
    assert _verdicts(_run((_waste_rule(),), rows)) == [("waste", "detected")]


@pytest.mark.parametrize("state", NON_VALUE_CASES)
@pytest.mark.parametrize("position", ["spend", "outcome"])
def test_waste_non_value_input_is_inconclusive_never_zero(state: str, position: str) -> None:
    # The valued side alone would fire; the unknown side must never be read as zero.
    rows = (
        _waste_rows("5000", "0", spend_state=state)
        if position == "spend"
        else _waste_rows("5000", "0", clicks_state=state)
    )
    findings = _run((_waste_rule(),), rows)
    assert _verdicts(findings) == [("waste", "inconclusive")]
    assert findings[0].mutation_recommendation_blocked is True


@pytest.mark.parametrize(
    "rows",
    [
        _waste_rows("999", "0", clicks_state="provider:timeout"),  # known spend below the minimum
        _waste_rows("5000", "1", spend_state="derived:input_missing"),  # known outcome above max
        _waste_rows("999", "1", clicks_state=ABSENT),  # known spend below the minimum, no outcome row
    ],
)
def test_waste_unknown_input_dominates_a_known_ruling_out(rows: list[Any]) -> None:
    # Pinned convention: any non-valued input gives inconclusive, even when a known value alone
    # would already rule the finding out (the ADR does not fix this; open decision).
    assert _verdicts(_run((_waste_rule(),), rows)) == [("waste", "inconclusive")]


def test_waste_row_for_another_window_is_absent_not_zero() -> None:
    rows = _metric(R0, (_day(3), END), SPEND, "5000") + _metric(R0, W3, CLICKS, "0")
    assert _verdicts(_run((_waste_rule(),), rows)) == [("waste", "inconclusive")]


def test_waste_finding_is_bound_exactly() -> None:
    context, evidence = _build((_waste_rule(),), _waste_rows("1000", "0"))
    (finding,) = evaluate_findings(context, evidence)
    metrics = evidence.resolved_results[1]
    result_locator = _locator_dict(RESULT_TYPE, metrics.to_dict())
    core = {
        "$schema": FINDING_TYPE,
        "analysis_execution_locator": _locator_dict(EXECUTION_TYPE, evidence.execution.to_dict()),
        "result_locator": result_locator,
        "result_key": METRICS_KEY,
        "finding_key": _expected_key("rule:waste", "waste", R0, _day(2), END),
        "finding_type": "waste",
        "finding_status": "detected",
        "mutation_recommendation_blocked": False,
        "evidence_locators": [result_locator],
        "analysis_policy_locator": _locator_dict(POLICY_TYPE, context.policy.to_dict()),
    }
    assert finding.to_dict() == {**core, "finding_digest": _sha(core)}
    assert finding.locator().to_dict() == _locator_dict(FINDING_TYPE, finding.to_dict())


def test_every_expected_resource_is_evaluated() -> None:
    rows = _metric(RES[1], W3, SPEND, "5000") + _metric(RES[1], W3, CLICKS, "0")
    findings = _run((_waste_rule(),), rows, resources=RES)
    by_key = {finding.finding_key: finding.finding_status for finding in findings}
    assert by_key == {
        _expected_key("rule:waste", "waste", RES[0], _day(2), END): "inconclusive",
        _expected_key("rule:waste", "waste", RES[1], _day(2), END): "detected",
        _expected_key("rule:waste", "waste", RES[2], _day(2), END): "inconclusive",
    }
    keys = [finding.finding_key.encode("utf-8") for finding in findings]
    assert keys == sorted(keys)


# ------------------------------------------------------------------ applicability


@pytest.mark.parametrize(
    ("code", "scope_change", "instant"),
    [
        ("tenant_mismatch", {"tenant_ref": "tenant:t2"}, INSTANT),
        ("resource_scope_mismatch", {"resource_scope_ref": "scope:s2"}, INSTANT),
        ("resource_level_mismatch", {"resource_level": "adset"}, INSTANT),
        ("ad_platform_mismatch", {"ad_platform_ref": "google"}, INSTANT),
        ("currency_mismatch", {"currency": "USD"}, INSTANT),
        ("not_yet_valid", {}, "2025-12-31T23:59:59.999999Z"),
        ("expired", {}, "2027-01-01T00:00:00.000001Z"),
    ],
)
def test_inapplicable_policy_raises_the_policy_code(
    code: str, scope_change: dict[str, str], instant: str
) -> None:
    scope = dataclasses.replace(SCOPE, **scope_change)
    end = min(END, instant.partition("T")[0])  # the window may not end after the instant date
    rows = _waste_rows("1000", "0")
    context, evidence = _build((_waste_rule(),), rows, scope=scope, instant=instant, end=end)
    with pytest.raises(PolicyNotApplicableError) as info:
        evaluate_findings(context, evidence)
    assert info.value.code == code


@pytest.mark.parametrize(
    ("instant", "end", "verdict"),
    [
        ("2026-01-01T00:00:00.000000Z", "2026-01-01", "inconclusive"),  # rows are for END
        ("2027-01-01T00:00:00.000000Z", END, "detected"),
    ],
)
def test_policy_validity_bounds_are_inclusive(instant: str, end: str, verdict: str) -> None:
    findings = _run((_waste_rule(),), _waste_rows("1000", "0"), instant=instant, end=end)
    assert _verdicts(findings) == [("waste", verdict)]


# ------------------------------------------------------------------ saturation

CURRENT = (_day(1), END)  # window_days = 2
BASELINE = (_day(3), _day(2))


def _sat_rows(
    spend: tuple[str, str],
    clicks: tuple[str, str],
    states: tuple[str, str, str, str] = ("observed",) * 4,
) -> list[Any]:
    """(baseline, current) spend and clicks; states in the order spend_b, spend_c, clicks_b, clicks_c."""
    return (
        _metric(R0, BASELINE, SPEND, spend[0], states[0])
        + _metric(R0, CURRENT, SPEND, spend[1], states[1])
        + _metric(R0, BASELINE, CLICKS, clicks[0], states[2])
        + _metric(R0, CURRENT, CLICKS, clicks[1], states[3])
    )


def _sat(rule: dict[str, Any], spend: tuple[str, str], clicks: tuple[str, str]) -> list[Any]:
    return _verdicts(_run((rule,), _sat_rows(spend, clicks)))


SAT_DETECTED = [("saturation", "detected")]


@pytest.mark.parametrize(
    ("spend", "clicks", "expected"),
    [
        (("1000", "1500"), ("100", "110"), SAT_DETECTED),  # both growths exactly at threshold
        (("1000", "1499"), ("100", "110"), []),  # spend growth just below min_spend_growth
        (("1000", "1501"), ("100", "110"), SAT_DETECTED),  # spend growth just above
        (("1000", "1500"), ("100", "111"), []),  # outcome growth just above max_outcome_growth
        (("1000", "1500"), ("100", "109"), SAT_DETECTED),  # outcome growth just below
        (("1000", "1500"), ("100", "40"), SAT_DETECTED),  # negative outcome growth
        (("1000", "900"), ("100", "100"), []),  # negative spend growth
        (("99", "1000"), ("100", "100"), []),  # baseline spend just below min_baseline
        (("100", "1000"), ("100", "100"), SAT_DETECTED),  # baseline spend at min_baseline
    ],
)
def test_saturation_threshold_boundaries(
    spend: tuple[str, str], clicks: tuple[str, str], expected: list[Any]
) -> None:
    assert _sat(_saturation_rule(), spend, clicks) == expected


@pytest.mark.parametrize(
    ("spend", "clicks", "expected"),
    [
        # 2999999 / 2000000 = 1.4999995 -> ROUND_HALF_UP 1.500000 -> growth 0.500000 (fires)
        (("2000000", "2999999"), ("1", "1"), SAT_DETECTED),
        # 2999998 / 2000000 = 1.499999 exactly -> growth 0.499999 (does not fire)
        (("2000000", "2999998"), ("1", "1"), []),
        # 2200001 / 2000000 = 1.1000005 -> 1.100001 -> growth 0.100001 > 0.100000
        (("1", "2"), ("2000000", "2200001"), []),
        # 2200000 / 2000000 = 1.100000 -> growth 0.100000 (fires)
        (("1", "2"), ("2000000", "2200000"), SAT_DETECTED),
    ],
)
def test_saturation_growth_rounds_half_up_in_millionths(
    spend: tuple[str, str], clicks: tuple[str, str], expected: list[Any]
) -> None:
    assert _sat(_saturation_rule(min_baseline="0"), spend, clicks) == expected


@pytest.mark.parametrize(
    ("rule", "spend", "clicks", "expected"),
    [
        (
            _saturation_rule(min_growth="0.000000", max_growth="0.000000", min_baseline=str(MAX_INT64)),
            (str(MAX_INT64), str(MAX_INT64)),
            (str(MAX_INT64), str(MAX_INT64)),
            SAT_DETECTED,
        ),
        (
            _saturation_rule(min_baseline=str(MAX_INT64)),
            (str(MAX_INT64 - 1), str(MAX_INT64)),
            ("1", "1"),
            [],
        ),
        (
            _saturation_rule(min_growth="1.000000", min_baseline="1"),
            ("1", str(MAX_INT64)),
            ("1", "1"),
            SAT_DETECTED,
        ),
        (
            _saturation_rule(min_growth=str(MAX_INT64) + ".000000", min_baseline="1"),
            ("1", str(MAX_INT64)),
            ("1", "1"),
            [],
        ),
    ],
)
def test_saturation_int64_extremes(
    rule: dict[str, Any], spend: tuple[str, str], clicks: tuple[str, str], expected: list[Any]
) -> None:
    assert _sat(rule, spend, clicks) == expected


@pytest.mark.parametrize(
    ("spend", "clicks"),
    [(("0", "10"), ("1", "1")), (("10", "20"), ("0", "0"))],
)
def test_saturation_zero_baseline_is_division_by_zero_and_inconclusive(
    spend: tuple[str, str], clicks: tuple[str, str]
) -> None:
    assert _sat(_saturation_rule(min_baseline="0"), spend, clicks) == [("saturation", "inconclusive")]


@pytest.mark.parametrize("state", NON_VALUE_CASES)
@pytest.mark.parametrize("position", range(4))
def test_saturation_non_value_input_is_inconclusive(state: str, position: int) -> None:
    states = tuple(state if index == position else "observed" for index in range(4))
    rows = _sat_rows(("1000", "5000"), ("100", "100"), states)  # type: ignore[arg-type]
    findings = _run((_saturation_rule(),), rows)
    assert _verdicts(findings) == [("saturation", "inconclusive")]
    assert findings[0].finding_key == _expected_key(
        "rule:saturation", "saturation", R0, BASELINE[0], CURRENT[1]
    )


@pytest.mark.parametrize(
    ("spend", "clicks", "states"),
    [
        # known baseline spend below the gate, current outcome non-valued
        (("99", "1000"), ("100", "100"), ("observed", "observed", "observed", "provider:missing")),
        # known spend growth below the minimum, baseline outcome non-valued
        (("1000", "1000"), ("100", "100"), ("observed", "observed", "derived:input_unproven", "observed")),
        # known outcome growth above the maximum (100 -> 500), current spend absent
        (("1000", "5000"), ("100", "500"), ("observed", ABSENT, "observed", "observed")),
    ],
)
def test_saturation_unknown_input_dominates_a_known_ruling_out(
    spend: tuple[str, str], clicks: tuple[str, str], states: tuple[str, str, str, str]
) -> None:
    rows = _sat_rows(spend, clicks, states)
    assert _verdicts(_run((_saturation_rule(),), rows)) == [("saturation", "inconclusive")]


def test_saturation_computed_inputs_carry_values() -> None:
    rows = _sat_rows(("1000", "5000"), ("100", "100"), ("computed",) * 4)  # type: ignore[arg-type]
    assert _verdicts(_run((_saturation_rule(),), rows)) == SAT_DETECTED


# ------------------------------------------------------------------ stalled delivery


def _daily(values: list[tuple[str, str]], resource: str = R0) -> list[Any]:
    """Impressions per day, newest first: values[k] is (value, state) for END - k days."""
    rows: list[Any] = []
    for back, (value, state) in enumerate(values):
        rows += _metric(resource, (_day(back), _day(back)), IMPRESSIONS, value, state)
    return rows


def _obs(*values: str) -> list[tuple[str, str]]:
    return [(value, "observed") for value in values]


STALLED = [("stalled_delivery", "detected")]


@pytest.mark.parametrize(
    ("values", "expected"),
    [
        (_obs("10", "10", "10"), STALLED),  # at max_impressions every day
        (_obs("9", "0", "10"), STALLED),
        (_obs("10", "11", "10"), []),  # one day just above
        (_obs("10", "10", "10", "999"), STALLED),  # only the trailing run counts
        (_obs("10", "10"), [("stalled_delivery", "inconclusive")]),  # a day is absent
    ],
)
def test_stalled_delivery_threshold_boundaries(values: list[Any], expected: list[Any]) -> None:
    assert _verdicts(_run((_stalled_rule(),), _daily(values))) == expected


def test_stalled_delivery_int64_extremes_and_single_day() -> None:
    rule = _stalled_rule(days=1, max_impressions=str(MAX_INT64))
    assert _verdicts(_run((rule,), _daily(_obs(str(MAX_INT64))))) == STALLED
    rule = _stalled_rule(days=1, max_impressions=str(MAX_INT64 - 1))
    assert _verdicts(_run((rule,), _daily(_obs(str(MAX_INT64))))) == []
    rule = _stalled_rule(days=1, max_impressions="0")
    assert _verdicts(_run((rule,), _daily(_obs("0")))) == STALLED


@pytest.mark.parametrize("state", NON_VALUE_CASES)
@pytest.mark.parametrize("position", range(3))
def test_stalled_delivery_non_value_day_is_inconclusive(state: str, position: int) -> None:
    values = [("0", state if back == position else "observed") for back in range(3)]
    findings = _run((_stalled_rule(),), _daily(values))
    assert _verdicts(findings) == [("stalled_delivery", "inconclusive")]
    assert findings[0].finding_key == _expected_key(
        "rule:stalled", "stalled_delivery", R0, _day(2), END
    )


def test_stalled_delivery_non_value_day_wins_over_a_known_breach() -> None:
    values = [("999", "observed"), ("0", "provider:timeout"), ("0", "observed")]
    assert _verdicts(_run((_stalled_rule(),), _daily(values))) == [
        ("stalled_delivery", "inconclusive")
    ]


@pytest.mark.parametrize(
    "rule",
    [
        _waste_rule(window=9007199254740991),
        _saturation_rule(window=1000000),
        _stalled_rule(days=9007199254740991),
        _waste_rule(window=740000),
    ],
)
def test_window_before_the_first_calendar_date_rejects(rule: dict[str, Any]) -> None:
    _raises("window_out_of_range", _run, (rule,), [])


# ------------------------------------------------------------------ restatement

T1 = "2026-11-10T10:00:00.000000Z"
T2 = "2026-11-10T11:00:00.000000Z"
T3 = "2026-11-10T12:00:00.000000Z"
PROVIDER_REASONS = {
    "observed": None,
    "missing": "provider_omitted",
    "timeout": "provider_timeout",
    "not_applicable_at_level": "metric_not_applicable_at_level",
    "retracted_tombstone": "source_retracted",
}


def _landing(
    *,
    presence: str = "observed",
    raw: str = "100",
    at: str = T1,
    metric_date: str = END,
    resource: str = R0,
    binding: str = "binding:b1",
    obs: str = "observation:o1",
) -> AnalyticsLandingRow:
    valued = presence == "observed"
    return AnalyticsLandingRow(
        fact_key=FactKey(
            binding_ref=binding,
            account_ref="account:a1",
            resource_ref=resource,
            resource_level="campaign",
            metric_date=metric_date,
            metric_semantic_ref=IMPRESSIONS,
            source_metric_ref="source-metric:provider:pipeboard.impressions:v1",
            attribution_ref="attribution:not_applicable",
            breakdown_signature="breakdown:none",
        ),
        value_type="int64_count" if valued else None,
        raw_numeric_value=raw if valued else None,
        unit="count" if valued else None,
        currency=None,
        metric_origin="provider_observation",
        presence_status=presence,  # type: ignore[arg-type]
        unknown_reason=PROVIDER_REASONS[presence],  # type: ignore[arg-type]
        calculation_status="not_applicable",
        collected_at_utc=at,
        source_observation_ref=obs,
        adapter_version="adapter-1",
        semantic_version="semantic-1",
    )


def _restatement_evidence(evidence: AnalysisEvidence) -> list[dict[str, Any]]:
    """Containing artifacts only: the metric result and the bundle's dataset snapshot."""
    result = _locator_dict(RESULT_TYPE, evidence.resolved_results[1].to_dict())
    return sorted([result, SNAPSHOT.to_dict()], key=_jcs)


def _restated(rule: dict[str, Any], *history: AnalyticsLandingRow, **kwargs: Any) -> bool:
    findings = _run((rule,), [], history=history, **kwargs)
    assert _verdicts(findings) in ([], [("restatement", "detected")])
    return bool(findings)


RESTATEMENT_PAIRS = {
    "value_change": (_landing(raw="100"), _landing(raw="200", at=T2)),
    "state_flip": (_landing(raw="100"), _landing(presence="missing", at=T2)),
    "tombstone": (_landing(raw="100"), _landing(presence="retracted_tombstone", at=T2)),
    # Section 6.2 rule 2: at an equal instant the tombstone wins and restates.
    "tombstone_same_instant": (_landing(raw="100"), _landing(presence="retracted_tombstone")),
}


@pytest.mark.parametrize("case", sorted(RESTATEMENT_PAIRS))
def test_restatement_of_each_kind_is_detected_and_blocks(case: str) -> None:
    prior, current = RESTATEMENT_PAIRS[case]
    context, evidence = _build((_restatement_rule(),), [], history=(current, prior))
    (finding,) = evaluate_findings(context, evidence)
    assert (finding.finding_type, finding.finding_status) == ("restatement", "detected")
    assert finding.mutation_recommendation_blocked is True
    assert finding.finding_key == _expected_key("rule:restatement", "restatement", R0, _day(6), END)
    assert finding.to_dict()["evidence_locators"] == _restatement_evidence(evidence)


@pytest.mark.parametrize(
    ("case", "listed"),
    [
        ("value_change", ("state_flip", "tombstone")),
        ("state_flip", ("tombstone", "value_change")),
        ("tombstone", ("state_flip", "value_change")),
        ("tombstone_same_instant", ("state_flip", "value_change")),
    ],
)
def test_restatement_kind_not_listed_by_the_rule_is_ignored(case: str, listed: tuple[str, ...]) -> None:
    prior, current = RESTATEMENT_PAIRS[case]
    rule = _restatement_rule(kinds=listed)
    assert _run((rule,), [], history=(prior, current)) == ()


@pytest.mark.parametrize(
    ("prior", "current"),
    [
        (_landing(raw="100"), _landing(raw="100", at=T2, obs="observation:o2")),  # unchanged
        (_landing(presence="retracted_tombstone"), _landing(presence="missing", at=T2)),
        (_landing(presence="missing"), _landing(presence="not_applicable_at_level", at=T2)),
        (_landing(presence="missing"), _landing(presence="timeout", at=T2)),
    ],
)
def test_pairs_classify_restatement_returns_none_for_never_find(
    prior: AnalyticsLandingRow, current: AnalyticsLandingRow
) -> None:
    assert _run((_restatement_rule(),), [], history=(prior, current)) == ()


def test_restatement_chain_classifies_each_successive_winner() -> None:
    first, second = _landing(raw="100"), _landing(raw="200", at=T2)
    third = _landing(presence="missing", at=T3)
    assert _restated(_restatement_rule(kinds=("state_flip",)), third, first, second)
    assert _restated(_restatement_rule(kinds=("value_change",)), second, third, first)
    assert not _restated(_restatement_rule(kinds=("tombstone",)), first, second, third)
    # 100 -> 200 -> 100: successive pairs change value although first and last are equal.
    back = _landing(raw="100", at=T3)
    assert _restated(_restatement_rule(kinds=("value_change",)), back, second, first)
    # 100 -> missing -> 100: only state flips, never a value change.
    gap = _landing(presence="missing", at=T2)
    assert not _restated(_restatement_rule(kinds=("value_change",)), first, gap, back)
    assert _restated(_restatement_rule(kinds=("state_flip",)), first, gap, back)


def test_restatement_groups_by_fact_key_within_a_resource() -> None:
    # Two fact keys of one resource: a cross-key pairing would invent a value change.
    one_day = _landing(raw="100", metric_date=END)
    other_day = _landing(raw="200", metric_date=_day(1), at=T2)
    assert not _restated(_restatement_rule(), one_day, other_day)
    restated_day = _landing(raw="300", metric_date=_day(1), at=T3)
    assert _restated(_restatement_rule(), one_day, other_day, restated_day)


def test_restatement_groups_resources_apart_on_one_metric_date() -> None:
    first = _landing(raw="100", resource=RES[0])
    other = _landing(raw="200", resource=RES[2], at=T2)
    assert _run((_restatement_rule(),), [], history=(first, other), resources=RES) == ()


def test_restatement_ignores_rows_dated_after_the_window_end() -> None:
    later = _day(-1)
    prior, current = _landing(raw="1", metric_date=later), _landing(raw="2", metric_date=later, at=T2)
    assert not _restated(_restatement_rule(), prior, current)


def test_policy_without_a_restatement_rule_emits_no_restatement() -> None:
    prior, current = RESTATEMENT_PAIRS["tombstone"]
    findings = _run((_waste_rule(),), _waste_rows("1000", "0"), history=(prior, current))
    assert _verdicts(findings) == [("waste", "detected")]


@pytest.mark.parametrize(("back", "found"), [(6, True), (7, False)])
def test_restatement_lookback_window_is_inclusive(back: int, found: bool) -> None:
    prior = _landing(raw="1", metric_date=_day(back))
    current = _landing(raw="2", metric_date=_day(back), at=T2)
    findings = _run((_restatement_rule(lookback=7),), [], history=(prior, current))
    assert bool(findings) is found


def test_restatement_lookback_cannot_exceed_the_curation_window() -> None:
    assert _run((_restatement_rule(lookback=30),), [], curation=30) == ()
    _raises("lookback_exceeds_curation", _run, (_restatement_rule(lookback=31),), [], curation=30)


@pytest.mark.parametrize(
    ("lookback", "curation", "anchor", "inside"),
    [
        (7, 7, END, True),  # identical windows
        (7, 30, _day(-5), True),  # rule window strictly inside
        (7, 7, _day(-1), False),  # rule window starts one day before the curation window
        (7, 30, _day(1), False),  # rule window ends one day after the curation anchor
        (1, 1, END, True),
        (1, 1, _day(1), False),
    ],
)
def test_restatement_window_must_lie_inside_the_curation_window(
    lookback: int, curation: int, anchor: str, inside: bool
) -> None:
    rule = (_restatement_rule(lookback=lookback),)
    if inside:
        assert _run(rule, [], curation=curation, anchor=anchor) == ()
    else:
        _raises("lookback_exceeds_curation", _run, rule, [], curation=curation, anchor=anchor)


def test_free_window_end_cannot_escape_the_curation_window() -> None:
    # Reviewer reproduction: history ends at END, the window end is moved past the anchor.
    prior, current = RESTATEMENT_PAIRS["tombstone"]
    context, evidence = _build(
        (_restatement_rule(),), [], history=(prior, current), instant="2027-01-01T00:00:00.000000Z"
    )
    moved = dataclasses.replace(context, window_end_date="2026-12-31")
    _raises("lookback_exceeds_curation", evaluate_findings, moved, evidence)


def test_curation_anchor_is_irrelevant_without_a_restatement_rule() -> None:
    findings = _run((_waste_rule(),), _waste_rows("1000", "0"), anchor="2000-01-01", curation=1)
    assert _verdicts(findings) == [("waste", "detected")]


def test_restatement_findings_are_per_resource() -> None:
    history = (
        _landing(raw="1", resource=RES[2]),
        _landing(raw="2", resource=RES[2], at=T2),
        _landing(raw="1", resource=RES[0]),
    )
    findings = _run((_restatement_rule(),), [], history=history, resources=RES)
    assert [f.finding_key for f in findings] == [
        _expected_key("rule:restatement", "restatement", RES[2], _day(6), END)
    ]


@pytest.mark.parametrize(
    ("code", "history"),
    [
        ("history_scope_mismatch", (_landing(binding="binding:other"),)),
        ("resource_not_in_inventory", (_landing(resource=RES[1]),)),
        ("invalid_history", (_landing(), _landing())),
    ],
)
def test_restatement_history_rejections(code: str, history: tuple[AnalyticsLandingRow, ...]) -> None:
    _raises(code, _run, (_restatement_rule(),), [], history=history)


def test_restatement_and_threshold_findings_coexist_in_key_order() -> None:
    prior, current = RESTATEMENT_PAIRS["value_change"]
    rules = (_waste_rule(), _restatement_rule())
    findings = _run(rules, _waste_rows("1000", "0"), history=(prior, current))
    expected = sorted(
        [
            (_expected_key("rule:waste", "waste", R0, _day(2), END), False),
            (_expected_key("rule:restatement", "restatement", R0, _day(6), END), True),
        ],
        key=lambda pair: pair[0].encode("utf-8"),
    )
    assert [(f.finding_key, f.mutation_recommendation_blocked) for f in findings] == expected


def test_require_signed_rejects_an_unsigned_policy() -> None:
    context, evidence = _build((_waste_rule(),), _waste_rows("1000", "0"))
    unsigned = dataclasses.replace(evidence, require_signed=True)
    _raises("unsigned_artifact", evaluate_findings, context, unsigned)


# ------------------------------------------------------------------ P1 by hand


def _strip_signature(envelope: dict[str, Any]) -> dict[str, Any]:
    integrity = {
        key: value
        for key, value in envelope["integrity"].items()
        if key not in ("content_digest", "signature_base64")
    }
    return {**envelope, "integrity": integrity}


def _check_p1(artifact: Any, artifact_type: str) -> None:
    _raises("missing_member", artifact.p1_preimage)
    _raises("missing_member", artifact.p1_content_digest)
    unsigned = dataclasses.replace(artifact, integrity=_unsigned_integrity())
    assert unsigned.p1_preimage() == unsigned.to_dict()
    assert unsigned.p1_content_digest() == _sha(unsigned.to_dict())
    signed = _sign(artifact)
    envelope = signed.to_dict()
    assert signed.p1_preimage() == _strip_signature(envelope)
    assert signed.p1_content_digest() == _sha(_strip_signature(envelope))
    assert envelope["integrity"]["content_digest"] == _sha(_strip_signature(envelope))
    assert signed.locator().to_dict() == _locator_dict(artifact_type, envelope)
    bad = _signed_integrity("sha256:" + "0" * 64)
    _raises("content_digest_mismatch", dataclasses.replace, unsigned, integrity=bad)
    _raises("invalid_integrity", dataclasses.replace, artifact, integrity="integrity")


def test_finding_p1_preimage_digest_and_locator_by_hand() -> None:
    (finding,) = _run((_waste_rule(),), _waste_rows("1000", "0"))
    _check_p1(finding, FINDING_TYPE)
    assert _sign(finding).finding_digest == finding.finding_digest  # excludes integrity


# ------------------------------------------------------------------ closed parsing


def _finding_fixture() -> Finding:
    return _run((_waste_rule(),), _waste_rows("1000", "0"))[0]


def _restatement_finding() -> Finding:
    prior, current = RESTATEMENT_PAIRS["tombstone"]
    return _run((_restatement_rule(),), [], history=(prior, current))[0]


def test_finding_round_trip() -> None:
    finding = _finding_fixture()
    assert Finding.from_dict(finding.to_dict()) == finding
    signed = _sign(finding)
    assert Finding.from_dict(signed.to_dict(), require_signed=True) == signed
    restated = _restatement_finding()
    assert Finding.from_dict(restated.to_dict()) == restated
    _raises("missing_member", Finding.from_dict, finding.to_dict(), require_signed=True)
    unsigned = dataclasses.replace(finding, integrity=_unsigned_integrity())
    _raises("invalid_integrity", Finding.from_dict, unsigned.to_dict(), require_signed=True)
    _raises("invalid_type", Finding.from_dict, finding.to_dict(), require_signed=1)


FINDING_MUTATIONS: list[tuple[str, Callable[[dict[str, Any]], Any]]] = [
    ("unknown_member", lambda d: d.update(extra="x")),
    ("missing_member", lambda d: d.pop("finding_key")),
    ("missing_member", lambda d: d.pop("finding_digest")),
    ("schema_mismatch", lambda d: d.update({"$schema": "smart_ads/finding/v2"})),
    ("unknown_value", lambda d: d.update(finding_type="fraud")),
    ("unknown_value", lambda d: d.update(finding_status="maybe")),
    ("invalid_type", lambda d: d.update(finding_type=1)),
    ("invalid_type", lambda d: d.update(mutation_recommendation_blocked=0)),
    ("invalid_type", lambda d: d.update(result_key=True)),
    ("invalid_type", lambda d: d.update(finding_key=None)),
    ("invalid_grammar", lambda d: d.update(result_key="")),
    ("invalid_grammar", lambda d: d.update(finding_key="finding:abc")),
    ("invalid_grammar", lambda d: d.update(finding_digest="")),
    ("invalid_type", lambda d: d.update(finding_digest=7)),
    ("finding_digest_mismatch", lambda d: d.update(finding_digest="sha256:" + "0" * 64)),
    ("finding_digest_mismatch", lambda d: d.update(finding_type="saturation")),
    ("mutation_blocked_mismatch", lambda d: d.update(mutation_recommendation_blocked=True)),
    ("invalid_type", lambda d: d.update(evidence_locators=tuple(d["evidence_locators"]))),
    ("empty", lambda d: d.update(evidence_locators=[])),
    ("duplicate", lambda d: d.update(evidence_locators=d["evidence_locators"] * 2)),
    ("invalid_locator", lambda d: d.update(evidence_locators=[{"artifact_type": "x"}])),
    ("invalid_locator", lambda d: d.update(analysis_execution_locator=d["result_locator"])),
    ("invalid_locator", lambda d: d.update(analysis_policy_locator=d["result_locator"])),
    ("invalid_locator", lambda d: d.update(result_locator=d["analysis_policy_locator"])),
    ("invalid_integrity", lambda d: d.update(integrity={"key_id": "nope"})),
]


@pytest.mark.parametrize(("code", "mutate"), FINDING_MUTATIONS)
def test_finding_closed_parsing(code: str, mutate: Callable[[dict[str, Any]], Any]) -> None:
    data = _finding_fixture().to_dict()
    mutate(data)
    _raises(code, Finding.from_dict, data)


def test_finding_rejects_non_objects_and_unsorted_evidence() -> None:
    _raises("invalid_type", Finding.from_dict, [])
    _raises("invalid_type", Finding.from_dict, {1: "x"})
    data = _restatement_finding().to_dict()
    data["evidence_locators"] = list(reversed(data["evidence_locators"]))
    _raises("unsorted", Finding.from_dict, data)


def test_finding_construction_enforces_restatement_blocking() -> None:
    restated = _restatement_finding()
    _raises("mutation_blocked_mismatch", dataclasses.replace, restated, mutation_recommendation_blocked=False)
    _raises("invalid_type", dataclasses.replace, restated, evidence_locators=None)
    _raises("invalid_locator", dataclasses.replace, restated, evidence_locators=("x",))
    as_list = dataclasses.replace(restated, evidence_locators=list(restated.evidence_locators))
    assert as_list == restated and isinstance(as_list.evidence_locators, tuple)


FOREIGN_EVIDENCE = [
    _loc("smart_ads/gate2_approval_receipt/v1", "9"),
    _loc(LANDING_TYPE, "9"),
    _loc(EXECUTION_TYPE, "9"),
    _loc(POLICY_TYPE, "9"),
]


@pytest.mark.parametrize("foreign", FOREIGN_EVIDENCE, ids=lambda loc: loc.artifact_type)
def test_evidence_locator_types_are_closed(foreign: ArtifactLocator) -> None:
    finding = _finding_fixture()
    _raises("invalid_locator", dataclasses.replace, finding, evidence_locators=(foreign,))
    data = finding.to_dict()
    data["evidence_locators"] = [foreign.to_dict()]
    _raises("invalid_locator", Finding.from_dict, data)


def test_finding_class_constants_describe_the_wire_shape() -> None:
    finding = _finding_fixture()
    assert Finding.SCHEMA == FINDING_TYPE
    assert Finding.CORE_KEYS == frozenset(finding.to_dict())
    assert Finding.KEYS == Finding.CORE_KEYS | {"integrity"}
    assert Finding.KEYS == frozenset(_sign(finding).to_dict())
    assert Finding.P1_DOMAIN_PREFIX == "SMART-ADS:FINDING:V1\n"


# ------------------------------------------------------------------ bindings and inputs


def test_policy_must_be_the_replay_bundle_policy() -> None:
    context, evidence = _build((_waste_rule(),), _waste_rows("1000", "0"))
    other = dataclasses.replace(evidence, bundle_analysis_policy_locator=_loc(POLICY_TYPE, "f"))
    _raises("policy_locator_mismatch", evaluate_findings, context, other)


@pytest.mark.parametrize("change", [{"tenant": "tenant:t2"}, {"scope": "scope:s2"}])
def test_inventory_must_match_the_evaluation_scope(change: dict[str, str]) -> None:
    _raises("inventory_scope_mismatch", _run, (_waste_rule(),), [], inventory=_inventory(**change))


def test_metric_result_must_be_the_window_relation() -> None:
    context, evidence = _build((_waste_rule(),), _waste_rows("1000", "0"))
    scalar = dataclasses.replace(context, metrics_result_key="aaa:extra")
    _raises("result_columns_mismatch", evaluate_findings, scalar, evidence)
    with pytest.raises(ResultSetMismatchError) as info:
        evaluate_findings(dataclasses.replace(context, metrics_result_key="metrics:none"), evidence)
    assert info.value.code == "unknown_result_key"
    columns = [dict(column) for column in COLUMNS]
    columns[-1]["nullable"] = False
    _raises("result_columns_mismatch", _run, (_waste_rule(),), [], columns=columns)


def _patched(row: list[dict[str, Any]], index: int, cell: dict[str, Any]) -> list[dict[str, Any]]:
    return [cell if position == index else original for position, original in enumerate(row)]


SPEND_ROW = _mrow(R0, W3[0], W3[1], SPEND, "1000")
METRIC_ROW_CASES = [
    ("duplicate_metric_row", _waste_rows("1000", "0") + [SPEND_ROW]),
    ("resource_not_in_inventory", [_mrow(RES[1], W3[0], W3[1], SPEND, "1")]),
    ("invalid_metric_row", [_mrow(R0, END, _day(1), SPEND, "1")]),  # reversed window
    ("invalid_metric_row", [_patched(SPEND_ROW, 9, NULL)]),  # observed without a value
    ("invalid_metric_row", [_patched(SPEND_ROW, 11, _cell("utf8", "USD"))]),  # foreign currency
    ("invalid_metric_row", [_patched(SPEND_ROW, 5, _cell("utf8", "guessed"))]),
    (
        "metric_type_mismatch",
        [_patched(_mrow(R0, W3[0], W3[1], CLICKS, "5"), 3, _cell("opaque_ref", SPEND))],
    ),
]


@pytest.mark.parametrize(("code", "rows"), METRIC_ROW_CASES)
def test_metric_row_rejections(code: str, rows: list[Any]) -> None:
    _raises(code, _run, (_waste_rule(),), rows)


def test_unverifiable_execution_propagates_the_result_set_code() -> None:
    context, evidence = _build((_waste_rule(),), _waste_rows("1000", "0"))
    partial = dataclasses.replace(
        evidence,
        resolved_results=evidence.resolved_results[1:],
        resolved_schemas=evidence.resolved_schemas[1:],
    )
    with pytest.raises(ResultSetMismatchError) as info:
        evaluate_findings(context, partial)
    assert info.value.code == "extra_result"


CONTEXT_CASES: list[tuple[str, dict[str, Any]]] = [
    ("invalid_type", {"policy": None}),
    ("invalid_type", {"scope": None}),
    ("invalid_type", {"inventory": None}),
    ("invalid_type", {"evaluation_instant_utc": 1}),
    ("invalid_grammar", {"evaluation_instant_utc": "2026-11-11T00:00:00Z"}),
    ("invalid_grammar", {"window_end_date": "2026-02-30"}),
    ("invalid_type", {"window_end_date": None}),
    ("window_after_instant", {"window_end_date": "2026-11-12"}),  # instant date is 2026-11-11
    ("invalid_grammar", {"curation_anchor_date": "2026-11-31"}),
    ("invalid_type", {"curation_anchor_date": None}),
    ("invalid_type", {"curation_restatement_lookback_days": True}),
    ("invalid_type", {"curation_restatement_lookback_days": "7"}),
    ("out_of_range", {"curation_restatement_lookback_days": 0}),
    ("invalid_grammar", {"metrics_result_key": ""}),
    ("invalid_type", {"metrics_result_key": b"metrics"}),
    ("invalid_type", {"restatement_history": [object()]}),
    ("invalid_type", {"restatement_history": None}),
]


@pytest.mark.parametrize(("code", "change"), CONTEXT_CASES)
def test_context_rejections(code: str, change: dict[str, Any]) -> None:
    context, _ = _build((_waste_rule(),), [])
    _raises(code, dataclasses.replace, context, **change)


EVIDENCE_CASES: list[tuple[str, dict[str, Any]]] = [
    ("invalid_type", {"execution": {}}),
    ("invalid_type", {"resolved_results": [None]}),
    ("invalid_type", {"resolved_schemas": "schemas"}),
    ("invalid_locator", {"bundle_dataset_snapshot_locator": BUNDLE}),
    ("invalid_locator", {"bundle_analysis_policy_locator": SNAPSHOT}),
    ("invalid_type", {"require_signed": 1}),
]


@pytest.mark.parametrize(("code", "change"), EVIDENCE_CASES)
def test_evidence_rejections(code: str, change: dict[str, Any]) -> None:
    _, evidence = _build((_waste_rule(),), [])
    _raises(code, dataclasses.replace, evidence, **change)


@pytest.mark.parametrize(
    ("instant", "end", "allowed"),
    [
        ("2026-11-10T00:00:00.000000Z", END, True),  # same UTC date, first microsecond
        ("2026-11-10T23:59:59.999999Z", END, True),
        ("2026-11-09T23:59:59.999999Z", END, False),
        ("2026-11-11T00:00:00.000000Z", "2026-11-11", True),
        ("2026-11-11T00:00:00.000000Z", "2026-11-12", False),
    ],
)
def test_window_end_cannot_follow_the_instant_utc_date(instant: str, end: str, allowed: bool) -> None:
    context, _ = _build((_waste_rule(),), [])
    if allowed:
        moved = dataclasses.replace(context, evaluation_instant_utc=instant, window_end_date=end)
        assert moved.window_end_date == end
    else:
        _raises(
            "window_after_instant",
            dataclasses.replace,
            context,
            evaluation_instant_utc=instant,
            window_end_date=end,
        )


class _SubclassedWaste(WasteRule):
    """Passes the policy's isinstance check but is not one of the four closed rule classes."""


class _SubclassedSaturation(SaturationRule):
    """Second subclass, so the check is not tied to one rule type."""


@pytest.mark.parametrize("rule_cls", [_SubclassedWaste, _SubclassedSaturation])
def test_rule_subclass_is_a_coded_rejection_not_a_key_error(rule_cls: type) -> None:
    base = _waste_rule() if rule_cls is _SubclassedWaste else _saturation_rule()
    members = {k: v for k, v in base.items() if k != "rule_type"}
    policy = dataclasses.replace(_policy(base), rules=(rule_cls(**members),))
    _raises("invalid_type", _run, (), _waste_rows("1000", "0"), policy=policy)


def test_entry_points_reject_wrong_argument_types() -> None:
    context, evidence = _build((_waste_rule(),), [])
    _raises("invalid_type", evaluate_findings, None, evidence)
    _raises("invalid_type", evaluate_findings, context, None)
    listed = dataclasses.replace(context, restatement_history=[_landing()])
    assert isinstance(listed.restatement_history, tuple)


# ------------------------------------------------------------------ determinism and keys


def _full_scenario(**kwargs: Any) -> tuple[EvaluationContext, AnalysisEvidence]:
    prior, current = RESTATEMENT_PAIRS["value_change"]
    rules = (_waste_rule(), _saturation_rule(), _stalled_rule(), _restatement_rule())
    rows = _waste_rows("1000", "0") + _daily(_obs("1", "1", "1"))
    return _build(rules, rows, history=(prior, current), resources=RES, **kwargs)


def _payload(findings: tuple[Finding, ...]) -> bytes:
    return _jcs([finding.to_dict() for finding in findings])


def test_evaluation_is_deterministic_and_order_independent() -> None:
    context, evidence = _full_scenario()
    before = (_jcs(evidence.execution.to_dict()), context.restatement_history)
    baseline = evaluate_findings(context, evidence)
    assert _payload(evaluate_findings(context, evidence)) == _payload(baseline)
    for history in itertools.permutations(context.restatement_history):
        shuffled = dataclasses.replace(context, restatement_history=history)
        assert _payload(evaluate_findings(shuffled, evidence)) == _payload(baseline)
    reordered = dataclasses.replace(
        evidence,
        resolved_results=evidence.resolved_results[::-1],
        resolved_schemas=evidence.resolved_schemas[::-1],
    )
    assert _payload(evaluate_findings(context, reordered)) == _payload(baseline)
    inverted = dataclasses.replace(context, inventory=_inventory(tuple(reversed(RES))))
    assert _payload(evaluate_findings(inverted, evidence)) == _payload(baseline)
    assert (_jcs(evidence.execution.to_dict()), context.restatement_history) == before
    keys = [finding.finding_key for finding in baseline]
    assert len(baseline) == 10 and len(set(keys)) == len(keys)
    assert [key.encode("utf-8") for key in keys] == sorted(key.encode("utf-8") for key in keys)


def test_finding_key_depends_only_on_stable_identity() -> None:
    detected = _finding_fixture()
    inconclusive = _run((_waste_rule(),), _waste_rows("1000", "0", spend_state="provider:timeout"))[0]
    assert detected.finding_key == inconclusive.finding_key
    assert detected.finding_digest != inconclusive.finding_digest
    v2 = AnalysisPolicy.from_dict({**_policy(_waste_rule()).to_dict(), "policy_version": "2"})
    (bumped,) = _run((), _waste_rows("1000", "0"), policy=v2)
    identity = {
        "policy_id": "policy:p1",
        "policy_version": "2",
        "rule_id": "rule:waste",
        "finding_type": "waste",
        "result_key": METRICS_KEY,
        "resource_ref": R0,
        "window_start_date": _day(2),
        "window_end_date": END,
    }
    assert bumped.finding_key == "finding:" + _sha(identity) != detected.finding_key
    (renamed,) = _run((_waste_rule(rule_id="rule:waste_b"),), _waste_rows("1000", "0"))
    assert renamed.finding_key not in (detected.finding_key, bumped.finding_key)
    (wider,) = _run((_waste_rule(window=4),), _metric(R0, (_day(3), END), SPEND, "1000"))
    assert wider.finding_key == _expected_key("rule:waste", "waste", R0, _day(3), END)


# ------------------------------------------------------------------ module purity


def test_module_holds_no_numeric_literal_and_no_float() -> None:
    tree = ast.parse(Path(intelligence.__file__).read_text(encoding="utf-8"))
    numbers = {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and type(node.value) in (int, float, complex)
    }
    assert numbers <= {0, 1}
    assert not any(isinstance(node, ast.Name) and node.id == "float" for node in ast.walk(tree))
