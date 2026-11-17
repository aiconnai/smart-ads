"""Tests for smart_ads.analytics.certification (ADR-0001 sections 5.6, 6.4, 7).

Self-contained like the T3 test split: the scenario builders are local. Expected digests and
locators are recomputed with plain `json` + `hashlib` (all values are ASCII, so sorted-key
compact JSON is the RFC 8785 form).
"""
from __future__ import annotations

import ast
import base64
import dataclasses
import datetime
import functools
import hashlib
import itertools
import json
from pathlib import Path
from typing import Any, Callable

import pytest

from smart_ads.analytics import certification, intelligence
from smart_ads.analytics.certification import (
    AnalyticalCertificationRecord,
    AttestedCertificationInput,
    build_certification_record,
    verify_certification_record,
)
from smart_ads.analytics.formulas import (
    FORMULA_ERROR_CODES,
    CertificationInput,
    DerivedCertificationStatus,
    FormulaGraphError,
)
from smart_ads.analytics.intelligence import (
    INTELLIGENCE_ERROR_CODES,
    METRIC_WINDOW_COLUMNS,
    AnalysisEvidence,
    EvaluationContext,
    Finding,
    IntelligenceError,
    evaluate_findings,
)
from smart_ads.analytics.policy import (
    POLICY_ERROR_CODES,
    AnalysisPolicy,
    EvaluationScope,
    PolicyValidationError,
)
from smart_ads.analytics.results import (
    RESULT_SET_ERROR_CODES,
    AnalysisExecution,
    AnalysisResult,
    AnalysisResultSchema,
    CanonicalResultEntry,
    CanonicalResultSet,
    ResultSetMismatchError,
)
from smart_ads.contracts.jcs import ArtifactLocator, P1Integrity
from smart_ads.contracts.scalars import ClosedValidationError
from smart_ads.contracts.schemas import AnalyticsLandingRow, DateRange, FactKey
from smart_ads.domain.registry import ExpectedResourceInventory, ExpectedResourceKey

END = "2026-11-10"
INSTANT = "2026-11-11T00:00:00.000000Z"
METRICS_KEY = "metrics:window_states"
SPEND, CLICKS = "metric:spend_v1", "metric:clicks_v1"
FINDING_TYPE = "smart_ads/finding/v1"
RECORD_TYPE = "smart_ads/certification_record/v1"
POLICY_TYPE = "smart_ads/analysis_policy/v1"


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
        "$schema": "smart_ads/artifact_locator/v1",
        "artifact_type": artifact_type,
        "content_digest": digest,
        "serialization": "rfc8785-json",
        "store_kind": "cell_immutable_object",
        "object_ref": "cell-object:" + digest,
    }


def _raises(code: str, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> None:
    with pytest.raises(IntelligenceError) as info:
        fn(*args, **kwargs)
    assert info.value.code == code, str(info.value)


# ------------------------------------------------------------------ scenario builders

R0 = "resource:" + base64.b32encode(bytes([1]) * 32).decode("ascii").lower().rstrip("=")


def _day(back: int) -> str:
    return (datetime.date.fromisoformat(END) - datetime.timedelta(days=back)).isoformat()


def _loc(artifact_type: str, seed: str) -> ArtifactLocator:
    return ArtifactLocator.from_digest(artifact_type, "sha256:" + seed * 64)


BUNDLE = _loc("smart_ads/analysis_replay_input_bundle/v1", "a")
SNAPSHOT = _loc("smart_ads/dataset_snapshot/v1", "b")
RUN = _loc("smart_ads/migration_run_context/v1", "e")
KEY_REGISTRY = _loc("smart_ads/key_authorization_registry/v1", "c")
REGISTRY_SNAPSHOT = _loc("smart_ads/private_registry_snapshot/v1", "d")


def _unsigned_integrity() -> P1Integrity:
    return P1Integrity(key_id="key:ed25519:" + "b" * 64, key_registry_snapshot_locator=KEY_REGISTRY)


def _signed_integrity(content_digest: str) -> P1Integrity:
    signature = base64.b64encode(b"\x01" * 64).decode("ascii")
    return dataclasses.replace(
        _unsigned_integrity(), content_digest=content_digest, signature_base64=signature
    )


def _sign(artifact: Any) -> Any:
    unsigned = dataclasses.replace(artifact, integrity=_unsigned_integrity())
    return dataclasses.replace(unsigned, integrity=_signed_integrity(_sha(unsigned.to_dict())))


def _row(metric: str, value: str | None) -> list[dict[str, Any]]:
    """Observed W3 window row, or a provider `missing` row when `value` is None."""
    def cell(cell_type: str, text: str | None) -> dict[str, Any]:
        return {"_type": "null", "value": None} if text is None else {"_type": cell_type, "value": text}

    money = metric == SPEND
    numeric = (
        (None, None, None, None)
        if value is None
        else ("int64_minor_currency", value, "minor_currency", "BRL")
        if money
        else ("int64_count", value, "count", None)
    )
    presence, reason = ("observed", None) if value is not None else ("missing", "provider_omitted")
    texts = [R0, _day(2), END, metric, "provider_observation", presence, "not_applicable", reason, *numeric]
    return [cell(cell_type, text) for (_, cell_type, _), text in zip(METRIC_WINDOW_COLUMNS, texts)]


def _schema(columns: list[dict[str, Any]], kind: str) -> AnalysisResultSchema:
    return AnalysisResultSchema.from_dict(
        {"$schema": "smart_ads/analysis_result_schema/v1", "result_kind": kind, "columns": columns, "unique_key": None}
    )


METRIC_COLUMNS = [{"name": n, "cell_type": t, "nullable": b} for n, t, b in METRIC_WINDOW_COLUMNS]
EXTRA_COLUMNS = [{"name": "total", "cell_type": "int64", "nullable": False}]


def _result(key: str, rows: list[Any], schema: AnalysisResultSchema) -> AnalysisResult:
    schema_dict = schema.to_dict()
    projection = {
        "result_kind": schema_dict["result_kind"],
        "analysis_result_schema_locator": schema.locator().to_dict(),
        "columns": schema_dict["columns"],
        "rows": rows,
        "row_count": len(rows),
    }
    return AnalysisResult.from_dict(
        {
            "$schema": "smart_ads/analysis_result/v1",
            "migration_run_context_locator": RUN.to_dict(),
            "dataset_snapshot_locator": SNAPSHOT.to_dict(),
            "replay_input_bundle_locator": BUNDLE.to_dict(),
            "result_key": key,
            "result_projection": projection,
        }
    )


RULES = [
    {
        "rule_id": "rule:restatement",
        "rule_type": "restatement",
        "lookback_days": 7,
        "restatement_kinds": ["state_flip", "tombstone", "value_change"],
    },
    {"rule_id": "rule:stalled", "rule_type": "stalled_delivery", "min_consecutive_days": 3, "max_impressions": "10"},
    {
        "rule_id": "rule:waste",
        "rule_type": "waste",
        "window_days": 3,
        "spend_metric_ref": SPEND,
        "outcome_metric_ref": CLICKS,
        "min_spend_minor": "1000",
        "max_outcome_count": "0",
    },
]


def _policy(rules: list[dict[str, Any]]) -> AnalysisPolicy:
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
            "validity": {
                "valid_from_utc": "2026-01-01T00:00:00.000000Z",
                "valid_until_utc": "2027-01-01T00:00:00.000000Z",
            },
            "rules": rules,
        }
    )


def _inventory() -> ExpectedResourceInventory:
    key = ExpectedResourceKey(
        binding_ref="binding:b1", account_ref="account:a1", resource_ref=R0,
        resource_level="campaign", metric_date=END,
    )
    return ExpectedResourceInventory(
        inventory_id="inventory:i1",
        registry_snapshot_locator=REGISTRY_SNAPSHOT,
        registry_snapshot_digest=REGISTRY_SNAPSHOT.content_digest,
        tenant_ref="tenant:t1",
        binding_ref="binding:b1",
        account_ref="account:a1",
        resource_scope_ref="scope:s1",
        date_range=DateRange(start_date=_day(29), end_date=END),
        expected_resources=(key,),
    )


def _landing(raw: str, at: str) -> AnalyticsLandingRow:
    return AnalyticsLandingRow(
        fact_key=FactKey(
            binding_ref="binding:b1", account_ref="account:a1", resource_ref=R0,
            resource_level="campaign", metric_date=END, metric_semantic_ref="metric:impressions_v1",
            source_metric_ref="source-metric:provider:pipeboard.impressions:v1",
            attribution_ref="attribution:not_applicable", breakdown_signature="breakdown:none",
        ),
        value_type="int64_count", raw_numeric_value=raw, unit="count", currency=None,
        metric_origin="provider_observation", presence_status="observed", unknown_reason=None,
        calculation_status="not_applicable", collected_at_utc=at,
        source_observation_ref="observation:o1", adapter_version="adapter-1", semantic_version="semantic-1",
    )


HISTORY = (_landing("100", "2026-11-10T10:00:00.000000Z"), _landing("200", "2026-11-10T11:00:00.000000Z"))


def _build(
    *,
    rules: list[dict[str, Any]] = RULES,
    spend: str | None = "1000",
    clicks: str | None = "0",
    history: tuple[AnalyticsLandingRow, ...] = HISTORY,
    signed: bool = False,
) -> tuple[EvaluationContext, AnalysisEvidence]:
    """Default: waste detected, stalled inconclusive (no impressions), restatement detected."""
    seal: Callable[[Any], Any] = _sign if signed else (lambda artifact: artifact)
    policy = seal(_policy(rules))
    schema, extra_schema = seal(_schema(METRIC_COLUMNS, "relation")), seal(_schema(EXTRA_COLUMNS, "scalar"))
    extra = seal(_result("aaa:extra", [[{"_type": "int64", "value": "7"}]], extra_schema))
    results = (extra, seal(_result(METRICS_KEY, [_row(SPEND, spend), _row(CLICKS, clicks)], schema)))
    entries = [CanonicalResultEntry.from_result(result) for result in results]
    execution = seal(AnalysisExecution(BUNDLE, CanonicalResultSet.build(BUNDLE, entries)))
    context = EvaluationContext(
        policy=policy,
        scope=EvaluationScope("tenant:t1", "scope:s1", "campaign", "meta", "BRL"),
        evaluation_instant_utc=INSTANT,
        window_end_date=END,
        curation_restatement_lookback_days=30,
        curation_anchor_date=END,
        inventory=seal(_inventory()),
        metrics_result_key=METRICS_KEY,
        restatement_history=history,
    )
    evidence = AnalysisEvidence(
        execution=execution,
        resolved_results=results,
        resolved_schemas=(extra_schema, schema),
        bundle_dataset_snapshot_locator=SNAPSHOT,
        bundle_analysis_policy_locator=policy.locator(),
        require_signed=signed,
    )
    return context, evidence


@functools.cache
def _scenario() -> tuple[EvaluationContext, AnalysisEvidence, tuple[Finding, ...]]:
    context, evidence = _build()
    return context, evidence, evaluate_findings(context, evidence)


def _attested(status: str, origin: str = "derived_input", validated: bool = False) -> AttestedCertificationInput:
    return AttestedCertificationInput(
        CertificationInput(DerivedCertificationStatus(status), origin), validated  # type: ignore[arg-type]
    )


VERIFIED_INPUTS = [_attested("VERIFIED", "phase1_7b_base")]


def _record(inputs: list[AttestedCertificationInput] = VERIFIED_INPUTS) -> AnalyticalCertificationRecord:
    context, evidence, findings = _scenario()
    return build_certification_record(context, evidence, findings, inputs)


def _output_digest(evidence: AnalysisEvidence) -> str:
    preimage = evidence.execution.canonical_result_set.to_dict()
    del preimage["canonical_result_digest"]
    return _sha(preimage)


# Real evaluator scenarios by finding set: (_build arguments, sorted (type, status) it yields).
# "inconclusive" has no impressions rows for R0 at all and no clicks row, so both rules are
# inconclusive; "mixed" is the default scenario.
FINDING_SETS: dict[str, tuple[dict[str, Any], list[tuple[str, str]]]] = {
    "none": ({"rules": RULES[2:], "spend": "999"}, []),
    "detected": ({"rules": RULES[2:]}, [("waste", "detected")]),
    "inconclusive": (
        {"rules": RULES[1:], "clicks": None},
        [("stalled_delivery", "inconclusive"), ("waste", "inconclusive")],
    ),
    "mixed": (
        {},
        [("restatement", "detected"), ("stalled_delivery", "inconclusive"), ("waste", "detected")],
    ),
    "inconclusive_not_first": (
        {"rules": sorted([{**RULES[1], "rule_id": "rule:s"}, RULES[2]], key=lambda r: r["rule_id"].encode())},
        [("stalled_delivery", "inconclusive"), ("waste", "detected")],
    ),
}
# Evaluator (finding_key) order of each set's statuses: a cap that only looked at the first
# finding would miss "inconclusive_not_first".
FINDING_ORDER: dict[str, list[str]] = {
    "none": [],
    "detected": ["detected"],
    "inconclusive": ["inconclusive", "inconclusive"],
    "mixed": ["inconclusive", "detected", "detected"],
    "inconclusive_not_first": ["detected", "inconclusive"],
}


@functools.cache
def _set_scenario(name: str) -> tuple[EvaluationContext, AnalysisEvidence, tuple[Finding, ...]]:
    context, evidence = _build(**FINDING_SETS[name][0])
    return context, evidence, evaluate_findings(context, evidence)


def _certify(name: str, inputs: list[AttestedCertificationInput]) -> AnalyticalCertificationRecord:
    context, evidence, findings = _set_scenario(name)
    return build_certification_record(context, evidence, findings, inputs)


# ------------------------------------------------------------------ module boundary


def test_module_boundary_and_public_api() -> None:
    assert sorted(certification.__all__) == sorted(
        [
            "CERTIFICATION_RECORD_SCHEMA", "AnalyticalCertificationRecord", "AttestedCertificationInput",
            "build_certification_record", "verify_certification_record",
        ]
    )
    assert "derive_certification_status" not in vars(certification)
    for name in certification.__all__:
        assert not hasattr(intelligence, name), name  # intelligence never re-exports it
    tree = ast.parse(Path(intelligence.__file__).read_text(encoding="utf-8"))
    imported = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    assert "smart_ads.analytics.certification" not in imported


def test_record_class_constants_describe_the_wire_shape() -> None:
    record = _record()
    assert AnalyticalCertificationRecord.SCHEMA == RECORD_TYPE
    assert AnalyticalCertificationRecord.CORE_KEYS == frozenset(record.to_dict())
    assert AnalyticalCertificationRecord.KEYS == AnalyticalCertificationRecord.CORE_KEYS | {"integrity"}
    assert AnalyticalCertificationRecord.KEYS == frozenset(_sign(record).to_dict())
    assert AnalyticalCertificationRecord.P1_DOMAIN_PREFIX == "SMART-ADS:CERTIFICATION:V1\n"


# ------------------------------------------------------------------ certification status

RANK = ["BLOCKED", "UNRECONCILED", "UNAVAILABLE", "DEGRADED", "VERIFIED"]
ALLOWED_INPUTS = [
    (status, origin, validated)
    for status in RANK
    for origin in ("phase1_7b_base", "derived_input")
    for validated in (False, True)
    if not (status == "DEGRADED" and origin == "phase1_7b_base")
]


@pytest.mark.parametrize(
    "specs",
    [(spec,) for spec in ALLOWED_INPUTS] + list(itertools.product(ALLOWED_INPUTS, repeat=2)),
)
def test_certification_status_is_the_minimum_with_constrained_degraded(
    specs: tuple[tuple[str, str, bool], ...]
) -> None:
    inputs = [_attested(*spec) for spec in specs]
    expected = min((spec[0] for spec in specs), key=RANK.index)
    validated_degraded = any(spec[0] == "DEGRADED" and spec[2] for spec in specs)
    if expected == "DEGRADED" and not validated_degraded:
        _raises("degraded_not_permitted", _certify, "detected", inputs)
        _raises("degraded_not_permitted", _record, inputs)
        return
    capped = min(expected, CAP, key=RANK.index)  # the default scenario has an inconclusive finding
    for order in (inputs, list(reversed(inputs))):
        assert _certify("detected", order).derived_certification_status is DerivedCertificationStatus(expected)
        assert _record(order).derived_certification_status is DerivedCertificationStatus(capped)


def test_certification_status_rejections() -> None:
    with pytest.raises(FormulaGraphError) as formula_error:
        CertificationInput(DerivedCertificationStatus.DEGRADED, "phase1_7b_base")
    assert formula_error.value.code == "degraded_from_phase1_7b"
    with pytest.raises(FormulaGraphError) as formula_error:
        _record([])
    assert formula_error.value.code == "empty_certification_inputs"
    verified = CertificationInput(DerivedCertificationStatus.VERIFIED, "derived_input")
    _raises("invalid_type", AttestedCertificationInput, "VERIFIED", True)
    _raises("invalid_type", AttestedCertificationInput, verified, 1)
    _raises("invalid_type", _record, "VERIFIED")
    _raises("invalid_type", _record, [verified])


def test_certification_record_is_independent_of_input_order() -> None:
    inputs = [_attested("VERIFIED"), _attested("UNAVAILABLE", "phase1_7b_base"), _attested("DEGRADED", validated=True)]
    records = {_jcs(_record(list(order)).to_dict()) for order in itertools.permutations(inputs)}
    assert len(records) == 1


# ------------------------------------------------------------------ build


def test_certification_record_binds_exact_findings_and_output() -> None:
    _, evidence, findings = _scenario()
    verdicts = sorted((f.finding_type, f.finding_status) for f in findings)
    assert verdicts == [("restatement", "detected"), ("stalled_delivery", "inconclusive"), ("waste", "detected")]
    record = _record()
    locators = sorted((_locator_dict(FINDING_TYPE, f.to_dict()) for f in findings), key=_jcs)
    assert record.to_dict() == {
        "$schema": RECORD_TYPE,
        "finding_locators": locators,
        "derived_certification_status": "UNAVAILABLE",  # VERIFIED inputs, capped: stalled is inconclusive
        "mutation_recommendations_blocked": True,
        "output_digest": _output_digest(evidence),
    }
    assert record.locator().to_dict() == _locator_dict(RECORD_TYPE, record.to_dict())


@pytest.mark.parametrize(
    ("spend", "clicks", "count", "blocked"),
    [("999", "0", 0, False), ("1000", "0", 1, False), ("1000", None, 1, True)],
)
def test_record_blocks_only_when_a_finding_blocks(
    spend: str, clicks: str | None, count: int, blocked: bool
) -> None:
    context, evidence = _build(rules=RULES[2:], spend=spend, clicks=clicks)
    findings = evaluate_findings(context, evidence)
    record = build_certification_record(context, evidence, findings, VERIFIED_INPUTS)
    assert len(record.finding_locators) == count
    assert record.mutation_recommendations_blocked is blocked
    assert record.output_digest == _output_digest(evidence)


@pytest.mark.parametrize("variant", ["drop", "reverse", "foreign", "extra"])
def test_record_rejects_findings_that_differ_from_recomputation(variant: str) -> None:
    context, evidence, findings = _scenario()
    foreign_context, foreign_evidence = _build(rules=[{**RULES[2], "rule_id": "rule:other"}])
    foreign = evaluate_findings(foreign_context, foreign_evidence)
    supplied = {
        "drop": findings[1:],
        "reverse": tuple(reversed(findings)),
        "foreign": foreign,
        "extra": findings + foreign,
    }[variant]
    _raises("findings_mismatch", build_certification_record, context, evidence, supplied, VERIFIED_INPUTS)


def test_record_degraded_requires_an_independently_validated_degraded_input() -> None:
    _raises("degraded_not_permitted", _record, [_attested("DEGRADED"), _attested("VERIFIED")])
    _raises("degraded_not_permitted", _certify, "detected", [_attested("DEGRADED"), _attested("VERIFIED")])
    admitted = [_attested("DEGRADED", validated=True), _attested("VERIFIED")]
    assert _certify("detected", admitted).to_dict()["derived_certification_status"] == "DEGRADED"
    assert _record(admitted).to_dict()["derived_certification_status"] == "UNAVAILABLE"  # capped


def test_signed_certification_path() -> None:
    context, evidence = _build(signed=True)
    findings = evaluate_findings(context, evidence)
    _raises("unsigned_artifact", build_certification_record, context, evidence, findings, VERIFIED_INPUTS)
    sealed = tuple(_sign(finding) for finding in findings)
    record = build_certification_record(
        context, evidence, sealed, VERIFIED_INPUTS, integrity=_unsigned_integrity()
    )
    assert record.to_dict()["finding_locators"] == sorted(
        (_locator_dict(FINDING_TYPE, f.to_dict()) for f in sealed), key=_jcs
    )
    # VERIFIED inputs, capped: the signed mixed scenario has an inconclusive stalled finding.
    assert record.to_dict()["derived_certification_status"] == "UNAVAILABLE"
    final = _sign(record)
    assert AnalyticalCertificationRecord.from_dict(final.to_dict(), require_signed=True) == final
    assert verify_certification_record(final, context, evidence, sealed, VERIFIED_INPUTS) == final
    _raises("unsigned_artifact", verify_certification_record, record, context, evidence, sealed, VERIFIED_INPUTS)


def test_build_rejects_wrong_argument_types() -> None:
    context, evidence, _ = _scenario()
    _raises("invalid_type", build_certification_record, context, evidence, [None], VERIFIED_INPUTS)
    _raises("invalid_type", build_certification_record, None, evidence, [], VERIFIED_INPUTS)


# ------------------------------------------------------------------ verify


def test_verify_accepts_exactly_the_recomputed_record() -> None:
    context, evidence, findings = _scenario()
    record = _record()
    assert verify_certification_record(record, context, evidence, findings, VERIFIED_INPUTS) is record
    parsed = AnalyticalCertificationRecord.from_dict(record.to_dict())
    assert verify_certification_record(parsed, context, evidence, list(findings), VERIFIED_INPUTS) == record


def _tampered(change: dict[str, Any]) -> AnalyticalCertificationRecord:
    return AnalyticalCertificationRecord.from_dict({**_record().to_dict(), **change})


@pytest.mark.parametrize(
    "change",
    [
        {"mutation_recommendations_blocked": False},  # certifies a restatement but does not block
        {"derived_certification_status": "VERIFIED"},  # the inputs' status, above the cap
        {"derived_certification_status": "BLOCKED"},
        {"output_digest": "sha256:" + "0" * 64},
    ],
    ids=["unblocked_restatement", "status", "status_below_cap", "output_digest"],
)
def test_verify_rejects_a_record_that_differs_from_recomputation(change: dict[str, Any]) -> None:
    context, evidence, findings = _scenario()
    record = _tampered(change)
    _raises("record_mismatch", verify_certification_record, record, context, evidence, findings, VERIFIED_INPUTS)


def test_verify_rejects_dropped_findings_and_other_inputs() -> None:
    context, evidence, findings = _scenario()
    record = _record()
    dropped = _tampered({"finding_locators": record.to_dict()["finding_locators"][1:]})
    _raises("record_mismatch", verify_certification_record, dropped, context, evidence, findings, VERIFIED_INPUTS)
    _raises("findings_mismatch", verify_certification_record, record, context, evidence, findings[1:], VERIFIED_INPUTS)
    unreconciled = [_attested("UNRECONCILED")]  # DEGRADED inputs now cap to this same record
    _raises("record_mismatch", verify_certification_record, record, context, evidence, findings, unreconciled)
    clean_context, clean_evidence, clean_findings = _set_scenario("detected")
    clean = _certify("detected", VERIFIED_INPUTS)
    degraded = [_attested("DEGRADED", validated=True)]
    _raises(
        "record_mismatch", verify_certification_record, clean, clean_context, clean_evidence, clean_findings, degraded
    )
    _raises("invalid_type", verify_certification_record, record.to_dict(), context, evidence, findings, VERIFIED_INPUTS)
    _raises("invalid_type", verify_certification_record, record, context, None, findings, VERIFIED_INPUTS)


# ------------------------------------------------------------------ P1 by hand and closed parsing


def _strip_signature(envelope: dict[str, Any]) -> dict[str, Any]:
    integrity = {
        key: value
        for key, value in envelope["integrity"].items()
        if key not in ("content_digest", "signature_base64")
    }
    return {**envelope, "integrity": integrity}


def test_record_p1_preimage_digest_and_locator_by_hand() -> None:
    record = _record()
    _raises("missing_member", record.p1_preimage)
    _raises("missing_member", record.p1_content_digest)
    unsigned = dataclasses.replace(record, integrity=_unsigned_integrity())
    assert unsigned.p1_preimage() == unsigned.to_dict()
    assert unsigned.p1_content_digest() == _sha(unsigned.to_dict())
    envelope = _sign(record).to_dict()
    assert _sign(record).p1_preimage() == _strip_signature(envelope)
    assert _sign(record).p1_content_digest() == _sha(_strip_signature(envelope))
    assert envelope["integrity"]["content_digest"] == _sha(_strip_signature(envelope))
    assert _sign(record).locator().to_dict() == _locator_dict(RECORD_TYPE, envelope)
    bad = _signed_integrity("sha256:" + "0" * 64)
    _raises("content_digest_mismatch", dataclasses.replace, unsigned, integrity=bad)
    _raises("invalid_integrity", dataclasses.replace, record, integrity="integrity")


def test_record_round_trip() -> None:
    record = _record()
    assert AnalyticalCertificationRecord.from_dict(record.to_dict()) == record
    _raises("missing_member", AnalyticalCertificationRecord.from_dict, record.to_dict(), require_signed=True)


# ------------------------------------------------------------------ inconclusive findings cap the status
#
# Analytical policy extension decided by the repo owner (ADR-0001 neither requires nor forbids
# it): when any recomputed finding is inconclusive, the record status is
# min(status from the attested inputs, UNAVAILABLE). The oracles restate that rule and the
# unchanged blocking rule here instead of importing them from the code.

CAP = "UNAVAILABLE"
ATTESTED_STATUSES: dict[str, list[AttestedCertificationInput]] = {
    "BLOCKED": [_attested("BLOCKED", "phase1_7b_base"), _attested("VERIFIED")],
    "UNRECONCILED": [_attested("UNRECONCILED")],
    "UNAVAILABLE": [_attested("UNAVAILABLE", "phase1_7b_base", True)],
    "DEGRADED": [_attested("DEGRADED", validated=True), _attested("VERIFIED", "phase1_7b_base")],
    "VERIFIED": VERIFIED_INPUTS,
}
CAP_CASES = list(itertools.product(ATTESTED_STATUSES, FINDING_SETS))


def _oracle_status(attested: str, verdicts: list[tuple[str, str]]) -> str:
    if any(status == "inconclusive" for _, status in verdicts):
        return min(attested, CAP, key=RANK.index)
    return attested


def _oracle_blocked(verdicts: list[tuple[str, str]]) -> bool:
    """Today's rule, untouched by the cap: a restatement or an inconclusive finding blocks."""
    return any(kind == "restatement" or status == "inconclusive" for kind, status in verdicts)


def _hand_record(name: str, status: str) -> dict[str, Any]:
    """The record envelope for finding set `name` and `status`, built with json + hashlib."""
    _, evidence, findings = _set_scenario(name)
    return {
        "$schema": RECORD_TYPE,
        "finding_locators": sorted((_locator_dict(FINDING_TYPE, f.to_dict()) for f in findings), key=_jcs),
        "derived_certification_status": status,
        "mutation_recommendations_blocked": _oracle_blocked(FINDING_SETS[name][1]),
        "output_digest": _output_digest(evidence),
    }


def test_finding_sets_come_from_the_evaluator() -> None:
    for name, (_, verdicts) in FINDING_SETS.items():
        findings = _set_scenario(name)[2]
        assert sorted((f.finding_type, f.finding_status) for f in findings) == verdicts, name
        assert [f.finding_status for f in findings] == FINDING_ORDER[name], name
    assert FINDING_ORDER.keys() == FINDING_SETS.keys()
    blocked = [_oracle_blocked(FINDING_SETS[name][1]) for name in FINDING_SETS]
    assert blocked == [False, False, True, True, True]


@pytest.mark.parametrize(("attested", "finding_set"), CAP_CASES)
def test_inconclusive_finding_caps_the_status_at_unavailable(attested: str, finding_set: str) -> None:
    context, evidence, findings = _set_scenario(finding_set)
    verdicts = FINDING_SETS[finding_set][1]
    inputs = ATTESTED_STATUSES[attested]
    record = build_certification_record(context, evidence, findings, inputs)
    assert record.derived_certification_status is DerivedCertificationStatus(_oracle_status(attested, verdicts))
    assert record.mutation_recommendations_blocked is _oracle_blocked(verdicts)
    assert verify_certification_record(record, context, evidence, findings, inputs) is record
    signed = _sign(record)
    assert verify_certification_record(signed, context, evidence, findings, inputs) is signed


@pytest.mark.parametrize(("attested", "finding_set"), CAP_CASES)
def test_cap_moves_preimage_digest_and_locator_exactly_when_the_status_moves(
    attested: str, finding_set: str
) -> None:
    capped = _oracle_status(attested, FINDING_SETS[finding_set][1])
    record = _certify(finding_set, ATTESTED_STATUSES[attested])
    uncapped_wire, capped_wire = _hand_record(finding_set, attested), _hand_record(finding_set, capped)
    assert record.to_dict() == capped_wire
    unsigned = dataclasses.replace(record, integrity=_unsigned_integrity())
    block = _unsigned_integrity().to_dict()
    assert unsigned.p1_preimage() == {**capped_wire, "integrity": block}
    digest = hashlib.sha256(json.dumps({**capped_wire, "integrity": block}, sort_keys=True,
                                       separators=(",", ":")).encode("ascii")).hexdigest()
    assert unsigned.p1_content_digest() == "sha256:" + digest
    locator = record.locator().to_dict()
    assert locator == _locator_dict(RECORD_TYPE, capped_wire)
    unchanged = capped == attested
    assert (unsigned.p1_content_digest() == _sha({**uncapped_wire, "integrity": block})) is unchanged
    assert (locator == _locator_dict(RECORD_TYPE, uncapped_wire)) is unchanged
    if finding_set in ("none", "detected"):  # byte-identical to the record before the cap existed
        assert unchanged and _jcs(record.to_dict()) == _jcs(uncapped_wire)


@pytest.mark.parametrize("claimed", RANK)
@pytest.mark.parametrize(("attested", "finding_set"), CAP_CASES)
def test_verify_admits_only_the_capped_status(attested: str, finding_set: str, claimed: str) -> None:
    context, evidence, findings = _set_scenario(finding_set)
    inputs = ATTESTED_STATUSES[attested]
    built = build_certification_record(context, evidence, findings, inputs)
    forged = _sign(
        AnalyticalCertificationRecord.from_dict({**built.to_dict(), "derived_certification_status": claimed})
    )
    assert forged.to_dict()["integrity"]["content_digest"] == _sha(_strip_signature(forged.to_dict()))
    if claimed == _oracle_status(attested, FINDING_SETS[finding_set][1]):
        assert verify_certification_record(forged, context, evidence, findings, inputs) is forged
        return
    _raises("record_mismatch", verify_certification_record, forged, context, evidence, findings, inputs)
    unsigned_forged = {k: v for k, v in forged.to_dict().items() if k != "integrity"}
    assert build_certification_record(context, evidence, findings, inputs).to_dict() != unsigned_forged


@pytest.mark.parametrize("finding_set", ["inconclusive", "mixed", "inconclusive_not_first"])
def test_degraded_admission_still_raises_when_the_cap_would_lower_the_status(finding_set: str) -> None:
    context, evidence, findings = _set_scenario(finding_set)
    capped = _certify(finding_set, ATTESTED_STATUSES["UNAVAILABLE"])
    for inputs in (
        [_attested("DEGRADED")],
        [_attested("DEGRADED"), _attested("VERIFIED", validated=True)],
        [_attested("DEGRADED", "derived_input", False), _attested("VERIFIED", "phase1_7b_base", True)],
    ):
        _raises("degraded_not_permitted", build_certification_record, context, evidence, findings, inputs)
        _raises("degraded_not_permitted", verify_certification_record, capped, context, evidence, findings, inputs)
    admitted = _certify(finding_set, [_attested("DEGRADED", validated=True)])
    assert admitted.to_dict() == capped.to_dict()


RECORD_MUTATIONS: list[tuple[str, Callable[[dict[str, Any]], Any]]] = [
    ("unknown_member", lambda d: d.update(extra="x")),
    ("missing_member", lambda d: d.pop("output_digest")),
    ("schema_mismatch", lambda d: d.update({"$schema": "smart_ads/certification_7b_record/v1"})),
    ("unknown_value", lambda d: d.update(derived_certification_status="GOOD")),
    ("invalid_type", lambda d: d.update(derived_certification_status=4)),
    ("invalid_type", lambda d: d.update(mutation_recommendations_blocked=1)),
    ("invalid_type", lambda d: d.update(finding_locators=tuple(d["finding_locators"]))),
    ("duplicate", lambda d: d.update(finding_locators=d["finding_locators"] * 2)),
    ("unsorted", lambda d: d.update(finding_locators=list(reversed(d["finding_locators"])))),
    ("invalid_locator", lambda d: d.update(finding_locators=[_locator_dict(POLICY_TYPE, {})])),
    ("invalid_grammar", lambda d: d.update(output_digest="sha256:XYZ")),
    ("invalid_type", lambda d: d.update(output_digest=5)),
    ("mutation_blocked_mismatch", lambda d: d.update(finding_locators=[])),
]


@pytest.mark.parametrize(("code", "mutate"), RECORD_MUTATIONS)
def test_record_closed_parsing(code: str, mutate: Callable[[dict[str, Any]], Any]) -> None:
    data = _record().to_dict()
    mutate(data)
    _raises(code, AnalyticalCertificationRecord.from_dict, data)


def test_record_rejects_non_objects_and_bad_members() -> None:
    _raises("invalid_type", AnalyticalCertificationRecord.from_dict, "record")
    _raises("invalid_type", AnalyticalCertificationRecord.from_dict, {None: 1})
    record = _record()
    _raises("invalid_type", dataclasses.replace, record, derived_certification_status="VERIFIED")
    _raises("invalid_type", dataclasses.replace, record, finding_locators=None)


# ------------------------------------------------------------------ re-validation at the seam
#
# Supplied findings, the record and the attested inputs cross the seam too: one rebound after
# construction (object.__setattr__) is rejected with a closed code, never a bare exception.

CODE_SETS: dict[type, frozenset[str]] = {
    IntelligenceError: INTELLIGENCE_ERROR_CODES,
    PolicyValidationError: POLICY_ERROR_CODES,
    ResultSetMismatchError: RESULT_SET_ERROR_CODES,
    FormulaGraphError: FORMULA_ERROR_CODES,
}


def _tamper(target: Any, field: str, value: Any) -> None:
    object.__setattr__(target, field, value)


def _coded(call: Callable[[], Any]) -> Any:
    """The call's result, or (error type, code) of a closed coded rejection; anything else escapes."""
    try:
        return call()
    except ClosedValidationError as exc:
        assert type(exc) in CODE_SETS, repr(exc)
        assert exc.code in CODE_SETS[type(exc)], repr(exc)  # type: ignore[attr-defined]
        return type(exc), exc.code  # type: ignore[attr-defined]


_Supplied = tuple[tuple[Finding, ...], AnalyticalCertificationRecord, list[AttestedCertificationInput]]


def _fresh_supplied() -> _Supplied:
    """Private copies (tampering mutates in place) of the scenario's findings, record and input."""
    _, _, findings = _scenario()
    record = AnalyticalCertificationRecord.from_dict(_record().to_dict())
    return tuple(Finding.from_dict(f.to_dict()) for f in findings), record, [_attested("VERIFIED", "phase1_7b_base")]


def _outcomes(findings: Any, record: Any, inputs: Any) -> tuple[Any, Any]:
    """build / verify over the shared valid scenario, each as record bytes or a coded rejection."""
    context, evidence, _ = _scenario()
    return (
        _coded(lambda: _jcs(build_certification_record(context, evidence, findings, inputs).to_dict())),
        _coded(lambda: _jcs(verify_certification_record(record, context, evidence, findings, inputs).to_dict())),
    )


SUPPLIED_TARGETS: dict[str, tuple[type, Callable[..., Any], Callable[..., _Supplied]]] = {
    "finding": (Finding, lambda f, r, i: f[0], lambda f, r, i, new: ((new, *f[1:]), r, i)),
    "record": (AnalyticalCertificationRecord, lambda f, r, i: r, lambda f, r, i, new: (f, new, i)),
    "attested_input": (AttestedCertificationInput, lambda f, r, i: i[0], lambda f, r, i, new: (f, r, [new])),
    "certification_input": (
        CertificationInput,
        lambda f, r, i: i[0].certification_input,
        lambda f, r, i, new: (f, r, [AttestedCertificationInput(new, i[0].independently_validated)]),
    ),
}


@pytest.mark.parametrize(
    ("error", "code", "target", "field", "value", "verify_only"),
    [
        pytest.param(IntelligenceError, "invalid_type", "finding", "integrity", object(), False, id="finding-integrity"),
        pytest.param(IntelligenceError, "unknown_value", "finding", "finding_status", "maybe", False, id="finding-status"),
        pytest.param(IntelligenceError, "invalid_type", "record", "integrity", object(), True, id="record-integrity"),
        pytest.param(IntelligenceError, "invalid_type", "record", "finding_locators", "abc", True, id="record-locators"),
        pytest.param(
            IntelligenceError, "invalid_type", "attested_input", "independently_validated", 1, False, id="attested-flag"
        ),
        pytest.param(
            FormulaGraphError, "invalid_certification_status", "certification_input", "status", "VERIFIED", False,
            id="input-status",
        ),
    ],
)
def test_tampered_supplied_object_is_rejected_with_its_code(
    error: type, code: str, target: str, field: str, value: Any, verify_only: bool
) -> None:
    supplied = _fresh_supplied()
    _tamper(SUPPLIED_TARGETS[target][1](*supplied), field, value)
    build, verify = _outcomes(*supplied)
    assert verify == (error, code)
    assert build == ((_jcs(_record().to_dict())) if verify_only else (error, code))


def test_tampered_validation_flag_cannot_admit_degraded() -> None:
    _raises("degraded_not_permitted", _record, [_attested("DEGRADED")])
    inputs = [_attested("DEGRADED")]
    _tamper(inputs[0], "independently_validated", 1)  # truthy, but not the bool True
    _raises("invalid_type", _record, inputs)


def test_policy_emptied_after_construction_cannot_certify_nothing() -> None:
    # Reviewer reproduction: this used to give a VERIFIED, unblocked record over zero findings.
    context, evidence = _build()
    _tamper(context.policy, "rules", ())
    evidence = dataclasses.replace(evidence, bundle_analysis_policy_locator=context.policy.locator())
    for call in (
        lambda: build_certification_record(context, evidence, (), VERIFIED_INPUTS),
        lambda: verify_certification_record(_record(), context, evidence, (), VERIFIED_INPUTS),
    ):
        with pytest.raises(PolicyValidationError) as info:
            call()
        assert info.value.code == "empty"


class _Str(str):
    """Equal to the original string, but not of type str."""


class _Int(int):
    """Equal to the original int, but not of type int."""


def _hostile(original: Any) -> list[Any]:
    """Wrong type, bool, None, empty, subclass, out-of-range and still-valid replacements."""
    values: list[Any] = [object(), True, None, "", "zzz", 0, -1, 1 << 64, [], ()]
    if type(original) is str:
        values += [_Str(original), original + "x"]
    if type(original) is int:
        values += [_Int(original), original + 1]
    if isinstance(original, tuple):
        values += [list(original), original * 2, (object(),)]
    return values


SUPPLIED_FIELDS = [
    (target, field.name)
    for target, (cls, _, _) in SUPPLIED_TARGETS.items()
    for field in dataclasses.fields(cls)
]


@pytest.mark.parametrize(("target", "field"), SUPPLIED_FIELDS)
def test_tampered_supplied_field_acts_like_its_constructor_or_rejects(target: str, field: str) -> None:
    """build / verify return what a legitimately built object gives, or raise a coded error."""
    _, get, put = SUPPLIED_TARGETS[target]
    baseline = _outcomes(*_fresh_supplied())
    consumed = (target != "record", True)  # build never reads the record
    for value in _hostile(getattr(get(*_fresh_supplied()), field)):
        supplied = _fresh_supplied()
        victim = get(*supplied)
        try:
            legit = dataclasses.replace(victim, **{field: value})
        except Exception:  # the constructor rejects the value (or cannot even process it)
            legit = None
        _tamper(victim, field, value)
        tampered = _outcomes(*supplied)
        expected = baseline if legit is None else _outcomes(*put(*supplied, legit))
        for got, want, reads in zip(tampered, expected, consumed, strict=True):
            if legit is None and reads:
                assert type(got) is tuple, (value, got)
            else:
                assert type(got) is tuple or got == want, (value, got, want)


# ------------------------------------------------------------------ the integrity argument of build


def _integrity_block(signed: bool) -> P1Integrity:
    """A fresh integrity block valid for the default record: unsigned, or signed over its preimage."""
    block = _sign(_record()).integrity if signed else _unsigned_integrity()
    assert block is not None
    return block


def _built_with(integrity: Any) -> Any:
    """build_certification_record with `integrity`, as record bytes or a coded rejection.

    A returned record must also parse back through AnalyticalCertificationRecord.from_dict; that
    check runs outside `_coded`, so a record its own parser rejects fails the test.
    """
    context, evidence, findings = _scenario()
    outcome = _coded(
        lambda: build_certification_record(context, evidence, findings, VERIFIED_INPUTS, integrity=integrity)
    )
    if type(outcome) is tuple:
        return outcome
    wire = outcome.to_dict()
    assert AnalyticalCertificationRecord.from_dict(wire).to_dict() == wire
    return _jcs(wire)


@pytest.mark.parametrize(
    ("signed", "field", "value"),
    [
        pytest.param(False, "key_id", None, id="key-id-none"),  # used to serialise key_id null
        pytest.param(True, "signature_base64", 0, id="signature-int"),  # used to be accepted
        pytest.param(False, "key_registry_snapshot_locator", "abc", id="registry-str"),  # bare AttributeError
    ],
)
def test_tampered_integrity_argument_is_rejected_with_a_code(signed: bool, field: str, value: Any) -> None:
    block = _integrity_block(signed)
    _tamper(block, field, value)
    assert _built_with(block) == (IntelligenceError, "invalid_integrity")


def test_integrity_argument_of_another_type_is_rejected() -> None:
    assert _built_with("integrity") == (IntelligenceError, "invalid_integrity")
    assert _built_with(_unsigned_integrity().to_dict()) == (IntelligenceError, "invalid_integrity")


@pytest.mark.parametrize("signed", [False, True])
@pytest.mark.parametrize("field", [f.name for f in dataclasses.fields(P1Integrity)])
def test_tampered_integrity_slot_acts_like_its_constructor_or_rejects(signed: bool, field: str) -> None:
    valid = _built_with(_integrity_block(signed))
    assert type(valid) is bytes
    for value in _hostile(getattr(_integrity_block(signed), field)):
        block = _integrity_block(signed)
        try:
            legit = dataclasses.replace(block, **{field: value})
        except Exception:  # the constructor rejects the value (or cannot even process it)
            legit = None
        _tamper(block, field, value)
        got = _built_with(block)
        if legit is None:
            assert type(got) is tuple, (value, got)
        else:
            assert type(got) is tuple or got == _built_with(legit), (value, got)


# ------------------------------------------------------------------ the record verify returns


class _FakeStatus:
    """Not a DerivedCertificationStatus, but serialises like one."""

    value = "VERIFIED"


class _SubLocator(ArtifactLocator):
    """An ArtifactLocator subclass: one level below the record's fields."""


class _SubIntegrity(P1Integrity):
    """A P1Integrity subclass carried in the record's integrity slot."""


def _subclassed(cls: type, value: Any) -> Any:
    return cls(**{f.name: getattr(value, f.name) for f in dataclasses.fields(value)})


def _first_locator_subclassed(record: AnalyticalCertificationRecord) -> tuple[ArtifactLocator, ...]:
    first, *rest = record.finding_locators
    return (_subclassed(_SubLocator, first), *rest)


@pytest.mark.parametrize(
    ("field", "make"),
    [
        pytest.param("derived_certification_status", lambda r: _FakeStatus(), id="status-not-enum"),
        pytest.param("finding_locators", lambda r: list(r.finding_locators), id="locators-list"),
        pytest.param("finding_locators", _first_locator_subclassed, id="locator-subclass"),
        pytest.param(
            "integrity", lambda r: _subclassed(_SubIntegrity, _unsigned_integrity()), id="integrity-subclass"
        ),
    ],
)
def test_verify_rejects_a_record_that_is_not_what_its_wire_form_parses_to(
    field: str, make: Callable[[AnalyticalCertificationRecord], Any]
) -> None:
    context, evidence, findings = _scenario()
    record = AnalyticalCertificationRecord.from_dict(_record().to_dict())
    _tamper(record, field, make(record))
    assert AnalyticalCertificationRecord.from_dict(record.to_dict()).to_dict() == record.to_dict()
    _raises("invalid_type", verify_certification_record, record, context, evidence, findings, VERIFIED_INPUTS)


def test_verify_still_returns_the_genuine_record_it_was_given() -> None:
    context, evidence, findings = _scenario()
    for record in (_record(), _sign(_record()), AnalyticalCertificationRecord.from_dict(_record().to_dict())):
        assert verify_certification_record(record, context, evidence, findings, VERIFIED_INPUTS) is record


# ------------------------------------------------------------------ a deleted evidence slot


def test_deleted_require_signed_slot_gives_the_same_code_on_every_entry_point() -> None:
    record = _record()
    calls: list[Callable[[EvaluationContext, AnalysisEvidence], Any]] = [
        evaluate_findings,
        lambda c, e: build_certification_record(c, e, _scenario()[2], VERIFIED_INPUTS),
        lambda c, e: verify_certification_record(record, c, e, _scenario()[2], VERIFIED_INPUTS),
    ]
    for call in calls:
        context, evidence = _build()
        object.__delattr__(evidence, "require_signed")
        _raises("invalid_type", call, context, evidence)


def test_module_holds_no_numeric_literal_and_no_float() -> None:
    tree = ast.parse(Path(certification.__file__).read_text(encoding="utf-8"))
    numbers = {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and type(node.value) in (int, float, complex)
    }
    assert numbers <= {0, 1}
    assert not any(isinstance(node, ast.Name) and node.id == "float" for node in ast.walk(tree))
