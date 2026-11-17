"""Derived metric formulas, exact operators, formula bundle, and certification lattice (ADR-0001 §5.6)."""
from __future__ import annotations

import base64
import copy
import hashlib
import itertools
from typing import Any

import pytest

from smart_ads.analytics.formulas import (
    FORMULA_ERROR_CODES,
    CertificationInput,
    DerivedCertificationStatus,
    DerivedMetricDefinition,
    FormulaAst,
    FormulaBundle,
    FormulaGraphError,
    combine_derived_certification,
    compute_topological_order,
    divide_count_by_count,
    divide_money_by_count,
    divide_money_by_money,
)
from smart_ads.contracts.jcs import (
    ADR_P1_DOMAIN_PREFIXES,
    ArtifactLocator,
    P1Integrity,
    canonicalize_jcs,
    p1_content_digest,
)
from smart_ads.contracts.numerics import (
    MAX_INT64,
    PHASE1_BASE_METRICS,
    PHASE1_DIMENSIONS,
    BaseMetricDefinition,
    NumericStateRow,
)
from smart_ads.contracts.scalars import ClosedValidationError
from smart_ads.contracts.schemas import validate_source_metric_ref

CLICKS = "metric:clicks_v1"
IMPRESSIONS = "metric:impressions_v1"
SPEND = "metric:spend_v1"
MBC = "DIVIDE_MONEY_BY_COUNT"
CBC = "DIVIDE_COUNT_BY_COUNT"
MBM = "DIVIDE_MONEY_BY_MONEY"
OUTPUT_TYPE = {
    MBC: "int64_minor_currency",
    CBC: "decimal_ratio",
    MBM: "decimal_ratio",
}
DEFINITION_KEYS = {
    "$schema",
    "metric_semantic_ref",
    "input_metrics",
    "formula_ast",
    "formula_digest",
}
AST_KEYS = {
    "operator",
    "numerator_metric_ref",
    "denominator_metric_ref",
    "output_value_type",
    "rounding_mode",
}
BUNDLE_KEYS = {
    "$schema",
    "base_metric_refs",
    "definitions",
    "topological_order",
    "bundle_digest",
}

# Literal RFC 8785 bytes of the ADR §5.6 example with `formula_digest` removed,
# written by hand so the digest check does not depend on the code under test.
ADR_EXAMPLE_PREIMAGE = (
    b'{"$schema":"smart_ads/derived_metric_definition/v1",'
    b'"formula_ast":{"denominator_metric_ref":"metric:clicks_v1",'
    b'"numerator_metric_ref":"metric:spend_v1",'
    b'"operator":"DIVIDE_MONEY_BY_COUNT",'
    b'"output_value_type":"int64_minor_currency",'
    b'"rounding_mode":"ROUND_HALF_UP"},'
    b'"input_metrics":["metric:clicks_v1","metric:spend_v1"],'
    b'"metric_semantic_ref":"metric:derived_cpc_v1"}'
)
ADR_EXAMPLE_DIGEST = "sha256:" + hashlib.sha256(ADR_EXAMPLE_PREIMAGE).hexdigest()


def _sha(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonicalize_jcs(value)).hexdigest()


def _utf8_sorted(values: list[str]) -> list[str]:
    return sorted(values, key=lambda s: s.encode("utf-8"))


def _defn_dict(
    ref: str,
    operator: str,
    numerator: str,
    denominator: str,
    *,
    output: str | None = None,
    rounding: str = "ROUND_HALF_UP",
    input_metrics: list[str] | None = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "$schema": "smart_ads/derived_metric_definition/v1",
        "metric_semantic_ref": ref,
        "input_metrics": (
            input_metrics
            if input_metrics is not None
            else _utf8_sorted(sorted({numerator, denominator}))
        ),
        "formula_ast": {
            "operator": operator,
            "numerator_metric_ref": numerator,
            "denominator_metric_ref": denominator,
            "output_value_type": output if output is not None else OUTPUT_TYPE.get(operator, "decimal_ratio"),
            "rounding_mode": rounding,
        },
    }
    return dict(body, formula_digest=_sha(body))


def _bundle_dict(
    definitions: list[dict[str, Any]],
    *,
    topological_order: list[str],
    base_metric_refs: list[str] | None = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "$schema": "smart_ads/formula_bundle/v1",
        "base_metric_refs": (
            base_metric_refs if base_metric_refs is not None else [CLICKS, IMPRESSIONS, SPEND]
        ),
        "definitions": definitions,
        "topological_order": topological_order,
    }
    return dict(body, bundle_digest=_sha(body))


def _ast(operator: str, numerator: str, denominator: str) -> FormulaAst:
    return FormulaAst(
        operator=operator,
        numerator_metric_ref=numerator,
        denominator_metric_ref=denominator,
        output_value_type=OUTPUT_TYPE[operator],
        rounding_mode="ROUND_HALF_UP",
    )


def _defn(ref: str, operator: str, numerator: str, denominator: str) -> DerivedMetricDefinition:
    return DerivedMetricDefinition(
        metric_semantic_ref=ref,
        formula_ast=_ast(operator, numerator, denominator),
    )


def _phase1_bases() -> tuple[Any, ...]:
    return tuple(PHASE1_BASE_METRICS[ref] for ref in (SPEND, CLICKS, IMPRESSIONS))


def _sample_definitions() -> tuple[DerivedMetricDefinition, ...]:
    return (
        _defn("metric:derived_cpc_share_v1", MBM, "metric:derived_cpc_v1", SPEND),
        _defn("metric:derived_cpc_v1", MBC, SPEND, CLICKS),
        _defn("metric:derived_ctr_v1", CBC, CLICKS, IMPRESSIONS),
    )


SAMPLE_ORDER = (
    CLICKS,
    IMPRESSIONS,
    "metric:derived_ctr_v1",
    SPEND,
    "metric:derived_cpc_v1",
    "metric:derived_cpc_share_v1",
)


def _registry_locator() -> ArtifactLocator:
    return ArtifactLocator.from_digest(
        "smart_ads/key_authorization_registry/v1", "sha256:" + ("1" * 64)
    )


# --------------------------------------------------------------------------- errors


def test_formula_graph_error_is_closed_and_typed() -> None:
    err = FormulaGraphError("cycle", "a -> b -> a")
    assert isinstance(err, ClosedValidationError)
    assert err.code == "cycle"
    assert {
        "self_reference",
        "cycle",
        "unknown_dependency",
        "duplicate_output",
        "topological_order_mismatch",
    } <= FORMULA_ERROR_CODES
    with pytest.raises(ClosedValidationError):
        FormulaGraphError("not_a_code", "x")
    with pytest.raises(ClosedValidationError):
        FormulaGraphError(None, "x")  # type: ignore[arg-type]


# --------------------------------------------------------------------------- operators


def _assert_computed(row: NumericStateRow, value_type: str, raw: str, unit: str, currency: str | None) -> None:
    assert isinstance(row, NumericStateRow)
    assert row.metric_origin == "derived_formula"
    assert row.presence_status == "not_applicable"
    assert row.calculation_status == "computed"
    assert row.unknown_reason is None
    assert row.value_type == value_type
    assert row.raw_numeric_value == raw
    assert row.unit == unit
    assert row.currency == currency


def _assert_division_by_zero(row: NumericStateRow) -> None:
    assert isinstance(row, NumericStateRow)
    assert row.metric_origin == "derived_formula"
    assert row.presence_status == "not_applicable"
    assert row.calculation_status == "division_by_zero"
    assert row.unknown_reason == "division_by_zero"
    assert (row.value_type, row.raw_numeric_value, row.unit, row.currency) == (None, None, None, None)


@pytest.mark.parametrize(
    ("numerator", "denominator", "expected"),
    [
        (0, 1, "0"),
        (0, MAX_INT64, "0"),
        (1, 2, "1"),  # 0.5 -> 1 (half-even would give 0)
        (5, 2, "3"),  # 2.5 -> 3 (half-even would give 2)
        (3, 2, "2"),
        (7, 2, "4"),
        (1, 3, "0"),
        (2, 3, "1"),
        (9, 4, "2"),
        (10, 4, "3"),
        (149, 100, "1"),
        (150, 100, "2"),
        (151, 100, "2"),
        (249, 100, "2"),
        (250, 100, "3"),
        (12345, 1, "12345"),
        (MAX_INT64, 1, str(MAX_INT64)),
        (MAX_INT64, 2, "4611686018427387904"),  # 4611686018427387903.5 -> up
        (MAX_INT64 - 1, 2, "4611686018427387903"),
        (MAX_INT64, MAX_INT64, "1"),
        (MAX_INT64 - 1, MAX_INT64, "1"),
        (1, MAX_INT64, "0"),
    ],
)
def test_divide_money_by_count_round_half_up(numerator: int, denominator: int, expected: str) -> None:
    row = divide_money_by_count(numerator, denominator, currency="BRL")
    _assert_computed(row, "int64_minor_currency", expected, "minor_currency", "BRL")
    assert 0 <= int(row.raw_numeric_value or "x") <= MAX_INT64


def test_divide_money_by_count_preserves_currency() -> None:
    row = divide_money_by_count(5, 2, currency="USD")
    _assert_computed(row, "int64_minor_currency", "3", "minor_currency", "USD")
    with pytest.raises(FormulaGraphError) as exc_info:
        divide_money_by_count(5, 2, currency="brl")
    assert exc_info.value.code == "malformed"


RATIO_CASES = [
    (0, 7, "0.000000"),
    (7, 7, "1.000000"),
    (1, 2, "0.500000"),
    (3, 2, "1.500000"),
    (5, 8, "0.625000"),
    (1, 3, "0.333333"),
    (2, 3, "0.666667"),
    (1, 6, "0.166667"),
    (1, 7, "0.142857"),
    (1, 2_000_000, "0.000001"),  # 0.0000005 -> up
    (1, 2_000_001, "0.000000"),
    (3, 2_000_000, "0.000002"),  # 0.0000015 -> up
    (5, 2_000_000, "0.000003"),  # 0.0000025 -> up (half-even would give 0.000002)
    (1, 1_600_000, "0.000001"),  # 0.000000625 -> up
    (1, MAX_INT64, "0.000000"),
    (MAX_INT64, MAX_INT64, "1.000000"),
    (MAX_INT64, 1, f"{MAX_INT64}.000000"),
    (MAX_INT64, 3, "3074457345618258602.333333"),
]


@pytest.mark.parametrize(("numerator", "denominator", "expected"), RATIO_CASES)
def test_divide_count_by_count_six_place_half_up(numerator: int, denominator: int, expected: str) -> None:
    row = divide_count_by_count(numerator, denominator)
    _assert_computed(row, "decimal_ratio", expected, "ratio", None)


@pytest.mark.parametrize(("numerator", "denominator", "expected"), RATIO_CASES)
def test_divide_money_by_money_six_place_half_up(numerator: int, denominator: int, expected: str) -> None:
    row = divide_money_by_money(
        numerator, denominator, numerator_currency="BRL", denominator_currency="BRL"
    )
    _assert_computed(row, "decimal_ratio", expected, "ratio", None)


def test_divide_money_by_money_requires_same_currency() -> None:
    for denominator in (3, 0):
        with pytest.raises(FormulaGraphError) as exc_info:
            divide_money_by_money(
                1, denominator, numerator_currency="BRL", denominator_currency="USD"
            )
        assert exc_info.value.code == "currency_mismatch"
    with pytest.raises(FormulaGraphError) as exc_info:
        divide_money_by_money(1, 3, numerator_currency="BRL", denominator_currency="br")
    assert exc_info.value.code == "malformed"


def test_division_by_zero_returns_null_division_by_zero_row() -> None:
    for numerator in (0, 1, MAX_INT64):
        _assert_division_by_zero(divide_money_by_count(numerator, 0, currency="BRL"))
        _assert_division_by_zero(divide_count_by_count(numerator, 0))
        _assert_division_by_zero(
            divide_money_by_money(
                numerator, 0, numerator_currency="BRL", denominator_currency="BRL"
            )
        )


def _call_operator(name: str, numerator: object, denominator: object) -> NumericStateRow:
    if name == MBC:
        return divide_money_by_count(numerator, denominator, currency="BRL")  # type: ignore[arg-type]
    if name == CBC:
        return divide_count_by_count(numerator, denominator)  # type: ignore[arg-type]
    return divide_money_by_money(
        numerator,  # type: ignore[arg-type]
        denominator,  # type: ignore[arg-type]
        numerator_currency="BRL",
        denominator_currency="BRL",
    )


@pytest.mark.parametrize("operator", [MBC, CBC, MBM])
@pytest.mark.parametrize(
    ("numerator", "denominator", "code"),
    [
        (True, 1, "invalid_operand"),
        (1, True, "invalid_operand"),
        (False, 1, "invalid_operand"),
        ("5", 1, "invalid_operand"),
        (1, "5", "invalid_operand"),
        (1.0, 1, "invalid_operand"),
        (1, 1.0, "invalid_operand"),
        (None, 1, "invalid_operand"),
        (-1, 1, "operand_out_of_range"),
        (1, -1, "operand_out_of_range"),
        (MAX_INT64 + 1, 1, "operand_out_of_range"),
        (1, MAX_INT64 + 1, "operand_out_of_range"),
        (-(MAX_INT64 + 1), 1, "operand_out_of_range"),
    ],
)
def test_operators_reject_non_strict_or_out_of_range_operands(
    operator: str, numerator: object, denominator: object, code: str
) -> None:
    with pytest.raises(FormulaGraphError) as exc_info:
        _call_operator(operator, numerator, denominator)
    assert exc_info.value.code == code


# --------------------------------------------------------------------------- definition


def _adr_example_dict() -> dict[str, Any]:
    return {
        "$schema": "smart_ads/derived_metric_definition/v1",
        "metric_semantic_ref": "metric:derived_cpc_v1",
        "input_metrics": ["metric:clicks_v1", "metric:spend_v1"],
        "formula_ast": {
            "operator": "DIVIDE_MONEY_BY_COUNT",
            "numerator_metric_ref": "metric:spend_v1",
            "denominator_metric_ref": "metric:clicks_v1",
            "output_value_type": "int64_minor_currency",
            "rounding_mode": "ROUND_HALF_UP",
        },
        "formula_digest": ADR_EXAMPLE_DIGEST,
    }


def test_adr_example_definition_recomputes_digest_and_source_metric_ref() -> None:
    raw = _adr_example_dict()
    snapshot = copy.deepcopy(raw)
    defn = DerivedMetricDefinition.from_dict(raw)
    assert raw == snapshot  # input never mutated
    assert DerivedMetricDefinition.SCHEMA == "smart_ads/derived_metric_definition/v1"
    assert defn.formula_digest == ADR_EXAMPLE_DIGEST
    assert defn.input_metrics == (CLICKS, SPEND)
    assert defn.source_metric_ref == "source-metric:formula:" + ADR_EXAMPLE_DIGEST
    assert validate_source_metric_ref(defn.source_metric_ref) == defn.source_metric_ref
    out = defn.to_dict()
    assert out == raw
    assert set(out) == DEFINITION_KEYS
    assert set(out["formula_ast"]) == AST_KEYS
    out["formula_digest"] = "sha256:" + "0" * 64
    out["formula_ast"]["operator"] = "X"
    assert defn.to_dict() == raw  # to_dict returns fresh copies

    built = _defn("metric:derived_cpc_v1", MBC, SPEND, CLICKS)
    assert built == defn
    assert built.formula_digest == ADR_EXAMPLE_DIGEST


def test_definition_formula_digest_preimage_is_member_removed_never_blanked() -> None:
    raw = _adr_example_dict()
    body = {k: v for k, v in raw.items() if k != "formula_digest"}
    blanked = _sha(dict(body, formula_digest=""))
    nulled = _sha(dict(body, formula_digest=None))
    for asserted in (blanked, nulled, "sha256:" + "a" * 64):
        with pytest.raises(FormulaGraphError) as exc_info:
            DerivedMetricDefinition.from_dict(dict(raw, formula_digest=asserted))
        assert exc_info.value.code == "formula_digest_mismatch"
        with pytest.raises(FormulaGraphError) as exc_info:
            DerivedMetricDefinition(
                metric_semantic_ref="metric:derived_cpc_v1",
                formula_ast=_ast(MBC, SPEND, CLICKS),
                formula_digest=asserted,
            )
        assert exc_info.value.code == "formula_digest_mismatch"
    for bad in ("", None, "sha256:" + "A" * 64, ADR_EXAMPLE_DIGEST[7:]):
        with pytest.raises(FormulaGraphError) as exc_info:
            DerivedMetricDefinition.from_dict(dict(raw, formula_digest=bad))
        assert exc_info.value.code == "malformed"


def test_definition_rejects_closed_shape_violations() -> None:
    raw = _adr_example_dict()
    cases: list[object] = [
        dict(raw, extra=1),
        {k: v for k, v in raw.items() if k != "input_metrics"},
        dict(raw, **{"$schema": "smart_ads/derived_metric_definition/v2"}),
        dict(raw, formula_ast=dict(raw["formula_ast"], scale=0)),
        dict(raw, formula_ast={k: v for k, v in raw["formula_ast"].items() if k != "rounding_mode"}),
        dict(raw, formula_ast=[]),
        dict(raw, input_metrics=tuple(raw["input_metrics"])),
        [raw],
        None,
    ]
    for case in cases:
        with pytest.raises(FormulaGraphError) as exc_info:
            DerivedMetricDefinition.from_dict(case)
        assert exc_info.value.code == "malformed"


@pytest.mark.parametrize(
    ("kwargs", "code"),
    [
        ({"ref": "metric:Derived_v1"}, "malformed"),
        ({"ref": "metric:derived_v0"}, "malformed"),
        ({"numerator": "spend_v1"}, "malformed"),
        ({"operator": "DIVIDE"}, "invalid_operator"),
        ({"operator": "divide_money_by_count"}, "invalid_operator"),
        ({"output": "decimal_ratio"}, "output_type_mismatch"),
        ({"output": "int64_count"}, "output_type_mismatch"),
        ({"operator": CBC, "numerator": CLICKS, "denominator": IMPRESSIONS, "output": "int64_count"}, "output_type_mismatch"),
        ({"operator": MBM, "numerator": SPEND, "denominator": "metric:other_spend_v1", "output": "int64_minor_currency"}, "output_type_mismatch"),
        ({"rounding": "ROUND_HALF_EVEN"}, "invalid_rounding_mode"),
        ({"rounding": "round_half_up"}, "invalid_rounding_mode"),
        ({"operator": CBC, "numerator": CLICKS, "denominator": CLICKS, "output": "decimal_ratio"}, "same_operand"),
        ({"input_metrics": [SPEND, CLICKS]}, "input_metrics_mismatch"),
        ({"input_metrics": [CLICKS]}, "input_metrics_mismatch"),
        ({"input_metrics": [CLICKS, CLICKS, SPEND]}, "input_metrics_mismatch"),
        ({"input_metrics": [CLICKS, IMPRESSIONS, SPEND]}, "input_metrics_mismatch"),
        ({"input_metrics": []}, "input_metrics_mismatch"),
        ({"input_metrics": [CLICKS, 7]}, "malformed"),
        ({"ref": SPEND}, "self_reference"),
        ({"ref": CLICKS}, "self_reference"),
    ],
)
def test_definition_rejects_signature_violations(kwargs: dict[str, Any], code: str) -> None:
    params: dict[str, Any] = {
        "ref": "metric:derived_cpc_v1",
        "operator": MBC,
        "numerator": SPEND,
        "denominator": CLICKS,
    }
    params.update(kwargs)
    raw = _defn_dict(
        params.pop("ref"),
        params.pop("operator"),
        params.pop("numerator"),
        params.pop("denominator"),
        **params,
    )
    with pytest.raises(FormulaGraphError) as exc_info:
        DerivedMetricDefinition.from_dict(raw)
    assert exc_info.value.code == code


@pytest.mark.parametrize(
    "candidate",
    [
        "metric:clicks_v1",
        "metric:a_v12",
        "metric:derived_cpc_v1",
        "metric:clicks_v0",
        "metric:Clicks_v1",
        "metric:1clicks_v1",
        "metric:clicks",
        "metric:clicks_v01",
        "source-metric:clicks_v1",
        "metric:clicks_v1\n",
        "metric:cliçks_v1",
    ],
)
def test_metric_ref_grammar_matches_base_metric_definition(candidate: str) -> None:
    def base_accepts() -> bool:
        try:
            BaseMetricDefinition(
                metric_semantic_ref=candidate,
                canonical_name="clicks",
                value_type="int64_count",
                unit="count",
                currency_rule="must_be_null",
                dimensions=PHASE1_DIMENSIONS,
                aggregation_semantics="additive_across_none",
            )
        except ClosedValidationError:
            return False
        return True

    def derived_accepts() -> bool:
        try:
            _defn(candidate, MBC, "metric:zz_money_v1", "metric:zz_count_v1")
        except FormulaGraphError as exc:
            assert exc.code == "malformed"
            return False
        return True

    assert derived_accepts() is base_accepts()


def test_definition_constructor_rejects_wrong_types() -> None:
    with pytest.raises(FormulaGraphError) as exc_info:
        DerivedMetricDefinition(
            metric_semantic_ref="metric:derived_cpc_v1",
            formula_ast=_ast(MBC, SPEND, CLICKS).to_dict(),  # type: ignore[arg-type]
        )
    assert exc_info.value.code == "malformed"
    with pytest.raises(FormulaGraphError) as exc_info:
        DerivedMetricDefinition(
            metric_semantic_ref="metric:derived_cpc_v1",
            formula_ast=_ast(MBC, SPEND, CLICKS),
            input_metrics=(SPEND, CLICKS),
        )
    assert exc_info.value.code == "input_metrics_mismatch"


# --------------------------------------------------------------------------- bundle


def test_bundle_recomputes_unique_kahn_order_with_utf8_tie_break() -> None:
    definitions = _sample_definitions()
    assert compute_topological_order((SPEND, IMPRESSIONS, CLICKS), definitions) == SAMPLE_ORDER
    bundle = FormulaBundle(base_metrics=_phase1_bases(), definitions=definitions)
    assert bundle.topological_order == SAMPLE_ORDER
    assert tuple(d.metric_semantic_ref for d in bundle.definitions) == (
        "metric:derived_cpc_share_v1",
        "metric:derived_cpc_v1",
        "metric:derived_ctr_v1",
    )
    # Declared order equal to the recomputed one is accepted verbatim.
    declared = FormulaBundle(
        base_metrics=_phase1_bases(),
        definitions=tuple(reversed(definitions)),
        topological_order=SAMPLE_ORDER,
    )
    assert declared == bundle


def test_bundle_to_dict_digest_and_round_trip() -> None:
    bundle = FormulaBundle(base_metrics=_phase1_bases(), definitions=_sample_definitions())
    assert FormulaBundle.SCHEMA == "smart_ads/formula_bundle/v1"
    assert ADR_P1_DOMAIN_PREFIXES[FormulaBundle.SCHEMA] == "SMART-ADS:FORMULA-BUNDLE:V1\n"
    out = bundle.to_dict()
    assert set(out) == BUNDLE_KEYS
    assert out["base_metric_refs"] == [CLICKS, IMPRESSIONS, SPEND]
    assert out["topological_order"] == list(SAMPLE_ORDER)
    assert [d["metric_semantic_ref"] for d in out["definitions"]] == [
        "metric:derived_cpc_share_v1",
        "metric:derived_cpc_v1",
        "metric:derived_ctr_v1",
    ]
    body = {k: v for k, v in out.items() if k != "bundle_digest"}
    assert out["bundle_digest"] == _sha(body)
    assert bundle.bundle_digest == out["bundle_digest"]

    snapshot = copy.deepcopy(out)
    parsed = FormulaBundle.from_dict(out)
    assert out == snapshot
    assert parsed == bundle
    assert parsed.to_dict() == snapshot

    mapping = bundle.source_metric_refs
    assert set(mapping) == {d.metric_semantic_ref for d in bundle.definitions}
    for defn in bundle.definitions:
        assert mapping[defn.metric_semantic_ref] == "source-metric:formula:" + defn.formula_digest
    with pytest.raises(TypeError):
        mapping["metric:x_v1"] = "y"  # type: ignore[index]


def test_bundle_rejects_tampered_digest_and_unsorted_arrays() -> None:
    out = FormulaBundle(base_metrics=_phase1_bases(), definitions=_sample_definitions()).to_dict()
    with pytest.raises(FormulaGraphError) as exc_info:
        FormulaBundle.from_dict(dict(out, bundle_digest="sha256:" + "b" * 64))
    assert exc_info.value.code == "bundle_digest_mismatch"

    unsorted_defs = _bundle_dict(list(reversed(out["definitions"])), topological_order=list(SAMPLE_ORDER))
    with pytest.raises(FormulaGraphError) as exc_info:
        FormulaBundle.from_dict(unsorted_defs)
    assert exc_info.value.code == "unsorted"

    unsorted_bases = _bundle_dict(
        out["definitions"],
        topological_order=list(SAMPLE_ORDER),
        base_metric_refs=[SPEND, CLICKS, IMPRESSIONS],
    )
    with pytest.raises(FormulaGraphError) as exc_info:
        FormulaBundle.from_dict(unsorted_bases)
    assert exc_info.value.code == "unsorted"

    for bad in (dict(out, extra=1), {k: v for k, v in out.items() if k != "topological_order"}):
        with pytest.raises(FormulaGraphError) as exc_info:
            FormulaBundle.from_dict(bad)
        assert exc_info.value.code == "malformed"


def test_bundle_rejects_dependency_outside_base_registry() -> None:
    conversions = "metric:conversions_v1"
    raw = _bundle_dict(
        [_defn_dict("metric:derived_cpa_v1", MBC, SPEND, conversions)],
        topological_order=[CLICKS, conversions, "metric:derived_cpa_v1", SPEND],
        base_metric_refs=[CLICKS, conversions, SPEND],
    )
    with pytest.raises(FormulaGraphError) as exc_info:
        FormulaBundle.from_dict(raw)
    assert exc_info.value.code == "unknown_base_metric"


@pytest.mark.parametrize(
    "definition",
    [
        _defn("metric:bad_v1", CBC, SPEND, CLICKS),
        _defn("metric:bad_v1", CBC, CLICKS, SPEND),
        _defn("metric:bad_v1", MBC, CLICKS, SPEND),
        _defn("metric:bad_v1", MBC, SPEND, SPEND.replace("spend", "other")),
        _defn("metric:bad_v1", MBM, SPEND, CLICKS),
        _defn("metric:bad_v1", MBM, SPEND, "metric:derived_ctr_v1"),
        _defn("metric:bad_v1", CBC, "metric:derived_ctr_v1", CLICKS),
    ],
)
def test_bundle_rejects_operand_signature_mismatch(definition: DerivedMetricDefinition) -> None:
    bases = _phase1_bases()
    if "metric:other_v1" in definition.input_metrics:
        bases = bases + (
            BaseMetricDefinition(
                metric_semantic_ref="metric:other_v1",
                canonical_name="other",
                value_type="decimal_ratio",
                unit="ratio",
                currency_rule="must_be_null",
                dimensions=PHASE1_DIMENSIONS,
                aggregation_semantics="non_additive",
            ),
        )
    definitions = (definition, _defn("metric:derived_ctr_v1", CBC, CLICKS, IMPRESSIONS))
    with pytest.raises(FormulaGraphError) as exc_info:
        FormulaBundle(base_metrics=bases, definitions=definitions)
    assert exc_info.value.code == "operand_type_mismatch"


# The six mandatory negative fixtures of ADR-0001 §5.6 (L1421-1424).

_CPC = "metric:derived_cpc_v1"
_A = "metric:a_v1"
_B = "metric:b_v1"
_C = "metric:c_v1"
_D = "metric:d_v1"

NEGATIVE_FIXTURES: list[tuple[str, dict[str, Any], str]] = [
    (
        "direct_self_reference",
        _bundle_dict(
            [_defn_dict(_A, MBC, _A, CLICKS)],
            topological_order=[_A, CLICKS, IMPRESSIONS, SPEND],
        ),
        "self_reference",
    ),
    (
        "two_node_cycle",
        _bundle_dict(
            [_defn_dict(_A, MBC, _B, CLICKS), _defn_dict(_B, MBC, _A, CLICKS)],
            topological_order=[_A, _B, CLICKS, IMPRESSIONS, SPEND],
        ),
        "cycle",
    ),
    (
        "three_node_cycle",
        _bundle_dict(
            [
                _defn_dict(_A, MBC, _B, CLICKS),
                _defn_dict(_B, MBC, _C, CLICKS),
                _defn_dict(_C, MBC, _A, CLICKS),
            ],
            topological_order=[_A, _B, _C, CLICKS, IMPRESSIONS, SPEND],
        ),
        "cycle",
    ),
    (
        "four_node_cycle_beside_valid_branch",
        _bundle_dict(
            [
                _defn_dict(_A, MBC, _B, CLICKS),
                _defn_dict(_B, MBC, _C, CLICKS),
                _defn_dict(_C, MBC, _D, CLICKS),
                _defn_dict(_D, MBC, _A, CLICKS),
                _defn_dict(_CPC, MBC, SPEND, CLICKS),
            ],
            topological_order=[_A, _B, _C, _D, CLICKS, IMPRESSIONS, SPEND, _CPC],
        ),
        "cycle",
    ),
    (
        "unknown_dependency",
        _bundle_dict(
            [_defn_dict(_A, MBC, "metric:ghost_v1", CLICKS)],
            topological_order=[_A, CLICKS, IMPRESSIONS, SPEND],
        ),
        "unknown_dependency",
    ),
    (
        "duplicate_output_between_definitions",
        _bundle_dict(
            [_defn_dict(_CPC, MBC, SPEND, CLICKS), _defn_dict(_CPC, MBC, SPEND, IMPRESSIONS)],
            topological_order=[CLICKS, IMPRESSIONS, SPEND, _CPC],
        ),
        "duplicate_output",
    ),
    (
        "duplicate_output_shadowing_base_metric",
        _bundle_dict(
            [_defn_dict(IMPRESSIONS, MBC, SPEND, CLICKS)],
            topological_order=[CLICKS, IMPRESSIONS, SPEND],
        ),
        "duplicate_output",
    ),
    (
        "duplicate_base_metric_ref",
        _bundle_dict(
            [_defn_dict(_CPC, MBC, SPEND, CLICKS)],
            topological_order=[CLICKS, SPEND, _CPC],
            base_metric_refs=[CLICKS, CLICKS, SPEND],
        ),
        "duplicate_output",
    ),
    (
        "topological_order_lexicographic_instead_of_kahn",
        _bundle_dict(
            [
                _defn_dict(_CPC, MBC, SPEND, CLICKS),
                _defn_dict("metric:derived_ctr_v1", CBC, CLICKS, IMPRESSIONS),
            ],
            topological_order=[CLICKS, _CPC, "metric:derived_ctr_v1", IMPRESSIONS, SPEND],
        ),
        "topological_order_mismatch",
    ),
    (
        "topological_order_valid_but_not_tie_broken",
        _bundle_dict(
            [_defn_dict(_CPC, MBC, SPEND, CLICKS)],
            topological_order=[SPEND, CLICKS, IMPRESSIONS, _CPC],
        ),
        "topological_order_mismatch",
    ),
    (
        "topological_order_missing_node",
        _bundle_dict(
            [_defn_dict(_CPC, MBC, SPEND, CLICKS)],
            topological_order=[CLICKS, SPEND, _CPC],
        ),
        "topological_order_mismatch",
    ),
    (
        "topological_order_extra_node",
        _bundle_dict(
            [_defn_dict(_CPC, MBC, SPEND, CLICKS)],
            topological_order=[CLICKS, IMPRESSIONS, SPEND, _CPC, _A],
        ),
        "topological_order_mismatch",
    ),
    (
        "topological_order_duplicated_node",
        _bundle_dict(
            [_defn_dict(_CPC, MBC, SPEND, CLICKS)],
            topological_order=[CLICKS, IMPRESSIONS, SPEND, _CPC, _CPC],
        ),
        "topological_order_mismatch",
    ),
    (
        "topological_order_empty",
        _bundle_dict([_defn_dict(_CPC, MBC, SPEND, CLICKS)], topological_order=[]),
        "topological_order_mismatch",
    ),
]


@pytest.mark.parametrize(
    ("raw", "code"),
    [pytest.param(raw, code, id=name) for name, raw, code in NEGATIVE_FIXTURES],
)
def test_mandatory_negative_fixtures_reject_with_closed_code(raw: dict[str, Any], code: str) -> None:
    snapshot = copy.deepcopy(raw)
    with pytest.raises(FormulaGraphError) as exc_info:
        FormulaBundle.from_dict(raw)
    assert exc_info.value.code == code
    assert raw == snapshot


def test_valid_counterpart_of_topological_fixture_is_accepted() -> None:
    raw = _bundle_dict(
        [_defn_dict(_CPC, MBC, SPEND, CLICKS)],
        topological_order=[CLICKS, IMPRESSIONS, SPEND, _CPC],
    )
    bundle = FormulaBundle.from_dict(raw)
    assert bundle.topological_order == (CLICKS, IMPRESSIONS, SPEND, _CPC)
    assert bundle.to_dict() == raw


def test_negative_fixtures_reject_through_constructor_and_order_function() -> None:
    bases = _phase1_bases()
    cases: list[tuple[tuple[DerivedMetricDefinition, ...], str]] = [
        ((_defn(_A, MBC, _B, CLICKS), _defn(_B, MBC, _A, CLICKS)), "cycle"),
        (
            (
                _defn(_A, MBC, _B, CLICKS),
                _defn(_B, MBC, _C, CLICKS),
                _defn(_C, MBC, _A, CLICKS),
            ),
            "cycle",
        ),
        ((_defn(_A, MBC, "metric:ghost_v1", CLICKS),), "unknown_dependency"),
        ((_defn(_CPC, MBC, SPEND, CLICKS), _defn(_CPC, MBC, SPEND, IMPRESSIONS)), "duplicate_output"),
        ((_defn(SPEND, MBC, IMPRESSIONS.replace("impressions", "x"), CLICKS),), "duplicate_output"),
    ]
    for definitions, code in cases:
        with pytest.raises(FormulaGraphError) as exc_info:
            FormulaBundle(base_metrics=bases, definitions=definitions)
        assert exc_info.value.code == code
        with pytest.raises(FormulaGraphError) as exc_info:
            compute_topological_order((CLICKS, IMPRESSIONS, SPEND), definitions)
        assert exc_info.value.code == code

    with pytest.raises(FormulaGraphError) as exc_info:
        FormulaBundle(
            base_metrics=bases,
            definitions=(_defn(_CPC, MBC, SPEND, CLICKS),),
            topological_order=(CLICKS, SPEND, IMPRESSIONS, _CPC),
        )
    assert exc_info.value.code == "topological_order_mismatch"
    with pytest.raises(FormulaGraphError) as exc_info:
        FormulaBundle(base_metrics=bases, definitions=())
    assert exc_info.value.code == "malformed"
    with pytest.raises(FormulaGraphError) as exc_info:
        FormulaBundle(base_metrics=(), definitions=(_defn(_CPC, MBC, SPEND, CLICKS),))
    assert exc_info.value.code == "malformed"


def test_bundle_p1_integrity_content_digest() -> None:
    unsigned = FormulaBundle(
        base_metrics=_phase1_bases(),
        definitions=_sample_definitions(),
        integrity=P1Integrity(
            key_id="key:ed25519:" + "c" * 64,
            key_registry_snapshot_locator=_registry_locator(),
        ),
    )
    plain = FormulaBundle(base_metrics=_phase1_bases(), definitions=_sample_definitions())
    assert unsigned.bundle_digest == plain.bundle_digest  # integrity is outside the bundle digest
    unsigned_dict = unsigned.to_dict()
    assert set(unsigned_dict) == BUNDLE_KEYS | {"integrity"}
    with pytest.raises(ClosedValidationError):
        FormulaBundle.from_dict(unsigned_dict, require_signed=True)

    content_digest = p1_content_digest(unsigned_dict)
    signature = base64.b64encode(b"\x00" * 64).decode("ascii")
    signed_dict = dict(
        unsigned_dict,
        integrity=dict(
            unsigned_dict["integrity"],
            content_digest=content_digest,
            signature_base64=signature,
        ),
    )
    signed = FormulaBundle.from_dict(signed_dict, require_signed=True)
    assert signed.integrity is not None and signed.integrity.is_signed
    assert signed.to_dict() == signed_dict

    tampered = dict(
        signed_dict,
        integrity=dict(signed_dict["integrity"], content_digest="sha256:" + "f" * 64),
    )
    with pytest.raises(FormulaGraphError) as exc_info:
        FormulaBundle.from_dict(tampered, require_signed=True)
    assert exc_info.value.code == "content_digest_mismatch"


# --------------------------------------------------------------------------- certification lattice

ORDER = (
    DerivedCertificationStatus.BLOCKED,
    DerivedCertificationStatus.UNRECONCILED,
    DerivedCertificationStatus.UNAVAILABLE,
    DerivedCertificationStatus.DEGRADED,
    DerivedCertificationStatus.VERIFIED,
)


def test_certification_status_is_closed_total_order() -> None:
    assert tuple(DerivedCertificationStatus) == ORDER
    assert [s.value for s in ORDER] == [
        "BLOCKED",
        "UNRECONCILED",
        "UNAVAILABLE",
        "DEGRADED",
        "VERIFIED",
    ]
    for i, left in enumerate(ORDER):
        assert DerivedCertificationStatus.from_wire(left.value) is left
        for j, right in enumerate(ORDER):
            assert (left < right) is (i < j)
            assert (left <= right) is (i <= j)
            assert (left > right) is (i > j)
            assert (left >= right) is (i >= j)
            assert (left == right) is (i == j)
    with pytest.raises(TypeError):
        _ = ORDER[0] < "VERIFIED"  # type: ignore[operator]


@pytest.mark.parametrize("bad", ["verified", "", " VERIFIED", "PARTIAL", None, 1, True, b"VERIFIED"])
def test_certification_status_rejects_unknown_wire_values(bad: object) -> None:
    with pytest.raises(FormulaGraphError) as exc_info:
        DerivedCertificationStatus.from_wire(bad)
    assert exc_info.value.code == "invalid_certification_status"


def test_combination_is_minimum_for_every_pair_and_triple() -> None:
    for left, right in itertools.product(ORDER, repeat=2):
        combined = combine_derived_certification(
            (CertificationInput(left, "derived_input"), CertificationInput(right, "derived_input"))
        )
        assert combined is min(left, right, key=ORDER.index)
    for triple in itertools.product(ORDER, repeat=3):
        inputs = tuple(CertificationInput(s, "derived_input") for s in triple)
        assert combine_derived_certification(inputs) is min(triple, key=ORDER.index)
        assert combine_derived_certification(tuple(reversed(inputs))) is min(triple, key=ORDER.index)
    for status in ORDER:
        assert combine_derived_certification((CertificationInput(status, "derived_input"),)) is status


def test_phase1_7b_base_input_never_originates_degraded() -> None:
    with pytest.raises(FormulaGraphError) as exc_info:
        CertificationInput(DerivedCertificationStatus.DEGRADED, "phase1_7b_base")
    assert exc_info.value.code == "degraded_from_phase1_7b"

    allowed_base = [s for s in ORDER if s is not DerivedCertificationStatus.DEGRADED]
    for statuses in itertools.product(allowed_base, repeat=2):
        inputs = tuple(CertificationInput(s, "phase1_7b_base") for s in statuses)
        result = combine_derived_certification(inputs)
        assert result is not DerivedCertificationStatus.DEGRADED
        assert result is min(statuses, key=ORDER.index)

    degraded = CertificationInput(DerivedCertificationStatus.DEGRADED, "derived_input")
    verified_base = CertificationInput(DerivedCertificationStatus.VERIFIED, "phase1_7b_base")
    assert combine_derived_certification((verified_base, degraded)) is DerivedCertificationStatus.DEGRADED
    for worse in ORDER[:3]:
        base = CertificationInput(worse, "phase1_7b_base")
        assert combine_derived_certification((base, degraded)) is worse  # never softened


def test_certification_input_rejects_unprofiled_or_malformed_values() -> None:
    for origin in ("provider_mismatch", "", None, "PHASE1_7B_BASE"):
        with pytest.raises(FormulaGraphError) as exc_info:
            CertificationInput(DerivedCertificationStatus.VERIFIED, origin)  # type: ignore[arg-type]
        assert exc_info.value.code == "unprofiled_input_origin"
    with pytest.raises(FormulaGraphError) as exc_info:
        CertificationInput("VERIFIED", "derived_input")  # type: ignore[arg-type]
    assert exc_info.value.code == "invalid_certification_status"
    with pytest.raises(FormulaGraphError) as exc_info:
        combine_derived_certification(())
    assert exc_info.value.code == "empty_certification_inputs"
    with pytest.raises(FormulaGraphError) as exc_info:
        combine_derived_certification((DerivedCertificationStatus.VERIFIED,))  # type: ignore[arg-type]
    assert exc_info.value.code == "malformed"
