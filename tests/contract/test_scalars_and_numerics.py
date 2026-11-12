"""Contract tests for smart_ads.contracts.numerics and scalar/numeric laws (ADR-0001 §§4.3, 5.5.1)."""
from __future__ import annotations

from pathlib import Path
import subprocess
from types import MappingProxyType

import pytest

from smart_ads.contracts import (
    ADR_P1_DOMAIN_PREFIXES,
    ArtifactLocator,
    ClosedValidationError,
    P1Integrity,
    jcs_sha256,
    p1_content_digest,
    self_digest_jcs_sha256,
)
from smart_ads.contracts.numerics import (
    MAX_INT64,
    PHASE1_BASE_METRICS,
    PHASE1_DIMENSIONS,
    PHASE1_METRIC_NAME_TO_REF,
    PHASE1_METRIC_REF_TO_NAME,
    PROVIDER_PRESENCE_TO_UNKNOWN_REASON,
    BaseMetricDefinition,
    NumericStateRow,
    parse_brl_decimal_to_minor_units,
    validate_numeric_state,
)
from tools.governance import p1 as gov_p1


def test_max_int64_and_provider_presence_mapping() -> None:
    assert MAX_INT64 == (1 << 63) - 1 == 9223372036854775807
    assert isinstance(PROVIDER_PRESENCE_TO_UNKNOWN_REASON, MappingProxyType)
    assert dict(PROVIDER_PRESENCE_TO_UNKNOWN_REASON) == {
        "observed": None,
        "missing": "provider_omitted",
        "unproven_zero": "zero_not_proven",
        "timeout": "provider_timeout",
        "not_applicable_at_level": "metric_not_applicable_at_level",
        "retracted_tombstone": "source_retracted",
    }
    with pytest.raises(TypeError):
        PROVIDER_PRESENCE_TO_UNKNOWN_REASON["observed"] = "provider_omitted"  # type: ignore[index]


@pytest.mark.parametrize(
    ("metric_origin", "presence_status", "calculation_status"),
    [
        ("provider_observation", "observed", "not_applicable"),
        ("derived_formula", "not_applicable", "computed"),
    ],
)
@pytest.mark.parametrize(
    ("value_type", "raw_numeric_value", "unit", "currency", "query_currency"),
    [
        ("int64_count", "0", "count", None, "BRL"),
        ("int64_count", "42", "count", None, "BRL"),
        ("int64_count", "9223372036854775807", "count", None, "BRL"),
        ("int64_minor_currency", "0", "minor_currency", "BRL", "BRL"),
        ("int64_minor_currency", "9223372036854775807", "minor_currency", "BRL", "BRL"),
        ("int64_minor_currency", "150", "minor_currency", "USD", "USD"),
        ("decimal_ratio", "0.000000", "ratio", None, "BRL"),
        ("decimal_ratio", "12.345678", "ratio", None, "BRL"),
    ],
)
def test_validate_numeric_state_accepts_non_null_value_rows(
    metric_origin: str,
    presence_status: str,
    calculation_status: str,
    value_type: str,
    raw_numeric_value: str,
    unit: str,
    currency: str | None,
    query_currency: str,
) -> None:
    row = validate_numeric_state(
        metric_origin=metric_origin,
        presence_status=presence_status,
        calculation_status=calculation_status,
        unknown_reason=None,
        value_type=value_type,
        raw_numeric_value=raw_numeric_value,
        unit=unit,
        currency=currency,
        query_currency=query_currency,
    )
    assert isinstance(row, NumericStateRow)
    assert row.metric_origin == metric_origin
    assert row.presence_status == presence_status
    assert row.calculation_status == calculation_status
    assert row.unknown_reason is None
    assert row.value_type == value_type
    assert row.raw_numeric_value == raw_numeric_value
    assert row.unit == unit
    assert row.currency == currency
    with pytest.raises(AttributeError):
        row.raw_numeric_value = "1"  # type: ignore[misc]


@pytest.mark.parametrize(
    ("metric_origin", "presence_status", "calculation_status", "unknown_reason"),
    [
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
    ],
)
def test_validate_numeric_state_accepts_all_ten_null_quadruple_rows(
    metric_origin: str,
    presence_status: str,
    calculation_status: str,
    unknown_reason: str,
) -> None:
    row = validate_numeric_state(
        metric_origin=metric_origin,
        presence_status=presence_status,
        calculation_status=calculation_status,
        unknown_reason=unknown_reason,
        value_type=None,
        raw_numeric_value=None,
        unit=None,
        currency=None,
    )
    assert row == NumericStateRow(
        metric_origin=metric_origin,  # type: ignore[arg-type]
        presence_status=presence_status,  # type: ignore[arg-type]
        calculation_status=calculation_status,  # type: ignore[arg-type]
        unknown_reason=unknown_reason,  # type: ignore[arg-type]
        value_type=None,
        raw_numeric_value=None,
        unit=None,
        currency=None,
    )


@pytest.mark.parametrize(
    ("value_type", "bad_raw", "unit", "currency"),
    [
        ("int64_count", True, "count", None),
        ("int64_count", False, "count", None),
        ("int64_count", 0, "count", None),
        ("int64_count", 42, "count", None),
        ("int64_count", 0.0, "count", None),
        ("int64_count", 1.5, "count", None),
        ("int64_count", float("nan"), "count", None),
        ("int64_count", float("inf"), "count", None),
        ("int64_count", "9223372036854775808", "count", None),  # 2^63 overflow
        ("int64_count", "-1", "count", None),
        ("int64_count", "+1", "count", None),
        ("int64_count", "-0", "count", None),
        ("int64_count", "01", "count", None),
        ("int64_count", "00", "count", None),
        ("int64_count", "1,000", "count", None),
        ("int64_count", " 1", "count", None),
        ("int64_count", "1\n", "count", None),
        ("int64_count", "1e3", "count", None),
        ("int64_count", "١٢", "count", None),
        ("int64_count", "", "count", None),
        ("int64_minor_currency", "9223372036854775808", "minor_currency", "BRL"),
        ("int64_minor_currency", "-1", "minor_currency", "BRL"),
        ("int64_minor_currency", "01", "minor_currency", "BRL"),
        ("int64_minor_currency", "10.00", "minor_currency", "BRL"),
        ("decimal_ratio", "1.23", "ratio", None),
        ("decimal_ratio", "1.1234567", "ratio", None),
        ("decimal_ratio", "1", "ratio", None),
        ("decimal_ratio", "1.", "ratio", None),
        ("decimal_ratio", ".000000", "ratio", None),
        ("decimal_ratio", "01.000000", "ratio", None),
        ("decimal_ratio", "-0.000000", "ratio", None),
        ("decimal_ratio", "-1.000000", "ratio", None),
        ("decimal_ratio", "+1.000000", "ratio", None),
        ("decimal_ratio", "0.000000\n", "ratio", None),
        ("decimal_ratio", "٠.٠٠٠٠٠٠", "ratio", None),
    ],
)
def test_validate_numeric_state_rejects_bad_lexical_or_typed_values(
    value_type: str,
    bad_raw: object,
    unit: str,
    currency: str | None,
) -> None:
    with pytest.raises(ClosedValidationError):
        validate_numeric_state(
            metric_origin="provider_observation",
            presence_status="observed",
            calculation_status="not_applicable",
            unknown_reason=None,
            value_type=value_type,
            raw_numeric_value=bad_raw,
            unit=unit,
            currency=currency,
            query_currency="BRL",
        )


def test_validate_numeric_state_rejects_unit_currency_partial_null_and_matrix_violations() -> None:
    # Currency mismatch ("USD" vs query_currency="BRL") and missing/extra currency
    for vt, raw, unit, ccy, q_ccy in (
        ("int64_minor_currency", "100", "minor_currency", "USD", "BRL"),
        ("int64_minor_currency", "100", "minor_currency", None, "BRL"),
        ("int64_minor_currency", "100", "minor_currency", "brl", "brl"),
        ("int64_count", "100", "count", "BRL", "BRL"),
        ("decimal_ratio", "1.000000", "ratio", "BRL", "BRL"),
        ("int64_count", "100", "minor_currency", None, "BRL"),
        ("int64_minor_currency", "100", "count", "BRL", "BRL"),
        ("decimal_ratio", "1.000000", "count", None, "BRL"),
        ("float64", "1.000000", "ratio", None, "BRL"),
    ):
        with pytest.raises(ClosedValidationError):
            validate_numeric_state(
                metric_origin="provider_observation",
                presence_status="observed",
                calculation_status="not_applicable",
                unknown_reason=None,
                value_type=vt,
                raw_numeric_value=raw,
                unit=unit,
                currency=ccy,
                query_currency=q_ccy,
            )

    # Partial nulls on observed/computed row
    for vt, raw, unit, ccy in (
        (None, "0", "count", None),
        ("int64_count", None, "count", None),
        ("int64_count", "0", None, None),
        (None, None, None, None),
    ):
        with pytest.raises(ClosedValidationError):
            validate_numeric_state(
                metric_origin="provider_observation",
                presence_status="observed",
                calculation_status="not_applicable",
                unknown_reason=None,
                value_type=vt,
                raw_numeric_value=raw,
                unit=unit,
                currency=ccy,
            )

    # Non-null leakages on null-quadruple rows (never coerce missing/unproven to "0")
    for leak_vt, leak_raw, leak_unit, leak_ccy in (
        ("int64_count", "0", "count", None),
        ("int64_count", None, None, None),
        (None, "0", None, None),
        (None, None, "count", None),
        (None, None, None, "BRL"),
    ):
        with pytest.raises(ClosedValidationError):
            validate_numeric_state(
                metric_origin="provider_observation",
                presence_status="missing",
                calculation_status="not_applicable",
                unknown_reason="provider_omitted",
                value_type=leak_vt,
                raw_numeric_value=leak_raw,
                unit=leak_unit,
                currency=leak_ccy,
            )

    # Invalid (metric_origin, presence_status, calculation_status, unknown_reason) tuples
    invalid_tuples: list[tuple[object, object, object, object, bool]] = [
        ("provider_observation", "not_applicable", "not_applicable", None, True),
        ("provider_observation", "not_applicable", "computed", None, True),
        ("provider_observation", "observed", "computed", None, True),
        ("provider_observation", "observed", "not_applicable", "provider_omitted", True),
        ("provider_observation", "missing", "not_applicable", None, False),
        ("provider_observation", "missing", "not_applicable", "zero_not_proven", False),
        ("provider_observation", "timeout", "input_missing", "provider_timeout", False),
        ("derived_formula", "observed", "computed", None, True),
        ("derived_formula", "missing", "not_applicable", "provider_omitted", False),
        ("derived_formula", "timeout", "not_applicable", "provider_timeout", False),
        ("derived_formula", "unproven_zero", "not_applicable", "zero_not_proven", False),
        ("derived_formula", "not_applicable", "not_applicable", None, False),
        ("derived_formula", "not_applicable", "computed", "division_by_zero", True),
        ("derived_formula", "retracted_tombstone", "computed", "source_retracted", False),
        (["unhashable"], "observed", "not_applicable", None, True),
    ]
    for origin, presence, calc, reason, with_val in invalid_tuples:
        with pytest.raises(ClosedValidationError):
            validate_numeric_state(
                metric_origin=origin,
                presence_status=presence,
                calculation_status=calc,
                unknown_reason=reason,
                value_type="int64_count" if with_val else None,
                raw_numeric_value="0" if with_val else None,
                unit="count" if with_val else None,
                currency=None,
            )


def test_parse_brl_decimal_to_minor_units_exact_and_rejections() -> None:
    assert parse_brl_decimal_to_minor_units("0") == "0"
    assert parse_brl_decimal_to_minor_units("0.0") == "0"
    assert parse_brl_decimal_to_minor_units("0.00") == "0"
    assert parse_brl_decimal_to_minor_units("0.05") == "5"
    assert parse_brl_decimal_to_minor_units("0.5") == "50"
    assert parse_brl_decimal_to_minor_units("12.3") == "1230"
    assert parse_brl_decimal_to_minor_units("12.34") == "1234"
    assert parse_brl_decimal_to_minor_units("92233720368547758.07") == "9223372036854775807"

    for bad_brl in (
        "92233720368547758.08",  # MAX_INT64 + 1 cent
        "12.345",
        "-1.00",
        "+1.00",
        "-0.00",
        "01",
        "01.00",
        "00.50",
        "12.",
        ".50",
        "12,34",
        "1,234.56",
        " 12.34",
        "12.34 ",
        "12.34\n",
        "١٢.٣٤",
        "",
        12.34,
        12,
        0,
        True,
        False,
        None,
    ):
        with pytest.raises(ClosedValidationError):
            parse_brl_decimal_to_minor_units(bad_brl)


def test_base_metric_definition_and_phase1_base_metrics(tmp_path: Path) -> None:
    assert PHASE1_DIMENSIONS == (
        "attribution_ref",
        "breakdown_signature",
        "metric_date",
        "resource_level",
        "resource_ref",
    )
    assert list(PHASE1_DIMENSIONS) == sorted(
        PHASE1_DIMENSIONS, key=lambda s: s.encode("utf-8")
    )

    assert isinstance(PHASE1_BASE_METRICS, MappingProxyType)
    assert isinstance(PHASE1_METRIC_NAME_TO_REF, MappingProxyType)
    assert isinstance(PHASE1_METRIC_REF_TO_NAME, MappingProxyType)
    assert set(PHASE1_BASE_METRICS.keys()) == {
        "metric:clicks_v1",
        "metric:impressions_v1",
        "metric:spend_v1",
    }
    assert dict(PHASE1_METRIC_NAME_TO_REF) == {
        "clicks": "metric:clicks_v1",
        "impressions": "metric:impressions_v1",
        "spend": "metric:spend_v1",
    }
    assert dict(PHASE1_METRIC_REF_TO_NAME) == {
        "metric:clicks_v1": "clicks",
        "metric:impressions_v1": "impressions",
        "metric:spend_v1": "spend",
    }

    for ref, defn in PHASE1_BASE_METRICS.items():
        assert defn.metric_semantic_ref == ref
        assert defn.dimensions == PHASE1_DIMENSIONS
        assert defn.aggregation_semantics == "additive_across_none"
        expected_layer1 = self_digest_jcs_sha256(
            defn.to_dict(),
            digest_member="metric_definition_digest",
            strip_integrity=True,
        )
        assert defn.metric_definition_digest == expected_layer1
        assert BaseMetricDefinition.from_dict(defn.to_dict()) == defn

    # Direct construction normalizes unsorted dimensions; from_dict rejects unsorted dimensions.
    unsorted_dims = (
        "resource_ref",
        "resource_level",
        "metric_date",
        "attribution_ref",
        "breakdown_signature",
    )
    normalized_defn = BaseMetricDefinition(
        metric_semantic_ref="metric:impressions_v1",
        canonical_name="impressions",
        value_type="int64_count",
        unit="count",
        currency_rule="must_be_null",
        dimensions=unsorted_dims,
        aggregation_semantics="additive_across_none",
    )
    assert normalized_defn.dimensions == PHASE1_DIMENSIONS
    assert normalized_defn == PHASE1_BASE_METRICS["metric:impressions_v1"]

    bad_unsorted_wire = dict(normalized_defn.to_dict(), dimensions=list(unsorted_dims))
    with pytest.raises(ClosedValidationError):
        BaseMetricDefinition.from_dict(bad_unsorted_wire)

    # Digest tampering or blank digest on wire rejects
    tampered_digest = "sha256:" + ("0" * 64)
    with pytest.raises(ClosedValidationError):
        BaseMetricDefinition(
            metric_semantic_ref="metric:impressions_v1",
            canonical_name="impressions",
            value_type="int64_count",
            unit="count",
            currency_rule="must_be_null",
            dimensions=PHASE1_DIMENSIONS,
            aggregation_semantics="additive_across_none",
            metric_definition_digest=tampered_digest,
        )
    with pytest.raises(ClosedValidationError):
        BaseMetricDefinition.from_dict(
            dict(normalized_defn.to_dict(), metric_definition_digest="")
        )

    # P1 signing preserves Layer 1 digest and verifies Layer 2 content_digest
    priv = tmp_path / "ed25519.pem"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(priv)],
        check=True,
        capture_output=True,
    )
    raw32 = gov_p1.raw_public_key_from_pem(priv)
    key_id = gov_p1.key_id_for(raw32)
    reg_loc = ArtifactLocator.from_digest(
        "smart_ads/key_authorization_registry/v1", "sha256:" + ("1" * 64)
    )
    unsigned_defn = BaseMetricDefinition(
        metric_semantic_ref="metric:spend_v1",
        canonical_name="spend",
        value_type="int64_minor_currency",
        unit="minor_currency",
        currency_rule="must_be_query_currency",
        dimensions=PHASE1_DIMENSIONS,
        aggregation_semantics="additive_across_none",
        integrity=P1Integrity(key_id=key_id, key_registry_snapshot_locator=reg_loc),
    )
    assert (
        unsigned_defn.metric_definition_digest
        == PHASE1_BASE_METRICS["metric:spend_v1"].metric_definition_digest
    )
    with pytest.raises(ClosedValidationError):
        BaseMetricDefinition.from_dict(unsigned_defn.to_dict(), require_signed=True)

    p1_prefix = ADR_P1_DOMAIN_PREFIXES[BaseMetricDefinition.SCHEMA]
    signed_dict = gov_p1.sign_envelope(unsigned_defn.to_dict(), p1_prefix, priv)
    gov_p1.verify_envelope(signed_dict, p1_prefix, raw32)

    signed_defn = BaseMetricDefinition.from_dict(signed_dict, require_signed=True)
    assert signed_defn.integrity is not None and signed_defn.integrity.is_signed
    assert (
        signed_defn.metric_definition_digest
        == unsigned_defn.metric_definition_digest
    )
    assert signed_defn.integrity.content_digest == p1_content_digest(signed_dict)
    assert jcs_sha256(signed_defn.to_dict()) == jcs_sha256(signed_dict)

    # Tampering with signed envelope content_digest rejects
    bad_signed = dict(signed_dict)
    bad_signed["integrity"] = dict(
        signed_dict["integrity"], content_digest="sha256:" + ("f" * 64)
    )
    with pytest.raises(ClosedValidationError):
        BaseMetricDefinition.from_dict(bad_signed, require_signed=True)

    # Invalid ref/name/triple/dimension/aggregation rejections
    for kwargs in (
        {"metric_semantic_ref": "metric:impressions_v0"},
        {"metric_semantic_ref": "metric:Impressions_v1"},
        {"metric_semantic_ref": "impressions_v1"},
        {"canonical_name": "Impressions"},
        {"canonical_name": "1bad"},
        {"value_type": "int64_count", "unit": "count", "currency_rule": "must_be_query_currency"},
        {"value_type": "int64_minor_currency", "unit": "minor_currency", "currency_rule": "must_be_null"},
        {"value_type": "decimal_ratio", "unit": "ratio", "currency_rule": "must_be_query_currency"},
        {"dimensions": ()},
        {"dimensions": ("account_ref",)},
        {"dimensions": ("resource_ref", "resource_ref")},
        {"aggregation_semantics": "sum_all"},
    ):
        base_kwargs: dict[str, object] = {
            "metric_semantic_ref": "metric:impressions_v1",
            "canonical_name": "impressions",
            "value_type": "int64_count",
            "unit": "count",
            "currency_rule": "must_be_null",
            "dimensions": PHASE1_DIMENSIONS,
            "aggregation_semantics": "additive_across_none",
        }
        base_kwargs.update(kwargs)
        with pytest.raises(ClosedValidationError):
            BaseMetricDefinition(**base_kwargs)  # type: ignore[arg-type]


def test_overlong_digit_strings_raise_closed_validation_error_not_raw_value_error() -> None:
    overlong_int = "1" + ("0" * 5000)
    overlong_brl = overlong_int + ".00"

    # Valid boundaries continue to pass
    assert (
        validate_numeric_state(
            metric_origin="provider_observation",
            presence_status="observed",
            calculation_status="not_applicable",
            unknown_reason=None,
            value_type="int64_count",
            raw_numeric_value="0",
            unit="count",
            currency=None,
            query_currency="BRL",
        ).raw_numeric_value
        == "0"
    )
    assert (
        validate_numeric_state(
            metric_origin="provider_observation",
            presence_status="observed",
            calculation_status="not_applicable",
            unknown_reason=None,
            value_type="int64_count",
            raw_numeric_value="9223372036854775807",
            unit="count",
            currency=None,
            query_currency="BRL",
        ).raw_numeric_value
        == "9223372036854775807"
    )
    assert (
        validate_numeric_state(
            metric_origin="provider_observation",
            presence_status="observed",
            calculation_status="not_applicable",
            unknown_reason=None,
            value_type="int64_minor_currency",
            raw_numeric_value="9223372036854775807",
            unit="minor_currency",
            currency="BRL",
            query_currency="BRL",
        ).raw_numeric_value
        == "9223372036854775807"
    )
    assert parse_brl_decimal_to_minor_units("0") == "0"
    assert (
        parse_brl_decimal_to_minor_units("92233720368547758.07")
        == "9223372036854775807"
    )

    # 5001-digit strings must raise ClosedValidationError (not CPython int_max_str_digits ValueError)
    for origin, presence, calc in (
        ("provider_observation", "observed", "not_applicable"),
        ("derived_formula", "not_applicable", "computed"),
    ):
        with pytest.raises(ClosedValidationError):
            validate_numeric_state(
                metric_origin=origin,
                presence_status=presence,
                calculation_status=calc,
                unknown_reason=None,
                value_type="int64_count",
                raw_numeric_value=overlong_int,
                unit="count",
                currency=None,
                query_currency="BRL",
            )
        with pytest.raises(ClosedValidationError):
            validate_numeric_state(
                metric_origin=origin,
                presence_status=presence,
                calculation_status=calc,
                unknown_reason=None,
                value_type="int64_minor_currency",
                raw_numeric_value=overlong_int,
                unit="minor_currency",
                currency="BRL",
                query_currency="BRL",
            )
        with pytest.raises(ClosedValidationError):
            NumericStateRow(
                metric_origin=origin,  # type: ignore[arg-type]
                presence_status=presence,  # type: ignore[arg-type]
                calculation_status=calc,  # type: ignore[arg-type]
                unknown_reason=None,
                value_type="int64_count",
                raw_numeric_value=overlong_int,
                unit="count",
                currency=None,
            )

    for bad_overlong_brl in (overlong_int, overlong_brl):
        with pytest.raises(ClosedValidationError):
            parse_brl_decimal_to_minor_units(bad_overlong_brl)
