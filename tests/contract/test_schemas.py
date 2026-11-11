"""Contract tests for smart_ads.contracts.schemas and package re-exports (ADR-0001)."""
from __future__ import annotations

from pathlib import Path
import subprocess
from types import MappingProxyType

import pytest

import smart_ads.contracts as contracts
from smart_ads.contracts import (
    ADR_DATA_DOMAIN_PREFIXES,
    ADR_P1_DOMAIN_PREFIXES,
    SUPPLEMENTAL_DOMAIN_PREFIXES,
    ArtifactLocator,
    ClosedValidationError,
    P1Integrity,
    canonicalize_jcs,
    domain_jcs_sha256,
    jcs_sha256,
    self_digest_jcs_sha256,
)
from smart_ads.contracts.numerics import (
    PHASE1_BASE_METRICS,
    PROVIDER_PRESENCE_TO_UNKNOWN_REASON,
)
from smart_ads.contracts.schemas import (
    CORE_SCHEMA_DESCRIPTORS,
    PURPOSE_REQUIRED_EFFECT_ROLES,
    AdmittedCollection,
    AnalyticsLandingRow,
    CanonicalQueryContract,
    CollectionRequest,
    CollectionResult,
    DateRange,
    FactKey,
    NormalizedCollectionFact,
    NormalizedProviderError,
    PurposePrerequisiteLocators,
    ReconciliationRowKey,
    RetrievalContext,
    SemanticObservationProjection,
    TransportOutcome,
    UnsupportedDerivedCollectionFactError,
    compute_fact_projection_digest,
    compute_normalized_fact_set_digest,
    compute_schema_bundle_digest,
    project_collection_fact_to_landing_row,
    validate_source_metric_ref,
)
from tools.governance import p1 as gov_p1


VALID_REF_1 = "resource:" + ("a" * 52)
VALID_REF_2 = "resource:" + ("b" * 51) + "a"
VALID_REF_3 = "resource:" + ("c" * 51) + "a"


def _loc(artifact_type: str, fill: str = "a") -> ArtifactLocator:
    return ArtifactLocator.from_digest(artifact_type, "sha256:" + (fill * 64))


def _make_canonical_query() -> CanonicalQueryContract:
    return CanonicalQueryContract(
        tenant_ref="tenant:ibvi",
        binding_ref="binding:meta-primary",
        account_ref="account:ibvi-01",
        resource_scope_ref="scope:campaigns-active",
        ad_platform_ref="meta",
        date_rule="previous_local_day",
        date_range=DateRange(
            start_date="2026-11-10",
            end_date="2026-11-10",
            inclusive=True,
        ),
        reporting_timezone="America/Sao_Paulo",
        tzdb_version="2026a",
        resource_level="campaign",
        metric_semantic_refs=(
            "metric:clicks_v1",
            "metric:impressions_v1",
            "metric:spend_v1",
        ),
        requested_capabilities=("cap:campaign-basic-v1",),
        breakdowns=(),
        currency="BRL",
        attribution_semantics="not_applicable_to_selected_metrics",
        pagination_semantics="complete_result_required",
        aggregation_semantics="per_campaign_rows_no_cross_campaign_aggregation",
    )


def _make_fact_key(
    *,
    resource_ref: str = VALID_REF_1,
    metric_date: str = "2026-11-10",
    metric_semantic_ref: str = "metric:impressions_v1",
    source_metric_ref: str = "source-metric:provider:pipeboard.impressions:v1",
    attribution_ref: str = "attribution:not_applicable",
    breakdown_signature: str = "breakdown:none",
) -> FactKey:
    return FactKey(
        binding_ref="binding:meta-primary",
        account_ref="account:ibvi-01",
        resource_ref=resource_ref,
        resource_level="campaign",
        metric_date=metric_date,
        metric_semantic_ref=metric_semantic_ref,
        source_metric_ref=source_metric_ref,
        attribution_ref=attribution_ref,
        breakdown_signature=breakdown_signature,
    )


def _make_retrieval_context(
    retrieved_at_utc: str = "2026-11-11T04:15:00.123456Z",
) -> RetrievalContext:
    return RetrievalContext(
        retrieved_at_utc=retrieved_at_utc,
        source_observation_ref="observation:obs-001",
        adapter_version="pipeboard-adapter-0.1.0",
        semantic_version="smart-ads-semantic-1.0.0",
    )


def _make_transport_outcome(**overrides: object) -> TransportOutcome:
    base: dict[str, object] = {
        "network_ok": True,
        "http_status": 200,
        "media_and_encoding_valid": True,
        "auth_ok": True,
        "jsonrpc_error": False,
        "payload_schema_valid": True,
        "response_date_mismatch": False,
        "truncated_2mib": False,
        "non_empty_continuation": False,
        "reducer_order_or_count_mismatch": False,
        "duplicate_provider_observation": False,
    }
    base.update(overrides)
    return TransportOutcome(**base)  # type: ignore[arg-type]


def test_contracts_reexports_all_numerics_and_schemas_symbols() -> None:
    expected = {
        "MAX_INT64",
        "ValueType",
        "UnitType",
        "MetricOrigin",
        "PresenceStatus",
        "ProviderPresenceStatus",
        "CalculationStatus",
        "UnknownReason",
        "CurrencyRule",
        "AggregationSemantics",
        "NumericStateRow",
        "validate_numeric_state",
        "PROVIDER_PRESENCE_TO_UNKNOWN_REASON",
        "parse_brl_decimal_to_minor_units",
        "BaseMetricDefinition",
        "PHASE1_DIMENSIONS",
        "PHASE1_BASE_METRICS",
        "PHASE1_METRIC_NAME_TO_REF",
        "PHASE1_METRIC_REF_TO_NAME",
        "CollectionPurpose",
        "CallSide",
        "EffectRole",
        "PURPOSE_REQUIRED_EFFECT_ROLES",
        "validate_source_metric_ref",
        "UnsupportedDerivedCollectionFactError",
        "CollectionRequest",
        "DateRange",
        "CanonicalQueryContract",
        "PurposePrerequisiteLocators",
        "AdmittedCollection",
        "ReconciliationRowKey",
        "FactKey",
        "NormalizedCollectionFact",
        "compute_normalized_fact_set_digest",
        "compute_fact_projection_digest",
        "RetrievalContext",
        "SemanticObservationProjection",
        "AnalyticsLandingRow",
        "project_collection_fact_to_landing_row",
        "TransportOutcome",
        "NormalizedProviderError",
        "CollectionResult",
        "CORE_SCHEMA_DESCRIPTORS",
        "compute_schema_bundle_digest",
    }
    assert expected.issubset(set(contracts.__all__))
    for name in expected:
        assert hasattr(contracts, name), f"Missing re-export on smart_ads.contracts: {name}"


def test_validate_source_metric_ref_lexical_union() -> None:
    p_ref = "source-metric:provider:pipeboard.impressions:v1"
    f_ref = "source-metric:formula:sha256:" + ("a" * 64)
    assert validate_source_metric_ref(p_ref) == p_ref
    assert validate_source_metric_ref(f_ref) == f_ref

    max_provider = "source-metric:provider:" + ("a" * 128) + ":v12"
    assert validate_source_metric_ref(max_provider) == max_provider

    for bad in (
        "",
        None,
        123,
        "sha256:" + ("a" * 64),
        "source-metric:formula:" + ("a" * 64),
        "source-metric:formula:sha256:" + ("A" * 64),
        "source-metric:formula:sha256:" + ("a" * 63),
        "source-metric:provider:Pipeboard:v1",
        "source-metric:provider:.leadingdot:v1",
        "source-metric:provider:pipeboard:v0",
        "source-metric:provider:" + ("a" * 129) + ":v1",
        p_ref + "\n",
    ):
        with pytest.raises(ClosedValidationError):
            validate_source_metric_ref(bad)


def test_collection_request_closed_intent_and_rejections() -> None:
    req = CollectionRequest.from_dict(
        {
            "request_id": "req-001",
            "collection_purpose": "operational_read",
            "tenant_ref": "tenant:ibvi",
            "binding_ref": "binding:meta-primary",
            "resource_scope_ref": "scope:campaigns-active",
            "date_rule": "previous_local_day",
            "resource_level": "campaign",
            "requested_capabilities": ["cap:z-cap", "cap:a-cap"],
            "breakdowns": [],
        }
    )
    assert req.requested_capabilities == ("cap:a-cap", "cap:z-cap")
    assert req.breakdowns == ()
    assert len(req.to_dict()) == 9
    assert req.external_request_digest == jcs_sha256(req.to_dict())
    assert CollectionRequest.from_dict(req.to_dict()) == req

    base_dict = req.to_dict()
    for forbidden_extra in (
        "admitted_at_utc",
        "currency",
        "access_token",
        "registry_snapshot_digest",
        "$schema",
    ):
        with pytest.raises(ClosedValidationError):
            CollectionRequest.from_dict(dict(base_dict, **{forbidden_extra: "injected"}))

    for bad_patch in (
        {"request_id": "   "},
        {"collection_purpose": "shadow_read"},
        {"tenant_ref": "account:wrong"},
        {"binding_ref": "tenant:wrong"},
        {"resource_scope_ref": "cap:wrong"},
        {"date_rule": "last_7_days"},
        {"resource_level": "adset"},
        {"requested_capabilities": []},
        {"requested_capabilities": ["cap:a-cap", "cap:a-cap"]},
        {"requested_capabilities": ["metric:clicks_v1"]},
        {"requested_capabilities": "cap:a-cap"},
        {"breakdowns": ["age"]},
    ):
        with pytest.raises(ClosedValidationError):
            CollectionRequest.from_dict(dict(base_dict, **bad_patch))


def test_date_range_and_canonical_query_contract() -> None:
    with pytest.raises(ClosedValidationError):
        DateRange(start_date="2026-11-10", end_date="2026-11-10", inclusive=False)
    with pytest.raises(ClosedValidationError):
        DateRange(start_date="2026-11-10", end_date="2026-11-10", inclusive=1)  # type: ignore[arg-type]
    with pytest.raises(ClosedValidationError):
        DateRange(start_date="2026-11-11", end_date="2026-11-10", inclusive=True)

    cqc = _make_canonical_query()
    cqc_dict = cqc.to_dict()
    assert cqc_dict["$schema"] == "smart_ads/canonical_query_contract/v1"
    assert len(cqc_dict) == 18
    assert cqc.canonical_query_digest == jcs_sha256(cqc_dict)
    assert CanonicalQueryContract.from_dict(cqc_dict) == cqc

    # Python constructor normalizes metric order; from_dict rejects unsorted wire arrays!
    reordered_cqc = CanonicalQueryContract(
        tenant_ref=cqc.tenant_ref,
        binding_ref=cqc.binding_ref,
        account_ref=cqc.account_ref,
        resource_scope_ref=cqc.resource_scope_ref,
        ad_platform_ref="meta",
        date_rule="previous_local_day",
        date_range=cqc.date_range,
        reporting_timezone="America/Sao_Paulo",
        tzdb_version="2026a",
        resource_level="campaign",
        metric_semantic_refs=(
            "metric:impressions_v1",
            "metric:clicks_v1",
            "metric:spend_v1",
        ),
        requested_capabilities=cqc.requested_capabilities,
        breakdowns=(),
        currency="BRL",
        attribution_semantics=cqc.attribution_semantics,
        pagination_semantics=cqc.pagination_semantics,
        aggregation_semantics=cqc.aggregation_semantics,
    )
    assert reordered_cqc == cqc

    with pytest.raises(ClosedValidationError):
        CanonicalQueryContract.from_dict(
            dict(
                cqc_dict,
                metric_semantic_refs=[
                    "metric:impressions_v1",
                    "metric:clicks_v1",
                    "metric:spend_v1",
                ],
            )
        )
    with pytest.raises(ClosedValidationError):
        CanonicalQueryContract.from_dict(
            dict(
                cqc_dict,
                requested_capabilities=["cap:z", "cap:a"],
            )
        )

    # Multi-day range forbidden under previous_local_day
    with pytest.raises(ClosedValidationError):
        CanonicalQueryContract.from_dict(
            dict(
                cqc_dict,
                date_range={
                    "start_date": "2026-11-09",
                    "end_date": "2026-11-10",
                    "inclusive": True,
                },
            )
        )

    for bad_patch in (
        {"$schema": "smart_ads/other/v1"},
        {"ad_platform_ref": "google"},
        {"reporting_timezone": "UTC"},
        {"currency": "USD"},
        {"resource_level": "ad"},
        {"breakdowns": ["country"]},
        {"attribution_semantics": "7d_click"},
        {"pagination_semantics": "best_effort"},
        {"aggregation_semantics": "sum"},
    ):
        with pytest.raises(ClosedValidationError):
            CanonicalQueryContract.from_dict(dict(cqc_dict, **bad_patch))


def test_purpose_prerequisite_locators_and_admitted_collection(tmp_path: Path) -> None:
    assert isinstance(PURPOSE_REQUIRED_EFFECT_ROLES, MappingProxyType)
    assert dict(PURPOSE_REQUIRED_EFFECT_ROLES) == {
        "fixture_7a": (),
        "live_verification_7b": ("candidate_7b_call", "reference_7b_call"),
        "operational_read": ("operational_provider_read",),
    }

    prereq_7a = PurposePrerequisiteLocators(
        purpose="fixture_7a",
        sealed_sandbox_profile_locator=_loc("smart_ads/sealed_sandbox_profile/v1", "1"),
        regression_fixture_locator=_loc("smart_ads/regression_fixture/v1", "2"),
    )
    assert set(prereq_7a.to_dict().keys()) == {
        "purpose",
        "sealed_sandbox_profile_locator",
        "regression_fixture_locator",
    }
    assert PurposePrerequisiteLocators.from_dict(prereq_7a.to_dict()) == prereq_7a

    prereq_7b = PurposePrerequisiteLocators(
        purpose="live_verification_7b",
        legacy_step2_evidence_locator=_loc(
            "smart_ads/legacy_step2_implementation_evidence/v1", "3"
        ),
        live_read_activation_receipt_locator=_loc(
            "smart_ads/smart_ads_live_read_activation_receipt/v1", "4"
        ),
        gate3_selection_receipt_locator=_loc(
            "smart_ads/gate3_selection_receipt/v1", "5"
        ),
        workload_identity_effect_proof_locator=_loc("smart_ads/effect_proof/v1", "6"),
        deployment_effect_proof_locator=_loc("smart_ads/effect_proof/v1", "7"),
    )
    assert PurposePrerequisiteLocators.from_dict(prereq_7b.to_dict()) == prereq_7b

    prereq_op = PurposePrerequisiteLocators(
        purpose="operational_read",
        legacy_step2_evidence_locator=_loc(
            "smart_ads/legacy_step2_implementation_evidence/v1", "3"
        ),
        live_read_activation_receipt_locator=_loc(
            "smart_ads/smart_ads_live_read_activation_receipt/v1", "4"
        ),
        live_certification_head_locator=_loc(
            "smart_ads/live_certification_head/v1", "8"
        ),
        live_certification_transition_locator=_loc(
            "smart_ads/live_certification_transition/v1", "9"
        ),
        live_certification_certificate_locator=_loc(
            "smart_ads/live_certification_certificate/v1", "a"
        ),
        gate3_operational_renewal_locator=_loc(
            "smart_ads/gate3_selection_receipt/v1", "b"
        ),
        workload_identity_effect_proof_locator=_loc("smart_ads/effect_proof/v1", "6"),
        deployment_effect_proof_locator=_loc("smart_ads/effect_proof/v1", "7"),
        delegation_context_locator=_loc(
            "smart_ads/ibvi_ads_delegation_context/v1", "c"
        ),
    )
    assert PurposePrerequisiteLocators.from_dict(prereq_op.to_dict()) == prereq_op
    prereq_op_no_deleg = PurposePrerequisiteLocators.from_dict(
        dict(prereq_op.to_dict(), delegation_context_locator=None)
    )
    assert prereq_op_no_deleg.delegation_context_locator is None

    # Cross-purpose or current-call auth/reservation/execution/consumption locators reject!
    with pytest.raises(ClosedValidationError):
        PurposePrerequisiteLocators(
            purpose="fixture_7a",
            sealed_sandbox_profile_locator=_loc(
                "smart_ads/sealed_sandbox_profile/v1", "1"
            ),
            regression_fixture_locator=_loc("smart_ads/regression_fixture/v1", "2"),
            gate3_selection_receipt_locator=_loc(
                "smart_ads/gate3_selection_receipt/v1", "5"
            ),
        )
    for forbidden_current_call_key in (
        "authorization_locator",
        "reservation_locator",
        "execution_locator",
        "consumption_locator",
    ):
        with pytest.raises(ClosedValidationError):
            PurposePrerequisiteLocators.from_dict(
                dict(
                    prereq_7b.to_dict(),
                    **{
                        forbidden_current_call_key: _loc(
                            "smart_ads/authorization_receipt/v1", "d"
                        ).to_dict()
                    },
                )
            )

    cqc = _make_canonical_query()
    reg_loc = _loc("smart_ads/private_registry_snapshot/v1", "e")
    drv_loc = _loc("smart_ads/pipeboard_phase1_contract/v1", "f")
    clk_loc = _loc("smart_ads/clock_attestation/v1", "0")

    priv = tmp_path / "ed25519.pem"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(priv)],
        check=True,
        capture_output=True,
    )
    raw32 = gov_p1.raw_public_key_from_pem(priv)
    key_id = gov_p1.key_id_for(raw32)
    key_reg_loc = _loc("smart_ads/key_authorization_registry/v1", "1")

    admitted = AdmittedCollection(
        admission_id="admission:adm-001",
        collection_purpose="live_verification_7b",
        external_request_digest="sha256:" + ("2" * 64),
        tenant_ref=cqc.tenant_ref,
        binding_ref=cqc.binding_ref,
        account_ref=cqc.account_ref,
        resource_scope_ref=cqc.resource_scope_ref,
        resource_level="campaign",
        requested_capabilities=cqc.requested_capabilities,
        admitted_at_utc="2026-11-11T03:05:00Z",
        clock_attestation_locator=clk_loc,
        maximum_clock_uncertainty_ms=1000,
        tzdb_version=cqc.tzdb_version,
        reporting_timezone=cqc.reporting_timezone,
        computed_date_range=cqc.date_range,
        registry_snapshot_locator=reg_loc,
        registry_snapshot_digest=reg_loc.content_digest,
        currency="BRL",
        driver_id="pipeboard_hosted",
        driver_contract_locator=drv_loc,
        driver_contract_digest=drv_loc.content_digest,
        driver_capability_snapshot_digest="sha256:" + ("3" * 64),
        canonical_query_contract=cqc,
        canonical_query_digest=cqc.canonical_query_digest,
        purpose_prerequisite_locators=prereq_7b,
        required_effect_roles=("candidate_7b_call", "reference_7b_call"),
        integrity=P1Integrity(
            key_id=key_id, key_registry_snapshot_locator=key_reg_loc
        ),
    )

    signed_adm_dict = gov_p1.sign_envelope(
        admitted.to_dict(),
        ADR_P1_DOMAIN_PREFIXES[AdmittedCollection.SCHEMA],
        priv,
    )
    parsed_signed_adm = AdmittedCollection.from_dict(
        signed_adm_dict, require_signed=True
    )
    assert parsed_signed_adm.integrity is not None and parsed_signed_adm.integrity.is_signed

    adm_base = admitted.to_dict()
    for bad_adm_patch in (
        {"registry_snapshot_digest": "sha256:" + ("9" * 64)},
        {"driver_contract_digest": "sha256:" + ("9" * 64)},
        {"canonical_query_digest": "sha256:" + ("9" * 64)},
        {"purpose_prerequisite_locators": prereq_7a.to_dict()},
        {"required_effect_roles": ["operational_provider_read"]},
        {"tenant_ref": "tenant:other"},
        {"account_ref": "account:other"},
        {"tzdb_version": "2025c"},
        {"maximum_clock_uncertainty_ms": 0},
        {"maximum_clock_uncertainty_ms": True},
        {"admitted_at_utc": "2026-11-11T03:05:00.000000Z"},
        {"authorization_locator": _loc("smart_ads/authorization_receipt/v1").to_dict()},
    ):
        with pytest.raises(ClosedValidationError):
            AdmittedCollection.from_dict(dict(adm_base, **bad_adm_patch))


def test_facts_projection_landing_rows_and_derived_support() -> None:
    fk = _make_fact_key()
    assert fk.reconciliation_row_key == ReconciliationRowKey(
        resource_ref=VALID_REF_1,
        metric_date="2026-11-10",
        resource_level="campaign",
        breakdown_signature="breakdown:none",
    )
    assert fk.canonical_metric_ref == "metric:impressions_v1"
    assert fk.set_identity_array() == [
        VALID_REF_1,
        "2026-11-10",
        "campaign",
        "breakdown:none",
        "metric:impressions_v1",
    ]
    assert FactKey.from_dict(fk.to_dict()) == fk
    assert ReconciliationRowKey.from_dict(fk.reconciliation_row_key.to_dict()) == (
        fk.reconciliation_row_key
    )

    ctx = _make_retrieval_context()
    assert RetrievalContext.from_dict(ctx.to_dict()) == ctx

    # Project all 6 provider presence states (observed + 5 null-quadruple states including retracted_tombstone)
    provider_cases = [
        ("observed", "int64_count", "125", "count", None),
        ("missing", None, None, None, None),
        ("unproven_zero", None, None, None, None),
        ("timeout", None, None, None, None),
        ("not_applicable_at_level", None, None, None, None),
        ("retracted_tombstone", None, None, None, None),
    ]
    for presence, vt, raw_val, unit, ccy in provider_cases:
        fact = NormalizedCollectionFact(
            fact_key=fk,
            presence_status=presence,  # type: ignore[arg-type]
            value_type=vt,  # type: ignore[arg-type]
            raw_numeric_value=raw_val,
            unit=unit,  # type: ignore[arg-type]
            currency=ccy,
        )
        assert len(fact.to_dict()) == 6
        assert "$schema" not in fact.to_dict()
        assert NormalizedCollectionFact.from_dict(fact.to_dict()) == fact
        assert compute_fact_projection_digest(fact) == domain_jcs_sha256(
            ADR_DATA_DOMAIN_PREFIXES["7b_fact_projection"],
            fact.to_dict(),
        )

        row = project_collection_fact_to_landing_row(fact, ctx)
        assert len(row.to_dict()) == 16
        assert row.collected_at_utc == ctx.retrieved_at_utc
        assert row.metric_origin == "provider_observation"
        assert row.calculation_status == "not_applicable"
        assert row.unknown_reason == PROVIDER_PRESENCE_TO_UNKNOWN_REASON[presence]
        assert AnalyticsLandingRow.from_dict(row.to_dict()) == row

        expected_sem = SemanticObservationProjection(
            fact_key=fk,
            value_type=vt,  # type: ignore[arg-type]
            raw_numeric_value=raw_val,
            unit=unit,  # type: ignore[arg-type]
            currency=ccy,
            metric_origin="provider_observation",
            presence_status=presence,  # type: ignore[arg-type]
            unknown_reason=PROVIDER_PRESENCE_TO_UNKNOWN_REASON[presence],
            calculation_status="not_applicable",
            collected_at_utc=ctx.retrieved_at_utc,
            source_observation_ref=ctx.source_observation_ref,
            adapter_version=ctx.adapter_version,
            semantic_version=ctx.semantic_version,
        )
        assert len(expected_sem.to_dict()) == 13
        assert expected_sem.to_dict()["numeric"] == {"_type": vt, "value": raw_val}
        assert SemanticObservationProjection.from_dict(expected_sem.to_dict()) == expected_sem
        assert row.semantic_observation_digest == expected_sem.compute_digest()
        assert row.row_digest == self_digest_jcs_sha256(
            row.to_dict(),
            digest_member="row_digest",
            domain_prefix=ADR_DATA_DOMAIN_PREFIXES["row"],
            strip_integrity=False,
        )

    # Reject formula source_metric_ref in NormalizedCollectionFact with UnsupportedDerivedCollectionFactError
    assert issubclass(UnsupportedDerivedCollectionFactError, ClosedValidationError)
    derived_fk = _make_fact_key(
        metric_semantic_ref="metric:derived_cpc_v1",
        source_metric_ref="source-metric:formula:sha256:" + ("b" * 64),
    )
    with pytest.raises(UnsupportedDerivedCollectionFactError):
        NormalizedCollectionFact(
            fact_key=derived_fk,
            presence_status="observed",
            value_type="int64_minor_currency",
            raw_numeric_value="250",
            unit="minor_currency",
            currency="BRL",
        )

    # Base metric definition compatibility rejections (e.g., spend with count or clicks with money)
    spend_fk = _make_fact_key(
        metric_semantic_ref="metric:spend_v1",
        source_metric_ref="source-metric:provider:pipeboard.spend:v1",
    )
    with pytest.raises(ClosedValidationError):
        NormalizedCollectionFact(
            fact_key=spend_fk,
            presence_status="observed",
            value_type="int64_count",
            raw_numeric_value="250",
            unit="count",
            currency=None,
        )
    with pytest.raises(ClosedValidationError):
        AnalyticsLandingRow(
            fact_key=spend_fk,
            value_type="int64_count",
            raw_numeric_value="250",
            unit="count",
            currency=None,
            metric_origin="provider_observation",
            presence_status="observed",
            unknown_reason=None,
            calculation_status="not_applicable",
            collected_at_utc=ctx.retrieved_at_utc,
            source_observation_ref=ctx.source_observation_ref,
            adapter_version=ctx.adapter_version,
            semantic_version=ctx.semantic_version,
        )

    # Direct support in AnalyticsLandingRow for ALL 6 derived rows
    derived_cases = [
        (
            "not_applicable",
            "computed",
            None,
            "int64_minor_currency",
            "250",
            "minor_currency",
            "BRL",
        ),
        ("not_applicable", "input_missing", "input_missing", None, None, None, None),
        ("not_applicable", "input_unproven", "input_unproven", None, None, None, None),
        (
            "not_applicable",
            "division_by_zero",
            "division_by_zero",
            None,
            None,
            None,
            None,
        ),
        (
            "not_applicable_at_level",
            "not_applicable",
            "metric_not_applicable_at_level",
            None,
            None,
            None,
            None,
        ),
        (
            "retracted_tombstone",
            "not_applicable",
            "source_retracted",
            None,
            None,
            None,
            None,
        ),
    ]
    for presence, calc, reason, vt, raw_val, unit, ccy in derived_cases:
        d_row = AnalyticsLandingRow(
            fact_key=derived_fk,
            value_type=vt,  # type: ignore[arg-type]
            raw_numeric_value=raw_val,
            unit=unit,  # type: ignore[arg-type]
            currency=ccy,
            metric_origin="derived_formula",
            presence_status=presence,  # type: ignore[arg-type]
            unknown_reason=reason,  # type: ignore[arg-type]
            calculation_status=calc,  # type: ignore[arg-type]
            collected_at_utc=ctx.retrieved_at_utc,
            source_observation_ref=ctx.source_observation_ref,
            adapter_version=ctx.adapter_version,
            semantic_version=ctx.semantic_version,
        )
        assert AnalyticsLandingRow.from_dict(d_row.to_dict()) == d_row

    # Reject metric_origin <-> source_metric_ref mismatch and digest tampering
    with pytest.raises(ClosedValidationError):
        AnalyticsLandingRow(
            fact_key=derived_fk,
            value_type="int64_minor_currency",
            raw_numeric_value="250",
            unit="minor_currency",
            currency="BRL",
            metric_origin="provider_observation",
            presence_status="observed",
            unknown_reason=None,
            calculation_status="not_applicable",
            collected_at_utc=ctx.retrieved_at_utc,
            source_observation_ref=ctx.source_observation_ref,
            adapter_version=ctx.adapter_version,
            semantic_version=ctx.semantic_version,
        )

    sample_row = project_collection_fact_to_landing_row(
        NormalizedCollectionFact(
            fact_key=spend_fk,
            presence_status="observed",
            value_type="int64_minor_currency",
            raw_numeric_value="1234",
            unit="minor_currency",
            currency="BRL",
        ),
        ctx,
    )
    for tampered_patch in (
        {"semantic_observation_digest": "sha256:" + ("0" * 64)},
        {"row_digest": "sha256:" + ("0" * 64)},
        {"raw_numeric_value": "9999"},
        {"semantic_observation_digest": ""},
        {"row_digest": ""},
    ):
        with pytest.raises(ClosedValidationError):
            AnalyticsLandingRow.from_dict(dict(sample_row.to_dict(), **tampered_patch))


def test_compute_normalized_fact_set_digest_ordering_and_rejections() -> None:
    f_b = NormalizedCollectionFact(
        fact_key=_make_fact_key(
            resource_ref=VALID_REF_2,
            metric_semantic_ref="metric:impressions_v1",
            source_metric_ref="source-metric:provider:pipeboard.impressions:v1",
        ),
        presence_status="observed",
        value_type="int64_count",
        raw_numeric_value="10",
        unit="count",
        currency=None,
    )
    f_a = NormalizedCollectionFact(
        fact_key=_make_fact_key(
            resource_ref=VALID_REF_1,
            metric_semantic_ref="metric:clicks_v1",
            source_metric_ref="source-metric:provider:pipeboard.clicks:v1",
        ),
        presence_status="observed",
        value_type="int64_count",
        raw_numeric_value="2",
        unit="count",
        currency=None,
    )
    sorted_facts, set_digest = compute_normalized_fact_set_digest([f_b, f_a])
    assert sorted_facts == (f_a, f_b)
    assert set_digest == domain_jcs_sha256(
        ADR_DATA_DOMAIN_PREFIXES["normalized_fact_set"],
        [f_a.to_dict(), f_b.to_dict()],
    )

    # Retracted tombstone is valid inside complete normalized_fact_set (P-03)
    f_tombstone = NormalizedCollectionFact(
        fact_key=_make_fact_key(
            resource_ref=VALID_REF_3,
            metric_semantic_ref="metric:spend_v1",
            source_metric_ref="source-metric:provider:pipeboard.spend:v1",
        ),
        presence_status="retracted_tombstone",
        value_type=None,
        raw_numeric_value=None,
        unit=None,
        currency=None,
    )
    sorted_with_tomb, _ = compute_normalized_fact_set_digest([f_tombstone, f_a])
    assert sorted_with_tomb == (f_a, f_tombstone)

    # Non-complete presence statuses MUST be rejected by compute_normalized_fact_set_digest (P-03)
    for incomplete_presence in (
        "missing",
        "unproven_zero",
        "timeout",
        "not_applicable_at_level",
    ):
        bad_presence_fact = NormalizedCollectionFact(
            fact_key=_make_fact_key(
                resource_ref=VALID_REF_3,
                metric_semantic_ref="metric:spend_v1",
                source_metric_ref="source-metric:provider:pipeboard.spend:v1",
            ),
            presence_status=incomplete_presence,  # type: ignore[arg-type]
            value_type=None,
            raw_numeric_value=None,
            unit=None,
            currency=None,
        )
        with pytest.raises(ClosedValidationError):
            compute_normalized_fact_set_digest([f_a, bad_presence_fact])

    # Empty fact set rejects
    with pytest.raises(ClosedValidationError):
        compute_normalized_fact_set_digest([])

    # Duplicate I(f) rejects (even if raw_numeric_value differs!)
    f_a_dup = NormalizedCollectionFact(
        fact_key=f_a.fact_key,
        presence_status="observed",
        value_type="int64_count",
        raw_numeric_value="99",
        unit="count",
        currency=None,
    )
    with pytest.raises(ClosedValidationError):
        compute_normalized_fact_set_digest([f_a, f_a_dup])

    # Non-not_applicable or multiple attribution_ref rejects (P-12)
    f_bad_attr = NormalizedCollectionFact(
        fact_key=_make_fact_key(
            resource_ref=VALID_REF_3,
            attribution_ref="attribution:7d_click",
        ),
        presence_status="observed",
        value_type="int64_count",
        raw_numeric_value="5",
        unit="count",
        currency=None,
    )
    with pytest.raises(ClosedValidationError):
        compute_normalized_fact_set_digest([f_a, f_bad_attr])
    with pytest.raises(ClosedValidationError):
        compute_normalized_fact_set_digest([f_bad_attr])


def test_collection_result_complete_and_partial_invariants(tmp_path: Path) -> None:
    with pytest.raises(ClosedValidationError):
        _make_transport_outcome(http_status=True)
    with pytest.raises(ClosedValidationError):
        _make_transport_outcome(http_status=False)
    with pytest.raises(ClosedValidationError):
        _make_transport_outcome(network_ok=1)
    with pytest.raises(ClosedValidationError):
        NormalizedProviderError(
            error_code="ERR_1",
            category="unknown_cat",  # type: ignore[arg-type]
            sanitized_detail="detail",
        )

    adm_loc = _loc("smart_ads/admitted_collection/v1", "4")
    reg_loc = _loc("smart_ads/private_registry_snapshot/v1", "5")
    ctx = _make_retrieval_context()

    f1 = NormalizedCollectionFact(
        fact_key=_make_fact_key(
            resource_ref=VALID_REF_1,
            metric_semantic_ref="metric:clicks_v1",
            source_metric_ref="source-metric:provider:pipeboard.clicks:v1",
        ),
        presence_status="observed",
        value_type="int64_count",
        raw_numeric_value="10",
        unit="count",
        currency=None,
    )
    f2 = NormalizedCollectionFact(
        fact_key=_make_fact_key(
            resource_ref=VALID_REF_1,
            metric_semantic_ref="metric:impressions_v1",
            source_metric_ref="source-metric:provider:pipeboard.impressions:v1",
        ),
        presence_status="observed",
        value_type="int64_count",
        raw_numeric_value="100",
        unit="count",
        currency=None,
    )
    sorted_facts, fact_set_digest = compute_normalized_fact_set_digest([f2, f1])
    r1 = project_collection_fact_to_landing_row(f1, ctx)
    r2 = project_collection_fact_to_landing_row(f2, ctx)
    sorted_complete_candidates = tuple(
        sorted((r2, r1), key=lambda r: r.candidate_sort_key_jcs())
    )

    priv = tmp_path / "ed25519.pem"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(priv)],
        check=True,
        capture_output=True,
    )
    raw32 = gov_p1.raw_public_key_from_pem(priv)
    key_id = gov_p1.key_id_for(raw32)
    key_reg_loc = _loc("smart_ads/key_authorization_registry/v1", "6")

    complete_res = CollectionResult(
        admitted_collection_locator=adm_loc,
        admitted_collection_digest=adm_loc.content_digest,
        call_side="operational",
        registry_snapshot_locator=reg_loc,
        registry_snapshot_digest=reg_loc.content_digest,
        requested_capabilities=("cap:campaign-basic-v1",),
        observed_capabilities=("cap:campaign-basic-v1",),
        retrieval_context=ctx,
        transport_outcome=_make_transport_outcome(),
        candidates=sorted_complete_candidates,
        normalized_fact_set=sorted_facts,
        normalized_fact_set_digest=fact_set_digest,
        normalized_errors=(),
        integrity=P1Integrity(
            key_id=key_id, key_registry_snapshot_locator=key_reg_loc
        ),
    )
    res_dict = complete_res.to_dict()
    assert "status" not in res_dict
    assert len(res_dict) == 15
    assert [r.candidate_sort_key_jcs() for r in complete_res.candidates] == sorted(
        [r1.candidate_sort_key_jcs(), r2.candidate_sort_key_jcs()]
    )

    # Direct constructor also rejects out-of-order candidates
    with pytest.raises(ClosedValidationError):
        CollectionResult(
            admitted_collection_locator=adm_loc,
            admitted_collection_digest=adm_loc.content_digest,
            call_side="operational",
            registry_snapshot_locator=reg_loc,
            registry_snapshot_digest=reg_loc.content_digest,
            requested_capabilities=("cap:campaign-basic-v1",),
            observed_capabilities=("cap:campaign-basic-v1",),
            retrieval_context=ctx,
            transport_outcome=_make_transport_outcome(),
            candidates=(sorted_complete_candidates[1], sorted_complete_candidates[0]),
            normalized_fact_set=sorted_facts,
            normalized_fact_set_digest=fact_set_digest,
            normalized_errors=(),
        )

    signed_res_dict = gov_p1.sign_envelope(
        res_dict, ADR_P1_DOMAIN_PREFIXES[CollectionResult.SCHEMA], priv
    )
    parsed_signed_res = CollectionResult.from_dict(
        signed_res_dict, require_signed=True
    )
    assert parsed_signed_res.integrity is not None and parsed_signed_res.integrity.is_signed

    # Reject Producer status injection, invalid call_side, out-of-order candidates, partial fact-set nulls
    with pytest.raises(ClosedValidationError):
        CollectionResult.from_dict(dict(res_dict, status="complete"))
    with pytest.raises(ClosedValidationError):
        CollectionResult.from_dict(dict(res_dict, call_side="shadow"))
    with pytest.raises(ClosedValidationError):
        CollectionResult.from_dict(
            dict(
                res_dict,
                candidates=[
                    complete_res.candidates[1].to_dict(),
                    complete_res.candidates[0].to_dict(),
                ],
            )
        )
    with pytest.raises(ClosedValidationError):
        CollectionResult.from_dict(dict(res_dict, normalized_fact_set=None))
    with pytest.raises(ClosedValidationError):
        CollectionResult.from_dict(dict(res_dict, normalized_fact_set_digest=None))
    with pytest.raises(ClosedValidationError):
        CollectionResult.from_dict(
            dict(res_dict, normalized_fact_set=[f2.to_dict(), f1.to_dict()])
        )

    # All 4 retrieval_context provenance fields must match on every candidate row
    for bad_ctx in (
        _make_retrieval_context("2026-11-11T04:15:01.000000Z"),
        RetrievalContext(
            retrieved_at_utc=ctx.retrieved_at_utc,
            source_observation_ref="observation:other-obs",
            adapter_version=ctx.adapter_version,
            semantic_version=ctx.semantic_version,
        ),
        RetrievalContext(
            retrieved_at_utc=ctx.retrieved_at_utc,
            source_observation_ref=ctx.source_observation_ref,
            adapter_version="pipeboard-adapter-9.9.9",
            semantic_version=ctx.semantic_version,
        ),
        RetrievalContext(
            retrieved_at_utc=ctx.retrieved_at_utc,
            source_observation_ref=ctx.source_observation_ref,
            adapter_version=ctx.adapter_version,
            semantic_version="smart-ads-semantic-9.9.9",
        ),
    ):
        r_mismatch = project_collection_fact_to_landing_row(f1, bad_ctx)
        with pytest.raises(ClosedValidationError):
            CollectionResult(
                admitted_collection_locator=adm_loc,
                admitted_collection_digest=adm_loc.content_digest,
                call_side="candidate",
                registry_snapshot_locator=reg_loc,
                registry_snapshot_digest=reg_loc.content_digest,
                requested_capabilities=("cap:campaign-basic-v1",),
                observed_capabilities=("cap:campaign-basic-v1",),
                retrieval_context=ctx,
                transport_outcome=_make_transport_outcome(),
                candidates=(r_mismatch,),
                normalized_fact_set=None,
                normalized_fact_set_digest=None,
                normalized_errors=(),
            )

    # Dirty transport_outcome flags when normalized_fact_set is non-null MUST reject
    for dirty_to in (
        _make_transport_outcome(network_ok=False),
        _make_transport_outcome(http_status=None),
        _make_transport_outcome(http_status=503),
        _make_transport_outcome(media_and_encoding_valid=False),
        _make_transport_outcome(auth_ok=False),
        _make_transport_outcome(jsonrpc_error=True),
        _make_transport_outcome(payload_schema_valid=False),
        _make_transport_outcome(response_date_mismatch=True),
        _make_transport_outcome(truncated_2mib=True),
        _make_transport_outcome(non_empty_continuation=True),
        _make_transport_outcome(reducer_order_or_count_mismatch=True),
        _make_transport_outcome(duplicate_provider_observation=True),
    ):
        with pytest.raises(ClosedValidationError):
            CollectionResult(
                admitted_collection_locator=adm_loc,
                admitted_collection_digest=adm_loc.content_digest,
                call_side="operational",
                registry_snapshot_locator=reg_loc,
                registry_snapshot_digest=reg_loc.content_digest,
                requested_capabilities=("cap:campaign-basic-v1",),
                observed_capabilities=("cap:campaign-basic-v1",),
                retrieval_context=ctx,
                transport_outcome=dirty_to,
                candidates=sorted_complete_candidates,
                normalized_fact_set=sorted_facts,
                normalized_fact_set_digest=fact_set_digest,
                normalized_errors=(),
            )

    # Divergent candidates vs projected normalized_fact_set MUST reject
    f1_different_val = NormalizedCollectionFact(
        fact_key=f1.fact_key,
        presence_status="observed",
        value_type="int64_count",
        raw_numeric_value="999",
        unit="count",
        currency=None,
    )
    r1_different_val = project_collection_fact_to_landing_row(f1_different_val, ctx)
    for bad_candidates in (
        (),
        (r1,),
        tuple(sorted((r1_different_val, r2), key=lambda r: r.candidate_sort_key_jcs())),
        tuple(sorted((r1, r1, r2), key=lambda r: r.candidate_sort_key_jcs())),
    ):
        with pytest.raises(ClosedValidationError):
            CollectionResult(
                admitted_collection_locator=adm_loc,
                admitted_collection_digest=adm_loc.content_digest,
                call_side="operational",
                registry_snapshot_locator=reg_loc,
                registry_snapshot_digest=reg_loc.content_digest,
                requested_capabilities=("cap:campaign-basic-v1",),
                observed_capabilities=("cap:campaign-basic-v1",),
                retrieval_context=ctx,
                transport_outcome=_make_transport_outcome(),
                candidates=bad_candidates,
                normalized_fact_set=sorted_facts,
                normalized_fact_set_digest=fact_set_digest,
                normalized_errors=(),
            )

    # Partial result preserves duplicate fact_key rows (and even identical duplicate rows) sorted by K
    f1_alt = NormalizedCollectionFact(
        fact_key=f1.fact_key,
        presence_status="observed",
        value_type="int64_count",
        raw_numeric_value="99",
        unit="count",
        currency=None,
    )
    r1_alt = project_collection_fact_to_landing_row(f1_alt, ctx)
    partial_candidates = tuple(
        sorted((r1_alt, r1), key=lambda r: r.candidate_sort_key_jcs())
    )
    partial_res = CollectionResult(
        admitted_collection_locator=adm_loc,
        admitted_collection_digest=adm_loc.content_digest,
        call_side="reference",
        registry_snapshot_locator=reg_loc,
        registry_snapshot_digest=reg_loc.content_digest,
        requested_capabilities=("cap:campaign-basic-v1",),
        observed_capabilities=(),
        retrieval_context=ctx,
        transport_outcome=_make_transport_outcome(duplicate_provider_observation=True),
        candidates=partial_candidates,
        normalized_fact_set=None,
        normalized_fact_set_digest=None,
        normalized_errors=(
            NormalizedProviderError(
                error_code="DUPLICATE_FACT_KEY",
                category="completeness",
                sanitized_detail="duplicate observation for cmp-1 clicks",
            ),
        ),
    )
    assert len(partial_res.candidates) == 2
    assert partial_res.candidates[0].fact_key == partial_res.candidates[1].fact_key
    assert (
        partial_res.candidates[0].candidate_sort_key_jcs()
        <= partial_res.candidates[1].candidate_sort_key_jcs()
    )
    assert CollectionResult.from_dict(partial_res.to_dict()) == partial_res

    # Identical duplicate provider observations remain representable on partial CollectionResult (P-04)
    partial_identical_dup = CollectionResult(
        admitted_collection_locator=adm_loc,
        admitted_collection_digest=adm_loc.content_digest,
        call_side="reference",
        registry_snapshot_locator=reg_loc,
        registry_snapshot_digest=reg_loc.content_digest,
        requested_capabilities=("cap:campaign-basic-v1",),
        observed_capabilities=(),
        retrieval_context=ctx,
        transport_outcome=_make_transport_outcome(duplicate_provider_observation=True),
        candidates=(r1, r1),
        normalized_fact_set=None,
        normalized_fact_set_digest=None,
        normalized_errors=(),
    )
    assert len(partial_identical_dup.candidates) == 2


def test_fact_key_and_reconciliation_row_key_enforce_canonical_resource_ref() -> None:
    ctx = _make_retrieval_context()
    valid_fact = NormalizedCollectionFact(
        fact_key=_make_fact_key(resource_ref=VALID_REF_1),
        presence_status="observed",
        value_type="int64_count",
        raw_numeric_value="7",
        unit="count",
        currency=None,
    )
    valid_row = project_collection_fact_to_landing_row(valid_fact, ctx)
    valid_res = CollectionResult(
        admitted_collection_locator=_loc("smart_ads/admitted_collection/v1", "4"),
        admitted_collection_digest="sha256:" + ("4" * 64),
        call_side="operational",
        registry_snapshot_locator=_loc("smart_ads/private_registry_snapshot/v1", "5"),
        registry_snapshot_digest="sha256:" + ("5" * 64),
        requested_capabilities=("cap:campaign-basic-v1",),
        observed_capabilities=("cap:campaign-basic-v1",),
        retrieval_context=ctx,
        transport_outcome=_make_transport_outcome(),
        candidates=(valid_row,),
        normalized_fact_set=(valid_fact,),
        normalized_fact_set_digest=compute_normalized_fact_set_digest([valid_fact])[1],
        normalized_errors=(),
    )

    for bad_ref in (
        "resource:cmp-1",
        "resource:120210987654321",
        "resource:" + ("A" * 52),
        "resource:" + ("a" * 51) + "b",
        "resource:" + ("a" * 51) + "7",
        "account:ibvi-01",
    ):
        with pytest.raises(ClosedValidationError):
            FactKey(
                binding_ref="binding:meta-primary",
                account_ref="account:ibvi-01",
                resource_ref=bad_ref,
                resource_level="campaign",
                metric_date="2026-11-10",
                metric_semantic_ref="metric:impressions_v1",
                source_metric_ref="source-metric:provider:pipeboard.impressions:v1",
                attribution_ref="attribution:not_applicable",
                breakdown_signature="breakdown:none",
            )
        with pytest.raises(ClosedValidationError):
            ReconciliationRowKey(
                resource_ref=bad_ref,
                metric_date="2026-11-10",
                resource_level="campaign",
                breakdown_signature="breakdown:none",
            )
        bad_fk_dict = dict(valid_fact.fact_key.to_dict(), resource_ref=bad_ref)
        with pytest.raises(ClosedValidationError):
            NormalizedCollectionFact.from_dict(
                dict(valid_fact.to_dict(), fact_key=bad_fk_dict)
            )
        with pytest.raises(ClosedValidationError):
            AnalyticsLandingRow.from_dict(
                dict(valid_row.to_dict(), fact_key=bad_fk_dict)
            )
        bad_res_dict = dict(
            valid_res.to_dict(),
            candidates=[dict(valid_row.to_dict(), fact_key=bad_fk_dict)],
            normalized_fact_set=None,
            normalized_fact_set_digest=None,
        )
        with pytest.raises(ClosedValidationError):
            CollectionResult.from_dict(bad_res_dict)


def test_intrinsic_currency_self_consistency_and_non_brl_projection() -> None:
    ctx = _make_retrieval_context()
    spend_fk = _make_fact_key(
        resource_ref=VALID_REF_1,
        metric_semantic_ref="metric:spend_v1",
        source_metric_ref="source-metric:provider:pipeboard.spend:v1",
    )
    usd_fact = NormalizedCollectionFact(
        fact_key=spend_fk,
        presence_status="observed",
        value_type="int64_minor_currency",
        raw_numeric_value="450",
        unit="minor_currency",
        currency="USD",
    )
    assert NormalizedCollectionFact.from_dict(usd_fact.to_dict()) == usd_fact

    usd_row = project_collection_fact_to_landing_row(
        usd_fact, ctx, query_currency="USD"
    )
    assert usd_row.currency == "USD"
    assert AnalyticsLandingRow.from_dict(usd_row.to_dict()) == usd_row

    # Reject mismatched query_currency when projecting
    with pytest.raises(ClosedValidationError):
        project_collection_fact_to_landing_row(usd_fact, ctx, query_currency="BRL")

    # Complete CollectionResult supports consistent single non-BRL currency, rejects mixed currencies
    brl_fact = NormalizedCollectionFact(
        fact_key=_make_fact_key(
            resource_ref=VALID_REF_2,
            metric_semantic_ref="metric:spend_v1",
            source_metric_ref="source-metric:provider:pipeboard.spend:v1",
        ),
        presence_status="observed",
        value_type="int64_minor_currency",
        raw_numeric_value="500",
        unit="minor_currency",
        currency="BRL",
    )
    brl_row = project_collection_fact_to_landing_row(
        brl_fact, ctx, query_currency="BRL"
    )
    usd_complete = CollectionResult(
        admitted_collection_locator=_loc("smart_ads/admitted_collection/v1", "4"),
        admitted_collection_digest="sha256:" + ("4" * 64),
        call_side="operational",
        registry_snapshot_locator=_loc("smart_ads/private_registry_snapshot/v1", "5"),
        registry_snapshot_digest="sha256:" + ("5" * 64),
        requested_capabilities=("cap:campaign-basic-v1",),
        observed_capabilities=("cap:campaign-basic-v1",),
        retrieval_context=ctx,
        transport_outcome=_make_transport_outcome(),
        candidates=(usd_row,),
        normalized_fact_set=(usd_fact,),
        normalized_fact_set_digest=compute_normalized_fact_set_digest([usd_fact])[1],
        normalized_errors=(),
    )
    assert CollectionResult.from_dict(usd_complete.to_dict()) == usd_complete

    mixed_candidates = tuple(
        sorted((usd_row, brl_row), key=lambda r: r.candidate_sort_key_jcs())
    )
    with pytest.raises(ClosedValidationError):
        CollectionResult(
            admitted_collection_locator=_loc("smart_ads/admitted_collection/v1", "4"),
            admitted_collection_digest="sha256:" + ("4" * 64),
            call_side="operational",
            registry_snapshot_locator=_loc("smart_ads/private_registry_snapshot/v1", "5"),
            registry_snapshot_digest="sha256:" + ("5" * 64),
            requested_capabilities=("cap:campaign-basic-v1",),
            observed_capabilities=(),
            retrieval_context=ctx,
            transport_outcome=_make_transport_outcome(payload_schema_valid=False),
            candidates=mixed_candidates,
            normalized_fact_set=None,
            normalized_fact_set_digest=None,
            normalized_errors=(),
        )


def test_core_schema_descriptors_and_bundle_digest_determinism() -> None:
    schema_ids = [d["schema_id"] for d in CORE_SCHEMA_DESCRIPTORS]
    assert schema_ids == sorted(schema_ids, key=lambda s: s.encode("utf-8"))
    assert set(schema_ids) == {
        "smart_ads/admitted_collection/v1",
        "smart_ads/analytics_landing_row/v1",
        "smart_ads/artifact_locator/v1",
        "smart_ads/base_metric_definition/v1",
        "smart_ads/canonical_query_contract/v1",
        "smart_ads/capability_invalidation_transition/v1",
        "smart_ads/capability_revalidation_transition/v1",
        "smart_ads/collection_result/v1",
        "smart_ads/expected_resource_inventory/v1",
        "smart_ads/normalized_collection_fact/v1",
        "smart_ads/pipeboard_phase1_contract/v1",
        "smart_ads/private_registry_snapshot/v1",
        "smart_ads/semantic_observation_projection/v1",
    }

    by_id = {d["schema_id"]: d for d in CORE_SCHEMA_DESCRIPTORS}
    for sid, desc in by_id.items():
        fields = list(desc["fields"])
        assert fields == sorted(fields, key=lambda s: s.encode("utf-8"))
        assert desc["p1_domain_prefix"] == ADR_P1_DOMAIN_PREFIXES.get(sid)

    # Verify agreement with actual serialized keys of Task 2 & Task 3 dataclasses
    key_reg_loc = _loc("smart_ads/key_authorization_registry/v1", "1")
    sample_p1 = P1Integrity(
        key_id="key:ed25519:" + ("a" * 64),
        key_registry_snapshot_locator=key_reg_loc,
    )
    base_defn = PHASE1_BASE_METRICS["metric:clicks_v1"]
    base_defn_p1 = type(base_defn)(
        metric_semantic_ref=base_defn.metric_semantic_ref,
        canonical_name=base_defn.canonical_name,
        value_type=base_defn.value_type,
        unit=base_defn.unit,
        currency_rule=base_defn.currency_rule,
        dimensions=base_defn.dimensions,
        aggregation_semantics=base_defn.aggregation_semantics,
        integrity=sample_p1,
    )
    cqc = _make_canonical_query()
    fk = _make_fact_key()
    ctx = _make_retrieval_context()
    fact = NormalizedCollectionFact(
        fact_key=fk,
        presence_status="observed",
        value_type="int64_count",
        raw_numeric_value="1",
        unit="count",
        currency=None,
    )
    row = project_collection_fact_to_landing_row(fact, ctx)
    sem = SemanticObservationProjection(
        fact_key=fk,
        value_type="int64_count",
        raw_numeric_value="1",
        unit="count",
        currency=None,
        metric_origin="provider_observation",
        presence_status="observed",
        unknown_reason=None,
        calculation_status="not_applicable",
        collected_at_utc=ctx.retrieved_at_utc,
        source_observation_ref=ctx.source_observation_ref,
        adapter_version=ctx.adapter_version,
        semantic_version=ctx.semantic_version,
    )
    adm = AdmittedCollection(
        admission_id="admission:adm-x",
        collection_purpose="fixture_7a",
        external_request_digest="sha256:" + ("2" * 64),
        tenant_ref=cqc.tenant_ref,
        binding_ref=cqc.binding_ref,
        account_ref=cqc.account_ref,
        resource_scope_ref=cqc.resource_scope_ref,
        resource_level="campaign",
        requested_capabilities=cqc.requested_capabilities,
        admitted_at_utc="2026-11-11T03:00:00Z",
        clock_attestation_locator=_loc("smart_ads/clock_attestation/v1", "0"),
        maximum_clock_uncertainty_ms=500,
        tzdb_version=cqc.tzdb_version,
        reporting_timezone=cqc.reporting_timezone,
        computed_date_range=cqc.date_range,
        registry_snapshot_locator=_loc("smart_ads/private_registry_snapshot/v1", "3"),
        registry_snapshot_digest="sha256:" + ("3" * 64),
        currency="BRL",
        driver_id="pipeboard_hosted",
        driver_contract_locator=_loc("smart_ads/pipeboard_phase1_contract/v1", "4"),
        driver_contract_digest="sha256:" + ("4" * 64),
        driver_capability_snapshot_digest="sha256:" + ("5" * 64),
        canonical_query_contract=cqc,
        canonical_query_digest=cqc.canonical_query_digest,
        purpose_prerequisite_locators=PurposePrerequisiteLocators(
            purpose="fixture_7a",
            sealed_sandbox_profile_locator=_loc(
                "smart_ads/sealed_sandbox_profile/v1", "6"
            ),
            regression_fixture_locator=_loc("smart_ads/regression_fixture/v1", "7"),
        ),
        required_effect_roles=(),
        integrity=sample_p1,
    )
    res = CollectionResult(
        admitted_collection_locator=_loc("smart_ads/admitted_collection/v1", "8"),
        admitted_collection_digest="sha256:" + ("8" * 64),
        call_side="candidate",
        registry_snapshot_locator=_loc("smart_ads/private_registry_snapshot/v1", "3"),
        registry_snapshot_digest="sha256:" + ("3" * 64),
        requested_capabilities=cqc.requested_capabilities,
        observed_capabilities=cqc.requested_capabilities,
        retrieval_context=ctx,
        transport_outcome=_make_transport_outcome(),
        candidates=(row,),
        normalized_fact_set=(fact,),
        normalized_fact_set_digest=compute_normalized_fact_set_digest([fact])[1],
        normalized_errors=(),
        integrity=sample_p1,
    )

    for sid, obj_dict in (
        ("smart_ads/artifact_locator/v1", key_reg_loc.to_dict()),
        ("smart_ads/base_metric_definition/v1", base_defn_p1.to_dict()),
        ("smart_ads/canonical_query_contract/v1", cqc.to_dict()),
        ("smart_ads/admitted_collection/v1", adm.to_dict()),
        ("smart_ads/normalized_collection_fact/v1", fact.to_dict()),
        ("smart_ads/semantic_observation_projection/v1", sem.to_dict()),
        ("smart_ads/analytics_landing_row/v1", row.to_dict()),
        ("smart_ads/collection_result/v1", res.to_dict()),
    ):
        assert list(by_id[sid]["fields"]) == sorted(
            obj_dict.keys(), key=lambda s: s.encode("utf-8")
        )

    digest = compute_schema_bundle_digest()
    assert digest == compute_schema_bundle_digest()
    assert digest == domain_jcs_sha256(
        SUPPLEMENTAL_DOMAIN_PREFIXES["schema_bundle"],
        list(CORE_SCHEMA_DESCRIPTORS),
    )
