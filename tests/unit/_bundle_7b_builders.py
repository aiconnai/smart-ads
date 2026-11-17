"""Shared builders and independent oracles for the 7B bundle tests (not collected).

Expected digests are recomputed with ``hashlib`` over the documented preimage,
never with the helper under test.
"""
from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

import pytest

from smart_ads.contracts.jcs import ArtifactLocator, p1_content_digest
from smart_ads.contracts.schemas import (
    CanonicalQueryContract,
    CollectionResult,
    DateRange,
    FactKey,
    NormalizedCollectionFact,
    ReconciliationRowKey,
    RetrievalContext,
    TransportOutcome,
    compute_normalized_fact_set_digest,
    project_collection_fact_to_landing_row,
)
from smart_ads.reconciliation import bundle_7b as b7
from smart_ads.reconciliation.bundle_7b import (
    Bundle7BDefectError,
    MetricPairKey,
    compute_canonical_fact_key_digest,
)

IMPRESSIONS = "metric:impressions_v1"
CLICKS = "metric:clicks_v1"
SPEND = "metric:spend_v1"
REF_A = "resource:" + ("a" * 51) + "a"
REF_B = "resource:" + ("b" * 51) + "a"
REF_C = "resource:" + ("c" * 51) + "a"
DAY = "2026-11-10"
KEY_ID = "key:ed25519:" + ("a" * 64)
BINDING = "binding:meta-primary"
ACCOUNT = "account:ibvi-01"
CANDIDATE_AT = "2026-11-11T04:15:00.000000Z"
REFERENCE_AT = "2026-11-11T04:17:30.000000Z"


# ---------------------------------------------------------------------------
# Independent oracles and the defect-code accessor
# ---------------------------------------------------------------------------


def oracle_jcs(value: object) -> bytes:
    """RFC 8785 for the ASCII-only, string-and-null documents used in these tests."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def oracle_domain_digest(prefix: str, value: object) -> str:
    payload = prefix.encode("utf-8") + b"\x00" + oracle_jcs(value)
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def code_of(excinfo: pytest.ExceptionInfo[BaseException]) -> str:
    error = excinfo.value
    if not isinstance(error, Bundle7BDefectError) or error.code not in b7.DEFECT_CODES:
        raise AssertionError(f"not a coded 7B defect: {error!r}")
    return error.code


def sha(fill: str) -> str:
    return "sha256:" + (fill * 64)


def loc(artifact_type: str, fill: str = "a") -> ArtifactLocator:
    return ArtifactLocator.from_digest(artifact_type, sha(fill))


def signature() -> str:
    return base64.b64encode(bytes(64)).decode("ascii")


def registry_loc() -> ArtifactLocator:
    return loc("smart_ads/key_authorization_registry/v1", "9")


# ---------------------------------------------------------------------------
# Facts, results and selectors
# ---------------------------------------------------------------------------


def row_key(
    resource_ref: str = REF_A,
    *,
    metric_date: str = DAY,
    breakdown_signature: str = "breakdown:none",
) -> ReconciliationRowKey:
    return ReconciliationRowKey(
        resource_ref=resource_ref,
        metric_date=metric_date,
        resource_level="campaign",
        breakdown_signature=breakdown_signature,
    )


_SOURCES = {"candidate": "pipeboard", "reference": "meta"}


def fact(
    resource_ref: str,
    metric: str,
    raw: str | None,
    *,
    side: str = "candidate",
    presence_status: str = "observed",
    metric_date: str = DAY,
    currency: str = "BRL",
    binding_ref: str = BINDING,
    account_ref: str = ACCOUNT,
) -> NormalizedCollectionFact:
    short = metric.split(":", 1)[1].rsplit("_", 1)[0]
    is_money = metric == SPEND
    observed = presence_status == "observed"
    return NormalizedCollectionFact(
        fact_key=FactKey(
            binding_ref=binding_ref,
            account_ref=account_ref,
            resource_ref=resource_ref,
            resource_level="campaign",
            metric_date=metric_date,
            metric_semantic_ref=metric,
            source_metric_ref=f"source-metric:provider:{_SOURCES[side]}.{short}:v1",
            attribution_ref="attribution:not_applicable",
            breakdown_signature="breakdown:none",
        ),
        presence_status=presence_status,  # type: ignore[arg-type]
        value_type=(("int64_minor_currency" if is_money else "int64_count") if observed else None),
        raw_numeric_value=raw if observed else None,
        unit=(("minor_currency" if is_money else "count") if observed else None),
        currency=(currency if is_money and observed else None),
    )


def facts_for(
    values: dict[tuple[str, str], str], *, side: str = "candidate", **overrides: Any
) -> list[NormalizedCollectionFact]:
    return [
        fact(ref, metric, raw, side=side, **overrides) for (ref, metric), raw in values.items()
    ]


BASE_VALUES: dict[tuple[str, str], str] = {
    (REF_A, IMPRESSIONS): "1000",
    (REF_A, CLICKS): "100",
    (REF_A, SPEND): "50000",
    (REF_B, IMPRESSIONS): "0",
    (REF_B, CLICKS): "0",
    (REF_B, SPEND): "0",
}
CANDIDATE_VALUES = {**BASE_VALUES, (REF_A, CLICKS): "101"}


def many_resource_refs(count: int) -> list[str]:
    """``count`` distinct canonical 256-bit base32 resource refs."""
    refs = []
    for index in range(count):
        raw = hashlib.sha256(f"resource-{index}".encode("ascii")).digest()
        refs.append("resource:" + base64.b32encode(raw).decode("ascii").rstrip("=").lower())
    return refs


def many_rows(count: int) -> dict[tuple[str, str], str]:
    return {
        (ref, metric): "7" for ref in many_resource_refs(count) for metric in (
            IMPRESSIONS, CLICKS, SPEND
        )
    }


class LocatorCallCounter:
    """Counts whole-result canonicalizations through ``collection_result_locator``."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from smart_ads.reconciliation import bundle_evidence, bundle_verify

        self.calls = 0
        original = bundle_evidence.collection_result_locator

        def counting(result: CollectionResult) -> ArtifactLocator:
            self.calls += 1
            return original(result)

        for module in (bundle_evidence, bundle_verify):
            monkeypatch.setattr(module, "collection_result_locator", counting, raising=False)


def transport_ok() -> TransportOutcome:
    return TransportOutcome(
        network_ok=True,
        http_status=200,
        media_and_encoding_valid=True,
        auth_ok=True,
        jsonrpc_error=False,
        payload_schema_valid=True,
        response_date_mismatch=False,
        truncated_2mib=False,
        non_empty_continuation=False,
        reducer_order_or_count_mismatch=False,
        duplicate_provider_observation=False,
    )


def collection_result(
    facts: list[NormalizedCollectionFact],
    *,
    side: str,
    retrieved_at: str,
    admitted_locator: ArtifactLocator | None = None,
    registry_locator: ArtifactLocator | None = None,
) -> CollectionResult:
    adm = admitted_locator or loc("smart_ads/admitted_collection/v1", "c")
    reg = registry_locator or loc("smart_ads/private_registry_snapshot/v1", "d")
    ctx = RetrievalContext(
        retrieved_at_utc=retrieved_at,
        source_observation_ref=f"observation:{side}-001",
        adapter_version=f"{side}-adapter-1.0.0",
        semantic_version="smart-ads-semantic-1.0.0",
    )
    sorted_facts, digest = compute_normalized_fact_set_digest(facts)
    query_currency = next(
        (f.currency for f in sorted_facts if f.value_type == "int64_minor_currency" and f.currency),
        "BRL",
    )
    rows = sorted(
        (
            project_collection_fact_to_landing_row(f, ctx, query_currency=query_currency)
            for f in sorted_facts
        ),
        key=lambda row: row.candidate_sort_key_jcs(),
    )
    return CollectionResult(
        admitted_collection_locator=adm,
        admitted_collection_digest=adm.content_digest,
        call_side=side,  # type: ignore[arg-type]
        registry_snapshot_locator=reg,
        registry_snapshot_digest=reg.content_digest,
        requested_capabilities=("cap:campaign-basic-v1",),
        observed_capabilities=("cap:campaign-basic-v1",),
        retrieval_context=ctx,
        transport_outcome=transport_ok(),
        candidates=tuple(rows),
        normalized_fact_set=sorted_facts,
        normalized_fact_set_digest=digest,
        normalized_errors=(),
    )


def oracle_result_locator(result: CollectionResult) -> ArtifactLocator:
    digest = "sha256:" + hashlib.sha256(oracle_jcs(result.to_dict())).hexdigest()
    return ArtifactLocator.from_digest("smart_ads/collection_result/v1", digest)


@pytest.fixture
def cand_result() -> CollectionResult:
    return collection_result(facts_for(BASE_VALUES), side="candidate", retrieved_at=CANDIDATE_AT)


@pytest.fixture
def ref_result() -> CollectionResult:
    return collection_result(
        facts_for(BASE_VALUES, side="reference"), side="reference", retrieved_at=REFERENCE_AT
    )


def side_for(result: CollectionResult, pair: MetricPairKey) -> b7.ReconciliationSide:
    selector = b7.select_fact_evidence(result, pair)
    return b7.ReconciliationSide.for_fact(b7.resolve_fact_evidence(selector, result), selector)


TOLERANCE_LOC = loc("smart_ads/tolerance_profile/v1", "7")
EXACT_ROW = {
    "measured_absolute_delta": "0",
    "measured_relative_delta": "0.000000",
    "relative_delta_status": "computed",
    "reconciliation_outcome": "exact_match",
    "metric_verification_status": "VERIFIED",
}
WITHIN_TOLERANCE_ROW = {
    "measured_absolute_delta": "1",
    "measured_relative_delta": "0.010000",
    "relative_delta_status": "computed",
    "reconciliation_outcome": "within_declared_tolerance",
    "metric_verification_status": "VERIFIED",
}


def reconciliation_dict(
    cand_result: CollectionResult,
    ref_result: CollectionResult,
    pair: MetricPairKey,
    comparison: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "canonical_fact_key": pair.canonical_fact_key.to_dict(),
        "canonical_fact_key_digest": compute_canonical_fact_key_digest(pair.canonical_fact_key),
        "canonical_metric_ref": pair.canonical_metric_ref,
        "candidate": side_for(cand_result, pair).to_dict(),
        "reference": side_for(ref_result, pair).to_dict(),
        "tolerance_profile_locator": TOLERANCE_LOC.to_dict(),
        **(comparison if comparison is not None else EXACT_ROW),
    }


# ---------------------------------------------------------------------------
# Fingerprint, canonical query and native projection
# ---------------------------------------------------------------------------

FINGERPRINT_MEMBERS = (
    "selected_meta_api_version",
    "reference_client_identity_digest",
    "official_source_locators_digest",
    "candidate_driver_contract_digest",
    "canonical_query_digest",
    "parser_code_digest",
    "adapter_code_digest",
    "mapping_rules_digest",
    "schema_bundle_digest",
    "resource_mapping_contract_digest",
    "authorized_certification_scope",
)
SCOPE = "scope:campaigns-active"


def fingerprint_dict(**overrides: str) -> dict[str, str]:
    base = {
        "selected_meta_api_version": "v21.0",
        "reference_client_identity_digest": sha("1"),
        "official_source_locators_digest": sha("2"),
        "candidate_driver_contract_digest": sha("3"),
        "canonical_query_digest": sha("4"),
        "parser_code_digest": sha("5"),
        "adapter_code_digest": sha("6"),
        "mapping_rules_digest": sha("7"),
        "schema_bundle_digest": sha("8"),
        "resource_mapping_contract_digest": sha("9"),
        "authorized_certification_scope": SCOPE,
    }
    base.update(overrides)
    return base


def different_value(member: str, value: str) -> str:
    if member == "selected_meta_api_version":
        return "v22.0"
    if member == "authorized_certification_scope":
        return "scope:other-scope"
    return sha("f") if value != sha("f") else sha("e")


def canonical_query() -> CanonicalQueryContract:
    return CanonicalQueryContract(
        tenant_ref="tenant:ibvi",
        binding_ref=BINDING,
        account_ref=ACCOUNT,
        resource_scope_ref="scope:campaigns-active",
        ad_platform_ref="meta",
        date_rule="previous_local_day",
        date_range=DateRange(start_date=DAY, end_date=DAY, inclusive=True),
        reporting_timezone="America/Sao_Paulo",
        tzdb_version="2026a",
        resource_level="campaign",
        metric_semantic_refs=(CLICKS, IMPRESSIONS, SPEND),
        requested_capabilities=("cap:campaign-basic-v1",),
    )


QUERY_DIGEST = canonical_query().canonical_query_digest


def native_dict(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "$schema": "smart_ads/native_request_projection/v1",
        "endpoint": "/v21.0/insights",
        "http_method": "GET",
        "endpoint_version_ref": "api-version:v21.0",
        "resource_refs": [REF_A, REF_B],
        "date_range": {"start_date": DAY, "end_date": DAY, "inclusive": True},
        "resource_level": "campaign",
        "metrics": ["clicks", "impressions", "spend"],
        "breakdowns": [],
        "pagination": "complete_result_required",
        "currency": "BRL",
        "attribution_omission_state": "omitted",
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Tolerance profiles and reconciliation
# ---------------------------------------------------------------------------

GATE3_LOC = loc("smart_ads/gate3_selection_receipt/v1", "1")
RUN_LOC = loc("smart_ads/migration_run_context/v1", "3")


def profile_dict(
    metric: str,
    *,
    max_abs: str = "0",
    max_rel: str = "0.000000",
    query_digest: str = QUERY_DIGEST,
    scope: str = SCOPE,
    gate3: ArtifactLocator = GATE3_LOC,
    run: ArtifactLocator = RUN_LOC,
    signed: bool = True,
) -> dict[str, Any]:
    exact = max_abs == "0" and max_rel == "0.000000"
    data: dict[str, Any] = {
        "$schema": "smart_ads/tolerance_profile/v1",
        "canonical_metric_ref": metric,
        "value_type": "int64_minor_currency" if metric == SPEND else "int64_count",
        "max_absolute_delta": max_abs,
        "max_relative_delta": max_rel,
        "decimal_scale": 6,
        "rounding_mode": "ROUND_HALF_UP",
        "reference_zero_rule": "exact_zero_only",
        "authorization_binding": None if exact else {
            "gate3_selection_locator": gate3.to_dict(),
            "canonical_query_digest": query_digest,
            "authorized_certification_scope": scope,
            "migration_run_context_locator": run.to_dict(),
        },
    }
    if signed:
        data["integrity"] = {
            "key_id": KEY_ID, "key_registry_snapshot_locator": registry_loc().to_dict()
        }
        data["integrity"].update(
            content_digest=p1_content_digest(data), signature_base64=signature()
        )
    return data


def default_profiles(scope: str = SCOPE) -> dict[str, dict[str, Any]]:
    return {
        IMPRESSIONS: profile_dict(IMPRESSIONS),
        CLICKS: profile_dict(CLICKS, max_abs="5", max_rel="0.050000", scope=scope),
        SPEND: profile_dict(SPEND),
    }


def oracle_profile_locator(data: dict[str, Any]) -> ArtifactLocator:
    digest = "sha256:" + hashlib.sha256(oracle_jcs(data)).hexdigest()
    return ArtifactLocator.from_digest("smart_ads/tolerance_profile/v1", digest)


def reconcile(
    cand: CollectionResult,
    ref: CollectionResult,
    profiles: dict[str, dict[str, Any]] | None = None,
    **overrides: Any,
) -> b7.Reconciliation7BResult:
    kwargs: dict[str, Any] = {
        "candidate_result": cand,
        "reference_result": ref,
        "tolerance_profiles": default_profiles() if profiles is None else profiles,
        "gate3_selection_locator": GATE3_LOC,
        "canonical_query_contract": canonical_query(),
        "authorized_certification_scope": SCOPE,
        "migration_run_context_locator": RUN_LOC,
    }
    kwargs.update(overrides)
    return b7.reconcile_7b_fact_sets(**kwargs)


def results(
    cand_values: dict[tuple[str, str], str] = CANDIDATE_VALUES,
    ref_values: dict[tuple[str, str], str] = BASE_VALUES,
    *,
    cand_at: str = CANDIDATE_AT,
    ref_at: str = REFERENCE_AT,
    cand_facts: list[NormalizedCollectionFact] | None = None,
    ref_facts: list[NormalizedCollectionFact] | None = None,
) -> tuple[CollectionResult, CollectionResult]:
    cand = collection_result(
        cand_facts if cand_facts is not None else facts_for(cand_values),
        side="candidate", retrieved_at=cand_at,
    )
    ref = collection_result(
        ref_facts if ref_facts is not None else facts_for(ref_values, side="reference"),
        side="reference", retrieved_at=ref_at,
    )
    return cand, ref
