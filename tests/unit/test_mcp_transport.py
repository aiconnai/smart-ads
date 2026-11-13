"""Unit tests for closed 5-method MCP schemas, /ibvi-ads delegation gate, and zero-I/O gateway."""
from __future__ import annotations

import base64
from collections.abc import Mapping
import dataclasses
from typing import Any

import pytest

from smart_ads.contracts import (
    ArtifactLocator,
    ClosedValidationError,
    DateRange,
    canonicalize_jcs,
    loads_strict_json,
    validate_resource_ref,
)
from smart_ads.transports.mcp import (
    ALLOWED_FINDING_TYPES,
    ALLOWED_MCP_METHODS,
    AdmittedMcpRequest,
    IntelligenceFindingsQueryParams,
    McpDelegationContext,
    McpProtocolRejection,
    McpReadHandlerPort,
    McpRuntimeContext,
    McpWireOutcome,
    PerformanceQueryParams,
    RecurrentSummaryReportParams,
    handle_mcp_request_bytes,
    validate_mcp_method_params,
    verify_mcp_delegation_context,
)
from smart_ads.transports.mcp.protocol import _NonExactJsonNumber

PERF_METHODS = (
    "smart_ads.queries.get_ad_performance_v1",
    "smart_ads.queries.get_adset_performance_v1",
    "smart_ads.queries.get_campaign_performance_v1",
)
FINDINGS_METHOD = "smart_ads.queries.get_intelligence_findings_v1"
SUMMARY_METHOD = "smart_ads.reports.generate_recurrent_summary_v1"


def _res_ref(idx: int) -> str:
    raw = idx.to_bytes(32, "big")
    body = base64.b32encode(raw).decode("ascii").rstrip("=").lower()
    return validate_resource_ref(f"resource:{body}")


def _snapshot_locator_dict(
    artifact_type: str = "smart_ads/dataset_snapshot/v1",
    digest_char: str = "c",
) -> dict[str, Any]:
    return ArtifactLocator.from_digest(
        artifact_type, "sha256:" + (digest_char * 64)
    ).to_dict()


def _valid_delegation(
    *,
    allowed_method: str = "smart_ads.queries.get_campaign_performance_v1",
    schema: str = "smart_ads/ibvi_ads_delegation_context/v1",
    route: str = "/ibvi-ads",
    host_conductor_ref: str = "conductor:hermes",
    front_ref: str = "front:pinna",
    profile_ref: str = "profile:pinna-ops",
    tenant_ref: str = "tenant:ibvi",
    binding_ref: str = "binding:meta-1",
    resource_scope_ref: str = "scope:ibvi-1",
    policy_digest: str = "sha256:" + ("d" * 64),
    issued_at_utc: str = "2026-11-12T12:00:00Z",
    valid_until_utc: str = "2026-11-12T12:15:00Z",
    nonce: str = "nonce-ok-01",
    locator: ArtifactLocator | None = None,
) -> McpDelegationContext:
    loc = locator or ArtifactLocator.from_digest(
        "smart_ads/ibvi_ads_delegation_context/v1",
        "sha256:" + ("e" * 64),
    )
    return McpDelegationContext(
        schema=schema,
        route=route,
        host_conductor_ref=host_conductor_ref,
        front_ref=front_ref,
        profile_ref=profile_ref,
        tenant_ref=tenant_ref,
        binding_ref=binding_ref,
        resource_scope_ref=resource_scope_ref,
        allowed_method=allowed_method,
        policy_digest=policy_digest,
        issued_at_utc=issued_at_utc,
        valid_until_utc=valid_until_utc,
        nonce=nonce,
        locator=loc,
    )


def _valid_runtime(
    *,
    allowed_method: str = "smart_ads.queries.get_campaign_performance_v1",
    clock_lower_utc: str = "2026-11-12T12:01:00Z",
    clock_upper_utc: str = "2026-11-12T12:01:02Z",
    delegation: McpDelegationContext | None = None,
) -> McpRuntimeContext:
    return McpRuntimeContext(
        clock_lower_utc=clock_lower_utc,
        clock_upper_utc=clock_upper_utc,
        delegation_context=delegation
        if delegation is not None
        else _valid_delegation(allowed_method=allowed_method),
    )


def test_allowed_methods_and_finding_types_constants() -> None:
    assert ALLOWED_MCP_METHODS == (
        "smart_ads.queries.get_ad_performance_v1",
        "smart_ads.queries.get_adset_performance_v1",
        "smart_ads.queries.get_campaign_performance_v1",
        "smart_ads.queries.get_intelligence_findings_v1",
        "smart_ads.reports.generate_recurrent_summary_v1",
    )
    assert ALLOWED_FINDING_TYPES == frozenset(
        {"restatement", "saturation", "stalled_delivery", "waste"}
    )


@pytest.mark.parametrize("method", PERF_METHODS)
def test_performance_methods_valid_minimal_and_full_and_direct_date_range(
    method: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _forbid_from_dict(*args: object, **kwargs: object) -> DateRange:
        raise AssertionError("DateRange.from_dict must NEVER be called by MCP schemas")

    monkeypatch.setattr(DateRange, "from_dict", _forbid_from_dict)

    minimal_raw = {
        "tenant_ref": "tenant:ibvi",
        "binding_ref": "binding:meta-1",
        "resource_scope_ref": "scope:ibvi-1",
        "date_range": {"start_date": "2026-11-01", "end_date": "2026-11-10"},
    }
    res_min = validate_mcp_method_params(
        method, True, minimal_raw, request_id="req-1"
    )
    assert res_min == PerformanceQueryParams(
        method=method,
        tenant_ref="tenant:ibvi",
        binding_ref="binding:meta-1",
        resource_scope_ref="scope:ibvi-1",
        date_range=DateRange(start_date="2026-11-01", end_date="2026-11-10"),
        resource_refs=(),
        metric_refs=(),
    )

    refs_sorted = sorted([_res_ref(1), _res_ref(2)], key=lambda s: s.encode("utf-8"))
    metrics_sorted = ["metric:clicks_v1", "metric:impressions_v1", "metric:spend_v1"]
    full_raw = {
        **minimal_raw,
        "resource_refs": refs_sorted,
        "metric_refs": metrics_sorted,
    }
    res_full = validate_mcp_method_params(
        method, True, full_raw, request_id=42
    )
    assert res_full == PerformanceQueryParams(
        method=method,
        tenant_ref="tenant:ibvi",
        binding_ref="binding:meta-1",
        resource_scope_ref="scope:ibvi-1",
        date_range=DateRange(start_date="2026-11-01", end_date="2026-11-10"),
        resource_refs=tuple(refs_sorted),
        metric_refs=tuple(metrics_sorted),
    )


def test_intelligence_findings_and_recurrent_summary_valid_params() -> None:
    snap_dict = _snapshot_locator_dict()
    snap_obj = ArtifactLocator.from_dict(snap_dict)

    findings_min = validate_mcp_method_params(
        FINDINGS_METHOD,
        True,
        {
            "tenant_ref": "tenant:ibvi",
            "binding_ref": "binding:meta-1",
            "resource_scope_ref": "scope:ibvi-1",
            "dataset_snapshot_locator": snap_dict,
        },
        request_id="f-1",
    )
    assert findings_min == IntelligenceFindingsQueryParams(
        tenant_ref="tenant:ibvi",
        binding_ref="binding:meta-1",
        resource_scope_ref="scope:ibvi-1",
        dataset_snapshot_locator=snap_obj,
        finding_types=(),
    )

    findings_full = validate_mcp_method_params(
        FINDINGS_METHOD,
        True,
        {
            "tenant_ref": "tenant:ibvi",
            "binding_ref": "binding:meta-1",
            "resource_scope_ref": "scope:ibvi-1",
            "dataset_snapshot_locator": snap_dict,
            "finding_types": [
                "restatement",
                "saturation",
                "stalled_delivery",
                "waste",
            ],
        },
        request_id="f-2",
    )
    assert findings_full == IntelligenceFindingsQueryParams(
        tenant_ref="tenant:ibvi",
        binding_ref="binding:meta-1",
        resource_scope_ref="scope:ibvi-1",
        dataset_snapshot_locator=snap_obj,
        finding_types=(
            "restatement",
            "saturation",
            "stalled_delivery",
            "waste",
        ),
    )

    summary_daily = validate_mcp_method_params(
        SUMMARY_METHOD,
        True,
        {
            "tenant_ref": "tenant:ibvi",
            "binding_ref": "binding:meta-1",
            "resource_scope_ref": "scope:ibvi-1",
            "dataset_snapshot_locator": snap_dict,
            "cadence": "daily",
            "period_start_date": "2026-11-10",
            "period_end_date": "2026-11-10",
        },
        request_id="s-1",
    )
    assert summary_daily == RecurrentSummaryReportParams(
        tenant_ref="tenant:ibvi",
        binding_ref="binding:meta-1",
        resource_scope_ref="scope:ibvi-1",
        dataset_snapshot_locator=snap_obj,
        cadence="daily",
        period_start_date="2026-11-10",
        period_end_date="2026-11-10",
    )

    summary_weekly = validate_mcp_method_params(
        SUMMARY_METHOD,
        True,
        {
            "tenant_ref": "tenant:ibvi",
            "binding_ref": "binding:meta-1",
            "resource_scope_ref": "scope:ibvi-1",
            "dataset_snapshot_locator": snap_dict,
            "cadence": "weekly",
            "period_start_date": "2026-11-04",
            "period_end_date": "2026-11-10",
        },
        request_id="s-2",
    )
    assert summary_weekly == RecurrentSummaryReportParams(
        tenant_ref="tenant:ibvi",
        binding_ref="binding:meta-1",
        resource_scope_ref="scope:ibvi-1",
        dataset_snapshot_locator=snap_obj,
        cadence="weekly",
        period_start_date="2026-11-04",
        period_end_date="2026-11-10",
    )


def test_unsupported_method_precedes_missing_or_bad_params() -> None:
    rej = validate_mcp_method_params(
        "smart_ads.queries.unknown_v1",
        False,
        None,
        request_id="req-u",
    )
    assert rej == McpProtocolRejection(
        code=-32601,
        message="Method not found",
        request_id="req-u",
        case_id="unsupported_method",
    )


@pytest.mark.parametrize(
    ("has_params", "params_raw"),
    [
        (False, None),
        (True, None),
        (True, []),
        (True, [1, 2]),
        (True, "str"),
        (True, 123),
        (True, True),
        (True, _NonExactJsonNumber("1.5")),
    ],
)
def test_missing_or_non_dict_params_rejected_as_invalid_params(
    has_params: bool, params_raw: Any
) -> None:
    rej = validate_mcp_method_params(
        "smart_ads.queries.get_ad_performance_v1",
        has_params,
        params_raw,
        request_id="req-p",
    )
    assert rej == McpProtocolRejection(
        code=-32602,
        message="Invalid params",
        request_id="req-p",
        case_id="invalid_params",
    )


@pytest.mark.parametrize(
    ("extra_key", "extra_val"),
    [
        ("delegation_context", {"route": "/ibvi-ads"}),
        ("ibvi_ads_delegation_context", {"route": "/ibvi-ads"}),
        ("file_path", "/tmp/out.json"),
        ("output_path", "/tmp/out.json"),
        ("object_id", "act_123456"),
        ("account_id", "123456"),
        ("extra", _NonExactJsonNumber("1.5")),
    ],
)
def test_additional_properties_top_level_rejected_across_all_5_methods(
    extra_key: str, extra_val: Any
) -> None:
    perf_base = {
        "tenant_ref": "tenant:ibvi",
        "binding_ref": "binding:meta-1",
        "resource_scope_ref": "scope:ibvi-1",
        "date_range": {"start_date": "2026-11-01", "end_date": "2026-11-10"},
        extra_key: extra_val,
    }
    for m in PERF_METHODS:
        assert validate_mcp_method_params(
            m, True, perf_base, request_id="id-1"
        ) == McpProtocolRejection(
            code=-32602,
            message="Invalid params",
            request_id="id-1",
            case_id="additional_property",
        )

    findings_base = {
        "tenant_ref": "tenant:ibvi",
        "binding_ref": "binding:meta-1",
        "resource_scope_ref": "scope:ibvi-1",
        "dataset_snapshot_locator": _snapshot_locator_dict(),
        extra_key: extra_val,
    }
    assert validate_mcp_method_params(
        FINDINGS_METHOD, True, findings_base, request_id="id-2"
    ) == McpProtocolRejection(
        code=-32602,
        message="Invalid params",
        request_id="id-2",
        case_id="additional_property",
    )

    summary_base = {
        "tenant_ref": "tenant:ibvi",
        "binding_ref": "binding:meta-1",
        "resource_scope_ref": "scope:ibvi-1",
        "dataset_snapshot_locator": _snapshot_locator_dict(),
        "cadence": "daily",
        "period_start_date": "2026-11-10",
        "period_end_date": "2026-11-10",
        extra_key: extra_val,
    }
    assert validate_mcp_method_params(
        SUMMARY_METHOD, True, summary_base, request_id="id-3"
    ) == McpProtocolRejection(
        code=-32602,
        message="Invalid params",
        request_id="id-3",
        case_id="additional_property",
    )

    # Wire check with non-exact float 1.5 under unknown key -> additional_property
    wire_extra_float = (
        b'{"jsonrpc":"2.0","id":"w-extra","method":"smart_ads.queries.get_ad_performance_v1",'
        b'"params":{"tenant_ref":"tenant:ibvi","binding_ref":"binding:meta-1",'
        b'"resource_scope_ref":"scope:ibvi-1",'
        b'"date_range":{"start_date":"2026-11-01","end_date":"2026-11-10"},"extra":1.5}}'
    )
    out = handle_mcp_request_bytes(wire_extra_float, _valid_runtime(allowed_method="smart_ads.queries.get_ad_performance_v1"))
    assert out.rejection == McpProtocolRejection(
        code=-32602,
        message="Invalid params",
        request_id="w-extra",
        case_id="additional_property",
    )


def test_additional_properties_nested_in_date_range_and_dataset_snapshot_locator() -> None:
    # Nested date_range extra keys (including "inclusive": True and "inclusive": False!)
    for bad_dr in (
        {"start_date": "2026-11-01", "end_date": "2026-11-10", "inclusive": True},
        {"start_date": "2026-11-01", "end_date": "2026-11-10", "inclusive": False},
        {"start_date": "2026-11-01", "end_date": "2026-11-10", "extra": _NonExactJsonNumber("1.5")},
        {"inclusive": True},
    ):
        rej = validate_mcp_method_params(
            "smart_ads.queries.get_campaign_performance_v1",
            True,
            {
                "tenant_ref": "tenant:ibvi",
                "binding_ref": "binding:meta-1",
                "resource_scope_ref": "scope:ibvi-1",
                "date_range": bad_dr,
            },
            request_id="dr-extra",
        )
        assert rej == McpProtocolRejection(
            code=-32602,
            message="Invalid params",
            request_id="dr-extra",
            case_id="additional_property",
        )

    # Nested dataset_snapshot_locator extra keys (including legacy/wrong "locator" key)
    for extra_field in (
        {"locator": "cell-object:sha256:" + ("c" * 64)},
        {"git_commit": "a" * 40},
        {"extra_num": _NonExactJsonNumber("1.5")},
    ):
        bad_loc = {**_snapshot_locator_dict(), **extra_field}
        for method_name, extra_params in (
            (FINDINGS_METHOD, {}),
            (
                SUMMARY_METHOD,
                {
                    "cadence": "daily",
                    "period_start_date": "2026-11-10",
                    "period_end_date": "2026-11-10",
                },
            ),
        ):
            rej_loc = validate_mcp_method_params(
                method_name,
                True,
                {
                    "tenant_ref": "tenant:ibvi",
                    "binding_ref": "binding:meta-1",
                    "resource_scope_ref": "scope:ibvi-1",
                    "dataset_snapshot_locator": bad_loc,
                    **extra_params,
                },
                request_id="loc-extra",
            )
            assert rej_loc == McpProtocolRejection(
                code=-32602,
                message="Invalid params",
                request_id="loc-extra",
                case_id="additional_property",
            )


@pytest.mark.parametrize("raw_num_token", ["1.5", "9007199254740992", "-9007199254740992", "1e5"])
def test_non_exact_json_numbers_in_known_fields_rejected_as_invalid_params(
    raw_num_token: str,
) -> None:
    wire = (
        f'{{"jsonrpc":"2.0","id":"num-1","method":"smart_ads.queries.get_campaign_performance_v1",'
        f'"params":{{"tenant_ref":{raw_num_token},"binding_ref":"binding:meta-1",'
        f'"resource_scope_ref":"scope:ibvi-1",'
        f'"date_range":{{"start_date":"2026-11-01","end_date":"2026-11-10"}}}}}}'
    ).encode("utf-8")
    out = handle_mcp_request_bytes(wire, _valid_runtime())
    assert out.rejection == McpProtocolRejection(
        code=-32602,
        message="Invalid params",
        request_id="num-1",
        case_id="invalid_params",
    )

    wire_nested = (
        f'{{"jsonrpc":"2.0","id":"num-2","method":"smart_ads.queries.get_campaign_performance_v1",'
        f'"params":{{"tenant_ref":"tenant:ibvi","binding_ref":"binding:meta-1",'
        f'"resource_scope_ref":"scope:ibvi-1",'
        f'"date_range":{{"start_date":{raw_num_token},"end_date":"2026-11-10"}}}}}}'
    ).encode("utf-8")
    out_nested = handle_mcp_request_bytes(wire_nested, _valid_runtime())
    assert out_nested.rejection == McpProtocolRejection(
        code=-32602,
        message="Invalid params",
        request_id="num-2",
        case_id="invalid_params",
    )


def test_performance_methods_negative_cases() -> None:
    r1 = _res_ref(1)
    r2 = _res_ref(2)
    sorted_pair = sorted([r1, r2], key=lambda s: s.encode("utf-8"))
    reversed_pair = list(reversed(sorted_pair))

    base = {
        "tenant_ref": "tenant:ibvi",
        "binding_ref": "binding:meta-1",
        "resource_scope_ref": "scope:ibvi-1",
        "date_range": {"start_date": "2026-11-01", "end_date": "2026-11-10"},
    }
    invalid_variants: list[dict[str, Any]] = [
        {k: v for k, v in base.items() if k != "tenant_ref"},
        {k: v for k, v in base.items() if k != "date_range"},
        {**base, "tenant_ref": "binding:wrong-prefix"},
        {**base, "binding_ref": "tenant:wrong-prefix"},
        {**base, "resource_scope_ref": "tenant:wrong-prefix"},
        {**base, "date_range": None},
        {**base, "date_range": ["2026-11-01", "2026-11-10"]},
        {**base, "date_range": {"start_date": "2026-11-01"}},
        {**base, "date_range": {"start_date": "2026-11-11", "end_date": "2026-11-10"}},
        {**base, "date_range": {"start_date": "2026-02-29", "end_date": "2026-03-01"}},
        {**base, "date_range": {"start_date": 20261101, "end_date": "2026-11-10"}},
        {**base, "resource_refs": None},
        {**base, "resource_refs": []},
        {**base, "resource_refs": "not-a-list"},
        {**base, "resource_refs": ["resource:foo"]},
        {**base, "resource_refs": ["act_123456"]},
        {**base, "resource_refs": [sorted_pair[0], sorted_pair[0]]},
        {**base, "resource_refs": reversed_pair},
        {**base, "metric_refs": None},
        {**base, "metric_refs": []},
        {**base, "metric_refs": ["cap:wrong_prefix"]},
        {**base, "metric_refs": ["impressions"]},
        {**base, "metric_refs": ["metric:spend_v1", "metric:spend_v1"]},
        {**base, "metric_refs": ["metric:spend_v1", "metric:clicks_v1"]},
    ]
    for method in PERF_METHODS:
        for bad_params in invalid_variants:
            assert validate_mcp_method_params(
                method, True, bad_params, request_id="perf-neg"
            ) == McpProtocolRejection(
                code=-32602,
                message="Invalid params",
                request_id="perf-neg",
                case_id="invalid_params",
            )


def test_intelligence_findings_negative_cases() -> None:
    snap_ok = _snapshot_locator_dict()
    snap_wrong_type = _snapshot_locator_dict(
        artifact_type="smart_ads/admitted_collection/v1"
    )
    snap_missing_key = {
        k: v for k, v in snap_ok.items() if k != "object_ref"
    }
    snap_bad_ref = {**snap_ok, "object_ref": "cell-object:sha256:" + ("0" * 64)}

    base = {
        "tenant_ref": "tenant:ibvi",
        "binding_ref": "binding:meta-1",
        "resource_scope_ref": "scope:ibvi-1",
        "dataset_snapshot_locator": snap_ok,
    }
    for bad_params in (
        {k: v for k, v in base.items() if k != "dataset_snapshot_locator"},
        {**base, "dataset_snapshot_locator": None},
        {**base, "dataset_snapshot_locator": "sha256:" + ("c" * 64)},
        {**base, "dataset_snapshot_locator": snap_wrong_type},
        {**base, "dataset_snapshot_locator": snap_missing_key},
        {**base, "dataset_snapshot_locator": snap_bad_ref},
        {**base, "finding_types": None},
        {**base, "finding_types": []},
        {**base, "finding_types": "waste"},
        {**base, "finding_types": ["unknown"]},
        {**base, "finding_types": ["waste", "waste"]},
        {**base, "finding_types": ["waste", "restatement"]},
        {**base, "finding_types": [123]},
    ):
        assert validate_mcp_method_params(
            FINDINGS_METHOD, True, bad_params, request_id="find-neg"
        ) == McpProtocolRejection(
            code=-32602,
            message="Invalid params",
            request_id="find-neg",
            case_id="invalid_params",
        )


def test_recurrent_summary_negative_cases() -> None:
    snap_ok = _snapshot_locator_dict()
    base = {
        "tenant_ref": "tenant:ibvi",
        "binding_ref": "binding:meta-1",
        "resource_scope_ref": "scope:ibvi-1",
        "dataset_snapshot_locator": snap_ok,
        "cadence": "daily",
        "period_start_date": "2026-11-10",
        "period_end_date": "2026-11-10",
    }
    for bad_params in (
        {k: v for k, v in base.items() if k != "cadence"},
        {k: v for k, v in base.items() if k != "period_end_date"},
        {**base, "cadence": "monthly"},
        {**base, "cadence": None},
        {**base, "cadence": 1},
        {
            **base,
            "cadence": "daily",
            "period_start_date": "2026-11-09",
            "period_end_date": "2026-11-10",
        },
        {
            **base,
            "cadence": "weekly",
            "period_start_date": "2026-11-11",
            "period_end_date": "2026-11-10",
        },
        {
            **base,
            "dataset_snapshot_locator": _snapshot_locator_dict(
                artifact_type="smart_ads/collection_result/v1"
            ),
        },
        {**base, "period_start_date": "2026-13-01"},
        {**base, "period_end_date": "not-a-date"},
    ):
        assert validate_mcp_method_params(
            SUMMARY_METHOD, True, bad_params, request_id="sum-neg"
        ) == McpProtocolRejection(
            code=-32602,
            message="Invalid params",
            request_id="sum-neg",
            case_id="invalid_params",
        )


def test_delegation_verification_boundary_and_negative_matrix() -> None:
    method = "smart_ads.queries.get_campaign_performance_v1"
    params = PerformanceQueryParams(
        method=method,
        tenant_ref="tenant:ibvi",
        binding_ref="binding:meta-1",
        resource_scope_ref="scope:ibvi-1",
        date_range=DateRange(start_date="2026-11-01", end_date="2026-11-10"),
    )

    # Exact lower boundary (clock_lower_utc == issued_at_utc) and upper == valid_until - 1s -> VALID
    valid_del = _valid_delegation(allowed_method=method)
    rt_exact_bounds = McpRuntimeContext(
        clock_lower_utc="2026-11-12T12:00:00Z",
        clock_upper_utc="2026-11-12T12:14:59Z",
        delegation_context=valid_del,
    )
    verified = verify_mcp_delegation_context(
        rt_exact_bounds, method=method, params=params, request_id="del-ok"
    )
    assert verified == valid_del

    expected_rej = McpProtocolRejection(
        code=-32600,
        message="Invalid Request",
        request_id="del-bad",
        case_id="missing_or_invalid_ibvi_ads_delegation",
    )

    wrong_loc = ArtifactLocator.from_digest(
        "smart_ads/dataset_snapshot/v1", "sha256:" + ("9" * 64)
    )

    bad_runtimes: list[McpRuntimeContext | None] = [
        None,
        McpRuntimeContext(
            clock_lower_utc="2026-11-12T12:01:00Z",
            clock_upper_utc="2026-11-12T12:01:02Z",
            delegation_context=None,
        ),
        # Route != "/ibvi-ads"
        _valid_runtime(delegation=dataclasses.replace(valid_del, route="/ads")),
        _valid_runtime(delegation=dataclasses.replace(valid_del, route="")),
        _valid_runtime(delegation=dataclasses.replace(valid_del, route="/ibvi-ads/v2")),
        # Schema mismatch
        _valid_runtime(
            delegation=dataclasses.replace(
                valid_del, schema="smart_ads/other_schema/v1"
            )
        ),
        # Allowed method mismatch or outside allowlist
        _valid_runtime(
            delegation=dataclasses.replace(
                valid_del, allowed_method="smart_ads.queries.get_ad_performance_v1"
            )
        ),
        _valid_runtime(
            delegation=dataclasses.replace(
                valid_del, allowed_method="smart_ads.mutations.bad_v1"
            )
        ),
        # Scope trio mismatches against params
        _valid_runtime(
            delegation=dataclasses.replace(valid_del, tenant_ref="tenant:other")
        ),
        _valid_runtime(
            delegation=dataclasses.replace(valid_del, binding_ref="binding:other")
        ),
        _valid_runtime(
            delegation=dataclasses.replace(
                valid_del, resource_scope_ref="scope:other"
            )
        ),
        # Malformed refs / policy_digest / locator
        _valid_runtime(
            delegation=dataclasses.replace(
                valid_del, host_conductor_ref="front:wrong-prefix"
            )
        ),
        _valid_runtime(
            delegation=dataclasses.replace(
                valid_del, front_ref="conductor:wrong-prefix"
            )
        ),
        _valid_runtime(
            delegation=dataclasses.replace(
                valid_del, profile_ref="tenant:wrong-prefix"
            )
        ),
        _valid_runtime(
            delegation=dataclasses.replace(valid_del, policy_digest="sha256:bad")
        ),
        _valid_runtime(
            delegation=dataclasses.replace(valid_del, locator=wrong_loc)
        ),
        # Semi-open UTC window violations: issued_at <= clock_lower <= clock_upper < valid_until
        McpRuntimeContext(
            clock_lower_utc="2026-11-12T12:01:00Z",
            clock_upper_utc="2026-11-12T12:15:00Z",  # == valid_until_utc -> REJECTED!
            delegation_context=valid_del,
        ),
        McpRuntimeContext(
            clock_lower_utc="2026-11-12T11:59:59Z",  # < issued_at_utc -> REJECTED!
            clock_upper_utc="2026-11-12T12:01:00Z",
            delegation_context=valid_del,
        ),
        McpRuntimeContext(
            clock_lower_utc="2026-11-12T12:05:00Z",
            clock_upper_utc="2026-11-12T12:04:59Z",  # lower > upper -> REJECTED!
            delegation_context=valid_del,
        ),
        McpRuntimeContext(
            clock_lower_utc="2026-11-12T12:01:00.000000Z",  # fractional -> REJECTED!
            clock_upper_utc="2026-11-12T12:01:02Z",
            delegation_context=valid_del,
        ),
        _valid_runtime(
            delegation=dataclasses.replace(
                valid_del,
                issued_at_utc="2026-11-12T12:15:00Z",
                valid_until_utc="2026-11-12T12:15:00Z",
            )
        ),
        # Nonce violations: empty, space, >128, control, non-ASCII
        _valid_runtime(delegation=dataclasses.replace(valid_del, nonce="")),
        _valid_runtime(
            delegation=dataclasses.replace(valid_del, nonce="nonce with space")
        ),
        _valid_runtime(delegation=dataclasses.replace(valid_del, nonce="a" * 129)),
        _valid_runtime(delegation=dataclasses.replace(valid_del, nonce="bad\x7f")),
        _valid_runtime(delegation=dataclasses.replace(valid_del, nonce="nônce")),
    ]

    for bad_rt in bad_runtimes:
        assert (
            verify_mcp_delegation_context(
                bad_rt, method=method, params=params, request_id="del-bad"
            )
            == expected_rej
        )

    # Also confirm via full handle_mcp_request_bytes wire path with runtime_context=None
    wire_ok = canonicalize_jcs(
        {
            "jsonrpc": "2.0",
            "id": "wire-del-none",
            "method": method,
            "params": {
                "tenant_ref": "tenant:ibvi",
                "binding_ref": "binding:meta-1",
                "resource_scope_ref": "scope:ibvi-1",
                "date_range": {
                    "start_date": "2026-11-01",
                    "end_date": "2026-11-10",
                },
            },
        }
    )
    out_none = handle_mcp_request_bytes(wire_ok, None)
    assert out_none.admitted_request is None
    assert out_none.rejection == McpProtocolRejection(
        code=-32600,
        message="Invalid Request",
        request_id="wire-del-none",
        case_id="missing_or_invalid_ibvi_ads_delegation",
    )


def test_gateway_post_admission_handler_modes_and_closed_internal_errors() -> None:
    method = "smart_ads.queries.get_campaign_performance_v1"
    rt = _valid_runtime(allowed_method=method)
    raw_req = canonicalize_jcs(
        {
            "jsonrpc": "2.0",
            "id": "gw-1",
            "method": method,
            "params": {
                "tenant_ref": "tenant:ibvi",
                "binding_ref": "binding:meta-1",
                "resource_scope_ref": "scope:ibvi-1",
                "date_range": {
                    "start_date": "2026-11-01",
                    "end_date": "2026-11-10",
                },
            },
        }
    )

    # 1. handler=None -> admitted_request populated, closed -32603 wire_bytes
    out_no_handler = handle_mcp_request_bytes(raw_req, rt, handler=None)
    assert out_no_handler.rejection is None
    assert isinstance(out_no_handler.admitted_request, AdmittedMcpRequest)
    assert out_no_handler.admitted_request.request_id == "gw-1"
    assert out_no_handler.admitted_request.method == method
    assert (
        out_no_handler.wire_bytes
        == b'{"error":{"code":-32603,"message":"Internal error"},"id":"gw-1","jsonrpc":"2.0"}'
    )

    # 2. Valid handler returning {"rows": []}
    received: list[AdmittedMcpRequest] = []

    class _OkHandler:
        def handle(self, request: AdmittedMcpRequest) -> Mapping[str, Any]:
            received.append(request)
            return {"rows": []}

    ok_handler = _OkHandler()
    assert isinstance(ok_handler, McpReadHandlerPort)
    out_ok = handle_mcp_request_bytes(raw_req, rt, handler=ok_handler)
    assert out_ok.rejection is None
    assert out_ok.admitted_request is not None
    assert len(received) == 1
    assert received[0].clock_lower_utc == "2026-11-12T12:01:00Z"
    assert received[0].clock_upper_utc == "2026-11-12T12:01:02Z"
    assert (
        out_ok.wire_bytes
        == b'{"id":"gw-1","jsonrpc":"2.0","result":{"rows":[]}}'
    )

    # 3. Handler raising internal exception -> closed -32603 with zero secret leak
    class _RaisingHandler:
        def handle(self, request: AdmittedMcpRequest) -> Mapping[str, Any]:
            raise RuntimeError("sensitive internal credential token xyz-999")

    out_exc = handle_mcp_request_bytes(raw_req, rt, handler=_RaisingHandler())
    assert out_exc.rejection is None
    assert out_exc.admitted_request is not None
    assert (
        out_exc.wire_bytes
        == b'{"error":{"code":-32603,"message":"Internal error"},"id":"gw-1","jsonrpc":"2.0"}'
    )
    assert b"xyz-999" not in out_exc.wire_bytes
    assert "data" not in loads_strict_json(out_exc.wire_bytes)["error"]

    # 4. Handler returning float or invalid result type -> closed -32603
    for bad_return in (
        {"bad_float": 1.25},
        {"bad_int": 1 << 60},
        ["not", "a", "mapping"],
        {1: "non-str-key"},
    ):

        class _BadResultHandler:
            def __init__(self, payload: Any) -> None:
                self._payload = payload

            def handle(self, request: AdmittedMcpRequest) -> Mapping[str, Any]:
                return self._payload  # type: ignore[return-value]

        out_bad_res = handle_mcp_request_bytes(
            raw_req, rt, handler=_BadResultHandler(bad_return)
        )
        assert out_bad_res.rejection is None
        assert out_bad_res.admitted_request is not None
        assert (
            out_bad_res.wire_bytes
            == b'{"error":{"code":-32603,"message":"Internal error"},"id":"gw-1","jsonrpc":"2.0"}'
        )


def test_python_contract_guards_raise_closed_validation_error() -> None:
    dr = DateRange(start_date="2026-11-01", end_date="2026-11-10")
    with pytest.raises(ClosedValidationError):
        PerformanceQueryParams(
            method="smart_ads.queries.get_intelligence_findings_v1",
            tenant_ref="tenant:ibvi",
            binding_ref="binding:meta-1",
            resource_scope_ref="scope:ibvi-1",
            date_range=dr,
        )

    valid_params = PerformanceQueryParams(
        method="smart_ads.queries.get_campaign_performance_v1",
        tenant_ref="tenant:ibvi",
        binding_ref="binding:meta-1",
        resource_scope_ref="scope:ibvi-1",
        date_range=dr,
    )
    bad_del = _valid_delegation(route="/ads")
    with pytest.raises(ClosedValidationError):
        AdmittedMcpRequest(
            request_id="r-1",
            method="smart_ads.queries.get_campaign_performance_v1",
            params=valid_params,
            delegation_context=bad_del,
            clock_lower_utc="2026-11-12T12:01:00Z",
            clock_upper_utc="2026-11-12T12:01:02Z",
        )

    with pytest.raises(ClosedValidationError):
        McpWireOutcome(wire_bytes=b"{}", rejection=None, admitted_request=None)

    with pytest.raises(ClosedValidationError):
        handle_mcp_request_bytes(b"{}", None, handler=123)  # type: ignore[arg-type]

    with pytest.raises(ClosedValidationError):
        validate_mcp_method_params("", True, {}, request_id="r-1")

    with pytest.raises(ClosedValidationError):
        validate_mcp_method_params(
            "smart_ads.queries.get_campaign_performance_v1",
            1,  # type: ignore[arg-type]
            {},
            request_id="r-1",
        )

    with pytest.raises(ClosedValidationError):
        validate_mcp_method_params(
            "smart_ads.queries.get_campaign_performance_v1",
            True,
            {},
            request_id=True,  # type: ignore[arg-type]
        )

    with pytest.raises(ClosedValidationError):
        verify_mcp_delegation_context(
            _valid_runtime(allowed_method="smart_ads.queries.get_ad_performance_v1"),
            method="smart_ads.queries.get_ad_performance_v1",
            params=valid_params,  # method mismatch against campaign_performance_v1
            request_id="r-1",
        )
