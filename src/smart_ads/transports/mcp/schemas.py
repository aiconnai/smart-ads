"""Closed parameter schemas for the 5 ADR-0001 §3.3 read-only MCP methods."""
from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any, Final, Literal, TypeAlias

from smart_ads.contracts.jcs import ArtifactLocator
from smart_ads.contracts.scalars import (
    ClosedValidationError,
    parse_iso_date,
    validate_iso_date,
    validate_opaque_ref,
    validate_resource_ref,
)
from smart_ads.contracts.schemas import DateRange
from smart_ads.transports.mcp.protocol import (
    JsonRpcRequestId,
    McpProtocolRejection,
    _is_valid_jsonrpc_method_str,
    _is_valid_jsonrpc_request_id,
)

ALLOWED_MCP_METHODS: Final[tuple[str, ...]] = (
    "smart_ads.queries.get_ad_performance_v1",
    "smart_ads.queries.get_adset_performance_v1",
    "smart_ads.queries.get_campaign_performance_v1",
    "smart_ads.queries.get_intelligence_findings_v1",
    "smart_ads.reports.generate_recurrent_summary_v1",
)
_ALLOWED_MCP_METHODS_SET: Final[frozenset[str]] = frozenset(ALLOWED_MCP_METHODS)

ALLOWED_FINDING_TYPES: Final[frozenset[str]] = frozenset(
    {"restatement", "saturation", "stalled_delivery", "waste"}
)

_PERFORMANCE_METHODS: Final[frozenset[str]] = frozenset(
    {
        "smart_ads.queries.get_ad_performance_v1",
        "smart_ads.queries.get_adset_performance_v1",
        "smart_ads.queries.get_campaign_performance_v1",
    }
)
_FINDINGS_METHOD: Final[str] = "smart_ads.queries.get_intelligence_findings_v1"
_SUMMARY_METHOD: Final[str] = "smart_ads.reports.generate_recurrent_summary_v1"

_SCOPE_REQUIRED_KEYS: Final[frozenset[str]] = frozenset(
    {"tenant_ref", "binding_ref", "resource_scope_ref"}
)
_PERF_REQUIRED_KEYS: Final[frozenset[str]] = _SCOPE_REQUIRED_KEYS | {
    "date_range"
}
_PERF_ALLOWED_KEYS: Final[frozenset[str]] = _PERF_REQUIRED_KEYS | {
    "resource_refs",
    "metric_refs",
}

_FINDINGS_REQUIRED_KEYS: Final[frozenset[str]] = _SCOPE_REQUIRED_KEYS | {
    "dataset_snapshot_locator"
}
_FINDINGS_ALLOWED_KEYS: Final[frozenset[str]] = _FINDINGS_REQUIRED_KEYS | {
    "finding_types"
}

_SUMMARY_REQUIRED_KEYS: Final[frozenset[str]] = _SCOPE_REQUIRED_KEYS | {
    "dataset_snapshot_locator",
    "cadence",
    "period_start_date",
    "period_end_date",
}
_SUMMARY_ALLOWED_KEYS: Final[frozenset[str]] = _SUMMARY_REQUIRED_KEYS

_WIRE_DATE_RANGE_KEYS: Final[frozenset[str]] = frozenset(
    {"start_date", "end_date"}
)
_ARTIFACT_LOCATOR_KEYS: Final[frozenset[str]] = frozenset(
    {
        "$schema",
        "artifact_type",
        "content_digest",
        "serialization",
        "store_kind",
        "object_ref",
    }
)
_DATASET_SNAPSHOT_SCHEMA: Final[str] = "smart_ads/dataset_snapshot/v1"
_ALLOWED_CADENCES: Final[frozenset[str]] = frozenset({"daily", "weekly"})

SummaryCadence: TypeAlias = Literal["daily", "weekly"]


def _require_exact_str(value: object, *, field_name: str) -> str:
    if type(value) is not str:
        raise ClosedValidationError(f"{field_name}: expected exact str")
    return value


def _validate_scope_trio(
    tenant_ref: object,
    binding_ref: object,
    resource_scope_ref: object,
) -> tuple[str, str, str]:
    t_str = _require_exact_str(tenant_ref, field_name="params.tenant_ref")
    b_str = _require_exact_str(binding_ref, field_name="params.binding_ref")
    s_str = _require_exact_str(
        resource_scope_ref, field_name="params.resource_scope_ref"
    )
    return (
        validate_opaque_ref(
            t_str, field_name="params.tenant_ref", expected_prefix="tenant"
        ),
        validate_opaque_ref(
            b_str, field_name="params.binding_ref", expected_prefix="binding"
        ),
        validate_opaque_ref(
            s_str,
            field_name="params.resource_scope_ref",
            expected_prefix="scope",
        ),
    )


def _validate_strict_utf8_sorted_items(
    items: Sequence[object],
    *,
    field_name: str,
    item_validator: Callable[[str], str],
) -> tuple[str, ...]:
    validated: list[str] = []
    prev_bytes: bytes | None = None
    for raw_item in items:
        item_str = _require_exact_str(raw_item, field_name=field_name)
        checked = item_validator(item_str)
        curr_bytes = checked.encode("utf-8")
        if prev_bytes is not None and not (prev_bytes < curr_bytes):
            raise ClosedValidationError(
                f"{field_name}: must be strictly sorted by UTF-8 bytes without duplicates"
            )
        prev_bytes = curr_bytes
        validated.append(checked)
    return tuple(validated)


def _validate_finding_type_item(value: str) -> str:
    if value not in ALLOWED_FINDING_TYPES:
        raise ClosedValidationError(
            f"params.finding_types: unsupported finding type {value!r}"
        )
    return value


def _ensure_dict_str_keys(obj: dict[Any, Any], *, label: str) -> None:
    for key in obj:
        if type(key) is not str:
            raise ClosedValidationError(f"{label}: dict keys must be str")


def _parse_dataset_snapshot_locator(raw_loc: object) -> ArtifactLocator:
    if type(raw_loc) is not dict:
        raise ClosedValidationError(
            "params.dataset_snapshot_locator: expected dict"
        )
    if set(raw_loc.keys()) != _ARTIFACT_LOCATOR_KEYS:
        raise ClosedValidationError(
            "params.dataset_snapshot_locator: missing required locator keys"
        )
    for val in raw_loc.values():
        if type(val) is not str:
            raise ClosedValidationError(
                "params.dataset_snapshot_locator: all locator values must be str"
            )
    return ArtifactLocator.from_dict(
        raw_loc, expected_type=_DATASET_SNAPSHOT_SCHEMA
    )


@dataclass(frozen=True, slots=True)
class PerformanceQueryParams:
    """Validated closed parameters for `get_{ad,adset,campaign}_performance_v1`."""

    method: str
    tenant_ref: str
    binding_ref: str
    resource_scope_ref: str
    date_range: DateRange
    resource_refs: tuple[str, ...] = ()
    metric_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if (
            type(self.method) is not str
            or self.method not in _PERFORMANCE_METHODS
        ):
            raise ClosedValidationError(
                f"PerformanceQueryParams.method invalid: {self.method!r}"
            )
        _validate_scope_trio(
            self.tenant_ref, self.binding_ref, self.resource_scope_ref
        )
        if type(self.date_range) is not DateRange:
            raise ClosedValidationError(
                "PerformanceQueryParams.date_range must be a DateRange"
            )
        if type(self.resource_refs) is not tuple:
            raise ClosedValidationError(
                "PerformanceQueryParams.resource_refs must be a tuple"
            )
        _validate_strict_utf8_sorted_items(
            self.resource_refs,
            field_name="params.resource_refs",
            item_validator=lambda s: validate_resource_ref(
                s, field_name="params.resource_refs"
            ),
        )
        if type(self.metric_refs) is not tuple:
            raise ClosedValidationError(
                "PerformanceQueryParams.metric_refs must be a tuple"
            )
        _validate_strict_utf8_sorted_items(
            self.metric_refs,
            field_name="params.metric_refs",
            item_validator=lambda s: validate_opaque_ref(
                s, field_name="params.metric_refs", expected_prefix="metric"
            ),
        )


@dataclass(frozen=True, slots=True)
class IntelligenceFindingsQueryParams:
    """Validated closed parameters for `smart_ads.queries.get_intelligence_findings_v1`."""

    tenant_ref: str
    binding_ref: str
    resource_scope_ref: str
    dataset_snapshot_locator: ArtifactLocator
    finding_types: tuple[str, ...] = ()
    method: str = _FINDINGS_METHOD

    def __post_init__(self) -> None:
        if type(self.method) is not str or self.method != _FINDINGS_METHOD:
            raise ClosedValidationError(
                f"IntelligenceFindingsQueryParams.method must equal {_FINDINGS_METHOD!r}"
            )
        _validate_scope_trio(
            self.tenant_ref, self.binding_ref, self.resource_scope_ref
        )
        if (
            type(self.dataset_snapshot_locator) is not ArtifactLocator
            or self.dataset_snapshot_locator.artifact_type
            != _DATASET_SNAPSHOT_SCHEMA
        ):
            raise ClosedValidationError(
                "IntelligenceFindingsQueryParams.dataset_snapshot_locator must target "
                f"{_DATASET_SNAPSHOT_SCHEMA!r}"
            )
        if type(self.finding_types) is not tuple:
            raise ClosedValidationError(
                "IntelligenceFindingsQueryParams.finding_types must be a tuple"
            )
        _validate_strict_utf8_sorted_items(
            self.finding_types,
            field_name="params.finding_types",
            item_validator=_validate_finding_type_item,
        )


@dataclass(frozen=True, slots=True)
class RecurrentSummaryReportParams:
    """Validated closed parameters for `smart_ads.reports.generate_recurrent_summary_v1`."""

    tenant_ref: str
    binding_ref: str
    resource_scope_ref: str
    dataset_snapshot_locator: ArtifactLocator
    cadence: SummaryCadence
    period_start_date: str
    period_end_date: str
    method: str = _SUMMARY_METHOD

    def __post_init__(self) -> None:
        if type(self.method) is not str or self.method != _SUMMARY_METHOD:
            raise ClosedValidationError(
                f"RecurrentSummaryReportParams.method must equal {_SUMMARY_METHOD!r}"
            )
        _validate_scope_trio(
            self.tenant_ref, self.binding_ref, self.resource_scope_ref
        )
        if (
            type(self.dataset_snapshot_locator) is not ArtifactLocator
            or self.dataset_snapshot_locator.artifact_type
            != _DATASET_SNAPSHOT_SCHEMA
        ):
            raise ClosedValidationError(
                "RecurrentSummaryReportParams.dataset_snapshot_locator must target "
                f"{_DATASET_SNAPSHOT_SCHEMA!r}"
            )
        if (
            type(self.cadence) is not str
            or self.cadence not in _ALLOWED_CADENCES
        ):
            raise ClosedValidationError(
                f"RecurrentSummaryReportParams.cadence invalid: {self.cadence!r}"
            )
        start_str = _require_exact_str(
            self.period_start_date, field_name="params.period_start_date"
        )
        end_str = _require_exact_str(
            self.period_end_date, field_name="params.period_end_date"
        )
        validate_iso_date(start_str, field_name="params.period_start_date")
        validate_iso_date(end_str, field_name="params.period_end_date")
        start_d = parse_iso_date(
            start_str, field_name="params.period_start_date"
        )
        end_d = parse_iso_date(end_str, field_name="params.period_end_date")
        if start_d > end_d:
            raise ClosedValidationError(
                "RecurrentSummaryReportParams: period_start_date > period_end_date"
            )
        if self.cadence == "daily" and start_str != end_str:
            raise ClosedValidationError(
                "RecurrentSummaryReportParams: daily cadence requires period_start_date == period_end_date"
            )


McpMethodParams: TypeAlias = (
    PerformanceQueryParams
    | IntelligenceFindingsQueryParams
    | RecurrentSummaryReportParams
)


def validate_mcp_method_params(
    method: str,
    has_params: bool,
    params_raw: Any,
    *,
    request_id: JsonRpcRequestId,
) -> McpMethodParams | McpProtocolRejection:
    """Validate MCP method allowlist and closed `params` schema before any I/O."""
    if not _is_valid_jsonrpc_method_str(method):
        raise ClosedValidationError(
            "validate_mcp_method_params: method must be a non-empty non-control str"
        )
    if type(has_params) is not bool:
        raise ClosedValidationError(
            "validate_mcp_method_params: has_params must be bool"
        )
    if not _is_valid_jsonrpc_request_id(request_id):
        raise ClosedValidationError(
            "validate_mcp_method_params: request_id violates JSON-RPC 2.0 ID bounds"
        )

    if method not in _ALLOWED_MCP_METHODS_SET:
        return McpProtocolRejection(
            code=-32601,
            message="Method not found",
            request_id=request_id,
            case_id="unsupported_method",
        )

    if not has_params or type(params_raw) is not dict:
        return McpProtocolRejection(
            code=-32602,
            message="Invalid params",
            request_id=request_id,
            case_id="invalid_params",
        )

    _ensure_dict_str_keys(params_raw, label="params_raw")

    if method in _PERFORMANCE_METHODS:
        allowed_keys = _PERF_ALLOWED_KEYS
        required_keys = _PERF_REQUIRED_KEYS
    elif method == _FINDINGS_METHOD:
        allowed_keys = _FINDINGS_ALLOWED_KEYS
        required_keys = _FINDINGS_REQUIRED_KEYS
    else:
        allowed_keys = _SUMMARY_ALLOWED_KEYS
        required_keys = _SUMMARY_REQUIRED_KEYS

    if set(params_raw.keys()) - allowed_keys:
        return McpProtocolRejection(
            code=-32602,
            message="Invalid params",
            request_id=request_id,
            case_id="additional_property",
        )

    # Enforce nested additionalProperties: false prior to missing-key or scalar checks
    if method in _PERFORMANCE_METHODS:
        nested_dr = params_raw.get("date_range")
        if type(nested_dr) is dict:
            _ensure_dict_str_keys(nested_dr, label="params.date_range")
            if set(nested_dr.keys()) - _WIRE_DATE_RANGE_KEYS:
                return McpProtocolRejection(
                    code=-32602,
                    message="Invalid params",
                    request_id=request_id,
                    case_id="additional_property",
                )
    else:
        nested_loc = params_raw.get("dataset_snapshot_locator")
        if type(nested_loc) is dict:
            _ensure_dict_str_keys(
                nested_loc, label="params.dataset_snapshot_locator"
            )
            if set(nested_loc.keys()) - _ARTIFACT_LOCATOR_KEYS:
                return McpProtocolRejection(
                    code=-32602,
                    message="Invalid params",
                    request_id=request_id,
                    case_id="additional_property",
                )

    if not required_keys.issubset(params_raw.keys()):
        return McpProtocolRejection(
            code=-32602,
            message="Invalid params",
            request_id=request_id,
            case_id="invalid_params",
        )

    try:
        tenant_ref, binding_ref, resource_scope_ref = _validate_scope_trio(
            params_raw["tenant_ref"],
            params_raw["binding_ref"],
            params_raw["resource_scope_ref"],
        )

        if method in _PERFORMANCE_METHODS:
            raw_dr = params_raw["date_range"]
            if (
                type(raw_dr) is not dict
                or set(raw_dr.keys()) != _WIRE_DATE_RANGE_KEYS
            ):
                raise ClosedValidationError(
                    "params.date_range: expected {'start_date', 'end_date'}"
                )
            start_date = _require_exact_str(
                raw_dr["start_date"], field_name="params.date_range.start_date"
            )
            end_date = _require_exact_str(
                raw_dr["end_date"], field_name="params.date_range.end_date"
            )
            validate_iso_date(
                start_date, field_name="params.date_range.start_date"
            )
            validate_iso_date(
                end_date, field_name="params.date_range.end_date"
            )
            date_range_obj = DateRange(
                start_date=start_date, end_date=end_date
            )

            resource_refs_tuple: tuple[str, ...] = ()
            if "resource_refs" in params_raw:
                raw_rr = params_raw["resource_refs"]
                if type(raw_rr) is not list or len(raw_rr) == 0:
                    raise ClosedValidationError(
                        "params.resource_refs: expected non-empty JSON array"
                    )
                resource_refs_tuple = _validate_strict_utf8_sorted_items(
                    raw_rr,
                    field_name="params.resource_refs",
                    item_validator=lambda s: validate_resource_ref(
                        s, field_name="params.resource_refs"
                    ),
                )

            metric_refs_tuple: tuple[str, ...] = ()
            if "metric_refs" in params_raw:
                raw_mr = params_raw["metric_refs"]
                if type(raw_mr) is not list or len(raw_mr) == 0:
                    raise ClosedValidationError(
                        "params.metric_refs: expected non-empty JSON array"
                    )
                metric_refs_tuple = _validate_strict_utf8_sorted_items(
                    raw_mr,
                    field_name="params.metric_refs",
                    item_validator=lambda s: validate_opaque_ref(
                        s,
                        field_name="params.metric_refs",
                        expected_prefix="metric",
                    ),
                )

            return PerformanceQueryParams(
                method=method,
                tenant_ref=tenant_ref,
                binding_ref=binding_ref,
                resource_scope_ref=resource_scope_ref,
                date_range=date_range_obj,
                resource_refs=resource_refs_tuple,
                metric_refs=metric_refs_tuple,
            )

        if method == _FINDINGS_METHOD:
            locator_obj = _parse_dataset_snapshot_locator(
                params_raw["dataset_snapshot_locator"]
            )
            finding_types_tuple: tuple[str, ...] = ()
            if "finding_types" in params_raw:
                raw_ft = params_raw["finding_types"]
                if type(raw_ft) is not list or len(raw_ft) == 0:
                    raise ClosedValidationError(
                        "params.finding_types: expected non-empty JSON array"
                    )
                finding_types_tuple = _validate_strict_utf8_sorted_items(
                    raw_ft,
                    field_name="params.finding_types",
                    item_validator=_validate_finding_type_item,
                )
            return IntelligenceFindingsQueryParams(
                tenant_ref=tenant_ref,
                binding_ref=binding_ref,
                resource_scope_ref=resource_scope_ref,
                dataset_snapshot_locator=locator_obj,
                finding_types=finding_types_tuple,
            )

        locator_obj = _parse_dataset_snapshot_locator(
            params_raw["dataset_snapshot_locator"]
        )
        raw_cadence = _require_exact_str(
            params_raw["cadence"], field_name="params.cadence"
        )
        if raw_cadence == "daily":
            cadence_lit: SummaryCadence = "daily"
        elif raw_cadence == "weekly":
            cadence_lit = "weekly"
        else:
            raise ClosedValidationError(
                f"params.cadence: unsupported cadence {raw_cadence!r}"
            )
        period_start = _require_exact_str(
            params_raw["period_start_date"],
            field_name="params.period_start_date",
        )
        period_end = _require_exact_str(
            params_raw["period_end_date"],
            field_name="params.period_end_date",
        )
        return RecurrentSummaryReportParams(
            tenant_ref=tenant_ref,
            binding_ref=binding_ref,
            resource_scope_ref=resource_scope_ref,
            dataset_snapshot_locator=locator_obj,
            cadence=cadence_lit,
            period_start_date=period_start,
            period_end_date=period_end,
        )
    except ClosedValidationError:
        return McpProtocolRejection(
            code=-32602,
            message="Invalid params",
            request_id=request_id,
            case_id="invalid_params",
        )


__all__ = [
    "ALLOWED_FINDING_TYPES",
    "ALLOWED_MCP_METHODS",
    "IntelligenceFindingsQueryParams",
    "McpMethodParams",
    "PerformanceQueryParams",
    "RecurrentSummaryReportParams",
    "validate_mcp_method_params",
]
