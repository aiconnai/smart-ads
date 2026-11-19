"""Bounded Phase 1 Pipeboard campaign row metric parser and reducer (`0dbdfede` parity, ADR-0001 §4.1)."""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import re
from typing import Any, Final

from smart_ads.adapters.pipeboard.wire import (
    make_wire_rejection,
    parse_pipeboard_mcp_result,
)
from smart_ads.contracts.numerics import MAX_INT64

PipeboardRowReducer = Callable[[dict[str, Any]], list[dict[str, Any]]]

PINNED_PIPEBOARD_ROW_KEYS: Final[frozenset[str]] = frozenset(
    {
        "account_id",
        "account_name",
        "campaign_id",
        "campaign_name",
        "impressions",
        "clicks",
        "spend",
        "cpc",
        "cpm",
        "ctr",
        "reach",
        "frequency",
        "actions",
        "action_values",
        "conversions",
        "unique_clicks",
        "cost_per_action_type",
        "date_start",
        "date_stop",
    }
)
_PINNED_ROW_KEYS: Final[frozenset[str]] = PINNED_PIPEBOARD_ROW_KEYS

META_CAMPAIGN_ID_RE: Final[re.Pattern[str]] = re.compile(r"\A[1-9][0-9]{5,31}\Z")
_COUNT_STR_RE: Final[re.Pattern[str]] = re.compile(r"\A(0|[1-9][0-9]{0,18})\Z")
_SPEND_STR_RE: Final[re.Pattern[str]] = re.compile(
    r"\A(0|[1-9][0-9]{0,16})(?:\.([0-9]{1,2}))?\Z"
)


def _validate_optional_int64_metric(value: object) -> int | None:
    if value is None:
        return None
    if type(value) is int and 0 <= value <= MAX_INT64:
        return value
    raise make_wire_rejection("invalid_metric_value", payload_schema_valid=False)


@dataclass(frozen=True, slots=True)
class CanonicalCampaignMetrics:
    """Bounded non-negative int64 campaign row metrics with zero synthetic zeroes."""

    impressions: int | None = None
    clicks: int | None = None
    spend_minor: int | None = None

    def __post_init__(self) -> None:
        _validate_optional_int64_metric(self.impressions)
        _validate_optional_int64_metric(self.clicks)
        _validate_optional_int64_metric(self.spend_minor)
        if (
            self.impressions is None
            and self.clicks is None
            and self.spend_minor is None
        ):
            raise make_wire_rejection("empty_row_metrics", payload_schema_valid=False)

    def to_reducer_record(self) -> dict[str, int]:
        """Project present metrics to the exact `0dbdfede` reduced dict representation."""
        record: dict[str, int] = {}
        if self.impressions is not None:
            record["impressions"] = self.impressions
        if self.clicks is not None:
            record["clicks"] = self.clicks
        if self.spend_minor is not None:
            record["spend_minor"] = self.spend_minor
        return record


def _parse_bounded_count(raw: object) -> int:
    if type(raw) is int:
        if 0 <= raw <= MAX_INT64:
            return raw
        raise make_wire_rejection("invalid_metric_value", payload_schema_valid=False)
    if type(raw) is str and _COUNT_STR_RE.fullmatch(raw) is not None:
        parsed = int(raw, 10)
        if 0 <= parsed <= MAX_INT64:
            return parsed
    raise make_wire_rejection("invalid_metric_value", payload_schema_valid=False)


def _parse_bounded_spend_minor(raw: object) -> int:
    if type(raw) is not str:
        raise make_wire_rejection("invalid_metric_value", payload_schema_valid=False)
    match = _SPEND_STR_RE.fullmatch(raw)
    if match is None:
        raise make_wire_rejection("invalid_metric_value", payload_schema_valid=False)
    whole = int(match.group(1), 10)
    frac_raw = match.group(2)
    frac = 0 if frac_raw is None else int(frac_raw.ljust(2, "0"), 10)
    spend_minor = whole * 100 + frac
    if 0 <= spend_minor <= MAX_INT64:
        return spend_minor
    raise make_wire_rejection("invalid_metric_value", payload_schema_valid=False)


def parse_campaign_row_metrics(row: Mapping[str, Any]) -> CanonicalCampaignMetrics:
    """Parse bounded `impressions`, `clicks`, and BRL `spend` from a single campaign row."""
    if not isinstance(row, Mapping):
        raise make_wire_rejection("invalid_row_shape", payload_schema_valid=False)
    impressions = (
        _parse_bounded_count(row["impressions"]) if "impressions" in row else None
    )
    clicks = _parse_bounded_count(row["clicks"]) if "clicks" in row else None
    spend_minor = (
        _parse_bounded_spend_minor(row["spend"]) if "spend" in row else None
    )
    if impressions is None and clicks is None and spend_minor is None:
        raise make_wire_rejection("empty_row_metrics", payload_schema_valid=False)
    return CanonicalCampaignMetrics(
        impressions=impressions,
        clicks=clicks,
        spend_minor=spend_minor,
    )


def reduce_pipeboard_insights_result(
    mcp_result: dict[str, Any],
) -> list[dict[str, int]]:
    """Reduce MCP `get_insights` result dict to `[{'impressions': ..., 'clicks': ..., 'spend_minor': ...}]`."""
    _, _, rows = parse_pipeboard_mcp_result(mcp_result)
    records: list[dict[str, int]] = []
    for row in rows:
        if not isinstance(row, Mapping):
            raise make_wire_rejection("invalid_row_shape", payload_schema_valid=False)
        if not set(row.keys()).issubset(_PINNED_ROW_KEYS):
            raise make_wire_rejection("invalid_row_keys", payload_schema_valid=False)
        raw_cid = row.get("campaign_id")
        if type(raw_cid) is not str or META_CAMPAIGN_ID_RE.fullmatch(raw_cid) is None:
            raise make_wire_rejection("invalid_campaign_id", payload_schema_valid=False)
        records.append(parse_campaign_row_metrics(row).to_reducer_record())
    return records


__all__ = [
    "CanonicalCampaignMetrics",
    "META_CAMPAIGN_ID_RE",
    "PINNED_PIPEBOARD_ROW_KEYS",
    "PipeboardRowReducer",
    "parse_campaign_row_metrics",
    "reduce_pipeboard_insights_result",
]
