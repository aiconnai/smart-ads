"""Deterministic curation window, monthly partition-key derivation, and `curation_execution/v1` (ADR-0001 §§6.2–6.3)."""
from __future__ import annotations

from dataclasses import dataclass
import datetime
import re
from typing import Any, ClassVar, Final, Literal

from smart_ads.contracts.effects import (
    _require_json_list,
    _safe_int,
    _split_p1_envelope,
    _strict_id,
    _strict_str,
    _typed_locator,
    _verify_p1_integrity,
)
from smart_ads.contracts.jcs import (
    ADR_P1_DOMAIN_PREFIXES,
    ArtifactLocator,
    P1Integrity,
    canonicalize_jcs,
)
from smart_ads.contracts.operational_evidence import (
    AlgorithmProvenanceIdentity,
    SanitizedCandidateFactSet,
)
from smart_ads.contracts.scalars import (
    ClosedValidationError,
    parse_iso_date,
    validate_envelope_timestamp_utc,
    validate_iso_date,
)
from smart_ads.contracts.schemas import DateRange

CurationMode = Literal["genesis", "incremental"]

_RUN_CONTEXT_SCHEMA: Final[str] = "smart_ads/migration_run_context/v1"
_GENESIS_RECORD_SCHEMA: Final[str] = "smart_ads/dataset_catalog_genesis_record/v1"
_DATASET_CATALOG_SCHEMA: Final[str] = "smart_ads/dataset_catalog/v1"
_DATASET_SNAPSHOT_SCHEMA: Final[str] = "smart_ads/dataset_snapshot/v1"
_CATALOG_CUT_RECEIPT_SCHEMA: Final[str] = "smart_ads/dataset_catalog_cut_receipt/v1"
_GENERATION_MANIFEST_SCHEMA: Final[str] = "smart_ads/generation_manifest/v1"
_CURATION_MODES: Final[frozenset[str]] = frozenset({"genesis", "incremental"})
_PARTITION_KEY_RE: Final[re.Pattern[str]] = re.compile(
    r"\Ayear=([0-9]{4})/month=(0[1-9]|1[0-2])\Z"
)


def validate_partition_key(
    value: object,
    *,
    field_name: str = "partition_key",
) -> str:
    """Validate canonical monthly partition key `'year=YYYY/month=MM'` (`YYYY >= 0001`)."""
    checked = _strict_str(value, field_name=field_name)
    match = _PARTITION_KEY_RE.fullmatch(checked)
    if match is None or int(match.group(1)) < 1:
        raise ClosedValidationError(
            f"{field_name}: expected 'year=YYYY/month=MM' (0001..9999 / 01..12), "
            f"got {checked!r}"
        )
    return checked


def partition_key_for_metric_date(metric_date: str) -> str:
    """Derive `'year=YYYY/month=MM'` deterministically from `YYYY-MM-DD` `metric_date`."""
    checked = validate_iso_date(
        _strict_str(metric_date, field_name="metric_date"), field_name="metric_date"
    )
    return f"year={checked[:4]}/month={checked[5:7]}"


def compute_curation_window(
    curation_anchor_date: str,
    curation_timezone: str,
    tzdb_version: str,
    restatement_lookback_days: int,
) -> DateRange:
    """Compute inclusive `N`-day São Paulo curation window `[anchor - (N - 1), anchor]`."""
    anchor = parse_iso_date(
        _strict_str(curation_anchor_date, field_name="curation_anchor_date"),
        field_name="curation_anchor_date",
    )
    if (
        _strict_str(curation_timezone, field_name="curation_timezone")
        != "America/Sao_Paulo"
    ):
        raise ClosedValidationError(
            "curation_timezone: must equal 'America/Sao_Paulo'"
        )
    _strict_id(tzdb_version, field_name="tzdb_version")
    days = _safe_int(
        restatement_lookback_days,
        field_name="restatement_lookback_days",
        minimum=1,
    )
    try:
        start = anchor - datetime.timedelta(days=days - 1)
    except OverflowError as exc:
        raise ClosedValidationError(
            "restatement_lookback_days: curation window precedes 0001-01-01"
        ) from exc
    return DateRange(
        start_date=start.isoformat(),
        end_date=anchor.isoformat(),
        inclusive=True,
    )


def _validate_unique_manifest_locators(
    values: object,
    *,
    field_name: str,
) -> tuple[ArtifactLocator, ...]:
    if not isinstance(values, (list, tuple)):
        raise ClosedValidationError(
            f"{field_name}: expected list or tuple of ArtifactLocator"
        )
    items: list[ArtifactLocator] = []
    seen: set[bytes] = set()
    for idx, val in enumerate(values):
        loc = _typed_locator(
            val,
            field_name=f"{field_name}[{idx}]",
            expected_type=_GENERATION_MANIFEST_SCHEMA,
        )
        key = canonicalize_jcs(loc.to_dict())
        if key in seen:
            raise ClosedValidationError(
                f"{field_name}[{idx}]: duplicate generation_manifest locator"
            )
        seen.add(key)
        items.append(loc)
    return tuple(items)


def _check_curation_mode_locators(exec_obj: CurationExecution, *, label: str) -> None:
    if exec_obj.curation_mode == "genesis":
        if exec_obj.dataset_catalog_genesis_record_locator is None:
            raise ClosedValidationError(
                f"{label}: genesis mode requires dataset_catalog_genesis_record_locator"
            )
        _typed_locator(
            exec_obj.dataset_catalog_genesis_record_locator,
            field_name=f"{label}.dataset_catalog_genesis_record_locator",
            expected_type=_GENESIS_RECORD_SCHEMA,
        )
        if (
            exec_obj.base_dataset_snapshot_locator is not None
            or exec_obj.base_catalog_cut_receipt_locator is not None
            or len(exec_obj.historical_generation_manifest_locators) != 0
        ):
            raise ClosedValidationError(
                f"{label}: genesis mode requires null snapshot/cut locators and empty history"
            )
        return
    if exec_obj.dataset_catalog_genesis_record_locator is not None:
        raise ClosedValidationError(
            f"{label}: incremental mode forbids dataset_catalog_genesis_record_locator"
        )
    if (
        exec_obj.base_dataset_snapshot_locator is None
        or exec_obj.base_catalog_cut_receipt_locator is None
    ):
        raise ClosedValidationError(
            f"{label}: incremental mode requires non-null base snapshot and cut-receipt locators"
        )
    _typed_locator(
        exec_obj.base_dataset_snapshot_locator,
        field_name=f"{label}.base_dataset_snapshot_locator",
        expected_type=_DATASET_SNAPSHOT_SCHEMA,
    )
    _typed_locator(
        exec_obj.base_catalog_cut_receipt_locator,
        field_name=f"{label}.base_catalog_cut_receipt_locator",
        expected_type=_CATALOG_CUT_RECEIPT_SCHEMA,
    )


@dataclass(frozen=True, slots=True)
class CurationExecution:
    """Closed P1 `smart_ads/curation_execution/v1` envelope (ADR-0001 §6.2)."""

    SCHEMA: ClassVar[str] = "smart_ads/curation_execution/v1"
    P1_DOMAIN_PREFIX: ClassVar[str] = ADR_P1_DOMAIN_PREFIXES[SCHEMA]
    CORE_KEYS: ClassVar[frozenset[str]] = frozenset(
        {
            "$schema",
            "migration_run_context_locator",
            "curation_id",
            "curation_mode",
            "curation_anchor_date",
            "curation_timezone",
            "tzdb_version",
            "restatement_lookback_days",
            "curation_window",
            "sanitized_candidate_fact_set_locator",
            "curation_algorithm_identity",
            "dataset_catalog_genesis_record_locator",
            "base_dataset_catalog_locator",
            "base_dataset_snapshot_locator",
            "base_catalog_cut_receipt_locator",
            "historical_generation_manifest_locators",
            "executed_at_utc",
        }
    )
    KEYS: ClassVar[frozenset[str]] = CORE_KEYS | {"integrity"}

    migration_run_context_locator: ArtifactLocator
    curation_id: str
    curation_mode: CurationMode
    curation_anchor_date: str
    curation_timezone: str
    tzdb_version: str
    restatement_lookback_days: int
    curation_window: DateRange
    sanitized_candidate_fact_set_locator: ArtifactLocator
    curation_algorithm_identity: AlgorithmProvenanceIdentity
    dataset_catalog_genesis_record_locator: ArtifactLocator | None
    base_dataset_catalog_locator: ArtifactLocator
    base_dataset_snapshot_locator: ArtifactLocator | None
    base_catalog_cut_receipt_locator: ArtifactLocator | None
    historical_generation_manifest_locators: tuple[ArtifactLocator, ...]
    executed_at_utc: str
    integrity: P1Integrity | None = None

    def __post_init__(self) -> None:
        label = "curation_execution"
        _typed_locator(self.migration_run_context_locator, field_name=f"{label}.migration_run_context_locator", expected_type=_RUN_CONTEXT_SCHEMA)
        _strict_id(self.curation_id, field_name=f"{label}.curation_id")
        mode = _strict_str(self.curation_mode, field_name=f"{label}.curation_mode")
        if mode not in _CURATION_MODES:
            raise ClosedValidationError(f"{label}.curation_mode: invalid mode {mode!r}")
        expected_win = compute_curation_window(
            curation_anchor_date=self.curation_anchor_date,
            curation_timezone=self.curation_timezone,
            tzdb_version=self.tzdb_version,
            restatement_lookback_days=self.restatement_lookback_days,
        )
        if type(self.curation_window) is not DateRange:
            raise ClosedValidationError(f"{label}.curation_window: expected DateRange")
        DateRange.from_dict(self.curation_window.to_dict(), label=f"{label}.curation_window")
        if self.curation_window != expected_win:
            raise ClosedValidationError(f"{label}.curation_window: expected {expected_win!r}, got {self.curation_window!r}")
        _typed_locator(self.sanitized_candidate_fact_set_locator, field_name=f"{label}.sanitized_candidate_fact_set_locator", expected_type=SanitizedCandidateFactSet.SCHEMA)
        if type(self.curation_algorithm_identity) is not AlgorithmProvenanceIdentity:
            raise ClosedValidationError(f"{label}.curation_algorithm_identity: expected AlgorithmProvenanceIdentity")
        checked_alg = AlgorithmProvenanceIdentity.from_dict(self.curation_algorithm_identity.to_dict())
        if checked_alg.schema_id != self.SCHEMA:
            raise ClosedValidationError(f"{label}.curation_algorithm_identity.schema_id: expected {self.SCHEMA!r}, got {checked_alg.schema_id!r}")
        _typed_locator(self.base_dataset_catalog_locator, field_name=f"{label}.base_dataset_catalog_locator", expected_type=_DATASET_CATALOG_SCHEMA)
        hist = _validate_unique_manifest_locators(self.historical_generation_manifest_locators, field_name=f"{label}.historical_generation_manifest_locators")
        object.__setattr__(self, "historical_generation_manifest_locators", hist)
        _check_curation_mode_locators(self, label=label)
        validate_envelope_timestamp_utc(self.executed_at_utc, field_name=f"{label}.executed_at_utc")
        _verify_p1_integrity(self.integrity, self.to_dict, label=label)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "$schema": self.SCHEMA,
            "migration_run_context_locator": self.migration_run_context_locator.to_dict(),
            "curation_id": self.curation_id,
            "curation_mode": self.curation_mode,
            "curation_anchor_date": self.curation_anchor_date,
            "curation_timezone": self.curation_timezone,
            "tzdb_version": self.tzdb_version,
            "restatement_lookback_days": self.restatement_lookback_days,
            "curation_window": self.curation_window.to_dict(),
            "sanitized_candidate_fact_set_locator": self.sanitized_candidate_fact_set_locator.to_dict(),
            "curation_algorithm_identity": self.curation_algorithm_identity.to_dict(),
            "dataset_catalog_genesis_record_locator": (
                None if self.dataset_catalog_genesis_record_locator is None else self.dataset_catalog_genesis_record_locator.to_dict()
            ),
            "base_dataset_catalog_locator": self.base_dataset_catalog_locator.to_dict(),
            "base_dataset_snapshot_locator": (
                None if self.base_dataset_snapshot_locator is None else self.base_dataset_snapshot_locator.to_dict()
            ),
            "base_catalog_cut_receipt_locator": (
                None if self.base_catalog_cut_receipt_locator is None else self.base_catalog_cut_receipt_locator.to_dict()
            ),
            "historical_generation_manifest_locators": [loc.to_dict() for loc in self.historical_generation_manifest_locators],
            "executed_at_utc": self.executed_at_utc,
        }
        if self.integrity is not None:
            out["integrity"] = self.integrity.to_dict()
        return out

    @classmethod
    def from_dict(cls, data: object, *, require_signed: bool = False) -> CurationExecution:
        m, integrity = _split_p1_envelope(data, core_keys=cls.CORE_KEYS, schema=cls.SCHEMA, label="curation_execution", require_signed=require_signed)
        raw_hist = _require_json_list(m, "historical_generation_manifest_locators", label="curation_execution")
        raw_gen = m["dataset_catalog_genesis_record_locator"]
        raw_snap = m["base_dataset_snapshot_locator"]
        raw_cut = m["base_catalog_cut_receipt_locator"]
        return cls(
            migration_run_context_locator=ArtifactLocator.from_dict(m["migration_run_context_locator"], expected_type=_RUN_CONTEXT_SCHEMA),
            curation_id=m["curation_id"],
            curation_mode=m["curation_mode"],
            curation_anchor_date=m["curation_anchor_date"],
            curation_timezone=m["curation_timezone"],
            tzdb_version=m["tzdb_version"],
            restatement_lookback_days=m["restatement_lookback_days"],
            curation_window=DateRange.from_dict(m["curation_window"], label="curation_execution.curation_window"),
            sanitized_candidate_fact_set_locator=ArtifactLocator.from_dict(m["sanitized_candidate_fact_set_locator"], expected_type=SanitizedCandidateFactSet.SCHEMA),
            curation_algorithm_identity=AlgorithmProvenanceIdentity.from_dict(m["curation_algorithm_identity"]),
            dataset_catalog_genesis_record_locator=(
                None if raw_gen is None else ArtifactLocator.from_dict(raw_gen, expected_type=_GENESIS_RECORD_SCHEMA)
            ),
            base_dataset_catalog_locator=ArtifactLocator.from_dict(m["base_dataset_catalog_locator"], expected_type=_DATASET_CATALOG_SCHEMA),
            base_dataset_snapshot_locator=(
                None if raw_snap is None else ArtifactLocator.from_dict(raw_snap, expected_type=_DATASET_SNAPSHOT_SCHEMA)
            ),
            base_catalog_cut_receipt_locator=(
                None if raw_cut is None else ArtifactLocator.from_dict(raw_cut, expected_type=_CATALOG_CUT_RECEIPT_SCHEMA)
            ),
            historical_generation_manifest_locators=tuple(ArtifactLocator.from_dict(h, expected_type=_GENERATION_MANIFEST_SCHEMA) for h in raw_hist),
            executed_at_utc=m["executed_at_utc"],
            integrity=integrity,
        )

    def locator(self) -> ArtifactLocator:
        return ArtifactLocator.for_canonical_bytes(self.SCHEMA, canonicalize_jcs(self.to_dict()))


__all__ = [
    "CurationExecution",
    "CurationMode",
    "compute_curation_window",
    "partition_key_for_metric_date",
    "validate_partition_key",
]
