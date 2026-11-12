"""Authenticated clock, pure UTC-microsecond timezone policy, and cell runtime ports (ADR-0001 §§4.2, 12.1)."""
from __future__ import annotations

import bisect
from dataclasses import dataclass
import datetime
from typing import Any, ClassVar, Final, Literal, Protocol, runtime_checkable

from smart_ads.contracts.jcs import (
    MAX_JCS_SAFE_INT,
    ArtifactLocator,
    P1Integrity,
    canonicalize_jcs,
    p1_content_digest,
)
from smart_ads.contracts.numerics import MAX_INT64
from smart_ads.contracts.scalars import (
    ClosedValidationError,
    parse_timestamp_utc_micros,
    require_exact_keys,
    require_mapping,
    validate_non_empty_str,
    validate_opaque_ref,
    validate_sha256_prefixed,
    validate_timestamp_utc6,
    validate_timestamp_utc_seconds,
)
from smart_ads.contracts.schemas import (
    CallSide,
    CanonicalQueryContract,
    CollectionRequest,
    DateRange,
    PurposePrerequisiteLocators,
)
from smart_ads.domain.pipeboard_contract import PipeboardPhase1Contract
from smart_ads.domain.registry import (
    ExpectedResourceInventory,
    PrivateRegistrySnapshot,
)

_MICROSECONDS_PER_SECOND: Final[int] = 1_000_000
_MICROSECONDS_PER_DAY: Final[int] = 86_400_000_000
_UNIX_EPOCH_DATE: Final[datetime.date] = datetime.date(1970, 1, 1)

_CLOCK_ATTESTATION_CORE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "$schema",
        "attestation_id",
        "now_utc",
        "uncertainty_ms",
        "issued_at_utc",
        "valid_until_utc",
        "maximum_age_seconds",
    }
)
_UTC_OFFSET_TRANSITION_KEYS: Final[frozenset[str]] = frozenset(
    {"effective_from_utc_micros", "utc_offset_seconds"}
)
_TIMEZONE_RULE_SNAPSHOT_KEYS: Final[frozenset[str]] = frozenset(
    {"timezone_name", "tzdb_version", "transitions"}
)
_LIVE_CERT_HEAD_SCHEMA: Final[str] = "smart_ads/live_certification_head/v1"
_LIVE_CERT_TRANSITION_SCHEMA: Final[str] = (
    "smart_ads/live_certification_transition/v1"
)
_LIVE_CERT_CERTIFICATE_SCHEMA: Final[str] = (
    "smart_ads/live_certification_certificate/v1"
)
_GATE3_SELECTION_SCHEMA: Final[str] = "smart_ads/gate3_selection_receipt/v1"
_HERMES_DELEGATION_SCHEMA: Final[str] = (
    "smart_ads/ibvi_ads_delegation_context/v1"
)
_ALLOWED_GATE3_ROLES: Final[frozenset[str]] = frozenset(
    {"certification", "operational_renewal"}
)


class AmbiguousLocalDayError(ClosedValidationError):
    """Raised when `[now_utc - uncertainty, now_utc + uncertainty]` straddles midnight or lacks tz rules."""


_MIN_INT64: Final[int] = -(1 << 63)


def _validate_utc_micros(value: object, *, field_name: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not (_MIN_INT64 <= value <= MAX_INT64)
    ):
        raise ClosedValidationError(
            f"{field_name}: expected int64 UTC microseconds, got {value!r}"
        )
    return value


@dataclass(frozen=True, slots=True)
class ClockAttestation:
    """Closed `smart_ads/clock_attestation/v1` P1 envelope (ADR-0001 §§4.2, 12.1)."""

    SCHEMA: ClassVar[str] = "smart_ads/clock_attestation/v1"

    attestation_id: str
    now_utc: str
    uncertainty_ms: int
    issued_at_utc: str
    valid_until_utc: str
    maximum_age_seconds: int
    integrity: P1Integrity | None = None

    def __post_init__(self) -> None:
        validate_opaque_ref(
            self.attestation_id,
            field_name="clock_attestation.attestation_id",
            expected_prefix="clock",
        )
        validate_timestamp_utc6(
            self.now_utc, field_name="clock_attestation.now_utc"
        )
        if (
            isinstance(self.uncertainty_ms, bool)
            or not isinstance(self.uncertainty_ms, int)
            or not (0 <= self.uncertainty_ms <= MAX_JCS_SAFE_INT)
        ):
            raise ClosedValidationError(
                "clock_attestation.uncertainty_ms: expected non-negative safe int"
            )
        validate_timestamp_utc_seconds(
            self.issued_at_utc, field_name="clock_attestation.issued_at_utc"
        )
        validate_timestamp_utc_seconds(
            self.valid_until_utc,
            field_name="clock_attestation.valid_until_utc",
        )
        if (
            isinstance(self.maximum_age_seconds, bool)
            or not isinstance(self.maximum_age_seconds, int)
            or not (0 < self.maximum_age_seconds <= MAX_JCS_SAFE_INT)
        ):
            raise ClosedValidationError(
                "clock_attestation.maximum_age_seconds: expected positive safe int"
            )
        if self.integrity is not None and not isinstance(
            self.integrity, P1Integrity
        ):
            raise ClosedValidationError(
                "clock_attestation.integrity: expected P1Integrity or None"
            )
        if self.integrity is not None and self.integrity.is_signed:
            expected_p1 = p1_content_digest(self.to_dict())
            if self.integrity.content_digest != expected_p1:
                raise ClosedValidationError(
                    "clock_attestation.integrity.content_digest: recomputed "
                    f"{expected_p1!r} != asserted {self.integrity.content_digest!r}"
                )

    def verify_freshness(
        self, *, configured_max_uncertainty_ms: int
    ) -> tuple[int, int]:
        """Verify authenticated clock freshness and interval containment (ADR-0001 §12.1 L2811–2817)."""
        if (
            isinstance(configured_max_uncertainty_ms, bool)
            or not isinstance(configured_max_uncertainty_ms, int)
            or not (0 <= configured_max_uncertainty_ms <= MAX_JCS_SAFE_INT)
        ):
            raise ClosedValidationError(
                "configured_max_uncertainty_ms: expected non-negative safe int"
            )
        if self.uncertainty_ms > configured_max_uncertainty_ms:
            raise ClosedValidationError(
                f"clock_attestation: uncertainty_ms {self.uncertainty_ms} exceeds "
                f"configured_max_uncertainty_ms {configured_max_uncertainty_ms}"
            )

        now_us = parse_timestamp_utc_micros(
            self.now_utc, field_name="clock_attestation.now_utc"
        )
        unc_us = self.uncertainty_ms * 1_000
        lower_us = now_us - unc_us
        upper_us = now_us + unc_us

        issued_us = parse_timestamp_utc_micros(
            self.issued_at_utc,
            field_name="clock_attestation.issued_at_utc",
            allow_whole_seconds=True,
        )
        valid_until_us = parse_timestamp_utc_micros(
            self.valid_until_utc,
            field_name="clock_attestation.valid_until_utc",
            allow_whole_seconds=True,
        )

        if issued_us > valid_until_us:
            raise ClosedValidationError(
                "clock_attestation: issued_at_utc must not exceed valid_until_utc"
            )
        if lower_us < issued_us:
            raise ClosedValidationError(
                "clock_attestation: lower bound of uncertainty interval precedes issued_at_utc"
            )
        if upper_us > valid_until_us:
            raise ClosedValidationError(
                "clock_attestation: upper bound of uncertainty interval exceeds valid_until_utc"
            )
        if upper_us - issued_us > self.maximum_age_seconds * _MICROSECONDS_PER_SECOND:
            raise ClosedValidationError(
                "clock_attestation: upper(I) - issued_at_utc exceeds maximum_age_seconds"
            )
        return lower_us, upper_us

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "$schema": self.SCHEMA,
            "attestation_id": self.attestation_id,
            "now_utc": self.now_utc,
            "uncertainty_ms": self.uncertainty_ms,
            "issued_at_utc": self.issued_at_utc,
            "valid_until_utc": self.valid_until_utc,
            "maximum_age_seconds": self.maximum_age_seconds,
        }
        if self.integrity is not None:
            out["integrity"] = self.integrity.to_dict()
        return out

    @classmethod
    def from_dict(
        cls,
        data: object,
        *,
        require_signed: bool = False,
    ) -> ClockAttestation:
        if not isinstance(require_signed, bool):
            raise ClosedValidationError("require_signed: expected bool")
        mapping = require_mapping(data, label="clock_attestation")
        if require_signed or "integrity" in mapping:
            require_exact_keys(
                mapping,
                _CLOCK_ATTESTATION_CORE_KEYS | {"integrity"},
                label="clock_attestation",
            )
            integrity: P1Integrity | None = P1Integrity.from_dict(
                mapping["integrity"], require_signed=require_signed
            )
        else:
            require_exact_keys(
                mapping, _CLOCK_ATTESTATION_CORE_KEYS, label="clock_attestation"
            )
            integrity = None

        if mapping["$schema"] != cls.SCHEMA:
            raise ClosedValidationError(
                f"clock_attestation.$schema: expected {cls.SCHEMA!r}, "
                f"got {mapping['$schema']!r}"
            )
        return cls(
            attestation_id=mapping["attestation_id"],
            now_utc=mapping["now_utc"],
            uncertainty_ms=mapping["uncertainty_ms"],
            issued_at_utc=mapping["issued_at_utc"],
            valid_until_utc=mapping["valid_until_utc"],
            maximum_age_seconds=mapping["maximum_age_seconds"],
            integrity=integrity,
        )


@dataclass(frozen=True, slots=True)
class UtcOffsetTransition:
    """Pure UTC-microsecond offset rule transition without OS/zoneinfo ambient I/O."""

    effective_from_utc_micros: int
    utc_offset_seconds: int

    def __post_init__(self) -> None:
        _validate_utc_micros(
            self.effective_from_utc_micros,
            field_name="utc_offset_transition.effective_from_utc_micros",
        )
        if (
            isinstance(self.utc_offset_seconds, bool)
            or not isinstance(self.utc_offset_seconds, int)
            or not (-86_400 < self.utc_offset_seconds < 86_400)
        ):
            raise ClosedValidationError(
                "utc_offset_transition.utc_offset_seconds: expected int strictly "
                f"within (-86400, 86400), got {self.utc_offset_seconds!r}"
            )

    def to_dict(self) -> dict[str, int]:
        return {
            "effective_from_utc_micros": self.effective_from_utc_micros,
            "utc_offset_seconds": self.utc_offset_seconds,
        }

    @classmethod
    def from_dict(cls, data: object) -> UtcOffsetTransition:
        mapping = require_exact_keys(
            data, _UTC_OFFSET_TRANSITION_KEYS, label="utc_offset_transition"
        )
        return cls(
            effective_from_utc_micros=mapping["effective_from_utc_micros"],
            utc_offset_seconds=mapping["utc_offset_seconds"],
        )


@dataclass(frozen=True, slots=True)
class TimezoneRuleSnapshot:
    """Pure pre-resolved reporting timezone transition table (Phase 1: `America/Sao_Paulo`)."""

    timezone_name: str
    tzdb_version: str
    transitions: tuple[UtcOffsetTransition, ...]

    def __post_init__(self) -> None:
        if self.timezone_name != "America/Sao_Paulo":
            raise ClosedValidationError(
                "timezone_rule_snapshot.timezone_name: must equal 'America/Sao_Paulo' in Phase 1"
            )
        validate_non_empty_str(
            self.tzdb_version,
            field_name="timezone_rule_snapshot.tzdb_version",
        )
        if (
            not isinstance(self.transitions, (list, tuple))
            or len(self.transitions) == 0
        ):
            raise ClosedValidationError(
                "timezone_rule_snapshot.transitions: expected non-empty collection of UtcOffsetTransition"
            )
        transitions_tuple = tuple(self.transitions)
        prev_micros: int | None = None
        for tr in transitions_tuple:
            if not isinstance(tr, UtcOffsetTransition):
                raise ClosedValidationError(
                    "timezone_rule_snapshot.transitions: every element must be UtcOffsetTransition"
                )
            if (
                prev_micros is not None
                and tr.effective_from_utc_micros <= prev_micros
            ):
                raise ClosedValidationError(
                    "timezone_rule_snapshot.transitions: effective_from_utc_micros "
                    "must be strictly ascending"
                )
            prev_micros = tr.effective_from_utc_micros
        object.__setattr__(self, "transitions", transitions_tuple)

    def offset_seconds_at(self, utc_micros: int) -> int:
        """Return active UTC offset in seconds at `utc_micros`, failing closed if uncovered."""
        _validate_utc_micros(utc_micros, field_name="utc_micros")
        starts = [t.effective_from_utc_micros for t in self.transitions]
        idx = bisect.bisect_right(starts, utc_micros) - 1
        if idx < 0:
            raise AmbiguousLocalDayError(
                f"timezone_rule_snapshot: timestamp {utc_micros} precedes earliest "
                f"rule transition {starts[0]}"
            )
        return self.transitions[idx].utc_offset_seconds

    def local_civil_date_at(self, utc_micros: int) -> datetime.date:
        """Compute local civil date at `utc_micros` via pure integer microsecond arithmetic."""
        offset_seconds = self.offset_seconds_at(utc_micros)
        local_micros = utc_micros + offset_seconds * _MICROSECONDS_PER_SECOND
        days_since_epoch = local_micros // _MICROSECONDS_PER_DAY
        try:
            return _UNIX_EPOCH_DATE + datetime.timedelta(days=days_since_epoch)
        except OverflowError as exc:
            raise ClosedValidationError(
                f"timezone_rule_snapshot: local civil date at {utc_micros} "
                "overflows supported ISO-8601 date range"
            ) from exc

    def compute_previous_local_day(
        self,
        *,
        lower_utc_micros: int,
        upper_utc_micros: int,
    ) -> str:
        """Derive unambiguous `previous_local_day` across `[lower_utc_micros, upper_utc_micros]` (P-07)."""
        _validate_utc_micros(lower_utc_micros, field_name="lower_utc_micros")
        _validate_utc_micros(upper_utc_micros, field_name="upper_utc_micros")
        if lower_utc_micros > upper_utc_micros:
            raise ClosedValidationError(
                f"compute_previous_local_day: lower_utc_micros ({lower_utc_micros}) "
                f"> upper_utc_micros ({upper_utc_micros})"
            )

        probe_points: list[int] = [lower_utc_micros]
        for tr in self.transitions:
            t_us = tr.effective_from_utc_micros
            if lower_utc_micros < t_us <= upper_utc_micros:
                probe_points.append(t_us - 1)
                probe_points.append(t_us)
        if upper_utc_micros != lower_utc_micros:
            probe_points.append(upper_utc_micros)

        local_dates = {self.local_civil_date_at(pt) for pt in probe_points}
        if len(local_dates) != 1:
            sorted_dates = sorted(d.isoformat() for d in local_dates)
            raise AmbiguousLocalDayError(
                "authenticated clock uncertainty interval straddles local midnight "
                f"in {self.timezone_name}: {sorted_dates}"
            )

        (unique_local_date,) = tuple(local_dates)
        try:
            return (unique_local_date - datetime.timedelta(days=1)).isoformat()
        except OverflowError as exc:
            raise ClosedValidationError(
                "timezone_rule_snapshot: previous_local_day before "
                f"{unique_local_date.isoformat()} underflows supported ISO-8601 date range"
            ) from exc

    def to_dict(self) -> dict[str, Any]:
        return {
            "timezone_name": self.timezone_name,
            "tzdb_version": self.tzdb_version,
            "transitions": [tr.to_dict() for tr in self.transitions],
        }

    @classmethod
    def from_dict(cls, data: object) -> TimezoneRuleSnapshot:
        mapping = require_exact_keys(
            data, _TIMEZONE_RULE_SNAPSHOT_KEYS, label="timezone_rule_snapshot"
        )
        if not isinstance(mapping["transitions"], list):
            raise ClosedValidationError(
                "timezone_rule_snapshot.transitions: expected JSON array list"
            )
        return cls(
            timezone_name=mapping["timezone_name"],
            tzdb_version=mapping["tzdb_version"],
            transitions=tuple(
                UtcOffsetTransition.from_dict(item)
                for item in mapping["transitions"]
            ),
        )


@dataclass(frozen=True, slots=True)
class ResolvedClockState:
    """Protected runtime clock state resolved by `ClockAttestationPort`."""

    locator: ArtifactLocator
    attestation: ClockAttestation
    configured_max_uncertainty_ms: int

    def __post_init__(self) -> None:
        if not isinstance(self.locator, ArtifactLocator):
            raise ClosedValidationError(
                "resolved_clock_state.locator: expected ArtifactLocator"
            )
        if not isinstance(self.attestation, ClockAttestation):
            raise ClosedValidationError(
                "resolved_clock_state.attestation: expected ClockAttestation"
            )
        if (
            isinstance(self.configured_max_uncertainty_ms, bool)
            or not isinstance(self.configured_max_uncertainty_ms, int)
        ):
            raise ClosedValidationError(
                "resolved_clock_state.configured_max_uncertainty_ms: expected int"
            )
        expected_locator = ArtifactLocator.for_canonical_bytes(
            ClockAttestation.SCHEMA,
            canonicalize_jcs(self.attestation.to_dict()),
        )
        if self.locator != expected_locator:
            raise ClosedValidationError(
                "resolved_clock_state.locator: locator does not match canonical "
                "JCS digest of ClockAttestation"
            )


@dataclass(frozen=True, slots=True)
class ResolvedRegistryState:
    """Protected registry snapshot and driver contract resolved by `ProtectedRegistryPort`."""

    locator: ArtifactLocator
    snapshot: PrivateRegistrySnapshot
    driver_contract_locator: ArtifactLocator
    driver_contract: PipeboardPhase1Contract

    def __post_init__(self) -> None:
        if not isinstance(self.locator, ArtifactLocator):
            raise ClosedValidationError(
                "resolved_registry_state.locator: expected ArtifactLocator"
            )
        if not isinstance(self.snapshot, PrivateRegistrySnapshot):
            raise ClosedValidationError(
                "resolved_registry_state.snapshot: expected PrivateRegistrySnapshot"
            )
        if not isinstance(self.driver_contract_locator, ArtifactLocator):
            raise ClosedValidationError(
                "resolved_registry_state.driver_contract_locator: expected ArtifactLocator"
            )
        if not isinstance(self.driver_contract, PipeboardPhase1Contract):
            raise ClosedValidationError(
                "resolved_registry_state.driver_contract: expected PipeboardPhase1Contract"
            )
        expected_snap_loc = ArtifactLocator.for_canonical_bytes(
            PrivateRegistrySnapshot.SCHEMA,
            canonicalize_jcs(self.snapshot.to_dict()),
        )
        if self.locator != expected_snap_loc:
            raise ClosedValidationError(
                "resolved_registry_state.locator: locator does not match canonical "
                "JCS digest of PrivateRegistrySnapshot"
            )
        expected_drv_loc = ArtifactLocator.for_canonical_bytes(
            PipeboardPhase1Contract.SCHEMA,
            canonicalize_jcs(self.driver_contract.to_dict()),
        )
        if self.driver_contract_locator != expected_drv_loc:
            raise ClosedValidationError(
                "resolved_registry_state.driver_contract_locator: locator does not "
                "match canonical JCS digest of PipeboardPhase1Contract"
            )


@dataclass(frozen=True, slots=True)
class ResolvedGate3SelectionState:
    """Resolved Gate-3 selection/renewal receipt state and 900s/60s freshness profile (ADR-0001 §5.3)."""

    locator: ArtifactLocator
    selection_role: Literal["certification", "operational_renewal"]
    revalidated_at_utc: str
    valid_until_utc: str
    candidate_driver_contract_digest: str
    canonical_query_digest: str
    schema_bundle_digest: str
    resource_mapping_contract_digest: str
    authorized_certification_scope: str
    certification_fingerprint_digest: str
    maximum_age_seconds: int = 900
    maximum_clock_uncertainty_ms: int = 1000
    maximum_provider_dispatch_deadline_seconds: int = 60

    def __post_init__(self) -> None:
        if (
            not isinstance(self.locator, ArtifactLocator)
            or self.locator.artifact_type != _GATE3_SELECTION_SCHEMA
        ):
            raise ClosedValidationError(
                "resolved_gate3_selection_state.locator: expected "
                f"ArtifactLocator for {_GATE3_SELECTION_SCHEMA!r}"
            )
        if (
            not isinstance(self.selection_role, str)
            or self.selection_role not in _ALLOWED_GATE3_ROLES
        ):
            raise ClosedValidationError(
                "resolved_gate3_selection_state.selection_role: expected "
                f"one of {sorted(_ALLOWED_GATE3_ROLES)}, got {self.selection_role!r}"
            )
        validate_timestamp_utc_seconds(
            self.revalidated_at_utc,
            field_name="resolved_gate3_selection_state.revalidated_at_utc",
        )
        validate_timestamp_utc_seconds(
            self.valid_until_utc,
            field_name="resolved_gate3_selection_state.valid_until_utc",
        )
        revalidated_us = parse_timestamp_utc_micros(
            self.revalidated_at_utc,
            field_name="resolved_gate3_selection_state.revalidated_at_utc",
            allow_whole_seconds=True,
        )
        valid_until_us = parse_timestamp_utc_micros(
            self.valid_until_utc,
            field_name="resolved_gate3_selection_state.valid_until_utc",
            allow_whole_seconds=True,
        )
        if valid_until_us - revalidated_us != 900 * _MICROSECONDS_PER_SECOND:
            raise ClosedValidationError(
                "resolved_gate3_selection_state: Gate-3 freshness profile requires "
                "valid_until_utc - revalidated_at_utc == 900 seconds"
            )
        if (
            isinstance(self.maximum_age_seconds, bool)
            or self.maximum_age_seconds != 900
        ):
            raise ClosedValidationError(
                "resolved_gate3_selection_state.maximum_age_seconds: must equal 900"
            )
        if (
            isinstance(self.maximum_clock_uncertainty_ms, bool)
            or self.maximum_clock_uncertainty_ms != 1000
        ):
            raise ClosedValidationError(
                "resolved_gate3_selection_state.maximum_clock_uncertainty_ms: must equal 1000"
            )
        if (
            isinstance(self.maximum_provider_dispatch_deadline_seconds, bool)
            or self.maximum_provider_dispatch_deadline_seconds != 60
        ):
            raise ClosedValidationError(
                "resolved_gate3_selection_state.maximum_provider_dispatch_deadline_seconds: "
                "must equal 60"
            )
        validate_sha256_prefixed(
            self.candidate_driver_contract_digest,
            field_name="resolved_gate3_selection_state.candidate_driver_contract_digest",
        )
        validate_sha256_prefixed(
            self.canonical_query_digest,
            field_name="resolved_gate3_selection_state.canonical_query_digest",
        )
        validate_sha256_prefixed(
            self.schema_bundle_digest,
            field_name="resolved_gate3_selection_state.schema_bundle_digest",
        )
        validate_sha256_prefixed(
            self.resource_mapping_contract_digest,
            field_name="resolved_gate3_selection_state.resource_mapping_contract_digest",
        )
        validate_opaque_ref(
            self.authorized_certification_scope,
            field_name="resolved_gate3_selection_state.authorized_certification_scope",
            expected_prefix="scope",
        )
        validate_sha256_prefixed(
            self.certification_fingerprint_digest,
            field_name="resolved_gate3_selection_state.certification_fingerprint_digest",
        )


@dataclass(frozen=True, slots=True)
class ResolvedHermesDelegationState:
    """Resolved runtime-owned `smart_ads/ibvi_ads_delegation_context/v1` state (ADR-0001 §4.2)."""

    locator: ArtifactLocator
    tenant_ref: str
    front_ref: str
    profile_ref: str
    binding_ref: str
    resource_scope_ref: str
    issued_at_utc: str
    valid_until_utc: str
    route: str = "/ibvi-ads"

    def __post_init__(self) -> None:
        if (
            not isinstance(self.locator, ArtifactLocator)
            or self.locator.artifact_type != _HERMES_DELEGATION_SCHEMA
        ):
            raise ClosedValidationError(
                "resolved_hermes_delegation_state.locator: expected "
                f"ArtifactLocator for {_HERMES_DELEGATION_SCHEMA!r}"
            )
        validate_opaque_ref(
            self.tenant_ref,
            field_name="resolved_hermes_delegation_state.tenant_ref",
            expected_prefix="tenant",
        )
        validate_opaque_ref(
            self.front_ref,
            field_name="resolved_hermes_delegation_state.front_ref",
            expected_prefix="front",
        )
        validate_opaque_ref(
            self.profile_ref,
            field_name="resolved_hermes_delegation_state.profile_ref",
            expected_prefix="profile",
        )
        validate_opaque_ref(
            self.binding_ref,
            field_name="resolved_hermes_delegation_state.binding_ref",
            expected_prefix="binding",
        )
        validate_opaque_ref(
            self.resource_scope_ref,
            field_name="resolved_hermes_delegation_state.resource_scope_ref",
            expected_prefix="scope",
        )
        validate_timestamp_utc_seconds(
            self.issued_at_utc,
            field_name="resolved_hermes_delegation_state.issued_at_utc",
        )
        validate_timestamp_utc_seconds(
            self.valid_until_utc,
            field_name="resolved_hermes_delegation_state.valid_until_utc",
        )
        issued_us = parse_timestamp_utc_micros(
            self.issued_at_utc,
            field_name="resolved_hermes_delegation_state.issued_at_utc",
            allow_whole_seconds=True,
        )
        valid_until_us = parse_timestamp_utc_micros(
            self.valid_until_utc,
            field_name="resolved_hermes_delegation_state.valid_until_utc",
            allow_whole_seconds=True,
        )
        if issued_us > valid_until_us:
            raise ClosedValidationError(
                "resolved_hermes_delegation_state: issued_at_utc must not exceed valid_until_utc"
            )
        if self.route != "/ibvi-ads":
            raise ClosedValidationError(
                "resolved_hermes_delegation_state.route: must equal '/ibvi-ads'"
            )


@dataclass(frozen=True, slots=True)
class ResolvedLiveCertificationState:
    """Resolved live certification head, transition, certificate, and operational renewal metadata."""

    head_locator: ArtifactLocator
    transition_locator: ArtifactLocator
    certificate_locator: ArtifactLocator
    tenant_ref: str
    binding_ref: str
    resource_scope_ref: str
    driver_id: str
    driver_contract_digest: str
    canonical_query_digest: str
    schema_bundle_digest: str
    resource_mapping_contract_digest: str
    certificate_issued_at_utc: str
    certificate_valid_until_utc: str
    certified_fingerprint_digest: str
    renewal_selection_role: str
    renewal_fingerprint_digest: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.head_locator, ArtifactLocator)
            or self.head_locator.artifact_type != _LIVE_CERT_HEAD_SCHEMA
        ):
            raise ClosedValidationError(
                "resolved_live_certification_state.head_locator: expected "
                f"ArtifactLocator for {_LIVE_CERT_HEAD_SCHEMA!r}"
            )
        if (
            not isinstance(self.transition_locator, ArtifactLocator)
            or self.transition_locator.artifact_type
            != _LIVE_CERT_TRANSITION_SCHEMA
        ):
            raise ClosedValidationError(
                "resolved_live_certification_state.transition_locator: expected "
                f"ArtifactLocator for {_LIVE_CERT_TRANSITION_SCHEMA!r}"
            )
        if (
            not isinstance(self.certificate_locator, ArtifactLocator)
            or self.certificate_locator.artifact_type
            != _LIVE_CERT_CERTIFICATE_SCHEMA
        ):
            raise ClosedValidationError(
                "resolved_live_certification_state.certificate_locator: expected "
                f"ArtifactLocator for {_LIVE_CERT_CERTIFICATE_SCHEMA!r}"
            )
        validate_opaque_ref(
            self.tenant_ref,
            field_name="resolved_live_certification_state.tenant_ref",
            expected_prefix="tenant",
        )
        validate_opaque_ref(
            self.binding_ref,
            field_name="resolved_live_certification_state.binding_ref",
            expected_prefix="binding",
        )
        validate_opaque_ref(
            self.resource_scope_ref,
            field_name="resolved_live_certification_state.resource_scope_ref",
            expected_prefix="scope",
        )
        checked_driver = validate_non_empty_str(
            self.driver_id,
            field_name="resolved_live_certification_state.driver_id",
        )
        if any(ch.isspace() for ch in checked_driver):
            raise ClosedValidationError(
                "resolved_live_certification_state.driver_id: whitespace is forbidden"
            )
        validate_sha256_prefixed(
            self.driver_contract_digest,
            field_name="resolved_live_certification_state.driver_contract_digest",
        )
        validate_sha256_prefixed(
            self.canonical_query_digest,
            field_name="resolved_live_certification_state.canonical_query_digest",
        )
        validate_sha256_prefixed(
            self.schema_bundle_digest,
            field_name="resolved_live_certification_state.schema_bundle_digest",
        )
        validate_sha256_prefixed(
            self.resource_mapping_contract_digest,
            field_name="resolved_live_certification_state.resource_mapping_contract_digest",
        )
        validate_timestamp_utc_seconds(
            self.certificate_issued_at_utc,
            field_name="resolved_live_certification_state.certificate_issued_at_utc",
        )
        validate_timestamp_utc_seconds(
            self.certificate_valid_until_utc,
            field_name="resolved_live_certification_state.certificate_valid_until_utc",
        )
        cert_issued_us = parse_timestamp_utc_micros(
            self.certificate_issued_at_utc,
            field_name="resolved_live_certification_state.certificate_issued_at_utc",
            allow_whole_seconds=True,
        )
        cert_valid_until_us = parse_timestamp_utc_micros(
            self.certificate_valid_until_utc,
            field_name="resolved_live_certification_state.certificate_valid_until_utc",
            allow_whole_seconds=True,
        )
        if cert_issued_us > cert_valid_until_us:
            raise ClosedValidationError(
                "resolved_live_certification_state: certificate_issued_at_utc "
                "must not exceed certificate_valid_until_utc"
            )
        validate_sha256_prefixed(
            self.certified_fingerprint_digest,
            field_name="resolved_live_certification_state.certified_fingerprint_digest",
        )
        validate_non_empty_str(
            self.renewal_selection_role,
            field_name="resolved_live_certification_state.renewal_selection_role",
        )
        validate_sha256_prefixed(
            self.renewal_fingerprint_digest,
            field_name="resolved_live_certification_state.renewal_fingerprint_digest",
        )


@dataclass(frozen=True, slots=True)
class ResolvedPrerequisiteBundle:
    """Resolved purpose-discriminated prerequisite locators and role/certification/delegation metadata."""

    locators: PurposePrerequisiteLocators
    gate3_selection: ResolvedGate3SelectionState | None = None
    live_certification: ResolvedLiveCertificationState | None = None
    hermes_delegation: ResolvedHermesDelegationState | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.locators, PurposePrerequisiteLocators):
            raise ClosedValidationError(
                "resolved_prerequisite_bundle.locators: expected PurposePrerequisiteLocators"
            )
        if self.gate3_selection is not None and not isinstance(
            self.gate3_selection, ResolvedGate3SelectionState
        ):
            raise ClosedValidationError(
                "resolved_prerequisite_bundle.gate3_selection: expected "
                "ResolvedGate3SelectionState or None"
            )
        if self.live_certification is not None and not isinstance(
            self.live_certification, ResolvedLiveCertificationState
        ):
            raise ClosedValidationError(
                "resolved_prerequisite_bundle.live_certification: expected "
                "ResolvedLiveCertificationState or None"
            )
        if self.hermes_delegation is not None and not isinstance(
            self.hermes_delegation, ResolvedHermesDelegationState
        ):
            raise ClosedValidationError(
                "resolved_prerequisite_bundle.hermes_delegation: expected "
                "ResolvedHermesDelegationState or None"
            )


@runtime_checkable
class ClockAttestationPort(Protocol):
    """Port resolving protected cell clock attestation state."""

    def get_authenticated_clock(self) -> ResolvedClockState: ...


@runtime_checkable
class TimezonePolicyPort(Protocol):
    """Port resolving protected reporting timezone rule table."""

    def get_reporting_timezone_rules(self) -> TimezoneRuleSnapshot: ...


@runtime_checkable
class ProtectedRegistryPort(Protocol):
    """Port resolving active private registry snapshot and pinned driver contract."""

    def get_active_registry(self, *, tenant_ref: str) -> ResolvedRegistryState: ...


@runtime_checkable
class PurposePrerequisitePort(Protocol):
    """Port resolving purpose-specific prerequisite locators and live-certification state."""

    def resolve_prerequisites(
        self,
        *,
        request: CollectionRequest,
        canonical_query: CanonicalQueryContract,
        clock_state: ResolvedClockState,
    ) -> ResolvedPrerequisiteBundle: ...


@runtime_checkable
class ExpectedInventoryPort(Protocol):
    """Port resolving response-independent `expected_resource_inventory/v1` (`U`)."""

    def resolve_expected_inventory(
        self,
        *,
        registry_snapshot_locator: ArtifactLocator,
        tenant_ref: str,
        binding_ref: str,
        account_ref: str,
        resource_scope_ref: str,
        date_range: DateRange,
    ) -> ExpectedResourceInventory | None: ...


@runtime_checkable
class ReservationPort(Protocol):
    """Port recording pre-I/O authorization reservation for an admitted live call."""

    def reserve_admitted_call(
        self,
        *,
        admitted_collection_locator: ArtifactLocator,
        call_side: CallSide,
    ) -> ArtifactLocator: ...


@runtime_checkable
class EnvelopeSignerPort(Protocol):
    """Port signing and storing a P1 envelope in the cell immutable object store."""

    def sign_and_store(
        self, envelope_dict: dict[str, Any], *, domain_prefix: str
    ) -> tuple[dict[str, Any], ArtifactLocator]: ...


@dataclass(frozen=True, slots=True)
class CellRuntimePorts:
    """Bundle of zero-side-effect cell state resolution ports used during admission."""

    clock_port: ClockAttestationPort
    timezone_port: TimezonePolicyPort
    registry_port: ProtectedRegistryPort
    prerequisite_port: PurposePrerequisitePort
    signer_port: EnvelopeSignerPort | None = None
    require_hermes_delegation: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.clock_port, ClockAttestationPort):
            raise ClosedValidationError(
                "cell_runtime_ports.clock_port: expected ClockAttestationPort"
            )
        if not isinstance(self.timezone_port, TimezonePolicyPort):
            raise ClosedValidationError(
                "cell_runtime_ports.timezone_port: expected TimezonePolicyPort"
            )
        if not isinstance(self.registry_port, ProtectedRegistryPort):
            raise ClosedValidationError(
                "cell_runtime_ports.registry_port: expected ProtectedRegistryPort"
            )
        if not isinstance(self.prerequisite_port, PurposePrerequisitePort):
            raise ClosedValidationError(
                "cell_runtime_ports.prerequisite_port: expected PurposePrerequisitePort"
            )
        if self.signer_port is not None and not isinstance(
            self.signer_port, EnvelopeSignerPort
        ):
            raise ClosedValidationError(
                "cell_runtime_ports.signer_port: expected EnvelopeSignerPort or None"
            )
        if not isinstance(self.require_hermes_delegation, bool):
            raise ClosedValidationError(
                "cell_runtime_ports.require_hermes_delegation: expected bool"
            )


__all__ = [
    "AmbiguousLocalDayError",
    "CellRuntimePorts",
    "ClockAttestation",
    "ClockAttestationPort",
    "EnvelopeSignerPort",
    "ExpectedInventoryPort",
    "ProtectedRegistryPort",
    "PurposePrerequisitePort",
    "ReservationPort",
    "ResolvedClockState",
    "ResolvedGate3SelectionState",
    "ResolvedHermesDelegationState",
    "ResolvedLiveCertificationState",
    "ResolvedPrerequisiteBundle",
    "ResolvedRegistryState",
    "TimezonePolicyPort",
    "TimezoneRuleSnapshot",
    "UtcOffsetTransition",
]
