"""Capability lifecycle state machine, revalidation transitions, and invalidation transitions (ADR-0001 §§5.1, 5.4)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, ClassVar, Final, Literal

from smart_ads.contracts.jcs import (
    MAX_JCS_SAFE_INT,
    ArtifactLocator,
    P1Integrity,
    canonicalize_jcs,
    p1_content_digest,
    sort_utf8_strings,
)
from smart_ads.contracts.scalars import (
    ClosedValidationError,
    require_exact_keys,
    require_mapping,
    validate_non_empty_str,
    validate_opaque_ref,
    validate_sha256_prefixed,
    validate_timestamp_utc_seconds,
)
from smart_ads.domain.registry import CapabilityState, PrivateRegistrySnapshot

TransitionKind = Literal[
    "fixture_7a_promotion",
    "initial_live_certification",
    "live_recertification",
    "mark_unavailable",
    "mark_deferred",
    "begin_revalidation",
    "complete_revalidation_to_declared",
    "invalidate_fixture_certified",
    "invalidate_live_certified",
]

_ALL_CAPABILITY_STATES: Final[frozenset[str]] = frozenset(
    {
        "declared",
        "fixture_certified",
        "live_certified",
        "unavailable",
        "deferred",
        "invalidated",
        "revalidation_pending",
    }
)

ALLOWED_CAPABILITY_TRANSITIONS: Final[
    frozenset[tuple[CapabilityState, CapabilityState, TransitionKind]]
] = frozenset(
    {
        ("declared", "fixture_certified", "fixture_7a_promotion"),
        ("fixture_certified", "live_certified", "initial_live_certification"),
        ("live_certified", "live_certified", "live_recertification"),
        ("declared", "unavailable", "mark_unavailable"),
        ("declared", "deferred", "mark_deferred"),
        ("unavailable", "revalidation_pending", "begin_revalidation"),
        ("deferred", "revalidation_pending", "begin_revalidation"),
        ("invalidated", "revalidation_pending", "begin_revalidation"),
        (
            "revalidation_pending",
            "declared",
            "complete_revalidation_to_declared",
        ),
        ("fixture_certified", "invalidated", "invalidate_fixture_certified"),
        ("live_certified", "invalidated", "invalidate_live_certified"),
    }
)

IO_DENIED_CAPABILITY_STATES: Final[frozenset[CapabilityState]] = frozenset(
    {"unavailable", "deferred", "invalidated", "revalidation_pending"}
)

_REVALIDATION_KINDS: Final[frozenset[str]] = frozenset(
    {"begin_revalidation", "complete_revalidation_to_declared"}
)
_INVALIDATION_KINDS: Final[frozenset[str]] = frozenset(
    {"invalidate_fixture_certified", "invalidate_live_certified"}
)
_LIVE_CERTIFICATION_HEAD_SCHEMA: Final[str] = (
    "smart_ads/live_certification_head/v1"
)

_REVALIDATION_CORE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "$schema",
        "transition_id",
        "capability_ref",
        "capability_semantic_version",
        "required_metrics",
        "resource_scope_ref",
        "driver_contract_digest",
        "pinned_source_digest",
        "prior_snapshot_locator",
        "prior_snapshot_digest",
        "prior_state",
        "new_snapshot_locator",
        "new_snapshot_digest",
        "new_state",
        "transition_kind",
        "fresh_evidence_locators",
        "reason",
        "signer_principal_ref",
        "transitioned_at_utc",
        "cas_sequence",
    }
)
_INVALIDATION_CORE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "$schema",
        "transition_id",
        "capability_ref",
        "prior_snapshot_locator",
        "prior_snapshot_digest",
        "prior_state",
        "new_snapshot_locator",
        "new_snapshot_digest",
        "new_state",
        "transition_kind",
        "disqualifying_evidence_locators",
        "invalidated_live_certification_head_locator",
        "reason",
        "signer_principal_ref",
        "transitioned_at_utc",
        "cas_sequence",
    }
)


def is_io_denied_state(state: CapabilityState) -> bool:
    """Return True if `state` denies credentials, transport, and provider I/O (ADR-0001 §5.1 L733–734)."""
    if not isinstance(state, str) or state not in _ALL_CAPABILITY_STATES:
        raise ClosedValidationError(
            f"capability_state: invalid capability state {state!r}"
        )
    return state in IO_DENIED_CAPABILITY_STATES


def validate_capability_transition(
    from_state: CapabilityState,
    to_state: CapabilityState,
    transition_kind: TransitionKind,
) -> None:
    """Validate `(from_state, to_state, transition_kind)` against the closed 11-arrow lifecycle."""
    if (
        not isinstance(from_state, str)
        or not isinstance(to_state, str)
        or not isinstance(transition_kind, str)
        or (from_state, to_state, transition_kind)
        not in ALLOWED_CAPABILITY_TRANSITIONS
    ):
        raise ClosedValidationError(
            f"capability_transition: disallowed transition "
            f"({from_state!r} -> {to_state!r} via {transition_kind!r})"
        )


def _validate_cas_sequence(value: object, *, field_name: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not (1 <= value <= MAX_JCS_SAFE_INT)
    ):
        raise ClosedValidationError(
            f"{field_name}: expected positive safe int >= 1, got {value!r}"
        )
    return value


def _validate_locator_tuple(
    values: object,
    *,
    field_name: str,
    allow_empty: bool,
) -> tuple[ArtifactLocator, ...]:
    if not isinstance(values, (list, tuple)):
        raise ClosedValidationError(
            f"{field_name}: expected list or tuple of ArtifactLocator, got {type(values).__name__}"
        )
    if not allow_empty and len(values) == 0:
        raise ClosedValidationError(
            f"{field_name}: locator collection must be non-empty"
        )
    seen: set[bytes] = set()
    out: list[ArtifactLocator] = []
    for item in values:
        if not isinstance(item, ArtifactLocator):
            raise ClosedValidationError(
                f"{field_name}: every element must be ArtifactLocator"
            )
        key = canonicalize_jcs(item.to_dict())
        if key in seen:
            raise ClosedValidationError(
                f"{field_name}: duplicate ArtifactLocator is forbidden"
            )
        seen.add(key)
        out.append(item)
    return tuple(out)


def _validate_snapshot_pair(
    *,
    prior_locator: ArtifactLocator,
    prior_digest: str,
    new_locator: ArtifactLocator,
    new_digest: str,
    label: str,
) -> None:
    if (
        not isinstance(prior_locator, ArtifactLocator)
        or prior_locator.artifact_type != PrivateRegistrySnapshot.SCHEMA
    ):
        raise ClosedValidationError(
            f"{label}.prior_snapshot_locator: expected ArtifactLocator for "
            f"{PrivateRegistrySnapshot.SCHEMA!r}"
        )
    validate_sha256_prefixed(
        prior_digest, field_name=f"{label}.prior_snapshot_digest"
    )
    if prior_digest != prior_locator.content_digest:
        raise ClosedValidationError(
            f"{label}.prior_snapshot_digest: must equal prior_snapshot_locator.content_digest"
        )
    if (
        not isinstance(new_locator, ArtifactLocator)
        or new_locator.artifact_type != PrivateRegistrySnapshot.SCHEMA
    ):
        raise ClosedValidationError(
            f"{label}.new_snapshot_locator: expected ArtifactLocator for "
            f"{PrivateRegistrySnapshot.SCHEMA!r}"
        )
    validate_sha256_prefixed(
        new_digest, field_name=f"{label}.new_snapshot_digest"
    )
    if new_digest != new_locator.content_digest:
        raise ClosedValidationError(
            f"{label}.new_snapshot_digest: must equal new_snapshot_locator.content_digest"
        )
    if new_digest == prior_digest:
        raise ClosedValidationError(
            f"{label}.new_snapshot_digest: must differ from prior_snapshot_digest"
        )


@dataclass(frozen=True, slots=True)
class CapabilityRevalidationTransition:
    """Closed `smart_ads/capability_revalidation_transition/v1` P1 envelope (ADR-0001 §5.1 L727–738)."""

    SCHEMA: ClassVar[str] = "smart_ads/capability_revalidation_transition/v1"

    transition_id: str
    capability_ref: str
    capability_semantic_version: str
    required_metrics: tuple[str, ...]
    resource_scope_ref: str
    driver_contract_digest: str
    pinned_source_digest: str
    prior_snapshot_locator: ArtifactLocator
    prior_snapshot_digest: str
    prior_state: CapabilityState
    new_snapshot_locator: ArtifactLocator
    new_snapshot_digest: str
    new_state: CapabilityState
    transition_kind: TransitionKind
    fresh_evidence_locators: tuple[ArtifactLocator, ...]
    reason: str
    signer_principal_ref: str
    transitioned_at_utc: str
    cas_sequence: int
    integrity: P1Integrity | None = None

    def __post_init__(self) -> None:
        validate_opaque_ref(
            self.transition_id,
            field_name="capability_revalidation_transition.transition_id",
            expected_prefix="transition",
        )
        validate_opaque_ref(
            self.capability_ref,
            field_name="capability_revalidation_transition.capability_ref",
            expected_prefix="cap",
        )
        validate_non_empty_str(
            self.capability_semantic_version,
            field_name="capability_revalidation_transition.capability_semantic_version",
        )
        if not isinstance(self.required_metrics, (list, tuple)):
            raise ClosedValidationError(
                "capability_revalidation_transition.required_metrics: expected list or tuple"
            )
        sorted_metrics = sort_utf8_strings(
            self.required_metrics,
            field_name="capability_revalidation_transition.required_metrics",
            allow_empty=False,
            validator=lambda s: validate_opaque_ref(
                s,
                field_name="capability_revalidation_transition.required_metrics",
                expected_prefix="metric",
            ),
        )
        object.__setattr__(self, "required_metrics", sorted_metrics)

        validate_opaque_ref(
            self.resource_scope_ref,
            field_name="capability_revalidation_transition.resource_scope_ref",
            expected_prefix="scope",
        )
        validate_sha256_prefixed(
            self.driver_contract_digest,
            field_name="capability_revalidation_transition.driver_contract_digest",
        )
        validate_sha256_prefixed(
            self.pinned_source_digest,
            field_name="capability_revalidation_transition.pinned_source_digest",
        )

        _validate_snapshot_pair(
            prior_locator=self.prior_snapshot_locator,
            prior_digest=self.prior_snapshot_digest,
            new_locator=self.new_snapshot_locator,
            new_digest=self.new_snapshot_digest,
            label="capability_revalidation_transition",
        )
        if (
            not isinstance(self.transition_kind, str)
            or self.transition_kind not in _REVALIDATION_KINDS
        ):
            raise ClosedValidationError(
                "capability_revalidation_transition.transition_kind: expected "
                f"one of {sorted(_REVALIDATION_KINDS)}, got {self.transition_kind!r}"
            )
        validate_capability_transition(
            self.prior_state, self.new_state, self.transition_kind
        )

        require_non_empty_evidence = (
            self.transition_kind == "complete_revalidation_to_declared"
        )
        checked_evidence = _validate_locator_tuple(
            self.fresh_evidence_locators,
            field_name="capability_revalidation_transition.fresh_evidence_locators",
            allow_empty=not require_non_empty_evidence,
        )
        object.__setattr__(self, "fresh_evidence_locators", checked_evidence)

        validate_non_empty_str(
            self.reason,
            field_name="capability_revalidation_transition.reason",
        )
        validate_opaque_ref(
            self.signer_principal_ref,
            field_name="capability_revalidation_transition.signer_principal_ref",
            expected_prefix="principal",
        )
        validate_timestamp_utc_seconds(
            self.transitioned_at_utc,
            field_name="capability_revalidation_transition.transitioned_at_utc",
        )
        _validate_cas_sequence(
            self.cas_sequence,
            field_name="capability_revalidation_transition.cas_sequence",
        )

        if self.integrity is not None and not isinstance(
            self.integrity, P1Integrity
        ):
            raise ClosedValidationError(
                "capability_revalidation_transition.integrity: expected P1Integrity or None"
            )
        if self.integrity is not None and self.integrity.is_signed:
            expected_p1 = p1_content_digest(self.to_dict())
            if self.integrity.content_digest != expected_p1:
                raise ClosedValidationError(
                    "capability_revalidation_transition.integrity.content_digest: recomputed "
                    f"{expected_p1!r} != asserted {self.integrity.content_digest!r}"
                )

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "$schema": self.SCHEMA,
            "transition_id": self.transition_id,
            "capability_ref": self.capability_ref,
            "capability_semantic_version": self.capability_semantic_version,
            "required_metrics": list(self.required_metrics),
            "resource_scope_ref": self.resource_scope_ref,
            "driver_contract_digest": self.driver_contract_digest,
            "pinned_source_digest": self.pinned_source_digest,
            "prior_snapshot_locator": self.prior_snapshot_locator.to_dict(),
            "prior_snapshot_digest": self.prior_snapshot_digest,
            "prior_state": self.prior_state,
            "new_snapshot_locator": self.new_snapshot_locator.to_dict(),
            "new_snapshot_digest": self.new_snapshot_digest,
            "new_state": self.new_state,
            "transition_kind": self.transition_kind,
            "fresh_evidence_locators": [
                loc.to_dict() for loc in self.fresh_evidence_locators
            ],
            "reason": self.reason,
            "signer_principal_ref": self.signer_principal_ref,
            "transitioned_at_utc": self.transitioned_at_utc,
            "cas_sequence": self.cas_sequence,
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
    ) -> CapabilityRevalidationTransition:
        if not isinstance(require_signed, bool):
            raise ClosedValidationError("require_signed: expected bool")
        mapping = require_mapping(
            data, label="capability_revalidation_transition"
        )
        if require_signed or "integrity" in mapping:
            require_exact_keys(
                mapping,
                _REVALIDATION_CORE_KEYS | {"integrity"},
                label="capability_revalidation_transition",
            )
            integrity: P1Integrity | None = P1Integrity.from_dict(
                mapping["integrity"], require_signed=require_signed
            )
        else:
            require_exact_keys(
                mapping,
                _REVALIDATION_CORE_KEYS,
                label="capability_revalidation_transition",
            )
            integrity = None

        if mapping["$schema"] != cls.SCHEMA:
            raise ClosedValidationError(
                f"capability_revalidation_transition.$schema: expected {cls.SCHEMA!r}, "
                f"got {mapping['$schema']!r}"
            )
        if not isinstance(mapping["required_metrics"], list):
            raise ClosedValidationError(
                "capability_revalidation_transition.required_metrics: expected JSON array list"
            )
        sorted_metrics = sort_utf8_strings(
            mapping["required_metrics"],
            field_name="capability_revalidation_transition.required_metrics",
            allow_empty=False,
            validator=lambda s: validate_opaque_ref(
                s,
                field_name="capability_revalidation_transition.required_metrics",
                expected_prefix="metric",
            ),
        )
        if tuple(mapping["required_metrics"]) != sorted_metrics:
            raise ClosedValidationError(
                "capability_revalidation_transition.required_metrics: must already be UTF-8 sorted"
            )
        if not isinstance(mapping["fresh_evidence_locators"], list):
            raise ClosedValidationError(
                "capability_revalidation_transition.fresh_evidence_locators: expected JSON array list"
            )
        parsed_evidence = tuple(
            ArtifactLocator.from_dict(item)
            for item in mapping["fresh_evidence_locators"]
        )
        return cls(
            transition_id=mapping["transition_id"],
            capability_ref=mapping["capability_ref"],
            capability_semantic_version=mapping["capability_semantic_version"],
            required_metrics=sorted_metrics,
            resource_scope_ref=mapping["resource_scope_ref"],
            driver_contract_digest=mapping["driver_contract_digest"],
            pinned_source_digest=mapping["pinned_source_digest"],
            prior_snapshot_locator=ArtifactLocator.from_dict(
                mapping["prior_snapshot_locator"],
                expected_type=PrivateRegistrySnapshot.SCHEMA,
            ),
            prior_snapshot_digest=mapping["prior_snapshot_digest"],
            prior_state=mapping["prior_state"],
            new_snapshot_locator=ArtifactLocator.from_dict(
                mapping["new_snapshot_locator"],
                expected_type=PrivateRegistrySnapshot.SCHEMA,
            ),
            new_snapshot_digest=mapping["new_snapshot_digest"],
            new_state=mapping["new_state"],
            transition_kind=mapping["transition_kind"],
            fresh_evidence_locators=parsed_evidence,
            reason=mapping["reason"],
            signer_principal_ref=mapping["signer_principal_ref"],
            transitioned_at_utc=mapping["transitioned_at_utc"],
            cas_sequence=mapping["cas_sequence"],
            integrity=integrity,
        )


@dataclass(frozen=True, slots=True)
class CapabilityInvalidationTransition:
    """Closed `smart_ads/capability_invalidation_transition/v1` P1 envelope (ADR-0001 §5.1 L740–764)."""

    SCHEMA: ClassVar[str] = "smart_ads/capability_invalidation_transition/v1"

    transition_id: str
    capability_ref: str
    prior_snapshot_locator: ArtifactLocator
    prior_snapshot_digest: str
    prior_state: CapabilityState
    new_snapshot_locator: ArtifactLocator
    new_snapshot_digest: str
    new_state: CapabilityState
    transition_kind: TransitionKind
    disqualifying_evidence_locators: tuple[ArtifactLocator, ...]
    invalidated_live_certification_head_locator: ArtifactLocator | None
    reason: str
    signer_principal_ref: str
    transitioned_at_utc: str
    cas_sequence: int
    integrity: P1Integrity | None = None

    def __post_init__(self) -> None:
        validate_opaque_ref(
            self.transition_id,
            field_name="capability_invalidation_transition.transition_id",
            expected_prefix="transition",
        )
        validate_opaque_ref(
            self.capability_ref,
            field_name="capability_invalidation_transition.capability_ref",
            expected_prefix="cap",
        )
        _validate_snapshot_pair(
            prior_locator=self.prior_snapshot_locator,
            prior_digest=self.prior_snapshot_digest,
            new_locator=self.new_snapshot_locator,
            new_digest=self.new_snapshot_digest,
            label="capability_invalidation_transition",
        )
        if (
            not isinstance(self.transition_kind, str)
            or self.transition_kind not in _INVALIDATION_KINDS
        ):
            raise ClosedValidationError(
                "capability_invalidation_transition.transition_kind: expected "
                f"one of {sorted(_INVALIDATION_KINDS)}, got {self.transition_kind!r}"
            )
        if self.new_state != "invalidated":
            raise ClosedValidationError(
                "capability_invalidation_transition.new_state: must equal 'invalidated'"
            )
        validate_capability_transition(
            self.prior_state, self.new_state, self.transition_kind
        )

        checked_disq = _validate_locator_tuple(
            self.disqualifying_evidence_locators,
            field_name="capability_invalidation_transition.disqualifying_evidence_locators",
            allow_empty=False,
        )
        object.__setattr__(self, "disqualifying_evidence_locators", checked_disq)

        if self.prior_state == "live_certified":
            if (
                not isinstance(
                    self.invalidated_live_certification_head_locator,
                    ArtifactLocator,
                )
                or self.invalidated_live_certification_head_locator.artifact_type
                != _LIVE_CERTIFICATION_HEAD_SCHEMA
            ):
                raise ClosedValidationError(
                    "capability_invalidation_transition.invalidated_live_certification_head_locator: "
                    f"required ArtifactLocator for {_LIVE_CERTIFICATION_HEAD_SCHEMA!r} "
                    "when prior_state == 'live_certified'"
                )
        elif self.prior_state == "fixture_certified":
            if self.invalidated_live_certification_head_locator is not None:
                raise ClosedValidationError(
                    "capability_invalidation_transition.invalidated_live_certification_head_locator: "
                    "must be None when prior_state == 'fixture_certified'"
                )

        validate_non_empty_str(
            self.reason,
            field_name="capability_invalidation_transition.reason",
        )
        validate_opaque_ref(
            self.signer_principal_ref,
            field_name="capability_invalidation_transition.signer_principal_ref",
            expected_prefix="principal",
        )
        validate_timestamp_utc_seconds(
            self.transitioned_at_utc,
            field_name="capability_invalidation_transition.transitioned_at_utc",
        )
        _validate_cas_sequence(
            self.cas_sequence,
            field_name="capability_invalidation_transition.cas_sequence",
        )

        if self.integrity is not None and not isinstance(
            self.integrity, P1Integrity
        ):
            raise ClosedValidationError(
                "capability_invalidation_transition.integrity: expected P1Integrity or None"
            )
        if self.integrity is not None and self.integrity.is_signed:
            expected_p1 = p1_content_digest(self.to_dict())
            if self.integrity.content_digest != expected_p1:
                raise ClosedValidationError(
                    "capability_invalidation_transition.integrity.content_digest: recomputed "
                    f"{expected_p1!r} != asserted {self.integrity.content_digest!r}"
                )

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "$schema": self.SCHEMA,
            "transition_id": self.transition_id,
            "capability_ref": self.capability_ref,
            "prior_snapshot_locator": self.prior_snapshot_locator.to_dict(),
            "prior_snapshot_digest": self.prior_snapshot_digest,
            "prior_state": self.prior_state,
            "new_snapshot_locator": self.new_snapshot_locator.to_dict(),
            "new_snapshot_digest": self.new_snapshot_digest,
            "new_state": self.new_state,
            "transition_kind": self.transition_kind,
            "disqualifying_evidence_locators": [
                loc.to_dict() for loc in self.disqualifying_evidence_locators
            ],
            "invalidated_live_certification_head_locator": (
                None
                if self.invalidated_live_certification_head_locator is None
                else self.invalidated_live_certification_head_locator.to_dict()
            ),
            "reason": self.reason,
            "signer_principal_ref": self.signer_principal_ref,
            "transitioned_at_utc": self.transitioned_at_utc,
            "cas_sequence": self.cas_sequence,
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
    ) -> CapabilityInvalidationTransition:
        if not isinstance(require_signed, bool):
            raise ClosedValidationError("require_signed: expected bool")
        mapping = require_mapping(
            data, label="capability_invalidation_transition"
        )
        if require_signed or "integrity" in mapping:
            require_exact_keys(
                mapping,
                _INVALIDATION_CORE_KEYS | {"integrity"},
                label="capability_invalidation_transition",
            )
            integrity: P1Integrity | None = P1Integrity.from_dict(
                mapping["integrity"], require_signed=require_signed
            )
        else:
            require_exact_keys(
                mapping,
                _INVALIDATION_CORE_KEYS,
                label="capability_invalidation_transition",
            )
            integrity = None

        if mapping["$schema"] != cls.SCHEMA:
            raise ClosedValidationError(
                f"capability_invalidation_transition.$schema: expected {cls.SCHEMA!r}, "
                f"got {mapping['$schema']!r}"
            )
        if not isinstance(mapping["disqualifying_evidence_locators"], list):
            raise ClosedValidationError(
                "capability_invalidation_transition.disqualifying_evidence_locators: expected JSON array list"
            )
        parsed_disq = tuple(
            ArtifactLocator.from_dict(item)
            for item in mapping["disqualifying_evidence_locators"]
        )
        raw_head = mapping["invalidated_live_certification_head_locator"]
        parsed_head = (
            None if raw_head is None else ArtifactLocator.from_dict(raw_head)
        )
        return cls(
            transition_id=mapping["transition_id"],
            capability_ref=mapping["capability_ref"],
            prior_snapshot_locator=ArtifactLocator.from_dict(
                mapping["prior_snapshot_locator"],
                expected_type=PrivateRegistrySnapshot.SCHEMA,
            ),
            prior_snapshot_digest=mapping["prior_snapshot_digest"],
            prior_state=mapping["prior_state"],
            new_snapshot_locator=ArtifactLocator.from_dict(
                mapping["new_snapshot_locator"],
                expected_type=PrivateRegistrySnapshot.SCHEMA,
            ),
            new_snapshot_digest=mapping["new_snapshot_digest"],
            new_state=mapping["new_state"],
            transition_kind=mapping["transition_kind"],
            disqualifying_evidence_locators=parsed_disq,
            invalidated_live_certification_head_locator=parsed_head,
            reason=mapping["reason"],
            signer_principal_ref=mapping["signer_principal_ref"],
            transitioned_at_utc=mapping["transitioned_at_utc"],
            cas_sequence=mapping["cas_sequence"],
            integrity=integrity,
        )


__all__ = [
    "ALLOWED_CAPABILITY_TRANSITIONS",
    "CapabilityInvalidationTransition",
    "CapabilityRevalidationTransition",
    "IO_DENIED_CAPABILITY_STATES",
    "TransitionKind",
    "is_io_denied_state",
    "validate_capability_transition",
]
