"""Closed P1 retention roots, root-set heads, CAS receipts, and admission/release proofs (ADR-0001 §12.4)."""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, ClassVar, Final, Literal

from smart_ads.contracts.effects import (
    EffectProof, _P1EnvelopeBase, _require_json_list, _require_locator_digest_pair, _safe_int,
    _sorted_locator_tuple, _sorted_object_ref_tuple, _split_p1_envelope, _strict_id,
    _strict_str, _typed_locator, _verify_p1_integrity, sort_artifact_locators,
    sort_cell_object_refs,
)
from smart_ads.contracts.jcs import ADR_P1_DOMAIN_PREFIXES, ArtifactLocator, P1Integrity, jcs_sha256
from smart_ads.contracts.scalars import (
    ClosedValidationError, require_exact_keys, validate_envelope_timestamp_utc,
    validate_opaque_ref, validate_sha256_prefixed,
)

RetentionCasOperation = Literal["admit_roots", "release_roots"]

_RUN_CONTEXT_SCHEMA: Final[str] = "smart_ads/migration_run_context/v1"
_CAS_OPERATIONS: Final[frozenset[str]] = frozenset({"admit_roots", "release_roots"})


def compute_object_ref_set_digest(refs: Sequence[str], *, allow_empty: bool = False) -> str:
    """Compute canonical JCS SHA-256 digest of a sorted unique `cell-object:sha256:<hex>` array."""
    ordered = sort_cell_object_refs(refs, allow_empty=allow_empty, field_name="object_refs")
    return jcs_sha256(list(ordered))


def compute_root_locator_set_digest(
    locators: Sequence[ArtifactLocator], *, allow_empty: bool = True
) -> str:
    """Compute canonical JCS SHA-256 digest of a sorted unique `retention_root/v1` locator array."""
    ordered = sort_artifact_locators(
        locators, expected_type=RetentionRoot.SCHEMA, allow_empty=allow_empty, field_name="live_root_locators"
    )
    return jcs_sha256([loc.to_dict() for loc in ordered])


def _resolve_digest_or_default(current: object, expected: str, *, field_name: str) -> str:
    raw = _strict_str(current, field_name=field_name)
    if raw == "":
        return expected
    validate_sha256_prefixed(raw, field_name=field_name)
    if raw != expected:
        raise ClosedValidationError(f"{field_name}: recomputed {expected!r} != asserted {raw!r}")
    return raw


@dataclass(frozen=True, slots=True)
class RetentionRoot(_P1EnvelopeBase):
    """Closed P1 `smart_ads/retention_root/v1` envelope (8 core + `integrity` = 9 keys)."""

    SCHEMA: ClassVar[str] = "smart_ads/retention_root/v1"
    P1_DOMAIN_PREFIX: ClassVar[str] = ADR_P1_DOMAIN_PREFIXES[SCHEMA]
    CORE_KEYS: ClassVar[frozenset[str]] = frozenset(
        "$schema root_id cell_ref migration_run_context_locator target_artifact_locator "
        "pinned_object_refs pinned_object_set_digest created_at_utc".split()
    )
    KEYS: ClassVar[frozenset[str]] = CORE_KEYS | {"integrity"}

    root_id: str
    cell_ref: str
    migration_run_context_locator: ArtifactLocator
    target_artifact_locator: ArtifactLocator
    pinned_object_refs: tuple[str, ...]
    created_at_utc: str
    pinned_object_set_digest: str = ""
    integrity: P1Integrity | None = None

    def __post_init__(self) -> None:
        label = "retention_root"
        _strict_id(self.root_id, field_name=f"{label}.root_id")
        validate_opaque_ref(_strict_str(self.cell_ref, field_name=f"{label}.cell_ref"), field_name=f"{label}.cell_ref", expected_prefix="cell")
        _typed_locator(self.migration_run_context_locator, field_name=f"{label}.migration_run_context_locator", expected_type=_RUN_CONTEXT_SCHEMA)
        target = _typed_locator(self.target_artifact_locator, field_name=f"{label}.target_artifact_locator")
        if target.artifact_type == self.SCHEMA:
            raise ClosedValidationError(f"{label}.target_artifact_locator: retention_root cannot target another retention_root")
        refs = _sorted_object_ref_tuple(self.pinned_object_refs, field_name=f"{label}.pinned_object_refs", allow_empty=False)
        object.__setattr__(self, "pinned_object_refs", refs)
        object.__setattr__(self, "pinned_object_set_digest", _resolve_digest_or_default(self.pinned_object_set_digest, jcs_sha256(list(refs)), field_name=f"{label}.pinned_object_set_digest"))
        validate_envelope_timestamp_utc(self.created_at_utc, field_name=f"{label}.created_at_utc")
        _verify_p1_integrity(self.integrity, self.to_dict, label=label)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "$schema": self.SCHEMA, "root_id": self.root_id, "cell_ref": self.cell_ref,
            "migration_run_context_locator": self.migration_run_context_locator.to_dict(),
            "target_artifact_locator": self.target_artifact_locator.to_dict(),
            "pinned_object_refs": list(self.pinned_object_refs),
            "pinned_object_set_digest": self.pinned_object_set_digest, "created_at_utc": self.created_at_utc,
        }
        return out if self.integrity is None else {**out, "integrity": self.integrity.to_dict()}

    @classmethod
    def from_dict(cls, data: object, *, require_signed: bool = False) -> RetentionRoot:
        m, integrity = _split_p1_envelope(data, core_keys=cls.CORE_KEYS, schema=cls.SCHEMA, label="retention_root", require_signed=require_signed)
        raw_refs = _require_json_list(m, "pinned_object_refs", label="retention_root")
        digest = validate_sha256_prefixed(_strict_str(m["pinned_object_set_digest"], field_name="retention_root.pinned_object_set_digest"), field_name="retention_root.pinned_object_set_digest")
        return cls(
            root_id=m["root_id"], cell_ref=m["cell_ref"], pinned_object_refs=tuple(raw_refs),
            migration_run_context_locator=ArtifactLocator.from_dict(m["migration_run_context_locator"], expected_type=_RUN_CONTEXT_SCHEMA),
            target_artifact_locator=ArtifactLocator.from_dict(m["target_artifact_locator"]),
            created_at_utc=m["created_at_utc"], pinned_object_set_digest=digest, integrity=integrity,
        )


@dataclass(frozen=True, slots=True)
class RetentionRootSetHead(_P1EnvelopeBase):
    """Closed P1 `smart_ads/retention_root_set_head/v1` envelope (8 core + `integrity` = 9 keys)."""

    SCHEMA: ClassVar[str] = "smart_ads/retention_root_set_head/v1"
    P1_DOMAIN_PREFIX: ClassVar[str] = ADR_P1_DOMAIN_PREFIXES[SCHEMA]
    CORE_KEYS: ClassVar[frozenset[str]] = frozenset(
        "$schema head_id cell_ref head_epoch live_root_locators root_set_digest "
        "predecessor_head_locator issued_at_utc".split()
    )
    KEYS: ClassVar[frozenset[str]] = CORE_KEYS | {"integrity"}

    head_id: str
    cell_ref: str
    head_epoch: int
    live_root_locators: tuple[ArtifactLocator, ...]
    predecessor_head_locator: ArtifactLocator | None
    issued_at_utc: str
    root_set_digest: str = ""
    integrity: P1Integrity | None = None

    def __post_init__(self) -> None:
        label = "retention_root_set_head"
        _strict_id(self.head_id, field_name=f"{label}.head_id")
        validate_opaque_ref(_strict_str(self.cell_ref, field_name=f"{label}.cell_ref"), field_name=f"{label}.cell_ref", expected_prefix="cell")
        epoch = _safe_int(self.head_epoch, field_name=f"{label}.head_epoch", minimum=0)
        roots = _sorted_locator_tuple(self.live_root_locators, field_name=f"{label}.live_root_locators", expected_type=RetentionRoot.SCHEMA, allow_empty=True)
        object.__setattr__(self, "live_root_locators", roots)
        if epoch == 0:
            if roots or self.predecessor_head_locator is not None:
                raise ClosedValidationError(f"{label}: epoch-0 genesis head requires empty roots and null predecessor")
        else:
            if self.predecessor_head_locator is None:
                raise ClosedValidationError(f"{label}: head_epoch >= 1 requires non-null predecessor_head_locator")
            _typed_locator(self.predecessor_head_locator, field_name=f"{label}.predecessor_head_locator", expected_type=self.SCHEMA)
        object.__setattr__(self, "root_set_digest", _resolve_digest_or_default(self.root_set_digest, jcs_sha256([loc.to_dict() for loc in roots]), field_name=f"{label}.root_set_digest"))
        validate_envelope_timestamp_utc(self.issued_at_utc, field_name=f"{label}.issued_at_utc")
        _verify_p1_integrity(self.integrity, self.to_dict, label=label)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "$schema": self.SCHEMA, "head_id": self.head_id, "cell_ref": self.cell_ref,
            "head_epoch": self.head_epoch, "live_root_locators": [loc.to_dict() for loc in self.live_root_locators],
            "root_set_digest": self.root_set_digest, "issued_at_utc": self.issued_at_utc,
            "predecessor_head_locator": None if self.predecessor_head_locator is None else self.predecessor_head_locator.to_dict(),
        }
        return out if self.integrity is None else {**out, "integrity": self.integrity.to_dict()}

    @classmethod
    def from_dict(cls, data: object, *, require_signed: bool = False) -> RetentionRootSetHead:
        m, integrity = _split_p1_envelope(data, core_keys=cls.CORE_KEYS, schema=cls.SCHEMA, label="retention_root_set_head", require_signed=require_signed)
        raw_roots = _require_json_list(m, "live_root_locators", label="retention_root_set_head")
        digest = validate_sha256_prefixed(_strict_str(m["root_set_digest"], field_name="retention_root_set_head.root_set_digest"), field_name="retention_root_set_head.root_set_digest")
        raw_pred = m["predecessor_head_locator"]
        return cls(
            head_id=m["head_id"], cell_ref=m["cell_ref"], head_epoch=m["head_epoch"],
            live_root_locators=tuple(ArtifactLocator.from_dict(r, expected_type=RetentionRoot.SCHEMA) for r in raw_roots),
            predecessor_head_locator=None if raw_pred is None else ArtifactLocator.from_dict(raw_pred, expected_type=cls.SCHEMA),
            issued_at_utc=m["issued_at_utc"], root_set_digest=digest, integrity=integrity,
        )


@dataclass(frozen=True, slots=True)
class RetentionRootSetCasRequestProjection:
    """Closed 5-member `cas_request_projection` inside `retention_root_set_cas_receipt/v1`."""

    KEYS: ClassVar[frozenset[str]] = frozenset(
        "operation expected_old_head_epoch expected_old_head_digest "
        "requested_root_locators proposed_root_set_digest".split()
    )

    operation: RetentionCasOperation
    expected_old_head_epoch: int
    expected_old_head_digest: str
    requested_root_locators: tuple[ArtifactLocator, ...]
    proposed_root_set_digest: str

    def __post_init__(self) -> None:
        label = "retention_root_set_cas_request_projection"
        op = _strict_str(self.operation, field_name=f"{label}.operation")
        if op not in _CAS_OPERATIONS:
            raise ClosedValidationError(f"{label}.operation: invalid operation {op!r}")
        _safe_int(self.expected_old_head_epoch, field_name=f"{label}.expected_old_head_epoch", minimum=1 if op == "release_roots" else 0)
        validate_sha256_prefixed(_strict_str(self.expected_old_head_digest, field_name=f"{label}.expected_old_head_digest"), field_name=f"{label}.expected_old_head_digest")
        object.__setattr__(self, "requested_root_locators", _sorted_locator_tuple(self.requested_root_locators, field_name=f"{label}.requested_root_locators", expected_type=RetentionRoot.SCHEMA, allow_empty=False))
        validate_sha256_prefixed(_strict_str(self.proposed_root_set_digest, field_name=f"{label}.proposed_root_set_digest"), field_name=f"{label}.proposed_root_set_digest")

    def to_dict(self) -> dict[str, Any]:
        return {
            "operation": self.operation, "expected_old_head_epoch": self.expected_old_head_epoch,
            "expected_old_head_digest": self.expected_old_head_digest,
            "requested_root_locators": [loc.to_dict() for loc in self.requested_root_locators],
            "proposed_root_set_digest": self.proposed_root_set_digest,
        }

    @classmethod
    def from_dict(cls, data: object) -> RetentionRootSetCasRequestProjection:
        m = require_exact_keys(data, cls.KEYS, label="retention_root_set_cas_request_projection")
        raw_roots = _require_json_list(m, "requested_root_locators", label="retention_root_set_cas_request_projection")
        return cls(
            operation=m["operation"], expected_old_head_epoch=m["expected_old_head_epoch"],
            expected_old_head_digest=m["expected_old_head_digest"],
            requested_root_locators=tuple(ArtifactLocator.from_dict(r, expected_type=RetentionRoot.SCHEMA) for r in raw_roots),
            proposed_root_set_digest=m["proposed_root_set_digest"],
        )


@dataclass(frozen=True, slots=True)
class RetentionRootSetCasReceipt(_P1EnvelopeBase):
    """Closed P1 `smart_ads/retention_root_set_cas_receipt/v1` envelope (14 core + `integrity` = 15 keys)."""

    SCHEMA: ClassVar[str] = "smart_ads/retention_root_set_cas_receipt/v1"
    P1_DOMAIN_PREFIX: ClassVar[str] = ADR_P1_DOMAIN_PREFIXES[SCHEMA]
    CORE_KEYS: ClassVar[frozenset[str]] = frozenset(
        "$schema cas_receipt_id cell_ref operation cas_request_projection expected_old_head_locator "
        "expected_old_head_digest expected_old_epoch committed_new_head_locator committed_new_head_digest "
        "committed_new_epoch cas_status cas_linearization_id committed_at_utc".split()
    )
    KEYS: ClassVar[frozenset[str]] = CORE_KEYS | {"integrity"}

    cas_receipt_id: str
    cell_ref: str
    operation: RetentionCasOperation
    cas_request_projection: RetentionRootSetCasRequestProjection
    expected_old_head_locator: ArtifactLocator
    expected_old_head_digest: str
    expected_old_epoch: int
    committed_new_head_locator: ArtifactLocator
    committed_new_head_digest: str
    committed_new_epoch: int
    cas_status: str
    cas_linearization_id: str
    committed_at_utc: str
    integrity: P1Integrity | None = None

    def __post_init__(self) -> None:
        label = "retention_root_set_cas_receipt"
        _strict_id(self.cas_receipt_id, field_name=f"{label}.cas_receipt_id")
        validate_opaque_ref(_strict_str(self.cell_ref, field_name=f"{label}.cell_ref"), field_name=f"{label}.cell_ref", expected_prefix="cell")
        op = _strict_str(self.operation, field_name=f"{label}.operation")
        if op not in _CAS_OPERATIONS:
            raise ClosedValidationError(f"{label}.operation: invalid operation {op!r}")
        if type(self.cas_request_projection) is not RetentionRootSetCasRequestProjection:
            raise ClosedValidationError(f"{label}.cas_request_projection: expected RetentionRootSetCasRequestProjection")
        proj = RetentionRootSetCasRequestProjection.from_dict(self.cas_request_projection.to_dict())
        _, old_d = _require_locator_digest_pair(self.expected_old_head_locator, self.expected_old_head_digest, expected_type=RetentionRootSetHead.SCHEMA, loc_field=f"{label}.expected_old_head_locator", digest_field=f"{label}.expected_old_head_digest")
        _, new_d = _require_locator_digest_pair(self.committed_new_head_locator, self.committed_new_head_digest, expected_type=RetentionRootSetHead.SCHEMA, loc_field=f"{label}.committed_new_head_locator", digest_field=f"{label}.committed_new_head_digest")
        old_ep = _safe_int(self.expected_old_epoch, field_name=f"{label}.expected_old_epoch", minimum=1 if op == "release_roots" else 0)
        new_ep = _safe_int(self.committed_new_epoch, field_name=f"{label}.committed_new_epoch", minimum=1)
        if new_ep != old_ep + 1 or new_d == old_d:
            raise ClosedValidationError(f"{label}: committed head must advance epoch by +1 with distinct digest")
        if (proj.operation, proj.expected_old_head_epoch, proj.expected_old_head_digest) != (op, old_ep, old_d):
            raise ClosedValidationError(f"{label}: cas_request_projection disagrees with receipt header")
        if _strict_str(self.cas_status, field_name=f"{label}.cas_status") != "committed":
            raise ClosedValidationError(f"{label}.cas_status: must equal 'committed'")
        _strict_id(self.cas_linearization_id, field_name=f"{label}.cas_linearization_id")
        validate_envelope_timestamp_utc(self.committed_at_utc, field_name=f"{label}.committed_at_utc")
        _verify_p1_integrity(self.integrity, self.to_dict, label=label)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "$schema": self.SCHEMA, "cas_receipt_id": self.cas_receipt_id, "cell_ref": self.cell_ref,
            "operation": self.operation, "cas_request_projection": self.cas_request_projection.to_dict(),
            "expected_old_head_locator": self.expected_old_head_locator.to_dict(),
            "expected_old_head_digest": self.expected_old_head_digest, "expected_old_epoch": self.expected_old_epoch,
            "committed_new_head_locator": self.committed_new_head_locator.to_dict(),
            "committed_new_head_digest": self.committed_new_head_digest, "committed_new_epoch": self.committed_new_epoch,
            "cas_status": self.cas_status, "cas_linearization_id": self.cas_linearization_id,
            "committed_at_utc": self.committed_at_utc,
        }
        return out if self.integrity is None else {**out, "integrity": self.integrity.to_dict()}

    @classmethod
    def from_dict(cls, data: object, *, require_signed: bool = False) -> RetentionRootSetCasReceipt:
        m, integrity = _split_p1_envelope(data, core_keys=cls.CORE_KEYS, schema=cls.SCHEMA, label="retention_root_set_cas_receipt", require_signed=require_signed)
        return cls(
            cas_receipt_id=m["cas_receipt_id"], cell_ref=m["cell_ref"], operation=m["operation"],
            cas_request_projection=RetentionRootSetCasRequestProjection.from_dict(m["cas_request_projection"]),
            expected_old_head_locator=ArtifactLocator.from_dict(m["expected_old_head_locator"], expected_type=RetentionRootSetHead.SCHEMA),
            expected_old_head_digest=m["expected_old_head_digest"], expected_old_epoch=m["expected_old_epoch"],
            committed_new_head_locator=ArtifactLocator.from_dict(m["committed_new_head_locator"], expected_type=RetentionRootSetHead.SCHEMA),
            committed_new_head_digest=m["committed_new_head_digest"], committed_new_epoch=m["committed_new_epoch"],
            cas_status=m["cas_status"], cas_linearization_id=m["cas_linearization_id"],
            committed_at_utc=m["committed_at_utc"], integrity=integrity,
        )


@dataclass(frozen=True, slots=True)
class RetentionRootAdmissionResult(_P1EnvelopeBase):
    """Closed P1 `smart_ads/retention_root_admission_result/v1` (14 core + `integrity` = 15 keys)."""

    SCHEMA: ClassVar[str] = "smart_ads/retention_root_admission_result/v1"
    P1_DOMAIN_PREFIX: ClassVar[str] = ADR_P1_DOMAIN_PREFIXES[SCHEMA]
    CORE_KEYS: ClassVar[frozenset[str]] = frozenset(
        "$schema migration_run_context_locator cell_ref cas_receipt_locator cas_receipt_digest "
        "cas_linearization_id before_head_locator before_head_digest after_head_locator after_head_digest "
        "admitted_root_locators admitted_object_refs observed_status completed_at_utc".split()
    )
    KEYS: ClassVar[frozenset[str]] = CORE_KEYS | {"integrity"}

    migration_run_context_locator: ArtifactLocator
    cell_ref: str
    cas_receipt_locator: ArtifactLocator
    cas_receipt_digest: str
    cas_linearization_id: str
    before_head_locator: ArtifactLocator
    before_head_digest: str
    after_head_locator: ArtifactLocator
    after_head_digest: str
    admitted_root_locators: tuple[ArtifactLocator, ...]
    admitted_object_refs: tuple[str, ...]
    observed_status: str
    completed_at_utc: str
    integrity: P1Integrity | None = None

    def __post_init__(self) -> None:
        label = "retention_root_admission_result"
        _typed_locator(self.migration_run_context_locator, field_name=f"{label}.migration_run_context_locator", expected_type=_RUN_CONTEXT_SCHEMA)
        validate_opaque_ref(_strict_str(self.cell_ref, field_name=f"{label}.cell_ref"), field_name=f"{label}.cell_ref", expected_prefix="cell")
        _require_locator_digest_pair(self.cas_receipt_locator, self.cas_receipt_digest, expected_type=RetentionRootSetCasReceipt.SCHEMA, loc_field=f"{label}.cas_receipt_locator", digest_field=f"{label}.cas_receipt_digest")
        _strict_id(self.cas_linearization_id, field_name=f"{label}.cas_linearization_id")
        _, b_dig = _require_locator_digest_pair(self.before_head_locator, self.before_head_digest, expected_type=RetentionRootSetHead.SCHEMA, loc_field=f"{label}.before_head_locator", digest_field=f"{label}.before_head_digest")
        _, a_dig = _require_locator_digest_pair(self.after_head_locator, self.after_head_digest, expected_type=RetentionRootSetHead.SCHEMA, loc_field=f"{label}.after_head_locator", digest_field=f"{label}.after_head_digest")
        if b_dig == a_dig:
            raise ClosedValidationError(f"{label}: after_head_digest must differ from before_head_digest")
        object.__setattr__(self, "admitted_root_locators", _sorted_locator_tuple(self.admitted_root_locators, field_name=f"{label}.admitted_root_locators", expected_type=RetentionRoot.SCHEMA, allow_empty=False))
        object.__setattr__(self, "admitted_object_refs", _sorted_object_ref_tuple(self.admitted_object_refs, field_name=f"{label}.admitted_object_refs", allow_empty=False))
        if _strict_str(self.observed_status, field_name=f"{label}.observed_status") != "admitted":
            raise ClosedValidationError(f"{label}.observed_status: must equal 'admitted'")
        validate_envelope_timestamp_utc(self.completed_at_utc, field_name=f"{label}.completed_at_utc")
        _verify_p1_integrity(self.integrity, self.to_dict, label=label)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "$schema": self.SCHEMA, "cell_ref": self.cell_ref, "cas_linearization_id": self.cas_linearization_id,
            "migration_run_context_locator": self.migration_run_context_locator.to_dict(),
            "cas_receipt_locator": self.cas_receipt_locator.to_dict(), "cas_receipt_digest": self.cas_receipt_digest,
            "before_head_locator": self.before_head_locator.to_dict(), "before_head_digest": self.before_head_digest,
            "after_head_locator": self.after_head_locator.to_dict(), "after_head_digest": self.after_head_digest,
            "admitted_root_locators": [loc.to_dict() for loc in self.admitted_root_locators],
            "admitted_object_refs": list(self.admitted_object_refs),
            "observed_status": self.observed_status, "completed_at_utc": self.completed_at_utc,
        }
        return out if self.integrity is None else {**out, "integrity": self.integrity.to_dict()}

    @classmethod
    def from_dict(cls, data: object, *, require_signed: bool = False) -> RetentionRootAdmissionResult:
        m, integrity = _split_p1_envelope(data, core_keys=cls.CORE_KEYS, schema=cls.SCHEMA, label="retention_root_admission_result", require_signed=require_signed)
        raw_roots = _require_json_list(m, "admitted_root_locators", label="retention_root_admission_result")
        raw_refs = _require_json_list(m, "admitted_object_refs", label="retention_root_admission_result")
        return cls(
            migration_run_context_locator=ArtifactLocator.from_dict(m["migration_run_context_locator"], expected_type=_RUN_CONTEXT_SCHEMA),
            cell_ref=m["cell_ref"], cas_linearization_id=m["cas_linearization_id"],
            cas_receipt_locator=ArtifactLocator.from_dict(m["cas_receipt_locator"], expected_type=RetentionRootSetCasReceipt.SCHEMA),
            cas_receipt_digest=m["cas_receipt_digest"],
            before_head_locator=ArtifactLocator.from_dict(m["before_head_locator"], expected_type=RetentionRootSetHead.SCHEMA),
            before_head_digest=m["before_head_digest"],
            after_head_locator=ArtifactLocator.from_dict(m["after_head_locator"], expected_type=RetentionRootSetHead.SCHEMA),
            after_head_digest=m["after_head_digest"],
            admitted_root_locators=tuple(ArtifactLocator.from_dict(r, expected_type=RetentionRoot.SCHEMA) for r in raw_roots),
            admitted_object_refs=tuple(raw_refs), observed_status=m["observed_status"],
            completed_at_utc=m["completed_at_utc"], integrity=integrity,
        )


@dataclass(frozen=True, slots=True)
class RetentionRootAdmissionProof(_P1EnvelopeBase):
    """Closed P1 `smart_ads/retention_root_admission_proof/v1` (13 core + `integrity` = 14 keys)."""

    SCHEMA: ClassVar[str] = "smart_ads/retention_root_admission_proof/v1"
    P1_DOMAIN_PREFIX: ClassVar[str] = ADR_P1_DOMAIN_PREFIXES[SCHEMA]
    CORE_KEYS: ClassVar[frozenset[str]] = frozenset(
        "$schema migration_run_context_locator cell_ref effect_proof_locator admission_result_locator "
        "cas_receipt_locator before_head_locator after_head_locator admitted_root_locators "
        "admitted_object_refs before_reachability_graph_digest after_reachability_graph_digest verified_at_utc".split()
    )
    KEYS: ClassVar[frozenset[str]] = CORE_KEYS | {"integrity"}

    migration_run_context_locator: ArtifactLocator
    cell_ref: str
    effect_proof_locator: ArtifactLocator
    admission_result_locator: ArtifactLocator
    cas_receipt_locator: ArtifactLocator
    before_head_locator: ArtifactLocator
    after_head_locator: ArtifactLocator
    admitted_root_locators: tuple[ArtifactLocator, ...]
    admitted_object_refs: tuple[str, ...]
    before_reachability_graph_digest: str
    after_reachability_graph_digest: str
    verified_at_utc: str
    integrity: P1Integrity | None = None

    def __post_init__(self) -> None:
        label = "retention_root_admission_proof"
        _typed_locator(self.migration_run_context_locator, field_name=f"{label}.migration_run_context_locator", expected_type=_RUN_CONTEXT_SCHEMA)
        validate_opaque_ref(_strict_str(self.cell_ref, field_name=f"{label}.cell_ref"), field_name=f"{label}.cell_ref", expected_prefix="cell")
        _typed_locator(self.effect_proof_locator, field_name=f"{label}.effect_proof_locator", expected_type=EffectProof.SCHEMA)
        _typed_locator(self.admission_result_locator, field_name=f"{label}.admission_result_locator", expected_type=RetentionRootAdmissionResult.SCHEMA)
        _typed_locator(self.cas_receipt_locator, field_name=f"{label}.cas_receipt_locator", expected_type=RetentionRootSetCasReceipt.SCHEMA)
        b_loc = _typed_locator(self.before_head_locator, field_name=f"{label}.before_head_locator", expected_type=RetentionRootSetHead.SCHEMA)
        a_loc = _typed_locator(self.after_head_locator, field_name=f"{label}.after_head_locator", expected_type=RetentionRootSetHead.SCHEMA)
        if b_loc == a_loc:
            raise ClosedValidationError(f"{label}: after_head_locator must differ from before_head_locator")
        object.__setattr__(self, "admitted_root_locators", _sorted_locator_tuple(self.admitted_root_locators, field_name=f"{label}.admitted_root_locators", expected_type=RetentionRoot.SCHEMA, allow_empty=False))
        object.__setattr__(self, "admitted_object_refs", _sorted_object_ref_tuple(self.admitted_object_refs, field_name=f"{label}.admitted_object_refs", allow_empty=False))
        validate_sha256_prefixed(_strict_str(self.before_reachability_graph_digest, field_name=f"{label}.before_reachability_graph_digest"), field_name=f"{label}.before_reachability_graph_digest")
        validate_sha256_prefixed(_strict_str(self.after_reachability_graph_digest, field_name=f"{label}.after_reachability_graph_digest"), field_name=f"{label}.after_reachability_graph_digest")
        validate_envelope_timestamp_utc(self.verified_at_utc, field_name=f"{label}.verified_at_utc")
        _verify_p1_integrity(self.integrity, self.to_dict, label=label)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "$schema": self.SCHEMA, "cell_ref": self.cell_ref,
            "migration_run_context_locator": self.migration_run_context_locator.to_dict(),
            "effect_proof_locator": self.effect_proof_locator.to_dict(),
            "admission_result_locator": self.admission_result_locator.to_dict(),
            "cas_receipt_locator": self.cas_receipt_locator.to_dict(),
            "before_head_locator": self.before_head_locator.to_dict(),
            "after_head_locator": self.after_head_locator.to_dict(),
            "admitted_root_locators": [loc.to_dict() for loc in self.admitted_root_locators],
            "admitted_object_refs": list(self.admitted_object_refs),
            "before_reachability_graph_digest": self.before_reachability_graph_digest,
            "after_reachability_graph_digest": self.after_reachability_graph_digest,
            "verified_at_utc": self.verified_at_utc,
        }
        return out if self.integrity is None else {**out, "integrity": self.integrity.to_dict()}

    @classmethod
    def from_dict(cls, data: object, *, require_signed: bool = False) -> RetentionRootAdmissionProof:
        m, integrity = _split_p1_envelope(data, core_keys=cls.CORE_KEYS, schema=cls.SCHEMA, label="retention_root_admission_proof", require_signed=require_signed)
        raw_roots = _require_json_list(m, "admitted_root_locators", label="retention_root_admission_proof")
        raw_refs = _require_json_list(m, "admitted_object_refs", label="retention_root_admission_proof")
        return cls(
            migration_run_context_locator=ArtifactLocator.from_dict(m["migration_run_context_locator"], expected_type=_RUN_CONTEXT_SCHEMA),
            cell_ref=m["cell_ref"],
            effect_proof_locator=ArtifactLocator.from_dict(m["effect_proof_locator"], expected_type=EffectProof.SCHEMA),
            admission_result_locator=ArtifactLocator.from_dict(m["admission_result_locator"], expected_type=RetentionRootAdmissionResult.SCHEMA),
            cas_receipt_locator=ArtifactLocator.from_dict(m["cas_receipt_locator"], expected_type=RetentionRootSetCasReceipt.SCHEMA),
            before_head_locator=ArtifactLocator.from_dict(m["before_head_locator"], expected_type=RetentionRootSetHead.SCHEMA),
            after_head_locator=ArtifactLocator.from_dict(m["after_head_locator"], expected_type=RetentionRootSetHead.SCHEMA),
            admitted_root_locators=tuple(ArtifactLocator.from_dict(r, expected_type=RetentionRoot.SCHEMA) for r in raw_roots),
            admitted_object_refs=tuple(raw_refs),
            before_reachability_graph_digest=m["before_reachability_graph_digest"],
            after_reachability_graph_digest=m["after_reachability_graph_digest"],
            verified_at_utc=m["verified_at_utc"], integrity=integrity,
        )


@dataclass(frozen=True, slots=True)
class RetentionReleaseResult(_P1EnvelopeBase):
    """Closed P1 `smart_ads/retention_release_result/v1` (14 core + `integrity` = 15 keys)."""

    SCHEMA: ClassVar[str] = "smart_ads/retention_release_result/v1"
    P1_DOMAIN_PREFIX: ClassVar[str] = ADR_P1_DOMAIN_PREFIXES[SCHEMA]
    CORE_KEYS: ClassVar[frozenset[str]] = frozenset(
        "$schema migration_run_context_locator cell_ref cas_receipt_locator cas_receipt_digest "
        "cas_linearization_id before_head_locator before_head_digest after_head_locator after_head_digest "
        "released_root_locators released_object_refs observed_status completed_at_utc".split()
    )
    KEYS: ClassVar[frozenset[str]] = CORE_KEYS | {"integrity"}

    migration_run_context_locator: ArtifactLocator
    cell_ref: str
    cas_receipt_locator: ArtifactLocator
    cas_receipt_digest: str
    cas_linearization_id: str
    before_head_locator: ArtifactLocator
    before_head_digest: str
    after_head_locator: ArtifactLocator
    after_head_digest: str
    released_root_locators: tuple[ArtifactLocator, ...]
    released_object_refs: tuple[str, ...]
    observed_status: str
    completed_at_utc: str
    integrity: P1Integrity | None = None

    def __post_init__(self) -> None:
        label = "retention_release_result"
        _typed_locator(self.migration_run_context_locator, field_name=f"{label}.migration_run_context_locator", expected_type=_RUN_CONTEXT_SCHEMA)
        validate_opaque_ref(_strict_str(self.cell_ref, field_name=f"{label}.cell_ref"), field_name=f"{label}.cell_ref", expected_prefix="cell")
        _require_locator_digest_pair(self.cas_receipt_locator, self.cas_receipt_digest, expected_type=RetentionRootSetCasReceipt.SCHEMA, loc_field=f"{label}.cas_receipt_locator", digest_field=f"{label}.cas_receipt_digest")
        _strict_id(self.cas_linearization_id, field_name=f"{label}.cas_linearization_id")
        _, b_dig = _require_locator_digest_pair(self.before_head_locator, self.before_head_digest, expected_type=RetentionRootSetHead.SCHEMA, loc_field=f"{label}.before_head_locator", digest_field=f"{label}.before_head_digest")
        _, a_dig = _require_locator_digest_pair(self.after_head_locator, self.after_head_digest, expected_type=RetentionRootSetHead.SCHEMA, loc_field=f"{label}.after_head_locator", digest_field=f"{label}.after_head_digest")
        if b_dig == a_dig:
            raise ClosedValidationError(f"{label}: after_head_digest must differ from before_head_digest")
        object.__setattr__(self, "released_root_locators", _sorted_locator_tuple(self.released_root_locators, field_name=f"{label}.released_root_locators", expected_type=RetentionRoot.SCHEMA, allow_empty=False))
        object.__setattr__(self, "released_object_refs", _sorted_object_ref_tuple(self.released_object_refs, field_name=f"{label}.released_object_refs", allow_empty=True))
        if _strict_str(self.observed_status, field_name=f"{label}.observed_status") != "logically_unpinned":
            raise ClosedValidationError(f"{label}.observed_status: must equal 'logically_unpinned'")
        validate_envelope_timestamp_utc(self.completed_at_utc, field_name=f"{label}.completed_at_utc")
        _verify_p1_integrity(self.integrity, self.to_dict, label=label)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "$schema": self.SCHEMA, "cell_ref": self.cell_ref, "cas_linearization_id": self.cas_linearization_id,
            "migration_run_context_locator": self.migration_run_context_locator.to_dict(),
            "cas_receipt_locator": self.cas_receipt_locator.to_dict(), "cas_receipt_digest": self.cas_receipt_digest,
            "before_head_locator": self.before_head_locator.to_dict(), "before_head_digest": self.before_head_digest,
            "after_head_locator": self.after_head_locator.to_dict(), "after_head_digest": self.after_head_digest,
            "released_root_locators": [loc.to_dict() for loc in self.released_root_locators],
            "released_object_refs": list(self.released_object_refs),
            "observed_status": self.observed_status, "completed_at_utc": self.completed_at_utc,
        }
        return out if self.integrity is None else {**out, "integrity": self.integrity.to_dict()}

    @classmethod
    def from_dict(cls, data: object, *, require_signed: bool = False) -> RetentionReleaseResult:
        m, integrity = _split_p1_envelope(data, core_keys=cls.CORE_KEYS, schema=cls.SCHEMA, label="retention_release_result", require_signed=require_signed)
        raw_roots = _require_json_list(m, "released_root_locators", label="retention_release_result")
        raw_refs = _require_json_list(m, "released_object_refs", label="retention_release_result")
        return cls(
            migration_run_context_locator=ArtifactLocator.from_dict(m["migration_run_context_locator"], expected_type=_RUN_CONTEXT_SCHEMA),
            cell_ref=m["cell_ref"], cas_linearization_id=m["cas_linearization_id"],
            cas_receipt_locator=ArtifactLocator.from_dict(m["cas_receipt_locator"], expected_type=RetentionRootSetCasReceipt.SCHEMA),
            cas_receipt_digest=m["cas_receipt_digest"],
            before_head_locator=ArtifactLocator.from_dict(m["before_head_locator"], expected_type=RetentionRootSetHead.SCHEMA),
            before_head_digest=m["before_head_digest"],
            after_head_locator=ArtifactLocator.from_dict(m["after_head_locator"], expected_type=RetentionRootSetHead.SCHEMA),
            after_head_digest=m["after_head_digest"],
            released_root_locators=tuple(ArtifactLocator.from_dict(r, expected_type=RetentionRoot.SCHEMA) for r in raw_roots),
            released_object_refs=tuple(raw_refs), observed_status=m["observed_status"],
            completed_at_utc=m["completed_at_utc"], integrity=integrity,
        )


@dataclass(frozen=True, slots=True)
class RetentionReleaseProof(_P1EnvelopeBase):
    """Closed P1 `smart_ads/retention_release_proof/v1` (16 core + `integrity` = 17 keys)."""

    SCHEMA: ClassVar[str] = "smart_ads/retention_release_proof/v1"
    P1_DOMAIN_PREFIX: ClassVar[str] = ADR_P1_DOMAIN_PREFIXES[SCHEMA]
    CORE_KEYS: ClassVar[frozenset[str]] = frozenset(
        "$schema migration_run_context_locator cell_ref effect_proof_locator release_result_locator "
        "cas_receipt_locator before_head_locator after_head_locator released_root_locators retained_root_locators "
        "released_object_refs retained_object_refs before_reachability_graph_digest "
        "after_reachability_graph_digest retained_root_non_reachability_verified verified_at_utc".split()
    )
    KEYS: ClassVar[frozenset[str]] = CORE_KEYS | {"integrity"}

    migration_run_context_locator: ArtifactLocator
    cell_ref: str
    effect_proof_locator: ArtifactLocator
    release_result_locator: ArtifactLocator
    cas_receipt_locator: ArtifactLocator
    before_head_locator: ArtifactLocator
    after_head_locator: ArtifactLocator
    released_root_locators: tuple[ArtifactLocator, ...]
    retained_root_locators: tuple[ArtifactLocator, ...]
    released_object_refs: tuple[str, ...]
    retained_object_refs: tuple[str, ...]
    before_reachability_graph_digest: str
    after_reachability_graph_digest: str
    retained_root_non_reachability_verified: bool
    verified_at_utc: str
    integrity: P1Integrity | None = None

    def __post_init__(self) -> None:
        label = "retention_release_proof"
        _typed_locator(self.migration_run_context_locator, field_name=f"{label}.migration_run_context_locator", expected_type=_RUN_CONTEXT_SCHEMA)
        validate_opaque_ref(_strict_str(self.cell_ref, field_name=f"{label}.cell_ref"), field_name=f"{label}.cell_ref", expected_prefix="cell")
        _typed_locator(self.effect_proof_locator, field_name=f"{label}.effect_proof_locator", expected_type=EffectProof.SCHEMA)
        _typed_locator(self.release_result_locator, field_name=f"{label}.release_result_locator", expected_type=RetentionReleaseResult.SCHEMA)
        _typed_locator(self.cas_receipt_locator, field_name=f"{label}.cas_receipt_locator", expected_type=RetentionRootSetCasReceipt.SCHEMA)
        b_loc = _typed_locator(self.before_head_locator, field_name=f"{label}.before_head_locator", expected_type=RetentionRootSetHead.SCHEMA)
        a_loc = _typed_locator(self.after_head_locator, field_name=f"{label}.after_head_locator", expected_type=RetentionRootSetHead.SCHEMA)
        if b_loc == a_loc:
            raise ClosedValidationError(f"{label}: after_head_locator must differ from before_head_locator")
        rel_roots = _sorted_locator_tuple(self.released_root_locators, field_name=f"{label}.released_root_locators", expected_type=RetentionRoot.SCHEMA, allow_empty=False)
        ret_roots = _sorted_locator_tuple(self.retained_root_locators, field_name=f"{label}.retained_root_locators", expected_type=RetentionRoot.SCHEMA, allow_empty=True)
        rel_refs = _sorted_object_ref_tuple(self.released_object_refs, field_name=f"{label}.released_object_refs", allow_empty=True)
        ret_refs = _sorted_object_ref_tuple(self.retained_object_refs, field_name=f"{label}.retained_object_refs", allow_empty=True)
        if not set(rel_roots).isdisjoint(ret_roots) or not set(rel_refs).isdisjoint(ret_refs) or bool(ret_roots) != bool(ret_refs):
            raise ClosedValidationError(f"{label}: disjointness or retained-emptiness invariant violated")
        object.__setattr__(self, "released_root_locators", rel_roots)
        object.__setattr__(self, "retained_root_locators", ret_roots)
        object.__setattr__(self, "released_object_refs", rel_refs)
        object.__setattr__(self, "retained_object_refs", ret_refs)
        validate_sha256_prefixed(_strict_str(self.before_reachability_graph_digest, field_name=f"{label}.before_reachability_graph_digest"), field_name=f"{label}.before_reachability_graph_digest")
        validate_sha256_prefixed(_strict_str(self.after_reachability_graph_digest, field_name=f"{label}.after_reachability_graph_digest"), field_name=f"{label}.after_reachability_graph_digest")
        if type(self.retained_root_non_reachability_verified) is not bool or self.retained_root_non_reachability_verified is not True:
            raise ClosedValidationError(f"{label}.retained_root_non_reachability_verified: must be bool True")
        validate_envelope_timestamp_utc(self.verified_at_utc, field_name=f"{label}.verified_at_utc")
        _verify_p1_integrity(self.integrity, self.to_dict, label=label)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "$schema": self.SCHEMA, "cell_ref": self.cell_ref,
            "migration_run_context_locator": self.migration_run_context_locator.to_dict(),
            "effect_proof_locator": self.effect_proof_locator.to_dict(),
            "release_result_locator": self.release_result_locator.to_dict(),
            "cas_receipt_locator": self.cas_receipt_locator.to_dict(),
            "before_head_locator": self.before_head_locator.to_dict(),
            "after_head_locator": self.after_head_locator.to_dict(),
            "released_root_locators": [loc.to_dict() for loc in self.released_root_locators],
            "retained_root_locators": [loc.to_dict() for loc in self.retained_root_locators],
            "released_object_refs": list(self.released_object_refs),
            "retained_object_refs": list(self.retained_object_refs),
            "before_reachability_graph_digest": self.before_reachability_graph_digest,
            "after_reachability_graph_digest": self.after_reachability_graph_digest,
            "retained_root_non_reachability_verified": self.retained_root_non_reachability_verified,
            "verified_at_utc": self.verified_at_utc,
        }
        return out if self.integrity is None else {**out, "integrity": self.integrity.to_dict()}

    @classmethod
    def from_dict(cls, data: object, *, require_signed: bool = False) -> RetentionReleaseProof:
        m, integrity = _split_p1_envelope(data, core_keys=cls.CORE_KEYS, schema=cls.SCHEMA, label="retention_release_proof", require_signed=require_signed)
        raw_rel_r = _require_json_list(m, "released_root_locators", label="retention_release_proof")
        raw_ret_r = _require_json_list(m, "retained_root_locators", label="retention_release_proof")
        raw_rel_o = _require_json_list(m, "released_object_refs", label="retention_release_proof")
        raw_ret_o = _require_json_list(m, "retained_object_refs", label="retention_release_proof")
        return cls(
            migration_run_context_locator=ArtifactLocator.from_dict(m["migration_run_context_locator"], expected_type=_RUN_CONTEXT_SCHEMA),
            cell_ref=m["cell_ref"],
            effect_proof_locator=ArtifactLocator.from_dict(m["effect_proof_locator"], expected_type=EffectProof.SCHEMA),
            release_result_locator=ArtifactLocator.from_dict(m["release_result_locator"], expected_type=RetentionReleaseResult.SCHEMA),
            cas_receipt_locator=ArtifactLocator.from_dict(m["cas_receipt_locator"], expected_type=RetentionRootSetCasReceipt.SCHEMA),
            before_head_locator=ArtifactLocator.from_dict(m["before_head_locator"], expected_type=RetentionRootSetHead.SCHEMA),
            after_head_locator=ArtifactLocator.from_dict(m["after_head_locator"], expected_type=RetentionRootSetHead.SCHEMA),
            released_root_locators=tuple(ArtifactLocator.from_dict(r, expected_type=RetentionRoot.SCHEMA) for r in raw_rel_r),
            retained_root_locators=tuple(ArtifactLocator.from_dict(r, expected_type=RetentionRoot.SCHEMA) for r in raw_ret_r),
            released_object_refs=tuple(raw_rel_o), retained_object_refs=tuple(raw_ret_o),
            before_reachability_graph_digest=m["before_reachability_graph_digest"],
            after_reachability_graph_digest=m["after_reachability_graph_digest"],
            retained_root_non_reachability_verified=m["retained_root_non_reachability_verified"],
            verified_at_utc=m["verified_at_utc"], integrity=integrity,
        )


__all__ = [
    "RetentionCasOperation", "RetentionReleaseProof", "RetentionReleaseResult", "RetentionRoot",
    "RetentionRootAdmissionProof", "RetentionRootAdmissionResult", "RetentionRootSetCasReceipt",
    "RetentionRootSetCasRequestProjection", "RetentionRootSetHead",
    "compute_object_ref_set_digest", "compute_root_locator_set_digest",
]
