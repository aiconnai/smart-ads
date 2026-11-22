"""Closed generic 4-record anti-replay effect envelopes, discriminated subjects, and verifier (ADR-0001 §§12.3–12.5)."""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, fields
from itertools import pairwise
import re
from types import MappingProxyType
from typing import Any, ClassVar, Final, Literal, TypeVar
import unicodedata

from smart_ads.contracts.jcs import (
    ADR_P1_DOMAIN_PREFIXES, MAX_JCS_SAFE_INT, ArtifactLocator, P1Integrity,
    canonicalize_jcs, p1_content_digest, sort_utf8_strings,
)
from smart_ads.contracts.scalars import (
    ClosedValidationError, parse_timestamp_utc_micros, require_exact_keys, require_mapping,
    validate_envelope_timestamp_utc, validate_non_empty_str, validate_opaque_ref, validate_sha256_prefixed,
)

_T = TypeVar("_T")
ReservationStatus = Literal["reserved", "consumed", "in_doubt"]
InDoubtReason = Literal["pre_dispatch_freshness_failure", "pre_mutation_conflict_or_drift", "ambiguous_external_effect"]

_RUN_CONTEXT_SCHEMA: Final[str] = "smart_ads/migration_run_context/v1"
_ADMITTED_COLLECTION_SCHEMA: Final[str] = "smart_ads/admitted_collection/v1"
_REGISTRY_SNAPSHOT_SCHEMA: Final[str] = "smart_ads/private_registry_snapshot/v1"
_DELEGATION_CONTEXT_SCHEMA: Final[str] = "smart_ads/ibvi_ads_delegation_context/v1"
_RETENTION_HEAD_SCHEMA: Final[str] = "smart_ads/retention_root_set_head/v1"
_RETENTION_ROOT_SCHEMA: Final[str] = "smart_ads/retention_root/v1"
_CELL_OBJECT_REF_RE: Final[re.Pattern[str]] = re.compile(r"\Acell-object:sha256:[0-9a-f]{64}\Z")
_COLON_REF_RE: Final[re.Pattern[str]] = re.compile(r"\A[a-z][a-z0-9_-]*:[A-Za-z0-9._:-]+\Z")
_CALL_SIDES: Final[frozenset[str]] = frozenset({"candidate", "reference", "operational"})
_RESERVATION_STATUSES: Final[frozenset[str]] = frozenset({"reserved", "consumed", "in_doubt"})
_IN_DOUBT_REASONS: Final[frozenset[str]] = frozenset(
    {"pre_dispatch_freshness_failure", "pre_mutation_conflict_or_drift", "ambiguous_external_effect"}
)
_MAX_NONCE_LEN: Final[int] = 128


@dataclass(frozen=True, slots=True)
class EffectActionSpec:
    """Closed row of the ADR-0001 §12.3 effect-action matrix."""
    action: str
    subject_kind: str
    result_type: str
    dag_slot: str
    call_side: str | None = None


EFFECT_ACTION_MATRIX: Final[Mapping[str, EffectActionSpec]] = MappingProxyType({
    "provider_call_7b_candidate": EffectActionSpec("provider_call_7b_candidate", "provider_call_target", "smart_ads/collection_result/v1", "candidate_live_call_7b_effect_proof", "candidate"),
    "provider_call_7b_reference": EffectActionSpec("provider_call_7b_reference", "provider_call_target", "smart_ads/collection_result/v1", "reference_live_call_7b_effect_proof", "reference"),
    "provider_operational_read": EffectActionSpec("provider_operational_read", "provider_call_target", "smart_ads/collection_result/v1", "operational_provider_read_effect_proof", "operational"),
    "retention_release": EffectActionSpec("retention_release", "retention_release_target", "smart_ads/retention_release_result/v1", "retention_release_effect_proof"),
    "retention_root_admission": EffectActionSpec("retention_root_admission", "retention_root_admission_target", "smart_ads/retention_root_admission_result/v1", "retention_root_admission_effect_proof"),
})


def _serialize_val(val: Any) -> Any:
    if hasattr(val, "to_dict"):
        return val.to_dict()
    return [_serialize_val(item) for item in val] if isinstance(val, tuple) else val


class _SubjectBase:
    __slots__ = ()

    def to_dict(self) -> dict[str, Any]:
        return {f.name: _serialize_val(getattr(self, f.name)) for f in fields(self)}  # type: ignore[arg-type]


class _P1EnvelopeBase:
    """Shared `to_dict()`, `from_dict()`, and `locator()` over RFC 8785 canonical envelope bytes."""
    __slots__ = ()
    SCHEMA: ClassVar[str]
    CORE_KEYS: ClassVar[frozenset[str]]
    _LABEL: ClassVar[str] = "p1_envelope"
    _LOCATOR_FIELDS: ClassVar[Mapping[str, str | None]] = MappingProxyType({})

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"$schema": self.SCHEMA}
        for f in fields(self):  # type: ignore[arg-type]
            if f.name != "integrity":
                out[f.name] = _serialize_val(getattr(self, f.name))
        integrity = getattr(self, "integrity", None)
        return out if integrity is None else {**out, "integrity": integrity.to_dict()}

    @classmethod
    def from_dict(cls: type[_T], data: object, *, require_signed: bool = False) -> _T:
        m, integrity = _split_p1_envelope(data, core_keys=cls.CORE_KEYS, schema=cls.SCHEMA, label=cls._LABEL, require_signed=require_signed)  # type: ignore[attr-defined]
        loc_map: Mapping[str, str | None] = cls._LOCATOR_FIELDS  # type: ignore[attr-defined]
        lbl: str = cls._LABEL  # type: ignore[attr-defined]
        kw = {
            k: (_loc_from(m, k, loc_map[k]) if k in loc_map else parse_effect_subject(m[k], label=f"{lbl}.subject") if k == "subject" else m[k])
            for k in cls.CORE_KEYS if k != "$schema"  # type: ignore[attr-defined]
        }
        return cls(**kw, integrity=integrity)

    def locator(self) -> ArtifactLocator:
        return ArtifactLocator.for_canonical_bytes(self.SCHEMA, canonicalize_jcs(self.to_dict()))


def _strict_str(value: object, *, field_name: str) -> str:
    if type(value) is not str:
        raise ClosedValidationError(f"{field_name}: expected str, got {type(value).__name__}")
    return value

def _strict_id(value: object, *, field_name: str) -> str:
    checked = validate_non_empty_str(_strict_str(value, field_name=field_name), field_name=field_name)
    if checked != checked.strip() or any(unicodedata.category(ch) == "Cc" or ord(ch) <= 0x1F or 0x7F <= ord(ch) <= 0x9F for ch in checked):
        raise ClosedValidationError(f"{field_name}: leading/trailing whitespace and control chars are forbidden")
    return checked

def _validate_colon_ref(value: object, *, field_name: str) -> str:
    checked = _strict_id(value, field_name=field_name)
    if _COLON_REF_RE.fullmatch(checked) is None:
        raise ClosedValidationError(f"{field_name}: invalid reference {checked!r}")
    return checked

def _validate_nonce(value: object, *, field_name: str) -> str:
    checked = _strict_str(value, field_name=field_name)
    if not (1 <= len(checked) <= _MAX_NONCE_LEN) or any(not (0x21 <= ord(ch) <= 0x7E) for ch in checked):
        raise ClosedValidationError(f"{field_name}: expected 1..128 printable non-whitespace ASCII characters")
    return checked

def _safe_int(value: object, *, field_name: str, minimum: int = 0) -> int:
    if type(value) is not int or not (minimum <= value <= MAX_JCS_SAFE_INT):
        raise ClosedValidationError(f"{field_name}: expected int in [{minimum}, {MAX_JCS_SAFE_INT}], got {value!r}")
    return value

def validate_cell_object_ref(value: object, *, field_name: str = "object_ref") -> str:
    """Validate `'cell-object:sha256:' + 64 lowercase hex characters`."""
    if type(value) is not str or _CELL_OBJECT_REF_RE.fullmatch(value) is None:
        raise ClosedValidationError(f"{field_name}: expected 'cell-object:sha256:<64_lowercase_hex>'")
    return value

def sort_cell_object_refs(refs: Iterable[str], *, allow_empty: bool = False, field_name: str = "object_refs") -> tuple[str, ...]:
    """Validate unique `cell-object:sha256:<hex>` refs sorted by raw UTF-8 bytes."""
    return sort_utf8_strings(refs, field_name=field_name, allow_empty=allow_empty, validator=lambda s: validate_cell_object_ref(s, field_name=field_name))

def _sorted_object_ref_tuple(values: object, *, field_name: str, allow_empty: bool = False) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple)):
        raise ClosedValidationError(f"{field_name}: expected list or tuple, got {type(values).__name__}")
    raw_tuple = tuple(_strict_str(v, field_name=field_name) for v in values)
    ordered = sort_cell_object_refs(raw_tuple, allow_empty=allow_empty, field_name=field_name)
    if raw_tuple != ordered:
        raise ClosedValidationError(f"{field_name}: elements must already be sorted by raw UTF-8 bytes")
    return ordered

def _typed_locator(value: object, *, field_name: str, expected_type: str | None = None) -> ArtifactLocator:
    if type(value) is not ArtifactLocator:
        raise ClosedValidationError(f"{field_name}: expected ArtifactLocator, got {type(value).__name__}")
    try:
        raw = value.to_dict()
    except Exception as exc:
        raise ClosedValidationError(f"{field_name}: corrupted ArtifactLocator: {exc}") from None
    return ArtifactLocator.from_dict(raw, expected_type=expected_type)

def _loc_from(m: Mapping[str, Any], key: str, expected_type: str | None = None) -> ArtifactLocator:
    return ArtifactLocator.from_dict(m[key], expected_type=expected_type)

def sort_artifact_locators(
    locators: Iterable[ArtifactLocator], *, expected_type: str | None = None, allow_empty: bool = False, field_name: str = "locators"
) -> tuple[ArtifactLocator, ...]:
    """Validate unique `ArtifactLocator`s and sort by ascending RFC 8785 JCS bytes."""
    if isinstance(locators, (str, bytes, Mapping)) or not isinstance(locators, Iterable):
        raise ClosedValidationError(f"{field_name}: expected iterable of ArtifactLocator")
    keyed: list[tuple[bytes, ArtifactLocator]] = []
    seen: set[bytes] = set()
    for idx, item in enumerate(locators):
        loc = _typed_locator(item, field_name=f"{field_name}[{idx}]", expected_type=expected_type)
        key = canonicalize_jcs(loc.to_dict())
        if key in seen:
            raise ClosedValidationError(f"{field_name}[{idx}]: duplicate locator")
        seen.add(key)
        keyed.append((key, loc))
    if not allow_empty and not keyed:
        raise ClosedValidationError(f"{field_name}: collection must not be empty")
    keyed.sort(key=lambda pair: pair[0])
    return tuple(loc for _, loc in keyed)

def _sorted_locator_tuple(values: object, *, field_name: str, expected_type: str | None = None, allow_empty: bool = False) -> tuple[ArtifactLocator, ...]:
    if not isinstance(values, (list, tuple)):
        raise ClosedValidationError(f"{field_name}: expected list or tuple of ArtifactLocator")
    items = tuple(_typed_locator(v, field_name=f"{field_name}[]", expected_type=expected_type) for v in values)
    if not allow_empty and not items:
        raise ClosedValidationError(f"{field_name}: must not be empty")
    keys = [canonicalize_jcs(loc.to_dict()) for loc in items]
    if len(set(keys)) != len(keys):
        raise ClosedValidationError(f"{field_name}: duplicate locator")
    if any(left > right for left, right in pairwise(keys)):
        raise ClosedValidationError(f"{field_name}: locators must be sorted by ascending RFC 8785 bytes")
    return items

def _require_json_list(mapping: Mapping[str, Any], key: str, *, label: str) -> list[Any]:
    val = mapping[key]
    if not isinstance(val, list):
        raise ClosedValidationError(f"{label}.{key}: expected JSON array list")
    return val

def _require_locator_digest_pair(locator: object, digest_val: object, *, expected_type: str, loc_field: str, digest_field: str) -> tuple[ArtifactLocator, str]:
    loc = _typed_locator(locator, field_name=loc_field, expected_type=expected_type)
    checked_digest = validate_sha256_prefixed(_strict_str(digest_val, field_name=digest_field), field_name=digest_field)
    if checked_digest != loc.content_digest:
        raise ClosedValidationError(f"{digest_field}: must equal {loc_field}.content_digest")
    return loc, checked_digest

def _split_p1_envelope(data: object, *, core_keys: frozenset[str], schema: str, label: str, require_signed: bool) -> tuple[Mapping[str, Any], P1Integrity | None]:
    if type(require_signed) is not bool:
        raise ClosedValidationError("require_signed: expected bool")
    mapping = require_mapping(data, label=label)
    if require_signed or "integrity" in mapping:
        require_exact_keys(mapping, core_keys | {"integrity"}, label=label)
        integrity: P1Integrity | None = P1Integrity.from_dict(mapping["integrity"], require_signed=require_signed)
    else:
        require_exact_keys(mapping, core_keys, label=label)
        integrity = None
    if type(mapping["$schema"]) is not str or mapping["$schema"] != schema:
        raise ClosedValidationError(f"{label}.$schema: expected {schema!r}, got {mapping['$schema']!r}")
    return mapping, integrity

def _verify_p1_integrity(integrity: object, envelope_fn: Any, *, label: str) -> None:
    if integrity is not None and not isinstance(integrity, P1Integrity):
        raise ClosedValidationError(f"{label}.integrity: expected P1Integrity or None")
    if integrity is not None and ((integrity.content_digest is None) != (integrity.signature_base64 is None)):
        raise ClosedValidationError(f"{label}.integrity: partial signature state is forbidden")
    if integrity is not None and integrity.is_signed:
        expected = p1_content_digest(envelope_fn())
        if integrity.content_digest != expected:
            raise ClosedValidationError(f"{label}.integrity.content_digest: recomputed {expected!r} != asserted {integrity.content_digest!r}")

def _reparse_p1(obj: object, cls: type[_T], *, label: str, require_signed: bool = False) -> _T:
    if type(obj) is not cls:
        raise ClosedValidationError(f"{label}: expected {cls.__name__}, got {type(obj).__name__}")
    orig_int = getattr(obj, "integrity", None)
    if orig_int is not None and (not isinstance(orig_int, P1Integrity) or (orig_int.content_digest is None) != (orig_int.signature_base64 is None)):
        raise ClosedValidationError(f"{label}.integrity: corrupted P1Integrity")
    fresh: _T = cls.from_dict(obj.to_dict(), require_signed=require_signed)  # type: ignore[attr-defined]
    canonicalize_jcs(fresh.to_dict())  # type: ignore[attr-defined]
    return fresh

def _validate_retention_subject_common(obj: Any, *, label: str, min_epoch: int) -> None:
    if _strict_str(obj.subject_kind, field_name=f"{label}.subject_kind") != obj.SUBJECT_KIND:
        raise ClosedValidationError(f"{label}.subject_kind: expected {obj.SUBJECT_KIND!r}")
    _typed_locator(obj.migration_run_context_locator, field_name=f"{label}.migration_run_context_locator", expected_type=_RUN_CONTEXT_SCHEMA)
    validate_opaque_ref(_strict_str(obj.cell_ref, field_name=f"{label}.cell_ref"), field_name=f"{label}.cell_ref", expected_prefix="cell")
    _require_locator_digest_pair(
        obj.expected_root_set_head_locator, obj.expected_root_set_head_digest,
        expected_type=_RETENTION_HEAD_SCHEMA, loc_field=f"{label}.expected_root_set_head_locator", digest_field=f"{label}.expected_root_set_head_digest",
    )
    _safe_int(obj.expected_root_set_head_epoch, field_name=f"{label}.expected_root_set_head_epoch", minimum=min_epoch)
    for dname in ("before_reachability_graph_digest", "after_reachability_graph_digest", "proposed_root_set_digest"):
        validate_sha256_prefixed(_strict_str(getattr(obj, dname), field_name=f"{label}.{dname}"), field_name=f"{label}.{dname}")

def _check_locs(label: str, *specs: tuple[str, object, str | None]) -> None:
    for attr, val, expected_type in specs:
        _typed_locator(val, field_name=f"{label}.{attr}", expected_type=expected_type)

def _retention_subject_base_kwargs(m: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "migration_run_context_locator": _loc_from(m, "migration_run_context_locator", _RUN_CONTEXT_SCHEMA), "cell_ref": m["cell_ref"],
        "expected_root_set_head_locator": _loc_from(m, "expected_root_set_head_locator", _RETENTION_HEAD_SCHEMA),
        "expected_root_set_head_epoch": m["expected_root_set_head_epoch"], "expected_root_set_head_digest": m["expected_root_set_head_digest"],
        "before_reachability_graph_digest": m["before_reachability_graph_digest"],
        "after_reachability_graph_digest": m["after_reachability_graph_digest"],
        "proposed_root_set_digest": m["proposed_root_set_digest"], "subject_kind": m["subject_kind"],
    }


@dataclass(frozen=True, slots=True)
class ProviderCallTarget(_SubjectBase):
    """Discriminated `provider_call_target` authorization subject (ADR-0001 §12.3)."""
    SUBJECT_KIND: ClassVar[str] = "provider_call_target"
    KEYS: ClassVar[frozenset[str]] = frozenset("subject_kind migration_run_context_locator admitted_collection_locator call_side provider_target_ref canonical_query_digest registry_snapshot_locator tenant_ref binding_ref account_ref resource_scope_ref delegation_context_locator".split())
    migration_run_context_locator: ArtifactLocator
    admitted_collection_locator: ArtifactLocator
    call_side: str
    provider_target_ref: str
    canonical_query_digest: str
    registry_snapshot_locator: ArtifactLocator
    tenant_ref: str
    binding_ref: str
    account_ref: str
    resource_scope_ref: str
    delegation_context_locator: ArtifactLocator | None = None
    subject_kind: str = "provider_call_target"

    def __post_init__(self) -> None:
        label = "provider_call_target"
        if _strict_str(self.subject_kind, field_name=f"{label}.subject_kind") != self.SUBJECT_KIND:
            raise ClosedValidationError(f"{label}.subject_kind: expected {self.SUBJECT_KIND!r}")
        _check_locs(label, ("migration_run_context_locator", self.migration_run_context_locator, _RUN_CONTEXT_SCHEMA), ("admitted_collection_locator", self.admitted_collection_locator, _ADMITTED_COLLECTION_SCHEMA), ("registry_snapshot_locator", self.registry_snapshot_locator, _REGISTRY_SNAPSHOT_SCHEMA))
        if _strict_str(self.call_side, field_name=f"{label}.call_side") not in _CALL_SIDES:
            raise ClosedValidationError(f"{label}.call_side: invalid side {self.call_side!r}")
        _validate_colon_ref(self.provider_target_ref, field_name=f"{label}.provider_target_ref")
        validate_sha256_prefixed(_strict_str(self.canonical_query_digest, field_name=f"{label}.canonical_query_digest"), field_name=f"{label}.canonical_query_digest")
        for attr, pfx in (("tenant_ref", "tenant"), ("binding_ref", "binding"), ("account_ref", "account"), ("resource_scope_ref", "scope")):
            validate_opaque_ref(_strict_str(getattr(self, attr), field_name=f"{label}.{attr}"), field_name=f"{label}.{attr}", expected_prefix=pfx)
        if self.delegation_context_locator is not None:
            if self.call_side != "operational":
                raise ClosedValidationError(f"{label}.delegation_context_locator: must be None for 7B call_side={self.call_side!r}")
            _typed_locator(self.delegation_context_locator, field_name=f"{label}.delegation_context_locator", expected_type=_DELEGATION_CONTEXT_SCHEMA)

    @classmethod
    def from_dict(cls, data: object) -> ProviderCallTarget:
        m = require_exact_keys(data, cls.KEYS, label="provider_call_target")
        raw_deleg = m["delegation_context_locator"]
        return cls(
            migration_run_context_locator=_loc_from(m, "migration_run_context_locator", _RUN_CONTEXT_SCHEMA),
            admitted_collection_locator=_loc_from(m, "admitted_collection_locator", _ADMITTED_COLLECTION_SCHEMA),
            call_side=m["call_side"], provider_target_ref=m["provider_target_ref"], canonical_query_digest=m["canonical_query_digest"],
            registry_snapshot_locator=_loc_from(m, "registry_snapshot_locator", _REGISTRY_SNAPSHOT_SCHEMA),
            tenant_ref=m["tenant_ref"], binding_ref=m["binding_ref"], account_ref=m["account_ref"],
            resource_scope_ref=m["resource_scope_ref"], subject_kind=m["subject_kind"],
            delegation_context_locator=None if raw_deleg is None else ArtifactLocator.from_dict(raw_deleg, expected_type=_DELEGATION_CONTEXT_SCHEMA),
        )


@dataclass(frozen=True, slots=True)
class RetentionRootAdmissionTarget(_SubjectBase):
    """Discriminated `retention_root_admission_target` authorization subject (ADR-0001 §12.3)."""
    SUBJECT_KIND: ClassVar[str] = "retention_root_admission_target"
    KEYS: ClassVar[frozenset[str]] = frozenset("subject_kind migration_run_context_locator cell_ref expected_root_set_head_locator expected_root_set_head_epoch expected_root_set_head_digest admitted_root_locators admitted_object_refs before_reachability_graph_digest after_reachability_graph_digest proposed_root_set_digest".split())
    migration_run_context_locator: ArtifactLocator
    cell_ref: str
    expected_root_set_head_locator: ArtifactLocator
    expected_root_set_head_epoch: int
    expected_root_set_head_digest: str
    admitted_root_locators: tuple[ArtifactLocator, ...]
    admitted_object_refs: tuple[str, ...]
    before_reachability_graph_digest: str
    after_reachability_graph_digest: str
    proposed_root_set_digest: str
    subject_kind: str = "retention_root_admission_target"

    def __post_init__(self) -> None:
        label = "retention_root_admission_target"
        _validate_retention_subject_common(self, label=label, min_epoch=0)
        object.__setattr__(self, "admitted_root_locators", _sorted_locator_tuple(self.admitted_root_locators, field_name=f"{label}.admitted_root_locators", expected_type=_RETENTION_ROOT_SCHEMA, allow_empty=False))
        object.__setattr__(self, "admitted_object_refs", _sorted_object_ref_tuple(self.admitted_object_refs, field_name=f"{label}.admitted_object_refs", allow_empty=False))

    @classmethod
    def from_dict(cls, data: object) -> RetentionRootAdmissionTarget:
        m = require_exact_keys(data, cls.KEYS, label="retention_root_admission_target")
        raw_roots = _require_json_list(m, "admitted_root_locators", label="retention_root_admission_target")
        raw_refs = _require_json_list(m, "admitted_object_refs", label="retention_root_admission_target")
        return cls(**_retention_subject_base_kwargs(m), admitted_root_locators=tuple(ArtifactLocator.from_dict(r, expected_type=_RETENTION_ROOT_SCHEMA) for r in raw_roots), admitted_object_refs=tuple(raw_refs))


@dataclass(frozen=True, slots=True)
class RetentionReleaseTarget(_SubjectBase):
    """Discriminated `retention_release_target` authorization subject (ADR-0001 §12.3)."""
    SUBJECT_KIND: ClassVar[str] = "retention_release_target"
    KEYS: ClassVar[frozenset[str]] = frozenset("subject_kind migration_run_context_locator cell_ref expected_root_set_head_locator expected_root_set_head_epoch expected_root_set_head_digest released_root_locators retained_root_locators released_object_refs before_reachability_graph_digest after_reachability_graph_digest proposed_root_set_digest".split())
    migration_run_context_locator: ArtifactLocator
    cell_ref: str
    expected_root_set_head_locator: ArtifactLocator
    expected_root_set_head_epoch: int
    expected_root_set_head_digest: str
    released_root_locators: tuple[ArtifactLocator, ...]
    retained_root_locators: tuple[ArtifactLocator, ...]
    released_object_refs: tuple[str, ...]
    before_reachability_graph_digest: str
    after_reachability_graph_digest: str
    proposed_root_set_digest: str
    subject_kind: str = "retention_release_target"

    def __post_init__(self) -> None:
        label = "retention_release_target"
        _validate_retention_subject_common(self, label=label, min_epoch=1)
        rel_roots = _sorted_locator_tuple(self.released_root_locators, field_name=f"{label}.released_root_locators", expected_type=_RETENTION_ROOT_SCHEMA, allow_empty=False)
        ret_roots = _sorted_locator_tuple(self.retained_root_locators, field_name=f"{label}.retained_root_locators", expected_type=_RETENTION_ROOT_SCHEMA, allow_empty=True)
        if not set(rel_roots).isdisjoint(ret_roots):
            raise ClosedValidationError(f"{label}: released_root_locators and retained_root_locators must be disjoint")
        object.__setattr__(self, "released_root_locators", rel_roots)
        object.__setattr__(self, "retained_root_locators", ret_roots)
        object.__setattr__(self, "released_object_refs", _sorted_object_ref_tuple(self.released_object_refs, field_name=f"{label}.released_object_refs", allow_empty=True))

    @classmethod
    def from_dict(cls, data: object) -> RetentionReleaseTarget:
        m = require_exact_keys(data, cls.KEYS, label="retention_release_target")
        raw_rel = _require_json_list(m, "released_root_locators", label="retention_release_target")
        raw_ret = _require_json_list(m, "retained_root_locators", label="retention_release_target")
        raw_refs = _require_json_list(m, "released_object_refs", label="retention_release_target")
        return cls(
            **_retention_subject_base_kwargs(m),
            released_root_locators=tuple(ArtifactLocator.from_dict(r, expected_type=_RETENTION_ROOT_SCHEMA) for r in raw_rel),
            retained_root_locators=tuple(ArtifactLocator.from_dict(r, expected_type=_RETENTION_ROOT_SCHEMA) for r in raw_ret),
            released_object_refs=tuple(raw_refs),
        )


EffectSubject = ProviderCallTarget | RetentionRootAdmissionTarget | RetentionReleaseTarget
_SUBJECT_CLASSES: Final[Mapping[str, type[Any]]] = MappingProxyType({
    ProviderCallTarget.SUBJECT_KIND: ProviderCallTarget,
    RetentionRootAdmissionTarget.SUBJECT_KIND: RetentionRootAdmissionTarget,
    RetentionReleaseTarget.SUBJECT_KIND: RetentionReleaseTarget,
})


def parse_effect_subject(data: object, *, label: str = "subject") -> EffectSubject:
    """Parse a discriminated `subject_kind` authorization subject mapping."""
    mapping = require_mapping(data, label=label)
    kind = mapping.get("subject_kind")
    if type(kind) is not str or kind not in _SUBJECT_CLASSES:
        raise ClosedValidationError(f"{label}.subject_kind: unsupported subject_kind {kind!r}")
    return _SUBJECT_CLASSES[kind].from_dict(mapping)  # type: ignore[no-any-return]


def _validate_action_slot_and_subject(
    action: object, dag_slot: object, subject: object | None, *, label: str, run_loc: ArtifactLocator | None = None
) -> EffectActionSpec:
    act = _strict_str(action, field_name=f"{label}.action")
    spec = EFFECT_ACTION_MATRIX.get(act)
    if spec is None:
        raise ClosedValidationError(f"{label}.action: unsupported action {act!r}")
    slot = _strict_str(dag_slot, field_name=f"{label}.dag_slot")
    if slot != spec.dag_slot:
        raise ClosedValidationError(f"{label}.dag_slot: expected {spec.dag_slot!r} for action {act!r}, got {slot!r}")
    if subject is not None:
        expected_cls = _SUBJECT_CLASSES[spec.subject_kind]
        if type(subject) is not expected_cls:
            raise ClosedValidationError(f"{label}.subject: expected {expected_cls.__name__} for action {act!r}")
        parse_effect_subject(subject.to_dict(), label=f"{label}.subject")
        if spec.call_side is not None and subject.call_side != spec.call_side:
            raise ClosedValidationError(f"{label}.subject.call_side: expected {spec.call_side!r} for action {act!r}")
        if run_loc is not None and subject.migration_run_context_locator != run_loc:
            raise ClosedValidationError(f"{label}.subject.migration_run_context_locator: run mismatch")
    return spec


@dataclass(frozen=True, slots=True)
class AuthorizationReceipt(_P1EnvelopeBase):
    """Closed P1 `smart_ads/authorization_receipt/v1` envelope (ADR-0001 §§12.3–12.4)."""
    SCHEMA: ClassVar[str] = "smart_ads/authorization_receipt/v1"
    P1_DOMAIN_PREFIX: ClassVar[str] = ADR_P1_DOMAIN_PREFIXES[SCHEMA]
    CORE_KEYS: ClassVar[frozenset[str]] = frozenset("$schema authorization_id migration_run_context_locator action dag_slot subject parameters_digest predecessor_locators approving_principal_ref issued_at_utc valid_until_utc single_use_nonce".split())
    KEYS: ClassVar[frozenset[str]] = CORE_KEYS | {"integrity"}
    authorization_id: str
    migration_run_context_locator: ArtifactLocator
    action: str
    dag_slot: str
    subject: EffectSubject
    parameters_digest: str
    predecessor_locators: tuple[ArtifactLocator, ...]
    approving_principal_ref: str
    issued_at_utc: str
    valid_until_utc: str
    single_use_nonce: str
    integrity: P1Integrity | None = None

    def __post_init__(self) -> None:
        label = "authorization_receipt"
        _strict_id(self.authorization_id, field_name=f"{label}.authorization_id")
        run_loc = _typed_locator(self.migration_run_context_locator, field_name=f"{label}.migration_run_context_locator", expected_type=_RUN_CONTEXT_SCHEMA)
        _validate_action_slot_and_subject(self.action, self.dag_slot, self.subject, label=label, run_loc=run_loc)
        validate_sha256_prefixed(_strict_str(self.parameters_digest, field_name=f"{label}.parameters_digest"), field_name=f"{label}.parameters_digest")
        object.__setattr__(self, "predecessor_locators", _sorted_locator_tuple(self.predecessor_locators, field_name=f"{label}.predecessor_locators", allow_empty=True))
        validate_opaque_ref(_strict_str(self.approving_principal_ref, field_name=f"{label}.approving_principal_ref"), field_name=f"{label}.approving_principal_ref", expected_prefix="principal")
        validate_envelope_timestamp_utc(self.issued_at_utc, field_name=f"{label}.issued_at_utc")
        validate_envelope_timestamp_utc(self.valid_until_utc, field_name=f"{label}.valid_until_utc")
        if parse_timestamp_utc_micros(self.issued_at_utc, allow_whole_seconds=True) >= parse_timestamp_utc_micros(self.valid_until_utc, allow_whole_seconds=True):
            raise ClosedValidationError(f"{label}: issued_at_utc must precede valid_until_utc")
        _validate_nonce(self.single_use_nonce, field_name=f"{label}.single_use_nonce")
        _verify_p1_integrity(self.integrity, self.to_dict, label=label)

    @classmethod
    def from_dict(cls, data: object, *, require_signed: bool = False) -> AuthorizationReceipt:
        m, integrity = _split_p1_envelope(data, core_keys=cls.CORE_KEYS, schema=cls.SCHEMA, label="authorization_receipt", require_signed=require_signed)
        raw_preds = _require_json_list(m, "predecessor_locators", label="authorization_receipt")
        return cls(
            authorization_id=m["authorization_id"], action=m["action"], dag_slot=m["dag_slot"],
            migration_run_context_locator=_loc_from(m, "migration_run_context_locator", _RUN_CONTEXT_SCHEMA),
            subject=parse_effect_subject(m["subject"], label="authorization_receipt.subject"), parameters_digest=m["parameters_digest"],
            predecessor_locators=tuple(ArtifactLocator.from_dict(p) for p in raw_preds), approving_principal_ref=m["approving_principal_ref"],
            issued_at_utc=m["issued_at_utc"], valid_until_utc=m["valid_until_utc"], single_use_nonce=m["single_use_nonce"], integrity=integrity,
        )


@dataclass(frozen=True, slots=True)
class AuthorizationReservationRecord(_P1EnvelopeBase):
    """Closed P1 `smart_ads/authorization_reservation_record/v1` envelope (ADR-0001 §12.4)."""
    SCHEMA: ClassVar[str] = "smart_ads/authorization_reservation_record/v1"
    P1_DOMAIN_PREFIX: ClassVar[str] = ADR_P1_DOMAIN_PREFIXES[SCHEMA]
    CORE_KEYS: ClassVar[frozenset[str]] = frozenset("$schema reservation_id migration_run_context_locator authorization_locator authorization_receipt_digest single_use_nonce action dag_slot subject reservation_status in_doubt_reason reserved_at_utc".split())
    KEYS: ClassVar[frozenset[str]] = CORE_KEYS | {"integrity"}
    _LABEL: ClassVar[str] = "authorization_reservation_record"
    _LOCATOR_FIELDS: ClassVar[Mapping[str, str | None]] = MappingProxyType({"migration_run_context_locator": _RUN_CONTEXT_SCHEMA, "authorization_locator": AuthorizationReceipt.SCHEMA})
    reservation_id: str
    migration_run_context_locator: ArtifactLocator
    authorization_locator: ArtifactLocator
    authorization_receipt_digest: str
    single_use_nonce: str
    action: str
    dag_slot: str
    subject: EffectSubject
    reservation_status: ReservationStatus
    in_doubt_reason: InDoubtReason | None
    reserved_at_utc: str
    integrity: P1Integrity | None = None

    def __post_init__(self) -> None:
        label = self._LABEL
        _strict_id(self.reservation_id, field_name=f"{label}.reservation_id")
        run_loc = _typed_locator(self.migration_run_context_locator, field_name=f"{label}.migration_run_context_locator", expected_type=_RUN_CONTEXT_SCHEMA)
        _require_locator_digest_pair(self.authorization_locator, self.authorization_receipt_digest, expected_type=AuthorizationReceipt.SCHEMA, loc_field=f"{label}.authorization_locator", digest_field=f"{label}.authorization_receipt_digest")
        _validate_nonce(self.single_use_nonce, field_name=f"{label}.single_use_nonce")
        _validate_action_slot_and_subject(self.action, self.dag_slot, self.subject, label=label, run_loc=run_loc)
        status = _strict_str(self.reservation_status, field_name=f"{label}.reservation_status")
        if status not in _RESERVATION_STATUSES:
            raise ClosedValidationError(f"{label}.reservation_status: invalid {status!r}")
        if status == "in_doubt":
            if type(self.in_doubt_reason) is not str or self.in_doubt_reason not in _IN_DOUBT_REASONS:
                raise ClosedValidationError(f"{label}.in_doubt_reason: invalid {self.in_doubt_reason!r}")
        elif self.in_doubt_reason is not None:
            raise ClosedValidationError(f"{label}.in_doubt_reason: must be None when status={status!r}")
        validate_envelope_timestamp_utc(self.reserved_at_utc, field_name=f"{label}.reserved_at_utc")
        _verify_p1_integrity(self.integrity, self.to_dict, label=label)


@dataclass(frozen=True, slots=True)
class ExecutionReceipt(_P1EnvelopeBase):
    """Closed P1 `smart_ads/execution_receipt/v1` envelope (ADR-0001 §§12.3–12.4)."""
    SCHEMA: ClassVar[str] = "smart_ads/execution_receipt/v1"
    P1_DOMAIN_PREFIX: ClassVar[str] = ADR_P1_DOMAIN_PREFIXES[SCHEMA]
    CORE_KEYS: ClassVar[frozenset[str]] = frozenset("$schema execution_id migration_run_context_locator authorization_locator reservation_locator single_use_nonce action dag_slot subject execution_status action_result_locator executed_at_utc".split())
    KEYS: ClassVar[frozenset[str]] = CORE_KEYS | {"integrity"}
    _LABEL: ClassVar[str] = "execution_receipt"
    _LOCATOR_FIELDS: ClassVar[Mapping[str, str | None]] = MappingProxyType({
        "migration_run_context_locator": _RUN_CONTEXT_SCHEMA, "authorization_locator": AuthorizationReceipt.SCHEMA,
        "reservation_locator": AuthorizationReservationRecord.SCHEMA, "action_result_locator": None,
    })
    execution_id: str
    migration_run_context_locator: ArtifactLocator
    authorization_locator: ArtifactLocator
    reservation_locator: ArtifactLocator
    single_use_nonce: str
    action: str
    dag_slot: str
    subject: EffectSubject
    execution_status: str
    action_result_locator: ArtifactLocator
    executed_at_utc: str
    integrity: P1Integrity | None = None

    def __post_init__(self) -> None:
        label = self._LABEL
        _strict_id(self.execution_id, field_name=f"{label}.execution_id")
        run_loc = _typed_locator(self.migration_run_context_locator, field_name=f"{label}.migration_run_context_locator", expected_type=_RUN_CONTEXT_SCHEMA)
        _check_locs(label, ("authorization_locator", self.authorization_locator, AuthorizationReceipt.SCHEMA), ("reservation_locator", self.reservation_locator, AuthorizationReservationRecord.SCHEMA))
        _validate_nonce(self.single_use_nonce, field_name=f"{label}.single_use_nonce")
        spec = _validate_action_slot_and_subject(self.action, self.dag_slot, self.subject, label=label, run_loc=run_loc)
        if _strict_str(self.execution_status, field_name=f"{label}.execution_status") != "succeeded":
            raise ClosedValidationError(f"{label}.execution_status: must equal 'succeeded'")
        _typed_locator(self.action_result_locator, field_name=f"{label}.action_result_locator", expected_type=spec.result_type)
        validate_envelope_timestamp_utc(self.executed_at_utc, field_name=f"{label}.executed_at_utc")
        _verify_p1_integrity(self.integrity, self.to_dict, label=label)


@dataclass(frozen=True, slots=True)
class AuthorizationConsumptionRecord(_P1EnvelopeBase):
    """Closed P1 `smart_ads/authorization_consumption_record/v1` envelope (ADR-0001 §12.4)."""
    SCHEMA: ClassVar[str] = "smart_ads/authorization_consumption_record/v1"
    P1_DOMAIN_PREFIX: ClassVar[str] = ADR_P1_DOMAIN_PREFIXES[SCHEMA]
    CORE_KEYS: ClassVar[frozenset[str]] = frozenset("$schema consumption_id migration_run_context_locator authorization_locator authorization_receipt_digest reservation_locator execution_locator single_use_nonce action dag_slot consumption_status consumed_at_utc".split())
    KEYS: ClassVar[frozenset[str]] = CORE_KEYS | {"integrity"}
    _LABEL: ClassVar[str] = "authorization_consumption_record"
    _LOCATOR_FIELDS: ClassVar[Mapping[str, str | None]] = MappingProxyType({
        "migration_run_context_locator": _RUN_CONTEXT_SCHEMA, "authorization_locator": AuthorizationReceipt.SCHEMA,
        "reservation_locator": AuthorizationReservationRecord.SCHEMA, "execution_locator": ExecutionReceipt.SCHEMA,
    })
    consumption_id: str
    migration_run_context_locator: ArtifactLocator
    authorization_locator: ArtifactLocator
    authorization_receipt_digest: str
    reservation_locator: ArtifactLocator
    execution_locator: ArtifactLocator
    single_use_nonce: str
    action: str
    dag_slot: str
    consumption_status: str
    consumed_at_utc: str
    integrity: P1Integrity | None = None

    def __post_init__(self) -> None:
        label = self._LABEL
        _strict_id(self.consumption_id, field_name=f"{label}.consumption_id")
        _require_locator_digest_pair(self.authorization_locator, self.authorization_receipt_digest, expected_type=AuthorizationReceipt.SCHEMA, loc_field=f"{label}.authorization_locator", digest_field=f"{label}.authorization_receipt_digest")
        _check_locs(label, ("migration_run_context_locator", self.migration_run_context_locator, _RUN_CONTEXT_SCHEMA), ("reservation_locator", self.reservation_locator, AuthorizationReservationRecord.SCHEMA), ("execution_locator", self.execution_locator, ExecutionReceipt.SCHEMA))
        _validate_nonce(self.single_use_nonce, field_name=f"{label}.single_use_nonce")
        _validate_action_slot_and_subject(self.action, self.dag_slot, None, label=label)
        if _strict_str(self.consumption_status, field_name=f"{label}.consumption_status") != "consumed":
            raise ClosedValidationError(f"{label}.consumption_status: must equal 'consumed'")
        validate_envelope_timestamp_utc(self.consumed_at_utc, field_name=f"{label}.consumed_at_utc")
        _verify_p1_integrity(self.integrity, self.to_dict, label=label)


@dataclass(frozen=True, slots=True)
class EffectProof(_P1EnvelopeBase):
    """Closed P1 `smart_ads/effect_proof/v1` envelope (ADR-0001 §12.5)."""
    SCHEMA: ClassVar[str] = "smart_ads/effect_proof/v1"
    P1_DOMAIN_PREFIX: ClassVar[str] = ADR_P1_DOMAIN_PREFIXES[SCHEMA]
    CORE_KEYS: ClassVar[frozenset[str]] = frozenset("$schema effect_proof_id migration_run_context_locator action dag_slot authorization_locator reservation_locator execution_locator consumption_locator action_result_locator verified_at_utc".split())
    KEYS: ClassVar[frozenset[str]] = CORE_KEYS | {"integrity"}
    _LABEL: ClassVar[str] = "effect_proof"
    _LOCATOR_FIELDS: ClassVar[Mapping[str, str | None]] = MappingProxyType({
        "migration_run_context_locator": _RUN_CONTEXT_SCHEMA, "authorization_locator": AuthorizationReceipt.SCHEMA,
        "reservation_locator": AuthorizationReservationRecord.SCHEMA, "execution_locator": ExecutionReceipt.SCHEMA,
        "consumption_locator": AuthorizationConsumptionRecord.SCHEMA, "action_result_locator": None,
    })
    effect_proof_id: str
    migration_run_context_locator: ArtifactLocator
    action: str
    dag_slot: str
    authorization_locator: ArtifactLocator
    reservation_locator: ArtifactLocator
    execution_locator: ArtifactLocator
    consumption_locator: ArtifactLocator
    action_result_locator: ArtifactLocator
    verified_at_utc: str
    integrity: P1Integrity | None = None

    def __post_init__(self) -> None:
        label = self._LABEL
        _strict_id(self.effect_proof_id, field_name=f"{label}.effect_proof_id")
        spec = _validate_action_slot_and_subject(self.action, self.dag_slot, None, label=label)
        _check_locs(
            label,
            ("migration_run_context_locator", self.migration_run_context_locator, _RUN_CONTEXT_SCHEMA),
            ("authorization_locator", self.authorization_locator, AuthorizationReceipt.SCHEMA),
            ("reservation_locator", self.reservation_locator, AuthorizationReservationRecord.SCHEMA),
            ("execution_locator", self.execution_locator, ExecutionReceipt.SCHEMA),
            ("consumption_locator", self.consumption_locator, AuthorizationConsumptionRecord.SCHEMA),
            ("action_result_locator", self.action_result_locator, spec.result_type),
        )
        validate_envelope_timestamp_utc(self.verified_at_utc, field_name=f"{label}.verified_at_utc")
        _verify_p1_integrity(self.integrity, self.to_dict, label=label)


def _check_chain_links_and_identities(
    auth: AuthorizationReceipt, resv: AuthorizationReservationRecord,
    exec_rec: ExecutionReceipt, cons: AuthorizationConsumptionRecord, proof: EffectProof,
) -> None:
    auth_loc, resv_loc, exec_loc, cons_loc = auth.locator(), resv.locator(), exec_rec.locator(), cons.locator()
    if (
        resv.authorization_locator != auth_loc or resv.authorization_receipt_digest != auth_loc.content_digest
        or exec_rec.authorization_locator != auth_loc or exec_rec.reservation_locator != resv_loc
        or cons.authorization_locator != auth_loc or cons.authorization_receipt_digest != auth_loc.content_digest
        or cons.reservation_locator != resv_loc or cons.execution_locator != exec_loc
        or (proof.authorization_locator, proof.reservation_locator, proof.execution_locator, proof.consumption_locator) != (auth_loc, resv_loc, exec_loc, cons_loc)
    ):
        raise ClosedValidationError("effect_proof: four-record locator/digest chain mismatch")
    subj_jcs = canonicalize_jcs(auth.subject.to_dict())
    if canonicalize_jcs(resv.subject.to_dict()) != subj_jcs or canonicalize_jcs(exec_rec.subject.to_dict()) != subj_jcs:
        raise ClosedValidationError("effect_proof: subject JCS bytes diverge across chain")
    reg_locs = {rec.integrity.key_registry_snapshot_locator for rec in (auth, resv, exec_rec, cons, proof) if rec.integrity is not None}
    if len(reg_locs) > 1:
        raise ClosedValidationError("effect_proof: key_registry_snapshot_locator mismatch across chain")


def verify_four_record_effect_proof(
    *, effect_proof: EffectProof, authorization: AuthorizationReceipt, reservation: AuthorizationReservationRecord,
    execution: ExecutionReceipt, consumption: AuthorizationConsumptionRecord, expected_action: str,
    expected_dag_slot: str, expected_result_type: str, require_signed: bool = False,
) -> EffectProof:
    """Verify full 4-record anti-replay chain and `effect_proof/v1` agreement (ADR-0001 §§12.3–12.5)."""
    if type(require_signed) is not bool:
        raise ClosedValidationError("require_signed: expected bool")
    spec = _validate_action_slot_and_subject(expected_action, expected_dag_slot, None, label="expected")
    if _strict_str(expected_result_type, field_name="expected_result_type") != spec.result_type:
        raise ClosedValidationError(f"expected_result_type: expected {spec.result_type!r}")
    auth = _reparse_p1(authorization, AuthorizationReceipt, label="authorization", require_signed=require_signed)
    resv = _reparse_p1(reservation, AuthorizationReservationRecord, label="reservation", require_signed=require_signed)
    exec_rec = _reparse_p1(execution, ExecutionReceipt, label="execution", require_signed=require_signed)
    cons = _reparse_p1(consumption, AuthorizationConsumptionRecord, label="consumption", require_signed=require_signed)
    proof = _reparse_p1(effect_proof, EffectProof, label="effect_proof", require_signed=require_signed)
    if resv.reservation_status not in {"reserved", "consumed"}:
        raise ClosedValidationError(f"reservation.reservation_status: rejected {resv.reservation_status!r} (in_doubt forbidden)")
    for rec in (auth, resv, exec_rec, cons, proof):
        if (rec.action, rec.dag_slot, rec.migration_run_context_locator) != (expected_action, expected_dag_slot, auth.migration_run_context_locator):
            raise ClosedValidationError("effect_proof: action, dag_slot, or migration_run_context_locator mismatch")
    if len({auth.single_use_nonce, resv.single_use_nonce, exec_rec.single_use_nonce, cons.single_use_nonce}) != 1:
        raise ClosedValidationError("effect_proof: single_use_nonce mismatch across chain")
    if exec_rec.action_result_locator != proof.action_result_locator or proof.action_result_locator.artifact_type != expected_result_type:
        raise ClosedValidationError("effect_proof: action_result_locator mismatch")
    _check_chain_links_and_identities(auth, resv, exec_rec, cons, proof)
    return proof


__all__ = [
    "AuthorizationConsumptionRecord", "AuthorizationReceipt", "AuthorizationReservationRecord",
    "EFFECT_ACTION_MATRIX", "EffectActionSpec", "EffectProof", "EffectSubject", "ExecutionReceipt",
    "InDoubtReason", "ProviderCallTarget", "ReservationStatus", "RetentionReleaseTarget",
    "RetentionRootAdmissionTarget", "parse_effect_subject", "sort_artifact_locators",
    "sort_cell_object_refs", "validate_cell_object_ref", "verify_four_record_effect_proof",
]
