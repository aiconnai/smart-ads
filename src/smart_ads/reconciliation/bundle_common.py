"""Shared defect model, guards and grammar helpers of the 7B bundle (ADR-0001 section 5.4).

Malformed evidence (grammar, extra or missing member, wrong order, divergent
digest, failed binding) raises ``Bundle7BDefectError`` with a closed ``code``.
Names here are shared by the sibling ``bundle_*`` modules; the public API is
re-exported by ``smart_ads.reconciliation.bundle_7b``.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
import re
from typing import Any, Final, TypeVar

from smart_ads.contracts.jcs import (
    MAX_JCS_SAFE_INT,
    ArtifactLocator,
    P1Integrity,
    canonicalize_jcs,
    p1_content_digest,
)
from smart_ads.contracts.schemas import CanonicalQueryContract
from smart_ads.contracts.scalars import (
    ClosedValidationError,
    parse_timestamp_utc_micros,
    require_mapping,
    validate_opaque_ref,
    validate_sha256_prefixed,
)

T = TypeVar("T")

# ADR-0001 L955-967: the record seals exactly {impressions, clicks, spend}. The
# literal YAML order is kept (a choice the ADR does not fix beyond the literal).
REQUIRED_7B_METRICS: Final[tuple[str, ...]] = (
    "metric:impressions_v1",
    "metric:clicks_v1",
    "metric:spend_v1",
)
MAXIMUM_RETRIEVAL_SKEW_SECONDS: Final[int] = 300
MICROS_PER_SECOND: Final[int] = 1_000_000

CERTIFICATION_7B_RECORD_SCHEMA: Final[str] = "smart_ads/certification_7b_record/v1"
NATIVE_REQUEST_PROJECTION_SCHEMA: Final[str] = "smart_ads/native_request_projection/v1"
# Embedded closed value objects (ADR section 12.7): validated as subobjects of the
# record, so their serialized form carries no `$schema` member.
FACT_EVIDENCE_SELECTOR_SCHEMA: Final[str] = "smart_ads/fact_evidence_selector/v1"
FACT_RECONCILIATION_SCHEMA: Final[str] = "smart_ads/fact_reconciliation/v1"
GATE3_SELECTION_SCHEMA: Final[str] = "smart_ads/gate3_selection_receipt/v1"
RUN_CONTEXT_SCHEMA: Final[str] = "smart_ads/migration_run_context/v1"
EFFECT_PROOF_SCHEMA: Final[str] = "smart_ads/effect_proof/v1"
REGISTRY_SNAPSHOT_SCHEMA: Final[str] = "smart_ads/private_registry_snapshot/v1"
DRIVER_CONTRACT_SCHEMA: Final[str] = "smart_ads/pipeboard_phase1_contract/v1"
ADMITTED_COLLECTION_SCHEMA: Final[str] = "smart_ads/admitted_collection/v1"

DEFECT_CODES: Final[frozenset[str]] = frozenset(
    {
        # structure
        "malformed_argument",
        "malformed_member",
        "closed_member_set",
        "fixed_member_mismatch",
        "wrong_order",
        "duplicate_identity",
        # universes and counts
        "row_universe_conflict",
        "pair_universe_conflict",
        "row_universe_mismatch",
        "pair_universe_incomplete",
        "pair_universe_mismatch",
        "row_universe_digest_mismatch",
        "row_count_mismatch",
        "retrieval_skew_exceeded",
        # facts outside the admitted canonical query
        "fact_outside_query_window",
        "fact_binding_mismatch",
        "fact_account_mismatch",
        # Gate-3 fingerprint
        "fingerprint_mismatch",
        # fact evidence and reconciliations
        "collection_result_incomplete",
        "collection_result_mismatch",
        "evidence_container_mismatch",
        "evidence_not_addressable",
        "evidence_selector_mismatch",
        "normalized_fact_set_digest_mismatch",
        "fact_projection_digest_mismatch",
        "canonical_fact_key_digest_mismatch",
        "asserted_comparison_malformed",
        # native request projection and P1 integrity
        "native_projection_forbidden_content",
        "native_projection_mismatch",
        "native_request_digest_mismatch",
        "integrity_digest_mismatch",
        # comparison outcomes (returned as values by reconcile_7b_fact_sets)
        "metric_unreconciled",
        "metric_unavailable",
        "metric_blocked",
        # tolerance profiles
        "tolerance_profile_malformed",
        "tolerance_profile_unresolved",
        "tolerance_profile_unsigned",
        "tolerance_profile_metric_mismatch",
        "tolerance_profile_unbound",
        # execution records and the certification record
        "canonical_query_digest_mismatch",
        "canonical_query_mismatch",
        "driver_contract_digest_mismatch",
        "source_contract_mismatch",
        "native_version_mismatch",
        "fingerprint_member_mismatch",
        "effect_proof_not_distinct",
        "provider_target_not_distinct",
        "metric_not_verified",
        "logical_digest_mismatch",
        # verifier bindings to resolved evidence
        "run_context_mismatch",
        "gate3_selection_mismatch",
        "driver_contract_unresolved",
        "admission_mismatch",
        "effect_proof_mismatch",
        "effect_result_mismatch",
        "evidence_value_mismatch",
        "tolerance_profile_locator_mismatch",
        "asserted_comparison_mismatch",
    }
)

# ADR 7B literals such as `api-version:<v>`, `opaque-driver-contract:<digest>` and
# `provider-target:<name>` carry hyphenated prefixes, which the repo `opaque_ref`
# grammar (`^[a-z][a-z0-9_]*:`) does not admit; the body keeps the opaque_ref alphabet.
_HYPHEN_REF_RE: Final[re.Pattern[str]] = re.compile(r"\A([a-z][a-z0-9-]*):[A-Za-z0-9._:-]+\Z")


class Bundle7BDefectError(ClosedValidationError):
    """Malformed or unverifiable 7B evidence; ``code`` is a member of ``DEFECT_CODES``."""

    def __init__(self, code: str, detail: str) -> None:
        if not isinstance(code, str) or code not in DEFECT_CODES:
            raise ClosedValidationError(f"bundle_7b: unknown defect code {code!r}")
        self.code = code
        super().__init__(f"{code}: {detail}")


def guard(code: str, label: str, build: Callable[[], T]) -> T:
    """Run ``build`` and re-raise a plain ``ClosedValidationError`` as a coded defect."""
    try:
        return build()
    except Bundle7BDefectError:
        raise
    except ClosedValidationError as exc:
        raise Bundle7BDefectError(code, f"{label}: {exc}") from exc


def guard_any(code: str, label: str, build: Callable[[], T]) -> T:
    """Like ``guard``, and a bare error escaping ``build`` is coded too.

    Frozen objects validate once, in ``__post_init__``; a tampered one (a field set
    behind its back with ``object.__setattr__``) can fail in ``to_dict`` or in a
    validator with any exception. At the seam that is a malformed object, not a bug
    to leak: ``code`` it, keeping the cause. ``MemoryError`` is the process failing,
    not the object: it propagates. ``RecursionError`` (a deeply nested or cyclic
    object) is coded.
    """
    try:
        return build()
    except Bundle7BDefectError:
        raise
    except ClosedValidationError as exc:
        raise Bundle7BDefectError(code, f"{label}: {exc}") from exc
    except MemoryError:
        raise
    except Exception as exc:  # noqa: BLE001 - a tampered object can fail in any way
        raise Bundle7BDefectError(code, f"{label}: {type(exc).__name__}: {exc}") from exc


def require_type(value: object, expected: type, *, label: str) -> None:
    """Argument type check (``malformed_argument``)."""
    if not isinstance(value, expected):
        raise Bundle7BDefectError(
            "malformed_argument",
            f"{label}: expected {expected.__name__}, got {type(value).__name__}",
        )


def require_member(value: object, expected: type, *, label: str) -> None:
    """Like ``require_type`` but for members of evidence objects (``malformed_member``)."""
    if not isinstance(value, expected):
        raise Bundle7BDefectError("malformed_member", f"{label}: expected {expected.__name__}")


def require_tuple_of(value: object, expected: type, *, label: str) -> tuple[Any, ...]:
    """Frozen, hashable sequence members are tuples of ``expected`` (``malformed_member``)."""
    if not isinstance(value, tuple):
        raise Bundle7BDefectError("malformed_member", f"{label}: expected a tuple")
    for item in value:
        require_member(item, expected, label=f"{label}.entry")
    return value


def require_count(value: object, *, label: str) -> int:
    """A strict non-negative int within the RFC 8785 safe range (``malformed_member``)."""
    if type(value) is not int or not 0 <= value <= MAX_JCS_SAFE_INT:
        raise Bundle7BDefectError("malformed_member", f"{label}: expected a non-negative int")
    return value


def require_bool(value: object, *, label: str) -> bool:
    """Strict bool flag check (``malformed_argument``)."""
    if type(value) is not bool:
        raise Bundle7BDefectError("malformed_argument", f"{label}: expected bool")
    return value


def _check_integrity_pair(
    orig_int: object, fresh_int: object, *, code: str, label: str
) -> None:
    if orig_int is None and fresh_int is None:
        return
    if not isinstance(orig_int, P1Integrity) or not isinstance(fresh_int, P1Integrity):
        raise Bundle7BDefectError(code, f"{label}.integrity: expected P1Integrity")
    if (orig_int.content_digest is None) != (orig_int.signature_base64 is None):
        raise Bundle7BDefectError(code, f"{label}.integrity: partial signature state")
    if (orig_int.content_digest, orig_int.signature_base64) != (
        fresh_int.content_digest,
        fresh_int.signature_base64,
    ):
        raise Bundle7BDefectError(code, f"{label}.integrity: signature state changed")


def _check_reparsed_integrity(orig: Any, fresh: Any, *, code: str, label: str) -> None:
    fields = getattr(type(fresh), "__dataclass_fields__", ())
    if "integrity" in fields:
        _check_integrity_pair(orig.integrity, fresh.integrity, code=code, label=label)
    if "native_request_projection" in fields:
        _check_reparsed_integrity(
            orig.native_request_projection,
            fresh.native_request_projection,
            code=code,
            label=f"{label}.native_request_projection",
        )
    for side in ("candidate_execution", "reference_execution"):
        if side in fields:
            _check_reparsed_integrity(
                getattr(orig, side),
                getattr(fresh, side),
                code=code,
                label=f"{label}.{side}",
            )


def reparsed(
    value: T,
    expected: Any,
    *,
    label: str,
    canonical: bool = True,
    code: str = "malformed_member",
    require_signed: bool = False,
) -> T:
    """A fresh ``expected`` rebuilt from the wire form of ``value``: ``from_dict(to_dict())``.

    A frozen object that crosses a public seam is untrusted: its ``__post_init__``
    ran once, at construction, and ``object.__setattr__`` bypasses it. The copy is
    what the object's wire form would parse to, so a tampered object is rejected
    exactly as that wire form would be, and the caller must use the copy, never
    ``value``. Partial or corrupted ``P1Integrity`` states dropped by ``to_dict()``
    are rejected, and with ``canonical`` the copy's wire form must canonicalize.
    """
    require_type(value, expected, label=label)
    require_bool(require_signed, label="require_signed")

    def build() -> T:
        wire = value.to_dict()  # type: ignore[attr-defined]
        fresh: T = (
            expected.from_dict(wire, require_signed=require_signed)
            if require_signed
            else expected.from_dict(wire)
        )
        _check_reparsed_integrity(value, fresh, code=code, label=label)
        if canonical:
            canonicalize_jcs(fresh.to_dict())  # type: ignore[attr-defined]
        return fresh

    return guard_any(code, label, build)


def require_callable(value: object, *, label: str) -> None:
    if not callable(value):
        raise Bundle7BDefectError("malformed_argument", f"{label}: expected a callable")


def closed(data: object, keys: frozenset[str], *, label: str) -> Mapping[str, Any]:
    """Require a str-keyed mapping with exactly ``keys`` (this package's closed objects)."""
    mapping = guard("malformed_member", label, lambda: require_mapping(data, label=label))
    actual = set(mapping)
    if actual != keys:
        raise Bundle7BDefectError(
            "closed_member_set",
            f"{label}: missing={sorted(keys - actual)} extra={sorted(actual - keys)}",
        )
    return mapping


def require_collection(value: object, *, label: str) -> tuple[Any, ...]:
    if isinstance(value, (str, bytes, Mapping)) or not isinstance(value, Iterable):
        raise Bundle7BDefectError(
            "malformed_argument", f"{label}: expected an iterable collection"
        )
    return tuple(value)


def require_strictly_ascending(keys: Sequence[bytes], *, label: str) -> None:
    for previous, current in zip(keys, keys[1:]):
        if previous == current:
            raise Bundle7BDefectError("duplicate_identity", f"{label}: duplicate identity")
        if previous > current:
            raise Bundle7BDefectError("wrong_order", f"{label}: not in canonical order")


def jcs_bytes(value: object, *, label: str) -> bytes:
    return guard("malformed_member", label, lambda: canonicalize_jcs(value))


def metric_ref(value: object, *, label: str) -> str:
    return guard(
        "malformed_member",
        label,
        lambda: validate_opaque_ref(value, field_name=label, expected_prefix="metric"),
    )


def scope_ref(value: object, *, label: str) -> str:
    return guard(
        "malformed_member",
        label,
        lambda: validate_opaque_ref(value, field_name=label, expected_prefix="scope"),
    )


def sha256_member(value: object, *, label: str) -> str:
    return guard(
        "malformed_member", label, lambda: validate_sha256_prefixed(value, field_name=label)
    )


def hyphen_ref(value: object, *, prefixes: frozenset[str], label: str) -> str:
    match = _HYPHEN_REF_RE.fullmatch(value) if isinstance(value, str) else None
    if match is None or match.group(1) not in prefixes:
        raise Bundle7BDefectError(
            "malformed_member", f"{label}: expected a ref with prefix in {sorted(prefixes)}"
        )
    return value


def parse_integrity(
    mapping: Mapping[str, Any], *, label: str, require_signed: bool = False
) -> P1Integrity | None:
    require_bool(require_signed, label="require_signed")
    if "integrity" not in mapping:
        if require_signed:
            raise Bundle7BDefectError(
                "malformed_member", f"{label}.integrity: signed P1 integrity required"
            )
        return None
    return guard(
        "malformed_member",
        f"{label}.integrity",
        lambda: P1Integrity.from_dict(mapping["integrity"], require_signed=require_signed),
    )


def check_integrity(
    integrity: object, envelope: Callable[[], dict[str, Any]], *, label: str
) -> None:
    """A signed P1 block must carry the recomputed preimage digest (Ed25519 is never verified)."""
    if integrity is None:
        return
    if not isinstance(integrity, P1Integrity):
        raise Bundle7BDefectError("malformed_member", f"{label}.integrity: expected P1Integrity")
    if integrity.is_signed and integrity.content_digest != p1_content_digest(envelope()):
        raise Bundle7BDefectError(
            "integrity_digest_mismatch", f"{label}.integrity: digest differs"
        )


def require_locator(value: object, artifact_type: str, *, label: str) -> ArtifactLocator:
    if not isinstance(value, ArtifactLocator) or value.artifact_type != artifact_type:
        raise Bundle7BDefectError(
            "malformed_member", f"{label}: expected ArtifactLocator for {artifact_type!r}"
        )
    return value


def checked_argument_locator(value: object, artifact_type: str, *, label: str) -> ArtifactLocator:
    """A locator argument re-parsed from its wire form; the copy is what callers use.

    The class is checked first (``malformed_argument``), then the copy is built (a
    tampered locator is ``malformed_member``), then the artifact type of the copy
    (``malformed_argument``): a tampered ``artifact_type`` is never read raw.
    """
    fresh = reparsed(value, ArtifactLocator, label=label)
    if fresh.artifact_type != artifact_type:
        raise Bundle7BDefectError(
            "malformed_argument", f"{label}: expected {artifact_type!r} locator"
        )
    return fresh


def member_locator(owner: Any, name: str, artifact_type: str, *, label: str) -> None:
    require_locator(getattr(owner, name), artifact_type, label=f"{label}.{name}")


def parse_locator(value: object, artifact_type: str, *, label: str) -> ArtifactLocator:
    return guard(
        "malformed_member",
        label,
        lambda: ArtifactLocator.from_dict(value, expected_type=artifact_type),
    )


def parse_member_locator(
    mapping: Mapping[str, Any], name: str, artifact_type: str, *, label: str
) -> ArtifactLocator:
    return parse_locator(mapping[name], artifact_type, label=f"{label}.{name}")


def artifact_locator_for(artifact_type: str, artifact: Any) -> ArtifactLocator:
    """Repo locator convention: ``for_canonical_bytes(type, RFC8785(artifact.to_dict()))``.

    An artifact without a callable ``to_dict``, a non-JSON serialization, one whose
    ``to_dict`` fails (a tampered object) or an invalid artifact type is
    ``malformed_argument``. This only addresses the serialization it is given: it
    takes any artifact type, so it cannot re-parse it (the entry points that need a
    validated object re-parse it first).
    """
    to_dict = getattr(artifact, "to_dict", None)
    if not callable(to_dict):
        raise Bundle7BDefectError(
            "malformed_argument", "artifact: expected an object with a to_dict() method"
        )
    return guard_any(
        "malformed_argument",
        "artifact_locator_for",
        lambda: ArtifactLocator.for_canonical_bytes(artifact_type, canonicalize_jcs(to_dict())),
    )


def parse_query(value: object, *, label: str) -> CanonicalQueryContract:
    return guard("malformed_member", label, lambda: CanonicalQueryContract.from_dict(value))


def query_bytes(query: CanonicalQueryContract) -> bytes:
    return canonicalize_jcs(query.to_dict())


def _utc_micros(value: str) -> int:
    return guard(
        "malformed_member", "retrieved_at_utc", lambda: parse_timestamp_utc_micros(value)
    )


def within_skew(candidate_at: str, reference_at: str) -> bool:
    """Both retrieval timestamps at most ``MAXIMUM_RETRIEVAL_SKEW_SECONDS`` apart (inclusive)."""
    skew = abs(_utc_micros(candidate_at) - _utc_micros(reference_at))
    return skew <= MAXIMUM_RETRIEVAL_SKEW_SECONDS * MICROS_PER_SECOND
