"""Strict RFC 8785 JCS, explicit comparators, 3-layer digests, and pure P1 (ADR-0001)."""
from __future__ import annotations

import base64
from collections.abc import Callable, Iterable, Mapping
import copy
from dataclasses import dataclass
import hashlib
import json
import re
from types import MappingProxyType
from typing import Any, ClassVar, Final, TypeVar

from smart_ads.contracts.scalars import (
    ClosedValidationError,
    require_exact_keys,
    require_mapping,
    validate_ed25519_key_id,
    validate_non_empty_str,
    validate_sha256_prefixed,
    validate_utf8_nfc,
)

T = TypeVar("T")

MAX_JCS_SAFE_INT: Final[int] = (1 << 53) - 1
MIN_JCS_SAFE_INT: Final[int] = -((1 << 53) - 1)

_SHORT_ESCAPES: Final[Mapping[str, str]] = MappingProxyType(
    {
        "\\": "\\\\",
        '"': '\\"',
        "\b": "\\b",
        "\f": "\\f",
        "\n": "\\n",
        "\r": "\\r",
        "\t": "\\t",
    }
)
_ARTIFACT_TYPE_RE: Final[re.Pattern[str]] = re.compile(
    r"\Asmart_ads/[a-z0-9_]+/v[1-9][0-9]*\Z"
)
_LOCATOR_KEYS: Final[frozenset[str]] = frozenset(
    {
        "$schema",
        "artifact_type",
        "content_digest",
        "serialization",
        "store_kind",
        "object_ref",
    }
)
_UNSIGNED_P1_KEYS: Final[frozenset[str]] = frozenset(
    {"key_id", "key_registry_snapshot_locator"}
)
_SIGNED_P1_KEYS: Final[frozenset[str]] = frozenset(
    {
        "content_digest",
        "key_id",
        "key_registry_snapshot_locator",
        "signature_base64",
    }
)
_KEY_REGISTRY_SCHEMA: Final[str] = "smart_ads/key_authorization_registry/v1"


def _reject_surrogates(value: str, *, label: str) -> None:
    for ch in value:
        if 0xD800 <= ord(ch) <= 0xDFFF:
            raise ClosedValidationError(
                f"{label}: lone UTF-16 surrogate U+{ord(ch):04X} is forbidden"
            )


def _utf16be_sort_key(key: str) -> bytes:
    """RFC 8785 §3.2.3 object member sort key (UTF-16 code units)."""
    return key.encode("utf-16-be")


def _escape_jcs_string(value: str) -> str:
    out: list[str] = ['"']
    for ch in value:
        code = ord(ch)
        if 0xD800 <= code <= 0xDFFF:
            raise ClosedValidationError(
                f"canonicalize_jcs: lone UTF-16 surrogate U+{code:04X} is forbidden"
            )
        escaped = _SHORT_ESCAPES.get(ch)
        if escaped is not None:
            out.append(escaped)
        elif code <= 0x1F:
            out.append(f"\\u{code:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _dump_jcs(value: object, out: list[str]) -> None:
    if value is None:
        out.append("null")
        return
    if isinstance(value, bool):
        out.append("true" if value else "false")
        return
    if isinstance(value, int):
        if not (MIN_JCS_SAFE_INT <= value <= MAX_JCS_SAFE_INT):
            raise ClosedValidationError(
                f"canonicalize_jcs: integer {value} outside RFC 8785 I-JSON safe range "
                f"[{MIN_JCS_SAFE_INT}, {MAX_JCS_SAFE_INT}]"
            )
        out.append(str(int(value)))
        return
    if isinstance(value, float):
        raise ClosedValidationError(
            f"canonicalize_jcs: floating point values are forbidden (got {value!r})"
        )
    if isinstance(value, str):
        out.append(_escape_jcs_string(value))
        return
    if isinstance(value, (list, tuple)):
        out.append("[")
        for idx, item in enumerate(value):
            if idx:
                out.append(",")
            _dump_jcs(item, out)
        out.append("]")
        return
    if isinstance(value, Mapping):
        keys: list[str] = []
        for key in value:
            if not isinstance(key, str):
                raise ClosedValidationError(
                    f"canonicalize_jcs: object keys must be str, got {type(key).__name__}"
                )
            _reject_surrogates(key, label="canonicalize_jcs")
            keys.append(key)
        if len(set(keys)) != len(keys):
            raise ClosedValidationError(
                "canonicalize_jcs: duplicate object keys are forbidden"
            )
        sorted_keys = sorted(keys, key=_utf16be_sort_key)
        out.append("{")
        for idx, key in enumerate(sorted_keys):
            if idx:
                out.append(",")
            out.append(_escape_jcs_string(key))
            out.append(":")
            _dump_jcs(value[key], out)
        out.append("}")
        return
    raise ClosedValidationError(
        f"canonicalize_jcs: unsupported type {type(value).__name__}"
    )


def canonicalize_jcs(value: object) -> bytes:
    """Serialize `value` to strict RFC 8785 canonical JSON UTF-8 bytes."""
    out: list[str] = []
    try:
        _dump_jcs(value, out)
    except RecursionError as exc:
        raise ClosedValidationError(
            "canonicalize_jcs: maximum nesting depth exceeded"
        ) from exc
    return "".join(out).encode("utf-8")


def _strict_object_pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, val in pairs:
        _reject_surrogates(key, label="loads_strict_json")
        if key in result:
            raise ClosedValidationError(
                f"loads_strict_json: duplicate object key {key!r}"
            )
        result[key] = val
    return result


def _strict_parse_float(token: str) -> float:
    raise ClosedValidationError(
        f"loads_strict_json: floating point literal {token!r} is forbidden"
    )


def _strict_parse_constant(token: str) -> Any:
    raise ClosedValidationError(
        f"loads_strict_json: non-JSON constant {token!r} is forbidden"
    )


def _strict_parse_int(token: str) -> int:
    if len(token) > 20:
        raise ClosedValidationError(
            "loads_strict_json: integer literal exceeds RFC 8785 safe integer bounds"
        )
    try:
        parsed = int(token, 10)
    except ValueError as exc:
        raise ClosedValidationError(
            f"loads_strict_json: invalid integer literal {token!r}"
        ) from exc
    if not (MIN_JCS_SAFE_INT <= parsed <= MAX_JCS_SAFE_INT):
        raise ClosedValidationError(
            f"loads_strict_json: integer literal {parsed} outside "
            f"[{MIN_JCS_SAFE_INT}, {MAX_JCS_SAFE_INT}]"
        )
    return parsed


def _check_loaded_strings(node: Any) -> None:
    if isinstance(node, str):
        _reject_surrogates(node, label="loads_strict_json")
    elif isinstance(node, list):
        for elem in node:
            _check_loaded_strings(elem)
    elif isinstance(node, dict):
        for val in node.values():
            _check_loaded_strings(val)


def loads_strict_json(raw: str | bytes) -> Any:
    """Parse strict I-JSON / JCS-compatible JSON without floats, duplicates, or surrogates."""
    if isinstance(raw, bytes):
        try:
            text = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise ClosedValidationError(
                f"loads_strict_json: invalid UTF-8 input: {exc}"
            ) from exc
    elif isinstance(raw, str):
        _reject_surrogates(raw, label="loads_strict_json")
        text = raw
    else:
        raise ClosedValidationError(
            f"loads_strict_json: expected str or bytes, got {type(raw).__name__}"
        )

    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_strict_object_pairs_hook,
            parse_float=_strict_parse_float,
            parse_int=_strict_parse_int,
            parse_constant=_strict_parse_constant,
        )
        _check_loaded_strings(parsed)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ClosedValidationError(
            f"loads_strict_json: invalid JSON: {exc}"
        ) from exc

    return parsed


def sort_utf8_strings(
    values: Iterable[str],
    *,
    field_name: str,
    allow_empty: bool = False,
    validator: Callable[[str], str] | None = None,
) -> tuple[str, ...]:
    """Validate unique NFC UTF-8 strings and sort by ascending raw UTF-8 byte order."""
    if not isinstance(allow_empty, bool):
        raise ClosedValidationError(
            f"{field_name}: allow_empty must be bool, got {type(allow_empty).__name__}"
        )
    if isinstance(values, (str, bytes)) or not isinstance(values, Iterable):
        raise ClosedValidationError(
            f"{field_name}: expected an iterable collection of strings, got {type(values).__name__}"
        )

    validated: list[str] = []
    seen: set[str] = set()
    for raw_item in values:
        item = validate_utf8_nfc(raw_item, field_name=field_name, allow_empty=False)
        if validator is not None:
            item = validator(item)
            item = validate_utf8_nfc(item, field_name=field_name, allow_empty=False)
        if item in seen:
            raise ClosedValidationError(
                f"{field_name}: duplicate string element {item!r}"
            )
        seen.add(item)
        validated.append(item)

    if not allow_empty and not validated:
        raise ClosedValidationError(f"{field_name}: collection must not be empty")

    return tuple(sorted(validated, key=lambda s: s.encode("utf-8")))


def sort_by_jcs_key(
    items: Iterable[T],
    key_fn: Callable[[T], object],
) -> tuple[T, ...]:
    """Sort `items` deterministically by ascending RFC 8785 JCS bytes of `key_fn(item)`."""
    if isinstance(items, (str, bytes)) or not isinstance(items, Iterable):
        raise ClosedValidationError(
            f"sort_by_jcs_key: expected iterable items, got {type(items).__name__}"
        )
    return tuple(sorted(items, key=lambda item: canonicalize_jcs(key_fn(item))))


def jcs_sha256(value: object) -> str:
    """Compute `'sha256:' + hex(SHA-256(RFC8785(value)))`."""
    return "sha256:" + hashlib.sha256(canonicalize_jcs(value)).hexdigest()


def domain_jcs_sha256(domain_prefix: str, value: object) -> str:
    """Compute `'sha256:' + hex(SHA-256(UTF8(domain_prefix) || 0x00 || RFC8785(value)))`."""
    checked_prefix = validate_non_empty_str(
        domain_prefix, field_name="domain_prefix"
    )
    payload = (
        checked_prefix.encode("utf-8") + b"\x00" + canonicalize_jcs(value)
    )
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def self_digest_jcs_sha256(
    mapping: Mapping[str, Any],
    *,
    digest_member: str,
    domain_prefix: str | None = None,
    strip_integrity: bool = True,
) -> str:
    """Compute Layer-1 self-digest after deleting `digest_member` (and `integrity` if requested)."""
    if not isinstance(strip_integrity, bool):
        raise ClosedValidationError("strip_integrity: expected bool")
    checked_mapping = require_mapping(mapping, label="mapping")
    checked_member = validate_non_empty_str(
        digest_member, field_name="digest_member"
    )
    reduced = dict(checked_mapping)
    reduced.pop(checked_member, None)
    if strip_integrity:
        reduced.pop("integrity", None)
    if domain_prefix is None:
        return jcs_sha256(reduced)
    return domain_jcs_sha256(domain_prefix, reduced)


def decode_strict_base64(
    value: object,
    *,
    field_name: str,
    expected_len: int | None = None,
) -> bytes:
    """Decode standard, padded RFC 4648 Base64, rejecting base64url and non-canonical forms."""
    if not isinstance(value, str):
        raise ClosedValidationError(
            f"{field_name}: expected base64 str, got {type(value).__name__}"
        )
    if "-" in value or "_" in value:
        raise ClosedValidationError(
            f"{field_name}: base64url characters '-'/'_' are forbidden"
        )
    if not value.isascii():
        raise ClosedValidationError(
            f"{field_name}: base64 string must contain only ASCII characters"
        )
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception as exc:
        raise ClosedValidationError(
            f"{field_name}: invalid RFC 4648 base64 encoding: {exc}"
        ) from exc
    if base64.b64encode(raw).decode("ascii") != value:
        raise ClosedValidationError(
            f"{field_name}: base64 encoding must be canonical and padded"
        )
    if expected_len is not None:
        if (
            isinstance(expected_len, bool)
            or not isinstance(expected_len, int)
            or expected_len < 0
        ):
            raise ClosedValidationError(
                f"{field_name}: expected_len must be a non-negative int"
            )
        if len(raw) != expected_len:
            raise ClosedValidationError(
                f"{field_name}: expected {expected_len} decoded bytes, got {len(raw)}"
            )
    return raw


@dataclass(frozen=True, slots=True)
class ArtifactLocator:
    """Immutable 6-member typed content-addressed locator (ADR-0001 §12.2)."""

    SCHEMA: ClassVar[str] = "smart_ads/artifact_locator/v1"

    artifact_type: str
    content_digest: str
    serialization: str = "rfc8785-json"
    store_kind: str = "cell_immutable_object"
    object_ref: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.artifact_type, str) or not _ARTIFACT_TYPE_RE.fullmatch(
            self.artifact_type
        ):
            raise ClosedValidationError(
                f"artifact_locator.artifact_type: invalid schema identifier {self.artifact_type!r}"
            )
        validate_sha256_prefixed(
            self.content_digest, field_name="artifact_locator.content_digest"
        )
        if self.serialization != "rfc8785-json":
            raise ClosedValidationError(
                "artifact_locator.serialization: must equal 'rfc8785-json'"
            )
        if self.store_kind != "cell_immutable_object":
            raise ClosedValidationError(
                "artifact_locator.store_kind: must equal 'cell_immutable_object'"
            )
        expected_ref = f"cell-object:{self.content_digest}"
        if self.object_ref != expected_ref:
            raise ClosedValidationError(
                f"artifact_locator.object_ref: expected {expected_ref!r}, got {self.object_ref!r}"
            )

    @classmethod
    def from_digest(cls, artifact_type: str, content_digest: str) -> ArtifactLocator:
        """Construct an `ArtifactLocator` from `artifact_type` and `sha256:<hex>` digest."""
        validate_sha256_prefixed(
            content_digest, field_name="artifact_locator.content_digest"
        )
        return cls(
            artifact_type=artifact_type,
            content_digest=content_digest,
            serialization="rfc8785-json",
            store_kind="cell_immutable_object",
            object_ref=f"cell-object:{content_digest}",
        )

    @classmethod
    def for_canonical_bytes(
        cls, artifact_type: str, canonical_bytes: bytes
    ) -> ArtifactLocator:
        """Construct a Layer-3 `ArtifactLocator` over full RFC 8785 canonical bytes."""
        if not isinstance(canonical_bytes, bytes):
            raise ClosedValidationError(
                f"canonical_bytes: expected bytes, got {type(canonical_bytes).__name__}"
            )
        digest = "sha256:" + hashlib.sha256(canonical_bytes).hexdigest()
        return cls.from_digest(artifact_type, digest)

    @classmethod
    def from_dict(
        cls,
        data: object,
        *,
        expected_type: str | None = None,
    ) -> ArtifactLocator:
        """Validate and parse an exact 6-member `smart_ads/artifact_locator/v1` mapping."""
        mapping = require_exact_keys(
            data, _LOCATOR_KEYS, label="artifact_locator"
        )
        if mapping["$schema"] != cls.SCHEMA:
            raise ClosedValidationError(
                f"artifact_locator.$schema: expected {cls.SCHEMA!r}, got {mapping['$schema']!r}"
            )
        locator = cls(
            artifact_type=mapping["artifact_type"],
            content_digest=mapping["content_digest"],
            serialization=mapping["serialization"],
            store_kind=mapping["store_kind"],
            object_ref=mapping["object_ref"],
        )
        if expected_type is not None and locator.artifact_type != expected_type:
            raise ClosedValidationError(
                f"artifact_locator.artifact_type: expected {expected_type!r}, "
                f"got {locator.artifact_type!r}"
            )
        return locator

    def to_dict(self) -> dict[str, Any]:
        """Serialize to the closed 6-member `artifact_locator/v1` JSON object."""
        return {
            "$schema": self.SCHEMA,
            "artifact_type": self.artifact_type,
            "content_digest": self.content_digest,
            "serialization": self.serialization,
            "store_kind": self.store_kind,
            "object_ref": self.object_ref,
        }


@dataclass(frozen=True, slots=True)
class P1Integrity:
    """Closed P1 envelope integrity block (unsigned preimage or finalized signed state)."""

    key_id: str
    key_registry_snapshot_locator: ArtifactLocator
    content_digest: str | None = None
    signature_base64: str | None = None

    def __post_init__(self) -> None:
        validate_ed25519_key_id(self.key_id, field_name="integrity.key_id")
        if (
            not isinstance(self.key_registry_snapshot_locator, ArtifactLocator)
            or self.key_registry_snapshot_locator.artifact_type != _KEY_REGISTRY_SCHEMA
        ):
            raise ClosedValidationError(
                "integrity.key_registry_snapshot_locator: must be an ArtifactLocator "
                f"for {_KEY_REGISTRY_SCHEMA!r}"
            )
        if (self.content_digest is None) != (self.signature_base64 is None):
            raise ClosedValidationError(
                "integrity: partial signature state is forbidden "
                "(content_digest and signature_base64 must both be absent or both present)"
            )
        if self.content_digest is not None:
            validate_sha256_prefixed(
                self.content_digest, field_name="integrity.content_digest"
            )
            decode_strict_base64(
                self.signature_base64,
                field_name="integrity.signature_base64",
                expected_len=64,
            )

    @property
    def is_signed(self) -> bool:
        return self.content_digest is not None and self.signature_base64 is not None

    @classmethod
    def from_dict(
        cls,
        data: object,
        *,
        require_signed: bool = False,
    ) -> P1Integrity:
        """Parse an unsigned (2-member) or signed (4-member) P1 `integrity` mapping."""
        if not isinstance(require_signed, bool):
            raise ClosedValidationError("require_signed: expected bool")
        mapping = require_mapping(data, label="integrity")
        keys = set(mapping.keys())
        if keys == _SIGNED_P1_KEYS:
            if (
                mapping["content_digest"] is None
                or mapping["signature_base64"] is None
            ):
                raise ClosedValidationError(
                    "integrity: signed P1 members must not be null"
                )
            reg_locator = ArtifactLocator.from_dict(
                mapping["key_registry_snapshot_locator"],
                expected_type=_KEY_REGISTRY_SCHEMA,
            )
            return cls(
                key_id=mapping["key_id"],
                key_registry_snapshot_locator=reg_locator,
                content_digest=mapping["content_digest"],
                signature_base64=mapping["signature_base64"],
            )
        if not require_signed and keys == _UNSIGNED_P1_KEYS:
            reg_locator = ArtifactLocator.from_dict(
                mapping["key_registry_snapshot_locator"],
                expected_type=_KEY_REGISTRY_SCHEMA,
            )
            return cls(
                key_id=mapping["key_id"],
                key_registry_snapshot_locator=reg_locator,
            )
        expected = _SIGNED_P1_KEYS if require_signed else (_SIGNED_P1_KEYS | _UNSIGNED_P1_KEYS)
        raise ClosedValidationError(
            f"integrity: invalid P1 member set {sorted(keys)} (expected {sorted(expected)})"
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize unsigned (2 members) or signed (4 members) P1 `integrity` block."""
        out: dict[str, Any] = {
            "key_id": self.key_id,
            "key_registry_snapshot_locator": self.key_registry_snapshot_locator.to_dict(),
        }
        if self.is_signed:
            out["content_digest"] = self.content_digest
            out["signature_base64"] = self.signature_base64
        return out


def _deep_copy_json_tree(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {k: _deep_copy_json_tree(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_deep_copy_json_tree(v) for v in value]
    if isinstance(value, tuple):
        return tuple(_deep_copy_json_tree(v) for v in value)
    return copy.deepcopy(value)


def p1_preimage(envelope: Mapping[str, Any]) -> dict[str, Any]:
    """Return a deep copy of `envelope` with `/integrity/{content_digest,signature_base64}` deleted."""
    checked_env = require_mapping(envelope, label="p1.envelope")
    if "integrity" not in checked_env:
        raise ClosedValidationError(
            "p1_preimage: envelope must contain mapping member 'integrity'"
        )
    require_mapping(checked_env["integrity"], label="p1.envelope.integrity")
    cloned: dict[str, Any] = _deep_copy_json_tree(checked_env)
    integrity = cloned["integrity"]
    integrity.pop("content_digest", None)
    integrity.pop("signature_base64", None)
    return cloned


def p1_content_digest(envelope: Mapping[str, Any]) -> str:
    """Compute Layer-2 P1 preimage digest `'sha256:' + hex(SHA-256(RFC8785(P)))`."""
    canonical = canonicalize_jcs(p1_preimage(envelope))
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def p1_signing_message(envelope: Mapping[str, Any], domain_prefix: str) -> bytes:
    """Compute P1 Ed25519 signing message `UTF8(domain_prefix) || 0x00 || SHA-256(RFC8785(P))`."""
    checked_prefix = validate_non_empty_str(
        domain_prefix, field_name="domain_prefix"
    )
    digest_raw = hashlib.sha256(canonicalize_jcs(p1_preimage(envelope))).digest()
    return checked_prefix.encode("utf-8") + b"\x00" + digest_raw


ADR_P1_DOMAIN_PREFIXES: Mapping[str, str] = MappingProxyType(
    {
        "smart_ads/clock_attestation/v1": "SMART-ADS:CLOCK:V1\n",
        "smart_ads/private_registry_snapshot/v1": "SMART-ADS:PRIVATE-REGISTRY:V1\n",
        "smart_ads/capability_revalidation_transition/v1": "SMART-ADS:CAPABILITY-REVALIDATION:V1\n",
        "smart_ads/capability_invalidation_transition/v1": "SMART-ADS:CAPABILITY-INVALIDATION:V1\n",
        "smart_ads/ibvi_ads_delegation_context/v1": "SMART-ADS:IBVI-ADS-DELEGATION-CONTEXT:V1\n",
        "smart_ads/admitted_collection/v1": "SMART-ADS:ADMITTED-COLLECTION:V1\n",
        "smart_ads/pipeboard_phase1_contract/v1": "SMART-ADS:PIPEBOARD-PHASE1:V1\n",
        "smart_ads/collection_result/v1": "SMART-ADS:COLLECTION-RESULT:V1\n",
        "smart_ads/git_artifact_provenance/v1": "SMART-ADS:GIT-ARTIFACT:V1\n",
        "smart_ads/base_metric_definition/v1": "SMART-ADS:BASE-METRIC-DEFINITION:V1\n",
        "smart_ads/expected_resource_inventory/v1": "SMART-ADS:EXPECTED-RESOURCE-INVENTORY:V1\n",
        "smart_ads/live_certification_transition/v1": "SMART-ADS:LIVE-CERT-TRANSITION:V1\n",
        "smart_ads/live_certification_certificate/v1": "SMART-ADS:LIVE-CERTIFICATE:V1\n",
        "smart_ads/live_certification_head/v1": "SMART-ADS:LIVE-CERTIFICATION-HEAD:V1\n",
        "smart_ads/gate3_selection_receipt/v1": "SMART-ADS:GATE3-RECEIPT:V1\n",
        "smart_ads/smart_ads_live_read_activation_receipt/v1": "SMART-ADS:LIVE-READ-ACTIVATION:V1\n",
        "smart_ads/legacy_step2_implementation_evidence/v1": "SMART-ADS:LEGACY-STEP2-EVIDENCE:V1\n",
        "smart_ads/authorization_receipt/v1": "SMART-ADS:AUTH-RECEIPT:V1\n",
        "smart_ads/authorization_reservation_record/v1": "SMART-ADS:AUTH-RESERVATION:V1\n",
        "smart_ads/execution_receipt/v1": "SMART-ADS:EXEC-RECEIPT:V1\n",
        "smart_ads/authorization_consumption_record/v1": "SMART-ADS:AUTH-CONSUMPTION:V1\n",
        "smart_ads/effect_proof/v1": "SMART-ADS:EFFECT-PROOF:V1\n",
    }
)

ADR_DATA_DOMAIN_PREFIXES: Mapping[str, str] = MappingProxyType(
    {
        "normalized_fact_set": "SMART-ADS:NORMALIZED-FACT-SET:V1\n",
        "7b_canonical_fact_key": "SMART-ADS:7B-CANONICAL-FACT-KEY:V1\n",
        "7b_fact_projection": "SMART-ADS:7B-FACT-PROJECTION:V1\n",
        "7b_fact_reconciliations": "SMART-ADS:7B-FACT-RECONCILIATIONS:V1\n",
        "semantic_observation": "SMART-ADS:SEMANTIC-OBSERVATION:V1\n",
        "row": "SMART-ADS:ROW:V1\n",
        "logical_rows": "SMART-ADS:LOGICAL-ROWS:V1\n",
    }
)

SUPPLEMENTAL_DOMAIN_PREFIXES: Mapping[str, str] = MappingProxyType(
    {
        "schema_bundle": "SMART-ADS:SCHEMA-BUNDLE:V1\n",
        "resource_mapping_contract": "SMART-ADS:RESOURCE-MAPPING-CONTRACT:V1\n",
    }
)

__all__ = [
    "ADR_DATA_DOMAIN_PREFIXES",
    "ADR_P1_DOMAIN_PREFIXES",
    "ArtifactLocator",
    "MAX_JCS_SAFE_INT",
    "MIN_JCS_SAFE_INT",
    "P1Integrity",
    "SUPPLEMENTAL_DOMAIN_PREFIXES",
    "canonicalize_jcs",
    "decode_strict_base64",
    "domain_jcs_sha256",
    "jcs_sha256",
    "loads_strict_json",
    "p1_content_digest",
    "p1_preimage",
    "p1_signing_message",
    "self_digest_jcs_sha256",
    "sort_by_jcs_key",
    "sort_utf8_strings",
]
