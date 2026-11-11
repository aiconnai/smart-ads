"""Canonical HMAC-SHA256 Base32 resource_ref derivation and bidirectional directory (ADR-0001 §8)."""
from __future__ import annotations

import base64
from dataclasses import dataclass, field
import hashlib
import hmac
import re
from typing import Final

from smart_ads.contracts.scalars import (
    ClosedValidationError,
    validate_non_empty_str,
    validate_opaque_ref,
)

CANONICAL_RESOURCE_REF_RE: Final[re.Pattern[str]] = re.compile(
    r"^resource:[a-z2-7]{51}[aq]$"
)


def validate_resource_ref(
    value: object,
    *,
    field_name: str = "resource_ref",
) -> str:
    """Validate canonical 256-bit RFC 4648 lowercase unpadded Base32 `resource_ref`."""
    if (
        not isinstance(value, str)
        or "\n" in value
        or "\r" in value
        or CANONICAL_RESOURCE_REF_RE.fullmatch(value) is None
    ):
        raise ClosedValidationError(
            f"{field_name}: expected canonical '^resource:[a-z2-7]{{51}}[aq]$'"
        )
    body = value.split(":", 1)[1]
    try:
        raw = base64.b32decode(body.upper() + "====", casefold=False)
    except Exception as exc:
        raise ClosedValidationError(
            f"{field_name}: invalid RFC 4648 Base32 encoding"
        ) from exc
    if (
        len(raw) != 32
        or base64.b32encode(raw).decode("ascii").rstrip("=").lower() != body
    ):
        raise ClosedValidationError(
            f"{field_name}: non-canonical 256-bit Base32 resource_ref"
        )
    return value


def _validate_redacted_raw_provider_id(raw_provider_id: object) -> str:
    try:
        return validate_non_empty_str(
            raw_provider_id, field_name="raw_provider_id"
        )
    except ClosedValidationError:
        raise ClosedValidationError(
            "raw_provider_id: invalid provider resource identifier (redacted)"
        ) from None


def _validate_domain_separator(
    domain_separator: object,
    *,
    field_name: str = "domain_separator",
) -> str:
    if not isinstance(domain_separator, str) or domain_separator != "0x00":
        raise ClosedValidationError(f"{field_name}: must equal '0x00'")
    return domain_separator


@dataclass(frozen=True, slots=True)
class TenantResourceKeyHandle:
    """Private registry-boundary HMAC key handle with redacted secret material."""

    tenant_ref: str
    key_identity: str
    secret_bytes: bytes = field(repr=False)

    def __post_init__(self) -> None:
        validate_opaque_ref(
            self.tenant_ref,
            field_name="tenant_resource_key_handle.tenant_ref",
            expected_prefix="tenant",
        )
        validate_opaque_ref(
            self.key_identity,
            field_name="tenant_resource_key_handle.key_identity",
            expected_prefix="key",
        )
        if not isinstance(self.secret_bytes, bytes):
            raise ClosedValidationError(
                "tenant_resource_key_handle.secret_bytes: expected bytes"
            )
        if len(self.secret_bytes) < 32:
            raise ClosedValidationError(
                "tenant_resource_key_handle.secret_bytes: secret key must be at least 32 bytes"
            )

    def __repr__(self) -> str:
        return (
            f"TenantResourceKeyHandle(tenant_ref={self.tenant_ref!r}, "
            f"key_identity={self.key_identity!r}, secret_bytes=<REDACTED>)"
        )

    def __str__(self) -> str:
        return self.__repr__()


def derive_resource_ref(
    *,
    key_handle: TenantResourceKeyHandle,
    mapping_version: str,
    domain_separator: str = "0x00",
    ad_platform_ref: str,
    resource_level: str,
    raw_provider_id: str,
) -> str:
    """Derive canonical `resource_ref` via HMAC-SHA256 over `0x00`-separated UTF-8 NFC fields."""
    if not isinstance(key_handle, TenantResourceKeyHandle):
        raise ClosedValidationError(
            "key_handle: expected TenantResourceKeyHandle"
        )
    _validate_domain_separator(domain_separator, field_name="domain_separator")
    checked_version = validate_non_empty_str(
        mapping_version, field_name="mapping_version"
    )
    checked_platform = validate_non_empty_str(
        ad_platform_ref, field_name="ad_platform_ref"
    )
    checked_level = validate_non_empty_str(
        resource_level, field_name="resource_level"
    )
    checked_raw_id = _validate_redacted_raw_provider_id(raw_provider_id)

    preimage = b"\x00".join(
        part.encode("utf-8")
        for part in (
            checked_version,
            checked_platform,
            checked_level,
            checked_raw_id,
        )
    )
    digest = hmac.new(
        key_handle.secret_bytes, preimage, hashlib.sha256
    ).digest()
    encoded = (
        "resource:"
        + base64.b32encode(digest).decode("ascii").rstrip("=").lower()
    )
    return validate_resource_ref(encoded)


def verify_resource_ref(
    *,
    expected_resource_ref: str,
    key_handle: TenantResourceKeyHandle,
    mapping_version: str,
    domain_separator: str = "0x00",
    ad_platform_ref: str,
    resource_level: str,
    raw_provider_id: str,
) -> bool:
    """Verify `expected_resource_ref` in constant time against HMAC-SHA256 derivation."""
    checked_expected = validate_resource_ref(
        expected_resource_ref, field_name="expected_resource_ref"
    )
    actual = derive_resource_ref(
        key_handle=key_handle,
        mapping_version=mapping_version,
        domain_separator=domain_separator,
        ad_platform_ref=ad_platform_ref,
        resource_level=resource_level,
        raw_provider_id=raw_provider_id,
    )
    return hmac.compare_digest(
        checked_expected.encode("ascii"), actual.encode("ascii")
    )


@dataclass(frozen=True, init=False, slots=True)
class BidirectionalResourceDirectory:
    """Private registry-boundary 1-to-1 bijection `raw_provider_id <-> resource_ref`."""

    _key_handle: TenantResourceKeyHandle = field(repr=False)
    mapping_version: str
    domain_separator: str
    ad_platform_ref: str
    resource_level: str
    _raw_to_ref: dict[str, str] = field(repr=False)
    _ref_to_raw: dict[str, str] = field(repr=False)

    def __init__(
        self,
        key_handle: TenantResourceKeyHandle,
        mapping_version: str,
        domain_separator: str = "0x00",
        ad_platform_ref: str = "meta",
        resource_level: str = "campaign",
    ) -> None:
        if not isinstance(key_handle, TenantResourceKeyHandle):
            raise ClosedValidationError(
                "bidirectional_resource_directory.key_handle: expected TenantResourceKeyHandle"
            )
        object.__setattr__(self, "_key_handle", key_handle)
        object.__setattr__(
            self,
            "mapping_version",
            validate_non_empty_str(
                mapping_version,
                field_name="bidirectional_resource_directory.mapping_version",
            ),
        )
        object.__setattr__(
            self,
            "domain_separator",
            _validate_domain_separator(
                domain_separator,
                field_name="bidirectional_resource_directory.domain_separator",
            ),
        )
        object.__setattr__(
            self,
            "ad_platform_ref",
            validate_non_empty_str(
                ad_platform_ref,
                field_name="bidirectional_resource_directory.ad_platform_ref",
            ),
        )
        object.__setattr__(
            self,
            "resource_level",
            validate_non_empty_str(
                resource_level,
                field_name="bidirectional_resource_directory.resource_level",
            ),
        )
        object.__setattr__(self, "_raw_to_ref", {})
        object.__setattr__(self, "_ref_to_raw", {})

    @property
    def tenant_ref(self) -> str:
        return self._key_handle.tenant_ref

    @property
    def key_identity(self) -> str:
        return self._key_handle.key_identity

    @property
    def entry_count(self) -> int:
        return len(self._raw_to_ref)

    def __repr__(self) -> str:
        return (
            f"BidirectionalResourceDirectory("
            f"tenant_ref={self.tenant_ref!r}, "
            f"key_identity={self.key_identity!r}, "
            f"mapping_version={self.mapping_version!r}, "
            f"entry_count={self.entry_count})"
        )

    def __str__(self) -> str:
        return self.__repr__()

    def register(self, raw_provider_id: str) -> str:
        """Derive and register `(raw_provider_id, resource_ref)`, rejecting any bijection collision."""
        checked_raw = _validate_redacted_raw_provider_id(raw_provider_id)
        derived_ref = derive_resource_ref(
            key_handle=self._key_handle,
            mapping_version=self.mapping_version,
            domain_separator=self.domain_separator,
            ad_platform_ref=self.ad_platform_ref,
            resource_level=self.resource_level,
            raw_provider_id=checked_raw,
        )
        existing_ref = self._raw_to_ref.get(checked_raw)
        if existing_ref is not None:
            if (
                existing_ref != derived_ref
                or self._ref_to_raw.get(derived_ref) != checked_raw
            ):
                raise ClosedValidationError(
                    "bidirectional_resource_directory: resource mapping collision detected (redacted)"
                )
            return derived_ref

        if derived_ref in self._ref_to_raw:
            raise ClosedValidationError(
                "bidirectional_resource_directory: derived resource_ref collision detected (redacted)"
            )

        self._raw_to_ref[checked_raw] = derived_ref
        self._ref_to_raw[derived_ref] = checked_raw
        return derived_ref

    def register_verified_pair(
        self, raw_provider_id: str, resource_ref: str
    ) -> None:
        """Verify HMAC derivation and register `(raw_provider_id, resource_ref)` with 1-to-1 uniqueness."""
        checked_raw = _validate_redacted_raw_provider_id(raw_provider_id)
        checked_ref = validate_resource_ref(
            resource_ref, field_name="resource_ref"
        )
        if not verify_resource_ref(
            expected_resource_ref=checked_ref,
            key_handle=self._key_handle,
            mapping_version=self.mapping_version,
            domain_separator=self.domain_separator,
            ad_platform_ref=self.ad_platform_ref,
            resource_level=self.resource_level,
            raw_provider_id=checked_raw,
        ):
            raise ClosedValidationError(
                "bidirectional_resource_directory: resource_ref verification failed (redacted)"
            )

        existing_ref = self._raw_to_ref.get(checked_raw)
        if existing_ref is not None and existing_ref != checked_ref:
            raise ClosedValidationError(
                "bidirectional_resource_directory: forward mapping collision detected (redacted)"
            )
        existing_raw = self._ref_to_raw.get(checked_ref)
        if existing_raw is not None and existing_raw != checked_raw:
            raise ClosedValidationError(
                "bidirectional_resource_directory: reverse mapping collision detected (redacted)"
            )

        self._raw_to_ref[checked_raw] = checked_ref
        self._ref_to_raw[checked_ref] = checked_raw

    def resolve_resource_ref(self, raw_provider_id: str) -> str:
        """Resolve registered `resource_ref` for `raw_provider_id`, failing closed if unknown."""
        checked_raw = _validate_redacted_raw_provider_id(raw_provider_id)
        resolved = self._raw_to_ref.get(checked_raw)
        if resolved is None:
            raise ClosedValidationError(
                "bidirectional_resource_directory: unknown provider resource identifier (redacted)"
            )
        return resolved

    def known_resource_refs(self) -> tuple[str, ...]:
        """Return all registered `resource_ref` values sorted by ascending UTF-8 bytes."""
        return tuple(
            sorted(self._ref_to_raw.keys(), key=lambda s: s.encode("utf-8"))
        )


__all__ = [
    "BidirectionalResourceDirectory",
    "CANONICAL_RESOURCE_REF_RE",
    "TenantResourceKeyHandle",
    "derive_resource_ref",
    "validate_resource_ref",
    "verify_resource_ref",
]
