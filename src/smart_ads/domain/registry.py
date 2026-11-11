"""Private registry snapshot, capability states, bindings, scopes, and expected resource inventory (ADR-0001 §§4.2, 8)."""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, ClassVar, Final, Literal

from smart_ads.contracts.jcs import (
    SUPPLEMENTAL_DOMAIN_PREFIXES,
    ArtifactLocator,
    P1Integrity,
    canonicalize_jcs,
    domain_jcs_sha256,
    jcs_sha256,
    p1_content_digest,
    sort_utf8_strings,
)
from smart_ads.contracts.scalars import (
    ClosedValidationError,
    parse_iso_date,
    parse_timestamp_utc_micros,
    require_exact_keys,
    require_mapping,
    validate_currency_iso4217,
    validate_iso_date,
    validate_non_empty_str,
    validate_opaque_ref,
    validate_sha256_prefixed,
    validate_timestamp_utc_seconds,
    validate_utf8_nfc,
)
from smart_ads.contracts.schemas import DateRange
from smart_ads.domain.resource_ref import validate_resource_ref

CapabilityState = Literal[
    "declared",
    "fixture_certified",
    "live_certified",
    "unavailable",
    "deferred",
    "invalidated",
    "revalidation_pending",
]

_ALLOWED_CAPABILITY_STATES: Final[frozenset[str]] = frozenset(
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
_REGISTRY_SNAPSHOT_ID_RE: Final[re.Pattern[str]] = re.compile(
    r"\Aregistry-snapshot:[A-Za-z0-9._:-]+\Z"
)
_DRIVER_CAPABILITY_KEYS: Final[frozenset[str]] = frozenset(
    {
        "capability_ref",
        "capability_semantic_version",
        "driver_id",
        "driver_contract_locator",
        "driver_contract_digest",
        "resource_scope_ref",
        "state",
        "required_metrics",
    }
)
_REGISTRY_BINDING_KEYS: Final[frozenset[str]] = frozenset(
    {
        "binding_ref",
        "account_ref",
        "transport_provider_ref",
        "ad_platform_ref",
        "currency",
        "driver_id",
    }
)
_AUTHORIZED_SCOPE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "front_ref",
        "profile_ref",
        "binding_ref",
        "resource_scope_ref",
    }
)
_PRIVATE_REGISTRY_CORE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "$schema",
        "snapshot_id",
        "tenant_ref",
        "issued_at_utc",
        "valid_until_utc",
        "resource_ref_mapping_version",
        "key_identity",
        "domain_separator",
        "resource_mapping_contract_digest",
        "bindings",
        "authorized_scopes",
        "capabilities",
    }
)
_EXPECTED_RESOURCE_KEY_KEYS: Final[frozenset[str]] = frozenset(
    {
        "binding_ref",
        "account_ref",
        "resource_ref",
        "resource_level",
        "metric_date",
        "attribution_ref",
        "breakdown_signature",
    }
)
_EXPECTED_INVENTORY_CORE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "$schema",
        "inventory_id",
        "registry_snapshot_locator",
        "registry_snapshot_digest",
        "tenant_ref",
        "binding_ref",
        "account_ref",
        "resource_scope_ref",
        "date_range",
        "expected_resources",
    }
)


def _validate_driver_id(value: object, *, field_name: str) -> str:
    checked = validate_non_empty_str(value, field_name=field_name)
    if any(ch.isspace() for ch in checked):
        raise ClosedValidationError(f"{field_name}: whitespace is forbidden")
    return checked


def _validate_sorted_metric_refs(
    values: object,
    *,
    field_name: str,
    require_already_sorted: bool = False,
) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple)):
        raise ClosedValidationError(
            f"{field_name}: expected list or tuple of metric refs, got {type(values).__name__}"
        )
    sorted_vals = sort_utf8_strings(
        values,
        field_name=field_name,
        allow_empty=False,
        validator=lambda s: validate_opaque_ref(
            s, field_name=field_name, expected_prefix="metric"
        ),
    )
    if require_already_sorted and tuple(values) != sorted_vals:
        raise ClosedValidationError(
            f"{field_name}: array must already be canonically sorted by UTF-8 bytes"
        )
    return sorted_vals


@dataclass(frozen=True, slots=True)
class DriverCapabilityEntry:
    """Closed 8-member driver capability entry in a `PrivateRegistrySnapshot`."""

    capability_ref: str
    capability_semantic_version: str
    driver_id: str
    driver_contract_locator: ArtifactLocator
    driver_contract_digest: str
    resource_scope_ref: str
    state: CapabilityState
    required_metrics: tuple[str, ...]

    def __post_init__(self) -> None:
        validate_opaque_ref(
            self.capability_ref,
            field_name="driver_capability_entry.capability_ref",
            expected_prefix="cap",
        )
        validate_non_empty_str(
            self.capability_semantic_version,
            field_name="driver_capability_entry.capability_semantic_version",
        )
        _validate_driver_id(
            self.driver_id, field_name="driver_capability_entry.driver_id"
        )
        if not isinstance(self.driver_contract_locator, ArtifactLocator):
            raise ClosedValidationError(
                "driver_capability_entry.driver_contract_locator: expected ArtifactLocator"
            )
        validate_sha256_prefixed(
            self.driver_contract_digest,
            field_name="driver_capability_entry.driver_contract_digest",
        )
        if (
            self.driver_contract_digest
            != self.driver_contract_locator.content_digest
        ):
            raise ClosedValidationError(
                "driver_capability_entry.driver_contract_digest: must equal "
                "driver_contract_locator.content_digest"
            )
        validate_opaque_ref(
            self.resource_scope_ref,
            field_name="driver_capability_entry.resource_scope_ref",
            expected_prefix="scope",
        )
        if (
            not isinstance(self.state, str)
            or self.state not in _ALLOWED_CAPABILITY_STATES
        ):
            raise ClosedValidationError(
                f"driver_capability_entry.state: invalid capability state {self.state!r}"
            )
        sorted_metrics = _validate_sorted_metric_refs(
            self.required_metrics,
            field_name="driver_capability_entry.required_metrics",
        )
        object.__setattr__(self, "required_metrics", sorted_metrics)

    @property
    def capability_snapshot_digest(self) -> str:
        """Compute canonical JCS SHA-256 digest of this capability entry."""
        return jcs_sha256(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "capability_ref": self.capability_ref,
            "capability_semantic_version": self.capability_semantic_version,
            "driver_id": self.driver_id,
            "driver_contract_locator": self.driver_contract_locator.to_dict(),
            "driver_contract_digest": self.driver_contract_digest,
            "resource_scope_ref": self.resource_scope_ref,
            "state": self.state,
            "required_metrics": list(self.required_metrics),
        }

    @classmethod
    def from_dict(cls, data: object) -> DriverCapabilityEntry:
        mapping = require_exact_keys(
            data, _DRIVER_CAPABILITY_KEYS, label="driver_capability_entry"
        )
        if not isinstance(mapping["required_metrics"], list):
            raise ClosedValidationError(
                "driver_capability_entry.required_metrics: expected JSON array list"
            )
        metrics = _validate_sorted_metric_refs(
            mapping["required_metrics"],
            field_name="driver_capability_entry.required_metrics",
            require_already_sorted=True,
        )
        return cls(
            capability_ref=mapping["capability_ref"],
            capability_semantic_version=mapping["capability_semantic_version"],
            driver_id=mapping["driver_id"],
            driver_contract_locator=ArtifactLocator.from_dict(
                mapping["driver_contract_locator"]
            ),
            driver_contract_digest=mapping["driver_contract_digest"],
            resource_scope_ref=mapping["resource_scope_ref"],
            state=mapping["state"],
            required_metrics=metrics,
        )


@dataclass(frozen=True, slots=True)
class RegistryBinding:
    """Closed 6-member opaque registry binding with zero private account key or hash fields."""

    binding_ref: str
    account_ref: str
    transport_provider_ref: str
    ad_platform_ref: str
    currency: str
    driver_id: str

    def __post_init__(self) -> None:
        validate_opaque_ref(
            self.binding_ref,
            field_name="registry_binding.binding_ref",
            expected_prefix="binding",
        )
        validate_opaque_ref(
            self.account_ref,
            field_name="registry_binding.account_ref",
            expected_prefix="account",
        )
        validate_opaque_ref(
            self.transport_provider_ref,
            field_name="registry_binding.transport_provider_ref",
            expected_prefix="provider",
        )
        if self.ad_platform_ref != "meta":
            raise ClosedValidationError(
                "registry_binding.ad_platform_ref: must equal 'meta'"
            )
        validate_currency_iso4217(
            self.currency, field_name="registry_binding.currency"
        )
        if self.currency != "BRL":
            raise ClosedValidationError(
                "registry_binding.currency: must equal 'BRL' in Phase 1"
            )
        _validate_driver_id(self.driver_id, field_name="registry_binding.driver_id")

    def to_dict(self) -> dict[str, Any]:
        return {
            "binding_ref": self.binding_ref,
            "account_ref": self.account_ref,
            "transport_provider_ref": self.transport_provider_ref,
            "ad_platform_ref": self.ad_platform_ref,
            "currency": self.currency,
            "driver_id": self.driver_id,
        }

    @classmethod
    def from_dict(cls, data: object) -> RegistryBinding:
        mapping = require_exact_keys(
            data, _REGISTRY_BINDING_KEYS, label="registry_binding"
        )
        return cls(
            binding_ref=mapping["binding_ref"],
            account_ref=mapping["account_ref"],
            transport_provider_ref=mapping["transport_provider_ref"],
            ad_platform_ref=mapping["ad_platform_ref"],
            currency=mapping["currency"],
            driver_id=mapping["driver_id"],
        )


@dataclass(frozen=True, slots=True)
class AuthorizedScopeRelation:
    """Closed 4-member relational authorization `(front_ref, profile_ref, binding_ref, resource_scope_ref)`."""

    front_ref: str
    profile_ref: str
    binding_ref: str
    resource_scope_ref: str

    def __post_init__(self) -> None:
        validate_opaque_ref(
            self.front_ref,
            field_name="authorized_scope_relation.front_ref",
            expected_prefix="front",
        )
        validate_opaque_ref(
            self.profile_ref,
            field_name="authorized_scope_relation.profile_ref",
            expected_prefix="profile",
        )
        validate_opaque_ref(
            self.binding_ref,
            field_name="authorized_scope_relation.binding_ref",
            expected_prefix="binding",
        )
        validate_opaque_ref(
            self.resource_scope_ref,
            field_name="authorized_scope_relation.resource_scope_ref",
            expected_prefix="scope",
        )

    def sort_key_jcs(self) -> bytes:
        return canonicalize_jcs(
            [
                self.front_ref,
                self.profile_ref,
                self.binding_ref,
                self.resource_scope_ref,
            ]
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "front_ref": self.front_ref,
            "profile_ref": self.profile_ref,
            "binding_ref": self.binding_ref,
            "resource_scope_ref": self.resource_scope_ref,
        }

    @classmethod
    def from_dict(cls, data: object) -> AuthorizedScopeRelation:
        mapping = require_exact_keys(
            data, _AUTHORIZED_SCOPE_KEYS, label="authorized_scope_relation"
        )
        return cls(
            front_ref=mapping["front_ref"],
            profile_ref=mapping["profile_ref"],
            binding_ref=mapping["binding_ref"],
            resource_scope_ref=mapping["resource_scope_ref"],
        )


def compute_resource_mapping_contract_digest(
    *,
    tenant_ref: str,
    resource_ref_mapping_version: str,
    key_identity: str,
    domain_separator: str,
) -> str:
    """Compute domain-separated JCS digest over the non-secret resource mapping contract."""
    checked_tenant = validate_opaque_ref(
        tenant_ref,
        field_name="resource_mapping_contract.tenant_ref",
        expected_prefix="tenant",
    )
    checked_version = validate_non_empty_str(
        resource_ref_mapping_version,
        field_name="resource_mapping_contract.resource_ref_mapping_version",
    )
    checked_key = validate_opaque_ref(
        key_identity,
        field_name="resource_mapping_contract.key_identity",
        expected_prefix="key",
    )
    if not isinstance(domain_separator, str) or domain_separator != "0x00":
        raise ClosedValidationError(
            "resource_mapping_contract.domain_separator: must equal '0x00'"
        )
    return domain_jcs_sha256(
        SUPPLEMENTAL_DOMAIN_PREFIXES["resource_mapping_contract"],
        {
            "domain_separator": domain_separator,
            "key_identity": checked_key,
            "resource_ref_mapping_version": checked_version,
            "tenant_ref": checked_tenant,
        },
    )


@dataclass(frozen=True, slots=True)
class PrivateRegistrySnapshot:
    """Closed `smart_ads/private_registry_snapshot/v1` P1 envelope (ADR-0001 §8)."""

    SCHEMA: ClassVar[str] = "smart_ads/private_registry_snapshot/v1"

    snapshot_id: str
    tenant_ref: str
    issued_at_utc: str
    valid_until_utc: str
    resource_ref_mapping_version: str
    key_identity: str
    bindings: tuple[RegistryBinding, ...]
    authorized_scopes: tuple[AuthorizedScopeRelation, ...]
    capabilities: tuple[DriverCapabilityEntry, ...]
    domain_separator: str = "0x00"
    resource_mapping_contract_digest: str = ""
    integrity: P1Integrity | None = None

    def __post_init__(self) -> None:
        checked_snap_id = validate_utf8_nfc(
            self.snapshot_id,
            field_name="private_registry_snapshot.snapshot_id",
            allow_empty=False,
        )
        if not _REGISTRY_SNAPSHOT_ID_RE.fullmatch(checked_snap_id):
            raise ClosedValidationError(
                f"private_registry_snapshot.snapshot_id: expected 'registry-snapshot:<id>', "
                f"got {self.snapshot_id!r}"
            )
        validate_opaque_ref(
            self.tenant_ref,
            field_name="private_registry_snapshot.tenant_ref",
            expected_prefix="tenant",
        )
        validate_timestamp_utc_seconds(
            self.issued_at_utc,
            field_name="private_registry_snapshot.issued_at_utc",
        )
        validate_timestamp_utc_seconds(
            self.valid_until_utc,
            field_name="private_registry_snapshot.valid_until_utc",
        )
        issued_us = parse_timestamp_utc_micros(
            self.issued_at_utc,
            field_name="private_registry_snapshot.issued_at_utc",
            allow_whole_seconds=True,
        )
        valid_until_us = parse_timestamp_utc_micros(
            self.valid_until_utc,
            field_name="private_registry_snapshot.valid_until_utc",
            allow_whole_seconds=True,
        )
        if issued_us >= valid_until_us:
            raise ClosedValidationError(
                "private_registry_snapshot: issued_at_utc must be strictly before valid_until_utc"
            )
        validate_non_empty_str(
            self.resource_ref_mapping_version,
            field_name="private_registry_snapshot.resource_ref_mapping_version",
        )
        validate_opaque_ref(
            self.key_identity,
            field_name="private_registry_snapshot.key_identity",
            expected_prefix="key",
        )
        if not isinstance(self.domain_separator, str) or self.domain_separator != "0x00":
            raise ClosedValidationError(
                "private_registry_snapshot.domain_separator: must equal '0x00'"
            )

        expected_rmc_digest = compute_resource_mapping_contract_digest(
            tenant_ref=self.tenant_ref,
            resource_ref_mapping_version=self.resource_ref_mapping_version,
            key_identity=self.key_identity,
            domain_separator=self.domain_separator,
        )
        if not isinstance(self.resource_mapping_contract_digest, str):
            raise ClosedValidationError(
                "private_registry_snapshot.resource_mapping_contract_digest: expected str"
            )
        if self.resource_mapping_contract_digest == "":
            object.__setattr__(
                self, "resource_mapping_contract_digest", expected_rmc_digest
            )
        else:
            validate_sha256_prefixed(
                self.resource_mapping_contract_digest,
                field_name="private_registry_snapshot.resource_mapping_contract_digest",
            )
            if self.resource_mapping_contract_digest != expected_rmc_digest:
                raise ClosedValidationError(
                    "private_registry_snapshot.resource_mapping_contract_digest: recomputed "
                    f"{expected_rmc_digest!r} != asserted {self.resource_mapping_contract_digest!r}"
                )

        if not isinstance(self.bindings, (list, tuple)) or len(self.bindings) == 0:
            raise ClosedValidationError(
                "private_registry_snapshot.bindings: expected non-empty collection of RegistryBinding"
            )
        seen_binding_refs: set[str] = set()
        seen_account_refs: set[str] = set()
        for b in self.bindings:
            if not isinstance(b, RegistryBinding):
                raise ClosedValidationError(
                    "private_registry_snapshot.bindings: every element must be RegistryBinding"
                )
            if b.binding_ref in seen_binding_refs:
                raise ClosedValidationError(
                    f"private_registry_snapshot.bindings: duplicate binding_ref {b.binding_ref!r}"
                )
            if b.account_ref in seen_account_refs:
                raise ClosedValidationError(
                    f"private_registry_snapshot.bindings: duplicate account_ref {b.account_ref!r}"
                )
            seen_binding_refs.add(b.binding_ref)
            seen_account_refs.add(b.account_ref)
        sorted_bindings = tuple(
            sorted(self.bindings, key=lambda b: b.binding_ref.encode("utf-8"))
        )
        object.__setattr__(self, "bindings", sorted_bindings)

        if (
            not isinstance(self.authorized_scopes, (list, tuple))
            or len(self.authorized_scopes) == 0
        ):
            raise ClosedValidationError(
                "private_registry_snapshot.authorized_scopes: expected non-empty collection"
            )
        seen_scope_keys: set[bytes] = set()
        for rel in self.authorized_scopes:
            if not isinstance(rel, AuthorizedScopeRelation):
                raise ClosedValidationError(
                    "private_registry_snapshot.authorized_scopes: every element must be AuthorizedScopeRelation"
                )
            if rel.binding_ref not in seen_binding_refs:
                raise ClosedValidationError(
                    f"private_registry_snapshot.authorized_scopes: binding_ref {rel.binding_ref!r} "
                    "is absent from snapshot bindings"
                )
            rel_key = rel.sort_key_jcs()
            if rel_key in seen_scope_keys:
                raise ClosedValidationError(
                    "private_registry_snapshot.authorized_scopes: duplicate scope relation"
                )
            seen_scope_keys.add(rel_key)
        sorted_scopes = tuple(
            sorted(self.authorized_scopes, key=lambda r: r.sort_key_jcs())
        )
        object.__setattr__(self, "authorized_scopes", sorted_scopes)

        if (
            not isinstance(self.capabilities, (list, tuple))
            or len(self.capabilities) == 0
        ):
            raise ClosedValidationError(
                "private_registry_snapshot.capabilities: expected non-empty collection"
            )
        seen_cap_keys: set[bytes] = set()
        for cap in self.capabilities:
            if not isinstance(cap, DriverCapabilityEntry):
                raise ClosedValidationError(
                    "private_registry_snapshot.capabilities: every element must be DriverCapabilityEntry"
                )
            cap_key = canonicalize_jcs(
                [cap.capability_ref, cap.resource_scope_ref]
            )
            if cap_key in seen_cap_keys:
                raise ClosedValidationError(
                    "private_registry_snapshot.capabilities: duplicate (capability_ref, resource_scope_ref)"
                )
            seen_cap_keys.add(cap_key)
        sorted_caps = tuple(
            sorted(
                self.capabilities,
                key=lambda c: canonicalize_jcs(
                    [c.capability_ref, c.resource_scope_ref]
                ),
            )
        )
        object.__setattr__(self, "capabilities", sorted_caps)

        if self.integrity is not None and not isinstance(
            self.integrity, P1Integrity
        ):
            raise ClosedValidationError(
                "private_registry_snapshot.integrity: expected P1Integrity or None"
            )
        if self.integrity is not None and self.integrity.is_signed:
            expected_p1 = p1_content_digest(self.to_dict())
            if self.integrity.content_digest != expected_p1:
                raise ClosedValidationError(
                    "private_registry_snapshot.integrity.content_digest: recomputed "
                    f"{expected_p1!r} != asserted {self.integrity.content_digest!r}"
                )

    def get_binding(self, binding_ref: str) -> RegistryBinding:
        """Look up `RegistryBinding` by `binding_ref` or raise `ClosedValidationError`."""
        checked = validate_opaque_ref(
            binding_ref, field_name="binding_ref", expected_prefix="binding"
        )
        for binding in self.bindings:
            if binding.binding_ref == checked:
                return binding
        raise ClosedValidationError(
            f"private_registry_snapshot: unknown binding_ref {checked!r}"
        )

    def get_capability(
        self, capability_ref: str, resource_scope_ref: str
    ) -> DriverCapabilityEntry:
        """Look up `DriverCapabilityEntry` by `(capability_ref, resource_scope_ref)`."""
        checked_cap = validate_opaque_ref(
            capability_ref, field_name="capability_ref", expected_prefix="cap"
        )
        checked_scope = validate_opaque_ref(
            resource_scope_ref,
            field_name="resource_scope_ref",
            expected_prefix="scope",
        )
        for entry in self.capabilities:
            if (
                entry.capability_ref == checked_cap
                and entry.resource_scope_ref == checked_scope
            ):
                return entry
        raise ClosedValidationError(
            f"private_registry_snapshot: unknown capability ({checked_cap!r}, {checked_scope!r})"
        )

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "$schema": self.SCHEMA,
            "snapshot_id": self.snapshot_id,
            "tenant_ref": self.tenant_ref,
            "issued_at_utc": self.issued_at_utc,
            "valid_until_utc": self.valid_until_utc,
            "resource_ref_mapping_version": self.resource_ref_mapping_version,
            "key_identity": self.key_identity,
            "domain_separator": self.domain_separator,
            "resource_mapping_contract_digest": self.resource_mapping_contract_digest,
            "bindings": [b.to_dict() for b in self.bindings],
            "authorized_scopes": [r.to_dict() for r in self.authorized_scopes],
            "capabilities": [c.to_dict() for c in self.capabilities],
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
    ) -> PrivateRegistrySnapshot:
        if not isinstance(require_signed, bool):
            raise ClosedValidationError("require_signed: expected bool")
        mapping = require_mapping(data, label="private_registry_snapshot")
        if require_signed or "integrity" in mapping:
            require_exact_keys(
                mapping,
                _PRIVATE_REGISTRY_CORE_KEYS | {"integrity"},
                label="private_registry_snapshot",
            )
            integrity: P1Integrity | None = P1Integrity.from_dict(
                mapping["integrity"], require_signed=require_signed
            )
        else:
            require_exact_keys(
                mapping,
                _PRIVATE_REGISTRY_CORE_KEYS,
                label="private_registry_snapshot",
            )
            integrity = None

        if mapping["$schema"] != cls.SCHEMA:
            raise ClosedValidationError(
                f"private_registry_snapshot.$schema: expected {cls.SCHEMA!r}, "
                f"got {mapping['$schema']!r}"
            )
        rmc_digest = validate_sha256_prefixed(
            mapping["resource_mapping_contract_digest"],
            field_name="private_registry_snapshot.resource_mapping_contract_digest",
        )
        if not isinstance(mapping["bindings"], list):
            raise ClosedValidationError(
                "private_registry_snapshot.bindings: expected JSON array list"
            )
        if not isinstance(mapping["authorized_scopes"], list):
            raise ClosedValidationError(
                "private_registry_snapshot.authorized_scopes: expected JSON array list"
            )
        if not isinstance(mapping["capabilities"], list):
            raise ClosedValidationError(
                "private_registry_snapshot.capabilities: expected JSON array list"
            )

        parsed_bindings = tuple(
            RegistryBinding.from_dict(item) for item in mapping["bindings"]
        )
        binding_keys = [b.binding_ref.encode("utf-8") for b in parsed_bindings]
        if binding_keys != sorted(binding_keys):
            raise ClosedValidationError(
                "private_registry_snapshot.bindings: must already be sorted by binding_ref UTF-8"
            )

        parsed_scopes = tuple(
            AuthorizedScopeRelation.from_dict(item)
            for item in mapping["authorized_scopes"]
        )
        scope_keys = [r.sort_key_jcs() for r in parsed_scopes]
        if scope_keys != sorted(scope_keys):
            raise ClosedValidationError(
                "private_registry_snapshot.authorized_scopes: must already be canonically sorted"
            )

        parsed_caps = tuple(
            DriverCapabilityEntry.from_dict(item)
            for item in mapping["capabilities"]
        )
        cap_keys = [
            canonicalize_jcs([c.capability_ref, c.resource_scope_ref])
            for c in parsed_caps
        ]
        if cap_keys != sorted(cap_keys):
            raise ClosedValidationError(
                "private_registry_snapshot.capabilities: must already be canonically sorted"
            )

        return cls(
            snapshot_id=mapping["snapshot_id"],
            tenant_ref=mapping["tenant_ref"],
            issued_at_utc=mapping["issued_at_utc"],
            valid_until_utc=mapping["valid_until_utc"],
            resource_ref_mapping_version=mapping[
                "resource_ref_mapping_version"
            ],
            key_identity=mapping["key_identity"],
            bindings=parsed_bindings,
            authorized_scopes=parsed_scopes,
            capabilities=parsed_caps,
            domain_separator=mapping["domain_separator"],
            resource_mapping_contract_digest=rmc_digest,
            integrity=integrity,
        )


@dataclass(frozen=True, slots=True)
class ExpectedResourceKey:
    """Closed 7-member expected resource-observation key in `U` (ADR-0001 §4.2 L589–591)."""

    binding_ref: str
    account_ref: str
    resource_ref: str
    resource_level: str
    metric_date: str
    attribution_ref: str = "attribution:not_applicable"
    breakdown_signature: str = "breakdown:none"

    def __post_init__(self) -> None:
        validate_opaque_ref(
            self.binding_ref,
            field_name="expected_resource_key.binding_ref",
            expected_prefix="binding",
        )
        validate_opaque_ref(
            self.account_ref,
            field_name="expected_resource_key.account_ref",
            expected_prefix="account",
        )
        validate_resource_ref(
            self.resource_ref, field_name="expected_resource_key.resource_ref"
        )
        if self.resource_level != "campaign":
            raise ClosedValidationError(
                "expected_resource_key.resource_level: must equal 'campaign'"
            )
        validate_iso_date(
            self.metric_date, field_name="expected_resource_key.metric_date"
        )
        validate_opaque_ref(
            self.attribution_ref,
            field_name="expected_resource_key.attribution_ref",
            expected_prefix="attribution",
        )
        if self.attribution_ref != "attribution:not_applicable":
            raise ClosedValidationError(
                "expected_resource_key.attribution_ref: must equal 'attribution:not_applicable'"
            )
        validate_opaque_ref(
            self.breakdown_signature,
            field_name="expected_resource_key.breakdown_signature",
            expected_prefix="breakdown",
        )
        if self.breakdown_signature != "breakdown:none":
            raise ClosedValidationError(
                "expected_resource_key.breakdown_signature: must equal 'breakdown:none'"
            )

    def to_identity_array(self) -> list[str]:
        return [
            self.binding_ref,
            self.account_ref,
            self.resource_ref,
            self.resource_level,
            self.metric_date,
            self.attribution_ref,
            self.breakdown_signature,
        ]

    def to_dict(self) -> dict[str, Any]:
        return {
            "binding_ref": self.binding_ref,
            "account_ref": self.account_ref,
            "resource_ref": self.resource_ref,
            "resource_level": self.resource_level,
            "metric_date": self.metric_date,
            "attribution_ref": self.attribution_ref,
            "breakdown_signature": self.breakdown_signature,
        }

    @classmethod
    def from_dict(cls, data: object) -> ExpectedResourceKey:
        mapping = require_exact_keys(
            data, _EXPECTED_RESOURCE_KEY_KEYS, label="expected_resource_key"
        )
        return cls(
            binding_ref=mapping["binding_ref"],
            account_ref=mapping["account_ref"],
            resource_ref=mapping["resource_ref"],
            resource_level=mapping["resource_level"],
            metric_date=mapping["metric_date"],
            attribution_ref=mapping["attribution_ref"],
            breakdown_signature=mapping["breakdown_signature"],
        )


@dataclass(frozen=True, slots=True)
class ExpectedResourceInventory:
    """Closed `smart_ads/expected_resource_inventory/v1` P1 envelope (ADR-0001 §4.2 L589–601)."""

    SCHEMA: ClassVar[str] = "smart_ads/expected_resource_inventory/v1"

    inventory_id: str
    registry_snapshot_locator: ArtifactLocator
    registry_snapshot_digest: str
    tenant_ref: str
    binding_ref: str
    account_ref: str
    resource_scope_ref: str
    date_range: DateRange
    expected_resources: tuple[ExpectedResourceKey, ...]
    integrity: P1Integrity | None = None

    def __post_init__(self) -> None:
        validate_opaque_ref(
            self.inventory_id,
            field_name="expected_resource_inventory.inventory_id",
            expected_prefix="inventory",
        )
        if (
            not isinstance(self.registry_snapshot_locator, ArtifactLocator)
            or self.registry_snapshot_locator.artifact_type
            != PrivateRegistrySnapshot.SCHEMA
        ):
            raise ClosedValidationError(
                "expected_resource_inventory.registry_snapshot_locator: expected ArtifactLocator "
                f"for {PrivateRegistrySnapshot.SCHEMA!r}"
            )
        validate_sha256_prefixed(
            self.registry_snapshot_digest,
            field_name="expected_resource_inventory.registry_snapshot_digest",
        )
        if (
            self.registry_snapshot_digest
            != self.registry_snapshot_locator.content_digest
        ):
            raise ClosedValidationError(
                "expected_resource_inventory.registry_snapshot_digest: must equal "
                "registry_snapshot_locator.content_digest"
            )
        validate_opaque_ref(
            self.tenant_ref,
            field_name="expected_resource_inventory.tenant_ref",
            expected_prefix="tenant",
        )
        validate_opaque_ref(
            self.binding_ref,
            field_name="expected_resource_inventory.binding_ref",
            expected_prefix="binding",
        )
        validate_opaque_ref(
            self.account_ref,
            field_name="expected_resource_inventory.account_ref",
            expected_prefix="account",
        )
        validate_opaque_ref(
            self.resource_scope_ref,
            field_name="expected_resource_inventory.resource_scope_ref",
            expected_prefix="scope",
        )
        if not isinstance(self.date_range, DateRange):
            raise ClosedValidationError(
                "expected_resource_inventory.date_range: expected DateRange"
            )
        start_cal = parse_iso_date(
            self.date_range.start_date,
            field_name="expected_resource_inventory.date_range.start_date",
        )
        end_cal = parse_iso_date(
            self.date_range.end_date,
            field_name="expected_resource_inventory.date_range.end_date",
        )

        if (
            not isinstance(self.expected_resources, (list, tuple))
            or len(self.expected_resources) == 0
        ):
            raise ClosedValidationError(
                "expected_resource_inventory.expected_resources: U must be non-empty"
            )
        keyed: list[tuple[bytes, ExpectedResourceKey]] = []
        seen_identities: set[bytes] = set()
        seen_attributions: set[str] = set()
        for u in self.expected_resources:
            if not isinstance(u, ExpectedResourceKey):
                raise ClosedValidationError(
                    "expected_resource_inventory.expected_resources: every element must be ExpectedResourceKey"
                )
            if u.binding_ref != self.binding_ref:
                raise ClosedValidationError(
                    "expected_resource_inventory.expected_resources: u.binding_ref must equal inventory binding_ref"
                )
            if u.account_ref != self.account_ref:
                raise ClosedValidationError(
                    "expected_resource_inventory.expected_resources: u.account_ref must equal inventory account_ref"
                )
            u_cal = parse_iso_date(
                u.metric_date,
                field_name="expected_resource_inventory.expected_resources.metric_date",
            )
            if not (start_cal <= u_cal <= end_cal):
                raise ClosedValidationError(
                    "expected_resource_inventory.expected_resources: u.metric_date outside inventory date_range"
                )
            seen_attributions.add(u.attribution_ref)
            identity_bytes = canonicalize_jcs(u.to_identity_array())
            if identity_bytes in seen_identities:
                raise ClosedValidationError(
                    "expected_resource_inventory.expected_resources: duplicate expected resource key"
                )
            seen_identities.add(identity_bytes)
            keyed.append((identity_bytes, u))

        if seen_attributions != {"attribution:not_applicable"}:
            raise ClosedValidationError(
                "expected_resource_inventory.expected_resources: Phase 1 requires single "
                "'attribution:not_applicable' across U (P-12)"
            )
        keyed.sort(key=lambda pair: pair[0])
        object.__setattr__(
            self, "expected_resources", tuple(u for _, u in keyed)
        )

        if self.integrity is not None and not isinstance(
            self.integrity, P1Integrity
        ):
            raise ClosedValidationError(
                "expected_resource_inventory.integrity: expected P1Integrity or None"
            )
        if self.integrity is not None and self.integrity.is_signed:
            expected_p1 = p1_content_digest(self.to_dict())
            if self.integrity.content_digest != expected_p1:
                raise ClosedValidationError(
                    "expected_resource_inventory.integrity.content_digest: recomputed "
                    f"{expected_p1!r} != asserted {self.integrity.content_digest!r}"
                )

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "$schema": self.SCHEMA,
            "inventory_id": self.inventory_id,
            "registry_snapshot_locator": self.registry_snapshot_locator.to_dict(),
            "registry_snapshot_digest": self.registry_snapshot_digest,
            "tenant_ref": self.tenant_ref,
            "binding_ref": self.binding_ref,
            "account_ref": self.account_ref,
            "resource_scope_ref": self.resource_scope_ref,
            "date_range": self.date_range.to_dict(),
            "expected_resources": [u.to_dict() for u in self.expected_resources],
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
    ) -> ExpectedResourceInventory:
        if not isinstance(require_signed, bool):
            raise ClosedValidationError("require_signed: expected bool")
        mapping = require_mapping(data, label="expected_resource_inventory")
        if require_signed or "integrity" in mapping:
            require_exact_keys(
                mapping,
                _EXPECTED_INVENTORY_CORE_KEYS | {"integrity"},
                label="expected_resource_inventory",
            )
            integrity: P1Integrity | None = P1Integrity.from_dict(
                mapping["integrity"], require_signed=require_signed
            )
        else:
            require_exact_keys(
                mapping,
                _EXPECTED_INVENTORY_CORE_KEYS,
                label="expected_resource_inventory",
            )
            integrity = None

        if mapping["$schema"] != cls.SCHEMA:
            raise ClosedValidationError(
                f"expected_resource_inventory.$schema: expected {cls.SCHEMA!r}, "
                f"got {mapping['$schema']!r}"
            )
        if not isinstance(mapping["expected_resources"], list):
            raise ClosedValidationError(
                "expected_resource_inventory.expected_resources: expected JSON array list"
            )
        parsed_u = tuple(
            ExpectedResourceKey.from_dict(item)
            for item in mapping["expected_resources"]
        )
        u_keys = [canonicalize_jcs(u.to_identity_array()) for u in parsed_u]
        if u_keys != sorted(u_keys):
            raise ClosedValidationError(
                "expected_resource_inventory.expected_resources: must already be sorted by ascending JCS identity"
            )

        return cls(
            inventory_id=mapping["inventory_id"],
            registry_snapshot_locator=ArtifactLocator.from_dict(
                mapping["registry_snapshot_locator"],
                expected_type=PrivateRegistrySnapshot.SCHEMA,
            ),
            registry_snapshot_digest=mapping["registry_snapshot_digest"],
            tenant_ref=mapping["tenant_ref"],
            binding_ref=mapping["binding_ref"],
            account_ref=mapping["account_ref"],
            resource_scope_ref=mapping["resource_scope_ref"],
            date_range=DateRange.from_dict(
                mapping["date_range"],
                label="expected_resource_inventory.date_range",
            ),
            expected_resources=parsed_u,
            integrity=integrity,
        )


__all__ = [
    "AuthorizedScopeRelation",
    "CapabilityState",
    "DriverCapabilityEntry",
    "ExpectedResourceInventory",
    "ExpectedResourceKey",
    "PrivateRegistrySnapshot",
    "RegistryBinding",
    "compute_resource_mapping_contract_digest",
]
