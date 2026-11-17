"""7B Gate-3 fingerprint, candidate/reference execution records and row pairing (ADR 5.4).

Fixed literals (driver id, workload ref, ``result_status: complete`` and the
whole ``row_pairing``) come from the ADR YAML at L958-1043. The provider-target
literals are checked by the record, after their distinctness.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import re
from types import MappingProxyType
from typing import Any, ClassVar, Final

from smart_ads.contracts.jcs import MAX_JCS_SAFE_INT, ArtifactLocator, canonicalize_jcs
from smart_ads.contracts.schemas import CanonicalQueryContract
from smart_ads.contracts.scalars import validate_timestamp_utc6
from smart_ads.reconciliation.bundle_common import (
    ADMITTED_COLLECTION_SCHEMA,
    DRIVER_CONTRACT_SCHEMA,
    EFFECT_PROOF_SCHEMA,
    MAXIMUM_RETRIEVAL_SKEW_SECONDS,
    REGISTRY_SNAPSHOT_SCHEMA,
    Bundle7BDefectError,
    closed,
    guard,
    hyphen_ref,
    member_locator,
    parse_member_locator,
    parse_query,
    require_member,
    require_type,
    scope_ref,
    sha256_member,
)
from smart_ads.reconciliation.bundle_native import NativeRequestProjection

CANDIDATE_DRIVER_ID: Final[str] = "pipeboard_hosted"
CANDIDATE_PROVIDER_TARGET_REF: Final[str] = "provider-target:pipeboard-hosted"
REFERENCE_PROVIDER_TARGET_REF: Final[str] = "provider-target:independent-meta-reference"
REFERENCE_WORKLOAD_REF: Final[str] = "workload:independent_meta_reference_harness"

# ---------------------------------------------------------------------------
# Gate-3 certification fingerprint (ADR-0001 sections 5.3 and 5.4)
# ---------------------------------------------------------------------------

_FINGERPRINT_DIGEST_MEMBERS: Final[tuple[str, ...]] = (
    "reference_client_identity_digest",
    "official_source_locators_digest",
    "candidate_driver_contract_digest",
    "canonical_query_digest",
    "parser_code_digest",
    "adapter_code_digest",
    "mapping_rules_digest",
    "schema_bundle_digest",
    "resource_mapping_contract_digest",
)
# The selected version is copied into `api-version:<v>`, which must stay an opaque_ref.
_API_VERSION_RE: Final[re.Pattern[str]] = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")


@dataclass(frozen=True, slots=True)
class Gate3CertificationFingerprint:
    """The complete eleven-member ``certification_fingerprint`` of a certification selection."""

    KEYS: ClassVar[tuple[str, ...]] = (
        "selected_meta_api_version",
        *_FINGERPRINT_DIGEST_MEMBERS,
        "authorized_certification_scope",
    )

    selected_meta_api_version: str
    reference_client_identity_digest: str
    official_source_locators_digest: str
    candidate_driver_contract_digest: str
    canonical_query_digest: str
    parser_code_digest: str
    adapter_code_digest: str
    mapping_rules_digest: str
    schema_bundle_digest: str
    resource_mapping_contract_digest: str
    authorized_certification_scope: str

    def __post_init__(self) -> None:
        label = "gate3_certification_fingerprint"
        version = self.selected_meta_api_version
        if not isinstance(version, str) or _API_VERSION_RE.fullmatch(version) is None:
            raise Bundle7BDefectError(
                "malformed_member", f"{label}.selected_meta_api_version: invalid version"
            )
        for name in _FINGERPRINT_DIGEST_MEMBERS:
            sha256_member(getattr(self, name), label=f"{label}.{name}")
        scope_ref(
            self.authorized_certification_scope, label=f"{label}.authorized_certification_scope"
        )

    def to_dict(self) -> dict[str, str]:
        return {name: getattr(self, name) for name in self.KEYS}

    @classmethod
    def from_dict(cls, data: object) -> Gate3CertificationFingerprint:
        mapping = closed(data, frozenset(cls.KEYS), label="gate3_certification_fingerprint")
        return cls(**{name: mapping[name] for name in cls.KEYS})


def require_same_fingerprint(
    left: Gate3CertificationFingerprint,
    right: Gate3CertificationFingerprint,
    *,
    label: str,
) -> None:
    """Byte-for-byte equality of two complete fingerprints; any one member differing fails 7B."""
    require_type(left, Gate3CertificationFingerprint, label=f"{label}.left")
    require_type(right, Gate3CertificationFingerprint, label=f"{label}.right")
    if canonicalize_jcs(left.to_dict()) != canonicalize_jcs(right.to_dict()):
        differing = [n for n in left.KEYS if getattr(left, n) != getattr(right, n)]
        raise Bundle7BDefectError(
            "fingerprint_mismatch", f"{label}: members differ: {sorted(differing)}"
        )


# ---------------------------------------------------------------------------
# Execution records
# ---------------------------------------------------------------------------

_IMPLEMENTATION_KINDS: Final[frozenset[str]] = frozenset({"official_sdk", "direct_rest"})
_RESULT_STATUS_COMPLETE: Final[str] = "complete"
_COMMON_EXECUTION_DIGESTS: Final[tuple[str, ...]] = (
    "native_to_canonical_projection_algorithm_digest",
    "row_universe_digest",
    "normalized_fact_set_digest",
)
_COMMON_EXECUTION_RAW: Final[tuple[str, ...]] = (
    "provider_target_ref",
    "native_request_digest",
    "native_to_canonical_projection_algorithm_digest",
    "canonical_query_projection_digest",
    "retrieved_at_utc",
    "result_status",
    "row_count",
    "row_universe_digest",
    "normalized_fact_set_digest",
)
_CANDIDATE_DIGESTS: Final[tuple[str, ...]] = (
    "driver_contract_digest",
    "wheel_digest",
    "adapter_code_digest",
    "parser_code_digest",
    "mapping_rules_digest",
)
_REFERENCE_DIGESTS: Final[tuple[str, ...]] = (
    "reference_workload_binary_digest",
    "reference_code_digest",
    "reference_run_digest",
)
# Fingerprint members repeated in the candidate execution record (ADR L1097-1101).
_CANDIDATE_FINGERPRINT_PAIRS: Final[tuple[tuple[str, str], ...]] = (
    ("driver_contract_digest", "candidate_driver_contract_digest"),
    ("adapter_code_digest", "adapter_code_digest"),
    ("parser_code_digest", "parser_code_digest"),
    ("mapping_rules_digest", "mapping_rules_digest"),
)


def _check_query_projection(execution: Any, *, label: str) -> None:
    query = execution.canonical_query_projection
    digest = execution.canonical_query_projection_digest
    require_member(query, CanonicalQueryContract, label=f"{label}.canonical_query_projection")
    sha256_member(digest, label=f"{label}.canonical_query_projection_digest")
    if query.canonical_query_digest != digest:
        raise Bundle7BDefectError(
            "canonical_query_digest_mismatch", f"{label}.canonical_query_projection_digest differs"
        )


def _check_native(execution: Any, *, label: str) -> None:
    projection = execution.native_request_projection
    require_member(
        projection, NativeRequestProjection, label=f"{label}.native_request_projection"
    )
    if projection.endpoint_version_ref != execution.source_contract_ref:
        raise Bundle7BDefectError(
            "native_version_mismatch",
            f"{label}: native endpoint/version identity differs from source_contract_ref",
        )
    sha256_member(execution.native_request_digest, label=f"{label}.native_request_digest")
    if projection.native_request_digest != execution.native_request_digest:
        raise Bundle7BDefectError(
            "native_request_digest_mismatch", f"{label}.native_request_digest differs"
        )


def _check_common_execution(execution: Any, *, label: str) -> None:
    """Members shared by both execution records (validated after the side-specific ones)."""
    hyphen_ref(
        execution.provider_target_ref,
        prefixes=frozenset({"provider-target"}),
        label=f"{label}.provider_target_ref",
    )
    member_locator(
        execution, "admitted_collection_locator", ADMITTED_COLLECTION_SCHEMA, label=label
    )
    member_locator(execution, "effect_proof_locator", EFFECT_PROOF_SCHEMA, label=label)
    _check_native(execution, label=label)
    _check_query_projection(execution, label=label)
    for name in _COMMON_EXECUTION_DIGESTS:
        sha256_member(getattr(execution, name), label=f"{label}.{name}")
    field = f"{label}.retrieved_at_utc"
    guard(
        "malformed_member",
        field,
        lambda: validate_timestamp_utc6(execution.retrieved_at_utc, field_name=field),
    )
    if execution.result_status != _RESULT_STATUS_COMPLETE:
        raise Bundle7BDefectError(
            "fixed_member_mismatch", f"{label}.result_status: must be 'complete'"
        )
    count = execution.row_count
    if type(count) is not int or not 0 <= count <= MAX_JCS_SAFE_INT:
        raise Bundle7BDefectError(
            "malformed_member", f"{label}.row_count: expected a non-negative int"
        )
    require_member(
        execution.gate3_certification_fingerprint,
        Gate3CertificationFingerprint,
        label=f"{label}.gate3_certification_fingerprint",
    )


def _parse_common_execution(mapping: Mapping[str, Any], *, label: str) -> dict[str, Any]:
    return {
        **{name: mapping[name] for name in _COMMON_EXECUTION_RAW},
        "admitted_collection_locator": parse_member_locator(
            mapping, "admitted_collection_locator", ADMITTED_COLLECTION_SCHEMA, label=label
        ),
        "effect_proof_locator": parse_member_locator(
            mapping, "effect_proof_locator", EFFECT_PROOF_SCHEMA, label=label
        ),
        "native_request_projection": NativeRequestProjection.from_dict(
            mapping["native_request_projection"]
        ),
        "canonical_query_projection": parse_query(
            mapping["canonical_query_projection"], label=f"{label}.canonical_query_projection"
        ),
        "gate3_certification_fingerprint": Gate3CertificationFingerprint.from_dict(
            mapping["gate3_certification_fingerprint"]
        ),
    }


def _execution_dict(execution: Any, order: tuple[str, ...]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for name in order:
        value = getattr(execution, name)
        out[name] = value.to_dict() if hasattr(value, "to_dict") else value
    return out


@dataclass(frozen=True, slots=True)
class CandidateExecution:
    """``candidate_execution``: the version-opaque Pipeboard hosted call and its contract."""

    KEYS: ClassVar[tuple[str, ...]] = (
        "driver_id",
        "provider_target_ref",
        "admitted_collection_locator",
        "effect_proof_locator",
        "registry_snapshot_locator",
        "driver_contract_locator",
        "driver_contract_digest",
        "source_contract_ref",
        "wheel_digest",
        "adapter_code_digest",
        "parser_code_digest",
        "mapping_rules_digest",
        "native_request_projection",
        "native_request_digest",
        "native_to_canonical_projection_algorithm_digest",
        "canonical_query_projection",
        "canonical_query_projection_digest",
        "retrieved_at_utc",
        "result_status",
        "row_count",
        "row_universe_digest",
        "normalized_fact_set_digest",
        "gate3_certification_fingerprint",
    )

    driver_id: str
    provider_target_ref: str
    admitted_collection_locator: ArtifactLocator
    effect_proof_locator: ArtifactLocator
    registry_snapshot_locator: ArtifactLocator
    driver_contract_locator: ArtifactLocator
    driver_contract_digest: str
    source_contract_ref: str
    wheel_digest: str
    adapter_code_digest: str
    parser_code_digest: str
    mapping_rules_digest: str
    native_request_projection: NativeRequestProjection
    native_request_digest: str
    native_to_canonical_projection_algorithm_digest: str
    canonical_query_projection: CanonicalQueryContract
    canonical_query_projection_digest: str
    retrieved_at_utc: str
    result_status: str
    row_count: int
    row_universe_digest: str
    normalized_fact_set_digest: str
    gate3_certification_fingerprint: Gate3CertificationFingerprint

    def __post_init__(self) -> None:
        label = "candidate_execution"
        if self.driver_id != CANDIDATE_DRIVER_ID:
            raise Bundle7BDefectError(
                "fixed_member_mismatch", f"{label}.driver_id: must be {CANDIDATE_DRIVER_ID!r}"
            )
        member_locator(self, "registry_snapshot_locator", REGISTRY_SNAPSHOT_SCHEMA, label=label)
        member_locator(self, "driver_contract_locator", DRIVER_CONTRACT_SCHEMA, label=label)
        for name in _CANDIDATE_DIGESTS:
            sha256_member(getattr(self, name), label=f"{label}.{name}")
        if self.driver_contract_digest != self.driver_contract_locator.content_digest:
            raise Bundle7BDefectError(
                "driver_contract_digest_mismatch", f"{label}: digest differs from its locator"
            )
        hyphen_ref(
            self.source_contract_ref,
            prefixes=frozenset({"opaque-driver-contract"}),
            label=f"{label}.source_contract_ref",
        )
        if self.source_contract_ref != "opaque-driver-contract:" + self.driver_contract_digest:
            raise Bundle7BDefectError(
                "source_contract_mismatch", f"{label}.source_contract_ref: must name the contract"
            )
        _check_common_execution(self, label=label)
        fingerprint = self.gate3_certification_fingerprint
        for own, member in _CANDIDATE_FINGERPRINT_PAIRS:
            if getattr(self, own) != getattr(fingerprint, member):
                raise Bundle7BDefectError(
                    "fingerprint_member_mismatch", f"{label}.{own} differs from {member}"
                )

    def to_dict(self) -> dict[str, Any]:
        return _execution_dict(self, self.KEYS)

    @classmethod
    def from_dict(cls, data: object) -> CandidateExecution:
        label = "candidate_execution"
        mapping = closed(data, frozenset(cls.KEYS), label=label)
        own = ("driver_id", "source_contract_ref", *_CANDIDATE_DIGESTS)
        return cls(
            **{name: mapping[name] for name in own},
            registry_snapshot_locator=parse_member_locator(
                mapping, "registry_snapshot_locator", REGISTRY_SNAPSHOT_SCHEMA, label=label
            ),
            driver_contract_locator=parse_member_locator(
                mapping, "driver_contract_locator", DRIVER_CONTRACT_SCHEMA, label=label
            ),
            **_parse_common_execution(mapping, label=label),
        )


@dataclass(frozen=True, slots=True)
class ReferenceExecution:
    """``reference_execution``: the independent Meta reference harness at the Gate-3 version."""

    KEYS: ClassVar[tuple[str, ...]] = (
        "reference_workload_ref",
        "provider_target_ref",
        "admitted_collection_locator",
        "effect_proof_locator",
        "reference_workload_binary_digest",
        "reference_code_digest",
        "source_contract_ref",
        "implementation_kind",
        "native_request_projection",
        "native_request_digest",
        "native_to_canonical_projection_algorithm_digest",
        "canonical_query_projection",
        "canonical_query_projection_digest",
        "retrieved_at_utc",
        "result_status",
        "row_count",
        "row_universe_digest",
        "normalized_fact_set_digest",
        "reference_run_digest",
        "gate3_certification_fingerprint",
    )

    reference_workload_ref: str
    provider_target_ref: str
    admitted_collection_locator: ArtifactLocator
    effect_proof_locator: ArtifactLocator
    reference_workload_binary_digest: str
    reference_code_digest: str
    source_contract_ref: str
    implementation_kind: str
    native_request_projection: NativeRequestProjection
    native_request_digest: str
    native_to_canonical_projection_algorithm_digest: str
    canonical_query_projection: CanonicalQueryContract
    canonical_query_projection_digest: str
    retrieved_at_utc: str
    result_status: str
    row_count: int
    row_universe_digest: str
    normalized_fact_set_digest: str
    reference_run_digest: str
    gate3_certification_fingerprint: Gate3CertificationFingerprint

    def __post_init__(self) -> None:
        label = "reference_execution"
        if self.reference_workload_ref != REFERENCE_WORKLOAD_REF:
            raise Bundle7BDefectError(
                "fixed_member_mismatch",
                f"{label}.reference_workload_ref: must be {REFERENCE_WORKLOAD_REF!r}",
            )
        for name in _REFERENCE_DIGESTS:
            sha256_member(getattr(self, name), label=f"{label}.{name}")
        kind = self.implementation_kind
        if not isinstance(kind, str) or kind not in _IMPLEMENTATION_KINDS:
            raise Bundle7BDefectError(
                "malformed_member", f"{label}.implementation_kind: official_sdk or direct_rest"
            )
        hyphen_ref(
            self.source_contract_ref,
            prefixes=frozenset({"api-version"}),
            label=f"{label}.source_contract_ref",
        )
        fingerprint = self.gate3_certification_fingerprint
        require_member(
            fingerprint,
            Gate3CertificationFingerprint,
            label=f"{label}.gate3_certification_fingerprint",
        )
        if self.source_contract_ref != "api-version:" + fingerprint.selected_meta_api_version:
            raise Bundle7BDefectError(
                "source_contract_mismatch", f"{label}.source_contract_ref: must copy the version"
            )
        _check_common_execution(self, label=label)

    def to_dict(self) -> dict[str, Any]:
        return _execution_dict(self, self.KEYS)

    @classmethod
    def from_dict(cls, data: object) -> ReferenceExecution:
        label = "reference_execution"
        mapping = closed(data, frozenset(cls.KEYS), label=label)
        own = ("reference_workload_ref", "source_contract_ref", "implementation_kind")
        return cls(
            **{name: mapping[name] for name in (*own, *_REFERENCE_DIGESTS)},
            **_parse_common_execution(mapping, label=label),
        )


_ROW_PAIRING_LITERALS: Final[Mapping[str, object]] = MappingProxyType(
    {
        "canonical_key": (
            "resource_ref,metric_date,resource_level,breakdown_signature,canonical_metric_ref"
        ),
        "aggregation_rule": "sum_by_canonical_fact_key_and_metric",
        "deduplication_rule": "canonical_fact_key_and_metric_unique",
        "maximum_retrieval_skew_seconds": MAXIMUM_RETRIEVAL_SKEW_SECONDS,
    }
)


@dataclass(frozen=True, slots=True)
class RowPairing:
    """The fixed ``row_pairing`` member: every value is an ADR literal."""

    KEYS: ClassVar[tuple[str, ...]] = tuple(_ROW_PAIRING_LITERALS)

    canonical_key: str = str(_ROW_PAIRING_LITERALS["canonical_key"])
    aggregation_rule: str = str(_ROW_PAIRING_LITERALS["aggregation_rule"])
    deduplication_rule: str = str(_ROW_PAIRING_LITERALS["deduplication_rule"])
    maximum_retrieval_skew_seconds: int = MAXIMUM_RETRIEVAL_SKEW_SECONDS

    def __post_init__(self) -> None:
        for name, literal in _ROW_PAIRING_LITERALS.items():
            value = getattr(self, name)
            if type(value) is not type(literal) or value != literal:
                raise Bundle7BDefectError(
                    "fixed_member_mismatch", f"row_pairing.{name}: must be {literal!r}"
                )

    def to_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in self.KEYS}

    @classmethod
    def from_dict(cls, data: object) -> RowPairing:
        mapping = closed(data, frozenset(cls.KEYS), label="row_pairing")
        return cls(**{name: mapping[name] for name in cls.KEYS})
