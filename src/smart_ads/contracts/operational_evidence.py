"""Closed operational-read evidence, algorithm provenance identity, and sanitized candidates (ADR-0001 §§6.1–6.3)."""
from __future__ import annotations

from dataclasses import dataclass
from itertools import pairwise
import re
from typing import Any, ClassVar, Final

from smart_ads.contracts.effects import (
    AuthorizationConsumptionRecord,
    AuthorizationReceipt,
    AuthorizationReservationRecord,
    EffectProof,
    ExecutionReceipt,
    _require_json_list,
    _require_locator_digest_pair,
    _safe_int,
    _sorted_locator_tuple,
    _split_p1_envelope,
    _strict_id,
    _strict_str,
    _typed_locator,
    _verify_p1_integrity,
)
from smart_ads.contracts.git_provenance import (
    GitArtifactProvenance,
    _validate_relative_posix_path,
    _validate_repository_slug,
)
from smart_ads.contracts.jcs import (
    ADR_P1_DOMAIN_PREFIXES,
    ArtifactLocator,
    P1Integrity,
    canonicalize_jcs,
    jcs_sha256,
)
from smart_ads.contracts.scalars import (
    ClosedValidationError,
    require_exact_keys,
    validate_hex40,
    validate_opaque_ref,
    validate_sha256_prefixed,
)
from smart_ads.contracts.schemas import (
    AdmittedCollection,
    AnalyticsLandingRow,
    CollectionResult,
)

_RUN_CONTEXT_SCHEMA: Final[str] = "smart_ads/migration_run_context/v1"
_REGISTRY_SNAPSHOT_SCHEMA: Final[str] = "smart_ads/private_registry_snapshot/v1"
_EXPECTED_INVENTORY_SCHEMA: Final[str] = "smart_ads/expected_resource_inventory/v1"
_SCHEMA_ID_RE: Final[re.Pattern[str]] = re.compile(
    r"\Asmart_ads/[a-z0-9_]+/v[1-9][0-9]*\Z"
)


def _resolve_set_digest(
    current: object,
    expected: str,
    *,
    field_name: str,
) -> str:
    raw = _strict_str(current, field_name=field_name)
    if raw == "":
        return expected
    validate_sha256_prefixed(raw, field_name=field_name)
    if raw != expected:
        raise ClosedValidationError(
            f"{field_name}: recomputed {expected!r} != asserted {raw!r}"
        )
    return raw


def _validate_candidate_rows(
    values: object,
    *,
    field_name: str,
) -> tuple[AnalyticsLandingRow, ...]:
    if not isinstance(values, (list, tuple)) or len(values) == 0:
        raise ClosedValidationError(
            f"{field_name}: expected non-empty list or tuple of AnalyticsLandingRow"
        )
    rows: list[AnalyticsLandingRow] = []
    sort_keys: list[bytes] = []
    currencies: set[str] = set()
    for idx, item in enumerate(values):
        if type(item) is not AnalyticsLandingRow:
            raise ClosedValidationError(
                f"{field_name}[{idx}]: expected AnalyticsLandingRow"
            )
        fresh = AnalyticsLandingRow.from_dict(item.to_dict())
        rows.append(fresh)
        sort_keys.append(fresh.candidate_sort_key_jcs())
        if fresh.value_type == "int64_minor_currency" and fresh.currency is not None:
            currencies.add(fresh.currency)
    if len(currencies) > 1:
        raise ClosedValidationError(
            f"{field_name}: multiple currencies across candidate rows are forbidden"
        )
    if any(left >= right for left, right in pairwise(sort_keys)):
        raise ClosedValidationError(
            f"{field_name}: candidates must be strictly increasing and unique on K"
        )
    return tuple(rows)


@dataclass(frozen=True, slots=True)
class AlgorithmProvenanceIdentity:
    """Closed 10-member algorithm provenance identity (ADR-0001 §6.2 L1594–1596)."""

    KEYS: ClassVar[frozenset[str]] = frozenset(
        {
            "algorithm_id",
            "algorithm_version",
            "git_artifact_provenance_locator",
            "repository",
            "commit_sha",
            "path",
            "git_blob_oid",
            "file_content_sha256",
            "runtime_abi",
            "schema_id",
        }
    )

    algorithm_id: str
    algorithm_version: str
    git_artifact_provenance_locator: ArtifactLocator
    repository: str
    commit_sha: str
    path: str
    git_blob_oid: str
    file_content_sha256: str
    runtime_abi: str
    schema_id: str

    def __post_init__(self) -> None:
        label = "algorithm_provenance_identity"
        validate_opaque_ref(
            _strict_str(self.algorithm_id, field_name=f"{label}.algorithm_id"),
            field_name=f"{label}.algorithm_id",
            expected_prefix="algorithm",
        )
        _strict_id(self.algorithm_version, field_name=f"{label}.algorithm_version")
        _typed_locator(
            self.git_artifact_provenance_locator,
            field_name=f"{label}.git_artifact_provenance_locator",
            expected_type=GitArtifactProvenance.SCHEMA,
        )
        _validate_repository_slug(self.repository, field_name=f"{label}.repository")
        validate_hex40(_strict_str(self.commit_sha, field_name=f"{label}.commit_sha"), field_name=f"{label}.commit_sha")
        _validate_relative_posix_path(self.path, field_name=f"{label}.path")
        validate_hex40(_strict_str(self.git_blob_oid, field_name=f"{label}.git_blob_oid"), field_name=f"{label}.git_blob_oid")
        validate_sha256_prefixed(_strict_str(self.file_content_sha256, field_name=f"{label}.file_content_sha256"), field_name=f"{label}.file_content_sha256")
        if _strict_str(self.runtime_abi, field_name=f"{label}.runtime_abi") != "cpython-3.12":
            raise ClosedValidationError(f"{label}.runtime_abi: must equal 'cpython-3.12'")
        sid = _strict_str(self.schema_id, field_name=f"{label}.schema_id")
        if _SCHEMA_ID_RE.fullmatch(sid) is None:
            raise ClosedValidationError(f"{label}.schema_id: invalid schema identifier {sid!r}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "algorithm_id": self.algorithm_id,
            "algorithm_version": self.algorithm_version,
            "git_artifact_provenance_locator": self.git_artifact_provenance_locator.to_dict(),
            "repository": self.repository,
            "commit_sha": self.commit_sha,
            "path": self.path,
            "git_blob_oid": self.git_blob_oid,
            "file_content_sha256": self.file_content_sha256,
            "runtime_abi": self.runtime_abi,
            "schema_id": self.schema_id,
        }

    @classmethod
    def from_dict(cls, data: object) -> AlgorithmProvenanceIdentity:
        m = require_exact_keys(data, cls.KEYS, label="algorithm_provenance_identity")
        return cls(
            algorithm_id=m["algorithm_id"],
            algorithm_version=m["algorithm_version"],
            git_artifact_provenance_locator=ArtifactLocator.from_dict(
                m["git_artifact_provenance_locator"],
                expected_type=GitArtifactProvenance.SCHEMA,
            ),
            repository=m["repository"],
            commit_sha=m["commit_sha"],
            path=m["path"],
            git_blob_oid=m["git_blob_oid"],
            file_content_sha256=m["file_content_sha256"],
            runtime_abi=m["runtime_abi"],
            schema_id=m["schema_id"],
        )


@dataclass(frozen=True, slots=True)
class OperationalReadEvidence:
    """Closed P1 `smart_ads/operational_read_evidence/v1` envelope (ADR-0001 §§6.3, 12.7)."""

    SCHEMA: ClassVar[str] = "smart_ads/operational_read_evidence/v1"
    P1_DOMAIN_PREFIX: ClassVar[str] = ADR_P1_DOMAIN_PREFIXES[SCHEMA]
    CORE_KEYS: ClassVar[frozenset[str]] = frozenset(
        {
            "$schema",
            "migration_run_context_locator",
            "tenant_ref",
            "binding_ref",
            "account_ref",
            "resource_scope_ref",
            "canonical_query_digest",
            "registry_snapshot_locator",
            "registry_snapshot_digest",
            "expected_resource_inventory_locator",
            "admitted_collection_locator",
            "admitted_collection_digest",
            "collection_result_locator",
            "collection_result_digest",
            "normalized_fact_set_digest",
            "authorization_locator",
            "reservation_locator",
            "execution_locator",
            "consumption_locator",
            "effect_proof_locator",
        }
    )
    KEYS: ClassVar[frozenset[str]] = CORE_KEYS | {"integrity"}

    migration_run_context_locator: ArtifactLocator
    tenant_ref: str
    binding_ref: str
    account_ref: str
    resource_scope_ref: str
    canonical_query_digest: str
    registry_snapshot_locator: ArtifactLocator
    registry_snapshot_digest: str
    expected_resource_inventory_locator: ArtifactLocator
    admitted_collection_locator: ArtifactLocator
    admitted_collection_digest: str
    collection_result_locator: ArtifactLocator
    collection_result_digest: str
    normalized_fact_set_digest: str
    authorization_locator: ArtifactLocator
    reservation_locator: ArtifactLocator
    execution_locator: ArtifactLocator
    consumption_locator: ArtifactLocator
    effect_proof_locator: ArtifactLocator
    integrity: P1Integrity | None = None

    def __post_init__(self) -> None:
        label = "operational_read_evidence"
        _typed_locator(self.migration_run_context_locator, field_name=f"{label}.migration_run_context_locator", expected_type=_RUN_CONTEXT_SCHEMA)
        validate_opaque_ref(_strict_str(self.tenant_ref, field_name=f"{label}.tenant_ref"), field_name=f"{label}.tenant_ref", expected_prefix="tenant")
        validate_opaque_ref(_strict_str(self.binding_ref, field_name=f"{label}.binding_ref"), field_name=f"{label}.binding_ref", expected_prefix="binding")
        validate_opaque_ref(_strict_str(self.account_ref, field_name=f"{label}.account_ref"), field_name=f"{label}.account_ref", expected_prefix="account")
        validate_opaque_ref(_strict_str(self.resource_scope_ref, field_name=f"{label}.resource_scope_ref"), field_name=f"{label}.resource_scope_ref", expected_prefix="scope")
        validate_sha256_prefixed(_strict_str(self.canonical_query_digest, field_name=f"{label}.canonical_query_digest"), field_name=f"{label}.canonical_query_digest")
        _require_locator_digest_pair(self.registry_snapshot_locator, self.registry_snapshot_digest, expected_type=_REGISTRY_SNAPSHOT_SCHEMA, loc_field=f"{label}.registry_snapshot_locator", digest_field=f"{label}.registry_snapshot_digest")
        _typed_locator(self.expected_resource_inventory_locator, field_name=f"{label}.expected_resource_inventory_locator", expected_type=_EXPECTED_INVENTORY_SCHEMA)
        _require_locator_digest_pair(self.admitted_collection_locator, self.admitted_collection_digest, expected_type=AdmittedCollection.SCHEMA, loc_field=f"{label}.admitted_collection_locator", digest_field=f"{label}.admitted_collection_digest")
        _require_locator_digest_pair(self.collection_result_locator, self.collection_result_digest, expected_type=CollectionResult.SCHEMA, loc_field=f"{label}.collection_result_locator", digest_field=f"{label}.collection_result_digest")
        validate_sha256_prefixed(_strict_str(self.normalized_fact_set_digest, field_name=f"{label}.normalized_fact_set_digest"), field_name=f"{label}.normalized_fact_set_digest")
        _typed_locator(self.authorization_locator, field_name=f"{label}.authorization_locator", expected_type=AuthorizationReceipt.SCHEMA)
        _typed_locator(self.reservation_locator, field_name=f"{label}.reservation_locator", expected_type=AuthorizationReservationRecord.SCHEMA)
        _typed_locator(self.execution_locator, field_name=f"{label}.execution_locator", expected_type=ExecutionReceipt.SCHEMA)
        _typed_locator(self.consumption_locator, field_name=f"{label}.consumption_locator", expected_type=AuthorizationConsumptionRecord.SCHEMA)
        _typed_locator(self.effect_proof_locator, field_name=f"{label}.effect_proof_locator", expected_type=EffectProof.SCHEMA)
        _verify_p1_integrity(self.integrity, self.to_dict, label=label)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "$schema": self.SCHEMA,
            "migration_run_context_locator": self.migration_run_context_locator.to_dict(),
            "tenant_ref": self.tenant_ref,
            "binding_ref": self.binding_ref,
            "account_ref": self.account_ref,
            "resource_scope_ref": self.resource_scope_ref,
            "canonical_query_digest": self.canonical_query_digest,
            "registry_snapshot_locator": self.registry_snapshot_locator.to_dict(),
            "registry_snapshot_digest": self.registry_snapshot_digest,
            "expected_resource_inventory_locator": self.expected_resource_inventory_locator.to_dict(),
            "admitted_collection_locator": self.admitted_collection_locator.to_dict(),
            "admitted_collection_digest": self.admitted_collection_digest,
            "collection_result_locator": self.collection_result_locator.to_dict(),
            "collection_result_digest": self.collection_result_digest,
            "normalized_fact_set_digest": self.normalized_fact_set_digest,
            "authorization_locator": self.authorization_locator.to_dict(),
            "reservation_locator": self.reservation_locator.to_dict(),
            "execution_locator": self.execution_locator.to_dict(),
            "consumption_locator": self.consumption_locator.to_dict(),
            "effect_proof_locator": self.effect_proof_locator.to_dict(),
        }
        if self.integrity is not None:
            out["integrity"] = self.integrity.to_dict()
        return out

    @classmethod
    def from_dict(cls, data: object, *, require_signed: bool = False) -> OperationalReadEvidence:
        m, integrity = _split_p1_envelope(data, core_keys=cls.CORE_KEYS, schema=cls.SCHEMA, label="operational_read_evidence", require_signed=require_signed)
        return cls(
            migration_run_context_locator=ArtifactLocator.from_dict(m["migration_run_context_locator"], expected_type=_RUN_CONTEXT_SCHEMA),
            tenant_ref=m["tenant_ref"],
            binding_ref=m["binding_ref"],
            account_ref=m["account_ref"],
            resource_scope_ref=m["resource_scope_ref"],
            canonical_query_digest=m["canonical_query_digest"],
            registry_snapshot_locator=ArtifactLocator.from_dict(m["registry_snapshot_locator"], expected_type=_REGISTRY_SNAPSHOT_SCHEMA),
            registry_snapshot_digest=m["registry_snapshot_digest"],
            expected_resource_inventory_locator=ArtifactLocator.from_dict(m["expected_resource_inventory_locator"], expected_type=_EXPECTED_INVENTORY_SCHEMA),
            admitted_collection_locator=ArtifactLocator.from_dict(m["admitted_collection_locator"], expected_type=AdmittedCollection.SCHEMA),
            admitted_collection_digest=m["admitted_collection_digest"],
            collection_result_locator=ArtifactLocator.from_dict(m["collection_result_locator"], expected_type=CollectionResult.SCHEMA),
            collection_result_digest=m["collection_result_digest"],
            normalized_fact_set_digest=m["normalized_fact_set_digest"],
            authorization_locator=ArtifactLocator.from_dict(m["authorization_locator"], expected_type=AuthorizationReceipt.SCHEMA),
            reservation_locator=ArtifactLocator.from_dict(m["reservation_locator"], expected_type=AuthorizationReservationRecord.SCHEMA),
            execution_locator=ArtifactLocator.from_dict(m["execution_locator"], expected_type=ExecutionReceipt.SCHEMA),
            consumption_locator=ArtifactLocator.from_dict(m["consumption_locator"], expected_type=AuthorizationConsumptionRecord.SCHEMA),
            effect_proof_locator=ArtifactLocator.from_dict(m["effect_proof_locator"], expected_type=EffectProof.SCHEMA),
            integrity=integrity,
        )

    def locator(self) -> ArtifactLocator:
        return ArtifactLocator.for_canonical_bytes(self.SCHEMA, canonicalize_jcs(self.to_dict()))


@dataclass(frozen=True, slots=True)
class SanitizedCandidateFactSet:
    """Closed P1 `smart_ads/sanitized_candidate_fact_set/v1` envelope (ADR-0001 §6.2)."""

    SCHEMA: ClassVar[str] = "smart_ads/sanitized_candidate_fact_set/v1"
    P1_DOMAIN_PREFIX: ClassVar[str] = ADR_P1_DOMAIN_PREFIXES[SCHEMA]
    CORE_KEYS: ClassVar[frozenset[str]] = frozenset(
        {
            "$schema",
            "migration_run_context_locator",
            "sanitization_algorithm_identity",
            "source_collection_result_locators",
            "source_collection_result_set_digest",
            "operational_read_evidence_locators",
            "operational_read_evidence_set_digest",
            "candidates",
            "candidate_count",
        }
    )
    KEYS: ClassVar[frozenset[str]] = CORE_KEYS | {"integrity"}

    migration_run_context_locator: ArtifactLocator
    sanitization_algorithm_identity: AlgorithmProvenanceIdentity
    source_collection_result_locators: tuple[ArtifactLocator, ...]
    operational_read_evidence_locators: tuple[ArtifactLocator, ...]
    candidates: tuple[AnalyticsLandingRow, ...]
    candidate_count: int | None = None
    source_collection_result_set_digest: str = ""
    operational_read_evidence_set_digest: str = ""
    integrity: P1Integrity | None = None

    def __post_init__(self) -> None:
        label = "sanitized_candidate_fact_set"
        _typed_locator(self.migration_run_context_locator, field_name=f"{label}.migration_run_context_locator", expected_type=_RUN_CONTEXT_SCHEMA)
        if type(self.sanitization_algorithm_identity) is not AlgorithmProvenanceIdentity:
            raise ClosedValidationError(f"{label}.sanitization_algorithm_identity: expected AlgorithmProvenanceIdentity")
        AlgorithmProvenanceIdentity.from_dict(self.sanitization_algorithm_identity.to_dict())
        src_locs = _sorted_locator_tuple(self.source_collection_result_locators, field_name=f"{label}.source_collection_result_locators", expected_type=CollectionResult.SCHEMA, allow_empty=False)
        ev_locs = _sorted_locator_tuple(self.operational_read_evidence_locators, field_name=f"{label}.operational_read_evidence_locators", expected_type=OperationalReadEvidence.SCHEMA, allow_empty=False)
        if len(src_locs) != len(ev_locs):
            raise ClosedValidationError(f"{label}: 1-to-1 bijection requires equal source result and operational evidence counts")
        object.__setattr__(self, "source_collection_result_locators", src_locs)
        object.__setattr__(self, "operational_read_evidence_locators", ev_locs)
        src_digest = _resolve_set_digest(self.source_collection_result_set_digest, jcs_sha256([loc.to_dict() for loc in src_locs]), field_name=f"{label}.source_collection_result_set_digest")
        ev_digest = _resolve_set_digest(self.operational_read_evidence_set_digest, jcs_sha256([loc.to_dict() for loc in ev_locs]), field_name=f"{label}.operational_read_evidence_set_digest")
        object.__setattr__(self, "source_collection_result_set_digest", src_digest)
        object.__setattr__(self, "operational_read_evidence_set_digest", ev_digest)
        rows = _validate_candidate_rows(self.candidates, field_name=f"{label}.candidates")
        object.__setattr__(self, "candidates", rows)
        if self.candidate_count is None:
            object.__setattr__(self, "candidate_count", len(rows))
        elif _safe_int(self.candidate_count, field_name=f"{label}.candidate_count", minimum=1) != len(rows):
            raise ClosedValidationError(f"{label}.candidate_count: expected {len(rows)}, got {self.candidate_count}")
        _verify_p1_integrity(self.integrity, self.to_dict, label=label)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "$schema": self.SCHEMA,
            "migration_run_context_locator": self.migration_run_context_locator.to_dict(),
            "sanitization_algorithm_identity": self.sanitization_algorithm_identity.to_dict(),
            "source_collection_result_locators": [loc.to_dict() for loc in self.source_collection_result_locators],
            "source_collection_result_set_digest": self.source_collection_result_set_digest,
            "operational_read_evidence_locators": [loc.to_dict() for loc in self.operational_read_evidence_locators],
            "operational_read_evidence_set_digest": self.operational_read_evidence_set_digest,
            "candidates": [row.to_dict() for row in self.candidates],
            "candidate_count": self.candidate_count,
        }
        if self.integrity is not None:
            out["integrity"] = self.integrity.to_dict()
        return out

    @classmethod
    def from_dict(cls, data: object, *, require_signed: bool = False) -> SanitizedCandidateFactSet:
        m, integrity = _split_p1_envelope(data, core_keys=cls.CORE_KEYS, schema=cls.SCHEMA, label="sanitized_candidate_fact_set", require_signed=require_signed)
        raw_src = _require_json_list(m, "source_collection_result_locators", label="sanitized_candidate_fact_set")
        raw_ev = _require_json_list(m, "operational_read_evidence_locators", label="sanitized_candidate_fact_set")
        raw_cands = _require_json_list(m, "candidates", label="sanitized_candidate_fact_set")
        src_digest = validate_sha256_prefixed(_strict_str(m["source_collection_result_set_digest"], field_name="sanitized_candidate_fact_set.source_collection_result_set_digest"), field_name="sanitized_candidate_fact_set.source_collection_result_set_digest")
        ev_digest = validate_sha256_prefixed(_strict_str(m["operational_read_evidence_set_digest"], field_name="sanitized_candidate_fact_set.operational_read_evidence_set_digest"), field_name="sanitized_candidate_fact_set.operational_read_evidence_set_digest")
        count = _safe_int(m["candidate_count"], field_name="sanitized_candidate_fact_set.candidate_count", minimum=1)
        return cls(
            migration_run_context_locator=ArtifactLocator.from_dict(m["migration_run_context_locator"], expected_type=_RUN_CONTEXT_SCHEMA),
            sanitization_algorithm_identity=AlgorithmProvenanceIdentity.from_dict(m["sanitization_algorithm_identity"]),
            source_collection_result_locators=tuple(ArtifactLocator.from_dict(r, expected_type=CollectionResult.SCHEMA) for r in raw_src),
            source_collection_result_set_digest=src_digest,
            operational_read_evidence_locators=tuple(ArtifactLocator.from_dict(e, expected_type=OperationalReadEvidence.SCHEMA) for e in raw_ev),
            operational_read_evidence_set_digest=ev_digest,
            candidates=tuple(AnalyticsLandingRow.from_dict(c) for c in raw_cands),
            candidate_count=count,
            integrity=integrity,
        )

    def locator(self) -> ArtifactLocator:
        return ArtifactLocator.for_canonical_bytes(self.SCHEMA, canonicalize_jcs(self.to_dict()))


__all__ = [
    "AlgorithmProvenanceIdentity",
    "OperationalReadEvidence",
    "SanitizedCandidateFactSet",
]
