"""Closed legacy seam contract, protected release lineage, parity record, and wheel locator (ADR-0001 §§9.2, 10, 12.6)."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from itertools import pairwise
import re
from typing import Any, ClassVar, Final

from smart_ads.contracts.effects import (
    _P1EnvelopeBase, _SubjectBase, _require_json_list, _require_locator_digest_pair, _safe_int,
    _split_p1_envelope, _strict_id, _strict_str, _typed_locator, _verify_p1_integrity, validate_cell_object_ref,
)
from smart_ads.contracts.git_provenance import GitArtifactProvenance, _validate_relative_posix_path
from smart_ads.contracts.jcs import ADR_P1_DOMAIN_PREFIXES, ArtifactLocator, P1Integrity, jcs_sha256
from smart_ads.contracts.operational_evidence import AlgorithmProvenanceIdentity
from smart_ads.contracts.scalars import (
    ClosedValidationError, require_exact_keys, validate_envelope_timestamp_utc,
    validate_hex40, validate_opaque_ref, validate_sha256_prefixed,
)

_RUN_CONTEXT_SCHEMA: Final[str] = "smart_ads/migration_run_context/v1"
_DECOMP_MANIFEST_SCHEMA: Final[str] = "smart_ads/decomposition_manifest/v1"
_DECOMP_HEAD_SCHEMA: Final[str] = "smart_ads/decomposition_manifest_head/v1"
_PROTECTED_MERGE_SCHEMA: Final[str] = "smart_ads/protected_merge_evidence/v1"
_WHEEL_PROVENANCE_SCHEMA: Final[str] = "smart_ads/wheel_build_provenance/v1"
_LEGACY_REPOSITORY: Final[str] = "mbras-tech/mbras-campaigns"
_LEGACY_BASELINE_COMMIT: Final[str] = "d26c73d8508c7c3d43161fe36a80c44a46bf0f2d"
_LEGACY_BASELINE_TREE: Final[str] = "68ff6d6dbd6d7ecaafa3bca7d5de85a54d705798"
_SCHEMA_REF_RE: Final[re.Pattern[str]] = re.compile(r"\Asmart_ads/[a-z0-9_]+/v[1-9][0-9]*\Z")


def _validate_schema_ref(value: object, *, field_name: str) -> str:
    checked = _strict_str(value, field_name=field_name)
    if _SCHEMA_REF_RE.fullmatch(checked) is None:
        raise ClosedValidationError(f"{field_name}: invalid schema ref {checked!r}")
    return checked


def _resolve_digest_or_default(current: object, expected: str, *, field_name: str) -> str:
    raw = _strict_str(current, field_name=field_name)
    if raw == "":
        return expected
    validate_sha256_prefixed(raw, field_name=field_name)
    if raw != expected:
        raise ClosedValidationError(f"{field_name}: recomputed {expected!r} != asserted {raw!r}")
    return raw


def _sorted_unique_by_surface_id(
    values: object, cls: type[Any], *, field_name: str
) -> tuple[Any, ...]:
    if not isinstance(values, (list, tuple)) or len(values) == 0:
        raise ClosedValidationError(f"{field_name}: expected non-empty list or tuple of {cls.__name__}")
    out: list[Any] = []
    keys: list[bytes] = []
    for idx, item in enumerate(values):
        if type(item) is not cls:
            raise ClosedValidationError(f"{field_name}[{idx}]: expected {cls.__name__}")
        fresh = cls.from_dict(item.to_dict())
        out.append(fresh)
        keys.append(fresh.surface_id.encode("utf-8"))
    if any(left >= right for left, right in pairwise(keys)):
        raise ClosedValidationError(f"{field_name}: elements must be strictly sorted and unique by surface_id")
    return tuple(out)


def _validate_parent_edge_chain(
    values: object, *, release_sha: str, baseline_sha: str, field_name: str
) -> tuple[GitParentEdge, ...]:
    if not isinstance(values, (list, tuple)) or len(values) == 0:
        raise ClosedValidationError(f"{field_name}: expected non-empty list or tuple of GitParentEdge")
    edges: list[GitParentEdge] = []
    for idx, item in enumerate(values):
        if type(item) is not GitParentEdge:
            raise ClosedValidationError(f"{field_name}[{idx}]: expected GitParentEdge")
        edges.append(GitParentEdge.from_dict(item.to_dict()))
    if edges[0].child_sha != release_sha or edges[-1].parent_sha != baseline_sha:
        raise ClosedValidationError(f"{field_name}: chain must walk from protected release commit to baseline commit")
    if any(left.parent_sha != right.child_sha for left, right in pairwise(edges)):
        raise ClosedValidationError(f"{field_name}: adjacent parent_sha -> child_sha discontinuity")
    vertices = [edges[0].child_sha, *(e.parent_sha for e in edges)]
    if len(set(vertices)) != len(vertices):
        raise ClosedValidationError(f"{field_name}: duplicate commit or cycle in parent_edge_chain")
    return tuple(edges)


@dataclass(frozen=True, slots=True)
class WheelObjectLocator:
    """Closed 5-member `smart_ads/wheel_object_locator/v1` embedded binary locator."""

    SCHEMA: ClassVar[str] = "smart_ads/wheel_object_locator/v1"
    KEYS: ClassVar[frozenset[str]] = frozenset({"$schema", "store_kind", "object_ref", "wheel_digest", "size_bytes"})

    wheel_digest: str
    size_bytes: int
    store_kind: str = "cell_immutable_object"
    object_ref: str = ""

    def __post_init__(self) -> None:
        label = "wheel_object_locator"
        sha = validate_sha256_prefixed(_strict_str(self.wheel_digest, field_name=f"{label}.wheel_digest"), field_name=f"{label}.wheel_digest")
        _safe_int(self.size_bytes, field_name=f"{label}.size_bytes", minimum=1)
        if _strict_str(self.store_kind, field_name=f"{label}.store_kind") != "cell_immutable_object":
            raise ClosedValidationError(f"{label}.store_kind: must equal 'cell_immutable_object'")
        expected_ref = f"cell-object:{sha}"
        raw_ref = _strict_str(self.object_ref, field_name=f"{label}.object_ref")
        if raw_ref == "":
            object.__setattr__(self, "object_ref", expected_ref)
        elif raw_ref != expected_ref:
            raise ClosedValidationError(f"{label}.object_ref: expected {expected_ref!r}, got {raw_ref!r}")

    @classmethod
    def for_wheel_bytes(cls, raw_bytes: bytes) -> WheelObjectLocator:
        """Build a `WheelObjectLocator` over raw immutable wheel bytes."""
        if type(raw_bytes) is not bytes or len(raw_bytes) == 0:
            raise ClosedValidationError("raw_bytes: expected non-empty bytes")
        digest = "sha256:" + hashlib.sha256(raw_bytes).hexdigest()
        return cls(wheel_digest=digest, size_bytes=len(raw_bytes), object_ref=f"cell-object:{digest}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "$schema": self.SCHEMA, "store_kind": self.store_kind, "object_ref": self.object_ref,
            "wheel_digest": self.wheel_digest, "size_bytes": self.size_bytes,
        }

    @classmethod
    def from_dict(cls, data: object) -> WheelObjectLocator:
        m = require_exact_keys(data, cls.KEYS, label="wheel_object_locator")
        if type(m["$schema"]) is not str or m["$schema"] != cls.SCHEMA:
            raise ClosedValidationError(f"wheel_object_locator.$schema: expected {cls.SCHEMA!r}")
        return cls(
            wheel_digest=m["wheel_digest"], size_bytes=m["size_bytes"], store_kind=m["store_kind"],
            object_ref=validate_cell_object_ref(m["object_ref"], field_name="wheel_object_locator.object_ref"),
        )


@dataclass(frozen=True, slots=True)
class LegacyBaselineIdentity(_SubjectBase):
    """Pinned legacy baseline Git identity (`d26c73d8508c7c3d43161fe36a80c44a46bf0f2d`)."""

    KEYS: ClassVar[frozenset[str]] = frozenset({"repository", "commit_sha", "source_tree_oid"})

    repository: str = _LEGACY_REPOSITORY
    commit_sha: str = _LEGACY_BASELINE_COMMIT
    source_tree_oid: str = _LEGACY_BASELINE_TREE

    def __post_init__(self) -> None:
        label = "legacy_baseline_identity"
        if _strict_str(self.repository, field_name=f"{label}.repository") != _LEGACY_REPOSITORY:
            raise ClosedValidationError(f"{label}.repository: must equal {_LEGACY_REPOSITORY!r}")
        if _strict_str(self.commit_sha, field_name=f"{label}.commit_sha") != _LEGACY_BASELINE_COMMIT:
            raise ClosedValidationError(f"{label}.commit_sha: must equal {_LEGACY_BASELINE_COMMIT!r}")
        if _strict_str(self.source_tree_oid, field_name=f"{label}.source_tree_oid") != _LEGACY_BASELINE_TREE:
            raise ClosedValidationError(f"{label}.source_tree_oid: must equal {_LEGACY_BASELINE_TREE!r}")

    @classmethod
    def from_dict(cls, data: object) -> LegacyBaselineIdentity:
        m = require_exact_keys(data, cls.KEYS, label="legacy_baseline_identity")
        return cls(repository=m["repository"], commit_sha=m["commit_sha"], source_tree_oid=m["source_tree_oid"])


@dataclass(frozen=True, slots=True)
class GitReleaseIdentity(_SubjectBase):
    """Closed 3-member protected legacy Git release identity."""

    KEYS: ClassVar[frozenset[str]] = frozenset({"repository", "commit_sha", "tree_oid"})

    repository: str
    commit_sha: str
    tree_oid: str

    def __post_init__(self) -> None:
        label = "git_release_identity"
        if _strict_str(self.repository, field_name=f"{label}.repository") != _LEGACY_REPOSITORY:
            raise ClosedValidationError(f"{label}.repository: must equal {_LEGACY_REPOSITORY!r}")
        validate_hex40(_strict_str(self.commit_sha, field_name=f"{label}.commit_sha"), field_name=f"{label}.commit_sha")
        validate_hex40(_strict_str(self.tree_oid, field_name=f"{label}.tree_oid"), field_name=f"{label}.tree_oid")

    @classmethod
    def from_dict(cls, data: object) -> GitReleaseIdentity:
        m = require_exact_keys(data, cls.KEYS, label="git_release_identity")
        return cls(repository=m["repository"], commit_sha=m["commit_sha"], tree_oid=m["tree_oid"])


@dataclass(frozen=True, slots=True)
class GitParentEdge(_SubjectBase):
    """Closed 3-member Git commit parent lineage edge."""

    KEYS: ClassVar[frozenset[str]] = frozenset({"child_sha", "parent_sha", "child_commit_object_ref"})

    child_sha: str
    parent_sha: str
    child_commit_object_ref: str

    def __post_init__(self) -> None:
        label = "git_parent_edge"
        c_sha = validate_hex40(_strict_str(self.child_sha, field_name=f"{label}.child_sha"), field_name=f"{label}.child_sha")
        p_sha = validate_hex40(_strict_str(self.parent_sha, field_name=f"{label}.parent_sha"), field_name=f"{label}.parent_sha")
        if c_sha == p_sha:
            raise ClosedValidationError(f"{label}: parent_sha must differ from child_sha")
        validate_cell_object_ref(self.child_commit_object_ref, field_name=f"{label}.child_commit_object_ref")

    @classmethod
    def from_dict(cls, data: object) -> GitParentEdge:
        m = require_exact_keys(data, cls.KEYS, label="git_parent_edge")
        return cls(child_sha=m["child_sha"], parent_sha=m["parent_sha"], child_commit_object_ref=m["child_commit_object_ref"])


@dataclass(frozen=True, slots=True)
class SeamGitArtifactRef(_SubjectBase):
    """Closed 4-member Git artifact reference binding path, blob OID, SHA-256, and provenance locator."""

    KEYS: ClassVar[frozenset[str]] = frozenset({"source_path", "git_blob_oid", "file_content_sha256", "git_provenance_locator"})

    source_path: str
    git_blob_oid: str
    file_content_sha256: str
    git_provenance_locator: ArtifactLocator

    def __post_init__(self) -> None:
        label = "seam_git_artifact_ref"
        _validate_relative_posix_path(self.source_path, field_name=f"{label}.source_path")
        validate_hex40(_strict_str(self.git_blob_oid, field_name=f"{label}.git_blob_oid"), field_name=f"{label}.git_blob_oid")
        validate_sha256_prefixed(_strict_str(self.file_content_sha256, field_name=f"{label}.file_content_sha256"), field_name=f"{label}.file_content_sha256")
        _typed_locator(self.git_provenance_locator, field_name=f"{label}.git_provenance_locator", expected_type=GitArtifactProvenance.SCHEMA)

    @classmethod
    def from_dict(cls, data: object) -> SeamGitArtifactRef:
        m = require_exact_keys(data, cls.KEYS, label="seam_git_artifact_ref")
        return cls(
            source_path=m["source_path"], git_blob_oid=m["git_blob_oid"], file_content_sha256=m["file_content_sha256"],
            git_provenance_locator=ArtifactLocator.from_dict(m["git_provenance_locator"], expected_type=GitArtifactProvenance.SCHEMA),
        )


@dataclass(frozen=True, slots=True)
class CompatibilitySurfaceSpec(_SubjectBase):
    """Closed 4-member legacy-to-canonical compatibility surface specification."""

    KEYS: ClassVar[frozenset[str]] = frozenset({"surface_id", "producer_schema_ref", "consumer_schema_ref", "mapping_contract_ref"})

    surface_id: str
    producer_schema_ref: str
    consumer_schema_ref: str
    mapping_contract_ref: str

    def __post_init__(self) -> None:
        label = "compatibility_surface_spec"
        _strict_id(self.surface_id, field_name=f"{label}.surface_id")
        _validate_schema_ref(self.producer_schema_ref, field_name=f"{label}.producer_schema_ref")
        _validate_schema_ref(self.consumer_schema_ref, field_name=f"{label}.consumer_schema_ref")
        validate_opaque_ref(_strict_str(self.mapping_contract_ref, field_name=f"{label}.mapping_contract_ref"), field_name=f"{label}.mapping_contract_ref", expected_prefix="mapping")

    @classmethod
    def from_dict(cls, data: object) -> CompatibilitySurfaceSpec:
        m = require_exact_keys(data, cls.KEYS, label="compatibility_surface_spec")
        return cls(
            surface_id=m["surface_id"], producer_schema_ref=m["producer_schema_ref"],
            consumer_schema_ref=m["consumer_schema_ref"], mapping_contract_ref=m["mapping_contract_ref"],
        )


@dataclass(frozen=True, slots=True)
class SurfaceParityComparison(_SubjectBase):
    """Closed 7-member surface parity comparison result."""

    KEYS: ClassVar[frozenset[str]] = frozenset(
        {"surface_id", "mapping_contract_ref", "case_set_digest", "case_count", "legacy_projection_digest", "canonical_projection_digest", "parity_matched"}
    )

    surface_id: str
    mapping_contract_ref: str
    case_set_digest: str
    case_count: int
    legacy_projection_digest: str
    canonical_projection_digest: str
    parity_matched: bool

    def __post_init__(self) -> None:
        label = "surface_parity_comparison"
        _strict_id(self.surface_id, field_name=f"{label}.surface_id")
        validate_opaque_ref(_strict_str(self.mapping_contract_ref, field_name=f"{label}.mapping_contract_ref"), field_name=f"{label}.mapping_contract_ref", expected_prefix="mapping")
        validate_sha256_prefixed(_strict_str(self.case_set_digest, field_name=f"{label}.case_set_digest"), field_name=f"{label}.case_set_digest")
        _safe_int(self.case_count, field_name=f"{label}.case_count", minimum=1)
        leg_d = validate_sha256_prefixed(_strict_str(self.legacy_projection_digest, field_name=f"{label}.legacy_projection_digest"), field_name=f"{label}.legacy_projection_digest")
        can_d = validate_sha256_prefixed(_strict_str(self.canonical_projection_digest, field_name=f"{label}.canonical_projection_digest"), field_name=f"{label}.canonical_projection_digest")
        if type(self.parity_matched) is not bool or self.parity_matched != (leg_d == can_d):
            raise ClosedValidationError(f"{label}.parity_matched: must be bool equal to (legacy_projection_digest == canonical_projection_digest)")

    @classmethod
    def from_dict(cls, data: object) -> SurfaceParityComparison:
        m = require_exact_keys(data, cls.KEYS, label="surface_parity_comparison")
        return cls(
            surface_id=m["surface_id"], mapping_contract_ref=m["mapping_contract_ref"],
            case_set_digest=m["case_set_digest"], case_count=m["case_count"],
            legacy_projection_digest=m["legacy_projection_digest"], canonical_projection_digest=m["canonical_projection_digest"],
            parity_matched=m["parity_matched"],
        )


@dataclass(frozen=True, slots=True)
class LegacySeamContract(_P1EnvelopeBase):
    """Closed P1 `smart_ads/legacy_seam_contract/v1` envelope (10 core + `integrity` = 11 keys)."""

    SCHEMA: ClassVar[str] = "smart_ads/legacy_seam_contract/v1"
    P1_DOMAIN_PREFIX: ClassVar[str] = ADR_P1_DOMAIN_PREFIXES[SCHEMA]
    CORE_KEYS: ClassVar[frozenset[str]] = frozenset(
        "$schema migration_run_context_locator baseline_identity protected_release_identity "
        "decomposition_manifest_locator decomposition_manifest_digest seam_git_provenance_locator "
        "seam_file_content_sha256 contract_version compatibility_surfaces".split()
    )
    KEYS: ClassVar[frozenset[str]] = CORE_KEYS | {"integrity"}

    migration_run_context_locator: ArtifactLocator
    baseline_identity: LegacyBaselineIdentity
    protected_release_identity: GitReleaseIdentity
    decomposition_manifest_locator: ArtifactLocator
    decomposition_manifest_digest: str
    seam_git_provenance_locator: ArtifactLocator
    seam_file_content_sha256: str
    contract_version: str
    compatibility_surfaces: tuple[CompatibilitySurfaceSpec, ...]
    integrity: P1Integrity | None = None

    def __post_init__(self) -> None:
        label = "legacy_seam_contract"
        _typed_locator(self.migration_run_context_locator, field_name=f"{label}.migration_run_context_locator", expected_type=_RUN_CONTEXT_SCHEMA)
        if type(self.baseline_identity) is not LegacyBaselineIdentity:
            raise ClosedValidationError(f"{label}.baseline_identity: expected LegacyBaselineIdentity")
        LegacyBaselineIdentity.from_dict(self.baseline_identity.to_dict())
        if type(self.protected_release_identity) is not GitReleaseIdentity:
            raise ClosedValidationError(f"{label}.protected_release_identity: expected GitReleaseIdentity")
        GitReleaseIdentity.from_dict(self.protected_release_identity.to_dict())
        _require_locator_digest_pair(
            self.decomposition_manifest_locator, self.decomposition_manifest_digest, expected_type=_DECOMP_MANIFEST_SCHEMA,
            loc_field=f"{label}.decomposition_manifest_locator", digest_field=f"{label}.decomposition_manifest_digest",
        )
        _typed_locator(self.seam_git_provenance_locator, field_name=f"{label}.seam_git_provenance_locator", expected_type=GitArtifactProvenance.SCHEMA)
        validate_sha256_prefixed(_strict_str(self.seam_file_content_sha256, field_name=f"{label}.seam_file_content_sha256"), field_name=f"{label}.seam_file_content_sha256")
        _strict_id(self.contract_version, field_name=f"{label}.contract_version")
        object.__setattr__(self, "compatibility_surfaces", _sorted_unique_by_surface_id(self.compatibility_surfaces, CompatibilitySurfaceSpec, field_name=f"{label}.compatibility_surfaces"))
        _verify_p1_integrity(self.integrity, self.to_dict, label=label)

    @classmethod
    def from_dict(cls, data: object, *, require_signed: bool = False) -> LegacySeamContract:
        m, integrity = _split_p1_envelope(data, core_keys=cls.CORE_KEYS, schema=cls.SCHEMA, label="legacy_seam_contract", require_signed=require_signed)
        raw_surfaces = _require_json_list(m, "compatibility_surfaces", label="legacy_seam_contract")
        return cls(
            migration_run_context_locator=ArtifactLocator.from_dict(m["migration_run_context_locator"], expected_type=_RUN_CONTEXT_SCHEMA),
            baseline_identity=LegacyBaselineIdentity.from_dict(m["baseline_identity"]),
            protected_release_identity=GitReleaseIdentity.from_dict(m["protected_release_identity"]),
            decomposition_manifest_locator=ArtifactLocator.from_dict(m["decomposition_manifest_locator"], expected_type=_DECOMP_MANIFEST_SCHEMA),
            decomposition_manifest_digest=m["decomposition_manifest_digest"],
            seam_git_provenance_locator=ArtifactLocator.from_dict(m["seam_git_provenance_locator"], expected_type=GitArtifactProvenance.SCHEMA),
            seam_file_content_sha256=m["seam_file_content_sha256"],
            contract_version=m["contract_version"],
            compatibility_surfaces=tuple(CompatibilitySurfaceSpec.from_dict(s) for s in raw_surfaces),
            integrity=integrity,
        )


@dataclass(frozen=True, slots=True)
class LegacySeamRelease(_P1EnvelopeBase):
    """Closed P1 `smart_ads/legacy_seam_release/v1` envelope (19 core + `integrity` = 20 keys)."""

    SCHEMA: ClassVar[str] = "smart_ads/legacy_seam_release/v1"
    P1_DOMAIN_PREFIX: ClassVar[str] = ADR_P1_DOMAIN_PREFIXES[SCHEMA]
    CORE_KEYS: ClassVar[frozenset[str]] = frozenset(
        "$schema migration_run_context_locator baseline_identity baseline_commit_object_ref "
        "decomposition_manifest_head_locator decomposition_manifest_locator decomposition_manifest_digest "
        "protected_release_identity parent_edge_chain parent_edge_chain_digest protected_ref pr_number "
        "reviewed_head_sha protected_merge_sha protected_merge_evidence_locator branch_policy_digest "
        "seam_git_artifact seam_contract_locator seam_contract_digest".split()
    )
    KEYS: ClassVar[frozenset[str]] = CORE_KEYS | {"integrity"}

    migration_run_context_locator: ArtifactLocator
    baseline_identity: LegacyBaselineIdentity
    baseline_commit_object_ref: str
    decomposition_manifest_head_locator: ArtifactLocator
    decomposition_manifest_locator: ArtifactLocator
    decomposition_manifest_digest: str
    protected_release_identity: GitReleaseIdentity
    parent_edge_chain: tuple[GitParentEdge, ...]
    protected_ref: str
    pr_number: int
    reviewed_head_sha: str
    protected_merge_sha: str
    protected_merge_evidence_locator: ArtifactLocator
    branch_policy_digest: str
    seam_git_artifact: SeamGitArtifactRef
    seam_contract_locator: ArtifactLocator
    seam_contract_digest: str
    parent_edge_chain_digest: str = ""
    integrity: P1Integrity | None = None

    def __post_init__(self) -> None:
        label = "legacy_seam_release"
        _typed_locator(self.migration_run_context_locator, field_name=f"{label}.migration_run_context_locator", expected_type=_RUN_CONTEXT_SCHEMA)
        if type(self.baseline_identity) is not LegacyBaselineIdentity or type(self.protected_release_identity) is not GitReleaseIdentity:
            raise ClosedValidationError(f"{label}: expected LegacyBaselineIdentity and GitReleaseIdentity")
        base_id = LegacyBaselineIdentity.from_dict(self.baseline_identity.to_dict())
        rel_id = GitReleaseIdentity.from_dict(self.protected_release_identity.to_dict())
        if rel_id.commit_sha == base_id.commit_sha:
            raise ClosedValidationError(f"{label}: protected_release_identity.commit_sha must differ from baseline_identity.commit_sha")
        validate_cell_object_ref(self.baseline_commit_object_ref, field_name=f"{label}.baseline_commit_object_ref")
        _typed_locator(self.decomposition_manifest_head_locator, field_name=f"{label}.decomposition_manifest_head_locator", expected_type=_DECOMP_HEAD_SCHEMA)
        _require_locator_digest_pair(self.decomposition_manifest_locator, self.decomposition_manifest_digest, expected_type=_DECOMP_MANIFEST_SCHEMA, loc_field=f"{label}.decomposition_manifest_locator", digest_field=f"{label}.decomposition_manifest_digest")
        edges = _validate_parent_edge_chain(self.parent_edge_chain, release_sha=rel_id.commit_sha, baseline_sha=base_id.commit_sha, field_name=f"{label}.parent_edge_chain")
        object.__setattr__(self, "parent_edge_chain", edges)
        object.__setattr__(self, "parent_edge_chain_digest", _resolve_digest_or_default(self.parent_edge_chain_digest, jcs_sha256([e.to_dict() for e in edges]), field_name=f"{label}.parent_edge_chain_digest"))
        _strict_id(self.protected_ref, field_name=f"{label}.protected_ref")
        _safe_int(self.pr_number, field_name=f"{label}.pr_number", minimum=1)
        validate_hex40(_strict_str(self.reviewed_head_sha, field_name=f"{label}.reviewed_head_sha"), field_name=f"{label}.reviewed_head_sha")
        merge_sha = validate_hex40(_strict_str(self.protected_merge_sha, field_name=f"{label}.protected_merge_sha"), field_name=f"{label}.protected_merge_sha")
        if merge_sha != rel_id.commit_sha:
            raise ClosedValidationError(f"{label}.protected_merge_sha: must equal protected_release_identity.commit_sha")
        _typed_locator(self.protected_merge_evidence_locator, field_name=f"{label}.protected_merge_evidence_locator", expected_type=_PROTECTED_MERGE_SCHEMA)
        validate_sha256_prefixed(_strict_str(self.branch_policy_digest, field_name=f"{label}.branch_policy_digest"), field_name=f"{label}.branch_policy_digest")
        if type(self.seam_git_artifact) is not SeamGitArtifactRef:
            raise ClosedValidationError(f"{label}.seam_git_artifact: expected SeamGitArtifactRef")
        SeamGitArtifactRef.from_dict(self.seam_git_artifact.to_dict())
        _require_locator_digest_pair(self.seam_contract_locator, self.seam_contract_digest, expected_type=LegacySeamContract.SCHEMA, loc_field=f"{label}.seam_contract_locator", digest_field=f"{label}.seam_contract_digest")
        _verify_p1_integrity(self.integrity, self.to_dict, label=label)

    @classmethod
    def from_dict(cls, data: object, *, require_signed: bool = False) -> LegacySeamRelease:
        m, integrity = _split_p1_envelope(data, core_keys=cls.CORE_KEYS, schema=cls.SCHEMA, label="legacy_seam_release", require_signed=require_signed)
        raw_edges = _require_json_list(m, "parent_edge_chain", label="legacy_seam_release")
        chain_digest = validate_sha256_prefixed(_strict_str(m["parent_edge_chain_digest"], field_name="legacy_seam_release.parent_edge_chain_digest"), field_name="legacy_seam_release.parent_edge_chain_digest")
        return cls(
            migration_run_context_locator=ArtifactLocator.from_dict(m["migration_run_context_locator"], expected_type=_RUN_CONTEXT_SCHEMA),
            baseline_identity=LegacyBaselineIdentity.from_dict(m["baseline_identity"]),
            baseline_commit_object_ref=m["baseline_commit_object_ref"],
            decomposition_manifest_head_locator=ArtifactLocator.from_dict(m["decomposition_manifest_head_locator"], expected_type=_DECOMP_HEAD_SCHEMA),
            decomposition_manifest_locator=ArtifactLocator.from_dict(m["decomposition_manifest_locator"], expected_type=_DECOMP_MANIFEST_SCHEMA),
            decomposition_manifest_digest=m["decomposition_manifest_digest"],
            protected_release_identity=GitReleaseIdentity.from_dict(m["protected_release_identity"]),
            parent_edge_chain=tuple(GitParentEdge.from_dict(e) for e in raw_edges),
            parent_edge_chain_digest=chain_digest,
            protected_ref=m["protected_ref"], pr_number=m["pr_number"],
            reviewed_head_sha=m["reviewed_head_sha"], protected_merge_sha=m["protected_merge_sha"],
            protected_merge_evidence_locator=ArtifactLocator.from_dict(m["protected_merge_evidence_locator"], expected_type=_PROTECTED_MERGE_SCHEMA),
            branch_policy_digest=m["branch_policy_digest"],
            seam_git_artifact=SeamGitArtifactRef.from_dict(m["seam_git_artifact"]),
            seam_contract_locator=ArtifactLocator.from_dict(m["seam_contract_locator"], expected_type=LegacySeamContract.SCHEMA),
            seam_contract_digest=m["seam_contract_digest"],
            integrity=integrity,
        )


@dataclass(frozen=True, slots=True)
class SeamParityRecord(_P1EnvelopeBase):
    """Closed P1 `smart_ads/seam_parity_record/v1` envelope (14 core + `integrity` = 15 keys)."""

    SCHEMA: ClassVar[str] = "smart_ads/seam_parity_record/v1"
    P1_DOMAIN_PREFIX: ClassVar[str] = ADR_P1_DOMAIN_PREFIXES[SCHEMA]
    CORE_KEYS: ClassVar[frozenset[str]] = frozenset(
        "$schema migration_run_context_locator legacy_seam_release_locator legacy_seam_release_digest "
        "seam_contract_locator seam_contract_digest decomposition_manifest_head_locator "
        "decomposition_manifest_locator wheel_build_provenance_locator wheel_digest "
        "seam_adapter_algorithm_identity evaluated_at_utc surface_comparisons parity_status".split()
    )
    KEYS: ClassVar[frozenset[str]] = CORE_KEYS | {"integrity"}

    migration_run_context_locator: ArtifactLocator
    legacy_seam_release_locator: ArtifactLocator
    legacy_seam_release_digest: str
    seam_contract_locator: ArtifactLocator
    seam_contract_digest: str
    decomposition_manifest_head_locator: ArtifactLocator
    decomposition_manifest_locator: ArtifactLocator
    wheel_build_provenance_locator: ArtifactLocator
    wheel_digest: str
    seam_adapter_algorithm_identity: AlgorithmProvenanceIdentity
    evaluated_at_utc: str
    surface_comparisons: tuple[SurfaceParityComparison, ...]
    parity_status: str
    integrity: P1Integrity | None = None

    def __post_init__(self) -> None:
        label = "seam_parity_record"
        _typed_locator(self.migration_run_context_locator, field_name=f"{label}.migration_run_context_locator", expected_type=_RUN_CONTEXT_SCHEMA)
        _require_locator_digest_pair(self.legacy_seam_release_locator, self.legacy_seam_release_digest, expected_type=LegacySeamRelease.SCHEMA, loc_field=f"{label}.legacy_seam_release_locator", digest_field=f"{label}.legacy_seam_release_digest")
        _require_locator_digest_pair(self.seam_contract_locator, self.seam_contract_digest, expected_type=LegacySeamContract.SCHEMA, loc_field=f"{label}.seam_contract_locator", digest_field=f"{label}.seam_contract_digest")
        _typed_locator(self.decomposition_manifest_head_locator, field_name=f"{label}.decomposition_manifest_head_locator", expected_type=_DECOMP_HEAD_SCHEMA)
        _typed_locator(self.decomposition_manifest_locator, field_name=f"{label}.decomposition_manifest_locator", expected_type=_DECOMP_MANIFEST_SCHEMA)
        _typed_locator(self.wheel_build_provenance_locator, field_name=f"{label}.wheel_build_provenance_locator", expected_type=_WHEEL_PROVENANCE_SCHEMA)
        validate_sha256_prefixed(_strict_str(self.wheel_digest, field_name=f"{label}.wheel_digest"), field_name=f"{label}.wheel_digest")
        if type(self.seam_adapter_algorithm_identity) is not AlgorithmProvenanceIdentity:
            raise ClosedValidationError(f"{label}.seam_adapter_algorithm_identity: expected AlgorithmProvenanceIdentity")
        alg = AlgorithmProvenanceIdentity.from_dict(self.seam_adapter_algorithm_identity.to_dict())
        if alg.schema_id != self.SCHEMA:
            raise ClosedValidationError(f"{label}.seam_adapter_algorithm_identity.schema_id: expected {self.SCHEMA!r}")
        validate_envelope_timestamp_utc(self.evaluated_at_utc, field_name=f"{label}.evaluated_at_utc")
        comps = _sorted_unique_by_surface_id(self.surface_comparisons, SurfaceParityComparison, field_name=f"{label}.surface_comparisons")
        if any(c.parity_matched is not True for c in comps):
            raise ClosedValidationError(f"{label}.surface_comparisons: every surface must have parity_matched=True")
        object.__setattr__(self, "surface_comparisons", comps)
        if _strict_str(self.parity_status, field_name=f"{label}.parity_status") != "PASS":
            raise ClosedValidationError(f"{label}.parity_status: must equal 'PASS'")
        _verify_p1_integrity(self.integrity, self.to_dict, label=label)

    @classmethod
    def from_dict(cls, data: object, *, require_signed: bool = False) -> SeamParityRecord:
        m, integrity = _split_p1_envelope(data, core_keys=cls.CORE_KEYS, schema=cls.SCHEMA, label="seam_parity_record", require_signed=require_signed)
        raw_comps = _require_json_list(m, "surface_comparisons", label="seam_parity_record")
        return cls(
            migration_run_context_locator=ArtifactLocator.from_dict(m["migration_run_context_locator"], expected_type=_RUN_CONTEXT_SCHEMA),
            legacy_seam_release_locator=ArtifactLocator.from_dict(m["legacy_seam_release_locator"], expected_type=LegacySeamRelease.SCHEMA),
            legacy_seam_release_digest=m["legacy_seam_release_digest"],
            seam_contract_locator=ArtifactLocator.from_dict(m["seam_contract_locator"], expected_type=LegacySeamContract.SCHEMA),
            seam_contract_digest=m["seam_contract_digest"],
            decomposition_manifest_head_locator=ArtifactLocator.from_dict(m["decomposition_manifest_head_locator"], expected_type=_DECOMP_HEAD_SCHEMA),
            decomposition_manifest_locator=ArtifactLocator.from_dict(m["decomposition_manifest_locator"], expected_type=_DECOMP_MANIFEST_SCHEMA),
            wheel_build_provenance_locator=ArtifactLocator.from_dict(m["wheel_build_provenance_locator"], expected_type=_WHEEL_PROVENANCE_SCHEMA),
            wheel_digest=m["wheel_digest"],
            seam_adapter_algorithm_identity=AlgorithmProvenanceIdentity.from_dict(m["seam_adapter_algorithm_identity"]),
            evaluated_at_utc=m["evaluated_at_utc"],
            surface_comparisons=tuple(SurfaceParityComparison.from_dict(c) for c in raw_comps),
            parity_status=m["parity_status"],
            integrity=integrity,
        )


__all__ = [
    "CompatibilitySurfaceSpec",
    "GitParentEdge",
    "GitReleaseIdentity",
    "LegacyBaselineIdentity",
    "LegacySeamContract",
    "LegacySeamRelease",
    "SeamGitArtifactRef",
    "SeamParityRecord",
    "SurfaceParityComparison",
    "WheelObjectLocator",
]
