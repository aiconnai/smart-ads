"""Closed `/ibvi-ads` delegation, consumer feature-flag/readback, and tripartite contracts (ADR-0001 §§3.3, 12.6)."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from itertools import pairwise
import re
from typing import Any, ClassVar, Final

from smart_ads.contracts.effects import (
    _P1EnvelopeBase,
    _SubjectBase,
    _require_json_list,
    _require_locator_digest_pair,
    _split_p1_envelope,
    _strict_id,
    _strict_str,
    _typed_locator,
    _validate_nonce,
    _verify_p1_integrity,
    validate_cell_object_ref,
)
from smart_ads.contracts.git_provenance import GitArtifactProvenance, _validate_relative_posix_path
from smart_ads.contracts.jcs import (
    ADR_P1_DOMAIN_PREFIXES,
    ArtifactLocator,
    P1Integrity,
    canonicalize_jcs,
    jcs_sha256,
)
from smart_ads.contracts.operational_evidence import AlgorithmProvenanceIdentity
from smart_ads.contracts.scalars import (
    ClosedValidationError,
    parse_timestamp_utc_micros,
    require_exact_keys,
    require_mapping,
    validate_hex40,
    validate_opaque_ref,
    validate_sha256_prefixed,
    validate_timestamp_utc6,
    validate_timestamp_utc_seconds,
)
from smart_ads.contracts.seam import (
    LegacySeamContract,
    LegacySeamRelease,
    SeamGitArtifactRef,
    WheelObjectLocator,
    _resolve_digest_or_default,
)

_RUN_CONTEXT_SCHEMA: Final[str] = "smart_ads/migration_run_context/v1"
_DEPLOYMENT_CONFIG_RESULT_SCHEMA: Final[str] = "smart_ads/deployment_config_execution_result/v1"
_CLOCK_ATTESTATION_SCHEMA: Final[str] = "smart_ads/clock_attestation/v1"
_WHEEL_PROVENANCE_SCHEMA: Final[str] = "smart_ads/wheel_build_provenance/v1"
_LEGACY_REPOSITORY: Final[str] = "mbras-tech/mbras-campaigns"
_CANONICAL_REPOSITORY: Final[str] = "aiconnai/smart-ads"
_CONSUMER_REPOSITORY: Final[str] = "limaronaldo/hermes-ronaldo"
_IBVI_ADS_ROUTE: Final[str] = "/ibvi-ads"
_CANONICAL_MCP_METHODS: Final[tuple[str, ...]] = (
    "smart_ads.queries.get_ad_performance_v1",
    "smart_ads.queries.get_adset_performance_v1",
    "smart_ads.queries.get_campaign_performance_v1",
    "smart_ads.queries.get_intelligence_findings_v1",
    "smart_ads.reports.generate_recurrent_summary_v1",
)
_SYMBOL_NAME_RE: Final[re.Pattern[str]] = re.compile(
    r"\A[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?\Z"
)
_FLAG_KEY_RE: Final[re.Pattern[str]] = re.compile(r"\A[A-Za-z0-9_.-]{1,128}\Z")


def _validate_flag_routing_fields(
    *, flag_key: object, default_enabled: object, disabled_route: object, enabled_route: object, label: str
) -> None:
    fk = _strict_str(flag_key, field_name=f"{label}.flag_key")
    if _FLAG_KEY_RE.fullmatch(fk) is None:
        raise ClosedValidationError(f"{label}.flag_key: invalid flag_key {fk!r}")
    if type(default_enabled) is not bool or default_enabled is not False:
        raise ClosedValidationError(f"{label}.default_enabled: must be literal bool False")
    dis = _strict_id(disabled_route, field_name=f"{label}.disabled_legacy_route")
    if dis == _IBVI_ADS_ROUTE or dis.startswith("smart_ads"):
        raise ClosedValidationError(f"{label}.disabled_legacy_route: forbidden target {dis!r}")
    if _strict_str(enabled_route, field_name=f"{label}.enabled_smart_ads_route") != _IBVI_ADS_ROUTE:
        raise ClosedValidationError(f"{label}.enabled_smart_ads_route: must equal {_IBVI_ADS_ROUTE!r}")


def _validate_distinct_git_artifacts(
    adapter_art: object, flag_art: object, *, label: str
) -> tuple[TripartiteGitArtifactRef, TripartiteGitArtifactRef]:
    if type(adapter_art) is not TripartiteGitArtifactRef or type(flag_art) is not TripartiteGitArtifactRef:
        raise ClosedValidationError(f"{label}: expected TripartiteGitArtifactRef instances")
    a_ref = TripartiteGitArtifactRef.from_dict(adapter_art.to_dict())
    f_ref = TripartiteGitArtifactRef.from_dict(flag_art.to_dict())
    if a_ref.source_path == f_ref.source_path:
        raise ClosedValidationError(f"{label}: adapter and feature_flag source_path must be distinct")
    return a_ref, f_ref


def _validate_sorted_entrypoints(values: object, *, field_name: str) -> tuple[ReadEntrypointSelector, ...]:
    if not isinstance(values, (list, tuple)) or len(values) == 0:
        raise ClosedValidationError(f"{field_name}: expected non-empty list or tuple of ReadEntrypointSelector")
    out: list[ReadEntrypointSelector] = []
    keys: list[bytes] = []
    for idx, item in enumerate(values):
        if type(item) is not ReadEntrypointSelector:
            raise ClosedValidationError(f"{field_name}[{idx}]: expected ReadEntrypointSelector")
        fresh = ReadEntrypointSelector.from_dict(item.to_dict())
        out.append(fresh)
        keys.append(fresh.symbol_name.encode("utf-8"))
    if any(left >= right for left, right in pairwise(keys)):
        raise ClosedValidationError(f"{field_name}: selectors must be strictly sorted and unique by symbol_name")
    return tuple(out)


@dataclass(frozen=True, slots=True)
class TripartiteGitArtifactRef(_SubjectBase):
    """Closed 4-member consumer/tripartite Git artifact reference."""

    KEYS: ClassVar[frozenset[str]] = frozenset({"source_path", "git_blob_oid", "file_content_sha256", "git_provenance_locator"})

    source_path: str
    git_blob_oid: str
    file_content_sha256: str
    git_provenance_locator: ArtifactLocator

    def __post_init__(self) -> None:
        label = "tripartite_git_artifact_ref"
        _validate_relative_posix_path(self.source_path, field_name=f"{label}.source_path")
        validate_hex40(_strict_str(self.git_blob_oid, field_name=f"{label}.git_blob_oid"), field_name=f"{label}.git_blob_oid")
        validate_sha256_prefixed(_strict_str(self.file_content_sha256, field_name=f"{label}.file_content_sha256"), field_name=f"{label}.file_content_sha256")
        _typed_locator(self.git_provenance_locator, field_name=f"{label}.git_provenance_locator", expected_type=GitArtifactProvenance.SCHEMA)

    @classmethod
    def from_dict(cls, data: object) -> TripartiteGitArtifactRef:
        m = require_exact_keys(data, cls.KEYS, label="tripartite_git_artifact_ref")
        return cls(
            source_path=m["source_path"], git_blob_oid=m["git_blob_oid"], file_content_sha256=m["file_content_sha256"],
            git_provenance_locator=ArtifactLocator.from_dict(m["git_provenance_locator"], expected_type=GitArtifactProvenance.SCHEMA),
        )


@dataclass(frozen=True, slots=True)
class IbviAdsDelegationContext(_P1EnvelopeBase):
    """Closed P1 `smart_ads/ibvi_ads_delegation_context/v1` envelope (13 core + `integrity` = 14 keys)."""

    SCHEMA: ClassVar[str] = "smart_ads/ibvi_ads_delegation_context/v1"
    P1_DOMAIN_PREFIX: ClassVar[str] = ADR_P1_DOMAIN_PREFIXES[SCHEMA]
    CORE_KEYS: ClassVar[frozenset[str]] = frozenset(
        "$schema route host_conductor_ref front_ref profile_ref tenant_ref binding_ref "
        "resource_scope_ref allowed_method policy_digest issued_at_utc valid_until_utc nonce".split()
    )
    KEYS: ClassVar[frozenset[str]] = CORE_KEYS | {"integrity"}

    route: str
    host_conductor_ref: str
    front_ref: str
    profile_ref: str
    tenant_ref: str
    binding_ref: str
    resource_scope_ref: str
    allowed_method: str
    policy_digest: str
    issued_at_utc: str
    valid_until_utc: str
    nonce: str
    integrity: P1Integrity | None = None

    def __post_init__(self) -> None:
        label = "ibvi_ads_delegation_context"
        if _strict_str(self.route, field_name=f"{label}.route") != _IBVI_ADS_ROUTE:
            raise ClosedValidationError(f"{label}.route: must equal {_IBVI_ADS_ROUTE!r}")
        for attr, pfx in (
            ("host_conductor_ref", "conductor"), ("front_ref", "front"), ("profile_ref", "profile"),
            ("tenant_ref", "tenant"), ("binding_ref", "binding"), ("resource_scope_ref", "scope"),
        ):
            validate_opaque_ref(_strict_str(getattr(self, attr), field_name=f"{label}.{attr}"), field_name=f"{label}.{attr}", expected_prefix=pfx)
        if _strict_str(self.allowed_method, field_name=f"{label}.allowed_method") not in _CANONICAL_MCP_METHODS:
            raise ClosedValidationError(f"{label}.allowed_method: outside closed MCP allowlist")
        validate_sha256_prefixed(_strict_str(self.policy_digest, field_name=f"{label}.policy_digest"), field_name=f"{label}.policy_digest")
        iss = validate_timestamp_utc_seconds(_strict_str(self.issued_at_utc, field_name=f"{label}.issued_at_utc"), field_name=f"{label}.issued_at_utc")
        exp = validate_timestamp_utc_seconds(_strict_str(self.valid_until_utc, field_name=f"{label}.valid_until_utc"), field_name=f"{label}.valid_until_utc")
        if parse_timestamp_utc_micros(iss, allow_whole_seconds=True) >= parse_timestamp_utc_micros(exp, allow_whole_seconds=True):
            raise ClosedValidationError(f"{label}: issued_at_utc must strictly precede valid_until_utc")
        _validate_nonce(self.nonce, field_name=f"{label}.nonce")
        _verify_p1_integrity(self.integrity, self.to_dict, label=label)

    @classmethod
    def from_dict(cls, data: object, *, require_signed: bool = False) -> IbviAdsDelegationContext:
        m, integrity = _split_p1_envelope(data, core_keys=cls.CORE_KEYS, schema=cls.SCHEMA, label="ibvi_ads_delegation_context", require_signed=require_signed)
        return cls(
            route=m["route"], host_conductor_ref=m["host_conductor_ref"], front_ref=m["front_ref"],
            profile_ref=m["profile_ref"], tenant_ref=m["tenant_ref"], binding_ref=m["binding_ref"],
            resource_scope_ref=m["resource_scope_ref"], allowed_method=m["allowed_method"],
            policy_digest=m["policy_digest"], issued_at_utc=m["issued_at_utc"],
            valid_until_utc=m["valid_until_utc"], nonce=m["nonce"], integrity=integrity,
        )


@dataclass(frozen=True, slots=True)
class IbviAdsDelegationContract(_P1EnvelopeBase):
    """Closed P1 `smart_ads/ibvi_ads_delegation_contract/v1` envelope (11 core + `integrity` = 12 keys)."""

    SCHEMA: ClassVar[str] = "smart_ads/ibvi_ads_delegation_contract/v1"
    P1_DOMAIN_PREFIX: ClassVar[str] = ADR_P1_DOMAIN_PREFIXES[SCHEMA]
    CORE_KEYS: ClassVar[frozenset[str]] = frozenset(
        "$schema migration_run_context_locator consumer_repository consumer_commit_sha "
        "host_conductor_git_provenance_locator host_conductor_ref front_ref delegated_route "
        "policy_digest allowed_mcp_methods direct_route_bypass_denied".split()
    )
    KEYS: ClassVar[frozenset[str]] = CORE_KEYS | {"integrity"}

    migration_run_context_locator: ArtifactLocator
    consumer_repository: str
    consumer_commit_sha: str
    host_conductor_git_provenance_locator: ArtifactLocator
    host_conductor_ref: str
    front_ref: str
    delegated_route: str
    policy_digest: str
    allowed_mcp_methods: tuple[str, ...]
    direct_route_bypass_denied: bool
    integrity: P1Integrity | None = None

    def __post_init__(self) -> None:
        label = "ibvi_ads_delegation_contract"
        _typed_locator(self.migration_run_context_locator, field_name=f"{label}.migration_run_context_locator", expected_type=_RUN_CONTEXT_SCHEMA)
        if _strict_str(self.consumer_repository, field_name=f"{label}.consumer_repository") != _CONSUMER_REPOSITORY:
            raise ClosedValidationError(f"{label}.consumer_repository: must equal {_CONSUMER_REPOSITORY!r}")
        validate_hex40(_strict_str(self.consumer_commit_sha, field_name=f"{label}.consumer_commit_sha"), field_name=f"{label}.consumer_commit_sha")
        _typed_locator(self.host_conductor_git_provenance_locator, field_name=f"{label}.host_conductor_git_provenance_locator", expected_type=GitArtifactProvenance.SCHEMA)
        validate_opaque_ref(_strict_str(self.host_conductor_ref, field_name=f"{label}.host_conductor_ref"), field_name=f"{label}.host_conductor_ref", expected_prefix="conductor")
        validate_opaque_ref(_strict_str(self.front_ref, field_name=f"{label}.front_ref"), field_name=f"{label}.front_ref", expected_prefix="front")
        if _strict_str(self.delegated_route, field_name=f"{label}.delegated_route") != _IBVI_ADS_ROUTE:
            raise ClosedValidationError(f"{label}.delegated_route: must equal {_IBVI_ADS_ROUTE!r}")
        validate_sha256_prefixed(_strict_str(self.policy_digest, field_name=f"{label}.policy_digest"), field_name=f"{label}.policy_digest")
        if not isinstance(self.allowed_mcp_methods, (list, tuple)):
            raise ClosedValidationError(f"{label}.allowed_mcp_methods: expected list or tuple of str")
        methods = tuple(_strict_str(m, field_name=f"{label}.allowed_mcp_methods[]") for m in self.allowed_mcp_methods)
        if methods != _CANONICAL_MCP_METHODS:
            raise ClosedValidationError(f"{label}.allowed_mcp_methods: must equal exact canonical MCP allowlist")
        object.__setattr__(self, "allowed_mcp_methods", methods)
        if type(self.direct_route_bypass_denied) is not bool or self.direct_route_bypass_denied is not True:
            raise ClosedValidationError(f"{label}.direct_route_bypass_denied: must be literal bool True")
        _verify_p1_integrity(self.integrity, self.to_dict, label=label)

    @classmethod
    def from_dict(cls, data: object, *, require_signed: bool = False) -> IbviAdsDelegationContract:
        m, integrity = _split_p1_envelope(data, core_keys=cls.CORE_KEYS, schema=cls.SCHEMA, label="ibvi_ads_delegation_contract", require_signed=require_signed)
        raw_methods = _require_json_list(m, "allowed_mcp_methods", label="ibvi_ads_delegation_contract")
        return cls(
            migration_run_context_locator=ArtifactLocator.from_dict(m["migration_run_context_locator"], expected_type=_RUN_CONTEXT_SCHEMA),
            consumer_repository=m["consumer_repository"], consumer_commit_sha=m["consumer_commit_sha"],
            host_conductor_git_provenance_locator=ArtifactLocator.from_dict(m["host_conductor_git_provenance_locator"], expected_type=GitArtifactProvenance.SCHEMA),
            host_conductor_ref=m["host_conductor_ref"], front_ref=m["front_ref"],
            delegated_route=m["delegated_route"], policy_digest=m["policy_digest"],
            allowed_mcp_methods=tuple(raw_methods), direct_route_bypass_denied=m["direct_route_bypass_denied"],
            integrity=integrity,
        )


@dataclass(frozen=True, slots=True)
class ReadEntrypointSelector(_SubjectBase):
    """Closed 2-member consumer read entrypoint selector."""

    KEYS: ClassVar[frozenset[str]] = frozenset({"symbol_name", "mcp_method"})

    symbol_name: str
    mcp_method: str

    def __post_init__(self) -> None:
        label = "read_entrypoint_selector"
        sym = _strict_str(self.symbol_name, field_name=f"{label}.symbol_name")
        if _SYMBOL_NAME_RE.fullmatch(sym) is None:
            raise ClosedValidationError(f"{label}.symbol_name: invalid symbol {sym!r}")
        if _strict_str(self.mcp_method, field_name=f"{label}.mcp_method") not in _CANONICAL_MCP_METHODS:
            raise ClosedValidationError(f"{label}.mcp_method: outside closed MCP allowlist")

    @classmethod
    def from_dict(cls, data: object) -> ReadEntrypointSelector:
        m = require_exact_keys(data, cls.KEYS, label="read_entrypoint_selector")
        return cls(symbol_name=m["symbol_name"], mcp_method=m["mcp_method"])


@dataclass(frozen=True, slots=True)
class ConsumerFeatureFlagContract(_P1EnvelopeBase):
    """Closed P1 `smart_ads/consumer_feature_flag_contract/v1` envelope (13 core + `integrity` = 14 keys)."""

    SCHEMA: ClassVar[str] = "smart_ads/consumer_feature_flag_contract/v1"
    P1_DOMAIN_PREFIX: ClassVar[str] = ADR_P1_DOMAIN_PREFIXES[SCHEMA]
    CORE_KEYS: ClassVar[frozenset[str]] = frozenset(
        "$schema migration_run_context_locator consumer_repository consumer_commit_sha "
        "adapter_git_artifact feature_flag_git_artifact flag_key default_enabled "
        "disabled_legacy_route enabled_smart_ads_route read_entrypoints "
        "routing_verifier_identity ibvi_ads_delegation_contract_locator".split()
    )
    KEYS: ClassVar[frozenset[str]] = CORE_KEYS | {"integrity"}

    migration_run_context_locator: ArtifactLocator
    consumer_repository: str
    consumer_commit_sha: str
    adapter_git_artifact: TripartiteGitArtifactRef
    feature_flag_git_artifact: TripartiteGitArtifactRef
    flag_key: str
    default_enabled: bool
    disabled_legacy_route: str
    enabled_smart_ads_route: str
    read_entrypoints: tuple[ReadEntrypointSelector, ...]
    routing_verifier_identity: AlgorithmProvenanceIdentity
    ibvi_ads_delegation_contract_locator: ArtifactLocator
    integrity: P1Integrity | None = None

    def __post_init__(self) -> None:
        label = "consumer_feature_flag_contract"
        _typed_locator(self.migration_run_context_locator, field_name=f"{label}.migration_run_context_locator", expected_type=_RUN_CONTEXT_SCHEMA)
        if _strict_str(self.consumer_repository, field_name=f"{label}.consumer_repository") != _CONSUMER_REPOSITORY:
            raise ClosedValidationError(f"{label}.consumer_repository: must equal {_CONSUMER_REPOSITORY!r}")
        validate_hex40(_strict_str(self.consumer_commit_sha, field_name=f"{label}.consumer_commit_sha"), field_name=f"{label}.consumer_commit_sha")
        _validate_distinct_git_artifacts(self.adapter_git_artifact, self.feature_flag_git_artifact, label=label)
        _validate_flag_routing_fields(
            flag_key=self.flag_key, default_enabled=self.default_enabled,
            disabled_route=self.disabled_legacy_route, enabled_route=self.enabled_smart_ads_route, label=label,
        )
        object.__setattr__(self, "read_entrypoints", _validate_sorted_entrypoints(self.read_entrypoints, field_name=f"{label}.read_entrypoints"))
        if type(self.routing_verifier_identity) is not AlgorithmProvenanceIdentity:
            raise ClosedValidationError(f"{label}.routing_verifier_identity: expected AlgorithmProvenanceIdentity")
        alg = AlgorithmProvenanceIdentity.from_dict(self.routing_verifier_identity.to_dict())
        if alg.schema_id != self.SCHEMA:
            raise ClosedValidationError(f"{label}.routing_verifier_identity.schema_id: expected {self.SCHEMA!r}")
        _typed_locator(self.ibvi_ads_delegation_contract_locator, field_name=f"{label}.ibvi_ads_delegation_contract_locator", expected_type=IbviAdsDelegationContract.SCHEMA)
        _verify_p1_integrity(self.integrity, self.to_dict, label=label)

    @classmethod
    def from_dict(cls, data: object, *, require_signed: bool = False) -> ConsumerFeatureFlagContract:
        m, integrity = _split_p1_envelope(data, core_keys=cls.CORE_KEYS, schema=cls.SCHEMA, label="consumer_feature_flag_contract", require_signed=require_signed)
        raw_eps = _require_json_list(m, "read_entrypoints", label="consumer_feature_flag_contract")
        return cls(
            migration_run_context_locator=ArtifactLocator.from_dict(m["migration_run_context_locator"], expected_type=_RUN_CONTEXT_SCHEMA),
            consumer_repository=m["consumer_repository"], consumer_commit_sha=m["consumer_commit_sha"],
            adapter_git_artifact=TripartiteGitArtifactRef.from_dict(m["adapter_git_artifact"]),
            feature_flag_git_artifact=TripartiteGitArtifactRef.from_dict(m["feature_flag_git_artifact"]),
            flag_key=m["flag_key"], default_enabled=m["default_enabled"],
            disabled_legacy_route=m["disabled_legacy_route"], enabled_smart_ads_route=m["enabled_smart_ads_route"],
            read_entrypoints=tuple(ReadEntrypointSelector.from_dict(ep) for ep in raw_eps),
            routing_verifier_identity=AlgorithmProvenanceIdentity.from_dict(m["routing_verifier_identity"]),
            ibvi_ads_delegation_contract_locator=ArtifactLocator.from_dict(m["ibvi_ads_delegation_contract_locator"], expected_type=IbviAdsDelegationContract.SCHEMA),
            integrity=integrity,
        )


def compute_capture_replay_digest(
    *, consumer_repository: str, consumer_commit_sha: str, deployed_release_id: str, runtime_binary_sha256: str,
    captured_at_utc: str, capture_tool_identity: AlgorithmProvenanceIdentity, capture_tool_build_digest: str,
    live_adapter_artifact: TripartiteGitArtifactRef, live_adapter_object_ref: str,
    live_feature_flag_artifact: TripartiteGitArtifactRef, live_feature_flag_object_ref: str, live_flag_key: str,
    live_default_enabled: bool, live_disabled_legacy_route: str, live_enabled_smart_ads_route: str,
    feature_flag_contract_digest: str, ibvi_ads_delegation_contract_digest: str,
) -> str:
    """Compute canonical JCS SHA-256 `capture_replay_digest` over the 17-member deployment readback projection."""
    label = "consumer_deployment_readback"
    if _strict_str(consumer_repository, field_name=f"{label}.consumer_repository") != _CONSUMER_REPOSITORY:
        raise ClosedValidationError(f"{label}.consumer_repository: must equal {_CONSUMER_REPOSITORY!r}")
    validate_hex40(_strict_str(consumer_commit_sha, field_name=f"{label}.consumer_commit_sha"), field_name=f"{label}.consumer_commit_sha")
    _strict_id(deployed_release_id, field_name=f"{label}.deployed_release_id")
    for fn, val in (("runtime_binary_sha256", runtime_binary_sha256), ("capture_tool_build_digest", capture_tool_build_digest), ("feature_flag_contract_digest", feature_flag_contract_digest), ("ibvi_ads_delegation_contract_digest", ibvi_ads_delegation_contract_digest)):
        validate_sha256_prefixed(_strict_str(val, field_name=f"{label}.{fn}"), field_name=f"{label}.{fn}")
    validate_timestamp_utc6(_strict_str(captured_at_utc, field_name=f"{label}.captured_at_utc"), field_name=f"{label}.captured_at_utc")
    if type(capture_tool_identity) is not AlgorithmProvenanceIdentity:
        raise ClosedValidationError(f"{label}.capture_tool_identity: expected AlgorithmProvenanceIdentity")
    alg = AlgorithmProvenanceIdentity.from_dict(capture_tool_identity.to_dict())
    if alg.schema_id != ConsumerDeploymentReadback.SCHEMA:
        raise ClosedValidationError(f"{label}.capture_tool_identity.schema_id: expected {ConsumerDeploymentReadback.SCHEMA!r}")
    a_art, f_art = _validate_distinct_git_artifacts(live_adapter_artifact, live_feature_flag_artifact, label=label)
    if validate_cell_object_ref(live_adapter_object_ref, field_name=f"{label}.live_adapter_object_ref") != f"cell-object:{a_art.file_content_sha256}":
        raise ClosedValidationError(f"{label}.live_adapter_object_ref: must match live_adapter_artifact.file_content_sha256")
    if validate_cell_object_ref(live_feature_flag_object_ref, field_name=f"{label}.live_feature_flag_object_ref") != f"cell-object:{f_art.file_content_sha256}":
        raise ClosedValidationError(f"{label}.live_feature_flag_object_ref: must match live_feature_flag_artifact.file_content_sha256")
    _validate_flag_routing_fields(flag_key=live_flag_key, default_enabled=live_default_enabled, disabled_route=live_disabled_legacy_route, enabled_route=live_enabled_smart_ads_route, label=label)
    return jcs_sha256({
        "consumer_repository": consumer_repository, "consumer_commit_sha": consumer_commit_sha,
        "deployed_release_id": deployed_release_id, "runtime_binary_sha256": runtime_binary_sha256,
        "captured_at_utc": captured_at_utc, "capture_tool_identity": alg.to_dict(),
        "capture_tool_build_digest": capture_tool_build_digest, "live_adapter_artifact": a_art.to_dict(),
        "live_adapter_object_ref": live_adapter_object_ref, "live_feature_flag_artifact": f_art.to_dict(),
        "live_feature_flag_object_ref": live_feature_flag_object_ref, "live_flag_key": live_flag_key,
        "live_default_enabled": live_default_enabled, "live_disabled_legacy_route": live_disabled_legacy_route,
        "live_enabled_smart_ads_route": live_enabled_smart_ads_route,
        "feature_flag_contract_digest": feature_flag_contract_digest,
        "ibvi_ads_delegation_contract_digest": ibvi_ads_delegation_contract_digest,
    })


@dataclass(frozen=True, slots=True)
class ConsumerDeploymentReadback(_P1EnvelopeBase):
    """Closed P1 `smart_ads/consumer_deployment_readback/v1` envelope (24 core + `integrity` = 25 keys)."""

    SCHEMA: ClassVar[str] = "smart_ads/consumer_deployment_readback/v1"
    P1_DOMAIN_PREFIX: ClassVar[str] = ADR_P1_DOMAIN_PREFIXES[SCHEMA]
    CORE_KEYS: ClassVar[frozenset[str]] = frozenset(
        "$schema migration_run_context_locator consumer_repository consumer_commit_sha "
        "deployment_config_result_locator deployed_release_id runtime_binary_sha256 "
        "clock_attestation_locator captured_at_utc capture_tool_identity capture_tool_build_digest "
        "live_adapter_artifact live_adapter_object_ref live_feature_flag_artifact "
        "live_feature_flag_object_ref live_flag_key live_default_enabled live_disabled_legacy_route "
        "live_enabled_smart_ads_route feature_flag_contract_locator feature_flag_contract_digest "
        "ibvi_ads_delegation_contract_locator ibvi_ads_delegation_contract_digest capture_replay_digest".split()
    )
    KEYS: ClassVar[frozenset[str]] = CORE_KEYS | {"integrity"}

    migration_run_context_locator: ArtifactLocator
    consumer_repository: str
    consumer_commit_sha: str
    deployment_config_result_locator: ArtifactLocator
    deployed_release_id: str
    runtime_binary_sha256: str
    clock_attestation_locator: ArtifactLocator
    captured_at_utc: str
    capture_tool_identity: AlgorithmProvenanceIdentity
    capture_tool_build_digest: str
    live_adapter_artifact: TripartiteGitArtifactRef
    live_adapter_object_ref: str
    live_feature_flag_artifact: TripartiteGitArtifactRef
    live_feature_flag_object_ref: str
    live_flag_key: str
    live_default_enabled: bool
    live_disabled_legacy_route: str
    live_enabled_smart_ads_route: str
    feature_flag_contract_locator: ArtifactLocator
    feature_flag_contract_digest: str
    ibvi_ads_delegation_contract_locator: ArtifactLocator
    ibvi_ads_delegation_contract_digest: str
    capture_replay_digest: str = ""
    integrity: P1Integrity | None = None

    def __post_init__(self) -> None:
        label = "consumer_deployment_readback"
        _typed_locator(self.migration_run_context_locator, field_name=f"{label}.migration_run_context_locator", expected_type=_RUN_CONTEXT_SCHEMA)
        _typed_locator(self.deployment_config_result_locator, field_name=f"{label}.deployment_config_result_locator", expected_type=_DEPLOYMENT_CONFIG_RESULT_SCHEMA)
        _typed_locator(self.clock_attestation_locator, field_name=f"{label}.clock_attestation_locator", expected_type=_CLOCK_ATTESTATION_SCHEMA)
        _require_locator_digest_pair(self.feature_flag_contract_locator, self.feature_flag_contract_digest, expected_type=ConsumerFeatureFlagContract.SCHEMA, loc_field=f"{label}.feature_flag_contract_locator", digest_field=f"{label}.feature_flag_contract_digest")
        _require_locator_digest_pair(self.ibvi_ads_delegation_contract_locator, self.ibvi_ads_delegation_contract_digest, expected_type=IbviAdsDelegationContract.SCHEMA, loc_field=f"{label}.ibvi_ads_delegation_contract_locator", digest_field=f"{label}.ibvi_ads_delegation_contract_digest")
        expected_replay = compute_capture_replay_digest(
            consumer_repository=self.consumer_repository, consumer_commit_sha=self.consumer_commit_sha,
            deployed_release_id=self.deployed_release_id, runtime_binary_sha256=self.runtime_binary_sha256,
            captured_at_utc=self.captured_at_utc, capture_tool_identity=self.capture_tool_identity,
            capture_tool_build_digest=self.capture_tool_build_digest, live_adapter_artifact=self.live_adapter_artifact,
            live_adapter_object_ref=self.live_adapter_object_ref, live_feature_flag_artifact=self.live_feature_flag_artifact,
            live_feature_flag_object_ref=self.live_feature_flag_object_ref, live_flag_key=self.live_flag_key,
            live_default_enabled=self.live_default_enabled, live_disabled_legacy_route=self.live_disabled_legacy_route,
            live_enabled_smart_ads_route=self.live_enabled_smart_ads_route,
            feature_flag_contract_digest=self.feature_flag_contract_digest,
            ibvi_ads_delegation_contract_digest=self.ibvi_ads_delegation_contract_digest,
        )
        object.__setattr__(self, "capture_replay_digest", _resolve_digest_or_default(self.capture_replay_digest, expected_replay, field_name=f"{label}.capture_replay_digest"))
        _verify_p1_integrity(self.integrity, self.to_dict, label=label)

    @classmethod
    def from_dict(cls, data: object, *, require_signed: bool = False) -> ConsumerDeploymentReadback:
        m, integrity = _split_p1_envelope(data, core_keys=cls.CORE_KEYS, schema=cls.SCHEMA, label="consumer_deployment_readback", require_signed=require_signed)
        replay_d = validate_sha256_prefixed(_strict_str(m["capture_replay_digest"], field_name="consumer_deployment_readback.capture_replay_digest"), field_name="consumer_deployment_readback.capture_replay_digest")
        return cls(
            migration_run_context_locator=ArtifactLocator.from_dict(m["migration_run_context_locator"], expected_type=_RUN_CONTEXT_SCHEMA),
            consumer_repository=m["consumer_repository"], consumer_commit_sha=m["consumer_commit_sha"],
            deployment_config_result_locator=ArtifactLocator.from_dict(m["deployment_config_result_locator"], expected_type=_DEPLOYMENT_CONFIG_RESULT_SCHEMA),
            deployed_release_id=m["deployed_release_id"], runtime_binary_sha256=m["runtime_binary_sha256"],
            clock_attestation_locator=ArtifactLocator.from_dict(m["clock_attestation_locator"], expected_type=_CLOCK_ATTESTATION_SCHEMA),
            captured_at_utc=m["captured_at_utc"],
            capture_tool_identity=AlgorithmProvenanceIdentity.from_dict(m["capture_tool_identity"]),
            capture_tool_build_digest=m["capture_tool_build_digest"],
            live_adapter_artifact=TripartiteGitArtifactRef.from_dict(m["live_adapter_artifact"]),
            live_adapter_object_ref=m["live_adapter_object_ref"],
            live_feature_flag_artifact=TripartiteGitArtifactRef.from_dict(m["live_feature_flag_artifact"]),
            live_feature_flag_object_ref=m["live_feature_flag_object_ref"],
            live_flag_key=m["live_flag_key"], live_default_enabled=m["live_default_enabled"],
            live_disabled_legacy_route=m["live_disabled_legacy_route"],
            live_enabled_smart_ads_route=m["live_enabled_smart_ads_route"],
            feature_flag_contract_locator=ArtifactLocator.from_dict(m["feature_flag_contract_locator"], expected_type=ConsumerFeatureFlagContract.SCHEMA),
            feature_flag_contract_digest=m["feature_flag_contract_digest"],
            ibvi_ads_delegation_contract_locator=ArtifactLocator.from_dict(m["ibvi_ads_delegation_contract_locator"], expected_type=IbviAdsDelegationContract.SCHEMA),
            ibvi_ads_delegation_contract_digest=m["ibvi_ads_delegation_contract_digest"],
            capture_replay_digest=replay_d, integrity=integrity,
        )


@dataclass(frozen=True, slots=True)
class TripartiteLegacySide(_SubjectBase):
    """Closed 6-member `legacy_side` inside `tripartite_target` (ADR-0001 §12.6)."""

    KEYS: ClassVar[frozenset[str]] = frozenset(
        {"repository", "commit_sha", "legacy_seam_release_locator", "seam_git_artifact", "seam_contract_locator", "seam_contract_digest"}
    )

    repository: str
    commit_sha: str
    legacy_seam_release_locator: ArtifactLocator
    seam_git_artifact: SeamGitArtifactRef | TripartiteGitArtifactRef
    seam_contract_locator: ArtifactLocator
    seam_contract_digest: str

    def __post_init__(self) -> None:
        label = "tripartite_legacy_side"
        if _strict_str(self.repository, field_name=f"{label}.repository") != _LEGACY_REPOSITORY:
            raise ClosedValidationError(f"{label}.repository: must equal {_LEGACY_REPOSITORY!r}")
        validate_hex40(_strict_str(self.commit_sha, field_name=f"{label}.commit_sha"), field_name=f"{label}.commit_sha")
        _typed_locator(self.legacy_seam_release_locator, field_name=f"{label}.legacy_seam_release_locator", expected_type=LegacySeamRelease.SCHEMA)
        if type(self.seam_git_artifact) not in (SeamGitArtifactRef, TripartiteGitArtifactRef):
            raise ClosedValidationError(f"{label}.seam_git_artifact: expected SeamGitArtifactRef or TripartiteGitArtifactRef")
        object.__setattr__(self, "seam_git_artifact", SeamGitArtifactRef.from_dict(self.seam_git_artifact.to_dict()))
        _require_locator_digest_pair(self.seam_contract_locator, self.seam_contract_digest, expected_type=LegacySeamContract.SCHEMA, loc_field=f"{label}.seam_contract_locator", digest_field=f"{label}.seam_contract_digest")

    @classmethod
    def from_dict(cls, data: object) -> TripartiteLegacySide:
        m = require_exact_keys(data, cls.KEYS, label="tripartite_legacy_side")
        return cls(
            repository=m["repository"], commit_sha=m["commit_sha"],
            legacy_seam_release_locator=ArtifactLocator.from_dict(m["legacy_seam_release_locator"], expected_type=LegacySeamRelease.SCHEMA),
            seam_git_artifact=SeamGitArtifactRef.from_dict(m["seam_git_artifact"]),
            seam_contract_locator=ArtifactLocator.from_dict(m["seam_contract_locator"], expected_type=LegacySeamContract.SCHEMA),
            seam_contract_digest=m["seam_contract_digest"],
        )


@dataclass(frozen=True, slots=True)
class TripartiteCanonicalSide(_SubjectBase):
    """Closed 5-member `canonical_side` inside `tripartite_target` (ADR-0001 §12.6)."""

    KEYS: ClassVar[frozenset[str]] = frozenset({"repository", "commit_sha", "wheel", "wheel_digest", "build_provenance_locator"})

    repository: str
    commit_sha: str
    wheel: WheelObjectLocator
    wheel_digest: str
    build_provenance_locator: ArtifactLocator

    def __post_init__(self) -> None:
        label = "tripartite_canonical_side"
        if _strict_str(self.repository, field_name=f"{label}.repository") != _CANONICAL_REPOSITORY:
            raise ClosedValidationError(f"{label}.repository: must equal {_CANONICAL_REPOSITORY!r}")
        validate_hex40(_strict_str(self.commit_sha, field_name=f"{label}.commit_sha"), field_name=f"{label}.commit_sha")
        if type(self.wheel) is not WheelObjectLocator:
            raise ClosedValidationError(f"{label}.wheel: expected WheelObjectLocator")
        checked_whl = WheelObjectLocator.from_dict(self.wheel.to_dict())
        whl_d = validate_sha256_prefixed(_strict_str(self.wheel_digest, field_name=f"{label}.wheel_digest"), field_name=f"{label}.wheel_digest")
        if whl_d != checked_whl.wheel_digest:
            raise ClosedValidationError(f"{label}.wheel_digest: must equal wheel.wheel_digest")
        _typed_locator(self.build_provenance_locator, field_name=f"{label}.build_provenance_locator", expected_type=_WHEEL_PROVENANCE_SCHEMA)

    @classmethod
    def from_dict(cls, data: object) -> TripartiteCanonicalSide:
        m = require_exact_keys(data, cls.KEYS, label="tripartite_canonical_side")
        return cls(
            repository=m["repository"], commit_sha=m["commit_sha"],
            wheel=WheelObjectLocator.from_dict(m["wheel"]), wheel_digest=m["wheel_digest"],
            build_provenance_locator=ArtifactLocator.from_dict(m["build_provenance_locator"], expected_type=_WHEEL_PROVENANCE_SCHEMA),
        )


@dataclass(frozen=True, slots=True)
class TripartiteConsumerSide(_SubjectBase):
    """Closed 7-member `consumer_side` inside `tripartite_target` (ADR-0001 §12.6)."""

    KEYS: ClassVar[frozenset[str]] = frozenset(
        {"repository", "commit_sha", "adapter_git_artifact", "feature_flag_git_artifact", "feature_flag_contract_locator", "ibvi_ads_delegation_contract_locator", "consumer_contract_digest"}
    )

    repository: str
    commit_sha: str
    adapter_git_artifact: TripartiteGitArtifactRef
    feature_flag_git_artifact: TripartiteGitArtifactRef
    feature_flag_contract_locator: ArtifactLocator
    ibvi_ads_delegation_contract_locator: ArtifactLocator
    consumer_contract_digest: str

    def __post_init__(self) -> None:
        label = "tripartite_consumer_side"
        if _strict_str(self.repository, field_name=f"{label}.repository") != _CONSUMER_REPOSITORY:
            raise ClosedValidationError(f"{label}.repository: must equal {_CONSUMER_REPOSITORY!r}")
        validate_hex40(_strict_str(self.commit_sha, field_name=f"{label}.commit_sha"), field_name=f"{label}.commit_sha")
        _validate_distinct_git_artifacts(self.adapter_git_artifact, self.feature_flag_git_artifact, label=label)
        _typed_locator(self.feature_flag_contract_locator, field_name=f"{label}.feature_flag_contract_locator", expected_type=ConsumerFeatureFlagContract.SCHEMA)
        _typed_locator(self.ibvi_ads_delegation_contract_locator, field_name=f"{label}.ibvi_ads_delegation_contract_locator", expected_type=IbviAdsDelegationContract.SCHEMA)
        validate_sha256_prefixed(_strict_str(self.consumer_contract_digest, field_name=f"{label}.consumer_contract_digest"), field_name=f"{label}.consumer_contract_digest")

    @classmethod
    def from_dict(cls, data: object) -> TripartiteConsumerSide:
        m = require_exact_keys(data, cls.KEYS, label="tripartite_consumer_side")
        return cls(
            repository=m["repository"], commit_sha=m["commit_sha"],
            adapter_git_artifact=TripartiteGitArtifactRef.from_dict(m["adapter_git_artifact"]),
            feature_flag_git_artifact=TripartiteGitArtifactRef.from_dict(m["feature_flag_git_artifact"]),
            feature_flag_contract_locator=ArtifactLocator.from_dict(m["feature_flag_contract_locator"], expected_type=ConsumerFeatureFlagContract.SCHEMA),
            ibvi_ads_delegation_contract_locator=ArtifactLocator.from_dict(m["ibvi_ads_delegation_contract_locator"], expected_type=IbviAdsDelegationContract.SCHEMA),
            consumer_contract_digest=m["consumer_contract_digest"],
        )


def compute_consumer_contract_digest(
    *,
    adapter_git_artifact: TripartiteGitArtifactRef,
    feature_flag_git_artifact: TripartiteGitArtifactRef,
    resolved_feature_flag_contract_envelope: Mapping[str, Any],
    resolved_delegation_contract_envelope: Mapping[str, Any],
) -> str:
    """Compute role-tagged `consumer_contract_digest` (ADR-0001 §12.6 L3304–3311)."""
    a_art, f_art = _validate_distinct_git_artifacts(adapter_git_artifact, feature_flag_git_artifact, label="consumer_contract_preimage")
    ff_raw = require_mapping(resolved_feature_flag_contract_envelope, label="resolved_feature_flag_contract_envelope")
    dc_raw = require_mapping(resolved_delegation_contract_envelope, label="resolved_delegation_contract_envelope")
    ff_parsed = ConsumerFeatureFlagContract.from_dict(ff_raw)
    dc_parsed = IbviAdsDelegationContract.from_dict(dc_raw)
    if canonicalize_jcs(ff_parsed.to_dict()) != canonicalize_jcs(ff_raw) or canonicalize_jcs(dc_parsed.to_dict()) != canonicalize_jcs(dc_raw):
        raise ClosedValidationError("consumer_contract_preimage: resolved contract envelope failed canonical round-trip")
    return jcs_sha256([
        {"role": "adapter_git_artifact", "artifact": a_art.to_dict()},
        {"role": "feature_flag_git_artifact", "artifact": f_art.to_dict()},
        {"role": "feature_flag_contract", "artifact": dict(ff_raw)},
        {"role": "ibvi_ads_delegation_contract", "artifact": dict(dc_raw)},
    ])


def compute_tripartite_digest(
    *,
    legacy_side: TripartiteLegacySide,
    canonical_side: TripartiteCanonicalSide,
    consumer_side: TripartiteConsumerSide,
) -> str:
    """Compute role-tagged `tripartite_digest` (ADR-0001 §12.6 L3313–3319)."""
    if type(legacy_side) is not TripartiteLegacySide or type(canonical_side) is not TripartiteCanonicalSide or type(consumer_side) is not TripartiteConsumerSide:
        raise ClosedValidationError("tripartite_preimage: expected TripartiteLegacySide, TripartiteCanonicalSide, and TripartiteConsumerSide")
    leg = TripartiteLegacySide.from_dict(legacy_side.to_dict())
    can = TripartiteCanonicalSide.from_dict(canonical_side.to_dict())
    con = TripartiteConsumerSide.from_dict(consumer_side.to_dict())
    return jcs_sha256([
        {"role": "legacy_side", "side": leg.to_dict()},
        {"role": "canonical_side", "side": can.to_dict()},
        {"role": "consumer_side", "side": con.to_dict()},
    ])


@dataclass(frozen=True, slots=True)
class TripartiteTarget(_SubjectBase):
    """Closed 4-member `tripartite_target` binding legacy, canonical, and consumer sides (ADR-0001 §12.6)."""

    KEYS: ClassVar[frozenset[str]] = frozenset({"legacy_side", "canonical_side", "consumer_side", "tripartite_digest"})

    legacy_side: TripartiteLegacySide
    canonical_side: TripartiteCanonicalSide
    consumer_side: TripartiteConsumerSide
    tripartite_digest: str = ""

    def __post_init__(self) -> None:
        expected = compute_tripartite_digest(
            legacy_side=self.legacy_side, canonical_side=self.canonical_side, consumer_side=self.consumer_side
        )
        object.__setattr__(self, "tripartite_digest", _resolve_digest_or_default(self.tripartite_digest, expected, field_name="tripartite_target.tripartite_digest"))

    @classmethod
    def from_dict(cls, data: object) -> TripartiteTarget:
        m = require_exact_keys(data, cls.KEYS, label="tripartite_target")
        digest = validate_sha256_prefixed(_strict_str(m["tripartite_digest"], field_name="tripartite_target.tripartite_digest"), field_name="tripartite_target.tripartite_digest")
        return cls(
            legacy_side=TripartiteLegacySide.from_dict(m["legacy_side"]),
            canonical_side=TripartiteCanonicalSide.from_dict(m["canonical_side"]),
            consumer_side=TripartiteConsumerSide.from_dict(m["consumer_side"]),
            tripartite_digest=digest,
        )


__all__ = [
    "ConsumerDeploymentReadback",
    "ConsumerFeatureFlagContract",
    "IbviAdsDelegationContext",
    "IbviAdsDelegationContract",
    "ReadEntrypointSelector",
    "TripartiteCanonicalSide",
    "TripartiteConsumerSide",
    "TripartiteGitArtifactRef",
    "TripartiteLegacySide",
    "TripartiteTarget",
    "compute_capture_replay_digest",
    "compute_consumer_contract_digest",
    "compute_tripartite_digest",
]
