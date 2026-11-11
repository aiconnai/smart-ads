"""Closed Pipeboard Phase 1 driver contract, pinned d26c73d packet, and transport ceilings (ADR-0001 §4.1)."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import re
from types import MappingProxyType
from typing import Any, ClassVar, Final

from smart_ads.contracts.jcs import (
    ArtifactLocator,
    P1Integrity,
    p1_content_digest,
    self_digest_jcs_sha256,
)
from smart_ads.contracts.scalars import (
    ClosedValidationError,
    require_exact_keys,
    require_mapping,
    validate_hex40,
    validate_non_empty_str,
    validate_opaque_ref,
    validate_sha256_prefixed,
    validate_utf8_nfc,
)
from smart_ads.contracts.schemas import validate_source_metric_ref

PINNED_LEGACY_REPO: Final[str] = "mbras-tech/mbras-campaigns"
PINNED_LEGACY_COMMIT: Final[str] = "d26c73d8508c7c3d43161fe36a80c44a46bf0f2d"
PINNED_PIPEBOARD_D26_SPECS: Final[tuple[tuple[str, str, str, str], ...]] = (
    (
        "reducer",
        "scripts/operator/meta_daily_contract.py",
        "0dbdfede6c4a9eaffb35197118e80d8d72507335",
        "sha256:9e5b2f24a05029980748a9e7a8ae40e00fedc30b9bdf07be532d8a55a7eab9c9",
    ),
    (
        "frozen_config",
        "config/operator/meta_daily_get_insights_v1.yaml",
        "e0c86c24b0a5ac2aa761406bd6df7c4643b99af9",
        "sha256:08591f51a13424115dc1f138753cbee140403ae8c132848e495d367ec71f480e",
    ),
    (
        "generic_gate_limitations",
        "scripts/meta_ads/pipeboard_mcp.py",
        "434be6136972c4316a4593f3fc63250b79eb8f95",
        "sha256:b2fd1efd242067f08a7e0d4445076179736c5cd3e8adfc3181af0778ed7b4206",
    ),
    (
        "strict_transport",
        "scripts/operator/daily_strict_transports.py",
        "dfcaab5c2fa5c57384cfc5052acbf9aedf3d8ae1",
        "sha256:252c078d83ccf7eb726a19aaf226882731d55389c2c8f907491f955b8535e6ac",
    ),
    (
        "transport_limits",
        "scripts/pipeboard_limits.py",
        "306d2b1f5eae7084f5c1daca7f042e1b1d89350b",
        "sha256:cb1b73273d1942fdc9fc334639bd74eaddcf6af3e65a02a29eb8b60f94ff0ce5",
    ),
)

FORBIDDEN_PIPEBOARD_ARGUMENTS: Final[tuple[str, ...]] = (
    "access_token",
    "account_id",
    "action_attribution_windows",
    "action_breakdowns",
    "ad_id",
    "adset_id",
    "after",
    "breakdown",
    "campaign_id",
)

PIPEBOARD_PHASE1_METRIC_SOURCE_MAPPINGS: Final[Mapping[str, str]] = (
    MappingProxyType(
        {
            "metric:clicks_v1": "source-metric:provider:pipeboard.clicks:v1",
            "metric:impressions_v1": "source-metric:provider:pipeboard.impressions:v1",
            "metric:spend_v1": "source-metric:provider:pipeboard.spend:v1",
        }
    )
)

_GIT_ARTIFACT_PROVENANCE_SCHEMA: Final[str] = (
    "smart_ads/git_artifact_provenance/v1"
)
_DRIVER_CONTRACT_ID_RE: Final[re.Pattern[str]] = re.compile(
    r"\Adriver-contract:[A-Za-z0-9._:-]+\Z"
)

_PINNED_MEMBER_KEYS: Final[frozenset[str]] = frozenset(
    {
        "role",
        "repository",
        "commit_sha",
        "path",
        "git_blob_oid",
        "file_content_sha256",
        "git_artifact_provenance_locator",
    }
)
_LEGACY_PACKET_KEYS: Final[frozenset[str]] = frozenset(
    {
        "repository",
        "commit_sha",
        "members",
        "packet_digest",
    }
)
_UPSTREAM_REF_KEYS: Final[frozenset[str]] = frozenset(
    {
        "repository",
        "commit_sha",
        "path",
        "symbol",
        "hosted_parity_proven",
    }
)
_TRANSPORT_LIMITS_KEYS: Final[frozenset[str]] = frozenset(
    {
        "endpoint_url",
        "http_method",
        "connect_timeout_seconds",
        "wall_deadline_seconds",
        "request_content_type",
        "request_accept",
        "request_accept_encoding",
        "read_chunk_bytes",
        "max_streamed_bytes",
        "max_decoded_text_bytes",
        "jsonrpc_method",
        "tool_name",
        "level",
        "limit",
        "compact",
        "max_campaign_rows",
        "forbidden_arguments",
    }
)
_PIPEBOARD_CONTRACT_CORE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "$schema",
        "contract_id",
        "driver_id",
        "legacy_source_packet",
        "upstream_reference",
        "transport_limits",
        "metric_source_mappings",
    }
)


def _require_exact_int(
    value: object,
    expected: int,
    *,
    field_name: str,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value != expected:
        raise ClosedValidationError(
            f"{field_name}: expected exact int {expected}, got {value!r}"
        )
    return value


@dataclass(frozen=True, slots=True)
class PinnedGitArtifactMember:
    """Closed 7-member pinned Git artifact member inside `LegacySourcePacket`."""

    role: str
    repository: str
    commit_sha: str
    path: str
    git_blob_oid: str
    file_content_sha256: str
    git_artifact_provenance_locator: ArtifactLocator

    def __post_init__(self) -> None:
        validate_non_empty_str(
            self.role, field_name="pinned_git_artifact_member.role"
        )
        validate_non_empty_str(
            self.repository, field_name="pinned_git_artifact_member.repository"
        )
        validate_hex40(
            self.commit_sha, field_name="pinned_git_artifact_member.commit_sha"
        )
        validate_non_empty_str(
            self.path, field_name="pinned_git_artifact_member.path"
        )
        validate_hex40(
            self.git_blob_oid,
            field_name="pinned_git_artifact_member.git_blob_oid",
        )
        validate_sha256_prefixed(
            self.file_content_sha256,
            field_name="pinned_git_artifact_member.file_content_sha256",
        )
        if (
            not isinstance(
                self.git_artifact_provenance_locator, ArtifactLocator
            )
            or self.git_artifact_provenance_locator.artifact_type
            != _GIT_ARTIFACT_PROVENANCE_SCHEMA
        ):
            raise ClosedValidationError(
                "pinned_git_artifact_member.git_artifact_provenance_locator: "
                f"expected ArtifactLocator for {_GIT_ARTIFACT_PROVENANCE_SCHEMA!r}"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "repository": self.repository,
            "commit_sha": self.commit_sha,
            "path": self.path,
            "git_blob_oid": self.git_blob_oid,
            "file_content_sha256": self.file_content_sha256,
            "git_artifact_provenance_locator": self.git_artifact_provenance_locator.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: object) -> PinnedGitArtifactMember:
        mapping = require_exact_keys(
            data, _PINNED_MEMBER_KEYS, label="pinned_git_artifact_member"
        )
        return cls(
            role=mapping["role"],
            repository=mapping["repository"],
            commit_sha=mapping["commit_sha"],
            path=mapping["path"],
            git_blob_oid=mapping["git_blob_oid"],
            file_content_sha256=mapping["file_content_sha256"],
            git_artifact_provenance_locator=ArtifactLocator.from_dict(
                mapping["git_artifact_provenance_locator"],
                expected_type=_GIT_ARTIFACT_PROVENANCE_SCHEMA,
            ),
        )


@dataclass(frozen=True, slots=True)
class LegacySourcePacket:
    """Closed 4-member legacy source packet pinned to `mbras-tech/mbras-campaigns@d26c73d`."""

    repository: str
    commit_sha: str
    members: tuple[PinnedGitArtifactMember, ...]
    packet_digest: str = ""

    def __post_init__(self) -> None:
        if self.repository != PINNED_LEGACY_REPO:
            raise ClosedValidationError(
                f"legacy_source_packet.repository: expected {PINNED_LEGACY_REPO!r}, "
                f"got {self.repository!r}"
            )
        if self.commit_sha != PINNED_LEGACY_COMMIT:
            raise ClosedValidationError(
                f"legacy_source_packet.commit_sha: expected {PINNED_LEGACY_COMMIT!r}, "
                f"got {self.commit_sha!r}"
            )
        if not isinstance(self.members, (list, tuple)):
            raise ClosedValidationError(
                "legacy_source_packet.members: expected list or tuple of PinnedGitArtifactMember"
            )
        members_tuple = tuple(self.members)
        if len(members_tuple) != len(PINNED_PIPEBOARD_D26_SPECS):
            raise ClosedValidationError(
                f"legacy_source_packet.members: expected exact {len(PINNED_PIPEBOARD_D26_SPECS)} "
                f"pinned members, got {len(members_tuple)}"
            )
        for member, (exp_role, exp_path, exp_blob, exp_sha) in zip(
            members_tuple, PINNED_PIPEBOARD_D26_SPECS, strict=True
        ):
            if not isinstance(member, PinnedGitArtifactMember):
                raise ClosedValidationError(
                    "legacy_source_packet.members: every element must be PinnedGitArtifactMember"
                )
            if (
                member.role != exp_role
                or member.repository != PINNED_LEGACY_REPO
                or member.commit_sha != PINNED_LEGACY_COMMIT
                or member.path != exp_path
                or member.git_blob_oid != exp_blob
                or member.file_content_sha256 != exp_sha
            ):
                raise ClosedValidationError(
                    f"legacy_source_packet.members: pinned member mismatch for role {exp_role!r}"
                )
        object.__setattr__(self, "members", members_tuple)

        if not isinstance(self.packet_digest, str):
            raise ClosedValidationError(
                "legacy_source_packet.packet_digest: expected str"
            )
        expected_digest = self_digest_jcs_sha256(
            self.to_dict(),
            digest_member="packet_digest",
            strip_integrity=False,
        )
        if self.packet_digest == "":
            object.__setattr__(self, "packet_digest", expected_digest)
        else:
            validate_sha256_prefixed(
                self.packet_digest,
                field_name="legacy_source_packet.packet_digest",
            )
            if self.packet_digest != expected_digest:
                raise ClosedValidationError(
                    "legacy_source_packet.packet_digest: recomputed "
                    f"{expected_digest!r} != asserted {self.packet_digest!r}"
                )

    def to_dict(self) -> dict[str, Any]:
        return {
            "repository": self.repository,
            "commit_sha": self.commit_sha,
            "members": [m.to_dict() for m in self.members],
            "packet_digest": self.packet_digest,
        }

    @classmethod
    def from_dict(cls, data: object) -> LegacySourcePacket:
        mapping = require_exact_keys(
            data, _LEGACY_PACKET_KEYS, label="legacy_source_packet"
        )
        if not isinstance(mapping["members"], list):
            raise ClosedValidationError(
                "legacy_source_packet.members: expected JSON array list"
            )
        digest = validate_sha256_prefixed(
            mapping["packet_digest"],
            field_name="legacy_source_packet.packet_digest",
        )
        parsed_members = tuple(
            PinnedGitArtifactMember.from_dict(item)
            for item in mapping["members"]
        )
        return cls(
            repository=mapping["repository"],
            commit_sha=mapping["commit_sha"],
            members=parsed_members,
            packet_digest=digest,
        )


@dataclass(frozen=True, slots=True)
class PinnedUpstreamReference:
    """Closed 5-member upstream evidence reference (`hosted_parity_proven` MUST be `False`)."""

    repository: str = "pipeboard-co/meta-ads-mcp"
    commit_sha: str = "2ef198e266ca6a37b6dc2c42335f0a0885002771"
    path: str = "meta_ads_mcp/core/insights.py"
    symbol: str = "get_insights"
    hosted_parity_proven: bool = False

    def __post_init__(self) -> None:
        if self.repository != "pipeboard-co/meta-ads-mcp":
            raise ClosedValidationError(
                "pinned_upstream_reference.repository: must equal 'pipeboard-co/meta-ads-mcp'"
            )
        if self.commit_sha != "2ef198e266ca6a37b6dc2c42335f0a0885002771":
            raise ClosedValidationError(
                "pinned_upstream_reference.commit_sha: must equal "
                "'2ef198e266ca6a37b6dc2c42335f0a0885002771'"
            )
        if self.path != "meta_ads_mcp/core/insights.py":
            raise ClosedValidationError(
                "pinned_upstream_reference.path: must equal 'meta_ads_mcp/core/insights.py'"
            )
        if self.symbol != "get_insights":
            raise ClosedValidationError(
                "pinned_upstream_reference.symbol: must equal 'get_insights'"
            )
        if (
            not isinstance(self.hosted_parity_proven, bool)
            or self.hosted_parity_proven is not False
        ):
            raise ClosedValidationError(
                "pinned_upstream_reference.hosted_parity_proven: must be bool False "
                "(upstream code is evidence, never live parity authority)"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "repository": self.repository,
            "commit_sha": self.commit_sha,
            "path": self.path,
            "symbol": self.symbol,
            "hosted_parity_proven": self.hosted_parity_proven,
        }

    @classmethod
    def from_dict(cls, data: object) -> PinnedUpstreamReference:
        mapping = require_exact_keys(
            data, _UPSTREAM_REF_KEYS, label="pinned_upstream_reference"
        )
        return cls(
            repository=mapping["repository"],
            commit_sha=mapping["commit_sha"],
            path=mapping["path"],
            symbol=mapping["symbol"],
            hosted_parity_proven=mapping["hosted_parity_proven"],
        )


@dataclass(frozen=True, slots=True)
class PipeboardTransportLimits:
    """Closed 17-member Pipeboard HTTP, JSON-RPC, byte-ceiling, and argument limits (ADR-0001 §4.1)."""

    endpoint_url: str = "https://meta-ads.mcp.pipeboard.co/"
    http_method: str = "POST"
    connect_timeout_seconds: int = 5
    wall_deadline_seconds: int = 60
    request_content_type: str = "application/json"
    request_accept: str = "application/json, text/event-stream"
    request_accept_encoding: str = "identity"
    read_chunk_bytes: int = 65536
    max_streamed_bytes: int = 2_097_152
    max_decoded_text_bytes: int = 2_097_152
    jsonrpc_method: str = "tools/call"
    tool_name: str = "get_insights"
    level: str = "campaign"
    limit: int = 100
    compact: bool = True
    max_campaign_rows: int = 100
    forbidden_arguments: tuple[str, ...] = FORBIDDEN_PIPEBOARD_ARGUMENTS

    def __post_init__(self) -> None:
        if self.endpoint_url != "https://meta-ads.mcp.pipeboard.co/":
            raise ClosedValidationError(
                "pipeboard_transport_limits.endpoint_url: must equal 'https://meta-ads.mcp.pipeboard.co/'"
            )
        if self.http_method != "POST":
            raise ClosedValidationError(
                "pipeboard_transport_limits.http_method: must equal 'POST'"
            )
        _require_exact_int(
            self.connect_timeout_seconds,
            5,
            field_name="pipeboard_transport_limits.connect_timeout_seconds",
        )
        _require_exact_int(
            self.wall_deadline_seconds,
            60,
            field_name="pipeboard_transport_limits.wall_deadline_seconds",
        )
        if self.request_content_type != "application/json":
            raise ClosedValidationError(
                "pipeboard_transport_limits.request_content_type: must equal 'application/json'"
            )
        if self.request_accept != "application/json, text/event-stream":
            raise ClosedValidationError(
                "pipeboard_transport_limits.request_accept: must equal "
                "'application/json, text/event-stream'"
            )
        if self.request_accept_encoding != "identity":
            raise ClosedValidationError(
                "pipeboard_transport_limits.request_accept_encoding: must equal 'identity'"
            )
        _require_exact_int(
            self.read_chunk_bytes,
            65536,
            field_name="pipeboard_transport_limits.read_chunk_bytes",
        )
        _require_exact_int(
            self.max_streamed_bytes,
            2_097_152,
            field_name="pipeboard_transport_limits.max_streamed_bytes",
        )
        _require_exact_int(
            self.max_decoded_text_bytes,
            2_097_152,
            field_name="pipeboard_transport_limits.max_decoded_text_bytes",
        )
        if self.jsonrpc_method != "tools/call":
            raise ClosedValidationError(
                "pipeboard_transport_limits.jsonrpc_method: must equal 'tools/call'"
            )
        if self.tool_name != "get_insights":
            raise ClosedValidationError(
                "pipeboard_transport_limits.tool_name: must equal 'get_insights'"
            )
        if self.level != "campaign":
            raise ClosedValidationError(
                "pipeboard_transport_limits.level: must equal 'campaign'"
            )
        _require_exact_int(
            self.limit, 100, field_name="pipeboard_transport_limits.limit"
        )
        if not isinstance(self.compact, bool) or self.compact is not True:
            raise ClosedValidationError(
                "pipeboard_transport_limits.compact: must be bool True"
            )
        _require_exact_int(
            self.max_campaign_rows,
            100,
            field_name="pipeboard_transport_limits.max_campaign_rows",
        )
        if not isinstance(self.forbidden_arguments, (list, tuple)):
            raise ClosedValidationError(
                "pipeboard_transport_limits.forbidden_arguments: expected list or tuple"
            )
        forbidden_tuple = tuple(self.forbidden_arguments)
        if forbidden_tuple != FORBIDDEN_PIPEBOARD_ARGUMENTS:
            raise ClosedValidationError(
                "pipeboard_transport_limits.forbidden_arguments: must equal "
                "FORBIDDEN_PIPEBOARD_ARGUMENTS"
            )
        object.__setattr__(self, "forbidden_arguments", forbidden_tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "endpoint_url": self.endpoint_url,
            "http_method": self.http_method,
            "connect_timeout_seconds": self.connect_timeout_seconds,
            "wall_deadline_seconds": self.wall_deadline_seconds,
            "request_content_type": self.request_content_type,
            "request_accept": self.request_accept,
            "request_accept_encoding": self.request_accept_encoding,
            "read_chunk_bytes": self.read_chunk_bytes,
            "max_streamed_bytes": self.max_streamed_bytes,
            "max_decoded_text_bytes": self.max_decoded_text_bytes,
            "jsonrpc_method": self.jsonrpc_method,
            "tool_name": self.tool_name,
            "level": self.level,
            "limit": self.limit,
            "compact": self.compact,
            "max_campaign_rows": self.max_campaign_rows,
            "forbidden_arguments": list(self.forbidden_arguments),
        }

    @classmethod
    def from_dict(cls, data: object) -> PipeboardTransportLimits:
        mapping = require_exact_keys(
            data, _TRANSPORT_LIMITS_KEYS, label="pipeboard_transport_limits"
        )
        if not isinstance(mapping["forbidden_arguments"], list):
            raise ClosedValidationError(
                "pipeboard_transport_limits.forbidden_arguments: expected JSON array list"
            )
        return cls(
            endpoint_url=mapping["endpoint_url"],
            http_method=mapping["http_method"],
            connect_timeout_seconds=mapping["connect_timeout_seconds"],
            wall_deadline_seconds=mapping["wall_deadline_seconds"],
            request_content_type=mapping["request_content_type"],
            request_accept=mapping["request_accept"],
            request_accept_encoding=mapping["request_accept_encoding"],
            read_chunk_bytes=mapping["read_chunk_bytes"],
            max_streamed_bytes=mapping["max_streamed_bytes"],
            max_decoded_text_bytes=mapping["max_decoded_text_bytes"],
            jsonrpc_method=mapping["jsonrpc_method"],
            tool_name=mapping["tool_name"],
            level=mapping["level"],
            limit=mapping["limit"],
            compact=mapping["compact"],
            max_campaign_rows=mapping["max_campaign_rows"],
            forbidden_arguments=tuple(mapping["forbidden_arguments"]),
        )


@dataclass(frozen=True, slots=True)
class PipeboardPhase1Contract:
    """Closed `smart_ads/pipeboard_phase1_contract/v1` P1 envelope (ADR-0001 §4.1)."""

    SCHEMA: ClassVar[str] = "smart_ads/pipeboard_phase1_contract/v1"

    contract_id: str
    driver_id: str
    legacy_source_packet: LegacySourcePacket
    upstream_reference: PinnedUpstreamReference
    transport_limits: PipeboardTransportLimits
    metric_source_mappings: Mapping[str, str]
    integrity: P1Integrity | None = None

    def __post_init__(self) -> None:
        checked_contract_id = validate_utf8_nfc(
            self.contract_id,
            field_name="pipeboard_phase1_contract.contract_id",
            allow_empty=False,
        )
        if not _DRIVER_CONTRACT_ID_RE.fullmatch(checked_contract_id):
            raise ClosedValidationError(
                f"pipeboard_phase1_contract.contract_id: expected 'driver-contract:<id>', "
                f"got {self.contract_id!r}"
            )
        if self.driver_id != "pipeboard_hosted":
            raise ClosedValidationError(
                "pipeboard_phase1_contract.driver_id: must equal 'pipeboard_hosted'"
            )
        if not isinstance(self.legacy_source_packet, LegacySourcePacket):
            raise ClosedValidationError(
                "pipeboard_phase1_contract.legacy_source_packet: expected LegacySourcePacket"
            )
        if not isinstance(self.upstream_reference, PinnedUpstreamReference):
            raise ClosedValidationError(
                "pipeboard_phase1_contract.upstream_reference: expected PinnedUpstreamReference"
            )
        if not isinstance(self.transport_limits, PipeboardTransportLimits):
            raise ClosedValidationError(
                "pipeboard_phase1_contract.transport_limits: expected PipeboardTransportLimits"
            )

        checked_map = require_mapping(
            self.metric_source_mappings,
            label="pipeboard_phase1_contract.metric_source_mappings",
        )
        normalized_map: dict[str, str] = {}
        for k, v in checked_map.items():
            validate_opaque_ref(
                k,
                field_name="pipeboard_phase1_contract.metric_source_mappings.key",
                expected_prefix="metric",
            )
            validate_source_metric_ref(
                v,
                field_name="pipeboard_phase1_contract.metric_source_mappings.value",
            )
            normalized_map[k] = v
        if normalized_map != dict(PIPEBOARD_PHASE1_METRIC_SOURCE_MAPPINGS):
            raise ClosedValidationError(
                "pipeboard_phase1_contract.metric_source_mappings: must match "
                "PIPEBOARD_PHASE1_METRIC_SOURCE_MAPPINGS"
            )
        object.__setattr__(
            self,
            "metric_source_mappings",
            MappingProxyType(dict(sorted(normalized_map.items()))),
        )

        if self.integrity is not None and not isinstance(
            self.integrity, P1Integrity
        ):
            raise ClosedValidationError(
                "pipeboard_phase1_contract.integrity: expected P1Integrity or None"
            )
        if self.integrity is not None and self.integrity.is_signed:
            expected_p1 = p1_content_digest(self.to_dict())
            if self.integrity.content_digest != expected_p1:
                raise ClosedValidationError(
                    "pipeboard_phase1_contract.integrity.content_digest: recomputed "
                    f"{expected_p1!r} != asserted {self.integrity.content_digest!r}"
                )

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "$schema": self.SCHEMA,
            "contract_id": self.contract_id,
            "driver_id": self.driver_id,
            "legacy_source_packet": self.legacy_source_packet.to_dict(),
            "upstream_reference": self.upstream_reference.to_dict(),
            "transport_limits": self.transport_limits.to_dict(),
            "metric_source_mappings": dict(self.metric_source_mappings),
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
    ) -> PipeboardPhase1Contract:
        if not isinstance(require_signed, bool):
            raise ClosedValidationError("require_signed: expected bool")
        mapping = require_mapping(data, label="pipeboard_phase1_contract")
        if require_signed or "integrity" in mapping:
            require_exact_keys(
                mapping,
                _PIPEBOARD_CONTRACT_CORE_KEYS | {"integrity"},
                label="pipeboard_phase1_contract",
            )
            integrity: P1Integrity | None = P1Integrity.from_dict(
                mapping["integrity"], require_signed=require_signed
            )
        else:
            require_exact_keys(
                mapping,
                _PIPEBOARD_CONTRACT_CORE_KEYS,
                label="pipeboard_phase1_contract",
            )
            integrity = None

        if mapping["$schema"] != cls.SCHEMA:
            raise ClosedValidationError(
                f"pipeboard_phase1_contract.$schema: expected {cls.SCHEMA!r}, "
                f"got {mapping['$schema']!r}"
            )
        return cls(
            contract_id=mapping["contract_id"],
            driver_id=mapping["driver_id"],
            legacy_source_packet=LegacySourcePacket.from_dict(
                mapping["legacy_source_packet"]
            ),
            upstream_reference=PinnedUpstreamReference.from_dict(
                mapping["upstream_reference"]
            ),
            transport_limits=PipeboardTransportLimits.from_dict(
                mapping["transport_limits"]
            ),
            metric_source_mappings=mapping["metric_source_mappings"],
            integrity=integrity,
        )


__all__ = [
    "FORBIDDEN_PIPEBOARD_ARGUMENTS",
    "LegacySourcePacket",
    "PINNED_LEGACY_COMMIT",
    "PINNED_LEGACY_REPO",
    "PINNED_PIPEBOARD_D26_SPECS",
    "PIPEBOARD_PHASE1_METRIC_SOURCE_MAPPINGS",
    "PinnedGitArtifactMember",
    "PinnedUpstreamReference",
    "PipeboardPhase1Contract",
    "PipeboardTransportLimits",
]
