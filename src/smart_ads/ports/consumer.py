"""Pure consumer verification, AST routing analysis, offline intelligence, and seam projection ports (ADR-0001 §§3.3, 12.6)."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from itertools import pairwise
from types import MappingProxyType
from typing import Any, Protocol, runtime_checkable

from smart_ads.analytics.intelligence import AnalysisEvidence, EvaluationContext, Finding
from smart_ads.contracts.consumer import ConsumerFeatureFlagContract
from smart_ads.contracts.jcs import canonicalize_jcs, loads_strict_json
from smart_ads.contracts.operational_evidence import AlgorithmProvenanceIdentity
from smart_ads.contracts.scalars import ClosedValidationError
from smart_ads.ports.storage import CellObjectStorePort


def _freeze_jcs_value(val: Any) -> Any:
    if isinstance(val, Mapping):
        return MappingProxyType({k: _freeze_jcs_value(v) for k, v in val.items()})
    if isinstance(val, (list, tuple)):
        return tuple(_freeze_jcs_value(item) for item in val)
    return val


def _require_strict_non_empty_str(value: object, *, field_name: str) -> str:
    if type(value) is not str or not value or value != value.strip():
        raise ClosedValidationError(
            f"{field_name}: expected non-empty trimmed str, got {value!r}"
        )
    return value


def _require_sorted_unique_str_tuple(
    values: object, *, field_name: str
) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple)):
        raise ClosedValidationError(f"{field_name}: expected list or tuple of str")
    checked = tuple(
        _require_strict_non_empty_str(item, field_name=f"{field_name}[{idx}]")
        for idx, item in enumerate(values)
    )
    encoded = [item.encode("utf-8") for item in checked]
    if any(left >= right for left, right in pairwise(encoded)):
        raise ClosedValidationError(
            f"{field_name}: entries must be strictly sorted and unique by UTF-8 bytes"
        )
    return checked


def _require_sorted_route_facts(
    values: object, *, field_name: str
) -> tuple[EntrypointRouteFacts, ...]:
    if not isinstance(values, (list, tuple)):
        raise ClosedValidationError(
            f"{field_name}: expected list or tuple of EntrypointRouteFacts"
        )
    out: list[EntrypointRouteFacts] = []
    keys: list[bytes] = []
    for idx, item in enumerate(values):
        if type(item) is not EntrypointRouteFacts:
            raise ClosedValidationError(
                f"{field_name}[{idx}]: expected EntrypointRouteFacts"
            )
        out.append(item)
        keys.append(item.symbol_name.encode("utf-8"))
    if any(left >= right for left, right in pairwise(keys)):
        raise ClosedValidationError(
            f"{field_name}: route facts must be strictly sorted and unique by symbol_name"
        )
    return tuple(out)


@runtime_checkable
class P1SignatureVerifierPort(Protocol):
    """Cryptographic Ed25519 P1 envelope verifier against an immutable object store."""

    def verify_p1_envelope_signature(
        self,
        *,
        envelope: Mapping[str, Any],
        domain_prefix: str,
        store: CellObjectStorePort,
    ) -> None:
        """Verify Ed25519 signature, key registry authorization, and P1 preimage digest."""
        ...


@dataclass(frozen=True, slots=True)
class EntrypointRouteFacts:
    """Verified 2-way routing facts extracted from a consumer public entrypoint."""

    symbol_name: str
    flag_key: str
    true_route: str
    true_mcp_method: str
    false_route: str

    def __post_init__(self) -> None:
        _require_strict_non_empty_str(
            self.symbol_name, field_name="entrypoint_route_facts.symbol_name"
        )
        _require_strict_non_empty_str(
            self.flag_key, field_name="entrypoint_route_facts.flag_key"
        )
        _require_strict_non_empty_str(
            self.true_route, field_name="entrypoint_route_facts.true_route"
        )
        _require_strict_non_empty_str(
            self.true_mcp_method, field_name="entrypoint_route_facts.true_mcp_method"
        )
        _require_strict_non_empty_str(
            self.false_route, field_name="entrypoint_route_facts.false_route"
        )


@dataclass(frozen=True, slots=True)
class ConsumerRoutingAnalysis:
    """Closed result of static AST routing and feature-flag default verification."""

    flag_key: str
    default_enabled: bool
    disabled_legacy_route: str
    enabled_smart_ads_route: str
    discovered_public_entrypoints: tuple[str, ...]
    verified_entrypoints: tuple[EntrypointRouteFacts, ...]

    def __post_init__(self) -> None:
        _require_strict_non_empty_str(
            self.flag_key, field_name="consumer_routing_analysis.flag_key"
        )
        if type(self.default_enabled) is not bool:
            raise ClosedValidationError(
                "consumer_routing_analysis.default_enabled: expected strict bool"
            )
        _require_strict_non_empty_str(
            self.disabled_legacy_route,
            field_name="consumer_routing_analysis.disabled_legacy_route",
        )
        _require_strict_non_empty_str(
            self.enabled_smart_ads_route,
            field_name="consumer_routing_analysis.enabled_smart_ads_route",
        )
        object.__setattr__(
            self,
            "discovered_public_entrypoints",
            _require_sorted_unique_str_tuple(
                self.discovered_public_entrypoints,
                field_name="consumer_routing_analysis.discovered_public_entrypoints",
            ),
        )
        object.__setattr__(
            self,
            "verified_entrypoints",
            _require_sorted_route_facts(
                self.verified_entrypoints,
                field_name="consumer_routing_analysis.verified_entrypoints",
            ),
        )


@runtime_checkable
class ConsumerRoutingAnalyzerPort(Protocol):
    """Static zero-execution consumer adapter & feature-flag routing analyzer port."""

    def analyze_consumer_routing(
        self,
        *,
        adapter_bytes: bytes,
        feature_flag_bytes: bytes,
        contract: ConsumerFeatureFlagContract,
    ) -> ConsumerRoutingAnalysis:
        """Statically verify consumer feature-flag defaults and 2-way `/ibvi-ads` routing."""
        ...


@runtime_checkable
class OfflineIntelligencePort(Protocol):
    """Offline deterministic intelligence evaluator port carrying provenance identity."""

    @property
    def algorithm_identity(self) -> AlgorithmProvenanceIdentity:
        """Return closed 10-member `AlgorithmProvenanceIdentity` of the evaluator."""
        ...

    def evaluate_offline(
        self,
        *,
        context: EvaluationContext,
        evidence: Sequence[AnalysisEvidence],
    ) -> tuple[Finding, ...]:
        """Evaluate verified offline `evidence` under `context` and emit sorted `Finding`s."""
        ...


@dataclass(frozen=True, slots=True)
class SeamDualProjectionCase:
    """Closed dual-projection parity test case pairing MCP wire input and legacy payload."""

    case_id: str
    surface_id: str
    mcp_wire_request_bytes: bytes
    mcp_runtime_context: Any
    legacy_input_payload: Mapping[str, Any]

    def __post_init__(self) -> None:
        _require_strict_non_empty_str(
            self.case_id, field_name="seam_dual_projection_case.case_id"
        )
        _require_strict_non_empty_str(
            self.surface_id, field_name="seam_dual_projection_case.surface_id"
        )
        if type(self.mcp_wire_request_bytes) is not bytes or not self.mcp_wire_request_bytes:
            raise ClosedValidationError(
                "seam_dual_projection_case.mcp_wire_request_bytes: expected non-empty bytes"
            )
        if not isinstance(self.legacy_input_payload, Mapping):
            raise ClosedValidationError(
                "seam_dual_projection_case.legacy_input_payload: expected Mapping"
            )
        normalized = loads_strict_json(
            canonicalize_jcs(self.legacy_input_payload).decode("utf-8")
        )
        if not isinstance(normalized, Mapping):
            raise ClosedValidationError(
                "seam_dual_projection_case.legacy_input_payload: expected JSON object"
            )
        object.__setattr__(
            self,
            "legacy_input_payload",
            _freeze_jcs_value(normalized),
        )


@runtime_checkable
class SeamLegacyProjectorPort(Protocol):
    """Pure legacy compatibility-surface projector port for seam parity verification."""

    def project_legacy_surface(
        self,
        *,
        surface_id: str,
        mapping_contract_ref: str,
        case: SeamDualProjectionCase,
    ) -> Mapping[str, Any]:
        """Project `case.legacy_input_payload` onto `surface_id` under `mapping_contract_ref`."""
        ...


__all__ = [
    "ConsumerRoutingAnalysis",
    "ConsumerRoutingAnalyzerPort",
    "EntrypointRouteFacts",
    "OfflineIntelligencePort",
    "P1SignatureVerifierPort",
    "SeamDualProjectionCase",
    "SeamLegacyProjectorPort",
]
