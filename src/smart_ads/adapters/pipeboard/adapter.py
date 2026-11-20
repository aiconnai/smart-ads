"""Zero-I/O Pipeboard private binding boundary, Gates 1–3, and offline 7A fixture adapter (ADR-0001 §§4.1, 4.2)."""
from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
import re
from types import MappingProxyType
from typing import Any, Final

from smart_ads.adapters.pipeboard.reducer import (
    META_CAMPAIGN_ID_RE,
    PINNED_PIPEBOARD_ROW_KEYS,
    PipeboardRowReducer,
    parse_campaign_row_metrics,
    reduce_pipeboard_insights_result,
)
from smart_ads.adapters.pipeboard.wire import (
    STATIC_DETAIL_BY_CODE,
    ParsedPipeboardEnvelope,
    PipeboardAdapterError,
    PipeboardWireRejection,
    build_pipeboard_insights_request,
    make_wire_rejection,
    parse_pipeboard_http_and_mcp_envelope,
)
from smart_ads.contracts.jcs import ArtifactLocator, canonicalize_jcs
from smart_ads.contracts.numerics import MAX_INT64, PHASE1_BASE_METRICS
from smart_ads.contracts.scalars import ClosedValidationError
from smart_ads.contracts.schemas import (
    AdmittedCollection, DateRange, NormalizedProviderError, RetrievalContext,
)
from smart_ads.domain.registry import ExpectedResourceInventory
from smart_ads.domain.resource_ref import (
    BidirectionalResourceDirectory, TenantResourceKeyHandle,
)
from smart_ads.ports.cell_runtime import ExpectedInventoryPort, ResolvedRegistryState
from smart_ads.ports.provider import (
    AdmittedFixtureCall, ExternalIOCounters, FixtureObservationPort,
    ProviderObservationBatch, SanitizedMetricObservation, SanitizedResourceObservation,
)

_META_ACCOUNT_ID_RE: Final[re.Pattern[str]] = re.compile(r"\Aact_[1-9][0-9]{5,31}\Z")
_REDUCER_KEY_TO_METRIC_REF: Final[Mapping[str, str]] = MappingProxyType(
    {"clicks": "metric:clicks_v1", "impressions": "metric:impressions_v1", "spend_minor": "metric:spend_v1"}
)
_ALLOWED_REDUCER_KEYS: Final[frozenset[str]] = frozenset(_REDUCER_KEY_TO_METRIC_REF.keys())


def _init_or_verify_directory(
    resolved_registry: ResolvedRegistryState,
    *,
    resource_directory: BidirectionalResourceDirectory | None,
    key_handle: TenantResourceKeyHandle | None,
) -> BidirectionalResourceDirectory:
    snap = resolved_registry.snapshot
    if resource_directory is not None and key_handle is not None:
        raise PipeboardAdapterError("invalid_boundary_config") from None
    if resource_directory is None:
        if not isinstance(key_handle, TenantResourceKeyHandle):
            raise PipeboardAdapterError("invalid_boundary_config") from None
        if (
            key_handle.tenant_ref != snap.tenant_ref
            or key_handle.key_identity != snap.key_identity
        ):
            raise PipeboardAdapterError("invalid_boundary_config") from None
        try:
            return BidirectionalResourceDirectory(
                key_handle=key_handle,
                mapping_version=snap.resource_ref_mapping_version,
                domain_separator=snap.domain_separator,
                ad_platform_ref="meta",
                resource_level="campaign",
            )
        except ClosedValidationError:
            raise PipeboardAdapterError("invalid_boundary_config") from None

    if not isinstance(resource_directory, BidirectionalResourceDirectory):
        raise PipeboardAdapterError("invalid_boundary_config") from None
    if (
        resource_directory.tenant_ref != snap.tenant_ref
        or resource_directory.key_identity != snap.key_identity
        or resource_directory.mapping_version != snap.resource_ref_mapping_version
        or resource_directory.domain_separator != snap.domain_separator
        or resource_directory.ad_platform_ref != "meta"
        or resource_directory.resource_level != "campaign"
    ):
        raise PipeboardAdapterError("invalid_boundary_config") from None
    return resource_directory


class PrivatePipeboardBindingBoundary(ExpectedInventoryPort):
    """Private registry boundary holding redacted `act_*` bindings, HMAC directory, and authenticated `U`."""

    resolved_registry: ResolvedRegistryState
    resource_directory: BidirectionalResourceDirectory

    def __init__(
        self,
        *,
        resolved_registry: ResolvedRegistryState,
        resource_directory: BidirectionalResourceDirectory | None = None,
        key_handle: TenantResourceKeyHandle | None = None,
        private_account_bindings: Mapping[tuple[str, str], str] | None = None,
        authenticated_inventories: Iterable[
            tuple[ArtifactLocator, ExpectedResourceInventory]
        ] = (),
    ) -> None:
        if (
            not isinstance(resolved_registry, ResolvedRegistryState)
            or resolved_registry.driver_contract.driver_id != "pipeboard_hosted"
        ):
            raise PipeboardAdapterError("invalid_boundary_config") from None
        self.resolved_registry = resolved_registry
        self.resource_directory = _init_or_verify_directory(
            resolved_registry,
            resource_directory=resource_directory,
            key_handle=key_handle,
        )
        self._private_bindings: dict[tuple[str, str], str] = {}
        self._inventories: dict[
            tuple[str, str, str, DateRange],
            tuple[ArtifactLocator, ExpectedResourceInventory],
        ] = {}
        if private_account_bindings is not None:
            if not isinstance(private_account_bindings, Mapping):
                raise PipeboardAdapterError("invalid_boundary_config") from None
            for pair, obj_id in private_account_bindings.items():
                if not isinstance(pair, tuple) or len(pair) != 2:
                    raise PipeboardAdapterError("invalid_boundary_config") from None
                self.register_private_binding(
                    binding_ref=pair[0], account_ref=pair[1], private_object_id=obj_id
                )
        if isinstance(authenticated_inventories, (str, bytes, bytearray)) or not isinstance(
            authenticated_inventories, Iterable
        ):
            raise PipeboardAdapterError("invalid_boundary_config") from None
        for entry in authenticated_inventories:
            if not isinstance(entry, tuple) or len(entry) != 2:
                raise PipeboardAdapterError("invalid_boundary_config") from None
            self.register_authenticated_inventory(entry[0], entry[1])

    def __repr__(self) -> str:
        return (
            "PrivatePipeboardBindingBoundary("
            f"tenant_ref={self.resolved_registry.snapshot.tenant_ref!r}, "
            f"bindings={len(self._private_bindings)}, "
            f"inventories={len(self._inventories)}, "
            "private_ids=<REDACTED>)"
        )

    def __str__(self) -> str:
        return self.__repr__()

    def register_private_binding(
        self,
        *,
        binding_ref: str,
        account_ref: str,
        private_object_id: str,
    ) -> None:
        """Bind `(binding_ref, account_ref)` from snapshot to a private Meta `act_*` object ID."""
        if (
            type(binding_ref) is not str
            or type(account_ref) is not str
            or type(private_object_id) is not str
            or _META_ACCOUNT_ID_RE.fullmatch(private_object_id) is None
        ):
            raise PipeboardAdapterError("invalid_private_object_id") from None
        try:
            reg_binding = self.resolved_registry.snapshot.get_binding(binding_ref)
        except ClosedValidationError:
            raise PipeboardAdapterError("unregistered_private_binding") from None
        if (
            reg_binding.account_ref != account_ref
            or reg_binding.driver_id != "pipeboard_hosted"
            or reg_binding.ad_platform_ref != "meta"
            or reg_binding.currency != "BRL"
        ):
            raise PipeboardAdapterError("unregistered_private_binding") from None
        key = (binding_ref, account_ref)
        existing = self._private_bindings.get(key)
        if existing is not None and existing != private_object_id:
            raise PipeboardAdapterError("invalid_boundary_config") from None
        self._private_bindings[key] = private_object_id

    def register_verified_campaign_pair(
        self, raw_campaign_id: str, resource_ref: str
    ) -> None:
        """Verify HMAC derivation and register `(raw_campaign_id, resource_ref)` in `resource_directory`."""
        if (
            type(raw_campaign_id) is not str
            or META_CAMPAIGN_ID_RE.fullmatch(raw_campaign_id) is None
            or type(resource_ref) is not str
        ):
            raise PipeboardAdapterError("invalid_boundary_config") from None
        try:
            self.resource_directory.register_verified_pair(raw_campaign_id, resource_ref)
        except ClosedValidationError:
            raise PipeboardAdapterError("invalid_boundary_config") from None

    def register_authenticated_inventory(
        self,
        locator: ArtifactLocator,
        inventory: ExpectedResourceInventory,
    ) -> None:
        """Verify canonical locator and 7-tuple snapshot/scope binding of `ExpectedResourceInventory`."""
        if (
            not isinstance(locator, ArtifactLocator)
            or locator.artifact_type != ExpectedResourceInventory.SCHEMA
            or not isinstance(inventory, ExpectedResourceInventory)
        ):
            raise PipeboardAdapterError("invalid_boundary_config") from None
        expected_loc = ArtifactLocator.for_canonical_bytes(
            ExpectedResourceInventory.SCHEMA, canonicalize_jcs(inventory.to_dict())
        )
        snap = self.resolved_registry.snapshot
        auth_pairs = {(s.binding_ref, s.resource_scope_ref) for s in snap.authorized_scopes}
        try:
            reg_binding = snap.get_binding(inventory.binding_ref)
        except ClosedValidationError:
            raise PipeboardAdapterError("invalid_boundary_config") from None
        if (
            expected_loc != locator
            or inventory.registry_snapshot_locator != self.resolved_registry.locator
            or inventory.registry_snapshot_digest != self.resolved_registry.locator.content_digest
            or inventory.tenant_ref != snap.tenant_ref
            or reg_binding.account_ref != inventory.account_ref
            or reg_binding.driver_id != "pipeboard_hosted"
            or (inventory.binding_ref, inventory.resource_scope_ref) not in auth_pairs
            or inventory.date_range.start_date != inventory.date_range.end_date
        ):
            raise PipeboardAdapterError("invalid_boundary_config") from None
        inv_key = (
            inventory.binding_ref,
            inventory.account_ref,
            inventory.resource_scope_ref,
            inventory.date_range,
        )
        existing = self._inventories.get(inv_key)
        if existing is not None and existing != (locator, inventory):
            raise PipeboardAdapterError("invalid_boundary_config") from None
        self._inventories[inv_key] = (locator, inventory)

    def resolve_private_object_id(self, *, binding_ref: str, account_ref: str) -> str:
        """Resolve private Meta `act_*` ID for `(binding_ref, account_ref)`, failing closed if absent."""
        if type(binding_ref) is not str or type(account_ref) is not str:
            raise PipeboardAdapterError("unregistered_private_binding") from None
        private_id = self._private_bindings.get((binding_ref, account_ref))
        if private_id is None:
            raise PipeboardAdapterError("unregistered_private_binding") from None
        return private_id

    def resolve_authenticated_inventory(
        self,
        *,
        binding_ref: str,
        account_ref: str,
        resource_scope_ref: str,
        date_range: DateRange,
    ) -> tuple[ArtifactLocator, ExpectedResourceInventory]:
        """Resolve `(locator, ExpectedResourceInventory)` for the admitted 4-tuple or fail closed."""
        if (
            type(binding_ref) is not str
            or type(account_ref) is not str
            or type(resource_scope_ref) is not str
            or not isinstance(date_range, DateRange)
        ):
            raise PipeboardAdapterError("admission_snapshot_mismatch") from None
        pair = self._inventories.get((binding_ref, account_ref, resource_scope_ref, date_range))
        if pair is None:
            raise PipeboardAdapterError("admission_snapshot_mismatch") from None
        return pair

    def resolve_expected_inventory(
        self,
        *,
        registry_snapshot_locator: ArtifactLocator,
        tenant_ref: str,
        binding_ref: str,
        account_ref: str,
        resource_scope_ref: str,
        date_range: DateRange,
    ) -> ExpectedResourceInventory | None:
        """Implement `ExpectedInventoryPort` returning the exact authenticated `ExpectedResourceInventory`."""
        if (
            not isinstance(registry_snapshot_locator, ArtifactLocator)
            or type(tenant_ref) is not str
            or type(binding_ref) is not str
            or type(account_ref) is not str
            or type(resource_scope_ref) is not str
            or not isinstance(date_range, DateRange)
        ):
            raise PipeboardAdapterError("invalid_boundary_config") from None
        if (
            registry_snapshot_locator != self.resolved_registry.locator
            or tenant_ref != self.resolved_registry.snapshot.tenant_ref
        ):
            return None
        pair = self._inventories.get((binding_ref, account_ref, resource_scope_ref, date_range))
        return None if pair is None else pair[1]


def _check_phase1_admitted_compatibility(admitted: AdmittedCollection) -> None:
    cqc = admitted.canonical_query_contract
    if (
        admitted.driver_id != "pipeboard_hosted"
        or cqc.ad_platform_ref != "meta"
        or cqc.resource_level != "campaign"
        or cqc.breakdowns != ()
        or cqc.currency != "BRL"
        or admitted.computed_date_range.start_date != admitted.computed_date_range.end_date
    ):
        raise PipeboardAdapterError("invalid_admitted_collection") from None


def _verify_admitted_against_boundary(
    admitted: AdmittedCollection,
    boundary: PrivatePipeboardBindingBoundary,
) -> ExpectedResourceInventory:
    _check_phase1_admitted_compatibility(admitted)
    reg = boundary.resolved_registry
    snap = reg.snapshot
    auth_pairs = {(s.binding_ref, s.resource_scope_ref) for s in snap.authorized_scopes}
    if (
        admitted.registry_snapshot_locator != reg.locator
        or admitted.registry_snapshot_digest != reg.locator.content_digest
        or admitted.driver_contract_locator != reg.driver_contract_locator
        or admitted.driver_contract_digest != reg.driver_contract_locator.content_digest
        or admitted.canonical_query_contract.tenant_ref != snap.tenant_ref
        or admitted.tenant_ref != snap.tenant_ref
        or (admitted.binding_ref, admitted.resource_scope_ref) not in auth_pairs
    ):
        raise PipeboardAdapterError("admission_snapshot_mismatch") from None

    inv_loc, inv = boundary.resolve_authenticated_inventory(
        binding_ref=admitted.binding_ref,
        account_ref=admitted.account_ref,
        resource_scope_ref=admitted.resource_scope_ref,
        date_range=admitted.computed_date_range,
    )
    recomputed_inv_loc = ArtifactLocator.for_canonical_bytes(
        ExpectedResourceInventory.SCHEMA, canonicalize_jcs(inv.to_dict())
    )
    expected_7tuple = (
        admitted.registry_snapshot_locator,
        admitted.registry_snapshot_locator.content_digest,
        admitted.tenant_ref,
        admitted.binding_ref,
        admitted.account_ref,
        admitted.resource_scope_ref,
        admitted.computed_date_range,
    )
    actual_7tuple = (
        inv.registry_snapshot_locator,
        inv.registry_snapshot_digest,
        inv.tenant_ref,
        inv.binding_ref,
        inv.account_ref,
        inv.resource_scope_ref,
        inv.date_range,
    )
    if recomputed_inv_loc != inv_loc or actual_7tuple != expected_7tuple:
        raise PipeboardAdapterError("admission_snapshot_mismatch") from None
    return inv


def _gate1_dates_and_row_keys(
    rows: Sequence[Mapping[str, Any]], *, admitted_day: str
) -> None:
    for row in rows:
        if not isinstance(row, Mapping):
            raise make_wire_rejection("invalid_row_shape", payload_schema_valid=False) from None
        ds = row.get("date_start")
        de = row.get("date_stop")
        if type(ds) is not str or type(de) is not str or ds != admitted_day or de != admitted_day:
            raise make_wire_rejection("response_date_mismatch", response_date_mismatch=True) from None
    for row in rows:
        if not set(row.keys()).issubset(PINNED_PIPEBOARD_ROW_KEYS):
            raise make_wire_rejection("invalid_row_keys", payload_schema_valid=False) from None


def _gate2_bind_scoped_resources(
    rows: Sequence[Mapping[str, Any]],
    *,
    admitted_day: str,
    boundary: PrivatePipeboardBindingBoundary,
    expected_inventory: ExpectedResourceInventory,
) -> list[tuple[str, str, int]]:
    scoped_refs = frozenset(u.resource_ref for u in expected_inventory.expected_resources)
    bindings: list[tuple[str, str, int]] = []
    for row_ordinal, row in enumerate(rows):
        raw_cid = row.get("campaign_id")
        if type(raw_cid) is not str or META_CAMPAIGN_ID_RE.fullmatch(raw_cid) is None:
            raise make_wire_rejection("invalid_campaign_id", payload_schema_valid=False) from None
        try:
            resource_ref = boundary.resource_directory.resolve_resource_ref(raw_cid)
        except ClosedValidationError:
            raise make_wire_rejection("unknown_campaign_id", payload_schema_valid=False) from None
        if resource_ref is None:
            raise make_wire_rejection("unknown_campaign_id", payload_schema_valid=False) from None
        if resource_ref not in scoped_refs:
            raise make_wire_rejection("unscoped_campaign_resource", payload_schema_valid=False) from None
        bindings.append((resource_ref, admitted_day, row_ordinal))
    return bindings


def _validate_actual_reducer_records(
    actual_records: object, *, expected_records: list[dict[str, int]]
) -> list[dict[str, int]]:
    if type(actual_records) is not list:
        raise make_wire_rejection("reducer_output_invalid", reducer_order_or_count_mismatch=True) from None
    for rec in actual_records:
        if (
            type(rec) is not dict
            or len(rec) == 0
            or not set(rec.keys()).issubset(_ALLOWED_REDUCER_KEYS)
        ):
            raise make_wire_rejection("reducer_output_invalid", reducer_order_or_count_mismatch=True) from None
        for val in rec.values():
            if type(val) is not int or not (0 <= val <= MAX_INT64):
                raise make_wire_rejection(
                    "reducer_output_invalid", reducer_order_or_count_mismatch=True
                ) from None
    if len(actual_records) != len(expected_records) or any(
        actual_records[i] != expected_records[i] for i in range(len(expected_records))
    ):
        raise make_wire_rejection(
            "reducer_order_or_count_mismatch", reducer_order_or_count_mismatch=True
        ) from None
    return actual_records


def _build_metric_observation(
    reducer_key: str, val: int, *, currency: str
) -> SanitizedMetricObservation:
    metric_ref = _REDUCER_KEY_TO_METRIC_REF[reducer_key]
    defn = PHASE1_BASE_METRICS[metric_ref]
    obs_currency = currency if defn.currency_rule == "must_be_query_currency" else None
    return SanitizedMetricObservation(
        metric_semantic_ref=metric_ref,
        presence_status="observed",
        value_type=defn.value_type,
        raw_numeric_value=str(val),
        unit=defn.unit,
        currency=obs_currency,
    )


def _invoke_detached_reducer(
    parsed: ParsedPipeboardEnvelope, reducer: PipeboardRowReducer
) -> list[dict[str, int]]:
    expected_records = [
        parse_campaign_row_metrics(row).to_reducer_record() for row in parsed.rows
    ]
    reducer_input: dict[str, Any] = {
        "content": [{"type": "text", "text": parsed.raw_inner_text}]
    }
    if parsed.has_is_error_false:
        reducer_input["isError"] = False
    try:
        raw_actual = reducer(reducer_input)
    except Exception:
        raise make_wire_rejection(
            "reducer_output_invalid", reducer_order_or_count_mismatch=True
        ) from None
    return _validate_actual_reducer_records(raw_actual, expected_records=expected_records)


def _gate3_reduce_and_pair_observations(
    parsed: ParsedPipeboardEnvelope,
    *,
    ordered_bindings: list[tuple[str, str, int]],
    reducer: PipeboardRowReducer,
    currency: str,
) -> tuple[SanitizedResourceObservation, ...]:
    actual_records = _invoke_detached_reducer(parsed, reducer)
    seen_triples: set[tuple[str, str, str]] = set()
    grouped: dict[tuple[str, str], list[SanitizedMetricObservation]] = {}
    for (resource_ref, metric_date, _ordinal), rec in zip(
        ordered_bindings, actual_records, strict=True
    ):
        bucket = grouped.setdefault((resource_ref, metric_date), [])
        for r_key, val in rec.items():
            obs = _build_metric_observation(r_key, val, currency=currency)
            triple = (resource_ref, metric_date, obs.metric_semantic_ref)
            if triple in seen_triples:
                raise make_wire_rejection(
                    "duplicate_provider_observation", duplicate_provider_observation=True
                ) from None
            seen_triples.add(triple)
            bucket.append(obs)

    sorted_keys = sorted(
        grouped.keys(), key=lambda pair: (pair[0].encode("utf-8"), pair[1].encode("utf-8"))
    )
    return tuple(
        SanitizedResourceObservation(
            resource_ref=r_ref,
            metric_date=m_date,
            metric_observations=tuple(
                sorted(grouped[(r_ref, m_date)], key=lambda m: m.metric_semantic_ref.encode("utf-8"))
            ),
        )
        for r_ref, m_date in sorted_keys
    )


def _terminal_rejection_batch(
    rej: PipeboardWireRejection, retrieval_context: RetrievalContext
) -> ProviderObservationBatch:
    err = NormalizedProviderError(
        error_code=rej.code,
        category=rej.category,
        sanitized_detail=STATIC_DETAIL_BY_CODE[rej.code],
    )
    return ProviderObservationBatch(
        observed_capabilities=(),
        retrieval_context=retrieval_context,
        transport_outcome=rej.outcome,
        resource_observations=(),
        normalized_errors=(err,),
        io_counters=ExternalIOCounters.zero(),
    )


def _prepare_admitted_private_wire(
    admitted: object,
    boundary: object,
    retrieval_context: object,
    reducer: object,
) -> tuple[AdmittedCollection, PrivatePipeboardBindingBoundary, RetrievalContext, ExpectedResourceInventory, str]:
    if not isinstance(admitted, AdmittedCollection):
        raise PipeboardAdapterError("invalid_admitted_collection") from None
    if not isinstance(boundary, PrivatePipeboardBindingBoundary):
        raise PipeboardAdapterError("invalid_boundary_config") from None
    if not isinstance(retrieval_context, RetrievalContext):
        raise PipeboardAdapterError("invalid_retrieval_context") from None
    if not callable(reducer):
        raise PipeboardAdapterError("invalid_reducer_callable") from None
    expected_inventory = _verify_admitted_against_boundary(admitted, boundary)
    admitted_day = admitted.computed_date_range.start_date
    private_object_id = boundary.resolve_private_object_id(
        binding_ref=admitted.binding_ref, account_ref=admitted.account_ref
    )
    _ = build_pipeboard_insights_request(
        private_object_id=private_object_id,
        admitted_day=admitted_day,
        transport_limits=boundary.resolved_registry.driver_contract.transport_limits,
    )
    del private_object_id
    return admitted, boundary, retrieval_context, expected_inventory, admitted_day


def transform_pipeboard_response_to_batch(
    *,
    admitted: AdmittedCollection,
    boundary: PrivatePipeboardBindingBoundary,
    retrieval_context: RetrievalContext,
    network_ok: bool,
    http_status: int | None,
    headers: Sequence[tuple[str, str]],
    body_chunks: Iterable[bytes],
    reducer: PipeboardRowReducer = reduce_pipeboard_insights_result,
) -> ProviderObservationBatch:
    """Validate snapshot binding, parse Pipeboard HTTP/MCP wire, and run Gates 1–3 to a sanitized batch."""
    adm, bnd, rctx, expected_inventory, admitted_day = _prepare_admitted_private_wire(
        admitted, boundary, retrieval_context, reducer
    )
    try:
        parsed = parse_pipeboard_http_and_mcp_envelope(
            network_ok=network_ok,
            http_status=http_status,
            headers=headers,
            body_chunks=body_chunks,
            transport_limits=bnd.resolved_registry.driver_contract.transport_limits,
        )
        _gate1_dates_and_row_keys(parsed.rows, admitted_day=admitted_day)
        ordered_bindings = _gate2_bind_scoped_resources(
            parsed.rows, admitted_day=admitted_day, boundary=bnd, expected_inventory=expected_inventory
        )
        resource_observations = _gate3_reduce_and_pair_observations(
            parsed, ordered_bindings=ordered_bindings, reducer=reducer, currency=adm.currency
        )
    except PipeboardWireRejection as rej:
        return _terminal_rejection_batch(rej, rctx)
    return ProviderObservationBatch(
        observed_capabilities=(adm.canonical_query_contract.requested_capabilities[0],),
        retrieval_context=rctx,
        transport_outcome=parsed.transport_outcome,
        resource_observations=resource_observations,
        normalized_errors=(),
        io_counters=ExternalIOCounters.zero(),
    )


@dataclass(frozen=True, slots=True)
class RegisteredFixtureCase:
    """Immutable registered offline 7A Pipeboard fixture response entry."""

    admitted_locator: ArtifactLocator
    admitted: AdmittedCollection
    retrieval_context: RetrievalContext
    network_ok: bool
    http_status: int | None
    headers: tuple[Any, ...]
    body_chunks: tuple[bytes, ...] = field(repr=False)


class PipeboardFixtureAdapter(FixtureObservationPort):
    """Pure zero-I/O `FixtureObservationPort` implementation for offline 7A Pipeboard evaluation."""

    def __init__(
        self,
        *,
        boundary: PrivatePipeboardBindingBoundary,
        reducer: PipeboardRowReducer = reduce_pipeboard_insights_result,
    ) -> None:
        if not isinstance(boundary, PrivatePipeboardBindingBoundary):
            raise PipeboardAdapterError("invalid_boundary_config") from None
        if not callable(reducer):
            raise PipeboardAdapterError("invalid_reducer_callable") from None
        self._boundary = boundary
        self._reducer = reducer
        self._cases: dict[ArtifactLocator, RegisteredFixtureCase] = {}
        self._recorded_batches: dict[ArtifactLocator, ProviderObservationBatch] = {}

    def register_fixture_case(
        self,
        *,
        admitted: AdmittedCollection,
        retrieval_context: RetrievalContext,
        network_ok: bool,
        http_status: int | None,
        headers: Sequence[tuple[str, str]],
        body_chunks: Sequence[bytes],
    ) -> ArtifactLocator:
        """Register an offline 7A fixture case keyed by canonical `AdmittedCollection` locator."""
        if (
            not isinstance(admitted, AdmittedCollection)
            or admitted.collection_purpose != "fixture_7a"
        ):
            raise PipeboardAdapterError("invalid_admitted_collection") from None
        if not isinstance(retrieval_context, RetrievalContext):
            raise PipeboardAdapterError("invalid_retrieval_context") from None
        if (
            type(network_ok) is not bool
            or isinstance(headers, (str, bytes, bytearray))
            or not isinstance(headers, Sequence)
            or isinstance(body_chunks, (str, bytes, bytearray))
            or not isinstance(body_chunks, Sequence)
        ):
            raise PipeboardAdapterError("invalid_envelope_precondition") from None
        checked_chunks: list[bytes] = []
        for chunk in body_chunks:
            if type(chunk) is not bytes:
                raise PipeboardAdapterError("invalid_chunk_type") from None
            checked_chunks.append(chunk)

        admitted_loc = ArtifactLocator.for_canonical_bytes(
            AdmittedCollection.SCHEMA, canonicalize_jcs(admitted.to_dict())
        )
        entry = RegisteredFixtureCase(
            admitted_locator=admitted_loc,
            admitted=admitted,
            retrieval_context=retrieval_context,
            network_ok=network_ok,
            http_status=http_status,
            headers=tuple(headers),
            body_chunks=tuple(checked_chunks),
        )
        existing = self._cases.get(admitted_loc)
        if existing is not None and existing != entry:
            raise PipeboardAdapterError("duplicate_fixture_case") from None
        self._cases[admitted_loc] = entry
        return admitted_loc

    def load_fixture_observations(
        self, call: AdmittedFixtureCall
    ) -> ProviderObservationBatch:
        """Validate `AdmittedFixtureCall` snapshot binding, transform fixture response, and record batch."""
        if (
            not isinstance(call, AdmittedFixtureCall)
            or call.driver_id != "pipeboard_hosted"
            or call.driver_contract_digest
            != self._boundary.resolved_registry.driver_contract_locator.content_digest
        ):
            raise PipeboardAdapterError("invalid_fixture_call") from None

        case = self._cases.get(call.admitted_collection_locator)
        if case is None:
            raise PipeboardAdapterError("fixture_case_not_found") from None

        admitted = case.admitted
        recomputed_loc = ArtifactLocator.for_canonical_bytes(
            AdmittedCollection.SCHEMA, canonicalize_jcs(admitted.to_dict())
        )
        prereqs = admitted.purpose_prerequisite_locators
        if (
            recomputed_loc != call.admitted_collection_locator
            or recomputed_loc.content_digest != call.admitted_collection_digest
            or admitted.canonical_query_contract != call.canonical_query
            or call.canonical_query.tenant_ref
            != self._boundary.resolved_registry.snapshot.tenant_ref
            or prereqs is None
            or prereqs.regression_fixture_locator != call.regression_fixture_locator
        ):
            raise PipeboardAdapterError("admission_snapshot_mismatch") from None

        batch = transform_pipeboard_response_to_batch(
            admitted=admitted,
            boundary=self._boundary,
            retrieval_context=case.retrieval_context,
            network_ok=case.network_ok,
            http_status=case.http_status,
            headers=case.headers,
            body_chunks=case.body_chunks,
            reducer=self._reducer,
        )
        self._recorded_batches[call.admitted_collection_locator] = batch
        return batch

    def get_recorded_batch(
        self, admitted_collection_locator: ArtifactLocator
    ) -> ProviderObservationBatch:
        """Return the deterministic `ProviderObservationBatch` recorded for `admitted_collection_locator`."""
        if (
            not isinstance(admitted_collection_locator, ArtifactLocator)
            or admitted_collection_locator.artifact_type != AdmittedCollection.SCHEMA
        ):
            raise PipeboardAdapterError("recorded_batch_not_found") from None
        batch = self._recorded_batches.get(admitted_collection_locator)
        if batch is None:
            raise PipeboardAdapterError("recorded_batch_not_found") from None
        return batch


__all__ = [
    "PipeboardFixtureAdapter",
    "PrivatePipeboardBindingBoundary",
    "RegisteredFixtureCase",
    "transform_pipeboard_response_to_batch",
]
