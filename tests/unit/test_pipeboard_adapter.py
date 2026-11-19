"""Unit tests for Pipeboard reducer, PrivatePipeboardBindingBoundary, Gates 1–3, and PipeboardFixtureAdapter."""
from __future__ import annotations

from dataclasses import dataclass, replace
import json
from typing import Any

import pytest

import smart_ads.adapters as adapters_pkg
import smart_ads.adapters.pipeboard as pipeboard_pkg
from smart_ads.adapters.pipeboard import (
    PINNED_PIPEBOARD_ROW_KEYS,
    STATIC_DETAIL_BY_CODE,
    CanonicalCampaignMetrics,
    PipeboardAdapterError,
    PipeboardFixtureAdapter,
    PipeboardWireRejection,
    PrivatePipeboardBindingBoundary,
    RegisteredFixtureCase,
    parse_campaign_row_metrics,
    reduce_pipeboard_insights_result,
    transform_pipeboard_response_to_batch,
)
from smart_ads.adapters.pipeboard.wire import _WireDecimalToken, _WireOutOfRangeInt
from smart_ads.application import admit_collection, evaluate_fixture_collection
from smart_ads.contracts import (
    ArtifactLocator, CollectionRequest, DateRange, PurposePrerequisiteLocators,
    RetrievalContext, canonicalize_jcs, parse_timestamp_utc_micros,
)
from smart_ads.domain import (
    FORBIDDEN_PIPEBOARD_ARGUMENTS, PINNED_LEGACY_COMMIT, PINNED_LEGACY_REPO,
    PINNED_PIPEBOARD_D26_SPECS, PIPEBOARD_PHASE1_METRIC_SOURCE_MAPPINGS,
    AuthorizedScopeRelation, BidirectionalResourceDirectory, DriverCapabilityEntry,
    ExpectedResourceInventory, ExpectedResourceKey, LegacySourcePacket,
    PinnedGitArtifactMember, PinnedUpstreamReference, PipeboardPhase1Contract,
    PipeboardTransportLimits, PrivateRegistrySnapshot, RegistryBinding,
    TenantResourceKeyHandle, derive_resource_ref,
)
from smart_ads.ports import (
    AdmittedFixtureCall, CellRuntimePorts, ClockAttestation, ExpectedInventoryPort,
    FixtureObservationPort, ResolvedClockState, ResolvedPrerequisiteBundle,
    ResolvedRegistryState, SanitizedMetricObservation, SanitizedResourceObservation,
    TimezoneRuleSnapshot, UtcOffsetTransition,
)

SECRET_MARKER = "SECRET_CAMPAIGN_OR_TOKEN_777888999"
RAW_CID_A = "12021000000001"
RAW_CID_B = "12021000000002"
RAW_CID_UNSCOPED = "12021000000099"
RAW_ACCOUNT_ID = "act_5544332211"
JSON_HEADERS: tuple[tuple[str, str], ...] = (("Content-Type", "application/json"),)


def _loc(artifact_type: str, fill: str) -> ArtifactLocator:
    return ArtifactLocator.from_digest(artifact_type, "sha256:" + (fill * 64))


def _key_handle(tenant_ref: str = "tenant:ibvi") -> TenantResourceKeyHandle:
    return TenantResourceKeyHandle(
        tenant_ref=tenant_ref,
        key_identity="key:tenant-ibvi-hmac-v1",
        secret_bytes=b"0123456789abcdef0123456789abcdef_secret",
    )


def _derive_cid(raw_id: str, *, tenant_ref: str = "tenant:ibvi") -> str:
    return derive_resource_ref(
        key_handle=_key_handle(tenant_ref),
        mapping_version="hmac-sha256-b32-v1",
        domain_separator="0x00",
        ad_platform_ref="meta",
        resource_level="campaign",
        raw_provider_id=raw_id,
    )


REF_A = _derive_cid(RAW_CID_A)
REF_B = _derive_cid(RAW_CID_B)
REF_UNSCOPED = _derive_cid(RAW_CID_UNSCOPED)


def _make_contract() -> PipeboardPhase1Contract:
    members = tuple(
        PinnedGitArtifactMember(
            role=role,
            repository=PINNED_LEGACY_REPO,
            commit_sha=PINNED_LEGACY_COMMIT,
            path=path,
            git_blob_oid=blob_oid,
            file_content_sha256=file_sha,
            git_artifact_provenance_locator=_loc(
                "smart_ads/git_artifact_provenance/v1", str(idx + 1)
            ),
        )
        for idx, (role, path, blob_oid, file_sha) in enumerate(PINNED_PIPEBOARD_D26_SPECS)
    )
    return PipeboardPhase1Contract(
        contract_id="driver-contract:pipeboard-phase1-v1",
        driver_id="pipeboard_hosted",
        legacy_source_packet=LegacySourcePacket(PINNED_LEGACY_REPO, PINNED_LEGACY_COMMIT, members),
        upstream_reference=PinnedUpstreamReference(),
        transport_limits=PipeboardTransportLimits(forbidden_arguments=FORBIDDEN_PIPEBOARD_ARGUMENTS),
        metric_source_mappings=dict(PIPEBOARD_PHASE1_METRIC_SOURCE_MAPPINGS),
    )


def _make_registry_state(
    *,
    tenant_ref: str = "tenant:ibvi",
    snapshot_id: str = "registry-snapshot:2026-11-11-001",
) -> ResolvedRegistryState:
    contract = _make_contract()
    contract_loc = ArtifactLocator.for_canonical_bytes(
        PipeboardPhase1Contract.SCHEMA, canonicalize_jcs(contract.to_dict())
    )
    binding = RegistryBinding(
        "binding:meta-primary", "account:ibvi-01", "provider:pipeboard", "meta", "BRL", "pipeboard_hosted"
    )
    scope_active = AuthorizedScopeRelation(
        "front:ibvi", "profile:reader", "binding:meta-primary", "scope:campaigns-active"
    )
    cap = DriverCapabilityEntry(
        capability_ref="cap:campaign-basic-v1",
        capability_semantic_version="1.0.0",
        driver_id="pipeboard_hosted",
        driver_contract_locator=contract_loc,
        driver_contract_digest=contract_loc.content_digest,
        resource_scope_ref="scope:campaigns-active",
        state="declared",
        required_metrics=("metric:clicks_v1", "metric:impressions_v1", "metric:spend_v1"),
    )
    snapshot = PrivateRegistrySnapshot(
        snapshot_id=snapshot_id,
        tenant_ref=tenant_ref,
        issued_at_utc="2026-11-11T00:00:00Z",
        valid_until_utc="2026-11-12T00:00:00Z",
        resource_ref_mapping_version="hmac-sha256-b32-v1",
        key_identity="key:tenant-ibvi-hmac-v1",
        bindings=(binding,),
        authorized_scopes=(scope_active,),
        capabilities=(cap,),
    )
    snap_loc = ArtifactLocator.for_canonical_bytes(
        PrivateRegistrySnapshot.SCHEMA, canonicalize_jcs(snapshot.to_dict())
    )
    return ResolvedRegistryState(snap_loc, snapshot, contract_loc, contract)


def _make_inventory(
    reg_state: ResolvedRegistryState,
    *,
    day: str = "2026-11-10",
    refs: tuple[str, ...] = (REF_A, REF_B),
) -> tuple[ArtifactLocator, ExpectedResourceInventory]:
    keys = tuple(
        ExpectedResourceKey("binding:meta-primary", "account:ibvi-01", r, "campaign", day)
        for r in refs
    )
    inv = ExpectedResourceInventory(
        inventory_id="inventory:7a-2026-11-10",
        registry_snapshot_locator=reg_state.locator,
        registry_snapshot_digest=reg_state.locator.content_digest,
        tenant_ref=reg_state.snapshot.tenant_ref,
        binding_ref="binding:meta-primary",
        account_ref="account:ibvi-01",
        resource_scope_ref="scope:campaigns-active",
        date_range=DateRange(day, day, True),
        expected_resources=keys,
    )
    loc = ArtifactLocator.for_canonical_bytes(
        ExpectedResourceInventory.SCHEMA, canonicalize_jcs(inv.to_dict())
    )
    return loc, inv


@dataclass
class _StaticCellPorts:
    reg_state: ResolvedRegistryState

    def get_authenticated_clock(self) -> ResolvedClockState:
        att = ClockAttestation(
            "clock:att-001",
            "2026-11-11T15:00:00.250000Z",
            500,
            "2026-11-11T14:59:50Z",
            "2026-11-11T15:00:30Z",
            30,
        )
        loc = ArtifactLocator.for_canonical_bytes(
            ClockAttestation.SCHEMA, canonicalize_jcs(att.to_dict())
        )
        return ResolvedClockState(loc, att, 1000)

    def get_reporting_timezone_rules(self) -> TimezoneRuleSnapshot:
        t0 = parse_timestamp_utc_micros("2020-01-01T00:00:00Z", allow_whole_seconds=True)
        return TimezoneRuleSnapshot(
            "America/Sao_Paulo", "2026a", (UtcOffsetTransition(t0, -10_800),)
        )

    def get_active_registry(self, *, tenant_ref: str) -> ResolvedRegistryState:
        return self.reg_state

    def resolve_prerequisites(self, **_: Any) -> ResolvedPrerequisiteBundle:
        return ResolvedPrerequisiteBundle(
            locators=PurposePrerequisiteLocators(
                purpose="fixture_7a",
                sealed_sandbox_profile_locator=_loc("smart_ads/sealed_sandbox_profile/v1", "b"),
                regression_fixture_locator=_loc("smart_ads/regression_fixture/v1", "c"),
            )
        )


def _make_directory_and_boundary(
    reg_state: ResolvedRegistryState,
) -> PrivatePipeboardBindingBoundary:
    directory = BidirectionalResourceDirectory(
        _key_handle(), "hmac-sha256-b32-v1", "0x00", "meta", "campaign"
    )
    directory.register_verified_pair(RAW_CID_A, REF_A)
    directory.register_verified_pair(RAW_CID_B, REF_B)
    directory.register_verified_pair(RAW_CID_UNSCOPED, REF_UNSCOPED)
    inv_loc, inv = _make_inventory(reg_state)
    return PrivatePipeboardBindingBoundary(
        resolved_registry=reg_state,
        resource_directory=directory,
        private_account_bindings={("binding:meta-primary", "account:ibvi-01"): RAW_ACCOUNT_ID},
        authenticated_inventories=((inv_loc, inv),),
    )


def _build_world() -> tuple[
    ResolvedRegistryState,
    PrivatePipeboardBindingBoundary,
    CellRuntimePorts,
    CollectionRequest,
    AdmittedFixtureCall,
    Any,
]:
    reg_state = _make_registry_state()
    boundary = _make_directory_and_boundary(reg_state)
    helper = _StaticCellPorts(reg_state=reg_state)
    cell_ports = CellRuntimePorts(helper, helper, helper, helper)
    request = CollectionRequest(
        request_id="req-7a-001",
        collection_purpose="fixture_7a",
        tenant_ref="tenant:ibvi",
        binding_ref="binding:meta-primary",
        resource_scope_ref="scope:campaigns-active",
        date_rule="previous_local_day",
        resource_level="campaign",
        requested_capabilities=("cap:campaign-basic-v1",),
    )
    bundle = admit_collection(request, cell_ports, admission_id="admission:7a-001")
    reg_fix_loc = bundle.admitted.purpose_prerequisite_locators.regression_fixture_locator
    assert reg_fix_loc is not None
    call = AdmittedFixtureCall(
        admitted_collection_locator=bundle.locator,
        admitted_collection_digest=bundle.locator.content_digest,
        driver_id="pipeboard_hosted",
        driver_contract_digest=bundle.admitted.driver_contract_digest,
        canonical_query=bundle.admitted.canonical_query_contract,
        regression_fixture_locator=reg_fix_loc,
    )
    return reg_state, boundary, cell_ports, request, call, bundle


def _retrieval_ctx() -> RetrievalContext:
    return RetrievalContext(
        retrieved_at_utc="2026-11-11T15:00:01.125000Z",
        source_observation_ref="observation:pipeboard-fixture-001",
        adapter_version="pipeboard-offline-1.0.0",
        semantic_version="1.0.0",
    )


def _outer_bytes(inner_payload: Any, *, include_is_error: bool = False) -> bytes:
    text = (
        inner_payload
        if isinstance(inner_payload, str)
        else json.dumps(inner_payload, separators=(",", ":"))
    )
    res: dict[str, Any] = {"content": [{"type": "text", "text": text}]}
    if include_is_error:
        res["isError"] = False
    return json.dumps({"jsonrpc": "2.0", "id": 1, "result": res}, separators=(",", ":")).encode(
        "utf-8"
    )


def _valid_two_rows() -> list[dict[str, Any]]:
    return [
        {
            "campaign_id": RAW_CID_A,
            "campaign_name": f"Camp {SECRET_MARKER}",
            "date_start": "2026-11-10",
            "date_stop": "2026-11-10",
            "impressions": "1000",
            "clicks": 25,
            "spend": "92233720368547758.07",
            "cpc": 0.45,
        },
        {
            "campaign_id": RAW_CID_B,
            "date_start": "2026-11-10",
            "date_stop": "2026-11-10",
            "impressions": 0,
            "clicks": "0",
            "spend": "0",
        },
    ]


def _ok_wire(inner_payload: Any) -> dict[str, Any]:
    return {
        "network_ok": True,
        "http_status": 200,
        "headers": JSON_HEADERS,
        "body_chunks": (_outer_bytes(inner_payload),),
    }


BAD_METRIC_ROWS: tuple[tuple[dict[str, Any], str], ...] = (
    ({"impressions": True}, "invalid_metric_value"),
    ({"impressions": -1}, "invalid_metric_value"),
    ({"impressions": "01"}, "invalid_metric_value"),
    ({"impressions": "9223372036854775808"}, "invalid_metric_value"),
    ({"impressions": _WireOutOfRangeInt("9223372036854775808")}, "invalid_metric_value"),
    ({"clicks": _WireDecimalToken("1.0")}, "invalid_metric_value"),
    ({"spend": "92233720368547758.08"}, "invalid_metric_value"),
    ({"spend": 1200}, "invalid_metric_value"),
    ({"spend": "12.345"}, "invalid_metric_value"),
    ({"spend": "-1.00"}, "invalid_metric_value"),
    ({"spend": "01.00"}, "invalid_metric_value"),
    ({"campaign_id": RAW_CID_A}, "empty_row_metrics"),
)

COMPLETENESS_12_ROW_CASES: tuple[tuple[str, dict[str, Any], str, str, tuple[str, ...]], ...] = (
    ("row01_network_error", {"network_ok": False, "http_status": None, "headers": (), "body_chunks": ()}, "network_error", "failed", ("network_failed", "http_status_missing")),
    ("row02_missing_http_status", {"network_ok": True, "http_status": None, "headers": JSON_HEADERS, "body_chunks": ()}, "missing_http_status", "failed", ("http_status_missing",)),
    ("row03_http_auth_401", {"network_ok": True, "http_status": 401, "headers": (), "body_chunks": ()}, "http_auth_error", "failed", ("auth_failed", "http_status_401")),
    ("row04_http_502", {"network_ok": True, "http_status": 502, "headers": (), "body_chunks": ()}, "http_status_not_200", "failed", ("http_status_502",)),
    ("row05_bad_encoding", {"network_ok": True, "http_status": 200, "headers": (("Content-Type", "application/json"), ("Content-Encoding", "gzip")), "body_chunks": ()}, "forbidden_content_encoding", "failed", ("media_or_encoding_invalid",)),
    ("row06_jsonrpc_error", {"network_ok": True, "http_status": 200, "headers": JSON_HEADERS, "body_chunks": (b'{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"e"}}',)}, "jsonrpc_error_response", "failed", ("jsonrpc_error",)),
    ("row07_truncated_2mib", {"network_ok": True, "http_status": 200, "headers": (("Content-Type", "application/json"), ("Content-Length", "2097153")), "body_chunks": ()}, "declared_length_over_2mib", "partial", ("truncated_2mib", "missing_expected_fact_keys")),
    ("row08_paging_next", _ok_wire({"data": [], "paging": {"next": "cursor_2"}}), "non_empty_paging_next", "partial", ("non_empty_continuation", "missing_expected_fact_keys")),
    ("row09_schema_invalid", _ok_wire({"data": [{"campaign_id": RAW_CID_A, "adset_id": "999", "date_start": "2026-11-10", "date_stop": "2026-11-10", "impressions": "10"}]}), "invalid_row_keys", "partial", ("payload_schema_invalid", "missing_expected_fact_keys")),
    ("row10_date_mismatch", _ok_wire({"data": [{"campaign_id": RAW_CID_A, "date_start": "2026-11-09", "date_stop": "2026-11-10", "impressions": "10"}]}), "response_date_mismatch", "partial", ("response_date_mismatch", "missing_expected_fact_keys")),
    ("row12_duplicate_obs", _ok_wire({"data": [{"campaign_id": RAW_CID_A, "date_start": "2026-11-10", "date_stop": "2026-11-10", "impressions": "10"}, {"campaign_id": RAW_CID_A, "date_start": "2026-11-10", "date_stop": "2026-11-10", "impressions": "10"}]}), "duplicate_provider_observation", "partial", ("duplicate_provider_observation", "missing_expected_fact_keys")),
)


def test_adapters_and_pipeboard_package_exports() -> None:
    assert adapters_pkg.__all__ == []
    assert list(pipeboard_pkg.__all__) == sorted(
        pipeboard_pkg.__all__, key=lambda s: s.encode("utf-8")
    )
    assert len(PINNED_PIPEBOARD_ROW_KEYS) == 19
    for forbidden_col in ("adset_id", "adset_name", "ad_id", "ad_name"):
        assert forbidden_col not in PINNED_PIPEBOARD_ROW_KEYS
    assert RegisteredFixtureCase is not None


def test_parse_campaign_row_metrics_and_reducer_parity() -> None:
    m_full = parse_campaign_row_metrics(
        {"impressions": "9223372036854775807", "clicks": 0, "spend": "92233720368547758.07"}
    )
    assert m_full == CanonicalCampaignMetrics(
        impressions=(1 << 63) - 1, clicks=0, spend_minor=(1 << 63) - 1
    )
    assert m_full.to_reducer_record() == {
        "impressions": (1 << 63) - 1,
        "clicks": 0,
        "spend_minor": (1 << 63) - 1,
    }
    assert parse_campaign_row_metrics({"spend": "12.3"}).to_reducer_record() == {"spend_minor": 1230}
    mcp_res = {"content": [{"type": "text", "text": json.dumps({"data": _valid_two_rows()})}], "isError": False}
    assert reduce_pipeboard_insights_result(mcp_res) == [
        {"impressions": 1000, "clicks": 25, "spend_minor": 9223372036854775807},
        {"impressions": 0, "clicks": 0, "spend_minor": 0},
    ]


@pytest.mark.parametrize(("bad_row", "expected_code"), BAD_METRIC_ROWS)
def test_parse_campaign_row_metrics_rejects_invalid_values(
    bad_row: dict[str, Any], expected_code: str
) -> None:
    with pytest.raises(PipeboardWireRejection) as exc_info:
        parse_campaign_row_metrics(bad_row)
    assert exc_info.value.code == expected_code
    assert exc_info.value.category == "schema"
    assert exc_info.value.outcome.payload_schema_valid is False


def test_private_pipeboard_binding_boundary_validates_7_tuple_and_redacts_repr() -> None:
    reg_state, boundary, _, _, _, _ = _build_world()
    assert isinstance(boundary, ExpectedInventoryPort)
    assert RAW_ACCOUNT_ID not in repr(boundary) and RAW_ACCOUNT_ID not in str(boundary)
    day = DateRange("2026-11-10", "2026-11-10", True)
    resolved = boundary.resolve_expected_inventory(
        registry_snapshot_locator=reg_state.locator,
        tenant_ref="tenant:ibvi",
        binding_ref="binding:meta-primary",
        account_ref="account:ibvi-01",
        resource_scope_ref="scope:campaigns-active",
        date_range=day,
    )
    _, auth_inv = boundary.resolve_authenticated_inventory(
        binding_ref="binding:meta-primary",
        account_ref="account:ibvi-01",
        resource_scope_ref="scope:campaigns-active",
        date_range=day,
    )
    assert resolved is auth_inv
    assert (
        boundary.resolve_expected_inventory(
            registry_snapshot_locator=_loc(PrivateRegistrySnapshot.SCHEMA, "9"),
            tenant_ref="tenant:ibvi",
            binding_ref="binding:meta-primary",
            account_ref="account:ibvi-01",
            resource_scope_ref="scope:campaigns-active",
            date_range=day,
        )
        is None
    )
    other_reg = _make_registry_state(snapshot_id="registry-snapshot:2026-11-11-999")
    bad_loc, bad_inv = _make_inventory(other_reg)
    with pytest.raises(PipeboardAdapterError):
        boundary.register_authenticated_inventory(bad_loc, bad_inv)
    with pytest.raises(PipeboardAdapterError):
        boundary.register_authenticated_inventory(_loc(ExpectedResourceInventory.SCHEMA, "f"), auth_inv)
    with pytest.raises(PipeboardAdapterError):
        boundary.register_verified_campaign_pair("999999999999", REF_A)


def test_six_admission_snapshot_mismatch_checks_fail_before_private_lookup() -> None:
    reg_state, boundary, _, _, base_call, bundle = _build_world()
    other_reg = _make_registry_state(snapshot_id="registry-snapshot:2026-11-11-002")
    other_cqc = replace(
        bundle.admitted.canonical_query_contract, date_range=DateRange("2026-11-09", "2026-11-09", True)
    )
    other_drv_loc = _loc(PipeboardPhase1Contract.SCHEMA, "d")
    variants = (
        replace(bundle.admitted, registry_snapshot_locator=other_reg.locator, registry_snapshot_digest=other_reg.locator.content_digest),
        replace(bundle.admitted, driver_contract_locator=other_drv_loc, driver_contract_digest=other_drv_loc.content_digest),
        replace(
            bundle.admitted,
            computed_date_range=DateRange("2026-11-09", "2026-11-09", True),
            canonical_query_contract=other_cqc,
            canonical_query_digest=other_cqc.canonical_query_digest,
        ),
    )
    for idx, bad_adm in enumerate(variants):
        adapter = PipeboardFixtureAdapter(boundary=boundary)
        bad_loc = adapter.register_fixture_case(
            admitted=bad_adm, retrieval_context=_retrieval_ctx(), **_ok_wire({"data": _valid_two_rows()})
        )
        bad_call = AdmittedFixtureCall(
            admitted_collection_locator=bad_loc,
            admitted_collection_digest=bad_loc.content_digest,
            driver_id="pipeboard_hosted",
            driver_contract_digest=reg_state.driver_contract_locator.content_digest,
            canonical_query=bad_adm.canonical_query_contract,
            regression_fixture_locator=base_call.regression_fixture_locator,
        )
        with pytest.raises(PipeboardAdapterError) as exc_info:
            adapter.load_fixture_observations(bad_call)
        assert exc_info.value.code == "admission_snapshot_mismatch", f"variant {idx}"


def test_call_vs_admitted_binding_mismatches_and_preconditions() -> None:
    _, boundary, _, _, base_call, bundle = _build_world()
    adapter_ok = PipeboardFixtureAdapter(boundary=boundary)
    adapter_ok.register_fixture_case(
        admitted=bundle.admitted, retrieval_context=_retrieval_ctx(), **_ok_wire({"data": _valid_two_rows()})
    )
    alt_cqc = replace(base_call.canonical_query, tzdb_version="2025z")
    for bad_call in (
        replace(base_call, canonical_query=alt_cqc),
        replace(base_call, regression_fixture_locator=_loc("smart_ads/regression_fixture/v1", "e")),
    ):
        with pytest.raises(PipeboardAdapterError) as exc_info:
            adapter_ok.load_fixture_observations(bad_call)
        assert exc_info.value.code == "admission_snapshot_mismatch"

    other_boundary = PrivatePipeboardBindingBoundary(
        resolved_registry=_make_registry_state(tenant_ref="tenant:other"),
        key_handle=_key_handle("tenant:other"),
    )
    adapter_other = PipeboardFixtureAdapter(boundary=other_boundary)
    adapter_other.register_fixture_case(
        admitted=bundle.admitted, retrieval_context=_retrieval_ctx(), **_ok_wire({"data": []})
    )
    with pytest.raises(PipeboardAdapterError) as exc_tenant:
        adapter_other.load_fixture_observations(base_call)
    assert exc_tenant.value.code == "admission_snapshot_mismatch"
    with pytest.raises(PipeboardAdapterError) as exc_drv:
        adapter_ok.load_fixture_observations(replace(base_call, driver_id="other_driver"))
    assert exc_drv.value.code == "invalid_fixture_call"
    with pytest.raises(PipeboardAdapterError) as exc_missing:
        adapter_ok.load_fixture_observations(
            replace(base_call, admitted_collection_locator=_loc(bundle.admitted.SCHEMA, "7"), admitted_collection_digest="sha256:" + ("7" * 64))
        )
    assert exc_missing.value.code == "fixture_case_not_found"


def test_gate1_date_mismatch_precedes_row_keys_directory_and_reducer() -> None:
    _, boundary, _, _, _, bundle = _build_world()
    reducer_calls = 0

    def _spy_reducer(mcp_result: dict[str, Any]) -> list[dict[str, int]]:
        nonlocal reducer_calls
        reducer_calls += 1
        return reduce_pipeboard_insights_result(mcp_result)

    rows = [
        {"campaign_id": "bad", "adset_id": "x", "date_start": "2026-11-10", "date_stop": "2026-11-10", "impressions": "10"},
        {"campaign_id": f"bad_{SECRET_MARKER}", "adset_id": "x", "date_start": "2026-11-10", "date_stop": "2026-11-09", "impressions": "x"},
    ]
    batch = transform_pipeboard_response_to_batch(
        admitted=bundle.admitted,
        boundary=boundary,
        retrieval_context=_retrieval_ctx(),
        reducer=_spy_reducer,
        **_ok_wire({"data": rows}),
    )
    assert reducer_calls == 0
    assert batch.transport_outcome.response_date_mismatch is True
    assert batch.transport_outcome.payload_schema_valid is True
    assert batch.normalized_errors[0].error_code == "response_date_mismatch"

    non_map_batch = transform_pipeboard_response_to_batch(
        admitted=bundle.admitted, boundary=boundary, retrieval_context=_retrieval_ctx(), **_ok_wire({"data": [123]})
    )
    assert non_map_batch.normalized_errors[0].error_code == "invalid_row_shape"


@pytest.mark.parametrize(
    ("cid_val", "expected_code"),
    [
        ("0123456", "invalid_campaign_id"),
        ("12345", "invalid_campaign_id"),
        (12345678, "invalid_campaign_id"),
        ("999999999999", "unknown_campaign_id"),
        (RAW_CID_UNSCOPED, "unscoped_campaign_resource"),
    ],
)
def test_gate2_campaign_identity_and_scope_rejections(cid_val: Any, expected_code: str) -> None:
    _, boundary, _, _, _, bundle = _build_world()
    row = {"campaign_id": cid_val, "date_start": "2026-11-10", "date_stop": "2026-11-10", "impressions": "10"}
    batch = transform_pipeboard_response_to_batch(
        admitted=bundle.admitted, boundary=boundary, retrieval_context=_retrieval_ctx(), **_ok_wire({"data": [row]})
    )
    assert batch.transport_outcome.payload_schema_valid is False
    assert batch.normalized_errors[0].error_code == expected_code
    assert batch.normalized_errors[0].sanitized_detail == STATIC_DETAIL_BY_CODE[expected_code]


def test_gate3_detached_reducer_copy_and_anti_permutation_checks() -> None:
    _, boundary, _, _, _, bundle = _build_world()
    seen_is_error: list[Any] = []

    def _mutating_reducer(mcp_result: dict[str, Any]) -> list[dict[str, int]]:
        seen_is_error.append(mcp_result.get("isError"))
        out = reduce_pipeboard_insights_result(mcp_result)
        mcp_result["content"][0]["text"] = "mutated"
        mcp_result["content"].clear()
        return out

    ok_batch = transform_pipeboard_response_to_batch(
        admitted=bundle.admitted,
        boundary=boundary,
        retrieval_context=_retrieval_ctx(),
        network_ok=True,
        http_status=200,
        headers=JSON_HEADERS,
        body_chunks=[_outer_bytes({"data": _valid_two_rows()}, include_is_error=True)],
        reducer=_mutating_reducer,
    )
    assert seen_is_error == [False] and ok_batch.normalized_errors == ()
    for bad_reducer, exp_code in (
        (lambda m: list(reversed(reduce_pipeboard_insights_result(m))), "reducer_order_or_count_mismatch"),
        (lambda m: reduce_pipeboard_insights_result(m)[:1], "reducer_order_or_count_mismatch"),
        (lambda _m: [{"impressions": True}], "reducer_output_invalid"),
        (lambda _m: [{"extra": 1}], "reducer_output_invalid"),
        (lambda _m: (_ for _ in ()).throw(RuntimeError(SECRET_MARKER)), "reducer_output_invalid"),
    ):
        err_batch = transform_pipeboard_response_to_batch(
            admitted=bundle.admitted,
            boundary=boundary,
            retrieval_context=_retrieval_ctx(),
            reducer=bad_reducer,
            **_ok_wire({"data": _valid_two_rows()}),
        )
        assert err_batch.transport_outcome.reducer_order_or_count_mismatch is True
        assert err_batch.normalized_errors[0].error_code == exp_code
        assert SECRET_MARKER not in err_batch.normalized_errors[0].sanitized_detail


def test_disjoint_metric_rows_merge_cleanly_per_resource_day() -> None:
    _, boundary, _, _, _, bundle = _build_world()
    disjoint_rows = [
        {"campaign_id": RAW_CID_A, "date_start": "2026-11-10", "date_stop": "2026-11-10", "impressions": "10"},
        {"campaign_id": RAW_CID_A, "date_start": "2026-11-10", "date_stop": "2026-11-10", "clicks": "2"},
    ]
    merged_batch = transform_pipeboard_response_to_batch(
        admitted=bundle.admitted,
        boundary=boundary,
        retrieval_context=_retrieval_ctx(),
        **_ok_wire({"data": disjoint_rows}),
    )
    assert len(merged_batch.resource_observations) == 1
    assert len(merged_batch.resource_observations[0].metric_observations) == 2


def test_end_to_end_complete_fixture_evaluation_and_recorded_batch() -> None:
    _, boundary, cell_ports, request, _, bundle = _build_world()
    adapter = PipeboardFixtureAdapter(boundary=boundary)
    assert isinstance(adapter, FixtureObservationPort)
    with pytest.raises(PipeboardAdapterError) as exc_not_found:
        adapter.get_recorded_batch(bundle.locator)
    assert exc_not_found.value.code == "recorded_batch_not_found"

    reg_loc = adapter.register_fixture_case(
        admitted=bundle.admitted,
        retrieval_context=_retrieval_ctx(),
        **_ok_wire({"data": _valid_two_rows()}),
    )
    assert reg_loc == bundle.locator
    eval_out = evaluate_fixture_collection(
        request, admission_id="admission:7a-001", cell_ports=cell_ports, fixture_port=adapter, inventory_port=boundary
    )
    assert eval_out.completeness.status == "complete" and eval_out.completeness.reasons == ()
    assert eval_out.completeness.normalized_fact_set_digest is not None
    assert eval_out.io_counters.is_zero is True
    recorded = adapter.get_recorded_batch(eval_out.admitted_locator)
    assert recorded.retrieval_context == _retrieval_ctx()
    obs_by_ref = {o.resource_ref: o for o in recorded.resource_observations}
    assert obs_by_ref[REF_A] == SanitizedResourceObservation(
        resource_ref=REF_A,
        metric_date="2026-11-10",
        metric_observations=(
            SanitizedMetricObservation("metric:clicks_v1", "observed", "int64_count", "25", "count", None),
            SanitizedMetricObservation("metric:impressions_v1", "observed", "int64_count", "1000", "count", None),
            SanitizedMetricObservation("metric:spend_v1", "observed", "int64_minor_currency", "9223372036854775807", "minor_currency", "BRL"),
        ),
    )


@pytest.mark.parametrize(
    ("case_label", "wire_kwargs", "expected_code", "expected_status", "expected_reasons"),
    COMPLETENESS_12_ROW_CASES,
)
def test_all_completeness_rows_via_evaluate_fixture_collection(
    case_label: str,
    wire_kwargs: dict[str, Any],
    expected_code: str,
    expected_status: str,
    expected_reasons: tuple[str, ...],
) -> None:
    _, boundary, cell_ports, request, _, bundle = _build_world()
    adapter = PipeboardFixtureAdapter(boundary=boundary)
    adapter.register_fixture_case(admitted=bundle.admitted, retrieval_context=_retrieval_ctx(), **wire_kwargs)
    eval_out = evaluate_fixture_collection(
        request, admission_id="admission:7a-001", cell_ports=cell_ports, fixture_port=adapter, inventory_port=boundary
    )
    batch = adapter.get_recorded_batch(eval_out.admitted_locator)
    assert batch.normalized_errors[0].error_code == expected_code, case_label
    assert batch.observed_capabilities == ()
    assert eval_out.completeness.status == expected_status, case_label
    assert eval_out.completeness.reasons == expected_reasons, case_label


def test_row11_reducer_mismatch_completeness_via_evaluate_fixture_collection() -> None:
    _, boundary, cell_ports, request, _, bundle = _build_world()
    adapter = PipeboardFixtureAdapter(
        boundary=boundary, reducer=lambda m: list(reversed(reduce_pipeboard_insights_result(m)))
    )
    adapter.register_fixture_case(
        admitted=bundle.admitted, retrieval_context=_retrieval_ctx(), **_ok_wire({"data": _valid_two_rows()})
    )
    eval_out = evaluate_fixture_collection(
        request, admission_id="admission:7a-001", cell_ports=cell_ports, fixture_port=adapter, inventory_port=boundary
    )
    batch = adapter.get_recorded_batch(eval_out.admitted_locator)
    assert batch.normalized_errors[0].error_code == "reducer_order_or_count_mismatch"
    assert eval_out.completeness.status == "partial"
    assert eval_out.completeness.reasons == ("reducer_order_or_count_mismatch", "missing_expected_fact_keys")
