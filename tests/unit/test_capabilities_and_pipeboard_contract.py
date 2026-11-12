"""Unit tests for smart_ads.domain.capabilities and smart_ads.domain.pipeboard_contract (ADR-0001 §§4.1, 5.1, 5.4)."""
from __future__ import annotations

from pathlib import Path
import subprocess
from types import MappingProxyType
from typing import Any

import pytest

from smart_ads.contracts import (
    ADR_P1_DOMAIN_PREFIXES,
    ArtifactLocator,
    ClosedValidationError,
    DateRange,
    P1Integrity,
    self_digest_jcs_sha256,
)
from smart_ads.contracts.schemas import CORE_SCHEMA_DESCRIPTORS
from smart_ads.domain.capabilities import (
    ALLOWED_CAPABILITY_TRANSITIONS,
    IO_DENIED_CAPABILITY_STATES,
    CapabilityInvalidationTransition,
    CapabilityRevalidationTransition,
    is_io_denied_state,
    validate_capability_transition,
)
from smart_ads.domain.pipeboard_contract import (
    FORBIDDEN_PIPEBOARD_ARGUMENTS,
    PINNED_LEGACY_COMMIT,
    PINNED_LEGACY_REPO,
    PINNED_PIPEBOARD_D26_SPECS,
    PIPEBOARD_PHASE1_METRIC_SOURCE_MAPPINGS,
    LegacySourcePacket,
    PinnedGitArtifactMember,
    PinnedUpstreamReference,
    PipeboardPhase1Contract,
    PipeboardTransportLimits,
)
from smart_ads.domain.registry import (
    AuthorizedScopeRelation,
    DriverCapabilityEntry,
    ExpectedResourceInventory,
    ExpectedResourceKey,
    PrivateRegistrySnapshot,
    RegistryBinding,
)
from smart_ads.domain.resource_ref import TenantResourceKeyHandle, derive_resource_ref
from tools.governance import p1 as gov_p1


def _loc(artifact_type: str, fill: str = "a") -> ArtifactLocator:
    return ArtifactLocator.from_digest(artifact_type, "sha256:" + (fill * 64))


def _make_d26_members() -> tuple[PinnedGitArtifactMember, ...]:
    fill_chars = ("1", "2", "3", "4", "5")
    return tuple(
        PinnedGitArtifactMember(
            role=role,
            repository=PINNED_LEGACY_REPO,
            commit_sha=PINNED_LEGACY_COMMIT,
            path=path,
            git_blob_oid=blob_oid,
            file_content_sha256=file_sha,
            git_artifact_provenance_locator=_loc(
                "smart_ads/git_artifact_provenance/v1", fill
            ),
        )
        for (role, path, blob_oid, file_sha), fill in zip(
            PINNED_PIPEBOARD_D26_SPECS, fill_chars, strict=True
        )
    )


def _make_pipeboard_contract(
    *,
    integrity: P1Integrity | None = None,
) -> PipeboardPhase1Contract:
    packet = LegacySourcePacket(
        repository=PINNED_LEGACY_REPO,
        commit_sha=PINNED_LEGACY_COMMIT,
        members=_make_d26_members(),
    )
    return PipeboardPhase1Contract(
        contract_id="driver-contract:pipeboard-phase1-v1",
        driver_id="pipeboard_hosted",
        legacy_source_packet=packet,
        upstream_reference=PinnedUpstreamReference(
            repository="pipeboard-co/meta-ads-mcp",
            commit_sha="2ef198e266ca6a37b6dc2c42335f0a0885002771",
            path="meta_ads_mcp/core/insights.py",
            symbol="get_insights",
            hosted_parity_proven=False,
        ),
        transport_limits=PipeboardTransportLimits(
            endpoint_url="https://meta-ads.mcp.pipeboard.co/",
            http_method="POST",
            connect_timeout_seconds=5,
            wall_deadline_seconds=60,
            request_content_type="application/json",
            request_accept="application/json, text/event-stream",
            request_accept_encoding="identity",
            read_chunk_bytes=65536,
            max_streamed_bytes=2_097_152,
            max_decoded_text_bytes=2_097_152,
            jsonrpc_method="tools/call",
            tool_name="get_insights",
            level="campaign",
            limit=100,
            compact=True,
            max_campaign_rows=100,
            forbidden_arguments=FORBIDDEN_PIPEBOARD_ARGUMENTS,
        ),
        metric_source_mappings=dict(PIPEBOARD_PHASE1_METRIC_SOURCE_MAPPINGS),
        integrity=integrity,
    )


def test_capability_transition_matrix_exhaustive_11_allowed_and_disallowed() -> None:
    expected_11 = frozenset(
        {
            ("declared", "fixture_certified", "fixture_7a_promotion"),
            ("fixture_certified", "live_certified", "initial_live_certification"),
            ("live_certified", "live_certified", "live_recertification"),
            ("declared", "unavailable", "mark_unavailable"),
            ("declared", "deferred", "mark_deferred"),
            ("unavailable", "revalidation_pending", "begin_revalidation"),
            ("deferred", "revalidation_pending", "begin_revalidation"),
            ("invalidated", "revalidation_pending", "begin_revalidation"),
            (
                "revalidation_pending",
                "declared",
                "complete_revalidation_to_declared",
            ),
            ("fixture_certified", "invalidated", "invalidate_fixture_certified"),
            ("live_certified", "invalidated", "invalidate_live_certified"),
        }
    )
    assert ALLOWED_CAPABILITY_TRANSITIONS == expected_11
    assert len(ALLOWED_CAPABILITY_TRANSITIONS) == 11

    all_states = (
        "declared",
        "fixture_certified",
        "live_certified",
        "unavailable",
        "deferred",
        "invalidated",
        "revalidation_pending",
    )
    all_kinds = (
        "fixture_7a_promotion",
        "initial_live_certification",
        "live_recertification",
        "mark_unavailable",
        "mark_deferred",
        "begin_revalidation",
        "complete_revalidation_to_declared",
        "invalidate_fixture_certified",
        "invalidate_live_certified",
    )

    allowed_count = 0
    rejected_count = 0
    for from_s in all_states:
        for to_s in all_states:
            for kind in all_kinds:
                triple = (from_s, to_s, kind)
                if triple in expected_11:
                    validate_capability_transition(from_s, to_s, kind)  # type: ignore[arg-type]
                    allowed_count += 1
                else:
                    with pytest.raises(ClosedValidationError):
                        validate_capability_transition(from_s, to_s, kind)  # type: ignore[arg-type]
                    rejected_count += 1

    assert allowed_count == 11
    assert rejected_count == (7 * 7 * 9) - 11 == 430

    # Explicit negative checks highlighted in ADR-0001 §§5.1, 5.4
    for bad_triple in (
        ("live_certified", "live_certified", "initial_live_certification"),
        ("invalidated", "fixture_certified", "fixture_7a_promotion"),
        ("invalidated", "live_certified", "initial_live_certification"),
        ("invalidated", "live_certified", "live_recertification"),
        ("declared", "declared", "unknown_kind"),
        ("unknown_state", "declared", "complete_revalidation_to_declared"),
    ):
        with pytest.raises(ClosedValidationError):
            validate_capability_transition(*bad_triple)  # type: ignore[arg-type]

    assert IO_DENIED_CAPABILITY_STATES == frozenset(
        {"unavailable", "deferred", "invalidated", "revalidation_pending"}
    )
    for st in all_states:
        assert is_io_denied_state(st) == (st in IO_DENIED_CAPABILITY_STATES)  # type: ignore[arg-type]
    with pytest.raises(ClosedValidationError):
        is_io_denied_state("bogus_state")  # type: ignore[arg-type]


def test_capability_revalidation_transition_invariants_and_p1_signing(
    tmp_path: Path,
) -> None:
    prior_loc = _loc("smart_ads/private_registry_snapshot/v1", "1")
    new_loc = _loc("smart_ads/private_registry_snapshot/v1", "2")
    ev_loc = _loc("smart_ads/legacy_step2_implementation_evidence/v1", "3")

    for source_state in ("unavailable", "deferred", "invalidated"):
        begin_tr = CapabilityRevalidationTransition(
            transition_id="transition:rev-begin-001",
            capability_ref="cap:campaign-basic-v1",
            capability_semantic_version="1.0.0",
            required_metrics=(
                "metric:spend_v1",
                "metric:clicks_v1",
                "metric:impressions_v1",
            ),
            resource_scope_ref="scope:campaigns-active",
            driver_contract_digest="sha256:" + ("a" * 64),
            pinned_source_digest="sha256:" + ("b" * 64),
            prior_snapshot_locator=prior_loc,
            prior_snapshot_digest=prior_loc.content_digest,
            prior_state=source_state,  # type: ignore[arg-type]
            new_snapshot_locator=new_loc,
            new_snapshot_digest=new_loc.content_digest,
            new_state="revalidation_pending",
            transition_kind="begin_revalidation",
            fresh_evidence_locators=(),
            reason="Begin offline revalidation after recovery.",
            signer_principal_ref="principal:release-authority",
            transitioned_at_utc="2026-11-11T10:00:00Z",
            cas_sequence=1,
        )
        assert begin_tr.required_metrics == (
            "metric:clicks_v1",
            "metric:impressions_v1",
            "metric:spend_v1",
        )
        assert (
            CapabilityRevalidationTransition.from_dict(begin_tr.to_dict())
            == begin_tr
        )

    complete_tr = CapabilityRevalidationTransition(
        transition_id="transition:rev-complete-002",
        capability_ref="cap:campaign-basic-v1",
        capability_semantic_version="1.0.0",
        required_metrics=(
            "metric:clicks_v1",
            "metric:impressions_v1",
            "metric:spend_v1",
        ),
        resource_scope_ref="scope:campaigns-active",
        driver_contract_digest="sha256:" + ("a" * 64),
        pinned_source_digest="sha256:" + ("b" * 64),
        prior_snapshot_locator=prior_loc,
        prior_snapshot_digest=prior_loc.content_digest,
        prior_state="revalidation_pending",
        new_snapshot_locator=new_loc,
        new_snapshot_digest=new_loc.content_digest,
        new_state="declared",
        transition_kind="complete_revalidation_to_declared",
        fresh_evidence_locators=(ev_loc,),
        reason="Fresh offline 7A prerequisites verified.",
        signer_principal_ref="principal:release-authority",
        transitioned_at_utc="2026-11-11T11:00:00Z",
        cas_sequence=2,
    )
    assert (
        CapabilityRevalidationTransition.from_dict(complete_tr.to_dict())
        == complete_tr
    )

    base = complete_tr.to_dict()
    for bad_patch in (
        {"fresh_evidence_locators": []},
        {"fresh_evidence_locators": [ev_loc.to_dict(), ev_loc.to_dict()]},
        {
            "new_snapshot_locator": prior_loc.to_dict(),
            "new_snapshot_digest": prior_loc.content_digest,
        },
        {"prior_snapshot_digest": "sha256:" + ("9" * 64)},
        {"new_snapshot_digest": "sha256:" + ("9" * 64)},
        {"required_metrics": ["metric:spend_v1", "metric:clicks_v1"]},
        {"cas_sequence": 0},
        {"cas_sequence": -1},
        {"cas_sequence": True},
        {
            "prior_state": "declared",
            "new_state": "fixture_certified",
            "transition_kind": "fixture_7a_promotion",
        },
        {"extra_key": "rejected"},
    ):
        with pytest.raises(ClosedValidationError):
            CapabilityRevalidationTransition.from_dict(dict(base, **bad_patch))

    priv = tmp_path / "ed25519.pem"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(priv)],
        check=True,
        capture_output=True,
    )
    key_id = gov_p1.key_id_for(gov_p1.raw_public_key_from_pem(priv))
    key_reg_loc = _loc("smart_ads/key_authorization_registry/v1", "9")
    tr_p1 = CapabilityRevalidationTransition.from_dict(
        dict(
            base,
            integrity=P1Integrity(
                key_id=key_id, key_registry_snapshot_locator=key_reg_loc
            ).to_dict(),
        )
    )
    signed_tr = gov_p1.sign_envelope(
        tr_p1.to_dict(),
        ADR_P1_DOMAIN_PREFIXES[CapabilityRevalidationTransition.SCHEMA],
        priv,
    )
    parsed_signed = CapabilityRevalidationTransition.from_dict(
        signed_tr, require_signed=True
    )
    assert parsed_signed.integrity is not None and parsed_signed.integrity.is_signed


def test_capability_invalidation_transition_live_head_iff_live_certified_and_p1(
    tmp_path: Path,
) -> None:
    prior_loc = _loc("smart_ads/private_registry_snapshot/v1", "4")
    new_loc = _loc("smart_ads/private_registry_snapshot/v1", "5")
    disq_loc = _loc("smart_ads/collection_result/v1", "6")
    head_loc = _loc("smart_ads/live_certification_head/v1", "7")

    inv_fixture = CapabilityInvalidationTransition(
        transition_id="transition:inv-fix-001",
        capability_ref="cap:campaign-basic-v1",
        prior_snapshot_locator=prior_loc,
        prior_snapshot_digest=prior_loc.content_digest,
        prior_state="fixture_certified",
        new_snapshot_locator=new_loc,
        new_snapshot_digest=new_loc.content_digest,
        new_state="invalidated",
        transition_kind="invalidate_fixture_certified",
        disqualifying_evidence_locators=(disq_loc,),
        invalidated_live_certification_head_locator=None,
        reason="Adapter mapping changed; fixture certification invalidated.",
        signer_principal_ref="principal:release-authority",
        transitioned_at_utc="2026-11-11T12:00:00Z",
        cas_sequence=3,
    )
    assert (
        CapabilityInvalidationTransition.from_dict(inv_fixture.to_dict())
        == inv_fixture
    )

    inv_live = CapabilityInvalidationTransition(
        transition_id="transition:inv-live-002",
        capability_ref="cap:campaign-basic-v1",
        prior_snapshot_locator=prior_loc,
        prior_snapshot_digest=prior_loc.content_digest,
        prior_state="live_certified",
        new_snapshot_locator=new_loc,
        new_snapshot_digest=new_loc.content_digest,
        new_state="invalidated",
        transition_kind="invalidate_live_certified",
        disqualifying_evidence_locators=(disq_loc,),
        invalidated_live_certification_head_locator=head_loc,
        reason="7B recertification bundle failed completeness.",
        signer_principal_ref="principal:release-authority",
        transitioned_at_utc="2026-11-11T12:30:00Z",
        cas_sequence=4,
    )
    assert (
        CapabilityInvalidationTransition.from_dict(inv_live.to_dict()) == inv_live
    )

    # iff rule: fixture_certified MUST have None; live_certified MUST have live_certification_head/v1
    with pytest.raises(ClosedValidationError):
        CapabilityInvalidationTransition.from_dict(
            dict(
                inv_fixture.to_dict(),
                invalidated_live_certification_head_locator=head_loc.to_dict(),
            )
        )
    with pytest.raises(ClosedValidationError):
        CapabilityInvalidationTransition.from_dict(
            dict(
                inv_live.to_dict(),
                invalidated_live_certification_head_locator=None,
            )
        )
    with pytest.raises(ClosedValidationError):
        CapabilityInvalidationTransition.from_dict(
            dict(
                inv_live.to_dict(),
                invalidated_live_certification_head_locator=_loc(
                    "smart_ads/live_certification_certificate/v1", "8"
                ).to_dict(),
            )
        )

    for bad_inv_patch in (
        {"disqualifying_evidence_locators": []},
        {"disqualifying_evidence_locators": [disq_loc.to_dict(), disq_loc.to_dict()]},
        {
            "new_snapshot_locator": prior_loc.to_dict(),
            "new_snapshot_digest": prior_loc.content_digest,
        },
        {"transition_kind": "invalidate_fixture_certified"},
        {"new_state": "declared"},
        {"cas_sequence": 0},
        {"cas_sequence": False},
        {"extra": "bad"},
    ):
        with pytest.raises(ClosedValidationError):
            CapabilityInvalidationTransition.from_dict(
                dict(inv_live.to_dict(), **bad_inv_patch)
            )

    priv = tmp_path / "ed25519.pem"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(priv)],
        check=True,
        capture_output=True,
    )
    key_id = gov_p1.key_id_for(gov_p1.raw_public_key_from_pem(priv))
    key_reg_loc = _loc("smart_ads/key_authorization_registry/v1", "9")
    inv_live_p1 = CapabilityInvalidationTransition.from_dict(
        dict(
            inv_live.to_dict(),
            integrity=P1Integrity(
                key_id=key_id, key_registry_snapshot_locator=key_reg_loc
            ).to_dict(),
        )
    )
    signed_inv = gov_p1.sign_envelope(
        inv_live_p1.to_dict(),
        ADR_P1_DOMAIN_PREFIXES[CapabilityInvalidationTransition.SCHEMA],
        priv,
    )
    parsed_signed = CapabilityInvalidationTransition.from_dict(
        signed_inv, require_signed=True
    )
    assert parsed_signed.integrity is not None and parsed_signed.integrity.is_signed


def test_pipeboard_phase1_contract_pinned_d26_upstream_limits_and_rejections(
    tmp_path: Path,
) -> None:
    assert PINNED_LEGACY_REPO == "mbras-tech/mbras-campaigns"
    assert PINNED_LEGACY_COMMIT == "d26c73d8508c7c3d43161fe36a80c44a46bf0f2d"
    assert PINNED_PIPEBOARD_D26_SPECS == (
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
    assert FORBIDDEN_PIPEBOARD_ARGUMENTS == (
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
    assert isinstance(PIPEBOARD_PHASE1_METRIC_SOURCE_MAPPINGS, MappingProxyType)
    assert dict(PIPEBOARD_PHASE1_METRIC_SOURCE_MAPPINGS) == {
        "metric:clicks_v1": "source-metric:provider:pipeboard.clicks:v1",
        "metric:impressions_v1": "source-metric:provider:pipeboard.impressions:v1",
        "metric:spend_v1": "source-metric:provider:pipeboard.spend:v1",
    }

    contract = _make_pipeboard_contract()
    packet = contract.legacy_source_packet
    assert packet.packet_digest == self_digest_jcs_sha256(
        packet.to_dict(),
        digest_member="packet_digest",
        strip_integrity=False,
    )
    assert PipeboardPhase1Contract.from_dict(contract.to_dict()) == contract

    # Reject altered OID, SHA-256, repo, commit, provenance type, missing member, or tampered packet_digest
    pkt_dict = packet.to_dict()
    altered_member_oid = dict(
        pkt_dict["members"][0], git_blob_oid="0" * 40
    )
    altered_member_sha = dict(
        pkt_dict["members"][0], file_content_sha256="sha256:" + ("0" * 64)
    )
    altered_member_loc = dict(
        pkt_dict["members"][0],
        git_artifact_provenance_locator=_loc(
            "smart_ads/effect_proof/v1", "1"
        ).to_dict(),
    )
    for bad_pkt in (
        dict(pkt_dict, repository="other/repo"),
        dict(pkt_dict, commit_sha="f" * 40),
        dict(pkt_dict, packet_digest="sha256:" + ("0" * 64)),
        dict(pkt_dict, packet_digest=""),
        dict(pkt_dict, members=pkt_dict["members"][:4]),
        dict(pkt_dict, members=list(reversed(pkt_dict["members"]))),
        dict(
            pkt_dict,
            members=[altered_member_oid, *pkt_dict["members"][1:]],
        ),
        dict(
            pkt_dict,
            members=[altered_member_sha, *pkt_dict["members"][1:]],
        ),
        dict(
            pkt_dict,
            members=[altered_member_loc, *pkt_dict["members"][1:]],
        ),
    ):
        with pytest.raises(ClosedValidationError):
            LegacySourcePacket.from_dict(bad_pkt)

    # Reject hosted_parity_proven=True or altered upstream reference
    up_dict = contract.upstream_reference.to_dict()
    for bad_up_patch in (
        {"hosted_parity_proven": True},
        {"hosted_parity_proven": 0},
        {"repository": "other/meta-ads-mcp"},
        {"commit_sha": "0" * 40},
        {"path": "meta_ads_mcp/other.py"},
        {"symbol": "get_campaigns"},
    ):
        with pytest.raises(ClosedValidationError):
            PinnedUpstreamReference.from_dict(dict(up_dict, **bad_up_patch))

    # Reject any altered HTTP / JSON-RPC / byte ceiling / row ceiling / forbidden_arguments limit
    lim_dict = contract.transport_limits.to_dict()
    for bad_lim_patch in (
        {"endpoint_url": "https://evil.example.com/"},
        {"http_method": "GET"},
        {"connect_timeout_seconds": 10},
        {"connect_timeout_seconds": True},
        {"wall_deadline_seconds": 120},
        {"request_content_type": "text/plain"},
        {"request_accept": "application/json"},
        {"request_accept_encoding": "gzip"},
        {"read_chunk_bytes": 32768},
        {"max_streamed_bytes": 4_194_304},
        {"max_decoded_text_bytes": 4_194_304},
        {"jsonrpc_method": "tools/list"},
        {"tool_name": "get_campaigns"},
        {"level": "adset"},
        {"limit": 500},
        {"compact": False},
        {"compact": 1},
        {"max_campaign_rows": 101},
        {"forbidden_arguments": list(FORBIDDEN_PIPEBOARD_ARGUMENTS[:-1])},
    ):
        with pytest.raises(ClosedValidationError):
            PipeboardTransportLimits.from_dict(dict(lim_dict, **bad_lim_patch))

    # Reject altered driver_id, contract_id, or metric_source_mappings
    c_dict = contract.to_dict()
    for bad_c_patch in (
        {"driver_id": "meta_direct"},
        {"contract_id": "binding:wrong-prefix"},
        {
            "metric_source_mappings": {
                "metric:clicks_v1": "source-metric:provider:pipeboard.clicks:v1"
            }
        },
        {
            "metric_source_mappings": dict(
                PIPEBOARD_PHASE1_METRIC_SOURCE_MAPPINGS,
                **{
                    "metric:reach_v1": "source-metric:provider:pipeboard.reach:v1"
                },
            )
        },
        {"extra_member": "forbidden"},
    ):
        with pytest.raises(ClosedValidationError):
            PipeboardPhase1Contract.from_dict(dict(c_dict, **bad_c_patch))

    priv = tmp_path / "ed25519.pem"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(priv)],
        check=True,
        capture_output=True,
    )
    key_id = gov_p1.key_id_for(gov_p1.raw_public_key_from_pem(priv))
    key_reg_loc = _loc("smart_ads/key_authorization_registry/v1", "9")
    contract_p1 = _make_pipeboard_contract(
        integrity=P1Integrity(
            key_id=key_id, key_registry_snapshot_locator=key_reg_loc
        )
    )
    signed_contract = gov_p1.sign_envelope(
        contract_p1.to_dict(),
        ADR_P1_DOMAIN_PREFIXES[PipeboardPhase1Contract.SCHEMA],
        priv,
    )
    parsed_signed = PipeboardPhase1Contract.from_dict(
        signed_contract, require_signed=True
    )
    assert parsed_signed.integrity is not None and parsed_signed.integrity.is_signed


def test_all_five_domain_schemas_match_core_schema_descriptors() -> None:
    key_reg_loc = _loc("smart_ads/key_authorization_registry/v1", "1")
    sample_p1 = P1Integrity(
        key_id="key:ed25519:" + ("a" * 64),
        key_registry_snapshot_locator=key_reg_loc,
    )
    drv_loc = _loc("smart_ads/pipeboard_phase1_contract/v1", "2")
    reg_loc_1 = _loc("smart_ads/private_registry_snapshot/v1", "3")
    reg_loc_2 = _loc("smart_ads/private_registry_snapshot/v1", "4")

    snap = PrivateRegistrySnapshot(
        snapshot_id="registry-snapshot:snap-001",
        tenant_ref="tenant:ibvi",
        issued_at_utc="2026-11-11T00:00:00Z",
        valid_until_utc="2026-11-12T00:00:00Z",
        resource_ref_mapping_version="hmac-sha256-b32-v1",
        key_identity="key:tenant-ibvi-hmac-v1",
        bindings=(
            RegistryBinding(
                binding_ref="binding:meta-primary",
                account_ref="account:ibvi-01",
                transport_provider_ref="provider:pipeboard",
                ad_platform_ref="meta",
                currency="BRL",
                driver_id="pipeboard_hosted",
            ),
        ),
        authorized_scopes=(
            AuthorizedScopeRelation(
                front_ref="front:ibvi-dashboard",
                profile_ref="profile:ops-reader",
                binding_ref="binding:meta-primary",
                resource_scope_ref="scope:campaigns-active",
            ),
        ),
        capabilities=(
            DriverCapabilityEntry(
                capability_ref="cap:campaign-basic-v1",
                capability_semantic_version="1.0.0",
                driver_id="pipeboard_hosted",
                driver_contract_locator=drv_loc,
                driver_contract_digest=drv_loc.content_digest,
                resource_scope_ref="scope:campaigns-active",
                state="live_certified",
                required_metrics=("metric:clicks_v1",),
            ),
        ),
        integrity=sample_p1,
    )

    ref_1 = derive_resource_ref(
        key_handle=TenantResourceKeyHandle(
            tenant_ref="tenant:ibvi",
            key_identity="key:tenant-ibvi-hmac-v1",
            secret_bytes=b"x" * 32,
        ),
        mapping_version="hmac-sha256-b32-v1",
        ad_platform_ref="meta",
        resource_level="campaign",
        raw_provider_id="1001",
    )
    inv = ExpectedResourceInventory(
        inventory_id="inventory:inv-001",
        registry_snapshot_locator=reg_loc_1,
        registry_snapshot_digest=reg_loc_1.content_digest,
        tenant_ref="tenant:ibvi",
        binding_ref="binding:meta-primary",
        account_ref="account:ibvi-01",
        resource_scope_ref="scope:campaigns-active",
        date_range=DateRange(
            start_date="2026-11-10", end_date="2026-11-10", inclusive=True
        ),
        expected_resources=(
            ExpectedResourceKey(
                binding_ref="binding:meta-primary",
                account_ref="account:ibvi-01",
                resource_ref=ref_1,
                resource_level="campaign",
                metric_date="2026-11-10",
                attribution_ref="attribution:not_applicable",
                breakdown_signature="breakdown:none",
            ),
        ),
        integrity=sample_p1,
    )

    rev_tr = CapabilityRevalidationTransition(
        transition_id="transition:rev-001",
        capability_ref="cap:campaign-basic-v1",
        capability_semantic_version="1.0.0",
        required_metrics=("metric:clicks_v1",),
        resource_scope_ref="scope:campaigns-active",
        driver_contract_digest="sha256:" + ("a" * 64),
        pinned_source_digest="sha256:" + ("b" * 64),
        prior_snapshot_locator=reg_loc_1,
        prior_snapshot_digest=reg_loc_1.content_digest,
        prior_state="invalidated",
        new_snapshot_locator=reg_loc_2,
        new_snapshot_digest=reg_loc_2.content_digest,
        new_state="revalidation_pending",
        transition_kind="begin_revalidation",
        fresh_evidence_locators=(),
        reason="Start revalidation",
        signer_principal_ref="principal:release-authority",
        transitioned_at_utc="2026-11-11T10:00:00Z",
        cas_sequence=1,
        integrity=sample_p1,
    )

    inv_tr = CapabilityInvalidationTransition(
        transition_id="transition:inv-001",
        capability_ref="cap:campaign-basic-v1",
        prior_snapshot_locator=reg_loc_1,
        prior_snapshot_digest=reg_loc_1.content_digest,
        prior_state="live_certified",
        new_snapshot_locator=reg_loc_2,
        new_snapshot_digest=reg_loc_2.content_digest,
        new_state="invalidated",
        transition_kind="invalidate_live_certified",
        disqualifying_evidence_locators=(_loc("smart_ads/collection_result/v1", "5"),),
        invalidated_live_certification_head_locator=_loc(
            "smart_ads/live_certification_head/v1", "6"
        ),
        reason="7B failed",
        signer_principal_ref="principal:release-authority",
        transitioned_at_utc="2026-11-11T11:00:00Z",
        cas_sequence=2,
        integrity=sample_p1,
    )

    pb_contract = _make_pipeboard_contract(integrity=sample_p1)

    by_id: dict[str, Any] = {d["schema_id"]: d for d in CORE_SCHEMA_DESCRIPTORS}
    for schema_id, obj_dict in (
        (PrivateRegistrySnapshot.SCHEMA, snap.to_dict()),
        (ExpectedResourceInventory.SCHEMA, inv.to_dict()),
        (CapabilityRevalidationTransition.SCHEMA, rev_tr.to_dict()),
        (CapabilityInvalidationTransition.SCHEMA, inv_tr.to_dict()),
        (PipeboardPhase1Contract.SCHEMA, pb_contract.to_dict()),
    ):
        assert list(by_id[schema_id]["fields"]) == sorted(
            obj_dict.keys(), key=lambda s: s.encode("utf-8")
        )
        assert (
            by_id[schema_id]["p1_domain_prefix"]
            == ADR_P1_DOMAIN_PREFIXES[schema_id]
        )
