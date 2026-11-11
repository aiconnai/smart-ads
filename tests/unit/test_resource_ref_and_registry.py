"""Unit tests for smart_ads.domain.resource_ref and smart_ads.domain.registry (ADR-0001 §§4.2, 8)."""
from __future__ import annotations

import base64
import hashlib
import hmac
from pathlib import Path
import subprocess
from typing import Any

import pytest

from smart_ads.contracts import (
    ADR_P1_DOMAIN_PREFIXES,
    SUPPLEMENTAL_DOMAIN_PREFIXES,
    ArtifactLocator,
    ClosedValidationError,
    DateRange,
    P1Integrity,
    canonicalize_jcs,
    domain_jcs_sha256,
    jcs_sha256,
)
from smart_ads.contracts.schemas import CORE_SCHEMA_DESCRIPTORS
import smart_ads.domain as domain
from smart_ads.domain.registry import (
    AuthorizedScopeRelation,
    DriverCapabilityEntry,
    ExpectedResourceInventory,
    ExpectedResourceKey,
    PrivateRegistrySnapshot,
    RegistryBinding,
    compute_resource_mapping_contract_digest,
)
from smart_ads.domain.resource_ref import (
    CANONICAL_RESOURCE_REF_RE,
    BidirectionalResourceDirectory,
    TenantResourceKeyHandle,
    derive_resource_ref,
    validate_resource_ref,
    verify_resource_ref,
)
from tools.governance import p1 as gov_p1


def _loc(artifact_type: str, fill: str = "a") -> ArtifactLocator:
    return ArtifactLocator.from_digest(artifact_type, "sha256:" + (fill * 64))


def _make_key_handle(
    secret: bytes = b"SUPER_SECRET_KEY_BYTES_0123456789ABCDEF",
) -> TenantResourceKeyHandle:
    return TenantResourceKeyHandle(
        tenant_ref="tenant:ibvi",
        key_identity="key:tenant-ibvi-hmac-v1",
        secret_bytes=secret,
    )


def _make_capability_entry(
    *,
    capability_ref: str = "cap:campaign-basic-v1",
    resource_scope_ref: str = "scope:campaigns-active",
    state: str = "live_certified",
) -> DriverCapabilityEntry:
    drv_loc = _loc("smart_ads/pipeboard_phase1_contract/v1", "d")
    return DriverCapabilityEntry(
        capability_ref=capability_ref,
        capability_semantic_version="1.0.0",
        driver_id="pipeboard_hosted",
        driver_contract_locator=drv_loc,
        driver_contract_digest=drv_loc.content_digest,
        resource_scope_ref=resource_scope_ref,
        state=state,  # type: ignore[arg-type]
        required_metrics=(
            "metric:clicks_v1",
            "metric:impressions_v1",
            "metric:spend_v1",
        ),
    )


def _make_registry_snapshot(
    *,
    integrity: P1Integrity | None = None,
    resource_mapping_contract_digest: str = "",
) -> PrivateRegistrySnapshot:
    b2 = RegistryBinding(
        binding_ref="binding:meta-secondary",
        account_ref="account:ibvi-02",
        transport_provider_ref="provider:pipeboard",
        ad_platform_ref="meta",
        currency="BRL",
        driver_id="pipeboard_hosted",
    )
    b1 = RegistryBinding(
        binding_ref="binding:meta-primary",
        account_ref="account:ibvi-01",
        transport_provider_ref="provider:pipeboard",
        ad_platform_ref="meta",
        currency="BRL",
        driver_id="pipeboard_hosted",
    )
    s2 = AuthorizedScopeRelation(
        front_ref="front:ibvi-dashboard",
        profile_ref="profile:ops-reader",
        binding_ref="binding:meta-secondary",
        resource_scope_ref="scope:campaigns-secondary",
    )
    s1 = AuthorizedScopeRelation(
        front_ref="front:ibvi-dashboard",
        profile_ref="profile:ops-reader",
        binding_ref="binding:meta-primary",
        resource_scope_ref="scope:campaigns-active",
    )
    c2 = _make_capability_entry(
        capability_ref="cap:z-cap-v1",
        resource_scope_ref="scope:campaigns-secondary",
        state="declared",
    )
    c1 = _make_capability_entry(
        capability_ref="cap:campaign-basic-v1",
        resource_scope_ref="scope:campaigns-active",
        state="live_certified",
    )
    return PrivateRegistrySnapshot(
        snapshot_id="registry-snapshot:snap-2026-11-11-001",
        tenant_ref="tenant:ibvi",
        issued_at_utc="2026-11-11T00:00:00Z",
        valid_until_utc="2026-11-12T00:00:00Z",
        resource_ref_mapping_version="hmac-sha256-b32-v1",
        key_identity="key:tenant-ibvi-hmac-v1",
        bindings=(b2, b1),
        authorized_scopes=(s2, s1),
        capabilities=(c2, c1),
        domain_separator="0x00",
        resource_mapping_contract_digest=resource_mapping_contract_digest,
        integrity=integrity,
    )


def test_domain_package_reexports_all_public_symbols() -> None:
    expected = {
        "CANONICAL_RESOURCE_REF_RE",
        "TenantResourceKeyHandle",
        "derive_resource_ref",
        "validate_resource_ref",
        "verify_resource_ref",
        "BidirectionalResourceDirectory",
        "CapabilityState",
        "DriverCapabilityEntry",
        "RegistryBinding",
        "AuthorizedScopeRelation",
        "compute_resource_mapping_contract_digest",
        "PrivateRegistrySnapshot",
        "ExpectedResourceKey",
        "ExpectedResourceInventory",
        "TransitionKind",
        "ALLOWED_CAPABILITY_TRANSITIONS",
        "IO_DENIED_CAPABILITY_STATES",
        "is_io_denied_state",
        "validate_capability_transition",
        "CapabilityRevalidationTransition",
        "CapabilityInvalidationTransition",
        "PINNED_LEGACY_REPO",
        "PINNED_LEGACY_COMMIT",
        "PINNED_PIPEBOARD_D26_SPECS",
        "PinnedGitArtifactMember",
        "LegacySourcePacket",
        "PinnedUpstreamReference",
        "FORBIDDEN_PIPEBOARD_ARGUMENTS",
        "PIPEBOARD_PHASE1_METRIC_SOURCE_MAPPINGS",
        "PipeboardTransportLimits",
        "PipeboardPhase1Contract",
    }
    assert expected.issubset(set(domain.__all__))
    for symbol in expected:
        assert hasattr(domain, symbol), f"Missing re-export on smart_ads.domain: {symbol}"


def test_validate_resource_ref_canonical_base32_and_trailing_bits() -> None:
    assert CANONICAL_RESOURCE_REF_RE.pattern == r"^resource:[a-z2-7]{51}[aq]$"

    all_zero_ref = "resource:" + ("a" * 52)
    all_ones_ref = "resource:" + ("7" * 51) + "q"
    assert validate_resource_ref(all_zero_ref) == all_zero_ref
    assert validate_resource_ref(all_ones_ref) == all_ones_ref

    # Reject all 30 Base32 characters with non-zero 4 trailing padding bits (b..p and r..z, 2..7)
    non_zero_pad_chars = "bcdefghijklmnoprstuvwxyz234567"
    assert len(non_zero_pad_chars) == 30
    for bad_last in non_zero_pad_chars:
        candidate = "resource:" + ("a" * 51) + bad_last
        with pytest.raises(ClosedValidationError):
            validate_resource_ref(candidate)

    # Reject uppercase, '=' padding, wrong prefix, wrong length, invalid alphabet, NUL, newline, non-str
    for invalid in (
        None,
        123,
        b"resource:" + (b"a" * 52),
        "",
        "resource:cmp-1",
        "account:" + ("a" * 52),
        "resource:" + ("A" * 52),
        "resource:" + ("a" * 51) + "Q",
        "resource:" + ("a" * 52) + "====",
        "resource:" + ("a" * 51),
        "resource:" + ("a" * 53),
        "resource:" + ("0" * 51) + "a",
        "resource:" + ("1" * 51) + "a",
        "resource:" + ("8" * 51) + "a",
        "resource:" + ("9" * 51) + "a",
        all_zero_ref + "\n",
        all_zero_ref + "\x00",
    ):
        with pytest.raises(ClosedValidationError):
            validate_resource_ref(invalid)


def test_tenant_resource_key_handle_validation_and_secret_redaction() -> None:
    secret_marker = b"SUPER_SECRET_KEY_BYTES_0123456789ABCDEF"
    handle = _make_key_handle(secret_marker)
    assert handle.tenant_ref == "tenant:ibvi"
    assert handle.key_identity == "key:tenant-ibvi-hmac-v1"
    assert handle.secret_bytes == secret_marker

    for text in (repr(handle), str(handle)):
        assert "SUPER_SECRET_KEY_BYTES" not in text
        assert secret_marker.hex() not in text
        assert "tenant:ibvi" in text
        assert "key:tenant-ibvi-hmac-v1" in text

    short_secret = b"SHORT_SECRET_MARKER_XYZ"
    with pytest.raises(ClosedValidationError) as exc_info:
        TenantResourceKeyHandle(
            tenant_ref="tenant:ibvi",
            key_identity="key:tenant-ibvi-hmac-v1",
            secret_bytes=short_secret,
        )
    assert "SHORT_SECRET_MARKER_XYZ" not in str(exc_info.value)
    assert short_secret.hex() not in str(exc_info.value)

    for bad_kwargs in (
        {
            "tenant_ref": "account:wrong",
            "key_identity": "key:k1",
            "secret_bytes": secret_marker,
        },
        {
            "tenant_ref": "tenant:ibvi",
            "key_identity": "tenant:wrong",
            "secret_bytes": secret_marker,
        },
        {
            "tenant_ref": "tenant:ibvi",
            "key_identity": "key:k1",
            "secret_bytes": "a" * 32,
        },
        {
            "tenant_ref": "tenant:ibvi",
            "key_identity": "key:k1",
            "secret_bytes": bytearray(secret_marker),
        },
    ):
        with pytest.raises(ClosedValidationError):
            TenantResourceKeyHandle(**bad_kwargs)  # type: ignore[arg-type]


def test_derive_and_verify_resource_ref_determinism_sensitivity_and_redaction() -> None:
    secret = b"0123456789abcdef0123456789abcdef"
    handle = _make_key_handle(secret)
    raw_id = "120210987654321"

    derived = derive_resource_ref(
        key_handle=handle,
        mapping_version="hmac-sha256-b32-v1",
        domain_separator="0x00",
        ad_platform_ref="meta",
        resource_level="campaign",
        raw_provider_id=raw_id,
    )
    assert validate_resource_ref(derived) == derived

    expected_preimage = b"\x00".join(
        [
            b"hmac-sha256-b32-v1",
            b"meta",
            b"campaign",
            raw_id.encode("utf-8"),
        ]
    )
    expected_digest = hmac.new(secret, expected_preimage, hashlib.sha256).digest()
    expected_ref = (
        "resource:"
        + base64.b32encode(expected_digest).decode("ascii").rstrip("=").lower()
    )
    assert derived == expected_ref

    assert verify_resource_ref(
        expected_resource_ref=derived,
        key_handle=handle,
        mapping_version="hmac-sha256-b32-v1",
        domain_separator="0x00",
        ad_platform_ref="meta",
        resource_level="campaign",
        raw_provider_id=raw_id,
    )
    assert not verify_resource_ref(
        expected_resource_ref=derived,
        key_handle=handle,
        mapping_version="hmac-sha256-b32-v1",
        domain_separator="0x00",
        ad_platform_ref="meta",
        resource_level="campaign",
        raw_provider_id="120210987654322",
    )
    assert not verify_resource_ref(
        expected_resource_ref=derived,
        key_handle=handle,
        mapping_version="hmac-sha256-b32-v2",
        domain_separator="0x00",
        ad_platform_ref="meta",
        resource_level="campaign",
        raw_provider_id=raw_id,
    )

    # Wrong domain_separator or NUL injection rejects
    for bad_sep in ("0x01", "", "\x00", "|"):
        with pytest.raises(ClosedValidationError):
            derive_resource_ref(
                key_handle=handle,
                mapping_version="hmac-sha256-b32-v1",
                domain_separator=bad_sep,
                ad_platform_ref="meta",
                resource_level="campaign",
                raw_provider_id=raw_id,
            )

    with pytest.raises(ClosedValidationError):
        derive_resource_ref(
            key_handle=handle,
            mapping_version="hmac-sha256-b32-v1",
            ad_platform_ref="meta\x00injected",
            resource_level="campaign",
            raw_provider_id=raw_id,
        )

    # Invalid raw_provider_id MUST fail closed WITHOUT echoing raw_provider_id in exception!
    for bad_raw_id, leak_probe in (
        ("RAW_SECRET_CAMPAIGN_ID_777\x00INJECT", "RAW_SECRET_CAMPAIGN_ID_777"),
        ("RAW_NFD_CAMPAIGN_888_a\u0301", "RAW_NFD_CAMPAIGN_888"),
        ("   ", "0123456789abcdef"),
        ("", "0123456789abcdef"),
    ):
        with pytest.raises(ClosedValidationError) as exc_info:
            derive_resource_ref(
                key_handle=handle,
                mapping_version="hmac-sha256-b32-v1",
                ad_platform_ref="meta",
                resource_level="campaign",
                raw_provider_id=bad_raw_id,
            )
        assert leak_probe not in str(exc_info.value)
        assert leak_probe not in repr(exc_info.value)


def test_bidirectional_resource_directory_bijection_collision_and_redaction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = b"SECRET_HMAC_KEY_FOR_DIRECTORY_32B!!"
    handle = _make_key_handle(secret)
    directory = BidirectionalResourceDirectory(
        key_handle=handle,
        mapping_version="hmac-sha256-b32-v1",
        domain_separator="0x00",
        ad_platform_ref="meta",
        resource_level="campaign",
    )

    ref_a = directory.register("RAW_CAMPAIGN_AAA_1001")
    ref_b = directory.register("RAW_CAMPAIGN_BBB_2002")
    assert ref_a != ref_b
    # Idempotent registration of identical pair returns same resource_ref
    assert directory.register("RAW_CAMPAIGN_AAA_1001") == ref_a
    assert directory.resolve_resource_ref("RAW_CAMPAIGN_AAA_1001") == ref_a
    assert directory.resolve_resource_ref("RAW_CAMPAIGN_BBB_2002") == ref_b

    known = directory.known_resource_refs()
    assert known == tuple(sorted((ref_a, ref_b), key=lambda s: s.encode("utf-8")))

    with pytest.raises(AttributeError):
        directory.mapping_version = "tampered"  # type: ignore[misc]

    # register_verified_pair accepts matching pair and rejects mismatched pair without leaking raw ID
    raw_c = "RAW_CAMPAIGN_CCC_3003"
    ref_c = derive_resource_ref(
        key_handle=handle,
        mapping_version="hmac-sha256-b32-v1",
        ad_platform_ref="meta",
        resource_level="campaign",
        raw_provider_id=raw_c,
    )
    directory.register_verified_pair(raw_c, ref_c)
    directory.register_verified_pair(raw_c, ref_c)  # idempotent
    assert directory.resolve_resource_ref(raw_c) == ref_c

    with pytest.raises(ClosedValidationError) as mismatch_exc:
        directory.register_verified_pair("RAW_CAMPAIGN_MISMATCH_4004", ref_a)
    assert "RAW_CAMPAIGN_MISMATCH_4004" not in str(mismatch_exc.value)
    assert "RAW_CAMPAIGN_AAA_1001" not in str(mismatch_exc.value)

    # Unknown lookup fails closed without echoing raw_provider_id
    with pytest.raises(ClosedValidationError) as unknown_exc:
        directory.resolve_resource_ref("RAW_UNKNOWN_CAMPAIGN_9999")
    assert "RAW_UNKNOWN_CAMPAIGN_9999" not in str(unknown_exc.value)

    # repr() and str() NEVER expose raw_provider_id or secret_bytes
    for rendered in (repr(directory), str(directory)):
        assert "RAW_CAMPAIGN" not in rendered
        assert "SECRET_HMAC_KEY" not in rendered
        assert secret.hex() not in rendered
        assert "tenant:ibvi" in rendered
        assert "key:tenant-ibvi-hmac-v1" in rendered
        assert "hmac-sha256-b32-v1" in rendered
        assert "3" in rendered

    # Simulate cryptographic collision across two distinct raw_provider_ids
    class _FixedHmac:
        def digest(self) -> bytes:
            return b"\x42" * 32

    monkeypatch.setattr(hmac, "new", lambda *_args, **_kwargs: _FixedHmac())
    coll_dir = BidirectionalResourceDirectory(
        key_handle=handle,
        mapping_version="hmac-sha256-b32-v1",
        domain_separator="0x00",
        ad_platform_ref="meta",
        resource_level="campaign",
    )
    fixed_ref = coll_dir.register("COLLIDING_RAW_ID_ONE")
    with pytest.raises(ClosedValidationError) as coll_exc_1:
        coll_dir.register("COLLIDING_RAW_ID_TWO")
    assert "COLLIDING_RAW_ID_ONE" not in str(coll_exc_1.value)
    assert "COLLIDING_RAW_ID_TWO" not in str(coll_exc_1.value)

    with pytest.raises(ClosedValidationError) as coll_exc_2:
        coll_dir.register_verified_pair("COLLIDING_RAW_ID_TWO", fixed_ref)
    assert "COLLIDING_RAW_ID_ONE" not in str(coll_exc_2.value)
    assert "COLLIDING_RAW_ID_TWO" not in str(coll_exc_2.value)


def test_registry_binding_authorized_scope_and_driver_capability_entry() -> None:
    drv_loc = _loc("smart_ads/pipeboard_phase1_contract/v1", "d")
    cap = DriverCapabilityEntry(
        capability_ref="cap:campaign-basic-v1",
        capability_semantic_version="1.0.0",
        driver_id="pipeboard_hosted",
        driver_contract_locator=drv_loc,
        driver_contract_digest=drv_loc.content_digest,
        resource_scope_ref="scope:campaigns-active",
        state="fixture_certified",
        required_metrics=(
            "metric:spend_v1",
            "metric:clicks_v1",
            "metric:impressions_v1",
        ),
    )
    assert cap.required_metrics == (
        "metric:clicks_v1",
        "metric:impressions_v1",
        "metric:spend_v1",
    )
    assert len(cap.to_dict()) == 8
    assert cap.capability_snapshot_digest == jcs_sha256(cap.to_dict())
    assert DriverCapabilityEntry.from_dict(cap.to_dict()) == cap

    # from_dict requires required_metrics already UTF-8 sorted, exact 8 keys, matching digest, valid state
    cap_dict = cap.to_dict()
    for bad_cap_patch in (
        {"required_metrics": ["metric:spend_v1", "metric:clicks_v1"]},
        {"required_metrics": []},
        {"driver_contract_digest": "sha256:" + ("0" * 64)},
        {"state": "certified"},
        {"extra_field": "forbidden"},
    ):
        with pytest.raises(ClosedValidationError):
            DriverCapabilityEntry.from_dict(dict(cap_dict, **bad_cap_patch))

    binding = RegistryBinding(
        binding_ref="binding:meta-primary",
        account_ref="account:ibvi-01",
        transport_provider_ref="provider:pipeboard",
        ad_platform_ref="meta",
        currency="BRL",
        driver_id="pipeboard_hosted",
    )
    assert len(binding.to_dict()) == 6
    assert RegistryBinding.from_dict(binding.to_dict()) == binding

    # Security invariant P-08 / F10: reject private_account_key or unkeyed account hash fields
    for forbidden_key in (
        "private_account_key",
        "account_key_hash",
        "raw_account_id",
        "object_id",
        "access_token",
    ):
        with pytest.raises(ClosedValidationError):
            RegistryBinding.from_dict(
                dict(binding.to_dict(), **{forbidden_key: "act_12345"})
            )
    for bad_binding_patch in (
        {"ad_platform_ref": "google"},
        {"currency": "USD"},
        {"binding_ref": "account:wrong"},
        {"account_ref": "binding:wrong"},
        {"transport_provider_ref": "tenant:wrong"},
        {"driver_id": "   "},
    ):
        with pytest.raises(ClosedValidationError):
            RegistryBinding.from_dict(dict(binding.to_dict(), **bad_binding_patch))

    scope_rel = AuthorizedScopeRelation(
        front_ref="front:ibvi-dashboard",
        profile_ref="profile:ops-reader",
        binding_ref="binding:meta-primary",
        resource_scope_ref="scope:campaigns-active",
    )
    assert len(scope_rel.to_dict()) == 4
    assert AuthorizedScopeRelation.from_dict(scope_rel.to_dict()) == scope_rel
    with pytest.raises(ClosedValidationError):
        AuthorizedScopeRelation.from_dict(dict(scope_rel.to_dict(), extra="x"))


def test_private_registry_snapshot_invariants_sorting_and_p1_signing(
    tmp_path: Path,
) -> None:
    snap = _make_registry_snapshot()
    expected_rmc = compute_resource_mapping_contract_digest(
        tenant_ref="tenant:ibvi",
        resource_ref_mapping_version="hmac-sha256-b32-v1",
        key_identity="key:tenant-ibvi-hmac-v1",
        domain_separator="0x00",
    )
    assert expected_rmc == domain_jcs_sha256(
        SUPPLEMENTAL_DOMAIN_PREFIXES["resource_mapping_contract"],
        {
            "domain_separator": "0x00",
            "key_identity": "key:tenant-ibvi-hmac-v1",
            "resource_ref_mapping_version": "hmac-sha256-b32-v1",
            "tenant_ref": "tenant:ibvi",
        },
    )
    assert snap.resource_mapping_contract_digest == expected_rmc
    assert [b.binding_ref for b in snap.bindings] == [
        "binding:meta-primary",
        "binding:meta-secondary",
    ]
    assert [r.binding_ref for r in snap.authorized_scopes] == [
        "binding:meta-primary",
        "binding:meta-secondary",
    ]
    assert [c.capability_ref for c in snap.capabilities] == [
        "cap:campaign-basic-v1",
        "cap:z-cap-v1",
    ]

    assert snap.get_binding("binding:meta-primary").account_ref == "account:ibvi-01"
    with pytest.raises(ClosedValidationError):
        snap.get_binding("binding:nonexistent")

    assert (
        snap.get_capability(
            "cap:campaign-basic-v1", "scope:campaigns-active"
        ).state
        == "live_certified"
    )
    with pytest.raises(ClosedValidationError):
        snap.get_capability("cap:campaign-basic-v1", "scope:campaigns-secondary")

    assert PrivateRegistrySnapshot.from_dict(snap.to_dict()) == snap

    # Duplicate binding_ref, duplicate account_ref, dangling binding_ref in scopes, duplicate scope 4-tuple, duplicate cap
    b1 = snap.bindings[0]
    b_dup_account = RegistryBinding(
        binding_ref="binding:meta-tertiary",
        account_ref=b1.account_ref,
        transport_provider_ref="provider:pipeboard",
        ad_platform_ref="meta",
        currency="BRL",
        driver_id="pipeboard_hosted",
    )
    with pytest.raises(ClosedValidationError):
        PrivateRegistrySnapshot(
            snapshot_id=snap.snapshot_id,
            tenant_ref=snap.tenant_ref,
            issued_at_utc=snap.issued_at_utc,
            valid_until_utc=snap.valid_until_utc,
            resource_ref_mapping_version=snap.resource_ref_mapping_version,
            key_identity=snap.key_identity,
            bindings=(b1, b1),
            authorized_scopes=(snap.authorized_scopes[0],),
            capabilities=snap.capabilities,
        )
    with pytest.raises(ClosedValidationError):
        PrivateRegistrySnapshot(
            snapshot_id=snap.snapshot_id,
            tenant_ref=snap.tenant_ref,
            issued_at_utc=snap.issued_at_utc,
            valid_until_utc=snap.valid_until_utc,
            resource_ref_mapping_version=snap.resource_ref_mapping_version,
            key_identity=snap.key_identity,
            bindings=(b1, b_dup_account),
            authorized_scopes=(snap.authorized_scopes[0],),
            capabilities=snap.capabilities,
        )
    with pytest.raises(ClosedValidationError):
        PrivateRegistrySnapshot(
            snapshot_id=snap.snapshot_id,
            tenant_ref=snap.tenant_ref,
            issued_at_utc=snap.issued_at_utc,
            valid_until_utc=snap.valid_until_utc,
            resource_ref_mapping_version=snap.resource_ref_mapping_version,
            key_identity=snap.key_identity,
            bindings=(b1,),
            authorized_scopes=snap.authorized_scopes,  # second scope points to missing binding:meta-secondary
            capabilities=snap.capabilities,
        )
    with pytest.raises(ClosedValidationError):
        PrivateRegistrySnapshot(
            snapshot_id=snap.snapshot_id,
            tenant_ref=snap.tenant_ref,
            issued_at_utc=snap.issued_at_utc,
            valid_until_utc=snap.valid_until_utc,
            resource_ref_mapping_version=snap.resource_ref_mapping_version,
            key_identity=snap.key_identity,
            bindings=snap.bindings,
            authorized_scopes=(snap.authorized_scopes[0], snap.authorized_scopes[0]),
            capabilities=snap.capabilities,
        )
    with pytest.raises(ClosedValidationError):
        PrivateRegistrySnapshot(
            snapshot_id=snap.snapshot_id,
            tenant_ref=snap.tenant_ref,
            issued_at_utc=snap.issued_at_utc,
            valid_until_utc=snap.valid_until_utc,
            resource_ref_mapping_version=snap.resource_ref_mapping_version,
            key_identity=snap.key_identity,
            bindings=snap.bindings,
            authorized_scopes=snap.authorized_scopes,
            capabilities=(snap.capabilities[0], snap.capabilities[0]),
        )

    base_dict = snap.to_dict()
    for bad_snap_patch in (
        {"domain_separator": "0x01"},
        {"issued_at_utc": "2026-11-12T00:00:00Z"},
        {"valid_until_utc": "2026-11-10T00:00:00Z"},
        {"resource_mapping_contract_digest": "sha256:" + ("0" * 64)},
        {"resource_mapping_contract_digest": ""},
        {"bindings": list(reversed(base_dict["bindings"]))},
        {"authorized_scopes": list(reversed(base_dict["authorized_scopes"]))},
        {"capabilities": list(reversed(base_dict["capabilities"]))},
        {"bindings": []},
        {"authorized_scopes": []},
        {"capabilities": []},
        {"private_account_key": "secret"},
    ):
        with pytest.raises(ClosedValidationError):
            PrivateRegistrySnapshot.from_dict(dict(base_dict, **bad_snap_patch))

    # P1 signing round-trip
    priv = tmp_path / "ed25519.pem"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(priv)],
        check=True,
        capture_output=True,
    )
    key_id = gov_p1.key_id_for(gov_p1.raw_public_key_from_pem(priv))
    key_reg_loc = _loc("smart_ads/key_authorization_registry/v1", "1")
    snap_p1 = _make_registry_snapshot(
        integrity=P1Integrity(
            key_id=key_id, key_registry_snapshot_locator=key_reg_loc
        )
    )
    signed_snap = gov_p1.sign_envelope(
        snap_p1.to_dict(),
        ADR_P1_DOMAIN_PREFIXES[PrivateRegistrySnapshot.SCHEMA],
        priv,
    )
    parsed_signed = PrivateRegistrySnapshot.from_dict(
        signed_snap, require_signed=True
    )
    assert parsed_signed.integrity is not None and parsed_signed.integrity.is_signed


def test_expected_resource_inventory_completeness_universe_and_p12(
    tmp_path: Path,
) -> None:
    handle = _make_key_handle()
    ref_1 = derive_resource_ref(
        key_handle=handle,
        mapping_version="hmac-sha256-b32-v1",
        ad_platform_ref="meta",
        resource_level="campaign",
        raw_provider_id="1001",
    )
    ref_2 = derive_resource_ref(
        key_handle=handle,
        mapping_version="hmac-sha256-b32-v1",
        ad_platform_ref="meta",
        resource_level="campaign",
        raw_provider_id="1002",
    )

    # ExpectedResourceKey rejects non-canonical resource_ref (e.g., "resource:cmp-1")
    with pytest.raises(ClosedValidationError):
        ExpectedResourceKey(
            binding_ref="binding:meta-primary",
            account_ref="account:ibvi-01",
            resource_ref="resource:cmp-1",
            resource_level="campaign",
            metric_date="2026-11-10",
            attribution_ref="attribution:not_applicable",
            breakdown_signature="breakdown:none",
        )

    u1 = ExpectedResourceKey(
        binding_ref="binding:meta-primary",
        account_ref="account:ibvi-01",
        resource_ref=ref_1,
        resource_level="campaign",
        metric_date="2026-11-10",
        attribution_ref="attribution:not_applicable",
        breakdown_signature="breakdown:none",
    )
    u2 = ExpectedResourceKey(
        binding_ref="binding:meta-primary",
        account_ref="account:ibvi-01",
        resource_ref=ref_2,
        resource_level="campaign",
        metric_date="2026-11-10",
        attribution_ref="attribution:not_applicable",
        breakdown_signature="breakdown:none",
    )
    assert len(u1.to_dict()) == 7
    assert u1.to_identity_array() == [
        "binding:meta-primary",
        "account:ibvi-01",
        ref_1,
        "campaign",
        "2026-11-10",
        "attribution:not_applicable",
        "breakdown:none",
    ]
    assert ExpectedResourceKey.from_dict(u1.to_dict()) == u1

    reg_loc = _loc("smart_ads/private_registry_snapshot/v1", "e")
    unsorted_u = (
        (u2, u1)
        if canonicalize_jcs(u2.to_identity_array())
        > canonicalize_jcs(u1.to_identity_array())
        else (u1, u2)
    )
    inv = ExpectedResourceInventory(
        inventory_id="inventory:inv-2026-11-10-001",
        registry_snapshot_locator=reg_loc,
        registry_snapshot_digest=reg_loc.content_digest,
        tenant_ref="tenant:ibvi",
        binding_ref="binding:meta-primary",
        account_ref="account:ibvi-01",
        resource_scope_ref="scope:campaigns-active",
        date_range=DateRange(
            start_date="2026-11-10",
            end_date="2026-11-10",
            inclusive=True,
        ),
        expected_resources=unsorted_u,
    )
    assert [
        canonicalize_jcs(u.to_identity_array()) for u in inv.expected_resources
    ] == sorted(
        canonicalize_jcs(u.to_identity_array()) for u in inv.expected_resources
    )
    assert ExpectedResourceInventory.from_dict(inv.to_dict()) == inv

    inv_dict = inv.to_dict()
    for bad_inv_patch in (
        {"expected_resources": []},
        {"expected_resources": list(reversed(inv_dict["expected_resources"]))},
        {
            "expected_resources": [
                inv_dict["expected_resources"][0],
                inv_dict["expected_resources"][0],
            ]
        },
        {"registry_snapshot_digest": "sha256:" + ("0" * 64)},
        {"binding_ref": "binding:other"},
        {"account_ref": "account:other"},
        {
            "date_range": {
                "start_date": "2026-11-09",
                "end_date": "2026-11-09",
                "inclusive": True,
            }
        },
        {
            "expected_resources": [
                dict(
                    inv_dict["expected_resources"][0],
                    attribution_ref="attribution:7d_click",
                )
            ]
        },
    ):
        with pytest.raises(ClosedValidationError):
            ExpectedResourceInventory.from_dict(dict(inv_dict, **bad_inv_patch))

    # P1 signing + CORE_SCHEMA_DESCRIPTORS field-set agreement
    priv = tmp_path / "ed25519.pem"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(priv)],
        check=True,
        capture_output=True,
    )
    key_id = gov_p1.key_id_for(gov_p1.raw_public_key_from_pem(priv))
    key_reg_loc = _loc("smart_ads/key_authorization_registry/v1", "1")
    p1_int = P1Integrity(
        key_id=key_id, key_registry_snapshot_locator=key_reg_loc
    )
    inv_p1 = ExpectedResourceInventory(
        inventory_id=inv.inventory_id,
        registry_snapshot_locator=inv.registry_snapshot_locator,
        registry_snapshot_digest=inv.registry_snapshot_digest,
        tenant_ref=inv.tenant_ref,
        binding_ref=inv.binding_ref,
        account_ref=inv.account_ref,
        resource_scope_ref=inv.resource_scope_ref,
        date_range=inv.date_range,
        expected_resources=inv.expected_resources,
        integrity=p1_int,
    )
    signed_inv = gov_p1.sign_envelope(
        inv_p1.to_dict(),
        ADR_P1_DOMAIN_PREFIXES[ExpectedResourceInventory.SCHEMA],
        priv,
    )
    parsed_inv = ExpectedResourceInventory.from_dict(
        signed_inv, require_signed=True
    )
    assert parsed_inv.integrity is not None and parsed_inv.integrity.is_signed

    by_id: dict[str, Any] = {d["schema_id"]: d for d in CORE_SCHEMA_DESCRIPTORS}
    snap_p1 = _make_registry_snapshot(integrity=p1_int)
    assert list(by_id[PrivateRegistrySnapshot.SCHEMA]["fields"]) == sorted(
        snap_p1.to_dict().keys(), key=lambda s: s.encode("utf-8")
    )
    assert list(by_id[ExpectedResourceInventory.SCHEMA]["fields"]) == sorted(
        inv_p1.to_dict().keys(), key=lambda s: s.encode("utf-8")
    )
