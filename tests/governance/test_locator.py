"""Tests for tools.governance.locator — artifact_locator/v1 + content-addressed Store."""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from tools.governance import p1
from tools.governance.jcs import canonicalize
from tools.governance.locator import Store, make_locator, validate_locator


def test_make_locator_has_exactly_six_members() -> None:
    loc = make_locator("smart_ads/gate2_authority_policy/v1", b'{"a":1}')
    assert set(loc.keys()) == {
        "$schema",
        "artifact_type",
        "content_digest",
        "serialization",
        "store_kind",
        "object_ref",
    }
    assert loc["$schema"] == "smart_ads/artifact_locator/v1"
    assert loc["artifact_type"] == "smart_ads/gate2_authority_policy/v1"
    assert loc["serialization"] == "rfc8785-json"
    assert loc["store_kind"] == "cell_immutable_object"
    digest_hex = hashlib.sha256(b'{"a":1}').hexdigest()
    assert loc["content_digest"] == f"sha256:{digest_hex}"
    assert loc["object_ref"] == f"cell-object:sha256:{digest_hex}"


def test_validate_locator_ok() -> None:
    loc = make_locator("smart_ads/gate2_authority_policy/v1", b"payload")
    validate_locator(loc)  # must not raise


def test_validate_locator_rejects_extra_member() -> None:
    loc = make_locator("smart_ads/gate2_authority_policy/v1", b"payload")
    loc["extra"] = "nope"
    with pytest.raises(ValueError):
        validate_locator(loc)


def test_validate_locator_rejects_missing_member() -> None:
    loc = make_locator("smart_ads/gate2_authority_policy/v1", b"payload")
    del loc["store_kind"]
    with pytest.raises(ValueError):
        validate_locator(loc)


def test_validate_locator_rejects_digest_object_ref_mismatch() -> None:
    loc = make_locator("smart_ads/gate2_authority_policy/v1", b"payload")
    loc["object_ref"] = "cell-object:sha256:" + "0" * 64
    with pytest.raises(ValueError):
        validate_locator(loc)


def test_validate_locator_rejects_bad_schema_value() -> None:
    loc = make_locator("smart_ads/gate2_authority_policy/v1", b"payload")
    loc["$schema"] = "smart_ads/something_else/v1"
    with pytest.raises(ValueError):
        validate_locator(loc)


def test_validate_locator_rejects_uppercase_hex() -> None:
    loc = make_locator("smart_ads/gate2_authority_policy/v1", b"payload")
    loc["content_digest"] = loc["content_digest"].upper()
    loc["object_ref"] = loc["object_ref"].upper()
    with pytest.raises(ValueError):
        validate_locator(loc)


def test_store_put_get_roundtrip(tmp_path: Path) -> None:
    store = Store(tmp_path)
    envelope = {"$schema": "smart_ads/gate2_authority_policy/v1", "a": 1}
    loc = store.put(envelope)
    validate_locator(loc)
    assert loc["artifact_type"] == "smart_ads/gate2_authority_policy/v1"
    fetched = store.get(loc)
    assert fetched == envelope


def test_store_put_is_content_addressed(tmp_path: Path) -> None:
    store = Store(tmp_path)
    envelope = {"$schema": "smart_ads/gate2_authority_policy/v1", "a": 1}
    loc1 = store.put(envelope)
    loc2 = store.put(envelope)
    assert loc1 == loc2
    expected_path = tmp_path / "sha256" / (loc1["content_digest"].split(":", 1)[1] + ".json")
    assert expected_path.exists()
    assert expected_path.stat().st_size > 0


def test_store_put_refuses_overwrite_with_different_bytes(tmp_path: Path, monkeypatch) -> None:
    store = Store(tmp_path)
    envelope = {"$schema": "smart_ads/gate2_authority_policy/v1", "a": 1}
    loc = store.put(envelope)
    digest_hex = loc["content_digest"].split(":", 1)[1]
    path = tmp_path / "sha256" / f"{digest_hex}.json"
    path.write_bytes(b"corrupted-not-matching-digest")
    with pytest.raises(ValueError):
        store.put(envelope)


def test_store_get_detects_corruption(tmp_path: Path) -> None:
    store = Store(tmp_path)
    envelope = {"$schema": "smart_ads/gate2_authority_policy/v1", "a": 1}
    loc = store.put(envelope)
    digest_hex = loc["content_digest"].split(":", 1)[1]
    path = tmp_path / "sha256" / f"{digest_hex}.json"
    path.write_bytes(b'{"a":1,"corrupted":true}')
    with pytest.raises(ValueError):
        store.get(loc)


def test_store_get_rejects_artifact_type_mismatch(tmp_path: Path) -> None:
    store = Store(tmp_path)
    envelope = {"$schema": "smart_ads/gate2_authority_policy/v1", "a": 1}
    loc = store.put(envelope)
    mismatched_loc = dict(loc, artifact_type="smart_ads/key_authorization_registry/v1")
    with pytest.raises(ValueError, match="artifact_type_mismatch"):
        store.get(mismatched_loc)


def test_locator_digest_differs_from_p1_content_digest_for_signed_envelope(
    tmp_path: Path,
) -> None:
    import subprocess

    priv = tmp_path / "key.pem"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(priv)],
        check=True,
        capture_output=True,
    )
    raw32 = p1.raw_public_key_from_pem(priv)
    key_id = p1.key_id_for(raw32)
    envelope = {
        "$schema": "smart_ads/gate2_authority_policy/v1",
        "repository": "aiconnai/smart-ads",
        "integrity": {"key_id": key_id, "key_registry_snapshot_locator": None},
    }
    prefix = p1.DOMAIN_PREFIXES["gate2_authority_policy/v1"]
    signed = p1.sign_envelope(envelope, prefix, priv)

    store = Store(tmp_path / "store")
    loc = store.put(signed)

    # locator digest is over the FULL stored bytes; P1 digest is over the preimage.
    assert loc["content_digest"] != signed["integrity"]["content_digest"]
    full_bytes = canonicalize(signed)
    assert loc["content_digest"] == "sha256:" + hashlib.sha256(full_bytes).hexdigest()
