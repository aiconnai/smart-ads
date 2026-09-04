"""Tests for tools.governance.p1 — P1 preimage/digest/message + Ed25519 via openssl."""
from __future__ import annotations

import base64
import copy
import subprocess
from pathlib import Path

import pytest

from tools.governance import p1


@pytest.fixture()
def keypair(tmp_path: Path) -> tuple[Path, bytes]:
    priv = tmp_path / "key.pem"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(priv)],
        check=True,
        capture_output=True,
    )
    raw32 = p1.raw_public_key_from_pem(priv)
    return priv, raw32


def _envelope(key_id: str) -> dict:
    return {
        "$schema": "smart_ads/gate2_authority_policy/v1",
        "repository": "aiconnai/smart-ads",
        "designated_principals": ["principal:ronaldo"],
        "integrity": {
            "key_id": key_id,
            "key_registry_snapshot_locator": None,
        },
    }


def test_domain_prefixes_have_real_newline() -> None:
    assert p1.DOMAIN_PREFIXES["key_authorization_registry/v1"] == "SMART-ADS:KEY-REGISTRY:V1\n"
    assert (
        p1.DOMAIN_PREFIXES["gate2_authority_policy/v1"]
        == "SMART-ADS:GATE2-AUTHORITY-POLICY:V1\n"
    )
    assert (
        p1.DOMAIN_PREFIXES["protected_merge_evidence/v1"] == "SMART-ADS:PROTECTED-MERGE:V1\n"
    )
    assert p1.DOMAIN_PREFIXES["gate2_approval_receipt/v1"] == "SMART-ADS:GATE2-RECEIPT:V1\n"
    assert p1.DOMAIN_PREFIXES["migration_run_context/v1"] == "SMART-ADS:RUN-CONTEXT:V1\n"


def test_preimage_removes_exactly_two_members_keeps_siblings() -> None:
    env = _envelope("key:ed25519:deadbeef")
    env["integrity"]["content_digest"] = "sha256:aaaa"
    env["integrity"]["signature_base64"] = "AAAA"
    pre = p1.preimage(env)
    assert "content_digest" not in pre["integrity"]
    assert "signature_base64" not in pre["integrity"]
    assert pre["integrity"]["key_id"] == "key:ed25519:deadbeef"
    assert pre["integrity"]["key_registry_snapshot_locator"] is None
    # original untouched
    assert "content_digest" in env["integrity"]


def test_preimage_missing_integrity_raises() -> None:
    with pytest.raises(ValueError):
        p1.preimage({"$schema": "x"})


def test_preimage_integrity_not_dict_raises() -> None:
    with pytest.raises(ValueError):
        p1.preimage({"integrity": "nope"})


def test_key_id_for_and_raw_public_key_from_pem(keypair: tuple[Path, bytes]) -> None:
    priv, raw32 = keypair
    assert len(raw32) == 32
    key_id = p1.key_id_for(raw32)
    assert key_id.startswith("key:ed25519:")
    assert len(key_id) == len("key:ed25519:") + 64


def test_sign_and_verify_roundtrip(keypair: tuple[Path, bytes]) -> None:
    priv, raw32 = keypair
    key_id = p1.key_id_for(raw32)
    env = _envelope(key_id)
    prefix = p1.DOMAIN_PREFIXES["gate2_authority_policy/v1"]
    signed = p1.sign_envelope(env, prefix, priv)
    assert signed is not env
    assert "content_digest" not in env["integrity"]
    assert signed["integrity"]["content_digest"].startswith("sha256:")
    sig_raw = base64.b64decode(signed["integrity"]["signature_base64"], validate=True)
    assert len(sig_raw) == 64
    p1.verify_envelope(signed, prefix, raw32)  # must not raise


def test_verify_detects_tamper(keypair: tuple[Path, bytes]) -> None:
    priv, raw32 = keypair
    key_id = p1.key_id_for(raw32)
    env = _envelope(key_id)
    prefix = p1.DOMAIN_PREFIXES["gate2_authority_policy/v1"]
    signed = p1.sign_envelope(env, prefix, priv)
    tampered = copy.deepcopy(signed)
    tampered["repository"] = "someone-else/fork"
    with pytest.raises(ValueError):
        p1.verify_envelope(tampered, prefix, raw32)


def test_verify_wrong_domain_prefix_fails(keypair: tuple[Path, bytes]) -> None:
    priv, raw32 = keypair
    key_id = p1.key_id_for(raw32)
    env = _envelope(key_id)
    prefix = p1.DOMAIN_PREFIXES["gate2_authority_policy/v1"]
    signed = p1.sign_envelope(env, prefix, priv)
    wrong_prefix = p1.DOMAIN_PREFIXES["gate2_approval_receipt/v1"]
    with pytest.raises(ValueError):
        p1.verify_envelope(signed, wrong_prefix, raw32)


def test_verify_base64url_signature_rejected(keypair: tuple[Path, bytes]) -> None:
    """A base64url-encoded signature must be rejected by the strict decoder.

    Standard base64 and base64url differ only in the alphabet used for values 62
    and 63 ('+/' vs '-_'). For roughly 6.7% of random 64-byte Ed25519 signatures
    neither value occurs, so re-encoding produces a byte-identical string and the
    envelope stays valid. Re-signing until the encodings actually differ makes the
    assertion deterministic instead of failing on ~1 run in 15.
    """
    priv, raw32 = keypair
    key_id = p1.key_id_for(raw32)
    prefix = p1.DOMAIN_PREFIXES["gate2_authority_policy/v1"]

    for nonce in range(64):
        env = _envelope(key_id)
        env["_flake_nonce"] = nonce
        signed = p1.sign_envelope(env, prefix, priv)
        standard = signed["integrity"]["signature_base64"]
        sig_raw = base64.b64decode(standard, validate=True)
        urlsafe = base64.urlsafe_b64encode(sig_raw).decode("ascii")
        if urlsafe != standard:
            break
    else:  # pragma: no cover - probability below 2**-250
        pytest.fail("could not produce a signature whose base64url encoding differs")

    tampered = copy.deepcopy(signed)
    tampered["integrity"]["signature_base64"] = urlsafe
    with pytest.raises(ValueError):
        p1.verify_envelope(tampered, prefix, raw32)


@pytest.mark.parametrize("bad_char", ["-", "_"])
def test_strict_base64_decode_names_base64url_alphabet(bad_char: str) -> None:
    """base64url input is refused with a diagnostic naming the alphabet.

    `base64.b64decode(validate=True)` already refuses '-'/'_' on its own, so the
    explicit guard in `_strict_base64_decode` is not what makes this input unsafe
    to accept; it is what makes the refusal legible ("base64url characters ...")
    instead of the opaque stdlib "Only base64 data is allowed". Asserting on the
    message is therefore the only claim this test can honestly make -- a test that
    merely asserted `raises(ValueError)` would pass with the guard deleted.
    """
    value = "A" * 42 + bad_char + "A" * 43 + "=="
    with pytest.raises(ValueError, match="base64url"):
        p1._strict_base64_decode(value)


def test_verify_unpadded_signature_rejected(keypair: tuple[Path, bytes]) -> None:
    priv, raw32 = keypair
    key_id = p1.key_id_for(raw32)
    env = _envelope(key_id)
    prefix = p1.DOMAIN_PREFIXES["gate2_authority_policy/v1"]
    signed = p1.sign_envelope(env, prefix, priv)
    tampered = copy.deepcopy(signed)
    tampered["integrity"]["signature_base64"] = signed["integrity"]["signature_base64"].rstrip("=")
    with pytest.raises(ValueError):
        p1.verify_envelope(tampered, prefix, raw32)


def test_verify_wrong_key_id_rejected(keypair: tuple[Path, bytes]) -> None:
    priv, raw32 = keypair
    key_id = p1.key_id_for(raw32)
    env = _envelope(key_id)
    prefix = p1.DOMAIN_PREFIXES["gate2_authority_policy/v1"]
    signed = p1.sign_envelope(env, prefix, priv)
    tampered = copy.deepcopy(signed)
    tampered["integrity"]["key_id"] = "key:ed25519:" + "0" * 64
    with pytest.raises(ValueError):
        p1.verify_envelope(tampered, prefix, raw32)


def test_verify_wrong_signature_length_rejected(keypair: tuple[Path, bytes]) -> None:
    priv, raw32 = keypair
    key_id = p1.key_id_for(raw32)
    env = _envelope(key_id)
    prefix = p1.DOMAIN_PREFIXES["gate2_authority_policy/v1"]
    signed = p1.sign_envelope(env, prefix, priv)
    tampered = copy.deepcopy(signed)
    short_sig = b"\x00" * 63  # properly padded standard base64, wrong decoded length
    tampered["integrity"]["signature_base64"] = base64.b64encode(short_sig).decode("ascii")
    with pytest.raises(ValueError):
        p1.verify_envelope(tampered, prefix, raw32)


def test_verify_wrong_public_key_rejected(keypair: tuple[Path, bytes], tmp_path: Path) -> None:
    priv, raw32 = keypair
    other_priv = tmp_path / "other.pem"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(other_priv)],
        check=True,
        capture_output=True,
    )
    other_raw32 = p1.raw_public_key_from_pem(other_priv)
    key_id = p1.key_id_for(raw32)
    env = _envelope(key_id)
    prefix = p1.DOMAIN_PREFIXES["gate2_authority_policy/v1"]
    signed = p1.sign_envelope(env, prefix, priv)
    with pytest.raises(ValueError):
        p1.verify_envelope(signed, prefix, other_raw32)
