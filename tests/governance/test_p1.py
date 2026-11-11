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


def _registry_entry(
    raw32: bytes,
    *,
    role: str = "gate2_policy_issuer",
    action: str = "gate2_authority_policy_issue",
    schema: str = "smart_ads/gate2_authority_policy/v1",
) -> dict:
    import hashlib

    return {
        "key_id": p1.key_id_for(raw32),
        "role": role,
        "lifecycle_state": "active",
        "public_key_base64": base64.b64encode(raw32).decode("ascii"),
        "public_key_sha256": "sha256:" + hashlib.sha256(raw32).hexdigest(),
        "allowed_actions": [{"schema": schema, "action": action}],
        "validity": {
            "from": "2026-09-01T00:00:00Z",
            "until": "2026-10-01T00:00:00Z",
        },
    }


def test_decode_public_key_entry_happy_path_and_rejections(keypair: tuple[Path, bytes]) -> None:
    _, raw32 = keypair
    valid = _registry_entry(raw32)
    assert p1.decode_public_key_entry(valid) == raw32

    for non_dict in (None, [], "not-a-dict", 123):
        with pytest.raises(ValueError, match="JSON object"):
            p1.decode_public_key_entry(non_dict)  # type: ignore[arg-type]

    for bad_pub in (None, 123, ["abc"]):
        with pytest.raises(ValueError, match="invalid public key encoding"):
            p1.decode_public_key_entry(dict(valid, public_key_base64=bad_pub))

    unpadded = valid["public_key_base64"].rstrip("=")
    with pytest.raises(ValueError, match="invalid base64"):
        p1.decode_public_key_entry(dict(valid, public_key_base64=unpadded))

    urlsafe = "A" * 42 + "-_"
    with pytest.raises(ValueError, match="base64url"):
        p1.decode_public_key_entry(dict(valid, public_key_base64=urlsafe))

    for bad_len in (b"\x00" * 31, b"\x00" * 33):
        b64 = base64.b64encode(bad_len).decode("ascii")
        with pytest.raises(ValueError, match="canonical 32-byte Ed25519"):
            p1.decode_public_key_entry(dict(valid, public_key_base64=b64))

    with pytest.raises(ValueError, match="public key hash mismatch"):
        p1.decode_public_key_entry(dict(valid, public_key_sha256="sha256:" + "0" * 64))


def test_verify_historical_signer_happy_path_and_inclusive_lower_bound(
    keypair: tuple[Path, bytes],
) -> None:
    priv, raw32 = keypair
    entry = _registry_entry(raw32)
    prefix = p1.DOMAIN_PREFIXES["gate2_authority_policy/v1"]
    signed = p1.sign_envelope(_envelope(entry["key_id"]), prefix, priv)
    registry = {"issued_at_utc": "2026-09-01T00:00:00Z", "entries": [entry]}

    matched = p1.verify_historical_signer(
        signed,
        registry,
        prefix,
        "gate2_authority_policy_issue",
        "2026-09-01T00:00:00Z",
        required_role="gate2_policy_issuer",
    )
    assert matched == entry

    # required_role=None accepts any role as long as action, lifecycle, validity, and sig match.
    matched_no_role = p1.verify_historical_signer(
        signed,
        registry,
        prefix,
        "gate2_authority_policy_issue",
        "2026-09-15T12:00:00Z",
        required_role=None,
    )
    assert matched_no_role == entry


def test_verify_historical_signer_rejects_every_invalid_state(
    keypair: tuple[Path, bytes], tmp_path: Path
) -> None:
    priv, raw32 = keypair
    entry = _registry_entry(raw32)
    prefix = p1.DOMAIN_PREFIXES["gate2_authority_policy/v1"]
    action = "gate2_authority_policy_issue"
    when = "2026-09-10T00:00:00Z"
    signed = p1.sign_envelope(_envelope(entry["key_id"]), prefix, priv)
    registry = {"issued_at_utc": "2026-09-01T00:00:00Z", "entries": [entry]}

    # Non-dict envelope / registry and malformed top-level fields fail closed with ValueError.
    with pytest.raises(ValueError, match="JSON objects"):
        p1.verify_historical_signer("bad", registry, prefix, action, when)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="JSON objects"):
        p1.verify_historical_signer(signed, None, prefix, action, when)  # type: ignore[arg-type]

    no_schema = copy.deepcopy(signed)
    del no_schema["$schema"]
    with pytest.raises(ValueError, match="\\$schema"):
        p1.verify_historical_signer(no_schema, registry, prefix, action, when)

    bad_integrity = dict(signed, integrity="not-a-dict")
    with pytest.raises(ValueError, match="integrity"):
        p1.verify_historical_signer(bad_integrity, registry, prefix, action, when)

    bad_kid = copy.deepcopy(signed)
    bad_kid["integrity"]["key_id"] = ""
    with pytest.raises(ValueError, match="signer key_id"):
        p1.verify_historical_signer(bad_kid, registry, prefix, action, when)

    with pytest.raises(ValueError, match="domain_prefix"):
        p1.verify_historical_signer(signed, registry, "", action, when)
    with pytest.raises(ValueError, match="action"):
        p1.verify_historical_signer(signed, registry, prefix, "", when)

    # Registry issued after artifact (or missing issued_at_utc).
    with pytest.raises(ValueError, match="registry issued after artifact"):
        p1.verify_historical_signer(
            signed, dict(registry, issued_at_utc="2026-09-11T00:00:00Z"), prefix, action, when
        )
    with pytest.raises(ValueError, match="timestamp"):
        p1.verify_historical_signer(signed, {"entries": [entry]}, prefix, action, when)

    # Non-list entries and malformed sibling entries must fail closed (correctness-003).
    with pytest.raises(ValueError, match="entries must be a list"):
        p1.verify_historical_signer(signed, dict(registry, entries=None), prefix, action, when)
    for bad_sibling in ("not-a-dict", {}, {"key_id": ""}, {"key_id": 123}):
        with pytest.raises(ValueError, match="missing key_id"):
            p1.verify_historical_signer(
                signed, dict(registry, entries=[entry, bad_sibling]), prefix, action, when
            )

    # 0 matches and >1 matches.
    with pytest.raises(ValueError, match="exactly one historical registry entry"):
        p1.verify_historical_signer(signed, dict(registry, entries=[]), prefix, action, when)
    with pytest.raises(ValueError, match="exactly one historical registry entry"):
        p1.verify_historical_signer(
            signed, dict(registry, entries=[entry, copy.deepcopy(entry)]), prefix, action, when
        )

    # Lifecycle state, role, and allowed_actions guards.
    with pytest.raises(ValueError, match="lifecycle mismatch"):
        p1.verify_historical_signer(
            signed,
            dict(registry, entries=[dict(entry, lifecycle_state="revoked")]),
            prefix,
            action,
            when,
        )
    with pytest.raises(ValueError, match="role mismatch"):
        p1.verify_historical_signer(
            signed, registry, prefix, action, when, required_role="different_role"
        )
    for bad_actions in (None, "all", [{"schema": signed["$schema"], "action": "other"}]):
        with pytest.raises(ValueError, match="lacks exact action"):
            p1.verify_historical_signer(
                signed,
                dict(registry, entries=[dict(entry, allowed_actions=bad_actions)]),
                prefix,
                action,
                when,
            )

    # Validity structure and [from, until) interval boundaries.
    for bad_validity in (
        None,
        {"from": "2026-09-01T00:00:00Z"},
        {"from": "2026-09-01T00:00:00Z", "until": "2026-10-01T00:00:00Z", "extra": 1},
    ):
        with pytest.raises(ValueError, match="validity"):
            p1.verify_historical_signer(
                signed,
                dict(registry, entries=[dict(entry, validity=bad_validity)]),
                prefix,
                action,
                when,
            )
    early_registry = dict(registry, issued_at_utc="2026-08-01T00:00:00Z")
    for out_of_range in ("2026-08-31T23:59:59Z", "2026-10-01T00:00:00Z"):
        with pytest.raises(ValueError, match="outside historical validity interval"):
            p1.verify_historical_signer(signed, early_registry, prefix, action, out_of_range)

    # Signature mismatch at final verify_envelope step.
    tampered = copy.deepcopy(signed)
    tampered["repository"] = "evil/repo"
    with pytest.raises(ValueError, match="content_digest mismatch"):
        p1.verify_historical_signer(tampered, registry, prefix, action, when)
