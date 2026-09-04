"""P1 preimage / digest / message + Ed25519 signing and verification via openssl.

Implements ADR-0001 section on the P1 signing profile: the preimage `P` is the
envelope `E` with exactly the two members at JSON pointers
`/integrity/content_digest` and `/integrity/signature_base64` deleted (not
blanked, siblings kept). `C = RFC8785(P)`, `D = SHA-256(C)` (raw 32 bytes),
`content_digest = "sha256:" + lowercase_hex(D)`, and the signed message is
`M = UTF8(domain_prefix) || 0x00 || D`. There is no `cryptography` dependency
available in this environment, so all Ed25519 operations shell out to the
`openssl` CLI (3.x) via `subprocess`.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from tools.governance.jcs import canonicalize

DOMAIN_PREFIXES: dict[str, str] = {
    "key_authorization_registry/v1": "SMART-ADS:KEY-REGISTRY:V1\n",
    "gate2_authority_policy/v1": "SMART-ADS:GATE2-AUTHORITY-POLICY:V1\n",
    "protected_merge_evidence/v1": "SMART-ADS:PROTECTED-MERGE:V1\n",
    "gate2_approval_receipt/v1": "SMART-ADS:GATE2-RECEIPT:V1\n",
    "migration_run_context/v1": "SMART-ADS:RUN-CONTEXT:V1\n",
    "delivery_mode_decision_receipt/v1": "SMART-ADS:DELIVERY-MODE:V1\n",
}

_DER_ED25519_SPKI_HEADER = bytes.fromhex("302a300506032b6570032100")


def preimage(envelope: dict[str, Any]) -> dict[str, Any]:
    """Return a new envelope with exactly the two P1 integrity members removed."""
    if "integrity" not in envelope or not isinstance(envelope["integrity"], dict):
        raise ValueError(
            "p1.preimage: envelope must contain an object member 'integrity'"
        )
    result = copy.deepcopy(envelope)
    integrity = result["integrity"]
    integrity.pop("content_digest", None)
    integrity.pop("signature_base64", None)
    return result


def _digest_bytes(envelope: dict[str, Any]) -> bytes:
    pre = preimage(envelope)
    canonical = canonicalize(pre)
    return hashlib.sha256(canonical).digest()


def content_digest(envelope: dict[str, Any]) -> str:
    """Return the P1 content digest string 'sha256:<hex>' for `envelope`."""
    return "sha256:" + _digest_bytes(envelope).hex()


def message(envelope: dict[str, Any], domain_prefix: str) -> bytes:
    """Return the P1 signed message M = UTF8(domain_prefix) || 0x00 || D."""
    return domain_prefix.encode("utf-8") + b"\x00" + _digest_bytes(envelope)


def key_id_for(raw32: bytes) -> str:
    if len(raw32) != 32:
        raise ValueError(f"p1.key_id_for: expected 32 raw public key bytes, got {len(raw32)}")
    return "key:ed25519:" + hashlib.sha256(raw32).hexdigest()


def raw_public_key_from_pem(path: Path) -> bytes:
    """Extract the raw 32-byte Ed25519 public key from a PEM private or public key."""
    proc = subprocess.run(
        ["openssl", "pkey", "-in", str(path), "-pubout", "-outform", "DER"],
        check=True,
        capture_output=True,
    )
    der = proc.stdout
    if len(der) != 44 or der[:12] != _DER_ED25519_SPKI_HEADER:
        raise ValueError(
            "p1.raw_public_key_from_pem: unexpected DER SubjectPublicKeyInfo "
            f"(len={len(der)}, header={der[:12].hex()}); expected a 44-byte "
            "Ed25519 SPKI structure"
        )
    return der[12:]


def _openssl_sign(private_key_pem_path: Path, msg: bytes) -> bytes:
    with tempfile.TemporaryDirectory() as tmpdir:
        msg_path = Path(tmpdir) / "message.bin"
        sig_path = Path(tmpdir) / "signature.bin"
        msg_path.write_bytes(msg)
        subprocess.run(
            [
                "openssl", "pkeyutl", "-sign",
                "-inkey", str(private_key_pem_path),
                "-rawin", "-in", str(msg_path),
                "-out", str(sig_path),
            ],
            check=True,
            capture_output=True,
        )
        sig = sig_path.read_bytes()
    if len(sig) != 64:
        raise ValueError(
            f"p1._openssl_sign: expected a 64-byte Ed25519 signature, got {len(sig)}"
        )
    return sig


def _openssl_verify(raw32: bytes, msg: bytes, sig: bytes) -> bool:
    with tempfile.TemporaryDirectory() as tmpdir:
        der_path = Path(tmpdir) / "pub.der"
        msg_path = Path(tmpdir) / "message.bin"
        sig_path = Path(tmpdir) / "signature.bin"
        der_path.write_bytes(_DER_ED25519_SPKI_HEADER + raw32)
        msg_path.write_bytes(msg)
        sig_path.write_bytes(sig)
        proc = subprocess.run(
            [
                "openssl", "pkeyutl", "-verify",
                "-pubin", "-inkey", str(der_path), "-keyform", "DER",
                "-rawin", "-in", str(msg_path),
                "-sigfile", str(sig_path),
            ],
            capture_output=True,
        )
    return proc.returncode == 0


def sign_envelope(
    envelope: dict[str, Any], domain_prefix: str, private_key_pem_path: Path
) -> dict[str, Any]:
    """Return a NEW envelope with integrity.content_digest/signature_base64 set."""
    digest = content_digest(envelope)
    msg = message(envelope, domain_prefix)
    sig = _openssl_sign(Path(private_key_pem_path), msg)
    encoded = base64.b64encode(sig).decode("ascii")
    result = copy.deepcopy(envelope)
    result["integrity"]["content_digest"] = digest
    result["integrity"]["signature_base64"] = encoded
    return result


def _strict_base64_decode(value: str) -> bytes:
    if "-" in value or "_" in value:
        raise ValueError(
            "p1._strict_base64_decode: base64url characters '-'/'_' are not allowed"
        )
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception as exc:  # binascii.Error etc.
        raise ValueError(f"p1._strict_base64_decode: invalid base64: {exc}") from exc
    # Reject unpadded / non-canonical encodings by round-tripping.
    if base64.b64encode(raw).decode("ascii") != value:
        raise ValueError(
            "p1._strict_base64_decode: value is not RFC 4648 standard, padded base64"
        )
    return raw


def verify_envelope(
    envelope: dict[str, Any], domain_prefix: str, public_key_raw32: bytes
) -> None:
    """Verify `envelope` against `domain_prefix` and `public_key_raw32`.

    Raises ValueError on any failure: digest mismatch, malformed/base64url/
    unpadded signature, wrong length, signature verification failure, or
    key_id mismatch.
    """
    if "integrity" not in envelope or not isinstance(envelope["integrity"], dict):
        raise ValueError("p1.verify_envelope: envelope missing object member 'integrity'")
    integrity = envelope["integrity"]

    expected_digest = content_digest(envelope)
    actual_digest = integrity.get("content_digest")
    if actual_digest != expected_digest:
        raise ValueError(
            f"p1.verify_envelope: content_digest mismatch (expected {expected_digest!r}, "
            f"got {actual_digest!r})"
        )

    sig_b64 = integrity.get("signature_base64")
    if not isinstance(sig_b64, str):
        raise ValueError("p1.verify_envelope: signature_base64 missing or not a string")
    sig = _strict_base64_decode(sig_b64)
    if len(sig) != 64:
        raise ValueError(
            f"p1.verify_envelope: signature must decode to 64 bytes, got {len(sig)}"
        )

    expected_key_id = key_id_for(public_key_raw32)
    actual_key_id = integrity.get("key_id")
    if actual_key_id != expected_key_id:
        raise ValueError(
            f"p1.verify_envelope: key_id mismatch (expected {expected_key_id!r}, "
            f"got {actual_key_id!r})"
        )

    msg = message(envelope, domain_prefix)
    if not _openssl_verify(public_key_raw32, msg, sig):
        raise ValueError("p1.verify_envelope: Ed25519 signature verification failed")
