"""artifact_locator/v1 builders/validators and a content-addressed Store.

A locator has exactly six members (ADR-0001 section 12.2) and resolves an
artifact stored as RFC 8785 canonical JSON, addressed by the SHA-256 of its
canonical bytes.

IMPORTANT distinction: `Store.put` computes the locator's `content_digest`
over the FULL canonicalized envelope bytes (including any `integrity.
content_digest` / `integrity.signature_base64` members). This is a different
digest from the P1 `integrity.content_digest` in `tools.governance.p1`, which
is computed over the *preimage* (the envelope with those two integrity
members removed). The two digests coincide only for an envelope that has no
`integrity` object at all (e.g. `cell_trust_anchor_config/v1`, which is not
P1-signed). For any P1-signed artifact they differ by construction — do not
conflate "the locator resolves" with "the P1 signature verifies"; both checks
are required and independent.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from tools.governance.jcs import canonicalize, loads_strict

_LOCATOR_MEMBERS = {
    "$schema",
    "artifact_type",
    "content_digest",
    "serialization",
    "store_kind",
    "object_ref",
}
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def make_locator(artifact_type: str, canonical_bytes: bytes) -> dict[str, Any]:
    """Build an artifact_locator/v1 for `canonical_bytes` addressed content."""
    digest_hex = hashlib.sha256(canonical_bytes).hexdigest()
    return {
        "$schema": "smart_ads/artifact_locator/v1",
        "artifact_type": artifact_type,
        "content_digest": f"sha256:{digest_hex}",
        "serialization": "rfc8785-json",
        "store_kind": "cell_immutable_object",
        "object_ref": f"cell-object:sha256:{digest_hex}",
    }


def _digest_hex_from_prefixed(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        raise ValueError(f"locator.validate_locator: {field} must be 'sha256:<hex>'")
    hex_part = value[len("sha256:"):]
    if not _HEX64.match(hex_part):
        raise ValueError(
            f"locator.validate_locator: {field} hex must be 64 lowercase hex chars"
        )
    return hex_part


def validate_locator(loc: dict[str, Any]) -> None:
    """Raise ValueError unless `loc` has exactly the six required members with
    consistent, well-formed values."""
    actual_members = set(loc.keys())
    if actual_members != _LOCATOR_MEMBERS:
        missing = _LOCATOR_MEMBERS - actual_members
        extra = actual_members - _LOCATOR_MEMBERS
        raise ValueError(
            f"locator.validate_locator: locator must have exactly {sorted(_LOCATOR_MEMBERS)} "
            f"members (missing={sorted(missing)}, extra={sorted(extra)})"
        )
    if loc["$schema"] != "smart_ads/artifact_locator/v1":
        raise ValueError("locator.validate_locator: $schema must be smart_ads/artifact_locator/v1")
    if not isinstance(loc["artifact_type"], str) or not loc["artifact_type"]:
        raise ValueError("locator.validate_locator: artifact_type must be a non-empty string")
    if loc["serialization"] != "rfc8785-json":
        raise ValueError("locator.validate_locator: serialization must be rfc8785-json")
    if loc["store_kind"] != "cell_immutable_object":
        raise ValueError("locator.validate_locator: store_kind must be cell_immutable_object")

    digest_hex = _digest_hex_from_prefixed(loc["content_digest"], "content_digest")
    expected_object_ref = f"cell-object:sha256:{digest_hex}"
    if loc["object_ref"] != expected_object_ref:
        raise ValueError(
            "locator.validate_locator: object_ref does not agree with content_digest "
            f"(expected {expected_object_ref!r}, got {loc['object_ref']!r})"
        )


class Store:
    """Content-addressed object store rooted at `root/sha256/<hex>.json`."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)

    def _path_for(self, digest_hex: str) -> Path:
        return self.root / "sha256" / f"{digest_hex}.json"

    def put(self, envelope: dict[str, Any]) -> dict[str, Any]:
        """Canonicalize and persist the FULL `envelope`, returning its locator."""
        if "$schema" not in envelope or not isinstance(envelope["$schema"], str):
            raise ValueError("locator.Store.put: envelope must have a string '$schema' member")
        canonical = canonicalize(envelope)
        digest_hex = hashlib.sha256(canonical).hexdigest()
        path = self._path_for(digest_hex)
        if path.exists():
            existing = path.read_bytes()
            if existing != canonical:
                raise ValueError(
                    f"locator.Store.put: refusing to overwrite {path} with different bytes "
                    "for the same content-addressed digest"
                )
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(canonical)
        written = path.read_bytes()
        if len(written) == 0 or written != canonical:
            raise ValueError(f"locator.Store.put: write verification failed for {path}")
        return make_locator(envelope["$schema"], canonical)

    def get(self, locator: dict[str, Any]) -> dict[str, Any]:
        """Resolve `locator` and return the parsed envelope.

        Per ADR-0001 (locator validity, around L2833-2834), a locator is
        valid only if the object (1) resolves, (2) parses as `artifact_type`
        (its `$schema` member equals `locator["artifact_type"]`), and (3)
        recomputes to `content_digest`. All three checks are conjunctive and
        enforced here.
        """
        validate_locator(locator)
        digest_hex = locator["content_digest"][len("sha256:"):]
        path = self._path_for(digest_hex)
        if not path.exists():
            raise ValueError(f"locator.Store.get: no object at {path} for locator {locator!r}")
        raw = path.read_bytes()
        actual_hex = hashlib.sha256(raw).hexdigest()
        if actual_hex != digest_hex:
            raise ValueError(
                f"locator.Store.get: stored object at {path} does not match its "
                f"content-addressed digest (expected {digest_hex}, got {actual_hex})"
            )
        text = raw.decode("utf-8")
        value = loads_strict(text)
        if not isinstance(value, dict):
            raise ValueError(f"locator.Store.get: object at {path} is not a JSON object")
        actual_type = value.get("$schema")
        if actual_type != locator["artifact_type"]:
            raise ValueError(
                f"locator.Store.get: artifact_type_mismatch: object at {path} has "
                f"'$schema' {actual_type!r}, locator declares artifact_type "
                f"{locator['artifact_type']!r}"
            )
        return value
