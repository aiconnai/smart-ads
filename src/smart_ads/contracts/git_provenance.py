"""Closed P1 `smart_ads/git_artifact_provenance/v1` and pure Git blob helpers (ADR-0001)."""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
import hashlib
from typing import Any, ClassVar, Final
import unicodedata

from smart_ads.contracts.jcs import (
    ADR_P1_DOMAIN_PREFIXES,
    ArtifactLocator,
    P1Integrity,
    canonicalize_jcs,
    p1_content_digest,
)
from smart_ads.contracts.scalars import (
    ClosedValidationError,
    require_exact_keys,
    require_mapping,
    validate_hex40,
    validate_non_empty_str,
    validate_sha256_prefixed,
    validate_timestamp_utc_seconds,
)

_GIT_ARTIFACT_PROVENANCE_SCHEMA: Final[str] = "smart_ads/git_artifact_provenance/v1"


def _has_control_char(value: str) -> bool:
    return any(
        unicodedata.category(ch) == "Cc" or ord(ch) <= 0x1F or 0x7F <= ord(ch) <= 0x9F
        for ch in value
    )


def _validate_repository_slug(value: object, *, field_name: str) -> str:
    if type(value) is not str:
        raise ClosedValidationError(
            f"{field_name}: expected str, got {type(value).__name__}"
        )
    checked = validate_non_empty_str(value, field_name=field_name)
    if _has_control_char(checked) or any(ch.isspace() or ch == "\\" for ch in checked):
        raise ClosedValidationError(
            f"{field_name}: whitespace, backslashes, and control chars are forbidden"
        )
    parts = checked.split("/")
    if (
        len(parts) != 2
        or not parts[0]
        or not parts[1]
        or parts[0] in {".", ".."}
        or parts[1] in {".", ".."}
    ):
        raise ClosedValidationError(
            f"{field_name}: expected normalized '<owner>/<repo>' slug, got {checked!r}"
        )
    return checked


def _validate_relative_posix_path(value: object, *, field_name: str) -> str:
    if type(value) is not str:
        raise ClosedValidationError(
            f"{field_name}: expected str, got {type(value).__name__}"
        )
    checked = validate_non_empty_str(value, field_name=field_name)
    if "\\" in checked or _has_control_char(checked):
        raise ClosedValidationError(
            f"{field_name}: backslashes and control characters are forbidden"
        )
    segments = checked.split("/")
    if any(seg in {"", ".", ".."} for seg in segments):
        raise ClosedValidationError(
            f"{field_name}: expected normalized relative POSIX path, got {checked!r}"
        )
    return checked


def _require_strict_str_input(value: object, *, field_name: str) -> str:
    if type(value) is not str:
        raise ClosedValidationError(
            f"{field_name}: expected str, got {type(value).__name__}"
        )
    return value


@dataclass(frozen=True, slots=True)
class GitArtifactProvenance:
    """Closed P1 `smart_ads/git_artifact_provenance/v1` envelope."""

    SCHEMA: ClassVar[str] = _GIT_ARTIFACT_PROVENANCE_SCHEMA
    P1_DOMAIN_PREFIX: ClassVar[str] = ADR_P1_DOMAIN_PREFIXES[
        _GIT_ARTIFACT_PROVENANCE_SCHEMA
    ]
    CORE_KEYS: ClassVar[frozenset[str]] = frozenset(
        {
            "$schema",
            "repository",
            "commit_sha",
            "path",
            "git_blob_oid",
            "file_content_sha256",
            "resolved_at_utc",
        }
    )
    KEYS: ClassVar[frozenset[str]] = CORE_KEYS | {"integrity"}

    repository: str
    commit_sha: str
    path: str
    git_blob_oid: str
    file_content_sha256: str
    resolved_at_utc: str
    integrity: P1Integrity | None = None

    def __post_init__(self) -> None:
        _validate_repository_slug(
            self.repository, field_name="git_artifact_provenance.repository"
        )
        validate_hex40(
            _require_strict_str_input(
                self.commit_sha, field_name="git_artifact_provenance.commit_sha"
            ),
            field_name="git_artifact_provenance.commit_sha",
        )
        _validate_relative_posix_path(
            self.path, field_name="git_artifact_provenance.path"
        )
        validate_hex40(
            _require_strict_str_input(
                self.git_blob_oid, field_name="git_artifact_provenance.git_blob_oid"
            ),
            field_name="git_artifact_provenance.git_blob_oid",
        )
        validate_sha256_prefixed(
            _require_strict_str_input(
                self.file_content_sha256,
                field_name="git_artifact_provenance.file_content_sha256",
            ),
            field_name="git_artifact_provenance.file_content_sha256",
        )
        validate_timestamp_utc_seconds(
            _require_strict_str_input(
                self.resolved_at_utc,
                field_name="git_artifact_provenance.resolved_at_utc",
            ),
            field_name="git_artifact_provenance.resolved_at_utc",
        )
        if self.integrity is not None and not isinstance(self.integrity, P1Integrity):
            raise ClosedValidationError(
                "git_artifact_provenance.integrity: expected P1Integrity or None"
            )
        if self.integrity is not None and self.integrity.is_signed:
            expected_p1 = p1_content_digest(self.to_dict())
            if self.integrity.content_digest != expected_p1:
                raise ClosedValidationError(
                    "git_artifact_provenance.integrity.content_digest: recomputed "
                    f"{expected_p1!r} != asserted {self.integrity.content_digest!r}"
                )

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "$schema": self.SCHEMA,
            "repository": self.repository,
            "commit_sha": self.commit_sha,
            "path": self.path,
            "git_blob_oid": self.git_blob_oid,
            "file_content_sha256": self.file_content_sha256,
            "resolved_at_utc": self.resolved_at_utc,
        }
        if self.integrity is not None:
            out["integrity"] = self.integrity.to_dict()
        return out

    @classmethod
    def from_dict(
        cls,
        data: object,
        *,
        require_signed: bool = False,
    ) -> GitArtifactProvenance:
        if type(require_signed) is not bool:
            raise ClosedValidationError("require_signed: expected bool")
        mapping = require_mapping(data, label="git_artifact_provenance")
        if require_signed or "integrity" in mapping:
            require_exact_keys(mapping, cls.KEYS, label="git_artifact_provenance")
            integrity: P1Integrity | None = P1Integrity.from_dict(
                mapping["integrity"], require_signed=require_signed
            )
        else:
            require_exact_keys(mapping, cls.CORE_KEYS, label="git_artifact_provenance")
            integrity = None
        if type(mapping["$schema"]) is not str or mapping["$schema"] != cls.SCHEMA:
            raise ClosedValidationError(
                f"git_artifact_provenance.$schema: expected {cls.SCHEMA!r}, "
                f"got {mapping['$schema']!r}"
            )
        return cls(
            repository=mapping["repository"],
            commit_sha=mapping["commit_sha"],
            path=mapping["path"],
            git_blob_oid=mapping["git_blob_oid"],
            file_content_sha256=mapping["file_content_sha256"],
            resolved_at_utc=mapping["resolved_at_utc"],
            integrity=integrity,
        )


def compute_git_blob_oid(raw_bytes: bytes) -> str:
    """Compute lowercase 40-hex Git blob SHA-1 OID for `raw_bytes`."""
    if type(raw_bytes) is not bytes:
        raise ClosedValidationError(
            f"raw_bytes: expected bytes, got {type(raw_bytes).__name__}"
        )
    header = b"blob " + str(len(raw_bytes)).encode("ascii") + b"\x00"
    return hashlib.sha1(header + raw_bytes).hexdigest()


def _reparse_locator(loc: object, *, label: str) -> ArtifactLocator:
    if type(loc) is not ArtifactLocator:
        raise ClosedValidationError(
            f"{label}: expected ArtifactLocator, got {type(loc).__name__}"
        )
    try:
        raw = loc.to_dict()
    except Exception as exc:
        raise ClosedValidationError(f"{label}: corrupted ArtifactLocator: {exc}") from None
    return ArtifactLocator.from_dict(raw, expected_type=GitArtifactProvenance.SCHEMA)


def _reparse_provenance(prov: object, *, label: str) -> GitArtifactProvenance:
    if type(prov) is not GitArtifactProvenance:
        raise ClosedValidationError(
            f"{label}: expected GitArtifactProvenance, got {type(prov).__name__}"
        )
    try:
        raw = prov.to_dict()
    except Exception as exc:
        raise ClosedValidationError(
            f"{label}: corrupted GitArtifactProvenance: {exc}"
        ) from None
    return GitArtifactProvenance.from_dict(raw)


def sort_git_provenance_locators(
    locators: Sequence[ArtifactLocator],
) -> tuple[ArtifactLocator, ...]:
    """Validate unique `git_artifact_provenance/v1` locators sorted by ascending JCS bytes."""
    if isinstance(locators, (str, bytes, bytearray, memoryview)) or not isinstance(
        locators, Sequence
    ):
        raise ClosedValidationError(
            "locators: expected non-str/bytes Sequence of ArtifactLocator, "
            f"got {type(locators).__name__}"
        )
    keyed: list[tuple[bytes, ArtifactLocator]] = []
    seen_keys: set[bytes] = set()
    for idx, loc in enumerate(locators):
        revalidated = _reparse_locator(loc, label=f"locators[{idx}]")
        raw_jcs = canonicalize_jcs(revalidated.to_dict())
        if raw_jcs in seen_keys:
            raise ClosedValidationError(
                f"locators[{idx}]: duplicate git_artifact_provenance/v1 locator"
            )
        seen_keys.add(raw_jcs)
        keyed.append((raw_jcs, revalidated))
    keyed.sort(key=lambda pair: pair[0])
    return tuple(loc for _, loc in keyed)


def verify_git_provenance_against_bytes(
    prov: GitArtifactProvenance,
    raw_bytes: bytes,
) -> None:
    """Verify that `prov` revalidates and matches `raw_bytes` blob OID and SHA-256."""
    checked_prov = _reparse_provenance(prov, label="prov")
    expected_blob = compute_git_blob_oid(raw_bytes)
    if expected_blob != checked_prov.git_blob_oid:
        raise ClosedValidationError(
            "git_artifact_provenance.git_blob_oid: recomputed "
            f"{expected_blob!r} != declared {checked_prov.git_blob_oid!r}"
        )
    expected_sha256 = "sha256:" + hashlib.sha256(raw_bytes).hexdigest()
    if expected_sha256 != checked_prov.file_content_sha256:
        raise ClosedValidationError(
            "git_artifact_provenance.file_content_sha256: recomputed "
            f"{expected_sha256!r} != declared {checked_prov.file_content_sha256!r}"
        )


__all__ = [
    "GitArtifactProvenance",
    "compute_git_blob_oid",
    "sort_git_provenance_locators",
    "verify_git_provenance_against_bytes",
]
