"""Immutable content-addressed in-memory and non-symlink filesystem object stores (ADR-0001 §§6.3, 12.4)."""
from __future__ import annotations

from collections.abc import Mapping
import hashlib
import os
from pathlib import Path
import stat
import tempfile
from typing import Any, Final

from smart_ads.contracts.effects import _typed_locator, validate_cell_object_ref
from smart_ads.contracts.jcs import (
    MAX_JCS_SAFE_INT,
    ArtifactLocator,
    canonicalize_jcs,
    loads_strict_json,
)
from smart_ads.contracts.scalars import (
    ClosedValidationError,
    require_mapping,
    validate_non_empty_str,
)
from smart_ads.ports.storage import CellObjectStorePort

_MAX_OBJECT_BYTES: Final[int] = 268_435_456  # 256 MiB safety ceiling


def _sha256_hex(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _require_raw_bytes(raw: object) -> bytes:
    if type(raw) is not bytes:
        raise ClosedValidationError(
            f"object_store.put_bytes: expected bytes, got {type(raw).__name__}"
        )
    if len(raw) > _MAX_OBJECT_BYTES:
        raise ClosedValidationError(
            f"object_store.put_bytes: payload size {len(raw)} exceeds ceiling"
        )
    return raw


def _parse_object_ref(
    object_ref: object, *, expected_size_bytes: object = None
) -> tuple[str, str, int | None]:
    checked_ref = validate_cell_object_ref(object_ref, field_name="object_ref")
    digest_hex = checked_ref.rsplit(":", 1)[1]
    if expected_size_bytes is None:
        return checked_ref, digest_hex, None
    if type(expected_size_bytes) is not int or not (
        0 <= expected_size_bytes <= MAX_JCS_SAFE_INT
    ):
        raise ClosedValidationError(
            f"expected_size_bytes: expected non-negative int, got {expected_size_bytes!r}"
        )
    return checked_ref, digest_hex, expected_size_bytes


def _verify_object_bytes(
    raw: bytes,
    *,
    object_ref: str,
    expected_hex: str,
    expected_size_bytes: int | None,
) -> bytes:
    actual_hex = _sha256_hex(raw)
    if actual_hex != expected_hex:
        raise ClosedValidationError(
            f"object_store: SHA-256 mismatch on {object_ref!r} "
            f"(expected {expected_hex}, got {actual_hex})"
        )
    if expected_size_bytes is not None and len(raw) != expected_size_bytes:
        raise ClosedValidationError(
            f"object_store: size mismatch on {object_ref!r} "
            f"(expected {expected_size_bytes}, got {len(raw)})"
        )
    return raw


def _prepare_json_artifact_bytes(
    schema_id: object, payload: object
) -> tuple[ArtifactLocator, bytes]:
    checked_schema = validate_non_empty_str(schema_id, field_name="schema_id")
    mapping = require_mapping(payload, label="payload")
    if mapping.get("$schema") != checked_schema:
        raise ClosedValidationError(
            f"object_store.put_json_artifact: payload['$schema'] must equal "
            f"{checked_schema!r}, got {mapping.get('$schema')!r}"
        )
    canonical = canonicalize_jcs(mapping)
    loads_strict_json(canonical)
    locator = ArtifactLocator.for_canonical_bytes(checked_schema, canonical)
    return locator, canonical


def _parse_verified_json_artifact(
    raw: bytes, *, locator: ArtifactLocator
) -> dict[str, Any]:
    parsed = loads_strict_json(raw)
    if type(parsed) is not dict:
        raise ClosedValidationError(
            f"object_store.get_json_artifact: expected JSON object for {locator.object_ref!r}"
        )
    if canonicalize_jcs(parsed) != raw:
        raise ClosedValidationError(
            f"object_store.get_json_artifact: stored bytes at {locator.object_ref!r} "
            "are not canonical RFC 8785 JSON"
        )
    if parsed.get("$schema") != locator.artifact_type:
        raise ClosedValidationError(
            f"object_store.get_json_artifact: '$schema' {parsed.get('$schema')!r} "
            f"!= locator.artifact_type {locator.artifact_type!r}"
        )
    return parsed


class InMemoryCellObjectStore(CellObjectStorePort):
    """Immutable content-addressed in-memory cell object store (zero delete/overwrite)."""

    def __init__(self) -> None:
        self._blobs: dict[str, bytes] = {}

    def put_bytes(self, raw: bytes) -> str:
        checked = _require_raw_bytes(raw)
        digest_hex = _sha256_hex(checked)
        object_ref = f"cell-object:sha256:{digest_hex}"
        if object_ref in self._blobs:
            existing = self.get_bytes(object_ref, expected_size_bytes=len(checked))
            if existing != checked:
                raise ClosedValidationError(
                    f"object_store: content collision on {object_ref!r}"
                )
            return object_ref
        self._blobs[object_ref] = checked
        return object_ref

    def get_bytes(
        self, object_ref: str, *, expected_size_bytes: int | None = None
    ) -> bytes:
        checked_ref, digest_hex, exp_size = _parse_object_ref(
            object_ref, expected_size_bytes=expected_size_bytes
        )
        raw = self._blobs.get(checked_ref)
        if raw is None:
            raise ClosedValidationError(
                f"object_store: missing object {checked_ref!r}"
            )
        return _verify_object_bytes(
            raw,
            object_ref=checked_ref,
            expected_hex=digest_hex,
            expected_size_bytes=exp_size,
        )

    def has_object(self, object_ref: str) -> bool:
        checked_ref, _, _ = _parse_object_ref(object_ref)
        return checked_ref in self._blobs

    def put_json_artifact(
        self, schema_id: str, payload: Mapping[str, Any]
    ) -> ArtifactLocator:
        locator, canonical = _prepare_json_artifact_bytes(schema_id, payload)
        stored_ref = self.put_bytes(canonical)
        if stored_ref != locator.object_ref:
            raise ClosedValidationError("object_store: locator ref mismatch on put")
        return locator

    def get_json_artifact(self, locator: ArtifactLocator) -> dict[str, Any]:
        checked_loc = _typed_locator(locator, field_name="locator")
        raw = self.get_bytes(checked_loc.object_ref)
        return _parse_verified_json_artifact(raw, locator=checked_loc)


def _lstat_or_none(path: Path) -> os.stat_result | None:
    try:
        return os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ClosedValidationError(
            f"filesystem_object_store: stat error on {path}: {exc}"
        ) from exc


def _stat_regular_or_none(path: Path) -> os.stat_result | None:
    st = _lstat_or_none(path)
    if st is None:
        return None
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise ClosedValidationError(f"filesystem_object_store: symlink or non-regular file at {path}")
    return st


def _validate_non_symlink_dir(path: Path, *, create: bool, parents: bool) -> None:
    st = _lstat_or_none(path)
    if st is None:
        if not create:
            raise ClosedValidationError(
                f"filesystem_object_store: missing directory {path}"
            )
        try:
            path.mkdir(parents=parents, exist_ok=True)
        except OSError as exc:
            raise ClosedValidationError(
                f"filesystem_object_store: failed to create directory {path}: {exc}"
            ) from exc
        st = _lstat_or_none(path)
    if st is None or stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise ClosedValidationError(
            f"filesystem_object_store: path must be a non-symlink directory: {path}"
        )


def _read_regular_nofollow(path: Path) -> bytes:
    st = _stat_regular_or_none(path)
    if st is None:
        raise ClosedValidationError(f"filesystem_object_store: object missing at {path}")
    if st.st_size > _MAX_OBJECT_BYTES:
        raise ClosedValidationError(f"filesystem_object_store: file size {st.st_size} exceeds ceiling")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ClosedValidationError(f"filesystem_object_store: failed to open {path}: {exc}") from exc
    try:
        fst = os.fstat(fd)
        if not stat.S_ISREG(fst.st_mode) or fst.st_ino != st.st_ino or fst.st_dev != st.st_dev:
            raise ClosedValidationError(f"filesystem_object_store: inode changed during open on {path}")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, 65_536)
            if not chunk:
                break
            total += len(chunk)
            if total > _MAX_OBJECT_BYTES:
                raise ClosedValidationError("filesystem_object_store: oversized read")
            chunks.append(chunk)
        return b"".join(chunks)
    except OSError as exc:
        raise ClosedValidationError(f"filesystem_object_store: read error on {path}: {exc}") from exc
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def _atomic_write_readonly_blob(sha_dir: Path, target: Path, raw: bytes) -> bool:
    try:
        fd, tmp_name = tempfile.mkstemp(prefix=".tmp-cas-", dir=str(sha_dir))
    except OSError as exc:
        raise ClosedValidationError(f"filesystem_object_store: mkstemp failed in {sha_dir}: {exc}") from exc
    tmp_path = Path(tmp_name)
    closed = False
    try:
        view = memoryview(raw)
        written = 0
        while written < len(raw):
            written += os.write(fd, view[written:])
        os.fsync(fd)
        os.fchmod(fd, 0o444)
        os.close(fd)
        closed = True
        try:
            os.link(tmp_path, target)
            return True
        except FileExistsError:
            return False
    except OSError as exc:
        raise ClosedValidationError(f"filesystem_object_store: write/link error on {target}: {exc}") from exc
    finally:
        if not closed:
            try:
                os.close(fd)
            except OSError:
                pass
        if _lstat_or_none(tmp_path) is not None:
            try:
                os.unlink(tmp_path)
            except FileNotFoundError:
                pass
            except OSError as exc:
                raise ClosedValidationError(f"filesystem_object_store: unlink failed on {tmp_path}: {exc}") from exc


class FilesystemCellObjectStore(CellObjectStorePort):
    """Non-symlink `<root>/sha256/<64_hex>` immutable content-addressed object store."""

    def __init__(self, root: Path | str) -> None:
        if isinstance(root, Path):
            raw_str = str(root)
        elif type(root) is str:
            raw_str = root
        else:
            raise ClosedValidationError(
                f"filesystem_object_store: expected Path or str, got {type(root).__name__}"
            )
        validate_non_empty_str(raw_str, field_name="root")
        self._root = Path(raw_str)
        self._sha_dir = self._root / "sha256"
        _validate_non_symlink_dir(self._root, create=True, parents=True)
        _validate_non_symlink_dir(self._sha_dir, create=True, parents=False)

    def _object_paths(self, digest_hex: str) -> tuple[Path, Path]:
        _validate_non_symlink_dir(self._root, create=False, parents=False)
        _validate_non_symlink_dir(self._sha_dir, create=False, parents=False)
        return self._sha_dir / digest_hex, self._sha_dir / f"{digest_hex}.json"

    def put_bytes(self, raw: bytes) -> str:
        checked = _require_raw_bytes(raw)
        digest_hex = _sha256_hex(checked)
        object_ref = f"cell-object:sha256:{digest_hex}"
        target, json_target = self._object_paths(digest_hex)
        st_c, st_j = _stat_regular_or_none(target), _stat_regular_or_none(json_target)
        if st_c is not None or st_j is not None:
            existing = self.get_bytes(object_ref, expected_size_bytes=len(checked))
            if existing != checked:
                raise ClosedValidationError(f"filesystem_object_store: byte mismatch at {target}")
            return object_ref
        newly_linked = _atomic_write_readonly_blob(self._sha_dir, target, checked)
        if newly_linked:
            final_st = _stat_regular_or_none(target)
            if final_st is None or stat.S_IMODE(final_st.st_mode) != 0o444:
                raise ClosedValidationError(f"filesystem_object_store: failed to enforce 0o444 mode on {target}")
        verified = self.get_bytes(object_ref, expected_size_bytes=len(checked))
        if verified != checked:
            raise ClosedValidationError(f"filesystem_object_store: post-write readback mismatch on {target}")
        return object_ref

    def get_bytes(
        self, object_ref: str, *, expected_size_bytes: int | None = None
    ) -> bytes:
        checked_ref, digest_hex, exp_size = _parse_object_ref(
            object_ref, expected_size_bytes=expected_size_bytes
        )
        target, json_target = self._object_paths(digest_hex)
        st_c, st_j = _stat_regular_or_none(target), _stat_regular_or_none(json_target)
        if st_c is None and st_j is None:
            raise ClosedValidationError(f"filesystem_object_store: object missing at {target}")
        if st_c is not None and st_j is not None:
            raw_c = _verify_object_bytes(_read_regular_nofollow(target), object_ref=checked_ref, expected_hex=digest_hex, expected_size_bytes=exp_size)
            raw_j = _verify_object_bytes(_read_regular_nofollow(json_target), object_ref=checked_ref, expected_hex=digest_hex, expected_size_bytes=exp_size)
            if raw_c != raw_j:
                raise ClosedValidationError(f"filesystem_object_store: dual-path divergence on {checked_ref!r}")
            return raw_c
        chosen = target if st_c is not None else json_target
        return _verify_object_bytes(
            _read_regular_nofollow(chosen),
            object_ref=checked_ref,
            expected_hex=digest_hex,
            expected_size_bytes=exp_size,
        )

    def has_object(self, object_ref: str) -> bool:
        checked_ref, digest_hex, _ = _parse_object_ref(object_ref)
        target, json_target = self._object_paths(digest_hex)
        st_c, st_j = _stat_regular_or_none(target), _stat_regular_or_none(json_target)
        if st_c is None and st_j is None:
            return False
        if st_c is not None and st_j is not None:
            self.get_bytes(checked_ref)
        return True

    def put_json_artifact(
        self, schema_id: str, payload: Mapping[str, Any]
    ) -> ArtifactLocator:
        locator, canonical = _prepare_json_artifact_bytes(schema_id, payload)
        stored_ref = self.put_bytes(canonical)
        if stored_ref != locator.object_ref:
            raise ClosedValidationError(
                "filesystem_object_store: locator ref mismatch on put"
            )
        return locator

    def get_json_artifact(self, locator: ArtifactLocator) -> dict[str, Any]:
        checked_loc = _typed_locator(locator, field_name="locator")
        raw = self.get_bytes(checked_loc.object_ref)
        return _parse_verified_json_artifact(raw, locator=checked_loc)


__all__ = [
    "FilesystemCellObjectStore",
    "InMemoryCellObjectStore",
]
