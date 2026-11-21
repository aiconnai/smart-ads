"""Offline deterministic OCI composite image layout and safe multi-layer tar extractor."""
from __future__ import annotations

from collections import deque
from collections.abc import Mapping, Sequence
import copy
from dataclasses import dataclass
import gzip
import hashlib
import io
import os
from pathlib import Path
import re
import shutil
import tarfile
from typing import Any, Final
import zlib

from tools.governance import gov1_7a_runner, gov1_wheel
from tools.governance.gov1_oci_seccomp_bpf import compile_seccomp_profile_to_bpf
from tools.governance.jcs import canonicalize, loads_strict
from tools.governance.locator import digest, exact_fields, json_digest, source_path

PINNED_BASE_OCI_IMAGE_REF: Final[str] = "docker.io/library/python:3.12-slim-bookworm"
PINNED_BASE_OCI_MANIFEST_DIGEST: Final[str] = "sha256:0f086103b026048cc50cb5da25ec435c023c5241a83fc44daea593377abc61c4"
PINNED_BASE_OCI_CONFIG_DIGEST: Final[str] = "sha256:313cf8f190a1abab00472c1f0c950c10486c22114bcd8aef2a8198fb587a6d18"
PINNED_BASE_OCI_LAYER_DIGESTS: Final[tuple[str, ...]] = (
    "sha256:dd051e1b8c92ff101fa3071ab97ea4924885942f15644e01c3dc095764e863e3",
    "sha256:a47be7bff94f52aefb243d8b245b01c74976150bb88de60875c5eb7ac964f91e",
    "sha256:8691b22c22a3e005c632ab6bc07b085b98dae9cc02d1d84de175849f997439c7",
    "sha256:88d15687540999237909e04714b1393c610db9dc2e13d82acd6356fa9bf8f092",
)
PINNED_BASE_OCI_DIFF_IDS: Final[tuple[str, ...]] = (
    "sha256:1d7b9dd8778ebc4d9bf2f64436dd358640718cb349f5640b33bebaea4ffd62c2",
    "sha256:a3cfe73133965fb536427fde3fe66b2949ea6178f568733760bf45f5c8b5c405",
    "sha256:5e63f01f0cee6291b52c44ffeee48c9eb7b94cdb19478259bcfce37db9eb680e",
    "sha256:311a92d269bd002ca4ff3d801c6320df734027d3b425ff1ec860368f12b07a26",
)
_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"\Asha256:([0-9a-f]{64})\Z")
_INDEX_MEDIA_TYPES: Final[frozenset[str]] = frozenset({"application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json"})
_PYVENV_CFG_BYTES: Final[bytes] = b"home = /usr/local/bin\ninclude-system-site-packages = false\nversion = 3.12\nexecutable = /usr/local/bin/python3.12\n"
_DEFAULT_BOOTSTRAP_BYTES: Final[bytes] = b"#!/usr/bin/env python3\n"
_MAX_SYMLINK_HOPS: Final[int] = 16


@dataclass(frozen=True, slots=True)
class CompositeOciBundleSpec:
    layout_dir: Path
    oci_image_digest: str
    runner_binary_digest: str
    seccomp_profile_digest: str
    python_elf_sha256: str
    runner_script_sha256: str


def _sha256_hex(value: object, label: str) -> str:
    if type(value) is not str or (m := _SHA256_RE.fullmatch(value)) is None:
        raise ValueError(f"{label}: invalid sha256 digest {value!r}")
    return m.group(1)


def _read_regular_file(path: Path, label: str) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label}: expected non-symlink regular file at {path}")
    return path.read_bytes()


def _read_verified_blob(blobs_dir: Path, expected_digest: str, label: str, expected_size: object = None) -> bytes:
    raw = _read_regular_file(blobs_dir / _sha256_hex(expected_digest, label), label)
    if digest(raw) != expected_digest:
        raise ValueError(f"{label}: SHA-256 mismatch for blob {expected_digest}")
    if expected_size is not None and (type(expected_size) is not int or len(raw) != expected_size):
        raise ValueError(f"{label}: blob size mismatch for {expected_digest}")
    return raw


def _verify_layer_blob_and_diff_id(blobs_dir: Path, layer_desc: Mapping[str, Any], exp_digest: str, exp_diff_id: str) -> Path:
    blob_path = blobs_dir / _sha256_hex(exp_digest, "layer.digest")
    _sha256_hex(exp_diff_id, "layer.diff_id")
    if blob_path.is_symlink() or not blob_path.is_file():
        raise ValueError(f"layer blob missing or symlink: {blob_path}")
    comp_hasher, diff_hasher, total_size = hashlib.sha256(), hashlib.sha256(), 0
    with blob_path.open("rb") as raw_fh:
        while chunk := raw_fh.read(1048576):
            comp_hasher.update(chunk)
            total_size += len(chunk)
    if f"sha256:{comp_hasher.hexdigest()}" != exp_digest:
        raise ValueError(f"layer compressed SHA-256 mismatch for {exp_digest}")
    if "size" in layer_desc and (type(layer_desc["size"]) is not int or layer_desc["size"] != total_size):
        raise ValueError(f"layer size mismatch for {exp_digest}")
    try:
        with gzip.open(blob_path, "rb") as gz_fh:
            while chunk := gz_fh.read(1048576):
                diff_hasher.update(chunk)
    except (OSError, EOFError, zlib.error, tarfile.TarError) as exc:
        raise ValueError(f"layer gzip stream invalid for {exp_digest}: {exc}") from exc
    if f"sha256:{diff_hasher.hexdigest()}" != exp_diff_id:
        raise ValueError(f"layer diff_id SHA-256 mismatch for {exp_digest}")
    return blob_path


def _find_manifest_descriptor(blobs_dir: Path, index_obj: Any, expected_manifest_digest: str) -> dict[str, Any]:
    if not isinstance(index_obj, dict) or type(index_obj.get("manifests")) is not list:
        raise ValueError("index.json: expected JSON object with 'manifests' list")
    for entry in index_obj["manifests"]:
        if not isinstance(entry, dict):
            raise ValueError("index.json: manifest descriptor must be JSON object")
        if entry.get("digest") == expected_manifest_digest:
            return entry
    for entry in index_obj["manifests"]:
        if entry.get("mediaType") in _INDEX_MEDIA_TYPES and type(entry.get("digest")) is str:
            nested_raw = _read_verified_blob(blobs_dir, entry["digest"], "nested_index", entry.get("size"))
            nested_obj = loads_strict(nested_raw.decode("utf-8"))
            if isinstance(nested_obj, dict) and type(nested_obj.get("manifests")) is list:
                for sub in nested_obj["manifests"]:
                    if isinstance(sub, dict) and sub.get("digest") == expected_manifest_digest:
                        return sub
    raise ValueError(f"index.json: manifest digest {expected_manifest_digest!r} not found")


def _check_oci_layout_header_and_manifest(layout_dir: Path, expected_manifest_digest: str) -> tuple[Path, dict[str, Any], dict[str, Any]]:
    if layout_dir.is_symlink() or not layout_dir.is_dir():
        raise ValueError(f"oci_layout_dir: expected non-symlink directory at {layout_dir}")
    blobs_root, blobs_dir = layout_dir / "blobs", layout_dir / "blobs" / "sha256"
    if blobs_root.is_symlink() or blobs_dir.is_symlink() or not blobs_dir.is_dir():
        raise ValueError("oci_layout_dir: expected non-symlink blobs/sha256 directory")
    layout_obj = loads_strict(_read_regular_file(layout_dir / "oci-layout", "oci-layout").decode("utf-8"))
    exact_fields(layout_obj, {"imageLayoutVersion"}, "oci-layout")
    if layout_obj["imageLayoutVersion"] != "1.0.0":
        raise ValueError("oci-layout: expected imageLayoutVersion == '1.0.0'")
    index_obj = loads_strict(_read_regular_file(layout_dir / "index.json", "index.json").decode("utf-8"))
    man_desc = _find_manifest_descriptor(blobs_dir, index_obj, expected_manifest_digest)
    manifest = loads_strict(_read_verified_blob(blobs_dir, expected_manifest_digest, "manifest", man_desc.get("size")).decode("utf-8"))
    if not isinstance(manifest, dict) or not isinstance(manifest.get("config"), dict) or type(manifest.get("layers")) is not list:
        raise ValueError("manifest: invalid OCI image manifest structure")
    cfg_raw = _read_verified_blob(blobs_dir, str(manifest["config"].get("digest", "")), "config", manifest["config"].get("size"))
    config = loads_strict(cfg_raw.decode("utf-8"))
    if not isinstance(config, dict) or config.get("architecture") != "amd64" or config.get("os") != "linux":
        raise ValueError("config: expected linux/amd64 OCI image config")
    if not isinstance(config.get("rootfs"), dict) or config["rootfs"].get("type") != "layers" or type(config["rootfs"].get("diff_ids")) is not list:
        raise ValueError("config.rootfs: invalid layers structure")
    return blobs_dir, manifest, config


def verify_pinned_base_oci_layout(
    base_oci_dir: Path,
    *,
    expected_manifest_digest: str = PINNED_BASE_OCI_MANIFEST_DIGEST,
    expected_config_digest: str = PINNED_BASE_OCI_CONFIG_DIGEST,
    expected_layer_digests: tuple[str, ...] = PINNED_BASE_OCI_LAYER_DIGESTS,
    expected_diff_ids: tuple[str, ...] = PINNED_BASE_OCI_DIFF_IDS,
) -> dict[str, Any]:
    """Verify an offline OCI Image Layout against pinned manifest, config, layer, and diff_id digests."""
    if type(expected_layer_digests) is not tuple or type(expected_diff_ids) is not tuple or not expected_layer_digests or len(expected_layer_digests) != len(expected_diff_ids):
        raise ValueError("expected_layer_digests and expected_diff_ids: expected equal non-empty tuples")
    base_dir = Path(base_oci_dir)
    blobs_dir, manifest, config = _check_oci_layout_header_and_manifest(base_dir, expected_manifest_digest)
    if manifest["config"].get("digest") != expected_config_digest or config["rootfs"]["diff_ids"] != list(expected_diff_ids):
        raise ValueError("manifest.config.digest or config.rootfs.diff_ids mismatch")
    if [item.get("digest") if isinstance(item, dict) else None for item in manifest["layers"]] != list(expected_layer_digests):
        raise ValueError("manifest.layers digest sequence mismatch")
    layer_paths = [_verify_layer_blob_and_diff_id(blobs_dir, d, el, ed) for d, el, ed in zip(manifest["layers"], expected_layer_digests, expected_diff_ids, strict=True)]
    return {"base_oci_dir": base_dir, "manifest_digest": expected_manifest_digest, "config_digest": expected_config_digest, "layer_digests": list(expected_layer_digests), "diff_ids": list(expected_diff_ids), "layer_paths": layer_paths, "manifest": manifest, "config": config}


def _split_tar_member_parts(raw_name: str, *, strip_prefix: str | None = None) -> tuple[str, ...] | None:
    if "\x00" in raw_name or raw_name.startswith("/"):
        raise ValueError(f"tar member invalid or absolute path: {raw_name!r}")
    norm = raw_name[2:] if raw_name.startswith("./") else ("" if raw_name == "." else raw_name)
    stack: list[str] = []
    for seg in norm.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if not stack:
                raise ValueError(f"tar member escapes dest_root via '..': {raw_name!r}")
            stack.pop()
        else:
            stack.append(seg)
    if strip_prefix is not None:
        if not stack or stack[0] != strip_prefix:
            raise ValueError(f"tar member {raw_name!r} outside required prefix {strip_prefix!r}")
        stack = stack[1:]
    return tuple(stack) if stack else None


def _secure_resolve_parent(dest_root: Path, parent_parts: Sequence[str], dir_modes: dict[Path, int]) -> tuple[Path, list[str]]:
    resolved: list[str] = []
    pending: deque[str] = deque(parent_parts)
    hops = 0
    while pending:
        seg = pending.popleft()
        if seg in ("", "."):
            continue
        if seg == "..":
            if not resolved:
                raise ValueError("tar path traversal escapes dest_root")
            resolved.pop()
            continue
        cand = dest_root.joinpath(*resolved, seg)
        if cand.is_symlink():
            hops += 1
            if hops > _MAX_SYMLINK_HOPS:
                raise ValueError("tar intermediate symlink hop limit exceeded")
            target = os.readlink(cand)
            if "\x00" in target:
                raise ValueError("NUL byte in intermediate symlink target")
            if target.startswith("/"):
                resolved.clear()
            for t_seg in reversed(target.split("/")):
                if t_seg not in ("", "."):
                    pending.appendleft(t_seg)
        elif cand.exists():
            if not cand.is_dir():
                raise ValueError(f"tar non-directory parent component inside dest_root: {cand}")
            resolved.append(seg)
        else:
            cand.mkdir(mode=0o755, exist_ok=True)
            dir_modes.setdefault(cand, 0o555)
            resolved.append(seg)
    return dest_root.joinpath(*resolved), resolved


def _validate_symlink_target_confined(parent_resolved: Sequence[str], linkname: str) -> list[str]:
    if not linkname or "\x00" in linkname:
        raise ValueError("tar symlink linkname empty or contains NUL")
    sim = [] if linkname.startswith("/") else list(parent_resolved)
    for seg in linkname.split("/"):
        if seg == "..":
            if not sim:
                raise ValueError(f"tar symlink target escapes dest_root: {linkname!r}")
            sim.pop()
        elif seg not in ("", "."):
            sim.append(seg)
    return sim


def _remove_existing_entry(target: Path, dir_modes: dict[Path, int]) -> None:
    if target.is_symlink() or target.is_file():
        target.unlink()
    elif target.exists() and target.is_dir():
        cleanup_runc_bundle_trees(target)
        for k in [p for p in dir_modes if p == target or p.is_relative_to(target)]:
            dir_modes.pop(k, None)


def _apply_whiteout(parent_dir: Path, leaf: str, dir_modes: dict[Path, int]) -> bool:
    if leaf == ".wh..wh..opq":
        for child in list(parent_dir.iterdir()):
            _remove_existing_entry(child, dir_modes)
        return True
    if leaf.startswith(".wh."):
        victim_name = leaf[4:]
        if not victim_name or victim_name in (".", "..") or victim_name.startswith(".wh."):
            raise ValueError(f"invalid OCI whiteout marker: {leaf!r}")
        _remove_existing_entry(parent_dir / victim_name, dir_modes)
        return True
    return False


def _extract_tar_member(tf: tarfile.TarFile, member: tarfile.TarInfo, dest_root: Path, dir_modes: dict[Path, int], *, strip_prefix: str | None) -> None:
    if member.type in (tarfile.XHDTYPE, tarfile.XGLTYPE):
        return
    if member.type not in (tarfile.DIRTYPE, tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.SYMTYPE, tarfile.LNKTYPE):
        raise ValueError(f"tar unsupported or forbidden special node {member.name!r} (type={member.type!r})")
    if "\x00" in member.linkname:
        raise ValueError("tar linkname contains NUL")
    parts = _split_tar_member_parts(member.name, strip_prefix=strip_prefix)
    if parts is None:
        if member.isdir():
            dir_modes[dest_root] = ((member.mode & 0o0777) & ~0o0222) | 0o0500
        return
    parent_dir, parent_resolved = _secure_resolve_parent(dest_root, parts[:-1], dir_modes)
    if _apply_whiteout(parent_dir, parts[-1], dir_modes):
        return
    target = parent_dir / parts[-1]
    if member.isdir():
        if target.is_symlink() or (target.exists() and not target.is_dir()):
            _remove_existing_entry(target, dir_modes)
        target.mkdir(mode=0o755, exist_ok=True)
        dir_modes[target] = ((member.mode & 0o0777) & ~0o0222) | 0o0500
    elif member.issym():
        _validate_symlink_target_confined(parent_resolved, member.linkname)
        _remove_existing_entry(target, dir_modes)
        os.symlink(member.linkname, target)
    elif member.islnk():
        link_parts = _split_tar_member_parts(member.linkname, strip_prefix=strip_prefix)
        if not link_parts:
            raise ValueError(f"tar hardlink invalid target: {member.linkname!r}")
        l_parent, _ = _secure_resolve_parent(dest_root, link_parts[:-1], dir_modes)
        l_src = l_parent / link_parts[-1]
        if l_src.is_symlink() or not l_src.is_file() or not l_src.resolve().is_relative_to(dest_root.resolve()):
            raise ValueError(f"tar hardlink target invalid or escapes dest_root: {member.linkname!r}")
        _remove_existing_entry(target, dir_modes)
        os.link(l_src, target)
    else:
        _remove_existing_entry(target, dir_modes)
        src_fh = tf.extractfile(member)
        target.write_bytes(b"" if src_fh is None else src_fh.read())
        os.chmod(target, ((member.mode & 0o0777) & ~0o0222) | 0o0400)


def _extract_gzip_tar_layers(layer_paths: Sequence[Path], dest_root: Path, *, strip_prefix: str | None = None) -> dict[Path, int]:
    dest_root.mkdir(parents=True, mode=0o755, exist_ok=True)
    dir_modes: dict[Path, int] = {dest_root: 0o555}
    for layer_path in layer_paths:
        try:
            with gzip.open(layer_path, "rb") as gz_fh, tarfile.open(fileobj=gz_fh, mode="r|*") as tf:
                for member in tf:
                    _extract_tar_member(tf, member, dest_root, dir_modes, strip_prefix=strip_prefix)
        except (OSError, EOFError, zlib.error, tarfile.TarError) as exc:
            raise ValueError(f"layer tar/gzip stream invalid for {layer_path}: {exc}") from exc
    return dir_modes


def _finalize_dir_modes(dest_root: Path, dir_modes: Mapping[Path, int], *, root_mode: int = 0o555) -> None:
    all_dirs: list[Path] = []
    for curr_root, dirnames, _ in os.walk(dest_root, topdown=True, followlinks=False):
        c_path = Path(curr_root)
        if not c_path.is_symlink():
            all_dirs.append(c_path)
        dirnames[:] = [d for d in dirnames if not (c_path / d).is_symlink()]
    for d_path in sorted(all_dirs, key=lambda p: len(p.parts), reverse=True):
        os.chmod(d_path, root_mode if d_path == dest_root else dir_modes.get(d_path, 0o555))


def _build_deterministic_tar_gz_layer(entries: Mapping[str, tuple[str, int, bytes | str]]) -> dict[str, Any]:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tf:
        for path in sorted(entries.keys(), key=lambda s: s.encode("utf-8")):
            kind, mode, payload = entries[path]
            ti = tarfile.TarInfo(name=path)
            ti.mtime, ti.uid, ti.gid, ti.uname, ti.gname, ti.pax_headers, ti.mode = 0, 0, 0, "", "", {}, mode
            if kind == "dir":
                ti.type = tarfile.DIRTYPE
                tf.addfile(ti)
            elif kind == "sym":
                ti.type, ti.linkname = tarfile.SYMTYPE, str(payload)
                tf.addfile(ti)
            else:
                raw = payload if isinstance(payload, bytes) else payload.encode("utf-8")
                ti.type, ti.size = tarfile.REGTYPE, len(raw)
                tf.addfile(ti, io.BytesIO(raw))
    tar_bytes = buf.getvalue()
    gz_bytes = gzip.compress(tar_bytes, compresslevel=9, mtime=0)
    blob_digest = digest(gz_bytes)
    return {"gz_bytes": gz_bytes, "blob_digest": blob_digest, "diff_id": digest(tar_bytes), "descriptor": {"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": blob_digest, "size": len(gz_bytes)}}


def _build_7a_overlay_layers(
    *, wheel_bytes: bytes, corpus_bytes: bytes, replay_context_obj: Mapping[str, Any],
    resolved_d26_blobs: Mapping[str, bytes], seccomp_bpf_bytes: bytes,
    runner_py_bytes: bytes, venv_probe_bootstrap_bytes: bytes,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    shim_entries: dict[str, tuple[str, int, bytes | str]] = {d: ("dir", 0o555, b"") for d in ("app", "dev", "fixtures", "home", "proc", "run", "sys", "tmp", "usr", "usr/bin", "var", "var/run")}
    shim_entries["var/.wh.run"] = ("reg", 0o444, b"")
    shim_entries["usr/bin/python3"] = ("sym", 0o777, "/usr/local/bin/python3.12")
    wheel_members = gov1_wheel._read_and_validate_wheel_archive(wheel_bytes)[0]
    verified_d26 = gov1_7a_runner._verify_d26_blob_map(resolved_d26_blobs)
    app_entries: dict[str, tuple[str, int, bytes | str]] = {d: ("dir", 0o555, b"") for d in ("app", "app/d26", "app/venv", "app/venv/bin", "app/venv/lib", "app/venv/lib/python3.12", "app/venv/lib/python3.12/site-packages", "app/wheel")}
    app_entries.update({"app/runner.py": ("reg", 0o555, runner_py_bytes), "app/venv_probe_bootstrap.py": ("reg", 0o555, venv_probe_bootstrap_bytes), "app/seccomp_filter.bpf": ("reg", 0o444, seccomp_bpf_bytes), "app/wheel/smart_ads-0.1.0-py3-none-any.whl": ("reg", 0o444, wheel_bytes), "app/venv/pyvenv.cfg": ("reg", 0o444, _PYVENV_CFG_BYTES), "app/venv/bin/python": ("sym", 0o777, "/usr/local/bin/python3.12"), "app/venv/bin/python3": ("sym", 0o777, "/usr/local/bin/python3.12")})
    for rel_path, raw_bytes in wheel_members.items():
        full_rel = f"app/venv/lib/python3.12/site-packages/{rel_path}"
        parts = full_rel.split("/")
        for idx in range(1, len(parts)):
            app_entries.setdefault("/".join(parts[:idx]), ("dir", 0o555, b""))
        app_entries[full_rel] = ("reg", 0o444, raw_bytes)
    for role, rel_path, _, _ in gov1_7a_runner.PINNED_PIPEBOARD_D26_SPECS:
        app_entries[f"app/d26/{role}__{Path(rel_path).name}"] = ("reg", 0o444, verified_d26[rel_path])
    fixtures_entries: dict[str, tuple[str, int, bytes | str]] = {"fixtures": ("dir", 0o555, b""), "fixtures/pipeboard_7a_corpus_v1.json": ("reg", 0o444, corpus_bytes), "fixtures/replay_context_v1.json": ("reg", 0o444, canonicalize(dict(replay_context_obj)))}
    return _build_deterministic_tar_gz_layer(shim_entries), _build_deterministic_tar_gz_layer(app_entries), _build_deterministic_tar_gz_layer(fixtures_entries)


def _scan_single_layer_for_target(layer_path: Path, wanted: str) -> tuple[str, bytes | str | None]:
    w_parts = tuple(wanted.split("/"))
    state: tuple[str, bytes | str | None] = ("absent", None)
    try:
        with gzip.open(layer_path, "rb") as gz_fh, tarfile.open(fileobj=gz_fh, mode="r|*") as tf:
            for member in tf:
                if member.type in (tarfile.XHDTYPE, tarfile.XGLTYPE):
                    continue
                parts = _split_tar_member_parts(member.name)
                if not parts:
                    continue
                p_dirs, leaf = parts[:-1], parts[-1]
                if (leaf == ".wh..wh..opq" and w_parts[: len(p_dirs)] == p_dirs and len(w_parts) > len(p_dirs)) or (leaf.startswith(".wh.") and len(p_dirs) < len(w_parts) and (*p_dirs, leaf[4:]) == w_parts[: len(p_dirs) + 1]):
                    state = ("whited_out", None)
                elif parts == w_parts:
                    if member.issym() or member.islnk():
                        state = ("sym" if member.issym() else "lnk", member.linkname)
                    elif member.isfile():
                        fh = tf.extractfile(member)
                        state = ("reg", b"" if fh is None else fh.read())
                    else:
                        state = ("other", None)
    except (OSError, EOFError, zlib.error, tarfile.TarError) as exc:
        raise ValueError(f"layer tar/gzip stream invalid for {layer_path}: {exc}") from exc
    return state


def _extract_python_elf_from_base_layers(base_layer_paths: Sequence[Path]) -> bytes:
    wanted = "usr/local/bin/python3.12"
    for _ in range(_MAX_SYMLINK_HOPS + 1):
        next_target: str | None = None
        for layer_path in reversed(base_layer_paths):
            kind, payload = _scan_single_layer_for_target(layer_path, wanted)
            if kind == "reg" and isinstance(payload, bytes) and len(payload) > 0:
                return payload
            if kind in ("whited_out", "other"):
                raise ValueError("base_oci_dir: /usr/local/bin/python3.12 missing or non-regular")
            if kind in ("sym", "lnk") and isinstance(payload, str):
                if kind == "sym":
                    next_target = "/".join(_validate_symlink_target_confined(wanted.split("/")[:-1], payload))
                else:
                    lp = _split_tar_member_parts(payload)
                    if not lp:
                        raise ValueError("invalid hardlink for python3.12")
                    next_target = "/".join(lp)
                break
        if next_target is None:
            raise ValueError("base_oci_dir: missing /usr/local/bin/python3.12 in base layers")
        wanted = next_target
    raise ValueError("base_oci_dir: symlink hop limit exceeded resolving /usr/local/bin/python3.12")


def _write_composite_oci_files(out_dir: Path, verified_base: Mapping[str, Any], overlays: tuple[dict[str, Any], dict[str, Any], dict[str, Any]]) -> str:
    blobs_out = out_dir / "blobs" / "sha256"
    blobs_out.mkdir(parents=True, exist_ok=True)
    for src_blob in verified_base["layer_paths"]:
        shutil.copyfile(src_blob, blobs_out / src_blob.name)
    for overlay in overlays:
        (blobs_out / overlay["blob_digest"].split(":")[1]).write_bytes(overlay["gz_bytes"])
    comp_cfg = copy.deepcopy(verified_base["config"])
    comp_cfg["rootfs"] = {"type": "layers", "diff_ids": [*verified_base["diff_ids"], *(o["diff_id"] for o in overlays)]}
    if isinstance(comp_cfg.get("history"), list):
        comp_cfg["history"].extend({"created": "1970-01-01T00:00:00Z", "created_by": tag} for tag in ("smart_ads:rootfs_shim", "smart_ads:app", "smart_ads:fixtures"))
    cfg_bytes = canonicalize(comp_cfg)
    cfg_digest = digest(cfg_bytes)
    (blobs_out / cfg_digest.split(":")[1]).write_bytes(cfg_bytes)
    comp_man = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": cfg_digest, "size": len(cfg_bytes)}, "layers": [*copy.deepcopy(verified_base["manifest"]["layers"]), *(o["descriptor"] for o in overlays)]}
    man_bytes = canonicalize(comp_man)
    oci_image_digest = digest(man_bytes)
    (blobs_out / oci_image_digest.split(":")[1]).write_bytes(man_bytes)
    (out_dir / "oci-layout").write_bytes(canonicalize({"imageLayoutVersion": "1.0.0"}))
    (out_dir / "index.json").write_bytes(canonicalize({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": [{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": oci_image_digest, "size": len(man_bytes), "platform": {"architecture": "amd64", "os": "linux"}}]}))
    return oci_image_digest


def build_composite_7a_oci_layout(
    *, base_oci_dir: Path, output_layout_dir: Path, wheel_bytes: bytes, corpus_bytes: bytes,
    replay_context_obj: Mapping[str, Any], resolved_d26_blobs: Mapping[str, bytes],
    seccomp_profile: dict[str, Any], runner_py_bytes: bytes,
    venv_probe_bootstrap_bytes: bytes = _DEFAULT_BOOTSTRAP_BYTES,
    expected_manifest_digest: str = PINNED_BASE_OCI_MANIFEST_DIGEST,
    expected_config_digest: str = PINNED_BASE_OCI_CONFIG_DIGEST,
    expected_layer_digests: tuple[str, ...] = PINNED_BASE_OCI_LAYER_DIGESTS,
    expected_diff_ids: tuple[str, ...] = PINNED_BASE_OCI_DIFF_IDS,
) -> CompositeOciBundleSpec:
    """Build a deterministic composite 7A OCI Image Layout on top of a verified base layout."""
    for label, raw in (("wheel_bytes", wheel_bytes), ("corpus_bytes", corpus_bytes), ("runner_py_bytes", runner_py_bytes), ("venv_probe_bootstrap_bytes", venv_probe_bootstrap_bytes)):
        if type(raw) is not bytes or len(raw) == 0:
            raise ValueError(f"{label}: expected non-empty bytes")
    if not isinstance(replay_context_obj, Mapping):
        raise ValueError("replay_context_obj: expected Mapping")
    out_dir = Path(output_layout_dir)
    if out_dir.is_symlink() or (out_dir.exists() and any(out_dir.iterdir())):
        raise ValueError(f"output_layout_dir: expected non-symlink new or empty directory at {out_dir}")
    verified_base = verify_pinned_base_oci_layout(base_oci_dir, expected_manifest_digest=expected_manifest_digest, expected_config_digest=expected_config_digest, expected_layer_digests=expected_layer_digests, expected_diff_ids=expected_diff_ids)
    seccomp_digest, seccomp_bpf = compile_seccomp_profile_to_bpf(seccomp_profile)
    python_elf_sha256 = digest(_extract_python_elf_from_base_layers(verified_base["layer_paths"]))
    runner_script_sha256 = digest(runner_py_bytes)
    runner_binary_digest = json_digest({"kind": "smart_ads/7a_oci_runner_binary/v1", "python_elf_sha256": python_elf_sha256, "runner_script_sha256": runner_script_sha256})
    overlays = _build_7a_overlay_layers(wheel_bytes=wheel_bytes, corpus_bytes=corpus_bytes, replay_context_obj=replay_context_obj, resolved_d26_blobs=resolved_d26_blobs, seccomp_bpf_bytes=seccomp_bpf, runner_py_bytes=runner_py_bytes, venv_probe_bootstrap_bytes=venv_probe_bootstrap_bytes)
    oci_image_digest = _write_composite_oci_files(out_dir, verified_base, overlays)
    return CompositeOciBundleSpec(layout_dir=out_dir, oci_image_digest=oci_image_digest, runner_binary_digest=runner_binary_digest, seccomp_profile_digest=seccomp_digest, python_elf_sha256=python_elf_sha256, runner_script_sha256=runner_script_sha256)


def _verify_composite_layout_layers(spec: CompositeOciBundleSpec) -> list[Path]:
    blobs_dir, manifest, config = _check_oci_layout_header_and_manifest(spec.layout_dir, spec.oci_image_digest)
    diff_ids = config["rootfs"]["diff_ids"]
    if len(manifest["layers"]) < 4 or len(diff_ids) != len(manifest["layers"]):
        raise ValueError("composite_manifest: expected >= 4 layers matching diff_ids")
    return [_verify_layer_blob_and_diff_id(blobs_dir, ld, str(ld.get("digest", "")), str(di)) for ld, di in zip(manifest["layers"], diff_ids, strict=True)]


def _write_extra_app_files(
    app_dir: Path,
    extra_app_files: Mapping[str, bytes],
    dir_modes: dict[Path, int],
    extra_app_modes: Mapping[str, int] | None = None,
) -> None:
    if not isinstance(extra_app_files, Mapping):
        raise ValueError("extra_app_files: expected Mapping[str, bytes]")
    if extra_app_modes is not None:
        if not isinstance(extra_app_modes, Mapping) or not set(extra_app_modes.keys()).issubset(extra_app_files.keys()):
            raise ValueError("extra_app_modes: expected Mapping subset of extra_app_files")
        for m_rel, m_val in extra_app_modes.items():
            if type(m_val) is not int or m_val not in (0o444, 0o555):
                raise ValueError(f"extra_app_modes[{m_rel!r}]: expected 0o444 or 0o555, got {m_val!r}")
    for rel_path in sorted(extra_app_files.keys()):
        source_path(rel_path)
        raw = extra_app_files[rel_path]
        if type(raw) is not bytes:
            raise ValueError(f"extra_app_files[{rel_path!r}]: expected bytes")
        parts = rel_path.split("/")
        cur = app_dir
        for d_seg in parts[:-1]:
            cur = cur / d_seg
            if cur.is_symlink() or (cur.exists() and not cur.is_dir()):
                raise ValueError(f"extra_app_files[{rel_path!r}]: symlink or non-directory ancestor")
            cur.mkdir(mode=0o755, exist_ok=True)
            dir_modes.setdefault(cur, 0o555)
        leaf_path = cur / parts[-1]
        _remove_existing_entry(leaf_path, dir_modes)
        leaf_path.write_bytes(raw)
        os.chmod(leaf_path, 0o444 if extra_app_modes is None else extra_app_modes.get(rel_path, 0o444))


def materialize_runc_bundle_trees(
    *,
    composite_spec: CompositeOciBundleSpec,
    bundle_dir: Path,
    extra_app_files: Mapping[str, bytes] | None = None,
    extra_app_modes: Mapping[str, int] | None = None,
) -> dict[str, Path]:
    """Extract verified composite OCI layers into `bundle_dir/oci_extracted/{rootfs,app,fixtures}`."""
    if not isinstance(composite_spec, CompositeOciBundleSpec):
        raise ValueError("composite_spec: expected CompositeOciBundleSpec")
    b_root = Path(bundle_dir)
    if b_root.is_symlink() or (b_root.exists() and any(b_root.iterdir())):
        raise ValueError(f"bundle_dir: expected non-symlink new or empty directory at {b_root}")
    layer_paths = _verify_composite_layout_layers(composite_spec)
    b_root.mkdir(parents=True, mode=0o755, exist_ok=True)
    os.chmod(b_root, 0o755)
    oci_extracted = b_root / "oci_extracted"
    oci_extracted.mkdir(mode=0o755, exist_ok=True)
    os.chmod(oci_extracted, 0o755)
    rootfs_dir, app_dir, fixtures_dir = oci_extracted / "rootfs", oci_extracted / "app", oci_extracted / "fixtures"
    _finalize_dir_modes(rootfs_dir, _extract_gzip_tar_layers(layer_paths[:-2], rootfs_dir))
    app_modes = _extract_gzip_tar_layers([layer_paths[-2]], app_dir, strip_prefix="app")
    if extra_app_files is not None or extra_app_modes is not None:
        _write_extra_app_files(app_dir, {} if extra_app_files is None else extra_app_files, app_modes, extra_app_modes)
    _finalize_dir_modes(app_dir, app_modes)
    _finalize_dir_modes(fixtures_dir, _extract_gzip_tar_layers([layer_paths[-1]], fixtures_dir, strip_prefix="fixtures"))
    return {"bundle_dir": b_root, "oci_extracted": oci_extracted, "rootfs": rootfs_dir, "app": app_dir, "fixtures": fixtures_dir}


def cleanup_runc_bundle_trees(target_dir: Path) -> None:
    """Restore owner rw/rwx modes (`followlinks=False`, never chmodding symlinks) and remove `target_dir`."""
    root = Path(target_dir)
    if root.is_symlink():
        raise ValueError(f"target_dir: refusing to remove symlink {root}")
    if not root.exists():
        return
    os.chmod(root, 0o700)
    for curr_root, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        c_path = Path(curr_root)
        if not c_path.is_symlink():
            os.chmod(c_path, 0o700)
        for dname in dirnames:
            d_path = c_path / dname
            if not d_path.is_symlink():
                os.chmod(d_path, 0o700)
        for fname in filenames:
            f_path = c_path / fname
            if not f_path.is_symlink() and f_path.is_file():
                os.chmod(f_path, 0o600)
    shutil.rmtree(root)
