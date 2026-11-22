"""Deterministic gap-free stdlib Apache Parquet v1 (`PAR1`) codec for `analytics_landing_row/v1` (ADR-0001 §§6.1, 6.3)."""
from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
import struct
from typing import Any, Final, Literal, NamedTuple
import zlib

from smart_ads.contracts.jcs import canonicalize_jcs
from smart_ads.contracts.scalars import ClosedValidationError
from smart_ads.contracts.schemas import AnalyticsLandingRow
from smart_ads.domain.curation import partition_key_for_metric_date, validate_partition_key
from smart_ads.ports.storage import ParquetCompression, ParquetLandingCodecPort

# Exact 24 flattened columns in deterministic schema order: (column_name, is_optional)
PARQUET_LANDING_COLUMNS: Final[tuple[tuple[str, bool], ...]] = (
    ("$schema", False), ("binding_ref", False), ("account_ref", False),
    ("resource_ref", False), ("resource_level", False), ("metric_date", False),
    ("metric_semantic_ref", False), ("source_metric_ref", False),
    ("attribution_ref", False), ("breakdown_signature", False),
    ("value_type", True), ("raw_numeric_value", True), ("unit", True),
    ("currency", True), ("metric_origin", False), ("presence_status", False),
    ("unknown_reason", True), ("calculation_status", False),
    ("collected_at_utc", False), ("source_observation_ref", False),
    ("adapter_version", False), ("semantic_version", False),
    ("semantic_observation_digest", False), ("row_digest", False),
)
_FACT_KEY_COL_NAMES: Final[tuple[str, ...]] = tuple(n for n, _ in PARQUET_LANDING_COLUMNS[1:10])
_ROW_TAIL_COL_NAMES: Final[tuple[str, ...]] = tuple(n for n, _ in PARQUET_LANDING_COLUMNS[10:])

GZIP_RFC1952_HEADER: Final[bytes] = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff"
_PARQUET_MAGIC: Final[bytes] = b"PAR1"
_ROOT_SCHEMA_NAME: Final[str] = "analytics_landing_row_v1"

_CT_STOP, _CT_I16, _CT_I32, _CT_I64, _CT_BINARY, _CT_LIST, _CT_STRUCT = 0, 4, 5, 6, 8, 9, 12
_VALID_COMPACT_TYPES: Final[frozenset[int]] = frozenset(
    {_CT_I16, _CT_I32, _CT_I64, _CT_BINARY, _CT_LIST, _CT_STRUCT}
)
_TYPE_BYTE_ARRAY, _CONV_UTF8 = 6, 0
_REP_REQUIRED, _REP_OPTIONAL = 0, 1
_ENC_PLAIN, _ENC_RLE = 0, 3
_CODEC_UNCOMPRESSED, _CODEC_GZIP = 0, 2
_PAGE_DATA_PAGE: Final[int] = 0

_MAX_PARQUET_FILE_BYTES, _MAX_PARQUET_PAGE_BYTES, _MAX_PARQUET_ROWS = 67_108_864, 33_554_432, 1_000_000
_I16_MIN, _I16_MAX = -(1 << 15), (1 << 15) - 1
_I32_MIN, _I32_MAX = -(1 << 31), (1 << 31) - 1
_I64_MIN, _I64_MAX = -(1 << 63), (1 << 63) - 1


class _SchemaElemSpec(NamedTuple):
    name: str
    col_type: int | None = None
    repetition_type: int | None = None
    num_children: int | None = None
    converted_type: int | None = None

class _DataPageHeaderSpec(NamedTuple):
    num_values: int
    encoding: int
    def_encoding: int
    rep_encoding: int

class _PageHeaderSpec(NamedTuple):
    page_type: int
    uncompressed_page_size: int
    compressed_page_size: int
    data_page_header: _DataPageHeaderSpec

class _ColumnChunkSpec(NamedTuple):
    file_offset: int
    meta_data: _ColumnMetaSpec

class _ColumnMetaSpec(NamedTuple):
    col_type: int
    encodings: tuple[int, ...]
    path_in_schema: tuple[str, ...]
    codec: int
    num_values: int
    total_uncompressed_size: int
    total_compressed_size: int
    data_page_offset: int

class _RowGroupSpec(NamedTuple):
    columns: tuple[_ColumnChunkSpec, ...]
    total_byte_size: int
    num_rows: int
    file_offset: int | None = None

class _FileMetaSpec(NamedTuple):
    version: int
    schema: tuple[_SchemaElemSpec, ...]
    num_rows: int
    row_groups: tuple[_RowGroupSpec, ...]


def _encode_uvarint(value: int) -> bytes:
    if value < 0:
        raise ClosedValidationError(f"parquet: negative uvarint {value}")
    out, rem = bytearray(), value
    while rem >= 0x80:
        out.append((rem & 0x7F) | 0x80)
        rem >>= 7
    out.append(rem)
    return bytes(out)

def _encode_zigzag(value: int, *, bits: int) -> bytes:
    lo, hi = -(1 << (bits - 1)), (1 << (bits - 1)) - 1
    if not (lo <= value <= hi):
        raise ClosedValidationError(f"parquet: integer {value} overflows i{bits}")
    return _encode_uvarint(((value << 1) ^ (value >> (bits - 1))) & ((1 << bits) - 1))


class _CompactStructWriter:
    """Deterministic Thrift Compact Protocol struct serializer."""

    def __init__(self) -> None:
        self._buf, self._last_fid = bytearray(), 0

    def write_field_header(self, field_id: int, ctype: int) -> None:
        delta = field_id - self._last_fid
        if 1 <= delta <= 15:
            self._buf.append((delta << 4) | ctype)
        else:
            self._buf.append(ctype)
            self._buf.extend(_encode_zigzag(field_id, bits=16))
        self._last_fid = field_id

    def write_i32(self, field_id: int, value: int) -> None:
        self.write_field_header(field_id, _CT_I32)
        self._buf.extend(_encode_zigzag(value, bits=32))

    def write_i64(self, field_id: int, value: int) -> None:
        self.write_field_header(field_id, _CT_I64)
        self._buf.extend(_encode_zigzag(value, bits=64))

    def write_string(self, field_id: int, text: str) -> None:
        raw = text.encode("utf-8")
        self.write_field_header(field_id, _CT_BINARY)
        self._buf.extend(_encode_uvarint(len(raw)) + raw)

    def write_list_header(self, field_id: int, elem_ctype: int, count: int) -> None:
        self.write_field_header(field_id, _CT_LIST)
        if count < 15:
            self._buf.append((count << 4) | elem_ctype)
        else:
            self._buf.append(0xF0 | elem_ctype)
            self._buf.extend(_encode_uvarint(count))

    def write_raw(self, raw: bytes) -> None:
        self._buf.extend(raw)

    def write_struct_raw(self, field_id: int, encoded_struct: bytes) -> None:
        self.write_field_header(field_id, _CT_STRUCT)
        self._buf.extend(encoded_struct)

    def finish(self) -> bytes:
        self._buf.append(_CT_STOP)
        return bytes(self._buf)


class _CompactReader:
    """Strict minimal-varint Thrift Compact Protocol reader with zero slack tolerance."""

    def __init__(self, buf: bytes, start: int = 0, end: int | None = None) -> None:
        self._buf, self.pos, self._end = buf, start, (len(buf) if end is None else end)

    def read_byte(self) -> int:
        if self.pos >= self._end:
            raise ClosedValidationError("parquet: unexpected EOF in Thrift stream")
        val = self._buf[self.pos]
        self.pos += 1
        return val

    def read_bytes(self, length: int) -> bytes:
        if length < 0 or self.pos + length > self._end:
            raise ClosedValidationError("parquet: truncated binary field in Thrift")
        out = self._buf[self.pos : self.pos + length]
        self.pos += length
        return out

    def read_uvarint(self, *, max_bytes: int = 10) -> int:
        result, shift = 0, 0
        for idx in range(max_bytes):
            b = self.read_byte()
            if idx > 0 and b == 0:
                raise ClosedValidationError("parquet: non-minimal overlong varint")
            result |= (b & 0x7F) << shift
            if (b & 0x80) == 0:
                return result
            shift += 7
        raise ClosedValidationError("parquet: varint exceeds maximum byte length")

    def _read_zigzag(self, *, max_bytes: int, lo: int, hi: int) -> int:
        u = self.read_uvarint(max_bytes=max_bytes)
        val = (u >> 1) ^ -(u & 1)
        if not (lo <= val <= hi):
            raise ClosedValidationError(f"parquet: decoded integer {val} out of bounds")
        return val

    def read_i16(self) -> int:
        return self._read_zigzag(max_bytes=3, lo=_I16_MIN, hi=_I16_MAX)

    def read_i32(self) -> int:
        return self._read_zigzag(max_bytes=5, lo=_I32_MIN, hi=_I32_MAX)

    def read_i64(self) -> int:
        return self._read_zigzag(max_bytes=10, lo=_I64_MIN, hi=_I64_MAX)

    def read_string(self) -> str:
        length = self.read_uvarint(max_bytes=5)
        if length > 65_536:
            raise ClosedValidationError("parquet: metadata string exceeds 64 KiB")
        try:
            return self.read_bytes(length).decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise ClosedValidationError("parquet: invalid UTF-8 in metadata") from exc

    def read_field_header(self, last_fid: int, seen: set[int]) -> tuple[int, int]:
        b0 = self.read_byte()
        if b0 == _CT_STOP:
            return 0, _CT_STOP
        delta, ctype = (b0 >> 4) & 0x0F, b0 & 0x0F
        if ctype not in _VALID_COMPACT_TYPES:
            raise ClosedValidationError(f"parquet: unsupported Thrift ctype {ctype}")
        fid = self.read_i16() if delta == 0 else last_fid + delta
        if fid <= 0 or fid in seen:
            raise ClosedValidationError(f"parquet: invalid or duplicate field_id {fid}")
        seen.add(fid)
        return fid, ctype

    def read_list_header(self, expected_elem_ctype: int, *, max_len: int) -> int:
        b0 = self.read_byte()
        size_nibble, elem_ctype = (b0 >> 4) & 0x0F, b0 & 0x0F
        if elem_ctype != expected_elem_ctype:
            raise ClosedValidationError(f"parquet: list elem ctype {elem_ctype} != {expected_elem_ctype}")
        count = size_nibble if size_nibble < 15 else self.read_uvarint(max_bytes=5)
        if (size_nibble == 15 and count < 15) or count > max_len:
            raise ClosedValidationError(f"parquet: invalid or non-minimal list count {count}")
        return count

    def read_list(
        self, elem_ctype: int, item_fn: Callable[[_CompactReader], Any], *, max_len: int
    ) -> tuple[Any, ...]:
        return tuple(item_fn(self) for _ in range(self.read_list_header(elem_ctype, max_len=max_len)))

    def read_struct(
        self, decoders: Mapping[int, tuple[int, Callable[[_CompactReader], Any]]], *, required: frozenset[int]
    ) -> dict[int, Any]:
        last_fid, seen, out = 0, set[int](), dict[int, Any]()
        while True:
            fid, ctype = self.read_field_header(last_fid, seen)
            if ctype == _CT_STOP:
                break
            last_fid = fid
            spec = decoders.get(fid)
            if spec is None or spec[0] != ctype:
                raise ClosedValidationError(f"parquet: unexpected Thrift field ({fid}, {ctype})")
            out[fid] = spec[1](self)
        if not required.issubset(out.keys()):
            raise ClosedValidationError("parquet: missing required Thrift struct fields")
        return out


def _serialize_schema_element(elem: _SchemaElemSpec) -> bytes:
    w = _CompactStructWriter()
    if elem.col_type is not None:
        w.write_i32(1, elem.col_type)
    if elem.repetition_type is not None:
        w.write_i32(3, elem.repetition_type)
    w.write_string(4, elem.name)
    if elem.num_children is not None:
        w.write_i32(5, elem.num_children)
    if elem.converted_type is not None:
        w.write_i32(6, elem.converted_type)
    return w.finish()

def _serialize_page_header(*, uncompressed_size: int, compressed_size: int, num_values: int) -> bytes:
    dph, ph = _CompactStructWriter(), _CompactStructWriter()
    for fid, val in ((1, num_values), (2, _ENC_PLAIN), (3, _ENC_RLE), (4, _ENC_RLE)):
        dph.write_i32(fid, val)
    for fid, val in ((1, _PAGE_DATA_PAGE), (2, uncompressed_size), (3, compressed_size)):
        ph.write_i32(fid, val)
    ph.write_struct_raw(5, dph.finish())
    return ph.finish()

def _serialize_column_chunk(spec: _ColumnChunkSpec) -> bytes:
    cm, mw, cw = spec.meta_data, _CompactStructWriter(), _CompactStructWriter()
    mw.write_i32(1, cm.col_type)
    mw.write_list_header(2, _CT_I32, len(cm.encodings))
    for enc in cm.encodings:
        mw.write_raw(_encode_zigzag(enc, bits=32))
    mw.write_list_header(3, _CT_BINARY, len(cm.path_in_schema))
    for seg in cm.path_in_schema:
        seg_b = seg.encode("utf-8")
        mw.write_raw(_encode_uvarint(len(seg_b)) + seg_b)
    mw.write_i32(4, cm.codec)
    for fid, val in ((5, cm.num_values), (6, cm.total_uncompressed_size), (7, cm.total_compressed_size), (9, cm.data_page_offset)):
        mw.write_i64(fid, val)
    cw.write_i64(2, spec.file_offset)
    cw.write_struct_raw(3, mw.finish())
    return cw.finish()

def _serialize_row_group(rg: _RowGroupSpec) -> bytes:
    rw = _CompactStructWriter()
    rw.write_list_header(1, _CT_STRUCT, len(rg.columns))
    for col in rg.columns:
        rw.write_raw(_serialize_column_chunk(col))
    rw.write_i64(2, rg.total_byte_size)
    rw.write_i64(3, rg.num_rows)
    if rg.file_offset is not None:
        rw.write_i64(5, rg.file_offset)
    return rw.finish()

def _serialize_file_metadata(
    *, version: int, schema: Sequence[_SchemaElemSpec], num_rows: int, row_groups: Sequence[_RowGroupSpec]
) -> bytes:
    fw = _CompactStructWriter()
    fw.write_i32(1, version)
    fw.write_list_header(2, _CT_STRUCT, len(schema))
    for elem in schema:
        fw.write_raw(_serialize_schema_element(elem))
    fw.write_i64(3, num_rows)
    fw.write_list_header(4, _CT_STRUCT, len(row_groups))
    for rg in row_groups:
        fw.write_raw(_serialize_row_group(rg))
    return fw.finish()


_SCHEMA_ELEM_DECODERS: Final[Mapping[int, tuple[int, Callable[[_CompactReader], Any]]]] = {
    1: (_CT_I32, _CompactReader.read_i32), 3: (_CT_I32, _CompactReader.read_i32),
    4: (_CT_BINARY, _CompactReader.read_string), 5: (_CT_I32, _CompactReader.read_i32),
    6: (_CT_I32, _CompactReader.read_i32),
}
_DPH_DECODERS: Final[Mapping[int, tuple[int, Callable[[_CompactReader], Any]]]] = {
    fid: (_CT_I32, _CompactReader.read_i32) for fid in (1, 2, 3, 4)
}
_COL_META_DECODERS: Final[Mapping[int, tuple[int, Callable[[_CompactReader], Any]]]] = {
    1: (_CT_I32, _CompactReader.read_i32),
    2: (_CT_LIST, lambda r: r.read_list(_CT_I32, _CompactReader.read_i32, max_len=8)),
    3: (_CT_LIST, lambda r: r.read_list(_CT_BINARY, _CompactReader.read_string, max_len=4)),
    4: (_CT_I32, _CompactReader.read_i32),
    5: (_CT_I64, _CompactReader.read_i64), 6: (_CT_I64, _CompactReader.read_i64),
    7: (_CT_I64, _CompactReader.read_i64), 9: (_CT_I64, _CompactReader.read_i64),
}

def _parse_schema_element(r: _CompactReader) -> _SchemaElemSpec:
    f = r.read_struct(_SCHEMA_ELEM_DECODERS, required=frozenset({4}))
    return _SchemaElemSpec(f[4], f.get(1), f.get(3), f.get(5), f.get(6))

def _parse_data_page_header(r: _CompactReader) -> _DataPageHeaderSpec:
    f = r.read_struct(_DPH_DECODERS, required=frozenset({1, 2, 3, 4}))
    return _DataPageHeaderSpec(f[1], f[2], f[3], f[4])

def _parse_page_header_at(buf: bytes, start: int, limit: int) -> tuple[_PageHeaderSpec, int]:
    r = _CompactReader(buf, start, limit)
    decs: dict[int, tuple[int, Callable[[_CompactReader], Any]]] = {
        1: (_CT_I32, _CompactReader.read_i32), 2: (_CT_I32, _CompactReader.read_i32),
        3: (_CT_I32, _CompactReader.read_i32), 5: (_CT_STRUCT, _parse_data_page_header),
    }
    f = r.read_struct(decs, required=frozenset({1, 2, 3, 5}))
    return _PageHeaderSpec(f[1], f[2], f[3], f[5]), r.pos - start

def _parse_column_meta(r: _CompactReader) -> _ColumnMetaSpec:
    f = r.read_struct(_COL_META_DECODERS, required=frozenset({1, 2, 3, 4, 5, 6, 7, 9}))
    return _ColumnMetaSpec(f[1], f[2], f[3], f[4], f[5], f[6], f[7], f[9])

def _parse_column_chunk(r: _CompactReader) -> _ColumnChunkSpec:
    f = r.read_struct(
        {2: (_CT_I64, _CompactReader.read_i64), 3: (_CT_STRUCT, _parse_column_meta)},
        required=frozenset({2, 3}),
    )
    return _ColumnChunkSpec(file_offset=f[2], meta_data=f[3])

def _parse_row_group(r: _CompactReader) -> _RowGroupSpec:
    f = r.read_struct(
        {
            1: (_CT_LIST, lambda rd: rd.read_list(_CT_STRUCT, _parse_column_chunk, max_len=64)),
            2: (_CT_I64, _CompactReader.read_i64), 3: (_CT_I64, _CompactReader.read_i64),
            5: (_CT_I64, _CompactReader.read_i64),
        },
        required=frozenset({1, 2, 3}),
    )
    return _RowGroupSpec(f[1], f[2], f[3], f.get(5))

def _parse_file_metadata(footer_bytes: bytes) -> tuple[_FileMetaSpec, int]:
    r = _CompactReader(footer_bytes, 0, len(footer_bytes))
    f = r.read_struct(
        {
            1: (_CT_I32, _CompactReader.read_i32),
            2: (_CT_LIST, lambda rd: rd.read_list(_CT_STRUCT, _parse_schema_element, max_len=64)),
            3: (_CT_I64, _CompactReader.read_i64),
            4: (_CT_LIST, lambda rd: rd.read_list(_CT_STRUCT, _parse_row_group, max_len=16)),
        },
        required=frozenset({1, 2, 3, 4}),
    )
    if r.pos != len(footer_bytes):
        raise ClosedValidationError("parquet: trailing slack bytes inside FileMetaData")
    return _FileMetaSpec(f[1], f[2], f[3], f[4]), r.pos


def _encode_def_levels_bw1(levels: Sequence[int]) -> bytes:
    n = len(levels)
    if n == 0:
        return b""
    if n >= 8 and len(set(levels)) == 1:
        return _encode_uvarint(n << 1) + bytes((levels[0] & 1,))
    num_groups = (n + 7) // 8
    out = bytearray(_encode_uvarint((num_groups << 1) | 1))
    for g in range(num_groups):
        base, octet = g * 8, 0
        for bit_idx in range(8):
            if base + bit_idx < n and levels[base + bit_idx] == 1:
                octet |= 1 << bit_idx
        out.append(octet)
    return bytes(out)

def _decode_def_levels_bw1(buf: bytes, num_values: int) -> list[int]:
    r, out = _CompactReader(buf, 0, len(buf)), list[int]()
    while r.pos < len(buf):
        if len(out) >= num_values:
            raise ClosedValidationError("parquet: trailing definition-level runs")
        hdr, rem = r.read_uvarint(max_bytes=5), num_values - len(out)
        if (hdr & 1) == 0:
            run_len, val = hdr >> 1, r.read_byte()
            if not (1 <= run_len <= rem) or val not in (0, 1):
                raise ClosedValidationError("parquet: invalid RLE definition-level run")
            out.extend([val] * run_len)
        else:
            num_groups = hdr >> 1
            if not (1 <= num_groups <= (rem + 7) // 8):
                raise ClosedValidationError("parquet: invalid bit-packed group count")
            for byte_val in r.read_bytes(num_groups):
                for bit_idx in range(8):
                    bit = (byte_val >> bit_idx) & 1
                    if len(out) < num_values:
                        out.append(bit)
                    elif bit != 0:
                        raise ClosedValidationError("parquet: non-zero padding bit")
    if len(out) != num_values:
        raise ClosedValidationError("parquet: definition-level count mismatch")
    return out

def _encode_plain_utf8(values: Sequence[str]) -> bytes:
    return b"".join(struct.pack("<I", len(b)) + b for b in (v.encode("utf-8") for v in values))

def _decode_plain_utf8(buf: bytes, start: int, expected_count: int) -> list[str]:
    cursor, end, out = start, len(buf), list[str]()
    for _ in range(expected_count):
        if cursor + 4 > end:
            raise ClosedValidationError("parquet: truncated PLAIN BYTE_ARRAY length")
        byte_len = struct.unpack_from("<I", buf, cursor)[0]
        cursor += 4
        if cursor + byte_len > end:
            raise ClosedValidationError("parquet: truncated PLAIN BYTE_ARRAY value")
        try:
            out.append(buf[cursor : cursor + byte_len].decode("utf-8", errors="strict"))
        except UnicodeDecodeError as exc:
            raise ClosedValidationError("parquet: invalid UTF-8 cell value") from exc
        cursor += byte_len
    if cursor != end:
        raise ClosedValidationError("parquet: trailing slack bytes in DATA_PAGE")
    return out

def _compress_gzip_rfc1952(raw: bytes) -> bytes:
    comp = zlib.compressobj(level=9, method=zlib.DEFLATED, wbits=-15)
    deflated = comp.compress(raw) + comp.flush()
    return GZIP_RFC1952_HEADER + deflated + struct.pack("<II", zlib.crc32(raw) & 0xFFFFFFFF, len(raw) & 0xFFFFFFFF)

def _decompress_gzip_page(comp: bytes, expected_uncompressed_size: int) -> bytes:
    if len(comp) < 18 or comp[:10] != GZIP_RFC1952_HEADER:
        raise ClosedValidationError("parquet: GZIP page lacks canonical RFC 1952 header")
    exp_crc, exp_isize = struct.unpack_from("<II", comp, len(comp) - 8)
    try:
        decomp = zlib.decompressobj(-15)
        raw = decomp.decompress(comp[10:-8], expected_uncompressed_size + 1)
        if (
            len(raw) != expected_uncompressed_size or decomp.unconsumed_tail != b""
            or not decomp.eof or decomp.unused_data != b"" or decomp.flush(1) != b""
        ):
            raise ClosedValidationError("parquet: malformed or oversized GZIP stream")
    except zlib.error as exc:
        raise ClosedValidationError("parquet: corrupt GZIP deflate payload") from exc
    if (zlib.crc32(raw) & 0xFFFFFFFF) != exp_crc or (len(raw) & 0xFFFFFFFF) != exp_isize:
        raise ClosedValidationError("parquet: GZIP CRC-32 or ISIZE mismatch")
    return raw

def _encode_single_column_chunk(
    col_name: str, is_opt: bool, values: Sequence[str | None], *, offset: int, codec_id: int
) -> tuple[bytes, _ColumnChunkSpec]:
    if is_opt:
        rle = _encode_def_levels_bw1([0 if v is None else 1 for v in values])
        uncomp = struct.pack("<I", len(rle)) + rle + _encode_plain_utf8([v for v in values if v is not None])
        encodings = (_ENC_PLAIN, _ENC_RLE)
    else:
        if any(v is None for v in values):
            raise ClosedValidationError(f"parquet: null value in REQUIRED {col_name!r}")
        uncomp = _encode_plain_utf8([v for v in values if v is not None])
        encodings = (_ENC_PLAIN,)
    comp = _compress_gzip_rfc1952(uncomp) if codec_id == _CODEC_GZIP else uncomp
    ph_bytes = _serialize_page_header(uncompressed_size=len(uncomp), compressed_size=len(comp), num_values=len(values))
    chunk_bytes = ph_bytes + comp
    meta = _ColumnMetaSpec(
        _TYPE_BYTE_ARRAY, encodings, (col_name,), codec_id, len(values),
        len(ph_bytes) + len(uncomp), len(chunk_bytes), offset,
    )
    return chunk_bytes, _ColumnChunkSpec(file_offset=offset, meta_data=meta)

def _decode_column_page_values(uncomp: bytes, *, is_opt: bool, num_rows: int) -> list[str | None]:
    if not is_opt:
        return list(_decode_plain_utf8(uncomp, 0, num_rows))
    if len(uncomp) < 4:
        raise ClosedValidationError("parquet: truncated OPTIONAL definition levels")
    rle_len = struct.unpack_from("<I", uncomp, 0)[0]
    if 4 + rle_len > len(uncomp):
        raise ClosedValidationError("parquet: oversized OPTIONAL definition-level len")
    levels = _decode_def_levels_bw1(uncomp[4 : 4 + rle_len], num_rows)
    it = iter(_decode_plain_utf8(uncomp, 4 + rle_len, sum(levels)))
    return [next(it) if lvl == 1 else None for lvl in levels]

def _decode_single_column_chunk(
    raw_bytes: bytes, *, chunk: _ColumnChunkSpec, col_name: str, is_opt: bool,
    expected_offset: int, footer_start: int, num_rows: int,
) -> tuple[list[str | None], int, int]:
    cm = chunk.meta_data
    exp_enc = (_ENC_PLAIN, _ENC_RLE) if is_opt else (_ENC_PLAIN,)
    if (
        chunk.file_offset != expected_offset or cm.data_page_offset != expected_offset
        or (cm.col_type, cm.encodings, cm.path_in_schema, cm.num_values) != (_TYPE_BYTE_ARRAY, exp_enc, (col_name,), num_rows)
        or cm.codec not in (_CODEC_UNCOMPRESSED, _CODEC_GZIP)
    ):
        raise ClosedValidationError(f"parquet: non-contiguous or invalid chunk {col_name!r}")
    ph, hdr_len = _parse_page_header_at(raw_bytes, expected_offset, footer_start)
    dph = ph.data_page_header
    if (
        ph.page_type != _PAGE_DATA_PAGE or not (0 <= ph.uncompressed_page_size <= _MAX_PARQUET_PAGE_BYTES)
        or ph.compressed_page_size < 0 or cm.total_uncompressed_size != hdr_len + ph.uncompressed_page_size
        or cm.total_compressed_size != hdr_len + ph.compressed_page_size
        or expected_offset + cm.total_compressed_size > footer_start
        or (dph.num_values, dph.encoding, dph.def_encoding, dph.rep_encoding) != (num_rows, _ENC_PLAIN, _ENC_RLE, _ENC_RLE)
    ):
        raise ClosedValidationError(f"parquet: invalid PageHeader on {col_name!r}")
    comp_slice = raw_bytes[expected_offset + hdr_len : expected_offset + cm.total_compressed_size]
    if cm.codec == _CODEC_UNCOMPRESSED and ph.compressed_page_size != ph.uncompressed_page_size:
        raise ClosedValidationError("parquet: uncompressed page size mismatch")
    uncomp = comp_slice if cm.codec == _CODEC_UNCOMPRESSED else _decompress_gzip_page(comp_slice, ph.uncompressed_page_size)
    vals = _decode_column_page_values(uncomp, is_opt=is_opt, num_rows=num_rows)
    return vals, expected_offset + cm.total_compressed_size, cm.total_uncompressed_size

def _build_schema_specs(columns_spec: Sequence[tuple[str, bool]]) -> tuple[_SchemaElemSpec, ...]:
    root = _SchemaElemSpec(name=_ROOT_SCHEMA_NAME, num_children=len(columns_spec))
    leaves = tuple(
        _SchemaElemSpec(name, _TYPE_BYTE_ARRAY, _REP_OPTIONAL if is_opt else _REP_REQUIRED, None, _CONV_UTF8)
        for name, is_opt in columns_spec
    )
    return (root, *leaves)

def _encode_columns_to_parquet(
    columns_spec: Sequence[tuple[str, bool]], column_lists: Sequence[Sequence[str | None]],
    *, num_rows: int, compression: str,
) -> bytes:
    if type(compression) is not str or compression not in {"uncompressed", "gzip"}:
        raise ClosedValidationError(f"compression: unsupported codec {compression!r}")
    codec_id = _CODEC_GZIP if compression == "gzip" else _CODEC_UNCOMPRESSED
    schema = _build_schema_specs(columns_spec)
    if num_rows == 0:
        footer = _serialize_file_metadata(version=1, schema=schema, num_rows=0, row_groups=())
        return _PARQUET_MAGIC + footer + struct.pack("<I", len(footer)) + _PARQUET_MAGIC
    out, chunks, total_uncomp = bytearray(_PARQUET_MAGIC), list[_ColumnChunkSpec](), 0
    for (col_name, is_opt), col_vals in zip(columns_spec, column_lists, strict=True):
        chunk_bytes, chunk_spec = _encode_single_column_chunk(
            col_name, is_opt, col_vals, offset=len(out), codec_id=codec_id
        )
        out.extend(chunk_bytes)
        chunks.append(chunk_spec)
        total_uncomp += chunk_spec.meta_data.total_uncompressed_size
    rg = _RowGroupSpec(tuple(chunks), total_uncomp, num_rows, file_offset=4)
    footer = _serialize_file_metadata(version=1, schema=schema, num_rows=num_rows, row_groups=(rg,))
    return bytes(out) + footer + struct.pack("<I", len(footer)) + _PARQUET_MAGIC

def _validate_and_sort_input_rows(
    rows: Sequence[AnalyticsLandingRow], *, partition_key: str
) -> tuple[AnalyticsLandingRow, ...]:
    checked_pk = validate_partition_key(partition_key, field_name="partition_key")
    if isinstance(rows, (str, bytes, bytearray, memoryview)) or not isinstance(rows, Sequence):
        raise ClosedValidationError("rows: expected Sequence of AnalyticsLandingRow")
    if len(rows) > _MAX_PARQUET_ROWS:
        raise ClosedValidationError("rows: row count exceeds ceiling")
    keyed, seen_fk = list[tuple[bytes, AnalyticsLandingRow]](), set[bytes]()
    for idx, item in enumerate(rows):
        if type(item) is not AnalyticsLandingRow:
            raise ClosedValidationError(f"rows[{idx}]: expected AnalyticsLandingRow")
        fresh = AnalyticsLandingRow.from_dict(item.to_dict())
        if partition_key_for_metric_date(fresh.fact_key.metric_date) != checked_pk:
            raise ClosedValidationError(f"rows[{idx}]: partition_key mismatch vs {checked_pk!r}")
        fk_jcs = canonicalize_jcs(fresh.fact_key.to_dict())
        if fk_jcs in seen_fk:
            raise ClosedValidationError(f"rows[{idx}]: duplicate fact_key")
        seen_fk.add(fk_jcs)
        keyed.append((fk_jcs, fresh))
    keyed.sort(key=lambda pair: pair[0])
    return tuple(row for _, row in keyed)

def _extract_column_lists(rows: Sequence[AnalyticsLandingRow]) -> dict[str, list[str | None]]:
    cols: dict[str, list[str | None]] = {name: [] for name, _ in PARQUET_LANDING_COLUMNS}
    for row in rows:
        d = row.to_dict()
        fk = d["fact_key"]
        cols["$schema"].append(d["$schema"])
        for k in _FACT_KEY_COL_NAMES:
            cols[k].append(fk[k])
        for k in _ROW_TAIL_COL_NAMES:
            cols[k].append(d[k])
    return cols

def _reconstruct_and_verify_rows(
    decoded_cols: Sequence[list[str | None]], *, num_rows: int, expected_partition_key: str
) -> tuple[AnalyticsLandingRow, ...]:
    out: list[AnalyticsLandingRow] = []
    prev_fk: bytes | None = None
    for r_idx in range(num_rows):
        fk_dict = {k: decoded_cols[1 + i][r_idx] for i, k in enumerate(_FACT_KEY_COL_NAMES)}
        row_dict: dict[str, Any] = {
            "$schema": decoded_cols[0][r_idx], "fact_key": fk_dict,
            **{k: decoded_cols[10 + i][r_idx] for i, k in enumerate(_ROW_TAIL_COL_NAMES)},
        }
        row = AnalyticsLandingRow.from_dict(row_dict)
        if partition_key_for_metric_date(row.fact_key.metric_date) != expected_partition_key:
            raise ClosedValidationError(f"parquet: row[{r_idx}] partition_key mismatch")
        fk_jcs = canonicalize_jcs(row.fact_key.to_dict())
        if prev_fk is not None and fk_jcs <= prev_fk:
            raise ClosedValidationError(f"parquet: duplicate or unsorted fact_key at row[{r_idx}]")
        prev_fk = fk_jcs
        out.append(row)
    return tuple(out)

def _parse_and_check_parquet_envelope(raw_bytes: bytes) -> tuple[_FileMetaSpec, int]:
    if type(raw_bytes) is not bytes or not (12 <= len(raw_bytes) <= _MAX_PARQUET_FILE_BYTES):
        raise ClosedValidationError("parquet: invalid or oversized raw_bytes")
    if raw_bytes[:4] != _PARQUET_MAGIC or raw_bytes[-4:] != _PARQUET_MAGIC:
        raise ClosedValidationError("parquet: invalid PAR1 magic header or trailer")
    footer_len = struct.unpack_from("<I", raw_bytes, len(raw_bytes) - 8)[0]
    footer_start = len(raw_bytes) - 8 - footer_len
    if footer_len < 1 or footer_start < 4:
        raise ClosedValidationError("parquet: corrupt FileMetaData footer length")
    meta, _ = _parse_file_metadata(raw_bytes[footer_start : len(raw_bytes) - 8])
    if meta.version != 1 or not (0 <= meta.num_rows <= _MAX_PARQUET_ROWS):
        raise ClosedValidationError("parquet: unsupported version or row count")
    if meta.schema != _build_schema_specs(PARQUET_LANDING_COLUMNS):
        raise ClosedValidationError("parquet: schema mismatch vs 24-column landing schema")
    return meta, footer_start


def encode_landing_parquet(
    rows: Sequence[AnalyticsLandingRow], *, partition_key: str,
    compression: ParquetCompression = "uncompressed",
) -> bytes:
    """Encode `rows` into deterministic gap-free Apache Parquet v1 (`PAR1`) bytes."""
    ordered = _validate_and_sort_input_rows(rows, partition_key=partition_key)
    col_map = _extract_column_lists(ordered)
    col_lists = [col_map[name] for name, _ in PARQUET_LANDING_COLUMNS]
    return _encode_columns_to_parquet(
        PARQUET_LANDING_COLUMNS, col_lists, num_rows=len(ordered), compression=compression
    )


def decode_and_verify_landing_parquet(
    raw_bytes: bytes, *, expected_partition_key: str
) -> tuple[AnalyticsLandingRow, ...]:
    """Decode and verify contiguity, schema, row digests, partition key, and `fact_key` order."""
    checked_pk = validate_partition_key(expected_partition_key, field_name="expected_partition_key")
    meta, footer_start = _parse_and_check_parquet_envelope(raw_bytes)
    if meta.num_rows == 0:
        if len(meta.row_groups) != 0 or footer_start != 4:
            raise ClosedValidationError("parquet: non-empty or non-contiguous 0-row file")
        return ()
    if len(meta.row_groups) != 1:
        raise ClosedValidationError("parquet: expected exact single RowGroup")
    rg = meta.row_groups[0]
    if rg.num_rows != meta.num_rows or len(rg.columns) != len(PARQUET_LANDING_COLUMNS) or (
        rg.file_offset is not None and rg.file_offset != 4
    ):
        raise ClosedValidationError("parquet: RowGroup metadata mismatch")
    if len({c.meta_data.codec for c in rg.columns}) != 1:
        raise ClosedValidationError("parquet: mixed codecs across column chunks")
    cursor, sum_uncomp, decoded_cols = 4, 0, list[list[str | None]]()
    for chunk, (col_name, is_opt) in zip(rg.columns, PARQUET_LANDING_COLUMNS, strict=True):
        vals, cursor, col_uncomp = _decode_single_column_chunk(
            raw_bytes, chunk=chunk, col_name=col_name, is_opt=is_opt,
            expected_offset=cursor, footer_start=footer_start, num_rows=meta.num_rows,
        )
        decoded_cols.append(vals)
        sum_uncomp += col_uncomp
    if cursor != footer_start or rg.total_byte_size != sum_uncomp:
        raise ClosedValidationError("parquet: trailing slack bytes or total_byte_size mismatch")
    return _reconstruct_and_verify_rows(
        decoded_cols, num_rows=meta.num_rows, expected_partition_key=checked_pk
    )


class StdlibParquetLandingCodec(ParquetLandingCodecPort):
    """Pure Python 3.12 stdlib adapter implementing `ParquetLandingCodecPort`."""

    def encode_landing_rows(
        self, rows: Sequence[AnalyticsLandingRow], *, partition_key: str,
        compression: Literal["uncompressed", "gzip"] = "uncompressed",
    ) -> bytes:
        return encode_landing_parquet(rows, partition_key=partition_key, compression=compression)

    def decode_and_verify_landing_rows(
        self, raw_bytes: bytes, *, expected_partition_key: str
    ) -> tuple[AnalyticsLandingRow, ...]:
        return decode_and_verify_landing_parquet(raw_bytes, expected_partition_key=expected_partition_key)


__all__ = [
    "GZIP_RFC1952_HEADER", "PARQUET_LANDING_COLUMNS", "StdlibParquetLandingCodec",
    "decode_and_verify_landing_parquet", "encode_landing_parquet",
]
