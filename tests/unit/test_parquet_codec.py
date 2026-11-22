"""Unit tests for immutable content-addressed object stores and stdlib Apache Parquet v1 codec."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
from typing import Any

import pytest

from smart_ads.adapters.storage import (
    PARQUET_LANDING_COLUMNS,
    FilesystemCellObjectStore,
    InMemoryCellObjectStore,
    StdlibParquetLandingCodec,
    decode_and_verify_landing_parquet,
    encode_landing_parquet,
)
from smart_ads.adapters.storage import parquet as parquet_mod
from smart_ads.contracts.jcs import ArtifactLocator, canonicalize_jcs
from smart_ads.contracts.numerics import (
    CalculationStatus,
    MetricOrigin,
    PresenceStatus,
    UnitType,
    UnknownReason,
    ValueType,
)
from smart_ads.contracts.scalars import ClosedValidationError
from smart_ads.contracts.schemas import AnalyticsLandingRow, FactKey
from smart_ads.domain.resource_ref import TenantResourceKeyHandle, derive_resource_ref
from smart_ads.ports.storage import CellObjectStorePort, ParquetLandingCodecPort

GZIP_RFC1952_HEADER = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff"
_KEY_HANDLE = TenantResourceKeyHandle(
    tenant_ref="tenant:ibvi",
    key_identity="key:ibvi-parquet-test",
    secret_bytes=b"0123456789abcdef0123456789abcdef",
)


def _resource_ref(index: int) -> str:
    return derive_resource_ref(
        key_handle=_KEY_HANDLE,
        mapping_version="hmac-sha256-b32-v1",
        domain_separator="0x00",
        ad_platform_ref="meta",
        resource_level="campaign",
        raw_provider_id=str(100_000 + index),
    )


def _make_row(
    *,
    idx: int,
    metric_date: str = "2026-08-15",
    metric_semantic_ref: str = "metric:clicks_v1",
    metric_origin: MetricOrigin = "provider_observation",
    presence_status: PresenceStatus = "observed",
    calculation_status: CalculationStatus = "not_applicable",
    unknown_reason: UnknownReason | None = None,
    value_type: ValueType | None = "int64_count",
    raw_numeric_value: str | None = "42",
    unit: UnitType | None = "count",
    currency: str | None = None,
) -> AnalyticsLandingRow:
    if metric_origin == "provider_observation":
        source_metric_ref = f"source-metric:provider:pipeboard.m{idx}:v1"
    else:
        digest_hex = hashlib.sha256(f"formula-{idx}".encode("utf-8")).hexdigest()
        source_metric_ref = f"source-metric:formula:sha256:{digest_hex}"
    fact_key = FactKey(
        binding_ref="binding:meta-primary",
        account_ref="account:ibvi-01",
        resource_ref=_resource_ref(idx),
        resource_level="campaign",
        metric_date=metric_date,
        metric_semantic_ref=metric_semantic_ref,
        source_metric_ref=source_metric_ref,
        attribution_ref="attribution:not_applicable",
        breakdown_signature="breakdown:none",
    )
    return AnalyticsLandingRow(
        fact_key=fact_key,
        value_type=value_type,
        raw_numeric_value=raw_numeric_value,
        unit=unit,
        currency=currency,
        metric_origin=metric_origin,
        presence_status=presence_status,
        unknown_reason=unknown_reason,
        calculation_status=calculation_status,
        collected_at_utc="2026-08-16T03:15:00.123456Z",
        source_observation_ref=f"observation:obs-{idx:03d}",
        adapter_version="pipeboard-0.1.0",
        semantic_version="1.0.0",
    )


@pytest.fixture
def sample_12_matrix_rows() -> tuple[AnalyticsLandingRow, ...]:
    specs: tuple[dict[str, Any], ...] = (
        {"idx": 1, "metric_semantic_ref": "metric:spend_v1", "metric_origin": "provider_observation", "presence_status": "observed", "calculation_status": "not_applicable", "unknown_reason": None, "value_type": "int64_minor_currency", "raw_numeric_value": "125099", "unit": "minor_currency", "currency": "BRL"},
        {"idx": 2, "metric_semantic_ref": "metric:ctr_v1", "metric_origin": "derived_formula", "presence_status": "not_applicable", "calculation_status": "computed", "unknown_reason": None, "value_type": "decimal_ratio", "raw_numeric_value": "0.031250", "unit": "ratio", "currency": None},
        {"idx": 3, "metric_semantic_ref": "metric:clicks_v1", "metric_origin": "provider_observation", "presence_status": "missing", "calculation_status": "not_applicable", "unknown_reason": "provider_omitted", "value_type": None, "raw_numeric_value": None, "unit": None, "currency": None},
        {"idx": 4, "metric_semantic_ref": "metric:clicks_v1", "metric_origin": "provider_observation", "presence_status": "unproven_zero", "calculation_status": "not_applicable", "unknown_reason": "zero_not_proven", "value_type": None, "raw_numeric_value": None, "unit": None, "currency": None},
        {"idx": 5, "metric_semantic_ref": "metric:clicks_v1", "metric_origin": "provider_observation", "presence_status": "timeout", "calculation_status": "not_applicable", "unknown_reason": "provider_timeout", "value_type": None, "raw_numeric_value": None, "unit": None, "currency": None},
        {"idx": 6, "metric_semantic_ref": "metric:clicks_v1", "metric_origin": "provider_observation", "presence_status": "not_applicable_at_level", "calculation_status": "not_applicable", "unknown_reason": "metric_not_applicable_at_level", "value_type": None, "raw_numeric_value": None, "unit": None, "currency": None},
        {"idx": 7, "metric_semantic_ref": "metric:spend_v1", "metric_origin": "provider_observation", "presence_status": "retracted_tombstone", "calculation_status": "not_applicable", "unknown_reason": "source_retracted", "value_type": None, "raw_numeric_value": None, "unit": None, "currency": None},
        {"idx": 8, "metric_semantic_ref": "metric:ctr_v1", "metric_origin": "derived_formula", "presence_status": "not_applicable", "calculation_status": "input_missing", "unknown_reason": "input_missing", "value_type": None, "raw_numeric_value": None, "unit": None, "currency": None},
        {"idx": 9, "metric_semantic_ref": "metric:ctr_v1", "metric_origin": "derived_formula", "presence_status": "not_applicable", "calculation_status": "input_unproven", "unknown_reason": "input_unproven", "value_type": None, "raw_numeric_value": None, "unit": None, "currency": None},
        {"idx": 10, "metric_semantic_ref": "metric:ctr_v1", "metric_origin": "derived_formula", "presence_status": "not_applicable", "calculation_status": "division_by_zero", "unknown_reason": "division_by_zero", "value_type": None, "raw_numeric_value": None, "unit": None, "currency": None},
        {"idx": 11, "metric_semantic_ref": "metric:ctr_v1", "metric_origin": "derived_formula", "presence_status": "not_applicable_at_level", "calculation_status": "not_applicable", "unknown_reason": "metric_not_applicable_at_level", "value_type": None, "raw_numeric_value": None, "unit": None, "currency": None},
        {"idx": 12, "metric_semantic_ref": "metric:ctr_v1", "metric_origin": "derived_formula", "presence_status": "retracted_tombstone", "calculation_status": "not_applicable", "unknown_reason": "source_retracted", "value_type": None, "raw_numeric_value": None, "unit": None, "currency": None},
    )
    rows = tuple(_make_row(**spec) for spec in specs)
    return tuple(sorted(rows, key=lambda r: canonicalize_jcs(r.fact_key.to_dict())))


def test_parquet_columns_and_protocol_conformance(tmp_path: Path) -> None:
    expected_cols = (
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
    assert PARQUET_LANDING_COLUMNS == expected_cols
    assert len(PARQUET_LANDING_COLUMNS) == 24
    assert sum(1 for _, opt in PARQUET_LANDING_COLUMNS if not opt) == 19
    assert sum(1 for _, opt in PARQUET_LANDING_COLUMNS if opt) == 5

    mem_store = InMemoryCellObjectStore()
    fs_store = FilesystemCellObjectStore(tmp_path / "cell_store")
    codec = StdlibParquetLandingCodec()
    assert isinstance(mem_store, CellObjectStorePort)
    assert isinstance(fs_store, CellObjectStorePort)
    assert isinstance(codec, ParquetLandingCodecPort)
    for store in (mem_store, fs_store):
        for forbidden in ("delete", "remove", "unlink", "pop", "clear"):
            assert not hasattr(store, forbidden)


def test_all_12_matrix_states_and_value_types_roundtrip(
    sample_12_matrix_rows: tuple[AnalyticsLandingRow, ...],
) -> None:
    extra_value_rows = (
        _make_row(idx=21, metric_semantic_ref="metric:clicks_v1", metric_origin="provider_observation", value_type="int64_count", raw_numeric_value="0", unit="count", currency=None),
        _make_row(idx=22, metric_semantic_ref="metric:ctr_obs_v1", metric_origin="provider_observation", value_type="decimal_ratio", raw_numeric_value="1.250000", unit="ratio", currency=None),
        _make_row(idx=23, metric_semantic_ref="metric:net_clicks_v1", metric_origin="derived_formula", presence_status="not_applicable", calculation_status="computed", value_type="int64_count", raw_numeric_value="9223372036854775807", unit="count", currency=None),
        _make_row(idx=24, metric_semantic_ref="metric:net_spend_v1", metric_origin="derived_formula", presence_status="not_applicable", calculation_status="computed", value_type="int64_minor_currency", raw_numeric_value="50000", unit="minor_currency", currency="BRL"),
    )
    combined = tuple(
        sorted(
            (*sample_12_matrix_rows, *extra_value_rows),
            key=lambda r: canonicalize_jcs(r.fact_key.to_dict()),
        )
    )
    codec = StdlibParquetLandingCodec()
    for comp in ("uncompressed", "gzip"):
        raw_12 = codec.encode_landing_rows(
            sample_12_matrix_rows, partition_key="year=2026/month=08", compression=comp
        )
        assert codec.decode_and_verify_landing_rows(
            raw_12, expected_partition_key="year=2026/month=08"
        ) == sample_12_matrix_rows

        raw_all = encode_landing_parquet(
            combined, partition_key="year=2026/month=08", compression=comp
        )
        decoded_all = decode_and_verify_landing_parquet(
            raw_all, expected_partition_key="year=2026/month=08"
        )
        assert decoded_all == combined


def test_bitwise_determinism_rle_runs_and_gzip_rfc1952_header(
    sample_12_matrix_rows: tuple[AnalyticsLandingRow, ...],
) -> None:
    reversed_rows = tuple(reversed(sample_12_matrix_rows))
    uncomp_a = encode_landing_parquet(
        sample_12_matrix_rows, partition_key="year=2026/month=08", compression="uncompressed"
    )
    uncomp_b = encode_landing_parquet(
        reversed_rows, partition_key="year=2026/month=08", compression="uncompressed"
    )
    assert uncomp_a == uncomp_b
    assert uncomp_a[:4] == b"PAR1" and uncomp_a[-4:] == b"PAR1"

    gzip_a = encode_landing_parquet(
        sample_12_matrix_rows, partition_key="year=2026/month=08", compression="gzip"
    )
    gzip_b = encode_landing_parquet(
        reversed_rows, partition_key="year=2026/month=08", compression="gzip"
    )
    assert gzip_a == gzip_b
    assert gzip_a.count(GZIP_RFC1952_HEADER) == 24

    # Uniform >= 8 rows exercise RLE-run encoding on both all-null and all-present OPTIONAL columns
    uniform_10 = tuple(
        sorted(
            (_make_row(idx=50 + i) for i in range(10)),
            key=lambda r: canonicalize_jcs(r.fact_key.to_dict()),
        )
    )
    raw_u10 = encode_landing_parquet(
        uniform_10, partition_key="year=2026/month=08", compression="gzip"
    )
    assert decode_and_verify_landing_parquet(
        raw_u10, expected_partition_key="year=2026/month=08"
    ) == uniform_10
    for empty_codec in ("uncompressed", "gzip"):
        empty_raw = encode_landing_parquet(
            (), partition_key="year=2026/month=08", compression=empty_codec
        )
        assert decode_and_verify_landing_parquet(
            empty_raw, expected_partition_key="year=2026/month=08"
        ) == ()
    # Corrupt GZIP RFC 1952 OS byte inside first compressed page must fail closed
    tampered_gzip = gzip_a.replace(GZIP_RFC1952_HEADER, GZIP_RFC1952_HEADER[:-1] + b"\x03", 1)
    with pytest.raises(ClosedValidationError):
        decode_and_verify_landing_parquet(tampered_gzip, expected_partition_key="year=2026/month=08")


def _inject_slack_after_first_chunk(raw_parquet: bytes, slack: bytes) -> bytes:
    """Build Parquet bytes with `slack` after chunk 0 while updating subsequent offsets."""
    footer_len = struct.unpack_from("<I", raw_parquet, len(raw_parquet) - 8)[0]
    footer_start = len(raw_parquet) - 8 - footer_len
    meta, _ = parquet_mod._parse_file_metadata(raw_parquet[footer_start : len(raw_parquet) - 8])
    rg = meta.row_groups[0]
    c0_end = rg.columns[0].file_offset + rg.columns[0].meta_data.total_compressed_size
    shifted_cols: list[parquet_mod._ColumnChunkSpec] = [rg.columns[0]]
    for col in rg.columns[1:]:
        cm = col.meta_data
        new_off = col.file_offset + len(slack)
        new_cm = parquet_mod._ColumnMetaSpec(
            col_type=cm.col_type, encodings=cm.encodings, path_in_schema=cm.path_in_schema,
            codec=cm.codec, num_values=cm.num_values,
            total_uncompressed_size=cm.total_uncompressed_size,
            total_compressed_size=cm.total_compressed_size,
            data_page_offset=new_off,
        )
        shifted_cols.append(parquet_mod._ColumnChunkSpec(file_offset=new_off, meta_data=new_cm))
    new_rg = parquet_mod._RowGroupSpec(
        columns=tuple(shifted_cols), total_byte_size=rg.total_byte_size,
        num_rows=rg.num_rows, file_offset=rg.file_offset,
    )
    new_footer = parquet_mod._serialize_file_metadata(
        version=meta.version, schema=meta.schema, num_rows=meta.num_rows, row_groups=(new_rg,)
    )
    return (
        raw_parquet[:c0_end]
        + slack
        + raw_parquet[c0_end:footer_start]
        + new_footer
        + struct.pack("<I", len(new_footer))
        + b"PAR1"
    )


def test_parquet_rejects_magic_truncation_and_slack_bytes(
    sample_12_matrix_rows: tuple[AnalyticsLandingRow, ...],
) -> None:
    raw = encode_landing_parquet(
        sample_12_matrix_rows[:2], partition_key="year=2026/month=08", compression="uncompressed"
    )
    bad_cases = [
        b"PAR0" + raw[4:],
        raw[:-4] + b"PAR2",
        raw[:10],
        raw[:-1],
        b"PAR1PAR1",
        _inject_slack_after_first_chunk(raw, b"\x00"),
    ]
    # Also test slack between last column chunk and FileMetaData (keeping valid footer_len)
    footer_len = struct.unpack_from("<I", raw, len(raw) - 8)[0]
    footer_start = len(raw) - 8 - footer_len
    bad_cases.append(raw[:footer_start] + b"\x00\x00" + raw[footer_start:])
    # Also test trailing byte inside FileMetaData slice after Thrift STOP byte
    bad_cases.append(
        raw[: len(raw) - 8] + b"\x00" + struct.pack("<I", footer_len + 1) + b"PAR1"
    )
    for bad in bad_cases:
        with pytest.raises(ClosedValidationError):
            decode_and_verify_landing_parquet(bad, expected_partition_key="year=2026/month=08")


def test_parquet_rejects_schema_column_mutations(
    sample_12_matrix_rows: tuple[AnalyticsLandingRow, ...],
) -> None:
    rows = sample_12_matrix_rows[:2]
    col_map = parquet_mod._extract_column_lists(rows)
    # Missing column (23 cols)
    missing_spec = PARQUET_LANDING_COLUMNS[:-1]
    raw_missing = parquet_mod._encode_columns_to_parquet(
        missing_spec, [col_map[name] for name, _ in missing_spec],
        num_rows=len(rows), compression="uncompressed",
    )
    # Extra column (25 cols)
    extra_spec = (*PARQUET_LANDING_COLUMNS, ("extra_col", True))
    raw_extra = parquet_mod._encode_columns_to_parquet(
        extra_spec, [*[col_map[name] for name, _ in PARQUET_LANDING_COLUMNS], [None, None]],
        num_rows=len(rows), compression="uncompressed",
    )
    # Reordered columns (swap binding_ref and account_ref)
    reordered_list = list(PARQUET_LANDING_COLUMNS)
    reordered_list[1], reordered_list[2] = reordered_list[2], reordered_list[1]
    reordered_spec = tuple(reordered_list)
    raw_reordered = parquet_mod._encode_columns_to_parquet(
        reordered_spec, [col_map[name] for name, _ in reordered_spec],
        num_rows=len(rows), compression="uncompressed",
    )
    for bad in (raw_missing, raw_extra, raw_reordered):
        with pytest.raises(ClosedValidationError):
            decode_and_verify_landing_parquet(bad, expected_partition_key="year=2026/month=08")


def test_parquet_rejects_unsorted_duplicate_partition_and_digest_tampering(
    sample_12_matrix_rows: tuple[AnalyticsLandingRow, ...],
) -> None:
    r0, r1 = sample_12_matrix_rows[0], sample_12_matrix_rows[1]
    # Encoder rejects duplicate fact_key and divergent partition_key
    with pytest.raises(ClosedValidationError):
        encode_landing_parquet((r0, r0), partition_key="year=2026/month=08")
    with pytest.raises(ClosedValidationError):
        encode_landing_parquet((r0,), partition_key="year=2026/month=09")
    with pytest.raises(ClosedValidationError):
        encode_landing_parquet((r0,), partition_key="year=2026/month=08", compression="snappy")  # type: ignore[arg-type]

    # Decoder rejects divergent partition_key
    valid_raw = encode_landing_parquet((r0, r1), partition_key="year=2026/month=08")
    with pytest.raises(ClosedValidationError):
        decode_and_verify_landing_parquet(valid_raw, expected_partition_key="year=2026/month=09")

    # Wire-level unsorted fact_key & duplicate fact_key
    for bad_rows in ((r1, r0), (r0, r0)):
        col_map = parquet_mod._extract_column_lists(bad_rows)
        bad_wire = parquet_mod._encode_columns_to_parquet(
            PARQUET_LANDING_COLUMNS, [col_map[name] for name, _ in PARQUET_LANDING_COLUMNS],
            num_rows=2, compression="uncompressed",
        )
        with pytest.raises(ClosedValidationError):
            decode_and_verify_landing_parquet(bad_wire, expected_partition_key="year=2026/month=08")

    # Wire-level row_digest tampering
    orig_digest_bytes = r0.row_digest.encode("utf-8")
    flipped = orig_digest_bytes[:-1] + (b"0" if orig_digest_bytes[-1:] != b"0" else b"1")
    tampered_raw = valid_raw.replace(orig_digest_bytes, flipped, 1)
    assert tampered_raw != valid_raw
    with pytest.raises(ClosedValidationError):
        decode_and_verify_landing_parquet(tampered_raw, expected_partition_key="year=2026/month=08")


def test_in_memory_and_filesystem_cell_object_stores(tmp_path: Path) -> None:
    for store in (InMemoryCellObjectStore(), FilesystemCellObjectStore(tmp_path / "cas")):
        payload = b"immutable-parquet-or-json-bytes"
        expected_ref = "cell-object:sha256:" + hashlib.sha256(payload).hexdigest()
        assert not store.has_object(expected_ref)
        ref = store.put_bytes(payload)
        assert ref == expected_ref
        assert store.put_bytes(payload) == expected_ref
        assert store.has_object(ref)
        assert store.get_bytes(ref) == payload
        assert store.get_bytes(ref, expected_size_bytes=len(payload)) == payload
        with pytest.raises(ClosedValidationError):
            store.get_bytes(ref, expected_size_bytes=len(payload) + 1)
        with pytest.raises(ClosedValidationError):
            store.get_bytes("cell-object:sha256:" + ("f" * 64))
        with pytest.raises(ClosedValidationError):
            store.has_object("not-a-valid-ref")

        doc = {"$schema": "smart_ads/migration_run_context/v1", "z": 2, "a": "ok"}
        loc = store.put_json_artifact("smart_ads/migration_run_context/v1", doc)
        assert loc == ArtifactLocator.for_canonical_bytes(
            "smart_ads/migration_run_context/v1", canonicalize_jcs(doc)
        )
        loaded = store.get_json_artifact(loc)
        assert loaded == doc
        loaded["z"] = 999
        assert store.get_json_artifact(loc) == doc

        with pytest.raises(ClosedValidationError):
            store.put_json_artifact("smart_ads/other/v1", doc)
        non_canon = b'{ "$schema": "smart_ads/migration_run_context/v1", "a": 1 }'
        store.put_bytes(non_canon)
        non_canon_loc = ArtifactLocator.for_canonical_bytes(
            "smart_ads/migration_run_context/v1", non_canon
        )
        with pytest.raises(ClosedValidationError):
            store.get_json_artifact(non_canon_loc)


def test_filesystem_object_store_permissions_symlinks_and_bitrot(tmp_path: Path) -> None:
    real_dir = tmp_path / "real_target"
    real_dir.mkdir()
    symlink_root = tmp_path / "sym_root"
    symlink_root.symlink_to(real_dir)
    with pytest.raises(ClosedValidationError):
        FilesystemCellObjectStore(symlink_root)

    store_root = tmp_path / "fs_store"
    store = FilesystemCellObjectStore(store_root)
    raw = b"content-addressed-object-v1"
    ref = store.put_bytes(raw)
    hex_digest = ref.rsplit(":", 1)[1]
    obj_path = store_root / "sha256" / hex_digest
    assert obj_path.is_file() and not obj_path.is_symlink()
    assert stat.S_IMODE(obj_path.lstat().st_mode) == 0o444

    # Simulate on-disk bit-rot and verify both get_bytes and put_bytes fail closed
    os.chmod(obj_path, 0o644)
    obj_path.write_bytes(b"corrupted-disk-bytes-000000")
    os.chmod(obj_path, 0o444)
    with pytest.raises(ClosedValidationError):
        store.get_bytes(ref)
    with pytest.raises(ClosedValidationError):
        store.put_bytes(raw)

    # Planted dangling symlink in sha256/<64_hex> must fail closed on has/get/put
    planted_bytes = b"planted-symlink-victim"
    planted_hex = hashlib.sha256(planted_bytes).hexdigest()
    planted_ref = f"cell-object:sha256:{planted_hex}"
    (store_root / "sha256" / planted_hex).symlink_to(tmp_path / "nonexistent_target")
    with pytest.raises(ClosedValidationError):
        store.has_object(planted_ref)
    with pytest.raises(ClosedValidationError):
        store.get_bytes(planted_ref)
    with pytest.raises(ClosedValidationError):
        store.put_bytes(planted_bytes)


def _find_duckdb_binary() -> Path | None:
    duckdb_bin = Path("/opt/homebrew/bin/duckdb")
    if duckdb_bin.is_file():
        return duckdb_bin
    found = shutil.which("duckdb")
    return None if found is None else Path(found)


def test_duckdb_cli_reads_stdlib_parquet_uncompressed_and_gzip(
    tmp_path: Path, sample_12_matrix_rows: tuple[AnalyticsLandingRow, ...]
) -> None:
    duckdb_bin = _find_duckdb_binary()
    if duckdb_bin is None:
        return
    for codec in ("uncompressed", "gzip"):
        raw = encode_landing_parquet(
            sample_12_matrix_rows, partition_key="year=2026/month=08", compression=codec
        )
        pq_path = tmp_path / f"landing_{codec}.parquet"
        pq_path.write_bytes(raw)
        proc = subprocess.run(
            [str(duckdb_bin), "-json", "-c", f"SELECT count(*) AS n FROM read_parquet('{pq_path.as_posix()}');"],
            stdin=subprocess.DEVNULL, capture_output=True, text=True, check=True,
        )
        assert json.loads(proc.stdout) == [{"n": len(sample_12_matrix_rows)}]
        rows_proc = subprocess.run(
            [str(duckdb_bin), "-json", "-c", f"SELECT * FROM read_parquet('{pq_path.as_posix()}');"],
            stdin=subprocess.DEVNULL, capture_output=True, text=True, check=True,
        )
        duck_rows = json.loads(rows_proc.stdout)
        assert len(duck_rows) == len(sample_12_matrix_rows)
        for duck_row, exp_row in zip(duck_rows, sample_12_matrix_rows, strict=True):
            assert list(duck_row.keys()) == [c for c, _ in PARQUET_LANDING_COLUMNS]
            assert duck_row["row_digest"] == exp_row.row_digest
            assert duck_row["value_type"] == exp_row.value_type
            assert duck_row["raw_numeric_value"] == exp_row.raw_numeric_value
            assert duck_row["currency"] == exp_row.currency
            assert duck_row["unknown_reason"] == exp_row.unknown_reason
