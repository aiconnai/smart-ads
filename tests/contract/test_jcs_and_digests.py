"""Contract tests for smart_ads.contracts.{scalars,jcs} (ADR-0001)."""
from __future__ import annotations

import base64
from datetime import date
import hashlib
from pathlib import Path
import subprocess
from types import MappingProxyType
import unicodedata

import pytest

import smart_ads.contracts as contracts
from smart_ads.contracts import (
    ADR_DATA_DOMAIN_PREFIXES,
    ADR_P1_DOMAIN_PREFIXES,
    MAX_JCS_SAFE_INT,
    MIN_JCS_SAFE_INT,
    SUPPLEMENTAL_DOMAIN_PREFIXES,
    ArtifactLocator,
    ClosedValidationError,
    P1Integrity,
    canonicalize_jcs,
    decode_strict_base64,
    domain_jcs_sha256,
    jcs_sha256,
    loads_strict_json,
    p1_content_digest,
    p1_preimage,
    p1_signing_message,
    parse_iso_date,
    parse_timestamp_utc_micros,
    require_exact_keys,
    require_mapping,
    self_digest_jcs_sha256,
    sort_by_jcs_key,
    sort_utf8_strings,
    validate_currency_iso4217,
    validate_ed25519_key_id,
    validate_hex40,
    validate_iso_date,
    validate_non_empty_str,
    validate_opaque_ref,
    validate_sha256_prefixed,
    validate_timestamp_utc6,
    validate_timestamp_utc_seconds,
    validate_utf8_nfc,
)
from tools.governance import jcs as gov_jcs
from tools.governance import locator as gov_locator
from tools.governance import p1 as gov_p1


def test_contracts_package_reexports_public_api() -> None:
    assert issubclass(ClosedValidationError, ValueError)
    expected_exports = {
        "ADR_DATA_DOMAIN_PREFIXES",
        "ADR_P1_DOMAIN_PREFIXES",
        "ArtifactLocator",
        "ClosedValidationError",
        "MAX_JCS_SAFE_INT",
        "MIN_JCS_SAFE_INT",
        "P1Integrity",
        "SUPPLEMENTAL_DOMAIN_PREFIXES",
        "canonicalize_jcs",
        "decode_strict_base64",
        "domain_jcs_sha256",
        "jcs_sha256",
        "loads_strict_json",
        "p1_content_digest",
        "p1_preimage",
        "p1_signing_message",
        "parse_iso_date",
        "parse_timestamp_utc_micros",
        "require_exact_keys",
        "require_mapping",
        "self_digest_jcs_sha256",
        "sort_by_jcs_key",
        "sort_utf8_strings",
        "validate_currency_iso4217",
        "validate_ed25519_key_id",
        "validate_hex40",
        "validate_iso_date",
        "validate_non_empty_str",
        "validate_opaque_ref",
        "validate_sha256_prefixed",
        "validate_timestamp_utc6",
        "validate_timestamp_utc_seconds",
        "validate_utf8_nfc",
    }
    assert expected_exports.issubset(set(contracts.__all__))


def test_jcs_safe_integer_constants() -> None:
    assert MAX_JCS_SAFE_INT == (1 << 53) - 1 == 9007199254740991
    assert MIN_JCS_SAFE_INT == -((1 << 53) - 1) == -9007199254740991


def test_canonicalize_jcs_differential_parity_with_governance_jcs() -> None:
    all_c0_controls = "".join(chr(i) for i in range(0x20))
    vectors = [
        None,
        True,
        False,
        0,
        -0,
        -42,
        MAX_JCS_SAFE_INT,
        MIN_JCS_SAFE_INT,
        "",
        all_c0_controls + '"\\/€\x7f\U00010000\U0001f600',
        [True, False, None, 0, MAX_JCS_SAFE_INT, MIN_JCS_SAFE_INT, {"z": 1, "a": 2}],
        {
            "€": "euro-sign",
            "\U00010000": "u10000",
            " ": "space",
            "": "empty",
            "ÿ": "y-diaeresis",
            "\uff00": "fullwidth",
            "דּ": "hebrew-dalet-dagesh",
            "nested": {"\ue000": [1, 2, 3], "\U0001f600": {"b": False, "a": None}},
        },
    ]
    for vec in vectors:
        assert canonicalize_jcs(vec) == gov_jcs.canonicalize(vec)

    # Tuples and MappingProxyType serialize identically to list and dict.
    mapping_view = MappingProxyType({"b": (1, 2, ("x", None)), "a": True})
    assert canonicalize_jcs(mapping_view) == b'{"a":true,"b":[1,2,["x",null]]}'


def test_canonicalize_jcs_control_escapes_exact_rfc8785() -> None:
    assert (
        canonicalize_jcs('\x00\x01\x08\x09\x0a\x0c\x0d\x1f"\\/')
        == b'"\\u0000\\u0001\\b\\t\\n\\f\\r\\u001f\\"\\\\/"'
    )


def test_utf16be_jcs_key_order_vs_raw_utf8_comparator_divergence() -> None:
    # U+E000 (BMP: UTF-8 EE 80 80, UTF-16BE E0 00)
    # U+1F600 (Supplementary: UTF-8 F0 9F 98 80, UTF-16BE D8 3D DE 00)
    bmp_high = "\ue000"
    astral = "\U0001f600"

    # JCS object keys MUST sort by UTF-16BE code units: D83D < E000 -> astral first.
    jcs_bytes = canonicalize_jcs({bmp_high: 1, astral: 2})
    assert jcs_bytes == gov_jcs.canonicalize({bmp_high: 1, astral: 2})
    assert jcs_bytes == f'{{"{astral}":2,"{bmp_high}":1}}'.encode("utf-8")

    # Domain string sets MUST sort by raw UTF-8 bytes: EE < F0 -> bmp_high first.
    utf8_sorted = sort_utf8_strings([astral, bmp_high], field_name="items")
    assert utf8_sorted == (bmp_high, astral)


@pytest.mark.parametrize(
    "bad_value",
    [
        1.5,
        0.0,
        -0.0,
        float("nan"),
        float("inf"),
        float("-inf"),
        {"nested": [1.5]},
        MAX_JCS_SAFE_INT + 1,
        MIN_JCS_SAFE_INT - 1,
        1 << 64,
        -(1 << 64),
        "\ud800",
        "prefix\udfffsuffix",
        {"\ud800": 1},
        {"\udfff": 1},
        {1: "a"},
        {None: "a"},
        {True: "a"},
        {"set": {1, 2}},
        b"raw-bytes",
        object(),
    ],
)
def test_canonicalize_jcs_rejects_forbidden_values(bad_value: object) -> None:
    with pytest.raises(ClosedValidationError):
        canonicalize_jcs(bad_value)


def test_loads_strict_json_happy_path_str_and_bytes() -> None:
    raw_text = (
        f'{{"max":{MAX_JCS_SAFE_INT},"min":{MIN_JCS_SAFE_INT},'
        f'"pair":"\\ud83d\\ude00","arr":[true,false,null,"ok"]}}'
    )
    expected = {
        "max": MAX_JCS_SAFE_INT,
        "min": MIN_JCS_SAFE_INT,
        "pair": "\U0001f600",
        "arr": [True, False, None, "ok"],
    }
    assert loads_strict_json(raw_text) == expected
    assert loads_strict_json(raw_text.encode("utf-8")) == expected


@pytest.mark.parametrize(
    "bad_raw",
    [
        '{"a": 1, "a": 2}',
        '{"\\u0061": 1, "a": 2}',
        '{"nested": [{"k": 1, "k": 2}]}',
        "1.5",
        "0.0",
        "-0.0",
        "1e5",
        '{"x": 0.0}',
        "NaN",
        "Infinity",
        "-Infinity",
        '{"x": NaN}',
        str(MAX_JCS_SAFE_INT + 1),
        str(MIN_JCS_SAFE_INT - 1),
        "9" * 100,
        '{"s": "\\ud800"}',
        '{"s": "\\udfff"}',
        '{"\\ud800": 1}',
        '{"\\udfff": 1}',
        '{"s": "\ud800"}',
        b"\xff\xfe",
        b'{"s": "\x80"}',
        "{malformed",
        123,  # type: ignore[list-item]
        None,  # type: ignore[list-item]
    ],
)
def test_loads_strict_json_rejects_invalid_inputs(bad_raw: str | bytes) -> None:
    with pytest.raises(ClosedValidationError):
        loads_strict_json(bad_raw)


def test_sort_utf8_strings_validation_uniqueness_and_empty_policy() -> None:
    assert sort_utf8_strings(["b", "a", "c"], field_name="tags") == ("a", "b", "c")
    assert sort_utf8_strings([], field_name="tags", allow_empty=True) == ()

    with pytest.raises(ClosedValidationError):
        sort_utf8_strings([], field_name="tags", allow_empty=False)

    with pytest.raises(ClosedValidationError):
        sort_utf8_strings(["dup", "dup"], field_name="tags")

    # Bare str / bytes must not be silently iterated character-by-character.
    with pytest.raises(ClosedValidationError):
        sort_utf8_strings("abc", field_name="tags")
    with pytest.raises(ClosedValidationError):
        sort_utf8_strings(b"abc", field_name="tags")  # type: ignore[arg-type]

    # Non-NFC, NUL, empty element, lone surrogate, and custom validator failures reject.
    nfd = unicodedata.normalize("NFD", "é")
    for bad_elem in ("", "a\x00b", "\ud800", nfd):
        with pytest.raises(ClosedValidationError):
            sort_utf8_strings([bad_elem], field_name="tags")

    validated = sort_utf8_strings(
        ["USD", "BRL", "EUR"],
        field_name="currencies",
        validator=lambda s: validate_currency_iso4217(s, field_name="currencies"),
    )
    assert validated == ("BRL", "EUR", "USD")

    with pytest.raises(ClosedValidationError):
        sort_utf8_strings(
            ["USD", "brl"],
            field_name="currencies",
            validator=lambda s: validate_currency_iso4217(s, field_name="currencies"),
        )


def test_sort_by_jcs_key_orders_by_canonical_jcs_bytes() -> None:
    ordered = sort_by_jcs_key(
        [{"n": 10}, {"n": 2}, {"n": -1}],
        lambda r: r["n"],
    )
    # Canonical JCS bytes of numbers: b"-1" (0x2d), b"10" (0x31 0x30), b"2" (0x32)
    assert [r["n"] for r in ordered] == [-1, 10, 2]
    assert [canonicalize_jcs(r["n"]) for r in ordered] == sorted(
        [b"10", b"2", b"-1"]
    )

    composite = [
        {"id": "second", "k": {"b": 1, "a": 2}},
        {"id": "first", "k": {"a": 1, "b": 2}},
    ]
    assert [
        item["id"] for item in sort_by_jcs_key(composite, lambda r: r["k"])
    ] == ["first", "second"]

    with pytest.raises(ClosedValidationError):
        sort_by_jcs_key([{"x": 1.5}], lambda r: r["x"])


def test_three_layer_digest_invariants_and_governance_p1_parity(tmp_path: Path) -> None:
    priv = tmp_path / "ed25519.pem"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(priv)],
        check=True,
        capture_output=True,
    )
    raw32 = gov_p1.raw_public_key_from_pem(priv)
    key_id = gov_p1.key_id_for(raw32)

    registry_digest = "sha256:" + ("1" * 64)
    registry_locator = ArtifactLocator.from_digest(
        "smart_ads/key_authorization_registry/v1", registry_digest
    )
    unsigned_integrity = P1Integrity(
        key_id=key_id,
        key_registry_snapshot_locator=registry_locator,
    )
    assert not unsigned_integrity.is_signed

    schema = "smart_ads/private_registry_snapshot/v1"
    p1_prefix = ADR_P1_DOMAIN_PREFIXES[schema]
    data_prefix = ADR_DATA_DOMAIN_PREFIXES["row"]

    # Domain separation check on domain_jcs_sha256
    assert domain_jcs_sha256(data_prefix, {"a": 1}) != jcs_sha256({"a": 1})
    assert domain_jcs_sha256(data_prefix, {"a": 1}) != domain_jcs_sha256(
        ADR_DATA_DOMAIN_PREFIXES["logical_rows"], {"a": 1}
    )
    with pytest.raises(ClosedValidationError):
        domain_jcs_sha256("", {"a": 1})

    unsigned_envelope = {
        "$schema": schema,
        "tenant_id": "tenant:ibvi",
        "snapshot_epoch": 1,
        "snapshot_digest": "sha256:" + ("0" * 64),
        "integrity": unsigned_integrity.to_dict(),
    }

    # Layer 1: domain self-digest deletes snapshot_digest AND strips integrity.
    layer1_before = self_digest_jcs_sha256(
        unsigned_envelope,
        digest_member="snapshot_digest",
        domain_prefix=p1_prefix,
    )
    # Confirm digest_member was deleted (not blanked) and integrity was stripped.
    expected_reduced = {
        "$schema": schema,
        "tenant_id": "tenant:ibvi",
        "snapshot_epoch": 1,
    }
    assert layer1_before == domain_jcs_sha256(p1_prefix, expected_reduced)
    assert (
        self_digest_jcs_sha256(unsigned_envelope, digest_member="snapshot_digest")
        == jcs_sha256(expected_reduced)
    )
    assert (
        self_digest_jcs_sha256(
            unsigned_envelope,
            digest_member="snapshot_digest",
            strip_integrity=False,
        )
        != jcs_sha256(expected_reduced)
    )

    unsigned_envelope["snapshot_digest"] = layer1_before

    # Layer 2 before signing: exact parity with tools.governance.p1
    assert p1_preimage(unsigned_envelope) == gov_p1.preimage(unsigned_envelope)
    assert p1_content_digest(unsigned_envelope) == gov_p1.content_digest(
        unsigned_envelope
    )
    assert p1_signing_message(unsigned_envelope, p1_prefix) == gov_p1.message(
        unsigned_envelope, p1_prefix
    )

    # Sign with tools.governance.p1 (real Ed25519 via openssl)
    signed_envelope = gov_p1.sign_envelope(unsigned_envelope, p1_prefix, priv)
    gov_p1.verify_envelope(signed_envelope, p1_prefix, raw32)

    # Layer 1 MUST remain identical after P1 signing!
    layer1_after = self_digest_jcs_sha256(
        signed_envelope,
        digest_member="snapshot_digest",
        domain_prefix=p1_prefix,
    )
    assert layer1_after == layer1_before

    # Layer 2 MUST match tools.governance.p1 byte-for-byte after P1 signing, without mutating input!
    assert p1_preimage(signed_envelope) == gov_p1.preimage(signed_envelope)
    assert "content_digest" in signed_envelope["integrity"]
    assert "signature_base64" in signed_envelope["integrity"]
    layer2_digest = p1_content_digest(signed_envelope)
    assert layer2_digest == gov_p1.content_digest(signed_envelope)
    assert layer2_digest == signed_envelope["integrity"]["content_digest"]
    assert p1_signing_message(signed_envelope, p1_prefix) == gov_p1.message(
        signed_envelope, p1_prefix
    )

    # Parse signed integrity via P1Integrity.from_dict
    parsed_integrity = P1Integrity.from_dict(
        signed_envelope["integrity"], require_signed=True
    )
    assert parsed_integrity.is_signed
    assert parsed_integrity.to_dict() == signed_envelope["integrity"]

    # Layer 3: ArtifactLocator hashes the FULL canonical signed envelope bytes
    signed_bytes = canonicalize_jcs(signed_envelope)
    assert signed_bytes == gov_jcs.canonicalize(signed_envelope)
    locator = ArtifactLocator.for_canonical_bytes(schema, signed_bytes)
    assert locator.to_dict() == gov_locator.make_locator(schema, signed_bytes)
    assert locator.content_digest == "sha256:" + hashlib.sha256(signed_bytes).hexdigest()
    assert locator.content_digest != layer2_digest
    assert locator.content_digest != layer1_after


def test_p1_helpers_reject_malformed_envelopes() -> None:
    with pytest.raises(ClosedValidationError):
        p1_preimage({})
    with pytest.raises(ClosedValidationError):
        p1_preimage({"integrity": "not-a-mapping"})
    with pytest.raises(ClosedValidationError):
        p1_preimage("not-a-mapping")  # type: ignore[arg-type]
    with pytest.raises(ClosedValidationError):
        p1_signing_message({"integrity": {"key_id": "k"}}, "")


def test_artifact_locator_validation_and_roundtrip() -> None:
    digest = "sha256:" + ("a" * 64)
    loc = ArtifactLocator.from_digest("smart_ads/authorization_receipt/v1", digest)
    as_dict = loc.to_dict()
    assert as_dict == {
        "$schema": "smart_ads/artifact_locator/v1",
        "artifact_type": "smart_ads/authorization_receipt/v1",
        "content_digest": digest,
        "serialization": "rfc8785-json",
        "store_kind": "cell_immutable_object",
        "object_ref": f"cell-object:{digest}",
    }
    assert (
        ArtifactLocator.from_dict(
            as_dict, expected_type="smart_ads/authorization_receipt/v1"
        )
        == loc
    )

    # Missing member
    missing = dict(as_dict)
    del missing["store_kind"]
    with pytest.raises(ClosedValidationError):
        ArtifactLocator.from_dict(missing)

    # Extra member
    extra = dict(as_dict, git_sha="0" * 40)
    with pytest.raises(ClosedValidationError):
        ArtifactLocator.from_dict(extra)

    # Wrong $schema
    with pytest.raises(ClosedValidationError):
        ArtifactLocator.from_dict(dict(as_dict, **{"$schema": "smart_ads/other/v1"}))

    # Wrong expected_type
    with pytest.raises(ClosedValidationError):
        ArtifactLocator.from_dict(
            as_dict, expected_type="smart_ads/execution_receipt/v1"
        )

    # Mismatched or empty object_ref
    with pytest.raises(ClosedValidationError):
        ArtifactLocator.from_dict(
            dict(as_dict, object_ref="cell-object:sha256:" + ("b" * 64))
        )
    with pytest.raises(ClosedValidationError):
        ArtifactLocator(
            artifact_type="smart_ads/authorization_receipt/v1",
            content_digest=digest,
        )

    # Invalid artifact_type, serialization, store_kind, content_digest, non-bytes
    for bad_type in (
        "",
        "authorization_receipt/v1",
        "smart_ads/Auth/v1",
        "smart_ads/auth/v0",
        "smart_ads/auth/v01",
    ):
        with pytest.raises(ClosedValidationError):
            ArtifactLocator.from_digest(bad_type, digest)

    with pytest.raises(ClosedValidationError):
        ArtifactLocator(
            artifact_type="smart_ads/authorization_receipt/v1",
            content_digest=digest,
            serialization="json",
            object_ref=f"cell-object:{digest}",
        )
    with pytest.raises(ClosedValidationError):
        ArtifactLocator(
            artifact_type="smart_ads/authorization_receipt/v1",
            content_digest=digest,
            store_kind="s3",
            object_ref=f"cell-object:{digest}",
        )
    with pytest.raises(ClosedValidationError):
        ArtifactLocator.for_canonical_bytes(
            "smart_ads/authorization_receipt/v1",
            "{}",  # type: ignore[arg-type]
        )


def test_p1_integrity_and_strict_base64_rejections() -> None:
    reg_loc = ArtifactLocator.from_digest(
        "smart_ads/key_authorization_registry/v1", "sha256:" + ("2" * 64)
    )
    wrong_loc = ArtifactLocator.from_digest(
        "smart_ads/authorization_receipt/v1", "sha256:" + ("2" * 64)
    )
    key_id = "key:ed25519:" + ("f" * 64)
    valid_digest = "sha256:" + ("3" * 64)
    valid_sig_b64 = base64.b64encode(b"\xab" * 64).decode("ascii")

    unsigned = P1Integrity(key_id=key_id, key_registry_snapshot_locator=reg_loc)
    assert P1Integrity.from_dict(unsigned.to_dict(), require_signed=False) == unsigned
    with pytest.raises(ClosedValidationError):
        P1Integrity.from_dict(unsigned.to_dict(), require_signed=True)

    # Partial signature states must reject
    with pytest.raises(ClosedValidationError):
        P1Integrity(
            key_id=key_id,
            key_registry_snapshot_locator=reg_loc,
            content_digest=valid_digest,
            signature_base64=None,
        )
    with pytest.raises(ClosedValidationError):
        P1Integrity(
            key_id=key_id,
            key_registry_snapshot_locator=reg_loc,
            content_digest=None,
            signature_base64=valid_sig_b64,
        )

    # Null/blanked signature fields in 4-key dict must reject
    with pytest.raises(ClosedValidationError):
        P1Integrity.from_dict(
            {
                "key_id": key_id,
                "key_registry_snapshot_locator": reg_loc.to_dict(),
                "content_digest": None,
                "signature_base64": None,
            }
        )

    # Wrong registry locator artifact_type must reject
    with pytest.raises(ClosedValidationError):
        P1Integrity(key_id=key_id, key_registry_snapshot_locator=wrong_loc)

    # Base64url ('-' / '_'), unpadded base64, whitespace, and wrong decoded length must reject
    raw64_with_62_63 = bytes([0xFB, 0xFF]) * 32
    urlsafe_sig = base64.urlsafe_b64encode(raw64_with_62_63).decode("ascii")
    assert "-" in urlsafe_sig or "_" in urlsafe_sig
    unpadded_sig = valid_sig_b64.rstrip("=")
    short_sig = base64.b64encode(b"\x00" * 63).decode("ascii")
    long_sig = base64.b64encode(b"\x00" * 65).decode("ascii")

    for bad_sig in (urlsafe_sig, unpadded_sig, short_sig, long_sig, " " + valid_sig_b64):
        with pytest.raises(ClosedValidationError):
            P1Integrity(
                key_id=key_id,
                key_registry_snapshot_locator=reg_loc,
                content_digest=valid_digest,
                signature_base64=bad_sig,
            )

    assert (
        decode_strict_base64(valid_sig_b64, field_name="sig", expected_len=64)
        == b"\xab" * 64
    )
    for bad_b64 in (123, "A" * 42 + "-_", "AAAA=", "AAA"):
        with pytest.raises(ClosedValidationError):
            decode_strict_base64(bad_b64, field_name="sig")
    for bad_len in (True, -1):
        with pytest.raises(ClosedValidationError):
            decode_strict_base64(
                "AQ==",
                field_name="sig",
                expected_len=bad_len,  # type: ignore[arg-type]
            )
    with pytest.raises(ClosedValidationError):
        loads_strict_json("[" * 2000 + "]" * 2000)


def test_domain_prefix_tables_immutable_and_pairwise_disjoint() -> None:
    tables = (
        ADR_P1_DOMAIN_PREFIXES,
        ADR_DATA_DOMAIN_PREFIXES,
        SUPPLEMENTAL_DOMAIN_PREFIXES,
    )
    assert len(ADR_P1_DOMAIN_PREFIXES) == 22
    assert len(ADR_DATA_DOMAIN_PREFIXES) == 7
    assert len(SUPPLEMENTAL_DOMAIN_PREFIXES) == 2

    all_values: list[str] = []
    for tbl in tables:
        assert isinstance(tbl, MappingProxyType)
        with pytest.raises(TypeError):
            tbl["mutated"] = "SMART-ADS:MUTATED:V1\n"  # type: ignore[index]
        for key, prefix in tbl.items():
            assert isinstance(key, str) and key
            assert prefix.startswith("SMART-ADS:") and prefix.endswith(":V1\n")
            all_values.append(prefix)

    # All 31 prefix values across the 3 tables are pairwise disjoint
    assert len(all_values) == 31
    assert len(set(all_values)) == 31


def test_mapping_and_scalar_validators() -> None:
    assert require_mapping({"a": 1}, label="obj") == {"a": 1}
    assert require_exact_keys({"a": 1, "b": 2}, {"a", "b"}, label="obj") == {
        "a": 1,
        "b": 2,
    }

    for non_map in (None, True, 42, "str", [1, 2], {1: "int-key"}):
        with pytest.raises(ClosedValidationError):
            require_mapping(non_map, label="obj")

    with pytest.raises(ClosedValidationError, match="missing"):
        require_exact_keys({"a": 1}, {"a", "b"}, label="obj")
    with pytest.raises(ClosedValidationError, match="extra"):
        require_exact_keys({"a": 1, "b": 2, "c": 3}, {"a", "b"}, label="obj")

    assert validate_non_empty_str("hello", field_name="f") == "hello"
    assert validate_utf8_nfc("", field_name="f", allow_empty=True) == ""
    assert validate_utf8_nfc(" ", field_name="f", allow_empty=False) == " "

    nfd = unicodedata.normalize("NFD", "ã")
    for bad_non_empty in (None, 1, "", "   ", "\t\n", "a\x00b", "\ud800", nfd):
        with pytest.raises(ClosedValidationError):
            validate_non_empty_str(bad_non_empty, field_name="f")

    for bad_utf8 in (None, 1, "", "a\x00b", "\udfff", nfd):
        with pytest.raises(ClosedValidationError):
            validate_utf8_nfc(bad_utf8, field_name="f", allow_empty=False)

    sha = "sha256:" + ("0123456789abcdef" * 4)
    assert validate_sha256_prefixed(sha, field_name="d") == sha
    for bad_sha in (
        "sha256:" + ("A" * 64),
        "sha256:" + ("a" * 63),
        sha + "\n",
        "md5:" + ("a" * 64),
        123,
    ):
        with pytest.raises(ClosedValidationError):
            validate_sha256_prefixed(bad_sha, field_name="d")

    hex40 = "0123456789abcdef" * 2 + "01234567"
    assert validate_hex40(hex40, field_name="commit") == hex40
    for bad_hex in (hex40.upper(), hex40[:-1], hex40 + "\n", None):
        with pytest.raises(ClosedValidationError):
            validate_hex40(bad_hex, field_name="commit")

    kid = "key:ed25519:" + ("a" * 64)
    assert validate_ed25519_key_id(kid) == kid
    for bad_kid in ("key:ed25519:" + ("A" * 64), "key:rsa:" + ("a" * 64), kid + "\n"):
        with pytest.raises(ClosedValidationError):
            validate_ed25519_key_id(bad_kid)

    assert (
        validate_opaque_ref(
            "principal:operator-authorized_1.v2:sub",
            field_name="ref",
            expected_prefix="principal",
        )
        == "principal:operator-authorized_1.v2:sub"
    )
    with pytest.raises(ClosedValidationError):
        validate_opaque_ref(
            "principal:operator", field_name="ref", expected_prefix="tenant"
        )
    for bad_ref in (
        "",
        "Principal:op",
        "1bad:op",
        "principal:",
        "principal:has space",
        "principal:has\x00nul",
        "principal:é",
        "principal:op\n",
    ):
        with pytest.raises(ClosedValidationError):
            validate_opaque_ref(bad_ref, field_name="ref")

    assert validate_currency_iso4217("BRL") == "BRL"
    for bad_ccy in ("brl", "BR", "BRLX", "BR1", "BRL\n", None):
        with pytest.raises(ClosedValidationError):
            validate_currency_iso4217(bad_ccy)


def test_calendar_dates_and_utc_timestamps() -> None:
    assert validate_iso_date("2024-02-29", field_name="d") == "2024-02-29"
    assert validate_iso_date("2000-02-29", field_name="d") == "2000-02-29"
    assert parse_iso_date("2026-11-11", field_name="d") == date(2026, 11, 11)

    for bad_date in (
        "2026-02-29",
        "1900-02-29",
        "2026-13-01",
        "2026-00-01",
        "2026-04-31",
        "0000-01-01",
        "2026-1-01",
        "٢٠٢٦-٠١-٠١",
        "2026-11-11\n",
        20261111,
    ):
        with pytest.raises(ClosedValidationError):
            validate_iso_date(bad_date, field_name="d")
        with pytest.raises(ClosedValidationError):
            parse_iso_date(bad_date, field_name="d")

    ts6 = "2026-11-11T03:00:00.500000Z"
    ts_sec = "2026-11-11T03:00:00Z"
    assert validate_timestamp_utc6(ts6, field_name="ts") == ts6
    assert validate_timestamp_utc_seconds(ts_sec, field_name="ts") == ts_sec

    for bad_ts6 in (
        ts_sec,
        "2026-11-11T03:00:00.500Z",
        "2026-11-11T03:00:00.5000000Z",
        "2026-12-31T23:59:60.000000Z",  # leap second rejected
        "2026-11-11T24:00:00.000000Z",
        "2026-11-11T03:60:00.000000Z",
        "2026-02-29T03:00:00.000000Z",
        "2026-11-11T03:00:00.500000+00:00",
        "2026-11-11 03:00:00.500000Z",
        "2026-11-11T03:00:00.500000z",
        ts6 + "\n",
    ):
        with pytest.raises(ClosedValidationError):
            validate_timestamp_utc6(bad_ts6, field_name="ts")

    for bad_ts_sec in (
        ts6,
        "2026-12-31T23:59:60Z",  # leap second rejected
        "2026-11-11T24:00:00Z",
        "2026-02-29T00:00:00Z",
        "2026-11-11T03:00:00+00:00",
        ts_sec + "\n",
    ):
        with pytest.raises(ClosedValidationError):
            validate_timestamp_utc_seconds(bad_ts_sec, field_name="ts")

    # Pure arithmetic epoch microsecond conversion
    assert parse_timestamp_utc_micros("1970-01-01T00:00:00.000000Z") == 0
    assert parse_timestamp_utc_micros("1969-12-31T23:59:59.999999Z") == -1
    assert parse_timestamp_utc_micros("1969-12-31T23:59:59.000000Z") == -1_000_000
    assert (
        parse_timestamp_utc_micros(
            "1969-12-31T23:59:59Z", allow_whole_seconds=True
        )
        == -1_000_000
    )
    assert parse_timestamp_utc_micros(ts6) == 1_794_366_000_500_000
    assert (
        parse_timestamp_utc_micros(ts_sec, allow_whole_seconds=True)
        == 1_794_366_000_000_000
    )
    assert (
        parse_timestamp_utc_micros(ts6, allow_whole_seconds=True)
        == 1_794_366_000_500_000
    )
    with pytest.raises(ClosedValidationError):
        parse_timestamp_utc_micros(ts_sec, allow_whole_seconds=False)
