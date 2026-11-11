"""Closed scalar, mapping, and UTC calendar grammars (ADR-0001 §6.4)."""
from __future__ import annotations

from collections.abc import Mapping
import datetime
import re
from typing import AbstractSet, Any, Final
import unicodedata

_SHA256_PREFIXED_RE: Final[re.Pattern[str]] = re.compile(r"\Asha256:[0-9a-f]{64}\Z")
_HEX40_RE: Final[re.Pattern[str]] = re.compile(r"\A[0-9a-f]{40}\Z")
_ED25519_KEY_ID_RE: Final[re.Pattern[str]] = re.compile(
    r"\Akey:ed25519:[0-9a-f]{64}\Z"
)
_OPAQUE_REF_RE: Final[re.Pattern[str]] = re.compile(
    r"\A[a-z][a-z0-9_]*:[A-Za-z0-9._:-]+\Z"
)
_CURRENCY_ISO4217_RE: Final[re.Pattern[str]] = re.compile(r"\A[A-Z]{3}\Z")
_ISO_DATE_RE: Final[re.Pattern[str]] = re.compile(
    r"\A([0-9]{4})-([0-9]{2})-([0-9]{2})\Z"
)
_TIMESTAMP_UTC6_RE: Final[re.Pattern[str]] = re.compile(
    r"\A([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})\.([0-9]{6})Z\Z"
)
_TIMESTAMP_UTC_SECONDS_RE: Final[re.Pattern[str]] = re.compile(
    r"\A([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z\Z"
)
_UNIX_EPOCH_DATE: Final[datetime.date] = datetime.date(1970, 1, 1)


class ClosedValidationError(ValueError):
    """Raised on any closed-contract, grammar, or schema violation across smart_ads."""


def _has_surrogate(value: str) -> bool:
    return any(0xD800 <= ord(ch) <= 0xDFFF for ch in value)


def require_mapping(value: object, *, label: str) -> Mapping[str, Any]:
    """Require `value` to be a string-keyed Mapping."""
    if not isinstance(value, Mapping):
        raise ClosedValidationError(
            f"{label}: expected JSON object mapping, got {type(value).__name__}"
        )
    for key in value:
        if not isinstance(key, str):
            raise ClosedValidationError(
                f"{label}: mapping keys must be str, got {type(key).__name__}"
            )
    return value


def require_exact_keys(
    mapping: object,
    expected: AbstractSet[str],
    *,
    label: str,
) -> Mapping[str, Any]:
    """Require `mapping` to be a Mapping whose keys match `expected` exactly."""
    checked = require_mapping(mapping, label=label)
    actual_keys = set(checked.keys())
    expected_keys = set(expected)
    if actual_keys != expected_keys:
        missing = sorted(expected_keys - actual_keys)
        extra = sorted(actual_keys - expected_keys)
        raise ClosedValidationError(
            f"{label}: closed object key mismatch "
            f"(missing={missing}, extra={extra})"
        )
    return checked


def validate_utf8_nfc(
    value: object,
    *,
    field_name: str,
    allow_empty: bool = False,
) -> str:
    """Validate a UTF-8 scalar string in Unicode NFC without NUL or surrogates."""
    if not isinstance(allow_empty, bool):
        raise ClosedValidationError(
            f"{field_name}: allow_empty must be bool, got {type(allow_empty).__name__}"
        )
    if not isinstance(value, str):
        raise ClosedValidationError(
            f"{field_name}: expected str, got {type(value).__name__}"
        )
    if not allow_empty and len(value) == 0:
        raise ClosedValidationError(f"{field_name}: string must not be empty")
    if "\x00" in value:
        raise ClosedValidationError(f"{field_name}: NUL byte is forbidden")
    if _has_surrogate(value):
        raise ClosedValidationError(
            f"{field_name}: lone UTF-16 surrogates are forbidden"
        )
    if unicodedata.normalize("NFC", value) != value:
        raise ClosedValidationError(
            f"{field_name}: string must be normalized to Unicode NFC"
        )
    return value


def validate_non_empty_str(value: object, *, field_name: str) -> str:
    """Validate a non-empty, non-whitespace-only NFC string without NUL or surrogates."""
    checked = validate_utf8_nfc(value, field_name=field_name, allow_empty=False)
    if not checked.strip():
        raise ClosedValidationError(
            f"{field_name}: string must not be whitespace-only"
        )
    return checked


def validate_sha256_prefixed(value: object, *, field_name: str) -> str:
    """Validate `'sha256:' + 64 lowercase hex characters`."""
    if not isinstance(value, str) or not _SHA256_PREFIXED_RE.fullmatch(value):
        raise ClosedValidationError(
            f"{field_name}: expected 'sha256:<64_lowercase_hex>'"
        )
    return value


def validate_hex40(value: object, *, field_name: str) -> str:
    """Validate 40 lowercase hexadecimal characters (e.g., Git SHA-1 OID)."""
    if not isinstance(value, str) or not _HEX40_RE.fullmatch(value):
        raise ClosedValidationError(
            f"{field_name}: expected 40 lowercase hex characters"
        )
    return value


def validate_ed25519_key_id(value: object, *, field_name: str = "key_id") -> str:
    """Validate `'key:ed25519:' + 64 lowercase hex characters`."""
    if not isinstance(value, str) or not _ED25519_KEY_ID_RE.fullmatch(value):
        raise ClosedValidationError(
            f"{field_name}: expected 'key:ed25519:<64_lowercase_hex>'"
        )
    return value


def validate_opaque_ref(
    value: object,
    *,
    field_name: str,
    expected_prefix: str | None = None,
) -> str:
    """Validate `opaque_ref` grammar `^[a-z][a-z0-9_]*:[A-Za-z0-9._:-]+$` (ADR-0001 §6.4)."""
    checked = validate_utf8_nfc(value, field_name=field_name, allow_empty=False)
    if not _OPAQUE_REF_RE.fullmatch(checked):
        raise ClosedValidationError(
            f"{field_name}: invalid opaque_ref {checked!r}"
        )
    if expected_prefix is not None:
        if not isinstance(expected_prefix, str) or not expected_prefix:
            raise ClosedValidationError(
                f"{field_name}: expected_prefix must be a non-empty str"
            )
        prefix = checked.split(":", 1)[0]
        if prefix != expected_prefix:
            raise ClosedValidationError(
                f"{field_name}: expected opaque_ref prefix {expected_prefix!r}, got {prefix!r}"
            )
    return checked


def validate_currency_iso4217(value: object, *, field_name: str = "currency") -> str:
    """Validate uppercase 3-letter ISO 4217 currency code `^[A-Z]{3}$`."""
    if not isinstance(value, str) or not _CURRENCY_ISO4217_RE.fullmatch(value):
        raise ClosedValidationError(
            f"{field_name}: expected 3-letter uppercase ISO 4217 code"
        )
    return value


def _build_calendar_date(
    year: int,
    month: int,
    day: int,
    *,
    field_name: str,
) -> datetime.date:
    try:
        return datetime.date(year, month, day)
    except ValueError as exc:
        raise ClosedValidationError(
            f"{field_name}: invalid proleptic Gregorian date "
            f"{year:04d}-{month:02d}-{day:02d}"
        ) from exc


def _validate_utc_hms(
    hour: int,
    minute: int,
    second: int,
    *,
    field_name: str,
) -> None:
    if not (0 <= hour <= 23 and 0 <= minute <= 59 and 0 <= second <= 59):
        raise ClosedValidationError(
            f"{field_name}: invalid UTC time {hour:02d}:{minute:02d}:{second:02d} "
            "(leap second :60 is forbidden)"
        )


def parse_iso_date(value: object, *, field_name: str) -> datetime.date:
    """Validate `YYYY-MM-DD` and return a `datetime.date`."""
    if not isinstance(value, str):
        raise ClosedValidationError(
            f"{field_name}: expected ISO date str, got {type(value).__name__}"
        )
    match = _ISO_DATE_RE.fullmatch(value)
    if match is None:
        raise ClosedValidationError(
            f"{field_name}: expected YYYY-MM-DD ASCII date, got {value!r}"
        )
    year, month, day = (
        int(match.group(1)),
        int(match.group(2)),
        int(match.group(3)),
    )
    return _build_calendar_date(year, month, day, field_name=field_name)


def validate_iso_date(value: object, *, field_name: str) -> str:
    """Validate `YYYY-MM-DD` proleptic Gregorian calendar date and return the string."""
    parse_iso_date(value, field_name=field_name)
    assert isinstance(value, str)
    return value


def validate_timestamp_utc6(value: object, *, field_name: str) -> str:
    """Validate fixed-width `YYYY-MM-DDTHH:MM:SS.ffffffZ` UTC timestamp (ADR-0001 §6.4)."""
    if not isinstance(value, str):
        raise ClosedValidationError(
            f"{field_name}: expected UTC microsecond timestamp str, got {type(value).__name__}"
        )
    match = _TIMESTAMP_UTC6_RE.fullmatch(value)
    if match is None:
        raise ClosedValidationError(
            f"{field_name}: expected YYYY-MM-DDTHH:MM:SS.ffffffZ, got {value!r}"
        )
    year, month, day, hour, minute, second = (
        int(match.group(1)),
        int(match.group(2)),
        int(match.group(3)),
        int(match.group(4)),
        int(match.group(5)),
        int(match.group(6)),
    )
    _build_calendar_date(year, month, day, field_name=field_name)
    _validate_utc_hms(hour, minute, second, field_name=field_name)
    return value


def validate_timestamp_utc_seconds(value: object, *, field_name: str) -> str:
    """Validate whole-second `YYYY-MM-DDTHH:MM:SSZ` UTC timestamp."""
    if not isinstance(value, str):
        raise ClosedValidationError(
            f"{field_name}: expected whole-second UTC timestamp str, got {type(value).__name__}"
        )
    match = _TIMESTAMP_UTC_SECONDS_RE.fullmatch(value)
    if match is None:
        raise ClosedValidationError(
            f"{field_name}: expected YYYY-MM-DDTHH:MM:SSZ, got {value!r}"
        )
    year, month, day, hour, minute, second = (
        int(match.group(1)),
        int(match.group(2)),
        int(match.group(3)),
        int(match.group(4)),
        int(match.group(5)),
        int(match.group(6)),
    )
    _build_calendar_date(year, month, day, field_name=field_name)
    _validate_utc_hms(hour, minute, second, field_name=field_name)
    return value


def parse_timestamp_utc_micros(
    value: object,
    *,
    field_name: str = "timestamp",
    allow_whole_seconds: bool = False,
) -> int:
    """Convert canonical UTC timestamp to integer microseconds since Unix epoch."""
    if not isinstance(allow_whole_seconds, bool):
        raise ClosedValidationError(
            f"{field_name}: allow_whole_seconds must be bool, got {type(allow_whole_seconds).__name__}"
        )
    if not isinstance(value, str):
        raise ClosedValidationError(
            f"{field_name}: expected UTC timestamp str, got {type(value).__name__}"
        )
    match6 = _TIMESTAMP_UTC6_RE.fullmatch(value)
    if match6 is not None:
        year, month, day, hour, minute, second, micros = (
            int(match6.group(1)),
            int(match6.group(2)),
            int(match6.group(3)),
            int(match6.group(4)),
            int(match6.group(5)),
            int(match6.group(6)),
            int(match6.group(7)),
        )
    elif allow_whole_seconds:
        match_sec = _TIMESTAMP_UTC_SECONDS_RE.fullmatch(value)
        if match_sec is None:
            raise ClosedValidationError(
                f"{field_name}: expected YYYY-MM-DDTHH:MM:SS(.ffffff)Z, got {value!r}"
            )
        year, month, day, hour, minute, second = (
            int(match_sec.group(1)),
            int(match_sec.group(2)),
            int(match_sec.group(3)),
            int(match_sec.group(4)),
            int(match_sec.group(5)),
            int(match_sec.group(6)),
        )
        micros = 0
    else:
        raise ClosedValidationError(
            f"{field_name}: expected YYYY-MM-DDTHH:MM:SS.ffffffZ, got {value!r}"
        )

    cal_date = _build_calendar_date(year, month, day, field_name=field_name)
    _validate_utc_hms(hour, minute, second, field_name=field_name)
    days = (cal_date - _UNIX_EPOCH_DATE).days
    return (((days * 24 + hour) * 60 + minute) * 60 + second) * 1_000_000 + micros


__all__ = [
    "ClosedValidationError",
    "parse_iso_date",
    "parse_timestamp_utc_micros",
    "require_exact_keys",
    "require_mapping",
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
]
