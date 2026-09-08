"""Closed scalar checks shared by the local decomposition draft implementation."""
from __future__ import annotations

from datetime import datetime
import hashlib
import re

from tools.governance.jcs import canonicalize


def digest(value: bytes) -> str:
    return 'sha256:' + hashlib.sha256(value).hexdigest()


def json_digest(value: object) -> str:
    return digest(canonicalize(value))


def exact_fields(value: object, fields: set[str], label: str) -> None:
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError(f'{label}: expected exactly {sorted(fields)}')


def nonempty(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or '\x00' in value:
        raise ValueError(f'{label}: expected non-empty string')
    return value


def string_list(value: object, label: str) -> list[str]:
    if not isinstance(value, list):
        raise ValueError(f'{label}: expected list')
    for x in value:
        nonempty(x, label)
    if len(value) != len(set(value)):
        raise ValueError(f'{label}: duplicate values')
    return value


def source_path(value: object) -> str:
    name = nonempty(value, 'path')
    if (name.startswith('/') or '\\' in name or ':' in name or '%' in name
            or any(ord(c) < 32 for c in name)
            or any(p in ('', '.', '..') for p in name.split('/'))):
        raise ValueError(f'path: not normalized repository-relative: {name!r}')
    return name


def timestamp(value: object) -> datetime:
    if not isinstance(value, str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', value):
        raise ValueError('timestamp: require whole-second UTC YYYY-MM-DDTHH:MM:SSZ')
    try:
        return datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError as exc:
        raise ValueError('timestamp: invalid calendar value') from exc
