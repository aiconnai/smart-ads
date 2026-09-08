"""Strict public-authority primitives for the proposed D4 runtime contract.

No key loading, signing, network, or authority installation lives here.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import re
from typing import Protocol

from tools.governance import p1
from tools.governance.decomposition_common import digest, exact_fields, timestamp
from tools.governance.jcs import canonicalize
from tools.governance.locator import make_locator

PREFIX = 'smart_ads/'
REGISTRY = PREFIX + 'key_authorization_registry/v1'
INVENTORY = PREFIX + 'artifact_contract_inventory/v1'
CHECKPOINT = PREFIX + 'key_state_anti_rollback_checkpoint/v1'
HEAD = PREFIX + 'current_key_state_head/v1'
STATE = PREFIX + 'current_key_state/v1'
MANIFEST = PREFIX + 'decomposition_manifest/v1'
INTEGRITY = {'key_id', 'key_registry_snapshot_locator', 'content_digest', 'signature_base64'}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError('admission: ' + message)


def integer(value: object, minimum: int = 1) -> int:
    require(type(value) is int and value >= minimum, 'invalid monotonic integer')
    return value


def hash_value(value: object) -> str:
    require(isinstance(value, str) and re.fullmatch(r'sha256:[0-9a-f]{64}', value) is not None,
            'invalid digest')
    return value


def public_key(value: dict) -> bytes:
    try:
        raw = base64.b64decode(value['public_key_base64'], validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError('admission: invalid public key encoding') from exc
    require(len(raw) == 32 and base64.b64encode(raw).decode() == value['public_key_base64'],
            'public key must be canonical 32-byte Ed25519')
    require(digest(raw) == value['public_key_sha256'], 'public key hash mismatch')
    return raw


def validity(value: dict, instant: str) -> None:
    exact_fields(value, {'from', 'until'}, 'validity')
    start, end, when = timestamp(value['from']), timestamp(value['until']), timestamp(instant)
    require(start <= when < end, 'outside validity interval')


@dataclass(frozen=True)
class ClockInterval:
    """Authenticated bounds supplied by the trusted runtime, never a request."""
    lower_utc: str
    upper_utc: str

    def bounds(self):
        lo, hi = timestamp(self.lower_utc), timestamp(self.upper_utc)
        require(lo <= hi, 'malformed authenticated clock interval')
        return lo, hi


def fresh(value: dict, clock: ClockInterval) -> None:
    require(type(clock) is ClockInterval, 'authenticated clock unavailable')
    lo, hi = clock.bounds()
    start, end = timestamp(value['issued_at_utc']), timestamp(value['valid_until_utc'])
    age = integer(value['maximum_age_seconds'])
    require(start <= lo <= hi <= end and (hi - start).total_seconds() <= age,
            'stale, future, or uncertain authority proof')


@dataclass(frozen=True)
class Floor:
    epoch: int
    head_digest: str | None
    version: str

    def validate(self):
        integer(self.epoch, 0)
        require(isinstance(self.version, str) and bool(self.version), 'missing CAS version')
        if self.epoch == 0:
            require(self.head_digest is None, 'genesis floor must have null digest')
        else:
            hash_value(self.head_digest)


class ProtectedRuntime(Protocol):
    """Trusted integration boundary. Implementations must be protected and linearizable.

    A caller cannot supply these values via manifest/CLI params. The atomic CAS
    must also assert the authoritative head still equals expected_head_locator.
    This is a state write, not a read-only probe. No production adapter is shipped.
    """
    def configuration_bytes(self) -> bytes: ...
    def installation_authority(self) -> str: ...
    def authenticated_clock(self) -> ClockInterval: ...
    def read_head(self, register: str) -> dict: ...
    def observe_head_and_clock(self, register: str) -> tuple[dict, ClockInterval]:
        """One coherent final head/clock observation after all crypto and store I/O."""
        ...
    def read_checkpoint(self, register: str) -> tuple[dict, Floor]: ...
    def compare_and_swap(self, register: str, expected: Floor, new: Floor,
                         head_register: str, expected_head_locator: dict) -> bool: ...


@dataclass(frozen=True)
class InstallationPins:
    """Application-provisioned, out-of-band pins; not deserialized from requests."""
    configuration_digest: str
    installation_authority: str
    cell_id: str
    head_register: str
    checkpoint_register: str
    owner_principal: str
    owner_tenant: str


def load_object(store, locator: dict, schema: str) -> dict:
    value = store.get(locator)
    require(isinstance(value, dict) and value.get('$schema') == schema, 'typed locator schema mismatch')
    require(canonicalize(make_locator(schema, canonicalize(value))) == canonicalize(locator),
            'locator must address canonical envelope bytes')
    exact_fields(value.get('integrity'), INTEGRITY, 'P1 integrity')
    return value


def signature(value: dict, profile: dict, raw: bytes) -> None:
    require(value['$schema'] == profile['schema'], 'signature profile mismatch')
    p1.verify_envelope(value, profile['domain_prefix'], raw)


def registry(store, locator, config: dict, profiles: dict) -> dict:
    value = load_object(store, locator, REGISTRY)
    exact_fields(value, {'$schema', 'trust_anchor_id', 'epoch', 'issued_at_utc', 'entries', 'integrity'}, 'registry')
    require(value['trust_anchor_id'] == config['trust_anchor_id'], 'registry anchor changed')
    require(value['integrity']['key_registry_snapshot_locator'] is None, 'registry must use external anchor')
    integer(value['epoch'])
    validity(config['validity'], value['issued_at_utc'])
    signature(value, profiles[REGISTRY], public_key(config))
    require(isinstance(value['entries'], list) and bool(value['entries']), 'empty registry')
    ids, keys = set(), set()
    for entry in value['entries']:
        exact_fields(entry, {'key_id', 'public_key_base64', 'public_key_sha256', 'principal', 'tenant',
                             'role', 'validity', 'lifecycle_state', 'allowed_actions'}, 'registry entry')
        raw = public_key(entry)
        require(entry['key_id'] == p1.key_id_for(raw), 'key ID mismatch')
        require(entry['key_id'] not in ids and raw not in keys, 'duplicate registry identity')
        ids.add(entry['key_id'])
        keys.add(raw)
        for field in ('principal', 'tenant', 'role'):
            require(isinstance(entry[field], str) and bool(entry[field].strip()), 'missing registry identity')
        exact_fields(entry['validity'], {'from', 'until'}, 'key validity')
        require(timestamp(entry['validity']['from']) < timestamp(entry['validity']['until']), 'invalid key validity')
        require(entry['lifecycle_state'] in ('active', 'revoked', 'expired'), 'unknown key lifecycle')
        require(isinstance(entry['allowed_actions'], list), 'actions must be a list')
        pairs = set()
        for pair in entry['allowed_actions']:
            exact_fields(pair, {'schema', 'action'}, 'allowed action')
            require(all(isinstance(v, str) and v.strip() for v in pair.values()), 'malformed action')
            token = canonicalize(pair)
            require(token not in pairs, 'duplicate action')
            pairs.add(token)
    return value


def historical(store, value: dict, config: dict, profiles: dict, action: str,
               role: str, issued: str) -> tuple[dict, dict]:
    reg = registry(store, value['integrity']['key_registry_snapshot_locator'], config, profiles)
    require(timestamp(reg['issued_at_utc']) <= timestamp(issued), 'registry issued after artifact')
    matches = [e for e in reg['entries'] if e['key_id'] == value['integrity']['key_id']]
    require(len(matches) == 1, 'signer absent from historical registry')
    entry = matches[0]
    require(entry['role'] == role and entry['lifecycle_state'] == 'active', 'historical role/lifecycle mismatch')
    require({'schema': value['$schema'], 'action': action} in entry['allowed_actions'], 'exact action missing')
    validity(entry['validity'], issued)
    signature(value, profiles[value['$schema']], public_key(entry))
    return entry, reg
