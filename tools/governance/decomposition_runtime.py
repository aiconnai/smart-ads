"""Executable, unratified D4 verifier and public-authority primitives.

Only the six named predicates are implemented; listing 116 profiles does not
implement all 116 semantic verifiers. Successful inspection authorizes no effect.
No production ProtectedRuntime adapter is shipped.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Protocol

from tools.governance import decomposition as dec, p1
from tools.governance.decomposition_admission import STEPS, profile_proposals
from tools.governance.decomposition_governance import historical_prerequisites
from tools.governance.jcs import canonicalize, loads_strict
from tools.governance.locator import (
    digest,
    exact_fields,
    make_locator,
    timestamp,
    validate_locator,
)

PREFIX = 'smart_ads/'
REGISTRY = PREFIX + 'key_authorization_registry/v1'
INVENTORY = PREFIX + 'artifact_contract_inventory/v1'
CHECKPOINT = PREFIX + 'key_state_anti_rollback_checkpoint/v1'
HEAD = PREFIX + 'current_key_state_head/v1'
STATE = PREFIX + 'current_key_state/v1'
MANIFEST = PREFIX + 'decomposition_manifest/v1'
INTEGRITY = {'key_id', 'key_registry_snapshot_locator', 'content_digest', 'signature_base64'}

TIMES = {'issued_at_utc', 'valid_until_utc', 'maximum_age_seconds'}
COMMON = {'$schema', 'trust_anchor_id', 'cell_id', 'integrity'}
CONFIG = {
    '$schema', 'trust_anchor_id', 'public_key_base64', 'public_key_sha256', 'validity',
    'allowed_registry_artifact_types', 'inventory_bootstrap_profile', 'anti_rollback_checkpoint_profile',
    'cell_id', 'head_register', 'checkpoint_register', 'installation_authority',
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError('admission: ' + message)


def integer(value: object, minimum: int = 1) -> int:
    require(type(value) is int and value >= minimum, 'invalid monotonic integer')
    return value


def hash_value(value: object) -> str:
    require(
        isinstance(value, str) and re.fullmatch(r'sha256:[0-9a-f]{64}', value) is not None,
        'invalid digest',
    )
    return value


def public_key(value: dict) -> bytes:
    return p1.decode_public_key_entry(value, 'admission')


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
    require(
        start <= lo <= hi <= end and (hi - start).total_seconds() <= age,
        'stale, future, or uncertain authority proof',
    )


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
    def compare_and_swap(
        self,
        register: str,
        expected: Floor,
        new: Floor,
        head_register: str,
        expected_head_locator: dict,
    ) -> bool: ...


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
    validate_locator(locator, expected_type=schema)
    value = store.get(locator)
    require(isinstance(value, dict) and value.get('$schema') == schema, 'typed locator schema mismatch')
    require(
        canonicalize(make_locator(schema, canonicalize(value))) == canonicalize(locator),
        'locator must address canonical envelope bytes',
    )
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
        exact_fields(
            entry,
            {
                'key_id', 'public_key_base64', 'public_key_sha256', 'principal', 'tenant',
                'role', 'validity', 'lifecycle_state', 'allowed_actions',
            },
            'registry entry',
        )
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


def historical(
    store,
    value: dict,
    config: dict,
    profiles: dict,
    action: str,
    role: str,
    issued: str,
) -> tuple[dict, dict]:
    reg = registry(store, value['integrity']['key_registry_snapshot_locator'], config, profiles)
    entry = p1.verify_historical_signer(
        value,
        reg,
        profiles[value['$schema']]['domain_prefix'],
        action,
        issued,
        required_role=role,
        label='admission',
    )
    return entry, reg


class AdmissionVerifier:
    """Construct only at the trusted application boundary, using out-of-band pins.

    source must come from resolve_scope; a caller cannot provide SourceSnapshot
    contents through admission JSON. In-memory snapshots are used in unit tests.
    Installation pins and this verifier version bind the proposed semantic rules.
    """

    def __init__(self, runtime: ProtectedRuntime, pins: InstallationPins, store, adr: bytes):
        self.runtime, self.pins, self.store = runtime, pins, store
        self.profiles = {p['schema']: p for p in profile_proposals(adr)}

    def _configuration(self, clock):
        raw = self.runtime.configuration_bytes()
        hash_value(self.pins.configuration_digest)
        require(digest(raw) == self.pins.configuration_digest, 'protected configuration bytes changed')
        config = loads_strict(raw.decode('utf-8'))
        exact_fields(config, CONFIG, 'protected configuration')
        require(config['$schema'] == 'smart_ads/cell_trust_anchor_config/v1', 'configuration schema mismatch')
        for field, expected in (
            ('cell_id', self.pins.cell_id),
            ('head_register', self.pins.head_register),
            ('checkpoint_register', self.pins.checkpoint_register),
            ('installation_authority', self.pins.installation_authority),
        ):
            require(
                isinstance(expected, str) and bool(expected.strip()) and config[field] == expected,
                'protected installation identity mismatch',
            )
        require(
            self.runtime.installation_authority() == self.pins.installation_authority,
            'installation authority mismatch',
        )
        public_key(config)
        require(isinstance(config['trust_anchor_id'], str) and bool(config['trust_anchor_id'].strip()), 'anchor ID missing')
        clock.bounds()
        validity(config['validity'], clock.lower_utc)
        validity(config['validity'], clock.upper_utc)
        require(config['allowed_registry_artifact_types'] == [REGISTRY, INVENTORY], 'bootstrap allowlist mismatch')
        for field, schema in (
            ('inventory_bootstrap_profile', INVENTORY),
            ('anti_rollback_checkpoint_profile', CHECKPOINT),
        ):
            require(canonicalize(config[field]) == canonicalize(self.profiles[schema]), 'protected profile mismatch')
        return config

    def _anchored(self, value, config, profile):
        require(
            value['trust_anchor_id'] == config['trust_anchor_id'] and value['cell_id'] == config['cell_id'],
            'cell or anchor changed',
        )
        validity(config['validity'], value['issued_at_utc'])
        require(timestamp(value['issued_at_utc']) < timestamp(value['valid_until_utc']), 'invalid proof validity')
        integer(value['maximum_age_seconds'])
        signature(value, profile, public_key(config))

    def _inventory(self, locator, config, clock):
        value = load_object(self.store, locator, INVENTORY)
        exact_fields(value, COMMON | TIMES | {'epoch', 'predecessor_inventory_locator', 'profiles'}, 'contract inventory')
        # The profile comes from protected config, not the inventory itself.
        self._anchored(value, config, config['inventory_bootstrap_profile'])
        integer(value['epoch'])
        require(
            canonicalize(value['profiles']) == canonicalize(list(self.profiles.values())),
            'inventory requires all exact closed unique profiles',
        )
        fresh(value, clock)
        current, seen, history = value, set(), [value]
        for _ in range(256):
            previous = current['predecessor_inventory_locator']
            if current['epoch'] == 1:
                require(previous is None, 'inventory genesis predecessor must be null')
                return value, history
            require(previous is not None, 'inventory predecessor missing')
            token = canonicalize(previous)
            require(token not in seen, 'inventory cycle')
            seen.add(token)
            older = load_object(self.store, previous, INVENTORY)
            exact_fields(older, set(value), 'historical inventory')
            self._anchored(older, config, config['inventory_bootstrap_profile'])
            integer(older['epoch'])
            require(older['epoch'] + 1 == current['epoch'], 'inventory epoch skipped')
            require(timestamp(older['issued_at_utc']) <= timestamp(current['issued_at_utc']), 'inventory time reversed')
            # This contract supports one exact table; changing it requires new pins/code.
            require(canonicalize(older['profiles']) == canonicalize(value['profiles']), 'unsupported historical profile table')
            current = older
            history.append(older)
        raise ValueError('admission: inventory chain exceeds 256 links')

    def _checkpoint(self, config, clock):
        locator, floor = self.runtime.read_checkpoint(config['checkpoint_register'])
        require(type(floor) is Floor, 'protected floor unavailable')
        floor.validate()
        value = load_object(self.store, locator, CHECKPOINT)
        exact_fields(value, COMMON | TIMES | {'highest_seen_epoch', 'head_digest'}, 'checkpoint')
        self._anchored(value, config, config['anti_rollback_checkpoint_profile'])
        require(
            value['integrity']['key_registry_snapshot_locator'] is None,
            'A checkpoint must not depend on current keys or registry',
        )
        integer(value['highest_seen_epoch'], 0)
        require(value['highest_seen_epoch'] <= floor.epoch, 'protected floor below signed bootstrap checkpoint')
        if value['highest_seen_epoch'] == 0:
            require(value['head_digest'] is None, 'checkpoint genesis digest must be null')
        else:
            hash_value(value['head_digest'])
        if value['highest_seen_epoch'] == floor.epoch:
            require(value['head_digest'] == floor.head_digest, 'checkpoint/floor fork')
        fresh(value, clock)
        return value, floor

    def _state(self, head, config):
        require(head['current_state_locator']['content_digest'] == head['current_state_digest'], 'head/state digest mismatch')
        state = load_object(self.store, head['current_state_locator'], STATE)
        exact_fields(state, COMMON | TIMES | {'epoch', 'registry_locator', 'predecessor_state_locator', 'key_states'}, 'key state')
        self._anchored(state, config, self.profiles[STATE])
        require(type(state['epoch']) is int and state['epoch'] == head['epoch'], 'head/state epoch mismatch')
        require(state['issued_at_utc'] == head['issued_at_utc'], 'head/state issuance mismatch')
        reg = registry(self.store, state['registry_locator'], config, self.profiles)
        require(
            canonicalize(state['registry_locator']) == canonicalize(state['integrity']['key_registry_snapshot_locator']),
            'state signer snapshot must equal state registry',
        )
        expected = [
            {'key_id': e['key_id'], 'public_key_sha256': e['public_key_sha256'], 'lifecycle_state': e['lifecycle_state']}
            for e in reg['entries']
        ]
        require(canonicalize(state['key_states']) == canonicalize(expected), 'current key-state/registry mismatch')
        for value, action in ((head, 'current_key_state_head_issue'), (state, 'current_key_state_issue')):
            historical(self.store, value, config, self.profiles, action, 'trust_anchor', value['issued_at_utc'])
            require(
                canonicalize(value['integrity']['key_registry_snapshot_locator']) == canonicalize(state['registry_locator']),
                'head/state registry mismatch',
            )
        return state, reg

    def _chain(self, locator, config, checkpoint, floor, clock):
        head = load_object(self.store, locator, HEAD)
        tip, tip_state, tip_reg = None, None, None
        seen, found_floor, found_checkpoint = set(), floor.epoch == 0, checkpoint['highest_seen_epoch'] == 0
        newer_head, newer_state, newer_reg = None, None, None
        for _ in range(256):
            exact_fields(
                head,
                COMMON | TIMES | {
                    'epoch', 'current_state_locator', 'current_state_digest',
                    'predecessor_head_locator', 'predecessor_head_digest',
                },
                'key head',
            )
            self._anchored(head, config, self.profiles[HEAD])
            integer(head['epoch'])
            state, reg = self._state(head, config)
            if tip is None:
                tip, tip_state, tip_reg = head, state, reg
                require(head['epoch'] >= floor.epoch, 'head rollback')
                fresh(head, clock)
                fresh(state, clock)
            if newer_head is not None:
                require(head['epoch'] + 1 == newer_head['epoch'], 'head epoch skipped')
                require(timestamp(head['issued_at_utc']) <= timestamp(newer_head['issued_at_utc']), 'head time reversed')
                require(
                    canonicalize(newer_state['predecessor_state_locator']) == canonicalize(head['current_state_locator']),
                    'state predecessor does not match head chain',
                )
                require(reg['epoch'] <= newer_reg['epoch'], 'registry epoch rollback')
                if reg['epoch'] == newer_reg['epoch']:
                    require(canonicalize(reg) == canonicalize(newer_reg), 'same-epoch registry fork')
            if head['epoch'] == floor.epoch:
                require(locator['content_digest'] == floor.head_digest, 'protected head fork')
                found_floor = True
            if head['epoch'] == checkpoint['highest_seen_epoch']:
                require(locator['content_digest'] == checkpoint['head_digest'], 'signed checkpoint head fork')
                found_checkpoint = True
            if head['epoch'] == 1:
                require(
                    head['predecessor_head_locator'] is None
                    and head['predecessor_head_digest'] is None
                    and state['predecessor_state_locator'] is None,
                    'non-null genesis predecessor',
                )
                require(found_floor and found_checkpoint, 'checkpoint not on complete head chain')
                return tip, tip_state, tip_reg
            previous = head['predecessor_head_locator']
            require(
                isinstance(previous, dict) and previous.get('content_digest') == head['predecessor_head_digest'],
                'head predecessor missing or digest mismatch',
            )
            token = canonicalize(previous)
            require(token not in seen, 'head cycle')
            seen.add(token)
            newer_head, newer_state, newer_reg = head, state, reg
            locator, head = previous, load_object(self.store, previous, HEAD)
        raise ValueError('admission: head chain exceeds 256 links')

    def _current(self, entry, reg, clock, required_actions):
        matches = [e for e in reg['entries'] if e['key_id'] == entry['key_id']]
        require(len(matches) == 1, 'authority key absent from current state')
        current = matches[0]
        for field in ('public_key_sha256', 'principal', 'tenant', 'role'):
            require(current[field] == entry[field], 'authority identity changed')
        require(current['lifecycle_state'] == 'active', 'authority key currently revoked or expired')
        for schema, action in required_actions:
            require(
                {'schema': schema, 'action': action} in current['allowed_actions'],
                'required action withdrawn from current authority',
            )
        validity(current['validity'], clock.lower_utc)
        validity(current['validity'], clock.upper_utc)

    def _manifest(self, locator, source, config, reg, clock):
        value = load_object(self.store, locator, MANIFEST)
        fields = {
            'generated_at', 'supersedes_manifest_locator', 'supersedes_digest', 'correction_reason',
            'source_inventory', 'coverage_assertion', 'entries',
        }
        exact_fields(value, fields | {'$schema', 'manifest_digest', 'integrity'}, 'decomposition manifest')
        owner, historical_reg = historical(
            self.store, value, config, self.profiles,
            'decomposition_manifest_issue', 'decomposition_owner', value['generated_at'],
        )
        require(
            owner['principal'] == self.pins.owner_principal and owner['tenant'] == self.pins.owner_tenant,
            'decomposition owner binding mismatch',
        )
        require(historical_reg['epoch'] <= reg['epoch'], 'manifest registry newer than current authority')
        if historical_reg['epoch'] == reg['epoch']:
            require(canonicalize(historical_reg) == canonicalize(reg), 'manifest registry fork')
        self._current(owner, reg, clock, [(MANIFEST, 'decomposition_manifest_issue')])
        require(timestamp(value['generated_at']) <= clock.bounds()[0], 'manifest generated in future')
        require(value['manifest_digest'] == dec.manifest_digest(value), 'manifest semantic digest mismatch')
        expected = dec.build_candidate(source, value['source_inventory'], value['entries'], value['generated_at'])
        require(
            expected['validation_status'] == 'STRUCTURALLY_VALID',
            'manifest has pending decisions or blocking defects',
        )
        require(
            canonicalize({k: value[k] for k in fields}) == canonicalize(expected['payload']),
            'manifest dispositions/coverage/predecessor differ from recomputation',
        )
        return value, owner

    def verify(self, source, inventory_locator: dict, manifest_locator: dict) -> dict:
        """Verify a genesis manifest; atomically advance only the protected floor.

        No reservation, RPC, or effect is authorized. Immutable corrections are
        rejected until their predecessor-semantic verifier is implemented.
        """
        # Historical signature/link checks only; current authority comes from the
        # protected key state below, never from local registry discovery.
        prerequisites = historical_prerequisites()
        clock = self.runtime.authenticated_clock()
        config = self._configuration(clock)
        inventory, inventory_history = self._inventory(inventory_locator, config, clock)
        checkpoint, floor = self._checkpoint(config, clock)
        # Explicit equality at the transition out of provisional admission.
        row = next(p for p in inventory['profiles'] if p['schema'] == CHECKPOINT)
        require(canonicalize(row) == canonicalize(config['anti_rollback_checkpoint_profile']), 'checkpoint row differs')
        head_locator = self.runtime.read_head(config['head_register'])
        head, state, reg = self._chain(head_locator, config, checkpoint, floor, clock)
        for historic_inventory in inventory_history:
            anchor, historical_reg = historical(
                self.store, historic_inventory, config, self.profiles,
                'contract_inventory_issue', 'trust_anchor', historic_inventory['issued_at_utc'],
            )
            require(historical_reg['epoch'] <= reg['epoch'], 'inventory registry newer than current authority')
            if historical_reg['epoch'] == reg['epoch']:
                require(canonicalize(historical_reg) == canonicalize(reg), 'inventory registry fork')
            self._current(
                anchor, reg, clock,
                [
                    (INVENTORY, 'contract_inventory_issue'),
                    (HEAD, 'current_key_state_head_issue'),
                    (STATE, 'current_key_state_issue'),
                ],
            )
        manifest, owner = self._manifest(manifest_locator, source, config, reg, clock)
        # No CAS occurs on a failed dependent artifact. This single atomic operation
        # joins the step-3 floor check to the authoritative head checked in step 4.
        new = Floor(head['epoch'], head_locator['content_digest'], floor.version)
        require(
            self.runtime.compare_and_swap(
                config['checkpoint_register'], floor, new,
                config['head_register'], head_locator,
            ) is True,
            'protected CAS conflict',
        )
        # Finish all potentially slow store/signature/config reads before the
        # final coherent observation. Only pure comparisons follow it.
        self._manifest(manifest_locator, source, config, reg, clock)
        self._configuration(clock)
        final_head, final_clock = self.runtime.observe_head_and_clock(config['head_register'])
        require(final_clock.bounds()[0] >= clock.bounds()[0], 'authenticated clock moved backwards')
        validity(config['validity'], final_clock.lower_utc)
        validity(config['validity'], final_clock.upper_utc)
        for proof in (inventory, checkpoint, head, state):
            fresh(proof, final_clock)
        self._current(
            anchor, reg, final_clock,
            [
                (INVENTORY, 'contract_inventory_issue'),
                (HEAD, 'current_key_state_head_issue'),
                (STATE, 'current_key_state_issue'),
            ],
        )
        self._current(owner, reg, final_clock, [(MANIFEST, 'decomposition_manifest_issue')])
        require(
            canonicalize(final_head) == canonicalize(head_locator),
            'head advanced after validation; retry full verification',
        )
        return {
            'verification_status': 'VERIFIED',
            'contract': 'step4-admission-runtime-proposal-v1',
            'checks': [name for name, _, _ in STEPS],
            'effect_authorized': False,
            'manifest_digest': manifest['manifest_digest'],
            'inventory_locator': inventory_locator,
            'head_locator': head_locator,
            'authority_epoch': head['epoch'],
            'historical_prerequisites': prerequisites['predecessor_signatures_and_links'],
            'floor_before': {'epoch': floor.epoch, 'head_digest': floor.head_digest},
            'floor_after': {'epoch': new.epoch, 'head_digest': new.head_digest},
        }
