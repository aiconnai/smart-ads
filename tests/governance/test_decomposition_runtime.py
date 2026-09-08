"""Real P1 signatures over synthetic authority; no operator keys or real CAS."""
from __future__ import annotations

import base64
import copy
from dataclasses import replace
from pathlib import Path
import subprocess

import pytest

from tools.governance import decomposition as dec, p1
from tools.governance.decomposition_admission import profile_proposals
from tools.governance.decomposition_authority import (
    CHECKPOINT, HEAD, INVENTORY, MANIFEST, REGISTRY, STATE,
    ClockInterval, Floor, InstallationPins,
)
from tools.governance.decomposition_common import digest
from tools.governance.decomposition_decisions import decision_template
from tools.governance.decomposition_runtime import AdmissionVerifier
from tools.governance.decomposition_scope import SourceSnapshot
from tools.governance.decomposition_selectors import resolve_inventory
from tools.governance.jcs import canonicalize
from tools.governance.locator import Store

ROOT = Path(__file__).resolve().parents[2]
WHEN = '2026-09-07T10:00:00Z'
NOW = '2026-09-07T10:00:01Z'
UNTIL = '2027-01-01T00:00:00Z'
VALIDITY = {'from': '2026-01-01T00:00:00Z', 'until': UNTIL}


@pytest.fixture(scope='module')
def synthetic_keys(tmp_path_factory):
    root = tmp_path_factory.mktemp('synthetic-only-keys')
    result = []
    for name in ('anchor', 'owner'):
        private, public = root/(name+'.pem'), root/(name+'.pub.pem')
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'Ed25519', '-out', str(private)], check=True, capture_output=True)
        subprocess.run(['openssl', 'pkey', '-in', str(private), '-pubout', '-out', str(public)], check=True, capture_output=True)
        result.append((private, p1.raw_public_key_from_pem(private)))
    return result


class MemoryRuntime:
    """Actual atomic state transition in a hermetic fixture, not a PASS flag."""
    def __init__(self, config, head, checkpoint):
        self.config, self.head, self.checkpoint = canonicalize(config), head, checkpoint
        self.floor = Floor(0, None, 'v0')
        self.clock = ClockInterval(NOW, NOW)
        self.cas_calls = 0
        self.conflict = False
        self.after_cas_head = None
        self.after_cas_clock = None

    def configuration_bytes(self): return self.config
    def installation_authority(self): return 'synthetic-installation'
    def authenticated_clock(self): return self.clock
    def read_head(self, register):
        assert register == 'head:synthetic'
        return copy.deepcopy(self.head)
    def observe_head_and_clock(self, register):
        clock = self.authenticated_clock()
        return self.read_head(register), clock
    def read_checkpoint(self, register):
        assert register == 'checkpoint:synthetic'
        return copy.deepcopy(self.checkpoint), self.floor
    def compare_and_swap(self, register, expected, new, head_register, expected_head_locator):
        assert register == 'checkpoint:synthetic' and head_register == 'head:synthetic'
        self.cas_calls += 1
        if self.conflict or expected != self.floor or expected_head_locator != self.head:
            return False
        self.floor = replace(new, version='v' + str(self.cas_calls))
        if self.after_cas_head is not None: self.head = self.after_cas_head
        if self.after_cas_clock is not None: self.clock = self.after_cas_clock
        return True


class World:
    def __init__(self, root, keys, mutations=None):
        mutations = mutations or {}
        self.keys = keys
        self.adr = (ROOT/'docs/adr/ADR-0001-smart-ads-read-gateway.md').read_bytes()
        self.profiles = {p['schema']: p for p in profile_proposals(self.adr)}
        self.store = Store(root/'objects')
        self.objects = {}
        anchor, owner = keys[0][1], keys[1][1]
        self.config = {'$schema': 'smart_ads/cell_trust_anchor_config/v1', 'trust_anchor_id': 'synthetic-anchor',
                       'public_key_base64': base64.b64encode(anchor).decode(), 'public_key_sha256': digest(anchor),
                       'validity': VALIDITY, 'allowed_registry_artifact_types': [REGISTRY, INVENTORY],
                       'inventory_bootstrap_profile': self.profiles[INVENTORY],
                       'anti_rollback_checkpoint_profile': self.profiles[CHECKPOINT],
                       'cell_id': 'synthetic-cell', 'head_register': 'head:synthetic',
                       'checkpoint_register': 'checkpoint:synthetic', 'installation_authority': 'synthetic-installation'}
        actions = [(INVENTORY, 'contract_inventory_issue'), (HEAD, 'current_key_state_head_issue'),
                   (STATE, 'current_key_state_issue')]
        entries = []
        for raw, role, pairs in ((anchor, 'trust_anchor', actions),
                                 (owner, 'decomposition_owner', [(MANIFEST, 'decomposition_manifest_issue')])):
            entries.append({'key_id': p1.key_id_for(raw), 'public_key_base64': base64.b64encode(raw).decode(),
                            'public_key_sha256': digest(raw), 'principal': 'principal:synthetic', 'tenant': 'synthetic',
                            'role': role, 'validity': VALIDITY, 'lifecycle_state': 'active',
                            'allowed_actions': [{'schema': s, 'action': a} for s, a in pairs]})

        def emit(name, value, key=0, registry_locator=None):
            value = copy.deepcopy(value)
            value['integrity'] = {'key_id': p1.key_id_for(keys[key][1]), 'key_registry_snapshot_locator': registry_locator}
            before_digest = value.get('manifest_digest')
            if name in mutations: mutations[name](value)
            if name == 'manifest' and value['manifest_digest'] == before_digest:
                value['manifest_digest'] = dec.manifest_digest(value)
            domain = self.profiles[value['$schema']]['domain_prefix']
            signed = p1.sign_envelope(value, domain, keys[key][0])
            if 'signed_'+name in mutations: mutations['signed_'+name](signed)
            self.objects[name] = signed
            return self.store.put(signed)

        registry_loc = emit('registry', {'$schema': REGISTRY, 'trust_anchor_id': 'synthetic-anchor',
                                        'epoch': 4, 'issued_at_utc': WHEN, 'entries': entries})
        common = {'trust_anchor_id': 'synthetic-anchor', 'cell_id': 'synthetic-cell',
                  'issued_at_utc': WHEN, 'valid_until_utc': UNTIL, 'maximum_age_seconds': 300}
        key_states = [{k: e[k] for k in ('key_id', 'public_key_sha256', 'lifecycle_state')}
                      for e in self.objects['registry']['entries']]
        state_loc = emit('state', dict(common, **{'$schema': STATE, 'epoch': 1, 'registry_locator': registry_loc,
                         'predecessor_state_locator': None, 'key_states': key_states}), registry_locator=registry_loc)
        head_loc = emit('head', dict(common, **{'$schema': HEAD, 'epoch': 1, 'current_state_locator': state_loc,
                        'current_state_digest': state_loc['content_digest'], 'predecessor_head_locator': None,
                        'predecessor_head_digest': None}), registry_locator=registry_loc)
        checkpoint_loc = emit('checkpoint', dict(common, **{'$schema': CHECKPOINT, 'highest_seen_epoch': 0,
                                                            'head_digest': None}))
        self.inventory_loc = emit('inventory', dict(common, **{'$schema': INVENTORY, 'epoch': 1,
                                  'predecessor_inventory_locator': None, 'profiles': list(self.profiles.values())}),
                                  registry_locator=registry_loc)
        self.source = SourceSnapshot({'scripts/example.py': b'def example(): pass\n'}, {'scripts/example.py': '100644'})
        inv = resolve_inventory(self.source)
        entries = decision_template(inv)
        entries[0].update(system_owner='principal:synthetic', decision_status='approved',
                          migration_mode='repository_tooling', target_repository='aiconnai/smart-ads',
                          target_layer='repository_tooling', target_path='tooling/governance/example.py',
                          preserved_invariants=['fail_closed'], required_tests=['tests/test_example.py'])
        payload = dec.build_candidate(self.source, inv, entries, WHEN)['payload']
        value = dict(payload, **{'$schema': MANIFEST})
        value['manifest_digest'] = dec.manifest_digest(value)
        self.manifest_loc = emit('manifest', value, key=1, registry_locator=registry_loc)
        self.runtime = MemoryRuntime(self.config, head_loc, checkpoint_loc)
        self.pins = InstallationPins(digest(self.runtime.config), 'synthetic-installation', 'synthetic-cell',
                                     'head:synthetic', 'checkpoint:synthetic', 'principal:synthetic', 'synthetic')

    def verify(self):
        return AdmissionVerifier(self.runtime, self.pins, self.store, self.adr).verify(
            self.source, self.inventory_loc, self.manifest_loc)


@pytest.fixture
def world(tmp_path, synthetic_keys):
    return World(tmp_path, synthetic_keys)


def test_all_six_checks_use_crypto_and_advance_floor_without_effect_authority(world):
    result = world.verify()
    assert result['verification_status'] == 'VERIFIED'
    assert len(result['checks']) == 6 and result['effect_authorized'] is False
    assert world.runtime.floor.epoch == 1 and world.runtime.cas_calls == 1
    world.verify()  # same authoritative head, newer local CAS version is valid
    assert world.runtime.cas_calls == 2


@pytest.mark.parametrize('mutation', ['configuration', 'installation', 'bootstrap_profile', 'checkpoint_profile',
                                    'owner_principal', 'cell', 'clock_unknown', 'clock_reversed'])
def test_request_cannot_replace_protected_configuration_or_clock(world, mutation):
    if mutation == 'configuration': world.runtime.config += b'\n'
    if mutation == 'installation': world.pins = replace(world.pins, installation_authority='forged')
    if mutation.endswith('_profile'):
        config = copy.deepcopy(world.config)
        field = 'inventory_bootstrap_profile' if mutation == 'bootstrap_profile' else 'anti_rollback_checkpoint_profile'
        config[field]['domain_prefix'] += 'forged'
        world.runtime.config = canonicalize(config)
        world.pins = replace(world.pins, configuration_digest=digest(world.runtime.config))
    if mutation == 'owner_principal': world.pins = replace(world.pins, owner_principal='other')
    if mutation == 'cell': world.pins = replace(world.pins, cell_id='other')
    if mutation == 'clock_unknown': world.runtime.clock = ClockInterval(NOW, None)
    if mutation == 'clock_reversed': world.runtime.clock = ClockInterval(NOW, WHEN)
    with pytest.raises(ValueError): world.verify()
    assert world.runtime.cas_calls == 0


CASES = [
    ('inventory', lambda v: v['profiles'].pop()),
    ('inventory', lambda v: v['profiles'].append(copy.deepcopy(v['profiles'][0]))),
    ('inventory', lambda v: v.update(epoch=2)),
    ('inventory', lambda v: v.update(maximum_age_seconds=True)),
    ('checkpoint', lambda v: v['integrity'].update(key_registry_snapshot_locator={})),
    ('checkpoint', lambda v: v.update(highest_seen_epoch=True)),
    ('checkpoint', lambda v: v.update(highest_seen_epoch=1, head_digest='sha256:'+'0'*64)),
    ('head', lambda v: v.update(epoch=2)),
    ('head', lambda v: v.update(current_state_digest='sha256:'+'0'*64)),
    ('head', lambda v: v.update(cell_id='other')),
    ('state', lambda v: v.update(epoch=True)),
    ('state', lambda v: v.update(key_states=[])),
    ('state', lambda v: v.update(predecessor_state_locator={})),
    ('registry', lambda v: v['entries'].append(copy.deepcopy(v['entries'][0]))),
    ('registry', lambda v: v['entries'][1].update(role='trust_anchor')),
    ('registry', lambda v: v['entries'][1].update(lifecycle_state='revoked')),
    ('registry', lambda v: v['entries'][1].update(allowed_actions=[])),
    ('registry', lambda v: v['entries'][0].update(lifecycle_state='revoked')),
    ('registry', lambda v: v['entries'][1].update(public_key_sha256='sha256:'+'0'*64)),
    ('manifest', lambda v: v.update(manifest_digest='sha256:'+'0'*64)),
    ('manifest', lambda v: v['entries'][0].update(decision_status=None)),
    ('manifest', lambda v: v['entries'][0].update(blocking_defects=['open'])),
    ('manifest', lambda v: v.update(supersedes_manifest_locator={})),
    ('signed_inventory', lambda v: v.update(epoch=2)),
    ('signed_manifest', lambda v: v.update(generated_at=NOW)),
]


@pytest.mark.parametrize('name,mutation', CASES)
def test_signed_but_invalid_authority_or_dispositions_reject_before_CAS(tmp_path, synthetic_keys, name, mutation):
    world = World(tmp_path, synthetic_keys, {name: mutation})
    with pytest.raises(ValueError): world.verify()
    assert world.runtime.cas_calls == 0


@pytest.mark.parametrize('floor', [Floor(2, 'sha256:'+'0'*64, 'v1'), Floor(1, 'sha256:'+'0'*64, 'v1')])
def test_head_rollback_or_fork_rejected(world, floor):
    world.runtime.floor = floor
    with pytest.raises(ValueError, match='rollback|fork'): world.verify()
    assert world.runtime.cas_calls == 0


def test_CAS_conflict_never_reports_verified(world):
    world.runtime.conflict = True
    with pytest.raises(ValueError, match='CAS conflict'): world.verify()
    assert world.runtime.floor.epoch == 0


def test_head_advancing_after_CAS_requires_full_retry(world):
    world.runtime.after_cas_head = {'new': 'head'}
    with pytest.raises(ValueError, match='head advanced'): world.verify()
    assert world.runtime.floor.epoch == 1  # monotonic write is not rolled back


@pytest.mark.parametrize('clock', [ClockInterval('2026-09-07T09:59:59Z', NOW),
                                  ClockInterval(NOW, '2026-09-07T10:05:01Z')])
def test_authenticated_uncertainty_must_fit_entire_interval(world, clock):
    world.runtime.clock = clock
    with pytest.raises(ValueError): world.verify()
    assert world.runtime.cas_calls == 0


def test_expiration_after_CAS_does_not_return_success(world):
    world.runtime.after_cas_clock = ClockInterval('2026-09-07T10:06:00Z', '2026-09-07T10:06:00Z')
    with pytest.raises(ValueError, match='stale'): world.verify()


def test_source_mutation_rejects_before_CAS(world):
    world.source.files['scripts/example.py'] = b'def changed(): pass\n'
    with pytest.raises(ValueError): world.verify()
    assert world.runtime.cas_calls == 0


def test_wrong_signature_domain_rejects_before_CAS(world):
    value = world.objects['inventory']
    wrong = p1.sign_envelope(value, 'WRONG-DOMAIN', world.keys[0][0])
    world.inventory_loc = world.store.put(wrong)
    with pytest.raises(ValueError): world.verify()
    assert world.runtime.cas_calls == 0


def advance(world, mutation=None):
    """Build a genuine second immutable head/state link using synthetic signing."""
    state = copy.deepcopy(world.objects['state'])
    head = copy.deepcopy(world.objects['head'])
    state.update(epoch=2, predecessor_state_locator=head['current_state_locator'])
    if mutation: mutation(state)
    state = p1.sign_envelope(state, world.profiles[STATE]['domain_prefix'], world.keys[0][0])
    loc = world.store.put(state)
    head.update(epoch=2, current_state_locator=loc, current_state_digest=loc['content_digest'],
                predecessor_head_locator=world.runtime.head,
                predecessor_head_digest=world.runtime.head['content_digest'])
    head = p1.sign_envelope(head, world.profiles[HEAD]['domain_prefix'], world.keys[0][0])
    world.runtime.head = world.store.put(head)


def test_complete_predecessor_path_advances_protected_floor(world):
    world.verify()
    advance(world)
    result = world.verify()
    assert result['authority_epoch'] == 2 and world.runtime.floor.epoch == 2


def test_missing_state_link_rejects_even_with_correct_signed_head_chain(world):
    advance(world, lambda v: v.update(predecessor_state_locator=None))
    with pytest.raises(ValueError, match='state predecessor'): world.verify()
    assert world.runtime.cas_calls == 0


def test_current_revocation_rejects_a_valid_historical_owner_signature(world):
    reg = copy.deepcopy(world.objects['registry'])
    reg['epoch'] = 5
    reg['entries'][1]['lifecycle_state'] = 'revoked'
    reg = p1.sign_envelope(reg, world.profiles[REGISTRY]['domain_prefix'], world.keys[0][0])
    loc = world.store.put(reg)

    def change(state):
        state['registry_locator'] = loc
        state['integrity']['key_registry_snapshot_locator'] = loc
        state['key_states'][1]['lifecycle_state'] = 'revoked'
    advance(world, change)
    head = world.store.get(world.runtime.head)
    head['integrity']['key_registry_snapshot_locator'] = loc
    head = p1.sign_envelope(head, world.profiles[HEAD]['domain_prefix'], world.keys[0][0])
    world.runtime.head = world.store.put(head)
    with pytest.raises(ValueError, match='currently revoked'): world.verify()
    assert world.runtime.cas_calls == 0


def test_head_advancing_during_final_clock_is_not_reported_as_verified(world):
    original = world.runtime.authenticated_clock
    calls = 0

    def clock():
        nonlocal calls
        calls += 1
        if calls == 2: advance(world)
        return original()
    world.runtime.authenticated_clock = clock
    with pytest.raises(ValueError, match='head advanced'): world.verify()
    assert world.runtime.cas_calls == 1


def test_withdrawn_current_action_rejects_valid_historical_owner_signature(world):
    reg = copy.deepcopy(world.objects['registry'])
    reg['epoch'] = 5
    reg['entries'][1]['allowed_actions'] = []
    reg = p1.sign_envelope(reg, world.profiles[REGISTRY]['domain_prefix'], world.keys[0][0])
    loc = world.store.put(reg)

    def change(state):
        state['registry_locator'] = loc
        state['integrity']['key_registry_snapshot_locator'] = loc
    advance(world, change)
    head = world.store.get(world.runtime.head)
    head['integrity']['key_registry_snapshot_locator'] = loc
    head = p1.sign_envelope(head, world.profiles[HEAD]['domain_prefix'], world.keys[0][0])
    world.runtime.head = world.store.put(head)
    with pytest.raises(ValueError, match='action withdrawn'): world.verify()
    assert world.runtime.cas_calls == 0


def test_expiration_during_second_signature_pass_is_observed(world):
    get = world.store.get
    def expire_after_CAS(locator):
        if world.runtime.cas_calls:
            world.runtime.clock = ClockInterval('2026-09-07T10:06:00Z', '2026-09-07T10:06:00Z')
        return get(locator)
    world.store.get = expire_after_CAS
    with pytest.raises(ValueError, match='stale'): world.verify()
    assert world.runtime.cas_calls == 1
