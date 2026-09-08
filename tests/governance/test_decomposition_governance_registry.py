"""Locally observed registries in `inspect_governance`, without the protected runtime.

These checks describe repository observation, not admission. A registry counts as
observed when a file in this working tree names it, it verifies under the anchor
public key, and it continues the epoch-3 historical chain without gaps, rollback
or loss of entries. A local file proves neither publication nor current authority:
removing it lowers the reported observation, and only the protected current key
state decides authority. Objects merely deposited in the store are ignored.
Nothing here admits the manifest: the three admission blockers stay constant.
"""
from __future__ import annotations

import base64
import copy
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from tools.governance import decomposition as dec, p1
from tools.governance import decomposition_governance as governance
from tools.governance.locator import Store

ROOT = Path(__file__).resolve().parents[2]
REGISTRY = 'smart_ads/key_authorization_registry/v1'
DOMAIN = p1.DOMAIN_PREFIXES['key_authorization_registry/v1']
EPOCH3 = 'cell-object:sha256:977df65902295709c1137fded674a5ba2766bb94ee61833d3018c47dda4d1936'
EPOCH4 = 'cell-object:sha256:90c7686dc5f86f3964469a34100e0dbb134b482fb775ee1241db90cafb971eb4'
OWNER_ACTION = {'schema': 'smart_ads/decomposition_manifest/v1', 'action': 'decomposition_manifest_issue'}


def _docs_copy(tmp_path):
    shutil.copytree(ROOT / 'docs', tmp_path / 'docs')
    return tmp_path


def _reference(root, name, locator):
    path = root / 'docs/governance' / name / 'params' / f'registry_{name}_store_put.out'
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(locator, indent=2) + '\n')


def _epoch4(root):
    store = Store(root / 'docs/governance/cell-objects')
    loc = json.loads((root / 'docs/governance/registry-epoch4/params/registry_epoch4_store_put.out').read_text())
    return store, store.get(loc)


# --- real repository ---------------------------------------------------------

def test_real_repository_observes_epoch4_and_keeps_epoch3_historical():
    result = governance.inspect_governance(ROOT)
    assert result['registry_locator']['object_ref'] == EPOCH3
    assert result['epoch3_has_decomposition_action'] is False
    assert result['locally_observed_registry_locator']['object_ref'] == EPOCH4
    assert result['locally_observed_epoch'] == 4
    assert result['locally_observed_has_decomposition_action'] is True


def test_reported_scope_claims_observation_not_publication_or_authority():
    result = governance.inspect_governance(ROOT)
    assert 'locally observed' in result['locally_observed_registry_scope']
    for word in ('published', 'admitted', 'authority', 'rollback'):
        assert word not in result['locally_observed_registry_scope']


def test_observed_epoch4_does_not_lift_any_admission_blocker():
    result = governance.inspect_governance(ROOT)
    assert result['locally_observed_epoch'] == 4
    assert result['signable'] is False
    assert result['contract_ratification'] == 'NOT_RATIFIED'
    assert result['contract_inventory_admission'] == 'NOT_INSTALLED'
    assert dec.BLOCKERS == ['contract_amendment_not_ratified', 'decomposition_profile_not_admitted',
                            'human_decision_review_not_attested']


def test_local_observation_falls_back_when_the_referencing_file_is_removed(tmp_path):
    """A local file is not evidence of publication: removing it lowers the observation."""
    root = _docs_copy(tmp_path)
    (root / 'docs/governance/registry-epoch4/params/registry_epoch4_store_put.out').unlink()
    result = governance.inspect_governance(root)
    assert result['locally_observed_epoch'] == 3
    assert result['locally_observed_registry_locator']['object_ref'] == EPOCH3


# --- store deposits and local references --------------------------------------

def test_registry_only_deposited_in_store_is_ignored(tmp_path):
    root = _docs_copy(tmp_path)
    store, reg4 = _epoch4(root)
    forged = copy.deepcopy(reg4)
    forged['epoch'] = 5
    store.put(forged)  # no file anywhere in the tree references it
    result = governance.inspect_governance(root)
    assert result['locally_observed_epoch'] == 4
    assert result['locally_observed_registry_locator']['object_ref'] == EPOCH4


def test_referenced_tampered_registry_rejects_on_signature(tmp_path):
    """Mutated bytes: the store rejects on digest before any chain rule applies."""
    root = _docs_copy(tmp_path)
    store, reg4 = _epoch4(root)
    forged = copy.deepcopy(reg4)
    forged['epoch'] = 5  # signature no longer matches
    _reference(root, 'epoch5', store.put(forged))
    with pytest.raises(ValueError, match='content_digest|signature'):
        governance.inspect_governance(root)


def test_registry_signed_by_non_anchor_key_rejects_on_key_identity(tmp_path):
    """The envelope binds the signer key_id, so a foreign key is refused by identity."""
    root = _docs_copy(tmp_path)
    store, reg4 = _epoch4(root)
    private = tmp_path / 'synthetic.pem'
    subprocess.run(['openssl', 'genpkey', '-algorithm', 'Ed25519', '-out', str(private)],
                   check=True, capture_output=True)
    forged = copy.deepcopy(reg4)
    forged['epoch'] = 5
    forged['integrity'] = {'key_id': p1.key_id_for(p1.raw_public_key_from_pem(private)),
                           'key_registry_snapshot_locator': None}
    _reference(root, 'epoch5', store.put(p1.sign_envelope(forged, DOMAIN, private)))
    with pytest.raises(ValueError, match='key_id mismatch'):
        governance.inspect_governance(root)


def test_referenced_registry_reusing_the_floor_epoch_rejects_on_that_rule(tmp_path, anchor):
    """A validly signed sibling of the floor epoch must hit the floor-reuse rule itself.

    A tampered object never reaches it: the store rejects on digest first. Only a
    genuinely signed registry exercises the rule, so this uses the synthetic anchor.
    """
    e3 = _base_entries(anchor)
    store, refs = _chain(tmp_path, anchor, [(3, '2026-03-01T00:00:00Z', e3, None),
                                            (3, '2026-03-02T00:00:00Z', e3, None)])
    with pytest.raises(ValueError, match='reuses the historical floor epoch'):
        governance.observed_registry_chain(store, refs, anchor[1], 'synthetic-anchor', VALIDITY, refs[0])


# --- chain rules with a synthetic anchor ---------------------------------------

@pytest.fixture(scope='module')
def anchor(tmp_path_factory):
    root = tmp_path_factory.mktemp('synthetic-anchor')
    private = root / 'anchor.pem'
    subprocess.run(['openssl', 'genpkey', '-algorithm', 'Ed25519', '-out', str(private)],
                   check=True, capture_output=True)
    return private, p1.raw_public_key_from_pem(private)


VALIDITY = {'from': '2026-01-01T00:00:00Z', 'until': '2027-01-01T00:00:00Z'}


def _entry(raw, role, actions):
    return {'key_id': p1.key_id_for(raw), 'public_key_base64': base64.b64encode(raw).decode(),
            'public_key_sha256': 'sha256:' + p1.key_id_for(raw).split(':')[-1], 'principal': 'principal:synthetic',
            'tenant': 'synthetic', 'role': role, 'validity': VALIDITY, 'lifecycle_state': 'active',
            'allowed_actions': [{'schema': s, 'action': a} for s, a in actions]}


def _registry(anchor, epoch, issued, entries, mutate=None):
    private, raw = anchor
    value = {'$schema': REGISTRY, 'trust_anchor_id': 'synthetic-anchor', 'epoch': epoch,
             'issued_at_utc': issued, 'entries': entries,
             'integrity': {'key_id': p1.key_id_for(raw), 'key_registry_snapshot_locator': None}}
    if mutate:
        mutate(value)
    return p1.sign_envelope(value, DOMAIN, private)


def _chain(tmp_path, anchor, specs):
    """specs: list of (epoch, issued_at, entries, mutate). Returns store and references."""
    store = Store(tmp_path / 'store')
    references = []
    for spec in specs:
        references.append(store.put(_registry(anchor, *spec)))
    return store, references


def _base_entries(anchor):
    return [_entry(anchor[1], 'trust_anchor', [(REGISTRY, 'registry_issue')])]


def test_chain_accepts_contiguous_superset_epochs(tmp_path, anchor):
    e3 = _base_entries(anchor)
    e4 = copy.deepcopy(e3)
    e4[0]['allowed_actions'].append({'schema': 'x/v1', 'action': 'x'})
    store, refs = _chain(tmp_path, anchor, [(3, '2026-03-01T00:00:00Z', e3, None),
                                            (4, '2026-04-01T00:00:00Z', e4, None)])
    chain = governance.observed_registry_chain(store, refs, anchor[1], 'synthetic-anchor', VALIDITY, refs[0])
    assert [r['epoch'] for r in chain] == [3, 4]


@pytest.mark.parametrize('name,expected', [
    ('gap', 'skips an epoch'),
    ('issued_at_decreases', 'issuance time goes backwards'),
    ('entry_removed', 'drops a previously observed key'),
    ('action_removed', 'withdraws an observed action'),
    ('anchor_id_changed', 'names a different trust anchor'),
    ('same_epoch_different_bytes', 'reuses the historical floor epoch'),
    ('issued_outside_anchor_validity', 'issued outside anchor validity'),
    ('entry_validity_changed', 'changes validity of an observed key'),
    ('bool_epoch', 'must be an integer'),
])
def test_chain_rejects_violations(tmp_path, anchor, name, expected):
    """Each case must reach the rule it names, not merely raise somewhere earlier."""
    e3 = _base_entries(anchor)
    e4 = copy.deepcopy(e3)
    specs = [(3, '2026-03-01T00:00:00Z', e3, None)]
    if name == 'gap':
        specs.append((5, '2026-04-01T00:00:00Z', e4, None))
    elif name == 'issued_at_decreases':
        specs.append((4, '2026-02-01T00:00:00Z', e4, None))
    elif name == 'entry_removed':
        specs.append((4, '2026-04-01T00:00:00Z', [], None))
    elif name == 'action_removed':
        e4[0]['allowed_actions'] = []
        specs.append((4, '2026-04-01T00:00:00Z', e4, None))
    elif name == 'anchor_id_changed':
        specs.append((4, '2026-04-01T00:00:00Z', e4, lambda v: v.update(trust_anchor_id='other')))
    elif name == 'same_epoch_different_bytes':
        specs.append((3, '2026-03-02T00:00:00Z', e4, None))
    elif name == 'issued_outside_anchor_validity':
        specs.append((4, '2027-06-01T00:00:00Z', e4, None))
    elif name == 'entry_validity_changed':
        e4[0]['validity'] = {'from': '2026-01-01T00:00:00Z', 'until': '2028-01-01T00:00:00Z'}
        specs.append((4, '2026-04-01T00:00:00Z', e4, None))
    elif name == 'bool_epoch':
        specs.append((4, '2026-04-01T00:00:00Z', e4, lambda v: v.update(epoch=True)))
    store, refs = _chain(tmp_path, anchor, specs)
    with pytest.raises(ValueError, match=expected):
        governance.observed_registry_chain(store, refs, anchor[1], 'synthetic-anchor', VALIDITY, refs[0])


def test_missing_prerequisite_file_reports_a_governance_error(tmp_path):
    """A missing locator file must fail closed as ValueError, not leak FileNotFoundError."""
    root = _docs_copy(tmp_path)
    (root / 'docs/governance/legacy-step2/params/registry_epoch3_store_put.out').unlink()
    with pytest.raises(ValueError, match='unreadable'):
        governance.inspect_governance(root)


def test_registry_entry_without_key_id_reports_a_governance_error(tmp_path, anchor):
    """A malformed entry in an anchor-signed registry must not surface as KeyError."""
    e3 = _base_entries(anchor)
    e4 = copy.deepcopy(e3)
    del e4[0]['key_id']
    store, refs = _chain(tmp_path, anchor, [(3, '2026-03-01T00:00:00Z', e3, None),
                                            (4, '2026-04-01T00:00:00Z', e4, None)])
    with pytest.raises(ValueError, match='entry is missing key_id'):
        governance.observed_registry_chain(store, refs, anchor[1], 'synthetic-anchor', VALIDITY, refs[0])


def test_chain_requires_historical_floor_among_references(tmp_path, anchor):
    e3 = _base_entries(anchor)
    store, refs = _chain(tmp_path, anchor, [(3, '2026-03-01T00:00:00Z', e3, None),
                                            (4, '2026-04-01T00:00:00Z', e3, None)])
    with pytest.raises(ValueError, match='floor registry is not referenced'):
        governance.observed_registry_chain(store, refs[1:], anchor[1], 'synthetic-anchor', VALIDITY, refs[0])
