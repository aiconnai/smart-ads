"""The protected runtime decides current authority; local discovery never does.

`AdmissionVerifier.verify` keeps the historical predecessor prerequisites, which
are signature and link checks over fixed step-2/Gate-2 artifacts. It must not
consume the offline registry-chain observation: that rule is conservative because
offline there is no current key state to distinguish a legitimate withdrawal from
a rollback. With a valid protected state, withdrawing a historical action that no
check requires is permitted; withdrawing a required action, revoking the signer,
or rolling the head back still fails.
"""
from __future__ import annotations

import copy
from dataclasses import replace

import pytest

from tools.governance import decomposition_governance as governance
from tools.governance import p1
from tools.governance.decomposition_authority import HEAD, REGISTRY

from tests.governance.test_decomposition_runtime import World, advance, synthetic_keys  # noqa: F401


@pytest.fixture
def world(tmp_path, synthetic_keys):  # noqa: F811
    return World(tmp_path, synthetic_keys)


def _reissue_registry(world, mutate):
    """Publish a newer protected registry epoch and point head/state at it."""
    reg = copy.deepcopy(world.objects['registry'])
    reg['epoch'] = 5
    mutate(reg)
    reg = p1.sign_envelope(reg, world.profiles[REGISTRY]['domain_prefix'], world.keys[0][0])
    loc = world.store.put(reg)
    # The signed key state mirrors the registry; the runtime requires them to agree.
    key_states = [{'key_id': e['key_id'], 'public_key_sha256': e['public_key_sha256'],
                   'lifecycle_state': e['lifecycle_state']} for e in reg['entries']]

    def change(state):
        state['registry_locator'] = loc
        state['key_states'] = key_states
        state['integrity']['key_registry_snapshot_locator'] = loc
    advance(world, change)
    head = world.store.get(world.runtime.head)
    head['integrity']['key_registry_snapshot_locator'] = loc
    head = p1.sign_envelope(head, world.profiles[HEAD]['domain_prefix'], world.keys[0][0])
    world.runtime.head = world.store.put(head)


def test_verify_does_not_perform_offline_registry_discovery(world, monkeypatch):
    """Current authority comes from the protected state, never from the working tree."""
    def explode(*args, **kwargs):
        raise AssertionError('verify must not perform offline registry discovery')

    monkeypatch.setattr(governance, 'observed_registry_chain', explode)
    assert world.verify()['verification_status'] == 'VERIFIED'


def test_withdrawing_an_unused_historical_action_passes_with_valid_protected_state(world):
    """D4 permits withdrawing a historical action that no check requires.

    The owner entry keeps `decomposition_manifest_issue` and loses an action that
    no verifier predicate demands. The offline additive rule would reject this.
    """
    world.objects['registry']['entries'][1]['allowed_actions'].append(
        {'schema': 'x/v1', 'action': 'unused_legacy'})
    _reissue_registry(world, lambda reg: reg['entries'][1].update(
        allowed_actions=[a for a in reg['entries'][1]['allowed_actions'] if a['action'] != 'unused_legacy']))
    assert world.verify()['verification_status'] == 'VERIFIED'


def test_withdrawing_a_required_action_still_fails(world):
    _reissue_registry(world, lambda reg: reg['entries'][1].update(allowed_actions=[]))
    with pytest.raises(ValueError, match='action withdrawn'):
        world.verify()
    assert world.runtime.cas_calls == 0


def test_revoked_signer_still_fails(world):
    _reissue_registry(world, lambda reg: reg['entries'][1].update(lifecycle_state='revoked'))
    with pytest.raises(ValueError, match='currently revoked'):
        world.verify()
    assert world.runtime.cas_calls == 0


def test_head_rollback_still_fails(world):
    world.runtime.floor = replace(world.runtime.floor, epoch=9, head_digest='sha256:' + '0' * 64)
    with pytest.raises(ValueError, match='rollback|fork'):
        world.verify()
    assert world.runtime.cas_calls == 0
