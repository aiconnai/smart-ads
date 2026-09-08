"""Chain guards of the proposed D4 verifier that no other test exercises.

Registry epoch rollback and same-epoch registry fork are reachable and are covered
here: each test fails when its own guard is deleted.

Three further guards — `head cycle`, `inventory cycle` and the completeness check
`checkpoint not on complete head chain` — are unreachable by construction, so no
honest test can kill them. Both chains advance only through strictly decreasing
contiguous epochs, so a repeated locator is refused as a skipped epoch before any
cycle can close; and the walked head chain covers every epoch from the tip down to
1, with the signed checkpoint constrained to `0 < epoch <= floor <= tip`, so its
epoch is always met and rejected by the specific fork check instead. The tests
below pin the invariants that make them redundant: if a future change removes
epoch contiguity or the checkpoint/floor ordering, these fail and the redundant
guards must be revisited rather than trusted.
"""
from __future__ import annotations

import copy
from dataclasses import replace

import pytest

from tools.governance import p1
from tools.governance.decomposition_authority import CHECKPOINT, HEAD, INVENTORY, REGISTRY, STATE, Floor

from tests.governance.test_decomposition_runtime import World, synthetic_keys  # noqa: F401


@pytest.fixture
def world(tmp_path, synthetic_keys):  # noqa: F811
    return World(tmp_path, synthetic_keys)


def _sign(world, value, schema, key=0):
    return p1.sign_envelope(value, world.profiles[schema]['domain_prefix'], world.keys[key][0])


def _key_states(world, registry_loc):
    reg = world.store.get(registry_loc)
    return [{k: e[k] for k in ('key_id', 'public_key_sha256', 'lifecycle_state')} for e in reg['entries']]


def _registry_at(world, epoch, mutate=None):
    """Publish an anchor-signed registry at `epoch`, returning its locator."""
    reg = copy.deepcopy(world.objects['registry'])
    reg['epoch'] = epoch
    if mutate:
        mutate(reg)
    return world.store.put(_sign(world, reg, REGISTRY))


def _two_links(world, tip_registry, genesis_registry):
    """Build a genuine two-link head chain, each link naming its own registry.

    The genesis keeps `genesis_registry`; the tip at epoch 2 uses `tip_registry`,
    so adjacent links are compared by the registry rules under review.
    """
    old_state = copy.deepcopy(world.objects['state'])
    old_state['registry_locator'] = genesis_registry
    old_state['integrity']['key_registry_snapshot_locator'] = genesis_registry
    old_state['key_states'] = _key_states(world, genesis_registry)
    old_state_loc = world.store.put(_sign(world, old_state, STATE))
    old_head = copy.deepcopy(world.objects['head'])
    old_head['current_state_locator'] = old_state_loc
    old_head['current_state_digest'] = old_state_loc['content_digest']
    old_head['integrity']['key_registry_snapshot_locator'] = genesis_registry
    old_head_loc = world.store.put(_sign(world, old_head, HEAD))

    state = copy.deepcopy(world.objects['state'])
    state.update(epoch=2, registry_locator=tip_registry, predecessor_state_locator=old_state_loc,
                 key_states=_key_states(world, tip_registry))
    state['integrity']['key_registry_snapshot_locator'] = tip_registry
    state_loc = world.store.put(_sign(world, state, STATE))
    head = copy.deepcopy(world.objects['head'])
    head.update(epoch=2, current_state_locator=state_loc, current_state_digest=state_loc['content_digest'],
                predecessor_head_locator=old_head_loc, predecessor_head_digest=old_head_loc['content_digest'])
    head['integrity']['key_registry_snapshot_locator'] = tip_registry
    world.runtime.head = world.store.put(_sign(world, head, HEAD))
    return old_head_loc


# --- reachable guards: covered, and killed when deleted ------------------------

def test_registry_epoch_rollback_between_head_links_rejects(world):
    """The tip may not name an older registry epoch than its own predecessor."""
    _two_links(world, tip_registry=_registry_at(world, 3), genesis_registry=_registry_at(world, 4))
    with pytest.raises(ValueError, match='registry epoch rollback'):
        world.verify()
    assert world.runtime.cas_calls == 0


def test_same_epoch_registry_fork_between_head_links_rejects(world):
    """Two different registry bytes at the same epoch are a fork, not a transition."""
    original = _registry_at(world, 4)
    forked = _registry_at(world, 4, lambda reg: reg.update(issued_at_utc='2026-09-07T09:59:00Z'))
    assert original['content_digest'] != forked['content_digest']
    _two_links(world, tip_registry=forked, genesis_registry=original)
    with pytest.raises(ValueError, match='same-epoch registry fork'):
        world.verify()
    assert world.runtime.cas_calls == 0


# --- invariants that make the remaining guards redundant -----------------------

def test_head_chain_requires_contiguous_epochs_so_a_cycle_cannot_close(world):
    """A repeated head locator is refused as a skipped epoch, never reaching the cycle guard.

    This is what makes `head cycle` unreachable. If contiguity is ever relaxed,
    this test fails and the cycle guard stops being redundant.
    """
    state = copy.deepcopy(world.objects['state'])
    state.update(epoch=2, predecessor_state_locator=world.objects['head']['current_state_locator'])
    state_loc = world.store.put(_sign(world, state, STATE))
    head = copy.deepcopy(world.objects['head'])
    head.update(epoch=2, current_state_locator=state_loc, current_state_digest=state_loc['content_digest'])
    signed = _sign(world, head, HEAD)
    locator = world.store.put(signed)
    looping = copy.deepcopy(signed)
    looping['predecessor_head_locator'] = locator          # points at itself
    looping['predecessor_head_digest'] = locator['content_digest']
    world.runtime.head = world.store.put(_sign(world, looping, HEAD))
    with pytest.raises(ValueError, match='head epoch skipped'):
        world.verify()
    assert world.runtime.cas_calls == 0


def test_inventory_chain_requires_contiguous_epochs_so_a_cycle_cannot_close(world):
    """Same invariant on the inventory chain, making `inventory cycle` unreachable."""
    inventory = copy.deepcopy(world.objects['inventory'])
    inventory['epoch'] = 2
    signed = _sign(world, inventory, INVENTORY)
    locator = world.store.put(signed)
    looping = copy.deepcopy(signed)
    looping['predecessor_inventory_locator'] = locator     # points at itself
    world.inventory_loc = world.store.put(_sign(world, looping, INVENTORY))
    with pytest.raises(ValueError, match='inventory epoch skipped'):
        world.verify()
    assert world.runtime.cas_calls == 0


def test_signed_checkpoint_epoch_is_always_met_by_the_walked_chain(world):
    """The checkpoint sits within `0 < epoch <= floor <= tip`, so completeness cannot fail.

    A divergent checkpoint is caught by the specific fork check while walking the
    chain, never by the completeness check at genesis. That ordering is what makes
    `checkpoint not on complete head chain` unreachable.
    """
    genesis_loc = world.store.put(world.objects['head'])
    _two_links(world, tip_registry=_registry_at(world, 4), genesis_registry=_registry_at(world, 4))
    checkpoint = copy.deepcopy(world.objects['checkpoint'])
    checkpoint.update(highest_seen_epoch=1, head_digest='sha256:' + '9' * 64)  # epoch 1 is on the chain
    world.runtime.checkpoint = world.store.put(_sign(world, checkpoint, CHECKPOINT))
    world.runtime.floor = Floor(2, world.runtime.head['content_digest'], 'v0')
    with pytest.raises(ValueError, match='signed checkpoint head fork'):
        world.verify()
    assert world.runtime.cas_calls == 0
    assert genesis_loc['content_digest'] != checkpoint['head_digest']


def test_checkpoint_may_not_exceed_the_protected_floor(world):
    """`highest_seen_epoch <= floor.epoch` is the other half of the ordering above."""
    checkpoint = copy.deepcopy(world.objects['checkpoint'])
    checkpoint.update(highest_seen_epoch=5, head_digest='sha256:' + '9' * 64)
    world.runtime.checkpoint = world.store.put(_sign(world, checkpoint, CHECKPOINT))
    world.runtime.floor = Floor(1, world.store.put(world.objects['head'])['content_digest'], 'v0')
    with pytest.raises(ValueError, match='protected floor below signed bootstrap checkpoint'):
        world.verify()
    assert world.runtime.cas_calls == 0
