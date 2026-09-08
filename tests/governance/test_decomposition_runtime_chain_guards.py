"""Chain guards of the proposed D4 verifier that no other test exercises.

Registry epoch rollback and same-epoch registry fork are reachable and are covered
here: each test fails when its own guard is deleted.

`head cycle` and `inventory cycle` are additional defences. They did not fire in
any scenario examined here, but that is not universal unreachability: it rests on
the store validating locators and on the collision resistance of the hash. Closing
a loop would require an object whose predecessor locator carries that object's own
digest — computationally infeasible under those assumptions, not logically
impossible. Enumerating graphs that are already acyclic cannot establish the
property either. These tests therefore make no claim about the cycle guards
themselves; they pin the guard that fires first in the scenarios below, epoch
contiguity, and nothing here justifies removing the cycle guards.

Note that epoch contiguity alone would NOT prevent a cycle: `L0(epoch 3) ->
L1(epoch 2) -> L1` satisfies `2 + 1 == 3` and would reach the cycle guard on the
next step. It is the wrong invariant to lean on.

The completeness check `checkpoint not on complete head chain` is a different case:
the argument is structural, over epoch ordering, with no cryptographic assumption.
It is also conditional. Completeness is only evaluated once the walk reaches epoch
1, which requires epoch contiguity to hold at every step; given that, plus
`head rollback` (`tip.epoch >= floor.epoch`), the chain covers every epoch from the
tip down to 1 while the signed checkpoint sits within `0 < epoch <= floor <= tip`,
so its epoch is always met and a divergence is rejected by the specific fork check.
Both premises are pinned below; the claim holds while they do.
"""
from __future__ import annotations

import copy

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

def test_self_referencing_head_is_refused_before_the_cycle_guard(world):
    """A head naming itself is stopped by epoch contiguity, before the cycle guard.

    This pins the guard that fires here, and claims nothing about `head cycle`,
    which remains an additional defence. Contiguity would not prevent a cycle on
    its own: `L0(3) -> L1(2) -> L1` satisfies it and would reach the guard. The
    self-reference below is only expressible because the locator is computed after
    the fact; a real object carrying its own digest is infeasible under the store's
    hash assumptions, which is not the same as impossible.
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


def test_self_referencing_inventory_is_refused_before_the_cycle_guard(world):
    """Same ordering on the inventory chain: contiguity fires before `inventory cycle`."""
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
    """A divergent checkpoint is caught by the specific fork check, not by completeness.

    Given that epoch contiguity and `head rollback` hold, the walked chain covers
    every epoch from the tip down to 1 and the checkpoint sits within
    `0 < epoch <= floor <= tip`, so its epoch is always met on the way. The claim is
    conditional on those guards, both pinned here, and does not rest on any
    cryptographic assumption.
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


def test_tip_epoch_may_not_be_below_the_protected_floor(world):
    """`head rollback` is the other premise of the completeness argument above.

    Without it a tip below the floor could be walked, and the floor epoch would
    never be met on the chain, making the completeness check reachable again.
    """
    world.runtime.floor = Floor(9, 'sha256:' + '9' * 64, 'v0')
    with pytest.raises(ValueError, match='head rollback'):
        world.verify()
    assert world.runtime.cas_calls == 0


def test_checkpoint_may_not_exceed_the_protected_floor(world):
    """`highest_seen_epoch <= floor.epoch` is the other half of the ordering above."""
    checkpoint = copy.deepcopy(world.objects['checkpoint'])
    checkpoint.update(highest_seen_epoch=5, head_digest='sha256:' + '9' * 64)
    world.runtime.checkpoint = world.store.put(_sign(world, checkpoint, CHECKPOINT))
    world.runtime.floor = Floor(1, world.store.put(world.objects['head'])['content_digest'], 'v0')
    with pytest.raises(ValueError, match='protected floor below signed bootstrap checkpoint'):
        world.verify()
    assert world.runtime.cas_calls == 0
