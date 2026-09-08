"""v2 assemblies identify source members without pretending code was migrated."""
import pytest

from tools.governance import decomposition as dec
from tools.governance.decomposition_decisions import decision_template
from tools.governance.decomposition_scope import BASELINE, REPOSITORY, SourceSnapshot
from tools.governance.decomposition_selectors import resolve_inventory, SECURITY_PATH
from tools.governance.decomposition_targets import assembly_id, review_inputs


def assembly():
    raw = b'@pytest.mark.parametrize("x", [1, 2])\ndef check(x):\n    assert x'
    source = SourceSnapshot({SECURITY_PATH: raw}, {SECURITY_PATH: '100644'})
    inventory = resolve_inventory(source)
    entries = decision_template(inventory)
    by_id = {i['inventory_id']: i for i in inventory['items']}
    for e in entries:
        e.update(target_repository='aiconnai/smart-ads', target_layer='repository_tooling',
                 target_path='tests/test_check.py', migration_mode='split_by_invariant',
                 preserved_invariants=['parametrization'], required_tests=['tests/test_check.py'])
    for e in entries:
        other = next(x for x in entries if x is not e)
        role = 'definition' if by_id[e['inventory_id']]['source_selector']['selector_kind'] == 'ast_symbol' else 'decorator'
        e['target_selector'] = {'selector_kind': 'planned_assembly_member', 'inventory_id': e['inventory_id'],
                                'assembly_id': assembly_id(entries), 'role': role,
                                'companion_inventory_id': other['inventory_id']}
    return source, inventory, entries


def test_pending_assembly_has_exact_members_and_no_implicit_approval():
    source, inventory, entries = assembly()
    value = dec.build_candidate(source, inventory, entries, '2026-09-07T00:00:00Z')
    assert value['pending_decision_count'] == 2 and value['signable'] is False
    dec.verify_candidate(source, value)
    for e in entries:
        e.update(decision_status='approved', system_owner='principal:example')
    assert dec.build_candidate(source, inventory, entries, '2026-09-07T00:00:00Z')['validation_status'] == 'STRUCTURALLY_VALID'


@pytest.mark.parametrize('mutation', ['missing_selector', 'companion', 'assembly_id', 'duplicate_role',
                                    'owner', 'decision', 'tests', 'target', 'wrong_source', 'wrong_mode'])
def test_assembly_cannot_hide_inconsistent_dispositions(mutation):
    source, inventory, entries = assembly()
    e = entries[0]
    if mutation == 'missing_selector': e['target_selector'] = None
    if mutation == 'companion': e['target_selector']['companion_inventory_id'] = e['inventory_id']
    if mutation == 'assembly_id': e['target_selector']['assembly_id'] = 'sha256:'+'0'*64
    if mutation == 'duplicate_role': e['target_selector']['role'] = entries[1]['target_selector']['role']
    if mutation == 'owner': e['system_owner'] = 'different'
    if mutation == 'decision': e.update(decision_status='approved', system_owner='example')
    if mutation == 'tests': e['required_tests'] = ['tests/other.py']
    if mutation == 'target': e['target_path'] = 'tests/other.py'
    if mutation == 'wrong_source': e['target_selector']['inventory_id'] = 'source-unit:'+'0'*64
    if mutation == 'wrong_mode': e['migration_mode'] = 'repository_tooling'
    with pytest.raises(ValueError): dec.build_candidate(source, inventory, entries, '2026-09-07T00:00:00Z')


def retained():
    source, inv, entries = assembly()
    items = {i['inventory_id']: i for i in inv['items']}
    for e in entries:
        e.update(target_repository=REPOSITORY, target_layer='legacy_governance', target_path=SECURITY_PATH,
                 migration_mode='legacy_governance_only')
        e['target_selector'] = {'selector_kind': 'retained_source', 'inventory_id': e['inventory_id'],
                                'source_commit': BASELINE, 'source_selector_digest': items[e['inventory_id']]['source_selector_digest']}
    return source, inv, entries


def test_shared_legacy_target_is_exact_retained_disjoint_source():
    source, inv, entries = retained()
    dec.build_candidate(source, inv, entries, '2026-09-07T00:00:00Z')


@pytest.mark.parametrize('field,value', [('source_commit', '0'*40), ('source_selector_digest', 'sha256:'+'0'*64)])
def test_retained_source_identity_cannot_be_replaced(field, value):
    source, inv, entries = retained()
    entries[0]['target_selector'][field] = value
    with pytest.raises(ValueError): dec.build_candidate(source, inv, entries, '2026-09-07T00:00:00Z')


def test_v1_candidates_still_recompute_under_their_original_contract():
    source = SourceSnapshot({'scripts/a.py': b'pass\n'}, {'scripts/a.py': '100644'})
    inv = resolve_inventory(source)
    value = dec.build_candidate(source, inv, decision_template(inv), '2026-09-07T00:00:00Z', dec.LEGACY_CONTRACT)
    dec.verify_candidate(source, value)
    assert value['draft_contract'] == 'step4-local-draft-v1'


def test_v1_cannot_silently_use_v2_selectors():
    source, inv, entries = assembly()
    with pytest.raises(ValueError, match='v1 forbids'):
        dec.build_candidate(source, inv, entries, '2026-09-07T00:00:00Z', dec.LEGACY_CONTRACT)


def test_materialization_never_copies_approval_or_owner_from_review():
    source, inv, entries = assembly()
    review = {'entries': [{'inventory_id': e['inventory_id'], 'proposal': e,
                           'human_decision': 'approved', 'system_owner': 'invented'} for e in entries]}
    result = review_inputs(source, inv, review)
    assert all(e['decision_status'] is None and e['system_owner'] is None for e in result['entries'])
    assert {e['target_selector']['assembly_id'] for e in result['entries']} == {assembly_id(entries)}
