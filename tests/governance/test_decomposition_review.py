"""Counterexamples for non-authorizing admission and per-unit proposals."""
from __future__ import annotations

import copy
from pathlib import Path

import pytest

from tools.governance import decomposition_admission as admission
from tools.governance import decomposition_review as review
from tools.governance.decomposition_common import digest
from tools.governance.decomposition_review_rules import SECURITY_GROUPS
from tools.governance.decomposition_scope import SourceSnapshot, BASELINE, REPOSITORY
from tools.governance.decomposition_selectors import SECURITY_PATH, resolve_inventory

ROOT = Path(__file__).resolve().parents[2]


def admission_inputs():
    return ((ROOT/'docs/adr/ADR-0001-smart-ads-read-gateway.md').read_bytes(),
            (ROOT/'docs/governance/trust-anchor/cell_trust_anchor_config.json').read_bytes())


def test_all_profile_rows_and_only_checkpoint_uses_A():
    value = admission.build_admission_proposal(*admission_inputs())
    profiles = value['profiles_proposed']
    assert len(profiles) == 116
    assert {p['schema'] for p in profiles if p['time_policy']['code'] == 'A'} == {
        'smart_ads/key_state_anti_rollback_checkpoint/v1'}
    assert all(len(p) == 10 for p in profiles)
    assert all(p['domain_prefix'].endswith('\n') and not p['domain_prefix'].endswith('\\n') for p in profiles)
    assert {p['semantic_predicate_id'] for p in profiles} == {
        b['semantic_predicate_id'] for b in value['predicate_bindings_proposed']}
    assert all(b['executable_binding'] is None for b in value['predicate_bindings_proposed'])


@pytest.mark.parametrize('mutation', ['self_profile', 'role', 'policy', 'domain', 'omit', 'duplicate', 'approve', 'installation'])
def test_admission_proposal_cannot_be_self_authorized(mutation):
    adr, trust = admission_inputs()
    value = admission.build_admission_proposal(adr, trust)
    if mutation == 'self_profile': value['protected_config_amendment_proposed']['inventory_bootstrap_profile'] = {}
    if mutation == 'role': value['owner_binding_proposed']['registry_role'] = 'trust_anchor'
    if mutation == 'policy': value['profiles_proposed'][0]['time_policy']['code'] = 'H'
    if mutation == 'domain': value['profiles_proposed'][0]['domain_prefix'] += ' '
    if mutation == 'omit': value['profiles_proposed'].pop()
    if mutation == 'duplicate': value['profiles_proposed'].append(value['profiles_proposed'][0])
    if mutation == 'approve': value['human_ratification'] = True
    if mutation == 'installation': value['protected_config_amendment_proposed']['installation_receipt'] = 'claimed-installed'
    with pytest.raises(ValueError): admission.validate_admission_proposal(value, adr, trust)


@pytest.mark.parametrize('which', ['adr', 'trust'])
def test_changed_historical_bytes_reject(which):
    adr, trust = admission_inputs()
    with pytest.raises(ValueError):
        admission.build_admission_proposal(adr + (b'\n' if which == 'adr' else b''),
                                          trust + (b'\n' if which == 'trust' else b''))


def test_bootstrap_sequence_never_skips_current_authority():
    value = admission.build_admission_proposal(*admission_inputs())
    steps = value['ordered_checks']
    assert [s['id'] for s in steps] == [
        'protected_configuration', 'provisional_inventory', 'anti_rollback_checkpoint',
        'current_key_authority', 'inventory_E_validation', 'decomposition_H_validation']
    assert steps[-1]['depends_on'] == ['inventory_E_validation']
    assert value['unimplemented_runtime_checks'] == [s['id'] for s in steps]
    assert value['owner_binding_proposed']['key_id'] is None
    assert value['signable'] is False and value['authority'] == 'none'
    assert value['role_bindings_proposed']['external trust anchor'] == 'trust_anchor'
    assert {a['schema'] for a in value['anchor_actions_proposed']} == {
        'smart_ads/artifact_contract_inventory/v1', 'smart_ads/current_key_state/v1',
        'smart_ads/current_key_state_head/v1'}


def inputs(path='scripts/google_ads/pinna5109/create_campaign.py', raw=b'def mutate(): pass\n'):
    source = SourceSnapshot({path: raw}, {path: '100644'})
    group = review._group(path)
    row = {'source_path': path, 'source_file_digest': digest(raw), 'system_group': group,
           'migration_mode_proposed': 'defer_to_write_plane', 'decision_status_if_ratified': 'deferred',
           'target_repository_proposed': REPOSITORY, 'target_layer_proposed': 'legacy_governance',
           'target_path_proposed': None}
    paths = {'source': {'repository': REPOSITORY, 'commit_sha': BASELINE}, 'paths': [row]}
    return source, resolve_inventory(source), paths


def security_inputs():
    # Synthetic structure for rule coverage, not a substitute for the real-source review.
    parts = ['import pytest\n']
    for name in SECURITY_GROUPS:
        if name == 'test_sensitive_writers_reject_symlink_file_targets':
            parts.append('@pytest.mark.parametrize("writer", [_write_test_csv, _write_test_json])\n')
        body = '_write_test_csv(None)' if name == 'test_sensitive_writers_enforce_private_modes_under_permissive_umask' else 'pass'
        parts.append(f'def {name}():\n    {body}\n\n')
    return inputs(SECURITY_PATH, ''.join(parts).encode())


def test_proposals_keep_decisions_pending_and_source_bound():
    source, inv, paths = inputs()
    result = review.build_unit_review(source, inv, paths)
    review.validate_unit_review(result, source, inv, paths)
    e = result['entries'][0]
    assert e['human_decision'] is None and e['system_owner'] is None
    assert e['source_selector_digest'] == inv['items'][0]['source_selector_digest']
    assert e['proposal']['migration_mode'] == 'defer_to_write_plane'
    assert e['proposal']['decision_status_if_accepted'] == 'deferred'
    assert result['human_decisions_recorded'] == 0


@pytest.mark.parametrize('mutation', ['source', 'group', 'missing_path', 'duplicate_path', 'write_into_core', 'defer_new_repo', 'defer_target', 'defer_layer'])
def test_wrong_path_proposals_do_not_rebind_units(mutation):
    source, inv, paths = inputs()
    row = paths['paths'][0]
    if mutation == 'source': row['source_file_digest'] = 'sha256:' + '0'*64
    if mutation == 'group': row['system_group'] = 'operator-conductor'
    if mutation == 'missing_path': paths['paths'] = []
    if mutation == 'duplicate_path': paths['paths'].append(copy.deepcopy(row))
    if mutation == 'write_into_core': row['migration_mode_proposed'] = 'reimplement_clean'
    if mutation == 'defer_new_repo': row['target_repository_proposed'] = 'aiconnai/smart-ads'
    if mutation == 'defer_target': row['target_path_proposed'] = 'scripts/new.py'
    if mutation == 'defer_layer': row['target_layer_proposed'] = 'core_engine'
    with pytest.raises(ValueError): review.build_unit_review(source, inv, paths)


@pytest.mark.parametrize('field,value', [('target_repository_proposed', 'aiconnai/smart-ads'),
                                        ('target_path_proposed', 'scripts/autonomy/renamed.py')])
def test_legacy_retention_cannot_rehome_the_source(field, value):
    path = 'scripts/autonomy/controller.py'
    source, inv, paths = inputs(path)
    row = paths['paths'][0]
    row.update(migration_mode_proposed='legacy_governance_only', decision_status_if_ratified='approved',
               target_repository_proposed=REPOSITORY, target_layer_proposed='legacy_governance',
               target_path_proposed=path)
    review.build_unit_review(source, inv, paths)
    row[field] = value
    with pytest.raises(ValueError, match='legacy governance'):
        review.build_unit_review(source, inv, paths)


def test_security_rules_keep_history_and_decorators_explicit():
    source, inv, paths = security_inputs()
    result = review.build_unit_review(source, inv, paths)
    by_name = {e['source_selector'].get('symbol_name'): e for e in result['entries']
               if e['source_selector']['selector_kind'] == 'ast_symbol'}
    assert by_name['_assert_disablement_packet_semantics']['proposal']['target_repository'] == REPOSITORY
    assert by_name['test_meta_request_uses_header_and_strips_query_tokens']['proposal']['analysis_group'] == 'security-meta-mixed-write'
    decorated = by_name['test_sensitive_writers_reject_symlink_file_targets']
    residual = next(e for e in result['entries'] if e['following_symbol_inventory_id'] == decorated['inventory_id'])
    assert residual['proposal']['target_path'] == decorated['proposal']['target_path']
    assert any(decorated['inventory_id'] in g['inventory_ids'] for g in result['shared_target_groups'])
    helper = by_name['_write_test_csv']['inventory_id']
    assert helper in by_name['test_sensitive_writers_enforce_private_modes_under_permissive_umask']['local_helper_inventory_ids']
    assert helper in residual['local_helper_inventory_ids']
    assert helper not in decorated['local_helper_inventory_ids']


def test_review_mutation_does_not_poison_the_analyst_rules():
    source, inv, paths = inputs()
    result = review.build_unit_review(source, inv, paths)
    original = copy.deepcopy(result)
    result['entries'][0]['proposal']['preserved_invariants'].clear()
    with pytest.raises(ValueError): review.validate_unit_review(result, source, inv, paths)
    assert review.build_unit_review(source, inv, paths) == original


def test_approval_cannot_be_added_to_a_recomputed_review():
    source, inv, paths = inputs()
    result = review.build_unit_review(source, inv, paths)
    result['entries'][0]['human_decision'] = 'approved'
    with pytest.raises(ValueError): review.validate_unit_review(result, source, inv, paths)
