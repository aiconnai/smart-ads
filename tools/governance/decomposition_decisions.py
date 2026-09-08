"""Validate caller-supplied decisions; never infer human approval from a path."""
from __future__ import annotations

from tools.governance.decomposition_common import exact_fields, nonempty, source_path, string_list

FIELDS = {'inventory_id', 'system_id', 'system_owner', 'target_repository', 'target_layer',
          'target_path', 'target_selector', 'migration_mode', 'decision_status',
          'deferral_authority_ref', 'rejection_reason', 'preserved_invariants',
          'compatibility_surface', 'blocking_defects', 'required_tests'}
DESTINATIONS = {'aiconnai/smart-ads', 'mbras-tech/mbras-campaigns',
                'limaronaldo/hermes-ronaldo', 'runtime-private', 'none'}
LAYERS = {'core_engine', 'data_plane', 'repository_tooling', 'legacy_governance',
          'consumer_integration'}
IMPLEMENTATION = {'reimplement_clean', 'compatibility_seam', 'split_by_invariant',
                  'repository_tooling', 'legacy_governance_only'}
DEFERRED = {'defer_to_funnel_integration', 'defer_to_google_phase', 'defer_to_write_plane'}
MODES = IMPLEMENTATION | DEFERRED | {'reference_only'}


def _choice(value, allowed: set, label: str, nullable: bool = False) -> None:
    if value is None and nullable:
        return
    if not isinstance(value, str) or value not in allowed:
        raise ValueError(f'decision: invalid {label}')


def _target(entry: dict) -> None:
    path = entry['target_path']
    if path is None:
        return
    if entry['migration_mode'] == 'repository_tooling' and (
            entry['target_repository'] != 'aiconnai/smart-ads'
            or entry['target_layer'] != 'repository_tooling'):
        raise ValueError('decision: repository tooling must stay outside the core wheel')
    source_path(path)
    repo, layer = entry['target_repository'], entry['target_layer']
    roots = {('aiconnai/smart-ads', 'core_engine'): ('src/smart_ads/', 'tests/'),
             ('aiconnai/smart-ads', 'data_plane'): ('src/smart_ads/', 'tests/'),
             ('aiconnai/smart-ads', 'repository_tooling'): ('tooling/governance/', 'tests/'),
             ('limaronaldo/hermes-ronaldo', 'consumer_integration'): ('',),
             ('mbras-tech/mbras-campaigns', 'legacy_governance'): ('',),
             ('runtime-private', 'data_plane'): ('',)}
    if (repo, layer) not in roots or not any(path.startswith(p) for p in roots[(repo, layer)]):
        raise ValueError('decision: target path/repository/layer mismatch')


def _deferral_ref(ref: object) -> None:
    exact_fields(ref, {'repository', 'commit_sha', 'path', 'file_content_sha256', 'section'},
                 'deferral_authority_ref')
    # Exact protected ADR bytes at Gate 2, not a producer-selected paragraph.
    expected = {'repository': 'aiconnai/smart-ads',
                'commit_sha': 'a3f19ef668748c64c5c679710c231426c5e05f6a',
                'path': 'docs/adr/ADR-0001-smart-ads-read-gateway.md',
                'file_content_sha256': 'sha256:239b53e0af44c176b78c363dc271c9fd882910bd4ab2ffb6844cb8fb2458640e',
                'section': '9.2'}
    if ref != expected:
        raise ValueError('decision: deferral must cite the exact approved ADR §9.2')


def _routing(entry: dict, item: dict) -> None:
    path = item['source_path']
    mode = entry['migration_mode']
    required = None
    if path.startswith('scripts/google_ads/pinna5109/'):
        required = 'defer_to_write_plane'
        if mode not in (None, required):
            raise ValueError('decision: Pinna must remain deferred to the Write Plane')
    elif 'funnel' in path:
        required = 'defer_to_funnel_integration'
    elif 'google_canary' in path:
        required = 'defer_to_google_phase'
    elif (path.startswith(('scripts/autonomy/', 'tests/autonomy/'))
          or 'service_account' in path.lower()):
        required = 'legacy_governance_only'
    elif path.startswith('docs/harness/bin/') or path == 'tests/test_codex_gate.py':
        required = 'repository_tooling'
    if required and mode not in (None, required):
        raise ValueError('decision: migration mode contradicts the ADR system disposition')
    if path == 'tests/test_security_boundaries.py' and item['source_selector']['selector_kind'] == 'whole_file':
        raise ValueError('decision: security boundary file requires invariant-level split')
    if required == 'legacy_governance_only' and entry['decision_status'] is not None:
        if entry['target_repository'] != 'mbras-tech/mbras-campaigns':
            raise ValueError('decision: legacy governance cannot migrate to a different repository')


def validate_entry(entry: dict, item: dict) -> None:
    exact_fields(entry, FIELDS, 'decision')
    if entry['inventory_id'] != item['inventory_id']:
        raise ValueError('decision: inventory ID mismatch')
    nonempty(entry['system_id'], 'system_id')
    if entry['decision_status'] is not None or entry['system_owner'] is not None:
        nonempty(entry['system_owner'], 'system_owner')
    for field in ('preserved_invariants', 'compatibility_surface', 'blocking_defects', 'required_tests'):
        string_list(entry[field], field)
    for test in entry['required_tests']:
        if not source_path(test).startswith('tests/'):
            raise ValueError('decision: required_tests must be repository-relative test paths')
    status, mode = entry['decision_status'], entry['migration_mode']
    _choice(status, {'approved', 'deferred', 'rejected'}, 'status', nullable=True)
    _choice(mode, MODES, 'mode', nullable=status is None)
    _choice(entry['target_repository'], DESTINATIONS, 'destination', nullable=status is None)
    _choice(entry['target_layer'], LAYERS, 'layer', nullable=True)
    _target(entry)
    from tools.governance.decomposition_targets import validate_target
    validate_target(entry, item)
    _routing(entry, item)
    if status is None:  # Explicit unresolved input, never counted as an approved entry.
        return
    if status == 'approved':
        if mode not in IMPLEMENTATION | {'reference_only'}:
            raise ValueError('decision: approved status cannot defer')
        if entry['deferral_authority_ref'] is not None or entry['rejection_reason'] is not None:
            raise ValueError('decision: approved entries cannot carry deferral/rejection fields')
        if mode in IMPLEMENTATION and (entry['target_path'] is None or not entry['preserved_invariants']
                                       or not entry['required_tests']):
            raise ValueError('decision: implementation needs target, invariants and required tests')
        if entry['target_repository'] == 'none':
            raise ValueError('decision: approved destination cannot be none')
    elif status == 'deferred':
        if mode not in DEFERRED or entry['target_path'] is not None or entry['target_selector'] is not None:
            raise ValueError('decision: deferred entries forbid implementation targets')
        if entry['target_repository'] != 'mbras-tech/mbras-campaigns' or entry['rejection_reason'] is not None:
            raise ValueError('decision: deferred entries must retain explicit legacy ownership')
        _deferral_ref(entry['deferral_authority_ref'])
    else:
        if (entry['target_repository'] != 'none' or entry['target_layer'] is not None
                or entry['target_path'] is not None or mode != 'reference_only'
                or entry['required_tests'] or entry['deferral_authority_ref'] is not None):
            raise ValueError('decision: rejected entry has incompatible fields')
        nonempty(entry['rejection_reason'], 'rejection_reason')


def decision_template(inventory: dict) -> list[dict]:
    """No migration mode, destination or approval is inferred from source names."""
    return [{'inventory_id': i['inventory_id'], 'system_id': i['source_path'],
             'system_owner': None, 'target_repository': None, 'target_layer': None,
             'target_path': None, 'target_selector': None, 'migration_mode': None,
             'decision_status': None, 'deferral_authority_ref': None, 'rejection_reason': None,
             'preserved_invariants': [], 'compatibility_surface': [], 'blocking_defects': [],
             'required_tests': []} for i in inventory['items']]
