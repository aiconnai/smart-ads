"""Closed v2 target selectors: retained spans and planned two-member assemblies."""
from __future__ import annotations

from collections import defaultdict
import copy
import re

from tools.governance.decomposition_common import exact_fields, json_digest
from tools.governance.decomposition_scope import BASELINE, REPOSITORY
from tools.governance.jcs import canonicalize


def validate_target(entry: dict, item: dict) -> None:
    value = entry['target_selector']
    if value is None:
        return
    if not isinstance(value, dict) or entry['target_path'] is None:
        raise ValueError('target: selector requires an implementation path')
    if value.get('selector_kind') == 'retained_source':
        exact_fields(value, {'selector_kind', 'inventory_id', 'source_commit', 'source_selector_digest'}, 'retained target')
        if (value['inventory_id'] != item['inventory_id'] or value['source_commit'] != BASELINE
                or value['source_selector_digest'] != item['source_selector_digest']
                or entry['target_repository'] != REPOSITORY
                or entry['target_layer'] != 'legacy_governance'
                or entry['target_path'] != item['source_path']
                or entry['migration_mode'] != 'legacy_governance_only'):
            raise ValueError('target: retained span must identify the unchanged legacy source')
    elif value.get('selector_kind') == 'planned_assembly_member':
        exact_fields(value, {'selector_kind', 'assembly_id', 'inventory_id', 'role', 'companion_inventory_id'}, 'assembly member')
        if (value['inventory_id'] != item['inventory_id'] or value['role'] not in ('decorator', 'definition')
                or not isinstance(value['assembly_id'], str)
                or re.fullmatch(r'sha256:[0-9a-f]{64}', value['assembly_id']) is None
                or entry['target_repository'] != 'aiconnai/smart-ads'
                or entry['target_layer'] != 'repository_tooling'
                or entry['migration_mode'] != 'split_by_invariant'):
            raise ValueError('target: invalid planned assembly member')
    else:
        raise ValueError('target: unsupported selector kind')


def assembly_id(entries: list[dict]) -> str:
    return json_digest({'target_repository': entries[0]['target_repository'],
                        'target_layer': entries[0]['target_layer'], 'target_path': entries[0]['target_path'],
                        'members': sorted(e['inventory_id'] for e in entries),
                        'rule': 'decorator_before_definition_clean_reimplementation_v1'})


def _assembly(source, items: dict, entries: list[dict]) -> None:
    if len(entries) != 2 or {e['target_selector']['role'] for e in entries} != {'decorator', 'definition'}:
        raise ValueError('target: assembly requires exactly one decorator and one definition')
    by_role = {e['target_selector']['role']: e for e in entries}
    dec, definition = by_role['decorator'], by_role['definition']
    a, b = items[dec['inventory_id']], items[definition['inventory_id']]
    sa, sb = a['source_selector'], b['source_selector']
    if (a['source_path'] != b['source_path'] or sa['selector_kind'] != 'text_region'
            or sb['selector_kind'] != 'ast_symbol' or sa['byte_range'][1] != sb['byte_range'][0]
            or not source.files[a['source_path']][slice(*sa['byte_range'])].lstrip().startswith(b'@')):
        raise ValueError('target: assembly members must be adjacent decorator and AST definition')
    for entry, other in ((dec, definition), (definition, dec)):
        target = entry['target_selector']
        if target['assembly_id'] != assembly_id(entries) or target['companion_inventory_id'] != other['inventory_id']:
            raise ValueError('target: assembly identity/companion mismatch')
    for field in ('target_layer', 'migration_mode', 'decision_status', 'system_owner',
                  'preserved_invariants', 'required_tests', 'compatibility_surface', 'blocking_defects'):
        if canonicalize(dec[field]) != canonicalize(definition[field]):
            raise ValueError('target: coupled assembly dispositions disagree')


def validate_targets(source, inventory: dict, entries: list[dict]) -> None:
    items = {i['inventory_id']: i for i in inventory['items']}
    groups = defaultdict(list)
    for e in entries:
        validate_target(e, items[e['inventory_id']])
        if e['target_path'] is not None:
            groups[(e['target_repository'], e['target_path'])].append(e)
    for group in groups.values():
        selectors = [e['target_selector'] for e in group]
        kinds = {s['selector_kind'] if s else None for s in selectors}
        if len(group) == 1 and kinds != {'planned_assembly_member'}:
            continue
        if kinds == {'retained_source'}:
            # Inventory validation already proves disjoint source byte ranges.
            continue
        if kinds == {'planned_assembly_member'}:
            _assembly(source, items, group)
        else:
            raise ValueError('target: shared target requires complete retained selectors or an assembly')


def review_inputs(source, inventory: dict, unit_review: dict) -> dict:
    """Map reviewed proposals to pending v2 inputs, never to accepted decisions.

    The CLI verifies unit_review against immutable source/rules before this call.
    """
    from tools.governance.decomposition_decisions import decision_template
    from tools.governance.decomposition import CONTRACT, build_candidate
    entries = decision_template(inventory)
    proposals = {e['inventory_id']: e for e in unit_review['entries']}
    if len(proposals) != len(unit_review['entries']) or set(proposals) != {e['inventory_id'] for e in entries}:
        raise ValueError('target: review must cover inventory exactly once')
    items = {i['inventory_id']: i for i in inventory['items']}
    groups = defaultdict(list)
    for e in entries:
        p = proposals[e['inventory_id']]['proposal']
        for field in ('migration_mode', 'target_repository', 'target_layer', 'target_path', 'preserved_invariants', 'required_tests'):
            e[field] = copy.deepcopy(p[field])
        if e['target_path'] is not None:
            groups[(e['target_repository'], e['target_path'])].append(e)
    for group in groups.values():
        if len(group) < 2:
            continue
        if all(e['migration_mode'] == 'legacy_governance_only' for e in group):
            for e in group:
                e['target_selector'] = {'selector_kind': 'retained_source', 'inventory_id': e['inventory_id'],
                                        'source_commit': BASELINE,
                                        'source_selector_digest': items[e['inventory_id']]['source_selector_digest']}
        else:
            if len(group) != 2:
                raise ValueError('target: unknown multi-member assembly')
            for e in group:
                other = next(x for x in group if x is not e)
                role = 'definition' if items[e['inventory_id']]['source_selector']['selector_kind'] == 'ast_symbol' else 'decorator'
                e['target_selector'] = {'selector_kind': 'planned_assembly_member', 'assembly_id': assembly_id(group),
                                        'inventory_id': e['inventory_id'], 'role': role,
                                        'companion_inventory_id': other['inventory_id']}
    build_candidate(source, inventory, entries, '2026-09-07T00:00:00Z')
    return {'artifact_kind': 'decomposition_inputs_draft', 'draft_contract': CONTRACT,
            'inventory': copy.deepcopy(inventory), 'entries': entries}
