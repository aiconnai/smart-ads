"""Offline candidate builder, selectors, decisions, and target assemblies for Step 4.

The candidate is not a profiled/P1 envelope. No runtime signing domain is added.
Governance admission is separate from mechanical coverage and caller decisions.
"""
from __future__ import annotations

import ast
from collections import defaultdict
import copy
import re
import sys

from tools.governance import decomposition_scope as scope
from tools.governance.jcs import canonicalize
from tools.governance.locator import (
    digest,
    exact_fields,
    json_digest,
    nonempty,
    source_path,
    string_list,
    timestamp,
)

CONTRACT = 'step4-local-draft-v2'
LEGACY_CONTRACT = 'step4-local-draft-v1'
BLOCKERS = [
    'contract_amendment_not_ratified',
    'decomposition_profile_not_admitted',
    'human_decision_review_not_attested',
]

AST_ABI = 'python:3.12_ast_v1'
TEXT_ABI = 'raw_bytes:half_open_v1'
SECURITY_PATH = 'tests/test_security_boundaries.py'

FIELDS = {
    'inventory_id', 'system_id', 'system_owner', 'target_repository', 'target_layer',
    'target_path', 'target_selector', 'migration_mode', 'decision_status',
    'deferral_authority_ref', 'rejection_reason', 'preserved_invariants',
    'compatibility_surface', 'blocking_defects', 'required_tests',
}
DESTINATIONS = {
    'aiconnai/smart-ads', 'mbras-tech/mbras-campaigns',
    'limaronaldo/hermes-ronaldo', 'runtime-private', 'none',
}
LAYERS = {
    'core_engine', 'data_plane', 'repository_tooling', 'legacy_governance',
    'consumer_integration',
}
IMPLEMENTATION = {
    'reimplement_clean', 'compatibility_seam', 'split_by_invariant',
    'repository_tooling', 'legacy_governance_only',
}
DEFERRED = {
    'defer_to_funnel_integration', 'defer_to_google_phase', 'defer_to_write_plane',
}
MODES = IMPLEMENTATION | DEFERRED | {'reference_only'}

GROUP_MODES = {
    'pinna-write-plane': 'defer_to_write_plane',
    'ledger-controller': 'legacy_governance_only',
    'disablement-governance': 'legacy_governance_only',
    'codex-tooling': 'repository_tooling',
    'google-canary': 'defer_to_google_phase',
    'funnel': 'defer_to_funnel_integration',
    'operator-conductor': 'reimplement_clean',
}


def path_routing_group(path: str) -> str | None:
    """Canonical ADR §9.2 system-group classification by source path."""
    if path.startswith('scripts/google_ads/pinna5109/'):
        return 'pinna-write-plane'
    if path.startswith(('scripts/autonomy/', 'tests/autonomy/')):
        return 'ledger-controller'
    if 'service_account' in path.lower():
        return 'disablement-governance'
    if path.startswith('docs/harness/bin/') or path == 'tests/test_codex_gate.py':
        return 'codex-tooling'
    if 'google_canary' in path:
        return 'google-canary'
    if 'funnel' in path:
        return 'funnel'
    if path == 'scripts/operator/conductor.py':
        return 'operator-conductor'
    if path == SECURITY_PATH:
        return 'security-invariants'
    return None


# ---------------------------------------------------------------------------
# Selectors and Source Inventory
# ---------------------------------------------------------------------------


def whole_file(raw: bytes, mode: str) -> dict:
    return {
        'selector_kind': 'whole_file',
        'byte_range': [0, len(raw)],
        'raw_span_digest': digest(raw),
        'file_mode': mode,
    }


def text_region(raw: bytes, start: int, end: int) -> dict:
    return {
        'selector_kind': 'text_region',
        'selector_abi': TEXT_ABI,
        'byte_range': [start, end],
        'raw_span_digest': digest(raw[start:end]),
    }


def ast_symbols(raw: bytes) -> list[dict]:
    if sys.implementation.name != 'cpython' or sys.version_info[:2] != (3, 12):
        raise ValueError('selector: requires actual CPython 3.12, not feature_version emulation')
    try:
        decoded = raw.decode('utf-8')
        tree = ast.parse(decoded)
    except (UnicodeDecodeError, SyntaxError) as exc:
        raise ValueError('selector: source must parse as UTF-8 Python 3.12') from exc
    starts = [0]
    starts.extend(match.end() for match in re.finditer(rb'\r\n|\r|\n', raw))
    symbols = []

    def visit(node: ast.AST, parents: list[str]) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            name = '.'.join([*parents, node.name])
            start = starts[node.lineno - 1] + node.col_offset
            end = starts[node.end_lineno - 1] + node.end_col_offset
            symbols.append({
                'selector_kind': 'ast_symbol',
                'symbol_name': name,
                'parser_abi': AST_ABI,
                'byte_range': [start, end],
                'raw_span_digest': digest(raw[start:end]),
                'ast_digest': digest(ast.unparse(node).encode('utf-8')),
            })
            parents = [*parents, node.name]
        for child in ast.iter_child_nodes(node):
            visit(child, parents)

    visit(tree, [])
    return symbols


def partition_python(raw: bytes) -> list[dict]:
    """Select outermost definitions plus every intervening raw byte region.

    Nested definitions stay within their enclosing symbol; decorators and module
    data stay visible in residual regions. Their target decision is not inferred.
    """
    all_symbols = sorted(ast_symbols(raw), key=lambda s: (s['byte_range'][0], -s['byte_range'][1]))
    chosen = []
    end = 0
    for symbol in all_symbols:
        start, stop = symbol['byte_range']
        if start < end:
            continue
        if start > end:
            chosen.append(text_region(raw, end, start))
        chosen.append(symbol)
        end = stop
    if end < len(raw):
        chosen.append(text_region(raw, end, len(raw)))
    return chosen or [whole_file(raw, '100644')]


def validate_selector(raw: bytes, mode: str, selector: dict, symbols=None) -> None:
    if not isinstance(selector, dict):
        raise ValueError('selector: expected object')
    kind = selector.get('selector_kind')
    fields = {'selector_kind', 'byte_range', 'raw_span_digest'}
    extra = {
        'whole_file': {'file_mode'},
        'text_region': {'selector_abi'},
        'ast_symbol': {'symbol_name', 'parser_abi', 'ast_digest'},
    }
    if not isinstance(kind, str) or kind not in extra:
        raise ValueError('selector: unknown kind')
    exact_fields(selector, fields | extra[kind], 'selector')
    span = selector['byte_range']
    if (not isinstance(span, list) or len(span) != 2 or any(type(v) is not int for v in span)
            or not 0 <= span[0] <= span[1] <= len(raw)
            or (span[0] == span[1] and not (kind == 'whole_file' and len(raw) == 0))):
        raise ValueError('selector: invalid half-open byte range')
    if kind == 'whole_file':
        expected = whole_file(raw, mode)
    elif kind == 'text_region':
        expected = text_region(raw, *span)
    else:
        candidates = ast_symbols(raw) if symbols is None else symbols
        expected = next(
            (s for s in candidates if s['symbol_name'] == selector['symbol_name'] and s['byte_range'] == span),
            None,
        )
    if selector != expected:
        raise ValueError('selector: source/ABI/range/digest mismatch')


def coverage_role(path: str) -> str:
    if '/fixtures/' in path:
        return 'fixture'
    if path.startswith('tests/'):
        return 'test'
    if path.endswith('.md'):
        return 'documentation'
    if path.startswith('config/') or path.endswith(('.yaml', '.json', '.sha256')):
        return 'contract'
    return 'production_source'


def make_item(path: str, selector: dict) -> dict:
    sd = json_digest(selector)
    identity = {
        'repository': scope.REPOSITORY,
        'commit_sha': scope.BASELINE,
        'source_path': path,
        'source_selector_digest': sd,
    }
    return {
        'inventory_id': 'source-unit:' + json_digest(identity).removeprefix('sha256:'),
        'source_path': path,
        'source_selector': copy.deepcopy(selector),
        'source_selector_digest': sd,
        'source_digest': selector.get('ast_digest', selector['raw_span_digest']),
        'coverage_role': coverage_role(path),
    }


def _path_items(source: scope.SourceSnapshot, path: str, selected: list) -> list:
    raw = source.files[path]
    if not isinstance(selected, list) or not selected:
        raise ValueError('inventory: every path requires nonempty selectors')
    if any(not isinstance(s, dict) for s in selected):
        raise ValueError('inventory: selectors must be objects')
    symbols = ast_symbols(raw) if any(s.get('selector_kind') == 'ast_symbol' for s in selected) else []
    for s in selected:
        validate_selector(raw, source.modes[path], s, symbols)
    if path == SECURITY_PATH:
        expected = partition_python(raw)
        ordered = sorted(selected, key=lambda s: s['byte_range'])
        if ordered != expected or any(s['selector_kind'] == 'whole_file' for s in ordered):
            raise ValueError('inventory: security file requires canonical AST/residual partition in draft v1')
    spans = sorted(s['byte_range'] for s in selected)
    end = 0
    for start, stop in spans:
        if start < end:
            raise ValueError('inventory: overlap not supported in draft v1; select disjoint units')
        if start != end:
            raise ValueError('inventory: uncovered byte gap')
        end = stop
    if end != len(raw):
        raise ValueError('inventory: uncovered tail bytes')
    result = [make_item(path, s) for s in selected]
    if len({i['inventory_id'] for i in result}) != len(result):
        raise ValueError('inventory: duplicate selectors')
    return result


def resolve_inventory(source: scope.SourceSnapshot, selections: dict | None = None) -> dict:
    if selections is None:
        selections = {
            p: (partition_python(source.files[p]) if p == SECURITY_PATH
                else [whole_file(source.files[p], source.modes[p])])
            for p in source.paths
        }
    if not isinstance(selections, dict) or set(selections) != set(source.files):
        raise ValueError('inventory: selected paths must equal complete pinned source paths')
    items = [i for p in source.paths for i in _path_items(source, p, selections[p])]
    items.sort(key=lambda i: i['inventory_id'].encode('utf-8'))
    inventory = {
        '$schema': 'smart_ads/source_inventory/v1',
        'repository': scope.REPOSITORY,
        'commit_sha': scope.BASELINE,
        'inventory_scope': source.inventory_scope(),
        'declared_paths': source.paths,
        'declared_paths_digest': json_digest(source.paths),
        'items': items,
    }
    inventory['inventory_digest'] = json_digest(inventory)
    return inventory


def validate_inventory(source: scope.SourceSnapshot, inventory: dict) -> None:
    exact_fields(
        inventory,
        {
            '$schema', 'repository', 'commit_sha', 'inventory_scope',
            'declared_paths', 'declared_paths_digest', 'inventory_digest', 'items',
        },
        'inventory',
    )
    if not isinstance(inventory['items'], list):
        raise ValueError('inventory: items must be a list')
    selections = {p: [] for p in source.paths}
    for item in inventory['items']:
        exact_fields(
            item,
            {
                'inventory_id', 'source_path', 'source_selector',
                'source_selector_digest', 'source_digest', 'coverage_role',
            },
            'inventory item',
        )
        path = item['source_path']
        if not isinstance(path, str) or path not in selections:
            raise ValueError('inventory: unexpected source path')
        selections[path].append(item['source_selector'])
    if inventory != resolve_inventory(source, selections):
        raise ValueError('inventory: recomputed identity/digest/order mismatch')


# ---------------------------------------------------------------------------
# Target Selectors and Assemblies
# ---------------------------------------------------------------------------


def validate_target(entry: dict, item: dict) -> None:
    value = entry['target_selector']
    if value is None:
        return
    if not isinstance(value, dict) or entry['target_path'] is None:
        raise ValueError('target: selector requires an implementation path')
    if value.get('selector_kind') == 'retained_source':
        exact_fields(
            value,
            {'selector_kind', 'inventory_id', 'source_commit', 'source_selector_digest'},
            'retained target',
        )
        if (value['inventory_id'] != item['inventory_id']
                or value['source_commit'] != scope.BASELINE
                or value['source_selector_digest'] != item['source_selector_digest']
                or entry['target_repository'] != scope.REPOSITORY
                or entry['target_layer'] != 'legacy_governance'
                or entry['target_path'] != item['source_path']
                or entry['migration_mode'] != 'legacy_governance_only'):
            raise ValueError('target: retained span must identify the unchanged legacy source')
    elif value.get('selector_kind') == 'planned_assembly_member':
        exact_fields(
            value,
            {'selector_kind', 'assembly_id', 'inventory_id', 'role', 'companion_inventory_id'},
            'assembly member',
        )
        if (value['inventory_id'] != item['inventory_id']
                or value['role'] not in ('decorator', 'definition')
                or not isinstance(value['assembly_id'], str)
                or re.fullmatch(r'sha256:[0-9a-f]{64}', value['assembly_id']) is None
                or entry['target_repository'] != 'aiconnai/smart-ads'
                or entry['target_layer'] != 'repository_tooling'
                or entry['migration_mode'] != 'split_by_invariant'):
            raise ValueError('target: invalid planned assembly member')
    else:
        raise ValueError('target: unsupported selector kind')


def assembly_id(entries: list[dict]) -> str:
    return json_digest({
        'target_repository': entries[0]['target_repository'],
        'target_layer': entries[0]['target_layer'],
        'target_path': entries[0]['target_path'],
        'members': sorted(e['inventory_id'] for e in entries),
        'rule': 'decorator_before_definition_clean_reimplementation_v1',
    })


def _assembly(source, items: dict, entries: list[dict]) -> None:
    if len(entries) != 2 or {e['target_selector']['role'] for e in entries} != {'decorator', 'definition'}:
        raise ValueError('target: assembly requires exactly one decorator and one definition')
    by_role = {e['target_selector']['role']: e for e in entries}
    dec_entry, definition = by_role['decorator'], by_role['definition']
    a, b = items[dec_entry['inventory_id']], items[definition['inventory_id']]
    sa, sb = a['source_selector'], b['source_selector']
    if (a['source_path'] != b['source_path'] or sa['selector_kind'] != 'text_region'
            or sb['selector_kind'] != 'ast_symbol' or sa['byte_range'][1] != sb['byte_range'][0]
            or not source.files[a['source_path']][slice(*sa['byte_range'])].lstrip().startswith(b'@')):
        raise ValueError('target: assembly members must be adjacent decorator and AST definition')
    for entry, other in ((dec_entry, definition), (definition, dec_entry)):
        target = entry['target_selector']
        if target['assembly_id'] != assembly_id(entries) or target['companion_inventory_id'] != other['inventory_id']:
            raise ValueError('target: assembly identity/companion mismatch')
    for field in (
        'target_layer', 'migration_mode', 'decision_status', 'system_owner',
        'preserved_invariants', 'required_tests', 'compatibility_surface', 'blocking_defects',
    ):
        if canonicalize(dec_entry[field]) != canonicalize(definition[field]):
            raise ValueError('target: coupled assembly dispositions disagree')


def _validate_target_groups(source, items: dict, entries: list[dict]) -> None:
    groups = defaultdict(list)
    for e in entries:
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


def validate_targets(source, inventory: dict, entries: list[dict]) -> None:
    items = {i['inventory_id']: i for i in inventory['items']}
    for e in entries:
        validate_target(e, items[e['inventory_id']])
    _validate_target_groups(source, items, entries)


# ---------------------------------------------------------------------------
# Caller-Supplied Decisions
# ---------------------------------------------------------------------------


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
    roots = {
        ('aiconnai/smart-ads', 'core_engine'): ('src/smart_ads/', 'tests/'),
        ('aiconnai/smart-ads', 'data_plane'): ('src/smart_ads/', 'tests/'),
        ('aiconnai/smart-ads', 'repository_tooling'): ('tooling/governance/', 'tests/'),
        ('limaronaldo/hermes-ronaldo', 'consumer_integration'): ('',),
        ('mbras-tech/mbras-campaigns', 'legacy_governance'): ('',),
        ('runtime-private', 'data_plane'): ('',),
    }
    if (repo, layer) not in roots or not any(path.startswith(p) for p in roots[(repo, layer)]):
        raise ValueError('decision: target path/repository/layer mismatch')


def _deferral_ref(ref: object) -> None:
    exact_fields(
        ref,
        {'repository', 'commit_sha', 'path', 'file_content_sha256', 'section'},
        'deferral_authority_ref',
    )
    # Exact protected ADR bytes at Gate 2, not a producer-selected paragraph.
    expected = {
        'repository': 'aiconnai/smart-ads',
        'commit_sha': 'a3f19ef668748c64c5c679710c231426c5e05f6a',
        'path': 'docs/adr/ADR-0001-smart-ads-read-gateway.md',
        'file_content_sha256': 'sha256:239b53e0af44c176b78c363dc271c9fd882910bd4ab2ffb6844cb8fb2458640e',
        'section': '9.2',
    }
    if ref != expected:
        raise ValueError('decision: deferral must cite the exact approved ADR §9.2')


def _routing(entry: dict, item: dict) -> None:
    path = item['source_path']
    mode = entry['migration_mode']
    group = path_routing_group(path)
    required = GROUP_MODES.get(group) if group not in (None, 'operator-conductor', 'security-invariants') else None
    if group == 'pinna-write-plane' and mode not in (None, required):
        raise ValueError('decision: Pinna must remain deferred to the Write Plane')
    if required and mode not in (None, required):
        raise ValueError('decision: migration mode contradicts the ADR system disposition')
    if path == SECURITY_PATH and item['source_selector']['selector_kind'] == 'whole_file':
        raise ValueError('decision: security boundary file requires invariant-level split')
    if required == 'legacy_governance_only' and entry['decision_status'] is not None:
        if entry['target_repository'] != scope.REPOSITORY:
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
    validate_target(entry, item)
    _routing(entry, item)
    if status is None:  # Explicit unresolved input, never counted as an approved entry.
        return
    if status == 'approved':
        if mode not in IMPLEMENTATION | {'reference_only'}:
            raise ValueError('decision: approved status cannot defer')
        if entry['deferral_authority_ref'] is not None or entry['rejection_reason'] is not None:
            raise ValueError('decision: approved entries cannot carry deferral/rejection fields')
        if mode in IMPLEMENTATION and (
            entry['target_path'] is None or not entry['preserved_invariants'] or not entry['required_tests']
        ):
            raise ValueError('decision: implementation needs target, invariants and required tests')
        if entry['target_repository'] == 'none':
            raise ValueError('decision: approved destination cannot be none')
    elif status == 'deferred':
        if mode not in DEFERRED or entry['target_path'] is not None or entry['target_selector'] is not None:
            raise ValueError('decision: deferred entries forbid implementation targets')
        if entry['target_repository'] != scope.REPOSITORY or entry['rejection_reason'] is not None:
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
    return [
        {
            'inventory_id': i['inventory_id'], 'system_id': i['source_path'],
            'system_owner': None, 'target_repository': None, 'target_layer': None,
            'target_path': None, 'target_selector': None, 'migration_mode': None,
            'decision_status': None, 'deferral_authority_ref': None, 'rejection_reason': None,
            'preserved_invariants': [], 'compatibility_surface': [], 'blocking_defects': [],
            'required_tests': [],
        }
        for i in inventory['items']
    ]


# ---------------------------------------------------------------------------
# Candidate Manifest Builder & Verifier
# ---------------------------------------------------------------------------


def manifest_digest(value: dict) -> str:
    """D1 proposal: payload hash excludes manifest_digest and all of integrity.

    P1 itself remains unchanged; an eventual admitted envelope must separately
    bind the semantic digest, public key identity and registry locator.
    """
    return json_digest({k: v for k, v in value.items() if k not in {'manifest_digest', 'integrity'}})


def _ordered_entries(source, inventory: dict, entries: list, contract: str) -> list:
    if not isinstance(entries, list):
        raise ValueError('manifest: entries must be a list')
    items = {i['inventory_id']: i for i in inventory['items']}
    indexed = {}
    targets = set()
    for e in entries:
        if not isinstance(e, dict) or not isinstance(e.get('inventory_id'), str):
            raise ValueError('manifest: each entry needs an inventory ID')
        key = e['inventory_id']
        if key not in items or key in indexed:
            raise ValueError('manifest: extra or duplicate assignment')
        validate_entry(e, items[key])
        if contract == LEGACY_CONTRACT and e['target_selector'] is not None:
            raise ValueError('manifest: v1 forbids target selectors')
        if contract == LEGACY_CONTRACT and e['decision_status'] == 'approved' and e['target_path'] is not None:
            target = (e['target_repository'], e['target_path'])
            if target in targets:
                raise ValueError('manifest: shared target path not supported in draft v1')
            targets.add(target)
        indexed[key] = e
    if set(indexed) != set(items):
        raise ValueError('manifest: unassigned inventory items')
    if contract == CONTRACT:
        _validate_target_groups(source, items, list(indexed.values()))
    return [copy.deepcopy(indexed[k]) for k in sorted(indexed, key=lambda k: k.encode('utf-8'))]


def build_candidate(
    source: scope.SourceSnapshot,
    inventory: dict,
    entries: list,
    generated_at: str,
    contract: str = CONTRACT,
) -> dict:
    if contract not in (CONTRACT, LEGACY_CONTRACT):
        raise ValueError('manifest: unknown draft contract')
    timestamp(generated_at)
    validate_inventory(source, inventory)
    ordered = _ordered_entries(source, inventory, entries, contract)
    pending = sum(e['decision_status'] is None for e in ordered)
    defects = sum(bool(e['blocking_defects']) for e in ordered)
    count = len(inventory['items'])
    payload = {
        'generated_at': generated_at,
        'supersedes_manifest_locator': None,
        'supersedes_digest': None,
        'correction_reason': None,
        'source_inventory': copy.deepcopy(inventory),
        'coverage_assertion': {
            'inventory_item_count': count,
            'entry_count': count,
            'assigned_item_count': count,
            'unassigned_item_count': 0,
            'duplicate_assignment_count': 0,
            'conflict_count': 0,
        },
        'entries': ordered,
    }
    # This digest describes the candidate payload, not a final signed manifest.
    return {
        'artifact_kind': 'decomposition_candidate',
        'draft_contract': contract,
        'signable': False,
        'validation_status': 'INCOMPLETE' if pending or defects else 'STRUCTURALLY_VALID',
        'pending_decision_count': pending,
        'blocking_defect_entry_count': defects,
        'admission_blockers': list(BLOCKERS),
        'payload': payload,
        'candidate_payload_digest': manifest_digest(payload),
    }


def verify_candidate(source: scope.SourceSnapshot, candidate: dict) -> None:
    exact_fields(
        candidate,
        {
            'artifact_kind', 'draft_contract', 'signable', 'validation_status',
            'pending_decision_count', 'blocking_defect_entry_count',
            'admission_blockers', 'payload', 'candidate_payload_digest',
        },
        'candidate',
    )
    payload = candidate['payload']
    exact_fields(
        payload,
        {
            'generated_at', 'supersedes_manifest_locator', 'supersedes_digest',
            'correction_reason', 'source_inventory', 'coverage_assertion', 'entries',
        },
        'payload',
    )
    expected = build_candidate(
        source,
        payload['source_inventory'],
        payload['entries'],
        payload['generated_at'],
        candidate['draft_contract'],
    )
    if canonicalize(candidate) != canonicalize(expected):
        raise ValueError('candidate: recomputed content/digest/status mismatch')


def review_inputs(source: scope.SourceSnapshot, inventory: dict, unit_review: dict) -> dict:
    """Map reviewed proposals to pending v2 inputs, never to accepted decisions.

    The CLI verifies unit_review against immutable source/rules before this call.
    """
    entries = decision_template(inventory)
    proposals = {e['inventory_id']: e for e in unit_review['entries']}
    if len(proposals) != len(unit_review['entries']) or set(proposals) != {e['inventory_id'] for e in entries}:
        raise ValueError('target: review must cover inventory exactly once')
    items = {i['inventory_id']: i for i in inventory['items']}
    groups = defaultdict(list)
    for e in entries:
        p = proposals[e['inventory_id']]['proposal']
        for field in (
            'migration_mode', 'target_repository', 'target_layer',
            'target_path', 'preserved_invariants', 'required_tests',
        ):
            e[field] = copy.deepcopy(p[field])
        if e['target_path'] is not None:
            groups[(e['target_repository'], e['target_path'])].append(e)
    for group in groups.values():
        if len(group) < 2:
            continue
        if all(e['migration_mode'] == 'legacy_governance_only' for e in group):
            for e in group:
                e['target_selector'] = {
                    'selector_kind': 'retained_source',
                    'inventory_id': e['inventory_id'],
                    'source_commit': scope.BASELINE,
                    'source_selector_digest': items[e['inventory_id']]['source_selector_digest'],
                }
        else:
            if len(group) != 2:
                raise ValueError('target: unknown multi-member assembly')
            for e in group:
                other = next(x for x in group if x is not e)
                role = (
                    'definition'
                    if items[e['inventory_id']]['source_selector']['selector_kind'] == 'ast_symbol'
                    else 'decorator'
                )
                e['target_selector'] = {
                    'selector_kind': 'planned_assembly_member',
                    'assembly_id': assembly_id(group),
                    'inventory_id': e['inventory_id'],
                    'role': role,
                    'companion_inventory_id': other['inventory_id'],
                }
    build_candidate(source, inventory, entries, '2026-09-07T00:00:00Z')
    return {
        'artifact_kind': 'decomposition_inputs_draft',
        'draft_contract': CONTRACT,
        'inventory': copy.deepcopy(inventory),
        'entries': entries,
    }
