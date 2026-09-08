"""Evidence-bound per-unit migration proposals; no decisions are accepted here."""
from __future__ import annotations

import ast
import copy
from collections import Counter, defaultdict

from tools.governance.decomposition_common import digest, json_digest, source_path
from tools.governance.decomposition_decisions import decision_template, validate_entry
from tools.governance.decomposition_governance import ADR_DIGEST
from tools.governance.decomposition_review_rules import GROUPS, SECURITY_GROUPS
from tools.governance.decomposition_scope import SourceSnapshot, BASELINE, REPOSITORY
from tools.governance.decomposition_selectors import SECURITY_PATH, validate_inventory
from tools.governance.jcs import canonicalize


def _group(path: str) -> str:
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
    raise ValueError('review: source has no explicit analyst disposition')


def _path_rows(source: SourceSnapshot, proposal: dict) -> dict:
    if (proposal['source']['repository'] != REPOSITORY
            or proposal['source']['commit_sha'] != BASELINE):
        raise ValueError('review: path proposals name another source')
    rows = proposal['paths']
    indexed = {r['source_path']: r for r in rows}
    if len(indexed) != len(rows) or set(indexed) != set(source.paths):
        raise ValueError('review: path proposals must cover source exactly once')
    for path, row in indexed.items():
        if (row['source_file_digest'] != digest(source.files[path])
                or row['system_group'] != _group(path)):
            raise ValueError('review: path proposal differs from immutable source/group')
    return indexed


def _file_facts(source: SourceSnapshot, path: str) -> dict:
    raw = source.files[path]
    facts = {'source_path': path, 'raw_file_digest': digest(raw), 'bytes': len(raw),
             'lines': len(raw.splitlines()), 'outer_definitions': [], 'imports': [],
             'scan_scope': 'static names/imports, not transitive dependency or runtime proof'}
    if path.endswith('.py'):
        tree = ast.parse(raw.decode('utf-8'))
        facts['outer_definitions'] = [n.name for n in tree.body
                                      if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
        facts['imports'] = sorted({ast.unparse(n) for n in ast.walk(tree)
                                   if isinstance(n, (ast.Import, ast.ImportFrom))})
    return facts


def _whole_proposal(path: str, row: dict) -> dict:
    group = _group(path)
    modes = {'ledger-controller': 'legacy_governance_only', 'disablement-governance': 'legacy_governance_only',
             'codex-tooling': 'repository_tooling', 'funnel': 'defer_to_funnel_integration',
             'google-canary': 'defer_to_google_phase', 'pinna-write-plane': 'defer_to_write_plane',
             'operator-conductor': 'reimplement_clean'}
    expected_status = 'deferred' if modes[group].startswith('defer_') else 'approved'
    if row['migration_mode_proposed'] != modes[group] or row['decision_status_if_ratified'] != expected_status:
        raise ValueError('review: proposed path disposition contradicts the ADR group')
    if expected_status == 'deferred' and (
            row['target_repository_proposed'] != REPOSITORY
            or row['target_layer_proposed'] != 'legacy_governance'
            or row['target_path_proposed'] is not None):
        raise ValueError('review: deferral must retain the legacy repository without implementation target')
    if modes[group] == 'legacy_governance_only' and (
            row['target_repository_proposed'] != REPOSITORY
            or row['target_layer_proposed'] != 'legacy_governance'
            or row['target_path_proposed'] != path):
        raise ValueError('review: legacy governance must preserve its existing source location')
    rationale, invariants, tests = GROUPS[group]
    return {'analysis_group': group, 'migration_mode': row['migration_mode_proposed'],
            'decision_status_if_accepted': row['decision_status_if_ratified'],
            'target_repository': row['target_repository_proposed'],
            'target_layer': row['target_layer_proposed'], 'target_path': row['target_path_proposed'],
            'rationale': rationale, 'preserved_invariants': invariants,
            'required_tests': tests, 'test_evidence_status': 'planned_or_legacy_reference; not_executed',
            'target_selector': None}


def _security_proposal(item: dict, raw: bytes, symbols: list) -> tuple[dict, str | None]:
    selector = item['source_selector']
    start, end = selector['byte_range']
    segment = raw[start:end]
    following = next((s for s in symbols if s['source_selector']['byte_range'][0] >= end), None)
    linked = None
    if selector['selector_kind'] == 'ast_symbol':
        symbol = selector['symbol_name']
        group = SECURITY_GROUPS[symbol]
    elif not segment.strip():
        symbol, group = 'whitespace', 'source-whitespace'
    elif start == 0:
        symbol, group = 'module_context', 'security-module-context'
    elif segment.lstrip().startswith(b'@') and following is not None:
        symbol = following['source_selector']['symbol_name']
        group = SECURITY_GROUPS[symbol]
        linked = following['inventory_id']
    else:
        raise ValueError('review: unclassified security residual; analyst review required')
    rationale, invariants, tests = GROUPS[group]
    legacy = group.endswith('-legacy') or group == 'security-module-context'
    mode = 'reference_only' if group == 'source-whitespace' else (
        'legacy_governance_only' if legacy else 'split_by_invariant')
    target = None if group == 'source-whitespace' else (
        SECURITY_PATH if legacy else 'tests/security/decomposed/' + symbol.lstrip('_') + '.py')
    if target and not legacy:
        tests = [target] if symbol.startswith('test_') else ['tests/security/test_private_writer_fixtures.py']
    if linked:
        rationale += ' This residual contains the decorator/parameter corpus and must stay coupled to the following definition.'
    return {'analysis_group': group, 'migration_mode': mode,
            'decision_status_if_accepted': 'approved',
            'target_repository': REPOSITORY if legacy or target is None else 'aiconnai/smart-ads',
            'target_layer': 'legacy_governance' if legacy else ('repository_tooling' if target else None),
            'target_path': target, 'target_selector': None,
            'rationale': rationale, 'preserved_invariants': invariants, 'required_tests': tests,
            'test_evidence_status': 'planned_or_legacy_reference; not_executed'}, linked


def build_unit_review(source: SourceSnapshot, inventory: dict, path_proposals: dict) -> dict:
    validate_inventory(source, inventory)
    paths = _path_rows(source, path_proposals)
    security = sorted((i for i in inventory['items'] if i['source_path'] == SECURITY_PATH),
                      key=lambda i: i['source_selector']['byte_range'])
    symbols = [i for i in security if i['source_selector']['selector_kind'] == 'ast_symbol']
    nodes = {}
    if security:
        tree = ast.parse(source.files[SECURITY_PATH].decode('utf-8'))
        nodes = {n.name: n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.ClassDef))}
        if set(nodes) != set(SECURITY_GROUPS):
            raise ValueError('review: security definitions differ from explicit analyst rules')
    local_ids = {i['source_selector']['symbol_name']: i['inventory_id'] for i in symbols}
    references = []
    if security:
        line_starts = [0]
        for line in source.files[SECURITY_PATH].splitlines(keepends=True):
            line_starts.append(line_starts[-1] + len(line))
        references = [(line_starts[n.lineno - 1] + n.col_offset, local_ids[n.id])
                      for n in ast.walk(tree) if isinstance(n, ast.Name)
                      and isinstance(n.ctx, ast.Load) and n.id in local_ids]
    entries = []
    targets = defaultdict(list)
    for item in inventory['items']:
        path = item['source_path']; selector = item['source_selector']
        start, end = selector['byte_range']; raw = source.files[path]
        linked = None
        if path == SECURITY_PATH:
            disposition, linked = _security_proposal(item, raw, symbols)
        else:
            disposition = _whole_proposal(path, paths[path])
            probe = decision_template({'items': [item]})[0]
            probe.update({k: disposition[k] for k in ('migration_mode', 'target_repository', 'target_layer', 'target_path')})
            validate_entry(probe, item)
        if disposition['target_path'] is not None:
            source_path(disposition['target_path'])
            targets[(disposition['target_repository'], disposition['target_path'])].append(item['inventory_id'])
        deps = []
        if path == SECURITY_PATH:
            deps = sorted({target for offset, target in references
                           if start <= offset < end and target != item['inventory_id']})
        entries.append({'inventory_id': item['inventory_id'], 'source_path': path,
                        'source_selector_digest': item['source_selector_digest'],
                        'source_digest': item['source_digest'], 'source_selector': selector,
                        'line_range': [raw[:start].count(b'\n') + 1, raw[:max(start, end-1)].count(b'\n') + 1],
                        'proposal': disposition, 'human_decision': None, 'system_owner': None,
                        'authority_citation': {'adr_sha256': ADR_DIGEST, 'section': '9.2',
                                               'kind': 'source_requirement; not human ratification'},
                        'local_helper_inventory_ids': deps, 'following_symbol_inventory_id': linked})
    shared = [{'repository': repo, 'target_path': path, 'inventory_ids': ids,
               'resolution_required': 'target selectors/assembly contract; current draft rejects shared paths'}
              for (repo, path), ids in sorted(targets.items()) if len(ids) > 1]
    value = {'artifact_kind': 'decomposition_unit_review_proposals', 'authority': 'none',
             'signable': False, 'inventory_digest': inventory['inventory_digest'],
             'path_proposals_digest': json_digest(path_proposals),
             'unit_count': len(entries), 'human_decisions_recorded': 0,
             'group_counts': dict(sorted(Counter(e['proposal']['analysis_group'] for e in entries).items())),
             'file_facts': [_file_facts(source, p) for p in source.paths],
             'entries': entries, 'shared_target_groups': shared,
             'limitations': ['semantic review proposals, not accepted manifest entries',
                             'imports outside the source inventory are compatibility references, not added scope',
                             'tests name required work or preserved legacy tests; none were run from legacy',
                             'shared targets require the final selector/assembly contract before materialization']}
    value['review_digest'] = json_digest(value)
    return copy.deepcopy(value)


def validate_unit_review(value: dict, source: SourceSnapshot, inventory: dict, paths: dict) -> None:
    if canonicalize(value) != canonicalize(build_unit_review(source, inventory, paths)):
        raise ValueError('review: content, provenance or authority differs from recomputation')


def render_unit_review(value: dict) -> str:
    lines = ['# Revisão proposta das unidades de decomposição', '',
             'Propostas do executor, não aprovação humana. Nenhum código legado foi executado.', '',
             f"Unidades: {value['unit_count']}. Decisões humanas registradas: 0.",
             f"Digest da revisão: `{value['review_digest']}`.", '',
             'O JSON contém IDs completos, seletores/digests, invariantes, testes planejados e vínculos locais.',
             'A análise de arquivos inteiros combina a disposição do ADR com nomes/imports estáticos;',
             'não é certificação de runtime nem revisão de todas as linhas desses sistemas.',
             'Os testes citados são requisitos futuros ou referências legadas, não resultados executados.', '',
             '## Grupos e justificativas', '']
    for group, count in value['group_counts'].items():
        lines += [f'### {group} — {count}', '', GROUPS[group][0], '',
                  'Invariantes: ' + '; '.join(GROUPS[group][1]) + '.', '']
    index = {e['inventory_id']: e for e in value['entries']}
    short_ids = [e['inventory_id'].split(':')[1][:12] for e in value['entries']]
    if len(set(short_ids)) != len(short_ids):
        raise ValueError('review: abbreviated IDs collide; use longer display IDs')
    current_path = None
    for e in sorted(value['entries'], key=lambda e: (e['source_path'], e['source_selector']['byte_range'])):
        if e['source_path'] != current_path:
            current_path = e['source_path']
            lines += [f'## `{current_path}`', '', '| ID curto | Linhas | Unidade | Modo proposto | Destino proposto |',
                      '|---|---|---|---|---|']
        sel = e['source_selector']; p = e['proposal']
        label = sel.get('symbol_name', sel['selector_kind'])
        if e['following_symbol_inventory_id']:
            label = 'decorador de ' + index[e['following_symbol_inventory_id']]['source_selector']['symbol_name']
        target = p['target_repository'] + (':' + p['target_path'] if p['target_path'] else ' (sem implementação)')
        short = e['inventory_id'].split(':')[1][:12]
        lines.append(f"| `{short}` | {e['line_range'][0]}–{e['line_range'][1]} | `{label}` | `{p['migration_mode']}` | `{target}` |")
    lines += ['', '## Destinos compartilhados — materialização pendente', '',
              'Não renomear artificialmente arquivos legados nem soltar decoradores de suas funções.',
              'O draft atual recusa esses grupos; o contrato final de seletores/assembly deve resolvê-los.', '']
    for group in value['shared_target_groups']:
        lines.append(f"- `{group['repository']}:{group['target_path']}`: {len(group['inventory_ids'])} unidades.")
    return '\n'.join(lines) + '\n'
