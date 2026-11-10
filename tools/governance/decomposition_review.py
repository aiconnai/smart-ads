"""Evidence-bound per-unit migration proposals; no decisions are accepted here."""
from __future__ import annotations

import ast
from collections import Counter, defaultdict
import copy
from pathlib import Path

from tools.governance import decomposition as dec
from tools.governance.decomposition_admission import build_admission_proposal
from tools.governance.decomposition_governance import ADR_DIGEST, REPO_ROOT
from tools.governance.decomposition_scope import BASELINE, REPOSITORY, SourceSnapshot
from tools.governance.jcs import canonicalize, loads_strict
from tools.governance.locator import digest, json_digest, source_path

GROUPS = {
    'ledger-controller': (
        'Preserve the legacy lease, outbox, approval and recovery machinery; do not import it into the read gateway.',
        ['append-only recovery evidence', 'approval and idempotency binding', 'legacy state remains authoritative'],
        ['tests/autonomy/test_controller.py', 'tests/autonomy/test_ledger.py']),
    'disablement-governance': (
        'Retain the historical packet/template lifecycle under legacy governance; no credential action follows from decomposition.',
        ['immutable preparatory packet', 'separate human lifecycle checkpoints', 'no reuse of consumed authorization'],
        ['tests/test_service_account_disablement_authorization.py', 'tests/test_service_account_disablement_packet.py']),
    'codex-tooling': (
        'Rehome gates and scanners as repository tooling with their negative fixtures; exclude them from the distributable wheel.',
        ['trusted-base policy', 'complete range and payload coverage', 'no secrets in receipts', 'wheel excludes tooling'],
        ['tests/security/test_codex_gate.py']),
    'funnel': (
        'Defer the validator, schema and tests together. The read-gateway draft does not implement funnel publication semantics.',
        ['closed schemas and duplicate-key rejection', 'exact Decimal and time semantics', 'privacy and suppression gates'],
        ['tests/test_funnel_contract.py']),
    'google-canary': (
        'Defer the bounded canary, transport and fixtures to the Google phase; retain one-shot invocation and diagnostic limits.',
        ['explicit activation', 'consumed invocation cannot replay', 'bounded time/bytes/requests', 'sanitized output'],
        ['tests/operator/test_google_canary.py', 'tests/operator/test_google_canary_transport.py']),
    'pinna-write-plane': (
        'Defer the entire directory, including helpers, config and README, to the Write Plane. No mutation code is ported into read delivery.',
        ['human approval for writes', 'no inferred permission from helper purity', 'Customer Match data remains private'],
        []),
    'operator-conductor': (
        'Cleanly reimplement supplied-outcome orchestration; preserve validate/reduce/analyze ordering with collection owned by the host.',
        ['no collection inside conductor', 'canonical validated outcome', 'provider-agnostic injected intelligence'],
        ['tests/unit/test_conductor.py']),
    'security-filesystem': (
        'Reimplement the privacy invariant with synthetic fixtures; do not import the Pinna exporter or copy live output paths.',
        ['private file 0600 and directory 0700', 'reject symlink targets', 'retain opened directory under path swap', 'preserve existing parent mode'],
        []),
    'security-meta': (
        'Reimplement transport secrecy and allowlist tests with a fake read port. Legacy tests are evidence, not authorization for Graph I/O.',
        ['token only in header', 'allowlisted host before I/O', 'provider error bodies and exception chains stay value-silent'],
        []),
    'security-meta-mixed-write': (
        'This symbol also exercises POST. Preserve header/body sanitization as an invariant, but make read-gateway mutation attempts reject with zero I/O.',
        ['token stripped from query and payload', 'read path uses allowlisted host', 'POST path denied with zero provider calls'],
        []),
    'security-private-data': (
        'Port the output-exclusion invariant with synthetic file names; raw leads and exporter code do not enter the wheel.',
        ['sensitive outputs untracked and ignored', 'no raw lead data in docs or receipts'],
        []),
    'security-database-legacy': (
        'Keep the existing database diagnostic/document guard in legacy; it inspects files outside the 44-path source inventory.',
        ['diagnostics do not print environment values', 'static placeholders only', 'historical guide has no connection values'],
        ['tests/test_security_boundaries.py']),
    'security-history-legacy': (
        'Retain canonicalization helpers and historical authorization/disablement guards in legacy with their pinned documents and negative corpus.',
        ['exact historical digest', 'non-authorizing prose stays non-authorizing', 'value-silent metadata', 'encoded/confusable bypass rejection'],
        ['tests/test_security_boundaries.py']),
    'security-module-context': (
        'Retain mixed imports and historical constants as context. A clean target must select its own imports and fixtures; do not copy the module prefix.',
        ['no exporter/database imports in new tooling tests', 'historical constants remain bound to legacy guards'],
        ['tests/test_security_boundaries.py']),
    'source-whitespace': (
        'Account for these bytes without creating implementation. Whitespace has no independent destination or equivalence test.',
        ['source bytes remain covered'], []),
}

# Exact outer-definition names at the pinned baseline; unknown symbols reject.
SECURITY_GROUPS = {
    'test_private_output_normalization_does_not_exempt_arbitrary_root_paths': 'security-filesystem',
    'test_meta_request_uses_header_and_strips_query_tokens': 'security-meta-mixed-write',
    'test_meta_transport_rejects_non_allowlisted_host': 'security-meta',
    'test_meta_api_error_body_is_not_propagated': 'security-meta',
    'test_meta_transport_error_never_exposes_token': 'security-meta',
    'test_database_diagnostic_uri_uses_only_static_placeholders': 'security-database-legacy',
    'test_database_diagnostic_main_never_prints_supplied_values': 'security-database-legacy',
    'test_database_status_document_has_no_concrete_connection_values': 'security-database-legacy',
    '_canonicalize_historical_inventory_for_scan': 'security-history-legacy',
    '_metadata_field_values': 'security-history-legacy',
    '_assert_sanitized_scan_is_value_silent': 'security-history-legacy',
    '_assert_historical_inventory_semantics': 'security-history-legacy',
    '_assert_historical_inventory_is_value_silent': 'security-history-legacy',
    'test_historical_service_account_inventory_stays_value_silent': 'security-history-legacy',
    'test_historical_inventory_guard_rejects_sensitive_variants': 'security-history-legacy',
    'test_historical_inventory_guard_preserves_non_authorizing_history': 'security-history-legacy',
    'test_historical_inventory_guard_allows_harmless_prose_reflow': 'security-history-legacy',
    'test_historical_inventory_semantics_allow_harmless_latin_prose': 'security-history-legacy',
    'test_historical_inventory_semantics_allow_benign_pt_prose_across_line_break': 'security-history-legacy',
    'test_historical_inventory_semantics_reject_cross_line_pt_authorization': 'security-history-legacy',
    'test_historical_inventory_semantics_fail_closed_on_unreviewed_prose': 'security-history-legacy',
    '_assert_disablement_packet_semantics': 'security-history-legacy',
    '_assert_disablement_packet_is_value_silent': 'security-history-legacy',
    'test_disablement_packet_stays_value_silent_and_immutable': 'security-history-legacy',
    'test_disablement_packet_semantics_allow_safe_test_suffixes': 'security-history-legacy',
    'test_disablement_packet_raw_digest_rejects_rendering_sensitive_whitespace': 'security-history-legacy',
    'test_disablement_packet_guard_rejects_sensitive_variants': 'security-history-legacy',
    'test_disablement_packet_guard_is_immutable_against_edits': 'security-history-legacy',
    'test_lead_annex_outputs_are_covered_by_git_ignore': 'security-private-data',
    'test_meta_clients_use_shared_safe_transport': 'security-meta-mixed-write',
    'test_root_lead_generators_use_private_atomic_writer': 'security-private-data',
    'test_private_root_file_preserves_existing_parent_mode': 'security-filesystem',
    '_write_test_csv': 'security-filesystem',
    '_write_test_json': 'security-filesystem',
    '_write_test_html': 'security-filesystem',
    'test_sensitive_writers_enforce_private_modes_under_permissive_umask': 'security-filesystem',
    'test_sensitive_writers_reject_symlink_file_targets': 'security-filesystem',
    'test_sensitive_writers_reject_symlink_directories': 'security-filesystem',
    'test_sensitive_writer_retains_open_directory_when_path_is_swapped': 'security-filesystem',
}


def _group(path: str) -> str:
    group = dec.path_routing_group(path)
    if group is None:
        raise ValueError('review: source has no explicit analyst disposition')
    return group


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
    facts = {
        'source_path': path, 'raw_file_digest': digest(raw), 'bytes': len(raw),
        'lines': len(raw.splitlines()), 'outer_definitions': [], 'imports': [],
        'scan_scope': 'static names/imports, not transitive dependency or runtime proof',
    }
    if path.endswith('.py'):
        tree = ast.parse(raw.decode('utf-8'))
        facts['outer_definitions'] = [
            n.name for n in tree.body
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        ]
        facts['imports'] = sorted({
            ast.unparse(n) for n in ast.walk(tree)
            if isinstance(n, (ast.Import, ast.ImportFrom))
        })
    return facts


def _whole_proposal(path: str, row: dict) -> dict:
    group = _group(path)
    expected_mode = dec.GROUP_MODES[group]
    expected_status = 'deferred' if expected_mode.startswith('defer_') else 'approved'
    if row['migration_mode_proposed'] != expected_mode or row['decision_status_if_ratified'] != expected_status:
        raise ValueError('review: proposed path disposition contradicts the ADR group')
    if expected_status == 'deferred' and (
            row['target_repository_proposed'] != REPOSITORY
            or row['target_layer_proposed'] != 'legacy_governance'
            or row['target_path_proposed'] is not None):
        raise ValueError('review: deferral must retain the legacy repository without implementation target')
    if expected_mode == 'legacy_governance_only' and (
            row['target_repository_proposed'] != REPOSITORY
            or row['target_layer_proposed'] != 'legacy_governance'
            or row['target_path_proposed'] != path):
        raise ValueError('review: legacy governance must preserve its existing source location')
    rationale, invariants, tests = GROUPS[group]
    return {
        'analysis_group': group,
        'migration_mode': row['migration_mode_proposed'],
        'decision_status_if_accepted': row['decision_status_if_ratified'],
        'target_repository': row['target_repository_proposed'],
        'target_layer': row['target_layer_proposed'],
        'target_path': row['target_path_proposed'],
        'rationale': rationale,
        'preserved_invariants': invariants,
        'required_tests': tests,
        'test_evidence_status': 'planned_or_legacy_reference; not_executed',
        'target_selector': None,
    }


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
        dec.SECURITY_PATH if legacy else 'tests/security/decomposed/' + symbol.lstrip('_') + '.py')
    if target and not legacy:
        tests = [target] if symbol.startswith('test_') else ['tests/security/test_private_writer_fixtures.py']
    if linked:
        rationale += ' This residual contains the decorator/parameter corpus and must stay coupled to the following definition.'
    return {
        'analysis_group': group,
        'migration_mode': mode,
        'decision_status_if_accepted': 'approved',
        'target_repository': REPOSITORY if legacy or target is None else 'aiconnai/smart-ads',
        'target_layer': 'legacy_governance' if legacy else ('repository_tooling' if target else None),
        'target_path': target,
        'target_selector': None,
        'rationale': rationale,
        'preserved_invariants': invariants,
        'required_tests': tests,
        'test_evidence_status': 'planned_or_legacy_reference; not_executed',
    }, linked


def build_unit_review(source: SourceSnapshot, inventory: dict, path_proposals: dict) -> dict:
    dec.validate_inventory(source, inventory)
    paths = _path_rows(source, path_proposals)
    security = sorted(
        (i for i in inventory['items'] if i['source_path'] == dec.SECURITY_PATH),
        key=lambda i: i['source_selector']['byte_range'],
    )
    symbols = [i for i in security if i['source_selector']['selector_kind'] == 'ast_symbol']
    nodes = {}
    if security:
        tree = ast.parse(source.files[dec.SECURITY_PATH].decode('utf-8'))
        nodes = {n.name: n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.ClassDef))}
        if set(nodes) != set(SECURITY_GROUPS):
            raise ValueError('review: security definitions differ from explicit analyst rules')
    local_ids = {i['source_selector']['symbol_name']: i['inventory_id'] for i in symbols}
    references = []
    if security:
        line_starts = [0]
        for line in source.files[dec.SECURITY_PATH].splitlines(keepends=True):
            line_starts.append(line_starts[-1] + len(line))
        references = [
            (line_starts[n.lineno - 1] + n.col_offset, local_ids[n.id])
            for n in ast.walk(tree)
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load) and n.id in local_ids
        ]
    entries = []
    targets = defaultdict(list)
    for item in inventory['items']:
        path = item['source_path']
        selector = item['source_selector']
        start, end = selector['byte_range']
        raw = source.files[path]
        linked = None
        if path == dec.SECURITY_PATH:
            disposition, linked = _security_proposal(item, raw, symbols)
        else:
            disposition = _whole_proposal(path, paths[path])
            probe = dec.decision_template({'items': [item]})[0]
            probe.update({
                k: disposition[k]
                for k in ('migration_mode', 'target_repository', 'target_layer', 'target_path')
            })
            dec.validate_entry(probe, item)
        if disposition['target_path'] is not None:
            source_path(disposition['target_path'])
            targets[(disposition['target_repository'], disposition['target_path'])].append(item['inventory_id'])
        deps = []
        if path == dec.SECURITY_PATH:
            deps = sorted({
                target for offset, target in references
                if start <= offset < end and target != item['inventory_id']
            })
        entries.append({
            'inventory_id': item['inventory_id'],
            'source_path': path,
            'source_selector_digest': item['source_selector_digest'],
            'source_digest': item['source_digest'],
            'source_selector': selector,
            'line_range': [raw[:start].count(b'\n') + 1, raw[:max(start, end - 1)].count(b'\n') + 1],
            'proposal': disposition,
            'human_decision': None,
            'system_owner': None,
            'authority_citation': {
                'adr_sha256': ADR_DIGEST,
                'section': '9.2',
                'kind': 'source_requirement; not human ratification',
            },
            'local_helper_inventory_ids': deps,
            'following_symbol_inventory_id': linked,
        })
    shared = [
        {
            'repository': repo,
            'target_path': path,
            'inventory_ids': ids,
            'resolution_required': 'target selectors/assembly contract; current draft rejects shared paths',
        }
        for (repo, path), ids in sorted(targets.items()) if len(ids) > 1
    ]
    value = {
        'artifact_kind': 'decomposition_unit_review_proposals',
        'authority': 'none',
        'signable': False,
        'inventory_digest': inventory['inventory_digest'],
        'path_proposals_digest': json_digest(path_proposals),
        'unit_count': len(entries),
        'human_decisions_recorded': 0,
        'group_counts': dict(sorted(Counter(e['proposal']['analysis_group'] for e in entries).items())),
        'file_facts': [_file_facts(source, p) for p in source.paths],
        'entries': entries,
        'shared_target_groups': shared,
        'limitations': [
            'semantic review proposals, not accepted manifest entries',
            'imports outside the source inventory are compatibility references, not added scope',
            'tests name required work or preserved legacy tests; none were run from legacy',
            'shared targets require the final selector/assembly contract before materialization',
        ],
    }
    value['review_digest'] = json_digest(value)
    return copy.deepcopy(value)


def validate_unit_review(value: dict, source: SourceSnapshot, inventory: dict, paths: dict) -> None:
    if canonicalize(value) != canonicalize(build_unit_review(source, inventory, paths)):
        raise ValueError('review: content, provenance or authority differs from recomputation')


def build_review_bundle(
    source: SourceSnapshot, root: Path = REPO_ROOT
) -> tuple[dict, dict]:
    """Assemble the non-authorizing review bundle and return `(inventory, bundle)`."""
    inventory = dec.resolve_inventory(source)
    path_proposals = loads_strict(
        (root / 'docs/governance/decomposition/path-dispositions.proposed.json').read_text(encoding='utf-8')
    )
    if not isinstance(path_proposals, dict):
        raise ValueError('decomposition: input must be an object')
    bundle = {
        'artifact_kind': 'decomposition_review_bundle',
        'authority': 'none',
        'signable': False,
        'admission_proposal': build_admission_proposal(
            (root / 'docs/adr/ADR-0001-smart-ads-read-gateway.md').read_bytes(),
            (root / 'docs/governance/trust-anchor/cell_trust_anchor_config.json').read_bytes(),
        ),
        'unit_review': build_unit_review(source, inventory, path_proposals),
    }
    return inventory, bundle


def render_unit_review(value: dict) -> str:
    lines = [
        '# Revisão proposta das unidades de decomposição', '',
        'Propostas do executor, não aprovação humana. Nenhum código legado foi executado.', '',
        f"Unidades: {value['unit_count']}. Decisões humanas registradas: 0.",
        f"Digest da revisão: `{value['review_digest']}`.", '',
        'O JSON contém IDs completos, seletores/digests, invariantes, testes planejados e vínculos locais.',
        'A análise de arquivos inteiros combina a disposição do ADR com nomes/imports estáticos;',
        'não é certificação de runtime nem revisão de todas as linhas desses sistemas.',
        'Os testes citados são requisitos futuros ou referências legadas, não resultados executados.', '',
        '## Grupos e justificativas', '',
    ]
    for group, count in value['group_counts'].items():
        lines += [
            f'### {group} — {count}', '', GROUPS[group][0], '',
            'Invariantes: ' + '; '.join(GROUPS[group][1]) + '.', '',
        ]
    index = {e['inventory_id']: e for e in value['entries']}
    short_ids = [e['inventory_id'].split(':')[1][:12] for e in value['entries']]
    if len(set(short_ids)) != len(short_ids):
        raise ValueError('review: abbreviated IDs collide; use longer display IDs')
    current_path = None
    for e in sorted(value['entries'], key=lambda e: (e['source_path'], e['source_selector']['byte_range'])):
        if e['source_path'] != current_path:
            current_path = e['source_path']
            lines += [
                f'## `{current_path}`', '',
                '| ID curto | Linhas | Unidade | Modo proposto | Destino proposto |',
                '|---|---|---|---|---|',
            ]
        sel = e['source_selector']
        p = e['proposal']
        label = sel.get('symbol_name', sel['selector_kind'])
        if e['following_symbol_inventory_id']:
            label = 'decorador de ' + index[e['following_symbol_inventory_id']]['source_selector']['symbol_name']
        target = p['target_repository'] + (':' + p['target_path'] if p['target_path'] else ' (sem implementação)')
        short = e['inventory_id'].split(':')[1][:12]
        lines.append(
            f"| `{short}` | {e['line_range'][0]}–{e['line_range'][1]} | `{label}` | `{p['migration_mode']}` | `{target}` |"
        )
    lines += [
        '', '## Destinos compartilhados — materialização pendente', '',
        'Não renomear artificialmente arquivos legados nem soltar decoradores de suas funções.',
        'O draft atual recusa esses grupos; o contrato final de seletores/assembly deve resolvê-los.', '',
    ]
    for group in value['shared_target_groups']:
        lines.append(f"- `{group['repository']}:{group['target_path']}`: {len(group['inventory_ids'])} unidades.")
    return '\n'.join(lines) + '\n'
