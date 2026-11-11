"""Offline counterexamples for the proposed decomposition contract.

No assertion here promotes the unratified contract or a candidate to authority.
Synthetic source trees are data; legacy modules are never imported/executed.
"""
from __future__ import annotations

import copy
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from tools.governance import cli
from tools.governance import decomposition as dec
from tools.governance import decomposition_governance as governance
from tools.governance import decomposition_scope as scope
from tools.governance.locator import digest, source_path

decisions = dec
selectors = dec

ROOT = Path(__file__).resolve().parents[2]


def snapshot(raw=b'def hello():\n    return "ok"\n', path='scripts/example.py'):
    return scope.SourceSnapshot({path: raw}, {path: '100644'})


def entry(item, **updates):
    value = {'inventory_id': item['inventory_id'], 'system_id': 'example',
             'system_owner': 'legacy-operator', 'target_repository': 'aiconnai/smart-ads',
             'target_layer': 'repository_tooling', 'target_path': 'tooling/governance/example.py',
             'target_selector': None, 'migration_mode': 'repository_tooling',
             'decision_status': 'approved', 'deferral_authority_ref': None,
             'rejection_reason': None, 'preserved_invariants': ['no_provider_io'],
             'compatibility_surface': [], 'blocking_defects': [],
             'required_tests': ['tests/security/test_example.py']}
    value.update(updates)
    return value


@pytest.mark.parametrize('path', ['../x', '/x', 'a//b', 'a/./b', 'C:/x',
                                  'a\\b', 'a/%2e%2e/b', 'a\x00b'])
def test_rejects_escaping_paths(path):
    with pytest.raises(ValueError):
        source_path(path)


def test_ast_range_uses_utf8_bytes_and_does_not_execute(tmp_path):
    raw = b'x = "\xc3\xa9";\n\ndef hello():\n    return "\xc3\xa9"\n'
    symbols = selectors.ast_symbols(raw)
    sel = symbols[0]
    assert raw[slice(*sel['byte_range'])] == b'def hello():\n    return "\xc3\xa9"'
    assert sel['raw_span_digest'] == digest(raw[slice(*sel['byte_range'])])
    assert sel['parser_abi'] == 'python:3.12_ast_v1'


def test_partition_preserves_decorator_data_and_all_bytes():
    raw = b'import pytest\n\n@pytest.mark.parametrize("x", [1,2])\ndef test_x(x):\n    pass\n'
    selected = selectors.partition_python(raw)
    spans = sorted(s['byte_range'] for s in selected)
    assert spans[0][0] == 0 and spans[-1][1] == len(raw)
    assert all(a[1] == b[0] for a, b in zip(spans, spans[1:]))
    regions = [raw[slice(*s['byte_range'])] for s in selected if s['selector_kind'] == 'text_region']
    assert any(b'parametrize' in r for r in regions)


@pytest.mark.parametrize('mutation', ['hash', 'range', 'extra', 'bool', 'source'])
def test_selector_tampering_rejected(mutation):
    raw = b'def f():\n    return 1\n'
    sel = selectors.ast_symbols(raw)[0]
    if mutation == 'hash': sel['ast_digest'] = 'sha256:' + '0'*64
    if mutation == 'range': sel['byte_range'][1] -= 1
    if mutation == 'extra': sel['unexpected'] = True
    if mutation == 'bool': sel['byte_range'][0] = False
    if mutation == 'source': raw = raw.replace(b'return 1', b'return 2')
    with pytest.raises(ValueError):
        selectors.validate_selector(raw, '100644', sel)


def test_inventory_rejects_missing_path_and_tampered_item():
    source = snapshot()
    inv = selectors.resolve_inventory(source)
    broken = copy.deepcopy(inv); broken['declared_paths'] = []
    with pytest.raises(ValueError): selectors.validate_inventory(source, broken)
    broken = copy.deepcopy(inv); broken['items'][0]['source_digest'] = 'sha256:'+'0'*64
    with pytest.raises(ValueError): selectors.validate_inventory(source, broken)


def test_parent_and_child_overlap_cannot_be_silently_counted():
    raw = b'class A:\n    def method(self):\n        return 1\n'
    source = snapshot(raw)
    with pytest.raises(ValueError, match='overlap'):
        selectors.resolve_inventory(source, {'scripts/example.py': selectors.ast_symbols(raw)})


@pytest.mark.parametrize('updates', [
    {'decision_status': 'approved', 'migration_mode': 'defer_to_google_phase'},
    {'decision_status': 'deferred', 'migration_mode': 'defer_to_google_phase'},
    {'target_path': '../escape.py'}, {'target_path': 'src/smart_ads/x.py'},
    {'unexpected': 1}, {'target_selector': {}},
])
def test_invalid_destination_contract(updates):
    item = selectors.resolve_inventory(snapshot())['items'][0]
    with pytest.raises(ValueError): decisions.validate_entry(entry(item, **updates), item)


def test_pinna_never_enters_core_even_with_approved_status():
    item = selectors.resolve_inventory(snapshot(path='scripts/google_ads/pinna5109/create_campaign.py'))['items'][0]
    with pytest.raises(ValueError, match='Pinna'):
        decisions.validate_entry(entry(item, migration_mode='reimplement_clean',
                                       target_layer='core_engine', target_path='src/smart_ads/x.py'), item)


@pytest.mark.parametrize(
    'source_path_val,bad_updates,expected_match',
    [
        (
            'scripts/google_ads/pinna5109/mutate.py',
            {'migration_mode': 'reimplement_clean', 'target_layer': 'core_engine', 'target_path': 'src/smart_ads/m.py'},
            'Pinna',
        ),
        (
            'scripts/autonomy/controller.py',
            {'migration_mode': 'reimplement_clean', 'target_layer': 'core_engine', 'target_path': 'src/smart_ads/c.py'},
            'contradicts the ADR system disposition',
        ),
        (
            'DOCUMENTATION/IBVI_ADS_SERVICE_ACCOUNT_KEY_DISABLEMENT_PACKET.md',
            {'migration_mode': 'reference_only', 'target_layer': None, 'target_path': None, 'required_tests': [], 'preserved_invariants': []},
            'contradicts the ADR system disposition',
        ),
        (
            'docs/harness/bin/codex-gate.sh',
            {'migration_mode': 'reimplement_clean', 'target_layer': 'core_engine', 'target_path': 'src/smart_ads/g.py'},
            'contradicts the ADR system disposition',
        ),
        (
            'scripts/operator/google_canary.py',
            {'migration_mode': 'reimplement_clean', 'target_layer': 'core_engine', 'target_path': 'src/smart_ads/gc.py'},
            'contradicts the ADR system disposition',
        ),
        (
            'scripts/analytics/validate_funnel_contract.py',
            {'migration_mode': 'reimplement_clean', 'target_layer': 'core_engine', 'target_path': 'src/smart_ads/f.py'},
            'contradicts the ADR system disposition',
        ),
        (
            'scripts/autonomy/ledger.py',
            {
                'migration_mode': 'legacy_governance_only',
                'target_repository': 'aiconnai/smart-ads',
                'target_layer': 'repository_tooling',
                'target_path': 'tooling/governance/ledger.py',
            },
            'legacy governance cannot migrate to a different repository',
        ),
        (
            'tests/test_service_account_disablement_packet.py',
            {
                'migration_mode': 'legacy_governance_only',
                'target_repository': 'aiconnai/smart-ads',
                'target_layer': 'repository_tooling',
                'target_path': 'tests/test_service_account_disablement_packet.py',
            },
            'legacy governance cannot migrate to a different repository',
        ),
    ],
)
def test_validate_entry_enforces_all_six_group_modes_and_legacy_repo_lock(
    source_path_val: str, bad_updates: dict, expected_match: str
) -> None:
    item = selectors.resolve_inventory(snapshot(path=source_path_val))['items'][0]
    with pytest.raises(ValueError, match=expected_match):
        decisions.validate_entry(entry(item, **bad_updates), item)


def test_manifest_digest_does_not_depend_on_signature_results():
    value = {'source_inventory': {}, 'entries': [], 'generated_at': '2026-09-07T00:00:00Z'}
    before = dec.manifest_digest(value)
    value['integrity'] = {'key_id': 'fixture', 'content_digest': 'sha256:'+'0'*64,
                          'signature_base64': 'fixture-not-a-signature'}
    value['manifest_digest'] = before
    assert dec.manifest_digest(value) == before
    value['generated_at'] = '2026-09-08T00:00:00Z'
    assert dec.manifest_digest(value) != before


def test_candidate_pending_decisions_never_claims_ready():
    source = snapshot(); inv = selectors.resolve_inventory(source)
    entries = [entry(inv['items'][0], decision_status=None)]
    result = dec.build_candidate(source, inv, entries, '2026-09-07T00:00:00Z')
    assert result['signable'] is False
    assert result['pending_decision_count'] == 1
    assert result['validation_status'] == 'INCOMPLETE'
    assert '$schema' not in result and 'integrity' not in result


def test_duplicate_or_missing_assignments_rejected():
    source = snapshot(); inv = selectors.resolve_inventory(source); e = entry(inv['items'][0])
    for entries in [[], [e, e]]:
        with pytest.raises(ValueError): dec.build_candidate(source, inv, entries, '2026-09-07T00:00:00Z')


def test_candidate_verifier_recomputes_the_entire_result():
    source = snapshot(); inv = selectors.resolve_inventory(source)
    candidate = dec.build_candidate(source, inv, [entry(inv['items'][0])], '2026-09-07T00:00:00Z')
    dec.verify_candidate(source, candidate)
    candidate['signable'] = True
    with pytest.raises(ValueError): dec.verify_candidate(source, candidate)


@pytest.mark.parametrize('path', ['docs/harness/bin/codex-gate.sh', 'tests/test_codex_gate.py'])
def test_tooling_cannot_claim_a_core_target(path):
    source = snapshot(b'echo gate\n', path)
    inv = selectors.resolve_inventory(source)
    bad = entry(inv['items'][0], target_layer='core_engine', target_path='src/smart_ads/gate.py')
    with pytest.raises(ValueError, match='tooling'):
        dec.build_candidate(source, inv, [bad], '2026-09-07T00:00:00Z')


@pytest.mark.parametrize('arbitrary_split', [False, True])
def test_security_text_regions_cannot_hide_invariant_units(arbitrary_split):
    raw = b'def test_read(): pass\n\ndef test_write(): pass\n'
    source = snapshot(raw, selectors.SECURITY_PATH)
    selected = ([selectors.text_region(raw, 0, 1), selectors.text_region(raw, 1, len(raw))]
                if arbitrary_split else [selectors.text_region(raw, 0, len(raw))])
    with pytest.raises(ValueError, match='security'):
        selectors.resolve_inventory(source, {selectors.SECURITY_PATH: selected})


def test_canonical_security_partition_remains_revisable():
    source = snapshot(b'def test_read(): pass\n\ndef test_write(): pass\n', selectors.SECURITY_PATH)
    inv = selectors.resolve_inventory(source)
    candidate = dec.build_candidate(source, inv, decisions.decision_template(inv), '2026-09-07T00:00:00Z')
    dec.verify_candidate(source, candidate)
    assert candidate['validation_status'] == 'INCOMPLETE'


def test_pending_template_does_not_invent_an_owner():
    inv = selectors.resolve_inventory(snapshot())
    pending = decisions.decision_template(inv)[0]
    assert pending['system_owner'] is None
    decisions.validate_entry(pending, inv['items'][0])
    with pytest.raises(ValueError, match='system_owner'):
        decisions.validate_entry(entry(inv['items'][0], system_owner=None), inv['items'][0])


def test_shared_target_cannot_claim_zero_conflicts():
    source = scope.SourceSnapshot({'a.py': b'a', 'b.py': b'b'}, {'a.py': '100644', 'b.py': '100644'})
    inv = selectors.resolve_inventory(source)
    with pytest.raises(ValueError, match='shared target'):
        dec.build_candidate(source, inv, [entry(i) for i in inv['items']], '2026-09-07T00:00:00Z')


@pytest.mark.parametrize('newline', [b'\n', b'\r\n', b'\r'])
def test_ast_line_endings_are_byte_based(newline):
    raw = newline.join([b'# header', b'def f():', b'    return "\xc3\xa9"', b''])
    sel = selectors.ast_symbols(raw)[0]
    assert raw[slice(*sel['byte_range'])] == newline.join([b'def f():', b'    return "\xc3\xa9"'])


def test_non_python312_runtime_is_refused(monkeypatch):
    monkeypatch.setattr(selectors.sys, 'version_info', (3, 13, 0))
    with pytest.raises(ValueError, match='CPython 3.12'): selectors.ast_symbols(b'def f(): pass')


def test_source_is_parsed_without_side_effects(tmp_path):
    marker = tmp_path / 'must-not-exist'
    raw = f'open({str(marker)!r}, "w").write("bad")\ndef f(): pass\n'.encode()
    selectors.partition_python(raw)
    assert not marker.exists()


def test_rejects_uncovered_import_prefix_and_trailing_newline():
    raw = b'import os\n\ndef f(): pass\n'
    with pytest.raises(ValueError, match='gap'):
        selectors.resolve_inventory(snapshot(raw), {'scripts/example.py': selectors.ast_symbols(raw)})


def test_empty_file_is_representable_but_duplicate_empty_selector_is_not():
    source = snapshot(b''); inv = selectors.resolve_inventory(source)
    selectors.validate_inventory(source, inv)
    whole = selectors.whole_file(b'', '100644')
    with pytest.raises(ValueError, match='duplicate'):
        selectors.resolve_inventory(source, {'scripts/example.py': [whole, whole]})


def test_inventory_identity_binds_raw_text_as_well_as_ast():
    one = b'def f():\n    return 1\n'
    two = b'def f():\n    return  1\n'
    a, b = selectors.ast_symbols(one)[0], selectors.ast_symbols(two)[0]
    assert a['ast_digest'] == b['ast_digest']
    assert a['raw_span_digest'] != b['raw_span_digest']
    assert selectors.make_item('x.py', a)['inventory_id'] != selectors.make_item('x.py', b)['inventory_id']


def test_bool_is_not_an_integer_in_recomputed_candidate():
    source = snapshot();inv = selectors.resolve_inventory(source)
    c = dec.build_candidate(source, inv, [entry(inv['items'][0], decision_status=None)], '2026-09-07T00:00:00Z')
    c['pending_decision_count'] = True
    with pytest.raises(ValueError): dec.verify_candidate(source, c)


@pytest.mark.parametrize('when', ['2026-09-31T00:00:00Z', '2026-09-07',
                                 '2026-09-07T00:00:00+00:00', True])
def test_invalid_time_does_not_build(when):
    source = snapshot();inv = selectors.resolve_inventory(source)
    with pytest.raises(ValueError): dec.build_candidate(source, inv, [entry(inv['items'][0])], when)


def test_real_public_governance_is_incomplete_for_new_schema():
    result = governance.inspect_governance(ROOT)
    assert result['predecessor_signatures_and_links'] == 'PASS'
    assert result['epoch3_has_decomposition_action'] is False
    assert result['signable'] is False


def test_governance_rejects_changed_approved_adr(tmp_path):
    import shutil
    shutil.copytree(ROOT/'docs', tmp_path/'docs')
    adr = tmp_path/'docs/adr/ADR-0001-smart-ads-read-gateway.md'
    adr.write_bytes(adr.read_bytes()+b'\nchanged')
    with pytest.raises(ValueError, match='ADR bytes changed'):
        governance.inspect_governance(tmp_path)


def test_governance_rejects_corrupted_stored_registry(tmp_path):
    import shutil
    shutil.copytree(ROOT/'docs', tmp_path/'docs')
    loc = json.loads((tmp_path/'docs/governance/legacy-step2/params/registry_epoch3_store_put.out').read_text())
    obj = tmp_path/'docs/governance/cell-objects/sha256'/ (loc['content_digest'].split(':')[1]+'.json')
    obj.write_bytes(obj.read_bytes()+b'\n')
    with pytest.raises(ValueError, match='content-addressed digest'):
        governance.inspect_governance(tmp_path)


def test_draft_write_is_atomic_and_refuses_existing_target(tmp_path):
    path = tmp_path/'output.json'
    cli._write_json_file(str(path), {'draft': True}, allow_overwrite=False)
    before = path.read_bytes()
    with pytest.raises(ValueError, match='exists'):
        cli._write_json_file(str(path), {'draft': False}, allow_overwrite=False)
    assert path.read_bytes() == before
    assert list(tmp_path.glob('.decomposition-*')) == []


def test_cli_does_not_write_after_invalid_assignment(tmp_path, monkeypatch):
    source = snapshot();inv = selectors.resolve_inventory(source)
    monkeypatch.setattr(cli, 'resolve_scope', lambda _: source)
    p = tmp_path/'params.json';out = tmp_path/'result.json'
    p.write_text(json.dumps({'artifact_kind': 'decomposition_inputs_draft',
                            'draft_contract': dec.CONTRACT, 'inventory': inv, 'entries': []}))
    args = SimpleNamespace(command='build-decomposition-manifest', legacy_repo='unused',
                           params=str(p), out=str(out), generated_at='2026-09-07T00:00:00Z')
    with pytest.raises(ValueError, match='unassigned'): cli.run_decomposition(args)
    assert not out.exists()


def test_candidate_cannot_be_sent_to_existing_sign_or_store_commands():
    from tools.governance import p1
    from tools.governance.locator import Store
    source = snapshot();inv = selectors.resolve_inventory(source)
    c = dec.build_candidate(source, inv, [entry(inv['items'][0])], '2026-09-07T00:00:00Z')
    assert 'decomposition_manifest/v1' not in p1.DOMAIN_PREFIXES
    with pytest.raises(ValueError, match='integrity'): p1.preimage(c)
    with pytest.raises(ValueError, match='schema'): Store(Path('must-not-create')).put(c)


def _git(repo, *args):
    return subprocess.check_output(['git', '-C', str(repo), *args], text=True).strip()


@pytest.fixture
def git_source(tmp_path, monkeypatch):
    repo = tmp_path/'source';repo.mkdir()
    _git(repo, 'init', '-q')
    _git(repo, 'config', 'user.name', 'fixture')
    _git(repo, 'config', 'user.email', 'fixture@example.invalid')
    _git(repo, 'config', 'commit.gpgsign', 'false')
    paths = json.loads((ROOT/'tests/governance/fixtures/decomposition_scope_paths.json').read_text())
    for path in paths:
        f = repo/path;f.parent.mkdir(parents=True, exist_ok=True);f.write_bytes(b'fixture\n')
    _git(repo, 'add', '.');_git(repo, 'commit', '-qm', 'fixture baseline')
    head = _git(repo, 'rev-parse', 'HEAD');tree = _git(repo, 'rev-parse', 'HEAD^{tree}')
    monkeypatch.setattr(scope, 'BASELINE', head);monkeypatch.setattr(scope, 'TREE', tree)
    return repo, head


def test_git_resolver_ignores_worktree_overlay(git_source):
    repo, head = git_source
    before = scope.resolve_scope(repo, head)
    (repo/'scripts/operator/conductor.py').write_text('different local data')
    (repo/'scripts/google_ads/pinna5109/untracked.py').write_text('ignored overlay')
    after = scope.resolve_scope(repo, head)
    assert before.files == after.files and len(after.files) == 44


def test_git_resolver_rejects_descendant_identity(git_source):
    repo, head = git_source
    (repo/'scripts/operator/conductor.py').write_text('changed')
    _git(repo, 'add', '.');_git(repo, 'commit', '-qm', 'descendant')
    with pytest.raises(ValueError, match='baseline'):
        scope.resolve_scope(repo, _git(repo, 'rev-parse', 'HEAD'))


def test_git_resolver_rejects_symlink_even_with_matching_fixture_pin(git_source, monkeypatch):
    repo, _ = git_source
    path = repo/'scripts/operator/conductor.py';path.unlink();path.symlink_to('/outside/target')
    _git(repo, 'add', '.');_git(repo, 'commit', '-qm', 'link')
    head = _git(repo, 'rev-parse', 'HEAD')
    monkeypatch.setattr(scope, 'BASELINE', head)
    monkeypatch.setattr(scope, 'TREE', _git(repo, 'rev-parse', 'HEAD^{tree}'))
    with pytest.raises(ValueError, match='symlinks'): scope.resolve_scope(repo, head)


def test_git_resolver_rejects_extra_path_in_anchored_directory(git_source, monkeypatch):
    repo, _ = git_source
    (repo/'scripts/google_ads/pinna5109/extra.py').write_text('extra')
    _git(repo, 'add', '.');_git(repo, 'commit', '-qm', 'extra')
    head = _git(repo, 'rev-parse', 'HEAD')
    monkeypatch.setattr(scope, 'BASELINE', head)
    monkeypatch.setattr(scope, 'TREE', _git(repo, 'rev-parse', 'HEAD^{tree}'))
    with pytest.raises(ValueError, match='44 paths'): scope.resolve_scope(repo, head)


def test_cli_main_all_five_decomposition_subcommands_end_to_end(tmp_path, monkeypatch, capsys):
    from tools.governance import decomposition_review as review

    repo = tmp_path / 'legacy_source'
    repo.mkdir()
    _git(repo, 'init', '-q')
    _git(repo, 'config', 'user.name', 'fixture')
    _git(repo, 'config', 'user.email', 'fixture@example.invalid')
    _git(repo, 'config', 'commit.gpgsign', 'false')

    sec_parts = ['import pytest\n']
    for name in review.SECURITY_GROUPS:
        if name == 'test_sensitive_writers_reject_symlink_file_targets':
            sec_parts.append('@pytest.mark.parametrize("writer", [_write_test_csv, _write_test_json])\n')
        body = '_write_test_csv(None)' if name == 'test_sensitive_writers_enforce_private_modes_under_permissive_umask' else 'pass'
        sec_parts.append(f'def {name}():\n    {body}\n\n')
    sec_bytes = ''.join(sec_parts).encode('utf-8')

    paths = json.loads((ROOT / 'tests/governance/fixtures/decomposition_scope_paths.json').read_text(encoding='utf-8'))
    raw_by_path: dict[str, bytes] = {}
    for p in paths:
        content = sec_bytes if p == dec.SECURITY_PATH else (b'def stub():\n    return 1\n' if p.endswith('.py') else b'fixture\n')
        target = repo / p
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        raw_by_path[p] = content
    _git(repo, 'add', '.')
    _git(repo, 'commit', '-qm', 'fixture baseline')
    head = _git(repo, 'rev-parse', 'HEAD')
    tree = _git(repo, 'rev-parse', 'HEAD^{tree}')
    monkeypatch.setattr(scope, 'BASELINE', head)
    monkeypatch.setattr(scope, 'TREE', tree)
    monkeypatch.setattr(review, 'BASELINE', head)

    fixture_root = tmp_path / 'gov_root'
    (fixture_root / 'docs/adr').mkdir(parents=True)
    (fixture_root / 'docs/governance/trust-anchor').mkdir(parents=True)
    (fixture_root / 'docs/governance/decomposition').mkdir(parents=True)
    (fixture_root / 'docs/adr/ADR-0001-smart-ads-read-gateway.md').write_bytes(
        (ROOT / 'docs/adr/ADR-0001-smart-ads-read-gateway.md').read_bytes()
    )
    (fixture_root / 'docs/governance/trust-anchor/cell_trust_anchor_config.json').write_bytes(
        (ROOT / 'docs/governance/trust-anchor/cell_trust_anchor_config.json').read_bytes()
    )
    proposals = json.loads(
        (ROOT / 'docs/governance/decomposition/path-dispositions.proposed.json').read_text(encoding='utf-8')
    )
    proposals['source']['commit_sha'] = head
    proposals['source']['source_tree_oid'] = tree
    for row in proposals['paths']:
        row['source_file_digest'] = digest(raw_by_path[row['source_path']])
    (fixture_root / 'docs/governance/decomposition/path-dispositions.proposed.json').write_text(
        json.dumps(proposals), encoding='utf-8'
    )
    monkeypatch.setattr(review, 'REPO_ROOT', fixture_root)

    # 1. resolve-decomposition-inventory
    inv_out = tmp_path / 'inventory.json'
    assert cli.main(['resolve-decomposition-inventory', '--legacy-repo', str(repo), '--out', str(inv_out)]) == 0
    inv_meta = json.loads(capsys.readouterr().out)
    assert inv_meta['signable'] is False
    inv_payload = json.loads(inv_out.read_text(encoding='utf-8'))
    assert inv_payload['artifact_kind'] == 'decomposition_inputs_draft'

    # 2. prepare-decomposition-review (exercises build_review_bundle end-to-end)
    rev_out = tmp_path / 'review_bundle.json'
    assert cli.main(['prepare-decomposition-review', '--legacy-repo', str(repo), '--out', str(rev_out)]) == 0
    rev_meta = json.loads(capsys.readouterr().out)
    assert rev_meta['signable'] is False
    rev_payload = json.loads(rev_out.read_text(encoding='utf-8'))
    assert rev_payload['artifact_kind'] == 'decomposition_review_bundle'
    assert rev_payload['signable'] is False

    # 3. prepare-decomposition-dispositions
    disp_out = tmp_path / 'dispositions_draft.json'
    assert cli.main(['prepare-decomposition-dispositions', '--legacy-repo', str(repo), '--out', str(disp_out)]) == 0
    disp_meta = json.loads(capsys.readouterr().out)
    assert disp_meta['signable'] is False
    disp_payload = json.loads(disp_out.read_text(encoding='utf-8'))
    assert disp_payload['artifact_kind'] == 'decomposition_inputs_draft'

    # 4. build-decomposition-manifest
    cand_out = tmp_path / 'candidate_manifest.json'
    assert cli.main([
        'build-decomposition-manifest',
        '--legacy-repo', str(repo),
        '--params', str(inv_out),
        '--generated-at', '2026-09-07T00:00:00Z',
        '--out', str(cand_out),
    ]) == 0
    cand_meta = json.loads(capsys.readouterr().out)
    assert cand_meta['validation_status'] == 'INCOMPLETE'
    assert cand_meta['signable'] is False

    # 5. verify-decomposition-manifest (must return exit code 5 and signable=False)
    assert cli.main([
        'verify-decomposition-manifest',
        '--legacy-repo', str(repo),
        '--in', str(cand_out),
    ]) == 5
    ver_meta = json.loads(capsys.readouterr().out)
    assert ver_meta['candidate_matches_recomputation'] is True
    assert ver_meta['validation_status'] == 'INCOMPLETE'
    assert ver_meta['signable'] is False
