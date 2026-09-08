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

from tools.governance import decomposition as dec
from tools.governance import decomposition_decisions as decisions
from tools.governance import decomposition_scope as scope
from tools.governance import decomposition_selectors as selectors
from tools.governance import decomposition_cli as dcli
from tools.governance import decomposition_governance as governance
from tools.governance.decomposition_common import digest, source_path

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
    dcli._write(str(path), {'draft': True})
    before = path.read_bytes()
    with pytest.raises(ValueError, match='exists'): dcli._write(str(path), {'draft': False})
    assert path.read_bytes() == before
    assert list(tmp_path.glob('.decomposition-*')) == []


def test_cli_does_not_write_after_invalid_assignment(tmp_path, monkeypatch):
    source = snapshot();inv = selectors.resolve_inventory(source)
    monkeypatch.setattr(dcli, 'resolve_scope', lambda _: source)
    p = tmp_path/'params.json';out = tmp_path/'result.json'
    p.write_text(json.dumps({'artifact_kind': 'decomposition_inputs_draft',
                            'draft_contract': dec.CONTRACT, 'inventory': inv, 'entries': []}))
    args = SimpleNamespace(command='build-decomposition-manifest', legacy_repo='unused',
                           params=str(p), out=str(out), generated_at='2026-09-07T00:00:00Z')
    with pytest.raises(ValueError, match='unassigned'): dcli.run(args)
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
