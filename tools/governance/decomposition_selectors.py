"""Deterministic draft selectors; canonical data, never imported legacy modules."""
from __future__ import annotations

import ast
import copy
import re
import sys

from tools.governance import decomposition_scope as scope
from tools.governance.decomposition_common import digest, exact_fields, json_digest

AST_ABI = 'python:3.12_ast_v1'
TEXT_ABI = 'raw_bytes:half_open_v1'
SECURITY_PATH = 'tests/test_security_boundaries.py'


def whole_file(raw: bytes, mode: str) -> dict:
    return {'selector_kind': 'whole_file', 'byte_range': [0, len(raw)],
            'raw_span_digest': digest(raw), 'file_mode': mode}


def text_region(raw: bytes, start: int, end: int) -> dict:
    return {'selector_kind': 'text_region', 'selector_abi': TEXT_ABI,
            'byte_range': [start, end], 'raw_span_digest': digest(raw[start:end])}


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
            symbols.append({'selector_kind': 'ast_symbol', 'symbol_name': name,
                            'parser_abi': AST_ABI, 'byte_range': [start, end],
                            'raw_span_digest': digest(raw[start:end]),
                            'ast_digest': digest(ast.unparse(node).encode('utf-8'))})
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
    extra = {'whole_file': {'file_mode'}, 'text_region': {'selector_abi'},
             'ast_symbol': {'symbol_name', 'parser_abi', 'ast_digest'}}
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
        expected = next((s for s in candidates if s['symbol_name'] == selector['symbol_name']
                         and s['byte_range'] == span), None)
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
    identity = {'repository': scope.REPOSITORY, 'commit_sha': scope.BASELINE,
                'source_path': path, 'source_selector_digest': sd}
    return {'inventory_id': 'source-unit:' + json_digest(identity).removeprefix('sha256:'),
            'source_path': path, 'source_selector': copy.deepcopy(selector), 'source_selector_digest': sd,
            'source_digest': selector.get('ast_digest', selector['raw_span_digest']),
            'coverage_role': coverage_role(path)}


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
        selections = {p: (partition_python(source.files[p]) if p == SECURITY_PATH
                          else [whole_file(source.files[p], source.modes[p])]) for p in source.paths}
    if not isinstance(selections, dict) or set(selections) != set(source.files):
        raise ValueError('inventory: selected paths must equal complete pinned source paths')
    items = [i for p in source.paths for i in _path_items(source, p, selections[p])]
    items.sort(key=lambda i: i['inventory_id'].encode('utf-8'))
    inventory = {'$schema': 'smart_ads/source_inventory/v1', 'repository': scope.REPOSITORY,
                 'commit_sha': scope.BASELINE, 'inventory_scope': source.inventory_scope(),
                 'declared_paths': source.paths, 'declared_paths_digest': json_digest(source.paths),
                 'items': items}
    inventory['inventory_digest'] = json_digest(inventory)
    return inventory


def validate_inventory(source: scope.SourceSnapshot, inventory: dict) -> None:
    exact_fields(inventory, {'$schema', 'repository', 'commit_sha', 'inventory_scope',
                            'declared_paths', 'declared_paths_digest', 'inventory_digest', 'items'}, 'inventory')
    if not isinstance(inventory['items'], list):
        raise ValueError('inventory: items must be a list')
    selections = {p: [] for p in source.paths}
    for item in inventory['items']:
        exact_fields(item, {'inventory_id', 'source_path', 'source_selector',
                           'source_selector_digest', 'source_digest', 'coverage_role'}, 'inventory item')
        path = item['source_path']
        if not isinstance(path, str) or path not in selections:
            raise ValueError('inventory: unexpected source path')
        selections[path].append(item['source_selector'])
    if inventory != resolve_inventory(source, selections):
        raise ValueError('inventory: recomputed identity/digest/order mismatch')
