"""Pinned, offline Git blob reader. No worktree overlay or legacy code execution."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import subprocess

from tools.governance.decomposition_common import json_digest, source_path

REPOSITORY = 'mbras-tech/mbras-campaigns'
BASELINE = 'd26c73d8508c7c3d43161fe36a80c44a46bf0f2d'
TREE = '68ff6d6dbd6d7ecaafa3bca7d5de85a54d705798'
PATH_DIGEST = 'sha256:a0f50b3c10c145902851dec67c8e5a45e91ed5f9bffb463039a9d2cc7cdef32d'
ROOTS = (
    'docs/harness/bin', 'scripts/analytics/validate_funnel_contract.py',
    'scripts/autonomy/controller.py', 'scripts/autonomy/ledger.py',
    'scripts/google_ads/pinna5109', 'scripts/operator/conductor.py',
    'scripts/operator/google_canary.py', 'scripts/operator/google_canary_transport.py',
)
ASSOCIATED = (
    'config/analytics/funnel_contract_v1.yaml', 'tests/test_funnel_contract.py',
    'tests/autonomy/test_controller.py', 'tests/autonomy/test_ledger.py',
    'tests/test_codex_gate.py', 'tests/test_security_boundaries.py',
    'tests/operator/test_google_canary.py', 'tests/operator/test_google_canary_transport.py',
    'tests/operator/fixtures/google_canary',
    'tests/test_service_account_disablement_authorization.py',
    'tests/test_service_account_disablement_packet.py',
    'config/operator/service_account_authorization_template.sha256',
    'DOCUMENTATION/IBVI_ADS_SERVICE_ACCOUNT_KEY_DISABLEMENT_AUTHORIZATION.md',
    'DOCUMENTATION/IBVI_ADS_SERVICE_ACCOUNT_KEY_DISABLEMENT_DECISION_PACKET.md',
)


@dataclass(frozen=True)
class SourceSnapshot:
    """In-memory blob input to pure functions; use resolve_scope at admission."""

    files: dict[str, bytes]
    modes: dict[str, str]

    def __post_init__(self) -> None:
        if not self.files or set(self.files) != set(self.modes):
            raise ValueError('source: nonempty file/mode sets must be equal')
        for path, raw in self.files.items():
            source_path(path)
            if type(raw) is not bytes or self.modes[path] not in ('100644', '100755'):
                raise ValueError('source: require blob bytes and regular Git file mode')

    @property
    def paths(self) -> list[str]:
        return sorted(self.files, key=lambda p: p.encode('utf-8'))

    def inventory_scope(self) -> dict:
        return {'$schema': 'smart_ads/source_inventory_scope/v1', 'source_tree_oid': TREE,
                'scope_roots': list(ROOTS), 'associated_paths': list(ASSOCIATED),
                'inclusion_rules': ['all_exact_file_roots', 'all_recursive_directory_blobs'],
                'explicit_exclusions': [], 'path_universe_digest': json_digest(self.paths)}


def _git(repo: Path, *args: str) -> bytes:
    env = {'PATH': '/opt/homebrew/bin:/usr/bin:/bin', 'GIT_CONFIG_NOSYSTEM': '1',
           'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_NO_REPLACE_OBJECTS': '1',
           'GIT_NO_LAZY_FETCH': '1', 'GIT_OPTIONAL_LOCKS': '0'}
    command = ['git', '-c', 'protocol.allow=never', '-c', 'credential.helper=',
               '-C', str(repo), *args]
    try:
        result = subprocess.run(command, env=env, capture_output=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError('source: offline Git unavailable or timed out') from exc
    if result.returncode:
        raise ValueError('source: missing or unreadable pinned Git object')
    return result.stdout


def resolve_scope(repo: Path, baseline: str = BASELINE) -> SourceSnapshot:
    if baseline != BASELINE:
        raise ValueError('source: baseline must equal the pinned d26c73d commit')
    if _git(repo, 'rev-parse', '--verify', BASELINE + '^{commit}').decode().strip() != BASELINE:
        raise ValueError('source: canonical commit mismatch')
    if _git(repo, 'rev-parse', BASELINE + '^{tree}').decode().strip() != TREE:
        raise ValueError('source: root tree mismatch')
    records = {}
    for line in _git(repo, 'ls-tree', '-r', '-z', BASELINE).split(b'\0'):
        if not line:
            continue
        meta, raw_path = line.split(b'\t', 1)
        mode, kind, oid = meta.decode('ascii').split()
        path = raw_path.decode('utf-8')
        if path in records or not re.fullmatch(r'[0-9a-f]{40}', oid):
            raise ValueError('source: duplicate path or malformed Git object ID')
        records[path] = mode, kind, oid
    selected = set()
    for root in (*ROOTS, *ASSOCIATED):
        if _git(repo, 'cat-file', '-t', f'{BASELINE}:{root}').strip() not in (b'blob', b'tree'):
            raise ValueError('source: root must be a Git blob or tree')
        matches = {p for p in records if p == root or p.startswith(root + '/')}
        if not matches:
            raise ValueError('source: empty or absent required root')
        selected.update(matches)
    ordered = sorted(selected, key=lambda p: p.encode('utf-8'))
    if len(ordered) != 44 or json_digest(ordered) != PATH_DIGEST:
        raise ValueError('source: declared path universe does not match pinned 44 paths')
    files, modes = {}, {}
    for path in ordered:
        mode, kind, oid = records[path]
        if kind != 'blob' or mode not in ('100644', '100755'):
            raise ValueError('source: symlinks, submodules and nonregular objects forbidden')
        files[path] = _git(repo, 'cat-file', 'blob', oid)
        modes[path] = mode
    return SourceSnapshot(files, modes)
