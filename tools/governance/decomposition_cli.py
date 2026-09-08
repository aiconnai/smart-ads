"""CLI boundary for local drafts: fresh output files, no official envelope."""
from __future__ import annotations

import os
from pathlib import Path
import tempfile

from tools.governance import decomposition as dec
from tools.governance.decomposition_common import digest, exact_fields
from tools.governance.decomposition_decisions import decision_template
from tools.governance.decomposition_governance import inspect_governance
from tools.governance.decomposition_scope import resolve_scope
from tools.governance.decomposition_selectors import resolve_inventory
from tools.governance.jcs import canonicalize, loads_strict


def _read(path: str) -> dict:
    value = loads_strict(Path(path).read_text())
    if not isinstance(value, dict):
        raise ValueError('decomposition: input must be an object')
    return value


def _write(path: str, value: dict) -> dict:
    raw = canonicalize(value)
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        raise ValueError('decomposition: output exists; choose a fresh output path')
    fd, temp = tempfile.mkstemp(prefix='.decomposition-', dir=target.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temp, target)  # Atomic create, never overwrite a concurrently created file.
        directory = os.open(target.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(temp).unlink(missing_ok=True)
    if target.read_bytes() != raw:
        raise ValueError('decomposition: output readback mismatch')
    return {'path': str(target), 'size': len(raw), 'sha256': digest(raw), 'signable': False}


def run(args) -> tuple[dict, int]:
    try:
        return _run(args)
    except (OSError, TypeError, UnicodeError) as exc:
        raise ValueError(f'decomposition: invalid input or local I/O failure ({type(exc).__name__})') from exc


def _run(args) -> tuple[dict, int]:
    source = resolve_scope(Path(args.legacy_repo))
    if args.command in ('prepare-decomposition-review', 'prepare-decomposition-dispositions'):
        from tools.governance.decomposition_admission import build_admission_proposal
        from tools.governance.decomposition_review import build_unit_review
        root = Path(__file__).resolve().parents[2]
        inventory = resolve_inventory(source)
        value = {'artifact_kind': 'decomposition_review_bundle', 'authority': 'none', 'signable': False,
                 'admission_proposal': build_admission_proposal(
                     (root/'docs/adr/ADR-0001-smart-ads-read-gateway.md').read_bytes(),
                     (root/'docs/governance/trust-anchor/cell_trust_anchor_config.json').read_bytes()),
                 'unit_review': build_unit_review(source, inventory, _read(
                     str(root/'docs/governance/decomposition/path-dispositions.proposed.json')))}
        if args.command == 'prepare-decomposition-dispositions':
            from tools.governance.decomposition_targets import review_inputs
            value = review_inputs(source, inventory, value['unit_review'])
        return _write(args.out, value), 0
    if args.command == 'resolve-decomposition-inventory':
        inventory = resolve_inventory(source)
        value = {'artifact_kind': 'decomposition_inputs_draft', 'draft_contract': dec.CONTRACT,
                 'inventory': inventory, 'entries': decision_template(inventory)}
        return _write(args.out, value), 0
    if args.command == 'build-decomposition-manifest':
        inputs = _read(args.params)
        exact_fields(inputs, {'artifact_kind', 'draft_contract', 'inventory', 'entries'}, 'decomposition inputs')
        if (inputs['artifact_kind'] != 'decomposition_inputs_draft'
                or inputs['draft_contract'] not in (dec.CONTRACT, dec.LEGACY_CONTRACT)):
            raise ValueError('decomposition: unsupported input contract')
        candidate = dec.build_candidate(source, inputs['inventory'], inputs['entries'], args.generated_at,
                                        inputs['draft_contract'])
        governance = inspect_governance()
        result = _write(args.out, candidate)
        result.update({'validation_status': candidate['validation_status'], 'governance': governance})
        return result, 0
    candidate = _read(args.input)
    dec.verify_candidate(source, candidate)
    governance = inspect_governance()
    return {'candidate_matches_recomputation': True, 'validation_status': 'INCOMPLETE',
            'pending_decision_count': candidate['pending_decision_count'],
            'admission_blockers': candidate['admission_blockers'], 'governance': governance,
            'signable': False}, 5


def register(subparsers, handler) -> None:
    for command in ('resolve-decomposition-inventory', 'build-decomposition-manifest',
                    'verify-decomposition-manifest', 'prepare-decomposition-review',
                    'prepare-decomposition-dispositions'):
        parser = subparsers.add_parser(command, help='local unratified draft; never a signable envelope')
        parser.add_argument('--legacy-repo', required=True)
        if command != 'verify-decomposition-manifest':
            parser.add_argument('--out', required=True)
        if command == 'build-decomposition-manifest':
            parser.add_argument('--params', required=True)
            parser.add_argument('--generated-at', required=True)
        elif command == 'verify-decomposition-manifest':
            parser.add_argument('--in', dest='input', required=True)
        parser.set_defaults(func=handler)
