"""Offline candidate builder under the unratified local Step-4 contract.

The candidate is not a profiled/P1 envelope. No runtime signing domain is added.
Governance admission is separate from mechanical coverage and caller decisions.
"""
from __future__ import annotations

import copy

from tools.governance.decomposition_common import exact_fields, json_digest, timestamp
from tools.governance.decomposition_decisions import validate_entry
from tools.governance.decomposition_scope import SourceSnapshot
from tools.governance.decomposition_selectors import validate_inventory
from tools.governance.jcs import canonicalize

CONTRACT = 'step4-local-draft-v2'
LEGACY_CONTRACT = 'step4-local-draft-v1'
BLOCKERS = ['contract_amendment_not_ratified', 'decomposition_profile_not_admitted',
            'human_decision_review_not_attested']


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
        from tools.governance.decomposition_targets import validate_targets
        validate_targets(source, inventory, list(indexed.values()))
    return [copy.deepcopy(indexed[k]) for k in sorted(indexed, key=lambda k: k.encode('utf-8'))]


def build_candidate(source: SourceSnapshot, inventory: dict, entries: list, generated_at: str,
                    contract: str = CONTRACT) -> dict:
    if contract not in (CONTRACT, LEGACY_CONTRACT):
        raise ValueError('manifest: unknown draft contract')
    timestamp(generated_at)
    validate_inventory(source, inventory)
    ordered = _ordered_entries(source, inventory, entries, contract)
    pending = sum(e['decision_status'] is None for e in ordered)
    defects = sum(bool(e['blocking_defects']) for e in ordered)
    count = len(inventory['items'])
    payload = {'generated_at': generated_at, 'supersedes_manifest_locator': None,
               'supersedes_digest': None, 'correction_reason': None,
               'source_inventory': copy.deepcopy(inventory),
               'coverage_assertion': {'inventory_item_count': count, 'entry_count': count,
                                      'assigned_item_count': count, 'unassigned_item_count': 0,
                                      'duplicate_assignment_count': 0, 'conflict_count': 0},
               'entries': ordered}
    # This digest describes the candidate payload, not a final signed manifest.
    return {'artifact_kind': 'decomposition_candidate', 'draft_contract': contract,
            'signable': False, 'validation_status': 'INCOMPLETE' if pending or defects else 'STRUCTURALLY_VALID',
            'pending_decision_count': pending, 'blocking_defect_entry_count': defects,
            'admission_blockers': list(BLOCKERS), 'payload': payload,
            'candidate_payload_digest': manifest_digest(payload)}


def verify_candidate(source: SourceSnapshot, candidate: dict) -> None:
    exact_fields(candidate, {'artifact_kind', 'draft_contract', 'signable', 'validation_status',
                            'pending_decision_count', 'blocking_defect_entry_count',
                            'admission_blockers', 'payload', 'candidate_payload_digest'}, 'candidate')
    payload = candidate['payload']
    exact_fields(payload, {'generated_at', 'supersedes_manifest_locator', 'supersedes_digest',
                          'correction_reason', 'source_inventory', 'coverage_assertion', 'entries'}, 'payload')
    expected = build_candidate(source, payload['source_inventory'], payload['entries'], payload['generated_at'], candidate['draft_contract'])
    if canonicalize(candidate) != canonicalize(expected):
        raise ValueError('candidate: recomputed content/digest/status mismatch')
