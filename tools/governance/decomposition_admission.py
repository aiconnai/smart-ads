"""Prepare a reproducible D4 contract proposal, never bootstrap authority."""
from __future__ import annotations

from tools.governance.decomposition_common import digest, json_digest
from tools.governance.decomposition_governance import ADR_DIGEST
from tools.governance.jcs import canonicalize, loads_strict

TRUST_DIGEST = 'sha256:bda7f38dfe36fc083f11bfa8502bc0d0e458319026c87c893fa86210b901a8ad'
POLICIES = {
    'E': 'historical_registry_plus_monotonic_current_state_before_new_effect',
    'H': 'historical_issuance_and_validity_for_replay_E_before_new_effect',
    'T': 'named_effect_authenticated_clock_interval_replay_never_new_authority',
    'A': 'protected_trust_configuration_and_validity_no_current_key_dependency',
}
STEPS = (
    ('protected_configuration', [], 'protected_bytes_hash_installation_authority_and_validity'),
    ('provisional_inventory', ['protected_configuration'], 'pinned_bootstrap_profile_P1_closed_unique_rows'),
    ('anti_rollback_checkpoint', ['provisional_inventory'], 'config_pinned_A_profile_and_protected_highest_seen_CAS'),
    ('current_key_authority', ['anti_rollback_checkpoint'], 'checkpoint_row_equality_head_state_registry_epoch_digest_equalities'),
    ('inventory_E_validation', ['current_key_authority'], 'current_authority_revocation_and_inventory_validity'),
    ('decomposition_H_validation', ['inventory_E_validation'], 'exact_profile_owner_action_historical_validity_and_candidate_semantics'),
)


def profile_proposals(adr: bytes) -> list[dict]:
    """Expand all 116 pinned table rows; semantic IDs remain proposed bindings."""
    if digest(adr) != ADR_DIGEST:
        raise ValueError('admission: ADR must equal the approved bytes')
    section = adr.decode('utf-8').split('### 12.7 Schema-Specific Verification Profiles\n', 1)[1]
    section = section.split('\n## 13.', 1)[0]
    profiles = []
    for line in section.splitlines():
        if not line.startswith('| `') or ' | P1 | ' not in line:
            continue
        cells = [s.strip() for s in line.strip('|').split('|')]
        if len(cells) != 7:
            raise ValueError('admission: unexpected profile table shape')
        schema, preimage, role, policy_time, domain, predicate, slot = cells
        schema = schema.strip('`')
        policy, time = policy_time.split(' / ', 1)
        profiles.append({
            'schema': 'smart_ads/' + schema,
            'digest_json_pointer': '/integrity/content_digest',
            'signature_json_pointer': '/integrity/signature_base64',
            'preimage_rule': preimage,
            'signer_role': role,
            'current_revocation_policy': POLICIES[policy],
            'time_policy': {'code': policy, 'interval_semantics': time},
            'domain_prefix': domain.strip('`').replace('\\n', '\n'),
            'semantic_predicate_id': 'adr0001_v19:' + schema,
            'dag_slot': slot,
        })
    if len(profiles) != 116 or len({p['schema'] for p in profiles}) != 116:
        raise ValueError('admission: require the complete 116 unique profile rows')
    return sorted(profiles, key=lambda p: p['schema'].encode('utf-8'))


def build_admission_proposal(adr: bytes, trust_config: bytes) -> dict:
    profiles = profile_proposals(adr)
    if digest(trust_config) != TRUST_DIGEST:
        raise ValueError('admission: historical trust configuration identity changed')
    trust = loads_strict(trust_config.decode('utf-8'))
    by_schema = {p['schema']: p for p in profiles}
    inventory_schema = 'smart_ads/artifact_contract_inventory/v1'
    checkpoint_schema = 'smart_ads/key_state_anti_rollback_checkpoint/v1'
    value = {
        'artifact_kind': 'decomposition_admission_contract_proposal',
        'contract_version': 'step4-admission-proposal-v1',
        'authority': 'none', 'signable': False, 'human_ratification': None,
        'approved_adr_sha256': ADR_DIGEST, 'historical_trust_config_sha256': TRUST_DIGEST,
        'profile_count': len(profiles), 'profiles_proposed': profiles,
        'predicate_bindings_proposed': [
            {'semantic_predicate_id': 'adr0001_v19:' + cells[0].strip('`'),
             'normative_requirement': cells[5], 'executable_binding': None}
            for line in adr.decode('utf-8').split('### 12.7 Schema-Specific Verification Profiles\n', 1)[1].split('\n## 13.', 1)[0].splitlines()
            if line.startswith('| `') and ' | P1 | ' in line
            for cells in [[s.strip() for s in line.strip('|').split('|')]]
        ],
        'protected_config_amendment_proposed': {
            'preserve_existing_fields': trust,
            'add_allowed_artifact_types': [inventory_schema],
            'inventory_bootstrap_profile': by_schema[inventory_schema],
            'anti_rollback_checkpoint_profile': by_schema[checkpoint_schema],
            'cell_id': None, 'key_state_head_register': None,
            'anti_rollback_checkpoint_register': None,
            'installation_receipt': None,
            'rule': 'install_out_of_band_then_pin_complete_new_bytes_and_hash; never_request_selectable',
        },
        'owner_binding_proposed': {
            'principal': 'principal:ronaldo', 'tenant': 'mbras',
            'registry_role': 'decomposition_owner', 'profile_role': 'decomposition owner',
            'schema': 'smart_ads/decomposition_manifest/v1',
            'action': 'decomposition_manifest_issue', 'key_id': None,
            'key_policy': 'dedicated_human_supplied_public_key; preserve_existing_registry_entries',
            'registry_epoch': 4, 'historical_snapshot_epoch': 3,
        },
        'role_bindings_proposed': {'external trust anchor': 'trust_anchor',
                                   'decomposition owner': 'decomposition_owner'},
        'anchor_actions_proposed': [
            {'schema': 'smart_ads/artifact_contract_inventory/v1', 'action': 'contract_inventory_issue'},
            {'schema': 'smart_ads/current_key_state/v1', 'action': 'current_key_state_issue'},
            {'schema': 'smart_ads/current_key_state_head/v1', 'action': 'current_key_state_head_issue'},
        ],
        'checkpoint_A_rule': 'only_protected_configuration; never consult the registry/current state it bootstraps',
        'ordered_checks': [{'id': name, 'depends_on': deps, 'predicate': pred}
                           for name, deps, pred in STEPS],
        'release_condition': 'all_checks_verified_by_implemented_verifier; proposal_flags_are_not_evidence',
        'unimplemented_runtime_checks': [s[0] for s in STEPS],
    }
    value['proposal_digest'] = json_digest(value)
    return value


def validate_admission_proposal(value: dict, adr: bytes, trust_config: bytes) -> None:
    """Byte/type-sensitive recomputation. This validates the draft, not admission."""
    if canonicalize(value) != canonicalize(build_admission_proposal(adr, trust_config)):
        raise ValueError('admission: proposal differs from pinned contract; not admission evidence')
