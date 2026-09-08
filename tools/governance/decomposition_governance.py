"""Read-only checks against existing public Gate-2/run/manual/epoch-3 artifacts.

This does not install the proposed contract-inventory runtime or admit the
future decomposition-owner profile.
"""
from __future__ import annotations

import base64
from pathlib import Path

from tools.governance import p1
from tools.governance.decomposition_common import digest, timestamp
from tools.governance.decomposition_scope import BASELINE, REPOSITORY
from tools.governance.jcs import canonicalize, loads_strict
from tools.governance.locator import Store, make_locator

REPO_ROOT = Path(__file__).resolve().parents[2]
ANCHOR_PUBLIC = '/BR0HdhylfJYte950hx1m/QNGCpfX/368Eyy5PiYbEI='
ADR_DIGEST = 'sha256:239b53e0af44c176b78c363dc271c9fd882910bd4ab2ffb6844cb8fb2458640e'
SCHEMA = 'smart_ads/decomposition_manifest/v1'


def _load(path: Path) -> dict:
    try:
        text = path.read_text()
    except OSError as exc:
        raise ValueError(f'governance: missing or unreadable {path.name} ({type(exc).__name__})') from exc
    value = loads_strict(text)
    if not isinstance(value, dict):
        raise ValueError('governance: expected JSON object')
    return value


def _registry(store: Store, locator: dict, anchor_public: bytes | None = None) -> dict:
    value = store.get(locator)
    if value.get('$schema') != 'smart_ads/key_authorization_registry/v1':
        raise ValueError('governance: incorrect registry schema')
    p1.verify_envelope(value, p1.DOMAIN_PREFIXES['key_authorization_registry/v1'],
                       anchor_public if anchor_public is not None else base64.b64decode(ANCHOR_PUBLIC))
    return value


def _int(value: object, label: str) -> int:
    if type(value) is not int:
        raise ValueError(f'governance: {label} must be an integer')
    return value


def _key_id(entry: object) -> str:
    if not isinstance(entry, dict) or not isinstance(entry.get('key_id'), str):
        raise ValueError('governance: registry entry is missing key_id')
    return entry['key_id']


def _continues(previous: dict, current: dict) -> None:
    """`current` may only extend `previous`: same keys, identical entry fields, actions superset.

    Deliberately conservative and confined to offline observation. D4 does permit
    withdrawing a historical action that no check requires, but that judgement needs
    the protected current key state, which is unavailable here; offline, a withdrawal
    and a rollback are indistinguishable. `AdmissionVerifier` never consults this rule.
    """
    before = {_key_id(e): e for e in previous['entries']}
    after = {_key_id(e): e for e in current['entries']}
    if len(after) != len(current['entries']):
        raise ValueError('governance: registry repeats a key_id')
    for key_id, entry in before.items():
        if key_id not in after:
            raise ValueError('governance: registry drops a previously observed key')
        newer = after[key_id]
        for field in entry:
            if field == 'allowed_actions':
                continue
            if newer.get(field) != entry[field]:
                raise ValueError(f'governance: registry changes {field} of an observed key')
        missing = [a for a in entry['allowed_actions'] if a not in newer['allowed_actions']]
        if missing:
            raise ValueError('governance: registry withdraws an observed action; not decidable offline')


def observed_registry_chain(store: Store, references: list[dict], anchor_public: bytes, anchor_id: str,
                            anchor_validity: dict, historical: dict) -> list[dict]:
    """Return the contiguous registry chain from the historical floor to the newest observed epoch.

    Signatures are checked against the anchor public key pinned in protected configuration,
    never against the store contents: only registries named by a file in this working tree are
    considered, each must verify under the anchor, and epochs must continue the floor without
    gaps or loss. Any violation in a referenced file fails closed.

    A local file proves neither publication nor current authority. Removing one lowers the
    result, and nothing here protects against rollback in the sense the D4 runtime does: only
    the protected current key state decides authority.
    """
    floor_object = _registry(store, historical, anchor_public)
    floor_epoch = _int(floor_object['epoch'], 'historical epoch')
    by_epoch: dict[int, dict] = {}
    seen_floor = False
    for locator in references:
        registry = _registry(store, locator, anchor_public)
        epoch = _int(registry['epoch'], 'registry epoch')
        if registry.get('trust_anchor_id') != anchor_id:
            raise ValueError('governance: referenced registry names a different trust anchor')
        issued = timestamp(registry['issued_at_utc'])
        if not timestamp(anchor_validity['from']) <= issued < timestamp(anchor_validity['until']):
            raise ValueError('governance: referenced registry issued outside anchor validity')
        same_bytes = canonicalize(registry) == canonicalize(floor_object)
        if epoch < floor_epoch:
            continue  # predecessor of the floor (e.g. epochs 1-2): historical provenance, never authority
        if epoch == floor_epoch and not same_bytes:
            raise ValueError('governance: referenced registry reuses the historical floor epoch')
        if same_bytes:
            seen_floor = True
        if epoch in by_epoch and canonicalize(by_epoch[epoch]) != canonicalize(registry):
            raise ValueError('governance: two referenced registries share an epoch with different bytes')
        by_epoch[epoch] = registry
    if not seen_floor:
        raise ValueError('governance: historical floor registry is not referenced in the working tree')
    chain = [floor_object]
    epoch = floor_epoch
    while epoch + 1 in by_epoch:
        nxt = by_epoch[epoch + 1]
        if timestamp(nxt['issued_at_utc']) < timestamp(chain[-1]['issued_at_utc']):
            raise ValueError('governance: registry issuance time goes backwards')
        _continues(chain[-1], nxt)
        chain.append(nxt)
        epoch += 1
    if max(by_epoch) != epoch:
        raise ValueError('governance: referenced registry skips an epoch in the chain')
    return chain


def _signed(store: Store, locator: dict, schema: str, action: str, time_field: str) -> dict:
    value = store.get(locator)
    if value.get('$schema') != 'smart_ads/' + schema:
        raise ValueError('governance: predecessor schema mismatch')
    registry = _registry(store, value['integrity']['key_registry_snapshot_locator'])
    matches = [e for e in registry['entries'] if _key_id(e) == value['integrity']['key_id']]
    if len(matches) != 1:
        raise ValueError('governance: signer must match exactly one registry entry')
    entry = matches[0]
    if (entry['lifecycle_state'] != 'active'
            or {'schema': value['$schema'], 'action': action} not in entry['allowed_actions']):
        raise ValueError('governance: predecessor signer lacks exact action')
    when = timestamp(value[time_field])
    if not timestamp(entry['validity']['from']) <= when < timestamp(entry['validity']['until']):
        raise ValueError('governance: signer outside historical validity')
    p1.verify_envelope(value, p1.DOMAIN_PREFIXES[schema],
                       base64.b64decode(entry['public_key_base64'], validate=True))
    return value


def historical_prerequisites(root: Path = REPO_ROOT) -> dict:
    """Reject invalid existing prerequisites over the fixed step-2/Gate-2 artifacts.

    Signature and link checks only, over artifacts named by locators that do not move.
    Nothing here discovers anything in the working tree and nothing here decides current
    authority: `AdmissionVerifier` calls this and takes authority from the protected
    current key state alone.

    The root is trusted local configuration, not taken from a candidate file.
    Historical checks do not claim complete fresh-at-effect Gate-3 validation.
    """
    gov = root / 'docs/governance'
    store = Store(gov / 'cell-objects')
    anchor = _load(gov / 'trust-anchor/cell_trust_anchor_config.json')
    if anchor['public_key_base64'] != ANCHOR_PUBLIC:
        raise ValueError('governance: configured anchor differs from pinned public identity')
    manual_loc = _load(gov / 'run-context/params/delivery_mode_store_put.out')
    manual = _signed(store, manual_loc, 'delivery_mode_decision_receipt/v1',
                     'delivery_mode_decide', 'decided_at_utc')
    run = _signed(store, manual['run_context_locator'], 'migration_run_context/v1',
                  'run_context_initialize', 'created_at_utc')
    gate = _signed(store, run['gate2_receipt_locator'], 'gate2_approval_receipt/v1',
                   'gate2_approve', 'approved_at_utc')
    if manual['delivery_mode'] != 'manual' or gate['approval_status'] != 'approved':
        raise ValueError('governance: requires signed manual delivery and approved Gate 2')
    if manual['gate2_receipt_locator'] != run['gate2_receipt_locator']:
        raise ValueError('governance: mixed Gate-2 predecessors')
    identity = gate['approved_adr_git_identity']
    if identity != manual['approved_adr_git_identity'] or identity != run['approved_adr_git_identity']:
        raise ValueError('governance: inconsistent approved ADR identity')
    if (identity['path'] != 'docs/adr/ADR-0001-smart-ads-read-gateway.md'
            or identity['file_content_sha256'] != ADR_DIGEST
            or digest((root / identity['path']).read_bytes()) != ADR_DIGEST):
        raise ValueError('governance: approved ADR bytes changed; draft patch must stay separate')
    if run['legacy_source_identity'] != {'repository': REPOSITORY, 'commit_sha': BASELINE}:
        raise ValueError('governance: source identity mismatch')
    reg_loc = _load(gov / 'legacy-step2/params/registry_epoch3_store_put.out')
    registry = _registry(store, reg_loc)
    if type(registry['epoch']) is not int or registry['epoch'] != 3:
        raise ValueError('governance: unexpected historical epoch-3 snapshot')
    action = any(a == {'schema': SCHEMA, 'action': 'decomposition_manifest_issue'}
                 for e in registry['entries'] for a in e['allowed_actions'])
    return {'predecessor_signatures_and_links': 'PASS', 'manual_delivery': True,
            'approved_adr_unchanged': True, 'legacy_baseline_pinned': True,
            'epoch3_has_decomposition_action': action, 'registry_locator': reg_loc,
            'contract_inventory_admission': 'NOT_INSTALLED',
            'proposed_runtime_verifier': 'tools.governance.decomposition_runtime.AdmissionVerifier',
            'contract_ratification': 'NOT_RATIFIED', 'signable': False,
            'scope': 'historical offline prerequisites; not authority for new effects'}


def inspect_governance(root: Path = REPO_ROOT) -> dict:
    """Historical prerequisites plus the registry observed in this working tree.

    For local reporting only. The observation fields describe files present here now;
    they are not publication, admission, or current authority. The protected runtime
    calls `historical_prerequisites` instead and never consumes these fields.
    """
    result = historical_prerequisites(root)
    gov = root / 'docs/governance'
    store = Store(gov / 'cell-objects')
    anchor = _load(gov / 'trust-anchor/cell_trust_anchor_config.json')
    # Files under docs/governance name the objects, signatures are checked under the
    # protected anchor, and the chain must continue the epoch-3 floor. The floor locator
    # stays reported unchanged as the historical step-3 reference.
    references = [_load(p) for p in sorted(gov.glob('*/params/*registry*store_put.out'))]
    chain = observed_registry_chain(store, references, base64.b64decode(ANCHOR_PUBLIC),
                                    anchor['trust_anchor_id'], anchor['validity'],
                                    result['registry_locator'])
    latest = chain[-1]
    latest_loc = make_locator(latest['$schema'], canonicalize(latest))  # read-only: no store write
    latest_action = any(a == {'schema': SCHEMA, 'action': 'decomposition_manifest_issue'}
                        for e in latest['entries'] for a in e['allowed_actions'])
    return dict(result, **{
        'locally_observed_registry_locator': latest_loc, 'locally_observed_epoch': latest['epoch'],
        'locally_observed_has_decomposition_action': latest_action,
        'locally_observed_registry_scope': ('newest anchor-signed registry locally observed in this '
                                            'working tree; not evidence of a current key state')})
