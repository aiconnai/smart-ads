# Smart Ads Governance

Cryptographic and structural governance for the Smart Ads Read Gateway migration (ADR-0001), covering P1-signed envelopes, content-addressed artifact locators, Gate-2 approval evidence, Step-4 legacy decomposition candidates, and D4 runtime admission verification.

## Language

### Envelopes & Content Addressing

**Envelope**:
A canonical JSON governance document identified by a `$schema` URI that is either pinned out of band or signed under the P1 Ed25519 signature profile.
_Avoid_: Document, payload, record, message

**Preimage**:
The canonicalized JSON byte sequence of an Envelope with `/integrity/content_digest` and `/integrity/signature_base64` removed before computing the P1 content digest and Ed25519 signature.
_Avoid_: Unsigned body, raw payload, signable dict

**Locator**:
A closed 6-member content-addressed reference (`smart_ads/artifact_locator/v1`) binding `$schema`, `artifact_type`, `content_digest`, `serialization` (`rfc8785-json`), `store_kind` (`cell_immutable_object`), and digest-addressed `object_ref` inside the cell object store.
_Avoid_: Pointer, reference, URI, handle

### Authority & Runtime Admission (D4)

**Trust Anchor**:
The out-of-band root Ed25519 public key configuration (`cell_trust_anchor_config/v1`) that authenticates Key Authorization Registries and bootstrap runtime authority artifacts.
_Avoid_: Root CA, master key, bootstrap key

**Key Authorization Registry**:
A Trust Anchor-signed epoch snapshot (`key_authorization_registry/v1`) mapping Ed25519 `key_id` identities to principals, roles, validity windows, lifecycle states, and allowed `(schema, action)` pairs.
_Avoid_: Keyring, key list, ACL

**Current Key State**:
The monotonic, Trust Anchor-signed runtime authority projection (`current_key_state/v1`) paired with its head pointer (`current_key_state_head/v1`) that decides live key revocation and active epoch authority at admission time.
_Avoid_: Observed registry chain, local key cache, active keyring

**Anti-Rollback Checkpoint**:
The non-decreasing `current_key_state_head/v1` floor anchored by the Trust Anchor-signed bootstrap envelope (`key_state_anti_rollback_checkpoint/v1`: `highest_seen_epoch`, `head_digest`) and maintained in a protected register (`Floor`: `epoch`, `head_digest`, CAS `version`).
_Avoid_: Watermark, high-water mark, epoch counter

**Protected Runtime**:
The out-of-band execution substrate (`ProtectedRuntime`) and its immutable `InstallationPins` that provide authenticated clock intervals, head/checkpoint registers, and atomic compare-and-swap transitions to `AdmissionVerifier`.
_Avoid_: Runtime service, database adapter, environment

### Legacy Decomposition (Step 4)

**Source Snapshot**:
The immutable, offline-resolved set of 44 regular Git blobs (`SourceSnapshot`) from the pinned legacy commit (`mbras-tech/mbras-campaigns` at `d26c73d8508c7c3d43161fe36a80c44a46bf0f2d`).
_Avoid_: Working tree, repo checkout, file list

**Source Selector**:
A closed byte-range or CPython 3.12 AST symbol/region descriptor (`whole_file`, `ast_symbol`, or `text_region`) that partitions a file in the Source Snapshot without overlaps or gaps.
_Avoid_: Slice, chunk, AST node, code span

**Source Inventory**:
The deterministic 122-unit partition of the Source Snapshot (43 whole files plus 79 disjoint Source Selectors of `tests/test_security_boundaries.py`).
_Avoid_: Symbol catalogue, file manifest

**Decomposition Candidate**:
An unsigned, quarantined Step-4 draft (`artifact_kind: "decomposition_candidate"`, omitting `$schema` and `integrity`, with `signable: False` and explicit `admission_blockers`) assigning every unit in the Source Inventory a migration mode, target destination, and ADR §9.2 routing disposition without crossing into `smart_ads/decomposition_manifest/v1`.
_Avoid_: Signed manifest, final manifest, migration plan

**Unit Review Packet**:
The human-reviewable disposition proposal (`decomposition_unit_review_proposals`) and companion bundle (`decomposition_review_bundle`) pairing each Source Inventory unit with its ADR §9.2 routing rationale and admission contract proposal.
_Avoid_: Review report, disposition manifest
