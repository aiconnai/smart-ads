# D4 runtime and target assembly supplement — proposed, not ratified

This supplements `ADMISSION-CONTRACT.proposed.md` and the v1 local draft.
It does not change the approved ADR, install protected configuration, authorize
an effect, register a signing CLI domain, or approve any source disposition.
The existing `admission-contract.proposed.json` remains the reproducible record
of the earlier proposal; its `unimplemented_runtime_checks` is historical.

## Implemented boundary

`tools.governance.decomposition_runtime.AdmissionVerifier` implements the six
named D4 checks using P1 signatures, typed immutable locators, exact profiles,
historical registries, current head/state chains and a protected CAS protocol.
It supports a genesis decomposition manifest only. Immutable corrections fail
closed until a predecessor-semantic implementation exists.

Only these six checks are executable here. The full 116-row profile inventory
is checked against the pinned ADR table; this does **not** implement the other
schemas' semantic predicates. This module cannot serve as a generic verifier.

The verifier is an application library, not a request-selectable CLI adapter.
`InstallationPins` and `ProtectedRuntime` are constructed by trusted application
integration, never from a candidate, manifest, registry or CLI params. The
source argument must be obtained from `resolve_scope`, which pins the actual
legacy commit, tree, path universe and modes. Synthetic snapshots and ephemeral
keys appear only in tests. Existing signed Gate-2/run/manual prerequisites are
reverified from the fixed repository store before admission.

No production `ProtectedRuntime` adapter is installed or supplied. The existing
protected config lacks the new fields and its digest is unchanged. The normal
candidate CLI therefore reports `NOT_INSTALLED` and `signable: false`; it does
not silently substitute local files, an ordinary clock, or an in-memory CAS.

## Closed proposed wire shapes

These fields supplement ADR §12.1/§12.7, which specify semantic obligations
without a complete wire shape for these objects. Ratification binds these
exact names and rules. All objects are closed; unknown members reject.

All signed objects use exactly the four integrity fields already implemented
by P1: `key_id`, `key_registry_snapshot_locator`, `content_digest`,
`signature_base64`. The registry and sole A checkpoint have a null registry
locator; other signed objects have exactly one typed immutable registry locator.
Typed locators address the full canonical signed bytes, not the P1 preimage.

The protected config preserves its six existing identity/validity/allowlist
fields and `$schema`, and adds `inventory_bootstrap_profile`,
`anti_rollback_checkpoint_profile`, `cell_id`, `head_register`,
`checkpoint_register`, `installation_authority`. Its exact bytes/hash,
installation authority, cell and register identities are externally pinned.
The allowlist is exactly registry then contract-inventory. Both bootstrap
tuples must equal their complete ADR-expanded profile rows.

Every inventory, checkpoint, head and state has `$schema`, `trust_anchor_id`,
`cell_id`, `issued_at_utc`, `valid_until_utc`, `maximum_age_seconds`, `integrity`.
Their additional fields are:

| Object | Additional fields |
|---|---|
| Contract inventory | `epoch`, `predecessor_inventory_locator`, `profiles` |
| A checkpoint | `highest_seen_epoch`, `head_digest` |
| Key-state head | `epoch`, `current_state_locator`, `current_state_digest`, `predecessor_head_locator`, `predecessor_head_digest` |
| Key state | `epoch`, `registry_locator`, `predecessor_state_locator`, `key_states` |

Profiles are the 116 exact rows sorted by UTF-8 schema. Genesis inventory and
head/state epochs are 1 with null predecessors. Subsequent epochs increment by
one, link completely to genesis, and never reverse issuance time. A traversal
over 256 objects rejects rather than accepting a truncated chain. Historical
inventory tables must equal the pinned table; changing the table requires new
protected pins and verifier support. A state and its head share epoch and
issuance time; their registry locators are equal. Each head's predecessor state
is exactly the state named by the predecessor head. Registry epochs never
decrease along that chain; same-epoch different bytes reject.

`key_states` repeats every current registry entry's `key_id`, public-key hash
and lifecycle in registry order, with no omissions or extensions. The registry
shape remains the existing toolkit shape. Keys are unique by ID and public
bytes; hashes, canonical public-key encoding, validity, lifecycle and unique
exact schema/action pairs are checked. Owner admission requires the separately
pinned principal and tenant, role `decomposition_owner`, and exact
`decomposition_manifest_issue` action. Historical snapshots prove issuance;
current state independently rejects missing, revoked, expired or rebound keys.
It also requires the exact actions used by this verification to remain allowed
in the current registry: inventory/head/state issuance for the anchor and
manifest issuance for the owner. Withdrawal of unrelated historical actions
does not block. This is an explicit conservative proposed rule, not an inference
that a historical signature grants current authority.

For that rule to hold, the verifier consumes only `historical_prerequisites`,
which checks signatures and links over fixed step-2/Gate-2 locators. It never
consumes `inspect_governance`, whose registry-chain observation scans the local
working tree and, lacking any current key state, must treat every withdrawal as
indistinguishable from a rollback. That offline observation is local reporting:
a file present in a tree is not publication, not admission, and not authority.

## Protected state and ordering

`authenticated_clock()` supplies typed closed bounds, not a request timestamp.
The entire interval must fit each proof's validity and maximum age. Config and
key validity use their existing half-open interval convention. Unknown bounds,
future issuance, reversed clock, malformed integers (including bool), and
expiration at the final authenticated observation reject.

`read_checkpoint()` returns the signed A bootstrap checkpoint plus a protected
`Floor(epoch, head_digest, version)`. Epoch 0 has a null digest. The protected
floor can be newer than the signed bootstrap checkpoint; the complete verified
head chain must contain both exact identities. This allows monotonic progress
without requiring the human anchor to re-sign on each verification.

Step 3 validates the A signature, protected floor and CAS precondition. Step 4
verifies the full authoritative head/state chain. The floor update is delayed
until **all** dependent artifact checks succeed. The one atomic
`compare_and_swap` must compare the floor version **and** authoritative head
locator together, then advance the floor with a new opaque version. The runtime
must provide that linearizable transaction across the configured registers.
An implementation that merely compares a cached head is non-conforming.

CAS is a write. This session exercises only the synthetic in-memory runtime.
A CAS conflict rejects. Head advancement or expiry after CAS also rejects;
the monotonic floor is preserved, not rolled back. The caller must retry full
verification. `observe_head_and_clock()` supplies one coherent observation
after all second-pass store/signature/config I/O. Only pure comparisons follow
it, so head advancement or expiry during that work also rejects. As with any
read observation, this is not a lock against future advancement or elapsed time
after the observation. This atomic observation is another required runtime
integration guarantee; separate cached reads do not implement it.
Success returns `VERIFIED` with `effect_authorized: false` and
the checked head/digests. There is no receipt, reservation or I/O authorization;
an eventual effect executor must repeat its own immediate pre-I/O protocol.

## Target selectors: local draft v2

New candidates use `step4-local-draft-v2`; v1 candidates are recomputed under
their original rules. The approved ADR remains unchanged.

`retained_source` contains exactly `selector_kind`, `inventory_id`,
`source_commit`, `source_selector_digest`. It names the exact unchanged source
span at the legacy path/repository/layer, with `legacy_governance_only` mode.
Inventory coverage already proves those retained spans do not overlap. This
supports the 28-member retained legacy security-file group.

`planned_assembly_member` contains exactly `selector_kind`, `assembly_id`,
`inventory_id`, `role`, `companion_inventory_id`. An assembly has exactly one
decorator residual and its adjacent AST definition, in that source order. The
assembly ID hashes repository/layer/path, sorted member IDs and the fixed rule
`decorator_before_definition_clean_reimplementation_v1`. Owner, decision,
invariants, required tests, compatibility surface, defects and migration mode
must agree across both members. Missing members, disagreement, mismatched
companions, unsupported sharing or a selector with the wrong source reject.

These selectors describe a future clean reimplementation. They do not claim
target code or target byte ranges exist, and do not copy source code. Three
two-member groups use this rule. Source helper dependencies remain in the
separate unit-review artifact and remain work for implementation.

`prepare-decomposition-dispositions --legacy-repo ... --out ...` recomputes
the fixed reviewed proposal and materializes its targets/selectors while
leaving **every** `decision_status` and `system_owner` null. The subsequent
build/verify still returns a non-signable candidate with pending human review.

## Remaining authority work

Ratification of these contracts and all per-unit dispositions; human-supplied
owner public-key binding; an authorized registry revision; protected config
installation; authenticated head/clock/checkpoint integration; signed inventory
and signed manifest are still absent. Local implementation/test success is
not evidence that any of those steps occurred.
