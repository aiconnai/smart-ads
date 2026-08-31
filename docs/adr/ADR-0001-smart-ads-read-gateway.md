# ADR-0001: Smart Ads Read Gateway & Recurrent Analytics Architecture

- **Status:** Proposed / Awaiting Formal Approval (GATE HUMANO 2)
- **Decision Date:** 2026-08-30
- **Scope:** Read Plane Gateway, Lakehouse-Style Embedded Data Plane (`landing/`), Single Initial Operational Driver (`pipeboard_hosted`), Metric Certification Model, Semantic Metric Registry, and Canonical Migration DAG
- **Decision Owners:** MBRAS Group / aiconnai
- **Target Canonical Repository:** `aiconnai/smart-ads`
- **Source Legacy Repository:** `mbras-tech/mbras-campaigns`
- **Consumer Repository:** `limaronaldo/hermes-ronaldo`

---

## 1. Context & Problem Statement

Historical ad operations in luxury real estate (MBRAS Group / Pinna) required manual, ad-hoc pulls and human verification for every performance report. While the legacy workspace (`mbras-tech/mbras-campaigns`) established valuable contracts, safety boundaries, and naming governance, recurrence was blocked by structural coupling between business rules, customer data, and execution runtime.

The missing product is not another general-purpose marketing backend. It is a **governed, recurrent, read-only media intelligence gateway** that:
1. Operates within tenant private cells with zero raw PII or secret leakage;
2. Packages live and historical evidence deterministically into an embedded lakehouse-style data plane (`landing/`);
3. Normalizes marketing metrics into immutable semantic identities with certified UI reconciliation;
4. Enforces the foundational law of regression testing: `conversions = 65` vs `canonical leads = 23` are distinct semantic entities;
5. Evaluates functional intelligence rules (audience saturation, budget waste, stalled delivery, and retroactive restatements) over synthetic truth tables; and
6. Exposes a clean, read-only MCP interface for consumers (such as Hermes) while strictly isolating all mutation capabilities.

---

## 2. Supersession & Lineage Map (`Supersedes`)

This document defines the target architecture for the Read Plane. Formal supersession of `DOCUMENTATION/IBVI_ADS_OPERATOR_ADR.md` is **strictly partial, conditional, and phased**: the legacy ADR remains active during `direct → shadow → gateway → rollback` and is superseded **exclusively for the explicit Read Plane Allowlist** upon completion of post-retirement verification and issuance of the verified terminal `migration_completion_record/v1`.

### 2.1 Explicit Read Plane Supersession Allowlist
Upon issuance of `migration_completion_record/v1`, ADR-0001 supersedes the legacy ADR **only** for:
1. Analytical reporting and ad data collection architecture;
2. Metric semantic definitions for ad platforms (excluding CRM/commercial funnel definitions);
3. Analytical Parquet storage, DuckDB indices, and diagnostic pipelines; and
4. Read-only client transport (MCP Gateway).

### 2.2 Preserved Governance (Non-Superseded Scope)
All other areas—including `/ibvi-ads` business mutations, commercial CRM funnel contracts, Customer Match upload policies, CAPI lead writes, autonomous controller review policies, and Pinna operational mutation scripts (5,255 LOC)—**remain governed under existing legacy ADR and workspace policies** until a dedicated Write Plane ADR is formally approved.

| Decision / Area in Legacy ADR | Phased Transition Status | Target Disposition in ADR-0001 |
|---|---|---|
| `/ibvi-ads` as sole business entrypoint | **Active in Legacy during Transition** | Preserved in `mbras-campaigns` throughout transition. In `aiconnai/smart-ads`, the initial transport is the MCP server (`smart_ads.transports.mcp`) with tenant context pinned by cell runtime. |
| Pipeboard as sole live integration | **Active in Legacy** | Refined to single operational driver (`pipeboard_hosted`) under closed `ProviderPort`. `independent_meta_reference_harness` is decoupled as an independent certification reference harness. |
| `operator_run/v1` execution contract | **Preserved & Wrapped** | `operator_run/v1` is preserved intact for exact parity; wrapped by `smart_ads/tenant_execution/v1`. |
| Operational Acceptance Gate | **Preserved & Reconciled** | Literal requirement: **5 relatórios consecutivos em dias úteis aceitos por operador + 4 drafts/ciclos semanais consecutivos aceitos operacionalmente**. |
| Synthetic Collector `daily_collector.py` | **Preserved Fixture-Only** | Retained strictly as offline fixture harness; live collection uses the legacy runner seam. |
| Pinna Mutation Scripts (5,255 LOC) | **Deferred (`defer_to_write_plane`)** | 100% of mutation scripts and Customer Match loaders are deferred to the future **Write Plane ADR**. |

---

## 3. Scope Boundary: 100% Read Plane Isolation & Normative Defenses

ADR-0001 establishes **exclusively the Read Plane**:

```text
┌────────────────────────────────────────────────────────────────────────┐
│                        SMART ADS READ PLANE ARCHITECTURE               │
├────────────────────────────────────────────────────────────────────────┤
│ 1. Contracts & Schemas (smart_ads.contracts)                           │
│    • smart_ads/tenant/v1, front/v1, tenant_execution/v1                │
│    • smart_ads/analytics_landing/v1, curation_execution/v1            │
│    • smart_ads/generation_manifest/v1, dataset_snapshot/v1             │
│    • smart_ads/derived_metric_definition/v1, analysis_execution/v1    │
│    • smart_ads/certification_record/v1, finding/v1, report_execution/v1│
│    • smart_ads/delivery_mode_decision_receipt/v1                       │
│    • smart_ads/authorization_receipt/v1, execution_receipt/v1          │
│    • smart_ads/authorization_reservation_record/v1                     │
│    • smart_ads/reservation_reconciliation_record/v1                    │
│    • smart_ads/authorization_consumption_record/v1                     │
│    • smart_ads/readiness_attestation/v1                                │
│    • smart_ads/daily_acceptance_token/v1, weekly_acceptance_token/v1   │
│    • smart_ads/shadow_acceptance_record/v1                             │
│    • smart_ads/retirement_verification_record/v1                       │
│    • smart_ads/migration_completion_record/v1                          │
├────────────────────────────────────────────────────────────────────────┤
│ 2. Data Plane (Single Persisted Zone: landing/)                        │
│    • In-memory provider sanitization (zero raw payload stored)         │
│    • Atomic partition generation promotion via partition_head/v1 (CAS) │
│    • Ephemeral, rebuildable DuckDB analytical index                    │
├────────────────────────────────────────────────────────────────────────┤
│ 3. Pure Intelligence Layer (smart_ads.application.intelligence)        │
│    • Functional rules: Saturation, Waste, Stalled Delivery, Restatement│
│    • Restatement findings fail-closed (block mutation recommendations) │
├────────────────────────────────────────────────────────────────────────┤
│ 4. Provider Adapter & Certification Model                              │
│    • ProviderPort: closed boundary returning sanitized candidates      │
│    • PipeboardHostedAdapter (driver_id: pipeboard_hosted)              │
│    • 7A Hermetic Offline Certification + Synthetic 65×23 Regression Law│
│    • 7B Live Certification against independent reference               │
├────────────────────────────────────────────────────────────────────────┤
│ 5. Read-Only Transport (Deny-by-Default MCP Tool Inventory)            │
│    • MCP Server (smart_ads.transports.mcp) for Hermes consumption       │
└────────────────────────────────────────────────────────────────────────┘
```

### 3.1 Explicit Non-Goals for ADR-0001
Staging Ports, Approval Stores (SQLite/Postgres), CAS Execution Workers, Customer Match uploads, campaign creation/mutation, budget changes, CAPI lead writes, autonomous schedulers, commercial multi-tenant SaaS features, and writable filesystem APIs are **strictly out of scope**.

### 3.2 Normative Security Defenses
1. **7A Sealed Sandbox Profile:**
   * **Process & System Call Isolation:** Execution runs under strict confinement:
     * `prctl(PR_SET_NO_NEW_PRIVS, 1)` and seccomp-bpf filter blocking `execve`, `execveat`, `fork`, `vfork`, `clone`, `clone3`, `socket`, `connect`, `bind`, `sendto`, and `recvfrom`.
     * Environment variables strictly allowlisted: `PATH=/bin:/usr/bin`, `PYTHONPATH=<isolated_src>`, `LANG=C.UTF-8`, `PYTHONNOUSERSITE=1`, `HOME=/tmp/isolated_home`, `TMPDIR=/tmp/isolated_tmp`.
     * All cloud, ambient token, and provider environment variables are stripped.
     * All non-standard file descriptors ($FD > 2$) are closed prior to test suite execution.
   * **Network Deny-All:** Enforced via network namespace sandbox with disabled loopback (`lo` down) and process-level socket syscall interceptors.
   * **Host Credential Deny-All:** Read-only root filesystem with isolated ramdisks blocking access to `~/.netrc`, `~/.aws`, `~/.config`, and macOS Keychain.
   * **Evidence Binding:** Offline certification (`evidence_kind: fixture_7a`) cryptographically binds `sandbox_profile_digest` and `negative_security_test_report_digest`.
2. **MCP Pre-Handler Deny-by-Default & Transport Parser Bounds:**
   * `smart_ads.transports.mcp` implements a strictly closed inventory of exact tool identifiers:
     * `smart_ads.queries.get_campaign_performance_v1`
     * `smart_ads.queries.get_adset_performance_v1`
     * `smart_ads.queries.get_ad_performance_v1`
     * `smart_ads.queries.get_intelligence_findings_v1`
     * `smart_ads.reports.generate_recurrent_summary_v1`
   * Every tool schema strictly declares `"additionalProperties": false`.
   * **Transport Parser Pre-Parse Bounds:**
     * Maximum request body size: $64\text{ KB}$. Maximum JSON nesting depth: $8$.
     * Strict UTF-8 decoding (`errors='strict'`); duplicate JSON keys rejected immediately.
     * Exceeding limits, duplicate keys, or malformed JSON $\longrightarrow$ `-32700 Parse error`.
     * JSON-RPC batch arrays $\longrightarrow$ `-32600 Invalid Request`.
     * Method not in closed 5-tool inventory $\longrightarrow$ `-32601 Method not found`.
     * Parameter schema violation or undeclared properties $\longrightarrow$ `-32602 Invalid params`.
   * All rejections occur strictly at the transport boundary before any Registry lookup, logging IO, credential resolution, or RPC dispatch.
   * **Zero Filesystem Exposure:** Returns purely in-memory structured JSON. No filesystem APIs are exposed over MCP.

---

## 4. Single Operational Driver & ProviderPort Boundary

### 4.1 Driver Declaration & Phase 1 Grounded Capabilities
Phase 1 operates with exactly one operational driver:
```yaml
driver_id: pipeboard_hosted
transport_provider_ref: pipeboard
ad_platform_ref: meta
ad_platform_api_version:
  status: opaque
  value: null
```

* **Grounded Operational Scope (Phase 1):** In strict accordance with the frozen baseline configuration (`config/operator/meta_daily_get_insights_v1.yaml:16`), `pipeboard_hosted` in Phase 1 supports exclusively:
  * Resource level: `campaign` (only).
  * Supported core metrics: `impressions`, `clicks`, `spend`.
  * Date range: `previous_local_day` relative to request execution timestamp in `reporting_timezone` (`start_date == end_date`).
  * Attribution window: fixed provider default (no caller modification allowed).
  * Breakdowns: none (`[]`).
  * Capabilities outside this scope (e.g. actions, conversions, reach, frequency, ad-level breakdowns, or custom attribution windows) are declared `capability_state: deferred` in Phase 1.
* **Independent Live Reference:** `independent_meta_reference_harness` is used strictly during Gate 3 / 7B live certification. It is not an active operational fallback in Phase 1.
* **API Version Handling:** `pipeboard_hosted` declares `status: opaque` and `value: null` until verifiable upstream vendor attestation is provided. No global static API version is hardcoded into schemas.

### 4.2 Closed Boundary `ProviderPort` Contract & Precondition Enforcement
```python
def collect(request: CollectionRequest) -> CollectionResult:
    ...
```
* **`CollectionRequest` Schema:**
  * `request_id`: unique UUIDv4 string.
  * `collection_purpose`: strictly closed enum `fixture_7a | live_verification_7b | operational_read`.
  * `request_timestamp`: ISO-8601 UTC execution timestamp string.
  * `tenant_ref`: opaque tenant binding reference.
  * `binding_ref`: opaque tenant binding reference.
  * `resource_scope_ref`: authorized scope reference.
  * `date_range`: `{ start_date: "YYYY-MM-DD", end_date: "YYYY-MM-DD", inclusive: true }`.
  * `reporting_timezone`: IANA timezone string (e.g. `"America/Sao_Paulo"`).
  * `resource_level`: `campaign`.
  * `attribution_setting`: `"default"`.
  * `breakdowns`: `[]`.
  * `requested_capabilities`: non-empty ordered list of capability refs.
  * `registry_snapshot_digest`: SHA-256 digest of the authorized input registry state.
* **Pre-Flight Static Preconditions (Deny Before Credentials / RPC):**
  1. `requested_capabilities` must be **strictly non-empty** and satisfy `request.requested_capabilities ⊆ driver_capability_snapshot`.
  2. **Purpose-Aware Capability Invariant:**
     * If `collection_purpose == operational_read`: requested capabilities must be `live_certified`.
     * If `collection_purpose == live_verification_7b`: requested capabilities must be `fixture_certified` or `live_certified`.
     * If `collection_purpose == fixture_7a`: requested capabilities must be `declared` or `fixture_certified`.
  3. For Phase 1 (`pipeboard_hosted`), `request.date_range` must satisfy `start_date == end_date == date_of(request_timestamp - 1 day in reporting_timezone)`. Non-previous-day requests fail immediately with `outcome_status: failed`, `error: unsupported_date_range`.
  4. If any precondition fails, execution terminates immediately with `outcome_status: failed` before any credential lookup, token decryption, or RPC dispatch occurs.
* **`request_digest`:** Computed as SHA-256 over RFC 8785 canonical JSON bytes of `CollectionRequest`.
* **`CollectionResult`:**
  * `request_digest`: echoes input request digest.
  * `registry_snapshot_digest`: echoes input registry snapshot digest.
  * **`outcome_status` (Closed Precedence Order):**
    1. If network/auth/transport error or zero requested metrics observed $\longrightarrow$ `failed`.
    2. Else if schema validation fails or pagination truncated or any requested metric missing $\longrightarrow$ `partial` (strictly blocked from Parquet storage).
    3. Else (100% of non-empty requested metrics successfully observed, validated, and non-truncated) $\longrightarrow$ `complete`.
  * `capabilities_requested`: list of requested capability refs.
  * `capabilities_observed`: list of validated capability refs present in candidate.
  * `candidates`: list of validated, sanitized `analytics_landing/v1` observations.
  * `errors`: normalized local error classifications (fail closed).
* **Storage Invariant on Partial Results:** If `outcome_status in { partial, failed }`, curation execution **fails closed**. Writing a Parquet generation partition or promoting via `partition_head/v1` is **strictly prohibited**. A partial response can never create or overwrite a storage partition.
* **Invariants:**
  1. Accepts only opaque, authorized references.
  2. **Never leaks** raw provider payloads, API tokens, cleartext account IDs, provider request URLs, HTTP headers, or raw provider error bodies.

### 4.3 Total Discriminative Matrix for Observation & Calculation Dimensions
Observations and derivations are classified across four orthogonal dimensions using a **singular tagged numeric value representation**:

```text
value_type: "int64_minor_currency" | "int64_count" | "decimal_ratio" | null
raw_numeric_value: string | null
```

#### 1. Base Provider Observations (`metric_origin == provider_collected`):
* `calculation_status: not_applicable`.
* **Presence & Reason Matrix:**
  * `presence_status: observed` $\Longleftrightarrow$ `unknown_reason: null`, `value_type in {"int64_count", "int64_minor_currency"}`, `raw_numeric_value` is non-null canonical integer string.
  * `presence_status: missing` $\Longleftrightarrow$ `unknown_reason: provider_omitted`, `value_type: null`, `raw_numeric_value: null`.
  * `presence_status: unproven_zero` $\Longleftrightarrow$ `unknown_reason: unverified_zero`, `value_type: null`, `raw_numeric_value: null`.
  * `presence_status: timeout` $\Longleftrightarrow$ `unknown_reason: connection_timeout`, `value_type: null`, `raw_numeric_value: null`.
  * `presence_status: not_applicable_at_level` $\Longleftrightarrow$ `unknown_reason: capability_unsupported`, `value_type: null`, `raw_numeric_value: null`.
  * `presence_status: retracted_tombstone` $\Longleftrightarrow$ `unknown_reason: null`, `value_type: null`, `raw_numeric_value: null`.

#### 2. Derived Metrics (`metric_origin == derived_computed`):
* `presence_status: not_applicable`, `unknown_reason: null`.
* **Calculation Matrix (Evaluated in Strict Precedence Order):**
  1. If ANY required base input has `presence_status in {"missing", "timeout", "unproven_zero", "not_applicable_at_level", "retracted_tombstone"}` or `raw_numeric_value == null` $\longrightarrow$ `calculation_status: missing_input`, `value_type: null`, `raw_numeric_value: null`.
  2. Else if denominator input is numerically equal to 0 $\longrightarrow$ `calculation_status: division_by_zero`, `value_type: null`, `raw_numeric_value: null`.
  3. Else if mathematical domain error occurs $\longrightarrow$ `calculation_status: non_computable`, `value_type: null`, `raw_numeric_value: null`.
  4. Else $\longrightarrow$ `calculation_status: computed`:
     * For cost ratios (CPC, CPA, CPL): `value_type: "int64_minor_currency"`, `raw_numeric_value: string(round_half_up(spend_centavos / count))`.
     * For pure ratios (CTR, ROAS): `value_type: "decimal_ratio"`, `raw_numeric_value: string(format_decimal(ratio, scale=6))`.

*Invariant:* `unknown != zero`. In regression laws and truth tables, `unknown` denotes any non-observed base state (`presence_status in {"missing", "timeout", "unproven_zero"}`). A numerical value of zero is valid only when explicitly returned as `observed`.

---

## 5. Metric Certification Model & The 65×23 Regression Law

### 5.1 Capability Registry & Granular Lifecycle States
The engine maintains a capability registry where each capability declares its own required metric set and resource scope:
```text
capability_state:
  - declared          # Defined in schema/contracts, no test proof yet
  - fixture_certified # Proven offline against frozen synthetic fixtures (7A)
  - live_certified    # Certified live against independent reference (7B)
  - unavailable       # Confirmed unsupported by transport provider
  - deferred          # Valid capability postponed to future phase
```
*Invariants:*
* **Granular Evaluation:** Every `capability_definition` declares a **strictly non-empty `required_metrics` list**. Capabilities are certified and promoted individually.
* **7A Offline Certification** promotes capabilities strictly to `fixture_certified`. It **never** promotes a capability to `live_certified`.
* Promotion to `live_certified` requires successful execution of 7B live verification against `independent_meta_reference_harness`.

### 5.2 Scoped Certification Records (7A vs 7B Evidence Discrimination)
Every certification evaluation produces a `certification_record/v1` discriminating `evidence_kind`:

1. **For `evidence_kind: fixture_7a` (Offline Certification):**
   * Keyed by: `(tenant_ref, binding_ref, resource_scope_ref, metric_semantic_ref, source_contract_ref, fixture_dataset_digest, mapping_rules_digest)`
   * Storage digests (`generation_id`, `generation_manifest_digest`) are `null`.
   * Cryptographically binds:
     * `capability_definition_digest`: SHA-256 of capability contract definition.
     * `wheel_digest`: SHA-256 of candidate wheel package.
     * `sandbox_profile_digest`: SHA-256 of sealed sandbox profile.
     * `negative_security_test_report_digest`: SHA-256 of negative security assertion report.
     * `parser_code_digest`: SHA-256 of parser implementation.
     * `adapter_code_digest`: SHA-256 of adapter implementation.
     * `mapping_rules_digest`: SHA-256 of mapping rule definitions.
     * `fixture_dataset_digest`: SHA-256 of synthetic fixture dataset.

2. **For `evidence_kind: live_7b` (Live Verification):**
   * Keyed by the full 9-tuple:
     $$(tenant\_ref,\ binding\_ref,\ account\_ref,\ resource\_scope\_ref,\ metric\_semantic\_ref,\ source\_contract\_ref,\ generation\_id,\ generation\_manifest\_digest,\ registry\_snapshot\_digest)$$
   * Cryptographically binds `migration_run_id`, `generation_manifest_digest`, `reference_workload_ref`, `canonical_query_digest`, and `reference_run_digest`.

### 5.3 Per-Metric Verification States & Closed Success Criteria
```text
metric_verification_status:
  - VERIFIED      # Semantically valid and numerically verified against reference harness
  - DEGRADED      # Semantically valid with documented operational limitation (freshness/tolerance)
  - UNRECONCILED  # Uncertified metric, numerical mismatch, or inconclusive comparison
  - UNAVAILABLE   # Capability confirmed unsupported in that specific provider/platform context
  - BLOCKED       # Metric usage prohibited by governance or security policy

reconciliation_outcome:
  - exact_match
  - within_declared_tolerance
  - mismatch
  - not_comparable
```

* **Closed Promotion Invariant for `live_certified`:**
  Promotion of a capability to `live_certified` requires that **100% of the capability's declared `required_metrics`** achieve `metric_verification_status == VERIFIED` with `reconciliation_outcome in { exact_match, within_declared_tolerance }`. If any required metric produces `mismatch`, `not_comparable`, `UNRECONCILED`, `UNAVAILABLE`, or `BLOCKED`, the capability remains `fixture_certified` and live promotion is **strictly denied**.
* A semantic discrepancy can **never** be classified as `DEGRADED`.

### 5.4 7B Phase 1 Grounded Multi-Metric Pairing & Authenticated Gate 3 Receipt
`certification_7b_record/v1` in Phase 1 pairs the full grounded capability bundle (`impressions`, `clicks`, `spend`) over the exact canonical query contract:

```yaml
reconciliation_bundle:
  canonical_query_contract:
    tenant_ref: "tenant:mbras-group"
    binding_ref: "binding:opaque-primary-01"
    account_ref: "account:opaque-pinna-01"
    resource_scope_ref: "scope:opaque-pinna-meta"
    date_range:
      start_date: "2026-08-01"
      end_date: "2026-08-01"
      inclusive: true
    reporting_timezone: "America/Sao_Paulo"
    resource_level: "campaign"
    attribution_setting: "default"
    breakdowns: []
    currency: "BRL"
  canonical_query_digest: sha256:<64_hex_chars>
  gate3_selection_receipt_digest: sha256:<64_hex_chars>
  candidate_execution:
    transport_provider_ref: pipeboard
    ad_platform_ref: meta
    request_digest: sha256:<64_hex_chars>
    canonical_query_projection_digest: sha256:<64_hex_chars>
    generation_id: "gen:20260801-001"
    generation_manifest_digest: sha256:<64_hex_chars>
  reference_execution:
    reference_workload_ref: workload:meta_direct_verifier
    reference_workload_binary_digest: sha256:<64_hex_chars>
    ad_platform_ref: meta
    source_contract_ref: api-version:<selected_version>
    implementation_kind: official_sdk
    request_digest: sha256:<64_hex_chars>
    canonical_query_projection_digest: sha256:<64_hex_chars>
    reference_run_digest: sha256:<64_hex_chars>
  reconciled_metrics:
    - canonical_metric_ref: metric:impressions_v1
      candidate_metric:
        source_metric_ref: insights:impressions
        observed_value_string: "150000"
      reference_metric:
        source_metric_ref: insights:impressions
        observed_value_string: "150000"
      measured_absolute_delta: "0"
      measured_relative_delta: "0.000000"
      tolerance_profile:
        max_absolute_delta: "0"
        max_relative_delta: "0.0000"
      reconciliation_outcome: exact_match
      metric_verification_status: VERIFIED
    - canonical_metric_ref: metric:clicks_v1
      candidate_metric:
        source_metric_ref: insights:clicks
        observed_value_string: "3200"
      reference_metric:
        source_metric_ref: insights:clicks
        observed_value_string: "3200"
      measured_absolute_delta: "0"
      measured_relative_delta: "0.000000"
      tolerance_profile:
        max_absolute_delta: "0"
        max_relative_delta: "0.0000"
      reconciliation_outcome: exact_match
      metric_verification_status: VERIFIED
    - canonical_metric_ref: metric:spend_v1
      candidate_metric:
        source_metric_ref: insights:spend
        observed_value_string: "125000"
      reference_metric:
        source_metric_ref: insights:spend
        observed_value_string: "125000"
      measured_absolute_delta: "0"
      measured_relative_delta: "0.000000"
      tolerance_profile:
        max_absolute_delta: "0"
        max_relative_delta: "0.0001"
      reconciliation_outcome: exact_match
      metric_verification_status: VERIFIED
```

* **Authenticated Gate 3 Selection Receipt (`smart_ads/gate3_selection_receipt/v1`):**
```json
{
  "$schema": "smart_ads/gate3_selection_receipt/v1",
  "receipt_id": "receipt:gate3-00000000-0000-4000-8000-000000000000",
  "receipt_digest": "sha256:<64_hex_chars>",
  "migration_run_id": "migrun:20260830-001",
  "selected_meta_api_version": "v21.0",
  "implementation_kind": "official_sdk",
  "authorized_certification_scope": "scope:opaque-pinna-meta",
  "evidence_packet_digest": "sha256:<64_hex_chars>",
  "issued_at": "<ISO-8601-TIMESTAMP>",
  "authorizer_principal_ref": "principal:operator-authorized",
  "signature_algorithm": "ed25519",
  "public_key_ref": "key:ed25519:<sha256_public_key>",
  "signature_bytes_base64": "<base64_signature>"
}
```

*Invariants:*
* `canonical_query_digest` is computed as `SHA-256(RFC8785(canonical_query_contract))`.
* Both candidate and reference executions assert `canonical_query_projection_digest == canonical_query_digest`.
* `reference_execution.source_contract_ref` must match the exact version attested in `gate3_selection_receipt/v1`.
* If any metric in the bundle fails, the DAG executes a fail-closed branch (`CERT7B_FAIL`) halting further live promotion and emitting a certification failure record.

### 5.5 The 65×23 Regression Law as Pure Synthetic Regression-Only Law
The 65×23 regression law is a **purely synthetic offline regression-only invariant (7A)** designed to prove that the engine never conflates aggregate provider conversions with canonical business leads:

1. **Synthetic Aggregate Conversions (`conversions = 65`):**
   * Synthetic test fixture simulating an aggregate conversion metric where the value returns $65$.
   * `metric_semantic_ref`: `metric:aggregate_conversions_v1`.

2. **Synthetic Canonical Leads (`canonical_leads = 23`):**
   * Synthetic test fixture simulating a filtered CRM lead submission subset where the canonical lead metric returns $23$.
   * `metric_semantic_ref`: `metric:canonical_leads_v1`.

*Invariants:*
* `conversions` and `leads` have distinct `metric_semantic_ref` identifiers.
* They are **never aliases**, **never fallbacks**, and **never derived from one another**.
* Offline 7A test suites enforce counter-proofs over synthetic truth tables: `(65, unknown)`, `(0, 23)`, and `(unknown, unknown)`.
* This test is strictly `regression_only` and does not promote any live ad-platform capability.

### 5.6 Immutable Semantic Metric Identity
A canonical base metric is defined by the immutable tuple:
```text
(transport_provider_ref, ad_platform_ref, source_contract_ref, source_metric_ref,
 metric_action_type, resource_level, attribution_setting, reporting_timezone,
 currency_unit, aggregation_rule, breakdowns)
```

### 5.7 Derived Metrics Contract, Calculation Availability & Certification Lattice
For derived metrics (e.g. CTR, CPC, CPA, CPL, ROAS), the derivation is governed by an immutable formula contract (`smart_ads/derived_metric_definition/v1`):

```json
{
  "$schema": "smart_ads/derived_metric_definition/v1",
  "metric_semantic_ref": "metric:derived_cpc_v1",
  "input_metrics": [
    "metric:spend_v1",
    "metric:clicks_v1"
  ],
  "formula_ast": {
    "operator": "DIVIDE_MONEY_BY_COUNT",
    "numerator_metric_ref": "metric:spend_v1",
    "denominator_metric_ref": "metric:clicks_v1",
    "target_value_type": "int64_minor_currency",
    "rounding_mode": "ROUND_HALF_UP"
  },
  "output_value_type": "int64_minor_currency",
  "formula_digest": "sha256:<64_hex_chars>"
}
```

* **Formula Integrity:** Cryptographically bound via `formula_digest = SHA-256(RFC8785(definition_object_without_digest))`.
* **Fact Key for Derived Metrics:** Uses standard 9-tuple with `source_metric_ref` set to `formula_digest`.
* **Certification Status Lattice:**
  $$\text{BLOCKED} < \text{UNRECONCILED} < \text{UNAVAILABLE} < \text{DEGRADED} < \text{VERIFIED}$$
  A derived metric inherits the **worst** status among its inputs along this lattice:
  1. If ANY input is `BLOCKED` $\longrightarrow$ derived metric is `BLOCKED`.
  2. Else if ANY input is `UNRECONCILED` $\longrightarrow$ derived metric is `UNRECONCILED`.
  3. Else if ANY input is `UNAVAILABLE` $\longrightarrow$ derived metric is `UNAVAILABLE`.
  4. Else if ANY input is `DEGRADED` $\longrightarrow$ derived metric is `DEGRADED`.
  5. Else (all inputs `VERIFIED`) $\longrightarrow$ derived metric is `VERIFIED`.

---

## 6. Single Persisted Zone Data Plane (`landing/`)

```text
┌────────────────────────────────────────────────────────────────────────┐
│                        DATA PLANE LIFECYCLE                            │
├────────────────────────────────────────────────────────────────────────┤
│ 1. Provider Response in Memory                                         │
│    ├── Validated against transport schema                              │
│    ├── Sanitized & Normalized (opaque resource_ref assigned)           │
│    └── Raw JSON immediately discarded (Zero raw payload persisted)     │
│                                                                        │
│ 2. Candidate Creation: analytics_landing/v1                            │
│    ├── Computes typed logical_row_digest & payload_provenance_digest   │
│    └── Validated against declared capabilities                         │
│                                                                        │
│ 3. Curation Execution: curation_execution/v1                           │
│    ├── Embeds curation_anchor_timestamp & restatement_lookback_days    │
│    └── Merges candidates with total-order deduplication precedence     │
│                                                                        │
│ 4. Atomic Partition Generation: landing/year=YYYY/month=MM/            │
│    ├── Written to temporary generation file                            │
│    ├── Embeds generation_id, curation_digest, presence & origin columns│
│    ├── Rows sorted lexicographically by fact_key                       │
│    ├── Enforces primary key uniqueness (zero duplicates allowed)       │
│    ├── Computes physical_parquet_digest and logical_row_digest         │
│    └── Promotes generation atomically via partition_head/v1 (CAS)     │
│                                                                        │
│ 5. Dataset Snapshot Creation: dataset_snapshot/v1                      │
│    └── Binds all active generation manifests across partitions         │
│                                                                        │
│ 6. Analysis & Reporting Envelopes (Downstream of Dataset Snapshot):    │
│    ├── analysis_execution/v1 (binds dataset_snapshot_digest + policy)  │
│    ├── finding/v1 (binds analysis_execution_digest)                    │
│    └── report_execution/v1 (records certified report output)           │
│                                                                        │
│ 7. Ephemeral Query Layer: analytics/analytics.duckdb                   │
│    └── Rebuildable index strictly over dataset_snapshot Parquet        │
└────────────────────────────────────────────────────────────────────────┘
```

### 6.1 Long Fact Parquet Grain & Fact Key
The primary `fact_key` uniquely identifies each row within a partition:
$$\text{fact\_key} = (\text{binding\_ref},\ \text{account\_ref},\ \text{resource\_ref},\ \text{resource\_level},\ \text{metric\_date},\ \text{metric\_semantic\_ref},\ \text{source\_metric\_ref},\ \text{attribution\_ref},\ \text{breakdown\_signature})$$

Full storage schema (persisting presence, calculation, and discriminated numeric columns):
```text
binding_ref
account_ref
resource_ref
resource_level
metric_date
metric_semantic_ref
source_metric_ref
value_type
raw_numeric_value
unit
currency
attribution_ref
breakdown_signature
presence_status
unknown_reason
metric_origin
calculation_status
collected_at
adapter_version
semantic_contract_version
generation_id
curation_execution_digest
```

*Invariants:*
* Any collision on `fact_key` within a partition generation represents an integrity failure and fails closed (duplicate insertion rejected).
* Fact rows store `generation_id`, `curation_execution_digest`, `presence_status`, and `calculation_status`, ensuring `unknown != zero` is permanently preserved in storage.
* `analysis_execution_digest` is decoupled from storage, allowing re-analysis of the same immutable Parquet generation under new policies without storage mutation.

### 6.2 Strict Numeric Typing & RFC 8785 Canonical Representation
* Integer counts & minor units: stored as `value_type: "int64_count"` or `value_type: "int64_minor_currency"` with integer string `raw_numeric_value`.
* Derived Ratios/Decimals: stored as `value_type: "decimal_ratio"` with fixed-scale decimal string `raw_numeric_value` (e.g. `"0.123456"`).
* **Prohibition:** `float`, `NaN`, and `Infinity` are strictly forbidden in storage and contracts.
* **Canonical Hashing Projection:** To satisfy RFC 8785 §3.1 (which restricts native JSON numbers to IEEE-754 double precision), numeric values in row digests are projected into typed string representations `{"_type": "int64", "value": "12345"}` or `{"_type": "decimal", "value": "123.450000"}` prior to JCS SHA-256 computation.

### 6.3 Deterministic Curation & Partition Head CAS Promotion
* **Deterministic Curation Envelope (`curation_execution/v1`):**
  * `curation_anchor_timestamp`: ISO-8601 UTC anchor string.
  * `restatement_lookback_days`: integer calendar days (e.g. 7).
  * `curation_window`: closed date range `[date_of(anchor - lookback_days), date_of(anchor)]`.
  * **Total Order Deduplication Precedence:** When merging incoming candidates with historical partition rows on identical `fact_key`, sort by:
    1. Higher `collected_at` ISO-8601 timestamp string.
    2. Tie-breaker: lexicographically greater `logical_row_digest` string.
  * **Tombstones:** Retracted observations are stored with `presence_status: retracted_tombstone`, `value_type: null`, `raw_numeric_value: null`.
* **`generation_manifest/v1` Integrity Contract:** Records:
  * `generation_id`: unique generation identifier string.
  * `partition_key`: partition path string (e.g. `"year=2026/month=08"`).
  * `parent_generation_manifest_digest`: SHA-256 digest of predecessor generation manifest (or `null` at genesis).
  * `created_at`: ISO-8601 creation timestamp.
  * `row_count`: total integer row count.
  * `physical_parquet_digest`: SHA-256 of raw Parquet file bytes.
  * `logical_row_digest`: SHA-256 over RFC 8785 canonical rows.
  * `schema_version`: `"smart_ads/generation_manifest/v1"`.
  * `row_schema_version`: `"smart_ads/analytics_landing/v1"`.
  * `registry_snapshot_digest`: SHA-256 of active registry snapshot.
  * `curation_execution_digest`: SHA-256 of curation execution envelope.
* **`partition_head/v1`:** Storage pointer file located at `landing/year=YYYY/month=MM/HEAD`:
  * `active_generation_manifest_digest`: SHA-256 digest of current active generation manifest (or `null` at genesis).
  * `head_sequence_number`: monotonically increasing `int64` (starts at `0`).
* **Atomic Promotion Protocol:**
  * Promotion computes `generation_manifest/v1` containing `parent_generation_manifest_digest`.
  * Atomic CAS replaces `HEAD` pointer **only if** `HEAD.active_generation_manifest_digest == parent_generation_manifest_digest`.
  * Any concurrency conflict or stale parent digest fails closed immediately (`STALE_GENERATION_PROMOTION_CONFLICT`).
* **Atomic Dataset Snapshot (`dataset_snapshot/v1`):**
  * Downstream analytics queries across multiple partitions bind an immutable `dataset_snapshot/v1` envelope:
```json
{
  "$schema": "smart_ads/dataset_snapshot/v1",
  "snapshot_id": "snapshot:20260830-001",
  "snapshot_digest": "sha256:<64_hex_chars>",
  "created_at": "<ISO-8601-TIMESTAMP>",
  "curation_execution_digest": "sha256:<64_hex_chars>",
  "partition_manifests": [
    {
      "partition_key": "year=2026/month=08",
      "generation_manifest_digest": "sha256:<partition_1_generation_manifest_digest>"
    }
  ]
}
```
* **Retention Pinning Rule:** Data retention policies must never prune or delete a Parquet generation that is referenced by an active `dataset_snapshot/v1`, `analysis_execution/v1`, `finding/v1`, `report_execution/v1`, `certification_record/v1`, legal hold, or migration receipt.
* **Privacy & LGPD Boundary:** Zero persistence of raw payloads reduces the data attack surface and exposure risks. It **does not eliminate** privacy obligations (LGPD/GDPR): `landing/`, audit logs, and binding registries remain subject to legal basis, purpose limitation, necessity, security, access controls, and accountability.

---

## 7. Pure Intelligence Layer & Operational Signals

Pure functional evaluation:
$$\text{Analyze}(\text{LandingDataset},\ \text{TenantThresholdPolicy}) \longrightarrow \text{List}[\text{Finding}]$$

1. **Audience Saturation:** High frequency paired with declining First-Time Impression Ratio (FTIR).
2. **Budget Waste:** CPA/CPL statistically exceeding peer cohort median.
3. **Stalled Delivery:** Active budget allocated with near-zero impression delivery.
4. **Retroactive Restatement:** Retrospective degradation of conversion metrics without incremental spend. **Emits a First-Class Finding that strictly blocks automated mutation recommendations.**

*Invariants:* Thresholds are tenant-configurable policies (`smart_ads/threshold_policy/v1`), never hardcoded engine constants.

---

## 8. Relational Registry Authority & Binding Security

* **Relational Authority:** Cryptographic hashes and opaque references are transport mechanisms; relational truth resides in the private cell registry.
* **Uniqueness Constraints:**
  * `binding_ref` is unique per tenant.
  * `account_ref` is unique per tenant.
  * Provider accounts are unique per `(tenant, transport_provider_ref, ad_platform_ref, private_account_key)`.
* **Sub-Scope Authorization (`shared_with`):**
```yaml
account_bindings:
  - binding_ref: binding:opaque-primary-01
    transport_provider_ref: pipeboard
    ad_platform_ref: meta
    shared_with:
      - front_ref: front:front-alpha
        profile_ref: profile:profile-core
        resource_scope_ref: scope:scope-alpha-core
      - front_ref: front:front-beta
        profile_ref: profile:profile-ops
        resource_scope_ref: scope:scope-beta-ops
```
*Invariant:* Any collision between references, digests, or unauthorized scope cross-talk fails closed.

---

## 9. Baseline Audit & Decomposition Manifest Contract

Audited at commit `d26c73d8508c7c3d43161fe36a80c44a46bf0f2d` (`d26c73d`):
* **Pytest Baseline:** `2172 passed, 1 skipped, 3 warnings` (pytest 9.1.1, Python 3.12.11).
* **Linter Baseline:** `uv run ruff check --select E4,E7,E9,F scripts tests` — PASS (0 errors).
* **Typecheck Baseline:** `uv run basedpyright` — PASS (0 errors).
* **Security Guards Baseline:** 262 collected test cases (1,467 LOC in `tests/test_security_boundaries.py`).

### 9.1 Executable Contract for `MIGRATION_DECOMPOSITION_MANIFEST.json`
Immediately following Gate 2 and delivery mode selection, the formal decomposition manifest will be generated conforming to the following exact contract:

```json
{
  "$schema": "smart_ads/decomposition_manifest/v1",
  "manifest_digest": "sha256:<64_hex_chars>",
  "supersedes_digest": null,
  "generated_at": "<ISO-8601-TIMESTAMP>",
  "source_baseline_commit": "d26c73d8508c7c3d43161fe36a80c44a46bf0f2d",
  "entries": [
    {
      "source_repository": "mbras-tech/mbras-campaigns",
      "source_sha": "d26c73d8508c7c3d43161fe36a80c44a46bf0f2d",
      "source_path": "scripts/operator/conductor.py",
      "source_selector": {
        "selector_kind": "ast_symbol",
        "symbol_name": "conduct_offline_run",
        "parser_abi": "python:3.12_ast_v1",
        "byte_range": [1240, 3580],
        "raw_span_digest": "sha256:<64_hex_chars>"
      },
      "source_digest": "sha256:<64_hex_chars>",
      "system_id": "operator-core",
      "system_owner": "legacy-operator",
      "target_repository": "aiconnai/smart-ads",
      "target_layer": "core_engine",
      "migration_mode": "reimplement_clean",
      "decision_status": "approved",
      "preserved_invariants": ["fail_closed_on_missing_evidence", "digest_provenance"],
      "compatibility_surface": ["operator_run_v1"],
      "blocking_defects": [],
      "required_tests": ["test_conductor_parity.py"]
    }
  ]
}
```

* **Normative Hashing Standard:** All JSON digests are computed strictly according to **RFC 8785 (JSON Canonicalization Scheme / JCS)**.
* **Discriminative `source_selector` Preimages:**
  * For `selector_kind: whole_file`: SHA-256 over raw UTF-8 bytes of the file at `source_path` in `source_sha`.
  * For `selector_kind: ast_symbol`: SHA-256 of AST unparsed UTF-8 bytes of `symbol_name` definition at `source_path` in `source_sha` using Python 3.12 standard AST unparse format.
  * For `selector_kind: text_region`: SHA-256 of exact byte slice `byte_range: [start_byte, end_byte]` at `source_path` in `source_sha`.
  * `raw_span_digest`: Computed as SHA-256 over the exact slice of bytes `[start_byte, end_byte]` in the source file.
* **Digest Preimage:** `manifest_digest` is computed as the SHA-256 over RFC 8785 canonical JSON bytes of the entire manifest object excluding the `manifest_digest` property.
* **Closed Enums:**
  * `target_repository`: `aiconnai/smart-ads | mbras-tech/mbras-campaigns | limaronaldo/hermes-ronaldo | runtime-private | none`
  * `target_layer`: `core_engine | data_plane | repository_tooling | legacy_governance | consumer_integration | null`
  * `migration_mode`: `reimplement_clean | compatibility_seam | split_by_invariant | legacy_governance_only | repository_tooling | reference_only | defer_to_funnel_integration | defer_to_google_phase | defer_to_write_plane`
  * `decision_status`: `approved | deferred | rejected`
* **Invariants:** Full 40-char SHAs and 64-char SHA-256 digests (zero abbreviated hashes). Corrections require generating a new manifest referencing `supersedes_digest`.

### 9.2 Legacy Systems Decomposition Summary

> `source_loc` and `test_loc` are informative dimensioning metadata; canonical authority is strictly the 4-tuple: `(source_sha, source_path, source_selector, source_digest)`.

| Legacy System / Module | Primary Source Path | `source_loc` | `test_loc` (Associated Suites) | Manifest Disposition | Target Destination |
|---|---|---:|---:|---|---|
| **Ledger & Controller** | `scripts/autonomy/ledger.py` + `controller.py` | **5.943** | **3.459** (`test_controller.py`) | `legacy_governance_only` | Retained in legacy repository (P0 ledger defect blocks autonomous delivery only) |
| **Codex Gate & Scanners** | `docs/harness/bin/scan_codex_payload.py` + `sh` | **2.754** | **2.806** (`test_codex_gate.py`) | `repository_tooling` | Minimal re-implementation in `tooling/governance/` (outside wheel) |
| **Funnel Validator** | `scripts/analytics/validate_funnel_contract.py` | **2.786** | **1.677** (`test_funnel_contract.py`) | `defer_to_funnel_integration` | Deferred to dedicated funnel phase |
| **Google Canary Transport** | `scripts/operator/google_canary.py` | **2.125** | **3.148** (`tests/operator/test_google_canary.py`) | `defer_to_google_phase` | Deferred to future Google phase |
| **Security Boundaries** | `tests/test_security_boundaries.py` | — | **1.467** (262 test cases) | `split_by_invariant` | Pure invariants (umask 0600, symlinks, redaction) ported to `smart_ads` |
| **Disablement Packets** | Service account disablement docs | **656** | **2.014** (2 test suites) | `legacy_governance_only` | Retained in legacy repository |
| **Pinna Scripts (16 files)** | `scripts/google_ads/pinna5109/*.py` | **5.255** | — | `defer_to_write_plane` | 100% deferred to Write Plane ADR |

---

## 10. Canonical Repository Structure (`src/` Layout)

```text
smart-ads/
├── pyproject.toml                     # Package metadata and build definitions (src/ only)
├── uv.lock                            # Deterministic dependency resolution lockfile
├── README.md                          # Operational runbook
├── MIGRATION_DECOMPOSITION_MANIFEST.json # Granular decomposition contract (path + symbol)
├── docs/
│   ├── adr/
│   │   └── ADR-0001-smart-ads-read-gateway.md # This document
│   └── source-packets/                # Evidence packets and official API documentation
├── tooling/
│   └── governance/                    # Repo-local governance tooling (EXCLUDED from wheel)
├── src/
│   └── smart_ads/
│       ├── __init__.py
│       ├── domain/                    # Pure entities, metric value objects, invariants
│       ├── application/               # Read use cases (queries, reports, intelligence, ingestion)
│       │   ├── queries/
│       │   ├── reports/
│       │   ├── intelligence/
│       │   └── ingestion/
│       ├── ports/                     # Closed ProviderPort and StoragePort interfaces
│       ├── adapters/                  # Concrete I/O implementations
│       │   ├── pipeboard/             # PipeboardHostedAdapter and 7A mappings
│       │   └── storage/               # ParquetAtomicStorage and DuckDBViewEngine
│       ├── analytics/                 # Columnar SQL views and aggregations
│       ├── reconciliation/            # Certification registry and 7B live verification
│       ├── contracts/                 # JSON Schemas distributed via importlib.resources
│       │   └── v1/
│       ├── audit/                     # Append-only audit logger and event envelopes
│       └── transports/
│           └── mcp/                   # Closed inventory read-only MCP server for Hermes
└── tests/
    ├── unit/                          # Pure intelligence rule tests over truth tables
    ├── contract/                      # Schema validations and fail-closed property tests
    ├── certification_7a/              # Hermetic offline certification & 65×23 regression law
    ├── analytics/                     # DuckDB view queries and ratio calculations
    ├── integration/                   # Atomic Parquet generation and rebuild benchmarks
    ├── security/                      # Ported security invariants (umask, redaction, symlink)
    ├── migration/                     # Seam parity and decomposition manifest validation
    └── rollback/                      # Human-only feature flag toggle automated test
```

* **Wheel Packaging Invariant (GOV1 Enforcement):**
  * `pyproject.toml` strictly packages `src/smart_ads` and explicitly excludes `tooling/`.
  * AST import checker verifies zero imports matching `tooling.*` within `src/smart_ads`.
  * Wheel smoke install test installs the built `.whl` in a clean virtual environment and verifies successful import without dev tooling dependencies.

---

## 11. Canonical Migration DAG & Computable Acceptance Criteria

```mermaid
flowchart TD
    DRAFT["0. In-Memory Canonical Draft"] --> G1["[GATE HUMANO 1: CONCEDIDO]
    Authorization to Create Private Repo aiconnai/smart-ads"]

    G1 --> BOOTSTRAP["1. Bootstrap Repository & Record ADR-0001
    (docs/adr/ADR-0001-smart-ads-read-gateway.md)"]

    BOOTSTRAP --> G2["[GATE HUMANO 2]
    Formal Approval of ADR-0001 on Exact Commit SHA"]

    G2 --> DELIV_MODE{"Delivery Mode Selection
    (Manual / Human vs. Autonomous Engine)"}

    DELIV_MODE -->|Manual / Human| DELIV_REC["Emit delivery_mode_decision_receipt/v1 (manual mode)"] --> DEC_MAN["2. Generate MIGRATION_DECOMPOSITION_MANIFEST.json
    (Path + Symbol 4-Tuple Mapping)"]

    DELIV_MODE -->|Autonomous Engine| AUTON_GATE["Autonomous Eligibility Gate:
    (a) P0 Fix on Legacy Ledger Verified
    (b) Active Reviewer Attestation (sonnet-5-medium)
    (c) Worktree Isolation Enforced
    (d) Controller Invariants Passing (AGENTS.md)"]

    AUTON_GATE -->|Pass| DELIV_AUTON["Emit delivery_mode_decision_receipt/v1 (autonomous mode + evidence)"] --> DEC_MAN
    AUTON_GATE -->|Fail| FROZEN["Fail Closed: frozen_human_only"] --> WAIT_HUMAN["[WAITING_HUMAN_GATE: Explicit Manual Mode Decision Required]"] --> DELIV_REC

    DEC_MAN --> PR1["3. PR 1 (Smart Ads): Packaging (src/), Schemas,
    Semantic Metric Registry & ProviderPort"]
    DEC_MAN --> GOV1["3b. GOV 1: Governance & CI Tooling"]

    PR1 --> CONV_GATE["[CONVERGENCE GATE: PR 1 + GOV 1]"]
    GOV1 --> CONV_GATE

    CONV_GATE --> PR2["4. PR 2 (Smart Ads): Pure Intelligence Layer
    & Truth Table Edge Cases"]

    PR2 --> PR3["5. PR 3 (Smart Ads): Pipeboard Hosted Adapter Offline,
    Capability Registry & 7A Hermetic Offline Certification (CI)"]

    PR3 --> PR4["6. PR 4 (Smart Ads): landing/ Atomic Parquet Generation
    & curation_execution/v1 Lookback"]

    PR4 --> PR5["7. PR 5 (Smart Ads): Rebuildable DuckDB Analytics
    & Sanitized CSV Reports"]

    PR5 --> LEG_PR["8. Legacy Seam PR (mbras-tech/mbras-campaigns):
    Dual Projection Seam (Granular + Aggregated)"]

    LEG_PR --> PR6["9. PR 6 (Smart Ads): Granular Seam Adapter
    & operator_run/v1 Exact Parity"]

    PR6 --> SEAM_REC["10. Emit seam_parity_record/v1"]

    SEAM_REC --> HERMES_PR["11. Consumer PR (limaronaldo/hermes-ronaldo):
    Gateway Integration with Feature Flag (Default OFF)"]

    HERMES_PR --> LEGACY_STEP2["[LEGACY ADR STEP 2 HUMAN GO/NO-GO GATE]
    Formal Human Verification of Legacy Step 2 Policy Compliance
    Emits legacy_step2_authorization_receipt/v1"]

    LEGACY_STEP2 --> G3["[GATE HUMANO 3]
    Versão exata suportada, revalidada e selecionada
    + Escopo de certificação atestado
    Emits gate3_selection_receipt/v1"]

    G3 --> AUTH_ID["[HUMAN AUTHORIZATION: WORKLOAD IDENTITY]
    Emits workload_identity_authorization_receipt/v1"]

    AUTH_ID --> PROV_ID["Provision & Verify Workload Identity
    Emits workload_identity_execution_receipt/v1"]

    PROV_ID --> AUTH_DEPLOY["[HUMAN AUTHORIZATION: DEPLOYMENT & CONFIG]
    Emits deployment_config_authorization_receipt/v1"]

    AUTH_DEPLOY --> PROV_DEPLOY["Deploy & Verify Cell Configuration
    Emits deployment_config_execution_receipt/v1"]

    PROV_DEPLOY --> AUTH_CALLS["[HUMAN AUTHORIZATION: 7B LIVE CALLS]
    Emits live_call_authorization_receipt/v1"]

    AUTH_CALLS --> CERT7B["12. 7B Live Certification:
    Pipeboard vs. independent_meta_reference_harness"]

    CERT7B -->|Pass 100% verified| CERT7B_REC["Emits certification_7b_record/v1 + live_execution_receipt/v1"] --> AUTH_SHADOW
    CERT7B -->|Fail mismatch/unreconciled| CERT7B_FAIL["7B Certification Failed: Halts, emits failure receipt, denies shadow mode"]

    AUTH_SHADOW["[HUMAN AUTHORIZATION: SHADOW MODE]
    Emits shadow_mode_authorization_receipt/v1"] --> SHADOW["13. Shadow Mode in Hermes:
    Compare Direct vs. Gateway Responses"]

    SHADOW --> ACC["14. Operational Acceptance:
    5 relatórios diários consecutivos aceitos (Days 1..5)
    + 4 drafts semanais consecutivos aceitos (Weeks 1..4)
    Emits daily and weekly acceptance tokens"]

    ACC --> SHADOW_REC["14b. Emit shadow_acceptance_record/v1
    (Consolidates 5 Daily Tokens + 4 Weekly Tokens)"]

    SHADOW_REC --> AUTH_RB["[HUMAN AUTHORIZATION: ROLLBACK TEST]
    Emits rollback_test_authorization_receipt/v1"]

    AUTH_RB --> ROLLBACK["15. Human-Only Rollback Test & Validation
    Emits rollback_test_receipt/v1"]

    ROLLBACK --> MAN_FINAL["16. Tripartite MIGRATION_MANIFEST.json Generated
    (Proves Readiness; binds all digests, receipts & SHAs)"]

    MAN_FINAL --> AUTH_ATTEST["16a. [HUMAN AUTHORIZATION: READINESS ATTESTATION]
    Emits readiness_attestation_authorization_receipt/v1"]

    AUTH_ATTEST --> ATTEST["16b. Emit readiness_attestation.json
    (Signed Ed25519 Attestation of Tripartite Manifest)"]

    ATTEST --> G4["[GATE HUMANO 4]
    Formal Authorization of Read-Only Cutover on Exact Manifest & Attestation
    Emits cutover_authorization_receipt/v1"]

    G4 --> AUTH_CUTOVER["[HUMAN AUTHORIZATION: EXECUTE CUTOVER]"]

    AUTH_CUTOVER --> CUTOVER_EXEC["17. Cutover Execution (Toggle Feature Flag to Gateway)
    Emits cutover_execution_receipt/v1"]

    CUTOVER_EXEC --> STABILIZE["18. Post-Cutover Verification & Stabilization Window (14 days / 336h)
    Emits stabilization_period_completion_record/v1"]

    STABILIZE --> RETIRE_GATE["[GATE DE RETIRADA]
    Formal Authorization of Legacy Direct Read Retirement"]

    RETIRE_GATE --> AUTH_RETIRE["[HUMAN AUTHORIZATION: EXECUTE RETIREMENT]
    Emits retirement_authorization_receipt/v1"]

    AUTH_RETIRE --> RETIRE_EXEC["19. Decommission legacy direct read path only
    Emits retirement_execution_receipt/v1"]

    RETIRE_EXEC --> RETIRE_VERIF["20. Post-Retirement Verification Window (7 days / 168h zero-traffic)
    Emits retirement_verification_record/v1"]

    RETIRE_VERIF --> TERMINAL_REC["21. Emit migration_completion_record/v1
    (Signed Terminal Audit Record triggering partial supersession for Read Allowlist)"]

    TERMINAL_REC -.-> WRITE_PLANE["[Future Decoupled Phase]
    Write Plane ADR & Pinna Operational Mutation Engine"]
```

### 11.1 Operational Acceptance Computable Rules (`acceptance_profile/v1`)
* **Profile Definition:** Bound to `profile:operational-acceptance-pinna-v1`.
* **Calendar Authority & Timezone:** Evaluated strictly in `America/Sao_Paulo` timezone against `"B3_OFFICIAL_BANKING_DAYS_SAO_PAULO_2026_V1"`.
* **Mandatory Core Metrics:** `["impressions", "clicks", "spend"]`.
* **Daily Report Acceptance:** Requires 5 consecutive B3 business days of daily summary reports accepted by the human operator. Parity criterion: 100% of reported core metrics must achieve `metric_verification_status == VERIFIED` (`reconciliation_outcome in { exact_match, within_declared_tolerance }`) compared against the direct stream.
* **Daily Acceptance Token Envelope (`smart_ads/daily_acceptance_token/v1`):**
```json
{
  "$schema": "smart_ads/daily_acceptance_token/v1",
  "token_id": "token:day-00000000-0000-4000-8000-000000000000",
  "token_digest": "sha256:<64_hex_chars>",
  "migration_run_id": "migrun:20260830-001",
  "day_date": "2026-08-03",
  "calendar_authority": "B3_OFFICIAL_BANKING_DAYS_SAO_PAULO_2026_V1",
  "gateway_generation_manifest_digest": "sha256:<64_hex_chars>",
  "direct_stream_digest": "sha256:<64_hex_chars>",
  "reconciliation_digest": "sha256:<64_hex_chars>",
  "operator_principal_ref": "principal:operator-authorized",
  "signature_algorithm": "ed25519",
  "public_key_ref": "key:ed25519:<sha256_public_key>",
  "signature_bytes_base64": "<base64_signature>",
  "issued_at": "<ISO-8601-TIMESTAMP>"
}
```
* **Weekly Report Acceptance:** Requires 4 consecutive weekly draft cycles accepted operationally by the media team over 4 consecutive calendar weeks (ISO Monday 00:00 to Sunday 23:59:59 SP time).
* **Weekly Acceptance Token Envelope (`smart_ads/weekly_acceptance_token/v1`):**
```json
{
  "$schema": "smart_ads/weekly_acceptance_token/v1",
  "token_id": "token:week-00000000-0000-4000-8000-000000000000",
  "token_digest": "sha256:<64_hex_chars>",
  "migration_run_id": "migrun:20260830-001",
  "week_number": 1,
  "week_period": {
    "start_date": "2026-08-03",
    "end_date": "2026-08-09"
  },
  "draft_report_digest": "sha256:<64_hex_chars>",
  "calendar_authority": "B3_OFFICIAL_BANKING_DAYS_SAO_PAULO_2026_V1",
  "constituent_daily_token_digests": [
    "sha256:<day_1_token_digest>",
    "sha256:<day_2_token_digest>",
    "sha256:<day_3_token_digest>",
    "sha256:<day_4_token_digest>",
    "sha256:<day_5_token_digest>"
  ],
  "predecessor_weekly_token_digest": null,
  "operator_principal_ref": "principal:operator-authorized",
  "signature_algorithm": "ed25519",
  "public_key_ref": "key:ed25519:<sha256_public_key>",
  "signature_bytes_base64": "<base64_signature>",
  "issued_at": "<ISO-8601-TIMESTAMP>"
}
```
* **Consolidated Shadow Acceptance Record (`smart_ads/shadow_acceptance_record/v1`):**
```json
{
  "$schema": "smart_ads/shadow_acceptance_record/v1",
  "record_id": "record:shadow-acceptance-00000000-0000-4000-8000-000000000000",
  "record_digest": "sha256:<64_hex_chars>",
  "migration_run_id": "migrun:20260830-001",
  "daily_token_digests": [
    "sha256:<day_1_token_digest>",
    "sha256:<day_2_token_digest>",
    "sha256:<day_3_token_digest>",
    "sha256:<day_4_token_digest>",
    "sha256:<day_5_token_digest>"
  ],
  "weekly_token_digests": [
    "sha256:<week_1_token_digest>",
    "sha256:<week_2_token_digest>",
    "sha256:<week_3_token_digest>",
    "sha256:<week_4_token_digest>"
  ],
  "acceptance_profile_ref": "profile:operational-acceptance-pinna-v1",
  "operator_principal_ref": "principal:operator-authorized",
  "signature_algorithm": "ed25519",
  "public_key_ref": "key:ed25519:<sha256_public_key>",
  "signature_bytes_base64": "<base64_signature>",
  "issued_at": "<ISO-8601-TIMESTAMP>"
}
```
* **Reset Invariant:** Any single day or week with a pipeline failure, data mismatch, or operator rejection immediately resets the consecutive counter to zero (`consecutive_days = 0` or `consecutive_weeks = 0`).

### 11.2 Rollback Verification Computable Protocol (`rollback_test_protocol/v1`)
* **Workload & Sequence Log:** Dispatches a stream of $N = 600$ distinct sequential queries ($10\text{ req/s}$ for $T = 60\text{s}$), recording per-query log: `{ query_sequence_id, timestamp, route_taken: gateway | direct, latency_ms, http_status }`.
* **Synchronized Transition Protocol:**
  1. Queries $1..200$ routed to Gateway ($100\%$ success).
  2. At $T = 20\text{s}$, test harness initiates feature flag toggle `SMART_ADS_READ_GATEWAY_ENABLED: true → false`.
  3. Test harness awaits signed `feature_flag_ack_token` from Hermes confirming flag state is `false`.
  4. In-flight queries ($500\text{ms}$ drain window) complete.
  5. Queries $201..600$ dispatched, asserting $100\%$ route to Legacy Direct with $\le 500\text{ms}$ latency and $0$ errors.
* Emits `rollback_test_receipt/v1` binding `detailed_query_log_digest`, total submitted count ($600$), completed count ($600$), and zero error count.

### 11.3 14-Day Stabilization, Post-Retirement & Terminal Audit Record
* **14-Day Post-Cutover Stabilization Window (336 Continuous Hours):**
  * Gateway actively serves 100% of production traffic for 336 continuous hours.
  * Asserts hourly heartbeat telemetry: query volume $\ge \text{baseline\_min\_queries}$, error rate $< 0.001\%$, and write plane operational.
  * Emits signed `smart_ads/stabilization_period_completion_record/v1` binding `stabilization_timeseries_336h_digest`.
* **Post-Retirement Verification Window (168 Continuous Hours):**
  * Following legacy read decommissioning (`retirement_execution_receipt/v1`), active socket/HTTP monitoring verifies exactly $0$ inbound calls to legacy direct read endpoints over 168 continuous hours while Gateway query volume remains normal.
  * Emits signed `smart_ads/retirement_verification_record/v1` binding `zero_traffic_telemetry_168h_digest`.
* **Terminal Signed Audit Record (`smart_ads/migration_completion_record/v1`):**
```json
{
  "$schema": "smart_ads/migration_completion_record/v1",
  "record_id": "record:mig-completion-00000000-0000-4000-8000-000000000000",
  "record_digest": "sha256:<64_hex_chars>",
  "migration_run_id": "migrun:20260830-001",
  "readiness_manifest_digest": "sha256:<64_hex_chars>",
  "readiness_attestation_digest": "sha256:<64_hex_chars>",
  "cutover_execution_receipt_digest": "sha256:<64_hex_chars>",
  "stabilization_completion_record_digest": "sha256:<64_hex_chars>",
  "retirement_authorization_receipt_digest": "sha256:<64_hex_chars>",
  "retirement_execution_receipt_digest": "sha256:<64_hex_chars>",
  "retirement_verification_record_digest": "sha256:<64_hex_chars>",
  "completed_at": "<ISO-8601-TIMESTAMP>",
  "operator_principal_ref": "principal:operator-authorized",
  "signature_algorithm": "ed25519",
  "public_key_ref": "key:ed25519:<sha256_public_key>",
  "signature_bytes_base64": "<base64_signature>"
}
```
* Only this verified terminal record formally triggers the partial supersession of the legacy ADR for the Read Plane allowlist.

---

## 12. Tripartite Cutover Readiness Manifest & Verifiable Envelope Contracts

### 12.1 Key Authorization Registry (`key_authorization_registry/v1`)
Every cryptographic signature in the system is verified against a cell-protected key registry:
```json
{
  "$schema": "smart_ads/key_authorization_registry/v1",
  "keys": [
    {
      "key_id": "key:ed25519:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "principal_ref": "principal:operator-authorized",
      "tenant_ref": "tenant:mbras-group",
      "authorized_actions": [
        "delivery_mode_decision",
        "legacy_step2_authorization",
        "gate3_selection",
        "workload_identity_provisioning",
        "deployment_config",
        "live_7b_call",
        "shadow_mode_activation",
        "rollback_test_execution",
        "cutover_execution",
        "readiness_attestation",
        "daily_acceptance_token",
        "weekly_acceptance_token",
        "shadow_acceptance_record",
        "reservation_reconciliation",
        "retirement_authorization",
        "retirement_execution",
        "retirement_verification",
        "migration_completion"
      ],
      "valid_from": "2026-08-01T00:00:00Z",
      "valid_until": "2027-08-01T00:00:00Z",
      "revoked": false
    }
  ]
}
```

* **Delivery Mode Decision Receipt Schema (`smart_ads/delivery_mode_decision_receipt/v1`):**
```json
{
  "$schema": "smart_ads/delivery_mode_decision_receipt/v1",
  "receipt_id": "receipt:deliv-mode-00000000-0000-4000-8000-000000000000",
  "receipt_digest": "sha256:<64_hex_chars>",
  "migration_run_id": "migrun:20260830-001",
  "delivery_mode": "manual",
  "authorizer_principal_ref": "principal:operator-authorized",
  "authorized_sha": "d26c73d8508c7c3d43161fe36a80c44a46bf0f2d",
  "autonomous_eligibility_evidence_digest": null,
  "issued_at": "<ISO-8601-TIMESTAMP>",
  "signature_algorithm": "ed25519",
  "public_key_ref": "key:ed25519:<sha256_public_key>",
  "signature_bytes_base64": "<base64_signature>"
}
```

### 12.2 Standard Verifiable Authorization Receipt Schema
```json
{
  "$schema": "smart_ads/authorization_receipt/v1",
  "receipt_id": "receipt:auth-00000000-0000-4000-8000-000000000000",
  "receipt_digest": "sha256:<64_hex_chars>",
  "migration_run_id": "migrun:20260830-001",
  "receipt_type": "authorization",
  "authorizer_principal_ref": "principal:operator-authorized",
  "action_subject": {
    "tenant_ref": "tenant:mbras-group",
    "binding_ref": "binding:opaque-primary-01",
    "target_resource_ref": "gateway:smart-ads-read",
    "action_name": "cutover_execution",
    "action_parameters_digest": "sha256:<64_hex_chars>",
    "subject_manifest_digest": "sha256:<64_hex_chars>"
  },
  "predecessor_receipt_digest": "sha256:<64_hex_chars>",
  "single_use_nonce": "nonce:00000000-0000-4000-8000-000000000000",
  "issued_at": "<ISO-8601-TIMESTAMP>",
  "expires_at": "<ISO-8601-TIMESTAMP>",
  "signature_algorithm": "ed25519",
  "public_key_ref": "key:ed25519:<sha256_public_key>",
  "signature_bytes_base64": "<base64_signature>"
}
```

*Note on `subject_manifest_digest`:* For pre-readiness receipts (PR1..15, Gate 3, 7B, Shadow, Rollback), `subject_manifest_digest` is `null`. For readiness attestation, cutover authorization, and cutover execution receipts, `subject_manifest_digest` equals `manifest_digest` of `MIGRATION_MANIFEST.json`.

### 12.3 Standard Verifiable Execution Receipt Schema
```json
{
  "$schema": "smart_ads/execution_receipt/v1",
  "receipt_id": "receipt:exec-00000000-0000-4000-8000-000000000000",
  "receipt_digest": "sha256:<64_hex_chars>",
  "migration_run_id": "migrun:20260830-001",
  "receipt_type": "execution",
  "executor_principal_ref": "principal:cell-executor",
  "consumed_authorization_receipt_digest": "sha256:<64_hex_chars>",
  "consumed_single_use_nonce": "nonce:00000000-0000-4000-8000-000000000000",
  "action_subject": {
    "tenant_ref": "tenant:mbras-group",
    "binding_ref": "binding:opaque-primary-01",
    "target_resource_ref": "gateway:smart-ads-read",
    "action_name": "cutover_execution",
    "action_parameters_digest": "sha256:<64_hex_chars>",
    "subject_manifest_digest": "sha256:<64_hex_chars>"
  },
  "executed_at": "<ISO-8601-TIMESTAMP>",
  "duration_ms": 120,
  "status": "success",
  "error_details": null,
  "signature_algorithm": "ed25519",
  "public_key_ref": "key:ed25519:<sha256_public_key>",
  "signature_bytes_base64": "<base64_signature>"
}
```

### 12.4 Strict Non-Expiring Reservation & `in_doubt` Quarantine
To guarantee strict anti-replay before any external effect occurs:
1. **Phase 1 (Pre-Execution Reservation):** Prior to executing the authorized action, the worker atomically writes `authorization_reservation_record/v1` to cell storage indexed on `(authorization_receipt_digest, single_use_nonce)`. Any attempt to reserve a consumed or active nonce fails closed immediately.
2. **Fail-Closed `in_doubt` Quarantine Policy:**
   * A reservation **never automatically reopens or expires**.
   * If a worker crashes or encounters an ambiguous network response during execution, supervisor heartbeat detects the timeout ($> 300\text{s}$) and marks the reservation `reservation_state: in_doubt`.
   * An `in_doubt` reservation is permanently quarantined. Automated retry is strictly prohibited.
   * To retry the action, the operator must issue a **new authorization receipt with a fresh `single_use_nonce`**, while emitting an operator-signed `reservation_reconciliation_record/v1`:

```json
{
  "$schema": "smart_ads/reservation_reconciliation_record/v1",
  "reconciliation_id": "rec:recon-00000000-0000-4000-8000-000000000000",
  "record_digest": "sha256:<64_hex_chars>",
  "migration_run_id": "migrun:20260830-001",
  "quarantined_authorization_receipt_digest": "sha256:<64_hex_chars>",
  "quarantined_nonce": "nonce:00000000-0000-4000-8000-000000000000",
  "reconciliation_reason": "worker_crash_timeout_recovery",
  "reconciliation_action": "permanent_quarantine_closed",
  "operator_principal_ref": "principal:operator-authorized",
  "reconciled_at": "<ISO-8601-TIMESTAMP>",
  "signature_algorithm": "ed25519",
  "public_key_ref": "key:ed25519:<sha256_public_key>",
  "signature_bytes_base64": "<base64_signature>"
}
```
3. **Phase 2 (Append-Only Consumption):** Upon verified completion, the worker commits `authorization_consumption_record/v1`:

```json
{
  "$schema": "smart_ads/authorization_consumption_record/v1",
  "consumption_id": "consumption:00000000-0000-4000-8000-000000000000",
  "authorization_receipt_digest": "sha256:<64_hex_chars>",
  "consumed_nonce": "nonce:00000000-0000-4000-8000-000000000000",
  "execution_receipt_digest": "sha256:<64_hex_chars>",
  "consumed_at": "<ISO-8601-TIMESTAMP>"
}
```

### 12.5 Tripartite Cutover Readiness Manifest (`MIGRATION_MANIFEST.json`)
The `MIGRATION_MANIFEST.json` and its companion signed attestation are generated **prior to Gate 4** to attest readiness:

```json
{
  "manifest_schema_version": "smart_ads/migration_manifest/v1",
  "migration_run_id": "migrun:20260830-001",
  "manifest_digest": "sha256:<64_hex_chars>",
  "generated_at": "<ISO-8601-TIMESTAMP>",
  "decomposition_manifest_digest": "sha256:<64_hex_chars>",
  "source_packet_digest": "sha256:<64_hex_chars>",
  "delivery_mode_decision_receipt_digest": "sha256:<64_hex_chars>",
  "legacy_step2_authorization_receipt_digest": "sha256:<64_hex_chars>",
  "gate3_selection_receipt_digest": "sha256:<64_hex_chars>",
  "workload_identity_authorization_receipt_digest": "sha256:<64_hex_chars>",
  "workload_identity_execution_receipt_digest": "sha256:<64_hex_chars>",
  "deployment_config_authorization_receipt_digest": "sha256:<64_hex_chars>",
  "deployment_config_execution_receipt_digest": "sha256:<64_hex_chars>",
  "live_call_authorization_receipt_digest": "sha256:<64_hex_chars>",
  "certification_7b_record_digest": "sha256:<64_hex_chars>",
  "live_execution_receipt_digest": "sha256:<64_hex_chars>",
  "seam_parity_record_digest": "sha256:<64_hex_chars>",
  "shadow_mode_authorization_receipt_digest": "sha256:<64_hex_chars>",
  "shadow_acceptance_record_digest": "sha256:<64_hex_chars>",
  "rollback_test_authorization_receipt_digest": "sha256:<64_hex_chars>",
  "rollback_test_receipt_digest": "sha256:<64_hex_chars>",
  "tripartite_cutover": {
    "legacy_side": {
      "repository": "mbras-tech/mbras-campaigns",
      "commit_sha": "<seam_commit_sha_40_chars>",
      "seam_adapter_digest": "sha256:<64_hex_chars>"
    },
    "canonical_side": {
      "repository": "aiconnai/smart-ads",
      "commit_sha": "<canonical_commit_sha_40_chars>",
      "wheel_digest": "sha256:<64_hex_chars>"
    },
    "consumer_side": {
      "repository": "limaronaldo/hermes-ronaldo",
      "commit_sha": "<consumer_commit_sha_40_chars>",
      "feature_flag_digest": "sha256:<64_hex_chars>"
    }
  }
}
```

### 12.6 Signed Attestation Envelope (`readiness_attestation.json`)
```json
{
  "attestation_schema_version": "smart_ads/readiness_attestation/v1",
  "attestation_digest": "sha256:<64_hex_chars>",
  "migration_run_id": "migrun:20260830-001",
  "subject_manifest_digest": "sha256:<64_hex_chars>",
  "authorization_receipt_digest": "sha256:<64_hex_chars>",
  "consumed_nonce": "nonce:00000000-0000-4000-8000-000000000000",
  "attestor_principal_ref": "principal:operator-authorized",
  "signature_algorithm": "ed25519",
  "public_key_ref": "key:ed25519:<sha256_public_key>",
  "signature_bytes_base64": "<base64_signature>",
  "issued_at": "<ISO-8601-TIMESTAMP>"
}
```

### 12.7 Normative Cryptographic Equations & Universal Verifier
* **Normative Hashing Standard:** All JSON digests are computed strictly according to **RFC 8785 (JSON Canonicalization Scheme / JCS)**.
* For ANY envelope type $E$ with digest field $D$ and signature field $S$:
  $$D = \text{SHA-256}(\text{RFC8785}(E \setminus \{D, S\}))$$
* **Signing Preimages with Strict Domain Separation:**
  $$\text{Preimage} = \text{DomainPrefix} \parallel D$$
  * For Authorization Receipt: `DomainPrefix = "SMART-ADS:AUTH-RECEIPT:V1\n"`
  * For Execution Receipt: `DomainPrefix = "SMART-ADS:EXEC-RECEIPT:V1\n"`
  * For Delivery Mode Receipt: `DomainPrefix = "SMART-ADS:DELIV-MODE-RECEIPT:V1\n"`
  * For Gate 3 Receipt: `DomainPrefix = "SMART-ADS:GATE3-RECEIPT:V1\n"`
  * For Readiness Attestation: `DomainPrefix = "SMART-ADS:READINESS-ATTESTATION:V1\n"`
  * For Daily Token: `DomainPrefix = "SMART-ADS:DAILY-TOKEN:V1\n"`
  * For Weekly Token: `DomainPrefix = "SMART-ADS:WEEKLY-TOKEN:V1\n"`
  * For Shadow Acceptance Record: `DomainPrefix = "SMART-ADS:SHADOW-ACCEPTANCE:V1\n"`
  * For Reservation Reconciliation: `DomainPrefix = "SMART-ADS:RECON-RECORD:V1\n"`
  * For Migration Completion Record: `DomainPrefix = "SMART-ADS:MIG-COMPLETION:V1\n"`
* **Closed Universal Verifier Predicate:** Gate 4 and execution workers verify:
  1. Resolve `public_key_ref` in `key_authorization_registry/v1`.
  2. Confirm `key.revoked == false`.
  3. Confirm `issued_at >= key.valid_from` and `expires_at <= key.valid_until` (where `expires_at` is present).
  4. Confirm current time is within `[issued_at, expires_at]`.
  5. Confirm `authorizer_principal_ref == key.principal_ref` (or `attestor_principal_ref`/`operator_principal_ref`).
  6. Confirm `action_subject.tenant_ref == key.tenant_ref` (for receipts).
  7. Confirm `action_subject.action_name in key.authorized_actions` (for receipts).
  8. Recompute `expected_digest = SHA-256(RFC8785(envelope_without_digest_and_sig))` and assert `envelope.digest == expected_digest`.
  9. Verify Ed25519 signature over `DomainPrefix || expected_digest` using public key bytes.
  10. In `execution_receipt/v1`, assert `action_subject == authorization_receipt.action_subject` (byte-for-byte RFC 8785 equality).

---

## 13. Audit & Governance Status

```text
========================================================================
ADR Status:                       PROPOSED / RECORDED ON CANONICAL REPO
Target Repository:                aiconnai/smart-ads
Source Commit Baseline:           d26c73d8508c7c3d43161fe36a80c44a46bf0f2d
------------------------------------------------------------------------
Next Human Checkpoint:            [GATE HUMANO 2]
                                  Formal Approval of ADR-0001 on Exact Commit
Subsequent Step Post-Gate 2:      Generation of MIGRATION_DECOMPOSITION_MANIFEST.json
========================================================================
```
