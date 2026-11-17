"""Recomputable 7B bundle and sealed ``certification_7b_record/v1`` (ADR-0001 section 5.4).

Facade over the ``bundle_*`` modules of this package:

* ``bundle_common`` - defect model, guards, grammar and locator helpers;
* ``bundle_universe`` - the row universe ``U7``, the metric-pair universe ``U7M``;
* ``bundle_evidence`` - ``fact_evidence_selector/v1`` and ``fact_reconciliation/v1``;
* ``bundle_native`` - ``native_request_projection/v1`` and its injected check;
* ``bundle_executions`` - the Gate-3 fingerprint, execution records, row pairing;
* ``bundle_record`` - ``certification_7b_record/v1``;
* ``bundle_reconcile`` - tolerance profile resolution and ``reconcile_7b_fact_sets``;
* ``bundle_verify`` - ``verify_certification_7b_record``.

Malformed evidence (grammar, extra or missing member, wrong order, divergent
digest, failed binding) raises ``Bundle7BDefectError`` with a closed ``code``.
Legitimate failed comparisons (``mismatch``, ``not_comparable``) are values.
No float, clock, I/O or signature verification is involved.

Frozen objects validate once, in ``__post_init__``, and ``object.__setattr__``
bypasses that, so every public function that consumes a value object (the verifier,
``reconcile_7b_fact_sets``, ``check_native_request``, ``require_same_fingerprint``,
``select_fact_evidence``, ``resolve_fact_evidence`` and the ``compute_*`` /
``expected_pair_universe`` digest helpers) re-parses it from its wire form first,
``from_dict(to_dict())``, and uses only the copy. A tampered object is rejected exactly
as its wire form would be; a bare error from ``to_dict`` or ``from_dict`` is
``malformed_member``. Foreign objects are re-parsed through their own ``from_dict``;
``ResolvedGate3SelectionState`` has none and is rebuilt with its own constructor.
``artifact_locator_for`` and ``collection_result_locator`` only address a
serialization (coded errors, no re-parse). Constructors and methods of an already
built, tampered instance are not entry points.

Not verified, because no resolved evidence for them is supplied:

* ``wheel_digest``, ``reference_workload_binary_digest``, ``reference_code_digest``
  and ``reference_run_digest`` are checked for grammar only;
* the ``gate3_certification_fingerprint`` argument of the verifier is trusted as
  the selection's ``certification_fingerprint``: only five of its members are
  compared with ``ResolvedGate3SelectionState``; the other six
  (selected_meta_api_version, reference_client_identity_digest,
  official_source_locators_digest, parser_code_digest, adapter_code_digest,
  mapping_rules_digest) and ``certification_fingerprint_digest`` are not, since
  the ADR gives no formula for that digest;
* ``effect_proof/v1`` contents are not modelled; only the two proof locators,
  their distinctness and their result locators are checked.

Choices the ADR does not fix (open decisions, kept as implemented):

* ``required_metrics`` is pinned to the YAML order ``[impressions, clicks, spend]``;
* the ``native_request_projection/v1`` member names, and its endpoint grammar;
* ``native_request_digest`` is taken over the full ``to_dict()``, ``integrity`` included;
* a partial ``collection_result/v1`` raises ``collection_result_incomplete``
  instead of returning a failed value;
* ``X(f)`` for ``fact_projection_digest`` is the complete normalized fact.
"""
from __future__ import annotations

from smart_ads.reconciliation.bundle_common import (
    CERTIFICATION_7B_RECORD_SCHEMA,
    DEFECT_CODES,
    FACT_EVIDENCE_SELECTOR_SCHEMA,
    FACT_RECONCILIATION_SCHEMA,
    MAXIMUM_RETRIEVAL_SKEW_SECONDS,
    NATIVE_REQUEST_PROJECTION_SCHEMA,
    REQUIRED_7B_METRICS,
    Bundle7BDefectError,
    artifact_locator_for,
)
from smart_ads.reconciliation.bundle_evidence import (
    FactEvidenceSelector,
    FactReconciliation,
    ReconciliationSide,
    collection_result_locator,
    compute_logical_fact_reconciliation_digest,
    resolve_fact_evidence,
    select_fact_evidence,
)
from smart_ads.reconciliation.bundle_executions import (
    CANDIDATE_DRIVER_ID,
    CANDIDATE_PROVIDER_TARGET_REF,
    REFERENCE_PROVIDER_TARGET_REF,
    REFERENCE_WORKLOAD_REF,
    CandidateExecution,
    Gate3CertificationFingerprint,
    ReferenceExecution,
    RowPairing,
    require_same_fingerprint,
)
from smart_ads.reconciliation.bundle_native import (
    NativeRequestProjection,
    NativeToCanonicalAlgorithm,
    check_native_request,
)
from smart_ads.reconciliation.bundle_reconcile import (
    RECONCILE_OUTCOME_CODES,
    Reconciliation7BResult,
    reconcile_7b_fact_sets,
)
from smart_ads.reconciliation.bundle_record import Certification7BRecord
from smart_ads.reconciliation.bundle_universe import (
    MetricPairKey,
    compute_canonical_fact_key_digest,
    compute_pair_universe,
    compute_row_universe,
    compute_row_universe_digest,
    expected_pair_universe,
)
from smart_ads.reconciliation.bundle_verify import verify_certification_7b_record

__all__ = [
    "Bundle7BDefectError",
    "CANDIDATE_DRIVER_ID",
    "CANDIDATE_PROVIDER_TARGET_REF",
    "CERTIFICATION_7B_RECORD_SCHEMA",
    "CandidateExecution",
    "Certification7BRecord",
    "DEFECT_CODES",
    "FACT_EVIDENCE_SELECTOR_SCHEMA",
    "FACT_RECONCILIATION_SCHEMA",
    "FactEvidenceSelector",
    "FactReconciliation",
    "Gate3CertificationFingerprint",
    "MAXIMUM_RETRIEVAL_SKEW_SECONDS",
    "MetricPairKey",
    "NATIVE_REQUEST_PROJECTION_SCHEMA",
    "NativeRequestProjection",
    "NativeToCanonicalAlgorithm",
    "RECONCILE_OUTCOME_CODES",
    "REFERENCE_PROVIDER_TARGET_REF",
    "REFERENCE_WORKLOAD_REF",
    "REQUIRED_7B_METRICS",
    "Reconciliation7BResult",
    "ReconciliationSide",
    "ReferenceExecution",
    "RowPairing",
    "artifact_locator_for",
    "check_native_request",
    "collection_result_locator",
    "compute_canonical_fact_key_digest",
    "compute_logical_fact_reconciliation_digest",
    "compute_pair_universe",
    "compute_row_universe",
    "compute_row_universe_digest",
    "expected_pair_universe",
    "reconcile_7b_fact_sets",
    "require_same_fingerprint",
    "resolve_fact_evidence",
    "select_fact_evidence",
    "verify_certification_7b_record",
]
