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
    located,
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
    "check_native_request",
    "collection_result_locator",
    "compute_canonical_fact_key_digest",
    "compute_logical_fact_reconciliation_digest",
    "compute_pair_universe",
    "compute_row_universe",
    "compute_row_universe_digest",
    "expected_pair_universe",
    "located",
    "reconcile_7b_fact_sets",
    "require_same_fingerprint",
    "resolve_fact_evidence",
    "select_fact_evidence",
    "verify_certification_7b_record",
]
