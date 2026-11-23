"""Fail-closed admission, U x M completeness, collection, deterministic curation, and global catalog CAS."""
from __future__ import annotations

from smart_ads.application.admission import (
    AdmissionError,
    AdmittedCollectionBundle,
    admit_collection,
)
from smart_ads.application.collection import (
    FixtureCollectionEvaluation,
    LiveCallExecutionOutcome,
    PurposeEntrypointMismatchError,
    collect,
    evaluate_fixture_collection,
    execute_admitted_call,
)
from smart_ads.application.completeness import (
    CompletenessEvaluation,
    CompletenessStatus,
    build_expected_fact_universe,
    recompute_collection_completeness,
)
from smart_ads.application.curation_pipeline import (
    GlobalDatasetCatalogService,
    build_sanitized_candidate_fact_set,
    materialize_parquet_generation,
    publish_dataset_snapshot,
    replay_curated_partition_rows,
    verify_algorithm_provenance_identity,
    verify_curation_execution,
    verify_dataset_catalog_cut_receipt,
    verify_dataset_snapshot,
    verify_generation_manifest,
    verify_operational_read_evidence,
    verify_sanitized_candidate_fact_set,
)
from smart_ads.application.duckdb_execution import (
    execute_analysis_replay_bundle,
    execute_certified_report,
)
from smart_ads.application.mcp_read_handler import (
    McpVerifiedReadIndex,
    VerifiedStoreMcpReadHandler,
    load_verified_snapshot_rows,
)
from smart_ads.application.retention_service import (
    ReachabilityClosure,
    RetentionRootSetService,
    WheelObjectLocator,
    build_retention_root,
    compute_retention_reachability_graph,
    head_pinned_object_refs,
    verify_retention_release_proof,
    verify_retention_root,
    verify_retention_root_admission_proof,
)

__all__ = [
    "AdmissionError",
    "AdmittedCollectionBundle",
    "CompletenessEvaluation",
    "CompletenessStatus",
    "FixtureCollectionEvaluation",
    "GlobalDatasetCatalogService",
    "LiveCallExecutionOutcome",
    "McpVerifiedReadIndex",
    "PurposeEntrypointMismatchError",
    "ReachabilityClosure",
    "RetentionRootSetService",
    "VerifiedStoreMcpReadHandler",
    "WheelObjectLocator",
    "admit_collection",
    "build_expected_fact_universe",
    "build_retention_root",
    "build_sanitized_candidate_fact_set",
    "collect",
    "compute_retention_reachability_graph",
    "evaluate_fixture_collection",
    "execute_admitted_call",
    "execute_analysis_replay_bundle",
    "execute_certified_report",
    "head_pinned_object_refs",
    "load_verified_snapshot_rows",
    "materialize_parquet_generation",
    "publish_dataset_snapshot",
    "recompute_collection_completeness",
    "replay_curated_partition_rows",
    "verify_algorithm_provenance_identity",
    "verify_curation_execution",
    "verify_dataset_catalog_cut_receipt",
    "verify_dataset_snapshot",
    "verify_generation_manifest",
    "verify_operational_read_evidence",
    "verify_retention_release_proof",
    "verify_retention_root",
    "verify_retention_root_admission_proof",
    "verify_sanitized_candidate_fact_set",
]
