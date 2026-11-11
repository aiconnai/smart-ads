"""Fail-closed admission, U x M completeness verifier, and purpose-discriminated collection orchestration."""
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

__all__ = [
    "AdmissionError",
    "AdmittedCollectionBundle",
    "CompletenessEvaluation",
    "CompletenessStatus",
    "FixtureCollectionEvaluation",
    "LiveCallExecutionOutcome",
    "PurposeEntrypointMismatchError",
    "admit_collection",
    "build_expected_fact_universe",
    "collect",
    "evaluate_fixture_collection",
    "execute_admitted_call",
    "recompute_collection_completeness",
]
