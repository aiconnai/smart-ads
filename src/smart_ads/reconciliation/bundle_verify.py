"""``verify_certification_7b_record``: recompute a 7B record from resolved evidence (ADR 5.4)."""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Final

from smart_ads.contracts.jcs import ArtifactLocator
from smart_ads.contracts.schemas import AdmittedCollection, CollectionResult
from smart_ads.domain.pipeboard_contract import PipeboardPhase1Contract
from smart_ads.ports.cell_runtime import ResolvedGate3SelectionState
from smart_ads.reconciliation.bundle_common import (
    EFFECT_PROOF_SCHEMA,
    RUN_CONTEXT_SCHEMA,
    Bundle7BDefectError,
    artifact_locator_for,
    query_bytes,
    require_argument_locator,
    require_callable,
    require_type,
)
from smart_ads.reconciliation.bundle_evidence import (
    FactReconciliation,
    ReconciliationSide,
    ResultIndex,
    resolve_fact_evidence,
)
from smart_ads.reconciliation.bundle_executions import (
    CandidateExecution,
    Gate3CertificationFingerprint,
    require_same_fingerprint,
)
from smart_ads.reconciliation.bundle_native import NativeToCanonicalAlgorithm, check_native_request
from smart_ads.reconciliation.bundle_reconcile import (
    ResolvedProfiles,
    binding_members,
    resolve_profiles,
    side_facts,
)
from smart_ads.reconciliation.bundle_record import Certification7BRecord
from smart_ads.reconciliation.bundle_universe import (
    SideUniverse,
    pair_of,
    require_facts_in_query,
)
from smart_ads.reconciliation.tolerance import ComparisonSide, compare_sides

_LIVE_7B_PURPOSE: Final[str] = "live_verification_7b"
# Resolved Gate-3 selection members that must agree with the resolved fingerprint.
_GATE3_STATE_FINGERPRINT_PAIRS: Final[tuple[str, ...]] = (
    "candidate_driver_contract_digest",
    "canonical_query_digest",
    "schema_bundle_digest",
    "resource_mapping_contract_digest",
    "authorized_certification_scope",
)


def _verify_arguments(record: object, arguments: Mapping[str, Any]) -> None:
    require_type(record, Certification7BRecord, label="record")
    for name, expected in (
        ("gate3_selection", ResolvedGate3SelectionState),
        ("gate3_certification_fingerprint", Gate3CertificationFingerprint),
        ("driver_contract", PipeboardPhase1Contract),
        ("candidate_admission", AdmittedCollection),
        ("reference_admission", AdmittedCollection),
        ("candidate_result", CollectionResult),
        ("reference_result", CollectionResult),
    ):
        require_type(arguments[name], expected, label=name)
    for name, artifact_type in (
        ("migration_run_context_locator", RUN_CONTEXT_SCHEMA),
        ("candidate_effect_proof_locator", EFFECT_PROOF_SCHEMA),
        ("reference_effect_proof_locator", EFFECT_PROOF_SCHEMA),
        ("candidate_effect_result_locator", CollectionResult.SCHEMA),
        ("reference_effect_result_locator", CollectionResult.SCHEMA),
    ):
        require_argument_locator(arguments[name], artifact_type, label=name)
    require_callable(arguments["project_native_request"], label="project_native_request")


def _verify_gate3(
    record: Certification7BRecord,
    selection: ResolvedGate3SelectionState,
    resolved: Gate3CertificationFingerprint,
) -> None:
    """Same fresh certification-role selection; whole-object fingerprint equality on both sides."""
    if selection.locator != record.gate3_selection_locator:
        raise Bundle7BDefectError(
            "gate3_selection_mismatch", "record names another Gate-3 selection"
        )
    if selection.selection_role != "certification":
        raise Bundle7BDefectError(
            "gate3_selection_mismatch", "only a certification-role selection may appear in 7B"
        )
    for name in ("candidate_execution", "reference_execution"):
        own = getattr(record, name).gate3_certification_fingerprint
        require_same_fingerprint(own, resolved, label=f"{name} vs resolved Gate-3 selection")
    for member in _GATE3_STATE_FINGERPRINT_PAIRS:
        if getattr(selection, member) != getattr(resolved, member):
            raise Bundle7BDefectError(
                "gate3_selection_mismatch", f"selection {member} differs from its fingerprint"
            )


def _verify_effect_locators(record: Certification7BRecord, arguments: Mapping[str, Any]) -> None:
    for side in ("candidate", "reference"):
        recorded = getattr(record, f"{side}_execution").effect_proof_locator
        if recorded != arguments[f"{side}_effect_proof_locator"]:
            raise Bundle7BDefectError(
                "effect_proof_mismatch", f"{side}: record names another effect proof"
            )
    candidate_result = arguments["candidate_effect_result_locator"]
    if candidate_result == arguments["reference_effect_result_locator"]:
        raise Bundle7BDefectError(
            "effect_proof_not_distinct", "one action result cannot satisfy both sides"
        )


def _verify_bindings(record: Certification7BRecord, arguments: Mapping[str, Any]) -> None:
    if record.migration_run_context_locator != arguments["migration_run_context_locator"]:
        raise Bundle7BDefectError(
            "run_context_mismatch", "record belongs to another migration run"
        )
    _verify_gate3(
        record, arguments["gate3_selection"], arguments["gate3_certification_fingerprint"]
    )
    _verify_effect_locators(record, arguments)
    contract_locator = artifact_locator_for(
        PipeboardPhase1Contract.SCHEMA, arguments["driver_contract"]
    )
    if contract_locator != record.candidate_execution.driver_contract_locator:
        raise Bundle7BDefectError(
            "driver_contract_unresolved", "candidate contract locator does not resolve"
        )


def _verify_admission(
    record: Certification7BRecord, execution: Any, admission: AdmittedCollection
) -> None:
    label = "admission"
    admitted_locator = artifact_locator_for(AdmittedCollection.SCHEMA, admission)
    if admitted_locator != execution.admitted_collection_locator:
        raise Bundle7BDefectError(
            "admission_mismatch", f"{label}: does not resolve the side's locator"
        )
    if admission.collection_purpose != _LIVE_7B_PURPOSE:
        raise Bundle7BDefectError(
            "admission_mismatch", f"{label}: purpose must be {_LIVE_7B_PURPOSE!r}"
        )
    admitted_query = query_bytes(admission.canonical_query_contract)
    if admitted_query != query_bytes(record.canonical_query_contract):
        raise Bundle7BDefectError("admission_mismatch", f"{label}: admitted another query")
    if not isinstance(execution, CandidateExecution):
        return
    admitted = (
        admission.driver_id,
        admission.driver_contract_locator,
        admission.registry_snapshot_locator,
    )
    recorded = (
        execution.driver_id,
        execution.driver_contract_locator,
        execution.registry_snapshot_locator,
    )
    if admitted != recorded:
        raise Bundle7BDefectError("admission_mismatch", f"{label}: driver or registry differs")


def _verify_result_binding(execution: Any, result: CollectionResult, call_side: str) -> None:
    if result.admitted_collection_locator != execution.admitted_collection_locator or (
        result.retrieval_context.retrieved_at_utc != execution.retrieved_at_utc
    ):
        raise Bundle7BDefectError(
            "collection_result_mismatch", f"{call_side}: admission or retrieval time differs"
        )
    if isinstance(execution, CandidateExecution) and (
        result.registry_snapshot_locator != execution.registry_snapshot_locator
    ):
        raise Bundle7BDefectError(
            "collection_result_mismatch", f"{call_side}: result registry snapshot differs"
        )
    if result.normalized_fact_set_digest != execution.normalized_fact_set_digest:
        raise Bundle7BDefectError(
            "normalized_fact_set_digest_mismatch", f"{call_side}: set digest differs"
        )


def _verify_result(
    record: Certification7BRecord,
    execution: Any,
    index: ResultIndex,
    call_side: str,
    effect_result: ArtifactLocator,
) -> None:
    result = index.result
    facts = side_facts(result, call_side)
    _verify_result_binding(execution, result, call_side)
    require_facts_in_query(facts, record.canonical_query_contract, label=f"{call_side}_result")
    if index.locator != effect_result:
        raise Bundle7BDefectError(
            "effect_result_mismatch", f"{call_side}: effect proof result is another result"
        )
    universe = SideUniverse.of(facts)
    if universe.row_universe_digest != execution.row_universe_digest:
        raise Bundle7BDefectError(
            "row_universe_digest_mismatch", f"{call_side}: recomputed U7 digest differs"
        )
    if not universe.is_complete:
        raise Bundle7BDefectError(
            "pair_universe_incomplete", f"{call_side}: U7M is not U7 x required_metrics"
        )
    if len(universe.pairs) != execution.row_count:
        raise Bundle7BDefectError(
            "row_count_mismatch", f"{call_side}: row_count must equal length(U7M)"
        )


def _verify_side(
    record: Certification7BRecord, call_side: str, arguments: Mapping[str, Any]
) -> ResultIndex:
    execution = getattr(record, f"{call_side}_execution")
    _verify_admission(record, execution, arguments[f"{call_side}_admission"])
    index = ResultIndex.of(arguments[f"{call_side}_result"])
    _verify_result(
        record,
        execution,
        index,
        call_side,
        arguments[f"{call_side}_effect_result_locator"],
    )
    check_native_request(
        execution.native_request_projection,
        native_request_digest=execution.native_request_digest,
        canonical_query=record.canonical_query_contract,
        algorithm_digest=execution.native_to_canonical_projection_algorithm_digest,
        project_native_request=arguments["project_native_request"],
    )
    return index


def _verify_side_evidence(
    item: FactReconciliation, side_name: str, result: ResultIndex
) -> ComparisonSide:
    side = getattr(item, side_name)
    fact = resolve_fact_evidence(side.fact_evidence_selector, result)
    if pair_of(fact) != item.pair_key():
        raise Bundle7BDefectError(
            "evidence_selector_mismatch", f"{side_name}: fact metric is not the compared metric"
        )
    resolved = ReconciliationSide.for_fact(fact, side.fact_evidence_selector)
    if resolved != side:
        raise Bundle7BDefectError(
            "evidence_value_mismatch", f"{side_name}: copied fields differ from the fact"
        )
    return resolved.comparison_side()


def _verify_reconciliation(
    item: FactReconciliation,
    indexes: Mapping[str, ResultIndex],
    profiles: ResolvedProfiles,
) -> None:
    candidate = _verify_side_evidence(item, "candidate", indexes["candidate"])
    reference = _verify_side_evidence(item, "reference", indexes["reference"])
    metric = item.canonical_metric_ref
    profile, profile_locator = profiles[metric]
    if item.tolerance_profile_locator != profile_locator:
        raise Bundle7BDefectError(
            "tolerance_profile_locator_mismatch", "reconciliation names another profile"
        )
    recomputed = compare_sides(candidate, reference, profile, canonical_metric_ref=metric)
    if recomputed != item.asserted_comparison:
        raise Bundle7BDefectError(
            "asserted_comparison_mismatch", f"{item.pair_key().kfive()}: asserted members differ"
        )


def _verify_reconciliations(
    record: Certification7BRecord,
    arguments: Mapping[str, Any],
    indexes: Mapping[str, ResultIndex],
    tolerance_profiles: object,
) -> None:
    """Resolve the protected profiles under the record's run, query, scope and selection."""
    fingerprint = arguments["gate3_certification_fingerprint"]
    binding = binding_members(
        gate3_selection_locator=record.gate3_selection_locator,
        canonical_query_digest=record.canonical_query_digest,
        authorized_certification_scope=fingerprint.authorized_certification_scope,
        migration_run_context_locator=record.migration_run_context_locator,
    )
    profiles = resolve_profiles(tolerance_profiles, binding)
    for item in record.fact_reconciliations:
        _verify_reconciliation(item, indexes, profiles)


def verify_certification_7b_record(
    record: Certification7BRecord,
    *,
    migration_run_context_locator: ArtifactLocator,
    gate3_selection: ResolvedGate3SelectionState,
    gate3_certification_fingerprint: Gate3CertificationFingerprint,
    driver_contract: PipeboardPhase1Contract,
    candidate_admission: AdmittedCollection,
    reference_admission: AdmittedCollection,
    candidate_result: CollectionResult,
    reference_result: CollectionResult,
    candidate_effect_proof_locator: ArtifactLocator,
    candidate_effect_result_locator: ArtifactLocator,
    reference_effect_proof_locator: ArtifactLocator,
    reference_effect_result_locator: ArtifactLocator,
    tolerance_profiles: Mapping[str, Mapping[str, Any]],
    project_native_request: NativeToCanonicalAlgorithm,
) -> None:
    """Recompute the whole 7B record from in-memory resolved evidence; any failure raises.

    The record constructor already recomputed every intrinsic member. This adds
    the bindings to resolved evidence (run, certification-role Gate-3 selection
    and fingerprint, driver contract, admissions, complete results whose facts lie
    inside the admitted query window, binding and account, effect-proof locators,
    injected native projection, protected tolerance profiles) and, per
    reconciliation, the resolved facts and the recomputed comparison.

    Not verified here, because no resolved evidence for them is supplied:

    * ``wheel_digest``, ``reference_workload_binary_digest``,
      ``reference_code_digest`` and ``reference_run_digest`` are checked for
      grammar only;
    * ``gate3_certification_fingerprint`` is trusted as the selection's
      ``certification_fingerprint``: only five members are compared with
      ``gate3_selection`` (candidate_driver_contract_digest,
      canonical_query_digest, schema_bundle_digest,
      resource_mapping_contract_digest, authorized_certification_scope); the
      other six (selected_meta_api_version, reference_client_identity_digest,
      official_source_locators_digest, parser_code_digest, adapter_code_digest,
      mapping_rules_digest) and the selection's
      ``certification_fingerprint_digest`` are not, since the ADR gives no
      formula for that digest;
    * ``effect_proof/v1`` contents are not modelled: only the two proof
      locators and their result locators are compared.
    """
    arguments: dict[str, Any] = {
        "migration_run_context_locator": migration_run_context_locator,
        "gate3_selection": gate3_selection,
        "gate3_certification_fingerprint": gate3_certification_fingerprint,
        "driver_contract": driver_contract,
        "candidate_admission": candidate_admission,
        "reference_admission": reference_admission,
        "candidate_result": candidate_result,
        "reference_result": reference_result,
        "candidate_effect_proof_locator": candidate_effect_proof_locator,
        "candidate_effect_result_locator": candidate_effect_result_locator,
        "reference_effect_proof_locator": reference_effect_proof_locator,
        "reference_effect_result_locator": reference_effect_result_locator,
        "project_native_request": project_native_request,
    }
    _verify_arguments(record, arguments)
    _verify_bindings(record, arguments)
    # Each side's recomputed U7 digest equals the record's (which the constructor
    # recomputed from the reconciliations) and each U7M is complete, so the two
    # sides and the reconciliation set necessarily share one universe.
    indexes = {side: _verify_side(record, side, arguments) for side in ("candidate", "reference")}
    _verify_reconciliations(record, arguments, indexes, tolerance_profiles)
