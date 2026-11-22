"""Unit tests for PR 4 contracts (effects, operational_evidence, retention) and domain (curation, catalog)."""
from __future__ import annotations

import dataclasses
from typing import Any

import pytest

import smart_ads.contracts as contracts_pkg
from smart_ads.contracts import (
    ADR_DATA_DOMAIN_PREFIXES,
    ADR_P1_DOMAIN_PREFIXES,
    ArtifactLocator,
    ClosedValidationError,
    P1Integrity,
    domain_jcs_sha256,
    jcs_sha256,
    p1_content_digest,
    self_digest_jcs_sha256,
    validate_envelope_timestamp_utc,
)
from smart_ads.contracts.effects import (
    AuthorizationConsumptionRecord,
    AuthorizationReceipt,
    AuthorizationReservationRecord,
    EffectProof,
    ExecutionReceipt,
    ProviderCallTarget,
    RetentionReleaseTarget,
    RetentionRootAdmissionTarget,
    parse_effect_subject,
    sort_artifact_locators,
    sort_cell_object_refs,
    validate_cell_object_ref,
    verify_four_record_effect_proof,
)
from smart_ads.contracts.operational_evidence import (
    AlgorithmProvenanceIdentity,
    OperationalReadEvidence,
    SanitizedCandidateFactSet,
)
from smart_ads.contracts.retention import (
    RetentionReleaseProof,
    RetentionReleaseResult,
    RetentionRoot,
    RetentionRootAdmissionProof,
    RetentionRootAdmissionResult,
    RetentionRootSetCasReceipt,
    RetentionRootSetCasRequestProjection,
    RetentionRootSetHead,
)
from smart_ads.contracts.schemas import AnalyticsLandingRow, DateRange, FactKey
import smart_ads.domain as domain_pkg
from smart_ads.domain.catalog import (
    ActivePartitionHead,
    CatalogCasRequestProjection,
    DatasetCatalog,
    DatasetCatalogCutReceipt,
    DatasetCatalogGenesisConsumptionRecord,
    DatasetCatalogGenesisRecord,
    DatasetSnapshot,
    GenerationManifest,
    ParquetObjectLocator,
    compute_logical_rows_digest,
    compute_physical_parquet_set_digest,
)
from smart_ads.domain.curation import (
    CurationExecution,
    compute_curation_window,
    partition_key_for_metric_date,
    validate_partition_key,
)


def _loc(artifact_type: str, fill: str = "a") -> ArtifactLocator:
    return ArtifactLocator.from_digest(artifact_type, "sha256:" + (fill * 64))


def _unsigned_p1() -> P1Integrity:
    return P1Integrity(
        key_id="key:ed25519:" + ("a" * 64),
        key_registry_snapshot_locator=_loc("smart_ads/key_authorization_registry/v1", "9"),
    )


def _sign_dict(unsigned_dict: dict[str, Any]) -> dict[str, Any]:
    return {
        **unsigned_dict,
        "integrity": {
            **_unsigned_p1().to_dict(),
            "content_digest": p1_content_digest(unsigned_dict),
            "signature_base64": ("A" * 86) + "==",
        },
    }


def _make_landing_row(
    *,
    metric_date: str = "2026-11-10",
    metric_semantic_ref: str = "metric:clicks_v1",
    source_metric_ref: str = "source-metric:provider:pipeboard.clicks:v1",
    raw_val: str = "15",
    collected_at_utc: str = "2026-11-11T03:02:00.000000Z",
) -> AnalyticsLandingRow:
    fk = FactKey(
        binding_ref="binding:meta-primary",
        account_ref="account:ibvi-01",
        resource_ref="resource:" + ("a" * 52),
        resource_level="campaign",
        metric_date=metric_date,
        metric_semantic_ref=metric_semantic_ref,
        source_metric_ref=source_metric_ref,
        attribution_ref="attribution:not_applicable",
        breakdown_signature="breakdown:none",
    )
    return AnalyticsLandingRow(
        fact_key=fk,
        value_type="int64_count",
        raw_numeric_value=raw_val,
        unit="count",
        currency=None,
        metric_origin="provider_observation",
        presence_status="observed",
        unknown_reason=None,
        calculation_status="not_applicable",
        collected_at_utc=collected_at_utc,
        source_observation_ref="observation:obs-001",
        adapter_version="pipeboard-0.1.0",
        semantic_version="1.0.0",
    )


def _make_algorithm_id(schema_id: str = "smart_ads/sanitized_candidate_fact_set/v1") -> AlgorithmProvenanceIdentity:
    return AlgorithmProvenanceIdentity(
        algorithm_id="algorithm:curation-v1",
        algorithm_version="1.0.0",
        git_artifact_provenance_locator=_loc("smart_ads/git_artifact_provenance/v1", "6"),
        repository="aiconnai/smart-ads",
        commit_sha="a" * 40,
        path="src/smart_ads/application/curation_pipeline.py",
        git_blob_oid="b" * 40,
        file_content_sha256="sha256:" + ("c" * 64),
        runtime_abi="cpython-3.12",
        schema_id=schema_id,
    )


def _build_operational_effect_chain() -> tuple[
    ProviderCallTarget,
    AuthorizationReceipt,
    AuthorizationReservationRecord,
    ExecutionReceipt,
    AuthorizationConsumptionRecord,
    EffectProof,
]:
    run_loc = _loc("smart_ads/migration_run_context/v1", "1")
    adm_loc = _loc("smart_ads/admitted_collection/v1", "2")
    reg_loc = _loc("smart_ads/private_registry_snapshot/v1", "3")
    res_loc = _loc("smart_ads/collection_result/v1", "5")
    p1 = _unsigned_p1()
    subj = ProviderCallTarget(
        migration_run_context_locator=run_loc,
        admitted_collection_locator=adm_loc,
        call_side="operational",
        provider_target_ref="provider-target:pipeboard-hosted",
        canonical_query_digest="sha256:" + ("7" * 64),
        registry_snapshot_locator=reg_loc,
        tenant_ref="tenant:ibvi",
        binding_ref="binding:meta-primary",
        account_ref="account:ibvi-01",
        resource_scope_ref="scope:campaigns-active",
        delegation_context_locator=_loc("smart_ads/ibvi_ads_delegation_context/v1", "8"),
    )
    auth = AuthorizationReceipt.from_dict(
        _sign_dict(
            AuthorizationReceipt(
                authorization_id="auth:op-001",
                migration_run_context_locator=run_loc,
                action="provider_operational_read",
                dag_slot="operational_provider_read_effect_proof",
                subject=subj,
                parameters_digest="sha256:" + ("d" * 64),
                predecessor_locators=(adm_loc,),
                approving_principal_ref="principal:operator-01",
                issued_at_utc="2026-11-11T03:00:00Z",
                valid_until_utc="2026-11-11T04:00:00.500000Z",
                single_use_nonce="nonce-op-001",
                integrity=p1,
            ).to_dict()
        ),
        require_signed=True,
    )
    resv, exec_rec, cons, proof = _finish_signed_effect_chain(auth, res_loc)
    return subj, auth, resv, exec_rec, cons, proof


def _finish_signed_effect_chain(
    auth: AuthorizationReceipt,
    result_loc: ArtifactLocator,
) -> tuple[
    AuthorizationReservationRecord,
    ExecutionReceipt,
    AuthorizationConsumptionRecord,
    EffectProof,
]:
    p1 = _unsigned_p1()
    auth_loc = auth.locator()
    resv_raw = AuthorizationReservationRecord(
        "resv:001", auth.migration_run_context_locator, auth_loc, auth_loc.content_digest,
        auth.single_use_nonce, auth.action, auth.dag_slot, auth.subject, "consumed", None,
        "2026-11-11T03:01:00Z", p1,
    )
    resv = AuthorizationReservationRecord.from_dict(_sign_dict(resv_raw.to_dict()), require_signed=True)
    exec_raw = ExecutionReceipt(
        "exec:001", auth.migration_run_context_locator, auth_loc, resv.locator(),
        auth.single_use_nonce, auth.action, auth.dag_slot, auth.subject, "succeeded",
        result_loc, "2026-11-11T03:02:00Z", p1,
    )
    exec_rec = ExecutionReceipt.from_dict(_sign_dict(exec_raw.to_dict()), require_signed=True)
    cons, proof = _build_signed_consumption_and_proof(auth, resv.locator(), exec_rec.locator(), result_loc)
    return resv, exec_rec, cons, proof


def _build_signed_consumption_and_proof(
    auth: AuthorizationReceipt,
    resv_loc: ArtifactLocator,
    exec_loc: ArtifactLocator,
    result_loc: ArtifactLocator,
) -> tuple[AuthorizationConsumptionRecord, EffectProof]:
    p1 = _unsigned_p1()
    auth_loc = auth.locator()
    cons_raw = AuthorizationConsumptionRecord(
        "cons:001", auth.migration_run_context_locator, auth_loc, auth_loc.content_digest,
        resv_loc, exec_loc, auth.single_use_nonce, auth.action, auth.dag_slot, "consumed",
        "2026-11-11T03:03:00Z", p1,
    )
    cons = AuthorizationConsumptionRecord.from_dict(_sign_dict(cons_raw.to_dict()), require_signed=True)
    proof_raw = EffectProof(
        "proof:001", auth.migration_run_context_locator, auth.action, auth.dag_slot,
        auth_loc, resv_loc, exec_loc, cons.locator(), result_loc, "2026-11-11T03:04:00Z", p1,
    )
    proof = EffectProof.from_dict(_sign_dict(proof_raw.to_dict()), require_signed=True)
    return cons, proof


def test_envelope_timestamp_and_cell_object_ref_validators() -> None:
    assert validate_envelope_timestamp_utc("2026-11-11T03:00:00Z") == "2026-11-11T03:00:00Z"
    assert validate_envelope_timestamp_utc("2026-11-11T03:00:00.123456Z") == "2026-11-11T03:00:00.123456Z"
    for bad_ts in ("2026-11-11T03:00:00.123Z", "2026-11-11T24:00:00Z", True, None):
        with pytest.raises(ClosedValidationError):
            validate_envelope_timestamp_utc(bad_ts)

    obj_ref = "cell-object:sha256:" + ("a" * 64)
    assert validate_cell_object_ref(obj_ref) == obj_ref
    assert sort_cell_object_refs(["cell-object:sha256:" + ("b" * 64), obj_ref]) == (
        obj_ref,
        "cell-object:sha256:" + ("b" * 64),
    )
    with pytest.raises(ClosedValidationError):
        validate_cell_object_ref("sha256:" + ("a" * 64))


def test_discriminated_effect_subjects_roundtrip_and_rejections() -> None:
    run_loc = _loc("smart_ads/migration_run_context/v1", "1")
    head_loc = _loc("smart_ads/retention_root_set_head/v1", "2")
    sorted_roots = sort_artifact_locators(
        [_loc("smart_ads/retention_root/v1", "4"), _loc("smart_ads/retention_root/v1", "3")],
        expected_type="smart_ads/retention_root/v1",
    )
    adm_target = RetentionRootAdmissionTarget(
        run_loc, "cell:ibvi-primary", head_loc, 0, head_loc.content_digest, sorted_roots,
        ("cell-object:sha256:" + ("5" * 64),), "sha256:" + ("6" * 64), "sha256:" + ("7" * 64),
        "sha256:" + ("8" * 64),
    )
    assert parse_effect_subject(adm_target.to_dict()) == adm_target
    rel_target = RetentionReleaseTarget(
        run_loc, "cell:ibvi-primary", head_loc, 1, head_loc.content_digest, (sorted_roots[0],),
        (sorted_roots[1],), (), "sha256:" + ("7" * 64), "sha256:" + ("8" * 64), "sha256:" + ("9" * 64),
    )
    assert parse_effect_subject(rel_target.to_dict()) == rel_target
    with pytest.raises(ClosedValidationError):
        ProviderCallTarget(
            run_loc, _loc("smart_ads/admitted_collection/v1", "2"), "candidate",
            "provider-target:pipeboard-hosted", "sha256:" + ("7" * 64),
            _loc("smart_ads/private_registry_snapshot/v1", "3"), "tenant:ibvi", "binding:meta-primary",
            "account:ibvi-01", "scope:campaigns-active", _loc("smart_ads/ibvi_ads_delegation_context/v1", "8"),
        )


def test_verify_four_record_effect_proof_happy_path_and_in_doubt_rejection() -> None:
    _, auth, resv, exec_rec, cons, proof = _build_operational_effect_chain()
    verified = verify_four_record_effect_proof(
        effect_proof=proof, authorization=auth, reservation=resv, execution=exec_rec, consumption=cons,
        expected_action="provider_operational_read", expected_dag_slot="operational_provider_read_effect_proof",
        expected_result_type="smart_ads/collection_result/v1", require_signed=True,
    )
    assert verified == proof
    in_doubt_resv = AuthorizationReservationRecord.from_dict(
        _sign_dict({**resv.to_dict(), "reservation_status": "in_doubt", "in_doubt_reason": "pre_dispatch_freshness_failure", "integrity": _unsigned_p1().to_dict()}),
        require_signed=True,
    )
    in_doubt_exec = ExecutionReceipt.from_dict(
        _sign_dict({**exec_rec.to_dict(), "reservation_locator": in_doubt_resv.locator().to_dict(), "integrity": _unsigned_p1().to_dict()}),
        require_signed=True,
    )
    in_doubt_cons, in_doubt_proof = _build_signed_consumption_and_proof(
        auth, in_doubt_resv.locator(), in_doubt_exec.locator(), exec_rec.action_result_locator
    )
    with pytest.raises(ClosedValidationError, match="in_doubt|reservation_status"):
        verify_four_record_effect_proof(
            effect_proof=in_doubt_proof, authorization=auth, reservation=in_doubt_resv,
            execution=in_doubt_exec, consumption=in_doubt_cons, expected_action="provider_operational_read",
            expected_dag_slot="operational_provider_read_effect_proof",
            expected_result_type="smart_ads/collection_result/v1",
        )


def test_effect_chain_rejects_nonce_action_and_unsigned_tampering() -> None:
    _, auth, resv, exec_rec, cons, proof = _build_operational_effect_chain()
    with pytest.raises(ClosedValidationError):
        AuthorizationReservationRecord(
            reservation_id="resv:bad",
            migration_run_context_locator=auth.migration_run_context_locator,
            authorization_locator=auth.locator(),
            authorization_receipt_digest=auth.locator().content_digest,
            single_use_nonce=auth.single_use_nonce,
            action=auth.action,
            dag_slot=auth.dag_slot,
            subject=auth.subject,
            reservation_status="reserved",
            in_doubt_reason="ambiguous_external_effect",
            reserved_at_utc="2026-11-11T03:01:00Z",
        )
    with pytest.raises(ClosedValidationError):
        verify_four_record_effect_proof(
            effect_proof=proof,
            authorization=auth,
            reservation=resv,
            execution=exec_rec,
            consumption=cons,
            expected_action="retention_release",
            expected_dag_slot="retention_release_effect_proof",
            expected_result_type="smart_ads/retention_release_result/v1",
        )
    unsigned_proof = dataclasses.replace(proof, integrity=_unsigned_p1())
    with pytest.raises(ClosedValidationError):
        verify_four_record_effect_proof(
            effect_proof=unsigned_proof,
            authorization=auth,
            reservation=resv,
            execution=exec_rec,
            consumption=cons,
            expected_action="provider_operational_read",
            expected_dag_slot="operational_provider_read_effect_proof",
            expected_result_type="smart_ads/collection_result/v1",
            require_signed=True,
        )


def test_operational_evidence_and_sanitized_candidate_fact_set() -> None:
    _, auth, resv, exec_rec, cons, proof = _build_operational_effect_chain()
    reg_loc = _loc("smart_ads/private_registry_snapshot/v1", "3")
    adm_loc = _loc("smart_ads/admitted_collection/v1", "2")
    res_loc = _loc("smart_ads/collection_result/v1", "5")
    ev = OperationalReadEvidence(
        migration_run_context_locator=auth.migration_run_context_locator,
        tenant_ref="tenant:ibvi",
        binding_ref="binding:meta-primary",
        account_ref="account:ibvi-01",
        resource_scope_ref="scope:campaigns-active",
        canonical_query_digest="sha256:" + ("7" * 64),
        registry_snapshot_locator=reg_loc,
        registry_snapshot_digest=reg_loc.content_digest,
        expected_resource_inventory_locator=_loc("smart_ads/expected_resource_inventory/v1", "4"),
        admitted_collection_locator=adm_loc,
        admitted_collection_digest=adm_loc.content_digest,
        collection_result_locator=res_loc,
        collection_result_digest=res_loc.content_digest,
        normalized_fact_set_digest="sha256:" + ("b" * 64),
        authorization_locator=auth.locator(),
        reservation_locator=resv.locator(),
        execution_locator=exec_rec.locator(),
        consumption_locator=cons.locator(),
        effect_proof_locator=proof.locator(),
        integrity=_unsigned_p1(),
    )
    signed_ev = OperationalReadEvidence.from_dict(_sign_dict(ev.to_dict()), require_signed=True)
    assert signed_ev.integrity is not None and signed_ev.integrity.is_signed

    row_a = _make_landing_row(metric_semantic_ref="metric:clicks_v1", source_metric_ref="source-metric:provider:pipeboard.clicks:v1")
    row_b = _make_landing_row(metric_semantic_ref="metric:impressions_v1", source_metric_ref="source-metric:provider:pipeboard.impressions:v1")
    ordered = tuple(sorted((row_b, row_a), key=lambda r: r.candidate_sort_key_jcs()))
    cset = SanitizedCandidateFactSet(
        migration_run_context_locator=auth.migration_run_context_locator,
        sanitization_algorithm_identity=_make_algorithm_id(),
        source_collection_result_locators=(res_loc,),
        operational_read_evidence_locators=(signed_ev.locator(),),
        candidates=ordered,
        integrity=_unsigned_p1(),
    )
    assert cset.candidate_count == 2
    assert SanitizedCandidateFactSet.from_dict(_sign_dict(cset.to_dict()), require_signed=True).candidate_count == 2
    with pytest.raises(ClosedValidationError):
        SanitizedCandidateFactSet.from_dict({**cset.to_dict(), "candidates": [ordered[1].to_dict(), ordered[0].to_dict()]})


def test_retention_contracts_key_counts_and_roundtrips() -> None:
    assert len(RetentionRoot.KEYS) == 9 and len(RetentionRoot.CORE_KEYS) == 8
    assert len(RetentionRootSetHead.KEYS) == 9 and len(RetentionRootSetHead.CORE_KEYS) == 8
    assert len(RetentionRootSetCasReceipt.KEYS) == 15 and len(RetentionRootSetCasReceipt.CORE_KEYS) == 14
    assert len(RetentionRootAdmissionResult.KEYS) == 15 and len(RetentionRootAdmissionResult.CORE_KEYS) == 14
    assert len(RetentionRootAdmissionProof.KEYS) == 14 and len(RetentionRootAdmissionProof.CORE_KEYS) == 13
    assert len(RetentionReleaseResult.KEYS) == 15 and len(RetentionReleaseResult.CORE_KEYS) == 14
    assert len(RetentionReleaseProof.KEYS) == 17 and len(RetentionReleaseProof.CORE_KEYS) == 16

    run_loc = _loc("smart_ads/migration_run_context/v1", "1")
    target_loc = _loc("smart_ads/dataset_snapshot/v1", "2")
    root = RetentionRoot("root:r1", "cell:c1", run_loc, target_loc, (target_loc.object_ref,), "2026-11-11T03:00:00Z", integrity=_unsigned_p1())
    assert root.pinned_object_set_digest == jcs_sha256([target_loc.object_ref])
    assert RetentionRoot.from_dict(_sign_dict(root.to_dict()), require_signed=True).locator().artifact_type == RetentionRoot.SCHEMA

    head0 = RetentionRootSetHead("head:h0", "cell:c1", 0, (), None, "2026-11-11T03:00:00Z")
    head1 = RetentionRootSetHead("head:h1", "cell:c1", 1, (root.locator(),), head0.locator(), "2026-11-11T03:01:00Z")
    assert RetentionRootSetHead.from_dict(head0.to_dict()) == head0
    assert RetentionRootSetHead.from_dict(head1.to_dict()) == head1

    # Epoch 0 forbids predecessor; epoch >= 1 requires predecessor
    with pytest.raises(ClosedValidationError):
        RetentionRootSetHead("head:bad0", "cell:c1", 0, (), head0.locator(), "2026-11-11T03:00:00Z")
    with pytest.raises(ClosedValidationError):
        RetentionRootSetHead("head:bad1", "cell:c1", 1, (root.locator(),), None, "2026-11-11T03:01:00Z")


def test_retention_release_proof_rejects_overlapping_objects_or_false_flag() -> None:
    run_loc = _loc("smart_ads/migration_run_context/v1", "1")
    r1, r2 = sort_artifact_locators([_loc("smart_ads/retention_root/v1", "3"), _loc("smart_ads/retention_root/v1", "2")])
    shared_obj = "cell-object:sha256:" + ("9" * 64)
    base_kwargs: dict[str, Any] = {
        "migration_run_context_locator": run_loc,
        "cell_ref": "cell:c1",
        "effect_proof_locator": _loc("smart_ads/effect_proof/v1", "4"),
        "release_result_locator": _loc("smart_ads/retention_release_result/v1", "5"),
        "cas_receipt_locator": _loc("smart_ads/retention_root_set_cas_receipt/v1", "6"),
        "before_head_locator": _loc("smart_ads/retention_root_set_head/v1", "7"),
        "after_head_locator": _loc("smart_ads/retention_root_set_head/v1", "8"),
        "released_root_locators": (r1,),
        "retained_root_locators": (r2,),
        "released_object_refs": ("cell-object:sha256:" + ("a" * 64),),
        "retained_object_refs": (shared_obj,),
        "before_reachability_graph_digest": "sha256:" + ("b" * 64),
        "after_reachability_graph_digest": "sha256:" + ("c" * 64),
        "retained_root_non_reachability_verified": True,
        "verified_at_utc": "2026-11-11T03:10:00Z",
    }
    valid_proof = RetentionReleaseProof(**base_kwargs)
    assert RetentionReleaseProof.from_dict(valid_proof.to_dict()) == valid_proof

    with pytest.raises(ClosedValidationError):
        RetentionReleaseProof(**{**base_kwargs, "released_object_refs": (shared_obj,)})
    with pytest.raises(ClosedValidationError):
        RetentionReleaseProof(**{**base_kwargs, "retained_root_non_reachability_verified": False})


def test_curation_partition_keys_windows_and_modes() -> None:
    assert partition_key_for_metric_date("2026-08-31") == "year=2026/month=08"
    assert validate_partition_key("year=2026/month=12") == "year=2026/month=12"
    for bad_pk in ("year=2026/month=00", "year=2026/month=13", "2026-08", "year=0000/month=01", 123):
        with pytest.raises(ClosedValidationError):
            validate_partition_key(bad_pk)

    win_1 = compute_curation_window(
        curation_anchor_date="2026-11-10",
        curation_timezone="America/Sao_Paulo",
        tzdb_version="2026a",
        restatement_lookback_days=1,
    )
    assert win_1 == DateRange("2026-11-10", "2026-11-10", True)

    win_7 = compute_curation_window(
        curation_anchor_date="2026-03-03",
        curation_timezone="America/Sao_Paulo",
        tzdb_version="2026a",
        restatement_lookback_days=7,
    )
    assert win_7 == DateRange("2026-02-25", "2026-03-03", True)

    for bad_kwargs in (
        {"curation_anchor_date": "2026-11-10", "curation_timezone": "UTC", "tzdb_version": "2026a", "restatement_lookback_days": 1},
        {"curation_anchor_date": "2026-11-10", "curation_timezone": "America/Sao_Paulo", "tzdb_version": "  ", "restatement_lookback_days": 1},
        {"curation_anchor_date": "2026-11-10", "curation_timezone": "America/Sao_Paulo", "tzdb_version": "2026a", "restatement_lookback_days": 0},
        {"curation_anchor_date": "2026-11-10", "curation_timezone": "America/Sao_Paulo", "tzdb_version": "2026a", "restatement_lookback_days": True},
    ):
        with pytest.raises(ClosedValidationError):
            compute_curation_window(**bad_kwargs)  # type: ignore[arg-type]


def test_curation_execution_genesis_vs_incremental_invariants() -> None:
    run_loc, cand_loc = _loc("smart_ads/migration_run_context/v1", "1"), _loc("smart_ads/sanitized_candidate_fact_set/v1", "2")
    cat_loc, gen_rec_loc = _loc("smart_ads/dataset_catalog/v1", "3"), _loc("smart_ads/dataset_catalog_genesis_record/v1", "4")
    snap_loc, cut_loc = _loc("smart_ads/dataset_snapshot/v1", "5"), _loc("smart_ads/dataset_catalog_cut_receipt/v1", "6")
    hist_loc = _loc("smart_ads/generation_manifest/v1", "7")
    alg_id, win = _make_algorithm_id("smart_ads/curation_execution/v1"), DateRange("2026-11-08", "2026-11-10", True)

    gen_exec = CurationExecution(
        run_loc, "curation:gen-1", "genesis", "2026-11-10", "America/Sao_Paulo", "2026a", 3, win,
        cand_loc, alg_id, gen_rec_loc, cat_loc, None, None, (), "2026-11-11T03:05:00Z",
    )
    assert CurationExecution.from_dict(gen_exec.to_dict()) == gen_exec
    inc_exec = CurationExecution(
        run_loc, "curation:inc-1", "incremental", "2026-11-10", "America/Sao_Paulo", "2026a", 3, win,
        cand_loc, alg_id, None, cat_loc, snap_loc, cut_loc, (hist_loc,), "2026-11-11T03:06:00Z",
    )
    assert CurationExecution.from_dict(inc_exec.to_dict()) == inc_exec
    with pytest.raises(ClosedValidationError):
        CurationExecution.from_dict({**gen_exec.to_dict(), "historical_generation_manifest_locators": [hist_loc.to_dict()]})
    with pytest.raises(ClosedValidationError):
        CurationExecution.from_dict({**inc_exec.to_dict(), "dataset_catalog_genesis_record_locator": gen_rec_loc.to_dict()})


@pytest.fixture
def sample_cut_epoch1_dict() -> dict[str, object]:
    run_loc = _loc("smart_ads/migration_run_context/v1", "1")
    old_cat = _loc("smart_ads/dataset_catalog/v1", "2")
    new_cat = _loc("smart_ads/dataset_catalog/v1", "3")
    gen_man = _loc("smart_ads/generation_manifest/v1", "4")
    receipt = DatasetCatalogCutReceipt(
        cut_id="cut:epoch-1-to-2",
        cell_ref="cell:ibvi-primary",
        migration_run_context_locator=run_loc,
        old_catalog_locator=old_cat,
        old_catalog_digest=old_cat.content_digest,
        old_catalog_epoch=1,
        new_catalog_locator=new_cat,
        new_catalog_digest=new_cat.content_digest,
        new_catalog_epoch=2,
        cas_request_projection=CatalogCasRequestProjection(
            operation="replace_partition",
            expected_old_catalog_epoch=1,
            expected_old_catalog_digest=old_cat.content_digest,
            partition_key="year=2026/month=11",
            target_head_sequence_number=2,
            generation_manifest_locator=gen_man,
        ),
        cas_linearization_id="lin:cat-002",
        committed_at_utc="2026-11-12T03:07:00Z",
        integrity=_unsigned_p1(),
    )
    return receipt.to_dict()


def test_cut_receipt_forbids_genesis_fields_after_epoch_zero(
    sample_cut_epoch1_dict: dict[str, object],
) -> None:
    parsed = DatasetCatalogCutReceipt.from_dict(sample_cut_epoch1_dict)
    assert "genesis_record_locator" not in parsed.to_dict()
    tampered = {**sample_cut_epoch1_dict, "genesis_record_locator": None}
    with pytest.raises(ClosedValidationError):
        DatasetCatalogCutReceipt.from_dict(tampered)


def test_catalog_parquet_digests_active_head_and_snapshot_self_digest() -> None:
    pq_b = ParquetObjectLocator("year=2026/month=11", "sha256:" + ("b" * 64), 256)
    pq_a = ParquetObjectLocator("year=2026/month=11", "sha256:" + ("a" * 64), 128)
    sorted_pq, pq_set_digest = compute_physical_parquet_set_digest([pq_b, pq_a])
    assert sorted_pq == (pq_a, pq_b)
    assert pq_set_digest == domain_jcs_sha256(
        ADR_DATA_DOMAIN_PREFIXES["parquet_object_set"], [pq_a.to_dict(), pq_b.to_dict()]
    )

    row_clicks = _make_landing_row(metric_semantic_ref="metric:clicks_v1", source_metric_ref="source-metric:provider:pipeboard.clicks:v1")
    row_impr = _make_landing_row(metric_semantic_ref="metric:impressions_v1", source_metric_ref="source-metric:provider:pipeboard.impressions:v1")
    sorted_rows, logical_digest = compute_logical_rows_digest([row_impr, row_clicks])
    assert sorted_rows == (row_clicks, row_impr)
    assert logical_digest == domain_jcs_sha256(
        ADR_DATA_DOMAIN_PREFIXES["logical_rows"], [row_clicks.to_dict(), row_impr.to_dict()]
    )
    with pytest.raises(ClosedValidationError):
        compute_logical_rows_digest([row_clicks, row_clicks])

    head = ActivePartitionHead("year=2026/month=11", 1, _loc("smart_ads/generation_manifest/v1", "4"))
    assert set(head.to_dict()) == {"partition_key", "head_sequence_number", "generation_manifest_locator"}
    assert "$schema" not in head.to_dict()

    snap = DatasetSnapshot(
        snapshot_id="snapshot:snap-001",
        catalog_epoch=1,
        dataset_catalog_locator=_loc("smart_ads/dataset_catalog/v1", "5"),
        catalog_cut_receipt_locator=_loc("smart_ads/dataset_catalog_cut_receipt/v1", "6"),
        created_at="2026-11-11T03:08:00Z",
        partition_heads=(head,),
        integrity=_unsigned_p1(),
    )
    expected_self = self_digest_jcs_sha256(
        snap.to_dict(), digest_member="snapshot_digest", domain_prefix=None, strip_integrity=True
    )
    assert snap.snapshot_digest == expected_self
    signed_snap = DatasetSnapshot.from_dict(_sign_dict(snap.to_dict()), require_signed=True)
    assert signed_snap.snapshot_digest == snap.snapshot_digest
    with pytest.raises(ClosedValidationError):
        DatasetSnapshot.from_dict({**snap.to_dict(), "snapshot_digest": "sha256:" + ("0" * 64)})


def test_contracts_and_domain_package_reexports_sorted_and_complete() -> None:
    assert contracts_pkg.__all__ == sorted(contracts_pkg.__all__, key=lambda s: s.encode("utf-8"))
    assert domain_pkg.__all__ == sorted(domain_pkg.__all__, key=lambda s: s.encode("utf-8"))
    for sym in (
        "AuthorizationReceipt",
        "EffectProof",
        "OperationalReadEvidence",
        "SanitizedCandidateFactSet",
        "RetentionRoot",
        "RetentionReleaseProof",
        "verify_four_record_effect_proof",
    ):
        assert sym in contracts_pkg.__all__ and hasattr(contracts_pkg, sym)
    for sym in (
        "ActivePartitionHead",
        "CurationExecution",
        "DatasetCatalog",
        "DatasetCatalogCutReceipt",
        "DatasetSnapshot",
        "GenerationManifest",
        "ParquetObjectLocator",
        "compute_curation_window",
        "partition_key_for_metric_date",
    ):
        assert sym in domain_pkg.__all__ and hasattr(domain_pkg, sym)
