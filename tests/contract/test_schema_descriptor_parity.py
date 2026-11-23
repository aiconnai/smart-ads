"""Parity of the PR 2 core schema descriptors with the implemented types, and package re-exports.

`CORE_SCHEMA_DESCRIPTORS` in `smart_ads.contracts.schemas` is literal data (that module cannot
import `smart_ads.analytics` or `smart_ads.reconciliation`, which import it). These tests pin each
descriptor to the key set the implemented type actually serializes, following the rule of the
existing descriptors: `fields` is the complete `to_dict()` key set, including `$schema` when the
type emits it and `integrity` for P1 artifacts (ADR-0001 section 12.7), while embedded value
objects carry no `integrity` and no P1 domain prefix.
"""
from __future__ import annotations

import __future__
import ast
import dataclasses
import importlib
import os
from pathlib import Path
import subprocess
import sys
import types
from typing import Any

import pytest

import smart_ads
from smart_ads.analytics import cells, certification, formulas, intelligence, lattice, policy, replay_bundle, reporting, results
from smart_ads.contracts import consumer, effects, git_provenance, negative_security, operational_evidence, retention, seam
from smart_ads.contracts.jcs import ADR_P1_DOMAIN_PREFIXES, ArtifactLocator, P1Integrity, p1_content_digest
from smart_ads.contracts.numerics import PHASE1_BASE_METRICS
from smart_ads.contracts.scalars import ClosedValidationError
from smart_ads.contracts.schemas import CORE_SCHEMA_DESCRIPTORS, AnalyticsLandingRow, DateRange, FactKey
import smart_ads.contracts.schemas as schemas_module
from smart_ads.domain import catalog, curation
from smart_ads.reconciliation import bundle_7b, tolerance
import smart_ads.reconciliation.certification_7a as certification_7a
from tests.unit._bundle_7b_builders import CLICKS, native_dict, profile_dict
from tests.unit._bundle_7b_world import build_world
from tests.unit.test_certification_7a_record import build_valid_7a_world

REPO_ROOT = Path(__file__).resolve().parents[2]

P1_SCHEMA_TYPES: dict[str, type] = {
    "smart_ads/formula_bundle/v1": formulas.FormulaBundle,
    "smart_ads/analysis_result_schema/v1": cells.AnalysisResultSchema,
    "smart_ads/analysis_result/v1": results.AnalysisResult,
    "smart_ads/analysis_execution/v1": results.AnalysisExecution,
    "smart_ads/analysis_policy/v1": policy.AnalysisPolicy,
    "smart_ads/finding/v1": intelligence.Finding,
    "smart_ads/certification_record/v1": certification.AnalyticalCertificationRecord,
    "smart_ads/tolerance_profile/v1": tolerance.ToleranceProfile,
    "smart_ads/native_request_projection/v1": bundle_7b.NativeRequestProjection,
    "smart_ads/certification_7b_record/v1": bundle_7b.Certification7BRecord,
    "smart_ads/git_artifact_provenance/v1": git_provenance.GitArtifactProvenance,
    "smart_ads/negative_security_test_report/v1": negative_security.NegativeSecurityTestReport,
    "smart_ads/certification_7a_record/v1": certification_7a.Certification7ARecord,
    "smart_ads/authorization_receipt/v1": effects.AuthorizationReceipt,
    "smart_ads/authorization_reservation_record/v1": effects.AuthorizationReservationRecord,
    "smart_ads/execution_receipt/v1": effects.ExecutionReceipt,
    "smart_ads/authorization_consumption_record/v1": effects.AuthorizationConsumptionRecord,
    "smart_ads/effect_proof/v1": effects.EffectProof,
    "smart_ads/operational_read_evidence/v1": operational_evidence.OperationalReadEvidence,
    "smart_ads/sanitized_candidate_fact_set/v1": operational_evidence.SanitizedCandidateFactSet,
    "smart_ads/retention_root/v1": retention.RetentionRoot,
    "smart_ads/retention_root_set_head/v1": retention.RetentionRootSetHead,
    "smart_ads/retention_root_set_cas_receipt/v1": retention.RetentionRootSetCasReceipt,
    "smart_ads/retention_root_admission_result/v1": retention.RetentionRootAdmissionResult,
    "smart_ads/retention_root_admission_proof/v1": retention.RetentionRootAdmissionProof,
    "smart_ads/retention_release_result/v1": retention.RetentionReleaseResult,
    "smart_ads/retention_release_proof/v1": retention.RetentionReleaseProof,
    "smart_ads/curation_execution/v1": curation.CurationExecution,
    "smart_ads/generation_manifest/v1": catalog.GenerationManifest,
    "smart_ads/dataset_catalog_genesis_record/v1": catalog.DatasetCatalogGenesisRecord,
    "smart_ads/dataset_catalog_genesis_consumption_record/v1": catalog.DatasetCatalogGenesisConsumptionRecord,
    "smart_ads/dataset_catalog/v1": catalog.DatasetCatalog,
    "smart_ads/dataset_catalog_cut_receipt/v1": catalog.DatasetCatalogCutReceipt,
    "smart_ads/dataset_snapshot/v1": catalog.DatasetSnapshot,
    "smart_ads/analysis_replay_input_bundle/v1": replay_bundle.AnalysisReplayInputBundle,
    "smart_ads/report_execution/v1": reporting.ReportExecution,
    "smart_ads/legacy_seam_contract/v1": seam.LegacySeamContract,
    "smart_ads/legacy_seam_release/v1": seam.LegacySeamRelease,
    "smart_ads/seam_parity_record/v1": seam.SeamParityRecord,
    "smart_ads/ibvi_ads_delegation_context/v1": consumer.IbviAdsDelegationContext,
    "smart_ads/ibvi_ads_delegation_contract/v1": consumer.IbviAdsDelegationContract,
    "smart_ads/consumer_feature_flag_contract/v1": consumer.ConsumerFeatureFlagContract,
    "smart_ads/consumer_deployment_readback/v1": consumer.ConsumerDeploymentReadback,
}
EMBEDDED_SCHEMA_TYPES: dict[str, type] = {
    "smart_ads/regression_fixture/v1": lattice.RegressionFixtureV1,
    "smart_ads/derived_metric_definition/v1": formulas.DerivedMetricDefinition,
    "smart_ads/canonical_result_set/v1": results.CanonicalResultSet,
    "smart_ads/fact_evidence_selector/v1": bundle_7b.FactEvidenceSelector,
    "smart_ads/fact_reconciliation/v1": bundle_7b.FactReconciliation,
    "smart_ads/parquet_object_locator/v1": catalog.ParquetObjectLocator,
    "smart_ads/active_partition_head/v1": catalog.ActivePartitionHead,
    "smart_ads/duckdb_binary_object_locator/v1": replay_bundle.DuckDbBinaryObjectLocator,
    "smart_ads/duckdb_extension_binary_locator/v1": replay_bundle.DuckDbExtensionBinaryLocator,
    "smart_ads/wheel_object_locator/v1": seam.WheelObjectLocator,
}
PR2_SCHEMA_TYPES: dict[str, type] = {**P1_SCHEMA_TYPES, **EMBEDDED_SCHEMA_TYPES}
# Embedded value objects of ADR section 5.4 L1133-1146 and section 6.3 L1788-1799 carry no `$schema` member on the wire.
SCHEMALESS_EMBEDDED = frozenset(
    {
        "smart_ads/fact_evidence_selector/v1",
        "smart_ads/fact_reconciliation/v1",
        "smart_ads/active_partition_head/v1",
    }
)

# Module-level schema id constants that must agree with the class constant and the descriptor.
SCHEMA_ID_CONSTANTS: tuple[tuple[str, str], ...] = (
    (cells.ANALYSIS_RESULT_SCHEMA_TYPE, "smart_ads/analysis_result_schema/v1"),
    (cells.ANALYSIS_RESULT_TYPE, "smart_ads/analysis_result/v1"),
    (cells.ANALYSIS_EXECUTION_TYPE, "smart_ads/analysis_execution/v1"),
    (cells.CANONICAL_RESULT_SET_TYPE, "smart_ads/canonical_result_set/v1"),
    (cells.REPLAY_BUNDLE_TYPE, "smart_ads/analysis_replay_input_bundle/v1"),
    (replay_bundle.DUCKDB_BINARY_LOCATOR_SCHEMA, "smart_ads/duckdb_binary_object_locator/v1"),
    (replay_bundle.DUCKDB_EXT_BINARY_LOCATOR_SCHEMA, "smart_ads/duckdb_extension_binary_locator/v1"),
    (reporting.REPORT_EXECUTION_SCHEMA, "smart_ads/report_execution/v1"),
    (intelligence.FINDING_SCHEMA, "smart_ads/finding/v1"),
    (certification.CERTIFICATION_RECORD_SCHEMA, "smart_ads/certification_record/v1"),
    (bundle_7b.FACT_EVIDENCE_SELECTOR_SCHEMA, "smart_ads/fact_evidence_selector/v1"),
    (bundle_7b.FACT_RECONCILIATION_SCHEMA, "smart_ads/fact_reconciliation/v1"),
    (bundle_7b.NATIVE_REQUEST_PROJECTION_SCHEMA, "smart_ads/native_request_projection/v1"),
    (bundle_7b.CERTIFICATION_7B_RECORD_SCHEMA, "smart_ads/certification_7b_record/v1"),
    (certification_7a.CERTIFICATION_7A_RECORD_SCHEMA, "smart_ads/certification_7a_record/v1"),
)

PRE_PR2_SCHEMA_IDS = frozenset(
    {
        "smart_ads/admitted_collection/v1",
        "smart_ads/analytics_landing_row/v1",
        "smart_ads/artifact_locator/v1",
        "smart_ads/base_metric_definition/v1",
        "smart_ads/canonical_query_contract/v1",
        "smart_ads/capability_invalidation_transition/v1",
        "smart_ads/capability_revalidation_transition/v1",
        "smart_ads/collection_result/v1",
        "smart_ads/expected_resource_inventory/v1",
        "smart_ads/normalized_collection_fact/v1",
        "smart_ads/pipeboard_phase1_contract/v1",
        "smart_ads/private_registry_snapshot/v1",
        "smart_ads/semantic_observation_projection/v1",
    }
)

PACKAGE_SUBMODULES: dict[str, tuple[str, ...]] = {
    "smart_ads.analytics": (
        "cells",
        "certification",
        "formulas",
        "intelligence",
        "lattice",
        "policy",
        "replay_bundle",
        "reporting",
        "results",
    ),
    # The 7A/7B public facades and tolerance, never the internal bundle_* modules.
    "smart_ads.reconciliation": ("bundle_7b", "certification_7a", "tolerance"),
}
# Names two submodules export as different objects; not re-exported at package level.
WITHHELD_AMBIGUOUS: dict[str, frozenset[str]] = {
    "smart_ads.analytics": frozenset({"RESTATEMENT_KINDS"}),
    "smart_ads.reconciliation": frozenset(),
}


def _utf8_sorted(values: Any) -> list[str]:
    return sorted(values, key=lambda s: s.encode("utf-8"))


def _by_id() -> dict[str, Any]:
    return {d["schema_id"]: d for d in CORE_SCHEMA_DESCRIPTORS}


# ---------------------------------------------------------------- real instances


def _loc(artifact_type: str, fill: str) -> ArtifactLocator:
    return ArtifactLocator.from_digest(artifact_type, "sha256:" + (fill * 64))


UNSIGNED = P1Integrity(
    key_id="key:ed25519:" + ("a" * 64),
    key_registry_snapshot_locator=_loc("smart_ads/key_authorization_registry/v1", "9"),
)
WASTE_RULE = {
    "rule_id": "rule:waste",
    "rule_type": "waste",
    "window_days": 3,
    "spend_metric_ref": "metric:spend_v1",
    "outcome_metric_ref": "metric:clicks_v1",
    "min_spend_minor": "1000",
    "max_outcome_count": "0",
}


def _analysis_instances() -> dict[str, Any]:
    column = cells.ResultColumn("value", "int64", False)
    schema = cells.AnalysisResultSchema("scalar", (column,), None, UNSIGNED)
    projection = cells.ResultProjection(
        "scalar", schema.locator(), (column,), ((cells.TaggedScalarCell("int64", "7"),),), 1
    )
    bundle_loc = _loc(cells.REPLAY_BUNDLE_TYPE, "3")
    result = results.AnalysisResult(
        migration_run_context_locator=_loc(cells.RUN_CONTEXT_TYPE, "1"),
        dataset_snapshot_locator=_loc(cells.DATASET_SNAPSHOT_TYPE, "2"),
        replay_input_bundle_locator=bundle_loc,
        result_key="result:spend",
        result_projection=projection,
        integrity=UNSIGNED,
    )
    result_set = results.CanonicalResultSet.build(
        bundle_loc, (results.CanonicalResultEntry.from_result(result),)
    )
    execution = results.AnalysisExecution(bundle_loc, result_set, UNSIGNED)
    finding = intelligence.Finding(
        analysis_execution_locator=execution.locator(),
        result_locator=result.locator(),
        result_key="result:spend",
        finding_key="finding:sha256:" + ("4" * 64),
        finding_type="waste",
        finding_status="detected",
        mutation_recommendation_blocked=False,
        evidence_locators=(result.locator(),),
        analysis_policy_locator=_loc("smart_ads/analysis_policy/v1", "5"),
        integrity=UNSIGNED,
    )
    record = certification.AnalyticalCertificationRecord(
        finding_locators=(finding.locator(),),
        derived_certification_status=formulas.DerivedCertificationStatus.VERIFIED,
        mutation_recommendations_blocked=False,
        output_digest=result_set.canonical_result_digest,
        integrity=UNSIGNED,
    )
    return {
        "smart_ads/analysis_result_schema/v1": schema,
        "smart_ads/analysis_result/v1": result,
        "smart_ads/canonical_result_set/v1": result_set,
        "smart_ads/analysis_execution/v1": execution,
        "smart_ads/finding/v1": finding,
        "smart_ads/certification_record/v1": record,
    }


def _formula_and_policy_instances() -> dict[str, Any]:
    formula_ast = formulas.FormulaAst(
        "DIVIDE_MONEY_BY_COUNT",
        "metric:spend_v1",
        "metric:clicks_v1",
        "int64_minor_currency",
        "ROUND_HALF_UP",
    )
    definition = formulas.DerivedMetricDefinition("metric:derived_cpc_v1", formula_ast)
    bundle = formulas.FormulaBundle(
        base_metrics=(
            PHASE1_BASE_METRICS["metric:clicks_v1"],
            PHASE1_BASE_METRICS["metric:spend_v1"],
        ),
        definitions=(definition,),
        integrity=UNSIGNED,
    )
    analysis_policy = policy.AnalysisPolicy.from_dict(
        {
            "$schema": "smart_ads/analysis_policy/v1",
            "policy_id": "policy:p1",
            "policy_version": "1",
            "tenant_ref": "tenant:t1",
            "applicability_scope": {
                "resource_scope_ref": "scope:s1",
                "resource_level": "campaign",
                "ad_platform_ref": "meta",
                "currency": "BRL",
            },
            "validity": {
                "valid_from_utc": "2026-01-01T00:00:00.000000Z",
                "valid_until_utc": "2027-01-01T00:00:00.000000Z",
            },
            "rules": [dict(WASTE_RULE)],
            "integrity": UNSIGNED.to_dict(),
        }
    )
    return {
        "smart_ads/regression_fixture/v1": lattice.RegressionFixtureV1.canonical(
            "sha256:" + ("6" * 64)
        ),
        "smart_ads/derived_metric_definition/v1": definition,
        "smart_ads/formula_bundle/v1": bundle,
        "smart_ads/analysis_policy/v1": analysis_policy,
    }


def _reconciliation_instances() -> dict[str, Any]:
    record = dataclasses.replace(build_world().parsed(), integrity=UNSIGNED)
    reconciliation = record.fact_reconciliations[0]
    return {
        # A non-zero profile, so `authorization_binding` is an object rather than null.
        "smart_ads/tolerance_profile/v1": tolerance.ToleranceProfile.from_dict(
            profile_dict(CLICKS, max_abs="5", max_rel="0.050000")
        ),
        "smart_ads/native_request_projection/v1": bundle_7b.NativeRequestProjection.from_dict(
            {**native_dict(), "integrity": UNSIGNED.to_dict()}
        ),
        "smart_ads/fact_evidence_selector/v1": reconciliation.candidate.fact_evidence_selector,
        "smart_ads/fact_reconciliation/v1": reconciliation,
        "smart_ads/certification_7b_record/v1": record,
    }


def _pr3_7a_instances() -> dict[str, Any]:
    world_7a = build_valid_7a_world()
    git_prov = git_provenance.GitArtifactProvenance(
        repository="aiconnai/smart-ads",
        commit_sha="a" * 40,
        path="src/smart_ads/reconciliation/certification_7a.py",
        git_blob_oid="b" * 40,
        file_content_sha256="sha256:" + ("c" * 64),
        resolved_at_utc="2026-09-07T10:00:00Z",
        integrity=UNSIGNED,
    )
    neg_rep = dataclasses.replace(world_7a.negative_report, integrity=UNSIGNED)
    cert_rec = dataclasses.replace(world_7a.record, integrity=UNSIGNED)
    return {
        "smart_ads/git_artifact_provenance/v1": git_prov,
        "smart_ads/negative_security_test_report/v1": neg_rep,
        "smart_ads/certification_7a_record/v1": cert_rec,
    }


def _pr4_effect_and_evidence_instances() -> tuple[dict[str, Any], Any, Any]:
    run_loc, adm_loc = _loc("smart_ads/migration_run_context/v1", "1"), _loc("smart_ads/admitted_collection/v1", "2")
    reg_loc, inv_loc = _loc("smart_ads/private_registry_snapshot/v1", "3"), _loc("smart_ads/expected_resource_inventory/v1", "4")
    res_loc, prov_loc = _loc("smart_ads/collection_result/v1", "5"), _loc("smart_ads/git_artifact_provenance/v1", "6")
    subj = effects.ProviderCallTarget(run_loc, adm_loc, "operational", "provider-target:pipeboard-hosted", "sha256:" + ("7" * 64), reg_loc, "tenant:ibvi", "binding:meta-primary", "account:ibvi-01", "scope:campaigns-active", _loc("smart_ads/ibvi_ads_delegation_context/v1", "8"))
    auth = effects.AuthorizationReceipt("auth:op-001", run_loc, "provider_operational_read", "operational_provider_read_effect_proof", subj, "sha256:" + ("a" * 64), (adm_loc,), "principal:operator-01", "2026-11-11T03:00:00Z", "2026-11-11T04:00:00Z", "nonce-op-001", UNSIGNED)
    auth_loc = auth.locator()
    resv = effects.AuthorizationReservationRecord("resv:op-001", run_loc, auth_loc, auth_loc.content_digest, "nonce-op-001", "provider_operational_read", "operational_provider_read_effect_proof", subj, "consumed", None, "2026-11-11T03:01:00Z", UNSIGNED)
    exec_rec = effects.ExecutionReceipt("exec:op-001", run_loc, auth_loc, resv.locator(), "nonce-op-001", "provider_operational_read", "operational_provider_read_effect_proof", subj, "succeeded", res_loc, "2026-11-11T03:02:00Z", UNSIGNED)
    cons = effects.AuthorizationConsumptionRecord("cons:op-001", run_loc, auth_loc, auth_loc.content_digest, resv.locator(), exec_rec.locator(), "nonce-op-001", "provider_operational_read", "operational_provider_read_effect_proof", "consumed", "2026-11-11T03:03:00Z", UNSIGNED)
    eff_proof = effects.EffectProof("proof:op-001", run_loc, "provider_operational_read", "operational_provider_read_effect_proof", auth_loc, resv.locator(), exec_rec.locator(), cons.locator(), res_loc, "2026-11-11T03:04:00Z", UNSIGNED)
    op_ev = operational_evidence.OperationalReadEvidence(run_loc, "tenant:ibvi", "binding:meta-primary", "account:ibvi-01", "scope:campaigns-active", "sha256:" + ("7" * 64), reg_loc, reg_loc.content_digest, inv_loc, adm_loc, adm_loc.content_digest, res_loc, res_loc.content_digest, "sha256:" + ("b" * 64), auth_loc, resv.locator(), exec_rec.locator(), cons.locator(), eff_proof.locator(), UNSIGNED)
    alg_id = operational_evidence.AlgorithmProvenanceIdentity("algorithm:sanitizer-v1", "1.0.0", prov_loc, "aiconnai/smart-ads", "a" * 40, "src/smart_ads/application/curation_pipeline.py", "b" * 40, "sha256:" + ("c" * 64), "cpython-3.12", "smart_ads/sanitized_candidate_fact_set/v1")
    row = AnalyticsLandingRow(FactKey("binding:meta-primary", "account:ibvi-01", "resource:" + ("a" * 52), "campaign", "2026-11-10", "metric:clicks_v1", "source-metric:provider:pipeboard.clicks:v1", "attribution:not_applicable", "breakdown:none"), "int64_count", "10", "count", None, "provider_observation", "observed", None, "not_applicable", "2026-11-11T03:02:00.000000Z", "observation:obs-001", "pipeboard-0.1.0", "1.0.0")
    cand_set = operational_evidence.SanitizedCandidateFactSet(run_loc, alg_id, (res_loc,), (op_ev.locator(),), (row,), integrity=UNSIGNED)
    out = {
        "smart_ads/authorization_receipt/v1": auth,
        "smart_ads/authorization_reservation_record/v1": resv,
        "smart_ads/execution_receipt/v1": exec_rec,
        "smart_ads/authorization_consumption_record/v1": cons,
        "smart_ads/effect_proof/v1": eff_proof,
        "smart_ads/operational_read_evidence/v1": op_ev,
        "smart_ads/sanitized_candidate_fact_set/v1": cand_set,
    }
    return out, alg_id, row


def _pr4_curation_and_catalog_instances(eff_ev: dict[str, Any], alg_id: Any, row: Any) -> tuple[dict[str, Any], Any]:
    run_loc, reg_loc = _loc("smart_ads/migration_run_context/v1", "1"), _loc("smart_ads/private_registry_snapshot/v1", "3")
    op_ev_loc = eff_ev["smart_ads/operational_read_evidence/v1"].locator()
    cand_loc = eff_ev["smart_ads/sanitized_candidate_fact_set/v1"].locator()
    epoch0_cat = catalog.DatasetCatalog("catalog:cell-0", "cell:ibvi-primary", 0, "2026-11-11T03:00:00Z", (), UNSIGNED)
    gen_rec = catalog.DatasetCatalogGenesisRecord("genesis:cell-0", "cell:ibvi-primary", run_loc, epoch0_cat.locator(), epoch0_cat.locator().content_digest, "principal:bootstrap-authority", "2026-11-11T03:00:00Z", UNSIGNED)
    cur_exec = curation.CurationExecution(run_loc, "curation:cur-001", "genesis", "2026-11-10", "America/Sao_Paulo", "2026a", 1, DateRange("2026-11-10", "2026-11-10", True), cand_loc, dataclasses.replace(alg_id, schema_id=curation.CurationExecution.SCHEMA), gen_rec.locator(), epoch0_cat.locator(), None, None, (), "2026-11-11T03:05:00Z", UNSIGNED)
    pq_loc = catalog.ParquetObjectLocator("year=2026/month=11", "sha256:" + ("d" * 64), 512)
    _, logical_digest = catalog.compute_logical_rows_digest((row,))
    gen_man = catalog.GenerationManifest(run_loc, "generation:gen-001", "year=2026/month=11", None, "2026-11-11T03:06:00Z", 1, logical_digest, reg_loc, cur_exec.locator(), epoch0_cat.locator(), (op_ev_loc,), (pq_loc,), integrity=UNSIGNED)
    part_head = catalog.ActivePartitionHead("year=2026/month=11", 1, gen_man.locator())
    epoch1_cat = catalog.DatasetCatalog("catalog:cell-1", "cell:ibvi-primary", 1, "2026-11-11T03:07:00Z", (part_head,), UNSIGNED)
    gen_cons = catalog.DatasetCatalogGenesisConsumptionRecord(gen_rec.locator(), gen_rec.locator().content_digest, epoch0_cat.locator(), epoch0_cat.locator().content_digest, epoch1_cat.locator(), epoch1_cat.locator().content_digest, "cut:cut-001", "lin:cat-001", "2026-11-11T03:07:00Z", UNSIGNED)
    cas_proj = catalog.CatalogCasRequestProjection("add_partition", 0, epoch0_cat.locator().content_digest, "year=2026/month=11", 1, gen_man.locator())
    cut_rec = catalog.DatasetCatalogCutReceipt("cut:cut-001", "cell:ibvi-primary", run_loc, epoch0_cat.locator(), epoch0_cat.locator().content_digest, 0, epoch1_cat.locator(), epoch1_cat.locator().content_digest, 1, cas_proj, "lin:cat-001", "2026-11-11T03:07:00Z", gen_rec.locator(), gen_rec.locator().content_digest, gen_cons.locator(), gen_cons.locator().content_digest, UNSIGNED)
    ds_snap = catalog.DatasetSnapshot("snapshot:snap-001", 1, epoch1_cat.locator(), cut_rec.locator(), "2026-11-11T03:08:00Z", (part_head,), integrity=UNSIGNED)
    out = {
        "smart_ads/curation_execution/v1": cur_exec,
        "smart_ads/parquet_object_locator/v1": pq_loc,
        "smart_ads/generation_manifest/v1": gen_man,
        "smart_ads/active_partition_head/v1": part_head,
        "smart_ads/dataset_catalog_genesis_record/v1": gen_rec,
        "smart_ads/dataset_catalog_genesis_consumption_record/v1": gen_cons,
        "smart_ads/dataset_catalog/v1": epoch1_cat,
        "smart_ads/dataset_catalog_cut_receipt/v1": cut_rec,
        "smart_ads/dataset_snapshot/v1": ds_snap,
    }
    return out, ds_snap


def _pr4_retention_instances(ds_snap: Any) -> dict[str, Any]:
    run_loc = _loc("smart_ads/migration_run_context/v1", "1")
    snap_ref = ds_snap.locator().object_ref
    ret_root = retention.RetentionRoot("root:snap-001", "cell:ibvi-primary", run_loc, ds_snap.locator(), (snap_ref,), "2026-11-11T03:09:00Z", integrity=UNSIGNED)
    head0 = retention.RetentionRootSetHead("head:ret-0", "cell:ibvi-primary", 0, (), None, "2026-11-11T03:00:00Z", integrity=UNSIGNED)
    head1 = retention.RetentionRootSetHead("head:ret-1", "cell:ibvi-primary", 1, (ret_root.locator(),), head0.locator(), "2026-11-11T03:10:00Z", integrity=UNSIGNED)
    head2 = retention.RetentionRootSetHead("head:ret-2", "cell:ibvi-primary", 2, (), head1.locator(), "2026-11-11T03:12:00Z", integrity=UNSIGNED)
    adm_proj = retention.RetentionRootSetCasRequestProjection("admit_roots", 0, head0.locator().content_digest, (ret_root.locator(),), head1.root_set_digest)
    ret_cas = retention.RetentionRootSetCasReceipt("cas:ret-001", "cell:ibvi-primary", "admit_roots", adm_proj, head0.locator(), head0.locator().content_digest, 0, head1.locator(), head1.locator().content_digest, 1, "committed", "lin:ret-001", "2026-11-11T03:10:00Z", UNSIGNED)
    adm_res = retention.RetentionRootAdmissionResult(run_loc, "cell:ibvi-primary", ret_cas.locator(), ret_cas.locator().content_digest, "lin:ret-001", head0.locator(), head0.locator().content_digest, head1.locator(), head1.locator().content_digest, (ret_root.locator(),), (snap_ref,), "admitted", "2026-11-11T03:10:00Z", UNSIGNED)
    adm_proof = retention.RetentionRootAdmissionProof(run_loc, "cell:ibvi-primary", _loc("smart_ads/effect_proof/v1", "e"), adm_res.locator(), ret_cas.locator(), head0.locator(), head1.locator(), (ret_root.locator(),), (snap_ref,), "sha256:" + ("0" * 64), "sha256:" + ("1" * 64), "2026-11-11T03:11:00Z", UNSIGNED)
    rel_proj = retention.RetentionRootSetCasRequestProjection("release_roots", 1, head1.locator().content_digest, (ret_root.locator(),), head2.root_set_digest)
    rel_cas = retention.RetentionRootSetCasReceipt("cas:ret-002", "cell:ibvi-primary", "release_roots", rel_proj, head1.locator(), head1.locator().content_digest, 1, head2.locator(), head2.locator().content_digest, 2, "committed", "lin:ret-002", "2026-11-11T03:12:00Z", UNSIGNED)
    rel_res = retention.RetentionReleaseResult(run_loc, "cell:ibvi-primary", rel_cas.locator(), rel_cas.locator().content_digest, "lin:ret-002", head1.locator(), head1.locator().content_digest, head2.locator(), head2.locator().content_digest, (ret_root.locator(),), (snap_ref,), "logically_unpinned", "2026-11-11T03:12:00Z", UNSIGNED)
    rel_proof = retention.RetentionReleaseProof(run_loc, "cell:ibvi-primary", _loc("smart_ads/effect_proof/v1", "f"), rel_res.locator(), rel_cas.locator(), head1.locator(), head2.locator(), (ret_root.locator(),), (), (snap_ref,), (), "sha256:" + ("1" * 64), "sha256:" + ("0" * 64), True, "2026-11-11T03:13:00Z", UNSIGNED)
    return {
        "smart_ads/retention_root/v1": ret_root,
        "smart_ads/retention_root_set_head/v1": head1,
        "smart_ads/retention_root_set_cas_receipt/v1": ret_cas,
        "smart_ads/retention_root_admission_result/v1": adm_res,
        "smart_ads/retention_root_admission_proof/v1": adm_proof,
        "smart_ads/retention_release_result/v1": rel_res,
        "smart_ads/retention_release_proof/v1": rel_proof,
    }


def _pr4_replay_and_report_instances(
    eff_ev: dict[str, Any], cur_cat: dict[str, Any], ds_snap: Any, alg_id: Any
) -> dict[str, Any]:
    run_loc = _loc("smart_ads/migration_run_context/v1", "1")
    pol_loc, inv_loc = _loc("smart_ads/analysis_policy/v1", "5"), _loc("smart_ads/expected_resource_inventory/v1", "4")
    prov_loc = _loc("smart_ads/git_artifact_provenance/v1", "6")
    db_bin = replay_bundle.DuckDbBinaryObjectLocator("sha256:" + ("7" * 64), 4096)
    ext_bin = replay_bundle.DuckDbExtensionBinaryLocator("sha256:" + ("8" * 64), 2048)
    col = cells.ResultColumn("total_spend", "int64", False)
    r_schema = cells.AnalysisResultSchema("scalar", (col,), None, UNSIGNED)
    q_def = replay_bundle.DuckDbQueryDefinition("result:spend", "query:q1", "SELECT 7 AS total_spend", r_schema.locator(), "scalar", (col,), None, ())
    bundle = replay_bundle.AnalysisReplayInputBundle("bundle:b-001", run_loc, ds_snap.locator(), "1.5.5", db_bin, (replay_bundle.DuckDbExtensionSpec("parquet", "1.5.5", "explicit_local_binary", ext_bin),), (replay_bundle.DuckDbSessionSetting("threads", cells.TaggedScalarCell("int64", "1")),), (replay_bundle.DuckDbViewDefinition("v_landing", "SELECT * FROM __smart_ads_landing", ()),), (q_def,), pol_loc, (prov_loc,), UNSIGNED)
    proj = cells.ResultProjection("scalar", r_schema.locator(), (col,), ((cells.TaggedScalarCell("int64", "7"),),), 1)
    a_res = results.AnalysisResult(run_loc, ds_snap.locator(), bundle.locator(), "result:spend", proj, UNSIGNED)
    c_set = results.CanonicalResultSet.build(bundle.locator(), (results.CanonicalResultEntry.from_result(a_res),))
    a_exec = results.AnalysisExecution(bundle.locator(), c_set, UNSIGNED)
    cert_rec = certification.AnalyticalCertificationRecord((), formulas.DerivedCertificationStatus.VERIFIED, False, c_set.canonical_result_digest, UNSIGNED)
    attested = (certification.AttestedCertificationInput(formulas.CertificationInput(formulas.DerivedCertificationStatus.VERIFIED, "phase1_7b_base"), True),)
    rep_in = reporting.CanonicalReportInput(ds_snap.snapshot_digest, c_set.canonical_result_digest, "2026-11-11T03:10:00.000000Z", "2026-11-10", "result:spend", inv_loc, cur_cat["smart_ads/curation_execution/v1"].locator(), (), attested, (), formulas.DerivedCertificationStatus.VERIFIED, False)
    rep_res = reporting.render_canonical_report_result(rep_in, ())
    op_ev = eff_ev["smart_ads/operational_read_evidence/v1"]
    rep_exec = reporting.ReportExecution("report:rep-001", run_loc, ds_snap.locator(), bundle.locator(), a_exec.locator(), pol_loc, (), (cert_rec.locator(),), (op_ev.locator(),), (op_ev.effect_proof_locator,), prov_loc, dataclasses.replace(alg_id, schema_id=reporting.ReportExecution.SCHEMA), rep_in, rep_res, "2026-11-11T03:11:00Z", integrity=UNSIGNED)
    return {
        "smart_ads/duckdb_binary_object_locator/v1": db_bin,
        "smart_ads/duckdb_extension_binary_locator/v1": ext_bin,
        "smart_ads/analysis_replay_input_bundle/v1": bundle,
        "smart_ads/report_execution/v1": rep_exec,
    }


def _pr4_instances() -> dict[str, Any]:
    eff_ev, alg_id, row = _pr4_effect_and_evidence_instances()
    cur_cat, ds_snap = _pr4_curation_and_catalog_instances(eff_ev, alg_id, row)
    ret = _pr4_retention_instances(ds_snap)
    rep = _pr4_replay_and_report_instances(eff_ev, cur_cat, ds_snap, alg_id)
    return {**eff_ev, **cur_cat, **ret, **rep}


def _pr5_instances() -> dict[str, Any]:
    run_loc, prov_loc = _loc("smart_ads/migration_run_context/v1", "1"), _loc("smart_ads/git_artifact_provenance/v1", "6")
    dm_loc, dmh_loc = _loc("smart_ads/decomposition_manifest/v1", "2"), _loc("smart_ads/decomposition_manifest_head/v1", "3")
    base_id = seam.LegacyBaselineIdentity()
    rel_id = seam.GitReleaseIdentity("mbras-tech/mbras-campaigns", "e" * 40, "f" * 40)
    alg_base = operational_evidence.AlgorithmProvenanceIdentity("algorithm:pr5-v1", "1.0.0", prov_loc, "aiconnai/smart-ads", "a" * 40, "src/smart_ads/contracts/seam.py", "b" * 40, "sha256:" + ("c" * 64), "cpython-3.12", seam.SeamParityRecord.SCHEMA)
    surf = seam.CompatibilitySurfaceSpec("surface:campaign", "smart_ads/collection_result/v1", "smart_ads/analytics_landing_row/v1", "mapping:campaign-v1")
    seam_con = seam.LegacySeamContract(run_loc, base_id, rel_id, dm_loc, dm_loc.content_digest, prov_loc, "sha256:" + ("5" * 64), "seam-v1", (surf,), UNSIGNED)
    edge = seam.GitParentEdge(rel_id.commit_sha, base_id.commit_sha, "cell-object:sha256:" + ("7" * 64))
    seam_art = seam.SeamGitArtifactRef("scripts/operator/seam.py", "1" * 40, "sha256:" + ("5" * 64), prov_loc)
    seam_rel = seam.LegacySeamRelease(run_loc, base_id, "cell-object:sha256:" + ("8" * 64), dmh_loc, dm_loc, dm_loc.content_digest, rel_id, (edge,), "refs/heads/main", 1, "2" * 40, rel_id.commit_sha, _loc("smart_ads/protected_merge_evidence/v1", "b"), "sha256:" + ("c" * 64), seam_art, seam_con.locator(), seam_con.locator().content_digest, integrity=UNSIGNED)
    cmp = seam.SurfaceParityComparison("surface:campaign", "mapping:campaign-v1", "sha256:" + ("1" * 64), 2, "sha256:" + ("e" * 64), "sha256:" + ("e" * 64), True)
    seam_par = seam.SeamParityRecord(run_loc, seam_rel.locator(), seam_rel.locator().content_digest, seam_con.locator(), seam_con.locator().content_digest, dmh_loc, dm_loc, _loc("smart_ads/wheel_build_provenance/v1", "d"), "sha256:" + ("f" * 64), alg_base, "2026-11-12T12:00:00Z", (cmp,), "PASS", UNSIGNED)
    del_ctx = consumer.IbviAdsDelegationContext("/ibvi-ads", "conductor:hermes", "front:pinna", "profile:pinna", "tenant:ibvi", "binding:meta-primary", "scope:campaigns-active", "smart_ads.queries.get_campaign_performance_v1", "sha256:" + ("7" * 64), "2026-11-12T12:00:00Z", "2026-11-12T12:15:00Z", "nonce-pr5-1", UNSIGNED)
    methods = ("smart_ads.queries.get_ad_performance_v1", "smart_ads.queries.get_adset_performance_v1", "smart_ads.queries.get_campaign_performance_v1", "smart_ads.queries.get_intelligence_findings_v1", "smart_ads.reports.generate_recurrent_summary_v1")
    del_con = consumer.IbviAdsDelegationContract(run_loc, "limaronaldo/hermes-ronaldo", "3" * 40, prov_loc, "conductor:hermes", "front:pinna", "/ibvi-ads", "sha256:" + ("7" * 64), methods, True, UNSIGNED)
    adp_sha, ff_sha = "sha256:" + ("8" * 64), "sha256:" + ("9" * 64)
    adp_ref = consumer.TripartiteGitArtifactRef("src/ibvi_ads/adapter.py", "4" * 40, adp_sha, prov_loc)
    ff_ref = consumer.TripartiteGitArtifactRef("src/ibvi_ads/flags.py", "5" * 40, ff_sha, prov_loc)
    ff_con = consumer.ConsumerFeatureFlagContract(run_loc, "limaronaldo/hermes-ronaldo", "3" * 40, adp_ref, ff_ref, "ibvi_ads.smart_ads_v1", False, "legacy:mbras_direct", "/ibvi-ads", (consumer.ReadEntrypointSelector("CampaignGateway.fetch", "smart_ads.queries.get_campaign_performance_v1"),), dataclasses.replace(alg_base, schema_id=consumer.ConsumerFeatureFlagContract.SCHEMA), del_con.locator(), UNSIGNED)
    rb = consumer.ConsumerDeploymentReadback(run_loc, "limaronaldo/hermes-ronaldo", "3" * 40, _loc("smart_ads/deployment_config_execution_result/v1", "a"), "release:hermes-1", "sha256:" + ("b" * 64), _loc("smart_ads/clock_attestation/v1", "c"), "2026-11-12T12:05:00.000000Z", dataclasses.replace(alg_base, schema_id=consumer.ConsumerDeploymentReadback.SCHEMA), "sha256:" + ("d" * 64), adp_ref, f"cell-object:{adp_sha}", ff_ref, f"cell-object:{ff_sha}", "ibvi_ads.smart_ads_v1", False, "legacy:mbras_direct", "/ibvi-ads", ff_con.locator(), ff_con.locator().content_digest, del_con.locator(), del_con.locator().content_digest, integrity=UNSIGNED)
    whl = seam.WheelObjectLocator.for_wheel_bytes(b"PK\x03\x04-pr5")
    return {seam_con.SCHEMA: seam_con, seam_rel.SCHEMA: seam_rel, seam_par.SCHEMA: seam_par, del_ctx.SCHEMA: del_ctx, del_con.SCHEMA: del_con, ff_con.SCHEMA: ff_con, rb.SCHEMA: rb, whl.SCHEMA: whl}


@pytest.fixture(scope="module")
def instances() -> dict[str, Any]:
    built = {
        **_analysis_instances(),
        **_formula_and_policy_instances(),
        **_reconciliation_instances(),
        **_pr3_7a_instances(),
        **_pr4_instances(),
        **_pr5_instances(),
    }
    assert set(built) == set(PR2_SCHEMA_TYPES)
    for schema_id, obj in built.items():
        assert type(obj) is PR2_SCHEMA_TYPES[schema_id], schema_id
    return built


# ---------------------------------------------------------------- descriptor registry shape


def test_registry_has_66_unique_descriptors_sorted_by_utf8_schema_id() -> None:
    schema_ids = [d["schema_id"] for d in CORE_SCHEMA_DESCRIPTORS]
    assert len(CORE_SCHEMA_DESCRIPTORS) == 66
    assert len(set(schema_ids)) == len(schema_ids)
    assert schema_ids == _utf8_sorted(schema_ids)
    assert set(schema_ids) == PRE_PR2_SCHEMA_IDS | set(PR2_SCHEMA_TYPES)
    assert len(PRE_PR2_SCHEMA_IDS | set(PR2_SCHEMA_TYPES)) == 13 + 53


def test_every_descriptor_is_immutable_with_sorted_unique_fields() -> None:
    for desc in CORE_SCHEMA_DESCRIPTORS:
        assert set(desc) == {"schema_id", "fields", "p1_domain_prefix"}
        assert isinstance(desc["fields"], tuple)
        fields = list(desc["fields"])
        assert fields == _utf8_sorted(fields)
        assert len(set(fields)) == len(fields)
        assert desc["p1_domain_prefix"] == ADR_P1_DOMAIN_PREFIXES.get(desc["schema_id"])
        with pytest.raises(TypeError):
            desc["fields"] = ()  # type: ignore[index]


def test_schemas_module_never_imports_the_analysis_or_reconciliation_layers() -> None:
    tree = ast.parse(Path(schemas_module.__file__).read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module is not None:
            imported.add(node.module)
        elif isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
    for module in imported:
        assert not module.startswith(("smart_ads.analytics", "smart_ads.reconciliation")), module


# ---------------------------------------------------------------- parity with implemented types


@pytest.mark.parametrize("schema_id", sorted(PR2_SCHEMA_TYPES))
def test_descriptor_schema_id_equals_the_type_schema_constant(schema_id: str) -> None:
    assert schema_id in _by_id()
    assert PR2_SCHEMA_TYPES[schema_id].SCHEMA == schema_id


def test_module_schema_id_constants_agree_with_descriptors() -> None:
    by_id = _by_id()
    for constant, schema_id in SCHEMA_ID_CONSTANTS:
        assert constant == schema_id
        assert constant in by_id


@pytest.mark.parametrize("schema_id", sorted(PR2_SCHEMA_TYPES))
def test_descriptor_fields_equal_the_to_dict_key_set(
    schema_id: str, instances: dict[str, Any]
) -> None:
    emitted = instances[schema_id].to_dict()
    assert list(_by_id()[schema_id]["fields"]) == _utf8_sorted(emitted)


@pytest.mark.parametrize("schema_id", sorted(P1_SCHEMA_TYPES))
def test_p1_descriptor_lists_integrity_and_its_adr_domain_prefix(
    schema_id: str, instances: dict[str, Any]
) -> None:
    desc = _by_id()[schema_id]
    assert "$schema" in desc["fields"]
    assert "integrity" in desc["fields"]
    assert desc["p1_domain_prefix"] == ADR_P1_DOMAIN_PREFIXES[schema_id]
    # `integrity` is the only optional member: without it the wire is the descriptor minus it.
    bare = dataclasses.replace(instances[schema_id], integrity=None).to_dict()
    assert set(bare) == set(desc["fields"]) - {"integrity"}


@pytest.mark.parametrize("schema_id", sorted(EMBEDDED_SCHEMA_TYPES))
def test_embedded_descriptor_has_no_integrity_and_no_p1_prefix(schema_id: str) -> None:
    desc = _by_id()[schema_id]
    assert "integrity" not in desc["fields"]
    assert desc["p1_domain_prefix"] is None
    assert schema_id not in ADR_P1_DOMAIN_PREFIXES
    assert ("$schema" in desc["fields"]) is (schema_id not in SCHEMALESS_EMBEDDED)


def _declared_key_constants() -> list[tuple[str, frozenset[str], frozenset[str] | None]]:
    """(schema id, full key constant, core key constant or None) for types that declare them."""
    with_integrity = {"integrity"}
    p1_with_keys: tuple[type[Any], ...] = (
        policy.AnalysisPolicy, intelligence.Finding, certification.AnalyticalCertificationRecord,
        git_provenance.GitArtifactProvenance, negative_security.NegativeSecurityTestReport,
        certification_7a.Certification7ARecord, effects.AuthorizationReceipt,
        effects.AuthorizationReservationRecord, effects.ExecutionReceipt,
        effects.AuthorizationConsumptionRecord, effects.EffectProof,
        operational_evidence.OperationalReadEvidence, operational_evidence.SanitizedCandidateFactSet,
        retention.RetentionRoot, retention.RetentionRootSetHead, retention.RetentionRootSetCasReceipt,
        retention.RetentionRootAdmissionResult, retention.RetentionRootAdmissionProof,
        retention.RetentionReleaseResult, retention.RetentionReleaseProof, curation.CurationExecution,
        catalog.GenerationManifest, catalog.DatasetCatalogGenesisRecord,
        catalog.DatasetCatalogGenesisConsumptionRecord, catalog.DatasetCatalog,
        catalog.DatasetCatalogCutReceipt, catalog.DatasetSnapshot,
        replay_bundle.AnalysisReplayInputBundle, reporting.ReportExecution,
        seam.LegacySeamContract, seam.LegacySeamRelease, seam.SeamParityRecord,
        consumer.IbviAdsDelegationContext, consumer.IbviAdsDelegationContract,
        consumer.ConsumerFeatureFlagContract, consumer.ConsumerDeploymentReadback,
    )
    embedded_with_keys: tuple[type[Any], ...] = (
        catalog.ParquetObjectLocator, catalog.ActivePartitionHead,
        replay_bundle.DuckDbBinaryObjectLocator, replay_bundle.DuckDbExtensionBinaryLocator,
        bundle_7b.FactEvidenceSelector, bundle_7b.FactReconciliation, seam.WheelObjectLocator,
    )
    return [
        *((c.SCHEMA, frozenset(c.KEYS), frozenset(c.CORE_KEYS)) for c in p1_with_keys),
        ("smart_ads/native_request_projection/v1", frozenset(bundle_7b.NativeRequestProjection.CORE_KEYS) | with_integrity, frozenset(bundle_7b.NativeRequestProjection.CORE_KEYS)),
        ("smart_ads/certification_7b_record/v1", frozenset(bundle_7b.Certification7BRecord.CORE_KEYS) | with_integrity, frozenset(bundle_7b.Certification7BRecord.CORE_KEYS)),
        *((c.SCHEMA, frozenset(c.KEYS), None) for c in embedded_with_keys),
    ]


_PR3_AND_PR4_P1_SCHEMA_IDS = frozenset(
    f"smart_ads/{n}/v1"
    for n in (
        "git_artifact_provenance negative_security_test_report certification_7a_record "
        "authorization_receipt authorization_reservation_record execution_receipt "
        "authorization_consumption_record effect_proof operational_read_evidence "
        "sanitized_candidate_fact_set retention_root retention_root_set_head "
        "retention_root_set_cas_receipt retention_root_admission_result retention_root_admission_proof "
        "retention_release_result retention_release_proof curation_execution generation_manifest "
        "dataset_catalog_genesis_record dataset_catalog_genesis_consumption_record dataset_catalog "
        "dataset_catalog_cut_receipt dataset_snapshot analysis_replay_input_bundle report_execution "
        "legacy_seam_contract legacy_seam_release seam_parity_record ibvi_ads_delegation_context "
        "ibvi_ads_delegation_contract consumer_feature_flag_contract consumer_deployment_readback"
    ).split()
)


@pytest.mark.parametrize("schema_id", sorted(_PR3_AND_PR4_P1_SCHEMA_IDS))
def test_p1_types_enforce_require_signed_roundtrip(
    schema_id: str, instances: dict[str, Any]
) -> None:
    cls = P1_SCHEMA_TYPES[schema_id]
    unsigned_dict = {**instances[schema_id].to_dict(), "integrity": UNSIGNED.to_dict()}
    with pytest.raises(ClosedValidationError):
        cls.from_dict(unsigned_dict, require_signed=True)
    without_integrity = {k: v for k, v in unsigned_dict.items() if k != "integrity"}
    with pytest.raises(ClosedValidationError):
        cls.from_dict(without_integrity, require_signed=True)
    signed_dict = {
        **unsigned_dict,
        "integrity": {
            **UNSIGNED.to_dict(),
            "content_digest": p1_content_digest(unsigned_dict),
            "signature_base64": ("A" * 86) + "==",
        },
    }
    parsed = cls.from_dict(signed_dict, require_signed=True)
    assert parsed.to_dict() == signed_dict


def test_class_key_constants_match_descriptor_and_a_real_to_dict(
    instances: dict[str, Any],
) -> None:
    by_id = _by_id()
    for schema_id, keys, core_keys in _declared_key_constants():
        fields = frozenset(by_id[schema_id]["fields"])
        assert keys == fields, schema_id
        assert keys == frozenset(instances[schema_id].to_dict()), schema_id
        if core_keys is not None:
            assert core_keys == fields - {"integrity"}, schema_id


# ---------------------------------------------------------------- package re-exports


def _submodule(package: str, name: str) -> Any:
    return importlib.import_module(f"{package}.{name}")


@pytest.mark.parametrize("package", sorted(PACKAGE_SUBMODULES))
def test_package_all_is_explicit_sorted_and_unique(package: str) -> None:
    exported = importlib.import_module(package).__all__
    assert isinstance(exported, list)
    assert exported == _utf8_sorted(exported)
    assert len(set(exported)) == len(exported)


@pytest.mark.parametrize("package", sorted(PACKAGE_SUBMODULES))
def test_package_all_is_the_submodule_union_minus_ambiguous_names(package: str) -> None:
    union: set[str] = set()
    for name in PACKAGE_SUBMODULES[package]:
        union.update(_submodule(package, name).__all__)
    exported = set(importlib.import_module(package).__all__)
    assert exported == union - WITHHELD_AMBIGUOUS[package]


@pytest.mark.parametrize("package", sorted(PACKAGE_SUBMODULES))
def test_every_package_name_is_the_same_object_as_in_its_submodules(package: str) -> None:
    pkg = importlib.import_module(package)
    for name in pkg.__all__:
        owners = [
            _submodule(package, sub)
            for sub in PACKAGE_SUBMODULES[package]
            if name in _submodule(package, sub).__all__
        ]
        assert owners, name
        for owner in owners:
            assert getattr(pkg, name) is getattr(owner, name), (package, name)


@pytest.mark.parametrize("package", sorted(PACKAGE_SUBMODULES))
def test_withheld_names_are_absent_from_the_package(package: str) -> None:
    pkg = importlib.import_module(package)
    for name in WITHHELD_AMBIGUOUS[package]:
        assert name not in pkg.__all__
        assert not hasattr(pkg, name)


def test_the_two_restatement_kinds_tuples_agree_by_value() -> None:
    # intelligence.py relies on these being equal; whether they are one object is not pinned.
    assert lattice.RESTATEMENT_KINDS == policy.RESTATEMENT_KINDS


@pytest.mark.parametrize("package", sorted(PACKAGE_SUBMODULES))
def test_package_namespace_leaks_no_public_name_outside_all(package: str) -> None:
    pkg = importlib.import_module(package)
    exported = set(pkg.__all__)
    leaked = sorted(
        name
        for name, value in vars(pkg).items()
        if not name.startswith("_")
        and not isinstance(value, types.ModuleType)
        # `from __future__ import annotations` binds this feature object in every module.
        and not (name == "annotations" and value is __future__.annotations)
        and name not in exported
    )
    assert leaked == [], leaked


_FRESH_IMPORT_CHECK = """
import sys
for name in sys.argv[1:]:
    __import__(name)
for name in ("smart_ads.analytics", "smart_ads.reconciliation", "smart_ads.adapters.pipeboard"):
    module = sys.modules[name]
    missing = [n for n in module.__all__ if not hasattr(module, n)]
    if missing:
        raise SystemExit(f"{name}: unresolved {missing}")
"""
# Resolve smart_ads from the exact package root selected by the parent pytest process
# (src/ in host/CI and site-packages in isolated wheel Docker suites).
_SMART_ADS_IMPORT_ROOT = str(Path(smart_ads.__file__).resolve().parents[1])
_SRC_ENV = {**os.environ, "PYTHONPATH": _SMART_ADS_IMPORT_ROOT}


@pytest.mark.parametrize(
    "order",
    [
        ("smart_ads.analytics", "smart_ads.reconciliation", "smart_ads.adapters.pipeboard"),
        ("smart_ads.reconciliation", "smart_ads.analytics", "smart_ads.adapters.pipeboard"),
        ("smart_ads.adapters.pipeboard", "smart_ads.reconciliation", "smart_ads.analytics"),
        ("smart_ads.contracts.schemas", "smart_ads.reconciliation", "smart_ads.analytics"),
        ("smart_ads.analytics.lattice", "smart_ads.reconciliation.tolerance"),
    ],
)
def test_packages_import_cleanly_in_a_fresh_interpreter(order: tuple[str, ...]) -> None:
    completed = subprocess.run(
        [sys.executable, "-W", "error", "-c", _FRESH_IMPORT_CHECK, *order],
        cwd=REPO_ROOT,
        env=_SRC_ENV,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr


def test_contracts_schemas_loads_without_the_analysis_or_reconciliation_layers() -> None:
    code = (
        "import sys\n"
        "import smart_ads.contracts.schemas\n"
        "loaded = [m for m in sys.modules if m.startswith(('smart_ads.analytics', "
        "'smart_ads.reconciliation', 'smart_ads.adapters', 'smart_ads.application', "
        "'smart_ads.domain', 'smart_ads.ports'))]\n"
        "if loaded:\n"
        "    raise SystemExit(f'unexpected: {loaded}')\n"
    )
    completed = subprocess.run(
        [sys.executable, "-W", "error", "-c", code],
        cwd=REPO_ROOT,
        env=_SRC_ENV,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
