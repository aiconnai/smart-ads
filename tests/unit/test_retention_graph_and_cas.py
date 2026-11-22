"""Unit tests for transitive retention reachability closure and one-way root-set CAS service."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
import hashlib
from typing import Any

import pytest

from smart_ads.adapters.storage import InMemoryCellObjectStore, StdlibParquetLandingCodec
from smart_ads.analytics import (
    METRIC_WINDOW_COLUMNS, REPORT_EXECUTION_SCHEMA, AnalysisExecution, AnalysisPolicy,
    AnalysisReplayInputBundle, AnalysisResultSchema, AttestedCertificationInput, CanonicalResultEntry,
    CanonicalResultSet, CertificationInput, DerivedCertificationStatus, DuckDbBinaryObjectLocator,
    DuckDbExtensionBinaryLocator, DuckDbExtensionSpec, DuckDbQueryDefinition, DuckDbSessionSetting,
    EvaluationContext, EvaluationScope, ReportExecution, ResultColumn, TaggedScalarCell,
)
import smart_ads.application as application_pkg
from smart_ads.application import (
    GlobalDatasetCatalogService, ReachabilityClosure, RetentionRootSetService, WheelObjectLocator,
    build_retention_root, build_sanitized_candidate_fact_set, compute_retention_reachability_graph,
    execute_analysis_replay_bundle, execute_certified_report, head_pinned_object_refs,
    materialize_parquet_generation, publish_dataset_snapshot, verify_retention_release_proof,
    verify_retention_root, verify_retention_root_admission_proof,
)
from smart_ads.contracts import (
    AdmittedCollection, ArtifactLocator, CanonicalQueryContract, ClosedValidationError, CollectionResult,
    DateRange, P1Integrity, PurposePrerequisiteLocators, RetrievalContext, compute_normalized_fact_set_digest,
    jcs_sha256, p1_content_digest, project_collection_fact_to_landing_row,
)
from smart_ads.contracts.effects import (
    AuthorizationConsumptionRecord, AuthorizationReceipt, AuthorizationReservationRecord, EffectProof,
    ExecutionReceipt, ProviderCallTarget, RetentionReleaseTarget, RetentionRootAdmissionTarget,
    sort_artifact_locators, sort_cell_object_refs,
)
from smart_ads.contracts.git_provenance import GitArtifactProvenance, compute_git_blob_oid
from smart_ads.contracts.operational_evidence import AlgorithmProvenanceIdentity, OperationalReadEvidence, SanitizedCandidateFactSet
from smart_ads.contracts.retention import (
    RetentionReleaseProof, RetentionReleaseResult, RetentionRoot, RetentionRootAdmissionProof,
    RetentionRootAdmissionResult, RetentionRootSetCasReceipt, RetentionRootSetCasRequestProjection,
    RetentionRootSetHead, compute_root_locator_set_digest,
)
from smart_ads.domain import (
    FORBIDDEN_PIPEBOARD_ARGUMENTS, PINNED_LEGACY_COMMIT, PINNED_LEGACY_REPO, PINNED_PIPEBOARD_D26_SPECS,
    PIPEBOARD_PHASE1_METRIC_SOURCE_MAPPINGS, ActivePartitionHead, AuthorizedScopeRelation,
    CatalogCasRequestProjection, CurationExecution, DatasetCatalog, DatasetCatalogCutReceipt,
    DatasetCatalogGenesisConsumptionRecord, DatasetCatalogGenesisRecord, DatasetSnapshot,
    DriverCapabilityEntry, ExpectedResourceInventory, ExpectedResourceKey, GenerationManifest,
    LegacySourcePacket, PinnedGitArtifactMember, PinnedUpstreamReference, PipeboardPhase1Contract,
    PipeboardTransportLimits, PrivateRegistrySnapshot, RegistryBinding, compute_curation_window,
)
from smart_ads.ports.cell_runtime import ClockAttestation
from smart_ads.ports.storage import CellObjectStorePort
from tests.unit.test_curation_and_catalog import _CAMP_A, _METRICS_3, _clean_transport, _make_facts
from tests.unit.test_duckdb_replay_and_reporting import DeterministicInMemoryDuckDbEngine, _LIVE_METRICS_WINDOW_SQL, _METRIC_ORDER, _METRIC_UKEY

_KEY_ID = "key:ed25519:" + ("9" * 64)
_SIG_B64 = ("A" * 86) + "=="


def _sign_payload(raw_no_int: Mapping[str, Any], key_reg_loc: ArtifactLocator) -> dict[str, Any]:
    unsigned = P1Integrity(key_id=_KEY_ID, key_registry_snapshot_locator=key_reg_loc)
    digest = p1_content_digest({**raw_no_int, "integrity": unsigned.to_dict()})
    return {**raw_no_int, "integrity": P1Integrity(_KEY_ID, key_reg_loc, digest, _SIG_B64).to_dict()}


def _put_signed_envelope(store: InMemoryCellObjectStore, schema_id: str, body: Mapping[str, Any], key_reg_loc: ArtifactLocator) -> tuple[dict[str, Any], ArtifactLocator]:
    signed = _sign_payload({"$schema": schema_id, **{k: v for k, v in body.items() if k != "integrity"}}, key_reg_loc)
    return signed, store.put_json_artifact(schema_id, signed)


def _put_signed_model(store: InMemoryCellObjectStore, obj: Any, key_reg_loc: ArtifactLocator) -> tuple[Any, ArtifactLocator]:
    signed, loc = _put_signed_envelope(store, obj.SCHEMA, obj.to_dict(), key_reg_loc)
    return type(obj).from_dict(signed, require_signed=True), loc


def _put_git_prov(store: InMemoryCellObjectStore, key_reg_loc: ArtifactLocator, repo: str, commit: str, path: str, raw: bytes) -> tuple[GitArtifactProvenance, ArtifactLocator]:
    prov = GitArtifactProvenance(repo, commit, path, compute_git_blob_oid(raw), "sha256:" + hashlib.sha256(raw).hexdigest(), "2026-11-10T00:00:00Z")
    return _put_signed_model(store, prov, key_reg_loc)


def _put_prereq_effect_chain(store: InMemoryCellObjectStore, run_loc: ArtifactLocator, key_reg_loc: ArtifactLocator, *, action: str, slot: str, subject_kind: str, result_schema: str, tag: str) -> ArtifactLocator:
    _, res_loc = _put_signed_envelope(store, result_schema, {"migration_run_context_locator": run_loc.to_dict(), "tag": tag}, key_reg_loc)
    subj, nonce = {"subject_kind": subject_kind, "migration_run_context_locator": run_loc.to_dict(), "tag": tag}, f"nonce-prereq-{tag}"
    _, auth_loc = _put_signed_envelope(store, AuthorizationReceipt.SCHEMA, {"authorization_id": f"auth:{tag}", "migration_run_context_locator": run_loc.to_dict(), "action": action, "dag_slot": slot, "subject": subj, "parameters_digest": "sha256:" + ("1" * 64), "predecessor_locators": [], "approving_principal_ref": "principal:ops-01", "issued_at_utc": "2026-11-10T00:00:00Z", "valid_until_utc": "2026-11-12T00:00:00Z", "single_use_nonce": nonce}, key_reg_loc)
    _, resv_loc = _put_signed_envelope(store, AuthorizationReservationRecord.SCHEMA, {"reservation_id": f"resv:{tag}", "migration_run_context_locator": run_loc.to_dict(), "authorization_locator": auth_loc.to_dict(), "authorization_receipt_digest": auth_loc.content_digest, "single_use_nonce": nonce, "action": action, "dag_slot": slot, "subject": subj, "reservation_status": "consumed", "in_doubt_reason": None, "reserved_at_utc": "2026-11-10T00:01:00Z"}, key_reg_loc)
    _, exec_loc = _put_signed_envelope(store, ExecutionReceipt.SCHEMA, {"execution_id": f"exec:{tag}", "migration_run_context_locator": run_loc.to_dict(), "authorization_locator": auth_loc.to_dict(), "reservation_locator": resv_loc.to_dict(), "single_use_nonce": nonce, "action": action, "dag_slot": slot, "subject": subj, "execution_status": "succeeded", "action_result_locator": res_loc.to_dict(), "executed_at_utc": "2026-11-10T00:02:00Z"}, key_reg_loc)
    _, cons_loc = _put_signed_envelope(store, AuthorizationConsumptionRecord.SCHEMA, {"consumption_id": f"cons:{tag}", "migration_run_context_locator": run_loc.to_dict(), "authorization_locator": auth_loc.to_dict(), "authorization_receipt_digest": auth_loc.content_digest, "reservation_locator": resv_loc.to_dict(), "execution_locator": exec_loc.to_dict(), "single_use_nonce": nonce, "action": action, "dag_slot": slot, "consumption_status": "consumed", "consumed_at_utc": "2026-11-10T00:02:00Z"}, key_reg_loc)
    _, pf_loc = _put_signed_envelope(store, EffectProof.SCHEMA, {"effect_proof_id": f"proof:{tag}", "migration_run_context_locator": run_loc.to_dict(), "action": action, "dag_slot": slot, "authorization_locator": auth_loc.to_dict(), "reservation_locator": resv_loc.to_dict(), "execution_locator": exec_loc.to_dict(), "consumption_locator": cons_loc.to_dict(), "action_result_locator": res_loc.to_dict(), "verified_at_utc": "2026-11-10T00:03:00Z"}, key_reg_loc)
    return pf_loc


def _build_prereqs_and_registry(
    store: InMemoryCellObjectStore, run_loc: ArtifactLocator, key_reg_loc: ArtifactLocator
) -> tuple[PurposePrerequisiteLocators, ArtifactLocator, PipeboardPhase1Contract, ArtifactLocator, ArtifactLocator]:
    d26_members: list[PinnedGitArtifactMember] = []
    for role, path, blob_oid, file_sha in PINNED_PIPEBOARD_D26_SPECS:
        raw_prov = GitArtifactProvenance(PINNED_LEGACY_REPO, PINNED_LEGACY_COMMIT, path, blob_oid, file_sha, "2026-11-10T00:00:00Z")
        _, m_loc = _put_signed_model(store, raw_prov, key_reg_loc)
        d26_members.append(PinnedGitArtifactMember(role, PINNED_LEGACY_REPO, PINNED_LEGACY_COMMIT, path, blob_oid, file_sha, m_loc))
    raw_contract = PipeboardPhase1Contract(
        "driver-contract:pipeboard-phase1-v1", "pipeboard_hosted",
        LegacySourcePacket(PINNED_LEGACY_REPO, PINNED_LEGACY_COMMIT, tuple(d26_members)),
        PinnedUpstreamReference(), PipeboardTransportLimits(forbidden_arguments=FORBIDDEN_PIPEBOARD_ARGUMENTS),
        dict(PIPEBOARD_PHASE1_METRIC_SOURCE_MAPPINGS),
    )
    contract, contract_loc = _put_signed_model(store, raw_contract, key_reg_loc)
    cap = DriverCapabilityEntry("cap:meta_daily_campaign_v1", "1.0.0", "pipeboard_hosted", contract_loc, contract_loc.content_digest, "scope:campaigns-active", "live_certified", _METRICS_3)
    raw_reg = PrivateRegistrySnapshot(
        "registry-snapshot:ibvi-001", "tenant:ibvi", "2026-11-10T00:00:00Z", "2026-11-15T00:00:00Z",
        "hmac-sha256-b32-v1", "key:tenant-ibvi-hmac-v1",
        (RegistryBinding("binding:meta-primary", "account:ibvi-01", "provider:pipeboard", "meta", "BRL", "pipeboard_hosted"),),
        (AuthorizedScopeRelation("front:pinna", "profile:pinna", "binding:meta-primary", "scope:campaigns-active"),), (cap,),
    )
    _, reg_loc = _put_signed_model(store, raw_reg, key_reg_loc)
    _, clock_loc = _put_signed_model(store, ClockAttestation("clock:att-001", "2026-11-11T03:00:00.000000Z", 250, "2026-11-11T02:59:50Z", "2026-11-11T03:00:30Z", 30), key_reg_loc)
    prereq_locs = {
        k: _put_signed_envelope(store, sch, {"migration_run_context_locator": run_loc.to_dict(), "slot": k}, key_reg_loc)[1]
        for k, sch in (
            ("step2", "smart_ads/legacy_step2_implementation_evidence/v1"),
            ("act", "smart_ads/smart_ads_live_read_activation_receipt/v1"),
            ("head", "smart_ads/live_certification_head/v1"),
            ("trans", "smart_ads/live_certification_transition/v1"),
            ("cert", "smart_ads/live_certification_certificate/v1"),
            ("gate3", "smart_ads/gate3_selection_receipt/v1"),
            ("deleg", "smart_ads/ibvi_ads_delegation_context/v1"),
        )
    }
    wi_pf = _put_prereq_effect_chain(store, run_loc, key_reg_loc, action="workload_identity_provision", slot="workload_identity_effect_proof", subject_kind="workload_identity_target", result_schema="smart_ads/workload_identity_execution_result/v1", tag="wi")
    dp_pf = _put_prereq_effect_chain(store, run_loc, key_reg_loc, action="deployment_config_apply", slot="deployment_config_effect_proof", subject_kind="deployment_target", result_schema="smart_ads/deployment_config_execution_result/v1", tag="dp")
    prereqs = PurposePrerequisiteLocators(
        purpose="operational_read", legacy_step2_evidence_locator=prereq_locs["step2"],
        live_read_activation_receipt_locator=prereq_locs["act"], live_certification_head_locator=prereq_locs["head"],
        live_certification_transition_locator=prereq_locs["trans"], live_certification_certificate_locator=prereq_locs["cert"],
        gate3_operational_renewal_locator=prereq_locs["gate3"], workload_identity_effect_proof_locator=wi_pf,
        deployment_effect_proof_locator=dp_pf, delegation_context_locator=prereq_locs["deleg"],
    )
    return prereqs, reg_loc, contract, contract_loc, clock_loc


class RetentionWorld:
    """Full end-to-end signed DAG (`ReportExecution -> ... -> Parquet/DuckDB/Wheel + P1 key registry`)."""

    def __init__(self) -> None:
        self.store, self.codec = InMemoryCellObjectStore(), StdlibParquetLandingCodec()
        self.cell_ref = "cell:ibvi-primary"
        self.run_loc = self.store.put_json_artifact("smart_ads/migration_run_context/v1", {"$schema": "smart_ads/migration_run_context/v1", "run_id": "run:pr4-ret-001"})
        self.key_reg_loc = self.store.put_json_artifact("smart_ads/key_authorization_registry/v1", {"$schema": "smart_ads/key_authorization_registry/v1", "keys": [_KEY_ID]})
        self.prereqs, self.reg_loc, self.driver_contract, self.driver_loc, self.clock_loc = _build_prereqs_and_registry(self.store, self.run_loc, self.key_reg_loc)
        self.san_alg, self.cur_alg, self.render_alg, self.tmpl_loc = self._init_algorithms()
        self.duck_bytes, self.ext_bytes, self.wheel_bytes = b"\x7fELF-duckdb-1.5.5", b"ext-parquet-1.5.5", b"PK\x03\x04-mock-wheel-bytes"
        self.duck_ref = self.store.put_bytes(self.duck_bytes)
        self.ext_ref = self.store.put_bytes(self.ext_bytes)
        self.wheel_ref = self.store.put_bytes(self.wheel_bytes)
        _, self.wheel_prov_loc = _put_signed_envelope(self.store, "smart_ads/wheel_build_provenance/v1", {
            "migration_run_context_locator": self.run_loc.to_dict(),
            "wheel": WheelObjectLocator.for_wheel_bytes(self.wheel_bytes).to_dict(),
        }, self.key_reg_loc)
        self._init_catalog_and_snapshots()
        self._init_reports_and_roots()

    def _init_algorithms(self) -> tuple[AlgorithmProvenanceIdentity, AlgorithmProvenanceIdentity, AlgorithmProvenanceIdentity, ArtifactLocator]:
        sp, sp_loc = _put_git_prov(self.store, self.key_reg_loc, "aiconnai/smart-ads", "a" * 40, "src/smart_ads/application/curation_pipeline.py", b"# sanitize")
        cp, cp_loc = _put_git_prov(self.store, self.key_reg_loc, "aiconnai/smart-ads", "a" * 40, "src/smart_ads/domain/curation.py", b"# curate")
        rp, rp_loc = _put_git_prov(self.store, self.key_reg_loc, "aiconnai/smart-ads", "a" * 40, "src/smart_ads/analytics/reporting.py", b"# render")
        _, tmpl_loc = _put_git_prov(self.store, self.key_reg_loc, "aiconnai/smart-ads", "a" * 40, "src/smart_ads/analytics/template.json", b'{"v":1}')
        return (
            AlgorithmProvenanceIdentity("algorithm:sanitize-v1", "1.0.0", sp_loc, sp.repository, sp.commit_sha, sp.path, sp.git_blob_oid, sp.file_content_sha256, "cpython-3.12", SanitizedCandidateFactSet.SCHEMA),
            AlgorithmProvenanceIdentity("algorithm:curate-v1", "1.0.0", cp_loc, cp.repository, cp.commit_sha, cp.path, cp.git_blob_oid, cp.file_content_sha256, "cpython-3.12", CurationExecution.SCHEMA),
            AlgorithmProvenanceIdentity("algorithm:render-v1", "1.0.0", rp_loc, rp.repository, rp.commit_sha, rp.path, rp.git_blob_oid, rp.file_content_sha256, "cpython-3.12", REPORT_EXECUTION_SCHEMA),
            tmpl_loc,
        )

    def _store_op_read(self, metric_date: str, tag: str, *, clicks_val: str, collected_at: str) -> tuple[OperationalReadEvidence, ArtifactLocator, ArtifactLocator]:
        dr = DateRange(metric_date, metric_date, True)
        cqc = CanonicalQueryContract("tenant:ibvi", "binding:meta-primary", "account:ibvi-01", "scope:campaigns-active", "meta", "previous_local_day", dr, "America/Sao_Paulo", "2026a", "campaign", _METRICS_3, ("cap:meta_daily_campaign_v1",))
        raw_adm = AdmittedCollection(f"admission:{tag}", "operational_read", "sha256:" + ("5" * 64), "tenant:ibvi", "binding:meta-primary", "account:ibvi-01", "scope:campaigns-active", "campaign", ("cap:meta_daily_campaign_v1",), "2026-11-11T03:00:00Z", self.clock_loc, 250, "2026a", "America/Sao_Paulo", dr, self.reg_loc, self.reg_loc.content_digest, "BRL", "pipeboard_hosted", self.driver_loc, self.driver_loc.content_digest, "sha256:" + ("6" * 64), cqc, cqc.canonical_query_digest, self.prereqs, ("operational_provider_read",))
        adm, adm_loc = _put_signed_model(self.store, raw_adm, self.key_reg_loc)
        raw_inv = ExpectedResourceInventory(f"inventory:{tag}", self.reg_loc, self.reg_loc.content_digest, "tenant:ibvi", "binding:meta-primary", "account:ibvi-01", "scope:campaigns-active", dr, (ExpectedResourceKey("binding:meta-primary", "account:ibvi-01", _CAMP_A, "campaign", metric_date),))
        _, inv_loc = _put_signed_model(self.store, raw_inv, self.key_reg_loc)
        facts = _make_facts(metric_date, clicks_val=clicks_val)
        _, f_dig = compute_normalized_fact_set_digest(facts)
        rctx = RetrievalContext(collected_at, f"observation:{tag}", "pipeboard-0.1.0", "1.0.0")
        cands = tuple(sorted((project_collection_fact_to_landing_row(f, rctx) for f in facts), key=lambda r: r.candidate_sort_key_jcs()))
        _, res_loc = _put_signed_model(self.store, CollectionResult(adm_loc, adm_loc.content_digest, "operational", self.reg_loc, self.reg_loc.content_digest, adm.requested_capabilities, adm.requested_capabilities, rctx, _clean_transport(), cands, facts, f_dig, ()), self.key_reg_loc)
        subj = ProviderCallTarget(self.run_loc, adm_loc, "operational", "provider-target:pipeboard", adm.canonical_query_digest, self.reg_loc, "tenant:ibvi", "binding:meta-primary", "account:ibvi-01", "scope:campaigns-active", self.prereqs.delegation_context_locator)
        nonce = f"nonce-op-{tag}"
        _, a_loc = _put_signed_model(self.store, AuthorizationReceipt(f"auth:{tag}", self.run_loc, "provider_operational_read", "operational_provider_read_effect_proof", subj, "sha256:" + ("7" * 64), (adm_loc,), "principal:op-01", "2026-11-11T03:00:00Z", "2026-11-11T04:00:00Z", nonce), self.key_reg_loc)
        _, rv_loc = _put_signed_model(self.store, AuthorizationReservationRecord(f"rv:{tag}", self.run_loc, a_loc, a_loc.content_digest, nonce, "provider_operational_read", "operational_provider_read_effect_proof", subj, "consumed", None, "2026-11-11T03:01:00Z"), self.key_reg_loc)
        _, ex_loc = _put_signed_model(self.store, ExecutionReceipt(f"ex:{tag}", self.run_loc, a_loc, rv_loc, nonce, "provider_operational_read", "operational_provider_read_effect_proof", subj, "succeeded", res_loc, "2026-11-11T03:02:00Z"), self.key_reg_loc)
        _, cn_loc = _put_signed_model(self.store, AuthorizationConsumptionRecord(f"cn:{tag}", self.run_loc, a_loc, a_loc.content_digest, rv_loc, ex_loc, nonce, "provider_operational_read", "operational_provider_read_effect_proof", "consumed", "2026-11-11T03:02:00Z"), self.key_reg_loc)
        _, pf_loc = _put_signed_model(self.store, EffectProof(f"pf:{tag}", self.run_loc, "provider_operational_read", "operational_provider_read_effect_proof", a_loc, rv_loc, ex_loc, cn_loc, res_loc, "2026-11-11T03:03:00Z"), self.key_reg_loc)
        ev, ev_loc = _put_signed_model(self.store, OperationalReadEvidence(self.run_loc, "tenant:ibvi", "binding:meta-primary", "account:ibvi-01", "scope:campaigns-active", adm.canonical_query_digest, self.reg_loc, self.reg_loc.content_digest, inv_loc, adm_loc, adm_loc.content_digest, res_loc, res_loc.content_digest, f_dig, a_loc, rv_loc, ex_loc, cn_loc, pf_loc), self.key_reg_loc)
        return ev, ev_loc, inv_loc

    def _materialize_signed_gen(
        self, tag: str, mode: str, date_str: str, ev_loc: ArtifactLocator, base_cat_loc: ArtifactLocator,
        snap_loc: ArtifactLocator | None, cut_loc: ArtifactLocator | None, hist_locs: tuple[ArtifactLocator, ...],
        parent_loc: ArtifactLocator | None,
    ) -> tuple[GenerationManifest, ArtifactLocator]:
        raw_cs = build_sanitized_candidate_fact_set(migration_run_context_locator=self.run_loc, sanitization_algorithm_identity=self.san_alg, store=self.store, evidence_locators=(ev_loc,), require_signed_inputs=True)
        _, cs_loc = _put_signed_model(self.store, raw_cs, self.key_reg_loc)
        win = compute_curation_window(date_str, "America/Sao_Paulo", "2026a", 1)
        raw_cur = CurationExecution(self.run_loc, f"cur:{tag}", mode, date_str, "America/Sao_Paulo", "2026a", 1, win, cs_loc, self.cur_alg, self.genesis_loc if mode == "genesis" else None, base_cat_loc, snap_loc, cut_loc, hist_locs, "2026-11-11T03:05:00Z")  # type: ignore[arg-type]
        _, cur_loc = _put_signed_model(self.store, raw_cur, self.key_reg_loc)
        raw_gm, _ = materialize_parquet_generation(generation_id=f"gen:{tag}", created_at_utc="2026-11-11T03:06:00Z", registry_snapshot_locator=self.reg_loc, curation_locator=cur_loc, store=self.store, parquet_codec=self.codec, parent_generation_manifest_locator=parent_loc)
        return _put_signed_model(self.store, raw_gm, self.key_reg_loc)

    def _commit_signed_cut(
        self, svc: GlobalDatasetCatalogService, *, idx: int, op: str, seq: int, gm: GenerationManifest,
        gm_loc: ArtifactLocator, genesis_loc: ArtifactLocator | None = None,
    ) -> tuple[DatasetSnapshot, ArtifactLocator, ArtifactLocator]:
        old_loc, old_cat = svc.current_head()
        new_head = ActivePartitionHead(gm.partition_key, seq, gm_loc)
        heads = tuple(sorted((*(h for h in old_cat.partition_heads if h.partition_key != gm.partition_key), new_head), key=lambda h: h.partition_key.encode("utf-8")))
        ts = f"2026-11-11T03:0{6 + idx}:00Z"
        cat_s, _ = _put_signed_model(self.store, DatasetCatalog(f"catalog:{idx}", self.cell_ref, idx, ts, heads), self.key_reg_loc)
        cons_s = None if genesis_loc is None else _put_signed_model(self.store, DatasetCatalogGenesisConsumptionRecord(genesis_loc, genesis_loc.content_digest, old_loc, old_loc.content_digest, cat_s.locator(), cat_s.locator().content_digest, f"cut:{idx}", f"lin:{idx}", ts), self.key_reg_loc)[0]
        proj = CatalogCasRequestProjection(op, old_cat.catalog_epoch, old_loc.content_digest, gm.partition_key, seq, gm_loc)  # type: ignore[arg-type]
        rec_s, _ = _put_signed_model(self.store, DatasetCatalogCutReceipt(f"cut:{idx}", self.cell_ref, self.run_loc, old_loc, old_loc.content_digest, old_cat.catalog_epoch, cat_s.locator(), cat_s.locator().content_digest, idx, proj, f"lin:{idx}", ts, None if genesis_loc is None else genesis_loc, None if genesis_loc is None else genesis_loc.content_digest, None if cons_s is None else cons_s.locator(), None if cons_s is None else cons_s.locator().content_digest), self.key_reg_loc)
        _, _, _, rec_loc = svc.commit_partition_cut(cut_id=f"cut:{idx}", cas_linearization_id=f"lin:{idx}", committed_at_utc=ts, expected_old_catalog_locator=old_loc, expected_old_catalog_epoch=old_cat.catalog_epoch, generation_manifest_locator=gm_loc, new_catalog_id=f"catalog:{idx}", genesis_record_locator=genesis_loc, consumption_integrity=None if cons_s is None else cons_s.integrity, catalog_integrity=cat_s.integrity, receipt_integrity=rec_s.integrity)
        raw_snap, _ = publish_dataset_snapshot(snapshot_id=f"snapshot:{idx}", created_at=ts, cut_receipt_locator=rec_loc, store=self.store)
        snap_s, snap_loc = _put_signed_model(self.store, raw_snap, self.key_reg_loc)
        return snap_s, snap_loc, rec_loc

    def _init_catalog_and_snapshots(self) -> None:
        _, self.epoch0_loc = _put_signed_model(self.store, DatasetCatalog("catalog:0", self.cell_ref, 0, "2026-11-10T00:00:00Z", ()), self.key_reg_loc)
        _, self.genesis_loc = _put_signed_model(self.store, DatasetCatalogGenesisRecord("genesis:001", self.cell_ref, self.run_loc, self.epoch0_loc, self.epoch0_loc.content_digest, "authority:root", "2026-11-10T00:01:00Z"), self.key_reg_loc)
        cat_svc = GlobalDatasetCatalogService(self.store, self.epoch0_loc, parquet_codec=self.codec, require_signed=True)
        _, ev_oct_loc, _ = self._store_op_read("2026-10-31", "oct", clicks_val="10", collected_at="2026-11-01T03:02:00.000000Z")
        self.gm_oct, self.gm_oct_loc = self._materialize_signed_gen("oct", "genesis", "2026-10-31", ev_oct_loc, self.epoch0_loc, None, None, (), None)
        self.shared_parquet_object_ref = self.gm_oct.parquet_object_locators[0].object_ref
        _, snap0_oct_loc, cut1_loc = self._commit_signed_cut(cat_svc, idx=1, op="add_partition", seq=1, gm=self.gm_oct, gm_loc=self.gm_oct_loc, genesis_loc=self.genesis_loc)
        _, ev_n1_loc, self.inv_loc = self._store_op_read("2026-11-10", "nov1", clicks_val="0", collected_at="2026-11-11T03:02:00.000000Z")
        self.gm_nov1, self.gm_nov1_loc = self._materialize_signed_gen("nov1", "incremental", "2026-11-10", ev_n1_loc, cat_svc.current_head()[0], snap0_oct_loc, cut1_loc, (), None)
        self.snap1, self.snap1_loc, cut2_loc = self._commit_signed_cut(cat_svc, idx=2, op="add_partition", seq=1, gm=self.gm_nov1, gm_loc=self.gm_nov1_loc)
        _, ev_n2_loc, _ = self._store_op_read("2026-11-10", "nov2", clicks_val="0", collected_at="2026-11-11T03:04:00.000000Z")
        self.gm_nov2, self.gm_nov2_loc = self._materialize_signed_gen("nov2", "incremental", "2026-11-10", ev_n2_loc, cat_svc.current_head()[0], self.snap1_loc, cut2_loc, (self.gm_nov1_loc,), self.gm_nov1_loc)
        self.snap2, self.snap2_loc, _ = self._commit_signed_cut(cat_svc, idx=3, op="replace_partition", seq=2, gm=self.gm_nov2, gm_loc=self.gm_nov2_loc)
        self.nov2_parquet_object_ref = self.gm_nov2.parquet_object_locators[0].object_ref

    def _build_signed_report(
        self, tag: str, snap_loc: ArtifactLocator, cur_loc: ArtifactLocator, hist_locs: tuple[ArtifactLocator, ...]
    ) -> tuple[ReportExecution, ArtifactLocator]:
        cols = tuple(ResultColumn(n, t, nl) for n, t, nl in METRIC_WINDOW_COLUMNS)
        q_m = DuckDbQueryDefinition("result:metrics", "query:metrics", _LIVE_METRICS_WINDOW_SQL, self.metrics_schema_loc, "relation", cols, _METRIC_UKEY, _METRIC_ORDER)
        exts = (DuckDbExtensionSpec("parquet", "1.5.5", "explicit_local_binary", DuckDbExtensionBinaryLocator.for_binary_bytes(self.ext_bytes)),)
        bi_locs = sort_artifact_locators((self.tmpl_loc, self.wheel_prov_loc))
        raw_b = AnalysisReplayInputBundle(f"bundle:{tag}", self.run_loc, snap_loc, "1.5.5", DuckDbBinaryObjectLocator.for_binary_bytes(self.duck_bytes), exts, (DuckDbSessionSetting("threads", TaggedScalarCell("int64", "1")),), (), (q_m,), self.policy_loc, bi_locs)
        _, b_loc = _put_signed_model(self.store, raw_b, self.key_reg_loc)
        engine = DeterministicInMemoryDuckDbEngine()
        u_exec, _, u_res = execute_analysis_replay_bundle(bundle_locator=b_loc, store=self.store, parquet_codec=self.codec, duckdb_engine=engine, require_signed_inputs=True)
        s_res, _ = _put_signed_model(self.store, u_res[0][0], self.key_reg_loc)
        from smart_ads.analytics.results import AnalysisExecution, CanonicalResultEntry, CanonicalResultSet
        s_exec_pre, _ = _put_signed_model(self.store, AnalysisExecution(b_loc, CanonicalResultSet.build(b_loc, (CanonicalResultEntry.from_result(s_res),))), self.key_reg_loc)
        _, s_exec_loc, _ = execute_analysis_replay_bundle(bundle_locator=b_loc, store=self.store, parquet_codec=self.codec, duckdb_engine=engine, result_integrities={"result:metrics": s_res.integrity}, execution_integrity=s_exec_pre.integrity, require_signed_inputs=True)  # type: ignore[dict-item]
        attested = (AttestedCertificationInput(CertificationInput(DerivedCertificationStatus.VERIFIED, "phase1_7b_base"), True),)
        u_rep, _, u_cert, _, u_f = execute_certified_report(report_id=f"report:{tag}", executed_at_utc="2026-11-11T03:20:00Z", bundle_locator=b_loc, execution_locator=s_exec_loc, evaluation_context=self.eval_ctx, expected_resource_inventory_locator=self.eval_inv_loc, curation_execution_locator=cur_loc, restatement_history_generation_locators=hist_locs, attested_certification_inputs=attested, report_template_provenance_locator=self.tmpl_loc, render_algorithm_identity=self.render_alg, store=self.store, parquet_codec=self.codec)
        f_ints = tuple(_put_signed_model(self.store, f, self.key_reg_loc)[0].integrity for f, _ in u_f)
        _, _, u_cert2, _, _ = execute_certified_report(report_id=f"report:{tag}", executed_at_utc="2026-11-11T03:20:00Z", bundle_locator=b_loc, execution_locator=s_exec_loc, evaluation_context=self.eval_ctx, expected_resource_inventory_locator=self.eval_inv_loc, curation_execution_locator=cur_loc, restatement_history_generation_locators=hist_locs, attested_certification_inputs=attested, report_template_provenance_locator=self.tmpl_loc, render_algorithm_identity=self.render_alg, store=self.store, parquet_codec=self.codec, finding_integrities=f_ints)  # type: ignore[arg-type]
        c_int = _put_signed_model(self.store, u_cert2, self.key_reg_loc)[0].integrity
        u_rep3, _, _, _, _ = execute_certified_report(report_id=f"report:{tag}", executed_at_utc="2026-11-11T03:20:00Z", bundle_locator=b_loc, execution_locator=s_exec_loc, evaluation_context=self.eval_ctx, expected_resource_inventory_locator=self.eval_inv_loc, curation_execution_locator=cur_loc, restatement_history_generation_locators=hist_locs, attested_certification_inputs=attested, report_template_provenance_locator=self.tmpl_loc, render_algorithm_identity=self.render_alg, store=self.store, parquet_codec=self.codec, finding_integrities=f_ints, certification_integrity=c_int)  # type: ignore[arg-type]
        r_int = _put_signed_model(self.store, u_rep3, self.key_reg_loc)[0].integrity
        rep, rep_loc, _, _, _ = execute_certified_report(report_id=f"report:{tag}", executed_at_utc="2026-11-11T03:20:00Z", bundle_locator=b_loc, execution_locator=s_exec_loc, evaluation_context=self.eval_ctx, expected_resource_inventory_locator=self.eval_inv_loc, curation_execution_locator=cur_loc, restatement_history_generation_locators=hist_locs, attested_certification_inputs=attested, report_template_provenance_locator=self.tmpl_loc, render_algorithm_identity=self.render_alg, store=self.store, parquet_codec=self.codec, finding_integrities=f_ints, certification_integrity=c_int, report_integrity=r_int, require_signed_inputs=True)  # type: ignore[arg-type]
        return rep, rep_loc

    def _init_reports_and_roots(self) -> None:
        raw_pol = AnalysisPolicy.from_dict({
            "$schema": "smart_ads/analysis_policy/v1", "policy_id": "policy:waste-v1", "policy_version": "1", "tenant_ref": "tenant:ibvi",
            "applicability_scope": {"resource_scope_ref": "scope:campaigns-active", "resource_level": "campaign", "ad_platform_ref": "meta", "currency": "BRL"},
            "validity": {"valid_from_utc": "2026-01-01T00:00:00.000000Z", "valid_until_utc": "2027-01-01T00:00:00.000000Z"},
            "rules": [{"rule_id": "rule:waste-3d", "rule_type": "waste", "window_days": 3, "spend_metric_ref": "metric:spend_v1", "outcome_metric_ref": "metric:clicks_v1", "min_spend_minor": "1000", "max_outcome_count": "0"}],
        })
        self.policy, self.policy_loc = _put_signed_model(self.store, raw_pol, self.key_reg_loc)
        cols = tuple(ResultColumn(n, t, nl) for n, t, nl in METRIC_WINDOW_COLUMNS)
        _, self.metrics_schema_loc = _put_signed_model(self.store, AnalysisResultSchema("relation", cols, _METRIC_UKEY), self.key_reg_loc)
        eval_inv, self.eval_inv_loc = _put_signed_model(
            self.store,
            ExpectedResourceInventory("inventory:eval-001", self.reg_loc, self.reg_loc.content_digest, "tenant:ibvi", "binding:meta-primary", "account:ibvi-01", "scope:campaigns-active", DateRange("2026-11-01", "2026-11-10", True), (ExpectedResourceKey("binding:meta-primary", "account:ibvi-01", _CAMP_A, "campaign", "2026-11-10"),)),
            self.key_reg_loc,
        )
        self.eval_ctx = EvaluationContext(self.policy, EvaluationScope("tenant:ibvi", "scope:campaigns-active", "campaign", "meta", "BRL"), "2026-11-11T03:15:00.000000Z", "2026-11-10", 7, "2026-11-10", eval_inv, "result:metrics", ())
        self.rep1, self.rep1_loc = self._build_signed_report("r1", self.snap1_loc, self.gm_nov1.curation_execution_locator, ())
        self.rep2, self.rep2_loc = self._build_signed_report("r2", self.snap2_loc, self.gm_nov2.curation_execution_locator, (self.gm_nov1_loc,))
        u_r1, _ = build_retention_root(root_id="root:r1", cell_ref=self.cell_ref, migration_run_context_locator=self.run_loc, target_artifact_locator=self.rep1_loc, created_at_utc="2026-11-11T03:25:00Z", store=self.store, parquet_codec=self.codec, integrity=P1Integrity(_KEY_ID, self.key_reg_loc))
        self.root1, self.root1_loc = _put_signed_model(self.store, u_r1, self.key_reg_loc)
        u_r2, _ = build_retention_root(root_id="root:r2", cell_ref=self.cell_ref, migration_run_context_locator=self.run_loc, target_artifact_locator=self.rep2_loc, created_at_utc="2026-11-11T03:26:00Z", store=self.store, parquet_codec=self.codec, integrity=P1Integrity(_KEY_ID, self.key_reg_loc))
        self.root2, self.root2_loc = _put_signed_model(self.store, u_r2, self.key_reg_loc)
        self.head0, self.head0_loc = _put_signed_model(self.store, RetentionRootSetHead("head:0", self.cell_ref, 0, (), None, "2026-11-11T03:24:00Z"), self.key_reg_loc)
        self.service = RetentionRootSetService(self.store, self.head0_loc, parquet_codec=self.codec)
        self.admit_root(self.service, (self.root1_loc,), tag="adm1")
        self.admit_root(self.service, (self.root2_loc,), tag="adm2")

    def authorize_admission(
        self, svc: RetentionRootSetService, root_locs: tuple[ArtifactLocator, ...], *, nonce: str,
        override_head_loc: ArtifactLocator | None = None, override_epoch: int | None = None,
    ) -> ArtifactLocator:
        h_loc, head = svc.current_head()
        exp_loc = h_loc if override_head_loc is None else override_head_loc
        exp_ep = head.head_epoch if override_epoch is None else override_epoch
        _, b_dig = head_pinned_object_refs(head, store=self.store, parquet_codec=self.codec)
        adm_closure = compute_retention_reachability_graph(root_locs, store=self.store, parquet_codec=self.codec)
        proposed = sort_artifact_locators((*head.live_root_locators, *root_locs), expected_type=RetentionRoot.SCHEMA)
        after_closure = compute_retention_reachability_graph(proposed, store=self.store, parquet_codec=self.codec)
        target = RetentionRootAdmissionTarget(
            migration_run_context_locator=self.run_loc, cell_ref=self.cell_ref, expected_root_set_head_locator=exp_loc,
            expected_root_set_head_epoch=exp_ep, expected_root_set_head_digest=exp_loc.content_digest,
            admitted_root_locators=root_locs, admitted_object_refs=adm_closure.reachable_object_refs,
            before_reachability_graph_digest=b_dig, after_reachability_graph_digest=after_closure.reachability_graph_digest,
            proposed_root_set_digest=compute_root_locator_set_digest(proposed, allow_empty=False),
        )
        _, auth_loc = _put_signed_model(self.store, AuthorizationReceipt(f"auth:{nonce}", self.run_loc, "retention_root_admission", "retention_root_admission_effect_proof", target, jcs_sha256(target.to_dict()), (), "principal:ret-01", "2026-11-11T03:30:00Z", "2026-11-11T04:30:00Z", nonce), self.key_reg_loc)
        return auth_loc

    def admit_root(
        self, svc: RetentionRootSetService, root_locs: tuple[ArtifactLocator, ...], *, tag: str
    ) -> tuple[RetentionRootAdmissionProof, ArtifactLocator]:
        auth_loc = self.authorize_admission(svc, root_locs, nonce=f"nonce-{tag}")
        return svc.admit_roots(
            authorization_locator=auth_loc, reservation_id=f"reservation:{tag}", reserved_at_utc="2026-11-11T03:31:00Z",
            cas_receipt_id=f"cas:{tag}", cas_linearization_id=f"lin:{tag}", committed_at_utc="2026-11-11T03:32:00Z",
            new_head_id=f"head:{tag}", execution_id=f"exec:{tag}", consumption_id=f"cons:{tag}",
            effect_proof_id=f"efp:{tag}", verified_at_utc="2026-11-11T03:33:00Z",
        )

    def authorize_release(
        self, svc: RetentionRootSetService, released_locs: tuple[ArtifactLocator, ...], *, nonce: str,
        override_released_refs: tuple[str, ...] | None = None,
    ) -> ArtifactLocator:
        h_loc, head = svc.current_head()
        b_objs, b_dig = head_pinned_object_refs(head, store=self.store, parquet_codec=self.codec)
        retained_locs = sort_artifact_locators([r for r in head.live_root_locators if r not in set(released_locs)], expected_type=RetentionRoot.SCHEMA, allow_empty=True)
        after_closure = compute_retention_reachability_graph(retained_locs, store=self.store, parquet_codec=self.codec)
        rel_refs = sort_cell_object_refs(b_objs - set(after_closure.reachable_object_refs), allow_empty=True) if override_released_refs is None else override_released_refs
        target = RetentionReleaseTarget(
            migration_run_context_locator=self.run_loc, cell_ref=self.cell_ref, expected_root_set_head_locator=h_loc,
            expected_root_set_head_epoch=head.head_epoch, expected_root_set_head_digest=h_loc.content_digest,
            released_root_locators=released_locs, retained_root_locators=retained_locs, released_object_refs=rel_refs,
            before_reachability_graph_digest=b_dig, after_reachability_graph_digest=after_closure.reachability_graph_digest,
            proposed_root_set_digest=compute_root_locator_set_digest(retained_locs, allow_empty=True),
        )
        _, auth_loc = _put_signed_model(self.store, AuthorizationReceipt(f"auth:{nonce}", self.run_loc, "retention_release", "retention_release_effect_proof", target, jcs_sha256(target.to_dict()), (), "principal:ret-01", "2026-11-11T03:40:00Z", "2026-11-11T04:40:00Z", nonce), self.key_reg_loc)
        return auth_loc

    def authorize_release_claiming_shared_parquet_object(self) -> ArtifactLocator:
        _, head = self.service.current_head()
        b_objs, _ = head_pinned_object_refs(head, store=self.store, parquet_codec=self.codec)
        ret_closure = compute_retention_reachability_graph((self.root1_loc,), store=self.store, parquet_codec=self.codec)
        bad_refs = sort_cell_object_refs((*(b_objs - set(ret_closure.reachable_object_refs)), self.shared_parquet_object_ref))
        return self.authorize_release(self.service, (self.root2_loc,), nonce="nonce-rel-shared-bad", override_released_refs=bad_refs)

    def call_release(
        self, svc: RetentionRootSetService, auth_loc: ArtifactLocator, *, reservation_id: str, tag: str = "rel"
    ) -> tuple[RetentionReleaseProof, ArtifactLocator]:
        return svc.release_roots(
            authorization_locator=auth_loc, reservation_id=reservation_id, reserved_at_utc="2026-11-11T03:41:00Z",
            cas_receipt_id=f"cas:{tag}:{reservation_id}", cas_linearization_id=f"lin:{tag}:{reservation_id}",
            committed_at_utc="2026-11-11T03:42:00Z", new_head_id=f"head:{tag}:{reservation_id}",
            execution_id=f"exec:{tag}:{reservation_id}", consumption_id=f"cons:{tag}:{reservation_id}",
            effect_proof_id=f"efp:{tag}:{reservation_id}", verified_at_utc="2026-11-11T03:43:00Z",
        )


    def clone(self) -> RetentionWorld:
        cloned = object.__new__(RetentionWorld)
        cloned.__dict__.update(self.__dict__)
        cloned.store = InMemoryCellObjectStore()
        cloned.store._blobs = dict(self.store._blobs)
        cloned.service = RetentionRootSetService(cloned.store, cloned.head0_loc, parquet_codec=cloned.codec)
        cloned.admit_root(cloned.service, (cloned.root1_loc,), tag="adm1")
        cloned.admit_root(cloned.service, (cloned.root2_loc,), tag="adm2")
        return cloned


@pytest.fixture(scope="module")
def base_retention_world() -> RetentionWorld:
    return RetentionWorld()


@pytest.fixture
def retention_world(base_retention_world: RetentionWorld) -> RetentionWorld:
    return base_retention_world.clone()


def test_public_exports_and_full_end_to_end_reachability_closure(base_retention_world: RetentionWorld) -> None:
    rw = base_retention_world
    for sym in (
        "ReachabilityClosure", "RetentionRootSetService", "WheelObjectLocator", "build_retention_root",
        "compute_retention_reachability_graph", "head_pinned_object_refs",
        "verify_retention_release_proof", "verify_retention_root", "verify_retention_root_admission_proof",
    ):
        assert sym in application_pkg.__all__ and hasattr(application_pkg, sym)
    closure = compute_retention_reachability_graph((rw.rep2_loc,), store=rw.store, parquet_codec=rw.codec)
    refs = set(closure.reachable_object_refs)
    loc_types = {loc.artifact_type for loc in closure.reachable_artifact_locators}
    for required_ref in (
        rw.rep2_loc.object_ref, rw.duck_ref, rw.ext_ref, rw.wheel_ref,
        rw.shared_parquet_object_ref, rw.gm_nov1.parquet_object_locators[0].object_ref,
        rw.nov2_parquet_object_ref, rw.run_loc.object_ref, rw.key_reg_loc.object_ref,
        rw.inv_loc.object_ref, rw.driver_loc.object_ref, rw.prereqs.delegation_context_locator.object_ref,  # type: ignore[union-attr]
    ):
        assert required_ref in refs
    for expected_schema in (
        "smart_ads/report_execution/v1", "smart_ads/certification_record/v1", "smart_ads/finding/v1",
        "smart_ads/analysis_execution/v1", "smart_ads/analysis_result/v1", "smart_ads/analysis_result_schema/v1",
        "smart_ads/analysis_replay_input_bundle/v1", "smart_ads/analysis_policy/v1", "smart_ads/dataset_snapshot/v1",
        "smart_ads/dataset_catalog/v1", "smart_ads/dataset_catalog_cut_receipt/v1",
        "smart_ads/dataset_catalog_genesis_record/v1", "smart_ads/dataset_catalog_genesis_consumption_record/v1",
        "smart_ads/generation_manifest/v1", "smart_ads/curation_execution/v1",
        "smart_ads/sanitized_candidate_fact_set/v1", "smart_ads/collection_result/v1",
        "smart_ads/operational_read_evidence/v1", "smart_ads/authorization_receipt/v1",
        "smart_ads/authorization_reservation_record/v1", "smart_ads/execution_receipt/v1",
        "smart_ads/authorization_consumption_record/v1", "smart_ads/effect_proof/v1",
        "smart_ads/admitted_collection/v1", "smart_ads/pipeboard_phase1_contract/v1",
        "smart_ads/expected_resource_inventory/v1", "smart_ads/key_authorization_registry/v1",
    ):
        assert expected_schema in loc_types
    assert rw.root2_loc.object_ref not in rw.root2.pinned_object_refs
    assert rw.rep2_loc.object_ref in rw.root2.pinned_object_refs
    assert verify_retention_root(rw.root2, store=rw.store, parquet_codec=rw.codec, require_signed=True).reachable_object_refs == rw.root2.pinned_object_refs


class _OverlayStore(CellObjectStorePort):
    """Test proxy store injecting missing objects, binary tampering, or synthetic locator cycles."""

    def __init__(self, base: CellObjectStorePort, *, drop_refs: set[str] | None = None, raw_overrides: Mapping[str, bytes] | None = None, json_overrides: Mapping[str, dict[str, Any]] | None = None) -> None:
        self._base = base
        self._drop = drop_refs or set()
        self._raw = dict(raw_overrides or {})
        self._json = dict(json_overrides or {})

    def put_bytes(self, raw: bytes) -> str:
        return self._base.put_bytes(raw)

    def get_bytes(self, object_ref: str, *, expected_size_bytes: int | None = None) -> bytes:
        if object_ref in self._drop:
            raise ClosedValidationError(f"missing {object_ref!r}")
        if object_ref in self._raw:
            return self._raw[object_ref]
        return self._base.get_bytes(object_ref, expected_size_bytes=expected_size_bytes)

    def has_object(self, object_ref: str) -> bool:
        return False if object_ref in self._drop else (object_ref in self._raw or self._base.has_object(object_ref))

    def put_json_artifact(self, schema_id: str, payload: Mapping[str, Any]) -> ArtifactLocator:
        return self._base.put_json_artifact(schema_id, payload)

    def get_json_artifact(self, locator: ArtifactLocator) -> dict[str, Any]:
        if locator.object_ref in self._drop:
            raise ClosedValidationError(f"missing {locator.object_ref!r}")
        if locator.object_ref in self._json:
            return self._json[locator.object_ref]
        return self._base.get_json_artifact(locator)


def test_reachability_fails_closed_on_missing_corrupt_binary_root_tamper_or_cycle(base_retention_world: RetentionWorld) -> None:
    rw = base_retention_world
    for missing_ref in (rw.key_reg_loc.object_ref, rw.shared_parquet_object_ref, rw.duck_ref, rw.wheel_ref):
        bad_store = _OverlayStore(rw.store, drop_refs={missing_ref})
        with pytest.raises(ClosedValidationError):
            compute_retention_reachability_graph((rw.rep2_loc,), store=bad_store, parquet_codec=rw.codec)
    for bad_raw in ({rw.duck_ref: b"wrong-size"}, {rw.duck_ref: b"X" * len(rw.duck_bytes)}, {rw.nov2_parquet_object_ref: b"X" * rw.gm_nov2.parquet_object_locators[0].size_bytes}):
        with pytest.raises(ClosedValidationError):
            compute_retention_reachability_graph((rw.rep2_loc,), store=_OverlayStore(rw.store, raw_overrides=bad_raw), parquet_codec=rw.codec)

    loc_a = ArtifactLocator.from_digest("smart_ads/migration_run_context/v1", "sha256:" + ("a" * 64))
    loc_b = ArtifactLocator.from_digest("smart_ads/migration_run_context/v1", "sha256:" + ("b" * 64))
    cyc_2 = _OverlayStore(rw.store, json_overrides={
        loc_a.object_ref: {"$schema": loc_a.artifact_type, "next": loc_b.to_dict()},
        loc_b.object_ref: {"$schema": loc_b.artifact_type, "next": loc_a.to_dict()},
    })
    with pytest.raises(ClosedValidationError, match="cycle"):
        compute_retention_reachability_graph((loc_a,), store=cyc_2)
    cyc_1 = _OverlayStore(rw.store, json_overrides={loc_a.object_ref: {"$schema": loc_a.artifact_type, "self": loc_a.to_dict()}})
    with pytest.raises(ClosedValidationError, match="cycle"):
        compute_retention_reachability_graph((loc_a,), store=cyc_1)

    dropped_target_refs = tuple(r for r in rw.root1.pinned_object_refs if r != rw.rep1_loc.object_ref)
    bad_root = RetentionRoot("root:bad", rw.cell_ref, rw.run_loc, rw.rep1_loc, dropped_target_refs, "2026-11-11T03:25:00Z")
    with pytest.raises(ClosedValidationError):
        verify_retention_root(bad_root, store=rw.store, parquet_codec=rw.codec)
    malformed_pol = {**rw.policy.to_dict(), "unexpected_field": 1}
    with pytest.raises(ClosedValidationError):
        compute_retention_reachability_graph((rw.rep2_loc,), store=_OverlayStore(rw.store, json_overrides={rw.policy_loc.object_ref: malformed_pol}), parquet_codec=rw.codec)
    with pytest.raises(ClosedValidationError):
        build_retention_root(root_id="root:nested", cell_ref=rw.cell_ref, migration_run_context_locator=rw.run_loc, target_artifact_locator=rw.root1_loc, created_at_utc="2026-11-11T03:25:00Z", store=rw.store)


def test_admit_roots_quarantines_in_doubt_on_missing_reachable_object_or_stale_head(retention_world: RetentionWorld) -> None:
    rw = retention_world
    svc = RetentionRootSetService(rw.store, rw.head0_loc, parquet_codec=rw.codec)
    p1, _ = rw.admit_root(svc, (rw.root1_loc,), tag="s1")
    assert svc.current_head()[1].head_epoch == 1
    assert verify_retention_root_admission_proof(p1, store=rw.store, parquet_codec=rw.codec) == p1

    # Stale head (authorizing against epoch 0 when current head is already epoch 1)
    stale_auth = rw.authorize_admission(svc, (rw.root2_loc,), nonce="nonce-stale-adm", override_head_loc=rw.head0_loc, override_epoch=0)
    head_before_stale = svc.current_head()
    with pytest.raises(ClosedValidationError):
        svc.admit_roots(
            authorization_locator=stale_auth, reservation_id="resv:stale", reserved_at_utc="2026-11-11T03:31:00Z",
            cas_receipt_id="cas:stale", cas_linearization_id="lin:stale", committed_at_utc="2026-11-11T03:32:00Z",
            new_head_id="head:stale", execution_id="exec:stale", consumption_id="cons:stale",
            effect_proof_id="efp:stale", verified_at_utc="2026-11-11T03:33:00Z",
        )
    assert svc.reservation_status_for(stale_auth) == "in_doubt"
    assert svc.current_head() == head_before_stale
    with pytest.raises(ClosedValidationError):
        svc.admit_roots(
            authorization_locator=stale_auth, reservation_id="resv:stale-retry", reserved_at_utc="2026-11-11T03:31:00Z",
            cas_receipt_id="cas:stale2", cas_linearization_id="lin:stale2", committed_at_utc="2026-11-11T03:32:00Z",
            new_head_id="head:stale2", execution_id="exec:stale2", consumption_id="cons:stale2",
            effect_proof_id="efp:stale2", verified_at_utc="2026-11-11T03:33:00Z",
        )

    # Missing transitively reachable object at admission time -> quarantined in_doubt
    auth_ok_in_base = rw.authorize_admission(svc, (rw.root2_loc,), nonce="nonce-miss-obj")
    gap_store = _OverlayStore(rw.store, drop_refs={rw.nov2_parquet_object_ref})
    gap_svc = RetentionRootSetService(gap_store, svc.current_head()[0], parquet_codec=rw.codec)
    with pytest.raises(ClosedValidationError):
        gap_svc.admit_roots(
            authorization_locator=auth_ok_in_base, reservation_id="resv:gap", reserved_at_utc="2026-11-11T03:31:00Z",
            cas_receipt_id="cas:gap", cas_linearization_id="lin:gap", committed_at_utc="2026-11-11T03:32:00Z",
            new_head_id="head:gap", execution_id="exec:gap", consumption_id="cons:gap",
            effect_proof_id="efp:gap", verified_at_utc="2026-11-11T03:33:00Z",
        )
    assert gap_svc.reservation_status_for(auth_ok_in_base) == "in_doubt"
    assert gap_svc.current_head()[1].head_epoch == 1


def test_release_blocks_and_quarantines_nonce_when_retained_root_reaches_target_object(
    retention_world: Any,
) -> None:
    svc = retention_world.service
    bad_auth_loc = retention_world.authorize_release_claiming_shared_parquet_object()
    with pytest.raises(ClosedValidationError, match="retained"):
        retention_world.call_release(svc, bad_auth_loc, reservation_id="reservation:r-bad")
    assert svc.reservation_status_for(bad_auth_loc) == "in_doubt"
    assert retention_world.store.has_object(retention_world.shared_parquet_object_ref) is True


def test_release_preserves_shared_objects_blocks_replay_and_never_deletes_bytes(retention_world: RetentionWorld) -> None:
    rw = retention_world
    svc = rw.service
    # Under-claiming released_object_refs (empty tuple when exclusive objects exist) also quarantines in_doubt
    under_auth = rw.authorize_release(svc, (rw.root2_loc,), nonce="nonce-under", override_released_refs=())
    with pytest.raises(ClosedValidationError):
        rw.call_release(svc, under_auth, reservation_id="resv:under")
    assert svc.reservation_status_for(under_auth) == "in_doubt"
    assert svc.current_head()[1].head_epoch == 2

    # Valid logical release of root_2 (epoch 2 -> 3) while root_1 stays retained
    before_objs, _ = head_pinned_object_refs(svc.current_head()[1], store=rw.store, parquet_codec=rw.codec)
    rel_auth = rw.authorize_release(svc, (rw.root2_loc,), nonce="nonce-rel-r2")
    rel_proof, _ = rw.call_release(svc, rel_auth, reservation_id="resv:rel-r2", tag="ok2")
    assert svc.reservation_status_for(rel_auth) == "consumed"
    assert svc.current_head()[1].head_epoch == 3
    assert svc.current_head()[1].live_root_locators == (rw.root1_loc,)
    assert rw.shared_parquet_object_ref in rel_proof.retained_object_refs
    assert rw.shared_parquet_object_ref not in rel_proof.released_object_refs
    assert rw.nov2_parquet_object_ref in rel_proof.released_object_refs
    assert verify_retention_release_proof(rel_proof, store=rw.store, parquet_codec=rw.codec) == rel_proof
    # Replay of consumed release authorization rejected
    with pytest.raises(ClosedValidationError):
        rw.call_release(svc, rel_auth, reservation_id="resv:rel-r2-replay", tag="rep")
    # Every single physical object (including logically unpinned ones) remains intact in CellObjectStorePort
    for obj_ref in before_objs:
        assert rw.store.has_object(obj_ref) is True

    # Release final root_1 (epoch 3 -> 4) to empty live root set
    rel_all_auth = rw.authorize_release(svc, (rw.root1_loc,), nonce="nonce-rel-r1")
    rel_all_proof, _ = rw.call_release(svc, rel_all_auth, reservation_id="resv:rel-r1", tag="ok1")
    assert rel_all_proof.retained_root_locators == () and rel_all_proof.retained_object_refs == ()
    assert verify_retention_release_proof(rel_all_proof, store=rw.store, parquet_codec=rw.codec) == rel_all_proof
    assert rw.store.has_object(rw.shared_parquet_object_ref) is True


def _compute_signed_admission_integrities(
    rw: RetentionWorld, auth_loc: ArtifactLocator, *, tag: str
) -> dict[str, P1Integrity]:
    auth = AuthorizationReceipt.from_dict(rw.store.get_json_artifact(auth_loc), require_signed=True)
    target: RetentionRootAdmissionTarget = auth.subject  # type: ignore[assignment]
    resv_d = _sign_payload(AuthorizationReservationRecord(f"resv:{tag}", rw.run_loc, auth_loc, auth_loc.content_digest, auth.single_use_nonce, auth.action, auth.dag_slot, target, "reserved", None, "2026-11-11T03:31:00Z").to_dict(), rw.key_reg_loc)
    resv = AuthorizationReservationRecord.from_dict(resv_d, require_signed=True)
    nh_d = _sign_payload(RetentionRootSetHead(f"head:{tag}", rw.cell_ref, target.expected_root_set_head_epoch + 1, target.admitted_root_locators, target.expected_root_set_head_locator, "2026-11-11T03:32:00Z").to_dict(), rw.key_reg_loc)
    nh = RetentionRootSetHead.from_dict(nh_d, require_signed=True)
    proj = RetentionRootSetCasRequestProjection("admit_roots", target.expected_root_set_head_epoch, target.expected_root_set_head_digest, target.admitted_root_locators, target.proposed_root_set_digest)
    cas_d = _sign_payload(RetentionRootSetCasReceipt(f"cas:{tag}", rw.cell_ref, "admit_roots", proj, target.expected_root_set_head_locator, target.expected_root_set_head_digest, target.expected_root_set_head_epoch, nh.locator(), nh.locator().content_digest, nh.head_epoch, "committed", f"lin:{tag}", "2026-11-11T03:32:00Z").to_dict(), rw.key_reg_loc)
    cas = RetentionRootSetCasReceipt.from_dict(cas_d, require_signed=True)
    res_d = _sign_payload(RetentionRootAdmissionResult(rw.run_loc, rw.cell_ref, cas.locator(), cas.locator().content_digest, f"lin:{tag}", target.expected_root_set_head_locator, target.expected_root_set_head_digest, nh.locator(), nh.locator().content_digest, target.admitted_root_locators, target.admitted_object_refs, "admitted", "2026-11-11T03:32:00Z").to_dict(), rw.key_reg_loc)
    adm_res = RetentionRootAdmissionResult.from_dict(res_d, require_signed=True)
    ex_d = _sign_payload(ExecutionReceipt(f"exec:{tag}", rw.run_loc, auth_loc, resv.locator(), auth.single_use_nonce, auth.action, auth.dag_slot, target, "succeeded", adm_res.locator(), "2026-11-11T03:32:00Z").to_dict(), rw.key_reg_loc)
    ex = ExecutionReceipt.from_dict(ex_d, require_signed=True)
    cn_d = _sign_payload(AuthorizationConsumptionRecord(f"cons:{tag}", rw.run_loc, auth_loc, auth_loc.content_digest, resv.locator(), ex.locator(), auth.single_use_nonce, auth.action, auth.dag_slot, "consumed", "2026-11-11T03:32:00Z").to_dict(), rw.key_reg_loc)
    cn = AuthorizationConsumptionRecord.from_dict(cn_d, require_signed=True)
    ef_d = _sign_payload(EffectProof(f"efp:{tag}", rw.run_loc, auth.action, auth.dag_slot, auth_loc, resv.locator(), ex.locator(), cn.locator(), adm_res.locator(), "2026-11-11T03:33:00Z").to_dict(), rw.key_reg_loc)
    ef = EffectProof.from_dict(ef_d, require_signed=True)
    pf_d = _sign_payload(RetentionRootAdmissionProof(rw.run_loc, rw.cell_ref, ef.locator(), adm_res.locator(), cas.locator(), target.expected_root_set_head_locator, nh.locator(), target.admitted_root_locators, target.admitted_object_refs, target.before_reachability_graph_digest, target.after_reachability_graph_digest, "2026-11-11T03:33:00Z").to_dict(), rw.key_reg_loc)
    pf = RetentionRootAdmissionProof.from_dict(pf_d, require_signed=True)
    return {k: v.integrity for k, v in (("reservation", resv), ("new_head", nh), ("cas_receipt", cas), ("admission_result", adm_res), ("execution", ex), ("consumption", cn), ("effect_proof", ef), ("admission_proof", pf)) if v.integrity is not None}


def _compute_signed_release_integrities(
    rw: RetentionWorld, auth_loc: ArtifactLocator, *, tag: str
) -> dict[str, P1Integrity]:
    auth = AuthorizationReceipt.from_dict(rw.store.get_json_artifact(auth_loc), require_signed=True)
    target: RetentionReleaseTarget = auth.subject  # type: ignore[assignment]
    ret_refs = compute_retention_reachability_graph(target.retained_root_locators, store=rw.store, parquet_codec=rw.codec).reachable_object_refs
    resv = AuthorizationReservationRecord.from_dict(_sign_payload(AuthorizationReservationRecord(f"resv:{tag}", rw.run_loc, auth_loc, auth_loc.content_digest, auth.single_use_nonce, auth.action, auth.dag_slot, target, "reserved", None, "2026-11-11T03:41:00Z").to_dict(), rw.key_reg_loc), require_signed=True)
    nh = RetentionRootSetHead.from_dict(_sign_payload(RetentionRootSetHead(f"head:{tag}", rw.cell_ref, target.expected_root_set_head_epoch + 1, target.retained_root_locators, target.expected_root_set_head_locator, "2026-11-11T03:42:00Z").to_dict(), rw.key_reg_loc), require_signed=True)
    proj = RetentionRootSetCasRequestProjection("release_roots", target.expected_root_set_head_epoch, target.expected_root_set_head_digest, target.released_root_locators, target.proposed_root_set_digest)
    cas = RetentionRootSetCasReceipt.from_dict(_sign_payload(RetentionRootSetCasReceipt(f"cas:{tag}", rw.cell_ref, "release_roots", proj, target.expected_root_set_head_locator, target.expected_root_set_head_digest, target.expected_root_set_head_epoch, nh.locator(), nh.locator().content_digest, nh.head_epoch, "committed", f"lin:{tag}", "2026-11-11T03:42:00Z").to_dict(), rw.key_reg_loc), require_signed=True)
    rel_res = RetentionReleaseResult.from_dict(_sign_payload(RetentionReleaseResult(rw.run_loc, rw.cell_ref, cas.locator(), cas.locator().content_digest, f"lin:{tag}", target.expected_root_set_head_locator, target.expected_root_set_head_digest, nh.locator(), nh.locator().content_digest, target.released_root_locators, target.released_object_refs, "logically_unpinned", "2026-11-11T03:42:00Z").to_dict(), rw.key_reg_loc), require_signed=True)
    ex = ExecutionReceipt.from_dict(_sign_payload(ExecutionReceipt(f"exec:{tag}", rw.run_loc, auth_loc, resv.locator(), auth.single_use_nonce, auth.action, auth.dag_slot, target, "succeeded", rel_res.locator(), "2026-11-11T03:42:00Z").to_dict(), rw.key_reg_loc), require_signed=True)
    cn = AuthorizationConsumptionRecord.from_dict(_sign_payload(AuthorizationConsumptionRecord(f"cons:{tag}", rw.run_loc, auth_loc, auth_loc.content_digest, resv.locator(), ex.locator(), auth.single_use_nonce, auth.action, auth.dag_slot, "consumed", "2026-11-11T03:42:00Z").to_dict(), rw.key_reg_loc), require_signed=True)
    ef = EffectProof.from_dict(_sign_payload(EffectProof(f"efp:{tag}", rw.run_loc, auth.action, auth.dag_slot, auth_loc, resv.locator(), ex.locator(), cn.locator(), rel_res.locator(), "2026-11-11T03:43:00Z").to_dict(), rw.key_reg_loc), require_signed=True)
    pf = RetentionReleaseProof.from_dict(_sign_payload(RetentionReleaseProof(rw.run_loc, rw.cell_ref, ef.locator(), rel_res.locator(), cas.locator(), target.expected_root_set_head_locator, nh.locator(), target.released_root_locators, target.retained_root_locators, target.released_object_refs, ret_refs, target.before_reachability_graph_digest, target.after_reachability_graph_digest, True, "2026-11-11T03:43:00Z").to_dict(), rw.key_reg_loc), require_signed=True)
    return {k: v.integrity for k, v in (("reservation", resv), ("new_head", nh), ("cas_receipt", cas), ("release_result", rel_res), ("execution", ex), ("consumption", cn), ("effect_proof", ef), ("release_proof", pf)) if v.integrity is not None}


def test_signed_mode_enforces_p1_signatures_across_service_and_verifiers(retention_world: RetentionWorld) -> None:
    rw = retention_world
    signed_svc = RetentionRootSetService(rw.store, rw.head0_loc, parquet_codec=rw.codec, require_signed=True)
    auth_loc = rw.authorize_admission(signed_svc, (rw.root1_loc,), nonce="nonce-signed-1")
    with pytest.raises(ClosedValidationError):
        signed_svc.admit_roots(
            authorization_locator=auth_loc, reservation_id="resv:unsigned-fail", reserved_at_utc="2026-11-11T03:31:00Z",
            cas_receipt_id="cas:uf", cas_linearization_id="lin:uf", committed_at_utc="2026-11-11T03:32:00Z",
            new_head_id="head:uf", execution_id="exec:uf", consumption_id="cons:uf",
            effect_proof_id="efp:uf", verified_at_utc="2026-11-11T03:33:00Z",
        )
    assert signed_svc.reservation_status_for(auth_loc) is None
    ints = _compute_signed_admission_integrities(rw, auth_loc, tag="sg1")
    proof, _ = signed_svc.admit_roots(
        authorization_locator=auth_loc, reservation_id="resv:sg1", reserved_at_utc="2026-11-11T03:31:00Z",
        cas_receipt_id="cas:sg1", cas_linearization_id="lin:sg1", committed_at_utc="2026-11-11T03:32:00Z",
        new_head_id="head:sg1", execution_id="exec:sg1", consumption_id="cons:sg1",
        effect_proof_id="efp:sg1", verified_at_utc="2026-11-11T03:33:00Z", integrities=ints,
    )
    assert proof.integrity is not None and proof.integrity.is_signed
    assert verify_retention_root_admission_proof(proof, store=rw.store, parquet_codec=rw.codec, require_signed=True) == proof
    with pytest.raises(ClosedValidationError):
        verify_retention_root_admission_proof(replace(proof, integrity=P1Integrity(_KEY_ID, rw.key_reg_loc)), store=rw.store, parquet_codec=rw.codec, require_signed=True)

    rel_auth = rw.authorize_release(signed_svc, (rw.root1_loc,), nonce="nonce-signed-rel-1")
    rel_ints = _compute_signed_release_integrities(rw, rel_auth, tag="sgr1")
    rel_pf, _ = signed_svc.release_roots(
        authorization_locator=rel_auth, reservation_id="resv:sgr1", reserved_at_utc="2026-11-11T03:41:00Z",
        cas_receipt_id="cas:sgr1", cas_linearization_id="lin:sgr1", committed_at_utc="2026-11-11T03:42:00Z",
        new_head_id="head:sgr1", execution_id="exec:sgr1", consumption_id="cons:sgr1",
        effect_proof_id="efp:sgr1", verified_at_utc="2026-11-11T03:43:00Z", integrities=rel_ints,
    )
    assert verify_retention_release_proof(rel_pf, store=rw.store, parquet_codec=rw.codec, require_signed=True) == rel_pf
    with pytest.raises(ClosedValidationError):
        verify_retention_release_proof(replace(rel_pf, integrity=P1Integrity(_KEY_ID, rw.key_reg_loc)), store=rw.store, parquet_codec=rw.codec, require_signed=True)
