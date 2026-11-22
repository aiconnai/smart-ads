"""Unit tests for deterministic curation, Parquet generations, global catalog CAS, and dataset snapshots."""
from __future__ import annotations

import dataclasses
import hashlib
from typing import Any

import pytest

from smart_ads.adapters.storage import InMemoryCellObjectStore, StdlibParquetLandingCodec
import smart_ads.application as application_pkg
from smart_ads.application.curation_pipeline import (
    GlobalDatasetCatalogService, build_sanitized_candidate_fact_set, materialize_parquet_generation,
    publish_dataset_snapshot, replay_curated_partition_rows, verify_algorithm_provenance_identity,
    verify_curation_execution, verify_dataset_catalog_cut_receipt, verify_dataset_snapshot,
    verify_generation_manifest, verify_operational_read_evidence, verify_sanitized_candidate_fact_set,
)
from smart_ads.contracts import (
    ArtifactLocator, CanonicalQueryContract, ClosedValidationError, CollectionPurpose,
    CollectionResult, DateRange, FactKey, NormalizedCollectionFact, NormalizedProviderError,
    P1Integrity, PurposePrerequisiteLocators, RetrievalContext, TransportOutcome,
    canonicalize_jcs, compute_normalized_fact_set_digest, p1_content_digest,
)
from smart_ads.contracts.effects import (
    AuthorizationConsumptionRecord, AuthorizationReceipt, AuthorizationReservationRecord,
    EffectProof, ExecutionReceipt, ProviderCallTarget,
)
from smart_ads.contracts.git_provenance import GitArtifactProvenance, compute_git_blob_oid
from smart_ads.contracts.operational_evidence import (
    AlgorithmProvenanceIdentity, OperationalReadEvidence, SanitizedCandidateFactSet,
)
from smart_ads.contracts.schemas import AdmittedCollection, project_collection_fact_to_landing_row
from smart_ads.domain import (
    PINNED_LEGACY_COMMIT, PINNED_LEGACY_REPO, PINNED_PIPEBOARD_D26_SPECS,
    PIPEBOARD_PHASE1_METRIC_SOURCE_MAPPINGS, ExpectedResourceInventory, ExpectedResourceKey,
    LegacySourcePacket, PinnedGitArtifactMember, PinnedUpstreamReference,
    PipeboardPhase1Contract, PipeboardTransportLimits,
)
from smart_ads.domain.catalog import (
    ActivePartitionHead, CatalogCasRequestProjection, DatasetCatalog, DatasetCatalogCutReceipt,
    DatasetCatalogGenesisConsumptionRecord, DatasetCatalogGenesisRecord, DatasetSnapshot,
    GenerationManifest, ParquetObjectLocator, compute_logical_rows_digest,
)
from smart_ads.domain.curation import CurationExecution, compute_curation_window

_METRICS_3 = ("metric:clicks_v1", "metric:impressions_v1", "metric:spend_v1")
_CAMP_A = "resource:" + ("a" * 52)


def _loc(artifact_type: str, fill: str = "a") -> ArtifactLocator:
    return ArtifactLocator.from_digest(artifact_type, "sha256:" + (fill * 64))


def _unsigned_p1() -> P1Integrity:
    return P1Integrity(
        key_id="key:ed25519:" + ("9" * 64),
        key_registry_snapshot_locator=_loc("smart_ads/key_authorization_registry/v1", "8"),
    )


def _signed_p1_for(unsigned_payload: dict[str, Any]) -> P1Integrity:
    base = _unsigned_p1()
    preimage_env = {**unsigned_payload, "integrity": base.to_dict()}
    return P1Integrity(
        key_id=base.key_id,
        key_registry_snapshot_locator=base.key_registry_snapshot_locator,
        content_digest=p1_content_digest(preimage_env),
        signature_base64=("A" * 86) + "==",
    )


def _sign_and_store(store: InMemoryCellObjectStore, schema_id: str, obj: Any) -> tuple[dict[str, Any], ArtifactLocator]:
    unsigned = {k: v for k, v in obj.to_dict().items() if k != "integrity"}
    signed = {**unsigned, "integrity": _signed_p1_for(unsigned).to_dict()}
    return signed, store.put_json_artifact(schema_id, signed)


def _make_prereqs(purpose: CollectionPurpose) -> PurposePrerequisiteLocators:
    if purpose == "fixture_7a":
        return PurposePrerequisiteLocators(
            purpose="fixture_7a",
            sealed_sandbox_profile_locator=_loc("smart_ads/sealed_sandbox_profile/v1", "b"),
            regression_fixture_locator=_loc("smart_ads/regression_fixture/v1", "c"),
        )
    if purpose == "live_verification_7b":
        return PurposePrerequisiteLocators(
            purpose="live_verification_7b",
            legacy_step2_evidence_locator=_loc("smart_ads/legacy_step2_implementation_evidence/v1", "b"),
            live_read_activation_receipt_locator=_loc("smart_ads/smart_ads_live_read_activation_receipt/v1", "c"),
            gate3_selection_receipt_locator=_loc("smart_ads/gate3_selection_receipt/v1", "d"),
            workload_identity_effect_proof_locator=_loc("smart_ads/effect_proof/v1", "e"),
            deployment_effect_proof_locator=_loc("smart_ads/effect_proof/v1", "f"),
        )
    return PurposePrerequisiteLocators(
        purpose="operational_read",
        legacy_step2_evidence_locator=_loc("smart_ads/legacy_step2_implementation_evidence/v1", "b"),
        live_read_activation_receipt_locator=_loc("smart_ads/smart_ads_live_read_activation_receipt/v1", "c"),
        live_certification_head_locator=_loc("smart_ads/live_certification_head/v1", "d"),
        live_certification_transition_locator=_loc("smart_ads/live_certification_transition/v1", "e"),
        live_certification_certificate_locator=_loc("smart_ads/live_certification_certificate/v1", "f"),
        gate3_operational_renewal_locator=_loc("smart_ads/gate3_selection_receipt/v1", "1"),
        workload_identity_effect_proof_locator=_loc("smart_ads/effect_proof/v1", "2"),
        deployment_effect_proof_locator=_loc("smart_ads/effect_proof/v1", "3"),
        delegation_context_locator=_loc("smart_ads/ibvi_ads_delegation_context/v1", "4"),
    )


def _make_facts(
    metric_date: str, *, clicks_val: str | None = "15", clicks_presence: str = "observed", spend_currency: str = "BRL"
) -> tuple[NormalizedCollectionFact, ...]:
    fk_c = FactKey("binding:meta-primary", "account:ibvi-01", _CAMP_A, "campaign", metric_date, "metric:clicks_v1", "source-metric:provider:pipeboard.clicks:v1", "attribution:not_applicable", "breakdown:none")
    fk_i = FactKey("binding:meta-primary", "account:ibvi-01", _CAMP_A, "campaign", metric_date, "metric:impressions_v1", "source-metric:provider:pipeboard.impressions:v1", "attribution:not_applicable", "breakdown:none")
    fk_s = FactKey("binding:meta-primary", "account:ibvi-01", _CAMP_A, "campaign", metric_date, "metric:spend_v1", "source-metric:provider:pipeboard.spend:v1", "attribution:not_applicable", "breakdown:none")
    f_c = NormalizedCollectionFact(
        fk_c, clicks_presence,  # type: ignore[arg-type]
        "int64_count" if clicks_presence == "observed" else None,
        clicks_val if clicks_presence == "observed" else None,
        "count" if clicks_presence == "observed" else None, None,
    )
    f_i = NormalizedCollectionFact(fk_i, "observed", "int64_count", "200", "count", None)
    f_s = NormalizedCollectionFact(fk_s, "observed", "int64_minor_currency", "5000", "minor_currency", spend_currency)
    return compute_normalized_fact_set_digest((f_c, f_i, f_s))[0]


def _clean_transport() -> TransportOutcome:
    return TransportOutcome(True, 200, True, True, False, True, False, False, False, False, False)


class CurationWorld:
    """Self-contained pure in-memory world for curation, Parquet generation, and catalog CAS tests."""

    def __init__(self) -> None:
        self.store, self.codec = InMemoryCellObjectStore(), StdlibParquetLandingCodec()
        self.run_loc = _loc("smart_ads/migration_run_context/v1", "1")
        self.reg_loc = _loc("smart_ads/private_registry_snapshot/v1", "2")
        self.clock_loc = _loc("smart_ads/clock_attestation/v1", "3")
        self.consumed_ledger: set[str] = set()
        self.driver_contract, self.driver_loc = self._store_driver_contract()
        self.san_alg, self.san_git = self._store_algorithm("algorithm:sanitize-v1", SanitizedCandidateFactSet.SCHEMA, b"sanitize-v1")
        self.cur_alg, self.cur_git = self._store_algorithm("algorithm:curate-v1", CurationExecution.SCHEMA, b"curate-v1")
        self.epoch0_cat = DatasetCatalog("catalog:epoch-0", "cell:ibvi-primary", 0, "2026-11-10T00:00:00Z", ())
        self.epoch0_loc = self.store.put_json_artifact(DatasetCatalog.SCHEMA, self.epoch0_cat.to_dict())
        self.genesis_rec = DatasetCatalogGenesisRecord(
            "genesis:cell-ibvi-001", "cell:ibvi-primary", self.run_loc,
            self.epoch0_loc, self.epoch0_loc.content_digest, "authority:bootstrap-root", "2026-11-10T00:01:00Z",
        )
        self.genesis_loc = self.store.put_json_artifact(DatasetCatalogGenesisRecord.SCHEMA, self.genesis_rec.to_dict())
        self.catalog_service = GlobalDatasetCatalogService(
            self.store, self.epoch0_loc, parquet_codec=self.codec, consumed_genesis_digests=self.consumed_ledger
        )

    def _store_driver_contract(self) -> tuple[PipeboardPhase1Contract, ArtifactLocator]:
        members = tuple(
            PinnedGitArtifactMember(role, PINNED_LEGACY_REPO, PINNED_LEGACY_COMMIT, path, blob, sha, _loc(GitArtifactProvenance.SCHEMA, str(i + 1)))
            for i, (role, path, blob, sha) in enumerate(PINNED_PIPEBOARD_D26_SPECS)
        )
        contract = PipeboardPhase1Contract(
            "driver-contract:pipeboard-phase1-v1", "pipeboard_hosted",
            LegacySourcePacket(PINNED_LEGACY_REPO, PINNED_LEGACY_COMMIT, members),
            PinnedUpstreamReference(), PipeboardTransportLimits(), dict(PIPEBOARD_PHASE1_METRIC_SOURCE_MAPPINGS),
        )
        s_dict, loc = _sign_and_store(self.store, PipeboardPhase1Contract.SCHEMA, contract)
        return PipeboardPhase1Contract.from_dict(s_dict, require_signed=True), loc

    def _store_algorithm(self, alg_id: str, schema_id: str, blob: bytes) -> tuple[AlgorithmProvenanceIdentity, GitArtifactProvenance]:
        oid, sha = compute_git_blob_oid(blob), "sha256:" + hashlib.sha256(blob).hexdigest()
        prov = GitArtifactProvenance("aiconnai/smart-ads", "a" * 40, "src/smart_ads/application/curation_pipeline.py", oid, sha, "2026-11-10T00:00:00Z")
        s_dict, prov_loc = _sign_and_store(self.store, GitArtifactProvenance.SCHEMA, prov)
        signed_prov = GitArtifactProvenance.from_dict(s_dict, require_signed=True)
        ident = AlgorithmProvenanceIdentity(
            alg_id, "1.0.0", prov_loc, signed_prov.repository, signed_prov.commit_sha,
            signed_prov.path, signed_prov.git_blob_oid, signed_prov.file_content_sha256, "cpython-3.12", schema_id,
        )
        return ident, signed_prov

    def store_admitted_and_inventory(
        self, metric_date: str, *, tag: str = "001", purpose: CollectionPurpose = "operational_read", signed: bool = True
    ) -> tuple[AdmittedCollection, ArtifactLocator, ExpectedResourceInventory, ArtifactLocator]:
        dr = DateRange(metric_date, metric_date, True)
        cqc = CanonicalQueryContract(
            "tenant:ibvi", "binding:meta-primary", "account:ibvi-01", "scope:campaigns-active",
            "meta", "previous_local_day", dr, "America/Sao_Paulo", "2026a", "campaign", _METRICS_3, ("cap:meta_daily_campaign_v1",),
        )
        roles = ("operational_provider_read",) if purpose == "operational_read" else (
            ("candidate_7b_call", "reference_7b_call") if purpose == "live_verification_7b" else ()
        )
        adm = AdmittedCollection(
            f"admission:{tag}", purpose, "sha256:" + ("5" * 64), "tenant:ibvi", "binding:meta-primary",
            "account:ibvi-01", "scope:campaigns-active", "campaign", ("cap:meta_daily_campaign_v1",),
            "2026-11-11T03:00:00Z", self.clock_loc, 500, "2026a", "America/Sao_Paulo", dr,
            self.reg_loc, self.reg_loc.content_digest, "BRL", "pipeboard_hosted", self.driver_loc,
            self.driver_loc.content_digest, "sha256:" + ("6" * 64), cqc, cqc.canonical_query_digest, _make_prereqs(purpose), roles,
        )
        inv = ExpectedResourceInventory(
            f"inventory:{tag}", self.reg_loc, self.reg_loc.content_digest, "tenant:ibvi",
            "binding:meta-primary", "account:ibvi-01", "scope:campaigns-active", dr,
            (ExpectedResourceKey("binding:meta-primary", "account:ibvi-01", _CAMP_A, "campaign", metric_date, "attribution:not_applicable", "breakdown:none"),),
        )
        if signed:
            a_d, a_loc = _sign_and_store(self.store, AdmittedCollection.SCHEMA, adm)
            i_d, i_loc = _sign_and_store(self.store, ExpectedResourceInventory.SCHEMA, inv)
            return AdmittedCollection.from_dict(a_d, require_signed=True), a_loc, ExpectedResourceInventory.from_dict(i_d, require_signed=True), i_loc
        return adm, self.store.put_json_artifact(AdmittedCollection.SCHEMA, adm.to_dict()), inv, self.store.put_json_artifact(ExpectedResourceInventory.SCHEMA, inv.to_dict())

    def store_effect_chain(
        self, adm: AdmittedCollection, adm_loc: ArtifactLocator, res_loc: ArtifactLocator,
        *, tag: str = "001", reservation_status: str = "consumed", signed: bool = True, override_delegation: ArtifactLocator | None = None,
    ) -> tuple[ArtifactLocator, ArtifactLocator, ArtifactLocator, ArtifactLocator, ArtifactLocator]:
        deleg = adm.purpose_prerequisite_locators.delegation_context_locator if override_delegation is None else override_delegation
        subj = ProviderCallTarget(
            self.run_loc, adm_loc, "operational", "provider-target:pipeboard-hosted", adm.canonical_query_digest,
            adm.registry_snapshot_locator, adm.tenant_ref, adm.binding_ref, adm.account_ref, adm.resource_scope_ref, deleg,
        )
        nonce = f"nonce-{tag}"
        auth = AuthorizationReceipt(
            f"auth:{tag}", self.run_loc, "provider_operational_read", "operational_provider_read_effect_proof",
            subj, "sha256:" + ("7" * 64), (adm_loc,), "principal:operator-01", "2026-11-11T03:00:00Z", "2026-11-11T04:00:00Z", nonce,
        )
        put_fn = lambda s, o: _sign_and_store(self.store, s, o)[1] if signed else self.store.put_json_artifact(s, o.to_dict())  # noqa: E731
        auth_loc = put_fn(AuthorizationReceipt.SCHEMA, auth)
        in_doubt = "pre_dispatch_freshness_failure" if reservation_status == "in_doubt" else None
        resv = AuthorizationReservationRecord(
            f"resv:{tag}", self.run_loc, auth_loc, auth_loc.content_digest, nonce,
            auth.action, auth.dag_slot, subj, reservation_status, in_doubt, "2026-11-11T03:01:00Z",  # type: ignore[arg-type]
        )
        resv_loc = put_fn(AuthorizationReservationRecord.SCHEMA, resv)
        exec_rec = ExecutionReceipt(f"exec:{tag}", self.run_loc, auth_loc, resv_loc, nonce, auth.action, auth.dag_slot, subj, "succeeded", res_loc, "2026-11-11T03:02:00Z")
        exec_loc = put_fn(ExecutionReceipt.SCHEMA, exec_rec)
        cons = AuthorizationConsumptionRecord(f"cons:{tag}", self.run_loc, auth_loc, auth_loc.content_digest, resv_loc, exec_loc, nonce, auth.action, auth.dag_slot, "consumed", "2026-11-11T03:03:00Z")
        cons_loc = put_fn(AuthorizationConsumptionRecord.SCHEMA, cons)
        proof = EffectProof(f"proof:{tag}", self.run_loc, auth.action, auth.dag_slot, auth_loc, resv_loc, exec_loc, cons_loc, res_loc, "2026-11-11T03:04:00Z")
        return auth_loc, resv_loc, exec_loc, cons_loc, put_fn(EffectProof.SCHEMA, proof)

    def store_operational_read(
        self, metric_date: str = "2026-11-10", *, tag: str = "001", collected_at_utc: str = "2026-11-11T03:02:00.000000Z",
        obs_ref: str = "observation:obs-001", clicks_val: str | None = "15", clicks_presence: str = "observed", signed: bool = True,
    ) -> tuple[OperationalReadEvidence, ArtifactLocator, CollectionResult, ArtifactLocator]:
        adm, adm_loc, _, inv_loc = self.store_admitted_and_inventory(metric_date, tag=tag, signed=signed)
        facts = _make_facts(metric_date, clicks_val=clicks_val, clicks_presence=clicks_presence)
        _, fact_digest = compute_normalized_fact_set_digest(facts)
        rctx = RetrievalContext(collected_at_utc, obs_ref, "pipeboard-0.1.0", "1.0.0")
        cands = tuple(sorted((project_collection_fact_to_landing_row(f, rctx) for f in facts), key=lambda r: r.candidate_sort_key_jcs()))
        res = CollectionResult(
            adm_loc, adm_loc.content_digest, "operational", self.reg_loc, self.reg_loc.content_digest,
            adm.requested_capabilities, adm.requested_capabilities, rctx, _clean_transport(), cands, facts, fact_digest, (),
        )
        if signed:
            r_dict, res_loc = _sign_and_store(self.store, CollectionResult.SCHEMA, res)
            res = CollectionResult.from_dict(r_dict, require_signed=True)
        else:
            res_loc = self.store.put_json_artifact(CollectionResult.SCHEMA, res.to_dict())
        a_l, r_l, x_l, c_l, pf_l = self.store_effect_chain(adm, adm_loc, res_loc, tag=tag, signed=signed)
        ev = OperationalReadEvidence(
            self.run_loc, adm.tenant_ref, adm.binding_ref, adm.account_ref, adm.resource_scope_ref,
            adm.canonical_query_digest, self.reg_loc, self.reg_loc.content_digest, inv_loc, adm_loc,
            adm_loc.content_digest, res_loc, res_loc.content_digest, fact_digest, a_l, r_l, x_l, c_l, pf_l,
        )
        if signed:
            e_dict, ev_loc = _sign_and_store(self.store, OperationalReadEvidence.SCHEMA, ev)
            return OperationalReadEvidence.from_dict(e_dict, require_signed=True), ev_loc, res, res_loc
        return ev, self.store.put_json_artifact(OperationalReadEvidence.SCHEMA, ev.to_dict()), res, res_loc

    def cur_and_gen(
        self, *, tag: str, mode: str, anchor: str, days: int, ev_locs: tuple[ArtifactLocator, ...],
        base_cat: ArtifactLocator, snap: ArtifactLocator | None = None, cut: ArtifactLocator | None = None,
        hist: tuple[ArtifactLocator, ...] = (), parent: ArtifactLocator | None = None,
    ) -> tuple[SanitizedCandidateFactSet, GenerationManifest, ArtifactLocator]:
        cset = build_sanitized_candidate_fact_set(
            migration_run_context_locator=self.run_loc, sanitization_algorithm_identity=self.san_alg,
            store=self.store, evidence_locators=ev_locs,
        )
        win = compute_curation_window(anchor, "America/Sao_Paulo", "2026a", days)
        gen_rec = self.genesis_loc if mode == "genesis" else None
        cur = CurationExecution(
            self.run_loc, f"curation:{tag}", mode, anchor, "America/Sao_Paulo", "2026a", days,  # type: ignore[arg-type]
            win, cset.locator(), self.cur_alg, gen_rec, base_cat, snap, cut, hist, "2026-11-11T03:05:00Z",
        )
        cur_loc = self.store.put_json_artifact(CurationExecution.SCHEMA, cur.to_dict())
        man, man_loc = materialize_parquet_generation(
            generation_id=f"gen:{tag}", created_at_utc="2026-11-11T03:06:00Z",
            registry_snapshot_locator=self.reg_loc, curation_locator=cur_loc,
            store=self.store, parquet_codec=self.codec, parent_generation_manifest_locator=parent,
        )
        return cset, man, man_loc

    def build_genesis_generation(self, *, tag: str = "g1", metric_date: str = "2026-11-10") -> tuple[GenerationManifest, ArtifactLocator]:
        _, ev_loc, _, _ = self.store_operational_read(metric_date, tag=tag, obs_ref=f"observation:{tag}")
        _, man, man_loc = self.cur_and_gen(tag=tag, mode="genesis", anchor=metric_date, days=1, ev_locs=(ev_loc,), base_cat=self.epoch0_loc)
        return man, man_loc

    def commit_first_cut(
        self, svc: GlobalDatasetCatalogService
    ) -> tuple[DatasetCatalog, ArtifactLocator, DatasetCatalogCutReceipt, ArtifactLocator]:
        _, gen_loc = self.build_genesis_generation(tag="first-cut")
        self._first_gen_loc = gen_loc
        return svc.commit_partition_cut(
            cut_id="cut:epoch-0-to-1", cas_linearization_id="lin:cat-001", committed_at_utc="2026-11-11T03:07:00Z",
            expected_old_catalog_locator=self.epoch0_loc, expected_old_catalog_epoch=0,
            generation_manifest_locator=gen_loc, new_catalog_id="catalog:epoch-1", genesis_record_locator=self.genesis_loc,
        )

    def replay_genesis_cut_against_fresh_service_sharing_consumed_ledger(
        self,
    ) -> tuple[DatasetCatalog, ArtifactLocator, DatasetCatalogCutReceipt, ArtifactLocator]:
        fresh_svc = GlobalDatasetCatalogService(
            self.store, self.epoch0_loc, parquet_codec=self.codec, consumed_genesis_digests=self.consumed_ledger
        )
        return fresh_svc.commit_partition_cut(
            cut_id="cut:replay-0-to-1", cas_linearization_id="lin:cat-replay", committed_at_utc="2026-11-11T03:08:00Z",
            expected_old_catalog_locator=self.epoch0_loc, expected_old_catalog_epoch=0,
            generation_manifest_locator=self._first_gen_loc, new_catalog_id="catalog:epoch-1-replay",
            genesis_record_locator=self.genesis_loc,
        )


@pytest.fixture
def curation_world() -> CurationWorld:
    return CurationWorld()


def _commit_cut_and_snapshot(
    world: CurationWorld, svc: GlobalDatasetCatalogService, gen_loc: ArtifactLocator,
    *, step: str, genesis_loc: ArtifactLocator | None = None,
) -> tuple[DatasetCatalog, ArtifactLocator, DatasetCatalogCutReceipt, ArtifactLocator, DatasetSnapshot, ArtifactLocator]:
    old_loc, old_cat = svc.current_head()
    new_cat, new_cat_loc, receipt, receipt_loc = svc.commit_partition_cut(
        cut_id=f"cut:{step}", cas_linearization_id=f"lin:{step}", committed_at_utc="2026-11-11T04:00:00Z",
        expected_old_catalog_locator=old_loc, expected_old_catalog_epoch=old_cat.catalog_epoch,
        generation_manifest_locator=gen_loc, new_catalog_id=f"catalog:{step}", genesis_record_locator=genesis_loc,
    )
    snap, snap_loc = publish_dataset_snapshot(
        snapshot_id=f"snapshot:{step}", created_at="2026-11-11T04:01:00Z",
        cut_receipt_locator=receipt_loc, store=world.store,
    )
    return new_cat, new_cat_loc, receipt, receipt_loc, snap, snap_loc


def test_algorithm_provenance_identity_verifier_and_mismatches(curation_world: CurationWorld) -> None:
    verify_algorithm_provenance_identity(curation_world.san_alg, curation_world.san_git)
    for field_name, bad_val in (
        ("git_artifact_provenance_locator", _loc(GitArtifactProvenance.SCHEMA, "e")),
        ("repository", "other/repo"), ("commit_sha", "f" * 40),
        ("path", "src/smart_ads/other.py"), ("git_blob_oid", "f" * 40), ("file_content_sha256", "sha256:" + ("f" * 64)),
    ):
        with pytest.raises(ClosedValidationError):
            verify_algorithm_provenance_identity(
                dataclasses.replace(curation_world.san_alg, **{field_name: bad_val}), curation_world.san_git
            )


def test_operational_read_evidence_happy_path_and_signed_enforcement(curation_world: CurationWorld) -> None:
    ev_signed, _, res_signed, _ = curation_world.store_operational_read(tag="op-s", signed=True)
    adm_out, res_out = verify_operational_read_evidence(ev_signed, store=curation_world.store, require_signed=True)
    assert adm_out.collection_purpose == "operational_read" and res_out == res_signed

    ev_u, _, _, res_u_loc = curation_world.store_operational_read(tag="op-u", signed=False)
    verify_operational_read_evidence(ev_u, store=curation_world.store, require_signed=False)
    with pytest.raises(ClosedValidationError):
        verify_operational_read_evidence(ev_u, store=curation_world.store, require_signed=True)

    adm_u = AdmittedCollection.from_dict(curation_world.store.get_json_artifact(ev_u.admitted_collection_locator))
    a_l, r_l, x_l, c_l, pf_l = curation_world.store_effect_chain(
        adm_u, ev_u.admitted_collection_locator, res_u_loc, tag="indoubt", reservation_status="in_doubt", signed=False
    )
    bad_ev = dataclasses.replace(
        ev_u, authorization_locator=a_l, reservation_locator=r_l, execution_locator=x_l, consumption_locator=c_l, effect_proof_locator=pf_l
    )
    with pytest.raises(ClosedValidationError, match="in_doubt|reservation_status"):
        verify_operational_read_evidence(bad_ev, store=curation_world.store)

    a2, r2, x2, c2, pf2 = curation_world.store_effect_chain(
        adm_u, ev_u.admitted_collection_locator, res_u_loc, tag="bad-deleg",
        signed=False, override_delegation=_loc("smart_ads/ibvi_ads_delegation_context/v1", "9"),
    )
    bad_deleg_ev = dataclasses.replace(
        ev_u, authorization_locator=a2, reservation_locator=r2, execution_locator=x2, consumption_locator=c2, effect_proof_locator=pf2
    )
    with pytest.raises(ClosedValidationError, match="ProviderCallTarget"):
        verify_operational_read_evidence(bad_deleg_ev, store=curation_world.store)

    usd_facts = _make_facts("2026-11-10", spend_currency="USD")
    _, usd_dig = compute_normalized_fact_set_digest(usd_facts)
    usd_rctx = RetrievalContext("2026-11-11T03:02:00.000000Z", "observation:usd-01", "pipeboard-0.1.0", "1.0.0")
    usd_cands = tuple(sorted((project_collection_fact_to_landing_row(f, usd_rctx, query_currency="USD") for f in usd_facts), key=lambda r: r.candidate_sort_key_jcs()))
    usd_res = CollectionResult(
        ev_u.admitted_collection_locator, ev_u.admitted_collection_digest, "operational", curation_world.reg_loc, curation_world.reg_loc.content_digest,
        adm_u.requested_capabilities, adm_u.requested_capabilities, usd_rctx, _clean_transport(), usd_cands, usd_facts, usd_dig, (),
    )
    usd_res_loc = curation_world.store.put_json_artifact(CollectionResult.SCHEMA, usd_res.to_dict())
    a3, r3, x3, c3, pf3 = curation_world.store_effect_chain(adm_u, ev_u.admitted_collection_locator, usd_res_loc, tag="usd-cur", signed=False)
    usd_ev = dataclasses.replace(
        ev_u, collection_result_locator=usd_res_loc, collection_result_digest=usd_res_loc.content_digest,
        normalized_fact_set_digest=usd_dig, authorization_locator=a3, reservation_locator=r3, execution_locator=x3, consumption_locator=c3, effect_proof_locator=pf3,
    )
    with pytest.raises(ClosedValidationError, match="currency|projection"):
        verify_operational_read_evidence(usd_ev, store=curation_world.store)


def test_operational_read_evidence_rejects_7a_7b_partial_and_failed(curation_world: CurationWorld) -> None:
    base_ev, _, base_res, _ = curation_world.store_operational_read("2026-11-10", tag="base", signed=False)
    for bad_purpose in ("fixture_7a", "live_verification_7b"):
        adm_p, adm_p_loc, _, inv_p_loc = curation_world.store_admitted_and_inventory(
            "2026-11-10", tag=f"p-{bad_purpose}", purpose=bad_purpose, signed=False  # type: ignore[arg-type]
        )
        res_p = dataclasses.replace(base_res, admitted_collection_locator=adm_p_loc, admitted_collection_digest=adm_p_loc.content_digest)
        res_p_loc = curation_world.store.put_json_artifact(CollectionResult.SCHEMA, res_p.to_dict())
        a_l, r_l, x_l, c_l, pf_l = curation_world.store_effect_chain(adm_p, adm_p_loc, res_p_loc, tag=f"p-{bad_purpose}", signed=False)
        ev_p = dataclasses.replace(
            base_ev, admitted_collection_locator=adm_p_loc, admitted_collection_digest=adm_p_loc.content_digest,
            expected_resource_inventory_locator=inv_p_loc, collection_result_locator=res_p_loc,
            collection_result_digest=res_p_loc.content_digest, authorization_locator=a_l,
            reservation_locator=r_l, execution_locator=x_l, consumption_locator=c_l, effect_proof_locator=pf_l,
        )
        with pytest.raises(ClosedValidationError, match="operational_read"):
            verify_operational_read_evidence(ev_p, store=curation_world.store)

    adm, adm_loc, _, inv_loc = curation_world.store_admitted_and_inventory("2026-11-10", tag="inc", signed=False)
    for label, bad_to in (("partial", dataclasses.replace(_clean_transport(), payload_schema_valid=False)), ("failed", dataclasses.replace(_clean_transport(), http_status=503))):
        bad_res = CollectionResult(
            adm_loc, adm_loc.content_digest, "operational", curation_world.reg_loc, curation_world.reg_loc.content_digest,
            adm.requested_capabilities, (), base_res.retrieval_context, bad_to, (), None, None, (NormalizedProviderError("ERR_1", "transport", "bad"),),
        )
        bad_res_loc = curation_world.store.put_json_artifact(CollectionResult.SCHEMA, bad_res.to_dict())
        a_l, r_l, x_l, c_l, pf_l = curation_world.store_effect_chain(adm, adm_loc, bad_res_loc, tag=f"inc-{label}", signed=False)
        bad_ev = OperationalReadEvidence(
            curation_world.run_loc, adm.tenant_ref, adm.binding_ref, adm.account_ref, adm.resource_scope_ref,
            adm.canonical_query_digest, curation_world.reg_loc, curation_world.reg_loc.content_digest, inv_loc, adm_loc,
            adm_loc.content_digest, bad_res_loc, bad_res_loc.content_digest, "sha256:" + ("b" * 64), a_l, r_l, x_l, c_l, pf_l,
        )
        with pytest.raises(ClosedValidationError, match=label):
            verify_operational_read_evidence(bad_ev, store=curation_world.store)


def test_sanitized_candidate_bijection_with_divergent_rfc8785_array_order(curation_world: CurationWorld) -> None:
    ev_1, ev_1_loc, _, res_1_loc = curation_world.store_operational_read(
        "2026-11-10", tag="bij-base", collected_at_utc="2026-11-11T03:02:00.000000Z", obs_ref="observation:bij-1"
    )
    ev_2_loc, res_2_loc = ev_1_loc, res_1_loc
    for i in range(64):
        _, cand_ev_loc, _, cand_res_loc = curation_world.store_operational_read(
            "2026-11-10", tag=f"bij-{i}", collected_at_utc="2026-11-11T03:05:00.000000Z", obs_ref=f"observation:bij-alt-{i}"
        )
        if (canonicalize_jcs(ev_1_loc.to_dict()) < canonicalize_jcs(cand_ev_loc.to_dict())) != (
            canonicalize_jcs(res_1_loc.to_dict()) < canonicalize_jcs(cand_res_loc.to_dict())
        ):
            ev_2_loc, res_2_loc = cand_ev_loc, cand_res_loc
            break
    assert (canonicalize_jcs(ev_1_loc.to_dict()) < canonicalize_jcs(ev_2_loc.to_dict())) != (
        canonicalize_jcs(res_1_loc.to_dict()) < canonicalize_jcs(res_2_loc.to_dict())
    )
    _, ev_dup_loc, _, _ = curation_world.store_operational_read(
        "2026-11-10", tag="bij-dup", collected_at_utc="2026-11-11T03:02:00.000000Z", obs_ref="observation:bij-1"
    )
    cset = build_sanitized_candidate_fact_set(
        migration_run_context_locator=curation_world.run_loc, sanitization_algorithm_identity=curation_world.san_alg,
        store=curation_world.store, evidence_locators=(ev_2_loc, ev_1_loc, ev_dup_loc), require_signed_inputs=True,
    )
    assert cset.candidate_count == 6 and verify_sanitized_candidate_fact_set(cset, store=curation_world.store) == cset

    truncated = SanitizedCandidateFactSet(
        curation_world.run_loc, curation_world.san_alg, cset.source_collection_result_locators,
        cset.operational_read_evidence_locators, cset.candidates[:-1],
    )
    with pytest.raises(ClosedValidationError):
        verify_sanitized_candidate_fact_set(truncated, store=curation_world.store)

    dup_ev_loc = curation_world.store.put_json_artifact(OperationalReadEvidence.SCHEMA, dataclasses.replace(ev_1, integrity=None).to_dict())
    with pytest.raises(ClosedValidationError, match="bijection|duplicate"):
        build_sanitized_candidate_fact_set(
            migration_run_context_locator=curation_world.run_loc, sanitization_algorithm_identity=curation_world.san_alg,
            store=curation_world.store, evidence_locators=(ev_1_loc, dup_ev_loc),
        )


def test_curation_window_rejects_out_of_window_and_multi_partition_cuts(curation_world: CurationWorld) -> None:
    _, ev_old_loc, _, _ = curation_world.store_operational_read("2026-11-05", tag="out-old", obs_ref="observation:o1")
    cset_old = build_sanitized_candidate_fact_set(
        migration_run_context_locator=curation_world.run_loc, sanitization_algorithm_identity=curation_world.san_alg,
        store=curation_world.store, evidence_locators=(ev_old_loc,),
    )
    win_nov = compute_curation_window("2026-11-10", "America/Sao_Paulo", "2026a", 3)
    cur_out = CurationExecution(
        curation_world.run_loc, "curation:out", "genesis", "2026-11-10", "America/Sao_Paulo", "2026a", 3,
        win_nov, cset_old.locator(), curation_world.cur_alg, curation_world.genesis_loc, curation_world.epoch0_loc,
        None, None, (), "2026-11-11T03:05:00Z",
    )
    with pytest.raises(ClosedValidationError, match="curation_window"):
        verify_curation_execution(cur_out, store=curation_world.store)

    _, ev_oct_loc, _, _ = curation_world.store_operational_read("2026-10-31", tag="mp-oct", obs_ref="observation:oct")
    _, ev_nov_loc, _, _ = curation_world.store_operational_read("2026-11-01", tag="mp-nov", obs_ref="observation:nov")
    cset_mp = build_sanitized_candidate_fact_set(
        migration_run_context_locator=curation_world.run_loc, sanitization_algorithm_identity=curation_world.san_alg,
        store=curation_world.store, evidence_locators=(ev_oct_loc, ev_nov_loc),
    )
    win_cross = compute_curation_window("2026-11-02", "America/Sao_Paulo", "2026a", 5)
    cur_mp = CurationExecution(
        curation_world.run_loc, "curation:mp", "genesis", "2026-11-02", "America/Sao_Paulo", "2026a", 5,
        win_cross, cset_mp.locator(), curation_world.cur_alg, curation_world.genesis_loc, curation_world.epoch0_loc,
        None, None, (), "2026-11-11T03:05:00Z",
    )
    with pytest.raises(ClosedValidationError, match="partition"):
        verify_curation_execution(cur_mp, store=curation_world.store)


def test_winner_precedence_idempotent_recuration_and_pre_window_preservation(curation_world: CurationWorld) -> None:
    _, ev_d02, _, _ = curation_world.store_operational_read("2026-11-02", tag="w-02", clicks_val="10", obs_ref="observation:d02")
    _, ev_d09_t1, _, _ = curation_world.store_operational_read(
        "2026-11-09", tag="w-09-t1", collected_at_utc="2026-11-10T01:00:00.000000Z",
        clicks_presence="retracted_tombstone", clicks_val=None, obs_ref="observation:d09-tomb",
    )
    _, _, gen_1_loc = curation_world.cur_and_gen(
        tag="w1", mode="genesis", anchor="2026-11-09", days=10, ev_locs=(ev_d02, ev_d09_t1), base_cat=curation_world.epoch0_loc
    )
    _, cat1_loc, _, cut1_loc, _, snap1_loc = _commit_cut_and_snapshot(
        curation_world, curation_world.catalog_service, gen_1_loc, step="w1", genesis_loc=curation_world.genesis_loc
    )
    _, ev_d09_later, _, _ = curation_world.store_operational_read(
        "2026-11-09", tag="w-09-t2", collected_at_utc="2026-11-10T05:00:00.000000Z", clicks_val="77", obs_ref="observation:d09-obs"
    )
    _, ev_d10_obs, _, _ = curation_world.store_operational_read(
        "2026-11-10", tag="w-10-obs", collected_at_utc="2026-11-11T06:00:00.000000Z", clicks_val="30", obs_ref="observation:d10-a"
    )
    _, ev_d10_tomb, _, _ = curation_world.store_operational_read(
        "2026-11-10", tag="w-10-tomb", collected_at_utc="2026-11-11T06:00:00.000000Z",
        clicks_presence="retracted_tombstone", clicks_val=None, obs_ref="observation:d10-b",
    )
    cset_2, gen_2, gen_2_loc = curation_world.cur_and_gen(
        tag="w2", mode="incremental", anchor="2026-11-10", days=3,
        ev_locs=(ev_d09_t1, ev_d09_later, ev_d10_obs, ev_d10_tomb),
        base_cat=cat1_loc, snap=snap1_loc, cut=cut1_loc, hist=(gen_1_loc,), parent=gen_1_loc,
    )
    rows_2 = verify_generation_manifest(gen_2, store=curation_world.store, parquet_codec=curation_world.codec)
    clicks_by_day = {r.fact_key.metric_date: r for r in rows_2 if r.fact_key.metric_semantic_ref == "metric:clicks_v1"}
    assert (clicks_by_day["2026-11-02"].raw_numeric_value, clicks_by_day["2026-11-09"].raw_numeric_value, clicks_by_day["2026-11-10"].presence_status) == ("10", "77", "retracted_tombstone")

    _, cat2_loc, _, cut2_loc, _, snap2_loc = _commit_cut_and_snapshot(curation_world, curation_world.catalog_service, gen_2_loc, step="w2")
    win_2 = compute_curation_window("2026-11-10", "America/Sao_Paulo", "2026a", 3)
    cur_3 = CurationExecution(
        curation_world.run_loc, "curation:w3", "incremental", "2026-11-10", "America/Sao_Paulo", "2026a", 3,
        win_2, cset_2.locator(), curation_world.cur_alg, None, cat2_loc, snap2_loc, cut2_loc, (gen_2_loc,), "2026-11-11T08:00:00Z",
    )
    pk_3, rows_3 = replay_curated_partition_rows(curation=cur_3, candidate_set=cset_2, historical_generations=((gen_2, rows_2),))
    assert pk_3 == "year=2026/month=11" and rows_3 == rows_2 and compute_logical_rows_digest(rows_3)[1] == gen_2.logical_rows_digest
    with pytest.raises(ClosedValidationError, match="historical_generation_manifest_locators"):
        verify_curation_execution(dataclasses.replace(cur_3, historical_generation_manifest_locators=()), store=curation_world.store)


def test_equal_timestamp_non_tombstone_tie_breaks_by_greater_semantic_digest(curation_world: CurationWorld) -> None:
    _, ev_a, _, _ = curation_world.store_operational_read("2026-11-10", tag="tie-a", collected_at_utc="2026-11-11T06:00:00.000000Z", clicks_val="41", obs_ref="observation:tie-a")
    _, ev_b, _, _ = curation_world.store_operational_read("2026-11-10", tag="tie-b", collected_at_utc="2026-11-11T06:00:00.000000Z", clicks_val="42", obs_ref="observation:tie-b")
    cset = build_sanitized_candidate_fact_set(
        migration_run_context_locator=curation_world.run_loc, sanitization_algorithm_identity=curation_world.san_alg,
        store=curation_world.store, evidence_locators=(ev_a, ev_b),
    )
    cur = CurationExecution(
        curation_world.run_loc, "curation:tie", "genesis", "2026-11-10", "America/Sao_Paulo", "2026a", 1,
        compute_curation_window("2026-11-10", "America/Sao_Paulo", "2026a", 1), cset.locator(),
        curation_world.cur_alg, curation_world.genesis_loc, curation_world.epoch0_loc, None, None, (), "2026-11-11T06:05:00Z",
    )
    _, winners = replay_curated_partition_rows(curation=cur, candidate_set=cset, historical_generations=())
    expected_max_digest = max(r.semantic_observation_digest for r in cset.candidates if r.fact_key.metric_semantic_ref == "metric:clicks_v1")
    won_clicks = next(r for r in winners if r.fact_key.metric_semantic_ref == "metric:clicks_v1")
    assert won_clicks.semantic_observation_digest == expected_max_digest


def test_genesis_record_is_single_use_and_blocks_replay_cut(curation_world: Any) -> None:
    svc = curation_world.catalog_service
    _, _, receipt_1, _ = curation_world.commit_first_cut(svc)
    assert receipt_1.new_catalog_epoch == 1
    with pytest.raises(ClosedValidationError, match="genesis"):
        curation_world.replay_genesis_cut_against_fresh_service_sharing_consumed_ledger()


def test_genesis_consumption_record_and_same_service_replay_rejection(curation_world: CurationWorld) -> None:
    svc = curation_world.catalog_service
    new_cat, new_cat_loc, receipt_1, _ = curation_world.commit_first_cut(svc)
    assert receipt_1.genesis_consumption_locator is not None
    cons = DatasetCatalogGenesisConsumptionRecord.from_dict(curation_world.store.get_json_artifact(receipt_1.genesis_consumption_locator))
    assert (cons.preallocated_cut_id, cons.cas_linearization_id, cons.empty_epoch0_catalog_locator, cons.first_successor_catalog_locator) == (
        receipt_1.cut_id, receipt_1.cas_linearization_id, curation_world.epoch0_loc, new_cat_loc
    )
    verify_dataset_catalog_cut_receipt(receipt_1, store=curation_world.store, parquet_codec=curation_world.codec)
    assert len(new_cat.partition_heads) == 1 and new_cat.partition_heads[0].head_sequence_number == 1
    with pytest.raises(ClosedValidationError, match="genesis|stale"):
        svc.commit_partition_cut(
            cut_id="cut:dup-genesis", cas_linearization_id="lin:dup-genesis", committed_at_utc="2026-11-11T03:09:00Z",
            expected_old_catalog_locator=curation_world.epoch0_loc, expected_old_catalog_epoch=0,
            generation_manifest_locator=curation_world._first_gen_loc, new_catalog_id="catalog:dup",
            genesis_record_locator=curation_world.genesis_loc,
        )


def test_parquet_generation_manifest_gzip_and_tamper_rejections(curation_world: CurationWorld) -> None:
    _, ev_loc, _, _ = curation_world.store_operational_read("2026-11-10", tag="gz-1", obs_ref="observation:gz-1")
    cset = build_sanitized_candidate_fact_set(
        migration_run_context_locator=curation_world.run_loc, sanitization_algorithm_identity=curation_world.san_alg,
        store=curation_world.store, evidence_locators=(ev_loc,),
    )
    cur = CurationExecution(
        curation_world.run_loc, "curation:gz", "genesis", "2026-11-10", "America/Sao_Paulo", "2026a", 1,
        compute_curation_window("2026-11-10", "America/Sao_Paulo", "2026a", 1), cset.locator(),
        curation_world.cur_alg, curation_world.genesis_loc, curation_world.epoch0_loc, None, None, (), "2026-11-11T03:05:00Z",
    )
    cur_loc = curation_world.store.put_json_artifact(CurationExecution.SCHEMA, cur.to_dict())
    gen_gz, _ = materialize_parquet_generation(
        generation_id="gen:gz", created_at_utc="2026-11-11T03:06:00Z", registry_snapshot_locator=curation_world.reg_loc,
        curation_locator=cur_loc, store=curation_world.store, parquet_codec=curation_world.codec, compression="gzip",
    )
    assert len(verify_generation_manifest(gen_gz, store=curation_world.store, parquet_codec=curation_world.codec)) == 3
    for bad_manifest in (
        dataclasses.replace(gen_gz, operational_read_evidence_locators=(_loc(OperationalReadEvidence.SCHEMA, "9"),)),
        dataclasses.replace(gen_gz, logical_rows_digest="sha256:" + ("0" * 64)),
        dataclasses.replace(gen_gz, base_dataset_catalog_locator=_loc(DatasetCatalog.SCHEMA, "9")),
        dataclasses.replace(gen_gz, parent_generation_manifest_locator=_loc(GenerationManifest.SCHEMA, "9")),
    ):
        with pytest.raises(ClosedValidationError):
            verify_generation_manifest(bad_manifest, store=curation_world.store, parquet_codec=curation_world.codec)


def test_global_catalog_cas_conflict_and_multi_partition_add(curation_world: CurationWorld) -> None:
    svc = curation_world.catalog_service
    cat1, cat1_loc, _, cut1_loc = curation_world.commit_first_cut(svc)
    snap1, snap1_loc = publish_dataset_snapshot(
        snapshot_id="snapshot:s1", created_at="2026-11-11T03:10:00Z", cut_receipt_locator=cut1_loc, store=curation_world.store
    )
    assert snap1.catalog_epoch == cat1.catalog_epoch and snap1.partition_heads == cat1.partition_heads
    assert verify_dataset_snapshot(snap1, store=curation_world.store, parquet_codec=curation_world.codec) == snap1

    _, ev_dec, _, _ = curation_world.store_operational_read("2026-12-01", tag="dec-1", obs_ref="observation:dec-1")
    cset_dec = build_sanitized_candidate_fact_set(
        migration_run_context_locator=curation_world.run_loc, sanitization_algorithm_identity=curation_world.san_alg,
        store=curation_world.store, evidence_locators=(ev_dec,),
    )
    cur_dec = CurationExecution(
        curation_world.run_loc, "curation:dec", "incremental", "2026-12-01", "America/Sao_Paulo", "2026a", 1,
        compute_curation_window("2026-12-01", "America/Sao_Paulo", "2026a", 1), cset_dec.locator(),
        curation_world.cur_alg, None, cat1_loc, snap1_loc, cut1_loc, (), "2026-12-02T03:05:00Z",
    )
    cur_dec_loc = curation_world.store.put_json_artifact(CurationExecution.SCHEMA, cur_dec.to_dict())
    _, gen_dec_loc = materialize_parquet_generation(
        generation_id="gen:dec-1", created_at_utc="2026-12-02T03:06:00Z", registry_snapshot_locator=curation_world.reg_loc,
        curation_locator=cur_dec_loc, store=curation_world.store, parquet_codec=curation_world.codec,
    )
    with pytest.raises(ClosedValidationError, match="genesis"):
        svc.commit_partition_cut(
            cut_id="cut:bad-gen", cas_linearization_id="lin:bad-gen", committed_at_utc="2026-12-02T03:07:00Z",
            expected_old_catalog_locator=cat1_loc, expected_old_catalog_epoch=1,
            generation_manifest_locator=gen_dec_loc, new_catalog_id="catalog:bad", genesis_record_locator=curation_world.genesis_loc,
        )
    with pytest.raises(ClosedValidationError, match="stale"):
        svc.commit_partition_cut(
            cut_id="cut:stale", cas_linearization_id="lin:stale", committed_at_utc="2026-12-02T03:07:00Z",
            expected_old_catalog_locator=_loc(DatasetCatalog.SCHEMA, "e"), expected_old_catalog_epoch=1,
            generation_manifest_locator=gen_dec_loc, new_catalog_id="catalog:stale",
        )
    assert svc.current_head() == (cat1_loc, cat1)
    cat2, _, _, _, _, _ = _commit_cut_and_snapshot(curation_world, svc, gen_dec_loc, step="dec-add")
    assert [h.partition_key for h in cat2.partition_heads] == ["year=2026/month=11", "year=2026/month=12"]
    assert cat2.partition_heads[0] == cat1.partition_heads[0] and cat2.partition_heads[1].head_sequence_number == 1


def test_replace_partition_sequence_parent_and_snapshot_equality(curation_world: CurationWorld) -> None:
    svc = curation_world.catalog_service
    _, cat1_loc, _, cut1_loc = curation_world.commit_first_cut(svc)
    _, snap1_loc = publish_dataset_snapshot(
        snapshot_id="snapshot:r1", created_at="2026-11-11T03:10:00Z", cut_receipt_locator=cut1_loc, store=curation_world.store
    )
    _, ev_dec, _, _ = curation_world.store_operational_read("2026-12-01", tag="r-dec", obs_ref="observation:r-dec")
    _, _, gen_dec_loc = curation_world.cur_and_gen(
        tag="r-dec", mode="incremental", anchor="2026-12-01", days=1,
        ev_locs=(ev_dec,), base_cat=cat1_loc, snap=snap1_loc, cut=cut1_loc,
    )
    cat2, cat2_loc, _, cut2_loc, _, snap2_loc = _commit_cut_and_snapshot(curation_world, svc, gen_dec_loc, step="r-dec")

    old_nov_head = cat2.partition_heads[0]
    _, ev_nov2, _, _ = curation_world.store_operational_read("2026-11-10", tag="r-nov2", clicks_val="99", obs_ref="observation:r-nov2")
    with pytest.raises(ClosedValidationError, match="parent_generation_manifest_locator"):
        curation_world.cur_and_gen(
            tag="bad-parent", mode="incremental", anchor="2026-11-10", days=1, ev_locs=(ev_nov2,),
            base_cat=cat2_loc, snap=snap2_loc, cut=cut2_loc, hist=(old_nov_head.generation_manifest_locator,), parent=None,
        )
    _, _, gen_nov2_loc = curation_world.cur_and_gen(
        tag="r-nov2", mode="incremental", anchor="2026-11-10", days=1, ev_locs=(ev_nov2,),
        base_cat=cat2_loc, snap=snap2_loc, cut=cut2_loc,
        hist=(old_nov_head.generation_manifest_locator,), parent=old_nov_head.generation_manifest_locator,
    )
    cat3, _, _, _, snap3, _ = _commit_cut_and_snapshot(curation_world, svc, gen_nov2_loc, step="r-nov-rep")
    assert cat3.catalog_epoch == 3 and cat3.partition_heads[0].head_sequence_number == 2 and cat3.partition_heads[1] == cat2.partition_heads[1]
    assert canonicalize_jcs([h.to_dict() for h in snap3.partition_heads]) == canonicalize_jcs([h.to_dict() for h in cat3.partition_heads])
    verify_dataset_snapshot(snap3, store=curation_world.store, parquet_codec=curation_world.codec)
    bad_snap = DatasetSnapshot("snapshot:tampered", snap3.catalog_epoch, snap3.dataset_catalog_locator, snap3.catalog_cut_receipt_locator, snap3.created_at, (snap3.partition_heads[0],))
    with pytest.raises(ClosedValidationError):
        verify_dataset_snapshot(bad_snap, store=curation_world.store, parquet_codec=curation_world.codec)


def test_signed_end_to_end_snapshot_and_call_side_rejection(curation_world: CurationWorld) -> None:
    store, codec = curation_world.store, curation_world.codec
    ev, ev_loc, res, _ = curation_world.store_operational_read("2026-11-10", tag="s-e2e", signed=True)
    cand_side_res = dataclasses.replace(res, call_side="candidate", integrity=None)
    cand_res_loc = store.put_json_artifact(CollectionResult.SCHEMA, cand_side_res.to_dict())
    bad_side_ev = dataclasses.replace(ev, collection_result_locator=cand_res_loc, collection_result_digest=cand_res_loc.content_digest, integrity=None)
    with pytest.raises(ClosedValidationError, match="call_side"):
        verify_operational_read_evidence(bad_side_ev, store=store)

    _, ep0_s_loc = _sign_and_store(store, DatasetCatalog.SCHEMA, curation_world.epoch0_cat)
    gen_rec_u = DatasetCatalogGenesisRecord("genesis:s-1", "cell:ibvi-primary", curation_world.run_loc, ep0_s_loc, ep0_s_loc.content_digest, "authority:bootstrap-root", "2026-11-10T00:01:00Z")
    _, gen_s_loc = _sign_and_store(store, DatasetCatalogGenesisRecord.SCHEMA, gen_rec_u)
    cset_u = build_sanitized_candidate_fact_set(migration_run_context_locator=curation_world.run_loc, sanitization_algorithm_identity=curation_world.san_alg, store=store, evidence_locators=(ev_loc,), require_signed_inputs=True)
    _, cset_s_loc = _sign_and_store(store, SanitizedCandidateFactSet.SCHEMA, cset_u)
    cur_u = CurationExecution(curation_world.run_loc, "curation:s-e2e", "genesis", "2026-11-10", "America/Sao_Paulo", "2026a", 1, compute_curation_window("2026-11-10", "America/Sao_Paulo", "2026a", 1), cset_s_loc, curation_world.cur_alg, gen_s_loc, ep0_s_loc, None, None, (), "2026-11-11T03:05:00Z")
    _, cur_s_loc = _sign_and_store(store, CurationExecution.SCHEMA, cur_u)
    man_u, _ = materialize_parquet_generation(generation_id="gen:s-e2e", created_at_utc="2026-11-11T03:06:00Z", registry_snapshot_locator=curation_world.reg_loc, curation_locator=cur_s_loc, store=store, parquet_codec=codec)
    _, man_s_loc = _sign_and_store(store, GenerationManifest.SCHEMA, man_u)
    cat_u = DatasetCatalog("catalog:s-1", "cell:ibvi-primary", 1, "2026-11-11T03:07:00Z", (DatasetCatalog.from_dict({"$schema": DatasetCatalog.SCHEMA, "catalog_id": "catalog:s-1", "cell_ref": "cell:ibvi-primary", "catalog_epoch": 1, "created_at_utc": "2026-11-11T03:07:00Z", "partition_heads": [{"partition_key": "year=2026/month=11", "head_sequence_number": 1, "generation_manifest_locator": man_s_loc.to_dict()}]}).partition_heads[0],))
    cat_int = _signed_p1_for(cat_u.to_dict())
    cat_s = dataclasses.replace(cat_u, integrity=cat_int)
    cons_u = DatasetCatalogGenesisConsumptionRecord(gen_s_loc, gen_s_loc.content_digest, ep0_s_loc, ep0_s_loc.content_digest, cat_s.locator(), cat_s.locator().content_digest, "cut:s-1", "lin:s-1", "2026-11-11T03:07:00Z")
    cons_int = _signed_p1_for(cons_u.to_dict())
    signed_ledger: set[str] = set()
    svc_s = GlobalDatasetCatalogService(store, ep0_s_loc, parquet_codec=codec, consumed_genesis_digests=signed_ledger, require_signed=True)
    _, _, rec_u, _ = GlobalDatasetCatalogService(store, ep0_s_loc, parquet_codec=codec).commit_partition_cut(cut_id="cut:s-1", cas_linearization_id="lin:s-1", committed_at_utc="2026-11-11T03:07:00Z", expected_old_catalog_locator=ep0_s_loc, expected_old_catalog_epoch=0, generation_manifest_locator=man_s_loc, new_catalog_id="catalog:s-1", genesis_record_locator=gen_s_loc, consumption_integrity=cons_int, catalog_integrity=cat_int)
    for bad_cat_int, bad_cons_int, bad_rec_int in ((None, cons_int, _signed_p1_for(rec_u.to_dict())), (cat_int, _unsigned_p1(), None), (cat_int, cons_int, None)):
        with pytest.raises(ClosedValidationError):
            svc_s.commit_partition_cut(cut_id="cut:s-1", cas_linearization_id="lin:s-1", committed_at_utc="2026-11-11T03:07:00Z", expected_old_catalog_locator=ep0_s_loc, expected_old_catalog_epoch=0, generation_manifest_locator=man_s_loc, new_catalog_id="catalog:s-1", genesis_record_locator=gen_s_loc, consumption_integrity=bad_cons_int, catalog_integrity=bad_cat_int, receipt_integrity=bad_rec_int)
    assert svc_s.current_head()[0] == ep0_s_loc and signed_ledger == set()
    _, _, _, rec_s_loc = svc_s.commit_partition_cut(cut_id="cut:s-1", cas_linearization_id="lin:s-1", committed_at_utc="2026-11-11T03:07:00Z", expected_old_catalog_locator=ep0_s_loc, expected_old_catalog_epoch=0, generation_manifest_locator=man_s_loc, new_catalog_id="catalog:s-1", genesis_record_locator=gen_s_loc, consumption_integrity=cons_int, catalog_integrity=cat_int, receipt_integrity=_signed_p1_for(rec_u.to_dict()))
    snap_u, _ = publish_dataset_snapshot(snapshot_id="snapshot:s-e2e", created_at="2026-11-11T03:08:00Z", cut_receipt_locator=rec_s_loc, store=store)
    snap_s, _ = publish_dataset_snapshot(snapshot_id="snapshot:s-e2e", created_at="2026-11-11T03:08:00Z", cut_receipt_locator=rec_s_loc, store=store, integrity=_signed_p1_for(snap_u.to_dict()))
    assert verify_dataset_snapshot(snap_s, store=store, parquet_codec=codec, require_signed=True) == snap_s
    with pytest.raises(ClosedValidationError):
        verify_dataset_snapshot(snap_u, store=store, parquet_codec=codec, require_signed=True)


def test_codec_free_cas_and_snapshot_publish_reject_manifest_partition_mismatch(curation_world: CurationWorld) -> None:
    man_valid, valid_man_loc = curation_world.build_genesis_generation(tag="cf-1", metric_date="2026-11-10")
    raw_pq = curation_world.store.get_bytes(man_valid.parquet_object_locators[0].object_ref)
    bad_pq_loc = ParquetObjectLocator.for_parquet_bytes("year=2026/month=12", raw_pq)
    bad_man = GenerationManifest(
        man_valid.migration_run_context_locator, "gen:bad-pk", "year=2026/month=12", None, man_valid.created_at_utc,
        man_valid.row_count, man_valid.logical_rows_digest, man_valid.registry_snapshot_locator,
        man_valid.curation_execution_locator, man_valid.base_dataset_catalog_locator,
        man_valid.operational_read_evidence_locators, (bad_pq_loc,),
    )
    bad_man_loc = curation_world.store.put_json_artifact(GenerationManifest.SCHEMA, bad_man.to_dict())
    cf_ledger: set[str] = set()
    svc_cf = GlobalDatasetCatalogService(curation_world.store, curation_world.epoch0_loc, parquet_codec=None, consumed_genesis_digests=cf_ledger)
    with pytest.raises(ClosedValidationError, match="partition_key"):
        svc_cf.commit_partition_cut(
            cut_id="cut:bad-pk", cas_linearization_id="lin:bad-pk", committed_at_utc="2026-11-11T03:07:00Z",
            expected_old_catalog_locator=curation_world.epoch0_loc, expected_old_catalog_epoch=0,
            generation_manifest_locator=bad_man_loc, new_catalog_id="catalog:bad-pk", genesis_record_locator=curation_world.genesis_loc,
        )
    assert svc_cf.current_head() == (curation_world.epoch0_loc, curation_world.epoch0_cat) and cf_ledger == set()
    _, cf_cat_loc, _, _ = svc_cf.commit_partition_cut(
        cut_id="cut:ok-cf", cas_linearization_id="lin:ok-cf", committed_at_utc="2026-11-11T03:07:00Z",
        expected_old_catalog_locator=curation_world.epoch0_loc, expected_old_catalog_epoch=0,
        generation_manifest_locator=valid_man_loc, new_catalog_id="catalog:ok-cf", genesis_record_locator=curation_world.genesis_loc,
    )
    assert svc_cf.current_head()[0] == cf_cat_loc

    forged_cat = DatasetCatalog("catalog:forged-pk", "cell:ibvi-primary", 1, "2026-11-11T03:07:00Z", (ActivePartitionHead("year=2026/month=12", 1, bad_man_loc),))
    forged_cat_loc = curation_world.store.put_json_artifact(DatasetCatalog.SCHEMA, forged_cat.to_dict())
    forged_cons = DatasetCatalogGenesisConsumptionRecord(
        curation_world.genesis_loc, curation_world.genesis_loc.content_digest, curation_world.epoch0_loc,
        curation_world.epoch0_loc.content_digest, forged_cat_loc, forged_cat_loc.content_digest, "cut:forged", "lin:forged", "2026-11-11T03:07:00Z",
    )
    forged_cons_loc = curation_world.store.put_json_artifact(DatasetCatalogGenesisConsumptionRecord.SCHEMA, forged_cons.to_dict())
    forged_rec = DatasetCatalogCutReceipt(
        cut_id="cut:forged", cell_ref="cell:ibvi-primary", migration_run_context_locator=man_valid.migration_run_context_locator,
        old_catalog_locator=curation_world.epoch0_loc, old_catalog_digest=curation_world.epoch0_loc.content_digest, old_catalog_epoch=0,
        new_catalog_locator=forged_cat_loc, new_catalog_digest=forged_cat_loc.content_digest, new_catalog_epoch=1,
        cas_request_projection=CatalogCasRequestProjection("add_partition", 0, curation_world.epoch0_loc.content_digest, "year=2026/month=12", 1, bad_man_loc),
        cas_linearization_id="lin:forged", committed_at_utc="2026-11-11T03:07:00Z",
        genesis_record_locator=curation_world.genesis_loc, genesis_record_digest=curation_world.genesis_loc.content_digest,
        genesis_consumption_locator=forged_cons_loc, genesis_consumption_digest=forged_cons_loc.content_digest,
    )
    forged_rec_loc = curation_world.store.put_json_artifact(DatasetCatalogCutReceipt.SCHEMA, forged_rec.to_dict())
    with pytest.raises(ClosedValidationError, match="partition_key"):
        publish_dataset_snapshot(snapshot_id="snapshot:forged", created_at="2026-11-11T03:08:00Z", cut_receipt_locator=forged_rec_loc, store=curation_world.store)


def test_application_package_reexports_all_curation_and_catalog_symbols() -> None:
    assert application_pkg.__all__ == sorted(application_pkg.__all__, key=lambda s: s.encode("utf-8"))
    for sym in (
        "GlobalDatasetCatalogService", "build_sanitized_candidate_fact_set", "materialize_parquet_generation",
        "publish_dataset_snapshot", "replay_curated_partition_rows", "verify_algorithm_provenance_identity",
        "verify_curation_execution", "verify_dataset_catalog_cut_receipt", "verify_dataset_snapshot",
        "verify_generation_manifest", "verify_operational_read_evidence", "verify_sanitized_candidate_fact_set",
    ):
        assert sym in application_pkg.__all__ and hasattr(application_pkg, sym)
