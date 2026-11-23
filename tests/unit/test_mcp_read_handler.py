"""Unit tests for `load_verified_snapshot_rows`, `McpVerifiedReadIndex`, and `VerifiedStoreMcpReadHandler`."""
from __future__ import annotations

import base64
from collections.abc import Callable, Mapping, Sequence
from dataclasses import replace
import hashlib
import hmac
from typing import Any

import pytest

from smart_ads.adapters.storage import InMemoryCellObjectStore, StdlibParquetLandingCodec
from smart_ads.analytics import (
    METRIC_WINDOW_COLUMNS,
    REPORT_EXECUTION_SCHEMA,
    AnalyticalCertificationRecord,
    AnalysisExecution,
    AnalysisPolicy,
    AnalysisReplayInputBundle,
    AnalysisResultSchema,
    AttestedCertificationInput,
    CanonicalResultEntry,
    CanonicalResultSet,
    CertificationInput,
    DerivedCertificationStatus,
    DuckDbBinaryObjectLocator,
    DuckDbExtensionBinaryLocator,
    DuckDbExtensionSpec,
    DuckDbQueryDefinition,
    DuckDbSessionSetting,
    EvaluationContext,
    EvaluationScope,
    Finding,
    ReportExecution,
    ResultColumn,
    TaggedScalarCell,
    derive_snapshot_restatement_history,
)
import smart_ads.application as application_pkg
from smart_ads.application import (
    GlobalDatasetCatalogService,
    McpVerifiedReadIndex,
    VerifiedStoreMcpReadHandler,
    build_sanitized_candidate_fact_set,
    execute_analysis_replay_bundle,
    execute_certified_report,
    load_verified_snapshot_rows,
    materialize_parquet_generation,
    publish_dataset_snapshot,
)
import smart_ads.application.mcp_read_handler as mcp_read_handler_mod
from smart_ads.contracts import (
    ADR_P1_DOMAIN_PREFIXES,
    AdmittedCollection,
    ArtifactLocator,
    CanonicalQueryContract,
    ClosedValidationError,
    CollectionResult,
    DateRange,
    FactKey,
    IbviAdsDelegationContext,
    NormalizedCollectionFact,
    P1Integrity,
    PurposePrerequisiteLocators,
    RetrievalContext,
    canonicalize_jcs,
    compute_normalized_fact_set_digest,
    loads_strict_json,
    p1_content_digest,
    p1_signing_message,
    project_collection_fact_to_landing_row,
)
from smart_ads.contracts.effects import (
    AuthorizationConsumptionRecord,
    AuthorizationReceipt,
    AuthorizationReservationRecord,
    EffectProof,
    ExecutionReceipt,
    ProviderCallTarget,
    sort_artifact_locators,
)
from smart_ads.contracts.git_provenance import GitArtifactProvenance, compute_git_blob_oid
from smart_ads.contracts.operational_evidence import (
    AlgorithmProvenanceIdentity,
    OperationalReadEvidence,
    SanitizedCandidateFactSet,
)
from smart_ads.domain import (
    FORBIDDEN_PIPEBOARD_ARGUMENTS,
    PINNED_LEGACY_COMMIT,
    PINNED_LEGACY_REPO,
    PINNED_PIPEBOARD_D26_SPECS,
    PIPEBOARD_PHASE1_METRIC_SOURCE_MAPPINGS,
    ActivePartitionHead,
    AuthorizedScopeRelation,
    CatalogCasRequestProjection,
    CurationExecution,
    DatasetCatalog,
    DatasetCatalogCutReceipt,
    DatasetCatalogGenesisConsumptionRecord,
    DatasetCatalogGenesisRecord,
    DatasetSnapshot,
    DriverCapabilityEntry,
    ExpectedResourceInventory,
    ExpectedResourceKey,
    GenerationManifest,
    LegacySourcePacket,
    PinnedGitArtifactMember,
    PinnedUpstreamReference,
    PipeboardPhase1Contract,
    PipeboardTransportLimits,
    PrivateRegistrySnapshot,
    RegistryBinding,
    compute_curation_window,
)
from smart_ads.ports import CellObjectStorePort, P1SignatureVerifierPort
from smart_ads.ports.cell_runtime import ClockAttestation
from smart_ads.transports.mcp import (
    McpDelegationContext,
    McpReadHandlerPort,
    McpRuntimeContext,
    handle_mcp_request_bytes,
)
from tests.unit.test_curation_and_catalog import _CAMP_A, _METRICS_3, _clean_transport
from tests.unit.test_duckdb_replay_and_reporting import (
    DeterministicInMemoryDuckDbEngine,
    _METRIC_ORDER,
    _METRIC_UKEY,
)

_CAMP_B = "resource:" + ("b" * 51) + "a"
_CAMP_OUT = "resource:" + ("c" * 51) + "a"
_KEY_ID = "key:ed25519:" + ("9" * 64)
_TEST_MAC_SECRET = b"smart-ads-task3-domain-separated-p1-secret"


def _compute_domain_sig(envelope: Mapping[str, Any], domain_prefix: str) -> str:
    msg = p1_signing_message(envelope, domain_prefix)
    mac32 = hmac.new(_TEST_MAC_SECRET, msg, hashlib.sha256).digest()
    return base64.b64encode(mac32 + mac32).decode("ascii")


class DeterministicDomainP1Verifier(P1SignatureVerifierPort):
    """Domain-separated P1 verifier checking key registry, preimage digest, and MAC signature."""

    def __init__(self) -> None:
        self.verified_schemas: list[str] = []

    def verify_p1_envelope_signature(
        self, *, envelope: Mapping[str, Any], domain_prefix: str, store: CellObjectStorePort
    ) -> None:
        schema_id = envelope.get("$schema")
        if type(schema_id) is not str or ADR_P1_DOMAIN_PREFIXES.get(schema_id) != domain_prefix:
            raise ClosedValidationError("P1 verifier: schema_id / domain_prefix mismatch")
        integrity = P1Integrity.from_dict(envelope.get("integrity"), require_signed=True)
        key_reg = store.get_json_artifact(integrity.key_registry_snapshot_locator)
        if integrity.key_id not in key_reg.get("keys", ()):
            raise ClosedValidationError("P1 verifier: unauthorized key_id")
        if integrity.content_digest != p1_content_digest(envelope):
            raise ClosedValidationError("P1 verifier: content_digest mismatch")
        if integrity.signature_base64 != _compute_domain_sig(envelope, domain_prefix):
            raise ClosedValidationError("P1 verifier: cryptographic signature mismatch")
        self.verified_schemas.append(schema_id)


def _sign_dict(raw_no_int: Mapping[str, Any], key_reg_loc: ArtifactLocator) -> dict[str, Any]:
    schema_id = str(raw_no_int["$schema"])
    unsigned = P1Integrity(key_id=_KEY_ID, key_registry_snapshot_locator=key_reg_loc)
    pre = {**raw_no_int, "integrity": unsigned.to_dict()}
    sig = _compute_domain_sig(pre, ADR_P1_DOMAIN_PREFIXES[schema_id])
    return {**raw_no_int, "integrity": P1Integrity(_KEY_ID, key_reg_loc, p1_content_digest(pre), sig).to_dict()}


def _put_signed_env(
    store: InMemoryCellObjectStore, schema_id: str, body: Mapping[str, Any], key_reg_loc: ArtifactLocator
) -> tuple[dict[str, Any], ArtifactLocator]:
    payload = _sign_dict({"$schema": schema_id, **{k: v for k, v in body.items() if k != "integrity"}}, key_reg_loc)
    return payload, store.put_json_artifact(schema_id, payload)


def _put_signed_obj(
    store: InMemoryCellObjectStore, obj: Any, key_reg_loc: ArtifactLocator
) -> tuple[Any, ArtifactLocator]:
    signed, loc = _put_signed_env(store, obj.SCHEMA, obj.to_dict(), key_reg_loc)
    return type(obj).from_dict(signed, require_signed=True), loc


def _put_git_prov(
    store: InMemoryCellObjectStore, key_reg_loc: ArtifactLocator, repo: str, commit: str, path: str, raw: bytes
) -> tuple[GitArtifactProvenance, ArtifactLocator]:
    prov = GitArtifactProvenance(
        repo, commit, path, compute_git_blob_oid(raw), "sha256:" + hashlib.sha256(raw).hexdigest(), "2026-11-10T00:00:00Z"
    )
    return _put_signed_obj(store, prov, key_reg_loc)


def _put_prereq_chain(
    store: InMemoryCellObjectStore, run_loc: ArtifactLocator, key_reg_loc: ArtifactLocator,
    *, action: str, slot: str, subject_kind: str, result_schema: str, tag: str,
) -> ArtifactLocator:
    res_payload = {"$schema": result_schema, "migration_run_context_locator": run_loc.to_dict(), "tag": tag}
    res_loc = store.put_json_artifact(result_schema, res_payload)
    subj = {"subject_kind": subject_kind, "migration_run_context_locator": run_loc.to_dict(), "tag": tag}
    nonce = f"nonce-pre-{tag}"
    _, a_loc = _put_signed_env(store, AuthorizationReceipt.SCHEMA, {"authorization_id": f"auth:{tag}", "migration_run_context_locator": run_loc.to_dict(), "action": action, "dag_slot": slot, "subject": subj, "parameters_digest": "sha256:" + ("1" * 64), "predecessor_locators": [], "approving_principal_ref": "principal:ops-01", "issued_at_utc": "2026-11-10T00:00:00Z", "valid_until_utc": "2026-11-12T00:00:00Z", "single_use_nonce": nonce}, key_reg_loc)
    _, r_loc = _put_signed_env(store, AuthorizationReservationRecord.SCHEMA, {"reservation_id": f"resv:{tag}", "migration_run_context_locator": run_loc.to_dict(), "authorization_locator": a_loc.to_dict(), "authorization_receipt_digest": a_loc.content_digest, "single_use_nonce": nonce, "action": action, "dag_slot": slot, "subject": subj, "reservation_status": "consumed", "in_doubt_reason": None, "reserved_at_utc": "2026-11-10T00:01:00Z"}, key_reg_loc)
    _, e_loc = _put_signed_env(store, ExecutionReceipt.SCHEMA, {"execution_id": f"exec:{tag}", "migration_run_context_locator": run_loc.to_dict(), "authorization_locator": a_loc.to_dict(), "reservation_locator": r_loc.to_dict(), "single_use_nonce": nonce, "action": action, "dag_slot": slot, "subject": subj, "execution_status": "succeeded", "action_result_locator": res_loc.to_dict(), "executed_at_utc": "2026-11-10T00:02:00Z"}, key_reg_loc)
    _, c_loc = _put_signed_env(store, AuthorizationConsumptionRecord.SCHEMA, {"consumption_id": f"cons:{tag}", "migration_run_context_locator": run_loc.to_dict(), "authorization_locator": a_loc.to_dict(), "authorization_receipt_digest": a_loc.content_digest, "reservation_locator": r_loc.to_dict(), "execution_locator": e_loc.to_dict(), "single_use_nonce": nonce, "action": action, "dag_slot": slot, "consumption_status": "consumed", "consumed_at_utc": "2026-11-10T00:02:00Z"}, key_reg_loc)
    _, p_loc = _put_signed_env(store, EffectProof.SCHEMA, {"effect_proof_id": f"proof:{tag}", "migration_run_context_locator": run_loc.to_dict(), "action": action, "dag_slot": slot, "authorization_locator": a_loc.to_dict(), "reservation_locator": r_loc.to_dict(), "execution_locator": e_loc.to_dict(), "consumption_locator": c_loc.to_dict(), "action_result_locator": res_loc.to_dict(), "verified_at_utc": "2026-11-10T00:03:00Z"}, key_reg_loc)
    return p_loc


def _make_two_campaign_facts(metric_date: str, *, clicks_a: str, clicks_b: str = "25") -> tuple[NormalizedCollectionFact, ...]:
    facts: list[NormalizedCollectionFact] = []
    for camp, clicks in ((_CAMP_A, clicks_a), (_CAMP_B, clicks_b)):
        fk_c = FactKey("binding:meta-primary", "account:ibvi-01", camp, "campaign", metric_date, "metric:clicks_v1", "source-metric:provider:pipeboard.clicks:v1", "attribution:not_applicable", "breakdown:none")
        fk_i = FactKey("binding:meta-primary", "account:ibvi-01", camp, "campaign", metric_date, "metric:impressions_v1", "source-metric:provider:pipeboard.impressions:v1", "attribution:not_applicable", "breakdown:none")
        fk_s = FactKey("binding:meta-primary", "account:ibvi-01", camp, "campaign", metric_date, "metric:spend_v1", "source-metric:provider:pipeboard.spend:v1", "attribution:not_applicable", "breakdown:none")
        facts.extend((
            NormalizedCollectionFact(fk_c, "observed", "int64_count", clicks, "count", None),
            NormalizedCollectionFact(fk_i, "observed", "int64_count", "200", "count", None),
            NormalizedCollectionFact(fk_s, "observed", "int64_minor_currency", "5000", "minor_currency", "BRL"),
        ))
    return compute_normalized_fact_set_digest(facts)[0]


def _two_camp_window_rows(
    rows: tuple[ Any, ...], _q: DuckDbQueryDefinition
) -> tuple[tuple[TaggedScalarCell, ...], ...]:
    nov_rows = [r for r in rows if "2026-11-08" <= r.fact_key.metric_date <= "2026-11-10"]
    out: list[tuple[TaggedScalarCell, ...]] = []
    for camp in (_CAMP_A, _CAMP_B):
        for metric_ref in ("metric:clicks_v1", "metric:spend_v1"):
            m_rows = [r for r in nov_rows if r.fact_key.resource_ref == camp and r.fact_key.metric_semantic_ref == metric_ref]
            if not m_rows:
                continue
            total = sum(int(r.raw_numeric_value) for r in m_rows if r.raw_numeric_value is not None)
            sample = m_rows[0]
            ccy = TaggedScalarCell("null", None) if sample.currency is None else TaggedScalarCell("utf8", sample.currency)
            out.append((
                TaggedScalarCell("opaque_ref", camp), TaggedScalarCell("date", "2026-11-08"),
                TaggedScalarCell("date", "2026-11-10"), TaggedScalarCell("opaque_ref", metric_ref),
                TaggedScalarCell("utf8", "provider_observation"), TaggedScalarCell("utf8", "observed"),
                TaggedScalarCell("utf8", "not_applicable"), TaggedScalarCell("null", None),
                TaggedScalarCell("utf8", sample.value_type or "int64_count"), TaggedScalarCell("int64", str(total)),
                TaggedScalarCell("utf8", sample.unit or "count"), ccy,
            ))
    return tuple(out)


class McpHandlerWorld:
    """Hermetic signed world for snapshot rows, read index, and MCP handler verification."""

    def __init__(self) -> None:
        self.store, self.codec = InMemoryCellObjectStore(), StdlibParquetLandingCodec()
        self.verifier = DeterministicDomainP1Verifier()
        self.cell_ref = "cell:ibvi-primary"
        self.key_reg_loc = self.store.put_json_artifact("smart_ads/key_authorization_registry/v1", {"$schema": "smart_ads/key_authorization_registry/v1", "keys": [_KEY_ID]})
        self.run_loc = self.store.put_json_artifact("smart_ads/migration_run_context/v1", {"$schema": "smart_ads/migration_run_context/v1", "run_id": "run:mcp-001"})
        self._init_registry_and_prereqs()
        self._init_algorithms()
        self._init_snapshots()
        self._init_analytics_and_reports()
        self.default_index = self.build_index()
        self.default_handler = VerifiedStoreMcpReadHandler(self.default_index)

    def _init_registry_and_prereqs(self) -> None:
        d26_fixed = []
        for role, path, blob_oid, file_sha in PINNED_PIPEBOARD_D26_SPECS:
            _, m_loc = _put_signed_obj(self.store, GitArtifactProvenance(PINNED_LEGACY_REPO, PINNED_LEGACY_COMMIT, path, blob_oid, file_sha, "2026-11-10T00:00:00Z"), self.key_reg_loc)
            d26_fixed.append(PinnedGitArtifactMember(role, PINNED_LEGACY_REPO, PINNED_LEGACY_COMMIT, path, blob_oid, file_sha, m_loc))
        raw_drv = PipeboardPhase1Contract("driver-contract:pipeboard-phase1-v1", "pipeboard_hosted", LegacySourcePacket(PINNED_LEGACY_REPO, PINNED_LEGACY_COMMIT, tuple(d26_fixed)), PinnedUpstreamReference(), PipeboardTransportLimits(forbidden_arguments=FORBIDDEN_PIPEBOARD_ARGUMENTS), dict(PIPEBOARD_PHASE1_METRIC_SOURCE_MAPPINGS))
        self.driver_contract, self.driver_loc = _put_signed_obj(self.store, raw_drv, self.key_reg_loc)
        cap = DriverCapabilityEntry("cap:meta_daily_campaign_v1", "1.0.0", "pipeboard_hosted", self.driver_loc, self.driver_loc.content_digest, "scope:campaigns-active", "live_certified", _METRICS_3)
        raw_reg = PrivateRegistrySnapshot(
            "registry-snapshot:ibvi-001", "tenant:ibvi", "2026-11-10T00:00:00Z", "2026-11-15T00:00:00Z",
            "hmac-sha256-b32-v1", "key:tenant-ibvi-hmac-v1",
            (RegistryBinding("binding:meta-primary", "account:ibvi-01", "provider:pipeboard", "meta", "BRL", "pipeboard_hosted"),),
            (AuthorizedScopeRelation("front:pinna", "profile:pinna-ops", "binding:meta-primary", "scope:campaigns-active"),), (cap,),
        )
        self.registry, self.reg_loc = _put_signed_obj(self.store, raw_reg, self.key_reg_loc)
        _, self.clock_loc = _put_signed_obj(self.store, ClockAttestation("clock:att-001", "2026-11-11T03:00:00.000000Z", 250, "2026-11-11T02:59:50Z", "2026-11-11T03:00:30Z", 30), self.key_reg_loc)
        p_locs = {k: _put_signed_env(self.store, s, {"migration_run_context_locator": self.run_loc.to_dict(), "slot": k}, self.key_reg_loc)[1] for k, s in (("step2", "smart_ads/legacy_step2_implementation_evidence/v1"), ("act", "smart_ads/smart_ads_live_read_activation_receipt/v1"), ("head", "smart_ads/live_certification_head/v1"), ("trans", "smart_ads/live_certification_transition/v1"), ("cert", "smart_ads/live_certification_certificate/v1"), ("gate3", "smart_ads/gate3_selection_receipt/v1"))}
        _, del_loc = _put_signed_obj(self.store, IbviAdsDelegationContext("/ibvi-ads", "conductor:hermes", "front:pinna", "profile:pinna-ops", "tenant:ibvi", "binding:meta-primary", "scope:campaigns-active", "smart_ads.queries.get_campaign_performance_v1", "sha256:" + ("8" * 64), "2026-11-11T02:55:00Z", "2026-11-11T04:00:00Z", "nonce-mcp-001"), self.key_reg_loc)
        wi_pf = _put_prereq_chain(self.store, self.run_loc, self.key_reg_loc, action="workload_identity_provision", slot="workload_identity_effect_proof", subject_kind="workload_identity_target", result_schema="smart_ads/workload_identity_execution_result/v1", tag="wi")
        dp_pf = _put_prereq_chain(self.store, self.run_loc, self.key_reg_loc, action="deployment_config_apply", slot="deployment_config_effect_proof", subject_kind="deployment_target", result_schema="smart_ads/deployment_config_execution_result/v1", tag="dp")
        self.prereqs = PurposePrerequisiteLocators(purpose="operational_read", legacy_step2_evidence_locator=p_locs["step2"], live_read_activation_receipt_locator=p_locs["act"], live_certification_head_locator=p_locs["head"], live_certification_transition_locator=p_locs["trans"], live_certification_certificate_locator=p_locs["cert"], gate3_operational_renewal_locator=p_locs["gate3"], workload_identity_effect_proof_locator=wi_pf, deployment_effect_proof_locator=dp_pf, delegation_context_locator=del_loc)

    def _init_algorithms(self) -> None:
        sp, sp_loc = _put_git_prov(self.store, self.key_reg_loc, "aiconnai/smart-ads", "a" * 40, "src/smart_ads/application/curation_pipeline.py", b"# sanitize")
        cp, cp_loc = _put_git_prov(self.store, self.key_reg_loc, "aiconnai/smart-ads", "a" * 40, "src/smart_ads/domain/curation.py", b"# curate")
        rp, rp_loc = _put_git_prov(self.store, self.key_reg_loc, "aiconnai/smart-ads", "a" * 40, "src/smart_ads/analytics/reporting.py", b"# render")
        _, self.tmpl_loc = _put_git_prov(self.store, self.key_reg_loc, "aiconnai/smart-ads", "a" * 40, "src/smart_ads/analytics/template.json", b'{"v":1}')
        self.san_alg = AlgorithmProvenanceIdentity("algorithm:sanitize-v1", "1.0.0", sp_loc, sp.repository, sp.commit_sha, sp.path, sp.git_blob_oid, sp.file_content_sha256, "cpython-3.12", SanitizedCandidateFactSet.SCHEMA)
        self.cur_alg = AlgorithmProvenanceIdentity("algorithm:curate-v1", "1.0.0", cp_loc, cp.repository, cp.commit_sha, cp.path, cp.git_blob_oid, cp.file_content_sha256, "cpython-3.12", CurationExecution.SCHEMA)
        self.render_alg = AlgorithmProvenanceIdentity("algorithm:render-v1", "1.0.0", rp_loc, rp.repository, rp.commit_sha, rp.path, rp.git_blob_oid, rp.file_content_sha256, "cpython-3.12", REPORT_EXECUTION_SCHEMA)
        self.duck_bytes, self.ext_bytes = b"\x7fELF-duckdb-1.5.5", b"ext-parquet-1.5.5"
        self.store.put_bytes(self.duck_bytes)
        self.store.put_bytes(self.ext_bytes)

    def _store_op_read(self, metric_date: str, tag: str, *, clicks_a: str, collected_at: str) -> ArtifactLocator:
        dr = DateRange(metric_date, metric_date, True)
        cqc = CanonicalQueryContract("tenant:ibvi", "binding:meta-primary", "account:ibvi-01", "scope:campaigns-active", "meta", "previous_local_day", dr, "America/Sao_Paulo", "2026a", "campaign", _METRICS_3, ("cap:meta_daily_campaign_v1",))
        raw_adm = AdmittedCollection(f"admission:{tag}", "operational_read", "sha256:" + ("5" * 64), "tenant:ibvi", "binding:meta-primary", "account:ibvi-01", "scope:campaigns-active", "campaign", ("cap:meta_daily_campaign_v1",), "2026-11-11T03:00:00Z", self.clock_loc, 250, "2026a", "America/Sao_Paulo", dr, self.reg_loc, self.reg_loc.content_digest, "BRL", "pipeboard_hosted", self.driver_loc, self.driver_loc.content_digest, "sha256:" + ("6" * 64), cqc, cqc.canonical_query_digest, self.prereqs, ("operational_provider_read",))
        adm, adm_loc = _put_signed_obj(self.store, raw_adm, self.key_reg_loc)
        keys = tuple(ExpectedResourceKey("binding:meta-primary", "account:ibvi-01", c, "campaign", metric_date) for c in (_CAMP_A, _CAMP_B))
        _, inv_loc = _put_signed_obj(self.store, ExpectedResourceInventory(f"inventory:{tag}", self.reg_loc, self.reg_loc.content_digest, "tenant:ibvi", "binding:meta-primary", "account:ibvi-01", "scope:campaigns-active", dr, keys), self.key_reg_loc)
        facts = _make_two_campaign_facts(metric_date, clicks_a=clicks_a)
        _, f_dig = compute_normalized_fact_set_digest(facts)
        rctx = RetrievalContext(collected_at, f"observation:{tag}", "pipeboard-0.1.0", "1.0.0")
        cands = tuple(sorted((project_collection_fact_to_landing_row(f, rctx) for f in facts), key=lambda r: r.candidate_sort_key_jcs()))
        _, res_loc = _put_signed_obj(self.store, CollectionResult(adm_loc, adm_loc.content_digest, "operational", self.reg_loc, self.reg_loc.content_digest, adm.requested_capabilities, adm.requested_capabilities, rctx, _clean_transport(), cands, facts, f_dig, ()), self.key_reg_loc)
        subj = ProviderCallTarget(self.run_loc, adm_loc, "operational", "provider-target:pipeboard", adm.canonical_query_digest, self.reg_loc, "tenant:ibvi", "binding:meta-primary", "account:ibvi-01", "scope:campaigns-active", self.prereqs.delegation_context_locator)
        nonce = f"nonce-op-{tag}"
        _, a_loc = _put_signed_obj(self.store, AuthorizationReceipt(f"auth:{tag}", self.run_loc, "provider_operational_read", "operational_provider_read_effect_proof", subj, "sha256:" + ("7" * 64), (adm_loc,), "principal:op-01", "2026-11-11T03:00:00Z", "2026-11-11T04:00:00Z", nonce), self.key_reg_loc)
        _, rv_loc = _put_signed_obj(self.store, AuthorizationReservationRecord(f"rv:{tag}", self.run_loc, a_loc, a_loc.content_digest, nonce, "provider_operational_read", "operational_provider_read_effect_proof", subj, "consumed", None, "2026-11-11T03:01:00Z"), self.key_reg_loc)
        _, ex_loc = _put_signed_obj(self.store, ExecutionReceipt(f"ex:{tag}", self.run_loc, a_loc, rv_loc, nonce, "provider_operational_read", "operational_provider_read_effect_proof", subj, "succeeded", res_loc, "2026-11-11T03:02:00Z"), self.key_reg_loc)
        _, cn_loc = _put_signed_obj(self.store, AuthorizationConsumptionRecord(f"cn:{tag}", self.run_loc, a_loc, a_loc.content_digest, rv_loc, ex_loc, nonce, "provider_operational_read", "operational_provider_read_effect_proof", "consumed", "2026-11-11T03:02:00Z"), self.key_reg_loc)
        _, pf_loc = _put_signed_obj(self.store, EffectProof(f"pf:{tag}", self.run_loc, "provider_operational_read", "operational_provider_read_effect_proof", a_loc, rv_loc, ex_loc, cn_loc, res_loc, "2026-11-11T03:03:00Z"), self.key_reg_loc)
        _, ev_loc = _put_signed_obj(self.store, OperationalReadEvidence(self.run_loc, "tenant:ibvi", "binding:meta-primary", "account:ibvi-01", "scope:campaigns-active", adm.canonical_query_digest, self.reg_loc, self.reg_loc.content_digest, inv_loc, adm_loc, adm_loc.content_digest, res_loc, res_loc.content_digest, f_dig, a_loc, rv_loc, ex_loc, cn_loc, pf_loc), self.key_reg_loc)
        return ev_loc

    def _materialize_gen(
        self, tag: str, mode: str, date_str: str, ev_loc: ArtifactLocator, base_cat_loc: ArtifactLocator,
        snap_loc: ArtifactLocator | None, cut_loc: ArtifactLocator | None, hist_locs: tuple[ArtifactLocator, ...],
        parent_loc: ArtifactLocator | None,
    ) -> tuple[GenerationManifest, ArtifactLocator, ArtifactLocator]:
        raw_cs = build_sanitized_candidate_fact_set(migration_run_context_locator=self.run_loc, sanitization_algorithm_identity=self.san_alg, store=self.store, evidence_locators=(ev_loc,), require_signed_inputs=True)
        _, cs_loc = _put_signed_obj(self.store, raw_cs, self.key_reg_loc)
        win = compute_curation_window(date_str, "America/Sao_Paulo", "2026a", 1)
        raw_cur = CurationExecution(self.run_loc, f"cur:{tag}", mode, date_str, "America/Sao_Paulo", "2026a", 1, win, cs_loc, self.cur_alg, self.genesis_loc if mode == "genesis" else None, base_cat_loc, snap_loc, cut_loc, hist_locs, "2026-11-11T03:05:00Z")  # type: ignore[arg-type]
        _, cur_loc = _put_signed_obj(self.store, raw_cur, self.key_reg_loc)
        raw_gm, _ = materialize_parquet_generation(generation_id=f"gen:{tag}", created_at_utc="2026-11-11T03:06:00Z", registry_snapshot_locator=self.reg_loc, curation_locator=cur_loc, store=self.store, parquet_codec=self.codec, parent_generation_manifest_locator=parent_loc)
        gm, gm_loc = _put_signed_obj(self.store, raw_gm, self.key_reg_loc)
        return gm, gm_loc, cur_loc

    def _commit_cut(
        self, svc: GlobalDatasetCatalogService, *, idx: int, op: str, seq: int, gm: GenerationManifest,
        gm_loc: ArtifactLocator, genesis_loc: ArtifactLocator | None = None,
    ) -> tuple[DatasetSnapshot, ArtifactLocator, ArtifactLocator]:
        old_loc, old_cat = svc.current_head()
        new_head = ActivePartitionHead(gm.partition_key, seq, gm_loc)
        heads = tuple(sorted((*(h for h in old_cat.partition_heads if h.partition_key != gm.partition_key), new_head), key=lambda h: h.partition_key.encode("utf-8")))
        ts = f"2026-11-11T03:0{6 + idx}:00Z"
        cat_s, _ = _put_signed_obj(self.store, DatasetCatalog(f"catalog:{idx}", self.cell_ref, idx, ts, heads), self.key_reg_loc)
        cons_s = None if genesis_loc is None else _put_signed_obj(self.store, DatasetCatalogGenesisConsumptionRecord(genesis_loc, genesis_loc.content_digest, old_loc, old_loc.content_digest, cat_s.locator(), cat_s.locator().content_digest, f"cut:{idx}", f"lin:{idx}", ts), self.key_reg_loc)[0]
        proj = CatalogCasRequestProjection(op, old_cat.catalog_epoch, old_loc.content_digest, gm.partition_key, seq, gm_loc)  # type: ignore[arg-type]
        rec_s, _ = _put_signed_obj(self.store, DatasetCatalogCutReceipt(f"cut:{idx}", self.cell_ref, self.run_loc, old_loc, old_loc.content_digest, old_cat.catalog_epoch, cat_s.locator(), cat_s.locator().content_digest, idx, proj, f"lin:{idx}", ts, None if genesis_loc is None else genesis_loc, None if genesis_loc is None else genesis_loc.content_digest, None if cons_s is None else cons_s.locator(), None if cons_s is None else cons_s.locator().content_digest), self.key_reg_loc)
        _, _, _, rec_loc = svc.commit_partition_cut(cut_id=f"cut:{idx}", cas_linearization_id=f"lin:{idx}", committed_at_utc=ts, expected_old_catalog_locator=old_loc, expected_old_catalog_epoch=old_cat.catalog_epoch, generation_manifest_locator=gm_loc, new_catalog_id=f"catalog:{idx}", genesis_record_locator=genesis_loc, consumption_integrity=None if cons_s is None else cons_s.integrity, catalog_integrity=cat_s.integrity, receipt_integrity=rec_s.integrity)
        raw_snap, _ = publish_dataset_snapshot(snapshot_id=f"snapshot:{idx}", created_at=ts, cut_receipt_locator=rec_loc, store=self.store)
        snap_s, snap_loc = _put_signed_obj(self.store, raw_snap, self.key_reg_loc)
        return snap_s, snap_loc, rec_loc

    def _init_snapshots(self) -> None:
        _, self.epoch0_loc = _put_signed_obj(self.store, DatasetCatalog("catalog:0", self.cell_ref, 0, "2026-11-10T00:00:00Z", ()), self.key_reg_loc)
        _, self.genesis_loc = _put_signed_obj(self.store, DatasetCatalogGenesisRecord("genesis:001", self.cell_ref, self.run_loc, self.epoch0_loc, self.epoch0_loc.content_digest, "authority:root", "2026-11-10T00:01:00Z"), self.key_reg_loc)
        svc = GlobalDatasetCatalogService(self.store, self.epoch0_loc, parquet_codec=self.codec, require_signed=True)
        ev_oct = self._store_op_read("2026-10-31", "oct", clicks_a="12", collected_at="2026-11-01T03:02:00.000000Z")
        self.gm_oct, self.gm_oct_loc, _ = self._materialize_gen("oct", "genesis", "2026-10-31", ev_oct, self.epoch0_loc, None, None, (), None)
        _, snap0_loc, cut1_loc = self._commit_cut(svc, idx=1, op="add_partition", seq=1, gm=self.gm_oct, gm_loc=self.gm_oct_loc, genesis_loc=self.genesis_loc)
        ev_n1 = self._store_op_read("2026-11-10", "nov1", clicks_a="999", collected_at="2026-11-11T03:02:00.000000Z")
        self.gm_nov1, self.gm_nov1_loc, self.cur_nov1_loc = self._materialize_gen("nov1", "incremental", "2026-11-10", ev_n1, svc.current_head()[0], snap0_loc, cut1_loc, (), None)
        self.snap1, self.snap1_loc, cut2_loc = self._commit_cut(svc, idx=2, op="add_partition", seq=1, gm=self.gm_nov1, gm_loc=self.gm_nov1_loc)
        ev_n2 = self._store_op_read("2026-11-10", "nov2", clicks_a="0", collected_at="2026-11-11T03:04:00.000000Z")
        self.gm_nov2, self.gm_nov2_loc, self.cur_nov2_loc = self._materialize_gen("nov2", "incremental", "2026-11-10", ev_n2, svc.current_head()[0], self.snap1_loc, cut2_loc, (self.gm_nov1_loc,), self.gm_nov1_loc)
        self.snap2, self.snap2_loc, _ = self._commit_cut(svc, idx=3, op="replace_partition", seq=2, gm=self.gm_nov2, gm_loc=self.gm_nov2_loc)

    def _run_certified_chain(
        self, tag: str, snap_loc: ArtifactLocator, cur_loc: ArtifactLocator,
        hist_locs: tuple[ArtifactLocator, ...], lineage_gms: tuple[GenerationManifest, ...],
    ) -> tuple[ReportExecution, ArtifactLocator, ArtifactLocator, AnalyticalCertificationRecord, ArtifactLocator, tuple[ArtifactLocator, ...]]:
        l_rows = tuple(r for gm in lineage_gms for pq in gm.parquet_object_locators for r in self.codec.decode_and_verify_landing_rows(self.store.get_bytes(pq.object_ref, expected_size_bytes=pq.size_bytes), expected_partition_key=pq.partition_key))
        eval_ctx = EvaluationContext(self.policy, EvaluationScope("tenant:ibvi", "scope:campaigns-active", "campaign", "meta", "BRL"), "2026-11-11T03:15:00.000000Z", "2026-11-10", 1, "2026-11-10", self.eval_inv, "result:metrics", derive_snapshot_restatement_history(self.eval_inv, l_rows))
        cols = tuple(ResultColumn(n, t, nl) for n, t, nl in METRIC_WINDOW_COLUMNS)
        q_m = DuckDbQueryDefinition("result:metrics", "query:metrics", "SELECT 1", self.metrics_schema_loc, "relation", cols, _METRIC_UKEY, _METRIC_ORDER)
        exts = (DuckDbExtensionSpec("parquet", "1.5.5", "explicit_local_binary", DuckDbExtensionBinaryLocator.for_binary_bytes(self.ext_bytes)),)
        raw_b = AnalysisReplayInputBundle(f"bundle:{tag}", self.run_loc, snap_loc, "1.5.5", DuckDbBinaryObjectLocator.for_binary_bytes(self.duck_bytes), exts, (DuckDbSessionSetting("threads", TaggedScalarCell("int64", "1")),), (), (q_m,), self.policy_loc, (self.tmpl_loc,))
        _, b_loc = _put_signed_obj(self.store, raw_b, self.key_reg_loc)
        eng = DeterministicInMemoryDuckDbEngine({"result:metrics": _two_camp_window_rows})
        _, _, u_res = execute_analysis_replay_bundle(bundle_locator=b_loc, store=self.store, parquet_codec=self.codec, duckdb_engine=eng, require_signed_inputs=True)
        s_res, _ = _put_signed_obj(self.store, u_res[0][0], self.key_reg_loc)
        s_exec_pre, _ = _put_signed_obj(self.store, AnalysisExecution(b_loc, CanonicalResultSet.build(b_loc, (CanonicalResultEntry.from_result(s_res),))), self.key_reg_loc)
        _, exec_loc, _ = execute_analysis_replay_bundle(bundle_locator=b_loc, store=self.store, parquet_codec=self.codec, duckdb_engine=eng, result_integrities={"result:metrics": s_res.integrity}, execution_integrity=s_exec_pre.integrity, require_signed_inputs=True)  # type: ignore[dict-item]
        att = (AttestedCertificationInput(CertificationInput(DerivedCertificationStatus.VERIFIED, "phase1_7b_base"), True),)
        _, _, _, _, u_f = execute_certified_report(report_id=f"rep:{tag}", executed_at_utc="2026-11-11T03:20:00Z", bundle_locator=b_loc, execution_locator=exec_loc, evaluation_context=eval_ctx, expected_resource_inventory_locator=self.eval_inv_loc, curation_execution_locator=cur_loc, restatement_history_generation_locators=hist_locs, attested_certification_inputs=att, report_template_provenance_locator=self.tmpl_loc, render_algorithm_identity=self.render_alg, store=self.store, parquet_codec=self.codec)
        f_ints = tuple(_put_signed_obj(self.store, f, self.key_reg_loc)[0].integrity for f, _ in u_f)
        _, _, u_c2, _, _ = execute_certified_report(report_id=f"rep:{tag}", executed_at_utc="2026-11-11T03:20:00Z", bundle_locator=b_loc, execution_locator=exec_loc, evaluation_context=eval_ctx, expected_resource_inventory_locator=self.eval_inv_loc, curation_execution_locator=cur_loc, restatement_history_generation_locators=hist_locs, attested_certification_inputs=att, report_template_provenance_locator=self.tmpl_loc, render_algorithm_identity=self.render_alg, store=self.store, parquet_codec=self.codec, finding_integrities=f_ints)  # type: ignore[arg-type]
        c_int = _put_signed_obj(self.store, u_c2, self.key_reg_loc)[0].integrity
        u_r3, _, _, _, _ = execute_certified_report(report_id=f"rep:{tag}", executed_at_utc="2026-11-11T03:20:00Z", bundle_locator=b_loc, execution_locator=exec_loc, evaluation_context=eval_ctx, expected_resource_inventory_locator=self.eval_inv_loc, curation_execution_locator=cur_loc, restatement_history_generation_locators=hist_locs, attested_certification_inputs=att, report_template_provenance_locator=self.tmpl_loc, render_algorithm_identity=self.render_alg, store=self.store, parquet_codec=self.codec, finding_integrities=f_ints, certification_integrity=c_int)  # type: ignore[arg-type]
        r_int = _put_signed_obj(self.store, u_r3, self.key_reg_loc)[0].integrity
        rep, rep_loc, cert, cert_loc, f_pairs = execute_certified_report(report_id=f"rep:{tag}", executed_at_utc="2026-11-11T03:20:00Z", bundle_locator=b_loc, execution_locator=exec_loc, evaluation_context=eval_ctx, expected_resource_inventory_locator=self.eval_inv_loc, curation_execution_locator=cur_loc, restatement_history_generation_locators=hist_locs, attested_certification_inputs=att, report_template_provenance_locator=self.tmpl_loc, render_algorithm_identity=self.render_alg, store=self.store, parquet_codec=self.codec, finding_integrities=f_ints, certification_integrity=c_int, report_integrity=r_int, require_signed_inputs=True)  # type: ignore[arg-type]
        return rep, rep_loc, exec_loc, cert, cert_loc, tuple(loc for _, loc in f_pairs)

    def _init_analytics_and_reports(self) -> None:
        raw_pol = AnalysisPolicy.from_dict({
            "$schema": "smart_ads/analysis_policy/v1", "policy_id": "policy:waste-restatement-v1", "policy_version": "1", "tenant_ref": "tenant:ibvi",
            "applicability_scope": {"resource_scope_ref": "scope:campaigns-active", "resource_level": "campaign", "ad_platform_ref": "meta", "currency": "BRL"},
            "validity": {"valid_from_utc": "2026-01-01T00:00:00.000000Z", "valid_until_utc": "2027-01-01T00:00:00.000000Z"},
            "rules": [
                {"rule_id": "rule:restatement-1d", "rule_type": "restatement", "lookback_days": 1, "restatement_kinds": ["value_change"]},
                {"rule_id": "rule:waste-3d", "rule_type": "waste", "window_days": 3, "spend_metric_ref": "metric:spend_v1", "outcome_metric_ref": "metric:clicks_v1", "min_spend_minor": "1000", "max_outcome_count": "0"},
            ],
        })
        self.policy, self.policy_loc = _put_signed_obj(self.store, raw_pol, self.key_reg_loc)
        cols = tuple(ResultColumn(n, t, nl) for n, t, nl in METRIC_WINDOW_COLUMNS)
        _, self.metrics_schema_loc = _put_signed_obj(self.store, AnalysisResultSchema("relation", cols, _METRIC_UKEY), self.key_reg_loc)
        u_keys = tuple(
            ExpectedResourceKey("binding:meta-primary", "account:ibvi-01", c, "campaign", d)
            for d in ("2026-10-31", "2026-11-10") for c in (_CAMP_A, _CAMP_B)
        )
        self.eval_inv, self.eval_inv_loc = _put_signed_obj(
            self.store,
            ExpectedResourceInventory("inventory:wide-001", self.reg_loc, self.reg_loc.content_digest, "tenant:ibvi", "binding:meta-primary", "account:ibvi-01", "scope:campaigns-active", DateRange("2026-10-31", "2026-11-10", True), u_keys),
            self.key_reg_loc,
        )
        self.rep1, self.rep1_loc, self.exec1_loc, self.cert1, self.cert1_loc, self.f1_locs = self._run_certified_chain("s1", self.snap1_loc, self.cur_nov1_loc, (), (self.gm_oct, self.gm_nov1))
        self.rep2, self.rep2_loc, self.exec2_loc, self.cert2, self.cert2_loc, self.f2_locs = self._run_certified_chain("s2", self.snap2_loc, self.cur_nov2_loc, (self.gm_nov1_loc,), (self.gm_oct, self.gm_nov1, self.gm_nov2))

    def build_index(self, **overrides: Any) -> McpVerifiedReadIndex:
        scope_key = ("tenant:ibvi", "binding:meta-primary", "scope:campaigns-active")
        kwargs: dict[str, Any] = {
            "active_dataset_snapshot_locator": self.snap2_loc,
            "registry_snapshot_locator": self.reg_loc,
            "scope_inventory_locators": {scope_key: (self.eval_inv_loc,)},
            "findings_entries": (
                (self.snap1_loc, *scope_key, self.exec1_loc, self.cert1_loc, self.f1_locs, self.eval_inv_loc),
                (self.snap2_loc, *scope_key, self.exec2_loc, self.cert2_loc, self.f2_locs, self.eval_inv_loc),
            ),
            "summary_report_entries": (
                (self.snap2_loc, *scope_key, "daily", "2026-11-10", "2026-11-10", self.rep2_loc),
                (self.snap2_loc, *scope_key, "weekly", "2026-11-04", "2026-11-10", self.rep2_loc),
            ),
            "store": self.store,
            "parquet_codec": self.codec,
            "signature_verifier": self.verifier,
            "require_signed": True,
        }
        kwargs.update(overrides)
        return McpVerifiedReadIndex.build(**kwargs)


@pytest.fixture(scope="module")
def world() -> McpHandlerWorld:
    return McpHandlerWorld()


def _mcp_ctx(
    method: str,
    *,
    front_ref: str = "front:pinna",
    profile_ref: str = "profile:pinna-ops",
    tenant_ref: str = "tenant:ibvi",
    binding_ref: str = "binding:meta-primary",
    resource_scope_ref: str = "scope:campaigns-active",
    clock_lower_utc: str = "2026-11-12T12:01:00Z",
    clock_upper_utc: str = "2026-11-12T12:01:02Z",
    issued_at_utc: str = "2026-11-12T12:00:00Z",
    valid_until_utc: str = "2026-11-12T12:15:00Z",
) -> McpRuntimeContext:
    del_loc = ArtifactLocator.from_digest("smart_ads/ibvi_ads_delegation_context/v1", "sha256:" + ("e" * 64))
    deleg = McpDelegationContext(
        schema="smart_ads/ibvi_ads_delegation_context/v1", route="/ibvi-ads", host_conductor_ref="conductor:hermes",
        front_ref=front_ref, profile_ref=profile_ref, tenant_ref=tenant_ref, binding_ref=binding_ref,
        resource_scope_ref=resource_scope_ref, allowed_method=method, policy_digest="sha256:" + ("d" * 64),
        issued_at_utc=issued_at_utc, valid_until_utc=valid_until_utc, nonce="nonce-mcp-test-01", locator=del_loc,
    )
    return McpRuntimeContext(clock_lower_utc=clock_lower_utc, clock_upper_utc=clock_upper_utc, delegation_context=deleg)


def _call_wire(
    handler: McpReadHandlerPort, method: str, params: Mapping[str, Any], *, req_id: str | int = "req-1",
    ctx: McpRuntimeContext | None = None,
) -> dict[str, Any]:
    raw = canonicalize_jcs({"jsonrpc": "2.0", "id": req_id, "method": method, "params": dict(params)})
    outcome = handle_mcp_request_bytes(raw, ctx or _mcp_ctx(method), handler=handler)
    assert outcome.rejection is None and outcome.admitted_request is not None
    return loads_strict_json(outcome.wire_bytes)


def test_exports_and_index_direct_construction_guard(world: McpHandlerWorld) -> None:
    expected = ["McpVerifiedReadIndex", "VerifiedStoreMcpReadHandler", "load_verified_snapshot_rows"]
    assert mcp_read_handler_mod.__all__ == expected
    assert application_pkg.__all__ == sorted(application_pkg.__all__, key=lambda s: s.encode("utf-8"))
    for sym in expected:
        assert sym in application_pkg.__all__ and getattr(application_pkg, sym) is getattr(mcp_read_handler_mod, sym)
    idx = world.build_index()
    handler = VerifiedStoreMcpReadHandler(idx)
    assert isinstance(handler, McpReadHandlerPort)
    with pytest.raises(ClosedValidationError):
        VerifiedStoreMcpReadHandler("not-an-index")  # type: ignore[arg-type]
    with pytest.raises(ClosedValidationError):
        McpVerifiedReadIndex(  # type: ignore[call-arg]
            world.reg_loc, world.registry, world.snap2_loc, world.snap2, (), {}, {}, {}, object()
        )


def test_load_verified_snapshot_rows_active_heads_sorting_and_p1_gate(world: McpHandlerWorld) -> None:
    verifier = DeterministicDomainP1Verifier()
    snap, rows = load_verified_snapshot_rows(
        world.snap2_loc, store=world.store, parquet_codec=world.codec, signature_verifier=verifier, require_signed=True
    )
    assert snap == world.snap2
    assert DatasetSnapshot.SCHEMA in verifier.verified_schemas
    assert GenerationManifest.SCHEMA in verifier.verified_schemas
    assert len(rows) == 12
    jcs_keys = [canonicalize_jcs(r.fact_key.to_dict()) for r in rows]
    assert jcs_keys == sorted(jcs_keys) and len(set(jcs_keys)) == 12
    nov_clicks_a = [r for r in rows if r.fact_key == FactKey("binding:meta-primary", "account:ibvi-01", _CAMP_A, "campaign", "2026-11-10", "metric:clicks_v1", "source-metric:provider:pipeboard.clicks:v1", "attribution:not_applicable", "breakdown:none")]
    assert len(nov_clicks_a) == 1 and nov_clicks_a[0].raw_numeric_value == "0"
    with pytest.raises(ClosedValidationError):
        load_verified_snapshot_rows(world.snap2_loc, store=world.store, parquet_codec=world.codec, signature_verifier=None, require_signed=True)
    snap_u, rows_u = load_verified_snapshot_rows(world.snap2_loc, store=world.store, parquet_codec=world.codec, signature_verifier=None, require_signed=False)
    assert snap_u == world.snap2 and rows_u == rows


def test_load_verified_snapshot_rows_rejects_bad_signature_or_corrupt_parquet(world: McpHandlerWorld) -> None:
    class RejectingVerifier(P1SignatureVerifierPort):
        def verify_p1_envelope_signature(self, *, envelope: Mapping[str, Any], domain_prefix: str, store: CellObjectStorePort) -> None:
            raise ValueError("bad Ed25519 signature")

    with pytest.raises(ClosedValidationError):
        load_verified_snapshot_rows(world.snap2_loc, store=world.store, parquet_codec=world.codec, signature_verifier=RejectingVerifier(), require_signed=True)

    class CorruptParquetStore(CellObjectStorePort):
        def put_bytes(self, raw: bytes) -> str:
            return world.store.put_bytes(raw)

        def get_bytes(self, object_ref: str, *, expected_size_bytes: int | None = None) -> bytes:
            raw = world.store.get_bytes(object_ref, expected_size_bytes=expected_size_bytes)
            return b"X" * len(raw)

        def has_object(self, object_ref: str) -> bool:
            return world.store.has_object(object_ref)

        def put_json_artifact(self, schema_id: str, payload: Mapping[str, Any]) -> ArtifactLocator:
            return world.store.put_json_artifact(schema_id, payload)

        def get_json_artifact(self, locator: ArtifactLocator) -> dict[str, Any]:
            return world.store.get_json_artifact(locator)

    with pytest.raises(ClosedValidationError):
        load_verified_snapshot_rows(world.snap2_loc, store=CorruptParquetStore(), parquet_codec=world.codec, signature_verifier=world.verifier, require_signed=True)


def test_index_build_rejects_mismatched_inventory_duplicates_and_bad_windows(world: McpHandlerWorld) -> None:
    scope_key = ("tenant:ibvi", "binding:meta-primary", "scope:campaigns-active")
    other_reg_loc = ArtifactLocator.from_digest(PrivateRegistrySnapshot.SCHEMA, "sha256:" + ("f" * 64))
    _, bad_inv_loc = _put_signed_obj(
        world.store,
        ExpectedResourceInventory("inventory:bad-reg", other_reg_loc, other_reg_loc.content_digest, "tenant:ibvi", "binding:meta-primary", "account:ibvi-01", "scope:campaigns-active", DateRange("2026-11-10", "2026-11-10", True), (ExpectedResourceKey("binding:meta-primary", "account:ibvi-01", _CAMP_A, "campaign", "2026-11-10"),)),
        world.key_reg_loc,
    )
    with pytest.raises(ClosedValidationError):
        world.build_index(scope_inventory_locators={scope_key: (bad_inv_loc,)})
    with pytest.raises(ClosedValidationError):
        world.build_index(scope_inventory_locators={("tenant:ibvi", "binding:meta-primary", "scope:other"): (world.eval_inv_loc,)})
    dup_f = (world.snap2_loc, *scope_key, world.exec2_loc, world.cert2_loc, world.f2_locs, world.eval_inv_loc)
    with pytest.raises(ClosedValidationError):
        world.build_index(findings_entries=(dup_f, dup_f))
    with pytest.raises(ClosedValidationError):
        world.build_index(findings_entries=((world.snap1_loc, *scope_key, world.exec2_loc, world.cert2_loc, world.f2_locs, world.eval_inv_loc),))
    with pytest.raises(ClosedValidationError):
        world.build_index(summary_report_entries=((world.snap2_loc, *scope_key, "weekly", "2026-11-05", "2026-11-10", world.rep2_loc),))
    with pytest.raises(ClosedValidationError):
        world.build_index(summary_report_entries=((world.snap2_loc, *scope_key, "daily", "2026-11-09", "2026-11-09", world.rep2_loc),))


def test_handler_registry_freshness_and_scope_gates_fail_closed_32603(world: McpHandlerWorld) -> None:
    handler = world.default_handler
    method = "smart_ads.queries.get_campaign_performance_v1"
    base_params = {
        "tenant_ref": "tenant:ibvi",
        "binding_ref": "binding:meta-primary",
        "resource_scope_ref": "scope:campaigns-active",
        "date_range": {"start_date": "2026-11-10", "end_date": "2026-11-10"},
    }
    bad_contexts = (
        _mcp_ctx(method, front_ref="front:unauthorized"),
        _mcp_ctx(method, profile_ref="profile:unauthorized"),
        _mcp_ctx(method, tenant_ref="tenant:other", issued_at_utc="2026-11-12T12:00:00Z"),
        _mcp_ctx(method, clock_lower_utc="2026-11-09T23:59:59Z", clock_upper_utc="2026-11-10T00:00:01Z", issued_at_utc="2026-11-09T23:50:00Z"),
        _mcp_ctx(method, clock_lower_utc="2026-11-14T23:59:59Z", clock_upper_utc="2026-11-15T00:00:00Z", issued_at_utc="2026-11-14T23:50:00Z", valid_until_utc="2026-11-15T00:10:00Z"),
    )
    for idx, bad_ctx in enumerate(bad_contexts):
        p = {**base_params, "tenant_ref": bad_ctx.delegation_context.tenant_ref}  # type: ignore[union-attr]
        resp = _call_wire(handler, method, p, req_id=f"gate-{idx}", ctx=bad_ctx)
        assert resp == {"jsonrpc": "2.0", "id": f"gate-{idx}", "error": {"code": -32603, "message": "Internal error"}}
    with pytest.raises(ClosedValidationError):
        handler.handle("not-an-admitted-request")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "deferred_method",
    (
        "smart_ads.queries.get_ad_performance_v1",
        "smart_ads.queries.get_adset_performance_v1",
    ),
)
def test_deferred_ad_and_adset_methods_return_closed_32603(world: McpHandlerWorld, deferred_method: str) -> None:
    params = {
        "tenant_ref": "tenant:ibvi",
        "binding_ref": "binding:meta-primary",
        "resource_scope_ref": "scope:campaigns-active",
        "date_range": {"start_date": "2026-11-10", "end_date": "2026-11-10"},
    }
    resp = _call_wire(world.default_handler, deferred_method, params, req_id="def-1")
    assert resp == {"jsonrpc": "2.0", "id": "def-1", "error": {"code": -32603, "message": "Internal error"}}


def test_campaign_performance_projection_filtering_and_c92_hygiene(world: McpHandlerWorld) -> None:
    handler = world.default_handler
    method = "smart_ads.queries.get_campaign_performance_v1"
    resp = _call_wire(
        handler,
        method,
        {
            "tenant_ref": "tenant:ibvi",
            "binding_ref": "binding:meta-primary",
            "resource_scope_ref": "scope:campaigns-active",
            "date_range": {"start_date": "2026-11-10", "end_date": "2026-11-10"},
            "resource_refs": [_CAMP_A],
            "metric_refs": ["metric:clicks_v1", "metric:spend_v1"],
        },
        req_id=101,
    )
    res = resp["result"]
    assert res["$schema"] == "smart_ads/mcp_campaign_performance_result/v1"
    assert res["dataset_snapshot_locator"] == world.snap2_loc.to_dict()
    assert res["dataset_snapshot_digest"] == world.snap2.snapshot_digest
    assert len(res["rows"]) == 2
    expected_row_keys = {"fact_key", "value_type", "raw_numeric_value", "unit", "currency", "presence_status", "unknown_reason", "calculation_status"}
    for row in res["rows"]:
        assert set(row.keys()) == expected_row_keys
        assert row["fact_key"]["resource_ref"] == _CAMP_A
    out_of_scope_resp = _call_wire(
        handler,
        method,
        {
            "tenant_ref": "tenant:ibvi",
            "binding_ref": "binding:meta-primary",
            "resource_scope_ref": "scope:campaigns-active",
            "date_range": {"start_date": "2026-11-10", "end_date": "2026-11-10"},
            "resource_refs": [_CAMP_OUT],
        },
        req_id="oos-1",
    )
    assert out_of_scope_resp == {"jsonrpc": "2.0", "id": "oos-1", "error": {"code": -32603, "message": "Internal error"}}


def test_campaign_performance_rejects_uncovered_or_conflicting_inventories(world: McpHandlerWorld) -> None:
    scope_key = ("tenant:ibvi", "binding:meta-primary", "scope:campaigns-active")
    _, partial_inv_loc = _put_signed_obj(
        world.store,
        ExpectedResourceInventory(
            "inventory:conflict-001", world.reg_loc, world.reg_loc.content_digest, "tenant:ibvi",
            "binding:meta-primary", "account:ibvi-01", "scope:campaigns-active",
            DateRange("2026-11-10", "2026-11-10", True),
            (ExpectedResourceKey("binding:meta-primary", "account:ibvi-01", _CAMP_A, "campaign", "2026-11-10"),),
        ),
        world.key_reg_loc,
    )
    conflict_handler = VerifiedStoreMcpReadHandler(
        world.build_index(scope_inventory_locators={scope_key: (world.eval_inv_loc, partial_inv_loc)})
    )
    method = "smart_ads.queries.get_campaign_performance_v1"
    conflict_resp = _call_wire(
        conflict_handler,
        method,
        {"tenant_ref": "tenant:ibvi", "binding_ref": "binding:meta-primary", "resource_scope_ref": "scope:campaigns-active", "date_range": {"start_date": "2026-11-10", "end_date": "2026-11-10"}},
        req_id="conf-1",
    )
    assert conflict_resp["error"] == {"code": -32603, "message": "Internal error"}
    uncovered_resp = _call_wire(
        VerifiedStoreMcpReadHandler(world.build_index()),
        method,
        {"tenant_ref": "tenant:ibvi", "binding_ref": "binding:meta-primary", "resource_scope_ref": "scope:campaigns-active", "date_range": {"start_date": "2026-10-01", "end_date": "2026-10-31"}},
        req_id="uncov-1",
    )
    assert uncovered_resp["error"] == {"code": -32603, "message": "Internal error"}


def test_intelligence_findings_zero_findings_and_filtered_projection(world: McpHandlerWorld) -> None:
    handler = world.default_handler
    method = "smart_ads.queries.get_intelligence_findings_v1"
    scope = {"tenant_ref": "tenant:ibvi", "binding_ref": "binding:meta-primary", "resource_scope_ref": "scope:campaigns-active"}
    zero_resp = _call_wire(handler, method, {**scope, "dataset_snapshot_locator": world.snap1_loc.to_dict()}, req_id="f-zero")["result"]
    assert zero_resp["$schema"] == "smart_ads/mcp_intelligence_findings_result/v1"
    assert zero_resp["findings"] == [] and zero_resp["mutation_recommendations_blocked"] is False
    assert zero_resp["derived_certification_status"] == "VERIFIED"

    all_s2 = _call_wire(handler, method, {**scope, "dataset_snapshot_locator": world.snap2_loc.to_dict()}, req_id="f-all")["result"]
    assert len(all_s2["findings"]) == 2 and all_s2["mutation_recommendations_blocked"] is True
    assert {f["finding_type"] for f in all_s2["findings"]} == {"restatement", "waste"}
    for f_dict in all_s2["findings"]:
        assert set(f_dict.keys()) == {"finding_key", "finding_type", "finding_status", "mutation_recommendation_blocked", "finding_digest"}

    waste_only = _call_wire(handler, method, {**scope, "dataset_snapshot_locator": world.snap2_loc.to_dict(), "finding_types": ["waste"]}, req_id="f-waste")["result"]
    assert len(waste_only["findings"]) == 1 and waste_only["findings"][0]["finding_type"] == "waste"
    assert waste_only["mutation_recommendations_blocked"] is True


def test_recurrent_summary_daily_weekly_and_missing_entry_rejection(world: McpHandlerWorld) -> None:
    handler = world.default_handler
    method = "smart_ads.reports.generate_recurrent_summary_v1"
    scope = {"tenant_ref": "tenant:ibvi", "binding_ref": "binding:meta-primary", "resource_scope_ref": "scope:campaigns-active"}
    daily = _call_wire(
        handler, method,
        {**scope, "dataset_snapshot_locator": world.snap2_loc.to_dict(), "cadence": "daily", "period_start_date": "2026-11-10", "period_end_date": "2026-11-10"},
        req_id="sum-d",
    )["result"]
    assert daily["$schema"] == "smart_ads/mcp_recurrent_summary_result/v1"
    assert daily["report_result"] == world.rep2.canonical_report_result.to_dict()

    weekly = _call_wire(
        handler, method,
        {**scope, "dataset_snapshot_locator": world.snap2_loc.to_dict(), "cadence": "weekly", "period_start_date": "2026-11-04", "period_end_date": "2026-11-10"},
        req_id="sum-w",
    )["result"]
    assert weekly["cadence"] == "weekly" and weekly["report_result"] == world.rep2.canonical_report_result.to_dict()

    missing = _call_wire(
        handler, method,
        {**scope, "dataset_snapshot_locator": world.snap1_loc.to_dict(), "cadence": "daily", "period_start_date": "2026-11-10", "period_end_date": "2026-11-10"},
        req_id="sum-miss",
    )
    assert missing == {"jsonrpc": "2.0", "id": "sum-miss", "error": {"code": -32603, "message": "Internal error"}}

