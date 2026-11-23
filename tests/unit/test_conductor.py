"""Unit tests for `src/smart_ads/application/conductor.py` (`conduct_offline_run`)."""
from __future__ import annotations

import ast
import base64
from collections.abc import Callable, Mapping, Sequence
from dataclasses import replace
import hashlib
import hmac
from pathlib import Path
from typing import Any

import pytest

from smart_ads.adapters.storage import InMemoryCellObjectStore, StdlibParquetLandingCodec
from smart_ads.analytics import FINDING_DETECTED, FINDING_INCONCLUSIVE, METRIC_WINDOW_COLUMNS, AnalyticalCertificationRecord, AnalysisEvidence, AnalysisExecution, AnalysisPolicy, AnalysisReplayInputBundle, AnalysisResult, AnalysisResultSchema, AttestedCertificationInput, CanonicalResultEntry, CanonicalResultSet, CertificationInput, DerivedCertificationStatus, DuckDbBinaryObjectLocator, DuckDbExtensionBinaryLocator, DuckDbExtensionSpec, DuckDbQueryDefinition, DuckDbSessionSetting, EvaluationContext, Finding, ResultColumn, ResultProjection, TaggedScalarCell, build_certification_record, evaluate_findings, verify_certification_record
import smart_ads.application as application_pkg
from smart_ads.application import PREDECESSOR_P1_DOMAIN_PREFIXES, ConductorRunInput, ConductorRunOutcome, GlobalDatasetCatalogService, build_sanitized_candidate_fact_set, conduct_offline_run, execute_analysis_replay_bundle, materialize_parquet_generation, publish_dataset_snapshot
import smart_ads.application.conductor as conductor_mod
from smart_ads.contracts import ADR_P1_DOMAIN_PREFIXES, AdmittedCollection, AlgorithmProvenanceIdentity, ArtifactLocator, CanonicalQueryContract, ClosedValidationError, CollectionResult, DateRange, FactKey, GitArtifactProvenance, IbviAdsDelegationContext, NormalizedCollectionFact, OperationalReadEvidence, P1Integrity, PurposePrerequisiteLocators, RetrievalContext, SanitizedCandidateFactSet, canonicalize_jcs, compute_git_blob_oid, compute_normalized_fact_set_digest, jcs_sha256, p1_content_digest, p1_signing_message, project_collection_fact_to_landing_row
from smart_ads.contracts.effects import AuthorizationConsumptionRecord, AuthorizationReceipt, AuthorizationReservationRecord, EffectProof, ExecutionReceipt, ProviderCallTarget
from smart_ads.domain import FORBIDDEN_PIPEBOARD_ARGUMENTS, PINNED_LEGACY_COMMIT, PINNED_LEGACY_REPO, PINNED_PIPEBOARD_D26_SPECS, PIPEBOARD_PHASE1_METRIC_SOURCE_MAPPINGS, ActivePartitionHead, AuthorizedScopeRelation, CatalogCasRequestProjection, CurationExecution, DatasetCatalog, DatasetCatalogCutReceipt, DatasetCatalogGenesisConsumptionRecord, DatasetCatalogGenesisRecord, DatasetSnapshot, DriverCapabilityEntry, ExpectedResourceInventory, ExpectedResourceKey, GenerationManifest, LegacySourcePacket, PinnedGitArtifactMember, PinnedUpstreamReference, PipeboardPhase1Contract, PipeboardTransportLimits, PrivateRegistrySnapshot, RegistryBinding, compute_curation_window
from smart_ads.ports import CellObjectStorePort, OfflineIntelligencePort, P1SignatureVerifierPort
from smart_ads.ports.cell_runtime import ClockAttestation
from tests.contract.test_packaging_boundary import REPO_ROOT, scan_pure_layer_ast_violations
from tests.unit.test_curation_and_catalog import _CAMP_A, _METRICS_3, _clean_transport
from tests.unit.test_duckdb_replay_and_reporting import DeterministicInMemoryDuckDbEngine, _METRIC_ORDER, _METRIC_UKEY

_CAMP_B = "resource:" + ("b" * 51) + "a"
_CAMP_OUT = "resource:" + ("d" * 51) + "a"
_KEY_ID = "key:ed25519:" + ("9" * 64)
_MAC_SECRET = b"smart-ads-task5-conductor-p1-domain-secret"
_DOMAINS: dict[str, str] = {**ADR_P1_DOMAIN_PREFIXES, **PREDECESSOR_P1_DOMAIN_PREFIXES}
_ADR_PIN: dict[str, str] = {
    "repository": "aiconnai/smart-ads",
    "commit_sha": "a3f19ef668748c64c5c679710c231426c5e05f6a",
    "path": "docs/adr/ADR-0001-smart-ads-read-gateway.md",
    "git_blob_oid": "1" * 40,
    "file_content_sha256": "sha256:" + ("2" * 64),
}


def _compute_sig(envelope: Mapping[str, Any], domain_prefix: str) -> str:
    msg = p1_signing_message(envelope, domain_prefix)
    mac32 = hmac.new(_MAC_SECRET, msg, hashlib.sha256).digest()
    return base64.b64encode(mac32 + mac32).decode("ascii")


class ConductorDomainP1Verifier(P1SignatureVerifierPort):
    """Domain-separated Ed25519-profile test verifier over `_DOMAINS`."""

    def __init__(self) -> None:
        self.verified_schemas: list[str] = []

    def verify_p1_envelope_signature(
        self, *, envelope: Mapping[str, Any], domain_prefix: str, store: CellObjectStorePort
    ) -> None:
        schema_id = envelope.get("$schema")
        if type(schema_id) is not str or _DOMAINS.get(schema_id) != domain_prefix:
            raise ClosedValidationError("verifier: schema_id / domain_prefix mismatch")
        integ = P1Integrity.from_dict(envelope.get("integrity"), require_signed=True)
        key_reg = store.get_json_artifact(integ.key_registry_snapshot_locator)
        if integ.key_id not in key_reg.get("keys", ()):
            raise ClosedValidationError("verifier: unauthorized key_id")
        if integ.content_digest != p1_content_digest(envelope):
            raise ClosedValidationError("verifier: content_digest mismatch")
        if integ.signature_base64 != _compute_sig(envelope, domain_prefix):
            raise ClosedValidationError("verifier: cryptographic signature mismatch")
        self.verified_schemas.append(schema_id)


class ReadOnlyGuardStore(CellObjectStorePort):
    """Wraps a `CellObjectStorePort`, rejects writes, and optionally hides objects."""

    def __init__(self, inner: CellObjectStorePort, *, hidden_refs: frozenset[str] = frozenset()) -> None:
        self._inner = inner
        self._hidden = hidden_refs

    def put_bytes(self, raw: bytes) -> str:
        raise ClosedValidationError("conductor must never invoke put_bytes")

    def get_bytes(self, object_ref: str, *, expected_size_bytes: int | None = None) -> bytes:
        if object_ref in self._hidden:
            raise ClosedValidationError(f"object hidden: {object_ref}")
        return self._inner.get_bytes(object_ref, expected_size_bytes=expected_size_bytes)

    def has_object(self, object_ref: str) -> bool:
        return False if object_ref in self._hidden else self._inner.has_object(object_ref)

    def put_json_artifact(self, schema_id: str, payload: Mapping[str, Any]) -> ArtifactLocator:
        raise ClosedValidationError("conductor must never invoke put_json_artifact")

    def get_json_artifact(self, locator: ArtifactLocator) -> dict[str, Any]:
        if locator.object_ref in self._hidden:
            raise ClosedValidationError(f"artifact hidden: {locator.object_ref}")
        return self._inner.get_json_artifact(locator)


def _sign_dict(raw_no_int: Mapping[str, Any], key_reg_loc: ArtifactLocator) -> dict[str, Any]:
    schema_id = str(raw_no_int["$schema"])
    unsigned = P1Integrity(key_id=_KEY_ID, key_registry_snapshot_locator=key_reg_loc)
    pre = {**raw_no_int, "integrity": unsigned.to_dict()}
    sig = _compute_sig(pre, _DOMAINS[schema_id])
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
    store: InMemoryCellObjectStore, key_reg_loc: ArtifactLocator, path: str, raw: bytes
) -> tuple[GitArtifactProvenance, ArtifactLocator]:
    prov = GitArtifactProvenance(
        "aiconnai/smart-ads", "a" * 40, path, compute_git_blob_oid(raw),
        "sha256:" + hashlib.sha256(raw).hexdigest(), "2026-11-10T00:00:00Z",
    )
    return _put_signed_obj(store, prov, key_reg_loc)


def _put_effect_chain(
    store: InMemoryCellObjectStore, run_loc: ArtifactLocator, key_reg_loc: ArtifactLocator,
    *, action: str, slot: str, subject_kind: str, result_schema: str, tag: str,
) -> ArtifactLocator:
    res_loc = store.put_json_artifact(result_schema, {"$schema": result_schema, "migration_run_context_locator": run_loc.to_dict(), "tag": tag})
    subj = {"subject_kind": subject_kind, "migration_run_context_locator": run_loc.to_dict(), "tag": tag}
    nonce = f"nonce-pre-{tag}"
    _, a_loc = _put_signed_env(store, AuthorizationReceipt.SCHEMA, {"authorization_id": f"auth:{tag}", "migration_run_context_locator": run_loc.to_dict(), "action": action, "dag_slot": slot, "subject": subj, "parameters_digest": "sha256:" + ("1" * 64), "predecessor_locators": [], "approving_principal_ref": "principal:ops-01", "issued_at_utc": "2026-11-10T00:00:00Z", "valid_until_utc": "2026-11-12T00:00:00Z", "single_use_nonce": nonce}, key_reg_loc)
    _, r_loc = _put_signed_env(store, AuthorizationReservationRecord.SCHEMA, {"reservation_id": f"resv:{tag}", "migration_run_context_locator": run_loc.to_dict(), "authorization_locator": a_loc.to_dict(), "authorization_receipt_digest": a_loc.content_digest, "single_use_nonce": nonce, "action": action, "dag_slot": slot, "subject": subj, "reservation_status": "consumed", "in_doubt_reason": None, "reserved_at_utc": "2026-11-10T00:01:00Z"}, key_reg_loc)
    _, e_loc = _put_signed_env(store, ExecutionReceipt.SCHEMA, {"execution_id": f"exec:{tag}", "migration_run_context_locator": run_loc.to_dict(), "authorization_locator": a_loc.to_dict(), "reservation_locator": r_loc.to_dict(), "single_use_nonce": nonce, "action": action, "dag_slot": slot, "subject": subj, "execution_status": "succeeded", "action_result_locator": res_loc.to_dict(), "executed_at_utc": "2026-11-10T00:02:00Z"}, key_reg_loc)
    _, c_loc = _put_signed_env(store, AuthorizationConsumptionRecord.SCHEMA, {"consumption_id": f"cons:{tag}", "migration_run_context_locator": run_loc.to_dict(), "authorization_locator": a_loc.to_dict(), "authorization_receipt_digest": a_loc.content_digest, "reservation_locator": r_loc.to_dict(), "execution_locator": e_loc.to_dict(), "single_use_nonce": nonce, "action": action, "dag_slot": slot, "consumption_status": "consumed", "consumed_at_utc": "2026-11-10T00:02:00Z"}, key_reg_loc)
    _, p_loc = _put_signed_env(store, EffectProof.SCHEMA, {"effect_proof_id": f"proof:{tag}", "migration_run_context_locator": run_loc.to_dict(), "action": action, "dag_slot": slot, "authorization_locator": a_loc.to_dict(), "reservation_locator": r_loc.to_dict(), "execution_locator": e_loc.to_dict(), "consumption_locator": c_loc.to_dict(), "action_result_locator": res_loc.to_dict(), "verified_at_utc": "2026-11-10T00:03:00Z"}, key_reg_loc)
    return p_loc


def _make_campaign_facts(metric_date: str, *, clicks_a: str, clicks_b: str = "25") -> tuple[NormalizedCollectionFact, ...]:
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


def _metrics_projection_rows(rows: tuple[Any, ...], _q: DuckDbQueryDefinition) -> tuple[tuple[TaggedScalarCell, ...], ...]:
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


def _scalar_row_count(rows: tuple[Any, ...], _q: DuckDbQueryDefinition) -> tuple[tuple[TaggedScalarCell, ...], ...]:
    return ((TaggedScalarCell("int64", str(len(rows))),),)


class PolicyRuleOfflineIntelligence:
    """First `OfflineIntelligencePort` implementation delegating to pure `evaluate_findings`."""

    def __init__(self, identity: AlgorithmProvenanceIdentity, *, reverse_output: bool = False) -> None:
        self._identity = identity
        self._reverse = reverse_output

    @property
    def algorithm_identity(self) -> AlgorithmProvenanceIdentity:
        return self._identity

    def evaluate_offline(
        self, *, context: EvaluationContext, evidence: Sequence[AnalysisEvidence]
    ) -> tuple[Finding, ...]:
        found = evaluate_findings(context, evidence[0])
        return tuple(reversed(found)) if self._reverse else found


class ConservativeAuditOfflineIntelligence:
    """Second distinct `OfflineIntelligencePort` emitting inconclusive audit findings."""

    def __init__(self, identity: AlgorithmProvenanceIdentity) -> None:
        self._identity = identity

    @property
    def algorithm_identity(self) -> AlgorithmProvenanceIdentity:
        return self._identity

    def evaluate_offline(
        self, *, context: EvaluationContext, evidence: Sequence[AnalysisEvidence]
    ) -> tuple[Finding, ...]:
        primary = evidence[0]
        entry = primary.execution.canonical_result_set.entry(context.metrics_result_key)
        pol = context.policy
        f_key_a = "finding:" + jcs_sha256({"alg": self._identity.algorithm_id, "camp": _CAMP_A, "pol": pol.policy_id})
        f_key_b = "finding:" + jcs_sha256({"alg": self._identity.algorithm_id, "camp": _CAMP_B, "pol": pol.policy_id})
        f_b = Finding(primary.execution.locator(), entry.result_locator, entry.result_key, f_key_b, "restatement", FINDING_INCONCLUSIVE, True, (entry.result_locator,), primary.bundle_analysis_policy_locator)
        f_a = Finding(primary.execution.locator(), entry.result_locator, entry.result_key, f_key_a, "waste", FINDING_INCONCLUSIVE, True, (entry.result_locator,), primary.bundle_analysis_policy_locator)
        return (f_b, f_a)


class CustomCallbackIntelligence:
    """Test `OfflineIntelligencePort` returning caller-specified raw output."""

    def __init__(
        self, identity: AlgorithmProvenanceIdentity, fn: Callable[[EvaluationContext, Sequence[AnalysisEvidence]], Any]
    ) -> None:
        self._identity = identity
        self._fn = fn

    @property
    def algorithm_identity(self) -> AlgorithmProvenanceIdentity:
        return self._identity

    def evaluate_offline(self, *, context: EvaluationContext, evidence: Sequence[AnalysisEvidence]) -> Any:
        return self._fn(context, evidence)


class ConductorTestWorld:
    """Hermetic signed world for `conduct_offline_run` unit and negative tests."""

    def __init__(self) -> None:
        self.store, self.codec = InMemoryCellObjectStore(), StdlibParquetLandingCodec()
        self.verifier = ConductorDomainP1Verifier()
        self.cell_ref = "cell:ibvi-primary"
        self.key_reg_loc = self.store.put_json_artifact("smart_ads/key_authorization_registry/v1", {"$schema": "smart_ads/key_authorization_registry/v1", "keys": [_KEY_ID]})
        self.run_ctx, self.run_loc = self._put_run_context("run:conductor-001")
        self._init_registry_and_prereqs()
        self._init_algorithms()
        self._init_snapshots()
        self._init_analytics()

    def _put_run_context(self, run_id: str, *, tenant_ref: str = "tenant:ibvi") -> tuple[dict[str, Any], ArtifactLocator]:
        gate2_loc = ArtifactLocator.from_digest("smart_ads/gate2_approval_receipt/v1", "sha256:" + ("4" * 64))
        body = {
            "gate2_receipt_locator": gate2_loc.to_dict(),
            "approved_adr_git_identity": dict(_ADR_PIN),
            "legacy_source_identity": {"repository": PINNED_LEGACY_REPO, "commit_sha": PINNED_LEGACY_COMMIT},
            "tenant_ref": tenant_ref, "cell_ref": self.cell_ref, "run_id": run_id,
            "created_at_utc": "2026-11-10T00:00:00Z",
        }
        return _put_signed_env(self.store, "smart_ads/migration_run_context/v1", body, self.key_reg_loc)

    def _init_registry_and_prereqs(self) -> None:
        d26 = []
        for role, path, blob_oid, file_sha in PINNED_PIPEBOARD_D26_SPECS:
            _, m_loc = _put_signed_obj(self.store, GitArtifactProvenance(PINNED_LEGACY_REPO, PINNED_LEGACY_COMMIT, path, blob_oid, file_sha, "2026-11-10T00:00:00Z"), self.key_reg_loc)
            d26.append(PinnedGitArtifactMember(role, PINNED_LEGACY_REPO, PINNED_LEGACY_COMMIT, path, blob_oid, file_sha, m_loc))
        raw_drv = PipeboardPhase1Contract("driver-contract:pipeboard-phase1-v1", "pipeboard_hosted", LegacySourcePacket(PINNED_LEGACY_REPO, PINNED_LEGACY_COMMIT, tuple(d26)), PinnedUpstreamReference(), PipeboardTransportLimits(forbidden_arguments=FORBIDDEN_PIPEBOARD_ARGUMENTS), dict(PIPEBOARD_PHASE1_METRIC_SOURCE_MAPPINGS))
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
        _, del_loc = _put_signed_obj(self.store, IbviAdsDelegationContext("/ibvi-ads", "conductor:hermes", "front:pinna", "profile:pinna-ops", "tenant:ibvi", "binding:meta-primary", "scope:campaigns-active", "smart_ads.queries.get_campaign_performance_v1", "sha256:" + ("8" * 64), "2026-11-11T02:55:00Z", "2026-11-11T04:00:00Z", "nonce-cond-001"), self.key_reg_loc)
        wi_pf = _put_effect_chain(self.store, self.run_loc, self.key_reg_loc, action="workload_identity_provision", slot="workload_identity_effect_proof", subject_kind="workload_identity_target", result_schema="smart_ads/workload_identity_execution_result/v1", tag="wi")
        dp_pf = _put_effect_chain(self.store, self.run_loc, self.key_reg_loc, action="deployment_config_apply", slot="deployment_config_effect_proof", subject_kind="deployment_target", result_schema="smart_ads/deployment_config_execution_result/v1", tag="dp")
        self.prereqs = PurposePrerequisiteLocators(purpose="operational_read", legacy_step2_evidence_locator=p_locs["step2"], live_read_activation_receipt_locator=p_locs["act"], live_certification_head_locator=p_locs["head"], live_certification_transition_locator=p_locs["trans"], live_certification_certificate_locator=p_locs["cert"], gate3_operational_renewal_locator=p_locs["gate3"], workload_identity_effect_proof_locator=wi_pf, deployment_effect_proof_locator=dp_pf, delegation_context_locator=del_loc)

    def _init_algorithms(self) -> None:
        sp, sp_loc = _put_git_prov(self.store, self.key_reg_loc, "src/smart_ads/application/curation_pipeline.py", b"# sanitize")
        cp, cp_loc = _put_git_prov(self.store, self.key_reg_loc, "src/smart_ads/domain/curation.py", b"# curate")
        ip1, ip1_loc = _put_git_prov(self.store, self.key_reg_loc, "src/smart_ads/analytics/intelligence.py", b"# intel-v1")
        ip2, ip2_loc = _put_git_prov(self.store, self.key_reg_loc, "src/smart_ads/analytics/intelligence_alt.py", b"# intel-v2")
        _, self.tmpl_loc = _put_git_prov(self.store, self.key_reg_loc, "src/smart_ads/analytics/template.json", b'{"v":1}')
        self.san_alg = AlgorithmProvenanceIdentity("algorithm:sanitize-v1", "1.0.0", sp_loc, sp.repository, sp.commit_sha, sp.path, sp.git_blob_oid, sp.file_content_sha256, "cpython-3.12", SanitizedCandidateFactSet.SCHEMA)
        self.cur_alg = AlgorithmProvenanceIdentity("algorithm:curate-v1", "1.0.0", cp_loc, cp.repository, cp.commit_sha, cp.path, cp.git_blob_oid, cp.file_content_sha256, "cpython-3.12", CurationExecution.SCHEMA)
        self.intel_alg_1 = AlgorithmProvenanceIdentity("algorithm:policy-intel-v1", "1.0.0", ip1_loc, ip1.repository, ip1.commit_sha, ip1.path, ip1.git_blob_oid, ip1.file_content_sha256, "cpython-3.12", Finding.SCHEMA)
        self.intel_alg_2 = AlgorithmProvenanceIdentity("algorithm:conservative-intel-v2", "2.0.0", ip2_loc, ip2.repository, ip2.commit_sha, ip2.path, ip2.git_blob_oid, ip2.file_content_sha256, "cpython-3.12", Finding.SCHEMA)
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
        facts = _make_campaign_facts(metric_date, clicks_a=clicks_a)
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
    ) -> tuple[GenerationManifest, ArtifactLocator]:
        raw_cs = build_sanitized_candidate_fact_set(migration_run_context_locator=self.run_loc, sanitization_algorithm_identity=self.san_alg, store=self.store, evidence_locators=(ev_loc,), require_signed_inputs=True)
        _, cs_loc = _put_signed_obj(self.store, raw_cs, self.key_reg_loc)
        win = compute_curation_window(date_str, "America/Sao_Paulo", "2026a", 1)
        raw_cur = CurationExecution(self.run_loc, f"cur:{tag}", mode, date_str, "America/Sao_Paulo", "2026a", 1, win, cs_loc, self.cur_alg, self.genesis_loc if mode == "genesis" else None, base_cat_loc, snap_loc, cut_loc, hist_locs, "2026-11-11T03:05:00Z")  # type: ignore[arg-type]
        _, cur_loc = _put_signed_obj(self.store, raw_cur, self.key_reg_loc)
        raw_gm, _ = materialize_parquet_generation(generation_id=f"gen:{tag}", created_at_utc="2026-11-11T03:06:00Z", registry_snapshot_locator=self.reg_loc, curation_locator=cur_loc, store=self.store, parquet_codec=self.codec, parent_generation_manifest_locator=parent_loc)
        return _put_signed_obj(self.store, raw_gm, self.key_reg_loc)

    def _commit_cut(
        self, svc: GlobalDatasetCatalogService, *, idx: int, op: str, seq: int, gm: GenerationManifest,
        gm_loc: ArtifactLocator, genesis_loc: ArtifactLocator | None = None,
    ) -> tuple[DatasetSnapshot, ArtifactLocator, ArtifactLocator]:
        old_loc, old_cat = svc.current_head()
        new_head = ActivePartitionHead(gm.partition_key, seq, gm_loc)
        heads = tuple(sorted((*(h for h in old_cat.partition_heads if h.partition_key != gm.partition_key), new_head), key=lambda h: h.partition_key.encode("utf-8")))
        ts = f"2026-11-11T03:0{5 + idx}:00Z"
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
        gm_oct, gm_oct_loc = self._materialize_gen("oct", "genesis", "2026-10-31", ev_oct, self.epoch0_loc, None, None, (), None)
        _, snap0_loc, cut1_loc = self._commit_cut(svc, idx=1, op="add_partition", seq=1, gm=gm_oct, gm_loc=gm_oct_loc, genesis_loc=self.genesis_loc)
        ev_n1 = self._store_op_read("2026-11-10", "nov1", clicks_a="999", collected_at="2026-11-11T03:02:00.000000Z")
        gm_n1, gm_n1_loc = self._materialize_gen("nov1", "incremental", "2026-11-10", ev_n1, svc.current_head()[0], snap0_loc, cut1_loc, (), None)
        self.snap1, self.snap1_loc, cut2_loc = self._commit_cut(svc, idx=2, op="add_partition", seq=1, gm=gm_n1, gm_loc=gm_n1_loc)
        ev_n2 = self._store_op_read("2026-11-10", "nov2", clicks_a="0", collected_at="2026-11-11T03:04:00.000000Z")
        gm_n2, gm_n2_loc = self._materialize_gen("nov2", "incremental", "2026-11-10", ev_n2, svc.current_head()[0], self.snap1_loc, cut2_loc, (gm_n1_loc,), gm_n1_loc)
        self.snap2, self.snap2_loc, cut3_loc = self._commit_cut(svc, idx=3, op="replace_partition", seq=2, gm=gm_n2, gm_loc=gm_n2_loc)
        ev_dec = self._store_op_read("2026-12-01", "dec1", clicks_a="5", collected_at="2026-12-02T03:02:00.000000Z")
        gm_dec, gm_dec_loc = self._materialize_gen("dec1", "incremental", "2026-12-01", ev_dec, svc.current_head()[0], self.snap2_loc, cut3_loc, (), None)
        self.snap3, self.snap3_loc, _ = self._commit_cut(svc, idx=4, op="add_partition", seq=1, gm=gm_dec, gm_loc=gm_dec_loc)

    def _build_signed_execution(
        self, tag: str, snap_loc: ArtifactLocator, queries: tuple[DuckDbQueryDefinition, ...]
    ) -> tuple[AnalysisReplayInputBundle, ArtifactLocator, AnalysisExecution, ArtifactLocator, tuple[AnalysisResult, ...]]:
        exts = (DuckDbExtensionSpec("parquet", "1.5.5", "explicit_local_binary", DuckDbExtensionBinaryLocator.for_binary_bytes(self.ext_bytes)),)
        raw_b = AnalysisReplayInputBundle(f"bundle:{tag}", self.run_loc, snap_loc, "1.5.5", DuckDbBinaryObjectLocator.for_binary_bytes(self.duck_bytes), exts, (DuckDbSessionSetting("threads", TaggedScalarCell("int64", "1")),), (), queries, self.policy_loc, (self.tmpl_loc,))
        bundle, b_loc = _put_signed_obj(self.store, raw_b, self.key_reg_loc)
        eng = DeterministicInMemoryDuckDbEngine({"result:metrics": _metrics_projection_rows, "result:row_count": _scalar_row_count})
        _, _, u_pairs = execute_analysis_replay_bundle(bundle_locator=b_loc, store=self.store, parquet_codec=self.codec, duckdb_engine=eng, require_signed_inputs=True)
        signed_res = {r.result_key: _put_signed_obj(self.store, r, self.key_reg_loc)[0] for r, _ in u_pairs}
        entries = tuple(CanonicalResultEntry.from_result(signed_res[k]) for k in sorted(signed_res, key=lambda s: s.encode("utf-8")))
        s_exec_pre, _ = _put_signed_obj(self.store, AnalysisExecution(b_loc, CanonicalResultSet.build(b_loc, entries)), self.key_reg_loc)
        r_ints = {k: v.integrity for k, v in signed_res.items()}
        exec_obj, exec_loc, _ = execute_analysis_replay_bundle(bundle_locator=b_loc, store=self.store, parquet_codec=self.codec, duckdb_engine=eng, result_integrities=r_ints, execution_integrity=s_exec_pre.integrity, require_signed_inputs=True)  # type: ignore[arg-type]
        return bundle, b_loc, exec_obj, exec_loc, tuple(signed_res[k] for k in sorted(signed_res, key=lambda s: s.encode("utf-8")))

    def _init_analytics(self) -> None:
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
        m_cols = tuple(ResultColumn(n, t, nl) for n, t, nl in METRIC_WINDOW_COLUMNS)
        self.metrics_schema, self.metrics_schema_loc = _put_signed_obj(self.store, AnalysisResultSchema("relation", m_cols, _METRIC_UKEY), self.key_reg_loc)
        s_cols = (ResultColumn("row_count", "int64", False),)
        self.scalar_schema, self.scalar_schema_loc = _put_signed_obj(self.store, AnalysisResultSchema("scalar", s_cols, None), self.key_reg_loc)
        inv_keys = tuple(
            ExpectedResourceKey("binding:meta-primary", "account:ibvi-01", c, "campaign", d)
            for d in ("2026-10-31", "2026-11-10") for c in (_CAMP_A, _CAMP_B)
        )
        self.inventory, self.inv_loc = _put_signed_obj(self.store, ExpectedResourceInventory("inventory:eval-001", self.reg_loc, self.reg_loc.content_digest, "tenant:ibvi", "binding:meta-primary", "account:ibvi-01", "scope:campaigns-active", DateRange("2026-10-31", "2026-11-10", True), inv_keys), self.key_reg_loc)
        q_m = DuckDbQueryDefinition("result:metrics", "query:metrics", "SELECT 1", self.metrics_schema_loc, "relation", m_cols, _METRIC_UKEY, _METRIC_ORDER)
        q_s = DuckDbQueryDefinition("result:row_count", "query:row_count", "SELECT 1", self.scalar_schema_loc, "scalar", s_cols, None, ())
        self.bundle, self.bundle_loc, self.exec_obj, self.exec_loc, self.results = self._build_signed_execution("main", self.snap3_loc, (q_m, q_s))
        _, _, self.aux_exec, self.aux_exec_loc, self.aux_results = self._build_signed_execution("aux", self.snap3_loc, (q_s,))
        self.attested = (AttestedCertificationInput(CertificationInput(DerivedCertificationStatus.VERIFIED, "phase1_7b_base"), True),)

    def make_run_input(self, **overrides: Any) -> ConductorRunInput:
        base: dict[str, Any] = {
            "migration_run_context_locator": self.run_loc,
            "dataset_snapshot_locator": self.snap3_loc,
            "expected_resource_inventory_locator": self.inv_loc,
            "analysis_policy_locator": self.policy_loc,
            "analysis_execution_locator": self.exec_loc,
            "evaluation_instant_utc": "2026-11-11T03:15:00.000000Z",
            "window_end_date": "2026-11-10",
            "attested_certification_inputs": self.attested,
            "resolved_analysis_results": self.results,
            "analysis_evidence": (),
            "certification_integrity": None,
            "store": ReadOnlyGuardStore(self.store),
            "parquet_codec": self.codec,
            "signature_verifier": self.verifier,
            "require_signed": True,
        }
        base.update(overrides)
        return ConductorRunInput(**base)


@pytest.fixture(scope="module")
def world() -> ConductorTestWorld:
    return ConductorTestWorld()


def test_conductor_ast_zero_collection_admission_provider_and_pipeboard_coupling() -> None:
    path: Path = REPO_ROOT / "src" / "smart_ads" / "application" / "conductor.py"
    source = path.read_text(encoding="utf-8")
    assert scan_pure_layer_ast_violations(source, filename=str(path)) == []
    tree = ast.parse(source, filename=str(path))
    forbidden_prefixes = (
        "smart_ads.ports.provider",
        "smart_ads.ports.cell_runtime",
        "smart_ads.application.collection",
        "smart_ads.application.admission",
        "smart_ads.adapters",
    )
    forbidden_names = {
        "collect", "admit_collection", "execute_admitted_call",
        "evaluate_fixture_collection", "ProviderReadPort", "PipeboardFixtureAdapter",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert not alias.name.startswith(forbidden_prefixes)
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            assert not mod.startswith(forbidden_prefixes)
            if node.level > 0:
                assert mod not in {"collection", "admission"}
            for alias in node.names:
                assert alias.name not in forbidden_names
        elif isinstance(node, ast.Name):
            assert node.id not in forbidden_names
        elif isinstance(node, ast.Attribute):
            assert node.attr not in forbidden_names


def test_application_package_exports_conductor_public_api() -> None:
    assert application_pkg.ConductorRunInput is conductor_mod.ConductorRunInput
    assert application_pkg.ConductorRunOutcome is conductor_mod.ConductorRunOutcome
    assert application_pkg.conduct_offline_run is conductor_mod.conduct_offline_run
    for symbol in ("ConductorRunInput", "ConductorRunOutcome", "conduct_offline_run"):
        assert symbol in application_pkg.__all__


def test_provider_agnostic_injected_intelligence_two_implementations(world: ConductorTestWorld) -> None:
    run_input = world.make_run_input()
    intel_1 = PolicyRuleOfflineIntelligence(world.intel_alg_1)
    intel_2 = ConservativeAuditOfflineIntelligence(world.intel_alg_2)
    assert isinstance(intel_1, OfflineIntelligencePort)
    assert isinstance(intel_2, OfflineIntelligencePort)

    out_1 = conduct_offline_run(run_input=run_input, intelligence=intel_1)
    out_2 = conduct_offline_run(run_input=run_input, intelligence=intel_2)

    assert out_1.intelligence_algorithm_identity == world.intel_alg_1
    assert out_2.intelligence_algorithm_identity == world.intel_alg_2
    assert out_1.dataset_snapshot_digest == world.snap3.snapshot_digest
    assert out_1.reduced_row_count == 12
    assert out_2.reduced_row_count == 12
    assert out_1.reduced_evidence_digest == out_2.reduced_evidence_digest
    assert {f.finding_type for f in out_1.findings} == {"restatement", "waste"}
    assert all(f.finding_status == FINDING_DETECTED for f in out_1.findings)
    assert out_1.certification_record.derived_certification_status is DerivedCertificationStatus.VERIFIED
    assert out_1.certification_record.mutation_recommendations_blocked is True
    assert all(f.finding_status == FINDING_INCONCLUSIVE for f in out_2.findings)
    assert out_2.certification_record.derived_certification_status is DerivedCertificationStatus.UNAVAILABLE
    assert out_1.findings != out_2.findings
    assert out_1.outcome_digest != out_2.outcome_digest


def test_canonical_outcome_order_independence_and_jcs_determinism(world: ConductorTestWorld) -> None:
    schemas = (world.metrics_schema, world.scalar_schema)
    ev_main = AnalysisEvidence(world.exec_obj, world.results, schemas, world.snap3_loc, world.policy_loc, True, world.run_loc)
    ev_main_rev = AnalysisEvidence(world.exec_obj, tuple(reversed(world.results)), tuple(reversed(schemas)), world.snap3_loc, world.policy_loc, True, None)
    ev_aux = AnalysisEvidence(world.aux_exec, world.aux_results, (world.scalar_schema,), world.snap3_loc, world.policy_loc, True, world.run_loc)

    in_forward = world.make_run_input(resolved_analysis_results=world.results, analysis_evidence=(ev_main, ev_aux))
    in_reverse = world.make_run_input(resolved_analysis_results=tuple(reversed(world.results)), analysis_evidence=(ev_aux, ev_main_rev))

    out_fwd = conduct_offline_run(run_input=in_forward, intelligence=PolicyRuleOfflineIntelligence(world.intel_alg_1, reverse_output=False))
    out_rev = conduct_offline_run(run_input=in_reverse, intelligence=PolicyRuleOfflineIntelligence(world.intel_alg_1, reverse_output=True))

    assert out_fwd == out_rev
    assert out_fwd.outcome_digest == out_rev.outcome_digest
    assert canonicalize_jcs(out_fwd.to_dict()) == canonicalize_jcs(out_rev.to_dict())
    assert [f.finding_key for f in out_fwd.findings] == sorted((f.finding_key for f in out_fwd.findings), key=lambda s: s.encode("utf-8"))
    assert list(out_fwd.finding_digests) == sorted(out_fwd.finding_digests, key=lambda s: s.encode("utf-8"))
    assert ConductorRunOutcome.from_dict(out_fwd.to_dict()) == out_fwd


def test_certification_record_matches_analytics_certification_verifier(world: ConductorTestWorld) -> None:
    signed_findings_intel = CustomCallbackIntelligence(
        world.intel_alg_1,
        lambda ctx, ev: tuple(Finding.from_dict(_sign_dict(f.to_dict(), world.key_reg_loc), require_signed=True) for f in evaluate_findings(ctx, ev[0])),
    )
    out_pre = conduct_offline_run(run_input=world.make_run_input(), intelligence=signed_findings_intel)
    signed_cert_dict = _sign_dict(out_pre.certification_record.to_dict(), world.key_reg_loc)
    cert_int = P1Integrity.from_dict(signed_cert_dict["integrity"], require_signed=True)
    out_s = conduct_offline_run(run_input=world.make_run_input(certification_integrity=cert_int), intelligence=signed_findings_intel)
    assert out_s.certification_record.integrity == cert_int
    captured: list[tuple[EvaluationContext, AnalysisEvidence]] = []
    probe_intel = CustomCallbackIntelligence(world.intel_alg_1, lambda ctx, ev: (captured.append((ctx, ev[0])) or evaluate_findings(ctx, ev[0])))
    conduct_offline_run(run_input=world.make_run_input(), intelligence=probe_intel)
    ctx, ev0 = captured[0]
    expected_cert = build_certification_record(ctx, ev0, list(out_s.findings), list(world.attested), integrity=cert_int)
    assert out_s.certification_record == expected_cert
    assert verify_certification_record(out_s.certification_record, ctx, ev0, list(out_s.findings), list(world.attested)) == out_s.certification_record


def test_unsigned_mode_and_window_end_reduction_filtering(world: ConductorTestWorld) -> None:
    out_nov = conduct_offline_run(
        run_input=world.make_run_input(signature_verifier=None, require_signed=False),
        intelligence=PolicyRuleOfflineIntelligence(world.intel_alg_1),
    )
    assert out_nov.reduced_row_count == 12

    inv_dec_keys = tuple(ExpectedResourceKey("binding:meta-primary", "account:ibvi-01", c, "campaign", d) for c in (_CAMP_A, _CAMP_B) for d in ("2026-10-31", "2026-11-10", "2026-12-01"))
    _, inv_dec_loc = _put_signed_obj(world.store, ExpectedResourceInventory("inventory:dec-001", world.reg_loc, world.reg_loc.content_digest, "tenant:ibvi", "binding:meta-primary", "account:ibvi-01", "scope:campaigns-active", DateRange("2026-10-31", "2026-12-01", True), inv_dec_keys), world.key_reg_loc)
    empty_intel = CustomCallbackIntelligence(world.intel_alg_1, lambda _ctx, _ev: ())
    out_dec = conduct_offline_run(
        run_input=world.make_run_input(
            expected_resource_inventory_locator=inv_dec_loc,
            evaluation_instant_utc="2026-12-02T12:00:00.000000Z",
            window_end_date="2026-12-01",
            store=ReadOnlyGuardStore(world.store),
        ),
        intelligence=empty_intel,
    )
    assert out_dec.reduced_row_count == 18
    assert out_dec.reduced_evidence_digest != out_nov.reduced_evidence_digest
    assert out_dec.findings == ()
    assert out_dec.finding_digests == ()
    assert out_dec.certification_record.mutation_recommendations_blocked is False


def test_rejects_invalid_inputs_ports_and_algorithm_provenance(world: ConductorTestWorld) -> None:
    intel = PolicyRuleOfflineIntelligence(world.intel_alg_1)
    with pytest.raises(ClosedValidationError):
        conduct_offline_run(run_input="not-an-input", intelligence=intel)  # type: ignore[arg-type]
    with pytest.raises(ClosedValidationError):
        conduct_offline_run(run_input=world.make_run_input(), intelligence=object())  # type: ignore[arg-type]
    with pytest.raises(ClosedValidationError, match="signature_verifier"):
        world.make_run_input(signature_verifier=None, require_signed=True)
    with pytest.raises(ClosedValidationError, match="window_after_instant|window_end_date"):
        world.make_run_input(evaluation_instant_utc="2026-11-09T00:00:00.000000Z", window_end_date="2026-11-10")

    bad_schema_alg = replace(world.intel_alg_1, schema_id= SanitizedCandidateFactSet.SCHEMA)
    with pytest.raises(ClosedValidationError, match="schema_id"):
        conduct_offline_run(run_input=world.make_run_input(), intelligence=PolicyRuleOfflineIntelligence(bad_schema_alg))

    bad_blob_alg = replace(world.intel_alg_1, git_blob_oid="f" * 40)
    with pytest.raises(ClosedValidationError, match="mismatch"):
        conduct_offline_run(run_input=world.make_run_input(), intelligence=PolicyRuleOfflineIntelligence(bad_blob_alg))


def test_rejects_cross_snapshot_duplicate_or_unregistered_analysis_results(world: ConductorTestWorld) -> None:
    intel = PolicyRuleOfflineIntelligence(world.intel_alg_1)
    with pytest.raises(ClosedValidationError, match="duplicate"):
        conduct_offline_run(
            run_input=world.make_run_input(resolved_analysis_results=(world.results[0], world.results[0])),
            intelligence=intel,
        )

    raw_cross_snap = {**world.results[0].to_dict(), "dataset_snapshot_locator": world.snap2_loc.to_dict()}
    cross_snap_res = AnalysisResult.from_dict(_sign_dict(raw_cross_snap, world.key_reg_loc), require_signed=True)
    with pytest.raises(ClosedValidationError):
        conduct_offline_run(
            run_input=world.make_run_input(resolved_analysis_results=(cross_snap_res, world.results[1])),
            intelligence=intel,
        )

    other_run_loc = world._put_run_context("run:conductor-other")[1]
    raw_cross_run = {**world.results[0].to_dict(), "migration_run_context_locator": other_run_loc.to_dict()}
    cross_run_res = AnalysisResult.from_dict(_sign_dict(raw_cross_run, world.key_reg_loc), require_signed=True)
    with pytest.raises(ClosedValidationError):
        conduct_offline_run(
            run_input=world.make_run_input(resolved_analysis_results=(cross_run_res, world.results[1])),
            intelligence=intel,
        )

    with pytest.raises(ClosedValidationError):
        conduct_offline_run(
            run_input=world.make_run_input(resolved_analysis_results=(world.aux_results[0], world.results[0])),
            intelligence=intel,
        )


def test_rejects_out_of_inventory_resource_and_mismatched_evidence(world: ConductorTestWorld) -> None:
    intel = PolicyRuleOfflineIntelligence(world.intel_alg_1)
    narrow_inv, narrow_inv_loc = _put_signed_obj(
        world.store,
        ExpectedResourceInventory(
            "inventory:narrow-001", world.reg_loc, world.reg_loc.content_digest,
            "tenant:ibvi", "binding:meta-primary", "account:ibvi-01", "scope:campaigns-active",
            DateRange("2026-10-31", "2026-11-10", True),
            (ExpectedResourceKey("binding:meta-primary", "account:ibvi-01", _CAMP_A, "campaign", "2026-11-10"),),
        ),
        world.key_reg_loc,
    )
    assert narrow_inv.inventory_id == "inventory:narrow-001"
    with pytest.raises(ClosedValidationError, match="resource_ref|inventory"):
        conduct_offline_run(
            run_input=world.make_run_input(expected_resource_inventory_locator=narrow_inv_loc, store=ReadOnlyGuardStore(world.store)),
            intelligence=intel,
        )

    only_aux_ev = AnalysisEvidence(world.aux_exec, world.aux_results, (world.scalar_schema,), world.snap3_loc, world.policy_loc, True, world.run_loc)
    with pytest.raises(ClosedValidationError, match="analysis_execution_locator|primary"):
        conduct_offline_run(
            run_input=world.make_run_input(analysis_evidence=(only_aux_ev,)),
            intelligence=intel,
        )


def test_rejects_tampered_duplicate_or_out_of_policy_findings(world: ConductorTestWorld) -> None:
    run_in = world.make_run_input()
    bad_str_intel = CustomCallbackIntelligence(world.intel_alg_1, lambda _c, _e: "not-a-sequence")
    with pytest.raises(ClosedValidationError):
        conduct_offline_run(run_input=run_in, intelligence=bad_str_intel)

    def _dup_findings(ctx: EvaluationContext, ev: Sequence[AnalysisEvidence]) -> tuple[Finding, ...]:
        found = evaluate_findings(ctx, ev[0])
        return (found[0], found[0])

    with pytest.raises(ClosedValidationError, match="duplicate"):
        conduct_offline_run(run_input=run_in, intelligence=CustomCallbackIntelligence(world.intel_alg_1, _dup_findings))

    def _out_of_policy_finding(ctx: EvaluationContext, ev: Sequence[AnalysisEvidence]) -> tuple[Finding, ...]:
        entry = ev[0].execution.canonical_result_set.entry(ctx.metrics_result_key)
        fkey = "finding:sha256:" + ("3" * 64)
        return (Finding(world.exec_loc, entry.result_locator, entry.result_key, fkey, "saturation", FINDING_DETECTED, False, (entry.result_locator,), world.policy_loc),)

    with pytest.raises(ClosedValidationError, match="policy|finding_type"):
        conduct_offline_run(run_input=run_in, intelligence=CustomCallbackIntelligence(world.intel_alg_1, _out_of_policy_finding))

    def _tampered_finding(ctx: EvaluationContext, ev: Sequence[AnalysisEvidence]) -> tuple[Finding, ...]:
        f0 = evaluate_findings(ctx, ev[0])[0]
        object.__setattr__(f0, "finding_digest", "sha256:" + ("0" * 64))
        return (f0,)

    with pytest.raises(ClosedValidationError):
        conduct_offline_run(run_input=run_in, intelligence=CustomCallbackIntelligence(world.intel_alg_1, _tampered_finding))


def test_rejects_wrong_finding_locators_and_unpermitted_degraded_certification(world: ConductorTestWorld) -> None:
    run_in = world.make_run_input()

    def _wrong_exec_finding(ctx: EvaluationContext, ev: Sequence[AnalysisEvidence]) -> tuple[Finding, ...]:
        entry = ev[0].execution.canonical_result_set.entry(ctx.metrics_result_key)
        fkey = "finding:sha256:" + ("7" * 64)
        return (Finding(world.aux_exec_loc, entry.result_locator, entry.result_key, fkey, "waste", FINDING_DETECTED, False, (entry.result_locator,), world.policy_loc),)

    with pytest.raises(ClosedValidationError, match="analysis_execution_locator|mismatch"):
        conduct_offline_run(run_input=run_in, intelligence=CustomCallbackIntelligence(world.intel_alg_1, _wrong_exec_finding))

    bad_degraded = (AttestedCertificationInput(CertificationInput(DerivedCertificationStatus.DEGRADED, "derived_input"), False),)
    with pytest.raises(ClosedValidationError, match="degraded|DEGRADED"):
        conduct_offline_run(
            run_input=world.make_run_input(attested_certification_inputs=bad_degraded),
            intelligence=PolicyRuleOfflineIntelligence(world.intel_alg_1),
        )


def test_rejects_empty_wire_outcome_digest_and_missing_registry_snapshot(world: ConductorTestWorld) -> None:
    intel = PolicyRuleOfflineIntelligence(world.intel_alg_1)
    valid_out = conduct_offline_run(run_input=world.make_run_input(), intelligence=intel)
    with pytest.raises(ClosedValidationError, match="outcome_digest"):
        ConductorRunOutcome.from_dict({**valid_out.to_dict(), "outcome_digest": ""})

    missing_reg_store = ReadOnlyGuardStore(world.store, hidden_refs=frozenset({world.reg_loc.object_ref}))
    with pytest.raises(ClosedValidationError):
        conduct_offline_run(
            run_input=world.make_run_input(store=missing_reg_store),
            intelligence=intel,
        )


def test_rejects_forged_unstored_bad_sig_and_undeclared_query_auxiliary_evidence(world: ConductorTestWorld) -> None:
    intel = PolicyRuleOfflineIntelligence(world.intel_alg_1)
    ev_main = AnalysisEvidence(world.exec_obj, world.results, (world.metrics_schema, world.scalar_schema), world.snap3_loc, world.policy_loc, True, world.run_loc)
    s_cols = (ResultColumn("row_count", "int64", False),)
    forged_proj = ResultProjection("scalar", world.scalar_schema_loc, s_cols, ((TaggedScalarCell("int64", "999"),),), 1)
    forged_res = AnalysisResult.from_dict(_sign_dict(AnalysisResult(world.run_loc, world.snap3_loc, world.aux_exec.analysis_replay_input_bundle_locator, "result:row_count", forged_proj).to_dict(), world.key_reg_loc), require_signed=True)
    forged_exec = AnalysisExecution.from_dict(_sign_dict(AnalysisExecution(world.aux_exec.analysis_replay_input_bundle_locator, CanonicalResultSet.build(world.aux_exec.analysis_replay_input_bundle_locator, (CanonicalResultEntry.from_result(forged_res),))).to_dict(), world.key_reg_loc), require_signed=True)
    unstored_aux_ev = AnalysisEvidence(forged_exec, (forged_res,), (world.scalar_schema,), world.snap3_loc, world.policy_loc, True, world.run_loc)
    with pytest.raises(ClosedValidationError):
        conduct_offline_run(run_input=world.make_run_input(analysis_evidence=(ev_main, unstored_aux_ev)), intelligence=intel)

    bad_b64 = base64.b64encode(b"\x01" * 64).decode("ascii")
    bad_sig_dict = {**world.aux_results[0].to_dict(), "integrity": {**world.aux_results[0].integrity.to_dict(), "signature_base64": bad_b64}}  # type: ignore[union-attr]
    world.store.put_json_artifact(AnalysisResult.SCHEMA, bad_sig_dict)
    bad_sig_res = AnalysisResult.from_dict(bad_sig_dict, require_signed=True)
    bad_sig_exec, _ = _put_signed_obj(world.store, AnalysisExecution(world.aux_exec.analysis_replay_input_bundle_locator, CanonicalResultSet.build(world.aux_exec.analysis_replay_input_bundle_locator, (CanonicalResultEntry.from_result(bad_sig_res),))), world.key_reg_loc)
    bad_sig_ev = AnalysisEvidence(bad_sig_exec, (bad_sig_res,), (world.scalar_schema,), world.snap3_loc, world.policy_loc, True, world.run_loc)
    with pytest.raises(ClosedValidationError, match="signature"):
        conduct_offline_run(run_input=world.make_run_input(analysis_evidence=(ev_main, bad_sig_ev)), intelligence=intel)

    undeclared_res, _ = _put_signed_obj(world.store, AnalysisResult(world.run_loc, world.snap3_loc, world.aux_exec.analysis_replay_input_bundle_locator, "result:undeclared", forged_proj), world.key_reg_loc)
    undeclared_exec, _ = _put_signed_obj(world.store, AnalysisExecution(world.aux_exec.analysis_replay_input_bundle_locator, CanonicalResultSet.build(world.aux_exec.analysis_replay_input_bundle_locator, (CanonicalResultEntry.from_result(undeclared_res),))), world.key_reg_loc)
    undeclared_ev = AnalysisEvidence(undeclared_exec, (undeclared_res,), (world.scalar_schema,), world.snap3_loc, world.policy_loc, True, world.run_loc)
    with pytest.raises(ClosedValidationError):
        conduct_offline_run(run_input=world.make_run_input(analysis_evidence=(ev_main, undeclared_ev)), intelligence=intel)
    with pytest.raises(ClosedValidationError):
        conduct_offline_run(run_input=world.make_run_input(analysis_execution_locator=undeclared_exec.locator(), resolved_analysis_results=(undeclared_res,)), intelligence=intel)

    wrong_schema_ev = AnalysisEvidence(world.aux_exec, world.aux_results, (world.metrics_schema,), world.snap3_loc, world.policy_loc, True, world.run_loc)
    with pytest.raises(ClosedValidationError, match="resolved_schemas"):
        conduct_offline_run(run_input=world.make_run_input(analysis_evidence=(ev_main, wrong_schema_ev)), intelligence=intel)


def test_rejects_out_of_inventory_resource_in_auxiliary_evidence(world: ConductorTestWorld) -> None:
    intel = PolicyRuleOfflineIntelligence(world.intel_alg_1)
    ev_main = AnalysisEvidence(world.exec_obj, world.results, (world.metrics_schema, world.scalar_schema), world.snap3_loc, world.policy_loc, True, world.run_loc)
    r_cols = (ResultColumn("resource_ref", "opaque_ref", False),)
    r_schema, r_schema_loc = _put_signed_obj(world.store, AnalysisResultSchema("relation", r_cols, ("resource_ref",)), world.key_reg_loc)
    q_r = DuckDbQueryDefinition("result:res_check", "query:res_check", "SELECT 1", r_schema_loc, "relation", r_cols, ("resource_ref",), ("resource_ref",))
    exts = (DuckDbExtensionSpec("parquet", "1.5.5", "explicit_local_binary", DuckDbExtensionBinaryLocator.for_binary_bytes(world.ext_bytes)),)
    _, b_out_loc = _put_signed_obj(world.store, AnalysisReplayInputBundle("bundle:aux-out", world.run_loc, world.snap3_loc, "1.5.5", DuckDbBinaryObjectLocator.for_binary_bytes(world.duck_bytes), exts, (DuckDbSessionSetting("threads", TaggedScalarCell("int64", "1")),), (), (q_r,), world.policy_loc, (world.tmpl_loc,)), world.key_reg_loc)
    out_proj = ResultProjection("relation", r_schema_loc, r_cols, ((TaggedScalarCell("opaque_ref", _CAMP_OUT),),), 1)
    out_res, _ = _put_signed_obj(world.store, AnalysisResult(world.run_loc, world.snap3_loc, b_out_loc, "result:res_check", out_proj), world.key_reg_loc)
    out_exec, _ = _put_signed_obj(world.store, AnalysisExecution(b_out_loc, CanonicalResultSet.build(b_out_loc, (CanonicalResultEntry.from_result(out_res),))), world.key_reg_loc)
    out_aux_ev = AnalysisEvidence(out_exec, (out_res,), (r_schema,), world.snap3_loc, world.policy_loc, True, world.run_loc)
    with pytest.raises(ClosedValidationError, match="resource_ref|inventory"):
        conduct_offline_run(run_input=world.make_run_input(analysis_evidence=(ev_main, out_aux_ev)), intelligence=intel)

