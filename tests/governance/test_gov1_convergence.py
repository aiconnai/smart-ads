"""Tests for tools.governance.gov1_convergence — Etapa 8 gate, D4 Etapa 7 verifier, and Etapa 11 fail-closed block."""
from __future__ import annotations

import ast
import base64
import copy
from dataclasses import replace
from pathlib import Path
import shutil
import subprocess
from typing import Any

import pytest

from smart_ads.contracts.schemas import compute_schema_bundle_digest
from tools.governance import decomposition_admission, p1
from tools.governance.decomposition_runtime import (
    CHECKPOINT,
    HEAD,
    INVENTORY,
    REGISTRY,
    STATE,
    ClockInterval,
    Floor,
    InstallationPins,
)
from tools.governance.decomposition_scope import run_git_offline
import tools.governance.gov1_convergence as gov1_convergence
import tools.governance.gov1_mcp as gov1_mcp
import tools.governance.gov1_sandbox as gov1_sandbox
import tools.governance.gov1_wheel as gov1_wheel
from tools.governance.jcs import canonicalize
from tools.governance.locator import Store, digest, json_digest, make_locator

REPO_ROOT = Path(__file__).resolve().parents[2]
ADR_PATH = REPO_ROOT / "docs" / "adr" / "ADR-0001-smart-ads-read-gateway.md"
PYPROJECT_PATH = REPO_ROOT / "pyproject.toml"
UV_LOCK_PATH = REPO_ROOT / "uv.lock"
EXPECTED_ADR_SHA256 = (
    "sha256:239b53e0af44c176b78c363dc271c9fd882910bd4ab2ffb6844cb8fb2458640e"
)

EXPECTED_17_NEGATIVE_CASES: tuple[str, ...] = (
    "cpu_limit_enforced",
    "credential_paths_denied",
    "env_is_exact_allowlist",
    "file_size_limit_enforced",
    "host_dev_denied",
    "host_home_denied",
    "host_proc_denied",
    "host_sys_denied",
    "inherited_fd_denied",
    "memory_limit_enforced",
    "output_limit_enforced",
    "pids_limit_enforced",
    "process_creation_denied",
    "socket_denied",
    "tmpfs_limit_enforced",
    "wall_clock_limit_enforced",
    "write_outside_tmp_denied",
)

RUN_CONTEXT_LOCATOR = make_locator(
    "smart_ads/migration_run_context/v1", b'{"run":"gov1-task6"}'
)
ALT_RUN_CONTEXT_LOCATOR = make_locator(
    "smart_ads/migration_run_context/v1", b'{"run":"gov1-task6-other"}'
)
OCI_IMAGE_DIGEST = "sha256:" + ("1" * 64)
RUNNER_BINARY_DIGEST = "sha256:" + ("2" * 64)

VALID_FROM_UTC = "2026-01-01T00:00:00Z"
VALID_UNTIL_UTC = "2027-01-01T00:00:00Z"
ISSUED_AT_UTC = "2026-09-07T10:00:00Z"
BUILT_AT_UTC = "2026-09-07T10:00:05Z"
VERIFIED_AT_UTC = "2026-09-07T10:00:10Z"
EXECUTED_AT_UTC = "2026-09-07T10:00:15Z"
CONVERGED_AT_UTC = "2026-09-07T10:00:18Z"
CLOCK_NOW_UTC = "2026-09-07T10:00:20Z"
BUILD_RUN_ID = "build-run-gov1-task6-001"


def _recompute_candidate_digest(candidate: dict[str, Any]) -> dict[str, Any]:
    updated = copy.deepcopy(candidate)
    updated["payload_digest"] = json_digest(updated["payload"])
    return updated


def _init_temp_git_repo(dest: Path) -> Path:
    dest.mkdir(parents=True, exist_ok=True)
    shutil.copy2(PYPROJECT_PATH, dest / "pyproject.toml")
    shutil.copy2(UV_LOCK_PATH, dest / "uv.lock")
    shutil.copytree(
        REPO_ROOT / "src",
        dest / "src",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo", "*.egg-info"),
    )
    run_git_offline(dest, "init", "-q")
    run_git_offline(dest, "config", "user.name", "Gov1 Convergence Test")
    run_git_offline(dest, "config", "user.email", "gov1@example.invalid")
    run_git_offline(dest, "config", "commit.gpgsign", "false")
    run_git_offline(dest, "add", ".")
    run_git_offline(dest, "commit", "-q", "-m", "commit A baseline")
    return dest


class MemoryProtectedRuntime:
    """Hermetic in-memory ProtectedRuntime exercising linearizable CAS and final head/clock check."""

    def __init__(
        self,
        config: dict[str, Any],
        head: dict[str, Any],
        checkpoint: dict[str, Any],
    ) -> None:
        self.config = canonicalize(config)
        self.head = copy.deepcopy(head)
        self.checkpoint = copy.deepcopy(checkpoint)
        self.floor = Floor(0, None, "v0")
        self.clock = ClockInterval(CLOCK_NOW_UTC, CLOCK_NOW_UTC)
        self.cas_calls = 0
        self.conflict = False
        self.after_cas_head: dict[str, Any] | None = None
        self.after_cas_clock: ClockInterval | None = None

    def configuration_bytes(self) -> bytes:
        return self.config

    def installation_authority(self) -> str:
        return "synthetic-gov1-installation"

    def authenticated_clock(self) -> ClockInterval:
        return self.clock

    def read_head(self, register: str) -> dict[str, Any]:
        assert register == "head:gov1-synthetic"
        return copy.deepcopy(self.head)

    def observe_head_and_clock(
        self, register: str
    ) -> tuple[dict[str, Any], ClockInterval]:
        clock = self.authenticated_clock()
        return self.read_head(register), clock

    def read_checkpoint(self, register: str) -> tuple[dict[str, Any], Floor]:
        assert register == "checkpoint:gov1-synthetic"
        return copy.deepcopy(self.checkpoint), self.floor

    def compare_and_swap(
        self,
        register: str,
        expected: Floor,
        new: Floor,
        head_register: str,
        expected_head_locator: dict[str, Any],
    ) -> bool:
        assert (
            register == "checkpoint:gov1-synthetic"
            and head_register == "head:gov1-synthetic"
        )
        self.cas_calls += 1
        if (
            self.conflict
            or expected != self.floor
            or expected_head_locator != self.head
        ):
            return False
        self.floor = replace(new, version=f"v{self.cas_calls}")
        if self.after_cas_head is not None:
            self.head = copy.deepcopy(self.after_cas_head)
        if self.after_cas_clock is not None:
            self.clock = self.after_cas_clock
        return True


@pytest.fixture(scope="module")
def synthetic_gov1_keys(
    tmp_path_factory: pytest.TempPathFactory,
) -> dict[str, tuple[Path, bytes, str]]:
    root = tmp_path_factory.mktemp("gov1_d4_keys")
    role_names = (
        "trust_anchor",
        "security_owner",
        "build_provenance_verifier",
        "build_boundary_verifier",
        "security_verifier",
        "gov1_convergence_verifier",
        "7a_verifier",
        "independent_7a_verifier",
    )
    out: dict[str, tuple[Path, bytes, str]] = {}
    for role in role_names:
        priv = root / f"{role}.pem"
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "Ed25519", "-out", str(priv)],
            check=True,
            capture_output=True,
        )
        raw32 = p1.raw_public_key_from_pem(priv)
        out[role] = (priv, raw32, p1.key_id_for(raw32))
    return out


@pytest.fixture(scope="module")
def baseline_artifacts(
    tmp_path_factory: pytest.TempPathFactory,
) -> dict[str, Any]:
    out_dir = tmp_path_factory.mktemp("gov1_conv_baseline")
    wheel_path, snapshot = gov1_wheel.build_reproducible_wheel(REPO_ROOT, out_dir)
    wheel_bytes = wheel_path.read_bytes()
    inspection = gov1_wheel.inspect_wheel_boundary(wheel_path)
    execution = gov1_mcp.execute_mcp_rejection_matrix_on_wheel(wheel_path)
    seccomp_profile = gov1_sandbox.build_default_7a_seccomp_profile()

    sandbox_cand = gov1_sandbox.build_sealed_sandbox_profile_candidate(
        migration_run_context_locator=RUN_CONTEXT_LOCATOR,
        oci_image_digest=OCI_IMAGE_DIGEST,
        runner_binary_digest=RUNNER_BINARY_DIGEST,
        seccomp_profile=seccomp_profile,
        issued_at_utc=ISSUED_AT_UTC,
        valid_from_utc=VALID_FROM_UTC,
        valid_until_utc=VALID_UNTIL_UTC,
    )
    sandbox_cand_ref = gov1_sandbox.build_local_candidate_ref(sandbox_cand)

    prov_cand = gov1_wheel.build_wheel_build_provenance_candidate(
        migration_run_context_locator=RUN_CONTEXT_LOCATOR,
        build_run_id=BUILD_RUN_ID,
        built_at_utc=BUILT_AT_UTC,
        snapshot=snapshot,
        source_date_epoch=gov1_wheel.DEFAULT_SOURCE_DATE_EPOCH,
        schema_bundle_digest=inspection["schema_bundle_digest"],
        wheel_bytes=wheel_bytes,
    )
    prov_cand_ref = gov1_sandbox.build_local_candidate_ref(prov_cand)

    boundary_cand = gov1_wheel.build_wheel_boundary_report_candidate(
        migration_run_context_locator=RUN_CONTEXT_LOCATOR,
        build_run_id=BUILD_RUN_ID,
        verified_at_utc=VERIFIED_AT_UTC,
        source_commit_sha=snapshot.commit_sha,
        build_backend_digest=snapshot.build_backend_digest,
        wheel_build_provenance_candidate_ref=prov_cand_ref,
        inspection=inspection,
    )

    mcp_cand = gov1_mcp.build_mcp_rejection_matrix_report_candidate(
        migration_run_context_locator=RUN_CONTEXT_LOCATOR,
        build_run_id=BUILD_RUN_ID,
        executed_at_utc=EXECUTED_AT_UTC,
        source_commit_sha=snapshot.commit_sha,
        build_backend_digest=snapshot.build_backend_digest,
        sealed_sandbox_profile_candidate_ref=sandbox_cand_ref,
        execution=execution,
    )

    return {
        "wheel_path": wheel_path,
        "wheel_bytes": wheel_bytes,
        "snapshot": snapshot,
        "inspection": inspection,
        "execution": execution,
        "seccomp_profile": seccomp_profile,
        "sandbox_cand": sandbox_cand,
        "sandbox_cand_ref": sandbox_cand_ref,
        "prov_cand": prov_cand,
        "prov_cand_ref": prov_cand_ref,
        "boundary_cand": boundary_cand,
        "mcp_cand": mcp_cand,
    }


class Gov1D4World:
    """Synthetic D4 authority world signing all 4 Etapa 7 envelopes under ADR-0001 §12.7 profiles."""

    def __init__(
        self,
        root: Path,
        keys: dict[str, tuple[Path, bytes, str]],
        baseline: dict[str, Any],
        *,
        registry_mutation: Any = None,
        sandbox_validity: dict[str, str] | None = None,
        built_at_utc: str = BUILT_AT_UTC,
    ) -> None:
        self.keys = keys
        self.baseline = baseline
        self.adr = ADR_PATH.read_bytes()
        self.profiles = {
            p["schema"]: p for p in decomposition_admission.profile_proposals(self.adr)
        }
        self.store = Store(root / "objects")
        self.objects: dict[str, dict[str, Any]] = {}

        _, anchor_raw, _ = keys["trust_anchor"]
        validity_window = {"from": VALID_FROM_UTC, "until": VALID_UNTIL_UTC}
        self.config = {
            "$schema": "smart_ads/cell_trust_anchor_config/v1",
            "trust_anchor_id": "synthetic-gov1-anchor",
            "public_key_base64": base64.b64encode(anchor_raw).decode("ascii"),
            "public_key_sha256": digest(anchor_raw),
            "validity": validity_window,
            "allowed_registry_artifact_types": [REGISTRY, INVENTORY],
            "inventory_bootstrap_profile": self.profiles[INVENTORY],
            "anti_rollback_checkpoint_profile": self.profiles[CHECKPOINT],
            "cell_id": "synthetic-gov1-cell",
            "head_register": "head:gov1-synthetic",
            "checkpoint_register": "checkpoint:gov1-synthetic",
            "installation_authority": "synthetic-gov1-installation",
        }

        role_action_specs = (
            (
                "trust_anchor",
                [
                    (INVENTORY, "contract_inventory_issue"),
                    (HEAD, "current_key_state_head_issue"),
                    (STATE, "current_key_state_issue"),
                ],
            ),
            (
                "security_owner",
                [
                    (
                        gov1_sandbox.SANDBOX_PROFILE_SCHEMA,
                        "sealed_sandbox_profile_issue",
                    )
                ],
            ),
            (
                "build_provenance_verifier",
                [
                    (
                        gov1_wheel.WHEEL_BUILD_PROVENANCE_SCHEMA,
                        "wheel_build_provenance_issue",
                    )
                ],
            ),
            (
                "build_boundary_verifier",
                [
                    (
                        gov1_wheel.WHEEL_BOUNDARY_REPORT_SCHEMA,
                        "wheel_boundary_report_issue",
                    )
                ],
            ),
            (
                "security_verifier",
                [
                    (
                        gov1_mcp.MCP_REJECTION_REPORT_SCHEMA,
                        "mcp_rejection_matrix_report_issue",
                    )
                ],
            ),
            (
                "gov1_convergence_verifier",
                [
                    (
                        gov1_convergence.GOV1_CONVERGENCE_SCHEMA,
                        "gov1_convergence_record_issue",
                    )
                ],
            ),
            (
                "7a_verifier",
                [
                    (
                        gov1_convergence.NEGATIVE_SECURITY_SCHEMA,
                        "negative_security_test_report_issue",
                    )
                ],
            ),
            (
                "independent_7a_verifier",
                [
                    (
                        gov1_convergence.CERTIFICATION_7A_SCHEMA,
                        "certification_7a_record_issue",
                    )
                ],
            ),
        )

        entries: list[dict[str, Any]] = []
        for role_name, pairs in role_action_specs:
            _, raw32, key_id = keys[role_name]
            entries.append(
                {
                    "key_id": key_id,
                    "public_key_base64": base64.b64encode(raw32).decode("ascii"),
                    "public_key_sha256": digest(raw32),
                    "principal": f"principal:{role_name}",
                    "tenant": "synthetic-tenant",
                    "role": role_name,
                    "validity": copy.deepcopy(validity_window),
                    "lifecycle_state": "active",
                    "allowed_actions": [
                        {"schema": schema, "action": action} for schema, action in pairs
                    ],
                }
            )

        reg_unsigned: dict[str, Any] = {
            "$schema": REGISTRY,
            "trust_anchor_id": "synthetic-gov1-anchor",
            "epoch": 4,
            "issued_at_utc": ISSUED_AT_UTC,
            "entries": entries,
            "integrity": {
                "key_id": keys["trust_anchor"][2],
                "key_registry_snapshot_locator": None,
            },
        }
        if registry_mutation is not None:
            registry_mutation(reg_unsigned)
        reg_signed = p1.sign_envelope(
            reg_unsigned,
            self.profiles[REGISTRY]["domain_prefix"],
            keys["trust_anchor"][0],
        )
        self.objects["registry"] = reg_signed
        self.registry_loc = self.store.put(reg_signed)

        common = {
            "trust_anchor_id": "synthetic-gov1-anchor",
            "cell_id": "synthetic-gov1-cell",
            "issued_at_utc": ISSUED_AT_UTC,
            "valid_until_utc": VALID_UNTIL_UTC,
            "maximum_age_seconds": 300,
        }
        key_states = [
            {
                "key_id": e["key_id"],
                "public_key_sha256": e["public_key_sha256"],
                "lifecycle_state": e["lifecycle_state"],
            }
            for e in reg_signed["entries"]
        ]
        state_signed = p1.sign_envelope(
            {
                **common,
                "$schema": STATE,
                "epoch": 1,
                "registry_locator": self.registry_loc,
                "predecessor_state_locator": None,
                "key_states": key_states,
                "integrity": {
                    "key_id": keys["trust_anchor"][2],
                    "key_registry_snapshot_locator": self.registry_loc,
                },
            },
            self.profiles[STATE]["domain_prefix"],
            keys["trust_anchor"][0],
        )
        self.objects["state"] = state_signed
        self.state_loc = self.store.put(state_signed)

        head_signed = p1.sign_envelope(
            {
                **common,
                "$schema": HEAD,
                "epoch": 1,
                "current_state_locator": self.state_loc,
                "current_state_digest": self.state_loc["content_digest"],
                "predecessor_head_locator": None,
                "predecessor_head_digest": None,
                "integrity": {
                    "key_id": keys["trust_anchor"][2],
                    "key_registry_snapshot_locator": self.registry_loc,
                },
            },
            self.profiles[HEAD]["domain_prefix"],
            keys["trust_anchor"][0],
        )
        self.objects["head"] = head_signed
        self.head_loc = self.store.put(head_signed)

        checkpoint_signed = p1.sign_envelope(
            {
                **common,
                "$schema": CHECKPOINT,
                "highest_seen_epoch": 0,
                "head_digest": None,
                "integrity": {
                    "key_id": keys["trust_anchor"][2],
                    "key_registry_snapshot_locator": None,
                },
            },
            self.profiles[CHECKPOINT]["domain_prefix"],
            keys["trust_anchor"][0],
        )
        self.objects["checkpoint"] = checkpoint_signed
        self.checkpoint_loc = self.store.put(checkpoint_signed)

        inventory_signed = p1.sign_envelope(
            {
                **common,
                "$schema": INVENTORY,
                "epoch": 1,
                "predecessor_inventory_locator": None,
                "profiles": list(self.profiles.values()),
                "integrity": {
                    "key_id": keys["trust_anchor"][2],
                    "key_registry_snapshot_locator": self.registry_loc,
                },
            },
            self.profiles[INVENTORY]["domain_prefix"],
            keys["trust_anchor"][0],
        )
        self.objects["inventory"] = inventory_signed
        self.inventory_loc = self.store.put(inventory_signed)

        eff_sbx_val = sandbox_validity or {
            "from": VALID_FROM_UTC,
            "until": VALID_UNTIL_UTC,
        }
        sbx_unsigned = gov1_sandbox.build_sealed_sandbox_profile_envelope(
            migration_run_context_locator=RUN_CONTEXT_LOCATOR,
            oci_image_digest=OCI_IMAGE_DIGEST,
            runner_binary_digest=RUNNER_BINARY_DIGEST,
            seccomp_profile=baseline["seccomp_profile"],
            issued_at_utc=ISSUED_AT_UTC,
            valid_from_utc=eff_sbx_val["from"],
            valid_until_utc=eff_sbx_val["until"],
            registry_locator=self.registry_loc,
            signer_key_id=keys["security_owner"][2],
        )
        self.sandbox_env = p1.sign_envelope(
            sbx_unsigned,
            self.profiles[gov1_sandbox.SANDBOX_PROFILE_SCHEMA]["domain_prefix"],
            keys["security_owner"][0],
        )
        self.sandbox_loc = self.store.put(self.sandbox_env)

        snapshot: gov1_wheel.GitBuildSnapshot = baseline["snapshot"]
        prov_unsigned = gov1_wheel.build_wheel_build_provenance_envelope(
            migration_run_context_locator=RUN_CONTEXT_LOCATOR,
            build_run_id=BUILD_RUN_ID,
            built_at_utc=built_at_utc,
            snapshot=snapshot,
            source_date_epoch=gov1_wheel.DEFAULT_SOURCE_DATE_EPOCH,
            schema_bundle_digest=baseline["inspection"]["schema_bundle_digest"],
            wheel_bytes=baseline["wheel_bytes"],
            registry_locator=self.registry_loc,
            signer_key_id=keys["build_provenance_verifier"][2],
        )
        self.prov_env = p1.sign_envelope(
            prov_unsigned,
            self.profiles[gov1_wheel.WHEEL_BUILD_PROVENANCE_SCHEMA]["domain_prefix"],
            keys["build_provenance_verifier"][0],
        )
        self.prov_loc = self.store.put(self.prov_env)

        bound_unsigned = gov1_wheel.build_wheel_boundary_report_envelope(
            migration_run_context_locator=RUN_CONTEXT_LOCATOR,
            build_run_id=BUILD_RUN_ID,
            verified_at_utc=VERIFIED_AT_UTC,
            source_commit_sha=snapshot.commit_sha,
            build_backend_digest=snapshot.build_backend_digest,
            wheel_build_provenance_locator=self.prov_loc,
            inspection=baseline["inspection"],
            registry_locator=self.registry_loc,
            signer_key_id=keys["build_boundary_verifier"][2],
        )
        self.boundary_env = p1.sign_envelope(
            bound_unsigned,
            self.profiles[gov1_wheel.WHEEL_BOUNDARY_REPORT_SCHEMA]["domain_prefix"],
            keys["build_boundary_verifier"][0],
        )
        self.boundary_loc = self.store.put(self.boundary_env)

        mcp_unsigned = gov1_mcp.build_mcp_rejection_matrix_report_envelope(
            migration_run_context_locator=RUN_CONTEXT_LOCATOR,
            build_run_id=BUILD_RUN_ID,
            executed_at_utc=EXECUTED_AT_UTC,
            source_commit_sha=snapshot.commit_sha,
            build_backend_digest=snapshot.build_backend_digest,
            sealed_sandbox_profile_locator=self.sandbox_loc,
            execution=baseline["execution"],
            registry_locator=self.registry_loc,
            signer_key_id=keys["security_verifier"][2],
        )
        self.mcp_env = p1.sign_envelope(
            mcp_unsigned,
            self.profiles[gov1_mcp.MCP_REJECTION_REPORT_SCHEMA]["domain_prefix"],
            keys["security_verifier"][0],
        )
        self.mcp_loc = self.store.put(self.mcp_env)

        neg_unsigned = {
            "$schema": gov1_convergence.NEGATIVE_SECURITY_SCHEMA,
            "migration_run_context_locator": RUN_CONTEXT_LOCATOR,
            "sealed_sandbox_profile_locator": self.sandbox_loc,
            "build_run_id": BUILD_RUN_ID,
            "executed_at_utc": EXECUTED_AT_UTC,
            "source_commit_sha": snapshot.commit_sha,
            "wheel_digest": digest(baseline["wheel_bytes"]),
            "build_backend_digest": snapshot.build_backend_digest,
            "schema_bundle_digest": baseline["inspection"]["schema_bundle_digest"],
            "cases": [
                {"case_id": c, "status": "passed"}
                for c in gov1_convergence.MANDATORY_7A_NEGATIVE_SECURITY_CASES
            ],
            "integrity": {
                "key_id": keys["7a_verifier"][2],
                "key_registry_snapshot_locator": self.registry_loc,
            },
        }
        self.neg_env = p1.sign_envelope(
            neg_unsigned,
            self.profiles[gov1_convergence.NEGATIVE_SECURITY_SCHEMA]["domain_prefix"],
            keys["7a_verifier"][0],
        )
        self.neg_loc = self.store.put(self.neg_env)

        cert7a_unsigned = {
            "$schema": gov1_convergence.CERTIFICATION_7A_SCHEMA,
            "migration_run_context_locator": RUN_CONTEXT_LOCATOR,
            "sealed_sandbox_profile_locator": self.sandbox_loc,
            "negative_security_test_report_locator": self.neg_loc,
            "wheel_boundary_report_locator": self.boundary_loc,
            "mcp_rejection_matrix_report_locator": self.mcp_loc,
            "build_run_id": BUILD_RUN_ID,
            "certified_at_utc": EXECUTED_AT_UTC,
            "source_commit_sha": snapshot.commit_sha,
            "wheel_digest": digest(baseline["wheel_bytes"]),
            "build_backend_digest": snapshot.build_backend_digest,
            "schema_bundle_digest": baseline["inspection"]["schema_bundle_digest"],
            "certification_status": "PASS",
            "integrity": {
                "key_id": keys["independent_7a_verifier"][2],
                "key_registry_snapshot_locator": self.registry_loc,
            },
        }
        self.cert7a_env = p1.sign_envelope(
            cert7a_unsigned,
            self.profiles[gov1_convergence.CERTIFICATION_7A_SCHEMA]["domain_prefix"],
            keys["independent_7a_verifier"][0],
        )
        self.cert7a_loc = self.store.put(self.cert7a_env)

        self.runtime = MemoryProtectedRuntime(
            self.config, self.head_loc, self.checkpoint_loc
        )
        self.pins = InstallationPins(
            configuration_digest=digest(self.runtime.config),
            installation_authority="synthetic-gov1-installation",
            cell_id="synthetic-gov1-cell",
            head_register="head:gov1-synthetic",
            checkpoint_register="checkpoint:gov1-synthetic",
            owner_principal="principal:ronaldo",
            owner_tenant="synthetic-tenant",
        )

    def make_verifier(self) -> gov1_convergence.Gov1AdmissionVerifier:
        return gov1_convergence.Gov1AdmissionVerifier(
            self.runtime,
            self.pins,
            self.store,
            self.adr,
            inventory_locator=self.inventory_loc,
        )

    def advance_current_registry(self, mutate_reg_fn: Any) -> None:
        new_reg = copy.deepcopy(self.objects["registry"])
        new_reg["epoch"] = 5
        new_reg["integrity"] = {
            "key_id": self.keys["trust_anchor"][2],
            "key_registry_snapshot_locator": None,
        }
        mutate_reg_fn(new_reg)
        signed_reg = p1.sign_envelope(
            new_reg,
            self.profiles[REGISTRY]["domain_prefix"],
            self.keys["trust_anchor"][0],
        )
        reg_loc = self.store.put(signed_reg)

        new_state = copy.deepcopy(self.objects["state"])
        new_state.update(
            epoch=2,
            registry_locator=reg_loc,
            predecessor_state_locator=self.state_loc,
            key_states=[
                {
                    "key_id": e["key_id"],
                    "public_key_sha256": e["public_key_sha256"],
                    "lifecycle_state": e["lifecycle_state"],
                }
                for e in signed_reg["entries"]
            ],
            integrity={
                "key_id": self.keys["trust_anchor"][2],
                "key_registry_snapshot_locator": reg_loc,
            },
        )
        signed_state = p1.sign_envelope(
            new_state,
            self.profiles[STATE]["domain_prefix"],
            self.keys["trust_anchor"][0],
        )
        state_loc = self.store.put(signed_state)

        new_head = copy.deepcopy(self.objects["head"])
        new_head.update(
            epoch=2,
            current_state_locator=state_loc,
            current_state_digest=state_loc["content_digest"],
            predecessor_head_locator=self.runtime.head,
            predecessor_head_digest=self.runtime.head["content_digest"],
            integrity={
                "key_id": self.keys["trust_anchor"][2],
                "key_registry_snapshot_locator": reg_loc,
            },
        )
        signed_head = p1.sign_envelope(
            new_head,
            self.profiles[HEAD]["domain_prefix"],
            self.keys["trust_anchor"][0],
        )
        self.runtime.head = self.store.put(signed_head)


# ---------------------------------------------------------------------------
# 1. Constants, ADR-0001 Parity, p1.DOMAIN_PREFIXES & Zero ast.Assert
# ---------------------------------------------------------------------------


def test_constants_adr_cases_domain_prefixes_and_zero_ast_assert_across_all_gov1_modules() -> None:
    assert (
        gov1_convergence.GOV1_CONVERGENCE_SCHEMA
        == "smart_ads/gov1_convergence_record/v1"
    )
    assert (
        gov1_convergence.NEGATIVE_SECURITY_SCHEMA
        == "smart_ads/negative_security_test_report/v1"
    )
    assert (
        gov1_convergence.CERTIFICATION_7A_SCHEMA
        == "smart_ads/certification_7a_record/v1"
    )
    assert isinstance(gov1_convergence.MANDATORY_7A_NEGATIVE_SECURITY_CASES, tuple)
    assert (
        gov1_convergence.MANDATORY_7A_NEGATIVE_SECURITY_CASES
        == EXPECTED_17_NEGATIVE_CASES
    )
    assert len(gov1_convergence.MANDATORY_7A_NEGATIVE_SECURITY_CASES) == 17
    assert list(gov1_convergence.MANDATORY_7A_NEGATIVE_SECURITY_CASES) == sorted(
        gov1_convergence.MANDATORY_7A_NEGATIVE_SECURITY_CASES,
        key=lambda s: s.encode("utf-8"),
    )

    # Cross-check exact 17 negative cases against ADR-0001 §3.2 L164-180
    adr_bytes = ADR_PATH.read_bytes()
    assert digest(adr_bytes) == EXPECTED_ADR_SHA256
    adr_lines = adr_bytes.decode("utf-8").splitlines()
    assert tuple(adr_lines[163:180]) == gov1_convergence.MANDATORY_7A_NEGATIVE_SECURITY_CASES

    # p1.DOMAIN_PREFIXES must remain untouched with exactly the 7 pre-D4 schemas
    assert len(p1.DOMAIN_PREFIXES) == 7
    assert "sealed_sandbox_profile/v1" not in p1.DOMAIN_PREFIXES
    assert "gov1_convergence_record/v1" not in p1.DOMAIN_PREFIXES

    # Zero ast.Assert across ALL tools/governance/gov1_*.py modules
    gov1_files = sorted((REPO_ROOT / "tools" / "governance").glob("gov1_*.py"))
    assert [f.name for f in gov1_files] == [
        "gov1_convergence.py",
        "gov1_mcp.py",
        "gov1_sandbox.py",
        "gov1_wheel.py",
    ]
    for mod_path in gov1_files:
        tree = ast.parse(mod_path.read_text(encoding="utf-8"), filename=str(mod_path))
        assert [n for n in ast.walk(tree) if isinstance(n, ast.Assert)] == [], (
            f"ast.Assert found in {mod_path}"
        )


# ---------------------------------------------------------------------------
# 2. Etapa 8 (`verify_pr1_gov1_convergence`) — Candidate Mode & Anti-Mixing
# ---------------------------------------------------------------------------


def test_verify_pr1_gov1_convergence_succeeds_for_coherent_local_candidates(
    baseline_artifacts: dict[str, Any],
) -> None:
    receipt = gov1_convergence.verify_pr1_gov1_convergence(
        sandbox_profile=baseline_artifacts["sandbox_cand"],
        wheel_provenance=baseline_artifacts["prov_cand"],
        wheel_boundary_report=baseline_artifacts["boundary_cand"],
        mcp_rejection_report=baseline_artifacts["mcp_cand"],
        seccomp_profile=baseline_artifacts["seccomp_profile"],
        wheel_path=baseline_artifacts["wheel_path"],
        repo_root=REPO_ROOT,
    )
    assert receipt["artifact_kind"] == "pr1_gov1_pre_pr2_convergence_gate"
    assert receipt["gate_status"] == "PASS"
    assert receipt["mode"] == "candidate"
    assert receipt["final_gov1_convergence_emitted"] is False
    assert receipt["pending_pr3_constituents"] == [
        "smart_ads/certification_7a_record/v1",
        "smart_ads/negative_security_test_report/v1",
    ]
    assert receipt["signable"] is False
    assert receipt["authority"] == "none"
    assert receipt["migration_run_context_locator"] == RUN_CONTEXT_LOCATOR
    assert receipt["build_run_id"] == BUILD_RUN_ID
    assert receipt["source_commit_sha"] == baseline_artifacts["snapshot"].commit_sha
    assert receipt["wheel_digest"] == digest(baseline_artifacts["wheel_bytes"])
    assert (
        receipt["build_backend_digest"]
        == baseline_artifacts["snapshot"].build_backend_digest
    )
    assert receipt["schema_bundle_digest"] == compute_schema_bundle_digest()
    assert receipt["seccomp_profile_digest"] == gov1_sandbox.verify_seccomp_profile(
        baseline_artifacts["seccomp_profile"]
    )
    assert (
        receipt["sorted_record_digest"]
        == baseline_artifacts["inspection"]["sorted_record_digest"]
    )
    assert "$schema" not in receipt and "integrity" not in receipt


@pytest.mark.parametrize(
    "swap_field",
    [
        "sandbox_profile",
        "wheel_provenance",
        "wheel_boundary_report",
        "mcp_rejection_report",
    ],
)
def test_verify_pr1_gov1_convergence_rejects_mode_mixing_and_interchanged_refs(
    tmp_path: Path,
    baseline_artifacts: dict[str, Any],
    synthetic_gov1_keys: dict[str, tuple[Path, bytes, str]],
    swap_field: str,
) -> None:
    world = Gov1D4World(tmp_path, synthetic_gov1_keys, baseline_artifacts)
    kwargs: dict[str, Any] = {
        "sandbox_profile": baseline_artifacts["sandbox_cand"],
        "wheel_provenance": baseline_artifacts["prov_cand"],
        "wheel_boundary_report": baseline_artifacts["boundary_cand"],
        "mcp_rejection_report": baseline_artifacts["mcp_cand"],
        "seccomp_profile": baseline_artifacts["seccomp_profile"],
        "wheel_path": baseline_artifacts["wheel_path"],
        "repo_root": REPO_ROOT,
    }
    env_map = {
        "sandbox_profile": world.sandbox_env,
        "wheel_provenance": world.prov_env,
        "wheel_boundary_report": world.boundary_env,
        "mcp_rejection_report": world.mcp_env,
    }
    kwargs[swap_field] = env_map[swap_field]
    with pytest.raises(ValueError):
        gov1_convergence.verify_pr1_gov1_convergence(**kwargs)

    # Envelope mode without admission_verifier or store must also fail closed
    with pytest.raises(ValueError):
        gov1_convergence.verify_pr1_gov1_convergence(
            sandbox_profile=world.sandbox_env,
            wheel_provenance=world.prov_env,
            wheel_boundary_report=world.boundary_env,
            mcp_rejection_report=world.mcp_env,
            seccomp_profile=baseline_artifacts["seccomp_profile"],
            wheel_path=baseline_artifacts["wheel_path"],
            repo_root=REPO_ROOT,
        )

    # Candidate trying to use artifact_locator/v1 instead of gov1_local_candidate_ref fails closed
    bad_bound_cand = copy.deepcopy(baseline_artifacts["boundary_cand"])
    del bad_bound_cand["payload"]["wheel_build_provenance_candidate_ref"]
    bad_bound_cand["payload"]["wheel_build_provenance_locator"] = world.prov_loc
    bad_bound_cand = _recompute_candidate_digest(bad_bound_cand)
    with pytest.raises(ValueError):
        gov1_convergence.verify_pr1_gov1_convergence(
            sandbox_profile=baseline_artifacts["sandbox_cand"],
            wheel_provenance=baseline_artifacts["prov_cand"],
            wheel_boundary_report=bad_bound_cand,
            mcp_rejection_report=baseline_artifacts["mcp_cand"],
            seccomp_profile=baseline_artifacts["seccomp_profile"],
            wheel_path=baseline_artifacts["wheel_path"],
            repo_root=REPO_ROOT,
        )

    # Symmetric check: P1 envelopes trying to use gov1_local_candidate_ref instead of artifact_locator/v1 fail closed
    verifier = world.make_verifier()
    bad_bound_env = copy.deepcopy(world.boundary_env)
    del bad_bound_env["wheel_build_provenance_locator"]
    bad_bound_env["wheel_build_provenance_candidate_ref"] = (
        baseline_artifacts["prov_cand_ref"]
    )
    bad_bound_env = p1.sign_envelope(
        bad_bound_env,
        world.profiles[gov1_wheel.WHEEL_BOUNDARY_REPORT_SCHEMA]["domain_prefix"],
        synthetic_gov1_keys["build_boundary_verifier"][0],
    )
    world.store.put(bad_bound_env)
    with pytest.raises(ValueError, match="wheel_build_provenance_locator"):
        gov1_convergence.verify_pr1_gov1_convergence(
            sandbox_profile=world.sandbox_env,
            wheel_provenance=world.prov_env,
            wheel_boundary_report=bad_bound_env,
            mcp_rejection_report=world.mcp_env,
            seccomp_profile=baseline_artifacts["seccomp_profile"],
            wheel_path=baseline_artifacts["wheel_path"],
            repo_root=REPO_ROOT,
            admission_verifier=verifier,
            store=world.store,
        )

    bad_mcp_env = copy.deepcopy(world.mcp_env)
    del bad_mcp_env["sealed_sandbox_profile_locator"]
    bad_mcp_env["sealed_sandbox_profile_candidate_ref"] = (
        baseline_artifacts["sandbox_cand_ref"]
    )
    bad_mcp_env = p1.sign_envelope(
        bad_mcp_env,
        world.profiles[gov1_mcp.MCP_REJECTION_REPORT_SCHEMA]["domain_prefix"],
        synthetic_gov1_keys["security_verifier"][0],
    )
    world.store.put(bad_mcp_env)
    with pytest.raises(ValueError, match="sealed_sandbox_profile_locator"):
        gov1_convergence.verify_pr1_gov1_convergence(
            sandbox_profile=world.sandbox_env,
            wheel_provenance=world.prov_env,
            wheel_boundary_report=world.boundary_env,
            mcp_rejection_report=bad_mcp_env,
            seccomp_profile=baseline_artifacts["seccomp_profile"],
            wheel_path=baseline_artifacts["wheel_path"],
            repo_root=REPO_ROOT,
            admission_verifier=verifier,
            store=world.store,
        )


# ---------------------------------------------------------------------------
# 3. Exact Cross-Binding Matrix (`F-05`)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "case_name",
    [
        "run_ctx_sandbox",
        "run_ctx_prov",
        "run_ctx_boundary",
        "run_ctx_mcp",
        "build_run_id_prov",
        "build_run_id_boundary",
        "build_run_id_mcp",
        "commit_sha_prov",
        "commit_sha_boundary",
        "commit_sha_mcp",
        "wheel_digest_prov",
        "wheel_digest_boundary",
        "wheel_digest_mcp",
        "backend_digest_prov",
        "backend_digest_boundary",
        "backend_digest_mcp",
        "schema_digest_prov",
        "schema_digest_boundary",
        "schema_digest_mcp",
        "prov_candidate_ref_mismatch",
        "sandbox_candidate_ref_mismatch",
        "mcp_executed_before_sandbox_from",
        "mcp_executed_at_sandbox_until",
    ],
)
def test_verify_pr1_gov1_convergence_enforces_exact_cross_binding_matrix_f05(
    baseline_artifacts: dict[str, Any],
    case_name: str,
) -> None:
    sbx = copy.deepcopy(baseline_artifacts["sandbox_cand"])
    prov = copy.deepcopy(baseline_artifacts["prov_cand"])
    bound = copy.deepcopy(baseline_artifacts["boundary_cand"])
    mcp = copy.deepcopy(baseline_artifacts["mcp_cand"])

    other_sha256 = "sha256:" + ("f" * 64)
    other_commit = "f" * 40

    if case_name == "run_ctx_sandbox":
        sbx["payload"]["migration_run_context_locator"] = ALT_RUN_CONTEXT_LOCATOR
        sbx = _recompute_candidate_digest(sbx)
        mcp["payload"]["sealed_sandbox_profile_candidate_ref"] = (
            gov1_sandbox.build_local_candidate_ref(sbx)
        )
        mcp = _recompute_candidate_digest(mcp)
    elif case_name == "run_ctx_prov":
        prov["payload"]["migration_run_context_locator"] = ALT_RUN_CONTEXT_LOCATOR
        prov = _recompute_candidate_digest(prov)
        bound["payload"]["wheel_build_provenance_candidate_ref"] = (
            gov1_sandbox.build_local_candidate_ref(prov)
        )
        bound = _recompute_candidate_digest(bound)
    elif case_name == "run_ctx_boundary":
        bound["payload"]["migration_run_context_locator"] = ALT_RUN_CONTEXT_LOCATOR
        bound = _recompute_candidate_digest(bound)
    elif case_name == "run_ctx_mcp":
        mcp["payload"]["migration_run_context_locator"] = ALT_RUN_CONTEXT_LOCATOR
        mcp = _recompute_candidate_digest(mcp)
    elif case_name == "build_run_id_prov":
        prov["payload"]["build_run_id"] = "other-build-run"
        prov = _recompute_candidate_digest(prov)
        bound["payload"]["wheel_build_provenance_candidate_ref"] = (
            gov1_sandbox.build_local_candidate_ref(prov)
        )
        bound = _recompute_candidate_digest(bound)
    elif case_name == "build_run_id_boundary":
        bound["payload"]["build_run_id"] = "other-build-run"
        bound = _recompute_candidate_digest(bound)
    elif case_name == "build_run_id_mcp":
        mcp["payload"]["build_run_id"] = "other-build-run"
        mcp = _recompute_candidate_digest(mcp)
    elif case_name == "commit_sha_prov":
        prov["payload"]["source_commit_sha"] = other_commit
        prov = _recompute_candidate_digest(prov)
        bound["payload"]["wheel_build_provenance_candidate_ref"] = (
            gov1_sandbox.build_local_candidate_ref(prov)
        )
        bound = _recompute_candidate_digest(bound)
    elif case_name == "commit_sha_boundary":
        bound["payload"]["source_commit_sha"] = other_commit
        bound = _recompute_candidate_digest(bound)
    elif case_name == "commit_sha_mcp":
        mcp["payload"]["source_commit_sha"] = other_commit
        mcp = _recompute_candidate_digest(mcp)
    elif case_name == "wheel_digest_prov":
        prov["payload"]["wheel_digest"] = other_sha256
        prov["payload"]["wheel"]["wheel_digest"] = other_sha256
        prov["payload"]["wheel"]["object_ref"] = f"cell-object:{other_sha256}"
        prov = _recompute_candidate_digest(prov)
        bound["payload"]["wheel_build_provenance_candidate_ref"] = (
            gov1_sandbox.build_local_candidate_ref(prov)
        )
        bound = _recompute_candidate_digest(bound)
    elif case_name == "wheel_digest_boundary":
        bound["payload"]["wheel_digest"] = other_sha256
        bound = _recompute_candidate_digest(bound)
    elif case_name == "wheel_digest_mcp":
        mcp["payload"]["wheel_digest"] = other_sha256
        mcp = _recompute_candidate_digest(mcp)
    elif case_name == "backend_digest_prov":
        prov["payload"]["build_backend_digest"] = other_sha256
        prov = _recompute_candidate_digest(prov)
        bound["payload"]["wheel_build_provenance_candidate_ref"] = (
            gov1_sandbox.build_local_candidate_ref(prov)
        )
        bound = _recompute_candidate_digest(bound)
    elif case_name == "backend_digest_boundary":
        bound["payload"]["build_backend_digest"] = other_sha256
        bound = _recompute_candidate_digest(bound)
    elif case_name == "backend_digest_mcp":
        mcp["payload"]["build_backend_digest"] = other_sha256
        mcp = _recompute_candidate_digest(mcp)
    elif case_name == "schema_digest_prov":
        prov["payload"]["schema_bundle_digest"] = other_sha256
        prov = _recompute_candidate_digest(prov)
        bound["payload"]["wheel_build_provenance_candidate_ref"] = (
            gov1_sandbox.build_local_candidate_ref(prov)
        )
        bound = _recompute_candidate_digest(bound)
    elif case_name == "schema_digest_boundary":
        bound["payload"]["schema_bundle_digest"] = other_sha256
        bound = _recompute_candidate_digest(bound)
    elif case_name == "schema_digest_mcp":
        mcp["payload"]["schema_bundle_digest"] = other_sha256
        mcp = _recompute_candidate_digest(mcp)
    elif case_name == "prov_candidate_ref_mismatch":
        other_prov = copy.deepcopy(prov)
        other_prov["payload"]["built_at_utc"] = "2026-09-07T10:00:06Z"
        other_prov = _recompute_candidate_digest(other_prov)
        bound["payload"]["wheel_build_provenance_candidate_ref"] = (
            gov1_sandbox.build_local_candidate_ref(other_prov)
        )
        bound = _recompute_candidate_digest(bound)
    elif case_name == "sandbox_candidate_ref_mismatch":
        other_sbx = copy.deepcopy(sbx)
        other_sbx["payload"]["issued_at_utc"] = "2026-09-07T10:00:01Z"
        other_sbx = _recompute_candidate_digest(other_sbx)
        mcp["payload"]["sealed_sandbox_profile_candidate_ref"] = (
            gov1_sandbox.build_local_candidate_ref(other_sbx)
        )
        mcp = _recompute_candidate_digest(mcp)
    elif case_name == "mcp_executed_before_sandbox_from":
        mcp["payload"]["executed_at_utc"] = "2025-12-31T23:59:59Z"
        mcp = _recompute_candidate_digest(mcp)
    elif case_name == "mcp_executed_at_sandbox_until":
        mcp["payload"]["executed_at_utc"] = VALID_UNTIL_UTC
        mcp = _recompute_candidate_digest(mcp)

    with pytest.raises(ValueError):
        gov1_convergence.verify_pr1_gov1_convergence(
            sandbox_profile=sbx,
            wheel_provenance=prov,
            wheel_boundary_report=bound,
            mcp_rejection_report=mcp,
            seccomp_profile=baseline_artifacts["seccomp_profile"],
            wheel_path=baseline_artifacts["wheel_path"],
            repo_root=REPO_ROOT,
        )


# ---------------------------------------------------------------------------
# 4. Material Recomputation & Cross-Commit Wheel Origin (`F-08`)
# ---------------------------------------------------------------------------


def test_verify_pr1_gov1_convergence_rejects_consistent_json_with_bad_seccomp_or_tampered_wheel(
    tmp_path: Path,
    baseline_artifacts: dict[str, Any],
) -> None:
    # (a1) JSON-consistent candidate bundle where seccomp_profile permits forbidden 'socket'
    bad_seccomp = copy.deepcopy(baseline_artifacts["seccomp_profile"])
    bad_seccomp["syscalls"][0]["names"] = sorted(
        [*bad_seccomp["syscalls"][0]["names"], "socket"]
    )
    forged_sbx = copy.deepcopy(baseline_artifacts["sandbox_cand"])
    forged_sbx["payload"]["seccomp_profile_digest"] = json_digest(bad_seccomp)
    forged_sbx = _recompute_candidate_digest(forged_sbx)
    forged_mcp = copy.deepcopy(baseline_artifacts["mcp_cand"])
    forged_mcp["payload"]["sealed_sandbox_profile_candidate_ref"] = (
        gov1_sandbox.build_local_candidate_ref(forged_sbx)
    )
    forged_mcp = _recompute_candidate_digest(forged_mcp)

    with pytest.raises(ValueError, match="socket|denied"):
        gov1_convergence.verify_pr1_gov1_convergence(
            sandbox_profile=forged_sbx,
            wheel_provenance=baseline_artifacts["prov_cand"],
            wheel_boundary_report=baseline_artifacts["boundary_cand"],
            mcp_rejection_report=forged_mcp,
            seccomp_profile=bad_seccomp,
            wheel_path=baseline_artifacts["wheel_path"],
            repo_root=REPO_ROOT,
        )

    # (a2) Corrupted wheel_path on disk diverges from declared wheel_digest / sorted_record_entries
    bad_wheel = tmp_path / "corrupted.whl"
    bad_wheel.write_bytes(baseline_artifacts["wheel_bytes"] + b"extra")
    with pytest.raises(ValueError):
        gov1_convergence.verify_pr1_gov1_convergence(
            sandbox_profile=baseline_artifacts["sandbox_cand"],
            wheel_provenance=baseline_artifacts["prov_cand"],
            wheel_boundary_report=baseline_artifacts["boundary_cand"],
            mcp_rejection_report=baseline_artifacts["mcp_cand"],
            seccomp_profile=baseline_artifacts["seccomp_profile"],
            wheel_path=bad_wheel,
            repo_root=REPO_ROOT,
        )


def test_verify_pr1_gov1_convergence_rejects_docstring_modified_wheel_claiming_original_commit_f08(
    tmp_path: Path,
    baseline_artifacts: dict[str, Any],
) -> None:
    repo = _init_temp_git_repo(tmp_path / "temp_repo")
    snap_a = gov1_wheel.materialize_git_build_snapshot(repo, commit_ref="HEAD")

    # Commit B modifies ONLY a docstring in src/smart_ads/__init__.py so schema_bundle_digest,
    # packaged_modules, AST boundary scan, and all 11 MCP cases remain 100% identical!
    init_py = repo / "src" / "smart_ads" / "__init__.py"
    original_init = init_py.read_text(encoding="utf-8")
    assert "(ADR-0001)." in original_init
    init_py.write_text(
        original_init.replace(
            "(ADR-0001).", "(ADR-0001 — modified docstring in commit B).", 1
        ),
        encoding="utf-8",
    )
    run_git_offline(repo, "add", "src/smart_ads/__init__.py")
    run_git_offline(repo, "commit", "-q", "-m", "commit B docstring change")

    wheel_b_path, snap_b = gov1_wheel.build_reproducible_wheel(
        repo, tmp_path / "wheel_b_out", commit_ref="HEAD"
    )
    wheel_b_bytes = wheel_b_path.read_bytes()
    assert snap_b.commit_sha != snap_a.commit_sha

    insp_b = gov1_wheel.inspect_wheel_boundary(wheel_b_path)
    exec_b = gov1_mcp.execute_mcp_rejection_matrix_on_wheel(wheel_b_path)
    assert insp_b["schema_bundle_digest"] == compute_schema_bundle_digest()

    # Build provenance claiming Commit A (snap_a) while binding Wheel B's bytes & digest
    forged_prov = gov1_wheel.build_wheel_build_provenance_candidate(
        migration_run_context_locator=RUN_CONTEXT_LOCATOR,
        build_run_id=BUILD_RUN_ID,
        built_at_utc=BUILT_AT_UTC,
        snapshot=snap_a,
        source_date_epoch=gov1_wheel.DEFAULT_SOURCE_DATE_EPOCH,
        schema_bundle_digest=insp_b["schema_bundle_digest"],
        wheel_bytes=wheel_b_bytes,
    )
    forged_prov_ref = gov1_sandbox.build_local_candidate_ref(forged_prov)
    bound_b = gov1_wheel.build_wheel_boundary_report_candidate(
        migration_run_context_locator=RUN_CONTEXT_LOCATOR,
        build_run_id=BUILD_RUN_ID,
        verified_at_utc=VERIFIED_AT_UTC,
        source_commit_sha=snap_a.commit_sha,
        build_backend_digest=snap_a.build_backend_digest,
        wheel_build_provenance_candidate_ref=forged_prov_ref,
        inspection=insp_b,
    )
    mcp_b = gov1_mcp.build_mcp_rejection_matrix_report_candidate(
        migration_run_context_locator=RUN_CONTEXT_LOCATOR,
        build_run_id=BUILD_RUN_ID,
        executed_at_utc=EXECUTED_AT_UTC,
        source_commit_sha=snap_a.commit_sha,
        build_backend_digest=snap_a.build_backend_digest,
        sealed_sandbox_profile_candidate_ref=baseline_artifacts["sandbox_cand_ref"],
        execution=exec_b,
    )

    with pytest.raises(ValueError, match="provenance|mismatch|rebuilt"):
        gov1_convergence.verify_pr1_gov1_convergence(
            sandbox_profile=baseline_artifacts["sandbox_cand"],
            wheel_provenance=forged_prov,
            wheel_boundary_report=bound_b,
            mcp_rejection_report=mcp_b,
            seccomp_profile=baseline_artifacts["seccomp_profile"],
            wheel_path=wheel_b_path,
            repo_root=repo,
        )


# ---------------------------------------------------------------------------
# 5. Etapa 11 (`gov1_convergence_record/v1`) — Fail-Closed Block in Etapa 8 (`F-09`)
# ---------------------------------------------------------------------------


def test_etapa11_gov1_convergence_record_fails_closed_in_etapa8_f09(
    tmp_path: Path,
    baseline_artifacts: dict[str, Any],
    synthetic_gov1_keys: dict[str, tuple[Path, bytes, str]],
) -> None:
    world = Gov1D4World(tmp_path, synthetic_gov1_keys, baseline_artifacts)
    snapshot: gov1_wheel.GitBuildSnapshot = baseline_artifacts["snapshot"]
    neg_loc = make_locator(
        gov1_convergence.NEGATIVE_SECURITY_SCHEMA, b'{"neg":"pr3-pending"}'
    )
    cert7a_loc = make_locator(
        gov1_convergence.CERTIFICATION_7A_SCHEMA, b'{"cert":"pr3-pending"}'
    )

    valid_builder_kwargs: dict[str, Any] = {
        "migration_run_context_locator": RUN_CONTEXT_LOCATOR,
        "wheel_boundary_report_locator": world.boundary_loc,
        "sealed_sandbox_profile_locator": world.sandbox_loc,
        "negative_security_test_report_locator": neg_loc,
        "mcp_rejection_matrix_report_locator": world.mcp_loc,
        "certification_7a_record_locator": cert7a_loc,
        "build_run_id": BUILD_RUN_ID,
        "converged_at_utc": CONVERGED_AT_UTC,
        "source_commit_sha": snapshot.commit_sha,
        "wheel_digest": digest(baseline_artifacts["wheel_bytes"]),
        "build_backend_digest": snapshot.build_backend_digest,
        "schema_bundle_digest": baseline_artifacts["inspection"]["schema_bundle_digest"],
        "registry_locator": world.registry_loc,
        "signer_key_id": synthetic_gov1_keys["gov1_convergence_verifier"][2],
    }

    # 1. Even with all 6 syntactically valid typed locators, Etapa 8 (`pr3_verifier=None`) MUST fail closed
    with pytest.raises(ValueError, match="fail-closed|PR 3|pr3_verifier"):
        gov1_convergence.build_gov1_convergence_record_envelope(
            **valid_builder_kwargs,
            pr3_verifier=None,
        )

    # 2. Missing / None / bare digest / wrong artifact_type on 7A locators also fail closed
    for bad_override in (
        {"negative_security_test_report_locator": None},
        {"certification_7a_record_locator": None},
        {"negative_security_test_report_locator": "sha256:" + ("a" * 64)},
        {"certification_7a_record_locator": world.sandbox_loc},
        {"wheel_digest": "sha256:" + ("0" * 64)},
        {"converged_at_utc": "2026-09-07T10:00:14Z"},  # backdated before MCP executed_at_utc
    ):
        bad_kwargs = {**valid_builder_kwargs, **bad_override, "store": world.store}
        with pytest.raises(ValueError):
            gov1_convergence.build_gov1_convergence_record_envelope(**bad_kwargs)

    # 3. Hand-craft a signed P1 gov1_convergence_record/v1 envelope with all 15 closed fields
    # and store it; both verify_gov1_convergence_record and Gov1AdmissionVerifier MUST fail closed!
    raw_conv_unsigned = {
        "$schema": gov1_convergence.GOV1_CONVERGENCE_SCHEMA,
        "migration_run_context_locator": RUN_CONTEXT_LOCATOR,
        "wheel_boundary_report_locator": world.boundary_loc,
        "sealed_sandbox_profile_locator": world.sandbox_loc,
        "negative_security_test_report_locator": neg_loc,
        "mcp_rejection_matrix_report_locator": world.mcp_loc,
        "certification_7a_record_locator": cert7a_loc,
        "build_run_id": BUILD_RUN_ID,
        "converged_at_utc": CONVERGED_AT_UTC,
        "source_commit_sha": snapshot.commit_sha,
        "wheel_digest": digest(baseline_artifacts["wheel_bytes"]),
        "build_backend_digest": snapshot.build_backend_digest,
        "schema_bundle_digest": baseline_artifacts["inspection"]["schema_bundle_digest"],
        "convergence_status": "PASS",
        "integrity": {
            "key_id": synthetic_gov1_keys["gov1_convergence_verifier"][2],
            "key_registry_snapshot_locator": world.registry_loc,
        },
    }
    conv_signed = p1.sign_envelope(
        raw_conv_unsigned,
        world.profiles[gov1_convergence.GOV1_CONVERGENCE_SCHEMA]["domain_prefix"],
        synthetic_gov1_keys["gov1_convergence_verifier"][0],
    )
    conv_loc = world.store.put(conv_signed)

    with pytest.raises(ValueError, match="fail-closed|PR 3|pr3_verifier"):
        gov1_convergence.verify_gov1_convergence_record(
            conv_signed, store=world.store, pr3_verifier=None
        )

    # Also test a rejecting Pr3SevenAConstituentVerifier implementation
    class _RejectingPr3Verifier:
        def verify_7a_constituents(self, **kwargs: Any) -> dict[str, Any]:
            return {"certified": False}

    assert isinstance(
        _RejectingPr3Verifier(), gov1_convergence.Pr3SevenAConstituentVerifier
    )
    with pytest.raises(ValueError):
        gov1_convergence.verify_gov1_convergence_record(
            conv_signed,
            store=world.store,
            pr3_verifier=_RejectingPr3Verifier(),
        )

    verifier = world.make_verifier()
    with pytest.raises(ValueError, match="fail-closed|PR 3|pr3_verifier"):
        verifier.verify_artifact(conv_loc)
    assert world.runtime.cas_calls == 0


# ---------------------------------------------------------------------------
# 6. `Gov1AdmissionVerifier` (D4 `ProtectedRuntime`) over Etapa 7 Envelopes
# ---------------------------------------------------------------------------


def test_gov1_admission_verifier_admits_signed_etapa7_bundle_and_passes_convergence_gate(
    tmp_path: Path,
    baseline_artifacts: dict[str, Any],
    synthetic_gov1_keys: dict[str, tuple[Path, bytes, str]],
) -> None:
    world = Gov1D4World(tmp_path, synthetic_gov1_keys, baseline_artifacts)
    verifier = world.make_verifier()

    receipt = gov1_convergence.verify_pr1_gov1_convergence(
        sandbox_profile=world.sandbox_env,
        wheel_provenance=world.prov_env,
        wheel_boundary_report=world.boundary_env,
        mcp_rejection_report=world.mcp_env,
        seccomp_profile=baseline_artifacts["seccomp_profile"],
        wheel_path=baseline_artifacts["wheel_path"],
        repo_root=REPO_ROOT,
        admission_verifier=verifier,
        store=world.store,
    )
    assert receipt["gate_status"] == "PASS"
    assert receipt["mode"] == "envelope"
    assert receipt["final_gov1_convergence_emitted"] is False
    assert receipt["signable"] is False
    assert receipt["authority"] == "none"
    assert world.runtime.floor.epoch == 1
    assert world.runtime.cas_calls == 1

    # Individual D4 verification on sealed_sandbox_profile also succeeds and advances CAS version
    sbx_ver = verifier.verify_artifact(
        world.sandbox_loc,
        seccomp_profile=baseline_artifacts["seccomp_profile"],
    )
    assert sbx_ver["verification_status"] == "VERIFIED"
    assert sbx_ver["schema"] == gov1_sandbox.SANDBOX_PROFILE_SCHEMA
    assert sbx_ver["effect_authorized"] is False
    assert world.runtime.cas_calls == 2


@pytest.mark.parametrize(
    ("counterexample", "expected_match"),
    [
        ("wrong_role_in_registry", "signer role mismatch"),
        ("withdrawn_action_in_current_state", "action withdrawn"),
        ("revoked_key_in_current_state", "authority key currently revoked or expired"),
        ("expired_sandbox_validity_window", "outside validity interval"),
        ("future_built_at_timestamp", "timestamp in future relative to authenticated clock"),
        ("wrong_signature_domain", "signature verification failed"),
        ("cas_conflict", "protected CAS conflict"),
        ("head_advanced_during_final_observation", "head advanced after validation"),
        ("clock_reversed_during_final_observation", "authenticated clock moved backwards"),
        ("sandbox_expired_at_final_clock", "outside validity interval"),
    ],
)
def test_gov1_admission_verifier_rejects_d4_counterexamples_fail_closed(
    tmp_path: Path,
    baseline_artifacts: dict[str, Any],
    synthetic_gov1_keys: dict[str, tuple[Path, bytes, str]],
    counterexample: str,
    expected_match: str,
) -> None:
    if counterexample == "wrong_role_in_registry":
        world = Gov1D4World(
            tmp_path,
            synthetic_gov1_keys,
            baseline_artifacts,
            registry_mutation=lambda reg: reg["entries"][4].update(
                role="security_owner"
            ),
        )
    elif counterexample == "expired_sandbox_validity_window":
        world = Gov1D4World(
            tmp_path,
            synthetic_gov1_keys,
            baseline_artifacts,
            sandbox_validity={
                "from": "2026-01-01T00:00:00Z",
                "until": "2026-09-07T10:00:18Z",
            },
        )
    elif counterexample == "future_built_at_timestamp":
        world = Gov1D4World(
            tmp_path,
            synthetic_gov1_keys,
            baseline_artifacts,
            built_at_utc="2026-09-07T10:00:25Z",
        )
    else:
        world = Gov1D4World(tmp_path, synthetic_gov1_keys, baseline_artifacts)

    if counterexample == "withdrawn_action_in_current_state":
        world.advance_current_registry(
            lambda reg: reg["entries"][4].update(allowed_actions=[])
        )
    elif counterexample == "revoked_key_in_current_state":
        world.advance_current_registry(
            lambda reg: reg["entries"][1].update(lifecycle_state="revoked")
        )
    elif counterexample == "wrong_signature_domain":
        wrong_sbx = p1.sign_envelope(
            world.sandbox_env,
            "SMART-ADS:WRONG-DOMAIN:V1\n",
            synthetic_gov1_keys["security_owner"][0],
        )
        world.sandbox_env = wrong_sbx
        world.sandbox_loc = world.store.put(wrong_sbx)
        updated_mcp = copy.deepcopy(world.mcp_env)
        updated_mcp["sealed_sandbox_profile_locator"] = world.sandbox_loc
        world.mcp_env = p1.sign_envelope(
            updated_mcp,
            world.profiles[gov1_mcp.MCP_REJECTION_REPORT_SCHEMA]["domain_prefix"],
            synthetic_gov1_keys["security_verifier"][0],
        )
        world.mcp_loc = world.store.put(world.mcp_env)
    elif counterexample == "cas_conflict":
        world.runtime.conflict = True
    elif counterexample == "head_advanced_during_final_observation":
        world.runtime.after_cas_head = make_locator(HEAD, b'{"new":"head"}')
    elif counterexample == "clock_reversed_during_final_observation":
        world.runtime.after_cas_clock = ClockInterval(
            "2026-09-07T10:00:19Z", "2026-09-07T10:00:19Z"
        )
    elif counterexample == "sandbox_expired_at_final_clock":
        world = Gov1D4World(
            tmp_path / "exp_after_cas",
            synthetic_gov1_keys,
            baseline_artifacts,
            sandbox_validity={
                "from": "2026-01-01T00:00:00Z",
                "until": "2026-09-07T10:01:00Z",
            },
        )
        world.runtime.after_cas_clock = ClockInterval(
            "2026-09-07T10:01:00Z", "2026-09-07T10:01:00Z"
        )

    verifier = world.make_verifier()
    with pytest.raises(ValueError, match=expected_match):
        gov1_convergence.verify_pr1_gov1_convergence(
            sandbox_profile=world.sandbox_env,
            wheel_provenance=world.prov_env,
            wheel_boundary_report=world.boundary_env,
            mcp_rejection_report=world.mcp_env,
            seccomp_profile=baseline_artifacts["seccomp_profile"],
            wheel_path=baseline_artifacts["wheel_path"],
            repo_root=REPO_ROOT,
            admission_verifier=verifier,
            store=world.store,
        )

    if counterexample in {
        "wrong_role_in_registry",
        "withdrawn_action_in_current_state",
        "revoked_key_in_current_state",
        "expired_sandbox_validity_window",
        "future_built_at_timestamp",
        "wrong_signature_domain",
    }:
        assert world.runtime.cas_calls == 0
    elif counterexample == "cas_conflict":
        assert world.runtime.floor.epoch == 0


def test_gov1_admission_verifier_rejects_malformed_signed_envelopes_with_value_error_not_key_error(
    tmp_path: Path,
    baseline_artifacts: dict[str, Any],
    synthetic_gov1_keys: dict[str, tuple[Path, bytes, str]],
) -> None:
    world = Gov1D4World(tmp_path, synthetic_gov1_keys, baseline_artifacts)
    verifier = world.make_verifier()

    # 1. Signed sandbox envelope missing "validity" -> must raise ValueError, never KeyError
    bad_sbx = copy.deepcopy(world.sandbox_env)
    del bad_sbx["validity"]
    bad_sbx = p1.sign_envelope(
        bad_sbx,
        world.profiles[gov1_sandbox.SANDBOX_PROFILE_SCHEMA]["domain_prefix"],
        synthetic_gov1_keys["security_owner"][0],
    )
    bad_sbx_loc = world.store.put(bad_sbx)
    with pytest.raises(ValueError):
        verifier.verify_artifact(
            bad_sbx_loc,
            seccomp_profile=baseline_artifacts["seccomp_profile"],
        )
    with pytest.raises(ValueError):
        verifier.admit_etapa7_bundle(
            sandbox_profile_locator=bad_sbx_loc,
            wheel_provenance_locator=world.prov_loc,
            wheel_boundary_report_locator=world.boundary_loc,
            mcp_rejection_report_locator=world.mcp_loc,
            seccomp_profile=baseline_artifacts["seccomp_profile"],
            wheel_path=baseline_artifacts["wheel_path"],
            repo_root=REPO_ROOT,
        )

    # 2. Signed wheel_boundary_report missing "wheel_build_provenance_locator" -> ValueError, never KeyError
    bad_bound = copy.deepcopy(world.boundary_env)
    del bad_bound["wheel_build_provenance_locator"]
    bad_bound = p1.sign_envelope(
        bad_bound,
        world.profiles[gov1_wheel.WHEEL_BOUNDARY_REPORT_SCHEMA]["domain_prefix"],
        synthetic_gov1_keys["build_boundary_verifier"][0],
    )
    bad_bound_loc = world.store.put(bad_bound)
    with pytest.raises(ValueError):
        verifier.verify_artifact(
            bad_bound_loc,
            wheel_path=baseline_artifacts["wheel_path"],
            repo_root=REPO_ROOT,
        )

    # 3. Signed mcp_rejection_matrix_report missing "sealed_sandbox_profile_locator" -> ValueError, never KeyError
    bad_mcp = copy.deepcopy(world.mcp_env)
    del bad_mcp["sealed_sandbox_profile_locator"]
    bad_mcp = p1.sign_envelope(
        bad_mcp,
        world.profiles[gov1_mcp.MCP_REJECTION_REPORT_SCHEMA]["domain_prefix"],
        synthetic_gov1_keys["security_verifier"][0],
    )
    bad_mcp_loc = world.store.put(bad_mcp)
    with pytest.raises(ValueError):
        verifier.verify_artifact(
            bad_mcp_loc,
            wheel_path=baseline_artifacts["wheel_path"],
            seccomp_profile=baseline_artifacts["seccomp_profile"],
        )

    # 4. Boundary report referencing a signed provenance envelope missing "migration_run_context_locator"
    # or having built_at_utc > verified_at_utc -> ValueError, never KeyError
    bad_prov_missing_ctx = copy.deepcopy(world.prov_env)
    del bad_prov_missing_ctx["migration_run_context_locator"]
    bad_prov_missing_ctx = p1.sign_envelope(
        bad_prov_missing_ctx,
        world.profiles[gov1_wheel.WHEEL_BUILD_PROVENANCE_SCHEMA]["domain_prefix"],
        synthetic_gov1_keys["build_provenance_verifier"][0],
    )
    bad_prov_loc = world.store.put(bad_prov_missing_ctx)
    bound_ref_bad_prov = copy.deepcopy(world.boundary_env)
    bound_ref_bad_prov["wheel_build_provenance_locator"] = bad_prov_loc
    bound_ref_bad_prov = p1.sign_envelope(
        bound_ref_bad_prov,
        world.profiles[gov1_wheel.WHEEL_BOUNDARY_REPORT_SCHEMA]["domain_prefix"],
        synthetic_gov1_keys["build_boundary_verifier"][0],
    )
    bound_ref_bad_prov_loc = world.store.put(bound_ref_bad_prov)
    with pytest.raises(ValueError):
        verifier.verify_artifact(
            bound_ref_bad_prov_loc,
            wheel_path=baseline_artifacts["wheel_path"],
            repo_root=REPO_ROOT,
        )

    prov_after_verify = copy.deepcopy(world.prov_env)
    prov_after_verify["built_at_utc"] = "2026-09-07T10:00:12Z"  # > VERIFIED_AT_UTC (10:00:10Z)
    prov_after_verify = p1.sign_envelope(
        prov_after_verify,
        world.profiles[gov1_wheel.WHEEL_BUILD_PROVENANCE_SCHEMA]["domain_prefix"],
        synthetic_gov1_keys["build_provenance_verifier"][0],
    )
    prov_after_verify_loc = world.store.put(prov_after_verify)
    bound_backdated = copy.deepcopy(world.boundary_env)
    bound_backdated["wheel_build_provenance_locator"] = prov_after_verify_loc
    bound_backdated = p1.sign_envelope(
        bound_backdated,
        world.profiles[gov1_wheel.WHEEL_BOUNDARY_REPORT_SCHEMA]["domain_prefix"],
        synthetic_gov1_keys["build_boundary_verifier"][0],
    )
    bound_backdated_loc = world.store.put(bound_backdated)
    with pytest.raises(ValueError):
        verifier.verify_artifact(
            bound_backdated_loc,
            wheel_path=baseline_artifacts["wheel_path"],
            repo_root=REPO_ROOT,
        )

    # 5. MCP report referencing a signed sandbox envelope whose issued_at_utc >= validity.until
    bad_sbx_issuance = copy.deepcopy(world.sandbox_env)
    bad_sbx_issuance["validity"] = {
        "from": "2026-01-01T00:00:00Z",
        "until": "2026-09-07T09:59:00Z",
    }
    bad_sbx_issuance = p1.sign_envelope(
        bad_sbx_issuance,
        world.profiles[gov1_sandbox.SANDBOX_PROFILE_SCHEMA]["domain_prefix"],
        synthetic_gov1_keys["security_owner"][0],
    )
    bad_sbx_issuance_loc = world.store.put(bad_sbx_issuance)
    mcp_ref_bad_sbx = copy.deepcopy(world.mcp_env)
    mcp_ref_bad_sbx["sealed_sandbox_profile_locator"] = bad_sbx_issuance_loc
    mcp_ref_bad_sbx = p1.sign_envelope(
        mcp_ref_bad_sbx,
        world.profiles[gov1_mcp.MCP_REJECTION_REPORT_SCHEMA]["domain_prefix"],
        synthetic_gov1_keys["security_verifier"][0],
    )
    mcp_ref_bad_sbx_loc = world.store.put(mcp_ref_bad_sbx)
    with pytest.raises(ValueError):
        verifier.verify_artifact(
            mcp_ref_bad_sbx_loc,
            wheel_path=baseline_artifacts["wheel_path"],
            seccomp_profile=baseline_artifacts["seccomp_profile"],
        )

    # 6. Missing required material inputs in Gov1AdmissionVerifier.verify_artifact fail closed
    with pytest.raises(ValueError, match="seccomp_profile"):
        verifier.verify_artifact(world.sandbox_loc, seccomp_profile=None)
    with pytest.raises(ValueError, match="wheel_path"):
        verifier.verify_artifact(
            world.prov_loc, wheel_path=None, repo_root=REPO_ROOT
        )
    with pytest.raises(ValueError, match="repo_root"):
        verifier.verify_artifact(
            world.prov_loc,
            wheel_path=baseline_artifacts["wheel_path"],
            repo_root=None,
        )
    with pytest.raises(ValueError, match="wheel_path"):
        verifier.verify_artifact(
            world.boundary_loc, wheel_path=None, repo_root=REPO_ROOT
        )
    with pytest.raises(ValueError, match="repo_root"):
        verifier.verify_artifact(
            world.boundary_loc,
            wheel_path=baseline_artifacts["wheel_path"],
            repo_root=None,
        )
    with pytest.raises(ValueError, match="wheel_path"):
        verifier.verify_artifact(
            world.mcp_loc,
            wheel_path=None,
            seccomp_profile=baseline_artifacts["seccomp_profile"],
        )
    with pytest.raises(ValueError, match="seccomp_profile"):
        verifier.verify_artifact(
            world.mcp_loc,
            wheel_path=baseline_artifacts["wheel_path"],
            seccomp_profile=None,
        )

    assert world.runtime.cas_calls == 0


def _rebind_signed_7a_constituents(
    world: Gov1D4World,
    keys: dict[str, tuple[Path, bytes, str]],
    *,
    sandbox_loc: dict[str, Any] | None = None,
    boundary_loc: dict[str, Any] | None = None,
    mcp_loc: dict[str, Any] | None = None,
    neg_executed_at_utc: str = EXECUTED_AT_UTC,
    certified_at_utc: str = EXECUTED_AT_UTC,
) -> tuple[dict[str, Any], dict[str, Any]]:
    eff_sbx_loc = sandbox_loc if sandbox_loc is not None else world.sandbox_loc
    eff_bound_loc = boundary_loc if boundary_loc is not None else world.boundary_loc
    eff_mcp_loc = mcp_loc if mcp_loc is not None else world.mcp_loc

    neg_env = copy.deepcopy(world.neg_env)
    neg_env["sealed_sandbox_profile_locator"] = eff_sbx_loc
    neg_env["executed_at_utc"] = neg_executed_at_utc
    neg_env["integrity"] = {
        "key_id": keys["7a_verifier"][2],
        "key_registry_snapshot_locator": world.registry_loc,
    }
    neg_signed = p1.sign_envelope(
        neg_env,
        world.profiles[gov1_convergence.NEGATIVE_SECURITY_SCHEMA]["domain_prefix"],
        keys["7a_verifier"][0],
    )
    neg_loc = world.store.put(neg_signed)

    cert7a_env = copy.deepcopy(world.cert7a_env)
    cert7a_env["sealed_sandbox_profile_locator"] = eff_sbx_loc
    cert7a_env["negative_security_test_report_locator"] = neg_loc
    cert7a_env["wheel_boundary_report_locator"] = eff_bound_loc
    cert7a_env["mcp_rejection_matrix_report_locator"] = eff_mcp_loc
    cert7a_env["certified_at_utc"] = certified_at_utc
    cert7a_env["integrity"] = {
        "key_id": keys["independent_7a_verifier"][2],
        "key_registry_snapshot_locator": world.registry_loc,
    }
    cert7a_signed = p1.sign_envelope(
        cert7a_env,
        world.profiles[gov1_convergence.CERTIFICATION_7A_SCHEMA]["domain_prefix"],
        keys["independent_7a_verifier"][0],
    )
    cert7a_loc = world.store.put(cert7a_signed)
    return neg_loc, cert7a_loc


def test_etapa11_certified_pr3_verifier_enforces_store_constituent_linkage_and_d4_authority(
    tmp_path: Path,
    baseline_artifacts: dict[str, Any],
    synthetic_gov1_keys: dict[str, tuple[Path, bytes, str]],
) -> None:
    world = Gov1D4World(tmp_path, synthetic_gov1_keys, baseline_artifacts)
    snapshot: gov1_wheel.GitBuildSnapshot = baseline_artifacts["snapshot"]
    neg_loc = world.neg_loc
    cert7a_loc = world.cert7a_loc

    class _CertifiedPr3Verifier:
        def verify_7a_constituents(self, **kwargs: Any) -> dict[str, Any]:
            return {
                "certified": True,
                "negative_cases": list(
                    gov1_convergence.MANDATORY_7A_NEGATIVE_SECURITY_CASES
                ),
                "negative_executed_at_utc": EXECUTED_AT_UTC,
                "certified_at_utc": EXECUTED_AT_UTC,
            }

    pr3_ok = _CertifiedPr3Verifier()
    assert isinstance(pr3_ok, gov1_convergence.Pr3SevenAConstituentVerifier)

    base_kwargs: dict[str, Any] = {
        "migration_run_context_locator": RUN_CONTEXT_LOCATOR,
        "wheel_boundary_report_locator": world.boundary_loc,
        "sealed_sandbox_profile_locator": world.sandbox_loc,
        "negative_security_test_report_locator": neg_loc,
        "mcp_rejection_matrix_report_locator": world.mcp_loc,
        "certification_7a_record_locator": cert7a_loc,
        "build_run_id": BUILD_RUN_ID,
        "converged_at_utc": CONVERGED_AT_UTC,
        "source_commit_sha": snapshot.commit_sha,
        "wheel_digest": digest(baseline_artifacts["wheel_bytes"]),
        "build_backend_digest": snapshot.build_backend_digest,
        "schema_bundle_digest": baseline_artifacts["inspection"]["schema_bundle_digest"],
        "registry_locator": world.registry_loc,
        "signer_key_id": synthetic_gov1_keys["gov1_convergence_verifier"][2],
    }

    # 1. Calling build or verify with pr3_verifier!=None but store=None MUST fail closed
    with pytest.raises(ValueError, match="Store|store"):
        gov1_convergence.build_gov1_convergence_record_envelope(
            **base_kwargs,
            store=None,
            pr3_verifier=pr3_ok,
        )

    conv_unsigned = gov1_convergence.build_gov1_convergence_record_envelope(
        **base_kwargs,
        store=world.store,
        pr3_verifier=pr3_ok,
    )
    conv_signed = p1.sign_envelope(
        conv_unsigned,
        world.profiles[gov1_convergence.GOV1_CONVERGENCE_SCHEMA]["domain_prefix"],
        synthetic_gov1_keys["gov1_convergence_verifier"][0],
    )
    conv_loc = world.store.put(conv_signed)

    with pytest.raises(ValueError, match="Store|store"):
        gov1_convergence.verify_gov1_convergence_record(
            conv_signed,
            store=None,
            seccomp_profile=baseline_artifacts["seccomp_profile"],
            wheel_path=baseline_artifacts["wheel_path"],
            repo_root=REPO_ROOT,
            pr3_verifier=pr3_ok,
        )

    # 2. Transitive provenance mismatch (boundary -> provenance with mismatched source_commit_sha)
    bad_prov = copy.deepcopy(world.prov_env)
    bad_prov["source_commit_sha"] = "f" * 40
    bad_prov = p1.sign_envelope(
        bad_prov,
        world.profiles[gov1_wheel.WHEEL_BUILD_PROVENANCE_SCHEMA]["domain_prefix"],
        synthetic_gov1_keys["build_provenance_verifier"][0],
    )
    bad_prov_loc = world.store.put(bad_prov)
    bound_with_bad_prov = copy.deepcopy(world.boundary_env)
    bound_with_bad_prov["wheel_build_provenance_locator"] = bad_prov_loc
    bound_with_bad_prov = p1.sign_envelope(
        bound_with_bad_prov,
        world.profiles[gov1_wheel.WHEEL_BOUNDARY_REPORT_SCHEMA]["domain_prefix"],
        synthetic_gov1_keys["build_boundary_verifier"][0],
    )
    bound_with_bad_prov_loc = world.store.put(bound_with_bad_prov)
    rebound_neg_loc, rebound_cert7a_loc = _rebind_signed_7a_constituents(
        world,
        synthetic_gov1_keys,
        boundary_loc=bound_with_bad_prov_loc,
    )
    with pytest.raises(ValueError, match="source_commit_sha|provenance"):
        gov1_convergence.build_gov1_convergence_record_envelope(
            **{
                **base_kwargs,
                "wheel_boundary_report_locator": bound_with_bad_prov_loc,
                "negative_security_test_report_locator": rebound_neg_loc,
                "certification_7a_record_locator": rebound_cert7a_loc,
            },
            store=world.store,
            pr3_verifier=pr3_ok,
        )

    # 3. MCP executed_at_utc outside sandbox validity window in Store
    narrow_sbx = gov1_sandbox.build_sealed_sandbox_profile_envelope(
        migration_run_context_locator=RUN_CONTEXT_LOCATOR,
        oci_image_digest=OCI_IMAGE_DIGEST,
        runner_binary_digest=RUNNER_BINARY_DIGEST,
        seccomp_profile=baseline_artifacts["seccomp_profile"],
        issued_at_utc="2026-09-07T10:00:00Z",
        valid_from_utc="2026-09-07T10:00:00Z",
        valid_until_utc="2026-09-07T10:00:10Z",  # expires BEFORE EXECUTED_AT_UTC (10:00:15Z)
        registry_locator=world.registry_loc,
        signer_key_id=synthetic_gov1_keys["security_owner"][2],
    )
    narrow_sbx = p1.sign_envelope(
        narrow_sbx,
        world.profiles[gov1_sandbox.SANDBOX_PROFILE_SCHEMA]["domain_prefix"],
        synthetic_gov1_keys["security_owner"][0],
    )
    narrow_sbx_loc = world.store.put(narrow_sbx)
    mcp_outside_sbx = copy.deepcopy(world.mcp_env)
    mcp_outside_sbx["sealed_sandbox_profile_locator"] = narrow_sbx_loc
    mcp_outside_sbx = p1.sign_envelope(
        mcp_outside_sbx,
        world.profiles[gov1_mcp.MCP_REJECTION_REPORT_SCHEMA]["domain_prefix"],
        synthetic_gov1_keys["security_verifier"][0],
    )
    mcp_outside_sbx_loc = world.store.put(mcp_outside_sbx)
    narrow_neg_loc, narrow_cert7a_loc = _rebind_signed_7a_constituents(
        world,
        synthetic_gov1_keys,
        sandbox_loc=narrow_sbx_loc,
        mcp_loc=mcp_outside_sbx_loc,
    )
    with pytest.raises(ValueError, match="validity"):
        gov1_convergence.build_gov1_convergence_record_envelope(
            **{
                **base_kwargs,
                "sealed_sandbox_profile_locator": narrow_sbx_loc,
                "mcp_rejection_matrix_report_locator": mcp_outside_sbx_loc,
                "negative_security_test_report_locator": narrow_neg_loc,
                "certification_7a_record_locator": narrow_cert7a_loc,
            },
            store=world.store,
            pr3_verifier=pr3_ok,
        )

    # Anti-backdating with certified pr3_verifier: converged_at_utc before constituent or PR3 timestamps fails closed
    with pytest.raises(ValueError, match="backdated"):
        gov1_convergence.build_gov1_convergence_record_envelope(
            **{**base_kwargs, "converged_at_utc": "2026-09-07T10:00:04Z"},
            store=world.store,
            pr3_verifier=pr3_ok,
        )
    backdated_conv = copy.deepcopy(conv_signed)
    backdated_conv["converged_at_utc"] = "2026-09-07T10:00:04Z"
    backdated_conv = p1.sign_envelope(
        backdated_conv,
        world.profiles[gov1_convergence.GOV1_CONVERGENCE_SCHEMA]["domain_prefix"],
        synthetic_gov1_keys["gov1_convergence_verifier"][0],
    )
    with pytest.raises(ValueError, match="backdated"):
        gov1_convergence.verify_gov1_convergence_record(
            backdated_conv,
            store=world.store,
            seccomp_profile=baseline_artifacts["seccomp_profile"],
            wheel_path=baseline_artifacts["wheel_path"],
            repo_root=REPO_ROOT,
            pr3_verifier=pr3_ok,
        )

    # 4. Gov1AdmissionVerifier with pr3_verifier!=None requires seccomp_profile, wheel_path, AND repo_root
    verifier_with_pr3 = gov1_convergence.Gov1AdmissionVerifier(
        world.runtime,
        world.pins,
        world.store,
        world.adr,
        inventory_locator=world.inventory_loc,
        pr3_verifier=pr3_ok,
    )
    for missing_kw in (
        {"seccomp_profile": None},
        {"wheel_path": None},
        {"repo_root": None},
    ):
        call_kw: dict[str, Any] = {
            "seccomp_profile": baseline_artifacts["seccomp_profile"],
            "wheel_path": baseline_artifacts["wheel_path"],
            "repo_root": REPO_ROOT,
            **missing_kw,
        }
        with pytest.raises(ValueError):
            verifier_with_pr3.verify_artifact(conv_loc, **call_kw)
    assert world.runtime.cas_calls == 0

    # 5. Gov1AdmissionVerifier with pr3_verifier!=None rejects constituent with wrong D4 signature/role
    wrong_signer_mcp = copy.deepcopy(world.mcp_env)
    wrong_signer_mcp["integrity"]["key_id"] = synthetic_gov1_keys["security_owner"][2]
    wrong_signer_mcp = p1.sign_envelope(
        wrong_signer_mcp,
        world.profiles[gov1_mcp.MCP_REJECTION_REPORT_SCHEMA]["domain_prefix"],
        synthetic_gov1_keys["security_owner"][0],  # security_owner instead of security_verifier!
    )
    wrong_signer_mcp_loc = world.store.put(wrong_signer_mcp)
    ws_neg_loc, ws_cert7a_loc = _rebind_signed_7a_constituents(
        world,
        synthetic_gov1_keys,
        mcp_loc=wrong_signer_mcp_loc,
    )
    conv_bad_constituent_sig = gov1_convergence.build_gov1_convergence_record_envelope(
        **{
            **base_kwargs,
            "mcp_rejection_matrix_report_locator": wrong_signer_mcp_loc,
            "negative_security_test_report_locator": ws_neg_loc,
            "certification_7a_record_locator": ws_cert7a_loc,
        },
        store=world.store,
        pr3_verifier=pr3_ok,
    )
    conv_bad_constituent_sig = p1.sign_envelope(
        conv_bad_constituent_sig,
        world.profiles[gov1_convergence.GOV1_CONVERGENCE_SCHEMA]["domain_prefix"],
        synthetic_gov1_keys["gov1_convergence_verifier"][0],
    )
    conv_bad_constituent_sig_loc = world.store.put(conv_bad_constituent_sig)
    with pytest.raises(ValueError, match="signer role mismatch"):
        verifier_with_pr3.verify_artifact(
            conv_bad_constituent_sig_loc,
            seccomp_profile=baseline_artifacts["seccomp_profile"],
            wheel_path=baseline_artifacts["wheel_path"],
            repo_root=REPO_ROOT,
        )
    assert world.runtime.cas_calls == 0

    # 6. Positive control: valid D4 signatures on all 6 constituents + material inputs + certified pr3_verifier
    admitted_conv = verifier_with_pr3.verify_artifact(
        conv_loc,
        seccomp_profile=baseline_artifacts["seccomp_profile"],
        wheel_path=baseline_artifacts["wheel_path"],
        repo_root=REPO_ROOT,
    )
    assert admitted_conv["verification_status"] == "VERIFIED"
    assert admitted_conv["schema"] == gov1_convergence.GOV1_CONVERGENCE_SCHEMA
    assert world.runtime.cas_calls == 1


# ---------------------------------------------------------------------------
# 7. Final Max-Review Regression Tests (`shallow-004`, `deep-1-001..003`, `history-001..002`)
# ---------------------------------------------------------------------------


def test_shallow004_rejects_unsigned_store_constituents_and_unsigned_top_level_convergence_envelope(
    tmp_path: Path,
    baseline_artifacts: dict[str, Any],
    synthetic_gov1_keys: dict[str, tuple[Path, bytes, str]],
) -> None:
    world = Gov1D4World(tmp_path, synthetic_gov1_keys, baseline_artifacts)
    snapshot: gov1_wheel.GitBuildSnapshot = baseline_artifacts["snapshot"]

    class _CertifiedPr3Verifier:
        def verify_7a_constituents(self, **kwargs: Any) -> dict[str, Any]:
            return {
                "certified": True,
                "negative_cases": list(
                    gov1_convergence.MANDATORY_7A_NEGATIVE_SECURITY_CASES
                ),
                "negative_executed_at_utc": EXECUTED_AT_UTC,
                "certified_at_utc": EXECUTED_AT_UTC,
            }

    pr3_ok = _CertifiedPr3Verifier()
    base_kwargs: dict[str, Any] = {
        "migration_run_context_locator": RUN_CONTEXT_LOCATOR,
        "wheel_boundary_report_locator": world.boundary_loc,
        "sealed_sandbox_profile_locator": world.sandbox_loc,
        "negative_security_test_report_locator": world.neg_loc,
        "mcp_rejection_matrix_report_locator": world.mcp_loc,
        "certification_7a_record_locator": world.cert7a_loc,
        "build_run_id": BUILD_RUN_ID,
        "converged_at_utc": CONVERGED_AT_UTC,
        "source_commit_sha": snapshot.commit_sha,
        "wheel_digest": digest(baseline_artifacts["wheel_bytes"]),
        "build_backend_digest": snapshot.build_backend_digest,
        "schema_bundle_digest": baseline_artifacts["inspection"]["schema_bundle_digest"],
        "registry_locator": world.registry_loc,
        "signer_key_id": synthetic_gov1_keys["gov1_convergence_verifier"][2],
    }

    # Unsigned 2-field sandbox envelope in Store must be rejected when building convergence preimage
    unsigned_sbx = gov1_sandbox.build_sealed_sandbox_profile_envelope(
        migration_run_context_locator=RUN_CONTEXT_LOCATOR,
        oci_image_digest=OCI_IMAGE_DIGEST,
        runner_binary_digest=RUNNER_BINARY_DIGEST,
        seccomp_profile=baseline_artifacts["seccomp_profile"],
        issued_at_utc=ISSUED_AT_UTC,
        valid_from_utc=VALID_FROM_UTC,
        valid_until_utc=VALID_UNTIL_UTC,
        registry_locator=world.registry_loc,
        signer_key_id=synthetic_gov1_keys["security_owner"][2],
    )
    unsigned_sbx_loc = world.store.put(unsigned_sbx)
    mcp_for_unsigned_sbx = copy.deepcopy(world.mcp_env)
    mcp_for_unsigned_sbx["sealed_sandbox_profile_locator"] = unsigned_sbx_loc
    mcp_for_unsigned_sbx = p1.sign_envelope(
        mcp_for_unsigned_sbx,
        world.profiles[gov1_mcp.MCP_REJECTION_REPORT_SCHEMA]["domain_prefix"],
        synthetic_gov1_keys["security_verifier"][0],
    )
    mcp_for_unsigned_sbx_loc = world.store.put(mcp_for_unsigned_sbx)
    un_neg_loc, un_cert7a_loc = _rebind_signed_7a_constituents(
        world,
        synthetic_gov1_keys,
        sandbox_loc=unsigned_sbx_loc,
        mcp_loc=mcp_for_unsigned_sbx_loc,
    )
    with pytest.raises(ValueError, match="integrity|signed"):
        gov1_convergence.build_gov1_convergence_record_envelope(
            **{
                **base_kwargs,
                "sealed_sandbox_profile_locator": unsigned_sbx_loc,
                "mcp_rejection_matrix_report_locator": mcp_for_unsigned_sbx_loc,
                "negative_security_test_report_locator": un_neg_loc,
                "certification_7a_record_locator": un_cert7a_loc,
            },
            store=world.store,
            pr3_verifier=pr3_ok,
        )

    # Unsigned 2-field top-level convergence envelope must be rejected by verify_gov1_convergence_record
    conv_unsigned = gov1_convergence.build_gov1_convergence_record_envelope(
        **base_kwargs,
        store=world.store,
        pr3_verifier=pr3_ok,
    )
    with pytest.raises(ValueError, match="integrity|signed"):
        gov1_convergence.verify_gov1_convergence_record(
            conv_unsigned,
            store=world.store,
            seccomp_profile=baseline_artifacts["seccomp_profile"],
            wheel_path=baseline_artifacts["wheel_path"],
            repo_root=REPO_ROOT,
            pr3_verifier=pr3_ok,
        )


def test_deep1_001_enforces_boundary_inspection_mcp_execution_and_mandatory_material_inputs(
    tmp_path: Path,
    baseline_artifacts: dict[str, Any],
    synthetic_gov1_keys: dict[str, tuple[Path, bytes, str]],
) -> None:
    assert hasattr(gov1_convergence, "_BOUNDARY_ENVELOPE_17_FIELDS")
    assert not hasattr(gov1_convergence, "_BOUNDARY_ENVELOPE_16_FIELDS")
    assert len(gov1_convergence._BOUNDARY_ENVELOPE_17_FIELDS) == 17

    world = Gov1D4World(tmp_path, synthetic_gov1_keys, baseline_artifacts)
    snapshot: gov1_wheel.GitBuildSnapshot = baseline_artifacts["snapshot"]

    class _CertifiedPr3Verifier:
        def verify_7a_constituents(self, **kwargs: Any) -> dict[str, Any]:
            return {
                "certified": True,
                "negative_cases": list(
                    gov1_convergence.MANDATORY_7A_NEGATIVE_SECURITY_CASES
                ),
                "negative_executed_at_utc": EXECUTED_AT_UTC,
                "certified_at_utc": EXECUTED_AT_UTC,
            }

    pr3_ok = _CertifiedPr3Verifier()
    base_kwargs: dict[str, Any] = {
        "migration_run_context_locator": RUN_CONTEXT_LOCATOR,
        "wheel_boundary_report_locator": world.boundary_loc,
        "sealed_sandbox_profile_locator": world.sandbox_loc,
        "negative_security_test_report_locator": world.neg_loc,
        "mcp_rejection_matrix_report_locator": world.mcp_loc,
        "certification_7a_record_locator": world.cert7a_loc,
        "build_run_id": BUILD_RUN_ID,
        "converged_at_utc": CONVERGED_AT_UTC,
        "source_commit_sha": snapshot.commit_sha,
        "wheel_digest": digest(baseline_artifacts["wheel_bytes"]),
        "build_backend_digest": snapshot.build_backend_digest,
        "schema_bundle_digest": baseline_artifacts["inspection"]["schema_bundle_digest"],
        "registry_locator": world.registry_loc,
        "signer_key_id": synthetic_gov1_keys["gov1_convergence_verifier"][2],
    }

    # 1. Failing archive_allowlist_passed=False on signed boundary envelope in Store fails closed
    bad_bound = copy.deepcopy(world.boundary_env)
    bad_bound["archive_allowlist_passed"] = False
    bad_bound = p1.sign_envelope(
        bad_bound,
        world.profiles[gov1_wheel.WHEEL_BOUNDARY_REPORT_SCHEMA]["domain_prefix"],
        synthetic_gov1_keys["build_boundary_verifier"][0],
    )
    bad_bound_loc = world.store.put(bad_bound)
    b_neg_loc, b_cert7a_loc = _rebind_signed_7a_constituents(
        world, synthetic_gov1_keys, boundary_loc=bad_bound_loc
    )
    with pytest.raises(ValueError, match="archive_allowlist_passed"):
        gov1_convergence.build_gov1_convergence_record_envelope(
            **{
                **base_kwargs,
                "wheel_boundary_report_locator": bad_bound_loc,
                "negative_security_test_report_locator": b_neg_loc,
                "certification_7a_record_locator": b_cert7a_loc,
            },
            store=world.store,
            pr3_verifier=pr3_ok,
        )

    # 2. Failing body_64k_boundary_verified=False or non-zero io_counters on signed MCP envelope in Store fails closed
    bad_mcp_64k = copy.deepcopy(world.mcp_env)
    bad_mcp_64k["body_64k_boundary_verified"] = False
    bad_mcp_64k = p1.sign_envelope(
        bad_mcp_64k,
        world.profiles[gov1_mcp.MCP_REJECTION_REPORT_SCHEMA]["domain_prefix"],
        synthetic_gov1_keys["security_verifier"][0],
    )
    bad_mcp_64k_loc = world.store.put(bad_mcp_64k)
    m_neg_loc, m_cert7a_loc = _rebind_signed_7a_constituents(
        world, synthetic_gov1_keys, mcp_loc=bad_mcp_64k_loc
    )
    with pytest.raises(ValueError, match="body_64k_boundary_verified"):
        gov1_convergence.build_gov1_convergence_record_envelope(
            **{
                **base_kwargs,
                "mcp_rejection_matrix_report_locator": bad_mcp_64k_loc,
                "negative_security_test_report_locator": m_neg_loc,
                "certification_7a_record_locator": m_cert7a_loc,
            },
            store=world.store,
            pr3_verifier=pr3_ok,
        )

    bad_mcp_io = copy.deepcopy(world.mcp_env)
    bad_mcp_io["cases"][0]["io_counters"]["socket_attempts"] = 1
    bad_mcp_io = p1.sign_envelope(
        bad_mcp_io,
        world.profiles[gov1_mcp.MCP_REJECTION_REPORT_SCHEMA]["domain_prefix"],
        synthetic_gov1_keys["security_verifier"][0],
    )
    bad_mcp_io_loc = world.store.put(bad_mcp_io)
    io_neg_loc, io_cert7a_loc = _rebind_signed_7a_constituents(
        world, synthetic_gov1_keys, mcp_loc=bad_mcp_io_loc
    )
    with pytest.raises(ValueError, match="socket_attempts|io_counters"):
        gov1_convergence.build_gov1_convergence_record_envelope(
            **{
                **base_kwargs,
                "mcp_rejection_matrix_report_locator": bad_mcp_io_loc,
                "negative_security_test_report_locator": io_neg_loc,
                "certification_7a_record_locator": io_cert7a_loc,
            },
            store=world.store,
            pr3_verifier=pr3_ok,
        )

    # 3. verify_gov1_convergence_record unconditionally requires seccomp_profile, wheel_path, and repo_root
    conv_unsigned = gov1_convergence.build_gov1_convergence_record_envelope(
        **base_kwargs,
        store=world.store,
        pr3_verifier=pr3_ok,
    )
    conv_signed = p1.sign_envelope(
        conv_unsigned,
        world.profiles[gov1_convergence.GOV1_CONVERGENCE_SCHEMA]["domain_prefix"],
        synthetic_gov1_keys["gov1_convergence_verifier"][0],
    )
    for missing_kw, expected_err in (
        ({"seccomp_profile": None}, "seccomp_profile"),
        ({"wheel_path": None}, "wheel_path"),
        ({"repo_root": None}, "repo_root"),
    ):
        verify_kw: dict[str, Any] = {
            "store": world.store,
            "seccomp_profile": baseline_artifacts["seccomp_profile"],
            "wheel_path": baseline_artifacts["wheel_path"],
            "repo_root": REPO_ROOT,
            "pr3_verifier": pr3_ok,
            **missing_kw,
        }
        with pytest.raises(ValueError, match=expected_err):
            gov1_convergence.verify_gov1_convergence_record(conv_signed, **verify_kw)


def test_deep1_002_verify_artifact_unconditionally_verifies_provenance_and_sandbox_dependencies(
    tmp_path: Path,
    baseline_artifacts: dict[str, Any],
    synthetic_gov1_keys: dict[str, tuple[Path, bytes, str]],
) -> None:
    world = Gov1D4World(tmp_path, synthetic_gov1_keys, baseline_artifacts)
    verifier = world.make_verifier()

    # MCP report referencing a signed sandbox envelope whose seccomp_profile_digest binds a forbidden 'socket' rule
    bad_seccomp = copy.deepcopy(baseline_artifacts["seccomp_profile"])
    bad_seccomp["syscalls"][0]["names"] = sorted(
        [*bad_seccomp["syscalls"][0]["names"], "socket"]
    )
    forged_sbx = copy.deepcopy(world.sandbox_env)
    forged_sbx["seccomp_profile_digest"] = json_digest(bad_seccomp)
    forged_sbx = p1.sign_envelope(
        forged_sbx,
        world.profiles[gov1_sandbox.SANDBOX_PROFILE_SCHEMA]["domain_prefix"],
        synthetic_gov1_keys["security_owner"][0],
    )
    forged_sbx_loc = world.store.put(forged_sbx)
    mcp_with_forged_sbx = copy.deepcopy(world.mcp_env)
    mcp_with_forged_sbx["sealed_sandbox_profile_locator"] = forged_sbx_loc
    mcp_with_forged_sbx = p1.sign_envelope(
        mcp_with_forged_sbx,
        world.profiles[gov1_mcp.MCP_REJECTION_REPORT_SCHEMA]["domain_prefix"],
        synthetic_gov1_keys["security_verifier"][0],
    )
    mcp_with_forged_sbx_loc = world.store.put(mcp_with_forged_sbx)

    with pytest.raises(ValueError, match="socket|denied|seccomp_profile_digest"):
        verifier.verify_artifact(
            mcp_with_forged_sbx_loc,
            wheel_path=baseline_artifacts["wheel_path"],
            seccomp_profile=bad_seccomp,
        )
    assert world.runtime.cas_calls == 0

    # Positive control: both boundary (with repo_root) and MCP (with seccomp_profile) verify cleanly
    res_bound = verifier.verify_artifact(
        world.boundary_loc,
        wheel_path=baseline_artifacts["wheel_path"],
        repo_root=REPO_ROOT,
    )
    assert res_bound["verification_status"] == "VERIFIED"
    assert world.runtime.cas_calls == 1

    res_mcp = verifier.verify_artifact(
        world.mcp_loc,
        wheel_path=baseline_artifacts["wheel_path"],
        seccomp_profile=baseline_artifacts["seccomp_profile"],
    )
    assert res_mcp["verification_status"] == "VERIFIED"
    assert world.runtime.cas_calls == 2


def test_deep1_003_rejects_foreign_tenant_signer_against_installation_pins(
    tmp_path: Path,
    baseline_artifacts: dict[str, Any],
    synthetic_gov1_keys: dict[str, tuple[Path, bytes, str]],
) -> None:
    world = Gov1D4World(
        tmp_path,
        synthetic_gov1_keys,
        baseline_artifacts,
        registry_mutation=lambda reg: reg["entries"][1].update(
            tenant="foreign-tenant"
        ),
    )
    verifier = world.make_verifier()

    with pytest.raises(ValueError, match="tenant mismatch"):
        verifier.verify_artifact(
            world.sandbox_loc,
            seccomp_profile=baseline_artifacts["seccomp_profile"],
        )
    assert world.runtime.cas_calls == 0

    with pytest.raises(ValueError, match="tenant mismatch"):
        verifier.admit_etapa7_bundle(
            sandbox_profile_locator=world.sandbox_loc,
            wheel_provenance_locator=world.prov_loc,
            wheel_boundary_report_locator=world.boundary_loc,
            mcp_rejection_report_locator=world.mcp_loc,
            seccomp_profile=baseline_artifacts["seccomp_profile"],
            wheel_path=baseline_artifacts["wheel_path"],
            repo_root=REPO_ROOT,
        )
    assert world.runtime.cas_calls == 0


def test_history001_enforces_store_7a_constituents_timestamps_d4_roles_and_verifier_independence(
    tmp_path: Path,
    baseline_artifacts: dict[str, Any],
    synthetic_gov1_keys: dict[str, tuple[Path, bytes, str]],
) -> None:
    world = Gov1D4World(tmp_path, synthetic_gov1_keys, baseline_artifacts)
    snapshot: gov1_wheel.GitBuildSnapshot = baseline_artifacts["snapshot"]

    class _CertifiedPr3Verifier:
        def __init__(
            self,
            neg_ts: Any = EXECUTED_AT_UTC,
            cert_ts: Any = EXECUTED_AT_UTC,
        ) -> None:
            self.neg_ts = neg_ts
            self.cert_ts = cert_ts

        def verify_7a_constituents(self, **kwargs: Any) -> dict[str, Any]:
            return {
                "certified": True,
                "negative_cases": list(
                    gov1_convergence.MANDATORY_7A_NEGATIVE_SECURITY_CASES
                ),
                "negative_executed_at_utc": self.neg_ts,
                "certified_at_utc": self.cert_ts,
            }

    pr3_ok = _CertifiedPr3Verifier()
    base_kwargs: dict[str, Any] = {
        "migration_run_context_locator": RUN_CONTEXT_LOCATOR,
        "wheel_boundary_report_locator": world.boundary_loc,
        "sealed_sandbox_profile_locator": world.sandbox_loc,
        "negative_security_test_report_locator": world.neg_loc,
        "mcp_rejection_matrix_report_locator": world.mcp_loc,
        "certification_7a_record_locator": world.cert7a_loc,
        "build_run_id": BUILD_RUN_ID,
        "converged_at_utc": CONVERGED_AT_UTC,
        "source_commit_sha": snapshot.commit_sha,
        "wheel_digest": digest(baseline_artifacts["wheel_bytes"]),
        "build_backend_digest": snapshot.build_backend_digest,
        "schema_bundle_digest": baseline_artifacts["inspection"]["schema_bundle_digest"],
        "registry_locator": world.registry_loc,
        "signer_key_id": synthetic_gov1_keys["gov1_convergence_verifier"][2],
    }

    # 1. Missing 7A constituent from Store fails closed
    missing_neg_loc = make_locator(
        gov1_convergence.NEGATIVE_SECURITY_SCHEMA, b'{"missing":"neg"}'
    )
    with pytest.raises(ValueError, match=r"locator\.Store\.get: no object"):
        gov1_convergence.build_gov1_convergence_record_envelope(
            **{**base_kwargs, "negative_security_test_report_locator": missing_neg_loc},
            store=world.store,
            pr3_verifier=pr3_ok,
        )

    missing_cert_loc = make_locator(
        gov1_convergence.CERTIFICATION_7A_SCHEMA, b'{"missing":"cert"}'
    )
    with pytest.raises(ValueError, match=r"locator\.Store\.get: no object"):
        gov1_convergence.build_gov1_convergence_record_envelope(
            **{**base_kwargs, "certification_7a_record_locator": missing_cert_loc},
            store=world.store,
            pr3_verifier=pr3_ok,
        )

    # 2. Missing/None timestamps in pr3_verifier outcome or certified_at_utc < negative_executed_at_utc fail closed
    for bad_pr3 in (
        _CertifiedPr3Verifier(neg_ts=None, cert_ts=EXECUTED_AT_UTC),
        _CertifiedPr3Verifier(neg_ts=EXECUTED_AT_UTC, cert_ts=None),
        _CertifiedPr3Verifier(
            neg_ts="2026-09-07T10:00:16Z", cert_ts=EXECUTED_AT_UTC
        ),
    ):
        with pytest.raises(ValueError):
            gov1_convergence.build_gov1_convergence_record_envelope(
                **base_kwargs,
                store=world.store,
                pr3_verifier=bad_pr3,
            )

    # 3. 7A constituent signed under wrong role or wrong domain fails D4 admission with cas_calls == 0
    verifier_with_pr3 = gov1_convergence.Gov1AdmissionVerifier(
        world.runtime,
        world.pins,
        world.store,
        world.adr,
        inventory_locator=world.inventory_loc,
        pr3_verifier=pr3_ok,
    )
    wrong_domain_neg = p1.sign_envelope(
        world.neg_env,
        "SMART-ADS:WRONG-7A:V1\n",
        synthetic_gov1_keys["7a_verifier"][0],
    )
    wrong_domain_neg_loc = world.store.put(wrong_domain_neg)
    wd_cert7a = copy.deepcopy(world.cert7a_env)
    wd_cert7a["negative_security_test_report_locator"] = wrong_domain_neg_loc
    wd_cert7a = p1.sign_envelope(
        wd_cert7a,
        world.profiles[gov1_convergence.CERTIFICATION_7A_SCHEMA]["domain_prefix"],
        synthetic_gov1_keys["independent_7a_verifier"][0],
    )
    wd_cert7a_loc = world.store.put(wd_cert7a)
    conv_wd = p1.sign_envelope(
        gov1_convergence.build_gov1_convergence_record_envelope(
            **{
                **base_kwargs,
                "negative_security_test_report_locator": wrong_domain_neg_loc,
                "certification_7a_record_locator": wd_cert7a_loc,
            },
            store=world.store,
            pr3_verifier=pr3_ok,
        ),
        world.profiles[gov1_convergence.GOV1_CONVERGENCE_SCHEMA]["domain_prefix"],
        synthetic_gov1_keys["gov1_convergence_verifier"][0],
    )
    conv_wd_loc = world.store.put(conv_wd)
    with pytest.raises(ValueError, match="signature verification failed"):
        verifier_with_pr3.verify_artifact(
            conv_wd_loc,
            seccomp_profile=baseline_artifacts["seccomp_profile"],
            wheel_path=baseline_artifacts["wheel_path"],
            repo_root=REPO_ROOT,
        )
    assert world.runtime.cas_calls == 0

    # 4. Revoked 7a_verifier key in current state fails D4 admission with cas_calls == 0
    world_revoked = Gov1D4World(
        tmp_path / "revoked_7a", synthetic_gov1_keys, baseline_artifacts
    )
    world_revoked.advance_current_registry(
        lambda reg: reg["entries"][6].update(lifecycle_state="revoked")
    )
    conv_rev = p1.sign_envelope(
        gov1_convergence.build_gov1_convergence_record_envelope(
            migration_run_context_locator=RUN_CONTEXT_LOCATOR,
            wheel_boundary_report_locator=world_revoked.boundary_loc,
            sealed_sandbox_profile_locator=world_revoked.sandbox_loc,
            negative_security_test_report_locator=world_revoked.neg_loc,
            mcp_rejection_matrix_report_locator=world_revoked.mcp_loc,
            certification_7a_record_locator=world_revoked.cert7a_loc,
            build_run_id=BUILD_RUN_ID,
            converged_at_utc=CONVERGED_AT_UTC,
            source_commit_sha=snapshot.commit_sha,
            wheel_digest=digest(baseline_artifacts["wheel_bytes"]),
            build_backend_digest=snapshot.build_backend_digest,
            schema_bundle_digest=baseline_artifacts["inspection"]["schema_bundle_digest"],
            registry_locator=world_revoked.registry_loc,
            signer_key_id=synthetic_gov1_keys["gov1_convergence_verifier"][2],
            store=world_revoked.store,
            pr3_verifier=pr3_ok,
        ),
        world_revoked.profiles[gov1_convergence.GOV1_CONVERGENCE_SCHEMA][
            "domain_prefix"
        ],
        synthetic_gov1_keys["gov1_convergence_verifier"][0],
    )
    conv_rev_loc = world_revoked.store.put(conv_rev)
    verifier_rev = gov1_convergence.Gov1AdmissionVerifier(
        world_revoked.runtime,
        world_revoked.pins,
        world_revoked.store,
        world_revoked.adr,
        inventory_locator=world_revoked.inventory_loc,
        pr3_verifier=pr3_ok,
    )
    with pytest.raises(
        ValueError, match="authority key currently revoked or expired"
    ):
        verifier_rev.verify_artifact(
            conv_rev_loc,
            seccomp_profile=baseline_artifacts["seccomp_profile"],
            wheel_path=baseline_artifacts["wheel_path"],
            repo_root=REPO_ROOT,
        )
    assert world_revoked.runtime.cas_calls == 0

    # 5. Shared principal between 7a_verifier and independent_7a_verifier fails D4 admission with cas_calls == 0
    world_colluding = Gov1D4World(
        tmp_path / "colluding_7a",
        synthetic_gov1_keys,
        baseline_artifacts,
        registry_mutation=lambda reg: reg["entries"][7].update(
            principal=reg["entries"][6]["principal"]
        ),
    )
    conv_col = p1.sign_envelope(
        gov1_convergence.build_gov1_convergence_record_envelope(
            migration_run_context_locator=RUN_CONTEXT_LOCATOR,
            wheel_boundary_report_locator=world_colluding.boundary_loc,
            sealed_sandbox_profile_locator=world_colluding.sandbox_loc,
            negative_security_test_report_locator=world_colluding.neg_loc,
            mcp_rejection_matrix_report_locator=world_colluding.mcp_loc,
            certification_7a_record_locator=world_colluding.cert7a_loc,
            build_run_id=BUILD_RUN_ID,
            converged_at_utc=CONVERGED_AT_UTC,
            source_commit_sha=snapshot.commit_sha,
            wheel_digest=digest(baseline_artifacts["wheel_bytes"]),
            build_backend_digest=snapshot.build_backend_digest,
            schema_bundle_digest=baseline_artifacts["inspection"]["schema_bundle_digest"],
            registry_locator=world_colluding.registry_loc,
            signer_key_id=synthetic_gov1_keys["gov1_convergence_verifier"][2],
            store=world_colluding.store,
            pr3_verifier=pr3_ok,
        ),
        world_colluding.profiles[gov1_convergence.GOV1_CONVERGENCE_SCHEMA][
            "domain_prefix"
        ],
        synthetic_gov1_keys["gov1_convergence_verifier"][0],
    )
    conv_col_loc = world_colluding.store.put(conv_col)
    verifier_col = gov1_convergence.Gov1AdmissionVerifier(
        world_colluding.runtime,
        world_colluding.pins,
        world_colluding.store,
        world_colluding.adr,
        inventory_locator=world_colluding.inventory_loc,
        pr3_verifier=pr3_ok,
    )
    with pytest.raises(ValueError, match="independent_7a_verifier|distinct"):
        verifier_col.verify_artifact(
            conv_col_loc,
            seccomp_profile=baseline_artifacts["seccomp_profile"],
            wheel_path=baseline_artifacts["wheel_path"],
            repo_root=REPO_ROOT,
        )
    assert world_colluding.runtime.cas_calls == 0


def test_history002_enforces_post_cas_second_signature_pass_config_immutability_and_store_parity(
    tmp_path: Path,
    baseline_artifacts: dict[str, Any],
    synthetic_gov1_keys: dict[str, tuple[Path, bytes, str]],
) -> None:
    # 1. Clock expiration during post-CAS second signature pass on verify_artifact (mirrors test_decomposition_runtime.py)
    world_clock = Gov1D4World(
        tmp_path / "post_cas_clock", synthetic_gov1_keys, baseline_artifacts
    )
    orig_get = world_clock.store.get

    def expire_during_second_pass(
        locator: dict[str, Any], expected_type: str | None = None
    ) -> dict[str, Any]:
        if world_clock.runtime.cas_calls:
            world_clock.runtime.clock = ClockInterval(
                "2026-09-07T10:06:00Z", "2026-09-07T10:06:00Z"
            )
        return orig_get(locator, expected_type=expected_type)

    world_clock.store.get = expire_during_second_pass  # type: ignore[method-assign]
    verifier_clock = world_clock.make_verifier()
    with pytest.raises(ValueError, match="stale"):
        verifier_clock.verify_artifact(
            world_clock.sandbox_loc,
            seccomp_profile=baseline_artifacts["seccomp_profile"],
        )
    assert world_clock.runtime.cas_calls == 1

    # 2. Protected configuration / installation authority drift after CAS on admit_etapa7_bundle
    world_cfg = Gov1D4World(
        tmp_path / "post_cas_cfg", synthetic_gov1_keys, baseline_artifacts
    )
    orig_ia = world_cfg.runtime.installation_authority
    world_cfg.runtime.installation_authority = (  # type: ignore[method-assign]
        lambda: "drifted-installation"
        if world_cfg.runtime.cas_calls
        else orig_ia()
    )
    verifier_cfg = world_cfg.make_verifier()
    with pytest.raises(
        ValueError,
        match="installation authority mismatch|protected configuration changed",
    ):
        verifier_cfg.admit_etapa7_bundle(
            sandbox_profile_locator=world_cfg.sandbox_loc,
            wheel_provenance_locator=world_cfg.prov_loc,
            wheel_boundary_report_locator=world_cfg.boundary_loc,
            mcp_rejection_report_locator=world_cfg.mcp_loc,
            seccomp_profile=baseline_artifacts["seccomp_profile"],
            wheel_path=baseline_artifacts["wheel_path"],
            repo_root=REPO_ROOT,
        )
    assert world_cfg.runtime.cas_calls == 1

    # 2b. Protected configuration drift after CAS fails closed
    world_cfg_drift = Gov1D4World(
        tmp_path / "post_cas_cfg_drift", synthetic_gov1_keys, baseline_artifacts
    )
    drifted_cfg = copy.deepcopy(world_cfg_drift.config)
    drifted_cfg["head_register"] = "head:drifted-synthetic"
    verifier_cfg_drift = world_cfg_drift.make_verifier()
    orig_cfg_fn = verifier_cfg_drift._configuration
    verifier_cfg_drift._configuration = (  # type: ignore[method-assign]
        lambda clk: copy.deepcopy(drifted_cfg)
        if world_cfg_drift.runtime.cas_calls
        else orig_cfg_fn(clk)
    )
    with pytest.raises(
        ValueError, match="protected configuration changed during admission"
    ):
        verifier_cfg_drift.verify_artifact(
            world_cfg_drift.sandbox_loc,
            seccomp_profile=baseline_artifacts["seccomp_profile"],
        )
    assert world_cfg_drift.runtime.cas_calls == 1

    # 3. Store object mutation during post-CAS reload fails closed
    world_mut = Gov1D4World(
        tmp_path / "post_cas_mut", synthetic_gov1_keys, baseline_artifacts
    )
    orig_mut_get = world_mut.store.get

    def corrupt_after_cas(
        locator: dict[str, Any], expected_type: str | None = None
    ) -> dict[str, Any]:
        obj = orig_mut_get(locator, expected_type=expected_type)
        if (
            world_mut.runtime.cas_calls
            and locator.get("artifact_type") == gov1_sandbox.SANDBOX_PROFILE_SCHEMA
        ):
            tampered = copy.deepcopy(obj)
            tampered["issued_at_utc"] = "2026-09-07T10:00:01Z"
            return tampered
        return obj

    world_mut.store.get = corrupt_after_cas  # type: ignore[method-assign]
    verifier_mut = world_mut.make_verifier()
    with pytest.raises(ValueError):
        verifier_mut.verify_artifact(
            world_mut.sandbox_loc,
            seccomp_profile=baseline_artifacts["seccomp_profile"],
        )
    assert world_mut.runtime.cas_calls == 1


