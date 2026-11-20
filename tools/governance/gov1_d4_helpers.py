"""D4 monotonic registry lineage `1..tip_reg`, `SnapshotStore`, 4 leaf auth, and candidate Etapa 11 helpers."""
from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
import contextlib
import copy
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import tempfile
from types import MappingProxyType
from typing import Any, Final

from tools.governance import decomposition_governance, gov1_7a_runner, p1
from tools.governance.decomposition_admission import profile_proposals
from tools.governance.decomposition_governance import ANCHOR_PUBLIC, REPO_ROOT
from tools.governance.decomposition_runtime import (
    CHECKPOINT, CONFIG, HEAD, INVENTORY, REGISTRY, STATE, ClockInterval, InstallationPins,
    load_object, public_key, registry, require, validity,
)
from tools.governance.gov1_7a_negative import (
    NEGATIVE_SECURITY_REPORT_SCHEMA, extract_provenance_payload, verify_negative_security_test_report,
)
from tools.governance.gov1_7a_runner import (
    EXPECTED_RESOURCE_INVENTORY_SCHEMA, GIT_ARTIFACT_PROVENANCE_SCHEMA, PINNED_PIPEBOARD_D26_SPECS,
    PRIVATE_REGISTRY_SNAPSHOT_SCHEMA, verify_expected_resource_inventory_envelope,
    verify_git_artifact_provenance_envelope, verify_private_registry_snapshot_envelope,
)
from tools.governance.gov1_mcp import MCP_REJECTION_REPORT_SCHEMA, verify_mcp_rejection_matrix_report
from tools.governance.gov1_sandbox import (
    LOCAL_CANDIDATE_KIND, SANDBOX_PROFILE_SCHEMA, build_local_candidate_ref, unwrap_local_candidate,
    verify_local_candidate_ref, verify_seccomp_profile, verify_sealed_sandbox_profile, wrap_local_candidate,
)
from tools.governance.gov1_wheel import (
    DEFAULT_REPOSITORY, EXPECTED_WHEEL_FILENAME, WHEEL_BOUNDARY_REPORT_SCHEMA, WHEEL_BUILD_PROVENANCE_SCHEMA,
    IsolatedWheelProbeRunner, verify_wheel_boundary_report, verify_wheel_build_provenance,
)
from tools.governance.jcs import canonicalize, loads_strict
from tools.governance.locator import Store, digest, exact_fields, timestamp, validate_locator

GOV1_CONVERGENCE_SCHEMA: Final[str] = "smart_ads/gov1_convergence_record/v1"
CERTIFICATION_7A_SCHEMA: Final[str] = "smart_ads/certification_7a_record/v1"
PIPEBOARD_CONTRACT_SCHEMA: Final[str] = "smart_ads/pipeboard_phase1_contract/v1"
_RUN_CONTEXT_SCHEMA: Final[str] = "smart_ads/migration_run_context/v1"
_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"\Asha256:[0-9a-f]{64}\Z")
_GIT_OID_RE: Final[re.Pattern[str]] = re.compile(r"\A[0-9a-f]{40}\Z")

_D4_SCHEMA_ROLE_ACTION_SPECS: Final[Mapping[str, tuple[str, str, str]]] = MappingProxyType(
    {
        SANDBOX_PROFILE_SCHEMA: ("security owner", "security_owner", "sealed_sandbox_profile_issue"),
        WHEEL_BUILD_PROVENANCE_SCHEMA: ("build provenance verifier", "build_provenance_verifier", "wheel_build_provenance_issue"),
        WHEEL_BOUNDARY_REPORT_SCHEMA: ("build-boundary verifier", "build_boundary_verifier", "wheel_boundary_report_issue"),
        MCP_REJECTION_REPORT_SCHEMA: ("security verifier", "security_verifier", "mcp_rejection_matrix_report_issue"),
        NEGATIVE_SECURITY_REPORT_SCHEMA: ("7A verifier", "7a_verifier", "negative_security_test_report_issue"),
        CERTIFICATION_7A_SCHEMA: ("independent 7A verifier", "independent_7a_verifier", "certification_7a_record_issue"),
        GOV1_CONVERGENCE_SCHEMA: ("GOV1 convergence verifier", "gov1_convergence_verifier", "gov1_convergence_record_issue"),
        PIPEBOARD_CONTRACT_SCHEMA: ("ProviderPort policy owner", "provider_port_policy_owner", "pipeboard_phase1_contract_issue"),
        PRIVATE_REGISTRY_SNAPSHOT_SCHEMA: ("registry publisher", "registry_publisher", "private_registry_snapshot_issue"),
        EXPECTED_RESOURCE_INVENTORY_SCHEMA: ("private registry publisher", "private_registry_publisher", "expected_resource_inventory_issue"),
        GIT_ARTIFACT_PROVENANCE_SCHEMA: ("Git provenance verifier", "git_provenance_verifier", "git_artifact_provenance_issue"),
    }
)

_SEVEN_GOV1_RUN_CTX_SCHEMAS: Final[frozenset[str]] = frozenset(
    (SANDBOX_PROFILE_SCHEMA, WHEEL_BUILD_PROVENANCE_SCHEMA, WHEEL_BOUNDARY_REPORT_SCHEMA, MCP_REJECTION_REPORT_SCHEMA, NEGATIVE_SECURITY_REPORT_SCHEMA, CERTIFICATION_7A_SCHEMA, GOV1_CONVERGENCE_SCHEMA)
)

_GOV1_CONVERGENCE_CANDIDATE_PAYLOAD_FIELDS: Final[set[str]] = set(
    "migration_run_context_locator wheel_boundary_report_candidate_ref sealed_sandbox_profile_candidate_ref "
    "negative_security_test_report_candidate_ref mcp_rejection_matrix_report_candidate_ref "
    "certification_7a_record_candidate_ref build_run_id converged_at_utc source_commit_sha "
    "wheel_digest build_backend_digest schema_bundle_digest convergence_status".split()
)

_IMMUTABLE_KEY_FIELDS: Final[tuple[str, ...]] = ("public_key_base64", "public_key_sha256", "principal", "tenant", "role", "validity")
_LIFECYCLE_TRANSITIONS: Final[Mapping[str, frozenset[str]]] = MappingProxyType(
    {"active": frozenset({"active", "revoked", "expired"}), "revoked": frozenset({"revoked"}), "expired": frozenset({"expired"})}
)


def _cert7a_mod() -> Any:
    from tools.governance import gov1_7a_certification

    return gov1_7a_certification


def _strict_str(value: object, label: str) -> str:
    if type(value) is not str or not value.strip() or value != value.strip() or "\x00" in value:
        raise ValueError(f"{label}: expected non-empty stripped string")
    return value


def _sha256_str(value: object, label: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise ValueError(f"{label}: expected 'sha256:<64_lowercase_hex>'")
    return value


def _git_oid_str(value: object, label: str) -> str:
    if type(value) is not str or _GIT_OID_RE.fullmatch(value) is None:
        raise ValueError(f"{label}: expected 40-char lowercase hex Git OID")
    return value


def _read_nonempty_regular_file(path_value: object, label: str) -> tuple[Path, bytes]:
    if not isinstance(path_value, (str, os.PathLike)):
        raise ValueError(f"{label}: expected filesystem path")
    file_path = Path(path_value)
    if file_path.is_symlink() or not file_path.is_file():
        raise ValueError(f"{label}: expected regular non-symlink file at {file_path}")
    raw = file_path.read_bytes()
    if len(raw) == 0:
        raise ValueError(f"{label}: expected non-empty file at {file_path}")
    return file_path, raw


class SnapshotStore(Store):
    """Frozen in-memory read-only `Store` holding only D4-authenticated canonical envelopes."""

    def __init__(self, envelopes: Sequence[Mapping[str, Any]] = ()) -> None:
        super().__init__(Path("/nonexistent-d4-snapshot-store"))
        if isinstance(envelopes, (str, bytes, bytearray)) or not isinstance(envelopes, Sequence):
            raise ValueError("SnapshotStore: envelopes must be a Sequence of Mapping objects")
        by_digest: dict[str, bytes] = {}
        for env in envelopes:
            if not isinstance(env, Mapping) or type(env.get("$schema")) is not str or not env["$schema"]:
                raise ValueError("SnapshotStore: each envelope must be a Mapping with non-empty '$schema'")
            raw = canonicalize(dict(env))
            loads_strict(raw.decode("utf-8"))
            d_hex = hashlib.sha256(raw).hexdigest()
            if d_hex in by_digest and by_digest[d_hex] != raw:
                raise ValueError("SnapshotStore: conflicting canonical bytes for digest")
            by_digest[d_hex] = raw
        self._objects: Mapping[str, bytes] = MappingProxyType(by_digest)

    def _path_for(self, digest_hex: str) -> Path:
        _ = digest_hex
        raise ValueError("SnapshotStore: filesystem access is disabled")

    def put(self, envelope: dict[str, Any]) -> dict[str, Any]:
        _ = envelope
        raise ValueError("SnapshotStore.put: read-only D4 snapshot store forbids writes")

    def get(self, locator: dict[str, Any], expected_type: str | None = None) -> dict[str, Any]:
        validate_locator(locator, expected_type=expected_type)
        digest_hex = locator["content_digest"][len("sha256:") :]
        raw = self._objects.get(digest_hex)
        if raw is None:
            raise ValueError(f"SnapshotStore.get: unauthenticated or missing object for {locator!r}")
        if hashlib.sha256(raw).hexdigest() != digest_hex:
            raise ValueError("SnapshotStore.get: digest mismatch in snapshot store")
        value = loads_strict(raw.decode("utf-8"))
        if not isinstance(value, dict) or value.get("$schema") != locator["artifact_type"]:
            raise ValueError("SnapshotStore.get: artifact_type mismatch in snapshot store")
        return copy.deepcopy(value)


def _validate_deployed_runtime_config(
    runtime_config: Mapping[str, Any] | bytes, repo_path: Path
) -> tuple[bytes, dict[str, Any], dict[str, Any]]:
    if type(runtime_config) is bytes:
        raw_cfg, loaded = runtime_config, loads_strict(runtime_config.decode("utf-8"))
        if not isinstance(loaded, dict):
            raise ValueError("runtime_config: expected JSON object bytes")
        cfg_d = loaded
    elif isinstance(runtime_config, Mapping):
        cfg_d = dict(runtime_config)
        raw_cfg = canonicalize(cfg_d)
        loads_strict(raw_cfg.decode("utf-8"))
    else:
        raise ValueError("runtime_config: expected Mapping or canonical UTF-8 bytes")
    exact_fields(cfg_d, CONFIG, "protected configuration")
    require(cfg_d["$schema"] == "smart_ads/cell_trust_anchor_config/v1", "configuration schema mismatch")
    public_key(cfg_d)
    require(cfg_d["public_key_base64"] == decomposition_governance.ANCHOR_PUBLIC, "runtime_config anchor mismatch")
    _strict_str(cfg_d["trust_anchor_id"], "runtime_config.trust_anchor_id")
    val_d = dict(cfg_d["validity"]) if isinstance(cfg_d["validity"], Mapping) else {}
    exact_fields(val_d, {"from", "until"}, "runtime_config.validity")
    require(
        type(val_d["from"]) is str
        and type(val_d["until"]) is str
        and timestamp(val_d["from"]) < timestamp(val_d["until"]),
        "invalid runtime_config validity interval",
    )
    require(cfg_d["allowed_registry_artifact_types"] == [REGISTRY, INVENTORY], "bootstrap allowlist mismatch")
    adr_raw = (repo_path / "docs/adr/ADR-0001-smart-ads-read-gateway.md").read_bytes()
    profiles = {p["schema"]: p for p in profile_proposals(adr_raw)}
    for fld, sch in (("inventory_bootstrap_profile", INVENTORY), ("anti_rollback_checkpoint_profile", CHECKPOINT)):
        require(
            isinstance(cfg_d[fld], Mapping) and canonicalize(dict(cfg_d[fld])) == canonicalize(profiles[sch]),
            "protected profile mismatch",
        )
    return raw_cfg, cfg_d, profiles


def _resolve_repo_pins_identity(
    *, repo_path: Path, configuration_digest: str | None, runtime_config: Mapping[str, Any] | bytes | None,
    installation_authority: str | None, cell_id: str | None, head_register: str | None, checkpoint_register: str | None,
) -> tuple[str, str, str, str, str, dict[str, Any] | None, dict[str, Any] | None]:
    if (configuration_digest is None) == (runtime_config is None):
        raise ValueError("Gov1InstallationPins.from_repo_prerequisites: specify exactly one of configuration_digest or runtime_config")
    if runtime_config is not None:
        raw_cfg, cfg_d, profiles = _validate_deployed_runtime_config(runtime_config, repo_path)
        resolved: list[str] = []
        for name, val in (("installation_authority", installation_authority), ("cell_id", cell_id), ("head_register", head_register), ("checkpoint_register", checkpoint_register)):
            cfg_str = _strict_str(cfg_d[name], f"runtime_config.{name}")
            if val is not None and val != cfg_str:
                raise ValueError(f"Gov1InstallationPins: {name} mismatch against runtime_config")
            resolved.append(cfg_str)
        return digest(raw_cfg), resolved[0], resolved[1], resolved[2], resolved[3], cfg_d, profiles
    return (
        _sha256_str(configuration_digest, "configuration_digest"),
        _strict_str(installation_authority, "installation_authority"),
        _strict_str(cell_id, "cell_id"),
        _strict_str(head_register, "head_register"),
        _strict_str(checkpoint_register, "checkpoint_register"),
        None, None,
    )


def _verify_repo_pre_head_registries(
    repo_path: Path, pre_locs: Sequence[dict[str, Any]], *,
    cfg_d: dict[str, Any] | None, profiles: dict[str, Any] | None, store: Store | None,
) -> None:
    if store is not None:
        require(isinstance(store, Store), "invalid immutable object store")
    if cfg_d is None or profiles is None:
        return
    cell_store = Store(repo_path / "docs/governance/cell-objects")
    extra_store = store if store is not None else cell_store
    prev_reg: dict[str, Any] | None = None
    for expected_ep, loc in enumerate(pre_locs, start=1):
        target_store = cell_store if expected_ep <= 3 else extra_store
        reg_obj = registry(target_store, loc, cfg_d, profiles)
        require(reg_obj["epoch"] == expected_ep, f"pre-head registry expected epoch {expected_ep}")
        if prev_reg is not None:
            _verify_d4_registry_lineage_step(prev_reg, reg_obj, cfg_d)
        prev_reg = reg_obj


@dataclass(frozen=True)
class Gov1InstallationPins(InstallationPins):
    """Out-of-band installation pins binding run context and pre-head D4 registry lineage."""

    pinned_run_context_locator: dict[str, Any]
    pinned_pre_head_registry_locators: tuple[dict[str, Any], ...] = ()

    def __post_init__(self) -> None:
        _sha256_str(self.configuration_digest, "Gov1InstallationPins.configuration_digest")
        for attr in ("installation_authority", "cell_id", "head_register", "checkpoint_register", "owner_principal", "owner_tenant"):
            _strict_str(getattr(self, attr), f"Gov1InstallationPins.{attr}")
        if not isinstance(self.pinned_run_context_locator, Mapping):
            raise ValueError("Gov1InstallationPins: pinned_run_context_locator must be a Mapping")
        run_ctx = copy.deepcopy(dict(self.pinned_run_context_locator))
        validate_locator(run_ctx, _RUN_CONTEXT_SCHEMA)
        raw_pre = self.pinned_pre_head_registry_locators
        if isinstance(raw_pre, (str, bytes, bytearray)) or not isinstance(raw_pre, Sequence):
            raise ValueError("Gov1InstallationPins: pinned_pre_head_registry_locators must be a Sequence")
        checked_pre: list[dict[str, Any]] = []
        for idx, loc in enumerate(raw_pre):
            if not isinstance(loc, Mapping):
                raise ValueError(f"Gov1InstallationPins: pre-head locator[{idx}] must be a Mapping")
            loc_d = copy.deepcopy(dict(loc))
            validate_locator(loc_d, REGISTRY)
            checked_pre.append(loc_d)
        object.__setattr__(self, "pinned_run_context_locator", run_ctx)
        object.__setattr__(self, "pinned_pre_head_registry_locators", tuple(checked_pre))

    @classmethod
    def from_repo_prerequisites(
        cls, root: Path = REPO_ROOT, *, configuration_digest: str | None = None,
        runtime_config: Mapping[str, Any] | bytes | None = None, installation_authority: str | None = None,
        cell_id: str | None = None, head_register: str | None = None, checkpoint_register: str | None = None,
        owner_principal: str = "principal:ronaldo", owner_tenant: str = "mbras",
        extra_pre_head_registry_locators: Sequence[dict[str, Any]] = (), store: Store | None = None,
    ) -> Gov1InstallationPins:
        if isinstance(extra_pre_head_registry_locators, (str, bytes, bytearray)) or not isinstance(extra_pre_head_registry_locators, Sequence):
            raise ValueError("Gov1InstallationPins: extra_pre_head_registry_locators must be a Sequence")
        repo_path = Path(root)
        cfg_dig, inst_auth, c_id, h_reg, ck_reg, cfg_d, profiles = _resolve_repo_pins_identity(
            repo_path=repo_path, configuration_digest=configuration_digest, runtime_config=runtime_config,
            installation_authority=installation_authority, cell_id=cell_id,
            head_register=head_register, checkpoint_register=checkpoint_register,
        )
        ident = decomposition_governance.verified_run_context_identity(repo_path)
        pre_locs = (
            ident["gate2_registry_locator"], ident["run_registry_locator"],
            ident["prerequisite_epoch3_registry_locator"], *extra_pre_head_registry_locators,
        )
        pins_obj = cls(
            configuration_digest=cfg_dig, installation_authority=inst_auth, cell_id=c_id,
            head_register=h_reg, checkpoint_register=ck_reg, owner_principal=owner_principal, owner_tenant=owner_tenant,
            pinned_run_context_locator=ident["run_context_locator"], pinned_pre_head_registry_locators=pre_locs,
        )
        _verify_repo_pre_head_registries(
            repo_path, pins_obj.pinned_pre_head_registry_locators, cfg_d=cfg_d, profiles=profiles, store=store
        )
        return pins_obj


def _resolve_d4_pins(
    pins: InstallationPins, *, config: Mapping[str, Any], head_1_reg: Mapping[str, Any], repo_root: Path | None = None
) -> tuple[dict[str, Any], tuple[dict[str, Any], ...]]:
    require(isinstance(pins, InstallationPins), "invalid installation pins")
    require(isinstance(head_1_reg, Mapping) and type(head_1_reg.get("epoch")) is int and head_1_reg["epoch"] >= 1, "invalid head_1_reg epoch")
    h1_epoch = head_1_reg["epoch"]
    if isinstance(pins, Gov1InstallationPins):
        require(len(pins.pinned_pre_head_registry_locators) == h1_epoch - 1, "pre-head registry locator count mismatch against head_1_reg epoch")
        return copy.deepcopy(pins.pinned_run_context_locator), tuple(copy.deepcopy(loc) for loc in pins.pinned_pre_head_registry_locators)
    require(isinstance(config, Mapping) and config.get("public_key_base64") == decomposition_governance.ANCHOR_PUBLIC, "base InstallationPins fallback requires ANCHOR_PUBLIC")
    require(h1_epoch <= 4, "base InstallationPins fallback requires head_1_reg epoch <= 4")
    ident = decomposition_governance.verified_run_context_identity(Path(repo_root) if repo_root is not None else REPO_ROOT)
    base_3 = (ident["gate2_registry_locator"], ident["run_registry_locator"], ident["prerequisite_epoch3_registry_locator"])
    return copy.deepcopy(ident["run_context_locator"]), tuple(copy.deepcopy(loc) for loc in base_3[: h1_epoch - 1])


def _validate_anchor_signed_registry_entries(
    reg_obj: Mapping[str, Any], config: Mapping[str, Any], label: str
) -> dict[str, dict[str, Any]]:
    if not isinstance(reg_obj, Mapping) or not isinstance(config, Mapping):
        raise ValueError(f"admission: {label} and config must be JSON objects")
    reg_d, cfg_d = dict(reg_obj), dict(config)
    exact_fields(reg_d, {"$schema", "trust_anchor_id", "epoch", "issued_at_utc", "entries", "integrity"}, label)
    require(reg_d["$schema"] == REGISTRY, f"{label} schema mismatch")
    require(reg_d["trust_anchor_id"] == cfg_d.get("trust_anchor_id"), f"{label} trust_anchor_id mismatch")
    require(
        isinstance(reg_d["integrity"], Mapping) and reg_d["integrity"].get("key_registry_snapshot_locator") is None,
        f"{label} must use external trust anchor",
    )
    require(type(reg_d["epoch"]) is int and reg_d["epoch"] >= 1, f"{label} invalid epoch")
    validity(dict(cfg_d["validity"]), reg_d["issued_at_utc"])
    p1.verify_envelope(reg_d, "SMART-ADS:KEY-REGISTRY:V1\n", public_key(cfg_d))
    require(isinstance(reg_d["entries"], list) and bool(reg_d["entries"]), f"{label} empty entries")
    by_id: dict[str, dict[str, Any]] = {}
    seen_pub: set[bytes] = set()
    for entry in reg_d["entries"]:
        exact_fields(entry, {"key_id", "public_key_base64", "public_key_sha256", "principal", "tenant", "role", "validity", "lifecycle_state", "allowed_actions"}, f"{label}.entry")
        raw = public_key(entry)
        require(entry["key_id"] == p1.key_id_for(raw) and entry["key_id"] not in by_id and raw not in seen_pub, f"{label} duplicate or invalid key")
        require(entry["lifecycle_state"] in _LIFECYCLE_TRANSITIONS, f"{label} invalid lifecycle_state")
        seen_pub.add(raw)
        by_id[entry["key_id"]] = entry
    return by_id


def _verify_d4_registry_lineage_step(
    older_reg: dict[str, Any], newer_reg: dict[str, Any], config: dict[str, Any]
) -> None:
    old_by_id = _validate_anchor_signed_registry_entries(older_reg, config, "older_registry")
    new_by_id = _validate_anchor_signed_registry_entries(newer_reg, config, "newer_registry")
    require(older_reg["epoch"] + 1 == newer_reg["epoch"], "registry lineage epoch skipped or out of order")
    require(timestamp(older_reg["issued_at_utc"]) <= timestamp(newer_reg["issued_at_utc"]), "registry lineage issued_at_utc reversed")
    for key_id, old_entry in old_by_id.items():
        require(key_id in new_by_id, f"registry lineage dropped historical key {key_id}")
        new_entry = new_by_id[key_id]
        require(
            canonicalize({k: old_entry[k] for k in _IMMUTABLE_KEY_FIELDS}) == canonicalize({k: new_entry[k] for k in _IMMUTABLE_KEY_FIELDS}),
            f"registry lineage mutated immutable identity of {key_id}",
        )
        old_state, new_state = old_entry["lifecycle_state"], new_entry["lifecycle_state"]
        require(new_state in _LIFECYCLE_TRANSITIONS[old_state], f"non-monotonic key lifecycle transition {old_state!r} -> {new_state!r} for {key_id}")


def _verify_d4_registry_membership(
    historical_reg: dict[str, Any],
    chain_registries_by_epoch: Mapping[int, bytes],
    *,
    label: str,
) -> None:
    require(
        isinstance(historical_reg, Mapping) and type(historical_reg.get("epoch")) is int,
        f"{label}: invalid historical registry",
    )
    epoch = historical_reg["epoch"]
    expected = chain_registries_by_epoch.get(epoch) if isinstance(chain_registries_by_epoch, Mapping) else None
    require(
        type(expected) is bytes and canonicalize(dict(historical_reg)) == expected,
        f"{label}: registry epoch {epoch} is not a canonical member of chain_registries_by_epoch",
    )


def _collect_head_chain_registries(
    store: Store,
    head_locator: dict[str, Any],
    config: dict[str, Any],
    profiles: dict[str, Any],
) -> list[dict[str, Any]]:
    regs_rev: list[dict[str, Any]] = []
    cur_loc: dict[str, Any] | None = head_locator
    for _ in range(256):
        require(isinstance(cur_loc, dict), "head chain locator missing")
        head_obj = load_object(store, cur_loc, HEAD)
        state_obj = load_object(store, head_obj["current_state_locator"], STATE)
        regs_rev.append(registry(store, state_obj["registry_locator"], config, profiles))
        if head_obj["epoch"] == 1:
            regs_rev.reverse()
            return regs_rev
        cur_loc = head_obj["predecessor_head_locator"]
    raise ValueError("admission: head chain exceeds 256 links")


def _reconstruct_d4_registry_chain(
    store: Store,
    *,
    head_locator: dict[str, Any],
    pins: InstallationPins,
    config: dict[str, Any],
    profiles: dict[str, Any],
    repo_root: Path | None = None,
) -> tuple[dict[str, Any], Mapping[int, bytes]]:
    head_regs = _collect_head_chain_registries(store, head_locator, config, profiles)
    pinned_run_ctx, pre_locs = _resolve_d4_pins(
        pins, config=config, head_1_reg=head_regs[0], repo_root=repo_root
    )
    regs_by_epoch: dict[int, dict[str, Any]] = {}
    bytes_by_epoch: dict[int, bytes] = {}
    for expected_ep, loc in enumerate(pre_locs, start=1):
        pre_reg = registry(store, loc, config, profiles)
        require(pre_reg["epoch"] == expected_ep, f"pre-head registry expected epoch {expected_ep}")
        regs_by_epoch[expected_ep] = pre_reg
        bytes_by_epoch[expected_ep] = canonicalize(pre_reg)
    for h_reg in head_regs:
        ep = h_reg["epoch"]
        raw_b = canonicalize(h_reg)
        require(ep >= head_regs[0]["epoch"], "head registry epoch precedes head_1_reg")
        if ep in bytes_by_epoch:
            require(bytes_by_epoch[ep] == raw_b, "same-epoch registry fork on head chain")
        else:
            regs_by_epoch[ep] = h_reg
            bytes_by_epoch[ep] = raw_b
    tip_epoch = head_regs[-1]["epoch"]
    require(
        type(tip_epoch) is int
        and tip_epoch >= 1
        and len(regs_by_epoch) == tip_epoch
        and all(1 <= ep <= tip_epoch for ep in regs_by_epoch),
        "non-contiguous D4 registry epoch sequence in 1..tip_reg",
    )
    for ep in range(1, tip_epoch):
        _verify_d4_registry_lineage_step(regs_by_epoch[ep], regs_by_epoch[ep + 1], config)
    return pinned_run_ctx, MappingProxyType(bytes_by_epoch)


def _enforce_pinned_run_context_locator(
    envelope: Mapping[str, Any], pinned_run_ctx_loc: Mapping[str, Any], schema: str
) -> None:
    if schema not in _SEVEN_GOV1_RUN_CTX_SCHEMAS:
        return
    require("migration_run_context_locator" in envelope, f"{schema}: missing migration_run_context_locator")
    require(
        isinstance(envelope["migration_run_context_locator"], Mapping)
        and canonicalize(dict(envelope["migration_run_context_locator"])) == canonicalize(dict(pinned_run_ctx_loc)),
        f"{schema}: migration_run_context_locator mismatch against installation pins",
    )


def _collect_13_unique_git_locators(
    cert7a_env: Mapping[str, Any], drv_env: Mapping[str, Any]
) -> list[dict[str, Any]]:
    pkt = drv_env.get("legacy_source_packet")
    members = pkt.get("members") if isinstance(pkt, Mapping) else None
    require(
        type(members) is list and len(members) == len(PINNED_PIPEBOARD_D26_SPECS),
        "pipeboard_phase1_contract: expected 5 legacy_source_packet.members",
    )
    for m in members:
        require(isinstance(m, Mapping), "legacy_source_packet.member: expected Mapping")
        exact_fields(dict(m), {"role", "repository", "commit_sha", "path", "git_blob_oid", "file_content_sha256", "git_artifact_provenance_locator"}, "legacy_source_packet.member")
    raw_locs: list[Any] = [
        *(m["git_artifact_provenance_locator"] for m in members),
        *cert7a_env["parser_artifact_locators"],
        *cert7a_env["adapter_artifact_locators"],
        *cert7a_env["mapping_artifact_locators"],
        cert7a_env["fixture_evidence"]["corpus_git_locator"],
    ]
    by_bytes: dict[bytes, dict[str, Any]] = {}
    for loc in raw_locs:
        require(isinstance(loc, dict), "git_artifact_provenance locator must be a JSON object")
        validate_locator(loc, GIT_ARTIFACT_PROVENANCE_SCHEMA)
        by_bytes[canonicalize(loc)] = copy.deepcopy(loc)
    require(len(by_bytes) == 13, "expected exactly 13 unique git_artifact_provenance/v1 locators")
    return [by_bytes[k] for k in sorted(by_bytes.keys())]


def _authenticate_contract_and_snapshot_leaves(
    verifier: Any,
    cert7a_env: Mapping[str, Any],
    *,
    t_earliest_7a: str,
    certified_at_utc: str,
    config: dict[str, Any],
    reg: dict[str, Any],
    clock: ClockInterval,
    chain_registries_by_epoch: Mapping[int, bytes],
) -> tuple[dict[str, Any], list[tuple[dict[str, Any], str, str]], list[tuple[dict[str, Any], dict[str, Any], str, str]], list[dict[str, Any]]]:
    cap = cert7a_env.get("capability")
    require(isinstance(cap, dict) and "driver_contract_locator" in cap and "registry_snapshot_locator" in cap, "certification_7a_record: invalid capability")
    drv_loc = cap["driver_contract_locator"]
    drv_env = load_object(verifier.store, drv_loc, PIPEBOARD_CONTRACT_SCHEMA)
    drv_signer, drv_act = verifier._verify_signer_authority(
        drv_env, schema=PIPEBOARD_CONTRACT_SCHEMA, event_time_utc=t_earliest_7a,
        config=config, reg=reg, clock=clock, chain_registries_by_epoch=chain_registries_by_epoch,
    )
    validity(drv_signer["validity"], certified_at_utc)

    snap_loc = cap["registry_snapshot_locator"]
    snap_env = verify_private_registry_snapshot_envelope(load_object(verifier.store, snap_loc, PRIVATE_REGISTRY_SNAPSHOT_SCHEMA), require_signed=True)
    snap_signer, snap_act = verifier._verify_signer_authority(
        snap_env, schema=PRIVATE_REGISTRY_SNAPSHOT_SCHEMA, event_time_utc=snap_env["issued_at_utc"],
        config=config, reg=reg, clock=clock, chain_registries_by_epoch=chain_registries_by_epoch,
    )
    snap_win = {"from": snap_env["issued_at_utc"], "until": snap_env["valid_until_utc"]}
    validity(snap_win, t_earliest_7a)
    validity(snap_win, certified_at_utc)
    reqs = [(drv_signer, PIPEBOARD_CONTRACT_SCHEMA, drv_act), (snap_signer, PRIVATE_REGISTRY_SNAPSHOT_SCHEMA, snap_act)]
    admitted = [
        (drv_loc, drv_env, PIPEBOARD_CONTRACT_SCHEMA, t_earliest_7a),
        (snap_loc, snap_env, PRIVATE_REGISTRY_SNAPSHOT_SCHEMA, snap_env["issued_at_utc"]),
    ]
    return drv_env, reqs, admitted, [drv_env, snap_env]


def _authenticate_d4_7a_leaf_envelopes(
    verifier: Any,
    cert7a_env: dict[str, Any],
    *,
    config: dict[str, Any],
    reg: dict[str, Any],
    clock: ClockInterval,
    chain_registries_by_epoch: Mapping[int, bytes],
) -> tuple[list[tuple[dict[str, Any], str, str]], list[tuple[dict[str, Any], dict[str, Any], str, str]], list[dict[str, Any]]]:
    ev = cert7a_env.get("fixture_evidence")
    cases = ev.get("cases") if isinstance(ev, Mapping) else None
    require(type(cases) is list and len(cases) > 0, "certification_7a_record: missing fixture_evidence.cases")
    for c in cases:
        require(isinstance(c, dict) and "started_at_utc" in c and "expected_resource_inventory_locator" in c, "invalid 7A case")
    certified_at_utc = cert7a_env["certified_at_utc"]
    t_earliest_7a = min(cases, key=lambda c: timestamp(c["started_at_utc"]))["started_at_utc"]
    drv_env, reqs, admitted, objs = _authenticate_contract_and_snapshot_leaves(
        verifier, cert7a_env, t_earliest_7a=t_earliest_7a, certified_at_utc=certified_at_utc,
        config=config, reg=reg, clock=clock, chain_registries_by_epoch=chain_registries_by_epoch,
    )
    inv_by_b: dict[bytes, tuple[dict[str, Any], list[dict[str, Any]]]] = {}
    for c in cases:
        loc = c["expected_resource_inventory_locator"]
        validate_locator(loc, EXPECTED_RESOURCE_INVENTORY_SCHEMA)
        inv_by_b.setdefault(canonicalize(loc), (copy.deepcopy(loc), []))[1].append(c)
    for inv_b in sorted(inv_by_b.keys()):
        inv_loc, inv_cases = inv_by_b[inv_b]
        t_inv = min(inv_cases, key=lambda c: timestamp(c["started_at_utc"]))["started_at_utc"]
        inv_env = verify_expected_resource_inventory_envelope(load_object(verifier.store, inv_loc, EXPECTED_RESOURCE_INVENTORY_SCHEMA), require_signed=True)
        inv_s, inv_act = verifier._verify_signer_authority(
            inv_env, schema=EXPECTED_RESOURCE_INVENTORY_SCHEMA, event_time_utc=t_inv,
            config=config, reg=reg, clock=clock, chain_registries_by_epoch=chain_registries_by_epoch,
        )
        validity(inv_s["validity"], certified_at_utc)
        reqs.append((inv_s, EXPECTED_RESOURCE_INVENTORY_SCHEMA, inv_act))
        admitted.append((inv_loc, inv_env, EXPECTED_RESOURCE_INVENTORY_SCHEMA, t_inv))
        objs.append(inv_env)
    for git_loc in _collect_13_unique_git_locators(cert7a_env, drv_env):
        git_env = verify_git_artifact_provenance_envelope(load_object(verifier.store, git_loc, GIT_ARTIFACT_PROVENANCE_SCHEMA), require_signed=True)
        require(timestamp(git_env["resolved_at_utc"]) <= timestamp(certified_at_utc), "git_artifact_provenance resolved_at_utc > certified_at_utc")
        git_s, git_act = verifier._verify_signer_authority(
            git_env, schema=GIT_ARTIFACT_PROVENANCE_SCHEMA, event_time_utc=git_env["resolved_at_utc"],
            config=config, reg=reg, clock=clock, chain_registries_by_epoch=chain_registries_by_epoch,
        )
        reqs.append((git_s, GIT_ARTIFACT_PROVENANCE_SCHEMA, git_act))
        admitted.append((git_loc, git_env, GIT_ARTIFACT_PROVENANCE_SCHEMA, git_env["resolved_at_utc"]))
        objs.append(git_env)
    return reqs, admitted, objs


@contextlib.contextmanager
def _disposable_wheel_path(wheel_bytes: bytes) -> Iterator[Path]:
    if type(wheel_bytes) is not bytes or len(wheel_bytes) == 0:
        raise ValueError("wheel_bytes: expected non-empty bytes")
    with tempfile.TemporaryDirectory(prefix="gov1-disposable-whl-") as tmp_dir:
        disposable_whl = Path(tmp_dir) / EXPECTED_WHEEL_FILENAME
        disposable_whl.write_bytes(wheel_bytes)
        os.chmod(disposable_whl, 0o444)
        yield disposable_whl


def _run_disposable_stage7_material_handoff(
    *, wheel_bytes: bytes, seccomp_profile: dict[str, Any], sandbox_obj: dict[str, Any],
    prov_obj: dict[str, Any], bound_obj: dict[str, Any], mcp_obj: dict[str, Any], repo_dir: Path,
    backend_wheel_dir: Path | None = None, site_packages_dir: Path | None = None,
    probe_runner: IsolatedWheelProbeRunner | None = None,
) -> tuple[str, dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    seccomp_digest = verify_seccomp_profile(seccomp_profile)
    sbx_res = verify_sealed_sandbox_profile(sandbox_obj, seccomp_profile=seccomp_profile)
    with _disposable_wheel_path(wheel_bytes) as disposable_whl:
        prov_res = verify_wheel_build_provenance(
            prov_obj, repo_root=repo_dir, wheel_path=disposable_whl,
            backend_wheel_dir=backend_wheel_dir, site_packages_dir=site_packages_dir, probe_runner=probe_runner,
        )
        bound_res = verify_wheel_boundary_report(bound_obj, wheel_path=disposable_whl, probe_runner=probe_runner)
        mcp_res = verify_mcp_rejection_matrix_report(mcp_obj, wheel_path=disposable_whl, probe_runner=probe_runner)
    if prov_res["wheel_digest"] != digest(wheel_bytes):
        raise ValueError("wheel_build_provenance: wheel_digest mismatch against captured wheel_bytes")
    if canonicalize(prov_res["payload"]) != canonicalize(extract_provenance_payload(prov_obj)):
        raise ValueError("wheel_build_provenance: recomputed payload diverges from extract_provenance_payload")
    return seccomp_digest, sbx_res, prov_res, bound_res, mcp_res


def build_gov1_convergence_record_candidate(
    *, migration_run_context_locator: Mapping[str, Any], wheel_boundary_report_candidate_ref: Mapping[str, Any],
    sealed_sandbox_profile_candidate_ref: Mapping[str, Any], negative_security_test_report_candidate_ref: Mapping[str, Any],
    mcp_rejection_matrix_report_candidate_ref: Mapping[str, Any], certification_7a_record_candidate_ref: Mapping[str, Any],
    build_run_id: str, converged_at_utc: str, source_commit_sha: str, wheel_digest: str,
    build_backend_digest: str, schema_bundle_digest: str, convergence_status: str = "PASS",
) -> dict[str, Any]:
    """Build a non-signable `gov1_local_candidate` for `smart_ads/gov1_convergence_record/v1`."""
    run_ctx = copy.deepcopy(dict(migration_run_context_locator))
    validate_locator(run_ctx, _RUN_CONTEXT_SCHEMA)
    refs = {
        "wheel_boundary_report_candidate_ref": (copy.deepcopy(dict(wheel_boundary_report_candidate_ref)), WHEEL_BOUNDARY_REPORT_SCHEMA),
        "sealed_sandbox_profile_candidate_ref": (copy.deepcopy(dict(sealed_sandbox_profile_candidate_ref)), SANDBOX_PROFILE_SCHEMA),
        "negative_security_test_report_candidate_ref": (copy.deepcopy(dict(negative_security_test_report_candidate_ref)), NEGATIVE_SECURITY_REPORT_SCHEMA),
        "mcp_rejection_matrix_report_candidate_ref": (copy.deepcopy(dict(mcp_rejection_matrix_report_candidate_ref)), MCP_REJECTION_REPORT_SCHEMA),
        "certification_7a_record_candidate_ref": (copy.deepcopy(dict(certification_7a_record_candidate_ref)), CERTIFICATION_7A_SCHEMA),
    }
    for ref_d, exp_schema in refs.values():
        verify_local_candidate_ref(ref_d, expected_schema=exp_schema)
    timestamp(converged_at_utc)
    if type(convergence_status) is not str or convergence_status != "PASS":
        raise ValueError("convergence_status: expected exact string 'PASS'")
    payload = {
        "migration_run_context_locator": run_ctx, **{k: v[0] for k, v in refs.items()},
        "build_run_id": _strict_str(build_run_id, "build_run_id"), "converged_at_utc": converged_at_utc,
        "source_commit_sha": _git_oid_str(source_commit_sha, "source_commit_sha"),
        "wheel_digest": _sha256_str(wheel_digest, "wheel_digest"),
        "build_backend_digest": _sha256_str(build_backend_digest, "build_backend_digest"),
        "schema_bundle_digest": _sha256_str(schema_bundle_digest, "schema_bundle_digest"), "convergence_status": "PASS",
    }
    loads_strict(canonicalize(payload).decode("utf-8"))
    return wrap_local_candidate(GOV1_CONVERGENCE_SCHEMA, payload)


def _unwrap_candidate_only(artifact: object, expected_schema: str, label: str) -> dict[str, Any]:
    if not isinstance(artifact, dict) or artifact.get("artifact_kind") != LOCAL_CANDIDATE_KIND or "$schema" in artifact or "integrity" in artifact:
        raise ValueError(f"{label}: expected {LOCAL_CANDIDATE_KIND!r} without envelope fields")
    return unwrap_local_candidate(artifact, expected_schema=expected_schema)


def _verify_candidate_convergence_cross_bindings(
    *, sbx_cand: dict[str, Any], prov_cand: dict[str, Any], bound_cand: dict[str, Any], mcp_cand: dict[str, Any],
    neg_cand: dict[str, Any], cert_cand: dict[str, Any], conv_cand: dict[str, Any], wheel_bytes: bytes,
) -> dict[str, Any]:
    sbx_p = _unwrap_candidate_only(sbx_cand, SANDBOX_PROFILE_SCHEMA, "sandbox_profile")
    prov_p = _unwrap_candidate_only(prov_cand, WHEEL_BUILD_PROVENANCE_SCHEMA, "wheel_provenance")
    bound_p = _unwrap_candidate_only(bound_cand, WHEEL_BOUNDARY_REPORT_SCHEMA, "wheel_boundary_report")
    mcp_p = _unwrap_candidate_only(mcp_cand, MCP_REJECTION_REPORT_SCHEMA, "mcp_rejection_report")
    neg_p = _unwrap_candidate_only(neg_cand, NEGATIVE_SECURITY_REPORT_SCHEMA, "negative_security_report")
    cert_p = _unwrap_candidate_only(cert_cand, CERTIFICATION_7A_SCHEMA, "certification_7a_record")
    conv_p = _unwrap_candidate_only(conv_cand, GOV1_CONVERGENCE_SCHEMA, "convergence_candidate")
    exact_fields(conv_p, _GOV1_CONVERGENCE_CANDIDATE_PAYLOAD_FIELDS, "gov1_convergence_candidate_payload")
    if conv_p["convergence_status"] != "PASS" or conv_p["wheel_digest"] != digest(wheel_bytes) or prov_p.get("repository") != DEFAULT_REPOSITORY or bound_p.get("repository") != DEFAULT_REPOSITORY:
        raise ValueError("verify_gov1_convergence_candidate: status, wheel_digest, or repository mismatch")
    sbx_ref_b, prov_ref_b = canonicalize(build_local_candidate_ref(sbx_cand)), canonicalize(build_local_candidate_ref(prov_cand))
    bound_ref_b, mcp_ref_b = canonicalize(build_local_candidate_ref(bound_cand)), canonicalize(build_local_candidate_ref(mcp_cand))
    neg_ref_b, cert_ref_b = canonicalize(build_local_candidate_ref(neg_cand)), canonicalize(build_local_candidate_ref(cert_cand))
    if (
        canonicalize(conv_p["sealed_sandbox_profile_candidate_ref"]) != sbx_ref_b
        or canonicalize(conv_p["wheel_boundary_report_candidate_ref"]) != bound_ref_b
        or canonicalize(conv_p["mcp_rejection_matrix_report_candidate_ref"]) != mcp_ref_b
        or canonicalize(conv_p["negative_security_test_report_candidate_ref"]) != neg_ref_b
        or canonicalize(conv_p["certification_7a_record_candidate_ref"]) != cert_ref_b
        or canonicalize(bound_p.get("wheel_build_provenance_candidate_ref")) != prov_ref_b
        or canonicalize(neg_p.get("wheel_build_provenance_candidate_ref")) != prov_ref_b
        or canonicalize(cert_p.get("wheel_build_provenance_candidate_ref")) != prov_ref_b
        or canonicalize(mcp_p.get("sealed_sandbox_profile_candidate_ref")) != sbx_ref_b
        or canonicalize(neg_p.get("sealed_sandbox_profile_candidate_ref")) != sbx_ref_b
        or canonicalize(cert_p.get("sealed_sandbox_profile_candidate_ref")) != sbx_ref_b
        or canonicalize(cert_p.get("wheel_boundary_report_candidate_ref")) != bound_ref_b
        or canonicalize(cert_p.get("negative_security_test_report_candidate_ref")) != neg_ref_b
    ):
        raise ValueError("verify_gov1_convergence_candidate: candidate_ref cross-binding mismatch")
    _verify_candidate_scalars_and_chronology(conv_p, sbx_p, prov_p, bound_p, mcp_p, neg_p, cert_p)
    return conv_p


def _verify_candidate_scalars_and_chronology(
    conv_p: Mapping[str, Any], sbx_p: Mapping[str, Any], prov_p: Mapping[str, Any], bound_p: Mapping[str, Any],
    mcp_p: Mapping[str, Any], neg_p: Mapping[str, Any], cert_p: Mapping[str, Any],
) -> None:
    run_ctx_b = canonicalize(conv_p["migration_run_context_locator"])
    for p in (sbx_p, prov_p, bound_p, mcp_p, neg_p, cert_p):
        if canonicalize(p.get("migration_run_context_locator")) != run_ctx_b:
            raise ValueError("verify_gov1_convergence_candidate: migration_run_context_locator mismatch")
    for p in (prov_p, bound_p, mcp_p, neg_p, cert_p):
        for k in ("build_run_id", "source_commit_sha", "wheel_digest", "build_backend_digest", "schema_bundle_digest"):
            if p.get(k) != conv_p[k]:
                raise ValueError(f"verify_gov1_convergence_candidate: {k} mismatch")
    validity(dict(sbx_p["validity"]), mcp_p["executed_at_utc"])
    validity(dict(sbx_p["validity"]), neg_p["executed_at_utc"])
    conv_dt = timestamp(conv_p["converged_at_utc"])
    if (
        timestamp(bound_p["verified_at_utc"]) < timestamp(prov_p["built_at_utc"])
        or timestamp(cert_p["certified_at_utc"]) < timestamp(neg_p["executed_at_utc"])
        or any(conv_dt < timestamp(t) for t in (sbx_p["issued_at_utc"], prov_p["built_at_utc"], bound_p["verified_at_utc"], mcp_p["executed_at_utc"], neg_p["executed_at_utc"], cert_p["certified_at_utc"]))
    ):
        raise ValueError("verify_gov1_convergence_candidate: constituent chronology or anti-backdating violation")


def verify_gov1_convergence_candidate(
    *, repo_root: Path, wheel_path: Path, corpus_path: Path, seccomp_profile: dict[str, Any],
    sandbox_profile: dict[str, Any], wheel_provenance: dict[str, Any], wheel_boundary_report: dict[str, Any],
    mcp_rejection_report: dict[str, Any], negative_security_report: dict[str, Any],
    certification_7a_record: dict[str, Any], convergence_candidate: dict[str, Any], store: Store,
    legacy_repo: Path | None = None, legacy_blobs_dir: Path | None = None,
    backend_wheel_dir: Path | None = None, site_packages_dir: Path | None = None,
    probe_runner: IsolatedWheelProbeRunner | None = None,
) -> dict[str, Any]:
    """Verify `gov1_convergence_record/v1` in candidate mode with ordered Stage-7 -> passive 7A handoff."""
    if not isinstance(store, Store) or not isinstance(seccomp_profile, dict) or not isinstance(repo_root, (str, os.PathLike)):
        raise ValueError("verify_gov1_convergence_candidate: invalid store, seccomp_profile, or repo_root")
    repo_dir = Path(repo_root)
    _, wheel_bytes = _read_nonempty_regular_file(wheel_path, "wheel_path")
    _, corpus_bytes = _read_nonempty_regular_file(corpus_path, "corpus_path")
    conv_p = _verify_candidate_convergence_cross_bindings(
        sbx_cand=sandbox_profile, prov_cand=wheel_provenance, bound_cand=wheel_boundary_report,
        mcp_cand=mcp_rejection_report, neg_cand=negative_security_report, cert_cand=certification_7a_record,
        conv_cand=convergence_candidate, wheel_bytes=wheel_bytes,
    )
    cert7a = _cert7a_mod()
    resolved_git_blobs = cert7a.resolve_7a_smart_ads_git_blobs(repo_dir, conv_p["source_commit_sha"])
    if corpus_bytes != resolved_git_blobs.get(cert7a.CORPUS_GIT_PATH[1]):
        raise ValueError("verify_gov1_convergence_candidate: corpus_path bytes disagree with Git blob at source_commit_sha")
    resolved_d26_blobs = gov1_7a_runner.resolve_pinned_pipeboard_d26_blobs(legacy_repo=legacy_repo, legacy_blobs_dir=legacy_blobs_dir)
    _, _, prov_res, _, _ = _run_disposable_stage7_material_handoff(
        wheel_bytes=wheel_bytes, seccomp_profile=seccomp_profile, sandbox_obj=sandbox_profile,
        prov_obj=wheel_provenance, bound_obj=wheel_boundary_report, mcp_obj=mcp_rejection_report,
        repo_dir=repo_dir, backend_wheel_dir=backend_wheel_dir, site_packages_dir=site_packages_dir, probe_runner=probe_runner,
    )
    verified_prov_cand = wrap_local_candidate(WHEEL_BUILD_PROVENANCE_SCHEMA, prov_res["payload"])
    if canonicalize(verified_prov_cand) != canonicalize(wheel_provenance):
        raise ValueError("verify_gov1_convergence_candidate: verified provenance candidate mismatch")
    neg_res = verify_negative_security_test_report(
        negative_security_report, sandbox_profile=sandbox_profile, wheel_provenance=verified_prov_cand, wheel_bytes=wheel_bytes
    )
    cert_res = cert7a.verify_certification_7a_replay_bytes(
        certification_7a_record, store=store, wheel_bytes=wheel_bytes, corpus_bytes=corpus_bytes,
        resolved_git_blobs=resolved_git_blobs, resolved_d26_blobs=resolved_d26_blobs,
        sandbox_profile=sandbox_profile, wheel_provenance=verified_prov_cand,
        wheel_boundary_report=wheel_boundary_report, negative_security_report=negative_security_report,
    )
    return {
        "mode": "candidate", "schema": GOV1_CONVERGENCE_SCHEMA, "convergence_status": "PASS",
        "signable": False, "authority": "none", "wheel_digest": conv_p["wheel_digest"],
        "source_commit_sha": conv_p["source_commit_sha"], "schema_bundle_digest": conv_p["schema_bundle_digest"],
        "converged_at_utc": conv_p["converged_at_utc"], "negative_executed_at_utc": neg_res["executed_at_utc"],
        "certified_at_utc": cert_res["certified_at_utc"], "payload": copy.deepcopy(conv_p),
    }


def _reload_and_verify_d4_external_7a_inputs(
    *, wheel_path: Path, expected_wheel_bytes: bytes, corpus_path: Path, expected_corpus_bytes: bytes,
    repo_dir: Path, source_commit_sha: str, expected_git_blobs: Mapping[str, bytes],
    legacy_repo: Path | None, legacy_blobs_dir: Path | None, expected_d26_blobs: Mapping[str, bytes],
) -> None:
    _, reloaded_whl = _read_nonempty_regular_file(wheel_path, "wheel_path")
    require(reloaded_whl == expected_wheel_bytes, "wheel_path bytes mutated during admission")
    _, reloaded_corpus = _read_nonempty_regular_file(corpus_path, "corpus_path")
    require(reloaded_corpus == expected_corpus_bytes, "corpus_path bytes mutated during admission")
    reloaded_git = _cert7a_mod().resolve_7a_smart_ads_git_blobs(repo_dir, source_commit_sha)
    require(dict(reloaded_git) == dict(expected_git_blobs), "smart_ads Git blobs mutated during admission")
    reloaded_d26 = gov1_7a_runner.resolve_pinned_pipeboard_d26_blobs(legacy_repo=legacy_repo, legacy_blobs_dir=legacy_blobs_dir)
    require(dict(reloaded_d26) == dict(expected_d26_blobs), "pinned d26 legacy blobs mutated during admission")


__all__ = "Gov1InstallationPins SnapshotStore _D4_SCHEMA_ROLE_ACTION_SPECS _SEVEN_GOV1_RUN_CTX_SCHEMAS _authenticate_d4_7a_leaf_envelopes _cert7a_mod _disposable_wheel_path _enforce_pinned_run_context_locator _read_nonempty_regular_file _reconstruct_d4_registry_chain _reload_and_verify_d4_external_7a_inputs _resolve_d4_pins _run_disposable_stage7_material_handoff _verify_d4_registry_lineage_step _verify_d4_registry_membership build_gov1_convergence_record_candidate verify_gov1_convergence_candidate".split()
