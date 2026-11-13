"""Executable and recomputable zero-I/O MCP rejection matrix report (`ADR-0001 §3.3`).

Implements `smart_ads/mcp_rejection_matrix_report/v1`:
- Validates wheel archive/RECORD/AST/import boundary via `inspect_wheel_boundary`;
- Extracts only `wheel_path` into a fresh clean `venv` outside the repository and runs a
  zero-`assert` subprocess under `python -I -B` (with sanitized environment and verified
  absence of `REPO_ROOT` / `REPO_ROOT/src` from `sys.path`);
- Executes all 11 normative `ADR-0001 §3.3` rejection cases in raw UTF-8 byte order plus
  the positive `65,536`-byte vs `65,537`-byte boundary probe against 6 external I/O adapter
  spies (`registry`, `audit`, `filesystem`, `credential`, `provider`, `network`) and a spy
  `McpReadHandlerPort`;
- Builds and materially verifies both `gov1_local_candidate` and P1-signable envelopes by
  recomputing the full matrix against `wheel_path`.
"""
from __future__ import annotations

import copy
import io
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from typing import Any, Final
import venv
import zipfile
import zlib

from tools.governance import p1
from tools.governance.gov1_sandbox import (
    LOCAL_CANDIDATE_KIND,
    SANDBOX_PROFILE_SCHEMA,
    unwrap_local_candidate,
    verify_local_candidate_ref,
    wrap_local_candidate,
)
from tools.governance.gov1_wheel import (
    inspect_wheel_boundary,
    verify_contiguous_zip_layout,
)
from tools.governance.jcs import canonicalize, loads_strict
from tools.governance.locator import (
    digest,
    exact_fields,
    json_digest,
    source_path,
    timestamp,
    validate_locator,
)

MCP_REJECTION_REPORT_SCHEMA: Final[str] = "smart_ads/mcp_rejection_matrix_report/v1"

_RUN_CONTEXT_SCHEMA: Final[str] = "smart_ads/migration_run_context/v1"
_KEY_REGISTRY_SCHEMA: Final[str] = "smart_ads/key_authorization_registry/v1"

_EXPECTED_ALLOWED_MCP_METHODS: Final[tuple[str, ...]] = (
    "smart_ads.queries.get_ad_performance_v1",
    "smart_ads.queries.get_adset_performance_v1",
    "smart_ads.queries.get_campaign_performance_v1",
    "smart_ads.queries.get_intelligence_findings_v1",
    "smart_ads.reports.generate_recurrent_summary_v1",
)

# Immutable primitive source of truth for ADR-0001 §3.3 L235-245 sorted by UTF-8 bytes of case_id.
_NORMATIVE_MCP_MATRIX_ROWS: Final[tuple[tuple[str, int, str, str], ...]] = (
    ("additional_property", -32602, "Invalid params", "validated_request_id"),
    ("batch_array", -32600, "Invalid Request", "null"),
    ("body_over_64k", -32600, "Invalid Request", "null"),
    ("duplicate_json_key", -32600, "Invalid Request", "null"),
    ("invalid_params", -32602, "Invalid params", "validated_request_id"),
    ("invalid_utf8", -32700, "Parse error", "null"),
    ("malformed_json", -32700, "Parse error", "null"),
    (
        "missing_or_invalid_ibvi_ads_delegation",
        -32600,
        "Invalid Request",
        "validated_request_id",
    ),
    ("nesting_depth_over_8", -32600, "Invalid Request", "null"),
    ("non_object_request", -32600, "Invalid Request", "null"),
    ("unsupported_method", -32601, "Method not found", "validated_request_id"),
)

EXPECTED_MCP_MATRIX_SPECS: Final[tuple[dict[str, Any], ...]] = tuple(
    {
        "case_id": case_id,
        "expected_code": expected_code,
        "expected_message": expected_message,
        "expected_id_policy": expected_id_policy,
    }
    for case_id, expected_code, expected_message, expected_id_policy in _NORMATIVE_MCP_MATRIX_ROWS
)

_IO_COUNTER_KEYS_SORTED: Final[tuple[str, ...]] = (
    "audit_calls",
    "credential_calls",
    "filesystem_calls",
    "network_calls",
    "provider_calls",
    "registry_calls",
)
_IO_COUNTER_FIELDS: Final[set[str]] = set(_IO_COUNTER_KEYS_SORTED)

_CASE_FIELDS: Final[set[str]] = {
    "case_id",
    "expected_code",
    "observed_code",
    "expected_message",
    "observed_message",
    "expected_id_policy",
    "observed_id_matches_policy",
    "response_shape_valid",
    "io_counters",
}

_EXECUTION_FIELDS: Final[set[str]] = {
    "wheel_digest",
    "schema_bundle_digest",
    "allowed_methods",
    "body_64k_boundary_verified",
    "cases",
}

_REPORT_COMMON_PAYLOAD_FIELDS: Final[set[str]] = _EXECUTION_FIELDS | {
    "migration_run_context_locator",
    "build_run_id",
    "executed_at_utc",
    "source_commit_sha",
    "build_backend_digest",
}
_REPORT_CANDIDATE_PAYLOAD_FIELDS: Final[set[str]] = (
    _REPORT_COMMON_PAYLOAD_FIELDS | {"sealed_sandbox_profile_candidate_ref"}
)
_REPORT_ENVELOPE_PAYLOAD_FIELDS: Final[set[str]] = (
    _REPORT_COMMON_PAYLOAD_FIELDS | {"sealed_sandbox_profile_locator"}
)
_REPORT_ENVELOPE_FIELDS: Final[set[str]] = (
    {"$schema", "integrity"} | _REPORT_ENVELOPE_PAYLOAD_FIELDS
)

_UNSIGNED_INTEGRITY_FIELDS: Final[set[str]] = {
    "key_id",
    "key_registry_snapshot_locator",
}
_SIGNED_INTEGRITY_FIELDS: Final[set[str]] = _UNSIGNED_INTEGRITY_FIELDS | {
    "content_digest",
    "signature_base64",
}

_SHA256_PREFIXED_RE: Final[re.Pattern[str]] = re.compile(r"\Asha256:[0-9a-f]{64}\Z")
_GIT_OID_RE: Final[re.Pattern[str]] = re.compile(r"\A[0-9a-f]{40}\Z")
_DEFAULT_SYSTEM_BIN_DIRS: Final[tuple[str, ...]] = (
    "/opt/homebrew/bin",
    "/usr/local/bin",
    "/usr/bin",
    "/bin",
)

# Zero-assert isolated clean-venv MCP rejection matrix probe executed under `python -I -B -c`.
_MCP_MATRIX_PROBE_SCRIPT: Final[str] = """
import base64
from collections.abc import Mapping
from dataclasses import dataclass
import importlib
import json
import os
from pathlib import Path
import sys
import sysconfig
from typing import Any

if sys.implementation.name != "cpython" or tuple(sys.version_info[:2]) != (3, 12):
    raise RuntimeError("MCP matrix probe requires CPython 3.12")
if sys.flags.isolated != 1 or sys.flags.dont_write_bytecode != 1:
    raise RuntimeError("MCP matrix probe requires -I -B flags")
if os.environ.get("PYTHONPATH") is not None:
    raise RuntimeError("PYTHONPATH must be absent in isolated MCP matrix probe")
if len(sys.argv) != 5:
    raise RuntimeError("unexpected MCP matrix probe argv length")

expected_purelib = Path(sys.argv[1]).resolve()
repo_root = Path(sys.argv[2]).resolve()
repo_src = Path(sys.argv[3]).resolve()
expected_schema_digest = sys.argv[4]

stdlib_roots = {
    Path(sys.base_prefix).resolve(),
    Path(sys.base_exec_prefix).resolve(),
    Path(sysconfig.get_path("stdlib")).resolve(),
    Path(sysconfig.get_path("platstdlib")).resolve(),
}

for raw_entry in list(sys.path):
    if raw_entry == "":
        raise RuntimeError("empty string leaked into clean venv sys.path")
    resolved_entry = Path(raw_entry).resolve()
    if (
        resolved_entry == repo_root
        or resolved_entry.is_relative_to(repo_root)
        or resolved_entry == repo_src
        or resolved_entry.is_relative_to(repo_src)
    ):
        raise RuntimeError(f"repository path leaked into clean venv sys.path: {raw_entry!r}")
    if resolved_entry != expected_purelib and not any(
        resolved_entry.is_relative_to(root) for root in stdlib_roots
    ):
        raise RuntimeError(f"unexpected sys.path entry in clean venv: {raw_entry!r}")

for forbidden_mod in ("tools", "tooling"):
    try:
        importlib.import_module(forbidden_mod)
    except ModuleNotFoundError:
        pass
    else:
        raise RuntimeError(f"{forbidden_mod!r} unexpectedly importable inside clean venv")

from smart_ads.contracts import (
    ArtifactLocator,
    canonicalize_jcs,
    loads_strict_json,
    validate_resource_ref,
)
from smart_ads.contracts.schemas import compute_schema_bundle_digest
from smart_ads.transports.mcp import (
    ALLOWED_MCP_METHODS,
    MAX_MCP_BODY_BYTES,
    AdmittedMcpRequest,
    McpDelegationContext,
    McpReadHandlerPort,
    McpRuntimeContext,
    PerformanceQueryParams,
    handle_mcp_request_bytes,
)

for mod_name, mod_obj in list(sys.modules.items()):
    if mod_name == "smart_ads" or mod_name.startswith("smart_ads."):
        mod_file = getattr(mod_obj, "__file__", None)
        if (
            type(mod_file) is not str
            or mod_file.endswith((".pyc", ".pyo"))
            or not Path(mod_file).resolve().is_relative_to(expected_purelib)
        ):
            raise RuntimeError(
                f"module {mod_name!r} resolved outside clean venv purelib: {mod_file!r}"
            )

actual_schema_digest = compute_schema_bundle_digest()
if actual_schema_digest != expected_schema_digest:
    raise RuntimeError(
        f"schema_bundle_digest mismatch: {actual_schema_digest!r} != {expected_schema_digest!r}"
    )

if MAX_MCP_BODY_BYTES != 65_536:
    raise RuntimeError(f"unexpected MAX_MCP_BODY_BYTES: {MAX_MCP_BODY_BYTES!r}")

allowed_methods_list = list(ALLOWED_MCP_METHODS)
if allowed_methods_list != sorted(allowed_methods_list, key=lambda s: s.encode("utf-8")):
    raise RuntimeError("ALLOWED_MCP_METHODS is not sorted by UTF-8 bytes")


@dataclass
class _AdapterSpy:
    name: str
    calls: int = 0

    def touch(self) -> None:
        self.calls += 1


class _SixAdapterIOSpyRig:
    def __init__(self) -> None:
        self.registry = _AdapterSpy("registry")
        self.audit = _AdapterSpy("audit")
        self.filesystem = _AdapterSpy("filesystem")
        self.credential = _AdapterSpy("credential")
        self.provider = _AdapterSpy("provider")
        self.network = _AdapterSpy("network")

    def touch_all(self) -> None:
        self.registry.touch()
        self.audit.touch()
        self.filesystem.touch()
        self.credential.touch()
        self.provider.touch()
        self.network.touch()

    def counters(self) -> dict[str, int]:
        return {
            "audit_calls": self.audit.calls,
            "credential_calls": self.credential.calls,
            "filesystem_calls": self.filesystem.calls,
            "network_calls": self.network.calls,
            "provider_calls": self.provider.calls,
            "registry_calls": self.registry.calls,
        }


class _RejectionSpyHandler:
    def __init__(self, rig: _SixAdapterIOSpyRig) -> None:
        self._rig = rig
        self.calls = 0

    def handle(self, request: AdmittedMcpRequest) -> Mapping[str, Any]:
        self.calls += 1
        self._rig.touch_all()
        return {"unexpected": True}


class _PositiveBoundarySpyHandler:
    def __init__(self, rig: _SixAdapterIOSpyRig) -> None:
        self._rig = rig
        self.admitted_requests: list[AdmittedMcpRequest] = []

    def handle(self, request: AdmittedMcpRequest) -> Mapping[str, Any]:
        self.admitted_requests.append(request)
        return {"method": request.method, "rows": []}


def _make_runtime_context(*, route: str = "/ibvi-ads") -> McpRuntimeContext:
    loc = ArtifactLocator.from_digest(
        "smart_ads/ibvi_ads_delegation_context/v1",
        "sha256:" + ("a" * 64),
    )
    delegation = McpDelegationContext(
        schema="smart_ads/ibvi_ads_delegation_context/v1",
        route=route,
        host_conductor_ref="conductor:hermes-prod",
        front_ref="front:pinna",
        profile_ref="profile:pinna-ops",
        tenant_ref="tenant:ibvi",
        binding_ref="binding:meta-1",
        resource_scope_ref="scope:ibvi-1",
        allowed_method="smart_ads.queries.get_campaign_performance_v1",
        policy_digest="sha256:" + ("b" * 64),
        issued_at_utc="2026-11-12T12:00:00Z",
        valid_until_utc="2026-11-12T12:15:00Z",
        nonce="nonce-gov1-mcp-001",
        locator=loc,
    )
    return McpRuntimeContext(
        clock_lower_utc="2026-11-12T12:01:00Z",
        clock_upper_utc="2026-11-12T12:01:02Z",
        delegation_context=delegation,
    )


def _canonical_resource_ref(idx: int) -> str:
    raw_32 = idx.to_bytes(32, "big")
    encoded = base64.b32encode(raw_32).decode("ascii").rstrip("=").lower()
    return validate_resource_ref(f"resource:{encoded}")


zero_counters = {
    "audit_calls": 0,
    "credential_calls": 0,
    "filesystem_calls": 0,
    "network_calls": 0,
    "provider_calls": 0,
    "registry_calls": 0,
}
valid_rt = _make_runtime_context(route="/ibvi-ads")
invalid_route_rt = _make_runtime_context(route="/ads")

# 1. Positive 65,536-byte vs negative 65,537-byte exact wire boundary check
resource_refs_64k = sorted(
    (_canonical_resource_ref(i) for i in range(1, 1019)),
    key=lambda s: s.encode("utf-8"),
)
boundary_envelope: dict[str, Any] = {
    "jsonrpc": "2.0",
    "id": "req-",
    "method": "smart_ads.queries.get_campaign_performance_v1",
    "params": {
        "tenant_ref": "tenant:ibvi",
        "binding_ref": "binding:meta-1",
        "resource_scope_ref": "scope:ibvi-1",
        "date_range": {
            "start_date": "2026-11-01",
            "end_date": "2026-11-10",
        },
        "resource_refs": resource_refs_64k,
    },
}
base_64k_len = len(canonicalize_jcs(boundary_envelope))
delta_64k = 65_536 - base_64k_len
if not (1 <= delta_64k <= 250):
    raise RuntimeError(f"unexpected 64 KiB padding delta: {delta_64k}")
exact_64k_id = "req-" + ("z" * delta_64k)
boundary_envelope["id"] = exact_64k_id
exact_64k_body = canonicalize_jcs(boundary_envelope)
if len(exact_64k_body) != 65_536:
    raise RuntimeError(f"expected 65,536-byte payload, got {len(exact_64k_body)}")

pos_rig = _SixAdapterIOSpyRig()
pos_handler = _PositiveBoundarySpyHandler(pos_rig)
if not isinstance(pos_handler, McpReadHandlerPort):
    raise RuntimeError("positive spy handler does not satisfy McpReadHandlerPort")

outcome_64k = handle_mcp_request_bytes(exact_64k_body, valid_rt, handler=pos_handler)
if (
    outcome_64k.rejection is not None
    or outcome_64k.admitted_request is None
    or outcome_64k.admitted_request.request_id != exact_64k_id
    or not isinstance(outcome_64k.admitted_request.params, PerformanceQueryParams)
    or len(pos_handler.admitted_requests) != 1
    or pos_rig.counters() != zero_counters
):
    raise RuntimeError("65,536-byte positive boundary check failed")

decoded_64k = loads_strict_json(outcome_64k.wire_bytes)
expected_64k_wire_obj = {
    "jsonrpc": "2.0",
    "id": exact_64k_id,
    "result": {
        "method": "smart_ads.queries.get_campaign_performance_v1",
        "rows": [],
    },
}
if (
    decoded_64k != expected_64k_wire_obj
    or outcome_64k.wire_bytes != canonicalize_jcs(expected_64k_wire_obj)
):
    raise RuntimeError("65,536-byte positive wire response mismatch")

boundary_envelope["id"] = exact_64k_id + "x"
over_64k_body = canonicalize_jcs(boundary_envelope)
if len(over_64k_body) != 65_537:
    raise RuntimeError(f"expected 65,537-byte payload, got {len(over_64k_body)}")

# Also confirm missing runtime_context=None rejects pre-I/O identically to invalid /ibvi-ads route
missing_deleg_rig = _SixAdapterIOSpyRig()
missing_deleg_spy = _RejectionSpyHandler(missing_deleg_rig)
missing_deleg_body = canonicalize_jcs(
    {
        "jsonrpc": "2.0",
        "id": "req-missing-ctx",
        "method": "smart_ads.queries.get_campaign_performance_v1",
        "params": {
            "tenant_ref": "tenant:ibvi",
            "binding_ref": "binding:meta-1",
            "resource_scope_ref": "scope:ibvi-1",
            "date_range": {
                "start_date": "2026-11-01",
                "end_date": "2026-11-10",
            },
        },
    }
)
missing_deleg_out = handle_mcp_request_bytes(
    missing_deleg_body, None, handler=missing_deleg_spy
)
if (
    missing_deleg_out.admitted_request is not None
    or missing_deleg_out.rejection is None
    or missing_deleg_out.rejection.case_id != "missing_or_invalid_ibvi_ads_delegation"
    or missing_deleg_out.rejection.code != -32600
    or missing_deleg_out.rejection.message != "Invalid Request"
    or missing_deleg_out.rejection.request_id != "req-missing-ctx"
    or missing_deleg_spy.calls != 0
    or missing_deleg_rig.counters() != zero_counters
):
    raise RuntimeError("missing runtime_context delegation check failed")

# 2. All 11 normative cases in strict UTF-8 byte order of case_id
matrix_vectors: list[tuple[str, bytes, McpRuntimeContext | None, int, str, str, str | int | None]] = [
    (
        "additional_property",
        canonicalize_jcs(
            {
                "jsonrpc": "2.0",
                "id": "req-additional-property",
                "method": "smart_ads.queries.get_campaign_performance_v1",
                "params": {
                    "tenant_ref": "tenant:ibvi",
                    "binding_ref": "binding:meta-1",
                    "resource_scope_ref": "scope:ibvi-1",
                    "date_range": {
                        "start_date": "2026-11-01",
                        "end_date": "2026-11-10",
                    },
                    "file_path": "/etc/passwd",
                },
            }
        ),
        valid_rt,
        -32602,
        "Invalid params",
        "validated_request_id",
        "req-additional-property",
    ),
    (
        "batch_array",
        b'[{"jsonrpc":"2.0","id":"req-batch-1","method":"smart_ads.queries.get_campaign_performance_v1"},'
        b'{"jsonrpc":"2.0","id":"req-batch-2","method":"smart_ads.queries.get_ad_performance_v1"}]',
        valid_rt,
        -32600,
        "Invalid Request",
        "null",
        None,
    ),
    (
        "body_over_64k",
        over_64k_body,
        valid_rt,
        -32600,
        "Invalid Request",
        "null",
        None,
    ),
    (
        "duplicate_json_key",
        b'{"jsonrpc":"2.0","id":"req-dup-1","id":"req-dup-2","method":"smart_ads.queries.get_campaign_performance_v1"}',
        valid_rt,
        -32600,
        "Invalid Request",
        "null",
        None,
    ),
    (
        "invalid_params",
        canonicalize_jcs(
            {
                "jsonrpc": "2.0",
                "id": "req-invalid-params",
                "method": "smart_ads.queries.get_campaign_performance_v1",
                "params": {
                    "tenant_ref": "raw-secret-account-12345",
                    "binding_ref": "binding:meta-1",
                    "resource_scope_ref": "scope:ibvi-1",
                    "date_range": {
                        "start_date": "2026-11-10",
                        "end_date": "2026-11-01",
                    },
                },
            }
        ),
        valid_rt,
        -32602,
        "Invalid params",
        "validated_request_id",
        "req-invalid-params",
    ),
    (
        "invalid_utf8",
        b'{"jsonrpc":"2.0","id":"req-utf8","bad":"' + bytes.fromhex("fffe") + b'"}',
        valid_rt,
        -32700,
        "Parse error",
        "null",
        None,
    ),
    (
        "malformed_json",
        b'{"jsonrpc":"2.0","id":"req-trunc","method":',
        valid_rt,
        -32700,
        "Parse error",
        "null",
        None,
    ),
    (
        "missing_or_invalid_ibvi_ads_delegation",
        canonicalize_jcs(
            {
                "jsonrpc": "2.0",
                "id": "req-missing-delegation",
                "method": "smart_ads.queries.get_campaign_performance_v1",
                "params": {
                    "tenant_ref": "tenant:ibvi",
                    "binding_ref": "binding:meta-1",
                    "resource_scope_ref": "scope:ibvi-1",
                    "date_range": {
                        "start_date": "2026-11-01",
                        "end_date": "2026-11-10",
                    },
                },
            }
        ),
        invalid_route_rt,
        -32600,
        "Invalid Request",
        "validated_request_id",
        "req-missing-delegation",
    ),
    (
        "nesting_depth_over_8",
        b'{"jsonrpc":"2.0","id":"req-depth-9","method":"smart_ads.queries.get_campaign_performance_v1",'
        b'"params":{"l3":{"l4":{"l5":{"l6":{"l7":{"l8":{"l9":{"leaf":1}}}}}}}}}',
        valid_rt,
        -32600,
        "Invalid Request",
        "null",
        None,
    ),
    (
        "non_object_request",
        b'"scalar-secret-do-not-echo"',
        valid_rt,
        -32600,
        "Invalid Request",
        "null",
        None,
    ),
    (
        "unsupported_method",
        canonicalize_jcs(
            {
                "jsonrpc": "2.0",
                "id": "req-unsupported-method",
                "method": "smart_ads.mutations.update_budget_v1",
                "params": {},
            }
        ),
        valid_rt,
        -32601,
        "Method not found",
        "validated_request_id",
        "req-unsupported-method",
    ),
]

forbidden_echo_tokens = (
    b"/etc/passwd",
    b"raw-secret-account-12345",
    b"scalar-secret-do-not-echo",
)

cases_out: list[dict[str, Any]] = []
for (
    case_id,
    raw_body,
    rt_ctx,
    expected_code,
    expected_message,
    expected_id_policy,
    expected_wire_id,
) in matrix_vectors:
    rig = _SixAdapterIOSpyRig()
    spy_handler = _RejectionSpyHandler(rig)
    if not isinstance(spy_handler, McpReadHandlerPort):
        raise RuntimeError("rejection spy handler does not satisfy McpReadHandlerPort")

    outcome = handle_mcp_request_bytes(raw_body, rt_ctx, handler=spy_handler)
    if (
        outcome.admitted_request is not None
        or outcome.rejection is None
        or outcome.rejection.case_id != case_id
        or spy_handler.calls != 0
    ):
        raise RuntimeError(f"matrix case {case_id!r} failed pre-I/O rejection")

    decoded = loads_strict_json(outcome.wire_bytes)
    shape_ok = (
        isinstance(decoded, dict)
        and set(decoded.keys()) == {"jsonrpc", "id", "error"}
        and type(decoded.get("jsonrpc")) is str
        and decoded.get("jsonrpc") == "2.0"
        and isinstance(decoded.get("error"), dict)
        and set(decoded["error"].keys()) == {"code", "message"}
        and type(decoded["error"].get("code")) is int
        and type(decoded["error"].get("message")) is str
        and outcome.wire_bytes == canonicalize_jcs(decoded)
        and all(tok not in outcome.wire_bytes for tok in forbidden_echo_tokens)
    )
    if not shape_ok:
        raise RuntimeError(f"matrix case {case_id!r} emitted invalid JSON-RPC error shape")

    observed_code = decoded["error"]["code"]
    observed_message = decoded["error"]["message"]
    observed_id = decoded["id"]
    if (
        outcome.rejection.code != observed_code
        or outcome.rejection.message != observed_message
        or outcome.rejection.request_id != observed_id
    ):
        raise RuntimeError(f"matrix case {case_id!r} descriptor/wire mismatch")

    if expected_id_policy == "null":
        id_matches = observed_id is None
    else:
        id_matches = (
            expected_wire_id is not None
            and type(observed_id) is type(expected_wire_id)
            and observed_id == expected_wire_id
        )

    counters = rig.counters()
    if (
        observed_code != expected_code
        or observed_message != expected_message
        or not id_matches
        or counters != zero_counters
    ):
        raise RuntimeError(f"matrix case {case_id!r} violated normative expectations")

    cases_out.append(
        {
            "case_id": case_id,
            "expected_code": expected_code,
            "observed_code": observed_code,
            "expected_message": expected_message,
            "observed_message": observed_message,
            "expected_id_policy": expected_id_policy,
            "observed_id_matches_policy": True,
            "response_shape_valid": True,
            "io_counters": counters,
        }
    )

sys.stdout.write(
    json.dumps(
        {
            "schema_bundle_digest": actual_schema_digest,
            "allowed_methods": allowed_methods_list,
            "body_64k_boundary_verified": True,
            "cases": cases_out,
        }
    )
)
"""


def _require_sha256_digest(value: object, label: str) -> str:
    if type(value) is not str or _SHA256_PREFIXED_RE.fullmatch(value) is None:
        raise ValueError(f"{label}: expected 'sha256:<64_lowercase_hex>'")
    return value


def _require_git_oid(value: object, label: str) -> str:
    if type(value) is not str or _GIT_OID_RE.fullmatch(value) is None:
        raise ValueError(f"{label}: expected 40-character lowercase hex Git OID")
    return value


def _require_strict_str(value: object, label: str) -> str:
    if (
        type(value) is not str
        or not value.strip()
        or value != value.strip()
        or "\x00" in value
    ):
        raise ValueError(f"{label}: expected non-empty stripped string without NUL")
    return value


def _require_exact_str(value: object, expected: str, label: str) -> str:
    if type(value) is not str or value != expected:
        raise ValueError(f"{label}: expected exact string {expected!r}")
    return value


def _require_exact_bool(value: object, expected: bool, label: str) -> bool:
    if type(value) is not bool or value is not expected:
        raise ValueError(f"{label}: expected exact boolean {expected!r}")
    return value


def _require_exact_int(value: object, expected: int, label: str) -> int:
    if type(value) is not int or value != expected:
        raise ValueError(f"{label}: expected exact integer {expected!r}")
    return value


def _require_timestamp_utc(value: object, label: str) -> str:
    if type(value) is not str:
        raise ValueError(f"{label}: expected whole-second UTC timestamp string")
    timestamp(value)
    return value


def _verify_cpython_312_runtime() -> None:
    impl_name = getattr(sys.implementation, "name", None)
    ver_info = sys.version_info
    if (
        impl_name != "cpython"
        or len(ver_info) < 2
        or (ver_info[0], ver_info[1]) != (3, 12)
    ):
        raise ValueError(
            "gov1_mcp: requires CPython 3.12 ('cp312'), "
            f"got implementation={impl_name!r}, version_info={tuple(ver_info[:3])!r}"
        )


def _clean_system_path() -> str:
    py_dir = str(Path(sys.executable).parent)
    candidates = [
        d for d in (py_dir, *_DEFAULT_SYSTEM_BIN_DIRS) if d and os.path.isabs(d)
    ]
    return os.pathsep.join(dict.fromkeys(candidates))


def _resolve_regular_wheel_file(wheel_path: Path) -> Path:
    if not isinstance(wheel_path, (str, os.PathLike)):
        raise ValueError("wheel_path: expected filesystem path")
    whl_file = Path(wheel_path)
    if whl_file.is_symlink() or not whl_file.is_file():
        raise ValueError(f"wheel_path: expected regular non-symlink file at {whl_file}")
    return whl_file


def _extract_verified_wheel_to_purelib(
    wheel_bytes: bytes,
    purelib_path: Path,
    expected_member_paths: set[str],
) -> None:
    try:
        zf_ctx = zipfile.ZipFile(io.BytesIO(wheel_bytes), "r")
    except zipfile.BadZipFile as exc:
        raise ValueError(f"wheel archive: invalid ZIP format: {exc}") from exc

    extracted: dict[str, bytes] = {}
    with zf_ctx as zf:
        infos = zf.infolist()
        if not infos:
            raise ValueError("wheel archive: empty ZIP central directory")
        verify_contiguous_zip_layout(wheel_bytes, infos, comment=zf.comment)
        for info in infos:
            if info.is_dir() or info.filename.endswith("/"):
                raise ValueError(
                    f"wheel archive: directory entry forbidden: {info.filename!r}"
                )
            unix_type = (info.external_attr >> 16) & 0o170000
            if unix_type == 0o120000 or (unix_type != 0 and unix_type != 0o100000):
                raise ValueError(
                    f"wheel archive: symlink or special entry forbidden: {info.filename!r}"
                )
            source_path(info.filename)
            if info.filename in extracted:
                raise ValueError(
                    f"wheel archive: duplicate central-directory entry {info.filename!r}"
                )
            try:
                raw = zf.read(info)
            except (
                zipfile.BadZipFile,
                zlib.error,
                EOFError,
                RuntimeError,
                NotImplementedError,
            ) as exc:
                raise ValueError(
                    f"wheel archive: failed to decompress member {info.filename!r}: {exc}"
                ) from exc
            if len(raw) != info.file_size:
                raise ValueError(
                    f"wheel archive: declared file_size mismatch on {info.filename!r}"
                )
            extracted[info.filename] = raw

    if set(extracted.keys()) != expected_member_paths:
        raise ValueError("wheel archive: member paths diverge from verified RECORD")

    resolved_purelib = purelib_path.resolve()
    for rel_path in sorted(extracted.keys(), key=lambda s: s.encode("utf-8")):
        dest = (resolved_purelib / rel_path).resolve()
        if not dest.is_relative_to(resolved_purelib):
            raise ValueError(f"clean_venv: path traversal rejected for {rel_path!r}")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(extracted[rel_path])


def _validate_allowed_methods(value: object, label: str) -> list[str]:
    if (
        type(value) is not list
        or len(value) != len(_EXPECTED_ALLOWED_MCP_METHODS)
        or any(type(item) is not str for item in value)
    ):
        raise ValueError(
            f"{label}: expected exact 5-string list {list(_EXPECTED_ALLOWED_MCP_METHODS)!r}"
        )
    if value != sorted(value, key=lambda s: s.encode("utf-8")):
        raise ValueError(f"{label}: allowed_methods must be sorted by UTF-8 bytes")
    if tuple(value) != _EXPECTED_ALLOWED_MCP_METHODS:
        raise ValueError(
            f"{label}: expected exact allowed_methods {list(_EXPECTED_ALLOWED_MCP_METHODS)!r}"
        )
    return list(value)


def _validate_cases(value: object, label: str) -> list[dict[str, Any]]:
    if type(value) is not list or len(value) != len(_NORMATIVE_MCP_MATRIX_ROWS):
        raise ValueError(
            f"{label}: expected exact list of {len(_NORMATIVE_MCP_MATRIX_ROWS)} normative cases"
        )

    seen_ids: list[str] = []
    for idx, item in enumerate(value):
        exact_fields(item, _CASE_FIELDS, f"{label}[{idx}]")
        cid = _require_strict_str(item["case_id"], f"{label}[{idx}].case_id")
        seen_ids.append(cid)

    if len(set(seen_ids)) != len(seen_ids):
        raise ValueError(f"{label}: duplicate case_id in cases")
    if seen_ids != sorted(seen_ids, key=lambda s: s.encode("utf-8")):
        raise ValueError(f"{label}: cases must be strictly sorted by raw UTF-8 bytes")

    expected_ids = [row[0] for row in _NORMATIVE_MCP_MATRIX_ROWS]
    if seen_ids != expected_ids:
        raise ValueError(
            f"{label}: case_id set mismatch against ADR-0001 §3.3 ({seen_ids!r} != {expected_ids!r})"
        )

    validated_cases: list[dict[str, Any]] = []
    for idx, (
        item,
        (norm_case_id, norm_code, norm_message, norm_id_policy),
    ) in enumerate(zip(value, _NORMATIVE_MCP_MATRIX_ROWS, strict=True)):
        _require_exact_str(item["case_id"], norm_case_id, f"{label}[{idx}].case_id")
        _require_exact_int(
            item["expected_code"], norm_code, f"{label}[{idx}].expected_code"
        )
        _require_exact_int(
            item["observed_code"], norm_code, f"{label}[{idx}].observed_code"
        )
        _require_exact_str(
            item["expected_message"], norm_message, f"{label}[{idx}].expected_message"
        )
        _require_exact_str(
            item["observed_message"], norm_message, f"{label}[{idx}].observed_message"
        )
        _require_exact_str(
            item["expected_id_policy"],
            norm_id_policy,
            f"{label}[{idx}].expected_id_policy",
        )
        _require_exact_bool(
            item["observed_id_matches_policy"],
            True,
            f"{label}[{idx}].observed_id_matches_policy",
        )
        _require_exact_bool(
            item["response_shape_valid"],
            True,
            f"{label}[{idx}].response_shape_valid",
        )

        counters = item["io_counters"]
        exact_fields(counters, _IO_COUNTER_FIELDS, f"{label}[{idx}].io_counters")
        checked_counters: dict[str, int] = {}
        for counter_key in _IO_COUNTER_KEYS_SORTED:
            checked_counters[counter_key] = _require_exact_int(
                counters[counter_key],
                0,
                f"{label}[{idx}].io_counters.{counter_key}",
            )

        validated_cases.append(
            {
                "case_id": norm_case_id,
                "expected_code": norm_code,
                "observed_code": norm_code,
                "expected_message": norm_message,
                "observed_message": norm_message,
                "expected_id_policy": norm_id_policy,
                "observed_id_matches_policy": True,
                "response_shape_valid": True,
                "io_counters": checked_counters,
            }
        )

    return validated_cases


def _validate_execution_dict(
    execution: dict[str, Any], *, label: str = "execution"
) -> dict[str, Any]:
    exact_fields(execution, _EXECUTION_FIELDS, label)
    whl_digest = _require_sha256_digest(
        execution["wheel_digest"], f"{label}.wheel_digest"
    )
    schema_digest = _require_sha256_digest(
        execution["schema_bundle_digest"], f"{label}.schema_bundle_digest"
    )
    allowed_methods = _validate_allowed_methods(
        execution["allowed_methods"], f"{label}.allowed_methods"
    )
    _require_exact_bool(
        execution["body_64k_boundary_verified"],
        True,
        f"{label}.body_64k_boundary_verified",
    )
    checked_cases = _validate_cases(execution["cases"], f"{label}.cases")
    return {
        "wheel_digest": whl_digest,
        "schema_bundle_digest": schema_digest,
        "allowed_methods": allowed_methods,
        "body_64k_boundary_verified": True,
        "cases": checked_cases,
    }


def _verify_envelope_integrity(envelope: dict[str, Any], *, label: str) -> None:
    integrity = envelope.get("integrity")
    if not isinstance(integrity, dict):
        raise ValueError(f"{label}.integrity: expected JSON object")
    keys = set(integrity.keys())
    if keys not in (_UNSIGNED_INTEGRITY_FIELDS, _SIGNED_INTEGRITY_FIELDS):
        raise ValueError(
            f"{label}.integrity: expected unsigned or signed P1 integrity fields"
        )
    _require_strict_str(integrity["key_id"], f"{label}.integrity.key_id")
    validate_locator(
        integrity["key_registry_snapshot_locator"], _KEY_REGISTRY_SCHEMA
    )
    if keys == _SIGNED_INTEGRITY_FIELDS:
        declared_digest = _require_sha256_digest(
            integrity["content_digest"], f"{label}.integrity.content_digest"
        )
        expected_digest = p1.content_digest(envelope)
        if declared_digest != expected_digest:
            raise ValueError(
                f"{label}.integrity.content_digest: mismatch against P1 preimage"
            )
        sig_b64 = integrity["signature_base64"]
        if type(sig_b64) is not str:
            raise ValueError(f"{label}.integrity.signature_base64: expected string")
        sig_bytes = p1._strict_base64_decode(sig_b64)
        if len(sig_bytes) != 64:
            raise ValueError(
                f"{label}.integrity.signature_base64: expected 64-byte Ed25519 signature"
            )


def execute_mcp_rejection_matrix_on_wheel(wheel_path: Path) -> dict[str, Any]:
    """Execute the 11-case ADR-0001 §3.3 MCP rejection matrix and 64 KiB boundary against an isolated wheel."""
    _verify_cpython_312_runtime()
    whl_file = _resolve_regular_wheel_file(wheel_path)
    boundary = inspect_wheel_boundary(whl_file)

    wheel_bytes = whl_file.read_bytes()
    if digest(wheel_bytes) != boundary["wheel_digest"]:
        raise ValueError(
            "wheel_path: concurrent modification detected against inspect_wheel_boundary digest"
        )
    if (
        boundary.get("archive_allowlist_passed") is not True
        or boundary.get("ast_boundary_scan_passed") is not True
        or boundary.get("isolated_venv_import_passed") is not True
    ):
        raise ValueError("wheel_path: wheel boundary inspection did not pass")

    expected_member_paths = {
        entry["path"] for entry in boundary["sorted_record_entries"]
    }
    governance_repo_root = Path(__file__).resolve().parents[2]

    with tempfile.TemporaryDirectory(prefix="gov1-mcp-venv-") as raw_tmp:
        tmp_root = Path(raw_tmp).resolve()
        if tmp_root.is_relative_to(governance_repo_root):
            raise ValueError(
                "clean_venv: temporary directory must reside outside repository"
            )

        venv_dir = tmp_root / "venv"
        probe_cwd = tmp_root / "cwd"
        probe_cwd.mkdir(parents=True, exist_ok=True)
        venv.EnvBuilder(
            system_site_packages=False,
            with_pip=False,
            clear=True,
            symlinks=os.name != "nt",
        ).create(venv_dir)
        venv_python = venv_dir / (
            "Scripts/python.exe" if os.name == "nt" else "bin/python"
        )

        clean_env = {
            "HOME": "/nonexistent",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": _clean_system_path(),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONHASHSEED": "0",
            "PYTHONNOUSERSITE": "1",
            "PYTHONSAFEPATH": "1",
            "TMPDIR": str(probe_cwd),
            "TZ": "UTC",
        }

        try:
            purelib_proc = subprocess.run(
                [
                    str(venv_python),
                    "-I",
                    "-B",
                    "-c",
                    "import sysconfig; print(sysconfig.get_path('purelib'))",
                ],
                cwd=str(probe_cwd),
                env=clean_env,
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError(f"clean_venv: failed to query purelib: {exc}") from exc

        if purelib_proc.returncode != 0:
            raise ValueError(
                f"clean_venv: failed to query purelib: {purelib_proc.stderr.strip()}"
            )
        purelib_path = Path(purelib_proc.stdout.strip()).resolve()
        if not purelib_path.is_relative_to(venv_dir.resolve()):
            raise ValueError("clean_venv: purelib resolved outside venv root")

        _extract_verified_wheel_to_purelib(
            wheel_bytes, purelib_path, expected_member_paths
        )

        try:
            probe_proc = subprocess.run(
                [
                    str(venv_python),
                    "-I",
                    "-B",
                    "-c",
                    _MCP_MATRIX_PROBE_SCRIPT,
                    str(purelib_path),
                    str(governance_repo_root),
                    str(governance_repo_root / "src"),
                    boundary["schema_bundle_digest"],
                ],
                cwd=str(probe_cwd),
                env=clean_env,
                capture_output=True,
                text=True,
                timeout=60,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError(
                f"clean_venv: isolated MCP matrix probe failed or timed out: {exc}"
            ) from exc

        if probe_proc.returncode != 0:
            raise ValueError(
                f"clean_venv: isolated MCP matrix probe failed: {probe_proc.stderr.strip()}"
            )

    probe_out = loads_strict(probe_proc.stdout)
    if not isinstance(probe_out, dict):
        raise ValueError("clean_venv: MCP matrix probe returned non-object JSON")
    exact_fields(
        probe_out,
        {
            "schema_bundle_digest",
            "allowed_methods",
            "body_64k_boundary_verified",
            "cases",
        },
        "clean_venv.mcp_probe",
    )
    if probe_out["schema_bundle_digest"] != boundary["schema_bundle_digest"]:
        raise ValueError("clean_venv: schema_bundle_digest mismatch")

    return _validate_execution_dict(
        {
            "wheel_digest": boundary["wheel_digest"],
            "schema_bundle_digest": boundary["schema_bundle_digest"],
            "allowed_methods": probe_out["allowed_methods"],
            "body_64k_boundary_verified": probe_out["body_64k_boundary_verified"],
            "cases": probe_out["cases"],
        },
        label="mcp_execution",
    )


def _build_report_common_payload(
    *,
    migration_run_context_locator: dict[str, Any],
    build_run_id: str,
    executed_at_utc: str,
    source_commit_sha: str,
    build_backend_digest: str,
    execution: dict[str, Any],
) -> dict[str, Any]:
    validate_locator(migration_run_context_locator, _RUN_CONTEXT_SCHEMA)
    _require_strict_str(build_run_id, "build_run_id")
    _require_timestamp_utc(executed_at_utc, "executed_at_utc")
    _require_git_oid(source_commit_sha, "source_commit_sha")
    _require_sha256_digest(build_backend_digest, "build_backend_digest")
    checked_exec = _validate_execution_dict(execution, label="execution")
    return {
        "migration_run_context_locator": copy.deepcopy(migration_run_context_locator),
        "build_run_id": build_run_id,
        "executed_at_utc": executed_at_utc,
        "source_commit_sha": source_commit_sha,
        "wheel_digest": checked_exec["wheel_digest"],
        "build_backend_digest": build_backend_digest,
        "schema_bundle_digest": checked_exec["schema_bundle_digest"],
        "allowed_methods": checked_exec["allowed_methods"],
        "body_64k_boundary_verified": checked_exec["body_64k_boundary_verified"],
        "cases": checked_exec["cases"],
    }


def build_mcp_rejection_matrix_report_envelope(
    *,
    migration_run_context_locator: dict[str, Any],
    build_run_id: str,
    executed_at_utc: str,
    source_commit_sha: str,
    build_backend_digest: str,
    sealed_sandbox_profile_locator: dict[str, Any],
    execution: dict[str, Any],
    registry_locator: dict[str, Any],
    signer_key_id: str,
) -> dict[str, Any]:
    """Build an unsigned P1 `smart_ads/mcp_rejection_matrix_report/v1` envelope."""
    validate_locator(sealed_sandbox_profile_locator, SANDBOX_PROFILE_SCHEMA)
    validate_locator(registry_locator, _KEY_REGISTRY_SCHEMA)
    _require_strict_str(signer_key_id, "signer_key_id")
    common = _build_report_common_payload(
        migration_run_context_locator=migration_run_context_locator,
        build_run_id=build_run_id,
        executed_at_utc=executed_at_utc,
        source_commit_sha=source_commit_sha,
        build_backend_digest=build_backend_digest,
        execution=execution,
    )
    envelope = {
        "$schema": MCP_REJECTION_REPORT_SCHEMA,
        **common,
        "sealed_sandbox_profile_locator": copy.deepcopy(
            sealed_sandbox_profile_locator
        ),
        "integrity": {
            "key_id": signer_key_id,
            "key_registry_snapshot_locator": copy.deepcopy(registry_locator),
        },
    }
    loads_strict(canonicalize(envelope).decode("utf-8"))
    return envelope


def build_mcp_rejection_matrix_report_candidate(
    *,
    migration_run_context_locator: dict[str, Any],
    build_run_id: str,
    executed_at_utc: str,
    source_commit_sha: str,
    build_backend_digest: str,
    sealed_sandbox_profile_candidate_ref: dict[str, Any],
    execution: dict[str, Any],
) -> dict[str, Any]:
    """Build a non-signable `gov1_local_candidate` for `mcp_rejection_matrix_report/v1`."""
    verify_local_candidate_ref(
        sealed_sandbox_profile_candidate_ref,
        expected_schema=SANDBOX_PROFILE_SCHEMA,
    )
    common = _build_report_common_payload(
        migration_run_context_locator=migration_run_context_locator,
        build_run_id=build_run_id,
        executed_at_utc=executed_at_utc,
        source_commit_sha=source_commit_sha,
        build_backend_digest=build_backend_digest,
        execution=execution,
    )
    payload = {
        **common,
        "sealed_sandbox_profile_candidate_ref": copy.deepcopy(
            sealed_sandbox_profile_candidate_ref
        ),
    }
    loads_strict(canonicalize(payload).decode("utf-8"))
    return wrap_local_candidate(MCP_REJECTION_REPORT_SCHEMA, payload)


def verify_mcp_rejection_matrix_report(
    artifact: dict[str, Any], *, wheel_path: Path
) -> dict[str, Any]:
    """Materially verify `mcp_rejection_matrix_report/v1` by re-executing the matrix on `wheel_path`."""
    if not isinstance(artifact, dict):
        raise ValueError(
            "verify_mcp_rejection_matrix_report: artifact must be a JSON object"
        )

    if artifact.get("artifact_kind") == LOCAL_CANDIDATE_KIND:
        if "$schema" in artifact or "integrity" in artifact:
            raise ValueError(
                "verify_mcp_rejection_matrix_report: local candidate must not contain envelope fields"
            )
        payload = unwrap_local_candidate(
            artifact, expected_schema=MCP_REJECTION_REPORT_SCHEMA
        )
        exact_fields(
            payload,
            _REPORT_CANDIDATE_PAYLOAD_FIELDS,
            "mcp_rejection_matrix_report_candidate_payload",
        )
        verify_local_candidate_ref(
            payload["sealed_sandbox_profile_candidate_ref"],
            expected_schema=SANDBOX_PROFILE_SCHEMA,
        )
        mode = "candidate"
    elif (
        artifact.get("$schema") == MCP_REJECTION_REPORT_SCHEMA
        and "artifact_kind" not in artifact
    ):
        exact_fields(
            artifact,
            _REPORT_ENVELOPE_FIELDS,
            "mcp_rejection_matrix_report_envelope",
        )
        _verify_envelope_integrity(artifact, label="mcp_rejection_matrix_report")
        payload = {
            k: copy.deepcopy(v)
            for k, v in artifact.items()
            if k not in {"$schema", "integrity"}
        }
        exact_fields(
            payload,
            _REPORT_ENVELOPE_PAYLOAD_FIELDS,
            "mcp_rejection_matrix_report_envelope_payload",
        )
        validate_locator(
            payload["sealed_sandbox_profile_locator"], SANDBOX_PROFILE_SCHEMA
        )
        mode = "envelope"
    else:
        raise ValueError(
            "verify_mcp_rejection_matrix_report: expected mcp_rejection_matrix_report/v1 "
            "envelope or gov1_local_candidate"
        )

    validate_locator(payload["migration_run_context_locator"], _RUN_CONTEXT_SCHEMA)
    _require_strict_str(payload["build_run_id"], "mcp_report.build_run_id")
    executed_at_utc = _require_timestamp_utc(
        payload["executed_at_utc"], "mcp_report.executed_at_utc"
    )
    _require_git_oid(payload["source_commit_sha"], "mcp_report.source_commit_sha")
    _require_sha256_digest(
        payload["build_backend_digest"], "mcp_report.build_backend_digest"
    )

    declared_execution = _validate_execution_dict(
        {k: payload[k] for k in _EXECUTION_FIELDS},
        label="mcp_report.execution",
    )
    loads_strict(canonicalize(payload).decode("utf-8"))

    whl_file = _resolve_regular_wheel_file(wheel_path)
    wheel_bytes = whl_file.read_bytes()
    actual_wheel_digest = digest(wheel_bytes)
    if actual_wheel_digest != declared_execution["wheel_digest"]:
        raise ValueError(
            "verify_mcp_rejection_matrix_report: wheel_digest mismatch against wheel_path"
        )

    live_execution = execute_mcp_rejection_matrix_on_wheel(whl_file)
    if (
        live_execution["wheel_digest"] != declared_execution["wheel_digest"]
        or live_execution["schema_bundle_digest"]
        != declared_execution["schema_bundle_digest"]
        or live_execution["allowed_methods"] != declared_execution["allowed_methods"]
        or live_execution["body_64k_boundary_verified"] is not True
        or live_execution["cases"] != declared_execution["cases"]
        or canonicalize(live_execution) != canonicalize(declared_execution)
    ):
        raise ValueError(
            "verify_mcp_rejection_matrix_report: declared report diverges from live wheel matrix execution"
        )

    return {
        "mode": mode,
        "schema": MCP_REJECTION_REPORT_SCHEMA,
        "wheel_digest": live_execution["wheel_digest"],
        "schema_bundle_digest": live_execution["schema_bundle_digest"],
        "executed_at_utc": executed_at_utc,
        "payload": copy.deepcopy(payload),
    }


__all__ = [
    "EXPECTED_MCP_MATRIX_SPECS",
    "MCP_REJECTION_REPORT_SCHEMA",
    "build_mcp_rejection_matrix_report_candidate",
    "build_mcp_rejection_matrix_report_envelope",
    "execute_mcp_rejection_matrix_on_wheel",
    "verify_mcp_rejection_matrix_report",
]
