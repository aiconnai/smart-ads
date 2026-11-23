"""Unit tests for `smart_ads.ports.consumer` and `Cpython312AstConsumerRoutingAnalyzer`."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
import sys
from types import SimpleNamespace
from typing import Any

import pytest

from smart_ads.adapters.consumer import Cpython312AstConsumerRoutingAnalyzer
from smart_ads.adapters.consumer.routing_analyzer import (
    Cpython312AstConsumerRoutingAnalyzer as DirectRoutingAnalyzer,
)
from smart_ads.analytics.intelligence import AnalysisEvidence, EvaluationContext, Finding
from smart_ads.contracts import (
    AlgorithmProvenanceIdentity,
    ArtifactLocator,
    ClosedValidationError,
    ConsumerFeatureFlagContract,
    IbviAdsDelegationContract,
    P1Integrity,
    ReadEntrypointSelector,
    TripartiteGitArtifactRef,
    canonicalize_jcs,
)
import smart_ads.ports as ports_pkg
from smart_ads.ports.consumer import (
    ConsumerRoutingAnalysis,
    ConsumerRoutingAnalyzerPort,
    EntrypointRouteFacts,
    OfflineIntelligencePort,
    P1SignatureVerifierPort,
    SeamDualProjectionCase,
    SeamLegacyProjectorPort,
)
from smart_ads.ports.storage import CellObjectStorePort
from smart_ads.transports.mcp import ALLOWED_MCP_METHODS
from tools.governance import gov1_wheel

REPO_ROOT = Path(__file__).resolve().parents[2]
_KEY_ID = "key:ed25519:" + ("a" * 64)
_KEY_REG_LOC = ArtifactLocator.from_digest(
    "smart_ads/key_authorization_registry/v1", "sha256:" + ("9" * 64)
)
_RUN_LOC = ArtifactLocator.from_digest(
    "smart_ads/migration_run_context/v1", "sha256:" + ("1" * 64)
)
_UNSIGNED = P1Integrity(key_id=_KEY_ID, key_registry_snapshot_locator=_KEY_REG_LOC)
_FLAG_KEY = "ibvi_ads.smart_ads_read_v1"
_LEGACY_ROUTE = "legacy:mbras_campaigns_direct"


def _make_alg_id(schema_id: str) -> AlgorithmProvenanceIdentity:
    prov_loc = ArtifactLocator.from_digest(
        "smart_ads/git_artifact_provenance/v1", "sha256:" + ("6" * 64)
    )
    return AlgorithmProvenanceIdentity(
        "algorithm:consumer-ast-routing-v1",
        "1.0.0",
        prov_loc,
        "aiconnai/smart-ads",
        "b" * 40,
        "src/smart_ads/adapters/consumer/routing_analyzer.py",
        "c" * 40,
        "sha256:" + ("d" * 64),
        "cpython-3.12",
        schema_id,
    )


def _make_contract(
    selectors: Sequence[tuple[str, str]] = (
        ("CampaignGateway.fetch", "smart_ads.queries.get_campaign_performance_v1"),
        ("fetch_adsets_async", "smart_ads.queries.get_adset_performance_v1"),
        ("get_daily_summary", "smart_ads.reports.generate_recurrent_summary_v1"),
    ),
    *,
    flag_key: str = _FLAG_KEY,
    disabled_legacy_route: str = _LEGACY_ROUTE,
    adapter_source_path: str = "src/ibvi_ads/adapter.py",
    ff_source_path: str = "src/ibvi_ads/flags.json",
) -> ConsumerFeatureFlagContract:
    prov_a = ArtifactLocator.from_digest("smart_ads/git_artifact_provenance/v1", "sha256:" + ("4" * 64))
    prov_f = ArtifactLocator.from_digest("smart_ads/git_artifact_provenance/v1", "sha256:" + ("5" * 64))
    prov_h = ArtifactLocator.from_digest("smart_ads/git_artifact_provenance/v1", "sha256:" + ("6" * 64))
    deleg = IbviAdsDelegationContract(
        _RUN_LOC, "limaronaldo/hermes-ronaldo", "3" * 40, prov_h, "conductor:hermes-main",
        "front:pinna", "/ibvi-ads", "sha256:" + ("7" * 64), ALLOWED_MCP_METHODS, True, _UNSIGNED,
    )
    adp_art = TripartiteGitArtifactRef(adapter_source_path, "4" * 40, "sha256:" + ("8" * 64), prov_a)
    ff_art = TripartiteGitArtifactRef(ff_source_path, "5" * 40, "sha256:" + ("9" * 64), prov_f)
    eps = tuple(ReadEntrypointSelector(sym, m) for sym, m in selectors)
    return ConsumerFeatureFlagContract(
        _RUN_LOC, "limaronaldo/hermes-ronaldo", "3" * 40, adp_art, ff_art, flag_key,
        False, disabled_legacy_route, "/ibvi-ads", eps,
        _make_alg_id(ConsumerFeatureFlagContract.SCHEMA), deleg.locator(), _UNSIGNED,
    )


_VALID_JSON_FLAGS = canonicalize_jcs(
    {
        "flag_key": _FLAG_KEY,
        "default_enabled": False,
        "disabled_legacy_route": _LEGACY_ROUTE,
        "enabled_smart_ads_route": "/ibvi-ads",
    }
)

_VALID_PY_FLAGS_SCALAR = (
    '"""Closed feature flag config."""\n'
    "from __future__ import annotations\n"
    "from typing import Final\n\n"
    f'FLAG_KEY: Final[str] = "{_FLAG_KEY}"\n'
    "DEFAULT_ENABLED: Final[bool] = False\n"
    f'DISABLED_LEGACY_ROUTE: Final[str] = "{_LEGACY_ROUTE}"\n'
    'ENABLED_SMART_ADS_ROUTE: Final[str] = "/ibvi-ads"\n'
).encode("utf-8")

_VALID_PY_FLAGS_DICT = (
    "from typing import Final\n"
    f'FEATURE_FLAGS: Final[dict[str, bool]] = {{"{_FLAG_KEY}": False}}\n'
).encode("utf-8")

_VALID_ADAPTER_SOURCE = '''"""Closed consumer read adapter."""
from __future__ import annotations
from typing import Any, Final

FLAG_KEY: Final[str] = "ibvi_ads.smart_ads_read_v1"
IBVI_ADS_ROUTE: Final[str] = "/ibvi-ads"
LEGACY_ROUTE: Final[str] = "legacy:mbras_campaigns_direct"
SUMMARY_METHOD: Final[str] = "smart_ads.reports.generate_recurrent_summary_v1"


class CampaignGateway:
    """Class-based consumer entrypoint."""

    def __init__(self, flags: Any, conductor: Any, legacy: Any) -> None:
        self._flags = flags
        self._conductor = conductor
        self._legacy = legacy

    def fetch(self, tenant_ref: str, start_date: str) -> Any:
        enabled = self._flags.is_enabled(FLAG_KEY)
        if enabled is True:
            return self._conductor.dispatch(
                IBVI_ADS_ROUTE,
                "smart_ads.queries.get_campaign_performance_v1",
                {"tenant_ref": tenant_ref, "start_date": start_date},
            )
        else:
            return self._legacy.call(LEGACY_ROUTE, {"tenant_ref": tenant_ref, "start_date": start_date})


async def fetch_adsets_async(payload: dict[str, Any], flags: Any, dispatch: Any, legacy: Any) -> Any:
    if flags.is_enabled(FLAG_KEY):
        return await dispatch("/ibvi-ads", "smart_ads.queries.get_adset_performance_v1", payload)
    else:
        return await legacy("legacy:mbras_campaigns_direct", payload)


def get_daily_summary(payload: dict[str, Any], flags: Any, dispatch: Any, legacy: Any) -> Any:
    return (
        dispatch(IBVI_ADS_ROUTE, SUMMARY_METHOD, payload)
        if flags.is_enabled("ibvi_ads.smart_ads_read_v1")
        else legacy(LEGACY_ROUTE, payload)
    )
'''.encode("utf-8")


class _StubP1Verifier:
    def verify_p1_envelope_signature(
        self, *, envelope: Mapping[str, Any], domain_prefix: str, store: CellObjectStorePort
    ) -> None:
        return None


class _StubOfflineIntel:
    @property
    def algorithm_identity(self) -> AlgorithmProvenanceIdentity:
        return _make_alg_id("smart_ads/finding/v1")

    def evaluate_offline(
        self, *, context: EvaluationContext, evidence: Sequence[AnalysisEvidence]
    ) -> tuple[Finding, ...]:
        return ()


class _StubLegacyProjector:
    def project_legacy_surface(
        self, *, surface_id: str, mapping_contract_ref: str, case: SeamDualProjectionCase
    ) -> Mapping[str, Any]:
        return dict(case.legacy_input_payload)


def test_consumer_ports_reexports_protocols_and_wheel_ast_compliance() -> None:
    assert Cpython312AstConsumerRoutingAnalyzer is DirectRoutingAnalyzer
    for sym in (
        "ConsumerRoutingAnalysis",
        "ConsumerRoutingAnalyzerPort",
        "EntrypointRouteFacts",
        "OfflineIntelligencePort",
        "P1SignatureVerifierPort",
        "SeamDualProjectionCase",
        "SeamLegacyProjectorPort",
    ):
        assert hasattr(ports_pkg, sym)
        assert sym in ports_pkg.__all__

    assert isinstance(Cpython312AstConsumerRoutingAnalyzer(), ConsumerRoutingAnalyzerPort)
    assert isinstance(_StubP1Verifier(), P1SignatureVerifierPort)
    assert isinstance(_StubOfflineIntel(), OfflineIntelligencePort)
    assert isinstance(_StubLegacyProjector(), SeamLegacyProjectorPort)

    for rel in (
        "smart_ads/ports/consumer.py",
        "smart_ads/ports/__init__.py",
        "smart_ads/adapters/consumer/__init__.py",
        "smart_ads/adapters/consumer/routing_analyzer.py",
    ):
        src = (REPO_ROOT / "src" / rel).read_text(encoding="utf-8")
        assert gov1_wheel._scan_wheel_python_ast_violations(src, filename=rel) == []


def test_consumer_port_dataclasses_closed_validation() -> None:
    fact = EntrypointRouteFacts(
        "get_daily_summary", _FLAG_KEY, "/ibvi-ads", ALLOWED_MCP_METHODS[0], _LEGACY_ROUTE
    )
    analysis = ConsumerRoutingAnalysis(
        _FLAG_KEY, False, _LEGACY_ROUTE, "/ibvi-ads", ("get_daily_summary",), (fact,)
    )
    assert analysis.verified_entrypoints == (fact,)
    with pytest.raises(ClosedValidationError):
        EntrypointRouteFacts("", _FLAG_KEY, "/ibvi-ads", ALLOWED_MCP_METHODS[0], _LEGACY_ROUTE)
    with pytest.raises(ClosedValidationError):
        ConsumerRoutingAnalysis(
            _FLAG_KEY, 0, _LEGACY_ROUTE, "/ibvi-ads", ("get_daily_summary",), (fact,)  # type: ignore[arg-type]
        )
    with pytest.raises(ClosedValidationError):
        ConsumerRoutingAnalysis(
            _FLAG_KEY, False, _LEGACY_ROUTE, "/ibvi-ads", ("z_ep", "a_ep"), (fact,)
        )

    case = SeamDualProjectionCase("case-1", "surface:campaign", b'{"jsonrpc":"2.0"}', None, {"k": 1})
    assert case.legacy_input_payload["k"] == 1
    with pytest.raises(ClosedValidationError):
        SeamDualProjectionCase("", "surface:campaign", b"{}", None, {"k": 1})
    with pytest.raises(ClosedValidationError):
        SeamDualProjectionCase("case-1", "surface:campaign", b"", None, {"k": 1})
    with pytest.raises(ClosedValidationError):
        SeamDualProjectionCase("case-1", "surface:campaign", b"{}", None, {"bad": 1.5})


@pytest.mark.parametrize(
    ("flag_bytes", "ff_path"),
    [
        (_VALID_JSON_FLAGS, "src/ibvi_ads/flags.json"),
        (_VALID_PY_FLAGS_SCALAR, "src/ibvi_ads/flags.py"),
        (_VALID_PY_FLAGS_DICT, "src/ibvi_ads/flags.py"),
    ],
)
def test_routing_analyzer_accepts_valid_json_and_python_flag_artifacts(
    flag_bytes: bytes, ff_path: str
) -> None:
    analyzer = Cpython312AstConsumerRoutingAnalyzer()
    contract = _make_contract(ff_source_path=ff_path)
    result = analyzer.analyze_consumer_routing(
        adapter_bytes=_VALID_ADAPTER_SOURCE,
        feature_flag_bytes=flag_bytes,
        contract=contract,
    )
    assert result.flag_key == _FLAG_KEY
    assert result.default_enabled is False
    assert result.disabled_legacy_route == _LEGACY_ROUTE
    assert result.enabled_smart_ads_route == "/ibvi-ads"
    assert result.discovered_public_entrypoints == (
        "CampaignGateway.fetch",
        "fetch_adsets_async",
        "get_daily_summary",
    )
    assert tuple(ep.symbol_name for ep in result.verified_entrypoints) == (
        "CampaignGateway.fetch",
        "fetch_adsets_async",
        "get_daily_summary",
    )
    for ep, expected in zip(result.verified_entrypoints, contract.read_entrypoints, strict=True):
        assert ep.flag_key == _FLAG_KEY
        assert ep.true_route == "/ibvi-ads"
        assert ep.true_mcp_method == expected.mcp_method
        assert ep.false_route == _LEGACY_ROUTE


@pytest.mark.parametrize(
    ("impl_name", "ver_info"),
    [("pypy", (3, 12, 0)), ("cpython", (3, 11, 9)), ("cpython", (3, 13, 0))],
)
def test_routing_analyzer_rejects_non_cpython_312_runtime(
    monkeypatch: pytest.MonkeyPatch, impl_name: str, ver_info: tuple[int, int, int]
) -> None:
    monkeypatch.setattr(sys, "implementation", SimpleNamespace(name=impl_name))
    monkeypatch.setattr(sys, "version_info", ver_info)
    analyzer = Cpython312AstConsumerRoutingAnalyzer()
    with pytest.raises(ClosedValidationError):
        analyzer.analyze_consumer_routing(
            adapter_bytes=_VALID_ADAPTER_SOURCE,
            feature_flag_bytes=_VALID_JSON_FLAGS,
            contract=_make_contract(),
        )


def test_routing_analyzer_rejects_invalid_input_types_and_byte_envelopes() -> None:
    analyzer = Cpython312AstConsumerRoutingAnalyzer()
    contract = _make_contract()
    for bad_adp, bad_ff, bad_c in (
        ("not-bytes", _VALID_JSON_FLAGS, contract),
        (_VALID_ADAPTER_SOURCE, bytearray(_VALID_JSON_FLAGS), contract),
        (_VALID_ADAPTER_SOURCE, _VALID_JSON_FLAGS, {}),
        (b"", _VALID_JSON_FLAGS, contract),
        (_VALID_ADAPTER_SOURCE, b"", contract),
        (b" " * 262_145, _VALID_JSON_FLAGS, contract),
        (b"\xef\xbb\xbf" + _VALID_ADAPTER_SOURCE, _VALID_JSON_FLAGS, contract),
        (_VALID_ADAPTER_SOURCE + b"\x00", _VALID_JSON_FLAGS, contract),
        (b"\xff\xfe", _VALID_JSON_FLAGS, contract),
        (b"# -*- coding: utf-8 -*-\n" + _VALID_ADAPTER_SOURCE, _VALID_JSON_FLAGS, contract),
        (b"#!/usr/bin/env python3\n# coding=latin-1\n" + _VALID_ADAPTER_SOURCE, _VALID_JSON_FLAGS, contract),
        (
            b"\x0c\x0c# coding: unicode_escape\n# safe \\u000aimport os\n" + _VALID_ADAPTER_SOURCE,
            _VALID_JSON_FLAGS,
            contract,
        ),
        (b"\x0b" + _VALID_ADAPTER_SOURCE, _VALID_JSON_FLAGS, contract),
        ("\u2028".encode("utf-8") + _VALID_ADAPTER_SOURCE, _VALID_JSON_FLAGS, contract),
    ):
        with pytest.raises(ClosedValidationError):
            analyzer.analyze_consumer_routing(
                adapter_bytes=bad_adp,  # type: ignore[arg-type]
                feature_flag_bytes=bad_ff,  # type: ignore[arg-type]
                contract=bad_c,  # type: ignore[arg-type]
            )


def test_routing_analyzer_enforces_ast_node_and_depth_ceilings() -> None:
    analyzer = Cpython312AstConsumerRoutingAnalyzer()
    contract = _make_contract((("read_one", ALLOWED_MCP_METHODS[0]),))
    deep_expr = "(" * 70 + '"x"' + ")" * 70
    deep_src = f"C = {deep_expr}\n".encode("utf-8")
    many_consts = "".join(f'C_{idx} = "v"\n' for idx in range(3500)).encode("utf-8")
    for payload in (deep_src, many_consts):
        with pytest.raises(ClosedValidationError):
            analyzer.analyze_consumer_routing(
                adapter_bytes=payload,
                feature_flag_bytes=_VALID_JSON_FLAGS,
                contract=contract,
            )


_BAD_FLAG_ARTIFACTS: tuple[bytes, ...] = (
    b'{"flag_key":"ibvi_ads.smart_ads_read_v1","default_enabled":true,"disabled_legacy_route":"legacy:mbras_campaigns_direct","enabled_smart_ads_route":"/ibvi-ads"}',
    b'{"flag_key":"ibvi_ads.smart_ads_read_v1","default_enabled":0,"disabled_legacy_route":"legacy:mbras_campaigns_direct","enabled_smart_ads_route":"/ibvi-ads"}',
    b'{"flag_key":"ibvi_ads.smart_ads_read_v1","default_enabled":"false","disabled_legacy_route":"legacy:mbras_campaigns_direct","enabled_smart_ads_route":"/ibvi-ads"}',
    b'{"flag_key":"ibvi_ads.smart_ads_read_v1","default_enabled":null,"disabled_legacy_route":"legacy:mbras_campaigns_direct","enabled_smart_ads_route":"/ibvi-ads"}',
    b'{"flag_key":"wrong.flag","default_enabled":false,"disabled_legacy_route":"legacy:mbras_campaigns_direct","enabled_smart_ads_route":"/ibvi-ads"}',
    b'{"flag_key":"ibvi_ads.smart_ads_read_v1","default_enabled":false,"disabled_legacy_route":"wrong:legacy","enabled_smart_ads_route":"/ibvi-ads"}',
    b'{"flag_key":"ibvi_ads.smart_ads_read_v1","default_enabled":false,"disabled_legacy_route":"legacy:mbras_campaigns_direct","enabled_smart_ads_route":"/ibvi-ads/v2"}',
    b'{"flag_key":"ibvi_ads.smart_ads_read_v1","default_enabled":false,"disabled_legacy_route":"legacy:mbras_campaigns_direct","enabled_smart_ads_route":"/ibvi-ads","extra":1}',
    b'FLAG_KEY = "ibvi_ads.smart_ads_read_v1"\nDEFAULT_ENABLED = True\n',
    b'FLAG_KEY = "ibvi_ads.smart_ads_read_v1"\nDEFAULT_ENABLED = 0\n',
    b'FLAG_KEY = "ibvi_ads.smart_ads_read_v1"\nDEFAULT_ENABLED = ""\n',
    b'FLAG_KEY = "ibvi_ads.smart_ads_read_v1"\nDEFAULT_ENABLED = "false"\n',
    b'FLAG_KEY = "ibvi_ads.smart_ads_read_v1"\nDEFAULT_ENABLED = None\n',
    b'import os\nFLAG_KEY = "ibvi_ads.smart_ads_read_v1"\nDEFAULT_ENABLED = bool(os.getenv("X"))\n',
    b'FLAG_KEY = "ibvi_ads.smart_ads_read_v1"\nDEFAULT_ENABLED = True\nDEFAULT_ENABLED = False\n',
    b'FLAG_KEY = "ibvi_ads.smart_ads_read_v1"\nif True:\n    DEFAULT_ENABLED = False\n',
    b'FLAG_KEY = "other.flag"\nDEFAULT_ENABLED = False\n',
    b'FLAG_KEY = "ibvi_ads.smart_ads_read_v1"\nDEFAULT_ENABLED = False\nDISABLED_LEGACY_ROUTE = "bad:route"\n',
    b'FEATURE_FLAGS = {"ibvi_ads.smart_ads_read_v1": True}\n',
    b'FLAG_KEY = "ibvi_ads.smart_ads_read_v1"\nNOT_ENABLED = False\n',
    b'FLAG_KEY = "ibvi_ads.smart_ads_read_v1"\nLEGACY_FALLBACK_ENABLED = False\n',
    b'flag_key = "ibvi_ads.smart_ads_read_v1"\ndefault_enabled = False\n',
)


@pytest.mark.parametrize("bad_flag_bytes", _BAD_FLAG_ARTIFACTS)
def test_routing_analyzer_rejects_malicious_or_ambiguous_flag_artifacts(bad_flag_bytes: bytes) -> None:
    analyzer = Cpython312AstConsumerRoutingAnalyzer()
    ff_path = "src/ibvi_ads/flags.json" if bad_flag_bytes.lstrip().startswith(b"{") else "src/ibvi_ads/flags.py"
    with pytest.raises(ClosedValidationError):
        analyzer.analyze_consumer_routing(
            adapter_bytes=_VALID_ADAPTER_SOURCE,
            feature_flag_bytes=bad_flag_bytes,
            contract=_make_contract(ff_source_path=ff_path),
        )


_SINGLE_CONTRACT_METHOD = "smart_ads.queries.get_campaign_performance_v1"
_VALID_SINGLE_ENTRYPOINT = (
    "def read_one(payload, flags, dispatch, legacy):\n"
    f'    if flags.is_enabled("{_FLAG_KEY}"):\n'
    f'        return dispatch("/ibvi-ads", "{_SINGLE_CONTRACT_METHOD}", payload)\n'
    "    else:\n"
    f'        return legacy("{_LEGACY_ROUTE}", payload)\n'
)

_BAD_ADAPTER_ARTIFACTS: tuple[str, ...] = (
    "import os\n" + _VALID_SINGLE_ENTRYPOINT,
    "import smart_ads\n" + _VALID_SINGLE_ENTRYPOINT,
    "from smart_ads.transports.mcp import handle_mcp_request_bytes\n" + _VALID_SINGLE_ENTRYPOINT,
    "from functools import wraps\n" + _VALID_SINGLE_ENTRYPOINT,
    "from . import helper\n" + _VALID_SINGLE_ENTRYPOINT,
    "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    pass\n" + _VALID_SINGLE_ENTRYPOINT,
    'mut_state = "bad"\n' + _VALID_SINGLE_ENTRYPOINT,
    'DUP = "a"\nDUP = "b"\n' + _VALID_SINGLE_ENTRYPOINT,
    'BAD_CONST = "smart_ads.internal.bypass"\n' + _VALID_SINGLE_ENTRYPOINT,
    'UNUSED_MCP = "smart_ads.queries.get_campaign_performance_v1"\n' + _VALID_SINGLE_ENTRYPOINT,
    'UNUSED_ROUTE = "/ibvi-ads"\n' + _VALID_SINGLE_ENTRYPOINT,
    "@dec\n" + _VALID_SINGLE_ENTRYPOINT,
    "class Sub(Base):\n    pass\n" + _VALID_SINGLE_ENTRYPOINT,
    _VALID_SINGLE_ENTRYPOINT + "\ndef extra_public(x):\n    return x\n",
    "def wrong_name(payload, flags, dispatch, legacy):\n"
    f'    if flags.is_enabled("{_FLAG_KEY}"):\n'
    f'        return dispatch("/ibvi-ads", "{_SINGLE_CONTRACT_METHOD}", payload)\n'
    "    else:\n"
    f'        return legacy("{_LEGACY_ROUTE}", payload)\n',
    _VALID_SINGLE_ENTRYPOINT + '\ndef _sneak(d):\n    return d("/ibvi-ads")\n',
    _VALID_SINGLE_ENTRYPOINT + '\ndef _sneak_str():\n    return "smart_ads.queries.get_ad_performance_v1"\n',
    "def read_one(payload={}, flags=None, dispatch=None, legacy=None):\n"
    f'    if flags.is_enabled("{_FLAG_KEY}"):\n'
    f'        return dispatch("/ibvi-ads", "{_SINGLE_CONTRACT_METHOD}", payload)\n'
    "    else:\n"
    f'        return legacy("{_LEGACY_ROUTE}", payload)\n',
    "def read_one(payload, flags, dispatch, legacy):\n"
    f'    if flags.is_enabled("{_FLAG_KEY}", True):\n'
    f'        return dispatch("/ibvi-ads", "{_SINGLE_CONTRACT_METHOD}", payload)\n'
    "    else:\n"
    f'        return legacy("{_LEGACY_ROUTE}", payload)\n',
    "def read_one(payload, flags, dispatch, legacy):\n"
    '    if flags.is_enabled("wrong.flag"):\n'
    f'        return dispatch("/ibvi-ads", "{_SINGLE_CONTRACT_METHOD}", payload)\n'
    "    else:\n"
    f'        return legacy("{_LEGACY_ROUTE}", payload)\n',
    "def read_one(payload, flags, dispatch, legacy):\n"
    f'    if not flags.is_enabled("{_FLAG_KEY}"):\n'
    f'        return dispatch("/ibvi-ads", "{_SINGLE_CONTRACT_METHOD}", payload)\n'
    "    else:\n"
    f'        return legacy("{_LEGACY_ROUTE}", payload)\n',
    "def read_one(payload, flags, dispatch, legacy):\n"
    f'    if flags.is_enabled("{_FLAG_KEY}") or True:\n'
    f'        return dispatch("/ibvi-ads", "{_SINGLE_CONTRACT_METHOD}", payload)\n'
    "    else:\n"
    f'        return legacy("{_LEGACY_ROUTE}", payload)\n',
    "def read_one(payload, flags, dispatch, legacy):\n"
    f'    enabled = flags.is_enabled("{_FLAG_KEY}")\n'
    "    if enabled == True:\n"
    f'        return dispatch("/ibvi-ads", "{_SINGLE_CONTRACT_METHOD}", payload)\n'
    "    else:\n"
    f'        return legacy("{_LEGACY_ROUTE}", payload)\n',
    "def read_one(payload, flags, dispatch, legacy):\n"
    f'    if flags.is_enabled("{_FLAG_KEY}"):\n'
    f'        return dispatch("/ibvi-ads", "{_SINGLE_CONTRACT_METHOD}", payload)\n',
    "def read_one(payload, flags, dispatch, legacy):\n"
    "    pre = 1\n"
    f'    if flags.is_enabled("{_FLAG_KEY}"):\n'
    f'        return dispatch("/ibvi-ads", "{_SINGLE_CONTRACT_METHOD}", payload)\n'
    "    else:\n"
    f'        return legacy("{_LEGACY_ROUTE}", payload)\n',
    "def read_one(payload, flags, dispatch, legacy):\n"
    f'    if flags.is_enabled("{_FLAG_KEY}"):\n'
    f'        return dispatch("/ibvi-ads/bypass", "{_SINGLE_CONTRACT_METHOD}", payload)\n'
    "    else:\n"
    f'        return legacy("{_LEGACY_ROUTE}", payload)\n',
    "def read_one(payload, flags, dispatch, legacy):\n"
    f'    if flags.is_enabled("{_FLAG_KEY}"):\n'
    '        return dispatch("/ibvi-ads", "smart_ads.queries.get_ad_performance_v1", payload)\n'
    "    else:\n"
    f'        return legacy("{_LEGACY_ROUTE}", payload)\n',
    "def read_one(payload, flags, dispatch, legacy):\n"
    f'    if flags.is_enabled("{_FLAG_KEY}"):\n'
    f'        return dispatch("/ibvi-ads", "{_SINGLE_CONTRACT_METHOD}", payload)\n'
    "    else:\n"
    '        return legacy("/ibvi-ads", payload)\n',
    "def read_one(payload, flags, dispatch, legacy):\n"
    f'    if flags.is_enabled("{_FLAG_KEY}"):\n'
    f'        return legacy("{_LEGACY_ROUTE}", payload)\n'
    "    else:\n"
    f'        return dispatch("/ibvi-ads", "{_SINGLE_CONTRACT_METHOD}", payload)\n',
    "def read_one(payload, flags, dispatch, legacy):\n"
    f'    if flags.is_enabled("{_FLAG_KEY}"):\n'
    f'        return dispatch("/ibvi-ads", "{_SINGLE_CONTRACT_METHOD}", transform(payload))\n'
    "    else:\n"
    f'        return legacy("{_LEGACY_ROUTE}", payload)\n',
    "def read_one(payload, flags, dispatch, legacy):\n"
    f'    if flags.is_enabled("{_FLAG_KEY}"):\n'
    f'        return dispatch("/ibvi-ads", "{_SINGLE_CONTRACT_METHOD}", {{"m": "smart_ads.leak"}})\n'
    "    else:\n"
    f'        return legacy("{_LEGACY_ROUTE}", payload)\n',
    f'FLAG_KEY = "{_FLAG_KEY}"\nIBVI_ADS_ROUTE = "/ibvi-ads"\n'
    'def read_one(payload, flags, dispatch, legacy, FLAG_KEY="always_on", IBVI_ADS_ROUTE="/hijack"):\n'
    "    if flags.is_enabled(FLAG_KEY):\n"
    f'        return dispatch(IBVI_ADS_ROUTE, "{_SINGLE_CONTRACT_METHOD}", payload)\n'
    "    else:\n"
    f'        return legacy("{_LEGACY_ROUTE}", payload)\n',
    'def read_one(payload, flags, dispatch, legacy, IBVI_ADS_ROUTE="/hijack"):\n'
    f'    if flags.is_enabled("{_FLAG_KEY}"):\n'
    f'        return dispatch(IBVI_ADS_ROUTE, "{_SINGLE_CONTRACT_METHOD}", payload)\n'
    "    else:\n"
    f'        return legacy("{_LEGACY_ROUTE}", payload)\n'
    'IBVI_ADS_ROUTE = "/ibvi-ads"\n',
    _VALID_SINGLE_ENTRYPOINT + "\ndef __getattr__(name):\n    return name\n",
)


_BAD_CLASS_ADAPTER_ARTIFACTS: tuple[str, ...] = (
    "class Gw:\n"
    "    def __new__(self, flags, conductor, legacy):\n"
    "        return conductor\n"
    "    def fetch(self, payload, flags, dispatch, legacy):\n"
    f'        if flags.is_enabled("{_FLAG_KEY}"):\n'
    f'            return dispatch("/ibvi-ads", "{_SINGLE_CONTRACT_METHOD}", payload)\n'
    "        else:\n"
    f'            return legacy("{_LEGACY_ROUTE}", payload)\n',
    "class Gw:\n"
    "    def __getattribute__(self, name):\n"
    "        return name\n"
    "    def fetch(self, payload, flags, dispatch, legacy):\n"
    f'        if flags.is_enabled("{_FLAG_KEY}"):\n'
    f'            return dispatch("/ibvi-ads", "{_SINGLE_CONTRACT_METHOD}", payload)\n'
    "        else:\n"
    f'            return legacy("{_LEGACY_ROUTE}", payload)\n',
    "class Gw:\n"
    "    def fetch(self, payload, flags, dispatch):\n"
    f'        if flags.is_enabled("{_FLAG_KEY}"):\n'
    f'            return dispatch("/ibvi-ads", "{_SINGLE_CONTRACT_METHOD}", payload)\n'
    "        else:\n"
    f'            return self.__setattr__("{_LEGACY_ROUTE}", payload)\n',
    "class Gw:\n"
    "    def fetch(self, payload):\n"
    f'        if self._flags.is_enabled("{_FLAG_KEY}"):\n'
    f'            return self._conductor("/ibvi-ads", "{_SINGLE_CONTRACT_METHOD}", payload)\n'
    "        else:\n"
    f'            return self._legacy("{_LEGACY_ROUTE}", payload)\n',
    "class Gw:\n"
    "    def __init__(self, shared, legacy):\n"
    "        self._flags = shared\n"
    "        self._conductor = shared\n"
    "        self._legacy = legacy\n"
    "    def fetch(self, payload):\n"
    f'        if self._flags.is_enabled("{_FLAG_KEY}"):\n'
    f'            return self._conductor("/ibvi-ads", "{_SINGLE_CONTRACT_METHOD}", payload)\n'
    "        else:\n"
    f'            return self._legacy("{_LEGACY_ROUTE}", payload)\n',
    "class Gw:\n"
    "    def __init__(self, flags, conductor, legacy):\n"
    "        self.__dict__ = flags\n"
    "        self._conductor = conductor\n"
    "        self._legacy = legacy\n"
    "    def fetch(self, payload, f):\n"
    f'        if f.is_enabled("{_FLAG_KEY}"):\n'
    f'            return self._conductor("/ibvi-ads", "{_SINGLE_CONTRACT_METHOD}", payload)\n'
    "        else:\n"
    f'            return self._legacy("{_LEGACY_ROUTE}", payload)\n',
)


@pytest.mark.parametrize("bad_adapter_src", _BAD_ADAPTER_ARTIFACTS)
def test_routing_analyzer_rejects_malicious_or_noncompliant_adapters(bad_adapter_src: str) -> None:
    analyzer = Cpython312AstConsumerRoutingAnalyzer()
    contract = _make_contract((("read_one", _SINGLE_CONTRACT_METHOD),))
    with pytest.raises(ClosedValidationError):
        analyzer.analyze_consumer_routing(
            adapter_bytes=bad_adapter_src.encode("utf-8"),
            feature_flag_bytes=_VALID_JSON_FLAGS,
            contract=contract,
        )


@pytest.mark.parametrize("bad_cls_src", _BAD_CLASS_ADAPTER_ARTIFACTS)
def test_routing_analyzer_rejects_class_dunders_unbound_self_and_init_aliasing(
    bad_cls_src: str,
) -> None:
    analyzer = Cpython312AstConsumerRoutingAnalyzer()
    contract = _make_contract((("Gw.fetch", _SINGLE_CONTRACT_METHOD),))
    with pytest.raises(ClosedValidationError):
        analyzer.analyze_consumer_routing(
            adapter_bytes=bad_cls_src.encode("utf-8"),
            feature_flag_bytes=_VALID_JSON_FLAGS,
            contract=contract,
        )
