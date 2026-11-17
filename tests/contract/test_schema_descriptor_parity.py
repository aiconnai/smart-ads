"""Parity of the PR 2 core schema descriptors with the implemented types, and package re-exports.

`CORE_SCHEMA_DESCRIPTORS` in `smart_ads.contracts.schemas` is literal data (that module cannot
import `smart_ads.analytics` or `smart_ads.reconciliation`, which import it). These tests pin each
descriptor to the key set the implemented type actually serializes, following the rule of the
existing descriptors: `fields` is the complete `to_dict()` key set, including `$schema` when the
type emits it and `integrity` for P1 artifacts (ADR-0001 section 12.7), while embedded value
objects carry no `integrity` and no P1 domain prefix.
"""
from __future__ import annotations

import ast
import dataclasses
import importlib
from pathlib import Path
import subprocess
import sys
from typing import Any

import pytest

from smart_ads.analytics import cells, certification, formulas, intelligence, lattice, policy, results
from smart_ads.contracts.jcs import ADR_P1_DOMAIN_PREFIXES, ArtifactLocator, P1Integrity
from smart_ads.contracts.numerics import PHASE1_BASE_METRICS
from smart_ads.contracts.schemas import CORE_SCHEMA_DESCRIPTORS
import smart_ads.contracts.schemas as schemas_module
from smart_ads.reconciliation import bundle_7b, tolerance
from tests.unit._bundle_7b_builders import CLICKS, native_dict, profile_dict
from tests.unit._bundle_7b_world import build_world

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
}
EMBEDDED_SCHEMA_TYPES: dict[str, type] = {
    "smart_ads/regression_fixture/v1": lattice.RegressionFixtureV1,
    "smart_ads/derived_metric_definition/v1": formulas.DerivedMetricDefinition,
    "smart_ads/canonical_result_set/v1": results.CanonicalResultSet,
    "smart_ads/fact_evidence_selector/v1": bundle_7b.FactEvidenceSelector,
    "smart_ads/fact_reconciliation/v1": bundle_7b.FactReconciliation,
}
PR2_SCHEMA_TYPES: dict[str, type] = {**P1_SCHEMA_TYPES, **EMBEDDED_SCHEMA_TYPES}
# Embedded value objects of ADR section 5.4 L1133-1146 carry no `$schema` member on the wire.
SCHEMALESS_EMBEDDED = frozenset(
    {"smart_ads/fact_evidence_selector/v1", "smart_ads/fact_reconciliation/v1"}
)

# Module-level schema id constants that must agree with the class constant and the descriptor.
SCHEMA_ID_CONSTANTS: tuple[tuple[str, str], ...] = (
    (cells.ANALYSIS_RESULT_SCHEMA_TYPE, "smart_ads/analysis_result_schema/v1"),
    (cells.ANALYSIS_RESULT_TYPE, "smart_ads/analysis_result/v1"),
    (cells.ANALYSIS_EXECUTION_TYPE, "smart_ads/analysis_execution/v1"),
    (cells.CANONICAL_RESULT_SET_TYPE, "smart_ads/canonical_result_set/v1"),
    (intelligence.FINDING_SCHEMA, "smart_ads/finding/v1"),
    (certification.CERTIFICATION_RECORD_SCHEMA, "smart_ads/certification_record/v1"),
    (bundle_7b.FACT_EVIDENCE_SELECTOR_SCHEMA, "smart_ads/fact_evidence_selector/v1"),
    (bundle_7b.FACT_RECONCILIATION_SCHEMA, "smart_ads/fact_reconciliation/v1"),
    (bundle_7b.NATIVE_REQUEST_PROJECTION_SCHEMA, "smart_ads/native_request_projection/v1"),
    (bundle_7b.CERTIFICATION_7B_RECORD_SCHEMA, "smart_ads/certification_7b_record/v1"),
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
        "cells", "certification", "formulas", "intelligence", "lattice", "policy", "results",
    ),
    # The 7B facade, never the internal bundle_* modules.
    "smart_ads.reconciliation": ("bundle_7b", "tolerance"),
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


@pytest.fixture(scope="module")
def instances() -> dict[str, Any]:
    built = {
        **_analysis_instances(),
        **_formula_and_policy_instances(),
        **_reconciliation_instances(),
    }
    assert set(built) == set(PR2_SCHEMA_TYPES)
    for schema_id, obj in built.items():
        assert type(obj) is PR2_SCHEMA_TYPES[schema_id], schema_id
    return built


# ---------------------------------------------------------------- descriptor registry shape


def test_registry_has_28_unique_descriptors_sorted_by_utf8_schema_id() -> None:
    schema_ids = [d["schema_id"] for d in CORE_SCHEMA_DESCRIPTORS]
    assert len(CORE_SCHEMA_DESCRIPTORS) == 28
    assert len(set(schema_ids)) == len(schema_ids)
    assert schema_ids == _utf8_sorted(schema_ids)
    assert set(schema_ids) == PRE_PR2_SCHEMA_IDS | set(PR2_SCHEMA_TYPES)
    assert len(PRE_PR2_SCHEMA_IDS | set(PR2_SCHEMA_TYPES)) == 13 + 15


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
    return [
        (
            "smart_ads/analysis_policy/v1",
            frozenset(policy.AnalysisPolicy.KEYS),
            frozenset(policy.AnalysisPolicy.CORE_KEYS),
        ),
        (
            "smart_ads/finding/v1",
            frozenset(intelligence.Finding.KEYS),
            frozenset(intelligence.Finding.CORE_KEYS),
        ),
        (
            "smart_ads/certification_record/v1",
            frozenset(certification.AnalyticalCertificationRecord.KEYS),
            frozenset(certification.AnalyticalCertificationRecord.CORE_KEYS),
        ),
        (
            "smart_ads/native_request_projection/v1",
            frozenset(bundle_7b.NativeRequestProjection.CORE_KEYS) | with_integrity,
            frozenset(bundle_7b.NativeRequestProjection.CORE_KEYS),
        ),
        (
            "smart_ads/certification_7b_record/v1",
            frozenset(bundle_7b.Certification7BRecord.CORE_KEYS) | with_integrity,
            frozenset(bundle_7b.Certification7BRecord.CORE_KEYS),
        ),
        (
            "smart_ads/fact_evidence_selector/v1",
            frozenset(bundle_7b.FactEvidenceSelector.KEYS),
            None,
        ),
        ("smart_ads/fact_reconciliation/v1", frozenset(bundle_7b.FactReconciliation.KEYS), None),
    ]


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
def test_withheld_names_are_really_ambiguous_and_absent(package: str) -> None:
    pkg = importlib.import_module(package)
    for name in WITHHELD_AMBIGUOUS[package]:
        objects = {
            id(getattr(_submodule(package, sub), name))
            for sub in PACKAGE_SUBMODULES[package]
            if name in _submodule(package, sub).__all__
        }
        assert len(objects) >= 2, name
        assert name not in pkg.__all__
        assert not hasattr(pkg, name)


_FRESH_IMPORT_CHECK = """
import sys
for name in sys.argv[1:]:
    __import__(name)
for name in ("smart_ads.analytics", "smart_ads.reconciliation"):
    module = sys.modules[name]
    missing = [n for n in module.__all__ if not hasattr(module, n)]
    if missing:
        raise SystemExit(f"{name}: unresolved {missing}")
"""


@pytest.mark.parametrize(
    "order",
    [
        ("smart_ads.analytics", "smart_ads.reconciliation"),
        ("smart_ads.reconciliation", "smart_ads.analytics"),
        ("smart_ads.contracts.schemas", "smart_ads.reconciliation", "smart_ads.analytics"),
        ("smart_ads.analytics.lattice", "smart_ads.reconciliation.tolerance"),
    ],
)
def test_packages_import_cleanly_in_a_fresh_interpreter(order: tuple[str, ...]) -> None:
    completed = subprocess.run(
        [sys.executable, "-W", "error", "-c", _FRESH_IMPORT_CHECK, *order],
        cwd=REPO_ROOT,
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
        "'smart_ads.reconciliation'))]\n"
        "if loaded:\n"
        "    raise SystemExit(f'unexpected: {loaded}')\n"
    )
    completed = subprocess.run(
        [sys.executable, "-W", "error", "-c", code],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
