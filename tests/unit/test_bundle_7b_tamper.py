"""Tampered frozen objects are rejected at the public entry points of the 7B bundle.

A frozen dataclass validates once, in ``__post_init__``; ``object.__setattr__`` (or
``__delattr__``) bypasses that. Every public function that consumes such an object
treats it as untrusted: a tampered object is rejected with a coded
``Bundle7BDefectError`` exactly as its wire form (``from_dict(to_dict())``) would be,
never with a bare exception and never by a silent accept.

The oracle of every sweep is that wire form, not the implementation under test.
"""
from __future__ import annotations

import collections.abc
import contextlib
import dataclasses
import hashlib
import inspect
import typing
from collections.abc import Callable, Iterator
from typing import Any

import pytest

from smart_ads.contracts.jcs import canonicalize_jcs, p1_content_digest
from smart_ads.contracts.schemas import NormalizedCollectionFact, ReconciliationRowKey
from smart_ads.reconciliation import bundle_7b as b7
from smart_ads.reconciliation.bundle_7b import Bundle7BDefectError, MetricPairKey
from tests.unit._bundle_7b_builders import (
    CANDIDATE_AT,
    CLICKS,
    GATE3_LOC,
    IMPRESSIONS,
    KEY_ID,
    REF_A,
    REF_B,
    RUN_LOC,
    SPEND,
    canonical_query,
    collection_result,
    facts_for,
    fingerprint_dict,
    many_rows,
    native_dict,
    reconcile,
    registry_loc,
    results,
    row_key,
    sha,
    signature,
)
from tests.unit._bundle_7b_world import (
    REF_ALGO,
    World,
    build_world,
    pinned_algorithm,
)

MISSING = object()  # sentinel: delete the slot instead of setting it
Outcome = tuple[str, str | None]  # ("ok", None) | ("coded", code) | ("leak", exception name)
# A one-resource world keeps every sweep fast; the default world is used for golden values.
ONE_RESOURCE = {(REF_A, IMPRESSIONS): "1000", (REF_A, CLICKS): "100", (REF_A, SPEND): "50000"}


@pytest.fixture(scope="module")
def world() -> World:
    return build_world(ONE_RESOURCE, ONE_RESOURCE)


class StrSub(str):
    """A str subclass: still a str, not an exact one."""


class IntSub(int):
    """An int subclass: rejected wherever the grammar says strict int."""


class AlwaysEq:
    """Not a str, equal to everything: a validator that compares with ``!=`` lets it through,
    and it is no JSON value, so canonicalizing it later fails."""

    def __eq__(self, other: object) -> bool:
        return True

    def __ne__(self, other: object) -> bool:
        return False


# ---------------------------------------------------------------------------
# Tamper machinery
# ---------------------------------------------------------------------------


def hostile_values(value: object, light: bool = False) -> list[object]:
    """Hostile replacements: wrong type, bool, None, empty, list-for-tuple, subclass, digest,
    and an always-equal object that is no JSON value. ``light`` keeps the four that matter
    most (None, always-equal, wrong grammar, deletion) for arguments that share a code path."""
    if light:
        return [None, AlwaysEq(), "not-valid", MISSING]
    out: list[object] = [None, True, 12345, "not-valid", (), AlwaysEq(), MISSING]
    if isinstance(value, bool):
        out.append(not value)
    if isinstance(value, tuple):
        out += [list(value), (12345,)]
    if isinstance(value, str):
        out.append(StrSub(value))
        if value.startswith("sha256:"):
            out.append(sha("f") if value != sha("f") else sha("e"))
    if type(value) is int:
        out += [IntSub(value), value + 1]
    return out


@contextlib.contextmanager
def hostile_set(owner: object, name: str, value: object) -> Iterator[None]:
    original = getattr(owner, name)
    if value is MISSING:
        object.__delattr__(owner, name)
    else:
        object.__setattr__(owner, name, value)
    try:
        yield
    finally:
        object.__setattr__(owner, name, original)


def reachable(root: object) -> Iterator[Any]:
    """Dataclass instances reachable from ``root``: the first element of each sequence, and
    at most two instances of one class of this package (both sides of a pair stay covered)
    or one instance of any other class."""
    seen: set[int] = set()
    per: dict[type, int] = {}
    stack = [root]
    while stack:
        obj = stack.pop()
        if id(obj) in seen:
            continue
        seen.add(id(obj))
        if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
            limit = 2 if type(obj).__module__.startswith("smart_ads.reconciliation.") else 1
            if per.get(type(obj), 0) >= limit:
                continue
            per[type(obj)] = per.get(type(obj), 0) + 1
            yield obj
            stack.extend(getattr(obj, f.name) for f in dataclasses.fields(obj))
        elif isinstance(obj, (tuple, list)) and obj:
            stack.append(obj[0])


def run(call: Callable[[], object]) -> Outcome:
    try:
        call()
    except Bundle7BDefectError as exc:
        if exc.code not in b7.DEFECT_CODES:  # explicit: an assert is stripped under python -O
            raise AssertionError(f"not a closed defect code: {exc.code!r}") from exc
        return ("coded", exc.code)
    except Exception as exc:  # noqa: BLE001 - classifying a leak is the point
        return ("leak", type(exc).__name__)
    return ("ok", None)


def rebuild(obj: Any) -> Any:
    """The wire-form round trip; ``ResolvedGate3SelectionState`` has none, so its own
    constructor around a re-parsed locator."""
    cls = type(obj)
    if hasattr(cls, "from_dict"):
        return cls.from_dict(obj.to_dict())
    return dataclasses.replace(obj, locator=copy_of(obj.locator))


def wire_outcome(
    root: Any, entry: Callable[[Any], object], clean: Any, valid: Outcome, *, lying: bool = False
) -> Outcome:
    """What the entry point must do with ``root``: what it does with its wire form. One equal
    to the clean object's behaves as the valid object, any other is run through the entry
    point. ``lying`` (``AlwaysEq``): equality proves nothing, the wire form must canonicalize."""
    try:
        fresh = rebuild(root)
    except Bundle7BDefectError as exc:
        return ("coded", exc.code)
    except Exception:  # noqa: BLE001 - a bare error of any kind is a malformed member
        return ("coded", "malformed_member")
    if lying and not serializable(fresh):
        return ("coded", "malformed_member")
    return valid if fresh == clean else run(lambda: entry(fresh))


def serializable(obj: Any) -> bool:
    """Whether ``obj`` has a wire form that RFC 8785 can canonicalize (equality can lie);
    ``ResolvedGate3SelectionState`` has none, so its locator stands for it."""
    to_dict = getattr(obj, "to_dict", None) or obj.locator.to_dict
    try:
        canonicalize_jcs(to_dict())
    except Exception:  # noqa: BLE001 - any failure means there is no canonical wire form
        return False
    return True


def sweep(root: Any, entry: Callable[[Any], object], light: bool = False) -> list[str]:
    """Tamper every field of every reachable object with every hostile value; list the misses."""
    misses: list[str] = []
    clean, valid = rebuild(root), run(lambda: entry(root))
    if valid != ("ok", None):
        raise AssertionError(f"the untampered root must be accepted, got {valid}")
    for owner in list(reachable(root)):
        for field in dataclasses.fields(owner):
            for value in hostile_values(getattr(owner, field.name), light):
                with hostile_set(owner, field.name, value):
                    lying = isinstance(value, AlwaysEq)
                    expected = wire_outcome(root, entry, clean, valid, lying=lying)
                    actual = run(lambda: entry(root))
                if actual != expected:
                    shown = repr(value)[:36]
                    misses.append(
                        f"{type(owner).__name__}.{field.name}={shown}: "
                        f"wire {expected}, entry {actual}"
                    )
    return misses


def assert_no_misses(misses: list[str]) -> None:
    assert not misses, f"{len(misses)} tampered cases: " + "; ".join(misses[:12])


def copy_of(obj: Any) -> Any:
    return type(obj).from_dict(obj.to_dict())


# ---------------------------------------------------------------------------
# The reviewer's reproduction and the nested cases
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def record(world: World) -> b7.Certification7BRecord:
    return world.parsed()


def _verify(world: World, rec: Any, **overrides: Any) -> None:
    b7.verify_certification_7b_record(rec, **dict(world.kwargs, **overrides))


def test_a_record_with_emptied_reconciliations_is_not_accepted(
    world: World, record: b7.Certification7BRecord
) -> None:
    with hostile_set(record, "fact_reconciliations", ()):
        with pytest.raises(Bundle7BDefectError) as wire:
            b7.Certification7BRecord.from_dict(record.to_dict())
        assert run(lambda: _verify(world, record)) == ("coded", wire.value.code)
    assert run(lambda: _verify(world, record)) == ("ok", None)


@pytest.mark.parametrize(
    ("path", "field", "value", "code"),
    [
        (("candidate_execution",), "row_count", True, "malformed_member"),
        (("candidate_execution",), "row_count", 7, "row_count_mismatch"),
        (("reference_execution",), "result_status", "partial", "fixed_member_mismatch"),
        (("row_pairing",), "maximum_retrieval_skew_seconds", 301, "fixed_member_mismatch"),
        (("row_pairing",), "aggregation_rule", None, "fixed_member_mismatch"),
        ((), "required_metrics", 5, "malformed_member"),
        ((), "required_metrics", ("metric:spend_v1",), "fixed_member_mismatch"),
        ((), "bundle_outcome", "failed", "fixed_member_mismatch"),
        (("candidate_execution", "gate3_certification_fingerprint"), "parser_code_digest",
         sha("f"), "fingerprint_member_mismatch"),
        (("reference_execution", "native_request_projection"), "endpoint",
         "https://x.test/v21.0/insights", "native_projection_forbidden_content"),
        (("fact_reconciliations", 0, "candidate", "fact_evidence_selector"),
         "fact_projection_digest", sha("f"), "logical_digest_mismatch"),
        (("fact_reconciliations", 0, "reference"), "currency", "USD", "malformed_member"),
        (("fact_reconciliations", 0), "canonical_fact_key", None, "malformed_member"),
        (("canonical_query_contract", "date_range"), "inclusive", False, "malformed_member"),
    ],
)
def test_nested_tampering_inside_a_record_is_a_coded_defect(
    world: World, record: b7.Certification7BRecord, path: tuple[Any, ...],
    field: str, value: object, code: str,
) -> None:
    owner: Any = record
    for step in path:
        owner = owner[step] if isinstance(step, int) else getattr(owner, step)
    clean = copy_of(record)
    with hostile_set(owner, field, value):
        assert run(lambda: _verify(world, record)) == ("coded", code)
        wire = wire_outcome(record, lambda fresh: _verify(world, fresh), clean, ("ok", None))
        assert wire == ("coded", code)


def test_tampering_in_the_last_element_of_a_sequence_is_caught_too(
    world: World, record: b7.Certification7BRecord
) -> None:
    last = record.fact_reconciliations[-1]
    with hostile_set(last.reference.fact_evidence_selector, "canonical_metric_ref", 12345):
        assert run(lambda: _verify(world, record)) == ("coded", "malformed_member")
    with hostile_set(last, "reconciliation_outcome", "mismatch"):
        assert run(lambda: _verify(world, record)) == ("coded", "asserted_comparison_malformed")


def test_nested_tampering_that_stays_well_formed_is_caught_by_the_verifier_bindings(
    world: World, record: b7.Certification7BRecord
) -> None:
    """The record seals the reconciliations, so a nested digest is resealed to reach the verifier."""
    selector = record.fact_reconciliations[0].candidate.fact_evidence_selector
    with hostile_set(selector, "fact_projection_digest", sha("f")):
        resealed = b7.compute_logical_fact_reconciliation_digest(record.fact_reconciliations)
        with hostile_set(record, "logical_fact_reconciliation_digest", resealed):
            assert run(lambda: _verify(world, record)) == (
                "coded", "fact_projection_digest_mismatch"
            )


def test_a_list_where_a_tuple_is_required_behaves_as_the_valid_object(
    world: World, record: b7.Certification7BRecord
) -> None:
    with hostile_set(record, "fact_reconciliations", list(record.fact_reconciliations)):
        assert run(lambda: _verify(world, record)) == ("ok", None)
    execution = record.candidate_execution
    with hostile_set(execution, "row_count", IntSub(execution.row_count)):
        assert run(lambda: _verify(world, record)) == ("coded", "malformed_member")


# ---------------------------------------------------------------------------
# Sweeps: every field of every reachable value object, every hostile value
# ---------------------------------------------------------------------------

VERIFY_ROOTS = (
    "record",
    "gate3_certification_fingerprint",
    "gate3_selection",
    "driver_contract",
    "candidate_admission",
    "reference_admission",
    "candidate_result",
    "reference_result",
    "migration_run_context_locator",
    "candidate_effect_proof_locator",
    "candidate_effect_result_locator",
    "reference_effect_proof_locator",
    "reference_effect_result_locator",
)


# The reference arguments share the candidate's code path: they are swept under their own
# names (a dropped re-parse must fail a case) with the light hostile set, for the runtime.
LIGHT_ROOTS = (
    "reference_admission",
    "reference_result",
    "reference_effect_proof_locator",
    "reference_effect_result_locator",
)


@pytest.mark.parametrize("name", VERIFY_ROOTS)
def test_verify_sweep_every_field_of_every_reachable_object(
    world: World, record: b7.Certification7BRecord, name: str
) -> None:
    """Each argument is swept under its own name: dropping one re-parse must fail a case."""
    if name == "record":
        root, entry = record, lambda obj: _verify(world, obj)
    else:
        original = world.kwargs[name]
        # Own instances only: a locator shared with another argument would be tampered in both.
        root = (
            dataclasses.replace(original, locator=copy_of(original.locator))
            if name == "gate3_selection"
            else copy_of(original)
        )
        entry = lambda obj: _verify(world, record, **{name: obj})  # noqa: E731
    assert_no_misses(sweep(root, entry, light=name in LIGHT_ROOTS))


RECONCILE_ROOTS = (
    "candidate_result",
    "reference_result",
    "canonical_query_contract",
    "gate3_selection_locator",
    "migration_run_context_locator",
)


@pytest.fixture
def reconcile_inputs() -> dict[str, Any]:
    cand, ref = results(ONE_RESOURCE, ONE_RESOURCE)
    return {
        "candidate_result": cand,
        "reference_result": ref,
        "canonical_query_contract": canonical_query(),
        "gate3_selection_locator": copy_of(GATE3_LOC),
        "migration_run_context_locator": copy_of(RUN_LOC),
    }


@pytest.mark.parametrize("name", RECONCILE_ROOTS)
def test_reconcile_sweep_every_field_of_every_reachable_object(
    reconcile_inputs: dict[str, Any], name: str
) -> None:
    def entry(obj: Any) -> None:
        inputs = dict(reconcile_inputs, **{name: obj})
        reconcile(inputs.pop("candidate_result"), inputs.pop("reference_result"), **inputs)

    assert run(lambda: entry(reconcile_inputs[name])) == ("ok", None)
    assert_no_misses(sweep(reconcile_inputs[name], entry))


# ---------------------------------------------------------------------------
# The other public functions that take this package's value objects
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def parts() -> dict[str, Any]:
    cand = collection_result(
        facts_for({(REF_A, CLICKS): "100"}), side="candidate", retrieved_at=CANDIDATE_AT
    )
    pair = MetricPairKey(row_key(REF_A), CLICKS)
    return {
        "result": cand,
        "pair": pair,
        "other_pair": MetricPairKey(row_key(REF_B), SPEND),
        "selector": b7.select_fact_evidence(cand, pair),
        "projection": b7.NativeRequestProjection.from_dict(native_dict()),
        "fingerprint": b7.Gate3CertificationFingerprint.from_dict(fingerprint_dict()),
        "key": row_key(REF_A),
        "other_key": row_key(REF_B),
        "fact": facts_for({(REF_A, CLICKS): "1"})[0],
        "reconciliations": reconcile(*results()).fact_reconciliations,
    }


def _check_native(projection: Any, query: Any, parts: dict[str, Any]) -> None:
    b7.check_native_request(
        projection,
        native_request_digest=parts["projection"].native_request_digest,
        canonical_query=query,
        algorithm_digest=REF_ALGO,
        project_native_request=pinned_algorithm,
    )


def _cases(parts: dict[str, Any]) -> dict[str, tuple[Any, Callable[[Any], object]]]:
    recs, fact_set = parts["reconciliations"], parts["result"]
    return {
        "check_native_request(projection)": (
            copy_of(parts["projection"]),
            lambda obj: _check_native(obj, canonical_query(), parts)),
        "check_native_request(canonical_query)": (
            canonical_query(), lambda obj: _check_native(parts["projection"], obj, parts)),
        "require_same_fingerprint(left)": (
            copy_of(parts["fingerprint"]),
            lambda obj: b7.require_same_fingerprint(obj, parts["fingerprint"], label="t")),
        "require_same_fingerprint(right)": (
            copy_of(parts["fingerprint"]),
            lambda obj: b7.require_same_fingerprint(parts["fingerprint"], obj, label="t")),
        "select_fact_evidence(result)": (
            fact_set, lambda obj: b7.select_fact_evidence(obj, parts["pair"])),
        "select_fact_evidence(pair)": (
            copy_of(parts["pair"]), lambda obj: b7.select_fact_evidence(fact_set, obj)),
        "resolve_fact_evidence(selector)": (
            copy_of(parts["selector"]), lambda obj: b7.resolve_fact_evidence(obj, fact_set)),
        "resolve_fact_evidence(result)": (
            fact_set, lambda obj: b7.resolve_fact_evidence(parts["selector"], obj)),
        "compute_canonical_fact_key_digest": (
            copy_of(parts["key"]), b7.compute_canonical_fact_key_digest),
        "compute_row_universe": (
            copy_of(parts["key"]),
            lambda obj: b7.compute_row_universe([obj, parts["other_key"]])),
        "compute_row_universe_digest": (
            copy_of(parts["key"]),
            lambda obj: b7.compute_row_universe_digest((obj, parts["other_key"]))),
        "expected_pair_universe": (
            copy_of(parts["key"]), lambda obj: b7.expected_pair_universe((obj,))),
        "compute_pair_universe(pair)": (
            copy_of(parts["pair"]),
            lambda obj: b7.compute_pair_universe([obj, parts["other_pair"]])),
        "compute_pair_universe(fact)": (
            copy_of(parts["fact"]), lambda obj: b7.compute_pair_universe([obj])),
        "compute_logical_fact_reconciliation_digest": (
            copy_of(recs[0]),
            lambda obj: b7.compute_logical_fact_reconciliation_digest((obj, *recs[1:]))),
    }


CASE_NAMES = (
    "check_native_request(projection)",
    "check_native_request(canonical_query)",
    "require_same_fingerprint(left)",
    "require_same_fingerprint(right)",
    "select_fact_evidence(result)",
    "select_fact_evidence(pair)",
    "resolve_fact_evidence(selector)",
    "resolve_fact_evidence(result)",
    "compute_canonical_fact_key_digest",
    "compute_row_universe",
    "compute_row_universe_digest",
    "expected_pair_universe",
    "compute_pair_universe(pair)",
    "compute_pair_universe(fact)",
    "compute_logical_fact_reconciliation_digest",
)


@pytest.mark.parametrize("name", CASE_NAMES)
def test_public_function_sweep(parts: dict[str, Any], name: str) -> None:
    root, entry = _cases(parts)[name]
    assert run(lambda: entry(root)) == ("ok", None)
    assert_no_misses(sweep(root, entry))


def _mentions_value_object(annotation: object) -> bool:
    """A frozen dataclass anywhere in the annotation (a callable's own parameters excluded)."""
    if isinstance(annotation, type):
        return dataclasses.is_dataclass(annotation)
    if typing.get_origin(annotation) is collections.abc.Callable:
        return False
    return any(_mentions_value_object(arg) for arg in typing.get_args(annotation))


def public_functions_taking_value_objects() -> set[str]:
    """Functions of the facade's ``__all__`` with a parameter annotated by a value object."""
    found = set()
    for name in b7.__all__:
        function = getattr(b7, name)
        if inspect.isfunction(function):
            hints = typing.get_type_hints(function)
            hints.pop("return", None)
            if any(_mentions_value_object(hint) for hint in hints.values()):
                found.add(name)
    return found


# Swept by name above, plus the verifier and reconcile (own sweeps) and the locator
# primitives (``test_locator_primitives_never_leak_a_bare_error``).
SWEPT_FUNCTIONS = {name.split("(")[0] for name in CASE_NAMES} | {
    "verify_certification_7b_record",
    "reconcile_7b_fact_sets",
    "collection_result_locator",
}


def test_every_public_function_taking_value_objects_is_swept(parts: dict[str, Any]) -> None:
    """Derived from the facade: a new public function with a value-object parameter and no
    sweep fails here, and so does a sweep for a function that is no longer public."""
    assert tuple(_cases(parts)) == CASE_NAMES
    assert public_functions_taking_value_objects() == SWEPT_FUNCTIONS
    assert SWEPT_FUNCTIONS | {"artifact_locator_for"} <= set(b7.__all__)


def _raising_key(exc_type: type[BaseException]) -> ReconciliationRowKey:
    """A key whose ``to_dict`` raises ``exc_type``: a stand-in for a tampered object."""

    class Raising(ReconciliationRowKey):
        def to_dict(self) -> dict[str, Any]:
            raise exc_type()

    return Raising(**row_key(REF_A).to_dict())


@pytest.mark.parametrize(
    "call",
    [
        b7.compute_canonical_fact_key_digest,
        lambda key: b7.compute_row_universe([key]),
        lambda key: b7.artifact_locator_for("smart_ads/tolerance_profile/v1", key),
    ],
    ids=["key_digest", "row_universe", "artifact_locator_for"],
)
def test_a_recursion_error_is_coded_and_a_memory_error_is_not_swallowed(
    call: Callable[[Any], object],
) -> None:
    assert run(lambda: call(_raising_key(RecursionError))) in {
        ("coded", "malformed_member"), ("coded", "malformed_argument"),
    }
    with pytest.raises(MemoryError):
        call(_raising_key(MemoryError))


WRONG_CLASS_CALLS: tuple[Callable[[dict[str, Any]], object], ...] = (
    lambda p: b7.select_fact_evidence("x", p["pair"]),  # type: ignore[arg-type]
    lambda p: b7.select_fact_evidence(p["result"], "x"),  # type: ignore[arg-type]
    lambda p: b7.resolve_fact_evidence("x", p["result"]),  # type: ignore[arg-type]
    lambda p: b7.resolve_fact_evidence(p["selector"], "x"),  # type: ignore[arg-type]
    lambda p: b7.require_same_fingerprint("x", p["fingerprint"], label="t"),  # type: ignore
    lambda p: b7.compute_canonical_fact_key_digest("x"),  # type: ignore[arg-type]
    lambda p: b7.compute_row_universe_digest(("x",)),  # type: ignore[arg-type]
    lambda p: b7.expected_pair_universe(("x",)),  # type: ignore[arg-type]
    lambda p: b7.compute_logical_fact_reconciliation_digest(("x",)),  # type: ignore[arg-type]
    lambda p: _check_native("x", canonical_query(), p),
    lambda p: _check_native(p["projection"], "x", p),
)


@pytest.mark.parametrize(
    "call",
    WRONG_CLASS_CALLS,
    ids=[
        "select(result)", "select(pair)", "resolve(selector)", "resolve(result)",
        "same_fingerprint", "key_digest", "row_universe_digest", "expected_pairs",
        "logical_digest", "native(projection)", "native(query)",
    ],
)
def test_wrong_class_arguments_stay_malformed_argument(
    parts: dict[str, Any], call: Callable[[dict[str, Any]], object]
) -> None:
    assert run(lambda: call(parts)) == ("coded", "malformed_argument")


def _always_eq_cases(
    parts: dict[str, Any], world: World, record: b7.Certification7BRecord
) -> dict[str, tuple[Any, str, Callable[[], object]]]:
    """name -> (owner, field, call): the field is one a foreign validator compares with ``!=``
    against a literal, so an always-equal object passes the wire-form round trip."""
    key, other_key = copy_of(parts["key"]), parts["other_key"]
    pair, query = copy_of(parts["pair"]), canonical_query()
    projection, side = copy_of(parts["projection"]), copy_of(parts["reconciliations"][0])
    cand, ref = results(ONE_RESOURCE, ONE_RESOURCE)
    recs = parts["reconciliations"]
    return {
        "reconcile_7b_fact_sets(query.resource_level)": (
            query, "resource_level", lambda: reconcile(cand, ref, canonical_query_contract=query)),
        "check_native_request(query.resource_level)": (
            query, "resource_level", lambda: _check_native(parts["projection"], query, parts)),
        "check_native_request(projection.attribution_omission_state)": (
            projection, "attribution_omission_state",
            lambda: _check_native(projection, canonical_query(), parts)),
        "compute_canonical_fact_key_digest": (
            key, "resource_level", lambda: b7.compute_canonical_fact_key_digest(key)),
        "compute_row_universe": (
            key, "resource_level", lambda: b7.compute_row_universe([key, other_key])),
        "compute_row_universe_digest": (
            key, "resource_level", lambda: b7.compute_row_universe_digest((key, other_key))),
        "expected_pair_universe": (
            key, "resource_level", lambda: b7.expected_pair_universe((key,))),
        "compute_pair_universe": (
            pair.canonical_fact_key, "resource_level", lambda: b7.compute_pair_universe([pair])),
        "compute_logical_fact_reconciliation_digest": (
            side.tolerance_profile_locator, "store_kind",
            lambda: b7.compute_logical_fact_reconciliation_digest((side, *recs[1:]))),
        "verify_certification_7b_record(record.bundle_outcome)": (
            record, "bundle_outcome", lambda: _verify(world, record)),
        "verify_certification_7b_record(execution.result_status)": (
            record.candidate_execution, "result_status", lambda: _verify(world, record)),
    }


ALWAYS_EQ_NAMES = (
    "reconcile_7b_fact_sets(query.resource_level)",
    "check_native_request(query.resource_level)",
    "check_native_request(projection.attribution_omission_state)",
    "compute_canonical_fact_key_digest",
    "compute_row_universe",
    "compute_row_universe_digest",
    "expected_pair_universe",
    "compute_pair_universe",
    "compute_logical_fact_reconciliation_digest",
    "verify_certification_7b_record(record.bundle_outcome)",
    "verify_certification_7b_record(execution.result_status)",
)


@pytest.mark.parametrize("name", ALWAYS_EQ_NAMES)
def test_an_always_equal_object_is_a_malformed_member_not_a_bare_error(
    parts: dict[str, Any], world: World, record: b7.Certification7BRecord, name: str
) -> None:
    """It passes ``from_dict(to_dict())`` and is no JSON value: a later canonicalization used
    to raise a plain ``ClosedValidationError`` (for the record, nothing at all)."""
    owner, field, call = _always_eq_cases(parts, world, record)[name]
    assert run(call) == ("ok", None)
    with hostile_set(owner, field, AlwaysEq()):
        assert run(call) == ("coded", "malformed_member")
    assert run(call) == ("ok", None)


def test_every_always_equal_case_is_named(
    parts: dict[str, Any], world: World, record: b7.Certification7BRecord
) -> None:
    assert tuple(_always_eq_cases(parts, world, record)) == ALWAYS_EQ_NAMES


def test_locator_primitives_never_leak_a_bare_error(parts: dict[str, Any]) -> None:
    """They only address a serialization and do not re-validate (a round trip costs several
    times the digest they wrap): one that cannot be serialized is coded, never a bare error."""
    rec = copy_of(parts["reconciliations"][0])
    result = copy_of(parts["result"])
    leaks: list[str] = []
    for root, call in (
        (rec, lambda obj: b7.artifact_locator_for("smart_ads/tolerance_profile/v1", obj)),
        (result, b7.collection_result_locator),
    ):
        for owner in list(reachable(root)):
            for field in dataclasses.fields(owner):
                for value in hostile_values(getattr(owner, field.name)):
                    with hostile_set(owner, field.name, value):
                        if run(lambda: call(root))[0] == "leak":
                            leaks.append(f"{type(owner).__name__}.{field.name}={value!r:.30}")
    assert not leaks, f"{len(leaks)} leaks: " + "; ".join(leaks[:12])


# ---------------------------------------------------------------------------
# Valid inputs are untouched; signed objects keep their integrity block
# ---------------------------------------------------------------------------


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonicalize_jcs(value)).hexdigest()


def test_valid_inputs_give_the_identical_result_and_the_world_still_verifies() -> None:
    """Golden values captured from the code before the revalidation was added."""
    world = build_world()
    result = reconcile(*results())
    assert result.bundle_outcome == "verified"
    assert result.defect_codes == ()
    assert result.logical_fact_reconciliation_digest == (
        "sha256:45e2409c575ed18226ee9f5a10e95520369b5922d0537c1c097211f2820d519e"
    )
    assert result.candidate_row_universe_digest == result.reference_row_universe_digest == (
        "sha256:51e357202d710b006372dac4a93b58f3c4cf69bc09b584c2acb979ec3b5549b6"
    )
    assert (result.candidate_row_count, result.reference_row_count) == (6, 6)
    assert _digest([r.to_dict() for r in result.fact_reconciliations]) == (
        "sha256:eb2ebf0703b0ec23112617bc89219f11c4aba9a534832c698825dca9e7b78ccc"
    )
    assert reconcile(*results()) == result
    rows = many_rows(5)
    big = reconcile(*results(rows, rows))
    assert big.logical_fact_reconciliation_digest == (
        "sha256:704ea0f17a9befb43f5a7d9f13d9aff47002dfa9cb5109543d1066304220e5a9"
    )
    assert _digest(world.record) == (
        "sha256:29d6335d33fd8aa41dcb6a95e5f16d7a66da1e9c3e61d3ee7e501a118e732f8e"
    )
    assert b7.verify_certification_7b_record(world.parsed(), **world.kwargs) is None


def _sealed(data: dict[str, Any], *, signed: bool) -> dict[str, Any]:
    out = dict(data)
    out["integrity"] = {
        "key_id": KEY_ID, "key_registry_snapshot_locator": registry_loc().to_dict()
    }
    if signed:
        out["integrity"].update(content_digest=p1_content_digest(out), signature_base64=signature())
    return out


@pytest.mark.parametrize("signed", [False, True])
def test_the_round_trip_keeps_the_integrity_block(world: World, signed: bool) -> None:
    sealed = b7.Certification7BRecord.from_dict(_sealed(world.record, signed=signed))
    assert sealed.integrity is not None and sealed.integrity.is_signed is signed
    assert run(lambda: _verify(world, sealed)) == ("ok", None)
    assert copy_of(sealed) == sealed


def test_a_signed_record_whose_preimage_or_digest_changed_is_rejected(world: World) -> None:
    sealed = b7.Certification7BRecord.from_dict(_sealed(world.record, signed=True))
    assert sealed.integrity is not None
    with hostile_set(sealed.integrity, "content_digest", sha("f")):
        assert run(lambda: _verify(world, sealed)) == ("coded", "integrity_digest_mismatch")
    # Still a well-formed record (inside the 300 s skew), but no longer the signed preimage.
    with hostile_set(sealed.candidate_execution, "retrieved_at_utc", "2026-11-11T04:15:01.000000Z"):
        assert run(lambda: _verify(world, sealed)) == ("coded", "integrity_digest_mismatch")


def test_partial_or_corrupted_p1_integrity_states_dropped_by_to_dict_are_rejected(
    world: World, parts: dict[str, Any]
) -> None:
    sealed = b7.Certification7BRecord.from_dict(_sealed(world.record, signed=True))
    assert sealed.integrity is not None
    for slot in ("signature_base64", "content_digest"):
        with hostile_set(sealed.integrity, slot, None):
            assert run(lambda: _verify(world, sealed)) == ("coded", "malformed_member")

    unsigned = b7.Certification7BRecord.from_dict(_sealed(world.record, signed=False))
    assert unsigned.integrity is not None
    for slot, bad in (
        ("content_digest", "not-valid"),
        ("content_digest", AlwaysEq()),
        ("signature_base64", 12345),
    ):
        with hostile_set(unsigned.integrity, slot, bad):
            assert run(lambda: _verify(world, unsigned)) == ("coded", "malformed_member")

    # Nested NativeRequestProjection inside CandidateExecution and ReferenceExecution.
    for side in ("candidate_execution", "reference_execution"):
        rec_data = dict(world.record)
        exec_data = dict(rec_data[side])
        signed_proj_dict = _sealed(exec_data["native_request_projection"], signed=True)
        exec_data["native_request_projection"] = signed_proj_dict
        exec_data["native_request_digest"] = b7.NativeRequestProjection.from_dict(
            signed_proj_dict
        ).native_request_digest
        rec_data[side] = exec_data
        rec_obj = b7.Certification7BRecord.from_dict(rec_data)
        exec_obj = getattr(rec_obj, side)
        proj_obj = exec_obj.native_request_projection
        assert proj_obj.integrity is not None
        with hostile_set(proj_obj.integrity, "signature_base64", None):
            downgraded_digest = proj_obj.native_request_digest
            with hostile_set(exec_obj, "native_request_digest", downgraded_digest):
                assert run(lambda: _verify(world, rec_obj)) == ("coded", "malformed_member")

    # Standalone NativeRequestProjection in check_native_request.
    signed_proj = b7.NativeRequestProjection.from_dict(_sealed(native_dict(), signed=True))
    assert signed_proj.integrity is not None
    with hostile_set(signed_proj.integrity, "signature_base64", None):
        downgraded_digest = signed_proj.native_request_digest
        assert run(
            lambda: b7.check_native_request(
                signed_proj,
                native_request_digest=downgraded_digest,
                canonical_query=canonical_query(),
                algorithm_digest=REF_ALGO,
                project_native_request=pinned_algorithm,
            )
        ) == ("coded", "malformed_member")

    # Foreign P1 objects (PipeboardPhase1Contract, AdmittedCollection, CollectionResult).
    signed_world = build_world(ONE_RESOURCE, ONE_RESOURCE, signed_p1=True)
    for arg_name in ("driver_contract", "candidate_admission", "candidate_result"):
        arg_obj = signed_world.kwargs[arg_name]
        assert arg_obj.integrity is not None
        with hostile_set(arg_obj.integrity, "signature_base64", None):
            assert run(
                lambda: _verify(signed_world, signed_world.parsed(), **{arg_name: arg_obj})
            ) == ("coded", "malformed_member")


# ---------------------------------------------------------------------------
# Nothing quadratic: round trips are per object, never per pair
# ---------------------------------------------------------------------------


def _count_calls(monkeypatch: pytest.MonkeyPatch, cls: type, count: list[int]) -> None:
    original = cls.from_dict.__func__  # type: ignore[attr-defined]

    def counting(klass: type, data: object, *args: Any, **kwargs: Any) -> Any:
        count[0] += 1
        return original(klass, data, *args, **kwargs)

    monkeypatch.setattr(cls, "from_dict", classmethod(counting))


@pytest.mark.parametrize("entry", ["reconcile", "verify"])
def test_round_trips_grow_linearly_with_the_row_count(
    monkeypatch: pytest.MonkeyPatch, entry: str
) -> None:
    counts: dict[int, list[int]] = {}
    for rows_count in (10, 20):
        rows = many_rows(rows_count)
        counter = {"fact": [0], "key": [0]}
        if entry == "reconcile":
            cand, ref = results(rows, rows)
            run_it: Callable[[], object] = lambda: reconcile(cand, ref)  # noqa: E731
        else:
            big = build_world(rows, rows)
            run_it = lambda: b7.verify_certification_7b_record(  # noqa: E731
                big.parsed(), **big.kwargs
            )
        with monkeypatch.context() as patch:
            _count_calls(patch, NormalizedCollectionFact, counter["fact"])
            _count_calls(patch, ReconciliationRowKey, counter["key"])
            run_it()
        counts[rows_count] = [counter["fact"][0], counter["key"][0]]
    for small, large in zip(counts[10], counts[20]):
        assert large <= 2.2 * small
