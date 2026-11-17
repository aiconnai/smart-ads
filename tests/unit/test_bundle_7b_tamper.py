"""Tampered frozen objects are rejected at the public entry points of the 7B bundle.

A frozen dataclass validates once, in ``__post_init__``; ``object.__setattr__`` (or
``__delattr__``) bypasses that. Every public function that consumes such an object
treats it as untrusted: a tampered object is rejected with a coded
``Bundle7BDefectError`` exactly as its wire form (``from_dict(to_dict())``) would be,
never with a bare exception and never by a silent accept.

The oracle of every sweep is that wire form, not the implementation under test.
"""
from __future__ import annotations

import contextlib
import dataclasses
import hashlib
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


# ---------------------------------------------------------------------------
# Tamper machinery
# ---------------------------------------------------------------------------


def hostile_values(value: object) -> list[object]:
    """Hostile replacements: wrong type, bool, None, empty, list-for-tuple, subclass, digest."""
    out: list[object] = [None, True, 12345, "not-valid", (), object(), MISSING]
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
        assert exc.code in b7.DEFECT_CODES
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
    root: Any, entry: Callable[[Any], object], clean: Any, valid: Outcome
) -> Outcome:
    """What the entry point must do with ``root``: what it does with its wire form.

    A wire form equal to the clean object's behaves as the valid object (``valid``);
    any other parse is run through the entry point, which then sees a clean object.
    """
    try:
        fresh = rebuild(root)
    except Bundle7BDefectError as exc:
        return ("coded", exc.code)
    except Exception:  # noqa: BLE001 - a bare error of any kind is a malformed member
        return ("coded", "malformed_member")
    return valid if fresh == clean else run(lambda: entry(fresh))


def sweep(root: Any, entry: Callable[[Any], object]) -> list[str]:
    """Tamper every field of every reachable object with every hostile value; list the misses."""
    misses: list[str] = []
    clean, valid = rebuild(root), run(lambda: entry(root))
    assert valid == ("ok", None)
    for owner in list(reachable(root)):
        for field in dataclasses.fields(owner):
            for value in hostile_values(getattr(owner, field.name)):
                with hostile_set(owner, field.name, value):
                    expected = wire_outcome(root, entry, clean, valid)
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
    assert_no_misses(sweep(root, entry))


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


def test_every_public_function_taking_value_objects_is_swept(parts: dict[str, Any]) -> None:
    assert tuple(_cases(parts)) == CASE_NAMES


WRONG_CLASS_CALLS: tuple[Callable[[dict[str, Any]], object], ...] = (
    lambda p: b7.select_fact_evidence("x", p["pair"]),  # type: ignore[arg-type]
    lambda p: b7.select_fact_evidence(p["result"], "x"),  # type: ignore[arg-type]
    lambda p: b7.resolve_fact_evidence("x", p["result"]),  # type: ignore[arg-type]
    lambda p: b7.resolve_fact_evidence(p["selector"], "x"),  # type: ignore[arg-type]
    lambda p: b7.require_same_fingerprint("x", p["fingerprint"], label="t"),  # type: ignore[arg-type]
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


def test_locator_primitives_never_leak_a_bare_error(parts: dict[str, Any]) -> None:
    """``artifact_locator_for`` and ``collection_result_locator`` only address a serialization.

    They do not re-validate (a round trip costs several times the digest they wrap); a
    tampered object that cannot be serialized comes out coded, never as a bare error.
    """
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
