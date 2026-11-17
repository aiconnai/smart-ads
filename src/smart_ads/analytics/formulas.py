"""Derived metric definitions, exact integer operators, and the acyclic formula bundle (ADR-0001 section 5.6)."""
from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
import enum
import functools
import re
from types import MappingProxyType
from typing import Any, ClassVar, Final, Literal, TypeVar

from smart_ads.contracts.jcs import (
    P1Integrity,
    p1_content_digest,
    self_digest_jcs_sha256,
)
from smart_ads.contracts.numerics import (
    MAX_INT64,
    PHASE1_BASE_METRICS,
    BaseMetricDefinition,
    NumericStateRow,
    ValueType,
    validate_numeric_state,
)
from smart_ads.contracts.scalars import (
    ClosedValidationError,
    require_exact_keys,
    require_mapping,
    validate_currency_iso4217,
    validate_sha256_prefixed,
)
from smart_ads.contracts.schemas import validate_source_metric_ref

T = TypeVar("T")

FormulaOperator = Literal[
    "DIVIDE_MONEY_BY_COUNT",
    "DIVIDE_COUNT_BY_COUNT",
    "DIVIDE_MONEY_BY_MONEY",
]
CertificationInputOrigin = Literal["phase1_7b_base", "derived_input"]

ROUND_HALF_UP: Final[str] = "ROUND_HALF_UP"
RATIO_SCALE: Final[int] = 6
_RATIO_FACTOR: Final[int] = 10**RATIO_SCALE

FORMULA_ERROR_CODES: Final[frozenset[str]] = frozenset(
    {
        # grammar, operands and operator signatures
        "malformed", "invalid_operand", "operand_out_of_range", "currency_mismatch",
        "invalid_operator", "output_type_mismatch", "invalid_rounding_mode", "same_operand",
        "input_metrics_mismatch", "formula_digest_mismatch",
        # bundle graph and envelope
        "self_reference", "cycle", "unknown_dependency", "unknown_base_metric",
        "duplicate_output", "unsorted", "operand_type_mismatch", "topological_order_mismatch",
        "bundle_digest_mismatch", "content_digest_mismatch",
        # derived certification
        "invalid_certification_status", "unprofiled_input_origin", "degraded_from_phase1_7b",
        "empty_certification_inputs",
    }
)

# operator -> (numerator value_type, denominator value_type, output value_type)
_MONEY: Final = "int64_minor_currency"
_COUNT: Final = "int64_count"
_RATIO: Final = "decimal_ratio"
OPERATOR_SIGNATURES: Final[Mapping[str, tuple[ValueType, ValueType, ValueType]]] = (
    MappingProxyType(
        {
            "DIVIDE_MONEY_BY_COUNT": (_MONEY, _COUNT, _MONEY),
            "DIVIDE_COUNT_BY_COUNT": (_COUNT, _COUNT, _RATIO),
            "DIVIDE_MONEY_BY_MONEY": (_MONEY, _MONEY, _RATIO),
        }
    )
)

# Same grammar as BaseMetricDefinition.metric_semantic_ref in contracts/numerics.py.
_METRIC_SEMANTIC_REF_RE: Final[re.Pattern[str]] = re.compile(
    r"\Ametric:[a-z][a-z0-9_]*_v[1-9][0-9]*\Z"
)
_AST_KEYS: Final[frozenset[str]] = frozenset(
    {"operator", "numerator_metric_ref", "denominator_metric_ref", "output_value_type", "rounding_mode"}
)
_DEFINITION_KEYS: Final[frozenset[str]] = frozenset(
    {"$schema", "metric_semantic_ref", "input_metrics", "formula_ast", "formula_digest"}
)
_BUNDLE_CORE_KEYS: Final[frozenset[str]] = frozenset(
    {"$schema", "base_metric_refs", "definitions", "topological_order", "bundle_digest"}
)
_CERTIFICATION_ORIGINS: Final[frozenset[str]] = frozenset({"phase1_7b_base", "derived_input"})


class FormulaGraphError(ClosedValidationError):
    """Typed rejection for derived formulas, the formula bundle graph, and certification inputs."""

    def __init__(self, code: str, message: str) -> None:
        if not isinstance(code, str) or code not in FORMULA_ERROR_CODES:
            raise ClosedValidationError(
                f"FormulaGraphError: code {code!r} is outside the closed code set"
            )
        super().__init__(f"{code}: {message}")
        self.code = code


def _guard(code: str, fn: Callable[..., T], *args: Any, **kwargs: Any) -> T:
    """Run a shared validator, re-raising its plain `ClosedValidationError` with `code`."""
    try:
        return fn(*args, **kwargs)
    except FormulaGraphError:
        raise
    except ClosedValidationError as exc:
        raise FormulaGraphError(code, str(exc)) from exc


def _utf8_key(value: str) -> bytes:
    return value.encode("utf-8")


def _validate_metric_ref(value: object, *, field_name: str) -> str:
    if not isinstance(value, str) or not _METRIC_SEMANTIC_REF_RE.fullmatch(value):
        raise FormulaGraphError(
            "malformed", f"{field_name}: expected 'metric:<name>_v<n>', got {value!r}"
        )
    return value


# --------------------------------------------------------------------------- operators


def _require_operand(value: object, *, field_name: str) -> int:
    if type(value) is not int:
        raise FormulaGraphError(
            "invalid_operand",
            f"{field_name}: expected strict int, got {type(value).__name__}",
        )
    if not 0 <= value <= MAX_INT64:
        raise FormulaGraphError(
            "operand_out_of_range", f"{field_name}: {value} outside 0..{MAX_INT64}"
        )
    return value


def _division_by_zero_row() -> NumericStateRow:
    return validate_numeric_state(
        metric_origin="derived_formula",
        presence_status="not_applicable",
        calculation_status="division_by_zero",
        unknown_reason="division_by_zero",
        value_type=None,
        raw_numeric_value=None,
        unit=None,
        currency=None,
    )


def _computed_row(
    value_type: ValueType, raw: str, unit: str, currency: str | None
) -> NumericStateRow:
    return validate_numeric_state(
        metric_origin="derived_formula",
        presence_status="not_applicable",
        calculation_status="computed",
        unknown_reason=None,
        value_type=value_type,
        raw_numeric_value=raw,
        unit=unit,
        currency=currency,
        query_currency=currency if currency is not None else "BRL",
    )


def _half_up_ratio6(numerator: int, denominator: int) -> str:
    scaled = (numerator * _RATIO_FACTOR * 2 + denominator) // (2 * denominator)
    whole, fraction = divmod(scaled, _RATIO_FACTOR)
    return f"{whole}.{fraction:0{RATIO_SCALE}d}"


def divide_money_by_count(
    numerator_minor: int, denominator_count: int, *, currency: str
) -> NumericStateRow:
    """`DIVIDE_MONEY_BY_COUNT`: minor currency / count -> minor currency, exact ROUND_HALF_UP."""
    num = _require_operand(numerator_minor, field_name="numerator_minor")
    den = _require_operand(denominator_count, field_name="denominator_count")
    checked_currency = _guard(
        "malformed", validate_currency_iso4217, currency, field_name="currency"
    )
    if den == 0:
        return _division_by_zero_row()
    quotient = (num * 2 + den) // (2 * den)
    return _computed_row(
        "int64_minor_currency", str(quotient), "minor_currency", checked_currency
    )


def divide_count_by_count(numerator_count: int, denominator_count: int) -> NumericStateRow:
    """`DIVIDE_COUNT_BY_COUNT`: count / count -> six-place decimal ratio, exact ROUND_HALF_UP."""
    num = _require_operand(numerator_count, field_name="numerator_count")
    den = _require_operand(denominator_count, field_name="denominator_count")
    if den == 0:
        return _division_by_zero_row()
    return _computed_row("decimal_ratio", _half_up_ratio6(num, den), "ratio", None)


def divide_money_by_money(
    numerator_minor: int,
    denominator_minor: int,
    *,
    numerator_currency: str,
    denominator_currency: str,
) -> NumericStateRow:
    """`DIVIDE_MONEY_BY_MONEY`: same-currency money / money -> six-place ratio, ROUND_HALF_UP."""
    num = _require_operand(numerator_minor, field_name="numerator_minor")
    den = _require_operand(denominator_minor, field_name="denominator_minor")
    num_ccy = _guard(
        "malformed",
        validate_currency_iso4217,
        numerator_currency,
        field_name="numerator_currency",
    )
    den_ccy = _guard(
        "malformed",
        validate_currency_iso4217,
        denominator_currency,
        field_name="denominator_currency",
    )
    if num_ccy != den_ccy:
        raise FormulaGraphError(
            "currency_mismatch",
            f"DIVIDE_MONEY_BY_MONEY requires one currency, got {num_ccy!r} / {den_ccy!r}",
        )
    if den == 0:
        return _division_by_zero_row()
    return _computed_row("decimal_ratio", _half_up_ratio6(num, den), "ratio", None)


# --------------------------------------------------------------------------- definition


@dataclass(frozen=True, slots=True)
class FormulaAst:
    """Closed five-member `formula_ast` of `derived_metric_definition/v1`."""

    operator: FormulaOperator
    numerator_metric_ref: str
    denominator_metric_ref: str
    output_value_type: ValueType
    rounding_mode: str

    def __post_init__(self) -> None:
        if not isinstance(self.operator, str) or self.operator not in OPERATOR_SIGNATURES:
            raise FormulaGraphError(
                "invalid_operator", f"formula_ast.operator: {self.operator!r}"
            )
        _validate_metric_ref(
            self.numerator_metric_ref, field_name="formula_ast.numerator_metric_ref"
        )
        _validate_metric_ref(
            self.denominator_metric_ref, field_name="formula_ast.denominator_metric_ref"
        )
        if self.numerator_metric_ref == self.denominator_metric_ref:
            raise FormulaGraphError(
                "same_operand",
                "formula_ast: numerator_metric_ref must differ from denominator_metric_ref",
            )
        expected_output = OPERATOR_SIGNATURES[self.operator][2]
        if self.output_value_type != expected_output:
            raise FormulaGraphError(
                "output_type_mismatch",
                f"formula_ast.output_value_type: {self.operator} requires "
                f"{expected_output!r}, got {self.output_value_type!r}",
            )
        if self.rounding_mode != ROUND_HALF_UP:
            raise FormulaGraphError(
                "invalid_rounding_mode",
                f"formula_ast.rounding_mode: expected {ROUND_HALF_UP!r}, got {self.rounding_mode!r}",
            )

    @property
    def metric_refs(self) -> tuple[str, ...]:
        """Canonical UTF-8-sorted metric references used by the AST."""
        return tuple(
            sorted(
                (self.numerator_metric_ref, self.denominator_metric_ref), key=_utf8_key
            )
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "operator": self.operator,
            "numerator_metric_ref": self.numerator_metric_ref,
            "denominator_metric_ref": self.denominator_metric_ref,
            "output_value_type": self.output_value_type,
            "rounding_mode": self.rounding_mode,
        }

    @classmethod
    def from_dict(cls, data: object) -> FormulaAst:
        mapping = _guard("malformed", require_exact_keys, data, _AST_KEYS, label="formula_ast")
        return cls(
            operator=mapping["operator"],
            numerator_metric_ref=mapping["numerator_metric_ref"],
            denominator_metric_ref=mapping["denominator_metric_ref"],
            output_value_type=mapping["output_value_type"],
            rounding_mode=mapping["rounding_mode"],
        )


@dataclass(frozen=True, slots=True)
class DerivedMetricDefinition:
    """Closed embedded `smart_ads/derived_metric_definition/v1` (ADR-0001 section 5.6)."""

    SCHEMA: ClassVar[str] = "smart_ads/derived_metric_definition/v1"

    metric_semantic_ref: str
    formula_ast: FormulaAst
    input_metrics: tuple[str, ...] | None = None
    formula_digest: str = ""

    def __post_init__(self) -> None:
        _validate_metric_ref(
            self.metric_semantic_ref,
            field_name="derived_metric_definition.metric_semantic_ref",
        )
        if not isinstance(self.formula_ast, FormulaAst):
            raise FormulaGraphError(
                "malformed", "derived_metric_definition.formula_ast: expected FormulaAst"
            )
        if self.metric_semantic_ref in self.formula_ast.metric_refs:
            raise FormulaGraphError(
                "self_reference",
                f"{self.metric_semantic_ref!r} depends directly on itself",
            )
        object.__setattr__(self, "input_metrics", self._checked_input_metrics())
        object.__setattr__(self, "formula_digest", self._checked_formula_digest())

    def _checked_input_metrics(self) -> tuple[str, ...]:
        expected = self.formula_ast.metric_refs
        if self.input_metrics is None:
            return expected
        if not isinstance(self.input_metrics, (list, tuple)):
            raise FormulaGraphError(
                "malformed", "derived_metric_definition.input_metrics: expected list or tuple"
            )
        for item in self.input_metrics:
            _validate_metric_ref(item, field_name="derived_metric_definition.input_metrics")
        if tuple(self.input_metrics) != expected:
            raise FormulaGraphError(
                "input_metrics_mismatch",
                f"derived_metric_definition.input_metrics: expected {list(expected)!r}, "
                f"got {list(self.input_metrics)!r}",
            )
        return expected

    def _checked_formula_digest(self) -> str:
        expected = self_digest_jcs_sha256(
            self._preimage(), digest_member="formula_digest", strip_integrity=False
        )
        if self.formula_digest == "":
            return expected
        _guard(
            "malformed",
            validate_sha256_prefixed,
            self.formula_digest,
            field_name="derived_metric_definition.formula_digest",
        )
        if self.formula_digest != expected:
            raise FormulaGraphError(
                "formula_digest_mismatch",
                f"recomputed {expected!r} != asserted {self.formula_digest!r}",
            )
        return expected

    def _preimage(self) -> dict[str, Any]:
        return {
            "$schema": self.SCHEMA,
            "metric_semantic_ref": self.metric_semantic_ref,
            "input_metrics": list(self.input_metrics),
            "formula_ast": self.formula_ast.to_dict(),
        }

    @property
    def source_metric_ref(self) -> str:
        """Tagged derived-row `source_metric_ref`: `'source-metric:formula:' || formula_digest`."""
        return _guard(
            "malformed",
            validate_source_metric_ref,
            "source-metric:formula:" + self.formula_digest,
        )

    def to_dict(self) -> dict[str, Any]:
        out = self._preimage()
        out["formula_digest"] = self.formula_digest
        return out

    @classmethod
    def from_dict(cls, data: object) -> DerivedMetricDefinition:
        label = "derived_metric_definition"
        mapping = _guard("malformed", require_exact_keys, data, _DEFINITION_KEYS, label=label)
        if mapping["$schema"] != cls.SCHEMA:
            raise FormulaGraphError(
                "malformed", f"{label}.$schema: expected {cls.SCHEMA!r}, got {mapping['$schema']!r}"
            )
        if not isinstance(mapping["input_metrics"], list):
            raise FormulaGraphError("malformed", f"{label}.input_metrics: expected JSON array")
        digest = _guard(
            "malformed",
            validate_sha256_prefixed,
            mapping["formula_digest"],
            field_name=f"{label}.formula_digest",
        )
        return cls(
            metric_semantic_ref=mapping["metric_semantic_ref"],
            formula_ast=FormulaAst.from_dict(mapping["formula_ast"]),
            input_metrics=tuple(mapping["input_metrics"]),
            formula_digest=digest,
        )


# --------------------------------------------------------------------------- graph


def _check_definition_outputs(
    base_refs: tuple[str, ...], definitions: tuple[DerivedMetricDefinition, ...]
) -> None:
    seen: set[str] = set()
    for ref in base_refs + tuple(d.metric_semantic_ref for d in definitions):
        if ref in seen:
            raise FormulaGraphError("duplicate_output", f"metric {ref!r} is defined twice")
        seen.add(ref)
    for defn in definitions:
        for dep in defn.input_metrics:
            if dep not in seen:
                raise FormulaGraphError(
                    "unknown_dependency",
                    f"{defn.metric_semantic_ref!r} depends on {dep!r}, outside the bundle "
                    "and base metric registry",
                )


def _require_typed_tuple(values: object, item_type: type, *, field_name: str) -> tuple[Any, ...]:
    if isinstance(values, (str, bytes, Mapping)) or not isinstance(values, Iterable):
        raise FormulaGraphError("malformed", f"{field_name}: expected an iterable collection")
    items = tuple(values)
    for item in items:
        if not isinstance(item, item_type):
            raise FormulaGraphError(
                "malformed", f"{field_name}: expected {item_type.__name__} items"
            )
    return items


def compute_topological_order(
    base_metric_refs: Iterable[str],
    definitions: Iterable[DerivedMetricDefinition],
) -> tuple[str, ...]:
    """Unique Kahn order over base + derived nodes; ready-node tie-break by raw UTF-8 bytes."""
    defs = _require_typed_tuple(definitions, DerivedMetricDefinition, field_name="definitions")
    bases = _require_typed_tuple(base_metric_refs, str, field_name="base_metric_refs")
    for ref in bases:
        _validate_metric_ref(ref, field_name="base_metric_refs")
    _check_definition_outputs(bases, defs)

    indegree = {ref: 0 for ref in bases}
    dependents: dict[str, list[str]] = {ref: [] for ref in bases}
    for defn in defs:
        indegree[defn.metric_semantic_ref] = len(defn.input_metrics)
        dependents.setdefault(defn.metric_semantic_ref, [])
    for defn in defs:
        for dep in defn.input_metrics:
            dependents[dep].append(defn.metric_semantic_ref)

    ready = [ref for ref, count in indegree.items() if count == 0]
    order: list[str] = []
    while ready:
        node = min(ready, key=_utf8_key)
        ready.remove(node)
        order.append(node)
        for child in dependents[node]:
            indegree[child] -= 1
            if indegree[child] == 0:
                ready.append(child)
    if len(order) != len(indegree):
        emitted = frozenset(order)
        stuck = sorted((ref for ref in indegree if ref not in emitted), key=_utf8_key)
        raise FormulaGraphError("cycle", f"dependency cycle through {stuck!r}")
    return tuple(order)


def _check_operand_signatures(
    bases: tuple[BaseMetricDefinition, ...],
    definitions: tuple[DerivedMetricDefinition, ...],
) -> None:
    value_types: dict[str, str] = {b.metric_semantic_ref: b.value_type for b in bases}
    for defn in definitions:
        value_types[defn.metric_semantic_ref] = defn.formula_ast.output_value_type
    for defn in definitions:
        ast = defn.formula_ast
        num_type, den_type, _ = OPERATOR_SIGNATURES[ast.operator]
        actual = (value_types[ast.numerator_metric_ref], value_types[ast.denominator_metric_ref])
        if actual != (num_type, den_type):
            raise FormulaGraphError(
                "operand_type_mismatch",
                f"{defn.metric_semantic_ref!r}: {ast.operator} requires operands "
                f"({num_type!r}, {den_type!r}), got {actual!r}",
            )


# --------------------------------------------------------------------------- bundle


@dataclass(frozen=True, slots=True)
class FormulaBundle:
    """P1 `smart_ads/formula_bundle/v1`: acyclic graph over base + derived metric definitions."""

    SCHEMA: ClassVar[str] = "smart_ads/formula_bundle/v1"

    base_metrics: tuple[BaseMetricDefinition, ...]
    definitions: tuple[DerivedMetricDefinition, ...]
    topological_order: tuple[str, ...] | None = None
    bundle_digest: str = ""
    integrity: P1Integrity | None = None
    # Not serialized: the base metric registry the bundle is validated against.
    base_metric_registry: Mapping[str, BaseMetricDefinition] = field(
        default_factory=lambda: PHASE1_BASE_METRICS, compare=False, repr=False
    )

    def __post_init__(self) -> None:
        if self.integrity is not None and not isinstance(self.integrity, P1Integrity):
            raise FormulaGraphError("malformed", "formula_bundle.integrity: expected P1Integrity")
        registry = _checked_registry(self.base_metric_registry)
        object.__setattr__(self, "base_metric_registry", registry)
        bases = _require_typed_tuple(
            self.base_metrics, BaseMetricDefinition, field_name="formula_bundle.base_metrics"
        )
        defs = _require_typed_tuple(
            self.definitions, DerivedMetricDefinition, field_name="formula_bundle.definitions"
        )
        if not bases or not defs:
            raise FormulaGraphError(
                "malformed", "formula_bundle: base_metrics and definitions must be non-empty"
            )
        _check_against_registry(bases, defs, registry)
        order = compute_topological_order((b.metric_semantic_ref for b in bases), defs)
        _check_operand_signatures(bases, defs)
        object.__setattr__(
            self, "base_metrics", tuple(sorted(bases, key=lambda b: _utf8_key(b.metric_semantic_ref)))
        )
        object.__setattr__(
            self, "definitions", tuple(sorted(defs, key=lambda d: _utf8_key(d.metric_semantic_ref)))
        )
        object.__setattr__(self, "topological_order", self._checked_order(order))
        object.__setattr__(self, "bundle_digest", self._checked_bundle_digest())
        self._check_integrity()

    def _checked_order(self, recomputed: tuple[str, ...]) -> tuple[str, ...]:
        if self.topological_order is None:
            return recomputed
        declared = self.topological_order
        if not isinstance(declared, (list, tuple)) or tuple(declared) != recomputed:
            raise FormulaGraphError(
                "topological_order_mismatch",
                f"asserted {declared!r} != recomputed {list(recomputed)!r}",
            )
        return recomputed

    def _checked_bundle_digest(self) -> str:
        expected = self_digest_jcs_sha256(
            self.to_dict(), digest_member="bundle_digest", strip_integrity=True
        )
        if self.bundle_digest == "":
            return expected
        _guard(
            "malformed",
            validate_sha256_prefixed,
            self.bundle_digest,
            field_name="formula_bundle.bundle_digest",
        )
        if self.bundle_digest != expected:
            raise FormulaGraphError(
                "bundle_digest_mismatch",
                f"recomputed {expected!r} != asserted {self.bundle_digest!r}",
            )
        return expected

    def _check_integrity(self) -> None:
        if self.integrity is not None and self.integrity.is_signed:
            expected = p1_content_digest(self.to_dict())
            if self.integrity.content_digest != expected:
                raise FormulaGraphError(
                    "content_digest_mismatch",
                    f"recomputed {expected!r} != asserted {self.integrity.content_digest!r}",
                )

    @property
    def source_metric_refs(self) -> Mapping[str, str]:
        """Formula digest mapping: derived `metric_semantic_ref` -> tagged `source_metric_ref`."""
        return MappingProxyType(
            {d.metric_semantic_ref: d.source_metric_ref for d in self.definitions}
        )

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "$schema": self.SCHEMA,
            "base_metric_refs": [b.metric_semantic_ref for b in self.base_metrics],
            "definitions": [d.to_dict() for d in self.definitions],
            "topological_order": list(self.topological_order or ()),
            "bundle_digest": self.bundle_digest,
        }
        if self.integrity is not None:
            out["integrity"] = self.integrity.to_dict()
        return out

    @classmethod
    def from_dict(
        cls,
        data: object,
        *,
        base_metric_registry: Mapping[str, BaseMetricDefinition] = PHASE1_BASE_METRICS,
        require_signed: bool = False,
    ) -> FormulaBundle:
        """Validate a closed bundle; base refs resolve only through `base_metric_registry`."""
        if not isinstance(require_signed, bool):
            raise FormulaGraphError("malformed", "require_signed: expected bool")
        mapping = _guard("malformed", require_mapping, data, label="formula_bundle")
        integrity = _parse_bundle_integrity(mapping, require_signed=require_signed)
        if mapping["$schema"] != cls.SCHEMA:
            raise FormulaGraphError(
                "malformed", f"formula_bundle.$schema: expected {cls.SCHEMA!r}"
            )
        for member in ("base_metric_refs", "definitions", "topological_order"):
            if not isinstance(mapping[member], list):
                raise FormulaGraphError("malformed", f"formula_bundle.{member}: expected JSON array")
        registry = _checked_registry(base_metric_registry)
        bases = _resolve_base_refs(mapping["base_metric_refs"], registry)
        defs = tuple(DerivedMetricDefinition.from_dict(item) for item in mapping["definitions"])
        _require_canonical_order(
            [d.metric_semantic_ref for d in defs], field_name="formula_bundle.definitions"
        )
        digest = _guard(
            "malformed",
            validate_sha256_prefixed,
            mapping["bundle_digest"],
            field_name="formula_bundle.bundle_digest",
        )
        return cls(
            base_metrics=bases,
            definitions=defs,
            topological_order=tuple(mapping["topological_order"]),
            bundle_digest=digest,
            integrity=integrity,
            base_metric_registry=registry,
        )


def _parse_bundle_integrity(
    mapping: Mapping[str, Any], *, require_signed: bool
) -> P1Integrity | None:
    if require_signed or "integrity" in mapping:
        _guard(
            "malformed",
            require_exact_keys,
            mapping,
            _BUNDLE_CORE_KEYS | {"integrity"},
            label="formula_bundle",
        )
        return _guard(
            "malformed", P1Integrity.from_dict, mapping["integrity"], require_signed=require_signed
        )
    _guard("malformed", require_exact_keys, mapping, _BUNDLE_CORE_KEYS, label="formula_bundle")
    return None


def _require_canonical_order(refs: list[str], *, field_name: str) -> None:
    if len(set(refs)) != len(refs):
        raise FormulaGraphError("duplicate_output", f"{field_name}: duplicate metric ref")
    if refs != sorted(refs, key=_utf8_key):
        raise FormulaGraphError(
            "unsorted", f"{field_name}: must be sorted by raw UTF-8 metric_semantic_ref"
        )


def _checked_registry(registry: object) -> Mapping[str, BaseMetricDefinition]:
    """Validate a base metric registry (each key equals its entry's ref) and freeze a copy."""
    if not isinstance(registry, Mapping):
        raise FormulaGraphError("malformed", "base_metric_registry: expected Mapping")
    for key, defn in registry.items():
        if not isinstance(defn, BaseMetricDefinition) or key != defn.metric_semantic_ref:
            raise FormulaGraphError(
                "malformed", f"base_metric_registry: key {key!r} does not match its definition"
            )
    return MappingProxyType(dict(registry))


def _check_against_registry(
    bases: tuple[BaseMetricDefinition, ...],
    definitions: tuple[DerivedMetricDefinition, ...],
    registry: Mapping[str, BaseMetricDefinition],
) -> None:
    """Listed bases must be the registered definitions; no derived output may reuse a registry ref."""
    for base in bases:
        registered = registry.get(base.metric_semantic_ref)
        if registered is None or registered.metric_definition_digest != base.metric_definition_digest:
            raise FormulaGraphError(
                "unknown_base_metric", f"{base.metric_semantic_ref!r} is not the registered base metric"
            )
    for defn in definitions:
        if defn.metric_semantic_ref in registry:
            raise FormulaGraphError(
                "duplicate_output",
                f"derived {defn.metric_semantic_ref!r} shadows a registry base metric",
            )


def _resolve_base_refs(
    raw_refs: list[object], registry: Mapping[str, BaseMetricDefinition]
) -> tuple[BaseMetricDefinition, ...]:
    refs = [_validate_metric_ref(r, field_name="formula_bundle.base_metric_refs") for r in raw_refs]
    _require_canonical_order(refs, field_name="formula_bundle.base_metric_refs")
    for ref in refs:
        if ref not in registry:
            raise FormulaGraphError("unknown_base_metric", f"{ref!r} is not in the registry")
    return tuple(registry[ref] for ref in refs)


# --------------------------------------------------------------------------- certification


@functools.total_ordering
class DerivedCertificationStatus(enum.Enum):
    """Closed enum, totally ordered `BLOCKED < UNRECONCILED < UNAVAILABLE < DEGRADED < VERIFIED`."""

    BLOCKED = "BLOCKED"
    UNRECONCILED = "UNRECONCILED"
    UNAVAILABLE = "UNAVAILABLE"
    DEGRADED = "DEGRADED"
    VERIFIED = "VERIFIED"

    @property
    def rank(self) -> int:
        return tuple(DerivedCertificationStatus).index(self)

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, DerivedCertificationStatus):
            return NotImplemented
        return self.rank < other.rank

    @classmethod
    def from_wire(cls, value: object) -> DerivedCertificationStatus:
        if not isinstance(value, str) or value not in cls.__members__:
            raise FormulaGraphError(
                "invalid_certification_status", f"unknown status {value!r}"
            )
        return cls[value]


@dataclass(frozen=True, slots=True)
class CertificationInput:
    """One input's certification status and its closed origin profile."""

    status: DerivedCertificationStatus
    origin: CertificationInputOrigin

    def __post_init__(self) -> None:
        if not isinstance(self.status, DerivedCertificationStatus):
            raise FormulaGraphError(
                "invalid_certification_status",
                f"expected DerivedCertificationStatus, got {type(self.status).__name__}",
            )
        if not isinstance(self.origin, str) or self.origin not in _CERTIFICATION_ORIGINS:
            raise FormulaGraphError(
                "unprofiled_input_origin", f"unprofiled origin {self.origin!r}"
            )
        if (
            self.origin == "phase1_7b_base"
            and self.status is DerivedCertificationStatus.DEGRADED
        ):
            raise FormulaGraphError(
                "degraded_from_phase1_7b", "Phase-1 7B never originates DEGRADED"
            )


def combine_derived_certification(
    inputs: Iterable[CertificationInput],
) -> DerivedCertificationStatus:
    """Derived certification inherits the worst (minimum) input status."""
    checked = _require_typed_tuple(inputs, CertificationInput, field_name="inputs")
    if not checked:
        raise FormulaGraphError("empty_certification_inputs", "at least one input is required")
    return min(item.status for item in checked)


__all__ = [
    "FORMULA_ERROR_CODES", "OPERATOR_SIGNATURES", "RATIO_SCALE", "ROUND_HALF_UP",
    "CertificationInput", "CertificationInputOrigin", "DerivedCertificationStatus",
    "DerivedMetricDefinition", "FormulaAst", "FormulaBundle", "FormulaGraphError",
    "FormulaOperator", "combine_derived_certification", "compute_topological_order",
    "divide_count_by_count", "divide_money_by_count", "divide_money_by_money",
]
