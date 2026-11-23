"""Zero-execution CPython 3.12 AST consumer feature-flag and `/ibvi-ads` routing analyzer (ADR-0001 §§3.3, 12.6)."""
from __future__ import annotations

import ast
from collections.abc import Mapping
from dataclasses import dataclass
import re
import sys
from typing import Final

from smart_ads.contracts.consumer import ConsumerFeatureFlagContract
from smart_ads.contracts.jcs import loads_strict_json
from smart_ads.contracts.scalars import ClosedValidationError, require_exact_keys
from smart_ads.ports.consumer import (
    ConsumerRoutingAnalysis,
    ConsumerRoutingAnalyzerPort,
    EntrypointRouteFacts,
)

_MAX_SOURCE_BYTES: Final[int] = 262_144
_MAX_AST_NODES: Final[int] = 10_000
_MAX_AST_DEPTH: Final[int] = 64
_IBVI_ADS_ROUTE: Final[str] = "/ibvi-ads"
_UTF8_BOM: Final[bytes] = b"\xef\xbb\xbf"
_PEP263_COOKIE_RE: Final[re.Pattern[str]] = re.compile(r"^[ \t\f]*#.*?coding[:=]")
_UPPER_SNAKE_RE: Final[re.Pattern[str]] = re.compile(r"\A[A-Z][A-Z0-9_]*\Z")
_IDENT_RE: Final[re.Pattern[str]] = re.compile(r"\A[A-Za-z_][A-Za-z0-9_]*\Z")
_FORBIDDEN_LINE_SEPS: Final[frozenset[str]] = frozenset(
    {"\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029"}
)

_CANONICAL_MCP_METHODS: Final[frozenset[str]] = frozenset({
    "smart_ads.queries.get_ad_performance_v1",
    "smart_ads.queries.get_adset_performance_v1",
    "smart_ads.queries.get_campaign_performance_v1",
    "smart_ads.queries.get_intelligence_findings_v1",
    "smart_ads.reports.generate_recurrent_summary_v1",
})
_FEATURE_FLAG_JSON_KEYS: Final[frozenset[str]] = frozenset(
    {"flag_key", "default_enabled", "disabled_legacy_route", "enabled_smart_ads_route"}
)
_ALLOWED_TYPING_IMPORTS: Final[frozenset[str]] = frozenset(
    {"Any", "Callable", "Final", "Mapping", "Optional", "Protocol", "Sequence", "TypeAlias"}
)
_ALLOWED_FLAG_KEY_NAMES: Final[frozenset[str]] = frozenset(
    {"flag_key", "smart_ads_flag_key", "consumer_flag_key", "ibvi_ads_flag_key"}
)
_ALLOWED_DEFAULT_ENABLED_NAMES: Final[frozenset[str]] = frozenset({
    "default_enabled", "smart_ads_default_enabled", "consumer_default_enabled",
    "ibvi_ads_default_enabled", "smart_ads_read_enabled", "ibvi_ads_smart_ads_enabled",
})
_ALLOWED_DISABLED_ROUTE_NAMES: Final[frozenset[str]] = frozenset({
    "disabled_legacy_route", "legacy_route",
    "consumer_disabled_legacy_route", "ibvi_ads_disabled_legacy_route",
})
_ALLOWED_ENABLED_ROUTE_NAMES: Final[frozenset[str]] = frozenset(
    {"enabled_smart_ads_route", "smart_ads_route", "delegated_route", "ibvi_ads_route"}
)
_ALLOWED_FLAG_DICT_NAMES: Final[frozenset[str]] = frozenset(
    {"feature_flags", "flags", "flag_defaults", "feature_flag_defaults", "feature_flag_config"}
)


@dataclass(frozen=True, slots=True)
class _ParsedEntrypoint:
    symbol_name: str
    fn: ast.FunctionDef | ast.AsyncFunctionDef
    is_method: bool
    allowed_self_attrs: frozenset[str]
    forbidden_self_attrs: frozenset[str]


@dataclass(frozen=True, slots=True)
class _EpScope:
    ep: _ParsedEntrypoint
    all_params: frozenset[str]
    non_default_params: frozenset[str]
    constants: Mapping[str, tuple[str, int]]
    reserved_names: frozenset[str]
    role_usage: dict[str, set[str]]
    literal_usage: dict[int, str]
    expected_flag_key: str


def _has_dunder_affix(name: str) -> bool:
    return name.startswith("__") or name.endswith("__")


def _verify_cpython_312_runtime() -> None:
    if sys.implementation.name != "cpython" or tuple(sys.version_info[:2]) != (3, 12):
        raise ClosedValidationError("routing_analyzer: requires CPython 3.12 runtime")


def _decode_verified_source_bytes(buf: object, *, label: str) -> str:
    if type(buf) is not bytes:
        raise ClosedValidationError(f"{label}: expected bytes")
    if not (1 <= len(buf) <= _MAX_SOURCE_BYTES):
        raise ClosedValidationError(f"{label}: byte length must be within [1, {_MAX_SOURCE_BYTES}]")
    if buf.startswith(_UTF8_BOM) or b"\x00" in buf:
        raise ClosedValidationError(f"{label}: UTF-8 BOM and NUL bytes are forbidden")
    try:
        text = buf.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ClosedValidationError(f"{label}: invalid UTF-8 bytes") from exc
    if any(ch in _FORBIDDEN_LINE_SEPS for ch in text):
        raise ClosedValidationError(f"{label}: non-standard line/control separator is forbidden")
    raw_head = [raw_line.decode("utf-8") for raw_line in buf.splitlines()[:2]]
    for line in [*raw_head, *text.splitlines()]:
        if _PEP263_COOKIE_RE.match(line) is not None:
            raise ClosedValidationError(f"{label}: PEP 263 encoding cookie is forbidden")
    return text


def _parse_bounded_python_ast(raw_bytes: bytes, text: str, *, label: str) -> ast.Module:
    try:
        tree = ast.parse(raw_bytes)
        text_tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError) as exc:
        raise ClosedValidationError(f"{label}: failed to parse Python AST") from exc
    if ast.dump(tree) != ast.dump(text_tree):
        raise ClosedValidationError(f"{label}: bytes vs str AST lexer differential")
    stack: list[tuple[ast.AST, int]] = [(tree, 0)]
    node_count = 0
    while stack:
        current, depth = stack.pop()
        node_count += 1
        if node_count > _MAX_AST_NODES or depth > _MAX_AST_DEPTH:
            raise ClosedValidationError(f"{label}: AST exceeds node or depth ceiling")
        for child in ast.iter_child_nodes(current):
            stack.append((child, depth + 1))
    return tree


def _is_docstring_stmt(stmt: ast.stmt) -> bool:
    return isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant) and type(stmt.value.value) is str


def _strip_leading_docstring(body: list[ast.stmt]) -> list[ast.stmt]:
    return body[1:] if body and _is_docstring_stmt(body[0]) else list(body)


def _is_closed_type_annotation(node: ast.expr) -> bool:
    stack: list[ast.AST] = [node]
    while stack:
        cur = stack.pop()
        if isinstance(cur, ast.Name) or (isinstance(cur, ast.Constant) and (cur.value is None or type(cur.value) is str)):
            continue
        if isinstance(cur, ast.Subscript):
            stack.extend((cur.value, cur.slice))
        elif isinstance(cur, ast.Tuple):
            stack.extend(cur.elts)
        elif isinstance(cur, ast.BinOp) and isinstance(cur.op, ast.BitOr):
            stack.extend((cur.left, cur.right))
        else:
            return False
    return True


def _extract_simple_name_assign(stmt: ast.stmt, *, label: str) -> tuple[str, ast.expr]:
    if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
        return stmt.targets[0].id, stmt.value
    if (
        isinstance(stmt, ast.AnnAssign)
        and isinstance(stmt.target, ast.Name)
        and stmt.simple == 1
        and stmt.value is not None
        and _is_closed_type_annotation(stmt.annotation)
    ):
        return stmt.target.id, stmt.value
    raise ClosedValidationError(f"{label}: unallowlisted statement or assignment target")


def _validate_flag_json(text: str, contract: ConsumerFeatureFlagContract) -> None:
    m = require_exact_keys(loads_strict_json(text), _FEATURE_FLAG_JSON_KEYS, label="feature_flag_json")
    if type(m["flag_key"]) is not str or m["flag_key"] != contract.flag_key:
        raise ClosedValidationError("feature_flag_json.flag_key: mismatch against contract")
    if type(m["default_enabled"]) is not bool or m["default_enabled"] is not False:
        raise ClosedValidationError("feature_flag_json.default_enabled: must be literal False")
    if type(m["disabled_legacy_route"]) is not str or m["disabled_legacy_route"] != contract.disabled_legacy_route:
        raise ClosedValidationError("feature_flag_json.disabled_legacy_route: mismatch")
    if type(m["enabled_smart_ads_route"]) is not str or m["enabled_smart_ads_route"] != _IBVI_ADS_ROUTE:
        raise ClosedValidationError("feature_flag_json.enabled_smart_ads_route: must be '/ibvi-ads'")


def _record_unique_flag_role(state: dict[str, object], role: str, value: object) -> None:
    if role in state and state[role] != value:
        raise ClosedValidationError(f"feature_flag_py: conflicting {role} bindings")
    state[role] = value


def _classify_flag_scalar(
    name: str, val: str | bool, state: dict[str, object], contract: ConsumerFeatureFlagContract
) -> None:
    norm = name.lower()
    if norm in _ALLOWED_FLAG_KEY_NAMES:
        if type(val) is not str or val != contract.flag_key or "scalar_flag_key" in state:
            raise ClosedValidationError("feature_flag_py: invalid or duplicate flag_key constant")
        state["scalar_flag_key"] = True
        _record_unique_flag_role(state, "flag_key", val)
    elif norm in _ALLOWED_DEFAULT_ENABLED_NAMES:
        if type(val) is not bool or val is not False or "scalar_enabled" in state:
            raise ClosedValidationError("feature_flag_py: default_enabled must be literal bool False")
        state["scalar_enabled"] = True
        _record_unique_flag_role(state, "default_enabled", False)
    elif norm in _ALLOWED_DISABLED_ROUTE_NAMES:
        if type(val) is not str or val != contract.disabled_legacy_route or "scalar_legacy" in state:
            raise ClosedValidationError("feature_flag_py: invalid disabled_legacy_route constant")
        state["scalar_legacy"] = True
    elif norm in _ALLOWED_ENABLED_ROUTE_NAMES:
        if type(val) is not str or val != _IBVI_ADS_ROUTE or "scalar_ibvi" in state:
            raise ClosedValidationError("feature_flag_py: invalid enabled_smart_ads_route constant")
        state["scalar_ibvi"] = True
    else:
        raise ClosedValidationError(f"feature_flag_py: unallowlisted constant {name!r}")


def _classify_flag_dict(
    name: str, node: ast.Dict, state: dict[str, object], contract: ConsumerFeatureFlagContract
) -> None:
    if name.lower() not in _ALLOWED_FLAG_DICT_NAMES or "dict_seen" in state:
        raise ClosedValidationError(f"feature_flag_py: unallowlisted or duplicate dict {name!r}")
    state["dict_seen"] = True
    entries: dict[str, str | bool] = {}
    for k_node, v_node in zip(node.keys, node.values, strict=True):
        if not isinstance(k_node, ast.Constant) or type(k_node.value) is not str or not k_node.value:
            raise ClosedValidationError("feature_flag_py: dict keys must be non-empty str literals")
        if k_node.value in entries or not isinstance(v_node, ast.Constant) or type(v_node.value) not in (str, bool):
            raise ClosedValidationError("feature_flag_py: duplicate dict key or non-literal value")
        if type(v_node.value) is bool and v_node.value is not False:
            raise ClosedValidationError("feature_flag_py: True flag value is forbidden")
        entries[k_node.value] = v_node.value
    if set(entries) == {contract.flag_key} and type(entries[contract.flag_key]) is bool:
        _record_unique_flag_role(state, "flag_key", contract.flag_key)
        _record_unique_flag_role(state, "default_enabled", False)
        return
    if not entries or not set(entries).issubset(_FEATURE_FLAG_JSON_KEYS) or not {"flag_key", "default_enabled"}.issubset(entries):
        raise ClosedValidationError("feature_flag_py: closed dict must match flag_key or config schema")
    for key, val in entries.items():
        _classify_flag_scalar(key, val, state, contract)


def _analyze_feature_flag_py(raw_bytes: bytes, text: str, contract: ConsumerFeatureFlagContract) -> None:
    tree = _parse_bounded_python_ast(raw_bytes, text, label="feature_flag_bytes")
    assigned: set[str] = set()
    state: dict[str, object] = {}
    for stmt in _strip_leading_docstring(tree.body):
        if isinstance(stmt, ast.ImportFrom) and stmt.level == 0 and stmt.module in {"__future__", "typing"}:
            allowed_sym = "annotations" if stmt.module == "__future__" else "Final"
            if stmt.names and all(a.name == allowed_sym and a.asname is None for a in stmt.names):
                continue
            raise ClosedValidationError("feature_flag_py: unallowlisted from-import")
        name, rhs = _extract_simple_name_assign(stmt, label="feature_flag_py")
        if _UPPER_SNAKE_RE.fullmatch(name) is None or name in assigned or name in {"Final", "annotations"}:
            raise ClosedValidationError(f"feature_flag_py: invalid, duplicate, or shadowed name {name!r}")
        assigned.add(name)
        if isinstance(rhs, ast.Constant) and type(rhs.value) in (str, bool):
            if type(rhs.value) is bool and rhs.value is not False:
                raise ClosedValidationError("feature_flag_py: True literal is forbidden")
            _classify_flag_scalar(name, rhs.value, state, contract)
        elif isinstance(rhs, ast.Dict):
            _classify_flag_dict(name, rhs, state, contract)
        else:
            raise ClosedValidationError("feature_flag_py: non-constant RHS is forbidden")
    if state.get("flag_key") != contract.flag_key or state.get("default_enabled") is not False:
        raise ClosedValidationError("feature_flag_py: missing unambiguous flag_key/False binding")


def _analyze_feature_flag_bytes(feature_flag_bytes: bytes, contract: ConsumerFeatureFlagContract) -> None:
    text = _decode_verified_source_bytes(feature_flag_bytes, label="feature_flag_bytes")
    stripped = text.lstrip()
    if not stripped:
        raise ClosedValidationError("feature_flag_bytes: empty or whitespace-only content")
    if stripped.startswith("{"):
        _validate_flag_json(text, contract)
    else:
        _analyze_feature_flag_py(feature_flag_bytes, text, contract)


def _validate_adapter_import(stmt: ast.stmt, reserved_names: set[str]) -> None:
    if not isinstance(stmt, ast.ImportFrom) or stmt.level != 0 or not stmt.names:
        raise ClosedValidationError("adapter_bytes: unallowlisted import statement")
    if stmt.module == "__future__":
        if any(a.name != "annotations" or a.asname is not None for a in stmt.names):
            raise ClosedValidationError("adapter_bytes: only 'from __future__ import annotations' allowed")
        reserved_names.add("annotations")
        return
    if stmt.module != "typing":
        raise ClosedValidationError(f"adapter_bytes: forbidden module import {stmt.module!r}")
    for alias in stmt.names:
        if alias.name not in _ALLOWED_TYPING_IMPORTS or alias.asname is not None or alias.name in reserved_names:
            raise ClosedValidationError(f"adapter_bytes: invalid or duplicate typing import {alias.name!r}")
        reserved_names.add(alias.name)


def _extract_module_str_const(
    stmt: ast.stmt, constants: dict[str, tuple[str, int]], reserved_names: set[str], contract: ConsumerFeatureFlagContract
) -> None:
    name, rhs = _extract_simple_name_assign(stmt, label="adapter_bytes")
    if _UPPER_SNAKE_RE.fullmatch(name) is None or name in reserved_names:
        raise ClosedValidationError(f"adapter_bytes: invalid or duplicate module constant {name!r}")
    if not isinstance(rhs, ast.Constant) or type(rhs.value) is not str:
        raise ClosedValidationError(f"adapter_bytes: module constant {name!r} must be str literal")
    val = rhs.value
    if val.startswith("smart_ads.") and val not in _CANONICAL_MCP_METHODS and val != contract.flag_key:
        raise ClosedValidationError(f"adapter_bytes: forbidden smart_ads constant {val!r}")
    reserved_names.add(name)
    constants[name] = (val, id(rhs))


def _check_safe_default(node: ast.expr | None, fn_name: str) -> None:
    if node is None or not isinstance(node, ast.Constant) or type(node.value) not in (str, int, type(None)):
        raise ClosedValidationError(f"adapter_bytes: forbidden default value on {fn_name!r}")


def _extract_fn_params(
    fn: ast.FunctionDef | ast.AsyncFunctionDef, *, is_method: bool, forbidden_names: frozenset[str] = frozenset()
) -> tuple[tuple[str, ...], frozenset[str]]:
    args = fn.args
    if fn.decorator_list or fn.type_params or args.posonlyargs or args.vararg is not None or args.kwarg is not None:
        raise ClosedValidationError(f"adapter_bytes: forbidden signature modifiers on {fn.name!r}")
    if fn.returns is not None and not _is_closed_type_annotation(fn.returns):
        raise ClosedValidationError(f"adapter_bytes: invalid return annotation on {fn.name!r}")
    pos_args = list(args.args)
    if is_method:
        if not pos_args or pos_args[0].arg != "self" or len(args.defaults) >= len(pos_args):
            raise ClosedValidationError(f"adapter_bytes: method {fn.name!r} must start with non-defaulted self")
        pos_args = pos_args[1:]
    for a_node in [*pos_args, *args.kwonlyargs]:
        if a_node.annotation is not None and not _is_closed_type_annotation(a_node.annotation):
            raise ClosedValidationError(f"adapter_bytes: invalid parameter annotation on {fn.name!r}")
    defaulted: set[str] = set()
    for a_node, d_val in zip(pos_args[len(pos_args) - len(args.defaults) :], args.defaults, strict=True):
        _check_safe_default(d_val, fn.name)
        defaulted.add(a_node.arg)
    for kw_node, kw_def in zip(args.kwonlyargs, args.kw_defaults, strict=True):
        if kw_def is not None:
            _check_safe_default(kw_def, fn.name)
            defaulted.add(kw_node.arg)
    names = tuple(a.arg for a in [*pos_args, *args.kwonlyargs])
    if len(set(names)) != len(names) or any(n == "self" or _has_dunder_affix(n) or n in forbidden_names for n in names):
        raise ClosedValidationError(f"adapter_bytes: duplicate, dunder, or shadowing parameter on {fn.name!r}")
    return names, frozenset(defaulted)


def _validate_class_init(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> frozenset[str]:
    if not isinstance(fn, ast.FunctionDef):
        raise ClosedValidationError("adapter_bytes: __init__ must be synchronous")
    params, defaulted = _extract_fn_params(fn, is_method=True)
    stmts = _strip_leading_docstring(fn.body)
    if defaulted or not stmts:
        raise ClosedValidationError("adapter_bytes: invalid __init__ defaults or empty body")
    if len(stmts) == 1 and isinstance(stmts[0], ast.Pass):
        return frozenset()
    param_set = frozenset(params)
    bound_attrs: set[str] = set()
    used_params: set[str] = set()
    for stmt in stmts:
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
            tgt, val = stmt.targets[0], stmt.value
        elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None and _is_closed_type_annotation(stmt.annotation):
            tgt, val = stmt.target, stmt.value
        else:
            raise ClosedValidationError("adapter_bytes: non-trivial statement in __init__")
        if (
            not isinstance(tgt, ast.Attribute) or not isinstance(tgt.value, ast.Name) or tgt.value.id != "self"
            or _has_dunder_affix(tgt.attr) or tgt.attr in bound_attrs
            or not isinstance(val, ast.Name) or val.id not in param_set or val.id in used_params
        ):
            raise ClosedValidationError("adapter_bytes: __init__ must bind distinct non-dunder self.<attr> = <param>")
        bound_attrs.add(tgt.attr)
        used_params.add(val.id)
    return frozenset(bound_attrs)


def _validate_private_helper(fn: ast.FunctionDef | ast.AsyncFunctionDef, *, is_method: bool) -> None:
    if _has_dunder_affix(fn.name):
        raise ClosedValidationError(f"adapter_bytes: dunder hook {fn.name!r} is forbidden")
    params, _ = _extract_fn_params(fn, is_method=is_method)
    stmts = _strip_leading_docstring(fn.body)
    if len(stmts) != 1 or not isinstance(stmts[0], ast.Return) or stmts[0].value is None:
        raise ClosedValidationError(f"adapter_bytes: non-trivial private helper {fn.name!r} forbidden")
    ret_val = stmts[0].value
    if isinstance(ret_val, ast.Name) and ret_val.id in params:
        return
    if isinstance(ret_val, ast.Constant) and type(ret_val.value) in (str, int, bool, type(None)):
        if type(ret_val.value) is str and ("smart_ads" in ret_val.value or ret_val.value.startswith(_IBVI_ADS_ROUTE)):
            raise ClosedValidationError(f"adapter_bytes: forbidden route/method in {fn.name!r}")
        return
    raise ClosedValidationError(f"adapter_bytes: forbidden expression in private helper {fn.name!r}")


def _verify_no_param_shadowing(tree: ast.Module, reserved_names: frozenset[str]) -> None:
    for stmt in _strip_leading_docstring(tree.body):
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _extract_fn_params(stmt, is_method=False, forbidden_names=reserved_names)
        elif isinstance(stmt, ast.ClassDef):
            cls_methods = frozenset(
                m.name for m in _strip_leading_docstring(stmt.body) if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))
            )
            forbidden = reserved_names | cls_methods
            for m_node in _strip_leading_docstring(stmt.body):
                if isinstance(m_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    _extract_fn_params(m_node, is_method=True, forbidden_names=forbidden)


def _resolve_str_expr(expr: ast.expr, scope: _EpScope, role: str) -> str:
    if isinstance(expr, ast.Constant) and type(expr.value) is str:
        scope.literal_usage[id(expr)] = role
        return expr.value
    if isinstance(expr, ast.Name) and expr.id not in scope.all_params and expr.id in scope.constants:
        scope.role_usage.setdefault(expr.id, set()).add(role)
        return scope.constants[expr.id][0]
    raise ClosedValidationError(f"adapter_bytes: expected string literal or UPPER_SNAKE constant for {role}")


def _extract_collaborator_key(expr: ast.expr, scope: _EpScope) -> str:
    if isinstance(expr, ast.Name) and expr.id in scope.non_default_params:
        return f"param:{expr.id}"
    if (
        scope.ep.is_method and isinstance(expr, ast.Attribute)
        and isinstance(expr.value, ast.Name) and expr.value.id == "self"
        and not _has_dunder_affix(expr.attr)
        and expr.attr in scope.ep.allowed_self_attrs
        and expr.attr not in scope.ep.forbidden_self_attrs
    ):
        return f"self:{expr.attr}"
    raise ClosedValidationError("adapter_bytes: unallowlisted collaborator receiver")


def _parse_flag_call(expr: ast.expr, scope: _EpScope) -> str:
    if (
        not isinstance(expr, ast.Call) or expr.keywords or len(expr.args) != 1
        or not isinstance(expr.func, ast.Attribute) or expr.func.attr != "is_enabled"
    ):
        raise ClosedValidationError("adapter_bytes: expected exact <flags>.is_enabled(<flag_key>) call")
    flags_collab = _extract_collaborator_key(expr.func.value, scope)
    resolved_key = _resolve_str_expr(expr.args[0], scope, "flag_key")
    if resolved_key != scope.expected_flag_key:
        raise ClosedValidationError(f"adapter_bytes: flag_key {resolved_key!r} != {scope.expected_flag_key!r}")
    return flags_collab


def _unwrap_cond_subject(cond: ast.expr) -> ast.expr:
    if (
        isinstance(cond, ast.Compare) and len(cond.ops) == 1 and isinstance(cond.ops[0], ast.Is)
        and len(cond.comparators) == 1 and isinstance(cond.comparators[0], ast.Constant)
        and type(cond.comparators[0].value) is bool and cond.comparators[0].value is True
    ):
        return cond.left
    return cond


def _parse_bound_flag_stmt(stmt: ast.stmt, scope: _EpScope) -> tuple[str, str]:
    if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
        var_name, rhs = stmt.targets[0].id, stmt.value
    elif (
        isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name) and stmt.simple == 1
        and stmt.value is not None and isinstance(stmt.annotation, ast.Name) and stmt.annotation.id == "bool"
    ):
        var_name, rhs = stmt.target.id, stmt.value
    else:
        raise ClosedValidationError("adapter_bytes: statement before routing branch must bind flag")
    if var_name in scope.all_params or var_name in scope.reserved_names or var_name == "self":
        raise ClosedValidationError(f"adapter_bytes: flag local {var_name!r} shadows outer symbol")
    return var_name, _parse_flag_call(rhs, scope)


def _split_entrypoint_routing(stmts: list[ast.stmt], scope: _EpScope) -> tuple[str, ast.expr, ast.expr]:
    if not stmts or len(stmts) > 2:
        raise ClosedValidationError("adapter_bytes: entrypoint must have closed 1- or 2-stmt body")
    bound_pair = _parse_bound_flag_stmt(stmts[0], scope) if len(stmts) == 2 else None
    term = stmts[-1]
    if isinstance(term, ast.If):
        if (
            len(term.body) != 1 or len(term.orelse) != 1
            or not isinstance(term.body[0], ast.Return) or not isinstance(term.orelse[0], ast.Return)
            or term.body[0].value is None or term.orelse[0].value is None
        ):
            raise ClosedValidationError("adapter_bytes: if/else must have exhaustive single-return branches")
        cond, t_expr, f_expr = term.test, term.body[0].value, term.orelse[0].value
    elif isinstance(term, ast.Return) and isinstance(term.value, ast.IfExp):
        cond, t_expr, f_expr = term.value.test, term.value.body, term.value.orelse
    else:
        raise ClosedValidationError("adapter_bytes: terminal statement must be closed binary if/else")
    subj = _unwrap_cond_subject(cond)
    if bound_pair is not None:
        if not isinstance(subj, ast.Name) or subj.id != bound_pair[0]:
            raise ClosedValidationError("adapter_bytes: condition must test the bound flag variable")
        return bound_pair[1], t_expr, f_expr
    return _parse_flag_call(subj, scope), t_expr, f_expr


def _unwrap_branch_call(
    expr: ast.expr, scope: _EpScope, *, is_async: bool, flags_collab: str
) -> tuple[str, list[ast.expr]]:
    inner = expr.value if is_async and isinstance(expr, ast.Await) else expr
    if isinstance(inner, ast.Await) or not isinstance(inner, ast.Call) or inner.keywords:
        raise ClosedValidationError("adapter_bytes: branch must return positional dispatch call")
    func = inner.func
    collab: str | None = None
    if (
        isinstance(func, ast.Attribute) and _IDENT_RE.fullmatch(func.attr) is not None
        and not func.attr.startswith("_") and not _has_dunder_affix(func.attr) and func.attr != "is_enabled"
    ):
        try:
            collab = _extract_collaborator_key(func.value, scope)
        except ClosedValidationError:
            collab = None
    if collab is None:
        collab = _extract_collaborator_key(func, scope)
    if collab == flags_collab:
        raise ClosedValidationError("adapter_bytes: flags collaborator cannot dispatch")
    return collab, list(inner.args)


def _validate_payload_expr(expr: ast.expr, *, value_params: frozenset[str], scope: _EpScope) -> None:
    if isinstance(expr, ast.Name) and expr.id in value_params:
        return
    if not isinstance(expr, ast.Dict):
        raise ClosedValidationError("adapter_bytes: payload must be parameter name or closed dict")
    seen_keys: set[str] = set()
    for k_node, v_node in zip(expr.keys, expr.values, strict=True):
        if not isinstance(k_node, ast.Constant) or type(k_node.value) is not str:
            raise ClosedValidationError("adapter_bytes: payload dict keys must be str literals")
        key_str = k_node.value
        if key_str in seen_keys or "smart_ads" in key_str or key_str.startswith(_IBVI_ADS_ROUTE):
            raise ClosedValidationError(f"adapter_bytes: invalid or duplicate payload key {key_str!r}")
        seen_keys.add(key_str)
        if isinstance(v_node, ast.Name) and v_node.id in value_params:
            continue
        if isinstance(v_node, ast.Name) and v_node.id not in scope.all_params and v_node.id in scope.constants:
            c_val = scope.constants[v_node.id][0]
            if "smart_ads" in c_val or c_val.startswith(_IBVI_ADS_ROUTE):
                raise ClosedValidationError("adapter_bytes: forbidden constant in payload dict")
            scope.role_usage.setdefault(v_node.id, set()).add("payload")
        elif isinstance(v_node, ast.Constant) and type(v_node.value) in (str, int, bool, type(None)):
            if type(v_node.value) is str and ("smart_ads" in v_node.value or v_node.value.startswith(_IBVI_ADS_ROUTE)):
                raise ClosedValidationError("adapter_bytes: forbidden route/method literal in payload")
        else:
            raise ClosedValidationError("adapter_bytes: unallowlisted value expression in payload dict")


def _verify_entrypoint_fn(
    ep: _ParsedEntrypoint,
    *,
    expected_mcp_method: str,
    contract: ConsumerFeatureFlagContract,
    constants: Mapping[str, tuple[str, int]],
    reserved_names: frozenset[str],
    role_usage: dict[str, set[str]],
    literal_usage: dict[int, str],
) -> EntrypointRouteFacts:
    params, defaulted = _extract_fn_params(
        ep.fn, is_method=ep.is_method, forbidden_names=reserved_names | ep.forbidden_self_attrs
    )
    all_params = frozenset(params)
    scope = _EpScope(
        ep, all_params, all_params - defaulted, constants, reserved_names,
        role_usage, literal_usage, contract.flag_key,
    )
    flags_collab, t_expr, f_expr = _split_entrypoint_routing(_strip_leading_docstring(ep.fn.body), scope)
    is_async = isinstance(ep.fn, ast.AsyncFunctionDef)
    t_collab, t_args = _unwrap_branch_call(t_expr, scope, is_async=is_async, flags_collab=flags_collab)
    f_collab, f_args = _unwrap_branch_call(f_expr, scope, is_async=is_async, flags_collab=flags_collab)
    if len(t_args) != 3 or len(f_args) != 2:
        raise ClosedValidationError(f"adapter_bytes: invalid dispatch arity in {ep.symbol_name!r}")
    t_route = _resolve_str_expr(t_args[0], scope, "true_route")
    t_method = _resolve_str_expr(t_args[1], scope, "true_method")
    f_route = _resolve_str_expr(f_args[0], scope, "false_route")
    if t_route != _IBVI_ADS_ROUTE or t_method != expected_mcp_method or f_route != contract.disabled_legacy_route:
        raise ClosedValidationError(f"adapter_bytes: route/method mismatch in {ep.symbol_name!r}")
    val_params = all_params - {c.removeprefix("param:") for c in (flags_collab, t_collab, f_collab) if c.startswith("param:")}
    _validate_payload_expr(t_args[2], value_params=val_params, scope=scope)
    _validate_payload_expr(f_args[1], value_params=val_params, scope=scope)
    return EntrypointRouteFacts(ep.symbol_name, contract.flag_key, t_route, t_method, f_route)


def _collect_class_entrypoints(cls_node: ast.ClassDef, out: list[_ParsedEntrypoint]) -> None:
    if (
        cls_node.name.startswith("_") or _has_dunder_affix(cls_node.name)
        or cls_node.bases or cls_node.keywords or cls_node.decorator_list or cls_node.type_params
    ):
        raise ClosedValidationError(f"adapter_bytes: invalid class definition {cls_node.name!r}")
    stmts = _strip_leading_docstring(cls_node.body)
    if not stmts:
        raise ClosedValidationError(f"adapter_bytes: empty class {cls_node.name!r}")
    method_nodes: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
    method_names: set[str] = set()
    init_attrs: frozenset[str] = frozenset()
    for member in stmts:
        if not isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)) or member.name in method_names:
            raise ClosedValidationError(f"adapter_bytes: invalid or duplicate member in {cls_node.name!r}")
        method_names.add(member.name)
        if member.name == "__init__":
            init_attrs = _validate_class_init(member)
        elif _has_dunder_affix(member.name):
            raise ClosedValidationError(f"adapter_bytes: forbidden dunder method {member.name!r}")
        elif member.name.startswith("_"):
            _validate_private_helper(member, is_method=True)
        else:
            method_nodes.append(member)
    forbidden = frozenset(method_names)
    for m_node in method_nodes:
        out.append(_ParsedEntrypoint(f"{cls_node.name}.{m_node.name}", m_node, True, init_attrs, forbidden))


def _collect_adapter_module(
    tree: ast.Module, contract: ConsumerFeatureFlagContract
) -> tuple[dict[str, tuple[str, int]], frozenset[str], list[_ParsedEntrypoint]]:
    constants: dict[str, tuple[str, int]] = {}
    reserved: set[str] = set()
    entrypoints: list[_ParsedEntrypoint] = []
    for stmt in _strip_leading_docstring(tree.body):
        if isinstance(stmt, (ast.Import, ast.ImportFrom)):
            _validate_adapter_import(stmt, reserved)
        elif isinstance(stmt, (ast.Assign, ast.AnnAssign)):
            _extract_module_str_const(stmt, constants, reserved, contract)
        elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if stmt.name in reserved or _has_dunder_affix(stmt.name):
                raise ClosedValidationError(f"adapter_bytes: duplicate or dunder top-level symbol {stmt.name!r}")
            reserved.add(stmt.name)
            if stmt.name.startswith("_"):
                _validate_private_helper(stmt, is_method=False)
            else:
                entrypoints.append(_ParsedEntrypoint(stmt.name, stmt, False, frozenset(), frozenset()))
        elif isinstance(stmt, ast.ClassDef):
            if stmt.name in reserved:
                raise ClosedValidationError(f"adapter_bytes: duplicate top-level class {stmt.name!r}")
            reserved.add(stmt.name)
            _collect_class_entrypoints(stmt, entrypoints)
        else:
            raise ClosedValidationError("adapter_bytes: unallowlisted top-level statement")
    frozen_reserved = frozenset(reserved)
    _verify_no_param_shadowing(tree, frozen_reserved)
    return constants, frozen_reserved, entrypoints


def _verify_global_string_literals(
    tree: ast.Module,
    *,
    contract: ConsumerFeatureFlagContract,
    constants: Mapping[str, tuple[str, int]],
    role_usage: Mapping[str, set[str]],
    literal_usage: Mapping[int, str],
) -> None:
    const_id_to_name = {node_id: name for name, (_, node_id) in constants.items()}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant) or type(node.value) is not str:
            continue
        val, nid = node.value, id(node)
        cname = const_id_to_name.get(nid)
        c_roles = role_usage.get(cname, set()) if cname is not None else set()
        if val.startswith(_IBVI_ADS_ROUTE):
            if val != _IBVI_ADS_ROUTE or (literal_usage.get(nid) != "true_route" and c_roles != {"true_route"}):
                raise ClosedValidationError(f"adapter_bytes: unverified '/ibvi-ads' literal {val!r}")
        if "smart_ads" in val:
            ok_flag = val == contract.flag_key and (literal_usage.get(nid) == "flag_key" or c_roles == {"flag_key"})
            ok_mcp = val in _CANONICAL_MCP_METHODS and (literal_usage.get(nid) == "true_method" or c_roles == {"true_method"})
            if not (ok_flag or ok_mcp):
                raise ClosedValidationError(f"adapter_bytes: unverified smart_ads literal {val!r}")


@dataclass(frozen=True, slots=True)
class Cpython312AstConsumerRoutingAnalyzer(ConsumerRoutingAnalyzerPort):
    """Deterministic zero-execution CPython 3.12 AST consumer routing verifier."""

    def analyze_consumer_routing(
        self,
        *,
        adapter_bytes: bytes,
        feature_flag_bytes: bytes,
        contract: ConsumerFeatureFlagContract,
    ) -> ConsumerRoutingAnalysis:
        """Verify feature-flag defaults and exhaustive 2-way `/ibvi-ads` delegation routing."""
        _verify_cpython_312_runtime()
        if type(contract) is not ConsumerFeatureFlagContract:
            raise ClosedValidationError("contract: expected ConsumerFeatureFlagContract")
        verified = ConsumerFeatureFlagContract.from_dict(contract.to_dict())
        _analyze_feature_flag_bytes(feature_flag_bytes, verified)
        adapter_text = _decode_verified_source_bytes(adapter_bytes, label="adapter_bytes")
        tree = _parse_bounded_python_ast(adapter_bytes, adapter_text, label="adapter_bytes")
        constants, reserved, entrypoints = _collect_adapter_module(tree, verified)
        expected_map = {ep.symbol_name: ep.mcp_method for ep in verified.read_entrypoints}
        discovered = tuple(sorted((ep.symbol_name for ep in entrypoints), key=lambda s: s.encode("utf-8")))
        if len(set(discovered)) != len(discovered) or set(discovered) != set(expected_map):
            raise ClosedValidationError("adapter_bytes: public entrypoint set mismatch against contract")
        role_usage: dict[str, set[str]] = {}
        literal_usage: dict[int, str] = {}
        facts = tuple(
            _verify_entrypoint_fn(
                ep, expected_mcp_method=expected_map[ep.symbol_name], contract=verified,
                constants=constants, reserved_names=reserved, role_usage=role_usage, literal_usage=literal_usage,
            )
            for ep in sorted(entrypoints, key=lambda e: e.symbol_name.encode("utf-8"))
        )
        _verify_global_string_literals(
            tree, contract=verified, constants=constants, role_usage=role_usage, literal_usage=literal_usage
        )
        return ConsumerRoutingAnalysis(
            verified.flag_key, False, verified.disabled_legacy_route, _IBVI_ADS_ROUTE, discovered, facts
        )


__all__ = ["Cpython312AstConsumerRoutingAnalyzer"]
