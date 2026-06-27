"""Collect every name bound anywhere in a module (the undefined-name substrate).

The complement to project import resolution: to flag an undefined NAME we first
need the set of names that ANY binding form
introduces. This module computes that set with a deliberate OVER-APPROXIMATION:
one flat walk of the whole tree, every scope merged. Over-approximating bindings
keeps the future checker FAIL-OPEN - a name bound in any scope is treated as
defined, so we never cry wolf on a name that is bound somewhere we did not model.

Pure, stdlib-only (ast + builtins) so it stays inside the zero-dependency core.
"""

from __future__ import annotations

import ast
import builtins

from .findings import Finding, Severity
from .resolution import _apply_pragmas, _is_aux_path

# ast.TypeAlias is Py3.12+; an empty tuple makes isinstance a no-op on 3.11.
_TYPE_ALIAS = getattr(ast, "TypeAlias", ())

# Module-level dunders Python injects into every module namespace.
_MODULE_DUNDERS = frozenset(
    {
        "__name__",
        "__file__",
        "__doc__",
        "__package__",
        "__spec__",
        "__loader__",
        "__builtins__",
        "__dict__",
        "__annotations__",
        "__path__",
    }
)

# Names injected into globals by IPython/Jupyter at runtime. Real code probes
# them with `try: get_ipython() except NameError`, so a static read would
# false-fire; treat them as always-defined.
_RUNTIME_INJECTED = frozenset({"get_ipython", "__IPYTHON__"})

# Names available without any binding: builtins, module dunders, __class__
# (implicitly bound inside methods that use super()), and runtime-injected globals.
ALWAYS_DEFINED: frozenset[str] = (
    frozenset(dir(builtins)) | _MODULE_DUNDERS | _RUNTIME_INJECTED | {"__class__"}
)


def _target_names(node: ast.expr) -> list[str]:
    """Name ids bound by an assignment-like target, recursing into Tuple/List/Starred.

    Attribute and Subscript targets bind no new name, so they are ignored.
    """
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, ast.Starred):
        return _target_names(node.value)
    if isinstance(node, (ast.Tuple, ast.List)):
        out: list[str] = []
        for elt in node.elts:
            out.extend(_target_names(elt))
        return out
    return []


def _arg_names(args: ast.arguments) -> list[str]:
    """Every parameter name of a function/lambda signature."""
    names = [a.arg for a in (*args.posonlyargs, *args.args, *args.kwonlyargs)]
    if args.vararg is not None:
        names.append(args.vararg.arg)
    if args.kwarg is not None:
        names.append(args.kwarg.arg)
    return names


def _type_param_names(node: ast.AST) -> list[str]:
    """PEP-695 type-parameter names (Py3.12+), guarded for older versions."""
    return [tp.name for tp in getattr(node, "type_params", ())]


def _binding_names(node: ast.AST) -> list[str]:
    """Names introduced by a single node (its own binding, not its children)."""
    if isinstance(node, (ast.Assign, ast.For, ast.AsyncFor, ast.comprehension)):
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        return [n for t in targets for n in _target_names(t)]
    if isinstance(node, (ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
        return _target_names(node.target)
    if isinstance(node, ast.withitem):
        return _target_names(node.optional_vars) if node.optional_vars else []
    if isinstance(node, ast.ExceptHandler):
        return [node.name] if node.name else []
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return [node.name, *_arg_names(node.args), *_type_param_names(node)]
    if isinstance(node, ast.ClassDef):
        return [node.name, *_type_param_names(node)]
    if isinstance(node, ast.Lambda):
        return _arg_names(node.args)
    if isinstance(node, ast.Import):
        return [a.asname or a.name.split(".")[0] for a in node.names]
    if isinstance(node, ast.ImportFrom):
        return [a.asname or a.name for a in node.names]
    if isinstance(node, (ast.Global, ast.Nonlocal)):
        return list(node.names)
    return _match_names(node)


def _match_names(node: ast.AST) -> list[str]:
    """Names captured by structural-pattern-match forms (Py3.10+)."""
    if isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
        return [node.name]
    if isinstance(node, ast.MatchMapping) and node.rest:
        return [node.rest]
    if isinstance(node, _TYPE_ALIAS):
        return [*_type_param_names(node)]
    return []


def collect_bound_names(tree: ast.AST) -> frozenset[str]:
    """Every name bound by any binding form, in any scope (over-approximation)."""
    names: set[str] = set()
    for node in ast.walk(tree):
        names.update(_binding_names(node))
    return frozenset(names)


def _has_star_import(tree: ast.AST) -> bool:
    """True if any `from x import *` appears (it can bind arbitrary names)."""
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and any(a.name == "*" for a in node.names):
            return True
    return False


def _undefined_finding(name: str, lineno: int, path: str | None) -> Finding:
    return Finding(
        rule_id="names.undefined",
        severity=Severity.MEDIUM,
        message=f"name '{name}' is not defined in this module",
        path=path,
        line=lineno,
        snippet=name,
        tags=("names",),
    )


def check_undefined_names(
    tree: ast.AST, path: str | None, *, text: str | None = None
) -> list[Finding]:
    """Flag a `Name` load bound nowhere in the module - the invented/typo symbol.

    Intra-module and over-approximating: a name bound in ANY scope (or a builtin/
    dunder) is treated as defined, so this stays FAIL-OPEN. It bails entirely on a
    `from x import *` (which can bind anything), on auxiliary trees, and honors
    `# rein:ignore`.
    """
    if _is_aux_path(path) or _has_star_import(tree):
        return []
    bound = collect_bound_names(tree) | ALWAYS_DEFINED
    findings: list[Finding] = []
    seen: set[tuple[str, int]] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Name) or not isinstance(node.ctx, ast.Load):
            continue
        if node.id in bound:
            continue
        key = (node.id, node.lineno)
        if key not in seen:
            seen.add(key)
            findings.append(_undefined_finding(node.id, node.lineno, path))
    lines = text.splitlines() if text is not None else None
    findings = _apply_pragmas(findings, lines)
    return sorted(findings, key=lambda f: f.line or 0)
