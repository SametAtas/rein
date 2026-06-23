"""Duplicate-function substrate: structural signatures over parsed functions.

The anti-slop moat as a STEERING feature - catch an agent that writes a function
duplicating one that already exists and tell it to reuse. This module is the pure
substrate: an EXACT body signature per function and an index grouping equal
signatures. The checker and the diff-scoped wiring build on it.

Pure, stdlib-only (ast). Operates on already-parsed trees - no file reads here.
"""

from __future__ import annotations

import ast

from .findings import Finding, Severity
from .resolution import _apply_pragmas, _is_aux_path


def _is_docstring(stmt: ast.stmt) -> bool:
    """True if a statement is a bare string-literal expression (a docstring)."""
    return (
        isinstance(stmt, ast.Expr)
        and isinstance(stmt.value, ast.Constant)
        and isinstance(stmt.value.value, str)
    )


def function_signature(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
    """An exact structural signature of a function body, or None when not worth it.

    Drops a leading docstring, then returns None for a trivial body (< 3 remaining
    statements) or a dunder method (`__init__`/`__eq__`/...) - boilerplate that
    legitimately repeats. Otherwise returns `ast.dump` of the remaining body
    (identifiers included, line numbers excluded), so two functions with identical
    bodies get identical signatures.
    """
    body = fn.body
    if body and _is_docstring(body[0]):
        body = body[1:]
    name = fn.name
    if len(body) < 3 or (name.startswith("__") and name.endswith("__")):
        return None
    return ast.dump(ast.Module(body=body, type_ignores=[]))


def _index_tree(label: str, tree: ast.AST, index: dict[str, list[str]]) -> None:
    """Add every non-trivial function in *tree* to *index* under its signature."""
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            sig = function_signature(node)
            if sig is not None:
                index.setdefault(sig, []).append(f"{label}:{node.name}")


def build_function_index(modules: dict[str, ast.AST]) -> dict[str, list[str]]:
    """Map each non-trivial function signature to its `label:funcname` locations.

    *modules* maps a module label (dotted name or path) to its parsed tree. Pure:
    the caller supplies the trees (no file reading here). A signature shared by
    more than one location marks a duplicate group.
    """
    index: dict[str, list[str]] = {}
    for label, tree in modules.items():
        _index_tree(label, tree, index)
    return index


def _duplicate_finding(
    fn: ast.FunctionDef | ast.AsyncFunctionDef, path: str | None, others: list[str]
) -> Finding:
    extra = f" (+{len(others) - 1} more)" if len(others) > 1 else ""
    return Finding(
        rule_id="dup.function",
        severity=Severity.MEDIUM,
        message=(
            f"function '{fn.name}' duplicates {others[0]}{extra}; "
            "import and reuse it instead"
        ),
        path=path,
        line=fn.lineno,
        snippet=fn.name,
        tags=("dup",),
    )


def check_duplicate_functions(
    tree: ast.AST,
    path: str | None,
    index: dict[str, list[str]],
    *,
    text: str | None = None,
) -> list[Finding]:
    """Flag a function whose body matches a DIFFERENT function in the index.

    A function is never a duplicate of itself (compared by `path:name` location).
    Trivial/dunder functions never signature, so they never flag. This is NOT
    diff-scoped here - 49c wires it into the diff path so only agent-ADDED
    functions are judged. Fail-open: skips auxiliary trees and honors
    `# rein:ignore` on the def line.
    """
    if _is_aux_path(path):
        return []
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        sig = function_signature(node)
        if sig is None:
            continue
        self_label = f"{path}:{node.name}"
        others = [loc for loc in index.get(sig, []) if loc != self_label]
        if others:
            findings.append(_duplicate_finding(node, path, others))
    lines = text.splitlines() if text is not None else None
    findings = _apply_pragmas(findings, lines)
    return sorted(findings, key=lambda f: f.line or 0)
