"""Per-function complexity-budget checker (`complexity.function`).

Declared house-rule: enforces per-function structural budgets (`max_params`,
`max_nesting_depth`). The within-function complement to `arch.layering`. PURE -
reuses the AST `scan_profile` already parsed. See COMPLEXITY-DESIGN.md.
"""

from __future__ import annotations

import ast

from .conventions_base import _convention_finding, _path_in_scope
from .findings import Finding
from .profile import ConventionEntry


def _function_param_count(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
    """Parameter count, excluding a leading `self`/`cls` receiver."""
    a = fn.args
    count = (
        len(a.posonlyargs)
        + len(a.args)
        + len(a.kwonlyargs)
        + (1 if a.vararg else 0)
        + (1 if a.kwarg else 0)
    )
    first = a.posonlyargs or a.args
    if first and first[0].arg in ("self", "cls"):
        count -= 1
    return count


def _block_depth(stmts: list[ast.stmt]) -> int:
    """Max nesting depth contributed by a list of statements (0 if none nest)."""
    return max((_stmt_depth(s) for s in stmts), default=0)


def _stmt_depth(node: ast.stmt) -> int:
    """Depth a single statement contributes to its enclosing block.

    Compound blocks (For/AsyncFor/While/With/AsyncWith/If/Try) add 1; `elif`
    chains are flattened (each branch at the same depth as the leading `if`);
    nested function/class scopes are NOT descended (judged independently).
    """
    if isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
        return 1 + max(_block_depth(node.body), _block_depth(node.orelse))
    if isinstance(node, (ast.With, ast.AsyncWith)):
        return 1 + _block_depth(node.body)
    if isinstance(node, ast.If):
        return _if_chain_depth(node)
    if isinstance(node, ast.Try):
        blocks = [node.body, node.orelse, node.finalbody]
        blocks += [h.body for h in node.handlers]
        return 1 + max((_block_depth(b) for b in blocks), default=0)
    return 0


def _if_chain_depth(node: ast.If) -> int:
    """Depth of a flattened if/elif/else chain (elif does NOT add depth)."""
    bodies: list[list[ast.stmt]] = []
    current = node
    while True:
        bodies.append(current.body)
        orelse = current.orelse
        if len(orelse) == 1 and isinstance(orelse[0], ast.If):
            current = orelse[0]  # elif: same level as the leading if
        else:
            if orelse:
                bodies.append(orelse)  # final else
            break
    return 1 + max((_block_depth(b) for b in bodies), default=0)


def _function_nesting_depth(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
    """Max compound-block nesting depth within the function's own body."""
    return _block_depth(fn.body)


def _run_complexity(
    tree: ast.AST, path: str | None, entry: ConventionEntry
) -> list[Finding]:
    """Checker for 'complexity.function'."""
    if not _path_in_scope(path, entry.params.get("paths")):
        return []

    max_params = entry.params.get("max_params")
    max_depth = entry.params.get("max_nesting_depth")
    if max_params is None and max_depth is None:
        return []

    message = entry.params.get("message")
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        if max_params is not None:
            count = _function_param_count(node)
            if count > max_params:
                findings.append(
                    _convention_finding(
                        entry,
                        path,
                        node.lineno,
                        message
                        or f"function '{node.name}' has {count} parameters (budget {max_params})",
                        node.name,
                    )
                )

        if max_depth is not None:
            depth = _function_nesting_depth(node)
            if depth > max_depth:
                findings.append(
                    _convention_finding(
                        entry,
                        path,
                        node.lineno,
                        message
                        or f"function '{node.name}' nesting depth {depth} exceeds budget {max_depth}",
                        node.name,
                    )
                )

    return findings
