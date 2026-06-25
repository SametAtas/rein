"""Project-aware reference resolution: flag imports that do not resolve.

With a ProjectModel of the stdlib, the project's declared dependencies, and its
own modules, rein can prove an import target does not exist - the
hallucinated/unresolved import that no single-file linter catches and that an LLM
reviewer only guesses at. Deterministic, no LLM, no network, no importing the
target's modules.

Precision first: the checker only judges
MODULE-TOP-LEVEL, UNCONDITIONAL imports - the direct children of the module body.
Function-level, try/except, `if TYPE_CHECKING:`, and other guarded imports are
nested, so iterating `tree.body` skips them for free: those are exactly the
optional/conditional patterns where a "does not resolve" verdict is untrustworthy.
The checker is also FAIL-OPEN: it says nothing without project context (model is
None), skips auxiliary trees (docs/examples/scripts/tests), exempts always-present
specials, and honors `# rein:ignore` lines.
"""

from __future__ import annotations

import ast

from .conventions_layering import _relative_base
from .findings import Finding, Severity
from .paths import path_parts
from .pragmas import filter_by_pragma
from .project import ProjectModel

_RULE_ID = "imports.unresolved"
# Module names that are always importable and must never flag.
_ALWAYS_AVAILABLE = frozenset({"__future__", "__main__", "__mp_main__"})
# Path components whose subtrees are not the shipped package; skip them entirely.
_AUX_DIRS = frozenset({"docs", "examples", "scripts", "benchmarks", "tests", "test"})


def _unresolved(target: str, lineno: int, path: str | None) -> Finding:
    return Finding(
        rule_id=_RULE_ID,
        severity=Severity.MEDIUM,
        message=(
            f"import '{target}' does not resolve to the stdlib, a declared "
            "dependency, or a project module"
        ),
        path=path,
        line=lineno,
        snippet=target,
        tags=("imports",),
    )


def _is_aux_path(path: str | None) -> bool:
    """True if any path component is an auxiliary (non-shipped) directory."""
    if path is None:
        return False
    return any(part in _AUX_DIRS for part in path_parts(path))


def _check_import(node: ast.Import, model: ProjectModel, path: str | None) -> list[Finding]:
    out: list[Finding] = []
    for alias in node.names:
        top = alias.name.split(".")[0]
        if top in _ALWAYS_AVAILABLE:
            continue
        if not model.resolves(top):
            out.append(_unresolved(alias.name, node.lineno, path))
    return out


def _suffix_in(segs: list[str], project_modules: frozenset[str]) -> bool:
    """True if any trailing slice of segs is a project module.

    The file-path resolution keeps leading source-root segments (e.g. `src`);
    project modules are stored relative to the source root, so a suffix match
    reconciles both src- and flat-layout without false positives.
    """
    return any(".".join(segs[i:]) in project_modules for i in range(len(segs)))


def _check_relative(node: ast.ImportFrom, model: ProjectModel, path: str | None) -> list[Finding]:
    if path is None:
        return []
    base = _relative_base(path, node.level)
    if base is None:
        return []
    modules = model.project_modules
    if node.module:
        # `from .mod import x`: the module must be a project module (recall path).
        segs = base + node.module.split(".")
        if not _suffix_in(segs, modules):
            return [_unresolved(".".join(segs), node.lineno, path)]
        return []
    # `from . import a, b` / `from .. import __version__`: the imported names may
    # be submodules OR __init__ bindings (variables/functions), indistinguishable
    # without importing. Precision-first: check only that the base package
    # resolves; if it does, pass. Flag only when the base itself is unresolved.
    if base and not _suffix_in(base, modules):
        return [_unresolved(".".join(base), node.lineno, path)]
    return []


def _check_import_from(node: ast.ImportFrom, model: ProjectModel, path: str | None) -> list[Finding]:
    if node.level and node.level >= 1:
        return _check_relative(node, model, path)
    module = node.module
    if module is None or module in _ALWAYS_AVAILABLE:
        return []
    top = module.split(".")[0]
    if model.resolves(module) or model.resolves(top):
        return []
    return [_unresolved(module, node.lineno, path)]


def _apply_pragmas(findings: list[Finding], lines: list[str] | None) -> list[Finding]:
    if lines is None:
        return findings
    kept: list[Finding] = []
    for f in findings:
        if f.line is not None and f.line <= len(lines):
            kept.extend(filter_by_pragma([f], lines[f.line - 1]))
        else:
            kept.append(f)
    return kept


def check_unresolved_imports(
    tree: ast.AST,
    path: str | None,
    model: ProjectModel | None,
    *,
    text: str | None = None,
) -> list[Finding]:
    """Flag module-top-level imports whose target does not resolve.

    Only the direct `import`/`from` children of the module body are judged, so
    function-level, try/except, and `if TYPE_CHECKING:` imports are skipped by
    construction. Inert (returns []) without project context or in an auxiliary
    tree. `text`, when supplied, lets the checker honor `# rein:ignore` pragmas on
    the import line, the same way the other line checks do.
    """
    if model is None or _is_aux_path(path):
        return []
    findings: list[Finding] = []
    for node in getattr(tree, "body", []):
        if isinstance(node, ast.Import):
            findings.extend(_check_import(node, model, path))
        elif isinstance(node, ast.ImportFrom):
            findings.extend(_check_import_from(node, model, path))
    lines = text.splitlines() if text is not None else None
    return _apply_pragmas(findings, lines)
