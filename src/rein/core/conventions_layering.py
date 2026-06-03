"""Architectural layering conventions."""

from __future__ import annotations

import ast
import sys

from .conventions_base import _convention_finding, _dotted_under, _path_in_scope
from .findings import Finding
from .profile import ConventionEntry


def _seg_infix(hay: list[str], needle: list[str]) -> bool:
    """True if needle segments are a contiguous infix of hay segments."""
    if not needle:
        return False
    n = len(needle)
    for i in range(len(hay) - n + 1):
        if hay[i : i + n] == needle:
            return True
    return False


def _check_import_node(
    node: ast.Import, forbidden: list[str], path: str, entry: ConventionEntry, message: str | None
) -> list[Finding]:
    """Check an Import node for forbidden absolute imports."""
    for alias in node.names:
        target = alias.name
        for f in forbidden:
            if _dotted_under(target, f):
                return [
                    _convention_finding(
                        entry,
                        path,
                        node.lineno,
                        message or f"layer must not import '{target}'",
                        target,
                    )
                ]
    return []


def _relative_base(path: str, level: int) -> list[str] | None:
    """Path segments the importing file resolves a relative import against.

    Drops the file's own basename, then climbs one directory per extra `.`
    beyond the first (level - 1). Returns None when the climb walks off the top
    of the path (more dots than directories), matching Python's own failure.
    """
    p = path.replace("\\", "/")
    base = [seg for seg in p.split("/") if seg][:-1]
    drop = level - 1
    if drop > len(base):
        return None
    return base[: len(base) - drop] if drop > 0 else base


def _relative_module_segments(node: ast.ImportFrom, path: str | None) -> list[list[str]]:
    """Resolve a relative ImportFrom to its MODULE candidate segment-lists.

    `from .pkg import a, b` -> one candidate, the module `[...base, 'pkg']` (the
    imported symbols are not modules). `from . import a, b` -> one candidate per
    imported submodule. Returns [] when the path is unknown or the climb fails.
    """
    if path is None:
        return []
    base = _relative_base(path, node.level)
    if base is None:
        return []
    if node.module:
        return [base + node.module.split(".")]
    return [base + [alias.name] for alias in node.names]


def _check_relative_import(
    node: ast.ImportFrom,
    forbidden_segments: list[list[str]],
    path: str,
    entry: ConventionEntry,
    message: str | None,
) -> list[Finding]:
    """Check a relative ImportFrom node for forbidden imports."""
    base_after_drop = _relative_base(path, node.level)
    if base_after_drop is None:
        return []

    if node.module:
        T = base_after_drop + node.module.split(".")
        candidate_lists = [T] + [T + [alias.name] for alias in node.names]
    else:
        candidate_lists = [base_after_drop + [alias.name] for alias in node.names]

    for cand in candidate_lists:
        for f_segs in forbidden_segments:
            if _seg_infix(cand, f_segs):
                target_dotted = ".".join(cand)
                return [
                    _convention_finding(
                        entry,
                        path,
                        node.lineno,
                        message or f"layer must not import '{target_dotted}'",
                        target_dotted,
                    )
                ]
    return []


def _check_absolute_import_from(
    node: ast.ImportFrom, forbidden: list[str], path: str, entry: ConventionEntry, message: str | None
) -> list[Finding]:
    """Check an absolute ImportFrom node for forbidden imports."""
    m = node.module
    if not m:
        return []
    candidates = [m] + [f"{m}.{alias.name}" for alias in node.names]
    for target in candidates:
        for f in forbidden:
            if _dotted_under(target, f):
                return [
                    _convention_finding(
                        entry,
                        path,
                        node.lineno,
                        message or f"layer must not import '{target}'",
                        target,
                    )
                ]
    return []


def _run_arch_layering(
    tree: ast.AST, path: str | None, entry: ConventionEntry
) -> list[Finding]:
    """Checker for 'arch.layering'."""
    if not _path_in_scope(path, entry.params.get("paths")):
        return []

    if path is None:
        return []

    forbidden = entry.params.get("forbidden") or []
    message = entry.params.get("message")
    forbidden_segments = [f.split(".") for f in forbidden]

    findings: list[Finding] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            res = _check_import_node(node, forbidden, path, entry, message)
            if res:
                findings.extend(res)
        elif isinstance(node, ast.ImportFrom):
            if node.level is not None and node.level >= 1:
                res = _check_relative_import(node, forbidden_segments, path, entry, message)
            elif node.level == 0 and node.module:
                res = _check_absolute_import_from(node, forbidden, path, entry, message)
            else:
                res = []
            if res:
                findings.extend(res)

    return findings


def _check_import_allowed(node, allowed, fire) -> list[Finding]:
    """Check an `import a.b.c` node against the allowlist (stdlib always ok)."""
    out: list[Finding] = []
    for alias in node.names:
        segs = alias.name.split(".")
        if segs[0] not in sys.stdlib_module_names and not allowed(segs):
            out.append(fire(alias.name, node.lineno))
    return out


def _check_importfrom_allowed(node, path, allowed, fire) -> list[Finding]:
    """Check a `from ... import ...` node against the allowlist.

    Relative imports resolve through the file path to their module segments;
    absolute imports check `node.module` (stdlib always ok). Imported symbols
    are never treated as modules.
    """
    if node.level is not None and node.level >= 1:
        out: list[Finding] = []
        for segs in _relative_module_segments(node, path):
            if not allowed(segs):
                out.append(fire(".".join(segs), node.lineno))
        return out
    if node.module:
        segs = node.module.split(".")
        if segs[0] not in sys.stdlib_module_names and not allowed(segs):
            return [fire(node.module, node.lineno)]
    return []


def _run_imports_allowed(
    tree: ast.AST, path: str | None, entry: ConventionEntry
) -> list[Finding]:
    """Checker for 'imports.allowed'."""
    if not _path_in_scope(path, entry.params.get("paths")):
        return []

    allow_segs = [a.split(".") for a in entry.params.get("allow", [])]
    message = entry.params.get("message")

    def _allowed(segs: list[str]) -> bool:
        return any(_seg_infix(segs, a) for a in allow_segs)

    def _fire(target: str, lineno: int) -> Finding:
        return _convention_finding(
            entry, path, lineno, message or f"import of '{target}' is not allowed", target
        )

    findings: list[Finding] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            findings.extend(_check_import_allowed(node, _allowed, _fire))
        elif isinstance(node, ast.ImportFrom):
            findings.extend(_check_importfrom_allowed(node, path, _allowed, _fire))

    return findings
