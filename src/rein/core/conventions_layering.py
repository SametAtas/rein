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


def _check_relative_import(
    node: ast.ImportFrom,
    forbidden_segments: list[list[str]],
    path: str,
    entry: ConventionEntry,
    message: str | None,
) -> list[Finding]:
    """Check a relative ImportFrom node for forbidden imports."""
    p = path.replace("\\", "/")
    base = [seg for seg in p.split("/") if seg][:-1]
    drop = node.level - 1
    if drop > len(base):
        return []
    base_after_drop = base[: len(base) - drop] if drop > 0 else base

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


def _run_imports_allowed(
    tree: ast.AST, path: str | None, entry: ConventionEntry
) -> list[Finding]:
    """Checker for 'imports.allowed'."""
    if not _path_in_scope(path, entry.params.get("paths")):
        return []

    allow = set(entry.params.get("allow", []))
    message = entry.params.get("message")

    findings: list[Finding] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                if top not in sys.stdlib_module_names and top not in allow:
                    findings.append(
                        _convention_finding(
                            entry,
                            path,
                            node.lineno,
                            message or f"import of '{top}' is not allowed",
                            top,
                        )
                    )
        elif isinstance(node, ast.ImportFrom):
            if node.level is not None and node.level > 0:
                continue
            if node.module:
                top = node.module.split(".")[0]
                if top not in sys.stdlib_module_names and top not in allow:
                    findings.append(
                        _convention_finding(
                            entry,
                            path,
                            node.lineno,
                            message or f"import of '{top}' is not allowed",
                            top,
                        )
                    )

    return findings
