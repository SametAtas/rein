"""Convention checkers engine.

Parses source code into an AST and dispatches to the pure checkers declared in
a ratified Profile.
"""

from __future__ import annotations

import ast
import fnmatch
from typing import Callable

from .conventions_base import (
    _STYLE_MATCHERS,
    _convention_finding,
    _has_test_function,
    _in_directory,
    _looks_like_test_name,
    _path_in_scope,
    _dotted_under,
)
from .conventions_complexity import _run_complexity
from .conventions_layering import _run_arch_layering, _run_imports_allowed
from .findings import Finding
from .parsing import safe_parse
from .paths import path_basename
from .profile import ConventionEntry, Profile
from .security import _build_import_map, _canonical_name, _dotted_name


def _run_naming(
    tree: ast.AST, path: str | None, entry: ConventionEntry
) -> list[Finding]:
    """Checker for 'naming.identifier'."""
    findings: list[Finding] = []
    target = entry.params.get("target")
    style = entry.params.get("style")
    if not target or not style:
        return findings

    matcher = _STYLE_MATCHERS.get(style)
    if not matcher:
        return findings

    for node in ast.walk(tree):
        if target == "function" and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            name = node.name
        elif target == "class" and isinstance(node, ast.ClassDef):
            name = node.name
        else:
            continue

        if name.startswith("__") and name.endswith("__"):
            continue

        if not matcher(name):
            findings.append(
                _convention_finding(
                    entry,
                    path,
                    node.lineno,
                    f"{target} '{name}' does not follow the '{style}' naming convention.",
                    name,
                )
            )

    return findings





def _run_test_layout(
    tree: ast.AST, path: str | None, entry: ConventionEntry
) -> list[Finding]:
    if path is None:
        return []

    basename = path_basename(path)
    if not _looks_like_test_name(basename):
        return []

    if not _has_test_function(tree):
        return []

    directory = entry.params["directory"]
    filename = entry.params["filename"]

    if not _in_directory(path, directory):
        msg = f"test file '{basename}' is outside the configured test directory '{directory}'"
    elif not fnmatch.fnmatchcase(basename, filename):
        msg = f"test file '{basename}' does not match the naming pattern '{filename}'"
    else:
        return []

    return [_convention_finding(entry, path, None, msg, basename)]





def _run_forbid_call(
    tree: ast.AST, path: str | None, entry: ConventionEntry
) -> list[Finding]:
    if not _path_in_scope(path, entry.params.get("paths")):
        return []

    forbidden = set(entry.params["calls"])
    message = entry.params.get("message")
    imports = _build_import_map(tree)

    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        raw = _dotted_name(node.func)
        if raw is None:
            continue

        name = _canonical_name(raw, imports)
        if name in forbidden:
            findings.append(
                _convention_finding(
                    entry,
                    path,
                    node.lineno,
                    message or f"call to '{name}' is forbidden",
                    name,
                )
            )

    return findings





def _run_forbid_import(
    tree: ast.AST, path: str | None, entry: ConventionEntry
) -> list[Finding]:
    if not _path_in_scope(path, entry.params.get("paths")):
        return []

    forbidden = entry.params["imports"]
    message = entry.params.get("message")

    findings: list[Finding] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            mods = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            mods = [node.module]
        else:
            continue

        for m in mods:
            for f in forbidden:
                if _dotted_under(m, f):
                    findings.append(
                        _convention_finding(
                            entry,
                            path,
                            node.lineno,
                            message or f"import of '{m}' is forbidden",
                            m,
                        )
                    )
                    break

    return findings


_RUNNERS: dict[str, Callable[[ast.AST, str | None, ConventionEntry], list[Finding]]] = {
    "naming.identifier": _run_naming,
    "layout.test-files": _run_test_layout,
    "forbid.call": _run_forbid_call,
    "forbid.import": _run_forbid_import,
    "arch.layering": _run_arch_layering,
    "imports.allowed": _run_imports_allowed,
    "complexity.function": _run_complexity,
}


def scan_profile(
    text: str, path: str | None, profile: Profile, *, tree: ast.Module | None = None
) -> list[Finding]:
    """Parse the AST and run all enabled conventions from the profile.

    A caller that already parsed the source can pass *tree* to avoid re-parsing.
    """
    findings: list[Finding] = []

    if not profile.conventions:
        return findings

    # Are there any enabled conventions with known checkers?
    active_entries = [
        e for e in profile.conventions if e.enabled and e.checker in _RUNNERS
    ]
    if not active_entries:
        return findings

    if tree is None:
        tree = safe_parse(text)
    if tree is None:
        return findings  # fail open on unparseable source

    for entry in active_entries:
        runner = _RUNNERS[entry.checker]
        findings.extend(runner(tree, path, entry))

    return findings
