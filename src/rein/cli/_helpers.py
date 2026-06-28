"""CLI helpers for `rein`.

Purely utility functions and detector wrappers for the thin CLI adapter.
"""

from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
import tomllib
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from ..core import custom
from ..core.code import code_domain
from ..core.conventions import scan_profile
from ..core.diffs import parse_added_lines
from ..core.duplication import build_function_index, check_duplicate_functions
from ..core.findings import Finding
from ..core.parsing import safe_parse
from ..core.profile import Profile, ProfileError, parse_profile, profile_invalid_finding
from ..core.project import build_project_model
from ..core.resolution import check_unresolved_imports
from ..core.review import review_diff_findings

_SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build",
    ".pytest_cache", ".mypy_cache", ".ruff_cache",
}


def _iter_files(paths: Iterable[str]) -> Iterable[str]:
    for path in paths:
        if os.path.isfile(path):
            yield path
        elif os.path.isdir(path):
            for root, dirs, files in os.walk(path):
                dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
                for name in files:
                    yield os.path.join(root, name)


def _git(*args: str) -> str:
    try:
        return subprocess.check_output(["git", *args], text=True, stderr=subprocess.DEVNULL)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return ""



def _discover_project_root() -> str | None:
    """Nearest ancestor (incl. cwd) with a dependency source, for the ProjectModel.

    Walks up from the working directory and returns the first directory holding a
    `pyproject.toml` or a `requirements*.txt`, else None (no project context).
    """
    cwd = Path.cwd()
    for directory in [cwd, *cwd.parents]:
        if (directory / "pyproject.toml").is_file():
            return str(directory)
        if any(directory.glob("requirements*.txt")):
            return str(directory)
    return None


def _is_within(path: str, root: str | None) -> bool:
    """True if `path` lives under `root` (the project the model was built for).

    The ProjectModel is discovered from the working directory, but review targets
    may point outside it (an installed package, a vendored tree, another
    checkout). Applying one project's module set to another tree mislabels every
    relative import as unresolved and renders the file's absolute path into the
    finding, so the project-aware checks must stay scoped to their own root.
    """
    if root is None:
        return False
    try:
        return os.path.commonpath([os.path.abspath(path), os.path.abspath(root)]) == os.path.abspath(root)
    except ValueError:  # different drives / mixed absolute-relative on Windows
        return False


def _collect_review_findings(targets: list[str], custom_rules: tuple[custom.CustomRule, ...] = (), profile: Profile | None = None) -> list[Finding]:
    findings: list[Finding] = []
    root = _discover_project_root()
    model = build_project_model(root) if root is not None else None
    for p in _iter_files(targets):
        if p.endswith(".py"):
            try:
                with open(p, encoding="utf-8") as fh:
                    text = fh.read()
            except (OSError, UnicodeDecodeError):
                continue
            # Parse once and share the tree across every AST-based checker.
            tree = safe_parse(text)
            findings.extend(code_domain(text, p, tree=tree))
            findings.extend(custom.scan_custom(text, p, custom_rules))
            if profile is not None:
                findings.extend(scan_profile(text, p, profile, tree=tree))
            if tree is not None:
                file_model = model if _is_within(p, root) else None
                findings.extend(check_unresolved_imports(tree, p, file_model, text=text))
    return findings


def _collect_stdin_findings(
    text: str,
    filename: str,
    custom_rules: tuple[custom.CustomRule, ...] = (),
    profile: Profile | None = None,
) -> list[Finding]:
    """Review one in-memory source (content mode), for `review --stdin`.

    The source is not on disk - it is the code an agent or a chat surface is
    about to write - so the project-aware checks (import resolution, path-based
    scanners) do not apply: this runs the content-mode set (`code_domain`) plus
    custom rules and the profile, sharing a single parse. `filename` is the
    virtual path used in findings and in path-based rules.
    """
    tree = safe_parse(text)
    findings: list[Finding] = list(code_domain(text, filename, tree=tree))
    findings.extend(custom.scan_custom(text, filename, custom_rules))
    if profile is not None:
        findings.extend(scan_profile(text, filename, profile, tree=tree))
    return findings


def _build_function_index(
    root: str | None, changed: dict[str, ast.Module | None]
) -> dict[str, list[str]]:
    """Signature -> `label:funcname` index for diff-scoped duplicate detection.

    Includes every parsed changed file (labeled by its diff path, so the checker
    excludes a function as its own duplicate) plus, when a project root exists,
    every other project `.py` parsed once - the cross-file substrate. With no
    project root the index is the changed files alone (within-diff detection).
    Adapter-side I/O on top of the pure `build_function_index`; a changed file is
    deduped by absolute path so it is never indexed twice under two labels.
    """
    modules: dict[str, ast.AST] = {p: t for p, t in changed.items() if t is not None}
    if root is not None:
        changed_abs = {os.path.abspath(p) for p in changed}
        for fpath in _iter_files([root]):
            if not fpath.endswith(".py") or os.path.abspath(fpath) in changed_abs:
                continue
            try:
                with open(fpath, encoding="utf-8") as fh:
                    tree = safe_parse(fh.read())
            except (OSError, UnicodeDecodeError):
                continue
            if tree is not None:
                modules[os.path.relpath(fpath, root)] = tree
    return build_function_index(modules)


def _collect_diff_findings(diff_text: str, custom_rules: tuple[custom.CustomRule, ...] = ()) -> list[Finding]:
    findings: list[Finding] = []
    paths = sorted({al.path for al in parse_added_lines(diff_text) if al.path})

    # Parse each changed file once; the tree is shared by code_domain, the dup
    # checker, and the project index (single-parse perf contract).
    sources: dict[str, str] = {}
    trees: dict[str, ast.Module | None] = {}
    for p in paths:
        try:
            with open(p, encoding="utf-8") as fh:
                sources[p] = fh.read()
        except (OSError, UnicodeDecodeError):
            continue
        trees[p] = safe_parse(sources[p])

    index = _build_function_index(_discover_project_root(), trees)

    for p in paths:
        if p not in sources:
            continue
        content, tree = sources[p], trees[p]

        def custom_domain(t: str, p_: str | None, _tree: ast.Module | None = tree) -> list[Finding]:
            return code_domain(t, p_, tree=_tree) + custom.scan_custom(t, p_, custom_rules)

        findings.extend(review_diff_findings(content, diff_text, p, domain=custom_domain))

        # dup.function is diff-scoped: only functions the agent ADDED are judged,
        # so review_diff_findings' added-line filter (not code_domain) gates it.
        if tree is not None:
            def dup_domain(t: str, p_: str | None, _tree: ast.Module = tree) -> list[Finding]:
                return check_duplicate_functions(_tree, p_, index, text=t)

            findings.extend(review_diff_findings(content, diff_text, p, domain=dup_domain))
    return findings


def _load_baseline(path: str) -> set[str]:
    """Fingerprints from a baseline file. Fail open: warn and return empty on
    any read/parse error, so a bad baseline never crashes or hides findings."""
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return {entry["fingerprint"] for entry in data.get("findings", [])}
    except (OSError, UnicodeDecodeError, ValueError, KeyError, TypeError):
        print(f"rein: could not read baseline '{path}'; ignoring it.", file=sys.stderr)
        return set()


def _load_profile(path: str = ".rein-profile.toml") -> tuple[Profile | None, list[Finding]]:
    if not os.path.exists(path):
        return None, []                      # missing -> silent, opt-in
    try:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
        return parse_profile(data), []
    except (OSError, tomllib.TOMLDecodeError, ProfileError) as exc:
        return None, [profile_invalid_finding(str(exc), path=path)]
