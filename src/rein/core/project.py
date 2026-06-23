"""ProjectModel: a pure, deterministic model of a repo's resolvable names.

Built once per directory review. It answers one
question - does a top-level import name resolve? - against three sources: the
stdlib, the project's declared/installed dependencies, and the project's own
modules. No network, no code execution, no importing the target's modules: it
only reads `pyproject.toml`/`requirements*.txt` and walks `*.py` paths.

stdlib-only (sys, pathlib, tomllib, importlib.metadata, re) so it stays inside
the zero-dependency core.
"""

from __future__ import annotations

import importlib.metadata
import re
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

# Directories that never hold importable project modules.
_SKIP_DIRS = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "build",
        "dist",
        "__pycache__",
        "node_modules",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
    }
)

# Everything from the first version-specifier / extra / marker char onward.
_SPEC_RE = re.compile(r"[<>=!~;\[].*$", re.DOTALL)
# PEP 503: collapse runs of -, _, . into a single -.
_NORMALIZE_RE = re.compile(r"[-_.]+")


@dataclass(frozen=True)
class ProjectModel:
    """What resolves in a project: stdlib, dependencies, and own modules."""

    stdlib: frozenset[str]
    third_party: frozenset[str]
    project_modules: frozenset[str]

    def resolves(self, top_level: str) -> bool:
        """True if a top-level import name resolves to stdlib, a declared/installed
        dependency, or a project module."""
        return (
            top_level in self.stdlib
            or top_level in self.third_party
            or top_level in self.project_modules
        )


def _dist_name(requirement: str) -> str:
    """The bare distribution name from a requirement string (no extras/specs/markers)."""
    return _SPEC_RE.sub("", requirement.strip()).strip()


def _declared_import_names(requirements: list[str]) -> set[str]:
    """Normalized import-name candidates for each declared requirement.

    PEP 503 normalizes to a dashed, lowercased name; import names use
    underscores, so both the dashed and underscored forms are kept.
    """
    names: set[str] = set()
    for req in requirements:
        raw = _dist_name(req)
        if not raw:
            continue
        norm = _NORMALIZE_RE.sub("-", raw).lower()
        names.add(norm)
        names.add(norm.replace("-", "_"))
    return names


def _pyproject_requirements(root: Path) -> tuple[list[str], bool]:
    """(requirement strings, whether pyproject declared a dependency source)."""
    pp = root / "pyproject.toml"
    if not pp.is_file():
        return [], False
    try:
        data = tomllib.loads(pp.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, OSError, UnicodeDecodeError):
        return [], False
    project = data.get("project")
    if not isinstance(project, dict):
        return [], False

    reqs: list[str] = []
    has_source = False
    deps = project.get("dependencies")
    if isinstance(deps, list):
        has_source = True
        reqs.extend(str(d) for d in deps)
    optional = project.get("optional-dependencies")
    if isinstance(optional, dict):
        has_source = True
        for group in optional.values():
            if isinstance(group, list):
                reqs.extend(str(d) for d in group)
    return reqs, has_source


def _read_requirements_file(path: Path) -> list[str]:
    """Non-blank, non-comment, non-flag lines of one requirements file."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    out: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and not stripped.startswith("-"):
            out.append(stripped)
    return out


def _requirements_txt(root: Path) -> tuple[list[str], bool]:
    """(requirement strings, whether any requirements*.txt exists at the root)."""
    files = sorted(root.glob("requirements*.txt"))
    reqs: list[str] = []
    for path in files:
        reqs.extend(_read_requirements_file(path))
    return reqs, bool(files)


def _deepest_source_root(py: Path, source_roots: list[Path]) -> Path:
    """The source root (root or root/src) that the file imports relative to.

    The deepest ancestor wins, so files under `src/` resolve against `src/` and
    everything else against the repo root. `root` matches every file, so a
    source root is always found.
    """
    best = source_roots[0]
    for sr in source_roots:
        if py.is_relative_to(sr) and len(sr.parts) > len(best.parts):
            best = sr
    return best


def _project_modules(root: Path) -> set[str]:
    """Dotted module name of every project `*.py`, plus each top-level segment.

    Modules are dotted relative to their SOURCE ROOT, not the repo root: the
    repo root (flat layout) and `root/src` (src layout) when present. So a
    src-layout `src/pkg/mod.py` resolves to `pkg.mod`, not `src.pkg.mod`.
    `a/b/__init__.py` -> `a.b`. Build/cache/VCS dirs are skipped so they do not
    masquerade as importable modules.
    """
    source_roots = [root]
    src = root / "src"
    if src.is_dir():
        source_roots.append(src)

    mods: set[str] = set()
    for py in root.rglob("*.py"):
        if any(seg in _SKIP_DIRS for seg in py.relative_to(root).parts[:-1]):
            continue
        parts = py.relative_to(_deepest_source_root(py, source_roots)).parts
        if py.stem == "__init__":
            dotted = list(parts[:-1])
        else:
            dotted = [*parts[:-1], py.stem]
        if not dotted:
            continue
        mods.add(".".join(dotted))
        mods.add(dotted[0])
    return mods


def build_project_model(root: str | Path) -> ProjectModel | None:
    """Build the model for a project root, or None when it has no dependency source.

    Fail-open trigger: with neither pyproject `[project]` dependencies/optional-
    dependencies nor a `requirements*.txt`, we cannot know what is installed, so
    we return None and the project-aware checkers stay inert.
    """
    root = Path(root)
    pp_reqs, pp_source = _pyproject_requirements(root)
    rt_reqs, rt_source = _requirements_txt(root)
    if not pp_source and not rt_source:
        return None

    installed = set(importlib.metadata.packages_distributions().keys())
    third_party = installed | _declared_import_names(pp_reqs + rt_reqs)
    return ProjectModel(
        stdlib=frozenset(sys.stdlib_module_names),
        third_party=frozenset(third_party),
        project_modules=frozenset(_project_modules(root)),
    )
