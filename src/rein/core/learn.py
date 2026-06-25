"""Deterministic measurement and draft rendering for rein learn."""

from __future__ import annotations

import ast
import fnmatch
from dataclasses import dataclass

from .conventions_base import _STYLE_MATCHERS, _has_test_function, _looks_like_test_name
from .parsing import safe_parse
from .paths import path_basename, path_parts
from .profile import Profile

AGREEMENT_MIN = 0.9
SAMPLE_MIN = 10
_STYLE_PRIORITY = ("snake_case", "PascalCase", "UPPER_CASE", "camelCase")
_TEST_DIR_NAMES = ("tests", "test")


@dataclass(frozen=True)
class MeasuredConvention:
    checker: str
    params: dict[str, str]
    agreement: float
    sample_size: int


def convention_id(m: MeasuredConvention) -> str:
    """Return the stable ID for a convention."""
    if m.checker == "naming.identifier":
        return f"{m.params.get('target', 'unknown')}-naming"
    return m.checker.replace(".", "-")


def filter_net_new(measured: list[MeasuredConvention], existing: Profile | None) -> list[MeasuredConvention]:
    """Return only the measured conventions that are not already in the profile."""
    if existing is None:
        return measured
    existing_ids = {e.id for e in existing.conventions}
    return [m for m in measured if convention_id(m) not in existing_ids]


def _collect_identifiers(sources: list[str]) -> tuple[list[str], list[str]]:
    """Collect non-dunder function and class names from parsed Python sources."""
    function_names: list[str] = []
    class_names: list[str] = []

    for src in sources:
        tree = safe_parse(src)
        if tree is None:
            continue

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if not (node.name.startswith("__") and node.name.endswith("__")):
                    function_names.append(node.name)
            elif isinstance(node, ast.ClassDef):
                if not (node.name.startswith("__") and node.name.endswith("__")):
                    class_names.append(node.name)

    return function_names, class_names


def measure_naming(sources: list[str]) -> list[MeasuredConvention]:
    """Measure naming conventions across parsed sources."""
    function_names, class_names = _collect_identifiers(sources)

    results: list[MeasuredConvention] = []
    for target, names in [("function", function_names), ("class", class_names)]:
        total = len(names)
        if total < SAMPLE_MIN:
            continue

        best_style = None
        max_agreement = -1.0

        for style in _STYLE_PRIORITY:
            matcher = _STYLE_MATCHERS[style]
            matches = sum(1 for n in names if matcher(n))
            agreement = matches / total
            if agreement > max_agreement:
                max_agreement = agreement
                best_style = style

        if max_agreement >= AGREEMENT_MIN and best_style is not None:
            results.append(
                MeasuredConvention(
                    checker="naming.identifier",
                    params={"target": target, "style": best_style},
                    agreement=round(max_agreement, 2),
                    sample_size=total,
                )
            )

    return results


def _measure_dir(test_paths: list[str], n: int) -> tuple[str, float]:
    # Only conventional test-directory names are inferred. A non-standard or
    # absent test dir yields no proposal (conservative: a human can add it),
    # which also prevents proposing a garbage segment from an absolute path.
    counts: dict[str, int] = {}
    for path in test_paths:
        segs = set(p for p in path_parts(path)[:-1] if p in _TEST_DIR_NAMES)
        for seg in segs:
            counts[seg] = counts.get(seg, 0) + 1
    if not counts:
        return "", 0.0
    dom = sorted(counts.items(), key=lambda kv: (-kv[1], 0 if kv[0] == "tests" else 1))[0][0]
    return dom, counts[dom] / n


def _measure_filename(test_paths: list[str], n: int) -> tuple[str, float]:
    pattern_counts = {"test_*.py": 0, "*_test.py": 0}
    for path in test_paths:
        basename = path_basename(path)
        if fnmatch.fnmatchcase(basename, "test_*.py"):
            pattern_counts["test_*.py"] += 1
        if fnmatch.fnmatchcase(basename, "*_test.py"):
            pattern_counts["*_test.py"] += 1
    pat = "test_*.py" if pattern_counts["test_*.py"] >= pattern_counts["*_test.py"] else "*_test.py"
    return pat, pattern_counts[pat] / n


def measure_test_layout(files: list[tuple[str, str]]) -> list[MeasuredConvention]:
    """Measure test layout conventions (directory and filename)."""
    test_paths = []
    for path, text in files:
        basename = path_basename(path)
        if not _looks_like_test_name(basename):
            continue
        tree = safe_parse(text)
        if tree is None:
            continue
        if _has_test_function(tree):
            test_paths.append(path)

    n = len(test_paths)
    if n < SAMPLE_MIN:
        return []

    dominant_dir, agreement_dir = _measure_dir(test_paths, n)
    dominant_pattern, agreement_name = _measure_filename(test_paths, n)
    if not dominant_dir:
        return []

    if agreement_dir >= AGREEMENT_MIN and agreement_name >= AGREEMENT_MIN:
        return [
            MeasuredConvention(
                checker="layout.test-files",
                params={"directory": dominant_dir, "filename": dominant_pattern},
                agreement=round(min(agreement_dir, agreement_name), 2),
                sample_size=n
            )
        ]
    return []


def render_profile_draft(measured: list[MeasuredConvention], measured_at: str) -> str:
    """Render a proposed draft profile from measured conventions."""
    lines = [
        "# .rein-profile.toml",
        "# The ratified, versioned record of THIS repo's conventions. Edited by humans,",
        "# proposed by `rein learn` and by agents, ratified only by a human committing it.",
        "# rein enforces it deterministically.",
        "",
        "version = 1",
    ]

    if not measured:
        lines.append("")
        lines.append("# No conventions met the threshold for proposal.")
        lines.append("")
        return "\n".join(lines)

    for m in measured:
        cid = convention_id(m)

        lines.append("")
        lines.append(f"[conventions.{cid}]")
        lines.append(f'checker = "{m.checker}"')
        lines.append('severity = "low"')
        for k, v in m.params.items():
            lines.append(f'{k} = "{v}"')

        lines.append("")
        lines.append(f"[conventions.{cid}.evidence]")
        lines.append('source = "measured"')
        lines.append(f"sample_size = {m.sample_size}")
        lines.append(f"agreement = {m.agreement}")
        lines.append(f'measured_at = "{measured_at}"')

    lines.append("")
    return "\n".join(lines)
