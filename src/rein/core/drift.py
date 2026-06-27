"""Convention drift detection (pure engine logic).

Measures conformance of the current codebase against ratified conventions
to identify when statistical norms have significantly decayed or shifted.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from typing import Any

from .conventions_base import (
    _STYLE_MATCHERS,
    _looks_like_test_name,
    _has_test_function,
    _in_directory,
)
from .learn import AGREEMENT_MIN, SAMPLE_MIN, _collect_identifiers
from .parsing import safe_parse
from .paths import path_basename
from .profile import Profile


@dataclass(frozen=True)
class DriftReport:
    convention_id: str
    checker: str
    summary: str
    ratified_agreement: float
    current_conformance: float
    sample_size: int
    drifted: bool


def _measure_naming_drift(
    entry: Any,
    function_names: list[str],
    class_names: list[str],
    ratified_agreement: float,
) -> DriftReport | None:
    """Helper to measure drift of a naming convention."""
    target = entry.params.get("target")
    style = entry.params.get("style")
    if not target or not style or style not in _STYLE_MATCHERS:
        return None

    names = function_names if target == "function" else class_names
    total = len(names)

    if total == 0:
        conformance = 0.0
    else:
        matcher = _STYLE_MATCHERS[style]
        matches = sum(1 for n in names if matcher(n))
        conformance = matches / total

    summary = f"{target} naming -> {style}"
    drifted = (total >= SAMPLE_MIN) and (conformance < AGREEMENT_MIN)

    return DriftReport(
        convention_id=entry.id,
        checker=entry.checker,
        summary=summary,
        ratified_agreement=ratified_agreement,
        current_conformance=round(conformance, 2),
        sample_size=total,
        drifted=drifted,
    )


def _measure_layout_drift(
    entry: Any,
    files: list[tuple[str, str]],
    ratified_agreement: float,
) -> DriftReport | None:
    """Helper to measure drift of a test layout convention."""
    directory = entry.params.get("directory")
    filename = entry.params.get("filename")
    if not directory or not filename:
        return None

    test_files: list[str] = []
    conforming_count = 0

    for path, text in files:
        if not path:
            continue
        basename = path_basename(path)
        if not _looks_like_test_name(basename):
            continue
        tree = safe_parse(text)
        if tree is not None and _has_test_function(tree):
            test_files.append(path)
            if _in_directory(path, directory) and fnmatch.fnmatchcase(basename, filename):
                conforming_count += 1

    total = len(test_files)
    conformance = (conforming_count / total) if total > 0 else 0.0
    summary = f"test layout -> {directory}, {filename}"
    drifted = (total >= SAMPLE_MIN) and (conformance < AGREEMENT_MIN)

    return DriftReport(
        convention_id=entry.id,
        checker=entry.checker,
        summary=summary,
        ratified_agreement=ratified_agreement,
        current_conformance=round(conformance, 2),
        sample_size=total,
        drifted=drifted,
    )


def measure_drift(profile: Profile, files: list[tuple[str, str]]) -> list[DriftReport]:
    """Measure conformance of files against the profile's statistical conventions.

    Advisory and read-only. Skips declared house rules or malformed evidence blocks.
    """
    reports: list[DriftReport] = []
    if not profile.conventions:
        return reports

    python_sources = [text for path, text in files if path and path.endswith(".py")]
    names_collected = False
    function_names: list[str] = []
    class_names: list[str] = []

    for entry in profile.conventions:
        if not entry.evidence or not isinstance(entry.evidence, dict):
            continue
        if entry.evidence.get("source") != "measured":
            continue

        ratified_agreement_val = entry.evidence.get("agreement")
        try:
            ratified_agreement = float(ratified_agreement_val)
        except (TypeError, ValueError):
            continue

        if entry.checker == "naming.identifier":
            if not names_collected:
                function_names, class_names = _collect_identifiers(python_sources)
                names_collected = True
            rep = _measure_naming_drift(entry, function_names, class_names, ratified_agreement)
            if rep is not None:
                reports.append(rep)
        elif entry.checker == "layout.test-files":
            rep = _measure_layout_drift(entry, files, ratified_agreement)
            if rep is not None:
                reports.append(rep)

    return reports
