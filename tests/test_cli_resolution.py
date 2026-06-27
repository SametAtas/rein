"""imports.unresolved wired into the CLI directory review."""

from __future__ import annotations

import os
from pathlib import Path

from rein.cli._helpers import _collect_review_findings


def _project(tmp_path: Path) -> None:
    # A pyproject with a dependency source so build_project_model returns a model.
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "demo"\ndependencies = ["requests"]\n',
        encoding="utf-8",
    )


def _review_in(tmp_path: Path, rel: str, src: str):
    target = tmp_path / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(src, encoding="utf-8")
    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        return _collect_review_findings([rel])
    finally:
        os.chdir(cwd)


def _unresolved(findings):
    return [f for f in findings if f.rule_id == "imports.unresolved"]


def test_top_level_unresolved_import_is_flagged(tmp_path: Path) -> None:
    _project(tmp_path)
    findings = _review_in(tmp_path, "app.py", "import nonexistent999\n")
    hits = _unresolved(findings)
    assert len(hits) == 1
    assert hits[0].snippet == "nonexistent999"


def test_function_level_unresolved_import_is_not_flagged(tmp_path: Path) -> None:
    _project(tmp_path)
    findings = _review_in(tmp_path, "app.py", "def f():\n    import nonexistent999\n")
    assert _unresolved(findings) == []


def test_clean_file_has_no_unresolved(tmp_path: Path) -> None:
    _project(tmp_path)
    findings = _review_in(tmp_path, "app.py", "import os\nimport requests\n")
    assert _unresolved(findings) == []


def test_out_of_project_target_is_not_resolved(tmp_path: Path) -> None:
    # cwd is a project, but the review target lives in a sibling tree the model
    # knows nothing about. Its relative imports must not be flagged, and the
    # finding must never render the file's absolute path. (Regression: the
    # cwd model used to be applied to every target, flagging foreign relative
    # imports and leaking $HOME into the snippet.)
    _project(tmp_path)
    outside = tmp_path.parent / "outside_pkg"
    (outside / "sub").mkdir(parents=True, exist_ok=True)
    (outside / "sub" / "mod.py").write_text("from .base import thing\n", encoding="utf-8")
    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        findings = _collect_review_findings([str(outside)])
    finally:
        os.chdir(cwd)
    assert _unresolved(findings) == []
