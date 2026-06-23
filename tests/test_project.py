"""Tests for the ProjectModel substrate."""

from __future__ import annotations

from pathlib import Path

from rein.core.project import ProjectModel, build_project_model


def _write(path: Path, content: str = "") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


_PYPROJECT = """\
[project]
name = "demo"
dependencies = ["requests>=2.0", "PyYAML"]

[project.optional-dependencies]
dev = ["pytest>=8.0"]
"""


def test_build_model_populates_all_three_sources(tmp_path: Path) -> None:
    _write(tmp_path / "pyproject.toml", _PYPROJECT)
    _write(tmp_path / "pkg" / "__init__.py")
    _write(tmp_path / "pkg" / "mod.py", "x = 1\n")
    _write(tmp_path / "pkg" / "sub" / "deep.py", "y = 2\n")

    model = build_project_model(tmp_path)
    assert isinstance(model, ProjectModel)

    # stdlib
    assert model.stdlib
    assert "os" in model.stdlib

    # declared dependencies, normalized to import-name candidates
    assert "requests" in model.third_party
    assert "pyyaml" in model.third_party  # PyYAML -> pyyaml (PEP 503)
    assert "pytest" in model.third_party  # from optional-dependencies

    # project modules: dotted names + top-level segment
    assert "pkg" in model.project_modules
    assert "pkg.mod" in model.project_modules
    assert "pkg.sub.deep" in model.project_modules


def test_resolves_each_kind_and_unknown(tmp_path: Path) -> None:
    _write(
        tmp_path / "pyproject.toml",
        '[project]\nname = "demo"\ndependencies = ["requests"]\n',
    )
    _write(tmp_path / "app" / "__init__.py")
    _write(tmp_path / "app" / "main.py", "z = 0\n")

    model = build_project_model(tmp_path)
    assert model is not None
    assert model.resolves("sys") is True  # stdlib
    assert model.resolves("requests") is True  # declared dependency
    assert model.resolves("app") is True  # project module
    assert model.resolves("totally_made_up_name_xyz") is False


def test_no_dependency_source_returns_none(tmp_path: Path) -> None:
    # .py files present, but no pyproject deps and no requirements*.txt.
    _write(tmp_path / "loose.py", "a = 1\n")
    assert build_project_model(tmp_path) is None


def test_requirements_txt_is_a_dependency_source(tmp_path: Path) -> None:
    _write(
        tmp_path / "requirements.txt",
        "flask==3.0\n# a comment\n-r other.txt\n\n",
    )
    _write(tmp_path / "app.py", "a = 1\n")

    model = build_project_model(tmp_path)
    assert model is not None
    assert "flask" in model.third_party
    assert "app" in model.project_modules


def test_src_layout_modules_relative_to_src_root(tmp_path: Path) -> None:
    # In a src layout, modules import relative to src/, not the repo root.
    _write(
        tmp_path / "pyproject.toml",
        '[project]\nname = "demo"\ndependencies = []\n',
    )
    _write(tmp_path / "src" / "pkg" / "__init__.py")
    _write(tmp_path / "src" / "pkg" / "mod.py", "x = 1\n")

    model = build_project_model(tmp_path)
    assert model is not None
    assert model.resolves("pkg") is True
    assert model.resolves("pkg.mod") is True
    assert model.resolves("src") is False
    assert "src.pkg" not in model.project_modules


def test_skip_dirs_excluded_from_project_modules(tmp_path: Path) -> None:
    _write(
        tmp_path / "pyproject.toml",
        '[project]\nname = "demo"\ndependencies = []\n',
    )
    _write(tmp_path / "good.py", "a = 1\n")
    _write(tmp_path / ".venv" / "lib" / "vendored.py", "b = 2\n")
    _write(tmp_path / "build" / "stale.py", "c = 3\n")

    model = build_project_model(tmp_path)
    assert model is not None
    assert "good" in model.project_modules
    assert "vendored" not in model.project_modules
    assert "stale" not in model.project_modules
