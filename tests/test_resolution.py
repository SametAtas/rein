"""Tests for the imports.unresolved checker."""

from __future__ import annotations

import ast
import sys

from rein.core.project import ProjectModel
from rein.core.resolution import check_unresolved_imports


def _model() -> ProjectModel:
    return ProjectModel(
        stdlib=frozenset(sys.stdlib_module_names),
        third_party=frozenset({"requests"}),
        project_modules=frozenset({"pkg", "pkg.mod", "pkg.sub"}),
    )


def _check(src: str, path: str | None = "pkg/sub.py", model: ProjectModel | None = None):
    if model is None:
        model = _model()
    return check_unresolved_imports(ast.parse(src), path, model, text=src)


# -- recall: hallucinated targets must fire ------------------------------------

def test_unresolved_absolute_import_fires() -> None:
    findings = _check("import nonexistent_pkg999\n")
    assert len(findings) == 1
    assert findings[0].rule_id == "imports.unresolved"
    assert findings[0].snippet == "nonexistent_pkg999"
    assert findings[0].line == 1


def test_unresolved_relative_import_fires() -> None:
    # `.gone` resolves to pkg.gone, not a project module.
    findings = _check("from .gone import thing\n", path="pkg/sub.py")
    assert len(findings) == 1
    assert findings[0].snippet == "pkg.gone"


# -- precision: resolvable targets stay silent ---------------------------------

def test_stdlib_import_clean() -> None:
    assert _check("import os\nimport os.path\n") == []


def test_declared_dependency_clean() -> None:
    assert _check("import requests\nfrom requests import Session\n") == []


def test_project_module_clean() -> None:
    assert _check("import pkg\nfrom pkg.mod import helper\n") == []


def test_relative_project_module_clean() -> None:
    assert _check("from .mod import helper\n", path="pkg/sub.py") == []


def test_from_dot_import_name_clean_when_base_resolves() -> None:
    # `from . import x` / `from .. import __version__`: the names may be __init__
    # bindings, not submodules. If the base package resolves, do not flag.
    assert _check("from . import helper\n", path="pkg/sub.py") == []
    assert _check("from . import a, b\n", path="pkg/mod.py") == []


# -- top-level-only: nested imports are never judged ---------------------------

def test_function_level_unresolved_is_skipped() -> None:
    # Only module-top-level imports are judged; a function-level import is nested.
    assert _check("def f():\n    import nonexistent_pkg999\n") == []


def test_try_except_importerror_exempt() -> None:
    # Now skipped by construction: the import is nested under `try`, not in body.
    src = "try:\n    import nonexistent_pkg999\nexcept ImportError:\n    nonexistent_pkg999 = None\n"
    assert _check(src) == []


def test_type_checking_block_exempt() -> None:
    # Nested under `if TYPE_CHECKING:`, so not a direct child of the module body.
    src = "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    import nonexistent_pkg999\n"
    assert _check(src) == []


# -- fail-open exemptions ------------------------------------------------------

def test_rein_ignore_pragma_exempt() -> None:
    assert _check("import nonexistent_pkg999  # rein:ignore imports.unresolved\n") == []
    assert _check("import nonexistent_pkg999  # rein:ignore\n") == []


def test_future_import_never_fires() -> None:
    assert _check("from __future__ import annotations\n") == []


def test_dunder_main_never_fires() -> None:
    assert _check("import __main__\n") == []


def test_auxiliary_path_is_skipped() -> None:
    # A file under an auxiliary tree is not the shipped package; do not judge it.
    src = "import nonexistent_pkg999\n"
    assert _check(src, path="docs/conf.py") == []
    assert _check(src, path="tests/test_thing.py") == []


def test_model_none_is_inert() -> None:
    src = "import nonexistent_pkg999\n"
    assert check_unresolved_imports(ast.parse(src), "pkg/sub.py", None, text=src) == []
