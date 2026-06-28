"""dup.function wired into the DIFF path only.

The precision lever is review_diff's added-line filter: a duplicate is reported
only when the duplicating function was ADDED in the diff. These tests are the
testbed gate for that wiring.
"""

from __future__ import annotations

import ast

import pytest

from rein.cli._helpers import _collect_diff_findings

# A reusable non-trivial body (>= 3 statements), shared so bodies collide.
_BODY = "    a = x + 1\n    b = a * 2\n    return b\n"


def _project(tmp_path, monkeypatch, files: dict[str, str], *, has_root: bool = True) -> None:
    """Lay out a temp project and chdir into it so _discover_project_root sees it."""
    if has_root:
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "t"\nversion = "0"\ndependencies = []\n', encoding="utf-8"
        )
    for name, content in files.items():
        (tmp_path / name).write_text(content, encoding="utf-8")
    monkeypatch.chdir(tmp_path)


def _dups(findings) -> list:
    return [f for f in findings if f.rule_id == "dup.function"]


def test_same_file_added_duplicate_fires(tmp_path, monkeypatch) -> None:
    content = "def original(x):\n" + _BODY + "def copy(x):\n" + _BODY
    _project(tmp_path, monkeypatch, {"util.py": content})
    diff = (
        "--- a/util.py\n+++ b/util.py\n@@ -1,4 +1,8 @@\n"
        " def original(x):\n     a = x + 1\n     b = a * 2\n     return b\n"
        "+def copy(x):\n+    a = x + 1\n+    b = a * 2\n+    return b\n"
    )
    dups = _dups(_collect_diff_findings(diff))
    assert len(dups) == 1
    assert dups[0].line == 5          # the ADDED def, not the pre-existing original
    assert dups[0].snippet == "copy"


def test_cross_file_added_duplicate_fires(tmp_path, monkeypatch) -> None:
    lib = "def existing(x):\n" + _BODY
    app = "import lib\n\n\ndef reimplemented(x):\n" + _BODY
    _project(tmp_path, monkeypatch, {"lib.py": lib, "app.py": app})
    diff = (
        "--- a/app.py\n+++ b/app.py\n@@ -1,1 +1,7 @@\n"
        " import lib\n"
        "+\n+\n+def reimplemented(x):\n+    a = x + 1\n+    b = a * 2\n+    return b\n"
    )
    dups = _dups(_collect_diff_findings(diff))
    assert len(dups) == 1
    assert dups[0].snippet == "reimplemented"
    assert "lib.py:existing" in dups[0].message


def test_novel_added_function_does_not_fire(tmp_path, monkeypatch) -> None:
    lib = "def existing(x):\n" + _BODY
    app = "def novel(x):\n    z = x * 7\n    w = z - 3\n    return w\n"
    _project(tmp_path, monkeypatch, {"lib.py": lib, "app.py": app})
    diff = (
        "--- a/app.py\n+++ b/app.py\n@@ -0,0 +1,4 @@\n"
        "+def novel(x):\n+    z = x * 7\n+    w = z - 3\n+    return w\n"
    )
    assert _dups(_collect_diff_findings(diff)) == []


def test_trivial_and_dunder_added_do_not_fire(tmp_path, monkeypatch) -> None:
    # Sibling carries identical bodies, but trivial/dunder never signature.
    lib = (
        "class D:\n    def __eq__(self, o):\n        self.a = 1\n        self.b = 2\n        self.c = 3\n"
        "def tiny2(x):\n    return x\n"
    )
    app = (
        "class C:\n    def __eq__(self, o):\n        self.a = 1\n        self.b = 2\n        self.c = 3\n"
        "def tiny(x):\n    return x\n"
    )
    _project(tmp_path, monkeypatch, {"lib.py": lib, "app.py": app})
    diff = (
        "--- a/app.py\n+++ b/app.py\n@@ -0,0 +1,7 @@\n"
        "+class C:\n+    def __eq__(self, o):\n+        self.a = 1\n+        self.b = 2\n+        self.c = 3\n"
        "+def tiny(x):\n+    return x\n"
    )
    assert _dups(_collect_diff_findings(diff)) == []


def test_preexisting_duplicates_not_on_added_lines_do_not_fire(tmp_path, monkeypatch) -> None:
    # mod.py already holds two identical functions (the flask/django case: a real
    # but accepted pre-existing dup). The diff adds an UNRELATED line, no def.
    content = "def dup_a(x):\n" + _BODY + "def dup_b(x):\n" + _BODY + "CONST = 1\n"
    _project(tmp_path, monkeypatch, {"mod.py": content})
    diff = (
        "--- a/mod.py\n+++ b/mod.py\n@@ -8,1 +8,2 @@\n"
        "     return b\n"
        "+CONST = 1\n"
    )
    assert _dups(_collect_diff_findings(diff)) == []


def test_realistic_normal_change_does_not_fire(tmp_path, monkeypatch) -> None:
    """Negative control / rein-diff dogfood: a normal change adding a genuinely
    new helper in a multi-file project -> no dup.function."""
    helpers = (
        "def load(path):\n    with open(path) as fh:\n        data = fh.read()\n    return data\n\n"
        "def save(path, data):\n    with open(path, 'w') as fh:\n        fh.write(data)\n    return True\n"
    )
    app = "import json\n\n\ndef parse_config(raw):\n    obj = json.loads(raw)\n    name = obj['name']\n    return name\n"
    _project(tmp_path, monkeypatch, {"helpers.py": helpers, "app.py": app})
    diff = (
        "--- a/app.py\n+++ b/app.py\n@@ -0,0 +1,7 @@\n"
        "+import json\n+\n+\n+def parse_config(raw):\n+    obj = json.loads(raw)\n+    name = obj['name']\n+    return name\n"
    )
    assert _dups(_collect_diff_findings(diff)) == []


@pytest.mark.parametrize("pragma", ["# rein:ignore dup.function", "# rein:ignore"])
def test_rein_ignore_pragma_on_added_def_line(tmp_path, monkeypatch, pragma) -> None:
    # NOTE: rein's pragma syntax is space-separated, not the bracket form
    # `# rein:ignore[dup.function]`; both the scoped and bare forms suppress here.
    lib = "def existing(x):\n" + _BODY
    app = f"def copy(x):  {pragma}\n" + _BODY
    _project(tmp_path, monkeypatch, {"lib.py": lib, "app.py": app})
    diff = (
        "--- a/app.py\n+++ b/app.py\n@@ -0,0 +1,4 @@\n"
        f"+def copy(x):  {pragma}\n+    a = x + 1\n+    b = a * 2\n+    return b\n"
    )
    assert _dups(_collect_diff_findings(diff)) == []


def test_no_project_context_is_within_file_only(tmp_path, monkeypatch) -> None:
    # No pyproject/requirements -> no project root -> cross-file is NOT indexed,
    # but a same-file added dup still fires.
    lib = "def existing(x):\n" + _BODY
    same = "def original(x):\n" + _BODY + "def copy(x):\n" + _BODY
    _project(tmp_path, monkeypatch, {"lib.py": lib, "same.py": same}, has_root=False)

    cross = (
        "--- a/cross.py\n+++ b/cross.py\n@@ -0,0 +1,4 @@\n"
        "+def reimpl(x):\n+    a = x + 1\n+    b = a * 2\n+    return b\n"
    )
    (tmp_path / "cross.py").write_text("def reimpl(x):\n" + _BODY, encoding="utf-8")
    assert _dups(_collect_diff_findings(cross)) == []     # lib.existing not indexed

    same_diff = (
        "--- a/same.py\n+++ b/same.py\n@@ -1,4 +1,8 @@\n"
        " def original(x):\n     a = x + 1\n     b = a * 2\n     return b\n"
        "+def copy(x):\n+    a = x + 1\n+    b = a * 2\n+    return b\n"
    )
    assert len(_dups(_collect_diff_findings(same_diff))) == 1


def test_diff_collect_parses_changed_file_once(tmp_path, monkeypatch) -> None:
    """Single-parse perf contract: the changed file is parsed exactly once and the
    tree shared across code_domain, the dup checker, and the index."""
    app = "def novel(x):\n    z = x * 7\n    w = z - 3\n    return w\n"
    _project(tmp_path, monkeypatch, {"app.py": app})
    diff = (
        "--- a/app.py\n+++ b/app.py\n@@ -0,0 +1,4 @@\n"
        "+def novel(x):\n+    z = x * 7\n+    w = z - 3\n+    return w\n"
    )
    calls = {"n": 0}
    real = ast.parse

    def counting(*a, **k):
        calls["n"] += 1
        return real(*a, **k)

    monkeypatch.setattr(ast, "parse", counting)
    _collect_diff_findings(diff)
    assert calls["n"] == 1
