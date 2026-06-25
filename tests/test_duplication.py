"""Tests for the duplicate-function substrate."""

from __future__ import annotations

import ast

from rein.core.duplication import (
    build_function_index,
    check_duplicate_functions,
    function_signature,
)

# A reusable non-trivial body (>= 3 statements, identifiers included).
_BODY = "    a = x + 1\n    b = a * 2\n    return b\n"


def _fn(src: str) -> ast.FunctionDef:
    return ast.parse(src).body[0]  # type: ignore[return-value]


def test_signature_none_for_trivial_body() -> None:
    assert function_signature(_fn("def f():\n    return 1\n")) is None


def test_signature_none_for_dunder() -> None:
    src = "def __init__(self):\n    self.a = 1\n    self.b = 2\n    self.c = 3\n"
    assert function_signature(_fn(src)) is None


def test_signature_nonnull_and_stable_for_nontrivial() -> None:
    src = "def f(x):\n" + _BODY
    sig = function_signature(_fn(src))
    assert isinstance(sig, str)
    assert function_signature(_fn(src)) == sig  # stable across parses


def test_leading_docstring_is_dropped() -> None:
    with_doc = _fn('def f(x):\n    """doc"""\n' + _BODY)
    without = _fn("def f(x):\n" + _BODY)
    assert function_signature(with_doc) == function_signature(without)


def test_identical_bodies_share_signature_despite_names() -> None:
    f1 = _fn("def f(x):\n" + _BODY)
    g1 = _fn("def g(x):\n" + _BODY)
    sig = function_signature(f1)
    assert sig is not None
    assert function_signature(g1) == sig


def test_build_index_groups_duplicates_and_isolates_unique() -> None:
    uniq = "def uniq(y):\n    p = y - 1\n    q = p * 3\n    return q\n"
    mod_a = ast.parse("def dup(x):\n" + _BODY + "\n\n" + uniq)
    mod_b = ast.parse("def dup2(x):\n" + _BODY)

    index = build_function_index({"a": mod_a, "b": mod_b})

    groups = [locs for locs in index.values() if len(locs) > 1]
    assert len(groups) == 1
    assert set(groups[0]) == {"a:dup", "b:dup2"}

    uniq_sig = function_signature(_fn(uniq))
    assert index[uniq_sig] == ["a:uniq"]


# -- check_duplicate_functions -------------------------------------------------

def _index_for(src: str, locations: list[str]) -> dict[str, list[str]]:
    sig = function_signature(_fn(src))
    assert sig is not None
    return {sig: locations}


def test_function_matching_different_location_fires() -> None:
    src = "def f(x):\n" + _BODY
    index = _index_for(src, ["mine.py:f", "other.py:g"])
    findings = check_duplicate_functions(ast.parse(src), "mine.py", index)
    assert len(findings) == 1
    assert findings[0].rule_id == "dup.function"
    assert findings[0].snippet == "f"
    assert findings[0].line == 1
    assert "other.py:g" in findings[0].message


def test_function_matching_only_itself_does_not_fire() -> None:
    src = "def f(x):\n" + _BODY
    index = _index_for(src, ["mine.py:f"])
    assert check_duplicate_functions(ast.parse(src), "mine.py", index) == []


def test_trivial_or_dunder_never_fires() -> None:
    trivial = ast.parse("def f():\n    return 1\n")
    assert check_duplicate_functions(trivial, "m.py", {"sig": ["a:b"]}) == []
    dunder = ast.parse("def __init__(self):\n    self.a = 1\n    self.b = 2\n    self.c = 3\n")
    assert check_duplicate_functions(dunder, "m.py", {}) == []


def test_function_absent_from_index_does_not_fire() -> None:
    src = "def f(x):\n" + _BODY
    assert check_duplicate_functions(ast.parse(src), "mine.py", {}) == []


def test_rein_ignore_pragma_on_def_line() -> None:
    src = "def f(x):  # rein:ignore dup.function\n" + _BODY
    index = _index_for(src, ["mine.py:f", "other.py:g"])
    assert check_duplicate_functions(ast.parse(src), "mine.py", index, text=src) == []
    bare = "def f(x):  # rein:ignore\n" + _BODY
    index2 = _index_for(bare, ["mine.py:f", "other.py:g"])
    assert check_duplicate_functions(ast.parse(bare), "mine.py", index2, text=bare) == []


def test_aux_path_skipped() -> None:
    src = "def f(x):\n" + _BODY
    index = _index_for(src, ["docs/x.py:f", "other.py:g"])
    assert check_duplicate_functions(ast.parse(src), "docs/conf.py", index) == []
