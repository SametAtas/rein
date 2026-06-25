"""Tests for the bound-name collection substrate."""

from __future__ import annotations

import ast
import sys

import pytest

from rein.core.names import (
    ALWAYS_DEFINED,
    check_undefined_names,
    collect_bound_names,
)


def _bound(src: str) -> frozenset[str]:
    return collect_bound_names(ast.parse(src))


def test_simple_assignment() -> None:
    assert "x" in _bound("x = 1\n")


def test_tuple_unpacking() -> None:
    names = _bound("a, (b, *c) = 1, (2, 3)\n")
    assert {"a", "b", "c"} <= names


def test_ann_assign() -> None:
    assert "y" in _bound("y: int = 1\n")


def test_aug_assign() -> None:
    assert "z" in _bound("z = 0\nz += 1\n")


def test_for_target() -> None:
    assert "i" in _bound("for i in range(3):\n    pass\n")


def test_with_as() -> None:
    assert "fh" in _bound("with open('x') as fh:\n    pass\n")


def test_except_as() -> None:
    assert "err" in _bound("try:\n    pass\nexcept Exception as err:\n    pass\n")


def test_function_def_name() -> None:
    assert "myfunc" in _bound("def myfunc():\n    pass\n")


def test_class_def_name() -> None:
    assert "MyClass" in _bound("class MyClass:\n    pass\n")


def test_function_params_including_kwonly_and_vararg() -> None:
    src = "def f(a, b, /, c, *args, d, **kwargs):\n    pass\n"
    assert {"a", "b", "c", "args", "d", "kwargs"} <= _bound(src)


def test_lambda_params() -> None:
    assert "p" in _bound("g = lambda p: p + 1\n")


def test_comprehension_target() -> None:
    assert "k" in _bound("xs = [k for k in range(3)]\n")


def test_import_and_alias() -> None:
    names = _bound("import os\nimport os.path as osp\nimport collections.abc\n")
    assert {"os", "osp", "collections"} <= names


def test_from_import_and_alias() -> None:
    names = _bound("from a import b\nfrom a import c as d\n")
    assert {"b", "d"} <= names


def test_global_and_nonlocal() -> None:
    src = "def outer():\n    v = 1\n    def inner():\n        nonlocal v\n        global gv\n    return inner\n"
    assert {"v", "gv"} <= _bound(src)


def test_walrus() -> None:
    assert "w" in _bound("if (w := 10) > 5:\n    pass\n")


def test_match_capture() -> None:
    src = "match obj:\n    case [first, *rest]:\n        pass\n    case {'k': 1, **others}:\n        pass\n    case other:\n        pass\n"
    assert {"first", "rest", "others", "other"} <= _bound(src)


@pytest.mark.skipif(sys.version_info < (3, 12), reason="PEP 695 type params need Py3.12+")
def test_type_params() -> None:
    names = _bound("def f[T](x: T) -> T:\n    return x\n")
    assert "T" in names
    alias_names = _bound("type Vec[U] = list[U]\n")
    assert "U" in alias_names


def test_always_defined_has_builtins_and_dunders() -> None:
    assert "print" in ALWAYS_DEFINED
    assert "len" in ALWAYS_DEFINED
    assert "__name__" in ALWAYS_DEFINED


# -- check_undefined_names -----------------------------------------------------

def _undef(src: str, path: str | None = "pkg/mod.py"):
    return check_undefined_names(ast.parse(src), path, text=src)


def test_undefined_call_fires() -> None:
    findings = _undef("def f(x):\n    return procss(x)\n")
    assert len(findings) == 1
    assert findings[0].rule_id == "names.undefined"
    assert findings[0].snippet == "procss"
    assert findings[0].line == 2


def test_undefined_attribute_base_fires() -> None:
    findings = _undef("def f():\n    return respone.json()\n")
    assert [f.snippet for f in findings] == ["respone"]


def test_clean_file_no_undefined() -> None:
    src = (
        "import math\n"
        "def f(items):\n"
        "    total = sum(len(s) for s in items)\n"
        "    if (n := total) > 0:\n"
        "        return math.sqrt(n)\n"
        "    return 0\n"
    )
    assert _undef(src) == []


def test_star_import_bails() -> None:
    # A star import can bind anything, so the checker stays silent (fail-open).
    assert _undef("from os import *\n\ndef f():\n    return something_unbound\n") == []


def test_aux_path_skipped() -> None:
    src = "x = undefined_thing\n"
    assert _undef(src, path="docs/conf.py") == []
    assert _undef(src, path="tests/test_x.py") == []


def test_rein_ignore_pragma() -> None:
    assert _undef("y = undefined_thing  # rein:ignore names.undefined\n") == []
    assert _undef("y = undefined_thing  # rein:ignore\n") == []


def test_ipython_injected_globals_not_flagged() -> None:
    # The IPython/Jupyter probe pattern references runtime-injected globals.
    src = "try:\n    ip = get_ipython()\nexcept NameError:\n    ip = None\nflag = __IPYTHON__\n"
    assert _undef(src) == []
