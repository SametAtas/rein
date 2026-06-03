"""Tests for core lint rules.

At least one positive and one negative case per rule, plus a pragma case.
"""

from rein.core.lint import lint_text


def _ids(findings):
    return {f.rule_id for f in findings}


# -- lint.syntax-error -------------------------------------------------------

def test_syntax_error_flagged():
    assert "lint.syntax-error" in _ids(lint_text("def foo(:\n"))


def test_valid_syntax_not_flagged():
    assert "lint.syntax-error" not in _ids(lint_text("x = 1\n"))


# -- lint.missing-future-import ----------------------------------------------

def test_missing_future_import_flagged():
    src = "def foo() -> int:\n    return 1\n"
    assert "lint.missing-future-import" in _ids(lint_text(src))


def test_future_import_present_not_flagged():
    src = "from __future__ import annotations\n\ndef foo() -> int:\n    return 1\n"
    assert "lint.missing-future-import" not in _ids(lint_text(src))


def test_no_functions_no_future_import_not_flagged():
    assert "lint.missing-future-import" not in _ids(lint_text("x = 1\n"))


# -- lint.missing-type-hints -------------------------------------------------

def test_missing_return_annotation_flagged():
    src = "from __future__ import annotations\n\ndef foo():\n    pass\n"
    assert "lint.missing-type-hints" in _ids(lint_text(src))


def test_missing_param_annotation_flagged():
    src = "from __future__ import annotations\n\ndef foo(x) -> None:\n    pass\n"
    assert "lint.missing-type-hints" in _ids(lint_text(src))


def test_fully_annotated_not_flagged():
    src = "from __future__ import annotations\n\ndef foo(x: int) -> int:\n    return x\n"
    assert "lint.missing-type-hints" not in _ids(lint_text(src))


def test_private_function_not_flagged():
    src = "from __future__ import annotations\n\ndef _helper():\n    pass\n"
    assert "lint.missing-type-hints" not in _ids(lint_text(src))


def test_self_cls_ignored():
    src = (
        "from __future__ import annotations\n\n"
        "class C:\n"
        "    def method(self, x: int) -> None:\n"
        "        pass\n"
    )
    assert "lint.missing-type-hints" not in _ids(lint_text(src))


# -- lint.function-too-long --------------------------------------------------

def test_long_function_flagged():
    body = "\n".join(f"    x{i} = {i}" for i in range(60))
    src = f"from __future__ import annotations\n\ndef foo() -> None:\n{body}\n"
    assert "lint.function-too-long" in _ids(lint_text(src))


def test_short_function_not_flagged():
    src = "from __future__ import annotations\n\ndef foo() -> None:\n    pass\n"
    assert "lint.function-too-long" not in _ids(lint_text(src))


# -- lint.file-too-long ------------------------------------------------------

def test_long_file_flagged():
    src = "\n".join(f"x{i} = {i}" for i in range(260))
    assert "lint.file-too-long" in _ids(lint_text(src))


def test_short_file_not_flagged():
    assert "lint.file-too-long" not in _ids(lint_text("x = 1\n"))


# -- lint.todo-comment -------------------------------------------------------

def test_todo_flagged():
    assert "lint.todo-comment" in _ids(lint_text("# TODO: fix this\n"))


def test_fixme_flagged():
    assert "lint.todo-comment" in _ids(lint_text("# FIXME: broken\n"))


def test_no_todo_not_flagged():
    assert "lint.todo-comment" not in _ids(lint_text("# this is fine\n"))


def test_todo_pragma_suppressed():
    src = "# TODO: fix later  # rein:ignore lint.todo-comment\n"
    assert "lint.todo-comment" not in _ids(lint_text(src))


# -- lint.stub-body ----------------------------------------------------------

def test_pass_body_flagged():
    src = "from __future__ import annotations\n\ndef foo() -> None:\n    pass\n"
    assert "lint.stub-body" in _ids(lint_text(src))


def test_ellipsis_body_flagged():
    src = "from __future__ import annotations\n\ndef foo() -> None:\n    ...\n"
    assert "lint.stub-body" in _ids(lint_text(src))


def test_raise_not_implemented_flagged():
    src = (
        "from __future__ import annotations\n\n"
        "def foo() -> None:\n"
        "    raise NotImplementedError\n"
    )
    assert "lint.stub-body" in _ids(lint_text(src))


def test_real_body_not_flagged():
    src = "from __future__ import annotations\n\ndef foo() -> int:\n    return 42\n"
    assert "lint.stub-body" not in _ids(lint_text(src))


# -- lint.non-ascii -----------------------------------------------------------

def test_non_ascii_flagged():
    src = "# hello " + "\u00e9" + "\n"
    assert "lint.non-ascii" in _ids(lint_text(src))


def test_ascii_only_not_flagged():
    assert "lint.non-ascii" not in _ids(lint_text("# hello world\n"))


# -- lint.trailing-whitespace -------------------------------------------------

def test_trailing_whitespace_flagged():
    assert "lint.trailing-whitespace" in _ids(lint_text("x = 1   \n"))


def test_no_trailing_whitespace_not_flagged():
    assert "lint.trailing-whitespace" not in _ids(lint_text("x = 1\n"))


# -- lint.unreachable-code ----------------------------------------------------

def test_unreachable_code_after_return():
    src = (
        "from __future__ import annotations\n"
        "def f() -> int:\n"
        "    return 1\n"
        "    x = 2\n"
    )
    findings = lint_text(src)
    assert "lint.unreachable-code" in _ids(findings)
    unreachable = [f for f in findings if f.rule_id == "lint.unreachable-code"]
    assert len(unreachable) == 1
    assert unreachable[0].line == 4
    assert unreachable[0].message == "unreachable code after a return statement"


def test_unreachable_code_after_raise():
    src = (
        "from __future__ import annotations\n"
        "def f() -> None:\n"
        "    raise ValueError()\n"
        "    print('unreachable')\n"
    )
    findings = lint_text(src)
    assert "lint.unreachable-code" in _ids(findings)
    unreachable = [f for f in findings if f.rule_id == "lint.unreachable-code"]
    assert len(unreachable) == 1
    assert unreachable[0].line == 4
    assert unreachable[0].message == "unreachable code after a raise statement"


def test_unreachable_code_after_break():
    src = (
        "from __future__ import annotations\n"
        "for i in range(5):\n"
        "    break\n"
        "    x = 1\n"
    )
    findings = lint_text(src)
    assert "lint.unreachable-code" in _ids(findings)
    unreachable = [f for f in findings if f.rule_id == "lint.unreachable-code"]
    assert len(unreachable) == 1
    assert unreachable[0].line == 4
    assert unreachable[0].message == "unreachable code after a break statement"


def test_unreachable_code_after_continue():
    src = (
        "from __future__ import annotations\n"
        "for i in range(5):\n"
        "    continue\n"
        "    y = 2\n"
    )
    findings = lint_text(src)
    assert "lint.unreachable-code" in _ids(findings)
    unreachable = [f for f in findings if f.rule_id == "lint.unreachable-code"]
    assert len(unreachable) == 1
    assert unreachable[0].line == 4
    assert unreachable[0].message == "unreachable code after a continue statement"


def test_unreachable_code_one_finding_per_list():
    src = (
        "from __future__ import annotations\n"
        "def f() -> None:\n"
        "    return\n"
        "    x = 1\n"
        "    y = 2\n"
    )
    findings = lint_text(src)
    unreachable = [f for f in findings if f.rule_id == "lint.unreachable-code"]
    assert len(unreachable) == 1
    assert unreachable[0].line == 4


def test_unreachable_code_false_positives():
    # Outer block code after a nested return is reachable
    src1 = (
        "from __future__ import annotations\n"
        "def f(c: bool) -> int:\n"
        "    if c:\n"
        "        return 1\n"
        "    x = 2\n"
        "    return x\n"
    )
    assert "lint.unreachable-code" not in _ids(lint_text(src1))

    # Terminator as the last statement of the block
    src2 = (
        "from __future__ import annotations\n"
        "def f() -> int:\n"
        "    return 1\n"
    )
    assert "lint.unreachable-code" not in _ids(lint_text(src2))

    # break/continue under if condition (code after the if block is reachable)
    src3 = (
        "from __future__ import annotations\n"
        "for i in range(10):\n"
        "    if i > 5:\n"
        "        break\n"
        "    z = 1\n"
    )
    assert "lint.unreachable-code" not in _ids(lint_text(src3))

    # A clean function
    src4 = (
        "from __future__ import annotations\n"
        "def f(x: int) -> int:\n"
        "    y = x + 1\n"
        "    return y\n"
    )
    assert "lint.unreachable-code" not in _ids(lint_text(src4))


def test_unreachable_code_pragma_suppressed():
    src = (
        "from __future__ import annotations\n"
        "def f() -> int:\n"
        "    return 1\n"
        "    x = 2  # rein:ignore lint.unreachable-code\n"
    )
    assert "lint.unreachable-code" not in _ids(lint_text(src))


# -- lint.commented-out-code --------------------------------------------------

def test_commented_out_code_function_flagged():
    src = (
        "# def f():\n"
        "#     return 1\n"
    )
    findings = lint_text(src)
    assert "lint.commented-out-code" in _ids(findings)
    commented = [f for f in findings if f.rule_id == "lint.commented-out-code"]
    assert len(commented) == 1
    assert commented[0].line == 1
    assert commented[0].message == "commented-out code block; delete it rather than commenting it out"


def test_commented_out_code_assignments_flagged():
    src = (
        "# x = 1\n"
        "# y = 2\n"
    )
    findings = lint_text(src)
    assert "lint.commented-out-code" in _ids(findings)


def test_commented_out_code_imports_flagged():
    src = (
        "# import os\n"
        "# import sys\n"
    )
    findings = lint_text(src)
    assert "lint.commented-out-code" in _ids(findings)


def test_commented_out_code_false_positives():
    # License header
    src1 = (
        "# Copyright 2026\n"
        "# All rights reserved\n"
    )
    assert "lint.commented-out-code" not in _ids(lint_text(src1))

    # Prose
    src2 = (
        "# This handles the legacy case.\n"
        "# Added in the 2019 migration.\n"
    )
    assert "lint.commented-out-code" not in _ids(lint_text(src2))

    # Single comment line (< 2 lines)
    src3 = "# x = 1\n"
    assert "lint.commented-out-code" not in _ids(lint_text(src3))

    # Pragma block / type ignores
    src4 = (
        "# type: ignore\n"
        "# noqa\n"
    )
    assert "lint.commented-out-code" not in _ids(lint_text(src4))

    # Bare names
    src5 = (
        "# foo\n"
        "# bar\n"
    )
    assert "lint.commented-out-code" not in _ids(lint_text(src5))

    # ASCII divider
    src6 = (
        "# ----\n"
        "# ----\n"
    )
    assert "lint.commented-out-code" not in _ids(lint_text(src6))

    # Shebang and coding directives
    src7 = (
        "#!/usr/bin/env python\n"
        "# -*- coding: utf-8 -*-\n"
    )
    assert "lint.commented-out-code" not in _ids(lint_text(src7))


def test_commented_out_code_lone_simple_statement_not_flagged():
    # Real Django FP (contrib/gis/gdal/geometries.py): a section header plus a
    # single illustrative assignment is documentation, not dead code. A lone
    # simple statement is too weak; require a compound stmt or >= 2 statements.
    src1 = (
        "# ### Geometry set-like operations ###\n"
        "# g = g1 | g2\n"
    )
    assert "lint.commented-out-code" not in _ids(lint_text(src1))

    src2 = (
        "# usage:\n"
        "# result = compute(x)\n"
    )
    assert "lint.commented-out-code" not in _ids(lint_text(src2))

    # But a compound statement (single block) is still strong evidence.
    src3 = (
        "# if ready:\n"
        "#     launch(x)\n"
    )
    assert "lint.commented-out-code" in _ids(lint_text(src3))


def test_commented_out_code_pragma_suppressed():
    src = (
        "# def f():  # rein:ignore lint.commented-out-code\n"
        "#     return 1\n"
    )
    assert "lint.commented-out-code" not in _ids(lint_text(src))

