"""Tests for the shared safe-parse helper."""

from __future__ import annotations

import ast

from rein.core.parsing import safe_parse


def test_valid_source_returns_module() -> None:
    tree = safe_parse("x = 1\n")
    assert isinstance(tree, ast.Module)


def test_syntax_error_returns_none() -> None:
    assert safe_parse("def (\n") is None


def test_null_byte_returns_none() -> None:
    # A null byte makes ast.parse raise ValueError, not SyntaxError.
    assert safe_parse("x = 1\x00\n") is None
