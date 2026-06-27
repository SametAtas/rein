"""Convention primitives and shared logic."""

from __future__ import annotations

import ast
import fnmatch
import re
from typing import Callable

from .findings import Finding
from .paths import normalize_path
from .profile import ConventionEntry


_STYLE_MATCHERS: dict[str, Callable[[str], bool]] = {
    "snake_case": lambda n: not any(c.isupper() for c in n),
    "camelCase": lambda n: re.fullmatch(r"[a-z][a-zA-Z0-9]*", n) is not None,
    "PascalCase": lambda n: re.fullmatch(r"_?[A-Z][a-zA-Z0-9]*", n) is not None,
    "UPPER_CASE": lambda n: re.fullmatch(r"[A-Z][A-Z0-9]*(_[A-Z0-9]+)*", n) is not None,
}


def _convention_finding(
    entry: ConventionEntry,
    path: str | None,
    line: int | None,
    message: str,
    snippet: str | None = None,
) -> Finding:
    return Finding(
        rule_id=f"convention.{entry.id}",
        severity=entry.severity,
        message=message,
        path=path,
        line=line,
        snippet=snippet,
        tags=("convention",),
    )


_BROAD_TEST_PATTERNS = ("test_*.py", "*_test.py")


def _looks_like_test_name(basename: str) -> bool:
    return any(fnmatch.fnmatchcase(basename, p) for p in _BROAD_TEST_PATTERNS)


def _has_test_function(tree: ast.AST) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name == "test" or node.name.startswith("test_"):
                return True
    return False


def _in_directory(path: str, directory: str) -> bool:
    norm = normalize_path(directory.strip("/"))
    p = normalize_path(path)
    return ("/" + p).find("/" + norm + "/") != -1


def _path_in_scope(path: str | None, paths: list[str] | None) -> bool:
    if paths is None:
        return True
    if path is None:
        return False
    p = normalize_path(path)
    return any(fnmatch.fnmatchcase(p, g) for g in paths)


def _dotted_under(module: str, prefix: str) -> bool:
    """True if module matches prefix, or is a submodule under prefix."""
    return module == prefix or module.startswith(prefix + ".")
