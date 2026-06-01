"""Clean-code lint checks over Python source.

Pure functions using only the stdlib ``ast`` module. No I/O, no subprocess,
no third-party dependencies. Each rule returns ``Finding`` objects tagged
``("lint",)`` and honors ``rein:ignore`` pragmas via ``filter_by_pragma``.
"""

from __future__ import annotations

import ast
import re

from .findings import Finding, Severity
from .lint_comments import _check_commented_code
from .pragmas import filter_by_pragma

_TODO_RE = re.compile(r"\b(TODO|FIXME|XXX)\b", re.IGNORECASE)  # rein:ignore lint.todo-comment

_MAX_FUNCTION_LINES = 50
_MAX_FILE_LINES = 250


def _lint_finding(
    rid: str, sev: Severity, msg: str, path: str | None, line: int | None, snip: str | None = None
) -> Finding:
    return Finding(rid, sev, msg, path, line, snip, ("lint",))


_UNPARSED = object()


def _parse_or_record(
    text: str, path: str | None, lines: list[str], findings: list[Finding]
) -> ast.Module | None:
    """Parse text, or append a syntax-error finding and return None on failure.

    Catches the full family of parse failures so hostile input degrades
    gracefully instead of crashing.
    """
    try:
        return ast.parse(text)
    except (SyntaxError, ValueError, RecursionError) as exc:
        line = exc.lineno if isinstance(exc, SyntaxError) else None
        message = f"Syntax error: {exc.msg}" if isinstance(exc, SyntaxError) else "Could not parse file."
        finding = _lint_finding("lint.syntax-error", Severity.MEDIUM, message, path, line)
        if line is not None and line <= len(lines):
            findings.extend(filter_by_pragma([finding], lines[line - 1]))
        else:
            findings.append(finding)
        return None


def _has_future_annotations(tree: ast.Module) -> bool:
    for node in ast.iter_child_nodes(tree):
        if (
            isinstance(node, ast.ImportFrom)
            and node.module == "__future__"
            and any(a.name == "annotations" for a in node.names)
        ):
            return True
    return False


def _has_functions_or_classes(tree: ast.Module) -> bool:
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return True
    return False


def _is_stub_body(body: list[ast.stmt]) -> bool:
    """True if the body is just pass, ..., or raise NotImplementedError.

    A leading docstring is ignored, so a documented stub still counts.
    """
    real = [
        s for s in body
        if not (
            isinstance(s, ast.Expr)
            and isinstance(s.value, ast.Constant)
            and isinstance(s.value.value, str)
        )
    ]
    if len(real) != 1:
        return False

    stmt = real[0]
    if isinstance(stmt, ast.Pass):
        return True
    if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant) and stmt.value.value is ...:
        return True
    if isinstance(stmt, ast.Raise) and stmt.exc is not None:
        if isinstance(stmt.exc, ast.Call) and isinstance(stmt.exc.func, ast.Name):
            if stmt.exc.func.id == "NotImplementedError":
                return True
        if isinstance(stmt.exc, ast.Name) and stmt.exc.id == "NotImplementedError":
            return True
    return False


def _missing_type_hints(
    node: ast.FunctionDef | ast.AsyncFunctionDef, path: str | None
) -> Finding | None:
    if node.name.startswith("_"):
        return None
    missing = False
    if node.returns is None:
        missing = True
    for arg in node.args.args:
        if arg.arg in ("self", "cls"):
            continue
        if arg.annotation is None:
            missing = True
    if missing:
        msg = f"Public function '{node.name}' is missing type annotations."
        return _lint_finding("lint.missing-type-hints", Severity.LOW, msg, path, node.lineno)
    return None


def _function_too_long(
    node: ast.FunctionDef | ast.AsyncFunctionDef, path: str | None
) -> Finding | None:
    if node.end_lineno is not None and node.end_lineno - node.lineno > _MAX_FUNCTION_LINES:
        msg = f"Function '{node.name}' is {node.end_lineno - node.lineno} lines long (limit: {_MAX_FUNCTION_LINES})."
        return _lint_finding("lint.function-too-long", Severity.LOW, msg, path, node.lineno)
    return None


def _stub_body_finding(
    node: ast.FunctionDef | ast.AsyncFunctionDef, path: str | None
) -> Finding | None:
    if _is_stub_body(node.body):
        msg = f"Function '{node.name}' has a stub body (pass/.../raise NotImplementedError)."
        return _lint_finding("lint.stub-body", Severity.LOW, msg, path, node.lineno)
    return None


def _check_ast_rules(tree: ast.Module, path: str | None) -> list[Finding]:
    """Run all AST-based rules over a parsed module."""
    findings: list[Finding] = []

    if _has_functions_or_classes(tree) and not _has_future_annotations(tree):
        msg = "Module defines functions or classes but lacks 'from __future__ import annotations'."
        findings.append(_lint_finding("lint.missing-future-import", Severity.INFO, msg, path, 1))

    for node in ast.walk(tree):
        for field in ("body", "orelse", "finalbody"):
            stmts = getattr(node, field, None)
            if not isinstance(stmts, list):
                continue
            for i, s in enumerate(stmts):
                if isinstance(s, (ast.Return, ast.Raise, ast.Break, ast.Continue)) and i < len(stmts) - 1:
                    kind = s.__class__.__name__.lower()
                    next_stmt = stmts[i + 1]
                    msg = f"unreachable code after a {kind} statement"
                    findings.append(_lint_finding("lint.unreachable-code", Severity.LOW, msg, path, next_stmt.lineno))
                    break

        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        for finding in (
            _missing_type_hints(node, path),
            _function_too_long(node, path),
            _stub_body_finding(node, path),
        ):
            if finding is not None:
                findings.append(finding)

    return findings


def _check_line_rules(lines: list[str], path: str | None) -> list[Finding]:
    """Run line-based rules (todo-comment, non-ascii) with pragma filtering."""  # rein:ignore lint.todo-comment
    findings: list[Finding] = []
    for lineno, line in enumerate(lines, start=1):
        line_findings: list[Finding] = []

        if _TODO_RE.search(line):
            msg = "Line contains a TODO/FIXME/XXX marker."  # rein:ignore lint.todo-comment
            line_findings.append(_lint_finding("lint.todo-comment", Severity.LOW, msg, path, lineno, line.strip()[:80]))  # rein:ignore lint.todo-comment

        try:
            line.encode("ascii")
        except UnicodeEncodeError:
            msg = "Line contains non-ASCII characters."
            line_findings.append(_lint_finding("lint.non-ascii", Severity.LOW, msg, path, lineno, line.strip()[:80]))

        if line != line.rstrip():
            msg = "Line has trailing whitespace."
            line_findings.append(_lint_finding("lint.trailing-whitespace", Severity.LOW, msg, path, lineno, line.strip()[:80]))

        findings.extend(filter_by_pragma(line_findings, line))

    return findings


def lint_text(text: str, path: str | None = None, *, tree: object = _UNPARSED) -> list[Finding]:
    """Run all lint rules. If *tree* is provided (already parsed), reuse it
    instead of parsing again - lets review() parse the source only once."""
    findings: list[Finding] = []
    lines = text.splitlines()
    if len(lines) > _MAX_FILE_LINES:
        msg = f"File is {len(lines)} lines long (limit: {_MAX_FILE_LINES})."
        findings.append(_lint_finding("lint.file-too-long", Severity.INFO, msg, path, None))
    if tree is _UNPARSED:
        tree = _parse_or_record(text, path, lines, findings)
    if tree is not None:
        for f in _check_ast_rules(tree, path):
            if f.line is not None and f.line <= len(lines):
                findings.extend(filter_by_pragma([f], lines[f.line - 1]))
            else:
                findings.append(f)

    # commented-out code check (uses tokenize, no new parse of main tree)
    for f in _check_commented_code(text, path):
        if f.line is not None and f.line <= len(lines):
            findings.extend(filter_by_pragma([f], lines[f.line - 1]))
        else:
            findings.append(f)

    findings.extend(_check_line_rules(lines, path))
    return findings


def lint_file(path: str) -> list[Finding]:
    """Lint a single Python file, skipping binaries gracefully."""
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    except (UnicodeDecodeError, OSError):
        return []
    return lint_text(text, path=path)
