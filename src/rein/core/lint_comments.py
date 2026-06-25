"""Check for commented-out code."""

from __future__ import annotations

import ast
import io
import re
import tokenize

from .findings import Finding, Severity

_EXEMPT_RE = re.compile(r"\b(noqa|type:|pragma:|pylint:|pyright:|mypy:|fmt:|isort:|rein" + r":ignore|TODO|FIXME|XXX|HACK|NOTE)(?!\w)", re.IGNORECASE)  # rein:ignore lint.todo-comment


def _is_block_exempt(block: list[int], comments: dict[int, str]) -> bool:
    """True if any comment in the block contains a directive/shebang exemption."""
    for lineno in block:
        comment_str = comments[lineno]
        comment_content = comment_str.lstrip()
        if comment_content.startswith("#!"):
            return True
        if "-*- coding" in comment_str.lower():
            return True
        if _EXEMPT_RE.search(comment_str):
            return True
    return False


def _decomment_block(block: list[int], comments: dict[int, str]) -> str:
    """De-comment each line in the block by stripping the leading '#' and at most one space."""
    lines_to_parse = []
    for lineno in block:
        comment = comments[lineno]
        s = comment[1:]
        if s.startswith(" "):
            s = s[1:]
        lines_to_parse.append(s)
    return "\n".join(lines_to_parse)


_COMPOUND_STMTS = (
    ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.If,
    ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith, ast.Try,
)
_SIMPLE_STMTS = (
    ast.Assign, ast.AnnAssign, ast.AugAssign, ast.Return, ast.Raise,
    ast.Assert, ast.Delete, ast.Import, ast.ImportFrom, ast.Global, ast.Nonlocal,
)


def _is_real_code_block(joined: str) -> bool:
    """True if the de-commented block parses as Python and is strong evidence of
    commented-out code: a COMPOUND statement (def/class/control-flow), or >= 2
    SIMPLE statements. A lone simple statement is too weak - a doc comment like
    ``# g = g1 | g2`` illustrating usage is not dead code (Django GIS, real FP)."""
    try:
        tree = ast.parse(joined)
    except Exception:
        return False

    simple = 0
    for s in tree.body:
        if isinstance(s, _COMPOUND_STMTS):
            return True
        if isinstance(s, _SIMPLE_STMTS) or (
            isinstance(s, ast.Expr) and isinstance(s.value, ast.Call)
        ):
            simple += 1
    return simple >= 2


def _check_commented_code(text: str, path: str | None) -> list[Finding]:
    """Scan the text for commented-out Python code blocks."""
    findings: list[Finding] = []
    comments: dict[int, str] = {}
    try:
        tokens = tokenize.generate_tokens(io.StringIO(text).readline)
        for t in tokens:
            if t.type == tokenize.COMMENT and t.line[:t.start[1]].strip() == "":
                comments[t.start[0]] = t.string
    except Exception:
        return []

    if not comments:
        return []

    sorted_lines = sorted(comments.keys())
    blocks: list[list[int]] = []
    current_block: list[int] = []
    for line in sorted_lines:
        if not current_block or line == current_block[-1] + 1:
            current_block.append(line)
        else:
            blocks.append(current_block)
            current_block = [line]
    if current_block:
        blocks.append(current_block)

    for block in [b for b in blocks if len(b) >= 2]:
        if _is_block_exempt(block, comments):
            continue
        joined = _decomment_block(block, comments)
        if _is_real_code_block(joined):
            msg = "commented-out code block; delete it rather than commenting it out"
            findings.append(Finding("lint.commented-out-code", Severity.LOW, msg, path, block[0], None, ("lint",)))

    return findings
