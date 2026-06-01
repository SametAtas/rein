"""The code domain: runs code guardrails (secrets, lint, security) over source.

This encapsulates the code-specific logic so the review engine can run it
as a generic Domain.
"""

from __future__ import annotations

import ast

from .findings import Finding
from .lint import lint_text
from .secrets import scan_text
from .security import scan_security


def _safe_parse(text: str) -> ast.Module | None:
    try:
        return ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return None


def _python_findings(text: str, path: str | None) -> list[Finding]:
    """Lint + security over text, parsing the AST exactly once on the happy path."""
    tree = _safe_parse(text)
    if tree is None:
        return lint_text(text, path)  # rare error path: lint reports it; security no-ops
    return lint_text(text, path, tree=tree) + scan_security(text, path, tree=tree)


def code_domain(text: str, path: str | None = None) -> list[Finding]:
    """Run all code guardrails over text.

    Always runs the secret scanner. If the path implies Python (or is None),
    also runs lint and security checks, parsing the AST at most once.
    """
    findings = list(scan_text(text, path))
    if path is None or path.endswith(".py"):
        findings.extend(_python_findings(text, path))
    return findings
