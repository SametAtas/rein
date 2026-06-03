"""Shared result types used by every check.

Every check in :mod:`rein.core` returns a list of :class:`Finding`. The CLI,
the MCP server, and the git hook are thin adapters that render these objects.
One result type means a check is written once and every adapter can render it.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    """Ordered so callers can filter with ``>=`` and pick an exit code."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:  # nicer rendering in CLI output
        return self.name


@dataclass(frozen=True)
class Finding:
    """One issue discovered by a check.

    Attributes:
        rule_id: Stable identifier for the rule, e.g. ``"secret.aws-access-key"``.
        severity: How serious the issue is.
        message: Human-readable explanation.
        path: File the finding relates to, if any.
        line: 1-based line number within ``path``, if known.
        snippet: A short, **already-redacted** excerpt for context.
    """

    rule_id: str
    severity: Severity
    message: str
    path: str | None = None
    line: int | None = None
    snippet: str | None = None
    tags: tuple[str, ...] = field(default_factory=tuple)

    def location(self) -> str:
        if self.path and self.line:
            return f"{self.path}:{self.line}"
        if self.path:
            return self.path
        return "-"

    def to_dict(self) -> dict:
        """JSON-friendly form, also reused by the MCP adapter later."""
        return {
            "rule_id": self.rule_id,
            "severity": str(self.severity),
            "message": self.message,
            "path": self.path,
            "line": self.line,
            "snippet": self.snippet,
            "tags": list(self.tags),
        }


# A domain takes text and an optional path, and returns a list of Findings.
Domain = Callable[[str, str | None], list[Finding]]


def max_severity(findings: list[Finding]) -> Severity | None:
    """Highest severity in a list, or ``None`` when the list is empty."""
    if not findings:
        return None
    return max(f.severity for f in findings)
