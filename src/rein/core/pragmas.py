"""Inline ignore-pragma parsing, shared by every scanner.

A ``# rein:ignore`` comment on a source line suppresses findings on that line.
A bare pragma suppresses everything; a scoped pragma (``rein:ignore id1, id2``)
suppresses only the listed rule ids. This module is used by both the secret
scanner and the linter so the behavior is consistent everywhere.
"""

from __future__ import annotations

from .findings import Finding

IGNORE_TOKEN = "rein:ignore"


def parse_ignore_pragma(line: str) -> set[str] | None:
    """Return the set of rule ids suppressed on *line*, or ``None`` if absent.

    An empty set means "suppress all" (bare pragma). A non-empty set lists
    the specific rule ids to suppress.
    """
    idx = line.find(IGNORE_TOKEN)
    if idx == -1:
        return None
    tail = line[idx + len(IGNORE_TOKEN):].strip()
    if not tail:
        return set()
    return {r.strip() for r in tail.split(",") if r.strip()}


def filter_by_pragma(line_findings: list[Finding], line: str) -> list[Finding]:
    """Drop findings on *line* according to its pragma, if any.

    No pragma: return all findings unchanged.
    Bare pragma: return [].
    Scoped pragma: drop findings whose rule_id appears in the pragma list.
    """
    suppressed = parse_ignore_pragma(line)
    if suppressed is None:
        return line_findings
    if not suppressed:
        return []
    return [f for f in line_findings if f.rule_id not in suppressed]
