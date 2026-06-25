"""Parse ruff check JSON output into Finding objects.

Separated from the core lint module because it wraps an external tool's format,
a distinct concern from our own AST analysis.
"""

from __future__ import annotations

import json

from .findings import Finding, Severity


def parse_ruff_output(json_text: str) -> list[Finding]:
    """Parse ruff check --output-format=json output into Findings."""
    if not json_text or not json_text.strip():
        return []

    try:
        items = json.loads(json_text)
    except json.JSONDecodeError:
        return []

    findings: list[Finding] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        code = item.get("code")
        loc = item.get("location")
        if not code or not isinstance(loc, dict) or "row" not in loc:
            continue

        findings.append(Finding(
            rule_id=f"ruff.{code}",
            severity=Severity.LOW,
            message=item.get("message", ""),
            path=item.get("filename"),
            line=loc["row"],
            tags=("lint", "ruff"),
        ))
    return findings
