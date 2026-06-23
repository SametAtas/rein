"""Custom regex rules defined in configuration."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .findings import Finding, Severity
from .pragmas import filter_by_pragma


@dataclass(frozen=True)
class CustomRule:
    id: str
    pattern: re.Pattern[str]
    severity: Severity
    message: str


def build_custom_rules(items: list[Any]) -> tuple[CustomRule, ...]:
    """Parse custom rule dictionaries from config into CustomRule objects."""
    rules = []
    for item in items:
        if not isinstance(item, dict):
            raise ValueError("Each custom rule must be a dictionary")

        rule_id = item.get("id")
        if not rule_id or not isinstance(rule_id, str):
            raise ValueError("Custom rule must have a string 'id'")

        pattern_str = item.get("pattern")
        if not pattern_str or not isinstance(pattern_str, str):
            raise ValueError(f"Custom rule '{rule_id}' must have a string 'pattern'")

        try:
            pattern = re.compile(pattern_str)
        except re.error as e:
            raise ValueError(f"Custom rule '{rule_id}' has invalid pattern '{pattern_str}': {e}") from e

        severity_str = item.get("severity", "MEDIUM")
        if not isinstance(severity_str, str):
            raise ValueError(f"Custom rule '{rule_id}' has invalid severity type")

        try:
            severity = Severity[severity_str.upper()]
        except KeyError:
            raise ValueError(f"Unknown severity for custom rule '{rule_id}': '{severity_str}'")

        message = item.get("message", f"Custom rule '{rule_id}' matched")
        if not isinstance(message, str):
            raise ValueError(f"Custom rule '{rule_id}' message must be a string")

        rules.append(CustomRule(rule_id, pattern, severity, message))

    return tuple(rules)


def scan_custom(text: str, path: str | None, rules: tuple[CustomRule, ...]) -> list[Finding]:
    """Scan text against custom rules, returning findings line by line."""
    if not text or not rules:
        return []

    findings = []
    for i, line in enumerate(text.splitlines(), start=1):
        line_findings = []
        for rule in rules:
            if rule.pattern.search(line):
                line_findings.append(
                    Finding(
                        rule_id=f"custom.{rule.id}",
                        severity=rule.severity,
                        message=rule.message,
                        path=path,
                        line=i,
                        snippet=line.strip()[:80],
                        tags=("custom",),
                    )
                )
        findings.extend(filter_by_pragma(line_findings, line))

    return findings
