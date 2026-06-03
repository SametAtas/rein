"""Parse output from the gitleaks secret scanner.

This is a pure parsing adapter. It takes gitleaks's JSON output and turns it
into rein Findings. It redacts all raw secrets by design.
"""

from __future__ import annotations

import json

from .findings import Finding, Severity


def parse_gitleaks_output(json_text: str) -> list[Finding]:
    """Parse gitleaks --report-format json output into a list of Findings.

    Tolerates bad JSON or empty input by returning an empty list.
    """
    if not json_text or not json_text.strip():
        return []

    try:
        data = json.loads(json_text)
    except json.JSONDecodeError:
        return []

    if not isinstance(data, list):
        return []

    findings = []
    for item in data:
        if not isinstance(item, dict):
            continue

        rule_id = item.get("RuleID")
        filename = item.get("File")

        if not rule_id or not filename:
            continue

        line_number = item.get("StartLine")
        if line_number is None:
            # Fallback if somehow missing
            line_number = 1

        description = item.get("Description", "")
        if not description:
            description = f"Possible secret ({rule_id})"

        findings.append(
            Finding(
                rule_id=f"gitleaks.{rule_id}",
                severity=Severity.HIGH,
                message=description,
                path=filename,
                line=line_number,
                snippet=None,  # NEVER leak the secret itself
                tags=("secret", "gitleaks"),
            )
        )
    return findings
