"""Parse output from the bandit security scanner.

This is a pure parsing adapter. It takes bandit's JSON output and turns it
into rein Findings. It does no I/O.
"""

from __future__ import annotations

import json

from .findings import Finding, Severity

_SEVERITY_MAP = {
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
}


def parse_bandit_output(json_text: str) -> list[Finding]:
    """Parse bandit -f json output into a list of Findings.

    Tolerates bad JSON or empty input by returning an empty list.
    """
    if not json_text or not json_text.strip():
        return []

    try:
        data = json.loads(json_text)
    except json.JSONDecodeError:
        return []

    if not isinstance(data, dict):
        return []

    results = data.get("results")
    if not isinstance(results, list):
        return []

    findings = []
    for item in results:
        if not isinstance(item, dict):
            continue
        test_id = item.get("test_id")
        filename = item.get("filename")
        line_number = item.get("line_number")

        if not test_id or not filename or line_number is None:
            continue

        issue_text = item.get("issue_text", "")
        sev_str = str(item.get("issue_severity", "")).lower()
        severity = _SEVERITY_MAP.get(sev_str, Severity.LOW)

        findings.append(
            Finding(
                rule_id=f"bandit.{test_id}",
                severity=severity,
                message=issue_text,
                path=filename,
                line=line_number,
                snippet=None,
                tags=("security", "bandit"),
            )
        )
    return findings
