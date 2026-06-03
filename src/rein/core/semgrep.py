"""Parser for semgrep JSON output."""

from __future__ import annotations

import json
import logging

from .findings import Finding, Severity

log = logging.getLogger(__name__)


def _parse_item(item: dict) -> Finding | None:
    if not isinstance(item, dict):
        return None

    check_id = item.get("check_id")
    path = item.get("path")
    start = item.get("start", {})

    if not isinstance(start, dict):
        return None

    line = start.get("line")

    if not check_id or not path or line is None:
        return None

    extra = item.get("extra", {})
    if not isinstance(extra, dict):
        extra = {}

    message = extra.get("message", "semgrep issue")
    raw_severity = extra.get("severity", "").upper()

    if raw_severity == "ERROR":
        severity = Severity.HIGH
    elif raw_severity == "INFO":
        severity = Severity.LOW
    else:
        severity = Severity.MEDIUM

    return Finding(
        rule_id=f"semgrep.{check_id}",
        severity=severity,
        message=str(message),
        path=str(path),
        line=int(line),
        tags=("semgrep",),
    )


def parse_semgrep_output(json_text: str) -> list[Finding]:
    """Parse semgrep JSON output into a list of Findings.

    Tolerates malformed JSON or unexpected structure by returning [] or skipping
    malformed entries.

    Severity mapping (from semgrep extra.severity):
    - ERROR -> HIGH
    - WARNING -> MEDIUM
    - INFO -> LOW
    - (default or missing) -> MEDIUM
    """
    if not json_text or not json_text.strip():
        return []

    try:
        data = json.loads(json_text)
    except json.JSONDecodeError:
        log.debug("semgrep output is not valid JSON")
        return []

    if not isinstance(data, dict):
        return []

    results = data.get("results")
    if not isinstance(results, list):
        return []

    findings = []
    for item in results:
        finding = _parse_item(item)
        if finding:
            findings.append(finding)

    return findings
