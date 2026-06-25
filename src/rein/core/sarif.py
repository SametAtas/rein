"""SARIF 2.1.0 emitter: render findings as a Static Analysis Results format doc.

SARIF is the interchange format GitHub code scanning and other tools consume, so
emitting it lets ``rein``'s findings surface natively in those UIs. This module
is pure: it maps a list of :class:`Finding` to a plain ``dict`` and never touches
the filesystem, the network, or any third-party library. Core stays zero-dep, so
the document is built by hand rather than via a SARIF SDK.
"""

from __future__ import annotations

from .findings import Finding, Severity

#: Maps each severity onto its SARIF result level. SARIF has no "critical", so
#: CRITICAL collapses onto "error" alongside HIGH.
_LEVEL_BY_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "none",
}

_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_INFORMATION_URI = "https://github.com/SametAtas/rein"


def _rules(findings: list[Finding]) -> list[dict]:
    """One rule descriptor per distinct rule_id, in first-seen order.

    ``properties.tags`` is included only when the first finding for that rule
    carries tags, so untagged rules stay free of empty noise.
    """
    rules: list[dict] = []
    seen: set[str] = set()
    for finding in findings:
        if finding.rule_id in seen:
            continue
        seen.add(finding.rule_id)
        rule: dict = {"id": finding.rule_id}
        if finding.tags:
            rule["properties"] = {"tags": list(finding.tags)}
        rules.append(rule)
    return rules


def _result(finding: Finding) -> dict:
    """One SARIF result for a finding.

    A ``locations`` entry is added only when the finding has a path; within it a
    ``region`` appears only with a line, and a snippet only when present. The
    ``ruleId`` always equals the finding's rule_id, which guarantees it resolves
    to a descriptor produced by :func:`_rules`.
    """
    result: dict = {
        "ruleId": finding.rule_id,
        "level": _LEVEL_BY_SEVERITY[finding.severity],
        "message": {"text": finding.message},
    }
    if finding.path:
        physical: dict = {"artifactLocation": {"uri": finding.path}}
        if finding.line is not None:
            region: dict = {"startLine": finding.line}
            if finding.snippet is not None:
                region["snippet"] = {"text": finding.snippet}
            physical["region"] = region
        result["locations"] = [{"physicalLocation": physical}]
    return result


def to_sarif(findings: list[Finding]) -> dict:
    """Build a SARIF 2.1.0 document from ``findings``.

    The document always has exactly one run. Empty input yields a valid run with
    no rules and no results. Every ``result.ruleId`` resolves to some
    ``runs[0].tool.driver.rules[].id``, since both derive from the same rule_ids.
    """
    from .. import __version__

    driver = {
        "name": "rein",
        "version": __version__,
        "informationUri": _INFORMATION_URI,
        "rules": _rules(findings),
    }
    return {
        "$schema": _SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": driver},
                "results": [_result(f) for f in findings],
            }
        ],
    }
