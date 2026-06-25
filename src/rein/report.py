"""Shared rendering and exit-code logic for adapters.

The CLI, the git hook, and any future adapter all turn a list of ``Finding``
objects into readable output and a process exit code. That presentation logic
lives here, in one place, so the adapters stay thin and behave the same way.

This code prints, so it is an adapter concern and does not belong in ``core``.
"""

from __future__ import annotations

import json

from .core.findings import Finding, Severity, max_severity
from .core.remediation import suggest_fix
from .core.review import ReviewResult, Verdict
from .core.sarif import to_sarif

# At or above this severity, a run is considered a failure (non-zero exit).
DEFAULT_FAIL_AT = Severity.HIGH


def _color(severity: Severity) -> str:
    if severity is Severity.HIGH:
        return "\033[91m"  # red
    if severity is Severity.MEDIUM:
        return "\033[93m"  # yellow
    if severity is Severity.LOW:
        return "\033[94m"  # blue
    return "\033[0m"       # default


def _reset() -> str:
    return "\033[0m"


def worst_exit_code(findings: list[Finding], fail_at: Severity = DEFAULT_FAIL_AT) -> int:
    """Return 1 if any finding is >= fail_at, else 0."""
    top = max_severity(findings)
    return 1 if top is not None and top >= fail_at else 0


def render(findings: list[Finding]) -> None:
    """Human-readable text output with severity-colored prefixes."""
    if not findings:
        print("rein: no issues found.")
        return

    for f in findings:
        sev = f.severity.name.ljust(8)
        prefix = f"{_color(f.severity)}[{sev}]{_reset()}"
        print(f"{prefix} {f.rule_id.ljust(32)} {f.location()}")
        if f.message:
            print(f"           {f.message}")
        if f.snippet:
            print(f"           {f.snippet}")

    print(f"\n{len(findings)} finding(s).")


def render_json(findings: list[Finding]) -> None:
    """Machine-readable JSON output (list of dicts)."""
    print(json.dumps([f.to_dict() for f in findings], indent=2))


def emit(findings: list[Finding], fmt: str = "text") -> None:
    """Render findings in the chosen format: "text" (default), "json", or "sarif".

    "sarif" is findings-only and carries no verdict; it never affects exit codes.
    """
    if fmt == "json":
        render_json(findings)
    elif fmt == "sarif":
        print(json.dumps(to_sarif(findings), indent=2))
    else:
        render(findings)


def render_report(result: ReviewResult, explain: bool = False) -> None:
    """Human-readable: the findings, then the overall verdict."""
    render(result.findings)
    print(f"\nVerdict: {result.verdict}")
    if explain and result.findings:
        print("\nSuggested fixes:")
        for f in result.findings:
            fix = suggest_fix(f)
            if fix is None:
                continue
            print(f"  [{f.rule_id}] {f.location()}: {fix.guidance}")
            if fix.safe_example is not None:
                print(f"      e.g. {fix.safe_example}")


def _report_dict(result: ReviewResult, explain: bool) -> dict:
    d = result.to_dict()
    if not explain:
        return d
    for f_dict, finding in zip(d["findings"], result.findings):
        fix = suggest_fix(finding)
        f_dict["fix"] = (
            {"guidance": fix.guidance, "safe_example": fix.safe_example}
            if fix is not None else None
        )
    return d


def emit_report(result: ReviewResult, fmt: str = "text", explain: bool = False) -> None:
    if fmt == "json":
        print(json.dumps(_report_dict(result, explain), indent=2))
    elif fmt == "sarif":
        # SARIF is findings-only: no verdict in the document, and --explain is
        # ignored. The verdict still gates the process via report_exit_code.
        print(json.dumps(to_sarif(result.findings), indent=2))
    else:
        render_report(result, explain)


def report_exit_code(result: ReviewResult) -> int:
    """Only a BLOCK verdict fails the process."""
    return 1 if result.verdict is Verdict.BLOCK else 0
