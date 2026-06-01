"""Pure tool functions exposed by the MCP server.

These translate between simple, JSON-friendly arguments and the rein.core checks,
returning lists of plain dicts (``Finding.to_dict()``). They import only
``core``, never the MCP SDK, so they stay unit-testable without a running server.
The SDK wiring lives in ``server.py``; keep these functions free of it.
"""

from __future__ import annotations

from ..core import commits, custom, lint, secrets, security
from ..core.code import code_domain
from ..core.config import DEFAULT_CONFIG, apply_disabled, config_from_dict
from ..core.findings import Finding
from ..core.remediation import suggest_fix
from ..core.review import ReviewResult, review as _review
from ..core.review import review_diff_findings


def scan_secrets(text: str, path: str | None = None) -> list[dict]:
    """Scan a blob of text for leaked secrets.

    Returns a list of finding dicts (``Finding.to_dict()``), empty when clean.
    Honors inline ``rein:ignore`` pragmas, since it calls the same core scanner.
    """
    return [f.to_dict() for f in secrets.scan_text(text, path=path)]


def check_commit(message: str, changed_files: list[str] | None = None) -> list[dict]:
    """Check a commit message and an optional list of changed file paths.

    Returns a list of finding dicts (``Finding.to_dict()``), empty when clean.
    """
    return [f.to_dict() for f in commits.check_commit(message, changed_files)]


def lint_code(text: str, path: str | None = None) -> list[dict]:
    """Run pure AST and line-based lint rules over a blob of Python source.

    Returns a list of finding dicts (``Finding.to_dict()``), empty when clean.
    Honors inline ``rein:ignore`` pragmas.
    """
    return [f.to_dict() for f in lint.lint_text(text, path)]


def scan_diff(diff_text: str) -> list[dict]:
    """Scan only the added lines in a unified diff for leaked secrets.

    Returns a list of finding dicts (``Finding.to_dict()``), empty when clean.
    Honors inline ``rein:ignore`` pragmas on added lines.
    """
    return [f.to_dict() for f in secrets.scan_diff(diff_text)]


def check_security(text: str, path: str | None = None) -> list[dict]:
    """Flag unsafe-code patterns in a blob of Python source.

    Returns a list of finding dicts (``Finding.to_dict()``), empty when clean.
    Honors inline ``rein:ignore`` pragmas.
    """
    return [f.to_dict() for f in security.scan_security(text, path)]


def review_code(text: str, path: str | None = None, config: dict | None = None) -> dict:
    """Run all guardrails and return a structured ReviewResult dict."""
    cfg = config_from_dict(config) if config else DEFAULT_CONFIG
    findings = _review(text, path).findings
    findings.extend(custom.scan_custom(text, path, cfg.custom_rules))
    findings = apply_disabled(findings, cfg.disabled)
    return ReviewResult.from_findings(findings, cfg.policy).to_dict()


def review_diff(new_text: str, diff_text: str, path: str | None = None, config: dict | None = None) -> dict:
    """Review only the lines a diff adds (for an agent checking its own patch)."""
    cfg = config_from_dict(config) if config else DEFAULT_CONFIG

    def custom_domain(t: str, p_: str | None) -> list[Finding]:
        return code_domain(t, p_) + custom.scan_custom(t, p_, cfg.custom_rules)

    findings = review_diff_findings(new_text, diff_text, path, domain=custom_domain)
    findings = apply_disabled(findings, cfg.disabled)
    return ReviewResult.from_findings(findings, cfg.policy).to_dict()


def suggest_fixes(text: str, path: str | None = None) -> list[dict]:
    """Review an artifact and return each finding with its remediation guidance.

    Built for agent self-correction: call review, then attach a fix per finding
    (guidance/safe_example are null when no remediation is known).
    """
    result = _review(text, path)
    items: list[dict] = []
    for f in result.findings:
        fix = suggest_fix(f)
        item = f.to_dict()
        item["fix"] = (
            {"guidance": fix.guidance, "safe_example": fix.safe_example}
            if fix is not None else None
        )
        items.append(item)
    return items
