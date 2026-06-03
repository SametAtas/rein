"""Tests for remediation guidance."""

from __future__ import annotations

from rein.core.findings import Finding, Severity
from rein.core.remediation import Remediation, suggest_fix


def _finding(rule_id: str) -> Finding:
    return Finding(rule_id, Severity.HIGH, "msg", None, None, None, ())


def test_suggest_fix_exact_match_with_example() -> None:
    fix = suggest_fix(_finding("security.weak-hash"))
    assert isinstance(fix, Remediation)
    assert "SHA-256" in fix.guidance
    assert fix.safe_example == "hashlib.sha256(data)"


def test_suggest_fix_exact_match_no_example() -> None:
    fix = suggest_fix(_finding("commit.empty"))
    assert isinstance(fix, Remediation)
    assert "non-empty" in fix.guidance
    assert fix.safe_example is None


def test_suggest_fix_category_fallback() -> None:
    fix = suggest_fix(_finding("secret.aws-access-key"))
    assert isinstance(fix, Remediation)
    assert "environment" in fix.guidance
    assert "os.environ" in str(fix.safe_example)

    fix2 = suggest_fix(_finding("ruff.F401"))
    assert isinstance(fix2, Remediation)
    assert "ruff rule documentation" in fix2.guidance


def test_suggest_fix_unknown_returns_none() -> None:
    assert suggest_fix(_finding("totally.unknown")) is None
