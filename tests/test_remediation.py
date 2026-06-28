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


def test_secret_guidance_steers_to_safe_pattern() -> None:
    # Every secret.* rule falls through to the category entry, so one check
    # covers the family. The guidance must steer to referencing the value by
    # name and supplying it out-of-band, not merely name the problem.
    for rule_id in ("secret.aws-access-key", "secret.high-entropy-assignment", "secret.github-token"):
        fix = suggest_fix(_finding(rule_id))
        assert isinstance(fix, Remediation)
        assert "out-of-band" in fix.guidance
        assert "os.environ['NAME']" in fix.guidance
        assert "secret manager" in fix.guidance


def test_secret_guidance_does_not_overclaim_runtime_isolation() -> None:
    # Honesty: rein is shift-left, code-time. The steering must not claim it
    # keeps secrets out of the model's traffic/context at runtime.
    fix = suggest_fix(_finding("secret.aws-access-key"))
    assert isinstance(fix, Remediation)
    low = fix.guidance.lower()
    for forbidden in ("runtime", "egress", "traffic", "proxy", "intercept"):
        assert forbidden not in low


def test_suggest_fix_unknown_returns_none() -> None:
    assert suggest_fix(_finding("totally.unknown")) is None
