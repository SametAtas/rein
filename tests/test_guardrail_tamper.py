"""Tests for config-tamper detection."""

from rein.core.commits import check_guardrail_changes, check_commit
from rein.core.findings import Severity
from rein.hooks.precommit import evaluate


def test_flags_guardrail_files():
    paths = [
        ".rein.toml",
        "pkg/.rein.toml",
        ".rein-baseline.json",
        ".githooks/pre-commit",
        ".rein-profile.toml",
        "pkg/.rein-profile.toml",
    ]
    findings = check_guardrail_changes(paths)
    assert len(findings) == 6
    for f in findings:
        assert f.rule_id == "commit.guardrail-modified"
        assert f.severity == Severity.HIGH


def test_ignores_safe_files():
    paths = [
        "src/app.py",
        "README.md",
        "config.toml",
        "rein.toml",
        "baseline.json",
    ]
    findings = check_guardrail_changes(paths)
    assert len(findings) == 0


def test_check_commit_includes_guardrail_findings():
    # Modified guardrail file
    findings = check_commit("feat: update config", [".rein.toml"])
    assert len(findings) == 1
    assert findings[0].rule_id == "commit.guardrail-modified"

    # Clean commit
    findings = check_commit("feat: update app", ["src/app.py"])
    assert len(findings) == 0


def test_evaluate_flags_staged_guardrail():
    staged_files = {".rein.toml": "fail_at = 'high'"}
    findings = evaluate(staged_files, "feat: lower threshold")

    guardrail_findings = [f for f in findings if f.rule_id == "commit.guardrail-modified"]
    assert len(guardrail_findings) == 1
    assert guardrail_findings[0].severity == Severity.HIGH
