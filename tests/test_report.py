"""Unit tests for the report rendering layer."""

from __future__ import annotations

import json

from rein.core.findings import Finding, Severity
from rein.core.review import ReviewResult, Verdict
from rein.report import (
    emit,
    emit_report,
    render_json,
    report_exit_code,
    worst_exit_code,
)


def _resolves(doc):
    """Every result.ruleId must resolve to a declared rules[].id."""
    run = doc["runs"][0]
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    for result in run["results"]:
        assert result["ruleId"] in rule_ids


def test_render_json_non_empty(capsys):
    findings = [
        Finding(
            rule_id="test.rule",
            severity=Severity.HIGH,
            message="Test message.",
            path="src/app.py",
            line=10,
        )
    ]
    render_json(findings)
    captured = capsys.readouterr()

    parsed = json.loads(captured.out)
    assert isinstance(parsed, list)
    assert len(parsed) == 1
    assert parsed[0]["rule_id"] == "test.rule"
    assert parsed[0]["severity"] == "HIGH"


def test_render_json_empty(capsys):
    render_json([])
    captured = capsys.readouterr()
    assert captured.out.strip() == "[]"

    parsed = json.loads(captured.out)
    assert parsed == []


def test_emit_json_mode(capsys):
    findings = [Finding("test.rule", Severity.LOW, "test")]
    emit(findings, "json")
    captured = capsys.readouterr()

    parsed = json.loads(captured.out)
    assert len(parsed) == 1
    assert parsed[0]["rule_id"] == "test.rule"


def test_emit_text_mode_default(capsys):
    findings = [Finding("test.rule", Severity.LOW, "test")]
    emit(findings)
    captured = capsys.readouterr()

    assert "test.rule" in captured.out
    # Not JSON
    try:
        json.loads(captured.out)
        assert False, "Should not be valid JSON"
    except json.JSONDecodeError:
        pass


def test_emit_empty_json(capsys):
    emit([], "json")
    captured = capsys.readouterr()

    assert "no issues found" not in captured.out
    parsed = json.loads(captured.out)
    assert parsed == []


def test_emit_sarif_mode(capsys):
    findings = [
        Finding("test.rule", Severity.HIGH, "Test message.", "src/app.py", 10),
    ]
    emit(findings, "sarif")
    captured = capsys.readouterr()

    doc = json.loads(captured.out)
    assert doc["version"] == "2.1.0"
    runs = doc["runs"]
    assert len(runs) == 1
    _resolves(doc)
    # The known finding's rule_id surfaces in both a result and a rule.
    rule_ids = {r["id"] for r in runs[0]["tool"]["driver"]["rules"]}
    assert "test.rule" in rule_ids
    assert runs[0]["results"][0]["ruleId"] == "test.rule"


def test_emit_report_sarif_mode(capsys):
    findings = [
        Finding("test.rule", Severity.HIGH, "Test message.", "src/app.py", 10),
    ]
    result = ReviewResult(findings, Verdict.BLOCK)
    emit_report(result, "sarif")
    captured = capsys.readouterr()

    doc = json.loads(captured.out)
    assert doc["version"] == "2.1.0"
    assert len(doc["runs"]) == 1
    _resolves(doc)
    # SARIF is findings-only: no verdict leaks into the document.
    assert "verdict" not in json.dumps(doc).lower()
    assert doc["runs"][0]["results"][0]["ruleId"] == "test.rule"


def test_emit_report_sarif_ignores_explain(capsys):
    """--explain must not change the SARIF document (no fix guidance leaks in)."""
    findings = [Finding("test.rule", Severity.HIGH, "Test message.", "src/app.py", 10)]
    result = ReviewResult(findings, Verdict.BLOCK)

    emit_report(result, "sarif", explain=False)
    plain = capsys.readouterr().out
    emit_report(result, "sarif", explain=True)
    explained = capsys.readouterr().out

    assert plain == explained


def test_sarif_does_not_change_exit_codes():
    """SARIF is findings-only; the exit-code helpers ignore format entirely."""
    findings = [
        Finding("test.rule", Severity.HIGH, "Test message.", "src/app.py", 10),
    ]
    # worst_exit_code takes findings, not a format -- same value every time.
    assert worst_exit_code(findings) == 1
    assert worst_exit_code([]) == 0

    blocked = ReviewResult(findings, Verdict.BLOCK)
    passed = ReviewResult(findings, Verdict.PASS)
    assert report_exit_code(blocked) == 1
    assert report_exit_code(passed) == 0
