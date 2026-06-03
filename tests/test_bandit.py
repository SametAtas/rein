"""Tests for the pure bandit JSON parser."""

from __future__ import annotations

from rein.core.bandit import parse_bandit_output
from rein.core.findings import Severity


def test_parse_bandit_output_success() -> None:
    sample = '''
    {
      "results": [
        {
          "test_id": "B602",
          "filename": "vuln.py",
          "line_number": 10,
          "issue_severity": "HIGH",
          "issue_text": "subprocess call with shell=True"
        },
        {
          "test_id": "B101",
          "filename": "asserts.py",
          "line_number": 4,
          "issue_severity": "LOW",
          "issue_text": "Use of assert detected"
        }
      ]
    }
    '''
    findings = parse_bandit_output(sample)
    assert len(findings) == 2

    assert findings[0].rule_id == "bandit.B602"
    assert findings[0].path == "vuln.py"
    assert findings[0].line == 10
    assert findings[0].severity == Severity.HIGH
    assert "shell=True" in findings[0].message
    assert "bandit" in findings[0].tags
    assert "security" in findings[0].tags

    assert findings[1].rule_id == "bandit.B101"
    assert findings[1].severity == Severity.LOW


def test_parse_bandit_output_empty_or_bad() -> None:
    assert parse_bandit_output("") == []
    assert parse_bandit_output("   ") == []
    assert parse_bandit_output("{") == []
    assert parse_bandit_output("[]") == []
    assert parse_bandit_output('{"results": null}') == []
    assert parse_bandit_output('{"results": [123, "string"]}') == []


def test_parse_bandit_output_malformed_results() -> None:
    sample = '''
    {
      "results": [
        {"test_id": "B100", "filename": "x.py"},
        {"test_id": "B100", "line_number": 5},
        {"filename": "x.py", "line_number": 5}
      ]
    }
    '''
    # Missing line_number, filename, test_id respectively -> skip
    assert parse_bandit_output(sample) == []
