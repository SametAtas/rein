"""Tests for the pure gitleaks JSON parser."""

from __future__ import annotations

from rein.core.findings import Severity
from rein.core.gitleaks import parse_gitleaks_output


def test_parse_gitleaks_output_success() -> None:
    import json as std_json
    key = "AKIA" + "IOSFODNN7EXAMPLE"
    sample_data = [
      {
        "RuleID": "aws-access-key",
        "Description": "AWS Access Key",
        "File": "config.py",
        "StartLine": 12,
        "Match": key,
        "Secret": key
      },
      {
        "RuleID": "generic-api-key",
        "Description": "",
        "File": "main.py",
        "StartLine": 42
      }
    ]
    sample = std_json.dumps(sample_data)
    findings = parse_gitleaks_output(sample)
    assert len(findings) == 2

    assert findings[0].rule_id == "gitleaks.aws-access-key"
    assert findings[0].path == "config.py"
    assert findings[0].line == 12
    assert findings[0].severity == Severity.HIGH
    assert "AWS Access Key" in findings[0].message
    assert "gitleaks" in findings[0].tags
    assert "secret" in findings[0].tags
    # CRITICAL: raw secret must not be in the finding
    assert findings[0].snippet is None
    assert ("AKIA" + "IOSFODNN7EXAMPLE") not in repr(findings[0])
    assert ("AKIA" + "IOSFODNN7EXAMPLE") not in findings[0].message

    assert findings[1].rule_id == "gitleaks.generic-api-key"
    assert findings[1].path == "main.py"
    assert findings[1].line == 42
    assert findings[1].severity == Severity.HIGH
    assert "Possible secret" in findings[1].message
    assert findings[1].snippet is None


def test_parse_gitleaks_output_empty_or_bad() -> None:
    assert parse_gitleaks_output("") == []
    assert parse_gitleaks_output("   ") == []
    assert parse_gitleaks_output("{") == []
    assert parse_gitleaks_output("{}") == []
    assert parse_gitleaks_output("[123, \"string\"]") == []


def test_parse_gitleaks_output_malformed_results() -> None:
    sample = '''
    [
      {"RuleID": "aws-access-key"},
      {"File": "config.py"},
      {"RuleID": "aws-access-key", "File": "config.py"}
    ]
    '''
    # Missing File, missing RuleID, missing StartLine (falls back to 1)
    findings = parse_gitleaks_output(sample)
    assert len(findings) == 1
    assert findings[0].path == "config.py"
    assert findings[0].line == 1
