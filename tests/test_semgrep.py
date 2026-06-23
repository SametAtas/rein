"""Tests for the semgrep parser."""

from rein.core.findings import Severity
from rein.core.semgrep import parse_semgrep_output


def test_parse_semgrep_output():
    json_text = """
    {
        "results": [
            {
                "check_id": "python.lang.security.audit.exec-used",
                "path": "app.py",
                "start": {"line": 10},
                "extra": {
                    "message": "Found call to exec()",
                    "severity": "ERROR"
                }
            },
            {
                "check_id": "python.lang.security.audit.eval-used",
                "path": "app.py",
                "start": {"line": 15},
                "extra": {
                    "message": "Found call to eval()",
                    "severity": "WARNING"
                }
            },
            {
                "check_id": "python.lang.security.info",
                "path": "app.py",
                "start": {"line": 20},
                "extra": {
                    "message": "Info message",
                    "severity": "INFO"
                }
            }
        ]
    }
    """
    findings = parse_semgrep_output(json_text)
    assert len(findings) == 3

    assert findings[0].rule_id == "semgrep.python.lang.security.audit.exec-used"
    assert findings[0].path == "app.py"
    assert findings[0].line == 10
    assert findings[0].severity == Severity.HIGH
    assert findings[0].message == "Found call to exec()"
    assert findings[0].tags == ("semgrep",)

    assert findings[1].severity == Severity.MEDIUM
    assert findings[2].severity == Severity.LOW


def test_parse_semgrep_output_malformed():
    assert parse_semgrep_output("") == []
    assert parse_semgrep_output("not json") == []
    assert parse_semgrep_output("{}") == []
    assert parse_semgrep_output('{"results": null}') == []
    assert parse_semgrep_output('{"results": ["not a dict"]}') == []

    # Missing check_id, path, or line should be skipped
    json_text = """
    {
        "results": [
            {"path": "app.py", "start": {"line": 10}},
            {"check_id": "id", "start": {"line": 10}},
            {"check_id": "id", "path": "app.py"}
        ]
    }
    """
    assert parse_semgrep_output(json_text) == []
