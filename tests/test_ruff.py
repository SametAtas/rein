"""Tests for ruff output parsing."""

from rein.core.ruff import parse_ruff_output


def test_parse_ruff_output_sample():
    sample = '''[
      {
        "code": "F401",
        "message": "os imported but unused",
        "location": {"row": 12},
        "filename": "src/app.py"
      },
      {
        "code": "E501",
        "message": "line too long",
        "location": {"row": 24},
        "filename": "src/app.py"
      }
    ]'''
    findings = parse_ruff_output(sample)
    assert len(findings) == 2
    assert findings[0].rule_id == "ruff.F401"
    assert findings[0].path == "src/app.py"
    assert findings[0].line == 12
    assert findings[0].message == "os imported but unused"
    assert "ruff" in findings[0].tags
    assert findings[1].rule_id == "ruff.E501"


def test_parse_ruff_output_empty():
    assert parse_ruff_output("[]") == []
    assert parse_ruff_output("") == []
    assert parse_ruff_output("   ") == []


def test_parse_ruff_output_malformed_items():
    # Tolerates missing fields or non-dict items
    sample = '''[
      "not a dict",
      {"code": "E1"},
      {"location": {"row": 1}},
      {"code": "E2", "location": {"row": 2}}
    ]'''
    findings = parse_ruff_output(sample)
    assert len(findings) == 1
    assert findings[0].rule_id == "ruff.E2"
