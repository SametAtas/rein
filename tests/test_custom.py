"""Tests for custom regex rules."""

import pytest
import re

from rein.core.custom import CustomRule, build_custom_rules, scan_custom
from rein.core.findings import Severity


def test_build_custom_rules_valid():
    items = [
        {
            "id": "no-print",
            "pattern": "\\bprint\\(",
            "severity": "low",
            "message": "Avoid print() in production code"
        }
    ]
    rules = build_custom_rules(items)
    assert len(rules) == 1
    assert rules[0].id == "no-print"
    assert rules[0].pattern.pattern == "\\bprint\\("
    assert rules[0].severity == Severity.LOW
    assert rules[0].message == "Avoid print() in production code"


def test_build_custom_rules_default_severity_and_message():
    items = [{"id": "foo", "pattern": "bar"}]
    rules = build_custom_rules(items)
    assert len(rules) == 1
    assert rules[0].severity == Severity.MEDIUM
    assert rules[0].message == "Custom rule 'foo' matched"


def test_build_custom_rules_invalid():
    with pytest.raises(ValueError, match="must be a dictionary"):
        build_custom_rules(["not-a-dict"])

    with pytest.raises(ValueError, match="must have a string 'id'"):
        build_custom_rules([{"pattern": "foo"}])

    with pytest.raises(ValueError, match="must have a string 'pattern'"):
        build_custom_rules([{"id": "foo"}])

    with pytest.raises(ValueError, match="invalid pattern"):
        build_custom_rules([{"id": "foo", "pattern": "[unterminated"}])

    with pytest.raises(ValueError, match="Unknown severity"):
        build_custom_rules([{"id": "foo", "pattern": "bar", "severity": "invalid"}])


def test_scan_custom():
    rules = (
        CustomRule("no-print", re.compile(r"\bprint\("), Severity.LOW, "No print()"),
    )
    text = "def foo():\n    print('hello')\n    return 42\n"
    findings = scan_custom(text, "foo.py", rules)

    assert len(findings) == 1
    assert findings[0].rule_id == "custom.no-print"
    assert findings[0].line == 2
    assert findings[0].severity == Severity.LOW
    assert findings[0].message == "No print()"
    assert findings[0].tags == ("custom",)
    assert findings[0].path == "foo.py"


def test_scan_custom_ignores_pragma():
    rules = (
        CustomRule("no-print", re.compile(r"\bprint\("), Severity.LOW, "No print()"),
    )
    text = "def foo():\n    print('hello')  # rein:ignore custom.no-print\n    return 42\n"
    findings = scan_custom(text, "foo.py", rules)

    assert len(findings) == 0
