"""Tests for configuration logic."""

import pytest

from rein.core.config import DEFAULT_CONFIG, apply_disabled, config_from_dict
from rein.core.findings import Finding, Severity


def test_default_config():
    assert DEFAULT_CONFIG.policy.fail_at == Severity.HIGH
    assert DEFAULT_CONFIG.policy.warn_at == Severity.LOW
    assert not DEFAULT_CONFIG.policy.category_fail_at
    assert not DEFAULT_CONFIG.disabled


def test_config_from_dict_empty():
    conf = config_from_dict({})
    assert conf == DEFAULT_CONFIG


def test_config_from_dict_full():
    data = {
        "policy": {
            "fail_at": "critical",
            "warn_at": "info",
            "category_fail_at": {
                "lint": "low",
                "secret": "CRITICAL"
            }
        },
        "rules": {
            "disabled": ["lint.todo-comment", "secret.jwt"]
        }
    }
    conf = config_from_dict(data)
    assert conf.policy.fail_at == Severity.CRITICAL
    assert conf.policy.warn_at == Severity.INFO
    assert conf.policy.category_fail_at["lint"] == Severity.LOW
    assert conf.policy.category_fail_at["secret"] == Severity.CRITICAL
    assert "lint.todo-comment" in conf.disabled
    assert "secret.jwt" in conf.disabled


def test_config_from_dict_case_insensitive_severity():
    data = {"policy": {"fail_at": "MeDiUm"}}
    conf = config_from_dict(data)
    assert conf.policy.fail_at == Severity.MEDIUM


def test_config_from_dict_invalid_severity():
    with pytest.raises(ValueError, match="Unknown severity: 'blocker'"):
        config_from_dict({"policy": {"fail_at": "blocker"}})


def test_config_from_dict_invalid_category():
    with pytest.raises(ValueError, match="Unknown category: 'formatting'"):
        config_from_dict({"policy": {"category_fail_at": {"formatting": "low"}}})


def test_config_from_dict_invalid_types():
    with pytest.raises(ValueError, match="policy section must be a dictionary"):
        config_from_dict({"policy": "not-a-dict"})

    with pytest.raises(ValueError, match="policy.category_fail_at must be a dictionary"):
        config_from_dict({"policy": {"category_fail_at": "not-a-dict"}})

    with pytest.raises(ValueError, match="rules section must be a dictionary"):
        config_from_dict({"rules": "not-a-dict"})

    with pytest.raises(ValueError, match="rules.disabled must be a list of strings"):
        config_from_dict({"rules": {"disabled": "not-a-list"}})


def test_apply_disabled():
    findings = [
        Finding("lint.todo-comment", Severity.LOW, "TODO found"),
        Finding("secret.jwt", Severity.CRITICAL, "JWT found"),
        Finding("security.eval-exec", Severity.HIGH, "eval used"),
    ]

    disabled = frozenset(["lint.todo-comment", "secret.jwt"])
    filtered = apply_disabled(findings, disabled)

    assert len(filtered) == 1
    assert filtered[0].rule_id == "security.eval-exec"


def test_apply_disabled_empty():
    findings = [
        Finding("security.eval-exec", Severity.HIGH, "eval used"),
    ]
    assert apply_disabled(findings, frozenset()) == findings


def test_config_detectors_parsing():
    data = {"detectors": {"bandit": True, "ruff": False, "semgrep": True}}
    conf = config_from_dict(data)
    assert conf.detectors == frozenset({"bandit", "semgrep"})


def test_config_detectors_invalid_name():
    with pytest.raises(ValueError, match="Unknown detector: 'unknown-tool'"):
        config_from_dict({"detectors": {"unknown-tool": True}})


def test_config_detectors_invalid_type():
    with pytest.raises(ValueError, match="detectors section must be a dictionary"):
        config_from_dict({"detectors": ["bandit"]})


def test_config_custom_rules_parsing():
    data = {
        "rules": {
            "custom": [
                {
                    "id": "no-print",
                    "pattern": "\\bprint\\(",
                    "severity": "low",
                    "message": "no prints"
                }
            ]
        }
    }
    conf = config_from_dict(data)
    assert len(conf.custom_rules) == 1
    assert conf.custom_rules[0].id == "no-print"
    assert conf.custom_rules[0].severity == Severity.LOW
