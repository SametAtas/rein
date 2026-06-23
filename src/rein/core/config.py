"""Configuration logic for rein.

Pure parsing and validation of settings, decoupled from file I/O.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .custom import CustomRule, build_custom_rules
from .findings import Finding, Severity
from .review import DEFAULT_POLICY, Policy

KNOWN_DETECTORS = frozenset({"ruff", "bandit", "gitleaks", "semgrep"})


@dataclass(frozen=True)
class Config:
    """The full resolved configuration."""

    policy: Policy
    disabled: frozenset[str] = field(default_factory=frozenset)
    detectors: frozenset[str] = field(default_factory=frozenset)
    custom_rules: tuple[CustomRule, ...] = field(default_factory=tuple)


DEFAULT_CONFIG = Config(DEFAULT_POLICY, frozenset(), frozenset(), tuple())


def _parse_severity(name: str) -> Severity:
    try:
        return Severity[name.upper()]
    except KeyError:
        raise ValueError(f"Unknown severity: '{name}'")


def _parse_policy(data: dict) -> Policy:
    policy_data = data.get("policy", {})
    if not isinstance(policy_data, dict):
        raise ValueError("policy section must be a dictionary")

    fail_at = DEFAULT_POLICY.fail_at
    warn_at = DEFAULT_POLICY.warn_at

    if "fail_at" in policy_data:
        fail_at = _parse_severity(policy_data["fail_at"])
    if "warn_at" in policy_data:
        warn_at = _parse_severity(policy_data["warn_at"])

    cat_data = policy_data.get("category_fail_at", {})
    if not isinstance(cat_data, dict):
        raise ValueError("policy.category_fail_at must be a dictionary")

    valid_categories = {"secret", "lint", "security", "commit", "ruff"}
    category_fail_at = {}
    for cat, sev_name in cat_data.items():
        if cat not in valid_categories:
            raise ValueError(f"Unknown category: '{cat}'")
        category_fail_at[cat] = _parse_severity(sev_name)

    return Policy(fail_at=fail_at, warn_at=warn_at, category_fail_at=category_fail_at)


def _parse_disabled(data: dict) -> frozenset[str]:
    rules_data = data.get("rules", {})
    if not isinstance(rules_data, dict):
        raise ValueError("rules section must be a dictionary")

    disabled_list = rules_data.get("disabled", [])
    if not isinstance(disabled_list, list):
        raise ValueError("rules.disabled must be a list of strings")

    return frozenset(str(x) for x in disabled_list)


def _parse_detectors(data: dict) -> frozenset[str]:
    detectors_data = data.get("detectors", {})
    if not isinstance(detectors_data, dict):
        raise ValueError("detectors section must be a dictionary")

    detectors_set = frozenset(k for k, v in detectors_data.items() if v)
    unknown = detectors_set - KNOWN_DETECTORS
    if unknown:
        raise ValueError(f"Unknown detector: '{sorted(unknown)[0]}'")
    return detectors_set


def config_from_dict(data: dict) -> Config:
    """Build a Config from a dictionary (e.g. parsed from TOML).

    Raises:
        ValueError: if a severity name or category is unknown, or if structure is malformed.
    """
    rules_data = data.get("rules", {})
    custom_rules_data = rules_data.get("custom", []) if isinstance(rules_data, dict) else []
    if not isinstance(custom_rules_data, list):
        raise ValueError("rules.custom must be a list of dictionaries")

    return Config(
        policy=_parse_policy(data),
        disabled=_parse_disabled(data),
        detectors=_parse_detectors(data),
        custom_rules=build_custom_rules(custom_rules_data),
    )


def apply_disabled(findings: list[Finding], disabled: frozenset[str]) -> list[Finding]:
    """Filter out any findings whose rule_id is in the disabled set."""
    if not disabled:
        return list(findings)
    return [f for f in findings if f.rule_id not in disabled]
