"""Tests for the SARIF 2.1.0 emitter.

The shape is validated by hand (no jsonschema) so core stays zero-dep, matching
the emitter it exercises. ``_assert_sarif_shape`` checks the structural
invariants every document must hold; individual tests then assert the
finding-specific mappings.
"""

from __future__ import annotations

import rein
from rein.core.findings import Finding, Severity
from rein.core.sarif import to_sarif


def _finding(
    rule_id: str = "lint.stub-body",
    severity: Severity = Severity.LOW,
    message: str = "Stub body.",
    path: str | None = "a.py",
    line: int | None = 5,
    snippet: str | None = "pass",
    tags: tuple[str, ...] = (),
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        message=message,
        path=path,
        line=line,
        snippet=snippet,
        tags=tags,
    )


def _assert_sarif_shape(doc: dict) -> None:
    """Validate the structural invariants of a SARIF 2.1.0 document.

    Pure-Python, no schema library: checks the envelope, the single run, the
    driver, and the core invariant that every result's ruleId resolves to a
    declared rule id.
    """
    assert doc["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    assert doc["version"] == "2.1.0"

    runs = doc["runs"]
    assert isinstance(runs, list) and len(runs) == 1
    run = runs[0]

    driver = run["tool"]["driver"]
    assert driver["name"] == "rein"
    assert isinstance(driver["version"], str)
    assert driver["informationUri"] == "https://github.com/SametAtas/rein"

    rule_ids = set()
    for rule in driver["rules"]:
        assert isinstance(rule["id"], str)
        rule_ids.add(rule["id"])
    # No duplicate rule descriptors.
    assert len(rule_ids) == len(driver["rules"])

    for result in run["results"]:
        assert isinstance(result["ruleId"], str)
        assert result["level"] in {"error", "warning", "note", "none"}
        assert isinstance(result["message"]["text"], str)
        # The load-bearing invariant: ruleId always resolves to a descriptor.
        assert result["ruleId"] in rule_ids


def test_empty_input_yields_valid_empty_run() -> None:
    doc = to_sarif([])
    _assert_sarif_shape(doc)
    run = doc["runs"][0]
    assert run["tool"]["driver"]["rules"] == []
    assert run["results"] == []


def test_version_matches_package() -> None:
    doc = to_sarif([_finding()])
    assert doc["runs"][0]["tool"]["driver"]["version"] == rein.__version__


def test_severity_maps_to_level() -> None:
    cases = {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
        Severity.INFO: "none",
    }
    for severity, expected in cases.items():
        doc = to_sarif([_finding(severity=severity)])
        _assert_sarif_shape(doc)
        assert doc["runs"][0]["results"][0]["level"] == expected


def test_full_location_includes_path_line_and_snippet() -> None:
    doc = to_sarif([_finding(path="a.py", line=5, snippet="pass")])
    _assert_sarif_shape(doc)
    physical = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert physical["artifactLocation"]["uri"] == "a.py"
    assert physical["region"]["startLine"] == 5
    assert physical["region"]["snippet"]["text"] == "pass"


def test_path_omitted_drops_locations() -> None:
    doc = to_sarif([_finding(path=None, line=5, snippet="pass")])
    _assert_sarif_shape(doc)
    assert "locations" not in doc["runs"][0]["results"][0]


def test_line_omitted_drops_region() -> None:
    doc = to_sarif([_finding(path="a.py", line=None, snippet="pass")])
    _assert_sarif_shape(doc)
    physical = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert physical["artifactLocation"]["uri"] == "a.py"
    assert "region" not in physical


def test_snippet_omitted_drops_snippet_only() -> None:
    doc = to_sarif([_finding(path="a.py", line=5, snippet=None)])
    _assert_sarif_shape(doc)
    region = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
    assert region["startLine"] == 5
    assert "snippet" not in region


def test_distinct_rules_deduplicated_first_seen() -> None:
    findings = [
        _finding(rule_id="b.rule", message="first b"),
        _finding(rule_id="a.rule", message="an a"),
        _finding(rule_id="b.rule", message="second b"),
    ]
    doc = to_sarif(findings)
    _assert_sarif_shape(doc)
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    assert [r["id"] for r in rules] == ["b.rule", "a.rule"]
    # Every result still emitted, even duplicates of the same rule.
    assert len(doc["runs"][0]["results"]) == 3


def test_tags_included_only_when_present() -> None:
    findings = [
        _finding(rule_id="tagged.rule", tags=("security", "owasp")),
        _finding(rule_id="plain.rule", tags=()),
    ]
    doc = to_sarif(findings)
    _assert_sarif_shape(doc)
    rules = {r["id"]: r for r in doc["runs"][0]["tool"]["driver"]["rules"]}
    assert rules["tagged.rule"]["properties"]["tags"] == ["security", "owasp"]
    assert "properties" not in rules["plain.rule"]


def test_rule_id_invariant_holds_across_mixed_findings() -> None:
    findings = [
        _finding(rule_id="x.one", severity=Severity.HIGH, path=None, line=None),
        _finding(rule_id="y.two", severity=Severity.INFO, path="b.py", line=3),
        _finding(rule_id="x.one", severity=Severity.HIGH),
    ]
    doc = to_sarif(findings)
    _assert_sarif_shape(doc)
