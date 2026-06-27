"""Tests for the external-scanner runner module (rein.scanners).

The runners are mocked, so these exercise the registry and the content-mode
pipeline (write temp file -> run -> parse -> remap path) without needing the
real scanners installed.
"""

from __future__ import annotations

from rein.scanners import DETECTORS, run_detectors, scan_content

_BANDIT_JSON = """
{"results": [
  {"test_id": "B101", "filename": "tmp.py", "line_number": 2,
   "issue_severity": "LOW", "issue_text": "Use of assert detected."}
]}
"""


def test_known_detectors_registered():
    assert set(DETECTORS) == {"ruff", "bandit", "gitleaks", "semgrep"}


def test_run_detectors_unknown_tool_ignored():
    assert run_detectors(["."], ["nonexistent"]) == []


def test_run_detectors_empty_tools():
    assert run_detectors(["."], []) == []


def test_scan_content_no_tools_returns_empty():
    assert scan_content("import os\n", "a.py", tools=[]) == []


def test_scan_content_empty_text_returns_empty():
    assert scan_content("   \n", "a.py", tools=["bandit"]) == []


def test_scan_content_runs_scanner_and_remaps_path(monkeypatch):
    monkeypatch.setattr("rein.scanners._run_bandit", lambda targets: _BANDIT_JSON)
    findings = scan_content("def f():\n    assert x\n", "auth.py", tools=["bandit"])
    assert findings, "expected a bandit finding from the content scan"
    # The finding's temp path is mapped back to the logical path for the message.
    assert all(f.path == "auth.py" for f in findings)
    assert any(f.rule_id.startswith("bandit.") for f in findings)


def test_scan_content_passes_a_target_to_the_scanner(monkeypatch):
    seen = {}

    def fake(targets):
        seen["targets"] = targets
        return ""

    monkeypatch.setattr("rein.scanners._run_bandit", fake)
    scan_content("assert x\n", path=None, tools=["bandit"])
    # A temp directory is passed (directory-oriented scanners like gitleaks work).
    assert seen.get("targets") and seen["targets"][0]
