"""Tests for junk file detection (Phase 29)."""

from rein.core.commits import check_commit
from rein.core.findings import Severity
from rein.core.junk import scan_junk_paths
from rein.hooks.precommit import evaluate
from rein.report import worst_exit_code


def test_scan_junk_paths_flags_representatives():
    paths = [
        ".DS_Store",
        "src/__pycache__/m.pyc",
        "pkg/app.py~",
        "notes.bak",
        "data_copy.py",
        "temp.py",
        "foo.js",
    ]
    findings = scan_junk_paths(paths)
    assert len(findings) == 7

    # OS Cruft
    assert findings[0].rule_id == "junk.os-cruft"
    assert findings[0].severity == Severity.MEDIUM
    assert findings[1].rule_id == "junk.os-cruft"
    assert findings[1].severity == Severity.MEDIUM

    # Backup
    assert findings[2].rule_id == "junk.backup-file"
    assert findings[2].severity == Severity.MEDIUM
    assert findings[3].rule_id == "junk.backup-file"
    assert findings[3].severity == Severity.MEDIUM
    assert findings[4].rule_id == "junk.backup-file"
    assert findings[4].severity == Severity.MEDIUM

    # Scratch
    assert findings[5].rule_id == "junk.scratch-file"
    assert findings[5].severity == Severity.LOW
    assert findings[6].rule_id == "junk.scratch-file"
    assert findings[6].severity == Severity.LOW


def test_scan_junk_paths_non_blocking_proof():
    paths = [".DS_Store", "notes.bak", "foo.js"]
    findings = scan_junk_paths(paths)
    # worst_exit_code should be 0 because highest severity is MEDIUM
    assert worst_exit_code(findings) == 0


def test_scan_junk_paths_low_fp_basket():
    paths = [
        "__init__.py",
        "conftest.py",
        "test_app.py",
        "app_test.py",
        "setup.py",
        "README.md",
        "CHANGELOG.md",
        "index.js",
        "main.py",
        "models/v2.py",
        "temperature.py",
        "api/users.py",
        "foobar.py",
    ]
    findings = scan_junk_paths(paths)
    assert len(findings) == 0


def test_at_most_one_finding_per_path():
    # .DS_Store matches OS-cruft, but stem is .DS_Store which might not trigger scratch,
    # let's try something that matches both: temp.bak
    # Matches both backup (.bak) and scratch (temp)
    paths = ["temp.bak"]
    findings = scan_junk_paths(paths)
    assert len(findings) == 1
    # First matched is backup (or OS cruft, depending on order)
    assert findings[0].rule_id == "junk.backup-file"


def test_integration_check_commit():
    findings = check_commit("feat: x", [".DS_Store"])
    junk_findings = [f for f in findings if f.rule_id == "junk.os-cruft"]
    assert len(junk_findings) == 1


def test_integration_evaluate():
    staged_files = {".DS_Store": ""}
    findings = evaluate(staged_files, "feat: x")
    junk_findings = [f for f in findings if f.rule_id == "junk.os-cruft"]
    assert len(junk_findings) == 1
