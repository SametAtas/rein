"""Integration tests for the CLI --format flag."""

from __future__ import annotations

import json

from rein.cli.__main__ import main

AWS = "AKIAIOSFODNN7EXAMPLE"  # rein:ignore


def test_scan_format_json_with_finding(tmp_path, capsys):
    f = tmp_path / "config.py"
    f.write_text(f'aws = "{AWS}"\n')

    exit_code = main(["scan", "--format", "json", str(f)])
    assert exit_code == 1

    captured = capsys.readouterr()
    parsed = json.loads(captured.out)
    assert len(parsed) == 1
    assert parsed[0]["rule_id"] == "secret.aws-access-key"


def test_scan_format_json_clean(tmp_path, capsys):
    f = tmp_path / "clean.py"
    f.write_text("x = 1\n")

    exit_code = main(["scan", "--format", "json", str(f)])
    assert exit_code == 0

    captured = capsys.readouterr()
    assert captured.out.strip() == "[]"
    parsed = json.loads(captured.out)
    assert parsed == []


def test_lint_format_json(tmp_path, capsys):
    f = tmp_path / "bad.py"
    f.write_text("def foo():\n    pass\n")

    exit_code = main(["lint", "--format", "json", str(f)])
    # missing-type-hints is LOW, default fail_at is HIGH, so exit code should be 0
    assert exit_code == 0

    captured = capsys.readouterr()
    parsed = json.loads(captured.out)

    rule_ids = {p["rule_id"] for p in parsed}
    assert "lint.missing-type-hints" in rule_ids
    assert "lint.stub-body" in rule_ids


def test_commit_check_format_json(capsys):
    exit_code = main(["commit-check", "--format", "json", "-m", "WIP: do a thing"])

    # WIP is MEDIUM, exit code 0
    assert exit_code == 0

    captured = capsys.readouterr()
    parsed = json.loads(captured.out)
    rule_ids = {p["rule_id"] for p in parsed}
    assert "commit.wip-marker" in rule_ids


def test_scan_format_sarif_with_finding(tmp_path, capsys):
    f = tmp_path / "config.py"
    f.write_text(f'aws = "{AWS}"\n')

    exit_code = main(["scan", "--format", "sarif", str(f)])
    # SARIF is findings-only and never changes the exit code: still gated by
    # the finding's severity, exactly as the json/text paths are.
    assert exit_code == 1

    captured = capsys.readouterr()
    doc = json.loads(captured.out)
    assert doc["version"] == "2.1.0"
    assert len(doc["runs"]) == 1

    run = doc["runs"][0]
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    for result in run["results"]:
        assert result["ruleId"] in rule_ids
    assert "secret.aws-access-key" in rule_ids


def test_scan_format_sarif_clean(tmp_path, capsys):
    f = tmp_path / "clean.py"
    f.write_text("x = 1\n")

    exit_code = main(["scan", "--format", "sarif", str(f)])
    assert exit_code == 0

    captured = capsys.readouterr()
    doc = json.loads(captured.out)
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"] == []


def test_scan_text_remains_default(tmp_path, capsys):
    f = tmp_path / "clean.py"
    f.write_text("x = 1\n")

    exit_code = main(["scan", str(f)])
    assert exit_code == 0

    captured = capsys.readouterr()
    assert "no issues found" in captured.out

    try:
        json.loads(captured.out)
        assert False, "Output should not be valid JSON"
    except json.JSONDecodeError:
        pass
