"""Integration tests for the review command with .rein.toml configuration."""

import json

from rein.cli.__main__ import main


def test_cmd_review_with_valid_config(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)

    # Create a config that blocks on LOW lint and ignores todo-comment
    config_text = """
    [policy.category_fail_at]
    lint = "low"

    [rules]
    disabled = ["lint.todo-comment"]
    """
    (tmp_path / ".rein.toml").write_text(config_text, encoding="utf-8")

    # Create a file with a TODO (should be ignored) and a missing type hint (LOW lint)
    test_file = tmp_path / "test_file.py"
    test_file.write_text(
        "def func():\n"
        "    pass  # TODO: implement\n",
        encoding="utf-8",
    )

    # Normally this would be PASS (no HIGH findings), but category_fail_at makes LOW lint a BLOCK
    rc = main(["review", "--format", "json", "."])
    assert rc != 0

    out = capsys.readouterr().out
    data = json.loads(out)

    assert data["verdict"] == "BLOCK"

    rule_ids = {f["rule_id"] for f in data["findings"]}
    assert "lint.missing-type-hints" in rule_ids
    assert "lint.todo-comment" not in rule_ids


def test_cmd_review_with_invalid_config(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)

    config_text = """
    [policy]
    fail_at = "not-a-severity"
    """
    (tmp_path / ".rein.toml").write_text(config_text, encoding="utf-8")

    rc = main(["review", "."])
    assert rc == 1  # Hard failure on bad config

    err = capsys.readouterr().err
    assert "rein: config error in '.rein.toml'" in err
    assert "Unknown severity" in err


def test_cmd_review_explicit_missing_config(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)

    rc = main(["review", "--config", "missing.toml", "."])
    assert rc == 1  # Hard failure on missing explicit config

    err = capsys.readouterr().err
    assert "rein: could not find config 'missing.toml'" in err


def test_cmd_review_malformed_toml(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)

    config_text = """
    [policy
    broken
    """
    (tmp_path / ".rein.toml").write_text(config_text, encoding="utf-8")

    rc = main(["review", "."])
    assert rc == 1

    err = capsys.readouterr().err
    assert "rein: config error in '.rein.toml'" in err


def test_cmd_review_with_detectors(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)

    config_text = """
    [detectors]
    bandit = true
    """
    (tmp_path / ".rein.toml").write_text(config_text, encoding="utf-8")

    test_file = tmp_path / "test_file.py"
    test_file.write_text("print('hello')\n", encoding="utf-8")

    def mock_run_bandit(targets):
        return '''
        {
          "results": [
            {
              "test_id": "B602",
              "filename": "test_file.py",
              "line_number": 1,
              "issue_severity": "HIGH",
              "issue_text": "mock bandit finding"
            }
          ]
        }
        '''
    monkeypatch.setattr("rein.scanners._run_bandit", mock_run_bandit)

    rc = main(["review", "--format", "json", "."])
    assert rc == 1

    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["verdict"] == "BLOCK"

    rule_ids = {f["rule_id"] for f in data["findings"]}
    assert "bandit.B602" in rule_ids


def test_cmd_review_with_semgrep(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".rein.toml").write_text("[detectors]\nsemgrep = true\n")

    def mock_run_semgrep(targets):
        return '''
        {
          "results": [
            {
              "check_id": "mock-check",
              "path": "test_file.py",
              "start": {"line": 1},
              "extra": {
                "message": "mock semgrep finding",
                "severity": "ERROR"
              }
            }
          ]
        }
        '''
    monkeypatch.setattr("rein.scanners._run_semgrep", mock_run_semgrep)

    rc = main(["review", "--format", "json", "."])
    assert rc == 1

    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["verdict"] == "BLOCK"

    rule_ids = {f["rule_id"] for f in data["findings"]}
    assert "semgrep.mock-check" in rule_ids


def test_cmd_review_with_custom_rule(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    toml_content = """
    [[rules.custom]]
    id = "no-print"
    pattern = "\\\\bprint\\\\("
    severity = "high"
    """
    (tmp_path / ".rein.toml").write_text(toml_content)
    (tmp_path / "app.py").write_text("def foo():\\n    print('hello')\\n")

    rc = main(["review", "--format", "json", "."])
    assert rc == 1

    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["verdict"] == "BLOCK"

    rule_ids = {f["rule_id"] for f in data["findings"]}
    assert "custom.no-print" in rule_ids
