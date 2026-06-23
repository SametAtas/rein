"""Integration tests for the rein review CLI subcommand."""

from __future__ import annotations

import json

from rein.cli.__main__ import main


def test_review_cli_high_blocks(tmp_path, capsys) -> None:
    f = tmp_path / "bad.py"
    f.write_text('import os\nos.system("ls")\n')
    exit_code = main(["review", str(f)])
    assert exit_code == 1
    captured = capsys.readouterr()
    assert "Verdict: BLOCK" in captured.out


def test_review_cli_high_json(tmp_path, capsys) -> None:
    f = tmp_path / "bad.py"
    f.write_text('import os\nos.system("ls")\n')
    exit_code = main(["review", "--format", "json", str(f)])
    assert exit_code == 1
    parsed = json.loads(capsys.readouterr().out)
    assert parsed["verdict"] == "BLOCK"
    assert len(parsed["findings"]) >= 1


def test_review_cli_clean_passes(tmp_path, capsys) -> None:
    f = tmp_path / "clean.py"
    f.write_text("x = 1\n")
    exit_code = main(["review", str(f)])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "Verdict: PASS" in captured.out


def test_review_cli_explain_text(tmp_path, capsys) -> None:
    f = tmp_path / "bad.py"
    f.write_text('import os\nos.system("ls")\n')
    exit_code = main(["review", "--explain", str(f)])
    assert exit_code == 1
    out = capsys.readouterr().out
    assert "Suggested fixes:" in out
    assert "Use subprocess with a list and shell=False" in out


def test_review_cli_explain_json(tmp_path, capsys) -> None:
    f = tmp_path / "bad.py"
    f.write_text('import os\nos.system("ls")\n')
    exit_code = main(["review", "--explain", "--format", "json", str(f)])
    assert exit_code == 1
    parsed = json.loads(capsys.readouterr().out)
    assert parsed["verdict"] == "BLOCK"
    finding = parsed["findings"][0]
    assert "fix" in finding
    assert finding["fix"]["guidance"] is not None


def test_review_cli_diff_blocks(monkeypatch, tmp_path, capsys) -> None:
    import io

    monkeypatch.chdir(tmp_path)
    f = tmp_path / "bad.py"
    f.write_text('import os\nos.system("ls")\n')

    diff = (
        "--- a/bad.py\n"
        "+++ b/bad.py\n"
        "@@ -1,1 +1,2 @@\n"
        " import os\n"
        '+os.system("ls")\n'
    )

    monkeypatch.setattr("sys.stdin", io.StringIO(diff))
    exit_code = main(["review", "--diff"])

    assert exit_code == 1
    out = capsys.readouterr().out
    assert "Verdict: BLOCK" in out
    assert "security.os-system" in out


def test_review_cli_bandit(monkeypatch, tmp_path, capsys) -> None:
    f = tmp_path / "app.py"
    f.write_text("print('hello')\n")

    def mock_run_bandit(targets: list[str]) -> str:
        return """
        {
          "results": [
            {
              "test_id": "B602",
              "filename": "app.py",
              "line_number": 1,
              "issue_severity": "HIGH",
              "issue_text": "mock bandit finding"
            }
          ]
        }
        """

    monkeypatch.setattr("rein.cli._helpers._run_bandit", mock_run_bandit)

    exit_code = main(["review", "--bandit", "--format", "json", str(f)])
    assert exit_code == 1

    parsed = json.loads(capsys.readouterr().out)
    assert parsed["verdict"] == "BLOCK"

    rule_ids = {finding["rule_id"] for finding in parsed["findings"]}
    assert "bandit.B602" in rule_ids


def test_review_cli_gitleaks(monkeypatch, tmp_path, capsys) -> None:
    f = tmp_path / "app.py"
    f.write_text("print('hello')\n")

    def mock_run_gitleaks(targets: list[str]) -> str:
        return """
        [
          {
            "RuleID": "mock-secret",
            "Description": "mock gitleaks finding",
            "File": "app.py",
            "StartLine": 1,
            "Match": "secret",
            "Secret": "secret"
          }
        ]
        """

    monkeypatch.setattr("rein.cli._helpers._run_gitleaks", mock_run_gitleaks)

    exit_code = main(["review", "--gitleaks", "--format", "json", str(f)])
    assert exit_code == 1

    parsed = json.loads(capsys.readouterr().out)
    assert parsed["verdict"] == "BLOCK"

    rule_ids = {finding["rule_id"] for finding in parsed["findings"]}
    assert "gitleaks.mock-secret" in rule_ids
