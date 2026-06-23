"""Tests for the CLI lint subcommand."""

from unittest.mock import patch

from rein.cli.__main__ import main


def test_lint_cli_core_rules(tmp_path, capsys):
    f = tmp_path / "bad.py"
    f.write_text("def foo(:\n")  # SyntaxError

    # main() returns the worst exit code
    exit_code = main(["lint", str(f)])
    assert exit_code == 0

    captured = capsys.readouterr()
    assert "lint.syntax-error" in captured.out
    assert "1 finding(s)." in captured.out


@patch("rein.cli._helpers._run_ruff")
def test_lint_cli_with_ruff_flag(mock_run_ruff, tmp_path, capsys):
    f = tmp_path / "ok.py"
    f.write_text("x = 1\n")

    # Monkeypatch to return a JSON fixture
    mock_run_ruff.return_value = '''[
      {
        "code": "F401",
        "message": "os imported but unused",
        "location": {"row": 12},
        "filename": "ok.py"
      }
    ]'''

    exit_code = main(["lint", "--ruff", str(f)])
    assert exit_code == 0

    captured = capsys.readouterr()
    assert "ruff.F401" in captured.out
    assert "1 finding(s)." in captured.out
