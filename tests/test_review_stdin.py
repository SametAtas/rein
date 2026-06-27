"""`rein review --stdin`: content-mode review of one in-memory source.

This backs the editor surfaces (a chat participant and a language-model tool)
that review code an agent is about to write, where the source is text, not a
file on disk.
"""

from __future__ import annotations

import argparse
import io

from rein.cli._helpers import _collect_stdin_findings
from rein.cli.commands import cmd_review


def _rules(findings):
    return {f.rule_id for f in findings}


def test_stdin_flags_secret_and_unsafe_code() -> None:
    src = 'password = "AKIAIOSFODNN7EXAMPLE"\neval(input())\n'
    rules = _rules(_collect_stdin_findings(src, "agent_snippet.py"))
    assert "security.eval-exec" in rules
    assert any(r.startswith("secret.") for r in rules)


def test_stdin_clean_source_has_no_findings() -> None:
    assert _collect_stdin_findings("import os\nprint(os.getcwd())\n", "ok.py") == []


def test_stdin_uses_the_given_filename_in_findings() -> None:
    findings = _collect_stdin_findings("eval(x)\n", "from_agent.py")
    assert findings
    assert all(f.path == "from_agent.py" for f in findings)


def test_stdin_degrades_on_unparseable_source() -> None:
    # Half-written agent code must not crash; secrets still scan (text-based).
    src = 'def f(:\n    token = "AKIAIOSFODNN7EXAMPLE"\n'
    rules = _rules(_collect_stdin_findings(src, "partial.py"))
    assert any(r.startswith("secret.") for r in rules)


def _review_args(**over) -> argparse.Namespace:
    base = dict(
        paths=[], diff=False, stdin=False, filename=None, explain=False,
        baseline=None, config=None, bandit=False, gitleaks=False, semgrep=False,
        format="text",
    )
    base.update(over)
    return argparse.Namespace(**base)


def test_cmd_review_rejects_stdin_with_diff(monkeypatch, tmp_path, capsys) -> None:
    monkeypatch.chdir(tmp_path)
    code = cmd_review(_review_args(stdin=True, diff=True))
    assert code == 1
    assert "use one" in capsys.readouterr().err


def test_cmd_review_stdin_blocks_on_finding(monkeypatch, tmp_path, capsys) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("sys.stdin", io.StringIO("eval(input())\n"))
    code = cmd_review(_review_args(stdin=True, filename="x.py", format="json"))
    assert code == 1  # blocking verdict
    assert "security.eval-exec" in capsys.readouterr().out
