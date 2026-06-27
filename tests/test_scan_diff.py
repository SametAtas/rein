"""Tests for core scan_diff and CLI --diff flag."""

from __future__ import annotations

import io
import json

from rein.core.secrets import scan_diff
from rein.cli.__main__ import main

AWS = "AKIAIOSFODNN7EXAMPLE"  # rein:ignore


def _make_diff(added_line: str, path: str = "app.py") -> str:
    return (
        f"--- a/{path}\n"
        f"+++ b/{path}\n"
        "@@ -1,1 +1,2 @@\n"
        " import os\n"
        f"+{added_line}\n"
    )


def test_added_secret_is_flagged() -> None:
    diff = _make_diff(f'aws = "{AWS}"')
    findings = scan_diff(diff)
    assert len(findings) >= 1
    assert any(f.rule_id == "secret.aws-access-key" for f in findings)
    assert findings[0].path == "app.py"
    assert findings[0].line == 2


def test_removed_secret_not_flagged() -> None:
    diff = (
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -1,2 +1,1 @@\n"
        " import os\n"
        f'-aws = "{AWS}"\n'
    )
    assert scan_diff(diff) == []


def test_context_secret_not_flagged() -> None:
    diff = (
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -1,2 +1,3 @@\n"
        f' aws = "{AWS}"\n'
        " import os\n"
        "+x = 1\n"
    )
    findings = scan_diff(diff)
    # Only "x = 1" is added, which is clean
    assert not any(f.rule_id == "secret.aws-access-key" for f in findings)


def test_added_line_with_ignore_pragma() -> None:
    diff = _make_diff(f'aws = "{AWS}"  # rein:ignore')
    assert scan_diff(diff) == []


def test_empty_diff() -> None:
    assert scan_diff("") == []


# -- CLI --diff integration ---------------------------------------------------


def test_cli_scan_diff_json(monkeypatch, capsys) -> None:
    diff = _make_diff(f'aws = "{AWS}"')
    monkeypatch.setattr("sys.stdin", io.StringIO(diff))
    exit_code = main(["scan", "--diff", "--format", "json"])
    assert exit_code == 1
    parsed = json.loads(capsys.readouterr().out)
    assert any(d["rule_id"] == "secret.aws-access-key" for d in parsed)


def test_cli_scan_diff_clean(monkeypatch, capsys) -> None:
    diff = _make_diff("x = 1")
    monkeypatch.setattr("sys.stdin", io.StringIO(diff))
    exit_code = main(["scan", "--diff", "--format", "json"])
    assert exit_code == 0
    parsed = json.loads(capsys.readouterr().out)
    assert parsed == []
