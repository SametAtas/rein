"""Integration tests for the rein security CLI subcommand."""

from __future__ import annotations

import json

from rein.cli.__main__ import main


def test_security_cli_high_finding(tmp_path, capsys) -> None:
    f = tmp_path / "bad.py"
    f.write_text('import os\nos.system("ls")\n')
    exit_code = main(["security", str(f)])
    assert exit_code == 1
    captured = capsys.readouterr()
    assert "security.os-system" in captured.out


def test_security_cli_high_json(tmp_path, capsys) -> None:
    f = tmp_path / "bad.py"
    f.write_text('import os\nos.system("ls")\n')
    exit_code = main(["security", "--format", "json", str(f)])
    assert exit_code == 1
    parsed = json.loads(capsys.readouterr().out)
    assert any(d["rule_id"] == "security.os-system" for d in parsed)


def test_security_cli_clean(tmp_path, capsys) -> None:
    f = tmp_path / "clean.py"
    f.write_text("x = 1\n")
    exit_code = main(["security", str(f)])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "no issues found" in captured.out


def test_security_cli_medium_no_block(tmp_path, capsys) -> None:
    f = tmp_path / "hash.py"
    f.write_text('import hashlib\nhashlib.md5(b"x")\n')
    exit_code = main(["security", str(f)])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "security.weak-hash" in captured.out
