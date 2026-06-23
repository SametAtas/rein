"""CLI integration tests for the baseline feature."""

from __future__ import annotations

import json
import os

from rein.cli.__main__ import main


def test_baseline_command_writes_file(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    vuln = tmp_path / "bad.py"
    vuln.write_text('import os\nos.system("a")\n', encoding="utf-8")

    rc = main(["baseline", "-o", "bl.json", "."])
    assert rc == 0
    bl = tmp_path / "bl.json"
    assert bl.exists()
    data = json.loads(bl.read_text(encoding="utf-8"))
    fps = {e["fingerprint"] for e in data["findings"]}
    assert len(fps) >= 1


def test_review_baseline_suppresses_known_shows_new(tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.chdir(tmp_path)
    vuln = tmp_path / "bad.py"
    vuln.write_text('import os\nos.system("a")\n', encoding="utf-8")

    main(["baseline", "-o", "bl.json", "."])
    capsys.readouterr()  # discard baseline output

    vuln.write_text('import os\nos.system("a")\neval("x")\n', encoding="utf-8")

    rc = main(["review", "--baseline", "bl.json", "--format", "json", "."])
    out = capsys.readouterr().out
    data = json.loads(out)
    findings = data["findings"] if isinstance(data, dict) else data
    rule_ids = {f["rule_id"] for f in findings}
    assert "security.eval-exec" in rule_ids
    assert "security.os-system" not in rule_ids


def test_review_missing_baseline_does_not_crash(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    vuln = tmp_path / "ok.py"
    vuln.write_text("x = 1\n", encoding="utf-8")

    rc = main(["review", "--baseline", "does-not-exist.json", "."])
    assert isinstance(rc, int)
