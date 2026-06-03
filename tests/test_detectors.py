"""Tests for detector runner robustness."""

import os
import subprocess
import tempfile
import json

from rein.cli._helpers import _run_gitleaks, _run_stdout_detector
from rein.cli.__main__ import main


def test_stdout_detector_timeout(monkeypatch, capsys):
    def mock_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args[0], timeout=kwargs.get("timeout", 0))

    monkeypatch.setattr(subprocess, "run", mock_run)

    out = _run_stdout_detector(["bandit"])
    assert out == ""

    stderr = capsys.readouterr().err
    assert "timed out after 60s; skipping" in stderr


def test_stdout_detector_oserror(monkeypatch, capsys):
    def mock_run(*args, **kwargs):
        raise OSError("mock os error")

    monkeypatch.setattr(subprocess, "run", mock_run)

    out = _run_stdout_detector(["bandit"])
    assert out == ""

    stderr = capsys.readouterr().err
    assert "failed (mock os error); skipping" in stderr


def test_stdout_detector_file_not_found(monkeypatch, capsys):
    def mock_run(*args, **kwargs):
        raise FileNotFoundError()

    monkeypatch.setattr(subprocess, "run", mock_run)

    out = _run_stdout_detector(["bandit"])
    assert out == ""

    stderr = capsys.readouterr().err
    assert "bandit not found; skipping" in stderr


def test_gitleaks_timeout_cleans_up_temp_file(monkeypatch, capsys):
    created_file = []

    original_mkstemp = tempfile.mkstemp

    def mock_mkstemp(*args, **kwargs):
        fd, path = original_mkstemp(*args, **kwargs)
        created_file.append(path)
        return fd, path

    monkeypatch.setattr(tempfile, "mkstemp", mock_mkstemp)

    def mock_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args[0], timeout=kwargs.get("timeout", 0))

    monkeypatch.setattr(subprocess, "run", mock_run)

    out = _run_gitleaks(["."])
    assert out == ""

    stderr = capsys.readouterr().err
    assert "gitleaks timed out after 60s; skipping" in stderr

    assert len(created_file) == 1
    # File should be cleaned up by finally block
    assert not os.path.exists(created_file[0])


def test_review_bandit_fails_open(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "app.py").write_text("print('hello')\n", encoding="utf-8")

    def mock_run_bandit(targets):
        return ""

    monkeypatch.setattr("rein.cli._helpers._run_bandit", mock_run_bandit)

    exit_code = main(["review", "--bandit", "--format", "json", "."])
    assert exit_code == 0

    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["verdict"] == "PASS"

    rule_ids = {f["rule_id"] for f in data["findings"]}
    assert not any(r.startswith("bandit.") for r in rule_ids)
