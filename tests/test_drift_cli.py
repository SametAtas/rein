"""CLI tests for convention profile drift detection."""

from __future__ import annotations

import pytest

from rein.cli.__main__ import main


def test_drift_cli_absent_profile(tmp_path, monkeypatch, capsys):
    # No profile exists -> note + exit 0
    monkeypatch.chdir(tmp_path)
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("def test(): pass")

    rc = main(["drift", "src"])
    assert rc == 0

    out, err = capsys.readouterr()
    assert "no profile found" in err
    assert not (tmp_path / ".rein-profile.toml").exists()


def test_drift_cli_broken_profile(tmp_path, monkeypatch, capsys):
    # Profile exists but is broken -> non-zero exit + error output
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".rein-profile.toml").write_text("broken = toml = format = {")

    rc = main(["drift"])
    assert rc != 0

    out, err = capsys.readouterr()
    assert "error" in err


def test_drift_cli_clean_no_drift(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)

    # Ratified profile with snake_case function naming
    profile_content = """version = 1
[conventions.function-naming]
checker = "naming.identifier"
target = "function"
style = "snake_case"

[conventions.function-naming.evidence]
source = "measured"
agreement = 0.95
sample_size = 12
measured_at = "2026-05-31"
"""
    (tmp_path / ".rein-profile.toml").write_text(profile_content)

    # 12 clean conforming functions
    (tmp_path / "app.py").write_text("\n".join(f"def func_{i}(): pass" for i in range(12)))

    rc = main(["drift"])
    assert rc == 0

    out, err = capsys.readouterr()
    assert "[OK] function-naming:" in out
    assert "conformance: 1.00" in out

    # Assert profile is unchanged
    assert (tmp_path / ".rein-profile.toml").read_text() == profile_content


def test_drift_cli_degraded_drift(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)

    # Ratified profile with PascalCase class naming
    profile_content = """version = 1
[conventions.class-naming]
checker = "naming.identifier"
target = "class"
style = "PascalCase"

[conventions.class-naming.evidence]
source = "measured"
agreement = 0.99
sample_size = 10
measured_at = "2026-05-31"
"""
    (tmp_path / ".rein-profile.toml").write_text(profile_content)

    # 10 classes: 7 conform, 3 degrade -> Conformance = 0.70 < 0.90, drifted = True
    classes_code = (
        "\n".join(f"class ConformingClass{i}: pass" for i in range(7))
        + "\n"
        + "\n".join(f"class badClass{i}: pass" for i in range(3))
    )
    (tmp_path / "app.py").write_text(classes_code)

    rc = main(["drift"])
    assert rc == 1

    out, err = capsys.readouterr()
    assert "[DRIFT] class-naming:" in out
    assert "conformance: 0.70" in out

    # Assert profile is unchanged
    assert (tmp_path / ".rein-profile.toml").read_text() == profile_content
