"""Integration tests for convention profile enforcement in the CLI."""

import json

from rein.cli.__main__ import main


def test_review_with_valid_profile(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)

    profile_text = """
    version = 1
    [conventions.fn]
    checker = "naming.identifier"
    target = "function"
    style = "snake_case"
    """
    (tmp_path / ".rein-profile.toml").write_text(profile_text, encoding="utf-8")

    test_file = tmp_path / "test_file.py"
    test_file.write_text("def badName(): pass\n", encoding="utf-8")

    rc = main(["review", "--format", "json", "."])
    # LOW severity defaults to WARN, so rc should be 0 unless configured otherwise
    assert rc == 0

    out, _ = capsys.readouterr()
    report = json.loads(out)

    findings = report.get("findings", [])
    conv_findings = [f for f in findings if f["rule_id"] == "convention.fn"]
    assert len(conv_findings) == 1
    assert conv_findings[0]["severity"] == "LOW"
    assert conv_findings[0]["snippet"] == "badName"


def test_review_with_broken_profile_blocks(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)

    profile_text = """
    version = 1
    [conventions.fn]
    checker = "unknown.checker"
    """
    (tmp_path / ".rein-profile.toml").write_text(profile_text, encoding="utf-8")

    test_file = tmp_path / "test_file.py"
    test_file.write_text("def good_name(): pass\n", encoding="utf-8")

    rc = main(["review", "--format", "json", "."])
    assert rc != 0

    out, _ = capsys.readouterr()
    report = json.loads(out)

    findings = report.get("findings", [])
    invalid_findings = [f for f in findings if f["rule_id"] == "rein.profile-invalid"]
    assert len(invalid_findings) == 1
    assert invalid_findings[0]["severity"] == "HIGH"


def test_review_missing_profile_silent(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)

    test_file = tmp_path / "test_file.py"
    test_file.write_text("def badName(): pass\n", encoding="utf-8")

    rc = main(["review", "--format", "json", "."])
    assert rc == 0

    out, _ = capsys.readouterr()
    report = json.loads(out)

    findings = report.get("findings", [])
    assert not any(f["rule_id"].startswith("convention.") for f in findings)
    assert not any(f["rule_id"] == "rein.profile-invalid" for f in findings)


def test_review_profile_finding_muted_by_disabled(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)

    profile_text = """
    version = 1
    [conventions.fn]
    checker = "naming.identifier"
    target = "function"
    style = "snake_case"
    """
    (tmp_path / ".rein-profile.toml").write_text(profile_text, encoding="utf-8")

    config_text = """
    [rules]
    disabled = ["convention.fn"]
    """
    (tmp_path / ".rein.toml").write_text(config_text, encoding="utf-8")

    test_file = tmp_path / "test_file.py"
    test_file.write_text("def badName(): pass\n", encoding="utf-8")

    rc = main(["review", "--format", "json", "."])
    assert rc == 0

    out, _ = capsys.readouterr()
    report = json.loads(out)

    findings = report.get("findings", [])
    assert not any(f["rule_id"] == "convention.fn" for f in findings)


def test_review_broken_profile_d2_proof(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)

    profile_text = """
    version = 1
    [conventions.fn]
    checker = "unknown.checker"
    """
    (tmp_path / ".rein-profile.toml").write_text(profile_text, encoding="utf-8")

    config_text = """
    [rules]
    disabled = ["rein.profile-invalid"]
    """
    (tmp_path / ".rein.toml").write_text(config_text, encoding="utf-8")

    test_file = tmp_path / "test_file.py"
    test_file.write_text("def good_name(): pass\n", encoding="utf-8")

    rc = main(["review", "--format", "json", "."])
    assert rc != 0

    out, _ = capsys.readouterr()
    report = json.loads(out)

    findings = report.get("findings", [])
    invalid_findings = [f for f in findings if f["rule_id"] == "rein.profile-invalid"]
    assert len(invalid_findings) == 1
    assert invalid_findings[0]["severity"] == "HIGH"
