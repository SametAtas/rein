import os
import pytest

from rein.cli.__main__ import main


def test_learn_cli_stdout(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text(
        "def snake_case_func(): pass\ndef snake2(): pass\ndef snake3(): pass\ndef snake4(): pass\n"
        "def snake5(): pass\ndef snake6(): pass\ndef snake7(): pass\ndef snake8(): pass\n"
        "def snake9(): pass\ndef snake10(): pass\n"
        "class PascalClass: pass\nclass P2: pass\nclass P3: pass\nclass P4: pass\n"
        "class P5: pass\nclass P6: pass\nclass P7: pass\nclass P8: pass\n"
        "class P9: pass\nclass P10: pass\n"
    )

    rc = main(["learn", "src"])
    assert rc == 0

    out, err = capsys.readouterr()
    assert "[conventions.function-naming]" in out
    assert "[conventions.class-naming]" in out


def test_learn_cli_existing_profile(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text(
        "def snake_case_func(): pass\ndef snake2(): pass\ndef snake3(): pass\ndef snake4(): pass\n"
        "def snake5(): pass\ndef snake6(): pass\ndef snake7(): pass\ndef snake8(): pass\n"
        "def snake9(): pass\ndef snake10(): pass\n"
        "class PascalClass: pass\nclass P2: pass\nclass P3: pass\nclass P4: pass\n"
        "class P5: pass\nclass P6: pass\nclass P7: pass\nclass P8: pass\n"
        "class P9: pass\nclass P10: pass\n"
    )

    (tmp_path / ".rein-profile.toml").write_text(
        'version = 1\n[conventions.function-naming]\nchecker = "naming.identifier"\ntarget = "function"\nstyle = "camelCase"\n'
    )

    rc = main(["learn", "src"])
    assert rc == 0

    out, err = capsys.readouterr()
    assert "[conventions.function-naming]" not in out
    assert "[conventions.class-naming]" in out


def test_learn_cli_output_refuses_overwrite(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text(
        "def snake_case_func(): pass\ndef snake2(): pass\ndef snake3(): pass\ndef snake4(): pass\n"
        "def snake5(): pass\ndef snake6(): pass\ndef snake7(): pass\ndef snake8(): pass\n"
        "def snake9(): pass\ndef snake10(): pass\n"
        "class PascalClass: pass\nclass P2: pass\nclass P3: pass\nclass P4: pass\n"
        "class P5: pass\nclass P6: pass\nclass P7: pass\nclass P8: pass\n"
        "class P9: pass\nclass P10: pass\n"
    )

    out_file = tmp_path / "out.toml"
    out_file.write_text("existing")

    rc = main(["learn", "src", "-o", "out.toml"])
    assert rc == 1

    out, err = capsys.readouterr()
    assert "error: output file 'out.toml' already exists" in err


def test_learn_cli_test_layout(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()

    # Create 10 test files to hit the minimum sample size
    for i in range(10):
        (tests_dir / f"test_module_{i}.py").write_text("def test_x(): pass")

    rc = main(["learn", "."])
    assert rc == 0

    out, err = capsys.readouterr()
    assert "[conventions.layout-test-files]" in out
    assert 'directory = "tests"' in out
    assert 'filename = "test_*.py"' in out
