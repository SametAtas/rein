"""Tests for the code domain pack."""

from __future__ import annotations

import ast

from rein.core.code import code_domain


def test_code_domain_returns_all_findings() -> None:
    text = "import os\nos.system('ls')\naws = \"AKIAIOSFODNN7EXAMPLE\"\n"  # rein:ignore secret.aws-access-key
    findings = code_domain(text, "m.py")
    rule_ids = {f.rule_id for f in findings}
    assert "security.os-system" in rule_ids
    assert "secret.aws-access-key" in rule_ids
    assert "lint.missing-future-import" not in rule_ids # No classes/functions


def test_code_domain_skips_lint_security_for_non_python() -> None:
    text = "import os\nos.system('ls')\naws = \"AKIAIOSFODNN7EXAMPLE\"\n"  # rein:ignore secret.aws-access-key
    findings = code_domain(text, "notes.txt")
    rule_ids = {f.rule_id for f in findings}
    assert "secret.aws-access-key" in rule_ids
    assert "security.os-system" not in rule_ids
    assert not any(r.startswith("lint.") for r in rule_ids)


def test_code_domain_parses_ast_once(monkeypatch) -> None:
    calls = {"n": 0}
    real = ast.parse

    def counting(*args, **kwargs):
        calls["n"] += 1
        return real(*args, **kwargs)

    monkeypatch.setattr(ast, "parse", counting)
    code_domain("import os\ndef f(x):\n    return x\n", "m.py")
    assert calls["n"] == 1
