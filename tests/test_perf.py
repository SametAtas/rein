from __future__ import annotations

import ast

from rein.core.code import code_domain
from rein.core.review import review


def test_review_parses_ast_once(monkeypatch) -> None:
    """The hot path must parse the source only once (no redundant re-parsing)."""
    calls = {"n": 0}
    real = ast.parse

    def counting(*args, **kwargs):
        calls["n"] += 1
        return real(*args, **kwargs)

    monkeypatch.setattr(ast, "parse", counting)
    review("import os\ndef f(x):\n    return x\n", "m.py", domain=code_domain)
    assert calls["n"] == 1


def test_review_survives_unparseable_input() -> None:
    """Malformed input degrades gracefully: a syntax-error finding, no crash."""
    result = review("def f(:\n", "m.py", domain=code_domain)
    assert any(f.rule_id == "lint.syntax-error" for f in result.findings)


def test_collect_review_parses_each_file_once(tmp_path, monkeypatch) -> None:
    """A review pass parses each .py file once, sharing the tree across all
    AST checkers (code domain, profile conventions, import resolution)."""
    from rein.cli._helpers import _collect_review_findings
    from rein.core.findings import Severity
    from rein.core.profile import ConventionEntry, Profile

    f = tmp_path / "m.py"
    f.write_text("import os\ndef f(x):\n    return x\n", encoding="utf-8")
    profile = Profile(
        version=1,
        conventions=(
            ConventionEntry(
                id="fn",
                checker="naming.identifier",
                severity=Severity.LOW,
                enabled=True,
                params={"target": "function", "style": "snake_case"},
            ),
        ),
    )

    calls = {"n": 0}
    real = ast.parse

    def counting(*args, **kwargs):
        calls["n"] += 1
        return real(*args, **kwargs)

    monkeypatch.setattr(ast, "parse", counting)
    _collect_review_findings([str(f)], profile=profile)
    assert calls["n"] == 1


def test_measure_drift_parses_ast_once(monkeypatch) -> None:
    """measure_drift must collect identifiers by parsing each source at most once,
    even with multiple naming conventions active.
    """
    from rein.core.drift import measure_drift
    from rein.core.profile import PROFILE_VERSION, parse_profile

    profile_data = {
        "version": PROFILE_VERSION,
        "conventions": {
            "function-naming": {
                "checker": "naming.identifier",
                "target": "function",
                "style": "snake_case",
                "evidence": {
                    "source": "measured",
                    "agreement": 0.95,
                    "sample_size": 1,
                },
            },
            "class-naming": {
                "checker": "naming.identifier",
                "target": "class",
                "style": "PascalCase",
                "evidence": {
                    "source": "measured",
                    "agreement": 0.95,
                    "sample_size": 1,
                },
            },
        },
    }
    profile = parse_profile(profile_data)
    files = [("a.py", "def func_1(): pass\nclass MyClass: pass")]

    calls = {"n": 0}
    real = ast.parse

    def counting(*args, **kwargs):
        calls["n"] += 1
        return real(*args, **kwargs)

    monkeypatch.setattr(ast, "parse", counting)
    measure_drift(profile, files)
    assert calls["n"] <= 1


def test_scan_profile_parses_ast_once(monkeypatch) -> None:
    """scan_profile must parse each source at most once."""
    from rein.core import conventions
    from rein.core.profile import Profile, ConventionEntry
    from rein.core.findings import Severity

    prof = Profile(
        version=1,
        conventions=(
            ConventionEntry(
                id="c1",
                checker="naming.identifier",
                severity=Severity.LOW,
                enabled=True,
                params={"target": "function", "style": "snake_case"},
            ),
            ConventionEntry(
                id="c2",
                checker="naming.identifier",
                severity=Severity.MEDIUM,
                enabled=True,
                params={"target": "class", "style": "PascalCase"},
            ),
        ),
    )

    calls = {"n": 0}
    real = ast.parse

    def counting(*args, **kwargs):
        calls["n"] += 1
        return real(*args, **kwargs)

    monkeypatch.setattr(ast, "parse", counting)
    conventions.scan_profile("def snake_case():\n    pass\n", "test.py", prof)
    assert calls["n"] == 1
