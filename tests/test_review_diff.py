"""Tests for the diff-aware review functionality."""

from __future__ import annotations

from rein.core.code import code_domain
from rein.core.review import review_diff, Verdict

AWS = "AKIAIOSFODNN7EXAMPLE"  # rein:ignore


def _make_diff(added_line: str, path: str = "app.py") -> str:
    return (
        f"--- a/{path}\n"
        f"+++ b/{path}\n"
        "@@ -1,1 +1,2 @@\n"
        " import os\n"
        f"+{added_line}\n"
    )


def test_review_diff_added_secret_blocks() -> None:
    diff = _make_diff(f'aws = "{AWS}"')
    new_text = f'import os\naws = "{AWS}"\n'
    result = review_diff(new_text, diff, "app.py", domain=code_domain)
    assert result.verdict is Verdict.BLOCK
    assert any(f.rule_id == "secret.aws-access-key" for f in result.findings)
    assert any(f.line == 2 for f in result.findings)


def test_review_diff_context_secret_passes() -> None:
    # Secret is in new_text but the diff says a DIFFERENT line was added.
    diff = _make_diff("x = 1")
    new_text = f'import os\nx = 1\naws = "{AWS}"\n'
    result = review_diff(new_text, diff, "app.py", domain=code_domain)
    # Finding would be at line 3, but diff only adds line 2
    assert result.verdict is Verdict.PASS
    assert not any(f.rule_id == "secret.aws-access-key" for f in result.findings)


def test_review_diff_security_issue_blocks() -> None:
    diff = _make_diff('os.system("ls")')
    new_text = 'import os\nos.system("ls")\n'
    result = review_diff(new_text, diff, "app.py", domain=code_domain)
    assert result.verdict is Verdict.BLOCK
    assert any(f.rule_id == "security.os-system" for f in result.findings)


def test_review_diff_excludes_file_level_findings() -> None:
    # A file > 200 lines triggers lint.file-too-long (line=None).
    # We want to prove review_diff_findings excludes it.
    new_text = "x = 1\n" * 250
    diff = _make_diff("x = 1")
    result = review_diff(new_text, diff, "app.py", domain=code_domain)
    assert not any(f.rule_id == "lint.file-too-long" for f in result.findings)


def test_review_diff_non_python_path() -> None:
    diff = _make_diff("eval(x)", "notes.md")
    new_text = "import os\neval(x)\n"
    # For a markdown file, lint/security do not run, so eval-exec should NOT be found.
    result = review_diff(new_text, diff, "notes.md", domain=code_domain)
    assert result.verdict is Verdict.PASS
    assert len(result.findings) == 0
