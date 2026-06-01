"""Contract for the pre-commit hook's pure logic.

These tests define correct behavior for ``hooks.precommit.evaluate``. They are
authored as the spec; the implementation must make them pass without changing
them. ``main`` (git I/O) is verified manually against a real repo.
"""

from rein.hooks.precommit import evaluate


def _ids(findings):
    return {f.rule_id for f in findings}


def test_clean_commit_has_no_findings():
    staged = {"src/app.py": "def add(a, b):\n    return a + b\n"}
    assert evaluate(staged, "feat(math): add helper") == []


def test_secret_in_staged_file_is_flagged_with_path():
    staged = {"config.py": 'aws = "AKIAIOSFODNN7EXAMPLE"\n'}  # rein:ignore
    findings = evaluate(staged, "chore: add config")
    assert "secret.aws-access-key" in _ids(findings)
    assert any(f.path == "config.py" for f in findings)


def test_bad_message_is_flagged():
    findings = evaluate({"src/app.py": "x = 1\n"}, "WIP")
    assert "commit.wip-marker" in _ids(findings)


def test_sensitive_staged_path_is_flagged():
    findings = evaluate({".env": "TOKEN=abc\n"}, "chore: env")
    assert "commit.sensitive-file" in _ids(findings)


def test_none_message_skips_message_checks_but_still_scans():
    # No message -> no commit-message findings, but secret scan still runs.
    findings = evaluate({"a.py": 'key = "AKIAIOSFODNN7EXAMPLE"\n'}, None)  # rein:ignore
    ids = _ids(findings)
    assert "secret.aws-access-key" in ids
    assert not any(i.startswith("commit.") and i != "commit.sensitive-file" for i in ids)


def test_multiple_files_all_scanned():
    staged = {
        "a.py": 'gh = "ghp_0123456789012345678901234567890123456"\n',  # rein:ignore
        "b.py": "clean = 1\n",
    }
    findings = evaluate(staged, "feat: two files")
    assert any(f.path == "a.py" for f in findings)
