"""Core baseline fingerprinting and filtering tests."""

from __future__ import annotations

from rein.core.baseline import apply_baseline, fingerprint, make_baseline
from rein.core.findings import Finding, Severity


def _finding(
    rule_id: str = "lint.stub-body",
    path: str = "a.py",
    line: int = 5,
    snippet: str | None = "pass",
    message: str = "Stub body.",
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=Severity.LOW,
        message=message,
        path=path,
        line=line,
        snippet=snippet,
    )


def test_fingerprint_stable_across_line_changes() -> None:
    """Same rule+path+content at different lines must produce the same hash."""
    a = _finding(line=5)
    b = _finding(line=99)
    assert fingerprint(a) == fingerprint(b)


def test_fingerprint_differs_by_rule_id() -> None:
    a = _finding(rule_id="lint.stub-body")
    b = _finding(rule_id="lint.missing-type-hints")
    assert fingerprint(a) != fingerprint(b)


def test_fingerprint_differs_by_path() -> None:
    a = _finding(path="a.py")
    b = _finding(path="b.py")
    assert fingerprint(a) != fingerprint(b)


def test_fingerprint_differs_by_snippet() -> None:
    a = _finding(snippet="pass")
    b = _finding(snippet="...")
    assert fingerprint(a) != fingerprint(b)


def test_fingerprint_uses_message_when_no_snippet() -> None:
    """Snippet-less findings use message to distinguish them."""
    a = _finding(snippet=None, message="Function 'foo' missing hints.")
    b = _finding(snippet=None, message="Function 'bar' missing hints.")
    assert fingerprint(a) != fingerprint(b)


def test_make_baseline_deduplicates() -> None:
    f = _finding()
    entries = make_baseline([f, f, f])
    assert len(entries) == 1


def test_make_baseline_entries_have_required_fields() -> None:
    f = _finding()
    entries = make_baseline([f])
    entry = entries[0]
    assert set(entry.keys()) == {"rule_id", "path", "fingerprint"}
    assert entry["rule_id"] == f.rule_id
    assert entry["path"] == f.path


def test_make_baseline_contains_no_raw_secret() -> None:
    f = _finding(snippet="AKIA************MPLE")
    entries = make_baseline([f])
    raw = str(entries)
    assert "AKIA" not in raw


def test_apply_baseline_drops_known_keeps_new() -> None:
    known = _finding(rule_id="lint.stub-body", line=5)
    new = _finding(rule_id="security.eval-exec", snippet="eval(...)")
    fps = {fingerprint(known)}
    result = apply_baseline([known, new], fps)
    assert len(result) == 1
    assert result[0].rule_id == "security.eval-exec"


def test_apply_baseline_empty_set_keeps_all() -> None:
    f = _finding()
    assert apply_baseline([f], set()) == [f]
