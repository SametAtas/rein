"""Tests for the shared ignore-pragma helper."""

from rein.core.findings import Finding, Severity
from rein.core.pragmas import filter_by_pragma, parse_ignore_pragma


def _finding(rule_id: str = "test.rule") -> Finding:
    return Finding(rule_id=rule_id, severity=Severity.LOW, message="test")


def test_no_pragma_returns_none():
    assert parse_ignore_pragma("x = 1") is None


def test_bare_pragma_returns_empty_set():
    assert parse_ignore_pragma("x = 1  # rein:ignore") == set()


def test_scoped_single_id():
    result = parse_ignore_pragma("x = 1  # rein:ignore secret.aws-access-key")
    assert result == {"secret.aws-access-key"}


def test_scoped_comma_list():
    result = parse_ignore_pragma("x = 1  # rein:ignore id.one, id.two")
    assert result == {"id.one", "id.two"}


def test_scoped_non_matching_id():
    result = parse_ignore_pragma("x = 1  # rein:ignore other.rule")
    assert result == {"other.rule"}


def test_filter_no_pragma_returns_all():
    findings = [_finding("a"), _finding("b")]
    assert filter_by_pragma(findings, "x = 1") == findings


def test_filter_bare_pragma_returns_empty():
    findings = [_finding("a"), _finding("b")]
    assert filter_by_pragma(findings, "x = 1  # rein:ignore") == []


def test_filter_scoped_drops_matching():
    findings = [_finding("a"), _finding("b")]
    result = filter_by_pragma(findings, "x = 1  # rein:ignore a")
    assert len(result) == 1
    assert result[0].rule_id == "b"


def test_filter_scoped_keeps_all_when_no_match():
    findings = [_finding("a"), _finding("b")]
    result = filter_by_pragma(findings, "x = 1  # rein:ignore c")
    assert result == findings
