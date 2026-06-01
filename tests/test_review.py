"""Tests for the review module (Policy, Verdict, decide)."""

from __future__ import annotations

from rein.core.findings import Finding, Severity
from rein.core.review import Policy, ReviewResult, Verdict, decide, review


def test_decide_empty() -> None:
    assert decide([]) is Verdict.PASS


def test_decide_single_high_finding_blocks() -> None:
    f = Finding("test.foo", Severity.HIGH, "msg", None, None, None, ())
    assert decide([f]) is Verdict.BLOCK


def test_decide_single_low_finding_warns() -> None:
    f = Finding("test.foo", Severity.LOW, "msg", None, None, None, ())
    assert decide([f]) is Verdict.WARN


def test_decide_single_info_finding_passes() -> None:
    f = Finding("test.foo", Severity.INFO, "msg", None, None, None, ())
    assert decide([f]) is Verdict.PASS


def test_decide_category_override() -> None:
    f = Finding("lint.foo", Severity.LOW, "msg", None, None, None, ())
    policy = Policy(category_fail_at={"lint": Severity.LOW})
    assert decide([f], policy) is Verdict.BLOCK


AWS = "AKIAIOSFODNN7EXAMPLE"  # rein:ignore


def test_review_secret_blocks() -> None:
    # Build AWS key from a literal that bypasses the own-repo scan
    result = review(f'aws = "{AWS}"\n')
    assert result.verdict is Verdict.BLOCK
    assert any(f.rule_id == "secret.aws-access-key" for f in result.findings)


def test_review_clean_passes() -> None:
    result = review("x = 1\n")
    assert result.verdict is Verdict.PASS
    assert len(result.findings) == 0


def test_review_medium_warns() -> None:
    result = review('import hashlib\nhashlib.md5(b"x")\n')
    assert result.verdict is Verdict.WARN
    assert any(f.rule_id == "security.weak-hash" for f in result.findings)


def test_review_result_to_dict() -> None:
    f = Finding("test.foo", Severity.HIGH, "msg", None, None, None, ())
    result = ReviewResult.from_findings([f])
    d = result.to_dict()
    assert d["verdict"] == "BLOCK"
    assert len(d["findings"]) == 1
    assert d["findings"][0]["rule_id"] == "test.foo"


def test_review_custom_domain_seam() -> None:
    stub = Finding("custom.rule", Severity.HIGH, "msg", None, None, None, ())
    result = review("anything", domain=lambda t, p: [stub])
    assert result.verdict is Verdict.BLOCK
    assert len(result.findings) == 1
    assert result.findings[0].rule_id == "custom.rule"
