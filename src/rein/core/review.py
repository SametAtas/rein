"""Turn findings into a configurable PASS/WARN/BLOCK verdict.

This is the single surface every future product (agent self-correction,
developer feedback, academic review) calls. Domains differ only by their Policy.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .code import code_domain
from .diffs import parse_added_lines
from .findings import Domain, Finding, Severity


class Verdict(Enum):
    PASS = "pass"
    WARN = "warn"
    BLOCK = "block"

    def __str__(self) -> str:
        return self.name


@dataclass(frozen=True)
class Policy:
    """Maps findings to a Verdict. The per-domain knob.

    fail_at: severity at/above which a finding blocks.
    warn_at: severity at/above which a finding warns (below fail_at).
    category_fail_at: override fail_at for a specific category, e.g.
        Policy(category_fail_at={"lint": Severity.LOW}) blocks on any lint issue
        (an academic/strict policy). Categories: secret, lint, security, commit, ruff.
    """

    fail_at: Severity = Severity.HIGH
    warn_at: Severity = Severity.LOW
    category_fail_at: dict[str, Severity] = field(default_factory=dict)


DEFAULT_POLICY = Policy()


def _category(finding: Finding) -> str:
    return finding.rule_id.split(".", 1)[0]


def decide(findings: list[Finding], policy: Policy | None = None) -> Verdict:
    """Pure: turn findings into a verdict under a policy. The heart of steering."""
    policy = policy or DEFAULT_POLICY
    blocked = warned = False
    for f in findings:
        fail_at = policy.category_fail_at.get(_category(f), policy.fail_at)
        if f.severity >= fail_at:
            blocked = True
        elif f.severity >= policy.warn_at:
            warned = True
    if blocked:
        return Verdict.BLOCK
    if warned:
        return Verdict.WARN
    return Verdict.PASS


@dataclass(frozen=True)
class ReviewResult:
    findings: list[Finding]
    verdict: Verdict

    @classmethod
    def from_findings(
        cls, findings: list[Finding], policy: Policy | None = None
    ) -> "ReviewResult":
        return cls(list(findings), decide(findings, policy))

    def to_dict(self) -> dict:
        return {
            "verdict": str(self.verdict),
            "findings": [f.to_dict() for f in self.findings],
        }


def review(
    text: str, path: str | None = None, policy: Policy | None = None, domain: Domain | None = None
) -> ReviewResult:
    """Run guardrails over an artifact's text and judge the result.

    Runs the given domain (defaults to code_domain) to gather findings. Commit hygiene
    is a different artifact and is intentionally not included here.
    """
    findings = (domain or code_domain)(text, path)
    return ReviewResult.from_findings(findings, policy)


def _added_lines_for(diff_text: str, path: str | None) -> set[int]:
    """New-file line numbers added by the diff, for one path (or all if None)."""
    return {
        al.line for al in parse_added_lines(diff_text)
        if path is None or al.path == path
    }


def review_diff_findings(
    new_text: str, diff_text: str, path: str | None = None, domain: Domain | None = None
) -> list[Finding]:
    """Findings on lines the diff adds, judged against the full new content.

    Runs the checks over the complete new file, then keeps only findings located
    on added lines. File-level findings (line is None) are excluded.
    """
    added = _added_lines_for(diff_text, path)
    findings = (domain or code_domain)(new_text, path)
    return [f for f in findings if f.line is not None and f.line in added]


def review_diff(
    new_text: str, diff_text: str, path: str | None = None, policy: Policy | None = None, domain: Domain | None = None
) -> ReviewResult:
    """Review only the lines a diff adds. new_text is the file's content after
    the change; diff_text identifies which lines are new. path should match the
    file path as it appears in the diff (or None for a single-file diff)."""
    return ReviewResult.from_findings(
        review_diff_findings(new_text, diff_text, path, domain), policy
    )
