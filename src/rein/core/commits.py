"""Commit hygiene checks.

Pure functions: they take the commit message and the list of changed files as
plain data, so they work the same whether the caller is the CLI reading from
git, the MCP server receiving JSON, or a unit test. No subprocess calls here.
"""

from __future__ import annotations

import re

from .findings import Finding, Severity
from .junk import scan_junk_paths

# Conventional Commits: type(scope)!: subject
_CONVENTIONAL_RE = re.compile(
    r"^(?P<type>build|chore|ci|docs|feat|fix|perf|refactor|revert|style|test)"
    r"(?:\([^)]+\))?(?P<breaking>!)?: .+",
)

_WIP_RE = re.compile(r"\b(wip|fixup|squash|asdf|temp|tmp|do not merge)\b", re.IGNORECASE)

# AI/tool attribution is banned (sole authorship; see CONTRIBUTING.md). These mirror
# .githooks/commit-msg EXACTLY so the engine (rein commit-check, CI) catches
# what the bypassable local hook does.
_COAUTHORED_RE = re.compile(r"co-?authored[ -]by", re.IGNORECASE)
_GENERATED_RE = re.compile(
    r"generated (with|by) .*\b"
    r"(claude|copilot|gemini|chatgpt|antigravity|cursor|codex|windsurf|llm|ai)\b",
    re.IGNORECASE,
)

SUBJECT_SOFT_LIMIT = 50  # ideal
SUBJECT_HARD_LIMIT = 72  # warn beyond this

# Files that almost never belong in a commit.
_SENSITIVE_FILE_RE = re.compile(
    r"(^|/)("
    r"\.env(\..*)?|"
    r".*\.pem|.*\.key|.*\.pfx|.*\.p12|"
    r"id_rsa|id_dsa|id_ecdsa|id_ed25519|"
    r"\.npmrc|\.pypirc|"
    r".*credentials.*|.*secrets?\..*"
    r")$",
    re.IGNORECASE,
)

# Files that control the guardrail itself.
_GUARDRAIL_FILE_RE = re.compile(
    r"(^|/)(\.rein\.toml|\.rein-baseline\.json|\.rein-profile\.toml)$|(?:\.githooks/)"
)


def _check_wip(subject: str) -> Finding | None:
    if _WIP_RE.search(subject):
        return Finding(
            "commit.wip-marker",
            Severity.MEDIUM,
            "Subject contains a work-in-progress marker (WIP/fixup/temp).",
            snippet=subject,
            tags=("commit",),
        )
    return None


def _check_subject_length(subject: str) -> Finding | None:
    if len(subject) > SUBJECT_HARD_LIMIT:
        return Finding(
            "commit.subject-too-long",
            Severity.LOW,
            f"Subject is {len(subject)} chars; keep it under {SUBJECT_HARD_LIMIT}.",
            snippet=subject,
            tags=("commit",),
        )
    return None


def _check_trailing_period(subject: str) -> Finding | None:
    if subject.endswith("."):
        return Finding(
            "commit.subject-trailing-period",
            Severity.INFO,
            "Subject should not end with a period.",
            snippet=subject,
            tags=("commit",),
        )
    return None


def _check_conventional(subject: str) -> Finding | None:
    if not _CONVENTIONAL_RE.match(subject):
        return Finding(
            "commit.not-conventional",
            Severity.LOW,
            "Subject does not follow Conventional Commits "
            "(e.g. 'feat: ...', 'fix(api): ...').",
            snippet=subject,
            tags=("commit",),
        )
    return None


def _check_attribution(message: str) -> Finding | None:
    if _COAUTHORED_RE.search(message) or _GENERATED_RE.search(message):
        return Finding(
            "commit.ai-attribution",
            Severity.HIGH,
            "commit message contains AI/tool attribution; "
            "sole authorship is required (see CONTRIBUTING.md)",
            tags=("commit",),
        )
    return None


def _check_blank_line(lines: list[str]) -> Finding | None:
    if len(lines) > 1 and lines[1].strip():
        return Finding(
            "commit.no-blank-line",
            Severity.LOW,
            "Leave a blank line between the subject and the body.",
            tags=("commit",),
        )
    return None


def check_commit_message(message: str) -> list[Finding]:
    """Validate a commit message's structure and wording."""
    message = message.strip("\n")
    if not message.strip():
        return [
            Finding(
                "commit.empty",
                Severity.HIGH,
                "Commit message is empty.",
                tags=("commit",),
            )
        ]

    lines = message.splitlines()
    subject = lines[0].rstrip()

    findings: list[Finding] = []
    for f in (
        _check_wip(subject),
        _check_subject_length(subject),
        _check_trailing_period(subject),
        _check_conventional(subject),
        _check_blank_line(lines),
        _check_attribution(message),
    ):
        if f is not None:
            findings.append(f)
    return findings


def check_changed_files(paths: list[str]) -> list[Finding]:
    """Flag files that usually shouldn't be committed."""
    findings: list[Finding] = []
    for path in paths:
        if _SENSITIVE_FILE_RE.search(path):
            findings.append(
                Finding(
                    "commit.sensitive-file",
                    Severity.HIGH,
                    "A sensitive file is staged for commit; verify it isn't a secret.",
                    path=path,
                    tags=("commit", "secret"),
                )
            )
    return findings


def check_guardrail_changes(paths: list[str]) -> list[Finding]:
    """Flag changes to rein's own config or hooks."""
    findings: list[Finding] = []
    for path in paths:
        if _GUARDRAIL_FILE_RE.search(path):
            findings.append(
                Finding(
                    "commit.guardrail-modified",
                    Severity.HIGH,
                    "A rein guardrail file was modified; verify the guardrail was not weakened (rule disabled, severity lowered, detector or baseline changed).",
                    path=path,
                    tags=("commit", "guardrail"),
                )
            )
    return findings


def check_commit(message: str, changed_files: list[str] | None = None) -> list[Finding]:
    """Run all commit checks together."""
    findings = check_commit_message(message)
    if changed_files:
        findings.extend(check_changed_files(changed_files))
        findings.extend(check_guardrail_changes(changed_files))
        findings.extend(scan_junk_paths(changed_files))
    return findings
