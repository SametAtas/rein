"""Detect leaked credentials in text, files, or diffs.

Two complementary strategies:

1. Pattern rules: high-confidence regexes for credentials with a known shape
   (AWS keys, GitHub tokens, PEM private keys, and so on). Low false-positive.
2. Entropy heuristic: catches generic ``secret = "<random>"`` assignments
   that don't match a known vendor shape, by measuring randomness of the value.

Both return :class:`~rein.core.findings.Finding` objects with the secret
**redacted** in the snippet, so results are safe to log or send to an agent.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

from .diffs import parse_added_lines
from .findings import Finding, Severity
from .pragmas import filter_by_pragma


@dataclass(frozen=True)
class PatternRule:
    rule_id: str
    severity: Severity
    description: str
    pattern: re.Pattern[str]


# High-confidence vendor patterns. Keep these tight: a false positive that
# blocks a commit erodes trust in the whole tool faster than a missed match.
PATTERN_RULES: list[PatternRule] = [
    PatternRule(
        "secret.aws-access-key",
        Severity.CRITICAL,
        "AWS access key ID",
        re.compile(r"\b((?:AKIA|ASIA|AGPA|AIDA|AROA)[A-Z0-9]{16})\b"),
    ),
    PatternRule(
        "secret.github-token",
        Severity.CRITICAL,
        "GitHub token",
        re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,255})\b"),
    ),
    PatternRule(
        "secret.openai-key",
        Severity.CRITICAL,
        "OpenAI API key",
        re.compile(r"\b(sk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{20,})\b"),
    ),
    PatternRule(
        "secret.anthropic-key",
        Severity.CRITICAL,
        "Anthropic API key",
        re.compile(r"\b(sk-ant-[A-Za-z0-9_-]{20,})\b"),
    ),
    PatternRule(
        "secret.stripe-key",
        Severity.CRITICAL,
        "Stripe secret key",
        re.compile(r"\b(sk_live_[A-Za-z0-9]{24})\b"),
    ),
    PatternRule(
        "secret.gitlab-pat",
        Severity.CRITICAL,
        "GitLab personal access token",
        re.compile(r"\b(glpat-[A-Za-z0-9_-]{20})\b"),
    ),
    PatternRule(
        "secret.sendgrid-key",
        Severity.HIGH,
        "SendGrid API key",
        re.compile(r"\b(SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,})\b"),
    ),
    PatternRule(
        "secret.npm-token",
        Severity.HIGH,
        "npm access token",
        re.compile(r"\b(npm_[A-Za-z0-9]{36})\b"),
    ),
    PatternRule(
        "secret.slack-token",
        Severity.HIGH,
        "Slack token",
        re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b"),
    ),
    PatternRule(
        "secret.google-api-key",
        Severity.HIGH,
        "Google API key",
        re.compile(r"\b(AIza[A-Za-z0-9_-]{35})\b"),
    ),
    PatternRule(
        "secret.private-key",
        Severity.CRITICAL,
        "Private key block",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    ),
    PatternRule(
        "secret.jwt",
        Severity.MEDIUM,
        "JSON Web Token",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    ),
]

# Generic ``name = "value"`` assignments where the name looks sensitive.
# We only flag these when the value also looks random (see _looks_secret).
_ASSIGNMENT_RE = re.compile(
    r"""(?P<key>[A-Za-z0-9_.\-]*
            (?:secret|passwd|password|token|api[_-]?key|access[_-]?key|
               auth|credential|private[_-]?key)
         [A-Za-z0-9_.\-]*)
        \s*[:=]\s*
        (?P<quote>['"]?)(?P<value>[^'"\s]{8,})(?P=quote)
    """,
    re.IGNORECASE | re.VERBOSE,
)

# Obvious placeholders that should never be flagged.
_PLACEHOLDER_RE = re.compile(
    r"^(?:x{3,}|\*{3,}|\.{3,}|<.*>|\{\{?.*\}?\}|your[_-].*|example.*|"
    r"changeme|placeholder|dummy|fake|test|none|null|true|false)$",
    re.IGNORECASE,
)

ENTROPY_THRESHOLD = 3.5  # bits/char; random-ish strings sit above ~3.5


def shannon_entropy(value: str) -> float:
    """Shannon entropy in bits per character. Higher == more random."""
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def redact(value: str, keep: int = 4) -> str:
    """Mask the middle of a secret, keeping a few edge chars for recognizability."""
    if len(value) <= keep * 2:
        return "*" * len(value)
    return f"{value[:keep]}{'*' * (len(value) - keep * 2)}{value[-keep:]}"


def _looks_secret(value: str) -> bool:
    if _PLACEHOLDER_RE.match(value):
        return False
    if any(ch in value for ch in "()[]") or "://" in value:
        return False  # function calls, indexing, and URLs are not literal secrets
    if len(set(value)) < 5:  # e.g. "aaaaaaaa" or "12345678"
        return False
    return shannon_entropy(value) >= ENTROPY_THRESHOLD


def scan_line(line: str, path: str | None = None, line_number: int = 1) -> list[Finding]:
    """Scan a single line for secrets, locating findings at *line_number*.

    Does NOT apply rein:ignore filtering -- the caller decides that, so this
    is reusable by both scan_text (whole blobs) and scan_diff (added lines).
    """
    findings: list[Finding] = []
    for rule in PATTERN_RULES:
        for match in rule.pattern.finditer(line):
            secret = match.group(match.lastindex or 0)  # rein:ignore secret.high-entropy-assignment
            findings.append(
                Finding(
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    message=f"Possible {rule.description} committed in source.",
                    path=path,
                    line=line_number,
                    snippet=redact(secret),
                    tags=("secret",),
                )
            )
    for match in _ASSIGNMENT_RE.finditer(line):
        value = match.group("value")
        if _looks_secret(value):
            findings.append(
                Finding(
                    rule_id="secret.high-entropy-assignment",
                    severity=Severity.HIGH,
                    message=(
                        f"Variable '{match.group('key')}' is assigned a "
                        "high-entropy value that looks like a hardcoded secret."
                    ),
                    path=path,
                    line=line_number,
                    snippet=f"{match.group('key')} = {redact(value)}",
                    tags=("secret", "heuristic"),
                )
            )
    return findings


def scan_text(text: str, path: str | None = None) -> list[Finding]:
    """Scan a blob of text and return all secret findings.

    Lines containing a ``rein:ignore`` pragma have their findings suppressed.
    A bare pragma silences every rule; a scoped one (``rein:ignore id1, id2``)
    silences only the listed ids.
    """
    findings: list[Finding] = []
    lines = text.splitlines()
    for lineno, line in enumerate(lines, start=1):
        line_findings = scan_line(line, path, lineno)
        findings.extend(filter_by_pragma(line_findings, line))
    return findings


def scan_file(path: str) -> list[Finding]:
    """Scan a single file, skipping binaries gracefully."""
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    except (UnicodeDecodeError, OSError):
        return []  # binary or unreadable; nothing text-based to scan
    return scan_text(text, path=path)


def scan_diff(diff_text: str) -> list[Finding]:
    """Scan only the lines a unified diff adds, ignoring removed/context lines.

    Useful for guarding exactly what an agent just wrote. Honors a rein:ignore
    pragma on the added line itself.
    """
    findings: list[Finding] = []
    for added in parse_added_lines(diff_text):
        line_findings = scan_line(added.text, path=added.path, line_number=added.line)
        findings.extend(filter_by_pragma(line_findings, added.text))
    return findings
