"""Baseline fingerprinting: accept current findings, block only new ones.

The fingerprint excludes line numbers so a finding survives code moving around;
it keys on the rule, the file, and the finding's content (redacted snippet, or
message when there is no snippet). Stored as a hash so the file leaks nothing.
"""

from __future__ import annotations

import hashlib

from .findings import Finding


def fingerprint(finding: Finding) -> str:
    """Stable id for a finding, independent of its line number.

    Uses the redacted snippet when present (distinguishes e.g. two different
    secrets in one file), else the message (carries the function/var name for
    snippet-less findings). Line is deliberately excluded so the fingerprint
    survives code shifting up or down.
    """
    content = finding.snippet if finding.snippet is not None else finding.message
    raw = f"{finding.rule_id}\0{finding.path or ''}\0{content}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def make_baseline(findings: list[Finding]) -> list[dict]:
    """Build de-duplicated, serializable baseline entries from current findings.

    Each entry carries rule_id and path for human auditing plus the fingerprint
    used for matching. No raw secret values are stored.
    """
    entries: dict[str, dict] = {}
    for f in findings:
        fp = fingerprint(f)
        entries[fp] = {"rule_id": f.rule_id, "path": f.path, "fingerprint": fp}
    return list(entries.values())


def apply_baseline(
    findings: list[Finding], fingerprints: set[str],
) -> list[Finding]:
    """Drop findings whose fingerprint is in the baseline; keep the rest."""
    return [f for f in findings if fingerprint(f) not in fingerprints]
