"""Junk file / anti-slop detection.

Scans paths to identify likely throwaway files such as editor cruft, backup
files, duplicate copies, and scratch placeholders. Designed with a strict
warning-only severity to preserve trust and prevent blocking legitimate commits.
"""

from __future__ import annotations

import re

from .findings import Finding, Severity

# junk.os-cruft
# .DS_Store, Thumbs.db, desktop.ini, *.swp, *.swo, *.pyc, *.pyo, or __pycache__/ in path
_OS_CRUFT_RE = re.compile(
    r"(^|/)(?:\.DS_Store|Thumbs\.db|desktop\.ini|__pycache__/.*|.*\.sw[po]|.*\.py[co])$",
    re.IGNORECASE,
)

# junk.backup-file
# extension .bak, .backup, .orig, .tmp
# trailing ~
# copy markers in the basename: ' (1)', ' (2)', ' copy', '(copy)'
# duplicate suffix before the extension: _copy, _backup, _bak, _orig, _old
_BACKUP_FILE_RE = re.compile(
    r"(?:~|\.(?:bak|backup|orig|tmp)|"
    r" \(\d+\)(?:\.[^/.]+)?| copy(?:\.[^/.]+)?|\(copy\)(?:\.[^/.]+)?|"
    r"_(?:copy|backup|bak|orig|old)(?:\.[^/.]+)?)$",
    re.IGNORECASE,
)

# junk.scratch-file
# basename stem exactly one of: temp, tmp, scratch, untitled, foo, bar, baz,
# qux, asdf, placeholder, deleteme, delete_me
_SCRATCH_STEMS = frozenset([
    "temp", "tmp", "scratch", "untitled", "foo", "bar", "baz", "qux",
    "asdf", "placeholder", "deleteme", "delete_me"
])


def _check_junk_path(path: str) -> Finding | None:
    basename = path.rsplit("/", 1)[-1]

    if _OS_CRUFT_RE.search(path):
        return Finding(
            "junk.os-cruft",
            Severity.MEDIUM,
            "Looks like an editor/OS artifact; it usually should not be committed.",
            path=path,
            tags=("junk",),
        )

    if _BACKUP_FILE_RE.search(basename):
        return Finding(
            "junk.backup-file",
            Severity.MEDIUM,
            "Looks like a backup or duplicate file (agents often leave these behind); remove it or rename it intentionally.",
            path=path,
            tags=("junk",),
        )

    if "." in basename and not basename.startswith("."):
        stem = basename.rsplit(".", 1)[0]
    else:
        stem = basename

    if stem.lower() in _SCRATCH_STEMS:
        return Finding(
            "junk.scratch-file",
            Severity.LOW,
            "Looks like a scratch/placeholder filename; rename it to something intentional or remove it.",
            path=path,
            tags=("junk",),
        )

    return None


def scan_junk_paths(paths: list[str]) -> list[Finding]:
    """Scan the given file paths for junk/slop filenames.

    Returns at most one Finding per path, picking the most severe match.
    """
    findings: list[Finding] = []
    for path in paths:
        f = _check_junk_path(path)
        if f:
            findings.append(f)
    return findings
