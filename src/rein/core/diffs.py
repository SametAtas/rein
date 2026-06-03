"""Parse unified diffs to extract only the lines that were added.

This is the foundation for scanning just what an agent wrote, ignoring
pre-existing code. The parser handles standard unified/git diffs and
tracks new-file line numbers accurately through hunks.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(?P<start>\d+)(?:,\d+)? @@")


@dataclass(frozen=True)
class AddedLine:
    """One line added by a diff, with its location in the new (post-image) file."""

    path: str | None
    line: int
    text: str


def _process_hunk_line(
    raw_line: str,
    current_path: str | None,
    new_lineno: int,
) -> tuple[AddedLine | None, int]:
    """Classify a line within a hunk and return any addition plus the next line number."""
    if raw_line.startswith("\\"):
        return None, new_lineno
    if raw_line.startswith("+"):
        added = AddedLine(
            path=current_path,
            line=new_lineno,
            text=raw_line[1:],
        )
        return added, new_lineno + 1
    if raw_line.startswith("-"):
        return None, new_lineno
    return None, new_lineno + 1


def parse_added_lines(diff_text: str) -> list[AddedLine]:
    """Extract every added line from a unified diff, with correct line numbers.

    Handles multiple files and multiple hunks per file. Removed and context
    lines are tracked for line-number accounting but not returned.
    """
    added: list[AddedLine] = []
    current_path: str | None = None
    new_lineno: int = 0
    in_hunk = False

    for raw_line in diff_text.splitlines():
        if raw_line.startswith("+++ "):
            path_part = raw_line[4:]
            # Strip tab and anything after (timestamps in some diff formats)
            path_part = path_part.split("\t", 1)[0]
            # Strip leading a/ or b/ prefix from git diffs
            if path_part.startswith("a/") or path_part.startswith("b/"):
                path_part = path_part[2:]
            current_path = None if path_part == "/dev/null" else path_part
            in_hunk = False
            continue

        if raw_line.startswith("--- "):
            continue

        hunk_match = _HUNK_RE.match(raw_line)
        if hunk_match:
            new_lineno = int(hunk_match.group("start"))
            in_hunk = True
            continue

        if not in_hunk:
            continue

        added_line, new_lineno = _process_hunk_line(raw_line, current_path, new_lineno)
        if added_line is not None:
            added.append(added_line)

    return added
