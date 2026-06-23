"""Path-string helpers shared across checks.

A leaf module (stdlib only, imports nothing from rein) so every core check can
normalize paths the same way. These operate on path STRINGS, not the filesystem:
backslashes are folded to forward slashes so checks behave identically on
Windows-style and POSIX-style paths.
"""

from __future__ import annotations


def normalize_path(path: str) -> str:
    """Fold backslashes to forward slashes for consistent string matching."""
    return path.replace("\\", "/")


def path_basename(path: str) -> str:
    """The final component of a path (after the last slash)."""
    return normalize_path(path).rsplit("/", 1)[-1]


def path_parts(path: str) -> list[str]:
    """The path split into its slash-separated components."""
    return normalize_path(path).split("/")
