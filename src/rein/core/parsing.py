"""Shared safe-parse helper.

A leaf module (stdlib + ast only) so every core check can parse source without
duplicating the same try/except. Returns None on unparseable input instead of
raising, letting callers fail open on broken source.
"""

from __future__ import annotations

import ast


def safe_parse(text: str) -> ast.Module | None:
    """Parse *text*, returning the module or None when it does not parse."""
    try:
        return ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return None
