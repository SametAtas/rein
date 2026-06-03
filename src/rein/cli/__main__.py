"""`rein` command line.

This is a thin adapter: it gathers input (files, git state), calls the pure
checks in :mod:`rein.core`, renders the resulting findings, and chooses an
exit code. All real logic lives in core so the MCP server and git hook can
reuse it unchanged.

Subcommands:
    rein scan [PATH ...]        Scan files/dirs for leaked secrets.
    rein commit-check [-m MSG]  Check a commit message + staged files.
"""

from __future__ import annotations

import argparse
import sys
from typing import Any

from .. import __version__
from .commands import (
    cmd_baseline,
    cmd_commit_check,
    cmd_drift,
    cmd_learn,
    cmd_lint,
    cmd_scan,
    cmd_review,
    cmd_security,
)


def _format_parent() -> argparse.ArgumentParser:
    parent = argparse.ArgumentParser(add_help=False)
    parent.add_argument(
        "--format", choices=["text", "json", "sarif"], default="text",
        help="Output format (default: text).",
    )
    return parent


def _add_basic_parsers(sub: Any, fmt_parent: argparse.ArgumentParser) -> None:
    p_scan = sub.add_parser("scan", help="Scan files/dirs for leaked secrets.", parents=[fmt_parent])
    p_scan.add_argument("paths", nargs="*", help="Files or directories (default: .).")
    p_scan.add_argument("--diff", action="store_true", help="Read a unified diff from stdin and scan only added lines.")
    p_scan.set_defaults(func=cmd_scan)

    p_commit = sub.add_parser("commit-check", help="Check a commit message + staged files.", parents=[fmt_parent])
    p_commit.add_argument("-m", "--message", help="Commit message text.")
    p_commit.add_argument("-F", "--message-file", help="Read the message from a file.")
    p_commit.set_defaults(func=cmd_commit_check)

    p_lint = sub.add_parser("lint", help="Lint Python files.", parents=[fmt_parent])
    p_lint.add_argument("paths", nargs="*", help="Files or directories (default: .).")
    p_lint.add_argument("--ruff", action="store_true", help="Run ruff alongside core rules.")
    p_lint.set_defaults(func=cmd_lint)

    p_sec = sub.add_parser("security", help="Scan Python files for unsafe-code patterns.", parents=[fmt_parent])
    p_sec.add_argument("paths", nargs="*", help="Files or directories (default: .).")
    p_sec.set_defaults(func=cmd_security)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rein",
        description="Guardrails that keep AI-written code clean and secure.",
    )
    parser.add_argument("--version", action="version", version=f"rein {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    fmt_parent = _format_parent()
    _add_basic_parsers(sub, fmt_parent)

    p_review = sub.add_parser("review", help="Run all guardrails and return a verdict.", parents=[fmt_parent])
    p_review.add_argument("paths", nargs="*", help="Files or directories (default: .).")
    p_review.add_argument("--diff", action="store_true", help="Read a unified diff from stdin; review only added lines (file content read from the working tree).")
    p_review.add_argument("--explain", action="store_true", help="Show how to fix each finding.")
    p_review.add_argument("--baseline", help="Suppress findings recorded in this baseline file.")
    p_review.add_argument("--config", help="Path to .rein.toml configuration file.")
    p_review.add_argument("--bandit", action="store_true", help="Run bandit alongside core rules.")
    p_review.add_argument("--gitleaks", action="store_true", help="Run gitleaks alongside core rules.")
    p_review.add_argument("--semgrep", action="store_true", help="Run semgrep alongside core rules.")
    p_review.set_defaults(func=cmd_review)

    p_base = sub.add_parser("baseline", help="Record current findings as an accepted baseline.")
    p_base.add_argument("paths", nargs="*", help="Files or directories (default: .).")
    p_base.add_argument("-o", "--output", default=None, help="Output file (default: .rein-baseline.json).")
    p_base.set_defaults(func=cmd_baseline)

    p_learn = sub.add_parser("learn", help="Measure conventions and draft a profile.")
    p_learn.add_argument("paths", nargs="*", help="Files or directories (default: .).")
    p_learn.add_argument("-o", "--output", help="Output file to write draft (default: stdout).")
    p_learn.set_defaults(func=cmd_learn)

    p_drift = sub.add_parser("drift", help="Check convention profile drift.")
    p_drift.add_argument("paths", nargs="*", help="Files or directories (default: .).")
    p_drift.set_defaults(func=cmd_drift)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
