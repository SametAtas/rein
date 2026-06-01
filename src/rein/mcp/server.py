"""MCP server adapter: exposes rein checks over the Model Context Protocol.

This is a thin wrapper. Detection logic lives in ``core``; the pure tool
functions live in ``tools.py``. This module only wires them into the SDK.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from . import tools

mcp = FastMCP("rein")


@mcp.tool()
def scan_secrets(text: str, path: str | None = None) -> list[dict]:
    """Scan text for leaked secrets; returns finding dicts."""
    return tools.scan_secrets(text, path)


@mcp.tool()
def check_commit(
    message: str, changed_files: list[str] | None = None
) -> list[dict]:
    """Check a commit message and changed files; returns finding dicts."""
    return tools.check_commit(message, changed_files)


@mcp.tool()
def lint_code(text: str, path: str | None = None) -> list[dict]:
    """Run pure AST and line-based lint rules over Python source."""
    return tools.lint_code(text, path)


@mcp.tool()
def scan_diff(diff_text: str) -> list[dict]:
    """Scan only added lines in a unified diff for secrets."""
    return tools.scan_diff(diff_text)


@mcp.tool()
def check_security(text: str, path: str | None = None) -> list[dict]:
    """Flag unsafe-code patterns in Python source."""
    return tools.check_security(text, path)


@mcp.tool()
def review_code(text: str, path: str | None = None, config: dict | None = None) -> dict:
    """Run all guardrails and return a structured ReviewResult dict."""
    return tools.review_code(text, path, config)


@mcp.tool()
def review_diff(new_text: str, diff_text: str, path: str | None = None, config: dict | None = None) -> dict:
    """Review only the lines a diff adds (for an agent checking its own patch)."""
    return tools.review_diff(new_text, diff_text, path, config)


@mcp.tool()
def suggest_fixes(text: str, path: str | None = None) -> list[dict]:
    """Review an artifact and return each finding with its remediation guidance."""
    return tools.suggest_fixes(text, path)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
