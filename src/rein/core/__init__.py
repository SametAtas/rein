"""Pure checking logic shared by every adapter (CLI, MCP, git hook)."""

from .findings import Finding, Severity, max_severity

__all__ = ["Finding", "Severity", "max_severity"]
