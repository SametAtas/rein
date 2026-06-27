"""Run external code scanners (ruff, bandit, gitleaks, semgrep) and adapt them.

These scanners are external processes, so this is an I/O module and lives OUTSIDE
the pure core (which may do no I/O). It invokes each scanner over file targets and
turns the output into ``Finding`` objects via the pure core parsers. Fail-open: a
missing or failing scanner is skipped with a note, never fatal.

Two entry points share one runner registry (no duplicated invocation logic):
  - ``run_detectors(targets, tools)`` - scan files/dirs on disk (used by the CLI).
  - ``scan_content(text, path, tools)`` - scan in-memory content by writing it to a
    temp file first (used by agent adapters that gate a tool call before it runs).
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from collections.abc import Iterable
from dataclasses import replace

from .core import bandit, gitleaks, ruff, semgrep
from .core.findings import Finding

DETECTOR_TIMEOUT = 60  # seconds; a detector must not hang the review


def _run_stdout_detector(cmd: list[str]) -> str:
    """Run a detector that writes JSON to stdout; fail open on any failure."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=DETECTOR_TIMEOUT)
        return proc.stdout
    except FileNotFoundError:
        print(f"rein: {cmd[0]} not found; skipping.", file=sys.stderr)
        return ""
    except subprocess.TimeoutExpired:
        print(f"rein: {cmd[0]} timed out after {DETECTOR_TIMEOUT}s; skipping.", file=sys.stderr)
        return ""
    except OSError as exc:
        print(f"rein: {cmd[0]} failed ({exc}); skipping.", file=sys.stderr)
        return ""


def _run_ruff(targets: list[str]) -> str:
    return _run_stdout_detector(["ruff", "check", "--output-format=json", *targets])


def _run_bandit(targets: list[str]) -> str:
    return _run_stdout_detector(["bandit", "-r", "-f", "json", "-q", *targets])


def _run_gitleaks(targets: list[str]) -> str:
    report = ""
    try:
        fd, report = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        subprocess.run(
            ["gitleaks", "dir", *targets, "--report-format", "json", "--report-path", report, "--no-banner"],
            capture_output=True,
            timeout=DETECTOR_TIMEOUT,
        )
        with open(report, encoding="utf-8") as fh:
            return fh.read()
    except FileNotFoundError:
        print("rein: gitleaks not found; skipping gitleaks checks.", file=sys.stderr)
        return ""
    except subprocess.TimeoutExpired:
        print(f"rein: gitleaks timed out after {DETECTOR_TIMEOUT}s; skipping.", file=sys.stderr)
        return ""
    except OSError as exc:
        print(f"rein: gitleaks failed ({exc}); skipping.", file=sys.stderr)
        return ""
    finally:
        if report and os.path.exists(report):
            try:
                os.unlink(report)
            except OSError:
                pass


def _run_semgrep(targets: list[str]) -> str:
    return _run_stdout_detector(["semgrep", "--json", "--quiet", "--config", "auto", *targets])


# name -> (runner over file targets, pure parser of its output). The single
# source of truth for which external scanners rein knows and how it invokes them.
# Runners are wrapped in a lambda so the call resolves the module-level function
# at call time, which keeps each runner independently patchable in tests.
DETECTORS = {
    "ruff": (lambda t: _run_ruff(t), ruff.parse_ruff_output),
    "bandit": (lambda t: _run_bandit(t), bandit.parse_bandit_output),
    "gitleaks": (lambda t: _run_gitleaks(t), gitleaks.parse_gitleaks_output),
    "semgrep": (lambda t: _run_semgrep(t), semgrep.parse_semgrep_output),
}


def run_detectors(targets: Iterable[str], tools: Iterable[str]) -> list[Finding]:
    """Run the named detectors over file/dir targets and return their Findings.

    Unknown names are ignored; each detector fails open independently.
    """
    target_list = list(targets)
    findings: list[Finding] = []
    for name in tools:
        entry = DETECTORS.get(name)
        if entry is None:
            continue
        runner, parser = entry
        findings.extend(parser(runner(target_list)))
    return findings


def scan_content(text: str, path: str | None = None, *, tools: Iterable[str]) -> list[Finding]:
    """Run the named scanners over in-memory content via a temp file.

    Lets an agent guardrail apply the full external-scanner depth to the code a
    tool is ABOUT to write or run, before it touches disk. The content is written
    into a throwaway directory (so directory-oriented scanners like gitleaks work)
    and each finding's path is mapped back to ``path`` for a readable message.
    Returns [] when no tools are requested.
    """
    tool_list = list(tools)
    if not tool_list or not text.strip():
        return []
    suffix = os.path.splitext(path)[1] if path else ""
    name = os.path.basename(path) if path else f"content{suffix or '.py'}"
    with tempfile.TemporaryDirectory(prefix="rein-scan-") as tmp:
        file_path = os.path.join(tmp, name)
        with open(file_path, "w", encoding="utf-8") as fh:
            fh.write(text)
        findings = run_detectors([tmp], tool_list)
    label = path or name
    return [replace(f, path=label) for f in findings]
