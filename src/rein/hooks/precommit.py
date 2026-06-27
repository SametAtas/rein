"""Git ``pre-commit`` hook adapter.

CONTRACT: do not change the signatures or the test expectations.
Implement the two functions below so that ``tests/test_precommit.py`` passes.

Design follows the project rule (see CONTRIBUTING.md): ``evaluate`` is pure and fully
unit-tested; ``main`` is the thin git/I-O wrapper around it.
"""

from __future__ import annotations

import subprocess

from ..core.commits import check_changed_files, check_commit_message, check_guardrail_changes
from ..core.findings import Finding
from ..core.junk import scan_junk_paths
from ..core.secrets import scan_text
from ..report import render, worst_exit_code


def evaluate(staged_files: dict[str, str], message: str | None) -> list[Finding]:
    """Run every pre-commit check over the staged content and commit message.

    Pure function: no git calls, no printing, no ``sys.exit``.

    Args:
        staged_files: Maps a file path to the exact content that is staged for
            commit (i.e. what ``git show :<path>`` would return). This is the
            staged blob, NOT the working-tree file.
        message: The proposed commit message, or ``None`` to skip message checks
            (e.g. when running an ad-hoc content scan).

    Required behavior:
        * For each staged file, scan its content for secrets
          (``rein.core.secrets.scan_text``), passing the path so findings are
          located correctly.
        * Run sensitive-file checks over the set of staged paths
          (``rein.core.commits.check_changed_files``).
        * If ``message`` is not ``None``, also run
          ``rein.core.commits.check_commit_message`` on it.
        * Return the combined list of findings. Return ``[]`` when clean.
    """
    findings: list[Finding] = []

    for path, content in staged_files.items():
        findings.extend(scan_text(content, path=path))

    findings.extend(check_changed_files(list(staged_files.keys())))
    findings.extend(check_guardrail_changes(list(staged_files.keys())))
    findings.extend(scan_junk_paths(list(staged_files.keys())))

    if message is not None:
        findings.extend(check_commit_message(message))

    return findings


def main(argv: list[str] | None = None) -> int:
    """Entry point invoked by git as ``.git/hooks/pre-commit``.

    Required behavior:
        * Collect staged paths with ``git diff --cached --name-only``.
        * For each, read the staged blob with ``git show :<path>`` (skip paths
          that are binary/unreadable, mirroring ``secrets.scan_file``).
        * Read the proposed message from the path given as the first CLI arg if
          present (git passes the message file to ``commit-msg``; for a plain
          ``pre-commit`` invocation ``message`` may be ``None``).
        * Call ``evaluate``, then ``rein.report.render`` the findings and
          return ``rein.report.worst_exit_code(findings)`` so a HIGH+ finding
          blocks the commit.
    """
    diff_result = subprocess.run(
        ["git", "diff", "--cached", "--name-only"],
        capture_output=True,
        text=True,
        check=True,
    )
    paths = [p for p in diff_result.stdout.splitlines() if p]

    staged_files: dict[str, str] = {}
    for path in paths:
        try:
            blob = subprocess.run(
                ["git", "show", f":{path}"],
                capture_output=True,
                check=True,
            )
            staged_files[path] = blob.stdout.decode("utf-8")
        except (subprocess.CalledProcessError, UnicodeDecodeError):
            continue

    message: str | None = None
    if argv:
        try:
            with open(argv[0], encoding="utf-8") as fh:
                message = fh.read()
        except (OSError, UnicodeDecodeError):
            pass

    findings = evaluate(staged_files, message)
    render(findings)
    return worst_exit_code(findings)


if __name__ == "__main__":
    import sys

    sys.exit(main(sys.argv[1:]))
