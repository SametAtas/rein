"""Remediation guidance for guardrail findings.

Pure mapping from a Finding to advice. Kept separate from detection so the
engine stays lean. Code rewriting is out of scope; rein only advises.
"""

from __future__ import annotations

from dataclasses import dataclass

from .findings import Finding


@dataclass(frozen=True)
class Remediation:
    """How to fix a finding.

    guidance is one actionable line; safe_example is a short safer code
    snippet where a clear one exists, else None.
    """

    guidance: str
    safe_example: str | None = None


# Per-rule guidance. Keep each entry to one compact line.
_RULES: dict[str, Remediation] = {
    # commit.*
    "commit.empty": Remediation("Write a non-empty commit message."),
    "commit.wip-marker": Remediation("Remove the WIP/fixup/temp marker before committing."),
    "commit.subject-too-long": Remediation("Shorten the subject to 72 characters or fewer."),
    "commit.subject-trailing-period": Remediation("Drop the trailing period from the subject."),
    "commit.not-conventional": Remediation("Prefix the subject with a Conventional Commit type.", "feat: add token refresh"),
    "commit.no-blank-line": Remediation("Separate the subject and body with a blank line."),
    "commit.sensitive-file": Remediation("Do not commit this file; add it to .gitignore and remove it from staging."),
    # lint.*
    "lint.syntax-error": Remediation("Fix the syntax error so the file parses."),
    "lint.missing-future-import": Remediation("Add 'from __future__ import annotations' at the top of the module.", "from __future__ import annotations"),
    "lint.missing-type-hints": Remediation("Add type annotations to the parameters and return value."),
    "lint.function-too-long": Remediation("Split the function into smaller, focused functions."),
    "lint.file-too-long": Remediation("Split the module into smaller files by responsibility."),
    "lint.todo-comment": Remediation("Resolve the TODO/FIXME or move it to an issue tracker."),  # rein:ignore lint.todo-comment
    "lint.stub-body": Remediation("Implement the function body or remove the stub."),
    "lint.non-ascii": Remediation("Replace non-ASCII characters with plain ASCII."),
    # security.*
    "security.eval-exec": Remediation("Avoid eval/exec; parse data explicitly.", "ast.literal_eval(value)"),
    "security.pickle-load": Remediation("Do not unpickle untrusted data; use a safe format.", "json.loads(data)"),
    "security.os-system": Remediation("Use subprocess with a list and shell=False.", 'subprocess.run(["ls", "-l"])'),
    "security.subprocess-shell": Remediation("Pass a list of args and shell=False.", 'subprocess.run(["ls", "-l"])'),
    "security.yaml-unsafe-load": Remediation("Use yaml.safe_load.", "yaml.safe_load(stream)"),
    "security.requests-no-verify": Remediation("Remove verify=False so TLS certificates are checked.", "requests.get(url)"),
    "security.weak-hash": Remediation("Use SHA-256 or stronger for security purposes.", "hashlib.sha256(data)"),
    "security.insecure-temp": Remediation("Use tempfile.mkstemp or NamedTemporaryFile.", "tempfile.mkstemp()"),
}

# Fallback by category prefix (rule_id before the first dot).
_CATEGORY: dict[str, Remediation] = {
    "secret": Remediation(
        "Remove the secret from source, rotate it, and load it from the environment.",
        'os.environ.get("API_KEY")',
    ),
    "ruff": Remediation("Apply the fix from the ruff rule documentation for this code."),
}


def suggest_fix(finding: Finding) -> Remediation | None:
    """Return remediation guidance for a finding, or None if none is known.

    Exact rule_id match first, then a category-prefix fallback so whole
    families (secret.*, ruff.*) are covered by one entry.
    """
    fix = _RULES.get(finding.rule_id)
    if fix is None:
        fix = _CATEGORY.get(finding.rule_id.split(".", 1)[0])
    return fix
