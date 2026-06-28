"""Flag a secret-named variable passed straight to an output sink.

A name-level steering check for the agent-loop "about to leak the secret to logs
or stdout" case (``print(token)``, ``logging.info(api_key)``). It complements
the value-matching rules in :mod:`rein.core.secrets`: those look at a value's
shape, this one looks at where a sensitively-named variable flows.
"""

from __future__ import annotations

import ast
import re

from .findings import Finding, Severity
from .parsing import safe_parse
from .pragmas import filter_by_pragma


# -- AST check: a secret-named variable passed straight to an output sink -----
#
# The "agent about to leak the secret to logs or stdout" case. Name-only (there
# is no value to entropy-check), so the heuristic is deliberately stricter than
# the assignment rule: polysemous stems ("auth", bare "key") are excluded to
# keep false positives near zero.

_LOG_LEVELS = frozenset(
    {"debug", "info", "warning", "warn", "error", "exception", "critical", "log"}
)
_LOG_RECEIVERS = frozenset({"logging", "logger", "log"})
_SECRET_WORDS = frozenset(
    {
        "secret", "secrets", "password", "passwd", "passphrase",
        "token", "tokens", "apikey", "credential", "credentials",
    }
)
_KEY_QUALIFIERS = frozenset(
    {"api", "access", "private", "secret", "session", "encryption", "signing"}
)
_CAMEL_RE = re.compile(r"([a-z0-9])([A-Z])")


def _name_tokens(name: str) -> set[str]:
    """Lowercased word tokens of an identifier (snake_case and camelCase)."""
    return {t for t in _CAMEL_RE.sub(r"\1_\2", name).lower().split("_") if t}


def _is_secret_var(name: str) -> bool:
    """True if an identifier conservatively names a credential.

    Matches a sensitive whole word (password, token, ...) or 'key' qualified by
    a sensitive stem (api_key, secret_key). Bare 'key' and 'auth' are excluded
    on purpose: primary_key, foreign_key, author, and oauth are not secrets.
    """
    toks = _name_tokens(name)
    if toks & _SECRET_WORDS:
        return True
    return "key" in toks and bool(toks & _KEY_QUALIFIERS)


def _output_sink(func: ast.expr) -> str | None:
    """Name of the output sink a call targets, or None if it is not one.

    Recognizes print(...), logging/logger/log.<level>(...), and
    sys.stdout/stderr.write(...). Conservative: a conventional sink shape only.
    """
    if isinstance(func, ast.Name) and func.id == "print":
        return "print"
    if isinstance(func, ast.Attribute):
        if (
            func.attr in _LOG_LEVELS
            and isinstance(func.value, ast.Name)
            and func.value.id in _LOG_RECEIVERS
        ):
            return f"{func.value.id}.{func.attr}"
        if (
            func.attr == "write"
            and isinstance(func.value, ast.Attribute)
            and func.value.attr in {"stdout", "stderr"}
            and isinstance(func.value.value, ast.Name)
            and func.value.value.id == "sys"
        ):
            return f"sys.{func.value.attr}.write"
    return None


def _secret_arg(call: ast.Call) -> str | None:
    """Name of the first secret-named bare-variable argument to *call*, or None.

    Only a bare Name passed straight in counts ("passed straight to output");
    f-strings, attributes, and nested calls deliberately do not match.
    """
    for arg in call.args:
        if isinstance(arg, ast.Name) and _is_secret_var(arg.id):
            return arg.id
    for kw in call.keywords:
        if isinstance(kw.value, ast.Name) and _is_secret_var(kw.value.id):
            return kw.value.id
    return None


_UNPARSED = object()


def scan_secret_output(text: str, path: str | None = None, *, tree: object = _UNPARSED) -> list[Finding]:
    """Flag a secret-named variable passed straight to an output sink.

    print(token), logging.info(api_key), sys.stderr.write(password). Pure AST,
    single parse (reuses *tree* when provided), pragma-respecting, fail-open on
    a parse error.
    """
    if tree is _UNPARSED:
        tree = safe_parse(text)
    if tree is None:
        return []
    lines = text.splitlines()
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        sink = _output_sink(node.func)
        if sink is None:
            continue
        var = _secret_arg(node)
        if var is None:
            continue
        finding = Finding(
            rule_id="secret.exposed-output",
            severity=Severity.MEDIUM,
            message=(
                f"Secret-named variable '{var}' is passed straight to {sink}(); "
                "it may leak to logs or output."
            ),
            path=path,
            line=node.lineno,
            snippet=f"{sink}({var})",
            tags=("secret", "heuristic"),
        )
        if finding.line is not None and finding.line <= len(lines):
            findings.extend(filter_by_pragma([finding], lines[finding.line - 1]))
        else:
            findings.append(finding)
    return findings
