"""Flag unsafe-code patterns that AI models frequently emit.

Pure AST analysis using only stdlib ``ast``. Each rule targets a specific
dangerous call pattern (eval, pickle, shell injection, etc.) and returns
``Finding`` objects tagged ``("security",)``. Honors ``rein:ignore`` pragmas.

This module is intentionally separate from ``lint.py``: security rules
block commits (HIGH severity), while lint rules are advisory (LOW/INFO).
"""

from __future__ import annotations

import ast

from .findings import Finding, Severity
from .pragmas import filter_by_pragma

# -- messages (kept short to respect file-length budget) ---------------------

_MSG_EVAL = (
    "Use of eval/exec runs arbitrary code;"
    " avoid it or strictly validate input."
)
_MSG_PICKLE = (
    "pickle executes arbitrary code on untrusted data;"
    " use json or a safe format."
)
_MSG_OS_SYSTEM = (
    "os.system/os.popen invokes a shell;"
    " use subprocess with a list and shell=False."
)
_MSG_SUBPROCESS = (
    "subprocess with shell=True risks shell injection;"
    " pass a list and shell=False."
)
_MSG_YAML = (
    "yaml.load without a safe Loader can build arbitrary objects;"
    " use yaml.safe_load."
)
_MSG_REQUESTS = (
    "TLS verification disabled (verify=False);"
    " do not disable certificate checks."
)
_MSG_WEAK_HASH = (
    "MD5/SHA1 are weak;"
    " use SHA-256 or stronger for security uses."
)
_MSG_MARSHAL = (
    "marshal.loads is unsafe on untrusted data;"
    " use json or a safe format."
)
_MSG_INSECURE_TEMP = (
    "tempfile.mktemp is race-prone;"
    " use mkstemp or NamedTemporaryFile."
)
_MSG_SSL_UNVERIFIED = (
    "ssl._create_unverified_context disables certificate checks;"
    " use create_default_context."
)

# dotted-name -> (rule_id, severity, message)
_NAME_RULES: dict[str, tuple[str, Severity, str]] = {
    "eval":            ("security.eval-exec",    Severity.HIGH, _MSG_EVAL),
    "exec":            ("security.eval-exec",    Severity.HIGH, _MSG_EVAL),
    "pickle.load":     ("security.pickle-load",  Severity.HIGH, _MSG_PICKLE),
    "pickle.loads":    ("security.pickle-load",  Severity.HIGH, _MSG_PICKLE),
    "cPickle.load":    ("security.pickle-load",  Severity.HIGH, _MSG_PICKLE),
    "cPickle.loads":   ("security.pickle-load",  Severity.HIGH, _MSG_PICKLE),
    "marshal.loads":   ("security.marshal-loads", Severity.HIGH, _MSG_MARSHAL),
    "os.system":       ("security.os-system",    Severity.HIGH, _MSG_OS_SYSTEM),
    "os.popen":        ("security.os-system",    Severity.HIGH, _MSG_OS_SYSTEM),
    "hashlib.md5":     ("security.weak-hash",    Severity.MEDIUM, _MSG_WEAK_HASH),
    "hashlib.sha1":    ("security.weak-hash",    Severity.MEDIUM, _MSG_WEAK_HASH),
    "ssl._create_unverified_context": (
        "security.ssl-unverified-context", Severity.HIGH, _MSG_SSL_UNVERIFIED,
    ),
    "tempfile.mktemp": ("security.insecure-temp", Severity.MEDIUM, _MSG_INSECURE_TEMP),
}


def _dotted_name(node: ast.expr) -> str | None:
    """Reconstruct a dotted call target, e.g. ``os.system`` or ``eval``."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def _kw_is(call: ast.Call, name: str, value: bool) -> bool:
    """True if *call* has a keyword argument *name* set to the constant *value*."""
    return any(
        k.arg == name
        and isinstance(k.value, ast.Constant)
        and k.value.value is value
        for k in call.keywords
    )


def _has_safe_loader(call: ast.Call) -> bool:
    """True if a yaml.load call has a Loader keyword or a second positional arg."""
    return len(call.args) >= 2 or any(k.arg == "Loader" for k in call.keywords)


def _hashlib_new_is_weak(call: ast.Call) -> bool:
    """True if hashlib.new is called with a weak hash name."""
    if call.args:
        arg = call.args[0]
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            return arg.value.lower() in {"md5", "sha1"}
    for kw in call.keywords:
        if kw.arg == "name" and isinstance(kw.value, ast.Constant):
            if isinstance(kw.value.value, str):
                return kw.value.value.lower() in {"md5", "sha1"}
    return False


def _check_call(
    call: ast.Call, name: str, path: str | None,
) -> Finding | None:
    """Return a Finding for a single call node, or None if it is safe."""
    rule = _NAME_RULES.get(name)
    if rule is not None:
        rule_id, severity, message = rule
        return Finding(
            rule_id=rule_id, severity=severity, message=message,
            path=path, line=call.lineno,
            snippet=f"{name}(...)", tags=("security",),
        )
    if name == "hashlib.new" and _hashlib_new_is_weak(call):
        return Finding(
            rule_id="security.weak-hash", severity=Severity.MEDIUM,
            message=_MSG_WEAK_HASH, path=path, line=call.lineno,
            snippet=f"{name}(...)", tags=("security",),
        )
    if name.startswith("subprocess.") and _kw_is(call, "shell", True):
        return Finding(
            rule_id="security.subprocess-shell", severity=Severity.HIGH,
            message=_MSG_SUBPROCESS, path=path, line=call.lineno,
            snippet=f"{name}(...)", tags=("security",),
        )
    if name == "yaml.load" and not _has_safe_loader(call):
        return Finding(
            rule_id="security.yaml-unsafe-load", severity=Severity.HIGH,
            message=_MSG_YAML, path=path, line=call.lineno,
            snippet="yaml.load(...)", tags=("security",),
        )
    if name.startswith("requests.") and _kw_is(call, "verify", False):
        return Finding(
            rule_id="security.requests-no-verify", severity=Severity.MEDIUM,
            message=_MSG_REQUESTS, path=path, line=call.lineno,
            snippet=f"{name}(...)", tags=("security",),
        )
    return None


def _build_import_map(tree: ast.Module) -> dict[str, str]:
    """Map each locally-bound name to the canonical module/attr it refers to.

    import os                  -> {"os": "os"}
    import os as o             -> {"o": "os"}
    import os.path as p        -> {"p": "os.path"}
    from os import system      -> {"system": "os.system"}
    from subprocess import run as r -> {"r": "subprocess.run"}
    Relative imports (module is None) are skipped.
    """
    imports: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.asname:
                    imports[a.asname] = a.name
                else:
                    top = a.name.split(".")[0]
                    imports[top] = top
        elif isinstance(node, ast.ImportFrom):
            if node.module is None:
                continue
            for a in node.names:
                imports[a.asname or a.name] = f"{node.module}.{a.name}"
    return imports


def _canonical_name(raw: str, imports: dict[str, str]) -> str:
    """Resolve a written call name (e.g. 'o.system', 'system') to its canonical
    dotted name (e.g. 'os.system') using the import map. Falls back to the raw
    name when the head is not an imported binding, so direct calls are unchanged.
    """
    parts = raw.split(".")
    base = imports.get(parts[0])
    if base is None:
        return raw
    rest = parts[1:]
    return f"{base}." + ".".join(rest) if rest else base


_UNPARSED = object()


def scan_security(text: str, path: str | None = None, *, tree: object = _UNPARSED) -> list[Finding]:
    """Flag unsafe-code patterns. If *tree* is provided, reuse it (review parses once)."""
    if tree is _UNPARSED:
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError, RecursionError):
            return []
    if tree is None:
        return []
    lines = text.splitlines()
    imports = _build_import_map(tree)
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        raw = _dotted_name(node.func)
        if raw is None:
            continue
        name = _canonical_name(raw, imports)
        finding = _check_call(node, name, path)
        if finding is None:
            continue
        if finding.line is not None and finding.line <= len(lines):
            findings.extend(filter_by_pragma([finding], lines[finding.line - 1]))
        else:
            findings.append(finding)
    return findings


def scan_security_file(path: str) -> list[Finding]:
    """Analyze a single Python file, skipping binaries gracefully."""
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    except (UnicodeDecodeError, OSError):
        return []
    return scan_security(text, path=path)
