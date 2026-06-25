"""Labeled accuracy corpus: locks false-positive/negative rates across checks.

Each Case runs one snippet through one check. A positive case (expect=rule_id)
must produce that rule; a negative case (expect=None) must produce no findings
for that check. The corpus is curated, so the engine must get every case right.
"""

from __future__ import annotations

from dataclasses import dataclass

from rein.core import lint, secrets, security


@dataclass(frozen=True)
class Case:
    name: str
    code: str
    check: str            # "secrets" | "security" | "lint"
    expect: str | None    # rule_id that must fire, or None = nothing should fire
    forbid: str | None = None  # rule_id that must NOT fire (optional)


_CHECKS = {
    "secrets": lambda code: secrets.scan_text(code),
    "security": lambda code: security.scan_security(code),
    "lint": lambda code: lint.lint_text(code),
}

_LONG_FN = "from __future__ import annotations\n\ndef big() -> None:\n" + "".join(
    f"    x{i} = {i}\n" for i in range(60)
)

CASES: list[Case] = [
    # --- secrets: positives (each line needs # rein:ignore) ---
    Case("aws key", 'k = "AKIAIOSFODNN7EXAMPLE"', "secrets", "secret.aws-access-key"),  # rein:ignore
    Case("github token", 't = "ghp_0123456789abcdefghijklmnopqrstuvwxyzABCD"', "secrets", "secret.github-token"),  # rein:ignore
    Case("openai key", 'k = "sk-abcdefghijklmnopqrstuvwxyz0123456789"', "secrets", "secret.openai-key"),  # rein:ignore
    Case("anthropic key", 'k = "sk-ant-abcdefghijklmnopqrstuvwxyz0123"', "secrets", "secret.anthropic-key", forbid="secret.openai-key"),  # rein:ignore
    Case("stripe key", 'k = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"', "secrets", "secret.stripe-key"),  # rein:ignore
    Case("gitlab pat", 't = "glpat-0123456789abcdefABCD"', "secrets", "secret.gitlab-pat"),  # rein:ignore
    Case("sendgrid key", 'k = "SG.0123456789abcdef.0123456789ABCDEF0123456789ABCDEF"', "secrets", "secret.sendgrid-key"),  # rein:ignore
    Case("npm token", 't = "npm_0123456789abcdef0123456789abcdef0123"', "secrets", "secret.npm-token"),  # rein:ignore
    Case("slack token", 't = "xoxb-1234567890-abcdefghij"', "secrets", "secret.slack-token"),  # rein:ignore
    Case("google key", 'k = "AIzaSyA1234567890abcdefghijklmnopqrstuv"', "secrets", "secret.google-api-key"),  # rein:ignore
    Case("private key", 's = "-----BEGIN RSA PRIVATE KEY-----"', "secrets", "secret.private-key"),  # rein:ignore
    Case("high-entropy assign", 'password = "f8Kz2pQ9rLmX4tWvB7nA"', "secrets", "secret.high-entropy-assignment"),  # rein:ignore
    # --- secrets: negatives ---
    Case("placeholder key", 'api_key = "your-api-key-here"', "secrets", None),
    Case("xxxx value", 'secret = "xxxxxxxx"', "secrets", None),
    Case("low-entropy", 'token = "aaaaaaaa"', "secrets", None),
    Case("changeme", 'password = "changeme"', "secrets", None),
    Case("normal string", 'name = "hello world"', "secrets", None),
    Case("random but non-sensitive name", 'data = "f8Kz2pQ9rLmX4tWvB7nA"', "secrets", None),
    Case("function call value", 'password = get_password()', "secrets", None),
    Case("env access value", 'password = os.environ["PASS"]', "secrets", None),
    Case("url value", 'auth_url = "https://example.com/oauth/authorize"', "secrets", None),
    Case("dotted call value", 'token = config.get_token()', "secrets", None),
    Case("stripe test key", 'note = "sk_test_4eC39HqLyjWDarjtT1zdp7dc"', "secrets", None),
    Case("gitlab pat short", 'note = "glpat-1234"', "secrets", None),
    Case("sendgrid short segments", 'note = "SG.short.token"', "secrets", None),
    Case("npm token short", 'note = "npm_shorttoken"', "secrets", None),
    # --- security: positives (direct + aliased/from-import) ---
    Case("eval", 'eval("1")', "security", "security.eval-exec"),
    Case("exec", 'exec("x = 1")', "security", "security.eval-exec"),
    Case("os.system direct", 'import os\nos.system("x")', "security", "security.os-system"),
    Case("os.system from-import", 'from os import system\nsystem("x")', "security", "security.os-system"),
    Case("pickle.loads", 'import pickle\npickle.loads(b)', "security", "security.pickle-load"),
    Case("pickle from-import", 'from pickle import loads\nloads(b)', "security", "security.pickle-load"),
    Case("subprocess shell", 'import subprocess\nsubprocess.run("x", shell=True)', "security", "security.subprocess-shell"),
    Case("subprocess aliased shell", 'import subprocess as sp\nsp.run("x", shell=True)', "security", "security.subprocess-shell"),
    Case("yaml.load", 'import yaml\nyaml.load(x)', "security", "security.yaml-unsafe-load"),
    Case("yaml from-import", 'from yaml import load\nload(x)', "security", "security.yaml-unsafe-load"),
    Case("requests verify=False", 'import requests\nrequests.get(u, verify=False)', "security", "security.requests-no-verify"),
    Case("hashlib.md5", 'import hashlib\nhashlib.md5(b)', "security", "security.weak-hash"),
    Case("hashlib aliased sha1", 'import hashlib as h\nh.sha1(b)', "security", "security.weak-hash"),
    Case("hashlib.new md5", 'import hashlib\nhashlib.new("md5")', "security", "security.weak-hash"),
    Case("marshal.loads", 'import marshal\nmarshal.loads(b)', "security", "security.marshal-loads"),
    Case("ssl unverified context", 'import ssl\nssl._create_unverified_context()', "security", "security.ssl-unverified-context"),
    Case("tempfile.mktemp", 'import tempfile\ntempfile.mktemp()', "security", "security.insecure-temp"),
    # --- security: negatives ---
    Case("subprocess no shell", 'import subprocess\nsubprocess.run(["x"])', "security", None),
    Case("yaml.safe_load", 'import yaml\nyaml.safe_load(x)', "security", None),
    Case("requests no verify arg", 'import requests\nrequests.get(u)', "security", None),
    Case("hashlib.sha256", 'import hashlib\nhashlib.sha256(b)', "security", None),
    Case("hashlib.new sha256", 'import hashlib\nhashlib.new("sha256")', "security", None),
    Case("marshal.dumps", 'import marshal\nmarshal.dumps(b)', "security", None),
    Case("ssl default context", 'import ssl\nssl.create_default_context()', "security", None),
    Case("tempfile.mkstemp", 'import tempfile\ntempfile.mkstemp()', "security", None),
    Case("os.path.join", 'import os\nos.path.join("a", "b")', "security", None),
    # --- lint: positives ---
    Case("missing type hints", "from __future__ import annotations\n\ndef foo():\n    return 1\n", "lint", "lint.missing-type-hints"),
    Case("function too long", _LONG_FN, "lint", "lint.function-too-long"),
    Case("todo", "# TODO: fix this\n", "lint", "lint.todo-comment"),  # rein:ignore lint.todo-comment
    Case("stub body", "from __future__ import annotations\n\ndef f() -> None:\n    pass\n", "lint", "lint.stub-body"),
    Case("non-ascii", "# caf\u00e9\n", "lint", "lint.non-ascii"),
    Case("missing future import", "def f() -> int:\n    return 1\n", "lint", "lint.missing-future-import"),
    Case("syntax error", "def f(:\n", "lint", "lint.syntax-error"),
    Case("trailing whitespace", "x = 1   \n", "lint", "lint.trailing-whitespace"),
    # --- lint: negatives ---
    Case("clean annotated fn", "from __future__ import annotations\n\n\ndef f(x: int) -> int:\n    return x\n", "lint", None),
    Case("trivial clean", "x = 1\n", "lint", None),
]


def _rule_ids(case: Case) -> set[str]:
    return {f.rule_id for f in _CHECKS[case.check](case.code)}


def test_accuracy_corpus() -> None:
    """Every curated case must be classified correctly: zero FN, zero FP."""
    false_negatives: list[str] = []   # expected a rule, none fired
    false_positives: list[str] = []   # expected nothing, something fired
    positives = negatives = 0
    for case in CASES:
        ids = _rule_ids(case)
        if case.expect is not None:
            positives += 1
            if case.expect not in ids:
                false_negatives.append(f"{case.name} (wanted {case.expect}, got {sorted(ids)})")
        else:
            negatives += 1
            if ids:
                false_positives.append(f"{case.name} (got {sorted(ids)})")
        if case.forbid is not None and case.forbid in ids:
            false_positives.append(f"{case.name} (forbidden {case.forbid} fired)")
    report = (
        f"corpus={len(CASES)} positives={positives} negatives={negatives} | "
        f"false_negatives={false_negatives} | false_positives={false_positives}"
    )
    assert not false_negatives and not false_positives, report
