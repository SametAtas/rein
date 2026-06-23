"""Contract for inline ignore pragmas in the secret scanner.

A `rein:ignore` comment on a line suppresses findings on that line. A bare
pragma suppresses everything on the line; a scoped pragma lists the rule ids it
silences. These tests define the behavior; the implementation must make them
pass without changing them.
"""

from rein.core import secrets

AWS = "AKIAIOSFODNN7EXAMPLE"  # rein:ignore


def _ids(findings):
    return {f.rule_id for f in findings}


def test_bare_pragma_suppresses_all_on_line():
    assert secrets.scan_text(f'aws = "{AWS}"  # rein:ignore') == []


def test_scoped_pragma_suppresses_named_rule():
    assert secrets.scan_text(f'aws = "{AWS}"  # rein:ignore secret.aws-access-key') == []


def test_scoped_pragma_leaves_other_rules_active():
    findings = secrets.scan_text(f'aws = "{AWS}"  # rein:ignore secret.github-token')
    assert "secret.aws-access-key" in _ids(findings)


def test_pragma_accepts_a_comma_separated_list():
    line = f'k = "{AWS}"  # rein:ignore secret.github-token, secret.aws-access-key'
    assert secrets.scan_text(line) == []


def test_pragma_only_affects_its_own_line():
    text = f'a = "{AWS}"  # rein:ignore\nb = "{AWS}"\n'
    findings = secrets.scan_text(text)
    assert "secret.aws-access-key" in _ids(findings)
    assert all(f.line == 2 for f in findings)


def test_line_without_pragma_is_unaffected():
    assert "secret.aws-access-key" in _ids(secrets.scan_text(f'a = "{AWS}"'))
