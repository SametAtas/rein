from rein.core import secrets
from rein.core.findings import Severity


def _rule_ids(findings):
    return {f.rule_id for f in findings}


def test_detects_aws_access_key():
    findings = secrets.scan_text('aws_key = "AKIAIOSFODNN7EXAMPLE"')  # rein:ignore
    assert "secret.aws-access-key" in _rule_ids(findings)
    assert all(f.severity == Severity.CRITICAL for f in findings if f.rule_id.endswith("aws-access-key"))


def test_detects_private_key_block():
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n"  # rein:ignore
    assert "secret.private-key" in _rule_ids(secrets.scan_text(text))


def test_detects_stripe_secret_key():
    findings = secrets.scan_text('stripe = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"')  # rein:ignore
    assert "secret.stripe-key" in _rule_ids(findings)


def test_detects_gitlab_pat():
    findings = secrets.scan_text('token = "glpat-0123456789abcdefABCD"')  # rein:ignore
    assert "secret.gitlab-pat" in _rule_ids(findings)


def test_detects_sendgrid_key():
    findings = secrets.scan_text(
        'token = "SG.0123456789abcdef.0123456789ABCDEF0123456789ABCDEF"'  # rein:ignore
    )
    assert "secret.sendgrid-key" in _rule_ids(findings)


def test_detects_npm_token():
    findings = secrets.scan_text(
        'token = "npm_0123456789abcdef0123456789abcdef0123"'  # rein:ignore
    )
    assert "secret.npm-token" in _rule_ids(findings)


def test_high_entropy_assignment_flagged():
    findings = secrets.scan_text('api_key = "f3Kd9xQ2vLm8Zp1Yt7Rb4Nc6Wq0Hs5"')  # rein:ignore
    assert "secret.high-entropy-assignment" in _rule_ids(findings)


def test_dotted_code_reference_not_flagged():
    # A type annotation `name: pkg.Type` reads as `name = pkg.Type` to the
    # assignment heuristic; a dotted code reference is not a literal secret.
    for line in (
        "    _token: vscode.CancellationToken,",
        "  auth_handler: app.security.middleware",
        "private_key: cryptography.hazmat.primitives",
    ):
        assert "secret.high-entropy-assignment" not in _rule_ids(secrets.scan_text(line))


def test_dotted_exclusion_does_not_hide_real_secrets():
    # The exclusion must not weaken detection: undotted opaque values still fire.
    assert "secret.high-entropy-assignment" in _rule_ids(
        secrets.scan_text("API_TOKEN=abcd1234efgh5678ijkl")
    )
    assert "secret.high-entropy-assignment" in _rule_ids(
        secrets.scan_text('api_key = "f3Kd9xQ2vLm8Zp1Yt7Rb4Nc6Wq0Hs5"')  # rein:ignore
    )


def test_placeholder_not_flagged():
    findings = secrets.scan_text('password = "changeme"')
    assert "secret.high-entropy-assignment" not in _rule_ids(findings)


def test_repeated_chars_not_flagged():
    findings = secrets.scan_text('token = "xxxxxxxxxxxx"')
    assert findings == []


def test_redaction_hides_middle():
    redacted = secrets.redact("AKIAIOSFODNN7EXAMPLE")  # rein:ignore
    assert redacted.startswith("AKIA")
    assert redacted.endswith("MPLE")
    assert "*" in redacted


def test_clean_text_has_no_findings():
    assert secrets.scan_text("def add(a, b):\n    return a + b\n") == []
