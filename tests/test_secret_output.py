from rein.core import secret_output
from rein.core.findings import Severity


def _rule_ids(findings):
    return {f.rule_id for f in findings}


# -- scan_secret_output: secret-named variable into an output sink ------------

def test_exposed_output_flags_print_of_token():
    findings = secret_output.scan_secret_output("print(api_token)")
    assert _rule_ids(findings) == {"secret.exposed-output"}
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].line == 1


def test_exposed_output_flags_logging_and_sys_write():
    assert "secret.exposed-output" in _rule_ids(secret_output.scan_secret_output("logging.info(api_key)"))
    assert "secret.exposed-output" in _rule_ids(secret_output.scan_secret_output("logger.error(secret_key)"))
    assert "secret.exposed-output" in _rule_ids(
        secret_output.scan_secret_output("sys.stderr.write(password)")
    )


def test_exposed_output_ignores_non_secret_names():
    # author/primary_key/foreign_key/oauth are not credentials; bare key excluded.
    for src in ("print(author)", "print(primary_key)", "print(foreign_key)", "print(oauth)"):
        assert secret_output.scan_secret_output(src) == []


def test_exposed_output_only_bare_name_arguments():
    # An f-string or attribute is not "passed straight" - conservative, no flag.
    assert secret_output.scan_secret_output('print(f"value={token}")') == []
    assert secret_output.scan_secret_output("print(config.token)") == []


def test_exposed_output_non_sink_call_is_ignored():
    assert secret_output.scan_secret_output("store(password)") == []


def test_exposed_output_honors_ignore_pragma():
    assert secret_output.scan_secret_output("print(password)  # rein:ignore") == []
    assert secret_output.scan_secret_output("print(password)  # rein:ignore secret.exposed-output") == []


def test_exposed_output_fails_open_on_syntax_error():
    assert secret_output.scan_secret_output("print(token") == []  # unbalanced; no crash
