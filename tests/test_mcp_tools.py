"""Contract for the MCP tool functions.

These define the behavior of the SDK-free layer the MCP server exposes. The
server (server.py) is verified by running it; this layer is unit-tested here.
Implement rein/mcp/tools.py to make these pass without changing them.
"""

import json

import pytest

from rein.mcp import tools

AWS = "AKIAIOSFODNN7EXAMPLE"  # rein:ignore


def test_scan_secrets_returns_finding_dicts():
    out = tools.scan_secrets(f'aws = "{AWS}"')
    assert isinstance(out, list)
    assert all(isinstance(d, dict) for d in out)
    assert any(d["rule_id"] == "secret.aws-access-key" for d in out)


def test_scan_secrets_clean_returns_empty():
    assert tools.scan_secrets("def add(a, b):\n    return a + b\n") == []


def test_scan_secrets_output_is_json_serializable():
    json.dumps(tools.scan_secrets(f'k = "{AWS}"'))


def test_scan_secrets_honors_ignore_pragma():
    assert tools.scan_secrets(f'aws = "{AWS}"  # rein:ignore') == []


def test_check_commit_flags_wip_message():
    out = tools.check_commit("WIP", [])
    assert any(d["rule_id"] == "commit.wip-marker" for d in out)


def test_check_commit_flags_sensitive_file():
    out = tools.check_commit("chore: env", [".env"])
    assert any(d["rule_id"] == "commit.sensitive-file" for d in out)


def test_check_commit_clean_returns_empty():
    assert tools.check_commit("feat(api): add endpoint", ["src/app.py"]) == []


def test_lint_code_returns_finding_dicts():
    out = tools.lint_code("def foo():\n    pass\n")
    assert isinstance(out, list)
    assert all(isinstance(d, dict) for d in out)
    assert any(d["rule_id"] == "lint.missing-type-hints" for d in out)


def test_lint_code_output_is_json_serializable():
    json.dumps(tools.lint_code("# TODO: later\n"))


def test_lint_code_honors_ignore_pragma():
    out = tools.lint_code("# TODO: later  # rein:ignore lint.todo-comment\n")
    assert not any(d["rule_id"] == "lint.todo-comment" for d in out)


def test_scan_diff_returns_finding_dicts():
    diff = (
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -1,1 +1,2 @@\n"
        " import os\n"
        f'+aws = "{AWS}"\n'
    )
    out = tools.scan_diff(diff)
    assert isinstance(out, list)
    assert all(isinstance(d, dict) for d in out)
    assert any(d["rule_id"] == "secret.aws-access-key" for d in out)


def test_scan_diff_clean_returns_empty():
    diff = (
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -1,1 +1,2 @@\n"
        " import os\n"
        "+x = 1\n"
    )
    assert tools.scan_diff(diff) == []


def test_scan_diff_empty_returns_empty():
    assert tools.scan_diff("") == []


def test_check_security_returns_finding_dicts():
    out = tools.check_security('eval("1")\n')
    assert isinstance(out, list)
    assert all(isinstance(d, dict) for d in out)
    assert any(d["rule_id"] == "security.eval-exec" for d in out)


def test_check_security_clean_returns_empty():
    assert tools.check_security("x = 1\n") == []


def test_review_code_returns_result_dict():
    out = tools.review_code('import os\nos.system("ls")\n')
    assert isinstance(out, dict)
    assert out["verdict"] == "BLOCK"
    assert len(out["findings"]) >= 1


def test_review_code_clean_returns_pass_dict():
    out = tools.review_code("x = 1\n")
    assert isinstance(out, dict)
    assert out["verdict"] == "PASS"
    assert len(out["findings"]) == 0


def test_suggest_fixes_returns_finding_with_fix():
    out = tools.suggest_fixes('import os\nos.system("ls")\n')
    assert isinstance(out, list)
    assert len(out) >= 1
    finding = out[0]
    assert finding["rule_id"] == "security.os-system"
    assert "fix" in finding
    assert finding["fix"] is not None
    assert isinstance(finding["fix"]["guidance"], str)


def test_review_diff_blocks_on_added_secret():
    diff = (
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -1,1 +1,2 @@\n"
        " import os\n"
        f'+aws = "{AWS}"\n'
    )
    new_text = f'import os\naws = "{AWS}"\n'
    out = tools.review_diff(new_text, diff, "app.py")
    assert out["verdict"] == "BLOCK"
    assert any(f["rule_id"] == "secret.aws-access-key" for f in out["findings"])


def test_review_diff_passes_on_context_secret():
    diff = (
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -1,1 +1,2 @@\n"
        " import os\n"
        "+x = 1\n"
    )
    new_text = f'import os\nx = 1\naws = "{AWS}"\n'
    out = tools.review_diff(new_text, diff, "app.py")
    assert out["verdict"] == "PASS"
    assert not any(f["rule_id"] == "secret.aws-access-key" for f in out["findings"])


def test_review_code_with_config_changes_verdict():
    # snippet has a lint finding (todo), normally WARN because default policy warn_at is LOW
    snippet = "# TODO: fix this\n"
    out_default = tools.review_code(snippet)
    assert out_default["verdict"] == "WARN"
    assert any(f["rule_id"] == "lint.todo-comment" for f in out_default["findings"])

    # with config setting lint fail_at to low, it blocks
    config = {"policy": {"category_fail_at": {"lint": "low"}}}
    out_custom = tools.review_code(snippet, config=config)
    assert out_custom["verdict"] == "BLOCK"


def test_review_code_with_config_disables_rule():
    snippet = "# TODO: fix this\n"
    config = {"rules": {"disabled": ["lint.todo-comment"]}}
    out = tools.review_code(snippet, config=config)
    assert not any(f["rule_id"] == "lint.todo-comment" for f in out["findings"])


def test_review_code_with_invalid_config_raises():
    snippet = "# TODO: fix this\n"
    config = {"policy": {"fail_at": "invalid_severity"}}
    with pytest.raises(ValueError):
        tools.review_code(snippet, config=config)


def test_review_diff_with_config_changes_verdict():
    diff = (
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -1,1 +1,2 @@\n"
        " import os\n"
        "+# TODO: fix this\n"
    )
    new_text = "import os\n# TODO: fix this\n"

    # Default is WARN
    out_default = tools.review_diff(new_text, diff, "app.py")
    assert out_default["verdict"] == "WARN"

    # Custom config makes it BLOCK
    config = {"policy": {"category_fail_at": {"lint": "low"}}}
    out_custom = tools.review_diff(new_text, diff, "app.py", config=config)
    assert out_custom["verdict"] == "BLOCK"
