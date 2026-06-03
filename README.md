# rein

[![CI](https://github.com/SametAtas/rein/actions/workflows/ci.yml/badge.svg)](https://github.com/SametAtas/rein/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

Agent-agnostic guardrails for AI-written code. `rein` detects leaked secrets,
unsafe-code patterns, clean-code lint issues, and commit-hygiene problems; turns
them into a policy verdict with remediation guidance; reviews whole files or
diffs; and can drive an agent to fix its own code. It is meant to be called by
any agent, a person, or a CI pipeline, and is not tied to a single host.

Detection lives in pure functions under `rein.core`. rein governs best-of-breed external detectors (like bandit, gitleaks, and ruff). The value sits in the engine (policy, verdict, steering, remediation), which keeps a dependency-free core while pulling findings from optional adapters. Thin adapters expose these checks: a command line, an MCP server, and a git pre-commit hook.

## Install

```bash
# End users: install the published package (the command stays `rein`)
pipx install rein-engine
# or: pip install rein-engine

# Developers: install from a clone with the dev extras
pip install -e ".[dev]"
```

## Usage

```bash
# Scan files or directories for leaked credentials
rein scan .
rein scan src/config.py

# Scan only added lines from a diff (reads stdin)
git diff | rein scan --diff

# Run lint rules over Python code
rein lint .
rein lint src/ --ruff

# Flag unsafe-code patterns
rein security .

# Run all guardrails and get a PASS/WARN/BLOCK verdict
rein review .
# Run all guardrails plus external detectors (installed separately)
# Detectors can also be enabled declaratively via .rein.toml
rein review --bandit --gitleaks --semgrep .
# Show how to fix each finding
rein review --explain .
# Review only changed lines (reads working tree and stdin diff)
git diff | rein review --diff

# Machine-readable findings for CI or agents
rein scan --format json .
rein lint --format json src/

# Check a commit message and the staged files
rein commit-check -m "feat(auth): add token refresh"
rein commit-check                 # uses the last commit message and staged files
# Note: commit-check and pre-commit hooks will strictly flag any modifications to rein's own config files as HIGH.
# They also provide advisory warnings (MEDIUM/LOW) if you attempt to commit junk/slop files (e.g. .DS_Store, temp.py).
```

`rein` exits non-zero on any finding at HIGH severity or above, so it works as a
CI step or a pre-commit hook.

### GitHub Action

You can drop `rein` directly into your GitHub Actions pipeline. It reviews a
path and uploads the findings as SARIF, so they surface in the Security tab:

```yaml
name: CI
on: [push, pull_request]

jobs:
  rein:
    runs-on: ubuntu-latest
    permissions:
      contents: read          # checkout the repository
      security-events: write  # upload SARIF to the Security tab
      actions: read           # upload-sarif reads run metadata (private repos)
    steps:
      - uses: actions/checkout@v4
      - name: Run rein review
        uses: SametAtas/rein@v0.1.0
        with:
          path: src/
          output: rein.sarif
```

Code scanning (the Security tab) needs GitHub Advanced Security on private
repositories. Where it is unavailable, set `upload: false` to produce the SARIF
file as a build artifact instead of uploading it.

## Configuration

Control the engine declaratively with a `.rein.toml` file at the root of your project to configure the `rein review` verdict policy, disable specific rules, and enable external detectors:

```toml
[policy]
fail_at = "high"          # severity at/above which a finding blocks
warn_at = "low"           # severity at/above which a finding warns

[policy.category_fail_at]
lint = "low"              # override fail threshold per category (secret/lint/security/commit/ruff)
secret = "critical"

[rules]
disabled = ["lint.todo-comment", "secret.jwt"]   # rule_ids to drop entirely

[[rules.custom]]
id = "no-print"
pattern = "\\bprint\\("
severity = "low"
message = "Avoid print() in production code"

[detectors]
# Declaratively enable external detectors (must be installed separately).
# Note: semgrep is a multi-language, rule-based detector and is heavier, so it is opt-in.
bandit = true
gitleaks = true
ruff = true
semgrep = true
```

You can override the path via `rein review --config path/to.toml .`.

## Layout

```text
src/rein/
  core/      pure checks: findings.py, pragmas.py, diffs.py, secrets.py, security.py, lint.py, commits.py, review.py, remediation.py, ruff.py, bandit.py, gitleaks.py
  report.py  shared output formatting and exit codes
  cli/       command-line adapter
  mcp/       MCP server adapter (stdio)
  hooks/     git pre-commit adapter
tests/       one test file per module
```

## Steering an agent

Agents can use rein to check and correct their own code before committing. The reference implementation for this steering loop is `rein.loop.run_loop` (pure, bounded, agent injected).

1. An LLM agent generates a patch.
2. The loop runs `review()` or `review_diff()`.
3. If the verdict is `BLOCK`, the loop fetches `suggest_fixes()` and feeds the findings + guidance back to the agent as a prompt.
4. The agent revises the code. The loop repeats until the verdict passes or the iteration bound is hit.

See `examples/guarded_agent.py` for a runnable demonstration.

## Adopting on an existing repo

Record the current findings so CI only blocks on new issues:

```bash
rein baseline              # writes .rein-baseline.json
git add .rein-baseline.json
rein review --baseline .rein-baseline.json .
```

Findings already in the baseline are suppressed; only new ones trigger a BLOCK.

## Use from an agent

Install with MCP support:

```bash
pip install -e ".[mcp]"
```

Start the stdio server:

```bash
rein-mcp
```

Client config snippet (e.g. for Claude Desktop or any MCP client):

```json
{
  "mcpServers": {
    "rein": {
      "command": "rein-mcp",
      "transport": "stdio"
    }
  }
}
```

The server exposes eight tools: ``scan_secrets``, ``check_commit``, ``lint_code``, ``scan_diff``, ``check_security``, ``review_code``, ``suggest_fixes``, and ``review_diff``. The review tools (``review_code`` and ``review_diff``) accept an optional ``config`` object (same shape as ``.rein.toml``) to steer with a custom policy.

A configurable ``Policy`` turns findings into a verdict and is how rein adapts to different standards and domains.

The rule the code follows: detection stays in `core` and returns `Finding`
objects; adapters only gather input, call `core`, and render the result.

## Test

```bash
pytest -q
```

## License

Apache-2.0 (see `LICENSE`). Contributions require a Developer Certificate of
Origin sign-off; see `CONTRIBUTING.md`.
