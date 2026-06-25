# AGENTS.md

Operating guide for AI agents (and humans) contributing to **rein**. Read this
fully before editing. It is the contract that keeps the codebase coherent across
multiple contributors who never talk to each other directly.

## What this project is

`rein` detects secrets, unsafe-code patterns, clean-code lint issues, and
commit hygiene; turns findings into a policy verdict with remediation guidance;
reviews whole files or diffs; and drives an agent steering loop -- usable from
the CLI, an MCP server, or a git hook. It must stay **agent-agnostic**:
usable from any agent or CI system, never tied to one host.

## The one architectural rule

> **`core/` thinks. Adapters do I/O.**

- `src/rein/core/` contains pure functions. No printing, no `sys.exit`, no
  subprocess, no network, no reading global state. Every check returns a list of
  `Finding` objects (see `core/findings.py`).
- `cli/`, `mcp/`, `hooks/` are **thin adapters**. They gather input (files, git,
  JSON), call `core`, render the `Finding`s, and pick an exit code. They contain
  no detection logic.

If you are about to put a regex or a rule inside an adapter, stop. It belongs in
`core/`, where every other interface can reuse it and a unit test can reach it
without spawning a process.

## Code style: the anti-slop charter

We want a repo that reads like one careful engineer wrote it, not a generator.

1. **Type-hint everything.** Public functions have full annotations. `from
   __future__ import annotations` at the top of each module.
2. **Docstrings explain *why*, not *what*.** A docstring that restates the
   function name ("`scan_file`: scans a file") is noise; delete it. Document
   intent, edge cases, and the contract.
3. **Plain ASCII only, no emojis, anywhere.** No emojis, em-dashes, smart
   quotes, arrows, or decorative symbols (such as check marks) in code, docs,
   comments, CLI output, or commit messages. Use `-`, `:`, or rephrase. The
   ASCII self-check below must print nothing. Comments mark non-obvious
   decisions only; code that needs a comment to be readable should be rewritten.
4. **Small files, small functions.** If a module passes ~250 lines or a function
   passes ~50, it probably wants splitting. Limits are guidelines -- split where
   there is a real seam, but do not fragment a cohesive module just to hit a
   number (that is its own slop; see rule 7). Prefer clarity over cleverness.
5. **Standard library first.** Add a dependency only when it earns its place;
   justify it in the PR. `core` should stay dependency-free.
6. **Match the surrounding code.** Naming, structure, and idiom should be
   indistinguishable from the existing modules.
7. **No dead scaffolding.** Don't commit `TODO`-stubs, empty handlers, or
   "future-proofing" abstractions with one caller.
8. **No marketing prose.** Docs and READMEs are terse and factual. No selling,
   no metaphors, no filler adjectives.

## Performance and resilience

rein is called everywhere, including agent loops that invoke it repeatedly, so
it must stay fast and hard to break.

1. Zero or minimal runtime dependencies. `core` stays dependency-free; stdlib first.
2. No redundant work. Parse a source once and share the AST across checks; keep
   every check O(n) in input size.
3. Bound, do not blow up. Malformed, huge, or hostile input degrades gracefully
   (return findings or empty, never crash). Parsing catches SyntaxError,
   ValueError, and RecursionError.
4. Treat latency as a feature. The hot path is review/review_diff; the
   perf-contract test asserts review parses the AST once.
5. External detectors run with a strict timeout and fail open to prevent hanging the review.

## Testing (non-negotiable)

- Every new behavior in `core/` ships with a `pytest` test in `tests/`.
- Tests must be deterministic and not touch the network.
- Test files are exempt from type-hint and future-import lint rules; `rein review .` warning on them is by design, while `rein review src/` is the clean gate.
- Run before every commit:
  ```bash
  pytest -q
  ```
- A change with failing or missing tests is not done.

## Commits & security

We dogfood our own tool. Before committing, run all three and make sure they
are clean:
```bash
pytest -q
rein scan .
git ls-files | xargs grep -nP '[^\x00-\x7F]'   # must print nothing: ASCII only
git ls-files | xargs grep -nP ' +$'            # must print nothing: no trailing whitespace
```
- Commit messages follow **Conventional Commits** (`feat:`, `fix:`, `docs:`,
  `refactor:`, `test:`, `chore:`), imperative mood, subject <= 72 chars. Keep
  them short and plain: one line, no multi-clause descriptions.
- **No tool or AI attribution trailers.** Never add `Co-Authored-By` or any
  tool or AI credit. A Developer Certificate of Origin `Signed-off-by:` line
  (the human author certifying origin, via `git commit -s`) is allowed and is
  required for outside contributions; see `CONTRIBUTING.md`. It is not an
  attribution trailer.
- **Never commit secrets or personal data**: no API keys, tokens, `.env` files,
  emails, home paths, or machine-specific config. `rein scan` must pass clean.

## How contributions are coordinated

Contributors do not share a chat. The repo is the shared memory:

- **Architecture & contracts** (the `Finding` shape, module boundaries, public
  function signatures, the tests that define correct behavior) are authored by
  the lead and committed first. Treat committed signatures and tests as fixed.
- **Implementation tasks** are picked up against those contracts. The job is to
  make the specified tests pass without changing the contract. If a contract
  seems wrong, leave it and raise it; don't silently rewrite it.
- When you finish a task: run `pytest -q` and `rein scan .`, then write a
  Conventional-Commit message describing only what you changed.

## Keeping the docs current

The repo is the shared memory: anyone should be able to continue without a chat.
When you finish a slice, update the project's durable docs in the same commit, so
the status and the reasoning behind a choice stay current. Keep them in the
project's voice: terse, factual, ASCII, no marketing. They capture intent,
status, and reasoning that the code and git log do not.

## Project layout

```text
src/rein/
  core/      pure logic: findings, diffs, secrets, security, lint, commits, code,
             review, remediation, baseline, config, conventions, drift, junk,
             ruff/bandit/gitleaks/semgrep adapters, sarif, custom
  loop.py    agent-loop driver (pure; agent injected)
  cli/       argparse adapter
  mcp/       MCP server adapter
  hooks/     git pre-commit adapter
tests/       pytest, one file per core module
examples/    runnable agent integrations
```

## Dev setup

```bash
pip install -e ".[dev]"            # editable install + pytest
pytest -q                          # run tests
rein scan .                        # dogfood the scanner
```

rein dogfoods itself: `rein commit-check` rejects any commit message carrying AI
or tool attribution (`Co-authored-by`, `generated by ...`) and flags tampering
with rein's own config; CI runs it on every push. A human DCO `Signed-off-by:`
line is allowed and is required for outside contributions.
