# Contributing to rein

Thanks for your interest in rein. A few rules keep the codebase coherent, and
contributions that ignore them will be asked to change:

- Architecture: detection logic lives in pure functions under `rein.core` and
  returns `Finding` objects. The CLI, MCP server, and git hooks are thin adapters
  that gather input, call core, and render. No detection logic in adapters.
- Style: type-hint everything, ASCII only (no emojis), keep files and functions
  small, prefer the standard library, and include tests.
- Commits: sole-authored, with a DCO sign-off (below). AI or tool attribution
  trailers are not accepted.

## License

rein is licensed under the Apache License, Version 2.0 (see `LICENSE`). By
contributing, you agree that your contributions are licensed under the same
terms.

## Developer Certificate of Origin (sign-off required)

This project uses the Developer Certificate of Origin (see `DCO`). Every commit
must be signed off, certifying that you wrote the change or have the right to
submit it under the project license. Add the sign-off with:

```bash
git commit -s -m "feat: your change"
```

This appends a line of the form:

```text
Signed-off-by: Your Name <you@example.com>
```

The sign-off certifies the origin of the work. It is not a tool or AI
attribution, which this project does not accept.

## Before you open a pull request

Run all three and make sure they are clean:

```bash
pytest -q
rein scan .
git ls-files | xargs grep -nP '[^\x00-\x7F]'   # must print nothing: ASCII only
```

Use Conventional Commit messages (`feat:`, `fix:`, `docs:`, `refactor:`,
`test:`, `chore:`), one line, imperative mood, subject 72 chars or fewer.
