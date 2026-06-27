# Changelog

Notable changes to the `rein-engine` distribution. The import package and the
`rein` command are unchanged across these versions.

## 0.3.2

### Added

- `rein review --stdin --filename PATH`: review source code read from stdin as
  one file (content mode), for editor and agent integrations that check code
  before it is written to disk.

### Fixed

- `secret.high-entropy-assignment` no longer flags a dotted code reference (a
  type annotation such as `x: pkg.Type`) as a hardcoded secret. The exclusion is
  limited to dotted identifiers, so an unquoted single-identifier secret in a
  config file is still detected.

## 0.3.1

### Fixed

- Scope project-aware import resolution to the working-directory project.
  Reviewing a path OUTSIDE that project (an installed package, a vendored tree,
  another checkout) no longer applies the wrong project's module set to those
  files. Previously this produced false `imports.unresolved` findings on the
  foreign files and rendered each file's absolute path into the finding snippet.
  Out-of-project files now skip project-aware resolution (the existing fail-open
  behavior); in-project review is unchanged. Found proactively while probing the
  scanner on installed packages, not from a user report.

## 0.3.0

### Added

- Content-mode scanning: review code supplied as text with no file path, through
  a runner shared across the CLI and the integrations.

## 0.2.0

### Added

- Project-aware import resolution (`imports.unresolved`): flag a module-top-level
  import whose target is not the stdlib, a declared dependency, or a project
  module.
- Undefined-name detection (`names.undefined`): flag a name that is used but
  bound nowhere reachable.
- Duplicate-function detection (`dup.function`): on a diff, flag an added
  function whose body duplicates one already in the project.

## 0.1.1

### Added

- First PyPI release, as the `rein-engine` distribution.
- GitHub Action that runs the review and emits SARIF for code scanning.
