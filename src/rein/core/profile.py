"""Convention profile parser and strict validation.

Parses a parsed TOML dictionary into a strongly typed Profile object, ensuring
all required parameters are present and no unknown parameters exist.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .findings import Finding, Severity

PROFILE_VERSION = 1

_NAMING_TARGETS = frozenset({"function", "class"})
_NAMING_STYLES = frozenset({"snake_case", "camelCase", "PascalCase", "UPPER_CASE"})


@dataclass(frozen=True)
class ParamSpec:
    kind: frozenset[str] | str
    required: bool = True


@dataclass(frozen=True)
class CheckerSpec:
    params: dict[str, ParamSpec]
    default_severity: Severity


CHECKERS: dict[str, CheckerSpec] = {
    "naming.identifier": CheckerSpec(
        params={"target": ParamSpec(_NAMING_TARGETS), "style": ParamSpec(_NAMING_STYLES)},
        default_severity=Severity.LOW,
    ),
    "layout.test-files": CheckerSpec(
        params={"directory": ParamSpec("str"), "filename": ParamSpec("str")},
        default_severity=Severity.LOW,
    ),
    "forbid.call": CheckerSpec(
        params={
            "calls": ParamSpec("list_str"),
            "message": ParamSpec("str", required=False),
            "paths": ParamSpec("list_str", required=False),
        },
        default_severity=Severity.MEDIUM,
    ),
    "forbid.import": CheckerSpec(
        params={
            "imports": ParamSpec("list_str"),
            "message": ParamSpec("str", required=False),
            "paths": ParamSpec("list_str", required=False),
        },
        default_severity=Severity.MEDIUM,
    ),
    "arch.layering": CheckerSpec(
        params={
            "paths": ParamSpec("list_str"),
            "forbidden": ParamSpec("list_str"),
            "message": ParamSpec("str", required=False),
        },
        default_severity=Severity.MEDIUM,
    ),
    "imports.allowed": CheckerSpec(
        params={
            "paths": ParamSpec("list_str"),
            "allow": ParamSpec("list_str"),
            "message": ParamSpec("str", required=False),
        },
        default_severity=Severity.MEDIUM,
    ),
    "complexity.function": CheckerSpec(
        params={
            "max_params": ParamSpec("int", required=False),
            "max_nesting_depth": ParamSpec("int", required=False),
            "paths": ParamSpec("list_str", required=False),
            "message": ParamSpec("str", required=False),
        },
        default_severity=Severity.MEDIUM,
    ),
}


@dataclass(frozen=True)
class ConventionEntry:
    id: str
    checker: str
    severity: Severity
    enabled: bool
    params: dict[str, Any]
    evidence: dict[str, Any] | None = None


@dataclass(frozen=True)
class Profile:
    version: int
    conventions: tuple[ConventionEntry, ...]


class ProfileError(ValueError):
    """A profile dict is structurally or semantically invalid."""


def _parse_params(cid: str, entry: Any, spec: CheckerSpec) -> dict[str, Any]:
    params: dict[str, Any] = {}
    for k, v in entry.items():
        if k in ("checker", "enabled", "severity", "evidence"):
            continue
        if k not in spec.params:
            raise ProfileError(f"convention '{cid}' has unknown key '{k}'")

        pspec = spec.params[k]
        kind = pspec.kind

        if isinstance(kind, frozenset):
            if v not in kind:
                raise ProfileError(
                    f"convention '{cid}' param '{k}' value '{v}' is invalid; "
                    f"allowed: {', '.join(sorted(kind))}"
                )
        elif kind == "str":
            if not isinstance(v, str) or not v:
                raise ProfileError(f"convention '{cid}' param '{k}' must be a non-empty string")
        elif kind == "list_str":
            if not isinstance(v, list) or not v or not all(isinstance(i, str) and i for i in v):
                raise ProfileError(f"convention '{cid}' param '{k}' must be a non-empty list of non-empty strings")
        elif kind == "int":
            # bool is an int subclass; reject `true`/`false` explicitly (the trap that bit `version`).
            if not isinstance(v, int) or isinstance(v, bool) or v < 1:
                raise ProfileError(f"convention '{cid}' param '{k}' must be a positive integer")

        params[k] = v

    for name, pspec in spec.params.items():
        if pspec.required and name not in params:
            raise ProfileError(f"convention '{cid}' missing required param '{name}'")

    return params


def _parse_convention_entry(cid: str, entry: Any) -> ConventionEntry:
    if not isinstance(entry, dict):
        raise ProfileError(f"convention '{cid}' must be a dictionary")

    if "checker" not in entry:
        raise ProfileError(f"convention '{cid}' missing required key 'checker'")
    checker_name = entry["checker"]
    if not isinstance(checker_name, str):
        raise ProfileError(f"convention '{cid}' key 'checker' must be a string")
    if checker_name not in CHECKERS:
        raise ProfileError(f"convention '{cid}' has unknown checker '{checker_name}'")

    spec = CHECKERS[checker_name]

    enabled = entry.get("enabled", True)
    if not isinstance(enabled, bool):
        raise ProfileError(f"convention '{cid}' key 'enabled' must be a boolean")

    resolved_severity = spec.default_severity
    if "severity" in entry:
        sev_str = entry["severity"]
        if not isinstance(sev_str, str):
            raise ProfileError(f"convention '{cid}' key 'severity' must be a string")
        try:
            resolved_severity = Severity[sev_str.upper()]
        except KeyError:
            raise ProfileError(f"convention '{cid}' has invalid severity '{sev_str}'")

    if "evidence" in entry:
        if not isinstance(entry["evidence"], dict):
            raise ProfileError(f"convention '{cid}' key 'evidence' must be a dictionary")

    params = _parse_params(cid, entry, spec)

    return ConventionEntry(
        id=cid,
        checker=checker_name,
        severity=resolved_severity,
        enabled=enabled,
        params=params,
        evidence=entry.get("evidence"),
    )


def parse_profile(data: dict) -> Profile:
    """Parse and strictly validate a profile dictionary.

    Raises:
        ProfileError: On any structural or semantic violation.
    """
    if not isinstance(data, dict):
        raise ProfileError("data must be a dictionary")

    if "version" not in data:
        raise ProfileError("missing version")
    version = data["version"]
    if isinstance(version, bool) or not isinstance(version, int):
        raise ProfileError("version must be an integer")
    if version != PROFILE_VERSION:
        raise ProfileError(f"profile version {version} is not supported by this rein; upgrade rein")

    allowed_top_keys = {"version", "conventions"}
    for k in data:
        if k not in allowed_top_keys:
            raise ProfileError(f"unknown top-level key: {k}")

    conventions_data = data.get("conventions")
    if conventions_data is None:
        return Profile(version=version, conventions=())

    if not isinstance(conventions_data, dict):
        raise ProfileError("conventions must be a dictionary")

    entries = [_parse_convention_entry(cid, entry) for cid, entry in conventions_data.items()]
    entries.sort(key=lambda x: x.id)
    return Profile(version=version, conventions=tuple(entries))


def profile_invalid_finding(reason: str, path: str | None = None) -> Finding:
    """Return a HIGH severity finding for an invalid profile."""
    return Finding(
        rule_id="rein.profile-invalid",
        severity=Severity.HIGH,
        message=f"rein profile is invalid and was not applied: {reason}",
        path=path,
        tags=("profile", "config"),
    )
