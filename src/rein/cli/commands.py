"""CLI commands for `rein`.

Provides individual command implementations called by the parser.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import sys
import tomllib

from ..core import baseline, lint, ruff, secrets, security
from ..core.commits import check_commit
from ..core.config import DEFAULT_CONFIG, apply_disabled, config_from_dict
from ..core.drift import measure_drift
from ..core.findings import Finding
from ..core.learn import filter_net_new, measure_naming, measure_test_layout, render_profile_draft
from ..core.profile import parse_profile, ProfileError
from ..core.review import ReviewResult
from ..report import emit, emit_report, report_exit_code, worst_exit_code
from .. import scanners
from . import _helpers


def cmd_scan(args: argparse.Namespace) -> int:
    if args.diff:
        findings = secrets.scan_diff(sys.stdin.read())
    else:
        targets = args.paths or ["."]
        findings: list[Finding] = []
        for filepath in _helpers._iter_files(targets):
            findings.extend(secrets.scan_file(filepath))
    emit(findings, args.format)
    return worst_exit_code(findings)


def cmd_commit_check(args: argparse.Namespace) -> int:
    if args.message is not None:
        message = args.message
    elif args.message_file is not None:
        with open(args.message_file, encoding="utf-8") as fh:
            message = fh.read()
    else:
        message = _helpers._git("log", "-1", "--pretty=%B") or ""

    staged = [p for p in _helpers._git("diff", "--cached", "--name-only").splitlines() if p]
    findings = check_commit(message, staged)
    emit(findings, args.format)
    return worst_exit_code(findings)


def cmd_lint(args: argparse.Namespace) -> int:
    targets = args.paths or ["."]
    findings = [f for p in _helpers._iter_files(targets) if p.endswith(".py") for f in lint.lint_file(p)]
    if args.ruff:
        findings.extend(ruff.parse_ruff_output(scanners._run_ruff(targets)))
    emit(findings, args.format)
    return worst_exit_code(findings)


def cmd_security(args: argparse.Namespace) -> int:
    targets = args.paths or ["."]
    findings = [f for p in _helpers._iter_files(targets) if p.endswith(".py") for f in security.scan_security_file(p)]
    emit(findings, args.format)
    return worst_exit_code(findings)


def cmd_review(args: argparse.Namespace) -> int:
    config = DEFAULT_CONFIG
    config_path = args.config or ".rein.toml"
    if os.path.exists(config_path):
        try:
            with open(config_path, "rb") as fh:
                data = tomllib.load(fh)
            config = config_from_dict(data)
        except (OSError, tomllib.TOMLDecodeError, ValueError) as exc:
            print(f"rein: config error in '{config_path}': {exc}", file=sys.stderr)
            return 1
    elif args.config:
        print(f"rein: could not find config '{args.config}'", file=sys.stderr)
        return 1

    profile, profile_findings = _helpers._load_profile()

    if args.diff:
        findings = _helpers._collect_diff_findings(sys.stdin.read(), config.custom_rules)
    else:
        findings = _helpers._collect_review_findings(args.paths or ["."], config.custom_rules, profile)

        enabled = set(config.detectors)
        if args.bandit:
            enabled.add("bandit")
        if args.gitleaks:
            enabled.add("gitleaks")
        if args.semgrep:
            enabled.add("semgrep")

        findings.extend(scanners.run_detectors(args.paths or ["."], sorted(enabled)))
    if args.baseline:
        findings = baseline.apply_baseline(findings, _helpers._load_baseline(args.baseline))

    findings = apply_disabled(findings, config.disabled)
    findings = profile_findings + findings
    result = ReviewResult.from_findings(findings, config.policy)
    emit_report(result, args.format, args.explain)
    return report_exit_code(result)


def cmd_baseline(args: argparse.Namespace) -> int:
    findings = _helpers._collect_review_findings(args.paths or ["."])
    data = {"version": 1, "findings": baseline.make_baseline(findings)}
    out = args.output or ".rein-baseline.json"
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
        fh.write("\n")
    print(f"rein: wrote baseline with {len(data['findings'])} finding(s) to {out}")
    return 0


def cmd_learn(args: argparse.Namespace) -> int:
    targets = args.paths or ["."]
    files = []
    for p in _helpers._iter_files(targets):
        if p.endswith(".py"):
            try:
                with open(p, encoding="utf-8") as fh:
                    files.append((p, fh.read()))
            except (OSError, UnicodeDecodeError):
                continue

    measured = measure_naming([text for _, text in files])
    measured.extend(measure_test_layout(files))

    existing = None
    if os.path.exists(".rein-profile.toml"):
        try:
            with open(".rein-profile.toml", "rb") as fh:
                data = tomllib.load(fh)
            existing = parse_profile(data)
        except (OSError, tomllib.TOMLDecodeError, ProfileError) as exc:
            print(f"rein: could not parse existing profile: {exc}", file=sys.stderr)
            existing = None

    filtered = filter_net_new(measured, existing)
    draft = render_profile_draft(filtered, datetime.date.today().isoformat())

    if args.output:
        if os.path.exists(args.output):
            print(f"rein: error: output file '{args.output}' already exists. Refusing to overwrite.", file=sys.stderr)
            return 1
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(draft)
        print(f"rein: wrote draft profile to {args.output}", file=sys.stderr)
    else:
        print(draft, end="")
    return 0


def cmd_drift(args: argparse.Namespace) -> int:
    profile, profile_findings = _helpers._load_profile()
    if profile is None:
        if not os.path.exists(".rein-profile.toml"):
            print("rein: no profile found; skipping drift check.", file=sys.stderr)
            return 0
        else:
            for f in profile_findings:
                print(f"rein: error: {f.message}", file=sys.stderr)
            return 1

    targets = args.paths or ["."]
    files = []
    for p in _helpers._iter_files(targets):
        if p.endswith(".py"):
            try:
                with open(p, encoding="utf-8") as fh:
                    files.append((p, fh.read()))
            except (OSError, UnicodeDecodeError):
                continue

    reports = measure_drift(profile, files)

    has_drift = False
    for r in reports:
        status = "DRIFT" if r.drifted else "OK"
        print(f"[{status}] {r.convention_id}: {r.summary} (conformance: {r.current_conformance:.2f}, ratified: {r.ratified_agreement:.2f}, sample: {r.sample_size})")
        if r.drifted:
            has_drift = True

    return 1 if has_drift else 0
