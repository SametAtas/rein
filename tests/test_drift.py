"""Tests for convention drift detection."""

from __future__ import annotations

import pytest

from rein.core.drift import measure_drift
from rein.core.profile import PROFILE_VERSION, parse_profile


def test_drift_clean_no_drift():
    profile_data = {
        "version": PROFILE_VERSION,
        "conventions": {
            "function-naming": {
                "checker": "naming.identifier",
                "target": "function",
                "style": "snake_case",
                "evidence": {
                    "source": "measured",
                    "agreement": 0.95,
                    "sample_size": 12,
                },
            }
        },
    }
    profile = parse_profile(profile_data)

    files = [("a.py", "\n".join(f"def func_{i}(): pass" for i in range(12)))]

    reports = measure_drift(profile, files)
    assert len(reports) == 1
    rep = reports[0]
    assert rep.convention_id == "function-naming"
    assert rep.checker == "naming.identifier"
    assert rep.summary == "function naming -> snake_case"
    assert rep.ratified_agreement == 0.95
    assert rep.current_conformance == 1.0
    assert rep.sample_size == 12
    assert rep.drifted is False


def test_drift_degraded_naming():
    profile_data = {
        "version": PROFILE_VERSION,
        "conventions": {
            "class-naming": {
                "checker": "naming.identifier",
                "target": "class",
                "style": "PascalCase",
                "evidence": {
                    "source": "measured",
                    "agreement": 0.99,
                    "sample_size": 10,
                },
            }
        },
    }
    profile = parse_profile(profile_data)

    # 10 classes total: 7 conform, 3 fail (camelCase). Conformance = 0.7 < 0.9 (AGREEMENT_MIN), drifted = True
    files = [
        (
            "a.py",
            "\n".join(f"class ConformingClass{i}: pass" for i in range(7))
            + "\n"
            + "\n".join(f"class badClass{i}: pass" for i in range(3)),
        )
    ]

    reports = measure_drift(profile, files)
    assert len(reports) == 1
    rep = reports[0]
    assert rep.convention_id == "class-naming"
    assert rep.current_conformance == 0.7
    assert rep.sample_size == 10
    assert rep.drifted is True


def test_drift_degraded_layout():
    profile_data = {
        "version": PROFILE_VERSION,
        "conventions": {
            "layout-conventions": {
                "checker": "layout.test-files",
                "directory": "tests/",
                "filename": "test_*.py",
                "evidence": {
                    "source": "measured",
                    "agreement": 0.95,
                    "sample_size": 10,
                },
            }
        },
    }
    profile = parse_profile(profile_data)

    files = []
    # 7 conforming
    for i in range(7):
        files.append((f"tests/test_{i}.py", "def test_func(): pass"))
    # 3 degraded (placed outside tests/ directory)
    for i in range(3):
        files.append((f"other/test_bad_{i}.py", "def test_func(): pass"))

    reports = measure_drift(profile, files)
    assert len(reports) == 1
    rep = reports[0]
    assert rep.convention_id == "layout-conventions"
    assert rep.checker == "layout.test-files"
    assert rep.summary == "test layout -> tests/, test_*.py"
    assert rep.current_conformance == 0.7
    assert rep.sample_size == 10
    assert rep.drifted is True


def test_drift_declared_and_non_measured_skipped():
    profile_data = {
        "version": PROFILE_VERSION,
        "conventions": {
            "declared-convention": {
                "checker": "naming.identifier",
                "target": "function",
                "style": "snake_case",
                "evidence": {
                    "source": "declared",
                    "agreement": 1.0,
                },
            },
            "no-evidence-convention": {
                "checker": "naming.identifier",
                "target": "function",
                "style": "snake_case",
            },
        },
    }
    profile = parse_profile(profile_data)

    files = [("a.py", "\n".join(f"def func_{i}(): pass" for i in range(12)))]

    reports = measure_drift(profile, files)
    assert len(reports) == 0


def test_drift_thin_sample_not_drifted():
    profile_data = {
        "version": PROFILE_VERSION,
        "conventions": {
            "function-naming": {
                "checker": "naming.identifier",
                "target": "function",
                "style": "snake_case",
                "evidence": {
                    "source": "measured",
                    "agreement": 0.95,
                    "sample_size": 12,
                },
            }
        },
    }
    profile = parse_profile(profile_data)

    # Only 5 functions (less than SAMPLE_MIN = 10), 2 conform, 3 do not.
    # Sample is thin -> drifted must be False.
    files = [
        (
            "a.py",
            "def func_1(): pass\ndef func_2(): pass\ndef badFunc3(): pass\ndef badFunc4(): pass\ndef badFunc5(): pass",
        )
    ]

    reports = measure_drift(profile, files)
    assert len(reports) == 1
    rep = reports[0]
    assert rep.sample_size == 5
    assert rep.current_conformance == 0.4
    assert rep.drifted is False


def test_drift_garbage_evidence_skipped():
    profile_data = {
        "version": PROFILE_VERSION,
        "conventions": {
            "garbage-agreement": {
                "checker": "naming.identifier",
                "target": "function",
                "style": "snake_case",
                "evidence": {
                    "source": "measured",
                    "agreement": "not-a-float",
                    "sample_size": 12,
                },
            }
        },
    }
    profile = parse_profile(profile_data)

    files = [("a.py", "\n".join(f"def func_{i}(): pass" for i in range(12)))]

    reports = measure_drift(profile, files)
    assert len(reports) == 0
