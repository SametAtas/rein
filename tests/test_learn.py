"""Tests for the rein learn deterministic measurement core."""

import tomllib

from rein.core.learn import (
    MeasuredConvention,
    convention_id,
    filter_net_new,
    measure_naming,
    measure_test_layout,
    render_profile_draft,
)
from rein.core.profile import ConventionEntry, Profile, parse_profile
from rein.core.findings import Severity


def test_measure_naming_snake_dominant():
    sources = [
        "def read_csv(): pass",
        "def foo_bar(): pass",
        "def _priv(): pass",
        "def get_user(): pass",
        "def func5(): pass",
        "def func6(): pass",
        "def func7(): pass",
        "def func8(): pass",
        "def func9(): pass",
        "def func10(): pass",
        "def camelCase(): pass",  # 1 outlier out of 11
    ]
    measured = measure_naming(sources)
    assert len(measured) == 1
    m = measured[0]
    assert m.checker == "naming.identifier"
    assert m.params == {"target": "function", "style": "snake_case"}
    assert m.sample_size == 11
    assert m.agreement >= 0.9


def test_measure_naming_pascalcase_class():
    sources = [
        "class MyClass: pass",
        "class HTTPClient: pass",
        "class URLParser: pass",
        "class _Private: pass",
        "class A: pass",
        "class B: pass",
        "class C: pass",
        "class D: pass",
        "class E: pass",
        "class F: pass",
    ]
    measured = measure_naming(sources)
    assert len(measured) == 1
    m = measured[0]
    assert m.params == {"target": "class", "style": "PascalCase"}
    assert m.sample_size == 10
    assert m.agreement == 1.0


def test_measure_naming_below_sample_min():
    sources = ["def a(): pass", "def b(): pass", "def c(): pass"]
    assert measure_naming(sources) == []


def test_measure_naming_below_agreement_min():
    sources = [f"def snake_func_{i}(): pass" for i in range(5)]
    sources.extend([f"def camelCase{i}(): pass" for i in range(5)])
    assert measure_naming(sources) == []


def test_measure_naming_only_dunders():
    sources = [f"def __init_{i}__(): pass" for i in range(15)]
    assert measure_naming(sources) == []


def test_measure_naming_unparseable_source():
    sources = [
        "def def error",
    ] + [f"def func_{i}(): pass" for i in range(10)]
    measured = measure_naming(sources)
    assert len(measured) == 1
    assert measured[0].sample_size == 10


def test_round_trip():
    measured = [
        MeasuredConvention(
            checker="naming.identifier",
            params={"target": "function", "style": "snake_case"},
            agreement=0.95,
            sample_size=100,
        )
    ]
    draft = render_profile_draft(measured, "2026-05-31")
    parsed_toml = tomllib.loads(draft)
    profile = parse_profile(parsed_toml)
    assert profile.version == 1
    assert len(profile.conventions) == 1
    entry = profile.conventions[0]
    assert entry.id == "function-naming"
    assert entry.checker == "naming.identifier"
    assert entry.params == {"target": "function", "style": "snake_case"}


def test_render_profile_draft_empty():
    draft = render_profile_draft([], "2026-05-31")
    parsed_toml = tomllib.loads(draft)
    profile = parse_profile(parsed_toml)
    assert profile.version == 1
    assert len(profile.conventions) == 0


def test_convention_id():
    m = MeasuredConvention("naming.identifier", {"target": "function", "style": "snake_case"}, 1.0, 10)
    assert convention_id(m) == "function-naming"

    m2 = MeasuredConvention("layout.test-files", {"directory": "tests"}, 1.0, 10)
    assert convention_id(m2) == "layout-test-files"


def test_filter_net_new():
    m1 = MeasuredConvention("naming.identifier", {"target": "function", "style": "snake_case"}, 1.0, 10)
    m2 = MeasuredConvention("naming.identifier", {"target": "class", "style": "PascalCase"}, 1.0, 10)

    assert filter_net_new([m1, m2], None) == [m1, m2]

    existing = Profile(
        version=1,
        conventions=(
            ConventionEntry("function-naming", "naming.identifier", Severity.LOW, True, {}),
        )
    )
    assert filter_net_new([m1, m2], existing) == [m2]


def test_measure_test_layout_proposes_tests_dir():
    files = [(f"tests/test_{i}.py", "def test_x():\n    assert 1\n") for i in range(12)]
    m = measure_test_layout(files)
    assert len(m) == 1
    assert m[0].checker == "layout.test-files"
    assert m[0].params == {"directory": "tests", "filename": "test_*.py"}


def test_measure_test_layout_finds_nested_tests_dir():
    files = [(f"src/pkg/tests/test_{i}.py", "def test_x():\n    assert 1\n") for i in range(12)]
    assert measure_test_layout(files)[0].params["directory"] == "tests"


def test_measure_test_layout_no_proposal_when_dir_is_not_conventional():
    # Tests not in a tests/ or test/ dir (here under absolute/garbage segments)
    # must yield NO proposal - never propose a stray path segment as the test dir.
    files = [(f"/tmp/scratch-xyz/test_{i}.py", "def test_x():\n    assert 1\n") for i in range(12)]
    assert measure_test_layout(files) == []


def test_measure_test_layout_valid():
    files = []
    for i in range(12):
        files.append((f"tests/test_foo_{i}.py", "def test_x(): pass"))

    measured = measure_test_layout(files)
    assert len(measured) == 1
    m = measured[0]
    assert m.checker == "layout.test-files"
    assert m.params == {"directory": "tests", "filename": "test_*.py"}
    assert m.agreement == 1.0
    assert m.sample_size == 12


def test_measure_test_layout_below_sample_min():
    files = []
    for i in range(5):
        files.append((f"tests/test_foo_{i}.py", "def test_x(): pass"))
    assert measure_test_layout(files) == []


def test_measure_test_layout_50_50_split():
    files = []
    for i in range(5):
        files.append((f"tests/test_foo_{i}.py", "def test_x(): pass"))
    for i in range(5):
        files.append((f"other/foo_{i}_test.py", "def test_x(): pass"))
    # 10 test modules, but dir is split 50/50, pattern is split 50/50
    assert measure_test_layout(files) == []


def test_measure_test_layout_non_test_files_ignored():
    files = []
    # Real test files
    for i in range(10):
        files.append((f"tests/test_foo_{i}.py", "def test_x(): pass"))
    # Test-ish name, no test function
    for i in range(5):
        files.append((f"tests/test_util_{i}.py", "def helper(): pass"))
    # Non-test names
    for i in range(5):
        files.append((f"src/app_{i}.py", "def test_x(): pass"))

    measured = measure_test_layout(files)
    assert len(measured) == 1
    assert measured[0].sample_size == 10  # Only the real 10 are counted
