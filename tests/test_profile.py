"""Tests for the convention profile parser and validation."""

import pytest

from rein.core.findings import Severity
from rein.core.profile import (
    PROFILE_VERSION,
    CheckerSpec,
    ConventionEntry,
    ParamSpec,
    ProfileError,
    _parse_params,
    parse_profile,
    profile_invalid_finding,
)


def test_parse_profile_valid_one_convention():
    data = {
        "version": PROFILE_VERSION,
        "conventions": {
            "test-func-naming": {
                "checker": "naming.identifier",
                "severity": "medium",
                "enabled": True,
                "target": "function",
                "style": "snake_case",
            }
        },
    }
    profile = parse_profile(data)
    assert profile.version == PROFILE_VERSION
    assert len(profile.conventions) == 1
    entry = profile.conventions[0]
    assert entry.id == "test-func-naming"
    assert entry.checker == "naming.identifier"
    assert entry.severity == Severity.MEDIUM
    assert entry.enabled is True
    assert entry.params == {"target": "function", "style": "snake_case"}


def test_parse_profile_omitted_severity_defaults_to_low():
    data = {
        "version": PROFILE_VERSION,
        "conventions": {
            "test-func-naming": {
                "checker": "naming.identifier",
                "target": "function",
                "style": "snake_case",
            }
        },
    }
    profile = parse_profile(data)
    assert profile.conventions[0].severity == Severity.LOW


def test_parse_profile_omitted_enabled_defaults_to_true():
    data = {
        "version": PROFILE_VERSION,
        "conventions": {
            "test-func-naming": {
                "checker": "naming.identifier",
                "target": "function",
                "style": "snake_case",
            }
        },
    }
    profile = parse_profile(data)
    assert profile.conventions[0].enabled is True


def test_parse_profile_enabled_false():
    data = {
        "version": PROFILE_VERSION,
        "conventions": {
            "test-func-naming": {
                "checker": "naming.identifier",
                "enabled": False,
                "target": "function",
                "style": "snake_case",
            }
        },
    }
    profile = parse_profile(data)
    assert profile.conventions[0].enabled is False


def test_parse_profile_evidence_retained():
    data = {
        "version": PROFILE_VERSION,
        "conventions": {
            "test-func-naming": {
                "checker": "naming.identifier",
                "target": "function",
                "style": "snake_case",
                "evidence": {
                    "source": "measured",
                    "agreement": 0.99,
                    "sample_size": 42,
                },
            }
        },
    }
    profile = parse_profile(data)
    entry = profile.conventions[0]
    assert entry.params == {"target": "function", "style": "snake_case"}
    assert entry.evidence == {
        "source": "measured",
        "agreement": 0.99,
        "sample_size": 42,
    }


def test_parse_profile_evidence_absent_defaults_to_none():
    data = {
        "version": PROFILE_VERSION,
        "conventions": {
            "test-func-naming": {
                "checker": "naming.identifier",
                "target": "function",
                "style": "snake_case",
            }
        },
    }
    profile = parse_profile(data)
    entry = profile.conventions[0]
    assert entry.evidence is None


def test_convention_entry_constructor_without_evidence():
    # Existing construction without evidence must still compile and default to None.
    entry = ConventionEntry(
        id="test-id",
        checker="naming.identifier",
        severity=Severity.LOW,
        enabled=True,
        params={"target": "function", "style": "snake_case"},
    )
    assert entry.evidence is None


def test_parse_profile_absent_conventions():
    data = {"version": PROFILE_VERSION}
    profile = parse_profile(data)
    assert len(profile.conventions) == 0


def test_parse_profile_two_conventions_sorted_by_id():
    data = {
        "version": PROFILE_VERSION,
        "conventions": {
            "z-naming": {
                "checker": "naming.identifier",
                "target": "function",
                "style": "snake_case",
            },
            "a-naming": {
                "checker": "naming.identifier",
                "target": "class",
                "style": "PascalCase",
            },
        },
    }
    profile = parse_profile(data)
    assert len(profile.conventions) == 2
    assert profile.conventions[0].id == "a-naming"
    assert profile.conventions[1].id == "z-naming"


# Failure cases

def test_parse_profile_missing_version():
    with pytest.raises(ProfileError, match="missing version"):
        parse_profile({})


def test_parse_profile_version_2():
    with pytest.raises(ProfileError, match="upgrade rein"):
        parse_profile({"version": 2})


def test_parse_profile_version_wrong_type():
    with pytest.raises(ProfileError, match="version must be an integer"):
        parse_profile({"version": "1"})


def test_parse_profile_version_bool_rejected():
    # bool is a subclass of int and True == 1, so a naive isinstance(int) check
    # would silently accept `version = true` as version 1. It must be rejected.
    with pytest.raises(ProfileError, match="version must be an integer"):
        parse_profile({"version": True})


def test_parse_profile_unknown_toplevel_key():
    with pytest.raises(ProfileError, match="unknown top-level key: foo"):
        parse_profile({"version": 1, "foo": "bar"})


def test_parse_profile_convention_not_a_dict():
    with pytest.raises(ProfileError, match="convention 'c1' must be a dictionary"):
        parse_profile({"version": 1, "conventions": {"c1": []}})


def test_parse_profile_missing_checker():
    data = {
        "version": 1,
        "conventions": {
            "c1": {"target": "function", "style": "snake_case"}
        },
    }
    with pytest.raises(ProfileError, match="convention 'c1' missing required key 'checker'"):
        parse_profile(data)


def test_parse_profile_unknown_checker():
    data = {
        "version": 1,
        "conventions": {
            "c1": {"checker": "foo.bar"}
        },
    }
    with pytest.raises(ProfileError, match="convention 'c1' has unknown checker 'foo.bar'"):
        parse_profile(data)


def test_parse_profile_unknown_key_in_convention():
    data = {
        "version": 1,
        "conventions": {
            "c1": {
                "checker": "naming.identifier",
                "target": "function",
                "style": "snake_case",
                "foo": "bar",
            }
        },
    }
    with pytest.raises(ProfileError, match="convention 'c1' has unknown key 'foo'"):
        parse_profile(data)


def test_parse_profile_missing_required_param():
    data = {
        "version": 1,
        "conventions": {
            "c1": {
                "checker": "naming.identifier",
                "target": "function",
            }
        },
    }
    with pytest.raises(ProfileError, match="convention 'c1' missing required param 'style'"):
        parse_profile(data)


def test_parse_profile_param_value_out_of_set():
    data = {
        "version": 1,
        "conventions": {
            "c1": {
                "checker": "naming.identifier",
                "target": "function",
                "style": "fooCase",
            }
        },
    }
    with pytest.raises(ProfileError, match="invalid; allowed: PascalCase, UPPER_CASE, camelCase, snake_case"):
        parse_profile(data)


def test_parse_profile_invalid_severity():
    data = {
        "version": 1,
        "conventions": {
            "c1": {
                "checker": "naming.identifier",
                "severity": "foo",
                "target": "function",
                "style": "snake_case",
            }
        },
    }
    with pytest.raises(ProfileError, match="convention 'c1' has invalid severity 'foo'"):
        parse_profile(data)


def test_parse_profile_non_bool_enabled():
    data = {
        "version": 1,
        "conventions": {
            "c1": {
                "checker": "naming.identifier",
                "enabled": "yes",
                "target": "function",
                "style": "snake_case",
            }
        },
    }
    with pytest.raises(ProfileError, match="convention 'c1' key 'enabled' must be a boolean"):
        parse_profile(data)


def test_parse_profile_non_dict_evidence():
    data = {
        "version": 1,
        "conventions": {
            "c1": {
                "checker": "naming.identifier",
                "evidence": "foo",
                "target": "function",
                "style": "snake_case",
            }
        },
    }
    with pytest.raises(ProfileError, match="convention 'c1' key 'evidence' must be a dictionary"):
        parse_profile(data)


def test_parse_profile_data_not_a_dict():
    with pytest.raises(ProfileError, match="data must be a dictionary"):
        parse_profile([])


def test_profile_invalid_finding_factory():
    finding = profile_invalid_finding("bad format")
    assert finding.rule_id == "rein.profile-invalid"
    assert finding.severity == Severity.HIGH
    assert "bad format" in finding.message
    assert "profile" in finding.tags
    assert "config" in finding.tags


def test_parse_profile_layout_valid():
    data = {
        "version": PROFILE_VERSION,
        "conventions": {
            "c1": {
                "checker": "layout.test-files",
                "directory": "tests/",
                "filename": "test_*.py",
            }
        },
    }
    profile = parse_profile(data)
    assert profile.conventions[0].params == {"directory": "tests/", "filename": "test_*.py"}


def test_parse_profile_layout_missing_filename():
    data = {
        "version": PROFILE_VERSION,
        "conventions": {
            "c1": {
                "checker": "layout.test-files",
                "directory": "tests/",
            }
        },
    }
    with pytest.raises(ProfileError, match="convention 'c1' missing required param 'filename'"):
        parse_profile(data)


def test_parse_profile_layout_empty_directory():
    data = {
        "version": PROFILE_VERSION,
        "conventions": {
            "c1": {
                "checker": "layout.test-files",
                "directory": "",
                "filename": "test_*.py",
            }
        },
    }
    with pytest.raises(ProfileError, match="convention 'c1' param 'directory' must be a non-empty string"):
        parse_profile(data)


def test_parse_profile_layout_non_string_directory():
    data = {
        "version": PROFILE_VERSION,
        "conventions": {
            "c1": {
                "checker": "layout.test-files",
                "directory": 123,
                "filename": "test_*.py",
            }
        },
    }
    with pytest.raises(ProfileError, match="convention 'c1' param 'directory' must be a non-empty string"):
        parse_profile(data)


def test_parse_params_list_str_valid():
    spec = CheckerSpec({"my_list": ParamSpec("list_str")}, Severity.LOW)
    entry = {"my_list": ["a", "b"]}
    assert _parse_params("c1", entry, spec) == {"my_list": ["a", "b"]}


def test_parse_params_list_str_invalid_not_list():
    spec = CheckerSpec({"my_list": ParamSpec("list_str")}, Severity.LOW)
    with pytest.raises(ProfileError, match="must be a non-empty list of non-empty strings"):
        _parse_params("c1", {"my_list": "a"}, spec)


def test_parse_params_list_str_invalid_empty():
    spec = CheckerSpec({"my_list": ParamSpec("list_str")}, Severity.LOW)
    with pytest.raises(ProfileError, match="must be a non-empty list of non-empty strings"):
        _parse_params("c1", {"my_list": []}, spec)


def test_parse_params_list_str_invalid_empty_item():
    spec = CheckerSpec({"my_list": ParamSpec("list_str")}, Severity.LOW)
    with pytest.raises(ProfileError, match="must be a non-empty list of non-empty strings"):
        _parse_params("c1", {"my_list": ["a", ""]}, spec)


def test_parse_params_optional_str_absent():
    spec = CheckerSpec({"my_opt": ParamSpec("str", required=False)}, Severity.LOW)
    assert _parse_params("c1", {}, spec) == {}


def test_parse_params_optional_str_present():
    spec = CheckerSpec({"my_opt": ParamSpec("str", required=False)}, Severity.LOW)
    assert _parse_params("c1", {"my_opt": "val"}, spec) == {"my_opt": "val"}


def test_parse_params_optional_str_present_but_invalid():
    spec = CheckerSpec({"my_opt": ParamSpec("str", required=False)}, Severity.LOW)
    with pytest.raises(ProfileError, match="must be a non-empty string"):
        _parse_params("c1", {"my_opt": ""}, spec)


def test_parse_params_int_valid():
    spec = CheckerSpec({"budget": ParamSpec("int")}, Severity.LOW)
    assert _parse_params("c1", {"budget": 5}, spec) == {"budget": 5}


def test_parse_params_int_one_is_valid():
    spec = CheckerSpec({"budget": ParamSpec("int")}, Severity.LOW)
    assert _parse_params("c1", {"budget": 1}, spec) == {"budget": 1}


def test_parse_params_int_zero_rejected():
    spec = CheckerSpec({"budget": ParamSpec("int")}, Severity.LOW)
    with pytest.raises(ProfileError, match="must be a positive integer"):
        _parse_params("c1", {"budget": 0}, spec)


def test_parse_params_int_negative_rejected():
    spec = CheckerSpec({"budget": ParamSpec("int")}, Severity.LOW)
    with pytest.raises(ProfileError, match="must be a positive integer"):
        _parse_params("c1", {"budget": -3}, spec)


def test_parse_params_int_non_int_rejected():
    spec = CheckerSpec({"budget": ParamSpec("int")}, Severity.LOW)
    with pytest.raises(ProfileError, match="must be a positive integer"):
        _parse_params("c1", {"budget": "5"}, spec)


def test_parse_params_int_bool_true_rejected():
    # True is an int subclass; a budget of `true` must not be silently treated as 1.
    spec = CheckerSpec({"budget": ParamSpec("int")}, Severity.LOW)
    with pytest.raises(ProfileError, match="must be a positive integer"):
        _parse_params("c1", {"budget": True}, spec)


def test_parse_params_int_bool_false_rejected():
    spec = CheckerSpec({"budget": ParamSpec("int")}, Severity.LOW)
    with pytest.raises(ProfileError, match="must be a positive integer"):
        _parse_params("c1", {"budget": False}, spec)
