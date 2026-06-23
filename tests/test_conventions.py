"""Tests for the convention checker engine."""

from rein.core import conventions, profile
from rein.core.findings import Severity


def test_naming_identifier_true_positives():
    text = """
def getUserData():
    pass

class myClass:
    def doThing(self):
        pass
"""
    prof = profile.Profile(
        version=1,
        conventions=(
            profile.ConventionEntry(
                id="c1",
                checker="naming.identifier",
                severity=Severity.LOW,
                enabled=True,
                params={"target": "function", "style": "snake_case"},
            ),
            profile.ConventionEntry(
                id="c2",
                checker="naming.identifier",
                severity=Severity.MEDIUM,
                enabled=True,
                params={"target": "class", "style": "PascalCase"},
            ),
        ),
    )
    findings = conventions.scan_profile(text, "test.py", prof)
    assert len(findings) == 3

    # The order of ast.walk is not strictly depth-first or guaranteed, so sort by line
    findings.sort(key=lambda f: f.line)

    assert findings[0].rule_id == "convention.c1"
    assert findings[0].snippet == "getUserData"
    assert findings[0].line == 2
    assert findings[0].severity == Severity.LOW

    assert findings[1].rule_id == "convention.c2"
    assert findings[1].snippet == "myClass"
    assert findings[1].line == 5
    assert findings[1].severity == Severity.MEDIUM

    assert findings[2].rule_id == "convention.c1"
    assert findings[2].snippet == "doThing"
    assert findings[2].line == 6


def test_naming_identifier_near_zero_fp_basket_function_snake_case():
    text = """
def foo(): pass
def foo_bar(): pass
def _private(): pass
def __init__(): pass
def __enter__(): pass
def _(): pass
def f2(): pass
def read_csv(): pass
"""
    prof = profile.Profile(
        version=1,
        conventions=(
            profile.ConventionEntry(
                id="c1",
                checker="naming.identifier",
                severity=Severity.LOW,
                enabled=True,
                params={"target": "function", "style": "snake_case"},
            ),
        ),
    )
    findings = conventions.scan_profile(text, "test.py", prof)
    assert len(findings) == 0


def test_naming_identifier_near_zero_fp_basket_class_pascalcase():
    text = """
class MyClass: pass
class HTTPServer: pass
class URLParser: pass
class _Private: pass
"""
    prof = profile.Profile(
        version=1,
        conventions=(
            profile.ConventionEntry(
                id="c1",
                checker="naming.identifier",
                severity=Severity.LOW,
                enabled=True,
                params={"target": "class", "style": "PascalCase"},
            ),
        ),
    )
    findings = conventions.scan_profile(text, "test.py", prof)
    assert len(findings) == 0


def test_naming_identifier_camelcase():
    text = """
def getUser(): pass
def get_user(): pass
"""
    prof = profile.Profile(
        version=1,
        conventions=(
            profile.ConventionEntry(
                id="c1",
                checker="naming.identifier",
                severity=Severity.LOW,
                enabled=True,
                params={"target": "function", "style": "camelCase"},
            ),
        ),
    )
    findings = conventions.scan_profile(text, "test.py", prof)
    assert len(findings) == 1
    assert findings[0].snippet == "get_user"


def test_enabled_false_skipped():
    text = "def getUserData(): pass"
    prof = profile.Profile(
        version=1,
        conventions=(
            profile.ConventionEntry(
                id="c1",
                checker="naming.identifier",
                severity=Severity.LOW,
                enabled=False,
                params={"target": "function", "style": "snake_case"},
            ),
        ),
    )
    findings = conventions.scan_profile(text, "test.py", prof)
    assert len(findings) == 0


def test_unparseable_source_safe():
    prof = profile.Profile(
        version=1,
        conventions=(
            profile.ConventionEntry(
                id="c1",
                checker="naming.identifier",
                severity=Severity.LOW,
                enabled=True,
                params={"target": "function", "style": "snake_case"},
            ),
        ),
    )
    findings = conventions.scan_profile("def def foo", "test.py", prof)
    assert len(findings) == 0


def test_drift_guard():
    assert set(profile.CHECKERS) == set(conventions._RUNNERS)


def test_layout_test_files_true_positives():
    prof = profile.Profile(
        version=1,
        conventions=(
            profile.ConventionEntry(
                id="c1",
                checker="layout.test-files",
                severity=Severity.LOW,
                enabled=True,
                params={"directory": "tests", "filename": "test_*.py"},
            ),
        ),
    )
    # Misplaced src
    findings = conventions.scan_profile("def test_x(): pass", "src/test_foo.py", prof)
    assert len(findings) == 1
    assert "outside the configured test directory" in findings[0].message

    # Misplaced root
    findings = conventions.scan_profile("def test_x(): pass", "test_foo.py", prof)
    assert len(findings) == 1
    assert "outside the configured test directory" in findings[0].message

    # Misnamed
    findings = conventions.scan_profile("def test_x(): pass", "tests/foo_test.py", prof)
    assert len(findings) == 1
    assert "does not match the naming pattern" in findings[0].message


def test_layout_test_files_near_zero_fp_basket():
    prof = profile.Profile(
        version=1,
        conventions=(
            profile.ConventionEntry(
                id="c1",
                checker="layout.test-files",
                severity=Severity.LOW,
                enabled=True,
                params={"directory": "tests", "filename": "test_*.py"},
            ),
        ),
    )

    # Incidental, non-test name
    assert len(conventions.scan_profile("def test_connection(): pass", "src/utils.py", prof)) == 0

    # Test name, no test fn
    assert len(conventions.scan_profile("DATA=[1]", "src/test_data.py", prof)) == 0

    # Fixture in tests
    assert len(conventions.scan_profile("def pytest_configure(): pass", "tests/conftest.py", prof)) == 0

    # Init in tests
    assert len(conventions.scan_profile("", "tests/__init__.py", prof)) == 0

    # Helper in tests
    assert len(conventions.scan_profile("def helper(): pass", "tests/helpers.py", prof)) == 0

    # Correct test
    assert len(conventions.scan_profile("def test_x(): pass", "tests/test_foo.py", prof)) == 0

    # Normal module
    assert len(conventions.scan_profile("def run(): pass", "src/app.py", prof)) == 0


def test_forbid_call_true_positives():
    prof = profile.Profile(
        version=1,
        conventions=(
            profile.ConventionEntry(
                id="c1",
                checker="forbid.call",
                severity=Severity.MEDIUM,
                enabled=True,
                params={"calls": ["print", "os.system"]},
            ),
        ),
    )

    findings = conventions.scan_profile('print("x")', "test.py", prof)
    assert len(findings) == 1
    assert "call to 'print' is forbidden" in findings[0].message
    assert findings[0].snippet == "print"

    findings = conventions.scan_profile('from os import system\nsystem("x")', "test.py", prof)
    assert len(findings) == 1
    assert "call to 'os.system' is forbidden" in findings[0].message
    assert findings[0].snippet == "os.system"


def test_forbid_call_near_zero_fp_basket():
    prof = profile.Profile(
        version=1,
        conventions=(
            profile.ConventionEntry(
                id="c1",
                checker="forbid.call",
                severity=Severity.MEDIUM,
                enabled=True,
                params={"calls": ["print"]},
            ),
        ),
    )
    # comment
    assert len(conventions.scan_profile('# print("x")', "test.py", prof)) == 0
    # string
    assert len(conventions.scan_profile('s = "print(1)"', "test.py", prof)) == 0
    # substring
    assert len(conventions.scan_profile('printer()', "test.py", prof)) == 0
    # unrelated
    assert len(conventions.scan_profile('os.system("x")', "test.py", prof)) == 0


def test_forbid_call_path_scoping():
    prof = profile.Profile(
        version=1,
        conventions=(
            profile.ConventionEntry(
                id="c1",
                checker="forbid.call",
                severity=Severity.MEDIUM,
                enabled=True,
                params={"calls": ["print"], "paths": ["src/core/*"]},
            ),
        ),
    )

    # Matches
    assert len(conventions.scan_profile('print()', "src/core/a.py", prof)) == 1
    # Different dir
    assert len(conventions.scan_profile('print()', "cli/b.py", prof)) == 0
    # path=None
    assert len(conventions.scan_profile('print()', None, prof)) == 0


def test_forbid_call_custom_message():
    prof = profile.Profile(
        version=1,
        conventions=(
            profile.ConventionEntry(
                id="c1",
                checker="forbid.call",
                severity=Severity.MEDIUM,
                enabled=True,
                params={"calls": ["print"], "message": "use logger"},
            ),
        ),
    )
    findings = conventions.scan_profile('print("x")', "test.py", prof)
    assert len(findings) == 1
    assert findings[0].message == "use logger"


def test_forbid_import_true_positives():
    prof = profile.Profile(
        version=1,
        conventions=(
            profile.ConventionEntry(
                id="c1",
                checker="forbid.import",
                severity=Severity.MEDIUM,
                enabled=True,
                params={"imports": ["requests"]},
            ),
        ),
    )

    findings = conventions.scan_profile('import requests', "test.py", prof)
    assert len(findings) == 1
    assert "import of 'requests' is forbidden" in findings[0].message

    findings = conventions.scan_profile('import requests as r', "test.py", prof)
    assert len(findings) == 1

    findings = conventions.scan_profile('from requests import get', "test.py", prof)
    assert len(findings) == 1

    findings = conventions.scan_profile('import requests.adapters', "test.py", prof)
    assert len(findings) == 1

    findings = conventions.scan_profile('from requests.adapters import X', "test.py", prof)
    assert len(findings) == 1


def test_forbid_import_near_zero_fp_basket():
    prof = profile.Profile(
        version=1,
        conventions=(
            profile.ConventionEntry(
                id="c1",
                checker="forbid.import",
                severity=Severity.MEDIUM,
                enabled=True,
                params={"imports": ["requests"]},
            ),
        ),
    )

    # different module sharing prefix
    assert len(conventions.scan_profile('import requests_oauthlib', "test.py", prof)) == 0
    # comment
    assert len(conventions.scan_profile('# import requests', "test.py", prof)) == 0
    # string
    assert len(conventions.scan_profile('s = "import requests"', "test.py", prof)) == 0
    # relative
    assert len(conventions.scan_profile('from . import requests', "test.py", prof)) == 0


def test_forbid_import_path_scoping():
    prof = profile.Profile(
        version=1,
        conventions=(
            profile.ConventionEntry(
                id="c1",
                checker="forbid.import",
                severity=Severity.MEDIUM,
                enabled=True,
                params={"imports": ["requests"], "paths": ["src/core/*"]},
            ),
        ),
    )

    assert len(conventions.scan_profile('import requests', "src/core/a.py", prof)) == 1
    assert len(conventions.scan_profile('import requests', "cli/b.py", prof)) == 0


def test_forbid_import_custom_message():
    prof = profile.Profile(
        version=1,
        conventions=(
            profile.ConventionEntry(
                id="c1",
                checker="forbid.import",
                severity=Severity.MEDIUM,
                enabled=True,
                params={"imports": ["requests"], "message": "use httpx"},
            ),
        ),
    )
    findings = conventions.scan_profile('import requests', "test.py", prof)
    assert len(findings) == 1
    assert findings[0].message == "use httpx"


# -- arch.layering -----------------------------------------------------------

def test_arch_layering_absolute_prefix_flagged():
    prof = profile.Profile(
        version=1,
        conventions=(
            profile.ConventionEntry(
                id="core-purity",
                checker="arch.layering",
                severity=Severity.MEDIUM,
                enabled=True,
                params={"paths": ["src/rein/core/*"], "forbidden": ["rein.cli"]},
            ),
        ),
    )

    # 1. Absolute prefix match (import rein.cli)
    text = "import rein.cli"
    findings = conventions.scan_profile(text, "src/rein/core/lint.py", prof)
    assert len(findings) == 1
    assert findings[0].rule_id == "convention.core-purity"
    assert findings[0].snippet == "rein.cli"
    assert "layer must not import 'rein.cli'" in findings[0].message


def test_arch_layering_from_pkg_import_submodule_flagged():
    prof = profile.Profile(
        version=1,
        conventions=(
            profile.ConventionEntry(
                id="core-purity",
                checker="arch.layering",
                severity=Severity.MEDIUM,
                enabled=True,
                params={"paths": ["src/rein/core/*"], "forbidden": ["rein.cli"]},
            ),
        ),
    )

    # 2. from PKG import submodule (from rein import cli)
    text = "from rein import cli"
    findings = conventions.scan_profile(text, "src/rein/core/lint.py", prof)
    assert len(findings) == 1
    assert findings[0].snippet == "rein.cli"


def test_arch_layering_import_abc_flagged():
    prof = profile.Profile(
        version=1,
        conventions=(
            profile.ConventionEntry(
                id="core-purity",
                checker="arch.layering",
                severity=Severity.MEDIUM,
                enabled=True,
                params={"paths": ["src/rein/core/*"], "forbidden": ["rein.cli"]},
            ),
        ),
    )

    # 3. import a.b.c (import rein.cli.main)
    text = "import rein.cli.main"
    findings = conventions.scan_profile(text, "src/rein/core/lint.py", prof)
    assert len(findings) == 1
    assert findings[0].snippet == "rein.cli.main"


def test_arch_layering_relative_parent_flagged():
    prof = profile.Profile(
        version=1,
        conventions=(
            profile.ConventionEntry(
                id="core-purity",
                checker="arch.layering",
                severity=Severity.MEDIUM,
                enabled=True,
                params={"paths": ["src/rein/core/*"], "forbidden": ["rein.cli"]},
            ),
        ),
    )

    # 4. relative: from ..cli import x
    text = "from ..cli import x"
    findings = conventions.scan_profile(text, "src/rein/core/lint.py", prof)
    assert len(findings) == 1
    assert findings[0].snippet == "src.rein.cli"
    assert "layer must not import 'src.rein.cli'" in findings[0].message


def test_arch_layering_relative_import_cli_flagged():
    prof = profile.Profile(
        version=1,
        conventions=(
            profile.ConventionEntry(
                id="core-purity",
                checker="arch.layering",
                severity=Severity.MEDIUM,
                enabled=True,
                params={"paths": ["src/rein/core/*"], "forbidden": ["rein.cli"]},
            ),
        ),
    )

    # 5. relative: from .. import cli
    text = "from .. import cli"
    findings = conventions.scan_profile(text, "src/rein/core/lint.py", prof)
    assert len(findings) == 1
    assert findings[0].snippet == "src.rein.cli"


def test_arch_layering_path_scope_gating():
    prof = profile.Profile(
        version=1,
        conventions=(
            profile.ConventionEntry(
                id="core-purity",
                checker="arch.layering",
                severity=Severity.MEDIUM,
                enabled=True,
                params={"paths": ["src/rein/core/*"], "forbidden": ["rein.cli"]},
            ),
        ),
    )

    # 6. Out-of-scope file (cli/main.py) must not flag
    text = "import rein.cli"
    findings = conventions.scan_profile(text, "src/rein/cli/main.py", prof)
    assert len(findings) == 0


def test_arch_layering_escaping_relative_no_crash():
    prof = profile.Profile(
        version=1,
        conventions=(
            profile.ConventionEntry(
                id="core-purity",
                checker="arch.layering",
                severity=Severity.MEDIUM,
                enabled=True,
                params={"paths": ["src/rein/core/*"], "forbidden": ["rein.cli"]},
            ),
        ),
    )

    # 7. Escaping relative (too many dots) -> no crash/finding
    text = "from ...... import x"
    findings = conventions.scan_profile(text, "src/rein/core/lint.py", prof)
    assert len(findings) == 0


def test_arch_layering_near_zero_fp_basket():
    prof = profile.Profile(
        version=1,
        conventions=(
            profile.ConventionEntry(
                id="core-purity",
                checker="arch.layering",
                severity=Severity.MEDIUM,
                enabled=True,
                params={"paths": ["src/rein/core/*"], "forbidden": ["rein.cli"]},
            ),
        ),
    )

    # 8a. External import (e.g. standard library or requests) -> not flagged
    text1 = "import os\nimport sys"
    assert len(conventions.scan_profile(text1, "src/rein/core/lint.py", prof)) == 0

    # 8b. Dot boundary match protection (rein.client vs rein.cli) -> not flagged
    text2 = "import rein.client"
    assert len(conventions.scan_profile(text2, "src/rein/core/lint.py", prof)) == 0

    # 8c. Legit relative same-package import (from . import sibling) -> not flagged
    text3 = "from . import sibling"
    assert len(conventions.scan_profile(text3, "src/rein/core/lint.py", prof)) == 0


def test_arch_layering_custom_message():
    prof = profile.Profile(
        version=1,
        conventions=(
            profile.ConventionEntry(
                id="core-purity",
                checker="arch.layering",
                severity=Severity.MEDIUM,
                enabled=True,
                params={
                    "paths": ["src/rein/core/*"],
                    "forbidden": ["rein.cli"],
                    "message": "core purity rule broken",
                },
            ),
        ),
    )

    text = "import rein.cli"
    findings = conventions.scan_profile(text, "src/rein/core/lint.py", prof)
    assert findings[0].message == "core purity rule broken"


# -- imports.allowed -----------------------------------------------------------

def test_imports_allowed_true_positives():
    prof = profile.Profile(
        version=1,
        conventions=(
            profile.ConventionEntry(
                id="c1",
                checker="imports.allowed",
                severity=Severity.MEDIUM,
                enabled=True,
                params={"paths": ["src/*"], "allow": ["rein"]},
            ),
        ),
    )

    # requests flagged
    text = "import requests"
    findings = conventions.scan_profile(text, "src/a.py", prof)
    assert len(findings) == 1
    assert "not allowed" in findings[0].message
    assert findings[0].snippet == "requests"

    # from requests import x
    text = "from requests import x"
    findings = conventions.scan_profile(text, "src/a.py", prof)
    assert len(findings) == 1
    assert findings[0].snippet == "requests"


def test_imports_allowed_near_zero_fp():
    prof = profile.Profile(
        version=1,
        conventions=(
            profile.ConventionEntry(
                id="c1",
                checker="imports.allowed",
                severity=Severity.MEDIUM,
                enabled=True,
                params={"paths": ["src/*"], "allow": ["rein"]},
            ),
        ),
    )

    # stdlib ok
    text = "import os\nfrom sys import path\nimport urllib.request"
    assert len(conventions.scan_profile(text, "src/a.py", prof)) == 0

    # __future__ ok
    text = "from __future__ import annotations"
    assert len(conventions.scan_profile(text, "src/a.py", prof)) == 0

    # allow=["rein"] ok
    text = "import rein\nfrom rein.core import something"
    assert len(conventions.scan_profile(text, "src/a.py", prof)) == 0

    # relatives ok when they resolve under an allowed prefix (path-based)
    text = "from . import siblings\nfrom ..parent import x"
    assert len(conventions.scan_profile(text, "src/rein/core/a.py", prof)) == 0

    # scope gating (out of scope)
    text = "import django"
    assert len(conventions.scan_profile(text, "tests/test_x.py", prof)) == 0


def _imports_allowed_prof(allow, paths):
    return profile.Profile(
        version=1,
        conventions=(
            profile.ConventionEntry(
                id="c1",
                checker="imports.allowed",
                severity=Severity.MEDIUM,
                enabled=True,
                params={"paths": paths, "allow": allow},
            ),
        ),
    )


def test_imports_allowed_resolves_relative_imports():
    # A relative import is now CHECKED (no longer skipped): it resolves through
    # the file path to the module it actually names.
    prof = _imports_allowed_prof(["rein.core.findings"], ["*rein/core/review.py"])
    path = "src/rein/core/review.py"

    # from .findings -> src.rein.core.findings, matches the allowed prefix.
    assert len(conventions.scan_profile("from .findings import Finding", path, prof)) == 0

    # from .code -> src.rein.core.code, a different (concrete-domain) module.
    findings = conventions.scan_profile("from .code import code_domain", path, prof)
    assert len(findings) == 1
    assert findings[0].snippet == "src.rein.core.code"


def test_imports_allowed_matches_full_dotted_prefix():
    # allow is a full dotted prefix, not just a top-level package name.
    prof = _imports_allowed_prof(["rein.core.findings"], ["*rein/core/review.py"])
    path = "src/rein/core/review.py"

    # A sibling sub-package under the same top segment still fires.
    findings = conventions.scan_profile("from rein.core.code import x", path, prof)
    assert len(findings) == 1
    assert findings[0].snippet == "rein.core.code"

    # The exact allowed prefix passes.
    assert len(conventions.scan_profile("from rein.core.findings import x", path, prof)) == 0

    # stdlib is always allowed, regardless of the (narrow) allowlist.
    assert len(conventions.scan_profile("from dataclasses import dataclass", path, prof)) == 0


def test_imports_allowed_top_level_prefix_back_compat():
    # A top-level allow entry still behaves like before for core files.
    prof = _imports_allowed_prof(["rein"], ["*rein/core/*"])
    path = "src/rein/core/a.py"

    # A core relative import resolves under 'rein' -> allowed.
    assert len(conventions.scan_profile("from .findings import x", path, prof)) == 0

    # A third-party import still fires.
    findings = conventions.scan_profile("import yaml", path, prof)
    assert len(findings) == 1
    assert findings[0].snippet == "yaml"


# -- complexity.function -------------------------------------------------------

def _complexity_prof(**params):
    return profile.Profile(
        version=1,
        conventions=(
            profile.ConventionEntry(
                id="c1",
                checker="complexity.function",
                severity=Severity.MEDIUM,
                enabled=True,
                params=params,
            ),
        ),
    )


def test_complexity_params_over_budget_flagged():
    prof = _complexity_prof(max_params=2)
    text = "def f(a, b, c):\n    pass\n"
    findings = conventions.scan_profile(text, "a.py", prof)
    assert len(findings) == 1
    assert findings[0].snippet == "f"
    assert "3 parameters" in findings[0].message
    assert "budget 2" in findings[0].message


def test_complexity_params_equal_budget_ok():
    # DL7: flag on STRICT > budget; == conforms.
    prof = _complexity_prof(max_params=3)
    text = "def f(a, b, c):\n    pass\n"
    assert conventions.scan_profile(text, "a.py", prof) == []


def test_complexity_params_excludes_self_and_cls():
    prof = _complexity_prof(max_params=2)
    text = (
        "class C:\n"
        "    def m(self, a, b):\n"  # 2 real params -> OK
        "        pass\n"
        "    @classmethod\n"
        "    def k(cls, a, b):\n"  # 2 real params -> OK
        "        pass\n"
    )
    assert conventions.scan_profile(text, "a.py", prof) == []


def test_complexity_params_counts_vararg_and_kwarg():
    prof = _complexity_prof(max_params=2)
    text = "def f(a, *args, **kwargs):\n    pass\n"  # 1 + 1 + 1 = 3
    findings = conventions.scan_profile(text, "a.py", prof)
    assert len(findings) == 1
    assert "3 parameters" in findings[0].message


def test_complexity_nesting_over_budget_flagged():
    prof = _complexity_prof(max_nesting_depth=2)
    text = (
        "def f():\n"
        "    for x in y:\n"        # depth 1
        "        while z:\n"       # depth 2
        "            if q:\n"      # depth 3
        "                pass\n"
    )
    findings = conventions.scan_profile(text, "a.py", prof)
    assert len(findings) == 1
    assert "nesting depth 3" in findings[0].message
    assert "budget 2" in findings[0].message


def test_complexity_nesting_equal_budget_ok():
    prof = _complexity_prof(max_nesting_depth=2)
    text = (
        "def f():\n"
        "    for x in y:\n"        # depth 1
        "        if z:\n"          # depth 2
        "            pass\n"
    )
    assert conventions.scan_profile(text, "a.py", prof) == []


def test_complexity_elif_chain_not_inflated():
    # FP guard (DL5): a flat if/elif/elif/else is depth 1, not 4.
    prof = _complexity_prof(max_nesting_depth=1)
    text = (
        "def f():\n"
        "    if a:\n"
        "        pass\n"
        "    elif b:\n"
        "        pass\n"
        "    elif c:\n"
        "        pass\n"
        "    else:\n"
        "        pass\n"
    )
    assert conventions.scan_profile(text, "a.py", prof) == []


def test_complexity_try_adds_depth():
    prof = _complexity_prof(max_nesting_depth=1)
    text = (
        "def f():\n"
        "    try:\n"               # depth 1
        "        if x:\n"          # depth 2
        "            pass\n"
        "    except Exception:\n"
        "        pass\n"
    )
    findings = conventions.scan_profile(text, "a.py", prof)
    assert len(findings) == 1
    assert "nesting depth 2" in findings[0].message


def test_complexity_nested_function_judged_independently():
    # The outer function is NOT penalized for the inner function's depth.
    prof = _complexity_prof(max_nesting_depth=1)
    text = (
        "def outer():\n"
        "    def inner():\n"       # nested scope; not descended for `outer`
        "        for x in y:\n"    # depth 1 within `inner`
        "            if z:\n"      # depth 2 within `inner`
        "                pass\n"
    )
    findings = conventions.scan_profile(text, "a.py", prof)
    # only `inner` flagged (depth 2 > 1); `outer` body has depth 0 (def not descended)
    assert len(findings) == 1
    assert findings[0].snippet == "inner"


def test_complexity_lambda_ignored():
    prof = _complexity_prof(max_params=1)
    text = "g = lambda a, b, c: a\n"  # lambda is not a def -> ignored
    assert conventions.scan_profile(text, "a.py", prof) == []


def test_complexity_no_budget_is_noop():
    prof = _complexity_prof(paths=["a.py"])  # neither budget set
    text = "def f(a, b, c, d, e):\n    for x in y:\n        for z in w:\n            pass\n"
    assert conventions.scan_profile(text, "a.py", prof) == []


def test_complexity_path_scope_gating():
    prof = _complexity_prof(max_params=1, paths=["src/*"])
    text = "def f(a, b, c):\n    pass\n"
    assert conventions.scan_profile(text, "tests/t.py", prof) == []
    assert len(conventions.scan_profile(text, "src/a.py", prof)) == 1


def test_complexity_both_budgets_violated_two_findings():
    prof = _complexity_prof(max_params=1, max_nesting_depth=1)
    text = (
        "def f(a, b, c):\n"        # 3 params > 1
        "    for x in y:\n"        # depth 1
        "        if z:\n"          # depth 2 > 1
        "            pass\n"
    )
    findings = conventions.scan_profile(text, "a.py", prof)
    assert len(findings) == 2
    messages = sorted(f.message for f in findings)
    assert any("parameters" in m for m in messages)
    assert any("nesting depth" in m for m in messages)


def test_complexity_custom_message_overrides():
    prof = _complexity_prof(max_params=1, message="too wide")
    text = "def f(a, b):\n    pass\n"
    findings = conventions.scan_profile(text, "a.py", prof)
    assert len(findings) == 1
    assert findings[0].message == "too wide"


def test_complexity_async_function_checked():
    prof = _complexity_prof(max_params=1)
    text = "async def f(a, b):\n    pass\n"
    findings = conventions.scan_profile(text, "a.py", prof)
    assert len(findings) == 1
    assert findings[0].snippet == "f"
