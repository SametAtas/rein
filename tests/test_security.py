"""Tests for security rules -- one positive and one negative case per rule."""

from __future__ import annotations

from rein.core.security import scan_security


def _ids(text: str) -> set[str]:
    return {f.rule_id for f in scan_security(text)}


# -- security.eval-exec ------------------------------------------------------

def test_eval_flagged() -> None:
    assert "security.eval-exec" in _ids('eval("1 + 1")\n')


def test_exec_flagged() -> None:
    assert "security.eval-exec" in _ids('exec("x = 1")\n')


def test_eval_not_flagged_without_call() -> None:
    assert "security.eval-exec" not in _ids("x = 1\n")


# -- security.pickle-load ---------------------------------------------------

def test_pickle_load_flagged() -> None:
    assert "security.pickle-load" in _ids("import pickle\npickle.load(f)\n")


def test_pickle_loads_flagged() -> None:
    assert "security.pickle-load" in _ids("import pickle\npickle.loads(b)\n")


def test_cpickle_load_flagged() -> None:
    assert "security.pickle-load" in _ids("import cPickle\ncPickle.load(f)\n")


# -- security.marshal-loads ---------------------------------------------------

def test_marshal_loads_flagged() -> None:
    assert "security.marshal-loads" in _ids("import marshal\nmarshal.loads(b)\n")


def test_marshal_dumps_not_flagged() -> None:
    assert "security.marshal-loads" not in _ids("import marshal\nmarshal.dumps(b)\n")


# -- security.os-system ------------------------------------------------------

def test_os_system_flagged() -> None:
    assert "security.os-system" in _ids('import os\nos.system("ls")\n')


def test_os_popen_flagged() -> None:
    assert "security.os-system" in _ids('import os\nos.popen("ls")\n')


# -- security.subprocess-shell -----------------------------------------------

def test_subprocess_shell_true_flagged() -> None:
    src = 'import subprocess\nsubprocess.run("ls", shell=True)\n'
    assert "security.subprocess-shell" in _ids(src)


def test_subprocess_call_shell_true_flagged() -> None:
    src = 'import subprocess\nsubprocess.call("ls", shell=True)\n'
    assert "security.subprocess-shell" in _ids(src)


def test_subprocess_run_no_shell_not_flagged() -> None:
    src = 'import subprocess\nsubprocess.run(["ls"])\n'
    assert "security.subprocess-shell" not in _ids(src)


def test_subprocess_run_shell_false_not_flagged() -> None:
    src = 'import subprocess\nsubprocess.run(["ls"], shell=False)\n'
    assert "security.subprocess-shell" not in _ids(src)


# -- security.yaml-unsafe-load -----------------------------------------------

def test_yaml_load_no_loader_flagged() -> None:
    assert "security.yaml-unsafe-load" in _ids("import yaml\nyaml.load(x)\n")


def test_yaml_safe_load_not_flagged() -> None:
    assert "security.yaml-unsafe-load" not in _ids(
        "import yaml\nyaml.safe_load(x)\n"
    )


def test_yaml_load_with_loader_kwarg_not_flagged() -> None:
    src = "import yaml\nyaml.load(x, Loader=yaml.SafeLoader)\n"
    assert "security.yaml-unsafe-load" not in _ids(src)


def test_yaml_load_with_second_arg_not_flagged() -> None:
    src = "import yaml\nyaml.load(x, yaml.SafeLoader)\n"
    assert "security.yaml-unsafe-load" not in _ids(src)


# -- security.requests-no-verify ---------------------------------------------

def test_requests_verify_false_flagged() -> None:
    src = 'import requests\nrequests.get("http://x", verify=False)\n'
    assert "security.requests-no-verify" in _ids(src)


def test_requests_get_no_verify_not_flagged() -> None:
    src = 'import requests\nrequests.get("http://x")\n'
    assert "security.requests-no-verify" not in _ids(src)


def test_requests_verify_true_not_flagged() -> None:
    src = 'import requests\nrequests.get("http://x", verify=True)\n'
    assert "security.requests-no-verify" not in _ids(src)


# -- security.weak-hash ------------------------------------------------------

def test_hashlib_md5_flagged() -> None:
    assert "security.weak-hash" in _ids('import hashlib\nhashlib.md5(b"x")\n')


def test_hashlib_sha1_flagged() -> None:
    assert "security.weak-hash" in _ids('import hashlib\nhashlib.sha1(b"x")\n')


def test_hashlib_new_md5_flagged() -> None:
    assert "security.weak-hash" in _ids('import hashlib\nhashlib.new("md5")\n')


def test_hashlib_new_sha1_flagged() -> None:
    assert "security.weak-hash" in _ids('import hashlib\nhashlib.new(name="sha1")\n')


def test_hashlib_new_sha256_not_flagged() -> None:
    assert "security.weak-hash" not in _ids(
        'import hashlib\nhashlib.new("sha256")\n'
    )


def test_hashlib_sha256_not_flagged() -> None:
    assert "security.weak-hash" not in _ids(
        'import hashlib\nhashlib.sha256(b"x")\n'
    )


# -- security.ssl-unverified-context -----------------------------------------

def test_ssl_unverified_context_flagged() -> None:
    assert "security.ssl-unverified-context" in _ids(
        "import ssl\nssl._create_unverified_context()\n"
    )


def test_ssl_create_default_context_not_flagged() -> None:
    assert "security.ssl-unverified-context" not in _ids(
        "import ssl\nssl.create_default_context()\n"
    )


# -- security.insecure-temp --------------------------------------------------

def test_tempfile_mktemp_flagged() -> None:
    assert "security.insecure-temp" in _ids(
        "import tempfile\ntempfile.mktemp()\n"
    )


def test_tempfile_mkstemp_not_flagged() -> None:
    assert "security.insecure-temp" not in _ids(
        "import tempfile\ntempfile.mkstemp()\n"
    )


# -- pragma suppression -------------------------------------------------------

def test_line_finding_has_security_tag() -> None:
    findings = scan_security("eval(x)\n")
    assert findings[0].tags == ("security",)


def test_import_alias_os_system_caught() -> None:
    findings = scan_security("from os import system\nsystem('ls')\n")
    assert len(findings) == 1
    assert findings[0].rule_id == "security.os-system"


def test_import_alias_os_system_as_caught() -> None:
    findings = scan_security("import os as o\no.system('ls')\n")
    assert len(findings) == 1
    assert findings[0].rule_id == "security.os-system"


def test_import_alias_subprocess_run_caught() -> None:
    findings = scan_security("import subprocess as sp\nsp.run('ls', shell=True)\n")
    assert len(findings) == 1
    assert findings[0].rule_id == "security.subprocess-shell"


def test_import_alias_subprocess_run_from_caught() -> None:
    findings = scan_security("from subprocess import run\nrun('ls', shell=True)\n")
    assert len(findings) == 1
    assert findings[0].rule_id == "security.subprocess-shell"


def test_import_alias_yaml_load_caught() -> None:
    findings = scan_security("from yaml import load\nload(x)\n")
    assert len(findings) == 1
    assert findings[0].rule_id == "security.yaml-unsafe-load"


def test_import_alias_pickle_loads_caught() -> None:
    findings = scan_security("from pickle import loads\nloads(b)\n")
    assert len(findings) == 1
    assert findings[0].rule_id == "security.pickle-load"


def test_import_alias_hashlib_md5_caught() -> None:
    findings = scan_security("import hashlib as h\nh.md5(b'x')\n")
    assert len(findings) == 1
    assert findings[0].rule_id == "security.weak-hash"


def test_import_alias_hashlib_new_caught() -> None:
    findings = scan_security("from hashlib import new\nnew('md5')\n")
    assert len(findings) == 1
    assert findings[0].rule_id == "security.weak-hash"


def test_import_alias_marshal_loads_caught() -> None:
    findings = scan_security("import marshal as m\nm.loads(b)\n")
    assert len(findings) == 1
    assert findings[0].rule_id == "security.marshal-loads"


def test_import_alias_ssl_unverified_context_caught() -> None:
    findings = scan_security(
        "from ssl import _create_unverified_context\n_create_unverified_context()\n"
    )
    assert len(findings) == 1
    assert findings[0].rule_id == "security.ssl-unverified-context"


def test_import_alias_subprocess_run_safe_negative() -> None:
    findings = scan_security("from subprocess import run\nrun(['ls'])\n")
    assert len(findings) == 0


def test_import_alias_unrelated_rule_negative() -> None:
    findings = scan_security("from os import getcwd\ngetcwd()\n")
    assert len(findings) == 0


def test_import_alias_unrelated_os_path_negative() -> None:
    findings = scan_security("import os\nos.path.join('a', 'b')\n")
    assert len(findings) == 0


def test_pragma_suppresses_eval() -> None:
    src = 'eval("x")  # rein:ignore security.eval-exec\n'
    assert "security.eval-exec" not in _ids(src)


# -- syntax error returns empty -----------------------------------------------

def test_syntax_error_returns_empty() -> None:
    assert scan_security("def foo(:\n") == []
