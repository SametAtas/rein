"""Tests for the unified-diff parser."""

from __future__ import annotations

from rein.core.diffs import parse_added_lines


def test_single_file_single_hunk() -> None:
    """Worked example from the spec: one added line at new-file line 2."""
    diff = (
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -1,2 +1,3 @@\n"
        " import os\n"
        '+TOKEN = "x"\n'
        " print(os)\n"
    )
    result = parse_added_lines(diff)
    assert len(result) == 1
    assert result[0].path == "app.py"
    assert result[0].line == 2
    assert result[0].text == 'TOKEN = "x"'


def test_multiple_hunks() -> None:
    diff = (
        "--- a/f.py\n"
        "+++ b/f.py\n"
        "@@ -1,2 +1,3 @@\n"
        " line1\n"
        "+added_at_2\n"
        " line2\n"
        "@@ -10,2 +11,3 @@\n"
        " line10\n"
        "+added_at_12\n"
        " line11\n"
    )
    result = parse_added_lines(diff)
    assert len(result) == 2
    assert result[0].line == 2
    assert result[0].text == "added_at_2"
    assert result[1].line == 12
    assert result[1].text == "added_at_12"


def test_multiple_files() -> None:
    diff = (
        "--- a/a.py\n"
        "+++ b/a.py\n"
        "@@ -1,1 +1,2 @@\n"
        " old\n"
        "+new_a\n"
        "--- a/b.py\n"
        "+++ b/b.py\n"
        "@@ -1,1 +1,2 @@\n"
        " old\n"
        "+new_b\n"
    )
    result = parse_added_lines(diff)
    assert len(result) == 2
    assert result[0].path == "a.py"
    assert result[0].text == "new_a"
    assert result[1].path == "b.py"
    assert result[1].text == "new_b"


def test_removed_lines_do_not_shift_new_lineno() -> None:
    diff = (
        "--- a/f.py\n"
        "+++ b/f.py\n"
        "@@ -1,3 +1,2 @@\n"
        " keep\n"
        "-removed\n"
        "+added\n"
    )
    result = parse_added_lines(diff)
    assert len(result) == 1
    # "keep" is context at new line 1, "-removed" does not increment,
    # so "+added" lands at new line 2.
    assert result[0].line == 2
    assert result[0].text == "added"


def test_context_lines_increment_lineno() -> None:
    diff = (
        "--- a/f.py\n"
        "+++ b/f.py\n"
        "@@ -1,3 +1,4 @@\n"
        " ctx1\n"
        " ctx2\n"
        " ctx3\n"
        "+added\n"
    )
    result = parse_added_lines(diff)
    assert len(result) == 1
    assert result[0].line == 4


def test_path_stripping() -> None:
    diff = (
        "--- a/src/foo.py\n"
        "+++ b/src/foo.py\n"
        "@@ -1,1 +1,2 @@\n"
        " x\n"
        "+y\n"
    )
    result = parse_added_lines(diff)
    assert result[0].path == "src/foo.py"


def test_dev_null_path() -> None:
    diff = (
        "--- /dev/null\n"
        "+++ /dev/null\n"
        "@@ -0,0 +1,1 @@\n"
        "+new\n"
    )
    result = parse_added_lines(diff)
    assert len(result) == 1
    assert result[0].path is None


def test_empty_diff() -> None:
    assert parse_added_lines("") == []


def test_plus_plus_plus_header_not_treated_as_added() -> None:
    diff = (
        "--- a/f.py\n"
        "+++ b/f.py\n"
        "@@ -1,1 +1,2 @@\n"
        " old\n"
        "+new\n"
    )
    result = parse_added_lines(diff)
    # Only the "+new" line, not the "+++ b/f.py" header
    assert len(result) == 1
    assert result[0].text == "new"


def test_no_newline_marker_ignored() -> None:
    diff = (
        "--- a/f.py\n"
        "+++ b/f.py\n"
        "@@ -1,1 +1,2 @@\n"
        " old\n"
        "+new\n"
        "\\ No newline at end of file\n"
    )
    result = parse_added_lines(diff)
    assert len(result) == 1
    assert result[0].line == 2
