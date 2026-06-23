"""Tests for the path-string helpers."""

from __future__ import annotations

from rein.core.paths import normalize_path, path_basename, path_parts


def test_normalize_path_windows() -> None:
    assert normalize_path("a\\b\\c.py") == "a/b/c.py"


def test_normalize_path_posix_unchanged() -> None:
    assert normalize_path("a/b/c.py") == "a/b/c.py"


def test_path_basename_windows() -> None:
    assert path_basename("a\\b\\c.py") == "c.py"


def test_path_basename_posix() -> None:
    assert path_basename("a/b/c.py") == "c.py"


def test_path_basename_no_separator() -> None:
    assert path_basename("c.py") == "c.py"


def test_path_parts_windows() -> None:
    assert path_parts("a\\b\\c.py") == ["a", "b", "c.py"]


def test_path_parts_posix() -> None:
    assert path_parts("a/b/c.py") == ["a", "b", "c.py"]
