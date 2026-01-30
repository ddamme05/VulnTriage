"""Tests for source code scanner."""

import tempfile
from pathlib import Path

import pytest

from vulntriage.scanner import (
    FileTooLargeError,
    discover_python_files,
    parse_file,
    scan_directory,
    scan_file,
)


def test_discover_single_file() -> None:
    """Discover a single Python file."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        py_file = tmp_path / "example.py"
        py_file.write_text("import os")

        files = discover_python_files(tmp_path)
        assert len(files) == 1
        assert files[0] == py_file


def test_discover_nested_files() -> None:
    """Discover Python files in nested directories."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        (tmp_path / "pkg").mkdir()
        (tmp_path / "pkg" / "sub").mkdir()

        (tmp_path / "root.py").write_text("")
        (tmp_path / "pkg" / "module.py").write_text("")
        (tmp_path / "pkg" / "sub" / "deep.py").write_text("")

        files = discover_python_files(tmp_path)
        assert len(files) == 3


def test_discover_excludes_pycache() -> None:
    """__pycache__ directories should be excluded."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        (tmp_path / "__pycache__").mkdir()
        (tmp_path / "__pycache__" / "cached.py").write_text("")
        (tmp_path / "real.py").write_text("")

        files = discover_python_files(tmp_path)
        assert len(files) == 1
        assert files[0].name == "real.py"


def test_discover_excludes_venv() -> None:
    """.venv and venv directories should be excluded."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        (tmp_path / ".venv").mkdir()
        (tmp_path / "venv").mkdir()
        (tmp_path / ".venv" / "lib.py").write_text("")
        (tmp_path / "venv" / "lib.py").write_text("")
        (tmp_path / "app.py").write_text("")

        files = discover_python_files(tmp_path)
        assert len(files) == 1
        assert files[0].name == "app.py"


def test_discover_excludes_docs_examples_vendor() -> None:
    """docs/, examples/, vendor/ directories should be excluded."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        (tmp_path / "docs").mkdir()
        (tmp_path / "examples").mkdir()
        (tmp_path / "vendor").mkdir()
        (tmp_path / "docs" / "conf.py").write_text("")
        (tmp_path / "examples" / "demo.py").write_text("")
        (tmp_path / "vendor" / "lib.py").write_text("")
        (tmp_path / "app.py").write_text("")

        files = discover_python_files(tmp_path)
        assert len(files) == 1
        assert files[0].name == "app.py"


def test_discover_does_not_exclude_nested_build_dir() -> None:
    """Nested build/ directories should not be excluded when only root is excluded."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        (tmp_path / "build").mkdir()
        (tmp_path / "build" / "skip.py").write_text("")
        (tmp_path / "pkg").mkdir()
        (tmp_path / "pkg" / "build").mkdir()
        (tmp_path / "pkg" / "build" / "keep.py").write_text("")
        (tmp_path / "app.py").write_text("")

        files = discover_python_files(tmp_path)
        names = {f.name for f in files}
        assert "app.py" in names
        assert "keep.py" in names
        assert "skip.py" not in names


def test_discover_respects_vulntriageignore() -> None:
    """.vulntriageignore patterns should exclude matching files."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        (tmp_path / ".vulntriageignore").write_text("skip.py\n", encoding="utf-8")
        (tmp_path / "skip.py").write_text("")
        (tmp_path / "keep.py").write_text("")

        files = discover_python_files(tmp_path)
        names = {f.name for f in files}
        assert "keep.py" in names
        assert "skip.py" not in names


def test_discover_excludes_tests_by_default() -> None:
    """tests/ directory and test_*.py files excluded by default."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        (tmp_path / "tests").mkdir()
        (tmp_path / "tests" / "test_foo.py").write_text("")
        (tmp_path / "test_bar.py").write_text("")  # test_* excluded
        (tmp_path / "bar_test.py").write_text("")  # *_test.py NOT excluded (narrower policy)
        (tmp_path / "app.py").write_text("")

        files = discover_python_files(tmp_path)
        assert len(files) == 2  # app.py and bar_test.py
        assert {f.name for f in files} == {"app.py", "bar_test.py"}


def test_discover_includes_tests_when_flag_set() -> None:
    """Tests included when include_tests=True."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        (tmp_path / "tests").mkdir()
        (tmp_path / "tests" / "test_foo.py").write_text("")
        (tmp_path / "app.py").write_text("")

        files = discover_python_files(tmp_path, include_tests=True)
        assert len(files) == 2


def test_discover_empty_directory() -> None:
    """Empty directory returns empty list."""
    with tempfile.TemporaryDirectory() as tmp:
        files = discover_python_files(Path(tmp))
        assert files == []


def test_discover_nonexistent_path() -> None:
    """Non-existent path returns empty list."""
    files = discover_python_files(Path("/nonexistent/path"))
    assert files == []


def test_discover_single_file_path() -> None:
    """Passing a single file path returns that file."""
    with tempfile.NamedTemporaryFile(suffix=".py", delete=False) as f:
        f.write(b"import os")
        path = Path(f.name)

    try:
        files = discover_python_files(path)
        assert len(files) == 1
        assert files[0] == path
    finally:
        path.unlink()


def test_discover_sorted_output() -> None:
    """Output should be sorted for determinism."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        (tmp_path / "z.py").write_text("")
        (tmp_path / "a.py").write_text("")
        (tmp_path / "m.py").write_text("")

        files = discover_python_files(tmp_path)
        assert files == sorted(files)


def test_parse_file_returns_tree() -> None:
    """parse_file should return a Tree-sitter tree."""
    with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w") as f:
        f.write("import os\nprint('hello')")
        path = Path(f.name)

    try:
        tree = parse_file(path)
        assert tree.root_node.type == "module"
    finally:
        path.unlink()


def test_scan_file_returns_parsed_file() -> None:
    """scan_file should return ParsedFile with symbol table."""
    with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w") as f:
        f.write("import requests\nfrom os import path")
        path = Path(f.name)

    try:
        parsed = scan_file(path)
        assert parsed.path == path
        assert parsed.tree is not None
        assert parsed.symbol_table is not None
        assert parsed.symbol_table.resolve_alias("requests") == "requests"
        assert parsed.symbol_table.resolve_alias("path") == "os.path"
    finally:
        path.unlink()


def test_scan_directory_returns_all_files() -> None:
    """scan_directory should parse all Python files."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        (tmp_path / "a.py").write_text("import os")
        (tmp_path / "b.py").write_text("import sys")

        result = scan_directory(tmp_path)
        assert len(result.parsed_files) == 2
        assert len(result.skipped_files) == 0
        assert all(r.symbol_table is not None for r in result.parsed_files)


def test_file_too_large_raises_error() -> None:
    """Files exceeding MAX_FILE_SIZE_BYTES should raise FileTooLargeError."""
    import vulntriage.scanner as scanner_module

    # Temporarily set a small limit for testing
    original_limit = scanner_module.MAX_FILE_SIZE_BYTES
    scanner_module.MAX_FILE_SIZE_BYTES = 100  # 100 bytes

    try:
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w") as f:
            f.write("x = 1\n" * 50)  # More than 100 bytes
            path = Path(f.name)

        try:
            with pytest.raises(FileTooLargeError):
                parse_file(path)
        finally:
            path.unlink()
    finally:
        scanner_module.MAX_FILE_SIZE_BYTES = original_limit


def test_scan_directory_skips_large_files() -> None:
    """scan_directory should skip large files without crashing."""
    import vulntriage.scanner as scanner_module

    original_limit = scanner_module.MAX_FILE_SIZE_BYTES
    scanner_module.MAX_FILE_SIZE_BYTES = 50  # 50 bytes

    try:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "small.py").write_text("x = 1")
            (tmp_path / "large.py").write_text("x = 1\n" * 20)  # Over 50 bytes

            import warnings
            with warnings.catch_warnings(record=True) as w:
                warnings.simplefilter("always")
                result = scan_directory(tmp_path)

            # Only small.py should be parsed
            assert len(result.parsed_files) == 1
            assert result.parsed_files[0].path.name == "small.py"

            # large.py should be in skipped files
            assert len(result.skipped_files) == 1
            assert result.skipped_files[0][0].name == "large.py"

            # Warning should have been raised for large.py
            assert len(w) == 1
            assert "large.py" in str(w[0].message)
    finally:
        scanner_module.MAX_FILE_SIZE_BYTES = original_limit
