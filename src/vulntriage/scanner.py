"""Source code scanner - discovers and parses Python files."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import pathspec
import tree_sitter
import tree_sitter_python

from .symbol_table import SymbolTable, build_symbol_table

# Initialize parser once (per code-style-guide: parser reuse)
_LANGUAGE = tree_sitter.Language(tree_sitter_python.language())
_PARSER = tree_sitter.Parser()
_PARSER.language = _LANGUAGE

# Default exclusion patterns (gitignore-style, relative to src)
DEFAULT_EXCLUDE_PATTERNS = (
    "__pycache__/",
    ".git/",
    "/.venv/",
    "/venv/",
    "/.tox/",
    "/.mypy_cache/",
    "/.pytest_cache/",
    "/node_modules/",
    ".eggs/",
    "*.egg-info/",
    "/build/",
    "/dist/",
    # Non-production paths (per design doc defaults)
    "/docs/",
    "/examples/",
    "/vendor/",
    "/notebooks/",
)

TEST_EXCLUDE_PATTERNS = (
    "tests/",
    "test_*.py",
)

# Maximum file size to parse (1MB default - prevents DoS on huge generated files)
MAX_FILE_SIZE_BYTES = 1_000_000


class FileTooLargeError(Exception):
    """Raised when a file exceeds MAX_FILE_SIZE_BYTES."""


@dataclass
class ParsedFile:
    """A parsed Python file with its symbol table."""

    path: Path
    tree: tree_sitter.Tree
    symbol_table: SymbolTable


@dataclass
class ScanDirectoryResult:
    """Result of scanning a directory, including skipped files."""

    parsed_files: list[ParsedFile]
    skipped_files: list[tuple[Path, str]]  # (path, reason)


def discover_python_files(
    src: Path,
    exclude_patterns: tuple[str, ...] | None = None,
    include_tests: bool = False,
) -> list[Path]:
    """Recursively discover all Python files in a directory.

    Args:
        src: Root directory to scan.
        exclude_patterns: Gitignore-style patterns to exclude (relative to src).
        include_tests: If False, exclude tests/ and test_*.py files.

    Returns:
        List of paths to Python files, sorted for determinism.
    """
    if not src.exists():
        return []

    if src.is_file():
        if src.suffix == ".py":
            return [src]
        return []

    patterns = exclude_patterns if exclude_patterns is not None else DEFAULT_EXCLUDE_PATTERNS
    if not include_tests:
        patterns = patterns + TEST_EXCLUDE_PATTERNS
    patterns = patterns + _load_vulntriageignore(src)
    spec = pathspec.PathSpec.from_lines("gitwildmatch", patterns)

    files: list[Path] = []

    for root, dirs, file_names in os.walk(src):
        root_path = Path(root)

        # Prune excluded directories before descending.
        pruned: list[str] = []
        for dir_name in dirs:
            if _matches_spec(root_path / dir_name, src, spec, is_dir=True):
                pruned.append(dir_name)
        for dir_name in pruned:
            dirs.remove(dir_name)
        dirs.sort()

        for file_name in sorted(file_names):
            if not file_name.endswith(".py"):
                continue
            path = root_path / file_name
            if _matches_spec(path, src, spec, is_dir=False):
                continue
            files.append(path)

    # Sort for determinism (per code-style-guide)
    return sorted(files)


def _matches_spec(path: Path, root: Path, spec: pathspec.PathSpec, is_dir: bool) -> bool:
    """Check if a path should be excluded from scanning."""
    rel = path.relative_to(root).as_posix()
    if is_dir and not rel.endswith("/"):
        rel = f"{rel}/"
    return spec.match_file(rel)


def _load_vulntriageignore(root: Path) -> tuple[str, ...]:
    """Load .vulntriageignore patterns from the repo root."""
    ignore_path = root / ".vulntriageignore"
    if not ignore_path.is_file():
        return ()
    try:
        lines = ignore_path.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError as exc:
        import warnings

        warnings.warn(
            f"Unable to read {ignore_path}: {exc}. Ignoring custom patterns.",
            stacklevel=2,
        )
        return ()
    patterns: list[str] = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        patterns.append(stripped)
    return tuple(patterns)


def parse_file(path: Path) -> tree_sitter.Tree:
    """Parse a Python file using Tree-sitter.

    Args:
        path: Path to the Python file.

    Returns:
        Tree-sitter parse tree.

    Raises:
        FileNotFoundError: If the file doesn't exist.
        FileTooLargeError: If the file exceeds MAX_FILE_SIZE_BYTES.
    """
    # Check file size before reading (prevent DoS from huge generated files)
    file_size = path.stat().st_size
    if file_size > MAX_FILE_SIZE_BYTES:
        raise FileTooLargeError(
            f"File {path} is {file_size:,} bytes (max: {MAX_FILE_SIZE_BYTES:,})"
        )

    content = path.read_bytes()
    return _PARSER.parse(content)


def scan_file(path: Path) -> ParsedFile:
    """Parse a Python file and build its symbol table.

    Args:
        path: Path to the Python file.

    Returns:
        ParsedFile with tree and symbol table.
    """
    tree = parse_file(path)
    symbol_table = build_symbol_table(path, tree.root_node)
    return ParsedFile(path=path, tree=tree, symbol_table=symbol_table)


def scan_directory(
    src: Path,
    exclude_patterns: tuple[str, ...] | None = None,
    include_tests: bool = False,
) -> ScanDirectoryResult:
    """Discover and parse all Python files in a directory.

    Args:
        src: Root directory to scan.
        exclude_patterns: Gitignore-style patterns to exclude.
        include_tests: If False, exclude test files.

    Returns:
        ScanDirectoryResult with parsed files and skipped files.
    """
    files = discover_python_files(src, exclude_patterns, include_tests)
    parsed_files: list[ParsedFile] = []
    skipped_files: list[tuple[Path, str]] = []

    for file_path in files:
        try:
            parsed = scan_file(file_path)
            parsed_files.append(parsed)
        except (FileNotFoundError, PermissionError, UnicodeDecodeError, FileTooLargeError) as e:
            # HEURISTIC: Skip unreadable/unparseable/oversized files
            # WHY: File may be deleted, permission-denied, non-UTF-8, or too large
            # LIMIT: We lose visibility into these files
            # ACCEPTABLE: Fail-closed in --strict mode
            import warnings
            warnings.warn(f"Skipping file {file_path}: {e}", stacklevel=2)
            skipped_files.append((file_path, str(e)))

    return ScanDirectoryResult(parsed_files=parsed_files, skipped_files=skipped_files)
