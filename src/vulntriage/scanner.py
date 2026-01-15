"""Source code scanner - discovers and parses Python files."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import tree_sitter
import tree_sitter_python

from .symbol_table import SymbolTable, build_symbol_table

# Initialize parser once (per code-style-guide: parser reuse)
_LANGUAGE = tree_sitter.Language(tree_sitter_python.language())
_PARSER = tree_sitter.Parser()
_PARSER.language = _LANGUAGE

# Default exclusion patterns (per DESIGN_RATIONALE.md)
DEFAULT_EXCLUDE_PATTERNS = frozenset({
    "__pycache__",
    ".git",
    ".venv",
    "venv",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    "node_modules",
    ".eggs",
    "*.egg-info",
    "build",
    "dist",
    # Non-production paths (per design doc defaults)
    "docs",
    "examples",
    "vendor",
    "notebooks",
})


@dataclass
class ParsedFile:
    """A parsed Python file with its symbol table."""

    path: Path
    tree: tree_sitter.Tree
    symbol_table: SymbolTable


def discover_python_files(
    src: Path,
    exclude_patterns: frozenset[str] | None = None,
    include_tests: bool = False,
) -> list[Path]:
    """Recursively discover all Python files in a directory.

    Args:
        src: Root directory to scan.
        exclude_patterns: Patterns to exclude (directory/file names).
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

    files: list[Path] = []

    # TODO: rglob traverses all directories including excluded ones.
    # For large repos with big .venv/node_modules, consider os.walk() with pruning.
    for path in src.rglob("*.py"):
        # Skip excluded directories
        if _should_exclude(path, patterns, include_tests):
            continue

        files.append(path)

    # Sort for determinism (per code-style-guide)
    return sorted(files)


def _should_exclude(path: Path, patterns: frozenset[str], include_tests: bool) -> bool:
    """Check if a path should be excluded from scanning."""
    parts = path.parts

    # Check each part against exclusion patterns
    for part in parts:
        if part in patterns:
            return True
        # Handle wildcard patterns like *.egg-info
        for pattern in patterns:
            if pattern.startswith("*") and part.endswith(pattern[1:]):
                return True

    # Test exclusion (tests/ directory and test_*.py files)
    if not include_tests:
        # Exclude tests/ directory only (not arbitrary 'test' in path)
        if "tests" in parts:
            return True
        # Exclude test_*.py files only (not *_test.py)
        if path.name.startswith("test_"):
            return True

    return False


def parse_file(path: Path) -> tree_sitter.Tree:
    """Parse a Python file using Tree-sitter.

    Args:
        path: Path to the Python file.

    Returns:
        Tree-sitter parse tree.

    Raises:
        FileNotFoundError: If the file doesn't exist.
    """
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
    exclude_patterns: frozenset[str] | None = None,
    include_tests: bool = False,
) -> list[ParsedFile]:
    """Discover and parse all Python files in a directory.

    Args:
        src: Root directory to scan.
        exclude_patterns: Patterns to exclude.
        include_tests: If False, exclude test files.

    Returns:
        List of ParsedFile objects, sorted by path.
    """
    files = discover_python_files(src, exclude_patterns, include_tests)
    results: list[ParsedFile] = []

    for file_path in files:
        try:
            parsed = scan_file(file_path)
            results.append(parsed)
        except (FileNotFoundError, UnicodeDecodeError) as e:
            # HEURISTIC: Skip unreadable files
            # WHY: File may have been deleted or have encoding issues
            # LIMIT: We lose visibility into these files
            # ACCEPTABLE: Fail-closed - missing analysis → needs_review for affected vulns
            import warnings
            warnings.warn(f"Skipping unreadable file {file_path}: {e}")

    return results
