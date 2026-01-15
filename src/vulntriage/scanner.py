"""Source code scanner - discovers and parses Python files."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import tree_sitter


def discover_python_files(src: Path) -> list[Path]:
    """Recursively discover all Python files in a directory.

    Args:
        src: Root directory to scan.

    Returns:
        List of paths to Python files.
    """
    # Silence unused argument warning until implemented
    _ = src
    # TODO: Implement file discovery
    # - Use pathlib.rglob("*.py")
    # - Respect .gitignore patterns
    # - Skip virtual environments and __pycache__
    raise NotImplementedError("Scanner not yet implemented")


def parse_file(path: Path) -> tree_sitter.Tree:
    """Parse a Python file using Tree-sitter.

    Args:
        path: Path to the Python file.

    Returns:
        Tree-sitter parse tree.
    """
    # Silence unused argument warning until implemented
    _ = path
    # TODO: Implement Tree-sitter parsing
    # - Initialize parser with Python grammar
    # - Read file content
    # - Parse and return tree
    raise NotImplementedError("Scanner not yet implemented")
