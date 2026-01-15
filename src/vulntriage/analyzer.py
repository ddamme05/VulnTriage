"""Analyzer - Tree-sitter visitor for finding call sites."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import tree_sitter

    from .symbol_table import SymbolTable


@dataclass
class CallSite:
    """Represents a function call site in the source code."""

    file_path: Path
    line: int
    column: int
    callee: str  # The resolved function name, e.g., "requests.get"
    context: str  # Surrounding code context for AI analysis


def find_call_sites(
    path: Path,
    root_node: tree_sitter.Node,
    symbol_table: SymbolTable,
    target_modules: set[str],
) -> list[CallSite]:
    """Find all call sites for functions from target modules.

    Args:
        path: Path to the source file.
        root_node: Tree-sitter root node for traversal.
        symbol_table: Symbol table for import resolution.
        target_modules: Set of module names to look for.

    Returns:
        List of CallSite objects for matching calls.
    """
    # Silence unused argument warnings until implemented
    _ = (path, root_node, symbol_table, target_modules)
    # TODO: Implement call site detection
    # - Walk tree looking for call expressions
    # - Resolve the callee through the symbol table
    # - Check if callee belongs to a target module
    # - Extract surrounding context (N lines before/after)
    raise NotImplementedError("Analyzer not yet implemented")


def check_dangerous_inputs(call_site: CallSite) -> bool:
    """Heuristic check if a call site receives dangerous inputs.

    Looks for patterns like:
    - sys.argv
    - os.environ
    - flask.request
    - input()

    Args:
        call_site: The call site to analyze.

    Returns:
        True if dangerous input patterns are detected nearby.
    """
    # Silence unused argument warning until implemented
    _ = call_site
    # TODO: Implement dangerous input detection
    # - Parse the context window
    # - Look for known dangerous patterns
    raise NotImplementedError("Dangerous input checker not yet implemented")
