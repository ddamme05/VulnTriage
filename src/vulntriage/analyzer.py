"""Analyzer - Tree-sitter visitor for finding call sites."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from .symbol_table import SymbolTable, _is_type_checking_condition

if TYPE_CHECKING:
    import tree_sitter


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
    target_modules: set[str] | None = None,
) -> list[CallSite]:
    """Find all call sites for functions from target modules.

    Args:
        path: Path to the source file.
        root_node: Tree-sitter root node for traversal.
        symbol_table: Symbol table for import resolution.
        target_modules: Set of module names to look for. If None, find all calls.

    Returns:
        List of CallSite objects for matching calls.
    """
    call_sites: list[CallSite] = []
    source_bytes = root_node.text if root_node.text else b""
    source_lines = source_bytes.decode("utf-8", errors="replace").split("\n")

    # Find TYPE_CHECKING blocks to skip (consistent with import handling)
    type_checking_ranges: list[tuple[int, int]] = []
    _find_type_checking_blocks(root_node, type_checking_ranges)

    _walk_for_calls(
        root_node, path, symbol_table, target_modules,
        call_sites, source_lines, type_checking_ranges
    )

    return call_sites


def _find_type_checking_blocks(
    node: tree_sitter.Node, ranges: list[tuple[int, int]]
) -> None:
    """Find TYPE_CHECKING blocks to skip call detection inside them."""
    if node.type == "if_statement":
        condition = node.child_by_field_name("condition")
        if condition and _is_type_checking_condition(condition):
            # Only skip the consequence (if body), not else
            consequence = node.child_by_field_name("consequence")
            if consequence:
                ranges.append((consequence.start_point[0], consequence.end_point[0]))

    for child in node.children:
        _find_type_checking_blocks(child, ranges)


def _walk_for_calls(
    node: tree_sitter.Node,
    path: Path,
    symbol_table: SymbolTable,
    target_modules: set[str] | None,
    call_sites: list[CallSite],
    source_lines: list[str],
    type_checking_ranges: list[tuple[int, int]],
) -> None:
    """Walk the AST looking for call expressions."""
    # Skip calls inside TYPE_CHECKING blocks
    line = node.start_point[0]
    for start, end in type_checking_ranges:
        if start <= line <= end:
            return  # Skip this entire subtree

    if node.type == "call":
        call_site = _process_call(node, path, symbol_table, target_modules, source_lines)
        if call_site:
            call_sites.append(call_site)

    for child in node.children:
        _walk_for_calls(
            child, path, symbol_table, target_modules,
            call_sites, source_lines, type_checking_ranges
        )


def _process_call(
    node: tree_sitter.Node,
    path: Path,
    symbol_table: SymbolTable,
    target_modules: set[str] | None,
    source_lines: list[str],
) -> CallSite | None:
    """Process a call node and create a CallSite if it matches."""
    # Get the function being called (first child of call node)
    func_node = node.child_by_field_name("function")
    if not func_node:
        return None

    # Resolve the callee name
    callee = _resolve_callee(func_node, symbol_table)
    if not callee:
        return None

    # If target_modules is specified, filter by module prefix
    if target_modules is not None and not _callee_matches_any_module(callee, target_modules):
        return None

    # Extract context (3 lines before and after)
    line = node.start_point[0] + 1  # 1-indexed
    context = _extract_context(source_lines, line, context_lines=3)

    return CallSite(
        file_path=path,
        line=line,
        column=node.start_point[1],
        callee=callee,
        context=context,
    )


def _resolve_callee(node: tree_sitter.Node, symbol_table: SymbolTable) -> str | None:
    """Resolve a function node to its fully qualified name."""
    if node.type == "identifier":
        # Simple call: foo()
        name = node.text.decode("utf-8") if node.text else ""
        # Try to resolve through symbol table
        resolved = symbol_table.resolve_alias(name)
        return resolved if resolved else name

    elif node.type == "attribute":
        # Attribute access: foo.bar() or foo.bar.baz()
        parts = _collect_attribute_parts(node)
        if not parts:
            return None

        # Try to resolve the root through symbol table
        root = parts[0]
        resolved_root = symbol_table.resolve_alias(root)

        if resolved_root:
            # Replace root with resolved name
            return ".".join([resolved_root, *parts[1:]])
        else:
            # Return as-is
            return ".".join(parts)

    return None


def _collect_attribute_parts(node: tree_sitter.Node) -> list[str]:
    """Collect all parts of an attribute access chain.

    Returns empty list if the chain has a non-identifier/non-attribute root
    (e.g., method chains like requests.get(...).json() where .json() has a call as root).
    """
    parts: list[str] = []

    if node.type == "attribute":
        # Get the object (left side)
        obj = node.child_by_field_name("object")
        if obj:
            if obj.type == "call":
                # Call as object (e.g., foo().bar) - don't resolve
                return []
            sub_parts = _collect_attribute_parts(obj)
            if not sub_parts and obj.type not in ("identifier",):
                # Non-resolvable root
                return []
            parts.extend(sub_parts)

        # Get the attribute (right side)
        attr = node.child_by_field_name("attribute")
        if attr and attr.text:
            parts.append(attr.text.decode("utf-8"))

    elif node.type == "identifier":
        if node.text:
            parts.append(node.text.decode("utf-8"))

    return parts


def _callee_matches_any_module(callee: str, modules: set[str]) -> bool:
    """Check if callee matches any of the target modules."""
    return any(callee == module or callee.startswith(module + ".") for module in modules)


def _extract_context(source_lines: list[str], line: int, context_lines: int = 3) -> str:
    """Extract context around a line."""
    start = max(0, line - context_lines - 1)  # 0-indexed
    end = min(len(source_lines), line + context_lines)
    return "\n".join(source_lines[start:end])


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
    dangerous_patterns = [
        "sys.argv",
        "os.environ",
        "environ.get",
        "request.",
        "flask.request",
        "input(",
        "stdin",
    ]

    context_lower = call_site.context.lower()
    return any(pattern.lower() in context_lower for pattern in dangerous_patterns)
