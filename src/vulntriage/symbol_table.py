"""Symbol table - tracks imports and their aliases per file."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import tree_sitter


@dataclass
class ImportedSymbol:
    """Represents an imported symbol with its origin and alias."""

    module: str  # e.g., "requests"
    name: str | None  # e.g., "get" for "from requests import get", None for module import
    alias: str  # The name used in code, e.g., "r" for "import requests as r"
    line: int  # Line number of the import


@dataclass
class SymbolTable:
    """Per-file symbol table tracking all imports."""

    file_path: Path
    imports: list[ImportedSymbol] = field(default_factory=list)

    def get_module_for_alias(self, alias: str) -> str | None:
        """Look up the original module name for an alias.

        Args:
            alias: The alias used in code.

        Returns:
            The original module name, or None if not found.
        """
        for imp in self.imports:
            if imp.alias == alias:
                return imp.module
        return None

    def resolve_alias(self, alias: str) -> str | None:
        """Resolve a local alias to its fully qualified name.

        Examples:
            - `import requests as r` → `requests`
            - `from requests import get as g` → `requests.get`
            - `from requests.sessions import Session as S` → `requests.sessions.Session`

        Args:
            alias: The alias used in code.

        Returns:
            The fully qualified name, or None if not found.
        """
        for imp in self.imports:
            if imp.alias == alias:
                # Reconstruct the full path
                if imp.name:
                    return f"{imp.module}.{imp.name}"
                return imp.module
        return None

    def is_from_module(self, name: str, target_module: str) -> bool:
        """Check if a name in code originates from a specific module.

        Uses prefix boundary matching (same as matcher._matches_module).

        Args:
            name: The name used in code.
            target_module: The module to check against (can be dotted, e.g., "google.auth").

        Returns:
            True if the name is imported from the target module.
        """
        for imp in self.imports:
            # Use prefix boundary matching with combined condition
            if imp.alias == name and (
                imp.module == target_module
                or imp.module.startswith(target_module + ".")
            ):
                return True
        return False


def build_symbol_table(path: Path, root_node: tree_sitter.Node) -> SymbolTable:
    """Build a symbol table from a parsed Python file.

    Args:
        path: Path to the source file.
        root_node: Tree-sitter root node (use tree.root_node).

    Returns:
        SymbolTable with all imports resolved.
    """
    table = SymbolTable(file_path=path)

    # Track TYPE_CHECKING blocks to skip imports inside them
    type_checking_ranges: list[tuple[int, int]] = []
    _find_type_checking_blocks(root_node, type_checking_ranges)

    # Walk the tree looking for import statements
    _walk_imports(root_node, table, type_checking_ranges)

    return table


def _find_type_checking_blocks(
    node: tree_sitter.Node, ranges: list[tuple[int, int]]
) -> None:
    """Find all if TYPE_CHECKING: blocks and record their line ranges.

    Only records the consequence (if body) range, NOT the else branch.
    This ensures imports in `else:` blocks are correctly included.
    """
    if node.type == "if_statement":
        # Check if condition is TYPE_CHECKING
        condition = node.child_by_field_name("condition")
        if condition and _is_type_checking_condition(condition):
            # Record only the consequence block, not the entire if statement
            consequence = node.child_by_field_name("consequence")
            if consequence:
                ranges.append((consequence.start_point[0], consequence.end_point[0]))

    for child in node.children:
        _find_type_checking_blocks(child, ranges)


def _is_type_checking_condition(node: tree_sitter.Node) -> bool:
    """Check if a condition node is TYPE_CHECKING."""
    if node.type == "identifier":
        return node.text is not None and node.text.decode("utf-8") == "TYPE_CHECKING"
    return False


def _is_in_type_checking(line: int, ranges: list[tuple[int, int]]) -> bool:
    """Check if a line is inside a TYPE_CHECKING block."""
    for start, end in ranges:
        if start <= line <= end:
            return True
    return False


def _walk_imports(
    node: tree_sitter.Node,
    table: SymbolTable,
    type_checking_ranges: list[tuple[int, int]],
) -> None:
    """Walk the AST and extract import statements."""
    if node.type == "import_statement":
        if not _is_in_type_checking(node.start_point[0], type_checking_ranges):
            _process_import_statement(node, table)
    elif node.type == "import_from_statement":
        if not _is_in_type_checking(node.start_point[0], type_checking_ranges):
            _process_import_from_statement(node, table)

    for child in node.children:
        _walk_imports(child, table, type_checking_ranges)


def _process_import_statement(node: tree_sitter.Node, table: SymbolTable) -> None:
    """Process `import x` or `import x as y` statements."""
    line = node.start_point[0] + 1  # 1-indexed

    for child in node.children:
        if child.type == "dotted_name":
            # import requests
            module = child.text.decode("utf-8") if child.text else ""
            _add_import(table, module, None, module, line)

        elif child.type == "aliased_import":
            # import requests as r
            name_node = child.child_by_field_name("name")
            alias_node = child.child_by_field_name("alias")
            if name_node and alias_node and name_node.text and alias_node.text:
                module = name_node.text.decode("utf-8")
                alias = alias_node.text.decode("utf-8")
                _add_import(table, module, None, alias, line)


def _process_import_from_statement(node: tree_sitter.Node, table: SymbolTable) -> None:
    """Process `from x import y` statements."""
    line = node.start_point[0] + 1  # 1-indexed

    # Get the module name
    module_node = node.child_by_field_name("module_name")
    if not module_node or not module_node.text:
        return

    module = module_node.text.decode("utf-8")

    # Skip relative imports (start with .)
    if module.startswith(".") or _has_relative_import_prefix(node):
        return

    # Process imported names
    for child in node.children:
        if child.type == "wildcard_import":
            # from x import * - no bindings created
            return

        if child.type == "dotted_name" and child != module_node:
            # Single name: from x import y
            name = child.text.decode("utf-8") if child.text else ""
            _add_import(table, module, name, name, line)

        elif child.type == "aliased_import":
            # from x import y as z
            name_node = child.child_by_field_name("name")
            alias_node = child.child_by_field_name("alias")
            if name_node and name_node.text:
                name = name_node.text.decode("utf-8")
                alias = alias_node.text.decode("utf-8") if alias_node and alias_node.text else name
                _add_import(table, module, name, alias, line)

        elif child.type == "import_list":
            # from x import (a, b, c)
            _process_import_list(child, module, table, line)


def _process_import_list(
    node: tree_sitter.Node, module: str, table: SymbolTable, line: int
) -> None:
    """Process a parenthesized import list."""
    for child in node.children:
        if child.type == "dotted_name":
            name = child.text.decode("utf-8") if child.text else ""
            _add_import(table, module, name, name, line)

        elif child.type == "aliased_import":
            name_node = child.child_by_field_name("name")
            alias_node = child.child_by_field_name("alias")
            if name_node and name_node.text:
                name = name_node.text.decode("utf-8")
                alias = alias_node.text.decode("utf-8") if alias_node and alias_node.text else name
                _add_import(table, module, name, alias, line)


def _has_relative_import_prefix(node: tree_sitter.Node) -> bool:
    """Check if import_from_statement has relative import dots."""
    for child in node.children:
        if child.type == "relative_import":
            return True
        # Also check for leading dots
        if child.type == "import_prefix":
            return True
    # Check the raw text for leading dots before module name
    if node.text:
        text = node.text.decode("utf-8")
        # "from . import x" or "from .. import x"
        if "from ." in text and "from .." not in text[:10]:
            return True
        if "from .." in text:
            return True
    return False


def _add_import(
    table: SymbolTable, module: str, name: str | None, alias: str, line: int
) -> None:
    """Add an import to the table, handling overrides."""
    # Remove any existing import with the same alias (later wins)
    table.imports = [imp for imp in table.imports if imp.alias != alias]

    table.imports.append(
        ImportedSymbol(module=module, name=name, alias=alias, line=line)
    )
