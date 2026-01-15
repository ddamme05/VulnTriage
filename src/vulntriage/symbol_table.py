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
    # Silence unused argument warning until implemented
    _ = root_node
    # TODO: Implement symbol table construction
    # - Walk root_node looking for import_statement and import_from_statement
    # - Handle aliases (as clause)
    # - Handle wildcard imports (from x import *)
    raise NotImplementedError("Symbol table builder not yet implemented")
