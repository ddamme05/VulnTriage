"""CVE function map loader - maps CVEs to known vulnerable functions."""

from __future__ import annotations

import json
from pathlib import Path

from .enrichment import normalize_cve_id


def load_cve_function_map(path: Path | None) -> dict[str, set[str]]:
    """Load CVE→functions map from JSON file.

    Format:
    {
        "CVE-2023-12345": ["package.module.func", "package.Class.method"],
        "CVE-2022-9999": ["pkg.subpkg.vulnerable_fn"]
    }

    Args:
        path: Path to JSON map file. If None, returns empty map.

    Returns:
        Dict mapping normalized CVE ID → set of vulnerable function names.
    """
    if path is None:
        return {}

    if not path.exists():
        import warnings
        warnings.warn(
            f"CVE function map not found at {path}. Function matching disabled.",
            stacklevel=2,
        )
        return {}

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        import warnings
        warnings.warn(
            f"Invalid JSON in CVE function map {path}: {e}",
            stacklevel=2,
        )
        return {}

    result: dict[str, set[str]] = {}

    for cve_raw, functions in data.items():
        cve_id = normalize_cve_id(cve_raw)
        if cve_id is None:
            import warnings
            warnings.warn(
                f"Invalid CVE ID in function map: {cve_raw}",
                stacklevel=2,
            )
            continue

        if not isinstance(functions, list):
            import warnings
            warnings.warn(
                f"Invalid function list for {cve_id}: expected list, got {type(functions).__name__}",
                stacklevel=2,
            )
            continue

        # Skip empty lists - treat as "no map for this CVE"
        if not functions:
            continue

        # Store function names as-is (case-sensitive matching)
        result[cve_id] = {str(fn).strip() for fn in functions if fn}

    return result


def get_vulnerable_functions(
    cve_id: str,
    function_map: dict[str, set[str]],
) -> set[str] | None:
    """Get vulnerable functions for a CVE.

    Args:
        cve_id: CVE identifier (will be normalized).
        function_map: Map from load_cve_function_map().

    Returns:
        Set of vulnerable function names, or None if CVE not in map.
    """
    normalized = normalize_cve_id(cve_id)
    if normalized is None:
        return None
    return function_map.get(normalized)


def matches_vulnerable_function(
    call_symbol: str,
    vulnerable_functions: set[str],
) -> bool:
    """Check if a call symbol matches any vulnerable function.

    Matching rules:
    1. Exact match (case-sensitive)
    2. Suffix match with dot boundary (call ends with "." + vulnerable function)

    Note: For best results, use fully-qualified function names in the map
    (e.g., "yaml.load" not just "load") to avoid false positives.

    Args:
        call_symbol: The symbol being called (e.g., "yaml.load", "Foo.bar.baz").
        vulnerable_functions: Set of vulnerable function patterns.

    Returns:
        True if call matches any vulnerable function.
    """
    for vuln_fn in vulnerable_functions:
        # Exact match
        if call_symbol == vuln_fn:
            return True
        # Suffix match with dot boundary only
        if call_symbol.endswith("." + vuln_fn):
            return True
    return False
