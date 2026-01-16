"""Matcher - correlates vulnerabilities with call sites."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from .models import EvidenceRef, ScanResult, TriageStatus, Vulnerability
from .package_map import canonicalize_package_name

if TYPE_CHECKING:
    from .analyzer import CallSite
    from .symbol_table import SymbolTable


@dataclass
class FileAnalysis:
    """Analysis results for a single source file."""

    file_path: Path
    symbol_table: SymbolTable
    call_sites: list[CallSite] = field(default_factory=list)

    def get_imported_root_modules(self) -> set[str]:
        """Get set of root module names imported in this file."""
        modules = set()
        for imp in self.symbol_table.imports:
            root = imp.module.split(".")[0]
            modules.add(root)
        return modules


def _matches_module(callee: str, module: str) -> bool:
    """Check if a callee matches a module by prefix boundary.

    Examples:
        - callee="requests.get", module="requests" → True
        - callee="requests", module="requests" → True
        - callee="requests_oauthlib.OAuth", module="requests" → False (not a boundary)
        - callee="google.auth.credentials", module="google.auth" → True
    """
    return callee == module or callee.startswith(module + ".")


def match_vulnerabilities(
    vulnerabilities: list[Vulnerability],
    analysis_map: dict[Path, FileAnalysis],
    package_to_modules: dict[str, list[str]],
) -> list[ScanResult]:
    """Match vulnerabilities against discovered call sites.

    Args:
        vulnerabilities: List of vulnerabilities from Trivy.
        analysis_map: Mapping of file paths to their analysis results.
            All paths should be consistently relative (or consistently absolute)
            to ensure stable evidence paths across machines/CI.
        package_to_modules: Mapping of canonicalized package names to module names.

    Returns:
        List of ScanResult objects (the canonical output type).
    """
    results: list[ScanResult] = []

    for vuln in vulnerabilities:
        # Get the module names for this package (use shared canonicalization)
        canonical_name = canonicalize_package_name(vuln.pkg_name)
        modules = package_to_modules.get(canonical_name, [])

        if not modules:
            # Unknown package mapping - needs review
            results.append(ScanResult(
                vulnerability=vuln,
                status="needs_review",
                reason=f"Unknown package mapping for '{vuln.pkg_name}'",
            ))
            continue

        # Use sets to prevent duplicates
        imported_in_files: set[Path] = set()
        matching_calls: set[tuple[Path, int, str]] = set()  # (path, line, callee)

        for file_path, analysis in analysis_map.items():
            # NOTE: get_imported_root_modules() only tracks roots, so "imported"
            # means "root is imported somewhere." Fine for gating, not a proof
            # of specific submodule import.
            imported_roots = analysis.get_imported_root_modules()

            for module in modules:
                root = module.split(".")[0]
                if root in imported_roots:
                    imported_in_files.add(file_path)

                    # Find calls to this module using prefix matching
                    for call in analysis.call_sites:
                        if _matches_module(call.callee, module):
                            # Use loop's file_path for consistency, not call.file_path
                            matching_calls.add((file_path, call.line, call.callee))

        # Determine status
        status: TriageStatus
        reason: str
        evidence: list[EvidenceRef] = []

        if not imported_in_files:
            # Before dismissing, check for uncertainty from wildcard/dynamic imports
            # HEURISTIC: Uncertainty check
            # WHY: Wildcard or dynamic imports may have imported the module
            # LIMIT: Conservative - may flag packages that weren't actually used
            # ACCEPTABLE: Fail-closed - uncertainty prevents false dismissal
            uncertainty_reasons: list[str] = []
            for analysis in analysis_map.values():
                for module in modules:
                    reason_str = analysis.symbol_table.has_uncertainty_for_module(module)
                    if reason_str:
                        uncertainty_reasons.append(reason_str)

            if uncertainty_reasons:
                status = "needs_review"
                reason = (
                    f"Package '{vuln.pkg_name}' has import uncertainty: "
                    f"{uncertainty_reasons[0]}"
                )
            else:
                status = "dismissed"
                reason = f"Package '{vuln.pkg_name}' is not imported in any application code"
        elif not matching_calls:
            status = "needs_review"
            reason = f"Package '{vuln.pkg_name}' is imported but no direct calls found"
        else:
            # TODO: After AI analysis, downgrade to "needs_review" if model says
            # "not exploitable / unclear." Only keep "actionable" for confirmed exploitable.
            status = "actionable"
            reason = f"Found {len(matching_calls)} call(s) to '{vuln.pkg_name}'"
            for path, line, callee in matching_calls:
                evidence.append(EvidenceRef(
                    file_path=str(path),
                    line_start=line,
                    line_end=line,
                    symbol_name=callee,
                ))

        results.append(ScanResult(
            vulnerability=vuln,
            status=status,
            reason=reason,
            evidence=evidence,
        ))

    return results
