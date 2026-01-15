"""Triage orchestration - coordinates the full vulnerability analysis pipeline."""

from __future__ import annotations

from pathlib import Path

from .analyzer import find_call_sites
from .matcher import FileAnalysis, match_vulnerabilities
from .models import ScanResult
from .package_map import build_package_map
from .scanner import scan_directory
from .trivy_adapter import load_trivy_report


def triage(
    trivy_json: Path,
    src: Path,
    include_tests: bool = False,
) -> list[ScanResult]:
    """Run the full vulnerability triage pipeline.

    Pipeline stages:
    1. Load vulnerabilities from Trivy JSON
    2. Scan source directory to build symbol tables
    3. Find call sites in each file
    4. Match vulnerabilities against call sites
    5. Return classified results

    Args:
        trivy_json: Path to Trivy JSON report.
        src: Path to source directory to analyze.
        include_tests: If True, include test files in analysis.

    Returns:
        List of ScanResult objects with classification and evidence.
    """
    # Stage 1: Load vulnerabilities
    vulnerabilities = load_trivy_report(trivy_json)

    if not vulnerabilities:
        return []

    # Stage 2: Build package map
    package_to_modules = build_package_map()

    # Get target modules for filtering call sites
    target_modules: set[str] = set()
    for vuln in vulnerabilities:
        # Look up modules for this package
        from .package_map import canonicalize_package_name
        canonical = canonicalize_package_name(vuln.pkg_name)
        modules = package_to_modules.get(canonical, [])
        target_modules.update(modules)

        # Also add package name itself as potential module
        # (many packages have matching import names)
        target_modules.add(vuln.pkg_name.lower().replace("-", "_"))

    # Stage 3: Scan source directory
    parsed_files = scan_directory(src, include_tests=include_tests)

    # Stage 4: Find call sites and build analysis map
    analysis_map: dict[Path, FileAnalysis] = {}

    for parsed in parsed_files:
        call_sites = find_call_sites(
            parsed.path,
            parsed.tree.root_node,
            parsed.symbol_table,
            target_modules if target_modules else None,
        )

        analysis_map[parsed.path] = FileAnalysis(
            file_path=parsed.path,
            symbol_table=parsed.symbol_table,
            call_sites=call_sites,
        )

    # Stage 5: Match vulnerabilities
    results = match_vulnerabilities(
        vulnerabilities,
        analysis_map,
        package_to_modules,
    )

    # Sort results by severity priority for stable output
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    results.sort(key=lambda r: (
        severity_order.get(r.vulnerability.severity, 5),
        r.vulnerability.vuln_id,
    ))

    return results
