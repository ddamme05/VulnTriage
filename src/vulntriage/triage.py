"""Triage orchestration - coordinates the full vulnerability analysis pipeline."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from .analyzer import find_call_sites
from .cve_function_map import load_cve_function_map
from .enrichment import enrich_vulnerabilities, refresh_epss_data, refresh_kev_data
from .matcher import FileAnalysis, match_vulnerabilities
from .models import ScanResult
from .package_map import build_package_map
from .scanner import scan_directory
from .trivy_adapter import load_trivy_report

if TYPE_CHECKING:
    from rich.console import Console

    from .ai_analyst import AIConfig


def triage(
    trivy_json: Path,
    src: Path,
    include_tests: bool = False,
    strict: bool = False,
    enrich: bool = True,
    epss_file: Path | None = None,
    kev_file: Path | None = None,
    refresh: bool = False,
    offline: bool = False,
    prioritize_risk: bool = False,
    cve_function_map_file: Path | None = None,
    ai_config: "AIConfig | None" = None,
    console: "Console | None" = None,
) -> list[ScanResult]:
    """Run the full vulnerability triage pipeline.

    Pipeline stages:
    1. Load vulnerabilities from Trivy JSON
    2. Enrich with EPSS/KEV threat intelligence (optional)
    3. Scan source directory to build symbol tables
    4. Find call sites in each file
    5. Match vulnerabilities against call sites
    6. (Optional) AI analysis for non-dismissed results
    7. Return classified results

    Args:
        trivy_json: Path to Trivy JSON report.
        src: Path to source directory to analyze.
        include_tests: If True, include test files in analysis.
        strict: If True, prevent dismissals when any files were skipped.
        enrich: If True, enrich vulnerabilities with EPSS/KEV data.
        epss_file: Optional custom EPSS CSV path.
        kev_file: Optional custom KEV JSON path.
        refresh: If True, refresh cached EPSS/KEV data before enrichment.
        offline: If True, disallow refresh/network operations.
        prioritize_risk: If True, sort by KEV/EPSS instead of severity.
        cve_function_map_file: Optional CVE function map JSON path.
        ai_config: Optional AI configuration (if None or disabled, no AI analysis).
        console: Optional Rich console for progress output.

    Returns:
        List of ScanResult objects with classification and evidence.
    """
    # Stage 1: Load vulnerabilities
    vulnerabilities = load_trivy_report(trivy_json)

    if not vulnerabilities:
        return []

    # Stage 2: Enrich with EPSS/KEV (optional)
    if enrich:
        if offline and refresh:
            raise ValueError("Offline mode enabled; refresh not permitted.")
        if refresh and (epss_file or kev_file):
            import warnings
            warnings.warn(
                "--refresh ignored because custom data source was provided.",
                stacklevel=2,
            )
            refresh = False

        if refresh:
            refresh_epss_data()
            refresh_kev_data()

        vulnerabilities = enrich_vulnerabilities(
            vulnerabilities,
            epss_path=epss_file,
            kev_path=kev_file,
        )

    # Stage 3: Build package map
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

    # Stage 4: Scan source directory
    scan_result = scan_directory(src, include_tests=include_tests)

    # Stage 5: Find call sites and build analysis map
    analysis_map: dict[Path, FileAnalysis] = {}

    for parsed in scan_result.parsed_files:
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

    # Stage 6: Match vulnerabilities
    cve_function_map = load_cve_function_map(cve_function_map_file)
    results = match_vulnerabilities(
        vulnerabilities,
        analysis_map,
        package_to_modules,
        cve_function_map,
    )

    # Strict mode: if any files were skipped, prevent dismissals
    if strict and scan_result.skipped_files:
        skipped_count = len(scan_result.skipped_files)
        results = _apply_strict_mode(results, skipped_count)

    # Stage 7: Sort results (before AI so candidates are prioritized)
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}

    if prioritize_risk:
        # Sort by: KEV first → has EPSS → EPSS desc → severity → vuln_id
        # This ensures CVEs with EPSS data sort by exploit probability,
        # while CVEs without EPSS fall back to severity-based ordering
        results.sort(key=lambda r: (
            not r.vulnerability.is_kev,  # KEV first (False < True)
            r.vulnerability.epss_score is None,  # Has EPSS before missing EPSS
            -(r.vulnerability.epss_score or 0),  # Higher EPSS first (within group)
            severity_order.get(r.vulnerability.severity, 5),
            r.vulnerability.vuln_id,
        ))
    else:
        # Default: severity → vuln_id (backward compatible)
        results.sort(key=lambda r: (
            severity_order.get(r.vulnerability.severity, 5),
            r.vulnerability.vuln_id,
        ))

    # Stage 8: AI analysis (optional, advisory only)
    # AI is NEVER run for dismissed findings (explicit skip policy).
    # The --ai-limit applies only to actionable/needs_review.
    if ai_config and ai_config.enabled:
        from .ai_analyst import apply_ai_analysis
        results = apply_ai_analysis(results, ai_config, console)

    return results


def _apply_strict_mode(results: list[ScanResult], skipped_count: int) -> list[ScanResult]:
    """Prevent dismissals in strict mode - dismissed vulns become needs_review.

    Actionable results are kept as-is (we have evidence of usage).
    Only dismissed results are upgraded - we can't prove absence with incomplete scan.

    Args:
        results: Original classification results.
        skipped_count: Number of files that were skipped.

    Returns:
        Updated results with dismissed vulns forced to needs_review.
    """
    updated: list[ScanResult] = []

    for r in results:
        if r.status == "dismissed":
            # Force to needs_review - we can't prove absence with incomplete scan
            updated.append(ScanResult(
                vulnerability=r.vulnerability,
                status="needs_review",
                reason=f"{r.reason}; {skipped_count} file(s) skipped (--strict mode)",
                evidence=r.evidence,
            ))
        else:
            # actionable and needs_review stay as-is
            updated.append(r)

    return updated
