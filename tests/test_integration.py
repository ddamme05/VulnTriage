"""Integration tests for end-to-end triage pipeline."""

import json
import tempfile
from pathlib import Path

from vulntriage.triage import triage


def create_trivy_json(vulnerabilities: list) -> Path:
    """Create a temporary Trivy JSON file."""
    data = {
        "SchemaVersion": 2,
        "Results": [
            {
                "Target": "requirements.txt",
                "Type": "pip",
                "Vulnerabilities": vulnerabilities,
            }
        ] if vulnerabilities else [],
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(data, f)
        return Path(f.name)


def create_source_file(tmp_path: Path, content: str) -> Path:
    """Create a source file in the temp directory."""
    src_file = tmp_path / "app.py"
    src_file.write_text(content)
    return src_file


def test_empty_trivy_report() -> None:
    """Empty Trivy report returns empty results."""
    trivy_json = create_trivy_json([])
    try:
        with tempfile.TemporaryDirectory() as tmp:
            results = triage(trivy_json, Path(tmp))
            assert results == []
    finally:
        trivy_json.unlink()


def test_vulnerability_dismissed_no_import() -> None:
    """Vulnerability dismissed when package not imported."""
    trivy_json = create_trivy_json([
        {
            "VulnerabilityID": "CVE-2023-00001",
            "PkgName": "requests",
            "InstalledVersion": "2.28.0",
            "Severity": "HIGH",
        }
    ])

    try:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            # Source file doesn't import requests
            (tmp_path / "app.py").write_text("import os\nprint('hello')")

            results = triage(trivy_json, tmp_path)
            assert len(results) == 1
            assert results[0].status == "dismissed"
            assert "not imported" in results[0].reason.lower()
    finally:
        trivy_json.unlink()


def test_vulnerability_actionable_with_call() -> None:
    """Vulnerability actionable when package used."""
    trivy_json = create_trivy_json([
        {
            "VulnerabilityID": "CVE-2023-00001",
            "PkgName": "requests",
            "InstalledVersion": "2.28.0",
            "Severity": "HIGH",
        }
    ])

    try:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            # Source file imports and calls requests
            (tmp_path / "app.py").write_text("""\
import requests
response = requests.get("https://example.com")
""")

            results = triage(trivy_json, tmp_path)
            assert len(results) == 1
            assert results[0].status == "actionable"
            assert len(results[0].evidence) >= 1
    finally:
        trivy_json.unlink()


def test_vulnerability_needs_review_import_only() -> None:
    """Vulnerability needs_review when imported but not called."""
    trivy_json = create_trivy_json([
        {
            "VulnerabilityID": "CVE-2023-00001",
            "PkgName": "requests",
            "InstalledVersion": "2.28.0",
            "Severity": "HIGH",
        }
    ])

    try:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            # Source file imports but doesn't call
            (tmp_path / "app.py").write_text("""\
import requests
# Not used
print("hello")
""")

            results = triage(trivy_json, tmp_path)
            assert len(results) == 1
            assert results[0].status == "needs_review"
            assert "imported but no direct calls" in results[0].reason.lower()
    finally:
        trivy_json.unlink()


def test_multiple_vulnerabilities() -> None:
    """Multiple vulnerabilities are classified independently."""
    trivy_json = create_trivy_json([
        {
            "VulnerabilityID": "CVE-2023-00001",
            "PkgName": "requests",
            "InstalledVersion": "2.28.0",
            "Severity": "HIGH",
        },
        {
            "VulnerabilityID": "CVE-2023-00002",
            "PkgName": "urllib3",
            "InstalledVersion": "1.26.0",
            "Severity": "MEDIUM",
        },
    ])

    try:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            # Only use requests, not urllib3
            (tmp_path / "app.py").write_text("""\
import requests
response = requests.get("https://example.com")
""")

            results = triage(trivy_json, tmp_path)
            assert len(results) == 2

            # Find results by CVE
            results_by_cve = {r.vulnerability.vuln_id: r for r in results}

            # requests should be actionable
            assert results_by_cve["CVE-2023-00001"].status == "actionable"

            # urllib3 should be dismissed (not imported)
            assert results_by_cve["CVE-2023-00002"].status == "dismissed"
    finally:
        trivy_json.unlink()


def test_results_sorted_by_severity() -> None:
    """Results are sorted by severity (CRITICAL first)."""
    trivy_json = create_trivy_json([
        {
            "VulnerabilityID": "CVE-2023-LOW",
            "PkgName": "pkg1",
            "InstalledVersion": "1.0.0",
            "Severity": "LOW",
        },
        {
            "VulnerabilityID": "CVE-2023-CRITICAL",
            "PkgName": "pkg2",
            "InstalledVersion": "1.0.0",
            "Severity": "CRITICAL",
        },
        {
            "VulnerabilityID": "CVE-2023-HIGH",
            "PkgName": "pkg3",
            "InstalledVersion": "1.0.0",
            "Severity": "HIGH",
        },
    ])

    try:
        with tempfile.TemporaryDirectory() as tmp:
            results = triage(trivy_json, Path(tmp))
            assert len(results) == 3

            # Check order: CRITICAL, HIGH, LOW
            severities = [r.vulnerability.severity for r in results]
            assert severities == ["CRITICAL", "HIGH", "LOW"]
    finally:
        trivy_json.unlink()


def test_unknown_package_needs_review() -> None:
    """Unknown/unmapped package should always be needs_review, never dismissed."""
    trivy_json = create_trivy_json([
        {
            "VulnerabilityID": "CVE-2023-00001",
            # obscure-package-xyz is NOT in package map
            "PkgName": "obscure-package-xyz",
            "InstalledVersion": "1.0.0",
            "Severity": "HIGH",
        }
    ])

    try:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            # Source file doesn't import this package - but since it's unknown,
            # we can't be sure. Must be needs_review, NOT dismissed.
            (tmp_path / "app.py").write_text("import os\nprint('hello')")

            results = triage(trivy_json, tmp_path)
            assert len(results) == 1
            assert results[0].status == "needs_review"
            assert "unknown" in results[0].reason.lower() or "mapping" in results[0].reason.lower()
    finally:
        trivy_json.unlink()


def test_wildcard_import_forces_needs_review() -> None:
    """Wildcard import should prevent dismissal."""
    trivy_json = create_trivy_json([
        {
            "VulnerabilityID": "CVE-2023-00001",
            "PkgName": "requests",
            "InstalledVersion": "2.28.0",
            "Severity": "HIGH",
        }
    ])

    try:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            # Wildcard import from requests - can't know what was imported
            (tmp_path / "app.py").write_text("from requests import *\n")

            results = triage(trivy_json, tmp_path)
            assert len(results) == 1
            # Should NOT be dismissed - wildcard creates uncertainty
            assert results[0].status == "needs_review"
            assert "wildcard" in results[0].reason.lower() or "uncertainty" in results[0].reason.lower()
    finally:
        trivy_json.unlink()


def test_dynamic_import_forces_needs_review() -> None:
    """Dynamic import should prevent dismissal."""
    trivy_json = create_trivy_json([
        {
            "VulnerabilityID": "CVE-2023-00001",
            "PkgName": "requests",
            "InstalledVersion": "2.28.0",
            "Severity": "HIGH",
        }
    ])

    try:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            # Dynamic import - can't know what module will be imported
            (tmp_path / "app.py").write_text(
                "import importlib\n"
                "mod = importlib.import_module('requests')\n"
            )

            results = triage(trivy_json, tmp_path)
            assert len(results) == 1
            # Should NOT be dismissed - dynamic import creates uncertainty
            assert results[0].status == "needs_review"
            assert "dynamic" in results[0].reason.lower() or "uncertainty" in results[0].reason.lower()
    finally:
        trivy_json.unlink()


def test_strict_mode_forces_needs_review_when_files_skipped() -> None:
    """Strict mode should force dismissed to needs_review when files are skipped."""
    import vulntriage.scanner as scanner_module

    trivy_json = create_trivy_json([
        {
            "VulnerabilityID": "CVE-2023-00001",
            "PkgName": "requests",
            "InstalledVersion": "2.28.0",
            "Severity": "HIGH",
        }
    ])

    # Temporarily set small file size limit to force a skip
    original_limit = scanner_module.MAX_FILE_SIZE_BYTES
    scanner_module.MAX_FILE_SIZE_BYTES = 50  # 50 bytes

    try:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            # Small file - no requests import
            (tmp_path / "small.py").write_text("x = 1")
            # Large file - will be skipped
            (tmp_path / "large.py").write_text("x = 1\n" * 20)

            import warnings
            with warnings.catch_warnings(record=True):
                warnings.simplefilter("always")

                # Without strict mode, should be dismissed
                results_normal = triage(trivy_json, tmp_path, strict=False)
                assert len(results_normal) == 1
                assert results_normal[0].status == "dismissed"

                # With strict mode, should be needs_review
                results_strict = triage(trivy_json, tmp_path, strict=True)
                assert len(results_strict) == 1
                assert results_strict[0].status == "needs_review"
                assert "--strict" in results_strict[0].reason
                assert "skipped" in results_strict[0].reason.lower()
    finally:
        scanner_module.MAX_FILE_SIZE_BYTES = original_limit
        trivy_json.unlink()


# --- EPSS/KEV Enrichment Integration Tests ---


def test_enrichment_populates_epss_and_kev_fields() -> None:
    """Enrichment should populate epss_score and is_kev on vulnerabilities."""
    trivy_json = create_trivy_json([
        {
            "VulnerabilityID": "CVE-2021-44228",  # In bundled sample data
            "PkgName": "log4j",
            "InstalledVersion": "2.14.0",
            "Severity": "CRITICAL",
        }
    ])

    try:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            create_source_file(tmp_path, "x = 1")  # No import

            results = triage(trivy_json, tmp_path, enrich=True)
            assert len(results) == 1
            vuln = results[0].vulnerability

            # CVE-2021-44228 is in bundled sample data (EPSS and KEV)
            # NOTE: These assertions are coupled to bundled sample data values
            assert vuln.epss_score is not None
            assert vuln.is_kev is True
    finally:
        trivy_json.unlink()


def test_no_enrich_leaves_fields_none() -> None:
    """--no-enrich should leave EPSS/KEV fields as None/False."""
    trivy_json = create_trivy_json([
        {
            "VulnerabilityID": "CVE-2021-44228",
            "PkgName": "log4j",
            "InstalledVersion": "2.14.0",
            "Severity": "CRITICAL",
        }
    ])

    try:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            create_source_file(tmp_path, "x = 1")

            results = triage(trivy_json, tmp_path, enrich=False)
            assert len(results) == 1
            vuln = results[0].vulnerability

            # Should remain unenriched
            assert vuln.epss_score is None
            assert vuln.is_kev is False
    finally:
        trivy_json.unlink()


def test_prioritize_risk_sorts_kev_first() -> None:
    """--prioritize-risk should sort KEV vulnerabilities before non-KEV."""
    trivy_json = create_trivy_json([
        {
            "VulnerabilityID": "CVE-2023-99999",  # Not in KEV
            "PkgName": "pkg1",
            "InstalledVersion": "1.0.0",
            "Severity": "CRITICAL",
        },
        {
            "VulnerabilityID": "CVE-2021-44228",  # In KEV
            "PkgName": "log4j",
            "InstalledVersion": "2.14.0",
            "Severity": "HIGH",  # Lower severity but KEV
        },
    ])

    try:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            create_source_file(tmp_path, "x = 1")

            # Default sort: CRITICAL first
            results_default = triage(trivy_json, tmp_path, prioritize_risk=False)
            assert len(results_default) == 2
            assert results_default[0].vulnerability.vuln_id == "CVE-2023-99999"

            # Risk sort: KEV first
            results_risk = triage(trivy_json, tmp_path, prioritize_risk=True)
            assert len(results_risk) == 2
            assert results_risk[0].vulnerability.vuln_id == "CVE-2021-44228"
            assert results_risk[0].vulnerability.is_kev is True
    finally:
        trivy_json.unlink()


def test_prioritize_risk_sorts_by_epss_within_kev() -> None:
    """--prioritize-risk should sort by EPSS within KEV/non-KEV groups."""
    trivy_json = create_trivy_json([
        {
            "VulnerabilityID": "CVE-2023-6129",  # Low EPSS in sample
            "PkgName": "pkg1",
            "InstalledVersion": "1.0.0",
            "Severity": "CRITICAL",
        },
        {
            "VulnerabilityID": "CVE-2023-44487",  # High EPSS in sample
            "PkgName": "pkg2",
            "InstalledVersion": "1.0.0",
            "Severity": "LOW",
        },
    ])

    try:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            create_source_file(tmp_path, "x = 1")

            results = triage(trivy_json, tmp_path, prioritize_risk=True)
            assert len(results) == 2

            # Higher EPSS should come first (sorting by EPSS desc)
            first_epss = results[0].vulnerability.epss_score or 0
            second_epss = results[1].vulnerability.epss_score or 0
            assert first_epss >= second_epss
    finally:
        trivy_json.unlink()


def test_cve_normalization_handles_lowercase() -> None:
    """CVE IDs should be normalized for matching."""
    # CVE-2021-44228 is in sample data
    trivy_json = create_trivy_json([
        {
            "VulnerabilityID": "cve-2021-44228",  # lowercase
            "PkgName": "log4j",
            "InstalledVersion": "2.14.0",
            "Severity": "CRITICAL",
        }
    ])

    try:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            create_source_file(tmp_path, "x = 1")

            results = triage(trivy_json, tmp_path, enrich=True)
            assert len(results) == 1
            vuln = results[0].vulnerability

            # Should match despite lowercase
            assert vuln.epss_score is not None
            assert vuln.is_kev is True
    finally:
        trivy_json.unlink()


def test_unknown_cve_has_no_epss() -> None:
    """CVE not in EPSS data should have None score."""
    trivy_json = create_trivy_json([
        {
            "VulnerabilityID": "CVE-9999-99999",  # Not in any data
            "PkgName": "unknown-pkg",
            "InstalledVersion": "1.0.0",
            "Severity": "MEDIUM",
        }
    ])

    try:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            create_source_file(tmp_path, "x = 1")

            results = triage(trivy_json, tmp_path, enrich=True)
            assert len(results) == 1
            vuln = results[0].vulnerability

            assert vuln.epss_score is None
            assert vuln.is_kev is False
    finally:
        trivy_json.unlink()


def test_enrichment_with_actionable_vulnerability() -> None:
    """Enrichment should work alongside actionable classification."""
    trivy_json = create_trivy_json([
        {
            "VulnerabilityID": "CVE-2021-44228",
            "PkgName": "requests",
            "InstalledVersion": "2.28.0",
            "Severity": "CRITICAL",
        }
    ])

    try:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            # Import AND call - should be actionable
            create_source_file(tmp_path, "import requests\nrequests.get('url')")

            results = triage(trivy_json, tmp_path, enrich=True)
            assert len(results) == 1

            # Should be both enriched AND actionable
            assert results[0].status == "actionable"
            assert results[0].vulnerability.epss_score is not None
            assert results[0].vulnerability.is_kev is True
    finally:
        trivy_json.unlink()


def test_prioritize_risk_kev_without_epss_vs_non_kev_with_epss() -> None:
    """KEV without EPSS should sort before non-KEV with EPSS.

    This tests the edge case where:
    - CVE-2017-5638 is in KEV but NOT in EPSS sample
    - CVE-2023-32681 is NOT in KEV but HAS EPSS data (12.5%)

    Expected: KEV item first (even without EPSS), then non-KEV with EPSS.
    """
    trivy_json = create_trivy_json([
        {
            "VulnerabilityID": "CVE-2023-32681",  # NOT in KEV, HAS EPSS (12.5%)
            "PkgName": "requests",
            "InstalledVersion": "2.28.0",
            "Severity": "MEDIUM",
        },
        {
            "VulnerabilityID": "CVE-2017-5638",  # IN KEV, NO EPSS
            "PkgName": "struts",
            "InstalledVersion": "2.3.0",
            "Severity": "CRITICAL",
        },
    ])

    try:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            create_source_file(tmp_path, "x = 1")

            results = triage(trivy_json, tmp_path, prioritize_risk=True)
            assert len(results) == 2

            # KEV item should be first, even though it has no EPSS
            assert results[0].vulnerability.vuln_id == "CVE-2017-5638"
            assert results[0].vulnerability.is_kev is True
            assert results[0].vulnerability.epss_score is None  # No EPSS data

            # Non-KEV with EPSS should be second
            assert results[1].vulnerability.vuln_id == "CVE-2023-32681"
            assert results[1].vulnerability.is_kev is False
            assert results[1].vulnerability.epss_score is not None  # Has EPSS
    finally:
        trivy_json.unlink()


def test_prioritize_risk_missing_epss_falls_back_to_severity() -> None:
    """CVEs without EPSS should sort by severity within their group.

    Tests that CRITICAL without EPSS comes before MEDIUM without EPSS.
    """
    trivy_json = create_trivy_json([
        {
            "VulnerabilityID": "CVE-9999-00001",  # Not in EPSS, MEDIUM
            "PkgName": "pkg1",
            "InstalledVersion": "1.0.0",
            "Severity": "MEDIUM",
        },
        {
            "VulnerabilityID": "CVE-9999-00002",  # Not in EPSS, CRITICAL
            "PkgName": "pkg2",
            "InstalledVersion": "1.0.0",
            "Severity": "CRITICAL",
        },
    ])

    try:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            create_source_file(tmp_path, "x = 1")

            results = triage(trivy_json, tmp_path, prioritize_risk=True)
            assert len(results) == 2

            # Both have no EPSS, so should fall back to severity
            assert results[0].vulnerability.vuln_id == "CVE-9999-00002"  # CRITICAL
            assert results[0].vulnerability.severity == "CRITICAL"
            assert results[0].vulnerability.epss_score is None

            assert results[1].vulnerability.vuln_id == "CVE-9999-00001"  # MEDIUM
            assert results[1].vulnerability.severity == "MEDIUM"
            assert results[1].vulnerability.epss_score is None
    finally:
        trivy_json.unlink()
