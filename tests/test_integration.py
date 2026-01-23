"""Integration tests for end-to-end triage pipeline."""

import json
import tempfile
from pathlib import Path

import pytest

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

