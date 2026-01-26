"""Tests for Trivy JSON adapter."""

import json
import tempfile
from pathlib import Path

from vulntriage.trivy_adapter import (
    _extract_cvss_score,
    load_trivy_report,
    load_trivy_report_from_string,
)

# Minimal Trivy JSON fixture
MINIMAL_TRIVY_JSON = {
    "SchemaVersion": 2,
    "Results": [
        {
            "Target": "requirements.txt",
            "Type": "pip",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2023-12345",
                    "PkgName": "requests",
                    "InstalledVersion": "2.28.0",
                    "FixedVersion": "2.31.0",
                    "Severity": "HIGH",
                    "Title": "Test vulnerability",
                    "Description": "A test vulnerability description",
                }
            ],
        }
    ],
}


def test_load_trivy_report_from_string_minimal() -> None:
    """Test parsing minimal Trivy JSON."""
    vulns = load_trivy_report_from_string(json.dumps(MINIMAL_TRIVY_JSON))

    assert len(vulns) == 1
    v = vulns[0]
    assert v.vuln_id == "CVE-2023-12345"
    assert v.pkg_name == "requests"
    assert v.installed_version == "2.28.0"
    assert v.fixed_version == "2.31.0"
    assert v.severity == "HIGH"
    assert v.title == "Test vulnerability"


def test_load_trivy_report_from_file() -> None:
    """Test loading from actual file."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(MINIMAL_TRIVY_JSON, f)
        f.flush()
        path = Path(f.name)

    try:
        vulns = load_trivy_report(path)
        assert len(vulns) == 1
        assert vulns[0].vuln_id == "CVE-2023-12345"
    finally:
        path.unlink()


def test_deduplication_by_cve_and_package() -> None:
    """Same CVE + same package should be deduplicated."""
    data = {
        "SchemaVersion": 2,
        "Results": [
            {
                "Target": "result1",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2023-00001",
                        "PkgName": "pkg1",
                        "InstalledVersion": "1.0.0",
                        "Severity": "HIGH",
                    }
                ],
            },
            {
                "Target": "result2",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2023-00001",  # Same CVE, same package
                        "PkgName": "pkg1",
                        "InstalledVersion": "1.0.0",
                        "Severity": "HIGH",
                    }
                ],
            },
        ],
    }

    vulns = load_trivy_report_from_string(json.dumps(data))
    assert len(vulns) == 1


def test_same_cve_different_packages_not_deduplicated() -> None:
    """Same CVE in different packages should NOT be deduplicated."""
    data = {
        "SchemaVersion": 2,
        "Results": [
            {
                "Target": "result1",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2023-00001",
                        "PkgName": "pkg1",
                        "InstalledVersion": "1.0.0",
                        "Severity": "HIGH",
                    },
                    {
                        "VulnerabilityID": "CVE-2023-00001",  # Same CVE, different package
                        "PkgName": "pkg2",
                        "InstalledVersion": "2.0.0",
                        "Severity": "HIGH",
                    },
                ],
            }
        ],
    }

    vulns = load_trivy_report_from_string(json.dumps(data))
    assert len(vulns) == 2
    assert {v.pkg_name for v in vulns} == {"pkg1", "pkg2"}


def test_same_cve_same_package_different_versions_not_deduplicated() -> None:
    """Same CVE + same package + different versions should NOT be deduplicated."""
    data = {
        "SchemaVersion": 2,
        "Results": [
            {
                "Target": "lockfile1",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2023-00001",
                        "PkgName": "requests",
                        "InstalledVersion": "2.28.0",
                        "Severity": "HIGH",
                    },
                ],
            },
            {
                "Target": "lockfile2",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2023-00001",  # Same CVE, same package
                        "PkgName": "requests",
                        "InstalledVersion": "2.25.0",  # Different version
                        "Severity": "HIGH",
                    },
                ],
            },
        ],
    }

    vulns = load_trivy_report_from_string(json.dumps(data))
    assert len(vulns) == 2


def test_deduplication_case_insensitive_package_name() -> None:
    """Same CVE with package name differing by case should be deduplicated."""
    data = {
        "SchemaVersion": 2,
        "Results": [
            {
                "Target": "result1",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2023-00001",
                        "PkgName": "Django",
                        "InstalledVersion": "4.0.0",
                        "Severity": "HIGH",
                    }
                ],
            },
            {
                "Target": "result2",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2023-00001",
                        "PkgName": "django",
                        "InstalledVersion": "4.0.0",
                        "Severity": "HIGH",
                    }
                ],
            },
        ],
    }

    vulns = load_trivy_report_from_string(json.dumps(data))
    assert len(vulns) == 1
    assert {v.installed_version for v in vulns} == {"4.0.0"}


def test_multiple_vulnerabilities() -> None:
    """Multiple distinct CVEs should all be included."""
    data = {
        "SchemaVersion": 2,
        "Results": [
            {
                "Target": "result1",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2023-00001",
                        "PkgName": "pkg1",
                        "InstalledVersion": "1.0.0",
                        "Severity": "HIGH",
                    },
                    {
                        "VulnerabilityID": "CVE-2023-00002",
                        "PkgName": "pkg2",
                        "InstalledVersion": "2.0.0",
                        "Severity": "MEDIUM",
                    },
                ],
            }
        ],
    }

    vulns = load_trivy_report_from_string(json.dumps(data))
    assert len(vulns) == 2
    assert {v.vuln_id for v in vulns} == {"CVE-2023-00001", "CVE-2023-00002"}


def test_empty_results() -> None:
    """Empty Results array should return empty list."""
    data = {"SchemaVersion": 2, "Results": []}
    vulns = load_trivy_report_from_string(json.dumps(data))
    assert vulns == []


def test_no_vulnerabilities() -> None:
    """Result with no Vulnerabilities key should return empty list."""
    data = {
        "SchemaVersion": 2,
        "Results": [{"Target": "clean.txt", "Type": "pip"}],
    }
    vulns = load_trivy_report_from_string(json.dumps(data))
    assert vulns == []


def test_cvss_extraction_nvd_v3() -> None:
    """CVSS score should be extracted from NVD V3."""
    cvss = {"nvd": {"V3Score": 7.5, "V2Score": 5.0}}
    assert _extract_cvss_score(cvss) == 7.5


def test_cvss_extraction_nvd_v2_fallback() -> None:
    """Fall back to V2 if V3 not available."""
    cvss = {"nvd": {"V2Score": 5.0}}
    assert _extract_cvss_score(cvss) == 5.0


def test_cvss_extraction_other_source() -> None:
    """Use other source if NVD not available."""
    cvss = {"redhat": {"V3Score": 6.5}}
    assert _extract_cvss_score(cvss) == 6.5


def test_cvss_extraction_none() -> None:
    """Return None if no CVSS data."""
    assert _extract_cvss_score(None) is None
    assert _extract_cvss_score({}) is None


def test_cvss_extraction_malformed() -> None:
    """Malformed CVSS data should return None, not raise."""
    # Null value
    assert _extract_cvss_score({"nvd": {"V3Score": None}}) is None
    # Non-numeric string
    assert _extract_cvss_score({"nvd": {"V3Score": "not-a-number"}}) is None
    # Nested wrong type
    assert _extract_cvss_score({"nvd": "not-a-dict"}) is None


def test_cvss_in_vulnerability() -> None:
    """CVSS score should be extracted into Vulnerability model."""
    data = {
        "SchemaVersion": 2,
        "Results": [
            {
                "Target": "test",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2023-99999",
                        "PkgName": "vulnerable-pkg",
                        "InstalledVersion": "1.0.0",
                        "Severity": "CRITICAL",
                        "CVSS": {"nvd": {"V3Score": 9.8}},
                    }
                ],
            }
        ],
    }

    vulns = load_trivy_report_from_string(json.dumps(data))
    assert len(vulns) == 1
    assert vulns[0].cvss_score == 9.8


def test_missing_optional_fields() -> None:
    """Optional fields should have sensible defaults."""
    data = {
        "SchemaVersion": 2,
        "Results": [
            {
                "Target": "test",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2023-MINIMAL",
                        "PkgName": "minimal-pkg",
                        "InstalledVersion": "0.1.0",
                    }
                ],
            }
        ],
    }

    vulns = load_trivy_report_from_string(json.dumps(data))
    assert len(vulns) == 1
    v = vulns[0]
    assert v.fixed_version is None
    assert v.severity == "UNKNOWN"
    assert v.title == ""
    assert v.description == ""
    assert v.cvss_score is None
