"""Trivy JSON adapter - converts Trivy output to internal vulnerability models."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from .models import Vulnerability


class TrivyVulnerability(BaseModel):
    """Raw vulnerability from Trivy JSON."""

    VulnerabilityID: str
    PkgName: str
    InstalledVersion: str
    FixedVersion: str | None = None
    Severity: str = "UNKNOWN"
    Title: str = ""
    Description: str = ""
    # CVSS scores - Trivy provides multiple sources
    CVSS: dict[str, Any] | None = None


class TrivyResult(BaseModel):
    """A single result from Trivy scan (one target)."""

    Target: str = ""
    Type: str = ""
    Vulnerabilities: list[TrivyVulnerability] | None = None


class TrivyReport(BaseModel):
    """Top-level Trivy JSON report."""

    SchemaVersion: int = Field(default=2)
    Results: list[TrivyResult] | None = None


def load_trivy_report(path: Path) -> list[Vulnerability]:
    """
    Load and parse a Trivy JSON report.

    Args:
        path: Path to the Trivy JSON file.

    Returns:
        List of Vulnerability objects extracted from the report.

    Raises:
        FileNotFoundError: If the report file doesn't exist.
        json.JSONDecodeError: If the file is not valid JSON.
        pydantic.ValidationError: If the JSON doesn't match expected schema.
    """
    content = path.read_text(encoding="utf-8")
    return load_trivy_report_from_string(content)


def load_trivy_report_from_string(content: str) -> list[Vulnerability]:
    """Parse Trivy JSON from a string (useful for testing).

    Args:
        content: JSON string.

    Returns:
        List of Vulnerability objects.
    """
    data = json.loads(content)
    report = TrivyReport.model_validate(data)
    return _extract_vulnerabilities(report)


def _extract_vulnerabilities(report: TrivyReport) -> list[Vulnerability]:
    """Extract and deduplicate vulnerabilities from a parsed report.

    Args:
        report: Parsed TrivyReport.

    Returns:
        List of deduplicated Vulnerability objects.
    """
    vulnerabilities: list[Vulnerability] = []
    # Dedupe by (CVE, PkgName, Version) to handle same CVE in different packages/versions
    seen_keys: set[tuple[str, str, str]] = set()

    if not report.Results:
        return vulnerabilities

    for result in report.Results:
        if not result.Vulnerabilities:
            continue

        for vuln in result.Vulnerabilities:
            # Deduplicate by (CVE ID, package name, version)
            key = (vuln.VulnerabilityID, vuln.PkgName, vuln.InstalledVersion)
            if key in seen_keys:
                continue
            seen_keys.add(key)

            vulnerabilities.append(_convert_vulnerability(vuln))

    return vulnerabilities


def _convert_vulnerability(vuln: TrivyVulnerability) -> Vulnerability:
    """Convert a TrivyVulnerability to our internal Vulnerability model.

    Args:
        vuln: Raw Trivy vulnerability.

    Returns:
        Internal Vulnerability object.
    """
    return Vulnerability(
        vuln_id=vuln.VulnerabilityID,
        pkg_name=vuln.PkgName,
        installed_version=vuln.InstalledVersion,
        fixed_version=vuln.FixedVersion,
        severity=vuln.Severity,
        title=vuln.Title,
        description=vuln.Description,
        cvss_score=_extract_cvss_score(vuln.CVSS),
    )


def _extract_cvss_score(cvss_data: dict[str, Any] | None) -> float | None:
    """Extract CVSS score from Trivy's CVSS dict.

    Trivy provides CVSS scores from multiple sources. We prefer:
    1. NVD (nvd)
    2. Any other source

    This function is best-effort and will return None on any parsing error.

    Args:
        cvss_data: Dict like {"nvd": {"V3Score": 7.5}, "redhat": {"V3Score": 6.0}}

    Returns:
        The CVSS score as a float, or None if not available or malformed.
    """
    if not cvss_data:
        return None

    try:
        # Prefer NVD
        if "nvd" in cvss_data:
            nvd = cvss_data["nvd"]
            if isinstance(nvd, dict):
                # Try V3 first, then V2
                if "V3Score" in nvd and nvd["V3Score"] is not None:
                    return float(nvd["V3Score"])
                if "V2Score" in nvd and nvd["V2Score"] is not None:
                    return float(nvd["V2Score"])

        # Fallback to any available source
        for source, scores in cvss_data.items():
            if isinstance(scores, dict):
                if "V3Score" in scores and scores["V3Score"] is not None:
                    return float(scores["V3Score"])
                if "V2Score" in scores and scores["V2Score"] is not None:
                    return float(scores["V2Score"])
    except (ValueError, TypeError):
        # Malformed CVSS data - return None instead of raising
        return None

    return None
