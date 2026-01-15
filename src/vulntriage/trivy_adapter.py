"""Trivy JSON adapter - converts Trivy output to internal vulnerability models."""

from pathlib import Path

from .models import Vulnerability


def load_trivy_report(path: Path) -> list[Vulnerability]:
    """
    Load and parse a Trivy JSON report.

    Args:
        path: Path to the Trivy JSON file.

    Returns:
        List of Vulnerability objects extracted from the report.
    """
    # TODO: Implement Trivy JSON parsing
    # - Read JSON file
    # - Extract Results[].Vulnerabilities[]
    # - Normalize package names
    # - Deduplicate by CVE ID
    raise NotImplementedError("Trivy adapter not yet implemented")
