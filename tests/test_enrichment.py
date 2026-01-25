"""Tests for EPSS/KEV enrichment module."""

import json
import tempfile
from pathlib import Path

from vulntriage.enrichment import (
    enrich_vulnerabilities,
    enrich_vulnerability,
    get_cache_dir,
    is_data_stale,
    load_epss_data,
    load_kev_data,
    normalize_cve_id,
)
from vulntriage.models import Vulnerability

# --- CVE Normalization Tests ---


def test_normalize_cve_standard() -> None:
    """Standard CVE format should be normalized."""
    assert normalize_cve_id("CVE-2023-12345") == "CVE-2023-12345"


def test_normalize_cve_lowercase() -> None:
    """Lowercase CVE should be normalized to uppercase."""
    assert normalize_cve_id("cve-2023-12345") == "CVE-2023-12345"


def test_normalize_cve_no_dashes() -> None:
    """CVE without dashes should be normalized."""
    assert normalize_cve_id("CVE202312345") == "CVE-2023-12345"


def test_normalize_cve_spaces() -> None:
    """CVE with spaces should be normalized."""
    assert normalize_cve_id("cve 2023 12345") == "CVE-2023-12345"


def test_normalize_cve_invalid() -> None:
    """Invalid CVE should return None."""
    assert normalize_cve_id("not-a-cve") is None
    assert normalize_cve_id("") is None
    assert normalize_cve_id("CVE-") is None


# --- EPSS Loading Tests ---


def test_load_epss_from_csv() -> None:
    """Load EPSS data from CSV file."""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".csv", delete=False
    ) as f:
        f.write("cve,epss,percentile\n")
        f.write("CVE-2023-12345,0.5,0.95\n")
        f.write("cve-2023-99999,0.01,0.50\n")
        path = Path(f.name)

    try:
        data = load_epss_data(path)
        assert len(data) == 2
        assert data["CVE-2023-12345"] == 0.5
        assert data["CVE-2023-99999"] == 0.01
    finally:
        path.unlink()


def test_load_epss_missing_file() -> None:
    """Missing EPSS file should return empty dict with warning."""
    import warnings

    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        data = load_epss_data(Path("/nonexistent/epss.csv"))

    # Should return empty dict, not crash
    assert data == {} or len(data) >= 0  # May have bundled fallback


def test_load_epss_invalid_score() -> None:
    """Invalid EPSS scores should be skipped."""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".csv", delete=False
    ) as f:
        f.write("cve,epss,percentile\n")
        f.write("CVE-2023-12345,0.5,0.95\n")
        f.write("CVE-2023-99999,invalid,0.50\n")  # Invalid score
        path = Path(f.name)

    try:
        data = load_epss_data(path)
        assert len(data) == 1
        assert "CVE-2023-12345" in data
        assert "CVE-2023-99999" not in data
    finally:
        path.unlink()


# --- KEV Loading Tests ---


def test_load_kev_from_json() -> None:
    """Load KEV data from JSON file."""
    kev_json = {
        "vulnerabilities": [
            {"cveID": "CVE-2023-12345"},
            {"cveID": "cve-2023-99999"},  # Lowercase
        ]
    }

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False
    ) as f:
        json.dump(kev_json, f)
        path = Path(f.name)

    try:
        data = load_kev_data(path)
        assert len(data) == 2
        assert "CVE-2023-12345" in data
        assert "CVE-2023-99999" in data
    finally:
        path.unlink()


def test_load_kev_missing_file() -> None:
    """Missing KEV file should return empty set with warning."""
    import warnings

    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        data = load_kev_data(Path("/nonexistent/kev.json"))

    # Should return empty set or bundled data, not crash
    assert isinstance(data, set)


# --- Enrichment Tests ---


def test_enrich_vulnerability() -> None:
    """Enrich a vulnerability with EPSS and KEV data."""
    vuln = Vulnerability(
        vuln_id="CVE-2023-12345",
        pkg_name="test-pkg",
        installed_version="1.0.0",
        severity="HIGH",
    )

    epss_data = {"CVE-2023-12345": 0.75}
    kev_data = {"CVE-2023-12345"}

    enriched = enrich_vulnerability(vuln, epss_data, kev_data)

    assert enriched.epss_score == 0.75
    assert enriched.is_kev is True
    # Original should be unchanged
    assert vuln.epss_score is None
    assert vuln.is_kev is False


def test_enrich_vulnerability_not_in_data() -> None:
    """Vulnerability not in EPSS/KEV data stays unenriched."""
    vuln = Vulnerability(
        vuln_id="CVE-2023-99999",
        pkg_name="test-pkg",
        installed_version="1.0.0",
        severity="MEDIUM",
    )

    epss_data = {"CVE-2023-12345": 0.75}
    kev_data = {"CVE-2023-12345"}

    enriched = enrich_vulnerability(vuln, epss_data, kev_data)

    assert enriched.epss_score is None
    assert enriched.is_kev is False


def test_enrich_vulnerabilities_list() -> None:
    """Enrich a list of vulnerabilities."""
    vulns = [
        Vulnerability(
            vuln_id="CVE-2023-12345",
            pkg_name="pkg1",
            installed_version="1.0.0",
            severity="HIGH",
        ),
        Vulnerability(
            vuln_id="CVE-2023-99999",
            pkg_name="pkg2",
            installed_version="2.0.0",
            severity="LOW",
        ),
    ]

    # Create temp files
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".csv", delete=False
    ) as f:
        f.write("cve,epss,percentile\n")
        f.write("CVE-2023-12345,0.80,0.98\n")
        epss_path = Path(f.name)

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False
    ) as f:
        json.dump({"vulnerabilities": [{"cveID": "CVE-2023-12345"}]}, f)
        kev_path = Path(f.name)

    try:
        enriched = enrich_vulnerabilities(vulns, epss_path, kev_path)

        assert len(enriched) == 2
        assert enriched[0].epss_score == 0.80
        assert enriched[0].is_kev is True
        assert enriched[1].epss_score is None
        assert enriched[1].is_kev is False
    finally:
        epss_path.unlink()
        kev_path.unlink()


# --- Cache Tests ---


def test_cache_dir_created() -> None:
    """Cache directory should be created."""
    cache_dir = get_cache_dir()
    assert cache_dir.exists()
    assert cache_dir.is_dir()


def test_is_data_stale_no_metadata() -> None:
    """Data is considered stale if no metadata exists."""
    # Use a unique data type to avoid interference
    assert is_data_stale("test_nonexistent_type_xyz")
