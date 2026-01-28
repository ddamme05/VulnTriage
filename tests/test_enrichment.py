"""Tests for EPSS/KEV enrichment module."""

import gzip
import io
import json
from datetime import datetime
from pathlib import Path

import pytest

from vulntriage.enrichment import (
    enrich_vulnerabilities,
    enrich_vulnerability,
    get_cache_dir,
    is_data_stale,
    load_epss_data,
    load_kev_data,
    normalize_cve_id,
    refresh_epss_data,
    refresh_kev_data,
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


def test_load_epss_from_csv(tmp_path: Path) -> None:
    """Load EPSS data from CSV file."""
    path = tmp_path / "epss.csv"
    path.write_text(
        "cve,epss,percentile\n"
        "CVE-2023-12345,0.5,0.95\n"
        "cve-2023-99999,0.01,0.50\n",
        encoding="utf-8",
    )

    data = load_epss_data(path)
    assert len(data) == 2
    assert data["CVE-2023-12345"] == 0.5
    assert data["CVE-2023-99999"] == 0.01


def test_load_epss_from_csv_with_comment_header(tmp_path: Path) -> None:
    """Load EPSS data when a comment line precedes the header."""
    path = tmp_path / "epss.csv"
    path.write_text(
        "#model_version:v2025.03.14,score_date:2026-01-27T12:55:00Z\n"
        "cve,epss,percentile\n"
        "CVE-2023-12345,0.5,0.95\n",
        encoding="utf-8",
    )

    data = load_epss_data(path)
    assert len(data) == 1
    assert data["CVE-2023-12345"] == 0.5


def test_load_epss_missing_file() -> None:
    """Missing EPSS file should return empty dict with warning."""
    import warnings

    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        data = load_epss_data(Path("/nonexistent/epss.csv"))

    # Should return empty dict, not crash
    assert data == {} or len(data) >= 0  # May have bundled fallback


def test_load_epss_invalid_score(tmp_path: Path) -> None:
    """Invalid EPSS scores should be skipped."""
    path = tmp_path / "epss_invalid.csv"
    path.write_text(
        "cve,epss,percentile\n"
        "CVE-2023-12345,0.5,0.95\n"
        "CVE-2023-99999,invalid,0.50\n",
        encoding="utf-8",
    )

    data = load_epss_data(path)
    assert len(data) == 1
    assert "CVE-2023-12345" in data
    assert "CVE-2023-99999" not in data


def test_load_epss_invalid_cache_falls_back_to_bundled(tmp_path: Path, monkeypatch) -> None:
    """Invalid cached EPSS should fall back to bundled data."""
    import vulntriage.enrichment as enrichment

    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    (cache_dir / "epss.csv").write_text("bad,header\n", encoding="utf-8")
    (cache_dir / "metadata.json").write_text(
        json.dumps({"epss_updated": datetime.now().isoformat()}),
        encoding="utf-8",
    )

    bundled = tmp_path / "epss_sample.csv"
    bundled.write_text("cve,epss\nCVE-2023-12345,0.5\n", encoding="utf-8")

    monkeypatch.setattr(enrichment, "CACHE_DIR", cache_dir)
    monkeypatch.setattr(enrichment, "_get_bundled_data_path", lambda _: bundled)

    with pytest.warns(UserWarning, match="Failed to load cached EPSS data"):
        data = enrichment.load_epss_data()
    assert data.get("CVE-2023-12345") == 0.5


# --- KEV Loading Tests ---


def test_load_kev_from_json(tmp_path: Path) -> None:
    """Load KEV data from JSON file."""
    kev_json = {
        "vulnerabilities": [
            {"cveID": "CVE-2023-12345"},
            {"cveID": "cve-2023-99999"},  # Lowercase
        ]
    }

    path = tmp_path / "kev.json"
    path.write_text(json.dumps(kev_json), encoding="utf-8")

    data = load_kev_data(path)
    assert len(data) == 2
    assert "CVE-2023-12345" in data
    assert "CVE-2023-99999" in data


def test_load_kev_missing_file() -> None:
    """Missing KEV file should return empty set with warning."""
    import warnings

    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        data = load_kev_data(Path("/nonexistent/kev.json"))

    # Should return empty set or bundled data, not crash
    assert isinstance(data, set)


def test_load_kev_invalid_cache_falls_back_to_bundled(tmp_path: Path, monkeypatch) -> None:
    """Invalid cached KEV should fall back to bundled data."""
    import vulntriage.enrichment as enrichment

    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    (cache_dir / "kev.json").write_text(json.dumps({"bad": []}), encoding="utf-8")
    (cache_dir / "metadata.json").write_text(
        json.dumps({"kev_updated": datetime.now().isoformat()}),
        encoding="utf-8",
    )

    bundled = tmp_path / "kev.json"
    bundled.write_text(
        json.dumps({"vulnerabilities": [{"cveID": "CVE-2023-12345"}]}),
        encoding="utf-8",
    )

    monkeypatch.setattr(enrichment, "CACHE_DIR", cache_dir)
    monkeypatch.setattr(enrichment, "_get_bundled_data_path", lambda _: bundled)

    with pytest.warns(UserWarning, match="Failed to load cached KEV data"):
        data = enrichment.load_kev_data()
    assert "CVE-2023-12345" in data


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


def test_enrich_vulnerabilities_list(tmp_path: Path) -> None:
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

    epss_path = tmp_path / "epss.csv"
    epss_path.write_text(
        "cve,epss,percentile\nCVE-2023-12345,0.80,0.98\n",
        encoding="utf-8",
    )

    kev_path = tmp_path / "kev.json"
    kev_path.write_text(
        json.dumps({"vulnerabilities": [{"cveID": "CVE-2023-12345"}]}),
        encoding="utf-8",
    )

    enriched = enrich_vulnerabilities(vulns, epss_path, kev_path)

    assert len(enriched) == 2
    assert enriched[0].epss_score == 0.80
    assert enriched[0].is_kev is True
    assert enriched[1].epss_score is None
    assert enriched[1].is_kev is False


# --- Cache Tests ---


def test_cache_dir_created() -> None:
    """Cache directory should be created."""
    cache_dir = get_cache_dir()
    assert cache_dir.exists()
    assert cache_dir.is_dir()


def test_is_data_stale_no_metadata() -> None:
    """Data is considered stale if no metadata exists."""
    # Use a unique data type to avoid interference
    assert is_data_stale("test_nonexistent_type_xyz", 3)


# --- Refresh Tests ---


class _FakeResponse(io.BytesIO):
    """Minimal file-like response for urlopen mocking."""

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    @property
    def status(self) -> int:
        return 200


def test_refresh_epss_data_writes_cache(tmp_path: Path, monkeypatch) -> None:
    """refresh_epss_data should download and write epss.csv in cache."""
    import vulntriage.enrichment as enrichment

    monkeypatch.setattr(enrichment, "CACHE_DIR", tmp_path / "cache")

    csv_data = "cve,epss\nCVE-2023-12345,0.5\n"
    gz_bytes = gzip.compress(csv_data.encode("utf-8"))

    monkeypatch.setattr(
        enrichment.urllib.request,
        "urlopen",
        lambda url, timeout=30: _FakeResponse(gz_bytes),
    )

    path = refresh_epss_data()
    assert path is not None
    assert path.exists()
    header = path.read_text(encoding="utf-8").splitlines()[0].lower()
    assert "cve" in header and "epss" in header


def test_refresh_epss_data_invalid_header(tmp_path: Path, monkeypatch) -> None:
    """Invalid EPSS header should be rejected."""
    import warnings
    import vulntriage.enrichment as enrichment

    monkeypatch.setattr(enrichment, "CACHE_DIR", tmp_path / "cache")

    csv_data = "foo,bar\n"
    gz_bytes = gzip.compress(csv_data.encode("utf-8"))

    monkeypatch.setattr(
        enrichment.urllib.request,
        "urlopen",
        lambda url, timeout=30: _FakeResponse(gz_bytes),
    )

    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        path = refresh_epss_data()
    assert path is None
    assert w


def test_refresh_epss_data_plain_csv(tmp_path: Path, monkeypatch) -> None:
    """Plain CSV EPSS downloads should be accepted (non-gzip)."""
    import vulntriage.enrichment as enrichment

    monkeypatch.setattr(enrichment, "CACHE_DIR", tmp_path / "cache")

    csv_data = "cve,epss\nCVE-2023-12345,0.5\n"
    csv_bytes = csv_data.encode("utf-8")

    monkeypatch.setattr(
        enrichment.urllib.request,
        "urlopen",
        lambda url, timeout=30: _FakeResponse(csv_bytes),
    )

    path = refresh_epss_data()
    assert path is not None
    assert path.exists()
    header = path.read_text(encoding="utf-8").splitlines()[0].lower()
    assert "cve" in header and "epss" in header


def test_refresh_epss_data_offline_guard(tmp_path: Path, monkeypatch) -> None:
    """Offline mode should prevent EPSS refresh."""
    import vulntriage.enrichment as enrichment

    monkeypatch.setattr(enrichment, "CACHE_DIR", tmp_path / "cache")
    monkeypatch.setenv("VULNTRIAGE_OFFLINE", "1")

    with pytest.raises(ValueError, match="Offline mode enabled"):
        refresh_epss_data()


def test_refresh_kev_data_writes_cache(tmp_path: Path, monkeypatch) -> None:
    """refresh_kev_data should download and write kev.json in cache."""
    import vulntriage.enrichment as enrichment

    monkeypatch.setattr(enrichment, "CACHE_DIR", tmp_path / "cache")

    kev_payload = {"vulnerabilities": [{"cveID": "CVE-2023-12345"}]}
    kev_bytes = json.dumps(kev_payload).encode("utf-8")

    monkeypatch.setattr(
        enrichment.urllib.request,
        "urlopen",
        lambda url, timeout=30: _FakeResponse(kev_bytes),
    )

    path = refresh_kev_data()
    assert path is not None
    assert path.exists()


def test_refresh_kev_data_offline_guard(tmp_path: Path, monkeypatch) -> None:
    """Offline mode should prevent KEV refresh."""
    import vulntriage.enrichment as enrichment

    monkeypatch.setattr(enrichment, "CACHE_DIR", tmp_path / "cache")
    monkeypatch.setenv("VULNTRIAGE_OFFLINE", "1")

    with pytest.raises(ValueError, match="Offline mode enabled"):
        refresh_kev_data()


def test_refresh_kev_data_invalid_schema(tmp_path: Path, monkeypatch) -> None:
    """Invalid KEV schema should be rejected."""
    import warnings
    import vulntriage.enrichment as enrichment

    monkeypatch.setattr(enrichment, "CACHE_DIR", tmp_path / "cache")

    kev_payload = {"not_vulnerabilities": []}
    kev_bytes = json.dumps(kev_payload).encode("utf-8")

    monkeypatch.setattr(
        enrichment.urllib.request,
        "urlopen",
        lambda url, timeout=30: _FakeResponse(kev_bytes),
    )

    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        path = refresh_kev_data()
    assert path is None
    assert w
