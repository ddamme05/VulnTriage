"""Threat intelligence enrichment - EPSS and KEV data loading."""

from __future__ import annotations

import contextlib
import csv
import gzip
import json
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .models import Vulnerability

# Cache directory for downloaded data
CACHE_DIR = Path.home() / ".cache" / "vulntriage"

# Data staleness threshold
MAX_DATA_AGE_DAYS = 7

# CVE ID normalization pattern
CVE_PATTERN = re.compile(r"(CVE)[- ]?(\d{4})[- ]?(\d+)", re.IGNORECASE)


def get_cache_dir() -> Path:
    """Get or create the cache directory.

    Returns CACHE_DIR if it can be created/accessed, otherwise None.
    Falls back to bundled data if cache isn't available.
    """
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        return CACHE_DIR
    except (OSError, PermissionError):
        # HOME not writable - will fall back to bundled data
        return CACHE_DIR  # Return path anyway, callers check .exists()


def normalize_cve_id(raw: str) -> str | None:
    """Normalize a CVE ID to standard format CVE-YYYY-NNNN.

    Handles variations like:
    - cve-2023-1234 → CVE-2023-1234
    - CVE20231234 → CVE-2023-1234
    - cve 2023 1234 → CVE-2023-1234

    Returns None if the string doesn't match CVE pattern.
    """
    match = CVE_PATTERN.search(raw)
    if not match:
        return None
    return f"CVE-{match.group(2)}-{match.group(3)}"


def _get_bundled_data_path(filename: str) -> Path | None:
    """Get path to bundled data using importlib.resources."""
    try:
        # Python 3.9+ compatible approach
        import importlib.resources as pkg_resources
        try:
            # Python 3.11+
            files = pkg_resources.files("vulntriage") / "data" / filename
            if hasattr(files, "is_file") and files.is_file():
                return Path(str(files))
        except (TypeError, AttributeError):
            pass

        # Fallback: check relative to this module
        module_dir = Path(__file__).parent
        bundled_path = module_dir / "data" / filename
        if bundled_path.exists():
            return bundled_path
    except Exception:
        pass
    return None


def _get_last_updated(data_type: str) -> datetime | None:
    """Get the last updated timestamp for a data file."""
    cache_dir = get_cache_dir()
    meta_file = cache_dir / "metadata.json"

    if not meta_file.exists():
        return None

    try:
        meta = json.loads(meta_file.read_text(encoding="utf-8"))
        timestamp_str = meta.get(f"{data_type}_updated")
        if timestamp_str:
            return datetime.fromisoformat(timestamp_str)
    except (json.JSONDecodeError, ValueError):
        pass
    return None


def _set_last_updated(data_type: str) -> None:
    """Set the last updated timestamp for a data file."""
    cache_dir = get_cache_dir()
    meta_file = cache_dir / "metadata.json"

    meta: dict[str, str] = {}
    if meta_file.exists():
        with contextlib.suppress(json.JSONDecodeError):
            meta = json.loads(meta_file.read_text(encoding="utf-8"))

    meta[f"{data_type}_updated"] = datetime.now().isoformat()
    meta_file.write_text(json.dumps(meta, indent=2), encoding="utf-8")


def is_data_stale(data_type: str, max_age_days: int = MAX_DATA_AGE_DAYS) -> bool:
    """Check if cached data is stale."""
    last_updated = _get_last_updated(data_type)
    if last_updated is None:
        return True
    return datetime.now() - last_updated > timedelta(days=max_age_days)


def load_epss_data(custom_path: Path | None = None) -> dict[str, float]:
    """Load EPSS data from CSV file.

    Data format: CSV with columns 'cve' and 'epss'
    Returns: dict mapping normalized CVE ID → EPSS score (0.0-1.0)

    Priority:
    1. Custom path if provided
    2. Cached data (~/.cache/vulntriage/epss.csv)
    3. Bundled data (fallback)
    """
    epss_data: dict[str, float] = {}

    # Determine which file to load
    path: Path | None = None

    if custom_path and custom_path.exists():
        path = custom_path
    else:
        cache_path = get_cache_dir() / "epss.csv"
        path = cache_path if cache_path.exists() else _get_bundled_data_path("epss_sample.csv")

    if path is None:
        import warnings
        warnings.warn("No EPSS data available. Enrichment will be incomplete.", stacklevel=2)
        return epss_data

    try:
        # Handle gzipped files
        if path.suffix == ".gz":
            with gzip.open(path, "rt", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    cve_raw = row.get("cve", "")
                    epss_raw = row.get("epss", "")
                    cve_id = normalize_cve_id(cve_raw)
                    if cve_id and epss_raw:
                        try:
                            epss_data[cve_id] = float(epss_raw)
                        except ValueError:
                            pass  # Skip invalid scores
        else:
            with path.open("r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    cve_raw = row.get("cve", "")
                    epss_raw = row.get("epss", "")
                    cve_id = normalize_cve_id(cve_raw)
                    if cve_id and epss_raw:
                        with contextlib.suppress(ValueError):
                            epss_data[cve_id] = float(epss_raw)
    except Exception as e:
        import warnings
        warnings.warn(f"Failed to load EPSS data from {path}: {e}", stacklevel=2)

    return epss_data


def load_kev_data(custom_path: Path | None = None) -> set[str]:
    """Load KEV (Known Exploited Vulnerabilities) data.

    Data format: JSON with 'vulnerabilities' array containing 'cveID' fields
    Returns: set of normalized CVE IDs

    Priority:
    1. Custom path if provided
    2. Cached data (~/.cache/vulntriage/kev.json)
    3. Bundled data (fallback)
    """
    kev_data: set[str] = set()

    # Determine which file to load
    path: Path | None = None

    if custom_path and custom_path.exists():
        path = custom_path
    else:
        cache_path = get_cache_dir() / "kev.json"
        path = cache_path if cache_path.exists() else _get_bundled_data_path("kev.json")

    if path is None:
        import warnings
        warnings.warn("No KEV data available. Enrichment will be incomplete.", stacklevel=2)
        return kev_data

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        vulnerabilities = data.get("vulnerabilities", [])
        for vuln in vulnerabilities:
            cve_raw = vuln.get("cveID", "")
            cve_id = normalize_cve_id(cve_raw)
            if cve_id:
                kev_data.add(cve_id)
    except Exception as e:
        import warnings
        warnings.warn(f"Failed to load KEV data from {path}: {e}", stacklevel=2)

    return kev_data


def enrich_vulnerability(
    vuln: Vulnerability,
    epss_data: dict[str, float],
    kev_data: set[str],
) -> Vulnerability:
    """Enrich a single vulnerability with EPSS and KEV data.

    Does not modify the original - returns a new instance.
    """
    cve_id = normalize_cve_id(vuln.vuln_id)

    epss_score = epss_data.get(cve_id) if cve_id else None
    is_kev = cve_id in kev_data if cve_id else False

    # Return new instance with enriched fields
    return vuln.model_copy(update={
        "epss_score": epss_score,
        "is_kev": is_kev,
    })


def enrich_vulnerabilities(
    vulnerabilities: list[Vulnerability],
    epss_path: Path | None = None,
    kev_path: Path | None = None,
) -> list[Vulnerability]:
    """Enrich a list of vulnerabilities with EPSS and KEV data.

    Args:
        vulnerabilities: List of vulnerabilities to enrich.
        epss_path: Optional custom EPSS data path.
        kev_path: Optional custom KEV data path.

    Returns:
        List of enriched vulnerabilities (new instances).
    """
    epss_data = load_epss_data(epss_path)
    kev_data = load_kev_data(kev_path)

    return [
        enrich_vulnerability(vuln, epss_data, kev_data)
        for vuln in vulnerabilities
    ]
