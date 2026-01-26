"""Threat intelligence enrichment - EPSS and KEV data loading."""

from __future__ import annotations

import contextlib
import csv
import gzip
import json
import re
import shutil
import urllib.request
from datetime import datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .models import Vulnerability

# Cache directory for downloaded data
CACHE_DIR = Path.home() / ".cache" / "vulntriage"

# Data staleness thresholds
EPSS_TTL_DAYS = 3
KEV_TTL_DAYS = 7

# Data sources
EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# CVE ID normalization pattern
CVE_PATTERN = re.compile(r"(CVE)[- ]?(\d{4})[- ]?(\d+)", re.IGNORECASE)


def get_cache_dir() -> Path:
    """Get or create the cache directory.

    Returns CACHE_DIR if it can be created/accessed, otherwise the path
    (callers should check .exists()). Falls back to bundled data if cache
    isn't available.
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
    if not cache_dir.exists():
        return
    meta_file = cache_dir / "metadata.json"

    meta: dict[str, str] = {}
    if meta_file.exists():
        with contextlib.suppress(json.JSONDecodeError):
            meta = json.loads(meta_file.read_text(encoding="utf-8"))

    meta[f"{data_type}_updated"] = datetime.now().isoformat()
    meta_file.write_text(json.dumps(meta, indent=2), encoding="utf-8")


def is_data_stale(data_type: str, max_age_days: int) -> bool:
    """Check if cached data is stale."""
    last_updated = _get_last_updated(data_type)
    if last_updated is None:
        return True
    return datetime.now() - last_updated > timedelta(days=max_age_days)


def _warn_if_stale(data_type: str, max_age_days: int) -> None:
    """Warn if cached data is stale."""
    last_updated = _get_last_updated(data_type)
    if last_updated is None:
        import warnings
        warnings.warn(
            f"Cached {data_type.upper()} data has no timestamp; run --refresh to update.",
            stacklevel=2,
        )
        return

    age = datetime.now() - last_updated
    if age > timedelta(days=max_age_days):
        import warnings
        warnings.warn(
            f"Cached {data_type.upper()} data is {age.days} day(s) old "
            f"(last updated {last_updated.date()}). Run --refresh to update.",
            stacklevel=2,
        )


def _validate_epss_header_from_gzip(path: Path) -> None:
    """Validate EPSS CSV header inside a gzip file."""
    with gzip.open(path, "rt", encoding="utf-8") as f:
        header = f.readline().strip().lower()
    if "cve" not in header or "epss" not in header:
        raise ValueError("Invalid EPSS header in gzip file")


def _validate_epss_header_from_csv(path: Path) -> None:
    """Validate EPSS CSV header from a plain CSV file."""
    with path.open("r", encoding="utf-8") as f:
        header = f.readline().strip().lower()
    if "cve" not in header or "epss" not in header:
        raise ValueError("Invalid EPSS header in CSV file")


def _validate_kev_json(path: Path) -> None:
    """Validate KEV JSON schema minimal shape."""
    data = json.loads(path.read_text(encoding="utf-8"))
    if "vulnerabilities" not in data:
        raise ValueError("Invalid KEV JSON schema (missing vulnerabilities key)")


def _load_epss_from_path(path: Path) -> dict[str, float]:
    """Load EPSS data from a validated CSV or CSV.GZ path."""
    _validate_epss_header_from_gzip(path) if path.suffix == ".gz" else _validate_epss_header_from_csv(path)

    epss_data: dict[str, float] = {}

    if path.suffix == ".gz":
        with gzip.open(path, "rt", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                cve_raw = row.get("cve", "")
                epss_raw = row.get("epss", "")
                cve_id = normalize_cve_id(cve_raw)
                if cve_id and epss_raw:
                    with contextlib.suppress(ValueError):
                        epss_data[cve_id] = float(epss_raw)
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

    return epss_data


def _load_kev_from_path(path: Path) -> set[str]:
    """Load KEV data from a validated JSON path."""
    _validate_kev_json(path)

    kev_data: set[str] = set()
    data = json.loads(path.read_text(encoding="utf-8"))
    vulnerabilities = data.get("vulnerabilities", [])
    for vuln in vulnerabilities:
        cve_raw = vuln.get("cveID", "")
        cve_id = normalize_cve_id(cve_raw)
        if cve_id:
            kev_data.add(cve_id)

    return kev_data


def _download_to_temp(url: str, temp_path: Path) -> None:
    """Download a URL to a temporary path."""
    with urllib.request.urlopen(url, timeout=30) as response:
        if hasattr(response, "status") and response.status >= 400:
            raise ValueError(f"Download failed with status {response.status}")
        with temp_path.open("wb") as out:
            shutil.copyfileobj(response, out)


def refresh_epss_data(dest_path: Path | None = None, url: str = EPSS_URL) -> Path | None:
    """Download and refresh EPSS data into cache (atomic update)."""
    cache_dir = get_cache_dir()
    if not cache_dir.exists():
        import warnings
        warnings.warn("Cache directory unavailable; skipping EPSS refresh.", stacklevel=2)
        return None

    if dest_path is None:
        dest_path = cache_dir / "epss.csv"
    else:
        dest_path.parent.mkdir(parents=True, exist_ok=True)

    gz_temp = dest_path.with_suffix(dest_path.suffix + ".tmp.gz")
    csv_temp = dest_path.with_suffix(dest_path.suffix + ".tmp")

    try:
        _download_to_temp(url, gz_temp)
        _validate_epss_header_from_gzip(gz_temp)

        with gzip.open(gz_temp, "rt", encoding="utf-8") as src, csv_temp.open(
            "w", encoding="utf-8"
        ) as dst:
            shutil.copyfileobj(src, dst)

        _validate_epss_header_from_csv(csv_temp)
        csv_temp.replace(dest_path)
        _set_last_updated("epss")
        return dest_path
    except Exception as e:
        import warnings
        warnings.warn(f"Failed to refresh EPSS data: {e}", stacklevel=2)
        return None
    finally:
        with contextlib.suppress(OSError):
            if gz_temp.exists():
                gz_temp.unlink()
        with contextlib.suppress(OSError):
            if csv_temp.exists():
                csv_temp.unlink()


def refresh_kev_data(dest_path: Path | None = None, url: str = KEV_URL) -> Path | None:
    """Download and refresh KEV data into cache (atomic update)."""
    cache_dir = get_cache_dir()
    if not cache_dir.exists():
        import warnings
        warnings.warn("Cache directory unavailable; skipping KEV refresh.", stacklevel=2)
        return None

    if dest_path is None:
        dest_path = cache_dir / "kev.json"
    else:
        dest_path.parent.mkdir(parents=True, exist_ok=True)

    temp_path = dest_path.with_suffix(dest_path.suffix + ".tmp")

    try:
        _download_to_temp(url, temp_path)
        _validate_kev_json(temp_path)
        temp_path.replace(dest_path)
        _set_last_updated("kev")
        return dest_path
    except Exception as e:
        import warnings
        warnings.warn(f"Failed to refresh KEV data: {e}", stacklevel=2)
        return None
    finally:
        with contextlib.suppress(OSError):
            if temp_path.exists():
                temp_path.unlink()


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

    if custom_path is not None:
        if not custom_path.exists():
            import warnings
            warnings.warn(
                f"EPSS file not found at {custom_path}. Enrichment will be incomplete.",
                stacklevel=2,
            )
            return epss_data
        try:
            return _load_epss_from_path(custom_path)
        except Exception as e:
            import warnings
            warnings.warn(
                f"Failed to load EPSS data from {custom_path}: {e}",
                stacklevel=2,
            )
            return epss_data

    cache_path = get_cache_dir() / "epss.csv"
    if cache_path.exists():
        _warn_if_stale("epss", EPSS_TTL_DAYS)
        try:
            return _load_epss_from_path(cache_path)
        except Exception as e:
            import warnings
            warnings.warn(
                f"Failed to load cached EPSS data from {cache_path}: {e}",
                stacklevel=2,
            )

    bundled_path = _get_bundled_data_path("epss_sample.csv")
    if bundled_path is None:
        import warnings
        warnings.warn("No EPSS data available. Enrichment will be incomplete.", stacklevel=2)
        return epss_data

    try:
        return _load_epss_from_path(bundled_path)
    except Exception as e:
        import warnings
        warnings.warn(
            f"Failed to load bundled EPSS data from {bundled_path}: {e}",
            stacklevel=2,
        )
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

    if custom_path is not None:
        if not custom_path.exists():
            import warnings
            warnings.warn(
                f"KEV file not found at {custom_path}. Enrichment will be incomplete.",
                stacklevel=2,
            )
            return kev_data
        try:
            return _load_kev_from_path(custom_path)
        except Exception as e:
            import warnings
            warnings.warn(
                f"Failed to load KEV data from {custom_path}: {e}",
                stacklevel=2,
            )
            return kev_data

    cache_path = get_cache_dir() / "kev.json"
    if cache_path.exists():
        _warn_if_stale("kev", KEV_TTL_DAYS)
        try:
            return _load_kev_from_path(cache_path)
        except Exception as e:
            import warnings
            warnings.warn(
                f"Failed to load cached KEV data from {cache_path}: {e}",
                stacklevel=2,
            )

    bundled_path = _get_bundled_data_path("kev.json")
    if bundled_path is None:
        import warnings
        warnings.warn("No KEV data available. Enrichment will be incomplete.", stacklevel=2)
        return kev_data

    try:
        return _load_kev_from_path(bundled_path)
    except Exception as e:
        import warnings
        warnings.warn(
            f"Failed to load bundled KEV data from {bundled_path}: {e}",
            stacklevel=2,
        )
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
