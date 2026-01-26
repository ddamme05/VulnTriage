"""CycloneDX VEX export utilities."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .models import ScanResult

BOM_FORMAT = "CycloneDX"
SPEC_VERSION = "1.5"
TOOL_VENDOR = "VulnTriage"
TOOL_NAME = "vulntriage"

_PURL_NORMALIZE_RE = re.compile(r"[-_.]+")


def _normalize_pypi_name(name: str) -> str:
    """Normalize a PyPI name for purl usage."""
    return _PURL_NORMALIZE_RE.sub("-", name.lower())


def _purl_for(name: str, version: str | None) -> str:
    """Build a purl for a PyPI package."""
    normalized = _normalize_pypi_name(name)
    if version:
        return f"pkg:pypi/{normalized}@{version}"
    return f"pkg:pypi/{normalized}"


def build_vex(results: list[ScanResult]) -> dict:
    """Build a CycloneDX VEX JSON document from scan results."""
    components: dict[str, dict] = {}
    vulnerabilities: list[dict] = []
    seen: set[tuple[str, str]] = set()

    for result in results:
        vuln = result.vulnerability
        purl = _purl_for(vuln.pkg_name, vuln.installed_version)

        if purl not in components:
            components[purl] = {
                "type": "library",
                "name": vuln.pkg_name,
                "version": vuln.installed_version,
                "purl": purl,
                "bom-ref": purl,
            }

        if result.status == "actionable":
            state = "exploitable"
        elif result.status == "needs_review":
            state = "in_triage"
        else:
            state = "not_affected"

        detail = f"{result.reason} (evidence: {len(result.evidence)})"
        analysis: dict[str, str] = {
            "state": state,
            "detail": detail,
        }
        if result.status == "dismissed":
            analysis["justification"] = "code_not_present"

        key = (vuln.vuln_id, purl)
        if key in seen:
            continue
        seen.add(key)

        vulnerabilities.append({
            "id": vuln.vuln_id,
            "analysis": analysis,
            "affects": [{"ref": purl}],
        })

    return {
        "bomFormat": BOM_FORMAT,
        "specVersion": SPEC_VERSION,
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "tools": [
                {
                    "vendor": TOOL_VENDOR,
                    "name": TOOL_NAME,
                    "version": __version__,
                }
            ],
        },
        "components": list(components.values()),
        "vulnerabilities": vulnerabilities,
    }


def write_vex(results: list[ScanResult], path: Path) -> None:
    """Write CycloneDX VEX JSON to disk."""
    path.parent.mkdir(parents=True, exist_ok=True)
    data = build_vex(results)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
