"""OpenVEX export utilities."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .models import ScanResult

CONTEXT = "https://openvex.dev/ns/v0.2.0"
AUTHOR = "VulnTriage"
TOOLING = "vulntriage"

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


def build_openvex(results: list[ScanResult]) -> dict[str, object]:
    """Build an OpenVEX JSON document from scan results."""
    statements: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()
    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    for result in results:
        vuln = result.vulnerability
        purl = _purl_for(vuln.pkg_name, vuln.installed_version)

        key = (vuln.vuln_id, purl)
        if key in seen:
            continue
        seen.add(key)

        if result.status == "actionable":
            status = "affected"
        elif result.status == "needs_review":
            status = "under_investigation"
        else:
            status = "not_affected"

        statement: dict[str, object] = {
            "vulnerability": {"name": vuln.vuln_id},
            "products": [{"@id": purl}],
            "status": status,
            "timestamp": timestamp,
        }

        if status == "affected":
            statement["action_statement"] = (
                f"VulnTriage detected usage evidence in code. {result.reason}"
            )
        elif status == "not_affected":
            statement["justification"] = "vulnerable_code_not_present"

        statements.append(statement)

    return {
        "@context": CONTEXT,
        "author": AUTHOR,
        "timestamp": timestamp,
        "version": 1,
        "tooling": f"{TOOLING}@{__version__}",
        "statements": statements,
    }


def write_openvex(results: list[ScanResult], path: Path) -> None:
    """Write OpenVEX JSON to disk."""
    path.parent.mkdir(parents=True, exist_ok=True)
    data = build_openvex(results)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
