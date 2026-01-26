"""Tests for CycloneDX VEX export."""

import json
from pathlib import Path

import pytest

from vulntriage.models import ScanResult, Vulnerability
from vulntriage.vex import build_vex, write_vex


def _purl(name: str, version: str) -> str:
    normalized = name.lower().replace("_", "-").replace(".", "-")
    normalized = "-".join(part for part in normalized.split("-") if part)
    return f"pkg:pypi/{normalized}@{version}"


def _make_vuln(vuln_id: str, pkg: str, version: str, severity: str) -> Vulnerability:
    return Vulnerability(
        vuln_id=vuln_id,
        pkg_name=pkg,
        installed_version=version,
        severity=severity,
    )


def test_build_vex_status_mapping() -> None:
    """VEX maps statuses to correct analysis.state values."""
    results = [
        ScanResult(
            vulnerability=_make_vuln("CVE-2023-0001", "requests", "2.28.0", "HIGH"),
            status="actionable",
            reason="call found",
            evidence=[],
        ),
        ScanResult(
            vulnerability=_make_vuln("CVE-2023-0002", "flask", "2.0.0", "MEDIUM"),
            status="needs_review",
            reason="import only",
            evidence=[],
        ),
        ScanResult(
            vulnerability=_make_vuln("CVE-2023-0003", "flask", "2.0.0", "LOW"),
            status="dismissed",
            reason="not imported",
            evidence=[],
        ),
    ]

    vex = build_vex(results)

    assert vex["bomFormat"] == "CycloneDX"
    assert vex["specVersion"] == "1.5"
    assert vex["version"] == 1

    # Components are deduped by purl
    assert len(vex["components"]) == 2

    by_id = {v["id"]: v for v in vex["vulnerabilities"]}
    assert by_id["CVE-2023-0001"]["analysis"]["state"] == "exploitable"
    assert by_id["CVE-2023-0002"]["analysis"]["state"] == "in_triage"
    assert by_id["CVE-2023-0003"]["analysis"]["state"] == "not_affected"
    assert by_id["CVE-2023-0003"]["analysis"]["justification"] == "code_not_present"

    flask_ref = _purl("flask", "2.0.0")
    assert by_id["CVE-2023-0002"]["affects"][0]["ref"] == flask_ref


def test_write_vex_validates(tmp_path: Path) -> None:
    """VEX output validates against CycloneDX schema."""
    results = [
        ScanResult(
            vulnerability=_make_vuln("CVE-2023-0001", "requests", "2.28.0", "HIGH"),
            status="actionable",
            reason="call found",
            evidence=[],
        )
    ]

    output_path = tmp_path / "out.vex.json"
    write_vex(results, output_path)

    data = json.loads(output_path.read_text(encoding="utf-8"))
    assert data["bomFormat"] == "CycloneDX"
    assert data["specVersion"] == "1.5"

    validator_mod = pytest.importorskip("cyclonedx.validation.json")
    schema_mod = pytest.importorskip("cyclonedx.schema")

    validator = validator_mod.JsonValidator(schema_mod.SchemaVersion.V1_5)
    validation_error = validator.validate_str(output_path.read_text(encoding="utf-8"))
    assert validation_error is None


def test_build_vex_dedupes_same_cve_component() -> None:
    """Duplicate CVE+package pairs should be emitted once."""
    vuln = _make_vuln("CVE-2023-0001", "requests", "2.28.0", "HIGH")
    results = [
        ScanResult(vulnerability=vuln, status="actionable", reason="call found", evidence=[]),
        ScanResult(vulnerability=vuln, status="actionable", reason="call found", evidence=[]),
    ]

    vex = build_vex(results)
    assert len(vex["vulnerabilities"]) == 1
