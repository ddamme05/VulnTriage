"""Tests for OpenVEX export."""

import json
from pathlib import Path

from vulntriage.models import ScanResult, Vulnerability
from vulntriage.openvex import build_openvex, write_openvex


def _make_vuln(vuln_id: str, pkg: str, version: str, severity: str) -> Vulnerability:
    return Vulnerability(
        vuln_id=vuln_id,
        pkg_name=pkg,
        installed_version=version,
        severity=severity,
    )


def test_build_openvex_status_mapping() -> None:
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

    vex = build_openvex(results)

    assert vex["@context"].startswith("https://openvex.dev/")
    assert vex["version"] == 1
    assert "statements" in vex

    by_id = {s["vulnerability"]["name"]: s for s in vex["statements"]}
    assert by_id["CVE-2023-0001"]["status"] == "affected"
    assert by_id["CVE-2023-0002"]["status"] == "under_investigation"
    assert by_id["CVE-2023-0003"]["status"] == "not_affected"
    assert by_id["CVE-2023-0003"]["justification"] == "vulnerable_code_not_present"


def test_write_openvex(tmp_path: Path) -> None:
    results = [
        ScanResult(
            vulnerability=_make_vuln("CVE-2023-0001", "requests", "2.28.0", "HIGH"),
            status="actionable",
            reason="call found",
            evidence=[],
        )
    ]

    output_path = tmp_path / "out.openvex.json"
    write_openvex(results, output_path)

    data = json.loads(output_path.read_text(encoding="utf-8"))
    assert data["@context"].startswith("https://openvex.dev/")
    assert data["version"] == 1
    assert len(data["statements"]) == 1


def test_build_openvex_dedupes_same_cve_component() -> None:
    vuln = _make_vuln("CVE-2023-0001", "requests", "2.28.0", "HIGH")
    results = [
        ScanResult(vulnerability=vuln, status="actionable", reason="call found", evidence=[]),
        ScanResult(vulnerability=vuln, status="actionable", reason="call found", evidence=[]),
    ]

    vex = build_openvex(results)
    assert len(vex["statements"]) == 1
