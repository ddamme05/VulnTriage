"""Smoke tests for VulnTriage CLI."""

import json
import subprocess
from pathlib import Path


def test_cli_help() -> None:
    """Test that the CLI --help command works."""
    result = subprocess.run(
        ["uv", "run", "vulntriage", "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert "vulntriage" in result.stdout.lower()
    assert "scan" in result.stdout


def test_cli_version() -> None:
    """Test that the version command works."""
    result = subprocess.run(
        ["uv", "run", "vulntriage", "version"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert "0.1.0" in result.stdout


def test_scan_help() -> None:
    """Test that scan --help works."""
    result = subprocess.run(
        ["uv", "run", "vulntriage", "scan", "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert "--trivy-json" in result.stdout
    assert "--src" in result.stdout


def test_scan_output_vex(tmp_path: Path) -> None:
    """Scan command writes a VEX file when requested."""
    trivy_json = {
        "SchemaVersion": 2,
        "Results": [
            {
                "Target": "requirements.txt",
                "Type": "pip",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2023-00001",
                        "PkgName": "requests",
                        "InstalledVersion": "2.28.0",
                        "Severity": "HIGH",
                    }
                ],
            }
        ],
    }

    trivy_path = tmp_path / "trivy.json"
    trivy_path.write_text(json.dumps(trivy_json), encoding="utf-8")

    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "app.py").write_text(
        "import requests\nrequests.get('https://example.com')\n",
        encoding="utf-8",
    )

    vex_path = tmp_path / "out.vex.json"

    result = subprocess.run(
        [
            "uv",
            "run",
            "vulntriage",
            "scan",
            "--trivy-json",
            str(trivy_path),
            "--src",
            str(src_dir),
            "--output-vex",
            str(vex_path),
            "--json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert vex_path.exists()
    assert "CycloneDX" in vex_path.read_text(encoding="utf-8")
