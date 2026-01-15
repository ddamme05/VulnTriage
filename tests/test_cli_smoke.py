"""Smoke tests for VulnTriage CLI."""

import subprocess


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
