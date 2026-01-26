"""Tests for CVE function map loader and matching."""

import json
from pathlib import Path

import pytest

from vulntriage.cve_function_map import (
    get_vulnerable_functions,
    load_cve_function_map,
    matches_vulnerable_function,
)


# --- Loader Tests ---


def test_load_cve_function_map_valid(tmp_path: Path) -> None:
    """Load a valid CVE function map."""
    map_file = tmp_path / "cve_map.json"
    map_file.write_text(
        json.dumps({
            "CVE-2023-12345": ["yaml.load", "yaml.unsafe_load"],
            "cve-2022-9999": ["pkg.vulnerable_fn"],
        }),
        encoding="utf-8",
    )

    result = load_cve_function_map(map_file)

    assert len(result) == 2
    assert "CVE-2023-12345" in result
    assert "yaml.load" in result["CVE-2023-12345"]
    assert "yaml.unsafe_load" in result["CVE-2023-12345"]
    # Normalized CVE ID
    assert "CVE-2022-9999" in result
    assert "pkg.vulnerable_fn" in result["CVE-2022-9999"]


def test_load_cve_function_map_none_path() -> None:
    """None path returns empty map."""
    result = load_cve_function_map(None)
    assert result == {}


def test_load_cve_function_map_missing_file(tmp_path: Path) -> None:
    """Missing file returns empty map with warning."""
    with pytest.warns(UserWarning, match="not found"):
        result = load_cve_function_map(tmp_path / "nonexistent.json")
    assert result == {}


def test_load_cve_function_map_invalid_json(tmp_path: Path) -> None:
    """Invalid JSON returns empty map with warning."""
    map_file = tmp_path / "bad.json"
    map_file.write_text("not valid json", encoding="utf-8")

    with pytest.warns(UserWarning, match="Invalid JSON"):
        result = load_cve_function_map(map_file)
    assert result == {}


def test_load_cve_function_map_invalid_cve_id(tmp_path: Path) -> None:
    """Invalid CVE IDs are skipped with warning."""
    map_file = tmp_path / "cve_map.json"
    map_file.write_text(
        json.dumps({
            "CVE-2023-12345": ["valid.fn"],
            "not-a-cve": ["invalid.fn"],
        }),
        encoding="utf-8",
    )

    with pytest.warns(UserWarning, match="Invalid CVE ID"):
        result = load_cve_function_map(map_file)

    assert len(result) == 1
    assert "CVE-2023-12345" in result


def test_load_cve_function_map_invalid_functions_type(tmp_path: Path) -> None:
    """Non-list function values are skipped with warning."""
    map_file = tmp_path / "cve_map.json"
    map_file.write_text(
        json.dumps({
            "CVE-2023-12345": ["valid.fn"],
            "CVE-2023-99999": "not-a-list",
        }),
        encoding="utf-8",
    )

    with pytest.warns(UserWarning, match="expected list"):
        result = load_cve_function_map(map_file)

    assert len(result) == 1
    assert "CVE-2023-12345" in result


def test_load_cve_function_map_empty_list_ignored(tmp_path: Path) -> None:
    """Empty function lists are treated as 'no map for this CVE'."""
    map_file = tmp_path / "cve_map.json"
    map_file.write_text(
        json.dumps({
            "CVE-2023-12345": ["valid.fn"],
            "CVE-2023-99999": [],  # Empty list - should be ignored
        }),
        encoding="utf-8",
    )

    result = load_cve_function_map(map_file)

    assert len(result) == 1
    assert "CVE-2023-12345" in result
    assert "CVE-2023-99999" not in result


# --- get_vulnerable_functions Tests ---


def test_get_vulnerable_functions_found() -> None:
    """Get functions for a CVE in the map."""
    fn_map = {"CVE-2023-12345": {"yaml.load", "yaml.unsafe_load"}}
    result = get_vulnerable_functions("CVE-2023-12345", fn_map)
    assert result == {"yaml.load", "yaml.unsafe_load"}


def test_get_vulnerable_functions_not_found() -> None:
    """CVE not in map returns None."""
    fn_map = {"CVE-2023-12345": {"yaml.load"}}
    result = get_vulnerable_functions("CVE-2099-99999", fn_map)
    assert result is None


def test_get_vulnerable_functions_normalizes_cve() -> None:
    """CVE ID is normalized before lookup."""
    fn_map = {"CVE-2023-12345": {"yaml.load"}}
    # Lowercase input should still match
    result = get_vulnerable_functions("cve-2023-12345", fn_map)
    assert result == {"yaml.load"}


# --- matches_vulnerable_function Tests ---


def test_matches_exact() -> None:
    """Exact match works."""
    assert matches_vulnerable_function("yaml.load", {"yaml.load"})


def test_matches_suffix() -> None:
    """Suffix match works."""
    assert matches_vulnerable_function("pyyaml.yaml.load", {"yaml.load"})


def test_matches_simple_name() -> None:
    """Simple function name matches with dot boundary."""
    # This now requires dot boundary - "unsafe_load" alone won't match
    # Use the call symbol with dot prefix
    assert matches_vulnerable_function("yaml.unsafe_load", {"yaml.unsafe_load"})
    # Dot-boundary suffix still works
    assert matches_vulnerable_function("pyyaml.yaml.unsafe_load", {"yaml.unsafe_load"})


def test_no_match() -> None:
    """Non-matching function returns False."""
    assert not matches_vulnerable_function("yaml.safe_load", {"yaml.load", "yaml.unsafe_load"})


def test_no_match_partial() -> None:
    """Partial matches in the middle don't count."""
    assert not matches_vulnerable_function("yaml.load.wrapper", {"yaml.load"})


# --- Integration Tests with Triage Pipeline ---


def test_triage_with_function_map_match(tmp_path: Path) -> None:
    """Function map + matching call → actionable."""
    from vulntriage.triage import triage

    # Create Trivy report
    trivy_data = {
        "Results": [{
            "Target": "requirements.txt",
            "Vulnerabilities": [{
                "VulnerabilityID": "CVE-2023-12345",
                "PkgName": "pyyaml",
                "InstalledVersion": "5.4",
                "Severity": "CRITICAL",
            }],
        }],
    }
    trivy_json = tmp_path / "trivy.json"
    trivy_json.write_text(json.dumps(trivy_data), encoding="utf-8")

    # Create source with vulnerable function call
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "app.py").write_text(
        "import yaml\nyaml.unsafe_load(data)",
        encoding="utf-8",
    )

    # Create function map
    fn_map = tmp_path / "fn_map.json"
    fn_map.write_text(
        json.dumps({"CVE-2023-12345": ["yaml.load", "yaml.unsafe_load"]}),
        encoding="utf-8",
    )

    results = triage(trivy_json, src_dir, enrich=False, cve_function_map_file=fn_map)

    assert len(results) == 1
    assert results[0].status == "actionable"
    assert "vulnerable function" in results[0].reason


def test_triage_with_function_map_no_match(tmp_path: Path) -> None:
    """Function map + call not matching vulnerable functions → needs_review."""
    from vulntriage.triage import triage

    # Create Trivy report
    trivy_data = {
        "Results": [{
            "Target": "requirements.txt",
            "Vulnerabilities": [{
                "VulnerabilityID": "CVE-2023-12345",
                "PkgName": "pyyaml",
                "InstalledVersion": "5.4",
                "Severity": "CRITICAL",
            }],
        }],
    }
    trivy_json = tmp_path / "trivy.json"
    trivy_json.write_text(json.dumps(trivy_data), encoding="utf-8")

    # Create source with safe function call (not in function map)
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "app.py").write_text(
        "import yaml\nyaml.safe_load(data)",
        encoding="utf-8",
    )

    # Create function map (only unsafe functions)
    fn_map = tmp_path / "fn_map.json"
    fn_map.write_text(
        json.dumps({"CVE-2023-12345": ["yaml.load", "yaml.unsafe_load"]}),
        encoding="utf-8",
    )

    results = triage(trivy_json, src_dir, enrich=False, cve_function_map_file=fn_map)

    assert len(results) == 1
    assert results[0].status == "needs_review"
    assert "not via known vulnerable functions" in results[0].reason


def test_triage_without_function_map_unchanged(tmp_path: Path) -> None:
    """No function map → original behavior (call = actionable)."""
    from vulntriage.triage import triage

    # Create Trivy report
    trivy_data = {
        "Results": [{
            "Target": "requirements.txt",
            "Vulnerabilities": [{
                "VulnerabilityID": "CVE-2023-12345",
                "PkgName": "pyyaml",
                "InstalledVersion": "5.4",
                "Severity": "CRITICAL",
            }],
        }],
    }
    trivy_json = tmp_path / "trivy.json"
    trivy_json.write_text(json.dumps(trivy_data), encoding="utf-8")

    # Create source with safe function call
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "app.py").write_text(
        "import yaml\nyaml.safe_load(data)",
        encoding="utf-8",
    )

    # No function map - original behavior
    results = triage(trivy_json, src_dir, enrich=False, cve_function_map_file=None)

    assert len(results) == 1
    # Without function map, any call is actionable
    assert results[0].status == "actionable"
