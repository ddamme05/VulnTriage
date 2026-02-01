"""Tests for configuration loading."""

from pathlib import Path

from vulntriage.config import load_config


def test_load_config_none(tmp_path: Path) -> None:
    cfg = load_config(tmp_path)
    assert cfg.data == {}
    assert cfg.source is None
    assert cfg.path is None
    assert cfg.base_dir == tmp_path.resolve()


def test_load_config_pyproject(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """
[tool.vulntriage]
trivy_json = "trivy.json"
include_dev = true
""".strip(),
        encoding="utf-8",
    )

    cfg = load_config(tmp_path)
    assert cfg.source == "pyproject.toml"
    assert cfg.path == pyproject
    assert cfg.data["trivy_json"] == "trivy.json"
    assert cfg.data["include_dev"] is True


def test_load_config_dotfile_scan_table(tmp_path: Path) -> None:
    dotfile = tmp_path / ".vulntriage.toml"
    dotfile.write_text(
        """
[scan]
trivy-json = "report.json"
json = true
""".strip(),
        encoding="utf-8",
    )

    cfg = load_config(tmp_path)
    assert cfg.source == ".vulntriage.toml"
    assert cfg.path == dotfile
    assert cfg.data["trivy_json"] == "report.json"
    assert cfg.data["json_output"] is True


def test_load_config_conflict_prefers_pyproject(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """
[tool.vulntriage]
trivy_json = "a.json"
""".strip(),
        encoding="utf-8",
    )
    dotfile = tmp_path / ".vulntriage.toml"
    dotfile.write_text(
        """
trivy_json = "b.json"
""".strip(),
        encoding="utf-8",
    )

    cfg = load_config(tmp_path)
    assert cfg.source == "pyproject.toml"
    assert cfg.data["trivy_json"] == "a.json"
    assert cfg.warnings
