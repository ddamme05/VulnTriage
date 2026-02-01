"""Configuration loading for VulnTriage."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import tomllib


@dataclass(frozen=True)
class ConfigLoad:
    """Resolved configuration with source metadata."""

    data: dict[str, Any]
    source: str | None
    path: Path | None
    base_dir: Path
    warnings: list[str]


def load_config(start: Path) -> ConfigLoad:
    """Load config from pyproject.toml or .vulntriage.toml (if present)."""
    start = start.resolve()
    pyproject = _find_upwards(start, "pyproject.toml")
    dotfile = _find_upwards(start, ".vulntriage.toml")

    py_data = _read_pyproject(pyproject) if pyproject else {}
    dot_data = _read_dotfile(dotfile) if dotfile else {}

    warnings: list[str] = []
    if py_data and dot_data:
        conflicts = {
            key
            for key in py_data.keys() & dot_data.keys()
            if py_data[key] != dot_data[key]
        }
        if conflicts:
            conflict_list = ", ".join(sorted(conflicts))
            warnings.append(
                "Config conflict between pyproject.toml and .vulntriage.toml "
                f"for keys: {conflict_list}. Using pyproject.toml."
            )

    if py_data:
        return ConfigLoad(
            data=py_data,
            source="pyproject.toml",
            path=pyproject,
            base_dir=pyproject.parent if pyproject else start,
            warnings=warnings,
        )
    if dot_data:
        return ConfigLoad(
            data=dot_data,
            source=".vulntriage.toml",
            path=dotfile,
            base_dir=dotfile.parent if dotfile else start,
            warnings=warnings,
        )

    return ConfigLoad(data={}, source=None, path=None, base_dir=start, warnings=warnings)


def _find_upwards(start: Path, filename: str) -> Path | None:
    """Find a file by walking up the directory tree."""
    for parent in (start, *start.parents):
        candidate = parent / filename
        if candidate.is_file():
            return candidate
    return None


def _read_pyproject(path: Path) -> dict[str, Any]:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    tool = data.get("tool", {})
    cfg = tool.get("vulntriage", {}) if isinstance(tool, dict) else {}
    return _normalize_config(cfg) if isinstance(cfg, dict) else {}


def _read_dotfile(path: Path) -> dict[str, Any]:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    if isinstance(data.get("scan"), dict):
        data = data["scan"]
    return _normalize_config(data) if isinstance(data, dict) else {}


def _normalize_config(cfg: dict[str, Any]) -> dict[str, Any]:
    normalized: dict[str, Any] = {}
    for key, value in cfg.items():
        if not isinstance(key, str):
            continue
        norm = key.strip().lower().replace("-", "_")
        if norm == "json":
            norm = "json_output"
        normalized[norm] = value
    return normalized
