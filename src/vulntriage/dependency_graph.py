"""Dependency graph utilities for direct vs transitive proximity detection."""

from __future__ import annotations

import json
import re
import tomllib
import warnings
from dataclasses import dataclass
from pathlib import Path

from .package_map import canonicalize_package_name

_LOCKFILE_PRECEDENCE = (
    "poetry.lock",
    "Pipfile.lock",
    "uv.lock",
    "requirements.txt",
)

_REQ_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*")


@dataclass
class DependencyGraph:
    """Dependency graph with direct roots and parent/child edges."""

    direct: set[str]
    edges: dict[str, set[str]]  # parent -> children
    reverse_edges: dict[str, set[str]]  # child -> parents
    all_packages: set[str]

    def proximity(self, pkg: str) -> str | None:
        if pkg in self.direct:
            return "direct"
        if pkg in self.all_packages:
            return "transitive"
        return None

    def get_parents(self, pkg: str) -> set[str]:
        return self.reverse_edges.get(pkg, set())


def discover_lockfile(root: Path) -> Path | None:
    """Discover a lockfile in the repository root using precedence."""
    if root.is_file():
        root = root.parent
    for name in _LOCKFILE_PRECEDENCE:
        candidate = root / name
        if candidate.is_file():
            return candidate
    return None


def build_dependency_graph(
    root: Path,
    lockfile: Path | None = None,
    include_dev: bool = False,
) -> DependencyGraph | None:
    """Build a dependency graph from a supported lockfile."""
    lockfile_path = lockfile or discover_lockfile(root)
    if lockfile_path is None:
        return None

    name = lockfile_path.name
    if name == "requirements.txt":
        return _graph_from_requirements(lockfile_path)
    if name == "poetry.lock":
        return _graph_from_poetry(lockfile_path, include_dev)
    if name == "Pipfile.lock":
        return _graph_from_pipfile(lockfile_path, include_dev)
    if name == "uv.lock":
        return _graph_from_uv_lock(lockfile_path, include_dev)

    warnings.warn(
        f"Unsupported lockfile type: {lockfile_path}. Proximity disabled.",
        stacklevel=2,
    )
    return None


def _graph_from_requirements(path: Path) -> DependencyGraph:
    direct: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        name = _parse_requirement_name(line)
        if name:
            direct.add(canonicalize_package_name(name))
    # requirements.txt does not provide a dependency graph
    edges = {pkg: set() for pkg in direct}
    return _build_graph(direct, edges)


def _graph_from_poetry(path: Path, include_dev: bool) -> DependencyGraph:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    packages = data.get("package", [])

    edges: dict[str, set[str]] = {}
    for pkg in packages:
        name_raw = pkg.get("name")
        if not name_raw:
            continue
        name = canonicalize_package_name(str(name_raw))
        deps = _parse_dependency_block(pkg.get("dependencies"))
        edges[name] = deps

    pyproject = _find_pyproject(path.parent)
    if not pyproject:
        warnings.warn(
            "pyproject.toml not found for poetry.lock; treating all as transitive.",
            stacklevel=2,
        )
        direct = set()
    else:
        direct = _poetry_direct_deps(pyproject, include_dev)

    return _build_graph(direct, edges)


def _graph_from_pipfile(path: Path, include_dev: bool) -> DependencyGraph:
    data = json.loads(path.read_text(encoding="utf-8"))
    default_pkgs = data.get("default", {})
    develop_pkgs = data.get("develop", {})

    edges: dict[str, set[str]] = {}
    all_names = set(default_pkgs.keys())
    if include_dev:
        all_names.update(develop_pkgs.keys())

    for pkg_name in all_names:
        info = default_pkgs.get(pkg_name) or develop_pkgs.get(pkg_name) or {}
        # Pipfile.lock typically does not embed transitive dependencies per package.
        deps = _parse_dependency_block(info.get("dependencies"))
        edges[canonicalize_package_name(pkg_name)] = deps

    pipfile = _find_pipfile(path.parent)
    if not pipfile:
        warnings.warn(
            "Pipfile not found for Pipfile.lock; using lockfile packages as direct.",
            stacklevel=2,
        )
        direct = {canonicalize_package_name(name) for name in default_pkgs.keys()}
        if include_dev:
            direct.update(canonicalize_package_name(name) for name in develop_pkgs.keys())
    else:
        direct = _pipfile_direct_deps(pipfile, include_dev)

    return _build_graph(direct, edges)


def _graph_from_uv_lock(path: Path, include_dev: bool) -> DependencyGraph:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    packages = data.get("package", [])

    edges: dict[str, set[str]] = {}
    for pkg in packages:
        name_raw = pkg.get("name")
        if not name_raw:
            continue
        name = canonicalize_package_name(str(name_raw))
        deps = _parse_dependency_block(pkg.get("dependencies"))
        edges[name] = deps

    pyproject = _find_pyproject(path.parent)
    if not pyproject:
        warnings.warn(
            "pyproject.toml not found for uv.lock; treating all as transitive.",
            stacklevel=2,
        )
        direct = set()
    else:
        direct = _pep621_direct_deps(pyproject, include_dev)

    return _build_graph(direct, edges)


def _build_graph(direct: set[str], edges: dict[str, set[str]]) -> DependencyGraph:
    reverse: dict[str, set[str]] = {}
    all_packages = set(direct)
    for parent, children in edges.items():
        all_packages.add(parent)
        for child in children:
            all_packages.add(child)
            reverse.setdefault(child, set()).add(parent)

    return DependencyGraph(
        direct=direct,
        edges=edges,
        reverse_edges=reverse,
        all_packages=all_packages,
    )


def _parse_dependency_block(value: object) -> set[str]:
    deps: set[str] = set()
    if isinstance(value, dict):
        for name in value.keys():
            deps.add(canonicalize_package_name(str(name)))
    elif isinstance(value, list):
        for entry in value:
            if isinstance(entry, str):
                name = _parse_requirement_name(entry)
                if name:
                    deps.add(canonicalize_package_name(name))
    return deps


def _parse_requirement_name(line: str) -> str | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    # Drop inline comments
    stripped = stripped.split("#", 1)[0].strip()
    if not stripped:
        return None
    # Skip common pip options
    if stripped.startswith(("-", "--")):
        return None
    # Remove environment markers
    stripped = stripped.split(";", 1)[0].strip()
    if not stripped:
        return None
    # Handle direct URL format: name @ url
    if "@" in stripped:
        left = stripped.split("@", 1)[0].strip()
        if left:
            stripped = left
    # Drop extras and version specifiers
    stripped = stripped.split("[", 1)[0].strip()
    match = _REQ_NAME_RE.match(stripped)
    if not match:
        return None
    return match.group(0)


def _find_pyproject(root: Path) -> Path | None:
    return _find_upwards(root, "pyproject.toml")


def _find_pipfile(root: Path) -> Path | None:
    return _find_upwards(root, "Pipfile")


def _find_upwards(root: Path, filename: str) -> Path | None:
    if root.is_file():
        root = root.parent
    for path in [root, *root.parents]:
        candidate = path / filename
        if candidate.is_file():
            return candidate
    return None


def _poetry_direct_deps(pyproject: Path, include_dev: bool) -> set[str]:
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {}) or {}
    direct = {
        canonicalize_package_name(name)
        for name in deps.keys()
        if str(name).lower() != "python"
    }
    if include_dev:
        dev_deps = data.get("tool", {}).get("poetry", {}).get("dev-dependencies", {}) or {}
        group_dev = (
            data.get("tool", {})
            .get("poetry", {})
            .get("group", {})
            .get("dev", {})
            .get("dependencies", {})
            or {}
        )
        for name in {*dev_deps.keys(), *group_dev.keys()}:
            direct.add(canonicalize_package_name(name))
    return direct


def _pep621_direct_deps(pyproject: Path, include_dev: bool) -> set[str]:
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    deps = data.get("project", {}).get("dependencies", []) or []
    direct = set()
    for dep in deps:
        if isinstance(dep, str):
            name = _parse_requirement_name(dep)
            if name:
                direct.add(canonicalize_package_name(name))
    if include_dev:
        optional = data.get("project", {}).get("optional-dependencies", {}) or {}
        dev_group = optional.get("dev", []) or []
        for dep in dev_group:
            if isinstance(dep, str):
                name = _parse_requirement_name(dep)
                if name:
                    direct.add(canonicalize_package_name(name))
        dependency_groups = data.get("dependency-groups", {}) or {}
        for group_deps in dependency_groups.values():
            if not isinstance(group_deps, list):
                continue
            for dep in group_deps:
                if isinstance(dep, str):
                    name = _parse_requirement_name(dep)
                    if name:
                        direct.add(canonicalize_package_name(name))
    return direct


def _pipfile_direct_deps(pipfile: Path, include_dev: bool) -> set[str]:
    data = tomllib.loads(pipfile.read_text(encoding="utf-8"))
    packages = data.get("packages", {}) or {}
    direct = {canonicalize_package_name(name) for name in packages.keys()}
    if include_dev:
        dev_packages = data.get("dev-packages", {}) or {}
        for name in dev_packages.keys():
            direct.add(canonicalize_package_name(name))
    return direct
