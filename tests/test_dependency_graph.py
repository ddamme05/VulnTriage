"""Tests for dependency graph proximity detection."""

from pathlib import Path

from vulntriage.dependency_graph import DependencyGraph, build_dependency_graph
from vulntriage.matcher import FileAnalysis, match_vulnerabilities
from vulntriage.models import Vulnerability
from vulntriage.symbol_table import ImportedSymbol, SymbolTable


def test_poetry_include_dev_controls_direct_deps(tmp_path: Path) -> None:
    """Poetry dev dependencies are included only with --include-dev."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """
[tool.poetry]
name = "demo"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.12"
requests = "^2.31.0"

[tool.poetry.dev-dependencies]
pytest = "^8.0.0"
""",
        encoding="utf-8",
    )

    poetry_lock = tmp_path / "poetry.lock"
    poetry_lock.write_text(
        """
[[package]]
name = "requests"
version = "2.31.0"
dependencies = { certifi = ">=2023.7.0" }

[[package]]
name = "pytest"
version = "8.0.0"
""",
        encoding="utf-8",
    )

    graph_no_dev = build_dependency_graph(tmp_path, lockfile=poetry_lock, include_dev=False)
    assert graph_no_dev is not None
    assert "requests" in graph_no_dev.direct
    assert "pytest" not in graph_no_dev.direct

    graph_with_dev = build_dependency_graph(tmp_path, lockfile=poetry_lock, include_dev=True)
    assert graph_with_dev is not None
    assert "pytest" in graph_with_dev.direct


def test_requirements_txt_all_direct(tmp_path: Path) -> None:
    """All packages in requirements.txt are treated as direct."""
    reqs = tmp_path / "requirements.txt"
    reqs.write_text(
        """
# comment
requests==2.31.0
flask>=2.0
-r other.txt
demo-pkg @ git+https://example.com/repo.git#egg=demo-pkg
demo-pkg[extra]==1.2.3
""",
        encoding="utf-8",
    )

    graph = build_dependency_graph(tmp_path, lockfile=reqs, include_dev=False)
    assert graph is not None
    assert {"requests", "flask", "demo_pkg"} <= graph.direct


def test_transitive_diamond_keeps_needs_review_when_parent_imported(tmp_path: Path) -> None:
    """Diamond graph: if any parent is imported, transitive stays needs_review."""
    graph = DependencyGraph(
        direct={"a", "b"},
        edges={"a": {"c"}, "b": {"c"}},
        reverse_edges={"c": {"a", "b"}},
        all_packages={"a", "b", "c"},
    )

    symbol_table = SymbolTable(
        file_path=tmp_path / "main.py",
        imports=[ImportedSymbol(module="b", name=None, alias="b", line=1)],
    )
    analysis_map = {
        symbol_table.file_path: FileAnalysis(
            file_path=symbol_table.file_path,
            symbol_table=symbol_table,
            call_sites=[],
        )
    }

    package_to_modules = {"a": ["a"], "b": ["b"], "c": ["c"]}
    vuln = Vulnerability(
        vuln_id="CVE-0000-0001",
        pkg_name="c",
        installed_version="1.0.0",
        severity="HIGH",
    )
    vuln.proximity = "transitive"

    results = match_vulnerabilities(
        [vuln],
        analysis_map,
        package_to_modules,
        dependency_graph=graph,
    )
    assert results[0].status == "needs_review"


def test_transitive_dismissed_when_all_parents_unimported(tmp_path: Path) -> None:
    """Transitive can be dismissed when all parent paths are dismissed."""
    graph = DependencyGraph(
        direct={"a", "b"},
        edges={"a": {"c"}, "b": {"c"}},
        reverse_edges={"c": {"a", "b"}},
        all_packages={"a", "b", "c"},
    )

    symbol_table = SymbolTable(file_path=tmp_path / "main.py")
    analysis_map = {
        symbol_table.file_path: FileAnalysis(
            file_path=symbol_table.file_path,
            symbol_table=symbol_table,
            call_sites=[],
        )
    }

    package_to_modules = {"a": ["a"], "b": ["b"], "c": ["c"]}
    vuln = Vulnerability(
        vuln_id="CVE-0000-0002",
        pkg_name="c",
        installed_version="1.0.0",
        severity="HIGH",
    )
    vuln.proximity = "transitive"

    results = match_vulnerabilities(
        [vuln],
        analysis_map,
        package_to_modules,
        dependency_graph=graph,
    )
    assert results[0].status == "dismissed"
