"""CLI entry point for VulnTriage."""

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from vulntriage import __version__
from vulntriage.triage import triage
from vulntriage.models import ScanResult

app = typer.Typer(
    name="vulntriage",
    help="Democratizing reachability analysis for vulnerability triage.",
    no_args_is_help=True,
)
console = Console()


@app.command()
def scan(
    trivy_json: Annotated[
        Path,
        typer.Option(
            "--trivy-json",
            "-t",
            help="Path to Trivy JSON output file.",
            exists=True,
            readable=True,
        ),
    ],
    src: Annotated[
        Path,
        typer.Option(
            "--src",
            "-s",
            help="Path to source directory to analyze.",
            exists=True,
            file_okay=False,
            readable=True,
        ),
    ] = Path("."),
    include_tests: Annotated[
        bool,
        typer.Option(
            "--include-tests",
            help="Include test files in analysis.",
        ),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option(
            "--json",
            "-j",
            help="Output results as JSON.",
        ),
    ] = False,
) -> None:
    """Scan source code for reachable vulnerabilities.

    Analyzes the Trivy report against your source code to determine
    which vulnerabilities are actually reachable and exploitable.
    """
    if not json_output:
        console.print("[bold blue]VulnTriage[/] - Reachability Analysis")
        console.print(f"  Trivy report: [cyan]{trivy_json}[/]")
        console.print(f"  Source path:  [cyan]{src}[/]")
        console.print()

    # Run the triage pipeline
    results = triage(trivy_json, src, include_tests=include_tests)

    if not results:
        if json_output:
            console.print("[]")
        else:
            console.print("[green]✓ No vulnerabilities found in Trivy report.[/]")
        return

    if json_output:
        _output_json(results)
    else:
        _output_table(results)


def _output_json(results: list["ScanResult"]) -> None:
    """Output results as JSON."""
    output = []
    for r in results:
        output.append({
            "vuln_id": r.vulnerability.vuln_id,
            "pkg_name": r.vulnerability.pkg_name,
            "installed_version": r.vulnerability.installed_version,
            "fixed_version": r.vulnerability.fixed_version,
            "severity": r.vulnerability.severity,
            "status": r.status,
            "reason": r.reason,
            "evidence": [
                {
                    "file_path": e.file_path,
                    "line_start": e.line_start,
                    "line_end": e.line_end,
                    "symbol_name": e.symbol_name,
                }
                for e in r.evidence
            ] if r.evidence else [],
        })
    console.print_json(data=output)


def _output_table(results: list["ScanResult"]) -> None:
    """Output results as a rich table."""
    # Count by status
    status_counts = {"actionable": 0, "needs_review": 0, "dismissed": 0}
    for r in results:
        status_counts[r.status] = status_counts.get(r.status, 0) + 1

    # Summary
    console.print(f"[bold]Found {len(results)} vulnerabilities:[/]")
    console.print(f"  🔴 Actionable:   [red bold]{status_counts['actionable']}[/]")
    console.print(f"  🟡 Needs Review: [yellow]{status_counts['needs_review']}[/]")
    console.print(f"  🟢 Dismissed:    [green]{status_counts['dismissed']}[/]")
    console.print()

    # Build table
    table = Table(show_header=True, header_style="bold")
    table.add_column("Status", width=12)
    table.add_column("Severity", width=10)
    table.add_column("CVE", width=18)
    table.add_column("Package")
    table.add_column("Evidence")

    status_styles = {
        "actionable": "[red bold]ACTIONABLE[/]",
        "needs_review": "[yellow]REVIEW[/]",
        "dismissed": "[green dim]DISMISSED[/]",
    }

    severity_styles = {
        "CRITICAL": "[red bold]CRITICAL[/]",
        "HIGH": "[red]HIGH[/]",
        "MEDIUM": "[yellow]MEDIUM[/]",
        "LOW": "[blue]LOW[/]",
        "UNKNOWN": "[dim]UNKNOWN[/]",
    }

    for r in results:
        status_display = status_styles.get(r.status, r.status)
        severity_display = severity_styles.get(r.vulnerability.severity, r.vulnerability.severity)

        # Format evidence
        if r.evidence:
            evidence_str = f"{len(r.evidence)} call(s)"
        else:
            evidence_str = "-"

        table.add_row(
            status_display,
            severity_display,
            r.vulnerability.vuln_id,
            f"{r.vulnerability.pkg_name}@{r.vulnerability.installed_version}",
            evidence_str,
        )

    console.print(table)


@app.command()
def version() -> None:
    """Show version information."""
    console.print(f"vulntriage [bold]{__version__}[/]")


if __name__ == "__main__":
    app()
