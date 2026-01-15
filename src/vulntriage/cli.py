"""CLI entry point for VulnTriage."""

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from vulntriage import __version__

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
    ] = Path(),
) -> None:
    """Scan source code for reachable vulnerabilities.

    Analyzes the Trivy report against your source code to determine
    which vulnerabilities are actually reachable and exploitable.
    """
    console.print("[bold blue]VulnTriage[/] - Reachability Analysis")
    console.print(f"  Trivy report: [cyan]{trivy_json}[/]")
    console.print(f"  Source path:  [cyan]{src}[/]")
    console.print()

    # TODO: Implement the 3-stage pipeline
    # 1. Load Trivy JSON via trivy_adapter
    # 2. Build package map
    # 3. Scan source files with Tree-sitter
    # 4. Build symbol tables
    # 5. Run analyzer to find call sites
    # 6. Match against vulnerabilities
    # 7. AI triage for actionable candidates

    console.print("[yellow]⚠️  Scanner not yet implemented.[/]")


@app.command()
def version() -> None:
    """Show version information."""
    console.print(f"vulntriage [bold]{__version__}[/]")


if __name__ == "__main__":
    app()
