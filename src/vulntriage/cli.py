"""CLI entry point for VulnTriage."""

import os
from pathlib import Path
from typing import TYPE_CHECKING, Annotated

import typer
from rich.console import Console
from rich.table import Table

from vulntriage import __version__
from vulntriage.ai_analyst import AIConfig
from vulntriage.enrichment import refresh_epss_data, refresh_kev_data
from vulntriage.triage import triage
from vulntriage.vex import write_vex
from vulntriage.openvex import write_openvex

if TYPE_CHECKING:
    from vulntriage.models import ScanResult

app = typer.Typer(
    name="vulntriage",
    help="Democratizing reachability analysis for vulnerability triage.",
    no_args_is_help=True,
)
console = Console()


def _env_bool(name: str) -> bool:
    """Parse a boolean environment variable."""
    return os.getenv(name, "").strip().lower() in {"1", "true", "yes", "on"}


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
    include_tests: Annotated[
        bool,
        typer.Option(
            "--include-tests",
            help="Include test files in analysis.",
        ),
    ] = False,
    include_dev: Annotated[
        bool,
        typer.Option(
            "--include-dev",
            help="Include dev/optional dependency groups when determining proximity.",
        ),
    ] = False,
    proximity: Annotated[
        bool,
        typer.Option(
            "--proximity/--no-proximity",
            help="Enable direct/transitive dependency detection when lockfiles exist.",
        ),
    ] = True,
    lockfile: Annotated[
        Path | None,
        typer.Option(
            "--lockfile",
            help="Path to lockfile for dependency proximity detection.",
            exists=True,
            dir_okay=False,
            readable=True,
        ),
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option(
            "--json",
            "-j",
            help="Output results as JSON.",
        ),
    ] = False,
    strict: Annotated[
        bool,
        typer.Option(
            "--strict",
            help="Fail closed: prevent dismissals if any files were skipped.",
        ),
    ] = False,
    enrich: Annotated[
        bool,
        typer.Option(
            "--enrich/--no-enrich",
            help="Enrich with EPSS/KEV threat intelligence.",
        ),
    ] = True,
    epss_file: Annotated[
        Path | None,
        typer.Option(
            "--epss-file",
            help="Use custom EPSS CSV file.",
            exists=True,
            dir_okay=False,
            readable=True,
        ),
    ] = None,
    kev_file: Annotated[
        Path | None,
        typer.Option(
            "--kev-file",
            help="Use custom KEV JSON file.",
            exists=True,
            dir_okay=False,
            readable=True,
        ),
    ] = None,
    refresh: Annotated[
        bool,
        typer.Option(
            "--refresh",
            help="Download latest EPSS/KEV data before scan.",
        ),
    ] = False,
    offline: Annotated[
        bool,
        typer.Option(
            "--offline",
            help="Disable network access; refresh is not permitted.",
        ),
    ] = _env_bool("VULNTRIAGE_OFFLINE"),
    prioritize_risk: Annotated[
        bool,
        typer.Option(
            "--prioritize-risk",
            help="Sort by KEV/EPSS instead of severity.",
        ),
    ] = False,
    output_vex: Annotated[
        Path | None,
        typer.Option(
            "--output-vex",
            help="Write CycloneDX VEX JSON to PATH.",
            dir_okay=False,
        ),
    ] = None,
    output_openvex: Annotated[
        Path | None,
        typer.Option(
            "--output-openvex",
            help="Write OpenVEX JSON to PATH.",
            dir_okay=False,
        ),
    ] = None,
    cve_function_map: Annotated[
        Path | None,
        typer.Option(
            "--cve-function-map",
            help="CVE→function map JSON for function-level matching.",
            exists=True,
            dir_okay=False,
            readable=True,
        ),
    ] = None,
    # AI analysis flags (all optional, default off)
    ai: Annotated[
        bool,
        typer.Option(
            "--ai/--no-ai",
            help="Enable AI exploitability analysis (requires OPENAI_API_KEY).",
        ),
    ] = False,
    ai_model: Annotated[
        str,
        typer.Option(
            "--ai-model",
            help="LLM model for AI analysis.",
        ),
    ] = "gpt-4o-mini",
    ai_timeout: Annotated[
        int,
        typer.Option(
            "--ai-timeout",
            help="Timeout for AI analysis in seconds.",
        ),
    ] = 30,
    ai_max_tokens: Annotated[
        int,
        typer.Option(
            "--ai-max-tokens",
            help="Maximum tokens for AI response.",
        ),
    ] = 900,
    ai_limit: Annotated[
        int,
        typer.Option(
            "--ai-limit",
            help="Maximum CVEs to analyze with AI per run.",
        ),
    ] = 25,
    ai_context_lines: Annotated[
        int,
        typer.Option(
            "--ai-context-lines",
            help="Total lines of code context for AI (split before/after).",
        ),
    ] = 50,
    ai_redact: Annotated[
        bool,
        typer.Option(
            "--ai-redact/--no-ai-redact",
            help="Redact secrets from code before sending to AI.",
        ),
    ] = True,
    ai_cache: Annotated[
        Path | None,
        typer.Option(
            "--ai-cache",
            help="File path for AI response cache (enables caching).",
        ),
    ] = None,
) -> None:
    """Scan source code for reachable vulnerabilities.

    Analyzes the Trivy report against your source code to determine
    which vulnerabilities are actually reachable and exploitable.
    """
    # Build AI config if enabled
    ai_config: AIConfig | None = None
    if ai:
        ai_config = AIConfig(
            enabled=True,
            model=ai_model,
            timeout=ai_timeout,
            max_tokens=ai_max_tokens,
            limit=ai_limit,
            context_lines=ai_context_lines,
            redact=ai_redact,
            cache_path=ai_cache,
        )

    if not json_output:
        console.print("[bold blue]VulnTriage[/] - Reachability Analysis")
        console.print(f"  Trivy report: [cyan]{trivy_json}[/]")
        console.print(f"  Source path:  [cyan]{src}[/]")
        if strict:
            console.print("  Mode:         [yellow]--strict[/]")
        if offline:
            console.print("  Mode:         [yellow]--offline[/]")
        if prioritize_risk:
            console.print("  Sorting:      [yellow]--prioritize-risk[/]")
        if ai_config:
            console.print(f"  AI analysis:  [magenta]--ai (limit={ai_limit})[/]")
        if prioritize_risk and not enrich:
            console.print(
                "[yellow]⚠ Warning: --prioritize-risk has no effect without enrichment.[/]"
            )
        console.print()

    if offline and refresh:
        raise typer.BadParameter("--offline set: --refresh is not permitted.")

    if refresh and not enrich:
        msg = "⚠ Warning: --refresh ignored because enrichment is disabled."
        if json_output:
            typer.echo(msg, err=True)
        else:
            console.print(f"[yellow]{msg}[/]")
        refresh = False

    if refresh and (epss_file or kev_file):
        msg = "⚠ Warning: --refresh ignored because custom data source was provided."
        if json_output:
            typer.echo(msg, err=True)
        else:
            console.print(f"[yellow]{msg}[/]")
        refresh = False

    if refresh:
        with console.status("[bold]Refreshing threat intelligence...[/]"):
            refresh_epss_data()
            refresh_kev_data()

    # Run the triage pipeline
    results = triage(
        trivy_json,
        src,
        include_tests=include_tests,
        strict=strict,
        include_dev=include_dev,
        proximity=proximity,
        lockfile=lockfile,
        warn_on_missing_lockfile=True,
        enrich=enrich,
        epss_file=epss_file,
        kev_file=kev_file,
        refresh=False,
        offline=offline,
        prioritize_risk=prioritize_risk,
        cve_function_map_file=cve_function_map,
        ai_config=ai_config,
        console=console if not json_output else None,
    )

    if output_vex:
        write_vex(results, output_vex)

    if output_openvex:
        write_openvex(results, output_openvex)

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
    output: list[dict[str, object]] = []
    for r in results:
        result_dict: dict[str, object] = {
            "vuln_id": r.vulnerability.vuln_id,
            "pkg_name": r.vulnerability.pkg_name,
            "installed_version": r.vulnerability.installed_version,
            "fixed_version": r.vulnerability.fixed_version,
            "severity": r.vulnerability.severity,
            "cvss_score": r.vulnerability.cvss_score,
            "epss_score": r.vulnerability.epss_score,
            "is_kev": r.vulnerability.is_kev,
            "proximity": r.vulnerability.proximity,
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
        }
        # Include AI analysis if present
        if r.ai_analysis:
            result_dict["ai_analysis"] = {
                "is_exploitable": r.ai_analysis.is_exploitable,
                "confidence": r.ai_analysis.confidence,
                "reasoning": r.ai_analysis.reasoning,
                "cited_lines": r.ai_analysis.cited_lines,
                "suggested_fix": r.ai_analysis.suggested_fix,
            }
        output.append(result_dict)
    console.print_json(data=output)


def _output_table(results: list["ScanResult"]) -> None:
    """Output results as a rich table."""
    # Count by status
    status_counts = {"actionable": 0, "needs_review": 0, "dismissed": 0}
    for r in results:
        status_counts[r.status] = status_counts.get(r.status, 0) + 1

    # Summary
    console.print(f"[bold]Found {len(results)} vulnerabilities:[/]")
    console.print(f"  Actionable:   [red bold]{status_counts['actionable']}[/]")
    console.print(f"  Needs Review: [yellow]{status_counts['needs_review']}[/]")
    console.print(f"  Dismissed:    [green]{status_counts['dismissed']}[/]")
    console.print()

    # Build table
    table = Table(show_header=True, header_style="bold")
    table.add_column("Status", width=12)
    table.add_column("Severity", width=10)
    table.add_column("CVE", width=18)
    table.add_column("Package")
    table.add_column("KEV", width=4)
    table.add_column("EPSS", width=6)
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
        evidence_str = f"{len(r.evidence)} call(s)" if r.evidence else "-"

        # Format KEV/EPSS
        kev_display = "[red bold]Y[/]" if r.vulnerability.is_kev else ""
        epss = r.vulnerability.epss_score
        epss_display = f"{epss:.1%}" if epss is not None else "-"

        table.add_row(
            status_display,
            severity_display,
            r.vulnerability.vuln_id,
            f"{r.vulnerability.pkg_name}@{r.vulnerability.installed_version}",
            kev_display,
            epss_display,
            evidence_str,
        )

    console.print(table)


@app.command()
def version() -> None:
    """Show version information."""
    console.print(f"vulntriage [bold]{__version__}[/]")


if __name__ == "__main__":
    app()
