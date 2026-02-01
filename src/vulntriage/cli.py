"""CLI entry point for VulnTriage."""

import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Annotated

import typer
from rich.console import Console
from rich.table import Table

from vulntriage import __version__
from vulntriage.ai_analyst import AIConfig
from vulntriage.config import load_config
from vulntriage.dependency_graph import discover_lockfile
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


def _param_from_cli(ctx: typer.Context, name: str) -> bool:
    try:
        source = ctx.get_parameter_source(name)
    except Exception:
        source = None
    if source is not None:
        try:
            return source == typer.core.ParameterSource.COMMANDLINE
        except Exception:
            if getattr(source, "name", "").upper() == "COMMANDLINE":
                return True
            if str(source).upper().endswith("COMMANDLINE"):
                return True

    # Fallback: inspect argv using the option flags for this parameter.
    try:
        for param in ctx.command.params:
            if param.name != name:
                continue
            for opt in getattr(param, "opts", []):
                if opt in sys.argv:
                    return True
            for opt in getattr(param, "secondary_opts", []):
                if opt in sys.argv:
                    return True
            break
    except Exception:
        pass
    return False


def _resolve_path(value: str | Path, base: Path) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = base / path
    return path


def _validate_file(path: Path, label: str) -> Path:
    if not path.is_file():
        raise typer.BadParameter(f"{label} does not exist: {path}")
    return path


def _discover_trivy_json(root: Path) -> tuple[Path | None, list[Path]]:
    candidates = ["trivy.json", "trivy-report.json", "trivy-results.json"]
    matches: list[tuple[int, Path]] = []
    for idx, name in enumerate(candidates):
        candidate = root / name
        if candidate.is_file():
            matches.append((idx, candidate))

    if not matches:
        return None, []

    min_idx = min(idx for idx, _ in matches)
    top = [path for idx, path in matches if idx == min_idx]
    if len(top) > 1:
        raise typer.BadParameter(
            "Multiple Trivy JSON files found at the same precedence: "
            + ", ".join(str(p) for p in top)
        )
    chosen = top[0]
    extras = [path for idx, path in matches if idx > min_idx]
    return chosen, extras


@app.command()
def scan(
    ctx: typer.Context,
    trivy_json: Annotated[
        Path | None,
        typer.Option(
            "--trivy-json",
            "-t",
            help="Path to Trivy JSON output file (auto-discovered if omitted).",
            exists=True,
            readable=True,
        ),
    ] = None,
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
            "--json/--no-json",
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
    dry_run: Annotated[
        bool,
        typer.Option(
            "--dry-run",
            help="Print resolved inputs and exit without running the scan.",
        ),
    ] = False,
) -> None:
    """Scan source code for reachable vulnerabilities.

    Analyzes the Trivy report against your source code to determine
    which vulnerabilities are actually reachable and exploitable.
    """
    config = load_config(Path.cwd())
    for warning in config.warnings:
        typer.echo(f"Warning: {warning}", err=True)

    cfg = config.data

    # Resolve source path
    src_source = "cli"
    if not _param_from_cli(ctx, "src"):
        cfg_src = cfg.get("src")
        if cfg_src is not None:
            src = _resolve_path(cfg_src, config.base_dir)
            src_source = f"config:{config.source}"
        else:
            src_source = "default"

    if src is None:
        src = Path()
    if not src.exists() or not src.is_dir():
        raise typer.BadParameter(f"Source path does not exist or is not a directory: {src}")

    # Resolve boolean options from config when CLI defaulted
    def _resolve_bool_option(
        name: str, current: bool, env_var: str | None = None
    ) -> tuple[bool, str]:
        if _param_from_cli(ctx, name):
            return current, "cli"
        if env_var and os.getenv(env_var):
            return current, f"env:{env_var}"
        if name in cfg:
            return bool(cfg[name]), f"config:{config.source}"
        return current, "default"

    include_tests, _ = _resolve_bool_option("include_tests", include_tests)
    include_dev, _ = _resolve_bool_option("include_dev", include_dev)
    proximity, proximity_source = _resolve_bool_option("proximity", proximity)
    json_output, json_source = _resolve_bool_option("json_output", json_output)
    strict, _ = _resolve_bool_option("strict", strict)
    enrich, _ = _resolve_bool_option("enrich", enrich)
    prioritize_risk, _ = _resolve_bool_option("prioritize_risk", prioritize_risk)
    offline, _ = _resolve_bool_option("offline", offline, "VULNTRIAGE_OFFLINE")

    # Resolve trivy json
    trivy_source = "cli"
    if not _param_from_cli(ctx, "trivy_json"):
        env_trivy = os.getenv("TRIVY_JSON")
        if env_trivy:
            trivy_json = _resolve_path(env_trivy, Path.cwd())
            trivy_source = "env:TRIVY_JSON"
        elif cfg.get("trivy_json") is not None:
            trivy_json = _resolve_path(cfg["trivy_json"], config.base_dir)
            trivy_source = f"config:{config.source}"
        else:
            search_root = config.base_dir
            trivy_json, extras = _discover_trivy_json(search_root)
            if trivy_json is not None:
                trivy_source = "auto"
                if extras:
                    typer.echo(
                        "Note: Using "
                        f"{trivy_json} (auto). Other Trivy files found: "
                        + ", ".join(str(p) for p in extras),
                        err=True,
                    )
            else:
                raise typer.BadParameter(
                    "No Trivy JSON found. Provide --trivy-json or run: "
                    "trivy fs --scanners vuln --format json --output trivy.json ."
                )

    if trivy_json is None:
        raise typer.BadParameter(
            "No Trivy JSON found. Provide --trivy-json or run: "
            "trivy fs --scanners vuln --format json --output trivy.json ."
        )
    trivy_json = _validate_file(trivy_json, "Trivy JSON")

    # Resolve lockfile
    lockfile_source = "cli"
    if not _param_from_cli(ctx, "lockfile"):
        env_lockfile = os.getenv("VULNTRIAGE_LOCKFILE")
        if env_lockfile:
            lockfile = _resolve_path(env_lockfile, Path.cwd())
            lockfile_source = "env:VULNTRIAGE_LOCKFILE"
        elif cfg.get("lockfile") is not None:
            lockfile = _resolve_path(cfg["lockfile"], config.base_dir)
            lockfile_source = f"config:{config.source}"
        else:
            lockfile_source = "auto"

    if lockfile is not None:
        lockfile = _validate_file(lockfile, "Lockfile")

    resolved_lockfile = lockfile
    if proximity and resolved_lockfile is None:
        resolved_lockfile = discover_lockfile(src)
    if proximity and lockfile is None and resolved_lockfile is not None:
        lockfile = resolved_lockfile

    if not sys.stdout.isatty() and json_source == "default":
        json_output = True
        json_source = "auto"
        typer.echo("Note: Non-TTY detected, defaulting to JSON output.", err=True)

    if dry_run:
        console.print("[bold]VulnTriage[/] - Dry Run")
        console.print(f"  Trivy JSON: [cyan]{trivy_json}[/] ({trivy_source})")
        console.print(f"  Source:     [cyan]{src}[/] ({src_source})")
        if proximity:
            lockfile_display = (
                f"{resolved_lockfile} ({lockfile_source})"
                if resolved_lockfile
                else f"none ({lockfile_source})"
            )
        else:
            lockfile_display = "disabled (--no-proximity)"
        console.print(f"  Lockfile:   [cyan]{lockfile_display}[/]")
        console.print(
            f"  Proximity:  [cyan]{'enabled' if proximity else 'disabled'}[/] ({proximity_source})"
        )
        console.print(f"  JSON:       [cyan]{'on' if json_output else 'off'}[/] ({json_source})")
        return

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
        console.print(f"  Trivy report: [cyan]{trivy_json}[/] ({trivy_source})")
        console.print(f"  Source path:  [cyan]{src}[/] ({src_source})")
        if proximity:
            if resolved_lockfile:
                console.print(
                    f"  Lockfile:    [cyan]{resolved_lockfile}[/] ({lockfile_source})"
                )
            else:
                console.print(f"  Lockfile:    [cyan]none[/] ({lockfile_source})")
        else:
            console.print("  Lockfile:    [cyan]disabled[/] (--no-proximity)")
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
