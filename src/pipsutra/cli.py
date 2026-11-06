from __future__ import annotations

from pathlib import Path
from typing import Literal

import typer
from rich.console import Console
from rich.table import Table

from pipsutra._version import __version__
from pipsutra.api import build_inventory_report, scan_project
from pipsutra.models import ScanReport

app = typer.Typer(
    name="pipsutra",
    help="Explainable security analysis for Python dependencies.",
    no_args_is_help=True,
    epilog="Developed by Nikhil Mutreja | Apache-2.0 License",
)
console = Console()
_SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _has_blocking_findings(report: ScanReport, threshold: str) -> bool:
    if threshold == "none":
        return False
    minimum = _SEVERITY_RANK[threshold.upper()]
    vulnerability_match = any(
        _SEVERITY_RANK.get(finding.severity, 0) >= minimum
        for finding in report.vulnerabilities
    )
    static_match = any(
        _SEVERITY_RANK.get(finding.severity, 0) >= minimum
        for finding in report.static_findings
    )
    return vulnerability_match or static_match


@app.command()
def version() -> None:
    """Print the installed PipSutra version."""
    console.print(f"PipSutra {__version__}\nDeveloped by Nikhil Mutreja")


def _write_json(payload: str, output: Path | None) -> None:
    if output is None:
        console.print(payload)
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(payload + "\n", encoding="utf-8")
    console.print(f"[green]JSON report written to {output}[/green]")


@app.command()
def inventory(
    project: Path = typer.Option(
        Path("."), "--project", "-p", exists=True, file_okay=False
    ),
    environment: Path | None = typer.Option(
        None, "--environment", "-e", exists=True, file_okay=False
    ),
    output: Path | None = typer.Option(None, "--output", "-o"),
) -> None:
    """Discover declared and installed dependencies and export an inventory."""
    try:
        report = build_inventory_report(project, environment)
    except (ValueError, OSError) as exc:
        console.print(f"[red]Inventory failed:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    table = Table(title="PipSutra dependency inventory")
    for heading in ("Package", "Version", "Classification", "Depth"):
        table.add_column(heading)
    for package in report.packages:
        if package.direct:
            classification = "direct"
        elif package.dependency_depth is not None:
            classification = "transitive"
        else:
            classification = "unlinked"
        depth = (
            str(package.dependency_depth)
            if package.dependency_depth is not None
            else "—"
        )
        table.add_row(package.name, package.version, classification, depth)
    console.print(table)
    console.print(
        f"Declared: {len(report.declared_dependencies)} | "
        f"Installed: {len(report.packages)} | Edges: {len(report.edges)} | "
        f"Missing direct: {len(report.missing_declared)}"
    )
    for warning in report.warnings:
        console.print(f"[yellow]Warning:[/yellow] {warning}")
    if output:
        _write_json(report.model_dump_json(indent=2), output)


@app.command()
def scan(
    project: Path = typer.Option(
        Path("."), "--project", "-p", exists=True, file_okay=False
    ),
    environment: Path | None = typer.Option(
        None, "--environment", "-e", exists=True, file_okay=False
    ),
    output: Path | None = typer.Option(None, "--output", "-o"),
    no_osv: bool = typer.Option(
        False, "--no-osv", help="Skip online OSV vulnerability checks."
    ),
    no_static: bool = typer.Option(
        False, "--no-static", help="Skip Python AST checks."
    ),
    timeout: float = typer.Option(15.0, "--timeout", min=1.0, max=120.0),
    fail_on: Literal["none", "low", "medium", "high", "critical"] = typer.Option(
        "none",
        "--fail-on",
        help="Exit with status 1 when a finding meets this severity threshold.",
    ),
) -> None:
    """Run dependency inventory, OSV checks, and Python AST rules."""
    try:
        report = scan_project(
            project,
            environment,
            check_vulnerabilities=not no_osv,
            check_static=not no_static,
            network_timeout=timeout,
        )
    except (ValueError, OSError) as exc:
        console.print(f"[red]Scan failed:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    console.print(f"[bold]PipSutra scan:[/bold] {report.project_path}")
    console.print(f"Risk: [bold]{report.risk.level} ({report.risk.score}/100)[/bold]")
    console.print(report.risk.explanation)
    if report.vulnerabilities:
        table = Table(title="Known vulnerabilities (OSV)")
        for heading in ("Package", "Version", "ID", "Severity", "Summary"):
            table.add_column(heading)
        for finding in report.vulnerabilities:
            table.add_row(
                finding.package,
                finding.version,
                finding.vulnerability_id,
                finding.severity,
                finding.summary[:80],
            )
        console.print(table)
    else:
        osv_status = report.checks["osv"]
        console.print(
            "OSV findings: 0" if osv_status == "completed" else f"OSV: {osv_status}"
        )
    if report.static_findings:
        table = Table(title="Static analysis findings")
        for heading in ("Severity", "Rule", "Location", "Finding"):
            table.add_column(heading)
        for sf in report.static_findings:
            table.add_row(
                sf.severity,
                sf.rule_id,
                f"{sf.file}:{sf.line}",
                sf.title,
            )
        console.print(table)
    else:
        console.print("Static findings: 0")
    for error in report.errors:
        console.print(f"[yellow]Warning:[/yellow] {error}")
    if output:
        _write_json(report.model_dump_json(indent=2), output)
    if _has_blocking_findings(report, fail_on):
        console.print(f"[red]Findings meet the --fail-on {fail_on} threshold.[/red]")
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
