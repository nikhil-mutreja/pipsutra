from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from pipsutra.cli import _has_blocking_findings, app
from pipsutra.models import (
    Inventory,
    RiskSummary,
    ScanReport,
    StaticFinding,
    VulnerabilityFinding,
)

runner = CliRunner()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_report(**overrides: object) -> ScanReport:
    defaults: dict[str, object] = dict(
        tool_version="0.1.0",
        project_path=".",
        environment_path=".venv",
        inventory=Inventory(project_path=".", environment_path=".venv"),
        vulnerabilities=[
            VulnerabilityFinding(
                package="demo",
                version="1.0",
                vulnerability_id="CVE-2026-0001",
                severity="HIGH",
            )
        ],
        static_findings=[
            StaticFinding(
                rule_id="DG-PY-001",
                title="Dynamic execution",
                severity="HIGH",
                confidence="HIGH",
                message="eval used",
                file="app.py",
                line=4,
                evidence="eval(x)",
                recommendation="Avoid eval",
            )
        ],
        risk=RiskSummary(score=50, level="HIGH", explanation="test"),
    )
    defaults.update(overrides)
    return ScanReport(**defaults)  # type: ignore[arg-type]


def _make_project(tmp_path: Path) -> tuple[Path, Path]:
    project = tmp_path / "project"
    environment = tmp_path / "environment"
    project.mkdir()
    environment.mkdir()
    return project, environment


# ---------------------------------------------------------------------------
# _has_blocking_findings
# ---------------------------------------------------------------------------


def test_fail_on_threshold_matches_findings() -> None:
    report = _make_report()
    assert not _has_blocking_findings(report, "none")
    assert not _has_blocking_findings(report, "critical")
    assert _has_blocking_findings(report, "high")
    assert _has_blocking_findings(report, "medium")
    assert _has_blocking_findings(report, "low")


def test_fail_on_none_never_blocks() -> None:
    report = _make_report(
        vulnerabilities=[
            VulnerabilityFinding(
                package="x",
                version="1.0",
                vulnerability_id="CVE-2026-9999",
                severity="CRITICAL",
            )
        ]
    )
    assert not _has_blocking_findings(report, "none")


# ---------------------------------------------------------------------------
# version command
# ---------------------------------------------------------------------------


def test_version_command_displays_developer_attribution() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "PipSutra 0.1.0" in result.output
    assert "Developed by Nikhil Mutreja" in result.output


# ---------------------------------------------------------------------------
# scan command — exit codes
# ---------------------------------------------------------------------------


def test_scan_cli_returns_nonzero_when_fail_threshold_is_met(
    tmp_path: Path,
) -> None:
    project, environment = _make_project(tmp_path)
    (project / "pyproject.toml").write_text("[project]\nname='demo'\nversion='1.0'\n")
    (project / "app.py").write_text("eval(payload)\n")

    result = runner.invoke(
        app,
        [
            "scan",
            "--project",
            str(project),
            "--environment",
            str(environment),
            "--no-osv",
            "--fail-on",
            "high",
        ],
    )

    assert result.exit_code == 1
    assert "Findings meet the --fail-on high threshold" in result.output


def test_scan_exits_zero_when_threshold_not_met(tmp_path: Path) -> None:
    """A HIGH finding with --fail-on critical should exit 0."""
    project, environment = _make_project(tmp_path)
    (project / "requirements.txt").write_text("", encoding="utf-8")
    (project / "app.py").write_text("eval(payload)\n", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "scan",
            "--project",
            str(project),
            "--environment",
            str(environment),
            "--no-osv",
            "--fail-on",
            "critical",
        ],
    )
    assert result.exit_code == 0


def test_scan_exits_zero_with_fail_on_none_even_with_findings(
    tmp_path: Path,
) -> None:
    project, environment = _make_project(tmp_path)
    (project / "requirements.txt").write_text("", encoding="utf-8")
    (project / "app.py").write_text("eval(payload)\n", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "scan",
            "--project",
            str(project),
            "--environment",
            str(environment),
            "--no-osv",
            "--fail-on",
            "none",
        ],
    )
    assert result.exit_code == 0


def test_scan_exits_2_on_invalid_project_path(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "scan",
            "--project",
            str(tmp_path / "nonexistent"),
        ],
    )
    # Typer reports path-does-not-exist errors with a non-zero exit
    assert result.exit_code != 0


def test_scan_no_static_skips_ast_check(tmp_path: Path) -> None:
    project, environment = _make_project(tmp_path)
    (project / "requirements.txt").write_text("", encoding="utf-8")
    (project / "app.py").write_text("eval(payload)\n", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "scan",
            "--project",
            str(project),
            "--environment",
            str(environment),
            "--no-osv",
            "--no-static",
        ],
    )
    assert result.exit_code == 0
    assert "Static findings: 0" in result.output


# ---------------------------------------------------------------------------
# scan command — JSON output
# ---------------------------------------------------------------------------


def test_scan_writes_valid_json_to_output_file(tmp_path: Path) -> None:
    project, environment = _make_project(tmp_path)
    output_file = tmp_path / "report.json"
    (project / "requirements.txt").write_text("", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "scan",
            "--project",
            str(project),
            "--environment",
            str(environment),
            "--no-osv",
            "--output",
            str(output_file),
        ],
    )
    assert result.exit_code == 0
    assert output_file.exists()
    data = json.loads(output_file.read_text(encoding="utf-8"))
    assert data["tool"] == "PipSutra"
    assert "risk" in data
    assert "checks" in data


# ---------------------------------------------------------------------------
# inventory command
# ---------------------------------------------------------------------------


def test_inventory_command_lists_packages(tmp_path: Path) -> None:
    project = tmp_path / "project"
    environment = tmp_path / ".venv"
    site_packages = environment / "lib" / "python3.13" / "site-packages"
    project.mkdir()
    site_packages.mkdir(parents=True)
    (project / "requirements.txt").write_text("demo-lib>=1\n", encoding="utf-8")
    dist_info = site_packages / "demo_lib-1.0.dist-info"
    dist_info.mkdir()
    (dist_info / "METADATA").write_text(
        "Metadata-Version: 2.1\nName: demo-lib\nVersion: 1.0\n\n",
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "inventory",
            "--project",
            str(project),
            "--environment",
            str(environment),
        ],
    )
    assert result.exit_code == 0
    assert "demo-lib" in result.output


def test_inventory_exits_2_on_bad_project_path(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "inventory",
            "--project",
            str(tmp_path / "missing"),
        ],
    )
    assert result.exit_code != 0


def test_inventory_writes_valid_json_to_output_file(tmp_path: Path) -> None:
    project, environment = _make_project(tmp_path)
    output_file = tmp_path / "inventory.json"
    (project / "requirements.txt").write_text("", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "inventory",
            "--project",
            str(project),
            "--environment",
            str(environment),
            "--output",
            str(output_file),
        ],
    )
    assert result.exit_code == 0
    assert output_file.exists()
    data = json.loads(output_file.read_text(encoding="utf-8"))
    assert data["schema_version"] == "1.0"
