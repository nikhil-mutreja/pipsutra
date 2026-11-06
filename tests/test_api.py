from __future__ import annotations

import json
from pathlib import Path

from pipsutra.api import scan_project

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_project(tmp_path: Path) -> tuple[Path, Path]:
    project = tmp_path / "project"
    environment = tmp_path / "environment"
    project.mkdir()
    environment.mkdir()
    return project, environment


def _make_venv_with_package(
    tmp_path: Path, pkg_name: str, pkg_version: str
) -> tuple[Path, Path]:
    project = tmp_path / "project"
    environment = tmp_path / ".venv"
    site_packages = environment / "lib" / "python3.13" / "site-packages"
    project.mkdir()
    site_packages.mkdir(parents=True)
    safe_name = pkg_name.replace("-", "_")
    dist_info = site_packages / f"{safe_name}-{pkg_version}.dist-info"
    dist_info.mkdir()
    (dist_info / "METADATA").write_text(
        f"Metadata-Version: 2.1\nName: {pkg_name}\nVersion: {pkg_version}\n\n",
        encoding="utf-8",
    )
    return project, environment


# ---------------------------------------------------------------------------
# Core scan behaviour
# ---------------------------------------------------------------------------


def test_scan_project_without_osv_is_offline_and_reports_checks(
    tmp_path: Path,
) -> None:
    project, environment = _make_project(tmp_path)
    (project / "requirements.txt").write_text("", encoding="utf-8")
    (project / "app.py").write_text("eval(payload)\n", encoding="utf-8")

    report = scan_project(project, environment, check_vulnerabilities=False)

    assert report.checks == {
        "inventory": "completed",
        "osv": "skipped",
        "static_analysis": "completed",
    }
    assert report.vulnerabilities == []
    assert report.risk.level == "UNKNOWN"
    assert [item.rule_id for item in report.static_findings] == ["DG-PY-001"]


def test_osv_failure_is_not_reported_as_clean_scan(tmp_path: Path, monkeypatch) -> None:
    project, environment = _make_venv_with_package(tmp_path, "demo-lib", "1.0")
    (project / "requirements.txt").write_text("demo-lib>=1\n", encoding="utf-8")
    (project / "app.py").write_text("# benign source\n", encoding="utf-8")
    monkeypatch.setattr(
        "pipsutra.api.query_osv",
        lambda packages, timeout: ([], ["OSV service unavailable"]),
    )

    report = scan_project(project, environment)

    assert report.checks["osv"] == "failed"
    assert report.risk.level == "UNKNOWN"
    assert report.errors == ["OSV service unavailable"]


# ---------------------------------------------------------------------------
# Incomplete checks force UNKNOWN risk level
# ---------------------------------------------------------------------------


def test_skipped_osv_forces_unknown_risk_level(tmp_path: Path) -> None:
    """When OSV is skipped, risk level must be UNKNOWN regardless of score."""
    project, environment = _make_project(tmp_path)
    (project / "requirements.txt").write_text("", encoding="utf-8")

    report = scan_project(project, environment, check_vulnerabilities=False)

    assert report.checks["osv"] == "skipped"
    assert report.risk.level == "UNKNOWN"
    assert "osv" in report.risk.explanation.lower()


def test_skipped_static_check_forces_unknown_risk_level(tmp_path: Path) -> None:
    """When static analysis is skipped, risk must be UNKNOWN."""
    project, environment = _make_project(tmp_path)
    (project / "requirements.txt").write_text("", encoding="utf-8")

    report = scan_project(
        project,
        environment,
        check_vulnerabilities=False,
        check_static=False,
    )

    assert report.checks["static_analysis"] == "skipped"
    assert report.risk.level == "UNKNOWN"


def test_both_checks_skipped_forces_unknown(tmp_path: Path) -> None:
    project, environment = _make_project(tmp_path)
    (project / "requirements.txt").write_text("", encoding="utf-8")

    report = scan_project(
        project, environment, check_vulnerabilities=False, check_static=False
    )

    assert report.risk.level == "UNKNOWN"
    assert "osv" in report.risk.explanation.lower()
    assert "static_analysis" in report.risk.explanation.lower()


def test_osv_partial_failure_forces_unknown(tmp_path: Path, monkeypatch) -> None:
    """A partial OSV error must produce UNKNOWN, not a misleading LOW verdict."""
    project, environment = _make_venv_with_package(tmp_path, "demo-lib", "1.0")
    (project / "requirements.txt").write_text("demo-lib>=1\n", encoding="utf-8")
    monkeypatch.setattr(
        "pipsutra.api.query_osv",
        lambda packages, timeout: ([], ["Partial batch failure at offset 0"]),
    )

    report = scan_project(project, environment)

    assert report.checks["osv"] == "failed"
    assert report.risk.level == "UNKNOWN"


# ---------------------------------------------------------------------------
# Report fields
# ---------------------------------------------------------------------------


def test_scan_report_contains_tool_version_and_attribution(tmp_path: Path) -> None:
    project, environment = _make_project(tmp_path)
    (project / "requirements.txt").write_text("", encoding="utf-8")

    report = scan_project(project, environment, check_vulnerabilities=False)

    assert report.tool == "PipSutra"
    assert report.tool_version == "0.1.0"


def test_scan_report_serializes_to_json(tmp_path: Path) -> None:
    project, environment = _make_project(tmp_path)
    (project / "requirements.txt").write_text("", encoding="utf-8")

    report = scan_project(project, environment, check_vulnerabilities=False)
    data = json.loads(report.model_dump_json())
    assert data["schema_version"] == "1.0"
    assert "risk" in data
