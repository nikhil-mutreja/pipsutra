from __future__ import annotations

import sys
from pathlib import Path

from pipsutra._version import __version__
from pipsutra.discovery import build_inventory
from pipsutra.models import Inventory, ScanReport
from pipsutra.risk import calculate_risk
from pipsutra.static_analysis import scan_python_source
from pipsutra.vulnerability import query_osv


def build_inventory_report(
    project: str | Path = ".", environment: str | Path | None = None
) -> Inventory:
    selected_environment = Path(environment) if environment else Path(sys.prefix)
    return build_inventory(project, selected_environment)


def scan_project(
    project: str | Path = ".",
    environment: str | Path | None = None,
    *,
    check_vulnerabilities: bool = True,
    check_static: bool = True,
    network_timeout: float = 15.0,
) -> ScanReport:
    inventory = build_inventory_report(project, environment)
    errors: list[str] = []
    checks = {
        "inventory": (
            "completed" if inventory.discovery_status == "complete" else "partial"
        )
    }

    osv_errors: list[str] = []
    if check_vulnerabilities:
        relevant_packages = [
            package
            for package in inventory.packages
            if package.direct or package.dependency_depth is not None
        ]
        vulnerabilities, osv_errors = query_osv(
            relevant_packages, timeout=network_timeout
        )
        errors.extend(osv_errors)
        checks["osv"] = "completed" if not osv_errors else "failed"
    else:
        vulnerabilities = []
        checks["osv"] = "skipped"

    if check_static:
        static_findings, static_warnings = scan_python_source(inventory.project_path)
        inventory.warnings.extend(static_warnings)
        checks["static_analysis"] = "partial" if static_warnings else "completed"
    else:
        static_findings = []
        checks["static_analysis"] = "skipped"

    risk = calculate_risk(vulnerabilities, static_findings)
    incomplete_checks = [
        name for name, status in checks.items() if status != "completed"
    ]
    if incomplete_checks:
        reason = ", ".join(incomplete_checks)
        risk = risk.model_copy(
            update={
                "level": "UNKNOWN",
                "explanation": (
                    risk.explanation
                    + f" Coverage is incomplete; check status: {reason}."
                ),
            }
        )

    return ScanReport(
        tool_version=__version__,
        project_path=inventory.project_path,
        environment_path=inventory.environment_path,
        inventory=inventory,
        vulnerabilities=vulnerabilities,
        static_findings=static_findings,
        risk=risk,
        checks=checks,
        errors=errors,
    )
