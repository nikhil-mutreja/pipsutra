from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Dependency(BaseModel):
    model_config = ConfigDict(frozen=True)
    name: str
    normalized_name: str
    specifier: str = ""
    source: str
    group: str = "main"
    marker: str | None = None
    active: bool = True
    direct: bool = True


class Package(BaseModel):
    model_config = ConfigDict(frozen=True)
    name: str
    normalized_name: str
    version: str
    location: str | None = None
    direct: bool = False
    dependency_depth: int | None = None
    metadata_complete: bool = True


class DependencyEdge(BaseModel):
    model_config = ConfigDict(frozen=True)
    parent: str
    child: str
    requirement: str | None = None
    marker: str | None = None


class VulnerabilityFinding(BaseModel):
    model_config = ConfigDict(frozen=True)
    package: str
    version: str
    vulnerability_id: str
    summary: str = ""
    details: str = ""
    aliases: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    severity: str = "UNKNOWN"
    source: str = "OSV"


class StaticFinding(BaseModel):
    model_config = ConfigDict(frozen=True)
    rule_id: str
    title: str
    severity: Literal["LOW", "MEDIUM", "HIGH"]
    confidence: Literal["LOW", "MEDIUM", "HIGH"]
    message: str
    file: str
    line: int
    evidence: str
    recommendation: str


class RiskSummary(BaseModel):
    model_config = ConfigDict(frozen=True)
    score: int = Field(ge=0, le=100)
    level: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"]
    explanation: str


class Inventory(BaseModel):
    schema_version: Literal["1.0"] = "1.0"
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    project_path: str
    environment_path: str
    declared_dependencies: list[Dependency] = Field(default_factory=list)
    packages: list[Package] = Field(default_factory=list)
    edges: list[DependencyEdge] = Field(default_factory=list)
    missing_declared: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    discovery_status: Literal["complete", "partial"] = "complete"


class ScanReport(BaseModel):
    schema_version: Literal["1.0"] = "1.0"
    tool: str = "PipSutra"
    tool_version: str
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    project_path: str
    environment_path: str
    inventory: Inventory
    vulnerabilities: list[VulnerabilityFinding] = Field(default_factory=list)
    static_findings: list[StaticFinding] = Field(default_factory=list)
    risk: RiskSummary
    checks: dict[str, str] = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)
