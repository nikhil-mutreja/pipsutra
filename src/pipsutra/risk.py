from __future__ import annotations

from typing import Literal

from pipsutra.models import RiskSummary, StaticFinding, VulnerabilityFinding

# Severity weights used to accumulate the heuristic score.
_WEIGHTS: dict[str, int] = {
    "LOW": 5,
    "MEDIUM": 15,
    "HIGH": 25,
    "CRITICAL": 35,
    "UNKNOWN": 8,
}

# Score bands (lower bound inclusive → level).
_BANDS: list[tuple[int, Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]]] = [
    (75, "CRITICAL"),
    (45, "HIGH"),
    (20, "MEDIUM"),
    (0, "LOW"),
]


def calculate_risk(
    vulnerabilities: list[VulnerabilityFinding], static_findings: list[StaticFinding]
) -> RiskSummary:
    score = min(
        100,
        sum(_WEIGHTS.get(item.severity, 8) for item in vulnerabilities)
        + sum(_WEIGHTS[item.severity] for item in static_findings),
    )
    level: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = "LOW"
    for threshold, band in _BANDS:
        if score >= threshold:
            level = band
            break
    explanation = (
        f"Heuristic score {score}/100 from {len(vulnerabilities)} vulnerability "
        f"finding(s) and {len(static_findings)} static finding(s). This score is "
        "a prioritization aid, not a probability of compromise or a safety verdict. "
        "Weights: LOW=5, MEDIUM=15, HIGH=25, CRITICAL=35, UNKNOWN=8; "
        "the score is capped at 100."
    )
    return RiskSummary(score=score, level=level, explanation=explanation)
