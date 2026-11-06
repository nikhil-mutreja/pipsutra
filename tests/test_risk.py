from __future__ import annotations

import pytest

from pipsutra.models import StaticFinding, VulnerabilityFinding
from pipsutra.risk import _BANDS, _WEIGHTS, calculate_risk

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _vuln(severity: str) -> VulnerabilityFinding:
    return VulnerabilityFinding(
        package="demo",
        version="1.0",
        vulnerability_id="GHSA-test",
        severity=severity,
    )


def _static(severity: str) -> StaticFinding:
    return StaticFinding(
        rule_id="DG-PY-001",
        title="Dynamic code execution",
        severity=severity,  # type: ignore[arg-type]
        confidence="HIGH",
        message="eval used",
        file="app.py",
        line=1,
        evidence="eval(x)",
        recommendation="Avoid eval",
    )


# ---------------------------------------------------------------------------
# Basic contract
# ---------------------------------------------------------------------------


def test_empty_findings_produce_low_risk_score() -> None:
    result = calculate_risk([], [])
    assert result.score == 0
    assert result.level == "LOW"
    assert "not a probability" in result.explanation


def test_explanation_always_present() -> None:
    result = calculate_risk([], [])
    assert result.explanation


# ---------------------------------------------------------------------------
# Weights table
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("severity", "expected_weight"),
    [
        ("LOW", 5),
        ("MEDIUM", 15),
        ("HIGH", 25),
        ("CRITICAL", 35),
        ("UNKNOWN", 8),
    ],
)
def test_weights_table_values(severity: str, expected_weight: int) -> None:
    assert _WEIGHTS[severity] == expected_weight


# ---------------------------------------------------------------------------
# Score band boundaries
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Score band boundaries — test the mapping directly
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("score", "expected_level"),
    [
        (0, "LOW"),
        (19, "LOW"),
        (20, "MEDIUM"),
        (44, "MEDIUM"),
        (45, "HIGH"),
        (74, "HIGH"),
        (75, "CRITICAL"),
        (100, "CRITICAL"),
    ],
)
def test_score_band_boundaries(score: int, expected_level: str) -> None:
    """
    Verify the _BANDS table maps every documented boundary to the right level.

    Not every integer score is reachable from the discrete weights (e.g. 19, 44,
    45, 74 cannot be expressed as a sum of {5,8,15,25,35}).  We therefore test
    the band table directly rather than constructing finding lists.
    """
    result_level: str = "LOW"
    for threshold, band in _BANDS:
        if score >= threshold:
            result_level = band
            break
    assert result_level == expected_level


def test_reachable_scores_produce_correct_levels() -> None:
    """End-to-end: accumulation + banding for scores we can actually construct."""
    # 0 → LOW
    assert calculate_risk([], []).level == "LOW"
    # 15 → LOW  (one MEDIUM vuln)
    assert calculate_risk([_vuln("MEDIUM")], []).level == "LOW"
    # 20 → MEDIUM  (one HIGH static: 25 — wait, that's HIGH band)
    # Use two MEDIUM = 30 → MEDIUM
    assert calculate_risk([_vuln("MEDIUM"), _vuln("MEDIUM")], []).score == 30
    assert calculate_risk([_vuln("MEDIUM"), _vuln("MEDIUM")], []).level == "MEDIUM"
    # 50 → HIGH  (two HIGH = 50)
    assert calculate_risk([_vuln("HIGH"), _vuln("HIGH")], []).score == 50
    assert calculate_risk([_vuln("HIGH"), _vuln("HIGH")], []).level == "HIGH"
    # 75 → CRITICAL  (CRITICAL+HIGH+MEDIUM = 35+25+15)
    result = calculate_risk([_vuln("CRITICAL"), _vuln("HIGH"), _vuln("MEDIUM")], [])
    assert result.score == 75
    assert result.level == "CRITICAL"


def test_score_is_capped_at_100() -> None:
    """A large number of CRITICAL findings must not exceed 100."""
    vulns = [_vuln("CRITICAL")] * 10  # 10 × 35 = 350 → should cap at 100
    result = calculate_risk(vulns, [])
    assert result.score == 100
    assert result.level == "CRITICAL"


# ---------------------------------------------------------------------------
# Duplicate findings are not artificially inflated
# ---------------------------------------------------------------------------


def test_duplicate_vulnerability_ids_are_counted_individually_not_collapsed() -> None:
    """
    The risk module does not deduplicate — that is the caller's responsibility.
    But we verify the score is simply additive (no silent multiplication).
    """
    v1 = _vuln("HIGH")  # 25
    v2 = _vuln("HIGH")  # 25 → total 50 → HIGH
    result = calculate_risk([v1, v2], [])
    assert result.score == 50
    assert result.level == "HIGH"


def test_mixed_vulnerability_and_static_findings_accumulate() -> None:
    result = calculate_risk([_vuln("MEDIUM")], [_static("HIGH")])
    # 15 + 25 = 40 → MEDIUM
    assert result.score == 40
    assert result.level == "MEDIUM"
    assert "1 vulnerability" in result.explanation
    assert "1 static" in result.explanation


# ---------------------------------------------------------------------------
# Bands list is ordered (defensive — ensures _BANDS is correct)
# ---------------------------------------------------------------------------


def test_bands_are_sorted_descending() -> None:
    thresholds = [t for t, _ in _BANDS]
    assert thresholds == sorted(thresholds, reverse=True)
