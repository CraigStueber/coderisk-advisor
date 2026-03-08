"""
Unit tests for utils.score_calculator.calculate_scores

Run with:
    cd backend
    python -m pytest tests/test_score_calculator.py -v
"""

from __future__ import annotations

import sys
import os

# Allow running directly from the backend/ directory
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from utils.score_calculator import calculate_scores


# ---------------------------------------------------------------------------
# Helper: build a minimal finding dict
# ---------------------------------------------------------------------------

def _vuln(
    id: str,
    severity: str,
    confidence: float,
    owasp_category: str,
    cvss_score: float | None = None,
) -> dict:
    f: dict = {
        "id": id,
        "severity": severity,
        "confidence": confidence,
        "owasp_category": owasp_category,
    }
    if cvss_score is not None:
        f["cvss_score"] = cvss_score
    return f


def _brisk(
    id: str,
    severity: str,
    confidence: float,
    risk_type: str,
) -> dict:
    return {
        "id": id,
        "severity": severity,
        "confidence": confidence,
        "risk_type": risk_type,
    }


# ---------------------------------------------------------------------------
# Test: empty list
# ---------------------------------------------------------------------------

def test_empty_findings_returns_zero_scores():
    result = calculate_scores([])

    assert result["overall_score"] == 0.0
    assert result["severity_counts"] == {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }
    assert result["owasp"] == {}
    assert result["cvss_like"] == {"impact": 0.0, "exploitability": 0.0}


# ---------------------------------------------------------------------------
# Test: single finding — severity fallback path (no cvss_score)
# ---------------------------------------------------------------------------

def test_single_finding_severity_fallback():
    """
    high severity, no cvss_score → exploitability from severity table.
    impact=8.0, exploitability=7.0, confidence=1.0
    base_score = (8.0 * 7.0) / 10 = 5.6
    rule_score = 5.6 * 1.0 = 5.6
    """
    result = calculate_scores([_vuln("V-001", "high", 1.0, "A01:2021")])

    assert result["overall_score"] == 5.6
    assert result["severity_counts"]["high"] == 1
    assert "A01:2021" in result["owasp"]
    assert result["owasp"]["A01:2021"] == 5.6
    assert result["cvss_like"]["impact"] == 8.0
    assert result["cvss_like"]["exploitability"] == 7.0


# ---------------------------------------------------------------------------
# Test: single finding — cvss_score overrides severity exploitability
# ---------------------------------------------------------------------------

def test_single_finding_cvss_overrides_exploitability():
    """
    high severity, cvss_score=9.8 → exploitability=9.8 (not 7.0)
    impact=8.0, exploitability=9.8, confidence=0.9
    base_score = (8.0 * 9.8) / 10 = 7.84
    rule_score = 7.84 * 0.9 = 7.056 → round to 2dp = 7.06
    """
    finding = _vuln("V-002", "high", 0.9, "A03:2021", cvss_score=9.8)
    result = calculate_scores([finding])

    expected_rule = round(7.84 * 0.9, 2)  # 7.06
    assert result["owasp"]["A03:2021"] == expected_rule
    assert result["cvss_like"]["exploitability"] == 9.8
    assert result["cvss_like"]["impact"] == 8.0


# ---------------------------------------------------------------------------
# Test: multi-category rollup — overall = max across categories
# ---------------------------------------------------------------------------

def test_multi_category_rollup_takes_max():
    """
    A01:2021: medium(5,5,0.8)→2.0;  low(2,2,1.0)→0.4  → cat_max=2.0
    A03:2021: critical(10,10,0.9)→9.0                   → cat_max=9.0
    overall = max(2.0, 9.0) = 9.0
    """
    findings = [
        _vuln("V-001", "medium", 0.8, "A01:2021"),
        _vuln("V-002", "critical", 0.9, "A03:2021"),
        _vuln("V-003", "low", 1.0, "A01:2021"),
    ]
    result = calculate_scores(findings)

    assert result["overall_score"] == 9.0
    assert result["owasp"]["A01:2021"] == 2.0
    assert result["owasp"]["A03:2021"] == 9.0
    assert result["severity_counts"]["medium"] == 1
    assert result["severity_counts"]["critical"] == 1
    assert result["severity_counts"]["low"] == 1


# ---------------------------------------------------------------------------
# Test: same category — owasp entry equals the max rule_score
# ---------------------------------------------------------------------------

def test_same_category_max_wins():
    """
    Two behavioral findings in the same risk_type.
    B-001: high, confidence=0.5 → rule=5.6*0.5=2.8
    B-002: high, confidence=1.0 → rule=5.6*1.0=5.6
    category max = 5.6
    """
    findings = [
        _brisk("B-001", "high", 0.5, "hallucinated_api"),
        _brisk("B-002", "high", 1.0, "hallucinated_api"),
    ]
    result = calculate_scores(findings)

    assert result["owasp"]["hallucinated_api"] == 5.6
    assert result["overall_score"] == 5.6
    assert result["severity_counts"]["high"] == 2


# ---------------------------------------------------------------------------
# Test: missing fields default to 0, no exception raised
# ---------------------------------------------------------------------------

def test_missing_fields_do_not_raise():
    """A finding with only an id should produce a zero score, not an exception."""
    result = calculate_scores([{"id": "X-001", "severity": "info"}])

    # info → impact=0, exploitability=0, confidence=0 → rule_score=0
    assert result["overall_score"] == 0.0
    assert result["severity_counts"]["info"] == 1


def test_completely_empty_finding_does_not_raise():
    """A totally empty finding dict should not raise an exception."""
    result = calculate_scores([{}])

    assert result["overall_score"] == 0.0
    # unknown severity → not counted in any standard bucket
    assert sum(result["severity_counts"].values()) == 0


# ---------------------------------------------------------------------------
# Test: mixed vuln + behavioral findings
# ---------------------------------------------------------------------------

def test_mixed_vuln_and_behavioral():
    """
    Combines owasp_category (vuln) and risk_type (behavioral) as distinct keys.
    """
    findings = [
        _vuln("V-001", "high", 0.8, "A01:2021"),
        _brisk("B-001", "medium", 0.7, "prompt_injection_surface"),
    ]
    result = calculate_scores(findings)

    # high, no cvss: impact=8.0, exp=7.0, conf=0.8 → base=5.6, rule=4.48
    assert "A01:2021" in result["owasp"]
    assert result["owasp"]["A01:2021"] == round(5.6 * 0.8, 2)

    # medium: impact=5, exp=5, conf=0.7 → base=2.5, rule=1.75
    assert "prompt_injection_surface" in result["owasp"]
    assert result["owasp"]["prompt_injection_surface"] == round(2.5 * 0.7, 2)

    assert result["overall_score"] == round(5.6 * 0.8, 1)
    assert result["severity_counts"]["high"] == 1
    assert result["severity_counts"]["medium"] == 1
