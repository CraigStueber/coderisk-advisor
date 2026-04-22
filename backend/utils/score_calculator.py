"""
CodeRisk Advisor — Deterministic Score Calculator

Pure Python. No LLM calls. Operates on the finalized list of findings after
the Skeptic pass so that disputed flags are already set.

Score model
-----------
Per finding:
    impact          — derived from severity (or explicit field if present)
    exploitability  — cvss_score if available, else derived from severity
    confidence      — finding["confidence"], clamped 0–1

    base_score  = (impact * exploitability) / 10   → 0–10
    rule_score  = base_score * confidence           → 0–10

Per OWASP/risk-type category:
    category_score = max(rule_score for finding in that category)

Overall:
    overall_score = max(category_scores)            → 0–10, rounded to 1 dp
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Severity → numeric weight tables
# ---------------------------------------------------------------------------

_SEVERITY_IMPACT: dict[str, float] = {
    "critical": 10.0,
    "high": 8.0,
    "medium": 5.0,
    "low": 2.0,
    "info": 0.0,
}

_SEVERITY_EXPLOITABILITY: dict[str, float] = {
    "critical": 10.0,
    "high": 7.0,
    "medium": 5.0,
    "low": 2.0,
    "info": 0.0,
}

_ZERO_COUNTS: dict[str, int] = {
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0,
    "info": 0,
}


# ---------------------------------------------------------------------------
# Field extractors with safe fallbacks
# ---------------------------------------------------------------------------

def _normalize_severity(finding: dict) -> str:
    """
    Return a clean severity string for table lookups.

    Pydantic enum repr leaks into state as "severity.medium" rather than
    "medium" when findings are reconstructed via dict comprehension in the
    Skeptic node. Split on "." and take the last segment to handle both.
    """
    raw = str(finding.get("severity", "")).lower()
    return raw.split(".")[-1]


def _get_impact(finding: dict) -> float:
    """Explicit 'impact' field takes priority; falls back to severity map."""
    raw = finding.get("impact")
    if raw is not None:
        try:
            return float(raw)
        except (ValueError, TypeError):
            pass
    return _SEVERITY_IMPACT.get(_normalize_severity(finding), 0.0)


def _get_exploitability(finding: dict) -> float:
    """Priority: explicit 'exploitability' → cvss_score → severity map."""
    raw = finding.get("exploitability")
    if raw is not None:
        try:
            return float(raw)
        except (ValueError, TypeError):
            pass
    cvss = finding.get("cvss_score")
    if cvss is not None:
        try:
            return float(cvss)
        except (ValueError, TypeError):
            pass
    return _SEVERITY_EXPLOITABILITY.get(_normalize_severity(finding), 0.0)


def _get_confidence(finding: dict) -> float:
    """Return confidence clamped to [0, 1].
    Missing field defaults to 0.7 — VulnScanner findings don't emit confidence;
    BehavioralRisk findings always include it.
    """
    raw = finding.get("confidence")
    if raw is None:
        return 0.7
    try:
        return max(0.0, min(1.0, float(raw)))
    except (ValueError, TypeError):
        return 0.7


def _category_key(finding: dict) -> str:
    """Return the grouping key for a finding (OWASP category or risk type)."""
    return (
        finding.get("owasp_category")
        or finding.get("risk_type")
        or "unknown"
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def calculate_scores(findings: list[dict]) -> dict:
    """Compute deterministic risk scores from a finalized list of findings.

    Args:
        findings: Combined VulnScanner + BehavioralRisk finding dicts after
                  the Skeptic pass. Disputed findings are included; their
                  confidence is already set by the source agent.

    Returns:
        {
            "overall_score":   float,          # 0–10, rounded to 1 dp
            "severity_counts": dict[str, int], # counts per severity level
            "owasp":           dict[str, float], # max rule_score per category
            "cvss_like":       {"impact": float, "exploitability": float}
        }
    """
    if not findings:
        return {
            "overall_score": 0.0,
            "severity_counts": dict(_ZERO_COUNTS),
            "owasp": {},
            "cvss_like": {"impact": 0.0, "exploitability": 0.0},
        }

    severity_counts: dict[str, int] = dict(_ZERO_COUNTS)
    category_scores: dict[str, float] = {}
    max_impact = 0.0
    max_exploitability = 0.0

    for finding in findings:
        severity = _normalize_severity(finding)
        if severity in severity_counts:
            severity_counts[severity] += 1

        impact = _get_impact(finding)
        exploitability = _get_exploitability(finding)
        confidence = _get_confidence(finding)

        base_score = (impact * exploitability) / 10.0
        rule_score = base_score * confidence

        logger.info(
            "[score_calculator] finding=%s confidence=%s rule_score=%s",
            finding.get("id"),
            confidence,
            rule_score,
        )

        cat = _category_key(finding)
        if cat not in category_scores or rule_score > category_scores[cat]:
            category_scores[cat] = rule_score

        if impact > max_impact:
            max_impact = impact
        if exploitability > max_exploitability:
            max_exploitability = exploitability

    overall = max(category_scores.values()) if category_scores else 0.0

    return {
        "overall_score": round(overall, 1),
        "severity_counts": severity_counts,
        "owasp": {k: round(v, 2) for k, v in category_scores.items()},
        "cvss_like": {
            "impact": round(max_impact, 1),
            "exploitability": round(max_exploitability, 1),
        },
    }