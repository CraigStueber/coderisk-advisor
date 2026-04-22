"""
CodeRisk Advisor — Deterministic Score Calculator

Pure Python. No LLM calls. Operates on the finalized combined list of
VulnScanner + BehavioralRisk findings after the Skeptic pass, plus the
behavioral signals object produced by the BehavioralRisk agent.

Score model
-----------
Per finding:
    impact          — explicit field if present, else derived from severity
    exploitability  — explicit field if present, then cvss_score, then severity
    confidence      — finding["confidence"], clamped 0–1
                      halved if finding is disputed (penalty, not exclusion)

    base_score  = (impact * exploitability) / 10   → 0–10
    rule_score  = base_score * confidence           → 0–10

Per category (OWASP category or behavioral risk_type):
    category_score = primary_rule_score
                   + 0.2 * sum(secondary rule_scores)
                   + signal_floor

    Where:
      primary        = highest rule_score in category
      secondary      = all other rule_scores in category (diminishing returns)
      signal_floor   = floor contribution from behavioral signal level for this
                       category's domain (low=0.0, medium=0.5, high=1.5)

Overall:
    raw_overall   = max(category_scores)
    overall_score = min(raw_overall * composition_multiplier, 10.0)
                                                    → rounded to 1 dp

Compositional risk bonus:
    Certain finding type combinations compound real-world risk beyond what
    individual category scores capture. A 1.15x multiplier is applied when
    any dangerous pair co-occurs in confirmed (non-disputed) findings:

      PROMPT_INJECTION_SURFACE + IDENTITY_CONFUSION
        → structural erosion amplifies active injection exploitability

      UNSAFE_LLM_OUTPUT_DESERIALIZATION + OVER_TRUST_OF_MODEL_OUTPUT
        → model output reaches both execution and access-control simultaneously

      COST_UNBOUNDED_EXECUTION + MISSING_FAILURE_BOUNDARY
        → unbounded loops with no circuit breaker: operational catastrophe risk

Signal floors:
    Behavioral signals contribute a floor score to their associated category
    even when no findings exist in that category. A submission with zero
    findings but operational_safety=high scores above 0.0.

Disputed findings:
    Included at half confidence rather than excluded. A confirmed medium
    finding always scores higher than a disputed high finding.
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

_DISPUTED_CONFIDENCE_MULTIPLIER = 0.5
_SECONDARY_FINDING_WEIGHT = 0.2
_COMPOSITION_MULTIPLIER = 1.15

# Signal level → floor score added to associated category buckets
_SIGNAL_FLOOR: dict[str, float] = {
    "low": 0.0,
    "medium": 0.5,
    "high": 1.5,
}

# Behavioral signal name → risk_type categories it applies to
_SIGNAL_CATEGORY_MAP: dict[str, list[str]] = {
    "hallucination_markers": [
        "hallucinated_api",
    ],
    "nondeterminism_sensitivity": [
        "non_deterministic_output_handling",
        "unsafe_llm_output_deserialization",
    ],
    "dependency_volatility": [
        "hallucinated_api",
        "invisible_model_substitution",
    ],
    "context_integrity": [
        "context_window_boundary_violation",
        "identity_confusion",
        "prompt_injection_surface",
    ],
    "operational_safety": [
        "cost_unbounded_execution",
        "missing_failure_boundary",
        "stale_grounding",
        "invisible_model_substitution",
    ],
}

# Dangerous co-occurring pairs — triggers composition multiplier on overall score
_DANGEROUS_PAIRS: list[tuple[str, str]] = [
    ("prompt_injection_surface", "identity_confusion"),
    ("unsafe_llm_output_deserialization", "over_trust_of_model_output"),
    ("cost_unbounded_execution", "missing_failure_boundary"),
]


# ---------------------------------------------------------------------------
# Field extractors
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
    """
    Confidence clamped to [0, 1].

    Defaults to 0.7 when absent — VulnScanner findings don't emit confidence;
    BehavioralRisk findings always do.

    Disputed findings are penalized to half confidence rather than excluded.
    A confirmed finding of equal severity always scores higher than a disputed one.
    """
    raw = finding.get("confidence")
    if raw is None:
        base = 0.7
    else:
        try:
            base = max(0.0, min(1.0, float(raw)))
        except (ValueError, TypeError):
            base = 0.7

    if finding.get("disputed"):
        base *= _DISPUTED_CONFIDENCE_MULTIPLIER

    return base


def _category_key(finding: dict) -> str:
    """Group by OWASP category for VulnScanner, risk_type for BehavioralRisk."""
    return (
        finding.get("owasp_category")
        or finding.get("risk_type")
        or "unknown"
    )


def _signal_level(signals: dict, signal_name: str) -> str:
    """Safely extract a normalized signal level string, defaulting to 'low'."""
    signal = signals.get(signal_name)
    if not isinstance(signal, dict):
        return "low"
    raw = str(signal.get("level", "low")).lower()
    # Handle Pydantic enum repr: "signallevel.high" → "high"
    return raw.split(".")[-1]


# ---------------------------------------------------------------------------
# Signal floor computation
# ---------------------------------------------------------------------------

def _compute_signal_floors(signals: dict) -> dict[str, float]:
    """
    Build a category → signal floor contribution map.

    Each behavioral signal maps to one or more risk_type categories. The
    floor for a category is the max across all signals that apply to it,
    preventing double-counting when multiple signals share a category.
    """
    floors: dict[str, float] = {}

    for signal_name, categories in _SIGNAL_CATEGORY_MAP.items():
        level = _signal_level(signals, signal_name)
        floor = _SIGNAL_FLOOR.get(level, 0.0)
        for cat in categories:
            if floor > floors.get(cat, 0.0):
                floors[cat] = floor

    return floors


# ---------------------------------------------------------------------------
# Compositional risk detection
# ---------------------------------------------------------------------------

def _get_composition_multiplier(findings: list[dict]) -> float:
    """
    Return 1.15 if any dangerous risk_type pair co-occurs in confirmed findings,
    otherwise 1.0.

    Only confirmed (non-disputed) findings are evaluated — disputed findings
    should not trigger compounding since their exploitability is uncertain.
    """
    confirmed_types = {
        f.get("risk_type", "")
        for f in findings
        if not f.get("disputed") and f.get("risk_type")
    }

    for type_a, type_b in _DANGEROUS_PAIRS:
        if type_a in confirmed_types and type_b in confirmed_types:
            logger.info(
                "[score_calculator] compositional risk: %s + %s → %.2fx",
                type_a,
                type_b,
                _COMPOSITION_MULTIPLIER,
            )
            return _COMPOSITION_MULTIPLIER

    return 1.0


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def calculate_scores(findings: list[dict], signals: dict | None = None) -> dict:
    """
    Compute deterministic risk scores from the finalized findings list
    and behavioral signals.

    Args:
        findings: VulnScanner + BehavioralRisk findings merged into one list
                  after the Skeptic pass.
                  Call as: calculate_scores(vuln_findings + behavioral_findings)
        signals:  The behavioral_signals dict from state, or None.
                  Drives signal floor contributions to category scores.

    Returns:
        {
            "overall_score":     float,            # 0–10, rounded to 1 dp
            "severity_counts":   dict[str, int],   # counts per severity level
            "category_scores":   dict[str, float], # dampened score per category
            "signal_floors":     dict[str, float], # nonzero floor contributions
            "composition_bonus": bool,             # whether multiplier was applied
            "cvss_like": {
                "impact":        float,
                "exploitability":float,
            }
        }
    """
    signals = signals or {}

    logger.info(
        "[score_calculator] input count=%d ids=%s signals_present=%s",
        len(findings),
        [f.get("id") for f in findings],
        bool(signals),
    )

    signal_floors = _compute_signal_floors(signals)

    # Early return only when both findings and signals are empty
    if not findings and not any(v > 0 for v in signal_floors.values()):
        return {
            "overall_score": 0.0,
            "severity_counts": dict(_ZERO_COUNTS),
            "category_scores": {},
            "signal_floors": {},
            "composition_bonus": False,
            "cvss_like": {"impact": 0.0, "exploitability": 0.0},
        }

    severity_counts: dict[str, int] = dict(_ZERO_COUNTS)
    category_rule_scores: dict[str, list[float]] = {}
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
            "[score_calculator] id=%s severity=%s disputed=%s "
            "impact=%.1f exploitability=%.1f confidence=%.2f rule_score=%.2f",
            finding.get("id"),
            severity,
            finding.get("disputed", False),
            impact,
            exploitability,
            confidence,
            rule_score,
        )

        cat = _category_key(finding)
        category_rule_scores.setdefault(cat, []).append(rule_score)

        if impact > max_impact:
            max_impact = impact
        if exploitability > max_exploitability:
            max_exploitability = exploitability

    # Build category scores: primary + dampened secondaries + signal floor
    category_scores: dict[str, float] = {}

    # Signal-floor-only categories (no findings in that category yet)
    for cat, floor in signal_floors.items():
        if floor > 0.0 and cat not in category_rule_scores:
            category_scores[cat] = floor

    # Finding-backed categories
    for cat, rule_scores in category_rule_scores.items():
        rule_scores_sorted = sorted(rule_scores, reverse=True)
        primary = rule_scores_sorted[0]
        secondary_sum = sum(rule_scores_sorted[1:])
        floor = signal_floors.get(cat, 0.0)
        raw = primary + (_SECONDARY_FINDING_WEIGHT * secondary_sum) + floor
        category_scores[cat] = min(raw, 10.0)

    if not category_scores:
        return {
            "overall_score": 0.0,
            "severity_counts": severity_counts,
            "category_scores": {},
            "signal_floors": {k: round(v, 2) for k, v in signal_floors.items() if v > 0},
            "composition_bonus": False,
            "cvss_like": {
                "impact": round(max_impact, 1),
                "exploitability": round(max_exploitability, 1),
            },
        }

    raw_overall = max(category_scores.values())
    multiplier = _get_composition_multiplier(findings)
    overall = min(raw_overall * multiplier, 10.0)
    composition_applied = multiplier > 1.0

    logger.info(
        "[score_calculator] overall=%.1f composition_bonus=%s active_floors=%s",
        overall,
        composition_applied,
        {k: v for k, v in signal_floors.items() if v > 0},
    )

    return {
        "overall_score": round(overall, 1),
        "severity_counts": severity_counts,
        "category_scores": {k: round(v, 2) for k, v in category_scores.items()},
        "signal_floors": {k: round(v, 2) for k, v in signal_floors.items() if v > 0},
        "composition_bonus": composition_applied,
        "cvss_like": {
            "impact": round(max_impact, 1),
            "exploitability": round(max_exploitability, 1),
        },
    }