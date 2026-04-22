"use client";

import {
  VulnFinding,
  BehavioralFinding,
  BehavioralSignals,
  ComputedScores,
} from "@/hooks/useAnalysis";
import styles from "./FindingsPanel.module.css";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface FindingsPanelProps {
  findings: {
    vuln: VulnFinding[];
    behavioral: BehavioralFinding[];
    signals: BehavioralSignals | null;
  };
  computedScores?: ComputedScores | null;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SEVERITY_COLORS: Record<string, string> = {
  critical: "var(--severity-critical, #ff4444)",
  high: "var(--severity-high, #ff8800)",
  medium: "var(--severity-medium, #ffcc00)",
  low: "var(--severity-low, #44aaff)",
  info: "var(--severity-info, #888888)",
};

const SIGNAL_LEVEL_COLORS: Record<string, string> = {
  low: "var(--severity-info, #888888)",
  medium: "var(--severity-medium, #ffcc00)",
  high: "var(--severity-high, #ff8800)",
};

// Human-readable labels for behavioral risk_type keys
const RISK_TYPE_LABELS: Record<string, string> = {
  hallucinated_api: "Hallucinated API",
  prompt_injection_surface: "Prompt Injection Surface",
  non_deterministic_output_handling: "Non-Deterministic Output Handling",
  unsafe_llm_output_deserialization: "Unsafe LLM Output Deserialization",
  assumed_context_dependency: "Assumed Context Dependency",
  missing_failure_boundary: "Missing Failure Boundary",
  over_trust_of_model_output: "Over-Trust of Model Output",
  context_window_boundary_violation: "Context Window Boundary Violation",
  identity_confusion: "Identity Confusion",
  cost_unbounded_execution: "Cost Unbounded Execution",
  stale_grounding: "Stale Grounding",
  invisible_model_substitution: "Invisible Model Substitution",
};

function formatRiskType(raw: string): string {
  return (
    RISK_TYPE_LABELS[raw] ??
    raw.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase())
  );
}

// ---------------------------------------------------------------------------
// Score display
// ---------------------------------------------------------------------------

function scoreColor(score: number): string {
  if (score >= 7.0) return "var(--severity-high, #ff8800)";
  if (score >= 4.0) return "var(--severity-medium, #ffcc00)";
  if (score > 0) return "var(--severity-low, #44aaff)";
  return "var(--severity-info, #888888)";
}

function ScoreSection({ scores }: { scores: ComputedScores }) {
  const {
    overall_score,
    severity_counts,
    composition_bonus,
    signal_floors,
    cvss_like,
  } = scores;
  const color = scoreColor(overall_score);

  const activeFloors = Object.entries(signal_floors ?? {}).filter(
    ([, v]) => v > 0.5,
  );

  return (
    <div className={styles.scoreSection}>
      <div className={styles.scoreHeader}>
        <div className={styles.overallScore}>
          <span className={styles.scoreValue} style={{ color }}>
            {overall_score.toFixed(1)}
          </span>
          <span className={styles.scoreLabel}>/ 10 Risk Score</span>
        </div>
        <div className={styles.severityCounts}>
          {(["critical", "high", "medium", "low"] as const).map((sev) => {
            const count = severity_counts[sev] ?? 0;
            if (count === 0) return null;
            return (
              <span
                key={sev}
                className={styles.severityCount}
                style={{ color: SEVERITY_COLORS[sev] }}
              >
                {count} {sev}
              </span>
            );
          })}
        </div>
      </div>

      {composition_bonus && (
        <div className={styles.compositionBadge}>
          ⚠ Compositional risk — co-occurring risk types amplified this score
        </div>
      )}

      {activeFloors.length > 0 && (
        <div className={styles.signalFloors}>
          <span className={styles.floorsLabel}>Elevated signal domains:</span>
          <div className={styles.floorTags}>
            {activeFloors.map(([cat]) => (
              <span key={cat} className={styles.floorTag}>
                {formatRiskType(cat)}
              </span>
            ))}
          </div>
        </div>
      )}

      <div className={styles.cvssLike}>
        <span className={styles.cvssLikeItem}>
          Impact <strong>{cvss_like.impact.toFixed(1)}</strong>
        </span>
        <span className={styles.cvssLikeSep}>·</span>
        <span className={styles.cvssLikeItem}>
          Exploitability <strong>{cvss_like.exploitability.toFixed(1)}</strong>
        </span>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// CVSS badge
// ---------------------------------------------------------------------------

function cvssColor(score: number | null): string {
  if (score === null) return "#888888";
  if (score >= 9.0) return "var(--severity-critical, #ff4444)";
  if (score >= 7.0) return "var(--severity-high, #ff8800)";
  if (score >= 4.0) return "var(--severity-medium, #ffcc00)";
  if (score > 0) return "var(--severity-low, #44aaff)";
  return "#888888";
}

function CvssScoreBadge({
  score,
  vector,
}: {
  score: number | null;
  vector: string | null;
}) {
  if (score === null) return null;
  const color = cvssColor(score);
  const label =
    score >= 9
      ? "Critical"
      : score >= 7
        ? "High"
        : score >= 4
          ? "Medium"
          : "Low";

  return (
    <div className={styles.cvssBadge} title={vector ?? undefined}>
      <span className={styles.cvssScore} style={{ color }}>
        {score.toFixed(1)}
      </span>
      <span className={styles.cvssLabel} style={{ color }}>
        {label}
      </span>
      {vector && (
        <span className={styles.cvssVector}>
          {vector.replace("CVSS:3.1/", "")}
        </span>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Finding cards
// ---------------------------------------------------------------------------

function FindingCard({ finding }: { finding: VulnFinding }) {
  const severityColor = SEVERITY_COLORS[finding.severity] ?? "#888";

  return (
    <div
      className={`${styles.findingCard} ${finding.disputed ? styles.disputed : ""}`}
    >
      <div className={styles.findingHeader}>
        <span className={styles.findingId}>{finding.id}</span>
        <span
          className={styles.findingSeverity}
          style={{ color: severityColor }}
        >
          {finding.severity.toUpperCase()}
        </span>
        {finding.disputed && (
          <span
            className={styles.disputedBadge}
            title={finding.dispute_rationale ?? undefined}
          >
            DISPUTED
          </span>
        )}
      </div>
      <div className={styles.findingTitle}>{finding.title}</div>
      <div className={styles.findingLocation}>{finding.location}</div>
      <div className={styles.findingOwasp}>{finding.owasp_category}</div>
      <CvssScoreBadge score={finding.cvss_score} vector={finding.cvss_vector} />
    </div>
  );
}

function BehavioralFindingCard({ finding }: { finding: BehavioralFinding }) {
  const severityColor = SEVERITY_COLORS[finding.severity] ?? "#888";

  return (
    <div
      className={`${styles.findingCard} ${finding.disputed ? styles.disputed : ""}`}
    >
      <div className={styles.findingHeader}>
        <span className={styles.findingId}>{finding.id}</span>
        <span
          className={styles.findingSeverity}
          style={{ color: severityColor }}
        >
          {finding.severity.toUpperCase()}
        </span>
        {finding.disputed && (
          <span
            className={styles.disputedBadge}
            title={finding.dispute_rationale ?? undefined}
          >
            DISPUTED
          </span>
        )}
      </div>
      <div className={styles.findingTitle}>
        {formatRiskType(finding.risk_type)}
      </div>
      <div className={styles.findingLocation}>{finding.location}</div>
      {finding.description && (
        <div className={styles.findingDescription}>{finding.description}</div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Signals section
// ---------------------------------------------------------------------------

function SignalLevelBadge({ level }: { level: string }) {
  const color = SIGNAL_LEVEL_COLORS[level] ?? "#888888";
  return (
    <span
      className={styles.signalLevelBadge}
      style={{ color, borderColor: `${color}40` }}
    >
      {level.toUpperCase()}
    </span>
  );
}

function BehavioralSignalsSection({ signals }: { signals: BehavioralSignals }) {
  const rows: Array<{
    key: keyof BehavioralSignals;
    label: string;
    indicators?: string[];
    packages?: string[];
  }> = [
    {
      key: "hallucination_markers",
      label: "Hallucination Markers",
      indicators: signals.hallucination_markers.indicators,
    },
    {
      key: "nondeterminism_sensitivity",
      label: "Nondeterminism Sensitivity",
    },
    {
      key: "dependency_volatility",
      label: "Dependency Volatility",
      packages: signals.dependency_volatility.suspicious_packages ?? [],
    },
    {
      key: "context_integrity",
      label: "Context Integrity",
    },
    {
      key: "operational_safety",
      label: "Operational Safety",
    },
  ];

  return (
    <div className={styles.section}>
      <div className={styles.sectionHeader}>
        <span className={styles.sectionTitle}>Behavioral Signals</span>
      </div>
      <div className={styles.signalsList}>
        {rows.map(({ key, label, indicators, packages }) => {
          const signal = signals[key] as { level: string; rationale: string };
          if (!signal) return null;
          return (
            <div key={key} className={styles.signalRow}>
              <div className={styles.signalHeader}>
                <span className={styles.signalLabel}>{label}</span>
                <SignalLevelBadge level={signal.level} />
              </div>
              <div className={styles.signalRationale}>{signal.rationale}</div>
              {indicators && indicators.length > 0 && (
                <ul className={styles.tagList}>
                  {indicators.map((ind, i) => (
                    <li key={i} className={styles.tagItem}>
                      {ind}
                    </li>
                  ))}
                </ul>
              )}
              {packages && packages.length > 0 && (
                <ul className={styles.tagList}>
                  {packages.map((pkg, i) => (
                    <li key={i} className={styles.tagItem}>
                      {pkg}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main panel
// ---------------------------------------------------------------------------

export function FindingsPanel({
  findings,
  computedScores,
}: FindingsPanelProps) {
  const hasContent =
    findings.vuln.length > 0 ||
    findings.behavioral.length > 0 ||
    findings.signals != null ||
    computedScores != null;

  if (!hasContent) return null;

  return (
    <div className={styles.panel}>
      {computedScores != null && <ScoreSection scores={computedScores} />}

      {findings.vuln.length > 0 && (
        <div className={styles.section}>
          <div className={styles.sectionHeader}>
            <span className={styles.sectionTitle}>Vulnerabilities</span>
            <span className={styles.sectionCount}>{findings.vuln.length}</span>
          </div>
          <div className={styles.findingsList}>
            {findings.vuln.map((f) => (
              <FindingCard key={f.id} finding={f} />
            ))}
          </div>
        </div>
      )}

      {findings.behavioral.length > 0 && (
        <div className={styles.section}>
          <div className={styles.sectionHeader}>
            <span className={styles.sectionTitle}>Behavioral Risks</span>
            <span className={styles.sectionCount}>
              {findings.behavioral.length}
            </span>
          </div>
          <div className={styles.findingsList}>
            {findings.behavioral.map((f) => (
              <BehavioralFindingCard key={f.id} finding={f} />
            ))}
          </div>
        </div>
      )}

      {findings.signals && (
        <BehavioralSignalsSection signals={findings.signals} />
      )}
    </div>
  );
}
