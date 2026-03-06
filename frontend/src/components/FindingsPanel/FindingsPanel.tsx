"use client";

import { VulnFinding } from "@/hooks/useAnalysis";
import styles from "./FindingsPanel.module.css";

interface FindingsPanelProps {
  findings: {
    vuln: VulnFinding[];
    behavioral: any[];
  };
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: "var(--severity-critical, #ff4444)",
  high: "var(--severity-high, #ff8800)",
  medium: "var(--severity-medium, #ffcc00)",
  low: "var(--severity-low, #44aaff)",
  info: "var(--severity-info, #888888)",
};

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

export function FindingsPanel({ findings }: FindingsPanelProps) {
  const hasFindings =
    findings.vuln.length > 0 || findings.behavioral.length > 0;

  if (!hasFindings) return null;

  return (
    <div className={styles.panel}>
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
            {findings.behavioral.map((f: any) => (
              <div key={f.id} className={styles.findingCard}>
                <div className={styles.findingHeader}>
                  <span className={styles.findingId}>{f.id}</span>
                  <span
                    className={styles.findingSeverity}
                    style={{ color: SEVERITY_COLORS[f.severity] ?? "#888" }}
                  >
                    {f.severity.toUpperCase()}
                  </span>
                  {f.disputed && (
                    <span className={styles.disputedBadge}>DISPUTED</span>
                  )}
                </div>
                <div className={styles.findingTitle}>{f.risk_type}</div>
                <div className={styles.findingLocation}>{f.location}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
