"use client";

import styles from "./MobileGate.module.css";

export function MobileGate() {
  return (
    <div className={styles.overlay}>
      <div className={styles.card}>
        <div className={styles.iconWrapper}>
          <svg
            xmlns="http://www.w3.org/2000/svg"
            viewBox="0 0 64 64"
            width="64"
            height="64"
            aria-hidden="true"
          >
            <rect width="64" height="64" rx="12" fill="#0f172a" />
            <path
              d="M32 10 L48 16 V30 C48 42 40 50 32 54 C24 50 16 42 16 30 V16 Z"
              fill="#1e293b"
              stroke="#ffffff"
              strokeWidth="2"
            />
            <text
              x="32"
              y="38"
              fontFamily="monospace"
              fontSize="18"
              textAnchor="middle"
              fill="#ffffff"
            >
              {"</>"}
            </text>
          </svg>
        </div>

        <h1 className={styles.title}>CodeRisk Advisor</h1>
        <p className={styles.tagline}>
          Multi-agent AI security review for Python, JavaScript, and TypeScript
        </p>

        <div className={styles.divider} />

        <p className={styles.message}>
          CodeRisk Advisor is a desktop-class tool designed for code review
          workflows. For the best experience, please open it on a screen wider
          than 1000px.
        </p>

        <div className={styles.techRow}>
          <span className={styles.tech}>LangGraph</span>
          <span className={styles.tech}>OWASP Top 10</span>
          <span className={styles.tech}>CVSS 3.1</span>
          <span className={styles.tech}>5-Agent Pipeline</span>
        </div>
      </div>
    </div>
  );
}
