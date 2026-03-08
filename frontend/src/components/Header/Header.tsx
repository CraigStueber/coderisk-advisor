"use client";

import styles from "./Header.module.css";

export function Header() {
  return (
    <header className={styles.header}>
      <div className={styles.left}>
        <span className={styles.logo}>
          <svg
            xmlns="http://www.w3.org/2000/svg"
            viewBox="0 0 64 64"
            className={styles.logoMark}
            aria-hidden="true"
          >
            <path
              d="M32 10 L48 16 V30 C48 42 40 50 32 54 C24 50 16 42 16 30 V16 Z"
              fill="none"
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
          CodeRisk Advisor
        </span>
        <span className={styles.badge}>BETA</span>
      </div>
      <div className={styles.right}>
        <span className={styles.meta}>Multi-agent security review</span>
        <a
          href="https://craigstueber.com"
          target="_blank"
          rel="noopener noreferrer"
          className={styles.link}
        >
          by Craig Stueber
        </a>
      </div>
    </header>
  );
}
