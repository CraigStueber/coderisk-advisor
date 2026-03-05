"use client";

import styles from "./Header.module.css";

export function Header() {
  return (
    <header className={styles.header}>
      <div className={styles.left}>
        <span className={styles.logo}>
          <span className={styles.logoMark}>▸</span>
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
