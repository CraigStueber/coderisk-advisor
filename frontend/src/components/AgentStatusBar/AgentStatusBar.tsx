"use client";

import styles from "./AgentStatusBar.module.css";

export type AgentStatus = "idle" | "running" | "complete" | "error";

export interface AgentState {
  name: string;
  displayName: string;
  status: AgentStatus;
  detail?: string;
  color: string;
}

interface AgentStatusBarProps {
  agents: AgentState[];
}

export function AgentStatusBar({ agents }: AgentStatusBarProps) {
  const activeAgents = agents.filter((a) => a.status !== "idle");
  if (activeAgents.length === 0) return null;

  return (
    <div className={styles.bar}>
      {agents.map((agent) => {
        if (agent.status === "idle") return null;
        return (
          <div
            key={agent.name}
            className={`${styles.agent} ${styles[agent.status]}`}
            style={{ "--agent-color": agent.color } as React.CSSProperties}
          >
            <span className={styles.dot} />
            <span className={styles.name}>{agent.displayName}</span>
            {agent.detail && (
              <span className={styles.detail}>{agent.detail}</span>
            )}
          </div>
        );
      })}
    </div>
  );
}
