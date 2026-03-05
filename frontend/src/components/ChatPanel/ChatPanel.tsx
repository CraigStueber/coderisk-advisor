"use client";

import { useEffect, useRef, useState } from "react";
import {
  AgentStatusBar,
  AgentState,
} from "@/components/AgentStatusBar/AgentStatusBar";
import styles from "./ChatPanel.module.css";

export interface ChatMessage {
  role: "user" | "assistant";
  content: string;
  isStreaming?: boolean;
}

interface ChatPanelProps {
  messages: ChatMessage[];
  agentStatuses: AgentState[];
  isAnalyzing: boolean;
  onFollowUp: (message: string) => void;
  sessionId: string | null;
}

export function ChatPanel({
  messages,
  agentStatuses,
  isAnalyzing,
  onFollowUp,
  sessionId,
}: ChatPanelProps) {
  const [input, setInput] = useState("");
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  // Auto-scroll to bottom on new messages
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const handleSubmit = () => {
    if (!input.trim() || isAnalyzing || !sessionId) return;
    onFollowUp(input.trim());
    setInput("");
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSubmit();
    }
  };

  const isEmpty = messages.length === 0;

  return (
    <div className={styles.panel}>
      {/* Agent status bar */}
      <AgentStatusBar agents={agentStatuses} />

      {/* Messages */}
      <div className={styles.messages}>
        {isEmpty ? (
          <EmptyState />
        ) : (
          messages.map((msg, i) => <Message key={i} message={msg} />)
        )}
        <div ref={messagesEndRef} />
      </div>

      {/* Input */}
      <div className={styles.inputArea}>
        {!sessionId && (
          <p className={styles.inputHint}>
            Submit code on the left to start a session
          </p>
        )}
        <div
          className={`${styles.inputRow} ${!sessionId ? styles.inputDisabled : ""}`}
        >
          <textarea
            ref={inputRef}
            className={styles.input}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder={
              sessionId
                ? "Ask about a finding, request remediation, or dig deeper..."
                : "Waiting for code submission..."
            }
            disabled={!sessionId || isAnalyzing}
            rows={2}
          />
          <button
            className={styles.sendBtn}
            onClick={handleSubmit}
            disabled={!input.trim() || isAnalyzing || !sessionId}
          >
            {isAnalyzing ? <span className={styles.spinner} /> : <span>↑</span>}
          </button>
        </div>
        <p className={styles.inputFooter}>
          Enter to send · Shift+Enter for new line
          {sessionId && (
            <span className={styles.sessionId}>
              session: {sessionId.slice(0, 8)}
            </span>
          )}
        </p>
      </div>
    </div>
  );
}

function Message({ message }: { message: ChatMessage }) {
  return (
    <div className={`${styles.message} ${styles[message.role]}`}>
      <span className={styles.roleLabel}>
        {message.role === "user" ? "you" : "advisor"}
      </span>
      <div className={styles.messageContent}>
        {message.content}
        {message.isStreaming && <span className={styles.cursor} />}
      </div>
    </div>
  );
}

function EmptyState() {
  return (
    <div className={styles.emptyState}>
      <div className={styles.emptyIcon}>▸</div>
      <p className={styles.emptyTitle}>Multi-agent security review</p>
      <p className={styles.emptyDesc}>
        Paste or upload Python code on the left.
        <br />
        Four specialized agents will analyze it in parallel
        <br />
        and walk you through the findings.
      </p>
      <div className={styles.agentList}>
        {[
          {
            name: "VulnScanner",
            desc: "OWASP Top 10",
            color: "var(--agent-vuln)",
          },
          {
            name: "BehavioralRisk",
            desc: "AI-specific failure modes",
            color: "var(--agent-behavioral)",
          },
          {
            name: "Skeptic",
            desc: "False positive review",
            color: "var(--agent-skeptic)",
          },
          {
            name: "Remediation",
            desc: "Prioritized fixes",
            color: "var(--agent-remediation)",
          },
        ].map((agent) => (
          <div key={agent.name} className={styles.agentItem}>
            <span
              className={styles.agentDot}
              style={{ background: agent.color }}
            />
            <span className={styles.agentName} style={{ color: agent.color }}>
              {agent.name}
            </span>
            <span className={styles.agentDesc}>{agent.desc}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
