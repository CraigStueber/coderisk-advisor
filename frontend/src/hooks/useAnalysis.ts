"use client";

import { useState, useRef, useCallback } from "react";
import { ChatMessage } from "@/components/ChatPanel/ChatPanel";
import { AgentState } from "@/components/AgentStatusBar/AgentStatusBar";

export interface VulnFinding {
  id: string;
  title: string;
  owasp_category: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  cvss_score: number | null;
  cvss_vector: string | null;
  confidence: number;
  location: string;
  description: string;
  evidence: string;
  disputed: boolean;
  dispute_rationale: string | null;
}

export interface BehavioralFinding {
  id: string;
  risk_type: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  confidence: number;
  location: string;
  description: string;
  llm_specific: boolean;
  disputed: boolean;
  dispute_rationale: string | null;
}

interface SignalDimension {
  level: "low" | "medium" | "high";
  rationale: string;
}

export interface BehavioralSignals {
  hallucination_markers: SignalDimension & { indicators: string[] };
  nondeterminism_sensitivity: SignalDimension;
  dependency_volatility: SignalDimension & {
    unpinned_dependencies: number | null;
    suspicious_packages: string[] | null;
  };
  context_integrity: SignalDimension;
  operational_safety: SignalDimension;
}

export interface ComputedScores {
  overall_score: number;
  severity_counts: Record<string, number>;
  category_scores: Record<string, number>;
  signal_floors: Record<string, number>;
  composition_bonus: boolean;
  cvss_like: { impact: number; exploitability: number };
}

const AGENT_CONFIG: Record<string, { displayName: string; color: string }> = {
  VulnScanner: { displayName: "VulnScanner", color: "var(--agent-vuln)" },
  BehavioralRisk: {
    displayName: "BehavioralRisk",
    color: "var(--agent-behavioral)",
  },
  Skeptic: { displayName: "Skeptic", color: "var(--agent-skeptic)" },
  Remediation: {
    displayName: "Remediation",
    color: "var(--agent-remediation)",
  },
  Synthesizer: {
    displayName: "Synthesizer",
    color: "var(--agent-synthesizer)",
  },
};

const INITIAL_AGENT_STATES: AgentState[] = Object.entries(AGENT_CONFIG).map(
  ([name, config]) => ({
    name,
    displayName: config.displayName,
    status: "idle",
    color: config.color,
  }),
);

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8080";
const STREAM_TIMEOUT_MS = 90_000;

export function useAnalysis() {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [agentStatuses, setAgentStatuses] =
    useState<AgentState[]>(INITIAL_AGENT_STATES);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [findings, setFindings] = useState<{
    vuln: VulnFinding[];
    behavioral: BehavioralFinding[];
    signals: BehavioralSignals | null;
  }>({ vuln: [], behavioral: [], signals: null });
  const [computedScores, setComputedScores] = useState<ComputedScores | null>(
    null,
  );
  const [sessionId, setSessionId] = useState<string | null>(() => {
    if (typeof window !== "undefined") {
      return sessionStorage.getItem("coderisk_session_id");
    }
    return null;
  });

  const streamingIndexRef = useRef<number>(-1);
  const abortControllerRef = useRef<AbortController | null>(null);
  const handleSSEEventRef = useRef<
    ((eventType: string, data: Record<string, unknown>) => void) | null
  >(null);

  const resetAgentStatuses = useCallback(() => {
    setAgentStatuses(
      INITIAL_AGENT_STATES.map((a) => ({ ...a, status: "idle" })),
    );
  }, []);

  const updateAgentStatus = useCallback(
    (agentName: string, status: AgentState["status"], detail?: string) => {
      setAgentStatuses((prev) =>
        prev.map((a) => (a.name === agentName ? { ...a, status, detail } : a)),
      );
    },
    [],
  );

  const stream = useCallback(
    async (
      body: Record<string, unknown>,
      userMessage: string,
      overrideSessionId?: string | null,
    ) => {
      setIsAnalyzing(true);
      resetAgentStatuses();
      setMessages([]);
      setFindings({ vuln: [], behavioral: [], signals: null });
      setComputedScores(null);

      setMessages((prev) => [...prev, { role: "user", content: userMessage }]);

      setMessages((prev) => {
        streamingIndexRef.current = prev.length;
        return [...prev, { role: "assistant", content: "", isStreaming: true }];
      });

      const controller = new AbortController();
      abortControllerRef.current = controller;
      const timeoutId = setTimeout(() => controller.abort(), STREAM_TIMEOUT_MS);

      try {
        const headers: Record<string, string> = {
          "Content-Type": "application/json",
        };
        const activeSessionId =
          overrideSessionId !== undefined ? overrideSessionId : sessionId;
        if (activeSessionId) {
          headers["X-Session-ID"] = activeSessionId;
        }

        const res = await fetch(`${API_URL}/api/analyze`, {
          method: "POST",
          headers,
          body: JSON.stringify(body),
          signal: controller.signal,
        });

        const newSessionId = res.headers.get("X-Session-ID");
        if (newSessionId) {
          setSessionId(newSessionId);
          sessionStorage.setItem("coderisk_session_id", newSessionId);
        }

        if (res.status === 401 || res.status === 403 || res.status === 404) {
          setSessionId(null);
          sessionStorage.removeItem("coderisk_session_id");
          throw new Error("session_invalid");
        }

        if (!res.ok || !res.body) {
          throw new Error(`http:${res.status}`);
        }

        const reader = res.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;

          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split("\n");
          buffer = lines.pop() ?? "";

          let currentEventType = "message";
          for (const line of lines) {
            if (line.startsWith("event: ")) {
              currentEventType = line.slice(7).trim();
            } else if (line.startsWith("data: ")) {
              const rawData = line.slice(6);
              try {
                const data = JSON.parse(rawData);
                handleSSEEventRef.current?.(currentEventType, data);
              } catch {
                // Partial JSON — wait for more data
              }
              currentEventType = "message";
            }
          }
        }
      } catch (err) {
        const error = err as Error;
        console.error("Stream error:", error);
        let userMessage = "An error occurred. Please try again.";
        if (error.name === "AbortError") {
          userMessage = "Analysis timed out. Please try again.";
        } else if (error.message === "session_invalid") {
          userMessage =
            "Your session has expired. Please submit your code again.";
        } else if (
          error.message.startsWith("Failed to fetch") ||
          error.message.startsWith("NetworkError")
        ) {
          userMessage = "Network error. Check your connection and try again.";
        }
        setMessages((prev) =>
          prev.map((m, i) =>
            i === streamingIndexRef.current
              ? { ...m, content: userMessage, isStreaming: false }
              : m,
          ),
        );
      } finally {
        clearTimeout(timeoutId);
        abortControllerRef.current = null;
        setMessages((prev) =>
          prev.map((m, i) =>
            i === streamingIndexRef.current ? { ...m, isStreaming: false } : m,
          ),
        );
        setIsAnalyzing(false);
      }
    },
    [sessionId, resetAgentStatuses],
  );

  const handleSSEEvent = useCallback(
    (eventType: string, data: Record<string, unknown>) => {
      switch (eventType) {
        case "agent_status": {
          const agent = data.agent;
          const status = data.status;
          const detail = data.detail;
          if (typeof agent !== "string" || typeof status !== "string") {
            console.warn("[useAnalysis] Malformed agent_status event:", data);
            break;
          }
          const validStatuses: AgentState["status"][] = [
            "idle",
            "running",
            "complete",
            "error",
          ];
          if (!validStatuses.includes(status as AgentState["status"])) {
            console.warn("[useAnalysis] Unknown agent status value:", status);
            break;
          }
          updateAgentStatus(
            agent,
            status as AgentState["status"],
            typeof detail === "string" ? detail : undefined,
          );
          break;
        }
        case "token": {
          const text = data.text;
          if (typeof text !== "string") {
            console.warn("[useAnalysis] Malformed token event:", data);
            break;
          }
          setMessages((prev) =>
            prev.map((m, i) =>
              i === streamingIndexRef.current
                ? { ...m, content: m.content + text }
                : m,
            ),
          );
          break;
        }
        case "findings": {
          const vuln = data.vuln;
          const behavioral = data.behavioral;
          if (Array.isArray(vuln) && Array.isArray(behavioral)) {
            setFindings({
              vuln: vuln as VulnFinding[],
              behavioral: behavioral as BehavioralFinding[],
              signals: (data.signals as BehavioralSignals) ?? null,
            });
          }
          break;
        }
        case "scores": {
          if (data && typeof data === "object") {
            setComputedScores(data as unknown as ComputedScores);
          }
          break;
        }
        case "done": {
          break;
        }
        case "error": {
          const message = data.message;
          if (typeof message !== "string") {
            console.warn("[useAnalysis] Malformed error event:", data);
            break;
          }
          setMessages((prev) =>
            prev.map((m, i) =>
              i === streamingIndexRef.current
                ? { ...m, content: `Error: ${message}`, isStreaming: false }
                : m,
            ),
          );
          break;
        }
      }
    },
    [updateAgentStatus],
  );

  handleSSEEventRef.current = handleSSEEvent;

  const submitCode = useCallback(
    (params: {
      code: string;
      message: string;
      filename?: string;
      language: string;
      flaggedAsAiGenerated: boolean;
    }) => {
      setSessionId(null);
      sessionStorage.removeItem("coderisk_session_id");

      stream(
        {
          code: params.code,
          message: params.message,
          filename: params.filename,
          language: params.language,
          flagged_as_ai_generated: params.flaggedAsAiGenerated,
        },
        params.message,
        null,
      );
    },
    [stream],
  );

  const submitFollowUp = useCallback(
    (message: string) => {
      stream({ message }, message);
    },
    [stream],
  );

  return {
    messages,
    agentStatuses,
    findings,
    computedScores,
    isAnalyzing,
    sessionId,
    submitCode,
    submitFollowUp,
  };
}
