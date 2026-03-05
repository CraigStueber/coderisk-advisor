"use client";

import { useState, useRef, useCallback } from "react";
import { ChatMessage } from "@/components/ChatPanel/ChatPanel";
import { AgentState } from "@/components/AgentStatusBar/AgentStatusBar";

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

export function useAnalysis() {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [agentStatuses, setAgentStatuses] =
    useState<AgentState[]>(INITIAL_AGENT_STATES);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [sessionId, setSessionId] = useState<string | null>(null);

  // Ref to track the streaming message index
  const streamingIndexRef = useRef<number>(-1);

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
    async (body: Record<string, unknown>, userMessage: string) => {
      setIsAnalyzing(true);
      resetAgentStatuses();

      // Add user message
      setMessages((prev) => [...prev, { role: "user", content: userMessage }]);

      // Add empty assistant message for streaming
      setMessages((prev) => {
        streamingIndexRef.current = prev.length;
        return [...prev, { role: "assistant", content: "", isStreaming: true }];
      });

      try {
        const headers: Record<string, string> = {
          "Content-Type": "application/json",
        };
        if (sessionId) {
          headers["X-Session-ID"] = sessionId;
        }

        const res = await fetch(`${API_URL}/api/analyze`, {
          method: "POST",
          headers,
          body: JSON.stringify(body),
        });

        // Capture session ID from response header
        const newSessionId = res.headers.get("X-Session-ID");
        if (newSessionId) {
          setSessionId(newSessionId);
          // Persist in sessionStorage for page reload resilience
          sessionStorage.setItem("coderisk_session_id", newSessionId);
        }

        if (!res.ok || !res.body) {
          throw new Error(`Request failed: ${res.status}`);
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

          for (const line of lines) {
            if (line.startsWith("event: ")) {
              // Event type is on this line, data follows
              continue;
            }

            if (line.startsWith("data: ")) {
              const rawEvent = line.slice(6);
              // Look back for the event type
              const eventTypeLine = lines[lines.indexOf(line) - 1];
              const eventType = eventTypeLine?.startsWith("event: ")
                ? eventTypeLine.slice(7).trim()
                : "message";

              try {
                const data = JSON.parse(rawEvent);
                handleSSEEvent(eventType, data);
              } catch {
                // Partial JSON — wait for more data
              }
            }
          }
        }
      } catch (err) {
        console.error("Stream error:", err);
        setMessages((prev) =>
          prev.map((m, i) =>
            i === streamingIndexRef.current
              ? {
                  ...m,
                  content: "An error occurred. Please try again.",
                  isStreaming: false,
                }
              : m,
          ),
        );
      } finally {
        // Mark streaming complete
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
          const agent = data.agent as string;
          const status = data.status as AgentState["status"];
          const detail = data.detail as string | undefined;
          updateAgentStatus(agent, status, detail);
          break;
        }
        case "token": {
          const text = data.text as string;
          setMessages((prev) =>
            prev.map((m, i) =>
              i === streamingIndexRef.current
                ? { ...m, content: m.content + text }
                : m,
            ),
          );
          break;
        }
        case "done": {
          // Session ID already captured from response header
          break;
        }
        case "error": {
          const message = data.message as string;
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

  const submitCode = useCallback(
    (params: {
      code: string;
      message: string;
      filename?: string;
      language: string;
      flaggedAsAiGenerated: boolean;
    }) => {
      stream(
        {
          code: params.code,
          message: params.message,
          filename: params.filename,
          language: params.language,
          flagged_as_ai_generated: params.flaggedAsAiGenerated,
        },
        params.message,
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
    isAnalyzing,
    sessionId,
    submitCode,
    submitFollowUp,
  };
}
