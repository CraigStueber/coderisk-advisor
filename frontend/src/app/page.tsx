"use client";

import { Header } from "@/components/Header/Header";
import { CodePanel } from "@/components/CodePanel/CodePanel";
import { ChatPanel } from "@/components/ChatPanel/ChatPanel";
import { FindingsPanel } from "@/components/FindingsPanel/FindingsPanel";
import { useAnalysis } from "@/hooks/useAnalysis";
import styles from "./page.module.css";
import "./globals.css";

export default function Home() {
  const analysis = useAnalysis();
  //Adding a comment to trigger a change for deployment testing
  return (
    <div className={styles.root}>
      <Header />
      <main className={styles.workspace}>
        <CodePanel
          onSubmit={analysis.submitCode}
          isAnalyzing={analysis.isAnalyzing}
        />
        <div className={styles.divider} />
        <ChatPanel
          messages={analysis.messages}
          agentStatuses={analysis.agentStatuses}
          isAnalyzing={analysis.isAnalyzing}
          onFollowUp={analysis.submitFollowUp}
          sessionId={analysis.sessionId}
        />
        <FindingsPanel findings={analysis.findings} />
      </main>
    </div>
  );
}
