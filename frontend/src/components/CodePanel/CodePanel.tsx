"use client";

import { useState, useRef, useCallback } from "react";
import {
  ExampleModal,
  ExampleSnippet,
} from "@/components/ExampleModal/ExampleModal";
import styles from "./CodePanel.module.css";

interface CodePanelProps {
  onSubmit: (params: {
    code: string;
    message: string;
    filename?: string;
    language: string;
    flaggedAsAiGenerated: boolean;
  }) => void;
  isAnalyzing: boolean;
}

export function CodePanel({ onSubmit, isAnalyzing }: CodePanelProps) {
  const [code, setCode] = useState("");
  const [filename, setFilename] = useState<string | undefined>();
  const [language, setLanguage] = useState("python");
  const [flaggedAsAiGenerated, setFlaggedAsAiGenerated] = useState(false);
  const [isDragging, setIsDragging] = useState(false);
  const [showExamples, setShowExamples] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const ACCEPTED_EXTENSIONS = [".py", ".js", ".ts", ".jsx", ".tsx"];

  const detectLanguage = (fname: string): string => {
    if (fname.endsWith(".py")) return "python";
    if (fname.endsWith(".ts") || fname.endsWith(".tsx")) return "typescript";
    if (fname.endsWith(".js") || fname.endsWith(".jsx")) return "javascript";
    return "python";
  };

  const handleFileUpload = useCallback(async (file: File) => {
    const isAccepted = ACCEPTED_EXTENSIONS.some((ext) =>
      file.name.endsWith(ext),
    );
    if (!isAccepted) {
      alert("Accepted file types: .py, .js, .ts, .jsx, .tsx");
      return;
    }
    const formData = new FormData();
    formData.append("file", file);
    try {
      const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/upload`, {
        method: "POST",
        body: formData,
      });
      const data = await res.json();
      if (data.code) {
        setCode(data.code);
        setFilename(data.filename);
        setLanguage(detectLanguage(data.filename ?? file.name));
      }
    } catch {
      alert("File upload failed");
    }
  }, []);

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setIsDragging(false);
      const file = e.dataTransfer.files[0];
      if (file) handleFileUpload(file);
    },
    [handleFileUpload],
  );

  const handleExampleSelect = (snippet: ExampleSnippet) => {
    setCode(snippet.code);
    setFilename(snippet.filename);
    setLanguage(snippet.language);
    setShowExamples(false);
  };

  const handleSubmit = () => {
    if (!code.trim() || isAnalyzing) return;
    onSubmit({
      code,
      message:
        "Please analyze this code for security vulnerabilities and behavioral risks.",
      filename,
      language,
      flaggedAsAiGenerated,
    });
  };

  const lineCount = code.split("\n").length;

  return (
    <>
      <div className={styles.panel}>
        <div className={styles.panelHeader}>
          <span className={styles.panelTitle}>Code Input</span>
          {filename && <span className={styles.filename}>{filename}</span>}
          <button
            className={styles.exampleBtn}
            onClick={() => setShowExamples(true)}
            disabled={isAnalyzing}
          >
            Try an example
          </button>
          <button
            className={styles.uploadBtn}
            onClick={() => fileInputRef.current?.click()}
            disabled={isAnalyzing}
          >
            Upload file
          </button>
          <input
            ref={fileInputRef}
            type="file"
            accept=".py,.js,.ts,.jsx,.tsx"
            style={{ display: "none" }}
            onChange={(e) => {
              const file = e.target.files?.[0];
              if (file) handleFileUpload(file);
            }}
          />
        </div>

        <div
          className={`${styles.editorWrapper} ${isDragging ? styles.dragging : ""}`}
          onDragOver={(e) => {
            e.preventDefault();
            setIsDragging(true);
          }}
          onDragLeave={() => setIsDragging(false)}
          onDrop={handleDrop}
        >
          <div className={styles.lineNumbers}>
            {Array.from({ length: Math.max(lineCount, 20) }, (_, i) => (
              <span key={i + 1}>{i + 1}</span>
            ))}
          </div>
          <textarea
            className={styles.editor}
            value={code}
            onChange={(e) => setCode(e.target.value)}
            placeholder="Paste code here, upload a file, or try an example..."
            spellCheck={false}
            disabled={isAnalyzing}
          />
          {isDragging && (
            <div className={styles.dropOverlay}>Drop file to load</div>
          )}
        </div>

        <div className={styles.footer}>
          <div className={styles.footerLeft}>
            <label className={styles.aiToggle}>
              <input
                type="checkbox"
                checked={flaggedAsAiGenerated}
                onChange={(e) => setFlaggedAsAiGenerated(e.target.checked)}
                disabled={isAnalyzing}
              />
              <span className={styles.toggleLabel}>AI-generated code</span>
              <span className={styles.toggleHint}>
                Deeper behavioral analysis
              </span>
            </label>
          </div>
          <div className={styles.footerRight}>
            {code && (
              <span className={styles.lineCount}>
                {lineCount} lines · {language}
              </span>
            )}
            <button
              className={styles.analyzeBtn}
              onClick={handleSubmit}
              disabled={!code.trim() || isAnalyzing}
            >
              {isAnalyzing ? (
                <>
                  <span className={styles.spinner} />
                  Analyzing
                </>
              ) : (
                <>
                  <span className={styles.btnIcon}>▸</span>Analyze
                </>
              )}
            </button>
          </div>
        </div>
      </div>

      {showExamples && (
        <ExampleModal
          onSelect={handleExampleSelect}
          onClose={() => setShowExamples(false)}
        />
      )}
    </>
  );
}
