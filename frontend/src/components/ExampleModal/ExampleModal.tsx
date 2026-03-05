"use client";

import { useState } from "react";
import styles from "./ExampleModal.module.css";

export interface ExampleSnippet {
  id: string;
  language: "python" | "javascript" | "typescript";
  vulnType: string;
  severity: "critical" | "high" | "medium";
  title: string;
  description: string;
  code: string;
  filename: string;
}

export const EXAMPLES: ExampleSnippet[] = [
  // Python
  {
    id: "py-sqli",
    language: "python",
    vulnType: "SQL Injection",
    severity: "high",
    title: "SQL Injection via f-string",
    description: "Unsanitized user input embedded directly into a SQL query.",
    filename: "db.py",
    code: `import sqlite3

def get_user(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute(
        f"SELECT * FROM users WHERE username = '{username}'"
    )
    return cursor.fetchone()

def delete_user(user_id):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute(
        f"DELETE FROM users WHERE id = {user_id}"
    )
    conn.commit()`,
  },
  {
    id: "py-cmdi",
    language: "python",
    vulnType: "Command Injection",
    severity: "critical",
    title: "Command Injection via subprocess",
    description: "User-controlled input passed directly to a shell command.",
    filename: "files.py",
    code: `import subprocess
import os

def process_file(filename):
    # Compress and archive user-supplied file
    result = subprocess.run(
        f"tar -czf archive.tar.gz {filename}",
        shell=True,
        capture_output=True,
        text=True
    )
    return result.stdout

def get_file_info(path):
    output = os.popen(f"ls -la {path}").read()
    return output`,
  },
  {
    id: "py-deserial",
    language: "python",
    vulnType: "Insecure Deserialization",
    severity: "critical",
    title: "Unsafe pickle deserialization",
    description:
      "Deserializing untrusted data with pickle allows arbitrary code execution.",
    filename: "session.py",
    code: `import pickle
import base64
from flask import request, session

def load_user_session():
    session_data = request.cookies.get('session')
    if session_data:
        # Decode and deserialize session from cookie
        raw = base64.b64decode(session_data)
        user = pickle.loads(raw)
        return user
    return None

def save_session(user_obj):
    raw = pickle.dumps(user_obj)
    return base64.b64encode(raw).decode()`,
  },

  // JavaScript / TypeScript
  {
    id: "js-xss",
    language: "javascript",
    vulnType: "Cross-Site Scripting (XSS)",
    severity: "high",
    title: "XSS via innerHTML injection",
    description: "Unsanitized user input rendered directly into the DOM.",
    filename: "renderer.js",
    code: `function renderUserProfile(user) {
  const container = document.getElementById('profile')

  // Render user-supplied bio directly
  container.innerHTML = \`
    <div class="profile">
      <h2>\${user.name}</h2>
      <p>\${user.bio}</p>
      <a href="\${user.website}">Visit website</a>
    </div>
  \`
}

function displayComment(commentText) {
  const feed = document.getElementById('comments')
  const div = document.createElement('div')
  div.innerHTML = commentText
  feed.appendChild(div)
}`,
  },
  {
    id: "js-prototype",
    language: "javascript",
    vulnType: "Prototype Pollution",
    severity: "high",
    title: "Prototype pollution via deep merge",
    description:
      "Recursive object merge allows attackers to pollute Object.prototype.",
    filename: "utils.js",
    code: `function deepMerge(target, source) {
  for (const key of Object.keys(source)) {
    if (source[key] && typeof source[key] === 'object') {
      if (!target[key]) target[key] = {}
      deepMerge(target[key], source[key])
    } else {
      target[key] = source[key]
    }
  }
  return target
}

// Called with user-supplied JSON body
function applyUserSettings(defaults, userSettings) {
  return deepMerge(defaults, userSettings)
}

// Attacker payload: {"__proto__": {"isAdmin": true}}`,
  },
  {
    id: "ts-llm-unsafe",
    language: "typescript",
    vulnType: "Unsafe LLM Output",
    severity: "high",
    title: "Unvalidated LLM output deserialization",
    description:
      "AI-generated JSON parsed and trusted without schema validation.",
    filename: "ai-handler.ts",
    code: `import OpenAI from 'openai'

const client = new OpenAI()

async function getStructuredAdvice(userQuery: string) {
  const response = await client.chat.completions.create({
    model: 'gpt-4o',
    messages: [
      {
        role: 'system',
        content: 'Return a JSON object with keys: action, target, priority'
      },
      { role: 'user', content: userQuery }
    ]
  })

  // Directly parse and execute LLM-generated action
  const advice = JSON.parse(response.choices[0].message.content!)
  await executeAction(advice.action, advice.target)
  return advice
}

async function executeAction(action: string, target: string) {
  // Executes whatever the LLM decided
  await db.query(\`\${action} \${target}\`)
}`,
  },
];

const SEVERITY_COLORS: Record<string, string> = {
  critical: "var(--critical)",
  high: "var(--high)",
  medium: "var(--medium)",
};

interface ExampleModalProps {
  onSelect: (snippet: ExampleSnippet) => void;
  onClose: () => void;
}

export function ExampleModal({ onSelect, onClose }: ExampleModalProps) {
  const [activeTab, setActiveTab] = useState<"python" | "js-ts">("python");

  const pythonExamples = EXAMPLES.filter((e) => e.language === "python");
  const jstsExamples = EXAMPLES.filter(
    (e) => e.language === "javascript" || e.language === "typescript",
  );
  const displayed = activeTab === "python" ? pythonExamples : jstsExamples;

  return (
    <div className={styles.overlay} onClick={onClose}>
      <div className={styles.modal} onClick={(e) => e.stopPropagation()}>
        <div className={styles.modalHeader}>
          <span className={styles.modalTitle}>Example Code Snippets</span>
          <button className={styles.closeBtn} onClick={onClose}>
            ✕
          </button>
        </div>

        <div className={styles.tabs}>
          <button
            className={`${styles.tab} ${activeTab === "python" ? styles.activeTab : ""}`}
            onClick={() => setActiveTab("python")}
          >
            Python
          </button>
          <button
            className={`${styles.tab} ${activeTab === "js-ts" ? styles.activeTab : ""}`}
            onClick={() => setActiveTab("js-ts")}
          >
            JavaScript / TypeScript
          </button>
        </div>

        <div className={styles.cards}>
          {displayed.map((snippet) => (
            <button
              key={snippet.id}
              className={styles.card}
              onClick={() => onSelect(snippet)}
            >
              <div className={styles.cardHeader}>
                <span
                  className={styles.severityBadge}
                  style={{
                    color: SEVERITY_COLORS[snippet.severity],
                    borderColor: SEVERITY_COLORS[snippet.severity],
                  }}
                >
                  {snippet.severity.toUpperCase()}
                </span>
                <span className={styles.vulnType}>{snippet.vulnType}</span>
                <span className={styles.langBadge}>{snippet.filename}</span>
              </div>
              <p className={styles.cardTitle}>{snippet.title}</p>
              <p className={styles.cardDesc}>{snippet.description}</p>
              <pre className={styles.codePreview}>
                {snippet.code.split("\n").slice(0, 4).join("\n")}
                {"\n..."}
              </pre>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
