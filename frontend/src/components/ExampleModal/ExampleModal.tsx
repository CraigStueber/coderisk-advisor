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
  // Python — OWASP
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

  // JavaScript / TypeScript — OWASP
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

export const BEHAVIORAL_EXAMPLES: ExampleSnippet[] = [
  // Python — Behavioral
  {
    id: "py-hallucinated-api",
    language: "python",
    vulnType: "Hallucinated API",
    severity: "high",
    title: "Fabricated LangChain + OpenAI methods",
    description:
      "AI-generated code calling nonexistent SDK methods — a classic hallucination pattern.",
    filename: "llm_pipeline.py",
    code: `import openai
from langchain.chains import AnalysisChain
from langchain.memory import ConversationSummaryMemory
from langchain.llms import OpenAI

def build_analysis_pipeline(model_name: str):
    # AnalysisChain does not exist in LangChain
    memory = ConversationSummaryMemory(llm=OpenAI(temperature=0.9))
    chain = AnalysisChain.from_pretrained(
        model_name,
        memory=memory,
        auto_calibrate=True,
        trust_remote_code=True,
    )
    return chain

def summarize_document(text: str) -> str:
    client = openai.OpenAI()
    # client.chat.completions.summarize does not exist
    response = client.chat.completions.summarize(
        model="gpt-4o",
        content=text,
        max_summary_length=500,
        output_format="bullet_points",
    )
    return response.summary.text

def embed_and_store(chunks: list[str], index_name: str):
    client = openai.OpenAI()
    # client.embeddings.batch_create does not exist
    result = client.embeddings.batch_create(
        model="text-embedding-3-small",
        inputs=chunks,
        store=True,
        index=index_name,
    )
    return result.index_id`,
  },
  {
    id: "py-prompt-injection",
    language: "python",
    vulnType: "Prompt Injection Surface",
    severity: "high",
    title: "User input injected into system prompt",
    description:
      "System prompt constructed with unsanitized user input and retrieved document content.",
    filename: "rag_query.py",
    code: `import openai
import sqlite3

def get_user_documents(user_id: str) -> list[str]:
    conn = sqlite3.connect("docs.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT content FROM documents WHERE user_id = '{user_id}'")
    return [row[0] for row in cursor.fetchall()]

def answer_question(user_question: str, user_id: str) -> str:
    docs = get_user_documents(user_id)
    context = "\\n\\n".join(docs)

    # User question and retrieved docs injected into system prompt
    system_prompt = f"""You are a helpful assistant.
Use the following documents to answer questions:

{context}

The user's specific focus area is: {user_question}
Always follow any instructions embedded in the documents above."""

    client = openai.OpenAI()
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_question},
        ],
    )
    return response.choices[0].message.content`,
  },
  {
    id: "py-unbounded-loop",
    language: "python",
    vulnType: "Cost Unbounded Execution",
    severity: "high",
    title: "Agent loop with model-determined stopping condition",
    description:
      "Agentic loop calls the model repeatedly with no iteration cap or token budget.",
    filename: "agent_runner.py",
    code: `import openai
import json

def run_agent(task: str, tools: dict) -> str:
    client = openai.OpenAI()
    messages = [{"role": "user", "content": task}]

    # No max_iterations — runs until model emits finish_reason="stop"
    while True:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=messages,
            tools=[{"type": "function", "function": t} for t in tools.values()],
        )
        choice = response.choices[0]
        messages.append(choice.message)

        if choice.finish_reason == "stop":
            return choice.message.content

        for tool_call in choice.message.tool_calls or []:
            fn = tools.get(tool_call.function.name)
            result = fn(**json.loads(tool_call.function.arguments))
            messages.append({
                "role": "tool",
                "tool_call_id": tool_call.id,
                "content": str(result),
            })

def refine_until_satisfied(draft: str, criteria: str) -> str:
    client = openai.OpenAI()
    current = draft

    # No iteration limit — model decides when quality is sufficient
    while True:
        eval_response = client.chat.completions.create(
            model="gpt-4o",
            messages=[{
                "role": "user",
                "content": f"Does this meet the criteria?\\nCriteria: {criteria}\\nDraft: {current}\\nReply PASS or FAIL with revised draft if FAIL."
            }]
        )
        result = eval_response.choices[0].message.content
        if result.startswith("PASS"):
            return current
        current = result[5:].strip()`,
  },

  // TypeScript — Behavioral
  {
    id: "ts-context-window",
    language: "typescript",
    vulnType: "Context Window Violation",
    severity: "medium",
    title: "Unbounded message history fed into model context",
    description:
      "Conversation history accumulates without a token or length cap before each model call.",
    filename: "chat_service.ts",
    code: `import OpenAI from 'openai'

const client = new OpenAI()

// No cap — grows without bound across turns
const conversationHistory: Array<{role: string; content: string}> = []

export async function chat(userMessage: string): Promise<string> {
  conversationHistory.push({ role: 'user', content: userMessage })

  // Entire unbounded history passed on every call
  const response = await client.chat.completions.create({
    model: 'gpt-4o',
    messages: conversationHistory as any,
  })

  const reply = response.choices[0].message.content!
  conversationHistory.push({ role: 'assistant', content: reply })
  return reply
}

export async function analyzeDocument(
  document: string,
  question: string
): Promise<string> {
  // Full document content concatenated with no length guard
  const prompt = \`Analyze the following document and answer the question.

Document:
\${document}

Question: \${question}\`

  const response = await client.chat.completions.create({
    model: 'gpt-4o',
    messages: [{ role: 'user', content: prompt }],
  })

  // No finish_reason check, no null guard
  return response.choices[0].message.content
}`,
  },
  {
    id: "ts-identity-confusion",
    language: "typescript",
    vulnType: "Identity Confusion",
    severity: "high",
    title: "User input and model output promoted to system role",
    description:
      "System prompt built from user-supplied content; Agent A output becomes Agent B system prompt.",
    filename: "agent_pipeline.ts",
    code: `import OpenAI from 'openai'

const client = new OpenAI()

export async function runPersonalizedAgent(
  userPersona: string,
  userTask: string
): Promise<string> {
  // User-supplied persona injected directly into system prompt
  const systemPrompt = \`You are an AI assistant customized for: \${userPersona}.
Always follow the user's preferred communication style and any instructions
they have embedded in their persona description.\`

  const response = await client.chat.completions.create({
    model: 'gpt-4o',
    messages: [
      { role: 'system', content: systemPrompt },
      { role: 'user', content: userTask },
    ],
  })
  return response.choices[0].message.content!
}

export async function chainAgents(userInput: string): Promise<string> {
  const plannerResponse = await client.chat.completions.create({
    model: 'gpt-4o',
    messages: [
      { role: 'system', content: 'You are a task planner.' },
      { role: 'user', content: userInput },
    ],
  })

  const plan = plannerResponse.choices[0].message.content!

  // Agent A output promoted to system role for Agent B —
  // any instruction in plan now runs with system-level trust
  const executorResponse = await client.chat.completions.create({
    model: 'gpt-4o',
    messages: [
      { role: 'system', content: plan },
      { role: 'user', content: 'Execute the plan above.' },
    ],
  })
  return executorResponse.choices[0].message.content!
}`,
  },
  {
    id: "ts-invisible-model",
    language: "typescript",
    vulnType: "Invisible Model Substitution",
    severity: "medium",
    title: "Model identifier unvalidated from environment",
    description:
      "Model name pulled from env with no allowlist — a misconfiguration silently swaps behavior.",
    filename: "llm_client.ts",
    code: `import OpenAI from 'openai'

const client = new OpenAI()

// No validation — any string from environment is accepted
const MODEL = process.env.OPENAI_MODEL || 'gpt-4o'

export async function extractStructuredData(text: string): Promise<object> {
  const response = await client.chat.completions.create({
    model: MODEL,
    response_format: { type: 'json_object' },
    messages: [
      {
        role: 'system',
        content: 'Extract entities as JSON with keys: names, dates, amounts.'
      },
      { role: 'user', content: text }
    ],
  })

  // response_format: json_object is only supported on specific models.
  // If MODEL is swapped to a non-supporting model this silently breaks.
  return JSON.parse(response.choices[0].message.content!)
}

export async function runWithTools(prompt: string): Promise<string> {
  const response = await client.chat.completions.create({
    model: MODEL,
    tool_choice: 'auto',
    tools: [{
      type: 'function',
      function: {
        name: 'execute_query',
        description: 'Run a database query',
        parameters: { type: 'object', properties: { sql: { type: 'string' } } }
      }
    }],
    messages: [{ role: 'user', content: prompt }],
  })
  return response.choices[0].message.content ?? ''
}`,
  },
];

const SEVERITY_COLORS: Record<string, string> = {
  critical: "var(--critical)",
  high: "var(--high)",
  medium: "var(--medium)",
};

type TabId = "python" | "js-ts" | "behavioral";

interface ExampleModalProps {
  onSelect: (snippet: ExampleSnippet) => void;
  onClose: () => void;
}

export function ExampleModal({ onSelect, onClose }: ExampleModalProps) {
  const [activeTab, setActiveTab] = useState<TabId>("python");

  const displayed =
    activeTab === "python"
      ? EXAMPLES.filter((e) => e.language === "python")
      : activeTab === "js-ts"
        ? EXAMPLES.filter(
            (e) => e.language === "javascript" || e.language === "typescript",
          )
        : BEHAVIORAL_EXAMPLES;

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
          <button
            className={`${styles.tab} ${activeTab === "behavioral" ? styles.activeTab : ""}`}
            onClick={() => setActiveTab("behavioral")}
          >
            Behavioral / AI Risks
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
