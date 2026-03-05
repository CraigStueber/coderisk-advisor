# CodeRisk Advisor

A multi-agent AI security review system for Python, JavaScript, and TypeScript code. Combines traditional OWASP Top 10 vulnerability scanning with AI-specific behavioral risk detection, running a panel of specialized LLM agents that each contribute different expertise and synthesize findings into conversational guidance for developers.

**Live:** [coderisk.craigstueber.com](https://coderisk.craigstueber.com)

---

## How it works

When you submit code, a LangGraph agent graph runs the following pipeline:

```
Submission
    ↓
VulnScanner (OWASP Top 10)  →  BehavioralRisk (AI-specific risks)
                                        ↓
                               Skeptic (disputes overconfident findings)
                                        ↓
                        Remediation (on-demand, triggered by user message)
                                        ↓
                               Synthesizer (conversational response)
                                        ↓
                                  Awaiting follow-up
```

- **VulnScanner** — GPT-4.1-mini; identifies OWASP Top 10 vulnerabilities with severity and confidence scores
- **BehavioralRisk** — Claude Sonnet 4.5; detects AI-specific risks (hallucinated APIs, prompt injection, unsafe deserialization, over-trust, etc.)
- **Skeptic** — Claude Sonnet 4.5; challenges findings with low confidence and marks disputed ones
- **Remediation** — GPT-4.1; generates prioritized fix suggestions when the user asks ("fix this", "how do I...", etc.)
- **Synthesizer** — GPT-4.1-mini; consolidates all findings into a clear, conversational response

Responses stream token-by-token via SSE with real-time agent status updates shown in the UI.

---

## Project structure

```
coderisk-advisor/
├── backend/               # FastAPI + LangGraph
│   ├── main.py            # HTTP layer, SSE streaming, session management
│   ├── graph/
│   │   ├── state.py       # CodeRiskState TypedDict + Pydantic models
│   │   ├── supervisor.py  # Graph assembly, routing logic, model registry
│   │   └── nodes/
│   │       └── nodes.py   # Agent implementations (run_vuln_scanner, etc.)
│   ├── prompts/           # System prompts per agent
│   ├── Dockerfile
│   ├── cloudrun.yaml      # Cloud Run Knative service config
│   ├── setup-gcloud.sh    # One-time GCP setup script
│   └── requirements.txt
└── frontend/              # Next.js 16 + React 19
    └── src/
        ├── app/           # Next.js app router (page.tsx, layout.tsx)
        ├── components/    # CodePanel, ChatPanel, AgentStatusBar, Header
        └── hooks/
            └── useAnalysis.ts  # SSE stream handling + session state
```

---

## API

| Method | Endpoint       | Description                                              |
| ------ | -------------- | -------------------------------------------------------- |
| `POST` | `/api/analyze` | Submit code or a follow-up message; returns SSE stream   |
| `POST` | `/api/upload`  | Upload a file (.py, .js, .ts, .jsx, .tsx; max 500 lines) |
| `GET`  | `/api/health`  | Health check                                             |

### `/api/analyze` request body

```json
{
  "message": "Analyze this code",
  "code": "...",
  "filename": "app.py",
  "language": "python",
  "flagged_as_ai_generated": false
}
```

### SSE event types

| Event          | Payload                                                                       |
| -------------- | ----------------------------------------------------------------------------- |
| `agent_status` | `{ "agent": string, "status": "running\|complete\|error", "detail": string }` |
| `token`        | `{ "text": string }`                                                          |
| `done`         | `{ "session_id": string }`                                                    |
| `error`        | `{ "message": string }`                                                       |

Sessions are tracked via the `X-Session-ID` response header and passed back on subsequent requests to maintain conversation history through the LangGraph checkpointer.

---

## Local development

### Backend

```bash
cd backend
python -m venv .venv
source .venv/Scripts/activate   # Windows
# source .venv/bin/activate     # macOS/Linux
pip install -r requirements.txt
```

Create a `.env` file in `backend/`:

```env
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...

# Optional — LangSmith tracing
LANGSMITH_TRACING=true
LANGCHAIN_API_KEY=lsv2_...
LANGCHAIN_PROJECT=coderisk-advisor

# Optional
ALLOWED_ORIGINS=http://localhost:3000
SESSION_TTL_SECONDS=3600
```

```bash
uvicorn main:app --reload --port 8080
```

### Frontend

```bash
cd frontend
npm install
```

Create a `.env.local` file in `frontend/`:

```env
NEXT_PUBLIC_API_URL=http://localhost:8080
```

```bash
npm run dev
```

Opens at `http://localhost:3000`.

---

## Deployment (Google Cloud Run)

### First-time setup

```bash
cd backend
chmod +x setup-gcloud.sh
./setup-gcloud.sh
```

This script:

1. Enables required GCP APIs (Cloud Run, Container Registry, Secret Manager, Cloud Build)
2. Creates secrets in Secret Manager for `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `LANGCHAIN_API_KEY`
3. Grants the Cloud Run service account access to those secrets
4. Builds and pushes the Docker image to GCR
5. Deploys via `cloudrun.yaml`

### Subsequent deploys

```bash
gcloud run services replace cloudrun.yaml --region us-central1
```

Or push to `main` if you have a Cloud Build trigger configured.

### Cloud Run config highlights (`cloudrun.yaml`)

| Setting                | Value | Reason                                                         |
| ---------------------- | ----- | -------------------------------------------------------------- |
| `minScale`             | 0     | Scales to zero when idle                                       |
| `maxScale`             | 3     | Bounded to avoid runaway costs                                 |
| `containerConcurrency` | 1     | One request per instance (LangGraph MemorySaver is in-process) |
| `timeoutSeconds`       | 120   | Multi-agent runs can take 30–60 seconds                        |

> **Scaling note:** The current checkpointer is `MemorySaver` (in-process). For multi-instance deployments, swap to `RedisSaver` and set `REDIS_URL`. The code uses `containerConcurrency: 1` as a workaround for now.

---

## Environment variables reference

| Variable              | Required | Default                                                   | Description              |
| --------------------- | -------- | --------------------------------------------------------- | ------------------------ |
| `OPENAI_API_KEY`      | Yes      | —                                                         | GPT-4.1 / GPT-4.1-mini   |
| `ANTHROPIC_API_KEY`   | Yes      | —                                                         | Claude Sonnet 4.5        |
| `LANGSMITH_TRACING`   | No       | `false`                                                   | Enable LangSmith tracing |
| `LANGCHAIN_API_KEY`   | No       | —                                                         | LangSmith API key        |
| `LANGCHAIN_PROJECT`   | No       | `coderisk-advisor`                                        | LangSmith project name   |
| `ALLOWED_ORIGINS`     | No       | `http://localhost:5173,https://coderisk.craigstueber.com` | CORS origins             |
| `SESSION_TTL_SECONDS` | No       | `3600`                                                    | Session expiry           |
| `NEXT_PUBLIC_API_URL` | No       | `http://localhost:8080`                                   | Frontend → backend URL   |
| `PORT`                | No       | `8080`                                                    | Backend listen port      |

---

## Tech stack

| Layer               | Technology                                                 |
| ------------------- | ---------------------------------------------------------- |
| Agent orchestration | [LangGraph](https://github.com/langchain-ai/langgraph) 0.2 |
| LLM providers       | OpenAI GPT-4.1 / GPT-4.1-mini, Anthropic Claude Sonnet 4.5 |
| Backend framework   | FastAPI 0.115, Uvicorn                                     |
| Frontend framework  | Next.js 16, React 19                                       |
| Observability       | LangSmith                                                  |
| Deployment          | Google Cloud Run                                           |
