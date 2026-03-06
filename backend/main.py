"""
CodeRisk Advisor — FastAPI Application

Endpoints:
  POST /api/analyze    — Submit code for analysis (new session or follow-up)
  GET  /api/health     — Health check for Cloud Run

Streaming:
  Responses are streamed via Server-Sent Events (SSE).
  Three event types are emitted on the same stream:

    event: agent_status
    data: {"agent": "<name>", "status": "running|complete|error", "detail": "..."}

    event: token
    data: {"text": "<chunk>"}

    event: done
    data: {"session_id": "<id>"}

Session handling:
  Sessions are keyed by a UUID issued on first request.
  The frontend stores this in sessionStorage and sends it as
  X-Session-ID header on subsequent requests.
  LangGraph thread_id maps 1:1 to session_id.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import uuid
from typing import AsyncGenerator

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from langchain_core.messages import HumanMessage
from pydantic import BaseModel, Field

from graph.state import CodeRiskState, CodeSubmission, SubmissionType
from graph.supervisor import graph

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="CodeRisk Advisor API", version="0.1.0")

# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------

allowed_origins_raw = os.getenv(
    "ALLOWED_ORIGINS",
    "http://localhost:5173,https://coderisk.craigstueber.com",
)
allowed_origins = [o.strip() for o in allowed_origins_raw.split(",")]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Session-ID"],
)


# ---------------------------------------------------------------------------
# Request schema
# ---------------------------------------------------------------------------

class AnalyzeRequest(BaseModel):
    message: str = Field(..., description="User message or follow-up question")
    code: str | None = Field(
        default=None,
        description="Code to analyze. Required on first turn, optional on follow-ups.",
    )
    filename: str | None = Field(
        default=None,
        description="Original filename if submitted via file upload",
    )
    language: str = Field(
        default="python",
        description="Programming language of the submitted code",
    )
    flagged_as_ai_generated: bool = Field(
        default=False,
        description="User explicitly flagged this code as AI-generated",
    )


# ---------------------------------------------------------------------------
# SSE helpers
# ---------------------------------------------------------------------------

def sse_event(event_type: str, data: dict) -> str:
    """Format a single SSE event string."""
    return f"event: {event_type}\ndata: {json.dumps(data)}\n\n"


def status_event(agent: str, status: str, detail: str = "") -> str:
    payload: dict = {"agent": agent, "status": status}
    if detail:
        payload["detail"] = detail
    return sse_event("agent_status", payload)


def token_event(text: str) -> str:
    return sse_event("token", {"text": text})


def done_event(session_id: str) -> str:
    return sse_event("done", {"session_id": session_id})


def error_event(message: str) -> str:
    return sse_event("error", {"message": message})


def findings_event(vuln_findings: list, behavioral_findings: list) -> str:
    return sse_event("findings", {
        "vuln": vuln_findings,
        "behavioral": behavioral_findings,
    })


# ---------------------------------------------------------------------------
# Graph streaming logic
# ---------------------------------------------------------------------------

async def stream_graph_response(
    session_id: str,
    state: CodeRiskState,
) -> AsyncGenerator[str, None]:
    """
    Runs the LangGraph graph and yields SSE events.

    Event sequence per turn:
    1. agent_status: running  — emitted as each node starts
    2. agent_status: complete — emitted as each node finishes
    3. token                  — streamed from Synthesizer output
    4. done                   — final event with session_id

    LangGraph's astream_events gives us node-level lifecycle hooks
    which map cleanly to our status events.
    """

    config = {
        "configurable": {"thread_id": session_id},
        "recursion_limit": 50,
    }

    # Track which agents have emitted their running event
    # to avoid duplicate status emissions
    running_emitted: set[str] = set()

    # Node name -> display name mapping
    node_display = {
        "supervisor": None,           # Internal routing — don't surface
        "vuln_scanner": "VulnScanner",
        "behavioral_risk": "BehavioralRisk",
        "skeptic": "Skeptic",
        "remediation": "Remediation",
        "synthesizer": "Synthesizer",
    }

    synthesizer_buffer = ""

    try:
        async for event in graph.astream_events(
             state,
            config=config,
            version="v2",
        ):
            kind = event.get("event")
            name = event.get("name", "")
            display = node_display.get(name)

            # Node started
            if kind == "on_chain_start" and display and name not in running_emitted:
                running_emitted.add(name)
                yield status_event(display, "running")

            # Synthesizer: emit collected response as tokens then complete status
            elif kind == "on_chain_end" and name == "synthesizer":
                event_data = event.get("data", {})
                output = event_data.get("output", {}) if isinstance(event_data, dict) else {}
                final_response = output.get("final_response", "") if isinstance(output, dict) else ""
                if final_response:
                    for char in final_response:
                        yield token_event(char)
                yield status_event("Synthesizer", "complete")

            # Node completed (non-synthesizer)
            elif kind == "on_chain_end" and display:
                detail = ""
                event_data = event.get("data", {})
                output = event_data.get("output") if isinstance(event_data, dict) else None

                if output is not None:
                    if name == "vuln_scanner":
                        findings = output.get("vuln_findings", []) if isinstance(output, dict) else []
                        count = len(findings)
                        detail = f"{count} finding{'s' if count != 1 else ''}"

                    elif name == "behavioral_risk":
                        findings = output.get("behavioral_findings", []) if isinstance(output, dict) else []
                        count = len(findings)
                        detail = f"{count} behavioral risk{'s' if count != 1 else ''}"

                    elif name == "skeptic":
                        assessment = output.get("skeptic_assessment") if isinstance(output, dict) else None
                        disputed = len(assessment.get("disputed_finding_ids", [])) if isinstance(assessment, dict) else 0
                        detail = f"{disputed} disputed" if disputed else "no disputes"

                        # Emit findings after skeptic completes — findings are now final
                        # (skeptic may have updated disputed flags on vuln/behavioral findings)
                        thread_state = await graph.aget_state(config)
                        vuln = thread_state.values.get("vuln_findings") or []
                        behavioral = thread_state.values.get("behavioral_findings") or []
                        if vuln or behavioral:
                            yield findings_event(vuln, behavioral)

                    elif name == "remediation":
                        items = output.get("remediation_items", []) if isinstance(output, dict) else []
                        count = len(items)
                        detail = f"{count} remediation item{'s' if count != 1 else ''}"

                yield status_event(display, "complete", detail)

        # Emit done
        yield done_event(session_id)

    except Exception as exc:
        logger.error("Graph execution error: %s", exc, exc_info=True)
        yield error_event(f"Analysis failed: {type(exc).__name__}")
        yield done_event(session_id)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/api/health")
async def health():
    return {"status": "ok"}


@app.post("/api/analyze")
async def analyze(request: Request, body: AnalyzeRequest):
    """
    Main analysis endpoint. Accepts code submissions and follow-up questions.
    Returns an SSE stream.

    Session lifecycle:
    - First request: no X-Session-ID header -> new session_id issued
    - Subsequent requests: X-Session-ID header -> existing graph thread resumed
    """

    # Session resolution
    session_id = request.headers.get("X-Session-ID")
    is_new_session = not session_id
    if is_new_session:
        session_id = str(uuid.uuid4())
        logger.info("New session created: %s", session_id)

    # Build submission if code was provided
    submission: CodeSubmission | None = None
    if body.code and body.code.strip():
        submission_type = (
            SubmissionType.AI_GENERATED
            if body.flagged_as_ai_generated
            else (
                SubmissionType.FILE
                if body.filename
                else SubmissionType.SNIPPET
            )
        )
        submission = CodeSubmission(
            raw_code=body.code.strip(),
            filename=body.filename,
            submission_type=submission_type,
            language=body.language,
            line_count=len(body.code.strip().splitlines()),
            flagged_as_ai_generated=body.flagged_as_ai_generated,
        )

    # Require code on new sessions
    if is_new_session and not submission:
        raise HTTPException(
            status_code=400,
            detail="Code is required to start a new analysis session.",
        )

    # Build initial state for this turn
    # LangGraph checkpointer merges this with existing thread state
    state = {
        "session_id": session_id,
        "submission": submission.model_dump() if submission else None,
        "messages": [HumanMessage(content=body.message)],
        "vuln_scan_complete": False if submission else True,
        "behavioral_scan_complete": False if submission else True,
        "skeptic_pass_complete": False if submission else True,
        "remediation_complete": True,
        "awaiting_user_input": False,
        "analysis_complete": False,
    }

    return StreamingResponse(
        stream_graph_response(session_id, state),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Session-ID": session_id,
            "X-Accel-Buffering": "no",  # Disable Nginx buffering on Cloud Run
        },
    )


@app.post("/api/upload")
async def upload_file(request: Request):
    """
    Accepts .py, .js, .ts, .jsx, .tsx file uploads and returns normalized
    code content. The frontend then passes this to /api/analyze.
    """
    from fastapi import UploadFile

    ACCEPTED_EXTENSIONS = (".py", ".js", ".ts", ".jsx", ".tsx")

    content_type = request.headers.get("content-type", "")
    if "multipart/form-data" not in content_type:
        raise HTTPException(status_code=400, detail="Expected multipart/form-data")

    form = await request.form()
    file: UploadFile = form.get("file")

    if not file:
        raise HTTPException(status_code=400, detail="No file provided")

    if not any(file.filename.endswith(ext) for ext in ACCEPTED_EXTENSIONS):
        raise HTTPException(
            status_code=400,
            detail=f"Accepted file types: {', '.join(ACCEPTED_EXTENSIONS)}",
        )

    raw = await file.read()

    try:
        code = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File must be UTF-8 encoded")

    lines = code.splitlines()
    if len(lines) > 500:
        raise HTTPException(
            status_code=400,
            detail=f"File too large: {len(lines)} lines. Maximum is 500 lines for this demo.",
        )

    # Detect language from extension
    language_map = {
        ".py": "python",
        ".js": "javascript",
        ".jsx": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
    }
    ext = next((e for e in ACCEPTED_EXTENSIONS if file.filename.endswith(e)), ".py")
    language = language_map.get(ext, "python")

    return {
        "filename": file.filename,
        "code": code,
        "line_count": len(lines),
        "language": language,
    }