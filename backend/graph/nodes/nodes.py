"""
CodeRisk Advisor — Agent Nodes
Each node receives a CodeRiskState dict and returns a partial dict
containing only the keys it updates. LangGraph merges these into state.
"""

from __future__ import annotations

import asyncio
import httpx
import json
import logging
from typing import Any

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from graph.state import (
    AgentRole,
    BehavioralRiskFinding,
    BehavioralSignals,
    RemediationItem,
    SkepticAssessment,
    VulnerabilityFinding,
)

logger = logging.getLogger(__name__)


def _log_node_entry(agent: AgentRole, session_id: str) -> None:
    logger.info("[%s] Node entered | session=%s", agent.value, session_id)


def _append_error(errors: list, agent: AgentRole, exc: Exception) -> list:
    return errors + [{
        "agent": agent.value,
        "error": type(exc).__name__,
        "detail": str(exc),
    }]


def _extract_json(text: str) -> str:
    """Strip markdown code fences and extract only the JSON portion."""
    text = text.strip()
    if text.startswith("```"):
        text = text[text.index("\n") + 1:]
    if "```" in text:
        text = text[:text.index("```")]
    return text.strip()


async def run_vuln_scanner(state: dict) -> dict:
    from langchain_openai import ChatOpenAI
    from prompts.vuln_scanner import VULN_SCANNER_SYSTEM_PROMPT

    session_id = state.get("session_id", "")
    _log_node_entry(AgentRole.VULN_SCANNER, session_id)

    submission = state.get("submission")
    if not submission:
        return {"vuln_scan_complete": True}

    errors = list(state.get("errors") or [])

    try:
        # Fresh instance to avoid connection pool exhaustion
        model = ChatOpenAI(
            model="gpt-4.1-mini",
            temperature=0.0,
            streaming=False,
        )
        messages = [
            SystemMessage(content=VULN_SCANNER_SYSTEM_PROMPT),
            HumanMessage(
                content=(
                    f"Language: {submission.get('language', 'python')}\n\n"
                    f"Analyze this code:\n\n```{submission.get('language', 'python')}\n"
                    f"{submission['raw_code']}\n```"
                )
            ),
        ]
        response = await model.ainvoke(messages)
        findings_data: list[dict] = json.loads(_extract_json(response.content))
        validated = [VulnerabilityFinding(**f).model_dump() for f in findings_data]
        return {"vuln_findings": validated, "vuln_scan_complete": True}

    except Exception as exc:
        logger.error("[vuln_scanner] Error: %s", exc)
        return {
            "vuln_scan_complete": True,
            "errors": _append_error(errors, AgentRole.VULN_SCANNER, exc),
        }


async def run_behavioral_risk(state: dict) -> dict:
    from langchain_openai import ChatOpenAI
    from prompts.behavioral_risk import (
        BEHAVIORAL_RISK_SYSTEM_PROMPT,
        BEHAVIORAL_RISK_AI_GENERATED_ADDENDUM,
    )

    session_id = state.get("session_id", "")
    _log_node_entry(AgentRole.BEHAVIORAL_RISK, session_id)

    submission = state.get("submission")
    if not submission:
        return {"behavioral_scan_complete": True}

    errors = list(state.get("errors") or [])

    try:
        model = ChatOpenAI(
            model="gpt-5.4",
            temperature=0.2,
        )
        system = BEHAVIORAL_RISK_SYSTEM_PROMPT
        if submission.get("flagged_as_ai_generated"):
            system += "\n\n" + BEHAVIORAL_RISK_AI_GENERATED_ADDENDUM

        messages = [
            SystemMessage(content=system),
            HumanMessage(
                content=(
                    f"Language: {submission.get('language', 'python')}\n"
                    f"Submission type: {submission.get('submission_type', 'snippet')}\n"
                    f"AI-generated: {submission.get('flagged_as_ai_generated', False)}\n\n"
                    f"```{submission.get('language', 'python')}\n{submission['raw_code']}\n```"
                )
            ),
        ]

        response = await model.ainvoke(messages)
        content = response.content
        logger.info("[behavioral_risk] Raw response: %s", content)
        parsed = json.loads(_extract_json(content))
        if isinstance(parsed, list):
            findings_data: list[dict] = parsed
            signals_data: dict = {}
        else:
            findings_data = parsed.get("findings", [])
            signals_data = parsed.get("signals", {})
        validated = [BehavioralRiskFinding(**f).model_dump() for f in findings_data]
        validated_signals = None
        if signals_data:
            try:
                validated_signals = BehavioralSignals(**signals_data).model_dump()
            except Exception as sig_exc:
                logger.warning("[behavioral_risk] Signals validation failed: %s", sig_exc)
        return {
            "behavioral_findings": validated,
            "behavioral_signals": validated_signals,
            "behavioral_scan_complete": True,
        }

    except Exception as exc:
        logger.error("[behavioral_risk] Error: %s", exc)
        return {
            "behavioral_scan_complete": True,
            "errors": _append_error(errors, AgentRole.BEHAVIORAL_RISK, exc),
        }


async def run_skeptic(state: dict) -> dict:
    from langchain_openai import ChatOpenAI
    from prompts.skeptic import SKEPTIC_SYSTEM_PROMPT

    session_id = state.get("session_id", "")
    _log_node_entry(AgentRole.SKEPTIC, session_id)

    vuln_findings = state.get("vuln_findings") or []
    behavioral_findings = state.get("behavioral_findings") or []
    all_findings = vuln_findings + behavioral_findings
    errors = list(state.get("errors") or [])

    if not all_findings:
        return {"skeptic_pass_complete": True}

    submission = state.get("submission", {})

    try:
        model = ChatOpenAI(
            model="gpt-5.4",
            temperature=0.3,
        )
        messages = [
            SystemMessage(content=SKEPTIC_SYSTEM_PROMPT),
            HumanMessage(
                content=(
                    f"Review these findings:\n\n{json.dumps(all_findings, indent=2)}\n\n"
                    f"Code under review:\n```python\n{submission.get('raw_code', '')}\n```"
                )
            ),
        ]

        response = await model.ainvoke(messages)
        content = response.content
        logger.info("[skeptic] Raw response: %s", content)
        assessment_data: dict = json.loads(_extract_json(content))
        assessment = SkepticAssessment(**assessment_data)

        disputed_ids = set(assessment.disputed_finding_ids)

        # Set disputed flag only — confidence penalty is owned by
        # score_calculator._get_confidence() to avoid double-penalizing.
        updated_vuln = [
            {**f, "disputed": True, "dispute_rationale": "Flagged by Skeptic"}
            if f["id"] in disputed_ids else f
            for f in vuln_findings
        ]
        updated_behavioral = [
            {**f, "disputed": True, "dispute_rationale": "Flagged by Skeptic"}
            if f["id"] in disputed_ids else f
            for f in behavioral_findings
        ]

        return {
            "skeptic_assessment": assessment.model_dump(),
            "vuln_findings": updated_vuln,
            "behavioral_findings": updated_behavioral,
            "skeptic_pass_complete": True,
        }

    except Exception as exc:
        logger.error("[skeptic] Error: %s", exc)
        return {
            "skeptic_pass_complete": True,
            "errors": _append_error(errors, AgentRole.SKEPTIC, exc),
        }


def run_score_calculator(state: dict) -> dict:
    from utils.score_calculator import calculate_scores

    vuln_findings = state.get("vuln_findings") or []
    behavioral_findings = state.get("behavioral_findings") or []
    signals = state.get("behavioral_signals") or {}

    scores = calculate_scores(vuln_findings + behavioral_findings, signals)
    logger.info(
        "[score_calculator] overall=%.1f counts=%s",
        scores["overall_score"],
        scores["severity_counts"],
    )
    return {"computed_scores": scores}


async def run_remediation(state: dict) -> dict:
    from prompts.remediation import REMEDIATION_SYSTEM_PROMPT

    session_id = state.get("session_id", "")
    _log_node_entry(AgentRole.REMEDIATION, session_id)

    vuln_findings = state.get("vuln_findings") or []
    behavioral_findings = state.get("behavioral_findings") or []
    confirmed = [f for f in vuln_findings + behavioral_findings if not f.get("disputed")]
    errors = list(state.get("errors") or [])

    if not confirmed:
        return {"remediation_complete": True}

    submission = state.get("submission", {})
    messages_history = state.get("messages") or []
    last_message = messages_history[-1].content if messages_history else ""

    logger.info(
        "[remediation] confirmed findings count=%d",
        len(confirmed),
    )

    try:
        from langchain_openai import ChatOpenAI
        model = ChatOpenAI(
            model="gpt-4.1",
            temperature=0.1,
            streaming=True,
        )
        messages = [
            SystemMessage(content=REMEDIATION_SYSTEM_PROMPT),
            HumanMessage(
                content=(
                    f"Confirmed findings:\n\n{json.dumps(confirmed, indent=2)}\n\n"
                    f"Code:\n```python\n{submission.get('raw_code', '')}\n```\n\n"
                    f"User question: {last_message}"
                )
            ),
        ]
        response = await model.ainvoke(messages)
        items_data: list[dict] = json.loads(response.content)
        validated = [RemediationItem(**item).model_dump() for item in items_data]
        return {"remediation_items": validated, "remediation_complete": True}

    except Exception as exc:
        logger.error("[remediation] Error: %s", exc)
        return {
            "remediation_complete": True,
            "errors": _append_error(errors, AgentRole.REMEDIATION, exc),
        }


async def run_synthesizer(state: dict) -> dict:
    from langchain_openai import ChatOpenAI
    from prompts.synthesizer import SYNTHESIZER_SYSTEM_PROMPT, build_synthesis_context

    session_id = state.get("session_id", "")
    _log_node_entry(AgentRole.SYNTHESIZER, session_id)

    errors = list(state.get("errors") or [])

    try:
        # Fresh instance with no keepalive to avoid stale Cloud Run connections
        model = ChatOpenAI(
            model="gpt-4.1-mini",
            temperature=0.3,
            streaming=True,
            http_async_client=httpx.AsyncClient(
                timeout=httpx.Timeout(60.0),
                limits=httpx.Limits(
                    max_connections=5,
                    max_keepalive_connections=0,
                ),
            ),
        )
        context = build_synthesis_context(state)
        history = list(state.get("messages") or [])

        messages = [
            SystemMessage(content=SYNTHESIZER_SYSTEM_PROMPT),
            *history,
            HumanMessage(content=f"Current analysis state:\n\n{context}"),
        ]

        # Retry up to 3 times on connection errors
        full_response = ""
        last_exc = None
        for attempt in range(3):
            try:
                full_response = ""
                async for chunk in model.astream(messages):
                    if chunk.content:
                        full_response += chunk.content
                if full_response:
                    break
            except Exception as exc:
                last_exc = exc
                logger.warning("[synthesizer] Attempt %d failed: %s", attempt + 1, exc)
                await asyncio.sleep(1.5 * (attempt + 1))

        if not full_response:
            raise last_exc or Exception("No response after retries")

        return {
            "final_response": full_response,
            "synthesized_response": full_response,
            "messages": [AIMessage(content=full_response)],
            "awaiting_user_input": True,
        }

    except Exception as exc:
        logger.error("[synthesizer] Error: %s", exc)
        fallback = "I encountered an issue generating a response. The analysis data is still available — ask me a specific question."
        return {
            "final_response": fallback,
            "synthesized_response": fallback,
            "messages": [AIMessage(content=fallback)],
            "awaiting_user_input": True,
            "errors": _append_error(errors, AgentRole.SYNTHESIZER, exc),
        }