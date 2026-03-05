from __future__ import annotations

from dotenv import load_dotenv
load_dotenv()

import logging
from typing import Literal

from langchain_core.messages import HumanMessage
from langchain_openai import ChatOpenAI
from langchain_anthropic import ChatAnthropic
from langgraph.graph import END, START, StateGraph
from langgraph.checkpoint.memory import MemorySaver

from graph.state import AgentRole, CodeRiskState
from graph.nodes.nodes import (
    run_vuln_scanner,
    run_behavioral_risk,
    run_skeptic,
    run_remediation,
    run_synthesizer,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Model registry
# ---------------------------------------------------------------------------

MODELS = {
    AgentRole.ORCHESTRATOR: ChatOpenAI(
        model="gpt-4.1-mini",
        temperature=0.1,
        streaming=True,
    ),
    AgentRole.VULN_SCANNER: ChatOpenAI(
        model="gpt-4.1-mini",
        temperature=0.0,
        streaming=False,
    ),
    AgentRole.BEHAVIORAL_RISK: ChatAnthropic(
        model="claude-sonnet-4-5",
        temperature=0.2,
        max_tokens=4096,
        streaming=True,
    ),
    AgentRole.SKEPTIC: ChatAnthropic(
        model="claude-sonnet-4-5",
        temperature=0.3,
        max_tokens=4096,
        streaming=True,
    ),
    AgentRole.REMEDIATION: ChatOpenAI(
        model="gpt-4.1",
        temperature=0.1,
        streaming=True,
    ),
    AgentRole.SYNTHESIZER: ChatOpenAI(
        model="gpt-4.1-mini",
        temperature=0.3,
        streaming=True,
    ),
}


# ---------------------------------------------------------------------------
# Supervisor node
# ---------------------------------------------------------------------------

async def supervisor(state: dict) -> dict:
    logger.info("[supervisor] flags — vuln=%s behavioral=%s skeptic=%s awaiting=%s findings=%s",
        state.get("vuln_scan_complete"),
        state.get("behavioral_scan_complete"),
        state.get("skeptic_pass_complete"),
        state.get("awaiting_user_input"),
        len(state.get("vuln_findings") or []),
    )
    has_submission = state.get("submission") is not None
    vuln_done = state.get("vuln_scan_complete", False)
    behavioral_done = state.get("behavioral_scan_complete", False)
    skeptic_done = state.get("skeptic_pass_complete", False)
    remediation_done = state.get("remediation_complete", False)
    awaiting = state.get("awaiting_user_input", False)

    # Scans pending means neither has run yet — vuln runs first, then behavioral
    scans_pending = has_submission and not vuln_done and not behavioral_done
    skeptic_pending = vuln_done and behavioral_done and not skeptic_done
    remediation_requested = _user_requested_remediation(state)
    remediation_pending = remediation_requested and skeptic_done and not remediation_done
    synthesis_needed = _synthesis_needed(state)

    if awaiting:
        return {"next_agent": None, "awaiting_user_input": True}
    elif scans_pending:
        return {"next_agent": AgentRole.VULN_SCANNER.value}
    elif skeptic_pending:
        return {"next_agent": AgentRole.SKEPTIC.value}
    elif remediation_pending:
        return {"next_agent": AgentRole.REMEDIATION.value}
    elif synthesis_needed:
        return {"next_agent": AgentRole.SYNTHESIZER.value}
    else:
        return {"next_agent": None, "awaiting_user_input": True}


def _user_requested_remediation(state: dict) -> bool:
    messages = state.get("messages") or []
    if not messages:
        return False
    last = messages[-1]
    text = (last.content if hasattr(last, "content") else "").lower()
    triggers = ["fix", "remediat", "how to", "what should i", "how do i", "suggest"]
    return any(t in text for t in triggers)


def _synthesis_needed(state: dict) -> bool:
    scans_ran = (
        state.get("vuln_scan_complete")
        and state.get("behavioral_scan_complete")
        and state.get("skeptic_pass_complete")
    )
    has_findings = bool(
        state.get("vuln_findings")
        or state.get("behavioral_findings")
        or state.get("skeptic_assessment")
        or state.get("remediation_items")
    )
    return scans_ran and not state.get("awaiting_user_input", False)


# ---------------------------------------------------------------------------
# Routing function
# ---------------------------------------------------------------------------

def route_from_supervisor(state: dict) -> Literal[
    "vuln_scanner",
    "behavioral_risk",
    "skeptic",
    "remediation",
    "synthesizer",
    "__end__",
]:
    if state.get("awaiting_user_input") or state.get("analysis_complete"):
        return "__end__"

    next_agent = state.get("next_agent")

    route_map = {
        AgentRole.VULN_SCANNER.value: "vuln_scanner",
        AgentRole.BEHAVIORAL_RISK.value: "behavioral_risk",
        AgentRole.SKEPTIC.value: "skeptic",
        AgentRole.REMEDIATION.value: "remediation",
        AgentRole.SYNTHESIZER.value: "synthesizer",
    }

    if next_agent and next_agent in route_map:
        return route_map[next_agent]

    return "__end__"


# ---------------------------------------------------------------------------
# Graph assembly
# ---------------------------------------------------------------------------

def build_graph() -> StateGraph:
    builder = StateGraph(CodeRiskState)

    builder.add_node("supervisor", supervisor)
    builder.add_node("vuln_scanner", run_vuln_scanner)
    builder.add_node("behavioral_risk", run_behavioral_risk)
    builder.add_node("skeptic", run_skeptic)
    builder.add_node("remediation", run_remediation)
    builder.add_node("synthesizer", run_synthesizer)

    builder.add_edge(START, "supervisor")

    builder.add_conditional_edges(
        "supervisor",
        route_from_supervisor,
        {
            "vuln_scanner": "vuln_scanner",
            "behavioral_risk": "behavioral_risk",
            "skeptic": "skeptic",
            "remediation": "remediation",
            "synthesizer": "synthesizer",
            "__end__": END,
        },
    )

    # Sequential — vuln runs first, then behavioral, then back to supervisor
    builder.add_edge("vuln_scanner", "behavioral_risk")
    builder.add_edge("behavioral_risk", "supervisor")
    builder.add_edge("skeptic", "supervisor")
    builder.add_edge("remediation", "supervisor")
    builder.add_edge("synthesizer", END)

    checkpointer = MemorySaver()
    return builder.compile(checkpointer=checkpointer)


graph = build_graph()