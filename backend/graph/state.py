"""
CodeRisk Advisor — Graph State Schema
Using TypedDict for proper LangGraph state merging.
Pydantic models are used for sub-structures only.
"""

from __future__ import annotations

from enum import Enum
from typing import Annotated, Any, Optional
from typing_extensions import TypedDict
from pydantic import BaseModel, Field
from langgraph.graph.message import add_messages
from langchain_core.messages import BaseMessage


class AgentRole(str, Enum):
    ORCHESTRATOR = "orchestrator"
    VULN_SCANNER = "vuln_scanner"
    BEHAVIORAL_RISK = "behavioral_risk"
    SKEPTIC = "skeptic"
    REMEDIATION = "remediation"
    SYNTHESIZER = "synthesizer"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class SubmissionType(str, Enum):
    SNIPPET = "snippet"
    FILE = "file"
    AI_GENERATED = "ai_generated"


class VulnerabilityFinding(BaseModel):
    id: str
    title: str
    owasp_category: str
    severity: Severity
    confidence: float = Field(..., ge=0.0, le=1.0)
    location: str
    description: str
    evidence: str
    disputed: bool = False
    dispute_rationale: Optional[str] = None


class BehavioralRiskFinding(BaseModel):
    id: str
    risk_type: str
    severity: Severity
    confidence: float = Field(..., ge=0.0, le=1.0)
    location: str
    description: str
    llm_specific: bool = True
    disputed: bool = False
    dispute_rationale: Optional[str] = None


class RemediationItem(BaseModel):
    finding_ids: list[str]
    priority: int = Field(..., ge=1)
    summary: str
    rationale: str
    code_suggestion: Optional[str] = None
    tradeoffs: Optional[str] = None


class SkepticAssessment(BaseModel):
    reviewed_finding_ids: list[str]
    disputed_finding_ids: list[str]
    overall_confidence_assessment: str
    false_positive_risk: str
    notes: str


class CodeSubmission(BaseModel):
    raw_code: str
    filename: Optional[str] = None
    submission_type: SubmissionType
    language: str = "python"
    line_count: int = 0
    flagged_as_ai_generated: bool = False


class CodeRiskState(TypedDict, total=False):
    messages: Annotated[list[BaseMessage], add_messages]
    submission: Optional[dict]
    vuln_findings: list[dict]
    behavioral_findings: list[dict]
    remediation_items: list[dict]
    skeptic_assessment: Optional[dict]
    synthesized_response: str
    next_agent: Optional[str]
    awaiting_user_input: bool
    analysis_complete: bool
    session_id: str
    turn_count: int
    vuln_scan_complete: bool
    behavioral_scan_complete: bool
    skeptic_pass_complete: bool
    remediation_complete: bool
    errors: list[dict]