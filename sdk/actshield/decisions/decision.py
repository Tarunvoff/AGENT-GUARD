"""Security enforcement decision models."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from actshield.risk.models import RiskFactorBreakdown, RiskLevel
from actshield.tracing.correlation import generate_id


class DecisionAction(str, Enum):
    """Deterministic security enforcement actions."""
    ALLOW = "ALLOW"
    MONITOR = "MONITOR"
    HUMAN_APPROVAL = "HUMAN_APPROVAL"
    QUARANTINE = "QUARANTINE"
    BLOCK = "BLOCK"
    REVOKE = "REVOKE"


class SecurityDecision(BaseModel):
    """A deterministic security decision emitted after policy evaluation."""
    
    decision_id: str = Field(default_factory=lambda: generate_id("dec"), description="Unique decision ID")
    action: DecisionAction = Field(..., description="Deterministic enforcement action")
    risk_level: RiskLevel = Field(default=RiskLevel.LOW, description="Assessed risk level")
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0, description="Risk score between 0.0 and 1.0")
    reason_code: str = Field(..., description="Machine-readable reason code")
    explanation: str = Field(..., description="Human-readable explanation of why the decision was rendered")
    trace_id: str = Field(..., description="Trace ID for causal correlation")
    policy_id: Optional[str] = Field(default=None, description="ID of the policy rule that determined this decision")
    
    # Causal and structured evaluation details
    evidence_references: List[str] = Field(
        default_factory=list,
        description="References to event_ids, context_ids, or delegation_ids establishing causal evidence"
    )
    influencing_context_ids: List[str] = Field(
        default_factory=list,
        description="IDs of context artifacts that influenced this execution request"
    )
    authority_containment: Dict[str, Any] = Field(
        default_factory=dict,
        description="Structured validation of requested capability vs delegated authority"
    )
    intent_alignment: Dict[str, Any] = Field(
        default_factory=dict,
        description="Structured evaluation of original user intent vs requested action"
    )
    risk_breakdown: Optional[RiskFactorBreakdown] = Field(
        default=None,
        description="Explainable breakdown of risk factor dimensions"
    )
    structured_explanation: Dict[str, Any] = Field(
        default_factory=dict,
        description="Structured breakdown for auditing and SIEM reporting"
    )
    
    evaluated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of evaluation"
    )

    @property
    def is_allowed(self) -> bool:
        """Helper to test if execution is permitted to proceed immediately."""
        return self.action in (DecisionAction.ALLOW, DecisionAction.MONITOR)

    @property
    def is_blocked(self) -> bool:
        """Helper to test if execution was blocked or quarantined."""
        return self.action in (DecisionAction.BLOCK, DecisionAction.QUARANTINE, DecisionAction.REVOKE)

