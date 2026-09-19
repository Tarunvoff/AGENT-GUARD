"""Security enforcement decision models."""

from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field

from agentguard.risk.models import RiskLevel
from agentguard.tracing.correlation import generate_id


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
    evidence_references: List[str] = Field(
        default_factory=list,
        description="References to event_ids, context_ids, or delegation_ids establishing causal evidence"
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
