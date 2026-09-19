"""Risk signals and assessment domain models."""

from enum import Enum
from typing import Any, Dict, List
from pydantic import BaseModel, Field

from agentguard.tracing.correlation import generate_id


class RiskLevel(str, Enum):
    """Standardized risk severity levels."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RiskSignal(BaseModel):
    """An individual risk indicator emitted by policy, taint tracker, APIRIS, or AI Secura."""
    signal_id: str = Field(default_factory=lambda: generate_id("rsig"))
    source: str = Field(..., description="Component emitting the signal (e.g., 'taint_tracker', 'apiris', 'ai_secura', 'policy')")
    risk_level: RiskLevel = Field(default=RiskLevel.LOW)
    score: float = Field(default=0.0, ge=0.0, le=1.0, description="Normalized risk score from 0.0 (safe) to 1.0 (dangerous)")
    indicator: str = Field(..., description="Short identifier of the risk condition (e.g. 'UNTRUSTED_TAINT_INTO_SENSITIVE_SINK')")
    details: Dict[str, Any] = Field(default_factory=dict, description="Contextual details and evidence")


class RiskAssessment(BaseModel):
    """Aggregated risk assessment for an action or tool invocation."""
    overall_level: RiskLevel = Field(default=RiskLevel.LOW)
    overall_score: float = Field(default=0.0, ge=0.0, le=1.0)
    signals: List[RiskSignal] = Field(default_factory=list)

    @classmethod
    def from_signals(cls, signals: List[RiskSignal]) -> "RiskAssessment":
        if not signals:
            return cls(overall_level=RiskLevel.LOW, overall_score=0.0, signals=[])
        
        max_score = max(s.score for s in signals)
        if max_score >= 0.85:
            level = RiskLevel.CRITICAL
        elif max_score >= 0.6:
            level = RiskLevel.HIGH
        elif max_score >= 0.3:
            level = RiskLevel.MEDIUM
        else:
            level = RiskLevel.LOW

        return cls(overall_level=level, overall_score=max_score, signals=signals)
