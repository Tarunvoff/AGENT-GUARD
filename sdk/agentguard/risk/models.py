"""Risk signals and explainable deterministic risk assessment models."""

from enum import Enum
from typing import Any, Dict, List, Optional
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
    indicator: str = Field(..., description="Short identifier of the risk condition")
    details: Dict[str, Any] = Field(default_factory=dict, description="Contextual details and evidence")


class RiskFactorBreakdown(BaseModel):
    """Explainable deterministic factor breakdown contributing to total risk score."""
    tainted_context_score: float = Field(default=0.0, description="Risk from active tainted/injected context (e.g. +0.25)")
    critical_sink_score: float = Field(default=0.0, description="Risk from target tool/resource sensitivity level (e.g. +0.25)")
    authority_violation_score: float = Field(default=0.0, description="Risk from delegation authority escalation (e.g. +0.25)")
    intent_violation_score: float = Field(default=0.0, description="Risk from divergence from original user intent (e.g. +0.15)")
    untrusted_origin_score: float = Field(default=0.0, description="Risk from external unverified origin (e.g. +0.10)")
    total_score: float = Field(default=0.0, ge=0.0, le=1.0)
    risk_factors: List[str] = Field(default_factory=list)

    @classmethod
    def compute(
        cls,
        has_tainted_context: bool,
        is_critical_sink: bool,
        has_authority_violation: bool,
        has_intent_violation: bool,
        is_untrusted_origin: bool,
    ) -> "RiskFactorBreakdown":
        factors: List[str] = []
        taint_s = 0.25 if has_tainted_context else 0.0
        if has_tainted_context:
            factors.append("tainted_context")

        crit_s = 0.25 if is_critical_sink else 0.0
        if is_critical_sink:
            factors.append("critical_resource_sink")

        auth_s = 0.25 if has_authority_violation else 0.0
        if has_authority_violation:
            factors.append("authority_escalation_violation")

        intent_s = 0.15 if has_intent_violation else 0.0
        if has_intent_violation:
            factors.append("user_intent_drift_violation")

        untrusted_s = 0.10 if is_untrusted_origin else 0.0
        if is_untrusted_origin:
            factors.append("external_untrusted_source_origin")

        total = min(1.0, taint_s + crit_s + auth_s + intent_s + untrusted_s)

        return cls(
            tainted_context_score=taint_s,
            critical_sink_score=crit_s,
            authority_violation_score=auth_s,
            intent_violation_score=intent_s,
            untrusted_origin_score=untrusted_s,
            total_score=round(total, 2),
            risk_factors=factors,
        )


class RiskAssessment(BaseModel):
    """Aggregated risk assessment for an action or tool invocation."""
    overall_level: RiskLevel = Field(default=RiskLevel.LOW)
    overall_score: float = Field(default=0.0, ge=0.0, le=1.0)
    signals: List[RiskSignal] = Field(default_factory=list)
    breakdown: Optional[RiskFactorBreakdown] = None

    @classmethod
    def from_signals(cls, signals: List[RiskSignal], breakdown: Optional[RiskFactorBreakdown] = None) -> "RiskAssessment":
        if not signals and not breakdown:
            return cls(overall_level=RiskLevel.LOW, overall_score=0.0, signals=[], breakdown=breakdown)
        
        max_score = breakdown.total_score if breakdown else max((s.score for s in signals), default=0.0)
        if max_score >= 0.7:
            level = RiskLevel.CRITICAL
        elif max_score >= 0.45:
            level = RiskLevel.HIGH
        elif max_score >= 0.2:
            level = RiskLevel.MEDIUM
        else:
            level = RiskLevel.LOW

        return cls(overall_level=level, overall_score=max_score, signals=signals, breakdown=breakdown)
