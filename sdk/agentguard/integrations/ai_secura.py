"""AI Secura security reasoning adapter interface (Dependency Inversion)."""

from typing import Any, Dict, List, Optional, Protocol, runtime_checkable
from pydantic import BaseModel, Field

from agentguard.risk.models import RiskLevel, RiskSignal


class SecurityContext(BaseModel):
    """Structured security context payload passed to AI Secura for cybersecurity reasoning."""
    trace_id: str
    task_intent: str
    initiating_user: Optional[str] = None
    acting_agent_id: Optional[str] = None
    acting_agent_name: Optional[str] = None
    acting_agent_trust: Optional[str] = None
    delegation_chain: List[Dict[str, Any]] = Field(default_factory=list)
    context_provenance: List[Dict[str, Any]] = Field(default_factory=list)
    taint_states: List[str] = Field(default_factory=list)
    tool_name: Optional[str] = None
    tool_arguments: Dict[str, Any] = Field(default_factory=dict)
    target_resource_sensitivity: Optional[str] = None


class SecurityAnalysis(BaseModel):
    """Structured reasoning output returned by AI Secura."""
    analysis_id: str
    summary: str
    risk_level: RiskLevel = RiskLevel.LOW
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    attack_indicators: List[str] = Field(default_factory=list)
    intent_drift_detected: bool = False
    authority_violation_detected: bool = False
    prompt_injection_indicators: List[str] = Field(default_factory=list)
    reasoning: str = ""
    signals: List[RiskSignal] = Field(default_factory=list)


@runtime_checkable
class SecurityReasoner(Protocol):
    """Protocol for AI Secura or pluggable cybersecurity reasoning LLM implementations."""

    def analyze(self, context: SecurityContext) -> SecurityAnalysis:
        """Analyze structured security context and produce reasoning insights without direct enforcement."""
        ...


class LocalAISecuraAdapter(SecurityReasoner):
    """Local baseline security reasoner adapter for Phase 1 testing and offline execution."""

    def analyze(self, context: SecurityContext) -> SecurityAnalysis:
        import uuid
        analysis_id = f"aisec_{uuid.uuid4().hex[:12]}"
        
        signals: List[RiskSignal] = []
        drift = False
        auth_violation = False
        attack_indicators = []

        # Check for untrusted taint in context
        if any(t in ("TAINTED", "UNTRUSTED") for t in context.taint_states):
            if context.target_resource_sensitivity in ("HIGH", "CRITICAL"):
                signals.append(
                    RiskSignal(
                        source="ai_secura",
                        risk_level=RiskLevel.HIGH,
                        score=0.85,
                        indicator="UNTRUSTED_TAINT_TO_CRITICAL_SINK",
                        details={"taint_states": context.taint_states},
                    )
                )
                attack_indicators.append("Potential Indirect Prompt Injection or Untrusted Data Exfiltration")

        # Check intent drift heuristic
        intent_lower = context.task_intent.lower()
        tool_lower = (context.tool_name or "").lower()
        if "financial" in intent_lower and any(kw in tool_lower for kw in ("delete", "admin", "drop_table")):
            drift = True
            signals.append(
                RiskSignal(
                    source="ai_secura",
                    risk_level=RiskLevel.CRITICAL,
                    score=0.95,
                    indicator="INTENT_DRIFT_DESTRUCTIVE_TOOL",
                    details={"intent": context.task_intent, "tool": context.tool_name},
                )
            )

        overall_score = max([s.score for s in signals], default=0.05)
        overall_level = RiskLevel.LOW
        if overall_score >= 0.8:
            overall_level = RiskLevel.CRITICAL
        elif overall_score >= 0.5:
            overall_level = RiskLevel.HIGH
        elif overall_score >= 0.25:
            overall_level = RiskLevel.MEDIUM

        return SecurityAnalysis(
            analysis_id=analysis_id,
            summary="Local AI Secura heuristic security analysis completed.",
            risk_level=overall_level,
            risk_score=overall_score,
            attack_indicators=attack_indicators,
            intent_drift_detected=drift,
            authority_violation_detected=auth_violation,
            reasoning=f"Analyzed delegation chain of depth {len(context.delegation_chain)} and {len(context.taint_states)} context objects.",
            signals=signals,
        )
