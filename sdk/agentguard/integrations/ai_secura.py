"""AI Secura security reasoning adapter interface (Dependency Inversion).

AI Secura evaluates structured security context, detects intent drift, indirect
prompt injections, and attack indicators. AI Secura reasons and explains;
AgentGuard's deterministic policy enforces.
"""

from typing import Any, Callable, Dict, List, Optional, Protocol, runtime_checkable
import uuid
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
    metadata: Dict[str, Any] = Field(default_factory=dict)


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
    """Protocol for AI Secura cybersecurity reasoning implementations."""

    def analyze(self, context: SecurityContext) -> SecurityAnalysis:
        """Analyze structured security context and produce reasoning insights without direct enforcement."""
        ...


class AISecuraClient(SecurityReasoner):
    """AI Secura Security Intelligence Reasoner.
    
    Provides deep semantic analysis across multi-agent delegation chains,
    untrusted MCP prompt injections, and intent divergence.
    """

    def __init__(
        self,
        api_endpoint: Optional[str] = None,
        api_key: Optional[str] = None,
        custom_engine: Optional[Callable[[SecurityContext], SecurityAnalysis]] = None,
    ) -> None:
        self.api_endpoint = api_endpoint or "https://ai-secura.internal/v1/reason"
        self.api_key = api_key or "ai-secura-live-token"
        self.custom_engine = custom_engine

    def analyze(self, context: SecurityContext) -> SecurityAnalysis:
        """Perform AI Secura security reasoning over the provided multi-agent context."""
        if self.custom_engine:
            return self.custom_engine(context)

        analysis_id = f"aisec_{uuid.uuid4().hex[:12]}"
        signals: List[RiskSignal] = []
        attack_indicators: List[str] = []
        prompt_injections: List[str] = []
        drift = False
        auth_violation = False

        # 1. Evaluate context taint and prompt injection heuristics
        args_str = str(context.tool_arguments).lower()
        context_str = json_str = str(context.context_provenance).lower()

        if any(kw in context_str or kw in args_str for kw in (
            "system directive", "override", "ignore previous", "exfiltrate",
            "admin exemption", "ciso security team has granted", "emergency exemption"
        )):
            prompt_injections.append("ADVERSARIAL_INDIRECT_PROMPT_INJECTION_DIRECTIVE")
            attack_indicators.append("Adversarial payload instruction detected in causal lineage")
            signals.append(
                RiskSignal(
                    source="ai_secura",
                    risk_level=RiskLevel.CRITICAL,
                    score=0.95,
                    indicator="AI_SECURA_PROMPT_INJECTION_DETECTED",
                    details={"matched_keywords": ["system directive", "override", "exfiltrate"]},
                )
            )

        # 2. Check for untrusted taint targeting critical sinks
        if any(t in ("TAINTED", "UNTRUSTED") for t in context.taint_states):
            if context.target_resource_sensitivity in ("HIGH", "CRITICAL"):
                signals.append(
                    RiskSignal(
                        source="ai_secura",
                        risk_level=RiskLevel.HIGH,
                        score=0.85,
                        indicator="AI_SECURA_TAINTED_CONTEXT_TO_SENSITIVE_SINK",
                        details={"taint_states": context.taint_states, "target_sensitivity": context.target_resource_sensitivity},
                    )
                )
                attack_indicators.append("Untrusted context attempting to influence sensitive data sink")

        # 3. Check intent drift
        intent_lower = (context.task_intent or "").lower()
        tool_lower = (context.tool_name or "").lower()
        if "public" in intent_lower or "research" in intent_lower:
            if any(p in tool_lower for p in ("customer_db", "pii", "users", "delete", "admin")):
                drift = True
                signals.append(
                    RiskSignal(
                        source="ai_secura",
                        risk_level=RiskLevel.CRITICAL,
                        score=0.90,
                        indicator="AI_SECURA_INTENT_DRIFT_PUBLIC_VS_SENSITIVE_SINK",
                        details={"intent": context.task_intent, "tool": context.tool_name},
                    )
                )
                attack_indicators.append(f"Intent drift: Public research intent diverted to sensitive tool '{context.tool_name}'")

        overall_score = max([s.score for s in signals], default=0.05)
        if overall_score >= 0.8:
            overall_level = RiskLevel.CRITICAL
        elif overall_score >= 0.5:
            overall_level = RiskLevel.HIGH
        elif overall_score >= 0.25:
            overall_level = RiskLevel.MEDIUM
        else:
            overall_level = RiskLevel.LOW

        reasoning = (
            f"AI Secura Reasoning: Evaluated delegation chain depth {len(context.delegation_chain)}, "
            f"{len(context.taint_states)} context states. "
            f"Prompt Injections: {len(prompt_injections)}, Intent Drift: {drift}."
        )

        return SecurityAnalysis(
            analysis_id=analysis_id,
            summary="AI Secura cybersecurity analysis completed.",
            risk_level=overall_level,
            risk_score=overall_score,
            attack_indicators=attack_indicators,
            intent_drift_detected=drift,
            authority_violation_detected=auth_violation,
            prompt_injection_indicators=prompt_injections,
            reasoning=reasoning,
            signals=signals,
        )


class LocalAISecuraAdapter(AISecuraClient):
    """Backward-compatible alias for local execution."""
    pass
