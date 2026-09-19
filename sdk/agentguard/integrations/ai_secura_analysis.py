"""Rich AI Secura Analysis output schema (Pydantic v2).

This schema is the contract between the OllamaAISecuraAdapter and
the rest of AgentGuard.  The PolicyEvaluator reads structured fields
from this object but remains the sole enforcement authority.
"""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
import uuid


class ThreatSeverity(str, Enum):
    """Severity classification for a detected or suspected threat."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


class IntentAlignment(str, Enum):
    """Alignment of the requested action against the original user intent."""
    ALIGNED = "ALIGNED"
    POTENTIALLY_DRIFTING = "POTENTIALLY_DRIFTING"
    VIOLATED = "VIOLATED"
    UNKNOWN = "UNKNOWN"


class AIRecommendation(str, Enum):
    """Non-binding recommendation from AI Secura to the PolicyEvaluator."""
    ALLOW = "ALLOW"
    MONITOR = "MONITOR"
    HUMAN_APPROVAL = "HUMAN_APPROVAL"
    BLOCK = "BLOCK"
    UNKNOWN = "UNKNOWN"


class AttackTechnique(str, Enum):
    """MITRE ATLAS / OWASP LLM Top-10 aligned attack technique labels."""
    PROMPT_INJECTION = "prompt_injection"
    INDIRECT_PROMPT_INJECTION = "indirect_prompt_injection"
    JAILBREAK = "jailbreak"
    SYSTEM_PROMPT_EXTRACTION = "system_prompt_extraction"
    INSTRUCTION_HIJACKING = "instruction_hijacking"
    SENSITIVE_INFORMATION_DISCLOSURE = "sensitive_information_disclosure"
    DATA_EXFILTRATION = "data_exfiltration"
    RAG_POISONING = "RAG_poisoning"
    RAG_DATA_LEAKAGE = "RAG_data_leakage"
    MALICIOUS_DOCUMENT = "malicious_document"
    AGENT_HIJACKING = "agent_hijacking"
    TOOL_ABUSE = "tool_abuse"
    EXCESSIVE_AGENCY = "excessive_agency"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    MCP_SECURITY = "MCP_security"
    TOOL_POISONING = "tool_poisoning"
    MALICIOUS_MCP_SERVER = "malicious_MCP_server"
    AI_API_SECURITY = "AI_API_security"
    AUTHENTICATION_FAILURE = "authentication_failure"
    AUTHORIZATION_FAILURE = "authorization_failure"
    AI_APPLICATION_VULNERABILITY = "AI_application_vulnerability"
    ADVERSARIAL_ATTACK = "adversarial_attack"
    CONTEXT_MANIPULATION = "context_manipulation"
    AI_SUPPLY_CHAIN = "AI_supply_chain"
    MODEL_DEPENDENCY_VULNERABILITY = "model_dependency_vulnerability"
    AI_SECURITY_MONITORING = "AI_security_monitoring"
    AI_SECURITY_EVALUATION = "AI_security_evaluation"
    LLM_RELIABILITY_SECURITY = "LLM_reliability_security"
    NONE = "none"
    UNKNOWN = "unknown"


class EvidenceTriad(BaseModel):
    """Strict separation of observed facts, inferred conclusions, and unknowns.

    AI Secura MUST NOT fabricate CVEs, CWE IDs, MITRE IDs, logs, or credentials.
    If evidence is absent, the field belongs in 'unknown'.
    """
    observed: List[str] = Field(
        default_factory=list,
        description="Facts directly present in the AgentGuard evidence packet.",
    )
    inferred: List[str] = Field(
        default_factory=list,
        description="Reasonable conclusions derived from the observed evidence.",
    )
    unknown: List[str] = Field(
        default_factory=list,
        description="Aspects that cannot be established from the available evidence.",
    )


class AuthorityAnalysis(BaseModel):
    """AI Secura reasoning about delegation authority — for explanation only, not enforcement."""
    acting_agent: Optional[str] = None
    delegated_capabilities: List[str] = Field(default_factory=list)
    requested_capability: Optional[str] = None
    required_capability: Optional[str] = None
    delegation_chain: List[str] = Field(default_factory=list)
    authority_violated: bool = False
    reasoning: str = ""


class TaintAnalysis(BaseModel):
    """AI Secura reasoning about context taint lineage."""
    context_id: Optional[str] = None
    source: Optional[str] = None
    trust_level: Optional[str] = None
    taint_state: Optional[str] = None
    origin_agent: Optional[str] = None
    propagation_chain: List[str] = Field(default_factory=list)
    is_tainted: bool = False
    reasoning: str = ""


class AISecuraAnalysis(BaseModel):
    """Complete structured output from AI Secura reasoning engine.

    IMPORTANT: This is *reasoning*, not enforcement.
    The AgentGuard PolicyEvaluator is the sole enforcement authority.
    ai_recommendation here is advisory only.
    """
    analysis_id: str = Field(default_factory=lambda: f"aisec35_{uuid.uuid4().hex[:12]}")

    # --- Threat Classification ---
    threat_type: str = Field(
        default="unknown",
        description="Primary threat type from the AI Secura security taxonomy.",
    )
    attack_category: str = Field(
        default="unknown",
        description="High-level attack category (e.g. 'injection', 'escalation', 'exfiltration').",
    )
    attack_technique: AttackTechnique = Field(
        default=AttackTechnique.UNKNOWN,
        description="Specific attack technique from the AI Secura taxonomy.",
    )
    severity: ThreatSeverity = Field(
        default=ThreatSeverity.UNKNOWN,
        description="Assessed threat severity.",
    )
    confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Confidence in the threat assessment (0.0 = uncertain, 1.0 = certain).",
    )

    # --- Evidence Model ---
    evidence: EvidenceTriad = Field(default_factory=EvidenceTriad)
    observed_indicators: List[str] = Field(
        default_factory=list,
        description="Specific observable indicators extracted from the security packet.",
    )

    # --- Alignment and Authority ---
    intent_alignment: IntentAlignment = Field(
        default=IntentAlignment.UNKNOWN,
        description="Alignment of the requested action to original user intent.",
    )
    authority_analysis: AuthorityAnalysis = Field(default_factory=AuthorityAnalysis)
    taint_analysis: TaintAnalysis = Field(default_factory=TaintAnalysis)

    # --- MITRE References (only when directly supported by evidence) ---
    mitre_attack_id: Optional[str] = Field(
        default=None,
        description="MITRE ATT&CK ID — only set when directly supported by observed evidence.",
    )
    mitre_atlas_id: Optional[str] = Field(
        default=None,
        description="MITRE ATLAS ID — only set when directly supported by observed evidence.",
    )

    # --- Analysis Narrative ---
    analysis: str = Field(
        default="",
        description="Comprehensive reasoning narrative from AI Secura.",
    )
    impact: str = Field(
        default="",
        description="Potential impact if the threat is not mitigated.",
    )
    influencing_context: str = Field(
        default="",
        description="Which context data items most influenced this analysis.",
    )

    # --- Remediation ---
    recommended_actions: List[str] = Field(
        default_factory=list,
        description="Security recommendations (advisory only).",
    )
    containment: List[str] = Field(
        default_factory=list,
        description="Immediate containment steps.",
    )
    remediation: List[str] = Field(
        default_factory=list,
        description="Longer-term remediation measures.",
    )
    additional_information_required: List[str] = Field(
        default_factory=list,
        description="Additional context or evidence needed for a definitive assessment.",
    )

    # --- Advisory Recommendation ---
    ai_recommendation: AIRecommendation = Field(
        default=AIRecommendation.UNKNOWN,
        description=(
            "NON-BINDING advisory recommendation to PolicyEvaluator. "
            "PolicyEvaluator may override this at any time."
        ),
    )

    # --- Provider Metadata ---
    provider: str = Field(default="local", description="Provider: 'ollama' or 'local'.")
    model: str = Field(default="local-heuristic")
    latency_ms: float = Field(default=0.0, description="Analysis latency in milliseconds.")
    ai_unavailable: bool = Field(
        default=False,
        description=(
            "True when Ollama is unreachable, timed out, or returned irrecoverably malformed output. "
            "When True, AgentGuard deterministic policy continues as sole enforcer."
        ),
    )
    json_repaired: bool = Field(
        default=False,
        description="True if the model output required one JSON repair attempt.",
    )
    raw_response: Optional[str] = Field(
        default=None,
        description="Raw model response string (for debugging). Redacted in production events.",
    )
