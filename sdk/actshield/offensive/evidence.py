"""Unified Security Analysis Evidence — Complete audit trail for attack analysis."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from actshield.offensive.attack import AttackType


class SecurityAnalysisEvidence(BaseModel):
    """Unified security evidence object capturing the end-to-end pipeline:
    OBSERVE -> CORRELATE -> ANALYZE -> ENFORCE -> EXECUTE.
    """

    attack_id: str
    attack_type: AttackType
    trace_id: Optional[str] = None
    acting_agent: str
    task_intent: str
    entry_point: str

    # Context & Taint Provenance
    context_sources: List[str] = Field(default_factory=list)
    taint_state: str = "CLEAN"
    context_ids: List[str] = Field(default_factory=list)

    # Authority & Capability
    requested_tool: str
    requested_capability: Optional[str] = None
    required_capabilities: List[str] = Field(default_factory=list)
    delegated_capabilities: List[str] = Field(default_factory=list)
    authority_contained: bool = True
    authority_reason: str = ""

    # Intent Alignment
    intent_aligned: bool = True
    intent_explanation: str = ""

    # APIRIS Tool Intelligence
    apiris_analysis: Optional[Dict[str, Any]] = None
    apiris_unavailable: bool = False

    # AI Secura Contextual Reasoning
    ai_analysis: Optional[Dict[str, Any]] = None
    ai_unavailable: bool = False

    # Deterministic Policy Decision
    policy_decision: str = "UNKNOWN"
    policy_reason_code: str = ""
    policy_explanation: str = ""
    risk_score: float = 0.0

    # Runtime Execution Evidence
    tool_executed: bool = False
    execution_count: int = 0
    sensitive_db_calls: int = 0

    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        """Convert evidence to structured dictionary."""
        return self.model_dump(mode="json")

