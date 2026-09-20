"""Security Drift Models for AgentGuard Phase 9."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from agentguard.tracing.correlation import generate_id


class DriftCategory(str, Enum):
    """Categorization of observed security drift."""
    AUTHORITY_DRIFT = "AUTHORITY_DRIFT"
    ACCESS_DRIFT = "ACCESS_DRIFT"
    CONTEXT_DRIFT = "CONTEXT_DRIFT"
    POLICY_DRIFT = "POLICY_DRIFT"
    BEHAVIORAL_DEVIATION = "BEHAVIORAL_DEVIATION"


class DriftSeverity(str, Enum):
    """Security severity of the detected drift."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DriftEvent(BaseModel):
    """Discrete security drift observation."""
    drift_id: str = Field(default_factory=lambda: generate_id("drf"))
    category: DriftCategory
    severity: DriftSeverity = Field(default=DriftSeverity.MEDIUM)
    entity_id: str = Field(..., description="Agent ID, context ID, or policy ID")
    entity_type: str = Field(..., description="'agent', 'context', 'tool', 'policy'")
    title: str
    description: str
    before_state: Any
    after_state: Any
    security_implication: str
    review_required: bool = True
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    evidence_refs: List[str] = Field(default_factory=list)

    @property
    def agent_id(self) -> str:
        """Convenience property for agent entity ID."""
        return self.entity_id



class AgentBehaviorBaseline(BaseModel):
    """Statistical profile of normal agent operation."""
    agent_id: str
    normal_tools: List[str] = Field(default_factory=list)
    normal_resources: List[str] = Field(default_factory=list)
    normal_max_depth: int = Field(default=2)
    normal_context_sources: List[str] = Field(default_factory=list)
    sample_count: int = 0
    last_updated: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
