"""Security Incident Model for AgentGuard Phase 9."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from agentguard.incidents.incident_state import IncidentSeverity, IncidentState
from agentguard.tracing.correlation import generate_id


class IncidentTimelineEntry(BaseModel):
    """A chronological causal entry within an incident storyline."""
    timestamp: str = Field(..., description="ISO timestamp or formatted time")
    stage: str = Field(..., description="Stage e.g. '01. INTENT', '03. CONTEXT', '07. ENFORCE'")
    agent_id: Optional[str] = None
    agent_name: Optional[str] = None
    action: str = ""
    detail: str = ""
    taint_state: str = "CLEAN"
    decision: Optional[str] = None
    event_id: Optional[str] = None
    actor_name: Optional[str] = None
    incident_state: Optional[IncidentState] = None

    @property
    def actor(self) -> str:
        return self.actor_name or self.agent_name or self.agent_id or "system"

    @property
    def reason(self) -> str:
        return self.detail or self.action

    @property
    def state(self) -> IncidentState:
        return self.incident_state or IncidentState.DETECTED


class SecurityIncident(BaseModel):
    """Complete causal security incident record."""
    incident_id: str = Field(default_factory=lambda: generate_id("inc"))
    title: str = Field(..., description="Summary title of the incident")
    severity: IncidentSeverity = Field(default=IncidentSeverity.MEDIUM)
    state: IncidentState = Field(default=IncidentState.DETECTED)
    attack_type: str = Field(default="policy_violation", description="Classification e.g. 'indirect_prompt_injection', 'authority_escape'")
    root_event_id: Optional[str] = None
    trace_id: str = Field(default_factory=lambda: generate_id("trc"), description="Causal trace ID linking all events")
    
    # Affected security entities
    affected_agents: List[str] = Field(default_factory=list)
    affected_tasks: List[str] = Field(default_factory=list)
    affected_resources: List[str] = Field(default_factory=list)
    
    # Causal context & taint state
    context_source: Optional[str] = None
    trust_state: str = "UNKNOWN"
    taint_state: str = "CLEAN"
    authority_violated: bool = False
    
    # Decisions & runtime evidence
    policy_verdict: str = "BLOCK"
    sensitive_operations_attempted: int = 0
    sensitive_operations_executed: int = 0  # CRITICAL: 0 proves prevention held
    
    # Intelligence enrichments
    ai_secura_summary: Optional[str] = None
    apiris_signals: List[str] = Field(default_factory=list)
    
    # Lifecycle & timeline
    timeline: List[IncidentTimelineEntry] = Field(default_factory=list)
    remediation_notes: Optional[str] = None
    regression_id: Optional[str] = None
    secured_replay_verified: bool = False
    
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @property
    def target_agent_id(self) -> str:
        return self.affected_agents[0] if self.affected_agents else ""

    @property
    def tool_name(self) -> str:
        return self.affected_resources[0] if self.affected_resources else ""

    @property
    def root_cause(self) -> str:
        return self.ai_secura_summary or self.remediation_notes or "Security boundary violation"

