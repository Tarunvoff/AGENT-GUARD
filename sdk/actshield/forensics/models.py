"""Forensic data models — Clean structured representations of security state.

These models are NEW. They do NOT duplicate existing security models.
They reference existing models by ID and add forensic-specific views.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from actshield.tracing.correlation import generate_id


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class AccessDecision(str, Enum):
    """Forensic access decision classification."""
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    HITL = "HITL"
    MONITOR = "MONITOR"
    UNKNOWN = "UNKNOWN"


class IncidentType(str, Enum):
    """Classification of security incident types."""
    INDIRECT_PROMPT_INJECTION = "INDIRECT_PROMPT_INJECTION"
    AUTHORITY_ESCALATION = "AUTHORITY_ESCALATION"
    TAINT_PROPAGATION = "TAINT_PROPAGATION"
    CAPABILITY_VIOLATION = "CAPABILITY_VIOLATION"
    INTENT_VIOLATION = "INTENT_VIOLATION"
    BYPASS_DETECTED = "BYPASS_DETECTED"
    UNTRUSTED_SENSITIVE_ACCESS = "UNTRUSTED_SENSITIVE_ACCESS"
    DELEGATION_VIOLATION = "DELEGATION_VIOLATION"
    GENERIC = "GENERIC"


class IncidentSeverity(str, Enum):
    """Incident severity tiers."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class IncidentStatus(str, Enum):
    """Incident containment status."""
    CONTAINED = "CONTAINED"
    ACTIVE = "ACTIVE"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"


# ---------------------------------------------------------------------------
# Graph Relationship Models
# ---------------------------------------------------------------------------

class AuthorityRelationship(BaseModel):
    """A single authority edge: who delegated what to whom."""
    relationship_id: str = Field(default_factory=lambda: generate_id("arl"))
    source_agent_id: str
    target_agent_id: str
    relationship_type: str = "delegates"
    capabilities: List[str] = Field(default_factory=list)
    delegation_id: Optional[str] = None
    task_id: Optional[str] = None
    trace_id: Optional[str] = None
    depth: int = 0
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status: str = "active"


class AccessRelationship(BaseModel):
    """A single access edge: agent↔tool↔resource."""
    relationship_id: str = Field(default_factory=lambda: generate_id("acc"))
    agent_id: str
    tool_name: str
    resource_id: Optional[str] = None
    resource_name: Optional[str] = None
    decision: AccessDecision = AccessDecision.UNKNOWN
    executed: bool = False
    capability_required: Optional[str] = None
    sensitivity: str = "UNKNOWN"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    trace_id: Optional[str] = None
    task_id: Optional[str] = None
    taint_state: str = "CLEAN"
    reason_code: str = ""


class DelegationRelationship(BaseModel):
    """Delegation chain edge — forensic representation of a Delegation record."""
    delegation_id: str
    delegator_agent_id: str
    delegate_agent_id: str
    granted_capabilities: List[str] = Field(default_factory=list)
    depth: int = 0
    parent_delegation_id: Optional[str] = None
    task_id: Optional[str] = None
    trace_id: Optional[str] = None
    status: str = "active"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Access Attempt / Actual Access
# ---------------------------------------------------------------------------

class AccessAttempt(BaseModel):
    """Records that an agent attempted to access a tool/resource."""
    attempt_id: str = Field(default_factory=lambda: generate_id("att"))
    agent_id: str
    task_id: Optional[str] = None
    trace_id: Optional[str] = None
    tool_name: str
    capability_requested: Optional[str] = None
    required_capability: Optional[str] = None
    resource_name: Optional[str] = None
    resource_sensitivity: str = "UNKNOWN"
    decision: AccessDecision = AccessDecision.UNKNOWN
    policy_reason: str = ""
    context_ids: List[str] = Field(default_factory=list)
    taint_state: str = "CLEAN"
    authority_contained: bool = True
    executed: bool = False
    execution_count: int = 0
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def was_blocked(self) -> bool:
        return self.decision == AccessDecision.BLOCK

    @property
    def was_allowed(self) -> bool:
        return self.decision in (AccessDecision.ALLOW, AccessDecision.MONITOR)


class ActualAccess(BaseModel):
    """Records confirmed execution — tool ran, resource was accessed."""
    access_id: str = Field(default_factory=lambda: generate_id("axs"))
    agent_id: str
    tool_name: str
    resource_name: Optional[str] = None
    resource_sensitivity: str = "UNKNOWN"
    execution_count: int = 1
    sensitive_db_calls: int = 0
    trace_id: Optional[str] = None
    task_id: Optional[str] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Agent & Resource Access Profiles
# ---------------------------------------------------------------------------

class AgentAccessProfile(BaseModel):
    """Complete forensic access profile for a single agent."""
    agent_id: str
    agent_name: str
    trust_level: str = "medium"
    declared_capabilities: List[str] = Field(default_factory=list)
    delegated_capabilities: List[str] = Field(default_factory=list)
    effective_capabilities: List[str] = Field(default_factory=list)
    restricted_capabilities: List[str] = Field(default_factory=list)
    reachable_tools: List[str] = Field(default_factory=list)
    reachable_resources: List[str] = Field(default_factory=list)
    recent_attempts: List[AccessAttempt] = Field(default_factory=list)
    recent_actual_access: List[ActualAccess] = Field(default_factory=list)
    delegation_chain: List[DelegationRelationship] = Field(default_factory=list)
    total_attempts: int = 0
    total_blocked: int = 0
    total_allowed: int = 0
    total_executions: int = 0
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ResourceAccessProfile(BaseModel):
    """Complete forensic access profile for a single resource."""
    resource_id: str
    resource_name: str
    resource_type: str = "api"
    sensitivity: str = "MEDIUM"
    exposing_tools: List[str] = Field(default_factory=list)
    authorized_agents: List[str] = Field(default_factory=list)
    attempted_agents: List[str] = Field(default_factory=list)
    actual_access_agents: List[str] = Field(default_factory=list)
    blocked_agents: List[str] = Field(default_factory=list)
    access_history: List[AccessAttempt] = Field(default_factory=list)
    total_attempts: int = 0
    total_blocked: int = 0
    total_executions: int = 0
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Access Matrix
# ---------------------------------------------------------------------------

class AccessMatrixEntry(BaseModel):
    """Single cell in the access matrix: agent × resource."""
    agent_id: str
    resource_name: str
    effective_permission: bool = False
    historically_accessed: bool = False
    attempted: bool = False
    blocked: bool = False


class AccessMatrix(BaseModel):
    """Machine-readable access matrix: agents × resources."""
    matrix_id: str = Field(default_factory=lambda: generate_id("mat"))
    agents: List[str] = Field(default_factory=list)
    resources: List[str] = Field(default_factory=list)
    # entries[agent_id][resource_name] = AccessMatrixEntry
    entries: Dict[str, Dict[str, AccessMatrixEntry]] = Field(default_factory=dict)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def to_table(self) -> Dict[str, Any]:
        """Return table-friendly representation."""
        rows = {}
        for agent in self.agents:
            rows[agent] = {}
            for resource in self.resources:
                entry = self.entries.get(agent, {}).get(resource)
                if entry:
                    if entry.effective_permission and entry.historically_accessed:
                        rows[agent][resource] = "YES (accessed)"
                    elif entry.effective_permission:
                        rows[agent][resource] = "YES"
                    elif entry.attempted:
                        rows[agent][resource] = "ATTEMPTED (blocked)"
                    else:
                        rows[agent][resource] = "NO"
                else:
                    rows[agent][resource] = "NO"
        return rows


# ---------------------------------------------------------------------------
# Access Snapshot & Diff
# ---------------------------------------------------------------------------

class AgentSnapshot(BaseModel):
    """Point-in-time security state of one agent."""
    agent_id: str
    effective_capabilities: List[str] = Field(default_factory=list)
    reachable_resources: List[str] = Field(default_factory=list)
    active_delegations: List[str] = Field(default_factory=list)
    taint_exposure: bool = False


class AccessSnapshot(BaseModel):
    """Complete security state snapshot at a point in time."""
    snapshot_id: str = Field(default_factory=lambda: generate_id("snp"))
    label: str = "snapshot"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    agents: Dict[str, AgentSnapshot] = Field(default_factory=dict)
    resources: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    delegations: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    context_count: int = 0
    tainted_context_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json")


class AccessDiff(BaseModel):
    """Before/after comparison of security state — distinguishes authority change from attack attempt."""
    diff_id: str = Field(default_factory=lambda: generate_id("dif"))
    before_snapshot_id: str
    after_snapshot_id: str
    authority_changed: bool = False
    new_capabilities: List[str] = Field(default_factory=list)
    lost_capabilities: List[str] = Field(default_factory=list)
    new_attempts: List[AccessAttempt] = Field(default_factory=list)
    new_actual_accesses: List[ActualAccess] = Field(default_factory=list)
    taint_changed: bool = False
    context_changed: bool = False
    attack_detected: bool = False
    attack_ids: List[str] = Field(default_factory=list)
    summary: str = ""
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Forensic Explanation
# ---------------------------------------------------------------------------

class ForensicExplanation(BaseModel):
    """Deterministic, evidence-backed explanation of a security decision.

    Assembled entirely from existing evidence — no LLM inference.
    """
    explanation_id: str = Field(default_factory=lambda: generate_id("exp"))
    event_id: Optional[str] = None
    trace_id: Optional[str] = None
    agent_id: str
    tool_name: str
    resource_name: Optional[str] = None
    resource_sensitivity: str = "UNKNOWN"

    # User intent
    original_intent: str = "Unspecified"

    # Influencing context
    influencing_context_sources: List[str] = Field(default_factory=list)
    influencing_context_ids: List[str] = Field(default_factory=list)
    context_trust: str = "UNKNOWN"

    # Taint
    taint_state: str = "CLEAN"

    # Authority chain
    delegated_authority: List[str] = Field(default_factory=list)
    requested_capability: Optional[str] = None
    effective_authority: str = "DENIED"  # "GRANTED" or "DENIED"

    # Policy
    policy_decision: AccessDecision = AccessDecision.UNKNOWN
    policy_reason_code: str = ""
    policy_explanation: str = ""

    # Intelligence signals (references only)
    ai_secura_summary: Optional[str] = None
    apiris_summary: Optional[str] = None

    # Hard execution evidence
    tool_executed: bool = False
    execution_count: int = 0
    sensitive_db_calls: int = 0

    # Bypass forensics (Phase 5 integration)
    bypass_detected: bool = False
    bypass_attack_id: Optional[str] = None
    regression_created: bool = False

    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def to_text(self) -> str:
        """Render human-readable forensic explanation."""
        lines = [
            "=" * 60,
            f"FORENSIC EXPLANATION — {self.tool_name}",
            "=" * 60,
            f"Agent:               {self.agent_id}",
            f"Tool:                {self.tool_name}",
            f"Resource:            {self.resource_name or 'N/A'}",
            f"Sensitivity:         {self.resource_sensitivity}",
            "",
            f"Original Intent:     {self.original_intent}",
            f"Context Sources:     {', '.join(self.influencing_context_sources) or 'none'}",
            f"Context Trust:       {self.context_trust}",
            f"Taint State:         {self.taint_state}",
            "",
            f"Delegated Authority: {', '.join(self.delegated_authority) or 'none'}",
            f"Requested Cap:       {self.requested_capability or 'N/A'}",
            f"Effective Authority: {self.effective_authority}",
            "",
            f"Policy Decision:     {self.policy_decision.value}",
            f"Reason Code:         {self.policy_reason_code}",
            f"Explanation:         {self.policy_explanation}",
            "",
        ]
        if self.ai_secura_summary:
            lines.append(f"AI Secura:           {self.ai_secura_summary}")
        if self.apiris_summary:
            lines.append(f"APIRIS:              {self.apiris_summary}")
        lines += [
            "",
            f"Tool Executed:       {self.tool_executed}",
            f"Execution Count:     {self.execution_count}",
            f"Sensitive DB Calls:  {self.sensitive_db_calls}",
        ]
        if self.bypass_detected:
            lines += [
                "",
                f"⚠ BYPASS DETECTED — Attack: {self.bypass_attack_id}",
                f"  Regression Created: {self.regression_created}",
            ]
        lines.append("=" * 60)
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Attack Forensic Report
# ---------------------------------------------------------------------------

class AttackForensicReport(BaseModel):
    """Unified forensic report for a single attack run.

    Aggregates: attack metadata + mutation lineage + security pipeline
    evidence + access impact + reachable resources + regression status.
    Connects Phase 5 offensive evidence to the forensic layer.
    """
    report_id: str = Field(default_factory=lambda: generate_id("afr"))
    attack_id: str
    campaign_id: Optional[str] = None
    attack_type: str = "UNKNOWN"
    target: str = ""
    entry_point: str = ""

    # Agent & task context
    agent_id: str = ""
    task_id: Optional[str] = None
    trace_id: Optional[str] = None
    original_intent: str = ""

    # Mutation lineage (Phase 5)
    mutation_lineage: List[str] = Field(default_factory=list)
    adaptive_iteration: int = 0
    parent_attack_id: Optional[str] = None

    # Context provenance
    influencing_contexts: List[str] = Field(default_factory=list)
    context_trust: str = "UNKNOWN"
    taint_state: str = "TAINTED"

    # Authority chain
    delegated_capabilities: List[str] = Field(default_factory=list)
    requested_capability: Optional[str] = None
    effective_capabilities: List[str] = Field(default_factory=list)
    authority_contained: bool = True

    # Resource target
    resource_name: Optional[str] = None
    resource_sensitivity: str = "UNKNOWN"

    # Intelligence signals
    apiris_summary: Optional[str] = None
    ai_secura_summary: Optional[str] = None
    risk_score: float = 0.0

    # Policy decision
    policy_decision: AccessDecision = AccessDecision.UNKNOWN
    policy_reason_code: str = ""
    policy_explanation: str = ""

    # Hard execution evidence
    tool_executed: bool = False
    execution_count: int = 0
    sensitive_db_calls: int = 0

    # Access impact
    actual_access: bool = False
    reachable_resources: List[str] = Field(default_factory=list)

    # Outcome
    bypassed: bool = False
    expected_decision: str = "BLOCK"
    actual_decision: str = "UNKNOWN"

    # Remediation
    remediation_status: str = "NONE"
    regression_status: str = "NONE"
    regression_fixture_id: Optional[str] = None

    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Incident
# ---------------------------------------------------------------------------

class ForensicIncident(BaseModel):
    """Unified incident — references (not duplicates) existing evidence."""
    incident_id: str = Field(default_factory=lambda: generate_id("inc"))
    incident_type: IncidentType = IncidentType.GENERIC
    severity: IncidentSeverity = IncidentSeverity.HIGH
    agent_id: Optional[str] = None
    resource_name: Optional[str] = None
    tool_name: Optional[str] = None
    decision: AccessDecision = AccessDecision.UNKNOWN
    executed: bool = False
    # References (IDs only — no duplication)
    trace_id: Optional[str] = None
    attack_id: Optional[str] = None
    decision_id: Optional[str] = None
    campaign_id: Optional[str] = None
    status: IncidentStatus = IncidentStatus.CONTAINED
    description: str = ""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

