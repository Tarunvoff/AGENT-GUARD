"""Clean API response models — dashboard-ready JSON shapes.

The dashboard NEVER needs to understand internal Python classes.
These models define the stable JSON contract consumed by the React dashboard.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from agentguard.tracing.correlation import generate_id


class HealthResponse(BaseModel):
    status: str = "ok"
    version: str = "1.0.0"
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    components: Dict[str, str] = Field(default_factory=dict)


class ErrorResponse(BaseModel):
    error: Dict[str, str]

    @classmethod
    def make(
        cls, code: str, message: str, request_id: Optional[str] = None
    ) -> "ErrorResponse":
        return cls(
            error={
                "code": code,
                "message": message,
                "request_id": request_id or generate_id("req"),
            }
        )


class OverviewResponse(BaseModel):
    agents: Optional[int] = None
    active_tasks: Optional[int] = None
    protected_tools: Optional[int] = None
    mcp_servers: Optional[int] = None
    attacks_today: Optional[int] = None
    blocked: Optional[int] = None
    hitl: Optional[int] = None
    bypasses: Optional[int] = None
    sensitive_attempts: Optional[int] = None
    sensitive_prevented: Optional[int] = None
    sensitive_executed: Optional[int] = None
    campaigns: Optional[int] = None
    regressions: Optional[int] = None
    incidents: Optional[int] = None
    availability: Optional[Dict[str, bool]] = None


class AgentSummary(BaseModel):
    agent_id: str
    agent_name: str
    trust_level: str
    effective_capabilities: List[str]
    total_attempts: int
    total_blocked: int


class AgentAccessResponse(BaseModel):
    agent_id: str
    agent_name: str
    trust_level: str
    declared: List[str] = Field(default_factory=list)
    delegated: List[str] = Field(default_factory=list)
    effective: List[str] = Field(default_factory=list)
    restricted: List[str] = Field(default_factory=list)
    reachable_tools: List[str] = Field(default_factory=list)
    reachable_resources: List[str] = Field(default_factory=list)
    total_attempts: int = 0
    total_blocked: int = 0
    total_allowed: int = 0
    total_executions: int = 0


class ResourceAccessResponse(BaseModel):
    resource_id: str
    resource_name: str
    resource_type: str
    sensitivity: str
    exposing_tools: List[str] = Field(default_factory=list)
    authorized_agents: List[str] = Field(default_factory=list)
    attempted_agents: List[str] = Field(default_factory=list)
    actual_access_agents: List[str] = Field(default_factory=list)
    blocked_agents: List[str] = Field(default_factory=list)
    total_attempts: int = 0
    total_blocked: int = 0
    total_executions: int = 0


class AccessMatrixResponse(BaseModel):
    matrix_id: str
    agents: List[str]
    resources: List[str]
    table: Dict[str, Dict[str, str]] = Field(default_factory=dict)
    effective_permissions: Dict[str, Dict[str, bool]] = Field(default_factory=dict)


class SnapshotSummary(BaseModel):
    snapshot_id: str
    label: str
    timestamp: str


class DiffResponse(BaseModel):
    diff_id: str
    before_snapshot_id: str
    after_snapshot_id: str
    authority_changed: bool
    new_capabilities: List[str]
    lost_capabilities: List[str]
    attack_detected: bool
    taint_changed: bool
    context_changed: bool
    summary: str


class AttackSummary(BaseModel):
    attack_id: str
    campaign_id: Optional[str]
    attack_type: str
    target: str
    entry_point: str
    expected_decision: str
    actual_decision: str
    bypassed: bool
    tool_executed: bool
    execution_count: int


class AttackForensicsResponse(BaseModel):
    report_id: str
    attack_id: str
    campaign_id: Optional[str]
    attack_type: str
    target: str
    agent_id: str
    original_intent: str
    mutation_lineage: List[str]
    taint_state: str
    policy_decision: str
    policy_reason_code: str
    tool_executed: bool
    execution_count: int
    sensitive_db_calls: int
    bypassed: bool
    reachable_resources: List[str]
    regression_status: str


class CampaignSummary(BaseModel):
    campaign_id: str
    total_attacks: int
    bypasses: int
    blocks: int
    bypass_rate: float


class IncidentResponse(BaseModel):
    incident_id: str
    incident_type: str
    severity: str
    agent_id: Optional[str]
    resource_name: Optional[str]
    tool_name: Optional[str]
    decision: str
    executed: bool
    trace_id: Optional[str]
    attack_id: Optional[str]
    status: str
    description: str
    timestamp: str


class PolicyEvaluateRequest(BaseModel):
    tool_name: str
    agent_id: str
    capabilities: List[str] = Field(default_factory=list)
    tainted_context: bool = False
    intent: str = ""


class PolicyEvaluateResponse(BaseModel):
    tool_name: str
    agent_id: str
    decision: str
    reason_code: str
    explanation: str
    risk_score: float
