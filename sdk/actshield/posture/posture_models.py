"""Security Posture Models for ActShield Phase 9.

Defines measurable security posture dimensions, findings, snapshots, and diffs.
Adheres strictly to the principle: All posture metrics must be explainable and backed by runtime evidence.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from actshield.tracing.correlation import generate_id


class PostureRating(str, Enum):
    """Overall security posture health rating."""
    HEALTHY = "HEALTHY"
    ELEVATED_RISK = "ELEVATED_RISK"
    DEGRADED = "DEGRADED"
    CRITICAL = "CRITICAL"


class FindingSeverity(str, Enum):
    """Severity classification for posture findings."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class PostureFinding(BaseModel):
    """Discrete, explainable finding pointing to specific runtime evidence."""
    finding_id: str = Field(default_factory=lambda: generate_id("fnd"))
    category: str = Field(..., description="Category: e.g. 'authority_violation', 'taint_exposure', 'open_regression'")
    severity: FindingSeverity = Field(default=FindingSeverity.MEDIUM)
    title: str = Field(..., description="Short summary of finding")
    description: str = Field(..., description="Detailed explanation of the issue")
    affected_entities: List[str] = Field(default_factory=list, description="Agents, tools, or resources involved")
    evidence_refs: List[str] = Field(default_factory=list, description="Event IDs or trace IDs serving as ground truth")
    remediation_advice: str = Field(default="", description="Recommended action to resolve")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def deduction(self) -> float:
        if self.severity == FindingSeverity.CRITICAL:
            return 25.0
        elif self.severity == FindingSeverity.HIGH:
            return 15.0
        elif self.severity == FindingSeverity.MEDIUM:
            return 5.0
        return 2.0

    @property
    def remediation(self) -> str:
        return self.remediation_advice



class PostureDimensionMetrics(BaseModel):
    """Measurable dimensions derived from actual runtime telemetry and forensic evidence."""
    unauthorized_access_attempts: int = Field(default=0, description="Blocked unauthorized access attempts")
    actual_unauthorized_executions: int = Field(default=0, description="CRITICAL: Any execution that bypassed policy")
    tainted_sensitive_requests: int = Field(default=0, description="Requests carrying tainted context to sensitive tools")
    authority_violations: int = Field(default=0, description="Requests exceeding delegated capability boundaries")
    intent_violations: int = Field(default=0, description="Actions drifting from declared user task intent")
    blocked_actions: int = Field(default=0, description="Total actions blocked by deterministic policy")
    hitl_actions: int = Field(default=0, description="Total actions escalated to Human-In-The-Loop")
    allowed_actions: int = Field(default=0, description="Total authorized actions executed")
    high_risk_agents_count: int = Field(default=0, description="Number of agents with LOW trust or active violations")
    untrusted_context_crossings: int = Field(default=0, description="Untrusted external data ingress events")
    sensitive_resource_exposures: int = Field(default=0, description="High/Critical resource access attempts")
    open_regressions: int = Field(default=0, description="Unresolved security regression fixtures")
    failed_secured_replays: int = Field(default=0, description="Regressions that failed to block on secured replay")
    offensive_validation_failures: int = Field(default=0, description="Bypasses discovered during offensive validation")
    
    # Availability KPIs
    ai_secura_availability_pct: float = Field(default=100.0, ge=0.0, le=100.0)
    apiris_availability_pct: float = Field(default=100.0, ge=0.0, le=100.0)
    policy_engine_availability_pct: float = Field(default=100.0, ge=0.0, le=100.0)
    
    # Latency percentiles in milliseconds
    mean_enforcement_latency_ms: float = Field(default=0.0)
    p95_enforcement_latency_ms: float = Field(default=0.0)

    @property
    def threat_prevention_rate(self) -> float:
        total = self.blocked_actions + self.actual_unauthorized_executions
        return 1.0 if total == 0 else max(0.0, min(1.0, self.blocked_actions / total))

    @property
    def boundary_adherence(self) -> float:
        return 1.0 if self.authority_violations == 0 else max(0.0, 1.0 - (self.authority_violations / 10.0))

    @property
    def lineage_integrity(self) -> float:
        return 1.0 if self.tainted_sensitive_requests == 0 else max(0.0, 1.0 - (self.tainted_sensitive_requests / 10.0))

    @property
    def incident_containment_speed_score(self) -> float:
        return 100.0

    @property
    def hygiene_score(self) -> float:
        return 100.0 if self.open_regressions == 0 else max(0.0, 100.0 - (self.open_regressions * 10.0))



class SecurityPostureSnapshot(BaseModel):
    """Time-series snapshot representing the state of security at a point in time."""
    snapshot_id: str = Field(default_factory=lambda: generate_id("pos_snap"))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    rating: PostureRating = Field(default=PostureRating.HEALTHY)
    security_score: float = Field(default=100.0, ge=0.0, le=100.0, description="100.0 = perfect prevention posture")
    metrics: PostureDimensionMetrics = Field(default_factory=PostureDimensionMetrics)
    findings: List[PostureFinding] = Field(default_factory=list)
    active_incidents_count: int = Field(default=0)
    total_events_evaluated: int = Field(default=0)
    environment: str = Field(default="production")
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @property
    def overall_score(self) -> float:
        """Alias for security_score."""
        return self.security_score

    @property
    def evaluated_at(self) -> datetime:
        """Alias for timestamp."""
        return self.timestamp

    @property
    def dimensions(self) -> PostureDimensionMetrics:
        """Alias for metrics."""
        return self.metrics



class PostureDiff(BaseModel):
    """Comparative diff between two posture snapshots."""
    before_snapshot_id: str
    after_snapshot_id: str
    score_change: float
    rating_transition: str
    new_findings: List[PostureFinding] = Field(default_factory=list)
    resolved_findings: List[str] = Field(default_factory=list)
    metric_deltas: Dict[str, Any] = Field(default_factory=dict)
    summary: str


