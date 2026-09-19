"""Strongly typed security events for multi-agent observability and enforcement."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional
from pydantic import BaseModel, ConfigDict, Field

from agentguard.tracing.correlation import generate_id


class EventType(str, Enum):
    """Enumeration of standard security-relevant event types."""
    AGENT_CREATED = "agent.created"
    AGENT_INVOKED = "agent.invoked"
    TASK_STARTED = "task.started"
    TASK_COMPLETED = "task.completed"
    AGENT_DELEGATED = "agent.delegated"
    CONTEXT_RECEIVED = "context.received"
    CONTEXT_GENERATED = "context.generated"
    CONTEXT_PROPAGATED = "context.propagated"
    TOOL_REQUESTED = "tool.requested"
    TOOL_INVOKED = "tool.invoked"
    RESOURCE_ACCESS_REQUESTED = "resource.access_requested"
    SECURITY_EVALUATED = "security.evaluated"
    SECURITY_DECISION = "security.decision"
    HUMAN_APPROVAL_REQUESTED = "human.approval_requested"
    HUMAN_APPROVAL_RECEIVED = "human.approval_received"
    INCIDENT_CREATED = "incident.created"


class SecurityEvent(BaseModel):
    """Core security event model for distributed provenance and causal reconstruction."""
    
    model_config = ConfigDict(arbitrary_types_allowed=True)

    event_id: str = Field(default_factory=lambda: generate_id("evt"), description="Unique event ID")
    event_type: EventType = Field(..., description="Categorical type of the security event")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of when the event occurred"
    )
    
    # Correlation coordinates
    trace_id: str = Field(..., description="Root trace ID for causal correlation")
    span_id: str = Field(..., description="Span ID representing the current execution boundary")
    parent_event_id: Optional[str] = Field(default=None, description="Immediate causal parent event ID")
    
    # Agent coordinates
    agent_id: Optional[str] = Field(default=None, description="Acting agent ID")
    parent_agent_id: Optional[str] = Field(default=None, description="Delegating or parent agent ID")
    
    # Execution coordinates
    task_id: Optional[str] = Field(default=None, description="Active task ID")
    delegation_id: Optional[str] = Field(default=None, description="Active delegation context ID")
    context_id: Optional[str] = Field(default=None, description="Associated context or data lineage ID")
    
    # Event data
    payload: Dict[str, Any] = Field(default_factory=dict, description="Structured event payload")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Custom metadata and tags")
