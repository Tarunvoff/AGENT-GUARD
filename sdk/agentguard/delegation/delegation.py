"""Delegation tracking and recursive delegation context management."""

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field

from agentguard.agents.identity import AgentCapability
from agentguard.delegation.authority import AuthorityGrant
from agentguard.tracing.correlation import SpanScope, generate_id, get_current_context
from agentguard.tracing.events import EventType

if TYPE_CHECKING:
    from agentguard.agents.agent import Agent
    from agentguard.client import AgentGuard


class Delegation(BaseModel):
    """Immutable delegation record capturing delegated authority in a multi-agent chain."""
    
    delegation_id: str = Field(default_factory=lambda: generate_id("dlg"), description="Unique delegation ID")
    task_id: str = Field(..., description="Active task ID")
    trace_id: str = Field(..., description="Active trace ID")
    parent_delegation_id: Optional[str] = Field(default=None, description="Immediate parent delegation ID in the chain")
    depth: int = Field(default=0, description="Nesting depth (0 = top-level delegation)")
    delegator_agent_id: str = Field(..., description="Agent granting authority")
    delegate_agent_id: str = Field(..., description="Agent receiving authority")
    authority_grant: AuthorityGrant = Field(..., description="Granted capabilities and constraints")
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC delegation creation timestamp"
    )
    status: str = Field(default="active", description="Status: 'active', 'completed', 'revoked'")
    metadata: Dict[str, Any] = Field(default_factory=dict)


class DelegationScope:
    """Context manager scope establishing an active delegation boundary."""

    def __init__(
        self,
        guard: "AgentGuard",
        delegator: "Agent",
        delegate: "Agent",
        capabilities: Optional[List[Union[str, AgentCapability]]] = None,
        constraints: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.guard = guard
        self.delegator = delegator
        self.delegate = delegate
        self.requested_capabilities = capabilities
        self.constraints = constraints or {}
        
        self.delegation: Optional[Delegation] = None
        self._span_scope: Optional[SpanScope] = None

    def __enter__(self) -> Delegation:
        current_ctx = get_current_context()
        trace_id = current_ctx.trace_id if current_ctx else generate_id("trc")
        task_id = current_ctx.task_id if current_ctx else generate_id("tsk")
        parent_delegation_id = current_ctx.delegation_id if current_ctx else None

        # Determine effective parent delegation depth
        parent_depth = 0
        parent_available_caps: List[str] = []
        
        if parent_delegation_id and parent_delegation_id in self.guard.delegation_registry:
            parent_dlg = self.guard.delegation_registry[parent_delegation_id]
            parent_depth = parent_dlg.depth + 1
            parent_available_caps = parent_dlg.authority_grant.granted_capabilities
        else:
            parent_available_caps = self.delegator.capability_names()

        # Parse requested capabilities or inherit delegator's available capabilities
        granted_cap_names: List[str] = []
        if self.requested_capabilities is not None:
            for c in self.requested_capabilities:
                if isinstance(c, str):
                    granted_cap_names.append(c)
                elif isinstance(c, AgentCapability):
                    granted_cap_names.append(c.name)
        else:
            granted_cap_names = list(parent_available_caps)

        # Build authority grant
        grant = AuthorityGrant(
            delegator_agent_id=self.delegator.agent_id,
            delegate_agent_id=self.delegate.agent_id,
            granted_capabilities=granted_cap_names,
            constraints=self.constraints,
        )

        # Check monotonic capability reduction
        if self.guard.config.enforce_monotonic_delegation:
            is_valid = grant.validate_monotonic_reduction(
                delegator_available_capabilities=parent_available_caps,
                strict=True,
            )
            if not is_valid:
                violation_details = {
                    "delegator_id": self.delegator.agent_id,
                    "delegate_id": self.delegate.agent_id,
                    "requested_capabilities": granted_cap_names,
                    "available_capabilities": parent_available_caps,
                }
                # Emit incident event
                self.guard.emit_event(
                    event_type=EventType.INCIDENT_CREATED,
                    agent_id=self.delegator.agent_id,
                    payload={
                        "incident_type": "AUTHORITY_ESCALATION_ATTEMPT",
                        "details": violation_details,
                    }
                )
                raise PermissionError(
                    f"Monotonic authority violation: Delegator '{self.delegator.name}' ({self.delegator.agent_id}) "
                    f"attempted to delegate capabilities {granted_cap_names} exceeding its authorized capabilities {parent_available_caps}"
                )

        self.delegation = Delegation(
            delegation_id=generate_id("dlg"),
            task_id=task_id,
            trace_id=trace_id,
            parent_delegation_id=parent_delegation_id,
            depth=parent_depth,
            delegator_agent_id=self.delegator.agent_id,
            delegate_agent_id=self.delegate.agent_id,
            authority_grant=grant,
            status="active",
        )

        # Store in registry
        self.guard.delegation_registry[self.delegation.delegation_id] = self.delegation

        # Enter span scope
        self._span_scope = SpanScope(
            name=f"delegation:{self.delegator.name}->{self.delegate.name}",
            trace_id=trace_id,
            task_id=task_id,
            agent_id=self.delegate.agent_id,
            delegation_id=self.delegation.delegation_id,
            metadata={
                "delegator_id": self.delegator.agent_id,
                "delegate_id": self.delegate.agent_id,
                "depth": parent_depth,
            }
        )
        self._span_scope.__enter__()

        # Emit agent.delegated event
        self.guard.emit_event(
            event_type=EventType.AGENT_DELEGATED,
            agent_id=self.delegate.agent_id,
            parent_agent_id=self.delegator.agent_id,
            delegation_id=self.delegation.delegation_id,
            payload={
                "delegator_id": self.delegator.agent_id,
                "delegator_name": self.delegator.name,
                "delegate_id": self.delegate.agent_id,
                "delegate_name": self.delegate.name,
                "granted_capabilities": granted_cap_names,
                "depth": parent_depth,
                "parent_delegation_id": parent_delegation_id,
            }
        )

        return self.delegation

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if self.delegation:
            self.delegation.status = "completed"
        if self._span_scope:
            self._span_scope.__exit__(exc_type, exc_val, exc_tb)

    async def __aenter__(self) -> Delegation:
        return self.__enter__()

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.__exit__(exc_type, exc_val, exc_tb)
