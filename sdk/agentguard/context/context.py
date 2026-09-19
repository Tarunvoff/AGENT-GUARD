"""Context container tracking data lineage, provenance, and taint state."""

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional
from pydantic import BaseModel, Field

from agentguard.context.provenance import ContextSource, Provenance
from agentguard.context.taint import TaintState
from agentguard.tracing.correlation import generate_id
from agentguard.tracing.events import EventType

if TYPE_CHECKING:
    from agentguard.client import AgentGuard


class Context(BaseModel):
    """Context and data lineage container tracked by AgentGuard."""
    
    context_id: str = Field(default_factory=lambda: generate_id("ctx"), description="Unique context ID")
    data: Any = Field(default=None, description="Payload data content or summary")
    source: ContextSource = Field(default=ContextSource.USER, description="Original source")
    source_type: str = Field(default="text", description="MIME type or semantic type")
    source_uri: Optional[str] = Field(default=None, description="URI or locator of context source")
    trust_level: str = Field(default="trusted", description="Trust level assigned at ingestion")
    taint_state: TaintState = Field(default=TaintState.TRUSTED, description="Current taint classification")
    
    # Origin & Lineage
    originating_event_id: Optional[str] = Field(default=None, description="Originating event ID")
    originating_agent_id: Optional[str] = Field(default=None, description="Agent that ingested or produced this")
    current_agent_id: Optional[str] = Field(default=None, description="Agent currently holding this context")
    parent_context_id: Optional[str] = Field(default=None, description="Parent context if derived")
    
    provenance: Provenance = Field(
        default_factory=Provenance,
        description="Chronological provenance graph"
    )
    
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Creation timestamp"
    )
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Custom metadata tags")

    def propagate(
        self,
        to_agent_id: str,
        action: str = "propagated",
        new_data: Any = None,
        taint_override: Optional[TaintState] = None,
        guard: Optional["AgentGuard"] = None,
    ) -> "Context":
        """Propagate or transform this context to another agent, recording the lineage hop."""
        new_taint = taint_override or self.taint_state
        new_provenance = self.provenance.model_copy(deep=True)
        
        derived_ctx = Context(
            context_id=generate_id("ctx"),
            data=new_data if new_data is not None else self.data,
            source=self.source,
            source_type=self.source_type,
            source_uri=self.source_uri,
            trust_level=self.trust_level,
            taint_state=new_taint,
            originating_event_id=self.originating_event_id,
            originating_agent_id=self.originating_agent_id,
            current_agent_id=to_agent_id,
            parent_context_id=self.context_id,
            provenance=new_provenance,
            metadata=dict(self.metadata),
        )

        event_id = None
        if guard is not None:
            guard.context_registry[derived_ctx.context_id] = derived_ctx
            evt = guard.emit_event(
                event_type=EventType.CONTEXT_PROPAGATED,
                context_id=derived_ctx.context_id,
                agent_id=to_agent_id,
                parent_agent_id=self.current_agent_id,
                payload={
                    "parent_context_id": self.context_id,
                    "taint_state": derived_ctx.taint_state.value,
                    "action": action,
                }
            )
            event_id = evt.event_id

        derived_ctx.provenance.record_hop(
            agent_id=to_agent_id,
            action=action,
            event_id=event_id,
            details={"from_agent": self.current_agent_id, "taint": new_taint.value},
        )

        return derived_ctx
