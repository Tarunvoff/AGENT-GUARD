"""Context container tracking data lineage, provenance, and taint state."""

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional
from pydantic import BaseModel, Field

from actshield.context.provenance import ContextSource, ContextTrustLevel, Provenance
from actshield.context.taint import TaintState
from actshield.tracing.correlation import generate_id
from actshield.tracing.events import EventType

if TYPE_CHECKING:
    from actshield.client import ActShield


class Context(BaseModel):
    """Context and data lineage container tracked by actshield."""
    
    context_id: str = Field(default_factory=lambda: generate_id("ctx"), description="Unique context ID")
    data: Any = Field(default=None, description="Payload data content or summary")
    source: ContextSource = Field(default=ContextSource.USER, description="Original source")
    source_type: str = Field(default="text", description="MIME type or semantic type")
    source_uri: Optional[str] = Field(default=None, description="URI or locator of context source")
    trust_level: str = Field(default="trusted", description="Trust level assigned at ingestion ('trusted', 'untrusted', 'verified')")
    taint_state: TaintState = Field(default=TaintState.CLEAN, description="Current taint classification ('CLEAN', 'UNTRUSTED', 'TAINTED', 'UNKNOWN')")
    
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
        guard: Optional["ActShield"] = None,
    ) -> "Context":
        """Propagate or transform this context to another agent, recording the lineage hop.
        
        Taint is strictly preserved across agent hops unless explicitly sanitized.
        """
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

    def sanitize(
        self,
        sanitizer_name: str,
        reason: str,
        transformed_data: Any = None,
        new_taint: TaintState = TaintState.CLEAN,
        guard: Optional["ActShield"] = None,
    ) -> "Context":
        """Perform an explicit, auditable sanitization operation on this context artifact."""
        previous_taint = self.taint_state.value
        new_provenance = self.provenance.model_copy(deep=True)

        sanitized_ctx = Context(
            context_id=generate_id("ctx"),
            data=transformed_data if transformed_data is not None else self.data,
            source=self.source,
            source_type=f"sanitized:{self.source_type}",
            source_uri=self.source_uri,
            trust_level="verified",
            taint_state=new_taint,
            originating_event_id=self.originating_event_id,
            originating_agent_id=self.originating_agent_id,
            current_agent_id=self.current_agent_id,
            parent_context_id=self.context_id,
            provenance=new_provenance,
            metadata={
                **self.metadata,
                "sanitized_by": sanitizer_name,
                "sanitization_reason": reason,
            },
        )

        event_id = None
        if guard is not None:
            guard.context_registry[sanitized_ctx.context_id] = sanitized_ctx
            evt = guard.emit_event(
                event_type=EventType.CONTEXT_SANITIZED,
                context_id=sanitized_ctx.context_id,
                agent_id=self.current_agent_id,
                payload={
                    "source_context_id": self.context_id,
                    "resulting_context_id": sanitized_ctx.context_id,
                    "sanitizer_name": sanitizer_name,
                    "reason": reason,
                    "previous_taint": previous_taint,
                    "new_taint": new_taint.value,
                }
            )
            event_id = evt.event_id

        sanitized_ctx.provenance.record_sanitization(
            sanitizer_name=sanitizer_name,
            reason=reason,
            previous_taint=previous_taint,
            new_taint=new_taint.value,
            event_id=event_id,
            details={"source_context_id": self.context_id},
        )

        return sanitized_ctx


