"""Correlation context management for distributed and multi-agent tracing."""

import contextvars
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Optional


def generate_id(prefix: str = "") -> str:
    """Generate a unique hex/uuid based ID with an optional prefix."""
    unique_part = uuid.uuid4().hex[:16]
    if prefix:
        return f"{prefix}_{unique_part}"
    return unique_part


@dataclass(frozen=True)
class CorrelationContext:
    """Immutable correlation context representing current execution coordinates."""
    trace_id: str
    span_id: str
    parent_span_id: Optional[str] = None
    task_id: Optional[str] = None
    agent_id: Optional[str] = None
    parent_agent_id: Optional[str] = None
    delegation_id: Optional[str] = None
    parent_event_id: Optional[str] = None
    context_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def derive_child_span(
        self,
        span_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        task_id: Optional[str] = None,
        delegation_id: Optional[str] = None,
        context_id: Optional[str] = None,
        parent_event_id: Optional[str] = None,
        extra_metadata: Optional[Dict[str, Any]] = None,
    ) -> "CorrelationContext":
        """Derive a child correlation context preserving the trace_id and updating span/agent relationships."""
        new_span_id = span_id or generate_id("spn")
        new_metadata = dict(self.metadata)
        if extra_metadata:
            new_metadata.update(extra_metadata)

        return CorrelationContext(
            trace_id=self.trace_id,
            span_id=new_span_id,
            parent_span_id=self.span_id,
            task_id=task_id if task_id is not None else self.task_id,
            agent_id=agent_id if agent_id is not None else self.agent_id,
            parent_agent_id=self.agent_id if (agent_id is not None and agent_id != self.agent_id) else self.parent_agent_id,
            delegation_id=delegation_id if delegation_id is not None else self.delegation_id,
            parent_event_id=parent_event_id if parent_event_id is not None else self.parent_event_id,
            context_id=context_id if context_id is not None else self.context_id,
            metadata=new_metadata,
        )


_current_correlation_ctx: contextvars.ContextVar[Optional[CorrelationContext]] = contextvars.ContextVar(
    "agentguard_correlation_ctx", default=None
)


def get_current_context() -> Optional[CorrelationContext]:
    """Retrieve the active correlation context for the current async/sync task."""
    return _current_correlation_ctx.get()


def set_current_context(ctx: Optional[CorrelationContext]) -> contextvars.Token:
    """Set the active correlation context and return the token to reset later."""
    return _current_correlation_ctx.set(ctx)


def reset_current_context(token: contextvars.Token) -> None:
    """Reset the correlation context using a saved token."""
    _current_correlation_ctx.reset(token)


def get_current_trace_id() -> Optional[str]:
    """Get the active trace ID if in an active trace scope."""
    ctx = get_current_context()
    return ctx.trace_id if ctx else None


def get_current_span_id() -> Optional[str]:
    """Get the active span ID if in an active span scope."""
    ctx = get_current_context()
    return ctx.span_id if ctx else None


def get_current_agent_id() -> Optional[str]:
    """Get the active agent ID."""
    ctx = get_current_context()
    return ctx.agent_id if ctx else None


def get_current_task_id() -> Optional[str]:
    """Get the active task ID."""
    ctx = get_current_context()
    return ctx.task_id if ctx else None


def get_current_delegation_id() -> Optional[str]:
    """Get the active delegation ID."""
    ctx = get_current_context()
    return ctx.delegation_id if ctx else None


class SpanScope:
    """Context manager for establishing or nesting a correlation span."""

    def __init__(
        self,
        name: str = "span",
        trace_id: Optional[str] = None,
        span_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        task_id: Optional[str] = None,
        delegation_id: Optional[str] = None,
        context_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.name = name
        self._requested_trace_id = trace_id
        self._requested_span_id = span_id
        self._agent_id = agent_id
        self._task_id = task_id
        self._delegation_id = delegation_id
        self._context_id = context_id
        self._metadata = metadata or {}
        self._token: Optional[contextvars.Token] = None
        self.context: Optional[CorrelationContext] = None
        self.start_time: float = 0.0

    def __enter__(self) -> CorrelationContext:
        self.start_time = time.time()
        parent_ctx = get_current_context()
        if parent_ctx is not None:
            self.context = parent_ctx.derive_child_span(
                span_id=self._requested_span_id,
                agent_id=self._agent_id,
                task_id=self._task_id,
                delegation_id=self._delegation_id,
                context_id=self._context_id,
                extra_metadata=self._metadata,
            )
        else:
            trace_id = self._requested_trace_id or generate_id("trc")
            span_id = self._requested_span_id or generate_id("spn")
            self.context = CorrelationContext(
                trace_id=trace_id,
                span_id=span_id,
                task_id=self._task_id,
                agent_id=self._agent_id,
                delegation_id=self._delegation_id,
                context_id=self._context_id,
                metadata=self._metadata,
            )
        self._token = set_current_context(self.context)
        return self.context

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if self._token is not None:
            reset_current_context(self._token)

    async def __aenter__(self) -> CorrelationContext:
        return self.__enter__()

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.__exit__(exc_type, exc_val, exc_tb)
