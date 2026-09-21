"""Agent runtime instance and orchestration interface."""

from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Union
from datetime import datetime, timezone
import inspect
from agentguard.agents.identity import AgentCapability, AgentIdentity, AgentStatus, AgentTrustLevel
from agentguard.tracing.events import EventType

if TYPE_CHECKING:
    from agentguard.client import AgentGuard
    from agentguard.delegation.delegation import DelegationScope
    from agentguard.tracing.correlation import SpanScope


class Agent:
    """Represents a registered AI Agent within the AgentGuard platform."""

    def __init__(self, identity: AgentIdentity, guard: Optional["AgentGuard"] = None) -> None:
        self.identity = identity
        self.guard = guard
        now_iso = datetime.now(timezone.utc).isoformat()
        if not self.identity.created_at:
            self.identity.created_at = now_iso
        if not self.identity.last_seen:
            self.identity.last_seen = now_iso

    @property
    def agent_id(self) -> str:
        return self.identity.agent_id

    @property
    def name(self) -> str:
        return self.identity.name

    @property
    def framework(self) -> str:
        return self.identity.framework

    @property
    def version(self) -> str:
        return self.identity.version

    @property
    def status(self) -> AgentStatus:
        return self.identity.status

    @property
    def trust_level(self) -> AgentTrustLevel:
        return self.identity.trust_level

    @property
    def capabilities(self) -> List[AgentCapability]:
        return self.identity.capabilities

    @property
    def parent_agent_id(self) -> Optional[str]:
        return self.identity.parent_agent_id

    @property
    def current_task(self) -> Optional[str]:
        return self.identity.current_task

    @property
    def owner_context(self) -> Optional[str]:
        return self.identity.owner_context

    @property
    def created_at(self) -> Optional[str]:
        return self.identity.created_at

    @property
    def last_seen(self) -> Optional[str]:
        return self.identity.last_seen

    @property
    def metadata(self) -> Dict[str, Any]:
        return self.identity.metadata

    def set_status(self, status: Union[str, AgentStatus]) -> None:
        """Update agent operational status."""
        if isinstance(status, str):
            status = AgentStatus(status.lower())
        self.identity.status = status
        self.touch()
        if self.guard:
            self.guard.emit_event(
                event_type=EventType.SECURITY_ALERT,
                agent_id=self.agent_id,
                payload={"action": "agent_status_change", "status": status.value},
            )

    def touch(self) -> None:
        """Update last seen timestamp."""
        self.identity.last_seen = datetime.now(timezone.utc).isoformat()

    def set_task(self, task_name_or_id: Optional[str]) -> None:
        """Set active task."""
        self.identity.current_task = task_name_or_id
        self.touch()

    def has_capability(self, capability_name: str) -> bool:
        """Check if this agent holds the specified capability."""
        return self.identity.has_capability(capability_name)

    def capability_names(self) -> List[str]:
        """Return list of declared capability names."""
        return self.identity.capability_names()

    def delegate(
        self,
        delegate: Optional["Agent"] = None,
        capabilities: Optional[List[Union[str, AgentCapability]]] = None,
        constraints: Optional[Dict[str, Any]] = None,
        to_agent: Optional["Agent"] = None,
    ) -> "DelegationScope":
        """Delegate a subset of authority/capabilities to a target agent within a scoped context."""
        target = delegate or to_agent
        if target is None:
            raise ValueError("Target delegate agent must be provided to delegate().")
        if self.guard is None:
            raise RuntimeError("Agent is not attached to an AgentGuard instance.")
        
        self.touch()
        return self.guard._create_delegation_scope(
            delegator=self,
            delegate=target,
            capabilities=capabilities,
            constraints=constraints,
        )

    def invoke(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """Invoke a synchronous function within this agent's execution context."""
        self.touch()
        if self.guard is None:
            return fn(*args, **kwargs)
        
        with self.guard.span(name=f"agent_invoke:{self.name}", agent_id=self.agent_id):
            self.guard.emit_event(
                event_type=EventType.AGENT_INVOKED,
                agent_id=self.agent_id,
                payload={
                    "agent_name": self.name,
                    "function": getattr(fn, "__name__", str(fn)),
                }
            )
            return fn(*args, **kwargs)

    async def ainvoke(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """Invoke an asynchronous function within this agent's execution context."""
        self.touch()
        if self.guard is None:
            if inspect.iscoroutinefunction(fn):
                return await fn(*args, **kwargs)
            return fn(*args, **kwargs)

        with self.guard.span(name=f"agent_ainvoke:{self.name}", agent_id=self.agent_id):
            self.guard.emit_event(
                event_type=EventType.AGENT_INVOKED,
                agent_id=self.agent_id,
                payload={
                    "agent_name": self.name,
                    "function": getattr(fn, "__name__", str(fn)),
                }
            )
            if inspect.iscoroutinefunction(fn):
                return await fn(*args, **kwargs)
            return fn(*args, **kwargs)

    def __call__(self, fn: Callable[..., Any]) -> Callable[..., Any]:
        """Allow Agent instance to be used directly as a decorator."""
        import functools
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            if self.guard:
                with self.guard.agent_context(self.agent_id):
                    if inspect.iscoroutinefunction(fn):
                        return self.ainvoke(fn, *args, **kwargs)
                    return self.invoke(fn, *args, **kwargs)
            else:
                if inspect.iscoroutinefunction(fn):
                    return fn(*args, **kwargs)
                return fn(*args, **kwargs)
        wrapper.agent = self  # type: ignore
        return wrapper

    def __enter__(self) -> "Agent":
        if self.guard:
            self._scope = self.guard.span(name=f"agent_scope:{self.name}", agent_id=self.agent_id)
            self._scope.__enter__()
        self.touch()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if hasattr(self, "_scope") and self._scope:
            self._scope.__exit__(exc_type, exc_val, exc_tb)

    def __repr__(self) -> str:
        return f"<Agent id='{self.agent_id}' name='{self.name}' status='{self.status.value}' trust='{self.trust_level.value}'>"
