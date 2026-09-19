"""Agent runtime instance and orchestration interface."""

from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Union
import inspect
from agentguard.agents.identity import AgentCapability, AgentIdentity, AgentTrustLevel
from agentguard.tracing.events import EventType

if TYPE_CHECKING:
    from agentguard.client import AgentGuard
    from agentguard.delegation.delegation import DelegationScope


class Agent:
    """Represents a registered AI Agent within the AgentGuard platform."""

    def __init__(self, identity: AgentIdentity, guard: Optional["AgentGuard"] = None) -> None:
        self.identity = identity
        self.guard = guard

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
    def capabilities(self) -> List[AgentCapability]:
        return self.identity.capabilities

    @property
    def trust_level(self) -> AgentTrustLevel:
        return self.identity.trust_level

    @property
    def metadata(self) -> Dict[str, Any]:
        return self.identity.metadata

    def has_capability(self, capability_name: str) -> bool:
        """Check if this agent holds the specified capability."""
        return self.identity.has_capability(capability_name)

    def capability_names(self) -> List[str]:
        """Return list of declared capability names."""
        return self.identity.capability_names()

    def delegate(
        self,
        delegate: "Agent",
        capabilities: Optional[List[Union[str, AgentCapability]]] = None,
        constraints: Optional[Dict[str, Any]] = None,
    ) -> "DelegationScope":
        """Delegate a subset of authority/capabilities to a target agent within a scoped context.
        
        Usage:
            with planner.delegate(researcher, capabilities=["public_search"]):
                ...
        """
        if self.guard is None:
            raise RuntimeError("Agent is not attached to an AgentGuard instance.")
        
        return self.guard._create_delegation_scope(
            delegator=self,
            delegate=delegate,
            capabilities=capabilities,
            constraints=constraints,
        )

    def invoke(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """Invoke a synchronous function within this agent's execution context."""
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

    def __repr__(self) -> str:
        return f"<Agent id='{self.agent_id}' name='{self.name}' trust='{self.trust_level.value}'>"
