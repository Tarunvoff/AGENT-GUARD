"""AgentGuard central client and security runtime orchestrator."""

from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Union

from agentguard.agents.agent import Agent
from agentguard.agents.identity import AgentCapability, AgentIdentity, AgentTrustLevel
from agentguard.config import AgentGuardConfig
from agentguard.context.context import Context
from agentguard.context.provenance import ContextSource, Provenance
from agentguard.context.taint import TaintState
from agentguard.decisions.decision import SecurityDecision
from agentguard.delegation.delegation import Delegation, DelegationScope
from agentguard.integrations.ai_secura import (
    LocalAISecuraAdapter,
    SecurityReasoner,
)
from agentguard.integrations.apiris import (
    APIIntelligence,
    LocalAPIRISAdapter,
)
from agentguard.approval.approval import ApprovalManager
from agentguard.gateway.http import HTTPGateway
from agentguard.gateway.mcp import MCPGateway
from agentguard.persistence.storage import SQLiteStorage, StorageBackend
from agentguard.policy.evaluator import PolicyEvaluator
from agentguard.policy.intent import IntentAnalyzer
from agentguard.tasks.task import Task, TaskContext
from agentguard.tools.interceptor import protected_tool as _protected_tool_decorator
from agentguard.tools.tool import Resource, SensitivityLevel, ToolDefinition, ToolRequest
from agentguard.tracing.correlation import (
    CorrelationContext,
    SpanScope,
    generate_id,
    get_current_agent_id,
    get_current_context,
    get_current_delegation_id,
    get_current_span_id,
    get_current_task_id,
    get_current_trace_id,
)
from agentguard.tracing.events import EventType, SecurityEvent
from agentguard.tracing.tracer import CausalGraph, TraceManager


class AgentGuard:
    """The central AgentGuard SDK client.
    
    Provides causal security tracking, authority delegation governance, context taint propagation,
    tool interception, and deterministic policy enforcement for multi-agent AI systems.
    """

    def __init__(
        self,
        config: Optional[AgentGuardConfig] = None,
        ai_secura: Optional[SecurityReasoner] = None,
        apiris: Optional[APIIntelligence] = None,
        intent_analyzer: Optional[IntentAnalyzer] = None,
        storage: Optional[StorageBackend] = None,
    ) -> None:
        self.config = config or AgentGuardConfig()
        self.tracer = TraceManager()
        self.storage: StorageBackend = storage or SQLiteStorage(":memory:")
        self.approvals = ApprovalManager(self)
        self.policy_evaluator = PolicyEvaluator(self)
        if intent_analyzer:
            self.policy_evaluator.intent_analyzer = intent_analyzer
        
        # Adapters (Dependency Inversion)
        self.ai_secura_adapter: SecurityReasoner = ai_secura or LocalAISecuraAdapter()
        self.apiris_adapter: APIIntelligence = apiris or LocalAPIRISAdapter()

        # In-memory registries
        self.agent_registry: Dict[str, Agent] = {}
        self.tool_registry: Dict[str, ToolDefinition] = {}
        self.delegation_registry: Dict[str, Delegation] = {}
        self.context_registry: Dict[str, Context] = {}

    @property
    def policy(self) -> PolicyEvaluator:
        """Alias for policy_evaluator."""
        return self.policy_evaluator

    def mcp_gateway(
        self,
        server_name: str = "upstream-mcp-server",
        server_uri: str = "mcp://gateway.internal/v1",
    ) -> MCPGateway:
        """Create a Model Context Protocol (MCP) live security gateway."""
        return MCPGateway(guard=self, server_name=server_name, server_uri=server_uri)

    def http_gateway(
        self,
        mock_transport: Optional[Callable[[str, str, Dict[str, Any], Any], Dict[str, Any]]] = None,
    ) -> HTTPGateway:
        """Create an HTTP API live security gateway."""
        return HTTPGateway(guard=self, mock_transport=mock_transport)


    def agent(

        self,
        name: str,
        framework: str = "custom",
        version: str = "1.0.0",
        capabilities: Optional[List[Union[str, AgentCapability, Dict[str, Any]]]] = None,
        trust_level: Union[str, AgentTrustLevel] = AgentTrustLevel.MEDIUM,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Agent:
        """Register and return an Agent instance."""
        if isinstance(trust_level, str):
            trust_level = AgentTrustLevel(trust_level.lower())

        identity = AgentIdentity(
            agent_id=generate_id("agt"),
            name=name,
            framework=framework,
            version=version,
            capabilities=capabilities or [],  # type: ignore
            trust_level=trust_level,
            metadata=metadata or {},
        )
        agent_instance = Agent(identity=identity, guard=self)
        self.agent_registry[agent_instance.agent_id] = agent_instance

        # Emit agent.created event
        self.emit_event(
            event_type=EventType.AGENT_CREATED,
            agent_id=agent_instance.agent_id,
            payload={
                "name": agent_instance.name,
                "framework": agent_instance.framework,
                "version": agent_instance.version,
                "capabilities": agent_instance.capability_names(),
                "trust_level": agent_instance.trust_level.value,
            },
            metadata=metadata,
        )

        return agent_instance

    def task(
        self,
        intent: str,
        initiating_user: Optional[str] = None,
        initiating_application: Optional[str] = None,
        task_id: Optional[str] = None,
        trace_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> TaskContext:
        """Create a scoped TaskContext for tracking user intent and correlation lifecycles."""
        return TaskContext(
            guard=self,
            intent=intent,
            initiating_user=initiating_user,
            initiating_application=initiating_application,
            task_id=task_id,
            trace_id=trace_id,
            metadata=metadata,
        )

    def context(
        self,
        data: Any = None,
        source: Union[str, ContextSource] = ContextSource.USER,
        source_type: str = "text",
        source_uri: Optional[str] = None,
        trust_level: str = "trusted",
        taint_state: Union[str, TaintState] = TaintState.CLEAN,
        agent_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Context:
        """Create and track a new Context artifact with provenance and taint classification."""
        if isinstance(source, str):
            source = ContextSource(source.lower())
        if isinstance(taint_state, str):
            taint_state = TaintState(taint_state.upper())

        current_ctx = get_current_context()
        acting_agent = agent_id or (current_ctx.agent_id if current_ctx else None)

        meta = dict(metadata or {})
        if current_ctx:
            meta["trace_id"] = current_ctx.trace_id
            meta["span_id"] = current_ctx.span_id

        prov = Provenance(
            source=source,
            source_uri=source_uri,
            trust_level=trust_level,
            originating_agent_id=acting_agent,
            originating_timestamp=datetime.now(timezone.utc),
        )

        ctx_obj = Context(
            context_id=generate_id("ctx"),
            data=data,
            source=source,
            source_type=source_type,
            source_uri=source_uri,
            trust_level=trust_level,
            taint_state=taint_state,
            originating_agent_id=acting_agent,
            current_agent_id=acting_agent,
            provenance=prov,
            metadata=meta,
        )

        self.context_registry[ctx_obj.context_id] = ctx_obj

        # Emit event
        evt_type = EventType.CONTEXT_RECEIVED if source in (ContextSource.USER, ContextSource.EXTERNAL_MCP, ContextSource.EXTERNAL_API) else EventType.CONTEXT_GENERATED
        evt = self.emit_event(
            event_type=evt_type,
            context_id=ctx_obj.context_id,
            agent_id=acting_agent,
            payload={
                "source": ctx_obj.source.value,
                "source_uri": source_uri,
                "trust_level": ctx_obj.trust_level,
                "taint_state": ctx_obj.taint_state.value,
            }
        )
        ctx_obj.originating_event_id = evt.event_id
        prov.originating_event_id = evt.event_id

        return ctx_obj

    def sanitize_context(
        self,
        source_context: Context,
        sanitizer_name: str,
        reason: str,
        transformed_data: Any = None,
        new_taint: TaintState = TaintState.CLEAN,
    ) -> Context:
        """Perform an explicit, auditable sanitization operation on an existing context object."""
        return source_context.sanitize(
            sanitizer_name=sanitizer_name,
            reason=reason,
            transformed_data=transformed_data,
            new_taint=new_taint,
            guard=self,
        )

    def register_tool(self, tool_def: ToolDefinition) -> ToolDefinition:
        """Register a tool definition with the SDK."""
        self.tool_registry[tool_def.tool_id] = tool_def
        self.tool_registry[tool_def.name] = tool_def
        return tool_def

    def protected_tool(
        self,
        name: Optional[str] = None,
        description: str = "",
        sensitivity: SensitivityLevel = SensitivityLevel.MEDIUM,
        required_capabilities: Optional[List[str]] = None,
        classification: str = "internal",
        target_resources: Optional[List[Resource]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Decorator to wrap tool functions with deterministic security enforcement."""
        return _protected_tool_decorator(
            guard=self,
            name=name,
            description=description,
            sensitivity=sensitivity,
            required_capabilities=required_capabilities,
            classification=classification,
            target_resources=target_resources,
            metadata=metadata,
        )

    def span(
        self,
        name: str = "span",
        agent_id: Optional[str] = None,
        task_id: Optional[str] = None,
        delegation_id: Optional[str] = None,
        context_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SpanScope:
        """Create a child span scope in the active trace."""
        return SpanScope(
            name=name,
            agent_id=agent_id,
            task_id=task_id,
            delegation_id=delegation_id,
            context_id=context_id,
            metadata=metadata,
        )

    def emit_event(
        self,
        event_type: EventType,
        trace_id: Optional[str] = None,
        span_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        parent_agent_id: Optional[str] = None,
        task_id: Optional[str] = None,
        delegation_id: Optional[str] = None,
        context_id: Optional[str] = None,
        payload: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SecurityEvent:
        """Emit and store a strongly-typed SecurityEvent in the tracer."""
        current_ctx = get_current_context()

        eff_trace_id = trace_id or (current_ctx.trace_id if current_ctx else generate_id("trc"))
        eff_span_id = span_id or (current_ctx.span_id if current_ctx else generate_id("spn"))
        eff_agent_id = agent_id or (current_ctx.agent_id if current_ctx else None)
        eff_parent_agent_id = parent_agent_id or (current_ctx.parent_agent_id if current_ctx else None)
        eff_task_id = task_id or (current_ctx.task_id if current_ctx else None)
        eff_delegation_id = delegation_id or (current_ctx.delegation_id if current_ctx else None)
        eff_context_id = context_id or (current_ctx.context_id if current_ctx else None)
        eff_parent_event_id = current_ctx.parent_event_id if current_ctx else None

        safe_payload = self.config.sanitize(payload or {})
        safe_metadata = self.config.sanitize(metadata or {})

        event = SecurityEvent(
            event_id=generate_id("evt"),
            event_type=event_type,
            timestamp=datetime.now(timezone.utc),
            trace_id=eff_trace_id,
            span_id=eff_span_id,
            parent_event_id=eff_parent_event_id,
            agent_id=eff_agent_id,
            parent_agent_id=eff_parent_agent_id,
            task_id=eff_task_id,
            delegation_id=eff_delegation_id,
            context_id=eff_context_id,
            payload=safe_payload,
            metadata=safe_metadata,
        )

        self.tracer.record_event(event)
        try:
            self.storage.save_event(event)
        except Exception:
            pass
        return event

    def evaluate_tool_invocation(self, tool_def: ToolDefinition, request: ToolRequest) -> SecurityDecision:
        """Evaluate security rules and signals before allowing tool execution."""
        current_ctx = get_current_context()
        active_contexts: List[Context] = []
        seen_cids = set()

        # 1. Contexts explicitly requested
        for cid in request.context_ids:
            if cid in self.context_registry and cid not in seen_cids:
                active_contexts.append(self.context_registry[cid])
                seen_cids.add(cid)

        # 2. Context active in correlation context
        if current_ctx and current_ctx.context_id and current_ctx.context_id in self.context_registry:
            if current_ctx.context_id not in seen_cids:
                active_contexts.append(self.context_registry[current_ctx.context_id])
                seen_cids.add(current_ctx.context_id)

        # 3. Contexts generated in THIS active trace
        trace_id = current_ctx.trace_id if current_ctx else None

        if trace_id:
            for ctx_id, ctx in self.context_registry.items():
                if ctx_id not in seen_cids and ctx.metadata.get("trace_id") == trace_id:
                    active_contexts.append(ctx)
                    seen_cids.add(ctx_id)

        # Filter out ancestor contexts that have been superseded by a sanitized context in the active trace
        sanitized_parent_ids = {
            ctx.parent_context_id
            for ctx in active_contexts
            if ctx.parent_context_id and ctx.metadata.get("sanitized_by") and ctx.taint_state.is_safe
        }
        effective_contexts = [
            c for c in active_contexts
            if c.context_id not in sanitized_parent_ids
        ]

        decision = self.policy_evaluator.evaluate(
            tool_def=tool_def,
            request=request,
            ctx=current_ctx,
            active_contexts=effective_contexts,
        )

        try:
            self.storage.save_decision(decision, trace_id=trace_id)
        except Exception:
            pass

        return decision



    def _create_delegation_scope(
        self,
        delegator: Agent,
        delegate: Agent,
        capabilities: Optional[List[Union[str, AgentCapability]]] = None,
        constraints: Optional[Dict[str, Any]] = None,
    ) -> DelegationScope:
        """Internal helper invoked by Agent.delegate(...)."""
        return DelegationScope(
            guard=self,
            delegator=delegator,
            delegate=delegate,
            capabilities=capabilities,
            constraints=constraints,
        )

    def reconstruct_trace(self, trace_id: str) -> CausalGraph:
        """Reconstruct the complete causal provenance and execution graph for a trace."""
        return self.tracer.reconstruct_causal_graph(trace_id, guard=self)

    def export_trace_json(self, trace_id: str, indent: int = 2) -> str:
        """Export trace causal graph as formatted JSON."""
        return self.reconstruct_trace(trace_id).to_json(indent=indent)

    def render_causal_tree(self, trace_id: str) -> str:
        """Render trace causal graph as an ASCII tree string."""
        return self.reconstruct_trace(trace_id).render_tree()

    def print_causal_tree(self, trace_id: str) -> None:
        """Print the rendered causal tree directly to standard output."""
        print(self.render_causal_tree(trace_id))
