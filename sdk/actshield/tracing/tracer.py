"""Causal trace manager, event repository, and causal graph reconstructor."""

import json
from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, List, Optional
from pydantic import BaseModel, Field

from actshield.tracing.events import EventType, SecurityEvent

if TYPE_CHECKING:
    from actshield.client import ActShield


class CausalNode(BaseModel):
    """A discrete entity in the multi-agent causal graph."""
    node_id: str
    node_type: str  # USER, TASK, AGENT, DELEGATION, CONTEXT, TOOL, RESOURCE, DECISION, EVENT
    label: str
    details: Dict[str, Any] = Field(default_factory=dict)
    timestamp: Optional[str] = None


class CausalEdge(BaseModel):
    """A directed causal dependency or data-flow relationship."""
    source_id: str
    target_id: str
    relation: str  # INITIATED, DELEGATED_TO, INGESTED_OR_PROPAGATED, INVOKED, TARGETS, GOVERNED_BY
    metadata: Dict[str, Any] = Field(default_factory=dict)


class CausalGraph(BaseModel):
    """Reconstructed end-to-end causal chain and provenance graph for a trace."""
    trace_id: str
    nodes: List[CausalNode] = Field(default_factory=list)
    edges: List[CausalEdge] = Field(default_factory=list)

    def to_json(self, indent: int = 2) -> str:
        """Export graph as machine-readable JSON."""
        return self.model_dump_json(indent=indent)

    def get_influencing_contexts(self, tool_name_or_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Query and return all context nodes that causally influenced tool requests in this trace."""
        context_nodes = [n for n in self.nodes if n.node_type == "CONTEXT"]
        results: List[Dict[str, Any]] = []
        for cn in context_nodes:
            cid = cn.details.get("context_id") or (cn.node_id[4:] if cn.node_id.startswith("ctx_") else cn.node_id)
            results.append({
                "context_id": cid,
                "label": cn.label,
                "details": cn.details,
                "timestamp": cn.timestamp,
            })
        return results

    def get_propagation_chain(self) -> List[str]:
        """Extract chronological agent propagation chain from graph nodes."""
        agent_nodes = [n for n in self.nodes if n.node_type == "AGENT"]
        seen = set()
        chain = []
        for n in agent_nodes:
            # Extract clean agent name from label e.g. "Agent: PlannerAgent"
            name = n.label.split("(")[0].replace("Agent:", "").strip()
            if name not in seen:
                seen.add(name)
                chain.append(name)
        return chain

    def render_tree(self) -> str:
        """Render a formatted human-readable causal execution tree using ASCII characters for universal terminal support."""
        lines: List[str] = [
            f"=== ActShield CAUSAL TRACE: {self.trace_id} ===",
            ""
        ]
        
        node_map = {n.node_id: n for n in self.nodes}
        # Find root nodes (nodes with no incoming edges)
        targets = {e.target_id for e in self.edges}
        roots = [n for n in self.nodes if n.node_id not in targets]

        if not roots and self.nodes:
            roots = [self.nodes[0]]

        # Build adjacency list: source -> list of (target_id, relation)
        adj: Dict[str, List[tuple[str, str]]] = {}
        for e in self.edges:
            adj.setdefault(e.source_id, []).append((e.target_id, e.relation))

        visited = set()

        def _dfs(current_id: str, prefix: str = "", is_last: bool = True) -> None:
            if current_id in visited:
                return
            visited.add(current_id)
            node = node_map.get(current_id)
            if not node:
                return

            connector = "\\-- " if is_last else "+-- "
            type_tag = f"[{node.node_type}]"
            lines.append(f"{prefix}{connector}{type_tag} {node.label}")

            child_prefix = prefix + ("    " if is_last else "|   ")
            children = adj.get(current_id, [])
            for i, (child_id, rel) in enumerate(children):
                child_is_last = (i == len(children) - 1)
                _dfs(child_id, child_prefix, child_is_last)

        for i, root in enumerate(roots):
            _dfs(root.node_id, "", is_last=(i == len(roots) - 1))

        # Add unvisited nodes if any disconnected events exist
        unvisited = [n for n in self.nodes if n.node_id not in visited]
        if unvisited:
            lines.append("")
            lines.append("--- Additional Correlated Events ---")
            for node in unvisited:
                lines.append(f"  * [{node.node_type}] {node.label}")

        return "\n".join(lines)


class TraceManager:
    """Thread-safe and async-safe in-memory security event repository."""

    def __init__(self) -> None:
        self._events: List[SecurityEvent] = []

    def record_event(self, event: SecurityEvent) -> None:
        """Store an emitted security event."""
        self._events.append(event)

    def get_events(self, trace_id: Optional[str] = None) -> List[SecurityEvent]:
        """Query events matching optional trace ID."""
        if trace_id is None:
            return list(self._events)
        return [e for e in self._events if e.trace_id == trace_id]

    def get_propagation_chain_for_context(self, context_id: str) -> List[str]:
        """Return the sequence of agent IDs that propagated a specific context."""
        events = [e for e in self._events if e.context_id == context_id or e.payload.get("parent_context_id") == context_id]
        agents = []
        for e in events:
            if e.agent_id and e.agent_id not in agents:
                agents.append(e.agent_id)
        return agents

    def reconstruct_causal_graph(self, trace_id: str, guard: Optional["ActShield"] = None) -> CausalGraph:
        """Reconstruct the complete causal chain from stored events and registries."""
        events = self.get_events(trace_id)
        nodes: List[CausalNode] = []
        edges: List[CausalEdge] = []
        node_ids = set()

        def add_node(n: CausalNode) -> None:
            if n.node_id not in node_ids:
                node_ids.add(n.node_id)
                nodes.append(n)

        def add_edge(src: str, dst: str, relation: str) -> None:
            edges.append(CausalEdge(source_id=src, target_id=dst, relation=relation))

        # Process Task Started
        user_node_id = None
        task_node_id = None
        last_entity_id = None

        for evt in events:
            evt_time_str = evt.timestamp.isoformat() if hasattr(evt.timestamp, "isoformat") else str(evt.timestamp)
            
            if evt.event_type == EventType.TASK_STARTED:
                user_name = evt.payload.get("initiating_user") or "User/Client"
                user_node_id = f"user_{evt.trace_id}"
                add_node(CausalNode(
                    node_id=user_node_id,
                    node_type="USER",
                    label=f"User: {user_name}",
                    details={"initiating_user": user_name},
                    timestamp=evt_time_str,
                ))
                
                task_id = evt.task_id or f"task_{evt.trace_id}"
                task_node_id = task_id
                add_node(CausalNode(
                    node_id=task_id,
                    node_type="TASK",
                    label=f"Task: {evt.payload.get('intent', 'Task')}",
                    details=evt.payload,
                    timestamp=evt_time_str,
                ))
                add_edge(user_node_id, task_id, "INITIATED")
                last_entity_id = task_id

            elif evt.event_type == EventType.AGENT_DELEGATED:
                delegator_id = evt.payload.get("delegator_id")
                delegator_name = evt.payload.get("delegator_name", delegator_id)
                delegate_id = evt.payload.get("delegate_id")
                delegate_name = evt.payload.get("delegate_name", delegate_id)
                caps = evt.payload.get("granted_capabilities", [])

                delegator_node_id = f"agent_{delegator_id}"
                delegate_node_id = f"agent_{delegate_id}"

                add_node(CausalNode(
                    node_id=delegator_node_id,
                    node_type="AGENT",
                    label=f"Agent: {delegator_name}",
                    details={"agent_id": delegator_id},
                    timestamp=evt_time_str,
                ))

                add_node(CausalNode(
                    node_id=delegate_node_id,
                    node_type="AGENT",
                    label=f"Agent: {delegate_name} (Granted: {caps})",
                    details={"agent_id": delegate_id, "granted_capabilities": caps},
                    timestamp=evt_time_str,
                ))

                # Link from task or delegator
                if last_entity_id and last_entity_id == task_node_id:
                    add_edge(task_node_id, delegator_node_id, "ENGAGED")

                add_edge(delegator_node_id, delegate_node_id, "DELEGATED_TO")
                last_entity_id = delegate_node_id

            elif evt.event_type in (EventType.CONTEXT_RECEIVED, EventType.CONTEXT_PROPAGATED, EventType.CONTEXT_SANITIZED):
                ctx_id = evt.context_id or f"ctx_{len(nodes)}"
                taint = evt.payload.get("taint_state", evt.payload.get("new_taint", "CLEAN"))
                src = evt.payload.get("source", "external")
                action = evt.payload.get("action", evt.event_type.value)
                ctx_node_id = f"ctx_{ctx_id}"
                node_details = dict(evt.payload)
                node_details["context_id"] = ctx_id
                
                add_node(CausalNode(
                    node_id=ctx_node_id,
                    node_type="CONTEXT",
                    label=f"Context: {src} [Taint: {taint}]",
                    details=node_details,
                    timestamp=evt_time_str,
                ))

                acting_agent_id = f"agent_{evt.agent_id}" if evt.agent_id else last_entity_id
                if acting_agent_id:
                    add_edge(acting_agent_id, ctx_node_id, "INGESTED_OR_PROPAGATED")
                    last_entity_id = ctx_node_id

            elif evt.event_type == EventType.TOOL_REQUESTED:
                tool_name = evt.payload.get("tool_name", "Tool")
                tool_id = evt.payload.get("tool_id", "tool")
                sens = evt.payload.get("sensitivity", "MEDIUM")
                tool_node_id = f"tool_req_{tool_id}_{evt.event_id}"
                
                add_node(CausalNode(
                    node_id=tool_node_id,
                    node_type="TOOL",
                    label=f"Tool: {tool_name} (Sensitivity: {sens})",
                    details=evt.payload,
                    timestamp=evt_time_str,
                ))

                agent_id = f"agent_{evt.agent_id}" if evt.agent_id else last_entity_id
                if agent_id:
                    add_edge(agent_id, tool_node_id, "INVOKED")
                last_entity_id = tool_node_id

            elif evt.event_type == EventType.RESOURCE_ACCESS_REQUESTED:
                rsc_name = evt.payload.get("resource_name", "Resource")
                rsc_id = evt.payload.get("resource_id", "rsc")
                sens = evt.payload.get("sensitivity", "MEDIUM")
                rsc_node_id = f"rsc_{rsc_id}_{evt.event_id}"

                add_node(CausalNode(
                    node_id=rsc_node_id,
                    node_type="RESOURCE",
                    label=f"Resource: {rsc_name} [{sens}]",
                    details=evt.payload,
                    timestamp=evt_time_str,
                ))

                if last_entity_id:
                    add_edge(last_entity_id, rsc_node_id, "TARGETS")
                last_entity_id = rsc_node_id

            elif evt.event_type == EventType.SECURITY_DECISION:
                action = evt.payload.get("action", "DECISION")
                reason = evt.payload.get("reason_code", "")
                score = evt.payload.get("risk_score", 0.0)
                dec_node_id = f"dec_{evt.payload.get('decision_id', evt.event_id)}"

                add_node(CausalNode(
                    node_id=dec_node_id,
                    node_type="DECISION",
                    label=f"Decision: {action} (Reason: {reason}, Risk: {score})",
                    details=evt.payload,
                    timestamp=evt_time_str,
                ))

                if last_entity_id:
                    add_edge(last_entity_id, dec_node_id, "GOVERNED_BY")
                last_entity_id = dec_node_id

        return CausalGraph(trace_id=trace_id, nodes=nodes, edges=edges)


