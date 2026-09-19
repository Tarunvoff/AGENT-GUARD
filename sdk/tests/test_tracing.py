"""Tests for distributed tracing, event correlation, and causal graph reconstruction."""

import json
from agentguard.client import AgentGuard
from agentguard.context.provenance import ContextSource
from agentguard.context.taint import TaintState
from agentguard.tools.tool import SensitivityLevel


def test_event_correlation_coordinates():
    guard = AgentGuard()
    planner = guard.agent(name="planner", capabilities=["search"])
    researcher = guard.agent(name="researcher", capabilities=["search"])

    with guard.task(intent="Correlation check", initiating_user="tester") as task:
        with planner.delegate(researcher, capabilities=["search"]) as dlg:
            ctx = guard.context(
                data="research findings",
                source=ContextSource.AGENT_GENERATED,
                taint_state=TaintState.TRUSTED,
            )

    events = guard.tracer.get_events(task.trace_id)
    assert len(events) >= 3

    for evt in events:
        assert evt.trace_id == task.trace_id
        assert evt.span_id is not None
        assert evt.event_id.startswith("evt_")

    # Find delegation event
    dlg_events = [e for e in events if e.event_type.value == "agent.delegated"]
    assert len(dlg_events) == 1
    assert dlg_events[0].delegation_id == dlg.delegation_id
    assert dlg_events[0].agent_id == researcher.agent_id
    assert dlg_events[0].parent_agent_id == planner.agent_id


def test_causal_graph_reconstruction_and_render():
    guard = AgentGuard()
    planner = guard.agent(name="planner", capabilities=["search"])
    researcher = guard.agent(name="researcher", capabilities=["search"])

    @guard.protected_tool(name="search_web", required_capabilities=["search"], sensitivity=SensitivityLevel.LOW)
    def search_web(query: str):
        return [{"title": "Agent Security", "url": "https://example.com"}]

    with guard.task(intent="Market Analysis", initiating_user="alice") as task:
        with planner.delegate(researcher, capabilities=["search"]):
            ctx = guard.context(
                data="Search parameters",
                source=ContextSource.USER,
                taint_state=TaintState.TRUSTED,
            )
            search_web(query="AgentGuard architecture")

    # Reconstruct causal graph
    graph = guard.reconstruct_trace(task.trace_id)
    assert graph.trace_id == task.trace_id
    assert len(graph.nodes) >= 5
    assert len(graph.edges) >= 4

    # Check JSON serialization
    json_str = guard.export_trace_json(task.trace_id)
    parsed = json.loads(json_str)
    assert parsed["trace_id"] == task.trace_id
    assert "nodes" in parsed
    assert "edges" in parsed

    # Check ASCII tree rendering
    tree_str = guard.render_causal_tree(task.trace_id)
    assert "AGENTGUARD CAUSAL TRACE" in tree_str
    assert "[USER] User: alice" in tree_str
    assert "[TASK] Task: Market Analysis" in tree_str
    assert "[AGENT] Agent: researcher" in tree_str
    assert "[TOOL] Tool: search_web" in tree_str
    assert "[DECISION]" in tree_str
