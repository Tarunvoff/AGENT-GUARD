"""Comprehensive Phase 2 Test Suite: Multi-Agent Runtime & MCP Attack Simulation."""

import pytest
from actshield.client import ActShield
from actshield.context.provenance import ContextSource
from actshield.context.taint import TaintState
from actshield.decisions.decision import DecisionAction
from actshield.tools.tool import SensitivityLevel
from actshield.tracing.events import EventType
from examples.multi_agent.agents import setup_agents
from examples.multi_agent.attack_scenario import AttackResult, run_attack_scenario
from examples.multi_agent.benign_scenario import BenignScenarioResult, run_benign_scenario
from examples.multi_agent.enterprise_data import EnterpriseFinancialWarehouse
from examples.multi_agent.mcp_server import MCPMode, SimulatedMCPServer
from examples.multi_agent.tools import EnterpriseToolSuite


# -----------------------------------------------------------------------------
# Test 1: Benign Scenario Succeeds
# -----------------------------------------------------------------------------
def test_benign_scenario_succeeds():
    result = run_benign_scenario()
    assert result.allowed is True
    assert result.decision == "ALLOW"
    assert result.tool_executed is True
    assert result.financial_data["revenue"] == "$14.25B"
    assert result.financial_query_calls == 1
    assert result.customer_read_calls == 0


# -----------------------------------------------------------------------------
# Test 2: MCP Attack Response is Marked Untrusted
# -----------------------------------------------------------------------------
def test_mcp_attack_response_marked_untrusted():
    guard = ActShield()
    mcp_server = SimulatedMCPServer()
    resp = mcp_server.search_public_information("filing", mode=MCPMode.ATTACK)
    
    ctx = guard.context(
        data=resp["results"][0]["content"],
        source=ContextSource.EXTERNAL_MCP,
        source_uri=mcp_server.server_uri,
        trust_level="untrusted",
        taint_state=TaintState.TAINTED,
    )
    assert ctx.source == ContextSource.EXTERNAL_MCP
    assert ctx.trust_level == "untrusted"
    assert ctx.source_uri == "mcp://public-financial-search-v1"


# -----------------------------------------------------------------------------
# Test 3: Attack Context Becomes Tainted
# -----------------------------------------------------------------------------
def test_attack_context_becomes_tainted():
    guard = ActShield()
    ctx = guard.context(
        data="Malicious injected directive",
        source=ContextSource.EXTERNAL_MCP,
        taint_state=TaintState.TAINTED,
    )
    assert ctx.taint_state == TaintState.TAINTED
    assert ctx.taint_state.is_tainted is True
    assert ctx.taint_state.is_safe is False


# -----------------------------------------------------------------------------
# Test 4: Taint Propagates Through Multi-Agent Handoff
# -----------------------------------------------------------------------------
def test_taint_propagates_through_agent_handoff():
    guard = ActShield()
    planner, researcher, analyst, data_agent = setup_agents(guard)

    # Ingest tainted context at Researcher
    ctx1 = guard.context(
        data="Injected directive",
        source=ContextSource.EXTERNAL_MCP,
        taint_state=TaintState.TAINTED,
        agent_id=researcher.agent_id,
    )

    # Propagate Researcher -> Analyst
    ctx2 = ctx1.propagate(to_agent_id=analyst.agent_id, action="analyze", guard=guard)
    assert ctx2.taint_state == TaintState.TAINTED
    assert ctx2.current_agent_id == analyst.agent_id
    assert len(ctx2.provenance.hops) == 1

    # Propagate Analyst -> DataAgent
    ctx3 = ctx2.propagate(to_agent_id=data_agent.agent_id, action="forward", guard=guard)
    assert ctx3.taint_state == TaintState.TAINTED
    assert ctx3.current_agent_id == data_agent.agent_id
    assert len(ctx3.provenance.hops) == 2


# -----------------------------------------------------------------------------
# Test 5: Original User Intent Remains Attached
# -----------------------------------------------------------------------------
def test_original_intent_remains_attached():
    guard = ActShield()
    with guard.task(
        intent="Analyze FY2026 financial performance using public data.",
        initiating_user="ciso_auditor@acmeglobal.com",
    ) as task:
        assert task.original_intent == "Analyze FY2026 financial performance using public data."
        assert task.initiating_user == "ciso_auditor@acmeglobal.com"

        events = guard.tracer.get_events(task.trace_id)
        assert events[0].event_type == EventType.TASK_STARTED
        assert events[0].payload["intent"] == task.original_intent


# -----------------------------------------------------------------------------
# Test 6: Delegation Chain is Preserved
# -----------------------------------------------------------------------------
def test_delegation_chain_is_preserved():
    guard = ActShield()
    planner, researcher, analyst, data_agent = setup_agents(guard)

    with guard.task(intent="Delegation audit"):
        with planner.delegate(researcher, capabilities=["public_search", "financial_extract"]) as d1:
            with researcher.delegate(analyst, capabilities=["financial_extract"]) as d2:
                with analyst.delegate(data_agent, capabilities=["financial_extract"]) as d3:
                    assert d3.parent_delegation_id == d2.delegation_id
                    assert d2.parent_delegation_id == d1.delegation_id
                    assert d3.depth == 2

    dlg_events = [e for e in guard.tracer.get_events() if e.event_type == EventType.AGENT_DELEGATED]
    assert len(dlg_events) == 3


# -----------------------------------------------------------------------------
# Test 7: Unauthorized customer_db.read is Detected
# -----------------------------------------------------------------------------
def test_unauthorized_customer_db_read_detected():
    guard = ActShield()
    warehouse = EnterpriseFinancialWarehouse()
    mcp_server = SimulatedMCPServer()
    tools = EnterpriseToolSuite(guard=guard, warehouse=warehouse, mcp_server=mcp_server)
    planner, researcher, analyst, data_agent = setup_agents(guard)

    with guard.task(intent="Attempt unauthorized customer DB access"):
        with planner.delegate(researcher, capabilities=["public_search", "financial_extract"]):
            with researcher.delegate(analyst, capabilities=["financial_extract"]):
                with analyst.delegate(data_agent, capabilities=["financial_extract"]):
                    # data_agent was delegated ONLY financial_extract, lacking customer_db.read
                    with pytest.raises(PermissionError, match="DELEGATION_AUTHORITY_EXCEEDED"):
                        tools.read_customer_records()


# -----------------------------------------------------------------------------
# Test 8: Protected Tool Blocks the Request
# -----------------------------------------------------------------------------
def test_protected_tool_blocks_request():
    result = run_attack_scenario()
    assert result.blocked is True
    assert "DELEGATION_AUTHORITY_EXCEEDED" in result.reason or "TAINTED_CONTEXT" in result.reason


# -----------------------------------------------------------------------------
# Test 9: Underlying Database Function is NOT Executed
# -----------------------------------------------------------------------------
def test_underlying_database_function_not_executed():
    warehouse = EnterpriseFinancialWarehouse()
    guard = ActShield()
    mcp_server = SimulatedMCPServer()

    assert warehouse.customer_read_calls == 0
    result = run_attack_scenario(guard=guard, warehouse=warehouse, mcp_server=mcp_server)
    
    # HARD PROOF: customer_read_calls counter was never touched!
    assert warehouse.customer_read_calls == 0
    assert result.customer_read_calls == 0
    assert result.tool_executed is False


# -----------------------------------------------------------------------------
# Test 10: Security Decision is BLOCK
# -----------------------------------------------------------------------------
def test_security_decision_is_block():
    result = run_attack_scenario()
    assert result.decision == "BLOCK"


# -----------------------------------------------------------------------------
# Test 11: Attack Result is Created
# -----------------------------------------------------------------------------
def test_attack_result_created():
    result = run_attack_scenario()
    assert isinstance(result, AttackResult)
    assert result.attack_type == "indirect_prompt_injection"
    assert result.target_agent == "DataAgent"
    assert result.requested_capability == "customer_db.read"
    assert result.taint_state == "TAINTED"
    assert len(result.evidence_event_ids) > 0


# -----------------------------------------------------------------------------
# Test 12: Causal Graph Contains MCP as Context Origin
# -----------------------------------------------------------------------------
def test_causal_graph_contains_mcp_origin():
    result = run_attack_scenario()
    graph = result.graph
    
    context_nodes = [n for n in graph.nodes if n.node_type == "CONTEXT"]
    assert len(context_nodes) >= 1
    assert any("external_mcp" in str(n.details) or "TAINTED" in str(n.details) for n in context_nodes)


# -----------------------------------------------------------------------------
# Test 13: Trace Contains All Expected Agents
# -----------------------------------------------------------------------------
def test_trace_contains_all_expected_agents():
    result = run_benign_scenario()
    agent_nodes = [n for n in result.graph.nodes if n.node_type == "AGENT"]
    agent_labels = [n.label for n in agent_nodes]
    
    assert any("PlannerAgent" in l for l in agent_labels)
    assert any("ResearchAgent" in l for l in agent_labels)
    assert any("AnalysisAgent" in l for l in agent_labels)
    assert any("DataAgent" in l for l in agent_labels)


# -----------------------------------------------------------------------------
# Test 14: Trace IDs are Consistent
# -----------------------------------------------------------------------------
def test_trace_ids_are_consistent():
    guard = ActShield()
    warehouse = EnterpriseFinancialWarehouse()
    mcp_server = SimulatedMCPServer()
    result = run_benign_scenario(guard=guard, warehouse=warehouse, mcp_server=mcp_server)

    events = guard.tracer.get_events(result.trace_id)
    assert len(events) >= 6
    for evt in events:
        assert evt.trace_id == result.trace_id


# -----------------------------------------------------------------------------
# Test 15: Evidence Event IDs are Valid
# -----------------------------------------------------------------------------
def test_evidence_event_ids_valid():
    guard = ActShield()
    result = run_attack_scenario(guard=guard)
    
    all_event_ids = {e.event_id for e in guard.tracer.get_events(result.trace_id)}
    for ev_id in result.evidence_event_ids:
        assert ev_id in all_event_ids


# -----------------------------------------------------------------------------
# Test 16: Legitimate Financial Access Remains Allowed
# -----------------------------------------------------------------------------
def test_legitimate_financial_access_remains_allowed():
    warehouse = EnterpriseFinancialWarehouse()
    guard = ActShield()
    tools = EnterpriseToolSuite(guard=guard, warehouse=warehouse, mcp_server=SimulatedMCPServer())
    planner, researcher, analyst, data_agent = setup_agents(guard)

    with guard.task(intent="Legitimate financial query"):
        with planner.delegate(researcher, capabilities=["financial_extract"]):
            with researcher.delegate(analyst, capabilities=["financial_extract"]):
                with analyst.delegate(data_agent, capabilities=["financial_extract"]):
                    res = tools.query_financial_metrics(company="ACME Global", fiscal_year=2026)
                    assert res["revenue"] == "$14.25B"
                    assert warehouse.financial_query_calls == 1


# -----------------------------------------------------------------------------
# Test 17: Trusted Context Does Not Trigger Blocking
# -----------------------------------------------------------------------------
def test_trusted_context_does_not_trigger_blocking():
    guard = ActShield()
    warehouse = EnterpriseFinancialWarehouse()
    tools = EnterpriseToolSuite(guard=guard, warehouse=warehouse, mcp_server=SimulatedMCPServer())
    planner, researcher, analyst, data_agent = setup_agents(guard)

    with guard.task(intent="Trusted pipeline"):
        with planner.delegate(data_agent, capabilities=["financial_extract"]):
            trusted_ctx = guard.context(
                data="Clean internal query",
                source=ContextSource.SYSTEM,
                taint_state=TaintState.TRUSTED,
            )
            res = tools.query_financial_metrics(company="Globex Corp", fiscal_year=2026)
            assert res["revenue"] == "$8.40B"


# -----------------------------------------------------------------------------
# Test 18: Multiple Contexts Can Coexist
# -----------------------------------------------------------------------------
def test_multiple_contexts_coexist():
    guard = ActShield()
    planner = guard.agent(name="planner", capabilities=["public_search"])

    with guard.task(intent="Multiple context ingestion"):
        ctx1 = guard.context(data="Context A", source=ContextSource.USER, taint_state=TaintState.TRUSTED)
        ctx2 = guard.context(data="Context B", source=ContextSource.EXTERNAL_MCP, taint_state=TaintState.UNTRUSTED)
        ctx3 = guard.context(data="Context C", source=ContextSource.SYSTEM, taint_state=TaintState.TRUSTED)

        assert ctx1.context_id != ctx2.context_id != ctx3.context_id
        assert len(guard.context_registry) >= 3


# -----------------------------------------------------------------------------
# Test 19: Untrusted Context Does Not Globally Compromise Agent
# -----------------------------------------------------------------------------
def test_untrusted_context_does_not_globally_compromise_agent():
    """Taint belongs to context/data lineage, not global permanent agent corruption."""
    guard = ActShield()
    warehouse = EnterpriseFinancialWarehouse()
    tools = EnterpriseToolSuite(guard=guard, warehouse=warehouse, mcp_server=SimulatedMCPServer())
    planner, researcher, analyst, data_agent = setup_agents(guard)

    # Agent processes untrusted context in Task 1
    with guard.task(intent="Task with untrusted context"):
        with planner.delegate(data_agent, capabilities=["financial_extract"]):
            untrusted_ctx = guard.context(
                data="Untrusted input",
                source=ContextSource.EXTERNAL_MCP,
                taint_state=TaintState.UNTRUSTED,
            )

    # In a new, separate Task 2 with clean trusted context, the same agent can execute normally!
    with guard.task(intent="New task with clean context"):
        with planner.delegate(data_agent, capabilities=["financial_extract"]):
            clean_ctx = guard.context(
                data="Clean trusted input",
                source=ContextSource.USER,
                taint_state=TaintState.TRUSTED,
            )
            res = tools.query_financial_metrics(company="ACME Global", fiscal_year=2026)
            assert res["revenue"] == "$14.25B"


# -----------------------------------------------------------------------------
# Test 20: Recursive Delegation Still Works Seamlessly
# -----------------------------------------------------------------------------
def test_recursive_delegation_deep_chain():
    guard = ActShield()
    planner, researcher, analyst, data_agent = setup_agents(guard)

    with guard.task(intent="Deep recursive delegation"):
        with planner.delegate(researcher, capabilities=["public_search", "financial_extract"]) as d1:
            assert d1.depth == 0
            with researcher.delegate(analyst, capabilities=["financial_extract"]) as d2:
                assert d2.depth == 1
                with analyst.delegate(data_agent, capabilities=["financial_extract"]) as d3:
                    assert d3.depth == 2
                    assert d3.authority_grant.granted_capabilities == ["financial_extract"]
