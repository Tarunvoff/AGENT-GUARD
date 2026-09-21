"""End-to-end integration test for full causal chain reconstruction."""

import json
from actshield.agents.identity import AgentTrustLevel
from actshield.client import ActShield
from actshield.context.provenance import ContextSource
from actshield.context.taint import TaintState
from actshield.tools.tool import Resource, SensitivityLevel


def test_e2e_causal_chain_user_planner_researcher_dataagent_tool():
    """Validates complete causal chain:
    User -> Planner -> Researcher -> DataAgent -> Tool -> Resource -> Decision
    and asserts that the final reconstructed causal graph captures every link.
    """
    guard = ActShield()

    # 1. Register Agents
    planner = guard.agent(
        name="planner_agent",
        framework="crewai",
        capabilities=["plan_workflow", "public_search", "data_extraction"],
        trust_level=AgentTrustLevel.HIGH,
    )
    researcher = guard.agent(
        name="researcher_agent",
        framework="langchain",
        capabilities=["public_search", "data_extraction"],
        trust_level=AgentTrustLevel.MEDIUM,
    )
    data_agent = guard.agent(
        name="data_agent",
        framework="custom",
        capabilities=["data_extraction"],
        trust_level=AgentTrustLevel.MEDIUM,
    )

    # 2. Register Protected Tool & Target Resource
    sql_resource = Resource(
        name="quarterly_reports_db",
        resource_type="database",
        uri="postgres://reports.internal/q3_2026",
        sensitivity=SensitivityLevel.MEDIUM,
    )

    @guard.protected_tool(
        name="extract_quarterly_data",
        description="Extract quarterly financial data points",
        sensitivity=SensitivityLevel.MEDIUM,
        required_capabilities=["data_extraction"],
        target_resources=[sql_resource],
    )
    def extract_quarterly_data(company: str, year: int):
        return {
            "company": company,
            "year": year,
            "revenue": "$12.4B",
            "net_income": "$3.1B"
        }

    # 3. Execute End-to-End Task Workflow
    with guard.task(
        intent="Generate comprehensive financial analysis for ACME Corp 2026",
        initiating_user="sarah_ciso@enterprise.com",
        initiating_application="executive_ai_dashboard",
    ) as task:
        
        # User -> Planner
        # Planner receives initial intent and delegates to Researcher
        with planner.delegate(researcher, capabilities=["public_search", "data_extraction"]) as dlg_1:
            
            # Researcher ingests search context
            search_ctx = guard.context(
                data="Public SEC filings locator for ACME Corp",
                source=ContextSource.USER,
                taint_state=TaintState.TRUSTED,
            )

            # Researcher -> DataAgent
            with researcher.delegate(data_agent, capabilities=["data_extraction"]) as dlg_2:
                
                # DataAgent receives propagated context from Researcher
                data_ctx = search_ctx.propagate(
                    to_agent_id=data_agent.agent_id,
                    action="targeted_metric_search",
                    guard=guard,
                )

                # DataAgent invokes protected tool
                result = extract_quarterly_data(company="ACME Corp", year=2026)
                assert result["revenue"] == "$12.4B"

    # 4. Assert Complete Causal Graph Reconstruction
    graph = guard.reconstruct_trace(task.trace_id)
    assert graph.trace_id == task.trace_id

    # Check Nodes
    node_types = {n.node_type for n in graph.nodes}
    assert "USER" in node_types
    assert "TASK" in node_types
    assert "AGENT" in node_types
    assert "CONTEXT" in node_types
    assert "TOOL" in node_types
    assert "RESOURCE" in node_types
    assert "DECISION" in node_types

    # Verify agent node presence
    agent_labels = [n.label for n in graph.nodes if n.node_type == "AGENT"]
    assert any("planner_agent" in l for l in agent_labels)
    assert any("researcher_agent" in l for l in agent_labels)
    assert any("data_agent" in l for l in agent_labels)

    # Verify edges connecting the causal chain
    relations = [e.relation for e in graph.edges]
    assert "INITIATED" in relations
    assert "DELEGATED_TO" in relations
    assert "INGESTED_OR_PROPAGATED" in relations
    assert "INVOKED" in relations
    assert "TARGETS" in relations
    assert "GOVERNED_BY" in relations

    # Check JSON Export
    json_output = guard.export_trace_json(task.trace_id)
    parsed_json = json.loads(json_output)
    assert len(parsed_json["nodes"]) >= 7
    assert len(parsed_json["edges"]) >= 6

    # Check Human-readable tree output
    tree_text = guard.render_causal_tree(task.trace_id)
    assert "sarah_ciso@enterprise.com" in tree_text
    assert "planner_agent" in tree_text
    assert "researcher_agent" in tree_text
    assert "data_agent" in tree_text
    assert "extract_quarterly_data" in tree_text
    assert "quarterly_reports_db" in tree_text
    assert "ALLOW" in tree_text
