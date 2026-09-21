"""Benign multi-agent enterprise execution scenario.

Demonstrates:
- Legitimate user intent
- Step-by-step recursive delegation (Planner -> Researcher -> Analyst -> DataAgent)
- Ingestion and propagation of trusted/verified MCP search context
- Authorized execution of query_financial_metrics (ALLOW)
- Proof of execution via execution counter.
"""

from dataclasses import dataclass
from typing import Any, Dict, Optional
from actshield.client import AgentGuard
from actshield.context.provenance import ContextSource
from actshield.context.taint import TaintState
from actshield.tracing.tracer import CausalGraph
from examples.multi_agent.agents import setup_agents
from examples.multi_agent.enterprise_data import EnterpriseFinancialWarehouse
from examples.multi_agent.mcp_server import MCPMode, SimulatedMCPServer
from examples.multi_agent.tools import EnterpriseToolSuite


@dataclass
class BenignScenarioResult:
    trace_id: str
    task_id: str
    decision: str
    allowed: bool
    tool_executed: bool
    financial_data: Dict[str, Any]
    financial_query_calls: int
    customer_read_calls: int
    tree_text: str
    json_trace: str
    graph: CausalGraph


def run_benign_scenario(
    guard: Optional[AgentGuard] = None,
    warehouse: Optional[EnterpriseFinancialWarehouse] = None,
    mcp_server: Optional[SimulatedMCPServer] = None,
) -> BenignScenarioResult:
    """Execute the benign multi-agent workflow."""
    guard = guard or AgentGuard()
    warehouse = warehouse or EnterpriseFinancialWarehouse()
    mcp_server = mcp_server or SimulatedMCPServer()

    tools = EnterpriseToolSuite(guard=guard, warehouse=warehouse, mcp_server=mcp_server)
    planner, researcher, analyst, data_agent = setup_agents(guard)

    financial_result: Dict[str, Any] = {}
    task_id_recorded = ""
    trace_id_recorded = ""

    # User initiates the task
    with guard.task(
        intent="Analyze FY2026 financial performance for ACME Global using publicly available financial information.",
        initiating_user="ciso_auditor@acmeglobal.com",
        initiating_application="enterprise_audit_portal",
    ) as task:
        task_id_recorded = task.task_id
        trace_id_recorded = task.trace_id

        # 1. Planner delegates research to ResearcherAgent
        with planner.delegate(
            researcher,
            capabilities=["public_search", "public_documents", "financial_extract"]
        ) as d1:
            
            # 2. ResearcherAgent queries MCP service in BENIGN mode
            mcp_response = tools.financial_document_search(
                query="ACME Global FY2026 annual financial filing",
                mode=MCPMode.BENIGN,
            )

            # Ingest search output as trusted context artifact
            mcp_ctx = guard.context(
                data=mcp_response["results"][0]["content"],
                source=ContextSource.EXTERNAL_MCP,
                source_uri=mcp_server.server_uri,
                trust_level="verified_public",
                taint_state=TaintState.TRUSTED,
            )

            # 3. Researcher delegates analysis to AnalysisAgent
            with researcher.delegate(
                analyst,
                capabilities=["financial_extract"]
            ) as d2:
                
                # Propagate context from Researcher to Analyst
                analyst_ctx = mcp_ctx.propagate(
                    to_agent_id=analyst.agent_id,
                    action="analyze_filing_extract_metrics",
                    guard=guard,
                )

                # 4. Analyst delegates data query to DataAgent
                with analyst.delegate(
                    data_agent,
                    capabilities=["financial_extract"]
                ) as d3:
                    
                    # Propagate context to DataAgent
                    data_ctx = analyst_ctx.propagate(
                        to_agent_id=data_agent.agent_id,
                        action="execute_metrics_extraction",
                        guard=guard,
                    )

                    # 5. DataAgent invokes protected query_financial_metrics tool
                    financial_result = tools.query_financial_metrics(
                        company="ACME Global",
                        fiscal_year=2026,
                        auth_token="sk-live-internal-key-999"
                    )

    # Reconstruct causal graph & formatting
    graph = guard.reconstruct_trace(trace_id_recorded)
    tree_text = guard.render_causal_tree(trace_id_recorded)
    json_trace = guard.export_trace_json(trace_id_recorded, indent=2)

    return BenignScenarioResult(
        trace_id=trace_id_recorded,
        task_id=task_id_recorded,
        decision="ALLOW",
        allowed=True,
        tool_executed=(warehouse.financial_query_calls == 1),
        financial_data=financial_result,
        financial_query_calls=warehouse.financial_query_calls,
        customer_read_calls=warehouse.customer_read_calls,
        tree_text=tree_text,
        json_trace=json_trace,
        graph=graph,
    )
