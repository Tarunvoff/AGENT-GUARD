"""Legitimate authorized sensitive customer access scenario.

Demonstrates:
- Authorized customer audit workflow where customer_db.read is explicitly requested by user
- Authority is explicitly possessed and delegated down the chain
- Context carries trusted/clean provenance
- AgentGuard permits execution (ALLOW)
- Proof of legitimate execution via counter (customer_read_calls == 1).
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from agentguard.agents.identity import AgentTrustLevel
from agentguard.client import AgentGuard
from agentguard.context.provenance import ContextSource
from agentguard.context.taint import TaintState
from agentguard.tracing.tracer import CausalGraph
from examples.multi_agent.enterprise_data import EnterpriseFinancialWarehouse
from examples.multi_agent.mcp_server import SimulatedMCPServer
from examples.multi_agent.tools import EnterpriseToolSuite


@dataclass
class AuthorizedScenarioResult:
    trace_id: str
    task_id: str
    decision: str
    allowed: bool
    customer_records: List[Dict[str, Any]]
    customer_read_calls: int
    tree_text: str
    json_trace: str
    graph: CausalGraph


def run_authorized_customer_audit_scenario(
    guard: Optional[AgentGuard] = None,
    warehouse: Optional[EnterpriseFinancialWarehouse] = None,
    mcp_server: Optional[SimulatedMCPServer] = None,
) -> AuthorizedScenarioResult:
    """Execute legitimate workflow where sensitive customer DB access is authorized."""
    guard = guard or AgentGuard()
    warehouse = warehouse or EnterpriseFinancialWarehouse()
    mcp_server = mcp_server or SimulatedMCPServer()

    tools = EnterpriseToolSuite(guard=guard, warehouse=warehouse, mcp_server=mcp_server)

    # Register authorized audit agents where customer_db.read is explicitly authorized
    planner = guard.agent(
        name="CompliancePlannerAgent",
        framework="crewai",
        capabilities=["delegate_audit", "customer_db.read", "financial_extract"],
        trust_level=AgentTrustLevel.HIGH,
    )
    auditor = guard.agent(
        name="SecurityAuditAgent",
        framework="langchain",
        capabilities=["customer_db.read", "financial_extract"],
        trust_level=AgentTrustLevel.HIGH,
    )
    data_agent = guard.agent(
        name="DataAgent",
        framework="custom",
        capabilities=["customer_db.read", "financial_extract"],
        trust_level=AgentTrustLevel.MEDIUM,
    )

    records: List[Dict[str, Any]] = []
    task_id_rec = ""
    trace_id_rec = ""

    with guard.task(
        intent="Perform authorized internal customer risk audit and verify compliance records.",
        initiating_user="ciso_auditor@acmeglobal.com",
        initiating_application="enterprise_audit_portal",
    ) as task:
        task_id_rec = task.task_id
        trace_id_rec = task.trace_id

        # Planner delegates customer_db.read to Auditor
        with planner.delegate(auditor, capabilities=["customer_db.read", "financial_extract"]) as d1:
            
            # Auditor ingests authorized internal audit context
            audit_ctx = guard.context(
                data="Official compliance audit mandate CISO-2026-081",
                source=ContextSource.USER,
                trust_level="verified",
                taint_state=TaintState.CLEAN,
            )

            # Auditor delegates customer_db.read to DataAgent
            with auditor.delegate(data_agent, capabilities=["customer_db.read"]) as d2:
                
                # Propagate context
                data_ctx = audit_ctx.propagate(
                    to_agent_id=data_agent.agent_id,
                    action="execute_authorized_audit_query",
                    guard=guard,
                )

                # DataAgent invokes protected customer_db.read tool
                records = tools.read_customer_records(limit=3)

    graph = guard.reconstruct_trace(trace_id_rec)
    tree_text = guard.render_causal_tree(trace_id_rec)
    json_trace = guard.export_trace_json(trace_id_rec, indent=2)

    return AuthorizedScenarioResult(
        trace_id=trace_id_rec,
        task_id=task_id_rec,
        decision="ALLOW",
        allowed=True,
        customer_records=records,
        customer_read_calls=warehouse.customer_read_calls,
        tree_text=tree_text,
        json_trace=json_trace,
        graph=graph,
    )
