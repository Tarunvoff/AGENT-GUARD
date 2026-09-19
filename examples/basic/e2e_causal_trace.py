"""AgentGuard Phase 1 E2E Example: Multi-Agent Causal Trace & Security Governance.

This script demonstrates:
1. Agent registration with identities and capabilities
2. User task initialization with causal correlation
3. Multi-agent delegation (Planner -> Researcher -> DataAgent)
4. Monotonic authority enforcement
5. Ingestion and propagation of context with taint tracking
6. Protected tool execution against sensitive resources
7. Deterministic policy enforcement
8. Causal graph reconstruction output in both human-readable tree and JSON format.
"""

import json
from agentguard import (
    AgentGuard,
    AgentTrustLevel,
    ContextSource,
    DecisionAction,
    Resource,
    SensitivityLevel,
    TaintState,
)


def run_demo():
    print("=" * 80)
    print(" AgentGuard Phase 1 Foundation: Multi-Agent Causal Security Demonstration")
    print("=" * 80)

    guard = AgentGuard()

    # 1. Register Agents
    print("\n[1] Registering Autonomous Agents...")
    planner = guard.agent(
        name="PlannerAgent",
        framework="crewai",
        version="1.0.0",
        capabilities=["plan_workflow", "public_search", "financial_extract"],
        trust_level=AgentTrustLevel.HIGH,
        metadata={"owner": "AI Ops Team"}
    )
    print(f"  + Registered Planner: {planner.agent_id} (Capabilities: {planner.capability_names()})")

    researcher = guard.agent(
        name="ResearcherAgent",
        framework="langchain",
        version="2.1.0",
        capabilities=["public_search", "financial_extract"],
        trust_level=AgentTrustLevel.MEDIUM,
    )
    print(f"  + Registered Researcher: {researcher.agent_id} (Capabilities: {researcher.capability_names()})")

    data_agent = guard.agent(
        name="DataExtractionAgent",
        framework="custom",
        version="1.0.0",
        capabilities=["financial_extract"],
        trust_level=AgentTrustLevel.MEDIUM,
    )
    print(f"  + Registered DataAgent: {data_agent.agent_id} (Capabilities: {data_agent.capability_names()})")

    # 2. Register Protected Tool & Resource
    print("\n[2] Registering Protected Tools and Enterprise Resources...")
    financial_db = Resource(
        name="EnterpriseFinancialWarehouse",
        resource_type="database",
        uri="snowflake://acme_corp.eu-west-1/finance/q3_2026",
        sensitivity=SensitivityLevel.HIGH,
        metadata={"compliance": "SOX"}
    )

    @guard.protected_tool(
        name="query_financial_metrics",
        description="Extract quarterly revenue and EBITDA metrics from secure warehouse",
        sensitivity=SensitivityLevel.HIGH,
        required_capabilities=["financial_extract"],
        target_resources=[financial_db],
    )
    def query_financial_metrics(company: str, fiscal_year: int, auth_token: str = "sk-live-secret-token-999"):
        # Secret tokens in arguments will be automatically redacted in security events!
        return {
            "company": company,
            "fiscal_year": fiscal_year,
            "revenue": "$14.2B",
            "ebitda": "$4.1B",
            "net_margin": "28.8%",
            "source_status": "VERIFIED_AUDITED"
        }

    print(f"  + Registered Tool: 'query_financial_metrics' (Sensitivity: HIGH, Resource: {financial_db.name})")

    # 3. Execute Multi-Agent Workflow within Task Scope
    print("\n[3] Executing Multi-Agent Task Workflow with Causal Provenance...")
    
    with guard.task(
        intent="Analyze FY2026 financial performance for ACME Global",
        initiating_user="ciso_auditor@acmeglobal.com",
        initiating_application="agentic_audit_hub_v1",
    ) as task:
        print(f"  * Task Started: ID={task.task_id} Trace={task.trace_id}")
        print(f"    Intent: '{task.original_intent}'")

        # Step 3a: Planner delegates to Researcher
        print("  * Planner delegates authority to Researcher (Capabilities: public_search, financial_extract)...")
        with planner.delegate(researcher, capabilities=["public_search", "financial_extract"]) as dlg_1:
            print(f"    -> Active Delegation {dlg_1.delegation_id} (Depth: {dlg_1.depth})")

            # Researcher ingests external guidance context
            print("  * Researcher ingests external document context...")
            research_context = guard.context(
                data="Target query parameters for ACME Global FY2026 filings",
                source=ContextSource.USER,
                trust_level="verified",
                taint_state=TaintState.TRUSTED,
            )
            print(f"    -> Context Created: {research_context.context_id} [Taint: {research_context.taint_state.value}]")

            # Step 3b: Researcher delegates down to DataExtractionAgent
            print("  * Researcher delegates authority down to DataExtractionAgent (Capability: financial_extract)...")
            with researcher.delegate(data_agent, capabilities=["financial_extract"]) as dlg_2:
                print(f"    -> Active Sub-Delegation {dlg_2.delegation_id} (Depth: {dlg_2.depth}, Parent: {dlg_2.parent_delegation_id})")

                # Propagate context lineage to DataAgent
                print("  * Propagating context lineage to DataExtractionAgent...")
                data_context = research_context.propagate(
                    to_agent_id=data_agent.agent_id,
                    action="targeted_financial_query_preparation",
                    guard=guard,
                )
                print(f"    -> Derived Context: {data_context.context_id} (Lineage Hops: {len(data_context.provenance.hops)})")

                # Step 3c: DataAgent invokes protected financial tool
                print("  * DataExtractionAgent invoking protected tool 'query_financial_metrics'...")
                result = query_financial_metrics(
                    company="ACME Global",
                    fiscal_year=2026,
                    auth_token="sk-live-super-confidential-credential"
                )
                print(f"    -> Tool Output: {result['company']} Revenue={result['revenue']} (Status: {result['source_status']})")

    print("\n[4] Reconstructing Causal Execution & Security Enforcement Graph...")
    
    # 5. Output Human-Readable ASCII Causal Tree
    print("\n" + "-" * 80)
    print(" HUMAN-READABLE CAUSAL TRACE TREE:")
    print("-" * 80)
    guard.print_causal_tree(task.trace_id)

    # 6. Output Machine-Readable JSON Export
    print("\n" + "-" * 80)
    print(" MACHINE-READABLE CAUSAL GRAPH (JSON):")
    print("-" * 80)
    json_trace = guard.export_trace_json(task.trace_id, indent=2)
    print(json_trace)

    print("\n" + "=" * 80)
    print(" AgentGuard Phase 1 Demonstration Completed Successfully!")
    print("=" * 80)


if __name__ == "__main__":
    run_demo()
