"""Comprehensive Phase 2 Hardening & Causal Security Test Suite."""

import os
from typing import Any, Dict, List, Optional
import pytest
from agentguard.agents.identity import AgentTrustLevel
from agentguard.client import AgentGuard
from agentguard.context.provenance import ContextSource, ContextTrustLevel
from agentguard.context.taint import TaintState
from agentguard.decisions.decision import DecisionAction
from agentguard.policy.intent import (
    DeterministicIntentAnalyzer,
    IntentAlignmentResult,
    IntentAlignmentStatus,
    IntentAnalyzer,
)

from agentguard.risk.models import RiskFactorBreakdown
from agentguard.tools.tool import SensitivityLevel
from agentguard.tracing.events import EventType
from examples.multi_agent.agents import setup_agents
from examples.multi_agent.attack_scenario import (
    AttackResult,
    run_attack_scenario,
    run_authority_impersonation_attack,
    run_direct_escalation_attack,
    run_indirect_prompt_injection_attack,
    run_multihop_toolchain_attack,
    run_semantic_escalation_attack,
)
from examples.multi_agent.authorized_scenario import run_authorized_customer_audit_scenario
from examples.multi_agent.benign_scenario import run_benign_scenario
from examples.multi_agent.enterprise_data import EnterpriseFinancialWarehouse
from examples.multi_agent.mcp_server import MCPMode, SimulatedMCPServer
from examples.multi_agent.replay_attack import replay_attack
from examples.multi_agent.tools import EnterpriseToolSuite


# -----------------------------------------------------------------------------
# 1. External MCP is Untrusted but Clean
# -----------------------------------------------------------------------------
def test_external_mcp_untrusted_but_clean():
    guard = AgentGuard()
    warehouse = EnterpriseFinancialWarehouse()
    tools = EnterpriseToolSuite(guard=guard, warehouse=warehouse, mcp_server=SimulatedMCPServer())
    planner, researcher, analyst, data_agent = setup_agents(guard)

    with guard.task(intent="Analyze financial metrics"):
        with planner.delegate(data_agent, capabilities=["financial_extract"]):
            # UNTRUSTED source + CLEAN taint
            ctx = guard.context(
                data="Public financial metric table",
                source=ContextSource.EXTERNAL_MCP,
                trust_level=ContextTrustLevel.UNTRUSTED.value,
                taint_state=TaintState.CLEAN,
            )
            assert ctx.trust_level == "untrusted"
            assert ctx.taint_state == TaintState.CLEAN
            assert ctx.taint_state.is_safe is True

            # Execution is allowed because content is clean and capability is delegated
            res = tools.query_financial_metrics(company="ACME Global", fiscal_year=2026)
            assert res["revenue"] == "$14.25B"
            assert warehouse.financial_query_calls == 1


# -----------------------------------------------------------------------------
# 2. External MCP with Tainted Context
# -----------------------------------------------------------------------------
def test_external_mcp_tainted_context():
    guard = AgentGuard()
    ctx = guard.context(
        data="Injected adversarial directive",
        source=ContextSource.EXTERNAL_MCP,
        trust_level="untrusted",
        taint_state=TaintState.TAINTED,
    )
    assert ctx.trust_level == "untrusted"
    assert ctx.taint_state == TaintState.TAINTED
    assert ctx.taint_state.is_tainted is True
    assert ctx.taint_state.is_safe is False


# -----------------------------------------------------------------------------
# 3. Trust and Taint are Independent
# -----------------------------------------------------------------------------
def test_trust_and_taint_are_independent():
    guard = AgentGuard()
    
    # 4 distinct combinations
    c1 = guard.context(data="c1", source=ContextSource.USER, trust_level="trusted", taint_state=TaintState.CLEAN)
    c2 = guard.context(data="c2", source=ContextSource.EXTERNAL_MCP, trust_level="untrusted", taint_state=TaintState.CLEAN)
    c3 = guard.context(data="c3", source=ContextSource.EXTERNAL_MCP, trust_level="untrusted", taint_state=TaintState.TAINTED)
    c4 = guard.context(data="c4", source=ContextSource.USER, trust_level="trusted", taint_state=TaintState.TAINTED)

    assert c1.trust_level == "trusted" and c1.taint_state == TaintState.CLEAN
    assert c2.trust_level == "untrusted" and c2.taint_state == TaintState.CLEAN
    assert c3.trust_level == "untrusted" and c3.taint_state == TaintState.TAINTED
    assert c4.trust_level == "trusted" and c4.taint_state == TaintState.TAINTED


# -----------------------------------------------------------------------------
# 4. Original Intent Preserved Across Multi-Agent Handoffs
# -----------------------------------------------------------------------------
def test_original_intent_preserved_across_hops():
    guard = AgentGuard()
    planner, researcher, analyst, data_agent = setup_agents(guard)
    user_intent = "Analyze FY2026 financial performance for ACME Global using public info"

    with guard.task(intent=user_intent, initiating_user="ciso@acme.com") as task:
        with planner.delegate(researcher, capabilities=["public_search", "financial_extract"]):
            with researcher.delegate(analyst, capabilities=["financial_extract"]):
                with analyst.delegate(data_agent, capabilities=["financial_extract"]):
                    events = guard.tracer.get_events(task.trace_id)
                    assert events[0].payload["intent"] == user_intent
                    assert task.original_intent == user_intent


# -----------------------------------------------------------------------------
# 5. Intent Violation Detected Deterministically
# -----------------------------------------------------------------------------
def test_intent_violation_detected():
    analyzer = DeterministicIntentAnalyzer()
    res = analyzer.analyze(
        original_intent="Analyze FY2026 financial performance using publicly available financial information",
        tool_name="customer_db.read",
        required_capabilities=["customer_db.read"],
        target_resource_sensitivity="CRITICAL",
        target_resource_name="CustomerPIIVault",
    )
    assert res.status == IntentAlignmentStatus.VIOLATION
    assert res.is_violation is True
    assert "PUBLIC_INTENT_VS_CUSTOMER_PII_SINK" in res.matched_indicators


# -----------------------------------------------------------------------------
# 6. Legitimate Action Aligned With Intent
# -----------------------------------------------------------------------------
def test_legitimate_action_aligned_with_intent():
    analyzer = DeterministicIntentAnalyzer()
    res = analyzer.analyze(
        original_intent="Analyze FY2026 financial performance using publicly available financial information",
        tool_name="query_financial_metrics",
        required_capabilities=["financial_extract"],
        target_resource_sensitivity="HIGH",
        target_resource_name="EnterpriseFinancialWarehouse",
    )
    assert res.status == IntentAlignmentStatus.ALIGNED
    assert res.is_violation is False


# -----------------------------------------------------------------------------
# 7. Authority Containment Violation Reported in Structured Decision
# -----------------------------------------------------------------------------
def test_authority_containment_violation_reported():
    result = run_attack_scenario()
    assert result.authority_violation is True
    assert result.decision == "BLOCK"
    assert "customer_db.read" in result.requested_capability
    assert "financial_extract" in result.delegated_capabilities


# -----------------------------------------------------------------------------
# 8. Legitimate Sensitive Access Allowed (Positive Control)
# -----------------------------------------------------------------------------
def test_legitimate_sensitive_access_allowed():
    res = run_authorized_customer_audit_scenario()
    assert res.allowed is True
    assert res.decision == "ALLOW"
    assert res.customer_read_calls == 1
    assert len(res.customer_records) == 3


# -----------------------------------------------------------------------------
# 9. Influencing Context Identified in Causal Graph
# -----------------------------------------------------------------------------
def test_influencing_context_identified():
    result = run_attack_scenario()
    graph = result.graph
    influencing = graph.get_influencing_contexts()
    assert len(influencing) >= 1
    assert any(c["context_id"] == result.origin_context_id for c in influencing)


# -----------------------------------------------------------------------------
# 10. Causal Propagation Chain Reconstructed
# -----------------------------------------------------------------------------
def test_causal_propagation_reconstructed():
    result = run_attack_scenario()
    chain = result.propagation_chain
    assert "ResearchAgent" in chain
    assert "AnalysisAgent" in chain
    assert "DataAgent" in chain


# -----------------------------------------------------------------------------
# 11. Machine-Readable Attack Result Dictionary Export
# -----------------------------------------------------------------------------
def test_attack_result_dict_export():
    result = run_attack_scenario()
    d = result.to_dict()
    assert d["attack_type"] == "indirect_prompt_injection"
    assert d["authority_violation"] is True
    assert d["intent_violation"] is True
    assert d["decision"] == "BLOCK"
    assert d["tool_executed"] is False
    assert "risk_score" in d


# -----------------------------------------------------------------------------
# 12. Attack Variant 1: Direct Capability Escalation
# -----------------------------------------------------------------------------
def test_variant_1_direct_capability_escalation():
    res = run_direct_escalation_attack()
    assert res.blocked is True
    assert res.security_decision == "BLOCK"
    assert res.customer_read_calls == 0


# -----------------------------------------------------------------------------
# 13. Attack Variant 2: Indirect Prompt Injection
# -----------------------------------------------------------------------------
def test_variant_2_indirect_prompt_injection():
    res = run_indirect_prompt_injection_attack()
    assert res.blocked is True
    assert res.security_decision == "BLOCK"
    assert res.customer_read_calls == 0


# -----------------------------------------------------------------------------
# 14. Attack Variant 3: Authority Impersonation
# -----------------------------------------------------------------------------
def test_variant_3_authority_impersonation():
    res = run_authority_impersonation_attack()
    assert res.blocked is True
    assert res.security_decision == "BLOCK"
    assert res.customer_read_calls == 0


# -----------------------------------------------------------------------------
# 15. Attack Variant 4: Multi-Hop Tool Chain Escalation
# -----------------------------------------------------------------------------
def test_variant_4_multihop_toolchain_escalation():
    res = run_multihop_toolchain_attack()
    assert res.blocked is True
    assert res.security_decision == "BLOCK"
    assert res.customer_read_calls == 0


# -----------------------------------------------------------------------------
# 16. Attack Variant 5: Subtle Semantic Escalation
# -----------------------------------------------------------------------------
def test_variant_5_semantic_escalation():
    res = run_semantic_escalation_attack()
    assert res.blocked is True
    assert res.security_decision == "BLOCK"
    assert res.customer_read_calls == 0


# -----------------------------------------------------------------------------
# 17. Taint Cannot Be Laundered Through New Context Without Sanitization
# -----------------------------------------------------------------------------
def test_taint_cannot_be_laundered_through_new_context():
    guard = AgentGuard()
    warehouse = EnterpriseFinancialWarehouse()
    tools = EnterpriseToolSuite(guard=guard, warehouse=warehouse, mcp_server=SimulatedMCPServer())
    # Create an auditor agent with legitimate customer_db.read authority
    auditor = guard.agent(
        name="AuditorAgent",
        capabilities=["financial_extract", "customer_db.read"],
        trust_level="high",
    )
    data_agent = guard.agent(
        name="DataAgent",
        capabilities=["financial_extract", "customer_db.read"],
        trust_level="medium",
    )

    with guard.task(intent="Analyze financial data with customer audit"):
        with auditor.delegate(data_agent, capabilities=["financial_extract", "customer_db.read"]):

            # Ingest tainted context
            tainted_ctx = guard.context(
                data="Injected payload",
                source=ContextSource.EXTERNAL_MCP,
                taint_state=TaintState.TAINTED,
            )

            # Agent attempts to wrap the raw data into a 'new' context object without explicit sanitization
            laundered_ctx = tainted_ctx.propagate(
                to_agent_id=data_agent.agent_id,
                action="attempt_re_wrapping",
                guard=guard,
            )
            assert laundered_ctx.taint_state == TaintState.TAINTED  # Taint was NOT lost!

            # Attempting to access critical customer DB must be blocked
            with pytest.raises(PermissionError, match="TAINTED_CONTEXT_INTO_SENSITIVE_SINK"):
                tools.read_customer_records()

    assert warehouse.customer_read_calls == 0


# -----------------------------------------------------------------------------
# 18. Explicit Auditable Sanitization Clears Taint
# -----------------------------------------------------------------------------
def test_explicit_sanitization_clears_taint():
    guard = AgentGuard()
    warehouse = EnterpriseFinancialWarehouse()
    tools = EnterpriseToolSuite(guard=guard, warehouse=warehouse, mcp_server=SimulatedMCPServer())
    planner, researcher, analyst, data_agent = setup_agents(guard)

    with guard.task(intent="Analyze financial data"):
        # Ingest tainted context
        raw_ctx = guard.context(
            data="Raw text with injected string",
            source=ContextSource.EXTERNAL_MCP,
            taint_state=TaintState.TAINTED,
        )
        assert raw_ctx.taint_state == TaintState.TAINTED

        # Perform explicit, auditable schema validation sanitization
        clean_ctx = guard.sanitize_context(
            source_context=raw_ctx,
            sanitizer_name="PydanticFiscalSchemaValidator",
            reason="Extracted and verified structured quarterly financial schema, stripping natural language directives",
            transformed_data={"revenue": "$14.25B", "status": "VERIFIED"},
            new_taint=TaintState.CLEAN,
        )

        assert clean_ctx.taint_state == TaintState.CLEAN
        assert clean_ctx.metadata["sanitized_by"] == "PydanticFiscalSchemaValidator"
        assert len(clean_ctx.provenance.sanitizations) == 1
        assert clean_ctx.provenance.sanitizations[0].previous_taint == "TAINTED"
        assert clean_ctx.provenance.sanitizations[0].new_taint == "CLEAN"

        # Check emitted audit event
        san_events = [e for e in guard.tracer.get_events() if e.event_type == EventType.CONTEXT_SANITIZED]
        assert len(san_events) == 1
        assert san_events[0].payload["sanitizer_name"] == "PydanticFiscalSchemaValidator"


# -----------------------------------------------------------------------------
# 19. Deterministic Risk Factor Breakdown Computation
# -----------------------------------------------------------------------------
def test_deterministic_risk_breakdown_computation():
    breakdown = RiskFactorBreakdown.compute(
        has_tainted_context=True,       # +0.25
        is_critical_sink=True,          # +0.25
        has_authority_violation=True,   # +0.25
        has_intent_violation=True,      # +0.15
        is_untrusted_origin=True,       # +0.10
    )
    assert breakdown.tainted_context_score == 0.25
    assert breakdown.critical_sink_score == 0.25
    assert breakdown.authority_violation_score == 0.25
    assert breakdown.intent_violation_score == 0.15
    assert breakdown.untrusted_origin_score == 0.10
    assert breakdown.total_score == 1.00
    assert len(breakdown.risk_factors) == 5


# -----------------------------------------------------------------------------
# 20. Attack Replay Verification from Fixtures
# -----------------------------------------------------------------------------
def test_attack_replay_verification():
    fixtures = [
        "indirect_prompt_injection",
        "authority_impersonation",
        "tool_chain_escalation",
        "taint_laundering",
        "semantic_escalation",
    ]
    for fix in fixtures:
        assert replay_attack(fix) is True


# -----------------------------------------------------------------------------
# 21. Cross-Framework Metadata Preservation
# -----------------------------------------------------------------------------
def test_cross_framework_metadata_preservation():
    guard = AgentGuard()
    agent = guard.agent(
        name="LangGraphWorker",
        framework="langgraph",
        version="0.4.1",
        capabilities=["custom_op"],
        metadata={"runtime": "python3.13", "protocol": "MCP", "cluster": "eu-central-1"}
    )
    assert agent.framework == "langgraph"
    assert agent.metadata["protocol"] == "MCP"
    assert agent.metadata["cluster"] == "eu-central-1"

    # Event records framework metadata
    events = guard.tracer.get_events()
    assert events[0].payload["framework"] == "langgraph"
    assert events[0].metadata["protocol"] == "MCP"


# -----------------------------------------------------------------------------
# 22. Custom Intent Analyzer Protocol Registration
# -----------------------------------------------------------------------------
def test_custom_intent_analyzer_protocol_registration():
    class CustomRegexIntentAnalyzer(IntentAnalyzer):
        def analyze(self, original_intent: str, tool_name: str, **kwargs: Any) -> IntentAlignmentResult:
            if "financial" in original_intent.lower() and "customer" in tool_name.lower():
                return IntentAlignmentResult(
                    status=IntentAlignmentStatus.VIOLATION,
                    score=0.99,
                    reason="Custom analyzer flagged customer tool under financial intent",
                    matched_indicators=["CUSTOM_FLAG"],
                )
            return IntentAlignmentResult(status=IntentAlignmentStatus.ALIGNED, score=0.0)

    guard = AgentGuard(intent_analyzer=CustomRegexIntentAnalyzer())
    res = guard.policy.intent_analyzer.analyze(
        original_intent="Analyze financial report",
        tool_name="customer_db.read",
    )
    assert res.is_violation is True
    assert res.score == 0.99
    assert res.reason == "Custom analyzer flagged customer tool under financial intent"


# -----------------------------------------------------------------------------
# 23. Risk Breakdown Zero Baseline for Safe Executions
# -----------------------------------------------------------------------------
def test_risk_breakdown_zero_baseline():
    breakdown = RiskFactorBreakdown.compute(
        has_tainted_context=False,
        is_critical_sink=False,
        has_authority_violation=False,
        has_intent_violation=False,
        is_untrusted_origin=False,
    )
    assert breakdown.total_score == 0.0
    assert len(breakdown.risk_factors) == 0


# -----------------------------------------------------------------------------
# 24. Attack Fixtures JSON Schema Validation
# -----------------------------------------------------------------------------
def test_attack_fixtures_json_schema_validation():
    import json
    import pathlib
    fixture_dir = pathlib.Path(__file__).parent.parent.parent / "examples" / "attacks"
    files = list(fixture_dir.glob("*.json"))
    assert len(files) == 5

    required_keys = ["attack_id", "attack_type", "entry_point", "payload", "target_capability", "expected_decision"]
    for f in files:
        with open(f, "r", encoding="utf-8") as fp:
            data = json.load(fp)
            for k in required_keys:
                assert k in data, f"Missing {k} in fixture {f.name}"
            assert data["target_capability"] == "customer_db.read"
            assert data["expected_decision"] == "BLOCK"


# -----------------------------------------------------------------------------
# 25. Causal Graph Complete Edge & Relation Types
# -----------------------------------------------------------------------------
def test_causal_graph_complete_edge_relations():
    result = run_attack_scenario()
    graph = result.graph
    edge_relations = {e.relation for e in graph.edges}
    
    assert "INITIATED" in edge_relations
    assert "ENGAGED" in edge_relations
    assert "DELEGATED_TO" in edge_relations
    assert "INGESTED_OR_PROPAGATED" in edge_relations
    assert "INVOKED" in edge_relations
    assert "GOVERNED_BY" in edge_relations


# -----------------------------------------------------------------------------
# 26. Sanitized Context Allows Subsequent Tool Processing
# -----------------------------------------------------------------------------
def test_sanitized_context_allows_subsequent_tool_processing():
    guard = AgentGuard()
    warehouse = EnterpriseFinancialWarehouse()
    tools = EnterpriseToolSuite(guard=guard, warehouse=warehouse, mcp_server=SimulatedMCPServer())
    planner, researcher, analyst, data_agent = setup_agents(guard)

    with guard.task(intent="Analyze FY2026 financial metrics"):
        with planner.delegate(researcher, capabilities=["public_search", "public_documents", "financial_extract"]):
            # Ingest tainted MCP
            tainted_ctx = guard.context(
                data="Raw text with prompt injection payload",
                source=ContextSource.EXTERNAL_MCP,
                taint_state=TaintState.TAINTED,
            )
            # Explicit sanitization
            clean_ctx = guard.sanitize_context(
                source_context=tainted_ctx,
                sanitizer_name="PydanticFiscalSchemaValidator",
                reason="Validated fiscal schema",
                transformed_data={"company": "ACME Global", "fiscal_year": 2026},
                new_taint=TaintState.CLEAN,
            )
            # Legitimate financial query should succeed
            res = tools.query_financial_metrics(company="ACME Global", fiscal_year=2026)
            assert "revenue" in res
            assert warehouse.financial_query_calls == 1



# -----------------------------------------------------------------------------
# 27. Attack Result Dict Export Completeness
# -----------------------------------------------------------------------------
def test_attack_result_dict_export_completeness():
    result = run_attack_scenario()
    d = result.to_dict()
    assert d["decision"] == "BLOCK"
    assert d["tool_executed"] is False
    assert d["authority_violation"] is True
    assert d["intent_violation"] is True
    assert d["taint_state"] == "TAINTED"
    assert d["trust_state"] == "UNTRUSTED"
    assert d["risk_score"] > 0.8

