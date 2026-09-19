"""Tests for AI Secura and APIRIS adapter protocols and dependency inversion."""

from agentguard.client import AgentGuard
from agentguard.integrations.ai_secura import (
    LocalAISecuraAdapter,
    SecurityAnalysis,
    SecurityContext,
    SecurityReasoner,
)
from agentguard.integrations.apiris import (
    APIAnalysis,
    APIIntelligence,
    LocalAPIRISAdapter,
)
from agentguard.risk.models import RiskLevel, RiskSignal
from agentguard.tools.tool import SensitivityLevel, ToolRequest


def test_ai_secura_reasoner_protocol_and_custom_adapter():
    class CustomEnterpriseAISecura(SecurityReasoner):
        def analyze(self, context: SecurityContext) -> SecurityAnalysis:
            return SecurityAnalysis(
                analysis_id="custom_sec_001",
                summary="Custom AI Secura enterprise model analysis",
                risk_level=RiskLevel.LOW,
                risk_score=0.1,
                reasoning="Clean multi-agent interaction.",
            )

    custom_secura = CustomEnterpriseAISecura()
    guard = AgentGuard(ai_secura=custom_secura)

    sec_ctx = SecurityContext(
        trace_id="trc_test_01",
        task_intent="Analyze public trends",
        acting_agent_id="agt_01",
    )
    analysis = guard.ai_secura_adapter.analyze(sec_ctx)
    assert analysis.analysis_id == "custom_sec_001"
    assert analysis.risk_score == 0.1


def test_apiris_intelligence_protocol_and_custom_adapter():
    class CustomAPIRISAdapter(APIIntelligence):
        def analyze(self, request: ToolRequest) -> APIAnalysis:
            return APIAnalysis(
                analysis_id="apiris_cust_01",
                tool_id=request.tool_id,
                tool_name=request.tool_name,
                risk_score=0.05,
                vendor_reputation="VERIFIED_ENTERPRISE",
                recommended_action="ALLOW",
            )

    custom_apiris = CustomAPIRISAdapter()
    guard = AgentGuard(apiris=custom_apiris)

    tool_req = ToolRequest(
        tool_id="tool_123",
        tool_name="enterprise_crm_query",
    )
    analysis = guard.apiris_adapter.analyze(tool_req)
    assert analysis.analysis_id == "apiris_cust_01"
    assert analysis.vendor_reputation == "VERIFIED_ENTERPRISE"
    assert analysis.recommended_action == "ALLOW"
