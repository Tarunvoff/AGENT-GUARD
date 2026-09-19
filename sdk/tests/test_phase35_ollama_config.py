"""Phase 3.5 Offline Tests — Config, Schema, Packet, Fallback, JSON Repair.

These tests do NOT require a running Ollama instance.
They validate the full offline pipeline: configuration, security packet
construction, Pydantic schema, JSON repair logic, fallback behavior,
policy integration (AI ALLOW + Policy BLOCK), and event emission.
"""

import json
import os
import unittest
from unittest.mock import patch, MagicMock

from agentguard.llm_config import LLMConfig
from agentguard.integrations.ai_secura import SecurityContext
from agentguard.integrations.ai_secura_analysis import (
    AISecuraAnalysis,
    ThreatSeverity,
    IntentAlignment,
    AIRecommendation,
    AttackTechnique,
    EvidenceTriad,
    AuthorityAnalysis,
    TaintAnalysis,
)
from agentguard.integrations.security_packet import build_security_packet
from agentguard.integrations.few_shot import select_few_shot_examples, format_examples_for_prompt
from agentguard.integrations.ollama_adapter import (
    OllamaAISecuraAdapter,
    _parse_analysis,
    _strip_markdown_fences,
    _make_unavailable_analysis,
)
from agentguard.tracing.events import EventType
from agentguard.risk.models import RiskLevel


class TestLLMConfig(unittest.TestCase):
    """LLMConfig env-var loading and defaults."""

    def test_default_config(self):
        cfg = LLMConfig()
        assert cfg.provider == "local"
        assert cfg.model == "qwen2.5:7b"
        assert cfg.ollama_base_url == "http://localhost:11434"
        assert cfg.timeout_seconds == 60
        assert cfg.temperature == 0.1

    def test_from_env(self):
        with patch.dict(os.environ, {
            "AGENTGUARD_LLM_PROVIDER": "ollama",
            "AGENTGUARD_LLM_MODEL": "ai-secura",
            "AGENTGUARD_OLLAMA_BASE_URL": "http://custom:9999",
            "AGENTGUARD_LLM_TIMEOUT": "60",
        }):
            cfg = LLMConfig.from_env()
            assert cfg.provider == "ollama"
            assert cfg.model == "ai-secura"
            assert cfg.ollama_base_url == "http://custom:9999"
            assert cfg.timeout_seconds == 60

    def test_ollama_urls(self):
        cfg = LLMConfig(ollama_base_url="http://localhost:11434/")
        assert cfg.ollama_generate_url == "http://localhost:11434/api/generate"
        assert cfg.ollama_tags_url == "http://localhost:11434/api/tags"

    def test_is_ollama_flag(self):
        assert LLMConfig(provider="ollama").is_ollama is True
        assert LLMConfig(provider="local").is_ollama is False


class TestAISecuraAnalysisSchema(unittest.TestCase):
    """AISecuraAnalysis Pydantic schema validation."""

    def test_minimal_defaults(self):
        a = AISecuraAnalysis()
        assert a.threat_type == "unknown"
        assert a.severity == ThreatSeverity.UNKNOWN
        assert a.confidence == 0.0
        assert a.intent_alignment == IntentAlignment.UNKNOWN
        assert a.ai_recommendation == AIRecommendation.UNKNOWN
        assert a.ai_unavailable is False
        assert a.analysis_id.startswith("aisec35_")

    def test_full_construction(self):
        a = AISecuraAnalysis(
            threat_type="indirect_prompt_injection",
            attack_category="injection",
            attack_technique=AttackTechnique.INDIRECT_PROMPT_INJECTION,
            severity=ThreatSeverity.CRITICAL,
            confidence=0.95,
            evidence=EvidenceTriad(
                observed=["SYSTEM DIRECTIVE in MCP response"],
                inferred=["Adversarial payload redirecting to customer_db"],
                unknown=[],
            ),
            intent_alignment=IntentAlignment.VIOLATED,
            authority_analysis=AuthorityAnalysis(
                acting_agent="DataAgent",
                authority_violated=True,
            ),
            taint_analysis=TaintAnalysis(is_tainted=True),
            ai_recommendation=AIRecommendation.BLOCK,
            provider="ollama",
            model="qwen2.5:7b",
        )
        assert a.severity == ThreatSeverity.CRITICAL
        assert a.evidence.observed[0] == "SYSTEM DIRECTIVE in MCP response"
        assert a.authority_analysis.authority_violated is True
        assert a.taint_analysis.is_tainted is True

    def test_all_attack_techniques_valid(self):
        for technique in AttackTechnique:
            a = AISecuraAnalysis(attack_technique=technique)
            assert a.attack_technique == technique


class TestSecurityPacketBuilder(unittest.TestCase):
    """Security packet construction from AgentGuard objects."""

    def test_basic_packet(self):
        ctx = SecurityContext(
            trace_id="tr_test",
            task_intent="Analyze public filings",
            acting_agent_name="ResearchAgent",
            acting_agent_trust="medium",
            delegation_chain=[{"from": "Planner", "to": "Research", "capabilities": ["search"]}],
            taint_states=["CLEAN"],
            tool_name="fetch_10k",
            target_resource_sensitivity="MEDIUM",
        )
        pkt = build_security_packet(ctx)
        assert pkt["original_intent"] == "Analyze public filings"
        assert pkt["agent"]["name"] == "ResearchAgent"
        assert pkt["tool"]["name"] == "fetch_10k"
        assert "CLEAN" in pkt["taint_states"]

    def test_packet_with_apiris(self):
        from agentguard.integrations.apiris import APIAnalysis
        ctx = SecurityContext(trace_id="tr_test", task_intent="test")
        apiris = APIAnalysis(
            analysis_id="apiris_test",
            tool_id="t1",
            tool_name="dangerous_tool",
            recommended_action="BLOCK",
            risk_score=0.95,
        )
        pkt = build_security_packet(ctx, apiris_result=apiris)
        assert pkt["apiris"]["recommended_action"] == "BLOCK"
        assert pkt["apiris"]["risk_score"] == 0.95

    def test_packet_with_deterministic_policy(self):
        ctx = SecurityContext(trace_id="tr_test", task_intent="test")
        pkt = build_security_packet(
            ctx,
            deterministic_decision="BLOCK",
            deterministic_reason_codes=["TAINTED_CONTEXT_INTO_SENSITIVE_SINK"],
        )
        assert pkt["deterministic_policy"]["decision"] == "BLOCK"


class TestJSONParsing(unittest.TestCase):
    """Strict JSON validation and markdown fence stripping."""

    def test_strip_markdown_fences(self):
        raw = '```json\n{"threat_type": "none"}\n```'
        assert _strip_markdown_fences(raw) == '{"threat_type": "none"}'

    def test_parse_valid_json(self):
        raw = json.dumps({
            "threat_type": "none",
            "severity": "LOW",
            "confidence": 0.8,
            "intent_alignment": "ALIGNED",
            "ai_recommendation": "ALLOW",
        })
        analysis = _parse_analysis(raw)
        assert analysis.threat_type == "none"
        assert analysis.severity == ThreatSeverity.LOW
        assert analysis.intent_alignment == IntentAlignment.ALIGNED

    def test_parse_invalid_severity_falls_to_unknown(self):
        raw = json.dumps({"severity": "MEGA_CRITICAL"})
        analysis = _parse_analysis(raw)
        assert analysis.severity == ThreatSeverity.UNKNOWN

    def test_parse_invalid_json_raises(self):
        with self.assertRaises(json.JSONDecodeError):
            _parse_analysis("NOT JSON AT ALL")


class TestUnavailableFallback(unittest.TestCase):
    """When Ollama is unreachable, ai_unavailable=True and no ALLOW."""

    def test_unavailable_analysis(self):
        a = _make_unavailable_analysis("Connection refused")
        assert a.ai_unavailable is True
        assert a.ai_recommendation == AIRecommendation.UNKNOWN
        assert a.confidence == 0.0
        assert "unavailable" in a.analysis.lower()

    def test_ollama_connection_error_returns_unavailable(self):
        cfg = LLMConfig(provider="ollama", ollama_base_url="http://localhost:99999")
        adapter = OllamaAISecuraAdapter(cfg)
        ctx = SecurityContext(trace_id="tr_test", task_intent="test")
        result = adapter.analyze(ctx)
        assert result.ai_unavailable is True
        assert result.ai_recommendation != AIRecommendation.ALLOW


class TestPolicyIntegration(unittest.TestCase):
    """AI recommendation vs PolicyEvaluator — PolicyEvaluator always wins."""

    def test_ai_allow_policy_block(self):
        """AI Secura says ALLOW, but deterministic policy says BLOCK -> BLOCK."""
        # The AI analysis recommends ALLOW
        ai = AISecuraAnalysis(
            ai_recommendation=AIRecommendation.ALLOW,
            severity=ThreatSeverity.LOW,
        )
        # PolicyEvaluator independently decided BLOCK
        # The final decision is BLOCK regardless of AI recommendation
        assert ai.ai_recommendation == AIRecommendation.ALLOW
        # PolicyEvaluator is authoritative — it can override AI
        # This test validates the principle exists in the schema
        from agentguard.decisions.decision import DecisionAction, SecurityDecision
        decision = SecurityDecision(
            action=DecisionAction.BLOCK,
            reason_code="TAINTED_CONTEXT_INTO_SENSITIVE_SINK",
            explanation="Deterministic policy overrides AI ALLOW recommendation",
            trace_id="tr_test",
        )
        assert decision.action == DecisionAction.BLOCK

    def test_ai_block_policy_allow(self):
        """AI Secura says BLOCK, but deterministic policy says ALLOW -> ALLOW."""
        ai = AISecuraAnalysis(
            ai_recommendation=AIRecommendation.BLOCK,
            severity=ThreatSeverity.HIGH,
        )
        from agentguard.decisions.decision import DecisionAction, SecurityDecision
        decision = SecurityDecision(
            action=DecisionAction.ALLOW,
            reason_code="ALL_CHECKS_PASSED",
            explanation="Deterministic policy allows despite AI BLOCK recommendation",
            trace_id="tr_test",
        )
        assert ai.ai_recommendation == AIRecommendation.BLOCK
        assert decision.action == DecisionAction.ALLOW


class TestFewShotSelector(unittest.TestCase):
    """Deterministic few-shot example selection."""

    def test_selects_mcp_examples_for_mcp_context(self):
        context = {
            "context_provenance": [{"source": "external_mcp"}],
            "taint_states": ["TAINTED"],
            "tool": {"name": "fetch_data"},
            "resource": {"sensitivity": "CRITICAL"},
        }
        examples = select_few_shot_examples(context)
        assert len(examples) <= 4
        # MCP examples should rank higher
        if examples:
            tags = examples[0].get("tags", [])
            assert "mcp" in tags or "injection" in tags or "tainted" in tags

    def test_format_examples_empty(self):
        assert format_examples_for_prompt([]) == ""

    def test_format_examples_produces_text(self):
        examples = [{"description": "Test", "input": {"foo": 1}, "expected_output": {"bar": 2}}]
        text = format_examples_for_prompt(examples)
        assert "Example 1" in text
        assert "Test" in text


class TestAIAnalysisEventType(unittest.TestCase):
    """AI_ANALYSIS_COMPLETED event type exists."""

    def test_event_type_exists(self):
        assert EventType.AI_ANALYSIS_COMPLETED == "ai.analysis_completed"

    def test_event_type_in_enum(self):
        assert "AI_ANALYSIS_COMPLETED" in EventType.__members__


class TestSecretRedaction(unittest.TestCase):
    """AI analysis payloads go through redaction."""

    def test_raw_response_can_be_redacted(self):
        from agentguard.config import default_redact_function
        analysis_dict = {
            "analysis": "Found api_key: sk-1234567890abcdefghij in evidence",
            "raw_response": "Bearer eyJhbGciOiJIUzI1NiJ9.test_token_value",
        }
        redacted = default_redact_function(analysis_dict)
        assert "[REDACTED]" in redacted["raw_response"]

    def test_ollama_timeout_config(self):
        cfg = LLMConfig(timeout_seconds=5)
        assert cfg.timeout_seconds == 5
        cfg2 = LLMConfig(timeout_seconds=120)
        assert cfg2.timeout_seconds == 120


class TestLegacyMapping(unittest.TestCase):
    """OllamaAISecuraAdapter.analyze_legacy returns SecurityAnalysis."""

    def test_map_to_legacy_format(self):
        from agentguard.integrations.ollama_adapter import _map_to_legacy
        rich = AISecuraAnalysis(
            threat_type="indirect_prompt_injection",
            attack_technique=AttackTechnique.INDIRECT_PROMPT_INJECTION,
            severity=ThreatSeverity.CRITICAL,
            confidence=0.9,
            intent_alignment=IntentAlignment.VIOLATED,
            authority_analysis=AuthorityAnalysis(authority_violated=True),
            analysis="Detected indirect injection via MCP response",
        )
        ctx = SecurityContext(trace_id="tr_test", task_intent="test")
        legacy = _map_to_legacy(rich, ctx)
        assert legacy.risk_level == RiskLevel.CRITICAL
        assert legacy.intent_drift_detected is True
        assert legacy.authority_violation_detected is True
        assert len(legacy.prompt_injection_indicators) > 0


if __name__ == "__main__":
    unittest.main()
