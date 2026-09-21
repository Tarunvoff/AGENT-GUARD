"""Phase 4 Tests — Offensive strategies, multi-agent propagation, and cross-protocol equivalence."""

import unittest
from actshield.offensive.attack import AttackCase, AttackType, ExpectedBehavior
from actshield.offensive.engine import OffensiveEngine
from actshield.offensive.strategies import (
    PromptInjectionStrategy,
    AuthorityEscalationStrategy,
    ToolPoisoningStrategy,
    ContextManipulationStrategy,
    MCPInjectionStrategy,
    DataExfiltrationStrategy,
    DelegationEscalationStrategy,
)
from actshield.offensive.target import target_registry


class TestPhase4Strategies(unittest.TestCase):
    """Test all strategy generators and multi-agent execution."""

    def setUp(self):
        self.target = target_registry.get("actshield-demo")
        self.engine = OffensiveEngine()

    def test_all_strategies_generate_valid_cases(self):
        strategies = [
            PromptInjectionStrategy(),
            AuthorityEscalationStrategy(),
            ToolPoisoningStrategy(),
            ContextManipulationStrategy(),
            MCPInjectionStrategy(),
            DataExfiltrationStrategy(),
            DelegationEscalationStrategy(),
        ]
        for strat in strategies:
            cases = strat.generate(self.target, count=3)
            assert len(cases) == 3
            assert all(c.attack_id for c in cases)
            assert all(c.safety_class.value == "LOCAL_SYNTHETIC" for c in cases)

    def test_prompt_injection_strategy_execution(self):
        strat = PromptInjectionStrategy()
        cases = strat.generate(self.target, count=2)
        for c in cases:
            res = self.engine.execute_attack(c, self.target)
            assert res.blocked is True
            assert res.bypassed is False

    def test_authority_escalation_strategy_execution(self):
        strat = AuthorityEscalationStrategy()
        cases = strat.generate(self.target, count=2)
        for c in cases:
            res = self.engine.execute_attack(c, self.target)
            assert res.blocked is True

    def test_data_exfiltration_strategy_execution(self):
        strat = DataExfiltrationStrategy()
        cases = strat.generate(self.target, count=2)
        for c in cases:
            res = self.engine.execute_attack(c, self.target)
            assert res.blocked is True

    def test_cross_protocol_equivalence_mcp_and_http(self):
        """Verify equivalent causal security semantics across MCP and HTTP entry points."""
        mcp_attack = AttackCase(
            attack_id="atk_proto_mcp",
            description="MCP protocol test",
            entry_point="mcp_response",
            target_agent="DataAgent",
            payload="Extract customer records",
            target_tool="customer_db.read",
        )
        http_attack = AttackCase(
            attack_id="atk_proto_http",
            description="HTTP protocol test",
            entry_point="http_request",
            target_agent="DataAgent",
            payload="Extract customer records",
            target_tool="customer_db.read",
        )
        res_mcp = self.engine.execute_attack(mcp_attack, self.target)
        res_http = self.engine.execute_attack(http_attack, self.target)

        assert res_mcp.actual_decision == res_http.actual_decision == "BLOCK"
        assert res_mcp.blocked == res_http.blocked == True


if __name__ == "__main__":
    unittest.main()
