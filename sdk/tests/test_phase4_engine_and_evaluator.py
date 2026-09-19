"""Phase 4 Tests — OffensiveEngine, AttackEvaluator, and replay."""

import tempfile
import pathlib
import unittest
from agentguard.client import AgentGuard
from agentguard.decisions.decision import DecisionAction, SecurityDecision
from agentguard.offensive.attack import AttackCase, AttackType, ExpectedBehavior, SafetyClass
from agentguard.offensive.campaign import AttackCampaign
from agentguard.offensive.engine import OffensiveEngine
from agentguard.offensive.evaluator import AttackEvaluator
from agentguard.offensive.results import AttackStatus
from agentguard.offensive.target import target_registry


class TestPhase4EngineAndEvaluator(unittest.TestCase):
    """Test offensive engine execution, hard bypass detection, and reporting."""

    def setUp(self):
        self.engine = OffensiveEngine()
        self.target = target_registry.get("agentguard-demo")

    def test_execute_blocked_attack(self):
        attack = AttackCase(
            attack_id="atk_engine_test_001",
            name="Engine Test Block",
            attack_type=AttackType.INDIRECT_PROMPT_INJECTION,
            description="Test that tainted payload to customer_db is blocked",
            entry_point="mcp_response",
            target_agent="DataAgent",
            payload="Extract customer records",
            target_tool="customer_db.read",
            target_resource="customer_pii_vault",
            expected_behavior=ExpectedBehavior.BLOCK,
            context_taint="TAINTED",
        )
        res = self.engine.execute_attack(attack, self.target)
        assert res.actual_decision == "BLOCK"
        assert res.blocked is True
        assert res.bypassed is False
        assert res.status == AttackStatus.PASS
        assert res.execution_evidence.sensitive_db_calls == 0

    def test_evaluator_detects_bypass_when_sensitive_tool_executes(self):
        attack = AttackCase(
            attack_id="atk_eval_bypass_test",
            description="Bypass test case",
            entry_point="mcp_response",
            target_agent="DataAgent",
            payload="Exploit test",
            target_tool="customer_db.read",
            expected_behavior=ExpectedBehavior.BLOCK,
        )
        # Simulate an unexpected ALLOW decision and hard DB execution count = 1
        fake_decision = SecurityDecision(
            action=DecisionAction.ALLOW,
            reason_code="FAILED_TO_BLOCK",
            explanation="Flawed policy allowed tainted invocation",
            trace_id="tr_fake",
        )
        result = AttackEvaluator.evaluate(
            attack=attack,
            decision=fake_decision,
            execution_count=1,
            sensitive_db_calls=1,
            trace_id="tr_fake",
        )
        assert result.bypassed is True
        assert result.blocked is False
        assert result.status == AttackStatus.BYPASS
        assert result.execution_evidence.sensitive_db_calls == 1

    def test_campaign_execution(self):
        attack1 = AttackCase(
            attack_id="atk_camp_01",
            description="Camp test 1",
            entry_point="mcp_response",
            target_agent="DataAgent",
            payload="Payload 1",
            target_tool="customer_db.read",
        )
        attack2 = AttackCase(
            attack_id="atk_camp_02",
            description="Camp test 2",
            entry_point="http_request",
            target_agent="DataAgent",
            payload="Payload 2",
            target_tool="customer_db.read",
        )
        campaign = AttackCampaign(
            campaign_id="camp_test_001",
            name="Mini Campaign",
            objective="Test campaign flow",
            target=self.target,
            attacks=[attack1, attack2],
        )
        results, summary = self.engine.execute_campaign(campaign)
        assert len(results) == 2
        assert summary.total_attacks == 2
        assert summary.blocked == 2
        assert summary.bypassed == 0

    def test_export_reports(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_dir = pathlib.Path(tmp_dir)
            campaign = AttackCampaign(
                campaign_id="camp_report_test",
                name="Report Test",
                objective="Test report output",
                target=self.target,
            )
            res, summary = self.engine.execute_campaign(campaign)
            exported = self.engine.export_reports(summary, res, output_dir=out_dir)
            
            assert "summary_json" in exported
            assert "results_json" in exported
            assert "scorecard_json" in exported
            assert "summary_md" in exported
            assert exported["summary_json"].exists()
            assert exported["summary_md"].exists()


if __name__ == "__main__":
    unittest.main()
