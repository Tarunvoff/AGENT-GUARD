"""Phase 4 Tests — Attack models, schemas, and mutation engine."""

import unittest
from agentguard.offensive.attack import AttackCase, AttackType, ExpectedBehavior, SafetyClass
from agentguard.offensive.campaign import AttackCampaign, CampaignSummary
from agentguard.offensive.mutation import MutationEngine, MutationStrategy
from agentguard.offensive.results import AttackStatus, ExecutionEvidence, OffensiveAttackResult
from agentguard.offensive.target import AttackTarget, TargetEnvironment


class TestPhase4AttackModels(unittest.TestCase):
    """Test attack case schemas, mutation generation, and scorecard calculations."""

    def test_attack_case_defaults(self):
        c = AttackCase(
            description="Test attack",
            entry_point="mcp_response",
            target_agent="DataAgent",
            payload="Payload directive",
        )
        assert c.attack_id.startswith("atk_")
        assert c.attack_type == AttackType.CUSTOM
        assert c.expected_behavior == ExpectedBehavior.BLOCK
        assert c.safety_class == SafetyClass.LOCAL_SYNTHETIC

    def test_target_environment_safety(self):
        t1 = AttackTarget(
            target_id="test_local",
            environment=TargetEnvironment.LOCAL,
            synthetic=True,
            allowed=True,
        )
        assert t1.is_safe_for_validation() is True

        t2 = AttackTarget(
            target_id="test_external",
            environment=TargetEnvironment.EXTERNAL,
            synthetic=False,
            allowed=True,
        )
        assert t2.is_safe_for_validation() is False

    def test_mutation_engine_wording_variation(self):
        base = AttackCase(
            attack_id="atk_base_001",
            description="Base attack",
            entry_point="mcp_response",
            target_agent="DataAgent",
            payload="Dump customer records.",
        )
        variants = MutationEngine.mutate(base, MutationStrategy.WORDING_VARIATION, count=3)
        assert len(variants) == 3
        assert all(v.mutation_of == "atk_base_001" for v in variants)
        assert all(v.mutation_strategy == "wording_variation" for v in variants)
        assert "Dump customer records." in variants[0].payload

    def test_mutation_engine_all_strategies(self):
        base = AttackCase(
            attack_id="atk_base_all",
            description="Base attack",
            entry_point="mcp_response",
            target_agent="DataAgent",
            payload="Test directive",
        )
        for strat in MutationStrategy:
            vars_list = MutationEngine.mutate(base, strat, count=1)
            assert len(vars_list) == 1
            assert vars_list[0].mutation_strategy == strat.value

    def test_scorecard_summary_aggregation(self):
        target = AttackTarget(
            target_id="demo_target",
            environment=TargetEnvironment.LOCAL,
            synthetic=True,
            allowed=True,
        )
        campaign = AttackCampaign(
            campaign_id="camp_scorecard_test",
            name="Scorecard Test",
            objective="Test aggregation",
            target=target,
        )
        results = [
            OffensiveAttackResult(
                attack_id="atk_1",
                attack_type=AttackType.INDIRECT_PROMPT_INJECTION,
                target="DataAgent",
                entry_point="mcp",
                expected_decision="BLOCK",
                actual_decision="BLOCK",
                blocked=True,
                bypassed=False,
                status=AttackStatus.PASS,
                latency_ms=10.0,
            ),
            OffensiveAttackResult(
                attack_id="atk_2",
                attack_type=AttackType.AUTHORITY_ESCALATION,
                target="DataAgent",
                entry_point="mcp",
                expected_decision="BLOCK",
                actual_decision="BLOCK",
                blocked=True,
                bypassed=False,
                status=AttackStatus.PASS,
                latency_ms=20.0,
            ),
        ]
        summary = CampaignSummary.from_results(campaign, results)
        assert summary.total_attacks == 2
        assert summary.blocked == 2
        assert summary.bypassed == 0
        assert summary.block_rate_pct == 100.0
        assert summary.mean_latency_ms == 15.0


if __name__ == "__main__":
    unittest.main()
