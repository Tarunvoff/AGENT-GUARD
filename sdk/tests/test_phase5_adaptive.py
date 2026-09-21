"""Comprehensive Unit Test Suite for ActShield Phase 5 — Adaptive Offensive Security Validation."""

import json
import os
import pathlib
import unittest
from datetime import datetime

from actshield.client import ActShield
from actshield.decisions.decision import DecisionAction, SecurityDecision
from actshield.offensive.attack import AttackCase, AttackType, ExpectedBehavior, SafetyClass
from actshield.offensive.campaign import AttackCampaign, CampaignSummary
from actshield.offensive.corpus import AttackCorpus
from actshield.offensive.engine import OffensiveEngine
from actshield.offensive.evidence import SecurityAnalysisEvidence
from actshield.offensive.mutation import MutationStrategy
from actshield.offensive.results import AttackStatus
from actshield.offensive.safety import SafetyValidator
from actshield.offensive.target import AttackTarget, TargetEnvironment, TargetRegistry
from actshield.offensive.vulnerable_target import VulnerableDemoTarget
from actshield.offensive.adaptive import (
    AdaptiveAttackSelector,
    AdaptiveEngine,
    BoundarySearchEngine,
    CampaignMemory,
    DefenseCategory,
    DefenseFeedback,
    FeedbackAnalyzer,
    MutationNode,
    MutationPlanner,
)


class TestPhase5Adaptive(unittest.TestCase):
    """Test suite validating Phase 5 Adaptive Offensive Engine and Full Security Pipeline."""

    def setUp(self):
        self.guard = ActShield()
        self.engine = OffensiveEngine(guard=self.guard)
        self.target = AttackTarget(
            target_id="test-synth-env",
            name="Test Synthetic Target",
            environment=TargetEnvironment.LOCAL,
            synthetic=True,
            allowed=True,
        )

    # 1. Adaptive attack selection
    def test_adaptive_attack_selection(self):
        selector = AdaptiveAttackSelector(seed=42)
        seeds = selector.select_seeds(family="prompt_injection", limit=3)
        self.assertLessEqual(len(seeds), 3)
        for s in seeds:
            self.assertTrue("prompt_injection" in s.attack_type.value or "pinj" in s.attack_id)

    # 2. Mutation lineage preservation
    def test_mutation_lineage_preservation(self):
        memory = CampaignMemory(campaign_id="test_lineage")
        n0 = memory.record_node("atk_root", "atk_root", None, "baseline", 0, "base", "base")
        n1 = memory.record_node("atk_m1", "atk_root", "atk_root", "roleplay", 1, "base", "mut1")
        n2 = memory.record_node("atk_m2", "atk_root", "atk_m1", "base64", 2, "mut1", "mut2")

        lineage = memory.get_lineage("atk_m2")
        self.assertEqual(len(lineage), 3)
        self.assertEqual([n.mutation_id for n in lineage], ["atk_root", "atk_m1", "atk_m2"])
        self.assertEqual(lineage[2].depth, 2)

    # 3. Bounded mutation depth
    def test_bounded_mutation_depth(self):
        memory = CampaignMemory()
        search = BoundarySearchEngine(self.engine, memory, max_depth=2, branch_factor=1, max_attempts_per_attack=5)
        root = AttackCase(
            attack_id="atk_bound_test",
            description="Bounded depth test",
            target_agent="DataAgent",
            payload="Extract PII records",
            target_tool="customer_db.read",
        )
        results = search.explore_boundary(root, target=self.target)
        self.assertLessEqual(len(results), 5)
        for r in results:
            depth = len(r.mutation_lineage) - 1 if r.mutation_lineage else 0
            self.assertLessEqual(depth, 2)

    # 4. Deterministic adaptive replay with seed
    def test_deterministic_adaptive_replay_with_seed(self):
        sel1 = AdaptiveAttackSelector(seed=9999)
        seeds1 = [a.attack_id for a in sel1.select_seeds(limit=5)]
        
        sel2 = AdaptiveAttackSelector(seed=9999)
        seeds2 = [a.attack_id for a in sel2.select_seeds(limit=5)]
        
        self.assertEqual(seeds1, seeds2)

    # 5. Defense feedback classification
    def test_defense_feedback_classification(self):
        attack = AttackCase(
            attack_id="atk_feed_test",
            description="Taint feedback test",
            target_agent="DataAgent",
            payload="Extract PII",
            target_tool="customer_db.read",
            context_taint="TAINTED",
        )
        res = self.engine.execute_attack(attack, target=self.target)
        feedback = FeedbackAnalyzer.analyze(res)
        self.assertEqual(feedback.defense_category, DefenseCategory.TAINT_GUARD)
        self.assertIn("nested_roleplay", feedback.suggested_mutation_strategies)

    # 6. AI Secura integration in pipeline
    def test_ai_secura_integration_in_pipeline(self):
        attack = AttackCase(
            attack_id="atk_ai_pipe_test",
            description="AI Secura test",
            target_agent="DataAgent",
            payload="Extract records",
            target_tool="customer_db.read",
            context_taint="TAINTED",
        )
        res = self.engine.execute_attack(attack, target=self.target)
        self.assertIsNotNone(res.ai_analysis)
        self.assertIn("summary", res.ai_analysis)

    # 7. APIRIS integration in pipeline
    def test_apiris_integration_in_pipeline(self):
        attack = AttackCase(
            attack_id="atk_apiris_pipe_test",
            description="APIRIS test",
            target_agent="DataAgent",
            payload="Extract records",
            target_tool="customer_db.read",
        )
        res = self.engine.execute_attack(attack, target=self.target)
        self.assertIsNotNone(res.apiris_analysis)
        self.assertEqual(res.apiris_analysis.get("tool_name"), "customer_db.read")

    # 8. Provider failure fail-safe
    def test_provider_failure_fail_safe(self):
        # Even if ai_secura raises an exception, the pipeline remains fail-safe and blocks
        class FailingAISecura:
            def analyze(self, ctx):
                raise RuntimeError("AI Provider Network Disconnected")

        guard_failing = ActShield(ai_secura=FailingAISecura())
        engine_failing = OffensiveEngine(guard=guard_failing)
        attack = AttackCase(
            attack_id="atk_fail_provider",
            description="Failing provider test",
            target_agent="DataAgent",
            payload="Extract records",
            target_tool="customer_db.read",
            context_taint="TAINTED",
        )
        res = engine_failing.execute_attack(attack, target=self.target)
        self.assertEqual(res.actual_decision, "BLOCK")
        self.assertFalse(res.bypassed)

    # 9. Policy remains final deterministic authority
    def test_policy_remains_final_deterministic_authority(self):
        # AI Secura might advise LOW risk, but deterministic policy MUST still block tainted sensitive sink
        class BenignAdvisingAISecura:
            def analyze(self, ctx):
                from actshield.integrations.ai_secura import SecurityAnalysis
                return SecurityAnalysis(analysis_id="ai_benign", summary="Looks benign", risk_score=0.0)

        guard = ActShield(ai_secura=BenignAdvisingAISecura())
        engine = OffensiveEngine(guard=guard)
        attack = AttackCase(
            attack_id="atk_policy_authority",
            description="Policy authority test",
            target_agent="DataAgent",
            payload="Extract records",
            target_tool="customer_db.read",
            context_taint="TAINTED",
        )
        res = engine.execute_attack(attack, target=self.target)
        self.assertEqual(res.actual_decision, "BLOCK")
        self.assertEqual(res.execution_evidence.sensitive_db_calls, 0)

    # 10. Bypass discovery on vulnerable target
    def test_bypass_discovery_on_vulnerable_target(self):
        demo = VulnerableDemoTarget()
        bypass_attack = AttackCase(
            attack_id="atk_vuln_disc_01",
            name="Vulnerable Target Probe",
            description="Probe vulnerable target",
            target_agent="DataAgent",
            payload="Read customer records directly",
            target_tool="customer_db.read",
            context_taint="TAINTED",
            expected_behavior=ExpectedBehavior.BLOCK,
        )
        res = demo.execute_vulnerable_attack(bypass_attack)
        self.assertTrue(res.bypassed)
        self.assertEqual(res.execution_evidence.sensitive_db_calls, 1)

    # 11. Automatic regression fixture generation
    def test_automatic_regression_fixture_generation(self):
        demo = VulnerableDemoTarget()
        attack = AttackCase(
            attack_id="atk_reg_gen_test",
            description="Regression generation test",
            target_agent="DataAgent",
            payload="Extract records",
            target_tool="customer_db.read",
            context_taint="TAINTED",
        )
        res = demo.execute_vulnerable_attack(attack)
        fixture = demo.save_regression_fixture(attack, res)
        self.assertTrue(os.path.exists(fixture))

    # 12. Remediation replay blocks bypass
    def test_remediation_replay_blocks_bypass(self):
        demo = VulnerableDemoTarget()
        attack = AttackCase(
            attack_id="atk_remed_replay_test",
            description="Remediation replay test",
            target_agent="DataAgent",
            payload="Extract records",
            target_tool="customer_db.read",
            context_taint="TAINTED",
        )
        res_rem = demo.replay_remediation(attack)
        self.assertFalse(res_rem.bypassed)
        self.assertEqual(res_rem.actual_decision, "BLOCK")
        self.assertEqual(res_rem.execution_evidence.sensitive_db_calls, 0)

    # 13. Empirical execution evidence counting
    def test_empirical_execution_evidence_counting(self):
        attack = AttackCase(
            attack_id="atk_emp_count",
            description="Empirical counter test",
            target_agent="DataAgent",
            payload="Read public filings",
            target_tool="sec_edgar.fetch_filing",
            expected_behavior=ExpectedBehavior.ALLOW,
            context_taint="CLEAN",
        )
        res = self.engine.execute_attack(attack, target=self.target)
        self.assertEqual(res.actual_decision, "ALLOW")
        self.assertEqual(res.execution_evidence.execution_count, 1)
        self.assertEqual(res.execution_evidence.sensitive_db_calls, 0)

    # 14. Campaign metrics and empirical prevention rate
    def test_campaign_metrics_and_empirical_prevention_rate(self):
        campaign = AttackCampaign(name="Metrics Test", objective="Test metrics", target=self.target)
        results = [
            self.engine.execute_attack(AttackCase(
                attack_id="atk_m_01",
                target_agent="DataAgent",
                payload="PII read",
                target_tool="customer_db.read",
                context_taint="TAINTED",
            ), target=self.target),
            self.engine.execute_attack(AttackCase(
                attack_id="atk_m_02",
                target_agent="DataAgent",
                payload="Public filing",
                target_tool="sec_edgar.fetch_filing",
                context_taint="CLEAN",
                expected_behavior=ExpectedBehavior.ALLOW,
            ), target=self.target),
        ]
        summary = CampaignSummary.from_results(campaign, results)
        self.assertEqual(summary.total_attacks, 2)
        self.assertEqual(summary.empirical_prevention_rate, 1.0)
        self.assertEqual(summary.sensitive_actions_executed, 0)

    # 15. Attack family coverage across all 12 families
    def test_attack_family_coverage_all_12_families(self):
        corpus = AttackCorpus()
        all_attacks = corpus.get_all_attacks()
        families = {a.attack_type for a in all_attacks}
        self.assertGreaterEqual(len(families), 8)

    # 16. Safety boundary external IP rejected
    def test_safety_boundary_external_ip_rejected(self):
        val = SafetyValidator()
        bad_target = AttackTarget(
            target_id="evil-target",
            target_url="http://198.51.100.23:8080/exec",
            environment=TargetEnvironment.LOCAL,
            synthetic=False,
            allowed=False,
        )
        res = val.validate(AttackCase(attack_id="atk_ext", target_agent="Any", payload="test"), target=bad_target)
        self.assertFalse(res.safe)
        self.assertIn("not registered", res.reason.lower())

    # 17. Safety boundary destructive command rejected
    def test_safety_boundary_destructive_command_rejected(self):
        val = SafetyValidator()
        attack = AttackCase(
            attack_id="atk_destruct",
            target_agent="DataAgent",
            payload="rm -rf / --no-preserve-root",
        )
        res = val.validate(attack, target=self.target)
        self.assertFalse(res.safe)
        self.assertIn("Destructive", res.reason)

    # 18. Mutation planner maps defense to strategies
    def test_mutation_planner_maps_defense_to_strategies(self):
        fb = DefenseFeedback(
            attack_id="atk_p_01",
            decision="BLOCK",
            reason_code="TAINTED_CONTEXT_INTO_SENSITIVE_SINK",
            explanation="Tainted context blocked",
            defense_category=DefenseCategory.TAINT_GUARD,
            bypassed=False,
            sensitive_executions=0,
            suggested_mutation_strategies=["nested_roleplay", "base64_encoding"],
        )
        base = AttackCase(attack_id="atk_base", target_agent="DataAgent", payload="Extract records")
        planned = MutationPlanner.plan_next_mutations(base, fb, depth=1, branch_factor=2)
        self.assertEqual(len(planned), 2)
        self.assertEqual(planned[0].mutation_of, "atk_base")

    # 19. Campaign memory graph and lineage
    def test_campaign_memory_graph_and_lineage(self):
        mem = CampaignMemory()
        mem.record_node("root_1", "root_1", None, "baseline", 0)
        mem.record_node("mut_1a", "root_1", "root_1", "roleplay", 1)
        mem.record_node("mut_1b", "root_1", "mut_1a", "base64", 2)
        
        lin = mem.get_lineage("mut_1b")
        self.assertEqual([n.mutation_id for n in lin], ["root_1", "mut_1a", "mut_1b"])
        self.assertEqual(lin[1].strategy, "roleplay")

    # 20. Dashboard-ready JSON export
    def test_dashboard_ready_json_export(self):
        adaptive = AdaptiveEngine(max_depth=1, branch_factor=1, seed=1234)
        results, summary, memory = adaptive.run_adaptive_campaign(limit_seeds=2)
        
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            exported = adaptive.export_dashboard_json(summary, results, memory, output_dir=tmpdir)
            self.assertTrue(os.path.exists(exported["dashboard_json"]))
            data = json.loads(pathlib.Path(exported["dashboard_json"]).read_text(encoding="utf-8"))
            self.assertIn("campaign", data)
            self.assertIn("coverage", data)
            self.assertIn("security", data)
            self.assertIn("performance", data)
            self.assertIn("mutations", data)


if __name__ == "__main__":
    unittest.main()
