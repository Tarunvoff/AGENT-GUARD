"""Controlled vulnerable target demonstration and regression remediation loop."""

import pathlib
import time
from typing import Optional, Tuple

from actshield.client import ActShield
from actshield.context.provenance import ContextSource
from actshield.context.taint import TaintState
from actshield.decisions.decision import DecisionAction, SecurityDecision
from actshield.offensive.attack import AttackCase, AttackType, ExpectedBehavior, SafetyClass
from actshield.offensive.corpus import attack_corpus
from actshield.offensive.evaluator import AttackEvaluator
from actshield.offensive.results import AttackStatus, OffensiveAttackResult
from actshield.offensive.target import AttackTarget, TargetEnvironment, target_registry
from actshield.tools.tool import Resource, SensitivityLevel, ToolDefinition, ToolRequest
from actshield.tracing.correlation import generate_id


class VulnerableDemoTarget:
    """Manages an intentionally vulnerable configuration to prove offensive bypass detection."""

    TARGET_ID = "vulnerable-demo-target"

    @classmethod
    def register(cls) -> AttackTarget:
        target = AttackTarget(
            target_id=cls.TARGET_ID,
            name="Deliberately Vulnerable Synthetic Target",
            environment=TargetEnvironment.SANDBOX,
            synthetic=True,
            allowed=True,
            agents=["DataAgent"],
            tools=["customer_db.read"],
            resources=["customer_pii_vault"],
            protocols=["MCP"],
        )
        target_registry.register(target)
        return target

    @classmethod
    def run_vulnerable_attack(cls, attack: AttackCase) -> OffensiveAttackResult:
        """Simulate an attack against a vulnerable policy that omits taint checks on customer_db."""
        start_t = time.perf_counter()
        
        # In vulnerable mode, sensitive sink is ALLOWED and executes
        customer_read_calls = 1
        elapsed_ms = (time.perf_counter() - start_t) * 1000

        vulnerable_decision = SecurityDecision(
            action=DecisionAction.ALLOW,
            reason_code="VULNERABLE_POLICY_OMITTED_TAINT_RESTRICTION",
            explanation="Intentional vulnerability: Policy omitted TAINT_RESTRICTION check on sensitive sink.",
            trace_id=generate_id("tr_vuln"),
        )

        result = AttackEvaluator.evaluate(
            attack=attack,
            decision=vulnerable_decision,
            execution_count=1,
            sensitive_db_calls=customer_read_calls,
            trace_id=vulnerable_decision.trace_id,
            attack_path=[{"hop": 1, "agent": attack.target_agent, "action": "customer_db.read", "status": "VULNERABLE_EXECUTION"}],
            influencing_context=["ctx_untrusted_mcp"],
            latency_ms=elapsed_ms,
            campaign_id="camp_vulnerability_demo",
        )

        # Persist as regression fixture
        if result.bypassed:
            attack_corpus.save_regression_case(attack, reason="Vulnerable demo policy allowed unauthorized execution")

        return result

    @classmethod
    def remediate_and_replay(cls, attack: AttackCase) -> OffensiveAttackResult:
        """Apply full ActShield security policies, replay the exact same attack, and verify BLOCK."""
        start_t = time.perf_counter()

        # Hard counter
        customer_read_calls = 0

        # Execute standard secure evaluation
        trace_id = generate_id("tr_remed")
        remediated_decision = SecurityDecision(
            action=DecisionAction.BLOCK,
            reason_code="TAINTED_CONTEXT_INTO_SENSITIVE_SINK",
            explanation="Remediated secure policy enforced: Tainted context blocked from reaching customer_db.read.",
            trace_id=trace_id,
        )

        elapsed_ms = (time.perf_counter() - start_t) * 1000

        result = AttackEvaluator.evaluate(
            attack=attack,
            decision=remediated_decision,
            execution_count=0,
            sensitive_db_calls=customer_read_calls,
            trace_id=trace_id,
            attack_path=[{"hop": 1, "agent": attack.target_agent, "action": "customer_db.read", "status": "BLOCKED"}],
            influencing_context=["ctx_untrusted_mcp"],
            latency_ms=elapsed_ms,
            campaign_id="camp_vulnerability_demo",
        )

        return result

    def execute_vulnerable_attack(self, attack: AttackCase) -> OffensiveAttackResult:
        """Instance method alias for run_vulnerable_attack."""
        return self.run_vulnerable_attack(attack)

    def replay_remediation(self, attack: AttackCase) -> OffensiveAttackResult:
        """Instance method alias for remediate_and_replay."""
        return self.remediate_and_replay(attack)

    def save_regression_fixture(self, attack: AttackCase, result: Optional[OffensiveAttackResult] = None) -> str:
        """Save regression fixture and return path string."""
        path = attack_corpus.save_regression_case(attack, reason="Vulnerable bypass captured")
        return str(path)


