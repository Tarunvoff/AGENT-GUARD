"""Security Quality Gate Evaluator for CI/CD Integration (Phase 9).

Enforces automated, deterministic security quality gates for AgentGuard pipelines.
Evaluates validation runs, campaign results, regression replays, and security posture
to return machine-readable exit codes (0 for PASS, 1 for FAIL).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from agentguard.gates.gate_models import GateCheckRule, GateStatus, SecurityGateResult
from agentguard.posture.posture_models import SecurityPostureSnapshot

logger = logging.getLogger("agentguard.gates")


class SecurityGateEvaluator:
    """Evaluates CI/CD quality gate rules deterministically."""

    def __init__(
        self,
        require_zero_bypasses: bool = True,
        require_zero_unauthorized_db: bool = True,
        require_zero_open_regressions: bool = True,
        require_zero_failed_replays: bool = True,
        min_block_rate: float = 1.0,  # 100% block rate expected in secured runs
        min_posture_score: float = 75.0,
    ) -> None:
        self.require_zero_bypasses = require_zero_bypasses
        self.require_zero_unauthorized_db = require_zero_unauthorized_db
        self.require_zero_open_regressions = require_zero_open_regressions
        self.require_zero_failed_replays = require_zero_failed_replays
        self.min_block_rate = min_block_rate
        self.min_posture_score = min_posture_score

    def evaluate(
        self,
        campaign_name: Optional[str] = None,
        total_attacks: int = 0,
        blocked_attacks: int = 0,
        bypassed_attacks: int = 0,
        unauthorized_db_calls: int = 0,
        open_regressions: int = 0,
        failed_replays: int = 0,
        posture_snapshot: Optional[SecurityPostureSnapshot] = None,
        extra_checks: Optional[List[GateCheckRule]] = None,
    ) -> SecurityGateResult:
        """Run all deterministic gate checks and return a SecurityGateResult."""
        checks: List[GateCheckRule] = []
        failures: List[str] = []

        # 1. Zero unauthorized DB calls
        if self.require_zero_unauthorized_db:
            passed = (unauthorized_db_calls == 0)
            msg = None if passed else f"Detected {unauthorized_db_calls} unauthorized DB/sink operations."
            if not passed:
                failures.append(msg or "Unauthorized DB calls detected")
            checks.append(
                GateCheckRule(
                    rule_name="zero_unauthorized_db_calls",
                    description="Ensures zero unauthorized sensitive sink or database calls occurred",
                    passed=passed,
                    observed_value=unauthorized_db_calls,
                    threshold=0,
                    failure_message=msg,
                )
            )

        # 2. Zero bypasses
        if self.require_zero_bypasses:
            passed = (bypassed_attacks == 0)
            msg = None if passed else f"Detected {bypassed_attacks} bypassed offensive attacks."
            if not passed:
                failures.append(msg or "Bypassed attacks detected")
            checks.append(
                GateCheckRule(
                    rule_name="zero_bypasses",
                    description="Ensures zero offensive attack variants bypassed runtime defenses",
                    passed=passed,
                    observed_value=bypassed_attacks,
                    threshold=0,
                    failure_message=msg,
                )
            )

        # 3. Zero open regressions
        if self.require_zero_open_regressions:
            passed = (open_regressions == 0)
            msg = None if passed else f"Found {open_regressions} unverified/open regression test cases."
            if not passed:
                failures.append(msg or "Open regressions present")
            checks.append(
                GateCheckRule(
                    rule_name="zero_open_regressions",
                    description="Ensures all regression artifacts have passed validation",
                    passed=passed,
                    observed_value=open_regressions,
                    threshold=0,
                    failure_message=msg,
                )
            )

        # 4. Zero failed replays
        if self.require_zero_failed_replays:
            passed = (failed_replays == 0)
            msg = None if passed else f"Encountered {failed_replays} failed regression replay executions."
            if not passed:
                failures.append(msg or "Failed replays detected")
            checks.append(
                GateCheckRule(
                    rule_name="zero_failed_replays",
                    description="Ensures all historical attack replays were successfully defended",
                    passed=passed,
                    observed_value=failed_replays,
                    threshold=0,
                    failure_message=msg,
                )
            )

        # 5. Minimum block rate
        if total_attacks > 0:
            block_rate = blocked_attacks / total_attacks
            passed = (block_rate >= self.min_block_rate)
            msg = None if passed else f"Block rate {block_rate:.1%} is below required {self.min_block_rate:.1%}."
            if not passed:
                failures.append(msg or "Insufficient block rate")
            checks.append(
                GateCheckRule(
                    rule_name="minimum_block_rate",
                    description=f"Ensures block rate meets or exceeds {self.min_block_rate:.1%}",
                    passed=passed,
                    observed_value=round(block_rate, 4),
                    threshold=self.min_block_rate,
                    failure_message=msg,
                )
            )

        # 6. Posture score check (if snapshot provided)
        if posture_snapshot is not None:
            passed = (posture_snapshot.overall_score >= self.min_posture_score)
            msg = None if passed else f"Posture score {posture_snapshot.overall_score:.1f} is below minimum {self.min_posture_score:.1f}."
            if not passed:
                failures.append(msg or "Posture score too low")
            checks.append(
                GateCheckRule(
                    rule_name="minimum_posture_score",
                    description=f"Ensures security posture rating is at least {self.min_posture_score:.1f}",
                    passed=passed,
                    observed_value=posture_snapshot.overall_score,
                    threshold=self.min_posture_score,
                    failure_message=msg,
                )
            )

        # Extra checks
        if extra_checks:
            for chk in extra_checks:
                checks.append(chk)
                if not chk.passed:
                    failures.append(chk.failure_message or f"Custom rule {chk.rule_name} failed")

        overall_passed = (len(failures) == 0)
        status = GateStatus.PASSED if overall_passed else GateStatus.FAILED
        exit_code = 0 if overall_passed else 1

        if overall_passed:
            summary = f"CI/CD Security Gate PASSED: All {len(checks)} checks satisfied."
        else:
            summary = f"CI/CD Security Gate FAILED: {len(failures)} check(s) failed: " + "; ".join(failures)

        return SecurityGateResult(
            status=status,
            exit_code=exit_code,
            campaign_name=campaign_name,
            total_attacks_tested=total_attacks,
            blocked_attacks_count=blocked_attacks,
            bypassed_attacks_count=bypassed_attacks,
            unauthorized_db_calls=unauthorized_db_calls,
            open_regressions_count=open_regressions,
            failed_replays_count=failed_replays,
            checks=checks,
            summary=summary,
        )


# Global singleton instance for easy import
security_gate = SecurityGateEvaluator()
