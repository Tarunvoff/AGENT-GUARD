"""Posture calculation rules and scoring logic for ActShield Phase 9.

Computes explainable, deterministic security posture score based on concrete evidence.
Formula:
- Starts at 100.0 (Perfect prevention & alignment)
- Deductions are derived strictly from evidence (e.g. actual executions, open regressions, authority violations)
- Zero arbitrary ML weights.
"""

from __future__ import annotations

from typing import List, Tuple
from actshield.posture.posture_models import (
    FindingSeverity,
    PostureDimensionMetrics,
    PostureFinding,
    PostureRating,
)


class PostureRuleEvaluator:
    """Evaluates metrics to produce explainable posture score, rating, and discrete findings."""

    @staticmethod
    def evaluate(metrics: PostureDimensionMetrics) -> Tuple[float, PostureRating, List[PostureFinding]]:
        score = 100.0
        findings: List[PostureFinding] = []

        # 1. Critical invariant: Actual unauthorized execution
        if metrics.actual_unauthorized_executions > 0:
            deduction = min(50.0, metrics.actual_unauthorized_executions * 25.0)
            score -= deduction
            findings.append(PostureFinding(
                category="unauthorized_execution",
                severity=FindingSeverity.CRITICAL,
                title=f"{metrics.actual_unauthorized_executions} Actual Unauthorized Execution(s) Detected",
                description="Policy boundary was bypassed and a sensitive operation executed.",
                remediation_advice="Review vulnerable tools, revoke affected agent credentials, and deploy regression fix immediately.",
            ))

        # 2. Failed secured replays (Unresolved bypasses)
        if metrics.failed_secured_replays > 0:
            deduction = min(30.0, metrics.failed_secured_replays * 15.0)
            score -= deduction
            findings.append(PostureFinding(
                category="failed_secured_replay",
                severity=FindingSeverity.HIGH,
                title=f"{metrics.failed_secured_replays} Failed Secured Replay(s)",
                description="Known attack regression failed to block when replayed against secured policy.",
                remediation_advice="Harden deterministic policy rules for the failing attack scenario.",
            ))

        # 3. Open regressions
        if metrics.open_regressions > 0:
            deduction = min(20.0, metrics.open_regressions * 5.0)
            score -= deduction
            findings.append(PostureFinding(
                category="open_regression",
                severity=FindingSeverity.HIGH,
                title=f"{metrics.open_regressions} Open Security Regression(s)",
                description="Security test cases flagged as open without verified remediation.",
                remediation_advice="Run regression replay suite and verify all fixtures pass with BLOCK.",
            ))

        # 4. Tainted sensitive requests
        if metrics.tainted_sensitive_requests > 0:
            deduction = min(15.0, metrics.tainted_sensitive_requests * 2.0)
            score -= deduction
            findings.append(PostureFinding(
                category="taint_exposure",
                severity=FindingSeverity.MEDIUM,
                title=f"{metrics.tainted_sensitive_requests} Tainted Context Request(s) to Sensitive Sinks",
                description="Agents attempted to pass untrusted/tainted context to sensitive resources.",
                remediation_advice="Inspect context provenance chains and verify input sanitization boundaries.",
            ))

        # 5. Authority violations
        if metrics.authority_violations > 0:
            deduction = min(15.0, metrics.authority_violations * 2.0)
            score -= deduction
            findings.append(PostureFinding(
                category="authority_violation",
                severity=FindingSeverity.MEDIUM,
                title=f"{metrics.authority_violations} Delegated Authority Violation(s)",
                description="Sub-agents attempted actions exceeding granted capability envelopes.",
                remediation_advice="Enforce stricter delegation scopes and depth limits at task handoff.",
            ))

        # 6. Intent drift / violations
        if metrics.intent_violations > 0:
            deduction = min(10.0, metrics.intent_violations * 2.0)
            score -= deduction
            findings.append(PostureFinding(
                category="intent_violation",
                severity=FindingSeverity.MEDIUM,
                title=f"{metrics.intent_violations} Task Intent Violation(s)",
                description="Actions drifted from declared task intent as analyzed by AI Secura.",
                remediation_advice="Review task definitions and prompt instructions.",
            ))

        # 7. Availability degradation
        if metrics.ai_secura_availability_pct < 95.0:
            score -= 5.0
            findings.append(PostureFinding(
                category="availability_degraded",
                severity=FindingSeverity.LOW,
                title=f"AI Secura Availability Low ({metrics.ai_secura_availability_pct:.1f}%)",
                description="AI Secura reasoning service experienced downtime. Deterministic fallback active.",
                remediation_advice="Check LLM endpoint health and adapter timeouts.",
            ))

        if metrics.policy_engine_availability_pct < 100.0:
            score -= 15.0
            findings.append(PostureFinding(
                category="availability_critical",
                severity=FindingSeverity.HIGH,
                title="Policy Engine Experienced Interruptions",
                description="Deterministic policy engine health is below 100%.",
                remediation_advice="Inspect policy engine logs and persistence locks.",
            ))

        # Clamp score between 0.0 and 100.0
        final_score = max(0.0, min(100.0, round(score, 1)))

        # Determine rating
        if final_score >= 90.0:
            rating = PostureRating.HEALTHY
        elif final_score >= 75.0:
            rating = PostureRating.ELEVATED_RISK
        elif final_score >= 50.0:
            rating = PostureRating.DEGRADED
        else:
            rating = PostureRating.CRITICAL

        return final_score, rating, findings


