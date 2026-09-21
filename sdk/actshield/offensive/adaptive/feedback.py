"""Defensive feedback analyzer for adaptive offensive exploration."""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from actshield.offensive.results import AttackStatus, OffensiveAttackResult


class DefenseCategory(str, Enum):
    """Categorization of defensive enforcement mechanisms."""
    TAINT_GUARD = "TAINT_GUARD"                     # Blocked because tainted context reached a sensitive sink
    AUTHORITY_GUARD = "AUTHORITY_GUARD"             # Blocked due to missing capability or exceeded delegation
    INTENT_GUARD = "INTENT_GUARD"                   # Blocked due to divergence from task original intent
    TRUST_GUARD = "TRUST_GUARD"                     # Blocked because agent trust level is UNTRUSTED
    BENIGN_ALLOW = "BENIGN_ALLOW"                   # Allowed under standard policy
    UNKNOWN_DEFENSE = "UNKNOWN_DEFENSE"             # Other or unclassified


class DefenseFeedback(BaseModel):
    """Structured analytical feedback derived from previous defense response."""

    attack_id: str
    decision: str
    reason_code: str
    explanation: str
    defense_category: DefenseCategory
    bypassed: bool
    sensitive_executions: int
    
    # Adaptive guidance
    suggested_mutation_strategies: List[str] = Field(default_factory=list)
    boundary_distance_estimate: float = Field(default=1.0, description="1.0 = deeply blocked, 0.0 = bypassed")


class FeedbackAnalyzer:
    """Analyzes offensive attack results to guide subsequent mutation planning."""

    @staticmethod
    def analyze(result: OffensiveAttackResult) -> DefenseFeedback:
        """Extract actionable feedback from an attack result."""
        actual_action = result.actual_decision
        reason = result.execution_evidence.policy_reason or ""
        bypassed = result.bypassed
        sens_exec = result.execution_evidence.sensitive_db_calls

        # Classify defense
        if bypassed or actual_action == "ALLOW":
            category = DefenseCategory.BENIGN_ALLOW
            strategies = []
            dist = 0.0
        elif "TAINT" in reason or "tainted" in reason.lower():
            category = DefenseCategory.TAINT_GUARD
            strategies = ["context_repackaging", "nested_roleplay", "base64_encoding", "unicode_homoglyph"]
            dist = 0.7
        elif "AUTHORITY" in reason or "CAPABILITY" in reason or "DELEGATION" in reason:
            category = DefenseCategory.AUTHORITY_GUARD
            strategies = ["authority_impersonation", "semantic_reframing", "delimiter_injection"]
            dist = 0.8
        elif "INTENT" in reason or "intent" in reason.lower():
            category = DefenseCategory.INTENT_GUARD
            strategies = ["semantic_reframing", "typo_injection", "casing_randomization"]
            dist = 0.6
        elif "UNTRUSTED" in reason:
            category = DefenseCategory.TRUST_GUARD
            strategies = ["authority_impersonation", "nested_roleplay"]
            dist = 0.9
        else:
            category = DefenseCategory.UNKNOWN_DEFENSE
            strategies = ["semantic_reframing", "base64_encoding", "nested_roleplay"]
            dist = 0.75

        return DefenseFeedback(
            attack_id=result.attack_id,
            decision=actual_action,
            reason_code=reason,
            explanation=result.error_message or reason,
            defense_category=category,
            bypassed=bypassed,
            sensitive_executions=sens_exec,
            suggested_mutation_strategies=strategies,
            boundary_distance_estimate=dist,
        )

