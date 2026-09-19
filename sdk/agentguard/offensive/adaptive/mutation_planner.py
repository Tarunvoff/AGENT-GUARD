"""Adaptive mutation planner composing multi-step transformations based on defensive feedback."""

from typing import List, Optional
from agentguard.offensive.attack import AttackCase, SafetyClass
from agentguard.offensive.mutation import MutationEngine, MutationStrategy
from agentguard.offensive.adaptive.feedback import DefenseFeedback


class MutationPlanner:
    """Plans and composes targeted mutations based on previous defense reasons."""

    # Map feedback suggested strategy names to MutationStrategy enums
    STRATEGY_MAP = {
        "context_repackaging": MutationStrategy.CONTEXT_PLACEMENT,
        "nested_roleplay": MutationStrategy.ROLEPLAY_FRAMING,
        "base64_encoding": MutationStrategy.ENCODING_OBSCURE,
        "unicode_homoglyph": MutationStrategy.ENCODING_OBSCURE,
        "authority_impersonation": MutationStrategy.AUTHORITY_FABRICATION,
        "semantic_reframing": MutationStrategy.WORDING_VARIATION,
        "delimiter_injection": MutationStrategy.DELIMITER_STUFFING,
        "typo_injection": MutationStrategy.WORDING_VARIATION,
        "casing_randomization": MutationStrategy.WORDING_VARIATION,
        "urgency_escalation": MutationStrategy.URGENCY_INJECTION,
    }

    @classmethod
    def plan_next_mutations(
        cls,
        parent_attack: AttackCase,
        feedback: DefenseFeedback,
        depth: int,
        branch_factor: int = 2,
    ) -> List[AttackCase]:
        """Generate next generation of mutated attack cases tailored to previous defense response."""
        planned_cases: List[AttackCase] = []
        suggested = feedback.suggested_mutation_strategies or ["semantic_reframing", "nested_roleplay"]

        for idx, strat_name in enumerate(suggested[:branch_factor], 1):
            strategy_enum = cls.STRATEGY_MAP.get(strat_name, MutationStrategy.WORDING_VARIATION)
            
            # Apply transformation
            mutated_cases = MutationEngine.mutate(parent_attack, strategy=strategy_enum, count=1)
            if mutated_cases:
                mut_case = mutated_cases[0]
                mut_id = f"{parent_attack.attack_id}_d{depth}_{strategy_enum.value[:4]}_{idx:02d}"
                
                # Enrich metadata
                mut_case = mut_case.model_copy(update={
                    "attack_id": mut_id,
                    "mutation_of": parent_attack.attack_id,
                    "mutation_strategy": strategy_enum.value,
                    "safety_class": SafetyClass.LOCAL_SYNTHETIC,
                })
                planned_cases.append(mut_case)

        return planned_cases
