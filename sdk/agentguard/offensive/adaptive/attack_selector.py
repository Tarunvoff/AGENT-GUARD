"""Adaptive attack selector providing deterministic seed selection across attack families."""

import random
from typing import List, Optional
from agentguard.offensive.attack import AttackCase, AttackType
from agentguard.offensive.corpus import AttackCorpus, attack_corpus


class AdaptiveAttackSelector:
    """Selects base seed attacks from the corpus for adaptive exploration."""

    def __init__(self, corpus: Optional[AttackCorpus] = None, seed: Optional[int] = None) -> None:
        self.corpus = corpus or attack_corpus
        self.seed = seed
        if seed is not None:
            random.seed(seed)

    def select_seeds(
        self,
        family: Optional[str] = None,
        attack_id: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> List[AttackCase]:
        """Select seed attacks matching criteria."""
        all_attacks = self.corpus.get_all_attacks()

        if attack_id:
            found = self.corpus.get_attack(attack_id)
            return [found] if found else []

        if family:
            fam_clean = family.lower().replace("-", "_")
            filtered = [
                a for a in all_attacks
                if fam_clean in a.attack_type.value.lower() or fam_clean in a.attack_id.lower()
            ]
        else:
            filtered = all_attacks

        if self.seed is not None:
            # Deterministic shuffle
            rng = random.Random(self.seed)
            shuffled = list(filtered)
            rng.shuffle(shuffled)
            filtered = shuffled

        if limit and limit > 0:
            return filtered[:limit]

        return filtered
