"""Boundary search engine executing bounded adaptive exploration of defense limits."""

from typing import List, Optional, Tuple
from agentguard.offensive.attack import AttackCase
from agentguard.offensive.engine import OffensiveEngine
from agentguard.offensive.results import AttackStatus, OffensiveAttackResult
from agentguard.offensive.target import AttackTarget
from agentguard.offensive.adaptive.campaign_memory import CampaignMemory
from agentguard.offensive.adaptive.feedback import FeedbackAnalyzer
from agentguard.offensive.adaptive.mutation_planner import MutationPlanner


class BoundarySearchEngine:
    """Explores the decision boundary around an attack vector until bypass or max depth."""

    def __init__(
        self,
        engine: OffensiveEngine,
        memory: CampaignMemory,
        max_depth: int = 3,
        branch_factor: int = 2,
        max_attempts_per_attack: int = 10,
    ) -> None:
        self.engine = engine
        self.memory = memory
        self.max_depth = max_depth
        self.branch_factor = branch_factor
        self.max_attempts_per_attack = max_attempts_per_attack

    def explore_boundary(
        self,
        root_attack: AttackCase,
        target: Optional[AttackTarget] = None,
        campaign_id: Optional[str] = None,
    ) -> List[OffensiveAttackResult]:
        """Execute bounded adaptive exploration starting from root_attack."""
        results: List[OffensiveAttackResult] = []
        attempts = 0

        # Queue items: (AttackCase, depth, parent_id, strategy_name)
        queue: List[Tuple[AttackCase, int, Optional[str], str]] = [(root_attack, 0, None, "baseline")]

        while queue and attempts < self.max_attempts_per_attack:
            current_attack, depth, parent_id, strategy = queue.pop(0)
            attempts += 1

            # Get lineage so far
            lineage_ids = [n.mutation_id for n in self.memory.get_lineage(parent_id)] if parent_id else []
            lineage_ids.append(current_attack.attack_id)

            # Execute attack through full security pipeline
            res = self.engine.execute_attack(
                attack=current_attack,
                target=target,
                campaign_id=campaign_id,
                mutation_lineage=lineage_ids,
            )
            results.append(res)

            # Record in campaign memory
            self.memory.record_node(
                mutation_id=current_attack.attack_id,
                root_attack_id=root_attack.attack_id,
                parent_id=parent_id,
                strategy=strategy,
                depth=depth,
                input_payload=root_attack.payload,
                output_payload=current_attack.payload,
                defense_reason=res.execution_evidence.policy_reason,
                decision=res.actual_decision,
                status=res.status.value,
                sensitive_executions=res.execution_evidence.sensitive_db_calls,
                latency_ms=res.latency_ms,
            )

            # INVARIANT: If bypass is discovered, STOP exploring this branch immediately!
            if res.bypassed:
                break

            # If not bypassed and depth < max_depth, generate targeted mutations
            if depth < self.max_depth:
                feedback = FeedbackAnalyzer.analyze(res)
                next_mutations = MutationPlanner.plan_next_mutations(
                    parent_attack=current_attack,
                    feedback=feedback,
                    depth=depth + 1,
                    branch_factor=self.branch_factor,
                )

                for mut_case in next_mutations:
                    queue.append((
                        mut_case,
                        depth + 1,
                        current_attack.attack_id,
                        mut_case.mutation_strategy or "mutation",
                    ))

        return results
