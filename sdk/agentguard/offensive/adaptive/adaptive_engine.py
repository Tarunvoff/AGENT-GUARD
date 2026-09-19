"""Adaptive Offensive Engine — Master orchestrator for adaptive validation campaigns."""

import json
import logging
import os
import pathlib
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from agentguard.offensive.attack import AttackCase, AttackType
from agentguard.offensive.campaign import AttackCampaign, CampaignSummary
from agentguard.offensive.corpus import AttackCorpus, attack_corpus
from agentguard.offensive.engine import OffensiveEngine
from agentguard.offensive.results import AttackStatus, OffensiveAttackResult
from agentguard.offensive.safety import SafetyValidator, safety_validator
from agentguard.offensive.target import AttackTarget, TargetRegistry, target_registry
from agentguard.offensive.adaptive.attack_selector import AdaptiveAttackSelector
from agentguard.offensive.adaptive.boundary_search import BoundarySearchEngine
from agentguard.offensive.adaptive.campaign_memory import CampaignMemory, MutationNode

logger = logging.getLogger("agentguard.offensive.adaptive.engine")


class AdaptiveEngine:
    """Orchestrates adaptive multi-depth offensive campaigns against AgentGuard defenses."""

    def __init__(
        self,
        engine: Optional[OffensiveEngine] = None,
        corpus: Optional[AttackCorpus] = None,
        registry: Optional[TargetRegistry] = None,
        validator: Optional[SafetyValidator] = None,
        max_depth: int = 3,
        branch_factor: int = 2,
        seed: Optional[int] = 20260919,
    ) -> None:
        self.engine = engine or OffensiveEngine(corpus=corpus, registry=registry, validator=validator)
        self.corpus = corpus or attack_corpus
        self.registry = registry or target_registry
        self.validator = validator or safety_validator
        self.max_depth = max_depth
        self.branch_factor = branch_factor
        self.seed = seed
        self.selector = AdaptiveAttackSelector(corpus=self.corpus, seed=seed)

    def run_adaptive_campaign(
        self,
        family: Optional[str] = None,
        attack_id: Optional[str] = None,
        limit_seeds: Optional[int] = None,
        target: Optional[AttackTarget] = None,
        campaign_name: str = "Adaptive Offensive Campaign",
    ) -> Tuple[List[OffensiveAttackResult], CampaignSummary, CampaignMemory]:
        """Execute a full adaptive validation campaign."""
        start_time = time.perf_counter()
        target = target or self.registry.get("agentguard-demo")
        campaign_id = f"camp_adapt_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
        memory = CampaignMemory(campaign_id=campaign_id)

        search_engine = BoundarySearchEngine(
            engine=self.engine,
            memory=memory,
            max_depth=self.max_depth,
            branch_factor=self.branch_factor,
        )

        seed_attacks = self.selector.select_seeds(family=family, attack_id=attack_id, limit=limit_seeds)
        all_results: List[OffensiveAttackResult] = []

        campaign = AttackCampaign(
            campaign_id=campaign_id,
            name=campaign_name,
            objective=f"Adaptive exploration of defense boundaries (Max Depth: {self.max_depth})",
            target=target,
            attacks=seed_attacks,
        )

        for seed_attack in seed_attacks:
            branch_results = search_engine.explore_boundary(
                root_attack=seed_attack,
                target=target,
                campaign_id=campaign_id,
            )
            all_results.extend(branch_results)

        duration_ms = (time.perf_counter() - start_time) * 1000

        # Calculate enhanced scorecard
        summary = CampaignSummary.from_results(
            campaign=campaign,
            results=all_results,
            memory=memory,
            seed=self.seed,
            duration_ms=duration_ms,
        )

        return all_results, summary, memory

    def export_dashboard_json(
        self,
        summary: CampaignSummary,
        results: List[OffensiveAttackResult],
        memory: CampaignMemory,
        output_dir: Optional[str] = None,
    ) -> Dict[str, str]:
        """Export comprehensive dashboard-ready JSON artifacts."""
        if output_dir:
            out_path = pathlib.Path(output_dir)
        else:
            root = pathlib.Path(__file__).resolve().parent.parent.parent.parent.parent
            out_path = root / "reports" / "phase5"

        out_path.mkdir(parents=True, exist_ok=True)

        # 1. Dashboard Master Package
        dashboard_payload = {
            "campaign": {
                "campaign_id": summary.campaign_id,
                "name": summary.name,
                "target_id": summary.target_id,
                "timestamp": summary.timestamp.isoformat(),
                "seed": summary.campaign_seed,
                "duration_ms": summary.duration_ms,
            },
            "coverage": {
                "total_attacks": summary.total_attacks,
                "attack_family_breakdown": summary.coverage_breakdown,
                "unique_attack_variants": summary.unique_attack_variants,
                "max_mutation_depth": summary.max_mutation_depth,
                "avg_mutation_depth": summary.avg_mutation_depth,
            },
            "security": {
                "blocked": summary.blocked,
                "bypassed": summary.bypassed,
                "block_rate_pct": summary.block_rate_pct,
                "sensitive_actions_attempted": summary.sensitive_actions_attempted,
                "sensitive_actions_executed": summary.sensitive_actions_executed,
                "empirical_prevention_rate": summary.empirical_prevention_rate,
                "ai_analysis_availability_pct": summary.ai_analysis_availability_pct,
                "apiris_analysis_availability_pct": summary.apiris_analysis_availability_pct,
                "defense_reasons_breakdown": summary.defense_reasons_breakdown,
            },
            "performance": {
                "mean_latency_ms": summary.mean_latency_ms,
                "p95_latency_ms": summary.p95_latency_ms,
            },
            "mutations": [n.to_dict() for n in memory.get_all_nodes()],
            "bypasses": [n.to_dict() for n in memory.get_bypasses()],
            "regressions": summary.regression_fixtures_generated,
        }

        dash_file = out_path / "adaptive_dashboard.json"
        dash_file.write_text(json.dumps(dashboard_payload, indent=2), encoding="utf-8")

        # 2. Markdown Summary
        md_file = out_path / "adaptive_campaign_summary.md"
        md_file.write_text(summary.to_markdown(), encoding="utf-8")

        return {
            "dashboard_json": str(dash_file),
            "summary_md": str(md_file),
        }
