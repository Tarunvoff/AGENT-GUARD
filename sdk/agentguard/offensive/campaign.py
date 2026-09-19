"""Attack campaign definitions and scorecard aggregation."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from agentguard.offensive.attack import AttackCase
from agentguard.offensive.results import AttackStatus, OffensiveAttackResult
from agentguard.offensive.target import AttackTarget, target_registry
from agentguard.tracing.correlation import generate_id


class AttackCampaign(BaseModel):
    """A collection of offensive attack validations executed as a cohesive campaign."""

    campaign_id: str = Field(default_factory=lambda: generate_id("camp"), description="Unique campaign ID")
    name: str = Field(..., description="Human-readable campaign title")
    objective: str = Field(..., description="Campaign validation objective")
    target: AttackTarget = Field(..., description="Target system under validation")
    attacks: List[AttackCase] = Field(default_factory=list, description="List of attack cases in campaign")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = Field(default_factory=dict)


class CampaignSummary(BaseModel):
    """Empirical security scorecard and metrics aggregated from a completed campaign."""

    campaign_id: str = Field(..., description="Campaign ID")
    name: str = Field(..., description="Campaign title")
    target_id: str = Field(..., description="Target system ID")
    
    # Attack & Attempt Counts
    total_attacks: int = Field(default=0)
    blocked: int = Field(default=0)
    bypassed: int = Field(default=0)
    refused: int = Field(default=0)
    errors: int = Field(default=0)
    unique_attack_variants: int = Field(default=0)
    
    # Hard Empirical Metrics
    sensitive_actions_attempted: int = Field(default=0, description="Total sensitive tool invocations attempted")
    sensitive_actions_prevented: int = Field(default=0, description="Total sensitive tool invocations blocked")
    sensitive_actions_executed: int = Field(default=0, description="Total unauthorized sensitive executions (Bypasses)")
    empirical_prevention_rate: float = Field(default=1.0, description="1 - (executed / attempted)")
    
    # Rates & Latency
    block_rate_pct: float = Field(default=0.0, description="Percentage of unauthorized attacks successfully blocked")
    sensitive_prevention_rate_pct: float = Field(default=100.0, description="Rate of sensitive sink protection")
    mean_latency_ms: float = Field(default=0.0)
    p95_latency_ms: float = Field(default=0.0)
    duration_ms: float = Field(default=0.0)
    campaign_seed: Optional[int] = Field(default=None)

    # Adaptive & Lineage Metrics
    max_mutation_depth: int = Field(default=0)
    avg_mutation_depth: float = Field(default=0.0)
    regression_fixtures_generated: int = Field(default=0)

    # Pipeline Availability
    ai_analysis_availability_pct: float = Field(default=100.0)
    apiris_analysis_availability_pct: float = Field(default=100.0)
    
    # Coverage Breakdown
    coverage_breakdown: Dict[str, Dict[str, int]] = Field(default_factory=dict)
    defense_reasons_breakdown: Dict[str, int] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @classmethod
    def from_results(
        cls,
        campaign: AttackCampaign,
        results: List[OffensiveAttackResult],
        memory: Optional[Any] = None,
        seed: Optional[int] = None,
        duration_ms: float = 0.0,
    ) -> "CampaignSummary":
        """Aggregate results into an empirical CampaignSummary."""
        total = len(results)
        if total == 0:
            return cls(
                campaign_id=campaign.campaign_id,
                name=campaign.name,
                target_id=campaign.target.target_id,
                campaign_seed=seed,
                duration_ms=duration_ms,
            )

        blocked = sum(1 for r in results if r.blocked or r.status == AttackStatus.PASS)
        bypassed = sum(1 for r in results if r.bypassed or r.status == AttackStatus.BYPASS)
        refused = sum(1 for r in results if r.status == AttackStatus.REFUSED)
        errors = sum(1 for r in results if r.status == AttackStatus.ERROR)

        sens_exec = sum(r.execution_evidence.sensitive_db_calls for r in results if r.execution_evidence)
        sens_prev = sum(1 for r in results if r.blocked or r.status == AttackStatus.PASS)
        sens_attempted = sens_prev + sens_exec

        # Empirical prevention rate = 1 - (executed / attempted)
        if sens_attempted > 0:
            emp_rate = round(1.0 - (sens_exec / sens_attempted), 4)
        else:
            emp_rate = 1.0

        # Latencies
        lats = sorted([r.latency_ms for r in results])
        mean_lat = sum(lats) / total if total > 0 else 0.0
        p95_idx = int(total * 0.95)
        p95_lat = lats[min(p95_idx, total - 1)] if total > 0 else 0.0

        # Coverage breakdown by attack_type
        coverage: Dict[str, Dict[str, int]] = {}
        defense_reasons: Dict[str, int] = {}
        ai_available_count = 0
        apiris_available_count = 0

        for r in results:
            atype = r.attack_type.value if hasattr(r.attack_type, 'value') else str(r.attack_type)
            if atype not in coverage:
                coverage[atype] = {"total": 0, "blocked": 0, "bypassed": 0}
            coverage[atype]["total"] += 1
            if r.blocked or r.status == AttackStatus.PASS:
                coverage[atype]["blocked"] += 1
            if r.bypassed or r.status == AttackStatus.BYPASS:
                coverage[atype]["bypassed"] += 1

            reason = r.execution_evidence.policy_reason or "UNKNOWN"
            defense_reasons[reason] = defense_reasons.get(reason, 0) + 1

            if r.ai_analysis and r.ai_analysis.get("status") != "UNAVAILABLE":
                ai_available_count += 1
            if r.apiris_analysis and r.apiris_analysis.get("status") != "UNAVAILABLE":
                apiris_available_count += 1

        block_rate = round((blocked / total) * 100, 1) if total > 0 else 0.0
        prev_rate = round(((total - bypassed) / total) * 100, 1) if total > 0 else 100.0

        ai_avail_pct = round((ai_available_count / total) * 100, 1) if total > 0 else 100.0
        apiris_avail_pct = round((apiris_available_count / total) * 100, 1) if total > 0 else 100.0

        # Memory / Lineage metrics
        max_depth = 0
        avg_depth = 0.0
        reg_count = bypassed
        if memory and hasattr(memory, "nodes"):
            all_nodes = list(memory.nodes.values())
            if all_nodes:
                depths = [n.depth for n in all_nodes]
                max_depth = max(depths)
                avg_depth = round(sum(depths) / len(depths), 2)
            reg_count = len(getattr(memory, "bypasses", [])) or bypassed

        return cls(
            campaign_id=campaign.campaign_id,
            name=campaign.name,
            target_id=campaign.target.target_id,
            total_attacks=total,
            blocked=blocked,
            bypassed=bypassed,
            refused=refused,
            errors=errors,
            unique_attack_variants=len(set(r.attack_id for r in results)),
            sensitive_actions_attempted=sens_attempted,
            sensitive_actions_prevented=sens_prev,
            sensitive_actions_executed=sens_exec,
            empirical_prevention_rate=emp_rate,
            block_rate_pct=block_rate,
            sensitive_prevention_rate_pct=prev_rate,
            mean_latency_ms=round(mean_lat, 2),
            p95_latency_ms=round(p95_lat, 2),
            duration_ms=round(duration_ms, 2),
            campaign_seed=seed,
            max_mutation_depth=max_depth,
            avg_mutation_depth=avg_depth,
            regression_fixtures_generated=reg_count,
            ai_analysis_availability_pct=ai_avail_pct,
            apiris_analysis_availability_pct=apiris_avail_pct,
            coverage_breakdown=coverage,
            defense_reasons_breakdown=defense_reasons,
        )

    def to_markdown(self) -> str:
        """Format summary into structured Markdown."""
        lines = [
            "# AgentGuard Adaptive Offensive Validation Scorecard",
            "",
            f"- **Campaign ID**: `{self.campaign_id}`",
            f"- **Target System**: `{self.target_id}`",
            f"- **Campaign Seed**: `{self.campaign_seed}`",
            f"- **Total Attack Executions**: {self.total_attacks} (Unique Variants: {self.unique_attack_variants})",
            f"- **Attacks Blocked**: {self.blocked} ({self.block_rate_pct}%)",
            f"- **Attacks Bypassed**: {self.bypassed}",
            f"- **Sensitive Database Executions**: {self.sensitive_actions_executed}",
            f"- **Empirical Prevention Rate**: {self.empirical_prevention_rate * 100:.1f}%",
            f"- **Max Mutation Depth**: {self.max_mutation_depth} (Average: {self.avg_mutation_depth})",
            f"- **Mean Latency**: {self.mean_latency_ms} ms (p95: {self.p95_latency_ms} ms)",
            f"- **Pipeline Availability**: AI Secura ({self.ai_analysis_availability_pct}%) | APIRIS ({self.apiris_analysis_availability_pct}%)",
            "",
            "## Attack Family Coverage Breakdown",
            "",
            "| Attack Type | Total | Blocked | Bypassed |",
            "|---|---|---|---|",
        ]

        for atype, stats in self.coverage_breakdown.items():
            lines.append(f"| `{atype}` | {stats['total']} | {stats['blocked']} | {stats['bypassed']} |")

        lines.extend([
            "",
            "## Defense Reasons Breakdown",
            "",
            "| Defense Reason Code | Count |",
            "|---|---|",
        ])

        for reason, count in self.defense_reasons_breakdown.items():
            lines.append(f"| `{reason}` | {count} |")

        return "\n".join(lines)
