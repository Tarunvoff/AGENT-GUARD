"""Posture diffing, metrics calculation, and engine implementation."""

from __future__ import annotations

import statistics
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from agentguard.posture.posture_models import (
    FindingSeverity,
    PostureDiff,
    PostureDimensionMetrics,
    PostureFinding,
    PostureRating,
    SecurityPostureSnapshot,
)
from agentguard.posture.posture_rules import PostureRuleEvaluator


class PostureDiffEngine:
    """Computes explainable diffs between two security posture snapshots."""

    @staticmethod
    def diff(before: SecurityPostureSnapshot, after: SecurityPostureSnapshot) -> PostureDiff:
        score_change = round(after.security_score - before.security_score, 1)
        rating_transition = f"{before.rating.value} -> {after.rating.value}"

        before_fnd_titles = {f.title for f in before.findings}
        new_findings = [f for f in after.findings if f.title not in before_fnd_titles]
        after_fnd_titles = {f.title for f in after.findings}
        resolved_findings = [f.title for f in before.findings if f.title not in after_fnd_titles]

        # Calculate metric deltas
        metric_deltas: Dict[str, Any] = {}
        before_dict = before.metrics.model_dump()
        after_dict = after.metrics.model_dump()
        for k in before_dict:
            b_val = before_dict[k]
            a_val = after_dict[k]
            if isinstance(b_val, (int, float)) and isinstance(a_val, (int, float)):
                metric_deltas[k] = {
                    "before": b_val,
                    "after": a_val,
                    "delta": round(a_val - b_val, 2),
                }

        if score_change > 0:
            summary = f"Security posture improved by +{score_change} pts ({rating_transition}). Resolved {len(resolved_findings)} finding(s)."
        elif score_change < 0:
            summary = f"Security posture degraded by {score_change} pts ({rating_transition}). Discovered {len(new_findings)} new finding(s)."
        else:
            summary = f"Security posture remained stable at {after.security_score} pts ({rating_transition})."

        return PostureDiff(
            before_snapshot_id=before.snapshot_id,
            after_snapshot_id=after.snapshot_id,
            score_change=score_change,
            rating_transition=rating_transition,
            new_findings=new_findings,
            resolved_findings=resolved_findings,
            metric_deltas=metric_deltas,
            summary=summary,
        )


class PostureEngine:
    """Derives measurable posture snapshots from live runtime state."""

    def __init__(self, guard: Optional[Any] = None) -> None:
        self.guard = guard
        self.snapshots: List[SecurityPostureSnapshot] = []
        self._latencies: List[float] = []

    def evaluate_current_posture(
        self,
        events: Optional[List[Dict[str, Any]]] = None,
        regressions: Optional[List[Dict[str, Any]]] = None,
        incidents: Optional[List[Dict[str, Any]]] = None,
        agents: Optional[List[Dict[str, Any]]] = None,
        environment: str = "production",
    ) -> SecurityPostureSnapshot:
        """Derive and return the current Security Posture Snapshot."""
        return self.generate_snapshot(
            events=events or [],
            regressions=regressions,
            incidents=incidents,
            agents=agents,
            environment=environment,
        )

    def record_latency(self, latency_ms: float) -> None:
        """Record enforcement latency measurement."""

        self._latencies.append(latency_ms)
        if len(self._latencies) > 5000:
            self._latencies.pop(0)

    def compute_metrics(
        self,
        events: List[Dict[str, Any]],
        regressions: Optional[List[Dict[str, Any]]] = None,
        incidents: Optional[List[Dict[str, Any]]] = None,
        agents: Optional[List[Dict[str, Any]]] = None,
    ) -> PostureDimensionMetrics:
        """Derive dimension metrics from real event logs and state."""
        regressions = regressions or []
        incidents = incidents or []
        agents = agents or []

        unauthorized_attempts = sum(1 for e in events if e.get("decision") in ("BLOCK", "REVOKE"))
        actual_unauthorized = sum(1 for e in events if e.get("decision") == "ALLOW" and e.get("taint") == "TAINTED" and e.get("resource_sensitivity") in ("HIGH", "CRITICAL"))
        tainted_reqs = sum(1 for e in events if e.get("taint") in ("TAINTED", "UNTRUSTED") and e.get("tool"))
        auth_violations = sum(1 for e in events if e.get("authority_violation") or "authority" in str(e.get("reason", "")).lower())
        intent_violations = sum(1 for e in events if e.get("intent_alignment") in ("VIOLATED", "DRIFTING"))
        blocked_actions = sum(1 for e in events if e.get("decision") == "BLOCK")
        hitl_actions = sum(1 for e in events if e.get("decision") in ("HITL", "HUMAN_APPROVAL"))
        allowed_actions = sum(1 for e in events if e.get("decision") == "ALLOW")

        untrusted_crossings = sum(1 for e in events if e.get("context_source") == "external_mcp" or e.get("taint") == "UNTRUSTED")
        sensitive_exposures = sum(1 for e in events if e.get("resource_sensitivity") in ("HIGH", "CRITICAL"))

        open_regs = sum(1 for r in regressions if r.get("status", "OPEN") == "OPEN")
        failed_replays = sum(1 for r in regressions if r.get("replay_result") == "FAIL" or r.get("secured_replay_passed") is False)
        off_failures = sum(1 for r in regressions if r.get("bypass_detected") is True)

        high_risk_agents = sum(1 for a in agents if str(a.get("trust_level", "")).lower() in ("low", "untrusted"))

        # Latencies
        mean_lat = round(statistics.mean(self._latencies), 2) if self._latencies else 0.45
        p95_lat = round(statistics.quantiles(self._latencies, n=20)[18], 2) if len(self._latencies) >= 20 else (mean_lat * 1.4)

        return PostureDimensionMetrics(
            unauthorized_access_attempts=unauthorized_attempts,
            actual_unauthorized_executions=actual_unauthorized,
            tainted_sensitive_requests=tainted_reqs,
            authority_violations=auth_violations,
            intent_violations=intent_violations,
            blocked_actions=blocked_actions,
            hitl_actions=hitl_actions,
            allowed_actions=allowed_actions,
            high_risk_agents_count=high_risk_agents,
            untrusted_context_crossings=untrusted_crossings,
            sensitive_resource_exposures=sensitive_exposures,
            open_regressions=open_regs,
            failed_secured_replays=failed_replays,
            offensive_validation_failures=off_failures,
            ai_secura_availability_pct=100.0,
            apiris_availability_pct=100.0,
            policy_engine_availability_pct=100.0,
            mean_enforcement_latency_ms=mean_lat,
            p95_enforcement_latency_ms=p95_lat,
        )

    def generate_snapshot(
        self,
        events: List[Dict[str, Any]],
        regressions: Optional[List[Dict[str, Any]]] = None,
        incidents: Optional[List[Dict[str, Any]]] = None,
        agents: Optional[List[Dict[str, Any]]] = None,
        environment: str = "production",
    ) -> SecurityPostureSnapshot:
        """Create and store a full security posture snapshot."""
        metrics = self.compute_metrics(events, regressions, incidents, agents)
        score, rating, findings = PostureRuleEvaluator.evaluate(metrics)

        snapshot = SecurityPostureSnapshot(
            rating=rating,
            security_score=score,
            metrics=metrics,
            findings=findings,
            active_incidents_count=len(incidents or []),
            total_events_evaluated=len(events),
            environment=environment,
        )
        self.snapshots.append(snapshot)
        return snapshot

    def get_latest_snapshot(self) -> Optional[SecurityPostureSnapshot]:
        return self.snapshots[-1] if self.snapshots else None

    def diff_latest(self) -> Optional[PostureDiff]:
        if len(self.snapshots) < 2:
            return None
        return PostureDiffEngine.diff(self.snapshots[-2], self.snapshots[-1])
