"""Authority, Access, Context Drift detectors and statistical Behavioral Baselines (Phase 9)."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set
from actshield.drift.drift_models import (
    AgentBehaviorBaseline,
    DriftCategory,
    DriftEvent,
    DriftSeverity,
)


class AuthorityDriftDetector:
    """Detects capability modifications, permission creep, and unapproved authority expansions."""

    @staticmethod
    def detect(agent_id: str, baseline_caps: List[str], current_caps: List[str]) -> Optional[DriftEvent]:
        base_set = set(baseline_caps)
        curr_set = set(current_caps)

        added = curr_set - base_set
        removed = base_set - curr_set

        if not added and not removed:
            return None

        if added:
            severity = DriftSeverity.HIGH if any("write" in c or "exec" in c or "delete" in c for c in added) else DriftSeverity.MEDIUM
            return DriftEvent(
                category=DriftCategory.AUTHORITY_DRIFT,
                severity=severity,
                entity_id=agent_id,
                entity_type="agent",
                title=f"Authority Expansion Detected on Agent '{agent_id}'",
                description=f"Agent granted new capabilities: {list(added)}",
                before_state=baseline_caps,
                after_state=current_caps,
                security_implication="Agent capability boundary expanded. Verify alignment with principle of least privilege.",
                review_required=True,
            )
        else:
            return DriftEvent(
                category=DriftCategory.AUTHORITY_DRIFT,
                severity=DriftSeverity.LOW,
                entity_id=agent_id,
                entity_type="agent",
                title=f"Authority Reduction on Agent '{agent_id}'",
                description=f"Capabilities removed: {list(removed)}",
                before_state=baseline_caps,
                after_state=current_caps,
                security_implication="Capabilities revoked. Baseline updated.",
                review_required=False,
            )


class AccessDriftDetector:
    """Detects newly targeted resources that the agent has never accessed historically."""

    @staticmethod
    def detect(agent_id: str, historical_targets: List[str], current_target: str, sensitivity: str = "MEDIUM") -> Optional[DriftEvent]:
        if current_target in historical_targets:
            return None

        is_sensitive = sensitivity.upper() in ("HIGH", "CRITICAL")
        return DriftEvent(
            category=DriftCategory.ACCESS_DRIFT,
            severity=DriftSeverity.HIGH if is_sensitive else DriftSeverity.MEDIUM,
            entity_id=agent_id,
            entity_type="agent",
            title=f"New Resource Target Attempted: '{current_target}'",
            description=f"Agent '{agent_id}' attempted access to '{current_target}' for the first time.",
            before_state=historical_targets,
            after_state=historical_targets + [current_target],
            security_implication="Anomalous resource access path. Potential lateral movement or prompt injection target.",
            review_required=True,
        )


class ContextDriftDetector:
    """Tracks trust transitions and degradation across context provenance chains."""

    @staticmethod
    def detect(context_id: str, before_trust: str, after_trust: str, source: str) -> Optional[DriftEvent]:
        if before_trust == after_trust:
            return None

        # Trust downgraded e.g. CLEAN -> TAINTED or TRUSTED -> UNTRUSTED
        is_downgrade = after_trust in ("TAINTED", "UNTRUSTED")
        return DriftEvent(
            category=DriftCategory.CONTEXT_DRIFT,
            severity=DriftSeverity.HIGH if is_downgrade else DriftSeverity.LOW,
            entity_id=context_id,
            entity_type="context",
            title=f"Context Trust State Transition ({before_trust} -> {after_trust})",
            description=f"Context from source '{source}' changed trust classification to '{after_trust}'.",
            before_state=before_trust,
            after_state=after_trust,
            security_implication="Taint boundary crossed. Downstream agents consuming this context must be restricted from sensitive sinks.",
            review_required=is_downgrade,
        )


class BehavioralBaselineTracker:
    """Maintains statistical baseline profiles per agent and detects behavioral anomalies."""

    def __init__(self, guard: Optional[Any] = None) -> None:
        self.guard = guard
        self.baselines: Dict[str, AgentBehaviorBaseline] = {}
        self.drift_events: List[DriftEvent] = []

    def record_drift(self, event: DriftEvent) -> None:
        """Record and track a security drift event."""
        self.drift_events.append(event)

    def update_baseline(self, agent_id: str, tool_name: str, resource_name: Optional[str] = None, source: Optional[str] = None) -> None:

        if agent_id not in self.baselines:
            self.baselines[agent_id] = AgentBehaviorBaseline(agent_id=agent_id)

        b = self.baselines[agent_id]
        if tool_name not in b.normal_tools:
            b.normal_tools.append(tool_name)
        if resource_name and resource_name not in b.normal_resources:
            b.normal_resources.append(resource_name)
        if source and source not in b.normal_context_sources:
            b.normal_context_sources.append(source)
        b.sample_count += 1

    def check_deviation(self, agent_id: str, tool_name: str, resource_name: Optional[str] = None) -> Optional[DriftEvent]:
        b = self.baselines.get(agent_id)
        if not b or b.sample_count < 3:
            return None  # Baseline warming up

        if tool_name not in b.normal_tools:
            return DriftEvent(
                category=DriftCategory.BEHAVIORAL_DEVIATION,
                severity=DriftSeverity.MEDIUM,
                entity_id=agent_id,
                entity_type="agent",
                title=f"Behavioral Anomaly: Unseen Tool '{tool_name}'",
                description=f"Agent '{agent_id}' invoked tool '{tool_name}', which deviates from established profile ({b.normal_tools}).",
                before_state=b.normal_tools,
                after_state=tool_name,
                security_implication="Statistical deviation from historical behavior.",
                review_required=True,
            )
        return None

