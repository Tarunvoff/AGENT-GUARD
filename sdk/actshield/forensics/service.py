"""ForensicService — central orchestrator of the forensic intelligence layer.

Wires together:
  - AuthorityGraph (delegation registry)
  - EffectiveAccessCalculator (deterministic access)
  - AccessGraph (attempt/actual access tracking)
  - SnapshotStore (point-in-time security state)
  - ForensicExplainer (evidence-backed explanations)
  - ForensicQueryEngine (all named queries)

Read-only with respect to security authority.
PolicyEvaluator remains the enforcement authority.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List, Optional

from actshield.forensics.access_graph import AccessGraph
from actshield.forensics.authority_graph import AuthorityGraph
from actshield.forensics.delegation_graph import EffectiveAccessCalculator
from actshield.forensics.explanation import ForensicExplainer
from actshield.forensics.models import (
    AccessAttempt,
    AccessDecision,
    AccessSnapshot,
    ActualAccess,
    ForensicIncident,
)
from actshield.forensics.queries import ForensicQueryEngine
from actshield.forensics.snapshots import SnapshotStore, capture_snapshot
from actshield.offensive.results import OffensiveAttackResult

if TYPE_CHECKING:
    from actshield.client import ActShield


class ForensicService:
    """Central forensic intelligence service.

    Attach to an ActShield instance and call record_* methods from
    tool interceptors or attack engine hooks to populate the forensic
    state. Then query via .query for dashboard/CLI consumption.

    Security guarantees:
      - Forensic queries are read-only with respect to security authority
      - PolicyEvaluator remains the enforcement authority
      - Forensic layer CANNOT grant capabilities or bypass policy
      - No AI/LLM used for access determination or explanations
    """

    def __init__(self, guard: "ActShield") -> None:
        self._guard = guard
        self._auth_graph = AuthorityGraph.from_guard(guard)
        self._calculator = EffectiveAccessCalculator(guard)
        self.access_graph = AccessGraph()
        self._snapshots = SnapshotStore()
        self._attack_results: Dict[str, OffensiveAttackResult] = {}
        self._incidents: Dict[str, ForensicIncident] = {}
        self._explainer = ForensicExplainer(self)
        self.query = ForensicQueryEngine(self)

        # Pre-populate access graph with tool/resource registry
        self._sync_tool_registry()

    def _sync_tool_registry(self) -> None:
        """Register tools and compute authorized agents from tool registry."""
        calc = self._calculator
        for tool_def in self._guard.tool_registry.values():
            self.access_graph.register_tool(tool_def)
            # Pre-compute authorized agents
            for agent_id in self._guard.agent_registry:
                if calc.can_access_tool(agent_id, tool_def.name):
                    for resource in tool_def.target_resources:
                        self.access_graph.declare_authorized_agent(
                            resource.name, agent_id
                        )

    def refresh(self) -> None:
        """Refresh the authority graph and tool registry from the current guard state."""
        self._auth_graph = AuthorityGraph.from_guard(self._guard)
        self._sync_tool_registry()

    # ------------------------------------------------------------------
    # Recording API — called by tool interceptors / offensive engine
    # ------------------------------------------------------------------

    def record_access_attempt(
        self,
        agent_id: str,
        tool_name: str,
        decision: str,
        policy_reason: str = "",
        capability_requested: Optional[str] = None,
        resource_name: Optional[str] = None,
        resource_sensitivity: str = "UNKNOWN",
        trace_id: Optional[str] = None,
        task_id: Optional[str] = None,
        context_ids: Optional[List[str]] = None,
        taint_state: str = "CLEAN",
        authority_contained: bool = True,
        executed: bool = False,
        execution_count: int = 0,
    ) -> AccessAttempt:
        """Record a tool access attempt (blocked, allowed, or HITL)."""
        try:
            dec = AccessDecision(decision.upper())
        except ValueError:
            dec = AccessDecision.UNKNOWN

        attempt = AccessAttempt(
            agent_id=agent_id,
            task_id=task_id,
            trace_id=trace_id,
            tool_name=tool_name,
            capability_requested=capability_requested,
            resource_name=resource_name,
            resource_sensitivity=resource_sensitivity,
            decision=dec,
            policy_reason=policy_reason,
            context_ids=context_ids or [],
            taint_state=taint_state,
            authority_contained=authority_contained,
            executed=executed,
            execution_count=execution_count,
        )
        self.access_graph.record_attempt(attempt)
        return attempt

    def record_actual_access(
        self,
        agent_id: str,
        tool_name: str,
        resource_name: Optional[str] = None,
        resource_sensitivity: str = "UNKNOWN",
        execution_count: int = 1,
        sensitive_db_calls: int = 0,
        trace_id: Optional[str] = None,
        task_id: Optional[str] = None,
    ) -> ActualAccess:
        """Record a confirmed tool execution (tool actually ran)."""
        access = ActualAccess(
            agent_id=agent_id,
            tool_name=tool_name,
            resource_name=resource_name,
            resource_sensitivity=resource_sensitivity,
            execution_count=execution_count,
            sensitive_db_calls=sensitive_db_calls,
            trace_id=trace_id,
            task_id=task_id,
        )
        self.access_graph.record_actual_access(access)
        return access

    def ingest_attack_result(self, result: OffensiveAttackResult) -> None:
        """Ingest a Phase 5 OffensiveAttackResult into the forensic layer."""
        self._attack_results[result.attack_id] = result

        # Auto-record attempt from execution evidence
        ev = result.security_evidence
        agent_id = ev.acting_agent if ev else ""
        tool_name = result.entry_point
        decision = result.actual_decision
        resource_name = None
        resource_sensitivity = "UNKNOWN"

        if ev:
            try:
                dec = AccessDecision(decision.upper())
            except ValueError:
                dec = AccessDecision.UNKNOWN

            attempt = AccessAttempt(
                agent_id=agent_id,
                trace_id=result.trace_id,
                tool_name=tool_name,
                capability_requested=ev.requested_capability,
                resource_name=resource_name,
                resource_sensitivity=resource_sensitivity,
                decision=dec,
                policy_reason=ev.policy_reason_code,
                context_ids=ev.context_ids,
                taint_state=ev.taint_state,
                authority_contained=ev.authority_contained,
                executed=result.actual_execution,
                execution_count=result.execution_evidence.execution_count,
            )
            self.access_graph.record_attempt(attempt)

            if result.actual_execution:
                actual = ActualAccess(
                    agent_id=agent_id,
                    tool_name=tool_name,
                    execution_count=result.execution_evidence.execution_count,
                    sensitive_db_calls=result.execution_evidence.sensitive_db_calls,
                    trace_id=result.trace_id,
                )
                self.access_graph.record_actual_access(actual)

    def record_incident(self, incident: ForensicIncident) -> ForensicIncident:
        """Store a forensic incident."""
        self._incidents[incident.incident_id] = incident
        return incident

    # ------------------------------------------------------------------
    # Snapshot API
    # ------------------------------------------------------------------

    def take_snapshot(self, label: str = "snapshot") -> AccessSnapshot:
        """Capture current security state as a snapshot."""
        ctx_count = len(self._guard.context_registry)
        tainted_count = sum(
            1 for ctx in self._guard.context_registry.values()
            if hasattr(ctx, "taint_state") and ctx.taint_state.value == "TAINTED"
        )
        snapshot = capture_snapshot(
            self._calculator,
            label=label,
            context_count=ctx_count,
            tainted_context_count=tainted_count,
        )
        self._snapshots.save(snapshot)
        return snapshot

    # ------------------------------------------------------------------
    # JSON Export
    # ------------------------------------------------------------------

    def export_all(self, output_dir: str = "reports/forensics") -> Dict[str, str]:
        """Export all forensic data to JSON files in output_dir."""
        import os
        from actshield.forensics.serializers import export_json

        os.makedirs(output_dir, exist_ok=True)
        exported: Dict[str, str] = {}

        # Overview
        exported["overview.json"] = export_json(
            self.query.get_overview(),
            os.path.join(output_dir, "overview.json"),
        )

        # Per-agent access profiles
        agent_profiles = {}
        for agent_id in self._guard.agent_registry:
            profile = self.query.get_agent_access(agent_id)
            if profile:
                agent_profiles[agent_id] = profile.model_dump(mode="json")
        exported["agent_access.json"] = export_json(
            agent_profiles,
            os.path.join(output_dir, "agent_access.json"),
        )

        # Access matrix
        matrix = self.query.get_access_matrix()
        exported["access_matrix.json"] = export_json(
            matrix.model_dump(mode="json"),
            os.path.join(output_dir, "access_matrix.json"),
        )

        # Delegation graph
        if self._auth_graph:
            exported["delegation_graph.json"] = export_json(
                self._auth_graph.to_dict(),
                os.path.join(output_dir, "delegation_graph.json"),
            )

        # Resource access
        resource_profiles = {}
        for resource_name in self.access_graph.get_all_resources():
            profile = self.query.get_resource_access(resource_name)
            if profile:
                resource_profiles[resource_name] = profile.model_dump(mode="json")
        exported["resource_access.json"] = export_json(
            resource_profiles,
            os.path.join(output_dir, "resource_access.json"),
        )

        # Attack forensics
        attack_reports = {}
        for attack_id in self._attack_results:
            report = self.query.get_attack_forensics(attack_id)
            if report:
                attack_reports[attack_id] = report.model_dump(mode="json")
        exported["attack_forensics.json"] = export_json(
            attack_reports,
            os.path.join(output_dir, "attack_forensics.json"),
        )

        # Incidents
        incidents = {
            inc_id: inc.model_dump(mode="json")
            for inc_id, inc in self._incidents.items()
        }
        exported["incidents.json"] = export_json(
            incidents,
            os.path.join(output_dir, "incidents.json"),
        )

        # Latest snapshot
        latest = self._snapshots.latest()
        if latest:
            exported["access_snapshot.json"] = export_json(
                latest.model_dump(mode="json"),
                os.path.join(output_dir, "access_snapshot.json"),
            )

        return exported


