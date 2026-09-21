"""Forensic query engine — answers structured forensic questions.

Implements all named queries from the spec:
  get_agent_access, get_resource_access, get_agent_delegation_chain,
  get_resource_authorized_agents, get_agent_attempts, get_agent_actual_access,
  get_resource_access_history, get_reachable_resources, get_reachable_agents,
  get_access_snapshot, compare_access_snapshots, get_influencing_context,
  get_causal_path, get_attack_forensics, get_decision_explanation,
  get_regression_forensics

All queries are read-only. None can modify security authority.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List, Optional

from actshield.forensics.models import (
    AccessDiff,
    AccessMatrix,
    AccessMatrixEntry,
    AccessSnapshot,
    AgentAccessProfile,
    AttackForensicReport,
    ForensicExplanation,
    ForensicIncident,
    ResourceAccessProfile,
)
from actshield.forensics.snapshots import compare_snapshots

if TYPE_CHECKING:
    from actshield.forensics.service import ForensicService


class ForensicQueryEngine:
    """Central query interface for the forensic layer.

    Every method is read-only with respect to the security runtime.
    Queries never grant capabilities, modify taint, or bypass policy.
    """

    def __init__(self, service: "ForensicService") -> None:
        self._svc = service

    # ------------------------------------------------------------------
    # Agent queries
    # ------------------------------------------------------------------

    def get_agent_access(self, agent_id: str) -> Optional[AgentAccessProfile]:
        """Return full forensic access profile for an agent."""
        agent = self._svc._guard.agent_registry.get(agent_id)
        if agent is None:
            return None

        calc = self._svc._calculator
        declared = calc.get_declared_capabilities(agent_id) if calc else []
        delegated = calc.get_delegated_capabilities(agent_id) if calc else []
        effective = calc.get_effective_capabilities(agent_id) if calc else []
        reachable_tools = calc.get_reachable_tools(agent_id) if calc else []
        reachable_resources = calc.get_reachable_resources(agent_id) if calc else []

        # Authority graph
        auth_graph = self._svc._auth_graph
        delegation_chain = auth_graph.get_delegation_chain(agent_id) if auth_graph else []

        # Access graph
        acc_graph = self._svc.access_graph
        attempts = acc_graph.get_agent_attempts(agent_id)
        actual = acc_graph.get_agent_actual_access(agent_id)

        # Never count blocked attempts as actual access
        total_blocked = sum(1 for a in attempts if a.was_blocked)
        total_allowed = sum(1 for a in attempts if a.was_allowed)
        total_executions = sum(a.execution_count for a in actual)

        return AgentAccessProfile(
            agent_id=agent_id,
            agent_name=agent.name,
            trust_level=agent.trust_level.value,
            declared_capabilities=declared,
            delegated_capabilities=delegated,
            effective_capabilities=effective,
            restricted_capabilities=[],
            reachable_tools=reachable_tools,
            reachable_resources=reachable_resources,
            recent_attempts=attempts[-20:],
            recent_actual_access=actual[-20:],
            delegation_chain=delegation_chain,
            total_attempts=len(attempts),
            total_blocked=total_blocked,
            total_allowed=total_allowed,
            total_executions=total_executions,
        )

    def get_all_agents(self) -> List[str]:
        return sorted(self._svc._guard.agent_registry.keys())

    def get_agent_delegation_chain(self, agent_id: str) -> List[Dict[str, Any]]:
        """Return the full delegation chain leading to agent_id."""
        if not self._svc._auth_graph:
            return []
        chain = self._svc._auth_graph.get_delegation_chain(agent_id)
        return [c.model_dump(mode="json") for c in chain]

    def get_agent_attempts(self, agent_id: str) -> List[Dict[str, Any]]:
        return [
            a.model_dump(mode="json")
            for a in self._svc.access_graph.get_agent_attempts(agent_id)
        ]

    def get_agent_actual_access(self, agent_id: str) -> List[Dict[str, Any]]:
        return [
            a.model_dump(mode="json")
            for a in self._svc.access_graph.get_agent_actual_access(agent_id)
        ]

    def get_reachable_resources(self, agent_id: str) -> List[str]:
        """Deterministic reachable-resource analysis using authority state."""
        if not self._svc._calculator:
            return []
        return self._svc._calculator.get_reachable_resources(agent_id)

    def get_reachable_tools(self, agent_id: str) -> List[str]:
        if not self._svc._calculator:
            return []
        return self._svc._calculator.get_reachable_tools(agent_id)

    # ------------------------------------------------------------------
    # Resource queries
    # ------------------------------------------------------------------

    def get_resource_access(
        self, resource_name: str
    ) -> Optional[ResourceAccessProfile]:
        return self._svc.access_graph.get_resource_profile(resource_name)

    def get_all_resources(self) -> List[str]:
        return self._svc.access_graph.get_all_resources()

    def get_resource_authorized_agents(
        self, resource_name: str
    ) -> List[str]:
        return self._svc.access_graph.get_reachable_agents(resource_name)

    def get_resource_access_history(
        self, resource_name: str
    ) -> List[Dict[str, Any]]:
        return [
            a.model_dump(mode="json")
            for a in self._svc.access_graph.get_resource_history(resource_name)
        ]

    def get_reachable_agents(self, resource_name: str) -> List[str]:
        return self._svc.access_graph.get_reachable_agents(resource_name)

    # ------------------------------------------------------------------
    # Access matrix
    # ------------------------------------------------------------------

    def get_access_matrix(self) -> AccessMatrix:
        """Build the full agent × resource access matrix."""
        agent_ids = self.get_all_agents()
        resource_names = self.get_all_resources()

        # Also include resources from tool registry
        for tool_def in self._svc._guard.tool_registry.values():
            for resource in tool_def.target_resources:
                if resource.name not in resource_names:
                    resource_names.append(resource.name)
        resource_names = sorted(set(resource_names))

        matrix = AccessMatrix(agents=agent_ids, resources=resource_names)
        calc = self._svc._calculator

        for agent_id in agent_ids:
            matrix.entries[agent_id] = {}
            eff_perm = set(calc.get_reachable_resources(agent_id)) if calc else set()
            attempts = self._svc.access_graph.get_agent_attempts(agent_id)
            actual = self._svc.access_graph.get_agent_actual_access(agent_id)

            for resource_name in resource_names:
                attempted = any(
                    a.resource_name == resource_name or a.tool_name == resource_name
                    for a in attempts
                )
                blocked = any(
                    (a.resource_name == resource_name or a.tool_name == resource_name)
                    and a.was_blocked
                    for a in attempts
                )
                historically_accessed = any(
                    a.resource_name == resource_name or a.tool_name == resource_name
                    for a in actual
                )
                matrix.entries[agent_id][resource_name] = AccessMatrixEntry(
                    agent_id=agent_id,
                    resource_name=resource_name,
                    effective_permission=resource_name in eff_perm,
                    historically_accessed=historically_accessed,
                    attempted=attempted,
                    blocked=blocked,
                )

        return matrix

    # ------------------------------------------------------------------
    # Snapshot queries
    # ------------------------------------------------------------------

    def get_access_snapshot(
        self, snapshot_id: str
    ) -> Optional[AccessSnapshot]:
        return self._svc._snapshots.get(snapshot_id)

    def list_snapshots(self) -> List[Dict[str, Any]]:
        return [
            {"snapshot_id": s.snapshot_id, "label": s.label, "timestamp": s.timestamp.isoformat()}
            for s in self._svc._snapshots.list_all()
        ]

    def compare_access_snapshots(
        self, before_id: str, after_id: str
    ) -> Optional[AccessDiff]:
        before = self._svc._snapshots.get(before_id)
        after = self._svc._snapshots.get(after_id)
        if not before or not after:
            return None
        return compare_snapshots(before, after)

    # ------------------------------------------------------------------
    # Trace / causal queries
    # ------------------------------------------------------------------

    def get_causal_path(self, trace_id: str) -> Optional[str]:
        """Return the causal graph JSON for a trace (from storage)."""
        if self._svc._guard.storage:
            return self._svc._guard.storage.get_trace_graph(trace_id)
        return None

    def get_influencing_context(
        self, trace_id: str
    ) -> List[Dict[str, Any]]:
        """Return context records influencing a trace."""
        events = self._svc._guard.storage.get_events(trace_id=trace_id)
        contexts = []
        for event in events:
            if event.event_type.value in (
                "context.received", "context.propagated", "context.generated"
            ):
                contexts.append({
                    "event_id": event.event_id,
                    "event_type": event.event_type.value,
                    "context_id": event.context_id,
                    "agent_id": event.agent_id,
                    "timestamp": event.timestamp.isoformat(),
                    "payload": event.payload,
                })
        return contexts

    # ------------------------------------------------------------------
    # Attack / campaign queries
    # ------------------------------------------------------------------

    def get_attack_forensics(
        self, attack_id: str
    ) -> Optional[AttackForensicReport]:
        """Return the full forensic report for an attack."""
        return self._svc._explainer.explain_attack(attack_id)

    def get_regression_forensics(
        self, regression_id: str
    ) -> Optional[AttackForensicReport]:
        """Return forensic report for a regression attack (same as attack)."""
        return self.get_attack_forensics(regression_id)

    def get_all_attack_ids(self) -> List[str]:
        return list(self._svc._attack_results.keys())

    def get_all_bypass_attacks(self) -> List[str]:
        return [
            aid for aid, r in self._svc._attack_results.items()
            if r.bypassed
        ]

    # ------------------------------------------------------------------
    # Decision explanation
    # ------------------------------------------------------------------

    def get_decision_explanation(
        self,
        event_id: Optional[str] = None,
        trace_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        tool_name: Optional[str] = None,
    ) -> ForensicExplanation:
        """Return a deterministic explanation for a security decision."""
        return self._svc._explainer.explain_decision(
            event_id=event_id,
            trace_id=trace_id,
            agent_id=agent_id,
            tool_name=tool_name,
        )

    # ------------------------------------------------------------------
    # Incidents
    # ------------------------------------------------------------------

    def get_all_incidents(self) -> List[ForensicIncident]:
        return list(self._svc._incidents.values())

    def get_incident(self, incident_id: str) -> Optional[ForensicIncident]:
        return self._svc._incidents.get(incident_id)

    # ------------------------------------------------------------------
    # Overview metrics
    # ------------------------------------------------------------------

    def get_overview(self) -> Dict[str, Any]:
        """Return aggregate dashboard-ready metrics."""
        guard = self._svc._guard
        attempts = self._svc.access_graph.get_all_attempts()
        actual = self._svc.access_graph.get_all_actual_accesses()
        bypass_count = len(self.get_all_bypass_attacks())
        incidents = list(self._svc._incidents.values())

        # Count today's attacks (all attacks from attack_results)
        attack_count = len(self._svc._attack_results)
        blocked_count = sum(1 for a in attempts if a.was_blocked)
        hitl_count = sum(
            1 for a in attempts if a.decision.value == "HITL"
        )
        sensitive_attempts = sum(
            1 for a in attempts
            if a.resource_sensitivity in ("HIGH", "CRITICAL")
        )
        sensitive_prevented = sum(
            1 for a in attempts
            if a.resource_sensitivity in ("HIGH", "CRITICAL") and a.was_blocked
        )
        sensitive_executed = sum(
            a.sensitive_db_calls for a in actual
        )

        return {
            "agents": len(guard.agent_registry),
            "active_tasks": None,  # TaskManager not directly accessible
            "protected_tools": len(guard.tool_registry),
            "mcp_servers": None,
            "attacks_today": attack_count,
            "blocked": blocked_count,
            "hitl": hitl_count,
            "bypasses": bypass_count,
            "sensitive_attempts": sensitive_attempts,
            "sensitive_prevented": sensitive_prevented,
            "sensitive_executed": sensitive_executed,
            "campaigns": len({
                r.campaign_id for r in self._svc._attack_results.values()
                if r.campaign_id
            }),
            "regressions": bypass_count,
            "incidents": len(incidents),
            "availability": {
                "active_tasks": False,
                "mcp_servers": False,
            },
        }

