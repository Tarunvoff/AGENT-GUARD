"""Access graph — resource-centric view of who accessed (or attempted) what.

Tracks:
  - Which agents can access which resources (effective permission)
  - Which agents attempted access
  - Which agents actually accessed (executed)
  - Which attempts were blocked and why

Read-only with respect to security authority.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Set
from actshield.forensics.models import (
    AccessAttempt,
    AccessDecision,
    AccessRelationship,
    ActualAccess,
    ResourceAccessProfile,
)
from actshield.tools.tool import ToolDefinition


class ResourceNode:
    """In-memory node representing one protected resource in the access graph."""

    def __init__(
        self,
        resource_id: str,
        resource_name: str,
        resource_type: str = "api",
        sensitivity: str = "MEDIUM",
    ) -> None:
        self.resource_id = resource_id
        self.resource_name = resource_name
        self.resource_type = resource_type
        self.sensitivity = sensitivity
        self.exposing_tools: List[str] = []
        self.authorized_agents: List[str] = []
        self.attempts: List[AccessAttempt] = []
        self.actual_accesses: List[ActualAccess] = []

    def add_exposing_tool(self, tool_name: str) -> None:
        if tool_name not in self.exposing_tools:
            self.exposing_tools.append(tool_name)

    def add_authorized_agent(self, agent_id: str) -> None:
        if agent_id not in self.authorized_agents:
            self.authorized_agents.append(agent_id)

    def record_attempt(self, attempt: AccessAttempt) -> None:
        self.attempts.append(attempt)

    def record_actual_access(self, access: ActualAccess) -> None:
        self.actual_accesses.append(access)

    def to_profile(self) -> ResourceAccessProfile:
        attempted = list({a.agent_id for a in self.attempts})
        actual = list({a.agent_id for a in self.actual_accesses})
        blocked = list({a.agent_id for a in self.attempts if a.was_blocked})
        return ResourceAccessProfile(
            resource_id=self.resource_id,
            resource_name=self.resource_name,
            resource_type=self.resource_type,
            sensitivity=self.sensitivity,
            exposing_tools=list(self.exposing_tools),
            authorized_agents=list(self.authorized_agents),
            attempted_agents=attempted,
            actual_access_agents=actual,
            blocked_agents=blocked,
            access_history=list(self.attempts),
            total_attempts=len(self.attempts),
            total_blocked=sum(1 for a in self.attempts if a.was_blocked),
            total_executions=sum(a.execution_count for a in self.actual_accesses),
        )


class AccessGraph:
    """Resource-centric access graph.

    Answers:
      - Which agents can access resource X?
      - Which tools expose resource X?
      - Which agents attempted access to X?
      - Which agents actually accessed X?
      - Which attempts were blocked?
    """

    def __init__(self) -> None:
        # resource_name → ResourceNode
        self._resources: Dict[str, ResourceNode] = {}
        # agent_id → list of AccessRelationship
        self._agent_rels: Dict[str, List[AccessRelationship]] = {}
        # All recorded attempts
        self._attempts: List[AccessAttempt] = []
        # All confirmed actual accesses
        self._actual: List[ActualAccess] = []

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register_resource(
        self,
        resource_id: str,
        resource_name: str,
        resource_type: str = "api",
        sensitivity: str = "MEDIUM",
    ) -> ResourceNode:
        if resource_name not in self._resources:
            self._resources[resource_name] = ResourceNode(
                resource_id=resource_id,
                resource_name=resource_name,
                resource_type=resource_type,
                sensitivity=sensitivity,
            )
        return self._resources[resource_name]

    def register_tool(self, tool_def: ToolDefinition) -> None:
        """Register all resources exposed by a tool definition."""
        for resource in tool_def.target_resources:
            node = self.register_resource(
                resource_id=resource.resource_id,
                resource_name=resource.name,
                resource_type=resource.resource_type,
                sensitivity=resource.sensitivity.value,
            )
            node.add_exposing_tool(tool_def.name)

    def declare_authorized_agent(self, resource_name: str, agent_id: str) -> None:
        """Mark an agent as authorized to access a resource (based on capability check)."""
        if resource_name in self._resources:
            self._resources[resource_name].add_authorized_agent(agent_id)

    # ------------------------------------------------------------------
    # Recording
    # ------------------------------------------------------------------

    def record_attempt(self, attempt: AccessAttempt) -> None:
        """Record an access attempt (may be blocked or allowed)."""
        self._attempts.append(attempt)
        resource = attempt.resource_name or attempt.tool_name
        if resource in self._resources:
            self._resources[resource].record_attempt(attempt)

        rel = AccessRelationship(
            agent_id=attempt.agent_id,
            tool_name=attempt.tool_name,
            resource_name=attempt.resource_name,
            decision=attempt.decision,
            executed=attempt.executed,
            capability_required=attempt.capability_requested,
            sensitivity=attempt.resource_sensitivity,
            trace_id=attempt.trace_id,
            task_id=attempt.task_id,
            taint_state=attempt.taint_state,
            reason_code=attempt.policy_reason,
        )
        self._agent_rels.setdefault(attempt.agent_id, []).append(rel)

    def record_actual_access(self, access: ActualAccess) -> None:
        """Record confirmed execution of a tool/resource access."""
        self._actual.append(access)
        resource = access.resource_name or access.tool_name
        if resource in self._resources:
            self._resources[resource].record_actual_access(access)

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_resource_profile(
        self, resource_name: str
    ) -> Optional[ResourceAccessProfile]:
        node = self._resources.get(resource_name)
        return node.to_profile() if node else None

    def get_all_resources(self) -> List[str]:
        return sorted(self._resources.keys())

    def get_agent_attempts(self, agent_id: str) -> List[AccessAttempt]:
        return [a for a in self._attempts if a.agent_id == agent_id]

    def get_agent_actual_access(self, agent_id: str) -> List[ActualAccess]:
        return [a for a in self._actual if a.agent_id == agent_id]

    def get_resource_history(self, resource_name: str) -> List[AccessAttempt]:
        node = self._resources.get(resource_name)
        return list(node.attempts) if node else []

    def get_reachable_agents(self, resource_name: str) -> List[str]:
        node = self._resources.get(resource_name)
        return list(node.authorized_agents) if node else []

    def get_all_attempts(self) -> List[AccessAttempt]:
        return list(self._attempts)

    def get_all_actual_accesses(self) -> List[ActualAccess]:
        return list(self._actual)

    def get_agent_relationships(
        self, agent_id: str
    ) -> List[AccessRelationship]:
        return list(self._agent_rels.get(agent_id, []))

    def to_dict(self) -> dict:
        return {
            "resources": {
                name: node.to_profile().model_dump(mode="json")
                for name, node in self._resources.items()
            },
            "total_attempts": len(self._attempts),
            "total_actual_accesses": len(self._actual),
        }

