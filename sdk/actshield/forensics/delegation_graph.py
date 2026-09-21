"""Effective access calculator — deterministic, never uses AI.

Calculates:
    effective_access = declared_capabilities
                     + valid_delegated_capabilities
                     - explicit_restrictions

Uses existing ActShield:
    - agent_registry (declared capabilities)
    - delegation_registry (delegated capabilities)
    - tool_registry (required capabilities per tool)
    - authority containment logic

Does NOT use AI Secura or APIRIS for access determination.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Dict, List, Set

if TYPE_CHECKING:
    from actshield.client import ActShield


class EffectiveAccessCalculator:
    """Deterministic calculation of effective capabilities and reachable resources.

    effective_access = declared_capabilities
                     + valid_delegated_capabilities
                     - explicit_restrictions

    Monotonic authority containment is preserved — a delegated agent can
    never receive more authority than the delegator holds.
    """

    def __init__(self, guard: "ActShield") -> None:
        self._guard = guard

    def get_effective_capabilities(self, agent_id: str) -> List[str]:
        """Return the union of declared + delegated capabilities for agent_id."""
        agent = self._guard.agent_registry.get(agent_id)
        declared: Set[str] = set(agent.capability_names()) if agent else set()

        delegated: Set[str] = set()
        for dlg in self._guard.delegation_registry.values():
            if dlg.delegate_agent_id == agent_id and dlg.status in ("active", "completed"):
                delegated.update(dlg.authority_grant.granted_capabilities)

        return sorted(declared | delegated)

    def get_declared_capabilities(self, agent_id: str) -> List[str]:
        agent = self._guard.agent_registry.get(agent_id)
        return agent.capability_names() if agent else []

    def get_delegated_capabilities(self, agent_id: str) -> List[str]:
        caps: Set[str] = set()
        for dlg in self._guard.delegation_registry.values():
            if dlg.delegate_agent_id == agent_id and dlg.status in ("active", "completed"):
                caps.update(dlg.authority_grant.granted_capabilities)
        return sorted(caps)

    def get_reachable_tools(self, agent_id: str) -> List[str]:
        """Return tools this agent can invoke based on effective capabilities."""
        effective = set(self.get_effective_capabilities(agent_id))
        reachable = []
        for tool_def in self._guard.tool_registry.values():
            required = set(tool_def.required_capabilities)
            if not required or required.issubset(effective):
                reachable.append(tool_def.name)
        return sorted(reachable)

    def get_reachable_resources(self, agent_id: str) -> List[str]:
        """Return resources this agent can reach via effective capabilities."""
        reachable_tools = set(self.get_reachable_tools(agent_id))
        resources: List[str] = []
        seen: Set[str] = set()
        for tool_def in self._guard.tool_registry.values():
            if tool_def.name in reachable_tools:
                for resource in tool_def.target_resources:
                    if resource.name not in seen:
                        seen.add(resource.name)
                        resources.append(resource.name)
        return sorted(resources)

    def can_access_tool(self, agent_id: str, tool_name: str) -> bool:
        """Check if agent has effective permission to invoke a named tool."""
        tool_def = self._get_tool(tool_name)
        if tool_def is None:
            return False
        effective = set(self.get_effective_capabilities(agent_id))
        required = set(tool_def.required_capabilities)
        return not required or required.issubset(effective)

    def can_access_resource(self, agent_id: str, resource_name: str) -> bool:
        """Check if agent has effective permission to reach a named resource."""
        return resource_name in self.get_reachable_resources(agent_id)

    def build_access_matrix(
        self,
        agent_ids: List[str],
        resource_names: List[str],
    ) -> Dict[str, Dict[str, bool]]:
        """Build effective-permission matrix: agent × resource → bool."""
        matrix: Dict[str, Dict[str, bool]] = {}
        for agent_id in agent_ids:
            matrix[agent_id] = {}
            for resource_name in resource_names:
                matrix[agent_id][resource_name] = self.can_access_resource(
                    agent_id, resource_name
                )
        return matrix

    def _get_tool(self, tool_name: str):
        for tool_def in self._guard.tool_registry.values():
            if tool_def.name == tool_name:
                return tool_def
        return None


