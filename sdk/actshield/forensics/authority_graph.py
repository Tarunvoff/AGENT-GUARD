"""Authority graph — builds and queries the agent authority/delegation graph.

Read-only. Does not grant or modify any authority.
Uses data already present in delegation_registry and agent_registry.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Dict, List, Optional, Set
from actshield.forensics.models import AuthorityRelationship, DelegationRelationship

if TYPE_CHECKING:
    from actshield.client import ActShield


class AuthorityGraph:
    """Directed authority graph built from the ActShield delegation registry.

    Nodes  = agent_ids
    Edges  = delegation records (delegator → delegate, labelled with capabilities)

    Never grants authority — read-only projection of existing security state.
    """

    def __init__(self) -> None:
        # adjacency: delegator_id → list of DelegationRelationship
        self._outgoing: Dict[str, List[DelegationRelationship]] = {}
        # reverse: delegate_id → list of DelegationRelationship
        self._incoming: Dict[str, List[DelegationRelationship]] = {}

    # ------------------------------------------------------------------
    # Build
    # ------------------------------------------------------------------

    @classmethod
    def from_guard(cls, guard: "ActShield") -> "AuthorityGraph":
        """Construct graph from an ActShield instance's delegation registry."""
        g = cls()
        for dlg in guard.delegation_registry.values():
            rel = DelegationRelationship(
                delegation_id=dlg.delegation_id,
                delegator_agent_id=dlg.delegator_agent_id,
                delegate_agent_id=dlg.delegate_agent_id,
                granted_capabilities=list(dlg.authority_grant.granted_capabilities),
                depth=dlg.depth,
                parent_delegation_id=dlg.parent_delegation_id,
                task_id=dlg.task_id,
                trace_id=dlg.trace_id,
                status=dlg.status,
                timestamp=dlg.created_at,
            )
            g._add_edge(rel)
        return g

    def add_delegation(self, rel: DelegationRelationship) -> None:
        """Add a delegation relationship to the graph."""
        self._add_edge(rel)

    def _add_edge(self, rel: DelegationRelationship) -> None:
        src = rel.delegator_agent_id
        dst = rel.delegate_agent_id
        self._outgoing.setdefault(src, []).append(rel)
        self._incoming.setdefault(dst, []).append(rel)

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_delegations_from(self, agent_id: str) -> List[DelegationRelationship]:
        """Return all delegations initiated by agent_id."""
        return list(self._outgoing.get(agent_id, []))

    def get_delegations_to(self, agent_id: str) -> List[DelegationRelationship]:
        """Return all delegations received by agent_id."""
        return list(self._incoming.get(agent_id, []))

    def get_authority_relationships(
        self, agent_id: str
    ) -> List[AuthorityRelationship]:
        """Return AuthorityRelationship objects where agent_id is delegator or delegate."""
        rels: List[AuthorityRelationship] = []
        for dlg in self.get_delegations_from(agent_id):
            rels.append(
                AuthorityRelationship(
                    source_agent_id=dlg.delegator_agent_id,
                    target_agent_id=dlg.delegate_agent_id,
                    capabilities=dlg.granted_capabilities,
                    delegation_id=dlg.delegation_id,
                    task_id=dlg.task_id,
                    trace_id=dlg.trace_id,
                    depth=dlg.depth,
                    timestamp=dlg.timestamp,
                    status=dlg.status,
                )
            )
        for dlg in self.get_delegations_to(agent_id):
            rels.append(
                AuthorityRelationship(
                    source_agent_id=dlg.delegator_agent_id,
                    target_agent_id=dlg.delegate_agent_id,
                    capabilities=dlg.granted_capabilities,
                    delegation_id=dlg.delegation_id,
                    task_id=dlg.task_id,
                    trace_id=dlg.trace_id,
                    depth=dlg.depth,
                    timestamp=dlg.timestamp,
                    status=dlg.status,
                )
            )
        return rels

    def get_delegation_chain(self, agent_id: str) -> List[DelegationRelationship]:
        """Walk the delegation chain from root to agent_id (recursive)."""
        chain: List[DelegationRelationship] = []
        visited: Set[str] = set()
        self._walk_up(agent_id, chain, visited)
        chain.sort(key=lambda r: r.depth)
        return chain

    def _walk_up(
        self,
        agent_id: str,
        chain: List[DelegationRelationship],
        visited: Set[str],
    ) -> None:
        if agent_id in visited:
            return
        visited.add(agent_id)
        for rel in self.get_delegations_to(agent_id):
            chain.append(rel)
            self._walk_up(rel.delegator_agent_id, chain, visited)

    def get_all_delegatees(self, agent_id: str) -> List[str]:
        """Return all agents that agent_id has (directly or transitively) delegated to."""
        result: List[str] = []
        visited: Set[str] = set()
        self._walk_down(agent_id, result, visited)
        return result

    def _walk_down(
        self, agent_id: str, result: List[str], visited: Set[str]
    ) -> None:
        if agent_id in visited:
            return
        visited.add(agent_id)
        for rel in self.get_delegations_from(agent_id):
            dst = rel.delegate_agent_id
            if dst not in result:
                result.append(dst)
            self._walk_down(dst, result, visited)

    def get_delegated_capabilities(self, agent_id: str) -> List[str]:
        """Return all capabilities delegated TO agent_id (most recent active delegation)."""
        delegations = self.get_delegations_to(agent_id)
        if not delegations:
            return []
        # Prefer active ones, fall back to completed
        active = [d for d in delegations if d.status == "active"]
        source = active if active else delegations
        caps: Set[str] = set()
        for d in source:
            caps.update(d.granted_capabilities)
        return sorted(caps)

    def get_all_agents(self) -> List[str]:
        """Return all agent IDs present in the graph."""
        agents: Set[str] = set()
        agents.update(self._outgoing.keys())
        agents.update(self._incoming.keys())
        return sorted(agents)

    def to_dict(self) -> dict:
        """Serializable representation of the authority graph."""
        edges = []
        seen: Set[str] = set()
        for rels in self._outgoing.values():
            for rel in rels:
                if rel.delegation_id not in seen:
                    seen.add(rel.delegation_id)
                    edges.append(rel.model_dump(mode="json"))
        return {
            "nodes": self.get_all_agents(),
            "edges": edges,
        }


