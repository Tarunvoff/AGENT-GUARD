"""Forensic snapshots — point-in-time captures of security state.

AccessSnapshot represents "what could every agent access at this point?"
Snapshots are serializable and can be compared via AccessDiff.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Dict, List, Optional

from actshield.forensics.models import (
    AccessDiff,
    AccessSnapshot,
    AgentSnapshot,
    AccessAttempt,
    ActualAccess,
)

if TYPE_CHECKING:
    from actshield.forensics.delegation_graph import EffectiveAccessCalculator


class SnapshotStore:
    """In-memory store for AccessSnapshots."""

    def __init__(self) -> None:
        self._snapshots: Dict[str, AccessSnapshot] = {}

    def save(self, snapshot: AccessSnapshot) -> None:
        self._snapshots[snapshot.snapshot_id] = snapshot

    def get(self, snapshot_id: str) -> Optional[AccessSnapshot]:
        return self._snapshots.get(snapshot_id)

    def list_all(self) -> List[AccessSnapshot]:
        return sorted(self._snapshots.values(), key=lambda s: s.timestamp)

    def latest(self) -> Optional[AccessSnapshot]:
        snaps = self.list_all()
        return snaps[-1] if snaps else None


def capture_snapshot(
    calc: "EffectiveAccessCalculator",
    label: str = "snapshot",
    context_count: int = 0,
    tainted_context_count: int = 0,
) -> AccessSnapshot:
    """Capture a point-in-time security state snapshot.

    Uses the EffectiveAccessCalculator to compute reachable resources
    deterministically. Does not use AI.
    """
    guard = calc._guard

    agent_snaps: Dict[str, AgentSnapshot] = {}
    for agent_id, agent in guard.agent_registry.items():
        effective_caps = calc.get_effective_capabilities(agent_id)
        reachable = calc.get_reachable_resources(agent_id)
        active_delegations = [
            dlg_id
            for dlg_id, dlg in guard.delegation_registry.items()
            if dlg.delegate_agent_id == agent_id and dlg.status == "active"
        ]
        agent_snaps[agent_id] = AgentSnapshot(
            agent_id=agent_id,
            effective_capabilities=effective_caps,
            reachable_resources=reachable,
            active_delegations=active_delegations,
        )

    resource_snap: Dict[str, Dict] = {}
    for tool_def in guard.tool_registry.values():
        for resource in tool_def.target_resources:
            if resource.name not in resource_snap:
                resource_snap[resource.name] = {
                    "resource_id": resource.resource_id,
                    "sensitivity": resource.sensitivity.value,
                    "exposing_tools": [],
                }
            resource_snap[resource.name]["exposing_tools"].append(tool_def.name)

    delegation_snap: Dict[str, Dict] = {}
    for dlg_id, dlg in guard.delegation_registry.items():
        delegation_snap[dlg_id] = {
            "delegator": dlg.delegator_agent_id,
            "delegate": dlg.delegate_agent_id,
            "capabilities": list(dlg.authority_grant.granted_capabilities),
            "status": dlg.status,
            "depth": dlg.depth,
        }

    return AccessSnapshot(
        label=label,
        agents=agent_snaps,
        resources=resource_snap,
        delegations=delegation_snap,
        context_count=context_count,
        tainted_context_count=tainted_context_count,
    )


def compare_snapshots(
    before: AccessSnapshot,
    after: AccessSnapshot,
    new_attempts: Optional[List[AccessAttempt]] = None,
    new_actual_accesses: Optional[List[ActualAccess]] = None,
    attack_ids: Optional[List[str]] = None,
) -> AccessDiff:
    """Produce an AccessDiff between two snapshots.

    Distinguishes:
      - Authority changes (effective capability set changed)
      - Attack attempts (new attempts observed)
      - Actual access (new executions confirmed)
    """
    new_attempts = new_attempts or []
    new_actual_accesses = new_actual_accesses or []
    attack_ids = attack_ids or []

    authority_changed = False
    new_caps: List[str] = []
    lost_caps: List[str] = []

    # Compare capabilities per agent
    for agent_id, after_snap in after.agents.items():
        before_snap = before.agents.get(agent_id)
        if before_snap:
            before_caps = set(before_snap.effective_capabilities)
            after_caps = set(after_snap.effective_capabilities)
            gained = list(after_caps - before_caps)
            lost = list(before_caps - after_caps)
            if gained or lost:
                authority_changed = True
                new_caps.extend(gained)
                lost_caps.extend(lost)
        else:
            # New agent
            authority_changed = True
            new_caps.extend(after_snap.effective_capabilities)

    taint_changed = (
        before.tainted_context_count != after.tainted_context_count
    )
    context_changed = before.context_count != after.context_count

    summary_parts = []
    if authority_changed:
        summary_parts.append(f"Authority changed: +{new_caps} -{lost_caps}")
    if new_attempts:
        blocked = [a for a in new_attempts if a.was_blocked]
        summary_parts.append(
            f"{len(new_attempts)} attempt(s), {len(blocked)} blocked"
        )
    if new_actual_accesses:
        summary_parts.append(f"{len(new_actual_accesses)} actual access(es)")
    if attack_ids:
        summary_parts.append(f"Attack(s): {attack_ids}")

    return AccessDiff(
        before_snapshot_id=before.snapshot_id,
        after_snapshot_id=after.snapshot_id,
        authority_changed=authority_changed,
        new_capabilities=new_caps,
        lost_capabilities=lost_caps,
        new_attempts=new_attempts,
        new_actual_accesses=new_actual_accesses,
        taint_changed=taint_changed,
        context_changed=context_changed,
        attack_detected=bool(attack_ids),
        attack_ids=attack_ids,
        summary=" | ".join(summary_parts) if summary_parts else "No significant changes",
    )

