"""Response orchestration engine and dynamic authority containment for AgentGuard Phase 9."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from agentguard.response.response_actions import ResponseActionRecord, ResponseActionType
from agentguard.response.response_audit import AuthorityChangeEvent
from agentguard.tracing.correlation import generate_id


class ResponseEngine:
    """Orchestrates safe, non-destructive response actions and dynamic authority containment."""

    def __init__(self, guard: Optional[Any] = None) -> None:
        self.guard = guard
        self.action_history: List[ResponseActionRecord] = []
        self.authority_audit_log: List[AuthorityChangeEvent] = []
        self.quarantined_contexts: set[str] = set()
        self.restricted_agents: Dict[str, List[str]] = {}  # agent_id -> list of restricted capabilities

    def block_action(self, target: str, reason: str, details: Optional[Dict[str, Any]] = None) -> ResponseActionRecord:
        """Enforce deterministic action block."""
        rec = ResponseActionRecord(
            action_type=ResponseActionType.BLOCK_ACTION,
            target_entity=target,
            reason=reason,
            details=details or {},
            executed_at=datetime.now(timezone.utc).isoformat(),
        )
        self.action_history.append(rec)
        return rec

    def quarantine_context(self, context_id: str, reason: str = "Tainted context quarantine", actor: str = "system") -> ResponseActionRecord:
        """Isolate a tainted context object from flowing to downstream agents."""
        self.quarantined_contexts.add(context_id)
        rec = ResponseActionRecord(
            action_type=ResponseActionType.QUARANTINE_CONTEXT,
            target_entity=context_id,
            reason=reason,
            details={"status": "QUARANTINED", "actor": actor},
            executed_at=datetime.now(timezone.utc).isoformat(),
        )
        self.action_history.append(rec)
        return rec

    def restrict_agent_authority(
        self,
        agent_id: str,
        current_capabilities: List[str],
        capabilities_to_restrict: List[str],
        reason: str,
    ) -> AuthorityChangeEvent:
        """
        Dynamically restrict specific capabilities for an agent after a security incident.
        Creates an immutable, auditable before/after authority record.
        """
        after_caps = [c for c in current_capabilities if c not in capabilities_to_restrict]
        self.restricted_agents[agent_id] = capabilities_to_restrict

        audit_event = AuthorityChangeEvent(
            agent_id=agent_id,
            trigger_reason=reason,
            before_capabilities=current_capabilities,
            after_capabilities=after_caps,
            restricted_capabilities=capabilities_to_restrict,
        )
        self.authority_audit_log.append(audit_event)

        rec = ResponseActionRecord(
            action_type=ResponseActionType.RESTRICT_AGENT,
            target_entity=agent_id,
            reason=reason,
            details={
                "before": current_capabilities,
                "after": after_caps,
                "restricted": capabilities_to_restrict,
            },
            executed_at=datetime.now(timezone.utc).isoformat(),
        )
        self.action_history.append(rec)
        return audit_event

    def restrict_authority(
        self,
        agent_id: str,
        restricted_capabilities: List[str],
        actor: str = "system",
        reason: str = "Containment restriction",
        previous_capabilities: Optional[List[str]] = None,
    ) -> AuthorityChangeEvent:
        """Convenience wrapper for restricting authority during incident response."""
        prev = previous_capabilities if previous_capabilities is not None else restricted_capabilities
        return self.restrict_agent_authority(
            agent_id=agent_id,
            current_capabilities=prev,
            capabilities_to_restrict=restricted_capabilities,
            reason=f"[{actor}] {reason}",
        )

    def restore_agent_authority(self, agent_id: str, restored_capabilities: List[str]) -> AuthorityChangeEvent:
        """Revert temporary capability restrictions after remediation."""
        current_restricted = self.restricted_agents.get(agent_id, [])
        new_restricted = [c for c in current_restricted if c not in restored_capabilities]
        self.restricted_agents[agent_id] = new_restricted

        audit_event = AuthorityChangeEvent(
            agent_id=agent_id,
            trigger_reason="Remediation verified — authority restored",
            before_capabilities=new_restricted,
            after_capabilities=restored_capabilities,
            restricted_capabilities=[],
        )
        self.authority_audit_log.append(audit_event)
        return audit_event

    def restore_authority(
        self,
        agent_id: str,
        restored_capabilities: List[str],
        actor: str = "system",
        reason: str = "Authority restored",
        current_capabilities: Optional[List[str]] = None,
    ) -> AuthorityChangeEvent:
        """Convenience wrapper for restoring authority after incident remediation."""
        return self.restore_agent_authority(
            agent_id=agent_id,
            restored_capabilities=restored_capabilities,
        )

    def list_actions(self) -> List[ResponseActionRecord]:
        return list(self.action_history)

    def list_authority_changes(self) -> List[AuthorityChangeEvent]:
        return list(self.authority_audit_log)

