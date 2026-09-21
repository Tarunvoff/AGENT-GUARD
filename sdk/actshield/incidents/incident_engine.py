"""Incident timeline builder and incident engine orchestrator for ActShield Phase 9."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from actshield.incidents.incident import IncidentTimelineEntry, SecurityIncident
from actshield.incidents.incident_rules import IncidentCreationRule
from actshield.incidents.incident_state import (
    IncidentSeverity,
    IncidentState,
    IncidentStateMachine,
)
from actshield.tracing.correlation import generate_id


class IncidentTimelineBuilder:
    """Builds a structured causal storyline from correlated events."""

    @staticmethod
    def from_events(events: List[Dict[str, Any]]) -> List[IncidentTimelineEntry]:
        timeline: List[IncidentTimelineEntry] = []
        for i, evt in enumerate(events):
            stage = f"0{i+1}. {evt.get('stage_name', evt.get('event_type', 'EVENT'))}"
            timeline.append(IncidentTimelineEntry(
                timestamp=str(evt.get("timestamp", datetime.now(timezone.utc).isoformat())),
                stage=stage,
                agent_id=evt.get("agent_id"),
                agent_name=evt.get("agent_name"),
                action=evt.get("action") or f"Called {evt.get('tool', 'tool')}",
                detail=evt.get("detail") or evt.get("reason") or "Event executed in trace",
                taint_state=evt.get("taint", "CLEAN"),
                decision=evt.get("decision"),
                event_id=evt.get("event_id"),
            ))
        return timeline


class IncidentEngine:
    """Manages continuous security incident generation, correlation, and lifecycle state."""

    def __init__(self, guard: Optional[Any] = None) -> None:
        self.guard = guard
        self.incidents: Dict[str, SecurityIncident] = {}

    def record_incident(self, incident: SecurityIncident) -> SecurityIncident:
        """Explicitly register a SecurityIncident."""
        self.incidents[incident.incident_id] = incident
        return incident

    def process_event(self, event: Dict[str, Any], related_events: Optional[List[Dict[str, Any]]] = None) -> Optional[SecurityIncident]:
        """Evaluate an event for incident creation and causal linking."""
        should_create, title, severity, attack_type = IncidentCreationRule.evaluate(event)
        if not should_create:
            return None

        trace_id = event.get("trace_id") or generate_id("trc")
        
        # Check if active incident already exists for this trace
        for existing in self.incidents.values():
            if existing.trace_id == trace_id and existing.state not in (IncidentState.CLOSED, IncidentState.VALIDATED):
                # Update existing incident
                if event.get("agent_id") and event["agent_id"] not in existing.affected_agents:
                    existing.affected_agents.append(event["agent_id"])
                if event.get("resource") and event["resource"] not in existing.affected_resources:
                    existing.affected_resources.append(event["resource"])
                existing.updated_at = datetime.now(timezone.utc)
                return existing

        timeline_events = related_events or [event]
        timeline = IncidentTimelineBuilder.from_events(timeline_events)

        incident = SecurityIncident(
            title=title or "Security Boundary Incident",
            severity=severity,
            state=IncidentState.DETECTED,
            attack_type=attack_type or "unknown_threat",
            root_event_id=event.get("event_id"),
            trace_id=trace_id,
            affected_agents=[event["agent_id"]] if event.get("agent_id") else [],
            affected_tasks=[event["task_id"]] if event.get("task_id") else [],
            affected_resources=[event["resource"]] if event.get("resource") else ([event["tool"]] if event.get("tool") else []),
            context_source=event.get("context_source"),
            trust_state=event.get("trust_level", "UNKNOWN"),
            taint_state=event.get("taint", "CLEAN"),
            authority_violated=bool(event.get("authority_violation", False)),
            policy_verdict=event.get("decision", "BLOCK"),
            sensitive_operations_attempted=1,
            sensitive_operations_executed=1 if event.get("decision") == "ALLOW" and event.get("taint") == "TAINTED" else 0,
            ai_secura_summary=event.get("ai_secura_summary") or event.get("threat_reason"),
            timeline=timeline,
        )

        self.incidents[incident.incident_id] = incident
        return incident

    def transition_state(self, incident_id: str, target_state: IncidentState, remediation_notes: Optional[str] = None) -> SecurityIncident:
        """Deterministically transition an incident's lifecycle state."""
        if incident_id not in self.incidents:
            raise KeyError(f"Incident with ID '{incident_id}' not found.")

        incident = self.incidents[incident_id]
        IncidentStateMachine.validate_transition(incident.state, target_state)
        incident.state = target_state
        if remediation_notes:
            incident.remediation_notes = remediation_notes
        incident.updated_at = datetime.now(timezone.utc)
        return incident

    def transition_incident_state(
        self,
        incident_id: str,
        to_state: IncidentState,
        actor: str = "system",
        reason: str = "",
    ) -> Optional[SecurityIncident]:
        """Transition incident state and append a timeline entry."""
        if incident_id not in self.incidents:
            return None

        incident = self.incidents[incident_id]
        IncidentStateMachine.validate_transition(incident.state, to_state)
        incident.state = to_state
        if reason:
            incident.remediation_notes = reason

        entry = IncidentTimelineEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            stage=f"Stage {to_state.value}",
            agent_id=incident.target_agent_id,
            action=f"Transitioned to {to_state.value}",
            detail=reason or f"State changed to {to_state.value}",
            actor_name=actor,
            incident_state=to_state,
        )
        incident.timeline.append(entry)
        incident.updated_at = datetime.now(timezone.utc)
        return incident

    def link_regression(self, incident_id: str, regression_id: str, secured_replay_passed: bool = True) -> SecurityIncident:
        """Attach verified regression fixture to incident and advance state."""
        if incident_id not in self.incidents:
            raise KeyError(f"Incident with ID '{incident_id}' not found.")

        incident = self.incidents[incident_id]
        incident.regression_id = regression_id
        incident.secured_replay_verified = secured_replay_passed
        if secured_replay_passed:
            incident.state = IncidentState.VALIDATED
        incident.updated_at = datetime.now(timezone.utc)
        return incident

    def get_incident(self, incident_id: str) -> Optional[SecurityIncident]:
        return self.incidents.get(incident_id)

    def list_incidents(self, state: Optional[IncidentState] = None) -> List[SecurityIncident]:
        if state:
            return [inc for inc in self.incidents.values() if inc.state == state]
        return list(self.incidents.values())



