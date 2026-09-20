"""AgentGuard Incidents Engine Package (Phase 9)."""

from agentguard.incidents.incident import IncidentTimelineEntry, SecurityIncident
from agentguard.incidents.incident_engine import IncidentEngine, IncidentTimelineBuilder
from agentguard.incidents.incident_rules import IncidentCreationRule
from agentguard.incidents.incident_state import (
    ALLOWED_TRANSITIONS,
    IncidentSeverity,
    IncidentState,
    IncidentStateMachine,
)

__all__ = [
    "IncidentTimelineEntry",
    "SecurityIncident",
    "IncidentEngine",
    "IncidentTimelineBuilder",
    "IncidentCreationRule",
    "ALLOWED_TRANSITIONS",
    "IncidentSeverity",
    "IncidentState",
    "IncidentStateMachine",
]
