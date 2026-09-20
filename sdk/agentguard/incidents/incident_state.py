"""Incident Lifecycle States and Deterministic State Transition Machine (Phase 9).

Lifecycle:
DETECTED -> TRIAGED -> INVESTIGATING -> CONTAINED -> REMEDIATED -> VALIDATED -> CLOSED

Note:
AI may provide analytical enrichment. Deterministic logic strictly governs state transitions.
"""

from enum import Enum
from typing import List, Set


class IncidentState(str, Enum):
    """Deterministic security incident states."""
    DETECTED = "DETECTED"
    TRIAGED = "TRIAGED"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    REMEDIATED = "REMEDIATED"
    VALIDATED = "VALIDATED"
    CLOSED = "CLOSED"


class IncidentSeverity(str, Enum):
    """Incident severity classification."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# Valid deterministic state transitions
ALLOWED_TRANSITIONS: dict[IncidentState, Set[IncidentState]] = {
    IncidentState.DETECTED: {IncidentState.TRIAGED, IncidentState.INVESTIGATING, IncidentState.CONTAINED, IncidentState.CLOSED},
    IncidentState.TRIAGED: {IncidentState.INVESTIGATING, IncidentState.CONTAINED, IncidentState.CLOSED},
    IncidentState.INVESTIGATING: {IncidentState.CONTAINED, IncidentState.REMEDIATED, IncidentState.CLOSED},
    IncidentState.CONTAINED: {IncidentState.REMEDIATED, IncidentState.VALIDATED, IncidentState.CLOSED},
    IncidentState.REMEDIATED: {IncidentState.VALIDATED, IncidentState.CLOSED, IncidentState.INVESTIGATING},
    IncidentState.VALIDATED: {IncidentState.CLOSED, IncidentState.INVESTIGATING},
    IncidentState.CLOSED: {IncidentState.INVESTIGATING},  # Reopen if needed
}


class IncidentStateMachine:
    """Validates and enforces deterministic incident lifecycle transitions."""

    @staticmethod
    def can_transition(current: IncidentState, target: IncidentState) -> bool:
        return target in ALLOWED_TRANSITIONS.get(current, set())

    @staticmethod
    def validate_transition(current: IncidentState, target: IncidentState) -> None:
        if not IncidentStateMachine.can_transition(current, target):
            raise ValueError(
                f"Invalid incident state transition from '{current.value}' to '{target.value}'. "
                f"Allowed transitions: {[s.value for s in ALLOWED_TRANSITIONS.get(current, set())]}"
            )
