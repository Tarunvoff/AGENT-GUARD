"""Deterministic rules for automatic incident creation in ActShield Phase 9."""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple
from actshield.incidents.incident_state import IncidentSeverity


class IncidentCreationRule:
    """Evaluates runtime security event signals to determine if an incident must be generated."""

    @staticmethod
    def evaluate(event: Dict[str, Any]) -> Tuple[bool, Optional[str], IncidentSeverity, Optional[str]]:
        """
        Evaluate an event dictionary or security payload.
        Returns: (should_create_incident, title, severity, attack_type)
        """
        decision = str(event.get("decision", "")).upper()
        taint = str(event.get("taint", "")).upper()
        res_sens = str(event.get("resource_sensitivity", "")).upper()
        auth_violation = bool(event.get("authority_violation", False))
        bypass_detected = bool(event.get("bypass_detected", False))
        attack_type = event.get("attack_type") or event.get("threat_type") or "policy_violation"

        # Rule 1: CRITICAL INVARIANT — Actual unauthorized execution
        if decision == "ALLOW" and (taint == "TAINTED" or auth_violation) and res_sens in ("HIGH", "CRITICAL"):
            return (
                True,
                f"CRITICAL: Actual Unauthorized Execution on {event.get('resource', event.get('tool', 'Sensitive Resource'))}",
                IncidentSeverity.CRITICAL,
                "unauthorized_execution_bypass",
            )

        # Rule 2: Offensive Bypass Discovered
        if bypass_detected:
            return (
                True,
                f"Offensive Validation Bypass Detected: {event.get('variant_name', attack_type)}",
                IncidentSeverity.HIGH,
                "offensive_validation_bypass",
            )

        # Rule 3: Tainted context attempting high/critical resource
        if taint in ("TAINTED", "UNTRUSTED") and (res_sens in ("HIGH", "CRITICAL") or decision == "BLOCK"):
            return (
                True,
                f"Tainted Context Propagation to Sensitive Target: {event.get('tool', 'tool')}",
                IncidentSeverity.HIGH,
                "indirect_prompt_injection" if "injection" in attack_type.lower() else "tainted_data_propagation",
            )

        # Rule 4: Authority Boundary Escape Attempt
        if auth_violation or "authority" in str(event.get("reason", "")).lower():
            return (
                True,
                f"Delegated Authority Boundary Violation: {event.get('agent_id', 'Agent')} attempted {event.get('tool', 'action')}",
                IncidentSeverity.MEDIUM,
                "authority_escalation",
            )

        # Rule 5: Blocked Privileged Tool Execution
        if decision == "BLOCK" and res_sens in ("HIGH", "CRITICAL"):
            return (
                True,
                f"Blocked High-Risk Tool Request on {event.get('tool', 'tool')}",
                IncidentSeverity.MEDIUM,
                attack_type,
            )

        return (False, None, IncidentSeverity.LOW, None)

    @staticmethod
    def evaluate_threat_event(
        threat_type: str,
        severity: IncidentSeverity,
        title: str,
        description: str,
        source_context_id: Optional[str] = None,
        target_agent_id: Optional[str] = None,
        tool_name: Optional[str] = None,
        root_cause: Optional[str] = None,
        evidence_event_ids: Optional[List[str]] = None,
    ) -> Any:
        """Construct a SecurityIncident directly from threat analysis signals."""
        from actshield.incidents.incident import IncidentTimelineEntry, SecurityIncident
        from actshield.incidents.incident_state import IncidentState
        from datetime import datetime, timezone

        timeline = [
            IncidentTimelineEntry(
                timestamp=datetime.now(timezone.utc).isoformat(),
                stage="01. DETECTED",
                agent_id=target_agent_id,
                action=f"Detected {threat_type} on {tool_name or 'resource'}",
                detail=description,
                taint_state="UNTRUSTED",
                decision="BLOCK",
                actor_name="detection_engine",
                incident_state=IncidentState.DETECTED,
            )
        ]

        return SecurityIncident(
            title=title,
            severity=severity,
            state=IncidentState.DETECTED,
            attack_type=threat_type,
            affected_agents=[target_agent_id] if target_agent_id else [],
            affected_resources=[tool_name] if tool_name else [],
            ai_secura_summary=root_cause or description,
            timeline=timeline,
            remediation_notes=root_cause,
        )



