"""Deterministic forensic explainer — assembles evidence-backed explanations.

The explanation is assembled from ACTUAL recorded evidence.
No LLM is called. No AI invents the explanation.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List, Optional

from actshield.forensics.models import (
    AccessDecision,
    AttackForensicReport,
    ForensicExplanation,
    ForensicIncident,
    IncidentSeverity,
    IncidentStatus,
    IncidentType,
)

if TYPE_CHECKING:
    from actshield.forensics.service import ForensicService


class ForensicExplainer:
    """Builds deterministic forensic explanations from recorded evidence.

    Source of truth chain:
      SecurityDecision → structured_explanation → authority_containment
      → intent_alignment → risk_breakdown + SecurityAnalysisEvidence
    """

    def __init__(self, service: "ForensicService") -> None:
        self._svc = service

    def explain_decision(
        self,
        event_id: Optional[str] = None,
        trace_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        tool_name: Optional[str] = None,
        decision_dict: Optional[Dict[str, Any]] = None,
    ) -> ForensicExplanation:
        """Build a forensic explanation from a stored security decision.

        Falls back to the decision_dict if no storage record is found.
        """
        resolved_decision: Dict[str, Any] = {}

        # Try to pull from storage by trace_id
        if trace_id and self._svc._guard.storage:
            stored = self._svc._guard.storage.get_decisions(trace_id=trace_id, limit=1)
            if stored:
                resolved_decision = stored[0]

        # Merge with provided dict
        if decision_dict:
            resolved_decision.update(decision_dict)

        structured = resolved_decision.get("details_json") or {}
        if isinstance(structured, str):
            import json
            try:
                structured = json.loads(structured)
            except Exception:
                structured = {}

        se = structured.get("structured_explanation", {})
        auth = structured.get("authority_containment", {})
        intent = structured.get("intent_alignment", {})

        # Map decision action to AccessDecision
        action_str = resolved_decision.get("action", "UNKNOWN").upper()
        try:
            policy_decision = AccessDecision(action_str)
        except ValueError:
            policy_decision = AccessDecision.UNKNOWN

        # Influencing context — from the access graph
        attempts = self._svc.access_graph.get_agent_attempts(agent_id or "")
        related = [a for a in attempts if a.tool_name == (tool_name or "")]
        context_sources = []
        context_ids = []
        taint_state = "CLEAN"
        if related:
            latest = related[-1]
            context_ids = latest.context_ids
            taint_state = latest.taint_state

        # Context sources from structured explanation
        context_sources = se.get("context_sources", [])

        # Delegated authority
        delegated_caps = se.get("delegated_capabilities", [])
        if isinstance(delegated_caps, str):
            delegated_caps = [delegated_caps] if delegated_caps else []

        effective_authority = "GRANTED" if auth.get("contained", False) else "DENIED"

        # AI/APIRIS summaries
        ai_summary = None
        apiris_summary = None
        if agent_id:
            for attempt in self._svc.access_graph.get_agent_attempts(agent_id):
                if attempt.tool_name == (tool_name or ""):
                    # Check access graph for security evidence references
                    pass

        return ForensicExplanation(
            event_id=event_id,
            trace_id=trace_id or resolved_decision.get("trace_id"),
            agent_id=agent_id or se.get("agent", ""),
            tool_name=tool_name or se.get("requested_tool", ""),
            resource_name=se.get("sensitive_sink"),
            resource_sensitivity=se.get("sink_sensitivity", "UNKNOWN"),
            original_intent=intent.get("original_intent", "Unspecified"),
            influencing_context_sources=context_sources,
            influencing_context_ids=context_ids,
            context_trust="UNTRUSTED" if taint_state == "TAINTED" else "TRUSTED",
            taint_state=taint_state,
            delegated_authority=delegated_caps,
            requested_capability=(
                se.get("required_capabilities", [None])[0]
                if isinstance(se.get("required_capabilities"), list)
                else se.get("required_capabilities")
            ),
            effective_authority=effective_authority,
            policy_decision=policy_decision,
            policy_reason_code=resolved_decision.get("reason_code", ""),
            policy_explanation=resolved_decision.get("explanation", ""),
            ai_secura_summary=ai_summary,
            apiris_summary=apiris_summary,
            tool_executed=False,
            execution_count=0,
        )

    def explain_attack(
        self, attack_id: str
    ) -> Optional[AttackForensicReport]:
        """Build an AttackForensicReport from Phase 5 evidence."""
        result = self._svc._attack_results.get(attack_id)
        if result is None:
            return None

        ev = result.security_evidence
        lineage = result.mutation_lineage

        # Reachable resources for acting agent
        agent_id = ev.acting_agent if ev else ""
        reachable = []
        if agent_id and self._svc._calculator:
            reachable = self._svc._calculator.get_reachable_resources(agent_id)

        ai_summary = None
        apiris_summary = None
        if ev:
            if ev.ai_analysis and not ev.ai_unavailable:
                ai_summary = str(
                    ev.ai_analysis.get("threat_classification") or
                    ev.ai_analysis.get("security_level") or ""
                )
            if ev.apiris_analysis and not ev.apiris_unavailable:
                apiris_summary = str(
                    ev.apiris_analysis.get("risk_level") or
                    ev.apiris_analysis.get("classification") or ""
                )

        try:
            policy_dec = AccessDecision(result.actual_decision.upper())
        except ValueError:
            policy_dec = AccessDecision.UNKNOWN

        return AttackForensicReport(
            attack_id=attack_id,
            campaign_id=result.campaign_id,
            attack_type=result.attack_type.value,
            target=result.target,
            entry_point=result.entry_point,
            agent_id=agent_id,
            trace_id=result.trace_id,
            original_intent=ev.task_intent if ev else "",
            mutation_lineage=lineage,
            adaptive_iteration=getattr(result, "adaptive_iteration", 0),
            influencing_contexts=ev.context_ids if ev else [],
            context_trust="UNTRUSTED" if (ev and ev.taint_state == "TAINTED") else "TRUSTED",
            taint_state=ev.taint_state if ev else "UNKNOWN",
            delegated_capabilities=ev.delegated_capabilities if ev else [],
            requested_capability=ev.requested_capability if ev else None,
            effective_capabilities=ev.delegated_capabilities if ev else [],
            authority_contained=ev.authority_contained if ev else True,
            resource_name=None,
            apiris_summary=apiris_summary,
            ai_secura_summary=ai_summary,
            risk_score=ev.risk_score if ev else 0.0,
            policy_decision=policy_dec,
            policy_reason_code=ev.policy_reason_code if ev else "",
            policy_explanation=ev.policy_explanation if ev else "",
            tool_executed=result.actual_execution,
            execution_count=result.execution_evidence.execution_count,
            sensitive_db_calls=result.execution_evidence.sensitive_db_calls,
            actual_access=result.actual_execution,
            reachable_resources=reachable,
            bypassed=result.bypassed,
            expected_decision=result.expected_decision,
            actual_decision=result.actual_decision,
            regression_status=(
                "REGRESSION_CREATED" if result.bypassed else "NONE"
            ),
        )

    def classify_incident(
        self, attempt: "ForensicExplanation"
    ) -> IncidentType:
        """Classify incident type deterministically from the explanation."""
        if attempt.bypass_detected:
            return IncidentType.BYPASS_DETECTED
        reason = attempt.policy_reason_code
        if "TAINTED" in reason:
            return IncidentType.TAINT_PROPAGATION
        if "AUTHORITY" in reason or "DELEGATION" in reason:
            return IncidentType.AUTHORITY_ESCALATION
        if "CAPABILITY" in reason or "MISSING" in reason:
            return IncidentType.CAPABILITY_VIOLATION
        if "INTENT" in reason:
            return IncidentType.INTENT_VIOLATION
        if "UNTRUSTED" in reason:
            return IncidentType.UNTRUSTED_SENSITIVE_ACCESS
        return IncidentType.GENERIC

    def build_incident(
        self, explanation: ForensicExplanation
    ) -> ForensicIncident:
        """Build a ForensicIncident from an explanation (uses IDs, no duplication)."""
        severity = (
            IncidentSeverity.CRITICAL
            if explanation.resource_sensitivity == "CRITICAL"
            else IncidentSeverity.HIGH
            if explanation.policy_decision == AccessDecision.BLOCK
            else IncidentSeverity.MEDIUM
        )
        return ForensicIncident(
            incident_type=self.classify_incident(explanation),
            severity=severity,
            agent_id=explanation.agent_id,
            resource_name=explanation.resource_name,
            tool_name=explanation.tool_name,
            decision=explanation.policy_decision,
            executed=explanation.tool_executed,
            trace_id=explanation.trace_id,
            attack_id=explanation.bypass_attack_id,
            status=IncidentStatus.CONTAINED,
            description=explanation.policy_explanation,
        )

