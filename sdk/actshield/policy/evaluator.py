"""Deterministic policy evaluator enforcing security boundaries."""

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional
from actshield.agents.identity import AgentTrustLevel
from actshield.context.context import Context
from actshield.context.taint import TaintState
from actshield.decisions.decision import DecisionAction, SecurityDecision
from actshield.integrations.ai_secura import SecurityAnalysis, SecurityContext
from actshield.integrations.apiris import APIAnalysis
from actshield.policy.intent import DeterministicIntentAnalyzer, IntentAlignmentResult, IntentAnalyzer
from actshield.policy.policy import Policy
from actshield.risk.models import RiskFactorBreakdown, RiskLevel, RiskSignal
from actshield.tools.tool import SensitivityLevel, ToolDefinition, ToolRequest
from actshield.tracing.correlation import CorrelationContext, generate_id
from actshield.tracing.events import EventType

if TYPE_CHECKING:
    from actshield.client import ActShield


class PolicyEvaluator:
    """Deterministic security policy engine for actshield.
    
    Adheres strictly to the architectural principles:
    - AI reasons (AI Secura / Intent Analysis).
    - Deterministic policy evaluates signals, state, authority containment, intent alignment,
      and data taint to render decisions:
      ALLOW / MONITOR / HUMAN_APPROVAL / QUARANTINE / BLOCK / REVOKE.
    """

    def __init__(self, guard: "ActShield") -> None:
        self.guard = guard
        self.intent_analyzer: IntentAnalyzer = DeterministicIntentAnalyzer()
        self.default_policies: List[Policy] = []

    def evaluate(
        self,
        tool_def: ToolDefinition,
        request: ToolRequest,
        ctx: Optional[CorrelationContext],
        active_contexts: List[Context],
    ) -> SecurityDecision:
        trace_id = ctx.trace_id if ctx else generate_id("trc")
        evidence_refs: List[str] = []
        signals: List[RiskSignal] = []

        # 1. Resolve Acting Agent
        agent_id = request.agent_id or (ctx.agent_id if ctx else None)
        acting_agent = self.guard.agent_registry.get(agent_id) if agent_id else None

        # 2. Resolve Active Delegation Chain
        delegation_id = ctx.delegation_id if ctx else None
        active_delegation = self.guard.delegation_registry.get(delegation_id) if delegation_id else None

        if active_delegation:
            evidence_refs.append(active_delegation.delegation_id)

        # 3. Influencing Contexts & Taint Assessment
        influencing_ctx_ids = [c.context_id for c in active_contexts if c is not None]
        for c in active_contexts:
            if c.context_id and c.context_id not in evidence_refs:
                evidence_refs.append(c.context_id)

        has_tainted_context = any(c.taint_state in (TaintState.TAINTED, TaintState.UNTRUSTED) for c in active_contexts)
        has_untrusted_origin = any(c.source.value in ("external_mcp", "external_api") or c.trust_level == "untrusted" or c.taint_state == TaintState.UNTRUSTED for c in active_contexts)
        is_critical_sink = tool_def.sensitivity in (SensitivityLevel.HIGH, SensitivityLevel.CRITICAL)


        # 4. Authority Containment Evaluation
        authority_violation = False
        authority_reason = ""
        delegated_caps: List[str] = []

        if active_delegation is not None:
            delegated_caps = list(active_delegation.authority_grant.granted_capabilities)
            for req_cap in tool_def.required_capabilities:
                if not active_delegation.authority_grant.contains_capability(req_cap):
                    authority_violation = True
                    authority_reason = f"Delegated authority {delegated_caps} lacks required capability '{req_cap}'"
                    break
        elif acting_agent is not None:
            delegated_caps = acting_agent.capability_names()
            for req_cap in tool_def.required_capabilities:
                if not acting_agent.has_capability(req_cap):
                    authority_violation = True
                    authority_reason = f"Agent '{acting_agent.name}' does not possess declared capability '{req_cap}'"
                    break

        authority_containment_report = {
            "requesting_agent": acting_agent.name if acting_agent else agent_id,
            "required_capabilities": tool_def.required_capabilities,
            "delegated_capabilities": delegated_caps,
            "delegation_id": delegation_id,
            "contained": not authority_violation,
            "reason": authority_reason if authority_violation else "Authority containment verified.",
        }

        # 5. Intent Alignment Evaluation
        original_intent = ctx.metadata.get("intent", "Unspecified task intent") if ctx else "Unspecified task intent"
        target_res_name = tool_def.target_resources[0].name if tool_def.target_resources else None
        
        intent_res: IntentAlignmentResult = self.intent_analyzer.analyze(
            original_intent=original_intent,
            tool_name=tool_def.name,
            required_capabilities=tool_def.required_capabilities,
            target_resource_sensitivity=tool_def.sensitivity.value,
            target_resource_name=target_res_name,
            arguments=request.arguments,
        )
        intent_violation = intent_res.is_violation

        intent_alignment_report = {
            "original_intent": original_intent,
            "action_name": tool_def.name,
            "status": intent_res.status.value,
            "aligned": not intent_violation,
            "explanation": intent_res.explanation,
            "indicators": intent_res.matched_indicators,
        }

        # 6. Compute Deterministic Risk Breakdown
        risk_breakdown = RiskFactorBreakdown.compute(
            has_tainted_context=has_tainted_context,
            is_critical_sink=is_critical_sink,
            has_authority_violation=authority_violation,
            has_intent_violation=intent_violation,
            is_untrusted_origin=has_untrusted_origin,
        )

        # 7. Build Structured Explanation
        structured_explanation = {
            "agent": acting_agent.name if acting_agent else agent_id,
            "requested_tool": tool_def.name,
            "required_capabilities": tool_def.required_capabilities,
            "delegated_capabilities": delegated_caps,
            "authority_containment": "PASSED" if not authority_violation else "FAILED",
            "original_intent": original_intent,
            "intent_alignment": "PASSED" if not intent_violation else "FAILED",
            "context_sources": [c.source.value for c in active_contexts],
            "context_taint_states": [c.taint_state.value for c in active_contexts],
            "sensitive_sink": target_res_name or tool_def.name,
            "sink_sensitivity": tool_def.sensitivity.value,
            "risk_factors": risk_breakdown.risk_factors,
            "total_risk_score": risk_breakdown.total_score,
        }

        # 8. Deterministic Decision Rule Evaluations
        # Rule 8a: Authority Escalation Violation -> BLOCK
        if authority_violation:
            reason_code = "DELEGATION_AUTHORITY_EXCEEDED" if active_delegation else "MISSING_AGENT_CAPABILITY"
            explanation = (
                f"Agent '{acting_agent.name if acting_agent else agent_id}' was delegated authority "
                f"lacking required capability '{tool_def.required_capabilities}' for tool '{tool_def.name}'."
                if active_delegation else
                f"Agent '{acting_agent.name if acting_agent else agent_id}' does not possess declared capability "
                f"required to invoke tool '{tool_def.name}'."
            )
            decision = SecurityDecision(
                action=DecisionAction.BLOCK,
                risk_level=RiskLevel.HIGH if risk_breakdown.total_score < 0.7 else RiskLevel.CRITICAL,
                risk_score=risk_breakdown.total_score,
                reason_code=reason_code,
                explanation=explanation,
                trace_id=trace_id,
                evidence_references=evidence_refs,
                influencing_context_ids=influencing_ctx_ids,
                authority_containment=authority_containment_report,
                intent_alignment=intent_alignment_report,
                risk_breakdown=risk_breakdown,
                structured_explanation=structured_explanation,
            )
            self._emit_decision_events(tool_def, request, decision)
            return decision

        # Rule 8b: Tainted Context flowing into Sensitive Sink -> BLOCK
        if has_tainted_context and is_critical_sink:
            if self.guard.config.block_tainted_sink_access:
                decision = SecurityDecision(
                    action=DecisionAction.BLOCK,
                    risk_level=RiskLevel.CRITICAL,
                    risk_score=risk_breakdown.total_score,
                    reason_code="TAINTED_CONTEXT_INTO_SENSITIVE_SINK",
                    explanation=(
                        f"Tainted or injected context attempted to flow into {tool_def.sensitivity.value} "
                        f"sensitive tool/resource '{tool_def.name}' without explicit verification/sanitization."
                    ),
                    trace_id=trace_id,
                    evidence_references=evidence_refs,
                    influencing_context_ids=influencing_ctx_ids,
                    authority_containment=authority_containment_report,
                    intent_alignment=intent_alignment_report,
                    risk_breakdown=risk_breakdown,
                    structured_explanation=structured_explanation,
                )
                self._emit_decision_events(tool_def, request, decision)
                return decision

        # Rule 8c: Untrusted Agent Sensitive Access -> BLOCK
        if acting_agent is not None and acting_agent.trust_level == AgentTrustLevel.UNTRUSTED and tool_def.sensitivity != SensitivityLevel.LOW:
            decision = SecurityDecision(
                action=DecisionAction.BLOCK,
                risk_level=RiskLevel.HIGH,
                risk_score=risk_breakdown.total_score,
                reason_code="UNTRUSTED_AGENT_SENSITIVE_ACCESS",
                explanation=f"Untrusted agent '{acting_agent.name}' is prohibited from invoking {tool_def.sensitivity.value} tool '{tool_def.name}'.",
                trace_id=trace_id,
                evidence_references=evidence_refs,
                influencing_context_ids=influencing_ctx_ids,
                authority_containment=authority_containment_report,
                intent_alignment=intent_alignment_report,
                risk_breakdown=risk_breakdown,
                structured_explanation=structured_explanation,
            )
            self._emit_decision_events(tool_def, request, decision)
            return decision

        # Rule 8d: User Intent Alignment Violation -> BLOCK
        if intent_violation and is_critical_sink:
            decision = SecurityDecision(
                action=DecisionAction.BLOCK,
                risk_level=RiskLevel.HIGH,
                risk_score=risk_breakdown.total_score,
                reason_code="INTENT_ALIGNMENT_VIOLATION",
                explanation=intent_res.explanation,
                trace_id=trace_id,
                evidence_references=evidence_refs,
                influencing_context_ids=influencing_ctx_ids,
                authority_containment=authority_containment_report,
                intent_alignment=intent_alignment_report,
                risk_breakdown=risk_breakdown,
                structured_explanation=structured_explanation,
            )
            self._emit_decision_events(tool_def, request, decision)
            return decision

        # Rule 8e: Default Allowed / Monitored
        action = DecisionAction.ALLOW if risk_breakdown.total_score < 0.4 else DecisionAction.MONITOR
        decision = SecurityDecision(
            action=action,
            risk_level=RiskLevel.LOW if action == DecisionAction.ALLOW else RiskLevel.MEDIUM,
            risk_score=risk_breakdown.total_score,
            reason_code="POLICY_ALLOW_STANDARD" if action == DecisionAction.ALLOW else "RISK_MONITORED",
            explanation="Action permitted under standard security policy." if action == DecisionAction.ALLOW else "Action permitted under continuous security monitoring.",
            trace_id=trace_id,
            evidence_references=evidence_refs,
            influencing_context_ids=influencing_ctx_ids,
            authority_containment=authority_containment_report,
            intent_alignment=intent_alignment_report,
            risk_breakdown=risk_breakdown,
            structured_explanation=structured_explanation,
        )

        self._emit_decision_events(tool_def, request, decision)
        return decision

    def _emit_decision_events(
        self,
        tool_def: ToolDefinition,
        request: ToolRequest,
        decision: SecurityDecision,
    ) -> None:
        """Emit security.evaluated and security.decision events to the tracer."""
        self.guard.emit_event(
            event_type=EventType.SECURITY_EVALUATED,
            trace_id=decision.trace_id,
            agent_id=request.agent_id,
            payload={
                "tool_id": tool_def.tool_id,
                "tool_name": tool_def.name,
                "risk_score": decision.risk_score,
                "risk_level": decision.risk_level.value,
                "authority_contained": decision.authority_containment.get("contained", True),
                "intent_aligned": decision.intent_alignment.get("aligned", True),
            }
        )

        self.guard.emit_event(
            event_type=EventType.SECURITY_DECISION,
            trace_id=decision.trace_id,
            agent_id=request.agent_id,
            payload={
                "decision_id": decision.decision_id,
                "action": decision.action.value,
                "reason_code": decision.reason_code,
                "explanation": decision.explanation,
                "risk_score": decision.risk_score,
                "evidence_references": decision.evidence_references,
                "influencing_context_ids": decision.influencing_context_ids,
                "structured_explanation": decision.structured_explanation,
            }
        )


