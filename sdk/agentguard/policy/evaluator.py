"""Deterministic policy evaluator enforcing security boundaries."""

from datetime import datetime, timezone
from typing import TYPE_CHECKING, List, Optional
from agentguard.agents.identity import AgentTrustLevel
from agentguard.context.context import Context
from agentguard.context.taint import TaintState
from agentguard.decisions.decision import DecisionAction, SecurityDecision
from agentguard.integrations.ai_secura import SecurityAnalysis, SecurityContext
from agentguard.integrations.apiris import APIAnalysis
from agentguard.policy.policy import Policy
from agentguard.risk.models import RiskLevel, RiskSignal
from agentguard.tools.tool import SensitivityLevel, ToolDefinition, ToolRequest
from agentguard.tracing.correlation import CorrelationContext, generate_id
from agentguard.tracing.events import EventType

if TYPE_CHECKING:
    from agentguard.client import AgentGuard


class PolicyEvaluator:
    """Deterministic security policy engine for AgentGuard.
    
    Adheres strictly to the architectural principle:
    - AI (AI Secura) and APIRIS provide intelligence and reasoning signals.
    - Deterministic policy evaluates signals, state, and rules to decide enforcement:
      ALLOW / MONITOR / HUMAN_APPROVAL / QUARANTINE / BLOCK / REVOKE.
    """

    def __init__(self, guard: "AgentGuard") -> None:
        self.guard = guard
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

        # 3. Monotonic Capability & Authority Containment Check
        if tool_def.required_capabilities:
            for req_cap in tool_def.required_capabilities:
                # Check delegation grant first if in a delegated scope
                if active_delegation is not None:
                    if not active_delegation.authority_grant.contains_capability(req_cap):
                        decision = SecurityDecision(
                            action=DecisionAction.BLOCK,
                            risk_level=RiskLevel.HIGH,
                            risk_score=0.9,
                            reason_code="DELEGATION_AUTHORITY_EXCEEDED",
                            explanation=(
                                f"Agent '{acting_agent.name if acting_agent else agent_id}' was delegated authority "
                                f"lacking required capability '{req_cap}' for tool '{tool_def.name}'."
                            ),
                            trace_id=trace_id,
                            evidence_references=evidence_refs,
                        )
                        self._emit_decision_events(tool_def, request, decision)
                        return decision

                # Check agent's own declared capabilities
                elif acting_agent is not None:
                    if not acting_agent.has_capability(req_cap):
                        decision = SecurityDecision(
                            action=DecisionAction.BLOCK,
                            risk_level=RiskLevel.HIGH,
                            risk_score=0.85,
                            reason_code="MISSING_AGENT_CAPABILITY",
                            explanation=(
                                f"Agent '{acting_agent.name}' does not possess declared capability '{req_cap}' "
                                f"required to invoke tool '{tool_def.name}'."
                            ),
                            trace_id=trace_id,
                            evidence_references=evidence_refs,
                        )
                        self._emit_decision_events(tool_def, request, decision)
                        return decision

        # 4. Agent Trust Level vs Tool Sensitivity Check
        if acting_agent is not None:
            if acting_agent.trust_level == AgentTrustLevel.UNTRUSTED and tool_def.sensitivity != SensitivityLevel.LOW:
                decision = SecurityDecision(
                    action=DecisionAction.BLOCK,
                    risk_level=RiskLevel.HIGH,
                    risk_score=0.8,
                    reason_code="UNTRUSTED_AGENT_SENSITIVE_ACCESS",
                    explanation=f"Untrusted agent '{acting_agent.name}' is prohibited from invoking {tool_def.sensitivity.value} tool '{tool_def.name}'.",
                    trace_id=trace_id,
                    evidence_references=evidence_refs,
                )
                self._emit_decision_events(tool_def, request, decision)
                return decision

        # 5. Taint Propagation & Sensitive Sink Governance
        taint_states = [c.taint_state for c in active_contexts if c is not None]
        for c in active_contexts:
            if c.context_id:
                evidence_refs.append(c.context_id)

        has_taint = any(t in (TaintState.TAINTED, TaintState.UNTRUSTED) for t in taint_states)
        if has_taint and tool_def.sensitivity in (SensitivityLevel.HIGH, SensitivityLevel.CRITICAL):
            if self.guard.config.block_tainted_sink_access:
                decision = SecurityDecision(
                    action=DecisionAction.BLOCK,
                    risk_level=RiskLevel.CRITICAL,
                    risk_score=0.95,
                    reason_code="TAINTED_CONTEXT_INTO_SENSITIVE_SINK",
                    explanation=(
                        f"Tainted or untrusted context attempted to flow into {tool_def.sensitivity.value} "
                        f"sensitive tool/resource '{tool_def.name}' without verification."
                    ),
                    trace_id=trace_id,
                    evidence_references=evidence_refs,
                )
                self._emit_decision_events(tool_def, request, decision)
                return decision

        # 6. APIRIS Tool & API Intelligence Analysis
        apiris_adapter = self.guard.apiris_adapter
        if apiris_adapter is not None:
            apiris_res: APIAnalysis = apiris_adapter.analyze(request)
            signals.extend(apiris_res.signals)
            if apiris_res.recommended_action == "BLOCK" or apiris_res.risk_score >= self.guard.config.default_risk_threshold:
                decision = SecurityDecision(
                    action=DecisionAction.BLOCK,
                    risk_level=RiskLevel.HIGH if apiris_res.risk_score < 0.9 else RiskLevel.CRITICAL,
                    risk_score=apiris_res.risk_score,
                    reason_code="APIRIS_API_RISK_REJECTED",
                    explanation=f"APIRIS intelligence engine flagged tool request '{tool_def.name}' as dangerous: score={apiris_res.risk_score}.",
                    trace_id=trace_id,
                    evidence_references=evidence_refs,
                )
                self._emit_decision_events(tool_def, request, decision)
                return decision

        # 7. AI Secura Security Reasoning
        ai_secura_adapter = self.guard.ai_secura_adapter
        if ai_secura_adapter is not None:
            sec_ctx = SecurityContext(
                trace_id=trace_id,
                task_intent=ctx.metadata.get("intent", "unspecified") if ctx else "unspecified",
                acting_agent_id=agent_id,
                acting_agent_name=acting_agent.name if acting_agent else None,
                acting_agent_trust=acting_agent.trust_level.value if acting_agent else None,
                delegation_chain=[d.model_dump() for d in self.guard.delegation_registry.values() if d.trace_id == trace_id],
                context_provenance=[c.provenance.model_dump() for c in active_contexts],
                taint_states=[t.value for t in taint_states],
                tool_name=tool_def.name,
                tool_arguments=request.arguments,
                target_resource_sensitivity=tool_def.sensitivity.value,
            )
            ai_analysis: SecurityAnalysis = ai_secura_adapter.analyze(sec_ctx)
            signals.extend(ai_analysis.signals)

            if ai_analysis.intent_drift_detected and tool_def.sensitivity in (SensitivityLevel.HIGH, SensitivityLevel.CRITICAL):
                decision = SecurityDecision(
                    action=DecisionAction.BLOCK,
                    risk_level=RiskLevel.CRITICAL,
                    risk_score=ai_analysis.risk_score,
                    reason_code="AI_SECURA_INTENT_DRIFT_DETECTED",
                    explanation=f"AI Secura detected critical intent drift: {ai_analysis.summary}",
                    trace_id=trace_id,
                    evidence_references=evidence_refs,
                )
                self._emit_decision_events(tool_def, request, decision)
                return decision

        # 8. Compute Aggregate Risk Score and Render Decision
        max_signal_score = max([s.score for s in signals], default=0.0)
        
        if max_signal_score >= self.guard.config.default_risk_threshold:
            action = DecisionAction.BLOCK
            level = RiskLevel.CRITICAL if max_signal_score >= 0.85 else RiskLevel.HIGH
        elif max_signal_score >= 0.4:
            action = DecisionAction.MONITOR
            level = RiskLevel.MEDIUM
        else:
            action = DecisionAction.ALLOW
            level = RiskLevel.LOW

        decision = SecurityDecision(
            action=action,
            risk_level=level,
            risk_score=max_signal_score,
            reason_code="POLICY_ALLOW_STANDARD" if action == DecisionAction.ALLOW else "RISK_MONITORED",
            explanation="Action permitted under standard security policy." if action == DecisionAction.ALLOW else "Action permitted under continuous security monitoring.",
            trace_id=trace_id,
            evidence_references=evidence_refs,
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
            }
        )
