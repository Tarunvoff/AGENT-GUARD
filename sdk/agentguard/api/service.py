"""ApiService — programmatic API layer over ForensicService.

This is the backend contract the dashboard consumes.
Returns clean Pydantic models that serialize to JSON.

Authentication/Authorization:
    SecurityPrincipal interface provided for future extension.
    Development mode allows unauthenticated access.

Observability:
    All responses carry request_id for correlation:
    Dashboard request → API request_id → Forensic query → trace_id
"""

from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional

from agentguard.api.models import (
    AccessMatrixResponse,
    AgentAccessResponse,
    AgentSummary,
    AttackForensicsResponse,
    AttackSummary,
    CampaignSummary,
    DiffResponse,
    ErrorResponse,
    HealthResponse,
    IncidentResponse,
    OverviewResponse,
    PolicyEvaluateRequest,
    PolicyEvaluateResponse,
    ResourceAccessResponse,
    SnapshotSummary,
)
from agentguard.forensics.service import ForensicService


def _new_request_id() -> str:
    return f"req_{uuid.uuid4().hex[:12]}"


class SecurityPrincipal:
    """Extensible auth principal. Development mode: all principals are ADMIN."""

    class Permission:
        READ_RUNTIME = "READ_RUNTIME"
        READ_FORENSICS = "READ_FORENSICS"
        READ_ATTACKS = "READ_ATTACKS"
        READ_POLICIES = "READ_POLICIES"
        ADMIN = "ADMIN"

    def __init__(self, permissions: Optional[List[str]] = None, dev_mode: bool = True) -> None:
        self.permissions = permissions or [self.Permission.ADMIN]
        self.dev_mode = dev_mode

    def can(self, permission: str) -> bool:
        if self.dev_mode:
            return True
        return permission in self.permissions or self.Permission.ADMIN in self.permissions


class ApiService:
    """Unified product API service.

    Wraps ForensicService and exposes clean endpoint-equivalent methods.
    Each method mirrors a REST endpoint conceptually.
    """

    VERSION = "1.0.0"

    def __init__(
        self,
        forensic_service: ForensicService,
        dev_mode: bool = True,
    ) -> None:
        self._fs = forensic_service
        self._principal = SecurityPrincipal(dev_mode=dev_mode)

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    def get_health(self) -> HealthResponse:
        """GET /api/v1/health"""
        return HealthResponse(
            status="ok",
            version=self.VERSION,
            components={
                "forensic_service": "ok",
                "authority_graph": "ok",
                "access_graph": "ok",
                "storage": "ok" if self._fs._guard.storage else "unavailable",
            },
        )

    def get_ready(self) -> Dict[str, Any]:
        """GET /api/v1/ready"""
        return {"ready": True, "version": self.VERSION}

    # ------------------------------------------------------------------
    # Overview
    # ------------------------------------------------------------------

    def get_overview(self) -> OverviewResponse:
        """GET /api/v1/overview"""
        data = self._fs.query.get_overview()
        return OverviewResponse(**{k: data.get(k) for k in OverviewResponse.model_fields})

    # ------------------------------------------------------------------
    # Agents
    # ------------------------------------------------------------------

    def list_agents(self) -> List[AgentSummary]:
        """GET /api/v1/agents"""
        summaries = []
        for agent_id in self._fs.query.get_all_agents():
            profile = self._fs.query.get_agent_access(agent_id)
            if profile:
                summaries.append(AgentSummary(
                    agent_id=profile.agent_id,
                    agent_name=profile.agent_name,
                    trust_level=profile.trust_level,
                    effective_capabilities=profile.effective_capabilities,
                    total_attempts=profile.total_attempts,
                    total_blocked=profile.total_blocked,
                ))
        return summaries

    def get_agent(self, agent_id: str) -> AgentSummary | ErrorResponse:
        """GET /api/v1/agents/{agent_id}"""
        rid = _new_request_id()
        profile = self._fs.query.get_agent_access(agent_id)
        if not profile:
            return ErrorResponse.make("AGENT_NOT_FOUND", f"Agent '{agent_id}' was not found", rid)
        return AgentSummary(
            agent_id=profile.agent_id,
            agent_name=profile.agent_name,
            trust_level=profile.trust_level,
            effective_capabilities=profile.effective_capabilities,
            total_attempts=profile.total_attempts,
            total_blocked=profile.total_blocked,
        )

    def get_agent_access(self, agent_id: str) -> AgentAccessResponse | ErrorResponse:
        """GET /api/v1/agents/{agent_id}/access"""
        rid = _new_request_id()
        profile = self._fs.query.get_agent_access(agent_id)
        if not profile:
            return ErrorResponse.make("AGENT_NOT_FOUND", f"Agent '{agent_id}' was not found", rid)
        return AgentAccessResponse(
            agent_id=profile.agent_id,
            agent_name=profile.agent_name,
            trust_level=profile.trust_level,
            declared=profile.declared_capabilities,
            delegated=profile.delegated_capabilities,
            effective=profile.effective_capabilities,
            restricted=profile.restricted_capabilities,
            reachable_tools=profile.reachable_tools,
            reachable_resources=profile.reachable_resources,
            total_attempts=profile.total_attempts,
            total_blocked=profile.total_blocked,
            total_allowed=profile.total_allowed,
            total_executions=profile.total_executions,
        )

    def get_agent_delegation(self, agent_id: str) -> List[Dict[str, Any]] | ErrorResponse:
        """GET /api/v1/agents/{agent_id}/delegation"""
        rid = _new_request_id()
        if agent_id not in self._fs._guard.agent_registry:
            return ErrorResponse.make("AGENT_NOT_FOUND", f"Agent '{agent_id}' was not found", rid)
        return self._fs.query.get_agent_delegation_chain(agent_id)

    def get_agent_attempts(self, agent_id: str) -> List[Dict[str, Any]] | ErrorResponse:
        """GET /api/v1/agents/{agent_id}/attempts"""
        rid = _new_request_id()
        if agent_id not in self._fs._guard.agent_registry:
            return ErrorResponse.make("AGENT_NOT_FOUND", f"Agent '{agent_id}' was not found", rid)
        return self._fs.query.get_agent_attempts(agent_id)

    def get_agent_actual_access(
        self, agent_id: str
    ) -> List[Dict[str, Any]] | ErrorResponse:
        """GET /api/v1/agents/{agent_id}/actual-access"""
        rid = _new_request_id()
        if agent_id not in self._fs._guard.agent_registry:
            return ErrorResponse.make("AGENT_NOT_FOUND", f"Agent '{agent_id}' was not found", rid)
        return self._fs.query.get_agent_actual_access(agent_id)

    # ------------------------------------------------------------------
    # Resources
    # ------------------------------------------------------------------

    def list_resources(self) -> List[str]:
        """GET /api/v1/resources"""
        return self._fs.query.get_all_resources()

    def get_resource(
        self, resource_name: str
    ) -> ResourceAccessResponse | ErrorResponse:
        """GET /api/v1/resources/{resource_id}"""
        rid = _new_request_id()
        profile = self._fs.query.get_resource_access(resource_name)
        if not profile:
            return ErrorResponse.make(
                "RESOURCE_NOT_FOUND", f"Resource '{resource_name}' was not found", rid
            )
        return ResourceAccessResponse(
            resource_id=profile.resource_id,
            resource_name=profile.resource_name,
            resource_type=profile.resource_type,
            sensitivity=profile.sensitivity,
            exposing_tools=profile.exposing_tools,
            authorized_agents=profile.authorized_agents,
            attempted_agents=profile.attempted_agents,
            actual_access_agents=profile.actual_access_agents,
            blocked_agents=profile.blocked_agents,
            total_attempts=profile.total_attempts,
            total_blocked=profile.total_blocked,
            total_executions=profile.total_executions,
        )

    def get_resource_history(
        self, resource_name: str
    ) -> List[Dict[str, Any]] | ErrorResponse:
        """GET /api/v1/resources/{resource_id}/history"""
        rid = _new_request_id()
        resources = self._fs.query.get_all_resources()
        if resource_name not in resources:
            return ErrorResponse.make(
                "RESOURCE_NOT_FOUND", f"Resource '{resource_name}' was not found", rid
            )
        return self._fs.query.get_resource_access_history(resource_name)

    # ------------------------------------------------------------------
    # Access matrix & snapshots
    # ------------------------------------------------------------------

    def get_access_matrix(self) -> AccessMatrixResponse:
        """GET /api/v1/access/matrix"""
        matrix = self._fs.query.get_access_matrix()
        table = matrix.to_table()
        eff_perms: Dict[str, Dict[str, bool]] = {}
        for agent_id, resources in matrix.entries.items():
            eff_perms[agent_id] = {
                r: e.effective_permission for r, e in resources.items()
            }
        return AccessMatrixResponse(
            matrix_id=matrix.matrix_id,
            agents=matrix.agents,
            resources=matrix.resources,
            table=table,
            effective_permissions=eff_perms,
        )

    def list_snapshots(self) -> List[SnapshotSummary]:
        """GET /api/v1/access/snapshots"""
        return [
            SnapshotSummary(**s)
            for s in self._fs.query.list_snapshots()
        ]

    def get_snapshot(
        self, snapshot_id: str
    ) -> Dict[str, Any] | ErrorResponse:
        """GET /api/v1/access/snapshots/{snapshot_id}"""
        rid = _new_request_id()
        snap = self._fs.query.get_access_snapshot(snapshot_id)
        if not snap:
            return ErrorResponse.make(
                "SNAPSHOT_NOT_FOUND", f"Snapshot '{snapshot_id}' was not found", rid
            )
        return snap.model_dump(mode="json")

    def get_access_diff(
        self, before_id: str, after_id: str
    ) -> DiffResponse | ErrorResponse:
        """GET /api/v1/access/diff?before=...&after=..."""
        rid = _new_request_id()
        diff = self._fs.query.compare_access_snapshots(before_id, after_id)
        if not diff:
            return ErrorResponse.make(
                "SNAPSHOT_NOT_FOUND",
                f"Could not compare snapshots '{before_id}' and '{after_id}'",
                rid,
            )
        return DiffResponse(
            diff_id=diff.diff_id,
            before_snapshot_id=diff.before_snapshot_id,
            after_snapshot_id=diff.after_snapshot_id,
            authority_changed=diff.authority_changed,
            new_capabilities=diff.new_capabilities,
            lost_capabilities=diff.lost_capabilities,
            attack_detected=diff.attack_detected,
            taint_changed=diff.taint_changed,
            context_changed=diff.context_changed,
            summary=diff.summary,
        )

    # ------------------------------------------------------------------
    # Traces
    # ------------------------------------------------------------------

    def get_trace(self, trace_id: str) -> Dict[str, Any] | ErrorResponse:
        """GET /api/v1/traces/{trace_id}"""
        rid = _new_request_id()
        graph_json = self._fs.query.get_causal_path(trace_id)
        if graph_json is None:
            return ErrorResponse.make(
                "TRACE_NOT_FOUND", f"Trace '{trace_id}' was not found", rid
            )
        import json
        try:
            return json.loads(graph_json)
        except Exception:
            return {"trace_id": trace_id, "graph": graph_json}

    # ------------------------------------------------------------------
    # Attacks
    # ------------------------------------------------------------------

    def list_attacks(self) -> List[AttackSummary]:
        """GET /api/v1/attacks"""
        summaries = []
        for attack_id, result in self._fs._attack_results.items():
            summaries.append(AttackSummary(
                attack_id=attack_id,
                campaign_id=result.campaign_id,
                attack_type=result.attack_type.value,
                target=result.target,
                entry_point=result.entry_point,
                expected_decision=result.expected_decision,
                actual_decision=result.actual_decision,
                bypassed=result.bypassed,
                tool_executed=result.actual_execution,
                execution_count=result.execution_evidence.execution_count,
            ))
        return summaries

    def get_attack(self, attack_id: str) -> AttackSummary | ErrorResponse:
        """GET /api/v1/attacks/{attack_id}"""
        rid = _new_request_id()
        result = self._fs._attack_results.get(attack_id)
        if not result:
            return ErrorResponse.make(
                "ATTACK_NOT_FOUND", f"Attack '{attack_id}' was not found", rid
            )
        return AttackSummary(
            attack_id=attack_id,
            campaign_id=result.campaign_id,
            attack_type=result.attack_type.value,
            target=result.target,
            entry_point=result.entry_point,
            expected_decision=result.expected_decision,
            actual_decision=result.actual_decision,
            bypassed=result.bypassed,
            tool_executed=result.actual_execution,
            execution_count=result.execution_evidence.execution_count,
        )

    def get_attack_lineage(
        self, attack_id: str
    ) -> Dict[str, Any] | ErrorResponse:
        """GET /api/v1/attacks/{attack_id}/lineage"""
        rid = _new_request_id()
        result = self._fs._attack_results.get(attack_id)
        if not result:
            return ErrorResponse.make(
                "ATTACK_NOT_FOUND", f"Attack '{attack_id}' was not found", rid
            )
        return {
            "attack_id": attack_id,
            "mutation_lineage": result.mutation_lineage,
            "adaptive_iteration": getattr(result, "adaptive_iteration", 0),
            "parent_attack_id": None,
        }

    def get_attack_forensics(
        self, attack_id: str
    ) -> AttackForensicsResponse | ErrorResponse:
        """GET /api/v1/attacks/{attack_id}/forensics"""
        rid = _new_request_id()
        report = self._fs.query.get_attack_forensics(attack_id)
        if not report:
            return ErrorResponse.make(
                "ATTACK_NOT_FOUND", f"Attack '{attack_id}' forensics not found", rid
            )
        return AttackForensicsResponse(
            report_id=report.report_id,
            attack_id=report.attack_id,
            campaign_id=report.campaign_id,
            attack_type=report.attack_type,
            target=report.target,
            agent_id=report.agent_id,
            original_intent=report.original_intent,
            mutation_lineage=report.mutation_lineage,
            taint_state=report.taint_state,
            policy_decision=report.policy_decision.value,
            policy_reason_code=report.policy_reason_code,
            tool_executed=report.tool_executed,
            execution_count=report.execution_count,
            sensitive_db_calls=report.sensitive_db_calls,
            bypassed=report.bypassed,
            reachable_resources=report.reachable_resources,
            regression_status=report.regression_status,
        )

    # ------------------------------------------------------------------
    # Campaigns
    # ------------------------------------------------------------------

    def list_campaigns(self) -> List[CampaignSummary]:
        """GET /api/v1/campaigns"""
        campaigns: Dict[str, Dict[str, Any]] = {}
        for result in self._fs._attack_results.values():
            cid = result.campaign_id or "unknown"
            if cid not in campaigns:
                campaigns[cid] = {"total": 0, "bypasses": 0, "blocks": 0}
            campaigns[cid]["total"] += 1
            if result.bypassed:
                campaigns[cid]["bypasses"] += 1
            if result.blocked:
                campaigns[cid]["blocks"] += 1
        return [
            CampaignSummary(
                campaign_id=cid,
                total_attacks=data["total"],
                bypasses=data["bypasses"],
                blocks=data["blocks"],
                bypass_rate=data["bypasses"] / data["total"] if data["total"] else 0.0,
            )
            for cid, data in campaigns.items()
        ]

    # ------------------------------------------------------------------
    # Incidents
    # ------------------------------------------------------------------

    def list_incidents(self) -> List[IncidentResponse]:
        """GET /api/v1/incidents"""
        return [
            IncidentResponse(
                incident_id=inc.incident_id,
                incident_type=inc.incident_type.value,
                severity=inc.severity.value,
                agent_id=inc.agent_id,
                resource_name=inc.resource_name,
                tool_name=inc.tool_name,
                decision=inc.decision.value,
                executed=inc.executed,
                trace_id=inc.trace_id,
                attack_id=inc.attack_id,
                status=inc.status.value,
                description=inc.description,
                timestamp=inc.timestamp.isoformat(),
            )
            for inc in self._fs.query.get_all_incidents()
        ]

    # ------------------------------------------------------------------
    # Regressions
    # ------------------------------------------------------------------

    def list_regressions(self) -> List[AttackSummary]:
        """GET /api/v1/regressions — bypass attacks are regressions."""
        return [
            s for s in self.list_attacks() if s.bypassed
        ]

    def get_regression(
        self, regression_id: str
    ) -> AttackForensicsResponse | ErrorResponse:
        """GET /api/v1/regressions/{regression_id}"""
        return self.get_attack_forensics(regression_id)

    # ------------------------------------------------------------------
    # Policies
    # ------------------------------------------------------------------

    def list_policies(self) -> List[Dict[str, Any]]:
        """GET /api/v1/policies — returns active policy configuration."""
        cfg = self._fs._guard.config
        return [
            {
                "policy_id": "p_tainted_sink",
                "name": "Block tainted context into sensitive sink",
                "enabled": cfg.block_tainted_sink_access,
                "action": "BLOCK",
            },
            {
                "policy_id": "p_monotonic_delegation",
                "name": "Enforce monotonic authority containment",
                "enabled": cfg.enforce_monotonic_delegation,
                "action": "BLOCK",
            },
        ]

    def evaluate_policy(
        self, request: PolicyEvaluateRequest
    ) -> PolicyEvaluateResponse:
        """POST /api/v1/policies/evaluate — simulate a policy check (READ-ONLY).

        This does NOT modify any security state.
        This does NOT grant any capabilities.
        """
        from agentguard.tools.tool import ToolDefinition, ToolRequest, SensitivityLevel
        from agentguard.context.context import Context
        from agentguard.context.taint import TaintState
        from agentguard.context.provenance import ContextSource, Provenance

        # Look up the tool definition
        tool_def = None
        for td in self._fs._guard.tool_registry.values():
            if td.name == request.tool_name:
                tool_def = td
                break

        if tool_def is None:
            # Build a synthetic tool for evaluation
            tool_def = ToolDefinition(
                name=request.tool_name,
                sensitivity=SensitivityLevel.HIGH,
                required_capabilities=request.capabilities,
            )

        tool_req = ToolRequest(
            tool_id=tool_def.tool_id,
            tool_name=tool_def.name,
            agent_id=request.agent_id,
        )

        contexts = []
        if request.tainted_context:
            from agentguard.tracing.correlation import generate_id
            prov = Provenance(
                source=ContextSource.EXTERNAL_MCP,
                trust_level="untrusted",
            )
            ctx = Context(
                context_id=generate_id("ctx"),
                source=ContextSource.EXTERNAL_MCP,
                taint_state=TaintState.TAINTED,
                provenance=prov,
            )
            contexts.append(ctx)

        from agentguard.tracing.correlation import CorrelationContext, generate_id as gid
        corr = CorrelationContext(
            trace_id=gid("trc"),
            span_id=gid("spn"),
            task_id=gid("tsk"),
            agent_id=request.agent_id,
            metadata={"intent": request.intent},
        )

        decision = self._fs._guard.policy_evaluator.evaluate(
            tool_def=tool_def,
            request=tool_req,
            ctx=corr,
            active_contexts=contexts,
        )

        return PolicyEvaluateResponse(
            tool_name=request.tool_name,
            agent_id=request.agent_id,
            decision=decision.action.value,
            reason_code=decision.reason_code,
            explanation=decision.explanation,
            risk_score=decision.risk_score,
        )

    # ------------------------------------------------------------------
    # Metrics
    # ------------------------------------------------------------------

    def get_metrics(self) -> Dict[str, Any]:
        """GET /api/v1/metrics"""
        overview = self._fs.query.get_overview()
        return {
            "total_agents": overview.get("agents", 0),
            "total_attacks": overview.get("attacks_today", 0),
            "bypass_rate": (
                overview["bypasses"] / overview["attacks_today"]
                if overview.get("attacks_today")
                else 0.0
            ),
            "block_rate": (
                overview["blocked"] / overview["attacks_today"]
                if overview.get("attacks_today")
                else 0.0
            ),
            "sensitive_prevention_rate": (
                overview["sensitive_prevented"] / overview["sensitive_attempts"]
                if overview.get("sensitive_attempts")
                else 1.0
            ),
        }
