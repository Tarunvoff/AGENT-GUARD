"""Control-to-threat mapping — how ActShield controls mitigate each threat."""
from __future__ import annotations

from pydantic import BaseModel, Field

from actshield.threatmodel.models import ControlEffectiveness


class Mitigation(BaseModel):
    """A single ActShield control and its relationship to a threat."""
    control_id: str
    control_name: str
    description: str
    # How the control works mechanically
    mechanism: str
    # Enforcement action
    enforcement_action: str  # BLOCK | MONITOR | DETECT | ALERT
    # Where in the ActShield pipeline this runs
    pipeline_stage: str  # provenance | taint | intent | authority | policy | evidence


class ControlMapping(BaseModel):
    """Maps a threat to the set of ActShield controls that mitigate it."""
    threat_id: str
    controls: list[Mitigation] = Field(default_factory=list)
    combined_effectiveness: ControlEffectiveness = ControlEffectiveness.REDUCES
    notes: str = ""


# ── ActShield control definitions ─────────────────────────────────────────────

ACTSHIELD_CONTROLS: dict[str, Mitigation] = {
    "provenance_tracking": Mitigation(
        control_id="ctl_provenance",
        control_name="Context Provenance Tracking",
        description=(
            "Every piece of context entering the agent system is tagged with its "
            "origin source, trust level, and a provenance chain."
        ),
        mechanism=(
            "ProvenanceHop records are attached to each context element. "
            "External sources receive EXTERNAL trust level."
        ),
        enforcement_action="DETECT",
        pipeline_stage="provenance",
    ),
    "taint_tracking": Mitigation(
        control_id="ctl_taint",
        control_name="Taint Propagation",
        description=(
            "Context derived from untrusted or external sources is marked TAINTED "
            "and that taint propagates through the reasoning chain."
        ),
        mechanism=(
            "TaintState.TAINTED is set on context from external sources. "
            "Tainted context cannot authorize CRITICAL tool execution."
        ),
        enforcement_action="BLOCK",
        pipeline_stage="taint",
    ),
    "mcp_gateway": Mitigation(
        control_id="ctl_mcp",
        control_name="MCP Gateway Interception",
        description="All MCP server communications are intercepted and inspected.",
        mechanism=(
            "MCPGateway wraps all MCP calls. Responses are analyzed, "
            "taint-marked, and provenance-recorded before entering agent context."
        ),
        enforcement_action="BLOCK",
        pipeline_stage="provenance",
    ),
    "http_gateway": Mitigation(
        control_id="ctl_http",
        control_name="HTTP Gateway Interception",
        description="All external HTTP calls are intercepted and responses are taint-marked.",
        mechanism=(
            "HTTPGateway intercepts outbound requests and inbound responses. "
            "External responses marked EXTERNAL and TAINTED."
        ),
        enforcement_action="DETECT",
        pipeline_stage="provenance",
    ),
    "intent_analysis": Mitigation(
        control_id="ctl_intent",
        control_name="Intent Analysis (AI Secura / Deterministic)",
        description=(
            "AI-powered and deterministic intent analysis classifies whether "
            "a tool request is aligned with the declared task."
        ),
        mechanism=(
            "DeterministicIntentAnalyzer checks keywords, patterns, and taint. "
            "AI Secura provides probabilistic scoring. Results inform policy."
        ),
        enforcement_action="ALERT",
        pipeline_stage="intent",
    ),
    "authority_containment": Mitigation(
        control_id="ctl_authority",
        control_name="Authority Containment",
        description=(
            "Agents cannot claim authority beyond what was explicitly delegated. "
            "The containment invariant: effective ≤ delegated ≤ declared."
        ),
        mechanism=(
            "Effective authority is computed from the delegation chain. "
            "Tool requests requiring authority exceeding effective are blocked."
        ),
        enforcement_action="BLOCK",
        pipeline_stage="authority",
    ),
    "effective_authority_check": Mitigation(
        control_id="ctl_eff_auth",
        control_name="Effective Authority Verification",
        description="Verifies the computed effective authority before any tool execution.",
        mechanism=(
            "DECLARED → DELEGATED → EFFECTIVE chain is computed and compared "
            "against required tool authority."
        ),
        enforcement_action="BLOCK",
        pipeline_stage="authority",
    ),
    "delegation_tracking": Mitigation(
        control_id="ctl_delegation",
        control_name="Delegation Chain Tracking",
        description="Full delegation graph is maintained and verified for every agent action.",
        mechanism="Delegation records are immutable and cryptographically linked.",
        enforcement_action="DETECT",
        pipeline_stage="authority",
    ),
    "policy_evaluation": Mitigation(
        control_id="ctl_policy",
        control_name="Deterministic Policy Evaluation",
        description=(
            "The PolicyEvaluator applies rules deterministically — AI advice "
            "is input to policy, not the policy itself."
        ),
        mechanism=(
            "PolicyEvaluator evaluates RuleCondition sets. "
            "Output: ALLOW | MONITOR | HITL | QUARANTINE | BLOCK | REVOKE."
        ),
        enforcement_action="BLOCK",
        pipeline_stage="policy",
    ),
    "tool_interception": Mitigation(
        control_id="ctl_tool",
        control_name="Tool Interception (@protect decorator)",
        description="Protected tools cannot execute without passing the full ActShield pipeline.",
        mechanism=(
            "@guard.protect() wraps tool functions. All executions pass through "
            "provenance → taint → intent → authority → policy before execution."
        ),
        enforcement_action="BLOCK",
        pipeline_stage="policy",
    ),
    "audit_logging": Mitigation(
        control_id="ctl_audit",
        control_name="Structured Audit Logging",
        description="Every security decision produces a structured, immutable audit record.",
        mechanism=(
            "SecurityEvent records are written with: who, what, when, why, "
            "context, authority, tool, resource, decision, outcome."
        ),
        enforcement_action="DETECT",
        pipeline_stage="evidence",
    ),
    "source_attribution": Mitigation(
        control_id="ctl_attribution",
        control_name="Source Attribution",
        description="Context elements are attributed to their originating source at retrieval time.",
        mechanism="ProvenanceHop records source URL, trust level, and retrieval timestamp.",
        enforcement_action="DETECT",
        pipeline_stage="provenance",
    ),
    "sensitivity_classification": Mitigation(
        control_id="ctl_sensitivity",
        control_name="Tool Sensitivity Classification",
        description="Tools are classified by sensitivity level (LOW → CRITICAL).",
        mechanism=(
            "SensitivityLevel is declared on ToolDefinition. "
            "CRITICAL tools require authority + clean taint + explicit policy."
        ),
        enforcement_action="BLOCK",
        pipeline_stage="policy",
    ),
}


def get_control(control_id: str) -> Mitigation | None:
    return ACTSHIELD_CONTROLS.get(control_id)


def get_all_controls() -> list[Mitigation]:
    return list(ACTSHIELD_CONTROLS.values())


def build_control_coverage_map(threat_control_ids: list[str]) -> dict[str, bool]:
    """Return which ActShield control domains are covered."""
    domains = {
        "Identity": any(c in threat_control_ids for c in ["provenance_tracking", "delegation_tracking"]),
        "Authority": any(c in threat_control_ids for c in ["authority_containment", "effective_authority_check", "delegation_tracking"]),
        "Context": any(c in threat_control_ids for c in ["taint_tracking", "provenance_tracking", "source_attribution"]),
        "Tool Security": any(c in threat_control_ids for c in ["tool_interception", "sensitivity_classification"]),
        "MCP": any(c in threat_control_ids for c in ["mcp_gateway"]),
        "Data Access": any(c in threat_control_ids for c in ["authority_containment", "policy_evaluation"]),
        "Delegation": any(c in threat_control_ids for c in ["delegation_tracking", "authority_containment"]),
        "Enforcement": any(c in threat_control_ids for c in ["policy_evaluation"]),
        "Evidence": any(c in threat_control_ids for c in ["audit_logging"]),
    }
    return domains
