"""Threat catalog — structured threats mapped to actors, assets, boundaries, and controls."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from actshield.threatmodel.models import ThreatSeverity, ThreatCategory, ControlEffectiveness


class Threat(BaseModel):
    """A structured threat in the agent system."""
    threat_id: str
    name: str
    category: ThreatCategory
    severity: ThreatSeverity
    description: str
    # Linkage
    actor_ids: list[str] = Field(default_factory=list)
    asset_ids: list[str] = Field(default_factory=list)
    boundary_ids: list[str] = Field(default_factory=list)
    entry_points: list[str] = Field(default_factory=list)
    # Attack path description
    attack_path: list[str] = Field(default_factory=list)
    # STRIDE / MITRE ATLAS reference
    stride_category: str | None = None
    mitre_atlas_id: str | None = None
    # Control mapping
    actshield_controls: list[str] = Field(default_factory=list)
    control_effectiveness: ControlEffectiveness = ControlEffectiveness.REDUCES
    # Residual risk if control fails
    residual_risk: str = "Unknown"
    # Evidence that ActShield generates on detection
    evidence_generated: list[str] = Field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


class ThreatCatalog:
    """Built-in catalog of threats relevant to autonomous agent systems."""

    _CATALOG: list[dict[str, Any]] = [
        # ── Prompt Injection ──────────────────────────────────────────────
        {
            "threat_id": "thr_direct_pi",
            "name": "Direct Prompt Injection",
            "category": ThreatCategory.PROMPT_INJECTION,
            "severity": ThreatSeverity.HIGH,
            "description": (
                "User or attacker provides crafted input designed to override "
                "agent instructions or manipulate its behavior."
            ),
            "actor_ids": ["act_mal_user", "act_ext_attacker"],
            "asset_ids": ["ast_sys_prompts", "ast_agent_authority"],
            "boundary_ids": ["bnd_ext_int"],
            "entry_points": ["user_input", "task_description"],
            "attack_path": [
                "Attacker crafts malicious user input",
                "Input enters agent context",
                "Agent interprets injected instructions",
                "Agent requests unauthorized tool or resource",
            ],
            "stride_category": "Elevation of Privilege",
            "mitre_atlas_id": "AML.T0051",
            "actshield_controls": [
                "intent_analysis", "taint_tracking", "authority_containment", "policy_evaluation"
            ],
            "control_effectiveness": ControlEffectiveness.REDUCES,
            "residual_risk": "Low — intent analysis reduces but cannot fully eliminate all injection patterns",
            "evidence_generated": ["SecurityEvent", "IntentAnalysisResult", "PolicyDecision"],
        },
        {
            "threat_id": "thr_indirect_pi",
            "name": "Indirect Prompt Injection",
            "category": ThreatCategory.INDIRECT_PROMPT_INJECTION,
            "severity": ThreatSeverity.CRITICAL,
            "description": (
                "Malicious instructions embedded in external content (web pages, "
                "documents, MCP responses) that an agent processes and acts upon."
            ),
            "actor_ids": ["act_mal_mcp", "act_poisoned_doc", "act_ext_attacker"],
            "asset_ids": ["ast_customer_db", "ast_creds", "ast_cloud_resources"],
            "boundary_ids": ["bnd_ext_int", "bnd_mcp_context", "bnd_context_tool"],
            "entry_points": ["external_mcp_response", "web_content", "rag_retrieval_result"],
            "attack_path": [
                "Attacker embeds instructions in external content / MCP response",
                "Agent fetches and processes content",
                "Tainted context enters agent reasoning",
                "Agent generates privileged tool request",
                "Request attempts to cross context→tool boundary",
                "ActShield policy evaluation required",
            ],
            "stride_category": "Tampering / Elevation of Privilege",
            "mitre_atlas_id": "AML.T0051.001",
            "actshield_controls": [
                "mcp_gateway", "http_gateway", "provenance_tracking",
                "taint_tracking", "intent_analysis", "authority_containment",
                "policy_evaluation", "tool_interception"
            ],
            "control_effectiveness": ControlEffectiveness.PREVENTS,
            "residual_risk": (
                "Low — multi-layer defense: taint propagation ensures tainted "
                "context cannot authorize sensitive tool execution without explicit "
                "authority and clean provenance."
            ),
            "evidence_generated": [
                "TaintEvent", "ProvenanceRecord", "SecurityEvent",
                "PolicyDecision", "ForensicTrace"
            ],
        },
        # ── Tool Poisoning ────────────────────────────────────────────────
        {
            "threat_id": "thr_tool_poison",
            "name": "Tool Poisoning",
            "category": ThreatCategory.TOOL_POISONING,
            "severity": ThreatSeverity.HIGH,
            "description": (
                "A tool (especially an MCP-provided tool) returns malicious "
                "instructions disguised as legitimate tool output."
            ),
            "actor_ids": ["act_mal_mcp", "act_supply_chain"],
            "asset_ids": ["ast_agent_authority", "ast_customer_db"],
            "boundary_ids": ["bnd_mcp_context", "bnd_context_tool"],
            "entry_points": ["mcp_tool_response", "tool_output"],
            "attack_path": [
                "Compromised tool returns crafted response",
                "Response contains embedded instructions",
                "Agent treats tool output as authoritative",
                "Agent requests escalated or unauthorized action",
            ],
            "stride_category": "Tampering",
            "actshield_controls": [
                "mcp_gateway", "taint_tracking", "provenance_tracking", "policy_evaluation"
            ],
            "control_effectiveness": ControlEffectiveness.DETECTS,
            "residual_risk": "Medium — detection depends on response analysis quality",
            "evidence_generated": ["TaintEvent", "MCPInterceptionEvent", "SecurityEvent"],
        },
        # ── Delegation Abuse ──────────────────────────────────────────────
        {
            "threat_id": "thr_delegation_abuse",
            "name": "Delegation Authority Abuse",
            "category": ThreatCategory.DELEGATION_ABUSE,
            "severity": ThreatSeverity.HIGH,
            "description": (
                "A sub-agent or compromised agent attempts to claim authority "
                "beyond what was explicitly delegated to it."
            ),
            "actor_ids": ["act_compromised_agent", "act_mal_user"],
            "asset_ids": ["ast_agent_authority", "ast_customer_db", "ast_cloud_resources"],
            "boundary_ids": ["bnd_agent_agent", "bnd_agent_db"],
            "entry_points": ["delegation_request", "sub_task_creation"],
            "attack_path": [
                "Agent receives or fabricates elevated delegation claim",
                "Agent requests resource requiring higher authority",
                "ActShield checks effective authority chain",
                "Delegation chain verification fails or is circumvented",
            ],
            "stride_category": "Elevation of Privilege",
            "actshield_controls": [
                "delegation_tracking", "authority_containment",
                "effective_authority_check", "policy_evaluation"
            ],
            "control_effectiveness": ControlEffectiveness.PREVENTS,
            "residual_risk": (
                "Low — ActShield enforces that effective authority cannot exceed "
                "the delegating agent's own authority (containment invariant)."
            ),
            "evidence_generated": ["DelegationEvent", "AuthorityCheckResult", "PolicyDecision"],
        },
        # ── Credential Theft ──────────────────────────────────────────────
        {
            "threat_id": "thr_cred_theft",
            "name": "Credential / Secret Theft",
            "category": ThreatCategory.CREDENTIAL_THEFT,
            "severity": ThreatSeverity.CRITICAL,
            "description": (
                "An attacker manipulates an agent to exfiltrate API keys, tokens, "
                "or other credentials through tool calls or context leakage."
            ),
            "actor_ids": ["act_ext_attacker", "act_mal_user", "act_compromised_agent"],
            "asset_ids": ["ast_creds"],
            "boundary_ids": ["bnd_ext_int", "bnd_context_tool"],
            "entry_points": ["user_input", "external_mcp_response", "tool_request"],
            "attack_path": [
                "Attacker injects instruction to read/return secrets",
                "Agent attempts to access credential store",
                "Tool interception evaluates request",
                "Authority and sensitivity check applied",
            ],
            "stride_category": "Information Disclosure",
            "actshield_controls": [
                "tool_interception", "authority_containment",
                "policy_evaluation", "sensitivity_classification"
            ],
            "control_effectiveness": ControlEffectiveness.PREVENTS,
            "residual_risk": "Low — CRITICAL sensitivity tools require explicit authority",
            "evidence_generated": ["SecurityEvent", "PolicyDecision", "ForensicTrace"],
        },
        # ── Data Exfiltration ─────────────────────────────────────────────
        {
            "threat_id": "thr_data_exfil",
            "name": "Customer Data Exfiltration",
            "category": ThreatCategory.INFORMATION_DISCLOSURE,
            "severity": ThreatSeverity.CRITICAL,
            "description": (
                "Agent is manipulated to query the customer database and "
                "return results to an unauthorized external endpoint."
            ),
            "actor_ids": ["act_ext_attacker", "act_mal_mcp", "act_insider"],
            "asset_ids": ["ast_customer_db"],
            "boundary_ids": ["bnd_agent_db", "bnd_ext_int"],
            "entry_points": ["external_mcp_response", "user_input", "database_tool_call"],
            "attack_path": [
                "External MCP response contains exfiltration instruction",
                "Agent context becomes tainted",
                "Agent requests customer_db.read with tainted context",
                "ActShield evaluates: taint + authority + policy",
                "BLOCK enforced",
            ],
            "stride_category": "Information Disclosure",
            "mitre_atlas_id": "AML.T0048",
            "actshield_controls": [
                "taint_tracking", "authority_containment", "policy_evaluation",
                "tool_interception", "protected_tool"
            ],
            "control_effectiveness": ControlEffectiveness.PREVENTS,
            "residual_risk": "Low — CRITICAL asset requires authority + clean taint",
            "evidence_generated": [
                "TaintEvent", "SecurityEvent", "PolicyDecision",
                "IncidentCreated", "ForensicTrace"
            ],
        },
        # ── MCP Compromise ────────────────────────────────────────────────
        {
            "threat_id": "thr_mcp_compromise",
            "name": "MCP Server Compromise",
            "category": ThreatCategory.MCP_COMPROMISE,
            "severity": ThreatSeverity.HIGH,
            "description": (
                "An external MCP server the agent system relies on is compromised "
                "and begins returning adversarial responses."
            ),
            "actor_ids": ["act_mal_mcp", "act_supply_chain"],
            "asset_ids": ["ast_agent_authority", "ast_customer_db", "ast_cloud_resources"],
            "boundary_ids": ["bnd_mcp_context", "bnd_ext_int"],
            "entry_points": ["mcp_tool_response", "mcp_resource_content"],
            "attack_path": [
                "Legitimate MCP server is compromised",
                "Agent makes trusted MCP call",
                "Compromised response returned",
                "Response crosses External→Internal boundary",
                "ActShield MCP gateway intercepts",
                "Taint applied to all derived context",
            ],
            "stride_category": "Tampering",
            "actshield_controls": [
                "mcp_gateway", "taint_tracking", "provenance_tracking"
            ],
            "control_effectiveness": ControlEffectiveness.DETECTS,
            "residual_risk": (
                "Medium — content-level injection within MCP response may require "
                "additional semantic analysis to detect."
            ),
            "evidence_generated": ["MCPInterceptionEvent", "TaintEvent", "ProvenanceRecord"],
        },
        # ── RAG Poisoning ─────────────────────────────────────────────────
        {
            "threat_id": "thr_rag_poison",
            "name": "RAG Source Poisoning",
            "category": ThreatCategory.RAG_POISONING,
            "severity": ThreatSeverity.HIGH,
            "description": (
                "Vector database or document store is poisoned with adversarial "
                "content that influences agent reasoning when retrieved."
            ),
            "actor_ids": ["act_poisoned_rag", "act_ext_attacker"],
            "asset_ids": ["ast_rag_sources", "ast_customer_db"],
            "boundary_ids": ["bnd_rag_context", "bnd_context_tool"],
            "entry_points": ["rag_retrieval_result", "vector_db_response"],
            "attack_path": [
                "Attacker inserts adversarial document into knowledge base",
                "Agent retrieves poisoned document via RAG",
                "Poisoned content enters context",
                "ActShield marks retrieval source as external",
                "Taint propagated to derived reasoning",
                "Tool request with tainted context blocked",
            ],
            "stride_category": "Tampering",
            "actshield_controls": [
                "provenance_tracking", "taint_marking", "intent_analysis", "policy_evaluation"
            ],
            "control_effectiveness": ControlEffectiveness.REDUCES,
            "residual_risk": (
                "Medium — depends on RAG source classification. "
                "Internal RAG sources receive lower taint."
            ),
            "evidence_generated": ["ProvenanceRecord", "TaintEvent", "SecurityEvent"],
        },
        # ── Privilege Escalation ──────────────────────────────────────────
        {
            "threat_id": "thr_priv_esc",
            "name": "Agent Privilege Escalation",
            "category": ThreatCategory.ELEVATION_OF_PRIVILEGE,
            "severity": ThreatSeverity.HIGH,
            "description": (
                "Agent attempts to execute actions requiring higher authority "
                "than its effective delegation chain permits."
            ),
            "actor_ids": ["act_compromised_agent", "act_mal_user"],
            "asset_ids": ["ast_agent_authority", "ast_cloud_resources"],
            "boundary_ids": ["bnd_agent_agent", "bnd_agent_db"],
            "entry_points": ["tool_request", "delegation_request"],
            "attack_path": [
                "Agent constructs tool request requiring elevated authority",
                "ActShield checks DECLARED → DELEGATED → EFFECTIVE chain",
                "Effective authority insufficient",
                "BLOCK enforced",
            ],
            "stride_category": "Elevation of Privilege",
            "mitre_atlas_id": "AML.T0043",
            "actshield_controls": [
                "authority_containment", "effective_authority_check", "policy_evaluation"
            ],
            "control_effectiveness": ControlEffectiveness.PREVENTS,
            "residual_risk": "Low — authority containment invariant is deterministically enforced",
            "evidence_generated": ["AuthorityCheckResult", "PolicyDecision", "SecurityEvent"],
        },
        # ── Supply Chain ──────────────────────────────────────────────────
        {
            "threat_id": "thr_supply_chain",
            "name": "Supply Chain Attack",
            "category": ThreatCategory.SUPPLY_CHAIN,
            "severity": ThreatSeverity.CRITICAL,
            "description": (
                "A compromised dependency, tool library, or external service "
                "introduces malicious behavior into the agent system."
            ),
            "actor_ids": ["act_supply_chain"],
            "asset_ids": ["ast_creds", "ast_customer_db", "ast_cloud_resources"],
            "boundary_ids": ["bnd_ext_int", "bnd_context_tool"],
            "entry_points": ["package_dependency", "external_service"],
            "attack_path": [
                "Malicious code introduced in dependency",
                "Agent system loads compromised package",
                "Compromised code executes with agent authority",
                "ActShield tool interception monitors execution",
            ],
            "stride_category": "Tampering",
            "actshield_controls": [
                "tool_interception", "authority_containment", "audit_logging"
            ],
            "control_effectiveness": ControlEffectiveness.MONITORS,
            "residual_risk": (
                "High — ActShield can detect anomalous tool calls but cannot "
                "prevent malicious code that executes within a trusted process."
            ),
            "evidence_generated": ["SecurityEvent", "AnomalyAlert", "AuditLog"],
        },
    ]

    def __init__(self) -> None:
        self._threats: dict[str, Threat] = {
            d["threat_id"]: Threat(**d) for d in self._CATALOG
        }

    def register(self, threat: Threat) -> None:
        self._threats[threat.threat_id] = threat

    def get(self, threat_id: str) -> Threat | None:
        return self._threats.get(threat_id)

    def all(self) -> list[Threat]:
        return list(self._threats.values())

    def by_severity(self, severity: ThreatSeverity) -> list[Threat]:
        return [t for t in self._threats.values() if t.severity == severity]

    def by_category(self, category: ThreatCategory) -> list[Threat]:
        return [t for t in self._threats.values() if t.category == category]

    def by_asset(self, asset_id: str) -> list[Threat]:
        return [t for t in self._threats.values() if asset_id in t.asset_ids]

    def count(self) -> int:
        return len(self._threats)
