"""Trust and authority boundaries for the agent system threat model."""
from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class BoundaryType(str, Enum):
    TRUST = "TRUST"           # Who/what is trusted at this boundary
    AUTHORITY = "AUTHORITY"   # What operations are permitted
    DATA = "DATA"             # What data can cross this boundary
    NETWORK = "NETWORK"       # Network-level isolation
    EXECUTION = "EXECUTION"   # Sandbox / runtime isolation


class TrustBoundary(BaseModel):
    """A boundary in the agent system that separates trust zones."""
    boundary_id: str
    name: str
    boundary_type: BoundaryType
    description: str
    # Zones on either side
    trusted_zone: str
    untrusted_zone: str
    # Controls enforced at this boundary by ActShield
    controls: list[str] = Field(default_factory=list)
    # Entry points that cross this boundary
    crossing_entry_points: list[str] = Field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


class BoundaryRegistry:
    """Registry of trust boundaries in the agent system."""

    _DEFAULTS: list[dict[str, Any]] = [
        {
            "boundary_id": "bnd_ext_int",
            "name": "External → Internal",
            "boundary_type": BoundaryType.TRUST,
            "description": (
                "Primary boundary between external internet and internal agent "
                "infrastructure. All external MCP responses, web content, and "
                "user inputs cross this boundary."
            ),
            "trusted_zone": "internal",
            "untrusted_zone": "external",
            "controls": ["provenance_tracking", "taint_marking", "mcp_gateway", "http_gateway"],
            "crossing_entry_points": [
                "external_mcp_response", "web_content", "user_input", "external_api"
            ],
        },
        {
            "boundary_id": "bnd_agent_agent",
            "name": "Agent → Sub-Agent Delegation",
            "boundary_type": BoundaryType.AUTHORITY,
            "description": (
                "Authority boundary enforced when an orchestrator agent delegates "
                "tasks to sub-agents. Authority cannot be escalated beyond the "
                "delegating agent's effective authority."
            ),
            "trusted_zone": "orchestrator",
            "untrusted_zone": "sub-agent",
            "controls": ["delegation_tracking", "authority_containment", "effective_authority_check"],
            "crossing_entry_points": ["delegation_request", "sub_task_creation"],
        },
        {
            "boundary_id": "bnd_context_tool",
            "name": "Context → Tool Execution",
            "boundary_type": BoundaryType.DATA,
            "description": (
                "Critical boundary between agent context (which may be tainted "
                "by external sources) and privileged tool execution."
            ),
            "trusted_zone": "tool_executor",
            "untrusted_zone": "agent_context",
            "controls": [
                "taint_tracking", "provenance_check", "intent_analysis",
                "policy_evaluation", "tool_interception"
            ],
            "crossing_entry_points": ["tool_request", "tool_call"],
        },
        {
            "boundary_id": "bnd_mcp_context",
            "name": "MCP Server → Agent Context",
            "boundary_type": BoundaryType.DATA,
            "description": (
                "Boundary between external MCP server responses and the agent "
                "context window. Malicious MCP responses can inject instructions."
            ),
            "trusted_zone": "agent_context",
            "untrusted_zone": "mcp_response",
            "controls": ["mcp_gateway", "taint_marking", "provenance_tracking", "intent_analysis"],
            "crossing_entry_points": ["mcp_tool_response", "mcp_resource_content"],
        },
        {
            "boundary_id": "bnd_agent_db",
            "name": "Agent → Sensitive Database",
            "boundary_type": BoundaryType.AUTHORITY,
            "description": (
                "Authority boundary protecting sensitive databases from unauthorized "
                "agent access. Requires explicit authority grant and clean context."
            ),
            "trusted_zone": "database",
            "untrusted_zone": "agent",
            "controls": [
                "authority_containment", "taint_check", "policy_evaluation",
                "protected_tool", "audit_logging"
            ],
            "crossing_entry_points": ["database_tool_call"],
        },
        {
            "boundary_id": "bnd_rag_context",
            "name": "RAG Source → Agent Context",
            "boundary_type": BoundaryType.DATA,
            "description": (
                "Boundary between retrieval-augmented sources and the agent context. "
                "Poisoned documents retrieved via RAG can influence agent reasoning."
            ),
            "trusted_zone": "agent_context",
            "untrusted_zone": "rag_retrieval",
            "controls": ["provenance_tracking", "taint_marking", "source_attribution"],
            "crossing_entry_points": ["rag_retrieval_result", "vector_db_response"],
        },
        {
            "boundary_id": "bnd_internal_cloud",
            "name": "Internal → Cloud Infrastructure",
            "boundary_type": BoundaryType.NETWORK,
            "description": (
                "Network boundary between internal agent execution and cloud "
                "infrastructure APIs. Unauthorized cloud API calls can cause "
                "significant resource abuse."
            ),
            "trusted_zone": "cloud",
            "untrusted_zone": "agent_network",
            "controls": ["authority_containment", "policy_evaluation", "http_gateway"],
            "crossing_entry_points": ["cloud_api_call", "infrastructure_tool"],
        },
    ]

    def __init__(self) -> None:
        self._boundaries: dict[str, TrustBoundary] = {
            d["boundary_id"]: TrustBoundary(**d) for d in self._DEFAULTS
        }

    def register(self, boundary: TrustBoundary) -> None:
        self._boundaries[boundary.boundary_id] = boundary

    def get(self, boundary_id: str) -> TrustBoundary | None:
        return self._boundaries.get(boundary_id)

    def all(self) -> list[TrustBoundary]:
        return list(self._boundaries.values())

    def count(self) -> int:
        return len(self._boundaries)

    def for_entry_point(self, entry_point: str) -> list[TrustBoundary]:
        return [
            b for b in self._boundaries.values()
            if entry_point in b.crossing_entry_points
        ]
