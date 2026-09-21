"""Threat model assets — sensitive resources that must be protected."""
from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class AssetSensitivity(str, Enum):
    CRITICAL = "CRITICAL"   # Breach = catastrophic impact
    HIGH = "HIGH"           # Breach = significant harm
    MEDIUM = "MEDIUM"       # Breach = moderate harm
    LOW = "LOW"             # Breach = limited harm


class Asset(BaseModel):
    """A sensitive resource in the agent system that requires protection."""
    asset_id: str
    name: str
    description: str
    sensitivity: AssetSensitivity
    owner: str = "system"
    allowed_agents: list[str] = Field(default_factory=list)
    allowed_operations: list[str] = Field(default_factory=list)
    trust_boundary: str = "internal"
    # Business impact if compromised
    impact_confidentiality: str = "unknown"
    impact_integrity: str = "unknown"
    impact_availability: str = "unknown"
    # ActShield tool name that protects this asset (if any)
    protected_by_tool: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


class AssetRegistry:
    """Registry of known sensitive assets in the monitored system."""

    # Default built-in assets for a typical enterprise agent deployment
    _DEFAULTS: list[dict[str, Any]] = [
        {
            "asset_id": "ast_creds",
            "name": "Credentials & API Keys",
            "description": "Service account tokens, API keys, OAuth secrets used by agents",
            "sensitivity": AssetSensitivity.CRITICAL,
            "owner": "platform",
            "allowed_agents": ["orchestrator"],
            "allowed_operations": ["read"],
            "trust_boundary": "internal",
            "impact_confidentiality": "Full system compromise possible",
            "impact_integrity": "Attacker can issue authenticated requests",
            "impact_availability": "Token revocation required",
        },
        {
            "asset_id": "ast_customer_db",
            "name": "Customer Database",
            "description": "PII, financial data, and customer records",
            "sensitivity": AssetSensitivity.CRITICAL,
            "owner": "data-team",
            "allowed_agents": ["analysis-agent"],
            "allowed_operations": ["read"],
            "trust_boundary": "internal",
            "impact_confidentiality": "Regulatory breach, customer harm",
            "impact_integrity": "Data corruption or fraud",
            "impact_availability": "Service disruption",
        },
        {
            "asset_id": "ast_sys_prompts",
            "name": "System Prompts & Agent Instructions",
            "description": "Confidential agent instructions, personas, and behavioral constraints",
            "sensitivity": AssetSensitivity.HIGH,
            "owner": "platform",
            "allowed_agents": ["orchestrator"],
            "allowed_operations": ["read"],
            "trust_boundary": "internal",
            "impact_confidentiality": "Enables adversarial prompt engineering",
            "impact_integrity": "Behavioral manipulation possible",
            "impact_availability": "Low",
        },
        {
            "asset_id": "ast_internal_docs",
            "name": "Internal Documents & Source Code",
            "description": "Proprietary documentation, source code, and internal knowledge bases",
            "sensitivity": AssetSensitivity.HIGH,
            "owner": "engineering",
            "allowed_agents": ["research-agent", "analysis-agent"],
            "allowed_operations": ["read"],
            "trust_boundary": "internal",
            "impact_confidentiality": "IP theft, competitive harm",
            "impact_integrity": "Sabotage possible",
            "impact_availability": "Medium",
        },
        {
            "asset_id": "ast_cloud_resources",
            "name": "Cloud Infrastructure Resources",
            "description": "AWS/GCP/Azure APIs, compute, storage, networking",
            "sensitivity": AssetSensitivity.CRITICAL,
            "owner": "infrastructure",
            "allowed_agents": ["orchestrator"],
            "allowed_operations": ["read", "limited-write"],
            "trust_boundary": "cloud-boundary",
            "impact_confidentiality": "Data exfiltration at scale",
            "impact_integrity": "Infrastructure destruction",
            "impact_availability": "Full service outage",
        },
        {
            "asset_id": "ast_agent_authority",
            "name": "Agent Authority Grants",
            "description": "Delegated permissions and authority scopes assigned to agents",
            "sensitivity": AssetSensitivity.HIGH,
            "owner": "platform",
            "allowed_agents": ["orchestrator"],
            "allowed_operations": ["read", "delegate"],
            "trust_boundary": "internal",
            "impact_confidentiality": "Low",
            "impact_integrity": "Privilege escalation possible",
            "impact_availability": "Low",
        },
        {
            "asset_id": "ast_rag_sources",
            "name": "RAG Knowledge Sources",
            "description": "Vector databases, document stores used for retrieval-augmented generation",
            "sensitivity": AssetSensitivity.MEDIUM,
            "owner": "ai-team",
            "allowed_agents": ["research-agent", "analysis-agent"],
            "allowed_operations": ["read", "query"],
            "trust_boundary": "internal",
            "impact_confidentiality": "Sensitive doc exposure",
            "impact_integrity": "Poisoned retrieval results affect agent reasoning",
            "impact_availability": "Degraded agent quality",
        },
        {
            "asset_id": "ast_audit_logs",
            "name": "Security Audit Logs",
            "description": "ActShield event logs, forensic traces, and security evidence",
            "sensitivity": AssetSensitivity.HIGH,
            "owner": "security-team",
            "allowed_agents": [],
            "allowed_operations": ["read"],
            "trust_boundary": "internal",
            "impact_confidentiality": "Attacker can study detection patterns",
            "impact_integrity": "Evidence tampering breaks forensics",
            "impact_availability": "Incident response compromised",
        },
    ]

    def __init__(self) -> None:
        self._assets: dict[str, Asset] = {
            d["asset_id"]: Asset(**d) for d in self._DEFAULTS
        }

    def register(self, asset: Asset) -> None:
        self._assets[asset.asset_id] = asset

    def get(self, asset_id: str) -> Asset | None:
        return self._assets.get(asset_id)

    def all(self) -> list[Asset]:
        return list(self._assets.values())

    def by_sensitivity(self, sensitivity: AssetSensitivity) -> list[Asset]:
        return [a for a in self._assets.values() if a.sensitivity == sensitivity]

    def count(self) -> int:
        return len(self._assets)
