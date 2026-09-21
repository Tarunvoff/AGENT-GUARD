"""Threat modeling core models — ThreatModel, AnalysisResult, enumerations."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ThreatSeverity(str, Enum):
    """CVSS-inspired severity classification."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class ThreatCategory(str, Enum):
    """Top-level threat category aligned to STRIDE + MITRE ATLAS concepts."""
    # STRIDE
    SPOOFING = "SPOOFING"                  # Identity / agent impersonation
    TAMPERING = "TAMPERING"                # Context or data tampering
    REPUDIATION = "REPUDIATION"            # Lack of audit trail
    INFORMATION_DISCLOSURE = "INFO_DISCLOSURE"  # Data exfiltration
    DENIAL_OF_SERVICE = "DENIAL_OF_SERVICE"
    ELEVATION_OF_PRIVILEGE = "PRIVILEGE_ESCALATION"
    # MITRE ATLAS / Agentic AI specific
    PROMPT_INJECTION = "PROMPT_INJECTION"
    INDIRECT_PROMPT_INJECTION = "INDIRECT_PROMPT_INJECTION"
    TOOL_POISONING = "TOOL_POISONING"
    CONTEXT_POISONING = "CONTEXT_POISONING"
    DELEGATION_ABUSE = "DELEGATION_ABUSE"
    CREDENTIAL_THEFT = "CREDENTIAL_THEFT"
    MCP_COMPROMISE = "MCP_COMPROMISE"
    SUPPLY_CHAIN = "SUPPLY_CHAIN"
    RAG_POISONING = "RAG_POISONING"


class ControlEffectiveness(str, Enum):
    """How effectively the mapped ActShield control mitigates the threat."""
    PREVENTS = "PREVENTS"      # Control fully prevents exploitation
    DETECTS = "DETECTS"        # Control detects but may not prevent
    REDUCES = "REDUCES"        # Control reduces likelihood / impact
    MONITORS = "MONITORS"      # Control provides observability only
    NONE = "NONE"              # No current control coverage


class ThreatModel(BaseModel):
    """Container for the full threat model of a deployed agent system."""
    model_id: str = Field(default_factory=lambda: f"tm_{uuid.uuid4().hex[:8]}")
    system_name: str = "ActShield-Monitored System"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    version: str = "1.0.0"

    # Populated by the registry/analyzer
    asset_count: int = 0
    actor_count: int = 0
    boundary_count: int = 0
    threat_count: int = 0
    scenario_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


class AnalysisResult(BaseModel):
    """Complete output of a ThreatAnalyzer.analyze() run."""
    model: ThreatModel
    threats_by_severity: dict[str, list[dict[str, Any]]] = Field(default_factory=dict)
    control_coverage: dict[str, bool] = Field(default_factory=dict)
    residual_risks: list[dict[str, Any]] = Field(default_factory=list)
    attack_paths: list[dict[str, Any]] = Field(default_factory=list)
    analysis_timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    overall_risk_score: float = 0.0  # 0-10 scale

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")
