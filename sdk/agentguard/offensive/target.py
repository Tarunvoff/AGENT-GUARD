"""Attack target definition and registration registry."""

import os
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class TargetEnvironment(str, Enum):
    """Target execution environment."""
    SANDBOX = "sandbox"
    LOCAL = "local"
    SIMULATION = "simulation"
    EXTERNAL = "external"


class AttackTarget(BaseModel):
    """Registration record for a target system undergoing offensive validation."""

    target_id: str = Field(..., description="Unique target identifier (e.g. 'agentguard-demo')")
    name: str = Field(default="", description="Human-readable target name")
    environment: TargetEnvironment = Field(default=TargetEnvironment.LOCAL, description="Target environment")
    synthetic: bool = Field(default=True, description="Must be True: targets must be synthetic simulations")
    allowed: bool = Field(default=True, description="Explicit allowlist authorization flag")
    
    # Target system components
    agents: List[str] = Field(default_factory=list, description="List of registered agent names")
    tools: List[str] = Field(default_factory=list, description="List of available tool names")
    resources: List[str] = Field(default_factory=list, description="List of protected resource names")
    protocols: List[str] = Field(default_factory=lambda: ["MCP", "HTTP"], description="Supported protocols")
    
    # Execution Tracking
    sensitive_db_name: str = Field(default="customer_db", description="Name of sensitive sink resource")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Target configuration metadata")

    def is_safe_for_validation(self) -> bool:
        """Check if target satisfies the strict local synthetic safety invariant."""
        return (
            self.synthetic is True
            and self.allowed is True
            and self.environment in (TargetEnvironment.SANDBOX, TargetEnvironment.LOCAL, TargetEnvironment.SIMULATION)
        )


class TargetRegistry:
    """Registry maintaining authorized local synthetic attack targets."""

    def __init__(self) -> None:
        self._targets: Dict[str, AttackTarget] = {}
        self._register_default_sandbox()

    def _register_default_sandbox(self) -> None:
        """Register the default local enterprise synthetic target."""
        default_target = AttackTarget(
            target_id="agentguard-demo",
            name="Local Synthetic Enterprise Sandbox",
            environment=TargetEnvironment.LOCAL,
            synthetic=True,
            allowed=True,
            agents=["PlannerAgent", "ResearchAgent", "AnalysisAgent", "DataAgent"],
            tools=["sec_edgar.fetch_filing", "web_search", "financial_extract", "customer_db.read", "http_post"],
            resources=["public_filing_cache", "customer_pii_vault", "financial_ledger"],
            protocols=["MCP", "HTTP"],
            sensitive_db_name="customer_db",
        )
        self.register(default_target)

    def register(self, target: AttackTarget) -> None:
        """Register a new attack target with safety validation."""
        if not target.is_safe_for_validation():
            raise ValueError(
                f"Refusing to register unsafe target '{target.target_id}': "
                f"Target must be synthetic=True, allowed=True, and local/sandbox."
            )
        self._targets[target.target_id] = target

    def get(self, target_id: str) -> Optional[AttackTarget]:
        return self._targets.get(target_id)

    def list_targets(self) -> List[AttackTarget]:
        return list(self._targets.values())

    def is_target_allowed(self, target_id: str) -> bool:
        target = self.get(target_id)
        return target is not None and target.is_safe_for_validation()


# Global default registry instance
target_registry = TargetRegistry()
