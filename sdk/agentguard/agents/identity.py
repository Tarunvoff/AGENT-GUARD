"""Agent identity and capability definitions."""

from enum import Enum
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field, field_validator

from agentguard.tracing.correlation import generate_id


class AgentTrustLevel(str, Enum):
    """Standardized agent trust levels."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNTRUSTED = "untrusted"


class AgentCapability(BaseModel):
    """Specific permission or functional capability possessed or granted to an agent."""
    name: str = Field(..., description="Canonical capability name (e.g., 'public_search', 'database_read')")
    description: Optional[str] = Field(default=None, description="Description of the capability")
    scope: Optional[str] = Field(default=None, description="Resource scope limitation (e.g. 'domain:finance')")
    sensitivity: Optional[str] = Field(default=None, description="Sensitivity classification")

    def matches(self, required_capability: str) -> bool:
        """Check if this capability satisfies a required capability name or pattern."""
        if self.name == required_capability or self.name == "*":
            return True
        if self.name.endswith(".*") and required_capability.startswith(self.name[:-2]):
            return True
        return False


class AgentIdentity(BaseModel):
    """Immutable identity record for an AI agent registered in AgentGuard."""
    
    agent_id: str = Field(default_factory=lambda: generate_id("agt"), description="Unique agent identifier")
    name: str = Field(..., description="Human-readable agent name")
    framework: str = Field(default="custom", description="Framework name (e.g., 'langchain', 'autogen', 'crewai', 'custom')")
    version: str = Field(default="1.0.0", description="Agent implementation version")
    capabilities: List[AgentCapability] = Field(
        default_factory=list,
        description="Declared capabilities of this agent"
    )
    trust_level: AgentTrustLevel = Field(
        default=AgentTrustLevel.MEDIUM,
        description="Assigned baseline trust level"
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional identity metadata, tags, or deployment labels"
    )

    @field_validator("capabilities", mode="before")
    @classmethod
    def parse_capabilities(cls, v: Any) -> List[AgentCapability]:
        """Allow passing strings or dicts as capabilities."""
        if not v:
            return []
        parsed = []
        for item in v:
            if isinstance(item, str):
                parsed.append(AgentCapability(name=item))
            elif isinstance(item, dict):
                parsed.append(AgentCapability(**item))
            elif isinstance(item, AgentCapability):
                parsed.append(item)
            else:
                raise ValueError(f"Invalid capability format: {item}")
        return parsed

    def has_capability(self, capability_name: str) -> bool:
        """Verify whether this identity possesses a specified capability."""
        return any(cap.matches(capability_name) for cap in self.capabilities)

    def capability_names(self) -> List[str]:
        """Return list of string capability names."""
        return [c.name for c in self.capabilities]
