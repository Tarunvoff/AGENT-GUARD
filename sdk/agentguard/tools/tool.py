"""Tool and resource models for protected execution and access governance."""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from agentguard.risk.models import RiskLevel
from agentguard.tracing.correlation import generate_id


class SensitivityLevel(str, Enum):
    """Sensitivity classification of tools and resources."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Resource(BaseModel):
    """A protected asset, system, database, or API target accessed via tools."""
    resource_id: str = Field(default_factory=lambda: generate_id("rsc"))
    name: str = Field(..., description="Resource name (e.g. 'financial_database', 'user_pii_vault')")
    resource_type: str = Field(default="api", description="Resource type ('database', 'filesystem', 'api', 'model')")
    uri: Optional[str] = Field(default=None, description="URI or path locator")
    sensitivity: SensitivityLevel = Field(default=SensitivityLevel.MEDIUM)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ToolDefinition(BaseModel):
    """Metadata and security properties defining an executable tool or MCP endpoint."""
    
    tool_id: str = Field(default_factory=lambda: generate_id("tool"))
    name: str = Field(..., description="Canonical tool name (e.g. 'execute_sql_query', 'fetch_webpage')")
    description: str = Field(default="", description="Functional description of the tool")
    sensitivity: SensitivityLevel = Field(default=SensitivityLevel.MEDIUM, description="Sensitivity classification")
    required_capabilities: List[str] = Field(
        default_factory=list,
        description="List of capability names an agent must possess to invoke this tool"
    )
    classification: str = Field(
        default="internal",
        description="Origin classification: 'internal', 'external', 'mcp', 'sensitive'"
    )
    target_resources: List[Resource] = Field(
        default_factory=list,
        description="Underlying resources accessed by this tool"
    )
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ToolRequest(BaseModel):
    """A concrete invocation request targeting a tool."""
    
    request_id: str = Field(default_factory=lambda: generate_id("req"))
    tool_id: str = Field(..., description="Tool ID being invoked")
    tool_name: str = Field(..., description="Tool name")
    agent_id: Optional[str] = Field(default=None, description="Requesting agent ID")
    arguments: Dict[str, Any] = Field(default_factory=dict, description="Tool invocation parameters")
    context_ids: List[str] = Field(default_factory=list, description="IDs of context objects influencing this request")
    target_resource: Optional[Resource] = Field(default=None, description="Specific target resource if applicable")


class ToolResult(BaseModel):
    """The result or error produced by a tool execution."""
    
    success: bool = Field(default=True)
    output: Any = Field(default=None)
    error: Optional[str] = Field(default=None)
    execution_time_ms: float = Field(default=0.0)
