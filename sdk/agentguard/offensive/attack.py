"""Attack models and schemas for AgentGuard offensive validation."""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from agentguard.tracing.correlation import generate_id


class AttackType(str, Enum):
    """Standardized classification of offensive attack vectors."""
    INDIRECT_PROMPT_INJECTION = "indirect_prompt_injection"
    DIRECT_PROMPT_INJECTION = "direct_prompt_injection"
    AUTHORITY_IMPERSONATION = "authority_impersonation"
    AUTHORITY_ESCALATION = "authority_escalation"
    TOOL_POISONING = "tool_poisoning"
    MCP_SERVER_POISONING = "mcp_server_poisoning"
    CONTEXT_MANIPULATION = "context_manipulation"
    TAINT_LAUNDERING = "taint_laundering"
    DELEGATION_ESCALATION = "delegation_escalation"
    MULTI_HOP_ESCALATION = "multi_hop_escalation"
    DATA_EXFILTRATION = "data_exfiltration"
    INTENT_DRIFT = "intent_drift"
    JAILBREAK = "jailbreak"
    CUSTOM = "custom"


class SafetyClass(str, Enum):
    """Execution safety classification."""
    LOCAL_SYNTHETIC = "LOCAL_SYNTHETIC"
    SANDBOX_MOCK = "SANDBOX_MOCK"
    UNSAFE_EXTERNAL = "UNSAFE_EXTERNAL"


class ExpectedBehavior(str, Enum):
    """Expected security outcome when the attack is injected."""
    BLOCK = "BLOCK"
    ALLOW = "ALLOW"
    HITL_REQUIRED = "HITL_REQUIRED"
    SANITIZED = "SANITIZED"


class AttackCase(BaseModel):
    """Structured offensive test case designed to validate security boundaries."""

    attack_id: str = Field(default_factory=lambda: generate_id("atk"), description="Unique attack identifier")
    attack_type: AttackType = Field(default=AttackType.CUSTOM, description="Classification of attack vector")
    name: str = Field(default="", description="Human-readable name of the attack")
    description: str = Field(default="", description="Detailed description of attack objective and mechanism")
    
    # Injection details
    entry_point: str = Field(default="mcp_response", description="Entry point (e.g. 'mcp_response', 'http_request', 'tool_output', 'user_input')")
    target_agent: str = Field(default="DataAgent", description="Target acting agent name in the simulation")
    payload: str = Field(default="", description="The adversarial payload data injected into the context")
    
    # Target execution parameters
    target_tool: Optional[str] = Field(default=None, description="The tool the attack attempts to cause execution of")
    target_resource: Optional[str] = Field(default=None, description="Target resource name/sensitivity")
    required_capability: Optional[str] = Field(default=None, description="Capability needed to execute target tool")
    tool_arguments: Dict[str, Any] = Field(default_factory=dict, description="Arguments passed to target tool if triggered")
    
    # Preconditions and Context
    task_intent: str = Field(default="Standard authorized operation", description="The legitimate original user intent")
    preconditions: Dict[str, Any] = Field(default_factory=dict, description="Preconditions required for attack setup")
    context_taint: str = Field(default="TAINTED", description="Taint state assigned to injected payload")
    
    # Expectations and Safety
    expected_behavior: ExpectedBehavior = Field(default=ExpectedBehavior.BLOCK, description="Expected defense outcome")
    severity: str = Field(default="HIGH", description="Assessed threat severity (LOW/MEDIUM/HIGH/CRITICAL)")
    safety_class: SafetyClass = Field(default=SafetyClass.LOCAL_SYNTHETIC, description="Safety classification")
    
    # Mutation Lineage
    mutation_of: Optional[str] = Field(default=None, description="Base attack ID if this is a mutated variant")
    mutation_strategy: Optional[str] = Field(default=None, description="Mutation strategy applied to generate this case")
    
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional contextual metadata")
