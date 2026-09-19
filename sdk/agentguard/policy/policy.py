"""Deterministic security policy definitions."""

from enum import Enum
from typing import Any, Callable, Dict, List, Optional
from pydantic import BaseModel, Field

from agentguard.decisions.decision import DecisionAction
from agentguard.risk.models import RiskLevel
from agentguard.tracing.correlation import generate_id


class RuleCondition(str, Enum):
    """Common condition types evaluated by policy rules."""
    CAPABILITY_REQUIRED = "CAPABILITY_REQUIRED"
    TAINT_RESTRICTION = "TAINT_RESTRICTION"
    TRUST_LEVEL_MINIMUM = "TRUST_LEVEL_MINIMUM"
    SENSITIVITY_THRESHOLD = "SENSITIVITY_THRESHOLD"
    APIRIS_RISK_THRESHOLD = "APIRIS_RISK_THRESHOLD"
    AI_SECURA_INTENT_DRIFT = "AI_SECURA_INTENT_DRIFT"
    CUSTOM = "CUSTOM"


class PolicyRule(BaseModel):
    """An individual deterministic rule within a Policy."""
    
    rule_id: str = Field(default_factory=lambda: generate_id("rule"))
    name: str = Field(..., description="Human-readable rule name")
    description: str = Field(default="")
    condition_type: RuleCondition = Field(default=RuleCondition.CUSTOM)
    target_action: DecisionAction = Field(default=DecisionAction.BLOCK, description="Enforcement action if rule matches")
    risk_level: RiskLevel = Field(default=RiskLevel.HIGH)
    reason_code: str = Field(default="POLICY_VIOLATION")
    explanation_template: str = Field(default="Policy rule violation detected.")
    enabled: bool = Field(default=True)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class Policy(BaseModel):
    """A collection of security rules governing agent executions, delegations, and tool access."""
    
    policy_id: str = Field(default_factory=lambda: generate_id("pol"))
    name: str = Field(..., description="Policy name")
    description: str = Field(default="")
    version: str = Field(default="1.0.0")
    rules: List[PolicyRule] = Field(default_factory=list)
    enabled: bool = Field(default=True)
    metadata: Dict[str, Any] = Field(default_factory=dict)
