"""Results and evidence recording for offensive security validations."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from agentguard.offensive.attack import AttackType, ExpectedBehavior
from agentguard.offensive.evidence import SecurityAnalysisEvidence


class AttackStatus(str, Enum):
    """Overall status of an offensive attack validation."""
    PASS = "PASS"         # Attack was defended as expected (e.g. expected BLOCK and was BLOCKED with 0 sensitive sink executions)
    BYPASS = "BYPASS"     # Critical Security Failure: Attack succeeded in unauthorized execution
    ERROR = "ERROR"       # Engine or execution error during simulation
    REFUSED = "REFUSED"   # Attack was refused by SafetyValidator due to policy/safety rules


class ExecutionEvidence(BaseModel):
    """Hard empirical execution metrics confirming whether tools executed."""
    tool_executed: bool = Field(default=False, description="Did the target tool execute?")
    execution_count: int = Field(default=0, description="Total execution count of target tool")
    sensitive_db_calls: int = Field(default=0, description="Actual counter of sensitive database executions")
    actual_action: str = Field(default="UNKNOWN", description="Actual policy decision action (ALLOW/BLOCK/etc.)")
    policy_reason: str = Field(default="", description="Policy reason code or explanation")
    taint_state: str = Field(default="CLEAN", description="Observed taint state at the tool sink")
    causal_trace_preserved: bool = Field(default=True, description="Was causal correlation preserved across the flow?")


class OffensiveAttackResult(BaseModel):
    """Comprehensive auditable record of an offensive validation run."""

    attack_id: str = Field(..., description="ID of the executed attack case")
    campaign_id: Optional[str] = Field(default=None, description="Campaign identifier")
    attack_type: AttackType = Field(..., description="Classification of attack vector")
    target: str = Field(..., description="Target system identifier")
    entry_point: str = Field(..., description="Entry point utilized")
    
    # Decisions & Execution
    expected_decision: str = Field(default="BLOCK", description="Expected policy decision")
    actual_decision: str = Field(default="UNKNOWN", description="Actual policy decision rendered")
    expected_execution: bool = Field(default=False, description="Was the tool expected to execute?")
    actual_execution: bool = Field(default=False, description="Did the tool actually execute?")
    
    # Defense Metrics
    blocked: bool = Field(default=False, description="True if policy blocked the action")
    bypassed: bool = Field(default=False, description="True if attack bypassed defenses (SECURITY FAILURE)")
    
    # Causal & Security Trace Lineage
    trace_id: Optional[str] = Field(default=None, description="Causal correlation trace ID")
    attack_path: List[Dict[str, Any]] = Field(default_factory=list, description="Causal propagation hops")
    influencing_context: List[str] = Field(default_factory=list, description="Context IDs influencing execution")
    taint_state: str = Field(default="TAINTED", description="Taint state at execution sink")
    authority_violation: bool = Field(default=False, description="Was authority containment violated?")
    intent_violation: bool = Field(default=False, description="Was original intent violated?")
    
    # Intelligence Signals & Unified Evidence
    ai_analysis: Optional[Dict[str, Any]] = Field(default=None, description="AI Secura advisory analysis")
    apiris_analysis: Optional[Dict[str, Any]] = Field(default=None, description="APIRIS intelligence analysis")
    security_evidence: Optional[SecurityAnalysisEvidence] = Field(default=None, description="Unified security analysis evidence")
    mutation_lineage: List[str] = Field(default_factory=list, description="List of mutation IDs leading to this attack")
    
    # Hard Execution Evidence
    execution_evidence: ExecutionEvidence = Field(default_factory=ExecutionEvidence, description="Execution counters")
    severity: str = Field(default="HIGH", description="Attack severity")
    latency_ms: float = Field(default=0.0, description="Total execution latency in milliseconds")
    
    status: AttackStatus = Field(default=AttackStatus.PASS, description="Final outcome (PASS/BYPASS/ERROR/REFUSED)")
    error_message: Optional[str] = Field(default=None, description="Error or refusal details")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Timestamp of execution")
