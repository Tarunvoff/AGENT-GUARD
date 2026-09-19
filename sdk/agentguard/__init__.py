"""AgentGuard: Causal Security & Enforcement SDK for Multi-Agent AI Systems."""

from agentguard.agents.agent import Agent
from agentguard.agents.identity import AgentCapability, AgentIdentity, AgentTrustLevel
from agentguard.client import AgentGuard
from agentguard.config import AgentGuardConfig
from agentguard.context.context import Context
from agentguard.context.provenance import ContextSource, ContextTrustLevel, Provenance, ProvenanceHop, SanitizationRecord
from agentguard.context.taint import TaintState
from agentguard.decisions.decision import DecisionAction, SecurityDecision
from agentguard.delegation.authority import AuthorityGrant
from agentguard.delegation.delegation import Delegation, DelegationScope
from agentguard.approval.approval import (
    ApprovalManager,
    ApprovalRequest,
    ApprovalStatus,
)
from agentguard.gateway.http import HTTPGateway, HTTPInterceptedResponse
from agentguard.gateway.mcp import MCPGateway, MCPMessage

from agentguard.integrations.ai_secura import (
    AISecuraClient,
    LocalAISecuraAdapter,
    SecurityAnalysis,
    SecurityContext,
    SecurityReasoner,
)
from agentguard.integrations.ai_secura_analysis import (
    AISecuraAnalysis,
    ThreatSeverity,
    IntentAlignment,
    AIRecommendation,
    AttackTechnique,
    EvidenceTriad,
    AuthorityAnalysis,
    TaintAnalysis,
)
from agentguard.integrations.ollama_adapter import OllamaAISecuraAdapter
from agentguard.llm_config import LLMConfig
from agentguard.integrations.apiris import (
    APIAnalysis,
    APIIntelligence,
    APIRISClient,
    LocalAPIRISAdapter,
)
from agentguard.persistence.siem import SIEMExporter, SIEMFormat
from agentguard.persistence.storage import (
    PostgresStorage,
    SQLiteStorage,
    StorageBackend,
)
from agentguard.policy.evaluator import PolicyEvaluator
from agentguard.policy.intent import (
    DeterministicIntentAnalyzer,
    IntentAlignmentResult,
    IntentAlignmentStatus,
    IntentAnalyzer,
)
from agentguard.policy.policy import Policy, PolicyRule, RuleCondition
from agentguard.risk.models import RiskAssessment, RiskFactorBreakdown, RiskLevel, RiskSignal
from agentguard.tasks.task import Task, TaskContext, TaskStatus
from agentguard.tools.interceptor import protected_tool
from agentguard.tools.tool import (
    Resource,
    SensitivityLevel,
    ToolDefinition,
    ToolRequest,
    ToolResult,
)
from agentguard.tracing.correlation import (
    CorrelationContext,
    SpanScope,
    generate_id,
    get_current_agent_id,
    get_current_context,
    get_current_delegation_id,
    get_current_span_id,
    get_current_task_id,
    get_current_trace_id,
)
from agentguard.tracing.events import EventType, SecurityEvent
from agentguard.tracing.tracer import CausalEdge, CausalGraph, CausalNode, TraceManager

__version__ = "0.3.5"

__all__ = [
    "AgentGuard",
    "AgentGuardConfig",
    "Agent",
    "AgentIdentity",
    "AgentCapability",
    "AgentTrustLevel",
    "Task",
    "TaskContext",
    "TaskStatus",
    "Delegation",
    "DelegationScope",
    "AuthorityGrant",
    "Context",
    "ContextSource",
    "ContextTrustLevel",
    "Provenance",
    "ProvenanceHop",
    "SanitizationRecord",
    "TaintState",
    "ToolDefinition",
    "Resource",
    "SensitivityLevel",
    "ToolRequest",
    "ToolResult",
    "protected_tool",
    "Policy",
    "PolicyRule",
    "RuleCondition",
    "PolicyEvaluator",
    "IntentAnalyzer",
    "DeterministicIntentAnalyzer",
    "IntentAlignmentStatus",
    "IntentAlignmentResult",
    "RiskLevel",
    "RiskSignal",
    "RiskAssessment",
    "RiskFactorBreakdown",
    "DecisionAction",
    "SecurityDecision",
    "EventType",
    "SecurityEvent",
    "CorrelationContext",
    "SpanScope",
    "generate_id",
    "get_current_context",
    "get_current_trace_id",
    "get_current_span_id",
    "get_current_agent_id",
    "get_current_task_id",
    "get_current_delegation_id",
    "CausalNode",
    "CausalEdge",
    "CausalGraph",
    "TraceManager",
    "SecurityReasoner",
    "SecurityContext",
    "SecurityAnalysis",
    "AISecuraClient",
    "LocalAISecuraAdapter",
    "APIIntelligence",
    "APIAnalysis",
    "APIRISClient",
    "LocalAPIRISAdapter",
    "MCPGateway",
    "MCPMessage",
    "HTTPGateway",
    "HTTPInterceptedResponse",
    "ApprovalManager",
    "ApprovalRequest",
    "ApprovalStatus",
    "StorageBackend",
    "SQLiteStorage",
    "PostgresStorage",
    "SIEMExporter",
    "SIEMFormat",
    "OllamaAISecuraAdapter",
    "AISecuraAnalysis",
    "ThreatSeverity",
    "IntentAlignment",
    "AIRecommendation",
    "AttackTechnique",
    "EvidenceTriad",
    "AuthorityAnalysis",
    "TaintAnalysis",
    "LLMConfig",
]

