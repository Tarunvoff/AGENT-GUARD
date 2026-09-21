"""ActShield: Security Control Plane SDK for Autonomous and Multi-Agent AI Systems.

Quick start::

    from actshield import ActShield

    guard = ActShield(mode="strict")

    @guard.protect(tool="customer_db.read", sensitivity="critical")
    async def read_customer_data():
        ...

    # Threat modeling
    from actshield.threatmodel import ThreatAnalyzer
    analyzer = ThreatAnalyzer()
    result = analyzer.analyze()
"""

from actshield.agents.agent import Agent
from actshield.agents.identity import AgentCapability, AgentIdentity, AgentStatus, AgentTrustLevel
from actshield.client import ActShield
from actshield.config import ActShieldConfig
from actshield.context.context import Context
from actshield.context.provenance import ContextSource, ContextTrustLevel, Provenance, ProvenanceHop, SanitizationRecord
from actshield.context.taint import TaintState
from actshield.decisions.decision import DecisionAction, SecurityDecision
from actshield.delegation.authority import AuthorityGrant
from actshield.delegation.delegation import Delegation, DelegationScope
from actshield.approval.approval import (
    ApprovalManager,
    ApprovalRequest,
    ApprovalStatus,
)
from actshield.gateway.http import HTTPGateway, HTTPInterceptedResponse
from actshield.gateway.mcp import MCPGateway, MCPMessage

from actshield.integrations.ai_secura import (
    AISecuraClient,
    LocalAISecuraAdapter,
    SecurityAnalysis,
    SecurityContext,
    SecurityReasoner,
)
from actshield.integrations.ai_secura_analysis import (
    AISecuraAnalysis,
    ThreatSeverity,
    IntentAlignment,
    AIRecommendation,
    AttackTechnique,
    EvidenceTriad,
    AuthorityAnalysis,
    TaintAnalysis,
)
from actshield.integrations.ollama_adapter import OllamaAISecuraAdapter
from actshield.llm_config import LLMConfig
from actshield.offensive import (
    AttackCase,
    AttackType,
    ExpectedBehavior,
    SafetyClass,
    AttackTarget,
    TargetEnvironment,
    TargetRegistry,
    target_registry,
    SafetyValidationResult,
    SafetyValidator,
    safety_validator,
    AttackStatus,
    ExecutionEvidence,
    OffensiveAttackResult,
    AttackEvaluator,
    MutationEngine,
    MutationStrategy,
    AttackCampaign,
    CampaignSummary,
    AttackCorpus,
    attack_corpus,
    AIAttackGenerator,
    VulnerableDemoTarget,
    OffensiveEngine,
    SecurityAnalysisEvidence,
    AdaptiveEngine,
    CampaignMemory,
)
from actshield.integrations.apiris import (
    APIAnalysis,
    APIIntelligence,
    APIRISClient,
    LocalAPIRISAdapter,
)
from actshield.persistence.siem import SIEMExporter, SIEMFormat
from actshield.persistence.storage import (
    PostgresStorage,
    SQLiteStorage,
    StorageBackend,
)
from actshield.policy.evaluator import PolicyEvaluator
from actshield.policy.intent import (
    DeterministicIntentAnalyzer,
    IntentAlignmentResult,
    IntentAlignmentStatus,
    IntentAnalyzer,
)
from actshield.policy.policy import Policy, PolicyRule, RuleCondition
from actshield.risk.models import RiskAssessment, RiskFactorBreakdown, RiskLevel, RiskSignal
from actshield.tasks.task import Task, TaskContext, TaskStatus
from actshield.tools.interceptor import protected_tool
from actshield.tools.tool import (
    Resource,
    SensitivityLevel,
    ToolDefinition,
    ToolRequest,
    ToolResult,
)
from actshield.tracing.correlation import (
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
from actshield.tracing.events import EventType, SecurityEvent
from actshield.tracing.tracer import CausalEdge, CausalGraph, CausalNode, TraceManager

__version__ = "0.9.0"

# Phase 6.5 — Forensic Intelligence + Product API
from actshield.forensics.service import ForensicService
from actshield.forensics.queries import ForensicQueryEngine
from actshield.forensics.models import (
    AgentAccessProfile,
    ResourceAccessProfile,
    AccessAttempt,
    ActualAccess,
    AccessSnapshot,
    AccessDiff,
    ForensicExplanation,
    AttackForensicReport,
    ForensicIncident,
    IncidentType,
    IncidentSeverity,
    AccessMatrix,
)
from actshield.api.service import ApiService, SecurityPrincipal
from actshield.api.models import (
    AgentAccessResponse,
    ResourceAccessResponse,
    AccessMatrixResponse,
    OverviewResponse,
    AttackForensicsResponse,
    IncidentResponse,
    ErrorResponse,
    HealthResponse,
)

# Phase 9 — Continuous Security Control Plane
from actshield.posture import (
    SecurityPostureSnapshot,
    PostureRating,
    FindingSeverity,
    PostureFinding,
    PostureDimensionMetrics,
    PostureDiff,
    PostureEngine,
    PostureDiffEngine,
    PostureRuleEvaluator,
)
from actshield.incidents import (
    SecurityIncident,
    IncidentState,
    IncidentStateMachine,
    IncidentTimelineEntry,
    IncidentEngine,
    IncidentCreationRule,
)
from actshield.response import (
    ResponseActionType,
    ResponseActionRecord,
    AuthorityChangeEvent,
    ResponseEngine,
)
from actshield.drift import (
    DriftCategory,
    DriftSeverity,
    DriftEvent,
    AgentBehaviorBaseline,
    BehavioralBaselineTracker,
    AuthorityDriftDetector,
    AccessDriftDetector,
    ContextDriftDetector,
)
from actshield.gates import (
    GateStatus,
    GateCheckRule,
    SecurityGateResult,
    SecurityGateEvaluator,
    security_gate,
)

# Threat Modeling
from actshield.threatmodel import (
    ThreatAnalyzer,
    ThreatReportRenderer,
    ThreatModelExporter,
    ThreatModel,
    AnalysisResult as ThreatAnalysisResult,
    ThreatSeverity,
    ThreatCategory,
    Asset,
    AssetSensitivity,
    ThreatActor,
    ActorType,
    TrustBoundary,
    BoundaryType,
    Threat,
    AttackScenario,
)

__all__ = [
    "ActShield",
    "ActShieldConfig",
    "Agent",
    "AgentIdentity",
    "AgentCapability",
    "AgentTrustLevel",
    "AgentStatus",
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
    "LLMConfig",
    # Phase 4 Offensive Validation Engine
    "AttackCase",
    "AttackType",
    "ExpectedBehavior",
    "SafetyClass",
    "AttackTarget",
    "TargetEnvironment",
    "TargetRegistry",
    "target_registry",
    "SafetyValidator",
    "SafetyValidationResult",
    "safety_validator",
    "AttackStatus",
    "ExecutionEvidence",
    "OffensiveAttackResult",
    "AttackEvaluator",
    "MutationEngine",
    "MutationStrategy",
    "AttackCampaign",
    "CampaignSummary",
    "AttackCorpus",
    "attack_corpus",
    "AIAttackGenerator",
    "VulnerableDemoTarget",
    "OffensiveEngine",
    # Phase 5 Adaptive Offensive Security Validation
    "SecurityAnalysisEvidence",
    "AdaptiveEngine",
    "CampaignMemory",
    # Phase 6.5 — Forensic Intelligence + Product API
    "ForensicService",
    "ForensicQueryEngine",
    "AgentAccessProfile",
    "ResourceAccessProfile",
    "AccessAttempt",
    "ActualAccess",
    "AccessSnapshot",
    "AccessDiff",
    "ForensicExplanation",
    "AttackForensicReport",
    "ForensicIncident",
    "IncidentType",
    "IncidentSeverity",
    "AccessMatrix",
    "ApiService",
    "SecurityPrincipal",
    "AgentAccessResponse",
    "ResourceAccessResponse",
    "AccessMatrixResponse",
    "OverviewResponse",
    "AttackForensicsResponse",
    "IncidentResponse",
    "ErrorResponse",
    "HealthResponse",
    # Phase 9 — Continuous Security Control Plane
    "SecurityPostureSnapshot",
    "PostureRating",
    "FindingSeverity",
    "PostureFinding",
    "PostureDimensionMetrics",
    "PostureDiff",
    "PostureEngine",
    "PostureDiffEngine",
    "PostureRuleEvaluator",
    "SecurityIncident",
    "IncidentState",
    "IncidentStateMachine",
    "IncidentTimelineEntry",
    "IncidentEngine",
    "IncidentCreationRule",
    "ResponseActionType",
    "ResponseActionRecord",
    "AuthorityChangeEvent",
    "ResponseEngine",
    "DriftCategory",
    "DriftSeverity",
    "DriftEvent",
    "AgentBehaviorBaseline",
    "BehavioralBaselineTracker",
    "AuthorityDriftDetector",
    "AccessDriftDetector",
    "ContextDriftDetector",
    "GateStatus",
    "GateCheckRule",
    "SecurityGateResult",
    "SecurityGateEvaluator",
    "security_gate",
    # Threat Modeling
    "ThreatAnalyzer",
    "ThreatReportRenderer",
    "ThreatModelExporter",
    "ThreatModel",
    "ThreatAnalysisResult",
    "ThreatSeverity",
    "ThreatCategory",
    "Asset",
    "AssetSensitivity",
    "ThreatActor",
    "ActorType",
    "TrustBoundary",
    "BoundaryType",
    "Threat",
    "AttackScenario",
    # Backward Compatibility Aliases
    "AgentGuard",
    "AgentGuardConfig",
]

# Backward compatibility aliases
AgentGuard = ActShield
AgentGuardConfig = ActShieldConfig






