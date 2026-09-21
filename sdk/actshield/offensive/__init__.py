"""ActShield Offensive Security Validation Engine."""

from actshield.offensive.attack import (
    AttackCase,
    AttackType,
    ExpectedBehavior,
    SafetyClass,
)
from actshield.offensive.target import (
    AttackTarget,
    TargetEnvironment,
    TargetRegistry,
    target_registry,
)
from actshield.offensive.safety import (
    SafetyValidationResult,
    SafetyValidator,
    safety_validator,
)
from actshield.offensive.evidence import SecurityAnalysisEvidence
from actshield.offensive.results import (
    AttackStatus,
    ExecutionEvidence,
    OffensiveAttackResult,
)
from actshield.offensive.evaluator import AttackEvaluator
from actshield.offensive.mutation import (
    MutationEngine,
    MutationStrategy,
)
from actshield.offensive.campaign import (
    AttackCampaign,
    CampaignSummary,
)
from actshield.offensive.corpus import (
    AttackCorpus,
    attack_corpus,
)
from actshield.offensive.generator import (
    AIAttackGenerator,
    OFFENSIVE_SYSTEM_PROMPT,
)
from actshield.offensive.vulnerable_target import VulnerableDemoTarget
from actshield.offensive.engine import OffensiveEngine
from actshield.offensive.adaptive import (
    AdaptiveAttackSelector,
    AdaptiveEngine,
    BoundarySearchEngine,
    CampaignMemory,
    DefenseCategory,
    DefenseFeedback,
    FeedbackAnalyzer,
    MutationNode,
    MutationPlanner,
)

__all__ = [
    "AttackCase",
    "AttackType",
    "ExpectedBehavior",
    "SafetyClass",
    "AttackTarget",
    "TargetEnvironment",
    "TargetRegistry",
    "target_registry",
    "SafetyValidationResult",
    "SafetyValidator",
    "safety_validator",
    "SecurityAnalysisEvidence",
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
    "OFFENSIVE_SYSTEM_PROMPT",
    "VulnerableDemoTarget",
    "OffensiveEngine",
    "AdaptiveAttackSelector",
    "AdaptiveEngine",
    "BoundarySearchEngine",
    "CampaignMemory",
    "DefenseCategory",
    "DefenseFeedback",
    "FeedbackAnalyzer",
    "MutationNode",
    "MutationPlanner",
]


