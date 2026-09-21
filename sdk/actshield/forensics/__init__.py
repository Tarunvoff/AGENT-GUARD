"""ActShield Phase 6.5 — Forensic Intelligence Layer.

Turns existing runtime security events into a coherent forensic intelligence
layer answering: WHAT happened, WHY, WHO caused it, WHO had authority,
WHAT was accessed (or attempted), and WHAT could be reached.

Read-only with respect to security authority. PolicyEvaluator remains the
enforcement authority. This layer only observes and answers queries.
"""

from actshield.forensics.models import (
    AgentAccessProfile,
    ResourceAccessProfile,
    AuthorityRelationship,
    AccessRelationship,
    DelegationRelationship,
    AccessAttempt,
    ActualAccess,
    AccessSnapshot,
    AccessDiff,
    ForensicExplanation,
    AttackForensicReport,
    AccessDecision,
    ForensicIncident,
    IncidentType,
    IncidentSeverity,
)
from actshield.forensics.service import ForensicService
from actshield.forensics.queries import ForensicQueryEngine

__all__ = [
    # Models
    "AgentAccessProfile",
    "ResourceAccessProfile",
    "AuthorityRelationship",
    "AccessRelationship",
    "DelegationRelationship",
    "AccessAttempt",
    "ActualAccess",
    "AccessSnapshot",
    "AccessDiff",
    "ForensicExplanation",
    "AttackForensicReport",
    "AccessDecision",
    "ForensicIncident",
    "IncidentType",
    "IncidentSeverity",
    # Services
    "ForensicService",
    "ForensicQueryEngine",
]


