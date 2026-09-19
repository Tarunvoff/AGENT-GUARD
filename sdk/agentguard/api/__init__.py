"""AgentGuard Unified Product API — FastAPI routes for dashboard consumption.

Provides clean JSON endpoints that the future React dashboard can consume
without importing any AgentGuard Python internals.

Architecture:
    ForensicService → ForensicQueryEngine → API routes → JSON responses
"""

from agentguard.api.service import ApiService
from agentguard.api.models import (
    AgentAccessResponse,
    ResourceAccessResponse,
    AccessMatrixResponse,
    OverviewResponse,
    AttackForensicsResponse,
    IncidentResponse,
    ErrorResponse,
    HealthResponse,
)

__all__ = [
    "ApiService",
    "AgentAccessResponse",
    "ResourceAccessResponse",
    "AccessMatrixResponse",
    "OverviewResponse",
    "AttackForensicsResponse",
    "IncidentResponse",
    "ErrorResponse",
    "HealthResponse",
]
