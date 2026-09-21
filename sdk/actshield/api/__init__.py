"""ActShield Unified Product API — FastAPI routes for dashboard consumption.

Provides clean JSON endpoints that the future React dashboard can consume
without importing any ActShield Python internals.

Architecture:
    ForensicService → ForensicQueryEngine → API routes → JSON responses
"""

from actshield.api.service import ApiService
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


