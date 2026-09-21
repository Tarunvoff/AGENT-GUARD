"""Response action models for ActShield Phase 9."""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from actshield.tracing.correlation import generate_id


class ResponseActionType(str, Enum):
    """Supported containment and response actions (Safe-by-default)."""
    BLOCK_ACTION = "BLOCK_ACTION"
    REQUIRE_HITL = "REQUIRE_HITL"
    QUARANTINE_CONTEXT = "QUARANTINE_CONTEXT"
    REVOKE_DELEGATION = "REVOKE_DELEGATION"
    RESTRICT_AGENT = "RESTRICT_AGENT"
    TRIGGER_SNAPSHOT = "TRIGGER_SNAPSHOT"
    CREATE_REGRESSION = "CREATE_REGRESSION"
    TRIGGER_REPLAY = "TRIGGER_REPLAY"


class ResponseActionRecord(BaseModel):
    """Record of an executed containment or response action."""
    action_id: str = Field(default_factory=lambda: generate_id("act"))
    action_type: ResponseActionType
    target_entity: str = Field(..., description="Agent ID, context ID, or delegation ID")
    reason: str
    status: str = Field(default="EXECUTED")
    details: Dict[str, Any] = Field(default_factory=dict)
    executed_at: str

    @property
    def target_id(self) -> str:
        return self.target_entity



