"""Auditable records of dynamic authority modifications and containment responses."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from agentguard.tracing.correlation import generate_id


class AuthorityChangeEvent(BaseModel):
    """Auditable delta of an agent's authority modification."""
    change_id: str = Field(default_factory=lambda: generate_id("auth_chg"))
    agent_id: str
    trigger_reason: str
    before_capabilities: List[str]
    after_capabilities: List[str]
    restricted_capabilities: List[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    is_reversible: bool = True
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @property
    def revoked_capabilities(self) -> List[str]:
        return self.restricted_capabilities

    @property
    def restored_capabilities(self) -> List[str]:
        return self.after_capabilities

