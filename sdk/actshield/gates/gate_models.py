"""Security Quality Gate Models for CI/CD Integration (Phase 9)."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from actshield.tracing.correlation import generate_id


class GateStatus(str, Enum):
    """Overall status of a CI/CD security gate evaluation."""
    PASSED = "PASSED"
    FAILED = "FAILED"
    WARNING = "WARNING"


class GateCheckRule(BaseModel):
    """Specific deterministic check executed by the security gate."""
    rule_name: str
    description: str
    passed: bool
    observed_value: Any
    threshold: Any
    failure_message: Optional[str] = None


class SecurityGateResult(BaseModel):
    """Machine-readable security gate outcome for CI/CD pipelines."""
    gate_id: str = Field(default_factory=lambda: generate_id("gate"))
    status: GateStatus = Field(default=GateStatus.PASSED)
    exit_code: int = Field(default=0, description="0 = PASS, 1 = FAIL")
    evaluated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    campaign_name: Optional[str] = None
    total_attacks_tested: int = 0
    blocked_attacks_count: int = 0
    bypassed_attacks_count: int = 0
    unauthorized_db_calls: int = 0
    open_regressions_count: int = 0
    failed_replays_count: int = 0
    checks: List[GateCheckRule] = Field(default_factory=list)
    summary: str = ""
    metadata: Dict[str, Any] = Field(default_factory=dict)

