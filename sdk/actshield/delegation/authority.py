"""Authority granting and monotonic delegation validation."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set
from pydantic import BaseModel, Field

from actshield.tracing.correlation import generate_id


class AuthorityGrant(BaseModel):
    """Explicit grant of capabilities from a delegator to a delegate."""
    
    grant_id: str = Field(default_factory=lambda: generate_id("grnt"))
    delegator_agent_id: str = Field(..., description="Agent ID yielding authority")
    delegate_agent_id: str = Field(..., description="Agent ID receiving authority")
    granted_capabilities: List[str] = Field(
        default_factory=list,
        description="Explicit list of capability names granted"
    )
    constraints: Dict[str, Any] = Field(
        default_factory=dict,
        description="Optional execution constraints (e.g. rate_limit, max_cost, valid_until)"
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC grant creation timestamp"
    )

    def contains_capability(self, capability_name: str) -> bool:
        """Verify if a specific capability is covered by this grant."""
        if "*" in self.granted_capabilities or capability_name in self.granted_capabilities:
            return True
        for cap in self.granted_capabilities:
            if cap.endswith(".*") and capability_name.startswith(cap[:-2]):
                return True
        return False

    def validate_monotonic_reduction(
        self,
        delegator_available_capabilities: List[str],
        strict: bool = True,
    ) -> bool:
        """Enforce that granted capabilities are a strict subset of delegator available capabilities."""
        if not strict:
            return True
        if "*" in delegator_available_capabilities:
            return True
        
        delegator_set: Set[str] = set(delegator_available_capabilities)
        for requested_cap in self.granted_capabilities:
            if requested_cap == "*":
                return False  # Cannot grant wildcard if delegator doesn't have wildcard
            if requested_cap not in delegator_set:
                # Check wildcard prefix
                matched = False
                for d_cap in delegator_set:
                    if d_cap.endswith(".*") and requested_cap.startswith(d_cap[:-2]):
                        matched = True
                        break
                if not matched:
                    return False
        return True

