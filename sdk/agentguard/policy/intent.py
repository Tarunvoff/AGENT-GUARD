"""Intent tracking and deterministic intent alignment analysis."""

from enum import Enum
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable
from pydantic import BaseModel, Field


class IntentAlignmentStatus(str, Enum):
    """Alignment status between original user intent and requested agent action."""
    ALIGNED = "ALIGNED"
    MISALIGNED = "MISALIGNED"
    VIOLATION = "VIOLATION"
    UNKNOWN = "UNKNOWN"


class IntentAlignmentResult(BaseModel):
    """Result of intent alignment verification."""
    status: IntentAlignmentStatus = IntentAlignmentStatus.ALIGNED
    score: float = Field(default=0.0, ge=0.0, le=1.0, description="Risk contribution (0.0 = aligned, 1.0 = direct violation)")
    explanation: str = Field(default="Action aligns with original user intent.")
    matched_indicators: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def __init__(self, **data: Any) -> None:
        if "reason" in data and "explanation" not in data:
            data["explanation"] = data["reason"]
        super().__init__(**data)

    @property
    def is_violation(self) -> bool:
        return self.status in (IntentAlignmentStatus.VIOLATION, IntentAlignmentStatus.MISALIGNED)

    @property
    def reason(self) -> str:
        return self.explanation




@runtime_checkable
class IntentAnalyzer(Protocol):
    """Protocol for intent alignment analysis (extensible for AI Secura in Phase 5)."""

    def analyze(
        self,
        original_intent: str,
        tool_name: str,
        required_capabilities: List[str],
        target_resource_sensitivity: str,
        target_resource_name: Optional[str] = None,
        arguments: Optional[Dict[str, Any]] = None,
    ) -> IntentAlignmentResult:
        """Evaluate if the requested action and required capability remain within the original user intent."""
        ...


class DeterministicIntentAnalyzer(IntentAnalyzer):
    """Deterministic, explainable baseline intent analyzer for Phase 2."""

    def analyze(
        self,
        original_intent: str,
        tool_name: str,
        required_capabilities: List[str],
        target_resource_sensitivity: str,
        target_resource_name: Optional[str] = None,
        arguments: Optional[Dict[str, Any]] = None,
    ) -> IntentAlignmentResult:
        intent_lower = (original_intent or "").lower()
        tool_lower = (tool_name or "").lower()
        res_lower = (target_resource_name or "").lower()
        caps = [c.lower() for c in required_capabilities]

        indicators: List[str] = []

        # Check for public/financial scope vs customer PII / sensitive data
        is_public_financial_intent = any(k in intent_lower for k in ("public", "financial", "sec", "annual report", "10-k", "market"))
        is_customer_pii_target = any("customer" in c for c in caps) or "customer" in tool_lower or "customer" in res_lower or "pii" in res_lower
        
        if is_public_financial_intent and is_customer_pii_target:
            indicators.append("PUBLIC_INTENT_VS_CUSTOMER_PII_SINK")
            return IntentAlignmentResult(
                status=IntentAlignmentStatus.VIOLATION,
                score=0.85,
                explanation=(
                    f"Intent Violation: Original user intent was scoped to public financial information ('{original_intent}'), "
                    f"but requested tool '{tool_name}' targets sensitive customer records/PII."
                ),
                matched_indicators=indicators,
            )

        # Check for administrative / destructive actions in audit intents
        is_read_intent = any(k in intent_lower for k in ("analyze", "audit", "find", "read", "extract", "search"))
        is_destructive_action = any(k in tool_lower for k in ("delete", "drop", "write", "modify", "admin", "truncate"))

        if is_read_intent and is_destructive_action:
            indicators.append("READ_AUDIT_INTENT_VS_DESTRUCTIVE_ACTION")
            return IntentAlignmentResult(
                status=IntentAlignmentStatus.VIOLATION,
                score=0.95,
                explanation=(
                    f"Intent Violation: Original intent is read/audit ('{original_intent}'), "
                    f"but requested tool '{tool_name}' performs destructive modification."
                ),
                matched_indicators=indicators,
            )

        return IntentAlignmentResult(
            status=IntentAlignmentStatus.ALIGNED,
            score=0.0,
            explanation=f"Action '{tool_name}' aligns with declared user intent.",
            matched_indicators=[],
        )
