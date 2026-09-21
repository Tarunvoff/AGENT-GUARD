"""Human-in-the-Loop (HITL) approval governance and workflows."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional
import uuid
from pydantic import BaseModel, Field

from actshield.decisions.decision import SecurityDecision
from actshield.tools.tool import ToolDefinition, ToolRequest
from actshield.tracing.events import EventType


class ApprovalStatus(str, Enum):
    """Lifecycle status of a human approval ticket."""
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"


class ApprovalRequest(BaseModel):
    """Human-in-the-Loop approval ticket representation."""
    request_id: str = Field(default_factory=lambda: f"appr_{uuid.uuid4().hex[:12]}")
    trace_id: str
    tool_name: str
    tool_id: str
    arguments: Dict[str, Any] = Field(default_factory=dict)
    requesting_agent_id: Optional[str] = None
    reason: str
    risk_score: float = 0.0
    status: ApprovalStatus = ApprovalStatus.PENDING
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    reviewed_at: Optional[datetime] = None
    reviewer_id: Optional[str] = None
    review_notes: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @property
    def is_pending(self) -> bool:
        return self.status == ApprovalStatus.PENDING

    @property
    def is_approved(self) -> bool:
        return self.status == ApprovalStatus.APPROVED


class ApprovalManager:
    """Manages pending human approval requests and approval lifecycle callbacks."""

    def __init__(self, guard: Any) -> None:
        self.guard = guard
        self._requests: Dict[str, ApprovalRequest] = {}
        self._handlers: List[Callable[[ApprovalRequest], None]] = []

    def register_notification_handler(self, handler: Callable[[ApprovalRequest], None]) -> None:
        """Register a callback for new approval requests (e.g. Slack/Teams/PagerDuty notification)."""
        self._handlers.append(handler)

    def request_approval(
        self,
        tool_def: ToolDefinition,
        request: ToolRequest,
        decision: SecurityDecision,
        trace_id: str,
        reason: Optional[str] = None,
    ) -> ApprovalRequest:
        """Create and register a pending human approval ticket."""
        appr = ApprovalRequest(
            trace_id=trace_id,
            tool_name=tool_def.name,
            tool_id=tool_def.tool_id,
            arguments=request.arguments,
            requesting_agent_id=request.agent_id,
            reason=reason or decision.explanation or "Requires explicit human confirmation.",
            risk_score=decision.risk_score,
            metadata={
                "sensitivity": tool_def.sensitivity.value,
                "reason_code": decision.reason_code,
            },
        )
        self._requests[appr.request_id] = appr

        # Emit approval.requested event
        self.guard.emit_event(
            event_type=EventType.APPROVAL_REQUESTED,
            trace_id=trace_id,
            agent_id=request.agent_id,
            payload={
                "approval_id": appr.request_id,
                "tool_name": tool_def.name,
                "reason": appr.reason,
                "risk_score": appr.risk_score,
                "status": appr.status.value,
            },
        )

        for handler in self._handlers:
            try:
                handler(appr)
            except Exception:
                pass

        return appr

    def approve(self, request_id: str, reviewer_id: str, notes: str = "Approved by authorized human operator") -> ApprovalRequest:
        """Grant approval to a pending request."""
        if request_id not in self._requests:
            raise KeyError(f"Approval request '{request_id}' not found.")
        
        req = self._requests[request_id]
        if req.status != ApprovalStatus.PENDING:
            raise ValueError(f"Approval request '{request_id}' is not in PENDING status (current: {req.status}).")

        req.status = ApprovalStatus.APPROVED
        req.reviewer_id = reviewer_id
        req.review_notes = notes
        req.reviewed_at = datetime.now(timezone.utc)

        # Emit approval.granted event
        self.guard.emit_event(
            event_type=EventType.APPROVAL_GRANTED,
            trace_id=req.trace_id,
            agent_id=req.requesting_agent_id,
            payload={
                "approval_id": req.request_id,
                "tool_name": req.tool_name,
                "reviewer_id": reviewer_id,
                "notes": notes,
            },
        )
        return req

    def reject(self, request_id: str, reviewer_id: str, notes: str = "Rejected by human security operator") -> ApprovalRequest:
        """Reject a pending approval request."""
        if request_id not in self._requests:
            raise KeyError(f"Approval request '{request_id}' not found.")
        
        req = self._requests[request_id]
        req.status = ApprovalStatus.REJECTED
        req.reviewer_id = reviewer_id
        req.review_notes = notes
        req.reviewed_at = datetime.now(timezone.utc)

        # Emit approval.rejected event
        self.guard.emit_event(
            event_type=EventType.APPROVAL_REJECTED,
            trace_id=req.trace_id,
            agent_id=req.requesting_agent_id,
            payload={
                "approval_id": req.request_id,
                "tool_name": req.tool_name,
                "reviewer_id": reviewer_id,
                "notes": notes,
            },
        )
        return req

    def get_request(self, request_id: str) -> Optional[ApprovalRequest]:
        return self._requests.get(request_id)

    def get_pending_requests(self) -> List[ApprovalRequest]:
        return [r for r in self._requests.values() if r.status == ApprovalStatus.PENDING]

