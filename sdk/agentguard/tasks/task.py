"""Task domain model and context management."""

import inspect
from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING, Any, Dict, Optional
from pydantic import BaseModel, Field

from agentguard.tracing.correlation import SpanScope, generate_id, get_current_context
from agentguard.tracing.events import EventType

if TYPE_CHECKING:
    from agentguard.client import AgentGuard


class TaskStatus(str, Enum):
    """Execution status of a task."""
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"


class Task(BaseModel):
    """Represents a discrete goal, query, or user-initiated workflow in the system."""
    
    task_id: str = Field(default_factory=lambda: generate_id("tsk"), description="Unique task ID")
    trace_id: str = Field(..., description="Root trace ID for this task lifecycle")
    original_intent: str = Field(..., description="The original human/initiator intent description")
    initiating_user: Optional[str] = Field(default=None, description="Username, identity or sub of initiating user")
    initiating_application: Optional[str] = Field(default=None, description="Application or service initiating the task")
    status: TaskStatus = Field(default=TaskStatus.RUNNING, description="Current task status")
    parent_task_id: Optional[str] = Field(default=None, description="Parent task ID if nested")
    start_time: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC start time"
    )
    end_time: Optional[datetime] = Field(default=None, description="UTC completion time")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary task metadata")

    def complete(self, status: TaskStatus = TaskStatus.COMPLETED) -> None:
        """Mark task as finished."""
        self.status = status
        self.end_time = datetime.now(timezone.utc)


class TaskContext:
    """Context manager scope establishing task boundaries, correlation IDs, and lifecycle events."""

    def __init__(
        self,
        guard: "AgentGuard",
        intent: str,
        initiating_user: Optional[str] = None,
        initiating_application: Optional[str] = None,
        task_id: Optional[str] = None,
        trace_id: Optional[str] = None,
        parent_task_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.guard = guard
        self.intent = intent
        self.initiating_user = initiating_user
        self.initiating_application = initiating_application
        self._requested_task_id = task_id or generate_id("tsk")
        self._requested_trace_id = trace_id
        self._parent_task_id = parent_task_id
        self._metadata = metadata or {}
        
        self.task: Optional[Task] = None
        self._span_scope: Optional[SpanScope] = None

    def __enter__(self) -> Task:
        current_ctx = get_current_context()
        trace_id = self._requested_trace_id or (current_ctx.trace_id if current_ctx else generate_id("trc"))
        parent_task_id = self._parent_task_id or (current_ctx.task_id if current_ctx else None)

        self.task = Task(
            task_id=self._requested_task_id,
            trace_id=trace_id,
            original_intent=self.intent,
            initiating_user=self.initiating_user,
            initiating_application=self.initiating_application,
            status=TaskStatus.RUNNING,
            parent_task_id=parent_task_id,
            metadata=self._metadata,
        )

        self._span_scope = SpanScope(
            name=f"task:{self.task.task_id}",
            trace_id=self.task.trace_id,
            task_id=self.task.task_id,
            metadata={"intent": self.intent},
        )
        self._span_scope.__enter__()

        # Emit task.started event
        self.guard.emit_event(
            event_type=EventType.TASK_STARTED,
            task_id=self.task.task_id,
            payload={
                "intent": self.intent,
                "initiating_user": self.initiating_user,
                "initiating_application": self.initiating_application,
                "parent_task_id": self.task.parent_task_id,
            },
            metadata=self._metadata,
        )

        return self.task

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if self.task:
            if exc_type is not None:
                self.task.complete(status=TaskStatus.FAILED)
            else:
                self.task.complete(status=TaskStatus.COMPLETED)

            # Emit task.completed event
            self.guard.emit_event(
                event_type=EventType.TASK_COMPLETED,
                task_id=self.task.task_id,
                payload={
                    "status": self.task.status.value,
                    "duration_seconds": (
                        (self.task.end_time - self.task.start_time).total_seconds()
                        if self.task.end_time else 0.0
                    ),
                    "error": str(exc_val) if exc_val else None,
                }
            )

        if self._span_scope:
            self._span_scope.__exit__(exc_type, exc_val, exc_tb)

    async def __aenter__(self) -> Task:
        return self.__enter__()

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.__exit__(exc_type, exc_val, exc_tb)
