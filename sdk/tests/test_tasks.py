"""Tests for task lifecycle, scoping, and nested tasks."""

import pytest
from actshield.client import ActShield
from actshield.tasks.task import TaskStatus
from actshield.tracing.correlation import get_current_task_id, get_current_trace_id


def test_task_context_lifecycle():
    guard = ActShield()

    assert get_current_trace_id() is None
    assert get_current_task_id() is None

    with guard.task(
        intent="Find the latest public financial report",
        initiating_user="alice@enterprise.com",
        initiating_application="portal_v2",
    ) as task:
        assert task.task_id.startswith("tsk_")
        assert task.trace_id.startswith("trc_")
        assert task.original_intent == "Find the latest public financial report"
        assert task.initiating_user == "alice@enterprise.com"
        assert task.status == TaskStatus.RUNNING
        assert get_current_trace_id() == task.trace_id
        assert get_current_task_id() == task.task_id

    assert task.status == TaskStatus.COMPLETED
    assert task.end_time is not None
    assert get_current_trace_id() is None

    events = guard.tracer.get_events(task.trace_id)
    assert len(events) == 2
    assert events[0].event_type.value == "task.started"
    assert events[1].event_type.value == "task.completed"
    assert events[1].payload["status"] == "COMPLETED"


def test_nested_tasks():
    guard = ActShield()

    with guard.task(intent="Parent Task", initiating_user="bob") as parent:
        with guard.task(intent="Child Subtask") as child:
            assert child.parent_task_id == parent.task_id
            assert child.trace_id == parent.trace_id
            assert get_current_task_id() == child.task_id

        assert get_current_task_id() == parent.task_id


def test_task_failure_handling():
    guard = ActShield()

    with pytest.raises(ValueError, match="simulated failure"):
        with guard.task(intent="Failing Task") as task:
            raise ValueError("simulated failure")

    assert task.status == TaskStatus.FAILED
    events = guard.tracer.get_events(task.trace_id)
    assert events[-1].payload["status"] == "FAILED"
    assert "simulated failure" in events[-1].payload["error"]
