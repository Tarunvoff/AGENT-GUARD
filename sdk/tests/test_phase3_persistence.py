"""Unit tests for Phase 3 Persistent Evidence and SIEM Exporter."""

import json
import os
import tempfile
import pytest

from agentguard.client import AgentGuard
from agentguard.decisions.decision import DecisionAction, SecurityDecision
from agentguard.persistence.siem import SIEMExporter, SIEMFormat
from agentguard.persistence.storage import PostgresStorage, SQLiteStorage
from agentguard.risk.models import RiskLevel
from agentguard.tracing.events import EventType, SecurityEvent


# -----------------------------------------------------------------------------
# 1. SQLite Storage Event Persistence & Querying
# -----------------------------------------------------------------------------
def test_sqlite_storage_event_persistence():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    try:
        storage = SQLiteStorage(db_path)
        guard = AgentGuard(storage=storage)
        agent = guard.agent(name="StorageAgent", capabilities=["search"])

        with guard.task(intent="Test persistent audit storage") as task:
            guard.emit_event(
                event_type=EventType.CONTEXT_RECEIVED,
                trace_id=task.trace_id,
                agent_id=agent.agent_id,
                payload={"data": "sample audit payload"},
            )

        events = storage.get_events(trace_id=task.trace_id)
        assert len(events) >= 2  # task.started, context.received
        assert storage.count_events() >= 2

        # Verify event round-trip
        ctx_evt = [e for e in events if e.event_type == EventType.CONTEXT_RECEIVED][0]
        assert ctx_evt.payload["data"] == "sample audit payload"
        assert ctx_evt.agent_id == agent.agent_id

    finally:
        storage.close()
        if os.path.exists(db_path):
            os.remove(db_path)


# -----------------------------------------------------------------------------
# 2. SQLite Storage Decision Persistence
# -----------------------------------------------------------------------------
def test_sqlite_storage_decision_persistence():
    storage = SQLiteStorage(":memory:")
    guard = AgentGuard(storage=storage)
    agent = guard.agent(name="DecAgent", capabilities=["read"])

    @guard.protected_tool(name="sample_tool", required_capabilities=["read"])
    def sample_tool():
        return "ok"

    with guard.task(intent="Evaluate and save decision") as task:
        with guard.span("step", agent_id=agent.agent_id):
            sample_tool()

    decisions = storage.get_decisions(trace_id=task.trace_id)
    assert len(decisions) >= 1
    assert decisions[0]["action"] == "ALLOW"
    assert decisions[0]["risk_level"] == "LOW"


# -----------------------------------------------------------------------------
# 3. SQLite Storage Causal Trace Graph Persistence
# -----------------------------------------------------------------------------
def test_sqlite_storage_causal_trace_graph():
    storage = SQLiteStorage(":memory:")
    trace_id = "trc_test_12345"
    graph_json = json.dumps({"nodes": [{"id": "node_1"}], "edges": []})

    storage.save_trace_graph(trace_id=trace_id, graph_json=graph_json, user_intent="Fiscal analysis")
    retrieved = storage.get_trace_graph(trace_id)
    assert retrieved is not None
    data = json.loads(retrieved)
    assert len(data["nodes"]) == 1


# -----------------------------------------------------------------------------
# 4. SIEM Exporter: JSON Lines Format
# -----------------------------------------------------------------------------
def test_siem_exporter_json_lines():
    guard = AgentGuard()
    with guard.task(intent="SIEM export test") as task:
        guard.emit_event(
            event_type=EventType.SECURITY_DECISION,
            trace_id=task.trace_id,
            payload={"decision": "BLOCK", "reason": "Tainted sink"},
        )

    events = guard.tracer.get_events(task.trace_id)
    ndjson = SIEMExporter.to_json_lines(events)
    lines = ndjson.strip().split("\n")
    assert len(lines) >= 2

    first_obj = json.loads(lines[0])
    assert "@timestamp" in first_obj
    assert "agentguard" in first_obj
    assert first_obj["agentguard"]["trace_id"] == task.trace_id


# -----------------------------------------------------------------------------
# 5. SIEM Exporter: Common Event Format (CEF)
# -----------------------------------------------------------------------------
def test_siem_exporter_cef_format():
    guard = AgentGuard()
    with guard.task(intent="CEF export test") as task:
        guard.emit_event(
            event_type=EventType.CONTEXT_SANITIZED,
            trace_id=task.trace_id,
            payload={"sanitizer": "PydanticValidator"},
        )

    events = guard.tracer.get_events(task.trace_id)
    cef_output = SIEMExporter.to_cef(events)
    assert "CEF:0|AgentGuard|AgentGuard-SDK|0.3.0|" in cef_output
    assert f"cs1={task.trace_id}" in cef_output


# -----------------------------------------------------------------------------
# 6. SIEM Exporter: Syslog RFC 5424 Format
# -----------------------------------------------------------------------------
def test_siem_exporter_syslog_format():
    guard = AgentGuard()
    with guard.task(intent="Syslog export test") as task:
        guard.emit_event(
            event_type=EventType.TOOL_REQUESTED,
            trace_id=task.trace_id,
            payload={"tool_name": "query_db"},
        )

    events = guard.tracer.get_events(task.trace_id)
    syslog_output = SIEMExporter.to_syslog(events)
    assert "<134>1" in syslog_output
    assert "agentguard-runtime security-audit" in syslog_output
    assert f'trace_id="{task.trace_id}"' in syslog_output


# -----------------------------------------------------------------------------
# 7. Postgres Storage Fallback Compatibility
# -----------------------------------------------------------------------------
def test_postgres_storage_interface():
    pg = PostgresStorage("postgresql://test:test@localhost/testdb")
    guard = AgentGuard(storage=pg)
    with guard.task(intent="Test postgres interface"):
        pass
    assert pg.count_events() >= 1
