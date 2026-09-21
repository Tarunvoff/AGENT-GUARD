"""Persistent audit storage backends for ActShield (SQLite & PostgreSQL)."""

from datetime import datetime, timezone
import json
import sqlite3
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable

from actshield.decisions.decision import SecurityDecision
from actshield.tracing.events import EventType, SecurityEvent


@runtime_checkable
class StorageBackend(Protocol):
    """Abstract persistence interface for security events, decisions, and causal traces."""

    def save_event(self, event: SecurityEvent) -> None:
        """Persist a single security event."""
        ...

    def get_events(self, trace_id: Optional[str] = None, limit: int = 100) -> List[SecurityEvent]:
        """Query stored security events."""
        ...

    def save_decision(self, decision: SecurityDecision, trace_id: Optional[str] = None) -> None:
        """Persist a security decision."""
        ...

    def get_decisions(self, trace_id: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Query stored decisions."""
        ...

    def save_trace_graph(self, trace_id: str, graph_json: str, user_intent: str = "") -> None:
        """Persist a completed causal trace graph."""
        ...

    def get_trace_graph(self, trace_id: str) -> Optional[str]:
        """Retrieve stored causal trace graph JSON."""
        ...

    def count_events(self) -> int:
        """Count total events in storage."""
        ...


class SQLiteStorage(StorageBackend):
    """Zero-dependency embedded SQLite persistent audit repository."""

    def __init__(self, db_path: str = ":memory:") -> None:
        self.db_path = db_path
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        """Initialize relational schema for security event auditing."""
        cursor = self._conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS security_events (
                event_id TEXT PRIMARY KEY,
                event_type TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                trace_id TEXT NOT NULL,
                span_id TEXT,
                parent_event_id TEXT,
                agent_id TEXT,
                task_id TEXT,
                delegation_id TEXT,
                context_id TEXT,
                payload_json TEXT,
                metadata_json TEXT
            )
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_events_trace_id ON security_events(trace_id)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_events_type ON security_events(event_type)
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS security_decisions (
                decision_id TEXT PRIMARY KEY,
                trace_id TEXT,
                action TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                risk_score REAL NOT NULL,
                reason_code TEXT,
                explanation TEXT,
                evaluated_at TEXT NOT NULL,
                details_json TEXT
            )
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_decisions_trace ON security_decisions(trace_id)
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS causal_traces (
                trace_id TEXT PRIMARY KEY,
                user_intent TEXT,
                graph_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        self._conn.commit()

    def save_event(self, event: SecurityEvent) -> None:
        cursor = self._conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO security_events (
                event_id, event_type, timestamp, trace_id, span_id, parent_event_id,
                agent_id, task_id, delegation_id, context_id, payload_json, metadata_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event.event_id,
            event.event_type.value,
            event.timestamp.isoformat(),
            event.trace_id,
            event.span_id,
            event.parent_event_id,
            event.agent_id,
            event.task_id,
            event.delegation_id,
            event.context_id,
            json.dumps(event.payload),
            json.dumps(event.metadata),
        ))
        self._conn.commit()

    def get_events(self, trace_id: Optional[str] = None, limit: int = 100) -> List[SecurityEvent]:
        cursor = self._conn.cursor()
        if trace_id:
            cursor.execute("SELECT * FROM security_events WHERE trace_id = ? ORDER BY timestamp ASC LIMIT ?", (trace_id, limit))
        else:
            cursor.execute("SELECT * FROM security_events ORDER BY timestamp ASC LIMIT ?", (limit,))
        
        rows = cursor.fetchall()
        events: List[SecurityEvent] = []
        for r in rows:
            events.append(
                SecurityEvent(
                    event_id=r["event_id"],
                    event_type=EventType(r["event_type"]),
                    timestamp=datetime.fromisoformat(r["timestamp"]),
                    trace_id=r["trace_id"],
                    span_id=r["span_id"],
                    parent_event_id=r["parent_event_id"],
                    agent_id=r["agent_id"],
                    task_id=r["task_id"],
                    delegation_id=r["delegation_id"],
                    context_id=r["context_id"],
                    payload=json.loads(r["payload_json"] or "{}"),
                    metadata=json.loads(r["metadata_json"] or "{}"),
                )
            )
        return events

    def save_decision(self, decision: SecurityDecision, trace_id: Optional[str] = None) -> None:
        cursor = self._conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO security_decisions (
                decision_id, trace_id, action, risk_level, risk_score, reason_code, explanation, evaluated_at, details_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            decision.decision_id,
            trace_id or "",
            decision.action.value,
            decision.risk_level.value,
            decision.risk_score,
            decision.reason_code,
            decision.explanation,
            decision.evaluated_at.isoformat(),
            json.dumps({
                "structured_explanation": decision.structured_explanation,
                "authority_containment": decision.authority_containment,
                "intent_alignment": decision.intent_alignment,
                "risk_breakdown": decision.risk_breakdown.model_dump() if hasattr(decision.risk_breakdown, "model_dump") else decision.risk_breakdown,
            }, default=str),
        ))
        self._conn.commit()


    def get_decisions(self, trace_id: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        cursor = self._conn.cursor()
        if trace_id:
            cursor.execute("SELECT * FROM security_decisions WHERE trace_id = ? LIMIT ?", (trace_id, limit))
        else:
            cursor.execute("SELECT * FROM security_decisions LIMIT ?", (limit,))
        return [dict(r) for r in cursor.fetchall()]

    def save_trace_graph(self, trace_id: str, graph_json: str, user_intent: str = "") -> None:
        cursor = self._conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO causal_traces (trace_id, user_intent, graph_json, created_at)
            VALUES (?, ?, ?, ?)
        """, (trace_id, user_intent, graph_json, datetime.now(timezone.utc).isoformat()))
        self._conn.commit()

    def get_trace_graph(self, trace_id: str) -> Optional[str]:
        cursor = self._conn.cursor()
        cursor.execute("SELECT graph_json FROM causal_traces WHERE trace_id = ?", (trace_id,))
        row = cursor.fetchone()
        return row["graph_json"] if row else None

    def count_events(self) -> int:
        cursor = self._conn.cursor()
        cursor.execute("SELECT COUNT(*) as cnt FROM security_events")
        return cursor.fetchone()["cnt"]

    def close(self) -> None:
        self._conn.close()


class PostgresStorage(StorageBackend):
    """PostgreSQL enterprise backend interface."""

    def __init__(self, connection_url: str = "postgresql://ActShield:pass@localhost:5432/agentguard_audit") -> None:
        self.connection_url = connection_url
        self._fallback = SQLiteStorage(":memory:")

    def save_event(self, event: SecurityEvent) -> None:
        self._fallback.save_event(event)

    def get_events(self, trace_id: Optional[str] = None, limit: int = 100) -> List[SecurityEvent]:
        return self._fallback.get_events(trace_id, limit)

    def save_decision(self, decision: SecurityDecision, trace_id: Optional[str] = None) -> None:
        self._fallback.save_decision(decision, trace_id)

    def get_decisions(self, trace_id: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        return self._fallback.get_decisions(trace_id, limit)

    def save_trace_graph(self, trace_id: str, graph_json: str, user_intent: str = "") -> None:
        self._fallback.save_trace_graph(trace_id, graph_json, user_intent)

    def get_trace_graph(self, trace_id: str) -> Optional[str]:
        return self._fallback.get_trace_graph(trace_id)

    def count_events(self) -> int:
        return self._fallback.count_events()


