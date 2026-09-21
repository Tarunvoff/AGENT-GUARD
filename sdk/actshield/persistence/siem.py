"""SIEM-Ready Security Event Formatter and Exporter.

Supports enterprise SIEM formats:
- JSON Lines (Elasticsearch / OpenSearch / Datadog / Splunk HEC)
- Common Event Format (CEF / ArcSight / QRadar)
- Syslog RFC 5424 Format
"""

from enum import Enum
import json
from typing import Any, Dict, List, Union

from actshield.decisions.decision import SecurityDecision
from actshield.tracing.events import SecurityEvent


class SIEMFormat(str, Enum):
    JSON_LINES = "JSON_LINES"
    CEF = "CEF"
    SYSLOG = "SYSLOG"


class SIEMExporter:
    """Formats security events and decisions for SIEM ingestion."""

    @classmethod
    def format_event_json(cls, event: SecurityEvent) -> Dict[str, Any]:
        """Convert a SecurityEvent into standard SIEM JSON format."""
        return {
            "@timestamp": event.timestamp.isoformat(),
            "event": {
                "id": event.event_id,
                "type": event.event_type.value,
                "category": "security_audit",
                "dataset": "actshield.events",
            },
            "ActShield": {
                "trace_id": event.trace_id,
                "span_id": event.span_id,
                "agent_id": event.agent_id,
                "task_id": event.task_id,
                "delegation_id": event.delegation_id,
                "context_id": event.context_id,
            },
            "payload": event.payload,
            "metadata": event.metadata,
        }

    @classmethod
    def to_json_lines(cls, events: List[SecurityEvent]) -> str:
        """Export a list of SecurityEvents as newline-delimited JSON (NDJSON)."""
        lines = [json.dumps(cls.format_event_json(e)) for e in events]
        return "\n".join(lines)

    @classmethod
    def format_event_cef(cls, event: SecurityEvent) -> str:
        """Format a single SecurityEvent in Common Event Format (CEF).
        Format: CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|Extension
        """
        # Map event type to severity (0-10)
        sev_map = {
            "security.decision": 8,
            "context.sanitized": 3,
            "agent.delegated": 4,
            "tool.requested": 5,
        }
        severity = sev_map.get(event.event_type.value, 5)

        ext_pairs = [
            f"externalId={event.event_id}",
            f"rt={event.timestamp.isoformat()}",
            f"cs1={event.trace_id}",
            f"cs1Label=TraceID",
            f"cs2={event.agent_id or 'none'}",
            f"cs2Label=AgentID",
        ]
        if event.context_id:
            ext_pairs.append(f"cs3={event.context_id}")
            ext_pairs.append(f"cs3Label=ContextID")

        ext_str = " ".join(ext_pairs)
        return f"CEF:0|ActShield|ActShield-SDK|0.3.0|{event.event_type.value}|{event.event_type.value}|{severity}|{ext_str}"

    @classmethod
    def to_cef(cls, events: List[SecurityEvent]) -> str:
        """Export multiple SecurityEvents in CEF format."""
        return "\n".join(cls.format_event_cef(e) for e in events)

    @classmethod
    def format_event_syslog(cls, event: SecurityEvent) -> str:
        """Format a single SecurityEvent in Syslog RFC 5424 style."""
        ts = event.timestamp.isoformat()
        payload_str = json.dumps(cls.format_event_json(event))
        return f"<134>1 {ts} ActShield-runtime security-audit - {event.event_id} [ActShield@44400 trace_id=\"{event.trace_id}\" event_type=\"{event.event_type.value}\"] {payload_str}"

    @classmethod
    def to_syslog(cls, events: List[SecurityEvent]) -> str:
        """Export multiple SecurityEvents as Syslog messages."""
        return "\n".join(cls.format_event_syslog(e) for e in events)


