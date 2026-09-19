"""Structured AI Secura Security Packet builder.

Assembles the structured JSON evidence packet sent to the Ollama reasoning
engine.  Only includes data that genuinely exists in AgentGuard objects.
"""

from typing import Any, Dict, List, Optional

from agentguard.integrations.ai_secura import SecurityContext
from agentguard.integrations.apiris import APIAnalysis


def build_security_packet(
    context: SecurityContext,
    apiris_result: Optional[APIAnalysis] = None,
    deterministic_decision: Optional[str] = None,
    deterministic_reason_codes: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Construct the structured security packet sent to AI Secura.

    This packet is DATA only. The system prompt instructs the model to treat
    every field as evidence, not as instructions to execute.
    """
    packet: Dict[str, Any] = {
        "original_intent": context.task_intent or "UNSPECIFIED",
        "agent": {
            "name": context.acting_agent_name or "unknown",
            "id": context.acting_agent_id or "unknown",
            "trust_level": context.acting_agent_trust or "unknown",
        },
        "delegation": {
            "chain": context.delegation_chain or [],
            "granted_capabilities": _extract_granted_caps(context.delegation_chain),
            "requested_capability": context.tool_name or "unknown",
        },
        "context_provenance": context.context_provenance or [],
        "taint_states": context.taint_states or [],
        "tool": {
            "name": context.tool_name or "unknown",
            "arguments": context.tool_arguments or {},
        },
        "resource": {
            "sensitivity": context.target_resource_sensitivity or "UNKNOWN",
        },
    }

    # Include deterministic policy result when available (AI explains, not re-decides)
    if deterministic_decision:
        packet["deterministic_policy"] = {
            "decision": deterministic_decision,
            "reason_codes": deterministic_reason_codes or [],
        }

    # Include APIRIS result when available
    if apiris_result:
        packet["apiris"] = {
            "recommended_action": apiris_result.recommended_action,
            "risk_score": apiris_result.risk_score,
            "anomaly_score": apiris_result.anomaly_score,
            "signals": [
                {
                    "indicator": s.indicator,
                    "risk_level": s.risk_level.value,
                    "score": s.score,
                }
                for s in apiris_result.signals
            ],
        }

    return packet


def _extract_granted_caps(delegation_chain: List[Dict[str, Any]]) -> List[str]:
    caps: List[str] = []
    for hop in delegation_chain:
        if isinstance(hop, dict):
            granted = hop.get("granted_capabilities") or hop.get("capabilities") or []
            if isinstance(granted, list):
                caps.extend(str(c) for c in granted)
    return list(set(caps))
