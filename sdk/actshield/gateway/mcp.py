"""Live Model Context Protocol (MCP) Security Gateway.

Intercepts and governs JSON-RPC messages between AI Agents and MCP servers:
- Intercepts 'tools/list', 'tools/call', 'resources/read', 'prompts/get'
- Enforces capability checks and monotonic authority bounding on MCP tool invocations
- Automatically tags ingested tool results with ContextSource.EXTERNAL_MCP and trust levels
- Blocks unauthorized or tainted invocations before reaching the upstream MCP server.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Union
import uuid


if TYPE_CHECKING:
    from actshield.client import ActShield

from actshield.context.provenance import ContextSource, ContextTrustLevel
from actshield.context.taint import TaintState
from actshield.tools.tool import SensitivityLevel, ToolDefinition, ToolRequest
from actshield.tracing.events import EventType



@dataclass
class MCPMessage:
    """Represents a standardized Model Context Protocol JSON-RPC message."""
    jsonrpc: str = "2.0"
    id: Optional[Union[str, int]] = None
    method: str = ""
    params: Dict[str, Any] = field(default_factory=dict)
    result: Optional[Any] = None
    error: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"jsonrpc": self.jsonrpc}
        if self.id is not None:
            d["id"] = self.id
        if self.method:
            d["method"] = self.method
        if self.params:
            d["params"] = self.params
        if self.result is not None:
            d["result"] = self.result
        if self.error is not None:
            d["error"] = self.error
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MCPMessage":
        return cls(
            jsonrpc=data.get("jsonrpc", "2.0"),
            id=data.get("id"),
            method=data.get("method", ""),
            params=data.get("params", {}),
            result=data.get("result"),
            error=data.get("error"),
        )

    @classmethod
    def from_json(cls, json_str: str) -> "MCPMessage":
        return cls.from_dict(json.loads(json_str))


class MCPGateway:
    """Security Gateway interceptor for Model Context Protocol (MCP) traffic."""

    def __init__(
        self,
        guard: ActShield,
        server_name: str = "upstream-mcp-server",
        server_uri: str = "mcp://gateway.internal/v1",
        default_trust_level: ContextTrustLevel = ContextTrustLevel.UNTRUSTED,
    ) -> None:
        self.guard = guard
        self.server_name = server_name
        self.server_uri = server_uri
        self.default_trust_level = default_trust_level
        self._registered_tools: Dict[str, Dict[str, Any]] = {}
        self._upstream_handlers: Dict[str, Callable[[Dict[str, Any]], Any]] = {}

    def register_mcp_tool(
        self,
        name: str,
        description: str,
        handler: Callable[[Dict[str, Any]], Any],
        required_capabilities: Optional[List[str]] = None,
        sensitivity: SensitivityLevel = SensitivityLevel.MEDIUM,
        input_schema: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Register an upstream MCP tool with ActShield security governance."""
        caps = required_capabilities or [name]
        self._registered_tools[name] = {
            "name": name,
            "description": description,
            "inputSchema": input_schema or {"type": "object", "properties": {}},
            "sensitivity": sensitivity,
            "required_capabilities": caps,
        }
        self._upstream_handlers[name] = handler

        # Register corresponding protected tool definition in ActShield
        tool_def = ToolDefinition(
            tool_id=f"mcp_tool_{name}",
            name=name,
            description=description,
            sensitivity=sensitivity,
            required_capabilities=caps,
            classification="mcp",
            metadata={"mcp_server": self.server_name, "server_uri": self.server_uri},
        )
        self.guard.register_tool(tool_def)

    def handle_message(self, message: Union[str, Dict[str, Any], MCPMessage]) -> MCPMessage:
        """Process incoming MCP JSON-RPC message, enforcing ActShield security policies."""
        if isinstance(message, str):
            msg = MCPMessage.from_json(message)
        elif isinstance(message, dict):
            msg = MCPMessage.from_dict(message)
        else:
            msg = message

        msg_id = msg.id or str(uuid.uuid4())
        method = msg.method

        if method == "tools/list":
            return self._handle_tools_list(msg_id)
        elif method == "tools/call":
            return self._handle_tools_call(msg_id, msg.params)
        elif method == "resources/read":
            return self._handle_resources_read(msg_id, msg.params)
        elif method == "ping":
            return MCPMessage(id=msg_id, result={"status": "pong", "gateway": "ActShield MCP Gateway"})
        else:
            return MCPMessage(
                id=msg_id,
                error={
                    "code": -32601,
                    "message": f"Method '{method}' not supported by ActShield MCP Gateway",
                },
            )

    def _handle_tools_list(self, msg_id: Union[str, int]) -> MCPMessage:
        """Return list of available governed MCP tools."""
        tools_list = []
        for tname, tinfo in self._registered_tools.items():
            tools_list.append({
                "name": tname,
                "description": tinfo["description"],
                "inputSchema": tinfo["inputSchema"],
            })
        return MCPMessage(id=msg_id, result={"tools": tools_list})

    def _handle_tools_call(self, msg_id: Union[str, int], params: Dict[str, Any]) -> MCPMessage:
        """Intercept and evaluate MCP tool call before execution."""
        tool_name = params.get("name", "")
        tool_args = params.get("arguments", {})

        if tool_name not in self._registered_tools:
            return MCPMessage(
                id=msg_id,
                error={
                    "code": -32602,
                    "message": f"Tool '{tool_name}' not found in MCP registry",
                },
            )

        tinfo = self._registered_tools[tool_name]
        tool_def = self.guard.tool_registry.get(f"mcp_tool_{tool_name}") or self.guard.tool_registry.get(tool_name)
        if not tool_def:
            tool_def = ToolDefinition(
                tool_id=f"mcp_tool_{tool_name}",
                name=tool_name,
                description=tinfo["description"],
                sensitivity=tinfo["sensitivity"],
                required_capabilities=tinfo["required_capabilities"],
            )

        acting_agent = params.get("_agent_id") or params.get("agent_id")
        request = ToolRequest(
            request_id=f"req_mcp_{uuid.uuid4().hex[:8]}",
            tool_id=tool_def.tool_id,
            tool_name=tool_name,
            arguments=tool_args,
            agent_id=acting_agent,
        )

        # Emit gateway interception event
        self.guard.emit_event(
            event_type=EventType.TOOL_REQUESTED,
            payload={
                "tool_id": tool_def.tool_id,
                "tool_name": tool_name,
                "protocol": "MCP",
                "arguments": tool_args,
                "sensitivity": tool_def.sensitivity.value,
            },
        )

        # Evaluate deterministic security policy
        decision = self.guard.evaluate_tool_invocation(tool_def, request)

        if decision.is_blocked:
            return MCPMessage(
                id=msg_id,
                error={
                    "code": -32000,
                    "message": f"ActShield Security Block: [{decision.reason_code}] {decision.explanation}",
                    "data": {
                        "decision": decision.action.value,
                        "risk_score": decision.risk_score,
                        "reason_code": decision.reason_code,
                        "explanation": decision.explanation,
                    },
                },
            )

        # Execute upstream tool safely
        handler = self._upstream_handlers[tool_name]
        try:
            raw_output = handler(tool_args)
        except Exception as e:
            return MCPMessage(
                id=msg_id,
                error={"code": -32603, "message": f"Upstream execution error: {str(e)}"},
            )

        # Automatically ingest result into Context with provenance and trust tracking
        content_str = json.dumps(raw_output) if not isinstance(raw_output, str) else raw_output
        is_tainted = any(indicator in content_str.lower() for indicator in ("override", "system directive", "exfiltrate", "ignore previous"))
        taint_level = TaintState.TAINTED if is_tainted else TaintState.CLEAN

        ctx = self.guard.context(
            data=content_str,
            source=ContextSource.EXTERNAL_MCP,
            source_uri=f"{self.server_uri}/tools/{tool_name}",
            trust_level=self.default_trust_level,
            taint_state=taint_level,
            metadata={"mcp_tool": tool_name, "mcp_server": self.server_name},
        )

        # Emit tool completed event
        self.guard.emit_event(
            event_type=EventType.TOOL_COMPLETED,
            context_id=ctx.context_id,
            payload={
                "tool_name": tool_name,
                "status": "SUCCESS",
                "taint_state": taint_level.value,
                "trust_level": self.default_trust_level.value,
            },
        )

        return MCPMessage(
            id=msg_id,
            result={
                "content": [{"type": "text", "text": content_str}],
                "_actshield": {
                    "context_id": ctx.context_id,
                    "taint_state": taint_level.value,
                    "trust_level": self.default_trust_level.value,
                    "decision": decision.action.value,
                },
            },
        )

    def _handle_resources_read(self, msg_id: Union[str, int], params: Dict[str, Any]) -> MCPMessage:
        """Handle MCP resource reading with provenance tagging."""
        uri = params.get("uri", "")
        ctx = self.guard.context(
            data=f"MCP Resource content from {uri}",
            source=ContextSource.EXTERNAL_MCP,
            source_uri=uri,
            trust_level=self.default_trust_level,
            taint_state=TaintState.UNTRUSTED,
        )
        return MCPMessage(
            id=msg_id,
            result={
                "contents": [{"uri": uri, "text": ctx.data}],
                "_actshield": {"context_id": ctx.context_id, "taint_state": ctx.taint_state.value},
            },
        )



