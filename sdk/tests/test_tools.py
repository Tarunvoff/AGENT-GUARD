"""Tests for tool registration, protected execution, and interceptor hooks."""

import pytest
from agentguard.client import AgentGuard
from agentguard.tools.tool import Resource, SensitivityLevel


def test_tool_registration():
    guard = AgentGuard()
    
    resource = Resource(name="customers_db", resource_type="database", sensitivity=SensitivityLevel.HIGH)
    
    @guard.protected_tool(
        name="query_customers",
        description="Fetch customer information",
        sensitivity=SensitivityLevel.HIGH,
        required_capabilities=["db.read"],
        target_resources=[resource]
    )
    def query_customers(customer_id: str, api_key: str = "sk-12345678901234567890"):
        return {"customer_id": customer_id, "name": "ACME Corp"}

    assert "query_customers" in guard.tool_registry
    tool_def = guard.tool_registry["query_customers"]
    assert tool_def.sensitivity == SensitivityLevel.HIGH
    assert tool_def.required_capabilities == ["db.read"]
    assert len(tool_def.target_resources) == 1


def test_sync_protected_tool_execution_allowed():
    guard = AgentGuard()
    agent = guard.agent(name="db_agent", capabilities=["db.read"])

    @guard.protected_tool(
        name="read_data",
        required_capabilities=["db.read"],
        sensitivity=SensitivityLevel.LOW,
    )
    def read_data(table: str):
        return [f"row1 from {table}", f"row2 from {table}"]

    with guard.task(intent="Fetch table data"):
        with guard.span("db_op", agent_id=agent.agent_id):
            result = read_data(table="users")
            assert len(result) == 2

    # Verify tool events
    events = [e for e in guard.tracer.get_events() if e.event_type.value in ("tool.requested", "tool.invoked")]
    assert len(events) == 2
    assert events[0].payload["tool_name"] == "read_data"
    assert events[1].payload["success"] is True


@pytest.mark.asyncio
async def test_async_protected_tool_execution_allowed():
    guard = AgentGuard()
    agent = guard.agent(name="async_agent", capabilities=["api.call"])

    @guard.protected_tool(
        name="fetch_remote",
        required_capabilities=["api.call"],
        sensitivity=SensitivityLevel.LOW,
    )
    async def fetch_remote(url: str):
        return {"status": 200, "url": url}

    with guard.task(intent="Async fetch"):
        with guard.span("async_op", agent_id=agent.agent_id):
            res = await fetch_remote(url="https://api.example.com/status")
            assert res["status"] == 200

    events = [e for e in guard.tracer.get_events() if e.event_type.value == "tool.invoked"]
    assert len(events) == 1
    assert events[0].payload["success"] is True


def test_secret_redaction_in_tool_events():
    guard = AgentGuard()
    agent = guard.agent(name="api_agent", capabilities=["api.call"])

    @guard.protected_tool(
        name="authenticated_request",
        required_capabilities=["api.call"],
        sensitivity=SensitivityLevel.LOW,
    )
    def authenticated_request(endpoint: str, api_key: str):
        return {"endpoint": endpoint, "status": "ok"}

    with guard.task(intent="Auth request"):
        with guard.span("auth_call", agent_id=agent.agent_id):
            authenticated_request(endpoint="/api/v1/data", api_key="sk-live-1234567890abcdef1234")

    # Check that tool.requested event payload redacted the api_key
    req_events = [e for e in guard.tracer.get_events() if e.event_type.value == "tool.requested"]
    assert len(req_events) == 1
    assert req_events[0].payload["arguments"]["api_key"] == "[REDACTED]"
