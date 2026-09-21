"""Tests for Agent creation, identity, and capabilities."""

import pytest
from actshield.agents.agent import Agent
from actshield.agents.identity import AgentCapability, AgentIdentity, AgentTrustLevel
from actshield.client import ActShield


def test_agent_identity_creation():
    identity = AgentIdentity(
        name="planner_agent",
        framework="crewai",
        version="1.2.0",
        capabilities=["plan_generation", "task_delegation"],
        trust_level=AgentTrustLevel.HIGH,
        metadata={"department": "research"}
    )
    assert identity.name == "planner_agent"
    assert identity.framework == "crewai"
    assert identity.version == "1.2.0"
    assert len(identity.capabilities) == 2
    assert identity.has_capability("plan_generation")
    assert identity.has_capability("task_delegation")
    assert not identity.has_capability("execute_sql")
    assert identity.trust_level == AgentTrustLevel.HIGH
    assert identity.metadata["department"] == "research"


def test_agent_wildcard_capabilities():
    identity = AgentIdentity(
        name="super_admin_agent",
        capabilities=["database.*", "public_search"],
    )
    assert identity.has_capability("database.read")
    assert identity.has_capability("database.write")
    assert identity.has_capability("public_search")
    assert not identity.has_capability("filesystem.delete")


def test_guard_agent_factory():
    guard = ActShield()
    agent = guard.agent(
        name="research_agent",
        framework="custom",
        capabilities=["public_search", "public_documents"],
        trust_level=AgentTrustLevel.MEDIUM
    )
    assert isinstance(agent, Agent)
    assert agent.name == "research_agent"
    assert agent.agent_id.startswith("agt_")
    assert agent.has_capability("public_search")
    assert agent.agent_id in guard.agent_registry

    # Check event emission
    events = guard.tracer.get_events()
    assert len(events) == 1
    assert events[0].event_type.value == "agent.created"
    assert events[0].agent_id == agent.agent_id
