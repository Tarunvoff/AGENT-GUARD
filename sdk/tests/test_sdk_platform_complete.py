"""Tests for ActShield SDK-First Public Facades, Agent Discovery, Topology & CLI."""
import pytest
from actshield import ActShield, AgentStatus, AgentTrustLevel
from actshield.doctor import run_doctor
from actshield.cli.graph import render_agent_topology
from actshield.cli.shell import ActShieldShell
from actshield.providers.registry import get_provider_registry


def test_sdk_facade_lifecycle():
    guard = ActShield(mode="strict")
    assert not guard.is_running
    guard.start()
    assert guard.is_running
    assert guard.mode == "strict"


def test_sdk_agent_registration_and_status():
    guard = ActShield()
    agent = guard.register_agent(
        name="test-worker",
        capabilities=["data_read", "search"],
        trust_level=AgentTrustLevel.HIGH,
    )
    assert agent.agent_id.startswith("agt_")
    assert agent.name == "test-worker"
    assert agent.status == AgentStatus.ACTIVE
    assert agent.has_capability("data_read")
    assert not agent.has_capability("db_admin")

    agent.set_status(AgentStatus.QUARANTINED)
    assert agent.status == AgentStatus.QUARANTINED


def test_sdk_agent_decorator_and_context():
    guard = ActShield()

    @guard.agent(name="analyst-agent", capabilities=["metrics"])
    def analyze_metrics(data):
        return f"analyzed {data}"

    res = analyze_metrics("cpu_stats")
    assert res == "analyzed cpu_stats"
    assert analyze_metrics.agent.name == "analyst-agent"

    with guard.agent_context("analyst-agent") as a:
        assert a.name == "analyst-agent"
        assert a.last_seen is not None


def test_sdk_observe_analyze_enforce_explain():
    guard = ActShield()
    evt = guard.observe("custom_test_event", payload={"key": "value"})
    assert evt.event_id.startswith("evt_")

    analysis = guard.analyze("web_search", payload={"query": "test"})
    assert "threat_severity" in analysis
    assert "recommendation" in analysis

    dec = guard.enforce("web_search")
    assert dec is not None

    explanation = guard.explain(evt.event_id)
    assert explanation is not None


def test_cli_doctor_runs_cleanly():
    code = run_doctor(json_output=True)
    assert code == 0


def test_provider_registry_active_switch():
    registry = get_provider_registry()
    provs = registry.list_providers()
    assert len(provs) > 0
    active = registry.get_active_provider()
    assert active is not None
