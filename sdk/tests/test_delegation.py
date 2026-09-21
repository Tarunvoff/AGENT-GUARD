"""Tests for delegation, recursive delegation, and monotonic authority containment."""

import pytest
from actshield.client import ActShield
from actshield.tracing.correlation import get_current_agent_id, get_current_delegation_id


def test_single_delegation():
    guard = ActShield()
    planner = guard.agent(name="planner", capabilities=["plan", "search", "read"])
    researcher = guard.agent(name="researcher", capabilities=["search", "read", "download"])

    with guard.task(intent="Perform market research"):
        with planner.delegate(researcher, capabilities=["search"]):
            assert get_current_agent_id() == researcher.agent_id
            dlg_id = get_current_delegation_id()
            assert dlg_id is not None
            delegation = guard.delegation_registry[dlg_id]
            assert delegation.depth == 0
            assert delegation.delegator_agent_id == planner.agent_id
            assert delegation.delegate_agent_id == researcher.agent_id
            assert delegation.authority_grant.granted_capabilities == ["search"]


def test_recursive_deep_delegation():
    """Test deep recursive delegation without hardcoded depth limit:
    Planner -> Researcher -> Analyst -> DataAgent -> Parser
    """
    guard = ActShield()
    planner = guard.agent(name="planner", capabilities=["plan", "search", "analyze", "data_fetch", "parse"])
    researcher = guard.agent(name="researcher", capabilities=["search", "analyze", "data_fetch", "parse"])
    analyst = guard.agent(name="analyst", capabilities=["analyze", "data_fetch", "parse"])
    data_agent = guard.agent(name="data_agent", capabilities=["data_fetch", "parse"])
    parser = guard.agent(name="parser", capabilities=["parse"])

    with guard.task(intent="Deep multi-agent workflow"):
        with planner.delegate(researcher, capabilities=["search", "analyze", "data_fetch", "parse"]) as d1:
            assert d1.depth == 0
            with researcher.delegate(analyst, capabilities=["analyze", "data_fetch", "parse"]) as d2:
                assert d2.depth == 1
                assert d2.parent_delegation_id == d1.delegation_id
                with analyst.delegate(data_agent, capabilities=["data_fetch", "parse"]) as d3:
                    assert d3.depth == 2
                    assert d3.parent_delegation_id == d2.delegation_id
                    with data_agent.delegate(parser, capabilities=["parse"]) as d4:
                        assert d4.depth == 3
                        assert d4.parent_delegation_id == d3.delegation_id
                        assert get_current_agent_id() == parser.agent_id

    # Verify delegation events emitted
    events = [e for e in guard.tracer.get_events() if e.event_type.value == "agent.delegated"]
    assert len(events) == 4


def test_monotonic_authority_reduction_violation():
    """Delegator attempting to grant capabilities it does not hold must fail."""
    guard = ActShield()
    planner = guard.agent(name="planner", capabilities=["search"])
    researcher = guard.agent(name="researcher", capabilities=["admin_delete", "search"])

    with guard.task(intent="Attempt privilege escalation"):
        # planner only has 'search', trying to grant 'admin_delete' must raise PermissionError
        with pytest.raises(PermissionError, match="Monotonic authority violation"):
            with planner.delegate(researcher, capabilities=["admin_delete"]):
                pass

    # Verify incident was created
    incidents = [e for e in guard.tracer.get_events() if e.event_type.value == "incident.created"]
    assert len(incidents) == 1
    assert incidents[0].payload["incident_type"] == "AUTHORITY_ESCALATION_ATTEMPT"
