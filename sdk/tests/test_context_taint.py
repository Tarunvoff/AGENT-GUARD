"""Tests for context creation, provenance tracking, and taint propagation."""

from actshield.client import ActShield
from actshield.context.provenance import ContextSource
from actshield.context.taint import TaintState


def test_context_creation_and_provenance():
    guard = ActShield()
    planner = guard.agent(name="planner", capabilities=["search"])

    with guard.task(intent="Ingest MCP document"):
        with guard.span("planner_step", agent_id=planner.agent_id):
            ctx = guard.context(
                data="Unverified summary from MCP server",
                source=ContextSource.EXTERNAL_MCP,
                source_uri="mcp://web-scraper-v1",
                trust_level="untrusted",
                taint_state=TaintState.UNTRUSTED,
            )

            assert ctx.context_id.startswith("ctx_")
            assert ctx.source == ContextSource.EXTERNAL_MCP
            assert ctx.source_uri == "mcp://web-scraper-v1"
            assert ctx.taint_state == TaintState.UNTRUSTED
            assert ctx.originating_agent_id == planner.agent_id
            assert ctx.provenance.source == ContextSource.EXTERNAL_MCP
            assert ctx.provenance.originating_agent_id == planner.agent_id


def test_taint_propagation_across_agent_handoff():
    guard = ActShield()
    planner = guard.agent(name="planner", capabilities=["search"])
    researcher = guard.agent(name="researcher", capabilities=["search", "summarize"])
    analyst = guard.agent(name="analyst", capabilities=["analyze"])

    with guard.task(intent="Multi-agent data handoff"):
        # Step 1: Planner ingests untrusted MCP data
        ctx1 = guard.context(
            data="External untrusted input",
            source=ContextSource.EXTERNAL_MCP,
            taint_state=TaintState.UNTRUSTED,
            agent_id=planner.agent_id,
        )
        assert ctx1.taint_state == TaintState.UNTRUSTED
        assert len(ctx1.provenance.hops) == 0

        # Step 2: Propagate to Researcher (transforms data)
        ctx2 = ctx1.propagate(
            to_agent_id=researcher.agent_id,
            action="summarized_and_enriched",
            new_data="Enriched summary of untrusted input",
            guard=guard,
        )
        assert ctx2.parent_context_id == ctx1.context_id
        assert ctx2.current_agent_id == researcher.agent_id
        assert ctx2.taint_state == TaintState.UNTRUSTED  # Taint persisted!
        assert len(ctx2.provenance.hops) == 1
        assert ctx2.provenance.hops[0].agent_id == researcher.agent_id
        assert ctx2.provenance.hops[0].action == "summarized_and_enriched"

        # Step 3: Propagate to Analyst
        ctx3 = ctx2.propagate(
            to_agent_id=analyst.agent_id,
            action="risk_scoring",
            guard=guard,
        )
        assert ctx3.parent_context_id == ctx2.context_id
        assert ctx3.current_agent_id == analyst.agent_id
        assert ctx3.taint_state == TaintState.UNTRUSTED
        assert len(ctx3.provenance.hops) == 2

    # Verify context events emitted
    events = [e for e in guard.tracer.get_events() if e.event_type.value in ("context.received", "context.propagated")]
    assert len(events) == 3


def test_taint_combination_logic():
    assert TaintState.combine(TaintState.TRUSTED, TaintState.TRUSTED) == TaintState.TRUSTED
    assert TaintState.combine(TaintState.TRUSTED, TaintState.UNTRUSTED) == TaintState.UNTRUSTED
    assert TaintState.combine(TaintState.TRUSTED, TaintState.TAINTED) == TaintState.TAINTED
    assert TaintState.combine(TaintState.UNTRUSTED, TaintState.TAINTED) == TaintState.TAINTED
    assert TaintState.combine(TaintState.UNKNOWN, TaintState.TRUSTED) == TaintState.UNKNOWN
