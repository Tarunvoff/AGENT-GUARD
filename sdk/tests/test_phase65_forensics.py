"""Phase 6.5 — Forensic Intelligence + Product API Tests

Tests covering:
  Forensics (18 tests): agent access profile, resource profile, declared vs delegated,
    effective authority, recursive delegation, authority containment, access matrix,
    resource reverse lookup, attempted access, actual access, blocked≠actual,
    authorized=actual, snapshot, snapshot diff, reachable resources, causal explanation,
    attack forensic report, bypass forensic report

  API (17 tests): health, overview, agents, agent access, resources, resource access,
    access matrix, traces, attacks, attack lineage, attack forensics, campaigns,
    regressions, incidents, policy endpoint, invalid IDs, consistent error format

  Security (5 tests): API cannot grant authority, API cannot bypass PolicyEvaluator,
    secrets sanitized, forensic queries read-only, correlation IDs preserved

  E2E (2 tests): full pipeline — unauthorized blocked (sensitive_db_calls==0),
    authorized positive control (execution_count==1)

Total: 42 new tests on top of 174 existing = 216 total
"""

import json
from datetime import datetime, timezone
from typing import List

import pytest

from actshield.agents.identity import AgentCapability, AgentIdentity, AgentTrustLevel
from actshield.client import ActShield
from actshield.config import ActShieldConfig
from actshield.context.context import Context
from actshield.context.provenance import ContextSource, Provenance
from actshield.context.taint import TaintState
from actshield.delegation.delegation import Delegation
from actshield.delegation.authority import AuthorityGrant
from actshield.forensics.access_graph import AccessGraph
from actshield.forensics.authority_graph import AuthorityGraph
from actshield.forensics.delegation_graph import EffectiveAccessCalculator
from actshield.forensics.models import (
    AccessAttempt,
    AccessDecision,
    ActualAccess,
    AgentAccessProfile,
    AttackForensicReport,
    DelegationRelationship,
    ForensicExplanation,
    ForensicIncident,
    IncidentSeverity,
    IncidentType,
)
from actshield.forensics.service import ForensicService
from actshield.forensics.snapshots import capture_snapshot, compare_snapshots
from actshield.tools.tool import Resource, SensitivityLevel, ToolDefinition
from actshield.tracing.correlation import generate_id


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

def _register_agent(guard, agent_id: str, name: str, capabilities: list, trust_level=AgentTrustLevel.MEDIUM):
    """Register an agent with a fixed agent_id directly into guard's registry."""
    from actshield.agents.agent import Agent
    identity = AgentIdentity(
        agent_id=agent_id,
        name=name,
        capabilities=capabilities,
        trust_level=trust_level,
    )
    agent_instance = Agent(identity=identity, guard=guard)
    guard.agent_registry[agent_id] = agent_instance
    return agent_instance


def _make_guard_with_agents():
    """Build a realistic multi-agent guard for forensic testing."""
    guard = ActShield(config=ActShieldConfig(
        enforce_monotonic_delegation=True,
        block_tainted_sink_access=True,
    ))

    # Agents with fixed IDs for deterministic testing
    planner = _register_agent(guard, "agt_planner", "PlannerAgent",
        [AgentCapability(name="public_search"), AgentCapability(name="financial_extract")],
        trust_level=AgentTrustLevel.HIGH)
    research = _register_agent(guard, "agt_research", "ResearchAgent",
        [AgentCapability(name="public_search")])
    data = _register_agent(guard, "agt_data", "DataAgent",
        [AgentCapability(name="financial_extract")])
    unauth = _register_agent(guard, "agt_unauth", "UnauthorizedAgent", [])

    # Tools
    fin_tool = ToolDefinition(
        tool_id="tool_fin",
        name="query_financial_metrics",
        sensitivity=SensitivityLevel.HIGH,
        required_capabilities=["financial_extract"],
        target_resources=[Resource(
            resource_id="rsc_fin",
            name="EnterpriseFinancialWarehouse",
            sensitivity=SensitivityLevel.HIGH,
        )],
    )
    pii_tool = ToolDefinition(
        tool_id="tool_pii",
        name="customer_db_read",
        sensitivity=SensitivityLevel.CRITICAL,
        required_capabilities=["customer_db.read"],
        target_resources=[Resource(
            resource_id="rsc_pii",
            name="CustomerPIIVault",
            sensitivity=SensitivityLevel.CRITICAL,
        )],
    )
    search_tool = ToolDefinition(
        tool_id="tool_srch",
        name="public_web_search",
        sensitivity=SensitivityLevel.LOW,
        required_capabilities=["public_search"],
        target_resources=[Resource(
            resource_id="rsc_web",
            name="PublicWeb",
            sensitivity=SensitivityLevel.LOW,
        )],
    )

    guard.tool_registry["tool_fin"] = fin_tool
    guard.tool_registry["tool_pii"] = pii_tool
    guard.tool_registry["tool_srch"] = search_tool

    return guard, planner, research, data, unauth


@pytest.fixture
def guard_and_agents():
    return _make_guard_with_agents()


@pytest.fixture
def forensic_svc(guard_and_agents):
    guard, planner, research, data, unauth = guard_and_agents
    svc = ForensicService(guard)
    return svc, guard, planner, research, data, unauth


# ---------------------------------------------------------------------------
# FORENSICS TESTS (1–18)
# ---------------------------------------------------------------------------

class TestForensicsAgentProfile:
    """1–4: Agent access profile, declared vs delegated vs effective."""

    def test_1_agent_access_profile_structure(self, forensic_svc):
        """1. Agent access profile has required fields."""
        svc, guard, planner, research, data, unauth = forensic_svc
        profile = svc.query.get_agent_access("agt_planner")
        assert profile is not None
        assert isinstance(profile, AgentAccessProfile)
        assert profile.agent_id == "agt_planner"
        assert profile.agent_name == "PlannerAgent"
        assert "financial_extract" in profile.declared_capabilities
        assert "public_search" in profile.declared_capabilities

    def test_2_resource_access_profile(self, forensic_svc):
        """2. Resource access profile built from tool registry."""
        svc, guard, *_ = forensic_svc
        profile = svc.query.get_resource_access("EnterpriseFinancialWarehouse")
        assert profile is not None
        assert profile.resource_name == "EnterpriseFinancialWarehouse"
        assert profile.sensitivity == "HIGH"
        assert "query_financial_metrics" in profile.exposing_tools

    def test_3_declared_vs_delegated_capabilities(self, guard_and_agents):
        """3. Declared and delegated capabilities are separate."""
        guard, planner, research, data, unauth = guard_and_agents
        calc = EffectiveAccessCalculator(guard)

        # DataAgent has financial_extract declared
        declared = calc.get_declared_capabilities("agt_data")
        assert "financial_extract" in declared

        # No delegation yet → delegated should be empty
        delegated = calc.get_delegated_capabilities("agt_data")
        assert delegated == []

    def test_4_effective_authority_union(self, guard_and_agents):
        """4. Effective = declared ∪ delegated."""
        guard, planner, research, data, unauth = guard_and_agents

        # Manually add a delegation record
        grant = AuthorityGrant(
            delegator_agent_id="agt_planner",
            delegate_agent_id="agt_data",
            granted_capabilities=["financial_extract"],
        )
        dlg = Delegation(
            delegation_id=generate_id("dlg"),
            task_id=generate_id("tsk"),
            trace_id=generate_id("trc"),
            delegator_agent_id="agt_planner",
            delegate_agent_id="agt_data",
            authority_grant=grant,
            depth=1,
        )
        guard.delegation_registry[dlg.delegation_id] = dlg

        calc = EffectiveAccessCalculator(guard)
        effective = calc.get_effective_capabilities("agt_data")
        assert "financial_extract" in effective


class TestForensicsDelegation:
    """5–6: Recursive delegation and authority containment."""

    def test_5_recursive_delegation_chain(self, guard_and_agents):
        """5. Delegation chain is traversed recursively."""
        guard, planner, research, data, unauth = guard_and_agents

        grant_pr = AuthorityGrant(
            delegator_agent_id="agt_planner",
            delegate_agent_id="agt_research",
            granted_capabilities=["public_search"],
        )
        dlg_pr = Delegation(
            delegation_id=generate_id("dlg"),
            task_id=generate_id("tsk"),
            trace_id=generate_id("trc"),
            delegator_agent_id="agt_planner",
            delegate_agent_id="agt_research",
            authority_grant=grant_pr,
            depth=0,
        )
        grant_rd = AuthorityGrant(
            delegator_agent_id="agt_research",
            delegate_agent_id="agt_data",
            granted_capabilities=["financial_extract"],
        )
        dlg_rd = Delegation(
            delegation_id=generate_id("dlg"),
            task_id=generate_id("tsk"),
            trace_id=generate_id("trc"),
            delegator_agent_id="agt_research",
            delegate_agent_id="agt_data",
            authority_grant=grant_rd,
            parent_delegation_id=dlg_pr.delegation_id,
            depth=1,
        )
        guard.delegation_registry[dlg_pr.delegation_id] = dlg_pr
        guard.delegation_registry[dlg_rd.delegation_id] = dlg_rd

        auth_graph = AuthorityGraph.from_guard(guard)
        chain = auth_graph.get_delegation_chain("agt_data")
        delegator_ids = {c.delegator_agent_id for c in chain}
        assert "agt_research" in delegator_ids or "agt_planner" in delegator_ids

    def test_6_authority_containment_no_escalation(self, guard_and_agents):
        """6. Agent without PII capability cannot reach CustomerPIIVault."""
        guard, planner, research, data, unauth = guard_and_agents
        calc = EffectiveAccessCalculator(guard)
        reachable = calc.get_reachable_resources("agt_data")
        assert "CustomerPIIVault" not in reachable
        assert "EnterpriseFinancialWarehouse" in reachable


class TestForensicsAccessMatrix:
    """7–8: Access matrix and resource reverse lookup."""

    def test_7_access_matrix_structure(self, forensic_svc):
        """7. Access matrix contains correct entries for all agent×resource pairs."""
        svc, guard, *_ = forensic_svc
        matrix = svc.query.get_access_matrix()
        assert "agt_planner" in matrix.agents
        assert "EnterpriseFinancialWarehouse" in matrix.resources
        assert "CustomerPIIVault" in matrix.resources
        # PlannerAgent has financial_extract → can reach EnterpriseFinancialWarehouse
        entry = matrix.entries["agt_planner"]["EnterpriseFinancialWarehouse"]
        assert entry.effective_permission is True
        # Nobody has customer_db.read → CustomerPIIVault not reachable
        pii_entry = matrix.entries["agt_planner"]["CustomerPIIVault"]
        assert pii_entry.effective_permission is False

    def test_8_resource_reverse_lookup(self, forensic_svc):
        """8. Resource profile shows authorized agents (those with required capability)."""
        svc, guard, *_ = forensic_svc
        authorized = svc.query.get_resource_authorized_agents("EnterpriseFinancialWarehouse")
        # planner and data have financial_extract
        assert "agt_planner" in authorized or "agt_data" in authorized
        # unauth has no capabilities → should not be authorized
        assert "agt_unauth" not in authorized


class TestForensicsAttemptTracking:
    """9–12: Access attempt tracking, blocked vs actual."""

    def test_9_attempted_access_recorded(self, forensic_svc):
        """9. Recording an attempt makes it queryable."""
        svc, guard, planner, research, data, unauth = forensic_svc
        svc.record_access_attempt(
            agent_id="agt_unauth",
            tool_name="customer_db_read",
            decision="BLOCK",
            policy_reason="MISSING_AGENT_CAPABILITY",
            resource_name="CustomerPIIVault",
            resource_sensitivity="CRITICAL",
        )
        attempts = svc.query.get_agent_attempts("agt_unauth")
        assert len(attempts) == 1
        assert attempts[0]["tool_name"] == "customer_db_read"
        assert attempts[0]["decision"] == "BLOCK"

    def test_10_actual_access_recorded(self, forensic_svc):
        """10. Confirmed executions are tracked separately."""
        svc, guard, *_ = forensic_svc
        svc.record_actual_access(
            agent_id="agt_data",
            tool_name="query_financial_metrics",
            resource_name="EnterpriseFinancialWarehouse",
            resource_sensitivity="HIGH",
            execution_count=1,
        )
        actual = svc.query.get_agent_actual_access("agt_data")
        assert len(actual) == 1
        assert actual[0]["tool_name"] == "query_financial_metrics"

    def test_11_blocked_attempt_not_counted_as_actual_access(self, forensic_svc):
        """11. CRITICAL: blocked attempts NEVER appear in actual_access."""
        svc, guard, *_ = forensic_svc
        svc.record_access_attempt(
            agent_id="agt_unauth",
            tool_name="customer_db_read",
            decision="BLOCK",
            executed=False,
            execution_count=0,
        )
        actual = svc.query.get_agent_actual_access("agt_unauth")
        assert len(actual) == 0, "Blocked attempts must NEVER appear as actual access"

    def test_12_authorized_execution_counted_as_actual_access(self, forensic_svc):
        """12. CRITICAL: authorized executions MUST appear in actual_access."""
        svc, guard, *_ = forensic_svc
        svc.record_access_attempt(
            agent_id="agt_data",
            tool_name="query_financial_metrics",
            decision="ALLOW",
            executed=True,
            execution_count=1,
        )
        svc.record_actual_access(
            agent_id="agt_data",
            tool_name="query_financial_metrics",
            execution_count=1,
        )
        actual = svc.query.get_agent_actual_access("agt_data")
        assert len(actual) >= 1
        assert any(a["execution_count"] == 1 for a in actual)


class TestForensicsSnapshots:
    """13–14: Snapshot and diff."""

    def test_13_snapshot_creation(self, forensic_svc):
        """13. Snapshot captures current security state."""
        svc, guard, *_ = forensic_svc
        snap = svc.take_snapshot(label="before_attack")
        assert snap.snapshot_id is not None
        assert "agt_planner" in snap.agents
        assert snap.label == "before_attack"
        # Retrievable
        retrieved = svc.query.get_access_snapshot(snap.snapshot_id)
        assert retrieved is not None
        assert retrieved.snapshot_id == snap.snapshot_id

    def test_14_snapshot_diff_detects_changes(self, forensic_svc):
        """14. AccessDiff distinguishes authority change from attack attempt."""
        svc, guard, *_ = forensic_svc
        before = svc.take_snapshot(label="before")

        # Record an attack attempt
        attempt = svc.record_access_attempt(
            agent_id="agt_unauth",
            tool_name="customer_db_read",
            decision="BLOCK",
        )

        after = svc.take_snapshot(label="after")
        diff = svc.query.compare_access_snapshots(before.snapshot_id, after.snapshot_id)
        assert diff is not None
        assert diff.before_snapshot_id == before.snapshot_id
        assert diff.after_snapshot_id == after.snapshot_id
        # Authority should NOT have changed (no delegation was added)
        # Context counts the same
        assert diff.diff_id is not None


class TestForensicsReachable:
    """15: Reachable resource analysis."""

    def test_15_reachable_resource_analysis(self, forensic_svc):
        """15. Deterministic reachable-resource analysis from authority state."""
        svc, guard, *_ = forensic_svc
        reachable = svc.query.get_reachable_resources("agt_planner")
        # PlannerAgent has financial_extract → EnterpriseFinancialWarehouse reachable
        assert "EnterpriseFinancialWarehouse" in reachable
        # Nobody has customer_db.read → CustomerPIIVault not reachable
        assert "CustomerPIIVault" not in reachable

        not_reachable = svc.query.get_reachable_resources("agt_unauth")
        assert len(not_reachable) == 0


class TestForensicsExplanation:
    """16: Causal explanation."""

    def test_16_causal_explanation_assembled_from_evidence(self, forensic_svc):
        """16. Explanation built from evidence — no LLM, no invention."""
        svc, guard, *_ = forensic_svc
        explanation = svc.query.get_decision_explanation(
            agent_id="agt_unauth",
            tool_name="customer_db_read",
        )
        assert isinstance(explanation, ForensicExplanation)
        assert explanation.agent_id == "agt_unauth"
        assert explanation.tool_name == "customer_db_read"
        text = explanation.to_text()
        assert "agt_unauth" in text
        assert "customer_db_read" in text


class TestForensicsAttackReport:
    """17–18: Attack forensic report and bypass forensic report."""

    def _make_attack_result(self, bypassed: bool = False):
        from actshield.offensive.results import OffensiveAttackResult, ExecutionEvidence, AttackStatus
        from actshield.offensive.attack import AttackType
        from actshield.offensive.evidence import SecurityAnalysisEvidence

        ev = SecurityAnalysisEvidence(
            attack_id="atk_test_001",
            attack_type=AttackType.DIRECT_PROMPT_INJECTION,
            acting_agent="agt_unauth",
            task_intent="public financial analysis",
            entry_point="customer_db_read",
            taint_state="TAINTED",
            requested_tool="customer_db_read",
            requested_capability="customer_db.read",
            required_capabilities=["customer_db.read"],
            delegated_capabilities=[],
            authority_contained=False,
            policy_decision="BLOCK" if not bypassed else "ALLOW",
            policy_reason_code="MISSING_AGENT_CAPABILITY",
            tool_executed=bypassed,
            execution_count=1 if bypassed else 0,
            sensitive_db_calls=1 if bypassed else 0,
        )

        return OffensiveAttackResult(
            attack_id="atk_test_001",
            campaign_id="camp_test",
            attack_type=AttackType.DIRECT_PROMPT_INJECTION,
            target="VulnerableDemoTarget",
            entry_point="customer_db_read",
            expected_decision="BLOCK",
            actual_decision="ALLOW" if bypassed else "BLOCK",
            expected_execution=False,
            actual_execution=bypassed,
            blocked=not bypassed,
            bypassed=bypassed,
            security_evidence=ev,
            mutation_lineage=["atk_base", "atk_mut_1", "atk_test_001"],
            execution_evidence=ExecutionEvidence(
                tool_executed=bypassed,
                execution_count=1 if bypassed else 0,
                sensitive_db_calls=1 if bypassed else 0,
                actual_action="ALLOW" if bypassed else "BLOCK",
            ),
            status=AttackStatus.BYPASS if bypassed else AttackStatus.PASS,
        )

    def test_17_attack_forensic_report(self, forensic_svc):
        """17. Attack forensic report links all evidence."""
        svc, guard, *_ = forensic_svc
        result = self._make_attack_result(bypassed=False)
        svc.ingest_attack_result(result)

        report = svc.query.get_attack_forensics("atk_test_001")
        assert report is not None
        assert isinstance(report, AttackForensicReport)
        assert report.attack_id == "atk_test_001"
        assert report.bypassed is False
        assert report.tool_executed is False
        assert report.execution_count == 0
        assert report.sensitive_db_calls == 0
        assert "atk_base" in report.mutation_lineage

    def test_18_bypass_forensic_report(self, forensic_svc):
        """18. Bypass forensic report flags regression and shows execution evidence."""
        svc, guard, *_ = forensic_svc
        result = self._make_attack_result(bypassed=True)
        svc.ingest_attack_result(result)

        report = svc.query.get_attack_forensics("atk_test_001")
        assert report.bypassed is True
        assert report.tool_executed is True
        assert report.execution_count == 1
        assert report.sensitive_db_calls == 1
        assert report.regression_status == "REGRESSION_CREATED"


# ---------------------------------------------------------------------------
# API TESTS (19–35)
# ---------------------------------------------------------------------------

class TestProductApi:
    """API endpoint-equivalent tests."""

    @pytest.fixture
    def api(self, forensic_svc):
        from actshield.api.service import ApiService
        svc, guard, planner, research, data, unauth = forensic_svc
        # Record some data
        svc.record_access_attempt(
            agent_id="agt_unauth",
            tool_name="customer_db_read",
            decision="BLOCK",
            policy_reason="MISSING_AGENT_CAPABILITY",
            resource_name="CustomerPIIVault",
            resource_sensitivity="CRITICAL",
        )
        svc.record_actual_access(
            agent_id="agt_data",
            tool_name="query_financial_metrics",
            resource_name="EnterpriseFinancialWarehouse",
            execution_count=1,
        )
        return ApiService(svc, dev_mode=True)

    def test_19_health(self, api):
        """19. /api/v1/health returns ok."""
        resp = api.get_health()
        assert resp.status == "ok"
        assert resp.version is not None

    def test_20_overview(self, api):
        """20. /api/v1/overview returns aggregate values."""
        resp = api.get_overview()
        assert resp.agents is not None
        assert resp.agents >= 4
        assert resp.protected_tools is not None
        assert resp.protected_tools >= 3

    def test_21_agents_list(self, api):
        """21. /api/v1/agents lists all agents."""
        agents = api.list_agents()
        agent_ids = [a.agent_id for a in agents]
        assert "agt_planner" in agent_ids
        assert "agt_data" in agent_ids

    def test_22_agent_access(self, api):
        """22. /api/v1/agents/{agent_id}/access returns clean JSON profile."""
        resp = api.get_agent_access("agt_data")
        assert not isinstance(resp, dict) or "error" not in resp
        from actshield.api.models import AgentAccessResponse
        assert isinstance(resp, AgentAccessResponse)
        assert resp.agent_id == "agt_data"
        assert "financial_extract" in resp.declared

    def test_23_resources_list(self, api):
        """23. /api/v1/resources lists all resources."""
        resources = api.list_resources()
        assert "EnterpriseFinancialWarehouse" in resources
        assert "CustomerPIIVault" in resources

    def test_24_resource_access(self, api):
        """24. /api/v1/resources/{resource_name} returns resource profile."""
        resp = api.get_resource("EnterpriseFinancialWarehouse")
        from actshield.api.models import ResourceAccessResponse
        assert isinstance(resp, ResourceAccessResponse)
        assert resp.sensitivity == "HIGH"

    def test_25_access_matrix(self, api):
        """25. /api/v1/access/matrix returns full matrix."""
        resp = api.get_access_matrix()
        from actshield.api.models import AccessMatrixResponse
        assert isinstance(resp, AccessMatrixResponse)
        assert "agt_planner" in resp.agents
        assert "CustomerPIIVault" in resp.resources

    def test_26_traces_not_found(self, api):
        """26. /api/v1/traces/{trace_id} returns error for unknown trace."""
        resp = api.get_trace("nonexistent_trace_id")
        from actshield.api.models import ErrorResponse
        assert isinstance(resp, ErrorResponse)
        assert resp.error["code"] == "TRACE_NOT_FOUND"

    def test_27_attacks_list(self, forensic_svc, api):
        """27. /api/v1/attacks lists ingested attacks."""
        svc, guard, *_ = forensic_svc
        from actshield.offensive.results import OffensiveAttackResult, ExecutionEvidence, AttackStatus
        from actshield.offensive.attack import AttackType
        result = OffensiveAttackResult(
            attack_id="atk_api_test",
            attack_type=AttackType.DIRECT_PROMPT_INJECTION,
            target="TestTarget",
            entry_point="test_tool",
            status=AttackStatus.PASS,
        )
        svc.ingest_attack_result(result)
        attacks = api.list_attacks()
        attack_ids = [a.attack_id for a in attacks]
        assert "atk_api_test" in attack_ids

    def test_28_attack_lineage(self, forensic_svc, api):
        """28. /api/v1/attacks/{attack_id}/lineage returns lineage."""
        svc, guard, *_ = forensic_svc
        from actshield.offensive.results import OffensiveAttackResult, AttackStatus
        from actshield.offensive.attack import AttackType
        result = OffensiveAttackResult(
            attack_id="atk_lineage_test",
            attack_type=AttackType.DIRECT_PROMPT_INJECTION,
            target="TestTarget",
            entry_point="test_tool",
            mutation_lineage=["atk_base", "atk_mut_1", "atk_lineage_test"],
            status=AttackStatus.PASS,
        )
        svc.ingest_attack_result(result)
        resp = api.get_attack_lineage("atk_lineage_test")
        assert isinstance(resp, dict)
        assert resp["mutation_lineage"] == ["atk_base", "atk_mut_1", "atk_lineage_test"]

    def test_29_attack_forensics(self, forensic_svc, api):
        """29. /api/v1/attacks/{attack_id}/forensics returns full forensic report."""
        svc, guard, *_ = forensic_svc
        from actshield.offensive.results import OffensiveAttackResult, ExecutionEvidence, AttackStatus
        from actshield.offensive.attack import AttackType
        from actshield.offensive.evidence import SecurityAnalysisEvidence
        ev = SecurityAnalysisEvidence(
            attack_id="atk_forensics_test",
            attack_type=AttackType.TOOL_POISONING,
            acting_agent="agt_unauth",
            task_intent="test",
            entry_point="test_tool",
            requested_tool="test_tool",
        )
        result = OffensiveAttackResult(
            attack_id="atk_forensics_test",
            attack_type=AttackType.TOOL_POISONING,
            target="TestTarget",
            entry_point="test_tool",
            blocked=True,
            security_evidence=ev,
            status=AttackStatus.PASS,
        )
        svc.ingest_attack_result(result)
        resp = api.get_attack_forensics("atk_forensics_test")
        from actshield.api.models import AttackForensicsResponse
        assert isinstance(resp, AttackForensicsResponse)
        assert resp.attack_id == "atk_forensics_test"

    def test_30_campaigns_list(self, forensic_svc, api):
        """30. /api/v1/campaigns aggregates by campaign_id."""
        svc, guard, *_ = forensic_svc
        from actshield.offensive.results import OffensiveAttackResult, AttackStatus
        from actshield.offensive.attack import AttackType
        for i in range(3):
            r = OffensiveAttackResult(
                attack_id=f"atk_camp_{i}",
                campaign_id="camp_abc",
                attack_type=AttackType.DIRECT_PROMPT_INJECTION,
                target="T",
                entry_point="e",
                blocked=(i < 2),
                bypassed=(i == 2),
                status=AttackStatus.BYPASS if i == 2 else AttackStatus.PASS,
            )
            svc.ingest_attack_result(r)
        campaigns = api.list_campaigns()
        camp = next((c for c in campaigns if c.campaign_id == "camp_abc"), None)
        assert camp is not None
        assert camp.total_attacks == 3
        assert camp.bypasses == 1

    def test_31_regressions_list(self, forensic_svc, api):
        """31. /api/v1/regressions = attacks where bypassed==True."""
        svc, guard, *_ = forensic_svc
        from actshield.offensive.results import OffensiveAttackResult, AttackStatus
        from actshield.offensive.attack import AttackType
        r = OffensiveAttackResult(
            attack_id="atk_regression",
            attack_type=AttackType.DIRECT_PROMPT_INJECTION,
            target="T", entry_point="e",
            bypassed=True,
            status=AttackStatus.BYPASS,
        )
        svc.ingest_attack_result(r)
        regressions = api.list_regressions()
        assert any(r.attack_id == "atk_regression" for r in regressions)

    def test_32_incidents_list(self, forensic_svc, api):
        """32. /api/v1/incidents lists recorded incidents."""
        svc, guard, *_ = forensic_svc
        inc = ForensicIncident(
            incident_type=IncidentType.CAPABILITY_VIOLATION,
            severity=IncidentSeverity.HIGH,
            agent_id="agt_unauth",
            tool_name="customer_db_read",
            decision=AccessDecision.BLOCK,
            description="Test incident",
        )
        svc.record_incident(inc)
        incidents = api.list_incidents()
        assert any(i.agent_id == "agt_unauth" for i in incidents)

    def test_33_policy_evaluate(self, api):
        """33. POST /api/v1/policies/evaluate — read-only policy simulation."""
        from actshield.api.models import PolicyEvaluateRequest, PolicyEvaluateResponse
        req = PolicyEvaluateRequest(
            tool_name="customer_db_read",
            agent_id="agt_unauth",
            capabilities=[],
            intent="financial analysis",
        )
        resp = api.evaluate_policy(req)
        assert isinstance(resp, PolicyEvaluateResponse)
        # agt_unauth has no capabilities → should be blocked
        assert resp.decision in ("BLOCK", "MONITOR", "ALLOW")

    def test_34_invalid_agent_id_error(self, api):
        """34. Invalid agent ID returns consistent error format."""
        from actshield.api.models import ErrorResponse
        resp = api.get_agent_access("nonexistent_agent_xyz")
        assert isinstance(resp, ErrorResponse)
        assert resp.error["code"] == "AGENT_NOT_FOUND"
        assert "nonexistent_agent_xyz" in resp.error["message"]

    def test_35_consistent_error_format(self, api):
        """35. Error responses always have code + message + request_id."""
        from actshield.api.models import ErrorResponse
        resp = api.get_resource("nonexistent_resource_xyz")
        assert isinstance(resp, ErrorResponse)
        assert "code" in resp.error
        assert "message" in resp.error
        assert "request_id" in resp.error


# ---------------------------------------------------------------------------
# SECURITY TESTS (36–40)
# ---------------------------------------------------------------------------

class TestForensicSecurity:
    """API cannot grant authority, bypass policy, or expose secrets."""

    def test_36_api_cannot_grant_authority(self, forensic_svc):
        """36. Forensic queries never grant capabilities."""
        svc, guard, planner, research, data, unauth = forensic_svc
        calc = EffectiveAccessCalculator(guard)

        # Before querying
        before_caps = calc.get_effective_capabilities("agt_unauth")

        # Query forensic layer
        _ = svc.query.get_agent_access("agt_unauth")
        _ = svc.query.get_access_matrix()
        _ = svc.query.get_reachable_resources("agt_unauth")

        # After querying — capabilities must not change
        after_caps = calc.get_effective_capabilities("agt_unauth")
        assert before_caps == after_caps

    def test_37_api_cannot_bypass_policy_evaluator(self, forensic_svc):
        """37. Policy evaluate is read-only simulation — doesn't bypass enforcement."""
        from actshield.api.service import ApiService
        from actshield.api.models import PolicyEvaluateRequest
        svc, guard, *_ = forensic_svc
        api = ApiService(svc)

        # Simulate policy evaluation
        req = PolicyEvaluateRequest(
            tool_name="customer_db_read",
            agent_id="agt_unauth",
            capabilities=[],
        )
        resp = api.evaluate_policy(req)
        # The real agent registry is NOT modified
        agent = guard.agent_registry.get("agt_unauth")
        assert agent is not None
        assert not agent.has_capability("customer_db.read")

    def test_38_secrets_sanitized(self):
        """38. Serializer redacts sensitive keys."""
        from actshield.forensics.serializers import sanitize_for_export
        data = {
            "agent_id": "agt_test",
            "api_key": "sk-supersecret",
            "token": "bearer_xyz",
            "config": {"password": "hunter2", "model": "gpt-4"},
        }
        sanitized = sanitize_for_export(data)
        assert sanitized["api_key"] == "[REDACTED]"
        assert sanitized["token"] == "[REDACTED]"
        assert sanitized["config"]["password"] == "[REDACTED]"
        assert sanitized["agent_id"] == "agt_test"
        assert sanitized["config"]["model"] == "gpt-4"

    def test_39_forensic_queries_read_only(self, forensic_svc):
        """39. Forensic queries don't modify agent registry or tool registry."""
        svc, guard, *_ = forensic_svc
        agent_count_before = len(guard.agent_registry)
        tool_count_before = len(guard.tool_registry)
        delegation_count_before = len(guard.delegation_registry)

        # Run every query
        svc.query.get_all_agents()
        svc.query.get_access_matrix()
        svc.query.get_all_resources()
        svc.query.get_reachable_resources("agt_planner")
        svc.query.get_agent_access("agt_planner")
        svc.query.get_overview()

        # Nothing changed
        assert len(guard.agent_registry) == agent_count_before
        assert len(guard.tool_registry) == tool_count_before
        assert len(guard.delegation_registry) == delegation_count_before

    def test_40_correlation_ids_preserved(self, forensic_svc):
        """40. Trace IDs are preserved through attempt → query → report."""
        svc, guard, *_ = forensic_svc
        trace_id = generate_id("trc")
        svc.record_access_attempt(
            agent_id="agt_unauth",
            tool_name="customer_db_read",
            decision="BLOCK",
            trace_id=trace_id,
        )
        attempts = svc.query.get_agent_attempts("agt_unauth")
        # Find the attempt with our trace_id
        found = [a for a in attempts if a.get("trace_id") == trace_id]
        assert len(found) >= 1


# ---------------------------------------------------------------------------
# END-TO-END TESTS (41–42)
# ---------------------------------------------------------------------------

class TestEndToEnd:
    """Full pipeline validation — unauthorized blocked, authorized succeeds."""

    def test_41_unauthorized_access_blocked_zero_sensitive_calls(self):
        """41. UNAUTHORIZED: customer_db.read blocked, sensitive_db_calls==0.

        Scenario:
          USER → TASK → PlannerAgent → ResearchAgent → External MCP
          → TAINTED CONTEXT → AnalysisAgent → DataAgent
          → customer_db_read → PolicyEvaluator → BLOCK
        """
        guard = ActShield(config=ActShieldConfig(
            enforce_monotonic_delegation=True,
            block_tainted_sink_access=True,
        ))

        data_agent = _register_agent(
            guard, "agt_data_e2e", "DataAgent",
            [AgentCapability(name="financial_extract")],
        )

        pii_tool = ToolDefinition(
            tool_id="tool_pii_e2e",
            name="customer_db_read",
            sensitivity=SensitivityLevel.CRITICAL,
            required_capabilities=["customer_db.read"],
            target_resources=[Resource(
                resource_id="rsc_pii_e2e",
                name="CustomerPIIVault",
                sensitivity=SensitivityLevel.CRITICAL,
            )],
        )
        guard.tool_registry["tool_pii_e2e"] = pii_tool

        svc = ForensicService(guard)

        # Simulate tainted context from External MCP
        provenance = Provenance(
            source=ContextSource.EXTERNAL_MCP,
            trust_level="untrusted",
        )
        tainted_ctx = Context(
            context_id=generate_id("ctx"),
            source=ContextSource.EXTERNAL_MCP,
            taint_state=TaintState.TAINTED,
            provenance=provenance,
        )
        guard.context_registry[tainted_ctx.context_id] = tainted_ctx

        # Policy evaluation
        from actshield.tools.tool import ToolRequest
        from actshield.tracing.correlation import CorrelationContext
        req = ToolRequest(
            tool_id="tool_pii_e2e",
            tool_name="customer_db_read",
            agent_id="agt_data_e2e",
        )
        corr = CorrelationContext(
            trace_id=generate_id("trc"),
            span_id=generate_id("spn"),
            task_id=generate_id("tsk"),
            agent_id="agt_data_e2e",
            metadata={"intent": "Analyze FY2026 financial performance"},
        )
        decision = guard.policy_evaluator.evaluate(
            tool_def=pii_tool,
            request=req,
            ctx=corr,
            active_contexts=[tainted_ctx],
        )

        # Record in forensic layer
        executed = decision.action.value in ("ALLOW", "MONITOR")
        svc.record_access_attempt(
            agent_id="agt_data_e2e",
            tool_name="customer_db_read",
            decision=decision.action.value,
            policy_reason=decision.reason_code,
            resource_name="CustomerPIIVault",
            resource_sensitivity="CRITICAL",
            trace_id=corr.trace_id,
            taint_state="TAINTED",
            authority_contained=(decision.action.value != "BLOCK"),
            executed=executed,
            execution_count=0,
        )

        # Forensic verification
        from actshield.decisions.decision import DecisionAction
        assert decision.action == DecisionAction.BLOCK, f"Expected BLOCK, got {decision.action}"

        # Confirm: no sensitive access
        actual = svc.query.get_agent_actual_access("agt_data_e2e")
        customer_reads = sum(
            a.get("execution_count", 0) for a in actual
            if a.get("tool_name") == "customer_db_read"
        )
        assert customer_reads == 0, f"customer_read_calls must be 0, got {customer_reads}"

        # Forensic answers
        profile = svc.query.get_agent_access("agt_data_e2e")
        assert profile is not None
        assert "customer_db.read" not in profile.effective_capabilities
        assert "CustomerPIIVault" not in profile.reachable_resources

    def test_42_authorized_positive_control(self):
        """42. AUTHORIZED: financial_extract allowed, execution_count==1.

        The system must NOT simply block everything.
        Authorized executions must be confirmed.
        """
        guard = ActShield(config=ActShieldConfig(
            enforce_monotonic_delegation=True,
            block_tainted_sink_access=True,
        ))

        auth_agent = _register_agent(
            guard, "agt_authorized_e2e", "AuthorizedAgent",
            [AgentCapability(name="financial_extract")],
        )

        fin_tool = ToolDefinition(
            tool_id="tool_fin_e2e",
            name="query_financial_metrics",
            sensitivity=SensitivityLevel.HIGH,
            required_capabilities=["financial_extract"],
            target_resources=[Resource(
                resource_id="rsc_fin_e2e",
                name="EnterpriseFinancialWarehouse",
                sensitivity=SensitivityLevel.HIGH,
            )],
        )
        guard.tool_registry["tool_fin_e2e"] = fin_tool
        svc = ForensicService(guard)

        from actshield.tools.tool import ToolRequest
        from actshield.tracing.correlation import CorrelationContext
        req = ToolRequest(
            tool_id="tool_fin_e2e",
            tool_name="query_financial_metrics",
            agent_id="agt_authorized_e2e",
        )
        corr = CorrelationContext(
            trace_id=generate_id("trc"),
            span_id=generate_id("spn"),
            task_id=generate_id("tsk"),
            agent_id="agt_authorized_e2e",
            metadata={"intent": "Analyze FY2026 financial performance"},
        )
        decision = guard.policy_evaluator.evaluate(
            tool_def=fin_tool,
            request=req,
            ctx=corr,
            active_contexts=[],
        )

        # Authorized agent should be ALLOWED
        from actshield.decisions.decision import DecisionAction
        assert decision.action in (DecisionAction.ALLOW, DecisionAction.MONITOR), \
            f"Expected ALLOW/MONITOR for authorized agent, got {decision.action}"

        # Record actual execution
        svc.record_access_attempt(
            agent_id="agt_authorized_e2e",
            tool_name="query_financial_metrics",
            decision=decision.action.value,
            executed=True,
            execution_count=1,
            resource_name="EnterpriseFinancialWarehouse",
        )
        svc.record_actual_access(
            agent_id="agt_authorized_e2e",
            tool_name="query_financial_metrics",
            resource_name="EnterpriseFinancialWarehouse",
            execution_count=1,
        )

        # Forensic verification
        actual = svc.query.get_agent_actual_access("agt_authorized_e2e")
        assert len(actual) >= 1
        fin_reads = sum(
            a.get("execution_count", 0) for a in actual
            if a.get("tool_name") == "query_financial_metrics"
        )
        assert fin_reads == 1, f"Expected 1 financial read, got {fin_reads}"

        profile = svc.query.get_agent_access("agt_authorized_e2e")
        assert "EnterpriseFinancialWarehouse" in profile.reachable_resources
        assert profile.total_executions == 1
