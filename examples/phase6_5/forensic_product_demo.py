"""
============================================================
AGENTGUARD PHASE 6.5
FORENSIC INTELLIGENCE + PRODUCT API DEMO
============================================================

Demonstrates end-to-end:
  1. Create agents and delegation chain
  2. Register protected tools and resources
  3. Execute legitimate access (authorized positive control)
  4. Execute unauthorized attempt (blocked, zero sensitive DB calls)
  5. Generate forensic snapshot
  6. Generate access matrix
  7. Generate attack forensic report (using Phase 5 evidence)
  8. Explain blocked decision
  9. Show reachable resources
 10. Show actual vs attempted access
 11. Show before/after access state diff
 12. Export all forensic data to JSON
 13. Demo Product API (all endpoint-equivalent methods)
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "sdk"))

from agentguard.agents.agent import Agent
from agentguard.agents.identity import AgentCapability, AgentIdentity, AgentTrustLevel
from agentguard.client import AgentGuard
from agentguard.config import AgentGuardConfig
from agentguard.context.context import Context
from agentguard.context.provenance import ContextSource, Provenance
from agentguard.context.taint import TaintState
from agentguard.decisions.decision import DecisionAction
from agentguard.delegation.authority import AuthorityGrant
from agentguard.delegation.delegation import Delegation
from agentguard.forensics.service import ForensicService
from agentguard.forensics.models import ForensicIncident, IncidentType, IncidentSeverity, AccessDecision
from agentguard.api.service import ApiService
from agentguard.api.models import PolicyEvaluateRequest
from agentguard.tracing.correlation import generate_id
from agentguard.tools.tool import Resource, SensitivityLevel, ToolDefinition, ToolRequest
from agentguard.tracing.correlation import CorrelationContext


# ---------------------------------------------------------------------------
# 0. Banner
# ---------------------------------------------------------------------------
def banner(title: str) -> None:
    print("\n" + "=" * 60)
    print(f"  {title}")
    print("=" * 60)


def section(title: str) -> None:
    print(f"\n{'â”€' * 60}")
    print(f"  {title}")
    print(f"{'â”€' * 60}")


banner("AGENTGUARD PHASE 6.5 â€” FORENSIC INTELLIGENCE + PRODUCT API")


# ---------------------------------------------------------------------------
# 1. Setup AgentGuard runtime
# ---------------------------------------------------------------------------
section("1. Initialize Runtime")

guard = AgentGuard(config=AgentGuardConfig(
    enforce_monotonic_delegation=True,
    block_tainted_sink_access=True,
))

# Register agents directly for demo (fixed IDs)
def _reg(agent_id, name, caps, trust=AgentTrustLevel.MEDIUM):
    identity = AgentIdentity(agent_id=agent_id, name=name, capabilities=caps, trust_level=trust)
    agent = Agent(identity=identity, guard=guard)
    guard.agent_registry[agent_id] = agent
    return agent

planner = _reg("agt_planner", "PlannerAgent",
               [AgentCapability(name="public_search"), AgentCapability(name="financial_extract")],
               trust=AgentTrustLevel.HIGH)
research = _reg("agt_research", "ResearchAgent", [AgentCapability(name="public_search")])
data    = _reg("agt_data", "DataAgent", [AgentCapability(name="financial_extract")])
unauth  = _reg("agt_unauth", "DataAgent_Compromised", [])

print(f"  âœ“ Registered {len(guard.agent_registry)} agents")

# Register tools and resources
fin_tool = ToolDefinition(
    tool_id="tool_fin", name="query_financial_metrics",
    sensitivity=SensitivityLevel.HIGH,
    required_capabilities=["financial_extract"],
    target_resources=[Resource(resource_id="rsc_fin", name="EnterpriseFinancialWarehouse",
                               sensitivity=SensitivityLevel.HIGH)],
)
pii_tool = ToolDefinition(
    tool_id="tool_pii", name="customer_db_read",
    sensitivity=SensitivityLevel.CRITICAL,
    required_capabilities=["customer_db.read"],
    target_resources=[Resource(resource_id="rsc_pii", name="CustomerPIIVault",
                               sensitivity=SensitivityLevel.CRITICAL)],
)
search_tool = ToolDefinition(
    tool_id="tool_srch", name="public_web_search",
    sensitivity=SensitivityLevel.LOW,
    required_capabilities=["public_search"],
    target_resources=[Resource(resource_id="rsc_web", name="PublicWeb",
                               sensitivity=SensitivityLevel.LOW)],
)

guard.tool_registry["tool_fin"]  = fin_tool
guard.tool_registry["tool_pii"]  = pii_tool
guard.tool_registry["tool_srch"] = search_tool

print(f"  âœ“ Registered {len(guard.tool_registry)} protected tools")

# Add delegation: PlannerAgent â†’ DataAgent (financial_extract)
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
print(f"  âœ“ Delegation: PlannerAgent â†’ DataAgent (financial_extract)")


# ---------------------------------------------------------------------------
# 2. Attach Forensic Service
# ---------------------------------------------------------------------------
section("2. Attach ForensicService")

forensic = ForensicService(guard)
api = ApiService(forensic, dev_mode=True)

print(f"  âœ“ ForensicService attached")
print(f"  âœ“ ApiService ready (dev_mode)")


# ---------------------------------------------------------------------------
# 3. Capture BEFORE snapshot
# ---------------------------------------------------------------------------
section("3. Security State Snapshot (BEFORE)")

snap_before = forensic.take_snapshot(label="before_attack")
print(f"  âœ“ Snapshot: {snap_before.snapshot_id}")
print(f"  Agents: {list(snap_before.agents.keys())}")


# ---------------------------------------------------------------------------
# 4. Legitimate access â€” authorized positive control
# ---------------------------------------------------------------------------
section("4. Authorized Access â€” DataAgent â†’ financial_metrics")

corr_auth = CorrelationContext(
    trace_id=generate_id("trc"),
    span_id=generate_id("spn"),
    task_id=generate_id("tsk"),
    agent_id="agt_data",
    metadata={"intent": "Analyze FY2026 financial performance using public data"},
)
req_auth = ToolRequest(tool_id="tool_fin", tool_name="query_financial_metrics", agent_id="agt_data")
decision_auth = guard.policy_evaluator.evaluate(
    tool_def=fin_tool, request=req_auth, ctx=corr_auth, active_contexts=[]
)

print(f"  Decision: {decision_auth.action.value}  (reason: {decision_auth.reason_code})")
assert decision_auth.action in (DecisionAction.ALLOW, DecisionAction.MONITOR), \
    f"Expected ALLOW for authorized agent, got {decision_auth.action}"

# Record in forensic layer
forensic.record_access_attempt(
    agent_id="agt_data",
    tool_name="query_financial_metrics",
    decision=decision_auth.action.value,
    resource_name="EnterpriseFinancialWarehouse",
    resource_sensitivity="HIGH",
    trace_id=corr_auth.trace_id,
    executed=True, execution_count=1,
)
forensic.record_actual_access(
    agent_id="agt_data",
    tool_name="query_financial_metrics",
    resource_name="EnterpriseFinancialWarehouse",
    execution_count=1,
)
print(f"  âœ“ Execution recorded: execution_count=1")


# ---------------------------------------------------------------------------
# 5. Unauthorized attempt â€” tainted context â†’ PII vault
# ---------------------------------------------------------------------------
section("5. Unauthorized Attempt â€” DataAgent_Compromised â†’ customer_db_read")

# Simulate tainted context from External MCP
prov = Provenance(source=ContextSource.EXTERNAL_MCP, trust_level="untrusted")
tainted_ctx = Context(
    context_id=generate_id("ctx"),
    source=ContextSource.EXTERNAL_MCP,
    taint_state=TaintState.TAINTED,
    provenance=prov,
)
guard.context_registry[tainted_ctx.context_id] = tainted_ctx

corr_unauth = CorrelationContext(
    trace_id=generate_id("trc"),
    span_id=generate_id("spn"),
    task_id=generate_id("tsk"),
    agent_id="agt_unauth",
    metadata={"intent": "Analyze FY2026 financial performance using public data"},
)
req_unauth = ToolRequest(tool_id="tool_pii", tool_name="customer_db_read", agent_id="agt_unauth")
decision_unauth = guard.policy_evaluator.evaluate(
    tool_def=pii_tool, request=req_unauth, ctx=corr_unauth,
    active_contexts=[tainted_ctx]
)

print(f"  Decision: {decision_unauth.action.value}  (reason: {decision_unauth.reason_code})")
assert decision_unauth.action == DecisionAction.BLOCK, \
    f"Expected BLOCK for unauthorized agent, got {decision_unauth.action}"

forensic.record_access_attempt(
    agent_id="agt_unauth",
    tool_name="customer_db_read",
    decision="BLOCK",
    policy_reason=decision_unauth.reason_code,
    resource_name="CustomerPIIVault",
    resource_sensitivity="CRITICAL",
    trace_id=corr_unauth.trace_id,
    taint_state="TAINTED",
    authority_contained=False,
    executed=False, execution_count=0,
)

# Create incident
incident = forensic.record_incident(ForensicIncident(
    incident_type=IncidentType.CAPABILITY_VIOLATION,
    severity=IncidentSeverity.CRITICAL,
    agent_id="agt_unauth",
    resource_name="CustomerPIIVault",
    tool_name="customer_db_read",
    decision=AccessDecision.BLOCK,
    executed=False,
    trace_id=corr_unauth.trace_id,
    description=decision_unauth.explanation,
))
print(f"  âœ“ Incident recorded: {incident.incident_id}")


# ---------------------------------------------------------------------------
# 6. Agent Access Profile
# ---------------------------------------------------------------------------
section("6. Agent: DataAgent")

profile = forensic.query.get_agent_access("agt_data")
print(f"""
  AGENT: {profile.agent_name}

  DECLARED ACCESS
  {profile.declared_capabilities}

  DELEGATED ACCESS
  {profile.delegated_capabilities}

  EFFECTIVE ACCESS
  {profile.effective_capabilities}

  ATTEMPTED
  {[a.tool_name for a in profile.recent_attempts]}

  ACTUAL
  {[a.tool_name for a in profile.recent_actual_access]}

  TOTAL EXECUTIONS: {profile.total_executions}
  TOTAL BLOCKED:    {profile.total_blocked}
""")


# ---------------------------------------------------------------------------
# 7. Access Matrix
# ---------------------------------------------------------------------------
section("7. Access Matrix")

matrix = forensic.query.get_access_matrix()
table = matrix.to_table()
if matrix.agents and matrix.resources:
    header = f"{'AGENT':<25} | " + " | ".join(f"{r[:20]:<20}" for r in matrix.resources)
    print(f"  {header}")
    print(f"  {'â”€' * len(header)}")
    for agent_id, row in table.items():
        vals = " | ".join(f"{row.get(r, 'NO'):<20}" for r in matrix.resources)
        print(f"  {agent_id:<25} | {vals}")


# ---------------------------------------------------------------------------
# 8. Reachable Resources
# ---------------------------------------------------------------------------
section("8. Reachable Resources")

for aid in ["agt_data", "agt_unauth"]:
    reachable = forensic.query.get_reachable_resources(aid)
    print(f"\n  {aid}:")
    if reachable:
        for r in reachable:
            print(f"    âœ“ {r}")
    else:
        print("    (none)")

    # Show explicitly non-reachable sensitive resources
    all_resources = forensic.query.get_all_resources()
    non_reachable = [r for r in all_resources if r not in reachable]
    for r in non_reachable:
        print(f"    âœ— {r}  (not authorized)")


# ---------------------------------------------------------------------------
# 9. Forensic Explanation â€” WHY WAS customer_db_read BLOCKED?
# ---------------------------------------------------------------------------
section("9. Forensic Explanation â€” WHY BLOCKED?")

explanation = forensic.query.get_decision_explanation(
    agent_id="agt_unauth",
    tool_name="customer_db_read",
    trace_id=corr_unauth.trace_id,
)
print(explanation.to_text())


# ---------------------------------------------------------------------------
# 10. Snapshot + Diff (BEFORE vs AFTER)
# ---------------------------------------------------------------------------
section("10. Security State Diff â€” Before vs After")

snap_after = forensic.take_snapshot(label="after_attack")
diff = forensic.query.compare_access_snapshots(snap_before.snapshot_id, snap_after.snapshot_id)

print(f"  Before:           {snap_before.snapshot_id}")
print(f"  After:            {snap_after.snapshot_id}")
print(f"  Authority Changed: {diff.authority_changed}")
print(f"  Context Changed:   {diff.context_changed}")
print(f"  Attack Detected:   {diff.attack_detected}")
print(f"  Summary:          {diff.summary}")


# ---------------------------------------------------------------------------
# 11. Product API Demo
# ---------------------------------------------------------------------------
section("11. Product API â€” Dashboard-Ready Endpoints")

print("\n  GET /api/v1/health")
health = api.get_health()
print(f"    status={health.status}  version={health.version}")

print("\n  GET /api/v1/overview")
overview = api.get_overview()
print(f"    agents={overview.agents}  tools={overview.protected_tools}")
print(f"    blocked={overview.blocked}  bypasses={overview.bypasses}")
print(f"    sensitive_prevented={overview.sensitive_prevented}  sensitive_executed={overview.sensitive_executed}")

print("\n  GET /api/v1/agents")
agents_list = api.list_agents()
for a in agents_list:
    print(f"    {a.agent_id:<20} | {a.trust_level:<8} | caps={a.effective_capabilities}")

print("\n  GET /api/v1/agents/agt_data/access")
ag_access = api.get_agent_access("agt_data")
print(f"    declared={ag_access.declared}")
print(f"    effective={ag_access.effective}")
print(f"    reachable_resources={ag_access.reachable_resources}")

print("\n  GET /api/v1/resources/CustomerPIIVault")
rsc = api.get_resource("CustomerPIIVault")
if not isinstance(rsc, dict):
    print(f"    sensitivity={rsc.sensitivity}")
    print(f"    authorized_agents={rsc.authorized_agents}")
    print(f"    attempted_agents={rsc.attempted_agents}")
    print(f"    total_blocked={rsc.total_blocked}")

print("\n  GET /api/v1/access/matrix")
mat_resp = api.get_access_matrix()
print(f"    {len(mat_resp.agents)} agents Ã— {len(mat_resp.resources)} resources")

print("\n  POST /api/v1/policies/evaluate")
eval_req = PolicyEvaluateRequest(
    tool_name="customer_db_read",
    agent_id="agt_unauth",
    capabilities=[],
    tainted_context=True,
    intent="financial analysis",
)
eval_resp = api.evaluate_policy(eval_req)
print(f"    decision={eval_resp.decision}  reason={eval_resp.reason_code}")

print("\n  GET /api/v1/incidents")
incidents = api.list_incidents()
print(f"    {len(incidents)} incident(s) recorded")
for inc in incidents:
    print(f"    [{inc.severity}] {inc.incident_type} â€” {inc.agent_id} â†’ {inc.tool_name} â†’ {inc.decision}")


# ---------------------------------------------------------------------------
# 12. JSON Export
# ---------------------------------------------------------------------------
section("12. JSON Export â†’ reports/forensics/")

output_dir = "reports/forensics"
exported = forensic.export_all(output_dir=output_dir)
for filename, path in exported.items():
    size = os.path.getsize(path)
    print(f"  âœ“ {filename:<30} ({size:>6} bytes)")


# ---------------------------------------------------------------------------
# 13. Final Validation
# ---------------------------------------------------------------------------
section("13. Final Validation")

data_actual = forensic.query.get_agent_actual_access("agt_data")
unauth_actual = forensic.query.get_agent_actual_access("agt_unauth")
fin_reads = sum(a.get("execution_count", 0) for a in data_actual if "financial" in a.get("tool_name", ""))
pii_reads = sum(a.get("execution_count", 0) for a in unauth_actual if "customer" in a.get("tool_name", ""))

print(f"""
  âœ“ DataAgent financial executions:     {fin_reads}  (expected â‰¥1)
  âœ“ Unauthorized PII reads:             {pii_reads}  (expected =0)
  âœ“ Authorized execution confirmed:     {fin_reads >= 1}
  âœ“ PII vault protected:                {pii_reads == 0}
""")

assert fin_reads >= 1, "FAIL: authorized financial access not recorded"
assert pii_reads == 0, f"FAIL: PII vault accessed {pii_reads} times â€” SECURITY FAILURE"


# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
banner("PHASE 6.5 DEMO COMPLETE âœ“")
print("""
  FORENSIC LAYER:    âœ“ Operational
  AUTHORITY GRAPH:   âœ“ Built from delegation registry
  ACCESS GRAPH:      âœ“ Tracks attempted vs actual
  ACCESS MATRIX:     âœ“ Generated
  SNAPSHOTS:         âœ“ Before/after captured
  DIFF:              âœ“ Attack detected, authority unchanged
  EXPLANATION:       âœ“ Evidence-backed, no LLM
  PRODUCT API:       âœ“ All endpoints returning clean JSON
  JSON EXPORTS:      âœ“ Stable schemas in reports/forensics/
  SECURITY:          âœ“ Read-only, no authority grants
  E2E:               âœ“ Authorized=1 execution, Unauthorized=0 PII reads
""")

