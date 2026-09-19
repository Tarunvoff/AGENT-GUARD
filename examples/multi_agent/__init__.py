"""Multi-agent enterprise simulation package."""

from examples.multi_agent.agents import setup_agents
from examples.multi_agent.attack_scenario import (
    AttackResult,
    run_attack_scenario,
    run_authority_impersonation_attack,
    run_direct_escalation_attack,
    run_indirect_prompt_injection_attack,
    run_multihop_toolchain_attack,
    run_semantic_escalation_attack,
)
from examples.multi_agent.authorized_scenario import (
    AuthorizedScenarioResult,
    run_authorized_customer_audit_scenario,
)
from examples.multi_agent.benign_scenario import BenignScenarioResult, run_benign_scenario
from examples.multi_agent.enterprise_data import EnterpriseFinancialWarehouse
from examples.multi_agent.mcp_server import MCPMode, SimulatedMCPServer
from examples.multi_agent.tools import EnterpriseToolSuite

__all__ = [
    "EnterpriseFinancialWarehouse",
    "SimulatedMCPServer",
    "MCPMode",
    "setup_agents",
    "EnterpriseToolSuite",
    "run_benign_scenario",
    "BenignScenarioResult",
    "run_attack_scenario",
    "AttackResult",
    "run_authorized_customer_audit_scenario",
    "AuthorizedScenarioResult",
    "run_direct_escalation_attack",
    "run_indirect_prompt_injection_attack",
    "run_authority_impersonation_attack",
    "run_multihop_toolchain_attack",
    "run_semantic_escalation_attack",
]
