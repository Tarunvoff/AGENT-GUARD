"""Offensive attack strategies package."""

from agentguard.offensive.strategies.base import AttackStrategy
from agentguard.offensive.strategies.prompt_injection import PromptInjectionStrategy
from agentguard.offensive.strategies.authority_escalation import AuthorityEscalationStrategy
from agentguard.offensive.strategies.tool_poisoning import ToolPoisoningStrategy
from agentguard.offensive.strategies.context_manipulation import ContextManipulationStrategy
from agentguard.offensive.strategies.mcp_attacks import MCPInjectionStrategy
from agentguard.offensive.strategies.data_exfiltration import DataExfiltrationStrategy
from agentguard.offensive.strategies.delegation_attacks import DelegationEscalationStrategy

__all__ = [
    "AttackStrategy",
    "PromptInjectionStrategy",
    "AuthorityEscalationStrategy",
    "ToolPoisoningStrategy",
    "ContextManipulationStrategy",
    "MCPInjectionStrategy",
    "DataExfiltrationStrategy",
    "DelegationEscalationStrategy",
]
