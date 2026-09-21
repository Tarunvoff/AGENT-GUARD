"""Offensive attack strategies package."""

from actshield.offensive.strategies.base import AttackStrategy
from actshield.offensive.strategies.prompt_injection import PromptInjectionStrategy
from actshield.offensive.strategies.authority_escalation import AuthorityEscalationStrategy
from actshield.offensive.strategies.tool_poisoning import ToolPoisoningStrategy
from actshield.offensive.strategies.context_manipulation import ContextManipulationStrategy
from actshield.offensive.strategies.mcp_attacks import MCPInjectionStrategy
from actshield.offensive.strategies.data_exfiltration import DataExfiltrationStrategy
from actshield.offensive.strategies.delegation_attacks import DelegationEscalationStrategy

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

