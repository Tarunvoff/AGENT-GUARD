"""Threat actors — who can attack the agent system and how."""
from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ActorType(str, Enum):
    """Classification of threat actor origin."""
    EXTERNAL_ATTACKER = "EXTERNAL_ATTACKER"
    MALICIOUS_USER = "MALICIOUS_USER"
    COMPROMISED_AGENT = "COMPROMISED_AGENT"
    MALICIOUS_MCP_SERVER = "MALICIOUS_MCP_SERVER"
    POISONED_DOCUMENT = "POISONED_DOCUMENT"
    POISONED_RAG_SOURCE = "POISONED_RAG_SOURCE"
    COMPROMISED_TOOL = "COMPROMISED_TOOL"
    SUPPLY_CHAIN_ATTACKER = "SUPPLY_CHAIN_ATTACKER"
    INSIDER_THREAT = "INSIDER_THREAT"
    PROMPT_INJECTOR = "PROMPT_INJECTOR"


class ActorCapability(str, Enum):
    """What the actor is capable of doing."""
    CRAFT_PROMPTS = "CRAFT_PROMPTS"
    INJECT_CONTEXT = "INJECT_CONTEXT"
    POISON_DOCUMENTS = "POISON_DOCUMENTS"
    INTERCEPT_RESPONSES = "INTERCEPT_RESPONSES"
    COMPROMISE_TOOLS = "COMPROMISE_TOOLS"
    IMPERSONATE_AGENT = "IMPERSONATE_AGENT"
    EXFILTRATE_DATA = "EXFILTRATE_DATA"
    ESCALATE_PRIVILEGES = "ESCALATE_PRIVILEGES"
    MANIPULATE_DELEGATION = "MANIPULATE_DELEGATION"


class ThreatActor(BaseModel):
    """A threat actor that can attack the agent system."""
    actor_id: str
    name: str
    actor_type: ActorType
    description: str
    capabilities: list[ActorCapability] = Field(default_factory=list)
    entry_points: list[str] = Field(default_factory=list)
    # MITRE ATT&CK-style sophistication: 1 (script kiddie) to 5 (nation-state)
    sophistication: int = 2
    # Is this actor already inside the trust boundary?
    is_internal: bool = False

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


class ActorRegistry:
    """Catalog of threat actors relevant to autonomous AI systems."""

    _DEFAULTS: list[dict[str, Any]] = [
        {
            "actor_id": "act_ext_attacker",
            "name": "External Attacker",
            "actor_type": ActorType.EXTERNAL_ATTACKER,
            "description": (
                "Adversary with no authenticated access who interacts with the "
                "agent system through public-facing interfaces or indirect channels."
            ),
            "capabilities": [
                ActorCapability.CRAFT_PROMPTS,
                ActorCapability.POISON_DOCUMENTS,
                ActorCapability.EXFILTRATE_DATA,
            ],
            "entry_points": ["public_api", "user_input", "web_content", "external_mcp"],
            "sophistication": 3,
            "is_internal": False,
        },
        {
            "actor_id": "act_mal_user",
            "name": "Malicious User",
            "actor_type": ActorType.MALICIOUS_USER,
            "description": (
                "Authenticated user who attempts to manipulate agent behavior "
                "to access resources beyond their authorization."
            ),
            "capabilities": [
                ActorCapability.CRAFT_PROMPTS,
                ActorCapability.ESCALATE_PRIVILEGES,
                ActorCapability.EXFILTRATE_DATA,
            ],
            "entry_points": ["user_input", "task_description", "file_upload"],
            "sophistication": 2,
            "is_internal": False,
        },
        {
            "actor_id": "act_compromised_agent",
            "name": "Compromised Agent",
            "actor_type": ActorType.COMPROMISED_AGENT,
            "description": (
                "A sub-agent that has been manipulated (via prompt injection or "
                "tool poisoning) to act outside its delegated authority."
            ),
            "capabilities": [
                ActorCapability.INJECT_CONTEXT,
                ActorCapability.ESCALATE_PRIVILEGES,
                ActorCapability.MANIPULATE_DELEGATION,
                ActorCapability.EXFILTRATE_DATA,
            ],
            "entry_points": ["sub_agent_context", "delegation_chain", "tool_response"],
            "sophistication": 4,
            "is_internal": True,
        },
        {
            "actor_id": "act_mal_mcp",
            "name": "Malicious MCP Server",
            "actor_type": ActorType.MALICIOUS_MCP_SERVER,
            "description": (
                "An external MCP server that returns crafted responses designed "
                "to inject malicious instructions into the agent context."
            ),
            "capabilities": [
                ActorCapability.INJECT_CONTEXT,
                ActorCapability.POISON_DOCUMENTS,
                ActorCapability.INTERCEPT_RESPONSES,
            ],
            "entry_points": ["mcp_response", "external_api_response", "tool_output"],
            "sophistication": 4,
            "is_internal": False,
        },
        {
            "actor_id": "act_poisoned_doc",
            "name": "Poisoned Document",
            "actor_type": ActorType.POISONED_DOCUMENT,
            "description": (
                "A document (web page, PDF, email) that contains embedded "
                "instructions targeting an agent that will process it."
            ),
            "capabilities": [
                ActorCapability.CRAFT_PROMPTS,
                ActorCapability.INJECT_CONTEXT,
            ],
            "entry_points": ["web_content", "file_system", "email", "rag_source"],
            "sophistication": 1,
            "is_internal": False,
        },
        {
            "actor_id": "act_poisoned_rag",
            "name": "Poisoned RAG Source",
            "actor_type": ActorType.POISONED_RAG_SOURCE,
            "description": (
                "A vector database or document store that has been poisoned "
                "with adversarial content designed to influence agent reasoning."
            ),
            "capabilities": [
                ActorCapability.INJECT_CONTEXT,
                ActorCapability.POISON_DOCUMENTS,
            ],
            "entry_points": ["rag_retrieval", "vector_db_query", "knowledge_base"],
            "sophistication": 3,
            "is_internal": False,
        },
        {
            "actor_id": "act_supply_chain",
            "name": "Supply Chain Attacker",
            "actor_type": ActorType.SUPPLY_CHAIN_ATTACKER,
            "description": (
                "Attacker who compromises a dependency, tool, or external service "
                "used by the agent system."
            ),
            "capabilities": [
                ActorCapability.COMPROMISE_TOOLS,
                ActorCapability.INTERCEPT_RESPONSES,
                ActorCapability.EXFILTRATE_DATA,
            ],
            "entry_points": ["package_dependency", "external_service", "third_party_api"],
            "sophistication": 5,
            "is_internal": False,
        },
        {
            "actor_id": "act_insider",
            "name": "Insider Threat",
            "actor_type": ActorType.INSIDER_THREAT,
            "description": (
                "A trusted internal actor (employee, contractor) who misuses "
                "legitimate access to agent capabilities or data."
            ),
            "capabilities": [
                ActorCapability.ESCALATE_PRIVILEGES,
                ActorCapability.EXFILTRATE_DATA,
                ActorCapability.MANIPULATE_DELEGATION,
            ],
            "entry_points": ["authenticated_api", "admin_interface", "direct_db_access"],
            "sophistication": 3,
            "is_internal": True,
        },
    ]

    def __init__(self) -> None:
        self._actors: dict[str, ThreatActor] = {
            d["actor_id"]: ThreatActor(**d) for d in self._DEFAULTS
        }

    def register(self, actor: ThreatActor) -> None:
        self._actors[actor.actor_id] = actor

    def get(self, actor_id: str) -> ThreatActor | None:
        return self._actors.get(actor_id)

    def all(self) -> list[ThreatActor]:
        return list(self._actors.values())

    def count(self) -> int:
        return len(self._actors)
