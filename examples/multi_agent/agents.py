"""Multi-agent setup with distinct authority boundaries."""

from typing import Tuple
from agentguard.agents.agent import Agent
from agentguard.agents.identity import AgentTrustLevel
from agentguard.client import AgentGuard


def setup_agents(guard: AgentGuard) -> Tuple[Agent, Agent, Agent, Agent]:
    """Register the 4 enterprise simulation agents with explicit capability boundaries.
    
    Authority Hierarchy:
    - PlannerAgent: Can orchestrate research, documents, and financial analysis workflow, but has NO customer_db access.
    - ResearchAgent: Can query public information, documents, and extract public financial metrics.
    - AnalysisAgent: Can analyze financial information and extract financial metrics.
    - DataAgent: Can execute authorized financial extractions, and has dormant capability for customer DB
                 which is ONLY usable if explicitly delegated (never delegated in standard research workflows).
    
    Returns:
        Tuple of (planner, researcher, analyst, data_agent)
    """
    planner = guard.agent(
        name="PlannerAgent",
        framework="crewai",
        version="1.0.0",
        capabilities=["delegate_research", "public_search", "public_documents", "financial_extract", "report_generation", "external_api"],
        trust_level=AgentTrustLevel.HIGH,
        metadata={"role": "Orchestrator", "department": "Enterprise AI Systems"},
    )

    researcher = guard.agent(
        name="ResearchAgent",
        framework="langchain",
        version="2.0.0",
        capabilities=["public_search", "public_documents", "financial_extract", "external_api"],
        trust_level=AgentTrustLevel.MEDIUM,
        metadata={"role": "External Researcher", "department": "Market Intel"},
    )


    analyst = guard.agent(
        name="AnalysisAgent",
        framework="autogen",
        version="1.5.0",
        capabilities=["financial_analysis", "financial_extract"],
        trust_level=AgentTrustLevel.MEDIUM,
        metadata={"role": "Financial Analyst", "department": "Finance"},
    )

    data_agent = guard.agent(
        name="DataAgent",
        framework="custom",
        version="1.0.0",
        capabilities=["financial_extract", "customer_db.read"],
        trust_level=AgentTrustLevel.MEDIUM,
        metadata={"role": "Database Gateway", "department": "Data Platform"},
    )

    return planner, researcher, analyst, data_agent
