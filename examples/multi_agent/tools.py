"""AgentGuard-protected tool implementations across sensitivity levels."""

from typing import Any, Callable, Dict, List, Optional
from agentguard.client import AgentGuard
from agentguard.tools.tool import Resource, SensitivityLevel
from examples.multi_agent.enterprise_data import EnterpriseFinancialWarehouse
from examples.multi_agent.mcp_server import MCPMode, SimulatedMCPServer


class EnterpriseToolSuite:
    """Encapsulates registered and protected enterprise tools bound to an AgentGuard instance."""

    def __init__(
        self,
        guard: AgentGuard,
        warehouse: EnterpriseFinancialWarehouse,
        mcp_server: SimulatedMCPServer,
    ) -> None:
        self.guard = guard
        self.warehouse = warehouse
        self.mcp_server = mcp_server

        # Define protected resources
        self.financial_resource = Resource(
            name="EnterpriseFinancialWarehouse",
            resource_type="database",
            uri="snowflake://acme.internal/financial_metrics",
            sensitivity=SensitivityLevel.HIGH,
            metadata={"data_class": "CONFIDENTIAL_FINANCIAL"},
        )

        self.customer_resource = Resource(
            name="CustomerPIIVault",
            resource_type="database",
            uri="postgres://customer-vault.internal/pii_records",
            sensitivity=SensitivityLevel.CRITICAL,
            metadata={"data_class": "RESTRICTED_CUSTOMER_PII"},
        )

        # 1. Public Search Tool (LOW sensitivity)
        @guard.protected_tool(
            name="public_search",
            description="Search public internet and news archives",
            sensitivity=SensitivityLevel.LOW,
            required_capabilities=["public_search"],
        )
        def public_search(query: str) -> Dict[str, Any]:
            return {
                "query": query,
                "status": "SUCCESS",
                "snippets": [
                    f"Public search results for '{query}' indicate solid industrial performance in 2026."
                ],
            }
        self.public_search = public_search

        # 2. Financial Document Search / MCP Search (MEDIUM sensitivity)
        @guard.protected_tool(
            name="financial_document_search",
            description="Retrieve public filings and SEC disclosures via external MCP service",
            sensitivity=SensitivityLevel.MEDIUM,
            required_capabilities=["public_documents"],
        )
        def financial_document_search(query: str, mode: MCPMode = MCPMode.BENIGN) -> Dict[str, Any]:
            return self.mcp_server.search_public_information(query=query, mode=mode)
        self.financial_document_search = financial_document_search

        # 3. Query Financial Metrics (HIGH sensitivity)
        @guard.protected_tool(
            name="query_financial_metrics",
            description="Extract enterprise financial metrics from confidential warehouse",
            sensitivity=SensitivityLevel.HIGH,
            required_capabilities=["financial_extract"],
            target_resources=[self.financial_resource],
        )
        def query_financial_metrics(company: str, fiscal_year: int, auth_token: str = "sk-live-internal-token") -> Dict[str, Any]:
            return self.warehouse.query_financial_metrics(company=company, fiscal_year=fiscal_year)
        self.query_financial_metrics = query_financial_metrics

        # 4. Read Customer Records (CRITICAL sensitivity)
        @guard.protected_tool(
            name="customer_db.read",
            description="Extract customer account PII and transaction records from customer vault",
            sensitivity=SensitivityLevel.CRITICAL,
            required_capabilities=["customer_db.read"],
            target_resources=[self.customer_resource],
        )
        def read_customer_records(limit: int = 10, filter_status: Optional[str] = None) -> List[Dict[str, Any]]:
            # CRITICAL PROTECTED FUNCTION: Never executed when blocked by AgentGuard!
            return self.warehouse.read_customer_records(limit=limit, filter_status=filter_status)
        self.read_customer_records = read_customer_records

        # 5. External API Call (MEDIUM sensitivity)
        @guard.protected_tool(
            name="external_api_call",
            description="Invoke third-party external partner API",
            sensitivity=SensitivityLevel.MEDIUM,
            required_capabilities=["external_api"],
        )
        def external_api_call(endpoint: str, payload: Dict[str, Any]) -> Dict[str, Any]:
            return {"status": "SUCCESS", "endpoint": endpoint, "processed": True}
        self.external_api_call = external_api_call

