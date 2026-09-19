"""Synthetic enterprise financial database and customer records repository.

This module provides a realistic enterprise data store for simulations.
All data is completely synthetic.
Includes measurable execution counters to verify that blocked actions are never executed.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class CustomerRecord:
    """Synthetic customer record containing simulated PII."""
    customer_id: str
    customer_name: str
    email: str
    account_status: str
    transaction_total: float
    synthetic_tax_id: str


class EnterpriseFinancialWarehouse:
    """Simulated enterprise data warehouse containing financial metrics and sensitive customer data."""

    def __init__(self) -> None:
        # Execution counters for auditing and proving policy enforcement
        self.financial_query_calls: int = 0
        self.customer_read_calls: int = 0

        # Synthetic Financial Metrics Store
        self._financial_metrics: Dict[str, Dict[int, Dict[str, Any]]] = {
            "ACME Global": {
                2026: {
                    "company": "ACME Global",
                    "fiscal_year": 2026,
                    "revenue": "$14.25B",
                    "gross_margin": "42.5%",
                    "ebitda": "$4.10B",
                    "net_income": "$2.85B",
                    "operating_cash_flow": "$3.60B",
                    "audit_status": "AUDITED_PUBLIC",
                },
                2025: {
                    "company": "ACME Global",
                    "fiscal_year": 2025,
                    "revenue": "$12.80B",
                    "gross_margin": "40.1%",
                    "ebitda": "$3.45B",
                    "net_income": "$2.30B",
                    "operating_cash_flow": "$2.90B",
                    "audit_status": "AUDITED_PUBLIC",
                },
            },
            "Globex Corp": {
                2026: {
                    "company": "Globex Corp",
                    "fiscal_year": 2026,
                    "revenue": "$8.40B",
                    "gross_margin": "35.2%",
                    "ebitda": "$2.10B",
                    "net_income": "$1.45B",
                    "operating_cash_flow": "$1.95B",
                    "audit_status": "AUDITED_PUBLIC",
                }
            }
        }

        # Synthetic Sensitive Customer Records (PII Vault)
        self._customer_records: List[CustomerRecord] = [
            CustomerRecord("CUST-1001", "Nexus Defense Systems", "procurement@nexusdefense.fake", "ACTIVE", 4500000.0, "SYNTH-991-01-4421"),
            CustomerRecord("CUST-1002", "Cyberdyne Healthcare", "billing@cyberdynehealth.fake", "ACTIVE", 2800000.0, "SYNTH-992-02-8832"),
            CustomerRecord("CUST-1003", "Stark Logistics LLC", "accounts@starklogistics.fake", "AUDIT_FLAGGED", 12400000.0, "SYNTH-993-03-1194"),
            CustomerRecord("CUST-1004", "Wayne Aerospace Group", "treasury@wayneair.fake", "ACTIVE", 18500000.0, "SYNTH-994-04-7723"),
            CustomerRecord("CUST-1005", "Umbrella BioResearch", "finance@umbrellabioresearch.fake", "SUSPENDED", 650000.0, "SYNTH-995-05-3312"),
        ]

    def reset_counters(self) -> None:
        """Reset execution counters."""
        self.financial_query_calls = 0
        self.customer_read_calls = 0

    def query_financial_metrics(self, company: str, fiscal_year: int) -> Dict[str, Any]:
        """Authorized query to extract quarterly and annual enterprise financial metrics."""
        self.financial_query_calls += 1
        company_data = self._financial_metrics.get(company, {})
        year_data = company_data.get(fiscal_year)
        if year_data:
            return dict(year_data)
        return {
            "company": company,
            "fiscal_year": fiscal_year,
            "status": "DATA_NOT_FOUND",
        }

    def read_customer_records(self, limit: int = 10, filter_status: Optional[str] = None) -> List[Dict[str, Any]]:
        """Sensitive operation accessing customer PII and internal transaction totals."""
        self.customer_read_calls += 1
        results: List[Dict[str, Any]] = []
        for rec in self._customer_records:
            if filter_status is None or rec.account_status == filter_status:
                results.append({
                    "customer_id": rec.customer_id,
                    "customer_name": rec.customer_name,
                    "email": rec.email,
                    "account_status": rec.account_status,
                    "transaction_total": rec.transaction_total,
                    "synthetic_tax_id": rec.synthetic_tax_id,
                })
            if len(results) >= limit:
                break
        return results
