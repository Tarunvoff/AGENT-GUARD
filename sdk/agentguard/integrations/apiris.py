"""APIRIS API decision-intelligence and security framework adapter interface."""

from typing import Any, Dict, List, Optional, Protocol, runtime_checkable
from pydantic import BaseModel, Field

from agentguard.risk.models import RiskLevel, RiskSignal
from agentguard.tools.tool import ToolRequest


class APIAnalysis(BaseModel):
    """API & tool intelligence analysis returned by APIRIS."""
    analysis_id: str
    tool_id: str
    tool_name: str
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    anomaly_score: float = Field(default=0.0, ge=0.0, le=1.0)
    cve_indicators: List[str] = Field(default_factory=list)
    vendor_reputation: str = "TRUSTED"
    latency_ms_estimate: float = 50.0
    cost_estimate_usd: float = 0.0
    recommended_action: str = "ALLOW"
    signals: List[RiskSignal] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


@runtime_checkable
class APIIntelligence(Protocol):
    """Protocol for APIRIS API intelligence engine."""

    def analyze(self, request: ToolRequest) -> APIAnalysis:
        """Analyze tool request metadata, endpoint parameters, and reputation."""
        ...


class LocalAPIRISAdapter(APIIntelligence):
    """Local baseline APIRIS adapter for offline intelligence analysis."""

    def analyze(self, request: ToolRequest) -> APIAnalysis:
        import uuid
        analysis_id = f"apiris_{uuid.uuid4().hex[:12]}"
        
        signals: List[RiskSignal] = []
        cves: List[str] = []
        risk_score = 0.1
        rec_action = "ALLOW"

        # Check for dangerous arguments in tool request
        args_str = str(request.arguments).lower()
        if any(pat in args_str for pat in ("rm -rf", "drop table", "--exec", "cmd.exe", "eval(")):
            risk_score = 0.95
            rec_action = "BLOCK"
            signals.append(
                RiskSignal(
                    source="apiris",
                    risk_level=RiskLevel.CRITICAL,
                    score=0.95,
                    indicator="APIRIS_COMMAND_INJECTION_PATTERN",
                    details={"arguments": request.arguments},
                )
            )

        return APIAnalysis(
            analysis_id=analysis_id,
            tool_id=request.tool_id,
            tool_name=request.tool_name,
            risk_score=risk_score,
            anomaly_score=0.05,
            cve_indicators=cves,
            vendor_reputation="VERIFIED_INTERNAL" if not request.tool_name.startswith("external_") else "EXTERNAL_THIRD_PARTY",
            latency_ms_estimate=25.0,
            cost_estimate_usd=0.001,
            recommended_action=rec_action,
            signals=signals,
        )
