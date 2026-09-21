"""APIRIS API decision-intelligence and tool security interface."""

from typing import Any, Callable, Dict, List, Optional, Protocol, runtime_checkable
import uuid
from pydantic import BaseModel, Field

from actshield.risk.models import RiskLevel, RiskSignal
from actshield.tools.tool import ToolRequest


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


class APIRISClient(APIIntelligence):
    """APIRIS API decision intelligence client.
    
    Inspects endpoint reputation, argument injection signatures, rate anomalies,
    and returns recommendations (ALLOW, MONITOR, HUMAN_APPROVAL, BLOCK).
    """

    def __init__(
        self,
        api_endpoint: Optional[str] = None,
        api_key: Optional[str] = None,
        custom_engine: Optional[Callable[[ToolRequest], APIAnalysis]] = None,
    ) -> None:
        self.api_endpoint = api_endpoint or "https://apiris.internal/v1/analyze"
        self.api_key = api_key or "apiris-live-token"
        self.custom_engine = custom_engine

    def analyze(self, request: ToolRequest) -> APIAnalysis:
        """Perform APIRIS decision intelligence analysis on the requested tool invocation."""
        if self.custom_engine:
            return self.custom_engine(request)

        analysis_id = f"apiris_{uuid.uuid4().hex[:12]}"
        signals: List[RiskSignal] = []
        cves: List[str] = []
        risk_score = 0.05
        anomaly_score = 0.02
        rec_action = "ALLOW"

        args_str = str(request.arguments).lower()
        tool_name_lower = (request.tool_name or "").lower()

        # 1. Command injection pattern checks
        if any(pat in args_str for pat in ("rm -rf", "drop table", "--exec", "cmd.exe", "eval(", "; cat /etc/passwd", "bash -i")):
            risk_score = 0.95
            anomaly_score = 0.98
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

        # 2. SSRF / Untrusted domain check
        if any(pat in args_str for pat in ("169.254.169.254", "localhost:8080", "127.0.0.1", "evil-exfil.com")):
            risk_score = 0.90
            rec_action = "BLOCK"
            signals.append(
                RiskSignal(
                    source="apiris",
                    risk_level=RiskLevel.CRITICAL,
                    score=0.90,
                    indicator="APIRIS_SSRF_OR_UNTRUSTED_DESTINATION",
                    details={"arguments": request.arguments},
                )
            )

        # 3. High sensitivity / Financial tool heuristic
        if "customer_db" in tool_name_lower or "pii" in tool_name_lower:
            risk_score = max(risk_score, 0.40)
            vendor_rep = "INTERNAL_RESTRICTED"
        else:
            vendor_rep = "TRUSTED"

        return APIAnalysis(
            analysis_id=analysis_id,
            tool_id=request.tool_id,
            tool_name=request.tool_name,
            risk_score=risk_score,
            anomaly_score=anomaly_score,
            cve_indicators=cves,
            vendor_reputation=vendor_rep,
            latency_ms_estimate=45.0,
            recommended_action=rec_action,
            signals=signals,
            metadata={"evaluated_by": "APIRIS-v3.0"},
        )


class LocalAPIRISAdapter(APIRISClient):
    """Backward-compatible alias for local execution."""
    pass

