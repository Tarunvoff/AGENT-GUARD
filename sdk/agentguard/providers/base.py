"""
AgentGuard Security AI Provider — Base Protocol
================================================
All AI intelligence providers must implement SecurityAIProvider.
The deterministic enforcement path (PolicyEvaluator) never depends on this.
If all providers fail, AgentGuard fails-safe to deterministic deny.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class AnalysisResult:
    """Structured result from an AI security intelligence provider."""
    risk_score: float                          # 0.0 – 1.0
    threat_indicators: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    provider_used: str = "unknown"
    model_used: str = "unknown"
    latency_ms: float = 0.0
    raw_response: Optional[str] = None
    analyzed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    confidence: float = 1.0                    # 0.0 – 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_high_risk(self) -> bool:
        return self.risk_score >= 0.7

    @property
    def is_critical(self) -> bool:
        return self.risk_score >= 0.9


@dataclass
class HealthReport:
    """Provider health status."""
    available: bool
    provider_name: str
    model: str = "unknown"
    latency_ms: float = 0.0
    error: Optional[str] = None
    checked_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def status_label(self) -> str:
        return "AVAILABLE" if self.available else "UNAVAILABLE"


class SecurityAIProvider(ABC):
    """
    Abstract base for all AgentGuard AI intelligence providers.

    Implementations must NOT affect the deterministic enforcement boundary.
    They provide advisory intelligence only — all block/allow decisions
    are made by the PolicyEvaluator using deterministic rules.
    """

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Human-readable provider name (e.g. 'ollama', 'openai', 'gemini')."""

    @property
    @abstractmethod
    def model_name(self) -> str:
        """Model identifier used by this provider."""

    @property
    @abstractmethod
    def is_available(self) -> bool:
        """
        Fast synchronous availability check (no network call).
        Returns False if the provider is not configured or dependencies missing.
        """

    @abstractmethod
    def analyze(self, packet: Dict[str, Any]) -> Optional[AnalysisResult]:
        """
        Run security intelligence analysis on a packet.

        Args:
            packet: A dict describing the security event/request context.

        Returns:
            AnalysisResult if successful, None if provider is unavailable or
            fails. Callers MUST treat None as non-blocking (fail-safe).
        """

    @abstractmethod
    def health_check(self) -> HealthReport:
        """
        Perform a full health check including a network/API call.
        Must never raise — always return HealthReport(available=False) on error.
        """

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} provider={self.provider_name!r} model={self.model_name!r}>"
