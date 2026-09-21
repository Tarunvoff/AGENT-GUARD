"""
AgentGuard — Ollama Provider
============================
Bridges local Ollama models (default: qwen2.5:7b) into the SecurityAIProvider interface.
"""
from __future__ import annotations

import logging
import os
import time
from typing import Any, Dict, Optional

from agentguard.llm_config import LLMConfig
from agentguard.providers.base import AnalysisResult, HealthReport, SecurityAIProvider

logger = logging.getLogger("agentguard.providers.ollama")


class OllamaProvider(SecurityAIProvider):
    """
    Local Ollama Security AI Provider.
    Calls a local Ollama instance without external internet dependencies.
    """

    def __init__(self, config: Optional[LLMConfig] = None) -> None:
        self.config = config or LLMConfig.from_env()
        self._adapter = None

    @property
    def provider_name(self) -> str:
        return "ollama"

    @property
    def model_name(self) -> str:
        return self.config.model or "qwen2.5:7b"

    @property
    def is_available(self) -> bool:
        if not getattr(self.config, "enabled", True):
            return False
        # Fast local ping if adapter exists
        adapter = self._get_adapter()
        if adapter and hasattr(adapter, "health_check"):
            try:
                res = adapter.health_check()
                return bool(res.get("available", False))
            except Exception:
                return False
        return False

    def _get_adapter(self):
        if self._adapter is None:
            try:
                from agentguard.integrations.ollama_adapter import OllamaAISecuraAdapter
                self._adapter = OllamaAISecuraAdapter(self.config)
            except Exception as e:
                logger.debug("Failed to initialize Ollama adapter: %s", e)
                return None
        return self._adapter

    def analyze(self, packet: Dict[str, Any]) -> Optional[AnalysisResult]:
        adapter = self._get_adapter()
        if not adapter:
            return None

        t0 = time.monotonic()
        try:
            # Check if packet has raw structured data or needs direct LLM analyze
            raw_analysis = adapter.analyze_raw_packet(packet) if hasattr(adapter, "analyze_raw_packet") else None
            
            # If standard adapter analysis
            if raw_analysis is None and hasattr(adapter, "analyze"):
                # Construct or use packet directly if mock/adapted
                pass

            latency = (time.monotonic() - t0) * 1000
            
            if raw_analysis:
                return AnalysisResult(
                    risk_score=float(raw_analysis.get("risk_score", 0.0)),
                    threat_indicators=raw_analysis.get("threat_indicators", []),
                    recommendations=raw_analysis.get("recommendations", []),
                    provider_used=self.provider_name,
                    model_used=self.model_name,
                    latency_ms=latency,
                    raw_response=raw_analysis.get("raw_response"),
                    confidence=float(raw_analysis.get("confidence", 0.9)),
                )
            
            # Simple fallback if packet was analyzed directly
            return AnalysisResult(
                risk_score=float(packet.get("risk_score", 0.1)),
                threat_indicators=packet.get("threat_indicators", []),
                recommendations=packet.get("recommendations", []),
                provider_used=self.provider_name,
                model_used=self.model_name,
                latency_ms=latency,
            )
        except Exception as exc:
            logger.warning("Ollama analysis failed: %s", exc)
            return None

    def health_check(self) -> HealthReport:
        t0 = time.monotonic()
        adapter = self._get_adapter()
        if not adapter:
            return HealthReport(
                available=False,
                provider_name=self.provider_name,
                model=self.model_name,
                error="Adapter not initialized",
            )

        try:
            health = adapter.health_check()
            latency = (time.monotonic() - t0) * 1000
            is_avail = bool(health.get("available", False))
            return HealthReport(
                available=is_avail,
                provider_name=self.provider_name,
                model=self.model_name,
                latency_ms=latency,
                error=health.get("error") if not is_avail else None,
                metadata=health,
            )
        except Exception as exc:
            return HealthReport(
                available=False,
                provider_name=self.provider_name,
                model=self.model_name,
                latency_ms=(time.monotonic() - t0) * 1000,
                error=str(exc),
            )
