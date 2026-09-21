"""
AgentGuard — Anthropic Provider
===============================
Security reasoning provider backed by Anthropic Claude models.
"""
from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Dict, Optional

from agentguard.providers.base import AnalysisResult, HealthReport, SecurityAIProvider

logger = logging.getLogger("agentguard.providers.anthropic")


class AnthropicProvider(SecurityAIProvider):
    """
    Anthropic Claude Security Reasoning Provider.
    Requires ANTHROPIC_API_KEY environment variable.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "claude-3-5-sonnet-20241022",
        timeout: float = 5.0,
    ) -> None:
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self.model = model or os.environ.get("ANTHROPIC_MODEL", "claude-3-5-sonnet-20241022")
        self.timeout = timeout
        self._client = None

    @property
    def provider_name(self) -> str:
        return "anthropic"

    @property
    def model_name(self) -> str:
        return self.model

    @property
    def is_available(self) -> bool:
        return bool(self.api_key)

    def _get_client(self):
        if not self.is_available:
            return None
        if self._client is None:
            try:
                import anthropic
                self._client = anthropic.Anthropic(api_key=self.api_key, timeout=self.timeout)
            except ImportError:
                logger.debug("anthropic python package not installed")
                return None
            except Exception as e:
                logger.debug("Failed to init anthropic client: %s", e)
                return None
        return self._client

    def analyze(self, packet: Dict[str, Any]) -> Optional[AnalysisResult]:
        client = self._get_client()
        if not client:
            return None

        t0 = time.monotonic()
        system_prompt = (
            "You are AgentGuard AI Security Reasoning Engine. Analyze the security packet.\n"
            "Output ONLY a raw JSON object with keys: risk_score (0.0-1.0), threat_indicators (list of str), "
            "recommendations (list of str), confidence (0.0-1.0)."
        )
        try:
            response = client.messages.create(
                model=self.model,
                max_tokens=1024,
                system=system_prompt,
                messages=[
                    {"role": "user", "content": json.dumps(packet, default=str)},
                ],
            )
            latency = (time.monotonic() - t0) * 1000
            content = response.content[0].text if response.content else "{}"
            # Extract JSON block if wrapped in markdown
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0].strip()
            elif "```" in content:
                content = content.split("```")[1].split("```")[0].strip()
            
            data = json.loads(content)
            return AnalysisResult(
                risk_score=float(data.get("risk_score", 0.0)),
                threat_indicators=data.get("threat_indicators", []),
                recommendations=data.get("recommendations", []),
                provider_used=self.provider_name,
                model_used=self.model_name,
                latency_ms=latency,
                raw_response=content,
                confidence=float(data.get("confidence", 0.9)),
            )
        except Exception as exc:
            logger.warning("Anthropic analysis failed: %s", exc)
            return None

    def health_check(self) -> HealthReport:
        if not self.is_available:
            return HealthReport(
                available=False,
                provider_name=self.provider_name,
                model=self.model_name,
                error="ANTHROPIC_API_KEY environment variable not set",
            )
        client = self._get_client()
        if not client:
            return HealthReport(
                available=False,
                provider_name=self.provider_name,
                model=self.model_name,
                error="anthropic library not installed or client init failed",
            )
        t0 = time.monotonic()
        try:
            # Low latency lightweight ping
            client.messages.create(
                model=self.model,
                max_tokens=1,
                messages=[{"role": "user", "content": "ping"}],
            )
            latency = (time.monotonic() - t0) * 1000
            return HealthReport(
                available=True,
                provider_name=self.provider_name,
                model=self.model_name,
                latency_ms=latency,
            )
        except Exception as exc:
            return HealthReport(
                available=False,
                provider_name=self.provider_name,
                model=self.model_name,
                latency_ms=(time.monotonic() - t0) * 1000,
                error=str(exc),
            )
