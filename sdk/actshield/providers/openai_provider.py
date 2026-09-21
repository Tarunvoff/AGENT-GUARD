"""
ActShield — OpenAI Provider
============================
OpenAI-compatible security reasoning provider.
Supports GPT-4o, GPT-4o-mini, and compatible self-hosted OpenAI APIs.
"""
from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Dict, Optional

from actshield.providers.base import AnalysisResult, HealthReport, SecurityAIProvider

logger = logging.getLogger("actshield.providers.openai")


class OpenAIProvider(SecurityAIProvider):
    """
    OpenAI API Security Provider.
    Requires OPENAI_API_KEY environment variable.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "gpt-4o-mini",
        base_url: Optional[str] = None,
        timeout: float = 5.0,
    ) -> None:
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY")
        self.model = model or os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
        self.base_url = base_url or os.environ.get("OPENAI_BASE_URL")
        self.timeout = timeout
        self._client = None

    @property
    def provider_name(self) -> str:
        return "openai"

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
                import openai
                kwargs = {"api_key": self.api_key, "timeout": self.timeout}
                if self.base_url:
                    kwargs["base_url"] = self.base_url
                self._client = openai.OpenAI(**kwargs)
            except ImportError:
                logger.debug("openai python package not installed")
                return None
            except Exception as e:
                logger.debug("Failed to init openai client: %s", e)
                return None
        return self._client

    def analyze(self, packet: Dict[str, Any]) -> Optional[AnalysisResult]:
        client = self._get_client()
        if not client:
            return None

        t0 = time.monotonic()
        system_prompt = (
            "You are ActShield AI Security Reasoning Engine. Analyze the security packet.\n"
            "Output JSON with keys: risk_score (0.0-1.0), threat_indicators (list of str), "
            "recommendations (list of str), confidence (0.0-1.0)."
        )
        try:
            response = client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": json.dumps(packet, default=str)},
                ],
                response_format={"type": "json_object"},
                temperature=0.0,
            )
            latency = (time.monotonic() - t0) * 1000
            content = response.choices[0].message.content or "{}"
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
            logger.warning("OpenAI analysis failed: %s", exc)
            return None

    def health_check(self) -> HealthReport:
        if not self.is_available:
            return HealthReport(
                available=False,
                provider_name=self.provider_name,
                model=self.model_name,
                error="OPENAI_API_KEY environment variable not set",
            )
        client = self._get_client()
        if not client:
            return HealthReport(
                available=False,
                provider_name=self.provider_name,
                model=self.model_name,
                error="openai library not installed or client init failed",
            )
        t0 = time.monotonic()
        try:
            client.models.list()
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


