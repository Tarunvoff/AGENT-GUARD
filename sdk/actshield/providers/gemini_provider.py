"""
ActShield — Google Gemini Provider
===================================
Security reasoning provider backed by Google Gemini models.
"""
from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Dict, Optional

from actshield.providers.base import AnalysisResult, HealthReport, SecurityAIProvider

logger = logging.getLogger("actshield.providers.gemini")


class GeminiProvider(SecurityAIProvider):
    """
    Google Gemini Security Reasoning Provider.
    Requires GOOGLE_API_KEY or GEMINI_API_KEY environment variable.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "gemini-1.5-flash",
    ) -> None:
        self.api_key = api_key or os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY")
        self.model = model or os.environ.get("GEMINI_MODEL", "gemini-1.5-flash")
        self._client = None

    @property
    def provider_name(self) -> str:
        return "gemini"

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
                import google.generativeai as genai
                genai.configure(api_key=self.api_key)
                self._client = genai.GenerativeModel(self.model)
            except ImportError:
                logger.debug("google-generativeai python package not installed")
                return None
            except Exception as e:
                logger.debug("Failed to init gemini model: %s", e)
                return None
        return self._client

    def analyze(self, packet: Dict[str, Any]) -> Optional[AnalysisResult]:
        client = self._get_client()
        if not client:
            return None

        t0 = time.monotonic()
        system_instruction = (
            "Analyze the given security packet for multi-agent AI risks. "
            "Output JSON object with keys: risk_score (0.0-1.0), threat_indicators (list of str), "
            "recommendations (list of str), confidence (0.0-1.0)."
        )
        prompt = f"{system_instruction}\n\nSecurity Packet:\n{json.dumps(packet, default=str)}"
        try:
            response = client.generate_content(
                prompt,
                generation_config={"response_mime_type": "application/json"}
            )
            latency = (time.monotonic() - t0) * 1000
            content = response.text or "{}"
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
            logger.warning("Gemini analysis failed: %s", exc)
            return None

    def health_check(self) -> HealthReport:
        if not self.is_available:
            return HealthReport(
                available=False,
                provider_name=self.provider_name,
                model=self.model_name,
                error="GOOGLE_API_KEY environment variable not set",
            )
        client = self._get_client()
        if not client:
            return HealthReport(
                available=False,
                provider_name=self.provider_name,
                model=self.model_name,
                error="google-generativeai library not installed or client init failed",
            )
        t0 = time.monotonic()
        try:
            # Quick lightweight generation or model check
            import google.generativeai as genai
            genai.get_model(f"models/{self.model}")
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


