"""ActShield — NullProvider (fail-safe sentinel)."""
from __future__ import annotations

import time
from typing import Any, Dict, Optional

from actshield.providers.base import AnalysisResult, HealthReport, SecurityAIProvider


class NullProvider(SecurityAIProvider):
    """
    Fail-safe sentinel provider. Always reports unavailable.
    Registered last in the default registry so that analyze() returns None
    when all real providers are unreachable — triggering deterministic deny.
    """

    @property
    def provider_name(self) -> str:
        return "null"

    @property
    def model_name(self) -> str:
        return "none"

    @property
    def is_available(self) -> bool:
        return False

    def analyze(self, packet: Dict[str, Any]) -> Optional[AnalysisResult]:
        return None

    def health_check(self) -> HealthReport:
        return HealthReport(
            available=False,
            provider_name=self.provider_name,
            model="none",
            error="NullProvider — no AI backend configured",
        )


