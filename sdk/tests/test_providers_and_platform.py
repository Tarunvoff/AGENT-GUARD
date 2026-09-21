"""
Unit tests for Provider Registry, Providers, and Platform CLI extensions.
"""
import unittest
from unittest.mock import MagicMock, patch

from agentguard.providers.base import AnalysisResult, HealthReport, SecurityAIProvider
from agentguard.providers.null_provider import NullProvider
from agentguard.providers.registry import ProviderRegistry, get_default_registry, reset_default_registry


class MockProvider(SecurityAIProvider):
    def __init__(self, name="mock", available=True, risk_score=0.2):
        self._name = name
        self._available = available
        self._risk_score = risk_score

    @property
    def provider_name(self) -> str:
        return self._name

    @property
    def model_name(self) -> str:
        return "mock-v1"

    @property
    def is_available(self) -> bool:
        return self._available

    def analyze(self, packet):
        if not self._available:
            return None
        return AnalysisResult(
            risk_score=self._risk_score,
            threat_indicators=["mock_indicator"],
            recommendations=["mock_rec"],
            provider_used=self._name,
            model_used=self.model_name,
        )

    def health_check(self) -> HealthReport:
        return HealthReport(
            available=self._available,
            provider_name=self._name,
            model=self.model_name,
        )


class TestProviderRegistry(unittest.TestCase):
    """Test provider registry and failover behavior."""

    def setUp(self):
        reset_default_registry()

    def test_null_provider_always_failsafe(self):
        null_p = NullProvider()
        self.assertFalse(null_p.is_available)
        self.assertIsNone(null_p.analyze({"test": 1}))
        report = null_p.health_check()
        self.assertFalse(report.available)

    def test_registry_failover_chain(self):
        reg = ProviderRegistry()
        p1 = MockProvider(name="failing", available=False)
        p2 = MockProvider(name="working", available=True, risk_score=0.45)
        null_p = NullProvider()

        reg.register(p1)
        reg.register(p2)
        reg.register(null_p)

        self.assertEqual(len(reg), 3)
        self.assertEqual(reg.get_active().provider_name, "working")

        # Test analysis failover
        res = reg.analyze({"action": "call_db"})
        self.assertIsNotNone(res)
        self.assertEqual(res.provider_used, "working")
        self.assertEqual(res.risk_score, 0.45)

    def test_registry_all_fail_returns_none(self):
        reg = ProviderRegistry()
        p1 = MockProvider(name="down1", available=False)
        p2 = MockProvider(name="down2", available=False)
        reg.register(p1)
        reg.register(p2)

        res = reg.analyze({"test": "data"})
        self.assertIsNone(res)  # Deterministic fail-safe


if __name__ == "__main__":
    unittest.main()
