"""
AgentGuard Provider Registry
=============================
Ordered failover chain of SecurityAIProviders.
The enforcement layer (PolicyEvaluator) NEVER calls this — it always
runs deterministic rules regardless of AI availability.
"""
from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional

from agentguard.providers.base import AnalysisResult, HealthReport, SecurityAIProvider

logger = logging.getLogger(__name__)


class ProviderRegistry:
    """
    Registry of SecurityAIProviders with ordered failover.

    Usage:
        registry = ProviderRegistry()
        registry.register(OllamaProvider())
        registry.register(OpenAIProvider())
        registry.register(NullProvider())   # Always last as sentinel

        result = registry.analyze(packet)   # None = fail-safe deny advisory
    """

    def __init__(self) -> None:
        self._providers: List[SecurityAIProvider] = []

    def register(self, provider: SecurityAIProvider, *, position: Optional[int] = None) -> None:
        """Register a provider. Appends to end unless position specified."""
        if position is not None:
            self._providers.insert(position, provider)
        else:
            self._providers.append(provider)
        logger.debug("Registered provider: %s", provider.provider_name)

    def unregister(self, provider_name: str) -> bool:
        """Remove provider by name. Returns True if found and removed."""
        before = len(self._providers)
        self._providers = [p for p in self._providers if p.provider_name != provider_name]
        return len(self._providers) < before

    @property
    def providers(self) -> List[SecurityAIProvider]:
        return list(self._providers)

    def get_provider(self, name: str) -> Optional[SecurityAIProvider]:
        for p in self._providers:
            if p.provider_name == name:
                return p
        return None

    def get_active(self) -> Optional[SecurityAIProvider]:
        """Return the first available provider, or None."""
        for p in self._providers:
            if p.is_available:
                return p
        return None

    def get_active_provider(self) -> SecurityAIProvider:
        """Return active provider or NullProvider."""
        active = self.get_active()
        if active:
            return active
        from agentguard.providers.null_provider import NullProvider
        return NullProvider()

    def set_active_provider(self, name: str) -> None:
        """Move named provider to top of priority chain."""
        norm_name = name.lower().replace("-", "_")
        found = None
        for p in self._providers:
            if p.provider_name.lower().replace("-", "_") == norm_name:
                found = p
                break
        if not found:
            raise ValueError(f"Provider '{name}' not found in registry.")
        self._providers.remove(found)
        self._providers.insert(0, found)

    def list_providers(self) -> List[Dict[str, Any]]:
        """List all registered providers with status."""
        active = self.get_active_provider()
        res = []
        for p in self._providers:
            is_act = p.provider_name == active.provider_name
            res.append({
                "name": p.provider_name,
                "provider_type": getattr(p, "provider_type", "llm"),
                "is_healthy": p.is_available,
                "is_active": is_act,
            })
        return res

    def analyze(self, packet: Dict[str, Any]) -> Optional[AnalysisResult]:
        """
        Try each provider in order. Returns first successful AnalysisResult.
        Returns None if all providers fail — callers treat this as fail-safe.
        """
        for provider in self._providers:
            if not provider.is_available:
                logger.debug("Provider %s not available, skipping", provider.provider_name)
                continue
            try:
                t0 = time.monotonic()
                result = provider.analyze(packet)
                if result is not None:
                    result.latency_ms = (time.monotonic() - t0) * 1000
                    result.provider_used = provider.provider_name
                    logger.debug(
                        "Provider %s returned risk_score=%.2f in %.1fms",
                        provider.provider_name, result.risk_score, result.latency_ms,
                    )
                    return result
            except Exception as exc:  # noqa: BLE001
                logger.warning("Provider %s raised: %s", provider.provider_name, exc)
                continue
        logger.warning("All providers failed or unavailable — returning None (fail-safe)")
        return None

    def health_check_all(self) -> List[HealthReport]:
        """Run health check on every registered provider."""
        reports = []
        for provider in self._providers:
            try:
                report = provider.health_check()
            except Exception as exc:  # noqa: BLE001
                from agentguard.providers.base import HealthReport
                report = HealthReport(
                    available=False,
                    provider_name=provider.provider_name,
                    error=str(exc),
                )
            reports.append(report)
        return reports

    def benchmark(self, packet: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Run analysis on all available providers and return latency stats."""
        results = []
        for provider in self._providers:
            if not provider.is_available:
                results.append({"provider": provider.provider_name, "available": False})
                continue
            t0 = time.monotonic()
            try:
                result = provider.analyze(packet)
                latency = (time.monotonic() - t0) * 1000
                results.append({
                    "provider": provider.provider_name,
                    "available": True,
                    "success": result is not None,
                    "latency_ms": round(latency, 1),
                    "risk_score": result.risk_score if result else None,
                })
            except Exception as exc:  # noqa: BLE001
                results.append({
                    "provider": provider.provider_name,
                    "available": True,
                    "success": False,
                    "error": str(exc),
                })
        return results

    def __len__(self) -> int:
        return len(self._providers)

    def __repr__(self) -> str:
        names = [p.provider_name for p in self._providers]
        return f"<ProviderRegistry providers={names}>"


# ---------------------------------------------------------------------------
# Default global registry — populated lazily from environment
# ---------------------------------------------------------------------------

_default_registry: Optional[ProviderRegistry] = None


def _build_default_registry() -> ProviderRegistry:
    """Build the default registry by inspecting environment variables."""
    from agentguard.providers.null_provider import NullProvider

    registry = ProviderRegistry()

    # Ollama — try first (local, no API key needed)
    try:
        from agentguard.providers.ollama_provider import OllamaProvider
        registry.register(OllamaProvider())
    except Exception:  # noqa: BLE001
        pass

    # OpenAI — if OPENAI_API_KEY is set
    try:
        from agentguard.providers.openai_provider import OpenAIProvider
        registry.register(OpenAIProvider())
    except Exception:  # noqa: BLE001
        pass

    # Gemini — if GOOGLE_API_KEY is set
    try:
        from agentguard.providers.gemini_provider import GeminiProvider
        registry.register(GeminiProvider())
    except Exception:  # noqa: BLE001
        pass

    # Anthropic — if ANTHROPIC_API_KEY is set
    try:
        from agentguard.providers.anthropic_provider import AnthropicProvider
        registry.register(AnthropicProvider())
    except Exception:  # noqa: BLE001
        pass

    # Null sentinel — always last
    registry.register(NullProvider())
    return registry


def get_default_registry() -> ProviderRegistry:
    """Return (and lazily build) the process-global provider registry."""
    global _default_registry
    if _default_registry is None:
        _default_registry = _build_default_registry()
    return _default_registry


def reset_default_registry() -> None:
    """Reset the default registry (useful in tests)."""
    global _default_registry
    _default_registry = None


# Alias for clean public SDK naming
get_provider_registry = get_default_registry

