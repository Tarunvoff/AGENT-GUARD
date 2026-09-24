"""AgentGuard: Enterprise Security Control Plane for Autonomous and Multi-Agent AI Systems.

Quick start::

    from agentguard import AgentGuard, AgentIdentity, AgentTrustLevel

    guard = AgentGuard(enforcement_mode="STRICT")

    @guard.protect(tool="customer_db.read", sensitivity="critical")
    async def read_customer_data():
        ...

    # Threat modeling
    from agentguard.threatmodel import ThreatAnalyzer
    analyzer = ThreatAnalyzer()
    result = analyzer.analyze()
"""
from __future__ import annotations

import sys
import importlib
import actshield

# Inherit package path so submodules resolve directly
__path__ = list(actshield.__path__)

# Re-export core ActShield SDK components under canonical AgentGuard namespace
from actshield import *  # noqa: F401, F403
from actshield import __version__, __all__ as _actshield_all

# Backward/forward canonical naming aliases
AgentGuard = ActShield
AgentGuardConfig = ActShieldConfig

__all__ = list(_actshield_all)
if "AgentGuard" not in __all__:
    __all__.append("AgentGuard")
if "AgentGuardConfig" not in __all__:
    __all__.append("AgentGuardConfig")
