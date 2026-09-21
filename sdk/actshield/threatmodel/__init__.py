"""ActShield Threat Modeling Subsystem.

Provides a formal, structured threat modeling layer that sits above the
ActShield runtime enforcement engine.

Architecture:
    Threat Model
        ↓
    Assets + Actors + Boundaries
        ↓
    Threat Scenarios
        ↓
    Control Mapping
        ↓
    ActShield Enforcement Controls

Usage:
    from actshield.threatmodel import ThreatAnalyzer, ThreatReportRenderer

    analyzer = ThreatAnalyzer()
    result = analyzer.analyze()

    renderer = ThreatReportRenderer()
    renderer.render_analysis_report(result)
"""

from actshield.threatmodel.models import (
    ThreatModel,
    AnalysisResult,
    ThreatSeverity,
    ThreatCategory,
    ControlEffectiveness,
)
from actshield.threatmodel.assets import Asset, AssetSensitivity, AssetRegistry
from actshield.threatmodel.actors import ThreatActor, ActorType, ActorRegistry
from actshield.threatmodel.boundaries import TrustBoundary, BoundaryType, BoundaryRegistry
from actshield.threatmodel.threats import Threat, ThreatCatalog
from actshield.threatmodel.scenarios import AttackScenario, ScenarioStep
from actshield.threatmodel.mitigations import Mitigation, ControlMapping
from actshield.threatmodel.analyzer import ThreatAnalyzer
from actshield.threatmodel.scoring import ThreatScorer
from actshield.threatmodel.report import ThreatReportRenderer
from actshield.threatmodel.exporters import ThreatModelExporter

__all__ = [
    "ThreatModel",
    "AnalysisResult",
    "ThreatSeverity",
    "ThreatCategory",
    "ControlEffectiveness",
    "Asset",
    "AssetSensitivity",
    "AssetRegistry",
    "ThreatActor",
    "ActorType",
    "ActorRegistry",
    "TrustBoundary",
    "BoundaryType",
    "BoundaryRegistry",
    "Threat",
    "ThreatCatalog",
    "AttackScenario",
    "ScenarioStep",
    "Mitigation",
    "ControlMapping",
    "ThreatAnalyzer",
    "ThreatScorer",
    "ThreatReportRenderer",
    "ThreatModelExporter",
]
