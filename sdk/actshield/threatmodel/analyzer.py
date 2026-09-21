"""ThreatAnalyzer — orchestrates analysis of the full threat model."""
from __future__ import annotations

from typing import Optional

from actshield.threatmodel.assets import AssetRegistry
from actshield.threatmodel.actors import ActorRegistry
from actshield.threatmodel.boundaries import BoundaryRegistry
from actshield.threatmodel.threats import ThreatCatalog, Threat
from actshield.threatmodel.scenarios import get_builtin_scenarios
from actshield.threatmodel.mitigations import build_control_coverage_map, get_all_controls
from actshield.threatmodel.models import (
    ThreatModel,
    AnalysisResult,
    ThreatSeverity,
)
from actshield.threatmodel.scoring import ThreatScorer


class ThreatAnalyzer:
    """Main threat analysis engine.

    Aggregates assets, actors, boundaries, threats, and scenarios into
    a structured AnalysisResult that can be rendered or exported.
    """

    def __init__(
        self,
        system_name: str = "ActShield-Monitored Agent System",
        asset_registry: Optional[AssetRegistry] = None,
        actor_registry: Optional[ActorRegistry] = None,
        boundary_registry: Optional[BoundaryRegistry] = None,
        threat_catalog: Optional[ThreatCatalog] = None,
    ) -> None:
        self.system_name = system_name
        self.assets = asset_registry or AssetRegistry()
        self.actors = actor_registry or ActorRegistry()
        self.boundaries = boundary_registry or BoundaryRegistry()
        self.threats = threat_catalog or ThreatCatalog()
        self.scorer = ThreatScorer()

    def get_model(self) -> ThreatModel:
        """Return a summary ThreatModel snapshot."""
        all_threats = self.threats.all()
        all_scenarios = get_builtin_scenarios()
        return ThreatModel(
            system_name=self.system_name,
            asset_count=self.assets.count(),
            actor_count=self.actors.count(),
            boundary_count=self.boundaries.count(),
            threat_count=self.threats.count(),
            scenario_count=len(all_scenarios),
        )

    def get_threat(self, threat_id: str) -> Threat:
        threat = self.threats.get(threat_id)
        if threat is None:
            raise ValueError(f"Threat not found: {threat_id}")
        return threat

    def list_threats(self, severity_filter: Optional[str] = None) -> list[Threat]:
        all_threats = self.threats.all()
        if severity_filter:
            try:
                sev = ThreatSeverity(severity_filter.upper())
                return [t for t in all_threats if t.severity == sev]
            except ValueError:
                pass
        return all_threats

    def analyze(self) -> AnalysisResult:
        """Run the full threat analysis and return a structured result."""
        all_threats = self.threats.all()
        all_scenarios = get_builtin_scenarios()

        # Build model summary
        model = self.get_model()

        # Group threats by severity
        threats_by_severity: dict[str, list[dict]] = {s.value: [] for s in ThreatSeverity}
        for threat in all_threats:
            threats_by_severity[threat.severity.value].append(threat.to_dict())

        # Collect all control IDs referenced across all threats
        all_control_ids: list[str] = []
        for threat in all_threats:
            all_control_ids.extend(threat.actshield_controls)

        # Build coverage map
        control_coverage = build_control_coverage_map(all_control_ids)

        # Residual risks: threats where controls don't prevent
        from actshield.threatmodel.models import ControlEffectiveness
        residual_risks = [
            {
                "threat_id": t.threat_id,
                "name": t.name,
                "severity": t.severity.value,
                "residual_score": self.scorer.residual_score(t),
                "residual_risk": t.residual_risk,
                "control_effectiveness": t.control_effectiveness.value,
            }
            for t in all_threats
            if t.control_effectiveness not in (
                ControlEffectiveness.PREVENTS,
            )
        ]

        # Build attack paths from scenarios
        attack_paths = [
            {
                "scenario_id": s.scenario_id,
                "name": s.name,
                "severity": s.severity.value,
                "step_count": len(s.steps),
                "enforcement": s.actshield_enforcement,
                "threat_ids": s.threat_ids,
            }
            for s in all_scenarios
        ]

        overall_risk_score = self.scorer.overall_risk_score(all_threats)

        return AnalysisResult(
            model=model,
            threats_by_severity=threats_by_severity,
            control_coverage=control_coverage,
            residual_risks=residual_risks,
            attack_paths=attack_paths,
            overall_risk_score=overall_risk_score,
        )
