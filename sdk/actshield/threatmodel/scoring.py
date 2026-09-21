"""Threat severity scoring — CVSS-inspired scoring for agent system threats."""
from __future__ import annotations

from actshield.threatmodel.models import ThreatSeverity, ControlEffectiveness
from actshield.threatmodel.threats import Threat


# Base scores by severity (maps to CVSS base score ranges)
_SEVERITY_BASE: dict[ThreatSeverity, float] = {
    ThreatSeverity.CRITICAL: 9.0,
    ThreatSeverity.HIGH: 7.5,
    ThreatSeverity.MEDIUM: 5.0,
    ThreatSeverity.LOW: 2.5,
    ThreatSeverity.INFORMATIONAL: 0.5,
}

# Control effectiveness modifiers (reduce residual risk)
_EFFECTIVENESS_MODIFIER: dict[ControlEffectiveness, float] = {
    ControlEffectiveness.PREVENTS: 0.1,   # 90% reduction
    ControlEffectiveness.DETECTS: 0.5,    # 50% reduction
    ControlEffectiveness.REDUCES: 0.6,    # 40% reduction
    ControlEffectiveness.MONITORS: 0.8,   # 20% reduction
    ControlEffectiveness.NONE: 1.0,       # No reduction
}


class ThreatScorer:
    """Computes risk scores for threats."""

    def base_score(self, threat: Threat) -> float:
        """Return the inherent base risk score (0-10)."""
        return _SEVERITY_BASE.get(threat.severity, 5.0)

    def residual_score(self, threat: Threat) -> float:
        """Return the residual risk score after ActShield controls are applied."""
        base = self.base_score(threat)
        modifier = _EFFECTIVENESS_MODIFIER.get(
            threat.control_effectiveness, 1.0
        )
        return round(base * modifier, 2)

    def overall_risk_score(self, threats: list[Threat]) -> float:
        """Aggregate risk score for the full threat model (0-10 scale)."""
        if not threats:
            return 0.0
        residuals = [self.residual_score(t) for t in threats]
        # Weighted by severity — critical threats dominate
        weights = [_SEVERITY_BASE.get(t.severity, 5.0) for t in threats]
        total_weight = sum(weights)
        if total_weight == 0:
            return 0.0
        weighted_sum = sum(r * w for r, w in zip(residuals, weights))
        return round(weighted_sum / total_weight, 2)

    def severity_counts(self, threats: list[Threat]) -> dict[str, int]:
        counts: dict[str, int] = {s.value: 0 for s in ThreatSeverity}
        for t in threats:
            counts[t.severity.value] += 1
        return counts

    def coverage_percentage(self, threats: list[Threat]) -> float:
        """Percentage of threats with at least one ActShield control."""
        if not threats:
            return 100.0
        covered = sum(1 for t in threats if t.actshield_controls)
        return round((covered / len(threats)) * 100, 1)
