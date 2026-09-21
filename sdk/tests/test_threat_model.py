"""Unit tests for the ActShield Threat Modeling Subsystem."""

import json
import pytest

from actshield.threatmodel import (
    ActorRegistry,
    ActorType,
    AnalysisResult,
    Asset,
    AssetRegistry,
    AssetSensitivity,
    AttackScenario,
    BoundaryRegistry,
    BoundaryType,
    ControlEffectiveness,
    ControlMapping,
    Mitigation,
    ScenarioStep,
    Threat,
    ThreatActor,
    ThreatAnalyzer,
    ThreatCatalog,
    ThreatCategory,
    ThreatModel,
    ThreatModelExporter,
    ThreatReportRenderer,
    ThreatScorer,
    ThreatSeverity,
)
from actshield.threatmodel.scenarios import get_builtin_scenarios


def test_asset_registry():
    registry = AssetRegistry()
    assert registry.count() >= 5
    assets = registry.all()
    assert any(a.asset_id == "ast_creds" for a in assets)
    
    # Custom asset registration
    custom = Asset(
        asset_id="ast_custom_vault",
        name="Custom Data Vault",
        sensitivity=AssetSensitivity.CRITICAL,
        description="Encrypted customer records",
    )
    registry.register(custom)
    assert registry.get("ast_custom_vault") is not None
    assert registry.get("ast_custom_vault").name == "Custom Data Vault"


def test_actor_registry():
    registry = ActorRegistry()
    assert registry.count() >= 4
    actors = registry.all()
    assert any(a.actor_type == ActorType.EXTERNAL_ATTACKER for a in actors)
    assert any(a.actor_type == ActorType.MALICIOUS_MCP_SERVER for a in actors)
    
    actor = registry.get("act_compromised_agent")
    assert actor is not None
    assert actor.actor_type == ActorType.COMPROMISED_AGENT


def test_boundary_registry():
    registry = BoundaryRegistry()
    assert registry.count() >= 4
    boundaries = registry.all()
    assert any(b.boundary_type == BoundaryType.TRUST for b in boundaries)
    assert any(b.boundary_type == BoundaryType.AUTHORITY for b in boundaries)


def test_threat_catalog():
    catalog = ThreatCatalog()
    assert catalog.count() >= 8
    all_threats = catalog.all()
    for t in all_threats:
        assert t.threat_id.startswith("thr_")
        assert t.severity in (ThreatSeverity.CRITICAL, ThreatSeverity.HIGH, ThreatSeverity.MEDIUM, ThreatSeverity.LOW)
        assert isinstance(t.category, ThreatCategory)


def test_threat_scorer():
    catalog = ThreatCatalog()
    scorer = ThreatScorer()
    all_threats = catalog.all()
    
    overall_score = scorer.overall_risk_score(all_threats)
    assert 0.0 <= overall_score <= 10.0
    
    for t in all_threats:
        base_score = scorer.base_score(t)
        res_score = scorer.residual_score(t)
        assert base_score >= res_score
        assert 0.0 <= res_score <= 10.0


def test_threat_analyzer():
    analyzer = ThreatAnalyzer()
    model = analyzer.get_model()
    assert model.threat_count >= 8
    assert model.asset_count >= 5
    assert model.actor_count >= 4
    assert model.boundary_count >= 4
    
    result = analyzer.analyze()
    assert isinstance(result, AnalysisResult)
    assert result.overall_risk_score >= 0.0
    assert len(result.threats_by_severity) > 0
    assert "CRITICAL" in result.threats_by_severity or "HIGH" in result.threats_by_severity
    assert len(result.attack_paths) >= 3


def test_threat_report_renderer():
    analyzer = ThreatAnalyzer()
    result = analyzer.analyze()
    renderer = ThreatReportRenderer()
    
    # Markdown report rendering
    md = renderer.to_markdown(result)
    assert len(md) > 100
    assert "# " in md


def test_threat_model_exporter():
    analyzer = ThreatAnalyzer()
    result = analyzer.analyze()
    exporter = ThreatModelExporter()
    
    # JSON export
    json_out = exporter.export(result, format="json")
    data = json.loads(json_out)
    assert "threats_by_severity" in data or "model" in data
    
    # Markdown export
    md_out = exporter.export(result, format="markdown")
    assert isinstance(md_out, str)
    assert len(md_out) > 100
