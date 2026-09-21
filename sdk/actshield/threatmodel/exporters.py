"""Threat model exporters — JSON, YAML, Markdown."""
from __future__ import annotations

import json
from typing import Literal

from actshield.threatmodel.models import AnalysisResult
from actshield.threatmodel.report import ThreatReportRenderer

ExportFormat = Literal["json", "yaml", "markdown"]


class ThreatModelExporter:
    """Exports threat analysis results to external formats."""

    def export(self, result: AnalysisResult, format: ExportFormat = "json") -> str:
        if format == "json":
            return self._to_json(result)
        elif format == "yaml":
            return self._to_yaml(result)
        elif format == "markdown":
            renderer = ThreatReportRenderer()
            return renderer.to_markdown(result)
        else:
            raise ValueError(f"Unsupported export format: {format}. Use json, yaml, or markdown.")

    def _to_json(self, result: AnalysisResult) -> str:
        return json.dumps(result.to_dict(), indent=2, default=str)

    def _to_yaml(self, result: AnalysisResult) -> str:
        try:
            import yaml  # type: ignore[import]
            return yaml.dump(result.to_dict(), default_flow_style=False, allow_unicode=True)
        except ImportError:
            # Fallback: minimal YAML-like output without PyYAML
            data = result.to_dict()
            lines = ["# ActShield Threat Model Export (YAML)"]
            lines.append(f"overall_risk_score: {data.get('overall_risk_score', 0)}")
            lines.append("model:")
            model = data.get("model", {})
            for k, v in model.items():
                lines.append(f"  {k}: {json.dumps(v)}")
            lines.append("threats_by_severity:")
            for sev, threats in data.get("threats_by_severity", {}).items():
                lines.append(f"  {sev}: {len(threats)} threat(s)")
            lines.append(
                "# Install PyYAML for full YAML export: pip install pyyaml"
            )
            return "\n".join(lines)
