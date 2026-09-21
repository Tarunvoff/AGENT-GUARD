"""Threat model Rich CLI renderer — professional security report output."""
from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree
from rich.columns import Columns
from rich.text import Text
from rich import box

from actshield.cli.theme import ACTSHIELD_THEME
from actshield.threatmodel.models import (
    ThreatModel,
    AnalysisResult,
    ThreatSeverity,
    ControlEffectiveness,
)
from actshield.threatmodel.threats import Threat

console = Console(theme=ACTSHIELD_THEME)

# Severity → Rich style
_SEV_STYLE: dict[str, str] = {
    ThreatSeverity.CRITICAL.value: "ag.critical",
    ThreatSeverity.HIGH.value: "ag.attack",
    ThreatSeverity.MEDIUM.value: "ag.warning",
    ThreatSeverity.LOW.value: "ag.monitor",
    ThreatSeverity.INFORMATIONAL.value: "ag.dim",
}

_EFF_LABEL: dict[ControlEffectiveness, str] = {
    ControlEffectiveness.PREVENTS: "✓ PREVENTS",
    ControlEffectiveness.DETECTS: "◉ DETECTS",
    ControlEffectiveness.REDUCES: "◈ REDUCES",
    ControlEffectiveness.MONITORS: "○ MONITORS",
    ControlEffectiveness.NONE: "✗ NONE",
}

_EFF_STYLE: dict[ControlEffectiveness, str] = {
    ControlEffectiveness.PREVENTS: "ag.healthy",
    ControlEffectiveness.DETECTS: "ag.monitor",
    ControlEffectiveness.REDUCES: "ag.warning",
    ControlEffectiveness.MONITORS: "ag.hitl",
    ControlEffectiveness.NONE: "ag.violation",
}


class ThreatReportRenderer:
    """Renders threat model data as Rich terminal output."""

    # ── Summary ──────────────────────────────────────────────────────────────

    def render_model_summary(self, model: ThreatModel) -> None:
        console.print()
        console.print(Panel(
            f"[ag.header]System[/ag.header]       {model.system_name}\n"
            f"[ag.header]Model ID[/ag.header]     [ag.id]{model.model_id}[/ag.id]\n"
            f"[ag.header]Version[/ag.header]      {model.version}\n\n"
            f"[ag.label]Assets         [/ag.label][bold]{model.asset_count}[/bold]\n"
            f"[ag.label]Threat Actors  [/ag.label][bold]{model.actor_count}[/bold]\n"
            f"[ag.label]Trust Boundaries[/ag.label][bold]{model.boundary_count}[/bold]\n"
            f"[ag.label]Threats        [/ag.label][bold]{model.threat_count}[/bold]\n"
            f"[ag.label]Attack Scenarios[/ag.label][bold]{model.scenario_count}[/bold]",
            title="[ag.brand]ACTSHIELD  THREAT MODEL[/ag.brand]",
            border_style="rgb(59,130,246)",
            expand=False,
        ))
        console.print()

    # ── Threat list ──────────────────────────────────────────────────────────

    def render_threat_list(self, threats: list[Threat]) -> None:
        table = Table(
            box=box.SIMPLE_HEAD,
            show_header=True,
            header_style="ag.header",
            pad_edge=False,
            expand=False,
        )
        table.add_column("ID", style="ag.id", no_wrap=True)
        table.add_column("Name", min_width=32)
        table.add_column("Category", style="ag.label")
        table.add_column("Severity", no_wrap=True)
        table.add_column("Control Effectiveness", no_wrap=True)
        table.add_column("Entry Point(s)", style="ag.dim")

        for t in sorted(
            threats,
            key=lambda x: list(ThreatSeverity).index(x.severity)
        ):
            sev_style = _SEV_STYLE.get(t.severity.value, "")
            eff_label = _EFF_LABEL.get(t.control_effectiveness, "?")
            eff_style = _EFF_STYLE.get(t.control_effectiveness, "")
            table.add_row(
                t.threat_id,
                t.name,
                t.category.value.replace("_", " "),
                Text(t.severity.value, style=sev_style),
                Text(eff_label, style=eff_style),
                ", ".join(t.entry_points[:2]),
            )

        console.print()
        console.print(table)
        console.print(f"  [ag.dim]{len(threats)} threat(s)[/ag.dim]")
        console.print()

    # ── Threat detail ────────────────────────────────────────────────────────

    def render_threat_detail(self, threat: Threat) -> None:
        sev_style = _SEV_STYLE.get(threat.severity.value, "")
        eff_label = _EFF_LABEL.get(threat.control_effectiveness, "?")
        eff_style = _EFF_STYLE.get(threat.control_effectiveness, "")

        # Attack path tree
        path_tree = Tree("[ag.label]Attack Path[/ag.label]")
        for step in threat.attack_path:
            path_tree.add(f"[ag.dim]{step}[/ag.dim]")

        # Controls table
        controls_text = "\n".join(
            f"  [ag.healthy]·[/ag.healthy] {c.replace('_', ' ').title()}"
            for c in threat.actshield_controls
        ) or "  [ag.violation]No controls mapped[/ag.violation]"

        content = (
            f"[ag.label]ID         [/ag.label] {threat.threat_id}\n"
            f"[ag.label]Category   [/ag.label] {threat.category.value.replace('_', ' ')}\n"
            f"[ag.label]Severity   [/ag.label] [{sev_style}]{threat.severity.value}[/{sev_style}]\n"
            f"[ag.label]STRIDE     [/ag.label] {threat.stride_category or 'N/A'}\n"
            f"[ag.label]MITRE Atlas[/ag.label] {threat.mitre_atlas_id or 'N/A'}\n\n"
            f"[ag.header]Description[/ag.header]\n  {threat.description}\n\n"
            f"[ag.header]ActShield Controls[/ag.header]\n{controls_text}\n\n"
            f"[ag.header]Control Effectiveness[/ag.header]\n  [{eff_style}]{eff_label}[/{eff_style}]\n\n"
            f"[ag.header]Residual Risk[/ag.header]\n  {threat.residual_risk}\n\n"
            f"[ag.header]Evidence Generated[/ag.header]\n  "
            + ", ".join(threat.evidence_generated)
        )

        console.print()
        console.print(Panel(
            content,
            title=f"[ag.brand]{threat.name}[/ag.brand]",
            border_style="rgb(59,130,246)",
            expand=False,
        ))
        console.print()
        console.print(path_tree)
        console.print()

    # ── Full analysis report ─────────────────────────────────────────────────

    def render_analysis_report(self, result: AnalysisResult) -> None:
        model = result.model
        sev_counts = {s.value: 0 for s in ThreatSeverity}
        for sev, threats in result.threats_by_severity.items():
            sev_counts[sev] = len(threats)

        console.print()
        # Header panel
        console.print(Panel(
            f"[ag.label]System         [/ag.label]{model.system_name}\n"
            f"[ag.label]Analysis Time  [/ag.label]{result.analysis_timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
            f"[ag.label]Overall Risk   [/ag.label][bold]{result.overall_risk_score:.1f}[/bold] / 10.0\n",
            title="[ag.brand]ACTSHIELD  THREAT ANALYSIS[/ag.brand]",
            border_style="rgb(59,130,246)",
            expand=False,
        ))

        # Counts row
        console.print()
        console.print("  [ag.header]Threat Inventory[/ag.header]")
        counts_table = Table(box=box.SIMPLE, show_header=False, pad_edge=False)
        counts_table.add_column("", style="ag.label", no_wrap=True)
        counts_table.add_column("", style="bold", no_wrap=True)
        counts_table.add_row("Assets", str(model.asset_count))
        counts_table.add_row("Trust Boundaries", str(model.boundary_count))
        counts_table.add_row("Threat Actors", str(model.actor_count))
        counts_table.add_row("Identified Threats", str(model.threat_count))
        counts_table.add_row("Attack Scenarios", str(model.scenario_count))
        console.print(counts_table)

        # Severity breakdown
        console.print()
        console.print("  [ag.header]Severity Breakdown[/ag.header]")
        sev_table = Table(box=box.SIMPLE, show_header=False, pad_edge=False)
        sev_table.add_column("", no_wrap=True)
        sev_table.add_column("", no_wrap=True)
        for sev, style in _SEV_STYLE.items():
            count = sev_counts.get(sev, 0)
            bar = "█" * count
            sev_table.add_row(
                Text(f"  {sev:<14}", style=style),
                Text(f"{count:>3}  {bar}", style=style),
            )
        console.print(sev_table)

        # Coverage map
        console.print()
        console.print("  [ag.header]Control Domain Coverage[/ag.header]")
        cov_table = Table(box=box.SIMPLE, show_header=False, pad_edge=False)
        cov_table.add_column("", style="ag.label", no_wrap=True)
        cov_table.add_column("", no_wrap=True)
        for domain, covered in result.control_coverage.items():
            mark = Text("  ✓", style="ag.healthy") if covered else Text("  ✗", style="ag.violation")
            cov_table.add_row(f"  {domain:<24}", mark)
        console.print(cov_table)

        # Attack paths
        if result.attack_paths:
            console.print()
            console.print("  [ag.header]Attack Scenarios[/ag.header]")
            for path in result.attack_paths:
                sev_style = _SEV_STYLE.get(path["severity"], "")
                enforcement = path["enforcement"]
                enf_style = "ag.block" if enforcement == "BLOCK" else "ag.monitor"
                console.print(
                    f"  [{sev_style}]{path['severity']:<10}[/{sev_style}]"
                    f"  {path['name']:<52}"
                    f"  [{enf_style}]{enforcement}[/{enf_style}]"
                )

        # Residual risks
        if result.residual_risks:
            console.print()
            console.print("  [ag.header]Residual Risks[/ag.header]")
            for risk in result.residual_risks:
                sev_style = _SEV_STYLE.get(risk["severity"], "")
                console.print(
                    f"  [{sev_style}]{risk['severity']:<10}[/{sev_style}]"
                    f"  {risk['name']:<40}"
                    f"  score={risk['residual_score']:.1f}"
                )

        console.print()

    # ── Attack graph (Rich tree) ──────────────────────────────────────────────

    def render_attack_graph(self, result: AnalysisResult) -> None:
        from actshield.threatmodel.scenarios import get_builtin_scenarios
        scenarios = get_builtin_scenarios()

        console.print()
        root = Tree("[ag.brand]ACTSHIELD  ATTACK GRAPH[/ag.brand]")
        for scenario in scenarios:
            sev_style = _SEV_STYLE.get(scenario.severity.value, "")
            scenario_node = root.add(
                f"[{sev_style}]{scenario.severity.value}[/{sev_style}]  {scenario.name}"
            )
            for step in scenario.steps:
                outcome_style = (
                    "ag.healthy" if step.outcome == "blocked"
                    else "ag.warning" if step.outcome == "detected"
                    else "ag.dim"
                )
                label = f"[{outcome_style}]{step.outcome.upper():>8}[/{outcome_style}]  Step {step.step_num}: {step.description[:60]}"
                scenario_node.add(label)
        console.print(root)
        console.print()

    # ── Markdown export ───────────────────────────────────────────────────────

    def to_markdown(self, result: AnalysisResult) -> str:
        model = result.model
        lines = [
            f"# ActShield Threat Model Report",
            f"",
            f"**System:** {model.system_name}  ",
            f"**Date:** {result.analysis_timestamp.strftime('%Y-%m-%d %H:%M UTC')}  ",
            f"**Overall Risk Score:** {result.overall_risk_score:.1f} / 10.0  ",
            f"**Model ID:** `{model.model_id}`",
            f"",
            f"---",
            f"",
            f"## Inventory",
            f"",
            f"| Category | Count |",
            f"|----------|-------|",
            f"| Assets | {model.asset_count} |",
            f"| Trust Boundaries | {model.boundary_count} |",
            f"| Threat Actors | {model.actor_count} |",
            f"| Identified Threats | {model.threat_count} |",
            f"| Attack Scenarios | {model.scenario_count} |",
            f"",
            f"## Severity Breakdown",
            f"",
            f"| Severity | Count |",
            f"|----------|-------|",
        ]
        for sev in ThreatSeverity:
            count = len(result.threats_by_severity.get(sev.value, []))
            lines.append(f"| {sev.value} | {count} |")

        lines += [
            f"",
            f"## Control Domain Coverage",
            f"",
            f"| Domain | Covered |",
            f"|--------|---------|",
        ]
        for domain, covered in result.control_coverage.items():
            mark = "✓" if covered else "✗"
            lines.append(f"| {domain} | {mark} |")

        lines += [
            f"",
            f"## Threats",
            f"",
        ]
        for sev in ThreatSeverity:
            threats = result.threats_by_severity.get(sev.value, [])
            if threats:
                lines.append(f"### {sev.value}")
                lines.append(f"")
                for t in threats:
                    lines.append(f"#### {t['name']}")
                    lines.append(f"")
                    lines.append(f"- **ID:** `{t['threat_id']}`")
                    lines.append(f"- **Category:** {t['category']}")
                    lines.append(f"- **Controls:** {', '.join(t.get('actshield_controls', []))}")
                    lines.append(f"- **Effectiveness:** {t.get('control_effectiveness', 'N/A')}")
                    lines.append(f"- **Residual Risk:** {t.get('residual_risk', 'N/A')}")
                    lines.append(f"")

        if result.residual_risks:
            lines += [f"## Residual Risks", f""]
            for risk in result.residual_risks:
                lines.append(
                    f"- **{risk['name']}** ({risk['severity']}) — "
                    f"residual score: {risk['residual_score']:.1f} — {risk['residual_risk']}"
                )
            lines.append(f"")

        lines += [
            f"---",
            f"",
            f"*Generated by ActShield v0.9.0*",
            f"",
        ]
        return "\n".join(lines)
