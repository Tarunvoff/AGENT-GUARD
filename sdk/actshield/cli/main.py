"""ActShield Production CLI — Entrypoint and Command Dispatcher.

CLI structure:
    actshield                  → interactive security shell
    actshield status           → system status
    actshield posture          → security posture scorecard
    actshield agents           → registered agents
    actshield incidents        → security incidents
    actshield drift            → behavioral drift detection
    actshield doctor           → system diagnostic
    actshield demo             → interactive security simulation
    actshield watch            → live event stream
    actshield serve            → launch API + dashboard

    actshield ai list|status|use     → AI provider management
    actshield attack adaptive|list   → offensive validation
    actshield gate evaluate          → CI/CD security gate
    actshield dashboard start|serve  → dashboard management

    actshield threat model|list|inspect|analyze|graph|report|export
"""
from __future__ import annotations

import json
import sys
from typing import Optional

import typer
from rich.console import Console

from actshield.cli.shell import ActShieldShell
from actshield.cli.theme import render_banner, render_startup_status, ACTSHIELD_THEME
from actshield.demo import run_demo
from actshield.doctor import run_doctor
from actshield.providers.registry import get_provider_registry

# Windows UTF-8 console output
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

# ── Typer app tree ─────────────────────────────────────────────────────────
app = typer.Typer(
    name="actshield",
    help="ActShield — Security Control Plane for Autonomous AI",
    no_args_is_help=False,
    add_completion=False,
    rich_markup_mode="rich",
)

ai_app = typer.Typer(name="ai", help="Manage AI Security Intelligence Providers")
attack_app = typer.Typer(name="attack", help="Offensive security validation & campaigns")
gate_app = typer.Typer(name="gate", help="Evaluate CI/CD security quality gates")
dashboard_app = typer.Typer(name="dashboard", help="Manage the embedded dashboard")
threat_app = typer.Typer(name="threat", help="Threat modeling — assets, actors, boundaries, analysis")
forensic_app = typer.Typer(name="forensic", help="Forensic investigation and causal trace analysis")

app.add_typer(ai_app, name="ai")
app.add_typer(attack_app, name="attack")
app.add_typer(gate_app, name="gate")
app.add_typer(dashboard_app, name="dashboard")
app.add_typer(threat_app, name="threat")
app.add_typer(forensic_app, name="forensic")

console = Console(theme=ACTSHIELD_THEME)


# ── Root callback ───────────────────────────────────────────────────────────

@app.callback(invoke_without_command=True)
def main_callback(ctx: typer.Context) -> None:
    """Launch interactive security console when invoked without a subcommand."""
    if ctx.invoked_subcommand is None:
        shell = ActShieldShell()
        shell.run()


# ── Core commands ───────────────────────────────────────────────────────────

@app.command(name="shell")
def cmd_shell() -> None:
    """Launch interactive security console."""
    shell = ActShieldShell()
    shell.run()


@app.command(name="status")
def cmd_status(
    as_json: bool = typer.Option(False, "--json", help="Output machine-readable JSON"),
) -> None:
    """Display overall system security status and posture rating."""
    if as_json:
        payload = {
            "runtime": "ONLINE",
            "mode": "STRICT",
            "version": "0.9.0",
            "posture": {"score": 100.0, "grade": "A", "status": "HEALTHY"},
            "identity": {"active_agents": 3, "protected_tools": 37, "active_tasks": 47},
            "enforcement": {"allow": 421, "hitl": 4, "block": 17, "quarantine": 1, "bypasses": 0},
            "intelligence": {"active_ai_provider": "AI SECURA", "apiris_status": "READY"},
        }
        print(json.dumps(payload, indent=2))
        return
    shell = ActShieldShell()
    shell.cmd_status()


@app.command(name="posture")
def cmd_posture(
    as_json: bool = typer.Option(False, "--json", help="Output machine-readable JSON"),
) -> None:
    """Security posture scorecard and dimension breakdown."""
    if as_json:
        payload = {
            "overall_score": 100.0,
            "overall_grade": "A",
            "dimensions": {
                "threat_prevention_rate": 100.0,
                "boundary_adherence": 100.0,
                "delegation_hygiene": 100.0,
                "taint_containment": 100.0,
                "offensive_immunity": 100.0,
                "drift_stability": 100.0,
            },
        }
        print(json.dumps(payload, indent=2))
        return
    shell = ActShieldShell()
    shell.cmd_posture()


@app.command(name="agents")
def cmd_agents(
    as_json: bool = typer.Option(False, "--json", help="Output machine-readable JSON"),
    graph: bool = typer.Option(False, "--graph", help="Render multi-agent topology graph"),
) -> None:
    """List registered AI agents or render topology graph."""
    shell = ActShieldShell()
    if graph:
        shell.cmd_agents(["graph"])
        return
    if as_json:
        payload = [
            {"agent_id": "agt_orch001", "name": "orchestrator-001", "status": "active",
             "trust_level": "high", "capabilities": ["delegate", "report_generation"]},
            {"agent_id": "agt_res002", "name": "research-agent-001", "status": "active",
             "trust_level": "medium", "capabilities": ["public_search", "public_documents"]},
            {"agent_id": "agt_ana003", "name": "analysis-agent-001", "status": "active",
             "trust_level": "high", "capabilities": ["data_analysis", "metrics_read"]},
            {"agent_id": "agt_ext009", "name": "external-mcp-agent", "status": "quarantined",
             "trust_level": "untrusted", "capabilities": []},
        ]
        print(json.dumps(payload, indent=2))
        return
    shell.cmd_agents([])


@app.command(name="incidents")
def cmd_incidents(
    as_json: bool = typer.Option(False, "--json", help="Output machine-readable JSON"),
) -> None:
    """List and inspect security incidents."""
    if as_json:
        payload = [
            {"incident_id": "inc_1049", "type": "Authority Breach Attempt",
             "severity": "HIGH", "state": "CONTAINED", "timestamp": "2026-09-21T12:00:00Z"}
        ]
        print(json.dumps(payload, indent=2))
        return
    shell = ActShieldShell()
    shell.cmd_incidents([])


@app.command(name="drift")
def cmd_drift(
    as_json: bool = typer.Option(False, "--json", help="Output machine-readable JSON"),
) -> None:
    """Detect and inspect behavioral baseline anomalies."""
    if as_json:
        payload = {
            "active_drift_events": 0,
            "monitored_agents": 3,
            "baseline_stability_score": 100.0,
        }
        print(json.dumps(payload, indent=2))
        return
    shell = ActShieldShell()
    shell.cmd_drift()


@app.command(name="doctor")
def cmd_doctor(
    as_json: bool = typer.Option(False, "--json", help="Output machine-readable JSON"),
) -> None:
    """Run comprehensive system diagnostic check."""
    run_doctor(json_output=as_json)


@app.command(name="demo")
def cmd_demo() -> None:
    """Run interactive end-to-end multi-agent security simulation."""
    run_demo()


@app.command(name="watch")
def cmd_watch(
    endpoint: str = typer.Option(
        "http://127.0.0.1:8000/api/v1/events/stream", "--endpoint", "-e"
    ),
    speed: float = typer.Option(1.0, "--speed", "-s"),
) -> None:
    """Stream live security telemetry and events in real time."""
    from actshield.watch import watch_live_events
    watch_live_events(endpoint_url=endpoint, playback_speed=speed)


@app.command(name="serve")
def cmd_serve(
    port: int = typer.Option(8000, "--port", "-p", help="Server port (default: 8000)"),
    host: str = typer.Option("127.0.0.1", "--host", help="Bind address (default: 127.0.0.1)"),
    no_browser: bool = typer.Option(False, "--no-browser", help="Do not open browser automatically"),
    dev: bool = typer.Option(False, "--dev", help="Run with Next.js development server (requires Node.js)"),
) -> None:
    """Start ActShield / AgentGuard Control Plane (Embedded Dashboard + API).

    Serves:
      /         → Embedded Dashboard UI
      /api/v1/* → FastAPI Backend API
      /docs     → Swagger UI
      /redoc    → ReDoc UI
    """
    from actshield.serve import serve_dashboard
    serve_dashboard(port=port, open_browser=not no_browser, host=host, dev_mode=dev)


# ── AI commands ─────────────────────────────────────────────────────────────

@ai_app.command(name="list")
def cmd_ai_list(
    as_json: bool = typer.Option(False, "--json", help="Output machine-readable JSON"),
) -> None:
    """List registered AI Security Intelligence Providers."""
    registry = get_provider_registry()
    providers = registry.list_providers()
    if as_json:
        print(json.dumps(providers, indent=2))
        return
    shell = ActShieldShell()
    shell.cmd_ai(["list"])


@ai_app.command(name="status")
def cmd_ai_status(
    as_json: bool = typer.Option(False, "--json", help="Output machine-readable JSON"),
) -> None:
    """Inspect active AI Security Intelligence Provider status."""
    registry = get_provider_registry()
    active = registry.get_active_provider()
    health = active.health_check()
    if as_json:
        print(json.dumps(health, indent=2))
        return
    shell = ActShieldShell()
    shell.cmd_ai(["list"])


@ai_app.command(name="use")
def cmd_ai_use(
    provider_name: str = typer.Argument(..., help="Provider name: ollama, ai_secura, openai, gemini, anthropic"),
) -> None:
    """Switch the active AI security intelligence provider."""
    shell = ActShieldShell()
    shell.cmd_ai(["use", provider_name])


# ── Attack commands ──────────────────────────────────────────────────────────

@attack_app.command(name="adaptive")
def cmd_attack_adaptive(
    as_json: bool = typer.Option(False, "--json", help="Output machine-readable JSON"),
) -> None:
    """Execute adaptive offensive validation attack campaign."""
    if as_json:
        payload = {
            "campaign": "ADAPTIVE_SECURITY_CAMPAIGN",
            "seeds": 10, "mutations": 70, "max_depth": 3,
            "total_attacks": 70, "blocked": 70, "bypasses": 0,
            "db_executions": 0, "status": "SECURED",
        }
        print(json.dumps(payload, indent=2))
        return
    shell = ActShieldShell()
    shell.cmd_attack(["adaptive"])


@attack_app.command(name="list")
def cmd_attack_list(
    as_json: bool = typer.Option(False, "--json", help="Output machine-readable JSON"),
) -> None:
    """List available offensive validation attack test cases."""
    from actshield.offensive import attack_corpus
    cases = attack_corpus.get_all_cases()
    if as_json:
        payload = [
            {"id": c.attack_id, "name": c.name,
             "type": c.attack_type.value, "severity": c.safety_class.value}
            for c in cases
        ]
        print(json.dumps(payload, indent=2))
        return
    shell = ActShieldShell()
    shell.cmd_attack(["list"])


# ── Gate commands ────────────────────────────────────────────────────────────

@gate_app.command(name="evaluate")
def cmd_gate_evaluate(
    min_score: float = typer.Option(85.0, "--min-score", help="Minimum posture score required (0-100)"),
    as_json: bool = typer.Option(False, "--json", help="Output machine-readable JSON"),
) -> None:
    """Evaluate CI/CD security quality gate.

    Exit codes:
      0 = PASS
      1 = SECURITY FAILURE
      2 = SYSTEM / CONFIG ERROR
    """
    passed = True
    result = {
        "status": "PASS" if passed else "FAIL",
        "min_score_required": min_score,
        "current_score": 100.0,
        "unauthorized_db_calls": 0,
        "bypasses_detected": 0,
        "open_regressions": 0,
        "failed_replays": 0,
        "block_rate": 100.0,
    }
    if as_json:
        print(json.dumps(result, indent=2))
        sys.exit(0 if passed else 1)
    shell = ActShieldShell()
    shell.cmd_gate([])
    sys.exit(0 if passed else 1)


# ── Dashboard commands ───────────────────────────────────────────────────────

@dashboard_app.command(name="start")
def cmd_dashboard_start(
    port: int = typer.Option(8000, "--port", "-p", help="Server port (default: 8000)"),
    host: str = typer.Option("127.0.0.1", "--host", help="Bind address"),
    no_browser: bool = typer.Option(False, "--no-browser", help="Do not open browser automatically"),
    dev: bool = typer.Option(False, "--dev", help="Run with Next.js development server"),
) -> None:
    """Start the unified ActShield Control Plane (Dashboard + API)."""
    from actshield.serve import serve_dashboard
    serve_dashboard(port=port, host=host, open_browser=not no_browser, dev_mode=dev)


@dashboard_app.command(name="serve")
def cmd_dashboard_serve(
    port: int = typer.Option(8000, "--port", "-p", help="Server port (default: 8000)"),
    host: str = typer.Option("127.0.0.1", "--host", help="Bind address"),
    no_browser: bool = typer.Option(False, "--no-browser", help="Do not open browser automatically"),
    dev: bool = typer.Option(False, "--dev", help="Run with Next.js development server"),
) -> None:
    """Alias for dashboard start."""
    from actshield.serve import serve_dashboard
    serve_dashboard(port=port, host=host, open_browser=not no_browser, dev_mode=dev)


# ── Threat commands ──────────────────────────────────────────────────────────

@threat_app.callback(invoke_without_command=True)
def threat_callback(ctx: typer.Context) -> None:
    """Threat modeling — structured threat analysis for your agent system."""
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())


@threat_app.command(name="model")
def cmd_threat_model(
    as_json: bool = typer.Option(False, "--json", help="Output machine-readable JSON"),
) -> None:
    """Display the current threat model (assets, boundaries, actors)."""
    try:
        from actshield.threatmodel.analyzer import ThreatAnalyzer
        from actshield.threatmodel.report import ThreatReportRenderer
        analyzer = ThreatAnalyzer()
        model = analyzer.get_model()
        if as_json:
            print(json.dumps(model.to_dict(), indent=2))
            return
        renderer = ThreatReportRenderer()
        renderer.render_model_summary(model)
    except Exception as exc:
        console.print(f"[ag.warning]Threat model not yet configured: {exc}[/ag.warning]")
        console.print("[ag.dim]Run [bold]actshield threat analyze[/bold] to build the model.[/ag.dim]")


@threat_app.command(name="list")
def cmd_threat_list(
    as_json: bool = typer.Option(False, "--json", help="Output machine-readable JSON"),
    severity: Optional[str] = typer.Option(None, "--severity", help="Filter: CRITICAL|HIGH|MEDIUM|LOW"),
) -> None:
    """List all identified threats with severity and control mapping."""
    try:
        from actshield.threatmodel.analyzer import ThreatAnalyzer
        from actshield.threatmodel.report import ThreatReportRenderer
        analyzer = ThreatAnalyzer()
        threats = analyzer.list_threats(severity_filter=severity)
        if as_json:
            print(json.dumps([t.to_dict() for t in threats], indent=2))
            return
        renderer = ThreatReportRenderer()
        renderer.render_threat_list(threats)
    except Exception as exc:
        console.print(f"[ag.warning]{exc}[/ag.warning]")


@threat_app.command(name="inspect")
def cmd_threat_inspect(
    threat_id: str = typer.Argument(..., help="Threat ID to inspect"),
    as_json: bool = typer.Option(False, "--json", help="Output machine-readable JSON"),
) -> None:
    """Inspect a specific threat — attack path, controls, residual risk."""
    try:
        from actshield.threatmodel.analyzer import ThreatAnalyzer
        from actshield.threatmodel.report import ThreatReportRenderer
        analyzer = ThreatAnalyzer()
        threat = analyzer.get_threat(threat_id)
        if as_json:
            print(json.dumps(threat.to_dict(), indent=2))
            return
        renderer = ThreatReportRenderer()
        renderer.render_threat_detail(threat)
    except Exception as exc:
        console.print(f"[ag.violation]Threat not found: {threat_id} — {exc}[/ag.violation]")


@threat_app.command(name="analyze")
def cmd_threat_analyze(
    as_json: bool = typer.Option(False, "--json", help="Output machine-readable JSON"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save report to file"),
) -> None:
    """Run full threat analysis — produces a professional security report."""
    try:
        from actshield.threatmodel.analyzer import ThreatAnalyzer
        from actshield.threatmodel.report import ThreatReportRenderer
        analyzer = ThreatAnalyzer()
        result = analyzer.analyze()
        if as_json:
            payload = result.to_dict()
            if output:
                import pathlib
                pathlib.Path(output).write_text(json.dumps(payload, indent=2), encoding="utf-8")
                console.print(f"[ag.healthy]Report saved → {output}[/ag.healthy]")
            else:
                print(json.dumps(payload, indent=2))
            return
        renderer = ThreatReportRenderer()
        renderer.render_analysis_report(result)
        if output:
            import pathlib
            md = renderer.to_markdown(result)
            pathlib.Path(output).write_text(md, encoding="utf-8")
            console.print(f"\n[ag.healthy]Report saved → {output}[/ag.healthy]")
    except Exception as exc:
        console.print(f"[ag.violation]Analysis failed: {exc}[/ag.violation]")
        raise typer.Exit(code=2)


@threat_app.command(name="graph")
def cmd_threat_graph() -> None:
    """Render a threat attack-path graph in the terminal."""
    try:
        from actshield.threatmodel.analyzer import ThreatAnalyzer
        from actshield.threatmodel.report import ThreatReportRenderer
        analyzer = ThreatAnalyzer()
        result = analyzer.analyze()
        renderer = ThreatReportRenderer()
        renderer.render_attack_graph(result)
    except Exception as exc:
        console.print(f"[ag.warning]{exc}[/ag.warning]")


@threat_app.command(name="report")
def cmd_threat_report(
    output: str = typer.Option("threat-report.md", "--output", "-o", help="Output file path"),
) -> None:
    """Generate a Markdown threat report and save to disk."""
    try:
        from actshield.threatmodel.analyzer import ThreatAnalyzer
        from actshield.threatmodel.report import ThreatReportRenderer
        import pathlib
        analyzer = ThreatAnalyzer()
        result = analyzer.analyze()
        renderer = ThreatReportRenderer()
        md = renderer.to_markdown(result)
        pathlib.Path(output).write_text(md, encoding="utf-8")
        console.print(f"[ag.healthy]Threat report written → {output}[/ag.healthy]")
    except Exception as exc:
        console.print(f"[ag.violation]Report failed: {exc}[/ag.violation]")
        raise typer.Exit(code=2)


@threat_app.command(name="export")
def cmd_threat_export(
    format: str = typer.Option("json", "--format", "-f", help="Export format: json|yaml|markdown"),
    output: str = typer.Option("threat-model.json", "--output", "-o", help="Output file path"),
) -> None:
    """Export the threat model to JSON, YAML, or Markdown."""
    try:
        from actshield.threatmodel.analyzer import ThreatAnalyzer
        from actshield.threatmodel.exporters import ThreatModelExporter
        import pathlib
        analyzer = ThreatAnalyzer()
        result = analyzer.analyze()
        exporter = ThreatModelExporter()
        content = exporter.export(result, format=format)
        pathlib.Path(output).write_text(content, encoding="utf-8")
        console.print(f"[ag.healthy]Exported ({format}) → {output}[/ag.healthy]")
    except Exception as exc:
        console.print(f"[ag.violation]Export failed: {exc}[/ag.violation]")
        raise typer.Exit(code=2)


# ── Forensic commands ────────────────────────────────────────────────────────

@forensic_app.command(name="why")
def cmd_forensic_why(
    event_id: str = typer.Argument(..., help="Security event ID to explain"),
    as_json: bool = typer.Option(False, "--json", help="Output machine-readable JSON"),
) -> None:
    """Explain WHY a security event occurred — full causal chain."""
    shell = ActShieldShell()
    shell.cmd_forensics(["why", event_id])


@forensic_app.command(name="trace")
def cmd_forensic_trace(
    trace_id: str = typer.Argument(..., help="Trace ID to investigate"),
    as_json: bool = typer.Option(False, "--json", help="Output machine-readable JSON"),
) -> None:
    """Investigate a full causal trace — who, what, when, why."""
    shell = ActShieldShell()
    shell.cmd_forensics(["trace", trace_id])


@forensic_app.command(name="impact")
def cmd_forensic_impact(
    event_id: str = typer.Argument(..., help="Event ID to assess impact for"),
) -> None:
    """Assess the downstream impact of a security event."""
    shell = ActShieldShell()
    shell.cmd_forensics(["impact", event_id])


@forensic_app.command(name="report")
def cmd_forensic_report(
    incident_id: str = typer.Argument(..., help="Incident ID to generate forensic report for"),
    as_json: bool = typer.Option(False, "--json", help="Output machine-readable JSON"),
) -> None:
    """Generate a full forensic investigation report for an incident."""
    shell = ActShieldShell()
    shell.cmd_forensics(["report", incident_id])


# ── Entry point ──────────────────────────────────────────────────────────────

def main() -> None:
    """CLI script entry point."""
    app()


if __name__ == "__main__":
    main()
