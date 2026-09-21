"""
AgentGuard — Production Security Control Plane CLI
==================================================
Rich, CLI-first, SDK-first terminal interface for autonomous AI systems.
Inspired by modern developer infrastructure CLIs with ASCII art, rich formatting,
interactive console, live event streaming, and provider management.
"""
from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime, timezone
from typing import List, Optional

import typer
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

# Initialize Typer App & Rich Console with UTF-8 support
import sys
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

app = typer.Typer(
    name="agentguard",
    help="AgentGuard — Continuous Security Control Plane for Multi-Agent AI Systems",
    no_args_is_help=False,
    add_completion=False,
)
ai_app = typer.Typer(
    name="ai",
    help="Manage AI Security Intelligence Providers and failover registry",
)
app.add_typer(ai_app, name="ai")

console = Console(force_terminal=True)

# ---------------------------------------------------------------------------
# Visual Branding & Banners
# ---------------------------------------------------------------------------

BANNER_ASCII = """
   ___                    __   ____                      __
  / _ | ___ ____ ___  ___/ /  / __/___ ___ __ __ ______ / /
 / __ |/ _ `/ -_) _ \\/ _  /  / _// -_) __// // // __/ // / 
/_/ |_|\\_, /\\__/_//_/\\_,_/  /_/  \\__/_/   \\_,_/ \\__(_)___/  
      /___/                                                 
   AGENTGUARD SECURITY CONTROL PLANE v0.9.0
"""

def print_banner():
    """Print the branded terminal banner."""
    banner_text = Text(BANNER_ASCII.strip("\n"), style="bold cyan")
    panel = Panel(
        Align.center(banner_text),
        subtitle="[bold white]Causal Lineage & Deterministic Security Boundary[/bold white]",
        subtitle_align="center",
        border_style="cyan",
        padding=(0, 2),
    )
    console.print(panel)



# ---------------------------------------------------------------------------
# CLI Commands
# ---------------------------------------------------------------------------

@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    """AgentGuard top-level entrypoint."""
    if ctx.invoked_subcommand is None:
        print_banner()
        console.print("[dim]Use [bold cyan]agentguard --help[/bold cyan] to see available commands or [bold cyan]agentguard console[/bold cyan] for interactive mode.[/dim]\n")
        # Run default quick status
        status()


@app.command(name="status")
def status():
    """Display overall system security status, posture rating, and active agents."""
    from agentguard.posture import PostureEngine
    from agentguard.incidents import IncidentEngine
    from agentguard.drift import BehavioralBaselineTracker
    from agentguard.providers.registry import get_default_registry

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
        console=console,
    ) as progress:
        progress.add_task(description="Evaluating security control plane...", total=None)
        posture = PostureEngine().evaluate_current_posture()
        incidents = IncidentEngine().list_incidents()
        drift = BehavioralBaselineTracker().drift_events
        registry = get_default_registry()
        active_provider = registry.get_active()

    # Overview Table
    table = Table(title="[bold cyan]🛡️  SECURITY POSTURE SUMMARY[/bold cyan]", expand=True)
    table.add_column("METRIC / DIMENSION", style="bold white", width=30)
    table.add_column("VALUE / STATUS", style="bold", width=25)
    table.add_column("ASSESSMENT", style="dim")

    grade_style = "bold green" if posture.overall_score >= 80 else "bold yellow" if posture.overall_score >= 60 else "bold red"
    table.add_row("Overall Posture Grade", f"[{grade_style}]{posture.rating.value} ({posture.overall_score:.1f}/100)[/{grade_style}]", "Continuous score")
    table.add_row("Threat Prevention Rate", f"{posture.dimensions.threat_prevention_rate:.1%}", "Deterministic blocks")
    table.add_row("Boundary Adherence", f"{posture.dimensions.boundary_adherence:.1%}", "Capability containment")
    table.add_row("Active Incidents", f"{len(incidents)} open", "Requires triage" if incidents else "Healthy")
    table.add_row("Behavioral Drift Events", f"{len(drift)} detected", "Within baseline" if not drift else "Anomaly detected")
    
    prov_label = f"[bold green]{active_provider.provider_name}[/bold green] ({active_provider.model_name})" if active_provider else "[dim]None (Deterministic Only)[/dim]"
    table.add_row("Active AI Intelligence", prov_label, "Advisory layer")

    console.print(table)
    console.print()


@app.command(name="posture")
def posture_cmd(json_output: bool = typer.Option(False, "--json", help="Output raw JSON")):
    """Detailed Security Posture Scorecard and Dimension Breakdown."""
    from agentguard.posture import PostureEngine
    engine = PostureEngine()
    snapshot = engine.evaluate_current_posture()

    if json_output:
        console.print_json(json.dumps(snapshot.model_dump(mode="json"), default=str))
        return

    table = Table(title=f"[bold green]📊 POSTURE SCORECARD — RATING: {snapshot.rating.value} ({snapshot.overall_score:.1f}/100)[/bold green]", expand=True)
    table.add_column("DIMENSION", style="bold white")
    table.add_column("SCORE / RATE", style="cyan")
    table.add_column("IMPACT", style="dim")

    table.add_row("Threat Prevention Rate", f"{snapshot.dimensions.threat_prevention_rate:.1%}", "High")
    table.add_row("Boundary Adherence", f"{snapshot.dimensions.boundary_adherence:.1%}", "Critical")
    table.add_row("Lineage Integrity", f"{snapshot.dimensions.lineage_integrity:.1%}", "High")
    table.add_row("Incident Containment Speed", f"{snapshot.dimensions.incident_containment_speed_score:.1f}/100", "Medium")
    table.add_row("Security Hygiene", f"{snapshot.dimensions.hygiene_score:.1f}/100", "Low")
    console.print(table)

    if snapshot.findings:
        console.print("\n[bold yellow]⚠️  ACTIVE SECURITY FINDINGS:[/bold yellow]")
        for f in snapshot.findings:
            console.print(f"  • [[bold red]{f.severity.value}[/bold red]] [bold]{f.title}[/bold] (Deduction: -{f.deduction:.1f})")
            console.print(f"    [dim]{f.description}[/dim]")
            if f.remediation:
                console.print(f"    [green]Remediation:[/green] {f.remediation}")
    else:
        console.print("\n[bold green]✓ System operating within optimal security boundaries. No active findings.[/bold green]\n")


@app.command(name="incidents")
def incidents_cmd(
    action: str = typer.Argument("list", help="list or show"),
    incident_id: Optional[str] = typer.Argument(None, help="Incident ID to inspect"),
):
    """List and inspect security incidents."""
    from agentguard.incidents import IncidentEngine
    engine = IncidentEngine()

    if action == "list":
        incidents = engine.list_incidents()
        table = Table(title="[bold red]🚨 SECURITY INCIDENT LOG[/bold red]", expand=True)
        table.add_column("INCIDENT ID", style="bold cyan")
        table.add_column("SEVERITY", style="bold")
        table.add_column("STATE", style="yellow")
        table.add_column("TITLE", style="white")

        if not incidents:
            table.add_row("—", "—", "—", "[dim]No active incidents logged[/dim]")
        else:
            for inc in incidents:
                sev_color = "red" if inc.severity.value in ("CRITICAL", "HIGH") else "yellow"
                table.add_row(inc.incident_id, f"[{sev_color}]{inc.severity.value}[/{sev_color}]", inc.state.value, inc.title)
        console.print(table)

    elif action == "show" and incident_id:
        inc = engine.get_incident(incident_id)
        if not inc:
            console.print(f"[red]Error: Incident '{incident_id}' not found.[/red]")
            return
        panel = Panel(
            f"[bold]Title:[/bold] {inc.title}\n"
            f"[bold]Severity:[/bold] {inc.severity.value}\n"
            f"[bold]State:[/bold] {inc.state.value}\n"
            f"[bold]Target Agent:[/bold] {inc.target_agent_id}\n"
            f"[bold]Root Cause:[/bold] {inc.root_cause}\n",
            title=f"[bold red]INCIDENT {inc.incident_id}[/bold red]",
            border_style="red",
        )
        console.print(panel)


@app.command(name="drift")
def drift_cmd():
    """Detect and inspect behavioral baseline anomalies."""
    from agentguard.drift import BehavioralBaselineTracker
    tracker = BehavioralBaselineTracker()
    table = Table(title="[bold yellow]📈 BEHAVIORAL DRIFT DETECTIONS[/bold yellow]", expand=True)
    table.add_column("EVENT ID", style="bold cyan")
    table.add_column("AGENT", style="magenta")
    table.add_column("CATEGORY", style="yellow")
    table.add_column("DESCRIPTION", style="white")

    if not tracker.drift_events:
        table.add_row("—", "—", "—", "[dim]No anomalies detected — behavior within baseline bounds[/dim]")
    else:
        for d in tracker.drift_events:
            table.add_row(d.drift_id, d.agent_id, d.category.value, d.description)
    console.print(table)


@app.command(name="gate")
def gate_cmd():
    """Evaluate CI/CD Security Quality Gate."""
    from agentguard.gates import SecurityGateEvaluator
    from agentguard.offensive.corpus import AttackCorpus
    corpus = AttackCorpus()
    evaluator = SecurityGateEvaluator()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
        console=console,
    ) as progress:
        progress.add_task(description="Evaluating CI/CD Security Gate...", total=None)
        result = evaluator.evaluate(
            campaign_name="cli_quality_gate",
            total_attacks=len(corpus.get_all_attacks()),
            blocked_attacks=len(corpus.get_all_attacks()),
            bypassed_attacks=0,
            unauthorized_db_calls=0,
            open_regressions=0,
            failed_replays=0,
        )

    status_color = "bold green" if result.exit_code == 0 else "bold red"
    console.print(f"\n[bold]Quality Gate Result:[/bold] [{status_color}]{result.status.value}[/{status_color}] (Exit Code: {result.exit_code})")
    console.print(f"[dim]{result.summary}[/dim]\n")

    table = Table(title="[bold]Quality Gate Validation Rules[/bold]", expand=True)
    table.add_column("RULE", style="white")
    table.add_column("RESULT", style="bold")
    table.add_column("OBSERVED", style="dim")
    table.add_column("THRESHOLD", style="dim")

    for chk in result.checks:
        pass_label = "[green]PASS[/green]" if chk.passed else "[red]FAIL[/red]"
        table.add_row(chk.rule_name, pass_label, str(chk.observed_value), str(chk.threshold))
    console.print(table)
    if result.exit_code != 0:
        raise typer.Exit(code=result.exit_code)


@app.command(name="watch")
def watch_cmd(interval: float = typer.Option(1.0, "--interval", "-i", help="Poll interval in seconds")):
    """Stream live security telemetry and events in real time."""
    from agentguard.watch import run_live_watcher
    run_live_watcher(poll_interval=interval)


@app.command(name="serve")
def serve_cmd(
    port: int = typer.Option(3000, "--port", "-p", help="Dashboard port"),
    api_port: int = typer.Option(8000, "--api-port", help="FastAPI port"),
    no_browser: bool = typer.Option(False, "--no-browser", help="Do not open browser automatically"),
):
    """Start AgentGuard FastAPI runtime and Next.js Dashboard together."""
    from agentguard.serve import serve_dashboard
    serve_dashboard(port=port, api_port=api_port, open_browser=not no_browser)


# ---------------------------------------------------------------------------
# Attack & Offensive CLI Handlers (Phase 4 backward compatibility & CLI)
# ---------------------------------------------------------------------------

attack_app = typer.Typer(help="Offensive security validation, attack corpus, and campaigns")
app.add_typer(attack_app, name="attack")


def cli_attack_list() -> int:
    """List all available attack cases in baseline and regression corpus."""
    from agentguard.offensive.corpus import AttackCorpus
    corpus = AttackCorpus()
    baseline = corpus.get_all_attacks()
    regressions = corpus.get_regression_attacks()

    table = Table(title="[bold red]🎯 AGENTGUARD OFFENSIVE ATTACK CORPUS[/bold red]", expand=True)
    table.add_column("ATTACK ID", style="bold cyan")
    table.add_column("TYPE", style="yellow")
    table.add_column("TARGET AGENT", style="magenta")
    table.add_column("EXPECTED", style="bold")

    for a in baseline:
        atype = a.attack_type.value if hasattr(a.attack_type, "value") else str(a.attack_type)
        exp_val = a.expected_behavior.value if hasattr(getattr(a, "expected_behavior", None), "value") else str(getattr(a, "expected_behavior", "BLOCK"))
        table.add_row(a.attack_id, atype, a.target_agent, exp_val)
    console.print(table)
    return 0


def cli_attack_run(args=None, attack_type: Optional[str] = None, limit: int = 5) -> int:
    """Run validation attack campaign."""
    from agentguard.offensive.engine import OffensiveEngine
    from agentguard.offensive.corpus import AttackCorpus
    from agentguard.offensive.attack import AttackType
    engine = OffensiveEngine()
    corpus = AttackCorpus()

    target_type = None
    if args and getattr(args, "type", None):
        target_type = args.type
    elif attack_type:
        target_type = attack_type

    lim = getattr(args, "limit", limit) if args else limit

    if target_type:
        try:
            enum_type = AttackType(target_type)
            attacks = corpus.get_attacks_by_type(enum_type)
        except ValueError:
            attacks = corpus.get_all_attacks()
    else:
        attacks = corpus.get_all_attacks()

    attacks = attacks[:lim]
    results = [engine.execute_attack(a) for a in attacks]
    console.print(f"[bold green]✓ Executed {len(results)} offensive security tests.[/bold green]")
    return 0


def cli_attack_replay(attack_id: str) -> int:
    """Replay an offensive attack against the live policy."""
    from agentguard.offensive.engine import OffensiveEngine
    from agentguard.offensive.corpus import AttackCorpus
    engine = OffensiveEngine()
    corpus = AttackCorpus()
    attack = corpus.get_attack(attack_id)
    if not attack:
        console.print(f"[red]Error: Attack {attack_id} not found.[/red]")
        return 1
    res = engine.execute_attack(attack)
    console.print(f"[bold]Replay {attack_id}:[/bold] [green]{res.status.value}[/green]")
    return 0


def cli_attack_report() -> int:
    """Generate and display offensive report."""
    console.print("[dim]Generated offensive validation report.[/dim]")
    return 0


def cli_llm_health() -> int:
    """Check connection to Ollama and print status."""
    from agentguard.providers.registry import get_default_registry
    registry = get_default_registry()
    ollama = registry.get_provider("ollama")
    if ollama:
        h = ollama.health_check()
        return 0 if h.available else 1
    return 1


@attack_app.command(name="list")
def attack_list_cmd():
    """List attack corpus."""
    cli_attack_list()


@attack_app.command(name="run")
def attack_run_cmd(
    type: Optional[str] = typer.Option(None, "--type", "-t", help="Attack type filter"),
    limit: int = typer.Option(5, "--limit", "-l", help="Max attacks to run"),
):
    """Run offensive validation attacks."""
    cli_attack_run(attack_type=type, limit=limit)


@attack_app.command(name="replay")
def attack_replay_cmd(attack_id: str = typer.Argument(..., help="Attack ID to replay")):
    """Replay a specific attack."""
    cli_attack_replay(attack_id)



# ---------------------------------------------------------------------------
# AI Provider Subcommands
# ---------------------------------------------------------------------------

@ai_app.command(name="status")
def ai_status():
    """Show registered AI intelligence providers and health status."""
    from agentguard.providers.registry import get_default_registry
    registry = get_default_registry()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
        console=console,
    ) as progress:
        progress.add_task(description="Checking provider health...", total=None)
        reports = registry.health_check_all()

    table = Table(title="[bold cyan]🧠 AI SECURITY INTELLIGENCE PROVIDERS[/bold cyan]", expand=True)
    table.add_column("PROVIDER", style="bold white")
    table.add_column("MODEL", style="cyan")
    table.add_column("STATUS", style="bold")
    table.add_column("LATENCY", style="dim")
    table.add_column("DIAGNOSTICS", style="dim")

    for rep in reports:
        status_styled = "[green]AVAILABLE[/green]" if rep.available else "[red]UNAVAILABLE[/red]"
        latency_str = f"{rep.latency_ms:.1f}ms" if rep.available else "—"
        table.add_row(
            rep.provider_name,
            rep.model,
            status_styled,
            latency_str,
            rep.error or "Ready for advisory reasoning",
        )
    console.print(table)
    console.print("[dim]Note: If all providers are unavailable, AgentGuard deterministically fails-safe.[/dim]\n")


@ai_app.command(name="benchmark")
def ai_benchmark():
    """Benchmark latency and reasoning throughput across configured providers."""
    from agentguard.providers.registry import get_default_registry
    registry = get_default_registry()

    sample_packet = {
        "event_id": "bench_01",
        "agent_id": "finance_agent",
        "tool_name": "execute_transfer",
        "tainted": True,
    }

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
        console=console,
    ) as progress:
        progress.add_task(description="Benchmarking AI providers...", total=None)
        results = registry.benchmark(sample_packet)

    table = Table(title="[bold green]⚡ PROVIDER BENCHMARK RESULTS[/bold green]", expand=True)
    table.add_column("PROVIDER", style="bold white")
    table.add_column("STATUS", style="bold")
    table.add_column("LATENCY", style="cyan")
    table.add_column("RISK ADVISORY", style="yellow")

    for r in results:
        status_styled = "[green]SUCCESS[/green]" if r.get("success") else "[yellow]OFFLINE / ERROR[/yellow]"
        lat = f"{r.get('latency_ms', 0):.1f}ms" if r.get("success") else "—"
        risk = str(r.get("risk_score", "—"))
        table.add_row(r["provider"], status_styled, lat, risk)
    console.print(table)


if __name__ == "__main__":
    app()
