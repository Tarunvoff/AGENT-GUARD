"""
AgentGuard Live Event Watcher
=============================
Renders a live terminal feed of security events, posture changes, and incidents using Rich.
"""
from __future__ import annotations

import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


def _get_severity_style(severity: str) -> str:
    s = str(severity).upper()
    if s in ("CRITICAL", "BLOCK", "DENY"):
        return "bold red"
    elif s in ("HIGH", "QUARANTINE", "RESTRICT"):
        return "bold yellow"
    elif s in ("MEDIUM", "SUSPICIOUS", "WARN"):
        return "yellow"
    elif s in ("LOW", "INFO", "ALLOW"):
        return "green"
    return "dim"


def generate_watch_table(events: List[Dict[str, Any]]) -> Table:
    """Generate a rich table for live events."""
    table = Table(
        title="[bold cyan]⚡ LIVE CAUSAL SECURITY EVENT STREAM[/bold cyan]",
        title_justify="left",
        border_style="dim white",
        header_style="bold bright_white on grey23",
        expand=True,
    )
    table.add_column("TIME", style="dim", width=12)
    table.add_column("EVENT ID", style="bold cyan", width=14)
    table.add_column("AGENT", style="magenta", width=16)
    table.add_column("ACTION / TOOL", style="white", width=22)
    table.add_column("DECISION", width=12)
    table.add_column("SEVERITY", width=12)
    table.add_column("DETAILS", style="dim", no_wrap=False)

    if not events:
        table.add_row(
            datetime.now(timezone.utc).strftime("%H:%M:%S"),
            "—",
            "—",
            "Waiting for live events...",
            "[green]PASS[/green]",
            "[dim]INFO[/dim]",
            "Telemetry stream listening on active runtime",
        )
        return table

    for ev in reversed(events[-15:]):
        ts = ev.get("timestamp", datetime.now(timezone.utc).strftime("%H:%M:%S"))
        if isinstance(ts, datetime):
            ts = ts.strftime("%H:%M:%S")
        elif "T" in str(ts):
            ts = str(ts).split("T")[1][:8]

        sev = ev.get("severity", "LOW")
        sev_styled = f"[{_get_severity_style(sev)}]{sev}[/{_get_severity_style(sev)}]"
        dec = ev.get("decision", "ALLOW")
        dec_styled = f"[{_get_severity_style(dec)}]{dec}[/{_get_severity_style(dec)}]"

        table.add_row(
            str(ts),
            str(ev.get("event_id", "evt_live"))[:12],
            str(ev.get("agent_id", "agent_main")),
            str(ev.get("tool_name", ev.get("action", "unknown"))),
            dec_styled,
            sev_styled,
            str(ev.get("reason", ev.get("details", "OK")))[:50],
        )

    return table


def run_live_watcher(poll_interval: float = 1.0, max_iterations: Optional[int] = None) -> None:
    """Run interactive continuous live event watcher."""
    console = Console()
    events_buffer: List[Dict[str, Any]] = []

    # Check if API or SDK runtime is active
    from agentguard.client import AgentGuard
    ag = AgentGuard()

    # Seed with initial telemetry if available
    try:
        if hasattr(ag, "forensics") and hasattr(ag.forensics, "get_all_events"):
            events_buffer = ag.forensics.get_all_events()
    except Exception:
        pass

    iteration = 0
    with Live(generate_watch_table(events_buffer), console=console, refresh_per_second=4, screen=False) as live:
        try:
            while max_iterations is None or iteration < max_iterations:
                time.sleep(poll_interval)
                iteration += 1

                # Poll live runtime state or mock trace if idle
                try:
                    from agentguard.posture import PostureEngine
                    posture = PostureEngine().evaluate_current_posture()
                except Exception:
                    pass

                live.update(generate_watch_table(events_buffer))
        except KeyboardInterrupt:
            console.print("\n[yellow]Live event watcher stopped.[/yellow]")
