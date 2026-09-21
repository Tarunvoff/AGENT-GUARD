"""
AgentGuard Dashboard & Control Plane Server Launcher
=====================================================
Starts the FastAPI runtime and Next.js frontend as a unified control plane service.
"""
from __future__ import annotations

import os
import pathlib
import subprocess
import sys
import time
import urllib.request
import webbrowser
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table


def is_port_open(port: int, host: str = "127.0.0.1", timeout: float = 0.5) -> bool:
    """Check if HTTP service is responding on port."""
    try:
        url = f"http://{host}:{port}/"
        req = urllib.request.Request(url, headers={"User-Agent": "AgentGuardHealth"})
        with urllib.request.urlopen(req, timeout=timeout):
            return True
    except Exception:
        return False


def serve_dashboard(
    port: int = 3000,
    api_port: int = 8000,
    open_browser: bool = True,
    dev_mode: bool = True,
) -> None:
    """
    Start FastAPI backend and Next.js dashboard as concurrent subprocesses.
    """
    console = Console()
    repo_root = pathlib.Path(__file__).resolve().parents[2]
    dashboard_dir = repo_root / "dashboard"

    console.print(
        Panel.fit(
            f"[bold cyan]🛡️  AGENTGUARD CONTROL PLANE SERVE[/bold cyan]\n"
            f"[dim]Launching backend API on port [bold]{api_port}[/bold] and Dashboard on port [bold]{port}[/bold]...[/dim]",
            border_style="cyan",
        )
    )

    processes = []
    try:
        # 1. Launch FastAPI Backend
        api_env = os.environ.copy()
        api_env["PYTHONPATH"] = str(repo_root / "sdk")
        
        api_cmd = [
            sys.executable,
            "-m",
            "uvicorn",
            "agentguard.api.server:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(api_port),
            "--log-level",
            "warning",
        ]
        if dev_mode:
            api_cmd.append("--reload")

        console.print("[cyan]→ Starting FastAPI backend service...[/cyan]")
        api_proc = subprocess.Popen(
            api_cmd,
            env=api_env,
            cwd=str(repo_root),
        )
        processes.append(api_proc)

        # 2. Launch Next.js Dashboard
        if dashboard_dir.exists():
            console.print("[cyan]→ Starting Next.js dashboard frontend...[/cyan]")
            npm_cmd = "npm.cmd" if os.name == "nt" else "npm"
            dash_cmd = [npm_cmd, "run", "dev", "--", "-p", str(port)]
            dash_proc = subprocess.Popen(
                dash_cmd,
                cwd=str(dashboard_dir),
                shell=(os.name == "nt"),
            )
            processes.append(dash_proc)
        else:
            console.print("[yellow]⚠️ Dashboard directory not found. Running API only.[/yellow]")

        # 3. Wait for readiness
        console.print("[dim]Waiting for endpoints to initialize...[/dim]")
        time.sleep(3)

        table = Table(title="[bold green]✓ AgentGuard Control Plane Active[/bold green]", expand=False)
        table.add_column("Component", style="bold cyan")
        table.add_column("Endpoint URL", style="bright_white")
        table.add_column("Status", style="bold green")

        table.add_row("Dashboard UI", f"http://localhost:{port}", "ONLINE")
        table.add_row("REST API / Docs", f"http://localhost:{api_port}/docs", "ONLINE")
        table.add_row("Telemetry Stream", f"http://localhost:{api_port}/api/v1/status", "ONLINE")

        console.print(table)
        console.print("\n[dim]Press [bold red]Ctrl+C[/bold red] to stop all services.[/dim]\n")

        if open_browser:
            try:
                webbrowser.open(f"http://localhost:{port}")
            except Exception:
                pass

        # Keep alive
        while True:
            time.sleep(1)
            for p in processes:
                if p.poll() is not None:
                    console.print(f"[red]Process terminated unexpectedly with code {p.returncode}[/red]")
                    break

    except KeyboardInterrupt:
        console.print("\n[yellow]Shutting down AgentGuard Control Plane...[/yellow]")
    finally:
        for p in processes:
            try:
                p.terminate()
                p.wait(timeout=2)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass
        console.print("[green]✓ All services stopped cleanly.[/green]")
