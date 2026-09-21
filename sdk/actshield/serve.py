"""
ActShield Dashboard & Control Plane Server Launcher
=====================================================
Starts the unified control plane service (FastAPI API + Embedded Dashboard).
"""
from __future__ import annotations

import os
import pathlib
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
        url = f"http://{host}:{port}/api/v1/health"
        req = urllib.request.Request(url, headers={"User-Agent": "AgentGuardHealth"})
        with urllib.request.urlopen(req, timeout=timeout):
            return True
    except Exception:
        return False


def serve_dashboard(
    port: int = 8000,
    api_port: Optional[int] = None,
    open_browser: bool = True,
    host: str = "127.0.0.1",
    dev_mode: bool = False,
) -> None:
    """
    Start the unified ActShield Control Plane server.
    Serves:
      - / → Embedded Dashboard UI
      - /api/v1/* → FastAPI Backend API
      - /docs → OpenAPI Swagger UI
      - /redoc → ReDoc UI
    """
    console = Console()
    repo_root = pathlib.Path(__file__).resolve().parents[2]
    dashboard_dir = repo_root / "dashboard"
    target_port = api_port or port

    console.print(
        Panel.fit(
            f"[bold cyan]🛡️  ActShield / AgentGuard CONTROL PLANE[/bold cyan]\n"
            f"[dim]Serving unified dashboard and API on [bold]http://{host}:{target_port}[/bold][/dim]",
            border_style="cyan",
        )
    )

    if dev_mode and dashboard_dir.exists():
        import subprocess
        console.print("[yellow]→ Dev Mode: Starting separate backend and Next.js dev server...[/yellow]")
        api_env = os.environ.copy()
        api_env["PYTHONPATH"] = str(repo_root / "sdk")
        api_proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "actshield.api.server:app", "--host", host, "--port", str(target_port), "--reload"],
            env=api_env,
            cwd=str(repo_root),
        )
        npm_cmd = "npm.cmd" if os.name == "nt" else "npm"
        dash_proc = subprocess.Popen(
            [npm_cmd, "run", "dev", "--", "-p", "3000"],
            cwd=str(dashboard_dir),
            shell=(os.name == "nt"),
        )
        try:
            time.sleep(2)
            if open_browser:
                webbrowser.open("http://localhost:3000")
            while True:
                time.sleep(1)
                if api_proc.poll() is not None or dash_proc.poll() is not None:
                    break
        except KeyboardInterrupt:
            pass
        finally:
            api_proc.terminate()
            dash_proc.terminate()
        return

    # Production Embedded Server Mode (Zero Node.js/npm required)
    table = Table(title="[bold green]✓ ActShield Control Plane Active[/bold green]", expand=False)
    table.add_column("Component", style="bold cyan")
    table.add_column("Endpoint URL", style="bright_white")
    table.add_column("Status", style="bold green")

    table.add_row("Dashboard UI", f"http://{host}:{target_port}/", "ONLINE")
    table.add_row("API Overview", f"http://{host}:{target_port}/api/v1/overview", "ONLINE")
    table.add_row("Swagger Docs", f"http://{host}:{target_port}/docs", "ONLINE")
    table.add_row("ReDoc", f"http://{host}:{target_port}/redoc", "ONLINE")

    console.print(table)
    console.print(f"\n[dim]Running on http://{host}:{target_port}. Press [bold red]Ctrl+C[/bold red] to stop.[/dim]\n")

    if open_browser:
        try:
            webbrowser.open(f"http://{host}:{target_port}")
        except Exception:
            pass

    import uvicorn
    from actshield.api.server import app

    uvicorn.run(app, host=host, port=target_port, log_level="warning")



