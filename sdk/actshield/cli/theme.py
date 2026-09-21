"""ActShield CLI Theme & Terminal Visual Identity.

Defines the enterprise terminal palette:
- Primary: Steel Blue (#3b82f6), Slate (#64748b), Zinc White (#e4e4e7)
- Semantic status colors:
    Green  (#10b981) — allowed / healthy / pass
    Yellow (#f59e0b) — warning / monitor / degraded
    Orange (#f97316) — HITL / elevated
    Red    (#ef4444) — attack / violation / block / critical
    Blue   (#3b82f6) — ActShield platform / AI / intelligence
    Cyan   (#06b6d4) — APIRIS / external intelligence
"""
from __future__ import annotations

import sys
from rich.console import Console
from rich.theme import Theme

# Windows UTF-8 console output reconfiguration
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Rich Custom Theme — enterprise security palette
ACTSHIELD_THEME = Theme(
    {
        # Brand
        "ag.brand": "bold rgb(59,130,246)",       # steel blue
        "ag.subbrand": "bold rgb(100,116,139)",   # slate
        "ag.header": "bold rgb(228,228,231)",      # zinc white
        "ag.dim": "dim rgb(113,113,122)",          # zinc 500
        "ag.highlight": "bold rgb(6,182,212)",     # cyan
        "ag.label": "rgb(161,161,170)",            # zinc 400
        # Semantic statuses
        "ag.healthy": "bold rgb(16,185,129)",      # emerald 500
        "ag.allowed": "bold rgb(16,185,129)",
        "ag.pass": "bold rgb(16,185,129)",
        "ag.monitor": "bold rgb(245,158,11)",      # amber 500
        "ag.warning": "bold rgb(245,158,11)",
        "ag.hitl": "bold rgb(249,115,22)",         # orange 500
        "ag.degraded": "bold rgb(249,115,22)",
        "ag.elevated": "bold rgb(249,115,22)",
        "ag.attack": "bold rgb(239,68,68)",        # red 500
        "ag.violation": "bold rgb(239,68,68)",
        "ag.block": "bold rgb(239,68,68)",
        "ag.critical": "bold rgb(239,68,68)",
        "ag.quarantined": "bold rgb(239,68,68)",
        "ag.fail": "bold rgb(239,68,68)",
        # System components
        "ag.platform": "bold rgb(59,130,246)",     # blue — ActShield
        "ag.ai": "bold rgb(139,92,246)",           # violet — AI intelligence
        "ag.apiris": "bold rgb(6,182,212)",        # cyan — APIRIS
        "ag.mcp": "bold rgb(245,158,11)",          # amber — MCP (external, caution)
        "ag.id": "dim rgb(161,161,170)",           # IDs / timestamps
    }
)

console = Console(theme=ACTSHIELD_THEME)

# ActShield ASCII banner — block font
ASCII_BANNER = r"""[bold rgb(59,130,246)]
    █████╗  ██████╗████████╗███████╗██╗  ██╗██╗███████╗██╗     ██████╗
   ██╔══██╗██╔════╝╚══██╔══╝██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗
   ███████║██║        ██║   ███████╗███████║██║█████╗  ██║     ██║  ██║
   ██╔══██║██║        ██║   ╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║
   ██║  ██║╚██████╗   ██║   ███████║██║  ██║██║███████╗███████╗██████╔╝
   ╚═╝  ╚═╝ ╚═════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝
[/bold rgb(59,130,246)]
              [bold rgb(228,228,231)]Security Control Plane for Autonomous AI[/bold rgb(228,228,231)]
                           [bold rgb(100,116,139)]v0.9.0[/bold rgb(100,116,139)]
"""

STATUS_TEMPLATE = """\
  [ag.label]Runtime   [/ag.label]  {runtime}
  [ag.label]Policy    [/ag.label]  {policy}
  [ag.label]AI        [/ag.label]  {ai}
  [ag.label]APIRIS    [/ag.label]  {apiris}
  [ag.label]Dashboard [/ag.label]  {dashboard}
"""


def render_banner() -> None:
    """Render branded ASCII banner."""
    console.print(ASCII_BANNER)


def render_startup_status(
    *,
    runtime: str = "ONLINE",
    policy: str = "STRICT",
    ai: str = "AI SECURA",
    apiris: str = "READY",
    dashboard: str = "READY",
) -> None:
    """Render system startup status block."""
    def _fmt(label: str, style: str = "ag.healthy") -> str:
        return f"[{style}]● {label}[/{style}]"

    console.print(
        STATUS_TEMPLATE.format(
            runtime=_fmt(runtime),
            policy=_fmt(policy, "ag.platform"),
            ai=_fmt(ai, "ag.ai"),
            apiris=_fmt(apiris, "ag.apiris"),
            dashboard=_fmt(dashboard),
        )
    )
