"""AgentGuard CLI Theme & Terminal Visual Identity.

Defines the dark-terminal visual palette:
- Electric Violet (#a78bfa), Electric Purple (#c084fc), Bright Cyan (#38bdf8), Pure White
- Semantic status colors: Green (allowed/healthy), Yellow (warning/monitor),
  Orange (HITL/degraded), Red (attack/violation/block), Purple (AgentGuard/AI/platform)
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

# Rich Custom Theme
AGENTGUARD_THEME = Theme(
    {
        "ag.brand": "bold rgb(167,139,250)",
        "ag.subbrand": "bold rgb(192,132,252)",
        "ag.header": "bold bright_white",
        "ag.dim": "dim white",
        "ag.highlight": "bold bright_cyan",
        # Semantic statuses
        "ag.healthy": "bold rgb(52,211,153)",
        "ag.allowed": "bold rgb(52,211,153)",
        "ag.monitor": "bold rgb(250,204,21)",
        "ag.warning": "bold rgb(250,204,21)",
        "ag.hitl": "bold rgb(251,146,60)",
        "ag.degraded": "bold rgb(251,146,60)",
        "ag.attack": "bold rgb(248,113,113)",
        "ag.violation": "bold rgb(248,113,113)",
        "ag.block": "bold rgb(248,113,113)",
        "ag.quarantined": "bold rgb(248,113,113)",
        "ag.platform": "bold rgb(167,139,250)",
        "ag.ai": "bold rgb(192,132,252)",
        "ag.apiris": "bold bright_cyan",
    }
)

console = Console(theme=AGENTGUARD_THEME)

ASCII_BANNER = r"""[bold rgb(167,139,250)]
    █████╗  ██████╗ ███████╗███╗   ██╗████████╗
   ██╔══██╗██╔════╝ ██╔════╝████╗  ██║╚══██╔══╝
   ███████║██║  ███╗█████╗  ██╔██╗ ██║   ██║   
   ██╔══██║██║   ██║██╔══╝  ██║╚██╗██║   ██║   
   ██║  ██║╚██████╔╝███████╗██║ ╚████║   ██║   
   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝   

    ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗   
   ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗  
   ██║  ███╗██║   ██║███████║██████╔╝██║  ██║  
   ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║  
   ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝  
    ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝   [/bold rgb(167,139,250)]

                 [bold white]AGENTGUARD[/bold white]
      [bold rgb(192,132,252)]SECURITY CONTROL PLANE[/bold rgb(192,132,252)]
    [bold rgb(192,132,252)]FOR AUTONOMOUS AI SYSTEMS[/bold rgb(192,132,252)]
               [bold bright_cyan]v0.9.0[/bold bright_cyan]
"""


def render_banner() -> None:
    """Render branded ASCII banner."""
    console.print(ASCII_BANNER)
