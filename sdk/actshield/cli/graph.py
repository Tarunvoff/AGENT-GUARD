"""ActShield Multi-Agent Topology & Graph Visualizer for CLI."""
from __future__ import annotations

from typing import Dict, List, Optional
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.tree import Tree

from actshield.agents.identity import AgentStatus, AgentTrustLevel
from actshield.client import ActShield


def render_agent_topology(guard: Optional[ActShield] = None) -> None:
    """Render the multi-agent execution and delegation topology graph."""
    console = Console()
    
    # Root user node
    tree = Tree("[bold white]USER (Principal / Origin)[/bold white]")
    
    # Orchestrator
    orch = tree.add("[bold magenta]ORCHESTRATOR [dim](orchestrator-001)[/dim] ● ACTIVE [green]HIGH TRUST[/green][/bold magenta]")
    
    # Research child
    research_branch = orch.add("[bold purple]RESEARCH [dim](research-agent-001)[/dim] ● ACTIVE [green]MEDIUM TRUST[/green][/bold purple]")
    mcp_node = research_branch.add("[bold bright_cyan]MCP GATEWAY [dim](upstream-docs)[/dim] [yellow]TAINT SENSITIVE[/yellow][/bold bright_cyan]")
    mcp_node.add("[dim white]TOOL: web_search [ALLOW][/dim white]")
    
    # Analysis child
    analysis_branch = orch.add("[bold purple]ANALYSIS [dim](analysis-agent-001)[/dim] ● ACTIVE [green]HIGH TRUST[/green][/bold purple]")
    data_node = analysis_branch.add("[bold rgb(249,115,22)]DATA PIPELINE [dim](db-reader)[/dim] [orange3]RESTRICTED[/orange3][/bold rgb(249,115,22)]")
    data_node.add("[dim white]TOOL: customer_db.read [PROTECTED / EVALUATED][/dim white]")
    
    # Quarantined / External branch
    external_branch = tree.add("[bold red]EXTERNAL MCP AGENT [dim](ext-untrusted-09)[/dim] ● QUARANTINED [red]UNTRUSTED[/red][/bold red]")
    external_branch.add("[bold red]VIOLATION: Authority Boundary Exceeded -> AUTO-QUARANTINED[/bold red]")

    console.print()
    console.print(
        Panel(
            tree,
            title="[bold magenta]🛡️  ActShield MULTI-AGENT SECURITY TOPOLOGY[/bold magenta]",
            subtitle="[dim white]Purple = Active Agent │ Red = Quarantined/Blocked │ Cyan = Gateway/MCP │ Orange = Sensitive Resource[/dim white]",
            border_style="magenta",
        )
    )
    console.print()


