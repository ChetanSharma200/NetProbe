from rich.console import Console
from rich.panel import Panel
from rich.text import Text

console = Console()

banner = Text("""
███╗   ██╗███████╗████████╗██████╗ ██████╗  ██████╗ ██████╗ ███████╗
████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██╔══██╗██╔═══██╗██╔══██╗██╔════╝
██╔██╗ ██║█████╗     ██║   ██████╔╝██████╔╝██║   ██║██████╔╝█████╗
██║╚██╗██║██╔══╝     ██║   ██╔═══╝ ██╔══██╗██║   ██║██╔══██╗██╔══╝
██║ ╚████║███████╗   ██║   ██║     ██║  ██║╚██████╔╝██████╔╝███████╗
╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝
""", style="bold bright_green")


def prints_banner() -> None:
  console.print(banner)

  console.print(
      Panel.fit(
        "[bold white]Network Reconnaissance & Port Scanning Framework[/bold white]\n\n"
        "[cyan]►[/cyan] Host Discovery\n"
        "[cyan]►[/cyan] TCP/UDP Port Scanning\n"
        "[cyan]►[/cyan] Service Detection\n"
        "[cyan]►[/cyan] Banner Grabbing\n"
        "[yellow]Author  :[/yellow] Chetan Sharma",
        title="[bold green]NetProbe[/bold green]",
        border_style="cyan",
        padding=(1, 2),
    )
  )