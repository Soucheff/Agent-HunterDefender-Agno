import asyncio

import typer
from rich.console import Console
from rich.markdown import Markdown
from rich.table import Table

from hunter_defender_agent.auth.sidecar import AgentIdentitySidecarClient, SidecarError
from hunter_defender_agent.auth.user_session import (
    UserAuthenticationError,
    UserSessionAuthenticator,
)
from hunter_defender_agent.config import EntraConfigurationError, get_settings
from hunter_defender_agent.ollama import OllamaCheckError, OllamaHealthClient
from hunter_defender_agent.runtime import (
    IdentityInvestigationError,
    IdentityInvestigationRunner,
    InvestigationRequest,
)

app = typer.Typer(no_args_is_help=True, help="Hunter Defender identity analysis agent.")
console = Console()


@app.callback()
def main() -> None:
    """Run Hunter Defender identity analysis commands."""


@app.command()
def doctor() -> None:
    """Check local configuration and runtime dependencies."""
    settings = get_settings()
    rows: list[tuple[str, str, str]] = []

    try:
        status = asyncio.run(OllamaHealthClient(settings).check())
    except OllamaCheckError as error:
        console.print(f"[bold red]FAIL[/bold red] Ollama: {error}")
        raise typer.Exit(code=1) from error

    rows.extend(
        [
            ("Ollama", "[green]PASS[/green]", status.endpoint),
            ("Model", "[green]PASS[/green]", status.model),
            ("Context", "[green]PASS[/green]", str(settings.ollama_context_length)),
        ]
    )

    if settings.missing_entra_settings:
        rows.append(
            (
                "Entra/Sidecar",
                "[yellow]SKIP[/yellow]",
                "missing: " + ", ".join(settings.missing_entra_settings),
            )
        )
    else:
        sidecar = AgentIdentitySidecarClient(
            settings.entra_sidecar_base_url,
            settings.entra_timeout_seconds,
        )
        try:
            sidecar_status = asyncio.run(sidecar.check_health())
            rows.append(("Entra sidecar", "[green]PASS[/green]", sidecar_status.endpoint))
        except SidecarError as error:
            rows.append(("Entra sidecar", "[red]FAIL[/red]", str(error)))

    table = Table(title="Hunter Defender Doctor")
    table.add_column("Dependency")
    table.add_column("Status")
    table.add_column("Details")
    for row in rows:
        table.add_row(*row)
    console.print(table)


@app.command()
def login() -> None:
    """Sign in with Microsoft Entra ID using the system browser."""
    settings = get_settings()
    try:
        token = UserSessionAuthenticator(settings).acquire_token()
    except (EntraConfigurationError, UserAuthenticationError) as error:
        console.print(f"[bold red]FAIL[/bold red] Login: {error}")
        raise typer.Exit(code=1) from error

    identity = token.username or "authenticated user"
    console.print(f"[green]PASS[/green] Signed in as {identity}")


@app.command()
def logout() -> None:
    """Remove the locally cached Microsoft Entra session."""
    settings = get_settings()
    try:
        UserSessionAuthenticator(settings).logout()
    except EntraConfigurationError as error:
        console.print(f"[bold red]FAIL[/bold red] Logout: {error}")
        raise typer.Exit(code=1) from error

    console.print("[green]PASS[/green] Local Entra session removed")


@app.command(name="investigate-user")
def investigate_user(
    user_upn: str = typer.Argument(..., help="User principal name to investigate."),
    days_back: int = typer.Option(7, "--days-back", min=1, max=30, help="Lookback window in days."),
) -> None:
    """Run a one-shot read-only identity investigation for a user."""
    settings = get_settings()
    try:
        runner = IdentityInvestigationRunner.from_settings(settings)
        report = asyncio.run(
            runner.investigate(InvestigationRequest(user_upn=user_upn, days_back=days_back))
        )
    except (EntraConfigurationError, IdentityInvestigationError) as error:
        console.print(f"[bold red]FAIL[/bold red] {error}")
        raise typer.Exit(code=1) from error
    except (UserAuthenticationError, SidecarError) as error:
        console.print(f"[bold red]FAIL[/bold red] Authentication: {error}")
        raise typer.Exit(code=1) from error

    console.print(Markdown(report))


@app.command()
def chat() -> None:
    """Start an interactive read-only identity analysis session."""
    settings = get_settings()
    try:
        runner = IdentityInvestigationRunner.from_settings(settings)
    except EntraConfigurationError as error:
        console.print(f"[bold red]FAIL[/bold red] {error}")
        raise typer.Exit(code=1) from error

    try:
        asyncio.run(_run_chat(runner))
    except (UserAuthenticationError, SidecarError) as error:
        console.print(f"[bold red]FAIL[/bold red] Authentication: {error}")
        raise typer.Exit(code=1) from error


async def _run_chat(runner: IdentityInvestigationRunner) -> None:
    console.print(
        "[bold]Hunter Defender identity chat[/bold] (read-only).\n"
        "Ask in natural language and include the user and the time window, for example:\n"
        "  investigate alice@contoso.com over the last 14 days\n"
        "Type 'exit' or 'quit' to leave.\n"
    )
    async with runner.chat_session() as session:
        while True:
            try:
                message = console.input("[bold cyan]you[/bold cyan] > ")
            except (EOFError, KeyboardInterrupt):
                console.print()
                return
            command = message.strip()
            if command.lower() in {"exit", "quit"}:
                return
            if not command:
                continue
            with console.status("[dim]analyzing…[/dim]"):
                reply = await session.ask(command)
            console.print(Markdown(reply))


if __name__ == "__main__":
    app()
