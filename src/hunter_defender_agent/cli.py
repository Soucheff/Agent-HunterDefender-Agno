import asyncio

import typer
from rich.console import Console
from rich.table import Table

from hunter_defender_agent.auth.sidecar import AgentIdentitySidecarClient, SidecarError
from hunter_defender_agent.auth.user_session import (
    UserAuthenticationError,
    UserSessionAuthenticator,
)
from hunter_defender_agent.config import EntraConfigurationError, get_settings
from hunter_defender_agent.ollama import OllamaCheckError, OllamaHealthClient

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


if __name__ == "__main__":
    app()
