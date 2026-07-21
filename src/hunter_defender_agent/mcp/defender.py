import asyncio
from collections.abc import Callable
from typing import Protocol

from agno.tools.mcp import MCPTools

from hunter_defender_agent.auth.sidecar import AgentIdentitySidecarClient
from hunter_defender_agent.auth.user_session import UserAccessToken
from hunter_defender_agent.config import Settings

IDENTITY_TOOL_ALLOWLIST = frozenset(
    {
        "investigate_user",
        "analyze_user_risk_profile",
        "get_signin_logs",
        "get_risky_users",
        "get_risky_signins",
        "get_audit_logs",
        "get_conditional_access_policies",
    }
)


class UserTokenSource(Protocol):
    def acquire_token(self) -> UserAccessToken: ...


class AuthorizationNotPreparedError(RuntimeError):
    """Raised when MCP headers are requested before delegated token refresh."""


class DelegatedMcpAuthorization:
    """Prepare a delegated Agent ID header before each Agno agent run."""

    def __init__(
        self,
        settings: Settings,
        user_token_source: UserTokenSource,
        sidecar: AgentIdentitySidecarClient,
    ) -> None:
        settings.require_entra()
        assert settings.entra_agent_identity_client_id is not None

        self._agent_identity_client_id = str(settings.entra_agent_identity_client_id)
        self._service_name = settings.entra_sidecar_service_name
        self._user_token_source = user_token_source
        self._sidecar = sidecar
        self._authorization_header: str | None = None

    async def refresh(self) -> None:
        user_token = await asyncio.to_thread(self._user_token_source.acquire_token)
        self._authorization_header = await self._sidecar.get_delegated_authorization_header(
            user_token.value,
            self._service_name,
            self._agent_identity_client_id,
        )

    def headers(self) -> dict[str, str]:
        if self._authorization_header is None:
            raise AuthorizationNotPreparedError(
                "delegated MCP authorization must be refreshed before the agent run"
            )
        return {"Authorization": self._authorization_header}

    def clear(self) -> None:
        self._authorization_header = None


McpToolsFactory = Callable[..., MCPTools]


def create_identity_mcp_tools(
    settings: Settings,
    authorization: DelegatedMcpAuthorization,
    tools_factory: McpToolsFactory = MCPTools,
) -> MCPTools:
    """Build read-only identity MCP tools with per-run delegated headers."""
    settings.require_entra()
    return tools_factory(
        name="hunter_defender_identity",
        url=str(settings.hunter_defender_mcp_url),
        transport="streamable-http",
        timeout_seconds=int(settings.entra_timeout_seconds),
        include_tools=sorted(IDENTITY_TOOL_ALLOWLIST),
        header_provider=authorization.headers,
        refresh_connection=True,
    )
