from typing import Any, cast
from uuid import UUID

import httpx
import pytest
from agno.tools.mcp import MCPTools

from hunter_defender_agent.auth.sidecar import AgentIdentitySidecarClient
from hunter_defender_agent.auth.user_session import UserAccessToken
from hunter_defender_agent.config import Settings
from hunter_defender_agent.mcp.defender import (
    IDENTITY_TOOL_ALLOWLIST,
    AuthorizationNotPreparedError,
    DelegatedMcpAuthorization,
    create_identity_mcp_tools,
)


class FakeUserTokenSource:
    def acquire_token(self) -> UserAccessToken:
        return UserAccessToken(value="user-token", username="user@test")


def configured_settings() -> Settings:
    return Settings(
        azure_tenant_id=UUID("11111111-1111-1111-1111-111111111111"),
        entra_cli_client_id=UUID("22222222-2222-2222-2222-222222222222"),
        entra_agent_identity_client_id=UUID("33333333-3333-3333-3333-333333333333"),
        entra_user_scope="api://blueprint/access_as_user",
        entra_mcp_scope="api://mcp/Mcp.Access",
    )


@pytest.mark.asyncio
async def test_authorization_must_be_refreshed_before_use() -> None:
    sidecar = AgentIdentitySidecarClient(
        "http://127.0.0.1:5000",
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                200,
                json={"authorizationHeader": "Bearer delegated-token"},
            )
        ),
    )
    authorization = DelegatedMcpAuthorization(
        configured_settings(),
        FakeUserTokenSource(),
        sidecar,
    )

    with pytest.raises(AuthorizationNotPreparedError):
        authorization.headers()

    await authorization.refresh()

    assert authorization.headers() == {"Authorization": "Bearer delegated-token"}
    authorization.clear()
    with pytest.raises(AuthorizationNotPreparedError):
        authorization.headers()


def test_mcp_factory_enforces_identity_allowlist_and_dynamic_headers() -> None:
    captured: dict[str, Any] = {}

    def fake_factory(**kwargs: Any) -> MCPTools:
        captured.update(kwargs)
        return cast(MCPTools, object())

    sidecar = AgentIdentitySidecarClient("http://127.0.0.1:5000")
    authorization = DelegatedMcpAuthorization(
        configured_settings(),
        FakeUserTokenSource(),
        sidecar,
    )

    create_identity_mcp_tools(configured_settings(), authorization, fake_factory)

    assert set(captured["include_tools"]) == IDENTITY_TOOL_ALLOWLIST
    assert captured["transport"] == "streamable-http"
    assert captured["refresh_connection"] is True
    assert captured["header_provider"] == authorization.headers