import httpx
import pytest

from hunter_defender_agent.auth.sidecar import AgentIdentitySidecarClient, SidecarError


@pytest.mark.asyncio
async def test_delegated_header_forwards_user_token_and_agent_identity() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/AuthorizationHeader/HunterDefenderMcp"
        assert request.url.params["AgentIdentity"] == "agent-client-id"
        assert request.headers["Authorization"] == "Bearer user-token"
        return httpx.Response(200, json={"authorizationHeader": "Bearer delegated-token"})

    client = AgentIdentitySidecarClient(
        "http://127.0.0.1:5000",
        transport=httpx.MockTransport(handler),
    )

    header = await client.get_delegated_authorization_header(
        "user-token",
        "HunterDefenderMcp",
        "agent-client-id",
    )

    assert header == "Bearer delegated-token"


@pytest.mark.asyncio
async def test_client_error_does_not_expose_tokens_or_response_body() -> None:
    secret = "sensitive-user-token"
    transport = httpx.MockTransport(
        lambda request: httpx.Response(403, json={"detail": f"rejected {secret}"})
    )
    client = AgentIdentitySidecarClient("http://127.0.0.1:5000", transport=transport)

    with pytest.raises(SidecarError) as captured:
        await client.get_delegated_authorization_header(
            secret,
            "HunterDefenderMcp",
            "agent-client-id",
        )

    assert str(captured.value) == "sidecar request rejected (HTTP 403)"
    assert secret not in str(captured.value)


@pytest.mark.asyncio
async def test_invalid_authorization_scheme_is_rejected() -> None:
    transport = httpx.MockTransport(
        lambda request: httpx.Response(200, json={"authorizationHeader": "Basic value"})
    )
    client = AgentIdentitySidecarClient("http://127.0.0.1:5000", transport=transport)

    with pytest.raises(SidecarError, match="unsupported authorization scheme"):
        await client.get_delegated_authorization_header(
            "user-token",
            "HunterDefenderMcp",
            "agent-client-id",
        )