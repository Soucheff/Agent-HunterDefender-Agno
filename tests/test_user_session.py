from collections.abc import Mapping, Sequence
from uuid import UUID

import msal
import pytest

from hunter_defender_agent.auth.user_session import (
    ApplicationFactory,
    MsalApplication,
    UserAuthenticationError,
    UserSessionAuthenticator,
)
from hunter_defender_agent.config import Settings


class MemoryStore:
    def __init__(self) -> None:
        self.value: str | None = None
        self.deleted = False

    def load(self) -> str | None:
        return self.value

    def save(self, serialized_cache: str) -> None:
        self.value = serialized_cache

    def delete(self) -> None:
        self.deleted = True
        self.value = None


class FakeApplication:
    def __init__(
        self,
        silent_result: dict[str, object] | None,
        interactive_result: dict[str, object],
    ) -> None:
        self.silent_result = silent_result
        self.interactive_result = interactive_result
        self.interactive_calls = 0

    def get_accounts(self) -> list[dict[str, object]]:
        return [{"home_account_id": "account"}]

    def acquire_token_silent(
        self,
        scopes: Sequence[str],
        account: Mapping[str, object],
    ) -> dict[str, object] | None:
        assert isinstance(scopes, list)
        return self.silent_result

    def acquire_token_interactive(self, scopes: Sequence[str]) -> dict[str, object]:
        assert isinstance(scopes, list)
        self.interactive_calls += 1
        return self.interactive_result


def configured_settings() -> Settings:
    return Settings(
        azure_tenant_id=UUID("11111111-1111-1111-1111-111111111111"),
        entra_cli_client_id=UUID("22222222-2222-2222-2222-222222222222"),
        entra_agent_identity_client_id=UUID("33333333-3333-3333-3333-333333333333"),
        entra_user_scope="api://blueprint/access_as_user",
        entra_mcp_scope="api://mcp/Mcp.Access",
    )


def factory_for(application: MsalApplication) -> ApplicationFactory:
    def factory(
        client_id: str,
        authority: str,
        cache: msal.SerializableTokenCache,
    ) -> MsalApplication:
        assert client_id == "22222222-2222-2222-2222-222222222222"
        assert authority.endswith("/11111111-1111-1111-1111-111111111111")
        return application

    return factory


def test_silent_token_is_preferred() -> None:
    application = FakeApplication(
        {"access_token": "silent", "id_token_claims": {"preferred_username": "user@test"}},
        {"access_token": "interactive"},
    )
    authenticator = UserSessionAuthenticator(
        configured_settings(),
        store=MemoryStore(),
        application_factory=factory_for(application),
    )

    token = authenticator.acquire_token()

    assert token.value == "silent"
    assert token.username == "user@test"
    assert application.interactive_calls == 0


def test_interactive_login_is_used_after_cache_miss() -> None:
    application = FakeApplication(None, {"access_token": "interactive"})
    authenticator = UserSessionAuthenticator(
        configured_settings(),
        store=MemoryStore(),
        application_factory=factory_for(application),
    )

    assert authenticator.acquire_token().value == "interactive"
    assert application.interactive_calls == 1


def test_authentication_error_does_not_include_description_or_token() -> None:
    application = FakeApplication(
        None,
        {
            "error": "access_denied",
            "error_description": "secret response body",
            "correlation_id": "correlation-id",
        },
    )
    authenticator = UserSessionAuthenticator(
        configured_settings(),
        store=MemoryStore(),
        application_factory=factory_for(application),
    )

    with pytest.raises(UserAuthenticationError) as captured:
        authenticator.acquire_token()

    assert str(captured.value) == "Entra authentication failed (access_denied, correlation-id)"
    assert "secret response body" not in str(captured.value)