from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol, cast

import keyring
import msal

from hunter_defender_agent.config import Settings


class UserAuthenticationError(RuntimeError):
    """Raised when delegated user authentication cannot complete."""


class TokenCacheStore(Protocol):
    def load(self) -> str | None: ...

    def save(self, serialized_cache: str) -> None: ...

    def delete(self) -> None: ...


class MsalApplication(Protocol):
    def get_accounts(self) -> list[dict[str, object]]: ...

    def acquire_token_silent(
        self,
        scopes: Sequence[str],
        account: Mapping[str, object],
    ) -> dict[str, object] | None: ...

    def acquire_token_interactive(self, scopes: Sequence[str]) -> dict[str, object]: ...


ApplicationFactory = Callable[[str, str, msal.SerializableTokenCache], MsalApplication]


@dataclass(frozen=True)
class UserAccessToken:
    value: str
    username: str | None


class KeyringTokenCacheStore:
    def __init__(self, tenant_id: str, client_id: str) -> None:
        self._service = "hunter-defender-agent"
        self._account = f"{tenant_id}:{client_id}"

    def load(self) -> str | None:
        return keyring.get_password(self._service, self._account)

    def save(self, serialized_cache: str) -> None:
        keyring.set_password(self._service, self._account, serialized_cache)

    def delete(self) -> None:
        try:
            keyring.delete_password(self._service, self._account)
        except keyring.errors.PasswordDeleteError:
            pass


class UserSessionAuthenticator:
    def __init__(
        self,
        settings: Settings,
        store: TokenCacheStore | None = None,
        application_factory: ApplicationFactory | None = None,
    ) -> None:
        settings.require_entra()
        assert settings.azure_tenant_id is not None
        assert settings.entra_cli_client_id is not None
        assert settings.entra_user_scope is not None

        self._tenant_id = str(settings.azure_tenant_id)
        self._client_id = str(settings.entra_cli_client_id)
        self._scopes = [settings.entra_user_scope]
        self._store = store or KeyringTokenCacheStore(self._tenant_id, self._client_id)
        self._application_factory = application_factory or self._default_application_factory

    def acquire_token(self) -> UserAccessToken:
        cache = msal.SerializableTokenCache()
        if serialized_cache := self._store.load():
            cache.deserialize(serialized_cache)

        application = self._application_factory(
            self._client_id,
            f"https://login.microsoftonline.com/{self._tenant_id}",
            cache,
        )

        result: dict[str, object] | None = None
        accounts = application.get_accounts()
        if accounts:
            result = application.acquire_token_silent(self._scopes, account=accounts[0])
        if not result:
            result = application.acquire_token_interactive(self._scopes)

        if cache.has_state_changed:
            self._store.save(cache.serialize())

        access_token = result.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            error_code = result.get("error")
            correlation_id = result.get("correlation_id")
            details = ", ".join(
                str(item)
                for item in (error_code, correlation_id)
                if isinstance(item, str) and item
            )
            suffix = f" ({details})" if details else ""
            raise UserAuthenticationError(f"Entra authentication failed{suffix}")

        claims = result.get("id_token_claims")
        username = None
        if isinstance(claims, Mapping):
            candidate = claims.get("preferred_username")
            if isinstance(candidate, str):
                username = candidate

        return UserAccessToken(value=access_token, username=username)

    def logout(self) -> None:
        self._store.delete()

    @staticmethod
    def _default_application_factory(
        client_id: str,
        authority: str,
        cache: msal.SerializableTokenCache,
    ) -> MsalApplication:
        application = msal.PublicClientApplication(
            client_id=client_id,
            authority=authority,
            token_cache=cache,
        )
        return cast(MsalApplication, application)
