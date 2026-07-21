from dataclasses import dataclass

import httpx
from pydantic import BaseModel, ConfigDict, ValidationError


class SidecarError(RuntimeError):
    """Raised when the Entra Agent ID sidecar cannot serve a request."""


class _AuthorizationHeaderResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    authorizationHeader: str


@dataclass(frozen=True)
class SidecarStatus:
    endpoint: str


class AgentIdentitySidecarClient:
    def __init__(
        self,
        base_url: str,
        timeout_seconds: float = 30.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._timeout_seconds = timeout_seconds
        self._transport = transport

    async def check_health(self) -> SidecarStatus:
        async with self._client() as client:
            try:
                response = await client.get("/healthz")
                response.raise_for_status()
            except httpx.HTTPError as error:
                raise SidecarError(self._safe_error("health check failed", error)) from error

        return SidecarStatus(endpoint=self._base_url)

    async def get_delegated_authorization_header(
        self,
        user_access_token: str,
        service_name: str,
        agent_identity_client_id: str,
    ) -> str:
        if not user_access_token.strip():
            raise ValueError("user access token must not be blank")
        if not service_name.strip():
            raise ValueError("service name must not be blank")
        if not agent_identity_client_id.strip():
            raise ValueError("agent identity client ID must not be blank")

        async with self._client() as client:
            try:
                response = await client.get(
                    f"/AuthorizationHeader/{service_name}",
                    params={"AgentIdentity": agent_identity_client_id},
                    headers={"Authorization": f"Bearer {user_access_token}"},
                )
                response.raise_for_status()
                payload = _AuthorizationHeaderResponse.model_validate(response.json())
            except httpx.HTTPStatusError as error:
                status = error.response.status_code
                category = "request rejected" if 400 <= status < 500 else "service unavailable"
                raise SidecarError(f"sidecar {category} (HTTP {status})") from error
            except httpx.HTTPError as error:
                raise SidecarError(self._safe_error("request failed", error)) from error
            except (ValueError, ValidationError) as error:
                raise SidecarError("sidecar returned an invalid authorization response") from error

        authorization_header = payload.authorizationHeader.strip()
        if not authorization_header.startswith("Bearer "):
            raise SidecarError("sidecar returned an unsupported authorization scheme")
        return authorization_header

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=self._base_url,
            headers={"Host": "localhost"},
            timeout=httpx.Timeout(self._timeout_seconds, connect=5.0),
            transport=self._transport,
        )

    @staticmethod
    def _safe_error(context: str, error: httpx.HTTPError) -> str:
        if isinstance(error, httpx.TimeoutException):
            return f"sidecar {context}: timed out"
        return f"sidecar {context}: connection error"
