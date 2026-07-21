from dataclasses import dataclass
from typing import Any

import httpx

from hunter_defender_agent.config import Settings


class OllamaCheckError(RuntimeError):
    """Raised when the Ollama readiness check cannot complete."""


@dataclass(frozen=True)
class OllamaStatus:
    endpoint: str
    model: str
    installed_models: tuple[str, ...]


class OllamaHealthClient:
    def __init__(
        self,
        settings: Settings,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._settings = settings
        self._transport = transport

    async def check(self) -> OllamaStatus:
        try:
            async with httpx.AsyncClient(
                base_url=self._settings.ollama_base_url,
                timeout=httpx.Timeout(self._settings.ollama_timeout_seconds, connect=5.0),
                transport=self._transport,
            ) as client:
                response = await client.get("/api/tags")
                response.raise_for_status()
        except httpx.TimeoutException as error:
            raise OllamaCheckError("Ollama request timed out") from error
        except httpx.HTTPStatusError as error:
            raise OllamaCheckError(
                f"Ollama returned HTTP {error.response.status_code}"
            ) from error
        except httpx.RequestError as error:
            raise OllamaCheckError(f"Ollama is unreachable: {error}") from error

        try:
            payload: dict[str, Any] = response.json()
            models = tuple(
                item["name"]
                for item in payload.get("models", [])
                if isinstance(item, dict) and isinstance(item.get("name"), str)
            )
        except (TypeError, ValueError) as error:
            raise OllamaCheckError("Ollama returned an invalid model list") from error

        if self._settings.ollama_model not in models:
            raise OllamaCheckError(
                f"model {self._settings.ollama_model!r} is not installed; available: {models}"
            )

        return OllamaStatus(
            endpoint=self._settings.ollama_base_url,
            model=self._settings.ollama_model,
            installed_models=models,
        )
