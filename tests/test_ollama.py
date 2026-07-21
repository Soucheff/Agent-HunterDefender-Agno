import httpx
import pytest

from hunter_defender_agent.config import Settings
from hunter_defender_agent.ollama import OllamaCheckError, OllamaHealthClient


@pytest.mark.asyncio
async def test_health_check_accepts_configured_model() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/tags"
        return httpx.Response(200, json={"models": [{"name": "gpt-oss:20b"}]})

    settings = Settings()
    status = await OllamaHealthClient(settings, httpx.MockTransport(handler)).check()

    assert status.model == "gpt-oss:20b"


@pytest.mark.asyncio
async def test_health_check_rejects_missing_model() -> None:
    transport = httpx.MockTransport(
        lambda request: httpx.Response(200, json={"models": [{"name": "qwen3"}]})
    )

    with pytest.raises(OllamaCheckError, match="is not installed"):
        await OllamaHealthClient(Settings(), transport).check()