import pytest
from pydantic import HttpUrl, ValidationError

from hunter_defender_agent.config import EntraConfigurationError, Settings


def test_default_ollama_configuration() -> None:
    settings = Settings(ollama_host=HttpUrl("http://127.0.0.1:11434"))

    assert settings.ollama_base_url == "http://127.0.0.1:11434"
    assert settings.ollama_model == "gpt-oss:20b"
    assert settings.ollama_context_length == 16_384


def test_context_below_security_baseline_is_rejected() -> None:
    with pytest.raises(ValidationError):
        Settings(ollama_context_length=4096)


def test_entra_runtime_requires_all_identity_settings() -> None:
    settings = Settings(
        azure_tenant_id=None,
        entra_cli_client_id=None,
        entra_agent_identity_client_id=None,
        entra_user_scope="api://blueprint/access_as_user",
        entra_mcp_scope="api://mcp/Mcp.Access",
    )

    with pytest.raises(EntraConfigurationError, match="AZURE_TENANT_ID"):
        settings.require_entra()
