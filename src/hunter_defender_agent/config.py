from functools import lru_cache
from uuid import UUID

from pydantic import Field, HttpUrl, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class EntraConfigurationError(ValueError):
    """Raised when an Entra operation is requested without complete settings."""


class Settings(BaseSettings):
    """Runtime settings loaded from environment variables or a local .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        frozen=True,
        populate_by_name=True,
    )

    ollama_host: HttpUrl = Field(
        default=HttpUrl("http://127.0.0.1:11434"),
        validation_alias="OLLAMA_HOST",
    )
    ollama_model: str = Field(default="gpt-oss:20b", validation_alias="OLLAMA_MODEL")
    ollama_context_length: int = Field(
        default=16_384,
        ge=16_384,
        validation_alias="OLLAMA_CONTEXT_LENGTH",
    )
    ollama_keep_alive: str = Field(default="30m", validation_alias="OLLAMA_KEEP_ALIVE")
    ollama_timeout_seconds: float = Field(
        default=120.0,
        gt=0,
        le=600,
        validation_alias="OLLAMA_TIMEOUT_SECONDS",
    )
    azure_tenant_id: UUID | None = Field(default=None, validation_alias="AZURE_TENANT_ID")
    entra_cli_client_id: UUID | None = Field(default=None, validation_alias="ENTRA_CLI_CLIENT_ID")
    entra_agent_identity_client_id: UUID | None = Field(
        default=None,
        validation_alias="ENTRA_AGENT_IDENTITY_CLIENT_ID",
    )
    entra_user_scope: str | None = Field(default=None, validation_alias="ENTRA_USER_SCOPE")
    entra_mcp_scope: str | None = Field(default=None, validation_alias="ENTRA_MCP_SCOPE")
    hunter_defender_mcp_url: HttpUrl = Field(
        default=HttpUrl("http://127.0.0.1:8000/mcp"),
        validation_alias="HUNTER_DEFENDER_MCP_URL",
    )
    entra_sidecar_url: HttpUrl = Field(
        default=HttpUrl("http://127.0.0.1:5000"),
        validation_alias="ENTRA_SIDECAR_URL",
    )
    entra_sidecar_service_name: str = Field(
        default="HunterDefenderMcp",
        validation_alias="ENTRA_SIDECAR_SERVICE_NAME",
    )
    entra_timeout_seconds: float = Field(
        default=30.0,
        gt=0,
        le=120,
        validation_alias="ENTRA_TIMEOUT_SECONDS",
    )

    @field_validator("ollama_model", "ollama_keep_alive", "entra_sidecar_service_name")
    @classmethod
    def reject_blank_values(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("value must not be blank")
        return normalized

    @property
    def ollama_base_url(self) -> str:
        return str(self.ollama_host).rstrip("/")

    @property
    def entra_sidecar_base_url(self) -> str:
        return str(self.entra_sidecar_url).rstrip("/")

    @property
    def missing_entra_settings(self) -> tuple[str, ...]:
        required = {
            "AZURE_TENANT_ID": self.azure_tenant_id,
            "ENTRA_CLI_CLIENT_ID": self.entra_cli_client_id,
            "ENTRA_AGENT_IDENTITY_CLIENT_ID": self.entra_agent_identity_client_id,
            "ENTRA_USER_SCOPE": self.entra_user_scope,
            "ENTRA_MCP_SCOPE": self.entra_mcp_scope,
        }
        return tuple(name for name, value in required.items() if value is None)

    def require_entra(self) -> None:
        if missing := self.missing_entra_settings:
            raise EntraConfigurationError(
                "missing Entra settings: " + ", ".join(missing)
            )


@lru_cache
def get_settings() -> Settings:
    return Settings()
