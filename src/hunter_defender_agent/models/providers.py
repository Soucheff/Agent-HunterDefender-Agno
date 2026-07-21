from agno.models.ollama import Ollama

from hunter_defender_agent.config import Settings


def create_ollama_model(settings: Settings) -> Ollama:
    """Create an explicitly local Ollama model with deterministic defaults."""
    return Ollama(
        id=settings.ollama_model,
        host=settings.ollama_base_url,
        api_key=None,
        timeout=settings.ollama_timeout_seconds,
        keep_alive=settings.ollama_keep_alive,
        options={
            "temperature": 0,
            "num_ctx": settings.ollama_context_length,
        },
        request_params={"think": False},
    )
