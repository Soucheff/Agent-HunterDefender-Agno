from agno.tools.mcp import MCPTools
from pydantic import HttpUrl

from hunter_defender_agent.agents.identity import create_identity_agent
from hunter_defender_agent.config import Settings
from hunter_defender_agent.models.providers import create_ollama_model


def test_ollama_model_is_pinned_to_local_endpoint_without_api_key() -> None:
    model = create_ollama_model(Settings(ollama_host=HttpUrl("http://127.0.0.1:11434")))

    assert model.id == "gpt-oss:20b"
    assert model.host == "http://127.0.0.1:11434"
    assert model.api_key is None
    assert model.options == {"temperature": 0, "num_ctx": 16_384}
    assert model.request_params == {"think": False}


def test_identity_agent_has_bounded_tools_and_no_telemetry_or_storage() -> None:
    agent = create_identity_agent(
        create_ollama_model(Settings()),
        MCPTools(url="http://127.0.0.1:8000/mcp", transport="streamable-http"),
    )

    assert agent.tool_call_limit == 6
    assert agent.reasoning is False
    assert agent.telemetry is False
    assert agent.store_tool_messages is False
    assert agent.store_history_messages is False