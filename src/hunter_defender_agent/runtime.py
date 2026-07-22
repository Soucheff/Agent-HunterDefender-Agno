import re
from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass
from typing import Any, Protocol

from agno.agent import Agent
from agno.models.base import Model

from hunter_defender_agent.agents.identity import create_identity_agent
from hunter_defender_agent.auth.sidecar import AgentIdentitySidecarClient
from hunter_defender_agent.auth.user_session import UserSessionAuthenticator
from hunter_defender_agent.config import Settings
from hunter_defender_agent.mcp.defender import (
    DelegatedMcpAuthorization,
    create_identity_mcp_tools,
)
from hunter_defender_agent.models.providers import create_ollama_model

MAX_DAYS_BACK = 30
_UPN_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class IdentityInvestigationError(RuntimeError):
    """Raised for invalid investigation input or a failed investigation run."""


class Authorization(Protocol):
    async def refresh(self) -> None: ...

    def clear(self) -> None: ...


class AgentFactory(Protocol):
    def __call__(self, model: Any, tools: Any, *, enable_history: bool = ...) -> Agent: ...


def validate_user_upn(value: str) -> str:
    upn = value.strip()
    if not _UPN_PATTERN.match(upn):
        raise IdentityInvestigationError(f"invalid user principal name: {value!r}")
    return upn


def validate_days_back(value: int) -> int:
    if not 1 <= value <= MAX_DAYS_BACK:
        raise IdentityInvestigationError(f"days_back must be between 1 and {MAX_DAYS_BACK}")
    return value


def build_investigation_prompt(user_upn: str, days_back: int) -> str:
    return (
        f"Investigate the Microsoft Entra identity {user_upn} over the last {days_back} days.\n"
        "Call investigate_user first, then request additional atomic identity tools only to close "
        "material evidence gaps.\n"
        "Produce a concise report with these sections:\n"
        "1. Summary and the risk signals actually observed.\n"
        "2. Evidence, with every line citing the source tool.\n"
        "3. Facts versus hypotheses, clearly separated.\n"
        "4. Coverage, including any partial failures or missing data.\n"
        "5. Prioritized recommendations for human review.\n"
        "Never perform or claim to have performed any change, notification, or remediation."
    )


@dataclass(frozen=True)
class InvestigationRequest:
    user_upn: str
    days_back: int


def _content(result: Any) -> str:
    text = result.get_content_as_string()
    return text.strip() if isinstance(text, str) else ""


class ChatSession:
    """A live identity chat bound to one MCP connection and rolling history."""

    def __init__(self, agent: Agent, authorization: Authorization) -> None:
        self._agent = agent
        self._authorization = authorization
        self._session_id = "hunter-defender-identity-chat"

    async def ask(self, message: str) -> str:
        await self._authorization.refresh()
        result = await self._agent.arun(message, session_id=self._session_id)
        return _content(result)


class IdentityInvestigationRunner:
    """Orchestrate delegated authentication, MCP tools, and the identity agent."""

    def __init__(
        self,
        *,
        authorization: Authorization,
        tools: AbstractAsyncContextManager[Any],
        model: Model,
        agent_factory: AgentFactory = create_identity_agent,
    ) -> None:
        self._authorization = authorization
        self._tools = tools
        self._model = model
        self._agent_factory = agent_factory

    @classmethod
    def from_settings(cls, settings: Settings) -> "IdentityInvestigationRunner":
        settings.require_entra()
        user_source = UserSessionAuthenticator(settings)
        sidecar = AgentIdentitySidecarClient(
            settings.entra_sidecar_base_url,
            settings.entra_timeout_seconds,
        )
        authorization = DelegatedMcpAuthorization(settings, user_source, sidecar)
        tools = create_identity_mcp_tools(settings, authorization)
        model = create_ollama_model(settings)
        return cls(authorization=authorization, tools=tools, model=model)

    async def investigate(self, request: InvestigationRequest) -> str:
        prompt = build_investigation_prompt(
            validate_user_upn(request.user_upn),
            validate_days_back(request.days_back),
        )
        await self._authorization.refresh()
        try:
            async with self._tools:
                agent = self._agent_factory(self._model, self._tools)
                result = await agent.arun(prompt)
                return _content(result)
        finally:
            self._authorization.clear()

    @asynccontextmanager
    async def chat_session(self) -> AsyncIterator[ChatSession]:
        await self._authorization.refresh()
        try:
            async with self._tools:
                agent = self._agent_factory(self._model, self._tools, enable_history=True)
                yield ChatSession(agent, self._authorization)
        finally:
            self._authorization.clear()


BuiltRunner = Callable[[Settings], IdentityInvestigationRunner]
