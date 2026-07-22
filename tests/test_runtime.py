from typing import Any, cast

import pytest
from agno.models.base import Model

from hunter_defender_agent.runtime import (
    IdentityInvestigationError,
    IdentityInvestigationRunner,
    InvestigationRequest,
    build_investigation_prompt,
    validate_days_back,
    validate_user_upn,
)


class FakeAuthorization:
    def __init__(self, events: list[str]) -> None:
        self._events = events
        self.refresh_calls = 0
        self.clear_calls = 0

    async def refresh(self) -> None:
        self.refresh_calls += 1
        self._events.append("refresh")

    def clear(self) -> None:
        self.clear_calls += 1
        self._events.append("clear")


class FakeTools:
    def __init__(self, events: list[str]) -> None:
        self._events = events

    async def __aenter__(self) -> "FakeTools":
        self._events.append("tools_enter")
        return self

    async def __aexit__(self, *args: object) -> None:
        self._events.append("tools_exit")


class FakeRunResult:
    def __init__(self, content: str) -> None:
        self._content = content

    def get_content_as_string(self) -> str:
        return self._content


class FakeAgent:
    def __init__(self, events: list[str]) -> None:
        self._events = events
        self.inputs: list[str] = []

    async def arun(self, message: str, **kwargs: Any) -> FakeRunResult:
        self._events.append("arun")
        self.inputs.append(message)
        return FakeRunResult(f"report for: {message[:20]}")


def build_runner(events: list[str]) -> tuple[IdentityInvestigationRunner, FakeAgent]:
    agent = FakeAgent(events)

    def factory(model: Any, tools: Any, *, enable_history: bool = False) -> Any:
        events.append(f"factory(history={enable_history})")
        return agent

    runner = IdentityInvestigationRunner(
        authorization=FakeAuthorization(events),
        tools=FakeTools(events),
        model=cast(Model, object()),
        agent_factory=factory,
    )
    return runner, agent


def test_validate_user_upn_rejects_bad_values() -> None:
    with pytest.raises(IdentityInvestigationError):
        validate_user_upn("not-an-upn")
    assert validate_user_upn("  alice@contoso.com ") == "alice@contoso.com"


def test_validate_days_back_bounds() -> None:
    assert validate_days_back(30) == 30
    with pytest.raises(IdentityInvestigationError):
        validate_days_back(0)
    with pytest.raises(IdentityInvestigationError):
        validate_days_back(31)


def test_prompt_includes_subject_window_and_read_only_guardrail() -> None:
    prompt = build_investigation_prompt("alice@contoso.com", 7)
    assert "alice@contoso.com" in prompt
    assert "7 days" in prompt
    assert "investigate_user" in prompt
    assert "Never perform or claim" in prompt


@pytest.mark.asyncio
async def test_investigate_refreshes_before_connecting_and_clears_after() -> None:
    events: list[str] = []
    runner, agent = build_runner(events)

    report = await runner.investigate(
        InvestigationRequest(user_upn="alice@contoso.com", days_back=7)
    )

    assert report.startswith("report for:")
    assert events.index("refresh") < events.index("tools_enter")
    assert events.index("tools_enter") < events.index("arun")
    assert events.index("arun") < events.index("tools_exit")
    assert events[-1] == "clear"
    assert "alice@contoso.com" in agent.inputs[0]


@pytest.mark.asyncio
async def test_investigate_rejects_invalid_input_before_any_network() -> None:
    events: list[str] = []
    runner, _ = build_runner(events)

    with pytest.raises(IdentityInvestigationError):
        await runner.investigate(InvestigationRequest(user_upn="bad", days_back=7))

    assert events == []


@pytest.mark.asyncio
async def test_chat_session_enables_history_and_refreshes_each_turn() -> None:
    events: list[str] = []
    runner, agent = build_runner(events)

    async with runner.chat_session() as session:
        first = await session.ask("who signed in?")
        second = await session.ask("any risky sign-ins?")

    assert first.startswith("report for:")
    assert second.startswith("report for:")
    assert "factory(history=True)" in events
    assert events.count("refresh") == 3  # session start + two turns
    assert events[-1] == "clear"
    assert agent.inputs == ["who signed in?", "any risky sign-ins?"]
