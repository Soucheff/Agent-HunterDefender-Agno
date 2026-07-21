import json
from pathlib import Path
from typing import Any

import pytest

from hunter_defender_agent.mcp.defender import IDENTITY_TOOL_ALLOWLIST


def test_identity_allowlist_exists_and_is_read_only_in_mcp_contract() -> None:
    contract_path = (
        Path(__file__).resolve().parents[2]
        / "HunterDefenderMCP"
        / "contracts"
        / "defender-hunt-mcp.v1.json"
    )
    if not contract_path.exists():
        pytest.skip(f"Hunter Defender MCP contract is not available at {contract_path}")
    contract: dict[str, Any] = json.loads(contract_path.read_text(encoding="utf-8"))
    tools = {tool["name"]: tool for tool in contract["tools"]}

    assert IDENTITY_TOOL_ALLOWLIST <= tools.keys()
    for name in IDENTITY_TOOL_ALLOWLIST:
        annotations = tools[name]["annotations"]
        assert annotations["readOnlyHint"] is True
        assert annotations["destructiveHint"] is False