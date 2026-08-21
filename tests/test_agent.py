"""Tests for the agent's tools and output schema (no API key required)."""

from __future__ import annotations

import json

import pytest
from pydantic_ai import ModelRetry
from pydantic_ai.messages import ModelMessage, ModelResponse, ToolCallPart
from pydantic_ai.models.function import AgentInfo, FunctionModel

from sec_agent.agent import SecurityDeps, SecurityReport, build_agent


@pytest.fixture
def repo(tmp_path):
    (tmp_path / "app.py").write_text("PASSWORD = 'hunter2'\n", encoding="utf-8")
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "util.py").write_text("x = 1\n", encoding="utf-8")
    return tmp_path


def test_resolve_blocks_path_traversal(repo):
    deps = SecurityDeps(root=repo)
    with pytest.raises(ModelRetry):
        deps.resolve("../../etc/passwd")


def test_resolve_allows_paths_inside_root(repo):
    deps = SecurityDeps(root=repo)
    assert deps.resolve("pkg/util.py") == (repo / "pkg" / "util.py").resolve()


def test_resolve_rejects_escape_from_nested_root(repo):
    deps = SecurityDeps(root=repo / "pkg")
    with pytest.raises(ModelRetry):
        deps.resolve("../app.py")


def _scripted_model() -> FunctionModel:
    """A fake model that follows a list_files -> read_file -> report sequence."""

    def respond(messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
        turn = sum(1 for m in messages if m.kind == "response")
        if turn == 0:
            return ModelResponse(parts=[ToolCallPart("list_files", {"glob": "**/*.py"})])
        if turn == 1:
            return ModelResponse(parts=[ToolCallPart("read_file", {"path": "app.py"})])

        assert info.output_tools is not None
        report = {
            "summary": "Found a hardcoded password in the source.",
            "findings": [
                {
                    "title": "Hardcoded password",
                    "severity": "high",
                    "file": "app.py",
                    "line": 1,
                    "description": "The password is embedded in the source code.",
                    "recommendation": "Read it from an environment variable.",
                }
            ],
        }
        return ModelResponse(parts=[ToolCallPart(info.output_tools[0].name, report)])

    return FunctionModel(respond)


async def test_agent_returns_structured_report(repo):
    agent = build_agent()
    with agent.override(model=_scripted_model()):
        result = await agent.run("Review", deps=SecurityDeps(root=repo))

    assert isinstance(result.output, SecurityReport)
    assert result.output.findings[0].severity == "high"


async def test_tools_return_expected_content(repo):
    agent = build_agent()
    with agent.override(model=_scripted_model()):
        result = await agent.run("Review", deps=SecurityDeps(root=repo))

    returns = {
        part.tool_name: part.content
        for message in result.all_messages()
        for part in message.parts
        if part.part_kind == "tool-return"
    }

    listed = returns["list_files"]
    if isinstance(listed, str):
        listed = json.loads(listed)
    assert set(listed) == {"app.py", "pkg/util.py"}

    # read_file returns content prefixed with line numbers.
    assert "    1\tPASSWORD = 'hunter2'" in returns["read_file"]
