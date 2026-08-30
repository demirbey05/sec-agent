"""Tests for history compaction (no Elasticsearch or API key required).

`TestModel` and `FunctionModel` report a `test:test` model id, which the price
registry does not know, so every fraction is taken of the harness's 200k
fallback window. A technique configured by fraction would therefore never fire
here; the tests that need one to fire drive it through `compact_history`, which
applies no trigger of its own.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic_ai.messages import (
    ModelRequest,
    ModelResponse,
    TextPart,
    ToolCallPart,
    ToolReturnPart,
    UserPromptPart,
)
from pydantic_ai.models.function import AgentInfo, FunctionModel
from pydantic_ai.models.test import TestModel

from sec_agent.agent import Alert
from sec_agent.context import (
    COMPACTION_TECHNIQUES,
    build_strategy,
    capabilities,
    compact_history,
    is_pinned,
    pinned_notes,
    query_key,
)

ALERTS = Path(__file__).resolve().parent.parent / "siem" / "alerts"


@pytest.fixture
def alert() -> Alert:
    """A real alert from the lab, so the agent is built the way it really is."""
    return Alert.model_validate_json((ALERTS / "S1_brute_force.json").read_text())


# ---------------------------------------------------------------------------
# Selecting a technique
# ---------------------------------------------------------------------------


def test_every_documented_technique_builds():
    for name in COMPACTION_TECHNIQUES:
        assert build_strategy(name, fraction=0.75) is not None


def test_none_builds_nothing():
    assert build_strategy("none") is None
    assert build_strategy("off") is None


def test_unknown_technique_is_rejected_by_name():
    with pytest.raises(ValueError, match="tiered"):
        build_strategy("summarise-everything")


def test_default_is_off_but_the_gauge_still_registers():
    assert capabilities() == []
    assert len(capabilities(on_usage=lambda usage: None)) == 1


def test_chosen_technique_and_gauge_are_registered_in_order():
    registered = capabilities(technique="tiered", on_usage=lambda usage: None)
    # The gauge is last, so a reading reflects the post-compaction history.
    assert [type(c).__name__ for c in registered] == [
        "TieredCompaction",
        "ReportContextUsage",
    ]


# ---------------------------------------------------------------------------
# The deduplication key
# ---------------------------------------------------------------------------


def test_identical_queries_share_a_key():
    first = ToolCallPart("search_events", {"filters": {"user.name": "kadmin"}, "size": 20})
    second = ToolCallPart("search_events", {"size": 20, "filters": {"user.name": "kadmin"}})
    assert query_key(first) == query_key(second)


def test_unset_arguments_do_not_change_the_key():
    """An omitted `start` and an explicit `null` mean the same thing to the tool."""
    omitted = ToolCallPart("aggregate_events", {"group_by": "source.ip"})
    explicit = ToolCallPart("aggregate_events", {"group_by": "source.ip", "start": None})
    assert query_key(omitted) == query_key(explicit)


def test_different_queries_do_not_share_a_key():
    kadmin = ToolCallPart("entity_baseline", {"field_name": "user.name", "value": "kadmin"})
    other = ToolCallPart("entity_baseline", {"field_name": "user.name", "value": "mehmet"})
    assert query_key(kadmin) != query_key(other)


def test_json_encoded_arguments_are_parsed():
    """Some providers hand tool arguments back as a JSON string."""
    as_dict = ToolCallPart("search_events", {"size": 5})
    as_string = ToolCallPart("search_events", '{"size": 5}')
    assert query_key(as_dict) == query_key(as_string)


def test_non_query_tools_are_never_deduplicated():
    assert query_key(ToolCallPart("final_result", {"verdict": "true_positive"})) is None
    assert query_key(ToolCallPart("search_events", "not json at all")) is None


# ---------------------------------------------------------------------------
# The techniques, driven directly
# ---------------------------------------------------------------------------


def _history(pairs: int, payload_chars: int = 4_000) -> list:
    """A run of `pairs` search/return exchanges, each result `payload_chars` long."""
    messages: list = [ModelRequest(parts=[UserPromptPart(content="Triage alert a-1.")])]
    for index in range(pairs):
        call = ToolCallPart(
            "search_events",
            {"filters": {"user.name": f"user{index}"}},
            tool_call_id=f"call-{index}",
        )
        messages.append(ModelResponse(parts=[call]))
        messages.append(
            ModelRequest(
                parts=[
                    ToolReturnPart(
                        "search_events",
                        {
                            "shape": {"event.outcome": "failure"},
                            "events": ["x" * payload_chars],
                        },
                        tool_call_id=f"call-{index}",
                    )
                ]
            )
        )
    return messages


async def test_clear_tool_results_blanks_the_old_and_keeps_the_recent():
    history = _history(pairs=8)
    compacted = await compact_history(
        history, model=TestModel(), strategy=build_strategy("clear-tools")
    )

    returns = [
        part
        for message in compacted
        for part in message.parts
        if part.part_kind == "tool-return"
    ]
    assert len(returns) == 8, "clearing blanks content in place, it does not drop messages"
    cleared = [r for r in returns if isinstance(r.content, str) and "cleared" in r.content]
    # The three most recent pairs survive intact; the rest are blanked.
    assert len(cleared) == 5
    assert all(not isinstance(r.content, str) for r in returns[-3:])


async def test_nothing_is_cleared_when_it_would_reclaim_too_little():
    """Rewriting history busts the prompt cache; a trivial saving is not worth it."""
    history = _history(pairs=8, payload_chars=40)
    compacted = await compact_history(
        history, model=TestModel(), strategy=build_strategy("clear-tools")
    )
    assert compacted == history


async def test_deduplication_blanks_only_the_superseded_query():
    """Two identical queries, then a different one: only the first is superseded."""
    repeated = {"filters": {"user.name": "kadmin"}}
    history: list = [ModelRequest(parts=[UserPromptPart(content="Triage alert a-1.")])]
    for index, args in enumerate([repeated, repeated, {"filters": {"user.name": "other"}}]):
        history.append(
            ModelResponse(parts=[ToolCallPart("search_events", args, tool_call_id=f"c{index}")])
        )
        history.append(
            ModelRequest(
                parts=[
                    ToolReturnPart(
                        "search_events", {"events": ["x" * 400]}, tool_call_id=f"c{index}"
                    )
                ]
            )
        )

    compacted = await compact_history(
        history, model=TestModel(), strategy=build_strategy("dedupe")
    )
    returns = [
        part
        for message in compacted
        for part in message.parts
        if part.part_kind == "tool-return"
    ]
    superseded = [
        r for r in returns if isinstance(r.content, str) and "superseded" in r.content
    ]
    assert len(superseded) == 1
    assert returns.index(superseded[0]) == 0


async def test_sliding_window_keeps_the_alert_it_was_asked_to_triage():
    history = _history(pairs=30)
    compacted = await compact_history(
        history, model=TestModel(), strategy=build_strategy("sliding")
    )

    assert len(compacted) < len(history)
    prompts = [
        part.content
        for message in compacted
        for part in message.parts
        if part.part_kind == "user-prompt"
    ]
    assert "Triage alert a-1." in prompts


async def test_clamp_truncates_a_runaway_response_part():
    runaway = "la" * 60_000
    history = [
        ModelRequest(parts=[UserPromptPart(content="Triage alert a-1.")]),
        ModelResponse(parts=[TextPart(content=runaway)]),
    ]
    compacted = await compact_history(
        history, model=TestModel(), strategy=build_strategy("clamp")
    )

    text = compacted[-1].parts[0].content
    assert len(text) < len(runaway)
    assert "clamped" in text


async def test_summarizing_replaces_the_old_messages_with_one_summary():
    """The summariser is a real model call, so it is scripted rather than mocked out."""

    def summarise(messages, info: AgentInfo):
        assert "SOC analyst" in (info.instructions or "") or any(
            "SOC analyst" in str(part.content)
            for message in messages
            for part in message.parts
            if part.part_kind == "user-prompt"
        )
        return ModelResponse(parts=[TextPart(content="## Established\n14 failures from .44.")])

    history = _history(pairs=30)
    compacted = await compact_history(
        history, model=FunctionModel(summarise), strategy=build_strategy("summarize")
    )

    assert len(compacted) < len(history)
    assert any(
        "14 failures from .44." in str(part.content)
        for message in compacted
        for part in message.parts
    )


# `tiered` and `fallback` stop as soon as the history fits their target, and the
# target here is a fraction of the harness's 200k fallback window — which this
# test history never approaches. A tiny fraction puts the target back within
# reach, so the escalation itself is what gets tested.
TINY = 0.0005


async def test_fallback_degrades_to_dropping_messages_when_the_summary_fails():
    """A provider error mid-compaction must not end the run."""
    from pydantic_ai.exceptions import ModelHTTPError

    def refuse(messages, info: AgentInfo):
        raise ModelHTTPError(status_code=503, model_name="test", body="overloaded")

    history = _history(pairs=30)
    compacted = await compact_history(
        history,
        model=FunctionModel(refuse),
        strategy=build_strategy("fallback", fraction=TINY),
    )

    # No summary was written, but the history still came back shorter and intact.
    assert 0 < len(compacted) < len(history)


async def test_tiered_reaches_the_summary_only_after_the_cheap_passes():
    """The default recommendation, end to end: deterministic first, summary last."""
    summaries = 0

    def summarise(messages, info: AgentInfo):
        nonlocal summaries
        summaries += 1
        return ModelResponse(parts=[TextPart(content="## Established\n14 failures from .44.")])

    history = _history(pairs=30)
    compacted = await compact_history(
        history,
        model=FunctionModel(summarise),
        strategy=build_strategy("tiered", fraction=TINY),
    )

    assert len(compacted) < len(history)
    # Clearing the bulky results could not get a 30-pair history under 100 tokens,
    # so the last tier had to run — but exactly once.
    assert summaries == 1


async def test_tiered_leaves_a_history_that_already_fits_alone():
    """The expensive tier is never reached when nothing needs reclaiming."""
    history = _history(pairs=3, payload_chars=40)
    compacted = await compact_history(
        history, model=TestModel(), strategy=build_strategy("tiered")
    )
    assert compacted == history


# ---------------------------------------------------------------------------
# Pinning
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Wiring into the agent
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("technique", sorted(COMPACTION_TECHNIQUES))
async def test_every_technique_survives_a_real_run(technique, alert):
    """Building a capability is not the same as one surviving a request."""
    from sec_agent.agent import TriageDeps, build_agent

    agent = build_agent(model=TestModel(), compaction=technique)
    result = await agent.run("Triage alert a-1.", deps=TriageDeps(alert=alert))
    assert result.output.alert_id


async def test_gauge_is_read_before_each_request(alert):
    from sec_agent.agent import TriageDeps, build_agent

    readings = []
    agent = build_agent(model=TestModel(), on_usage=readings.append)
    with agent.override(model=TestModel()):
        await agent.run("Triage alert a-1.", deps=TriageDeps(alert=alert))

    assert readings, "ReportContextUsage never fired"
    first = readings[0]
    assert first.used_tokens > 0
    assert 0.0 < first.fraction < 1.0
    # `test:test` is not in the price registry, so the window is the fallback.
    assert first.resolved is False


def test_pinned_notes_are_marked_as_pinned():
    (message,) = pinned_notes(["185.220.101.44 is a known scanner."])
    assert all(is_pinned(part) for part in message.parts)


def test_no_notes_means_no_message():
    assert pinned_notes([]) == []


async def test_a_seeded_pin_reaches_the_model_and_stays_in_the_history(alert):
    """`--pin` seeds the history, so the note must survive a real run intact."""
    from sec_agent.agent import TriageDeps, build_agent

    note = "185.220.101.44 is a known scanner; I care about the successful logins."
    seen: list[str] = []

    def respond(messages, info: AgentInfo):
        seen.extend(
            str(item.content)
            for message in messages
            for part in message.parts
            if part.part_kind == "user-prompt" and not isinstance(part.content, str)
            for item in part.content
        )
        assert info.output_tools is not None
        return ModelResponse(
            parts=[
                ToolCallPart(
                    info.output_tools[0].name,
                    {
                        "alert_id": alert.alert_id,
                        "verdict": "inconclusive",
                        "severity": "low",
                        "confidence": 0.1,
                        "summary": "Not investigated.",
                    },
                )
            ]
        )

    agent = build_agent(model=FunctionModel(respond), compaction="tiered")
    result = await agent.run(
        f"Triage alert {alert.alert_id}.",
        deps=TriageDeps(alert=alert),
        message_history=pinned_notes([note]),
    )

    assert note in seen, "the pinned note never reached the model"
    assert any(
        is_pinned(part) for message in result.all_messages() for part in message.parts
    )


async def test_a_pin_survives_the_most_destructive_technique():
    """A sliding window drops the oldest messages; the pin is the oldest of all."""
    note = "185.220.101.44 is a known scanner; I care about the successful logins."
    history = [*pinned_notes([note]), *_history(pairs=30)]

    compacted = await compact_history(
        history, model=TestModel(), strategy=build_strategy("sliding")
    )

    assert len(compacted) < len(history)
    assert any(
        is_pinned(part) and note in str(part.content[0].content)
        for message in compacted
        for part in message.parts
    )
