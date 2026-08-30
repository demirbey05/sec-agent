"""Live trace of a triage run: what the model thinks, what it calls, what comes back.

The agent is otherwise a black box that prints a verdict. `--trace` turns the run
into a running commentary, so a wrong verdict can be traced back to the query that
misled the model.
"""

from __future__ import annotations

import json
import sys
from typing import Any

from pydantic_ai import Agent
from pydantic_ai.messages import (
    FunctionToolCallEvent,
    FunctionToolResultEvent,
    ModelMessage,
    PartDeltaEvent,
    PartStartEvent,
    RetryPromptPart,
    TextPart,
    TextPartDelta,
    ThinkingPart,
    ThinkingPartDelta,
)

from .agent import TriageDeps, TriageVerdict
from .context import ContextUsage

BOLD = "1"
DIM = "2"
RED = "31"
GREEN = "32"
YELLOW = "33"
CYAN = "36"

MAX_LINES = 14
"""Lines of a tool result shown before the rest is folded into a counter."""

MAX_WIDTH = 150


def _paint(text: str, code: str) -> str:
    """Colour `text`, unless stdout is a pipe or a file."""
    return f"\x1b[{code}m{text}\x1b[0m" if sys.stdout.isatty() else text


def _clip(text: str, width: int = MAX_WIDTH) -> str:
    return text if len(text) <= width else text[: width - 1] + "…"


def _format_args(args: str | dict[str, Any] | None) -> str:
    """Render tool arguments as `key=value, key=value`, dropping unset ones."""
    if isinstance(args, str):
        try:
            args = json.loads(args)
        except json.JSONDecodeError:
            return _clip(args)
    if not isinstance(args, dict) or not args:
        return ""
    parts = [
        f"{key}={value if isinstance(value, str) else json.dumps(value, default=str)}"
        for key, value in args.items()
        if value is not None
    ]
    return _clip(", ".join(parts))


def _folded_preview(content: dict[str, Any]) -> list[str]:
    """Render a folded `search_events` result for a human reading the trace.

    The shared shape is collapsed to a single line: it is the least interesting
    part of the result by construction. The outliers are printed in full, since
    a document that broke the pattern is usually why the query was run.
    """
    counts = [f"returned {content['returned']} of {content['total_matched']}"]
    if conforming := content.get("events"):
        counts.append(f"{len(conforming)} conforming")
    if outliers := content.get("outlier_count"):
        counts.append(f"{outliers} outlier{'s' if outliers != 1 else ''}")

    lines = [" · ".join(counts)]
    if content.get("note"):
        lines.append(content["note"])
    if shape := content.get("shape"):
        lines.append(f"shape: {json.dumps(shape, default=str)}")
    if conforming:
        first, last = conforming[0], conforming[-1]
        lines.append(f"events: {first[1]} … {last[1]}  [{first[0]} … {last[0]}]")
    for outlier in content.get("outliers", []):
        lines.append(f"outlier: {json.dumps(outlier, default=str)}")
    if truncated := content.get("truncated"):
        lines.append(truncated)
    return lines


def _preview(content: Any) -> list[str]:
    """Summarise a tool result: a headline, then one line per record."""
    if isinstance(content, list):
        head = [f"{len(content)} document{'s' if len(content) != 1 else ''}"]
        body = [json.dumps(item, default=str) for item in content]
    elif isinstance(content, dict):
        if "returned" in content and "total_matched" in content:
            head = []
            body = _folded_preview(content)
        else:
            head = []
            body = json.dumps(content, indent=2, default=str).splitlines()
    else:
        head = []
        body = str(content).splitlines()

    lines = head + [_clip(line) for line in body[:MAX_LINES]]
    if len(body) > MAX_LINES:
        lines.append(f"… +{len(body) - MAX_LINES} more lines")
    return lines or [""]


class Tracer:
    """Turns the agent's event stream into terminal output, as it happens."""

    def __init__(self) -> None:
        self._colour: str | None = None
        """Set while a thinking or text part is still streaming in."""

    def _write(self, text: str) -> None:
        if text and self._colour is not None:
            sys.stdout.write(_paint(text, self._colour))
            sys.stdout.flush()

    def _close(self) -> None:
        """Terminate a streaming part before printing anything else."""
        if self._colour is not None:
            sys.stdout.write("\n\n")
            self._colour = None

    def _open(self, header: str, colour: str, initial: str) -> None:
        self._close()
        print(_paint(header, colour))
        self._colour = colour
        self._write(initial)

    def handle(self, event: Any) -> None:
        """Render a single event from `Agent.run_stream_events`."""
        if isinstance(event, PartStartEvent):
            if isinstance(event.part, ThinkingPart):
                self._open("✻ Thinking", f"{DIM};{CYAN}", event.part.content)
            elif isinstance(event.part, TextPart):
                self._open("● Note", DIM, event.part.content)

        elif isinstance(event, PartDeltaEvent):
            if isinstance(event.delta, (ThinkingPartDelta, TextPartDelta)):
                self._write(event.delta.content_delta or "")

        elif isinstance(event, FunctionToolCallEvent):
            self._close()
            call = event.part
            print(
                _paint("●", GREEN)
                + " "
                + _paint(call.tool_name, BOLD)
                + f"({_format_args(call.args)})"
            )

        elif isinstance(event, FunctionToolResultEvent):
            part = event.part
            failed = isinstance(part, RetryPromptPart)
            gutter = _paint("  ⎿ ", RED if failed else DIM)
            lines = _preview(part.content)
            print(gutter + _paint(lines[0], YELLOW if failed else DIM))
            for line in lines[1:]:
                print("     " + _paint(line, YELLOW if failed else DIM))
            print()

    def finish(self) -> None:
        """Close whatever was still streaming when the run ended."""
        self._close()


def gauge(usage: ContextUsage) -> None:
    """Print how full the context is, before each request goes out.

    `resolved` is false when the window is the harness's conservative fallback
    rather than the model's real one, which makes the percentage a guess — worth
    saying, since it is the number a decision to compact rests on.
    """
    estimate = "" if usage.resolved else " (window estimated)"
    print(
        _paint(
            f"  context {usage.fraction:.0%} · "
            f"{usage.used_tokens:,} / {usage.window_tokens:,} tokens{estimate}",
            DIM,
        )
    )


async def run_traced(
    agent: Agent[TriageDeps, TriageVerdict],
    deps: TriageDeps,
    history: list[ModelMessage] | None = None,
) -> TriageVerdict:
    """Run the agent, printing every step, and return the final verdict."""
    tracer = Tracer()
    prompt = f"Triage alert {deps.alert.alert_id}."

    async with agent.run_stream_events(prompt, deps=deps, message_history=history) as events:
        async for event in events:
            tracer.handle(event)
        tracer.finish()
        usage = events.usage
        print(
            _paint(
                f"─── {usage.requests} model requests · "
                f"{usage.input_tokens} in / {usage.output_tokens} out tokens ───\n",
                DIM,
            )
        )
        return events.result.output
